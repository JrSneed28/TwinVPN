//
//  PacketLoop.swift
//  com.twinvpn.app.sysext
//
//  The datapath. Authority: ADR-0018 PB-1 ("zero FFI crossings per packet, with
//  one exception — `NEPacketTunnelFlow`, which is a Swift API and not this
//  ABI"), CB-2; ADR-0012 KS-1 (a packet that cannot be protected is dropped,
//  never sent in the clear).
//
//  ============================================================================
//  TWO LOOPS, AND WHAT NEITHER OF THEM DECIDES
//
//    inbound:  packetFlow.readPackets  ->  tvb_ext_inject_inbound
//    outbound: tvb_ext_next_outbound   ->  packetFlow.writePackets
//
//  Neither loop inspects a packet. There is no code in this file that reads a
//  byte of a packet's contents — no version nibble check, no header parse, no
//  address extraction. The family tag comes from NE on the way in and from the
//  core on the way out, and is MARSHALLED, never inferred. Inferring it (by
//  reading the IP version nibble, the obvious shortcut) would be the shell
//  forming an opinion about a packet, which is a decision.
//
//  ============================================================================
//  THE FAMILY TAG
//
//  NE's protocol tag is an `NSNumber` holding `AF_INET` or `AF_INET6`. The
//  bridge's is `TVB_FAMILY_V4` / `TVB_FAMILY_V6`, which are 4 and 6 — the IP
//  version numbers, not the AF constants, because `AF_INET6` differs between
//  Darwin (30) and Linux (10) and an ABI that carried the platform's own value
//  would mean two different things on the two sides of a cross-compile.
//
//  The conversion below is therefore a two-entry table, and it is marshalling:
//  it changes an encoding without changing a fact.
//
//  ============================================================================
//  BACKPRESSURE
//
//  `readPackets(completionHandler:)` delivers a batch and does not deliver
//  another until it is called again. That is NE's own backpressure and this file
//  uses it as such: the next `readPackets` is issued only after the whole batch
//  has been handed to the core. A loop that re-armed the read before draining
//  the batch would queue packets in the extension's heap, and a system extension
//  that grows its heap under load is one the OS eventually kills.
//
//  The outbound loop's backpressure is the bridge's blocking timeout: when the
//  core has nothing, `nextOutbound` returns `nil` after `timeoutMillis` and the
//  loop yields. It never spins.
//
//  ============================================================================
//  CANCELLATION
//
//  Both loops are `Task`s and both check `Task.isCancelled` at the top of every
//  iteration. Cancelling is how `stopTunnel` stops the datapath, and a loop that
//  ignored cancellation would keep injecting into a bridge the provider is about
//  to free.
//

import Foundation
import NetworkExtension

/// The datapath, as two cancellable tasks.
///
/// An actor, so the two tasks' handles cannot be raced by `start` and `stop`
/// arriving from different NE callbacks. The loops themselves run outside the
/// actor's isolation — they are long-lived and blocking, and holding the actor
/// for their duration would serialise the two directions into one.
actor PacketLoop {
    private let bridge: CoreBridge
    private let flow: NEPacketTunnelFlow
    private var inbound: Task<Void, Never>?
    private var outbound: Task<Void, Never>?

    /// How long `nextOutbound` blocks before returning "nothing yet".
    ///
    /// Not a timeout in the ADR-0018 sense — it bounds nothing and expires
    /// nothing. It is a poll granularity for a blocking C call, chosen so a
    /// cancelled task notices within a human-imperceptible interval without
    /// spinning. **Every deadline in this product is the core's**, composed from
    /// `twinvpn_env::Timer` on the injected monotonic clock; a shell that
    /// imposed one would put it outside CD-1's reach.
    private static let outboundPollMillis: UInt32 = 250

    init(bridge: CoreBridge, flow: NEPacketTunnelFlow) {
        self.bridge = bridge
        self.flow = flow
    }

    func start(correlation: Correlation) {
        guard inbound == nil, outbound == nil else { return }
        let bridge = self.bridge
        let flow = self.flow
        inbound = Task.detached(priority: .userInitiated) {
            await PacketLoop.runInbound(bridge: bridge, flow: flow, correlation: correlation)
        }
        outbound = Task.detached(priority: .userInitiated) {
            await PacketLoop.runOutbound(bridge: bridge, flow: flow, correlation: correlation)
        }
        TunnelLog.packets.info("datapath.started", correlation)
    }

    func stop(correlation: Correlation) {
        inbound?.cancel()
        outbound?.cancel()
        inbound = nil
        outbound = nil
        TunnelLog.packets.info("datapath.stopped", correlation)
    }

    // MARK: - Inbound: the OS's packets, into the core

    private static func runInbound(
        bridge: CoreBridge,
        flow: NEPacketTunnelFlow,
        correlation: Correlation
    ) async {
        // A failure counter, so a persistently failing datapath produces ONE log
        // line per burst rather than one per packet. A per-packet log line under
        // a datapath fault is a log that becomes the outage.
        var suppressedFailures = 0

        while !Task.isCancelled {
            let batch = await flow.readPacketObjects()
            if Task.isCancelled { break }

            for packet in batch {
                let family = tvbFamily(fromNE: packet.protocolFamily)
                do {
                    // `withUnsafeBytes` scopes the pointer to the call, which is
                    // exactly `tvb_slice`'s lifetime rule. No copy is made.
                    try packet.data.withUnsafeBytes { raw in
                        try bridge.injectInbound(raw, family: family, correlation: correlation)
                    }
                } catch {
                    // KS-1: a packet that cannot be protected is DROPPED. There
                    // is no fallback path that writes it somewhere else, and
                    // there is deliberately no retry: a retry would reorder the
                    // datapath and hide a persistent fault behind latency.
                    suppressedFailures += 1
                }
            }

            if suppressedFailures > 0 {
                TunnelLog.packets.error("datapath.inbound.dropped", correlation)
                TunnelLog.packets.info("datapath.inbound.dropped.count",
                                       count: suppressedFailures, correlation)
                suppressedFailures = 0
            }
        }
        TunnelLog.packets.info("datapath.inbound.exited", correlation)
    }

    // MARK: - Outbound: the core's packets, into the OS

    private static func runOutbound(
        bridge: CoreBridge,
        flow: NEPacketTunnelFlow,
        correlation: Correlation
    ) async {
        while !Task.isCancelled {
            let next: (packet: [UInt8], family: Int32)?
            do {
                next = try bridge.nextOutbound(
                    timeoutMillis: outboundPollMillis, correlation: correlation)
            } catch {
                // The bridge failed, not one packet. Log once and exit the loop:
                // continuing would spin against a broken bridge, and the
                // provider's own supervision is what restarts a datapath.
                if let bridgeError = error as? BridgeError {
                    TunnelLog.packets.error("datapath.outbound.failed",
                                            envelope: bridgeError.envelopeText,
                                            correlation)
                } else {
                    TunnelLog.packets.error("datapath.outbound.unavailable", correlation)
                }
                break
            }

            guard let next else { continue }   // timeout: nothing to write

            // `writePackets` is fire-and-forget by NE's design; it has no
            // completion handler and no error channel. One packet per call
            // rather than a batched accumulation: batching would need a buffer
            // whose flush deadline is a timer, and a timer here would be a
            // shell-side deadline (see `outboundPollMillis`'s note).
            flow.writePackets([Data(next.packet)],
                              withProtocols: [neFamily(fromTVB: next.family)])
        }
        TunnelLog.packets.info("datapath.outbound.exited", correlation)
    }

    // MARK: - The family table
    //
    // Two entries each way. Marshalling, not a decision: the fact ("this is an
    // IPv6 packet") is unchanged, only its encoding differs.

    /// NE's `AF_*` tag -> the bridge's IP version number.
    ///
    /// An unrecognised family maps to `TVB_FAMILY_V4`... it does **not**. There
    /// is no default: NE documents `protocolFamily` as `AF_INET` or `AF_INET6`
    /// for a packet-tunnel flow, and inventing a family for a third value would
    /// be the shell deciding what an unknown packet is. `0` is passed through
    /// instead, and the CORE refuses it — which is where a refusal belongs.
    private static func tvbFamily(fromNE family: sa_family_t) -> Int32 {
        switch Int32(family) {
        case AF_INET:  return TVB_FAMILY_V4
        case AF_INET6: return TVB_FAMILY_V6
        default:       return 0
        }
    }

    /// The bridge's IP version number -> NE's `AF_*` tag.
    ///
    /// Same shape, same reason. A family the bridge did not name is passed to NE
    /// as `0`, which NE rejects, rather than being silently written as IPv4.
    private static func neFamily(fromTVB family: Int32) -> NSNumber {
        switch family {
        case TVB_FAMILY_V4: return NSNumber(value: AF_INET)
        case TVB_FAMILY_V6: return NSNumber(value: AF_INET6)
        default:            return NSNumber(value: 0)
        }
    }
}

// MARK: -

private extension NEPacketTunnelFlow {
    /// `readPacketObjects` as an `async` call.
    ///
    /// UNVERIFIED: `readPacketObjects(completionHandler:)` is the `NEPacket`-
    /// returning variant, available from macOS 10.13. The older
    /// `readPackets(completionHandler:)` yields parallel `[Data]` and
    /// `[NSNumber]` arrays, and pairing two arrays by index is a place to be
    /// wrong. `NEPacket` carries the family with the bytes, so the pairing
    /// cannot drift — which is why this variant is used.
    ///
    /// This domain has not confirmed the selector's exact spelling on a Mac.
    func readPacketObjects() async -> [NEPacket] {
        await withCheckedContinuation { continuation in
            self.readPacketObjects { packets in
                continuation.resume(returning: packets)
            }
        }
    }
}
