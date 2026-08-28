//  PacketPump.swift — the standing read on NEPacketTunnelFlow.
//
//  Authority: ADR-0018 PB-1, PB-2, PB-4; ADR-0022 LC-31; ownership.md §10.2.
//
//  STATUS: written, not compiled.
//
//  ===========================================================================
//  WHY A STANDING READ AND NOT A POLL
//  ===========================================================================
//
//  `NEPacketTunnelFlow.readPackets` is a one-shot callback: it delivers a batch
//  and must be re-armed. PB-1 budgets "1 [crossing] per batch, + 1 copy per
//  packet", so the pump re-arms immediately from inside the completion handler
//  and never polls. A poll would multiply the crossing count by the poll rate and
//  blow PB-4's budget — "<= 5 % of the userspace-datapath throughput on the
//  reference device, measured, and a §14 revisit trigger if exceeded".
//
//  ===========================================================================
//  THIS IS NOT A KEEP-ALIVE
//  ===========================================================================
//
//  `ownership.md` §10.2's second prohibition: "No undocumented
//  background-execution tricks… Keepalives ride the tunnel socket's own
//  kernel-side timer where the platform offers one, never an app-side alarm
//  cadence chosen to defeat Doze."
//
//  There is no `Timer` in this file and no `DispatchSourceTimer`. The pump runs
//  when the OS hands it packets and is idle otherwise. Every deadline in the
//  system is the core's, composed from `twinvpn_env::Timer` on the injected
//  monotonic clock (CD-1), and nothing here schedules work to stay resident.

import Foundation
import NetworkExtension
import os

final class PacketPump {
    static let shared = PacketPump()

    private var flow: NEPacketTunnelFlow?
    private weak var core: CoreInstance?
    private var inbound: [Data] = []
    private let lock = NSLock()
    private let log = Logger(subsystem: "net.twinvpn.provider", category: "pump")

    /// How many packets may queue before the pump drops and counts.
    ///
    /// ADR-0022 LC-31's ladder sheds bounded caches at 10 MB; an unbounded packet
    /// queue is not a cache the ladder can shed, it is a jetsam kill waiting for a
    /// burst. Bounded, and the drop is COUNTED rather than silent — a silently
    /// dropped packet is indistinguishable on the wire from a network fault and
    /// gets debugged as one.
    private static let maxQueuedPackets = 512

    private(set) var droppedPackets: UInt64 = 0

    func attach(flow: NEPacketTunnelFlow, core: CoreInstance) {
        self.flow = flow
        self.core = core
        armRead()
    }

    func detach() {
        lock.lock()
        flow = nil
        core = nil
        inbound.removeAll()
        lock.unlock()
    }

    /// Hands the queued batch to Rust. Called through the bridge.
    func drainInbound() -> [Data] {
        lock.lock()
        defer { lock.unlock() }
        let batch = inbound
        inbound.removeAll(keepingCapacity: true)
        return batch
    }

    /// Re-arms the read.
    ///
    /// The `protocols` array `readPackets` hands back is DISCARDED here, and that
    /// is deliberate: Rust derives the family from each packet's own version
    /// nibble (`twinvpn_platform_ios::tun::packet_family`) so that the derivation
    /// is one function with tests rather than two sources that can disagree. A
    /// packet whose nibble says v6 and whose protocol number says v4 is a fact
    /// worth catching, and it is caught on the side that can refuse it.
    private func armRead() {
        guard let flow else { return }
        flow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            self.lock.lock()
            for packet in packets {
                if self.inbound.count >= Self.maxQueuedPackets {
                    self.droppedPackets += 1
                    continue
                }
                self.inbound.append(packet)
            }
            self.lock.unlock()
            // The core is told there is work; it decides when to do it.
            self.core?.submitPacketsAvailable()
            // Re-arm from inside the handler: one crossing per batch (PB-1),
            // and no timer anywhere.
            self.armRead()
        }
    }
}

/// Reads this process's resident size, for ADR-0022 LC-31's ladder.
///
/// The THRESHOLDS are in Rust (`twinvpn_platform_ios::lifecycle`), asserted at
/// compile time against ADR-0018 PB-6's table. This reads the number; it does not
/// decide what the number means.
enum MemoryReporter {
    static func residentBytes() -> UInt64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        // A failed read reports zero, which the ladder treats as "below every
        // threshold" — the wrong direction, but the alternative is a fabricated
        // large number that would shed caches for no reason. Recorded so the
        // choice is visible rather than accidental.
        guard result == KERN_SUCCESS else { return 0 }
        return UInt64(info.phys_footprint)
    }
}
