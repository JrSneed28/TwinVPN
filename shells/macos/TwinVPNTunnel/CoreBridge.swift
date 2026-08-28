//
//  CoreBridge.swift
//  com.twinvpn.app.sysext
//
//  The Swift half of the `twinvpn-bridge` C ABI
//  (`shells/macos/twinvpn-bridge/include/twinvpn_bridge.h`).
//
//  Authority: ADR-0018 §11.4 and §11.6 (the ABI and the seam), F-2 (no
//  malloc/free pairing crosses the boundary), F-3 (length-delimited, never
//  NUL-reliant), F-4 (errors carry a name, never an errno), F-6 (the reentrancy
//  guard), F-7 (`catch_unwind` containment at the boundary), CB-2 (the shell
//  holds no decision); ADR-0015 §11.2 (the diagnostic envelope).
//
//  ============================================================================
//  WHAT THIS FILE IS
//
//  A translation layer and nothing else. It converts Swift values into
//  `tvb_slice`s, calls one C function, converts the result back, and frees what
//  it was given. There is no branch in this file whose condition is a TwinVPN
//  domain fact — the only branches are on `TVB_OK` / `TVB_ERR` / `TVB_TIMEOUT`,
//  which say WHICH SHAPE the outcome took and never what it means.
//
//  ============================================================================
//  THE THREE OWNERSHIP RULES, AND WHERE EACH IS ENFORCED
//
//  1. **Every `tvb_buf *` the bridge returns is freed exactly once, with
//     `tvb_buf_free`, including on the error path.** F-2 makes the allocator's
//     side the deallocator's side; `consume(_:)` below is the ONLY place a
//     `tvb_buf` is read, and it frees in a `defer` before it can return. There
//     is no path out of `consume` that skips the free.
//
//  2. **A `tvb_slice` is valid only for the duration of the call it is passed
//     to.** `withSlice` scopes the pointer to a closure, so a slice cannot
//     outlive the buffer it borrows: escaping it does not compile.
//
//  3. **`tvb_ext *` is owned by exactly one `CoreBridge`.** `tvb_ext_free` runs
//     in `deinit` and nowhere else, and `stop()` does not free — a stopped
//     extension is still a valid handle, and freeing on stop would make a
//     double `stopTunnel` a use-after-free.
//
//  ============================================================================
//  CONCURRENCY
//
//  `next_settings` and `next_outbound` are BLOCKING with a timeout, and the
//  provider runs them on two different tasks concurrently with each other and
//  with `inject_inbound`. **That makes thread-safety a requirement on the Rust
//  side of this ABI, not an assumption of this file**, and it is stated here so
//  the requirement is written down on both sides: `tvb_ext` must tolerate
//  concurrent calls from distinct threads. F-6's reentrancy guard is about a
//  callback arriving *into* the core during a mutating call; it is not a
//  serialisation guarantee for outbound calls, and reading it as one would be a
//  mistake.
//
//  `@unchecked Sendable` records that judgement explicitly rather than letting
//  an implicit `nonisolated(unsafe)` hide it.
//

import Foundation

/// An error the bridge reported, carrying the core's own envelope **unparsed**.
///
/// F-4: the failure signal is the envelope, never the integer. The integer here
/// is kept only so a reader can tell `TVB_ERR` from an unexpected code; nothing
/// branches on it beyond that.
///
/// **The envelope is never parsed by this shell.** It is an ADR-0015 §11.2
/// document carrying a registered `reason_code`, and CB-2 forbids a branch whose
/// condition is a `reason_code` class. It is logged (at `.private`), and it is
/// handed back to whoever asked. That is all.
struct BridgeError: Error, Sendable {
    /// The raw envelope bytes, exactly as the core produced them.
    let envelope: [UInt8]
    /// The result code the call returned. `TVB_ERR` in every ordinary case.
    let code: Int32
    /// The C entry point that produced it — a stable, non-localised tag, the
    /// same discipline as `OsDetail.call` on the Rust side.
    let call: StaticString

    /// The envelope as text, for a log line. Lossy UTF-8 rather than a throwing
    /// decode: an envelope that is not valid UTF-8 is a bridge defect, and
    /// losing the diagnostic while reporting a *different* failure would hide
    /// the original one.
    var envelopeText: String {
        String(decoding: envelope, as: UTF8.self)
    }
}

/// The bridge could not be created or has gone away — a condition with no
/// envelope, because the call that would have produced one is the one that
/// failed.
struct BridgeUnavailable: Error, Sendable {
    let call: StaticString
}

/// One running extension instance, over the C ABI.
final class CoreBridge: @unchecked Sendable {
    /// `tvb_ext *`. An incomplete C struct imports as `OpaquePointer`.
    private let ext: OpaquePointer

    /// The ABI the bridge was compiled against, checked once at start.
    ///
    /// ADR-0018 VR-4: a mismatch is a **packaging defect**, not an operating
    /// state — but it is still checked, because the alternative is undefined
    /// behaviour. VR-2 forbids `abi_*` being used as a compatibility input
    /// anywhere except between a shell and a core in the same process, which is
    /// exactly and only what this is.
    static func assertABI() throws {
        let major = tvb_abi_major()
        guard major == TVB_ABI_MAJOR else {
            TunnelLog.bridge.error("bridge.abi.mismatch", Correlation.origin())
            throw BridgeUnavailable(call: "tvb_abi_major")
        }
    }

    // MARK: - Lifecycle

    /// Starts the core-side extension.
    ///
    /// `configJSON` is opaque to this file: it is produced by the containing
    /// app or by the provider's `options` and passed through byte-for-byte. The
    /// shell does not read it, does not validate it, and does not supply a
    /// default for anything missing from it — CB-2 again, and ADR-0018's
    /// "validate every untrusted input against `limits.json`" is the CORE's
    /// obligation, performed behind this call where the limits actually live.
    init(configJSON: [UInt8], correlation: Correlation) throws {
        var handle: OpaquePointer?
        var err: OpaquePointer?
        let rc = configJSON.withTVBSlice { config in
            correlation.wireBytes.withTVBSlice { cid in
                tvb_ext_start(config, cid, &handle, &err)
            }
        }
        guard rc == TVB_OK, let handle else {
            let envelope = CoreBridge.consume(err) ?? []
            TunnelLog.bridge.error(
                "bridge.start.failed",
                envelope: String(decoding: envelope, as: UTF8.self),
                correlation)
            throw BridgeError(envelope: envelope, code: rc, call: "tvb_ext_start")
        }
        // On success the ABI leaves `*err` untouched. Freeing a non-nil value
        // here would be defending against a bridge that violated its own
        // contract, and silently papering over that is worse than leaking:
        // `err` is asserted nil in debug and ignored in release.
        assert(err == nil, "tvb_ext_start wrote an envelope on success")
        self.ext = handle
        TunnelLog.bridge.info("bridge.start.ok", correlation)
    }

    deinit {
        // Rule 3. The ONLY call to `tvb_ext_free` in the shell.
        tvb_ext_free(ext)
    }

    /// Reports a stop. Does **not** free the handle.
    ///
    /// `reason` is `NEProviderStopReason.rawValue` — an OS fact the provider was
    /// handed, marshalled across unchanged. The shell does not interpret it and
    /// does not act differently for any value of it; the core decides what a
    /// stop reason means.
    func stop(reason: Int32, correlation: Correlation) throws {
        try call("tvb_ext_stop", correlation) { err in
            correlation.wireBytes.withTVBSlice { cid in
                tvb_ext_stop(ext, reason, cid, err)
            }
        }
    }

    // MARK: - Settings

    /// The next settings document the **core** computed, or `nil` if none
    /// arrived within `timeoutMillis`.
    ///
    /// `TVB_TIMEOUT` is not a failure: the ABI says so, and treating it as one
    /// would turn a quiet period into an error the provider reported.
    func nextSettings(timeoutMillis: UInt32, correlation: Correlation) throws -> [UInt8]? {
        var doc: OpaquePointer?
        var err: OpaquePointer?
        let rc = tvb_ext_next_settings(ext, timeoutMillis, &doc, &err)
        switch rc {
        case TVB_TIMEOUT:
            assert(doc == nil && err == nil)
            return nil
        case TVB_OK:
            return CoreBridge.consume(doc) ?? []
        default:
            let envelope = CoreBridge.consume(err) ?? []
            // Free the document too if the bridge produced both — rule 1 admits
            // no path that skips a free.
            _ = CoreBridge.consume(doc)
            TunnelLog.bridge.error(
                "bridge.next_settings.failed",
                envelope: String(decoding: envelope, as: UTF8.self),
                correlation)
            throw BridgeError(envelope: envelope, code: rc, call: "tvb_ext_next_settings")
        }
    }

    // MARK: - The packet path
    //
    // PB-1 permits exactly one FFI crossing per packet, through
    // `NEPacketTunnelFlow`. These two entries are that crossing and there is no
    // other packet-bearing call in the shell.

    /// Hands one packet read from `packetFlow` to the core.
    ///
    /// Takes an `UnsafeRawBufferPointer` rather than `Data` so the bytes are not
    /// copied on the way in: `Data`'s storage is not guaranteed contiguous, and
    /// a copy per packet is a copy per packet.
    func injectInbound(_ packet: UnsafeRawBufferPointer, family: Int32, correlation: Correlation) throws {
        var err: OpaquePointer?
        let base = packet.baseAddress?.assumingMemoryBound(to: UInt8.self)
        let rc = tvb_ext_inject_inbound(ext, base, packet.count, family, &err)
        guard rc == TVB_OK else {
            let envelope = CoreBridge.consume(err) ?? []
            // NOT logged per packet with the envelope: a failing datapath would
            // write a log line per packet and the log would become the outage.
            // The caller decides whether to log, and at what rate.
            throw BridgeError(envelope: envelope, code: rc, call: "tvb_ext_inject_inbound")
        }
        assert(err == nil)
    }

    /// One packet the core wants written to `packetFlow`, or `nil` on timeout.
    func nextOutbound(timeoutMillis: UInt32, correlation: Correlation) throws -> (packet: [UInt8], family: Int32)? {
        var pkt: OpaquePointer?
        var err: OpaquePointer?
        var family: Int32 = 0
        let rc = tvb_ext_next_outbound(ext, timeoutMillis, &pkt, &family, &err)
        switch rc {
        case TVB_TIMEOUT:
            assert(pkt == nil && err == nil)
            return nil
        case TVB_OK:
            guard let bytes = CoreBridge.consume(pkt) else {
                // TVB_OK with no buffer is a bridge defect. Reported as an
                // unavailable bridge rather than silently treated as a timeout,
                // because a datapath that silently drops is a datapath nobody
                // can debug.
                throw BridgeUnavailable(call: "tvb_ext_next_outbound")
            }
            return (bytes, family)
        default:
            let envelope = CoreBridge.consume(err) ?? []
            _ = CoreBridge.consume(pkt)
            throw BridgeError(envelope: envelope, code: rc, call: "tvb_ext_next_outbound")
        }
    }

    // MARK: - Lifecycle facts (ADR-0022)
    //
    // Each of these REPORTS. None of them asserts anything, renders anything, or
    // decides anything. ADR-0022's rule is that a resume must not render a
    // confident, stale green: the adapter reports the fact and the core decides,
    // so `wake` below is a notification and never a "we are still connected".

    func reportSleep(correlation: Correlation) throws {
        try call("tvb_ext_sleep", correlation) { err in
            correlation.wireBytes.withTVBSlice { cid in tvb_ext_sleep(ext, cid, err) }
        }
    }

    func reportWake(correlation: Correlation) throws {
        try call("tvb_ext_wake", correlation) { err in
            correlation.wireBytes.withTVBSlice { cid in tvb_ext_wake(ext, cid, err) }
        }
    }

    func reportNetworkChanged(correlation: Correlation) throws {
        try call("tvb_ext_network_changed", correlation) { err in
            correlation.wireBytes.withTVBSlice { cid in tvb_ext_network_changed(ext, cid, err) }
        }
    }

    // MARK: - The management hop

    /// `handleAppMessage`: an opaque MI envelope in, an opaque MI envelope out.
    ///
    /// ADR-0017 MI-20 — "one contract, two carriages, never two contracts" — is
    /// why this file does not decode either side. The envelope's schema lives in
    /// the Rust `mi` module that `twinvpnd` and `twinvpnctl` share; a Swift copy
    /// of it would be the second contract that rule forbids.
    func appMessage(_ request: [UInt8], correlation: Correlation) throws -> [UInt8] {
        var resp: OpaquePointer?
        var err: OpaquePointer?
        let rc = request.withTVBSlice { req in
            tvb_ext_app_message(ext, req, &resp, &err)
        }
        guard rc == TVB_OK else {
            let envelope = CoreBridge.consume(err) ?? []
            _ = CoreBridge.consume(resp)
            TunnelLog.bridge.error(
                "bridge.app_message.failed",
                envelope: String(decoding: envelope, as: UTF8.self),
                correlation)
            throw BridgeError(envelope: envelope, code: rc, call: "tvb_ext_app_message")
        }
        return CoreBridge.consume(resp) ?? []
    }

    // MARK: - Plumbing

    /// The shared shape of every entry that returns only success or an envelope.
    private func call(
        _ name: StaticString,
        _ correlation: Correlation,
        _ body: (UnsafeMutablePointer<OpaquePointer?>) -> Int32
    ) throws {
        var err: OpaquePointer?
        let rc = body(&err)
        guard rc == TVB_OK else {
            let envelope = CoreBridge.consume(err) ?? []
            TunnelLog.bridge.error(
                "bridge.call.failed",
                envelope: String(decoding: envelope, as: UTF8.self),
                correlation)
            throw BridgeError(envelope: envelope, code: rc, call: name)
        }
        assert(err == nil)
    }

    /// Rule 1, in one function: copy the bytes out, then free, always.
    ///
    /// A copy rather than a borrow, deliberately. A `tvb_buf` is the bridge's
    /// allocation and F-2 makes it the bridge's to free; handing its interior
    /// pointer to Swift code that outlives the call would put the free at a
    /// point no reviewer can locate. The copy is what makes "freed exactly once,
    /// here" a property of the file rather than of every call site.
    private static func consume(_ buf: OpaquePointer?) -> [UInt8]? {
        guard let buf else { return nil }
        defer { tvb_buf_free(buf) }
        let slice = tvb_buf_bytes(buf)
        guard let ptr = slice.ptr, slice.len > 0 else { return [] }
        return Array(UnsafeBufferPointer(start: ptr, count: Int(slice.len)))
    }
}

// MARK: -

extension Array where Element == UInt8 {
    /// Rule 2: a `tvb_slice` is valid only inside the closure.
    ///
    /// An empty array has no base address, so the slice is `(nil, 0)`. F-3 makes
    /// slices length-delimited and never NUL-reliant, so a null pointer with a
    /// zero length is a well-formed empty slice — **and the Rust side must
    /// accept it rather than dereferencing.** Stated here because it is the one
    /// shape a naive `from_raw_parts` gets wrong.
    @inline(__always)
    func withTVBSlice<R>(_ body: (tvb_slice) throws -> R) rethrows -> R {
        try withUnsafeBufferPointer { buffer in
            try body(tvb_slice(ptr: buffer.baseAddress, len: buffer.count))
        }
    }
}
