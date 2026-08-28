//  CoreInstance.swift — the `twinvpn.h` ABI of record, wrapped.
//
//  Authority: ADR-0018 §11.4 (F-1…F-10), §11.5's iOS rows, §11.6, PB-5;
//  ADR-0015 §11.2.1 (`INTERNAL.CORE_PANIC`).
//
//  STATUS: written, not compiled.
//
//  ===========================================================================
//  THIS IS THE ABI OF RECORD, AND THIS FILE ONLY WRAPS IT
//  ===========================================================================
//
//  Unlike `BridgeHost.swift`, which fills an INTERNAL bridge that
//  `ownership.md` §10.4 makes versionless, everything here crosses `twinvpn.h`.
//  F-1: "Every exported function is a compatibility obligation forever." Nothing
//  in this shell adds to it; `core-composition` owns it.
//
//  F-5's async model is "submit + one ordered event stream": `tw_core_submit` is
//  non-blocking, and the only blocking call is `tw_core_next_event` with an
//  explicit timeout, cancellable via `tw_core_wake`. That is why every `submit*`
//  below returns nothing and why there is exactly one drain loop.
//
//  F-6's threading: "a `tw_core*` is `Send` but not `Sync` for mutating calls:
//  exactly one thread may hold it for mutation at a time (S-47)." The serial
//  queue below is that thread, and there is only one.
//
//  F-8: "only handles, slices and scalars cross; structured data crosses as
//  encoded bytes." So every command and every event here is a `Data`, encoded
//  from `contracts/`. This file never inspects one.

import Foundation
import os
import TwinVPNCore

/// One core instance.
final class CoreInstance {
    private let handle: OpaquePointer
    /// F-6/S-47: exactly one thread may hold the handle for mutation.
    private let queue = DispatchQueue(label: "net.twinvpn.core", qos: .userInitiated)
    private var drainThread: Thread?
    private let log = Logger(subsystem: "net.twinvpn.provider", category: "core")

    /// PB-5 budgets this at **<= 50 ms at p95** on the iOS/iPadOS extension —
    /// "the tightest, because the OS starts the extension on demand while the
    /// user waits."
    static func create() throws -> CoreInstance {
        var error: UnsafeMutablePointer<tw_buf>?
        let config = CoreConfiguration.encoded()
        let handle = config.withUnsafeBytes { raw -> OpaquePointer? in
            let slice = tw_slice(ptr: raw.bindMemory(to: UInt8.self).baseAddress, len: raw.count)
            // The host vtable is `nil`: on this platform the adapter is linked
            // in-process as a Rust crate (ownership.md §10.4), so the core
            // reaches the platform through `twinvpn-platform-ios` directly
            // rather than back out through F-9. That is the whole substance of
            // the §10.4 ruling, and it is why W-24 and W-25 do not block this
            // shell — while remaining OPEN as ABI defects.
            tw_core_create(tw_abi_major(), nil, slice, &error)
        }
        guard let handle else {
            // F-4: the failure is an encoded `{reason_code, evidence, resolved}`,
            // never an errno and never a bool. It is rendered, not parsed here.
            throw CoreError.creationRefused(CoreError.decode(error))
        }
        return CoreInstance(handle: handle)
    }

    private init(handle: OpaquePointer) {
        self.handle = handle
    }

    // MARK: - submit

    func submitStart(options: [String: NSObject]?) {
        submit(CoreCommand.start(options))
    }

    func submitStopReason(_ raw: Int) {
        // The RAW value. `twinvpn_platform_ios::lifecycle::ProviderStopReason`
        // decodes it in Rust, where an unknown value is carried as
        // `Unknown(raw)` rather than coerced — "a stop this build cannot name is
        // not evidence of an orderly one", and `clean_shutdown` must not be set
        // for it.
        submit(CoreCommand.stopReason(raw))
    }

    func submitSleep() { submit(CoreCommand.sleep) }
    func submitWake() { submit(CoreCommand.wake) }
    func submitPacketsAvailable() { submit(CoreCommand.packetsAvailable) }
    func submitMemoryPressure(residentBytes: UInt64) {
        submit(CoreCommand.memoryPressure(residentBytes))
    }

    /// Delivers one `NWPathMonitor` snapshot.
    ///
    /// §11.16 (h): at the C ABI the subscription is satisfied by "an inbound
    /// command submission rather than a literal outbound function pointer" —
    /// which is exactly `NWPathMonitor`'s own shape.
    func submitPathSnapshot(_ json: String, acrossWake: Bool) {
        submit(CoreCommand.pathSnapshot(json, acrossWake: acrossWake))
    }

    private func submit(_ command: Data) {
        queue.async { [handle] in
            var error: UnsafeMutablePointer<tw_buf>?
            _ = command.withUnsafeBytes { raw in
                tw_core_submit(
                    handle,
                    tw_slice(ptr: raw.bindMemory(to: UInt8.self).baseAddress, len: raw.count),
                    &error)
            }
            // F-5: "rejected commands produce an event, never a silent drop", so
            // there is nothing to handle here — the rejection arrives on the
            // stream like everything else.
            if let error { tw_buf_free(error) }
        }
    }

    // MARK: - the management channel

    /// ADR-0017's request/response, carried opaquely.
    ///
    /// MI-15 forbids rendered text on this channel, and this method could not
    /// produce any if it wanted to: it moves bytes.
    func handleManagementRequest(_ request: Data) -> Data? {
        submit(CoreCommand.managementRequest(request))
        return nil
    }

    // MARK: - drain

    /// F-5's single ordered event stream.
    ///
    /// One loop, one thread. `tw_core_next_event` takes an explicit timeout and
    /// is cancellable via `tw_core_wake`, which is what `destroy()` uses rather
    /// than killing the thread.
    func startDraining(_ handler: @escaping (CoreEvent) -> Void) {
        let thread = Thread { [handle] in
            while !Thread.current.isCancelled {
                var event: UnsafeMutablePointer<tw_buf>?
                var error: UnsafeMutablePointer<tw_buf>?
                let rc = tw_core_next_event(handle, 1_000, &event, &error)
                if let event {
                    handler(CoreEvent.decode(event))
                    tw_buf_free(event)
                }
                if let error { tw_buf_free(error) }
                if rc < 0 { break }
            }
        }
        thread.name = "net.twinvpn.core.events"
        thread.start()
        drainThread = thread
    }

    func flush(withinMilliseconds milliseconds: Int) {
        submit(CoreCommand.flush)
        // ADR-0022 LC-25: pre-sleep is a FLUSH, never a teardown. The bound is
        // §11.4's iOS row's, and exceeding it is the OS's to punish.
        queue.sync {}
    }

    func destroy() {
        drainThread?.cancel()
        tw_core_wake(handle)
        queue.sync {}
        tw_core_destroy(handle)
    }
}

enum CoreError: Error {
    /// F-4's encoded failure, undecoded. It is RENDERED through
    /// `tw_render_diagnostic` (F-10) at the surface that has a locale, never
    /// turned into a sentence here.
    case creationRefused(Data)

    static func decode(_ buffer: UnsafeMutablePointer<tw_buf>?) -> Data {
        guard let buffer else { return Data() }
        defer { tw_buf_free(buffer) }
        let slice = tw_buf_bytes(buffer)
        guard let ptr = slice.ptr else { return Data() }
        return Data(bytes: ptr, count: slice.len)
    }
}
