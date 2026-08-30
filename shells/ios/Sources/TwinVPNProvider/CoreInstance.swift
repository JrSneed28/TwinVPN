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
//  The one place the two meet is `hostVTable` below: the STRUCT is `twinvpn.h`'s
//  `tw_host_vtable` and the three function pointers put into it are the internal
//  bridge's, exported by `twinvpn-platform-ios`. That adds no entry to F-9 —
//  all three slots have existed since `TW_ABI_MINOR` 0 — and moves no version
//  number. See that property's own note for why exactly three.
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
// The ABI of record, and the INTERNAL bridge. Both, and they stay two modules:
// `TwinVPNCore` is `twinvpn.h`, a compatibility obligation forever (F-1);
// `TwinVPNBridge` is `ownership.md` §10.4's versionless per-platform bridge,
// and it is where this file gets the three vtable entries below.
import TwinVPNBridge
import TwinVPNCore

/// One core instance.
///
/// # Every `tw_core *` and `tw_buf *` in this file is an `OpaquePointer`
///
/// `twinvpn.h` declares both as INCOMPLETE C types — `typedef struct tw_core
/// tw_core;` and `typedef struct tw_buf tw_buf;`, with no definition anywhere,
/// which is what makes them opaque to a C caller by construction. Swift does
/// not import an incomplete C struct as a named type at all, so `tw_buf` is not
/// a Swift type and `UnsafeMutablePointer<tw_buf>` does not name anything;
/// Swift imports a pointer to such a type as `OpaquePointer` instead. Writing
/// the named form is what failed run 33287265563 with `cannot find type
/// 'tw_buf' in scope`. `shells/macos`'s `CoreBridge.swift` states the same rule
/// for `tvb_ext`, and it is the reason `handle` below was already spelled this
/// way while the `tw_buf` out-parameters were not.
final class CoreInstance {
    private let handle: OpaquePointer
    /// F-6/S-47: exactly one thread may hold the handle for mutation.
    private let queue = DispatchQueue(label: "net.twinvpn.core", qos: .userInitiated)
    private var drainThread: Thread?
    private let log = Logger(subsystem: "net.twinvpn.provider", category: "core")

    /// The host vtable this provider hands `tw_core_create`.
    ///
    /// **This used to be `nil`, and that was the defect.** The comment that
    /// justified it — "the adapter is linked in-process, so the core reaches the
    /// platform through `twinvpn-platform-ios` rather than back out through
    /// F-9" — is true of the INTERNAL bridge (`twinvpn_ios_bridge_register`) and
    /// false of `tw_core_create`, which has no such path: it refuses a null
    /// vtable with `PLATFORM.ADAPTER_UNAVAILABLE`, and `twinvpn-ffi`'s own
    /// `create_refuses_a_null_vtable_by_name` pins the refusal. So the
    /// production provider could never create a core.
    ///
    /// Three entries are filled and every other one is deliberately NULL:
    ///
    /// - `os_csprng`, `elapsed_millis` and `boot_id` are W-7's three
    ///   shell-supplied capabilities. They carry a byte buffer, a count and a
    ///   `u64` — no structured data — and `twinvpn-platform-ios` implements all
    ///   three against the Darwin primitives ADR-0022 LC-8's table names. **This
    ///   file installs them; it does not write them.** LC-8's trap is that
    ///   Darwin's `CLOCK_MONOTONIC` is suspend-*inclusive*, the reverse of
    ///   Linux's, and picking the wrong primitive "compiles, passes every test
    ///   that does not suspend, and fails only on a device that actually
    ///   sleeps". The Rust half is checked for both iOS triples and its refusal
    ///   path is executed on Linux; every line in this file is `written, not
    ///   compiled` (README §1). `ownership.md` §10.3.
    /// - Sockets and interface enumeration are not on F-9 **at all** — §11.2
    ///   G-11 and `twinvpn.h`'s "WHAT IS DELIBERATELY ABSENT". PB-1 budgets zero
    ///   FFI crossings per packet, and `contracts/` holds no message that can
    ///   carry `InterfaceFacts`.
    /// - Every remaining entry carries F-8 structured data, which
    ///   `twinvpn-platform-ios` cannot encode: CD-I5 keeps it free of
    ///   `twinvpn-schema`. Those capabilities are reached in-process through
    ///   `IosPlatformAdapter` over the internal bridge, which is exactly what
    ///   §10.4 rules and what `BridgeHost.register()` wires up before this runs.
    ///
    /// F-9 reads a NULL entry as NOT ATTACHED, never as a silent success, so the
    /// absences above are a **declared posture** rather than a hole.
    ///
    /// Heap-allocated once and never freed, on purpose: `twinvpn.h` says
    /// "`host` must outlive the instance", and a stack temporary would satisfy
    /// that only because `twinvpn-ffi` happens to copy the struct. One
    /// allocation for the life of the extension makes the contract literally
    /// true instead of incidentally true.
    private static let hostVTable: UnsafePointer<tw_host_vtable> = {
        let storage = UnsafeMutablePointer<tw_host_vtable>.allocate(capacity: 1)
        var vtable = tw_host_vtable()
        // F-9's whole compatibility mechanism: `sizeof` AS THIS SHELL COMPILED
        // IT, so a longer core reads only the prefix this build declares.
        vtable.size = UInt32(MemoryLayout<tw_host_vtable>.size)
        // No context. All three entries are platform capabilities rather than
        // provider-instance ones — which is why they answer before
        // `twinvpn_ios_bridge_register` has run — and Rust never dereferences it.
        vtable.ctx = nil
        vtable.os_csprng = { ctx, out, len in twinvpn_ios_os_csprng(ctx, out, len) }
        vtable.elapsed_millis = { ctx, out in twinvpn_ios_elapsed_millis(ctx, out) }
        vtable.boot_id = { ctx, out in twinvpn_ios_boot_id(ctx, out) }
        storage.initialize(to: vtable)
        return UnsafePointer(storage)
    }()

    /// PB-5 budgets this at **<= 50 ms at p95** on the iOS/iPadOS extension —
    /// "the tightest, because the OS starts the extension on demand while the
    /// user waits."
    static func create() throws -> CoreInstance {
        var error: OpaquePointer?
        let config = CoreConfiguration.encoded()
        let handle = config.withUnsafeBytes { raw -> OpaquePointer? in
            let slice = tw_slice(ptr: raw.bindMemory(to: UInt8.self).baseAddress, len: raw.count)
            return tw_core_create(tw_abi_major(), hostVTable, slice, &error)
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
            var error: OpaquePointer?
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
                var event: OpaquePointer?
                var error: OpaquePointer?
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

    static func decode(_ buffer: OpaquePointer?) -> Data {
        guard let buffer else { return Data() }
        defer { tw_buf_free(buffer) }
        let slice = tw_buf_bytes(buffer)
        guard let ptr = slice.ptr else { return Data() }
        return Data(bytes: ptr, count: slice.len)
    }
}
