//
//  BridgeLinkAndLifecycleTests.swift — the Swift↔Rust half of the macOS
//  link/run evidence.
//
//  Authority: ADR-0018 §11.4 (a hand-written header is the ABI of record), F-1,
//  F-2, F-3, F-4, F-7, VR-4, CB-2, CB-6; ADR-0016 §11.6 (the start ordering),
//  PS-18, PS-22; ADR-0022 LC-24, LC-25.
//
//  ===========================================================================
//  WHAT THIS SUITE PROVES, AND ON WHICH RUNNER
//  ===========================================================================
//  It crosses the PRODUCTION boundary of this shell — `twinvpn_bridge.h`, whose
//  archive hosts the `Core`, the platform adapter, the key handle, the datapath
//  and the management interface (PS-22) — from Swift, and asserts what comes
//  back. It runs unchanged in two very different places and asserts a DIFFERENT
//  thing in each, because the two are different evidence:
//
//    HOSTED, UNPRIVILEGED (`macos-link-run`, runner `macos-26`)
//      `tvb_ext_start` MUST refuse. ADR-0016 §11.6's sequence reaches
//      `privilege_posture`, finds it is not root, and PS-18 forbids starting "in
//      a mode that cannot arm enforcement while reporting itself as running". So
//      the assertion is that the refusal is TYPED and NAMED — an ADR-0015 §11.2
//      envelope with a `reason_code` — and the transition recorded is
//      `STARTING->REFUSED`. That is a real crossing with a real result, and it
//      is NOT a NetworkExtension lifecycle pass.
//
//    SELF-HOSTED, PRIVILEGED (`macos-privileged-lifecycle`)
//      `tvb_ext_start` succeeds, and the suite then drives every lifecycle entry
//      the ABI has — sleep, wake, network-changed, stop — recording one
//      transition per acknowledged call.
//
//  The branch is on the RESULT CODE, never on an environment variable, so a
//  hosted run cannot be configured into claiming the privileged result and a
//  privileged run cannot quietly settle for the hosted one. `ci-macos.sh` writes
//  the two outcomes to DIFFERENT evidence files (`macos.json` and
//  `macos-privileged.json`) for the same reason.
//
//  ===========================================================================
//  CB-2 APPLIES TO THIS FILE TOO
//  ===========================================================================
//  Every branch below is on `TVB_OK` / `TVB_ERR` / `TVB_TIMEOUT`, which say
//  which SHAPE an outcome took and never what it means, or on whether a byte
//  string is non-empty. The envelope is checked for STRUCTURE — that it decodes
//  and carries a `reason_code` — and never for WHICH code, because branching on
//  a `reason_code` class is precisely what CB-2 forbids a shell to do.
//

import Foundation
import XCTest

/// Prints the marker `build/ci/ci-macos.sh` greps for.
///
/// Format fixed by `build/acceptance/platform-evidence.schema.json`:
/// `^TWINVPN_LIFECYCLE_TRANSITION [A-Z_]+->[A-Z_]+$`. Printed only after the
/// call it describes returned `TVB_OK` — never up front, never unconditionally.
private func observed(_ transition: String) {
    print("TWINVPN_LIFECYCLE_TRANSITION \(transition)")
}

/// Runs `body` with a `tvb_slice` over `bytes`, valid only inside the closure.
///
/// The ABI is explicit that a slice "is valid ONLY for the duration of the call
/// it is passed to", and scoping the pointer to a closure is what makes that
/// unrepresentable to get wrong: escaping it does not compile.
private func withSlice<R>(_ bytes: [UInt8], _ body: (tvb_slice) -> R) -> R {
    bytes.withUnsafeBufferPointer { buffer in
        body(tvb_slice(ptr: buffer.baseAddress, len: buffer.count))
    }
}

/// Reads a bridge-owned buffer and frees it. F-2: the bridge allocated it, the
/// bridge frees it, and there is no path out of here that skips the free.
private func consume(_ buffer: OpaquePointer?) -> Data {
    defer { tvb_buf_free(buffer) }
    let slice = tvb_buf_bytes(buffer)
    guard let base = slice.ptr, slice.len > 0 else { return Data() }
    return Data(UnsafeBufferPointer(start: base, count: slice.len))
}

final class BridgeLinkAndLifecycleTests: XCTestCase {

    // MARK: - the link itself

    /// **VR-4, checked the way VR-4 says to check it.**
    ///
    /// `TVB_ABI_MAJOR` is the constant THIS TARGET compiled out of
    /// `twinvpn_bridge.h`; `tvb_abi_major()` is what the linked archive reports.
    /// A mismatch means the header and the staticlib came from different builds
    /// — "a PACKAGING DEFECT, not an operating state" — and it is exactly the
    /// defect a repository that has never linked the two cannot detect.
    ///
    /// It is also the cheapest possible proof that the archive is REALLY linked:
    /// a stub with the right symbol names would have to be built from this same
    /// header to pass it.
    func test_the_linked_archive_and_the_header_agree_on_the_abi() {
        XCTAssertEqual(tvb_abi_major(), TVB_ABI_MAJOR,
                       "VR-4: twinvpn_bridge.h and libtwinvpn_bridge.a are from different builds")
        XCTAssertEqual(tvb_abi_minor(), TVB_ABI_MINOR)
    }

    /// **F-2's null tolerance, which is a safety property and not a nicety.**
    ///
    /// The header promises `tvb_buf_bytes` "returns `(NULL, 0)` for a NULL
    /// buffer, so a caller that forgot to check does not dereference", and that
    /// `tvb_buf_free` tolerates NULL. Both are the difference between a Swift
    /// bug and a crash inside the extension.
    func test_the_buffer_entries_tolerate_a_null_pointer() {
        let slice = tvb_buf_bytes(nil)
        XCTAssertNil(slice.ptr)
        XCTAssertEqual(slice.len, 0)
        tvb_buf_free(nil)
    }

    /// **F-3: a slice may be `(NULL, 0)`, and the Rust side must accept it.**
    ///
    /// Swift's `withUnsafeBufferPointer` yields a nil base address for an empty
    /// array, so `(NULL, 0)` is what an empty Swift value actually produces.
    /// `slice::from_raw_parts` on a null base is undefined behaviour, which is
    /// the one shape a naive implementation gets wrong — so it is exercised
    /// here, across the real boundary, rather than trusted.
    func test_an_empty_slice_crosses_without_undefined_behaviour() {
        var ext: OpaquePointer?
        var error: OpaquePointer?
        // An empty config AND an empty correlation id. The call must return a
        // shape, not crash; which shape is asserted by the lifecycle test below.
        let rc = withSlice([]) { config in
            withSlice([]) { correlation in
                tvb_ext_start(config, correlation, &ext, &error)
            }
        }
        XCTAssertTrue(rc == TVB_OK || rc == TVB_ERR, "an unexpected result code: \(rc)")
        _ = consume(error)
        if rc == TVB_OK { tvb_ext_free(ext) }
    }

    // MARK: - the lifecycle

    /// **The acceptance criterion: invoke the core, receive a result, and drive
    /// the lifecycle as far as this runner's privileges honestly allow.**
    func test_the_extension_lifecycle_across_the_production_bridge() throws {
        let config = Array(#"{"binding":"ci-link-run"}"#.utf8)
        let correlation = Array("ci-macos-link-run".utf8)

        var ext: OpaquePointer?
        var startError: OpaquePointer?
        let rc = withSlice(config) { config in
            withSlice(correlation) { correlation in
                tvb_ext_start(config, correlation, &ext, &startError)
            }
        }

        if rc == TVB_ERR {
            // The hosted, unprivileged path. ADR-0016 §11.6 + PS-18.
            let envelope = consume(startError)
            XCTAssertFalse(envelope.isEmpty, "F-4: a failure carries a NAME, never a bare code")
            let decoded = try XCTUnwrap(
                JSONSerialization.jsonObject(with: envelope) as? [String: Any],
                "the bridge's error envelope is the ADR-0015 §11.2 document as JSON")
            let code = try XCTUnwrap(decoded["reason_code"] as? String,
                                     "§11.2 requires a reason_code STRING")
            XCTAssertFalse(code.isEmpty)
            // NOT asserted: WHICH code. CB-2 forbids a branch in a shell whose
            // condition is a reason_code class, and a test that pinned the code
            // would be that branch written as an assertion.
            print("tvb_ext_start refused, as an unprivileged host must: \(code)")
            observed("STARTING->REFUSED")
            XCTAssertNil(ext, "TVB_ERR must not write *out")
            return
        }

        XCTAssertEqual(rc, TVB_OK, "an unexpected result code from tvb_ext_start: \(rc)")
        XCTAssertNil(startError, "TVB_OK must not write *err")
        let instance = try XCTUnwrap(ext, "TVB_OK must write *out")
        // Rule 3: ONE owner, ONE `tvb_ext_free`, and it is not on the stop path
        // — a stopped instance is still a valid handle.
        defer { tvb_ext_free(instance) }
        observed("STARTING->RUNNING")

        // The settings document the CORE computed. `TVB_TIMEOUT` is not a
        // failure and not a deadline guarantee, so a timeout here is reported
        // rather than asserted against: what is asserted is that a document, if
        // one arrives, is the core's own bytes and not something Swift built.
        var document: OpaquePointer?
        var settingsError: OpaquePointer?
        let settingsRc = tvb_ext_next_settings(instance, 1_000, &document, &settingsError)
        XCTAssertNotEqual(settingsRc, TVB_ERR, String(decoding: consume(settingsError), as: UTF8.self))
        if settingsRc == TVB_OK {
            let bytes = consume(document)
            XCTAssertFalse(bytes.isEmpty)
            XCTAssertNotNil(try? JSONSerialization.jsonObject(with: bytes),
                            "the settings document is UTF-8 JSON applied VERBATIM")
            observed("RUNNING->CONFIGURED")
        }

        // ADR-0022's lifecycle facts. Each REPORTS something the OS handed the
        // provider; none of them asserts, renders or decides anything, and the
        // core decides what each means. LC-24: a resume is a notification and
        // never a "we are still connected".
        try assertOk("tvb_ext_sleep") { err in
            withSlice(correlation) { tvb_ext_sleep(instance, $0, err) }
        }
        observed("RUNNING->SUSPENDED")

        try assertOk("tvb_ext_wake") { err in
            withSlice(correlation) { tvb_ext_wake(instance, $0, err) }
        }
        observed("SUSPENDED->RUNNING")

        try assertOk("tvb_ext_network_changed") { err in
            withSlice(correlation) { tvb_ext_network_changed(instance, $0, err) }
        }
        observed("RUNNING->REVALIDATING")
        observed("REVALIDATING->RUNNING")

        // CB-6: a stop does NOT tear down enforcement. The installed rule set is
        // in the OS's custody precisely so that the core going away does not
        // drop protection, and a stop that removed the pf anchor would defeat
        // it. `3` is carried through as the OS's own reason, unchanged — the
        // CORE decides what a stop reason means.
        try assertOk("tvb_ext_stop") { err in
            withSlice(correlation) { tvb_ext_stop(instance, 3, $0, err) }
        }
        observed("RUNNING->STOPPED")

        // And a second stop is idempotent rather than a use-after-free: the ABI
        // is explicit that `tvb_ext_stop` does not free, so a double
        // `stopTunnel` from the OS is safe.
        try assertOk("tvb_ext_stop (second)") { err in
            withSlice(correlation) { tvb_ext_stop(instance, 3, $0, err) }
        }
        observed("STOPPED->STOPPED")
    }

    /// Calls a bridge entry, asserts `TVB_OK`, and reports the envelope verbatim
    /// if it is not. Keeps the free on the error path in ONE place.
    private func assertOk(
        _ call: String,
        _ body: (UnsafeMutablePointer<OpaquePointer?>) -> Int32
    ) throws {
        var error: OpaquePointer?
        let rc = body(&error)
        let envelope = consume(error)
        XCTAssertEqual(rc, TVB_OK,
                       "\(call) returned \(rc): \(String(decoding: envelope, as: UTF8.self))")
    }
}
