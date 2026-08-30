//
//  CoreBridgeIntegrationTests.swift — the SIMULATOR-runnable half of the iOS
//  link/run evidence.
//
//  Authority: ADR-0018 §11.4 (`twinvpn.h` is the ABI of record), §11.9 row 1
//  (the core reaches iOS as a `staticlib` linked into the extension), F-1, F-4,
//  F-5, F-8, F-10, VR-4; ADR-0018 §11.16 (e) (lifecycle is delivered as
//  SUSPEND / RESUME / BACKGROUND / FOREGROUND commands, and the core holds no
//  OS lifecycle assumption of its own); ADR-0022 §11.12 (P21).
//
//  ===========================================================================
//  WHAT THIS SUITE IS, AND WHAT `TwinVPNTests` IS
//  ===========================================================================
//  Two suites, two kinds of evidence, and they must never be conflated.
//
//    TwinVPNIntegrationTests (this one)  runs on the SIMULATOR. It proves that
//      the real shared-core staticlib LINKED, LOADED, that the production
//      `twinvpn.h` boundary was CROSSED, that a RESULT came back through it,
//      and that the core accepted and completed the four lifecycle phase
//      transitions ADR-0018 §11.16 (e) names.
//
//    TwinVPNTests                        runs only on a PHYSICAL DEVICE and
//      skips itself on the simulator (`XCTSkipUnless(DeviceCapabilities.
//      isPhysicalDevice)`). It is the NetworkExtension-activation, jetsam,
//      leak-capture suite, and nothing here stands in for it.
//
//  A green run of this file is NOT a NetworkExtension lifecycle pass. The
//  simulator has no `includeAllNetworks`, no Secure Enclave, no jetsam, and no
//  provisioning profile; `build/ci/jobs/ios-device-lifecycle.yml` is where that
//  claim lives and it is a different job on different hardware.
//
//  ===========================================================================
//  THE HOST VTABLE IS THE PRODUCTION ONE — AND THAT IS A FIX
//  ===========================================================================
//  `tw_core_create` REFUSES a null `tw_host_vtable` with
//  `PLATFORM.ADAPTER_UNAVAILABLE` — `twinvpn-ffi`'s own
//  `create_refuses_a_null_vtable_by_name` asserts exactly that. So a core
//  instance cannot exist without one.
//
//  **The finding this file used to carry is CLOSED.**
//  `Sources/TwinVPNProvider/CoreInstance.swift` passed `nil` for that vtable,
//  commenting that the adapter is reached in-process through
//  `twinvpn-platform-ios`. That is true of the INTERNAL bridge
//  (`twinvpn_ios_bridge_register`) and was NOT true of `tw_core_create`, which
//  has no such path: with `nil` it could only ever return NULL, so the shipping
//  provider could never create a core.
//
//  It now installs three entries backed by `twinvpn_platform_ios::hostvtable` —
//  `os_csprng`, `elapsed_millis` and `boot_id`, W-7's three shell-supplied
//  capabilities and exactly what `twinvpn-ffi`'s `env::assemble` requires — and
//  leaves every other entry NULL for a RULED reason: sockets and interface
//  enumeration are not on F-9 at all (§11.2 G-11), and every remaining entry
//  carries F-8 structured data that `twinvpn-platform-ios` has no
//  `twinvpn-schema` dependency to encode (CD-I5). F-9's rule is that a NULL
//  entry reads as NOT ATTACHED, never as a silent success, so what the core then
//  does with a `net.up` is a REAL refusal computed by real core code, and that
//  is precisely the result this suite reads back.
//
//  **This suite now exercises that same vtable**, out of the same archive, over
//  the same internal bridge. It previously built its own from three Swift
//  functions, which made it green over a path the product did not take.
//  NO F-9 ENTRY WAS ADDED AND `TW_ABI_MINOR` DID NOT MOVE.
//
//  ===========================================================================
//  THE TRANSITION MARKERS
//  ===========================================================================
//  `build/ci/ci-ios.sh` reads `TWINVPN_LIFECYCLE_TRANSITION <FROM>-><TO>` lines
//  out of this suite's own output and puts them in the evidence file. Every
//  marker below is printed ONLY after the confirming `command.completed` event
//  has been read back off the core's event stream — never on the strength of a
//  submission returning `TW_OK`, and never unconditionally. A marker that is
//  printed whether or not the core did anything is the "compile-only job
//  dressed as a lifecycle job" the acceptance gate exists to reject.
//

import Foundation
import XCTest

// The ABI OF RECORD, over `Sources/TwinVPNBridge/include/module.modulemap`.
// `twinvpn.h` is STAGED into that directory by `Scripts/stage-headers.sh`; it is
// not committed, because a second copy of an ABI of record is a second thing
// that can drift from it.
import TwinVPNCore

// The INTERNAL bridge (`ownership.md` §10.4) — versionless, no compatibility
// obligation, and in the SAME archive as `twinvpn.h`'s symbols. It is where the
// three `tw_host_vtable` entries `twinvpn-platform-ios` backs are declared.
import TwinVPNBridge

// ===========================================================================
// MARK: - The host binding — THE PRODUCTION ONE
// ===========================================================================

/// The vtable this suite hands `tw_core_create`, and it is **the same one the
/// shipping provider hands it**.
///
/// This file used to build its own: three Swift functions over
/// `clock_gettime_nsec_np`, `arc4random_buf` and `kern.bootsessionuuid`. That
/// made the suite green while `Sources/TwinVPNProvider/CoreInstance.swift`
/// passed `nil` and could not create a core at all — a link/run job proving a
/// path the product does not take, which is the shape of evidence the
/// acceptance gate exists to reject.
///
/// The three entries below are now `twinvpn_platform_ios::hostvtable`'s,
/// resolved out of the same `libtwinvpn_core.a` this target links, over the
/// internal bridge. `CoreInstance.hostVTable` installs the identical three
/// symbols; nothing here stands in for them, and if the Rust half regresses,
/// this suite is what goes red.
///
/// **The duplication is of the INSTALLATION, never of the IMPLEMENTATION.** It
/// is unavoidable for the reason the `Frame` type below records: an
/// app-extension target cannot be linked into a test bundle and there is no
/// framework target to share.
///
/// Everything except the three is NULL and is meant to be. F-9 reads a NULL
/// entry as NOT ATTACHED, so what the core then does with a `net.up` is a REAL
/// refusal computed by real core code, which is precisely the result this suite
/// reads back — and `CoreInstance.hostVTable` documents why each absence is a
/// ruling (G-11, F-8, CD-I5) rather than a gap.
private func productionHostVTable() -> tw_host_vtable {
    var vtable = tw_host_vtable()
    // `size` is `sizeof(tw_host_vtable)` AS THIS TARGET COMPILED IT, which is
    // what F-9's first field means and what lets the core read only the entries
    // a shorter shell declared.
    vtable.size = UInt32(MemoryLayout<tw_host_vtable>.size)
    vtable.ctx = nil
    vtable.os_csprng = { ctx, out, len in twinvpn_ios_os_csprng(ctx, out, len) }
    vtable.elapsed_millis = { ctx, out in twinvpn_ios_elapsed_millis(ctx, out) }
    vtable.boot_id = { ctx, out in twinvpn_ios_boot_id(ctx, out) }
    return vtable
}

// ===========================================================================
// MARK: - The MI frame
// ===========================================================================

/// The framed submission form `tw_core_submit` documents.
///
/// A 4-byte BIG-ENDIAN length prefix and that many bytes of UTF-8 JSON, exactly
/// as the Unix socket, the named pipe and XPC carry it (MI-20: one contract,
/// several carriages).
///
/// This deliberately duplicates `Sources/TwinVPNShared/MIWire.swift`'s `MIFrame`
/// and `Sources/TwinVPNProvider/CoreProtocol.swift`'s `CoreCommand`, because an
/// app-extension target cannot be linked into a test bundle and there is no
/// framework target to share. The duplication is a real cost and it is named
/// rather than hidden: if `MIWire.swift` and this file ever disagree about the
/// frame, the core rejects one of them with `PROTO.MALFORMED_MESSAGE` and the
/// suite goes red, which is the failure mode worth having.
///
/// **The frame half of that cost is now removable.** `MIFrame` moved out of the
/// extension target and into `Sources/TwinVPNShared`, which is a SOURCE LIST and
/// not a framework — so this bundle can list that directory in `project.yml` and
/// delete the `request` below. It is left as-is in the change that made the move,
/// because taking it would edit a suite that produces the `build/ci/evidence`
/// link/run record, and that belongs in its own reviewed change rather than as a
/// side effect of one.
private enum Frame {
    static func request(_ operation: String, params: [UInt8] = []) -> Data {
        let object: [String: Any] = [
            "mi_version": 1,
            "request_id": [],
            "correlation_id": [],
            "seq": 0,
            "idempotency_key": [],
            "as_of_ms": 0,
            "body": [
                "kind": "request",
                "operation": operation,
                "params": params,
            ],
        ]
        let body = try! JSONSerialization.data(withJSONObject: object)
        var out = Data(capacity: body.count + 4)
        out.append(contentsOf: withUnsafeBytes(of: UInt32(body.count).bigEndian, Array.init))
        out.append(body)
        return out
    }
}

/// `host.lifecycle`'s ONE-BYTE phase selector.
///
/// `twinvpn-core`'s `dispatch::Lifecycle::from_params` reads `params.first()`
/// and maps 1/2/3/4 to SUSPEND/RESUME/BACKGROUND/FOREGROUND; anything else is
/// `None`, which `missing_parameter` turns into `PROTO.MALFORMED_MESSAGE`. It is
/// deliberately not a defaulted decode — "defaulting to FOREGROUND would wake a
/// device that asked to sleep".
private enum Phase: UInt8, CaseIterable {
    case suspend = 1
    case resume = 2
    case background = 3
    case foreground = 4

    /// The transition this phase drives, as the evidence file records it.
    var transition: String {
        switch self {
        case .suspend:    return "RUNNING->SUSPENDED"
        case .resume:     return "SUSPENDED->RUNNING"
        case .background: return "FOREGROUND->BACKGROUND"
        case .foreground: return "BACKGROUND->FOREGROUND"
        }
    }
}

/// Prints one transition marker. `build/ci/ci-ios.sh` greps for exactly this.
private func recordTransition(_ transition: String) {
    print("TWINVPN_LIFECYCLE_TRANSITION \(transition)")
}

// ===========================================================================
// MARK: - The suite
// ===========================================================================

final class CoreBridgeIntegrationTests: XCTestCase {

    // MARK: instance-free entry points

    /// VR-4, checked the way VR-4 says to check it.
    ///
    /// `TW_ABI_MAJOR` is the constant THIS TARGET compiled from `twinvpn.h`;
    /// `tw_abi_major()` is what the linked archive reports. A mismatch is a
    /// packaging defect — the header and the staticlib came from different
    /// commits — and it is exactly the defect a repository that has never
    /// linked the two cannot detect.
    func test_the_linked_archive_and_the_staged_header_agree_on_the_abi() {
        XCTAssertEqual(tw_abi_major(), TW_ABI_MAJOR,
                       "VR-4: the staticlib and the staged twinvpn.h are from different builds")
        XCTAssertEqual(tw_abi_minor(), TW_ABI_MINOR)
        XCTAssertGreaterThan(tw_reason_registry_version(), 0)
    }

    /// S-46 `CoreBuildIdentity`, read out of the artifact that was linked.
    ///
    /// This is the check that says WHICH core is in the binary. The value is
    /// "fixed at build time" and "immutable within an artifact", so a non-empty
    /// answer here is proof that a real, built core is linked in — a stub with
    /// the right symbol names would have nothing to report.
    func test_the_linked_core_reports_its_own_build_identity() {
        let identity = tw_build_identity()
        XCTAssertNotNil(identity.ptr, "S-46: the artifact must report its own identity")
        XCTAssertGreaterThan(identity.len, 0)
        // NOT freed: `twinvpn.h` says static storage, never freed. Passing it to
        // `tw_buf_free` would be a defect, and saying so here is cheaper than
        // finding out at run time.
    }

    /// F-10 — the one entry point that is pure and instance-free.
    ///
    /// Called with an EMPTY `platform_ctx`, which ADR-0019 LT-3b requires to
    /// resolve to the platform-neutral variant rather than falling back to the
    /// host's own platform. This is real core computation across the production
    /// boundary with no instance in existence, so it isolates "the archive is
    /// linked and its code runs" from anything about lifecycle.
    func test_a_diagnostic_renders_with_no_instance_in_existence() {
        let code = Array("PLATFORM.VPN_PERMISSION_DENIED".utf8)
        let locale = Array("en-GB".utf8)
        let rendered: OpaquePointer? = code.withUnsafeBufferPointer { c in
            locale.withUnsafeBufferPointer { l in
                tw_render_diagnostic(
                    tw_slice(ptr: c.baseAddress, len: c.count),
                    tw_slice(ptr: nil, len: 0),
                    tw_slice(ptr: l.baseAddress, len: l.count),
                    tw_slice(ptr: nil, len: 0))
            }
        }
        XCTAssertNotNil(rendered, "F-10: NEVER returns NULL — an unparseable code still renders")
        let bytes = tw_buf_bytes(rendered)
        XCTAssertGreaterThan(bytes.len, 0)
        tw_buf_free(rendered)
    }

    // MARK: the instance, and the lifecycle

    /// The whole acceptance criterion in one test: LINK, LOAD, INVOKE, RECEIVE,
    /// TRANSITION, SHUT DOWN.
    ///
    /// Every step asserts, and the transition markers are printed only from the
    /// event stream — see this file's header.
    func test_the_core_accepts_and_completes_every_lifecycle_phase() throws {
        var vtable = productionHostVTable()
        var createError: OpaquePointer?

        // CONFIG IS EMPTY, and that is CD-2 rather than laziness: configuration
        // is injected at construction and the core validates the blob against
        // `limits.json`. An empty blob is the "nothing configured" case, which is
        // what a freshly installed app has.
        let core = withUnsafePointer(to: &vtable) { host in
            tw_core_create(tw_abi_major(), host, tw_slice(ptr: nil, len: 0), &createError)
        }

        if core == nil {
            // F-4: the failure carries a NAME. Report it rather than a bare nil,
            // because "the core refused" and "the archive did not link" look
            // identical from an XCTAssertNotNil.
            let bytes = tw_buf_bytes(createError)
            let text = bytes.ptr.map {
                String(decoding: UnsafeBufferPointer(start: $0, count: bytes.len), as: UTF8.self)
            } ?? "<no envelope>"
            tw_buf_free(createError)
            XCTFail("tw_core_create refused: \(text)")
            return
        }
        XCTAssertNil(createError, "tw_core_create must not write an envelope on success")
        defer { tw_core_destroy(core) }

        // Drain whatever the core published while constructing, so the
        // completions below cannot be confused with a start-up diagnostic. The
        // `PLATFORM.ADAPTER_UNAVAILABLE` diagnostic this binding provokes is
        // EXPECTED — F-9 reads a NULL entry as NOT ATTACHED and the core says so
        // out loud rather than pretending an adapter is present.
        drainEvents(core, upTo: 8)

        // ADR-0018 §11.16 (e)'s four phases, each submitted and each confirmed
        // by its own `command.completed` before its marker is printed.
        for phase in Phase.allCases {
            var submitError: OpaquePointer?
            let framed = Frame.request("host.lifecycle", params: [phase.rawValue])
            let rc = framed.withUnsafeBytes { raw -> Int32 in
                tw_core_submit(
                    core,
                    tw_slice(ptr: raw.bindMemory(to: UInt8.self).baseAddress, len: raw.count),
                    &submitError)
            }
            tw_buf_free(submitError)
            XCTAssertEqual(rc, TW_OK, "host.lifecycle(\(phase)) was rejected at submission")

            let completed = awaitCompletion(core, of: "host.lifecycle")
            XCTAssertTrue(completed,
                          "the core acknowledged no completion for host.lifecycle(\(phase))")
            if completed { recordTransition(phase.transition) }
        }

        // `net.down` — ADR-0022 LC-25's pre-sleep FLUSH, which is not a teardown:
        // CB-6 leaves the installed rule set in the OS's custody, so the core
        // going away does not drop protection. It is the last transition this
        // suite drives and the one that makes the shutdown below graceful rather
        // than abrupt.
        var downError: OpaquePointer?
        let down = Frame.request("net.down")
        let downRc = down.withUnsafeBytes { raw -> Int32 in
            tw_core_submit(
                core,
                tw_slice(ptr: raw.bindMemory(to: UInt8.self).baseAddress, len: raw.count),
                &downError)
        }
        tw_buf_free(downError)
        XCTAssertEqual(downRc, TW_OK)
        if awaitCompletion(core, of: "net.down") {
            recordTransition("READY->STOPPED")
        } else {
            XCTFail("the core acknowledged no completion for net.down")
        }
    }

    /// F-5: "rejected commands produce an event, never a silent drop."
    ///
    /// A phase byte the core does not recognise MUST be a typed rejection, and
    /// it MUST NOT be defaulted to a phase. This is the negative control for the
    /// test above: without it, a core that accepted anything would look
    /// identical to one that decoded the selector.
    func test_an_unrecognised_lifecycle_phase_is_refused_by_name() throws {
        var vtable = productionHostVTable()
        var createError: OpaquePointer?
        let core = withUnsafePointer(to: &vtable) { host in
            tw_core_create(tw_abi_major(), host, tw_slice(ptr: nil, len: 0), &createError)
        }
        tw_buf_free(createError)
        let instance = try XCTUnwrap(core, "tw_core_create refused")
        defer { tw_core_destroy(instance) }
        drainEvents(instance, upTo: 8)

        var submitError: OpaquePointer?
        // 0x62 is 'b' — the first byte of the string "background", which is what
        // `CoreProtocol.swift` sends today. It is NOT a valid selector.
        let framed = Frame.request("host.lifecycle", params: [0x62])
        let rc = framed.withUnsafeBytes { raw -> Int32 in
            tw_core_submit(
                core,
                tw_slice(ptr: raw.bindMemory(to: UInt8.self).baseAddress, len: raw.count),
                &submitError)
        }
        XCTAssertEqual(rc, TW_ERR, "an unrecognised phase must be refused, never defaulted")
        XCTAssertNotNil(submitError, "F-4: the refusal carries a name")
        tw_buf_free(submitError)
    }

    // MARK: - the event stream

    /// Reads events until one is `command.completed` for `operation`.
    ///
    /// F-5's model is "submit + one ordered event stream", so a completion is
    /// found by READING, never by assuming. The `op` member is on the wire
    /// specifically because this ABI is fire-and-forget and a shell here has
    /// nothing else to correlate a completion against.
    private func awaitCompletion(_ core: OpaquePointer?, of operation: String) -> Bool {
        for _ in 0..<32 {
            guard let body = nextEventBody(core) else { continue }
            if body["topic"] as? String == "command.completed",
               body["op"] as? String == operation {
                return true
            }
            if body["topic"] as? String == "command.rejected",
               body["op"] as? String == operation {
                return false
            }
        }
        return false
    }

    /// Reads and discards up to `count` already-published events, stopping at
    /// the first timeout. Used once, after construction, so a start-up
    /// diagnostic cannot be mistaken for a lifecycle completion.
    private func drainEvents(_ core: OpaquePointer?, upTo count: Int) {
        for _ in 0..<count {
            if nextEventBody(core) == nil { return }
        }
    }

    /// One event, decoded from the MI frame `tw_core_next_event` documents:
    /// a 4-byte big-endian length prefix and that many bytes of UTF-8 JSON.
    private func nextEventBody(_ core: OpaquePointer?) -> [String: Any]? {
        var event: OpaquePointer?
        var error: OpaquePointer?
        let rc = tw_core_next_event(core, 500, &event, &error)
        defer {
            tw_buf_free(event)
            tw_buf_free(error)
        }
        guard rc == TW_OK, let event else { return nil }
        let bytes = tw_buf_bytes(event)
        guard let base = bytes.ptr, bytes.len > 4 else { return nil }
        let frame = Data(UnsafeBufferPointer(start: base, count: bytes.len))
        let length = frame.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard frame.count >= 4 + Int(length) else { return nil }
        let json = Data(frame.dropFirst(4).prefix(Int(length)))
        guard let object = try? JSONSerialization.jsonObject(with: json) as? [String: Any],
              let body = object["body"] as? [String: Any] else { return nil }
        return body
    }
}
