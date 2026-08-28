//  CoreProtocol.swift — the three types that cross `twinvpn.h`, as bytes.
//
//  Authority: ADR-0018 §11.4 F-4, F-5, F-8; ADR-0017 §11.3, MI-18, MI-19,
//  MI-20; `ownership.md` §8 R-2 and §10.8 M-1.
//
//  ===========================================================================
//  THE DEFECT THIS FILE CLOSES
//  ===========================================================================
//
//  `CoreInstance.swift` referenced `CoreCommand`, `CoreConfiguration` and
//  `CoreEvent`; `KeychainBridge.swift` referenced `Attestation`;
//  `PathMonitorBridge.swift` referenced `InterfaceFacts`, `NAT64Discovery` and
//  `SystemResolvers`. **None of the seven was defined anywhere in the
//  repository.** The extension could not compile, and the file headers'
//  "written, not compiled" concealed it: no build ever tried.
//
//  This file defines the three that cross the ABI. `PlatformFacts.swift`
//  defines the four that do not.
//
//  ===========================================================================
//  F-8, AND WHY EVERY TYPE HERE PRODUCES `Data`
//  ===========================================================================
//
//  > "only handles, slices and scalars cross; structured data crosses as
//  > encoded bytes."
//
//  So a command is `Data` and an event is decoded FROM `Data`. Nothing here is
//  a Swift model of a core type: there is no `struct Session`, no `enum
//  ConnectionState`, and no place a shell's idea of one could diverge from the
//  core's. MI-20 — "one contract, two carriages, never two contracts" — is what
//  makes that a rule rather than a preference.

import Foundation
// The ABI OF RECORD. `tw_buf` and `tw_buf_bytes` are `twinvpn.h`'s, and this
// shell consumes that header and never adds to it (F-1).
import TwinVPNCore

// ===========================================================================
// MARK: - The MI frame
// ===========================================================================

/// The length-prefixed JSON frame both directions of this ABI carry.
///
/// `twinvpn.h` is normative about it: *"a 4-byte BIG-ENDIAN length prefix
/// followed by that many bytes of UTF-8 JSON … a shell in another language
/// decodes the JSON and links NOTHING."* This is that decoder and that encoder,
/// and it is the whole of what this shell knows about the wire.
enum MIFrame {
    /// The cap `twinvpn_mgmt::envelope::MAX_ENVELOPE_BYTES` declares.
    ///
    /// Checked **before** anything proportional to the declared length is
    /// allocated: `ownership.md` §6 rule 9 makes an over-cap value a typed
    /// refusal, "never a truncation, never a pad, never a silent accept".
    static let maxBytes = 1 << 20

    static let prefixBytes = 4

    /// Wraps a JSON object as a frame.
    static func encode(_ object: [String: Any]) -> Data? {
        guard let body = try? JSONSerialization.data(withJSONObject: object),
              body.count <= maxBytes,
              let length = UInt32(exactly: body.count) else {
            return nil
        }
        var out = Data(capacity: body.count + prefixBytes)
        out.append(contentsOf: withUnsafeBytes(of: length.bigEndian, Array.init))
        out.append(body)
        return out
    }

    /// Reads a frame's JSON object.
    ///
    /// `nil` for anything malformed. The caller treats that as a frame it
    /// cannot read rather than as an event that did not happen — the two are
    /// different, and only the first is safe to ignore.
    static func decode(_ data: Data) -> [String: Any]? {
        guard data.count > prefixBytes else { return nil }
        let declared = data.prefix(prefixBytes).reduce(0) { ($0 << 8) | Int($1) }
        // The cap, before the slice.
        guard declared > 0, declared <= maxBytes,
              data.count >= prefixBytes + declared else { return nil }
        let body = data.subdata(in: prefixBytes ..< (prefixBytes + declared))
        return (try? JSONSerialization.jsonObject(with: body)) as? [String: Any]
    }
}

// ===========================================================================
// MARK: - CoreCommand
// ===========================================================================

/// One submission, encoded.
///
/// # Why every member returns `Data` and none returns a Swift enum
///
/// `tw_core_submit` takes a `tw_slice`. The catalogue of operations lives in
/// `twinvpn-mgmt` and is the contract; a Swift `enum` mirroring it would be a
/// second declaration of the same catalogue, which is exactly the R-31 defect
/// class. What this type holds instead is the **wire names**, one per member,
/// and each one is a string the core looks up in the catalogue it owns.
///
/// # The parameters
///
/// `twinvpn.h` accepts two forms and this type emits the framed one, because
/// several of these operations mean nothing without their parameters —
/// `host.lifecycle` names a phase, `host.network_changed` names a snapshot.
/// The bare-name form is what the ABI accepted *only*, before minor 1, and it
/// is why `pathSnapshot` had nowhere to put its JSON.
enum CoreCommand {
    /// `net.up` — bring every known session up and arm enforcement.
    ///
    /// The `options` an `NEPacketTunnelProvider` is started with are the OS's
    /// own dictionary and are **not** forwarded: they are untyped `NSObject`s
    /// from a caller the extension does not authenticate, and ADR-0018 CD-2
    /// keeps configuration out of the core's ambient environment. What the core
    /// needs from a start is that a start happened.
    static func start(_ options: [String: NSObject]?) -> Data {
        _ = options
        return request("net.up")
    }

    /// `host.lifecycle`, carrying the raw `NEProviderStopReason`.
    ///
    /// The RAW value, undecoded: `twinvpn_platform_ios::lifecycle::
    /// ProviderStopReason` carries an unrecognised one as `Unknown(raw)` rather
    /// than coercing it, because "a stop this build cannot name is not evidence
    /// of an orderly one" and `clean_shutdown` must not be set for it. A Swift
    /// `switch` here would be the coercion that rule forbids.
    static func stopReason(_ raw: Int) -> Data {
        request("host.lifecycle", params: Data(String(raw).utf8))
    }

    /// `host.lifecycle` — the app moved to the background.
    static var sleep: Data { request("host.lifecycle", params: Data("background".utf8)) }

    /// `host.lifecycle` — the app came to the foreground.
    static var wake: Data { request("host.lifecycle", params: Data("foreground".utf8)) }

    /// `path.probe` — packets are waiting on the tunnel's read side.
    static var packetsAvailable: Data { request("path.probe") }

    /// `host.lifecycle`, carrying the resident-byte reading ADR-0022 bounds.
    static func memoryPressure(_ residentBytes: UInt64) -> Data {
        request("host.lifecycle", params: Data("memory:\(residentBytes)".utf8))
    }

    /// `host.network_changed`, carrying one `NWPathMonitor` snapshot.
    ///
    /// §11.16 (h): at the C ABI the subscription is satisfied by "an inbound
    /// command submission rather than a literal outbound function pointer" —
    /// which is `NWPathMonitor`'s own shape. `acrossWake` is a **separate fact**
    /// from the snapshot: ADR-0022 LC-31 responds differently to a path that
    /// changed while the device slept, and folding it into the JSON would make
    /// it indistinguishable from a field the path monitor reported.
    static func pathSnapshot(_ json: String, acrossWake: Bool) -> Data {
        request(
            "host.network_changed",
            params: Data((acrossWake ? "wake:" : "live:").appending(json).utf8))
    }

    /// The management channel's opaque request.
    ///
    /// MI-15 forbids rendered text here and this could not produce any if it
    /// wanted to: it moves bytes.
    static func managementRequest(_ request: Data) -> Data {
        Self.request("diag.report", params: request)
    }

    /// `net.down` — ADR-0022 LC-25's pre-sleep is a FLUSH, never a teardown,
    /// and the core's own `net.down` keeps the rules installed (CB-6).
    static var flush: Data { request("net.down") }

    /// One `Request` body in an MI frame.
    private static func request(_ operation: String, params: Data = Data()) -> Data {
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
                "params": [UInt8](params),
            ],
        ]
        // A frame that will not encode must not silently become a DIFFERENT
        // command. The bare-name form is the same operation with no parameters,
        // which the core still accepts and which is never a different one.
        return MIFrame.encode(object) ?? Data(operation.utf8)
    }
}

// ===========================================================================
// MARK: - CoreConfiguration
// ===========================================================================

/// The `config` slice `tw_core_create` takes.
///
/// # Deliberately empty
///
/// ADR-0018 CD-2: *"Everything takes its `Env` at construction. There is no
/// global, no `OnceCell`, no ambient default."* On this platform the adapter is
/// linked in-process as a Rust crate (`ownership.md` §10.4), so every capability
/// the core needs it already has, and the shell has nothing left to configure.
///
/// It is a type rather than a bare `Data()` at the call site so that the day
/// there IS something to configure, there is one place to put it and one place
/// to review — rather than a literal in the middle of `create()`.
enum CoreConfiguration {
    static func encoded() -> Data { Data() }
}

// ===========================================================================
// MARK: - CoreEvent
// ===========================================================================

/// One event off F-5's single ordered stream.
///
/// # M-1, and why this decodes JSON rather than protobuf
///
/// The ABI used to write the bare event payload with **no discriminator**: six
/// message types into one buffer, so a receiver could not tell which it held,
/// and `Diagnostic` and `CommandRejected` — both an `ErrorEnvelope` — were
/// byte-identical. Every event now crosses as a `twinvpn_mgmt::envelope::
/// MgmtEnvelope`, the same length-prefixed JSON the Unix socket, the named pipe
/// and XPC carry. MI-20: this ABI is one of the carriages, not an exception.
struct CoreEvent {
    /// What this shell must *do*, which is a much smaller question than what
    /// the event *is*.
    enum Kind {
        /// The core wants `NEPacketTunnelNetworkSettings` applied.
        case settingsRequested
        /// The core wants the enforcement posture changed.
        case enforcementRequested
        /// An unsolicited diagnostic, or a rejected command.
        case diagnostic
        /// The tunnel must be cancelled.
        case cancelTunnel
    }

    let kind: Kind
    /// The registered code, for a log line **only**.
    ///
    /// CB-4 keeps every rendered string out of the shell's judgement and in the
    /// core's catalogue: the human sentence comes from `tw_render_diagnostic`
    /// (F-10), never from a string in this shell.
    let reasonCode: String
    /// F-5's total order. **Contiguous except across a `compacted` body**, which
    /// announces the gap it spans — so a receiver that has seen no `compacted`
    /// has missed nothing (MI-9a, MI-19).
    let seq: UInt64
    /// MI-18. The OS principal whose call produced this, or `nil` for an
    /// agent-internal or peer-initiated cause.
    ///
    /// > "the tunnel went down" and "Dana took the tunnel down" are different
    /// > facts.
    let actorPrincipal: String?
    /// **Which** operation this answers, on `command.completed` and
    /// `command.rejected`.
    ///
    /// The C ABI has no memory of a submission — `tw_core_submit` is
    /// fire-and-forget and returns no request id — so without this field a
    /// completion cannot be attributed to the command it completes.
    let op: String?

    /// Decodes one `tw_buf`.
    ///
    /// # An unknown `body.kind` is an event to ignore, never a parse failure
    ///
    /// `twinvpn.h` is explicit: *"read it first, and treat an unknown value as a
    /// forward-compatible event to ignore, never as a parse failure."* A shell
    /// that crashed on a body a newer core added would make every additive
    /// change a breaking one, which is the opposite of what the discriminator is
    /// for.
    static func decode(_ buffer: UnsafeMutablePointer<tw_buf>?) -> CoreEvent {
        guard let buffer else { return .unreadable }
        let slice = tw_buf_bytes(buffer)
        guard let ptr = slice.ptr else { return .unreadable }
        return decode(Data(bytes: ptr, count: slice.len))
    }

    /// The same, over bytes — so this is testable without a core.
    static func decode(_ data: Data) -> CoreEvent {
        guard let object = MIFrame.decode(data),
              let body = object["body"] as? [String: Any],
              let bodyKind = body["kind"] as? String else {
            return .unreadable
        }
        let seq = (object["seq"] as? NSNumber)?.uint64Value ?? 0

        switch bodyKind {
        case "event":
            let topic = body["topic"] as? String ?? ""
            return CoreEvent(
                kind: kind(forTopic: topic),
                reasonCode: topic,
                seq: seq,
                actorPrincipal: body["actor_principal"] as? String,
                op: body["op"] as? String)
        case "compacted":
            // MI-19's ordered marker. A gap is a fact the provider must see:
            // the settings it believes are applied may be stale, so it is
            // surfaced as a diagnostic rather than dropped.
            return CoreEvent(
                kind: .diagnostic,
                reasonCode: "MGMT.EVENTS_COMPACTED",
                seq: seq,
                actorPrincipal: nil,
                op: nil)
        default:
            // Forward-compatible. Named, so a log line says which body this
            // build did not know rather than reporting nothing at all.
            return CoreEvent(
                kind: .diagnostic,
                reasonCode: "MGMT.BODY_UNKNOWN",
                seq: seq,
                actorPrincipal: nil,
                op: nil)
        }
    }

    /// The topic → action map, and the only judgement this shell makes.
    ///
    /// Total over the five topics `twinvpn_core::events::topics::ALL` declares.
    /// A topic this build does not know becomes a diagnostic — it is logged and
    /// nothing is done, which is the only safe response to an instruction that
    /// was not understood.
    private static func kind(forTopic topic: String) -> Kind {
        switch topic {
        case "transition":
            // A state transition may require new `NEPacketTunnelNetworkSettings`
            // — the addresses, routes and DNS the contract carries.
            return .settingsRequested
        case "session":
            return .enforcementRequested
        case "diagnostic", "command.rejected", "command.completed":
            return .diagnostic
        default:
            return .diagnostic
        }
    }

    /// A frame this build could not read.
    ///
    /// Deliberately **not** `cancelTunnel`: a frame we could not decode is not
    /// evidence that the tunnel should go down, and treating it as such would
    /// let one malformed buffer disconnect a user.
    private static let unreadable = CoreEvent(
        kind: .diagnostic,
        reasonCode: "PROTO.UNPARSEABLE_ENVELOPE",
        seq: 0,
        actorPrincipal: nil,
        op: nil)
}
