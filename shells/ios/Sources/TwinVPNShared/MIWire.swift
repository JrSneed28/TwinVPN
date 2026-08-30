//  MIWire.swift — the ONE management-interface frame codec both iOS processes use.
//
//  Authority: `core/ffi/include/twinvpn.h` (normative, quoted below); ADR-0017
//  §11.3 (`MgmtEnvelope`), §11.9 (the operation catalogue), MI-20; ADR-0018 F-8.
//
//  STATUS: written, not compiled.
//
//  ===========================================================================
//  WHY THIS FILE IS IN `TwinVPNShared` AND NOT IN EITHER TARGET'S OWN DIRECTORY
//  ===========================================================================
//
//  `MIFrame` was declared in `Sources/TwinVPNProvider/CoreProtocol.swift`, which
//  the APP target does not compile — `project.yml`'s `TwinVPN` target lists
//  `Sources/TwinVPNApp`, `Sources/TwinVPNBridge` and `Sources/TwinVPNShared`, and
//  `Sources/TwinVPNProvider` is not among them. The app process needed the same
//  frame to speak to the extension over `NETunnelProviderSession.sendProviderMessage`
//  (ADR-0017 §11.2.1), so the only two options were to MOVE the declaration here
//  or to write a second one.
//
//  A SECOND COPY WOULD BE THE WRONG FIX, for exactly the reason
//  `EnforcementProgramme.swift` in this directory gives for the same choice: the
//  4-byte prefix, the endianness, the 1 MiB cap and the envelope's member names
//  are the spelling BOTH processes must agree on, and two declarations of them
//  are two things that can drift. MI-20 is the rule that makes it a rule —
//  "one contract, two carriages, NEVER two contracts" — and a shell that spelled
//  the frame twice would be the first place a third contract appeared.
//
//  ===========================================================================
//  THE FRAME, QUOTED FROM THE ABI OF RECORD
//  ===========================================================================
//
//  `core/ffi/include/twinvpn.h`, `tw_core_submit`, under the heading
//  "THE BYTES IN `command`. This paragraph is normative.":
//
//    "1. PREFERRED — one MANAGEMENT-INTERFACE FRAME, exactly as *event_out below
//        carries one and exactly as the Unix socket, the named pipe and XPC carry
//        one: a 4-byte BIG-ENDIAN length prefix followed by that many bytes of
//        UTF-8 JSON. `body.kind` MUST be "request", and the body carries:
//
//          operation   string  the wire name, e.g. "session.connect"
//          params      []uint8 the operation's encoded parameters (F-8)
//          if_version  uint?   the precondition, where the catalogue needs one"
//
//    "2. LEGACY — a bare UTF-8 operation name, no framing. Means exactly what it
//        always did: that operation, with NO parameters."
//
//  and, under `tw_core_next_event`'s "THE BYTES IN *event_out. This paragraph is
//  normative.":
//
//    "One MANAGEMENT-INTERFACE FRAME, exactly as the Unix socket, the named pipe
//     and XPC carry it: a 4-byte BIG-ENDIAN length prefix followed by that many
//     bytes of UTF-8 JSON. … The Rust declaration is
//     `twinvpn_mgmt::envelope::MgmtEnvelope`; a shell in another language decodes
//     the JSON and links NOTHING."
//
//  This file is that decoder and that encoder, and it is the whole of what either
//  iOS process knows about the wire.

import Foundation

// ===========================================================================
// MARK: - the frame
// ===========================================================================

/// The length-prefixed JSON frame both carriages of ADR-0017 carry on iOS: the
/// in-process `twinvpn.h` ABI, and `sendProviderMessage` between the app and the
/// extension.
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

    /// One `Request` body in a frame — the PREFERRED form above.
    ///
    /// `request_id` and `correlation_id` are empty because `twinvpn.h` says they
    /// must be: *"`request_id` and `correlation_id` are ignored on this carriage
    /// and SHOULD be empty: there is no connection here, and nothing to correlate
    /// an answer against."* The `sendProviderMessage` carriage inherits the same
    /// shape because it is the same contract (§11.2.1: "same operations, same
    /// scopes, same schema, same reason codes").
    ///
    /// # `idempotency_key` IS sent, where the catalogue requires one
    ///
    /// **This used to be hard-empty, and the header used to say it must be.**
    /// ABI minor 3 changed both halves: *"`idempotency_key` IS read, from the
    /// FRAME (form 1 only; a bare name carries none)… ADR-0008 makes it the
    /// CEREMONY key for `pair.begin`, `pair.confirm`, `device.revoke`,
    /// `key.rotate` and the three update operations, and those are refused as
    /// MGMT.PRECONDITION_FAILED without it. It is NOT a retry token here; it is
    /// the precondition."*
    ///
    /// So the default stays empty — an empty key means ABSENT, which is exactly
    /// the old behaviour for every operation that needs none — and a caller
    /// performing a ceremony supplies one. ADR-0008 N-4 puts the floor at **128
    /// bits of entropy**; minting it is the caller's, because the KEY IDENTIFIES
    /// THE CEREMONY and only the caller knows which submissions are the same one.
    ///
    /// `if_version` is deliberately **absent** rather than sent as null: it is
    /// `Option<u64>` with `#[serde(default)]` on the Rust side, so an omitted
    /// member decodes to `None`, and no operation either process submits today is
    /// one of §11.9's `ver` rows. Adding it belongs with the first `ver`
    /// operation a shell needs, not before one exists.
    static func request(_ operation: String,
                        params: Data = Data(),
                        idempotencyKey: Data = Data()) -> Data {
        let object: [String: Any] = [
            "mi_version": 1,
            "request_id": [],
            "correlation_id": [],
            "seq": 0,
            "idempotency_key": [UInt8](idempotencyKey),
            "as_of_ms": 0,
            "body": [
                "kind": "request",
                "operation": operation,
                "params": [UInt8](params),
            ],
        ]
        guard let framed = encode(object) else {
            // A frame that will not encode must not silently become a DIFFERENT
            // command. The bare-name form is LEGACY and, by `twinvpn.h`'s own
            // words, "that operation, with NO parameters" and no idempotency key
            // — so it is the same command ONLY for a submission that carries
            // neither. Where either is present, sending it would submit a
            // different operation than the caller asked for: a `pair.begin` with
            // no ceremony selector and no CEREMONY key, refused as
            // `PROTO.MALFORMED_MESSAGE` on a body the caller never wrote.
            //
            // Empty bytes are returned instead, which the core answers with a
            // TYPED refusal — `ownership.md` §6 rule 9's "never a truncation,
            // never a pad, never a silent accept" applied to the send side.
            return params.isEmpty && idempotencyKey.isEmpty ? Data(operation.utf8) : Data()
        }
        return framed
    }

    /// One `Response` body in a frame — the **agent's** direction.
    ///
    /// # Only ONE carriage in this shell emits a response, and it is not the ABI
    ///
    /// F-5 makes `tw_core_submit` fire-and-forget, so `twinvpn.h` never asks a
    /// shell to build one. ADR-0017 §11.2.1's app<->provider channel does: its
    /// first table row is "full request/response, byte-identical framing", and
    /// the EXTENSION is the agent on it. `PacketTunnelProvider.handleAppMessage`
    /// returned `nil` for every request until this existed, which is why
    /// `CoreLite.decodeStatus` could say "no byte stream has ever met this
    /// decoder".
    ///
    /// # `diagnostic` carries the code alone, and MI-14's other seven are a
    /// stated shortfall
    ///
    /// MI-14 requires the **resolved** attribute set inline — `class`,
    /// `severity`, `terminal`, `user_actionable`, `remediation_class`, `scope`
    /// and `doc_anchor` beside the code — "for **every** code, including codes
    /// the receiving client does not recognize", because a client resolving them
    /// from its own registry may hold an OLDER one than the agent.
    ///
    /// This shell cannot fill them. The core hands a failure to the C ABI as
    /// `*err_out`, "an ADR-0015 §11.2 envelope" written with `prost`; the seven
    /// attributes are inside its `resolved` submessage, and neither iOS target
    /// links a protobuf runtime. `ErrorEnvelope` below reads the `reason_code`
    /// and stops.
    ///
    /// **The failure MI-14 names cannot arise on THIS carriage**, which is why
    /// the shortfall is acceptable here and would not be on a socket: the app
    /// and the extension are two targets of ONE bundle, built from one core
    /// revision against one `reason_codes.json`, so the client's registry is the
    /// agent's registry. The app resolves the code through `tw_render_diagnostic`
    /// (F-10), which reads that same registry. Carrying the attributes would
    /// still be better — it would make the frame self-describing rather than
    /// co-versioned — and closing it is a protobuf runtime in the extension, not
    /// a longer function here.
    ///
    /// `committed_at_net_seq` is **absent** rather than null: it is
    /// `Option<u64>` with `#[serde(default)]`, MI-6 makes it the C2 cursor a
    /// MUTATING operation committed at, and nothing this carriage answers today
    /// commits to C2. Sending a zero would tell a client to wait for an event at
    /// sequence zero, which is a different claim from "there is no cursor".
    static func response(ok: Bool, result: Data = Data(), reasonCode: String? = nil) -> Data? {
        var body: [String: Any] = [
            "kind": "response",
            "ok": ok,
            "result": [UInt8](result),
        ]
        if let reasonCode {
            body["diagnostic"] = ["reason_code": reasonCode]
        }
        return encode([
            "mi_version": 1,
            "request_id": [],
            // §11.3 already specifies an empty `correlation_id` for a pushed
            // event; this is a RESPONSE, and it is empty for a different reason —
            // `request` sends no `request_id` on this carriage, so there is no id
            // to correlate against and inventing one would imply a request that
            // carried it.
            "correlation_id": [],
            "seq": 0,
            "idempotency_key": [],
            "as_of_ms": 0,
            "body": body,
        ])
    }
}

// ===========================================================================
// MARK: - the one field this shell reads out of an F-4 envelope
// ===========================================================================

/// `reason_code` out of an ADR-0015 §11.2 `ErrorEnvelope`.
///
/// # Why this exists, stated as the limitation it is
///
/// `twinvpn.h` says a failed call's `*err_out` "holds an ADR-0015 §11.2
/// envelope", and `twinvpn-ffi` writes it with `prost` — **protobuf, not the
/// length-prefixed JSON the event stream carries**. The two encodings are
/// deliberate and different: an EVENT is a `twinvpn_mgmt::envelope::MgmtEnvelope`,
/// which "a Swift or Kotlin shell decodes without linking a Rust type", while a
/// FAILURE is the generated `twinvpn.v1.ErrorEnvelope` itself.
///
/// Neither iOS target links a protobuf runtime, so the whole message is not
/// decodable here. What IS decodable is the one field a shell has to have:
/// without a `reason_code` there is nothing to put in a `Response.diagnostic`
/// and nothing to hand `tw_render_diagnostic` (F-10), and a refusal would reach
/// the user as a blank view — the failure mode ADR-0015 §11.2 rule 5 exists to
/// prevent.
///
/// # What is read, and what is deliberately not
///
/// `contracts/proto/twinvpn/v1/errors.proto` fixes `string reason_code = 1`, so
/// the field's key byte is `0x0A` (field 1, wire type 2) followed by a varint
/// length and that many UTF-8 bytes. `prost` emits fields in ascending field
/// number and omits a proto3 default, so a non-empty `reason_code` is always the
/// FIRST bytes of the message. This reads exactly that prefix and stops.
///
/// **`resolved` (field 3) and `evidence` (field 5) are NOT read.** Both are
/// nested messages, `evidence` carries ADR-0015 §11.4 classifications the core's
/// emitter is what bounds and truncates, and a hand-decoded approximation of
/// classified evidence is worse than none. See `MIFrame.response` for what that
/// costs against MI-14 and why it is survivable on that one carriage.
enum ErrorEnvelope {
    /// What a shell reports for an envelope it could not read.
    ///
    /// Registered, and it says what happened without claiming to know WHICH
    /// refusal this was — a substituted code would. It lives here rather than in
    /// either target's own catalogue because BOTH use it and the app target's
    /// `ReasonCode` is not compiled into the extension: two literals of one
    /// registry code are two things that can drift.
    static let unreadableCode = "PROTO.UNPARSEABLE_ENVELOPE"

    /// The registry code, or `nil` when these bytes do not begin with one.
    static func reasonCode(_ message: Data) -> String? {
        var index = message.startIndex
        // Field 1, wire type 2. Anything else means `reason_code` was not
        // written, which ADR-0015 §11.2 makes a malformed envelope; it is
        // reported as an absence rather than searched for further, because a
        // scan past an unknown field needs the full wire-format skip logic this
        // deliberately does not carry.
        guard index < message.endIndex, message[index] == 0x0A else { return nil }
        message.formIndex(after: &index)

        // The length varint. `reason_code` is "<= 64 bytes" (ADR-0015 §11.2 rule
        // 7), so one continuation byte is already more than the contract allows;
        // two is the ceiling this reads before giving up, which keeps a corrupt
        // buffer from driving an unbounded loop.
        var length = 0
        var shift = 0
        while index < message.endIndex {
            let byte = message[index]
            message.formIndex(after: &index)
            length |= Int(byte & 0x7F) << shift
            if byte & 0x80 == 0 { break }
            shift += 7
            if shift > 14 { return nil }
        }

        guard length > 0,
              let end = message.index(index, offsetBy: length, limitedBy: message.endIndex) else {
            return nil
        }
        // Not `String(decoding:as:)`, which substitutes U+FFFD: a code that is
        // not UTF-8 is not a code, and rendering a replacement character as one
        // would put an unregistered string on the path CB-4 reserves for the
        // catalogue.
        return String(data: message[index ..< end], encoding: .utf8)
    }
}

// ===========================================================================
// MARK: - the response half
// ===========================================================================

/// One `body.kind == "response"` envelope, decoded.
///
/// # Only the app has one of these, and only over `sendProviderMessage`
///
/// The `twinvpn.h` carriage never produces a response: F-5 makes
/// `tw_core_submit` fire-and-forget and every outcome arrives as an event on the
/// one ordered stream. ADR-0017 §11.2.1's app↔provider channel is the carriage
/// that does — "full request/response, byte-identical framing" is the first row
/// of its table — so this type exists for that one direction.
///
/// # `result` is bytes, and this type does not interpret them
///
/// ADR-0018 F-8: *"only handles, slices and scalars cross; structured data
/// crosses as ENCODED BYTES."* `twinvpn_mgmt::envelope::Response::result` is a
/// `Vec<u8>`, which JSON carries as an array of numbers; this decoder turns that
/// back into `Data` and stops. What those bytes mean is the caller's question and
/// is answered against the operation, never against this envelope.
struct MIResponse {
    /// `Response::ok`.
    let ok: Bool
    /// `Response::result`, undecoded.
    let result: Data
    /// `Response::diagnostic.reason_code`, when the agent sent one.
    ///
    /// A CODE, never a sentence. MI-15 forbids rendered text on this channel and
    /// MI-14 puts the resolved attributes beside the code; the surface that has a
    /// locale renders it through `tw_render_diagnostic` (F-10).
    let reasonCode: String?

    /// Decodes one frame.
    ///
    /// `nil` for a frame that is not a readable `response` — including a `reject`
    /// or an event body, which are not answers to a request and must not be
    /// mistaken for one. A caller that gets `nil` learns that it has no answer,
    /// which is a different fact from an answer that says "no".
    static func decode(_ data: Data) -> MIResponse? {
        guard let object = MIFrame.decode(data),
              let body = object["body"] as? [String: Any],
              body["kind"] as? String == "response",
              let ok = body["ok"] as? Bool else {
            return nil
        }
        let diagnostic = body["diagnostic"] as? [String: Any]
        return MIResponse(
            ok: ok,
            result: bytes(body["result"]),
            reasonCode: diagnostic?["reason_code"] as? String)
    }

    /// A JSON `[]uint8` back into `Data`.
    ///
    /// An element outside `0...255` truncates the run rather than wrapping it:
    /// `UInt8(exactly:)` returns nil and the loop stops, so a corrupt array
    /// yields a SHORTER buffer that will fail its own decode, never a buffer with
    /// invented bytes in it.
    private static func bytes(_ value: Any?) -> Data {
        guard let numbers = value as? [NSNumber] else { return Data() }
        var out = Data(capacity: numbers.count)
        for number in numbers {
            guard let byte = UInt8(exactly: number.intValue) else { break }
            out.append(byte)
        }
        return out
    }
}
