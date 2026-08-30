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
    /// `request_id`, `correlation_id` and `idempotency_key` are empty because
    /// `twinvpn.h` says they must be: *"`request_id`, `correlation_id` and
    /// `idempotency_key` are ignored on this carriage and SHOULD be empty: the
    /// ABI is in-process and fire-and-forget, so there is no request to correlate
    /// and no retry to deduplicate."* The `sendProviderMessage` carriage inherits
    /// the same shape because it is the same contract (§11.2.1: "same operations,
    /// same scopes, same schema, same reason codes").
    ///
    /// `if_version` is deliberately **absent** rather than sent as null: it is
    /// `Option<u64>` with `#[serde(default)]` on the Rust side, so an omitted
    /// member decodes to `None`, and no operation either process submits today is
    /// one of §11.9's `ver` rows. Adding it belongs with the first `ver`
    /// operation a shell needs, not before one exists.
    static func request(_ operation: String, params: Data = Data()) -> Data {
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
        return encode(object) ?? Data(operation.utf8)
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
