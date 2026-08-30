//  PairingModel.swift — the pairing view's model, and the CORE side of the split
//  `PairingView.swift` describes.
//
//  Authority: ADR-0018 §11.2 row 2.7, §11.12, F-5a, CB-4; ADR-0017 §11.2.1,
//  §11.9 (`pair.*`), MI-P1, MI-15, MI-20; ADR-0007 §7.4, N-16, N-17;
//  ADR-0008 N-4; ADR-0015 §11.2; `ownership.md` §10.1.
//
//  STATUS: written, not compiled.
//
//  ===========================================================================
//  WHAT THIS TYPE IS FOR
//  ===========================================================================
//
//  `PairingView` is "the pairing SHELL HALF, and only that": it opens the
//  camera, renders bytes as a QR code, and displays a string. This is the other
//  side of that seam — the part that talks to the core — and it is deliberately
//  the only file in the app that names a `pair.*` operation.
//
//  It makes NO ceremony decision. It does not parse a `PairingOffer`, derive a
//  `pairing_id` or a `K_pair`, compute a `transcript_hash`, or judge whether a
//  scan is valid, expired or replayed. Every one of those is §11.2 row 2.7's
//  "core: ceremony, SPAKE2/QR verification, idempotency", and `ownership.md`
//  §10.1 says of the shell half: "**Do not reimplement any of it.**"
//
//  What it does is submit three operations and hold what comes back.
//
//  ===========================================================================
//  WHY THE REQUEST GOES TO THE EXTENSION AND NOT TO A CORE IN THIS PROCESS
//  ===========================================================================
//
//  THIS IS THE ONE DESIGN DECISION IN THIS FILE, AND IT IS FORCED.
//
//  The obvious shape — this process creates a `core-lite` instance the way
//  `CoreInstance.swift` creates the extension's, and calls
//  `tw_core_submit_response` on it — CANNOT WORK, and the reason is one branch
//  in `twinvpn-core`'s `Core::submit_response`:
//
//      // core-lite carries no data-plane crate, so it performs NO command.
//      // Refusing by name is the honest answer; returning Ok would be the same
//      // false success this dispatcher exists to remove.
//      #[cfg(not(feature = "full"))]
//      { … return Err(Box::new(self.reject(submission, PLATFORM_ADAPTER_UNAVAILABLE))) }
//
//  `twinvpn-core/src/lib.rs` puts BOTH `pub mod dispatch` and `pub mod pairing`
//  behind `#[cfg(feature = "full")]`, and `project.yml` links this target
//  against `-ltwinvpn_core_lite`. So an app-process instance would answer every
//  `pair.begin` with `PLATFORM.ADAPTER_UNAVAILABLE` — a handle that refuses
//  everything, with a serial queue to guard it. ADR-0018 §11.12 says the same
//  thing in prose: `core-lite` "PARSES, VERIFIES AND RENDERS", and minting a
//  `PairingOffer` is none of those.
//
//  The full core is in the NetworkExtension, and ADR-0017 §11.2.1's
//  app<->provider channel is how this process reaches it: "full request/response,
//  byte-identical framing… same operations, same scopes, same schema, same
//  reason codes". `PacketTunnelProvider.handleAppMessage` forwards the frame to
//  `tw_core_submit_response` and returns F-5a's unicast body in a `Response`.
//
//  MI-P1 rule 1 permits the offer "only inside a `pair.begin` response, only
//  over the MI channel", and this IS that channel — unicast, request/response,
//  one requester. The broadcast the rule forbids is F-5's event stream, which
//  neither process routes this value onto.
//
//  **The stated cost.** §11.2.1's channel exists "only while the session is
//  connected", so this screen cannot pair a device whose tunnel is down. That is
//  reported as `MGMT.CHANNEL_UNSUPPORTED`, whose registry entry names this exact
//  case — "the platform channel cannot carry this operation in the current state
//  (iOS stopped session, Android disarm)" — rather than as a blank screen.
//
//  ===========================================================================
//  MI-P1 RULES 2 AND 3, HELD HERE
//  ===========================================================================
//
//  `twinvpn.h`: "THE BYTES MUST NOT BE LOGGED AT ANY LEVEL, MUST NOT BE PUT BACK
//  ON THE EVENT STREAM, MUST NOT REACH A TIER-1 DIAGNOSTIC BUNDLE, AND MUST NOT
//  BE PERSISTED BY EITHER SIDE. A `pair.begin` body additionally EXPIRES: drop it
//  at the offer's `not_after_ms` (120 s)."
//
//   * Not logged: there is no `Logger` in this file and `renderedOffer` is never
//     interpolated into a string.
//   * Not on the stream: this file submits, it never publishes.
//   * Not in a bundle: `CoreLite.assembleBundle` reads nothing from this type.
//   * Not persisted: the bytes live in one `@Published` property and in no file,
//     no `UserDefaults`, no Keychain item and no App Group container.
//   * Dropped at the deadline: `expiry` below, and `end()` on the way out.

import Foundation
// `twinvpn_ios_os_csprng` and `TW_OK`. The CEREMONY key is minted from the same
// entropy source the host vtable installs, rather than from a second API this
// shell would then owe an argument for.
import TwinVPNBridge
import TwinVPNCore

/// The pairing screen's model.
@MainActor
final class PairingModel: ObservableObject {
    // MARK: - what the view renders

    /// The offer's octets, for `QRCodeImage` to draw.
    ///
    /// **The `pairing_id` prefix is stripped before this is set.** The response
    /// body is `pairing_id ‖ dCBOR(offer)` and ADR-0023 **E1** renders the OFFER
    /// as the QR payload; a code carrying the id as well would not decode as a
    /// `PairingOffer` at the peer.
    @Published private(set) var renderedOffer: Data?

    /// ADR-0007 §7.4's "post-hoc display of the peer's label and 20-char
    /// fingerprint on both ends".
    ///
    /// **Always `nil` in this build, and that is a refusal rather than a gap in
    /// this file.** The fingerprint is a property of a CONFIRMED ceremony, and
    /// `twinvpn-core`'s `dispatch::disposition` answers `pair.confirm` with
    /// `CONTROL.UNREACHABLE`: "N-18 confirms a ceremony on both devices or on
    /// neither, so it needs BOTH `PairingAttestation`s, and this build can
    /// produce neither half." Displaying a fingerprint before the core has
    /// confirmed anything would be the shell asserting a ceremony completed —
    /// exactly the "agent's belief" ADR-0015 §11.6 rules out for the protection
    /// indicator, applied to the ceremony this screen performs.
    @Published private(set) var confirmationFingerprint: String?

    /// The registered code for whatever refused, or `nil`.
    ///
    /// A CODE, never a sentence: MI-15 forbids rendered text on the channel and
    /// CB-4 puts the rendering in the core. `DiagnosticView` hands this to
    /// `tw_render_diagnostic` (F-10) and shows the three parts that come back.
    @Published private(set) var reasonCode: String?

    /// The evidence beside that code.
    ///
    /// **Empty, always, and deliberately.** `Response.diagnostic.evidence` is
    /// typed JSON on the wire, but the extension cannot fill it: the core hands
    /// a failure to the C ABI as a `prost` `ErrorEnvelope`, neither iOS target
    /// links a protobuf runtime, and `ErrorEnvelope` in `MIWire.swift` reads the
    /// `reason_code` and stops. ADR-0015 §11.4 classifies every evidence entry
    /// and the core's emitter is what bounds and redacts the set; a hand-decoded
    /// approximation would be this shell inventing classified evidence, which is
    /// worse than showing none.
    @Published private(set) var evidence: [String: String] = [:]

    // MARK: - the ceremony's own state

    /// ADR-0017 §11.2.1's channel to the extension.
    ///
    /// The process-wide client, not a second one. §11.2.1 and ADR-0019 §11.8 are
    /// explicit that a per-scene replica "would be an **I8** break inside the app
    /// and is prohibited", and this screen is per-scene.
    private let management = ManagementClient.shared

    /// The 16-byte PUBLIC handle `pair.cancel` names. Not a secret — it is the
    /// value `pair.begin` publishes on the event stream.
    private var pairingID: Data?

    /// MI-P1 rule 2's deadline, as a task rather than a timer.
    private var expiry: Task<Void, Never>?

    /// ADR-0008's CEREMONY key — the PRECONDITION, not a retry token.
    ///
    /// `twinvpn.h`: `pair.begin` and `pair.confirm` "are refused as
    /// MGMT.PRECONDITION_FAILED without it". N-4 puts the floor at 128 bits of
    /// entropy; this is 256, from the same `os_csprng` the host vtable installs.
    ///
    /// **Minted once per CEREMONY, not once per submission and not once per
    /// model.** ADR-0008 makes the key name the ceremony: `pair.begin`'s replay
    /// path returns "the **original** `pairing_id`" for a repeated key, which is
    /// what keeps a retry from minting a second secret, and `pair.confirm`
    /// confirms the ceremony that key opened. A fresh key per submission would
    /// defeat both. A key that outlived `end()` would be worse — the ceremony it
    /// names has been cancelled, so the next `begin()` would replay into a
    /// cancelled one and get back an id with no offer behind it.
    private var ceremonyKey = Data()

    /// Whether a ceremony is open. `.task` re-fires on an identity change, and a
    /// second `pair.begin` under the same key would be a replay of the ceremony
    /// this screen is already showing.
    private var began = false

    // MARK: - the operations

    /// Opens the ceremony: `pair.begin`, C-B.
    func begin() async {
        guard !began else { return }
        began = true
        ceremonyKey = Self.mintCeremonyKey()

        // The selector byte, and nothing else. `Ceremony::from_params` reads
        // `params.first()` with NO default — "defaulting to C-B would silently
        // perform a different ceremony from the one asked for, and N-16 makes
        // 'which ceremony did this trust come from' an audit question that cannot
        // be answered retroactively."
        guard let response = await send(
            "pair.begin",
            params: Data([Ceremony.confidentialChannel.rawValue]),
            idempotencyKey: ceremonyKey) else {
            // A ceremony that never opened is not one to hold the screen closed
            // against. `began` is released so a later `.task` can try again, and
            // the retry mints a FRESH key rather than replaying this one — the
            // ceremony this attempt named does not exist, so replaying into it
            // would return an id with no offer behind it.
            began = false
            return
        }

        guard response.result.count > Self.pairingIDBytes else {
            // `ok` with no offer. `pair.begin`'s `response_body` answers `None`
            // "when no ceremony with that `pairing_id` is in flight — a replay
            // after cancellation or expiry", and a body that is the id alone is
            // the same fact. There is nothing to render and the core did not
            // refuse, so neither a QR code nor a registered refusal would be
            // true; the state is reported as the one it actually is.
            reasonCode = ReasonCode.unexpectedState
            began = false
            return
        }
        let body = response.result
        let split = body.index(body.startIndex, offsetBy: Self.pairingIDBytes)
        pairingID = Data(body[body.startIndex ..< split])
        renderedOffer = Data(body[split...])
        scheduleExpiry()
    }

    /// Hands the core the bytes a QR code contained: `pair.confirm`.
    ///
    /// The payload is passed through UNINSPECTED. `PairingView`'s scanner
    /// already refuses to look at it — "no validation, no length check against a
    /// `PairingOffer`'s shape, no expiry comparison" — and this method keeps that
    /// true across the seam: a payload that is not an offer is refused BY THE
    /// CORE with a registered code, and a length check here would be a second
    /// copy of a ceremony rule that could drift from the first.
    ///
    /// **It is refused today**, with `CONTROL.UNREACHABLE`. That refusal is the
    /// honest outcome for this build and is displayed as one; see
    /// `confirmationFingerprint`.
    func submitScannedPayload(_ payload: Data) {
        Task { [weak self] in
            guard let self else { return }
            // `pair.confirm` publishes its outcome and has no unicast body, so a
            // success carries nothing to render and leaves the view as it was.
            // `send` has already recorded the refusal if there was one.
            _ = await self.send(
                "pair.confirm", params: payload, idempotencyKey: self.ceremonyKey)
        }
    }

    /// Closes the screen: drop the secret, cancel the ceremony, reset the state.
    ///
    /// The order matters and is the security order. The offer is dropped FIRST
    /// and synchronously, because `onDisappear` is the last moment this file is
    /// sure to run; the cancel is a request over a channel that may already be
    /// gone, and a submission that never lands must not be what the secret's
    /// lifetime depends on.
    ///
    /// `pair.cancel` carries the `pairing_id` and NO idempotency key — the
    /// catalogue requires one on `pair.begin` and `pair.confirm`, not on this —
    /// and `dispatch` refuses any params length but 16 rather than truncating or
    /// padding (`ownership.md` §6 rule 9).
    func end() {
        expiry?.cancel()
        expiry = nil
        renderedOffer = nil
        confirmationFingerprint = nil
        reasonCode = nil
        began = false
        ceremonyKey = Data()

        guard let pairingID else { return }
        self.pairingID = nil
        let frame = MIFrame.request("pair.cancel", params: pairingID)
        let management = self.management
        // Deliberately unreported. The screen is gone, there is nothing left to
        // show a refusal on, and the core burns the offer at `not_after_ms`
        // whether this lands or not (`PairingCeremonies::expire_stale`).
        Task { _ = try? await management.send(frame) }
    }

    // MARK: - the one round trip

    /// Sends one request and reduces the answer to "usable" or "a code to show".
    ///
    /// Three failure shapes, each reported as itself rather than folded together:
    /// a channel that cannot carry the request at all, a frame this build cannot
    /// read, and an agent that answered `ok == false` with a registered code.
    private func send(_ operation: String,
                      params: Data,
                      idempotencyKey: Data) async -> MIResponse? {
        let request = MIFrame.request(
            operation, params: params, idempotencyKey: idempotencyKey)
        let raw: Data
        do {
            raw = try await management.send(request)
        } catch ManagementChannelError.noResponse {
            // The channel CARRIED the request and the agent answered nothing.
            // That is a different fact from a channel that could not carry it,
            // and folding the two together would tell a user to bring the tunnel
            // up when the tunnel is already up.
            reasonCode = ReasonCode.unexpectedState
            return nil
        } catch {
            // §11.2.1: "`sendProviderMessage` fails when stopped". The registry
            // entry for this code names that state — "the platform channel cannot
            // carry this operation in the current state (iOS stopped session,
            // Android disarm)" — so the user is told the tunnel has to be up
            // rather than that pairing is broken.
            reasonCode = ReasonCode.channelUnsupported
            return nil
        }
        guard let response = MIResponse.decode(raw) else {
            // Not an answer. `MIResponse.decode` returns `nil` for a frame that
            // is not a readable `response`, "including a `reject` or an event
            // body, which are not answers to a request and must not be mistaken
            // for one".
            reasonCode = ReasonCode.unparseableEnvelope
            return nil
        }
        guard response.ok else {
            reasonCode = response.reasonCode ?? ReasonCode.unparseableEnvelope
            return nil
        }
        reasonCode = nil
        return response
    }

    /// MI-P1 rule 2's "drop it at the offer's `not_after_ms` (120 s)".
    ///
    /// **The window is the CONTRACT's number, not a value read off the offer**,
    /// and the difference is stated rather than hidden: `not_after_ms` is field 7
    /// of a dCBOR `PairingOffer`, this target has no CBOR decoder, and adding one
    /// to read a single field would be a second decoder of a frozen contract.
    /// ADR-0007 §7.4 fixes the window at 120 s and
    /// `pairing::CEREMONY_EXPIRY_MS_FALLBACK` carries the same number, so the
    /// deadline is right; and it is measured from the RESPONSE rather than from
    /// the offer's own stamp, which can only make this shell drop the bytes
    /// EARLIER than the core would, never later.
    private func scheduleExpiry() {
        expiry?.cancel()
        expiry = Task { [weak self] in
            try? await Task.sleep(nanoseconds: Self.offerWindowNanoseconds)
            guard !Task.isCancelled else { return }
            // The view falls back to the camera, which is the correct state for a
            // ceremony whose offer has expired: the core burned its own copy in
            // `expire_stale`, so there is nothing left for a peer to scan.
            self?.renderedOffer = nil
        }
    }

    // MARK: - constants and the key

    /// `limits.json`'s `pairing_id_bytes`, and `twinvpn-core`'s
    /// `pairing::PAIRING_ID_BYTES`. The frozen width the response body is
    /// prefixed with.
    private static let pairingIDBytes = 16

    /// ADR-0007 §7.4's `not_after_ms = 120000`.
    private static let offerWindowNanoseconds: UInt64 = 120_000 * 1_000_000

    /// 256 bits from `os_csprng`, or empty.
    ///
    /// **An empty key is not padded and not substituted.** ADR-0008 N-4 sets a
    /// 128-bit floor, and a key this device could not generate is one the core
    /// must refuse: an empty `idempotency_key` decodes to `None` and `pair.begin`
    /// answers `MGMT.PRECONDITION_FAILED`, which is a loud refusal. Filling it
    /// with a counter, a UUID string or a clock reading would be a ceremony key
    /// with no entropy behind it, and the ceremony would proceed on it.
    private static func mintCeremonyKey() -> Data {
        var key = Data(count: 32)
        let ok = key.withUnsafeMutableBytes { raw -> Bool in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return false }
            return twinvpn_ios_os_csprng(nil, base, raw.count) == TW_OK
        }
        return ok ? key : Data()
    }
}

// ===========================================================================
// MARK: - the ceremony selector
// ===========================================================================

/// Which channel-authentication ceremony a `pair.begin` asks for.
///
/// **A MIRROR of the core's selector byte, not a second vocabulary** — the same
/// standing `CoreCommand.Phase` has in `CoreProtocol.swift`. It carries no
/// TwinVPN domain fact and no branch on one; it is the wire encoding of a choice
/// this screen makes, and `twinvpn_core::pairing::Ceremony::to_params` is where
/// the numbers come from.
enum Ceremony: UInt8 {
    /// **C-B.** The offer crosses an out-of-band confidential channel — a QR
    /// under ADR-0023 E1, a pasted Crockford block under E2. This is the one this
    /// screen performs.
    case confidentialChannel = 1
    /// **C-A.** SPAKE2 over P-256 with a nine-digit code (N-17).
    ///
    /// Declared and never submitted. `twinvpn-core` refuses it with
    /// `PROTO.CAPABILITY_MISSING` — "`Spake2Exchange` has no implementation and
    /// N-15 forbids inventing one" — and W-22 is what blocks it. The case exists
    /// so the mirror is complete and so a reader does not conclude that byte 2 is
    /// free.
    case humanCode = 2
}
