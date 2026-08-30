//  CoreLite.swift — the app process's core instance, and CB-4's presentation seam.
//
//  Authority: ADR-0018 §11.12 (`core-lite`), §11.5's iOS app row, CB-4, F-7,
//  F-10; ADR-0016 PS-24; ADR-0019 X3(5), LT-3a/b/c; ADR-0015 §11.2 rule 5,
//  §11.4.
//
//  STATUS: written, not compiled.
//
//  ===========================================================================
//  WHAT `core-lite` IS
//  ===========================================================================
//
//  ADR-0018 §11.12: "A feature profile of the SAME source containing
//  `twinvpn-schema`, `twinvpn-crypto` (verification only), `twinvpn-store`,
//  `twinvpn-trust` and `twinvpn-diag`, and NO data-plane crate. It exists to
//  satisfy C-3: the iOS/iPadOS app process PARSES, VERIFIES AND RENDERS… One
//  source, two artifacts; the profile is recorded in S-46 so a support case is
//  answerable."
//
//  ADR-0016 PS-24 rules that a second core instance in this process is consistent
//  with H2 and PS-1, "because PS-1 enumerates the authority by what it HOLDS —
//  the interface handle, the rule-set handle, the route and resolver program, the
//  key handle, the KS-9-registered sockets — and core-lite holds NONE of them. A
//  second core instance is a linkage fact; a second authority would be an I8
//  violation, and core-lite is not one."
//
//  Condition 3 is the one this file must never break: **core-lite MUST NOT be on
//  any recovery path.** Nothing here is called from a reconnect, and
//  `ContractCourier` documents why at length.
//
//  ===========================================================================
//  F-7 AND F-10: WHY A CORE FAULT CANNOT ABORT THE UI
//  ===========================================================================
//
//  ADR-0019 X3(5) requires that "a core fault MUST NOT abort the UI process", and
//  records it as "discharged twice: on Windows, macOS, Linux and Android the UI
//  process does not load the core at all; **on iOS/iPadOS, where the app hosts a
//  core-lite instance, ADR-0018 F-7's `catch_unwind` and poison contain it and
//  emit `INTERNAL.CORE_PANIC`**."
//
//  F-10 closes the remaining gap: `tw_render_diagnostic` is "pure: no I/O, no
//  clock, no ambient locale, no ambient platform, no instance, no global state…
//  **callable while an instance is poisoned**". So `renderDiagnostic` below does
//  NOT go through the instance, and it keeps working after a panic has poisoned
//  it — which is exactly when a user most needs to be told something.

import Foundation
import TwinVPNCore
// `UIDevice`, for `PlatformContext.current()` at the bottom of this file. It was
// missing: `import Foundation` does not vend UIKit, and neither does
// `TwinVPNCore`, so `UIDevice.current.userInterfaceIdiom` named nothing.
import UIKit

@MainActor
final class CoreLite {
    static let shared = CoreLite()

    // MARK: - the `tw_core` instance, and why there is not one yet
    //
    // ADR-0019 X3(5) and ADR-0016 PS-24 both describe this process as hosting a
    // `core-lite` instance, and `twinvpn-ffi` exports the whole `twinvpn.h`
    // surface in the `core-lite` profile as well as in `full` — its own manifest
    // says so: "F-1 makes the ABI a permanent obligation, so the surface is the
    // same either way; what differs is which core sits behind it." So
    // `tw_core_create` is linkable here and `CoreInstance.swift` in the extension
    // is the working model for how to call it.
    //
    // **Nothing in the app submits to it, so it is not created.** Every member
    // below is either F-10 (instance-free by construction) or a byte codec; the
    // only member that would need an instance is `assembleBundle`, and the ABI
    // cannot express what it needs:
    //
    //   * `twinvpn.h` makes `tw_core_submit` FIRE-AND-FORGET — "the ABI is
    //     in-process and fire-and-forget, so there is no request to correlate and
    //     no retry to deduplicate" — and every outcome arrives on the one ordered
    //     event stream. A synchronous `assembleBundle(providerTail:) -> Bundle`
    //     is a request/response call, and the only correlation this ABI offers is
    //     the `op` string on a `command.completed` body: per-OPERATION, not
    //     per-request.
    //   * The operation the assembly needs is refused today regardless.
    //     `twinvpn-core`'s `dispatch::disposition` answers `diag.bundle.create`
    //     with `STORE.CUSTODY_DEGRADED`, "a Tier-1 bundle is written to an
    //     agent-owned directory the vault vends (MI-D3), which needs
    //     `Core::open_store`".
    //
    // An instance created here today would therefore be a handle nothing holds a
    // conversation with, and F-6 would oblige a serial queue and a drain thread
    // to guard it — machinery for a conversation the ABI cannot carry. It is left
    // absent, and named, rather than built as scaffolding.
    //
    // Everything below this line is F-10, which is INSTANCE-FREE by construction,
    // and the MI request/response codec, which is bytes.

    // MARK: - rendering (F-10, instance-free)

    /// The three-part diagnostic, resolved by the core.
    ///
    /// **Instance-free.** This is F-1's one exception, and the reason is stated
    /// there: "the moment a diagnostic most needs rendering is exactly when no
    /// such instance exists — after `INTERNAL.CORE_PANIC` poisoned it, before
    /// `tw_core_create` has run, or inside a crash reporter."
    ///
    /// `platformContext` is passed EXPLICITLY. LT-3b: an empty one "MUST resolve
    /// to the platform-neutral variant and MUST NOT fall back to the host's own
    /// platform", and CD-2 forbids reading the OS version ambiently — so the app
    /// supplies it as data, the same way it supplies the locale.
    func renderDiagnostic(reasonCode: String,
                          evidence: [String: String],
                          locale: String,
                          platformContext: Data) -> RenderedDiagnostic {
        let evidenceBytes = (try? JSONSerialization.data(withJSONObject: evidence)) ?? Data()
        let rendered = reasonCode.withCString { code in
            evidenceBytes.withUnsafeBytes { ev in
                locale.withCString { loc in
                    platformContext.withUnsafeBytes { ctx in
                        tw_render_diagnostic(
                            tw_slice(ptr: UnsafeRawPointer(code).assumingMemoryBound(to: UInt8.self),
                                     len: strlen(code)),
                            tw_slice(ptr: ev.bindMemory(to: UInt8.self).baseAddress, len: ev.count),
                            tw_slice(ptr: UnsafeRawPointer(loc).assumingMemoryBound(to: UInt8.self),
                                     len: strlen(loc)),
                            tw_slice(ptr: ctx.bindMemory(to: UInt8.self).baseAddress, len: ctx.count))
                    }
                }
            }
        }
        defer { if let rendered { tw_buf_free(rendered) } }
        return RenderedDiagnostic.decode(rendered)
    }

    /// `renderDiagnostic`'s summary alone, for a key that carries no evidence.
    ///
    /// **NOT FOR CHROME.** Tab labels, navigation titles, button labels and
    /// accessibility labels are the SHELL's, and live in
    /// `Resources/Localizable.xcstrings`. They were routed through here once, on
    /// a comment claiming a "sibling entry point" to `tw_render_diagnostic` that
    /// `core/ffi/include/twinvpn.h` does not have; what actually happened is that
    /// `ObservedReasonCode::parse` rejected each lowercase key, `render` degraded
    /// to `Domain::Internal`, and every one of them displayed the INTERNAL
    /// fallback — "TwinVPN hit a defect in itself." — as its label.
    ///
    /// The one remaining caller is `StatusView`'s protection indicator, with
    /// `ui.protection.unknown`. That key is NOT chrome — it is a sentence about
    /// security posture, ADR-0019 §11.4's territory rather than a tab label — and
    /// it is left routed here, still unresolved, until it is decided whether it
    /// deserves a registered reason code. It has the same defect today; moving it
    /// into the shell's catalogue would decide that question by accident.
    func string(_ key: String) -> String {
        renderDiagnostic(reasonCode: key,
                         evidence: [:],
                         locale: Locale.current.identifier,
                         platformContext: PlatformContext.current()).summary
    }

    /// The protection indicator's sentence.
    ///
    /// ADR-0015 §11.6 rule 1: the indicator is "a PURE FUNCTION of the most
    /// recent assertion, NEVER of the agent's belief" — so every input is a field
    /// of the assertion and nothing here consults any other state.
    ///
    /// CB-4 splits the work: the SHELL picks which condition it is rendering (a
    /// presentation choice, the same one `StatusView` already makes when it asks
    /// for `ui.protection.unknown` on an absent assertion), and the CORE resolves
    /// that into a sentence. LT-3a's rule — variant selection "made in core from
    /// `platform_ctx`, never a shell choosing among returned keys" — is about
    /// choosing among the keys a render RETURNED, which this does not do.
    ///
    /// Both families travel as evidence because ADR-0015 §11.6 requires the
    /// assertion "for BOTH address families": a render that saw only one could not
    /// say "v4 is protected and v6 is not", which is ADR-0010 R1's forbidden
    /// asymmetry going unreported.
    func renderProtection(_ assertion: ProtectionAssertion) -> String {
        renderDiagnostic(
            reasonCode: "ui.protection.\(assertion.state.rawValue)",
            evidence: [
                "family_v4_protected": String(assertion.familyV4Protected),
                "family_v6_protected": String(assertion.familyV6Protected),
                // MI-16's stamp, carried so the render can say how old the fact
                // is. The freshness JUDGEMENT is the core's; this is the input.
                "as_of_ms": String(assertion.asOfMillis),
            ],
            locale: Locale.current.identifier,
            platformContext: PlatformContext.current()).summary
    }

    // MARK: - the management interface, as a client of the extension
    //
    // ADR-0017 §11.2.1's channel: `NETunnelProviderSession.sendProviderMessage`,
    // request/response, app-initiated, only while the session is connected. The
    // CONTRACT is not a subset — "same operations, same scopes, same schema, same
    // reason codes" — so these are §11.9 operations in §11.3 envelopes, built by
    // the one `MIFrame` in `Sources/TwinVPNShared`, which the extension also
    // compiles. `ManagementClient` moves the bytes; it never builds or reads one.

    /// `status.get`'s request.
    ///
    /// §11.9's first row: "Derived `TwinNet`-scope `ConnectionState` …
    /// enforcement mode, `ProtectionAssertion` + its freshness". Read-only,
    /// `mgmt.status`, no parameters and no `if_version`.
    func makeStatusRequest() -> Data { MIFrame.request("status.get") }

    /// `diag.log.tail`'s request — the provider's bounded Tier-0 tail.
    ///
    /// ADR-0022 LC-17 leaves the provider "diagnostic ring beyond bounded 64 KB
    /// tail"-free and puts assembly in this process; this is the ask for the tail
    /// the provider does hold.
    ///
    /// **§11.9 gives this row a `since` parameter and none is sent, because none
    /// can be honestly encoded from here** — `params` is F-8 bytes produced by the
    /// core's own encoder, and this shell has no encoder for them (see the note in
    /// `DiagnosticsView`'s partner finding). It is submitted as the whole tail;
    /// `twinvpn-core`'s `dispatch::disposition` refuses the operation today with
    /// `STORE.CUSTODY_DEGRADED` regardless, so the frame is what is being pinned
    /// here, not a working read.
    func makeRingTailRequest() -> Data { MIFrame.request("diag.log.tail") }

    /// One `status.get` response, decoded.
    ///
    /// The ENVELOPE decode is normative and is `MIFrame`/`MIResponse`'s:
    /// `twinvpn.h` fixes the 4-byte big-endian prefix and the UTF-8 JSON
    /// `MgmtEnvelope`, and `body.kind` is the discriminator.
    ///
    /// **The RESULT decode is not, and this is a stated limitation rather than a
    /// silent assumption.** `Response::result` is `Vec<u8>` — F-8 bytes whose
    /// encoding belongs to the operation. `twinvpn-core` encodes its own results
    /// with `prost`; `StatusSnapshot` is a JSON `Decodable` declared by this shell,
    /// and it is the same shape `StatusRecord.read()` already requires of the App
    /// Group record, so within this shell there is exactly one spelling rather
    /// than two. What does NOT yet exist is a provider that answers
    /// `sendProviderMessage` at all — `PacketTunnelProvider.handleAppMessage`
    /// returns `nil` today — so no byte stream has ever met this decoder.
    ///
    /// It FAILS CLOSED, which is the property that matters until it does: a
    /// response this build cannot read yields `nil`, `ManagementClient` leaves
    /// `snapshot` unset, and ADR-0015 O-18's direction — "an unrenewed assertion →
    /// the indicator becomes UNKNOWN, never PROTECTED" — is what the view already
    /// does with an absence. A wrong guess here shows UNKNOWN; it cannot show
    /// PROTECTED.
    func decodeStatus(_ response: Data) -> StatusSnapshot? {
        guard let envelope = MIResponse.decode(response), envelope.ok else {
            // `ok == false` carries a registered code, not a snapshot. The code is
            // the channel's to report and the core's to render; there is no
            // partial snapshot to salvage from a refusal.
            return nil
        }
        return try? JSONDecoder().decode(StatusSnapshot.self, from: envelope.result)
    }

    // MARK: - the Tier-1 bundle

    /// Assembles the eight-part Tier-1 bundle ADR-0015 §11.8 requires.
    ///
    /// **It refuses, and the refusal is the honest answer for this build.** Two
    /// independent things are missing and neither is this shell's to supply:
    ///
    ///   1. `twinvpn-core`'s `dispatch::disposition` marks `diag.bundle.create`
    ///      `NotWired` and answers `STORE.CUSTODY_DEGRADED` — "a Tier-1 bundle is
    ///      written to an agent-owned directory the vault vends (MI-D3), which
    ///      needs `Core::open_store`". The operation NAME is in ADR-0017 §11.9's
    ///      catalogue and in `twinvpn_mgmt::command::CoreCommand`, so nothing is
    ///      invented here; what is absent is the core's implementation of it.
    ///   2. `providerTail` has no encoding this shell can produce. `params` is
    ///      F-8 bytes belonging to the operation, written by the core's own
    ///      encoder, and this process has none — the same gap
    ///      `makeRingTailRequest` names for `diag.log.tail`'s `since`.
    ///
    /// It FAILS CLOSED, which is the property that matters: the caller reports a
    /// registered code and shows no bundle, rather than exporting an empty or
    /// partial artifact that a user might send to support as if it were evidence.
    /// ADR-0015 §11.8's bundle is "signed with `DeviceKey`" and expiring; a
    /// half-assembled one is not a smaller bundle, it is a different thing
    /// wearing the same name.
    ///
    /// The tail the provider handed over is DISCARDED here rather than held: it
    /// is Tier-0 log bytes with nothing to assemble them into, and keeping them
    /// alive in this process would be retention with no purpose.
    func assembleBundle(providerTail: Data) throws -> DiagnosticBundle {
        throw CoreLiteRefusal(reasonCode: ReasonCode.storeCustodyDegraded)
    }
}

/// A refusal from `core-lite`, carrying the REGISTERED code that names it.
///
/// A code, never a sentence — `ownership.md` §6 rule 12 admits registered codes
/// only, and CB-4 puts the rendering in the core. The surface that catches this
/// hands `reasonCode` to `tw_render_diagnostic` and shows what comes back.
struct CoreLiteRefusal: Error {
    let reasonCode: String
}

/// What `tw_render_diagnostic` returns: three parts, all three always present.
///
/// ADR-0019 §11.8: at compact width "the FULL three-part diagnostic still
/// renders… a truncated part 2 is an R-33 violation." So the type has no optional
/// explanation — a shell that could not render part 2 would have to say so rather
/// than quietly omitting it.
struct RenderedDiagnostic {
    let summary: String
    let explanation: String
    let nextAction: NextAction?

    static func decode(_ buffer: OpaquePointer?) -> RenderedDiagnostic {
        guard let buffer else {
            // ADR-0015 §11.2 rule 5: an unknown code "degrades to the DOMAIN
            // prefix" and "must not display the raw code as the primary signal".
            // The degradation is the CORE's; a nil here means the render itself
            // failed, which is a different and rarer condition.
            return RenderedDiagnostic(summary: "", explanation: "", nextAction: nil)
        }
        let slice = tw_buf_bytes(buffer)
        guard let ptr = slice.ptr,
              let decoded = try? JSONDecoder().decode(
                  Wire.self, from: Data(bytes: ptr, count: slice.len)) else {
            return RenderedDiagnostic(summary: "", explanation: "", nextAction: nil)
        }
        return RenderedDiagnostic(
            summary: decoded.summary,
            explanation: decoded.explanation,
            nextAction: decoded.nextAction)
    }

    private struct Wire: Decodable {
        let summary: String
        let explanation: String
        let nextAction: NextAction?

        enum CodingKeys: String, CodingKey {
            case summary, explanation
            case nextAction = "next_action"
        }
    }
}

/// The next action, INCLUDING its deep link.
///
/// LT-3's iOS row gives `App-prefs:General&path=VPN` "where available; otherwise
/// instructions only", and LT-3a puts that selection in the core: "made in core
/// from `platform_ctx`, never a shell choosing among returned keys." So the URL
/// arrives here already chosen, and this shell decides only whether tapping opens
/// it — which is presentation.
struct NextAction: Decodable {
    let label: String
    let deepLink: URL?

    enum CodingKeys: String, CodingKey {
        case label
        case deepLink = "deep_link"
    }
}

/// The `platform_ctx` every render carries.
///
/// Built explicitly rather than read ambiently. CD-2 forbids ambient inputs, and
/// LT-3b forbids falling back to the host's own platform when it is empty — the
/// two together mean the app must SAY which platform it is, every time.
enum PlatformContext {
    static func current() -> Data {
        let context: [String: String] = [
            "platform": UIDevice.current.userInterfaceIdiom == .pad ? "ipados" : "ios",
            "os_version": UIDevice.current.systemVersion,
        ]
        return (try? JSONSerialization.data(withJSONObject: context)) ?? Data()
    }
}
