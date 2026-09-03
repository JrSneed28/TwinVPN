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

    // MARK: - the `tw_core` instance, and why there is still not one
    //
    // ADR-0019 X3(5) and ADR-0016 PS-24 both describe this process as hosting a
    // `core-lite` instance, and `twinvpn-ffi` exports the whole `twinvpn.h`
    // surface in the `core-lite` profile as well as in `full` — its own manifest
    // says so: "F-1 makes the ABI a permanent obligation, so the surface is the
    // same either way; what differs is which core sits behind it." So
    // `tw_core_create` is linkable here and `CoreInstance.swift` in the extension
    // is the working model for how to call it.
    //
    // **Nothing in the app submits to one, so none is created.** The old note
    // here gave the reason as the ABI's — "there is no request to correlate" —
    // and ABI minor 3's `tw_core_submit_response` made that half FALSE. The
    // reason was therefore RE-MEASURED rather than inherited, and what is left is
    // sharper and is not about the ABI at all:
    //
    //   * **`core-lite` performs NO command.** `twinvpn-core`'s
    //     `Core::submit_response` refuses under `#[cfg(not(feature = "full"))]`
    //     with `PLATFORM.ADAPTER_UNAVAILABLE` — "core-lite carries no data-plane
    //     crate, so it performs NO command. Refusing by name is the honest
    //     answer; returning Ok would be the same false success this dispatcher
    //     exists to remove." `pub mod dispatch` and `pub mod pairing` are both
    //     `#[cfg(feature = "full")]`, and `project.yml` links this target against
    //     `-ltwinvpn_core_lite`. An instance here would be a handle that refuses
    //     everything, with an F-6 serial queue to guard it.
    //   * So the app reaches the FULL core the way ADR-0017 §11.2.1 says it
    //     does — `NETunnelProviderSession.sendProviderMessage`, "full
    //     request/response, byte-identical framing" — and `PairingModel` is the
    //     first caller that needs an answer rather than a poll.
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

    // THERE IS DELIBERATELY NO `string(_:)` AND NO `renderProtection(_:)` HERE.
    //
    // Both existed to turn a `ui.*` key into a sentence, and both were defects.
    // `tw_render_diagnostic` resolves REGISTERED reason codes; a `ui.*` key is
    // not one. `ObservedReasonCode::parse` rejects its lowercase bytes, `render`
    // degrades an unparseable code to `Domain::Internal` (ADR-0015 §11.2 rule 5,
    // behaving exactly as specified), and every caller got the INTERNAL domain
    // sentence — "TwinVPN hit a defect in itself." First the tab labels and
    // navigation titles, then, after those were moved out, the protection badge,
    // which read that sentence even in its `protected` state.
    //
    // Chrome lives in `Resources/Localizable.xcstrings`. So does the protection
    // badge: ADR-0019 §11.3 rides it ALONGSIDE the status and UI-2 models it as
    // the enum `PROTECTED|UNPROTECTED_ANNOUNCED|UNKNOWN`, so it is a projected
    // enum label, not a `Diagnostic`, and §11.4 does not reach it. `StatusView`
    // labels it from the catalogue with Android's `protection_*` keys (R-36).
    //
    // A real condition — including why a posture is what it is, and any
    // per-family asymmetry — arrives as a REGISTERED code (`POLICY.KILLSWITCH.*`,
    // `POLICY.LEAK.*`) and renders through `renderDiagnostic` above, whole, with
    // its declared evidence. `Scripts/check-chrome-strings.sh` fails the build on
    // any `ui.*` literal reaching the core, which is what keeps this comment from
    // being the only thing standing between here and a third recurrence.

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

    // MARK: - the enforcement programme

    /// The posture `VPNPermission.install` needs, rendered by the core.
    ///
    /// **It refuses, and the refusal is the honest answer for this build.**
    ///
    /// # Where a programme comes from, and why none of the three routes is open
    ///
    /// `EnforcementProgramme` mirrors `twinvpn_platform_ios::enforce::
    /// EnforcementProgramme` field for field, and Rust renders one with
    /// `EnforcementPosture::programme(generation, ruleset)`. There is a
    /// fail-closed `Default` for the posture — `full_protection_required: true`,
    /// `local_network_access: false`, restart on any interface — whose own
    /// comment says "a `Default` that armed nothing would make 'we never
    /// configured this' and 'policy says protect nothing' the same value". So the
    /// value exists. What does not exist is a way for THIS process to obtain it:
    ///
    ///   1. **Not from `core-lite`.** `Core::submit_response` refuses every
    ///      command under `#[cfg(not(feature = "full"))]` with
    ///      `PLATFORM.ADAPTER_UNAVAILABLE` — "core-lite carries no data-plane
    ///      crate, so it performs NO command". That is the same wall
    ///      `assembleBundle` reports below, reached before dispatch rather than
    ///      inside it.
    ///   2. **Not from the extension.** ADR-0017 §11.2.1's channel works "only
    ///      while the session is connected", and there is no session until a
    ///      profile is installed. Asking the provider for the programme needed to
    ///      install the profile is circular.
    ///   3. **Not from here.** `EnforcementProgramme.swift`'s header names this
    ///      exact temptation and refuses it: "A SECOND COPY IN THE APP WOULD BE
    ///      THE WRONG FIX… two declarations of them is two things that can drift,
    ///      and the drift would show up as an enforcement posture the app
    ///      installed and the extension cannot find." A hard-coded posture would
    ///      also be this shell deciding `include_all_networks`, which is KS-4's
    ///      inversion and CB-2's line — `enforce.rs` keeps the mapping in Rust
    ///      precisely "so the mapping … is one function with tests rather than a
    ///      Swift file".
    ///
    /// Closing it is ONE core change: an FFI export of the rendered default
    /// programme, alongside `tw_render_diagnostic` — pure, instance-free, and
    /// callable before any core exists, which is exactly the shape F-10 already
    /// establishes for a call the shell needs before it can bring anything up.
    /// This function is then a decode of what that returns, and every caller
    /// above it is already written.
    ///
    /// It FAILS CLOSED: the caller installs nothing and renders the registered
    /// code. The alternative — installing a posture this process invented —
    /// would put a profile on the device whose `includeAllNetworks` no part of
    /// the core ever asked for.
    func makeEnforcementProgramme() throws -> EnforcementProgramme {
        throw CoreLiteRefusal(reasonCode: ReasonCode.adapterUnavailable)
    }

    // MARK: - the Tier-1 bundle

    /// Assembles the eight-part Tier-1 bundle ADR-0015 §11.8 requires.
    ///
    /// **It refuses, and the refusal is the honest answer for this build.** Three
    /// independent things are missing and none is this shell's to supply:
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
    ///   3. **There is no core in this process to ask.** ADR-0018 §11.12 grants
    ///      `core-lite` `Capability::Bundle`, but `Core::submit_response` refuses
    ///      every command under `#[cfg(not(feature = "full"))]` — see the note on
    ///      the missing instance above — so the capability is declared and not yet
    ///      performed. Sending `diag.bundle.create` to the EXTENSION instead, over
    ///      §11.2.1's channel the way `PairingModel` does, would reach a core that
    ///      can dispatch it and still get (1) back; and it would put a Tier-1
    ///      bundle's assembly in the process ADR-0018 §11.12 deliberately moved it
    ///      out of, "to satisfy C-3: the iOS/iPadOS app process PARSES, VERIFIES
    ///      AND RENDERS".
    ///
    /// Closing it is therefore two core changes and then one here, in order:
    /// `diag.bundle.create` implemented, `core-lite` able to perform the commands
    /// its capability set already claims, and a `params` encoder for the tail.
    /// None is a longer function here.
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
