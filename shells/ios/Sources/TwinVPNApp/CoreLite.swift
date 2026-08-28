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

@MainActor
final class CoreLite {
    static let shared = CoreLite()

    private var instance: OpaquePointer?

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

    /// A catalogue string.
    ///
    /// The catalogue "ships EMBEDDED in the artifact, so it is covered by S-46 and
    /// by DP-5's SBOM" (CB-4) — which a literal in a Swift file is not.
    func string(_ key: String) -> String {
        renderDiagnostic(reasonCode: key,
                         evidence: [:],
                         locale: Locale.current.identifier,
                         platformContext: PlatformContext.current()).summary
    }
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

    static func decode(_ buffer: UnsafeMutablePointer<tw_buf>?) -> RenderedDiagnostic {
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
