//  StatusView.swift — the protection indicator, and the three-part diagnostic.
//
//  Authority: ADR-0015 §11.6 (`ProtectionAssertion`, O-18), §11.4 (redaction);
//  ADR-0018 CB-4, F-10; ADR-0019 §11.8 (Split View), LT-3; ADR-0017 MI-15, MI-16.
//
//  STATUS: written, not compiled.
//
//  ===========================================================================
//  THE INDICATOR IS A FUNCTION OF THE ASSERTION, NEVER OF A BELIEF
//  ===========================================================================
//
//  ADR-0015 §11.6 rule 1: the `ProtectionAssertion` is "produced by QUERYING the
//  enforcement layer — the actual installed firewall/route rule set from
//  ADR-0012, for both address families — and comparing it against the intended
//  policy. The user-visible protection indicator is a PURE FUNCTION of the most
//  recent assertion, NEVER of the agent's belief."
//
//  O-18 adds the direction: "an unrenewed assertion → the indicator becomes
//  UNKNOWN, never PROTECTED."
//
//  So this view renders `snapshot.protection` when `isLive`, and `UNKNOWN`
//  otherwise. There is no branch here that reasons about whether the tunnel
//  "should" be up: ADR-0017 LC-21/LC-22 require a re-attaching UI to render
//  UNKNOWN "until a snapshot or a fresh `ProtectionAssertion`", and this is that.

import SwiftUI

struct StatusView: View {
    @EnvironmentObject private var permission: VPNPermission
    @EnvironmentObject private var management: ManagementClient

    var body: some View {
        // `NavigationView`, not `NavigationStack`. §11.9 row 1 fixes the
        // deployment floor at iOS 15.0 and `NavigationStack` is iOS 16.0+, so it
        // does not exist at the floor this product commits to. `.stack` is what
        // makes the two behave alike: `NavigationView`'s default on a regular
        // width is the two-column split, and `TARGETED_DEVICE_FAMILY` includes
        // iPad — without it the same code is a single push on iPhone and a
        // sidebar on iPad, which ADR-0019 §11.8's "iPadOS is not iOS scaled up"
        // does not license as an accident.
        NavigationView {
            List {
                Section {
                    ProtectionIndicator(
                        // Not `snapshot?.protection ?? .protected`. O-18 fixes
                        // which way an absence rounds, and it is not toward
                        // green.
                        assertion: management.isLive ? management.snapshot?.protection : nil)
                }

                if let code = permission.reasonCode {
                    Section {
                        // The whole three-part diagnostic, resolved in the core.
                        // ADR-0019 §11.8: at compact width "the FULL three-part
                        // diagnostic still renders… a truncated part 2 is an R-33
                        // violation", which is why this is a `DiagnosticView` and
                        // not a one-line label.
                        DiagnosticView(reasonCode: code, evidence: [:])
                    }
                }

                Section {
                    // ADR-0015 §11.4: an interface name, an endpoint and a peer
                    // id are all SENSITIVE. The snapshot that crosses MI carries
                    // them already classified, and this list renders only what
                    // the classification permits at Tier 0 — it does not decide.
                    ForEach(management.snapshot?.peers ?? []) { peer in
                        PeerRow(peer: peer)
                    }
                }
            }
            .navigationTitle(CoreLite.shared.string("ui.status.title"))
            .refreshable {
                // Pull-to-refresh is a poll the USER asked for, which is the one
                // poll ADR-0017 §11.2.1's battery residual does not have to
                // apologise for.
                management.beginPolling()
            }
        }
        .navigationViewStyle(.stack)
    }
}

/// One peer, as the snapshot classified it.
///
/// # This row renders. It does not filter.
///
/// ADR-0015 §11.4 puts redaction at the EMITTER, "based on the schema
/// classification", and states that "there is no 'scrub the log with regexes
/// before sending' step". `PeerSummary`'s fields arrive already classified and,
/// where the tier required it, pseudonymised — `id` at Tier 0 is a token, not a
/// `DeviceIdentity` — so a filter here would be a second classifier that can
/// disagree with the first.
///
/// # `reason_code`, never a sentence
///
/// MI-15 forbids rendered text on the channel, so `PeerSummary.reasonCode` is a
/// code and the row resolves it through `tw_render_diagnostic` like every other
/// string this app shows. A peer with nothing to report renders its identifier
/// alone; there is no "OK" literal here, because that would be the one piece of
/// user-facing English CB-4 keeps out of this file.
struct PeerRow: View {
    let peer: PeerSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            // The token is opaque and can be long. Monospaced so two of them
            // compare by eye, and `.middle` so the two ends — the parts that
            // differ — survive a compact width.
            Text(peer.id)
                .font(.system(.body, design: .monospaced))
                .truncationMode(.middle)
                .lineLimit(1)
            if let code = peer.reasonCode {
                // The FULL three-part diagnostic, at every width. ADR-0019 §11.8:
                // "a truncated part 2 is an R-33 violation", and a list row is
                // not an exemption from that.
                DiagnosticView(reasonCode: code, evidence: ["as_of_ms": String(peer.asOfMillis)])
            }
        }
    }
}

/// The indicator.
///
/// Three states, and `unknown` is the one an absent assertion produces. There is
/// deliberately no "probably protected".
struct ProtectionIndicator: View {
    let assertion: ProtectionAssertion?

    var body: some View {
        HStack {
            Image(systemName: symbol)
                .foregroundStyle(tint)
                .accessibilityHidden(true)
            Text(label)
        }
        // The whole row is one accessibility element carrying the resolved text,
        // because a screen reader announcing "shield, protected" out of order is
        // a different sentence from the one the catalogue wrote.
        .accessibilityElement(children: .combine)
        .accessibilityLabel(label)
    }

    private var symbol: String {
        switch assertion?.state {
        case .protected: return "checkmark.shield.fill"
        case .blocked: return "shield.slash.fill"
        case .unprotected: return "exclamationmark.shield.fill"
        case nil: return "questionmark.circle"
        }
    }

    private var tint: Color {
        switch assertion?.state {
        case .protected: return .green
        case .blocked: return .orange
        case .unprotected: return .red
        // O-18: an absent assertion is not green and is not red. It is unknown,
        // and it looks unknown.
        case nil: return .secondary
        }
    }

    private var label: String {
        guard let assertion else {
            return CoreLite.shared.string("ui.protection.unknown")
        }
        return CoreLite.shared.renderProtection(assertion)
    }
}

/// The three-part diagnostic, rendered by the core.
///
/// ADR-0018 F-10's `tw_render_diagnostic` is "pure: no I/O, no clock, no ambient
/// locale, no ambient platform, no instance, no global state… callable while an
/// instance is poisoned", which is exactly when a user most needs to be told
/// something.
///
/// `platform_ctx` is supplied EXPLICITLY here — LT-3b forbids falling back to the
/// host's own platform, and CD-2 forbids reading it ambiently.
struct DiagnosticView: View {
    let reasonCode: String
    let evidence: [String: String]

    var body: some View {
        let rendered = CoreLite.shared.renderDiagnostic(
            reasonCode: reasonCode,
            evidence: evidence,
            locale: Locale.current.identifier,
            platformContext: PlatformContext.current())

        VStack(alignment: .leading, spacing: 8) {
            // Part 1: what happened. Part 2: why. Part 3: what to do.
            // All three render at every width (ADR-0019 §11.8 / R-33).
            Text(rendered.summary).font(.headline)
            Text(rendered.explanation).font(.body)
            if let action = rendered.nextAction {
                // The deep link, when there is one, is INSIDE the rendered next
                // action — LT-3's iOS row names `App-prefs:General&path=VPN`
                // "where available; otherwise instructions only", and which of
                // those applies is the core's variant selection, not a check in
                // this file.
                NextActionButton(action: action)
            }
        }
        .fixedSize(horizontal: false, vertical: true)
    }
}

/// Part 3 of the diagnostic: what to do, and — where the core supplied one — the
/// deep link that does it.
///
/// # This view makes exactly one decision, and it is a presentation one
///
/// LT-3a: the choice of WHICH next-action variant applies is "made in core from
/// `platform_ctx`, never a shell choosing among returned keys", and LT-3's iOS
/// row is what the core is choosing between — `App-prefs:General&path=VPN`
/// "where available; otherwise instructions only". So by the time an action
/// reaches here the question "is there a link?" has already been answered, and
/// `NextAction.deepLink` is that answer. The only thing left is whether tapping
/// opens it, which is CB-4's "presentation" column.
///
/// **A missing link is not an error and is not a disabled button.** LT-3's
/// "otherwise instructions only" means the label alone IS the whole next action
/// on that variant, so it renders as text. A dead control would tell the user
/// something is broken when nothing is.
///
/// `Link` is SwiftUI's own control for opening a URL and needs no UIKit and no
/// `UIApplication`. It handles a non-`http` scheme — which `App-prefs:` is —
/// through the same `openURL` action the environment vends.
struct NextActionButton: View {
    let action: NextAction

    var body: some View {
        if let destination = action.deepLink {
            Link(action.label, destination: destination)
        } else {
            // Instructions only. Still part 3, still rendered in full: ADR-0019
            // §11.8 requires the FULL three-part diagnostic at every width, and
            // "a truncated part 2 is an R-33 violation" applies no less to a
            // dropped part 3.
            Text(action.label)
        }
    }
}
