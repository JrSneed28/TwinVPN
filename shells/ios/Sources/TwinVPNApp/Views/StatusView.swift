//  StatusView.swift — the connect screen: one focal disc, one status line, and
//  the three-part diagnostic the contract requires in full.
//
//  Authority: `shells/ios/DESIGN.md` D1–D4, §2.4, §4.2, §6, §7, §8.2, §8.3, §10;
//  ADR-0015 §11.6 (`ProtectionAssertion`, O-18), §11.4 (redaction); ADR-0018
//  CB-4, F-10; ADR-0019 §11.8 (Split View), LT-3, A11Y-1, A11Y-3, A11Y-4,
//  A11Y-6, A11Y-8; ADR-0017 MI-15, MI-16.
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
//
//  ===========================================================================
//  WHY THIS IS A `ScrollView` AND NOT A `List`
//  ===========================================================================
//
//  DESIGN.md's Floor paragraph: `.scrollContentBackground(.hidden)` is iOS 16.0
//  and this product's floor is 15.0 (ADR-0018 §11.9 row 1). A `List` paints its
//  own opaque background at 15.0 and there is no supported way to remove it, so
//  a `List` here would draw a slab over §3's backdrop — which D1 makes the state
//  indicator. The list was the chrome; the backdrop is the information.
//
//  The `NavigationView` goes with it. §6: "the focal cluster owns the top ~55 %
//  of a 390 × 844 screen with nothing else in it", and a large title bar is
//  something. The screen's name is already on its tab.

import SwiftUI

struct StatusView: View {
    /// Resolved once, at the root, so the tab and the backdrop cannot disagree.
    let visual: StateVisual

    @EnvironmentObject private var permission: VPNPermission
    @EnvironmentObject private var management: ManagementClient
    @Environment(\.dynamicTypeSize) private var typeSize
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                FocalCluster(
                    visual: visual,
                    assertion: assertion,
                    diameter: discDiameter,
                    action: connectAction)

                // §6: "Focal cluster → first panel — 48". A fixed gap, not a
                // `Spacer`: §6's "If that space is empty because there is no
                // diagnostic, it stays empty" means the panels do not float up
                // to fill the screen when there is nothing to say.
                Color.clear.frame(height: Space.clusterToPanel)

                VStack(spacing: Space.betweenPanels) {
                    if let code = permission.reasonCode {
                        // The whole three-part diagnostic, resolved in the core.
                        // ADR-0019 §11.8: at compact width "the FULL three-part
                        // diagnostic still renders… a truncated part 2 is an R-33
                        // violation", which is why this is a `DiagnosticView` and
                        // not a one-line label.
                        DiagnosticView(reasonCode: code, evidence: [:])
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .glassPanel(tone: visual.tone)
                            .panelTransition(reduceMotion: reduceMotion)
                    }

                    // ADR-0015 §11.4: an interface name, an endpoint and a peer
                    // id are all SENSITIVE. The snapshot that crosses MI carries
                    // them already classified, and this list renders only what
                    // the classification permits at Tier 0 — it does not decide.
                    //
                    // A11Y-4's stated drop order is "the disc shrinks, the peer
                    // list drops, the diagnostic never does". This is the second
                    // step of it: at an accessibility content size the peers go,
                    // so that the diagnostic above keeps its unlimited lines.
                    if !typeSize.isAccessibilitySize {
                        ForEach(peers) { peer in
                            PeerRow(peer: peer)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .glassCard(tone: visual.tone)
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity)
            .padding(.horizontal, Space.screenMargin)
            .padding(.top, Space.huge)
            .padding(.bottom, Space.xxl)
        }
        // NO PULL-TO-REFRESH, and its removal is the honest option rather than
        // the lazy one.
        //
        // `.refreshable` is iOS 15.0+ but at 15.0 only `List` renders the
        // control; `ScrollView` gained it in iOS 16 beta 4, silently, with no
        // compile-time diagnostic. So on this product's floor the modifier is a
        // gesture that does nothing, and it came here from the `List` this
        // screen used to be. The two ways to keep a refresh affordance both lose
        // to the design: a toolbar button needs a navigation bar, which §6's
        // "the focal cluster owns the top ~55 % … with nothing else in it" does
        // not have, and any button needs an `arrow.clockwise`, which §9's "no SF
        // Symbol that is not one of the four in §2.4 plus the three tab glyphs"
        // forbids.
        //
        // Nothing is lost. ADR-0017 §11.2.1's first emulation already polls
        // `status.get` at 1 s for the whole time this scene is visible, so a
        // manual refresh could advance the snapshot by at most one interval.
        // §7: panels rise on appear and fade on dismiss. The animation is driven
        // from here because a `transition` is played by whichever `withAnimation`
        // encloses the change, and the change is a `@Published` one.
        .animation(Motion.panelAppear, value: permission.reasonCode)
    }

    // `@MainActor` on the three properties below, and not on the type: SwiftUI
    // marks `View.body` main-actor-isolated, but a computed property that is not
    // `body` is not. `VPNPermission` and `ManagementClient` are both
    // `@MainActor` classes (ADR-0017 §11.2.1's one-client-per-process rule is
    // why), so reading them from a nonisolated member is an isolation error the
    // moment strict checking is turned on.

    /// O-18 again, and the same expression as before the redesign: not
    /// `snapshot?.protection ?? .protected`, because an absence does not round
    /// toward green.
    @MainActor
    private var assertion: ProtectionAssertion? {
        management.isLive ? management.snapshot?.protection : nil
    }

    @MainActor
    private var peers: [PeerSummary] {
        management.snapshot?.peers ?? []
    }

    /// The disc's action, or `nil` where there is nothing the app can do.
    ///
    /// DESIGN.md §10 left this open — "a functionality decision that is yours,
    /// not this document's" — and it is now decided: the disc connects.
    ///
    /// `nil` for `.denied` and `.disabled`, which disables the control. ADR-0012
    /// §11.10: "on iOS/iPadOS the **only** unblock mechanism is removing the VPN
    /// profile in Settings — this is not 'ours', not a command". An enabled disc
    /// there would be a control that cannot work; the diagnostic panel below
    /// carries the next action instead, with the core choosing LT-3's
    /// `App-prefs:General&path=VPN` variant.
    @MainActor
    private var connectAction: (() -> Void)? {
        switch permission.state {
        case .absent, .installed:
            return {
                Task {
                    await permission.connect()
                    // Re-bind, because a first install creates a NEW
                    // `NETunnelProviderManager` and the channel is still holding
                    // the session of whatever came before it — `nil`, on a first
                    // run. Without this the tunnel comes up and the indicator
                    // stays UNKNOWN until the app is next made active, which is
                    // O-18 rounding correctly for the wrong reason.
                    management.attach(to: permission.manager)
                }
            }
        case .denied, .disabled:
            return nil
        }
    }

    /// §6: "Focal disc diameter — **216** (min 152 under compression)".
    ///
    /// Compression is Dynamic Type, and the trigger is the accessibility range
    /// rather than a measured overflow: A11Y-4 requires the full range "with no
    /// diagnostic text clipped at 200 %", and 200 % is where the accessibility
    /// sizes begin. Measuring the diagnostic to decide would need a layout pass
    /// whose result feeds back into the same layout.
    private var discDiameter: CGFloat {
        typeSize.isAccessibilitySize ? Space.discDiameterMin : Space.discDiameter
    }
}

// MARK: - the focal cluster (DESIGN.md D4, §6, §8.3)

/// The disc, the status hero and the qualifier — **one** accessibility element,
/// reading in that order (DESIGN.md §8.3, A11Y-3).
struct FocalCluster: View {
    let visual: StateVisual
    let assertion: ProtectionAssertion?
    let diameter: CGFloat
    var action: (() -> Void)?

    var body: some View {
        VStack(spacing: 0) {
            FocalDisc(visual: visual, diameter: diameter, action: action)

            Color.clear.frame(height: Space.discToHero)
            StyledText(label, .statusHero)

            // The qualifier line. §5 gives it a type role and §8.3 puts it third
            // in the combined element; it has no content today, and this is the
            // same held-open slot as §2.4's "Vocabulary slots held open".
            //
            // It stays EMPTY rather than being filled locally. CB-4 puts every
            // user-facing sentence in the core's catalogue or the shell's chrome
            // catalogue, and neither carries a qualifier for a
            // `ProtectionAssertion` today — §11.3's seven user-facing statuses
            // "the iOS app does not receive… today". Writing one here would be
            // the exact mistake the header of `TwinVPNApp.swift` records: a
            // shell inventing a string because a slot existed for it.
            if let qualifier {
                Color.clear.frame(height: Space.heroToQualifier)
                StyledText(qualifier, .qualifier)
            }
        }
        // §8.3: "the existing `.accessibilityElement(children: .combine)` on the
        // indicator stays exactly as it is."
        .accessibilityElement(children: .combine)
        .accessibilityLabel(label)
    }

    private var qualifier: String? { nil }

    /// The badge's text, from the SHELL's catalogue.
    ///
    /// # Why this is not a `tw_render_diagnostic` call
    ///
    /// It used to be one, with `"ui.protection.\(state)"` passed as a
    /// `reason_code`. That is not a reason code: `ObservedReasonCode::parse`
    /// rejects a lowercase byte, `render` degrades an unparseable code to
    /// `Domain::Internal` (ADR-0015 §11.2 rule 5, working as designed), and the
    /// badge rendered the INTERNAL domain sentence — "TwinVPN hit a defect in
    /// itself." — in all four cases, including `protected`, next to a green
    /// shield. The core was right; the caller was sending it a non-code.
    ///
    /// The badge is not a `Diagnostic` and has no `reason_code`. ADR-0019 §11.3
    /// puts it among the "two facts [that] ride ALONGSIDE the status", and UI-2
    /// models it as the enum `protection.indicator:
    /// PROTECTED|UNPROTECTED_ANNOUNCED|UNKNOWN`. §11.4 — the reason-code
    /// presentation contract — is about what a surface does with a `Diagnostic`.
    /// So this is a projected enum label, which is chrome, and R-36 makes it
    /// Android's `protection_*` keys spelled the same way.
    ///
    /// The WHY behind a posture is still the core's: `POLICY.KILLSWITCH.*` and
    /// `POLICY.LEAK.*` are registered codes and arrive through `DiagnosticView`,
    /// which is also where the per-family detail belongs — a three-valued badge
    /// was never able to say "v4 is protected and v6 is not".
    ///
    /// # It is a function of the ASSERTION, not of `StateVisual`
    ///
    /// `StateVisual.resolve` also answers for the profile, so it paints
    /// `attention` when the user has denied or disabled the VPN configuration.
    /// That is a fact about a profile, and none of the four `protection_*` keys
    /// is a claim about a profile — they are claims about traffic. Deriving the
    /// text from the tone would put `protection_unprotected` on screen on the
    /// strength of a Settings toggle, which is precisely the re-assertion D2
    /// forbids. The tone, the glyph and the field say "something needs you"; the
    /// diagnostic panel below says what, in the core's words.
    private var label: String {
        // O-18 fixes which way an absence rounds, and it is not toward green.
        guard let assertion else { return String(localized: "protection_unknown") }
        switch assertion.state {
        case .protected: return String(localized: "protection_protected")
        case .blocked: return String(localized: "protection_blocked")
        case .unprotected: return String(localized: "protection_unprotected")
        }
    }
}

/// The one large disc. D4: "It shows the state, and tapping it is the action."
///
/// # It is wired, and `nil` is a state rather than a default
///
/// DESIGN.md §10 left the wiring open — "a functionality decision that is yours,
/// not this document's" — and it is now made: `StatusView.connectAction` passes
/// `VPNPermission.connect()`. This view still knows nothing about it. `action`
/// stays optional because §10's `.disabled` affordance is exactly what
/// `.denied` and `.disabled` need, and the press animation, the button trait and
/// the enabled affordance all follow from the same `nil` check.
struct FocalDisc: View {
    let visual: StateVisual
    let diameter: CGFloat
    var action: (() -> Void)?

    @Environment(\.colorScheme) private var scheme
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var isPressed = false

    var body: some View {
        Button(action: { action?() }) {
            Image(systemName: visual.symbol)
                // D1: "There is no accent colour on a button, no coloured icon,
                // no state dot." The glyph is achromatic; the room's light is
                // what changed.
                .font(.system(size: diameter * 0.36, weight: .regular))
                .foregroundColor(DesignTokens.textPrimary(scheme))
                .frame(width: diameter, height: diameter)
                .glass(Circle(), tone: visual.tone)
                .overlay(contrastRing)
                .shadow(color: glowColor, radius: 40, x: 0, y: 0)
        }
        .buttonStyle(.plain)
        .disabled(action == nil)
        // A11Y-8's 44 × 44 is satisfied many times over by a 152 pt floor; the
        // constraint is stated so a later compression cannot quietly cross it.
        .frame(minWidth: Space.minTapTarget, minHeight: Space.minTapTarget)
        // §7: press is a 0.965 scale spring, and "the disc press becomes an
        // opacity change" under Reduce Motion.
        .scaleEffect(reduceMotion || !isPressed ? 1.0 : Motion.discPressScale)
        .opacity(reduceMotion && isPressed ? 0.7 : 1.0)
        .animation(Motion.discPress, value: isPressed)
        .animation(Motion.tone, value: visual.symbol)
        .simultaneousGesture(
            DragGesture(minimumDistance: 0)
                .onChanged { _ in if action != nil { isPressed = true } }
                .onEnded { _ in isPressed = false })
    }

    /// §4.2: "Radius 40, **zero offset** — a glow, not a shadow. Under Reduce
    /// Transparency or Increase Contrast it is removed entirely (the disc is
    /// opaque there and a glow around an opaque disc reads as smear)."
    private var glowColor: Color {
        guard !reduceTransparency, contrast == .standard else { return .clear }
        return visual.tone.color(scheme, contrast).opacity(0.28)
    }

    /// §8.2: "the disc gains a 2 pt tone-coloured ring — so the state is carried
    /// by a **shape** the moment colour is unreliable."
    @ViewBuilder
    private var contrastRing: some View {
        if contrast == .increased {
            Circle().strokeBorder(visual.tone.color(scheme, contrast), lineWidth: 2)
        }
    }
}

// MARK: - peers

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
        VStack(alignment: .leading, spacing: Space.panelStackGap) {
            // The token is opaque and can be long. Monospaced so two of them
            // compare by eye — §5's monospaced role keeps +0.5 tracking for
            // exactly that reason (A11Y-9) — and `.middle` so the two ends, the
            // parts that differ, survive a compact width.
            StyledText(peer.id, .mono)
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

// MARK: - the diagnostic

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

        VStack(alignment: .leading, spacing: Space.panelStackGap) {
            // Part 1: what happened. Part 2: why. Part 3: what to do.
            //
            // All three render at every width AND at every type size (ADR-0019
            // §11.8 / R-33). DESIGN.md §5: parts 1, 2 and 3 have "**no line
            // limit and no `.minimumScaleFactor`**" — the default is no limit,
            // so the guarantee here is that nothing below adds one.
            StyledText(rendered.summary, .diagnosticPart1)
            StyledText(rendered.explanation, .body)
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
        // §8.3 / A11Y-3: the diagnostic's three parts are ONE element, "with
        // part 3 as the action's label". `.combine` is what produces that shape:
        // the labels merge into one utterance and the `Link` survives as the
        // element's accessibility action, carrying its own label.
        .accessibilityElement(children: .combine)
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
///
/// D1 is why there is no tint on it: "There is no accent colour on a button."
/// The link is distinguished by being the last line and by carrying the
/// action — not by being blue.
struct NextActionButton: View {
    let action: NextAction

    var body: some View {
        if let destination = action.deepLink {
            Link(destination: destination) {
                StyledText(action.label, .qualifier)
            }
        } else {
            // Instructions only. Still part 3, still rendered in full: ADR-0019
            // §11.8 requires the FULL three-part diagnostic at every width, and
            // "a truncated part 2 is an R-33 violation" applies no less to a
            // dropped part 3.
            StyledText(action.label, .qualifier)
        }
    }
}
