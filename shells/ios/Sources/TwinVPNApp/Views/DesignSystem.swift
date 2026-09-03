//  DesignSystem.swift — the palette, the space scale, the radii, the motion
//  curves, and the one pure function that turns published state into a look.
//
//  Authority: `shells/ios/DESIGN.md` §2 (palette), §2.4 (state mapping), §4.1
//  (radii), §6 (space), §7 (motion), §8 (accessibility variants); ADR-0015 §11.6
//  (O-18); ADR-0018 §11.9 row 1 (the iOS 15.0 floor), CB-4; ADR-0019 A11Y-1,
//  A11Y-5, A11Y-8.
//
//  STATUS: written, not compiled.
//
//  ===========================================================================
//  THIS FILE IS VISUAL. IT READS STATE AND PUBLISHES NOTHING.
//  ===========================================================================
//
//  DESIGN.md's own scope line: "It specifies no behaviour: the state model
//  (`VPNPermission`, `ManagementClient`, `PairingModel`), the string ownership
//  rule (CB-4 — the core resolves, the shell presents), and the management
//  contract are unchanged by everything below."
//
//  So `StateVisual.resolve` is a PURE FUNCTION of three values the app already
//  publishes — `VPNPermission.state`, `ManagementClient.isLive` and
//  `StatusSnapshot.protection`. It adds no `@Published` property, performs no
//  management operation, and calls nothing. Every colour below is a constant.
//
//  There is no user-facing English in this file. There is no string in this file
//  at all except SF Symbol names, which are API identifiers, not copy.

import SwiftUI

// MARK: - the four tones (DESIGN.md §2.3)

/// The whole palette of asserted state. Four tones, and one of them is the
/// absence of an assertion.
///
/// DESIGN.md D2: "Colour is reserved for facts the product is prepared to
/// assert… Everything the product does not yet know (`Connecting`,
/// `Reconnecting`, `Unknown`, `Off`, an unrenewed assertion) renders
/// **achromatic**."
///
/// `neutral` is that achromatic tone. It is a real grey with real contrast
/// numbers, not a disabled or dimmed version of another tone — O-18's "an
/// unrenewed assertion → the indicator becomes UNKNOWN, never PROTECTED" is a
/// statement about a distinct state, and it gets a distinct colour.
enum StateTone: Equatable {
    case secure
    case held
    case attention
    case neutral

    /// The tone, resolved for a scheme and a contrast setting.
    ///
    /// The light and dark values are SEPARATE COLOURS, never one colour with an
    /// opacity change (DESIGN.md §2): "a green that is legible on `#0B0E0F` is
    /// 1.91:1 on `#F2F0EC` and would fail outright."
    ///
    /// The `.increased` pair is DESIGN.md §8.2's high-contrast swap. It is not a
    /// darkening of the standard pair; each value was picked against the ground
    /// it sits on.
    func color(_ scheme: ColorScheme, _ contrast: ColorSchemeContrast) -> Color {
        switch (self, scheme, contrast) {
        case (.secure, .light, .standard): return Color(hex: 0x0F7A54)
        case (.secure, .light, _): return Color(hex: 0x0A5B3E)
        case (.secure, _, .standard): return Color(hex: 0x34C98D)
        case (.secure, _, _): return Color(hex: 0x5BE3AB)

        case (.held, .light, .standard): return Color(hex: 0x8A5A08)
        case (.held, .light, _): return Color(hex: 0x6B4506)
        case (.held, _, .standard): return Color(hex: 0xE8A33D)
        case (.held, _, _): return Color(hex: 0xF5BE6A)

        case (.attention, .light, .standard): return Color(hex: 0xC0272E)
        case (.attention, .light, _): return Color(hex: 0x96161C)
        case (.attention, _, .standard): return Color(hex: 0xF2545B)
        case (.attention, _, _): return Color(hex: 0xFF8288)

        case (.neutral, .light, .standard): return Color(hex: 0x5A6366)
        case (.neutral, .light, _): return Color(hex: 0x41494C)
        case (.neutral, _, .standard): return Color(hex: 0x9AA3A6)
        case (.neutral, _, _): return Color(hex: 0xC2C9CB)
        }
    }
}

// MARK: - the field's geometry (DESIGN.md §2.4, §3)

/// The backdrop field's shape, which A11Y-1 makes a state carrier in its own
/// right.
///
/// DESIGN.md §2.4: "the field's **geometry** (tight/bright vs wide/dim) is a
/// fourth [channel] that survives a greyscale render, which is what the P18
/// oracle-5 pairwise image diff actually tests."
enum FieldGeometry: Equatable {
    /// Small, luminous, confident. The product is asserting something.
    case tightBright
    /// Large, dim, diffuse. The product is not.
    case wideDim

    /// DESIGN.md §3's field-opacity rows.
    var fieldOpacity: Double {
        switch self {
        case .tightBright: return 0.92
        case .wideDim: return 0.48
        }
    }

    /// DESIGN.md §3: wide/dim takes "both lobe radii ×1.35".
    var lobeRadiusScale: CGFloat {
        switch self {
        case .tightBright: return 1.0
        case .wideDim: return 1.35
        }
    }
}

// MARK: - the state mapping (DESIGN.md §2.4)

/// Everything the visual layer needs, derived from state the app already has.
///
/// # Why this is one struct and not four computed properties on a view
///
/// A11Y-1 requires state to be carried by at least two of {glyph, text label,
/// position} and to survive a greyscale render. Tone, geometry, breathing and
/// glyph are four channels that must never disagree, and the way to guarantee
/// they never disagree is to derive them together, once, from the same input —
/// not in four `switch`es that a later edit can drift apart.
struct StateVisual: Equatable {
    let tone: StateTone
    let geometry: FieldGeometry
    /// DESIGN.md §2.4: only the `neutral` row breathes. §7's rule is why —
    /// A11Y-6 "forbids a spinner as the sole indication of progress", so the
    /// breathing field is a fourth redundant channel and never the only one.
    let isBreathing: Bool
    /// One of the four SF Symbols DESIGN.md §9 permits. Not copy: an API name.
    let symbol: String

    /// The one absence: no profile, no live channel, or no assertion.
    ///
    /// O-18 fixes which way this rounds, and it is not toward green.
    static let unknown = StateVisual(
        tone: .neutral, geometry: .wideDim, isBreathing: true,
        symbol: "questionmark.circle")

    /// DESIGN.md §2.4's table, in the order §2.4 states it reads:
    /// `VPNPermission.state`, then `ManagementClient.isLive`, then
    /// `StatusSnapshot.protection`.
    ///
    /// # The order is the honesty rule
    ///
    /// A denied or disabled profile is a fact the OS asserted, so it gets a
    /// tone. An absent one is not a claim about traffic at all, so it does not —
    /// it rounds to `unknown` alongside a dead channel and a missing assertion.
    /// Reversing these two would paint `attention` over a fresh install that has
    /// simply never been asked to protect anything.
    ///
    /// Note what this function does NOT return: a label. The status hero's text
    /// stays a pure function of the `ProtectionAssertion` (O-18) and lives in
    /// `FocalCluster`, because the four `protection_*` catalogue keys are
    /// claims about traffic and this function also answers for the profile.
    static func resolve(profile: ProfileState,
                        isLive: Bool,
                        protection: ProtectionAssertion?) -> StateVisual {
        switch profile {
        case .denied, .disabled:
            return StateVisual(
                tone: .attention, geometry: .wideDim, isBreathing: false,
                symbol: "exclamationmark.shield.fill")
        case .absent:
            return .unknown
        case .installed:
            break
        }

        guard isLive, let protection else { return .unknown }

        switch protection.state {
        case .protected:
            return StateVisual(
                tone: .secure, geometry: .tightBright, isBreathing: false,
                symbol: "checkmark.shield.fill")
        case .blocked:
            return StateVisual(
                tone: .held, geometry: .tightBright, isBreathing: false,
                symbol: "shield.slash.fill")
        case .unprotected:
            return StateVisual(
                tone: .attention, geometry: .wideDim, isBreathing: false,
                symbol: "exclamationmark.shield.fill")
        }
    }
}

// MARK: - ground, glass and text tokens (DESIGN.md §2.1, §2.2, §8.1)

/// The nine non-state tokens.
///
/// Each takes the scheme explicitly rather than reading `@Environment`, so that
/// the values are testable constants and a preview can render both schemes side
/// by side without a second view hierarchy.
enum DesignTokens {
    /// DESIGN.md §2.1: "**Not** `#FFFFFF` or `#000000`: pure extremes give the
    /// glass no light to refract and the material renders dead flat."
    static func ground(_ scheme: ColorScheme) -> Color {
        scheme == .light ? Color(hex: 0xF2F0EC) : Color(hex: 0x0B0E0F)
    }

    /// Painted *over* the material, under the border.
    static func glassTint(_ scheme: ColorScheme) -> Color {
        scheme == .light ? Color.white.opacity(0.42) : Color.white.opacity(0.06)
    }

    /// The only place a hue touches a panel.
    static func glassStateTint(_ tone: StateTone,
                               _ scheme: ColorScheme,
                               _ contrast: ColorSchemeContrast) -> Color {
        tone.color(scheme, contrast).opacity(scheme == .light ? 0.05 : 0.06)
    }

    /// 1 pt, full perimeter. DESIGN.md §8.1 raises the opacity under Reduce
    /// Transparency, because the layers that were doing the separating are gone.
    static func borderHairline(_ scheme: ColorScheme, reduceTransparency: Bool) -> Color {
        if reduceTransparency {
            return scheme == .light
                ? Color.black.opacity(0.18) : Color.white.opacity(0.28)
        }
        return scheme == .light ? Color.black.opacity(0.08) : Color.white.opacity(0.10)
    }

    /// 1 pt inner stroke, linear gradient top→bottom. DESIGN.md D3: glass
    /// "separates from what is behind it… by catching light on its edge, not by
    /// casting darkness below it."
    static func borderHighlight(_ scheme: ColorScheme) -> LinearGradient {
        LinearGradient(
            colors: scheme == .light
                ? [Color.white.opacity(0.65), Color.white.opacity(0.00)]
                : [Color.white.opacity(0.22), Color.white.opacity(0.04)],
            startPoint: .top,
            endPoint: .bottom)
    }

    /// 1 pt inner stroke, **bottom edge only** — expressed as a gradient that is
    /// fully transparent for the top two thirds, because SwiftUI has no
    /// one-edge stroke and a second shape would be a second silhouette to keep
    /// in sync with the first.
    static func innerShade(_ scheme: ColorScheme) -> LinearGradient {
        let shade = scheme == .light
            ? Color.black.opacity(0.05) : Color.black.opacity(0.18)
        return LinearGradient(
            stops: [
                .init(color: .clear, location: 0.00),
                .init(color: .clear, location: 0.65),
                .init(color: shade, location: 1.00),
            ],
            startPoint: .top,
            endPoint: .bottom)
    }

    /// DESIGN.md §8.1: what `.ultraThinMaterial` becomes when the user has asked
    /// for no translucency. `Material` already falls back to opaque on its own;
    /// this exists because the tints stacked on top of it do not, and a
    /// half-removed stack renders muddier than either endpoint.
    static func opaqueMaterial(_ scheme: ColorScheme) -> Color {
        scheme == .light ? Color(hex: 0xFFFFFF) : Color(hex: 0x171B1D)
    }

    /// 17.4:1 light / 15.6:1 dark on glass.
    static func textPrimary(_ scheme: ColorScheme) -> Color {
        scheme == .light ? Color(hex: 0x14181A) : Color(hex: 0xF4F6F6)
    }

    /// 5.79:1 light / 6.68:1 dark on glass — A11Y-5's 4.5:1 with margin.
    static func textSecondary(_ scheme: ColorScheme) -> Color {
        scheme == .light ? Color(hex: 0x5A6366) : Color(hex: 0x9AA3A6)
    }
}

// MARK: - space (DESIGN.md §6)

/// 4 pt base. The scale is `4, 8, 12, 16, 24, 32, 48, 64` and nothing between.
///
/// These are raw point values, NOT `@ScaledMetric`. Dynamic Type scales type;
/// scaling the gaps as well at AX5 would push the focal cluster off a 390 × 844
/// screen before the diagnostic — which A11Y-4's stated drop order forbids, and
/// which §5's "the disc shrinks, the peer list drops, the diagnostic never does"
/// is the layout answer to.
enum Space {
    static let xs: CGFloat = 4
    static let s: CGFloat = 8
    static let m: CGFloat = 12
    static let l: CGFloat = 16
    static let xl: CGFloat = 24
    static let xxl: CGFloat = 32
    static let xxxl: CGFloat = 48
    static let huge: CGFloat = 64

    /// Screen horizontal margin.
    static let screenMargin: CGFloat = 24
    /// Focal disc diameter, and the floor it compresses to.
    static let discDiameter: CGFloat = 216
    static let discDiameterMin: CGFloat = 152
    /// Disc → status hero.
    static let discToHero: CGFloat = 32
    /// Status hero → qualifier line.
    static let heroToQualifier: CGFloat = 8
    /// Focal cluster → first panel.
    static let clusterToPanel: CGFloat = 48
    /// Between panels.
    static let betweenPanels: CGFloat = 16
    /// Panel padding.
    static let panelPadding: CGFloat = 20
    /// Stack gap inside a panel.
    static let panelStackGap: CGFloat = 12
    static let badgePaddingH: CGFloat = 12
    static let badgePaddingV: CGFloat = 6
    /// A11Y-8.
    static let minTapTarget: CGFloat = 44
}

// MARK: - radii (DESIGN.md §4.1)

/// All `.continuous`. No `.circular` corners anywhere.
enum Radius {
    static let panel: CGFloat = 28
    static let card: CGFloat = 20
    static let chip: CGFloat = 12
}

// MARK: - motion (DESIGN.md §7)

/// The six curves, and nothing else.
///
/// DESIGN.md §7's first rule is a performance one and is enforced by absence:
/// **blur radius is never animated**, so there is no curve here for it and
/// `Backdrop` holds its 64 pt radius as a constant outside every animated
/// property.
enum Motion {
    /// Tone change: field colour + glyph.
    static let tone = Animation.easeInOut(duration: 0.42)
    /// Field geometry change (tight ↔ wide).
    static let fieldGeometry = Animation.spring(response: 0.55, dampingFraction: 0.86)
    /// Disc press down / release.
    static let discPress = Animation.spring(response: 0.28, dampingFraction: 0.70)
    static let discPressScale: CGFloat = 0.965
    /// Panel appear: 8 pt rise + fade.
    static let panelAppear = Animation.easeOut(duration: 0.32)
    static let panelRise: CGFloat = 8
    /// Panel dismiss: fade only. "Panels rise on appear and do not fall on
    /// dismiss. Asymmetry is deliberate: arriving information deserves a
    /// gesture, departing information does not."
    static let panelDismiss = Animation.easeIn(duration: 0.20)
    /// The breathing field, at the `neutral` tone only.
    static let breathe = Animation.easeInOut(duration: 2.6).repeatForever(autoreverses: true)
    static let breatheLow: Double = 0.55
    static let breatheHigh: Double = 0.90
    /// Reduce Motion: "the breathing loop stops at a static 0.72".
    static let breatheStatic: Double = 0.72
}

// MARK: - hex

extension Color {
    /// sRGB from a 24-bit literal. DESIGN.md §2: "All values sRGB."
    ///
    /// `Color(.sRGB, …)` and not `Color(red:green:blue:)` — the latter is
    /// documented as sRGB too, but naming the space makes the design document's
    /// contrast measurements checkable against this file rather than assumed.
    init(hex: UInt32) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255.0,
            green: Double((hex >> 8) & 0xFF) / 255.0,
            blue: Double(hex & 0xFF) / 255.0,
            opacity: 1.0)
    }
}
