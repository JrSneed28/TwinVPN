//  GlassSurface.swift — the backdrop field (DESIGN.md §3) and the one glass
//  recipe every surface in the app uses (§4).
//
//  Authority: `shells/ios/DESIGN.md` D1, D3, §3, §4, §4.2, §8.1, §8.2;
//  ADR-0018 §11.9 row 1 (the iOS 15.0 floor); ADR-0019 A11Y-5, A11Y-6.
//
//  STATUS: written, not compiled.
//
//  ===========================================================================
//  TWO LAYERS, AND THE ORDER BETWEEN THEM IS THE DESIGN
//  ===========================================================================
//
//  DESIGN.md D1: "behind the glass sits a single large field of soft light whose
//  **colour and geometry are the connection state**. The glass panels on top are
//  achromatic and carry only text and glyph."
//
//  So `Backdrop` is tinted and `GlassSurface` is not — except for
//  `glassStateTint` at 0.05/0.06, which §2.1 calls "the only place a hue touches
//  a panel". Nothing else in this app draws a background, and nothing else in
//  this app is coloured.
//
//  ===========================================================================
//  WHY `.ultraThinMaterial` AND NOT A HAND-ROLLED BLUR
//  ===========================================================================
//
//  §3: "The **glass** uses `.ultraThinMaterial`, whose radius and saturation are
//  Apple's and are not settable at any iOS version; the design pins the material
//  and specifies every layer stacked on it, rather than pretending to a number
//  it cannot set."
//
//  The field's 64 pt and 1.18 ARE settable, because the app draws the field. The
//  material's are not, so they are not written down as if they were.

import SwiftUI

// MARK: - the backdrop (DESIGN.md §3)

/// One layer, drawn behind everything, ignoring safe areas.
///
/// ```
/// ground fill
///   └─ field: 2 radial gradients, tone-coloured, composited .plusLighter
///        └─ .blur(radius: 64)
///        └─ .saturation(1.18)
/// ```
///
/// # `.plusLighter` is load-bearing, not decorative
///
/// §3: "`.plusLighter` on `ground` `#0B0E0F` is what keeps the field luminous
/// instead of muddy — the two lobes add rather than occlude, so their overlap is
/// the brightest point on the screen and the disc sits in it." The blend is
/// applied twice for that reason: once between the lobes, inside a compositing
/// group, and once between the finished field and the ground.
///
/// # Stale is desaturated
///
/// §3's last paragraph: "Today the app renders a not-live snapshot identically
/// to a live one; this makes the distinction visible without adding a badge, a
/// banner, or a word." `isLive == false` is not a fifth tone — it is a filter
/// over whichever tone applies, so O-18's rounding still decides the hue and
/// this only decides how much of it survives.
struct Backdrop: View {
    let visual: StateVisual
    let isLive: Bool

    @Environment(\.colorScheme) private var scheme
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    @State private var isInhaled = false

    /// §3: 64 pt, and §7's first rule: "**Blur radius is never animated.** It is
    /// a full-screen recomposite per frame." Holding it as a `let` outside every
    /// animated property is how that rule is kept rather than remembered.
    private static let blurRadius: CGFloat = 64

    var body: some View {
        ZStack {
            DesignTokens.ground(scheme)
            // §8.1: under Reduce Transparency the field is "removed; flat
            // `ground`". Not dimmed, not made opaque — removed, because a
            // 64 pt blur is precisely the effect the setting exists to switch
            // off.
            if !reduceTransparency {
                field
            }
        }
        .ignoresSafeArea()
        // §3: "When `isLive == false`, the whole backdrop takes
        // `.saturation(0.15)`."
        .saturation(isLive ? 1.0 : 0.15)
        .animation(Motion.tone, value: visual.tone)
        .animation(Motion.tone, value: isLive)
        .animation(Motion.fieldGeometry, value: visual.geometry)
        .onAppear(perform: startBreathingIfNeeded)
        .onChange(of: visual.isBreathing) { _ in startBreathingIfNeeded() }
        // Decorative by construction: every fact this layer carries is also
        // carried by the glyph and the label above it (A11Y-1), so a screen
        // reader that announced the field would be reading the same state a
        // third time.
        .accessibilityHidden(true)
    }

    private var field: some View {
        GeometryReader { geometry in
            let width = geometry.size.width
            let scale = visual.geometry.lobeRadiusScale
            let tone = visual.tone.color(scheme, contrast)

            ZStack {
                // Primary lobe: centre (0.5w, 0.30h), radius 0.86w.
                lobe(tone: tone, peak: 0.55,
                     centre: UnitPoint(x: 0.5, y: 0.30),
                     radius: 0.86 * width * scale)
                // Secondary lobe: centre (0.18w, 0.86h), radius 0.62w.
                lobe(tone: tone, peak: 0.22,
                     centre: UnitPoint(x: 0.18, y: 0.86),
                     radius: 0.62 * width * scale)
            }
            // The lobes add to EACH OTHER inside this group…
            .compositingGroup()
            .blur(radius: Self.blurRadius)
            .saturation(1.18)
            .opacity(fieldOpacity)
            // …and the finished field adds to the ground.
            .blendMode(.plusLighter)
        }
    }

    private func lobe(tone: Color, peak: Double, centre: UnitPoint, radius: CGFloat) -> some View {
        // ponytail: the 64 pt blur has no material outside the frame, so the
        // secondary lobe fades slightly early against the bottom-left edge. At
        // 0.22 peak alpha on a soft gradient it is not visible; if it ever is,
        // draw the field into a frame inset by -64 and clip after the blur.
        RadialGradient(
            gradient: Gradient(colors: [tone.opacity(peak), tone.opacity(0.0)]),
            center: centre,
            startRadius: 0,
            endRadius: radius)
            .blendMode(.plusLighter)
    }

    /// §3's opacity rows, in precedence order.
    ///
    /// Stale wins over everything: a not-live snapshot is the one case where the
    /// product is saying "this may no longer be true", and letting a breathing
    /// loop brighten it back to 0.90 would animate away the very fact the
    /// desaturation exists to show.
    private var fieldOpacity: Double {
        guard isLive else { return 0.30 }
        guard visual.isBreathing else { return visual.geometry.fieldOpacity }
        // §7: Reduce Motion stops the loop at a static 0.72. The state is still
        // fully carried by the glyph and the label — A11Y-6 forbids motion being
        // the sole indication, and here it never is.
        guard !reduceMotion else { return Motion.breatheStatic }
        return isInhaled ? Motion.breatheHigh : Motion.breatheLow
    }

    private func startBreathingIfNeeded() {
        guard visual.isBreathing, !reduceMotion else {
            isInhaled = false
            return
        }
        withAnimation(Motion.breathe) { isInhaled = true }
    }
}

// MARK: - the glass (DESIGN.md §4)

/// One recipe, three sizes. Nothing else in the app uses a background.
///
/// ```
/// RoundedRectangle(cornerRadius: r, style: .continuous)
///   .fill(.ultraThinMaterial)                    // base
///   .overlay(glassTint)                          // 0.42 light / 0.06 dark
///   .overlay(glassStateTint)                     // state @ 0.05 / 0.06
///   .overlay(borderHighlight, lineWidth: 1)      // inner, top-weighted gradient
///   .overlay(innerShade,      lineWidth: 1)      // inner, bottom edge
///   .overlay(borderHairline,  lineWidth: 1)      // outer perimeter
/// ```
///
/// # The shape is a parameter, and that is the whole reason this is generic
///
/// §4.1 gives five radii and one of them is "full (circle)". A
/// `RoundedRectangle` with `cornerRadius: diameter / 2` is not a circle — the
/// `.continuous` curve is a squircle and reads visibly flat at the poles — so
/// the focal disc needs `Circle()` and the panels need `RoundedRectangle`. Both
/// are `InsettableShape`, which is what `strokeBorder` requires to inset a
/// stroke rather than centre it.
struct GlassSurface<S: InsettableShape>: View {
    let shape: S
    let tone: StateTone

    @Environment(\.colorScheme) private var scheme
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    var body: some View {
        ZStack {
            base
            // §8.1: both tints are REMOVED under Reduce Transparency, not
            // reduced. They are corrections for a translucent material's cast,
            // and over an opaque fill they are just a wash that costs contrast.
            if !reduceTransparency {
                shape.fill(DesignTokens.glassTint(scheme))
                shape.fill(DesignTokens.glassStateTint(tone, scheme, contrast))
            }
            // Inner strokes. `strokeBorder`, so the 1 pt sits wholly inside the
            // silhouette and the highlight reads as the glass's own edge.
            shape.strokeBorder(DesignTokens.borderHighlight(scheme), lineWidth: 1)
            shape.strokeBorder(DesignTokens.innerShade(scheme), lineWidth: 1)
            // §4: "Stroke order matters: the outer hairline is drawn last so the
            // highlight cannot bleed past the silhouette."
            shape.stroke(
                DesignTokens.borderHairline(scheme, reduceTransparency: reduceTransparency),
                lineWidth: 1)
        }
        // D3: "No shadows." There is exactly one shadow-shaped thing in this
        // system and it is the focal glow in `FocalDisc`, not here.
        .animation(Motion.tone, value: tone)
    }

    @ViewBuilder
    private var base: some View {
        if reduceTransparency {
            shape.fill(DesignTokens.opaqueMaterial(scheme))
        } else {
            shape.fill(.ultraThinMaterial)
        }
    }
}

extension View {
    /// The recipe, on an arbitrary shape.
    func glass<S: InsettableShape>(_ shape: S, tone: StateTone = .neutral) -> some View {
        background(GlassSurface(shape: shape, tone: tone))
    }

    /// §4.1's **panel**, radius 28: a diagnostic card or the pairing frame.
    /// Carries §6's 20 pt padding, because a panel without it is not a panel.
    func glassPanel(tone: StateTone = .neutral) -> some View {
        padding(Space.panelPadding)
            .glass(RoundedRectangle(cornerRadius: Radius.panel, style: .continuous), tone: tone)
    }

    /// §4.1's **card**, radius 20: a peer row or the redaction preview.
    func glassCard(tone: StateTone = .neutral) -> some View {
        padding(Space.l)
            .glass(RoundedRectangle(cornerRadius: Radius.card, style: .continuous), tone: tone)
    }

    /// §4.1's **chip**, radius 12.
    func glassChip(tone: StateTone = .neutral) -> some View {
        padding(.horizontal, Space.m)
            .padding(.vertical, Space.s)
            .glass(RoundedRectangle(cornerRadius: Radius.chip, style: .continuous), tone: tone)
    }

    /// §4.1's **badge**, a full capsule, with §6's 12 h / 6 v.
    func glassBadge(tone: StateTone = .neutral) -> some View {
        padding(.horizontal, Space.badgePaddingH)
            .padding(.vertical, Space.badgePaddingV)
            .glass(Capsule(style: .continuous), tone: tone)
    }

    /// §7's panel transition: "Panels rise on appear and do not fall on dismiss."
    ///
    /// The two curves are different — `.easeOut` 0.32 s in, `.easeIn` 0.20 s out
    /// — and `AnyTransition.animation(_:)` is what lets one `.animation(_:value:)`
    /// on the container drive both. Without it the container's curve would win in
    /// each direction and §7's asymmetry would exist only in the document.
    ///
    /// The flag is a parameter rather than an environment read because a
    /// transition is played by whichever `withAnimation` encloses the change, and
    /// an environment read inside the leaving view is not reliable once it is
    /// gone.
    func panelTransition(reduceMotion: Bool) -> some View {
        transition(
            .asymmetric(
                insertion: (reduceMotion ? AnyTransition.opacity : .panelRise)
                    .animation(Motion.panelAppear),
                removal: AnyTransition.opacity.animation(Motion.panelDismiss)))
    }
}

/// §7: "`.easeOut` + 8 pt rise + fade".
///
/// `.move(edge:)` is the obvious spelling and the wrong one — it translates by
/// the view's own height, which for a full-width diagnostic panel is a slide
/// from off-screen, not a rise. Eight points is eight points.
extension AnyTransition {
    static var panelRise: AnyTransition {
        .modifier(active: RiseAndFade(offset: Motion.panelRise),
                  identity: RiseAndFade(offset: 0))
    }
}

struct RiseAndFade: ViewModifier {
    let offset: CGFloat

    func body(content: Content) -> some View {
        content
            .offset(y: offset)
            .opacity(offset == 0 ? 1 : 0)
    }
}
