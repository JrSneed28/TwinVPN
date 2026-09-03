//  DesignType.swift — the seven type roles (DESIGN.md §5), and the one view that
//  renders them.
//
//  Authority: `shells/ios/DESIGN.md` §5, §2.2; ADR-0018 §11.9 row 1 (the iOS
//  15.0 floor); ADR-0019 A11Y-4, A11Y-9, R-33.
//
//  STATUS: written, not compiled.
//
//  ===========================================================================
//  WHY THIS IS A VIEW AND NOT A `.font()` MODIFIER
//  ===========================================================================
//
//  §5: "Sizes are base values at the default content size and are declared
//  through `@ScaledMetric(relativeTo:)`, because `Font.system(size:)` does
//  **not** track Dynamic Type and A11Y-4 requires the full range including
//  accessibility sizes with no diagnostic text clipped at 200 %."
//
//  `Font.system(size:)` takes a fixed point size; unlike `Font.custom(_:size:)`
//  — documented as scaling "with the body text style" — it has no documented
//  Dynamic Type scaling and no `relativeTo:` variant in any SDK, so
//  `@ScaledMetric` is what supplies the scaling.
//
//  `@ScaledMetric` is a property wrapper, so it needs a `View` to live in — a
//  free function returning a `Font` has nowhere to put one, and would silently
//  hand back a fixed size. Every piece of text in this app therefore goes
//  through `StyledText`, which owns the wrapper.
//
//  ===========================================================================
//  TRACKING, AND THE OVERLOAD TRAP THAT MAKES IT LOOK UNAVAILABLE
//  ===========================================================================
//
//  `Text.tracking(_:)` is **iOS 13.0+**, so every role's tracking below applies
//  at this product's floor. `mono` gets its specified +0.5 on every supported
//  OS, and A11Y-9 — "a 20-character fingerprint is compared by eye, character by
//  character, and tight tracking is what makes `8`/`B` and `0`/`O` a coin flip"
//  — is satisfied by the tracking AND by `design: .monospaced`, which reinforce
//  each other rather than one standing in for the other.
//
//  This file previously carried the opposite claim, behind an
//  `if #available(iOS 16.0, *)`, and the mistake is worth recording because the
//  trap that produces it is not obvious. **Apple's un-hashed documentation URL
//  for an overload set shows only the NEWEST overload.** Three APIs this design
//  system uses read as too new on their plain URL and are not:
//
//    | Plain URL reads | The overload that exists at the floor |
//    |---|---|
//    | `Font.system(size:weight:design:)` — iOS 16.0 | `…-73a88` — **iOS 13.0** |
//    | `InsettableShape.strokeBorder(_:lineWidth:antialiased:)` — iOS 17.0 | `…-6rs04` — **iOS 13.0** |
//    | `Shape.fill(_:style:)` — iOS 17.0 | `…-5fwbj` — **iOS 13.0** |
//
//  In each case Apple later added a variant — optional `Font.Weight?`, a
//  `ShapeView` return — that took over the canonical URL. Source compatibility
//  is unaffected. Check the hashed variant before concluding anything is too
//  new for 15.0.
//
//  Two semantics that bind this file's shape:
//
//    * **Never set both `tracking` and `kerning`.** Apple, on both pages: "If
//      you add both the `tracking(_:)` and `kerning(_:)` modifiers to a view,
//      the view applies the tracking and ignores the kerning." `TypeRole`
//      carries `tracking` only, and that is why.
//    * **Tracking, not kerning, for the negative values.** Negative kerning
//      crops the last character — it "affects the trailing edge of the text view
//      as well" — whereas tracking adjusts trailing whitespace instead. The
//      stated cost is that any non-zero tracking disables non-essential
//      ligatures, which at ±0.2–0.6 pt on a UI scale is not a concern.

import SwiftUI

// MARK: - the roles (DESIGN.md §5)

/// One row of §5's table.
///
/// Three weights only — Regular 400, Medium 500, Semibold 600. **Nothing is
/// Bold**, and there is no role here that could make it so.
struct TypeRole {
    let size: CGFloat
    let weight: Font.Weight
    let tracking: CGFloat
    /// What `@ScaledMetric` scales against, so that a role tracks the Dynamic
    /// Type ramp of the system style it is standing in for.
    let textStyle: Font.TextStyle
    let design: Font.Design
    /// §2.2 has exactly two text tokens. This picks between them.
    let isSecondary: Bool

    private init(_ size: CGFloat,
                 _ weight: Font.Weight,
                 tracking: CGFloat,
                 relativeTo textStyle: Font.TextStyle,
                 design: Font.Design = .default,
                 isSecondary: Bool = false) {
        self.size = size
        self.weight = weight
        self.tracking = tracking
        self.textStyle = textStyle
        self.design = design
        self.isSecondary = isSecondary
    }

    /// The status hero — the one large line under the focal disc.
    static let statusHero = TypeRole(40, .medium, tracking: -0.6, relativeTo: .largeTitle)

    /// A section title, and the label of a full-width control.
    static let sectionTitle = TypeRole(20, .semibold, tracking: -0.2, relativeTo: .title3)

    /// Diagnostic part 1 — what happened.
    static let diagnosticPart1 = TypeRole(17, .semibold, tracking: 0, relativeTo: .headline)

    /// Body, and diagnostic part 2 — why.
    static let body = TypeRole(17, .regular, tracking: 0, relativeTo: .body)

    /// The hero's qualifier line, and diagnostic part 3 — what to do.
    ///
    /// `textPrimary`, not `textSecondary`, even though it is the smallest role
    /// in the diagnostic. Part 3 is the instruction and, where the core supplied
    /// a deep link, the action's label (§8.3); grey text that carries a tap is
    /// the exact appearance of a disabled control, which LT-3's "otherwise
    /// instructions only" already says this must never be.
    static let qualifier = TypeRole(15, .regular, tracking: 0, relativeTo: .subheadline)

    /// Meta, and the badge.
    static let meta = TypeRole(
        13, .medium, tracking: 0.3, relativeTo: .footnote, isSecondary: true)

    /// The fingerprint, the peer id, and the redaction preview.
    ///
    /// A11Y-9: these are compared by eye, character by character.
    static let mono = TypeRole(
        15, .regular, tracking: 0.5, relativeTo: .subheadline, design: .monospaced)
}

// MARK: - the renderer

/// Every string this app draws.
///
/// # Line limits
///
/// §5: diagnostic parts 1, 2 and 3 have "**no line limit and no
/// `.minimumScaleFactor`**, at every width and every type size. R-33 makes a
/// truncated part 2 a violation, so the layout yields instead."
///
/// SwiftUI's default is already no limit and no scale factor, so the guarantee
/// is kept by this view never setting either. A caller that needs one — the peer
/// id, which is a token and not a sentence — applies it at the call site, where
/// it is visible.
struct StyledText: View {
    private let content: String
    private let role: TypeRole

    /// `@ScaledMetric` tracks Dynamic Type through the full accessibility range,
    /// which `Font.system(size:)` alone does not (A11Y-4).
    @ScaledMetric private var size: CGFloat

    @Environment(\.colorScheme) private var scheme

    init(_ content: String, _ role: TypeRole) {
        self.content = content
        self.role = role
        _size = ScaledMetric(wrappedValue: role.size, relativeTo: role.textStyle)
    }

    var body: some View {
        tracked
            .foregroundColor(
                role.isSecondary
                    ? DesignTokens.textSecondary(scheme)
                    : DesignTokens.textPrimary(scheme))
    }

    /// `tracking(0)` is a no-op, so the roles that specify none need no branch
    /// and this file contains no `#available` at all.
    private var tracked: Text {
        Text(content)
            .font(.system(size: size, weight: role.weight, design: role.design))
            .tracking(role.tracking)
    }
}
