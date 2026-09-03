# TwinVPN iOS — Visual Design System

**Scope.** The visual layer of `shells/ios/Sources/TwinVPNApp`. This document
specifies colour, material, form, type, space and motion. It specifies no
behaviour: the state model (`VPNPermission`, `ManagementClient`, `PairingModel`),
the string ownership rule (CB-4 — the core resolves, the shell presents), and the
management contract are unchanged by everything below.

**Floor.** iOS 15.0 (ADR-0018 §11.9 row 1). Every API named here exists at 15.0.
Three that do not, and are therefore not used: `.glassEffect()` (26.0),
`NavigationStack` (16.0), and `.scrollContentBackground(.hidden)` (16.0) — the
last is why the connect screen is a `ScrollView`, not a `List`.

---

## 1. The four decisions that define the look

### D1 — The backdrop is the state indicator; the glass is neutral

Glass needs something behind it, and a security product needs its state readable
from across a room. Those are the same problem, so they get one answer: behind
the glass sits a single large field of soft light whose **colour and geometry are
the connection state**. The glass panels on top are achromatic and carry only
text and glyph.

Nothing else in the app is tinted. There is no accent colour on a button, no
coloured icon, no state dot. The room's light changes; the furniture does not.

### D2 — Three hues, and *in progress* has none

Colour is reserved for facts the product is prepared to assert. *Secure*,
*Held*, *Attention* — three hues, and that is the whole palette. Everything the
product does not yet know (`Connecting`, `Reconnecting`, `Unknown`, `Off`,
an unrenewed assertion) renders **achromatic**: the field is present, moving,
luminous, and grey.

This is a product-honesty rule expressed as a palette. O-18 already says an
unrenewed assertion rounds to `UNKNOWN`, never `PROTECTED`; a design that gave
*Connecting* a hopeful blue would be re-asserting in pixels what the state model
refuses to assert in data.

### D3 — No shadows. Separation is a light edge.

There is exactly one shadow-shaped thing in the system: a state-tinted glow under
the focal element, and it is a glow rather than a shadow specifically so that the
only "elevation" the design owns is also information. Every other panel separates
from its backdrop by a **1 pt hairline border plus a top-edge highlight** — the
way real glass separates from what is behind it, which is by catching light on
its edge, not by casting darkness below it.

### D4 — The focal element *is* the control

The connect screen has one large disc. It shows the state, and tapping it is the
action. There is no separate primary button competing for the eye, no bottom
action bar, no card grid. Everything else on the screen is either one line of
text or a diagnostic the contract requires in full.

---

## 2. Palette

Nine tokens. All values sRGB. Light/dark are separate values, never one value
with an opacity change.

### 2.1 Ground and glass

| Token | Light | Dark | Notes |
|---|---|---|---|
| `ground` | `#F2F0EC` | `#0B0E0F` | Warm off-white / near-black. **Not** `#FFFFFF` or `#000000`: pure extremes give the glass no light to refract and the material renders dead flat |
| `glassTint` | `#FFFFFF` @ 0.42 | `#FFFFFF` @ 0.06 | Painted *over* the material, under the border |
| `glassStateTint` | state @ 0.05 | state @ 0.06 | The only place a hue touches a panel |
| `borderHairline` | `#000000` @ 0.08 | `#FFFFFF` @ 0.10 | 1 pt, full perimeter |
| `borderHighlight` | `#FFFFFF` @ 0.65 → 0.00 | `#FFFFFF` @ 0.22 → 0.04 | 1 pt inner stroke, linear gradient top→bottom |
| `innerShade` | `#000000` @ 0.05 | `#000000` @ 0.18 | 1 pt inner stroke, bottom edge only |

### 2.2 Text

| Token | Light | Dark | Measured contrast on glass |
|---|---|---|---|
| `textPrimary` | `#14181A` | `#F4F6F6` | 17.4:1 / 15.6:1 |
| `textSecondary` | `#5A6366` | `#9AA3A6` | 5.79:1 / 6.68:1 |

### 2.3 State hues

| Tone | Light | Dark | Contrast on ground (light / dark) |
|---|---|---|---|
| `secure` | `#0F7A54` | `#34C98D` | 4.76:1 / 9.15:1 |
| `held` | `#8A5A08` | `#E8A33D` | 5.31:1 / 8.94:1 |
| `attention` | `#C0272E` | `#F2545B` | 5.32:1 / 5.69:1 |
| `neutral` | `#5A6366` | `#9AA3A6` | 5.79:1 / 6.68:1 |

All four clear 4.5:1 as text and 3:1 as a UI component in both schemes
(A11Y-5). The light and dark values of a tone are genuinely different colours,
not one colour dimmed — a green that is legible on `#0B0E0F` is 1.91:1 on
`#F2F0EC` and would fail outright.

### 2.4 State mapping

The mapping is a **pure function of state the app already publishes**. It reads
`VPNPermission.state`, `ManagementClient.isLive` and
`StatusSnapshot.protection`, in that order, and introduces no new read, no new
`@Published` property and no new management operation.

| Condition | Tone | Field geometry | Glyph |
|---|---|---|---|
| `protection.state == .protected` | `secure` | tight, bright, still | `checkmark.shield.fill` |
| `protection.state == .blocked` | `held` | tight, bright, still | `shield.slash.fill` |
| `protection.state == .unprotected` | `attention` | wide, dim, still | `exclamationmark.shield.fill` |
| `protection == nil`, or `!isLive`, or profile `.absent` | `neutral` | wide, dim, breathing | `questionmark.circle` |
| profile `.denied` / `.disabled` | `attention` | wide, dim, still | `exclamationmark.shield.fill` |

**Colour is never the carrier.** A11Y-1 requires state in at least two of
{glyph, text label, position} and legibility in greyscale. The carriers here are
the SF Symbol and the label from `Localizable.xcstrings` (`protection_protected`,
`protection_blocked`, `protection_unprotected`, `protection_unknown`). Hue is a
third, redundant channel — and the field's **geometry** (tight/bright vs
wide/dim) is a fourth that survives a greyscale render, which is what the P18
oracle-5 pairwise image diff actually tests.

**Vocabulary slots held open.** §11.3 projects twelve `ConnectionState`s onto
seven user-facing statuses. The iOS app does not receive them today — the MI
snapshot carries a `ProtectionAssertion` and peers, nothing more. When they
arrive: *Connected* / *Connected — reduced* → `secure`; *Traffic stopped —
protected* → `held`; *Stopped — needs you* → `attention`; *Off* / *Connecting* /
*Reconnecting* → `neutral`, with *Connecting* and *Reconnecting* taking the
breathing field. Adding them is a mapping-table edit, not a redesign.

---

## 3. Backdrop

One layer, drawn behind everything, ignoring safe areas.

```
ground fill
  └─ field: 2 radial gradients, tone-coloured, composited .plusLighter
       └─ .blur(radius: 64)
       └─ .saturation(1.18)
```

| Property | Value |
|---|---|
| Primary lobe | centre `(0.5w, 0.30h)`, radius `0.86w`, stops: tone @ 0.55 → tone @ 0.00 |
| Secondary lobe | centre `(0.18w, 0.86h)`, radius `0.62w`, stops: tone @ 0.22 → tone @ 0.00 |
| Blur radius | **64 pt** |
| Saturation | **1.18** |
| Field opacity — tight/bright | **0.92** |
| Field opacity — wide/dim | **0.48**, and both lobe radii ×1.35 |
| Grain overlay | none |

Blur radius and saturation are real numbers here because this field is drawn by
the app. The **glass** uses `.ultraThinMaterial`, whose radius and saturation are
Apple's and are not settable at any iOS version; the design pins the material and
specifies every layer stacked on it, rather than pretending to a number it cannot
set.

`.plusLighter` on `ground` `#0B0E0F` is what keeps the field luminous instead of
muddy — the two lobes add rather than occlude, so their overlap is the brightest
point on the screen and the disc sits in it.

**Stale is desaturated.** When `isLive == false`, the whole backdrop takes
`.saturation(0.15)` and the field drops to 0.30 opacity. Today the app renders a
not-live snapshot identically to a live one; this makes the distinction visible
without adding a badge, a banner, or a word.

---

## 4. Glass

One recipe, three sizes. Nothing else in the app uses a background.

```
RoundedRectangle(cornerRadius: r, style: .continuous)
  .fill(.ultraThinMaterial)                    // base
  .overlay(glassTint)                          // 0.42 light / 0.06 dark
  .overlay(glassStateTint)                     // state @ 0.05 / 0.06
  .overlay(borderHighlight, lineWidth: 1)      // inner, top-weighted gradient
  .overlay(innerShade,      lineWidth: 1)      // inner, bottom edge
  .overlay(borderHairline,  lineWidth: 1)      // outer perimeter
```

Stroke order matters: the outer hairline is drawn last so the highlight cannot
bleed past the silhouette.

### 4.1 Radii

| Element | Radius |
|---|---|
| Focal disc | full (circle) |
| Panel (diagnostic card, pairing frame) | **28** |
| Card (peer row, redaction preview) | **20** |
| Chip / inline pill | **12** |
| Badge | full (capsule) |

All `.continuous`. No `.circular` corners anywhere.

### 4.2 Elevation

There is one, and it belongs to the focal disc:

```
.shadow(color: tone.opacity(0.28), radius: 40, x: 0, y: 0)
```

Radius 40, **zero offset** — a glow, not a shadow. Under Reduce Transparency or
Increase Contrast it is removed entirely (the disc is opaque there and a glow
around an opaque disc reads as smear).

Every other surface: **no shadow**. Not a subtle one, not a 2 pt one.

---

## 5. Type

System font (SF Pro). Three weights only: Regular 400, Medium 500, Semibold 600.
Nothing is Bold.

Sizes are base values at the default content size and are declared through
`@ScaledMetric(relativeTo:)`, because `Font.system(size:)` does **not** track
Dynamic Type and A11Y-4 requires the full range including accessibility sizes
with no diagnostic text clipped at 200 %.

| Role | Size | Weight | Tracking | `relativeTo` |
|---|---|---|---|---|
| Status hero | 40 | Medium | −0.6 | `.largeTitle` |
| Section title | 20 | Semibold | −0.2 | `.title3` |
| Diagnostic part 1 | 17 | Semibold | 0 | `.headline` |
| Body / diagnostic part 2 | 17 | Regular | 0 | `.body` |
| Qualifier / part 3 | 15 | Regular | 0 | `.subheadline` |
| Meta / badge | 13 | Medium | +0.3 | `.footnote` |
| Monospaced (fingerprint, peer id) | 15 | Regular | +0.5 | `.subheadline` |

The monospaced role keeps `design: .monospaced` and its +0.5 tracking because
A11Y-9 exists: a 20-character fingerprint is compared by eye, character by
character, and tight tracking is what makes `8`/`B` and `0`/`O` a coin flip.

**Line limits.** Diagnostic parts 1, 2 and 3 have **no line limit and no
`.minimumScaleFactor`**, at every width and every type size. R-33 makes a
truncated part 2 a violation, so the layout yields instead: the disc shrinks, the
peer list drops, the diagnostic never does (A11Y-4's stated drop order).

---

## 6. Space

4 pt base. The scale is `4, 8, 12, 16, 24, 32, 48, 64` and nothing between.

| Use | Value |
|---|---|
| Screen horizontal margin | **24** |
| Focal disc diameter | **216** (min 152 under compression) |
| Disc → status hero | **32** |
| Status hero → qualifier line | **8** |
| Focal cluster → first panel | **48** |
| Between panels | **16** |
| Panel padding | **20** |
| Stack gap inside a panel | **12** |
| Badge padding | 12 h / 6 v |
| Minimum tap target | **44 × 44** (A11Y-8) |

Generous means the focal cluster owns the top ~55 % of a 390 × 844 screen with
nothing else in it. If that space is empty because there is no diagnostic, it
stays empty.

---

## 7. Motion

| Transition | Curve | Duration |
|---|---|---|
| Tone change (field colour + glyph) | `.easeInOut` | **0.42 s** |
| Field geometry change (tight ↔ wide) | `.spring(response: 0.55, dampingFraction: 0.86)` | — |
| Disc press down / release | `.spring(response: 0.28, dampingFraction: 0.70)`, scale **0.965** | — |
| Panel appear | `.easeOut` + 8 pt rise + fade | **0.32 s** |
| Panel dismiss | `.easeIn` + fade only | **0.20 s** |
| Breathing field (neutral tone) | `.easeInOut`, `.repeatForever(autoreverses: true)`, opacity 0.55 ↔ 0.90 | **2.6 s** per half |

Rules:

- **Blur radius is never animated.** It is a full-screen recomposite per frame.
- Panels rise on appear and do not fall on dismiss. Asymmetry is deliberate:
  arriving information deserves a gesture, departing information does not.
- **Reduce Motion** (`@Environment(\.accessibilityReduceMotion)`): the breathing
  loop stops at a static 0.72, the disc press becomes an opacity change, panel
  rise becomes a plain fade. Nothing else changes, and nothing is *only*
  animated — A11Y-6 forbids a spinner as the sole indication of progress, and
  here the glyph and the label carry it in every case.

---

## 8. Accessibility variants

These are first-class renderings, not degradations. Translucency and low-opacity
borders fight contrast by construction, so each has a specified opaque form.

### 8.1 Reduce Transparency

SwiftUI `Material` already falls back to opaque, but the layers stacked on it do
not. Explicitly:

| Layer | Replacement |
|---|---|
| `.ultraThinMaterial` | solid `#FFFFFF` (light) / `#171B1D` (dark) |
| `glassTint`, `glassStateTint` | removed |
| Backdrop field | removed; flat `ground` |
| Focal glow | removed |
| `borderHairline` | opacity → **0.18** light / **0.28** dark |

### 8.2 Increase Contrast

Applies on top of §8.1. State tones swap to a high-contrast pair, and the disc
gains a 2 pt tone-coloured ring — so the state is carried by a **shape** the
moment colour is unreliable.

| Tone | Light HC | Dark HC |
|---|---|---|
| `secure` | `#0A5B3E` | `#5BE3AB` |
| `held` | `#6B4506` | `#F5BE6A` |
| `attention` | `#96161C` | `#FF8288` |
| `neutral` | `#41494C` | `#C2C9CB` |

### 8.3 Announcement

A11Y-2's live region is a behaviour, not a visual, and the existing
`.accessibilityElement(children: .combine)` on the indicator stays exactly as it
is. The design adds one obligation it must not break: the disc, the status hero
and the qualifier are **one** accessibility element reading in that order, and
the diagnostic's three parts are a second one (A11Y-3), with part 3 as the
action's label.

---

## 9. What this system does not have

Listed so the propagation step in §4 of the plan has something to check itself
against:

- No gradient with two brand hues. The field is one tone at varying alpha.
- No uniform card grid. Panels are full-width and stack; there is no two-column
  anything at compact width.
- No shadow except the one glow in §4.2.
- No accent colour on a control.
- No icon that is not an SF Symbol, and no SF Symbol that is not one of the four
  in §2.4 plus the three tab glyphs.
- No custom font, no custom easing curve beyond the six in §7, no third weight
  beyond the three in §5.
- No decorative divider. Panels are separated by 16 pt of nothing.

---

## 10. The connect screen's control — resolved

This section was an open item. It read: `VPNPermission.install(enforcement:)`
and `startTunnel()` have no caller outside the test suites, D4 makes the focal
disc a control, the brief was the visual layer only, so the default was "styled
as a control, nothing wired" and the wiring was "a functionality decision that
is yours, not this document's".

**That decision has been made: the disc connects.** `StatusView.connectAction`
passes `VPNPermission.connect()`, which installs the profile if there is none
and then starts the tunnel. `FocalDisc.action` stays optional, because §10's
`.disabled` affordance is exactly what two states still need.

| Profile state | Disc | Why |
|---|---|---|
| `.absent` | enabled → install, then start | the ordinary first run |
| `.installed` | enabled → start | |
| `.denied`, `.disabled` | **disabled** | ADR-0012 §11.10: "on iOS/iPadOS the **only** unblock mechanism is removing the VPN profile in Settings — this is not 'ours', not a command." The diagnostic panel carries LT-3's `App-prefs:General&path=VPN` next action instead |

Two things it deliberately does not do.

**It does not disconnect.** `VPNPermission.configure` sets
`isOnDemandEnabled = true` and the programme Rust renders carries
`disconnect_on_demand_enabled: false`, so `stopVPNTunnel()` is not a disconnect —
the on-demand rules bring the tunnel straight back. Making it stick would mean
the shell writing `isOnDemandEnabled = false`, which is the enforcement posture
`twinvpn_platform_ios::enforce` owns (KS-4). A disconnect affordance is a
core-side posture change first and a button second.

**It cannot complete a first install on this build**, and the wall is not in the
visual layer. `install(enforcement:)` needs an `EnforcementProgramme`, and no
route to one is open from the app process: `core-lite` "performs NO command"
(`Core::submit_response` refuses under `#[cfg(not(feature = "full"))]` with
`PLATFORM.ADAPTER_UNAVAILABLE`); the extension's channel works "only while the
session is connected", which is circular; and a Swift-side copy is what
`Sources/TwinVPNShared/EnforcementProgramme.swift`'s header forbids. So
`CoreLite.makeEnforcementProgramme()` refuses with the code `core-lite` itself
would return, the disc installs nothing, and the user sees that code rendered as
a diagnostic. Closing it is one FFI export of the rendered default posture,
alongside `tw_render_diagnostic`; every caller above it is already written.
