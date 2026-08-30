# ADR-0019: Application State Model, UI Architecture, and User-Facing Flows

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** APPLICATION
- **Related:** [ADR-0003](ADR-0003-network-contract-schema-format.md),
  [ADR-0007](ADR-0007-device-identity-and-pairing.md),
  [ADR-0008](ADR-0008-idempotency.md),
  [ADR-0009](ADR-0009-state-consistency.md),
  [ADR-0010](ADR-0010-ipv4-ipv6-routing.md),
  [ADR-0011](ADR-0011-dns-handling.md),
  [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md),
  [ADR-0013](ADR-0013-multi-client-gateway-architecture.md),
  [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md),
  [ADR-0015](ADR-0015-observability-and-diagnostics.md),
  [docs/architecture.md](../architecture.md), [docs/networking.md](../networking.md),
  [docs/protocol.md](../protocol.md), [docs/reliability.md](../reliability.md),
  [docs/testing-strategy.md](../testing-strategy.md), [docs/threat-model.md](../threat-model.md),
  [docs/vision.md](../vision.md)
  — and, in the Phase 1 application workstream,
  [ADR-0016](ADR-0016-client-process-and-privilege-separation.md),
  [ADR-0017](ADR-0017-local-management-interface.md),
  [ADR-0018](ADR-0018-shared-core-and-build-architecture.md),
  [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md),
  [ADR-0021](ADR-0021-packaging-distribution-and-updates.md),
  [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md),
  [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)

This ADR owns the **application layer above the daemon**: the UI-facing application state model
and its replica discipline, the projection of the twelve `ConnectionState`s onto a smaller
user-facing status vocabulary, the **presentation contract** for `reason_code`s, the localization
and text architecture, the per-platform UI framework realization, the user-facing flows and their
refusal branches, the UI half of the anti-silence obligation, the accessibility conformance
target, and the rule that keeps the GUI and the headless profile at parity. It is the document
that makes the *second half* of invariant **I6** real: the corpus specifies the machine-readable
half of "every failure has a name" thoroughly and the human half not at all, and a product that
emits a perfect `reason_code` and renders it as "Connection failed" has violated I6 at the last
inch.

It does **not** own: the `ConnectionState` machine ([docs/reliability.md](../reliability.md) §4),
the `reason_code` taxonomy, registry, or stability rules
([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2), **any reason code** — every code
named here is owned and registered elsewhere and is quoted, never minted — the kill-switch policy
or the local-authority disarm rule ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)
§11.10), the pairing ceremony ([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4), the
privilege split ([ADR-0016](ADR-0016-client-process-and-privilege-separation.md)), the management wire contract ([ADR-0017](ADR-0017-local-management-interface.md)), the shared core and its ABI
([ADR-0018](ADR-0018-shared-core-and-build-architecture.md)), persistence ([ADR-0020](ADR-0020-local-persistence-and-secure-storage.md)), packaging and store distribution ([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)), background
execution ([ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md)), or the headless profile ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)). Where those are needed, the required
interface is stated in §11.14 and nothing about their internals is invented.

---

## 1. Context

[docs/vision.md](../vision.md) makes three claims that land, in the end, on a screen. Claim 3 —
"failure is a first-class product surface" — is discharged in the corpus by
[ADR-0015](ADR-0015-observability-and-diagnostics.md)'s taxonomy, by
[docs/reliability.md](../reliability.md) §10's state-machine-boundary rule, and by the thirteen
domains' worth of registered codes. All of that is the machine-readable half. **R-22** requires a
"human-actionable explanation and a suggested next action"; **R-23** requires a connectivity
report a user can produce and read; **I6** names both halves in one sentence. Nothing in the
corpus says what the user actually sees.

That gap is not cosmetic. Four concrete failure modes live in it:

| Failure mode | Why the existing corpus does not prevent it |
|---|---|
| A perfect `reason_code` rendered as "Connection failed" | The registry carries `summary_key` and `next_action_key`; nothing specifies what a surface does with them, or what it does when it holds neither |
| A `reason_code` the shipped UI has never seen | [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 rule 5 requires degradation by `DOMAIN` prefix and forbids showing the raw code as the primary signal. It does not say what *is* shown |
| A stale green "Connected" after the daemon died | [ADR-0015](ADR-0015-observability-and-diagnostics.md) O-18 makes the *assertion* expire. Nothing makes the *pixel* expire |
| Six independently written UIs drifting into six different vocabularies | Nothing binds them to one projection or one text source |

The second problem this ADR solves is **I8 at the presentation layer**. The UI is the most
tempting place in the product to create a second writer: a settings screen that writes locally
and "syncs later", a status view that infers state while the daemon is unreachable, a tray icon
that remembers what it last drew. [docs/architecture.md](../architecture.md) §5 assigns exactly
one authoritative writer to every persistent fact; a UI that holds anything but a declared
replica breaks that table without appearing in it.

The third is **audience**. [docs/vision.md](../vision.md) §2's personas span an individual with
three devices, a traveller depending on fail-closed egress, a home-lab operator on Linux and
routers, and a small trusted group. The same product ships as an iPhone app, an iPad app, a
Mac menu-bar item, a Windows tray application, a GTK window, and no GUI at all on a 128 MB
router — and **R-21** requires the headless surface to have the same control contract as the GUI.
Six user interfaces plus a CLI is the honest cost, and the architecture has to make that cost
survivable rather than pretend it away.

---

## 2. Requirements

### 2.1 Existing requirements this ADR discharges or contributes to

| Requirement | This ADR's contribution |
|---|---|
| **R-22** (cryptic error codes) | The presentation contract §11.4, the catalogue §11.5, the localization architecture §11.6. This ADR is the consumer side of `summary_key` / `next_action_key` |
| **R-23** (insufficient diagnostics) | The connectivity-report surface and the redaction preview, §11.10(g) |
| **R-24** (revoked device keeps working) | The revocation flow §11.10(d), including the mandatory disclosure of the partition-bounded residual window |
| **R-21** (no Linux / router support) | The headless-parity rule §11.12, which converts "same control contract as the GUI" from aspiration into a build gate |
| **R-08** (unreliable mobile background) | The UI half: unconditional staleness on resume, §11.9(4) |
| **R-13**, **R-14** | Kill-switch posture display and the per-family leak indication, §11.10(f) |
| **I3**, **I6**, **I8** | Enforcement mechanisms named in §11.2, §11.4, §11.9, §11.15 |

### 2.2 New requirements proposed for [docs/vision.md](../vision.md) §5

| ID | Historical defect | TwinVPN requirement | Mechanism | Specified in |
|---|---|---|---|---|
| **R-33** | Failure text reaching the user as a generic string, a raw code, or an OS errno | Every `Diagnostic` presented to a user MUST render **three parts** — what happened, what it means for that user's traffic at that moment, and a suggested next action selected for the platform — **including** for a `reason_code` the surface does not recognize, where part 1 degrades to the `DOMAIN` prefix and parts 2 and 3 are still produced. A raw code, a bare number, an OS errno, an i18n key, or an empty next action as the **primary** user-facing signal is a defect. | Presentation contract (three-part rendering, disposition-derived consequence sentence, `DOMAIN` fallback table); a single presentation resolver in the shared core used by every surface including the CLI | ADR-0019 §11.4–§11.6; proof test **P18** |
| **R-34** | A VPN client displaying "Connected" after the tunnel, the daemon, or the process behind it had died | No surface may render a **positive** connection or protection state from a replica older than its declared staleness tolerance. Past `T_VM_STALE` the surface MUST render the last-known value explicitly marked stale; past `T_VM_UNKNOWN` it MUST render `UNKNOWN`. On resume from background or a management-stream gap, every cached value is stale **unconditionally**, without wall-clock arithmetic. | `Fresh<T>` render gate with no constructor from a stale value; `vm_seq` gap detection forcing a full resnapshot; the protection indicator as a pure function of the most recent `ProtectionAssertion` | ADR-0019 §11.2, §11.9; **S-48** |
| **R-35** | Connection state conveyed by a coloured dot; a security product unusable with a screen reader or a keyboard | Every graphical surface MUST meet **WCAG 2.2 Level AA** and its platform accessibility API contract. The connection and protection indicators MUST NOT convey state by colour alone. Asynchronous state changes MUST be announced to assistive technology with severity-appropriate politeness. Every action MUST be keyboard-operable. | A11Y-1…A11Y-10; greyscale pairwise-distinguishability and live-region assertions as release gates | ADR-0019 §11.11; proof test **P18** oracle 5 |
| **R-36** | A GUI that could do things the CLI could not, making headless deployments second-class | No UI capability may exist that the local management contract does not expose. Every UI action MUST be an operation of that contract; the GUI MUST have **no privileged side channel**. Text rendered by the GUI and by the CLI for the same `Diagnostic` in the same locale MUST be identical. | Single management-client dependency with a link-time symbol assertion; a generated operation × surface parity matrix as a build gate; one in-core presentation resolver | ADR-0019 §11.12; [ADR-0017](ADR-0017-local-management-interface.md); [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) |

---

## 3. Constraints

| # | Constraint | Source |
|---|---|---|
| C-1 | The UI process is **unprivileged** and its death MUST NOT affect enforcement; the kill-switch rule set outlives it | **H2** / [ADR-0016](ADR-0016-client-process-and-privilege-separation.md); S-18; [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6 |
| C-2 | There is exactly **one** local management contract, and the GUI has no side channel | **H3** / [ADR-0017](ADR-0017-local-management-interface.md); R-21 |
| C-3 | Business logic lives in **one portable core** behind a stable C ABI; no logic is reimplemented per platform | **H1** / [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) |
| C-4 | The `ConnectionState` machine has twelve states and one authority | [docs/reliability.md](../reliability.md) §4 |
| C-5 | `reason_code` is a **string** on the wire, ≤ 3 segments, append-only, and the **code is the contract; the text is not** | [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 rules 1–7 |
| C-6 | Diagnostics are **local-first** and must render with no network at all | [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.1 Tier 0, O-07 |
| C-7 | The iOS/iPadOS NetworkExtension provider is a **memory-constrained app extension**; contract fetch/parse and diagnostics already belong to the app process | [docs/networking.md](../networking.md) §5.4 |
| C-8 | No key export, escrow, or backup affordance may exist anywhere in the UI | **I4**, **P4** |
| C-9 | Disarming enforcement requires a local interactive action **plus** OS-mediated authentication; the UI is a requester, never the authority | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-21 |
| C-10 | Accepting a route is an **authorization decision**, and absent grants are denials | [docs/threat-model.md](../threat-model.md) §7, TM-A3 |
| C-11 | `DEGRADED` and `BLOCKED` MUST be visually distinct from connected in **every** surface | [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.6; [docs/reliability.md](../reliability.md) §7.6 |
| C-12 | Router-class targets have **no GUI**, ≤ 128 MB RAM, musl/uclibc, read-only rootfs | Brief §10; [docs/networking.md](../networking.md) §5.2 |
| C-13 | Store review (App Store, Play) governs iOS/iPadOS and Android distribution and constrains what the first-run flow may do | [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) |
| C-14 | `SECRET` fields have **no rendering code path**, in any build, at any log level | [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.4 |

---

## 4. Considered Alternatives

Five genuine options for the UI architecture. Each is evaluated against the H1 core boundary, the
iOS/iPadOS extension constraints, binary size, accessibility quality, platform-idiom expectations
for a **security** product, and the honest cost of six user interfaces.

- **Alternative A — Fully native per platform, no shared view-model.** SwiftUI (iOS/iPadOS/macOS),
  Jetpack Compose (Android), WinUI 3 (Windows), GTK4/libadwaita (Linux). Each shell talks to the
  daemon over [ADR-0017](ADR-0017-local-management-interface.md) and derives its own view-model and its own text from the raw
  `Diagnostic` stream.

- **Alternative B — One cross-platform UI toolkit.** A single UI codebase in Flutter, Qt, Avalonia,
  or Compose Multiplatform, rendering its own widgets on all six targets, embedding the core.

- **Alternative C — Web shell.** One HTML/CSS/JS application hosted in Tauri (system webview) or
  Electron (bundled Chromium) on desktop, and in a WKWebView/WebView on mobile.

- **Alternative D — Hybrid: a shared core view-model and presentation resolver driving thin
  native views.** The H1 core owns the projection from the twelve `ConnectionState`s to the
  user-facing vocabulary, owns the `Diagnostic` → three-part rendering, and owns the text
  catalogue lookup. Each platform ships a thin native view layer that consumes an immutable
  view-model snapshot plus a patch stream, and submits intents. Every string a user sees is
  produced by the core, in the requested locale, for the requesting platform.

- **Alternative E — Headless-first with minimal chrome.** No rich application. A status item /
  notification, the OS's own VPN settings integration, and a first-class CLI plus a local status
  page for everything else.

---

## 5. Advantages of Each Alternative

| # | Advantages |
|---|---|
| **A** | Best possible platform idiom and accessibility, because each surface uses the toolkit its assistive technology was built for. Smallest per-platform binary. No cross-platform runtime to audit or to break at an OS upgrade. iOS app-extension constraints are trivially satisfied because nothing extra is linked. Store review sees an ordinary native app |
| **B** | One UI codebase; a feature ships to six targets at once. Consistent behaviour by construction. Faster iteration on flows that are genuinely identical (device list, diagnostics viewer). One design system to maintain |
| **C** | The fastest layout iteration of any option, the largest hiring pool, and a rendering model that is already responsive and reflowable. The connectivity report — a long structured document — is the single surface a web renderer is genuinely best at |
| **D** | The projection, the vocabulary, and every user-visible string exist **once**, so six surfaces cannot drift; that is also what makes GUI/CLI text parity (R-36) mechanical rather than aspirational. Native views keep A's platform idiom and accessibility quality. The core is already required by H1, so the marginal cost is one FFI surface, not a new runtime. A new `reason_code` shipped in a core update reaches every surface without touching six view layers |
| **E** | Minimal attack surface and minimal binary. Nothing to keep in parity because there is almost nothing to keep. Ideal for the router and headless tiers, which are already GUI-less |

---

## 6. Disadvantages of Each Alternative

| # | Disadvantages |
|---|---|
| **A** | Six independent implementations of the state projection and six independent text tables — precisely the drift this ADR exists to prevent, and the mechanism by which "Connection failed" gets written six times. R-36 text parity becomes unenforceable. Six teams must each get `DEGRADED`-is-not-connected right |
| **B** | The toolkit becomes a hard dependency of a security product's entire user surface. Accessibility is the toolkit's, not the platform's, and on Windows and Linux that is materially worse. Binary size grows by 10–40 MB per target. On iOS the toolkit must be linked into the app; the extension constraint (C-7) is survivable but the app-review surface grows. Platform idiom is approximated, and for a security product a UI that feels foreign reduces trust in ways that are real but unmeasurable |
| **C** | Worst option for this product. A bundled-Chromium shell is 100 MB+ and a continuous CVE-tracking obligation on the update channel ([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)). A system-webview shell inherits six different webview versions. Content-security discipline becomes a security-critical property of a VPN client's UI. Screen-reader quality on Windows and Linux webviews is inconsistent. And on iOS/iPadOS/Android a webview app for a VPN invites review friction for no benefit |
| **D** | An FFI surface to design, version, and keep memory-safe across a C ABI — including string ownership for every rendered part. Locale and platform become **inputs to the core**, which is an unusual coupling and must be justified (it is: it is the only way one resolver can serve six platform-specific next actions). Six view layers still exist, so layout work is still six-fold. A core panic must not take the UI down |
| **E** | Fails the product. [docs/vision.md](../vision.md) §2's first two personas are not CLI users, the pairing ceremony of [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4 needs a camera and a screen, and R-23's connectivity report needs somewhere to be read. It also fails R-22 by having nowhere to put human-actionable text |

---

## 7. Security Implications

| # | Implication | Mitigation |
|---|---|---|
| S-1 | The UI runs unprivileged and must never become an enforcement authority. A design where the UI holds the kill switch alive is an **I3** violation | C-1/C-9: enforcement is OS-level and outlives the UI (S-18). The UI submits *intents* over [ADR-0017](ADR-0017-local-management-interface.md); disarm additionally requires OS-mediated authentication ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-21). §11.10(f) |
| S-2 | Route acceptance is an authorization decision made in the UI, so consent fatigue and consent phishing are security failures, not UX failures | RC-1…RC-5 in §11.10(e): named advertiser with fingerprint, prefix in plain language, default routes given higher friction, never actionable from a notification or lock screen, and a standing auditable grant list |
| S-3 | The pairing QR encodes `pairing_secret`, which is **optical-confidential** ([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4). A screenshot, a screen recording, a shoulder, or a screen-sharing session defeats it | §11.10(b): screenshot suppression where the platform provides it (`FLAG_SECURE` on Android, `isSecureTextEntry`-class protection is *not* available for arbitrary views on iOS — the residual is stated), a 120 s visible countdown, no persistence of the offer, and no clipboard path for the secret |
| S-4 | The recovery phrase is the trust root ([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.5); its compromise is total and unrecoverable | §11.10(b): no clipboard by default, no screenshot where suppressible, excluded from platform backup and from any keyboard/autofill cache, the N-12 three-word verification is not skippable, and backgrounding mid-ceremony abandons and regenerates |
| S-5 | The diagnostics share path can exfiltrate `SENSITIVE` fields | §11.10(g) DX-1: the preview renders through the **same** redaction path the export uses, and the share affordance is unreachable without passing through it. `SECRET` has no path at all (C-14) |
| S-6 | A UI deep link or URL handler that performs an action is a remote-actor path into a local-authority decision | UI-3 in §11.2: a link, notification action, or automation entry point MAY navigate to a surface and MUST NOT complete a pairing, a route acceptance, a revocation, or a disarm |
| S-7 | Notification and lock-screen content leaks peer labels and network facts | §11.9: notification bodies carry the projected status and the diagnostic summary only; peer labels are shown on the lock screen only if the platform's sensitive-content setting permits, and evidence fields are never in a notification |
| S-8 | A settings-sync convenience would create a second writer for a policy fact — an **I8** break with security consequences, because policy and route consent are authorization inputs | S-50 and S-51 are `LOCAL` with **no** remote replica; S-51 is explicitly non-syncable, and no preference may suppress a `POLICY`-class or `CRITICAL` diagnostic |
| S-9 | Rendering an unknown code as raw text invites a spoofed or attacker-influenced string into the UI | The code is never the primary signal (PC-2); the secondary technical line renders the code with a fixed character allowlist matching [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2's grammar, and anything else renders as malformed |

---

## 8. Reliability Implications

- **The UI is a replica, always.** S-48 declares the tolerance and the reconciliation rule. A UI
  that cannot reach the daemon reports exactly that, and reports the protection indicator as
  `UNKNOWN` — not as unprotected, because S-18 outlives the UI, and not as protected, because
  it cannot know.
- **UI death is not a product event.** Killing the UI process changes nothing about `Session`s,
  enforcement, or the state machine. The UI's own restart re-enters through a snapshot, never
  through a persisted view-model (S-48 durability column).
- **A path change is not a disconnect.** [docs/architecture.md](../architecture.md) §3.4
  normative consequence 4 binds directly: `MIGRATING` projects to *Connected*, and any surface
  that flashes a disconnect during a roam is a defect (§11.3).
- **`DEGRADED` is not connected and `RELAYED` is not degraded.** These are the two projection
  errors this product cannot afford: the first hides a real quality problem (C-11), the second
  trains the user to distrust the correct fallback that **R-02** exists to guarantee.
- **The aggregate never looks healthier than reality.** [docs/reliability.md](../reliability.md)
  §4.7's worst-wins order is consumed verbatim, including its two honesty rules, and the
  aggregate is never rendered as a bare word (§11.3).
- **Anti-silence has a UI half.** [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.6's
  four mechanisms all terminate in something drawn on a screen; §11.9 specifies the four
  corresponding UI mechanisms, of which the render-time freshness gate is the one that makes
  "stale green" unreachable by construction rather than by review.

---

## 9. Performance Implications

| Budget | Value | Rationale |
|---|---|---|
| Cold start to **first honest frame** | ≤ 400 ms p95 on the platform's reference device | The first frame is allowed to be `UNKNOWN`; it is not allowed to be optimistic. Showing `UNKNOWN` fast beats showing "Connected" slowly *or* quickly |
| Foreground resume to **first fresh snapshot** | ≤ 300 ms p95 with a live daemon; STALE presentation at 1 s | Aligned with [docs/reliability.md](../reliability.md) §11.3's 300 ms wake-to-traffic target, so the screen and the tunnel converge together |
| View-model patch application | ≤ 4 ms p95 per patch on the reference device | A device with 8 peers in a roam produces bursts; patches must not drop frames |
| Event coalescing | ≥ 60 patches/s coalesced to one render per frame; `INFO`-severity diagnostics coalesced over a 250 ms window | A candidate-racing burst ([ADR-0004](ADR-0004-nat-traversal-strategy.md)) can emit dozens of events per second per `Session`; the UI must not render each |
| Resident memory, GUI process | ≤ 120 MB p95 desktop, ≤ 60 MB mobile app process | The app process, not the extension. The extension holds no UI at all (C-7) |
| Text catalogue, per locale | ≤ 96 KB compressed | Bounded by ~600 registry codes × (summary + up to 6 platform next actions). This is what makes shipping all locales in the binary viable and removes any network dependency from rendering (C-6) |
| Connectivity-report render | ≤ 1 s for a 10-minute Tier-0 window, offline | R-23's report is read while the network is broken |

The dominant performance risk is the **event stream**, not rendering. A UI that subscribes to
every Tier-0 event will be woken continuously on a mobile device and will lose the battery
argument [docs/reliability.md](../reliability.md) §6.6 is careful about. The management contract
must therefore offer a **view-model-shaped** subscription (§11.14, [ADR-0017](ADR-0017-local-management-interface.md) interface 2), not a
raw ledger tail; the raw ledger is a pull, on demand, for the report.

---

## 10. Operational Implications

- **Two artifacts version independently.** The `reason_code` **registry** is append-only and is a
  contract ([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 rules 1–3, 6). The **text
  catalogue** is not a contract and may be reworded or retranslated at any time (rule 4). A
  catalogue update MUST NOT require a registry bump, and a registry addition MUST NOT block a
  release — the `DOMAIN` fallback covers the gap. §11.6.
- **A newer daemon with an older UI is the normal case**, not an edge case: the daemon updates on
  a service channel and the UI on a store channel, and on iOS/Android the store's review latency
  guarantees skew. This is why PC-2 is load-bearing rather than defensive.
- **Translation supply chain.** Catalogue strings are translated from a source locale with the
  code, the class, the severity, and the evidence-field list as translator context. Translators
  never see user data. The catalogue artifact is signed and shipped with the build ([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)).
- **Screenshots are the support channel people actually use.** The three-part rendering is
  designed so that a screenshot of it contains the code (as secondary detail), the state, and the
  action — enough to triage without a bundle.
- **Accessibility is a release gate**, audited per platform per release, not a backlog item
  (§11.11). Regressions here are silent and are found by users, not by CI, unless CI looks.
- **Router and headless tiers have no GUI to operate.** Their surface is the CLI and a read-only
  status page, both consuming the same resolver ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)). Operationally this means the text
  catalogue must be present on a 128 MB device; at ≤ 96 KB per locale it is, and the headless
  profile MAY ship a single locale plus the `DOMAIN` fallbacks.

---

## 11. Decision

**Adopt Alternative D: a shared core view-model and presentation resolver driving thin native
views**, with SwiftUI on iOS / iPadOS / macOS, Jetpack Compose on Android, WinUI 3 on Windows,
GTK4 + libadwaita on Linux, and **no GUI** on the router and headless tiers, all consuming one
projection and one text source from the H1 core over the [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) C ABI.

### 11.1 What "shared core view-model" means, precisely

Three things move into the core, and only three:

| Moved into the core | Left in the native view layer |
|---|---|
| The **projection** from the twelve `ConnectionState`s and the `TwinNet`-scope aggregate onto the user-facing vocabulary (§11.3) | Layout, navigation, animation, gesture, platform chrome |
| The **presentation resolver**: `Diagnostic` → the three parts, for a given locale and platform (§11.4–§11.6) | Typography, colour tokens, iconography, and the *placement* of the three parts |
| The **view-model assembly**: an immutable snapshot plus an ordered patch stream, derived from the [ADR-0017](ADR-0017-local-management-interface.md) subscription (§11.2) | Binding the snapshot to widgets, and accessibility annotation |

Everything else stays native. In particular the view layer contains **no** conditional logic on
`ConnectionState`, no string table, and no derived status of its own. A view layer that branches
on a `ConnectionState` name has re-implemented the projection and is a defect P18 oracle 7 is
built to catch.

The FFI surface is four calls. [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) owns
the ABI and its `tw_` symbol prefix; the render entry point is quoted from its F-10 verbatim, and
the other three are sketched illustratively:

```
tw_vm_subscribe(core, locale, &out_snapshot, &out_stream)   // §11.2
tw_vm_apply_next(stream, &out_patch)                        // ordered; carries the freshness stamp
tw_submit_intent(core, intent, idempotency_key, &out_receipt)   // ADR-0008 keyed

/* Instance-free by ADR-0018 F-10 — it takes no `tw_core*` at all: */
tw_buf *tw_render_diagnostic(tw_slice reason_code, tw_slice evidence,
                             tw_slice locale_bcp47, tw_slice platform_ctx);
uint32_t tw_reason_registry_version(void);
```

`tw_render_diagnostic` is **pure**: same inputs, same output, no I/O, no clock, no ambient locale,
**and no ambient platform**. That is what lets P18 drive it exhaustively and what lets the CLI
produce byte-identical text (HP-3).

**`platform_ctx` is a parameter rather than a build-time constant**, and that buys two things
beyond LT-3's variant selection. The renderer can render **for a platform it is not running on**,
so P18 drives every platform's variants exhaustively **from one CI runner** with no device farm,
and a support workstation can render a bundle collected from a different platform. The rule that
keeps it honest is LT-3's: an **empty** `platform_ctx` resolves to the platform-neutral variant
and MUST NOT fall back to the host's own platform, because an implicit host fallback is ambient
state readmitted through the back door — the thing F-10's purity exists to prevent.

**Instance-freedom is a safety property, not an ABI convenience**, and it closes a case this ADR
would otherwise have left open. Routing rendering through a live core instance would mean the
moment a diagnostic most needs rendering is exactly the moment none exists: after
`INTERNAL.CORE_PANIC` has poisoned the instance, before the core has been created, or inside a
crash reporter. Because the entry point takes no instance, **a poisoned core can still render the
diagnostic describing the fault that poisoned it** — so §11.9's obligation to say something true
survives a failure of the component that does the saying.

### 11.2 The application state model

**UI-1 (the replica rule).** The UI holds a **replica** of daemon-owned state and is never an
authority for any of it. The authoritative writer of every fact in the view-model is named in
[docs/architecture.md](../architecture.md) §5 or in a sibling ADR's `S-` block; the view-model
row is **S-48** and it declares one writer, no durability, and a discard-and-resnapshot conflict
rule. There is no field the UI computes from daemon state except the **freshness clock**, which
it computes from an injected monotonic source (assumption A-21).

**UI-2 (the shape).** The view-model is an immutable snapshot plus an ordered patch stream:

```
ClientViewModel {
  vm_seq            : u64            # strictly increasing; the reconciliation handle
  as_of             : monotonic ts   # when the daemon produced it, on the daemon's clock
  device            : { label, platform, twinnet_label, roles[], hardware_backed }
  aggregate         : { status, carriage, healthy_count, total_count, worst: Diagnostic|null }
  protection        : { indicator: PROTECTED|UNPROTECTED_ANNOUNCED|UNKNOWN,
                        mode: OFF|ARMED_ON_INTENT|ALWAYS_ON, effective_mode,
                        assertion_expires_at }
  trust             : { freshness: FRESH|STALE|EXPIRED, since, diagnostic|null }
  control_plane     : { reachable: bool, unreachable_since|null, diagnostic|null }
  peers[]           : { peer_id, label, platform, status, carriage, roles[],
                        last_validated_at, serving_peer_count|null, diagnostic|null }
  routes_accepted[] : { advertiser_id, prefix, family, accepted_at, source }
  diagnostics[]     : Diagnostic       # active set, deduplicated per §11.4 PC-6
  capabilities      : { can_pair, can_revoke, quorum_required_for[], platform_limits[] }
}
```

`Diagnostic` is [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.3's record, delivered
whole, **including its attributes for codes the UI does not recognize** ([ADR-0017](ADR-0017-local-management-interface.md) interface 3).
The view-model carries **codes and evidence, never rendered text** — rendering happens at the
surface, in that surface's locale, which is what allows one daemon to serve a GUI in French and
a CLI in the C locale simultaneously.

**UI-3 (what the UI may write).** Exactly two things: an **intent** submitted over [ADR-0017](ADR-0017-local-management-interface.md) with
an [ADR-0008](ADR-0008-idempotency.md) idempotency key, and its own presentation preferences
(**S-51**). An intent is a request, not a write: the UI MUST NOT optimistically apply an intent
to the view-model. The affordance shows *pending* until the daemon's patch confirms it. A link,
a notification action, a URL handler, or an automation entry point MAY navigate to a surface and
MUST NOT submit a pairing, route-acceptance, revocation, or disarm intent (S-6).

**UI-4 (staleness tolerance and the render gate).** Three UI-layer constants — these are
presentation constants and are **not** [docs/reliability.md](../reliability.md) §5 timers; they
gate pixels, never the state machine:

| Constant | Default | Meaning |
|---|---|---|
| `T_VM_FRESH` | 2 s | Below this the replica renders normally |
| `T_VM_STALE` | 5 s | At or past this, every state-bearing surface renders in **stale form**: the last-known value is shown, explicitly marked with its age, and **no positive affordance renders** — no green, no "Connected", no "Protected" |
| `T_VM_UNKNOWN` | 15 s | At or past this, the surface renders **`UNKNOWN`**: the value is withdrawn entirely and replaced by the daemon-unreachable presentation of §11.9(2) |

The gate is a **type**, not a check. Render functions take `Fresh<T>`; `Fresh<T>` has no
constructor from a value whose `as_of` is older than `T_VM_STALE`, and the stale and unknown
presentations take `Stale<T>` and `Unknown` respectively. A surface therefore cannot draw a
positive state from a stale replica, because it cannot obtain the value in the type that the
positive renderer accepts. This is the mechanism R-34 names; a lint or a code review is not.

**UI-5 (reconciliation).** Every patch carries `vm_seq`. On `received.vm_seq != last.vm_seq + 1`,
or on any stream reconnect, or on any resume from background, the UI **discards** its replica and
requests a full snapshot; it MUST NOT merge, MUST NOT interpolate, and MUST render stale-form
until the snapshot applies. A patch with `vm_seq` ≤ `last.vm_seq` is dropped (the replica is
`MONOTONIC` — it never renders backwards). The gap itself is surfaced in the status detail view,
not as a toast, because a toast about a gap is noise while a persistent marker is evidence.

**UI-6 (no persisted state renders as current).** A UI MAY persist layout, scroll position, and
S-51 preferences. It MUST NOT persist a view-model and render it as current at next launch; the
first frame after launch is `UNKNOWN` until the first snapshot arrives (§9's first-honest-frame
budget). A cached "Connected" from yesterday is the R-34 defect in its most literal form.

### 11.3 Projection: twelve `ConnectionState`s onto a user-facing vocabulary

The user-facing vocabulary is deliberately **smaller** than the state machine, and it is smaller
in a specific direction: it collapses states the user cannot act on differently, and refuses to
collapse states that mean different things about their traffic. The twelve states are
authoritative in [docs/reliability.md](../reliability.md) §4 and are not restated here.

| User-facing status | Projects from | Carriage qualifier shown | Why |
|---|---|---|---|
| **Off** | `DISCONNECTED` with enforcement mode `OFF` or `ARMED_ON_INTENT` and no connect intent | — | A resting state the user chose |
| **Connecting** | `DISCOVERING`, `NEGOTIATING`, `CONNECTING` | — | Collapsed: see below |
| **Connected** | `LOCAL_DIRECT`, `WAN_DIRECT`, `RELAYED`, `MIGRATING` | yes — *on this network* / *over the internet* / *via an encrypted relay* / *moving* | Collapsed: see below |
| **Connected — reduced** | `DEGRADED{carrier}` | the carrier's qualifier | **Never** collapsed into *Connected* (C-11). Carries the violated objective and its measured value from evidence |
| **Reconnecting** | `RECONNECTING` | — | Traffic is not flowing; the user needs to know that even though recovery is automatic |
| **Traffic stopped — protected** | `BLOCKED` | — | **I3** made visible. Never collapsed, never rendered as an error the user caused |
| **Stopped — needs you** | `FAILED` | — | Terminal for the attempt; always carries a `next_action` and, where present, the named retry precondition |

Two facts ride **alongside** the status and are never encoded as extra statuses, mirroring
[docs/reliability.md](../reliability.md) §4.1's three orthogonal facts:

| Badge | Values | Source |
|---|---|---|
| **Protection** | `Protected` · `Unprotected — announced` · `Unknown` | The most recent `ProtectionAssertion` only ([ADR-0015](ADR-0015-observability-and-diagnostics.md) O-17/O-18). Never derived from the status |
| **Trust freshness** | `Fresh` · `Stale` · `Elevated access paused` | `AUTH.TRUST_STATE_STALE` / `AUTH.TRUST_STATE_EXPIRED`. **Never** changes the status — [docs/reliability.md](../reliability.md) §7.6 is explicit that trust staleness produces a persistent `Diagnostic` and no `ConnectionState` change |

**What is deliberately collapsed, and why.**

| Collapse | Reason |
|---|---|
| `DISCOVERING` + `NEGOTIATING` + `CONNECTING` → *Connecting* | There is no user action that differs between them, and exposing three names invites the "stuck at 40 %" reading of a process that is racing candidates in parallel. The distinction survives in full in the per-peer technical detail row and in the connectivity report's candidate ledger, which is where it is diagnostically useful |
| `LOCAL_DIRECT` + `WAN_DIRECT` + `RELAYED` → *Connected* | A relayed path is a **working, confidential** path — the relay forwards opaque ciphertext (**I1**) and **R-02** guarantees relay fallback is not a connection failure. Rendering it as a warning would train the user to distrust the correct behaviour. Speed expectations do differ, so carriage is a qualifier |
| `MIGRATING` → *Connected* | [docs/architecture.md](../architecture.md) §3.4 consequence 4: the UI MUST NOT report a disconnect for a `Path` change. A roam that flashes "Disconnected" is the R-07 defect resurfacing at the presentation layer |
| Trust staleness → **not** collapsed into any status | See above; it is a badge |

**`TwinNet`-scope derived state.** The primary surface shows the aggregate computed by
[docs/reliability.md](../reliability.md) §4.7's worst-wins order, consumed verbatim, including
both honesty rules. Two presentation obligations follow:

- **AG-1.** The aggregate MUST NOT be rendered as a bare word. It renders as *status + healthy
  count + the worst contributing `Session`'s three-part diagnostic*, which is what makes
  §4.7's target sentence — "3 of 4 devices connected; laptop unreachable because …" — the
  default rendering rather than an aspiration.
- **AG-2.** When enforcement is `FAIL_CLOSED` and no `Session` in the protected scope has a
  usable path, the aggregate is *Traffic stopped — protected* **regardless** of individual
  session states, and the per-`Session` causes attach beneath it. A `FAILED` session inside a
  `BLOCKED` device shows both, in that order.

### 11.4 The reason-code presentation contract

This is the load-bearing section of this ADR. It defines what a surface does with a
`Diagnostic`, and it is written so that the answer is complete **before** anyone knows which code
arrived — because forward compatibility (C-5, [ADR-0015](ADR-0015-observability-and-diagnostics.md)
§11.2 rule 5) means an unknown code is the normal case, not the exception.

**This ADR owns no reason codes.** Every code named in §11.5 is owned and registered by another
document; this section specifies only how a code is *presented*.

#### PC-1 — the three parts

Every user-visible `Diagnostic` renders exactly three parts, always in this order, always all
three present:

| Part | Question it answers | Source | Degrades on unknown code? |
|---|---|---|---|
| **1. What happened** | "What did the product observe?" | `summary_key` → catalogue, in the requested locale, with declared evidence fields interpolated by name | **Yes** — to the `DOMAIN` sentence (PC-2) |
| **2. What this means for your traffic right now** | "Is my traffic flowing, blocked, or leaving unprotected?" | Computed from `(state_to, traffic disposition, enforcement mode)` per the table below — **not** from the code | **No — never degrades.** This is the insight the contract rests on |
| **3. Suggested next action** | "What do I do?" | `next_action_key` → catalogue, variant-selected by platform and OS version (§11.6); or, when `user_actionable == false`, the `remediation_class` sentence | **Yes** — to the `DOMAIN` default action, plus the always-available report action |

Part 2 is the reason a user who receives a code from a daemon three versions newer than their UI
is still told the truth about their traffic. The disposition vocabulary is
[docs/reliability.md](../reliability.md) §4.1's, and it is carried in the view-model, so the
mapping is mechanical:

| Traffic disposition | Part-2 sentence class |
|---|---|
| `TUNNELED_LOCAL_DIRECT` / `TUNNELED_WAN_DIRECT` / `TUNNELED_RELAY` | Your traffic is protected and flowing |
| `TUNNELED_DUAL` | Your traffic is protected and is moving to a new network path |
| `QUEUED_BOUNDED` | Traffic is being held briefly while the path changes; it has not been dropped |
| `DROPPED_FAIL_CLOSED` | Traffic is being **blocked rather than sent unprotected** |
| `DROPPED_NO_ROUTE` | Traffic to your devices has nowhere to go right now; the rest of this device's traffic is unaffected |
| `UNPROTECTED_ANNOUNCED` | Traffic is leaving this device **untunneled** |

**PC-2 — unknown codes.** A surface holding no catalogue entry for a `reason_code`:

1. splits the code on `.` and takes segment 1 as `DOMAIN`;
2. renders part 1 from the **domain fallback** entry for that `DOMAIN`, in the requested locale;
3. renders part 2 exactly as PC-1 specifies — unchanged, exact, undegraded;
4. renders part 3 from the domain's default next action, selected for the platform, and always
   includes the *open the connectivity report* action;
5. renders the raw code **exactly once**, in a secondary, copyable technical detail line, never
   as the headline (rule 5, O-02);
6. still chooses affordances correctly, because `class`, `severity`, `user_actionable`,
   `remediation_class`, and `scope` arrive with the `Diagnostic` even when the code does not
   ([ADR-0017](ADR-0017-local-management-interface.md) interface 3). An unknown `POLICY`-class `CRITICAL` code is still persistent and
   still non-dismissible under PC-5;
7. on an unrecognized `DOMAIN` — a fourteenth domain does not exist today, but a newer daemon is
   not obliged to be readable by an older UI — falls back to the neutral entry, which is a real
   sentence, not "Unknown error".

| `DOMAIN` | Fallback part 1 (illustrative source text) | Fallback part 3 |
|---|---|---|
| `NET` | TwinVPN hit a problem with this device's network connection | Check that this device is online, then open the connectivity report |
| `NAT` | This network's router is making a direct connection difficult | TwinVPN will keep trying, including through an encrypted relay; open the connectivity report for detail |
| `RELAY` | TwinVPN had a problem with the encrypted relay it uses when a direct connection is not possible | No action needed; TwinVPN is trying other relays. Open the connectivity report for detail |
| `AUTH` | There is a problem with the trust between this device and the other one | Open the device list to check this device's status, then open the connectivity report |
| `CRYPTO` | A secure handshake with the other device did not complete | TwinVPN will retry. If it persists, check that both devices are up to date |
| `PROTO` | This device and the other one could not agree on how to talk to each other | Update TwinVPN on both devices |
| `POLICY` | A protection or access rule is affecting this traffic | Open the protection settings to see which rule, and why |
| `DNS` | There is a problem resolving names while protected | Open the connectivity report's DNS section |
| `ROUTE` | TwinVPN could not program this device's network routes or interface | Close other VPN software, then open the connectivity report |
| `PLATFORM` | The operating system refused something TwinVPN needs | Open the connectivity report; it names the permission or component involved |
| `RESOURCE` | A device in your TwinNet is at a capacity limit | Open the device list; the limit and the current value are shown there |
| `CONTROL` | TwinVPN cannot reach the coordination service. **Your devices still talk to each other** | No action needed; this does not affect existing connections |
| `INTERNAL` | TwinVPN hit a defect in itself | Save a diagnostic report and send it to support |
| *(unrecognized)* | TwinVPN reported a condition this version does not recognize | Update TwinVPN, then open the connectivity report |

The `CONTROL` row deliberately carries the reassurance in part 1, because
[docs/reliability.md](../reliability.md) §9.4 makes surfacing a control-plane outage as a
terminal connection failure a defect: the tunnel is working, and the sentence must say so before
anything else.

**PC-3 — prohibited renderings.** Each is a defect, not a style preference.

| Prohibited | Why |
|---|---|
| A bare numeric code, an OS errno, an HRESULT, a `WSAGetLastError` value, or an `NSError` domain+code as the **primary** user-facing signal | **I6**; [docs/reliability.md](../reliability.md) §3.3; O-02. They may appear as declared `evidence`, attached to a code, never in place of one |
| "Connection failed", "Unknown error", "Something went wrong", "Error 0x…" | The founding complaint. Any condition reaching the user has been classified |
| The raw `reason_code` as the headline | Rule 5. It is secondary detail, exactly once |
| An indefinite spinner with no text past `T_CONNECT` | A progress indicator is not an explanation, and after the establishment deadline the machine has a named outcome |
| A connected or protected indication without a fresh `ProtectionAssertion` | O-18; R-34; §11.9 |
| Rendering `DEGRADED` or `BLOCKED` as connected | C-11 |
| Assembling a user-facing sentence by concatenating a code, or a key, with glue text — `"Failed: " + code` | §11.6 LT-4. It is unlocalizable, ungrammatical outside English, and it puts the code in the headline |
| A dismissal that makes a `POLICY`-class or `CRITICAL` condition invisible | PC-5 |
| `SECRET` evidence, or unpseudonymized `SENSITIVE` evidence, inside a share artifact or its preview | C-14; §11.10(g) |

**PC-4 — evidence rendering.** Declared `evidence_fields` render as a labelled block beneath the
three parts, governed by the registry's classification
([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.4): `PUBLIC` and `OPERATIONAL` always;
`SENSITIVE` on the `Owner`'s own device but pseudonymized in every share artifact; `SECRET`
never, because no path exists. Numbers a user or a support engineer needs come **from evidence**,
never from a prose string (O-14) — so `NET.QOS.RTT_HIGH` shows `measured_rtt_ms` next to
`threshold_ms` and `baseline_rtt_ms`, and the sentence does not contain a number the catalogue
had to be re-translated to change.

**PC-5 — persistence and dismissal.**

| `class` / `severity` | Presentation lifetime |
|---|---|
| `POLICY`, or `severity: CRITICAL` | **Persistent** while the condition holds, in every surface including tray, menu-bar, and notification. Dismissal collapses it to a badge; it MUST NOT become invisible. [docs/reliability.md](../reliability.md) §4.4 requires exactly this for `BLOCKED`: "the reason code and its remediation are displayed persistently" |
| `severity: ERROR` | Persistent in the primary surface while the condition holds; dismissible to the status detail view |
| `severity: WARN` | Persistent while the condition holds; dismissible, and reachable afterwards in the status detail view |
| `severity: INFO` | Transient; MAY auto-dismiss; MUST still be in the Tier-0 ledger and the report |

**PC-6 — one condition, one item.** N `Session`s failing with the same `reason_code` coalesce
into **one** presented item carrying the peer count and the peer list, not N notifications. The
`scope` evidence field ([docs/reliability.md](../reliability.md) §3.1) selects the coalescing key:
`session` coalesces by code, `device` / `relay` / `region` / `twinnet` are already single-instance.

**PC-7 — no surface is exempt.** The contract binds every surface: primary window, tray and
menu-bar item, Android foreground-service notification, macOS notification, Windows toast,
iPadOS widget, CLI, and the router status page. A surface too small for three parts renders
**part 2 first** and links to the rest — because "your traffic is blocked" is the part that
cannot be deferred.

### 11.5 The presentation catalogue — worked entries for the highest-traffic codes

Every code below is **owned and registered elsewhere**; the owner is named. The columns are this
ADR's contribution: part 1 and part 3 source text (English source locale, illustrative — the
text is not the contract, rule 4), and the affordance the surface offers. Part 2 is omitted from
the table on purpose: it is not a property of the code, it is computed by PC-1 from the
disposition the `Diagnostic` arrived with, and writing it per-code here would be the exact defect
mutant `M-P18-2` injects.

| `reason_code` (owner) | Part 1 — what happened | Part 3 — suggested next action | Affordance |
|---|---|---|---|
| `NAT.SYMMETRIC_BOTH_ENDS` ([ADR-0004](ADR-0004-nat-traversal-strategy.md)) | Both networks block direct connections, so this connection is going through an encrypted relay | Enabling IPv6 on either network usually restores a direct connection | Link: what a relay is · Report |
| `NAT.UDP_BLOCKED` ([ADR-0004](ADR-0004-nat-traversal-strategy.md)) | This network blocks the fastest way TwinVPN connects, so it fell back to a slower one that works | Nothing to do here. On a network you control, allowing outbound UDP restores full speed | Report |
| `NET.PATH.DEAD_NO_ALTERNATE` ([docs/reliability.md](../reliability.md)) | The network path to {peer_label} stopped responding and there is no other path to switch to yet | TwinVPN is reconnecting automatically. If this device just changed networks, this is expected | none (automatic) |
| `NET.QOS.RTT_HIGH` ([docs/reliability.md](../reliability.md)) | The connection to {peer_label} is much slower to respond than usual | TwinVPN is looking for a better path. Moving closer to your Wi-Fi access point often helps | Report |
| `NET.SILENT_PATH_SUSPECTED` ([ADR-0015](ADR-0015-observability-and-diagnostics.md)) | TwinVPN believed this connection was working but nothing is coming back over it | TwinVPN is re-checking the path now. No action needed | none (automatic) |
| `NET.CAPTIVE_PORTAL` ([docs/networking.md](../networking.md)) | This Wi-Fi network wants you to sign in before it will carry traffic | Open the network's sign-in page. TwinVPN will keep everything else blocked until you do | Button: open sign-in |
| `NET.MTU_BLACKHOLE_DETECTED` ([ADR-0015](ADR-0015-observability-and-diagnostics.md)) | This network silently drops larger packets, which was breaking some traffic | TwinVPN reduced its packet size to work around it. No action needed | Report |
| `RELAY.NONE_REACHABLE` ([ADR-0006](ADR-0006-relay-discovery-and-failover.md)) | TwinVPN could not reach any relay, and a direct connection is not possible from this network | Check whether this network blocks outbound connections; TwinVPN keeps retrying | Report |
| `RELAY.REGION.DOWN` ([ADR-0006](ADR-0006-relay-discovery-and-failover.md)) | The relays nearest you are unavailable, so TwinVPN switched to another region | Nothing to do. Connections may be slower by about {added_rtt_ms} ms until the nearer relays return | none (automatic) |
| `RELAY.FAILOVER.CROSS_REGION` ([ADR-0006](ADR-0006-relay-discovery-and-failover.md)) | TwinVPN moved this connection to a relay in a different region to keep it up | Nothing to do; this is TwinVPN working as intended | none (automatic) |
| `AUTH.DEVICE_REVOKED` ([ADR-0007](ADR-0007-device-identity-and-pairing.md)) | {peer_label} was removed from your TwinNet and can no longer connect | If this was not intentional, add the device again from an admin device | Button: re-enrol |
| `AUTH.PEER_UNTRUSTED` ([ADR-0007](ADR-0007-device-identity-and-pairing.md)) | The other device presented an identity this device has never paired with | Pair the two devices again | Button: pair |
| `AUTH.TRUST_STATE_STALE` ([ADR-0007](ADR-0007-device-identity-and-pairing.md)) | TwinVPN has not been able to refresh your TwinNet's membership list for {age}. Your devices still connect normally | No action needed. If this device has been offline, connecting it to the internet will refresh it | Link: what this affects |
| `AUTH.TRUST_STATE_EXPIRED` ([ADR-0007](ADR-0007-device-identity-and-pairing.md)) | Your devices still connect to each other, but exit-node access, LAN access, accepted routes, and new pairing are paused until TwinVPN can refresh membership | Connect this device to the internet to refresh. Everything resumes automatically | Link: what is paused |
| `AUTH.PAIRING_CODE_MISMATCH` ([ADR-0007](ADR-0007-device-identity-and-pairing.md)) | That pairing code was not correct. {attempts_remaining} attempts remain before this code is cancelled | Check the nine digits on the other device and try again | Field: retry |
| `AUTH.PAIRING_ATTEMPTS_EXCEEDED` ([ADR-0007](ADR-0007-device-identity-and-pairing.md)) | This pairing code has been cancelled after five failed attempts | Start pairing again from the other device to get a new code | Button: start again |
| `POLICY.KILLSWITCH.ENGAGED` ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)) | TwinVPN has no protected path right now, so it is blocking traffic instead of sending it unprotected | Wait — TwinVPN is reconnecting. To go online unprotected, turn protection off deliberately | Button: turn protection off (OS-authenticated) |
| `POLICY.KILLSWITCH.UNPROTECTED_FALLBACK` ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)) | Protection is turned off, so this device's traffic is leaving untunneled | Turn protection back on when you are done | Button: turn protection on |
| `POLICY.KILLSWITCH.ARM_FAILED` ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)) | TwinVPN could not install its protection rules, so it will not enter a protected state at all | {conflicting_component} may be blocking it. Close or exclude it, then try again | Button: retry · Report |
| `POLICY.KILLSWITCH.DISARM_REFUSED_REMOTE` ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)) | Something that was not you tried to turn protection off. TwinVPN refused | Nothing was disabled. Save a diagnostic report; this should not happen | Button: save report |
| `POLICY.LEAK.IPV6_UNPROTECTED` ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)) | This connection carries IPv4 only, so IPv6 destinations are being blocked rather than sent outside the tunnel | Nothing to do here. Enabling IPv6 on the other device restores full reach | Link: why |
| `POLICY.GATEWAY.EXIT_NOT_ENGAGED` ([ADR-0013](ADR-0013-multi-client-gateway-architecture.md)) | {peer_label} is not currently allowing this device to use it as an exit node | Turn exit-node access on for this device from {peer_label}, or from an admin device | Button: request access |
| `DNS.LEAK.QUERY_OBSERVED_OFF_TUNNEL` ([ADR-0011](ADR-0011-dns-handling.md)) | A name lookup went outside the tunnel. TwinVPN has re-applied its DNS settings | No action needed. If it repeats, save a diagnostic report | Button: save report |
| `DNS.RESOLUTION.BLOCKED_FAIL_CLOSED` ([ADR-0011](ADR-0011-dns-handling.md)) | TwinVPN blocked a name lookup rather than send it outside the tunnel | This clears when a protected path returns | none (automatic) |
| `DNS.PLATFORM.PRIVATE_DNS_ACTIVE` ([ADR-0011](ADR-0011-dns-handling.md)) | This device has Android Private DNS turned on, which takes precedence over TwinVPN's DNS settings | Set Private DNS to *Automatic* in Android settings if you want TwinVPN's DNS to apply | Button: open settings |
| `PROTO.VERSION_UNSUPPORTED` ([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)) | {peer_label} is running a version of TwinVPN this one can no longer talk to | Update TwinVPN on {peer_label} | Link: how to update |
| `PROTO.DOWNGRADE_REFUSED` ([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)) | Something tried to make these two devices use weaker settings than they agreed before. TwinVPN refused | Nothing was weakened. If this repeats on one network, save a diagnostic report | Button: save report |
| `PLATFORM.VPN_PERMISSION_DENIED` ([docs/architecture.md](../architecture.md) §2.5) | {os_name} has not given TwinVPN permission to create a VPN connection | *(platform-specific — see §11.6)* | Button: grant permission |
| `PLATFORM.ADAPTER_UNAVAILABLE` ([docs/architecture.md](../architecture.md) §2.5) | TwinVPN could not create the network adapter it needs on this device | *(platform-specific — see §11.6)* | Button: repair · Report |
| `PLATFORM.THIRD_PARTY_FILTER_SUSPECTED` ([docs/architecture.md](../architecture.md) §2.5) | {conflicting_component} appears to be filtering or claiming TwinVPN's network adapter | Add TwinVPN as an exclusion in {conflicting_component}, or close it and try again | Report |
| `PLATFORM.BACKGROUND_SUSPENDED` ([docs/reliability.md](../reliability.md)) | {os_name} paused TwinVPN in the background to save battery. It reconnects when you come back | Nothing to do. To stay reachable from other devices in the background, mark this device always-reachable | Link: always-reachable |
| `CONTROL.UNREACHABLE` ([ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md)) | TwinVPN has not reached the coordination service for {age}. Your devices still talk to each other normally | No action needed. Adding devices and changing settings will work again when it reconnects | Link: what this affects |
| `CONTROL.STALENESS.POLICY_GRANT_SUSPENDED` ([ADR-0009](ADR-0009-state-consistency.md)) | A permission expired while TwinVPN could not reach the coordination service, so it has been paused | Existing connections are unaffected; the permission returns automatically | Link: what is paused |
| `ROUTE.IFACE_CONFLICT` ([ADR-0010](ADR-0010-ipv4-ipv6-routing.md)) | Another program is already using the network interface TwinVPN needs | Close {conflicting_component}, then try again. TwinVPN will not overwrite another program's settings | Button: retry · Report |
| `INTERNAL.INVARIANT_VIOLATED` ([ADR-0015](ADR-0015-observability-and-diagnostics.md)) | TwinVPN detected a defect in itself and stopped rather than continue in an uncertain state | Save a diagnostic report and send it to support. This is a bug, not something you did | Button: save report |

Three conventions the table follows and every catalogue entry MUST follow:

1. **Part 1 never contains a code, a key, a hexadecimal number, or an acronym the persona table
   in [docs/vision.md](../vision.md) §2 would not recognize.** "Relay", "IPv6", and "Wi-Fi" pass;
   "srflx", "WFP sublayer", and "NAT class APDM" do not — those are evidence.
2. **Part 3 is an action, or an explicit statement that none is needed.** `user_actionable ==
   false` still produces a sentence, selected by `remediation_class`: `automatic` → "TwinVPN is
   handling this"; `wait` → "This clears on its own"; `network-operator` → "This is a property of
   the network you are on"; `unsupported` → "This platform cannot do this"; `user-action` is
   never paired with `user_actionable == false`.
3. **No entry blames the user**, and no entry says "failed" without saying what still works.

### 11.6 Localization and text architecture

**LT-1 — the catalogue.** One artifact per locale, keyed by the registry's `summary_key` and
`next_action_key`, not by `reason_code`, so a deprecated code aliased forward
([ADR-0015](ADR-0015-observability-and-diagnostics.md) rule 3) reuses its replacement's text
without a second entry:

```
catalogue/
  en.tvcat            # {catalogue_version, registry_version_floor, entries{}, domains{}, dispositions{}}
  de.tvcat  fr.tvcat  ja.tvcat  ar.tvcat  ...
entry :=
  summary        : ICU MessageFormat pattern, named placeholders only
  next_action    : { default: pattern, variants: [{platform, os_range, pattern}] }
  evidence_labels: { field_name -> label }
domains[DOMAIN]     := { summary, next_action }         # the PC-2 fallback
dispositions[D]     := pattern                           # the PC-1 part-2 sentence class
```

`registry_version_floor` records the registry version the catalogue was built against. It is a
**diagnostic**, not a gate: a catalogue older than the registry is normal (§10), and the
mismatch is what PC-2 exists to absorb.

**LT-2 — the fallback chain**, evaluated per string, never per catalogue:

```
requested locale+region (fr-CA)
  → base language (fr)
    → source locale (en)
      → domain fallback in the requested locale        # PC-2, still localized
        → domain fallback in the source locale
          → the neutral entry + the code as secondary detail
```

The chain **never** terminates in an empty string, in the i18n key, or in the raw code as the
primary signal. A missing translation degrades to a *less specific true sentence*, never to a
non-sentence. Falling through to a lower rung is counted and appears in the connectivity report,
so translation gaps are measurable rather than invisible.

**LT-3 — platform-varying next actions.** The fix for a Windows WFP problem is not the fix for an
Android always-on problem, so `next_action` is variant-selected by `(platform, os_version_range)`,
carried in `platform_ctx` (§11.1), with a **mandatory neutral variant**.

Three normative rules govern the selection:

| # | Rule |
|---|---|
| **LT-3a** | Selection is a **decision**, and by ADR-0018 CB-2 a shell may not hold one. It is therefore made in the core, from `platform_ctx`, never by a shell choosing among returned keys — which is also what keeps a GUI and a CLI **on the same host** from diverging (HP-3, P18 oracle 6) |
| **LT-3b** | An **empty** `platform_ctx` resolves to the **platform-neutral** variant. It MUST NOT fall back to the host's own platform. An implicit host fallback would make the render call ambient-dependent and is the defect F-10's purity exists to prevent (ADR-0018 §11.16(n)) |
| **LT-3c** | **Every code with a `next_action` MUST have a neutral variant.** This is a catalogue **completeness** requirement, not a nicety: without it LT-3b resolves to nothing and part 3 comes back empty, violating R-33. CI asserts it per locale — for every entry with any platform variant, a neutral variant exists and is non-empty — and a missing neutral variant fails the build |

The neutral variant is a real sentence, not a placeholder: it says what to do in terms that hold
on any platform, and the platform variants sharpen it. For
`PLATFORM.VPN_PERMISSION_DENIED` the neutral variant is *"Grant TwinVPN permission to create a
VPN connection in this device's system settings."* The variants:

| Platform | Part 3 variant | Deep link |
|---|---|---|
| Android | Allow the VPN connection request when {os_name} asks. If you dismissed it, open VPN settings and enable TwinVPN | `Settings.ACTION_VPN_SETTINGS` |
| iOS / iPadOS | Allow the VPN configuration when iOS asks, and confirm with your passcode. If you removed it, add it again below | `App-prefs:General&path=VPN` where available; otherwise instructions only |
| macOS | Open System Settings → Privacy & Security and allow the TwinVPN system extension. You may need to restart | `x-apple.systempreferences:com.apple.preference.security` |
| Windows | TwinVPN's background service is not installed or not running. Choose *Repair installation*; Windows will ask for administrator approval | elevated repair helper |
| Linux | The system refused the request. Grant the polkit action `{polkit_action_id}`, or add your user to the `twinvpn` group and sign in again | none — text plus the action id |
| OpenWrt / headless | *(no GUI — the CLI prints the same part 3 with the `uci` path)* | n/a |
| *(neutral — empty `platform_ctx`)* | Grant TwinVPN permission to create a VPN connection in this device's system settings | none, by construction |

**LT-4 — no assembled strings (normative).** No user-facing string is produced by concatenating a
`reason_code`, an i18n key, an enum name, or a fragment with glue text. Every sentence is a whole
catalogue pattern with **named** ICU placeholders bound to declared evidence fields. `"Failed: "
+ code` is prohibited in every surface, including the CLI and the router status page. The rule
exists because concatenation is unlocalizable (word order differs), ungrammatical (gender and
case differ), and because it is how the code ends up in the headline in violation of PC-3.

**LT-5 — plurals and gender.** ICU plural categories, never "1 device(s)" and never a manual
`n == 1` branch: Arabic has six categories, Polish three, Japanese one, and a hand-written branch
is wrong in most of them. Select-format for gendered nouns where the target language needs it.
Counts always come from evidence.

**LT-6 — bidirectional text.** Full RTL mirroring of layout, with these **exemptions rendered
LTR and isolated** with `U+2068` FIRST STRONG ISOLATE / `U+2069` POP DIRECTIONAL ISOLATE: IP
addresses, prefixes and CIDR lengths, `reason_code`s, key fingerprints, pairing codes, interface
names, URLs, and version numbers. Without isolation an Arabic or Hebrew peer label adjacent to an
address visually reorders the address — which, for a security product where the user is asked to
compare a fingerprint, is a correctness bug and not a typographic one.

**LT-7 — numbers and units.** Locale-formatted, with the unit from the evidence field's declared
type, and the raw value copyable. Durations are formatted relatively ("3 days") in part 1 and
absolutely in the evidence block.

**LT-8 — the catalogue is not the contract.** Restating rule 4 as an application obligation:
automation, tests, support tooling, and the CLI's `--json` output key on `reason_code`; nothing
in the product parses rendered text. This is what allows a catalogue to be corrected in a patch
release with no compatibility analysis.

**LT-9 — pseudo-locale in CI.** A generated pseudo-locale expands every string by 40 % and wraps
it in markers. Two gates run against it: no clipped or truncated diagnostic text at the largest
supported dynamic type size (A11Y-4), and **no unmarked Latin-script string in any rendered
surface** — which is how P18 oracle 7 detects a hardcoded English literal in a view layer.

### 11.7 UI framework realization, all ten targets

| Tier | Target | View layer | Primary surface | Secondary surfaces | Notes |
|---|---|---|---|---|---|
| Required | **iOS 15+** | SwiftUI | App window | Widget (read-only), notifications | UI lives in the **app** process only; the `NEPacketTunnelProvider` extension holds no UI (C-7). The app is a management client of the extension over [ADR-0017](ADR-0017-local-management-interface.md)'s platform binding |
| Required | **iPadOS 15+** | SwiftUI, distinct adaptive layout, same binary as iOS | App window(s), multi-scene | Widget, notifications, external display | §11.8 |
| Required | **Android API 26+** (target 29 behaviour) | Jetpack Compose | App window | **Foreground-service notification** — a first-class anti-silence surface, not chrome; quick-settings tile | The FGS notification is where a backgrounded user learns protection stopped. [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) owns the service; §11.9 owns what it says |
| Required | **Windows 10 21H2 / Server 2019+** | WinUI 3 (Windows App SDK) | Tray icon + flyout | App window, toast notifications | The UI process is **unprivileged** and speaks only [ADR-0017](ADR-0017-local-management-interface.md) to the service; it cannot self-elevate, and the elevated repair path is a separate helper (§11.10 a) |
| Required | **macOS 11+** | SwiftUI + AppKit for the status item | **Menu-bar item** | App window, notifications, login item | §11.8. Not Mac Catalyst |
| Required | **Linux** | GTK4 + libadwaita (reference GUI) | App window | Tray via StatusNotifierItem where the desktop provides one | **One** GUI, not two. Qt6 is permitted for a downstream KDE-first repackaging but is not shipped or supported by us. The **CLI is the supported baseline** on Linux, because no desktop session may be assumed |
| Future | **OpenWrt 21.02+ / routers** | **none** | LuCI status page (read-only) | CLI | ≤ 128 MB RAM, read-only rootfs, musl. The status page renders the same three parts from the same resolver via [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md); it submits **no** intents. Deferred: a write-capable LuCI app |
| Future | **Headless gateways** | **none** | CLI + local status endpoint | — | Same resolver, same operation set, single locale plus `DOMAIN` fallbacks permitted (§10) |
| Future | **CLI-only desktop** | **none** | CLI | — | A first-class configuration on every desktop OS, not a degraded mode; HP-1…HP-3 make it complete |
| Future | **Embedded / kiosk** | **none** | CLI | — | Deferred entirely; nothing in this ADR forecloses a future read-only display client, because a display client is a management-contract subscriber like any other |

**Why the shells are what they are.** SwiftUI is the only toolkit with first-class VoiceOver,
Dynamic Type, and Stage Manager support on Apple platforms, and it is already required for
anything that ships to the App Store credibly. Compose is Android's supported direction and gives
TalkBack semantics for free. WinUI 3 is the only Microsoft-supported path that gets modern
Narrator and UI Automation semantics without an Electron-class runtime. GTK4 + libadwaita gives
AT-SPI2 and Orca support and matches the desktop most of our Linux persona runs. In each case the
choice is driven by **the accessibility stack and the platform idiom**, which is exactly the axis
Alternatives B and C lose on for a security product.

**What is shared and what is not.** Shared: the projection, the resolver, the catalogue, the
management client, the intent set, and the connectivity-report model. Not shared: layout,
navigation, animation, gestures, and iconography. This split is what keeps six view layers a
*layout* cost rather than a *semantics* cost.

### 11.8 iPadOS and macOS specifically

**iPadOS is not iOS scaled up.** It ships from the same binary as iOS with the same core, the
same extension, and the same permission model — and a **distinct adaptive layout**. It is not a
Mac Catalyst app; Catalyst is rejected for macOS (below), and using it for iPadOS would buy
nothing.

| Concern | Decision |
|---|---|
| **Multi-window / Stage Manager** | Multiple `UIWindowScene`s supported: status, device detail, connectivity report, and pairing may each occupy a scene. **One subscription per process, not per scene** — every scene renders from the same `ClientViewModel` replica, so two windows can never show divergent states. A second replica per scene would be an **I8** break inside the app and is prohibited |
| **Pointer** | `UIPointerInteraction` with correct pointer effects on the status control and list rows. **No hover-only affordance**: every action reachable by pointer is reachable by touch and by keyboard |
| **Hardware keyboard** | A full `UIKeyCommand` set with a discoverability HUD: connect, disconnect, open report, focus device list, next/previous device. Destructive and authority actions — revoke, disarm, accept a route — have **no** single-key shortcut, and disarm is OS-mediated regardless (C-9) |
| **External display** | Supported as an ordinary scene. The app MUST NOT assume a size class, an aspect ratio, or a safe-area inset; the status surface is laid out from the trait collection at render time |
| **Split View / Slide Over** | At compact width the **full three-part diagnostic still renders** — parts 2 and 3 are never truncated. When space runs out, the peer list truncates first, then the evidence block. A truncated part 2 is an R-33 violation |
| **Files integration** | Diagnostics export through `.fileExporter` / `UIDocumentPickerViewController`, so the artifact lands in Files, iCloud Drive, or a third-party provider of the user's choosing. The export writes **only after** the redaction preview is confirmed (§11.10 g), and the artifact is signed and expiring per [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.9(4) |
| **Background posture** | Identical to iOS: the extension holds the data plane, the app process holds the UI and diagnostics (C-7). A larger screen buys no background allowance, and the UI must not imply it does |

**macOS.**

| Concern | Decision |
|---|---|
| **Menu bar vs window** | **Both**, with the menu-bar item as the *primary* status surface. It is the only surface present when the app window is closed, which makes it the anti-silence surface, and §11.9's freshness gate applies to it identically. Its menu carries the aggregate's three parts, not just an icon |
| **Menu-bar icon** | Rendered as a template image, so macOS strips colour — which is precisely why A11Y-1 requires shape and glyph differences rather than colour. Each projected status has a distinct glyph, and the menu's first item is the status **as text** |
| **Login item** | `SMAppService` on macOS 13+, the legacy login-item API on 11–12. **The login item is a convenience for the UI only.** Protection is held by the `launchd`-managed daemon and the system extension (H2 / [ADR-0016](ADR-0016-client-process-and-privilege-separation.md)) and by the OS-level rule set (S-18); disabling the login item MUST NOT change protection, and the UI says so at the point of the toggle |
| **System extension approval** | `OSSystemExtensionRequest`, approved in System Settings → Privacy & Security, sometimes requiring a restart. This is a **refusal branch** in onboarding (§11.10 a), detected asynchronously so the user is not made to restart the flow |
| **Distribution** | Developer ID with a **system extension** and Mac App Store with an **app extension** have materially different capability. [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) owns the choice; this ADR's binding rule: **the UI MUST NOT claim a protection posture the shipped build cannot deliver.** A build whose enforcement point cannot cover the boot window renders `POLICY.KILLSWITCH.BOOT_ENFORCEMENT_UNAVAILABLE` as a named platform limitation instead of a full-protection indicator |
| **Mac Catalyst — rejected** | Catalyst handles the menu-bar item, the login item, and the system-extension approval flow poorly, and all three are load-bearing here. A native AppKit/SwiftUI Mac app is the decision |

### 11.9 The anti-silence obligation in the UI

[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.6's four mechanisms all terminate in
something drawn on a screen; [docs/reliability.md](../reliability.md) §10 forbids the silent
failure they exist to prevent. These four are the UI's half, and each is independently testable.

**(1) The render-time freshness gate.** UI-4's `Fresh<T>` type. Every state-bearing surface —
window, tray, menu-bar item, notification body, widget, quick-settings tile — renders from
`(value, as_of, source)` and cannot obtain a positive renderer's input from a stale value. This
is the mechanism that makes a stale green **unreachable by construction**, and it applies to the
Android foreground-service notification specifically: a persistent notification still saying
"Connected" after the tunnel died is the founding defect wearing a system UI.

**(2) Daemon unreachable.** When the [ADR-0017](ADR-0017-local-management-interface.md) connection is lost, the UI renders a distinct
condition — *TwinVPN can't reach the TwinVPN service on this device* — and it is **honest in both
directions**:

- It MUST NOT say traffic is unprotected. The enforcement rule set is OS-level and outlives every
  process, including the daemon (S-18); the UI does not know that protection stopped.
- It MUST NOT say traffic is protected. It cannot obtain a fresh `ProtectionAssertion`.
- It renders protection as `UNKNOWN`, states that protection may still be in force, names the
  reconnection attempt, and — where the platform allows it — offers the OS-level restart path.
- It is **distinct** from "not connected to peers". Conflating a management-channel loss with a
  tunnel loss is a diagnosis the UI is not entitled to make.

**(3) Event-stream gap.** UI-5. A `vm_seq` gap or a resubscribe drops the replica and forces a
resnapshot; the surface renders stale-form until the snapshot applies, and the gap is recorded in
the status detail view. A gap that produced no visible change would mean the UI had guessed.

**(4) Resume from background.** On foreground, app resume, screen unlock, or system wake, **every
cached value is marked stale unconditionally** — no wall-clock arithmetic, because wall clocks
jump across suspend and that is the single most common transition-producing event on a laptop
([docs/reliability.md](../reliability.md) §10.2 E5). The UI renders stale-form, requests a
snapshot, and requests an immediate liveness refresh, converging with the tunnel's own
wake-to-traffic sequence (§11.3 of that document) rather than after it. If no fresh snapshot has
arrived by 1 s, the surface stays in stale-form; it does not become optimistic while waiting.

**(5) The protection indicator is not derived.** It is a pure function of the most recent
`ProtectionAssertion` (O-17/O-18) delivered over [ADR-0017](ADR-0017-local-management-interface.md), with exactly three values. The UI MUST
NOT synthesize it from the `ConnectionState`, from its own belief about what it requested, or
from the absence of an error. This closes the last path by which a UI could re-invent the belief
[ADR-0015](ADR-0015-observability-and-diagnostics.md) O-17 removed from the daemon.

### 11.10 User-facing flows

Specified as flows with states and failure branches. Layout is not specified; **refusal branches
are**, because every one of them is a real modal the user can decline.

#### (a) First run and onboarding

```
launch ─► what this is (and is not) ─► create TwinNet | join existing
       ─► identity generation (in secure storage, I4)
       ─► platform permission grant  ──refused──► PERMISSION_REFUSED (a state, not a dead end)
       ─► first pairing (b) | "this is your first device"
       ─► [create path only] Owner root ceremony (b)
```

The "what this is" screen states, in one sentence each, that TwinVPN connects the user's own
devices, that traffic exits from a device they own, and that it is **not** an anonymity service
([docs/vision.md](../vision.md) §3.1, §3.2). Setting that expectation before enrolment is a
product-honesty obligation, not marketing: a user who believes they bought anonymity has been
misled by omission.

**Permission grants and their refusal branches.**

| Platform | The modal | API | On refusal | Code surfaced |
|---|---|---|---|---|
| Android | VPN consent dialog | `VpnService.prepare()` | No tunnel is possible. Pairing, device list, settings, and diagnostics remain usable | `PLATFORM.VPN_PERMISSION_DENIED` |
| Android 13+ | Notification permission | `POST_NOTIFICATIONS` | The foreground-service notification cannot be posted, so the **anti-silence surface is gone**. The UI states plainly that TwinVPN will not be able to tell you when protection stops, and offers the settings path | *(reduced-visibility posture, stated in-app; [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) owns the service requirement)* |
| iOS / iPadOS | Install VPN configuration | `NEVPNManager.saveToPreferences` → system prompt + passcode/biometric | No tunnel is possible; the rest of the app remains usable | `PLATFORM.VPN_PERMISSION_DENIED` |
| macOS | System-extension approval | `OSSystemExtensionRequest` → System Settings, possibly a restart | No tunnel; detected asynchronously so approval later in the session completes the flow without restarting it | `PLATFORM.VPN_PERMISSION_DENIED` / `PLATFORM.ADAPTER_UNAVAILABLE` |
| Windows | UAC elevation for service and WinTun installation | installer / elevated helper | The unprivileged UI cannot self-elevate. It offers *Repair installation*, which re-runs the elevated helper. If the WFP sublayer cannot be registered, the product refuses to run unprotected | `PLATFORM.ADAPTER_UNAVAILABLE`; `NET.WFP_UNAVAILABLE` |
| Linux | polkit authentication for the privileged action | polkit agent | The UI names the polkit action id and the group / `CAP_NET_ADMIN` remediation, and points at the headless path | `PLATFORM.VPN_PERMISSION_DENIED` |
| OpenWrt / headless | *(none — no interactive session)* | `procd` service | Failure is a named startup condition on the CLI and in the status page | `PLATFORM.ADAPTER_UNAVAILABLE` |

**Normative onboarding rules.**

- **ONB-1.** A refusal is a **state**, never a dead end and never a loop. After any refusal the
  app remains usable for pairing, the device list, settings, and diagnostics, and shows a
  persistent affordance to grant the permission later.
- **ONB-2.** Every system permission prompt is preceded by a screen naming what is about to be
  asked and why. That screen MUST NOT be the only way forward in a way that blocks the app — a
  user may decline and continue.
- **ONB-3.** A system prompt is presented **at most once per launch**. Most platforms silently
  no-op a re-request after refusal, so a re-prompt loop shows the user *nothing happening*, which
  is the silent-failure defect in permission form. After the first refusal the UI switches
  permanently to the settings-deep-link affordance of LT-3.
- **ONB-4.** Onboarding MUST NOT ask for an account password and MUST NOT offer key backup,
  export, or escrow anywhere, ever (**I4**, **P4**, C-8). The help surface answers "how do I back
  up my key?" with: you do not — you enrol a replacement device and revoke the old one.
- **ONB-5.** Onboarding MUST NOT complete into a state where protection is claimed but the
  platform grant is missing. The projected status after a refusal is *Off*, with the refusal's
  three-part diagnostic attached.

#### (b) Pairing, enrolment, and the `Owner` root ceremony

Bound to [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4 and §7.5. The UI implements
that ceremony; it does not invent one.

**Roles.** The **joining** device generates `pairing_secret` and displays the offer; the
**approving** device holds an OSK with `ENROLL` power and approves. Authorization is the
approver's; channel authentication is the QR or the SPAKE2 run; confirmation is display-only.

| Ceremony | When the UI chooses it | UI specifics |
|---|---|---|
| **C-B, QR (primary)** | The joiner has a screen and the approver has a camera | The joiner displays the QR — never the reverse, because the joiner generated the secret. A visible 120 s countdown; the offer is not persisted, not screenshot-permitted where the platform allows suppression, and never on the clipboard. Expiry surfaces `AUTH.PAIRING_EXPIRED` with a *start again* action |
| **C-A, SPAKE2 (fallback)** | No camera-and-screen pair exists: headless joiner, router, TV, accessibility need | Nine digits, grouped 3-3-3, monospace, with a visible 120 s countdown. Per-attempt feedback carries `attempts_remaining` from evidence, because [ADR-0007](ADR-0007-device-identity-and-pairing.md) burns the code after five failed runs (`AUTH.PAIRING_ATTEMPTS_EXCEEDED`) |
| **C-C, SAS comparison — display only** | Always, after completion | Both ends display the peer label and the 20-character fingerprint as **recognition**: "You paired *NAS-Attic* — K7QD-2M9F-…". There MUST NOT be a "confirm the codes match" button that gates the ceremony. [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4 demoted C-C deliberately, and a confirmation gate that is not a security gate trains click-through on the ones that are |

**The `Owner` root-of-trust ceremony**, run once, on TwinNet creation:

1. The recovery phrase is displayed. Screenshot suppression is applied where the platform
   provides it (`FLAG_SECURE` on Android); **on iOS and iPadOS it cannot be suppressed** — the
   residual is stated to the user on that screen rather than left implied.
2. The phrase is excluded from platform backup, from keyboard and autofill caches, and from the
   clipboard by default; a copy action, where offered at all, warns first.
3. **N-12 verification is not skippable**: creation does not complete until three randomly chosen
   words are re-entered ([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.5,
   [docs/threat-model.md](../threat-model.md) §13).
4. Backgrounding the app mid-ceremony **abandons it and regenerates the phrase** on return. A
   half-recorded phrase is worse than none, because the user believes they have it.
5. **N-13**: while `n_osk == 1` the client shows a dismissible-but-**recurring** warning —
   recurring weekly and on every cold start after seven days — that losing this one admin device
   and its phrase destroys the TwinNet irrecoverably.

**OSK delegation and quorum.** Promoting a device to admin, revoking an admin device, or
publishing a new anchor requires one ORK signature **or** `k = min(2, n_osk)` independent OSK
signatures excluding the target's own. The UI therefore has a **pending multi-device operation**
state: "waiting for approval on *{device}*", with the requirement stated **before** the flow
starts, a visible list of which devices can satisfy it, and a cancel. Discovering at step six
that a second device is required is the failure mode this rule exists to prevent.

**How much ceremony a phone screen can carry — stated honestly.**

| Ceremony step | Phone | iPad / desktop | Headless |
|---|---|---|---|
| Scan a QR | Good — the camera is the best affordance the product has | Good | Impossible; use C-A |
| Display a QR | Good | Good | Impossible; use C-A |
| Enter 9 digits | Good | Good | Good (CLI) |
| Read and record a 24-word phrase | **Poor but necessary** — it is long, it must not be screenshotted, and it competes with every interruption a phone has. Mitigated by the abandon-on-background rule, not solved by it | Better | Good (CLI, one screen) |
| Verify three words | Adequate | Good | Good |
| Two-device quorum | **Needs a second screen by definition.** The UI says so up front | Same | Same |

#### (c) Device list and per-peer status

- A row carries: label, platform glyph, projected per-`Session` status, carriage qualifier,
  roles (`ExitNode` / `LANGateway`), trust-freshness badge, last **validated** time, and — when
  non-nominal — the coalesced three-part diagnostic.
- **Ordering is worst-status-first, then label.** Never last-seen alone, which hides a failing
  device below the fold.
- **Presence is a hint, never a gate.** S-11 is `EVENTUAL` and
  [docs/architecture.md](../architecture.md) states a "peer offline" record MUST NOT suppress a
  connection attempt. The UI therefore renders *"Not seen recently"*, never *"Offline"*, and MUST
  NOT disable the connect affordance on presence.
- Per-peer detail exposes the **full twelve-name** `ConnectionState` in a technical row (this is
  the one surface where the vocabulary is not collapsed), the active path class, relay and region
  when `RELAYED`, measured RTT, byte counters, and a link to that `Session`'s candidate ledger.
- **I7 in the UI:** a peer acting as a gateway shows the number of peers it is serving. No row,
  count, or copy may assume one client.

#### (d) Revoking a lost or stolen device

Bound to **R-24**, [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.7, and
[docs/threat-model.md](../threat-model.md) §13, whose runbook this flow implements step for step.

| Step | UI |
|---|---|
| 1 | Ask whether the device was **locked** when it was lost. The answer changes the exposure ([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.8) and therefore changes what the user is told. It is an information control, not a security control, and the UI says so |
| 2 | **Quorum pre-check.** If the target holds `ENROLL` or `DELEGATE`, this is a high-power operation needing ORK or `k = min(2, n_osk)` excluding the target's own OSK. State the requirement **before** starting. If it cannot be met, say exactly what is required and offer **no** lesser action that looks equivalent |
| 3 | Confirm against the device **label and fingerprint**, with the irreversibility stated: revocation cannot be undone, and the device must be re-enrolled to return |
| 4 | **Propagation and the residual window — mandatory disclosure** (below) |
| 5 | If the lost device was `hardware_backed = false`, state that the identity must be assumed **cloned** ([docs/threat-model.md](../threat-model.md) §13 step 6) and that TwinVPN will watch for `AUTH.IDENTITY_CONCURRENT_USE` |
| 6 | Offer re-enrolment of a replacement carrying the label and role |

**RV-1 (normative).** After revocation the UI MUST show, **on the result surface and not behind a
"learn more"**:

- propagation status per peer — *reached via the coordination service*, *reached via another
  device*, *not yet reached* — with counts, because the bound differs by path (p95 ≤ 30 s / ≤ 120 s,
  [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.7);
- the residual window in plain language: a device partitioned from **both** the coordination
  service and every updated peer keeps accepting the revoked device **at baseline only**, for as
  long as that partition lasts — **unbounded in time, bounded in consequence**;
- what "baseline" concretely means: the revoked device can *reach* that peer, and can obtain no
  exit egress, no LAN access, no accepted route, and no new pairing;
- the `T_TRUST_HARD` value in force (default 30 days, `Owner`-configurable within 24 h–90 d) and
  where to change it.

**R-24 requires the residual window to be "stated rather than implied", and a disclosure the user
must go looking for is implied.** That sentence is the whole reason RV-1 forbids progressive
disclosure here.

**RV-2.** Revocation MUST NOT be reachable from a swipe-to-delete gesture or any other affordance
whose idiom implies reversibility, and the result surface MUST NOT offer an undo.

#### (e) Exit node, LAN gateway, and route-acceptance consent

Two decisions with different authorities, and the UI must not blur them.

**Offering** (this device acts as `ExitNode` or `LANGateway`) is a local choice. The consequence
is stated before the toggle commits: other devices' traffic will egress from **this** device's IP
address and be attributed to this connection
([docs/threat-model.md](../threat-model.md) §14.1); these subnets become reachable; this many
peers may use it concurrently (**I7**).

**Using** (routing through a peer) is **route acceptance**, and
[docs/threat-model.md](../threat-model.md) §7 is explicit that this is an **authorization
decision** — one compromised device advertising `0.0.0.0/0` and `::/0` captures the whole
TwinNet's traffic if acceptance is automatic.

- **RC-1.** The consent surface names: the advertising device's **label and fingerprint**; the
  exact prefixes with address family; the port and protocol scope; whether it overlaps an already
  accepted prefix or a local on-link network; and — in plain language, not as a prefix — when it
  is a default route: *"all of this device's internet traffic will go through {peer_label}"*. It
  states that this is a permission being granted, not a preference being set.
- **RC-2.** A default route, or any prefix covering a local on-link network, requires a
  **distinct, higher-friction confirmation** and MUST NOT be grantable by a single tap.
- **RC-3.** Route consent MUST NOT be actionable from a notification or a lock screen. It is a
  local, in-app, authenticated-session decision.
- **RC-4.** **The shipped default is that no prefix is accepted without an explicit `Owner`
  grant.** Absent grants are denials (TM-A3). A conflict surfaces `ROUTE.PREFIX_CONFLICT` and is
  **never** silently resolved (R-17).
- **RC-5.** Accepted routes are a **standing, auditable list** with advertiser, prefix, family,
  and grant time (**S-50**), revocable from the same surface. A one-time dialog with no audit
  surface means the user cannot answer "what did I agree to?".
- **RC-6.** Exit engagement is a grant the **gateway** holds with a TTL (S-36) and the client's
  view of policy is advisory. The UI therefore renders exit status from the gateway's confirmed
  grant, never from local intent; when a grant lapses it says *exit access ended* with
  `POLICY.GATEWAY.EXIT_NOT_ENGAGED` and never silently reverts to the local default route.
- **RC-7.** Per-family status is always shown, both families side by side. A v4-only grant with
  v6 blocked renders `POLICY.LEAK.IPV6_UNPROTECTED` rather than hiding the asymmetry (**P9**).

#### (f) Kill-switch posture and disarm

**Posture display.** Mode (`OFF` / `ARMED_ON_INTENT` / `ALWAYS_ON`) plus the **effective** mode,
which is `max(local, policy_required)` ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)
KS-22). When the effective mode exceeds the local one the UI says **why** — a policy raised it —
and that the local control cannot lower it. The protection indicator itself comes only from the
`ProtectionAssertion` (§11.9(5)). On Android the platform-native expression is always-on plus
"block connections without VPN" ([docs/networking.md](../networking.md) §5.4): the UI **detects
and reports** whether it is enabled and links to the settings page; it MUST NOT claim to have
enabled it itself. Where no pre-network boot rule set is possible, the UI names the window with
`POLICY.KILLSWITCH.BOOT_ENFORCEMENT_UNAVAILABLE` rather than implying continuous coverage.

**Disarm.** [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-21 requires a local
interactive action, OS-mediated authentication of an `Owner`/administrator principal, and a
confirmation naming the consequence. **The UI is a requester, never the authority.** Its
obligations:

- **KD-1.** The confirmation names the consequence in part-2 terms — *"traffic will leave this
  device untunneled"* — never a bare "Are you sure?".
- **KD-2.** The destructive action is **not** the default focus and **not** the default button.
- **KD-3.** The OS authentication is the platform's: polkit on Linux, UAC elevation on Windows,
  Authorization Services on macOS, the Settings always-on toggle on Android, **VPN-profile
  removal on iOS**. On iOS the disarm happens *outside the app*; the UI describes it accurately
  and MUST NOT present an in-app toggle that appears to perform it.
- **KD-4.** Afterwards, `PERMISSIVE_ANNOUNCED` is indicated **persistently in every surface** —
  window, tray, menu-bar, notification — carrying
  `POLICY.KILLSWITCH.DISARMED_BY_OWNER`. This is the announced form of the one case where
  protected traffic may leave unprotected, and it is not dismissible into invisibility (PC-5).
- **KD-5.** There is no remote disarm path and no wire message that means "disarm". An attempt by
  a non-local actor surfaces `POLICY.KILLSWITCH.DISARM_REFUSED_REMOTE` at `CRITICAL`, presented
  as a **security event** that does not auto-dismiss.

#### (g) Diagnostics: the connectivity report and the redaction preview

**One affordance.** *Connectivity report* produces
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.8's eight-part report. It runs
**offline**, with no "enable logging first" step, because Tier 0 has already captured it.

**Rendering order — verdict first**, then environment, then both address families **side by side
and always both** (O-09), then DNS, then the candidate ledger, then the transport ladder, then
relays, then the enforcement snapshot. The user in trouble needs the verdict; support needs the
evidence; putting the evidence first serves neither. The candidate ledger renders **every**
candidate including the losers, with family, type, elapsed time, and per-candidate `reason_code`
— that ledger is the R-23 payload.

**The redaction preview (O-10, [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.9(3)).**
Sharing is a separate, explicit act, and the user must be able to see what they are about to
share.

- **DX-1.** The preview renders through the **same redaction path** the export uses. There is no
  second renderer, because a second renderer could lie.
- **DX-2.** The preview shows the artifact **as it will be shared**: `SENSITIVE` fields already in
  their pseudonymized form (`ipv4-A:port-1`, `peer-2`, `iface-1`), field by field, each labelled
  with its classification.
- **DX-3.** The share affordance is **unreachable** without passing through the preview.
- **DX-4.** `SECRET` fields are absent by construction and the preview shows **nothing** for them
  — not even a `[REDACTED]` row, which would imply the data was collected and withheld. The
  privacy surface states the never-collected column of
  [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.10 instead.
- **DX-5.** The artifact's signature and expiry are stated on the preview, and the user is told
  that pseudonyms differ across bundles so two bundles cannot be correlated.
- **DX-6.** There is **no support-initiated pull**. No remote actor can cause a report to be
  generated or transmitted, and the UI offers no path that would create one.

**Export targets.** iOS/iPadOS: `.fileExporter` into Files, plus the share sheet. Android: SAF
`ACTION_CREATE_DOCUMENT`. Windows / macOS / Linux: the platform file dialog. Headless: a path
printed on stdout ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)).

**Verbose capture.** `DEBUG` and `TRACE` are off, user-enablable, and auto-expiring
([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.5). While one is live the UI shows a
**persistent, countdown-bearing** indication, and it reverts without user action; a verbose
capture the user forgot about is a privacy defect.

#### (h) Basic and advanced presentation modes

The corpus has, until now, specified *what* every surface must show and left *how much* to the
implementer. That is the gap this subsection closes. Two modes exist; they are a **presentation**
control and nothing else.

> **Rule BA-1 (normative).** Mode changes what is **displayed**. It MUST NOT change what is
> enforced, what is authoritative, what is recorded, or what is available as an action. There is
> one state model (§11.2) and one projection (§11.3); a mode is a filter over the rendering of
> that projection, never a second projection.

- **BA-2 — Basic is the default**, on every graphical target, on first run and after any reset.
  A user who never opens settings never sees an unexplained internal name.
- **BA-3 — Advanced is additive only.** It adds detail; it removes nothing and it re-labels
  nothing. A user switching Basic → Advanced sees a superset, so a support instruction given for
  one mode is valid in the other.
- **BA-4 — The floor is the same in both modes.** The following are **not** advanced-only, and a
  mode MUST NOT hide, collapse, or defer any of them behind a disclosure control:

  | Always shown in both modes | Why |
  |---|---|
  | The projected status and its carriage qualifier (§11.3) | It is the answer to "is my traffic flowing" |
  | The **Protection** badge, including `Unprotected — announced` and `Unknown` | §11.9(5); it is a security signal, and A11Y-1 already forbids encoding it in colour alone |
  | The **three parts** of every active `Diagnostic` at `ERROR` and above (§11.4) | **I6**, R-33, P18. The three parts *are* the plain-language layer; hiding them leaves only the code |
  | `PERMISSIVE_ANNOUNCED` and `POLICY.KILLSWITCH.DISARMED_BY_OWNER` | **KD-4** requires it persistently in every surface and not dismissible into invisibility (PC-5) |
  | Kill-switch mode, effective mode, and the reason the effective mode exceeds the local one | §11.10(f) |
  | The revocation result surface of **RV-1** in full | R-24 requires the residual window *stated rather than implied*, and **RV-1 already forbids progressive disclosure there** — a Basic mode that abbreviated it would reintroduce exactly what RV-1 removed (T-7) |
  | Route-acceptance consent under **RC-1/RC-2**, including the plain-language default-route sentence | It is an authorization decision, not a preference |
  | Both address families, side by side, whenever they disagree (**RC-7**, O-09) | Hiding the asymmetry is the `POLICY.LEAK.IPV6_UNPROTECTED` defect wearing a settings toggle |

- **BA-5 — What Advanced adds.** The full twelve-name `ConnectionState` (the technical row of
  §11.10(c)); the active path class, relay identity and region, measured RTT and byte counters;
  the per-`Session` candidate ledger; the raw `reason_code` string alongside its three parts; the
  enforcement `ruleset_digest` and `EnforcementRecord`; `schema_version`, `custody_class` and
  `store_state`; `vm_seq` and replica freshness. Every one of these is already published on the
  [ADR-0017](ADR-0017-local-management-interface.md) contract — **Advanced introduces no new
  read**, which is what keeps it a presentation mode.
- **BA-6 — No action is mode-gated.** Every operation reachable in Advanced is reachable in
  Basic, on the same surface, with the same authority. **HP-1** already forbids a UI capability
  outside the management contract; BA-6 is its intra-UI form, and it is asserted the same way —
  the §11.13 P18 runner drives the operation matrix in both modes and a mode-conditional
  affordance fails the build. A mode that hid the disarm, revocation, or route-consent path would
  make Basic a *reduced-authority* product, which it is not.
- **BA-7 — Mode is local, durable, and per-install.** It is an `S-24` user preference, `LOCAL`,
  never synchronized to peers and never carried in any `Diagnostic`, support bundle or
  connectivity report — a support artifact must not vary by the reporter's display preference
  (DX-2's field-by-field rendering is mode-independent).
- **BA-8 — Headless has no modes.** The CLI renders the Advanced content set by default and the
  same three parts from the same resolver (**HP-3**); `--json` is unaffected by, and does not
  expose, any mode. There is no `--basic`.

**Testing.** P18 (§11.13) renders every catalogue entry, and every unknown-code fallback, in
**both modes** across its locale and `platform_ctx` matrix; a string present in one mode and
absent in the other for the same `Diagnostic` is a defect, as is any BA-4 row rendering
differently between them. This costs no device farm, for the reason §11.13 already gives.

### 11.11 Accessibility

**Conformance target: WCAG 2.2 Level AA** for every graphical surface, plus the platform
accessibility API contract — UIAccessibility/VoiceOver (iOS, iPadOS, macOS), Android
accessibility services/TalkBack, UI Automation/Narrator (Windows), AT-SPI2/Orca (Linux). The
target is named so it is testable, and conformance is a **release gate**, not a backlog item.

| # | Rule | How it is tested |
|---|---|---|
| **A11Y-1** | The connection and protection indicators MUST encode state in **at least two** of {glyph/shape, text label, position} and MUST be legible in greyscale. Colour alone is prohibited — this is a **security signal**, it fails for a large minority of users, and the platform itself removes the colour (a macOS menu-bar template image is monochrome by design) | Automated: greyscale renders of all seven projected statuses are pairwise distinguishable by image diff, and each carries a non-empty text label. P18 oracle 5 |
| **A11Y-2** | Asynchronous status changes are announced through a live region: **polite** by default; **assertive** for `BLOCKED`, `POLICY`-class, and `CRITICAL`. No more than one assertive announcement per 5 s, coalesced per PC-6. Transitions **into** a healthy state are polite. Raw codes are never announced | Screen-reader script per platform per release; announcement politeness asserted from the accessibility tree |
| **A11Y-3** | The three parts are **one** accessible unit, read in order, with part 3 also serving as the accessible action's label | Accessibility-tree assertion |
| **A11Y-4** | Full platform dynamic-type range including accessibility sizes; at 200 % text scaling (WCAG 1.4.4) and at reflow width (1.4.10) **no diagnostic text is truncated or clipped**. If content must be dropped, the peer list is dropped before the diagnostic | Pseudo-locale (LT-9) at maximum type size, screenshot-diff gate |
| **A11Y-5** | 4.5:1 text contrast, 3:1 non-text and UI-component contrast (1.4.11), in light, dark, and forced-colours/high-contrast modes. High contrast MUST NOT flatten the state indicator into one colour — which is why A11Y-1 exists | Automated contrast audit per theme |
| **A11Y-6** | Reduced-motion honoured. Progress MUST NOT be conveyed by animation alone: a spinner is never the only indication of *Connecting* | Setting toggled in the automated suite |
| **A11Y-7** | Every action keyboard-reachable and keyboard-operable, with a visible focus indicator meeting 2.4.11/2.4.13, no keyboard trap, and a logical order. Applies to iPadOS with a hardware keyboard | Keyboard-only traversal of every flow in §11.10 |
| **A11Y-8** | Target size ≥ 24×24 CSS px (2.5.8); ≥ 44×44 pt on touch platforms per the platform HIG | Static layout assertion |
| **A11Y-9** | Fingerprints, pairing codes, and addresses are grouped, selectable text — never image-only — and their accessible reading spells characters **in groups**. A screen reader pronouncing "K7QD2M9F" as a word defeats the verification the string exists for | Screen-reader script |
| **A11Y-10** | No accessibility affordance may complete an OS-mediated authority action on the user's behalf. The disarm lives outside the app precisely so that an accessibility service cannot silently satisfy it (C-9, KD-3) | Design consequence; asserted by the absence of an in-app disarm intent |

### 11.12 Headless parity (R-21, R-36)

- **HP-1.** **No UI capability may exist that the [ADR-0017](ADR-0017-local-management-interface.md) management contract does not expose.**
  Every UI action is an operation of that contract; there is no privileged side channel (**H3**).
  Enforced at build time: the UI binary links only the management-client library, and a link-time
  symbol assertion fails the build if it references any other IPC, privileged, or platform-
  administration entry point.
- **HP-2.** **The parity gate.** [ADR-0017](ADR-0017-local-management-interface.md) publishes its operation set as a machine-readable
  artifact. CI generates a matrix of {operation} × {invoked by a GUI surface, invoked by the CLI}
  from static call analysis; **an operation invoked by a GUI and by no CLI command fails the
  build.** This is what converts R-21's "same control contract as the GUI" from an aspiration
  into a mechanical property.
- **HP-3.** **Text parity.** The CLI renders the **same three parts** from the **same resolver**
  (§11.1). A rendered difference between GUI and CLI for one `Diagnostic` in one locale is a
  defect (P18 oracle 6). The CLI additionally offers `--json`, emitting the raw `Diagnostic`
  including `reason_code` and evidence, so scripts never parse rendered text (LT-8).
- **HP-4.** **Parity is not privilege.** OS-mediated authority actions (disarm) are *requests* in
  the contract and *authorizations* at the OS. Parity means the CLI can make the same request; it
  does not mean the CLI can bypass polkit (KS-21).
- **HP-5.** [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) owns the headless profile. This ADR's requirement on it is stated as an
  interface in §11.14.

### 11.13 Proof test P18

**P18 — Every failure the user sees is named, explained, and actionable.**

| | |
|---|---|
| **Proves** | **I6** (both halves), **R-22**, **R-33**, **R-35** (oracle 5), **R-36** (oracle 6); [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 rule 5 |
| **Lab scenario** | Not a network scenario. A **presentation harness** drives each shipped surface through the [ADR-0017](ADR-0017-local-management-interface.md) contract with synthetic view-model snapshots and `Diagnostic` records |
| **Preconditions (V3)** | The machine-readable `reason_code` registry artifact for the build under test; the catalogue artifact for every shipped locale; a built surface for each of the six GUI targets plus the CLI; the pseudo-locale of LT-9. **No device farm is required**: because `platform_ctx` is a parameter (§11.1), every platform's variants are rendered from one runner |
| **Assumptions** | H1, H3, and [ADR-0017](ADR-0017-local-management-interface.md) interface 3 (attributes delivered with unknown codes) |

**Procedure.**

1. Enumerate every `ACTIVE` code in the registry artifact.
2. For each code, for each shipped locale, for each `(state_to, traffic disposition, enforcement
   mode)` combination the registry declares reachable for it, inject a synthetic `Diagnostic`
   with each declared evidence field populated, and capture the **rendered output** of every
   surface (not the model — the rendered accessibility tree and the rendered text).
3. Repeat step 2 for **every `platform_ctx` value** the product ships — each platform crossed with
   each declared OS-version range — and once more with an **empty** `platform_ctx`.
4. Inject a synthetic **unknown** code per domain (an identifier absent from the registry), plus
   one with an entirely unrecognized `DOMAIN`, in every locale.
5. Repeat the whole run in the pseudo-locale at the maximum supported text size.
6. Capture greyscale renders of the status indicator for all seven projected statuses.
7. Simulate a dismissal of every rendered item and re-capture.

**Oracle.** For every rendered item:

1. **Three non-empty parts** are produced. Where `user_actionable == false`, part 3 is the
   `remediation_class` sentence — the field is never empty.
2. No rendered part contains the raw `reason_code`, a bare integer, an OS errno, or an i18n key.
3. Part 2 equals the disposition-class sentence for the injected
   `(state_to, disposition, enforcement mode)`, asserted against the §11.4 table — **not** against
   any per-code string.
4. For an unknown code: part 1 equals that `DOMAIN`'s fallback (or the neutral entry for an
   unrecognized domain); parts 2 and 3 are still produced; the raw code appears **exactly once**,
   in the secondary technical line.
5. Greyscale renders of the seven statuses are pairwise distinguishable and each carries a
   non-empty text label.
6. The CLI's three parts are **byte-identical** to the GUI's for the same input and locale.
7. In the pseudo-locale run, **no unmarked Latin-script string** appears in any rendered surface,
   and no diagnostic text is clipped or truncated.
8. Every `POLICY`-class or `CRITICAL` item is still present after the simulated dismissal.
9. With an **empty** `platform_ctx`, part 3 is the **neutral** variant, is non-empty, and is not
   equal to any host-platform variant — the LT-3b/LT-3c assertion. Every code carrying a
   `next_action` has a neutral variant in every shipped locale.

**Mutants (V2).** Each is a buildable patch that MUST fail:

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P18-1` | Catalogue miss falls back to the raw code string | Oracles 2, 4 |
| `M-P18-2` | Part 2 sourced from a per-code string instead of the disposition table | Oracle 3, on any code injected in a non-default state |
| `M-P18-3` | Unknown code renders "Unknown error" | Oracle 4 |
| `M-P18-4` | Status indicator distinguished by colour only | Oracle 5 |
| `M-P18-5` | One view-layer literal added — "Connection failed" | Oracle 7 |
| `M-P18-6` | CLI given its own text table | Oracle 6 |
| `M-P18-7` | `user_actionable == false` renders an empty part 3 | Oracle 1 |
| `M-P18-8` | `POLICY`-class items become dismissible to invisible | Oracle 8 |
| `M-P18-9` | Empty `platform_ctx` falls back to the host's platform | Oracle 9 — the run on a Linux runner returns the Linux variant where the neutral one is required |
| `M-P18-10` | One code's neutral variant deleted from the catalogue | Oracle 9's completeness clause; part 3 comes back empty, which oracle 1 also catches |

**Positive control (V4).** The same harness, one known code, one locale, an unmodified build,
must pass all eight — proving the harness observes success. Additionally a build with an
**empty catalogue** must fail every oracle, proving the harness reads rendered output rather than
the model.

**Pass criteria.** 100 % of `ACTIVE` codes × shipped locales × declared state combinations
produce a conforming rendering on **every** surface; the unknown-code set conforms in every
locale; all eight mutants fail with the expected oracle.

**Known limits.** P18 proves the text is present, structured, correctly sourced, and
forward-compatible. It **cannot** prove the text is good. Comprehension is measured by usability
testing, which is not a build gate and is not claimed as one. P18 also cannot prove a code's
*classification* is right; a code registered with the wrong `class` produces a conforming
rendering of a wrong thing, and that is the owning ADR's problem, not this test's.

### 11.14 Interfaces required from other ADRs

| # | From | Interface required |
|---|---|---|
| **X1** | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) (H2) | The UI process is unprivileged; its death, kill, or crash MUST NOT affect enforcement, `Session`s, or the state machine. A liveness signal the UI can use to distinguish "daemon not running" from "management channel lost" |
| **X2** | [ADR-0017](ADR-0017-local-management-interface.md) (H3) | (1) A **view-model-shaped** subscription — snapshot plus ordered patches, each carrying `vm_seq` and a monotonic `as_of` — not a raw Tier-0 ledger tail (§9). (2) An operation set published as a machine-readable artifact, for the HP-2 parity gate. (3) `Diagnostic` delivered **whole**, including `class`, `severity`, `user_actionable`, `remediation_class`, `scope`, and declared evidence, **even for codes the UI does not recognize** — PC-2 rule 6 depends on this and it is the single most load-bearing interface in this ADR. **Discharged**: the failure payload is `{reason_code, evidence, resolved}` and the `resolved` block is present for **every** code, recognized or not, so PC-2 keeps its strong form and an unknown `POLICY`-class `CRITICAL` condition stays non-dismissible under PC-5. (4) Payloads carry **codes and evidence, never rendered text**, so one daemon serves surfaces in different locales. **Discharged normatively**: every field of `resolved` is an enum, a boolean, or a stable anchor — none localized, none a sentence — and adding a `summary`, `message`, or `title` field to it is forbidden, which is what makes mutant `M-P18-2` permanently meaningful rather than merely currently true. (5) Intent submission accepting an [ADR-0008](ADR-0008-idempotency.md) idempotency key, with a pending→confirmed receipt so UI-3's no-optimistic-apply rule is implementable. (6) The current `ProtectionAssertion` with its freshness deadline |
| **X3** | [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) (H1) | (1) The projection of §11.3 and the resolution half of §11.4–§11.6 live in the core behind the C ABI — **accepted**, as ADR-0018 CB-4's core-resolves/shell-presents split. (2) `tw_render_diagnostic` is **pure and instance-free** — no I/O, no ambient clock, no ambient locale — so P18 can drive it exhaustively; **granted as F-10**, ADR-0018 F-1's one exception. (3) The catalogue ships as an embedded build artifact with defined string ownership across the ABI. (4) The core exposes the registry version it was built against — **discharged** by `tw_reason_registry_version()` and the `reason_registry_version` field of ADR-0018's S-46. (5) A core fault MUST NOT abort the UI process — **discharged three times, and the Android discharge was CORRECTED on 2026-08-30**: on Windows, macOS and Linux the UI process does not load the core at all, so the fault is in another process; on iOS/iPadOS, where the app hosts a core-lite instance, ADR-0018 F-7's `catch_unwind` and poison contain it and emit `INTERNAL.CORE_PANIC`; on **Android** the containment is `twinvpn-platform-android`'s `bridge::entry`, where no entry point throws into the JVM. **Android was previously listed with the desktops, and that was false.** `shells/android/app/src/main/AndroidManifest.xml` sets no `android:process`, so `MainActivity` and `TwinVpnService` share one process and the UI process *does* load the core — the claim held for the three desktop daemons and was extended to Android without checking. It was falsified by execution rather than by review: the Android shell had never run until run 33298081071 booted an emulator for the first time, and a registered refusal (`PLATFORM.ADAPTER_UNAVAILABLE`) thrown from `nativeOnNetwork` on `ConnectivityThread` killed PID 3277, taking the Activity with it. AOSP admits no survivable path — `ConnectivityManager$CallbackHandler.handleMessage` has no `try`/`catch`, `Looper.loop` rethrows, and `RuntimeInit`'s `KillApplicationHandler` ends in `Process.killProcess` inside a `finally`. Note F-7 does **not** cover this: it contains *panics*, and this was a typed refusal on the ordinary path. All five `bridge::entry` entry points are platform callbacks, so the rule is the file's and not one entry's, and `bridge::tests::no_bridge_entry_point_throws_into_the_jvm` holds it per entry by name. (6) The render call carries a **`platform_ctx` parameter** for LT-3's variant selection — **accepted**, on the stronger basis that ADR-0018 CB-2 forbids a shell holding a decision and "which next-action variant applies at this OS version" is a decision. The reciprocal obligation on this ADR is LT-3b/LT-3c: an empty `platform_ctx` resolves to the neutral variant and never to the host's platform, and every code with a `next_action` carries a neutral variant, CI-checked per locale (ADR-0018 §11.16(n)) |
| **X4** | [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md) | Durable storage for **S-50** (route-consent records) with the property that no non-local writer exists, and for **S-51** (UI preferences), separated so that a preference reset cannot clear a consent record |
| **X5** | [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) | The catalogue is signed and shipped with the build; catalogue-only updates MUST be possible without a registry bump (§10). The macOS distribution channel determines the achievable enforcement posture, and the UI MUST be able to query which posture the shipped build can deliver so §11.8 can refuse to over-claim |
| **X6** | [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) | Foreground/background/resume transitions delivered to the UI as events, so §11.9(4)'s unconditional invalidation has a trigger. The Android foreground-service notification is a **UI surface** governed by §11.9 and PC-7, not free-form service chrome |
| **X7** | [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) | The headless profile MUST consume the **same** presentation resolver and the **same** operation set (HP-3, HP-5). It MAY ship one locale plus `DOMAIN` fallbacks. The LuCI status page is a read-only subscriber that submits no intents |
| **X8** | [ADR-0015](ADR-0015-observability-and-diagnostics.md) | The registry artifact MUST declare, per code, the `(state_to, disposition)` combinations it is reachable in — P18 step 2 needs it. This is an addition to the registry's attribute set, requested here |
| **X9** | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) | Confirmation that the effective mode (`max(local, policy_required)`) and the reason a policy raised it are both readable over [ADR-0017](ADR-0017-local-management-interface.md), so KD's "say why" obligation is satisfiable |

### 11.15 State ownership

New rows for [docs/architecture.md](../architecture.md) §5, in its seven-column format.

| # | State | Authoritative writer | Replicas / caches (staleness tolerance) | Consistency class | Durability | On conflict |
|---|---|---|---|---|---|---|
| **S-48** | `ClientViewModel` — the UI-facing projection of daemon state (projected aggregate + per-`Session` rows, active `Diagnostic` set, `ProtectionAssertion` snapshot, trust freshness) | **The local daemon's view-model projector** ([ADR-0016](ADR-0016-client-process-and-privilege-separation.md), using the [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) core) | Every UI surface, window/scene, tray or menu-bar item, notification renderer, CLI invocation, and router status page holds a **read-only** replica. Tolerance: renders normally below `T_VM_STALE` (5 s), stale-form to `T_VM_UNKNOWN` (15 s), `UNKNOWN` beyond | `MONOTONIC` by `vm_seq` — a replica never renders backwards | **Non-durable by requirement.** MUST NOT be persisted and re-rendered as current at next launch (UI-6) | A `vm_seq` gap, an out-of-order patch, or a stream reconnect **discards** the replica and forces a full resnapshot; replicas are never merged. A patch with `vm_seq` ≤ the local high-water is dropped |
| **S-49** | Presentation binding in force for rendering — the resolved (locale, platform, OS version, catalogue version, registry version) tuple | **The shared core's presentation resolver** ([ADR-0018](ADR-0018-shared-core-and-build-architecture.md)), at process start and on OS locale change | None — every surface calls the resolver rather than caching text | `LOCAL` | Derived; re-resolved at launch and on locale change | The resolver is the only source of user-facing text. A surface rendering text it did not obtain from the resolver is a defect (P18 oracle 7) |
| **S-50** | `RouteConsentRecord` — per (advertiser `device_id`, prefix, family) the `Owner`'s explicit route-acceptance decision, its timestamp, the acting surface, and its revocation | **The local `Device`**, written **only** on an authenticated local `Owner` action submitted through [ADR-0017](ADR-0017-local-management-interface.md) | **None.** Never replicated to the control plane, never synced: a remote writer could grant a route to itself ([docs/threat-model.md](../threat-model.md) §7) | `LOCAL` | Durable on device; survives process death, update, and reboot | Absence is denial (TM-A3). A record MUST NOT be created by any non-local path. A prefix conflicting with an existing accepted prefix or an on-link network surfaces `ROUTE.PREFIX_CONFLICT` and MUST NOT be auto-resolved (R-17) |
| **S-51** | UI-local presentation preferences — theme, surface layout, column set, notification verbosity, dismissed-banner state, last-selected peer | **The UI surface** on that device | None; explicitly **not** synced — an `Owner`-scoped settings sync would give a settings document two writers (**I8**) | `LOCAL` | Durable locally, per surface | No conflict is possible. Normative limit: a preference MUST NOT suppress a `POLICY`-class or `CRITICAL` diagnostic (PC-5), which keeps S-51 out of the safety path |

### 11.16 Assumptions register

| # | Assumption | Depends on | If it is wrong, this changes |
|---|---|---|---|
| **AS-1** (**H1**) | One portable core in a memory-safe systems language behind a stable C ABI holds the engine, the state machine, and — per this ADR — the projection and the presentation resolver | [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) | §11.1 collapses. Without a shared core, the resolver must be duplicated per platform or extracted into a separate shared library; R-36 text parity (HP-3) and P18 oracle 6 become far harder, and Alternative A's drift risk returns |
| **AS-2** (**H2**) | Desktop/server clients are a privileged daemon plus a separate unprivileged UI process; on iOS/iPadOS/Android the OS-hosted extension or service is the daemon | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) | If the UI were privileged, C-1 and S-1 fail and the kill-switch authority argument in §11.10(f) has to be rebuilt. If there were no separate process at all, S-48's single writer disappears and the UI becomes an authority — an **I8** and **I3** break |
| **AS-3** (**H3**) | UI, CLI, and local automation reach the daemon over **one** authenticated, schema-versioned local management interface with an event stream, and the GUI has no privileged side channel | [ADR-0017](ADR-0017-local-management-interface.md) | HP-1 and HP-2 are unenforceable and R-36 becomes aspirational. If the contract cannot carry `Diagnostic` attributes for unknown codes (X2.3), PC-2 rule 6 fails and forward compatibility degrades from "correct affordance" to "generic text" |
| **AS-4** | The management contract offers a view-model-shaped subscription rather than a raw ledger tail | [ADR-0017](ADR-0017-local-management-interface.md) | §9's event-rate budget is unmet on mobile; the UI must do its own projection and coalescing, moving logic out of the core and weakening AS-1 |
| **AS-5** | Durable local storage exists for S-50 and S-51 with no remote writer, and the two are separable | [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md) | RC-5's auditable grant list cannot be durable, and RC-4's "absent grants are denials" becomes a runtime-only property that a preference reset could weaken |
| **AS-6** | Catalogue-only updates ship without a registry bump, and the shipped build's achievable enforcement posture is queryable | [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) | §10's independent-versioning claim fails and translation fixes become contract changes. On macOS the UI could over-claim a posture the App Store build cannot deliver |
| **AS-7** | Foreground/background/resume transitions are delivered to the UI as events, and the Android foreground-service notification is available as a UI surface | [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) | §11.9(4) loses its trigger and must fall back to polling, which contradicts §9's battery argument. Without the FGS notification, Android has no anti-silence surface while backgrounded |
| **AS-8** | The headless profile consumes the same resolver and operation set | [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) | HP-3 and P18 oracle 6 fail; the CLI drifts into its own vocabulary, which is exactly the R-21 defect |
| **AS-9** | The `reason_code` registry can declare, per code, the `(state_to, disposition)` combinations it is reachable in | [ADR-0015](ADR-0015-observability-and-diagnostics.md) (X8) | P18 step 2 must enumerate the full cross-product instead, which is larger but still finite — the test survives, at higher cost and with weaker relevance |
| **AS-10** | Timers, clocks, and randomness are injectable at component boundaries | [docs/architecture.md](../architecture.md) A-21 | The freshness gate (UI-4) cannot be driven deterministically and R-34 becomes untestable |

---

## 12. Why the Selected Option Won

**Against A (fully native, no shared view-model)** — the runner-up, and the option most teams
default to. A gets platform idiom and accessibility exactly right, which is why D keeps its view
layer verbatim. What A cannot do is keep six surfaces plus a CLI saying the same thing. The
projection in §11.3 contains four judgement calls (relay is not a warning, migrating is not a
disconnect, degraded is not connected, trust staleness is not a status) and A requires all six
teams to get all four right, forever, including for codes none of them has seen. R-36's text
parity is not merely hard under A — it is not a property A can have, because there is no shared
text. D pays one FFI surface to make it structural.

**Against B (one cross-platform toolkit)** — B solves the drift problem the same way D does, and
loses on the axis a security product cannot afford to lose on. Accessibility becomes the
toolkit's rather than the platform's, and on Windows and Linux that is a measurable downgrade
against the WCAG 2.2 AA target R-35 sets. Binary size grows by tens of megabytes on a product
whose router tier has 128 MB of RAM and whose mobile tier already carries an extension. And B
still needs the core for H1, so it pays D's FFI cost *and* a runtime cost.

**Against C (web shell)** — C is the wrong answer for this product specifically. A bundled
browser is a continuous CVE obligation on the update channel of a VPN client; a system webview is
six different renderers with six accessibility stories. Content-security discipline would become
a security-critical property of the UI of a product whose entire pitch is that its security
properties are structural. The one thing C is genuinely best at — rendering the long structured
connectivity report — is worth a webview *for that one surface* on desktop if it ever proves
necessary, and nothing in D forecloses that.

**Against E (headless-first)** — E fails the product. Two of [docs/vision.md](../vision.md) §2's
five personas are not CLI users, [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4's
primary ceremony needs a camera and a screen, and R-22's human-actionable text and R-23's report
need somewhere to be read. E survives as the **router and headless tier** of D, which is where it
is right.

**The decisive property.** D is the only alternative in which the sentence a user reads is
produced in one place, from one catalogue, by one pure function, for six GUIs and a CLI — which
makes I6's second half a testable property (P18) rather than a convention. Every other
alternative makes it a convention, and conventions are exactly what produced "Connection failed".

## 13. Known Tradeoffs

| # | Tradeoff | Accepted because |
|---|---|---|
| T-1 | Locale and platform become **inputs to the core**, an unusual coupling | It is the only way one resolver serves six platform-specific next actions (LT-3). The alternative — returning keys and resolving per platform — reintroduces six text tables and forfeits HP-3 |
| T-2 | Six view layers still exist; D removes semantic duplication, not layout work | Layout is the part that *should* differ per platform. Semantics is the part that must not |
| T-3 | Every user-facing string crosses a C ABI, with ownership and lifetime rules to get right | Bounded, testable, and paid once. A memory bug in string ownership is caught by P18's exhaustive drive far more reliably than by review |
| T-4 | Shipping every locale's catalogue in the binary costs size on the router tier | ≤ 96 KB per locale (§9), and the headless profile may ship one locale plus fallbacks. Rendering must work offline (C-6), so a download-on-demand catalogue is not an option |
| T-5 | A catalogue older than the daemon's registry is a **normal, permanent** condition | PC-2 makes it correct rather than merely tolerable, and §10 explains why store-channel skew guarantees it. The cost is that some users see a domain-level sentence where a specific one exists |
| T-6 | The freshness gate will sometimes show `UNKNOWN` when the system is in fact fine — a slow daemon under load, a suspended laptop | Deliberate asymmetry. A false `UNKNOWN` costs a moment of doubt; a false `Connected` is the defect the product exists to retire (R-34) |
| T-7 | RV-1 forbids progressive disclosure of the residual revocation window, so the revocation result surface is dense and slightly alarming | R-24 requires the window to be *stated rather than implied*. A user who has just lost a device is exactly the user entitled to the whole truth |
| T-8 | RC-2's higher-friction default-route consent will be annoying for a user who does this routinely | [docs/threat-model.md](../threat-model.md) §7: a default route captures the whole TwinNet's traffic. Friction proportional to blast radius is the correct design |
| T-9 | GTK4 on Linux serves GNOME-shaped desktops best and KDE users less well | Shipping two Linux GUIs doubles the accessibility and release burden for one platform tier. The CLI is the supported baseline, and a downstream Qt repackaging is permitted |
| T-10 | The iPad app shares a binary with iPhone, so it cannot use Mac-class multitasking idioms | It shares the NetworkExtension constraints and the core; the divergence is layout, scenes, pointer, and keyboard, all of which SwiftUI expresses in one codebase (§11.8) |

## 14. Revisit Conditions

Each is a measurable trigger, not a change of taste.

1. **Cold start.** If measured time from launch to first honest frame exceeds **400 ms at p95**
   on any required platform's reference device for two consecutive releases, revisit the FFI
   snapshot shape (a snapshot too large to marshal cheaply is the likely cause).
2. **Resume convergence.** If time from foreground to first fresh snapshot exceeds **1 s at p95**
   on iOS or Android — i.e. users routinely see stale-form after a normal unlock — revisit
   whether the view-model subscription should be re-established eagerly by the extension rather
   than by the app.
3. **Fallback rate.** If more than **2 %** of rendered diagnostics in a release fall through
   LT-2 to a `DOMAIN` fallback (counted locally, reported in the connectivity report), the
   catalogue release cadence is failing and must be decoupled further from the binary — or the
   registry is growing faster than translation can follow, which is an [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) problem.
4. **Unknown-domain renderings.** If the neutral fallback (unrecognized `DOMAIN`) is ever
   rendered in the field, a fourteenth domain has appeared. Revisit with
   [ADR-0015](ADR-0015-observability-and-diagnostics.md), because the thirteen are declared
   closed.
5. **Event rate.** If the view-model patch rate on a device with 8 peers exceeds **60/s
   sustained** on a mobile device, or measurably shortens battery life against the
   [docs/reliability.md](../reliability.md) §6.6 budget, revisit the subscription granularity in
   [ADR-0017](ADR-0017-local-management-interface.md) (X2.1).
6. **P18 cost.** If a full P18 run exceeds **30 minutes** on CI — registry codes × locales ×
   states × surfaces grows multiplicatively — revisit by sampling locales per run while keeping
   the source locale and one RTL locale exhaustive, and keeping the unknown-code set exhaustive.
7. **Binary size.** If the GUI shell for any required platform exceeds **40 MB** excluding the
   core, or the catalogue exceeds **96 KB** per locale, revisit the toolkit choice for that
   platform against Alternative B.
8. **Accessibility conformance.** If any release ships with an unresolved WCAG 2.2 AA failure in
   a flow of §11.10, the gate has been bypassed; treat as a release-process defect and revisit
   whether the audit is automatable enough to be a hard gate rather than a checklist.
9. **Platform floors.** If Apple removes the ability to run the UI in the app process while the
   provider runs in the extension, or Android removes the foreground-service notification as a
   persistent surface, revisit §11.9 — both are load-bearing for the anti-silence obligation.
10. **A UI-only capability appears.** If HP-2's parity matrix is ever suppressed or exempted for
    a shipping feature, R-36 has been abandoned; revisit this ADR rather than the gate.
