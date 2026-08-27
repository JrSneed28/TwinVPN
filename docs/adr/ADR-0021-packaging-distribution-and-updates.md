# ADR-0021: Packaging, Distribution, Code Signing, and Update Delivery

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
  [docs/vision.md](../vision.md), [docs/architecture.md](../architecture.md),
  [docs/networking.md](../networking.md), [docs/protocol.md](../protocol.md),
  [docs/reliability.md](../reliability.md), [docs/testing-strategy.md](../testing-strategy.md),
  [docs/threat-model.md](../threat-model.md)

This ADR owns how a TwinVPN client **becomes** an installed, trusted, running program on each of
the ten targets, and how it is **replaced** by a newer one: distribution channel, packaging
format, signing identity and key custody, the update manifest and its verification, staged
rollout, the apply sequence and its atomicity against
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)'s enforcement objects, install / upgrade /
downgrade / uninstall as state transitions, and managed deployment. It is the mechanism half of
[docs/architecture.md](../architecture.md) §2.21, whose **non-responsibilities are hard
constraints here**, not aspirations.

It does **not** own: the process and privilege split (ADR-0016), the local management interface
over which `update` verbs are invoked (ADR-0017), the shared core and its build system (ADR-0018),
any user-facing presentation of update state (ADR-0019), the local store and its schema migration
(ADR-0020), when a mobile OS permits work to run (ADR-0022), or the router/headless runtime
profile (ADR-0023). It does **not** own `ProtocolEpoch` allocation, the compatibility window, or
the deprecation gates — those are
[ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) §11.7, and this ADR
delivers the **evidence** and the **enforcement point** they require. It does **not** own the
kill-switch rule set — that is
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md); this ADR is constrained by KS-17 and
KS-23 and asks for exactly one amendment (§11.18 (b)).

> **Note on sibling references.** ADR-0016 … ADR-0023 land in the same integration pass as this
> file. They are referenced here by number only, deliberately unlinked, so that no link in this
> document is dangling at the moment it is written.

---

## 1. Context

[docs/architecture.md](../architecture.md) §2.21 asserts "signed artifacts with rollback
protection, staged rollout" and defers every mechanism. The corpus mentions notarization, the App
Store, sandboxing, MSIX, `deb`, `ipk`, SBOM and reproducible builds **exactly zero times**. That
silence is load-bearing in the wrong direction, because at least five accepted architectural
claims are unfunded without a distribution decision:

| Claim | Where | What it silently assumes about distribution |
|---|---|---|
| "Ship **WinTun** as a versioned, Microsoft-signed DLL+driver bundled with the app, installed and uninstalled by the app" | R-19, [docs/networking.md](../networking.md) §5.3 | That the packaging format permits shipping and installing a kernel-mode driver — MSIX and the Microsoft Store do not |
| "The rule set persists across upgrade" (`✔` in five of six platform rows) | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6, KS-23 | That the installer performs an atomic swap and that upgrade and uninstall are distinguishable to the uninstall path |
| "Fleet share of that epoch < 1% for ≥ 30 consecutive days, measured by the update service's fleet distribution report" | [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-25 G2 | That a fleet report exists, that it is computed over something, and that its coverage is known |
| "Refused by the updater **at install time, before the old binary runs**" | [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-30 | That there *is* an updater with a pre-execution gate on every channel — on iOS there is not |
| "System is in one of two well-defined states (old or new), never a third; kill switch holds throughout" | [docs/testing-strategy.md](../testing-strategy.md) §2.15 | That a crash-recovery journal exists and is readable without the daemon running |

There is a second, sharper reason this ADR matters. **The update channel is a code-execution path
into every device in every `TwinNet`.** [docs/threat-model.md](../threat-model.md) N4 concedes
"no defence against a compromised endpoint"; an adversary who can sign a release *becomes* every
endpoint at once. Measured by blast radius this is a more powerful key than the `OwnerRootKey`,
which reaches one `TwinNet`. The threat model has **no row for it** — see §11.20 (c).

## 2. Requirements

New requirements proposed for [docs/vision.md](../vision.md) §5, in that document's format. The
integrator merges them; §5.6 "Platform integration" is the natural home for R-40 … R-42 and §5.7
"Operability" for R-43.

| ID | Historical defect | TwinVPN requirement | Mechanism | Specified in |
|---|---|---|---|---|
| **R-40** | Unsigned, weakly-signed, or transport-trusted updates; a compromised distribution host owning every installed device | Every executable artifact MUST be verifiable **offline** against a build-time-pinned vendor trust anchor **and** against the host platform's own signing chain, and MUST NOT be installed without a verified inclusion proof in an append-only transparency log. Transport security MUST NOT be any part of the trust argument. | `ReleaseManifest` as an [ADR-0003](ADR-0003-network-contract-schema-format.md) B2 signed statement (deterministic CBOR in COSE_Sign1, ES256) under a quorum-held offline anchor; dual verification against the platform signature; mandatory log inclusion proof | ADR-0021 §11.3, §11.5, §11.8 |
| **R-41** | Silent downgrade to a known-vulnerable version; replayed old metadata pinning a device to it | Update metadata and installed-version state MUST be monotonic. A manifest below the stored high-water MUST be refused; a manifest older than the freshness bound MUST be refused; a rollback below the minimum supported `ProtocolVersion` MUST be refused **at install time, before the old binary runs**; any permitted downgrade MUST require a local `Owner`-authenticated action and MUST lower that device's own negotiation floors. | S-57 monotonic high-water + manifest expiry; a pre-execution installer gate on every self-updating channel; local-authority downgrade mirroring [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-21; S-37 floor lowering per [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-20/N-32 | ADR-0021 §11.8, §11.13 |
| **R-42** | An update that leaves the host unprotected, half-installed, or without its identity | An update MUST NOT leave the enforcement rule set absent at any instant, MUST NOT destroy the local store or the device identity, and an interrupted update MUST leave exactly the previous or the new version running — never a third state. Where a platform cannot close the unprotected window, the window MUST be **measured and reported as a number**, never assumed to be zero. | Atomic rule-set swap ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-23) plus the per-platform apply sequences of §11.10; the S-60 apply journal, fsync'd before every phase transition and readable without the daemon; ADR-0020 pre-migration retention; **P20** | ADR-0021 §11.10, §11.11, §11.13 |
| **R-43** | Deprecation decided by guesswork; an unreachable update service breaking connectivity | The update service MUST publish a fleet version/capability distribution sufficient to evaluate [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-25 G2, computed over an identifier that is **not** the `DeviceIdentity` and whose coverage is stated; and the update path MUST be **structurally incapable** of affecting an established `Session`, asserted mechanically rather than by care. | S-58 reporting epoch and the §11.7 fleet report with its stated coverage bias; a build-time dependency-graph assertion extending [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) §11.8 step 3; a destination-bounded `UPDATE` socket class that cannot carry host traffic | ADR-0021 §11.7, §11.9 |

## 3. Constraints

| # | Constraint | Source |
|---|---|---|
| **C1** | The update service MUST NOT be a connectivity dependency. An unreachable update service MUST NOT affect any `Session`. | [docs/architecture.md](../architecture.md) §2.21 |
| **C2** | An update MUST NOT leave the device unprotected *during* the update; the §2.16 rule set persists across upgrade. Replacement is by atomic swap, never remove-then-add, and the latch is never cleared. | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-23, §11.6 |
| **C3** | Update failure leaves the previous version running **and protected**. Rollback below the minimum supported `ProtocolVersion` MUST be refused. | [docs/architecture.md](../architecture.md) §2.21, S-23 |
| **C4** | No pushed configuration may disable the kill switch without explicit `Owner` action; disarming requires a *local interactive* action plus OS-mediated administrator authentication. | [docs/architecture.md](../architecture.md) §2.21, [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-21, KS-22 |
| **C5** | **I2 — no novel cryptography.** The signing scheme composes what the corpus already uses: deterministic CBOR + COSE_Sign1 + ES256. A second bespoke signature format is prohibited. | [docs/vision.md](../vision.md) §4.1, [ADR-0003](ADR-0003-network-contract-schema-format.md) §11, [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.1 |
| **C6** | **I4 — identity never leaves the device.** No packaging, backup, migration, or "restore my install" mechanism may export, escrow, or transport `DeviceKey` private material. | [docs/vision.md](../vision.md) §4.1 |
| **C7** | Release gating is [docs/testing-strategy.md](../testing-strategy.md) §6. This ADR MUST bind to §6.1's tiers and §6.5's blocker list and MUST NOT create a parallel set. | [docs/testing-strategy.md](../testing-strategy.md) §6, C-5, C-6 |
| **C8** | Minimum OS versions are already fixed: iOS 15 · Android API 26 (API 29 behaviour) · Windows 10 21H2 / Server 2019 · macOS 11 · Linux 5.6 (5.4 with userspace fallback) · OpenWrt 21.02. Packaging MUST NOT raise a floor without a stated compatibility break (R-20). | [docs/networking.md](../networking.md) §5.2 |
| **C9** | A crash or uninstall MUST leave the host neither unprotected **nor** permanently broken; all state written outside our own interface is owner-tagged and reclaimable. | [docs/networking.md](../networking.md) §5.5.3 |
| **C10** | The router target is ADR-0023's **H-EMB** deployment profile, which runs on **GC-0** silicon (ADR-0023 §11.13 EM-54): MIPS 24Kc @ 580 MHz, 1 core, 128 MB RAM with ≈ 24 MB free, **16 MB of total flash shared with the base system**, `ath79`-class, over a read-only squashfs root plus an overlay. **Flash, not RAM, is the binding constraint on packaging**, and **GC-0's 16 MB is the design point**. Three label families apply to such a device on **different axes** and MUST NOT be conflated: **HC-3** by ADR-0016's process-topology axis (headless), **H-EMB** by ADR-0023's deployment-profile axis, and **GC-0** by ADR-0023's silicon axis. **Only the silicon axis sizes a package**, so every number in §9 is a GC-0 number, not an H-EMB one. **ADR-0013's G1 "Router class" is a fourth thing and a much larger one** — its reference hardware is an RPi 4B with 2 GB of RAM, which is not router hardware — and it MUST NOT be used to size a package budget. | [docs/vision.md](../vision.md) R-21, brief §10, ADR-0023 §11.13, ADR-0016 |

## 4. Considered Alternatives

The decision axis is **who owns the code-execution path onto the device on each platform**, because
that choice — not branding — determines whether the product can hold `CAP_NET_ADMIN`, install a
driver, run a boot-time enforcement artifact, or refuse a downgrade before the old binary runs.

- **A — Store-first everywhere.** Ship through the platform's own store wherever one exists: App
  Store, Mac App Store, Microsoft Store (MSIX), Play Store, and a sandboxed store package
  (Flatpak or Snap) on Linux. No self-updater anywhere; the OS is the only installer.
- **B — Direct-first everywhere.** Developer ID + notarization on macOS, Authenticode MSI on
  Windows, our own signed `deb`/`rpm` repositories plus a static tarball on Linux, a
  self-distributed APK on Android, our own updater on every one of them. The App Store on
  iOS/iPadOS only because there is no alternative.
- **C — Capability-determined channel.** Choose, per platform, the channel that preserves the
  privileged posture [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) and R-19 require, and
  accept a store only where it costs nothing structural. A store channel is used where it is the
  only channel (iOS/iPadOS) or where it is the mainstream one and its costs are containable with a
  named secondary channel (Android). Store channels are refused where they would silently weaken
  enforcement (macOS, Windows, Linux).
- **D — Dual channel on every platform that permits it.** Maintain both a store build and a direct
  build on macOS, Windows, Linux and Android, and let the user choose.
- **E — One universal self-updating agent.** A single bespoke cross-platform updater and installer
  owned entirely by us; stores are used only as a thin discovery-and-bootstrap shim that installs
  the real agent.

## 5. Advantages of Each Alternative

**A — Store-first.** One update mechanism per OS, all of it maintained by the platform vendor. No
updater code of our own means no updater CVEs of our own and no signing infrastructure beyond
submission. Users get familiar install, uninstall and auto-update. Store review is a second pair of
eyes. Enterprise deployment via the store's own business channels is well trodden. On Android and
iOS this is what users already expect. Discovery is real: a store listing is free distribution.

**B — Direct-first.** Maximum capability everywhere: system extensions, privileged helpers, kernel
drivers, boot-time units, `CAP_NET_ADMIN`, per-machine installs. We control the update cadence
absolutely, which makes a security fast path a matter of hours rather than of a reviewer's queue.
We control rollback, which is what makes
[ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-30's pre-execution MSPV
gate implementable. No third party holds a signing key. Reproducible builds are achievable end to
end because we produce the final bytes.

**C — Capability-determined.** Keeps B's capability where capability is load-bearing and takes A's
distribution where A is the only road (iOS) or the mainstream one (Android). Each platform gets one
supported product with one enforcement posture, so there is never a build where I3 is quietly
weaker. The Android secondary channel is chosen for a specific purpose — auditability against a
third-party-held signing key — rather than as a second product.

**D — Dual channel.** Users who trust a store get a store; users who need capability get the direct
build. Enterprises get whichever their tooling ingests. It hedges a platform-policy change: if a
store rejects us, the direct build already exists and is already exercised.

**E — Universal agent.** One updater to write, test, fuzz and reason about, shared across all
targets — a natural fit with H1's single portable core. Update semantics (monotonicity, staged
rollout, atomic apply, the S-60 journal) exist in exactly one implementation, so **P20** tests one
mechanism rather than six. The store shim keeps discovery.

## 6. Disadvantages of Each Alternative

**A — Store-first.** Fatal on three platforms. **macOS**: a Mac App Store app is sandboxed, cannot
install a NetworkExtension **system** extension (only an app extension), cannot install a
`LaunchDaemon` via `SMAppService`/`SMJobBless`, and cannot write `/etc/pf.conf` or load a `pf`
anchor — deleting the "Boot-time pre-network enforcement" cell of
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6's macOS row and downgrading its "OS
reboot" durability from ✔ to ✘. **Windows**: MSIX runs in an app container with a virtualized
filesystem and registry, does not permit installing a kernel-mode driver, and constrains
per-machine service registration; WinTun (R-19) cannot be shipped this way. **Linux**: Flatpak has
no VPN portal and cannot hold `CAP_NET_ADMIN`, create a TUN device, program nftables, or install a
system-scope `systemd` unit; Snap's `network-control` interface needs store-granted auto-connection
and the daemon still has to escape confinement. **A sandboxed store package is a poor fit for a
program whose whole job is to be the network and policy authority for the host — the sandbox exists
to prevent exactly that.** And store review latency would govern the security fast path on every
platform at once.

**B — Direct-first.** Not available at all on iOS/iPadOS, so B is not a complete answer. It
forfeits store discovery on Android where most users are. It obliges us to run signing
infrastructure, a CDN, a transparency log and an updater — attack surface we would otherwise not
have. The self-distributed APK cannot auto-update without a per-install user confirmation.

**C — Capability-determined.** Two Android channels means two signing identities and, because
Android refuses an in-place upgrade across a signature change, **no migration path between them**.
Refusing the Mac App Store forfeits macOS store discovery and store-managed enterprise
distribution. It is the most explanation-heavy option: "why is your Mac app not in the App Store"
must be answered on a support page rather than by a link.

**D — Dual channel.** Two macOS products whose kill-switch durability differs, distinguished only
by where the user got it. [docs/vision.md](../vision.md) §4.1 requires a platform limitation to be
stated with its residual and never silently relaxed; a store build with weaker I3 enforcement, sold
under the same name, is precisely that silent relaxation. It also doubles the T3/T4 platform matrix
([docs/testing-strategy.md](../testing-strategy.md) §6.2) and the support surface for **P09**'s
per-platform oracle.

**E — Universal agent.** The store shim is a bootstrap-then-sideload pattern that App Store review
forbids outright and that Play treats as unwanted-software behaviour. It also concentrates every
platform's update path into one privileged program with no platform-level defence in depth behind
it.

## 7. Security Implications

1. **The release trust root is the highest-blast-radius key in the system**, exceeding the
   `OwnerRootKey`, which reaches one `TwinNet`. It therefore gets ORK-grade custody: offline,
   ceremony-only, threshold-held (§11.3, §11.4).
2. **Transport is not a trust boundary.** A CDN or mirror can serve any bytes it likes; the
   `ReleaseManifest` signature and the artifact digest are what make bytes ours. Stated so that
   "we use HTTPS" is never offered as the security argument.
3. **Three third parties hold a signing key we do not control** — Apple (App Store re-signing and
   notarization tickets), Google (Play App Signing), and indirectly the Authenticode CA. No
   mechanism here removes them; §11.3's residual column states them. Apple can additionally
   **revoke a notarization ticket and disable an already-installed macOS app at launch** — a
   vendor kill switch over our product.
4. **Verification is dual and independent**: our manifest chain and the platform's own chain must
   both accept an artifact, so a compromise of one does not suffice.
5. **Freshness defeats the freeze attack.** A signed-but-old manifest replayed forever pins a
   device to a vulnerable version without forging anything. Manifest expiry (§11.8) is the only
   defence against it and is therefore mandatory, not advisory.
6. **The transparency log converts a targeted attack into a detectable one**: a per-device forged
   update requires the attacker to publish the forgery to succeed.
7. **The update fetch is not host traffic.** §11.18 (b) requests a destination-bounded socket class
   modelled on [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.2 class 13 rather than
   on the destination-unbounded `BOOTSTRAP` class.
8. **Uninstall is not revocation.** An uninstalled device retains a valid `DeviceIdentity` at every
   peer until the `Owner` revokes it ([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.7);
   §11.13 says so because assuming otherwise is a plausible and dangerous mistake.
9. **On a managed device the MDM administrator is an `Owner`-class principal** for
   [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-21(2), because the OS grants them
   that authority. Where they differ from the TwinVPN `Owner`, they can remove protection and the
   `Owner` cannot prevent it (§11.15).

## 8. Reliability Implications

- **C1 is discharged structurally, not by discipline.** §11.9 forbids the datapath and connection
  state machine from linking the updater module at all, asserted at build time in T1 alongside the
  existing [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) §11.8 step-3 check. An
  unreachable update origin produces one `INFO`-severity code and nothing else.
- **Every apply is a planned outage of a bounded, named length, or of none.** §11.10 states per
  platform whether the tunnel drops, whether the enforcement object is ever absent, and the p95 and
  cap for each. Where the tunnel drops, the transition is the ordinary
  [docs/reliability.md](../reliability.md) `RECONNECTING` path with
  `PLATFORM.PROCESS_RESTARTED` — no new state and no new transition is introduced.
- **The failure branch is the designed branch.** §11.11 specifies recovery from an interruption at
  every phase boundary; the S-60 journal makes "old or new, never a third" decidable by a recovery
  entry point that runs without the daemon.
- **Router-class reliability is bought by refusing automation.** §11.1's OpenWrt row makes
  auto-install unavailable, because `opkg` is not transactional and there is no rollback partition.

## 9. Performance Implications

- Full artifacts only (§11.8) trade bytes for one fewer trusted code path. Budgets: desktop
  artifacts ≤ 40 MB, Android ≤ 30 MB download, iOS ≤ 60 MB. Exceeding a budget is a release-review
  item, and the 40 MB figure is the §14 trigger for revisiting deltas.
- **The router `ipk` budget is derived from flash, not chosen, and it is a GC-0 number.** Design
  point: **GC-0** silicon — 16 MB of total flash shared with the OpenWrt base system, 128 MB RAM
  with ≈ 24 MB free (C10) — which is the silicon the H-EMB deployment profile runs on. Base
  daemon + CLI package **≤ 900 KB compressed / ≤ 2 MB installed** on `mips_24kc` and
  `arm_cortex-a7`; the userspace datapath fallback is a **separate optional package** at ≤ 700 KB
  compressed, so the mandatory footprint stays small on devices that have the in-tree `wireguard`
  module. The 2 MB installed figure is what makes §11.2's OpenWrt "free overlay ≥ installed
  size × 2" pre-check satisfiable: it demands 4 MB of free overlay, which GC-0's 16 MB has and an
  **8 MB-flash device below GC-0 generally does not** — so on such a device only the base package
  is supported, and the optional fallback package is refused with
  `UPDATE.APPLY.STORAGE_INSUFFICIENT` rather than half-installed.
  **The budget binds at GC-0 and only at GC-0.** On **GC-0U** (dual A53, 128 MB flash) it is
  satisfied with two orders of magnitude of headroom and is not a constraint at all; quoting it as
  one there would repeat the axis error this constraint exists to prevent. Equally, sizing against
  **ADR-0013's G1** would have been roughly an order of magnitude too generous (C10).
- Verification cost is bounded and off the datapath: one ES256 verify over the manifest, one
  SHA-256 over the artifact, one Merkle inclusion proof. On **GC-0** silicon — a single 580 MHz
  MIPS 24Kc core with no crypto acceleration — the SHA-256 of a sub-megabyte artifact dominates
  and is under a second; it runs in the updater task, never in a path a packet waits on.
- The update check is one small signed document on a schedule (§11.8), never a poll loop, and is
  suppressed entirely on metered and low-power links using the `metered` / `low_power` facts
  [docs/networking.md](../networking.md) §5.1's `query_link_facts()` already exposes.
- On iOS/iPadOS the apply happens outside our process entirely, so it has no cost we can measure or
  control; what it has is a *window*, which §11.10 measures instead.

## 10. Operational Implications

- Release engineering owns a signing enclave, a transparency log, an artifact CDN, per-platform
  store accounts (Apple Developer Program with the NetworkExtension entitlement, Google Play
  Console with the VPN declaration, a Microsoft Partner Center account if a driver submission ever
  becomes necessary), Linux repository hosting, and an `opkg` feed.
- Certificate lifecycle becomes a scheduled operational event: **rotating the Authenticode
  certificate resets SmartScreen reputation** and produces user-visible warnings, so rotation is
  planned and overlapped (dual-signed transition), never done reactively except on compromise.
- Store review is a dependency in the incident timeline. The security fast path (§11.14) bypasses
  our own staged ladder but cannot bypass Apple's or Google's queue; expedited review is requested
  and is not guaranteed.
- Fleet reporting is an operational product: §11.7's distribution report is the input to
  [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)'s deprecation gates, and
  its **coverage** must be published alongside it or the gate is being evaluated on an unknown
  denominator.
- The self-hosted operator persona ([docs/vision.md](../vision.md) §2) needs an update mirror and a
  deployment profile, not a build system. §11.15 gives them both and states where the escape hatch
  to their own build lies.

## 11. Decision

**Adopt Alternative C — the capability-determined channel** — with exactly one deliberate
secondary channel (Android), one deliberate refusal (the Mac App Store and the Microsoft Store),
and one shared updater implementation for all self-updating channels, taken from E's best idea
without E's store shim.

### 11.1 Channel decision per target

| Target | Primary channel | Artifact | Installer | Update mechanism | Rollback available |
|---|---|---|---|---|---|
| **iOS 15+** | **App Store only** (no alternative exists at this tier) | `.ipa` containing the app and the `NEPacketTunnelProvider` app extension | Apple | **Store-managed**; timing chosen by the OS | **No** |
| **iPadOS 15+** | App Store only | as iOS, plus multi-scene UI | Apple | Store-managed | **No** |
| **macOS 11+** | **Developer ID + notarization** | notarized, stapled `.pkg` inside a notarized, stapled `.dmg`; the same `.pkg` is the MDM artifact | our privileged installer | **Self-updating** (our updater) | Yes, local `Owner` action |
| **Windows 10 21H2 / Server 2019+** | **Authenticode-signed per-machine MSI** (WiX) | `.msi` (x64, arm64) + `.intunewin` wrapper | Windows Installer, driven by our service | **Self-updating** (our updater invokes `msiexec` silently) | Yes, local `Owner` action |
| **Android API 26+** | **Play Store** (AAB) | `.aab` → Play-signed split APKs | Play | Store-managed | Refused by the platform (monotonic `versionCode`) |
| **Android — secondary** | **Self-hosted reproducible APK**, F-Droid-compatible | `.apk`, our signature | `PackageInstaller`, per-install user confirmation | Prompted self-update | Refused by the platform |
| **Linux (deb)** | **Our signed apt repository** | `.deb` (amd64, arm64, armhf) | `dpkg`/`apt` | Distro-managed **or** our updater | Yes, local `Owner` action |
| **Linux (rpm)** | **Our signed rpm repository** | `.rpm` (x86_64, aarch64) | `rpm`/`dnf` | Distro-managed **or** our updater | Yes |
| **Linux (portable)** | **Static relocatable tarball** into `/opt/twinvpn` | `.tar.zst` + detached manifest | our installer script | **Self-updating** | Yes |
| **OpenWrt 21.02+ / routers** | **Our signed `opkg` feed** | `.ipk` (`mips_24kc`, `mipsel_24kc`, `arm_cortex-a7`, `aarch64_cortex-a53`) | `opkg` | **Check only — never self-install** (`UPDATE.POLICY.MANUAL_ONLY`) | Yes, operator action |
| **Headless / CLI-only servers, containers** | deb/rpm or tarball; container images by digest | as Linux | operator's configuration management | **Operator-driven**; no self-update assumed | Yes |

**Refusals, stated once with their reason.** The **Mac App Store** is refused because a sandboxed
MAS app cannot install a NetworkExtension system extension or a `LaunchDaemon`, which deletes the
boot-time `pf` anchor and downgrades
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6's macOS reboot durability from ✔ to
✘; shipping two macOS builds where one has weaker I3 enforcement is the silent relaxation
[docs/vision.md](../vision.md) §4.1 forbids. **MSIX / the Microsoft Store** is refused because it
cannot install WinTun (R-19). **Flatpak and Snap** are refused as a product channel because a
sandbox cannot hold `CAP_NET_ADMIN`, create a TUN device, or program nftables; the **only**
permissible future use is packaging the *UI process* alone against a separately installed daemon
over ADR-0017's management interface, and that is deferred, not foreclosed.

### 11.2 What each channel costs, per platform

| Target | Capability consequences of the chosen channel |
|---|---|
| **iOS / iPadOS** | `com.apple.developer.networking.networkextension` with `packet-tunnel-provider` requires **Apple's approval of the entitlement request**, separately from app review; the app must be published by an enrolled organization under the VPN provisions of the App Review Guidelines, with a completed data-collection declaration. The provider runs in a **memory-constrained app extension** ([docs/networking.md](../networking.md) §5.4), so the artifact must keep it small — the budget itself belongs to ADR-0018/ADR-0022. There is **no sideloaded privileged helper**, no host firewall, and no boot enforcement (already conceded by [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6). Update cadence is gated by review; the expedited-review path is requested, not guaranteed. **No user-initiated rollback exists**, so [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-32's authorized-rollback flow is **unavailable on iOS** — the only remedy for a bad release is a forward fix. App thinning applies; bitcode does not (removed from the toolchain). |
| **iPadOS specifically** | Same store and same entitlement, but: multiple UI scenes may be live under Stage Manager and all are terminated by an update; external-display and hardware-keyboard state is lost across it; Files-based import is the delivery route for an operator's deployment profile on an unmanaged iPad; and **supervision via Apple Configurator or MDM is the only way to obtain Always-On VPN**, which is what closes the §11.10 iOS update window. An unsupervised iPad cannot close it. |
| **macOS** | Gained: NetworkExtension **system** extension (`com.apple.developer.system-extension.install` plus the `packet-tunnel-provider-systemextension` entitlement), an `SMAppService` `LaunchDaemon` for the boot-time `pf` anchor, our own update cadence, our own rollback. Cost: **user approval** of the system extension in System Settings on first install, with an administrator authentication on Apple silicon — on MDM-managed Macs a `SystemExtensionPolicy` payload pre-approves by team ID and removes the prompt. Gatekeeper requires notarization; **stapling matters**, because an un-stapled notarized app makes first launch depend on an online Gatekeeper check, and we refuse a first-run network dependency. Lost: App Store discovery and store-managed enterprise distribution. |
| **Windows** | Gained: per-machine install, a LocalSystem service with `FailureActions` auto-restart (the supervisor **P09** procedure A assumes), the WFP sublayer, and WinTun installed and uninstalled by us as R-19 requires. Cost: an **OV or EV code-signing certificate whose private key is in FIPS 140-2 L2+ hardware** (mandatory for all code-signing keys since the 2023 CA/B Forum change — EV now buys SmartScreen reputation seeding and driver-submission eligibility, not key protection); SmartScreen reputation accrues per certificate and **resets on rotation**. WinTun is a kernel-mode driver: since Windows 10 1607 kernel-mode drivers must be Microsoft-signed, so we ship the **upstream Microsoft-signed** WinTun binaries app-locally and re-verify their signature at load; we do **not** re-sign them and we do not submit them. If TwinVPN ever has to author its own driver, that becomes a Partner Center attestation or WHQL submission with an EV certificate and a **separate release cadence gated by Microsoft** — §14 revisit 7. Silent deployment is `msiexec /i … /qn` with public properties, ADMX policy templates, and an Intune Win32 wrapper. |
| **Android** | Play requires the **VpnService declaration** in Play Console, a Data safety disclosure, and compliance with the VPN policy: the VPN must be the app's core functionality, must not intercept other apps' traffic without disclosure, and must not monetize user data. Play additionally maintains an independent-security-review track for VPN apps; **the precise obligation moves and MUST be re-checked at each submission** (§14 revisit 6). New apps and updates ship as **app bundles**, which makes **Play App Signing mandatory — Google holds the app signing key and we hold only an upload key** (§11.3 residual). Native libraries must support **16 KB page sizes** (ELF `max-page-size=16384`, uncompressed and 16 KB-aligned in the APK) for Play's Android 15+ requirement, which lands directly on H1's shared core. The secondary channel exists because a third party holds the primary channel's final signature: **the reproducible self-hosted APK is the transparency root, and the Play artifact is auditable against it**. Cost of the secondary channel: it is signed with our own key, so **Android refuses an in-place upgrade between channels**; switching requires uninstall + reinstall, and Android deletes Keystore keys on uninstall, so **the device identity is destroyed and re-enrolment is required** ([ADR-0007](ADR-0007-device-identity-and-pairing.md) N-7). This is stated in the UI before the user commits. |
| **Linux** | Gained: `CAP_NET_ADMIN`, a system `systemd` unit, nftables, first-class headless operation (R-21). Cost: we host and sign two repositories and a tarball; distro reach is ours to maintain. Supported floor: Debian 11+/Ubuntu 20.04+, RHEL-family 8+, Fedora current-2, plus the tarball for anything else with `systemd` ≥ 245 and a 5.6 kernel (or 5.4 with the userspace datapath). Repository signing: apt with an OpenPGP key in `/usr/share/keyrings` referenced by `signed-by=` (never a global trusted keyring), rpm with `gpgcheck=1` **and** `repo_gpgcheck=1`. Units installed: `twinvpnd.service` (`Type=notify`, `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`, `StateDirectory=twinvpn`) and `twinvpn-killswitch.service` exactly as [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6 names it. |
| **OpenWrt / routers / headless** | The `opkg` feed index is signed with **`usign` (Ed25519)** because the platform's verifier is fixed and not ours to choose. That is a second signature algorithm beside C5's ES256, and it is accepted **in addition to**, never instead of, the COSE_Sign1 manifest the device itself verifies: the platform check gates `opkg`, our check gates trust. Read-only `squashfs` rootfs with a `jffs2` overlay means an install consumes overlay space and a full overlay turns an upgrade into a half-install, so the updater pre-checks `df /overlay` against installed size × 2 and refuses with `UPDATE.APPLY.STORAGE_INSUFFICIENT` rather than starting. **`sysupgrade` preserves only what is listed**: `/etc/twinvpn` MUST be registered in `/etc/sysupgrade.conf` or the firmware upgrade destroys the identity and the store, and `sysupgrade -n` destroys them regardless — the device then presents `AUTH.IDENTITY_MISSING` and re-enrols. Deferred for this tier, explicitly and without foreclosing: staged-rollout percentages, delta updates, A/B partitions, and secure-boot integration. |

### 11.3 Signing identities and key custody

**Rule U-1.** Every artifact carries **two independent signatures**: the platform's, and ours. Ours
is a `ReleaseManifest` — an [ADR-0003](ADR-0003-network-contract-schema-format.md) **B2 signed
statement**: deterministic CBOR (RFC 8949 §4.2.1) inside COSE_Sign1 (RFC 9052), **ES256**, verified
over received octets, `crit` enforced, non-canonical input rejected rather than normalized. No new
signature format is introduced (C5).

**Rule U-2 — the release trust hierarchy deliberately mirrors
[ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.5 rather than inventing a second shape.**

| Key | Role | Custody | Rotation | Third party holds a copy? |
|---|---|---|---|---|
| **RTA** — Release Trust Anchor | The public half is **pinned in every build**. Signs `ReleaseSigningDelegation` documents only. | Offline, ceremony-only, **threshold `k = 2` of `n = 4`** in FIPS 140-3 L3 HSMs held by separate custodians. Never resident between ceremonies. | Only by a new anchor at a strictly higher `anchor_version`, shipped in a build signed under the old one | **No** |
| **RMK** — Release Manifest Key | Signs every `ReleaseManifest`. Delegated by RTA with an expiry ≤ 12 months. | Networked HSM in the release enclave; signing requires a **2-person authorization** recorded in the log | Annually, overlapped: devices accept the current and the immediately previous RMK | **No** |
| Apple Developer ID Application + Installer | Gatekeeper, `.pkg` | Private keys on a PIV hardware token attached to a dedicated, network-isolated signing host | On CA schedule; overlapped | **No** — but Apple issues and can **revoke the notarization ticket**, disabling an installed app at launch |
| Apple App Store distribution | iOS/iPadOS submission | We sign for submission; **Apple re-signs the delivered artifact** | Apple's | **Yes — Apple** |
| Authenticode (OV/EV) | Windows | Cloud signing service or on-prem HSM (hardware mandatory) | Planned and overlapped, dual-signed; **reputation resets** | No (CA issues, does not hold) |
| Play upload key | Android AAB upload | HSM | Rotatable via Play's key-rotation flow | No |
| Play app signing key | The signature devices verify | **Google** | Google's | **Yes — Google** |
| apt/rpm repository OpenPGP key | Repository index | Smartcard on the signing host | Annually, both keys published during overlap | **No** |
| `usign` (Ed25519) feed key | `opkg` index | Offline on the signing host | Annually | **No** |

**Rule U-3 — residuals, stated rather than implied.** Apple and Google each hold a key capable of
producing an artifact our users' devices will accept, and Apple additionally holds a revocation
capability over installed macOS software. No mechanism in this ADR removes either. What it does
instead is make them **detectable**: §11.5's log records what we published, so a store artifact
that does not correspond to a logged entry is evidence. This is detection, not prevention, and it
is recorded as such in §11.20 (c).

### 11.4 Key compromise and rotation

| Event | Immediate action | What devices do | Residual |
|---|---|---|---|
| **RMK compromised** | RTA signs a `ReleaseSigningDelegation` revocation; new RMK delegated; all manifests re-signed | Refuse any manifest whose RMK is revoked (`UPDATE.VERIFY.KEY_REVOKED`); continue running the installed version, protected | Devices that installed a forged artifact before revocation are compromised endpoints (N4). Detection is the log |
| **RTA compromised** | **No in-band recovery exists** — the anchor is pinned in the binary | Nothing; a forged chain verifies | **Unmitigated.** This is why RTA is offline, threshold-held and ceremony-only. Recovery is out-of-band: republish through the platform channels whose trust root is Apple's or Google's, and require a manual reinstall on desktop. Named in §13 |
| **Authenticode key compromised** | Revoke with the CA, **setting the revocation date to the compromise time** so countersigned timestamps before it stay valid; re-sign under a new certificate | Refuse artifacts failing the platform check (`UPDATE.VERIFY.PLATFORM_SIGNATURE_INVALID`) | SmartScreen reputation resets; users see warnings until it re-accrues |
| **Developer ID key compromised** | Revoke with Apple; expect ticket revocation of affected builds | Gatekeeper refuses; already-installed copies may be disabled by Apple | Apple's action, not ours |
| **Play upload key compromised** | Play key-rotation flow | Unaffected — the app signing key is Google's | The attacker could have uploaded one build before detection |
| **Repository or feed key compromised** | Publish a new key, dual-sign during overlap, revoke the old | `apt`/`opkg` refuse the old index | Mirrors serving a stale index look identical to an attack; the manifest freshness bound (§11.8) is what distinguishes them |

**Rule U-4.** Every key in §11.3 has a rotation schedule, and rotation is exercised **at least once
per year in a rehearsal that produces a real signed artifact** on a non-production channel. A
rotation path that has never been executed is not a mitigation.

### 11.5 Reproducible builds, SBOM, and the transparency log

**Rule U-5 — reproducibility, honestly scoped.** Bit-identical rebuild from source is **required**
for the Android secondary APK and the Linux tarball, **best-effort** for `deb`/`rpm`/`ipk`, and
**not achievable** for App Store and Play artifacts because a third party produces the final bytes.
Mechanism: pinned toolchain container by digest, `SOURCE_DATE_EPOCH`, `--remap-path-prefix` on the
Rust core (H1), deterministic archive member ordering, and a published rebuilder attestation.

| Channel | Reproducible | Why |
|---|---|---|
| Android secondary APK, Linux tarball | **Yes, required** | We produce the final bytes; this is the transparency root for Android |
| `deb`, `rpm`, `ipk` | Best-effort | Packaging tools introduce timestamps we do not fully control |
| macOS `.pkg`, Windows `.msi` | No | The signature and the notarization ticket are non-deterministic by construction; the **payload** inside is reproducible and is what the rebuilder attests |
| App Store `.ipa`, Play split APKs | **No** | Apple and Google re-sign |

**Rule U-6 — SBOM.** Every artifact ships a **CycloneDX 1.5 JSON** SBOM covering the Rust crate
graph, the native libraries, and the bundled WinTun version with its upstream digest. Its digest is
carried in the `ReleaseManifest` and is therefore signed. It is published at a stable URL per
release.

**Rule U-7 — the transparency log.** Every `ReleaseManifest` is submitted to an **append-only
Merkle log** (RFC 6962-style) before publication. **A device MUST NOT install an artifact without a
verified signed inclusion proof for its manifest.** If the log is unreachable, no update is
installed and `UPDATE.MANIFEST.LOG_PROOF_MISSING` is emitted — not installing is always the safe
outcome, so a fail-closed log check costs availability of *updates* only, never of *sessions* (C1).
For the store channels, where we cannot know the final artifact digest in advance, the log records
the **submitted** artifact and version, which permits third-party audit of a downloaded store
artifact against our record — detection, not prevention.

### 11.6 Version identity — three numbers that MUST NOT be conflated

Conflating these is a defect class. They are independent and the manifest is the only place their
relationship is stated.

| Axis | Name | Form | Owner | Who negotiates it |
|---|---|---|---|---|
| 1 | **`AppVersion`** | SemVer 2.0 `<major>.<minor>.<patch>` plus a monotonic build number | **This ADR** | Nobody. It is a label for humans, stores and support |
| 2 | **`CoreAbiVersion`** | ADR-0018's stable C ABI version | **ADR-0018** | Nobody — see U-8 |
| 3 | **`ProtocolEpoch`** | `uint32`, monotonic, three axes in one number space | **[ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-1** | Peers, per `Session` |

**Rule U-8 — the shell and the core ship in one artifact.** The native shell and the portable core
(H1) MUST be built, signed, and installed as a single artifact. There is **no** partial update in
which one is replaced and the other is not, and therefore `CoreAbiVersion` is never negotiated at
runtime and never appears in a compatibility matrix. This deletes a whole defect class at the cost
of larger artifacts, and it is the reason §11.8 chooses full artifacts over deltas.

**Rule U-9 — store version constraints are a real mapping problem.** `AppVersion` MUST be mapped
per platform and the mapping MUST be monotone:

| Platform | Field | Constraint | Mapping rule |
|---|---|---|---|
| iOS / macOS | `CFBundleShortVersionString`, `CFBundleVersion` | `CFBundleVersion` must strictly increase per submission | `CFBundleVersion` = the monotonic build number |
| Android | `versionName`, `versionCode` | `versionCode` is a strictly increasing `int32`; downgrade installs are refused by the platform | `versionCode` = `major·10⁷ + minor·10⁴ + patch·10 + channel_digit` |
| Windows MSI | `ProductVersion` | `a.b.c` with `a ≤ 255`, `b ≤ 255`, `c ≤ 65535` — **naive SemVer does not fit** | `a = major`, `b = minor`, `c = patch·100 + build mod 100`; the full `AppVersion` is carried in `ARPCOMMENTS` and in the manifest |
| deb / rpm | `Version` | epoch-comparable | `<major>.<minor>.<patch>-<build>` |
| ipk | `Version` | as deb | as deb |

**Rule U-10 — the compatibility matrix.** For a device running `AppVersion` V:

| Fact | Rule |
|---|---|
| Supported `ProtocolEpoch` range | `[v_min, v_max]` from the build alone; `v_max − v_min ≥ 2` ([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-24). **`AppVersion` is not a proxy for it**; the manifest states the mapping explicitly |
| Peer interoperability | Governed solely by epoch negotiation, never by `AppVersion` comparison. A newer `AppVersion` at the same epoch changes nothing on the wire |
| Minimum installable predecessor | The manifest entry's `min_installable_from`. An older install must reach an intermediate version first, so that ADR-0020's forward-only migrations are never skipped |
| Minimum supported version for rollback | The MSPV in the currently signed released-version registry entry, **not** the local build's `v_min` ([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-29) |

### 11.7 Fleet version reporting — making N-25 G2 evaluable

**Rule U-11.** The update check-in is the fleet report. It carries exactly:

```
FleetCheckIn {
  report_epoch_id   : bytes(16)   # S-58, rotating; NOT derived from device_id  [OPERATIONAL]
  app_version       : string                                                    [OPERATIONAL]
  epoch_min, epoch_max : uint32   # the device's supported ProtocolEpoch range  [OPERATIONAL]
  capability_tokens : [string]    # ADR-0014 §11.11 registry names              [OPERATIONAL]
  platform, os_version, arch, channel                                           [OPERATIONAL]
}
```

It carries **no** `device_id`, no `TwinNet` identifier, no peer information, no endpoint, and no
field classified `SENSITIVE` or `SECRET` under
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.4. It is not telemetry and is not gated
on the telemetry opt-in, because it is the one request every device makes.

**Rule U-12 — `report_epoch_id` rotates every 30 days** and is drawn from the platform CSPRNG at
install and at each rotation. It MUST NOT be derived from `DeviceIdentity`, `device_id`, or any
hardware identifier. Rotation at exactly the length of N-25 G2's measurement window is deliberate:
distinct-device counting works within a window and long-term linkage does not.

**Rule U-13 — the fleet report states its own coverage, or the gate is unevaluable.** Fleet share
is computed over **distinct `report_epoch_id` values seen in the trailing 30 days**. The
denominator therefore excludes devices that were offline, that had check-in disabled by a managed
profile, or whose operator blocks the origin — so **the measured share of an old epoch is a lower
bound on the true share**. Consequently:

- The published report MUST carry `coverage_estimate` and `denominator` alongside each share.
- [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-25 G2 MUST be read as
  "< 1% of *reporting* devices", and the residual — silent devices — is bounded by the observation
  that a device unreachable for 30 days is unreachable by any deprecation notice either.
- The router/headless tier reports even though it never self-installs: a *check* is not an
  *install* (`UPDATE.POLICY.MANUAL_ONLY`).

### 11.8 The update mechanism for self-updating channels

**Rule U-14 — the manifest.** A `ReleaseManifest` is a B2 signed statement containing:

```
ReleaseManifest {
  manifest_version   : uint64      # monotonic; S-57 high-water
  issued_at          : timestamp
  expires_at         : timestamp   # issued_at + 14 d  (the freeze-attack bound)
  channel            : NIGHTLY | BETA | STABLE
  msvp               : uint32      # ADR-0014 N-29 minimum supported version
  entries[]          : { platform, arch, min_os, app_version, epoch_min, epoch_max,
                         artifact_digest, size, min_installable_from,
                         sbom_digest, rollout_permille, status }
  status             : ACTIVE | WITHDRAWN
  log_inclusion_proof
}
```

**Rule U-15 — verification order, all of it before a single byte is executed.**

| # | Check | Failure code |
|---|---|---|
| 1 | RTA → RMK delegation chain valid, unexpired, RMK not revoked | `UPDATE.MANIFEST.SIGNATURE_INVALID`, `UPDATE.VERIFY.KEY_REVOKED` |
| 2 | COSE_Sign1 verifies over received octets; `crit` enforced; encoding canonical | `UPDATE.MANIFEST.SIGNATURE_INVALID` |
| 3 | `manifest_version` **>** the stored high-water (S-57) | `UPDATE.MANIFEST.ROLLBACK_REFUSED` |
| 4 | `now < expires_at`, measured per [ADR-0009](ADR-0009-state-consistency.md) K-2/K-3 (the more conservative of monotonic and wall-clock elapsed) | `UPDATE.MANIFEST.STALE` |
| 5 | Transparency-log inclusion proof verifies | `UPDATE.MANIFEST.LOG_PROOF_MISSING` |
| 6 | Installed `AppVersion` ≥ `entry.min_installable_from` | `UPDATE.APPLY.FAILED` with evidence |
| 7 | Artifact SHA-256 == `artifact_digest` | `UPDATE.VERIFY.DIGEST_MISMATCH` |
| 8 | The artifact's **own platform signature** verifies (Authenticode / notarization ticket / APK signature) | `UPDATE.VERIFY.PLATFORM_SIGNATURE_INVALID` |
| 9 | Target `epoch_max` ≥ `msvp` — i.e. this is not a rollback below the minimum supported version | **`PROTO.VERSION_UNSUPPORTED`** ([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-30 already owns this condition; **no second code is minted for it**) |

**Rule U-16 — the design is TUF's four defences, not TUF's role model.** Signed metadata, monotonic
version, expiry, and threshold signing are adopted because they are the audited answers to the
audited attacks (I2's spirit). TUF's full five-role delegation hierarchy is **not** adopted: the
artifact set is small and fixed, and a second delegation hierarchy beside
[ADR-0007](ADR-0007-device-identity-and-pairing.md)'s would double the verifier surface for no gain
here. §14 revisit 8 is the trigger to reconsider.

**Rule U-17 — staged rollout.** `bucket = HMAC-SHA256(rollout_seed, release_id) mod 1000`, where
`rollout_seed` (S-58) is **local and never transmitted**, so bucketing is stable per (device,
release) and unobservable to the origin. Ladder and minimum dwell:

| Rung | `rollout_permille` | Minimum dwell | Automatic hold if |
|---|---|---|---|
| 1 | 10 (1%) | 24 h | any of the three conditions below |
| 2 | 50 (5%) | 24 h | " |
| 3 | 250 (25%) | 24 h | " |
| 4 | 500 (50%) | 24 h | " |
| 5 | 1000 (100%) | — | " |

Hold conditions: (a) crash-free device rate on the new version below the previous version's
baseline by more than **0.5 percentage points**; (b) `UPDATE.APPLY.FAILED` on more than **0.5%** of
attempts; (c) **any** increase over baseline in `POLICY.KILLSWITCH.ARM_FAILED` incidence — an
enforcement-arming regression holds the rollout immediately and unconditionally, because I3 is not
a rate to be traded.

**Rule U-18 — the bad-release kill switch is roll *forward*, not roll back.** Marking an entry
`WITHDRAWN` stops devices that have not installed it and offers the successor to those that have
(`UPDATE.RELEASE.WITHDRAWN`). An **automatic** downgrade is prohibited, because it would be a
remotely triggerable downgrade — exactly what
[ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-32 forbids. The only
downgrade path is the local, `Owner`-authenticated one of §11.13.

**Rule U-19 — full artifacts only, in Phase 1.** A binary-delta patcher is a parser applied to the
highest-value input in the system (the TM-24 class), and it is a second code path that would have
to be as trusted as the first. Artifact sizes (§9) do not justify it. §14 revisit 3 is the trigger.

**Rule U-20 — metered and low-power links.** The updater MUST consult `query_link_facts()`
([docs/networking.md](../networking.md) §5.1) and MUST NOT download on a link reporting `metered`
or `low_power` without explicit user approval; it defers with `UPDATE.CHANNEL.METERED_DEFERRED`.

**Rule U-21 — startup self-verification.** At every start, the daemon verifies its own installed
artifact digest against the stored S-57 record before arming anything. A mismatch is
`UPDATE.INTEGRITY.SELF_CHECK_FAILED` (FATAL): the daemon refuses to start the datapath, leaves
`RULESET_BLOCKED` in force, and tells the user to reinstall. Failing closed here is what makes
"tampered on disk" a named condition rather than an undefined one.

### 11.9 Why an unreachable update service cannot affect a `Session` — structurally

**Rule U-22 — the no-link assertion.** The updater is a module with **no** inbound edge from the
tunnel engine, the connection state machine, the platform network adapter, or the policy engine.
This is asserted at **build time** by extending the dependency-graph check that
[ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) §11.8 step 3 already runs in T1: the
data-plane and state-machine modules MUST NOT link the updater. A mutant that adds the edge exists
and must fail the check (§11.17, `M-P20-7`). This is the same shape of argument that discharges I5
for the control plane, applied to the management plane.

**Rule U-23 — the updater has no synchronous call in any connect, reconnect, migrate, rekey or
teardown path.** It is a scheduled task. Its failure modes are `UPDATE.CHANNEL.UNREACHABLE` at
`INFO` severity and nothing else. There is no "check for updates before connecting" step, and
adding one is a breaking change to this ADR.

**Rule U-24 — the update fetch is destination-bounded and cannot carry host traffic.** It uses a
new `UPDATE` socket registry class (requested of
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) in §11.18 (b)), modelled on that ADR's
class-13 detection probe: agent-originated only, no listener, HTTPS GET only, destinations bounded
to the pinned update-origin set, rate-limited, and reconciled against the KS-11 counters. **This
class exists because recovery would otherwise be circular**: under `FAIL_CLOSED` full-tunnel
routing a device blocked by
[ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-31 could never fetch the
update that N-31(4)(b) names as its recovery path.

### 11.10 The apply sequence and the protection-continuity contract

This is the section that discharges C2 and R-42. For each platform: what happens to the enforcement
object, whether the tunnel survives, and what the user's traffic is doing.

**Rule U-25 — the invariant that governs every row.** At **no instant** may the enforcement object
be absent while the [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) M2 latch is `UP`.
Replacement is an atomic swap between `RULESET_BLOCKED` and `RULESET_PROTECTED` (KS-17) or between
two generations of the same rule set. The latch is never cleared by an update (KS-23). Where a
platform cannot honour this, the row says so and names the residual.

| Platform | Enforcement object during the swap | Ever absent? | Tunnel drops? | Window (p95 / hard cap) | User traffic during the window | Residual |
|---|---|---|---|---|---|---|
| **Linux (kernel datapath)** | `table inet twinvpn`, kernel-resident. `nft -f` applies the whole file as **one transaction**, with `flush table` *inside* it. `nft delete table` is prohibited in every install path | **No** | **No.** The kernel `wireguard` interface and its key state outlive the userspace daemon; the new daemon **adopts** the existing owner-tagged interface rather than recreating it | Daemon absent 400 ms p95 / 5 s cap | Flows continue through the kernel; path migration and keepalive scheduling pause | None. This is the best row in the table |
| **Linux (5.4 userspace fallback)** | as above | **No** | **Yes** — the datapath *is* the process | Reconnect per [docs/reliability.md](../reliability.md) backoff, typically < 2 s | `RULESET_BLOCKED` stays live; protected traffic is **dropped, not leaked** | Outage, not leak |
| **Windows** | WFP provider and sublayer registered `FWPM_PROVIDER_FLAG_PERSISTENT` / filters `FWPM_FILTER_FLAG_PERSISTENT`, so they are BFE-resident and survive service stop. New filters are added and old-generation filters deleted **in one `FwpmTransaction`** | **No** | **Only if WinTun is replaced** (see §11.12) | Service absent 3 s p95 / 30 s cap (MSI service-stop timeout); driver replacement adds 1–4 s typical / 15 s cap | Blocked by the persistent filters throughout | Outage, not leak |
| **macOS** | `pf` anchor `twinvpn`, kernel-resident; `pfctl -a twinvpn -f <new>` is an atomic ruleset load. `pfctl -a twinvpn -F all` is prohibited. The `LaunchDaemon` is never unloaded before the new anchor is in place | **No** | **Yes.** `OSSystemExtensionManager` activation of the new version terminates the running `NEPacketTunnelProvider`; the `utun` goes away and its `NEPacketTunnelNetworkSettings` — including the default routes — are removed with it | Extension replacement 5 s p95 / **60 s watchdog** | The moment the tunnel's routes vanish, the host's original default route is live again; the `pf` anchor is what denies protected egress on it | Outage, not leak. On watchdog expiry: `UPDATE.APPLY.WINDOW_EXCEEDED`, `RULESET_BLOCKED` retained |
| **iOS / iPadOS** | **The provider *is* the enforcement.** `includeAllNetworks` exists only while the provider runs ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6 iOS row) | **Yes** | Yes | **Not bounded a priori** — the OS restarts the provider on the next network event under the on-demand rules; the window is **measured by P20-C and reported as a number** | Unsupervised: unprotected for the window. Supervised with an Always-On VPN payload configured to block when the tunnel is down: **the OS holds the block** and the window is closed | **The only row with a genuine unprotected window.** Named, measured, never claimed to be zero. Mitigation is supervision, which is an MDM capability, not an app capability |
| **Android (lockdown on)** | Lockdown is enforced by the system, not by our process | **No** | Yes — the process is replaced | Play-chosen; typically seconds | **Blocked by the OS** while our service is dead | Outage, not leak |
| **Android (lockdown off)** | None exists | n/a | Yes | n/a | Unprotected — but it was unprotected before the update too, so the update does not make it worse | The pre-existing Android residual of [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6, unchanged |
| **OpenWrt** | `table inet twinvpn`, reinstalled by our init script with `nft -f`. Our postinst reloads **only our table** and never calls `fw4 reload` | No, **for our own upgrade path** | Yes | Package replace 2 s p95 / 30 s cap | Blocked by our table | **An operator-triggered `fw4 reload` (e.g. from LuCI) rebuilds the whole firewall and produces a sub-second window we do not control.** [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6's OpenWrt "Uninstall / update ✔" should be qualified — §11.20 (a) |
| **Headless / container** | Whatever the host's enforcement is; typically the Linux row | as Linux | Orchestrator-dependent | Orchestrator-dependent | as Linux | Deferred to ADR-0023 |

**Rule U-26 — the tunnel dropping is not a leak, and the distinction is the point.** Five rows drop
the tunnel. In every one of them protected traffic is *dropped*, not *leaked*, because the
enforcement object is independent of the process being replaced. The honest summary is: **an update
costs availability on most platforms and costs protection on exactly one (unsupervised iOS), where
it is measured.**

**Rule U-27 — mobile apply timing is not ours.** On iOS and on Play-managed Android the OS chooses
when to apply. There is no "defer the update, a session is critical" capability and this ADR does
not pretend to one.

### 11.11 The failure branch — an interrupted update

**Rule U-28 — the phase journal (S-60).** Every apply writes and `fsync`s a journal record before
each phase transition. Phases: `STAGED` → `VERIFIED` → `PRE_MIGRATION_SNAPSHOT` → `SWAP_BEGIN` →
`SWAP_COMMIT` → `SETTLED`. The record carries the previous and new artifact paths, the
`ruleset_digest` observed before the swap, and the ADR-0020 pre-migration store snapshot reference.
It is readable by a recovery entry point **without the daemon running** — deliberately the same
property [ADR-0011](ADR-0011-dns-handling.md) requires of S-34.

**Rule U-29 — recovery is a function of the journal phase.**

| Phase at interruption | Recovery |
|---|---|
| `STAGED`, `VERIFIED` | Discard the staging directory. Previous version runs. `UPDATE.APPLY.FAILED` |
| `PRE_MIGRATION_SNAPSHOT` | Discard staging; the store is untouched (the snapshot is a copy, not a move). Previous version runs |
| `SWAP_BEGIN` | Platform-specific rollback: Windows Installer rollback; macOS restores the swapped-out `.app`; Linux/OpenWrt reinstall the previous package from the retained artifact. `UPDATE.APPLY.ROLLED_BACK` |
| `SWAP_COMMIT` | The new version is installed. Complete the settle steps; if the new version fails to start twice consecutively, the previous version is restored from the retained artifact and `UPDATE.APPLY.ROLLED_BACK` is emitted |
| `SETTLED` | Nothing to do |

**Rule U-30 — the two-state guarantee, and what backs it.** After any interruption, the installed
version is **exactly** the previous one or **exactly** the new one, verified by digesting the
installed artifact against the manifest. If neither matches, that is
`UPDATE.INTEGRITY.SELF_CHECK_FAILED` at FATAL and the daemon refuses to run the datapath while
leaving `RULESET_BLOCKED` in force. There is no "run it anyway and hope" path.

**Rule U-31 — the enforcement object is checked, not assumed.** On recovery, the installed
`ruleset_digest` is compared against the journal's `ruleset_digest_before`. A mismatch means
continuity cannot be asserted, so the recovery re-arms `RULESET_BLOCKED` from the boot artifact and
emits `UPDATE.APPLY.FAILED` rather than silently continuing.

### 11.12 The WinTun driver version-mismatch replacement path

[docs/networking.md](../networking.md) §5.3 requires: "On startup the adapter compares the loaded
driver version against the shipped version and re-installs on mismatch, emitting
`NET.DRIVER_REPLACED`." The packaging half of that is:

1. WinTun ships **app-local** in the install directory, never system-wide, and is versioned with
   the app (R-19). Its upstream digest and version are recorded in the SBOM and the manifest.
2. At service start, the shipped version is compared with the loaded driver version. **The
   comparison happens before any adapter is created**, so a mismatch never produces a
   half-configured interface.
3. On mismatch, while `RULESET_BLOCKED` is live: `WintunCloseAdapter` → `WintunDeleteDriver` → load
   the shipped binaries → `WintunCreateAdapter`. `NET.DRIVER_REPLACED` is emitted
   ([docs/networking.md](../networking.md) §5.3 owns this code; no second code is minted).
4. The WFP filters are **untouched** by any of it, because they are persistent BFE objects and not
   adapter-scoped. Protection holds across the driver replacement.
5. If the driver cannot be deleted because it is in use by another process, the update is
   **deferred, not half-applied**: the previous version continues to run against the previous
   driver, `UPDATE.APPLY.REBOOT_REQUIRED` is emitted, and the swap is retried after the next
   restart. The updater MUST NOT force a reboot.
6. If replacement fails outright: `PLATFORM.ADAPTER_UNAVAILABLE`
   ([docs/architecture.md](../architecture.md) §2.5.1 owns it), the client stays in
   `RULESET_BLOCKED`, and the datapath is not started.

### 11.13 Install, upgrade, downgrade, uninstall as state transitions

**Install layout.**

| Platform | Program | Config | Local store (ADR-0020) | Identity (S-01) | Boot artifact |
|---|---|---|---|---|---|
| Linux | `/opt/twinvpn` or distro paths | `/etc/twinvpn` | `/var/lib/twinvpn` (`StateDirectory`) | TPM handle in the kernel keyring, or a 0600 file | `twinvpn-killswitch.service`, `/etc/twinvpn/killswitch.nft` |
| Windows | `%ProgramFiles%\TwinVPN` (incl. WinTun) | `HKLM` policy + `%ProgramData%\TwinVPN` | `%ProgramData%\TwinVPN\store` | CNG / Platform Crypto Provider | WFP persistent provider + sublayer |
| macOS | `/Applications/TwinVPN.app` (incl. the system extension) | `/Library/Application Support/TwinVPN` | same | Secure Enclave via Keychain | `LaunchDaemon` + `/etc/pf.conf` anchor line |
| iOS / iPadOS | app container | app group container | app group container | Keychain, `AfterFirstUnlockThisDeviceOnly` | none available |
| Android | APK, per-app data dir | same | same | Android Keystore | OS lockdown setting |
| OpenWrt | `/usr/sbin`, `/usr/lib/twinvpn` | `/etc/twinvpn` + UCI | `/etc/twinvpn/store` (overlay) | file-backed, `hardware_backed = false` | init script + our nftables include |

**Rule U-32 — upgrade preserves state or fails.** An upgrade MUST NOT delete the local store or
the device identity (R-42). ADR-0020's migration runs on the new version's first start,
forward-only, after the S-60 `PRE_MIGRATION_SNAPSHOT` copy is taken. The snapshot is retained until
the new version has run **cleanly once** — defined as one successful start plus one successful
`apply(contract_generation)` ([docs/networking.md](../networking.md) §5.1) — after which it is
deleted. Within that retention window a downgrade can read the pre-migration copy; after it, a
downgrade gets ADR-0020's typed refusal, exactly as
[docs/testing-strategy.md](../testing-strategy.md) §2.15's downgrade row requires: read it, or
refuse with a typed `reason_code`, never crash or silently discard.

**Rule U-33 — downgrade.** Two paths, and only two.

| Path | Rule |
|---|---|
| Below the MSPV | **Refused at install time, before the old binary runs** ([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-30), with `PROTO.VERSION_UNSUPPORTED`. The gate is in **the installer package itself**, not only in our updater — an MSI `LaunchCondition` custom action, a `.pkg` preinstall script, and a `preinst` in deb/rpm — because a user can run an old installer directly. On iOS the path does not exist; on Android the platform refuses it |
| Within the supported window | Permitted **only** by a local, `Owner`-authenticated action mirroring [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-21(1)(2)(3): local interactive action, OS-mediated administrator authentication, and a confirmation naming the consequence. It MUST lower the device's own S-37 floors ([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-20/N-32) and the `Owner` MUST be told, by peer name, that each affected peer needs an explicit "accept downgrade for this device" action |

**Rule U-34 — uninstall, in this order.** The ordering is the mirror of KS-17: the enforcement
object is removed **last**, after there is nothing left to protect.

1. Request a graceful disconnect over ADR-0017's management interface and wait up to
   `T_UNINSTALL_DRAIN = 10 s`. If the daemon is unresponsive, proceed — leaving the host protected
   by a product that no longer exists is the "permanently broken" outcome
   [docs/networking.md](../networking.md) §5.5.3 forbids.
2. `set_link(down)`; `destroy_interface()` (idempotent, safe after crash).
3. **Windows only**: `WintunDeleteDriver` and remove the adapter. **No orphaned adapter may
   remain** ([docs/networking.md](../networking.md) §5.3).
4. Restore the host resolver from `S-34` `HostResolverRestorePoint`
   ([ADR-0011](ADR-0011-dns-handling.md)) before removing any resolver configuration.
5. Remove **all** owner-tagged state: the WFP provider, sublayer and persistent filters; the
   nftables table; the `pf` anchor and its `/etc/pf.conf` line; policy-routing rules and `fwmark`
   entries; and the boot artifacts. Owner-tagging is what makes this exhaustive rather than
   best-effort ([docs/networking.md](../networking.md) §5.5.3).
6. Remove program files and units.
7. Offer to remove the local store and the identity; **default is remove**.

**Rule U-35 — identity on uninstall is platform-dependent and MUST NOT be assumed either way.**
Android deletes Keystore keys on uninstall, so the identity is destroyed. iOS Keychain persistence
across app deletion is **not a documented guarantee and has changed between releases**, so the
client MUST handle both outcomes on the next install: identity present and store gone ⇒ rehydrate
from the identity; identity gone ⇒ `AUTH.IDENTITY_MISSING` and re-enrolment, which
[ADR-0007](ADR-0007-device-identity-and-pairing.md) N-7 makes a first-class flow rather than an
error. On Windows, macOS and Linux the uninstaller deletes the key handle by default and offers
"keep for reinstall".

**Rule U-36 — uninstall is not revocation.** An uninstalled device's `DeviceIdentity` remains valid
at every peer until the `Owner` revokes it
([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.7). The uninstaller MUST say so, and
ADR-0019 owns the wording. Assuming otherwise is the mistake this rule exists to prevent.

### 11.14 Release engineering, channel promotion, and the security fast path

**Rule U-37 — this ADR creates no release criterion of its own.**
[docs/testing-strategy.md](../testing-strategy.md) §6.5 is the exhaustive blocker list and §6.1 is
the tier definition. Channel promotion binds to them:

| Promotion | Gate |
|---|---|
| → `NIGHTLY` | T2 green (§6.1) |
| → `BETA` | T3 green, and not two consecutive red nights (§6.1 T3 row) |
| → `STABLE` | **T4 green and none of B-1 … B-20** (§6.5) — the range now includes this ADR's own owed row, which the earlier `B-1 … B-19` spelling excluded — with evidence bound to an exact commit or immutable snapshot per C-5 |
| Rung advance within `STABLE` | U-17's dwell and hold conditions |

**Rule U-38 — the security fast path.** It bypasses U-17's ladder, going to 100% at once. It does
**not** bypass §6.5. Authorization requires all of: (a) a classification of CVSS ≥ 7.0 **or** any
defect that defeats I1, I3 or I4; (b) two-person authorization from the RMK signing quorum, logged;
(c) a **T4-S** run — everything in T4 except the 72 h soak (§2.17) and the full compatibility
matrix (§2.18) — with the omitted work running **after** release and the release being
**automatically withdrawn** (U-18) if it fails. The residual is stated plainly: the fast path ships
on less evidence, deliberately, trading one risk against another. C-6's honest-release rule still
binds — the limitation is *known* and named, not produced by a disabled or retried-into-green test.

**Rule U-39 — the per-release artifact matrix** is itself a signed manifest entry set, and a
release is incomplete until every row exists: iOS/iPadOS (arm64); macOS universal (x86_64 +
arm64); Windows (x64, arm64); Android (arm64-v8a, armeabi-v7a, x86_64) in both channels; Linux deb
(amd64, arm64, armhf), rpm (x86_64, aarch64), tarball (x86_64, aarch64); OpenWrt ipk (`mips_24kc`,
`mipsel_24kc`, `arm_cortex-a7`, `aarch64_cortex-a53`). A missing row is a missing release, not a
partial one, except where the row is removed from the supported matrix in the same release —
which §6.5 B-8 already governs.

### 11.15 Managed deployment, MDM, and the kill-switch tension resolved

The tension is real: [docs/architecture.md](../architecture.md) §2.21 forbids a pushed
configuration from disabling the kill switch without explicit `Owner` action, and
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-21 requires a *local interactive* action
plus OS-mediated administrator authentication. MDM is by definition remote and non-interactive. The
resolution has four parts.

**Rule U-40 — a managed profile may only raise enforcement, never lower it.** KS-22's monotone rule
governs: effective mode is `max(local_mode, profile_required_mode)` over
`OFF < ARMED_ON_INTENT < ALWAYS_ON`. An MDM push that turns the kill switch **on** is permitted and
encouraged. One that turns it **off** is not expressible in the profile schema at all — an absent
message type cannot be forged, which is the same structural argument KS-22 makes.

**Rule U-41 — remote disable is not supported, and the alternative is named.** An enterprise that
wants enforcement relaxed for a captive-portal-heavy estate gets `portal_policy = PROMPT` and
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.7's time-boxed exemption, or a
per-device local `Owner` action. There is no fleet-wide disable, and requests for one are answered
with this rule rather than with a feature.

**Rule U-42 — but the platform's MDM outranks us, and that must be said.** On a supervised or
managed device the MDM administrator can remove the app, remove the VPN payload, or remove the
Always-On configuration. The OS grants them that authority; we cannot refuse it. **On such a device
the MDM administrator is an `Owner`-class principal for KS-21(2).** Where the MDM administrator and
the TwinVPN `Owner` are different people, the administrator can remove protection and the `Owner`
cannot prevent it. This residual is new to the corpus and belongs in the threat model — §11.20 (c).
Detection: the client observes profile or configuration removal and reports it as an unmissable
standing state; the presentation is ADR-0019's.

**Rule U-43 — the deployment profile.** A signed `DeploymentProfile` (a B2 signed statement,
signed by the operator's own key in the self-hosted case) delivered per platform via Apple MDM
managed app configuration, Intune app configuration or MSI public properties, Android Enterprise
managed configurations (`RestrictionsManager`), or a file dropped in `/etc/twinvpn/deployment.d/`.

| Permitted content | Forbidden content |
|---|---|
| Control-plane, rendezvous and relay endpoints (the self-hosted operator case) | Any `DeviceKey` material or import of one (**I4**, C6) |
| The `OwnerTrustAnchor` (S-32) to pin at first run | Any lowering of enforcement, any disarm (U-40) |
| Update channel, update origin mirror, update policy, check-in enable/disable | Any `AccessPolicy` or `DNSPolicy` content — those are the `Owner` authority's to author (S-06, S-07) |
| An enforcement **floor** | The RTA pin — a mirror may serve bytes, it may not change who signs them |
| Telemetry sink and diagnostic tier | Anything that would make the update service a connectivity dependency (C1) |

A profile containing **any** forbidden field is rejected **wholesale**, never field-by-field, so
there is no partial-application ambiguity: `UPDATE.MANAGED.CONFIG_REJECTED`.

**Rule U-44 — the self-hosted operator's escape hatch, and its cost.** An operator who wants their
own signing root builds their own client from source; it is then their product, with their RTA,
their signatures, no support from us, and **no upgrade path from our builds** (a signature change
on every platform). This is deliberately available and deliberately unattractive; the supported
path is our signed artifacts plus their signed `DeploymentProfile` plus their mirror.

### 11.16 Reason codes contributed to the `UPDATE` domain

`UPDATE` is a **new domain** ([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 owns the
taxonomy; this ADR owns the codes within the domain). Its registration is an obligation on
ADR-0015 — see §11.20 (b), including the fallback if the integrator refuses a fourteenth domain.
All codes are ≤ 3 segments and carry the full attribute set of §11.2; the table gives the
discriminating attributes.

| `reason_code` | class | severity | terminal | user_actionable | Condition / next action |
|---|---|---|---|---|---|
| `UPDATE.CHANNEL.UNREACHABLE` | TRANSIENT | INFO | false | false | The update origin is unreachable. The installed version keeps running, protected. **Never affects a `Session`** (C1) |
| `UPDATE.CHANNEL.METERED_DEFERRED` | POLICY | INFO | false | true | Download deferred on a metered or low-power link. Next: connect to an unmetered network, or approve the download |
| `UPDATE.MANIFEST.SIGNATURE_INVALID` | PERSISTENT | CRITICAL | false | false | The release manifest failed verification against the pinned anchor. Security event. The artifact is discarded automatically |
| `UPDATE.MANIFEST.ROLLBACK_REFUSED` | POLICY | CRITICAL | false | false | A manifest below the stored high-water was offered (S-57). Rollback attempt; refused |
| `UPDATE.MANIFEST.STALE` | PERSISTENT | WARN | false | true | The manifest is older than the freshness bound — a freeze attempt or a stalled mirror. Next: check the configured update origin |
| `UPDATE.MANIFEST.LOG_PROOF_MISSING` | PERSISTENT | CRITICAL | false | false | No verified transparency-log inclusion proof. Installation refused (U-7) |
| `UPDATE.VERIFY.DIGEST_MISMATCH` | PERSISTENT | CRITICAL | false | false | The downloaded artifact does not match the signed digest. Discarded; retried once from a different origin |
| `UPDATE.VERIFY.PLATFORM_SIGNATURE_INVALID` | PERSISTENT | CRITICAL | false | false | The artifact's Authenticode, notarization or APK signature failed. Discarded |
| `UPDATE.VERIFY.KEY_REVOKED` | PERSISTENT | CRITICAL | false | true | The signing key that produced this artifact is revoked. Next: reinstall from the platform channel |
| `UPDATE.APPLY.STAGED` | TRANSIENT | INFO | false | false | Verified and staged, awaiting the apply window |
| `UPDATE.APPLY.FAILED` | PERSISTENT | ERROR | false | true | Apply failed. **The previous version is running and protected** (C3). Next: retry, or send a diagnostic bundle |
| `UPDATE.APPLY.ROLLED_BACK` | PERSISTENT | WARN | false | false | Apply was interrupted and the previous version was restored (U-29) |
| `UPDATE.APPLY.REBOOT_REQUIRED` | POLICY | WARN | false | true | The update is staged but a restart is required (the WinTun in-use case, §11.12 step 5). The previous version keeps running. Next: restart when convenient |
| `UPDATE.APPLY.WINDOW_EXCEEDED` | PERSISTENT | CRITICAL | false | false | The §11.10 protection-continuity budget was exceeded during apply. Evidence: `{phase, platform, elapsed_ms}`. `RULESET_BLOCKED` is retained |
| `UPDATE.APPLY.STORAGE_INSUFFICIENT` | PERSISTENT | ERROR | false | true | Not enough free space to apply safely (the OpenWrt overlay case). Next: free the stated number of bytes |
| `UPDATE.RELEASE.WITHDRAWN` | POLICY | WARN | false | true | The installed version has been withdrawn. Next: update now. **Never an automatic downgrade** (U-18) |
| `UPDATE.POLICY.MANUAL_ONLY` | POLICY | INFO | false | true | This deployment tier never self-installs. An update is available and awaits the operator |
| `UPDATE.MANAGED.CONFIG_REJECTED` | POLICY | ERROR | false | true | A pushed deployment profile contained a forbidden field and was rejected wholesale (U-43). Next: correct the profile |
| `UPDATE.MANAGED.CHANNEL_PINNED` | POLICY | INFO | false | false | Updates are governed by a managed channel; this device will not self-update |
| `UPDATE.INTEGRITY.SELF_CHECK_FAILED` | FATAL | CRITICAL | **true** | true | The running installation failed its own startup integrity check (U-21). The datapath is not started and `RULESET_BLOCKED` is held. Next: reinstall |

**Deliberately not registered.** The install-time refusal of a below-MSPV rollback emits
[ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)'s
`PROTO.VERSION_UNSUPPORTED`, not a second code; the WinTun replacement emits
[docs/networking.md](../networking.md) §5.3's `NET.DRIVER_REPLACED`; an adapter that cannot be
created emits `PLATFORM.ADAPTER_UNAVAILABLE`; a deprecated epoch emits `PROTO.VERSION_DEPRECATED`.
Minting a parallel code for an already-registered condition would violate
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 rules 1–3.

### 11.17 Proof test P20 — conformance surface

**P20 — A hostile, downgraded, or interrupted update cannot execute, downgrade, or unprotect.**

| | |
|---|---|
| **Proves** | R-40, R-41, R-42, R-43; **I3**, **I6**, **I8** |
| **Lab scenario** | `S-UPD-FORGE-*`, `S-UPD-ROLLBACK-*`, `S-UPD-CONTINUITY-*`, `S-UPD-INTERRUPT-*`, run per platform of [docs/testing-strategy.md](../testing-strategy.md) §3.7 |
| **Preconditions (V3)** | Enforcement armed and confirmed by a `ProtectionAssertion` for both families; `ruleset_digest` recorded; a marked traffic generator running **independently of the agent**; an exec-audit channel available on the platform under test; a controlled update origin and a controlled transparency log |
| **Assumptions** | A-08, A-02, A-16; ADR-0020's pre-migration retention |

**Procedure A — forged artifact.** Four runs, one condition each: (1) a manifest signed by a key
outside the RTA chain; (2) a validly signed manifest whose artifact bytes are mutated; (3) a valid
manifest and artifact whose platform signature has been stripped; (4) a valid everything with no
transparency-log inclusion proof.
**Oracle.** Nothing installs; the installed artifact digest is byte-identical before and after;
the exec-audit channel shows **no execution of any path under the staging directory**; and the
expected one of `UPDATE.MANIFEST.SIGNATURE_INVALID` / `UPDATE.VERIFY.DIGEST_MISMATCH` /
`UPDATE.VERIFY.PLATFORM_SIGNATURE_INVALID` / `UPDATE.MANIFEST.LOG_PROOF_MISSING` is emitted.

**Procedure B — rollback and freeze.** (1) Replay a previously valid manifest with a lower
`manifest_version` ⇒ `UPDATE.MANIFEST.ROLLBACK_REFUSED`. (2) Freeze the origin on a valid manifest
and advance the clock past `expires_at` ⇒ `UPDATE.MANIFEST.STALE`. (3) Run the previous-version
installer package directly, with a target `epoch_max` below the MSPV ⇒ refused with
`PROTO.VERSION_UNSUPPORTED` **and the exec-audit channel shows the old binary never executed**
([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-30's "before the old
binary runs" is the assertion, not the intention).

**Procedure C — protection continuity during a real apply.** Run the real update path with the
independent marked generator running, sampling the enforcement object at **1 ms**. Deliberately the
same rig as **P09** procedure C.
**Oracle.** Zero marked bytes on any non-overlay interface, both families, across the whole event;
the enforcement object is present at **every** sample (an atomic swap yields at most one sample
showing the new digest, never a sample showing absence); `ruleset_digest` before and after are
either equal or differ exactly once; and the measured apply window is recorded **as a number per
platform** and compared with the §11.10 budget, exceeding it via
`UPDATE.APPLY.WINDOW_EXCEEDED`.

**Procedure D — interrupted apply.** Kill the updater at each S-60 phase boundary (one per run),
and separately cut power (VM reset) at each.
**Oracle.** On restart the installed artifact digest matches **exactly** the previous or **exactly**
the new manifest entry — never a third value; the local store opens and its schema version is one
of the two expected values; the device identity is present and a handshake to a known
`TrustedPeer` succeeds; the enforcement object is present with a digest matching one of the two
expected values; and where the journal's `ruleset_digest_before` mismatched, `UPDATE.APPLY.FAILED`
was emitted rather than a silent continue.

**Mutants (V2).**

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P20-1` | Manifest signature verified, artifact digest not | A-2 installs a mutated artifact |
| `M-P20-2` | No monotonic high-water on `manifest_version` | B-1 installs the replayed manifest |
| `M-P20-3` | Apply removes the rule set then re-adds it (KS-23 violation) | C shows a sampled gap. **Shared with `M-P09-3`** — declared here so the sharing is explicit and not a hidden duplicate |
| `M-P20-4` | Apply deletes the local store instead of migrating | D loses the store; the identity handshake fails |
| `M-P20-5` | Inclusion-proof check skipped when the log is unreachable (fail-open) | A-4 installs |
| `M-P20-6` | The MSPV gate runs after the binary starts rather than before | B-3's exec audit shows the old binary executed |
| `M-P20-7` | The updater module is linked from the connection state machine | The §11.9 U-22 build-time dependency assertion fails in T1 |

**Positive control (V4).** The same rig with verification disabled by a build flag **MUST** install
the forged artifact of A-1 and execute it. Without that control, "nothing installed" is not
evidence that the harness could have delivered a hostile update at all.

**Pass criteria.** All four procedures × all supported platforms (subject to the limits below) ×
both families: no forged or downgraded artifact executes; zero marked bytes except where §11.10's
iOS row declares a measured window instead; the two-state property holds at every phase boundary;
all seven mutants fail; positive controls green.

**Known limits, stated rather than papered over.** On **iOS/iPadOS** and on **Play-managed
Android** the store is the installer, so **procedures A, B and D are not executable at all**. They
run against the Android secondary channel where one exists; on iOS they do not run, and the
corresponding assurance is **inherited from Apple's channel as an assumption, not a test**.
Procedure C runs everywhere, degrading on iOS exactly as **P09** does — a companion-host wire
capture and a measured window rather than an asserted zero.

### 11.18 Interfaces required from other ADRs

| # | Required interface | Owner |
|---|---|---|
| (a) | Confirmation that `RemoveExistingProducts`-style upgrade paths are distinguishable from a true uninstall at the enforcement layer, so an upgrade never deletes the persistent enforcement objects while an uninstall does | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6 |
| (b) | **A fourth socket registry class `UPDATE`** in [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.5's KS-10 table and a corresponding class in §11.2: agent-originated, no listener, HTTPS GET only, **destination-bounded** to the pinned update-origin set, rate-limited, counters reconciled per KS-11. Modelled on class 13, not on `BOOTSTRAP`. **Without it, a device blocked by [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-31 under full-tunnel `FAIL_CLOSED` can never fetch the update N-31(4)(b) names as its recovery path** | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) |
| (c) | The MSPV value in the signed released-version registry entry (S-23) that N-29 refers to, in a form the installer can read **offline, before execution** | [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) |
| (d) | S-37 floor lowering as an idempotent local operation an authorized downgrade can invoke, with the per-peer notification list N-32 requires | [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-20, N-32 |
| (e) | A store whose schema migration is forward-only, whose pre-migration snapshot is a **copy** (never a move), and which refuses an unknown newer schema with a typed `reason_code` rather than crashing or discarding | ADR-0020 |
| (f) | `update check / stage / apply / rollback / status` as verbs on the single local management interface, authenticated to an administrator principal, with no privileged side channel of its own | ADR-0017 |
| (g) | Confirmation that the shell and the portable core are one build unit and one artifact (U-8), and that the core builds reproducibly and targets 16 KB ELF page alignment for Android | ADR-0018 |
| (h) | The rule governing **when** an apply may run on a mobile OS (foreground, charging, unmetered), and the guarantee that the updater is never the reason a background execution budget is consumed | ADR-0022 |
| (i) | The router/headless resource budget (RAM, CPU) against which §9's flash budget is the packaging half; and confirmation that `MANUAL_ONLY` is the correct default for that tier | ADR-0023 |
| (j) | The administrator principal that OS-mediated authentication authenticates against for U-33's downgrade and U-34's uninstall — the same principal KS-21(2) uses | [ADR-0007](ADR-0007-device-identity-and-pairing.md), ADR-0016 |
| (k) | Registration of the `UPDATE` domain in the taxonomy, or an explicit refusal (see §11.20 (b)) | [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 |

### 11.19 State ownership

New rows for [docs/architecture.md](../architecture.md) §5, in that table's seven-column format.

| # | State | Authoritative writer | Replicas / caches (staleness tolerance) | Consistency class | Durability | On conflict |
|---|---|---|---|---|---|---|
| **S-57** | `InstalledRelease` — `{app_version, release_id, artifact_digest, manifest_version_high_water, channel, installed_at}` | **Local `Device`** (the privileged updater, ADR-0016), writing through 2.20 | The Update Service (2.21) holds an aggregate count with **no authority**; S-23 is a different fact (the *released* registry, not what *this* device installed) | `MONOTONIC` — `manifest_version_high_water` MUST NOT decrease; `app_version` may decrease only via the U-33 local `Owner`-authenticated path | Durable; MUST survive the update that writes it, and MUST be written before `SWAP_COMMIT` | Higher `manifest_version` wins; a lower one is a rollback attempt and is refused with `UPDATE.MANIFEST.ROLLBACK_REFUSED` |
| **S-58** | `UpdateIdentity` — `{rollout_seed (never transmitted), report_epoch_id, report_epoch_started_at}` | **Local `Device`** | The update origin sees `report_epoch_id` only, for at most the current 30-day epoch, with no linkage to `device_id` | `LOCAL` | Durable. `rollout_seed` is stable for the life of the install; `report_epoch_id` rotates every 30 days | Local wins. Absence ⇒ generate fresh, which places the device in a new rollout bucket — a stated, accepted consequence |
| **S-59** | `UpdatePolicy` — `{channel, auto_install, metered_policy, origin_url, managed_pin}` — the **effective** policy computed from the local preference and any `DeploymentProfile` | **Local `Device`** (a managed profile is an *input* the device evaluates, never a second writer — **I8**) | None | `LOCAL` | Durable | Local wins. A managed profile may pin the channel and raise the enforcement floor; it may never lower enforcement (U-40) and may never write the RTA pin, which is build-time |
| **S-60** | `UpdateApplyJournal` — `{transaction_id, phase, previous_artifact, new_artifact, ruleset_digest_before, store_snapshot_ref, started_at}` | **Local `Device`** (the privileged updater) | None | `LOCAL` | **Durable, `fsync`ed before every phase transition, and readable by the recovery entry point without the daemon running** | Local wins. A journal whose `ruleset_digest_before` does not match the installed rule set means continuity cannot be asserted ⇒ re-arm `RULESET_BLOCKED` from the boot artifact and emit `UPDATE.APPLY.FAILED` |

**Why S-57 does not collide with S-23.** S-23 is the *released-version registry*, authored by the
Update Service on the management plane. S-57 is *what this device has installed*, authored by the
device. Two facts, two writers, no shared row — I8 holds.

### 11.20 Obligations placed on other documents

Reported, not made — this ADR modifies no existing file.

**(a) [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6.** The OpenWrt row's
"Uninstall / update ✔" should be **qualified**: our own upgrade path never removes the table, but
an operator-triggered `fw4 reload` rebuilds the whole firewall and produces a sub-second window we
do not control. §11.10's OpenWrt row states the residual; the durability table should reflect it as
◐ with a pointer here. ADR-0012 also owes §11.18 (a) and (b).

**(b) [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2.** The domain table needs an
`UPDATE` row: *"`UPDATE` — packaging, distribution, signing, and update delivery (owner: ADR-0021)"*.
This is in **tension with §11.2's statement that "the thirteen above are closed"**, and the tension
is stated rather than glossed. The case for a fourteenth domain: the update path is a distinct
trust boundary on a distinct plane (management), with no existing owner, and every candidate host
domain is wrong — `PLATFORM` is the Platform Network Adapter's OS-integration surface,
`CONTROL` is the control plane, and `PROTO` is the wire contract. **The fallback, if the integrator
holds the thirteen closed:** every code in §11.16 remaps mechanically to `PLATFORM.UPDATE.*`
(e.g. `UPDATE.APPLY.FAILED` → `PLATFORM.UPDATE.APPLY_FAILED`), staying within three segments. The
decision is ADR-0015's; this ADR states both forms so neither outcome requires a redesign.

**(c) [docs/threat-model.md](../threat-model.md).** Two gaps, both new:

1. **There is no supply-chain threat row.** §5's table has nothing for a forged or tampered
   update, and §15's open issues do not name it. Proposed: a `TM` row — *"Malicious or tampered
   client update"* — boundary TB-12 / all assets, mitigation §11.3–§11.5 and P20, residual
   "a compromised RTA is unmitigated in-band; Apple and Google each hold a signing key we do not
   control; detection via the transparency log", detection `UPDATE.MANIFEST.SIGNATURE_INVALID`,
   `UPDATE.VERIFY.DIGEST_MISMATCH`, `UPDATE.INTEGRITY.SELF_CHECK_FAILED`. §12's key-lifecycle table
   should gain columns for RTA and RMK.
2. **The MDM-administrator residual of U-42** is not stated anywhere: on a managed device the MDM
   administrator is an `Owner`-class principal for KS-21(2), and where they differ from the
   TwinVPN `Owner` they can remove protection without the `Owner`'s consent.

**(d) [docs/testing-strategy.md](../testing-strategy.md). — APPLIED.** §4.3 registers **P20**
(§11.17). This ADR originally owed §6.5 **two** rows; the reconciliation resolved them into
**one**, because the first was redundant:

- The row for *P20 failing under the PT-1/V2/V4 shape* is **subsumed by B-1**, which now reads
  **P01–P22** rather than P01–P15. A separate row would have made P20 the only proof test gated
  twice while P16–P19, P21 and P22 were gated not at all.
- The artifact-integrity row **is** owed and is now **B-20**: any released artifact lacking a
  valid platform signature, an RMK-signed manifest entry, a published SBOM, or a
  transparency-log inclusion proof. It is not a proof-test row, so nothing else covers it.

**There is no B-21.** The earlier draft of this subsection named one; §6.5 stops at B-20, and the
`STABLE` gate above cites `B-1 … B-20`. §2.15's "Interrupted upgrade" row is **consumed
unchanged** and is P20 procedure D's parent.

**(e) [docs/vision.md](../vision.md).** §5 gains R-40 … R-43 (§2); §7's requirement-to-ADR index
gains a row for ADR-0021 discharging R-19 (jointly with
[docs/architecture.md](../architecture.md) §2.5), R-40, R-41, R-42, R-43.

**(f) [docs/architecture.md](../architecture.md).** §5 gains S-57 … S-60; §2.21's "State owned"
row should name S-23 **and** point here for the device-side S-57.

### 11.21 Obligations placed on this ADR by sibling ADRs

Every row is explicitly confirmed or refined, following the house convention of
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.14. Silence would be a Phase 1 defect.

| Obligation as placed | Verdict | Where discharged |
|---|---|---|
| **ADR-0016 MX-1** — macOS is a NetworkExtension **system extension**, **Developer ID + notarized**, alongside a package-installed `LaunchDaemon`; MX-2 (Mac App Store) rejected because it forfeits KS-19 | **CONFIRMED, and arrived at independently.** §11.1 selects Developer ID + notarization as the macOS channel and refuses the Mac App Store on exactly the KS-19 ground — a sandboxed MAS app cannot install a `LaunchDaemon` or load a `pf` anchor, deleting the boot-enforcement cell of [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6's macOS row. **No fork exists between the two ADRs** | §11.1, §11.2 macOS row, §12 (1) |
| **ADR-0017 §11.14(f)** — the management-interface endpoint's containing directory is created by the init system with a privileged owner; the `twinvpn` group on Linux and `TwinVPN Users` group on Windows; the polkit policy file for `org.twinvpn.manage.disarm`; the pipe DACL | **CONFIRMED**, with the installer/runtime split made explicit: the package creates the *containers and the groups*, the daemon creates the *endpoint and its DACL* | **U-45** |
| **ADR-0017 A-6** — agent and CLI ship as one package, which is what makes its two-epoch skew window defensible | **CONFIRMED on every channel.** U-8 already requires the shell and the portable core to be one artifact; U-45 extends the same rule to the CLI. ADR-0017's A-6 therefore does **not** trigger and its 90-day window does not need to lengthen toward [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)'s 12-month wire window | **U-45**, U-8 |
| **ADR-0019 X5** — a signed catalogue, catalogue-only updates without a registry bump, and the shipped build's **achievable** enforcement posture queryable so the macOS rule can refuse to over-claim | **CONFIRMED**, in two mechanisms | **U-46**, **U-47** |

**Rule U-45 — the package creates the container and the group; the daemon creates the endpoint and
its DACL.** An installer-written access-control list would be stale the moment the daemon restarted,
so the split is deliberate.

| Platform | Created by the package | Created by the daemon at runtime |
|---|---|---|
| Linux | The system group `twinvpn`, created **empty** (`addgroup --system`); `RuntimeDirectory=twinvpn`, `RuntimeDirectoryMode=0750`, owner `root:twinvpn`, declared in `twinvpnd.service` so **`systemd`**, not the daemon, creates it; the polkit policy at `/usr/share/polkit-1/actions/org.twinvpn.policy` declaring `org.twinvpn.manage.disarm` with `allow_any=no`, `allow_inactive=no`, `allow_active=auth_admin_keep` | The socket inside that directory, mode `0660`, `root:twinvpn` |
| Windows | The local group `TwinVPN Users`, created **empty** by the MSI | The named pipe and its **explicit** DACL — SYSTEM and Administrators full control, `TwinVPN Users` read/write, no NULL DACL — resolved against the group SID at creation |
| macOS | The `LaunchDaemon` plist and `/var/run/twinvpn` at `0750 root:wheel` | The socket; and registration of the Authorization Services right `org.twinvpn.manage.disarm`, which lives in the policy database and is not an installer artifact |
| OpenWrt / headless | The `procd` init script and the runtime directory | The socket |

Both groups are created **empty**. Membership is an administrator action, never an install-time
default, so a fresh install grants no unprivileged process access to the management interface.
**The daemon, the CLI, and the platform shell are one package on every channel** (U-8): there is no
configuration in which a device runs a CLI of one version against a daemon of another.

**Rule U-46 — the diagnostic catalogue is a separately versioned, signed sub-artifact.** It carries
its own monotonic `catalogue_version` and digest inside the same `ReleaseManifest`, and:

- it **MAY** advance without an `AppVersion` or `ProtocolEpoch` bump — which is safe precisely
  because [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 rule 4 makes the code the
  contract and the human text not;
- it **MUST NOT** introduce, rename, or retire a `reason_code`. The registry is append-only and
  ships with the build; a catalogue may only supply or revise **text** for codes the installed
  build already knows, and an entry for an unknown code is ignored, leaving rule 5's `DOMAIN`-prefix
  degradation in force;
- it contains **no executable code**, which is what makes a catalogue-only update deliverable on
  iOS and iPadOS **without App Store review** — the reason ADR-0019 asked for it;
- it is verified by the full U-15 chain. Failure leaves the built-in catalogue in force and emits
  `UPDATE.VERIFY.DIGEST_MISMATCH`; a catalogue is never a reason to refuse to start.

**Rule U-47 — every build carries a signed `EnforcementCapabilityProfile` declaring what this
artifact can ACHIEVE.** This is a **build-time** fact — a function of the channel and of what the
packaging is permitted to install — and it is distinct from the runtime probe, which reports what
is actually in force. A macOS Developer ID artifact carrying the system extension and the
`LaunchDaemon` declares `killswitch_boot_enforced` achievable; **no iOS artifact ever can**. The
token vocabulary is [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) §11.11's
(`killswitch_os_enforced`, `killswitch_boot_enforced`, per
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.12(g)); this ADR contributes only the
build-time upper bound and its signature. A consumer MUST render the **minimum** of achievable and
actual, and MUST NOT claim a posture the shipped artifact cannot deliver even when a runtime probe
is inconclusive — an `UNKNOWN` probe on a build that cannot achieve the posture resolves to
*cannot*, never to *probably*.

### 11.22 Assumptions register

Format per [docs/architecture.md](../architecture.md) §9. §11.21 above records obligations placed on this ADR; this table records what this ADR assumes of others.

| # | Assumption | Depends on | If it is wrong, this changes |
|---|---|---|---|
| **U-A1** (**H1**) | One portable core with a stable C ABI plus thin native shells, shipped as a **single artifact** per platform | ADR-0018 | U-8 collapses: `CoreAbiVersion` becomes a negotiated runtime axis, §11.6 grows a fourth version number and a real compatibility matrix, and §11.10's "replace one thing" sequences become two-phase |
| **U-A2** (**H1**) | The core builds reproducibly under a pinned toolchain and can target 16 KB ELF page alignment | ADR-0018 | §11.5's reproducibility table loses the Android transparency root, and the Play channel cannot meet the 16 KB requirement — a hard Play blocker, not a degradation |
| **U-A3** (**H2**) | A privileged long-lived daemon exists on desktop/server and the updater runs at its privilege; the unprivileged UI cannot initiate a privileged install | ADR-0016 | §11.10's swap sequences and U-34's uninstall drain both need a different privileged actor; on platforms with no daemon the update becomes wholly OS-driven |
| **U-A4** (**H3**) | One local management interface carries `update` verbs; there is no separate updater IPC | ADR-0017 | §11.18 (f) becomes a new privileged surface of its own, and the headless/CLI update path in §11.1 needs its own contract |
| **U-A5** | The local store survives an update, migrates forward-only, and retains a pre-migration **copy** | ADR-0020 | R-42 loses its mechanism; U-32's downgrade window and P20 procedure D both change |
| **U-A6** | ADR-0022 owns *when* an apply may run on mobile and the updater never consumes a background-execution budget the datapath needs | ADR-0022 | §11.10's mobile rows and U-20's deferral policy change |
| **U-A7** | The router target is ADR-0023's **H-EMB** deployment profile running on **GC-0** silicon (16 MB flash, 128 MB RAM, ≈ 24 MB free). ADR-0023 owns the RAM and CPU budget; this ADR owns only flash and package size, and **every §9 router number is a GC-0 number** — not an H-EMB one, and not a GC-0U one. **ADR-0013's G1 "Router class" is a larger, different class and is not the sizing input** (C10) | ADR-0023 §11.13 EM-54; an amendment is owed by [ADR-0013](ADR-0013-multi-client-gateway-architecture.md)'s owner | §9's ipk budget must be re-derived jointly. If GC-0's flash moves off 16 MB, §11.2's ×2 overlay-headroom pre-check and the sub-GC-0 support statement both change, and `MANUAL_ONLY` may need to become configurable. **If a number of mine is ever re-attributed from GC-0 to GC-0U it becomes wrong by roughly an order of magnitude in the permissive direction** — the same failure mode that put ADR-0018's PB-3 at 2–3× its achievable value |
| **U-A8** | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) grants the `UPDATE` socket class of §11.18 (b) | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) | A device blocked under full-tunnel `FAIL_CLOSED` cannot self-update, [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-31(4)(b) becomes unreachable, and recovery requires a local reinstall |
| **U-A9** | [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)'s three-epoch skew and 12-month deprecation window hold | [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-24, N-25 | §11.6's `min_installable_from` policy and §11.7's reporting cadence change; a shorter window makes the fleet-report coverage question harder, not easier |
| **U-A10** | [ADR-0007](ADR-0007-device-identity-and-pairing.md)'s ES256 hierarchy stands, so RTA/RMK can mirror ORK/OSK rather than introduce a second scheme | [ADR-0007](ADR-0007-device-identity-and-pairing.md) | C5 forces a re-derivation of §11.3; a second signature algorithm doubles the verifier surface for the update path too |
| **U-A11** | [ADR-0015](ADR-0015-observability-and-diagnostics.md) accepts an `UPDATE` domain | [ADR-0015](ADR-0015-observability-and-diagnostics.md) | Every code in §11.16 remaps to `PLATFORM.UPDATE.*` — mechanical, and pre-stated in §11.20 (b) so it is not a redesign |

## 12. Why the Selected Option Won

1. **A and D are disqualified by one sentence each, and it is the same sentence.** A store build on
   macOS cannot install a `LaunchDaemon`, so it cannot hold the boot-time `pf` anchor that
   [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6 relies on; a store build on
   Windows cannot install WinTun, so it cannot satisfy R-19; a sandboxed Linux package cannot hold
   `CAP_NET_ADMIN`, so it cannot be the network authority at all. A (store-first) therefore cannot
   ship the product, and D (dual channel) ships two products with different I3 postures under one
   name — which [docs/vision.md](../vision.md) §4.1 explicitly forbids, because a limitation must be
   stated with its residual and never silently relaxed. D fails on a principle, not on effort.
2. **B is right about capability and wrong about reach.** It has no answer on iOS at all, and on
   Android it abandons the channel where the users are. C is B everywhere B is possible, plus a
   store where a store is unavoidable, plus one secondary channel chosen for a stated security
   purpose rather than for coverage.
3. **E's store shim is prohibited by the very stores it depends on.** Bootstrap-then-sideload is
   refused by App Store review and treated as unwanted-software behaviour by Play. E's genuinely
   good idea — one updater implementation, so **P20** tests one mechanism — is adopted into C
   without the shim (U-14 … U-21 are channel-independent).
4. **C makes N-30 implementable.** The pre-execution MSPV gate requires an installer we control on
   the platform where the rollback is attempted. C gives us that on macOS, Windows, Linux and
   OpenWrt; on iOS the platform removes the rollback entirely and on Android the platform enforces
   monotonicity for us. Under A, N-30 would be an intention on every platform.
5. **The Android secondary channel earns its cost.** Play App Signing means a third party produces
   the signature devices verify. A reproducible, self-signed APK plus the transparency log makes
   the Play artifact **auditable** — which is the only answer to a residual we cannot remove. Its
   real cost (no in-place migration, identity loss on channel switch) is stated in §11.2 and
   disclosed to the user before they commit, rather than discovered afterwards.

## 13. Known Tradeoffs

| # | Tradeoff | Why it is accepted |
|---|---|---|
| K-1 | **No Mac App Store presence.** We lose store discovery and store-managed enterprise distribution on macOS. | The alternative is a build whose reboot durability is ✘ where the corpus claims ✔ |
| K-2 | **We own an updater**, i.e. a privileged code-execution path we could have delegated to the OS on three platforms. | It is what makes N-30, U-18, U-33 and the security fast path real rather than aspirational. Mitigated by one implementation and seven mutants |
| K-3 | **A compromised RTA has no in-band recovery.** | It is why RTA is offline, threshold-held (2-of-4) and ceremony-only, and why the transparency log is mandatory: forging becomes publishing |
| K-4 | **Full artifacts only** — more bytes, especially on metered mobile links. | A delta patcher is a parser on the highest-value input in the system. §14 revisit 3 is the honest trigger |
| K-5 | **The transparency-log check can block an update** if the log is unavailable. | Not updating is always safe; the failure is availability of updates, never of sessions |
| K-6 | **Two Android channels, no migration between them**, with identity loss on a switch. | It is the only way to audit an artifact a third party signs. Disclosed before the user commits |
| K-7 | **Router-class targets never auto-update**, which is the tier least likely to be patched by hand. | `opkg` is not transactional, there is no rollback partition, and a full overlay turns an interrupted install into a brick. Availability of the router beats currency of the router |
| K-8 | **Rotating the Authenticode certificate resets SmartScreen reputation**, producing user-visible warnings. | Unavoidable; made a scheduled, overlapped, dual-signed event rather than an emergency |
| K-9 | **Unsupervised iOS has a real unprotected window during an update**, and we cannot close it. | Named, bounded by measurement rather than assertion, and closable only by supervision — which is an MDM capability, not an app capability |
| K-10 | **The security fast path ships on less evidence than a normal release.** | An explicit trade of one risk against another, two-person authorized, auto-withdrawn if the deferred soak fails, and still bound by §6.5 |

## 14. Revisit Conditions

Each is a measurable trigger.

1. **The measured p95 apply window on any platform exceeds its §11.10 budget in two consecutive T4
   runs.** The budget is wrong or the sequence is; both are this ADR's to fix.
2. **The measured iOS provider-restart-after-update window (P20 procedure C) exceeds 3000 ms at
   p95 on unsupervised devices**, or the distribution's p99 exceeds 30 s. The residual in §11.10's
   iOS row stops being "small and named" and becomes a product decision about supervision.
3. **Median full-artifact size on any platform exceeds 40 MB**, or the update-abandonment rate on
   metered links exceeds **5%** over 30 days. U-19's rejection of deltas must be re-argued.
4. **The fleet report's 30-day coverage falls below 90%** of devices known active by any other
   signal. [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-25 G2 becomes
   unevaluable and the deprecation gate needs a different evidence source.
5. **Apple permits a Mac App Store application to install a boot-time enforcement artifact
   equivalent to a `LaunchDaemon`-loaded `pf` anchor.** The MAS refusal in §11.1 loses its reason.
6. **Play mandates a requirement our build cannot satisfy without weakening enforcement**, or
   extends the native page-size requirement beyond what the toolchain in U-A2 can target. The Play
   channel becomes the secondary and the self-hosted APK the primary — a channel inversion this
   ADR's structure permits but does not assume.
7. **Microsoft requires MSIX for a distribution surface we need**, or changes kernel-mode driver
   policy such that WinTun can no longer be shipped app-locally. R-19's mechanism must be
   re-derived, possibly as a driver we submit ourselves.
8. **A transparency-log inclusion proof cannot be obtained for more than 1% of install attempts
   over 30 days.** U-7's MUST has become an availability problem, and the choice is a redundant log
   or a graded requirement — not a silent fail-open.
9. **OpenWrt gains a documented mechanism for a third-party nftables table that survives
   `fw4 reload` atomically.** §11.10's OpenWrt residual and §11.20 (a)'s requested qualification are
   both withdrawn.
10. **Any key in §11.3 is compromised**, or an annual rotation rehearsal (U-4) fails to produce a
    usable signed artifact. §11.4 is re-derived from what actually happened rather than from what
    was planned.
