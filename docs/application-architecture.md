# TwinVPN — Application and Platform Architecture

**Scope.** This is the anchor structural document for the **application and platform layer**: the
seam between the architecture that establishes and protects a tunnel and the six products that ship
it. [docs/architecture.md](architecture.md) says what the components are and who owns each fact;
this document says **what processes exist on a real host, which of them holds privilege, how they
talk, what is built once versus per platform, how it is packaged and updated, and what happens on a
device with no screen and no user**. Where a decision belongs to an owning ADR, this document states
the **interface it requires** and defers by ADR number.

**This layer is not a port of the tunnel to six operating systems.** Its load-bearing content is
§4 (the three cross-cutting decisions), §5 (the label axes, which retire a defect class the corpus
hit three times), and §6 (**the fail-closed recovery rule** — the single most productive structural
finding of this workstream, which located seven latent deadlocks across four ADRs).

**Related documents**

- [docs/vision.md](vision.md) — invariants **I1–I8**, principles **P1–P10**, requirements
  **R-01 … R-49** (§5.8 is this layer's)
- [docs/architecture.md](architecture.md) — components, domain model, plane separation,
  **state ownership §5** (§5.1 is this layer's, S-38 … S-68)
- [docs/networking.md](networking.md) — the platform network adapter contract (§5.1), the seam this
  layer builds on
- [docs/reliability.md](reliability.md) — the **authoritative** `ConnectionState` machine, timers,
  background operation
- [docs/protocol.md](protocol.md) · [docs/threat-model.md](threat-model.md) ·
  [docs/testing-strategy.md](testing-strategy.md) — proof tests **P16 … P22** are this layer's
- Owned ADRs: **[ADR-0016](adr/ADR-0016-client-process-and-privilege-separation.md) …
  [ADR-0023](adr/ADR-0023-headless-cli-and-embedded-profile.md)**

**Normative language.** MUST / MUST NOT / SHOULD / MAY per RFC 2119.

---

## 1. The layer at a glance

```
        ┌───────────── UNPRIVILEGED ─────────────┐   ┌──── PRIVILEGED ────┐
        │  GUI (SwiftUI / Compose / WinUI /      │   │  the AUTHORITY      │
        │       GTK4)   ·   CLI   ·   automation │   │  ─────────────────  │
        │                    │                   │   │  tunnel engine      │
        │                    ▼                   │   │  state machine      │
        │        one Management Interface  ──────┼──▶│  policy evaluation  │
        │        (ADR-0017, MI-1 parity)         │   │  kill-switch owner  │
        └────────────────────────────────────────┘   │  key HANDLE holder  │
                                                     └──────────┬──────────┘
                                                                │
                                    ┌───────────────────────────▼─────────────┐
                                    │  portable core (Rust, C ABI) — ADR-0018 │
                                    │  ── vtable ──────────────────────────── │
                                    │  platform adapter · secure items        │
                                    └─────────────────────────────────────────┘
```

Three claims define the layer, each discharged by an owning ADR:

1. **The GUI is not the product.** Protection outlives every unprivileged process. Closing a
   window, logging out, or having a memory manager kill the UI MUST NOT drop the tunnel or the
   leak guard (**R-25**, [ADR-0016](adr/ADR-0016-client-process-and-privilege-separation.md)).
2. **There is exactly one control contract.** The GUI has no privileged side channel; the CLI is a
   generated thin client over the same catalogue. This is what makes **R-21**'s "the same control
   contract as the GUI" a testable property rather than an aspiration
   (**MI-1**, [ADR-0017](adr/ADR-0017-local-management-interface.md)).
3. **The logic is written once.** Six shells render and marshal; none decides. A shell holding a
   TwinVPN domain decision is a defect, not a variation
   (**CB-2**, [ADR-0018](adr/ADR-0018-shared-core-and-build-architecture.md)).

## 2. Why this layer exists: the second defect family

[docs/vision.md](vision.md) §5's R-01 … R-24 are derived from the failure modes of *tunnels* —
traversal, durability, relays, leaks. R-25 … R-49 are derived the same way from the failure modes of
**shipped client applications**, which are a disjoint family:

| The tunnel is correct, and the product still fails, because… | Owning ADR |
|---|---|
| the GUI owned the protection, and the GUI died | [ADR-0016](adr/ADR-0016-client-process-and-privilege-separation.md) |
| the GUI could do something the CLI could not, so "headless is first-class" was false | [ADR-0017](adr/ADR-0017-local-management-interface.md) |
| six platforms each reimplemented one decision, six ways | [ADR-0018](adr/ADR-0018-shared-core-and-build-architecture.md) |
| a perfect `reason_code` arrived and was rendered "connection failed" | [ADR-0019](adr/ADR-0019-application-state-model-and-ui-architecture.md) |
| a firmware upgrade silently destroyed the identity of every device it reached | [ADR-0020](adr/ADR-0020-local-persistence-and-secure-storage.md) |
| the update dropped the firewall for a window nobody measured | [ADR-0021](adr/ADR-0021-packaging-distribution-and-updates.md) |
| the laptop resumed and rendered a confident, stale green | [ADR-0022](adr/ADR-0022-application-lifecycle-and-background-execution.md) |
| the router had no screen, no user, and no way to say what was wrong | [ADR-0023](adr/ADR-0023-headless-cli-and-embedded-profile.md) |

**I6's second half.** [docs/vision.md](vision.md) I6 requires every failure to carry a stable
`reason_code`, human-actionable text, and a next action. The corpus specified the machine-readable
half thoroughly and the human half **nowhere** — making **R-22 undischargeable by test**. A product
that emits a perfect code and renders it as "connection failed" has violated I6 at the last inch.
[ADR-0019](adr/ADR-0019-application-state-model-and-ui-architecture.md) owns that half, and **P18**
is its oracle.

## 3. Components added to [docs/architecture.md](architecture.md) §2

| # | Component | Plane | Owns | ADR |
|---|---|---|---|---|
| **2.23** | **Local Authority** | Data + local state | The privileged, supervised process holding the interface handle, rule-set handle, route/resolver program, key handle, and registered sockets. On HC-2 the OS-hosted extension *is* the authority | [ADR-0016](adr/ADR-0016-client-process-and-privilege-separation.md) |
| **2.24** | **Management Interface** | Local control | One catalogue of operations + one ordered event stream; peer-credential authentication; attach-time immutable scope sets | [ADR-0017](adr/ADR-0017-local-management-interface.md) |
| **2.25** | **Portable Core** | — (spans) | Every TwinVPN decision, behind a stable C ABI. Shells marshal and render only | [ADR-0018](adr/ADR-0018-shared-core-and-build-architecture.md) |
| **2.26** | **Presentation Resolver** | Local | Code → three-part rendering, **in-core**, pure and instance-free | [ADR-0019](adr/ADR-0019-application-state-model-and-ui-architecture.md) |
| **2.27** | **Two-tier Store** | Local state | Tier 1 secure items (shell-held); Tier 2 encrypted vault (core-side I/O over a shell-vended root) | [ADR-0020](adr/ADR-0020-local-persistence-and-secure-storage.md) |
| **2.28** | **Updater** | Management | Signed artifacts, monotonic manifests, journalled atomic apply | [ADR-0021](adr/ADR-0021-packaging-distribution-and-updates.md) |
| **2.29** | **Lifecycle Supervisor** | Local | Write-ahead `LifecycleJournal`; every restart is a resume | [ADR-0022](adr/ADR-0022-application-lifecycle-and-background-execution.md) |
| **2.30** | **Configuration Compiler** | Local | Declarative `IntentDocument` → monotone `IntentGeneration` | [ADR-0023](adr/ADR-0023-headless-cli-and-embedded-profile.md) |

State ownership rows **S-38 … S-68** are in [docs/architecture.md](architecture.md) **§5.1**. Two
properties are worth reading off them directly: **almost every row is `LOCAL`** — the application
layer adds essentially no remote authority, which is what keeps **I5** intact as the client grows —
and **five rows are non-durable *by requirement*** (S-43, S-45, S-48, S-66, S-67), because for those
persistence would itself be the defect: a value that survives is a value that can be replayed, or
rendered as current when it is not.

## 4. The three cross-cutting decisions

These were posed as hypotheses so eight ADRs could be authored in parallel without converging by
accident. Each has exactly one owner; every other ADR carried it in an assumptions register with an
"if it is wrong, this changes" column. **All three were confirmed by their owners.**

| # | Decision | Owner | Outcome |
|---|---|---|---|
| **H1** | One portable core in a memory-safe systems language behind a stable C ABI; thin native shells | [ADR-0018](adr/ADR-0018-shared-core-and-build-architecture.md) | **Confirmed** — Rust over a hand-written `twinvpn.h`. Beat Go on FFI callback direction (the seam is callback-heavy, Go's weakest direction), heap headroom inside a 9 MB core share, a mechanically-bounded memory-safety audit surface, and binary size at the two tightest rows |
| **H2** | A privileged supervised authority plus unprivileged clients | [ADR-0016](adr/ADR-0016-client-process-and-privilege-separation.md) | **Confirmed** — with the OS-imposed topology on HC-2 and a single root process on the embedded tier, residual declared. macOS resolved to **Developer ID + notarized system extension**, rejecting the App Store variant because it forfeits KS-19 |
| **H3** | One local management contract; no privileged side channel for the GUI | [ADR-0017](adr/ADR-0017-local-management-interface.md) | **Confirmed** — and strengthened: **MI-20** makes the catalogue *derived from* the core's command set (same names, same shapes, one generated source, build failure on an unmatched entry in either direction), not merely singular |

## 5. Label axes — four families, three axes, one rule

Three separate collisions in this corpus came from two documents independently reaching for the
same prefix. **Ownership was the missing field**, so it is a column here.

| Family | Axis | Owning document | Values | Answers |
|---|---|---|---|---|
| **`GC-*`** | **Silicon** | [ADR-0023](adr/ADR-0023-headless-cli-and-embedded-profile.md) §11.13 | `GC-0` (single core ~580–700 MHz, no crypto extensions, 128 MB RAM / **~24 MB free**, 16 MB flash) · `GC-0U` (dual A53, **same memory and flash**, more CPU) · `GC-1/2/3` = [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md)'s classes, renamed | What fits in flash and RAM; what throughput is reachable |
| **`HC-*`** | **Process / privilege shape** | [ADR-0016](adr/ADR-0016-client-process-and-privilege-separation.md) §11 | `HC-1` attended-separable · `HC-2` OS-mediated · `HC-3` headless | Which processes exist; who holds privilege; who loads the core |
| **`H-*`** | **Deployment profile** | [ADR-0023](adr/ADR-0023-headless-cli-and-embedded-profile.md) §11.1 | `H-EMB`, `H-SRV`, `H-CTR`, `H-CLI`. Every `H-*` sits in `HC-3` | Which supervisor, libc, config system, packaging |
| **`G1…G14`** | **Overloaded — a known defect** | [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md) | requirement ids **and** hardware classes share the prefix | — cite as `GC-1/2/3` for hardware |

> **Rule AL-1 (normative).** A **performance or size budget MUST cite a `GC-*` class.** Citing a
> deployment profile or a process topology where a silicon envelope is meant is a defect, because
> the reader cannot check the derivation.
>
> **Rule AL-2 (normative).** An ordinal in the `HC-n` series MUST NOT be used to mean a hardware
> envelope.
>
> **Rule AL-4 (normative).** Distinguish **build-derived** budgets (RSS, stripped size, `.ipk` size,
> flash-write rate — properties of the *compiled artifact*, identical on any envelope member built
> from the same source, therefore **portable**) from **silicon-derived** ones (throughput, cold
> start — properties of the *CPU*, therefore **not portable**). A build-derived budget may name only
> its class. A silicon-derived budget may not.
>
> **Rule AL-5 (normative) — split, do not annotate.** Where a silicon-derived budget *needs* a
> measuring-member qualifier to be meaningful, **the class is drawn on the wrong axis and MUST be
> split**. An annotation documents an ambiguity once; a split removes it for every future budget.
> A floor measured on the stronger member is not a floor.
>
> **Rule AL-3.** A class is an **envelope, not one SoC**. Any device inside it is a valid gating
> unit. This is what lets `GC-0` gate on a prebuilt-`std` ARM member while the MIPS triple remains a
> nightly portability build — so **no release gate depends on `build-std`**. Its limit is stated
> rather than assumed: **RSS and flash transfer across envelope members; throughput does not** (MIPS
> 24Kc has no SIMD, so a figure measured on ARM is an *upper bound*), which is why the nightly build
> still measures throughput.

**Why this is written as rules rather than as a note.** AL-1 would have caught the defect that
produced it. [ADR-0018](adr/ADR-0018-shared-core-and-build-architecture.md)'s embedded reference was
a *chimera* — `GC-0U`'s CPU paired with `GC-0`'s memory, matching neither class — and its throughput
budget was simultaneously **2–3× above** what the silicon its label denoted can reach and **below**
the silicon it was sized against. The inverse error was live in
[ADR-0021](adr/ADR-0021-packaging-distribution-and-updates.md), where a flash budget would have
read as satisfied because the silicon was assumed ~8× larger. Same conflation, opposite sign, both
invisible until silicon had its own axis.

> **A caveat worth generalising.** ADR-0018's budget carried "provisional until measured", and that
> caveat would **not** have caught the error, because the divergence was in the **reference device**,
> not the measurement — measuring would have cheerfully confirmed a number derived against the wrong
> hardware. **A measurement caveat is not a substitute for naming the device.**

## 6. The fail-closed recovery rule

> **Rule FC-1 (normative).** **No component whose availability depends on the tunnel being up may
> sit on the path that brings the tunnel up.**

This is the most productive structural finding of the workstream. It was named after three ADRs hit
it independently; once named, four further instances were found deliberately — including one in the
ADR that named it.

| # | Instance | Found by | Disposition |
|---|---|---|---|
| 1 | **Self-update deadlock.** [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) N-31(4)(b) names "a successful self-update" as the recovery path from a version block; [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) KS-10 permits exactly three `BOOTSTRAP` payloads, none an update fetch, and the update origin is not the control plane. Under full-tunnel `FAIL_CLOSED` the recovery path is unreachable **by construction** | ADR-0021 | **Closed — applied.** [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) KS-10a adds the `UPDATE` class: the privileged updater's fetch socket, signed manifest and artifact bytes only, **destination-bounded** to `UpdatePolicy`'s pinned origins (S-59), modelled on class 13 |
| 2 | **KS-9(2)'s mandated IPC hop** — which the correct topology eliminates, and which *is* the confused-deputy surface KS-9 exists to deny (sockets and enforcement are in one process; intra-process registration is not IPC) | ADR-0016 | **Closed — applied.** [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) KS-9a withdraws the IPC spelling: the registration MUST NOT be specified as IPC. Also resolves half of threat-model **O-11** |
| 3 | **core-lite on a recovery path.** Under `includeAllNetworks` the iOS app process has no network and cannot match class 7, because KS-9(1)'s predicate names the *provider* | ADR-0016 | Closed by prohibition |
| 4 | **Headless disarm.** Reject EM-39's reading of KS-21 and a headless device can never be disarmed — contradicting KS-20's "blocked must not mean bricked" | ADR-0023 | **Closed — applied.** [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) KS-21a adds the host-class rule defining what "interactive" means on `HC-3` hosts with no console, so KS-21 no longer makes disarm impossible there and KS-20's "blocked must not mean bricked" holds |
| 5 | **The contract fetch itself.** ADR-0018 had the iOS *app* process fetch the signed contract, following [docs/networking.md](networking.md) §5.4 literally | ADR-0018, on its own design | Fixed: the **extension** fetches; core-lite parses and verifies |
| 6 | **`RelayCapabilityToken` (S-30) absent from the app/extension table** — it is on step 4 of the recovery ladder, so an implementer would have had the app fetch it | ADR-0022, by audit | Closed by LC-17a |
| 7 | **The memory-shed ladder evicting recovery-path state** — the same class arriving through a side door: memory pressure deletes the thing recovery needs | ADR-0022 | Shed list closed against recovery state |

**The generative question**, which SHOULD be applied to every new recovery, registration or
bootstrap path: *is the channel it uses one of KS-10's three permitted payloads, the `RESOLVER`
class, or a class-13-shaped bounded exemption? If not, it is unreachable exactly when it is needed.*

Two disciplines learned while applying it. **The class-13 pattern is requested but not
automatically granted** — a time-sync class was declined by ADR-0023 on the reasoning that the relay
offset already supplies clock correction with **zero egress**, so an exemption would widen the
corpus's most dangerous row to buy a capability already held: *"twice-used is not thrice-justified."*
And a candidate **was refuted** — an RTC-less-router deadlock proposed by the integrator was broken
in two places by ADR-0023, which is the outcome the rule should produce as often as a confirmation.

## 6a. The class-axis rule

> **Rule CA-1 (normative).** A hardware class MUST be drawn on its **binding constraint**, not on a
> convenient or legible axis. Where the two differ, every budget derived from the class is wrong for
> some member of it.

A second defect class, found four times in this corpus and named only at the end:

| Instance | The convenient axis | The binding constraint | Consequence |
|---|---|---|---|
| [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md)'s "G1 — Router class" | "a small board" (an RPi 4B, 4×A72, 2 GB) | OpenWrt-class silicon | Peer counts and a ~300 Mbit/s ceiling derived on hardware ~16× the RAM of the devices the class names |
| ADR-0018's withdrawn embedded reference | — (a *chimera*: `GC-0U`'s CPU with `GC-0`'s memory) | — | A throughput budget simultaneously **2–3× above** the silicon its label denoted and **below** the silicon it was sized against |
| ADR-0018's original single-class `PB-3` | one embedded tier | two, with different CPUs | One threshold for two classes that cannot both meet it |
| ADR-0023's original `GC-0U` | **core count** | **crypto throughput**, where **SIMD** is the discontinuity (2–4× on ChaCha20-Poly1305, against ~2× for a second scalar core) | A single ≥ 80 Mbit/s release gate unreachable for half the class |

**The generative question**, which SHOULD be asked of any table that names hardware: *"which member
of this class am I actually measuring?"* It is cheap to ask and it has now caught four. In the last
case the class even hedged itself in plain sight — a "crypto acceleration: none (NEON helps
modestly)" row sitting inside a class defined by core count.

**Corroboration that the AL-4 cut is at the right joint:** when `GC-0U` was re-split on SIMD
presence, **no build-derived budget moved** — both classes are 128 MB / 16 MB — and only
silicon-derived rows re-sorted.

## 7. Platform realization

Minimum versions are fixed by [docs/networking.md](networking.md) §5.2 and are not restated.

| Target | `HC-*` | Authority | Enforcement point | Channel | Distribution |
|---|---|---|---|---|---|
| **Windows** | HC-1 | `TwinVPNService` (LocalSystem, trimmed privileges) | WFP sublayer, persistent + boot-time filters | Named pipe, explicit DACL | MSI, Authenticode + EV |
| **macOS** | HC-1 | NE **system extension** + minimal `LaunchDaemon` | pf anchor from `/etc/pf.conf`, daemon-applied | Unix socket / XPC | **Developer ID + notarized**, stapled |
| **Linux** | HC-1 / HC-3 | `twinvpnd`, `CAP_NET_ADMIN` only, `NoNewPrivileges` | nftables `inet` table, package-owned boot unit | Unix socket, `0660 root:twinvpn` | deb / rpm / static tarball |
| **iOS / iPadOS** | HC-2 | `NEPacketTunnelProvider` (OS-granted) | `includeAllNetworks`; **KS-19 unsatisfiable** | App Group + provider messaging (subset) | App Store only |
| **Android** | HC-2 | `:tunnel` process, foreground service | OS always-on + lockdown | Bound service / AIDL | Play + reproducible sideload |
| **OpenWrt / routers** | HC-3 | `twinvpnd`, root (optionally `ujail`) | `fw4` include, UCI-owned | Unix socket; **`ubus` never disarms** | opkg feed *(future-compatible)* |
| Headless Linux · containers · CLI-only | HC-3 | as Linux | as Linux | as Linux | as Linux |

**iPadOS is not "iOS but bigger."** Stage Manager, external display, hardware keyboard and Files
create presentation surfaces but **no new control surface** — and a configuration file dropped into
Files is **refused**, because it would be an unmediated second writer for Class-I intent (**I8**).

**Where an invariant cannot hold, it is named, not softened.** On the embedded tier with no secure
element, **I4 is not upheld**: the private half is a file, and anyone who can read the filesystem
obtains a working identity indistinguishable from the original. What remains is revocation, the
`EpochSeed` exclusion, and detection — *containment, not prevention*. The device advertises its
`custody_class`, and a `SOFTWARE_PORTABLE` device MUST NOT hold an `ENROLL`/`REVOKE`/`DELEGATE` OSK.

## 8. Verification

Proof tests **P16 … P22** are registered in [docs/testing-strategy.md](testing-strategy.md) §4.3,
raising the acceptance set to **twenty-two**; requirement traceability for R-25 … R-49 is §5.1b.
Two properties of the added set are worth stating here:

- **P18 needs no device farm.** Because `platform_ctx` is a parameter rather than a build-time
  constant, the renderer renders *for* a platform it is not running on — so every platform's
  variants are driven from one runner, and a support workstation can render a bundle collected
  elsewhere.
- **P20 is the largest inherited assumption in the corpus.** Its procedures A, B and D are **not
  executable on iOS at all**; there, assurance is inherited from Apple's channel *as an assumption,
  not a test*. Stated rather than absorbed.

## 9. Amendments owed to other documents

This workstream closes threat-model **O-11** (the local management IPC), but **only jointly** —
authentication and audit are split across
[ADR-0016](adr/ADR-0016-client-process-and-privilege-separation.md) and
[ADR-0017](adr/ADR-0017-local-management-interface.md), and it MUST NOT be closed against either
alone. It closes half of **G-5** and half of **O-5**.

**G-8 is closed, not reopened.** An earlier draft of this section recorded that this workstream
reopened it. That is superseded: the six residual defects the workstream found were discharged by
withdrawing A-21 from [docs/architecture.md](architecture.md) §9 and promoting it to requirement
**R-DET-1** in that document's own voice (§5.2), with enforcement **R-DET-1a** pointed at
[ADR-0018](adr/ADR-0018-shared-core-and-build-architecture.md) §11.8 CD-3 in T1.
[docs/testing-strategy.md](testing-strategy.md) §5.3 records G-8 closed on the same remedy. The
two documents agree.

**Status of the amendments below — all applied.** Every row in this table has been discharged in
the document that owns it; the table is retained as the audit trail of what this workstream owed
and where it landed, not as a list of outstanding work. Each row names its landing site.

| Owner | Amendment | Landed at |
|---|---|---|
| [docs/reliability.md](reliability.md) | **§5.3 registers long-horizon *policy* deadlines on a clock that pauses during suspend.** A laptop closed for sixty days accrues no monotonic time, so `T_TRUST_HARD` never expires and the device keeps exercising the granted authority **R-24** exists to suspend. A specified mechanism defeated by a different specified mechanism | **APPLIED** — [docs/reliability.md](reliability.md) **§5.3.1** — three clock classes; `T_TRUST_HARD`, `T_TRUST_STALE`, `T_IK_OVERLAP`, `T_TK_OVERLAP` and `PortalExemptionGrant` expiry are registered on **`ElapsedClock`** (suspend-inclusive). Rule **R-CLK-3** makes an unclassed constant a defect; §10.2 E5 records "monotonic for every timer" as **withdrawn** |
| [docs/networking.md](networking.md) | §5.4's Android-lockdown detection **cannot be built** for a non-DPC app on Android 10+ — under lockdown our own sockets are the permitted ones, so the obvious probe is invalid. And §5.4's contract-fetch sentence produces instance 5 of §6 if read literally | **APPLIED** — [docs/networking.md](networking.md) **§5.4** — "the app detects whether it is enabled" is marked **cannot be built**; the posture is three-valued (`LOCKDOWN_CONFIRMED` / `LOCKDOWN_ABSENT` / `LOCKDOWN_UNVERIFIED`), and `LOCKDOWN_UNVERIFIED` MUST present as **unprotected**. [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.6 consumes the three-valued posture, not a boolean |
| [docs/architecture.md](architecture.md) | §2.20 reads as though the durable store holds nothing sensitive, while [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) N-19 requires it to hold `PairSecret` and sealed `EpochSeed`s — *a reader following §2.20 alone builds an unencrypted store*. Also **A-21**, per G-8's four edits | **APPLIED** — [docs/architecture.md](architecture.md) **§2.20** — the non-responsibilities cell now states the store holds `SECRET`-class material and **MUST be encrypted at rest**, names [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) N-19's `PairSecret` and sealed `EpochSeed`s, and says in terms that a reader following the first two sentences alone would build an unencrypted store. **A-21** is superseded by **R-DET-1** (§5.2), per G-8 |
| [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) | The `UPDATE` class (§6 instance 1); KS-9(2)'s IPC requirement (instance 2); KS-21 on headless hosts (instance 4) | **APPLIED** — [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) — **KS-10a** (the `UPDATE` class), **KS-9a** (the IPC spelling withdrawn), **KS-21a** (the host-class rule for consoleless `HC-3` hosts). All three are §6 instances 1, 2 and 4 |
| [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) | `AUTH.CLOCK_IMPLAUSIBLE` is `terminal` + `user_actionable` — on an unattended RTC-less router that flag is *false*, and gating rather than reporting is the difference between a slow boot and a bricked router. Android `setUnlockedDeviceRequired(true)` prevents mid-session rekey. `DeviceKey` has no declared **availability class** | **APPLIED** — [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) — **N-24c**: `AUTH.CLOCK_IMPLAUSIBLE` reports and MUST NOT gate, with `user_actionable` **conditional on an attended host**; **N-24a** §7.3.1: `setUnlockedDeviceRequired(true)` withdrawn on Android, and the key **availability class** newly stated |
| [docs/threat-model.md](threat-model.md) | **Supply chain is entirely unmodelled** — no adversary, no threat row, and no release-key rows in §12, though the update channel's blast radius is *wider* than the `OwnerRootKey`'s. Plus the MDM-administrator residual, the iOS update window, and Apple's notarization revocation — the one case where the corpus asserts a property a third party can unilaterally void | **APPLIED** — [docs/threat-model.md](threat-model.md) — **AD-13** (supply-chain attacker) and **AD-14** (MDM administrator) in §4; **TM-31** (forged artifact) and **TM-32** (vendor notarization revocation) in §5; §12 key-lifecycle rows; §14.4 and §15 carry the MDM and iOS-window residuals |

## 10. Assumptions this document makes

| # | Assumption | Depends on | If it is wrong |
|---|---|---|---|
| **AA-01** | The platform network adapter contract of [docs/networking.md](networking.md) §5.1 is the *complete* seam; nothing above it branches on OS | [docs/networking.md](networking.md) | §1's diagram and ADR-0018's CB-3 lint both lose their basis |
| **AA-02** | [docs/reliability.md](reliability.md) §4 remains the sole authority for `ConnectionState`; this layer projects it and never redefines it | [docs/reliability.md](reliability.md) | ADR-0019 §11.3's projection becomes a second, drifting state machine |
| **AA-03** | Kill-switch enforcement is OS-level, locally authoritative, and survives every process death | [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) | R-25 and the whole §1 claim 1 collapse |
| **AA-04** | `reason_code` remains the contract and human text remains non-contractual | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 rule 4 | ADR-0019's catalogue-only update path and P18's oracles both fail |
