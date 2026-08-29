# ADR-0018: Shared Core, Language/Runtime, and Build Architecture

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** APPLICATION
- **Related:** [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md),
  [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md),
  [ADR-0003](ADR-0003-network-contract-schema-format.md),
  [ADR-0005](ADR-0005-relay-architecture.md),
  [ADR-0006](ADR-0006-relay-discovery-and-failover.md),
  [ADR-0007](ADR-0007-device-identity-and-pairing.md),
  [ADR-0009](ADR-0009-state-consistency.md),
  [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md),
  [ADR-0013](ADR-0013-multi-client-gateway-architecture.md),
  [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md),
  [ADR-0015](ADR-0015-observability-and-diagnostics.md),
  [ADR-0016](ADR-0016-client-process-and-privilege-separation.md),
  [ADR-0017](ADR-0017-local-management-interface.md),
  [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md),
  [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md),
  [ADR-0021](ADR-0021-packaging-distribution-and-updates.md),
  [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md),
  [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md),
  [docs/architecture.md](../architecture.md), [docs/networking.md](../networking.md),
  [docs/protocol.md](../protocol.md), [docs/reliability.md](../reliability.md),
  [docs/testing-strategy.md](../testing-strategy.md), [docs/threat-model.md](../threat-model.md)

This ADR owns the **shape of the implementation**: where the line between a portable core and a
native shell falls and the rule that decides ambiguous cases; the implementation language and
runtime; the C ABI across the core/shell boundary and its versioning; the module decomposition of
the core and the dependency arrows that make **I5**, **I4** and **I2** structural rather than
disciplinary; the injection mechanism that makes clocks, timers and randomness testable
([docs/architecture.md](../architecture.md) A-21,
[docs/testing-strategy.md](../testing-strategy.md) L-3); the ten-target build matrix with its
toolchains, linkage, minimum versions and size budgets; and the dependency and supply-chain policy
for the artifact.

It does **not** own: which OS process hosts the core
([ADR-0016](ADR-0016-client-process-and-privilege-separation.md)), the local management contract
that non-hosting processes use to reach it
([ADR-0017](ADR-0017-local-management-interface.md)), the realization of the durable store or
secure storage ([ADR-0020](ADR-0020-local-persistence-and-secure-storage.md)), signing,
notarization, packaging or update delivery
([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)), background execution policy
([ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md)), the tunnel protocol or
its primitives ([ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)), the wire
schema ([ADR-0003](ADR-0003-network-contract-schema-format.md)), the `ConnectionState` machine
([docs/reliability.md](../reliability.md) §4), or the platform adapter contract itself
([docs/networking.md](../networking.md) §5.1) — which this ADR consumes verbatim and specifies
only the *carriage of* across the boundary.

> **Sibling-ADR filenames** are given in the expected kebab-case form, as
> [docs/vision.md](../vision.md) §7 does. If an owner chooses a different slug, the integrator
> corrects the link here.

---

## 1. Context

Seven sibling ADRs in this workstream are being written against hypothesis **H1**: that one
portable core holds the entire tunnel engine, state machine, policy evaluation, candidate
gathering and contract handling, in a memory-safe systems language, behind a stable C ABI, with
thin native shells. This ADR owns H1 and must treat it as open.

The corpus makes the stakes concrete. [docs/reliability.md](../reliability.md) §4 specifies a
twelve-state machine with thirty-plus transitions and a merge gate
([docs/testing-strategy.md](../testing-strategy.md) §2.2) requiring **every** transition to be
covered. [ADR-0006](ADR-0006-relay-discovery-and-failover.md) specifies HRW relay ranking, dwell,
flap suppression and region failover. [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)
specifies a latch, an ordering discipline and a reconciler.
[ADR-0007](ADR-0007-device-identity-and-pairing.md) specifies epoch arithmetic, anti-rollback and
an offline verification chain. Reimplementing that six times — once per required platform — means
six state machines, six rankers, six reconcilers, and six sets of the bugs each one grows. It also
means the proof tests P01–P15, which
[docs/testing-strategy.md](../testing-strategy.md) §3.7 shows can only be run against real iOS on
a physical device farm, would have to pass six times against six different implementations.

Two constraints in the corpus shape the answer more than any preference. First,
[docs/architecture.md](../architecture.md) §4.2's directional dependency rule — *the data plane
MUST NOT hold a reference to any control-plane client* — is called "structurally checkable", and
[docs/testing-strategy.md](../testing-strategy.md) B-19 blocks a release if the check is absent.
A check needs an artifact to check. Second,
[docs/architecture.md](../architecture.md) A-21 and
[docs/testing-strategy.md](../testing-strategy.md) L-3 require that no component read a clock or
randomness except through an injected provider, enforced by lint. Both are properties of *code
structure*, and neither survives a design where each platform writes its own.

---

## 2. Requirements

New requirements proposed for [docs/vision.md](../vision.md) §5, in that document's format.

| ID | Historical defect | TwinVPN requirement | Mechanism | Specified in |
|---|---|---|---|---|
| **R-31** | Per-platform reimplementation drift: the same product behaves differently on each OS because each platform reimplemented connection logic, a fix lands on one platform only, and no single artifact can be tested to conclusion | All `ConnectionState` machine logic, policy evaluation, candidate gathering, path and relay selection, contract handling, and tunnel control MUST exist as **exactly one implementation**, shared unmodified by every supported target. A native shell MUST NOT contain a second implementation of any of it, and MUST NOT contain a branch whose condition is a TwinVPN domain fact | One portable core over a stable C ABI; the §11.1 split rule and the §11.2 component map as the review rule; the §11.7 crate graph asserted in CI; one conformance corpus run against the one core | This ADR §11.1, §11.2, §11.7 |
| **R-32** | "It does not build for that target any more": a supported platform silently falls behind because its toolchain, libc, or a transitive dependency stopped working, and the gap reaches users as a stale or feature-reduced artifact | Every supported target MUST be produced from **one build definition and one pinned toolchain**, MUST meet a declared binary-size and resident-memory budget, and MUST block the release if it cannot be built or its budget is breached. A target that can no longer be supported MUST be withdrawn **explicitly** — named in the support matrix and reported at runtime as `PLATFORM.OS_UNSUPPORTED` — never shipped with a silently different feature set | Single workspace + pinned toolchain manifest (§11.9); per-target size/RSS gate at T4; reproducible-build verification and per-artifact SBOM (§11.10, §11.11); the DP-7 ladder for a dependency with no build for a target | This ADR §11.9–§11.11; [docs/testing-strategy.md](../testing-strategy.md) §6.4, §6.5 B-8 |

Requirements this ADR discharges from [docs/vision.md](../vision.md) §5: **R-15** (§11.13),
**R-19**/**R-20** (§11.9), **R-21** (§11.9 rows 8–10, §11.12), **R-22** (§11.4 F-4).

---

## 3. Constraints

| # | Constraint | Source |
|---|---|---|
| **C-1** | The datapath is network-facing and parses attacker-controlled bytes. A new unique crash, hang, OOM or sanitizer report from any fuzz target blocks the release, regardless of perceived exploitability | [docs/testing-strategy.md](../testing-strategy.md) B-3; [docs/threat-model.md](../threat-model.md) TM-24 |
| **C-2** | No garbage-collection pause may be introduced into the packet path. Jitter above 30 ms σ is a `DEGRADED` entry condition | [docs/reliability.md](../reliability.md) §5.4 |
| **C-3** | The iOS/iPadOS `NEPacketTunnelProvider` runs in a memory-constrained app extension. 15 MB is an **observed, unguaranteed platform ceiling**, not a budget ([ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md)); the provider-wide budget is 12 MB and the core's share is 9 MB (PB-6). Contract parse and diagnostics are already assigned to the app process for this reason | [docs/networking.md](../networking.md) §5.4 |
| **C-4** | Router-class targets have no AES-NI or crypto extensions, may have a read-only rootfs, and are the tightest size and memory budget in the matrix. The binding class is **`GC-0`** (MIPS 24Kc single core, ~24 MB free RAM, 16 MB flash — BM-1), **not** ADR-0013's 2 GB `G1-a` reference. A performance regression there is release-blocking at a lower threshold than on desktop | [docs/testing-strategy.md](../testing-strategy.md) §6.4; [ADR-0015](ADR-0015-observability-and-diagnostics.md) C-6 |
| **C-5** | I2 forbids novel cryptography. Every primitive must be a published implementation of exactly the algorithm set in [docs/threat-model.md](../threat-model.md) §11, on **every** target | I2 / P2, TM-C1 |
| **C-6** | I4 requires the identity private half to be generated in, and never exported from, platform secure storage. The core therefore cannot hold it | I4; [ADR-0007](ADR-0007-device-identity-and-pairing.md) |
| **C-7** | I3 requires enforcement to survive process death. A crash in the core MUST NOT be able to drop the kill-switch rule set | I3; S-18; [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) |
| **C-8** | I5 must be enforced by a mechanism, not by care: the data plane must be *unable* to reach a control-plane client | [docs/architecture.md](../architecture.md) §4.2; B-19 |
| **C-9** | Clocks, timers, randomness and backoff must be injectable at component boundaries, enforced mechanically | A-21; L-3 |
| **C-10** | Minimum OS/kernel versions are already fixed and MUST NOT be re-decided here | [docs/networking.md](../networking.md) §5.2 |
| **C-11** | T1 must reach first verdict in ≤ 15 min. Every target's build competes for that budget | [docs/testing-strategy.md](../testing-strategy.md) §6.1 |
| **C-12** | Android app bundles must be 16 KB page-size aligned to remain publishable | Play policy; NDK linker flags |

---

## 4. Considered Alternatives

### 4.1 Language and runtime for the shared implementation (A–E)

| | Option | Shape |
|---|---|---|
| **A** | **Rust portable core, stable C ABI, thin native shells** | One `cargo` workspace; `staticlib`/`cdylib` per target; hand-written `twinvpn.h`; shells in Swift / Kotlin / C# / Rust |
| **B** | **Go portable core, `c-archive` + cgo bindings** | One Go module; `-buildmode=c-archive`/`c-shared`; `gomobile`-style bindings for Apple and Android |
| **C** | **C++20 portable core, C ABI** | One CMake project; `libtwinvpn.a`/`.so`; the same `twinvpn.h` |
| **D** | **Kotlin Multiplatform core, per-platform native datapath** | Shared Kotlin for state machine, policy, contracts; Kotlin/Native for Apple; datapath written natively per OS |
| **E** | **No shared core — per-platform native reimplementation** | Swift, Kotlin, C#, Go/Rust for Linux; a written specification as the only shared artifact |

### 4.2 The binding surface, given a compiled core (F–H)

| | Option | Shape |
|---|---|---|
| **F** | **Hand-written C header, hand-written per-language wrappers** | `twinvpn.h` is the ABI of record; Swift/Kotlin/C# glue written and maintained by hand |
| **G** | **Generated bindings as the ABI (UniFFI-style)** | Rust interface definitions generate Swift/Kotlin bindings; the generated FFI layer *is* the boundary and its shape is the tool's |
| **H** | **Hand-written C ABI of record, generated idiomatic wrappers** | `twinvpn.h` is small, hand-written and owned; ergonomic Swift/Kotlin/C# layers are generated from the same contract definitions that generate the message types |

---

## 5. Advantages of Each Alternative

**A — Rust core.** Memory safety without a garbage collector — the only option in the set that
satisfies C-1 and C-2 simultaneously. `unsafe` is an *enumerable set*, so "what must a security
reviewer read" has a mechanical answer. Static linking and small binaries suit C-4. `extern "C"`
costs a call in **both** directions, which matters because the adapter seam is callback-heavy.
Cargo's dependency graph is machine-readable, making C-8's structural check a build-time assertion
rather than a lint. Cross-compiles to every required triple.

**B — Go core.** Memory-safe. The best cross-compilation story in the set: one toolchain, no C
compiler for pure-Go targets. Fast builds, shallow ramp, working `c-archive` export, and a
production existence proof inside a NetworkExtension packet-tunnel provider — so the hardest
platform question is answered by existence rather than by argument.

**C — C++20 core.** Universal toolchain availability, including targets where newer languages are
thin. Smallest binaries and lowest baseline RSS in the set. Zero-cost FFI: the ABI *is* the
language's ABI. Deep ecosystem for packet processing, and the widest hiring pool for a datapath.

**D — Kotlin Multiplatform.** One language for the Android shell and the shared logic, removing an
entire boundary on the platform with the most complex lifecycle. Best-in-class serialization and
coroutine tooling for the state-machine-and-contracts half of the problem.

**E — Per-platform reimplementation.** Each shell is idiomatic and debuggable in its platform's own
tooling, with no FFI to obscure a stack trace. No ABI to version, no marshalling, no cross-language
build orchestration; platform teams ship independently. The fastest path to a credible first build
on any single platform.

**F — Hand-written header.** Total control of the ABI, its stability guarantee and its error model.
No tool version can move the boundary underneath us. Consumable by any language.

**G — Generated bindings.** Removes the largest source of hand-written glue and the bug class that
lives in it — mismatched lifetimes, wrong nullability, forgotten frees. Bindings stay in step with
the Rust definitions by construction.

**H — Hybrid.** The hand-written surface stays at roughly a dozen functions, so the forever-cost of
ABI stability is small, while the ergonomic surface shells actually touch is generated from the
contract artifacts that already generate message types, and so cannot drift from the schema.

---

## 6. Disadvantages of Each Alternative

**A — Rust core.** Slowest builds in the set, competing directly with C-11. Steeper ramp, and the
shells still need Swift/Kotlin/C# expertise, so the team is not smaller. Cross-compilation still
needs the NDK, MSVC and Xcode, so Rust's own cross-compilation strength is partly notional. Tier-3
targets (32-bit MIPS musl) have no prebuilt `std` and need `-Z build-std`. Async Rust across an FFI
boundary is genuinely awkward and must be designed for rather than assumed.

**B — Go core.** The GC is the problem, but not in the way usually stated: pauses are
sub-millisecond, and the binding constraint is *heap headroom* — on a 128 MB router (C-4) and
inside a memory-capped app extension (C-3) — where buying headroom back by tightening `GOGC` spends
CPU that PB-3's router budget does not have. Baseline binary and RSS cost several MB before product
code. Critically, the seam is bidirectional: the seven adapter functions plus the signer and store
are all calls **from C into the core's language**, and in Go each is a cgo callback with a goroutine
bind, under the rule that C may not retain Go pointers. C-1's audit surface becomes `unsafe.Pointer`
plus every cgo site — precisely where the platform code lives.

**C — C++20 core.** Converts C-1 from a cheap gate into the project's dominant recurring cost: where
the parser is not safe by construction, "zero new sanitizer reports" is an achievement each release
rather than the default state — and TM-24 already names a bespoke binary parser as the system's
least adversarially-reviewed surface. Weakest dependency management in the set, which makes §11.11's
SBOM and vetting obligations materially harder. No mechanical answer to "what must a reviewer read".

**D — Kotlin Multiplatform.** Kotlin/Native carries its own collector into the datapath, so C-2 is
unmet; the design therefore forks the datapath per OS — the tunnel engine, path racing and
enforcement written six times, which is exactly what R-31 forbids. No credible story for a `systemd`
daemon, a Windows service, or OpenWrt, so the router tier is excluded, contradicting R-21.

**E — Per-platform reimplementation.** Six `ConnectionState` machines, six relay rankers, six policy
evaluators, six anti-rollback implementations. The transition-coverage merge gate
([docs/testing-strategy.md](../testing-strategy.md) §2.2) must be satisfied six times and P01–P15
*proved* six times; §3.7 shows iOS runs only on a physical device farm, so five of the six would be
gated by scarce hardware. Every ADR becomes a specification six teams interpret independently, and
divergence surfaces as a field defect rather than a build failure. This is R-31's defect class.

**F — Hand-written header.** The per-language glue is where lifetime and nullability bugs live, and
it must be written four times and maintained forever.

**G — Generated bindings.** The generated FFI layer's shape belongs to the tool and its ABI moves
between tool versions — unacceptable when `abi_major` is a stability promise we make (VR-2). The
error model is enum-shaped, but **I6** requires a `reason_code` *string* with typed evidence, and
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 is explicit that an enum discards the
`DOMAIN` a receiver needs for prefix degradation. Coverage stops short of C# and plain C, so
Windows, Linux and any embedder fall outside it. The host-callback direction — the entire platform
adapter — is the least mature part of every such tool.

**H — Hybrid.** Three artifacts to keep aligned (header, contract types, wrapper layer); a mismatch
is a compile error rather than a runtime one, but it is still build-orchestration cost. Requires
discipline to keep the hand-written surface small, because every convenience added is permanent.

---

## 7. Security Implications

**7.1 The ABI is not a trust boundary, and must not be mistaken for one.** Shell and core run in
one process at one privilege. The real boundaries are ADR-0016's process boundary and ADR-0017's
management interface, and [docs/threat-model.md](../threat-model.md) §3 locates them there.
Validation at `twinvpn.h` buys nothing against an adversary and would give false assurance. What
the core **does** treat as untrusted, wherever it arrives from: packets, wire messages, link facts
reported by the OS, and every byte read from the durable store.

**7.2 Memory safety is the security argument for the language choice.** AD-12 and AD-2 both reach
the datapath's parsers, and B-3 makes any sanitizer report release-blocking. Option A makes the
codebase satisfy that gate by default and reduces "what could be memory-unsafe" to DP-4's allowlist.

**7.3 I4 is structural, not procedural.** No type in the workspace can carry an identity private
scalar; the core holds a `SignerHandle` into the host vtable, and every identity signing or
agreement operation is a call **out** to platform secure storage. The FFI exposes no function
returning private identity material. The L-DATA static private key is the already-decided exception
([ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) L-STORE): hardware-*wrapped*,
unwrapped into locked non-swappable memory owned by `twinvpn-crypto`, with TM-14 stating the
residual. This ADR does not widen that exception.

**7.4 I2 is a dependency-graph fact.** Exactly one crate may depend on a cryptographic
implementation (DP-3). Proof obligation P2 — "no build contains a bespoke primitive, AEAD,
handshake, or key schedule" — becomes a `cargo tree` assertion plus a review of one crate, rather
than an audit of the whole tree.

**7.5 Panic containment must not become a leak.** A panic caught at the ABI boundary poisons the
core instance (F-7). It MUST NOT tear down the installed kill-switch rule set: enforcement is at OS
level and locally authoritative (S-18, A-17), so a poisoned instance leaves the device `BLOCKED`,
not unprotected. This is the same argument
[docs/architecture.md](../architecture.md) §2.1 makes for process crash, applied one level down.

**7.6 Supply chain is the invariant-independent attack.** A malicious dependency or a compromised
build pipeline defeats every invariant at once: it can exfiltrate the *results* of identity
operations, weaken the RNG, or corrupt the desired rule set before the adapter installs it. §11.11
provides mechanisms (pinned lockfile, reproducible build, per-artifact SBOM, `unsafe` allowlist,
two-person dependency review, provenance handed to ADR-0021). **The threat model has no adversary
or threat row for it** — AD-1…AD-12 and TM-01…TM-30 contain none — so these mechanisms currently
mitigate an unmodelled threat. §11.16 (j) requires SECURITY to close that.

**7.7 Never-loggable discipline crosses the ABI.** Typed evidence attached to a `reason_code`
carries only fields that code declares
([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 `evidence_fields`), classified per
§11.4 of that ADR. The core, not the shell, applies redaction, because the shell has no way to know
a field's classification — and shipping unclassified evidence across the boundary would put the
never-loggable list ([docs/threat-model.md](../threat-model.md) §9) on the wrong side of it.

---

## 8. Reliability Implications

- **I5 becomes a build failure.** §11.7's rule — no data-plane crate may name the control-plane
  client crate as a dependency, direct or transitive, and the reverse edge is equally denied —
  realizes [docs/architecture.md](../architecture.md) §4.2 as a `Cargo.toml` fact. This is the
  artifact that [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) §11.8 step 3 asserts
  and that B-19 blocks a release without.
- **One implementation means one state machine to cover.** The T1 transition-coverage merge gate
  runs the core against a mock adapter on a Linux CI runner — no VM, no device farm — because CB-2
  puts every decision in the core. Under alternative E that gate is unaffordable for five of six
  platforms.
- **A poisoned core is a named, recoverable condition**, not a hang: `INTERNAL.CORE_PANIC`, the
  shell destroys and re-creates, the `Session` re-enters `RECONNECTING` from durable state exactly
  as [docs/architecture.md](../architecture.md) §2.1 requires after a process crash.
- **Determinism buys reproducible failure analysis.** With CD-1…CD-4, a field-reported transition
  sequence can be replayed at a seed. Without injected clocks,
  [docs/testing-strategy.md](../testing-strategy.md) §3.5's `BIT` class is unattainable and F-7
  (determinism defect) has no meaning.
- **Honest residual:** injected clocks give `BIT` determinism for the core's *event sequence*
  only. Levels ≥ 6 still run against real kernels, `conntrack` timers, `netem` and the scheduler.
  §3.5 already states this; this ADR does not improve it and does not claim to.

---

## 9. Performance Implications

Full budgets are in §11.13. The load-bearing points:

- The split costs **zero per-packet ABI crossings** on Linux, OpenWrt, Windows and Android, and
  **one crossing per batch plus one copy per packet** on iOS, iPadOS and the macOS app-extension
  configuration, where `NEPacketTunnelFlow` is the only path and it hands the caller `Data`.
- The ABI carries commands and events at state-transition rates (order 1–10²/s), not packet rates
  (order 10⁵–10⁶/s). That is why a message-port ABI (F-8) is affordable, and why widening it into a
  per-object API would be a mistake.
- On router-class targets the ceiling is set by ChaCha20-Poly1305 without AES-NI
  ([ADR-0013](ADR-0013-multi-client-gateway-architecture.md) §9), not by the split; the split's
  contribution there is the binary and RSS budget, not throughput.
- Cold start on the iOS/iPadOS extension is the tightest latency budget in the matrix, because the
  OS starts the extension on demand while the user waits (PB-4).

---

## 10. Operational Implications

- **One toolchain pin, fleet-wide.** `rust-toolchain.toml` names an exact version; advancing it is
  a reviewed commit that re-runs the whole matrix. A per-target toolchain drift is the mechanism by
  which R-32's defect happens.
- **Three CI runner families are mandatory**, not a convenience: Linux (Linux/musl/OpenWrt/Android),
  Windows (MSVC ABI — required for WFP, IP Helper and Authenticode), macOS (Xcode licensing). T1
  fans the matrix across all three in parallel to stay inside C-11.
- **Support triage reads one record.** `CoreBuildIdentity` (S-46) answers "which core, which ABI,
  which epochs, which crypto provider, which profile, which commit" in one line of a diagnostic
  bundle. Without it, "the Windows one behaves differently" is unanswerable.
- **A withdrawn target is an announcement, not a silence** (R-32). B-8 already blocks a release on
  a supported target failing its probe unless it is removed from the matrix in the same release;
  this ADR adds the build-time half.
- **Reproducibility stops at the signature.** Apple notarization and Authenticode stamps are not
  reproducible by construction; the reproducible artifact is the pre-signature one, and its digest
  is what §11.10 hands ADR-0021.

---

## 11. Decision

**Adopt A (Rust portable core over a stable C ABI, thin native shells) and H (hand-written
`twinvpn.h` as the ABI of record, generated idiomatic wrappers above it).** H1 is **confirmed**.

### 11.1 The split line, and the rule that decides ambiguous cases

**CB-1 — the split rule (normative).** Code belongs in a **shell** if and only if it (a) must call
a platform API that has no stable C-callable form, (b) must execute inside an OS-imposed process,
extension or service that the OS itself starts, or (c) is user-interface presentation. Everything
else belongs in the **core**. **Ambiguity resolves to the core.**

**CB-2 — the shell holds no decision.** A shell MAY translate, marshal, schedule and render. It
MUST NOT contain a branch whose condition is a TwinVPN domain fact — a `ConnectionState`, a
`reason_code` class, a policy verdict, a candidate priority, a timer expiry, a version comparison.
The falsification test: with every shell deleted and a mock adapter bound, the core must still make
every decision correctly. If it cannot, a decision leaked into a shell.

**CB-3 — no OS branch above the adapter.** [docs/networking.md](../networking.md) §5.1 requires
that nothing above the adapter branch on OS. Concretely: `#[cfg(target_os = …)]` is permitted only
in `twinvpn-platform-*` crates and in shells. Enforced by a T1 lint over the crate set.

**CB-4 — the core *resolves*; the shell *presents*.** These are two jobs and the line between them
is exact, because [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) hosts its
presentation resolver **inside** the core and an earlier form of this rule read as forbidding that:

| Job | Side | Content |
|---|---|---|
| **Resolution** | **Core** | `reason_code` + typed evidence + **locale + platform context** → catalogue lookup, evidence substitution into the declared template, the F-4 `resolved` attribute set, and the next-action **variant** selected per ADR-0019 LT-3. A **pure function** of its inputs (F-10) |
| **Presentation** | **Shell** | typography, layout, truncation, platform idiom, accessibility, iconography, and where the result appears |

Resolution belongs in the core under CB-2: it is a *decision* over declared data
([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2's registry attributes), and six shells
each mapping `reason_code` → message would be six divergent mappings — R-31's defect class exactly.
It also keeps resolution on the same side as the redaction classification §7.7 already requires the
core to own; splitting them would put half of one decision on each side of the boundary. What the
core still MUST NOT do: hardcode a language, read an ambient locale, or make a layout decision.
Locale is an explicit parameter, never ambient (CD-2). The catalogue ships **embedded in the
artifact**, so it is covered by S-46 and by DP-5's SBOM.

**CB-5 — secret custody is the one inversion, and its boundary is `authentication path`.**
Because of I4 the core cannot hold the identity private half, so identity *operations* are calls out
to the shell (§11.4). This is the only place where the core depends on a shell-provided capability
that is not the platform adapter.

The line is **not** "secrets live in the shell" — §7.3 already holds the L-DATA static private key in
core memory under ADR-0001's L-STORE decision. There are **three** kinds, not two:

| Key kind | May the core hold it? | Why |
|---|---|---|
| **Identity authentication path** — identity key (IK), `OwnerSigningKey`, `OwnerRootKey` | **Never.** Operations are vtable calls (`identity_sign`), performed **inside the element** | I4. Holding it means an attacker who reads core memory can *act as* this `Device`, and the compromise **outlives the device** rather than ending at revocation (TM-14) |
| **Tunnel authentication key** — the L-DATA static X25519 (TK) | **Yes**, hardware-*wrapped*, unwrapped into `twinvpn-crypto`'s locked, non-swappable, non-dumpable allocator | **A conceded platform-capability exception, not a security argument.** TK *does* authenticate — `Noise_IKpsk2` mixes both statics (TM-07) — so on principle it belongs in row 1. It is in row 2 because platform key APIs largely do not offer X25519 ECDH, which is exactly why [ADR-0007](ADR-0007-device-identity-and-pairing.md) N-5 seals it rather than making it element-resident. The residual is stated, not argued away: TM-14 — *TK extraction from process memory is undefended* |
| **Data-at-rest key** — the store encryption key (SEK) | **Yes**, same allocator | The only *principled* member of the core-held set. Compromise yields vault plaintext an attacker at that privilege largely reaches anyway, and confers **no** ability to authenticate as this `Device` |

An earlier revision collapsed rows 2 and 3 and justified both with "confers no ability to
authenticate as this `Device`". That is true of SEK and **false of TK**. The rows are separated here
because the reasons differ in kind: row 3 is a security argument, row 2 is a capability constraint
the corpus already conceded and whose residual TM-14 already carries. Conflating them would let a
future capability constraint borrow row 3's justification, which is the erosion CB-6a exists to stop.

**CB-6a — a core-held key is a DECLARED per-target fact, and on most targets it is the norm rather
than the exception.** Where the platform key API can perform the record AEAD itself, it **MUST**;
where it cannot, the key is core-held and that MUST be recorded in `CoreBuildIdentity` (S-46) and
surfaced in the diagnostic bundle, so "this device's vault key was software-held" is a readable fact
rather than an inference. Extending core-holding to any **identity** authentication-path key (row 1)
requires a new ADR under I4, not a review comment.

**The honest aggregate, from [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md)'s
per-target survey: mandatory platform AEAD exists on 2 of 10 targets** — Android (Keystore AES-GCM
with `setRandomizedEncryptionRequired`) and Windows with a TPM (CNG symmetric under the PCP). On the
three Apple targets the Secure Enclave offers key agreement and signing but no arbitrary-length AEAD
over caller data; on Linux with TPM 2.0 the symmetric path is orders of magnitude too slow for
per-record use; on Linux without TPM, OpenWrt, routers, headless and CLI-only there is no key API at
all.

So **the software-held path is the common case, and this ADR calls it that rather than "the
fallback"** — language that would let the corpus read as "usually hardware-protected, occasionally
not" when the truth is the reverse. Two consequences worth stating plainly:

1. **The declaration's value is discrimination, not rarity.** A flag that is set on 8 of 10 targets
   still tells a reviewer the real fleet posture at a glance and identifies exactly which two
   targets are stronger. That is what S-46 carrying it is for.
2. **The residual is not a new exposure class.** An attacker at agent privilege who can read SEK
   from core memory is AD-12-at-agent-privilege, which TM-14 already records as undefended for TK.
   SEK **joins an existing, already-stated residual** rather than opening a new one — which is why
   this is acceptable, and is the form the statement must take under
   [docs/vision.md](../vision.md) §4.1's rule that a platform limitation is named with its residual
   rather than silently relaxed.

**CB-7 — the store splits at the CB-1 line, not at the word "store".** A transaction engine is
*all decision* — write-ahead ordering, crash recovery, monotone rejection, migration — so CB-1 and
CB-2 put it in the core, and ten shells implementing it is R-31's defect class in its purest form.
What genuinely has no stable C-callable form is (a) secure-item storage, and (b) *obtaining* the
vault directory and stamping its platform attributes — on iOS the app-group container URL, the file
protection class, and the backup-exclusion flag are Objective-C APIs. **Ordinary file I/O over a
path that has already been vended is POSIX on all ten targets**, so by CB-1 it belongs in the core.

| Concern | Side | Mechanism |
|---|---|---|
| Record envelopes, AEAD, namespaces, schema, migration, monotone-floor rejection, recovery ladder, **multi-key commit** | **Core** (`twinvpn-store`) | all decision — CB-1, CB-2, R-31 |
| Tier-2 vault file I/O | **Core**, beneath a shell-vended `store_root` | POSIX; stable C form everywhere |
| Vending `store_root`; file-protection class; backup exclusion | **Shell** | no stable C form; only the shell knows the sandbox container or the OpenWrt overlay path |
| Tier-1 secure items — SEK, `K_bind`, the S-53 anchor | **Shell**, via `secure_item_*` | Keychain / Keystore / DPAPI / libsecret; whole-blob, per-item |
| Identity private half | **Shell only** | CB-5, I4 — unchanged |

**CB-6 — enforcement is computed in the core and held by the OS.** The core computes the desired
rule-set generation; the adapter installs it; the OS holds it. A core crash therefore cannot drop
protection (C-7, S-18).

### 11.2 Component map — [docs/architecture.md](../architecture.md) §2.1–2.22

| Component | Core | Shell | Seam, where split |
|---|---|---|---|
| 2.1 TwinVPN Client | **all logic** | process hosting only | the whole ABI |
| 2.2 Gateway / server role | admission, per-peer policy, accounting, fairness decisions | — | forwarding is kernel-side via the adapter. Not offered on iOS/iPadOS/Android ([ADR-0013](ADR-0013-multi-client-gateway-architecture.md)) |
| 2.3 Tunnel Engine | handshake driver, rekey scheduling, replay window, key state | — | **split by datapath**: on Linux/OpenWrt the core *programs* the kernel WireGuard module; elsewhere the core *is* the datapath (§11.13) |
| 2.4 Packet-Routing Engine | route and address computation, MTU/MSS, collision detection | — | `apply(contract_generation)` installs |
| 2.5 Platform Network Adapter | the **trait** | the **implementation** | **this is the seam** (§11.6) |
| 2.6 Device Identity | public identity, use-site protocol, attestation record | custody, sign/agree | `identity_*` vtable entries (CB-5) |
| 2.7 Pairing Subsystem | ceremony, SPAKE2/QR verification, idempotency | camera, QR render, display | commands + events |
| 2.8 Control Plane Service | *client only* (`twinvpn-cp-client`) | — | server-side is a different artifact |
| 2.9 Rendezvous / Discovery | *client only* | — | as 2.8 |
| 2.10 NAT Traversal | **all** — gathering, racing, validation, ladder | — | sockets via the adapter |
| 2.11 Relay Infrastructure | *client leg only* | — | the relay server is a separate artifact sharing `twinvpn-schema` and the framing crate |
| 2.12 Relay-Selection Service | client-side ranking, HRW, measured-RTT override (S-31) | — | ranked set is cached state |
| 2.13 Device-Presence Service | *client only* | — | — |
| 2.14 Policy Engine | **all** evaluation | — | enforcement programmed via adapter |
| 2.15 DNS Subsystem | stub resolver, `DNSPolicy` evaluation, restore-point bookkeeping (S-34) | — | resolver configuration installed via `apply` |
| 2.16 Kill Switch | latch, reconciler, desired-ruleset computation, `BLOCKED` decision | — | `set_ruleset(BLOCKED\|PROTECTED)`; OS holds the rules (CB-6) |
| 2.17 Local-LAN Discovery | announcement, candidate production, authentication | — | multicast sockets via adapter |
| 2.18 Exit-Node Functionality | policy, per-peer accounting | — | forwarding kernel-side |
| 2.19 Telemetry / Observability | ring buffer, event emission, redaction classification, bundle assembly | export, share sheet, file save | on iOS/iPadOS diagnostics run in the app process ([docs/networking.md](../networking.md) §5.4) via the `core-lite` profile (§11.12) |
| 2.20 Configuration / State Storage | schema, migration, monotonic-version enforcement, integrity verification | byte-level store, secure storage | `Store` capability; realization is [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md) |
| 2.21 Update / Version Management | rollback-floor check against S-23 only | **all** delivery | [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) owns it |
| 2.22 `Owner` Root-of-Trust | verification of anchors, delegations, epochs | OSK secure-element operations, ceremony UI | as 2.6 |

### 11.3 Language and runtime

| Constraint | Rust (A) | Go (B) | C++ (C) | KMP (D) | Per-platform (E) |
|---|---|---|---|---|---|
| Memory safety in a network-facing parser (C-1) | **yes, by default** | yes | no | yes | mixed |
| No GC in the datapath (C-2) | **yes** | GC present; heap headroom is the real cost | yes | GC present | mixed |
| Static link, small binary, router-class (C-4) | **yes** (~2–4 MB class) | ~8–15 MB class | **best** | poor | n/a |
| iOS/iPadOS extension memory (C-3) | **yes** | tight; proven but costly | yes | poor | yes |
| Android NDK + 16 KB pages (C-12) | yes, linker flags | yes | yes | native | yes |
| Windows service, MSVC ABI | yes | awkward | **yes** | no | yes |
| musl / uclibc | **yes** | yes | yes | no | n/a |
| Cross-compilation reach | good (needs vendor SDKs) | **best** | good | poor | n/a |
| FFI *into* the core from C (host vtable) | **fn pointer, one call** | cgo callback + goroutine bind | **native** | JNI/ObjC bridge | n/a |
| Audited crypto for all of TM §11 on all targets | yes, with the DP-7/DP-8 caveat | yes | yes | partial | n/a |
| Answers "what must a reviewer read for C-1" | **an allowlist** | `unsafe.Pointer` + every cgo site | the whole tree | n/a | ×6 |
| Satisfies R-31 | **yes** | yes | yes | **no** (datapath forks) | **no** |

**Selected: Rust.** Concrete bindings:

- One exact toolchain version pinned in `rust-toolchain.toml`, edition 2021 or later, advanced only
  by a reviewed commit that re-runs the full §11.9 matrix.
- `#![forbid(unsafe_code)]` in every crate except the DP-4 allowlist.
- Release profile: `lto = "fat"`, `codegen-units = 1`, `strip = "symbols"`; `opt-level = 3` on
  desktop/server, `opt-level = "z"` on router-class.
- `panic = "unwind"` in every shipped profile — **not** `abort` — because F-7's containment requires
  `catch_unwind` at the boundary. Entry points are declared `extern "C"` (not `"C-unwind"`), so an
  unwind that somehow escapes a wrapper aborts deterministically rather than becoming undefined
  behaviour.
- **Async with injected time.** The core is `async`, over a `Runtime` capability. Two bindings ship:
  a work-stealing runtime on Linux, Windows, macOS, Android and OpenWrt (single-threaded scheduler
  on iOS/iPadOS to stay inside C-3), and a virtual-time single-threaded runtime for TwinLab.
  Regardless of runtime, `Clock`, `Timer` and `Rng` are always injected traits (CD-1), so the lab's
  determinism does not depend on the runtime's cooperation.

### 11.4 The C ABI — `twinvpn.h`

**F-1 — the surface is small and coarse.** Roughly a dozen functions. Every exported function is a
compatibility obligation forever; convenience added here is permanent. **One deliberate exception
is granted, in F-10.**

**F-2 — ownership.** A buffer crossing the boundary is either borrowed for the duration of one call
(`const uint8_t*, size_t`) or owned by the allocator that created it and released by that side's
own free function. The core never frees a shell allocation; the shell never frees a core
allocation. No `malloc`/`free` pairing crosses the boundary.

**F-3 — strings and buffers.** UTF-8, length-delimited (`tw_slice`), never relying on NUL
termination, never assumed valid on input: invalid UTF-8 is a typed error, never a panic.

**F-4 — errors carry a name, never an errno (I6, R-22).** No function returns a bare `int`, a
negative errno, or a `bool` as its failure signal. Every fallible call yields, on failure, an
opaque `tw_buf` whose bytes decode to `{ reason_code, evidence, resolved }` in
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 form, with evidence restricted to that
code's declared `evidence_fields` and already redacted per §11.4 of that ADR. The shell MUST NOT
synthesize error text; it renders what it is given (CB-4, ADR-0019).

`resolved` carries the code's **registry attributes, looked up core-side at emission time**:
`class`, `severity`, `terminal`, `user_actionable`, `remediation_class`, `scope`, `doc_anchor`.
It is present for **every** code, including one the receiving consumer does not recognize — that is
the point: an unknown code still arrives with its severity and actionability intact, so a consumer
can behave correctly on a code shipped after it was built (ADR-0015 §11.2 rule 4's prefix
degradation, strengthened from "degrade on `DOMAIN`" to "degrade with the real attributes").

**`resolved` is metadata, not rendered text, and the distinction is normative.** Every field is a
machine-readable registry value — an enum, a boolean, or a stable anchor. No field is localized, and
none is a sentence. Carrying it therefore does **not** breach CB-4 (the core owns no user-visible
string) and does not breach [ADR-0017](ADR-0017-local-management-interface.md) MI-15 (no rendered
human text on the wire). Rendering remains a separate, later call the consumer makes on its own side
of the boundary (F-10). Adding a `summary`, `message`, or `title` field here would breach both, and
MUST NOT be done.

This shape exists because the core owns the registry lookup (CB-4). If the ABI carried only the bare
code, ADR-0017 would have to resolve these attributes itself — a second registry outside the core,
which contradicts CB-4 and is R-31's defect class. Requirement raised by
[ADR-0017](ADR-0017-local-management-interface.md) MI-14 and adopted here.

**F-5 — the async model is submit + one ordered event stream.** No blocking call crosses the
boundary except `tw_core_next_event`, which takes an explicit timeout and is cancellable via
`tw_core_wake`. `tw_core_submit` is non-blocking. All state changes, including the completion of a
submitted command, arrive as events on **exactly one** totally ordered stream per instance. This is
the same shape [ADR-0017](ADR-0017-local-management-interface.md) needs, so the local management
interface is a *transport* over this command/event set rather than a second contract (§11.16 (b)).

**F-6 — threads and reentrancy.** A `tw_core*` is `Send` but not `Sync` for mutating calls: exactly
one thread may hold it for mutation at a time (S-47). Read-only snapshot calls are safe from any
thread. Host vtable callbacks MAY be invoked on a core-owned thread; a callback MUST NOT re-enter
any mutating core function. Debug builds carry a reentrancy guard that trips
`INTERNAL.INVARIANT_VIOLATED`.

**F-7 — panic containment.** Every `extern "C"` body is wrapped in `catch_unwind`. A caught panic:
emits `INTERNAL.CORE_PANIC` with the transition context, marks the instance **poisoned**, makes
every subsequent call return that code, and obliges the shell to `tw_core_destroy` and re-create.
It MUST NOT tear down the installed rule set (§7.5). Every occurrence is a defect
([ADR-0015](ADR-0015-observability-and-diagnostics.md), `INTERNAL` domain) and a §14 revisit
trigger.

**F-8 — only handles, slices and scalars cross; structured data crosses as encoded bytes.** No
`struct` with product fields is defined in `twinvpn.h`. Commands, events, configuration, link facts
and the network-contract plan cross as length-delimited encoded blobs generated from ADR-0003's
contract artifacts. Consequence: the ABI is almost impossible to break accidentally, and idiomatic
wrappers (H) generate from the same source as the message types. Cost: one encode and one decode
per command and per event — free at the event rates §9 establishes, and a §14 revisit trigger if
those rates change.

**F-10 — `tw_render_diagnostic` is a pure, instance-free entry point, and is F-1's one exception.**
[ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) hosts its presentation resolver
in the core (CB-4) and requires the render call to be pure so its **P18** can drive it
exhaustively. Routing it through `tw_core_submit` would be wrong, not merely inelegant: submit
requires a live, un-poisoned instance, and **the moment a diagnostic most needs rendering is
exactly when no such instance exists** — after `INTERNAL.CORE_PANIC` poisoned it (F-7), before
`tw_core_create` has run, or inside a crash reporter. The function therefore takes no `tw_core*`:

```c
/* Pure: no I/O, no clock, no ambient locale, no ambient platform, no instance, no global state.
   Same inputs → same bytes, on every target. Callable while an instance is poisoned. */
tw_buf *tw_render_diagnostic(tw_slice reason_code, tw_slice evidence,
                             tw_slice locale_bcp47, tw_slice platform_ctx);
uint32_t tw_reason_registry_version(void);   /* the registry this build was compiled against */
```

**`platform_ctx` is the fourth parameter, and it is compelled by CB-2 rather than by taste.**
[ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) LT-3 selects the next-action
variant by `(platform, os_version_range)`, and the variants turn on OS **version**, not merely
platform: macOS `SMAppService` on 13+ versus the legacy login-item API on 11–12; Android 13+
`POST_NOTIFICATIONS` where earlier releases have no such prompt. Three reasons it is a parameter:

1. **The alternative puts a decision in a shell.** If the core returned only a next-action *key* and
   each shell picked the variant, the GUI and the CLI **on the same host** would implement that
   selection independently and could diverge — two implementations of one decision, which CB-2
   forbids and R-31 names as a defect class. This is ADR-0019's R-36 / HP-3 / P18-oracle-6 property,
   and it is a same-host GUI-vs-CLI parity claim, not a claim that a Windows string equals an
   Android one.
2. **Ambient OS version fails on exactly the grounds ambient locale does.** CD-2 forbids ambient
   state because it defeats exhaustive testing; an instance-free call could not read it anyway.
   A parameter is not state, so F-10's purity and instance-freedom are preserved either way.
3. **Platform is in the parameter too, though a build could imply it** — because the renderer must
   be able to render for a platform it is *not running on*. P18 drives every variant exhaustively
   from one Linux CI runner (the CD-5 argument, applied to rendering), and a support workstation
   renders a diagnostic bundle collected from a different platform. A build-time constant would
   break both.

Shape follows F-8: `platform_ctx` is a length-delimited encoded blob generated from ADR-0003's
contract artifacts, carrying at least `{platform, os_version}` and extensible — adding `arch` or a
distro identifier later needs no ABI break. **An empty `platform_ctx` MUST resolve to the
platform-neutral variant and MUST NOT fall back to the host's own platform**, which would readmit
ambient state through the back door. That obliges ADR-0019's catalogue to define a neutral variant
for every code, checkable in CI as a catalogue-completeness rule (§11.16 (n)).

Ownership is F-2 (core allocates, `tw_buf_free` releases), encoding is F-3 (UTF-8, length-delimited,
never NUL-reliant), and an unknown `reason_code` degrades on its `DOMAIN` prefix per
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 rule 4 rather than failing. **Naming is
settled: the symbol is `tw_render_diagnostic`.** Every symbol in `twinvpn.h` carries the `tw_`
prefix, and a single `tv_`-prefixed export would be an inconsistency in the one place consistency is
load-bearing — an ABI whose symbols do not share a prefix cannot be reviewed, linted, or namespaced
as a unit. `tw_reason_registry_version()` discharges ADR-0019's "expose the registry version built
against" and is mirrored in S-46, so it also reaches the diagnostic bundle without a live instance.

**A core fault cannot abort a UI process**, on every target, by two different mechanisms: on
Windows, macOS, Linux and Android the UI process **does not load the core at all** (§11.5) and a
fault is in another process entirely; on iOS/iPadOS, where the app process hosts `core-lite`, F-7's
`catch_unwind` and poison are what contain it. F-10's purity closes the remaining gap — a poisoned
instance still renders diagnostics, so the UI can display the fault that poisoned it.

```c
/* twinvpn.h — ABI major 1. Hand-written; this file is the ABI of record. */
typedef struct tw_core tw_core;                                   /* opaque instance   */
typedef struct tw_buf  tw_buf;                                    /* opaque core alloc */
typedef struct { const uint8_t *ptr; size_t len; } tw_slice;

uint32_t  tw_abi_major(void);
uint32_t  tw_abi_minor(void);
tw_slice  tw_build_identity(void);        /* S-46; static storage, never freed        */

tw_core  *tw_core_create(uint32_t abi_major_expected,
                         const tw_host_vtable *host,
                         tw_slice config, tw_buf **err_out);
void      tw_core_destroy(tw_core *);

int32_t   tw_core_submit(tw_core *, tw_slice command, tw_buf **err_out);
int32_t   tw_core_next_event(tw_core *, uint32_t timeout_ms,
                             tw_buf **event_out, tw_buf **err_out);
void      tw_core_wake(tw_core *);        /* callable from any thread                 */

tw_slice  tw_buf_bytes(const tw_buf *);
void      tw_buf_free(tw_buf *);
```

**F-9 — the host vtable, and the inversion of `subscribe_network_change`.** The vtable carries
[docs/networking.md](../networking.md) §5.1 verbatim, plus the CB-5 capabilities. Its first field is
`uint32_t size`, so entries may be added without an `abi_major` bump.

```c
typedef struct {
  uint32_t size;  void *ctx;
  /* docs/networking.md §5.1 */
  int32_t (*create_interface)(void*, tw_slice name, uint32_t mtu, uint64_t *h, tw_buf **err);
  int32_t (*apply)(void*, uint64_t h, uint64_t contract_generation, tw_slice plan, tw_buf **err);
  int32_t (*rollback)(void*, uint64_t h, uint64_t contract_generation, tw_buf **err);
  int32_t (*set_link)(void*, uint64_t h, int32_t up, tw_buf **err);
  int32_t (*set_ruleset)(void*, uint64_t h, int32_t ruleset, tw_buf **err); /* 0=BLOCKED 1=PROTECTED */
  int32_t (*query_link_facts)(void*, tw_buf **facts, tw_buf **err);
  int32_t (*destroy_interface)(void*, uint64_t h, tw_buf **err);
  /* subscribe_network_change: see below — realized inbound, deliberately absent here */
  /* CB-5 capabilities */
  int32_t (*identity_public)(void*, tw_buf **spki, tw_buf **err);
  int32_t (*identity_sign)(void*, tw_slice msg, tw_buf **sig, tw_buf **err);
  int32_t (*identity_attestation)(void*, tw_buf **att, tw_buf **err); /* hardware_backed, truthfully */
  /* Tier 1 ONLY — secure-storage-shaped items (SEK, K_bind, the S-53 anchor).
     Whole-blob atomic replacement, which is the shape Keychain / Keystore / DPAPI / libsecret
     actually have. NOT a general store: see CB-7. */
  int32_t (*secure_item_read)(void*, tw_slice key, tw_buf **val, tw_buf **err);
  int32_t (*secure_item_write_atomic)(void*, tw_slice key, tw_slice val, tw_buf **err);
  /* Tier 2 — the shell vends the directory and stamps its platform attributes; the core does
     the I/O beneath it. The path is INJECTED at construction, never discovered (CD-2). */
  int32_t (*store_root)(void*, tw_buf **path_utf8, tw_buf **err);
  int32_t (*os_csprng)(void*, uint8_t *out, size_t len);
} tw_host_vtable;
```

`subscribe_network_change(cb)` is **not** a function pointer the core hands out. Handing the OS a
pointer into the core would let a network-change notification arrive on an arbitrary thread while a
mutating call is in flight, breaking F-6. It is realized instead as: the shell subscribes with the
OS (still event-driven, never polled, exactly as §5.1 requires) and, on each event, calls
`tw_core_submit` with a `NetworkChanged` command carrying the new link facts. The contract's
*meaning* is unchanged; only its carriage is specified. §11.16 (h) asks NETWORKING to confirm.

### 11.5 Per-shell binding — and which processes load the core at all

Under H2/H3 the privileged host loads the core; every other process reaches it over ADR-0017. That
collapses the binding matrix to two languages:

| Process | Loads the core? | Binding | Rationale |
|---|---|---|---|
| iOS / iPadOS NE extension | **yes** | Swift ← module map over `twinvpn.h` + generated Swift wrapper | the OS starts the extension; the datapath must live in it |
| iOS / iPadOS app | yes, **`core-lite` profile** | same | C-3 assigns contract parse and diagnostics here; §11.12 |
| Android `VpnService` | **yes** | Kotlin ← generated JNI shim over `twinvpn.h` | fd obtained once at setup, then read directly (§11.13) |
| Android UI activity | no | ADR-0017 over binder | it is a UI |
| macOS system extension | **yes** | Swift, as iOS | |
| macOS app | no | ADR-0017 | |
| Windows service | **yes** | **Rust, links `staticlib` directly — no ABI crossing in-process** | avoids a second runtime in a privileged network service |
| Windows UI (WinUI / C#) | no | ADR-0017 | C#/P-Invoke into the core is rejected: unnecessary for a UI, and a GC'd runtime inside the privileged service would be a large, hard-to-audit surface |
| Linux `twinvpnd` | **yes** | Rust, static link | |
| Linux `twinvpnctl`, OpenWrt `ubus` bridge | no | ADR-0017 | R-21: the CLI uses the same control contract as the GUI, by construction |

The C ABI therefore has exactly **two** first-class consumers — Swift and Kotlin — plus any future
third-party embedder. That is the smallest forever-obligation consistent with H1, and it is a
direct consequence of H2/H3 being true; §11.15 B-01/B-02 record what changes if they are not.

**iPadOS specifics.** Stage Manager and multi-window mean several UI scenes in one app process.
There is still exactly **one** `core-lite` instance and one ADR-0017 client per app process (S-47);
scene state is shell state (ADR-0019). External display, hardware-keyboard shortcuts and Files
integration are entirely shell concerns. The app process is more likely to stay resident than on
iPhone, which changes nothing normative — but it does mean an iPadOS-only bug in the app↔extension
handoff can hide on iPhone, so §11.9's device matrix lists iPadOS as a distinct farm entry.

### 11.6 The seam, in both directions

| Direction | Mechanism | Thread | Blocking | Failure |
|---|---|---|---|---|
| core → shell: create/apply/rollback/set_link/set_ruleset/query_link_facts/destroy | host vtable call | the core thread making the call | yes, bounded by the adapter's own contract | typed `reason_code` in `err_out`; `apply` is all-or-nothing per generation and idempotent on the generation id ([docs/networking.md](../networking.md) §5.1, [ADR-0008](ADR-0008-idempotency.md)) |
| core → shell: identity sign/agree/attest | host vtable call | as above | yes | `AUTH.KEY_UNAVAILABLE` class per [ADR-0007](ADR-0007-device-identity-and-pairing.md) |
| core → shell: store read/write | host vtable call | as above | yes | `STORE.*` per [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md) |
| shell → core: network change, lifecycle, user intent, management requests | `tw_core_submit` | any, serialized by S-47 | no | rejected commands produce an event, never a silent drop |
| core → shell: state, transitions, diagnostics, command completions | `tw_core_next_event` | the shell's drain thread | with timeout | a dropped event is itself recorded ([ADR-0015](ADR-0015-observability-and-diagnostics.md)) |

### 11.7 Module decomposition, and the arrows that enforce the invariants

```
                      twinvpn-types   twinvpn-schema(gen)   twinvpn-env
                            ▲                ▲                  ▲
                            └────────┬───────┴──────────┬───────┘
                                     │                  │
        twinvpn-crypto ──────────────┤        twinvpn-platform (trait only)
        (ONLY crate with a crypto dep)│                  ▲
                                     │                  │
                              twinvpn-store ────────────┘
                                 ▲        ▲
        ── DATA PLANE ───────────┘        └──────────── CONTROL-PLANE CLIENT ──
        twinvpn-tunnel   twinvpn-path                    twinvpn-cp-client
        twinvpn-relay-client  twinvpn-route              twinvpn-trust
        twinvpn-dns      twinvpn-enforce
        twinvpn-gateway  twinvpn-session
                    ▲                                             ▲
                    └──────────────── twinvpn-core ───────────────┘
                                   (composition root)
                                            ▲
                             twinvpn-diag ──┤── twinvpn-mgmt
                                            ▲
                                      twinvpn-ffi  →  twinvpn.h  (cdylib/staticlib)
```

**CD-I5 (normative).** No crate in the data-plane group may declare `twinvpn-cp-client` as a
dependency, **direct or transitive**. The reverse edge is equally denied: `twinvpn-cp-client` MUST
NOT depend on any data-plane crate. The only path between them is `twinvpn-store`. Only
`twinvpn-core`, the composition root, may name both, and it wires the control-plane client *to the
store* and the data plane *from the store* — never to each other. This is
[docs/architecture.md](../architecture.md) §4.2 expressed as a dependency arrow, asserted in T1,
and it is the artifact [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) §11.8 step 3
requires and B-19 blocks a release without.

**CD-I2.** Only `twinvpn-crypto` may declare a dependency on a cryptographic implementation.
Asserted by a banned-dependency rule with a single-crate exception. This is P2's static half.

**CD-I4.** No type in the workspace can carry an identity private scalar; `twinvpn-trust` holds a
`SignerHandle` into the host vtable. The L-DATA static private key is the stated exception of §7.3
and lives only in `twinvpn-crypto`'s locked allocator.

**CD-CB3.** `#[cfg(target_os)]` outside `twinvpn-platform-*` and the shells fails T1.

### 11.8 Determinism and testability

**CD-1 — there are THREE clock types, and they are not interchangeable at the type level.**
`twinvpn-env` defines `MonotonicClock`, `ElapsedClock`, `WallClock`, `Timer`, `Rng`, `Runtime` and
`Entropy`. Nothing else in the workspace may read time or randomness. Adopting
[ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) LC-8 / I-03b:

| Type | Advances across suspend? | What takes it |
|---|---|---|
| `MonotonicClock` | **No** | every timer in [docs/reliability.md](../reliability.md) §5; watchdogs |
| `ElapsedClock` | **Yes** | suspend-gap measurement, rekey-window comparison, NAT binding-lifetime attribution |
| `WallClock` | n/a — **evidence only, never a timer input** | diagnostics, and validity windows subject to CD-1a |

**They MUST be distinct types with no conversion**, so a call site cannot silently take the wrong
one. Three reasons this is a type problem rather than a naming convention:

1. **The same spelling means opposite things across our targets.** Linux `CLOCK_MONOTONIC`
   *excludes* suspend; Darwin's *includes* it; on Windows the `MonotonicClock` is
   `QueryUnbiasedInterruptTime`, where "unbiased" means sleep is *excluded*. Per-platform mapping is
   [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) LC-8's and is not restated
   here.
2. **Rust's obvious default is wrong half the time.** `std::time::Instant` is suspend-exclusive on
   both Linux and Darwin — correct for `MonotonicClock`, silently wrong for anything needing the
   gap. CD-3's deny-list therefore bans `Instant::now` outright rather than steering it.
3. **Getting it backwards defeats recovery.** With one advancing clock, resuming from an 8-hour
   sleep fires every short-horizon timer's accrued backlog at once, and `T_DEAD` (15 s) declares
   every path dead *before* the wake ladder can re-validate one. The suspend window is already
   handled by parking and re-validation, so accruing through it actively defeats the recovery path.

**This sharpens the A-21 finding of §11.8.** Gap (2) said A-21 omits "a timer" as a distinct
injectable. LC-8 shows that is still not sufficient: naming "a timer" without naming **which of the
three clocks** each call site takes leaves exactly the ambiguity that produces a suspend defect —
and the defect is invisible on Linux CI and appears only on Darwin.

**CD-1a — wall-clock time is a three-state value, because most `GC-0` hardware has no RTC.**
OpenWrt-class devices boot to epoch 0 on every power cycle
([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) §11.16a). `Clock::wall()` therefore
returns `Unset` · `Offset{source}` · `Trusted`, never a bare timestamp, and **the core MUST NOT
evaluate any validity window — `nbf`/`exp`, TTL, certificate `not_after`, pairing expiry — against a
wall clock in the `Unset` state.** It is not a deadlock: ADR-0005's relay-supplied offset and
ADR-0009 K-2/K-6 already resolve it, and the offset moves the clock to `Offset`. The rule exists so
that the *unresolved* state is unrepresentable rather than silently reading as 1970 — which would
make every `nbf` check pass and every `exp` check fail, the worst possible failure direction for
admission control.

Monotonic time is unaffected and is what every timer in [docs/reliability.md](../reliability.md) §5
runs on, which is why keepalive, backoff and migration work correctly before any offset arrives.
This makes the type system carry the constraint: a `Trusted`-only API cannot be called with an
`Unset` clock, so the check is at compile time rather than in review. Boundary case worth naming:
`INTERNAL.INVARIANT_VIOLATED` if a validity window is evaluated against `Unset` — that is a defect,
not an operating state.

**CD-2.** Every component takes its `Env` at construction. No global, no `OnceCell` clock, no
ambient default. A component that cannot be constructed without a clock cannot silently acquire
one.

**CD-3 — the lint, which is the actual mechanism.** T1 runs a deny-list over the whole workspace
excluding `twinvpn-env`'s implementations: `SystemTime::now`, `Instant::now`, `getrandom`,
thread-local RNG constructors, the runtime's own time module, `chrono` now-constructors, and the
platform time syscalls. A violation fails the merge. **This ADR claims ownership of
[docs/testing-strategy.md](../testing-strategy.md) L-3**, which that document records as an unmet
dependency on [docs/architecture.md](../architecture.md); A-21 states it as an assumption and this
section supplies the mechanism.

**CD-4 — seeded streams.** `Env::rng_for(consumer_id)` derives
`HKDF-SHA-256(ikm = scenario_seed, info = "twinlab/v1/" || consumer_id)` exactly as
[docs/testing-strategy.md](../testing-strategy.md) §3.5 specifies. `consumer_id` is a `const` at
each consumer, so adding a consumer cannot shift an existing consumer's stream.
[ADR-0006](ADR-0006-relay-discovery-and-failover.md)'s HRW hash and its
`uniform(0, T_REGION_SPREAD)` draw take their streams from `rng_for("relay/hrw")` and
`rng_for("relay/region-spread")`, which is what makes them testable.

**CD-5 — the mock adapter is the payoff.** Because CB-2 puts every decision in the core, binding
`twinvpn-platform`'s trait to a mock exercises 100% of the decision logic on a Linux CI runner with
no VM and no device farm. The transition-coverage merge gate
([docs/testing-strategy.md](../testing-strategy.md) §2.2) is affordable **because** of the split
line, not despite it.

**CD-6 — the residual, restated not improved.** Injected clocks give `BIT` determinism for the
core's event sequence. Real kernels, `conntrack`, `netem` and the scheduler remain outside any
injected provider, so levels ≥ 6 declare `STATISTICAL` for durations. §3.5 already says this.

### 11.9 The build matrix

Minimum versions are taken from [docs/networking.md](../networking.md) §5.2 unchanged (C-10).
"Budget" is stripped artifact size and steady-state RSS; both gate at T4 (§6.4).

| # | Target | Triple(s) | Toolchain / SDK | Core artifact | Linkage | Minimum | Budget |
|---|---|---|---|---|---|---|---|
| 1 | **iOS** | `aarch64-apple-ios` | Xcode + pinned Rust | `staticlib` into the NE extension | static; system libs dynamic | **iOS 15** | `staticlib` ≤ 12 MB **on disk**; **core RSS ≤ 9 MB** inside ADR-0022's 12 MB provider budget (PB-6) |
| 2 | **iPadOS** | as row 1 | as row 1 | as row 1 | as row 1 | **iOS 15** | as row 1; distinct device-farm entry (§11.5) |
| 3 | **Android** | `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`, `i686-linux-android` | NDK r26+ | `cdylib` in the AAB | dynamic vs bionic | **API 26 min / 29 target** | ≤ 6 MB per ABI; **`LOAD` alignment ≥ 0x4000** (C-12) |
| 4 | **Windows** | `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc` | MSVC | `staticlib` into the service `.exe` | static core; dynamic UCRT | **Windows 10 21H2 / Server 2019** | ≤ 8 MB |
| 5 | **macOS** | `aarch64-apple-darwin`, `x86_64-apple-darwin` (universal 2) | Xcode | `staticlib` into the system extension | static | **macOS 11** | ≤ 10 MB per arch |
| 6 | **Linux (glibc)** | `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` | pinned Rust | `staticlib` into `twinvpnd` | static core, dynamic glibc | **kernel 5.6** (5.4 with userspace datapath) | ≤ 12 MB |
| 7 | **Linux (static)** | `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` | pinned Rust | fully static `twinvpnd` | fully static | as row 6 | ≤ 12 MB |
| 8 | **OpenWrt / router — `GC-0U`** (Cortex-A53 ×2 @ ~1 GHz `mt7622`, **SIMD present**; **128 MB / 16 MB flash**) | `aarch64-unknown-linux-musl`, `armv7-unknown-linux-musleabihf` | OpenWrt SDK **21.02** + pinned stable Rust | fully static `twinvpnd` | fully static, `opt-level="z"` | **≤ 4 MB stripped** (16 MB flash — BM-1.1 governs **both** classes); **≤ 13 MB RSS at 16 peers**; throughput per PB-3 `GC-0U` |
| 9 | **Router, 32-bit MIPS — `GC-0`** (envelope: single core ~580–700 MHz, 128 MB / ~24 MB free, 16 MB flash; canonical member 24Kc @ 580 MHz `ath79`) | `mipsel-unknown-linux-musl`, `mips-unknown-linux-musl` | as row 8 + **`build-std` on a separately pinned nightly (BM-2a)** | as row 8 | as row 8 | as row 8 | **≤ 4 MB stripped**; **≤ 10 MB RSS at 16 peers** (PB-6); throughput per PB-3 `GC-0`. **The `GC-0` class gates**, on a single-core **ARM** envelope member (BM-2b); this MIPS triple is a **nightly portability build** |
| 10 | **Headless gateway / CLI-only** | as rows 6–8 by host | as host row | as host row | as host row | as host row | as host row |

**BM-1 — three label axes, and every budget in this ADR names the silicon class it assumes.**
A budget quoted without its hardware class is void, and a label from the wrong axis is worse than
no label because it reads as precision.

| Axis | Prefix | What it classifies | Owner |
|---|---|---|---|
| **Process topology** | `HC-1` / `HC-2` / `HC-3` | Which processes exist, who is privileged, who loads the core | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) |
| **Deployment profile** | `H-*` (e.g. `H-EMB`) | How the product is deployed and operated | [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) |
| **Silicon / gateway class** | `GC-0` / `GC-0U` / `G1-a` | CPU, RAM, flash — the envelope every *number* is derived from | [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) §11.13 EM-54; `G1-a` is [ADR-0013](ADR-0013-multi-client-gateway-architecture.md)'s |

The axes **compose**: a router is `HC-3` (headless topology) **and** `H-EMB` (embedded profile)
**and** `GC-0` (constrained silicon), simultaneously, and the three facts answer different
questions. **`H-EMB` spans BOTH silicon classes** —
[ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) EM-54c states that every `H-*` profile
sits in `HC-3` and only `H-EMB` is `GC-0`/`GC-0U`. An earlier revision here read that as
`H-EMB` ≡ `GC-0`; it is not an equality, and **a gate MUST key off the silicon class, never off the
profile** — keying off `H-EMB` would gate `GC-0U` hardware at `GC-0`'s floor, the same category
error that produced BM-1.4's chimera. They remain
different kinds of claim, and **where a number is derived from hardware this ADR cites `GC-*`, not
`H-EMB`.** Two rules follow, and they are written as rules because this defect class has now
recurred three times in this corpus (ADR-0013's `G1`, an earlier `HC-0` in this ADR, and the
mis-derived budgets BM-1.4 records):

- **An ordinal in the `HC-n` series MUST NOT be used to mean a hardware envelope.**
- **A performance or size budget MUST cite a `GC-*` class.** Citing a profile or a topology where a
  silicon envelope is meant is a defect, because the reader cannot check the derivation.

**The silicon classes, adopted from [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) §11.13
rather than restated:**

| Class | Reference silicon | Measured envelope (ADR-0023) | What this ADR derives from it |
|---|---|---|---|
| **`GC-0`** | **An envelope, not one SoC**: single core, ~580–700 MHz, no crypto extensions, 128 MB RAM (**~24 MB realistically free**), 16 MB flash. Canonical member **MIPS 24Kc @ 580 MHz, `ath79`**. Binding constraint: **CPU** | kernel **20–35 Mbit/s**; userspace **8–15 Mbit/s, +3–6 MB RSS** | Row 9's gates (PB-3, PB-6). Being an *envelope* is load-bearing — see BM-2a's release valve |
| **`GC-0U`** | Cortex-A53-class with **SIMD present** (`mt7622`, `ipq40xx`) — **128 MB RAM, 16 MB flash, same as `GC-0`; more CPU only**. **`mt7621` (1004Kc ×2, no SIMD) is `GC-0`, not `GC-0U`** ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) EM-54e). ~24 MB free. 256–512 MB variants exist and raise only the peer ceiling (S-68) | kernel **≥ 80 Mbit/s**; userspace **≥ 40 Mbit/s** | Row 8's throughput floor. **Size and RSS are governed by the same 16 MB flash / ~24 MB free as `GC-0`** |
| **`G1-a`** | 4×Cortex-A72 @ 1.5 GHz, 2 GB, writable rootfs | ~300 Mbit/s aggregate | **Nothing in this ADR.** ADR-0013 §9's figure is derived here and is valid **only** here |

**BM-1.4 — the correction this table records.** An earlier revision of this ADR defined its
embedded reference as "dual-core Cortex-A53 @ ~1 GHz … 128 MB RAM, 16 MB flash" — **`GC-0U`'s CPU
paired with `GC-0`'s memory**, a device that matches neither class. Its throughput budget
(≥ 80 / ≥ 40 Mbit/s) was derived from that chimera's CPU and was therefore **2–3× above what `GC-0`
can reach** while sitting *below* `GC-0U`'s measured floor — a release-gating threshold unachievable
on the silicon its label denoted, and simultaneously too lax for the silicon it was numerically
sized against. PB-3a's "provisional until measured" caveat would not have caught it: the divergence
was in the **reference device**, not the measurement, so measuring would have confirmed a number
derived against the wrong hardware. The budgets are re-derived per class in PB-3.

Three further consequences, stated rather than inherited:

1. **The ≤ 4 MB stripped budget is a `GC-0` flash budget**, not an aesthetic one: 16 MB flash with a
   squashfs root leaves single-digit MB of usable overlay. It does **not** apply to `GC-0U`, which
   has 128 MB of flash. Devices with **8 MB flash or less are out of scope** and MUST be refused at
   install rather than half-installed.
2. **ADR-0013's `max_admitted_peers = 64` default MUST NOT be inherited by `GC-0`.** ADR-0013 §11.5
   sizes it against 2 GB and states ~21 MB typical / ~58 MB worst case at 64 peers — survivable on
   `G1-a`, impossible against `GC-0`'s ~24 MB free. The *mechanism* is already correct (MG-15
   refuses a configuration whose worst case exceeds measured available memory, at configuration
   time); only the **default** is wrong for this tier. Setting the `GC-0` default is
   [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)'s.
3. **`GC-0` is MIPS, which lands in §11.9 row 9, not row 8** — and row 9 was `build-std` and
   explicitly *not* a release gate. That made the flagship embedded target the one target with no
   gate at all, which R-21 ("router-class targets MUST be first-class") and R-32 (a supported target
   MUST meet a gated budget) jointly forbid. **BM-2a resolves it by gating row 9.**

§11.16 (f) asks ADR-0023 to confirm these classes; ADR-0013's owner still owes the amendment scoping
its G1 row to throughput. This ADR does not edit ADR-0013.

**BM-2 — one build definition.** All ten rows are produced from one workspace and one toolchain
pin. A target is *supported* only if T1 builds it.

**BM-2a — exactly one exception to the single-toolchain pin, and it exists so `GC-0` can gate.**
`GC-0` is `ath79`-class MIPS (row 9). Rust ships no prebuilt `std` for those triples, so the target
needs `-Z build-std`, which needs nightly — and BM-2 pins one stable toolchain fleet-wide. The
earlier resolution, leaving row 9 ungated, is not available. Note the argument does **not** rest on
`H-EMB` ≡ `GC-0`, which is false (BM-1): it rests on `GC-0` being **separately supported** — we ship
row 9's artifact, and `ath79` MIPS is the modal cheap OpenWrt router, so it is what R-21's
"OpenWrt-class, low-memory" names. R-32 forbids shipping a supported target without a gated
budget. Leaving it ungated would mean the flagship embedded target is the one target no gate covers,
while BM-5's honest alternative — withdrawing it — would contradict R-21 outright.

Therefore: row 9 MAY use a **second, separately pinned, exactly-dated nightly toolchain**, used for
no other row. It is recorded in S-46's `toolchain_digest` like any other, advanced only by a
reviewed commit that re-runs row 9's full build and budget check, and **row 9 gates a release**.
The cost is stated rather than hidden: a `build-std` target has no upstream CI, so a toolchain
advance can break it with no warning from outside this project, and the two-toolchain fleet is a
standing exception to BM-2 rather than a precedent.

**BM-2b — a budget is portable across envelope members only if it is BUILD-derived. Silicon-derived
budgets must be measured on the canonical member.** `GC-0` is an **envelope**, not one SoC (BM-1),
and the `build-std` fragility is a property of the `mips*-unknown-linux-musl` **triple**, not of the
envelope — a single-core **ARMv7** member has a Tier-2 prebuilt-`std` triple and no nightly
dependency. But "any member is a valid gating unit" is only half true, and the half that is false
would have this ADR measure a stand-in and report its number as the class's:

| Budget kind | Examples | Portable across envelope members? | `GC-0` disposition |
|---|---|---|---|
| **Build-derived** — a property of the compiled artifact, identical on any member built from the same source | RSS, stripped size, installed size, `.ipk`, persistent-state footprint, flash write rate | **Yes** | **Release gate.** May run on the ARM member when the MIPS build is broken |
| **Silicon-derived** — a property of the CPU | kernel and userspace throughput, cold start | **No.** 24Kc MIPS has no SIMD; a Cortex-A7 at a similar clock differs materially | **Nightly floor on the canonical `ath79` member**, disciplined by [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) §14 condition 1a — **not** a release gate |

So the `GC-0` **release gate is its build-derived budgets**, and those are exactly the ones that
close the memory hole this whole argument was about — RSS is what OOMs in the field. Its throughput
is a measured nightly floor on real `ath79` hardware, which is where that number is meaningful.
Row 9's MIPS build is a **nightly portability build** whose breakage is a filed toolchain defect
rather than a silicon-class withdrawal. BM-2a stays useful — MIPS must still build, and still needs
the pinned nightly — but no release gate depends on `build-std`, and §14 condition 10 no longer
escalates toward withdrawing `GC-0`.

**BM-2c — a silicon-derived budget names its measuring member, not merely its class.** BM-1 requires
every budget to name its silicon; where a class **spans silicon families** that is not sufficient.
`GC-0` spans MIPS 24Kc and single-core ARM, so its budgets name their measuring member.

> **ANSWERED — and the remedy is a split, not an annotation.**
> [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) **EM-54e** replies that where a
> silicon-derived budget *needs* a measuring-member qualifier to be meaningful, **the class is drawn
> on the wrong axis and MUST be split rather than annotated** — an annotation documents an ambiguity
> once, a split removes it for every future budget. `GC-0U` had grouped `mt7622` (A53, NEON) with
> `mt7621` (1004Kc, **no SIMD**) discriminating on **core count**, while the tier's stated binding
> constraint is **crypto throughput** — and on that axis SIMD is worth 2–4× on ChaCha20-Poly1305
> against roughly 2× for a second scalar core. The `GC-0`/`GC-0U` boundary is now **SIMD presence**
> and `mt7621` has moved down into `GC-0`.
>
> **Consequences for this ADR, applied above:** the ≥ 80 / ≥ 40 gate needs **no re-derivation** — it
> was derived on A53 and `GC-0U` is now A53-class by definition — and the provisional `mt7621`
> measuring decision is **reverted**. BM-2c's open item therefore closes **by construction** rather
> than by picking a weaker member. No build-derived budget moves, because both classes remain
> 128 MB / 16 MB; only silicon-derived rows re-sort, which is corroboration that the
> build-derived / silicon-derived cut sits at the right joint.
>
> *(Reconciled by the integrator after ADR-0018's owner became unavailable. This applies the answer
> this ADR explicitly asked for — "until told otherwise" — and introduces no new figure.)*

Choosing the specific gating device is this ADR's ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)
requires only that it sit inside the EM-54d envelope and ship prebuilt `std`); it is fixed in the
§11.9 row-9 note and pinned in the T4 rig inventory.

**What is deliberately NOT done: redefining `GC-0` as ARM.** The class names the worst silicon
OpenWrt 21.02 supports *that people actually run*, and `ath79` MIPS is the modal cheap router.
Defining a hardware class around our build tooling rather than the installed base would quietly drop
the most common device while leaving vision.md's "router-class targets are first-class" claim
standing — the dishonest option. Gating on an envelope member keeps the claim true; renaming the
envelope would not.

**BM-3 — cross versus native runners.**

| Family | Cross-buildable from Linux? | Native runner required for |
|---|---|---|
| Linux, musl, OpenWrt, Android | **yes** | T3 real router hardware; T3 Android device farm |
| Windows | **no** — MSVC ABI is required for WFP, IP Helper and Authenticode | T1 build and T3 VM fleet |
| macOS, iOS, iPadOS | **no** — Xcode licensing | T1 build and T3 VM + device farm |

T1 therefore fans the matrix across a Linux, a Windows and a macOS runner in parallel to stay
inside the ≤ 15 min budget (C-11). A target whose build cannot fit is moved to a lower tier as a
**reviewed change to the tier table**, per rule C-1 — never by raising the budget.

**BM-4 — budgets are gates.** A size or RSS breach at T4 is a failure, not a re-run, matching §6.4.
A router-class breach blocks at a lower threshold than a desktop breach, for the reason §6.4 gives.

**BM-5 — a target that cannot be built or budgeted is withdrawn explicitly** (R-32): named in the
support matrix in the same release, and reported at runtime by an out-of-range build as
`PLATFORM.OS_UNSUPPORTED`. B-8 already blocks the runtime half; BM-5 supplies the build half.

### 11.10 Reproducible builds, and the artifact interface handed to ADR-0021

**BM-6.** Reproducibility inputs: `--remap-path-prefix` for every source root, `SOURCE_DATE_EPOCH`,
the pinned toolchain digest, pinned SDK/NDK versions, the committed lockfile, and deterministic
archive member ordering.

**BM-7 — the honest posture.** Rows 6–10 are **bit-reproducible**. Rows 1–5 are reproducible **up
to the signature**: Apple notarization tickets and Authenticode timestamps are not reproducible by
construction. The reproducible artifact is therefore the *pre-signature* one, and it is that
artifact's digest that is published and attested.

**BM-8 — what ADR-0021 receives.** This ADR owns only what produces the artifact. The interface:

```
BuildArtifactSet := [
  { target_row, target_triple, artifact_path, artifact_sha256,
    core_version, abi_major, abi_minor, reason_registry_version,
    protocol_epoch_min, protocol_epoch_max, schema_digest,
    crypto_provider, profile,                   /* full | core-lite */
    toolchain_digest, sdk_digest, source_commit,
    sbom_path, reproducible: bool }
]
```

Signing, notarization, packaging, channels, staged rollout and update delivery are
[ADR-0021](ADR-0021-packaging-distribution-and-updates.md)'s, in full.

### 11.11 Dependency and supply-chain policy

**DP-1.** One committed lockfile for the whole workspace. No unbounded version ranges.

**DP-2 — mirror, do not source-vendor.** Dependencies are pinned by digest in a mirror, not copied
into the tree: source-vendoring makes a dependency bump invisible in the diff, which is exactly the
review a supply-chain policy exists to force. A target-specific patch uses `[patch]` with the patch
itself in-tree, reviewed, and carrying an upstream reference.

**DP-3 — the crypto seam.** `twinvpn-crypto` is the only crate permitted a cryptographic
dependency. It exposes exactly the primitive set of [docs/threat-model.md](../threat-model.md) §11
— X25519, ChaCha20-Poly1305, BLAKE2s, HKDF, ES256/P-256, HPKE, COSE/CBOR, SPAKE2 over P-256, and
QUIC+TLS 1.3 — and **this ADR does not choose the primitives**; ADR-0001 and ADR-0007 already did.
What this ADR requires of the dependency: a published implementation of exactly those algorithms,
with a published independent audit or an assurance argument recorded in the dependency ledger, and
a build for every §11.9 row. Introducing a primitive not on that list is a new ADR under I2/P2, not
a dependency bump.

**DP-4 — `unsafe` policy.** `#![forbid(unsafe_code)]` everywhere except an enumerated allowlist:
`twinvpn-ffi` (the boundary), `twinvpn-platform-*` (syscalls), and `twinvpn-crypto`'s locked-memory
allocator (`mlock`/`VirtualLock`, `MADV_DONTDUMP`, core dumps disabled — required by
[ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) L-STORE). Every block carries
a `// SAFETY:` justification. CI counts blocks; a **net increase** requires a SECURITY-owner
reviewer. Miri over the pure-Rust crates; ASan/UBSan/TSan over the FFI and platform crates at T3,
feeding B-3.

**DP-5 — SBOM.** One SPDX or CycloneDX document **per target artifact**, not per release, because
feature flags differ by target. Generated at build, digest-bound to the artifact, handed to
ADR-0021 in `BuildArtifactSet`.

**DP-6 — vetting.** A dependency ledger records, per direct dependency: why it is present, who
reviewed the last bump, whether it reaches a shipped artifact or only dev tooling, whether it
contains `unsafe`, and whether it has a published audit. Advisory, licence and duplicate-version
checks run at T1.

**DP-7 — the ladder for "no build for this target".** In order, stopping at the first that works:
(1) feature-gate the dependency out — establish whether that target needs it at all; (2) replace it
with a portable implementation; (3) add target support upstream; (4) `[patch]` in-tree with a
reviewed patch and an upstream reference; (5) **withdraw the target from the supported matrix in
that release, explicitly (BM-5)**. Shipping the target with a silently different feature set is
prohibited. The live instance of this is the crypto provider: assembly-backed providers commonly
have no build for 32-bit MIPS or older musl, which is why DP-3 defines a *seam* and why row 9 is
future-compatible rather than gated.

**DP-8 — at most two crypto providers fleet-wide.** Two implementations of the same specified
algorithm do not violate I2 — I2 forbids novel cryptography, not a second implementation — but they
double the assurance surface. Therefore: at most two, both must pass the **identical** golden-vector
corpus ([docs/testing-strategy.md](../testing-strategy.md) §2.3, byte-exact), and the provider in
force is recorded in `CoreBuildIdentity` (S-46) and printed in every diagnostic bundle.

**DP-9 — binding to the threat model.** A malicious dependency or compromised pipeline defeats
every invariant simultaneously. The mechanisms above are the mitigation; **the threat model
currently has no adversary or threat row to bind them to** (§7.6). §11.16 (j) requires one.

### 11.12 Repository organization, generated contracts, and the three version numbers

```
/core/                       one cargo workspace, all twinvpn-* crates
/core/ffi/include/twinvpn.h  hand-written; the ABI of record
/contracts/                  ADR-0003's .proto and .cddl — the single source
/contracts/gen/{rust,swift,kotlin,csharp}/   generated, committed, CI-verified byte-identical
/shells/ios/                 Swift package + Xcode project (app + NE extension)
/shells/android/             Gradle (app + VpnService)
/shells/macos/               Swift (app + system extension)
/shells/windows/             twinvpn-service (Rust) + WinUI app (C#)
/shells/linux/               twinvpnd (Rust) + twinvpnctl (Rust)
/shells/openwrt/             procd + UCI packaging over /shells/linux
/build/                      toolchain pins, target definitions, budgets.toml
/lab/                        TwinLab; never shipped
```

**Codegen rule.** `/contracts` is the single source; `/contracts/gen/**` is committed and CI
re-generates and diffs it, so a schema change that a language binding cannot express fails at merge
rather than at integration. This is what makes ADR-0003's contract artifacts reach Swift, Kotlin and
C# without a second schema.

**`core-lite`.** A feature profile of the *same* source containing `twinvpn-schema`,
`twinvpn-crypto` (verification only), `twinvpn-store`, `twinvpn-trust` and `twinvpn-diag`, and **no**
data-plane crate. It exists to satisfy C-3: the iOS/iPadOS app process **parses, verifies and
renders** — the signed network contract, and diagnostic assembly — and exchanges results with the
extension over ADR-0017. One source, two artifacts; the profile is recorded in S-46 so a support
case is answerable.

**`core-lite` MUST NOT sit on a fetch path or on any recovery path.** An earlier revision of this
ADR said the app process *fetches* the contract, reading
[docs/networking.md](../networking.md) §5.4's "contract fetch/parse … live in the app process"
literally. [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) PS-24 condition 3 shows
why that is wrong: under `includeAllNetworks` the iOS app process **has no network**, and it cannot
match [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)'s bootstrap-exemption class because
KS-9(1)'s predicate names the *provider*, not the app. An app-process fetch would therefore fail in
exactly the state where the contract is most needed, and would fail *silently from the extension's
point of view* — the deadlock shape where the component that can recover is not the component that
holds the network.

**Normative split, replacing the literal reading of §5.4:** the **extension fetches** (it holds the
exempted socket) and hands raw bytes to the app process over
[ADR-0017](ADR-0017-local-management-interface.md); **`core-lite` parses and verifies** those bytes
and returns the verified result the same way. Parse and verify are where C-3's memory pressure
actually lives — a signature verification and a CBOR decode over a multi-KB document — so the split
still discharges §5.4's intent. Fetching costs the extension a socket and a buffer, not a parser.
The general rule this instantiates: **no component whose availability depends on the tunnel being up
may sit on the path that brings the tunnel up.** §11.16 (m) asks NETWORKING to confirm the refined
reading.

**The three version numbers.** Confusing these is a defect class, so they are named and separated.

| # | Number | Versions | Form | Bumps when | Compared between |
|---|---|---|---|---|---|
| **V-A** | `core_version` | the shared core's own release | SemVer | any core change | humans, support, telemetry |
| **V-B** | `abi_major` / `abi_minor` | the `twinvpn.h` C ABI | two `uint32` | major on removal or semantic change; minor on addition | a shell binary and the core binary **in the same process** |
| **V-C** | `ProtocolEpoch` | ADR-0014's V-2 and V-3 wire behaviour | `uint32` | per [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-1 | peer↔peer, device↔control-plane, **on the wire** |

Two further numbers are commonly mistaken for these and are not: the shell's store/installer version
(ADR-0021's), and ADR-0003's schema artifact digest (V-1), which is a content identity, not a
version.

- **VR-1.** The three advance independently. A core release that changes no wire behaviour MUST NOT
  bump `ProtocolEpoch` (ADR-0014 N-1). A core release that changes no ABI MUST NOT bump `abi_major`.
- **VR-2.** `abi_*` MUST NOT be used as a **compatibility input** anywhere except between a
  shell and a core **in the same process**, and `ProtocolEpoch` MUST NOT appear in any
  shell↔core compatibility check. A message that carries an `abi_*` value **as a negotiation,
  gating, or routing input** is a defect.

  > **Clarified 2026-08-27.** As originally written this read "`abi_*` MUST NOT appear on
  > **any wire**", which contradicts **S-46** in §11.17: `CoreBuildIdentity` *includes*
  > `abi_major`/`abi_minor`, and S-46 states that "every diagnostic bundle embeds it; telemetry
  > holds a lossy replica" — and telemetry is channel C7, which is a wire. This is conflict
  > **CF-8** in `contracts/docs/phase1-conflicts.md`.
  >
  > The two rules were never in real tension; the wording was. **The prohibition is on `abi_*`
  > being a decision input outside one process, not on the bytes existing.** An ABI version is
  > meaningless between machines — it describes a linkage inside a single address space — so
  > using it to decide anything across a wire is the defect. Recording it as **build
  > provenance**, so a support case can answer "which core was loaded", is not.
  >
  > Normative consequences, so this is not re-litigated:
  > 1. `abi_*` MAY appear in a **Tier-1 diagnostic bundle** and in `CoreBuildIdentity`.
  > 2. `abi_*` MUST NOT appear in any **C1, C2, C4, C5 or C6** message.
  > 3. `abi_*` MUST be **omitted** from **Tier-2 aggregate telemetry**, which
  >    [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.1 restricts to coarse,
  >    identifier-free counters — an ABI pair is build-identifying and has no aggregate meaning.
  > 4. No receiver may branch on a received `abi_*` value.
- **VR-3.** The relation between them is a **table, not an inference**: `CoreBuildIdentity` (S-46)
  carries `{core_version, abi_major, abi_minor, protocol_epoch_min, protocol_epoch_max,
  schema_digest, reason_registry_version, crypto_provider, profile, target_triple, source_commit}`. Anything needing "which
  epochs does this build speak" reads the table. Deriving it from `core_version` is prohibited.
- **VR-4.** Shell and core ship as one signed artifact per platform (ADR-0021), so an `abi_major`
  mismatch is a **packaging defect**, not an operating state. It is still checked at
  `tw_core_create` and still named (`INTERNAL.ABI_VERSION_MISMATCH`), because the alternative is
  undefined behaviour. Distribution-packaged Linux MAY split them, and there the check is
  load-bearing rather than defensive.

### 11.13 Performance: what the split costs at the datapath

**PB-1 — zero FFI crossings per packet, and the one exception.**

| Target | Datapath | Per-packet crossings of `twinvpn.h` | Why |
|---|---|---|---|
| Linux, OpenWrt | kernel WireGuard module | **0** | the core programs the module; it never sees a packet |
| Linux (userspace fallback, kernel 5.4) | `tun` fd held by the core | **0** | fd obtained once via the adapter, then read directly |
| Windows | WinTun send/receive rings, called from `twinvpn-platform-windows` | **0** | C API called from Rust, in-process, not across the ABI |
| Android | `ParcelFileDescriptor` detached to a raw fd at setup | **0** | one JNI call at setup, then direct reads |
| macOS (system extension) | `utun` fd where the extension type permits | **0** | |
| **iOS, iPadOS, macOS app-extension** | `NEPacketTunnelFlow` | **1 per batch, + 1 copy per packet** | the API is Swift/Objective-C only and hands the caller `Data`; there is no fd. Unavoidable, therefore budgeted |

**PB-2 — copy budget.** Userspace datapath: ≤ 2 copies per packet (device read → in-place AEAD →
socket write) from a fixed, preallocated buffer pool — no growing arena. Kernel datapath: 0 copies
in our code. Apple platforms add the one forced `Data` copy of PB-1.

**PB-3 — throughput budgets (R-15), declaring the "declared fraction" of
[docs/testing-strategy.md](../testing-strategy.md) §2.16.**

Every row names its silicon (BM-1). A budget quoted without its hardware class is void.

| Rig — named silicon | Budget |
|---|---|
| Desktop pair, x86-64 with AES-NI, 1 GbE, **kernel datapath**, both families | **≥ 90 % of link rate** |
| Same rig, forced **userspace** datapath | **≥ 60 % of that rig's kernel-datapath figure**; the gap is published as a number, not discovered |
| **`GC-0`** (row 9) — MIPS 24Kc @ 580 MHz single core, **kernel** datapath | **≥ 20 Mbit/s** aggregate. **Nightly floor on the canonical `ath79` member, not a release gate** (BM-2b) — silicon-derived budgets do not transfer to a stand-in |
| **`GC-0`** — same, **userspace** datapath (kernel lacks the module) | **≥ 8 Mbit/s** aggregate — nightly floor as above. The **≤ +6 MB RSS** over the kernel-datapath figure is build-derived and **does** gate (PB-6) |
| **`GC-0U`** (row 8) — measured on the **Cortex-A53 `mt7622` member**, **kernel** datapath | **≥ 80 Mbit/s** aggregate. Release gate |
| **`GC-0U`** — same, **userspace** datapath | **≥ 40 Mbit/s** aggregate |
| **`G1-a`** — 4×Cortex-A72 @ 1.5 GHz, 2 GB | ~250–300 Mbit/s per [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) §9. **Not gated by this ADR**, and the figure MUST NOT be quoted for `GC-0` or `GC-0U` |
| `RELAYED` versus `WAN_DIRECT`, any class | relay overhead tracked as a number; p95 added latency is the gated one (R-12) |

**PB-3a — the embedded floors are the bottom of ADR-0023's measured envelope, deliberately.**
`GC-0`/`GC-0U` figures are **adopted from
[ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) §11.13, not invented here**: that ADR owns
the silicon envelope, this ADR owns only where inside it the release gate sits. The gate is set at
the **floor** of each measured range (20 of 20–35; 8 of 8–15; and `GC-0U`'s ≥ 80 / ≥ 40, which ADR-0023 adopted from this ADR's own
derivation because that is the silicon those numbers came from), because
a gate is a floor to stay above, not a target to aim at — a threshold set mid-range fails the rig on
an ordinary bad day and teaches the team to re-run rather than investigate
([docs/testing-strategy.md](../testing-strategy.md) §6.4: a result outside the band is a failure,
not a re-run).

**Both embedded classes gate, and the reason is the memory envelope, not the profile label.**
`GC-0` and `GC-0U` share **the same 128 MB / ~24 MB free / 16 MB flash**, differing only in CPU. So
`GC-0U`'s RSS gate cannot stand in for `GC-0`'s: gating at ≤ 13 MB does not verify ≤ 10 MB, and it is
the memory gate — not the throughput gate — that decides whether a build OOMs in the field. Flash is
governed by one number for both (≤ 4 MB, BM-1.1), so only **throughput** genuinely differs. Neither
class is "the aspiration". **This ADR does not propose re-baselining a single global PB-3 number onto
`GC-0`** — BM-1 requires each budget to name its silicon, so the classes gate against their own
floors and `GC-0`'s 20 Mbit/s never constrains `GC-0U`.
If ADR-0023 re-measures either envelope, these floors MUST be re-derived in a reviewed commit —
never adjusted by a test author on the day (rule C-1's reasoning, applied to a budget rather than a
tier).

**PB-4 — the split's own cost, as a number.** **0 ns/packet** on Linux, Windows, Android and
OpenWrt. On iOS/iPadOS/macOS-app-extension: **≤ 5 % of the userspace-datapath throughput** on the
reference device, measured, and a §14 revisit trigger if exceeded.

**PB-5 — cold start.** `tw_core_create` ≤ **50 ms at p95** on the iOS/iPadOS extension — the
tightest, because the OS starts the extension on demand while the user waits. Desktop and router
budgets are looser and are set at T4 against the same method. Cold start is **silicon-derived**
(BM-2b), so the `GC-0` figure is measured on the canonical `ath79` member and is a nightly floor,
never a number carried over from a stand-in.

**PB-6 — memory. The iOS/iPadOS figure is a share of someone else's budget, not a ceiling.**
[ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) establishes that **15 MB is
a platform CEILING** — an *observed* jetsam threshold Apple neither publishes nor guarantees, which
arrives with no notice — and that budgeting to a ceiling means dying on the first allocation spike.
Its provider-wide engineering budget is **12 MB** with a shed threshold at **10 MB**. Those are
platform-termination facts and are ADR-0022's; **the core's share within them is mine**:

| Level | Value | Owner |
|---|---|---|
| Platform ceiling (observed, unguaranteed) | 15 MB | ADR-0022 |
| Provider-wide engineering budget | 12 MB | ADR-0022 |
| Shed threshold | 10 MB | ADR-0022 |
| **Core RSS share** | **≤ 9 MB** | **this ADR** |
| **Core revisit trigger** | **8 MB p95** (§14 condition 2) | **this ADR** |

An earlier revision allotted the core 12 MB inside the 15 MB ceiling, which left the Swift shell,
the per-packet `Data` copy PB-1 concedes is unavoidable on `NEPacketTunnelFlow`, and all framework
overhead a combined 3 MB — and collided outright with ADR-0022's 12 MB provider-wide figure. The
3 MB that remains at 9 MB is deliberate and is the shell's to spend.

This does **not** weaken §12's language argument; it strengthens it. A smaller envelope makes a
no-GC runtime's advantage larger, not smaller — Go's heap-headroom cost was already the decisive
point at 15 MB and is sharper at 9.


Both embedded classes are budgeted against **~24 MB realistically free**, not the nominal 128 MB
([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) §11.14), and both at **16 peers** —
ADR-0023's `max_admitted_peers` default (MG-14's floor, explicitly not ADR-0013's 64, BM-1.2):

| Class | RSS gate at 16 peers | Worst case with ADR-0023's +3–6 MB userspace datapath | Headroom of ~24 MB |
|---|---|---|---|
| **`GC-0`** | **≤ 10 MB** | 13–16 MB | 8–11 MB |
| **`GC-0U`** | **≤ 13 MB** | 16–19 MB | 5–8 MB |

**`GC-0U` is the tighter case, not `GC-0`** — it carries more peers' worth of state on the same
~24 MB. An earlier revision here computed headroom from `GC-0U`'s figure while labelling it `GC-0`
and concluded ~6 MB for the wrong class; the corrected arithmetic is above.
[ADR-0015](ADR-0015-observability-and-diagnostics.md)'s 512 KB observability budget fits inside
whichever figure applies.

### 11.14 Reason codes

This ADR registers **no new reason codes** and introduces no new domain. It uses:

| Code | Domain owner | Used for |
|---|---|---|
| `PLATFORM.OS_UNSUPPORTED` | [docs/architecture.md](../architecture.md) §2.5.1 | the OS or build target is outside the §11.9 matrix, including a target withdrawn under BM-5 |
| `INTERNAL.INVARIANT_VIOLATED` | [ADR-0015](ADR-0015-observability-and-diagnostics.md) | F-6 reentrancy guard trip; CD-I5 violation observed at runtime; a second mutating attach to one instance (S-47) |
| `INTERNAL.UNEXPECTED_STATE` | [ADR-0015](ADR-0015-observability-and-diagnostics.md) | a decoded command or event that the core's state cannot accept |

Two codes are **requested** from the `INTERNAL` domain, which
[ADR-0015](ADR-0015-observability-and-diagnostics.md) owns. They are not registered here:

| Requested code | Class | Severity | Terminal | User-actionable | Condition and next action |
|---|---|---|---|---|---|
| `INTERNAL.CORE_PANIC` | FATAL | CRITICAL | no (instance-terminal) | no | A panic was caught at the ABI boundary (F-7). The instance is poisoned; the shell destroys and re-creates it, and the `Session` re-enters `RECONNECTING` from durable state. Enforcement stays installed. Every occurrence is a defect |
| `INTERNAL.ABI_VERSION_MISMATCH` | FATAL | CRITICAL | yes | **yes** | The shell's compiled `abi_major` is outside the loaded core's supported range (VR-4). Next action: reinstall the application as one artifact; on distribution-packaged Linux, install matching package versions |

### 11.15 Assumptions register

| # | Assumption | Depends on | If it is wrong, this changes |
|---|---|---|---|
| **B-01** | **H2** — on desktop/server the client is a privileged long-lived service plus a separate unprivileged UI process; on iOS/iPadOS/Android the OS-hosted extension is the "daemon" | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) | §11.5's "which process loads the core" table. If the UI must load the full core, the `core-lite` profile grows, capability-by-vtable stops bounding what the UI can do, and §11.16 (a)'s single-mutating-holder guarantee needs a different mechanism |
| **B-02** | **H3** — exactly one local management contract, the GUI has no privileged side channel, and (confirmed by ADR-0017 MI-20) its catalogue is **derived** from the core command set rather than independently defined | [ADR-0017](ADR-0017-local-management-interface.md) | §11.5: every non-hosting process reaches the core over ADR-0017. If there are two contracts, the ABI gains a second consumer class and F-1's small surface is unsustainable; §11.4 F-5's "same command set, different transport" claim fails |
| **B-03** | ADR-0020 realizes **Tier 1 only** behind the vtable (`secure_item_*`) and vends `store_root`; the record envelope, AEAD, migration, monotone rejection, recovery ladder and **multi-key commit** are core-side in `twinvpn-store` (CB-7). Where a platform key API cannot perform the record AEAD — **8 of 10 targets** — the shell unwraps the store key into the core's locked allocator, declared per CB-6a | [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md) | §11.7's store crate shape, CB-5's authentication-path boundary, and the CD-I4 mechanism. **Corrected from an earlier revision** that described the whole store as vtable-side — see CB-7 |
| **B-04** | ADR-0021 consumes `BuildArtifactSet`, ships shell+core as one signed artifact per platform, and owns staged rollout | [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) | VR-4 (ABI mismatch becomes an operational state rather than a packaging defect) and §13's blast-radius mitigation |
| **B-05** | ADR-0022 owns background and lifecycle policy; the core learns of suspend/resume/background/foreground as submitted commands and holds no OS lifecycle assumption of its own | [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) | §11.4 F-5's command set, PB-4's cold-start budget, and CD-1's requirement that `Clock` report a suspend discontinuity rather than hide it |
| **B-06** | ADR-0023 uses the **same** core artifact as the Linux daemon, differing only by feature profile and configuration | [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) | §11.9 rows 8–10; a separate embedded core would contradict R-31 outright |
| **B-07** | ADR-0019 hosts its presentation **resolver** in the core and its **presentation** in the shell (CB-4), requires the render call to be pure (F-10), ships the catalogue embedded in the artifact, reads the registry version from `tw_reason_registry_version()` / S-46, and selects next-action variants by `(platform, os_version)` supplied as `platform_ctx` rather than resolved shell-side | [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) | CB-4's split, F-10 (F-1's only exception, now four parameters), and S-46's `reason_registry_version`. If ADR-0019 keeps resolution shell-side, F-10 is withdrawn, the ABI returns to twelve functions, and six shells own six `reason_code` mappings and six variant selectors — which R-31 and CB-2 both forbid |
| **B-08** | [docs/networking.md](../networking.md) §5.1 is complete for all ten targets, and `apply` is the only system-mutating call | NETWORKING | §11.6 and CB-2: a second mutating path outside the adapter would necessarily put a decision in a shell |
| **B-09** | The L-DATA static private key may reside in core process memory, hardware-*wrapped* rather than hardware-*resident* | [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) L-STORE, [ADR-0007](ADR-0007-device-identity-and-pairing.md) | CD-I4. If TK must also be non-extractable, every AEAD operation becomes a vtable call and PB-1/PB-2 collapse entirely |
| **B-10** | ADR-0003's contract artifacts are the single source for generated types in every language | [ADR-0003](ADR-0003-network-contract-schema-format.md) | §11.12's `/contracts/gen` rule and VR-3's `schema_digest` |
| **B-11** | Rust keeps aarch64 and armv7 musl at a tier with prebuilt `std` | upstream toolchain | §11.9 row 8 and §14 condition 10; row 8 would join row 9's `build-std` posture, which is not acceptable for a release gate |

### 11.16 Interfaces required from other ADRs

| # | Required interface | Owner |
|---|---|---|
| (a) | Which OS process hosts the core on each target, and the guarantee that **exactly one** process holds a mutating core handle at a time (S-47) | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) |
| (b) | A transport for the command/event port that carries **the same command set** the core exposes over the ABI — one contract, two carriages, never two contracts | [ADR-0017](ADR-0017-local-management-interface.md) |
| (c) | Per CB-7: `secure_item_read`/`secure_item_write_atomic` for Tier-1 items; a `store_root` vended with its platform attributes already applied; and **`identity_sign` performed inside the element** (IK, ES256, never exported — CB-5 row 1). **This does NOT require in-element X25519 agree for TK**: per CB-5 row 2, TK is hardware-*wrapped* and unsealed into locked core memory ([ADR-0007](ADR-0007-device-identity-and-pairing.md) N-5, [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) L-STORE, this ADR §7.3 and B-09), precisely because platform key APIs largely do not offer X25519 ECDH. An earlier wording here said "sign and agree without exporting the private half", which read as requiring both in-element and would have contradicted N-5. The core owns the transaction engine, so ADR-0020 supplies **custody and a directory, not a database**. Plus the CB-6a per-target declaration of whether the platform key API performs the record AEAD | [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md) |
| (d) | Consumption of `BuildArtifactSet` (BM-8); shell+core as one signed artifact per platform; staged rollout; a rollback floor honouring S-23 | [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) |
| (e) | Lifecycle delivered as commands (`SUSPEND`/`RESUME`/`BACKGROUND`/`FOREGROUND`, [docs/reliability.md](../reliability.md) §4.3), **plus an explicit statement of the wall-clock discontinuity across suspend**, so the injected `Clock` reports it rather than hiding it | [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) |
| (f) | The `GC-0` / `GC-0U` envelopes this ADR adopts in BM-1 and gates in PB-3/PB-6, **§11.13/§11.14 treated as a pinged interface in both directions** — if either envelope is re-measured my floors must be re-derived, and if PB-3 moves EM-54c must be; the **`GC-0` envelope definition** that supplies BM-2b's portability split; `max_admitted_peers` = 16, not ADR-0013's 64 (BM-1.2); and — **BM-2c, open** — **which silicon member `GC-0U`'s ≥ 80 / ≥ 40 gate is measured on**, since `GC-0U` spans Cortex-A53 ×2 and MIPS 1004Kc ×2. This ADR assumes the weaker `mt7621` member until told otherwise, because a floor measured on the stronger member is not a floor. `H-EMB` spans **both** classes and is **not** an equality with `GC-0`. Separately, ADR-0013's owner scopes its ~300 Mbit/s figure to `G1-a` | [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md), [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) |
| (g) | Registration of `INTERNAL.CORE_PANIC` and `INTERNAL.ABI_VERSION_MISMATCH` in the `INTERNAL` domain, with the attributes in §11.14 | [ADR-0015](ADR-0015-observability-and-diagnostics.md) |
| (h) | Confirmation that `subscribe_network_change(cb)` is satisfied by an **inbound command submission** rather than a literal outbound function pointer (F-9). The contract's meaning is unchanged; if a literal callback is intended, this ADR overrules it and §11.4 F-6 states why | [docs/networking.md](../networking.md) §5.1 |
| (i) | Adoption of the **CD-3 lint** as the realization of L-3, and of the **CD-I5 crate-graph assertion** as the realization of B-19 / [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) §11.8 step 3 | [docs/testing-strategy.md](../testing-strategy.md) |
| (j) | A **build-pipeline / malicious-dependency adversary** and a corresponding threat row. §11.11 supplies mechanisms; there is currently no modelled threat for them to mitigate | [docs/threat-model.md](../threat-model.md) |
| (k) | Confirmation that no L-DATA operation requires a call out to the host (B-09), so PB-1's zero-crossing claim holds | [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) |
| (l) | An `identity_attestation()` capability that reports `hardware_backed` **truthfully per target**, so S-46 records it rather than the core assuming it. On a target with no secure element (row 8/9, containers, VMs) the residual is [docs/threat-model.md](../threat-model.md) TM-13's, unchanged; the core MUST NOT substitute a file-backed signer silently | [ADR-0007](ADR-0007-device-identity-and-pairing.md) |
| (m) | **Confirmation of the refined reading of [docs/networking.md](../networking.md) §5.4**: the extension **fetches** the signed network contract and `core-lite` **parses and verifies** it. §5.4's literal wording places fetch in the app process, which [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) PS-24 condition 3 shows is unreachable under `includeAllNetworks` | [docs/networking.md](../networking.md), [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) |
| (n) | **A platform-neutral next-action variant for every registered code**, so an empty `platform_ctx` always resolves (F-10); plus the `platform_ctx` field set and the LT-3 variant-selection table the core resolves against | [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) |
| (o) | **MI-20/MI-21 held as written**: the MI catalogue stays *derived* from the core command set, and the four transport-layer operations (`Hello`/`HelloAck`, `mi.catalogue.get`, `event.resync`, the MI half of `version.get`) stay closed and acquire **no** ABI counterpart. Each one that migrated inward would be a permanent F-1 obligation for a concern the in-process caller does not have | [ADR-0017](ADR-0017-local-management-interface.md) |
| (p) | **`ElapsedClock`, `Entropy` and `BootIdSource`, named as required shell interfaces.** This table did not list them and every shell brief did, which is finding **W-7** in `docs/implementation/ownership.md` §8 — recorded here on that row's disposition. All three are the shell's because the core cannot supply them: CD-1 makes `ElapsedClock` a **suspend-inclusive** clock and `std` has none; the platform calls behind `Entropy` and `BootIdSource` need `unsafe` (DP-4) or `cfg(target_os)` (CB-3), both of which CB-3 puts outside the portable core. Their F-9 entries exist — `elapsed_millis` and `boot_id` were two of W-26's four approved `size`-field additions, and `os_csprng` was in the struct from the start. **The failure mode this row exists to prevent is LC-8's:** all three have working `std`-only stand-ins on Linux, so a shell that omits them is invisible on a Linux CI host and wrong on every target that suspends | every shell owner |

### 11.17 State ownership

New rows for [docs/architecture.md](../architecture.md) §5, in its seven-column format.

| # | State | Authoritative writer | Replicas / caches (staleness tolerance) | Consistency class | Durability | On conflict |
|---|---|---|---|---|---|---|
| **S-46** | `CoreBuildIdentity` — `{core_version, abi_major, abi_minor, protocol_epoch_min, protocol_epoch_max, schema_digest, reason_registry_version, crypto_provider, profile, target_triple, source_commit, hardware_backed}` | **The core artifact itself**, fixed at build time (§11.9, BM-8) | The hosting shell caches it at attach; every diagnostic bundle embeds it; telemetry holds a lossy replica | `LOCAL` | **Immutable within an artifact**; cached durably alongside the diagnostic ring | Impossible to conflict — the value is a property of the loaded binary. A shell whose compiled `abi_major` is outside the loaded core's range MUST refuse to attach with `INTERNAL.ABI_VERSION_MISMATCH`, never proceed on a "close enough" match |
| **S-47** | `CoreInstanceBinding` — `{instance_id, abi_major_in_force, holding process and thread, generation, poisoned}` for a live core instance | **The core instance** | The attached shell holds an opaque handle only; no other replica exists | `LOCAL` | **Non-durable by requirement** — it MUST NOT survive process exit; a stale binding would be indistinguishable from a live second writer | Single writer by construction: a second **mutating** attach is refused with `INTERNAL.INVARIANT_VIOLATED`, never reconciled. Once `poisoned` (F-7) the binding is terminal and only `tw_core_destroy` clears it |

S-47 is the I8 mechanism at the shell boundary: it makes "two processes both driving one core" a
refused operation rather than a race, which is what ADR-0016's privilege split needs to be true
rather than assumed.

---

## 12. Why the Selected Option Won

**Against B (Go), the strongest runner-up.** Go is memory-safe, cross-compiles better than Rust,
builds far faster, and has a production existence proof inside an Apple NetworkExtension provider.
It lost on four specific points, not on preference:

1. **The seam is bidirectional and callback-heavy.** [docs/networking.md](../networking.md) §5.1 is
   seven host functions, and CB-5 adds five more. In Rust each is an `extern "C"` fn pointer costing
   a call. In Go each is a cgo callback with a goroutine bind, under the rule that C may not retain
   Go pointers. Our design is dominated by calls *into* the core's language, which is Go's weakest
   FFI direction.
2. **Heap headroom, not pause time, is the binding constraint.** Go's pauses are sub-millisecond
   and would not by themselves violate C-2. The problem is that inside a **9 MB core share** of
   ADR-0022's 12 MB provider budget (C-3, PB-6) and on a `GC-0` router with ~24 MB free (C-4), Go
   needs heap headroom Rust does not, and buying it back by tightening `GOGC` spends CPU that PB-3's
   router budget has none of. Rust has no such trade to make. **This point got stronger, not weaker,
   as the envelopes tightened.**
3. **B-3's audit surface.** "What must a security reviewer read to believe there is no memory
   unsafety" has a mechanical answer in Rust (the DP-4 allowlist) and an unbounded one in Go
   (`unsafe.Pointer` plus every cgo site) — and every cgo site in this design is platform code
   touching the OS.
4. **Size at the two tightest rows.** Row 1 (≤ 9 MB core RSS inside a 12 MB provider budget) and
   row 8 (≤ 4 MB stripped) are where the matrix is decided, and Go's baseline is several MB before
   product code.

**Where Go was better, stated plainly:** cross-compilation without a C toolchain (though Rust needs
the NDK, MSVC and Xcode regardless, so the practical gap is smaller than it first appears), build
speed against C-11, and a far shallower ramp.

**Against C (C++), D (KMP) and E (reimplementation)**, briefly, because §6 gives the analysis: C++
converts B-3 from a gate the codebase passes by default into the project's dominant recurring cost;
KMP forks the datapath per OS, which is R-31's defect, and excludes the router tier entirely; E is
R-31's defect in its pure form, with the added consequence that five of six platforms' proof-test
obligations would be gated behind scarce VM and device-farm capacity
([docs/testing-strategy.md](../testing-strategy.md) §3.7).

**Against G (generated bindings as the ABI).** UniFFI-style generation is genuinely attractive and
removes the glue that F makes us maintain. It lost as the *ABI of record* because the boundary's
shape would belong to a tool whose own ABI moves between versions, while `abi_major` is a stability
promise we make (VR-2); because its error model is enum-shaped where I6 and
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 require a `reason_code` **string** with
typed evidence; and because it does not reach C# or plain C. **H takes what G offered anyway**: the
ergonomic Swift and Kotlin layers are generated — from ADR-0003's contract artifacts, which already
generate the message types — while the twelve-function hand-written surface stays ours and stays
small. UniFFI-family tooling may produce those wrappers; it may not become the ABI.

---

## 13. Known Tradeoffs

1. **One core is one blast radius.** A core defect is a defect on all ten targets simultaneously.
   The mitigation is that the core is the most-tested component in the system (CD-5 makes that
   affordable), but the honest cost is that a bad core release is a fleet event, and ADR-0021's
   staged rollout is load-bearing rather than nice to have.
2. **The team is not smaller, only differently shaped.** Rust for the core plus Swift, Kotlin and
   C# for the shells is four languages. E would have been five and no ABI.
3. **The message-port ABI costs an encode and a decode per command and per event.** Free at 1–10²
   events/s; wrong if a future feature makes the event rate per-packet. §14 condition 5 falsifies it.
4. **Two crypto providers (DP-8) double the golden-vector obligation** and mean the algorithm in
   force is a per-target fact, not a global one.
5. **`core-lite` means one *source* but two *artifacts* per Apple platform.** R-31 is satisfied at
   the source level; support cannot answer a question without reading the `profile` field of S-46.
6. **`GC-0`'s throughput is a nightly floor, not a release gate — only its build-derived budgets
   gate.** BM-2b splits them because a stand-in measures itself: RSS, size and flash write rate are
   properties of the compiled artifact and transfer across envelope members, but throughput and cold
   start are properties of the CPU and do not. So the number that decides field survival (RSS) gates
   every release, while the number a user notices (throughput) is measured nightly on real `ath79`
   hardware under ADR-0023 §14 condition 1a. The honest residual: **a throughput regression on
   `GC-0` reaches a release branch and is caught overnight rather than at the gate.** That is
   accepted deliberately — the alternative was gating on a number measured on the wrong silicon,
   which is worse than a one-night delay because it is wrong rather than late.
7. **Reproducibility stops at the signature on Apple and Windows** (BM-7). The attestable artifact
   is the pre-signature one.
8. **Rust's build time competes directly with C-11.** Three parallel runner families and heavy
   caching are a hard requirement, not an optimization.
9. **The Apple datapath pays a copy per packet** (PB-1). It is forced by `NEPacketTunnelFlow` and
   budgeted at ≤ 5 % of userspace throughput, but it is a cost the other five platforms do not pay.

---

## 14. Revisit Conditions

Each is measurable, and each names what changes if it fires.

1. **`tw_core_create` exceeds 50 ms at p95** on the reference iOS/iPadOS device in T3 → revisit
   lazy initialization, or a resident-core design that survives extension restarts (PB-4).
2. **Core RSS in the iOS/iPadOS extension exceeds 8 MB at p95** — 89 % of the 9 MB core share, and
   deliberately *below* it, because a trigger that fires above its own budget reports a breach
   rather than warning of one (PB-6) → move more
   of the core into `core-lite` in the app process, or revisit the split line for Apple platforms
   (PB-6).
3. **The `GC-0` artifact exceeds 4 MB stripped, or steady-state RSS exceeds 10 MB at 16 peers of
   the ~24 MB free** (build-derived, so measurable on any envelope member — BM-2b), **or the
   nightly `ath79` floor falls below 20 Mbit/s kernel / 8 Mbit/s userspace** (PB-3) →
   re-evaluate feature gating, or withdraw a router row explicitly under BM-5 (R-32).
4. **The Apple per-packet crossing costs more than 5 % of userspace-datapath throughput** on the
   reference rig → revisit the Apple datapath, including whether a system-extension configuration
   can obtain a `utun` descriptor (PB-4).
5. **The ABI event rate exceeds 1 000 events/s at p95** in any T3 soak → the message-port shape
   (F-8) is wrong for that workload; revisit toward a shared-memory ring for the hot class.
6. **`abi_major` requires a second bump within 12 months of the first** → the boundary is drawn in
   the wrong place; re-run §11.1 rather than absorbing the churn.
7. **Any shipped shell is found to contain a decision** — a branch on a `ConnectionState`, a
   `reason_code` class, or a policy verdict → R-31 is not being enforced and the CD-CB3/CB-2 checks
   are insufficient; strengthen them before the next release.
8. **Any T1 target build pushes the tier past its 15-minute budget** → move a target's build down a
   tier as a reviewed change to [docs/testing-strategy.md](../testing-strategy.md) §6.1's table,
   per rule C-1. Never raise the budget.
9. **A primitive in [docs/threat-model.md](../threat-model.md) §11 has no implementation with a
   published audit for a supported target**, forcing a third provider or an unaudited one →
   escalate to SECURITY under I2/P2. Do not ship that target (DP-7 step 5).
10. **The MIPS portability build stays broken for two consecutive releases**, or **no device
    inside the `GC-0` envelope ships a prebuilt-`std` triple**. The first means `ath79` hardware is
    drifting out of support even though the class still gates (BM-2b) — decide explicitly whether
    MIPS remains in the matrix rather than letting it lapse. The second would remove BM-2b's gating
    unit and put the gate back on `build-std`; re-run BM-2a's cost analysis before accepting that.
    If **row 8** loses prebuilt `std`, a second `build-std` target would make BM-2a a pattern rather
    than an exception; re-run BM-2 instead of adding a third toolchain.
11. **`INTERNAL.CORE_PANIC` is observed in any T3 or T4 run, or above 0 occurrences per 10⁶
    device-hours in the field** → containment is masking a defect class; every occurrence is P1 per
    [ADR-0015](ADR-0015-observability-and-diagnostics.md)'s definition of the `INTERNAL` domain.
12. **Any two supported targets are measured to disagree on a `ConnectionState` transition** for
    the same TwinLab scenario at the same seed → the single-implementation claim of R-31 is false
    in practice; the divergence is a determinism defect (F-7) and blocks the release under B-14.
