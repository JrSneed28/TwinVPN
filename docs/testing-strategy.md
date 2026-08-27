# TwinVPN — Verification and Testing Strategy

> **Scope.** This document defines how every architectural claim made by TwinVPN is made
> *falsifiable*. It specifies the test taxonomy across nineteen levels; the design of
> **TwinLab**, the reproducible network laboratory that simulates the NAT, address-family, and
> impairment conditions the product must survive; the **twenty-two mandatory proof tests**
> (P01–P15 in §4, P16–P22 in §4.3) that together constitute the acceptance criteria for the
> whole architecture; the
> requirements→test traceability matrix binding the PairVPN defect list (R-01…R-24) and the
> shared invariants (I1–I8) to specific tests; the CI/CD gating tiers and release criteria; and
> the test-data and credential-handling policy. It specifies tests; it does not implement them.
> Phase 1 produces no code.
>
> **Related documents:** [docs/vision.md](vision.md) (requirement IDs R-01…R-24),
> [docs/architecture.md](architecture.md) (components and state authority),
> [docs/reliability.md](reliability.md) (the canonical `ConnectionState` machine),
> [docs/networking.md](networking.md) (NAT traversal, routing, DNS),
> [docs/protocol.md](protocol.md) (wire contracts),
> [docs/threat-model.md](threat-model.md) (adversaries),
> [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) (observability, owned here).

---

## 0. Assumptions register

These tests are written against specifications being authored concurrently. Every assumption
below is a place where this document could contradict another. **This register is a primary
input to the cross-document contradiction review.** Each entry states the assumption, whose
authority it belongs to, and what breaks in this document if the assumption is wrong.

| # | Assumption | Owner of the truth | Impact if wrong |
|---|---|---|---|
| **A-01** | Relay failover is modelled as `RELAYED → MIGRATING → RELAYED` **when the alternate is validated or warm** (a *cold* relay legally routes via `RECONNECTING`, ADR-0006 §11.5 rule 1), and direct-path upgrade as `RELAYED → MIGRATING → WAN_DIRECT`. Neither passes through `DISCONNECTED` or `RECONNECTING`, and neither changes the `Session` identifier or the tunnel key state. | [docs/reliability.md](reliability.md), [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) | The oracles of **P03** and **P05** are wrong; they assert exactly these transitions. |
| **A-02** | Every transition in the canonical state machine emits exactly one structured transition event `{from, to, trigger, reason_code, session_id, path_id, occurred_at}`, as a property of the transition, not of a call site. | [docs/reliability.md](reliability.md), required by [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §O-05 | Almost every oracle in §4 loses its primary observation channel and must fall back to packet capture, which is weaker and slower. |
| **A-03** | `HealthState` members are `HEALTHY`, `DEGRADED`, `UNHEALTHY`, `UNKNOWN`. | [docs/reliability.md](reliability.md) | Naming only; oracles that assert `HealthState` need renaming. |
| **A-04** | `Session` is durable and endpoint-independent; `Tunnel` is rebindable; `Path` is disposable. Loss of a `Path` does not destroy key state or application sockets. | [docs/architecture.md](architecture.md) §3.4 | **P04**, **P05**, **P15** are testing a decomposition that does not exist. |
| **A-05** | The tunnel is end-to-end encrypted between peer `Device`s with keys derived in a handshake to which no relay is a party, and a `Relay` is cryptographically indistinguishable from an arbitrary on-path network attacker. | [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) | **P14**'s structural argument collapses to a mere negative observation, which is much weaker evidence. |
| **A-06** | Device revocation is enforced at the **peer** (a peer refuses a revoked `TrustedPeer`) and not solely at the control plane, so revocation survives control-plane unavailability with a bounded propagation delay. | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) | **P10** must be reframed as "revoked devices cannot reconnect *while the control plane is reachable*", a materially weaker property. |
| **A-07** | Protocol version and `Capability` negotiation is integrity-protected such that a downgrade attempt is detectable by both peers, and an unsupported version produces a clean typed refusal (`PROTO.VERSION_UNSUPPORTED`) rather than an undefined state. | [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md), [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) | **P11** and **P12** have no oracle. |
| **A-08** *(corrected — was stated unconditionally)* | The kill switch is enforced by an OS-level rule set installed independently of the agent process, covering IPv4 and IPv6, and surviving agent crash, agent kill, update, and reboot — **guaranteed for Linux, Windows, macOS (running system), Android (lockdown enabled) and OpenWrt; qualified for iOS and for Android without lockdown**, where [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.6's limitation table states the residual exposure. | [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.14 (which confirmed this assumption in exactly this qualified form) | **P09** MUST therefore *assert* the guarantee where it is claimed and *measure* the window where it is not — never test a happy path and never assert a counter that does not exist on the platform (§4, P09's platform table). |
| **A-09** | `DNSPolicy` is enforced at the system-resolver layer such that no unencrypted fallback to a pre-existing resolver occurs while protected, for both families, including platform-specific bypasses (e.g. resolver processes outside the tunnel's routing scope). | [ADR-0011](adr/ADR-0011-dns-handling.md) | **P08**'s oracle set is incomplete; it would test only the in-tunnel resolver path. |
| **A-10** | A `TwinNet` address plan exists with a deterministic per-`Device` address in both families (v4 in a CGNAT-adjacent range, v6 ULA), assigned without DHCP. | [ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md), [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md) | **P06**'s multi-client addressing oracle and the lab's address provisioning need rework. |
| **A-11** | A gateway serves many peers over one shared virtual interface with per-peer policy and per-peer resource accounting. | [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md) | **P06**'s isolation and accounting oracles are unfounded. |
| **A-12** | Control-plane messages are schema-defined, versioned, and machine-validatable, so a schema-driven contract test tier is possible. | [ADR-0003](adr/ADR-0003-network-contract-schema-format.md), [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) | The contract-test level in §2 has no artifact to drive it and degrades to hand-written examples. |
| **A-13** *(strengthened)* | Established tunnels require no control-plane call for keepalive, rekey, path migration, or relay use. **Relay admission additionally survives a control-plane partition of any duration**: [ADR-0005](adr/ADR-0005-relay-architecture.md) §11.3 withdrew the former 30-hour `RelayCapabilityToken` cliff and replaced it with relay-issued renewal (token verifies under a known issuer key, `epoch` **equal** to the relay's `epoch_floor`, within `exp + T_RELAY_GRACE` = 6 h, live proof of possession of the bound `RLK`) — no control-plane involvement. | I5, [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §11.8, [ADR-0005](adr/ADR-0005-relay-architecture.md) §11.3 | **P15** is not a test of the architecture but of an accident. If the cliff returned, **P15**'s long variant would have to stop at 30 h and the control plane would be a bounded liveness dependency of every relayed pair. |
| **A-14** | Timers, clocks, randomness, and backoff schedules are injectable at component boundaries for test purposes. | [docs/architecture.md](architecture.md) | Determinism in the lab (§3.5) is unattainable and every timing-sensitive test becomes statistical. |
| **A-15** | The `reason_code` registry ships as a machine-readable artifact, and specific codes for crypto, policy, NAT, relay, and DNS domains are contributed by the ADRs owning those domains into the namespaces defined in [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2. | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) (taxonomy) + domain ADRs (codes) | The traceability matrix and every `reason_code` oracle lose their key; contract tests cannot diff the registry. |
| **A-16** | A `Diagnostic` is attached to entry into `DEGRADED`, `BLOCKED`, `FAILED`, and `RECONNECTING`; entry without one is itself a defect. | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.6, enforced in [docs/reliability.md](reliability.md) | The anti-silence property tests in §2.11 have nothing to assert on. |
| **A-17** | The transport fallback ladder (UDP → UDP:443 → TCP/TLS → HTTPS-shaped) exists with per-step observable results. | [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md) | The blocked-UDP and blocked-ports lab scenarios lose their oracle, and R-18 becomes untestable. |
| **A-18** | Relays and rendezvous are separate roles with independent failure domains, and a peer holds a *set* of relay candidates, not one. | [ADR-0005](adr/ADR-0005-relay-architecture.md), [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) | **P02**, **P03**, and the region-failure scenarios need redesign. |

**Assumption discipline.** Any test whose oracle depends on an assumption above carries that
assumption's identifier in its specification. When an assumption is contradicted by the owning
document, every test carrying its identifier is re-derived before it is re-run. A test that
silently keeps passing after its premise changed is worse than no test.

---

## 1. Verification principles

These are the rules used to reject a proposed test at review time.

| # | Principle | The rule it enforces |
|---|---|---|
| **V1** | **Every test names its oracle.** | A test specification that describes a procedure but not *how success is observed* is rejected. "Then it should work" is not an oracle. |
| **V2** | **Every test has a negative control.** | Each mandatory proof test names a deliberately-defective build (a *mutant*) that the test MUST fail against. A test never demonstrated to fail is not known to test anything. |
| **V3** | **Vacuous passes are defects, not luck.** | Every test asserts its own preconditions were met (traffic actually flowed, the impairment was actually applied, the peer was actually reachable). A test that would pass on an inert system is rejected. |
| **V4** | **Absence of a signal is not evidence unless the signal was provably possible.** | Leak tests must demonstrate that the leak *would* have been observed in the unprotected control run on the same rig. |
| **V5** | **Both address families, always.** | Any connectivity, routing, DNS, or leak test that exercises only IPv4 is incomplete and fails review (P9, phase rule 5). |
| **V6** | **Observability is the primary oracle; packet capture is the corroborating oracle.** | Assert on structured events and `reason_code`s (A-02), and independently corroborate the security-critical ones on the wire, because the system reporting on itself is not sufficient evidence for a security property. |
| **V7** | **Flake is a bug with an unknown cause.** | A test that fails intermittently is quarantined *and* filed, never retried into green. Retries are allowed only when the retry is recorded and counted against a flake budget. |
| **V8** | **Determinism is declared, not assumed.** | Every scenario declares whether it is bit-reproducible, statistically reproducible, or exploratory (§3.5), and its assertions must be valid for its declared class. |
| **V9** | **Tests bind to codes, not to text.** | Assertions key on `reason_code` values, never on human-readable strings, which are explicitly non-contractual ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 rule 4). |
| **V10** | **Simulators are themselves tested.** | The NAT emulators, impairment shims, and platform stubs carry their own conformance suites (§3.4). An unvalidated simulator manufactures false confidence at scale. |

---

## 2. Test taxonomy

### 2.0 Summary

`Budget` is wall-clock for the whole level in its named tier. `Tier` refers to §6.

| # | Level | Purpose | Real vs simulated | Where | Budget | Owner | Pass/fail criterion |
|---|---|---|---|---|---|---|---|
| 1 | **Unit** | Logic of a single function/type in isolation | Everything simulated; no I/O, no clock, no network | dev, T1 | ≤ 90 s | Component author | 100% pass; branch coverage ≥ 85% on parsers, state logic, policy evaluation |
| 2 | **Component** | One component against its declared interfaces with fakes for peers | Real component, fake dependencies, virtual clock | dev, T1 | ≤ 5 min | Component author | 100% pass; every state-machine transition covered at least once |
| 3 | **Protocol** | Wire-format conformance of encoders/decoders | Real codecs, static vectors, no network | dev, T1 | ≤ 3 min | PROTOCOL + TESTING | Byte-exact match against the golden corpus; zero unclassified decode outcomes |
| 4 | **Contract** | Schema compatibility across versions and components | Real schemas, generated messages | T1, T2 | ≤ 5 min | PROTOCOL + TESTING | No breaking schema diff without a version bump; `reason_code` registry diff is append-only |
| 5 | **Interoperability** | Build N talking to builds N-1, N+1, and to reference implementations | Real binaries of multiple versions, simulated network | T2, T4 | ≤ 40 min | TESTING | Every supported pair in the compatibility window establishes a `Tunnel`; every unsupported pair refuses cleanly |
| 6 | **Integration** | Two or more real components across a real transport | Real components, simulated network | T2 | ≤ 25 min | TESTING | All scenarios reach their expected terminal `ConnectionState` |
| 7 | **End-to-end** | Full product paths, client through gateway to destination | Real binaries, simulated network, simulated Internet | T2, T3 | ≤ 45 min | TESTING | Proof tests P01–P15 (§4) pass |
| 8 | **Platform** | OS-specific integration: adapters, permissions, lifecycle, background | Real OS (VM or device), simulated network | T3, T4 | ≤ 3 h | Platform owners | Per-OS capability matrix fully green; no unhandled OS-version condition |
| 9 | **Networking** | Routing, addressing, MTU, interface change, dual-stack correctness | Real stack in namespaces | T2, T3 | ≤ 30 min | NETWORKING + TESTING | Correct routes and addresses for both families; no route left behind after teardown |
| 10 | **NAT traversal** | Candidate gathering and hole punching across NAT classes | Real traversal code, emulated NAT | T2 (subset), T3 (full) | ≤ 90 min | NETWORKING + TESTING | Direct-path success rate meets the per-class budget (§3.6); relay fallback in every case where direct is impossible |
| 11 | **Relay** | Relay selection, health, failover, capacity, opacity | Real relay binaries, emulated network | T2, T3 | ≤ 40 min | RELIABILITY + TESTING | Failover within the bounded budget with no `Session` loss; no peer-pair record retained |
| 12 | **Security** | Adversarial behaviour against the threat model | Real crypto, adversarial peers/relays | T2 (regression), T4 (full) | ≤ 4 h | SECURITY + TESTING | Zero successful attacks from the modelled adversary set; all leak tests negative with positive controls green |
| 13 | **Fuzz** | Crash/hang/memory-safety resistance of all untrusted input | Real parsers, generated input | T3 (timeboxed), continuous | 8 CPU-h/night, continuous fleet | TESTING | Zero new unique crashes, hangs, OOMs, or sanitizer reports; corpus coverage non-regressing |
| 14 | **Property-based** | Invariants over generated state sequences | Model + real state machine | T1 (short), T3 (deep) | ≤ 4 min / ≤ 2 h | TESTING | Zero counterexamples; every shrunk counterexample becomes a permanent regression test |
| 15 | **Chaos** | Behaviour under injected infrastructure and process faults | Real components, injected faults | T3 | ≤ 60 min | RELIABILITY + TESTING | No `Session` loss for faults the design claims to survive; every survived fault produces a `Diagnostic` |
| 16 | **Performance** | Throughput, latency, CPU, handshake and connect time | Real datapath, pinned hardware | T3 (trend), T4 (gate) | ≤ 90 min | TESTING | Within budget (§2.16) on the reference rigs; no regression beyond the noise band |
| 17 | **Soak** | Behaviour over long duration: leaks, drift, rekey, churn | Real everything, long-running lab | T4 | 72 h | TESTING | No unbounded resource growth; no unexplained state transition; rekeys all succeed |
| 18 | **Upgrade** | Rolling upgrade, downgrade, and minimum-version enforcement | Real multi-version deployment | T2 (N-1), T4 (full) | ≤ 50 min | TESTING | No `Session` loss during rolling upgrade; below-minimum versions refused with a typed `reason_code` |
| 19 | **Compatibility** | Supported OS/kernel/router matrix over time | Real OS images, real router hardware | T4 | ≤ 6 h | Platform owners | Every enumerated supported target passes its capability probe and the E2E smoke set |

### 2.1 Unit

Isolation is total: no sockets, no filesystem, no real clock, no real randomness. The
highest-value unit targets are the ones where a bug is silent: packet header parsing, address
and prefix arithmetic for both families, MTU/MSS computation, backoff schedule computation,
`ConnectionCandidate` priority ordering, policy evaluation, `reason_code` classification, and
redaction classification lookup ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md)
§11.4). Coverage is a review aid, not a gate, except on the parsers and the policy
evaluator where branch coverage below 85% blocks merge.

### 2.2 Component

One component, real, wired to test doubles implementing its peers' declared interfaces, driven
by a virtual clock (A-14). The obligation that distinguishes this level: **every transition of
the canonical `ConnectionState` machine is exercised at least once**, including the ones that
are hard to reach in integration (e.g. **T17** `MIGRATING → RECONNECTING` with the old path already
dead, and **T33** `FAILED → DISCOVERING` on a qualifying environment event). Transition coverage is computed
from the structured transition events (A-02) and is a merge gate: an uncovered transition is a
missing test, reported by name.

### 2.3 Protocol

**Golden vector corpus.** A versioned, checked-in corpus of byte-exact wire artifacts, one
directory per `ProtocolVersion`, each entry being a triple: `input.bin`, `decoded.json`,
`meta.toml` (origin, version, expected outcome, whether it is well-formed).

| Corpus class | Contents | Assertion |
|---|---|---|
| `valid/` | Well-formed messages for every message type, every optional-field combination, both address families | Decode succeeds; re-encode is byte-identical (round-trip stability); decoded structure equals `decoded.json` |
| `valid-future/` | Messages from `ProtocolVersion` N+1 containing unknown fields and unknown extensions | Decode succeeds under forward-compatibility rules ([ADR-0003](adr/ADR-0003-network-contract-schema-format.md)); unknown fields preserved or ignored exactly as the schema specifies |
| `malformed/` | Truncations at every byte offset, oversized length prefixes, invalid enum discriminants, duplicate fields, cyclic/deep nesting, integer overflow in length arithmetic | Decode fails with a typed `PROTO.MALFORMED_MESSAGE`-class outcome. **No panic, no hang, no allocation proportional to a declared length, no partial application of a rejected message** |
| `hostile/` | Compression bombs, maximum-nesting structures, adversarial padding, ambiguous encodings, canonicalization variants | Rejected deterministically; two encodings of the same semantic content must not both be accepted where the schema requires canonical form |
| `crypto-kat/` | Known-answer vectors from the upstream specifications selected in [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) | Byte-exact agreement with the published vectors |

**Golden vector generation rule.** Vectors are generated once, reviewed, and frozen. A code
change that alters a golden vector is a wire-format change and MUST be accompanied by a
`ProtocolVersion` change per [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md). Silently
regenerating a corpus to make CI green is the single most dangerous failure mode of this level
and is blocked procedurally: corpus files are owned by PROTOCOL and require an explicit,
separately-reviewed change.

**Control `CR-I2` — the novel-construction review gate (closes G-4, explicitly rather than by
silence).** The `crypto-kat/` corpus proves *conformance to* each audited primitive. It cannot
detect a novel construction assembled **around** correct primitives — a bespoke KDF chain, a
hand-rolled nonce derivation, an ad-hoc MAC-then-encrypt composition — because every individual
primitive still matches its published vectors. **I2 is a process invariant and is accepted as a
REVIEW-class control.** The acceptance is recorded here with an owner and a trigger so that it is
a decision rather than an omission:

| | |
|---|---|
| **Trigger** | Any diff touching the key schedule, a KDF invocation, nonce or IV derivation, an AEAD call site, a signature construction, or the `crypto/` module boundary — detected mechanically at **T1** by a path-and-symbol filter, which is the *only* mechanical half of this control |
| **Obligation** | The diff cannot merge without a review recorded by a second engineer, naming (a) every primitive invoked, (b) the published specification each is used **as specified by**, and (c) an explicit statement that no new construction was composed. "No crypto change" is an acceptable finding; **silence is not** |
| **Evidence** | The recorded review is bound to the commit under C-5, the same way test evidence is |
| **What it does not do** | It does not prove absence of novel construction. It makes the claim *someone's*, at a named point, on every qualifying diff. A control that is honest about its strength is worth more than one that is assumed to be mechanical |
| **Escalation** | Where a review finds a genuinely new construction, I2 is **violated** and the change is refused, not risk-accepted — [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) owns the exception path |

**Differential decoding.** Where two implementations of a codec exist (e.g. a fast path and a
reference path, or two language bindings), all corpus classes run through both and must agree
on accept/reject and on the decoded structure.

### 2.4 Contract

Schema-driven and versioned per [ADR-0003](adr/ADR-0003-network-contract-schema-format.md) and
[ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md). Four checks:

1. **Schema compatibility diff.** The PR's schemas are diffed against the previous release's.
   Breaking changes (removed field, narrowed type, changed enum semantics, changed required-ness)
   fail unless accompanied by the version bump the versioning ADR requires.
2. **Producer/consumer contract tests.** Each producer publishes example messages generated
   from its schema; each consumer is verified against the producers' examples for every version
   in the compatibility window. This catches "the schema allows it but the consumer chokes".
3. **`reason_code` registry diff.** The machine-readable registry
   ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2) is diffed for append-only
   compliance: no rename, no semantic change of an `ACTIVE` code, no reuse of a `RETIRED`
   identifier, `DEPRECATED` entries carry `alias_of`. Any violation fails the build (A-15).
4. **Registry completeness.** Every registered code has `class`, `severity`, `summary_key`,
   `doc_anchor`, and — where `user_actionable` — `next_action_key`. A code missing any of these
   fails the build. This is the mechanical enforcement of R-22.

### 2.5 Interoperability

The matrix is version-pairs × transport × address family × path type.

| Axis | Values |
|---|---|
| Version pair | (N, N), (N, N-1), (N-1, N), (N, N+1), (N+1, N), (N, minimum-supported), (N, below-minimum) |
| Transport | UDP, UDP:443, TCP/TLS, HTTPS-shaped (A-17) |
| Family | IPv4-only, IPv6-only, dual-stack |
| Path | `LOCAL_DIRECT`, `WAN_DIRECT`, `RELAYED` |

Supported pairs must establish a `Tunnel` and pass a data-integrity check. The
`below-minimum` pair must fail *cleanly*: a typed refusal, a stable `reason_code`, no
half-open state on either side, and no resource retained after the refusal. A crash, a hang, or
an untyped failure on an unsupported pair is a P1 defect, not a compatibility limitation.

### 2.6 Integration

Real components, real transports, simulated network. This is the level where component
interface assumptions meet reality: idempotency of system-state application
([ADR-0008](adr/ADR-0008-idempotency.md)) is exercised by applying the same configuration
repeatedly and after a crash mid-apply; state consistency
([ADR-0009](adr/ADR-0009-state-consistency.md)) is exercised by restarting the state authority
and verifying the caches reconcile without a second writer appearing.

### 2.7 End-to-end

Whole product, from a client application's socket through the tunnel, through a gateway or
`ExitNode`, to a simulated destination. The mandatory proof tests (§4) live here. E2E tests are
expensive and are deliberately few: if a property can be proven at a lower level, it belongs at
the lower level. E2E exists to prove *composition*, and the proof tests are the enumeration of
what composition must deliver.

**Registered non-proof case: `connectivity-report conformance` (E2E-CR-1).** This is the covering
test for **R-23**, and it closes **G-5.3/G-1**. It is a Level 7 case rather than a proof test
because the acceptance set is enumerated in §4 and §4.3 and is not extended by this document.

| | |
|---|---|
| **Proves** | **R-23** — the connectivity report can be produced by an ordinary user on an ordinary build, and it names what was tried and what blocked it |
| **Scenario** | Any **failed** `S-NAT-*` family run (§3.3), so the report is produced about a real failure rather than a healthy path |
| **Preconditions (V3)** | A **release build**, not a debug build; no verbose capture enabled and no restart between the failure and the report; the `ConnectionCandidate` ledger recorded independently by the harness, so the oracle has a reference set the product did not author |
| **Oracle** | (1) The report is produced with **no rebuild, no debug binary and no "enable logging first" step** ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.8). (2) Its candidate ledger names **every** candidate in the harness's reference set — including the losers — each with family, type, elapsed time and a per-candidate `reason_code`; a missing candidate fails. (3) It names the **blocking constraint** as a registered `reason_code`, not as prose. (4) All eight parts are present and in §11.8's order, verdict first. (5) The produced artifact satisfies **PB-7** redaction: every `SENSITIVE` field is pseudonymized and no `SECRET` field is present in any form |
| **Mutants** | `M-CR-1` omit losing candidates from the ledger; `M-CR-2` emit the blocking constraint as human text with no code; `M-CR-3` gate production on a debug build; `M-CR-4` render the preview through a second renderer that does not redact (**DX-1**, [ADR-0019](adr/ADR-0019-application-state-model-and-ui-architecture.md) §11.10(g)) |
| **Positive control (V4)** | A seeded ledger with a known candidate set and a known blocking code renders exactly that set and that code |
| **Tier** | T3 and T4 |

### 2.8 Platform

Per-OS, on real OS images or real devices — never on a stub.

| Target class | Runs on | Specifically verifies |
|---|---|---|
| Windows | VM images per supported build | Adapter availability without a bespoke stale driver (R-19), DPAPI-NG/TPM key storage, firewall rule installation for both families, behaviour with third-party AV/firewall installed (R-18) |
| macOS | VM/hardware per supported version | NetworkExtension lifecycle, Keychain, system-extension approval flow, on-demand reactivation |
| iOS | Physical device farm | NetworkExtension background lifecycle, OS-initiated suspension and termination, resume without leak (R-08), roaming Wi-Fi↔cellular |
| Android | Physical device farm + emulators | VpnService lifecycle, Keystore/StrongBox, Doze and App Standby, per-app routing, always-on VPN + block-connections-without-VPN interaction with our own kill switch |
| Linux desktop/server | Container + VM per kernel | Kernel datapath and userspace fallback, systemd integration, nftables/iptables variants, resolver integration variants (systemd-resolved, resolvconf, static) |
| Router-class (OpenWrt-class) | Real hardware + emulated targets | Headless operation, low memory, userspace datapath, no-GUI configuration, persistent-storage-free operation (R-21) |

The **capability probe** is itself a test artifact: for each target, the probe's declared
requirements are asserted against the real OS, so an OS update that removes an API produces a
named failure (`PLATFORM.OS_UNSUPPORTED`, `PLATFORM.ADAPTER_UNAVAILABLE`) in CI before it
produces a field surprise (R-20).

### 2.9 Networking

Addressing and routing correctness in namespaces: deterministic `TwinNet` address assignment
without DHCP (R-03, A-10); correct route installation and, critically, correct *removal* —
a teardown that leaves a route, a rule, an address, or a firewall entry behind is a defect
(R-17); policy routing for a multi-peer gateway (A-11); PMTU discovery and MSS clamping for
both families, including the ICMP/ICMPv6-blackhole variant; interface add/remove/change; and
address-space collision detection against pre-existing virtual interfaces.

**The `S-COLL-*` pre-flight conflict family (closes G-3).** §2.9's other rows verify that a
*correct* install installs and a *correct* teardown removes. They do not verify the case **R-17
actually exists to retire**: a conflict that is *detected* must be **reported and refused**, not
silently overwritten. A product that quietly takes an address another component already holds has
passed every other row in this level.

| Case | Injected pre-existing state | Oracle |
|---|---|---|
| `S-COLL-ADDR` | A foreign virtual interface already carrying an address inside the `TwinNet` prefix, both families | `ROUTE.ADDRESS_COLLISION` (FATAL/CRITICAL, [ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md)) is emitted **before** any state change |
| `S-COLL-IFACE` | Another product holding an adapter with our naming/owner tag, or a routing entry for our prefix | `ROUTE.IFACE_CONFLICT` (PERSISTENT/ERROR) is emitted, and the conflicting owner is named where the platform makes it determinable |
| `S-COLL-RULE` | A pre-existing policy-routing rule at our priority, or a firewall entry in our table name | `ROUTE.IFACE_CONFLICT`, and the run does **not** proceed to arm enforcement |

**Rule COLL-1 — the no-modification assertion is the point of the family.** Every case captures
the host's interface list, address set, route table, policy-routing rules and firewall ruleset
**before** the attempt, and asserts them **byte-identical after**. A case that emits the right
code while having already created the interface **fails**: R-17 is a *pre-flight* requirement, and
a report issued after the damage is a log line, not a conflict report.

**Mutants (V2).** `M-COLL-1` detect-then-proceed (emits the code, installs anyway) — must fail
COLL-1; `M-COLL-2` overwrite silently with no code — must fail the oracle; `M-COLL-3` detect only
the v4 collision — must fail on the v6 case; `M-COLL-4` roll back after a partial install rather
than refusing before it — must fail COLL-1, because a rollback is observable to anything watching
the host in between.

**Positive control (V4).** The same rig with no pre-existing conflict installs cleanly and emits
no `ROUTE.*` code, proving the detector is not simply always-on. **Tier:** T2 and above.

### 2.10 NAT traversal

Driven by the TwinLab NAT class matrix (§3.3). Per NAT-class-pair, the test asserts the
*expected outcome class*, not merely "it connected":

| Expected outcome | Meaning | Assertion |
|---|---|---|
| `DIRECT_EXPECTED` | The pair should reach `WAN_DIRECT` | Reaches `WAN_DIRECT` within the budget; falling back to `RELAYED` is a **failure**, not a pass |
| `DIRECT_POSSIBLE` | Direct is achievable but not guaranteed | Success rate across N runs meets the per-pair budget (§3.6); every failure falls back to `RELAYED` |
| `RELAY_EXPECTED` | Direct is impossible for this pair | Reaches `RELAYED`; a claim of `WAN_DIRECT` indicates a broken NAT emulator (V10) and fails the run |

The `DIRECT_EXPECTED` class is what stops this level from passing vacuously: a build that gave
up on hole punching and always relayed would still "connect", and would be caught here and
nowhere else.

### 2.11 Property-based

Invariants over generated inputs and generated state sequences. Named invariants:

| Invariant under test | Statement | Generator |
|---|---|---|
| **PB-1 — No plaintext egress while blocked** | No reachable sequence of state-machine events permits protected traffic to egress untunneled while the machine is in `BLOCKED`. | Random walks over the state machine's event alphabet, including out-of-order, duplicated, and stale events |
| **PB-2 — Every bad state has a reason** | Every entry into `DEGRADED`, `BLOCKED`, `FAILED`, or `RECONNECTING` carries a `Diagnostic` with a registered `reason_code` (A-16) | Same generator as PB-1 |
| **PB-3 — Session survives path churn** | For any sequence of `Path` up/down/change events, `Session` identity and key state are preserved unless a terminal condition is reached (A-04) | Generated path event sequences with arbitrary interleaving |
| **PB-4 — Idempotency** | Applying the same system-state configuration k times yields the same final system state as applying it once, for all k ≥ 1, including with crashes injected between applications ([ADR-0008](adr/ADR-0008-idempotency.md)) | Generated configurations × generated crash points |
| **PB-5 — Round-trip stability** | For all well-formed messages, `decode(encode(m)) == m` and `encode(decode(b)) == b` where the schema declares canonical encoding | Structure-aware message generator from the schema |
| **PB-6 — Single writer** | No generated concurrent operation sequence produces two authoritative writers for one piece of persistent state (I8, [ADR-0009](adr/ADR-0009-state-consistency.md)) | Generated concurrent operation interleavings |
| **PB-7 — Redaction totality** | For every event schema and every generated field value, no `SECRET`-classified field appears in any rendered output at any log level, in any build ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.4) | Generated event instances with tagged canary values in every field |
| **PB-8 — Backoff bounds** | For all failure sequences, the reconnect schedule is monotone within its class, jittered, and never exceeds its declared ceiling nor retries faster than its declared floor | Generated failure sequences |
| **PB-9 — Address plan disjointness** | For any generated set of `Device`s in a `TwinNet`, derived addresses are unique and within the declared prefixes, in both families (A-10) | Generated `DeviceIdentity` sets, including adversarially near-colliding ones |
| **PB-10 — Monotone protection** | Protection status never transitions from a protected state to an unprotected state without an intervening observable event carrying a `reason_code` | Generated enforcement-layer perturbations |

Every shrunk counterexample is promoted to a named, permanent regression test at the unit or
component level. The property test finds it once; the regression test keeps it found.

### 2.12 Fuzz

| Target | Input | Harness style | Notes |
|---|---|---|---|
| `fz-packet-parser` | Raw tunnel-frame bytes | Coverage-guided, in-process, with ASan/UBSan/MSan | Post-decrypt and pre-decrypt entry points both fuzzed; the pre-decrypt one is the untrusted-network surface |
| `fz-handshake-state` | Handshake message sequences | Structure-aware + state-machine-aware; generates out-of-order, replayed, and truncated sequences | Asserts the state machine never reaches an undefined state and never allocates unboundedly |
| `fz-control-decoder` | Control-plane messages ([ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md)) | Structure-aware from the schema ([ADR-0003](adr/ADR-0003-network-contract-schema-format.md)) | Grammar derived from the schema so the fuzzer spends its budget past the length checks |
| `fz-config-parser` | Configuration files, CLI arguments, router-style config | Coverage-guided | Router targets accept config from less-trusted places than desktops |
| `fz-dns-response` | DNS/DoH/DoT responses | Structure-aware | Includes compression-pointer loops and malformed EDNS |
| `fz-relay-frame` | Relay framing on the infrastructure side | Coverage-guided, plus a differential mode | Infrastructure crash-resistance is an availability property (R-11) |
| `fz-bundle-parser` | Diagnostic bundle format | Coverage-guided | The support-side viewer parses attacker-influenced files |
| `fz-uri-and-invite` | Pairing invitations, deep links, QR payloads | Structure-aware | Attacker-supplied by nature |
| `fz-trust-document` | COSE_Sign1 / deterministic-CBOR over **every** [ADR-0003](adr/ADR-0003-network-contract-schema-format.md) B2 statement type. B2 is **no longer the seven types §6 was justified on** — ADR-0003's own note records **seventeen**: `PairingAttestation`, `RevocationRecord`, `DeviceIdentityRecord`, `PolicyBundle`, `RouteAdvertisement`, `ExitNodeOffer`, `IdentitySuccession`, `TunnelKeyBinding`, `OwnerTrustAnchor`, `OwnerDelegation`, `TrustEpochBundle`, `RelayCapabilityToken`, `RelayEpochFloor`, the signed relay map, `LogHead`, and the signed network contract. **The target set is the B2 list, whatever it currently is** — a new B2 type without a corpus entry fails the §2.4 contract check | Structure-aware from the CDDL schema, plus a canonicalization mode | Trust-bearing by [ADR-0003](adr/ADR-0003-network-contract-schema-format.md)'s own classification: verified offline **possibly years after issuance**, so forgery is total compromise and there is no revocation-by-freshness. Non-canonical input MUST be rejected, not normalized; signature verified over **received octets**; `crit` enforced. Reached by a *peer* in-session under [ADR-0009](adr/ADR-0009-state-consistency.md) §11.6 G-3 and [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7's peer-relayable `TrustEpochBundle`, so it is **not** a control-plane-only surface |
| `fz-capability-token` | `RelayCapabilityToken` (COSE_Sign1/CBOR: `iss`, `aud`, `sub`, `cnf`, `nbf`/`exp`, `epoch`, `quota`, `jti`), `RelayEpochFloor`, and the `Owner`-signed relay map | Structure-aware | These are B2 types, but they get a **separate target because of where the parser sits**: on the relay's **pre-admission, attacker-reachable** path. Admission is a pure offline function ([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.3) evaluated on attacker-supplied bytes before any authentication, and `RelayEpochFloor` is accepted **piggybacked from any connecting client**. `fz-trust-document` fuzzes these as documents; this target fuzzes them in the position an attacker actually occupies |
| `fz-attestation-blob` | Platform attestation chains and formats presented at pairing/enrolment | Structure-aware + coverage-guided | Vendor-defined, externally-sourced, and parsed before a trust decision ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.3). An unrecognized format degrades to `hardware_backed = false`; a malformed one must not crash the parser |
| `fz-control-reorder` | Sequences of control operations, not bytes | **Stateful harness**: replays every control operation N times in random order, including interleaved duplicates, stale `if_version` preconditions, and crash points between applications | Required by [ADR-0008](adr/ADR-0008-idempotency.md) §11 and **existing nowhere else**. Asserts the RQ-6 property directly: replaying an older trust state never un-revokes. Complements PB-4 by fuzzing *order*, which the property generator samples but does not adversarially search |

**Differential fuzzing** runs where a second implementation exists (codec fast path vs
reference; our decoder vs the upstream reference implementation of an adopted protocol), and
divergence in accept/reject is itself a finding.

Continuous fuzzing runs against `main` with a persistent, deduplicated corpus; the nightly tier
runs a fixed CPU-hour budget against the PR branch's changed targets. **A new unique crash,
hang, OOM, or sanitizer report is a release blocker regardless of perceived exploitability** —
triage classifies severity, it does not decide whether to fix.

### 2.13 Chaos

Fault injection against a running lab deployment. Each fault names the property the design
claims to preserve, so the test is a claim check rather than an exploration.

| Fault | Design claim under test | Oracle |
|---|---|---|
| Kill the control plane entirely | I5: established tunnels survive (A-13) | See **P15** |
| Kill the in-use relay process | R-10: bounded failover, no `Session` loss | See **P03** |
| Blackhole an entire `RelayRegion` | R-11: no single region is fatal (A-18) | Session migrates to another region; `RELAY.REGION_UNAVAILABLE` surfaced |
| Partition client from rendezvous but not from peer | R-11: cached `TrustedPeer`/`Endpoint` state permits reconnection without the control plane | Reconnect succeeds; `CONTROL.UNREACHABLE` surfaced as informational, not terminal |
| Kill the client agent process (SIGKILL) | I3: kill switch is not process-resident (A-08) | See **P09** |
| Suspend the client process (SIGSTOP) for longer than the assertion freshness window | O-18: a hung agent cannot show a stale protected indicator | Protection indicator becomes `UNKNOWN`, never stays `PROTECTED` |
| Fill the disk on a client | Observability must not break the datapath | Datapath unaffected; `dropped_events` increments; `RESOURCE.*` diagnostic raised |
| Clock jump forward/backward on a client | Rekey, expiry, and backoff logic tolerate clock movement | No spurious teardown; no key reuse; no negative-duration timer |
| Relay accepts then stalls (grey failure, no reset) | Health probing detects degraded, not just dead | `HealthState` → `DEGRADED`/`UNHEALTHY` (A-03) and failover triggers |
| Duplicate/replayed relay frames injected | Replay protection holds | `CRYPTO.REPLAY_DETECTED`; no duplicate delivery to the application |

Grey failures (stall, slow, partial) are given at least equal weight to hard failures, because
they are the class PairVPN handled worst.

### 2.14 Security

Adversary-driven, against the actors modelled in [docs/threat-model.md](threat-model.md).
Includes: the malicious-relay battery (**P14**), downgrade and version attacks (**P11**,
**P12**), revocation (**P10**), leak batteries (**P07**, **P08**, **P09**), malformed-input
resistance (**P13**), key-custody verification (no exportable device credential, I4), pairing
attacks (invitation replay, invitation phishing, out-of-band channel substitution), traffic
injection and replay, and a redaction/telemetry battery asserting
[ADR-0015](adr/ADR-0015-observability-and-diagnostics.md)'s privacy claims (nothing leaves the
device at Tier 0; no peer-pair record on relays; `SECRET` never rendered).

**The key-custody battery, and the `hardware_backed` accuracy requirement (closes G-5).** I4's
exclusion argument — that a private half cannot leave the device — is **conditional on the custody
claim being true**, and on `hardware_backed = false` targets (routers, containers, VMs) the private
half demonstrably *can* leave (**TM-13**, [ADR-0023](adr/ADR-0023-headless-cli-and-embedded-profile.md)
`PLATFORM.EMBEDDED.IDENTITY_CLONEABLE`). The battery therefore verifies the **flag**, not only the
key, because a false flag would make the whole argument unfalsifiable.

| # | Assertion | Applies to |
|---|---|---|
| **KC-1** | On every target in §2.18's matrix, the **live probe** result for both Tier-1 backends (identity backend, vault-key backend) is compared against the target's **declared** custody class, and the derived `custody_class` equals the **minimum** of the two (`S-54`, ST-9a). A target whose declaration and probe disagree fails | all |
| **KC-2** | **A false `hardware_backed = true` is impossible to produce.** On a target with the secure element removed, disabled, or emulated, the probe MUST report `false`. Asserted by running the same build on a hardware-backed and a deliberately software-only instance of the *same* platform and requiring the flag to differ | all |
| **KC-3** | Where `hardware_backed = true`, an export attempt through every platform API that could plausibly return key material fails, and no private half appears in any process dump, backup set, or exported container | hardware-backed targets |
| **KC-4** | Where `hardware_backed = false`, the test **asserts the clone succeeds** and that the device advertises `SOFTWARE_PORTABLE` and holds no `ENROLL`/`REVOKE`/`DELEGATE` OSK. This oracle is deliberately **inverted**: a build that claims non-exportability on a target where it is untrue fails here | software-custody targets |
| **KC-5** | A downward transition of `custody_class` at runtime emits `STORE.CUSTODY_DEGRADED` and forces IK rotation ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) N-24); a permanent `SOFTWARE_PORTABLE` steady state does **not** (EM-29a) | all |

**Mutants.** `M-KC-1` hard-code `hardware_backed = true`; `M-KC-2` derive the flag from the
platform name rather than the probe; `M-KC-3` report the **maximum** of the two backend probes
instead of the minimum; `M-KC-4` suppress `STORE.CUSTODY_DEGRADED` on transition. **Positive
control (V4):** a known-hardware-backed instance reports `true` and a known-software instance
reports `false` in the same session, proving the probe discriminates at all.

Security tests are the strictest consumers of **V2** and **V4**: every one ships with a mutant
it must catch, and every negative result ships with a positive control proving the observation
channel worked.

### 2.15 Upgrade

| Case | Procedure | Pass criterion |
|---|---|---|
| Rolling client upgrade N-1 → N | Upgrade one peer of an established `Session` while traffic flows | No `Session` loss; no plaintext egress during the swap; kill switch holds across the restart |
| Rolling infrastructure upgrade | Upgrade relays one at a time across a fleet carrying live sessions | Sessions migrate (A-01); zero terminated sessions attributable to the upgrade |
| Mixed fleet N-1/N/N+1 | Run all three concurrently in one `TwinNet` | Every supported pair interoperates; capability negotiation selects the common set |
| Downgrade N → N-1 | Roll a client back with persisted state written by N | N-1 either reads the state or refuses with a typed `reason_code`; it MUST NOT crash, corrupt, or silently discard |
| Minimum-supported-version rejection | Present a below-minimum peer | Clean typed refusal (`PROTO.VERSION_UNSUPPORTED`), no half-open state, no retry storm |
| Interrupted upgrade | Kill the installer/updater mid-write | System is in one of two well-defined states (old or new), never a third; kill switch holds throughout |

### 2.16 Performance

Measured on pinned reference rigs, not on shared CI runners.

| Metric | Rig | Budget shape |
|---|---|---|
| Throughput, `LOCAL_DIRECT`, kernel datapath | Desktop reference pair, 1 GbE | ≥ a declared fraction of link rate, both families (R-15) |
| Throughput, userspace datapath | Same rig, forced userspace | Declared lower budget; the gap is a documented number, not a surprise |
| Throughput, router-class | Reference router hardware | Declared budget; regressions here are release-blocking because headroom is smallest |
| Throughput, `RELAYED` | Lab relay, controlled RTT | Declared fraction of direct; relay overhead is a tracked number |
| Added latency, `RELAYED` vs `WAN_DIRECT` | Controlled | p50 and p95 both tracked; p95 is the one that matters (R-12) |
| Time to first byte, per NAT class pair | TwinLab matrix | p50/p95 per class; `RELAY_EXPECTED` pairs measured to relay establishment |
| Handshake CPU cost | Reference | Cost per handshake; gateway capacity derives from it |
| Gateway scaling | Reference gateway | Throughput and CPU vs concurrent peer count, to the declared peer limit (R-16, A-11) |
| Memory, steady state | All targets | Resident set, including the observability budget from [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §9 |
| Failover time | Lab | Relay failover and path migration wall-clock, p50/p95 |

Regression detection uses a noise band established from repeated runs on the same rig; a
result outside the band is a failure, not a re-run. Benchmarks are bound to an exact commit or
an immutable snapshot, and a candidate is always compared against a baseline built the same way.

### 2.17 Soak

72 hours minimum, on the release candidate, in a lab topology with continuous traffic, periodic
path churn, scheduled rekeys, relay failovers, client restarts, and peer join/leave churn on a
multi-client gateway. Watched: resident memory, file descriptors, conntrack/session table
occupancy, goroutine/thread counts, timer counts, log/ledger growth, and — the important one —
**the count of state transitions with no attributable trigger**. A single unexplained
transition in 72 hours is investigated, not averaged away.

### 2.18 Compatibility

The supported-target matrix is an enumerated, versioned artifact (R-20): each supported OS
version, kernel version, and router platform, with the specific API each depends on. Nightly,
each target runs its capability probe and an E2E smoke set. A target that fails is either fixed
or explicitly removed from the supported matrix in the same release — silent breakage is the
defect this level exists to prevent.

---

## 3. TwinLab — the reproducible network laboratory

### 3.1 What TwinLab is for, and the realization principle

TwinLab is the rig on which every claim in [docs/networking.md](networking.md),
[docs/reliability.md](reliability.md), [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md),
[ADR-0005](adr/ADR-0005-relay-architecture.md),
[ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) and
[ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) is made falsifiable. It is a
*network* laboratory, not a mock: real kernels, real sockets, real NAT state tables, real
firewall objects. The one thing it simulates is the Internet between them.

**The realization principle (normative).** Every condition TwinLab reproduces MUST be produced
by a *mechanism with the same observable semantics as the real thing*, never by a flag inside
TwinVPN. A test MUST NOT be able to detect that it is running in TwinLab by inspecting the
product's own configuration. Specifically: a build MUST NOT contain a `lab_mode`, a
`simulate_symmetric_nat` switch, or any code path reachable only under test. Where the product
must be steered (injected clock, seeded RNG — §3.5), the seam is a *constructor parameter at a
component boundary*, identical in shape in production, where it is bound to the real clock and
the OS CSPRNG.

Consequence: a `RELAY_EXPECTED` outcome in TwinLab is produced by a NAT that genuinely allocates
address-and-port-dependent mappings, so a build that "cheats" — that recognizes the lab and
relays early — is caught by §2.10's `DIRECT_EXPECTED` class, and a broken emulator is caught by
§3.4.4's conformance prober (**V10**).

### 3.2 Topology and how a node is realized

The unit of a TwinLab node is a **Linux network namespace**. Namespaces are joined by `veth`
pairs; a shared L2 segment is a Linux bridge inside a namespace with one `veth` leg per
attached node. Nothing runs on the host's root namespace except the orchestrator.

```text
        ┌──────────── site A ────────────┐          ┌──────────── site B ────────────┐
  dev-a1 ─┐                              │          │                              ┌─ dev-b1
  dev-a2 ─┼─[br-lan-a]─ nat-a ─┐         │          │        ┌─ nat-b ─[br-lan-b]─┼─ dev-b2
  gw-a  ──┘                    │         │          │        │                    └─ dev-b3
                               ├─ isp-a ─┴──[ core-transit ]─┴─ isp-b ─┤
                               │              │  │  │  │              │
                          [cgnat-a]           │  │  │  └── dst-*   (simulated Internet hosts)
                        (shared by ≥2         │  │  └───── relay-r2 (region EU, domain d2)
                         subscriber trees)    │  └──────── relay-r1 (region EU, domain d1)
                                              └─────────── rz (rendezvous) + cp (control plane)
                                                            + rs (relay-selection service)
```

| Element | Realization | Why this mechanism |
|---|---|---|
| `Device` node | Namespace running the real agent binary, one per device | Real sockets, real routing table, real `twin0` interface |
| L2 segment | Bridge + `veth` legs, optional client-isolation via `nft` in the bridge namespace | Produces genuine `LOCAL_DIRECT` and genuine hairpin failures |
| CPE / middlebox | Namespace with forwarding on and an nftables **NAT personality** (§3.3) | Mapping and filtering behaviour come from real `conntrack` state |
| Carrier CGNAT | A second middlebox namespace **shared by ≥ 2 subscriber trees**, so the public address really is shared | A single-subscriber "CGNAT" does not reproduce the port-exhaustion or hairpin properties |
| Transit / ISP | Namespace carrying the impairment qdiscs (§3.4) and the egress-filter personality | Impairment belongs on the path, not on the endpoint |
| `Relay` | Namespace running the real relay binary, tagged `RelayRegion` and `failure_domain` per [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.1 | ≥ 2 relays in ≥ 2 domains per region is a lab **precondition**, not a scenario option |
| Control plane / rendezvous / relay-selection | Three separately-killable namespaces | I5 and **P15** require them to fail independently ([ADR-0005](adr/ADR-0005-relay-architecture.md), A-18) |
| Simulated Internet | `dst-*` namespaces plus an authoritative + recursive DNS server with injectable fault modes (§3.4) | Gives DNS and `ExitNode` tests a real answerer to be denied by |

**Address realism (normative).** The lab MUST use globally-routable-shaped documentation
addresses for the "public" side (`198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`), RFC 6598
`100.64.0.0/10` for the carrier-NAT tier, and RFC 1918 space behind CPEs. It MUST NOT reuse the
`TwinNet` overlay prefixes ([ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md),
[ADR-0011](adr/ADR-0011-dns-handling.md) §11.13(a)) for underlay addressing — except in the one
scenario family (`S-COLL-*`) whose entire purpose is to reproduce the overlay/underlay collision
of `docs/networking.md` §7.5 and R-17.

### 3.3 NAT personalities — the class matrix (§2.10's driver)

Classes use [docs/networking.md](networking.md) §3.1's RFC 4787 / RFC 5382 terminology.
Mapping and filtering are configured **independently**, because they are independent axes and
conflating them is exactly the defect the legacy vocabulary causes.

| Personality | Mapping | Filtering | Legacy name | Realization |
|---|---|---|---|---|
| `N-ROUTED` | none | none | routed / native v6 | Forwarding only; no `nat` chain. The IPv6 default. |
| `N-EIM-EIF` | Endpoint-Independent | Endpoint-Independent | full cone | `snat` with `NF_NAT_RANGE_PERSISTENT` (`nft ... snat to <ext> persistent`) for EIM, **plus** a `cone` helper subscribed to `NFNETLINK_CONNTRACK` `NEW` events that installs a matching `dnat` for `(ext_ip, ext_port) → (int_ip, int_port)` for the mapping lifetime. There is no pure-nftables full cone; the helper is the honest mechanism and is itself conformance-tested (§3.4.4). |
| `N-EIM-ADF` | Endpoint-Independent | Address-Dependent | address-restricted cone | As `N-EIM-EIF`, but the helper's `dnat` rule carries `ip saddr <observed peer address>` / `ip6 saddr`, so a different address is filtered while a different port is not. |
| `N-EIM-APDF` | Endpoint-Independent | Address-and-Port-Dependent | port-restricted cone | `snat ... persistent` for EIM; **no** helper — stock `conntrack` reply matching already yields APDF. This is Linux's default behaviour and needs the least machinery. |
| `N-APDM-APDF` | Address-and-Port-Dependent | Address-and-Port-Dependent | symmetric | `masquerade fully-random`, which allocates a fresh source port per destination tuple, plus a per-destination `ct` mark so the allocation cannot be coincidentally reused. Two sub-variants: `-RAND` (uniform allocation, the birthday-prediction target) and `-SEQ` (a monotone allocator, the delta-prediction target) — `docs/networking.md` §3.6 distinguishes them, so the lab MUST too. |
| `N-CGNAT` | APDM at the carrier tier | APDF | CGNAT / double NAT | `N-EIM-APDF` at the CPE chained into a shared `N-APDM-APDF` carrier namespace on `100.64.0.0/10`, whose public address is shared by ≥ 2 subscriber trees. Port budget per subscriber is capped (`nft ... snat to <ext>:<lo>-<hi>`) so exhaustion is reachable. |
| `N-NAT64` | v6-only access + NAT64 | n/a | 464XLAT / mobile | `jool`-class stateful NAT64 in the transit namespace, `pref64` advertised **both** ways: RFC 8781 PREF64 in RAs (the path `docs/networking.md` §3.8 prefers) and RFC 7050 `ipv4only.arpa`, independently switchable so the "PREF64 absent, must fall back to RFC 7050" case is a distinct scenario. |

Two axes are configured orthogonally on every personality:

| Axis | Values | Realization |
|---|---|---|
| Mapping lifetime | 30 s (mobile), 120 s, 300 s (home CPE) | Per-namespace `nf_conntrack_udp_timeout` / `nf_conntrack_udp_timeout_stream`, or an `nft ct timeout` policy object bound to the flow |
| Hairpinning (RFC 4787 REQ-9) | on / off | Presence or absence of a hairpin `dnat` in the middlebox's `prerouting` for its own external address |
| Port-mapping protocol | `PCP` / `NAT-PMP` / `UPnP-IGDv2` / `none` | The corresponding daemon enabled in the middlebox namespace; `none` is the default so a test must *ask* for the easy path |

**Class-pair expectations.** Each ordered personality pair carries an expected outcome class
from `docs/networking.md` §3.2's traversability matrix, and §2.10's assertion is against that
class, not against "connected". The mapping is mechanical and MUST be generated from §3.2
rather than restated here, so a change to §3.2 cannot silently diverge from the lab.

### 3.4 The impairment matrix

Impairment is applied on the **transit** side of a link, never on the device namespace, so that
a device's own stack sees only what a real device sees.

| Condition | Mechanism | Parameters exercised | Determinism class (§3.5) |
|---|---|---|---|
| Latency | `tc qdisc netem delay` on the transit veth | 5 / 40 / 120 / 300 ms, one-way, asymmetric variants | STATISTICAL |
| Jitter | `netem delay <base> <jitter> distribution normal` | ±5 / ±30 / ±80 ms | STATISTICAL |
| Packet loss | Deterministic drop schedule loaded into an eBPF `tc` classifier from a seeded bitmap (**not** `netem loss`, see §3.5) | 0.1 / 1 / 2 / 5 / 20 % | BIT (seeded schedule) |
| Duplication | `netem duplicate` | 0.5 / 2 % | STATISTICAL |
| Reordering | `netem delay <d> reorder <p> <corr>` | 1 / 5 % with 25 % correlation | STATISTICAL |
| Corruption | `netem corrupt` | 0.01 / 0.1 % — corroborates AEAD rejection counters, never used for functional tests | STATISTICAL |
| Bandwidth restriction | `tbf` / `htb` on the transit veth | 1 / 10 / 100 Mbit, with a bounded burst | BIT for shaping, STATISTICAL for goodput |
| MTU mismatch | `ip link set dev <transit veth> mtu N` | 1500 / 1492 (PPPoE) / 1400 (xlat) / 1280 | BIT |
| PMTU black hole | Reduced MTU **plus** `nft` drop of ICMPv4 type 3 code 4 and ICMPv6 type 2 in the transit namespace | on / off | BIT |
| Blocked UDP | `nft` drop `meta l4proto udp` egress in the transit namespace, both families | total; or "all but 443" | BIT |
| Egress restricted to 443 | `nft` accept `tcp dport {80,443}` + `udp dport 443`, drop otherwise | with and without a transparent proxy requiring `CONNECT` | BIT |
| Captive portal | Transit namespace `dnat`s all HTTP/HTTPS to a portal host and answers a known name with the portal address, until "authenticated" by a token | pre-auth / post-auth | BIT |
| Interface change (roam) | Move the device's `veth` leg from `br-wifi` to `br-cell` and re-address, producing genuine `EV_LINK_DOWN` / `EV_ADDR_CHANGED` | same-family, cross-family (v4→v6-only), and make-before-break variants | BIT for the trigger |
| DNS failures | Lab resolver fault modes: timeout, `SERVFAIL`, `NXDOMAIN` for a known-good name, truncation without TC, compression-pointer loop, malformed EDNS, DNS64 synthesising for a name it should not | per-mode | BIT |
| Relay process failure | `SIGKILL` (hard), `SIGSTOP` (hang), `nft` blackhole (silent), and **grey**: accept-then-stall by dropping the relay's data egress while its health socket still answers | four modes | BIT for the trigger |
| Whole-region failure | Blackhole the region's transit namespace, both families, all relays in it | one region of ≥ 2 | BIT |
| Network partition | `nft` drop between two named transit segments, direction-selectable (asymmetric partitions are a distinct case) | symmetric / asymmetric | BIT |
| Control-plane outage | Blackhole `cp`, `rz`, `rs` independently or together | 4 combinations, ≥ the union case for **P15** | BIT |
| Host-level faults | `SIGKILL`/`SIGSTOP` of the agent, disk-full via a size-capped tmpfs, clock step ±10 min / ±25 h via `CLOCK_REALTIME` offset in the namespace, namespace reboot | per §2.13 | BIT for the trigger |

#### 3.4.1 Composition rule

An impairment set is a *set*, applied atomically before the scenario's first packet, and
recorded verbatim in the run record. Impairments MUST NOT be changed mid-scenario except through
a declared, timestamped **event schedule** (§3.6), because an undeclared mid-run change makes the
result unattributable.

#### 3.4.2 Simulator conformance suite (V10 — the obligation §2 places here)

**Rule L-1.** No traversal, leak, or relay test may run against a personality or impairment that
has not passed its conformance suite **in the same lab instantiation, on the same day**. A
personality that has drifted manufactures false confidence at the exact scale of the matrix.

| Simulator under test | Conformance assertion |
|---|---|
| NAT personality | An independent RFC 5780-style behaviour prober (not TwinVPN code) reports exactly the configured mapping and filtering behaviour, the configured mapping lifetime within ±10 %, and the configured hairpin result — for both families |
| CGNAT tier | Two subscriber trees observe the *same* public address and *disjoint* port ranges; port exhaustion is reachable and reported |
| NAT64 | A v4-literal destination is reachable from a v6-only client via the synthesized prefix, and `PREF64`-off forces the RFC 7050 path |
| Loss / duplication / reorder shim | Measured rate over 10⁵ packets is within the declared tolerance of the configured rate; for the seeded loss schedule, two runs at one seed drop the **identical** packet indices |
| PMTU black hole | A 1500-byte DF probe is dropped and **no** ICMP fragmentation-needed is observed at the sender |
| Egress filter | A UDP probe on each blocked port fails and on each permitted port succeeds, both families |
| Platform stub (where one exists) | Its declared capability set matches the real OS's on at least one real target per release (§2.8) |

### 3.5 Determinism

**Rule L-2 (V8).** Every scenario declares exactly one determinism class, and its assertions MUST
be valid for that class. An assertion of the form "exactly 3 retransmissions" in a
`STATISTICAL` scenario is a review failure, not a flaky test.

| Class | Meaning | Permitted assertions |
|---|---|---|
| `BIT` | Two runs at the same seed produce the same ordered sequence of structured transition events (A-02) and the same `reason_code` sequence | Exact event sequences, exact counters, exact state paths |
| `STATISTICAL` | Reproducible in distribution over a declared run count | Rates, percentiles with a declared confidence interval, monotonicity, bounds |
| `EXPLORATORY` | Not reproducible; used for fuzz, soak, and discovery | Crash/hang/sanitizer absence only. **MUST NOT** gate a release on a numeric threshold |

**Seeding.** A scenario carries one 128-bit `scenario_seed`. Every consumer derives its own
stream as `HKDF-SHA-256(ikm = scenario_seed, info = "twinlab/v1/" || consumer_id)`, so adding a
consumer does not shift any existing consumer's stream — the property that makes a seed useful a
year later. Consumers that MUST be seeded: candidate-racing tie-breaks, backoff jitter
(`docs/reliability.md` §6.1), the `uniform(0, T_REGION_SPREAD)` drain draw and the HRW hash
([ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.7, §11.16), port-prediction socket
selection (`docs/networking.md` §3.6), relay-selection score tie-breaks, the loss schedule, and
the fault-injection schedule.

**Why `netem loss` is rejected for `BIT` scenarios.** `netem`'s loss, reorder, and duplication
draws come from the kernel PRNG and are not seedable from userspace. A `BIT` scenario therefore
MUST use a precomputed drop schedule (a seeded bitmap over packet index, consumed by an eBPF `tc`
classifier). `netem` remains the mechanism for `STATISTICAL` scenarios, where its
non-reproducibility is declared rather than hidden.

**Clocks and timers — an unmet dependency, recorded.** Assumption **A-14** states that timers,
clocks, randomness, and backoff schedules are injectable at component boundaries, and names
[docs/architecture.md](architecture.md) as its owner. **[docs/architecture.md](architecture.md)
§9 does not currently contain such an assumption or requirement**, and no ADR asserts it:
[ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.16 *depends* on it ("the
`uniform(0, T_REGION_SPREAD)` draw and the HRW hash must be seedable") without owning it. This
document records it as a **required interface on the architecture**:

> **L-3 (required of [docs/architecture.md](architecture.md)).** Every component that reads
> wall-clock time, monotonic time, a timer, or randomness MUST obtain it from an injected
> provider bound at construction. The production binding is the real clock and the OS CSPRNG;
> the lab binding is a virtual clock and a seeded stream. There MUST be no direct call to a
> platform time or random API outside the provider implementations, and this MUST be enforced
> mechanically (a lint/deny-list in the T1 tier, §6).

Until L-3 is stated by its owner, the honest position is: **levels 1–2 achieve `BIT`; levels 6
and above achieve `BIT` only for their event *sequence*, not for their timing**, because
`conntrack` timers, `netem`, and the kernel scheduler run on real time and are outside any
injected provider. Scenarios above level 2 therefore declare `BIT` for ordered event sequences
and `STATISTICAL` for every duration.

### 3.6 Specifying, running, and reproducing a scenario

A scenario is a declarative document under version control. Nothing about a run may live only in
an operator's shell history.

```toml
id            = "S-NAT-APDM-APDM-V4-01"     # grammar below
determinism   = "BIT"                        # §3.5
seed          = "9f1c…"                      # 128-bit hex; omitted = generated and recorded
tier          = ["T3"]                       # §6
assumptions   = ["A-01", "A-02", "A-14", "A-17"]
proves        = ["P02"]

[topology]
sites   = [ { id = "a", nat = "N-APDM-APDF-RAND", lifetime_s = 120, hairpin = false, portmap = "none" },
            { id = "b", nat = "N-APDM-APDF-SEQ",  lifetime_s = 30,  hairpin = false, portmap = "none" } ]
family  = "v4-only"                          # v4-only | v6-only | dual | nat64
relays  = { regions = 2, per_region = 2, domains_per_region = 2 }

[impairment]
"isp-a" = { delay_ms = 40, loss_pct = 1.0 }
"isp-b" = { delay_ms = 15 }

[[schedule]]                                  # timestamped, declared mid-run events (§3.4.1)
at_ms = 12000
action = "kill_relay"
target = "relay-r1"

[expect]
outcome_class = "RELAY_EXPECTED"              # §2.10
```

**Scenario ID grammar.** `S-<FAMILY>-<SUBJECT>-<VARIANT>-<NN>`, where `FAMILY` ∈ {`NAT`, `NET`,
`DNS`, `KS`, `RELAY`, `GW`, `AUTH`, `PROTO`, `CP`, `COLL`, `PERF`, `SOAK`}. IDs are permanent:
a retired scenario's ID is never reused, for the same reason a retired `reason_code` is not
([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 rule 2).

**The run record (normative).** Every run emits a signed, self-contained record binding the
result to an exact input set: the scenario document's content hash; the resolved `seed`; the
commit or immutable dirty-worktree snapshot of every binary in the rig, product and lab alike;
the kernel version and the `nft`/`tc` versions of every namespace; the §3.4.2 conformance
results for every simulator used; the complete structured event stream (A-02); the packet
captures per interface; and the pass/fail verdict per oracle. **A verdict not bound to a run
record is not a result.** Reproduction is `twinlab run --record <hash>`, which reconstructs the
topology, the impairments, the seed, and the binaries.

**Per-pair direct-success budgets (§2.10's reference).** For `DIRECT_POSSIBLE` pairs, the class
does not assert success on a single run; it asserts a rate over N runs at distinct seeds.

| Pair class | N | Minimum direct-path success rate | Rationale |
|---|---|---|---|
| Any pair where either end is `N-ROUTED` on IPv6 | 20 | **100 %** | `docs/networking.md` §3.2's last row is unqualified; a single failure is a defect |
| EIM×EIM (any filtering) over v4 | 20 | **100 %** | Simultaneous open is deterministic against EIF/ADF/APDF |
| EIM×APDM with `portmap = PCP` | 20 | ≥ 95 % | An explicit mapping should not fail; the 5 % covers PCP-daemon races |
| EIM×`N-APDM-APDF-SEQ`, no port mapping | 50 | ≥ 80 % | Delta prediction against a monotone allocator |
| EIM×`N-APDM-APDF-RAND`, no port mapping | 50 | ≥ 60 % | `k = 256` birthday prediction, 2 s budget (`docs/networking.md` §3.6) |
| APDM×APDM, CGNAT×CGNAT, CGNAT×APDM over v4 | 20 | **0 % expected; `RELAY_EXPECTED`** | Relay by design (N4). A `WAN_DIRECT` claim here fails the run as an emulator defect (**V10**) |

A budget breach is a **failure**, not a re-run. Budgets are revised only by changing this table
in a reviewed commit, never by a test author on the day.

### 3.7 Platform matrix — what runs in the lab and what does not

A network namespace runs a Linux kernel. iOS and Android do not, macOS and Windows do not, and
pretending otherwise is how platform defects reach users. TwinLab therefore has two rigs that
share **one** personality and impairment library.

| Target | Where it runs | Attachment to TwinLab | What it can prove | What it cannot |
|---|---|---|---|---|
| Linux desktop/server | Namespace | Native `veth` | Everything | Nothing OS-specific to other platforms |
| OpenWrt / router-class | Namespace (userspace datapath) + **real hardware** nightly | `veth`; hardware via a lab VLAN into a transit namespace | Headless operation, low memory, `fw4` rule set, no-persistent-storage operation (R-21) | Vendor-kernel quirks not in the reference image |
| Windows | VM (one per supported build) | `tap`/bridged NIC into a transit namespace | WFP sublayer install, BOOTTIME/PERSISTENT filters, adapter lifecycle, third-party AV coexistence | Anything requiring a physical NIC driver we do not ship |
| macOS | VM or hardware per supported version | Bridged NIC into a transit namespace | `pf` anchor, NetworkExtension lifecycle, Keychain, system-extension approval | Recovery/safe-boot behaviour (asserted by inspection, disclosed as untested — [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.6) |
| iOS | **Physical device farm only** | Device associates to a lab AP whose uplink *is* a middlebox namespace running the same personality library | NetworkExtension background lifecycle, `includeAllNetworks` behaviour, roam Wi-Fi↔cellular (with a lab cellular emulator or a real SIM on a controlled APN), the attach-to-arm window | **No host firewall exists**, so no deny counters — every leak oracle degrades to wire capture on a companion host (§4, **P09**) |
| Android | Physical device farm + emulators | As iOS; emulators attach via the emulator's tap into a transit namespace | VpnService lifecycle, lockdown/always-on interaction, Doze, per-app routing, StrongBox custody | Vendor ROM behaviours outside the enumerated matrix; emulator-only results MUST NOT satisfy a §2.8 platform gate |

**Rule L-4.** The NAT personality, impairment, and DNS-fault definitions are **one library** used
by both rigs. A condition may not exist in one rig only. Where a rig cannot produce a condition
(e.g. a seeded loss schedule on a real Wi-Fi link), the scenario declares `STATISTICAL` and says
so; it does not quietly substitute a different condition.

**Rule L-5 (V5).** Every scenario family MUST be instantiated for `v4-only`, `v6-only`, and
`dual`, and NAT64 where the personality supports it. A family with only a v4 instantiation fails
review.

---

## 4. The mandatory proof tests P01–P15

These fifteen tests, **together with the seven application-layer proof tests P16–P22 registered
in §4.3, are the acceptance criteria for the whole architecture** — **twenty-two** in total. They
are not a sample of the E2E suite; they are the enumeration of what composition must deliver. A
release that cannot show all **twenty-two** green, each with its mutant set demonstrably caught
and its positive control demonstrably green, has not been shown to be TwinVPN.

**The count is load-bearing.** P16–P22 are the sole PROOF-class evidence for **R-25 … R-49**
(§5.1b) — the entire application and platform requirement set. Any statement of the acceptance
set, the tier contents (§6.2) or the release blockers (§6.5) that names only fifteen leaves those
twenty-five requirements ungated, which is the defect this sentence exists to prevent.

**How to read a proof test.** Every one carries: what it *proves* (R-numbers from
[docs/vision.md](vision.md) §5 and I-numbers from §4.1); the TwinLab scenario family (§3); its
preconditions, which are themselves asserted (**V3**); a numbered procedure; an **oracle** stated
precisely enough that two engineers write the same assertion (**V1**, **V6**); a **mutant set**
— deliberately defective builds the test MUST fail against (**V2**); a **positive control**
proving the observation channel works at all (**V4**); pass criteria; and known limits.

**Rule PT-1 (V2 is a gate).** Each mutant is a real, buildable, version-controlled patch against
the release commit. The mutant run is part of the test, not a thought experiment: `P0N` is
`PASS` only if the clean build passes **and** every mutant in its set fails, each with the
expected oracle. A mutant that unexpectedly passes is a **defect in the test**, filed at the same
severity as a product defect.

**Rule PT-2 (V6 layering).** The primary oracle is the structured transition/`Diagnostic` event
stream (A-02, A-16). For every test that asserts a *security* property (P07–P14), an independent
wire-capture oracle MUST corroborate it, because a system reporting on itself is not sufficient
evidence for a security property.

**Rule PT-3 (naming).** All oracles key on `reason_code` values, never on human text (**V9**,
[ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 rule 4). Codes are written in
this section in [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2's canonical
`DOMAIN.SUBDOMAIN.CONDITION` form. Where a source document spells the same condition in the older
`NET_*` / `NAT_*` underscore form ([docs/networking.md](networking.md) §3.7,
[docs/reliability.md](reliability.md) §4.5), the registry is the tie-breaker and the underscore
spellings MUST be reconciled into it before these oracles can be mechanically evaluated.

### 4.1 Conformance-surface ownership

**Twelve** ADRs (and, for P04, [docs/reliability.md](reliability.md)) wrote a **conformance
surface** for a proof test: a named set of observables that document guarantees to expose, so the
test can be written against a mechanism rather than an intention. Nine wrote one in the first
pass; the remaining three — ADR-0004 §11.6 (P01), ADR-0003 §11.7 (P13) and reliability.md §4.5's
T20 cause code (P04) — were added to close **G-10**, and **every proof test now has one.**
**Rule PT-4: where a surface exists, this document consumes it verbatim and does not re-derive
it.** With G-10 closed a surface always exists, so PT-4 is now unconditional: **this document
re-derives no oracle.** A re-derived oracle that drifts from its ADR is a contradiction produced by this document,
and it is the failure mode this table exists to prevent.

| Test | Owning conformance surface | What it supplies |
|---|---|---|
| **P01** | [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md) §11.6 | `NAT.DIRECT_ESTABLISHED` / `NAT.DIRECT_UPGRADED` with `family`, `candidate_type`, `elapsed_ms`, `relay_gathered_at_ms`; the candidate ledger including losers; the **structural** parallelism assertion `relay_gathered_at_ms ≤ first_direct_probe_ms`; and the four catchable mutants |
| **P02** | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.16 | Injection (symmetric NAT both ends, no port mapping) + the three-part oracle: no user action, the full `RelaySelected{…}` event, and the [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §11.8 zero-control-plane-call assertion |
| **P03** | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.16 | The injection set, the six-clause oracle (a)–(f), and three variants (whole region; standby's domain too; control plane blackholed during failover) |
| **P04** | [docs/reliability.md](reliability.md) §4.5 T20 | `NET.PATH.DEAD_NO_ALTERNATE` (`TRANSIENT`) on entry to `RECONNECTING`, with the fault-specific cause in the `caused_by` evidence field — the discrimination `M-P04-5` injects against |
| **P05** | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.10 + §11.17 (A-01 confirmed for both directions) | The upgrade policy and the confirmation that P05's oracle "is sound as written" |
| **P06** | [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md) §11.16 | Twelve oracles with their falsifying builds, plus §11.11's metric names — `gw_peer_floor_share_bps` / `gw_peer_achieved_bps` are **designated the fairness oracle** |
| **P07** | [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.9 | The dual-family Tier-2 canary, `ruleset_digest`, and two named mutants |
| **P08** | [ADR-0011](adr/ADR-0011-dns-handling.md) §11.12 — **the strongest surface in the corpus** | A complete eight-row table: structured oracle, wire oracle both families, the V3 precondition, the V4 positive control (`mode = OFF`), and four mutants (two inherited from ADR-0012, two its own) |
| **P09** | [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.9 + §11.6 | The six durability events per platform, `ruleset_digest`, the OS-applied boot artifact (KS-19), three named mutants, and the honest platform-limitation table |
| **P10** | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7 | The `EpochSeed`/`TwinNetPSK` construction that makes exclusion structural, and the propagation-bound table |
| **P11** | [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) §7.1 (**T1–T5**) + §7.2 | Five named attacks with their per-alternative outcomes — T2 and T3 are the whole argument — and the three-layer detection stack with the code each layer yields |
| **P12** | [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) §11.9 (**N-30, N-31(1)–(5)**) | The five-clause refusal contract, verbatim |
| **P13** | [ADR-0003](adr/ADR-0003-network-contract-schema-format.md) §11.7 | The closed **twelve-entry parser inventory** `PI-1 … PI-12` mapped to §2.12 fuzz targets; the three-outcome decode contract and rule **PA-1**; the per-input observables (outcome class, `PROTO.*` code, parser id, verified-octet digest); and the T1 inventory/target check |
| **P14** | [ADR-0005](adr/ADR-0005-relay-architecture.md) §7.1 (mirrored in [docs/threat-model.md](threat-model.md) §8.1) | The **three-element key inventory** that converts P14 from a statistical observation into an enumeration |
| **P15** | [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §11.8 | A four-step proof — architectural, enumerative over §16's message rows, **mechanical** (a build-time dependency-graph assertion), and negative — plus [docs/architecture.md](architecture.md) §4.4.5's five clauses |

**Three tests once had no owning conformance surface and were authored here from first
principles.** That asymmetry — the weakest-supported tests being known rather than assumed equal —
is **now closed (G-10)**; all three surfaces exist and are consumed under PT-4. The table is kept
as the audit trail of what each was missing and where it landed, because the *shape* of the defect
recurs: a test written against its own construction drifts from the mechanism silently.

| Test | What was missing, and where it landed | What corroborates it |
|---|---|---|
| **P01** | *(closed)* ADR-0004 supplied **no conformance surface, no R-ID of its own for the direct-path outcome, and no `reason_code`** for "direct succeeded". **Now §11.6**, which adds `NAT.DIRECT_ESTABLISHED` / `NAT.DIRECT_UPGRADED` and binds the outcome to **R-01**/**R-12** — the requirement was never missing, its *observable* was | The surface above; §2.10's **`DIRECT_EXPECTED` outcome class** and [docs/networking.md](networking.md) §3.2/§3.6 remain as the class-level corroboration |
| **P04** | *(closed)* T20 historically emitted **no `reason_code`**, so entry into `RECONNECTING` had nothing to assert on beyond the state name. The amendment **has landed**: [docs/reliability.md](reliability.md) §4.5 T20 emits `NET.PATH.DEAD_NO_ALTERNATE` with the specific cause in `caused_by`. P04's oracle is no longer written against a pending change | The T20 cause code, plus A-16's `Diagnostic`-on-entry rule, PB-8's backoff bounds, and the seeded jitter stream of §3.5 |
| **P13** | *(closed)* ADR-0003 specified canonical encoding and rejection semantics but supplied **no fuzz conformance surface** and named no parser inventory, so the twelve-parser enumeration lived in P13 itself and could silently fall behind the code. **Now §11.7**, where the inventory is normative, closed, and checked at T1 | The surface above; §2.3's frozen `malformed/` and `hostile/` corpora and §2.12's twelve fuzz targets are consumed by it rather than substituting for it |

---

#### P01 — Direct tunnels work when the network permits

| | |
|---|---|
| **Proves** | R-01 (parallel traversal), R-02 (direct failure is not connection failure), R-12 (direct upgrade); standing rule P9 |
| **Lab scenario** | `S-NAT-*` across every ordered personality pair of §3.3 whose §3.6 class is `DIRECT_EXPECTED` or `DIRECT_POSSIBLE`, in `v4-only`, `v6-only`, and `dual`; plus `S-NAT-LOCAL-*` on one L2 segment |
| **Preconditions (V3)** | §3.4.2 conformance green for both personalities that day; both peers paired and `TrustedPeer` present on both; relays reachable (so that relaying is a *choice*, not the only option); a byte of application traffic actually traverses the tunnel |
| **Assumptions** | A-02, A-04, A-17 |

**Procedure.**
1. Instantiate the pair's personalities; run the §3.4.2 prober and record its verdict in the run record.
2. Start both agents. Issue `EV_CONNECT_REQUESTED` on A only.
3. Capture on every interface of both device namespaces and on both middleboxes.
4. Drive a bidirectional application flow (TCP stream + UDP datagram set) with a per-packet marker.
5. Hold for 120 s (past `T_HEARTBEAT_IDLE` and past the shortest configured mapping lifetime) and re-drive the flow.

**Oracle.**
- Terminal `ConnectionState` is `LOCAL_DIRECT` for same-L2 scenarios and `WAN_DIRECT` otherwise, reached within `T_CONNECT` (10 s, `docs/reliability.md` §5.1) — asserted from the transition-event stream, whose last transition is T08 or T09.
- On a `DIRECT_EXPECTED` pair, **`RELAYED` appearing as the terminal state is a failure**, per §2.10 — including a `RELAYED → MIGRATING → WAN_DIRECT` path that lands correctly but took longer than `T_CONNECT`, which is recorded as a separate `SLOW_DIRECT` finding.
- Wire corroboration: the marked application bytes appear **only** inside encapsulated frames on the direct 5-tuple; the relay namespace's per-flow counters show zero data frames for this `pair_tag`.
- The candidate ledger ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.8) records a `RELAY` candidate gathered from the first gathering round, not after direct failure (`docs/networking.md` §3.3 rule 1).
- Dual-stack pairs: the winning candidate is the IPv6 one whenever both validate, within the `T_HE_BIAS` = 250 ms window.

**Mutants (V2).**

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P01-1` | Relay candidate gathered only after direct-path timeout | Time-to-first-byte exceeds `T_RELAY_FIRST_TRAFFIC` on relay pairs; ledger shows serial gathering |
| `M-P01-2` | Candidate racing serialized (one pair at a time) | `DIRECT_POSSIBLE` budgets in §3.6 breached; `T_CONNECT` expiries appear |
| `M-P01-3` | IPv6 candidates deprioritized below IPv4 | Dual-stack scenarios select v4; the `T_HE_BIAS` assertion fails |
| `M-P01-4` | NAT keepalive fixed at 300 s | The 120 s re-drive fails on the 30 s-lifetime personality with a `NAT.*` code |

**Positive control (V4).** The same rig, same seed, with both personalities set to `N-ROUTED`
must reach `WAN_DIRECT` in every run — proving the rig can observe success at all before any
`RELAY_EXPECTED` negative result is believed.

**Pass criteria.** Every `DIRECT_EXPECTED` pair reaches its expected state in 20/20 runs; every
`DIRECT_POSSIBLE` pair meets its §3.6 rate; all four mutants fail; all three families pass.

**Known limits.** The lab's personalities are a model of real middleboxes, not a census.
A field measurement programme (`docs/networking.md` §3.1's measured axes) is the only thing that
validates the *distribution*; P01 validates the *behaviour* per class.

---

#### P02 — Relays are selected automatically when required

| | |
|---|---|
| **Proves** | R-02, R-18 (blocked-UDP fallback), R-11; supports I5 |
| **Lab scenario** | `S-NAT-APDM-APDM-V4-*` and `S-NAT-CGNAT-CGNAT-V4-*` (relay by design); `S-NET-UDPBLOCKED-*` and `S-NET-443ONLY-*` (transport ladder) |
| **Preconditions (V3)** | ≥ 2 relays in ≥ 2 `failure_domain`s per region ([ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.1 rule 3); the direct path is genuinely impossible, proven by the §3.4.2 prober, not assumed |
| **Assumptions** | A-17, A-18, A-13 |

**Procedure.**
1. Configure both ends `N-APDM-APDF` with `portmap = none` and `hairpin = off`; or, for the transport-ladder variants, apply the blocked-UDP / 443-only egress filter.
2. Start both agents; connect; drive an application flow.
3. Assert **no user action** occurred: no prompt, no retry button, no config change between request and traffic.
4. Repeat with the control plane blackholed from t=0 to test the cached-set path.

**Oracle.**
- Terminal state `RELAYED`, reached with no user interaction, with first application byte within `T_RELAY_FIRST_TRAFFIC` (300 ms target) of `EV_CONNECT_REQUESTED` when the relay session is warm.
- A `RelaySelected{session_id, relay_id, region, failure_domain, score, rank, top_k[], map_version, map_age_ms, inputs{measured_rtt_ms, server_rank, health, load_class, breaker_state}}` event is emitted — selection is auditable, not a black box ([ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.16).
- The control-plane dependency assertion ([ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §11.8) shows **zero** control-plane calls on the establishment path in the blackholed variant.
- Transport-ladder variants: the ladder's per-step results are individually observable (`NAT.UDP_BLOCKED` then success on the TCP/TLS step), and the selected carriage is recorded (A-17).
- Wire corroboration: frames appear on the relay's 5-tuple only; no direct 5-tuple carries data.

**Mutants (V2).**

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P02-1` | Relay fallback gated behind a user prompt | "No user action" assertion fails |
| `M-P02-2` | Relay set reduced to one entry at the edge | Precondition assertion fails; §11.1 rule 3 violated |
| `M-P02-3` | Relay selection requires a live control-plane call | Blackholed variant never reaches `RELAYED`; I5 violated |
| `M-P02-4` | Transport ladder stops after UDP:443 | `S-NET-UDPBLOCKED-*` fails to connect; R-18 unmet |
| `M-P02-5` | `RelaySelected` omitted or lacking `top_k[]` | Auditability oracle fails (R-23) |

**Positive control (V4).** The same scenario with `N-EIM-APDF` at one end must reach
`WAN_DIRECT`, proving the rig can produce a direct path and that `RELAYED` here is caused by the
NAT class and not by a broken rig.

**Pass criteria.** `RELAYED` in 20/20 runs per scenario; `RelaySelected` complete in every run;
zero control-plane calls in the blackholed variant; all mutants fail.

**Known limits.** P02 proves selection happens and is auditable. Whether the *ranking* is good is
a performance question (§2.16), not a correctness one.

---

#### P03 — Relay failure triggers automatic failover

| | |
|---|---|
| **Proves** | R-10, R-11; I5 |
| **Lab scenario** | `S-RELAY-KILL-*` (four failure modes of §3.4: hard kill, hang, blackhole, grey stall), `S-RELAY-REGION-*`, and `S-RELAY-DRAIN-*` |
| **Preconditions (V3)** | `RELAYED` sustained past `T_STANDBY_WARM` (30 s) so a warm standby in a different `failure_domain` exists; an application flow is actually in progress, including an in-flight inner TCP connection |
| **Assumptions** | **A-01**, A-02, A-04, A-18 |

**Procedure.**
1. Establish `RELAYED` between A and B through `relay-r1` (region EU, domain d1). Verify the standby is bound on `relay-r2` (domain d2).
2. Start a long-lived inner TCP stream plus a marked UDP flow; wait ≥ `T_STANDBY_WARM`.
3. At a scheduled `at_ms`, apply one failure mode to `relay-r1`.
4. Record every transition event, every `RELAY.*` code, and both packet captures until traffic resumes.
5. Repeat for each of the four failure modes; then for the whole-region variant; then with the control plane blackholed throughout.

**Oracle (exact).**
- The transition sequence is **exactly** `RELAYED → MIGRATING → RELAYED`. The event stream MUST contain no `DISCONNECTED` and no `RECONNECTING` entry between them (A-01, [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.5 rule 1).
- `session_id` is **unchanged** across the whole sequence, in every emitted event.
- **Tunnel key state is preserved**: no `CRYPTO.*` handshake event of any kind occurs — no `EV_HANDSHAKE_OK`, no rekey, no `CRYPTO.HANDSHAKE_REJECTED`. The absence is asserted over the window, not merely "not observed in the log tail".
- The in-flight inner TCP connection survives: the same 4-tuple continues, sequence numbers advance monotonically, and no RST is seen at either endpoint.
- `RELAY.FAILOVER.COMPLETED` carries `from`, `to`, and `onset_to_traffic_ms`; `to.failure_domain ≠ from.failure_domain`.
- Onset→first-byte is within [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §9.4's budget for the detection class that fired, with `T_FAILOVER_TARGET` = 300 ms as the warm-standby design target.
- Region variant additionally asserts the `uniform(0, T_REGION_SPREAD)` split jitter and HRW spread of §11.7 — seeded, so the draw is reproducible.
- Control-plane-blackholed variant asserts zero control-plane calls throughout (architecture §4.4.5(c)).

**Mutants (V2).**

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P03-1` | Failover implemented as teardown + reconnect | `DISCONNECTED`/`RECONNECTING` appears; `session_id` changes |
| `M-P03-2` | Tunnel rekeyed on relay change | A `CRYPTO.*` handshake event appears |
| `M-P03-3` | Standby selected in the same `failure_domain` | Region variant loses both relays; `to.failure_domain == from.failure_domain` |
| `M-P03-4` | Only hard failure detected (grey stall ignored) | The accept-then-stall mode never triggers failover; traffic stops with no state change |
| `M-P03-5` | Failover requires a relay-selection-service call | Blackholed variant fails; I5 violated |

**Positive control (V4).** With `relay-r2` also removed from the map, the same injection MUST
produce an observable failure (`RELAY.FAILOVER_EXHAUSTED` → `RECONNECTING`/`BLOCKED`) — proving
the rig can observe failover *failing*, so a clean pass is evidence rather than inertness.

**Pass criteria.** All four failure modes, both families, 20/20 runs, exact sequence and
`session_id` stability in every one; all five mutants fail.

**Known limits.** The 300 ms target is a design target for a *warm* standby; the cold-standby
path is bounded by [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §9.4's slower class
and is asserted against that class, not against 300 ms.

---

#### P04 — Connection loss triggers automatic reconnection

| | |
|---|---|
| **Proves** | R-06, R-05, R-09; I6 |
| **Lab scenario** | `S-NET-PARTITION-*` (symmetric and asymmetric), `S-NET-LINKDOWN-*`, `S-KS-AGENTKILL-*`, `S-CP-BLACKHOLE-*` |
| **Preconditions (V3)** | An established steady state with traffic flowing; a durable `Endpoint` cache (S-15) and `TrustedPeer` (S-05) present on disk before the fault |
| **Assumptions** | A-02, A-04, A-13 |

**Procedure.**
1. Establish `WAN_DIRECT`; drive traffic; snapshot the on-disk `Endpoint` cache.
2. Apply, as separate runs: (a) a 60 s symmetric partition; (b) `EV_LINK_DOWN` by downing the device's `veth`; (c) `SIGKILL` of the agent followed by supervisor restart; (d) a namespace reboot; (e) the control plane blackholed for the entire run.
3. Remove the fault; do **not** touch the UI, the CLI, or any configuration.
4. Observe until steady state returns or a terminal state is reached.

**Oracle.**
- Recovery is unattended: the transition path is `… → RECONNECTING → (LOCAL_DIRECT|WAN_DIRECT|RELAYED)` (T20 then T25) with no `EV_CONNECT_REQUESTED` from a user source in the event stream.
- `NET.SESSION.RECOVERED` (T25) carries the measured outage duration.
- Backoff between attempts is monotone within its class, jittered, and bounded by the ceiling and floor of `docs/reliability.md` §6.1 — asserted from attempt timestamps against the seeded jitter stream (§3.5), which makes the schedule exactly checkable rather than approximately.
- **The T20 cause code is the primary oracle, and it is fault-specific.** Entry into `RECONNECTING` via T20 (`EV_PATH_DEAD` ∨ `EV_LINK_DOWN`, no alternate) MUST carry a `Diagnostic` whose `reason_code` is `NET.PATH.DEAD_NO_ALTERNATE` and whose **`caused_by` evidence field names the cause**, per `docs/reliability.md` T20: `NET.LINK.DOWN_WIFI` for variant (b), a `NET.*`/`NAT.*` path-death code for (a), and the restart/reboot path's own code for (c)/(d). A generic "reconnecting" code, or a `Diagnostic` with no code at all, is `INTERNAL.INVARIANT_VIOLATED` and fails the run (A-16, [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.6(3)). The oracle asserts `reason_code = NET.PATH.DEAD_NO_ALTERNATE` on every variant **and** asserts that `caused_by` differs across the four — a single state code with the cause in evidence is what T20 mandates, and asserting four different `reason_code`s would fail every conforming build — a build that names every path death identically has satisfied A-16's letter and defeated R-22's purpose. **Dependency:** this oracle is written against the amendment adding a cause code to [docs/reliability.md](reliability.md) T20; until that lands, P04's primary oracle is unavailable and the test degrades to a state-sequence assertion (§4.1).
- In variants (c) and (d), reconnection uses the **cached** `Endpoint`/`TrustedPeer` state with zero control-plane calls (architecture §4.4.5(d)).
- Under `FAIL_CLOSED`, no protected byte egresses at any point in the outage — corroborated on the wire, which links P04 to P09's oracle set.

**Mutants (V2).**

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P04-1` | Reconnect requires user action after N attempts | Unattended assertion fails |
| `M-P04-2` | Backoff without jitter | Attempt timestamps are exactly periodic; herd behaviour visible with 16 devices |
| `M-P04-3` | `Endpoint` cache not persisted | Variants (c)/(d) require the control plane; blackholed variant never recovers |
| `M-P04-4` | `RECONNECTING` entered without a `Diagnostic` | A-16 assertion fails |
| `M-P04-5` | T20 omits the `caused_by` evidence field, or emits the same `caused_by` for all four variants | The discrimination assertion fails; R-22 unmet even though A-16 is satisfied, because a single state code without the cause in evidence cannot tell a user *why* the path died |

**Positive control (V4).** A variant with the fault **not** removed must reach `BLOCKED` (T26,
`FAIL_CLOSED`) or `FAILED` (T27, `PERMISSIVE_ANNOUNCED`) with a terminal `reason_code`, proving
the rig observes non-recovery and that a pass is not a hang mistaken for health.

**Pass criteria.** All five fault variants recover unattended in 20/20 runs; backoff conforms;
every bad-state entry carries a code; all mutants fail.

**Known limits.** P04 does not bound recovery *time* beyond the `docs/reliability.md` §5.3
timers; recovery-time distribution is a §2.16 performance concern.

---

#### P05 — Path migration does not unnecessarily terminate sessions

| | |
|---|---|
| **Proves** | R-05, R-07, R-12; I5 |
| **Lab scenario** | `S-NET-ROAM-*` (Wi-Fi→cellular bridge move, address change, cross-family v4→v6-only), `S-RELAY-UPGRADE-*` (`RELAYED → WAN_DIRECT`), `S-NAT-REBIND-*` (mapping expiry mid-session) |
| **Preconditions (V3)** | Established steady state with an in-flight inner TCP connection and a marked UDP flow; for the upgrade variant, a direct path that becomes possible only after establishment |
| **Assumptions** | **A-01**, A-02, A-04 |

**Procedure.**
1. Establish the carrier state (`WAN_DIRECT` for roam variants, `RELAYED` for the upgrade variant).
2. Start an inner TCP stream and a marked UDP flow; record `session_id` and the tunnel key generation.
3. Apply the migration trigger: move the `veth` leg to the other access bridge and re-address (roam); or remove the NAT personality's port-mapping block so hole punching now succeeds (upgrade); or expire the NAT mapping (rebind).
4. Continue driving traffic throughout; do not pause the flow.

**Oracle (exact).**
- Roam / rebind: the sequence is `WAN_DIRECT → MIGRATING → WAN_DIRECT` (T21 then T15). Upgrade: **exactly** `RELAYED → MIGRATING → WAN_DIRECT` (T13 then T15). Neither passes through `DISCONNECTED` or `RECONNECTING` (A-01).
- `session_id` **unchanged** in every event across the sequence.
- **Tunnel key state preserved**: no `CRYPTO.*` handshake event; the tunnel key generation counter is identical before and after.
- The inner TCP connection survives with no RST and monotone sequence progression; UDP marker loss during the cutover is within `T_MIGRATE_QUEUE` (100 ms / 64 packets, drop-oldest).
- `NET.PATH.MIGRATED` (T15) carries `from`, `to`, and the measured deltas; inner v4 and v6 addresses are unchanged.
- Make-before-break is observable: while the old path is alive, both 5-tuples carry frames (`TUNNELED_DUAL`) before the old is released; the new path is not committed until `EV_PATH_VALIDATED`.
- Cross-family roam (v4-only → v6-only underlay) succeeds with the same assertions — a v4-only migration path is a **V5** failure.

**Mutants (V2).**

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P05-1` | Address change triggers teardown + reconnect | `DISCONNECTED`/`RECONNECTING` appears; `session_id` changes; TCP resets |
| `M-P05-2` | Migration commits before path validation | Traffic is emitted on an unvalidated path; the black-hole roam variant loses the session |
| `M-P05-3` | Break-before-make (old path released first) | Loss exceeds the `T_MIGRATE_QUEUE` bound even when the old path was alive |
| `M-P05-4` | Re-handshake on migration | A `CRYPTO.*` handshake event appears |
| `M-P05-5` | Upgrade path implemented as reconnect-as-direct | The upgrade variant shows `RELAYED → RECONNECTING → WAN_DIRECT` |

**Positive control (V4).** A variant in which the new path is genuinely unusable (destination
blackholed after the move) MUST produce `NET.PATH.MIGRATION_ABORTED` (T16, old path alive) or
`NET.PATH.MIGRATION_FAILED` → `RECONNECTING` (T17, old path dead) — proving the rig observes
migration failure.

**Pass criteria.** All variants, both families and the cross-family case, 20/20 runs, exact
sequences and `session_id`/key-state stability in every one; all mutants fail.

**Known limits.** Real mobile roams involve radio-layer behaviour (dormancy, IP retention across
handover) the lab approximates. The iOS/Android device rig (§3.7) is the authority for roam
timing; the namespace rig is the authority for the *state sequence*.

---

#### P06 — Multiple clients can use one gateway

| | |
|---|---|
| **Proves** | R-16, R-03, R-21; **I7** |
| **Lab scenario** | `S-GW-MULTI-*` with 16 peers (the MG-14 floor) on one `LANGateway`, and a 64-peer herd variant on a G1-class gateway |
| **Preconditions (V3)** | 16 distinct paired devices, each with a distinct `DeviceIdentity`; the gateway's overlay interface count observed **before** the test (must be one); a full packet capture running on `twin0` |
| **Assumptions** | A-10, A-11 |

**Procedure.**
1. Bring up the gateway with LAN routes and per-peer `AccessPolicy` differing between peers.
2. Admit all 16 peers; drive traffic from all 16 within one 1 s window.
3. Run the isolation, anti-spoofing, per-peer-policy, accounting, fairness, and quota probes of [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md) §11.16.
4. Revoke one peer's grant via `PolicyBundleUpdated` while its traffic is in flight.
5. Restart the gateway; observe re-addressing and reconnection with the control plane blackholed.
6. Repeat the whole set independently for IPv4 and for IPv6 (G9).

**Oracle.** Adopted verbatim from [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md)
§11.16, which was written to be this test's conformance surface:
- **Concurrency**: `gw_admitted_peers = 16`, all passing traffic in the same 1 s window.
- **Addressing (A-10)**: each peer's observed overlay source at the gateway equals the contract `/32` and the [ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md) §11.1 `/128` derivation; **no DHCP/DHCPv6/SLAAC frame appears on `twin0`** in the full capture (R-03).
- **Single interface (A-11)**: exactly one overlay interface for all N peers.
- **Isolation**: A→B overlay traffic is dropped, `gw_peer_drops{reason=POLICY.GATEWAY.PEER_TRANSIT_DENIED}` increments for A, and B's interface counters do not move.
- **Anti-spoofing**: a frame on A's tunnel bearing B's overlay source is dropped, `gw_peer_spoof_drops{peer=A}` increments, `POLICY.GATEWAY.SOURCE_SPOOFED` emitted.
- **Per-peer policy**: revoking A's grant stops A's *in-flight* traffic within 1 s of `PolicyBundleUpdated`.
- **Accounting**: `gw_peer_bytes` per peer sums to the gateway total within 1 %; every drop is attributed to a peer.
- **Fairness**: the designated oracle is the metric pair [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md) §11.11 names for it — **`gw_peer_floor_share_bps` and `gw_peer_achieved_bps`**, per peer. With A saturating the uplink and B starting cold, the assertion is `gw_peer_achieved_bps(B) ≥ gw_peer_floor_share_bps(B)` sustained, reached within 100 ms; `gw_peer_floor_violation_ms` p99 < 100 ms is the *latency* half of the same oracle (MG-10's bound). Asserting only the histogram would pass a build that meets the deadline while never actually granting B its floor share.
- **Quota isolation**: A exhausting its conntrack cap yields `RESOURCE.QUOTA.CONNTRACK_EXHAUSTED` for A while B's new flows still succeed.
- **Restart determinism**: every peer returns to the *same* overlay addresses with no control-plane involvement; forwarded TCP flows are observed to **break** — asserted as the honest expectation of §11.8.3, not hoped away.
- **Herd**: 64 simultaneous reconnects each either admitted or given `RESOURCE.ADMISSION.DEFERRED`; none times out silently.

**Mutants (V2).**

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P06-1` | Peers serialized / queued | Concurrency oracle fails |
| `M-P06-2` | Per-peer interfaces | Single-interface oracle fails |
| `M-P06-3` | Inter-peer transit open by default | Isolation oracle fails |
| `M-P06-4` | Inner source header trusted | Anti-spoofing oracle fails |
| `M-P06-5` | Single global counter set | Accounting attribution fails |
| `M-P06-6` | Shared FIFO scheduler | Fairness p99 breached by the noisy neighbour |
| `M-P06-7` | Shared conntrack table | B's flows fail when A exhausts quota |
| `M-P06-8` | Addresses leased rather than derived | DHCP frames appear on `twin0`; restart renumbers |
| `M-P06-9` | Policy evaluated at connect time only | In-flight revocation does not take effect |

**Positive control (V4).** A deliberately mis-scoped policy that *should* permit A→B transit
must show the packet arriving and the counters moving — proving the isolation oracle can observe
transit at all, so its absence in the clean run is evidence.

**Pass criteria.** All twelve oracles green for v4 and v6 independently; all nine mutants fail.

**Known limits.** 16 peers is the floor, not the ceiling; the scale curve to the declared peer
limit is a §2.16 performance measurement. Forwarded TCP flow breakage on gateway restart is a
**declared** behaviour, asserted here so that a future claim of flow survival must change this
test first.

---

#### P07 — IPv6 cannot bypass tunnel policy

| | |
|---|---|
| **Proves** | R-14; **I3**; standing rule P9 |
| **Lab scenario** | `S-KS-V6BYPASS-*`: (a) dual-stack from t=0; (b) IPv6 enabled *after* the tunnel is up via a new RA; (c) a new interface appearing mid-session (tethering / VM bridge); (d) an IPv4-only tunnel on an IPv6-capable host; (e) an `ExitNode` granting only one family |
| **Preconditions (V3)** | Kill switch armed (`FAIL_CLOSED`); a `ProtectionAssertion` confirming the intended rule set is installed **for both families** (KS-18(b)); the lab has a reachable off-tunnel IPv6 destination, so a leak is physically possible |
| **Assumptions** | A-08, A-02 |

**Procedure.**
1. Arm enforcement; establish the tunnel; record the `ruleset_digest` ([ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.13).
2. From a non-exempt socket in the protected scope, emit uniquely marked IPv6 datagrams to an off-tunnel destination.
3. Trigger each variant: send an RA advertising a new prefix; attach a new `veth`/bridge; start tethering; negotiate a v4-only tunnel; grant only v4 on the `ExitNode`.
4. Repeat the marked emission after each trigger, without waiting for any re-assertion tick.
5. Capture on **every** non-overlay interface, both families, for the whole run.

**Oracle.** Matched to what [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.9
claims to satisfy:
- The enforcement layer's **IPv6 deny counter increments** for each marked datagram, on each interface — the leak canary's own mechanism (§11.9, K12).
- **No marked byte appears on any non-overlay interface** in the wire capture (v6 *and* v4), which is the V6-corroborating oracle.
- For variants (b) and (c), the `ruleset_digest` is **unchanged** across the trigger: the new interface or prefix is denied by the *pre-existing* interface-scoped default-deny rule with no rule update required for correctness ([ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.3 row 3). A digest change here means the design's structural claim is false even if no packet leaked.
- Variants (d) and (e) enter `DEGRADED` (never a silent success) and emit `POLICY.LEAK.IPV6_UNPROTECTED` or `POLICY.LEAK.FAMILY_GRANT_MISSING` **naming the uncovered family** (KS-6, KS-8).
- Any observed egress raises `POLICY.LEAK.EGRESS_OBSERVED` at `CRITICAL` and drives T29 → `BLOCKED`; the test asserts that path fires, not merely that a log line exists.

**Mutants (V2).** [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.9 names the
first two; the rest are this document's.

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P07-1` | Tier-2 object omits the v6 filter | v6 deny counter never increments; marked bytes appear on the wire |
| `M-P07-2` | Tier 1 prefix-enumerated rather than complement-form in full-tunnel mode | A destination outside the enumeration leaks |
| `M-P07-3` | Rules are destination-prefix allow-lists rather than interface-scoped | Variants (b)/(c) leak until the 1 s re-assertion, and the `ruleset_digest` changes |
| `M-P07-4` | v4-only tunnel leaves v6 open instead of blocking (`DEGRADED` suppressed) | Variant (d) leaks and reports connected |
| `M-P07-5` | Absent per-family grant treated as permission | Variant (e) leaks; KS-8 violated |

**Positive control (V4).** The identical rig, identical seed, with enforcement `mode = OFF`
MUST observe the marked IPv6 bytes on the underlay interface. Without this the negative result is
not evidence — it is indistinguishable from a rig that cannot see IPv6 at all.

**Pass criteria.** Zero marked bytes off-tunnel in all five variants; deny counters increment in
all; `ruleset_digest` stable in (b)/(c); correct code with the named family in (d)/(e); all five
mutants fail; positive control green in the same session.

**Known limits.** Bounded by the platform table of
[ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.6, not by the rule design.
Platform-mandated exempt traffic (`POLICY.EXEMPT.PLATFORM_MANDATED`) is enumerated and excluded
from the assertion by identity, never by a wildcard.

---

#### P08 — DNS cannot bypass tunnel policy

| | |
|---|---|
| **Proves** | R-14; **I3** |
| **Lab scenario** | `S-DNS-BYPASS-*`: DHCP-supplied resolver present and reachable; a host-configured DoH endpoint; an application with an embedded resolver; Android strict Private DNS; Windows SMHNR parallel resolution; a captive-portal window followed by protected resolution; `mode = OFF` control |
| **Preconditions (V3)** | Armed enforcement; the **positive canary** answers, proving the host resolver actually reached our stub — a pass on an inert resolver is thereby impossible ([ADR-0011](adr/ADR-0011-dns-handling.md) §11.12); a reachable off-tunnel resolver exists in the lab |
| **Assumptions** | A-09, A-08 |

**Procedure.**
1. Arm enforcement; establish; confirm the positive canary `canary-<nonce>.<twinnet-label>.tnet.twinvpn.net` answers through the **host resolver API** with the per-boot authoritative marker.
2. Emit the **negative canary** — a query whose only possible answerer is off-tunnel — from a non-exempt socket in the protected scope, A and AAAA.
3. Repeat via each bypass channel: direct UDP/TCP 53 to the DHCP resolver, TCP 853, the known-DoH endpoint list, an app-embedded resolver, and the platform channels of [ADR-0011](adr/ADR-0011-dns-handling.md) §11.9.
4. Drive the captive-portal variant: authenticate through a portal exemption, then issue a protected-scope query for a name answered during the portal window.
5. Capture on every non-overlay interface for UDP/TCP 53, TCP 853, and the DoH endpoint list, **both families**.

**Oracle.** Matched to [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.9's P08
row and supplied in detail by [ADR-0011](adr/ADR-0011-dns-handling.md) §11.12:
- **Structured (primary)**: the negative canary's deny counter increments; absence of increment is `DNS.LEAK.QUERY_OBSERVED_OFF_TUNNEL` at `CRITICAL` driving T29. `POLICY.LEAK.DNS_UNPROTECTED` is the ADR-0012-side code; `DNS.STUB.CONFIG_REVERTED` and `DNS.RESOLUTION.BLOCKED_FAIL_CLOSED` are the stub-side ones.
- **Wire (corroborating)**: zero query bytes on any non-overlay interface for 53/853/DoH, both families.
- Protected-scope queries with no authorized secure path return **typed failures** — SERVFAIL + EDE 15 (`DNS.RESOLUTION.BLOCKED_FAIL_CLOSED`) — never a fallback answer and never a timeout.
- Portal variant: the protected-scope query does **not** receive the portal-window answer; `DNS.LEAK.PORTAL_ANSWER_QUARANTINED` is emitted (KS-16 held), and the caches are separately assertable.
- AAAA is asserted with the same rigor as A (**V5**, [ADR-0011](adr/ADR-0011-dns-handling.md) §11.6); an A-only pass fails review.

**Mutants (V2).** The first two are named by
[ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.9; the last two by
[ADR-0011](adr/ADR-0011-dns-handling.md) §11.12.

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P08-1` | Egress permitted to the DHCP-supplied resolver while armed | Negative canary counter does not increment; queries appear on the wire |
| `M-P08-2` | Portal-window answers cached into protected resolution | Portal variant serves a `portal`-scope answer to a `protected`-scope query (DN-1 violated) |
| `M-P08-3` | Falls back to the host resolver on stub failure | DN-10 clause 1 violated; off-tunnel query observed |
| `M-P08-4` | Containment covers v4 only | AAAA canary leaks; **V5** failure |

**Positive control (V4).** The same rig with `mode = OFF` MUST observe the off-tunnel query.
Additionally, the **positive canary** is itself the V3 precondition control: it proves the host
resolver reaches the stub, so an inert-resolver pass is impossible.

**Pass criteria.** Zero off-tunnel query bytes on every channel and both families; typed
failures where fail-closed applies; portal quarantine held; all four mutants fail; both controls
green.

**Known limits.** An application shipping its own resolver and its own encrypted transport to a
destination on the DoH list is *contained* (its packets are dropped) but not *steered*
(`DNS.PLATFORM.APP_EMBEDDED_RESOLVER_SUSPECTED`). A resolver contacting an endpoint not on the
known-DoH list over 443 is indistinguishable from ordinary HTTPS at the packet filter; that
traffic is nevertheless protected-scope and dropped by Tier 2, so the leak channel is closed by
P07's mechanism even though P08's DoH-specific oracle cannot name it.

---

#### P09 — Kill-switch mode fails closed

| | |
|---|---|
| **Proves** | R-13, R-08, R-14; **I3** |
| **Lab scenario** | `S-KS-CRASH-*`, `S-KS-SIGKILL-*`, `S-KS-UPDATE-*`, `S-KS-REBOOT-*` — **four separate procedures**, run per platform of §3.7 |
| **Preconditions (V3)** | Enforcement armed and confirmed by a `ProtectionAssertion` for both families; `ruleset_digest` recorded; a reachable off-tunnel destination in the lab; a marked traffic generator running **independently of the agent**, so it keeps emitting while the agent is dead |
| **Assumptions** | **A-08**, A-02, A-16 |

The four events are separate procedures because they exercise different mechanisms
([ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.6): crash and `SIGKILL` test
kernel residency, update tests atomic swap (KS-23), reboot tests the OS-applied boot artifact
(KS-19).

**Procedure A — crash.** Establish; start the independent marked generator; induce an in-process
abort (SIGSEGV via a fault-injection hook at a declared point, one point per run); observe until
the supervisor restarts the agent and re-arms.

**Procedure B — `kill -9`.** As A, but `SIGKILL` the agent so no handler runs at all. Additionally
hold the agent down for 60 s before allowing restart, so the "no process, marked traffic offered"
window is long and unambiguous.

**Procedure C — agent update.** As A, but run the real update path (installer/updater replacing
the binary and the rule artifact) while traffic is offered. Also run the **interrupted** variant:
kill the updater mid-write (§2.15).

**Procedure D — reboot.** As A, but reboot the namespace/VM/device. The marked generator is
configured to start **before** the agent at boot, so it emits into the window between the network
stack coming up and the agent starting — the window KS-19 exists to cover.

**Oracle.**
- **Zero marked bytes** reach any non-overlay interface at any instant of any procedure, both families — the wire oracle, taken on a capture that runs across the whole event including the dead-agent window.
- The enforcement layer's **deny counters increment** for the marked datagrams throughout the window in which the agent is absent, proving the rule set is still doing work and not merely present.
- `ruleset_digest` after the event equals the digest before it ([ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.9), asserting the *same* rule set — not merely *a* rule set — survived.
- Procedure C additionally asserts an **atomic swap**: at no sampling instant (1 ms polling of the rule set) is the rule set absent or partial. A remove-then-add is detectable as a sampled gap and fails.
- Procedure D asserts the boot rule set was applied by the **OS artifact**, not the agent: the deny counters are non-zero *before* the agent's first structured event of the boot.
- On restart, the protection indicator is never `PROTECTED` on stale evidence: a `ProtectionAssertion` older than its freshness window renders `UNKNOWN` ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.6(2), O-18).
- `POLICY.KILLSWITCH.ENGAGED` is the standing reason during the window; if arming fails at any point, `POLICY.KILLSWITCH.ARM_FAILED` is emitted and the client refuses to enter a protected state (never fails open).

**Platform degradation of the oracle — a known defect, stated rather than papered over.**
[ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.14 confirmed **A-08 only in
qualified form** (guaranteed on Linux, Windows, macOS-running, Android-with-lockdown and OpenWrt;
qualified on iOS and Android-without-lockdown) and directs that "P09 must therefore assert the
guarantee where it is claimed and *measure* the window where it is not, rather than testing a
happy path". The table below is that instruction executed. **Rule PT-5: P09 MUST NOT assert a
counter that does not exist on the platform under test**, and a platform whose row says "measured
window" contributes a **number** to the release record, never a pass.

| Platform | Oracle available | Consequence |
|---|---|---|
| Linux, Windows, macOS, OpenWrt | Deny counters **and** wire capture | Full oracle as above |
| Android | Lockdown is OS-enforced; per-app counters are not ours | Counter oracle degrades to the platform's own VPN-lockdown state plus wire capture on a companion host; lockdown posture is asserted as a precondition, and an un-lockdown'd device is reported as **unprotected**, not as a passing configuration |
| **iOS** | **None.** There is no host firewall on iOS and therefore **no deny counter to assert on** ([ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.6 limitation table) | **P09's oracle on iOS degrades to a wire-capture oracle taken on a companion host** — the lab AP's uplink namespace (§3.7) captures every packet the device emits, and the assertion is "no marked byte crossed the AP". There is no boot enforcement, so Procedure D does not assert zero-leak; it **measures the attach-to-arm window** and reports it as a number, per §11.6. Procedure C reduces to profile-removal behaviour, which removes enforcement by design |

**Mutants (V2).** All three are named by
[ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.9.

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P09-1` | Enforcement is process-resident (E4) | Procedures A, B and D leak the instant the process is gone |
| `M-P09-2` | Boot rule set installed by the agent rather than the OS artifact | Procedure D leaks in the pre-agent window; deny counters are zero before the agent's first event |
| `M-P09-3` | Update path removes-then-adds instead of swapping atomically (KS-23) | Procedure C shows a sampled gap; the interrupted variant leaves no rule set at all |

**Positive control (V4).** Every procedure is run once with `mode = OFF` on the same rig and the
same seed, and MUST observe the marked bytes on the underlay. On iOS this control runs on the
companion-host capture, which is what makes the degraded oracle admissible evidence rather than
an absence.

**Pass criteria.** All four procedures × all supported platforms × both families: zero marked
bytes (except where the platform row above declares a measured window instead); digest stable;
atomic swap held; all three mutants fail; positive controls green.

**Known limits.** macOS Recovery, Linux single-user, and Android safe mode bypass enforcement and
are **not** tested — they are disclosed in
[ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.6 and asserted here only by
inspection of the mechanism. An `Owner` with local admin can always disarm (KS-21); that path is
asserted to emit `POLICY.KILLSWITCH.DISARMED_BY_OWNER` and to be unreachable from any network
actor (see P10's control-plane variant and KS-22).

---

#### P10 — Revoked devices cannot reconnect

| | |
|---|---|
| **Proves** | I4 (custody is the basis of exclusion), I8 (S-03 single writer); threat-model rows **TM-02** and **TM-29**. **R-24** ([docs/vision.md](vision.md) §5.4) is the owning requirement — an earlier draft recorded that no R-number covered revocation; that is superseded, and G-6 is closed. Formerly a gap in §5 |
| **Lab scenario** | `S-AUTH-REVOKE-*`: (a) control plane reachable by all; (b) revoked device online, victim peer offline from the control plane but reachable by an updated peer; (c) **partitioned peer** — a peer reachable by neither the control plane nor any updated peer; (d) rollback attempt (replay an older revocation list / lower `trust_epoch`); (e) revocation during an established `Session` |
| **Preconditions (V3)** | Three paired devices minimum (revoker, victim peer, revoked device); an *established, working* connection from the to-be-revoked device before revocation, so the test proves exclusion rather than never-worked |
| **Assumptions** | **A-06**, A-02 |

**Procedure.**
1. Establish A↔R (R to be revoked) and A↔B. Verify traffic flows from R.
2. Issue the revocation: `RevocationRecord` at a strictly greater `trust_epoch`, with `EpochSeed(e)` HPKE-sealed to each surviving device ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7).
3. Variant (a): all reachable. Variant (b): partition A from the control plane, leave A↔B reachable. Variant (c): partition A from **both**. Variant (d): replay the pre-revocation record at A. Variant (e): keep R's `Session` up throughout.
4. From R, attempt a fresh handshake to A, repeatedly, for the duration of the variant's window.
5. Capture the handshake exchange on the wire.

**Oracle.**
- R's handshake is **refused at A**, not merely at the control plane (A-06): A emits `AUTH.DEVICE_REVOKED`, the transition is T11 `CONNECTING → FAILED` (non-retryable), and the wire capture shows no session keys were produced.
- The refusal is **structural, not a check**: at epoch `e`, R cannot compute `TwinNetPSK(A,R,e)` because it received no `EpochSeed(e)` seal. The test asserts this directly by feeding R's complete key material to the reference derivation and showing the epoch-`e` PSK is underivable — the same style of structural assertion as P14.
- Variant (b): A learns the revocation from B within **≤ one rekey interval (≤ 120 s)** of contact ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7; [ADR-0009](adr/ADR-0009-state-consistency.md) §11.6 G-3), with no control-plane call.
- Variant (d): the lower `trust_epoch` is refused with `AUTH.TRUST_EPOCH_ROLLBACK`; a broken `prev_entry_hash` yields `AUTH.TRUST_HISTORY_FORKED`. Rejection happens at A's **local durable store**, so it holds against a hostile control plane (TM-29).
- Variant (e): the established `Session` is **not** torn down at the trust boundary (I5), but granted authority suspends at `T_TRUST_HARD` while baseline reachability continues; `AUTH.TRUST_STATE_STALE` appears at `T_TRUST_STALE` = 24 h and `AUTH.TRUST_STATE_EXPIRED` at `T_TRUST_HARD`.
- Control-plane-adversary variant: a forged "disarm"/"un-revoke" from the control plane has **no message type to carry it** (KS-22) and any attempt yields `POLICY.KILLSWITCH.DISARM_REFUSED_REMOTE` or is rejected as an unknown type; denials never expire into permissions ([ADR-0009](adr/ADR-0009-state-consistency.md) §11.4).

**The partitioned-peer case — written against the resolved rule.** Variant (c) runs A partitioned
from both the control plane and every updated peer, with a virtual clock (§3.5, L-3) advancing past
`T_TRUST_HARD`, and asserts the **consequence bound**, not a refusal:

| At | A's behaviour toward revoked R | Oracle |
|---|---|---|
| `< T_TRUST_HARD` | R reaches A at baseline **and** may still use every granted authority | This window is the residual; the test *measures* it rather than asserting it away |
| `≥ T_TRUST_HARD` (default **30 d**, `Owner`-configurable within [24 h, 90 d]) | R **still completes a baseline handshake** — A cannot be told otherwise and refusing would break **R-11** — but every *granted* authority is refused: `ExitNode` egress, `LANGateway` access, `Route` acceptance, and new `Pairing` | `AUTH.TRUST_STATE_EXPIRED` present as a persistent `Diagnostic` with **no `ConnectionState` change**; the four grant refusals each emit their own `POLICY.GATEWAY.*` / `POLICY.SCOPE.*` code; established `Session`s survive throughout |

**This inverts an earlier draft of this test, deliberately.** That draft asserted that A *refuses
new handshakes* at `T_TRUST_HARD`, and recorded an unresolved disagreement between
[ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7 and
[ADR-0009](adr/ADR-0009-state-consistency.md) §11.5. **That disagreement is now resolved** and
both ADRs state the same rule: baseline reachability to an already-known `TrustedPeer` is a fact
the two devices established between themselves (architecture.md **A-02**) and no control-plane
silence may withdraw it, while every *granted* authority suspends at `T_TRUST_HARD` under
ADR-0009 §11.4's grant/deny asymmetry. P10's title remains true — a revoked device cannot
reconnect at any peer that has *learned* the revocation, which is every non-partitioned peer.

**Mutant M-P10-6.** A build that does **not** suspend grants at `T_TRUST_HARD` — trust state
expires and exit egress still works. This mutant is the whole point of variant (c): without it the
consequence bound is prose. It MUST be caught by the absence of the grant-refusal codes above.

**Mutant M-P10-7.** A build that suspends grants on the `PolicyBundle`'s `not_after_ms` **only**,
ignoring `T_TRUST_HARD`. Run with a bundle whose `not_after_ms` is 90 d and a `T_TRUST_HARD` of
30 d; the grants must still suspend at 30 d, because the effective time is
`min(bundle not_after_ms, T_TRUST_HARD)` (ADR-0009 §11.4).

**Mutants (V2).**

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P10-1` | Revocation enforced only at the control plane | Variants (b) and (c) admit R |
| `M-P10-2` | `EpochSeed` derived from a TwinNet-wide secret rather than pairwise + sealed | R derives the epoch-`e` PSK; the structural assertion fails ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7's correction to [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.5) |
| `M-P10-3` | `trust_epoch` accepted non-monotonically | Variant (d) succeeds; no `AUTH.TRUST_EPOCH_ROLLBACK` |
| `M-P10-4` | Peer-relayed `TrustEpochBundle` not implemented | Variant (b) exceeds the 120 s bound |
| `M-P10-5` | Revocation tears down established `Session`s | Variant (e) violates I5 |

**Positive control (V4).** Before revocation, R connects successfully in the same run, on the
same rig — the "it worked, then it did not" shape that distinguishes exclusion from a broken rig.

**Pass criteria.** Variants (a), (b), (d), (e) green in 20/20 runs; variant (c) green **against
the bound as written**, flagged pending the §11.5 reconciliation; all five mutants fail.

**Known limits.** Cloning a file-backed identity (`hardware_backed = false`: routers, containers,
VMs) is undefended (TM-13); P10 asserts only that both copies are excluded by the *same*
revocation, not that cloning is prevented.

---

#### P11 — Protocol downgrade attacks fail

| | |
|---|---|
| **Proves** | R-04; **I2** (composition integrity); threat-model **TM-09** |
| **Lab scenario** | `S-PROTO-DOWNGRADE-*` with an active on-path attacker in the transit namespace. **The variant set is [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) §7.1's attack table T1–T5, adopted verbatim**, plus (d′) an epoch below the peer's recorded S-37 floor |
| **Preconditions (V3)** | Both peers support a *strictly larger* common set than the attacker will force, so the downgrade is a real reduction; the attacker's rewrite is confirmed on the wire before the assertion is evaluated |
| **Assumptions** | **A-07**, A-02 |

**Procedure.**
1. Establish the attacker as a full on-path rewriter between A and B (both families).
2. Run each of T1–T5 below; verify **on capture** that the mutation actually reached the peer before any assertion is evaluated (**V3**).
3. Attempt establishment; record every event and code on both sides.
4. Repeat with the mutation applied in each direction independently, and against each of the three detection layers of [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) §7.2 (Rule-B signature, Noise prologue binding, in-session `NegotiationConfirm`).

**Oracle — [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) §7.1's
T1–T5, each with the outcome that ADR guarantees.** Every row MUST fail the handshake with no
session keys produced, asserted on the wire rather than by absence of a success event.

| Attack | Mutation | Required observation |
|---|---|---|
| **T1** | Rewrite A's `v_max` 9 → 8 in transit **to B only** | Handshake fails. A binds `A=[7,9]`, B binds `A=[7,8]` ⇒ transcripts differ. The offer's Rule-B signature **also** fails, so the cause is precise: `PROTO.NEGOTIATION_TAMPERED` at the signature layer, `PROTO.TRANSCRIPT_MISMATCH` as the backstop |
| **T2** | Rewrite **both** maxima 9 → 8 consistently | **The core case.** Handshake fails: A binds `{A=[7,9] own, B=[7,8] recv}` and B binds the mirror, so the transcripts differ even though both selections agree. A build that succeeds at 8 here has bound the *result* instead of the *inputs* and is a silent downgrade |
| **T3** | Strip `path_migration/1` from **both** advertisements | Handshake fails by the same asymmetry as T2. This is the capability analogue of T2 and, with it, "the whole argument" |
| **T4** | Replay a stale advertisement from a genuine earlier attempt | Handshake fails: `session_nonce` and `key_id` are inside each half, so transcripts differ even when the selection coincidentally matches |
| **T5** | Rendezvous substitutes its own key or set | **Rule-B signature fails first** — `PROTO.NEGOTIATION_TAMPERED`, pre-authentication, precise cause. Prologue binding is the backstop, and the test asserts the *ordering* (signature layer first), not merely that something failed |
| **d′** | Offer an epoch below the peer's recorded S-37 floor | `PROTO.DOWNGRADE_REFUSED` carrying `{peer_label, recorded_floor, offered_epoch, lost_security_capabilities[]}`; the monotonic floor does **not** decrease as a result of the attempt |

- `PROTO.TRANSCRIPT_MISMATCH` is asserted with `class = FATAL`, `severity = CRITICAL`, `terminal = true`, carrying `{local_hash, peer_hash, phase}` — classified as a **security event, not a network error** ([ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) §11.12).
- Layer attribution (§7.2) is asserted per attack: a prologue-layer failure MUST carry `PROTO.TRANSCRIPT_MISMATCH` **alongside** [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)'s `CRYPTO.HANDSHAKE_REJECTED`, and an in-session `NegotiationConfirm` mismatch MUST tear down the `Tunnel` with `PROTO.TRANSCRIPT_MISMATCH`.
- Repeated failures consistent with divergent floor/trust state surface `AUTH.PROLOGUE_OR_EPOCH_MISMATCH` after three attempts ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.6) — asserted so that the *honest limitation* (a prologue mismatch is indistinguishable from any other handshake failure) is itself observable at the third attempt rather than silent.
- Detection is **bilateral**: both peers emit a downgrade-class code, not only the victim.

**Mutants (V2).**

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P11-1` | Negotiation binds only the *selected* set, not the full advertisement (alternative VB-3) | **T2 and T3 succeed at the reduced set — the downgrade goes undetected.** This is the single most important mutant in P11, because VB-3 passes T1, T4 and T5 and is therefore indistinguishable from the correct design under any test that omits T2/T3 |
| `M-P11-2` | Transcript hash computed but not compared | No `PROTO.TRANSCRIPT_MISMATCH`; handshake completes |
| `M-P11-3` | S-37 floor writable downward by a peer's offer | Variant (d) succeeds and permanently lowers the floor |
| `M-P11-4` | Transcript mismatch classified as `TRANSIENT` and retried | The attack becomes a retry storm rather than a refusal; `terminal` assertion fails |
| `M-P11-5` | `NegotiationConfirm` accepted without comparison | T2/T3 still fail at the prologue layer, but the §7.2 layer-3 assertion fails — catching selection-function divergence that the wire layers cannot see |

**Positive control (V4).** The same attacker, same rig, passing the negotiation through
**unmodified**, must produce a successful handshake at the full common set — proving the attacker
is genuinely on-path and that the failure is caused by the rewrite.

**Pass criteria.** All six variants (T1–T5 and d′) fail closed with the correct code and the
correct detection layer, bilaterally, in 20/20 runs; no session keys produced; floor never
decreases; all five mutants fail — `M-P11-1` on **T2 and T3 specifically**.

**Known limits.** A prologue mismatch is not distinguishable from other handshake failures on a
single attempt — this is a stated limitation of
[ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.6, and P11 asserts the three-attempt
aggregation rather than pretending single-attempt attribution exists.

---

#### P12 — Unsupported versions fail safely

| | |
|---|---|
| **Proves** | R-04, R-22; **I6** |
| **Lab scenario** | `S-PROTO-VERSION-*`: (a) peer below MSPV; (b) peer above our range; (c) empty range intersection; (d) rollback below MSPV attempted by the updater; (e) below-minimum peer while the kill switch is engaged |
| **Preconditions (V3)** | Real binaries at the relevant versions (§2.5's version matrix), not a version field spoofed at runtime; resource baselines (fd count, memory, conntrack entries) captured before the attempt |
| **Assumptions** | **A-07**, A-02 |

**Procedure.**
1. Pair devices whose ranges do not intersect; attempt establishment 100 times in a row.
2. Sample fds, resident memory, half-open socket count, and conntrack entries on both sides after each attempt.
3. Variant (d): drive the real updater to install a build below MSPV.
4. Variant (e): arm the kill switch and repeat (a).
5. Leave the system idle for 30 min and observe retry behaviour.

**Oracle.**
- `PROTO.VERSION_UNSUPPORTED`, spelled exactly, `class = PERSISTENT`, `terminal = true`, `user_actionable = true`, carrying `{local_min, local_max, peer_min, peer_max, required_epoch, peer_label}` — **both ranges named**, never a bare numeric code (N-31(1), I6).
- `EV_VERSION_INCOMPATIBLE` fires and the per-`Session` transition is T06 `NEGOTIATING → FAILED`; under `FAIL_CLOSED` the **derived `TwinNet`-scope** state is additionally `BLOCKED` (reliability.md §4.7 rule 1, N-31(2), I3) while the per-`Session` state stays `FAILED` — variant (e) asserts the latter specifically.
- **No half-open state and no retained resource**: all four sampled resource metrics return to baseline after each of the 100 attempts (§2.5). A monotone climb over 100 attempts is a failure even if each individual attempt looks clean.
- Retry occurs only on explicit user action, a successful self-update, or a **6 h** floor — never a storm (N-31(4)). The 30 min idle observation asserts zero retries.
- The diagnostic remains **visible** as the connection's standing state reason (N-31(5)); it is not cleared by the next tick.
- Variant (d): the rollback is refused **at install time, before the old binary runs** (N-30), with `PROTO.VERSION_UNSUPPORTED`.
- No crash, no hang, no untyped failure on either side — a crash here is a P1 defect, not a compatibility limitation (§2.5).

**Mutants (V2).**

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P12-1` | Refusal leaves the socket half-open | Resource baselines climb across the 100 attempts |
| `M-P12-2` | Retry with ordinary backoff instead of the 6 h floor | Retry storm observed in the idle window |
| `M-P12-3` | Bare numeric/errno surfaced instead of the typed code | Registry-keyed oracle fails; R-22 unmet |
| `M-P12-4` | Rollback refused *after* the old binary runs | Variant (d) leaves a running binary that cannot connect and may read state it does not understand |
| `M-P12-5` | Kill switch not engaged on version failure | Variant (e) leaves the derived aggregate at `FAILED` with traffic unprotected instead of raising it to `BLOCKED` |

**Positive control (V4).** The same rig with a supported pair must establish and pass a
data-integrity check, proving the refusal is caused by the version relationship.

**Pass criteria.** Correct typed refusal in all five variants; flat resource curves over 100
attempts; zero unsolicited retries in 30 min; all five mutants fail.

**Known limits.** P12 covers the *version* axis. A device rolled back **within** the supported
window and refused by an S-37 floor is correct-by-design (N-32) and is covered by P11 variant
(d), not here.

---

#### P13 — Malformed packets cannot crash clients or infrastructure

| | |
|---|---|
| **Proves** | R-11 (infrastructure availability), R-22; threat-model **TM-24** |
| **Lab scenario** | `S-PROTO-FUZZ-*` in-lab replay plus the continuous fuzz fleet of §2.12; and `S-PROTO-CORPUS-*` replaying the §2.3 `malformed/` and `hostile/` corpora against live components |
| **Preconditions (V3)** | Every target built with ASan/UBSan (and MSan where available); the harness asserts each input was actually delivered and actually reached the parser (coverage of the parser entry point non-zero) |
| **Assumptions** | A-12, A-15 |

**Every parser is covered — the enumeration is the test.** Twelve parser families. A parser absent from this table is an
untested attack surface, so the table is normative and exhaustive.

| # | Parser | Untrusted source | Fuzz target (§2.12) | Owning spec |
|---|---|---|---|---|
| 1 | Relay control frames and `RelayFrame` framing | Any network peer, pre-authentication | `fz-relay-frame`, `fz-packet-parser` | [ADR-0005](adr/ADR-0005-relay-architecture.md) §9.1 |
| 2 | Relay **capability tokens** (`RelayCapabilityToken`, `cnf`, `jti`), `RelayEpochFloor`, and the signed relay map | A client presenting a token to a relay, **pre-admission**; `RelayEpochFloor` piggybacked by any connecting client | **`fz-capability-token`** | [ADR-0005](adr/ADR-0005-relay-architecture.md) §11.3 |
| 3 | DNS/DoH/DoT responses | Any upstream resolver or on-path attacker | `fz-dns-response` | [ADR-0011](adr/ADR-0011-dns-handling.md) |
| 4 | Control-plane envelopes (deterministic CBOR inside COSE_Sign1) | The control plane, the bus, or anything that can reach the socket | `fz-control-decoder` | [ADR-0003](adr/ADR-0003-network-contract-schema-format.md), [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) |
| 5 | **Revocation records and every other B2 signed statement** — the full [ADR-0003](adr/ADR-0003-network-contract-schema-format.md) B2 list (seventeen types), including `RevocationRecord`, `TrustEpochBundle`, `OwnerTrustAnchor`, `OwnerDelegation`, `IdentitySuccession`, `TunnelKeyBinding`, `PolicyBundle`, `LogHead` | A peer relaying a bundle in-session (G-3, §7.7), or a hostile control plane. **Verified offline possibly years after issuance** | **`fz-trust-document`** | [ADR-0003](adr/ADR-0003-network-contract-schema-format.md), [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7, [ADR-0009](adr/ADR-0009-state-consistency.md) §11.6 |
| 6 | Tunnel frames, pre- and post-decrypt | The network | `fz-packet-parser` | [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) |
| 7 | Handshake message sequences | The network | `fz-handshake-state` | [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) |
| 8 | Pairing invitations, deep links, QR payloads | A human pasting an attacker's string | `fz-uri-and-invite` | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.4 |
| 9 | Configuration files, CLI args, router-style config | Less-trusted on router targets | `fz-config-parser` | [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md) |
| 10 | Diagnostic bundle format | The support-side viewer parses attacker-influenced files | `fz-bundle-parser` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.9 |
| 11 | **Platform key-attestation blobs** | Vendor-defined, externally sourced, parsed **before** a trust decision at pairing/enrolment | **`fz-attestation-blob`** | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.3 (`AUTH.ATTESTATION_FORMAT_UNSUPPORTED` is the code that implies this parser exists) |
| 12 | **Control-operation *sequences*** — not a byte parser, a state parser | Any actor that can submit, duplicate, delay, or reorder control operations | **`fz-control-reorder`** | [ADR-0008](adr/ADR-0008-idempotency.md) §11 |

Rows 11 and 12 are the families the original ten-parser enumeration missed. Row 12 is the one
that is not a byte parser at all: [ADR-0008](adr/ADR-0008-idempotency.md) §11's harness fuzzes
**order**, which no byte-oriented fuzzer reaches, and its RQ-6 assertion — replaying an older
trust state never un-revokes — is a security property, not a robustness one.

**Procedure.**
1. For each parser, replay the frozen `malformed/` and `hostile/` corpora against a **live** component (not an in-process harness), for both the client and the infrastructure side.
2. Run **the full §2.12 target set — all twelve** (`fz-packet-parser`, `fz-handshake-state`, `fz-control-decoder`, `fz-config-parser`, `fz-dns-response`, `fz-relay-frame`, `fz-bundle-parser`, `fz-uri-and-invite`, `fz-trust-document`, `fz-capability-token`, `fz-attestation-blob`, `fz-control-reorder`) for the tier's CPU budget (§6); the per-PR nightly budget is spent on the targets a change touches, but a release candidate MUST have exercised every one of the twelve.
3. For parsers 1, 2, 6 and 11, drive the malformed input from an **unauthenticated** position, since that is the real attacker's position. For parser 5, drive it additionally from a *peer* position, because §7.7's `TrustEpochBundle` is peer-relayable and a control-plane-only harness would miss that path entirely.
4. For parser 12, run the reorder harness with N ≥ 100 permutations per operation, interleaved duplicates, stale `if_version` preconditions, and injected crash points.
5. Sample process liveness, memory, and fd count throughout; assert the datapath for *other* peers is unaffected.

**Oracle.**
- **Zero** crashes, hangs, OOMs, or sanitizer reports across all targets. A new unique finding is a release blocker regardless of perceived exploitability; triage classifies severity, it does not decide whether to fix (§2.12).
- Every rejection is typed: a `PROTO.MALFORMED_MESSAGE`-class outcome with a registered code. **Zero unclassified decode outcomes** (§2.3).
- **No allocation proportional to a declared length** and no partial application of a rejected message — asserted from allocator instrumentation, not from absence of a crash.
- Deterministic rejection: two encodings of the same semantic content are not both accepted where the schema requires canonical form (deterministic CBOR, RFC 8949 §4.2.1); signature verification is over **received octets** and `crit` is enforced.
- Reserved bits are zero on send and ignored on receive ([ADR-0005](adr/ADR-0005-relay-architecture.md) §9.1).
- Infrastructure isolation: a malformed frame from peer X does not perturb peer Y's flow counters on the same relay or gateway.
- Where a second implementation exists, differential decoding agrees on accept/reject; divergence is itself a finding.

**Mutants (V2).**

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P13-1` | Length prefix trusted for pre-allocation | OOM under the `hostile/` corpus; allocator assertion fires |
| `M-P13-2` | Signature verified over a re-encoded structure rather than received octets | A canonicalization variant is accepted |
| `M-P13-3` | `crit` header ignored | An unrecognized critical field is accepted |
| `M-P13-4` | Untyped rejection path (bare error) added to one parser | "Zero unclassified decode outcomes" fails |
| `M-P13-5` | Partial application of a rejected control message | State changes after a rejection |

**Positive control (V4).** The corresponding `valid/` corpus must be **accepted** by every parser
in the same run, and a deliberately-planted crashing input in a scratch target must be found by
the harness — proving the harness detects crashes at all.

**Pass criteria.** All twelve parser families, both sides, zero findings, zero unclassified outcomes, flat
resource curves, all five mutants caught.

**Known limits.** The bespoke relay frame parser is the newest and least adversarially-reviewed
surface in the system ([ADR-0005](adr/ADR-0005-relay-architecture.md) §13); P13 gives it the
largest continuous-fuzz budget, which reduces but does not eliminate that asymmetry. Fuzzing is
`EXPLORATORY` (§3.5): absence of a finding is not proof of absence of a bug.

---

#### P14 — Relay infrastructure cannot decrypt tunnel payloads

| | |
|---|---|
| **Proves** | **I1** — and P14 is the *only* evidence offered for I1 anywhere in this corpus (see §5) |
| **Conformance surface** | [ADR-0005](adr/ADR-0005-relay-architecture.md) §7.1 — "P14's oracle becomes an enumeration over a three-element key inventory rather than a statistical observation over traffic". Mirrored in [docs/threat-model.md](threat-model.md) §8.1 |
| **Lab scenario** | `S-RELAY-OPACITY-*`: a `RELAYED` session carrying known plaintext, with the relay under full test control (root in its namespace, memory readable, process debuggable) |
| **Preconditions (V3)** | Traffic genuinely traverses the relay (relay frame counters non-zero for this `pair_tag`); the captured frames are genuinely from this session (correlated by capture timestamp and frame count) |
| **Assumptions** | **A-05** |

**P14 is a structural test, not a statistical one.** The argument is an **enumeration over a
closed key inventory** ([docs/threat-model.md](threat-model.md) §8.1,
[ADR-0005](adr/ADR-0005-relay-architecture.md) §7.1), and the procedure is that enumeration
executed. A test that merely fails to find plaintext in a capture would be a weak negative
observation; this one asserts that decryption is *impossible from the relay's complete key
material*.

**Procedure.**
1. Establish A↔B `RELAYED`. Drive a flow whose plaintext is a known, high-entropy marked corpus (so that a partial break is detectable, not just a total one).
2. Capture **every** frame the relay forwards, in both directions, for the whole session.
3. Dump the relay's **complete key material at an instant of the test's choosing**, including at least one dump while the session is live: process memory (full core), the on-disk key store, the loaded configuration, and every key the relay's own inventory declares —
   - the relay static X25519 `RS`,
   - the issuer public-key set,
   - every per-leg key `K_leg` (the Noise_IK / TLS-exporter transport key with each device's `RLK`),
   - plus, deliberately over-collecting: every symmetric key, every X25519 scalar, and every 32-byte high-entropy region found by a memory scanner in the relay's address space.
4. Feed the **union** of that material to the reference L-DATA decryptor and attempt decryption of every captured frame under every key and every reasonable derivation.
5. Independently assert the inventory is closed: no key in the dump is an input to the L-DATA key schedule, and `RLK` remains domain-separated from L-DATA ([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.2(a)–(b)).
6. Repeat with the relay running a **modified** binary that retains everything it ever saw (a hoarding relay), to show that retention does not help.
7. Repeat with two relays colluding (both dumps unioned), since a single-relay assumption would be a weaker claim than I1 makes.

**Oracle.**
- **No captured frame decrypts** under any key in the union, in any direction, at any point in the session. The marked corpus does not appear, in whole or in part, in any decryption attempt's output.
- The relay holds **no L-DATA static, no L-DATA ephemeral, and no `TwinNetPSK`** — asserted by comparing the dumped key set against the L-DATA schedule's declared inputs, so the result is an inventory statement rather than a search outcome.
- `pair_tag` is one-way: the test attempts to invert it from the relay's material and fails; the relay's records contain no identity-level peer pair (TM-28, O-13).
- The hoarding and colluding variants change nothing.
- The relay *does* learn what the threat model says it learns — traffic volume, timing, packet sizes, both underlay addresses, and that two token holders are communicating ([docs/threat-model.md](threat-model.md) §8.3). The test **asserts these are observable**, so the honest metadata claim is verified as an upper bound rather than assumed.

**Mutants (V2).**

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P14-1` | `RLK` derived without domain separation from L-DATA | A key in the dump becomes an L-DATA input; step 5's inventory assertion fails and decryption succeeds |
| `M-P14-2` | Relay terminates and re-originates the tunnel ("optimizing" relay) | Frames decrypt under `K_leg`; I1 violated |
| `M-P14-3` | `TwinNetPSK` distributed to relays "for admission control" | Frames decrypt |
| `M-P14-4` | `pair_tag` computed reversibly (peer ids concatenated rather than HKDF'd) | Inversion succeeds; TM-28 bound breached |

**Positive control (V4).** The same rig, the same capture, the same decryptor, fed the **peers'**
key material must decrypt every frame and recover the marked corpus byte-for-byte. Without this
the negative result proves only that the decryptor does not work.

**Pass criteria.** Zero frames decrypt from relay material in every variant; the positive control
recovers 100 % of the corpus; the inventory assertion holds; all four mutants decrypt (i.e. fail
the test) as expected.

**Known limits.** P14's structural strength is conditional on
[ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) maintaining the domain
separation of `RLK` required by [ADR-0005](adr/ADR-0005-relay-architecture.md) §11.2(a)–(b). If
that separation were relaxed, P14 collapses to a weak negative observation (A-05), and the
mutant `M-P14-1` is exactly the tripwire for that. P14 says nothing about metadata, which is
§8.3's honest accounting, not a defect.

---

#### P15 — Control-plane outages do not unnecessarily terminate established tunnels

| | |
|---|---|
| **Proves** | R-11; **I5**. This is the negative conformance test [docs/architecture.md](architecture.md) §4.4.5 requires and A-20 assigns to this document |
| **Lab scenario** | `S-CP-BLACKHOLE-FULL-*`: control plane, rendezvous, presence, **and** relay-selection all blackholed simultaneously, while established `Session`s are running |
| **Preconditions (V3)** | Multiple established `Session`s across `LOCAL_DIRECT`, `WAN_DIRECT`, and `RELAYED`, all carrying traffic; the pre-materialized state set of architecture §4.4.1 verified present on disk **before** the blackhole |
| **Assumptions** | **A-13**, A-04, A-02 |

**Procedure.**
1. Establish at least one `Session` in each of the three carrying classes, plus a multi-peer gateway with 16 peers.
2. Verify architecture §4.4.1's pre-materialized set is complete on every device: peer public key, negotiated `Capability` set, `AccessPolicy` snapshot + version, `DNSPolicy` snapshot + version, assigned `TwinNet` addresses, cached `Endpoint` list, ranked `Relay` set with ≥ 2 alternates per region.
3. Blackhole `cp`, `rz`, presence, and `rs` simultaneously. Hold for 4 h of virtual clock, crossing the `refresh_after` (15 min) and the trust/membership `not_after` (24 h) bands of [ADR-0009](adr/ADR-0009-state-consistency.md) §11.4 in a long variant.
4. During the outage, exercise each clause of §4.4.5 in turn: (a) idle; (b) roam a device; (c) kill the in-use relay; (d) restart a client process; (e) let a `DNSPolicy` and an `AccessPolicy` bundle expire.
5. Restore the control plane and observe reconciliation.

**Oracle — clause by clause, as architecture §4.4.5 states them.**
- **(a)** No `Session` transitions to `DISCONNECTED` or `FAILED` for the whole outage. Keepalive and rekey continue; the rekey is asserted to have occurred (key generation advanced) with **zero** control-plane calls.
- **(b)** A `Path` roam still succeeds, with P05's exact oracle (`… → MIGRATING → …`, `session_id` unchanged, no `CRYPTO.*` handshake event).
- **(c)** A relay failover still succeeds, with P03's exact oracle (`RELAYED → MIGRATING → RELAYED`), selected from the **cached** ranked set — a set of size 1 at this point is a design error (§4.4.4).
- **(d)** A client process restart reconnects to a cached-`Endpoint` peer with no control-plane call.
- **(e)** Every degraded capability is reported with a **distinct `reason_code`**, not as a connection error: `CONTROL.UNREACHABLE` as informational rather than terminal; `CONTROL.STALENESS.DOCUMENT_STALE` on entering STALE; `CONTROL.STALENESS.POLICY_GRANT_SUSPENDED` and `DNS.UPSTREAM.FORWARDING_SUSPENDED` on policy EXPIRY; `CONTROL.STALENESS.TRUST_LIST_EXPIRED` on trust expiry; `CONTROL.STALENESS.RELAY_SET_EXPIRED` with **no enforcement effect whatsoever** ([ADR-0009](adr/ADR-0009-state-consistency.md) §11.4).
- **Dependency assertion (the mechanical part).** The instrumented control-plane client records **zero** outbound calls on every established-tunnel code path — keepalive, rekey, path probe, path migration, relay use, relay failover, `TwinNet`-name resolution, policy evaluation (architecture §4.4.2). This is asserted by instrumentation *and* corroborated by the blackhole itself: any call would have to fail, and a failed call on these paths is a violation even if the path then recovered.
- **Step 3 of [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §11.8 — the build-time dependency-graph assertion, run in T1.** The data-plane modules **MUST NOT link the control-plane client library**. This is a static dependency-graph check in CI, not a runtime observation, and it is what turns "we were careful" into "the build fails". ADR-0002 names it as the artifact **A-13** and architecture §4.4.5 need, and states explicitly that it **complements — does not replace —** the blackhole conformance test. P15 therefore has two independent oracles at different times: the link-graph assertion at T1, and the blackhole at T3/T4. A release that has only one of them has not discharged I5.
- **Step 4, negative.** The control-channel liveness signal is wired to nothing in [docs/reliability.md](reliability.md) §4.3 (ADR-0002 R-a): the test asserts that no control-plane event exists in the state machine's alphabet, so a control-plane outage cannot even *express* itself as a data-plane event. This is asserted by inspecting the §4.3 event table against the emitted stream, and it is why clause (a) is a structural result rather than a lucky one.
- **Relay admission survives the whole outage (A-13, strengthened).** The past-24 h variant runs long enough to cross the former 30-hour token cliff; the assertion is that relayed pairs keep working, admitted by **relay-issued renewal** with epoch equality, `exp + T_RELAY_GRACE` (6 h), and live `RLK` proof of possession ([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.3) — zero control-plane involvement at any point.
- **The grant/deny asymmetry is asserted, not assumed**: at policy EXPIRY, every *grant* suspends and every *deny* persists; no expiry path widens an authorization ([ADR-0009](adr/ADR-0009-state-consistency.md) §11.5). `twinnet`-zone names keep resolving throughout (I5).
- On restore, reconciliation produces no second writer for any fact (I8) and no `Session` is torn down by the reconciliation itself.

**Mutants (V2).**

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P15-1` | Rekey fetches a fresh policy snapshot | Dependency assertion fires; sessions fail at first rekey under blackhole |
| `M-P15-2` | Relay failover consults the relay-selection service | Clause (c) fails |
| `M-P15-3` | Reconnect after process restart requires a control-plane call | Clause (d) fails |
| `M-P15-4` | TTL expiry tears down `Session`s | Clause (a) fails at the 24 h band (§11.4, RQ-7) |
| `M-P15-5` | A policy *grant* survives expiry (fail-open on the authorization axis) | The asymmetry assertion fails |
| `M-P15-6` | `CONTROL.UNREACHABLE` surfaced as a terminal connection error | Clause (e) fails; the user is told the tunnel is broken when it is not |
| `M-P15-7` | A data-plane module links the control-plane client library (without yet calling it) | The **T1 dependency-graph assertion** fails at build time, before any runtime test runs — this mutant exists to prove the static check is live, since a passing blackhole test would not catch it |
| `M-P15-8` | Relay token renewal reintroduced as a control-plane call (the withdrawn 30-hour cliff) | The past-24 h variant loses every relayed pair at the cliff; A-13's strengthened half fails |

**Positive control (V4).** With the control plane **reachable**, every operation in step 4 must
succeed *and* the instrumented client must record non-zero calls for the operations that
legitimately need it (new pairing, new membership) — proving the dependency instrumentation
actually observes calls, so "zero calls" is evidence rather than a broken counter.

**Pass criteria.** All five clauses green in both the 4 h and the past-24 h variants, both
families, with the gateway present; zero recorded control-plane calls on established-tunnel
paths; the T1 dependency-graph assertion green in the same build; all eight mutants fail.

**Obligation discharged.** [docs/architecture.md](architecture.md) **A-20** assigns the ownership
and specification of the §4.4.5 negative I5 conformance test to this document. **P15 is that
test**, and A-20 is hereby confirmed rather than left as an unverified claim. Its five clauses
map one-to-one onto §4.4.5(a)–(e).

**Known limits.** P15 proves the data plane survives control-plane *unavailability*. It does not
prove behaviour under a control plane that is reachable but **malicious**; that is
[docs/threat-model.md](threat-model.md) §10 and is exercised by P10's rollback and
control-plane-adversary variants and by the §2.14 battery.

---


### 4.3 The application-layer proof tests P16–P22

The application-architecture workstream adds **seven** proof tests, raising the acceptance set to
**twenty-two**. They are specified in full by their owning ADRs and are **cited here, not restated**
— a second copy would drift, and PT-1/PT-2/PT-3 apply to them unchanged.

| Test | Proves | Owner (full specification) | Shape |
|---|---|---|---|
| **P16** | Enforcement survives the death of every unprivileged process; the privilege boundary holds | [ADR-0016](adr/ADR-0016-client-process-and-privilege-separation.md) | Procedure A asserts the user-logout durability claim ADR-0012 §11.6 had already *assumed* but which no document had made verifiable |
| **P17** | R-21's parity rule: no control operation exists outside the MI catalogue, and scopes are enforced per request | [ADR-0017](adr/ADR-0017-local-management-interface.md) | Clause A drives the GUI/CLI operation matrix; mutants cover cached catalogues and replayed credentials |
| **P18** | The *human* half of I6: every code renders three parts in every locale and surface, including unknown codes | [ADR-0019](adr/ADR-0019-application-state-model-and-ui-architecture.md) | 9 oracles, 10 mutants, positive control, driven across the locale, `platform_ctx` **and Basic/Advanced mode** matrices ([ADR-0019](adr/ADR-0019-application-state-model-and-ui-architecture.md) BA-4/BA-6/BA-8). Needs **no device farm** — `platform_ctx` is a parameter, so every platform's variants render from one runner |
| **P19** | Local state cannot be rolled back, and the custody flag cannot overstate custody | [ADR-0020](adr/ADR-0020-local-persistence-and-secure-storage.md) | 6 mutants, 3 variants. Variant 3 **inverts its oracle** on a snapshotted vTPM — it fails a build that *claims* detection where none is possible |
| **P20** | Artifact integrity, rollback refusal, and protection continuity across a real apply | [ADR-0021](adr/ADR-0021-packaging-distribution-and-updates.md) | 4 procedures, 7 mutants. P20-C **measures** the iOS unprotected window rather than asserting it is zero |
| **P21** | Protected, unattended resume from every termination class | [ADR-0022](adr/ADR-0022-application-lifecycle-and-background-execution.md) | 7 oracles, 6 mutants. Oracle 6 plants a 32-byte canary in the secret arena and greps every crash artifact including OS tombstones — converting [docs/threat-model.md](threat-model.md) §9's crash-dump claim from an intention into a falsifiable test |
| **P22** | The embedded profile meets its declared envelope on real hardware | [ADR-0023](adr/ADR-0023-headless-cli-and-embedded-profile.md) | Gates on the `GC-0U` reference unit with `GC-0` measured nightly |

**Rule PT-4 (consumed conformance surfaces).** Where an application-layer test asserts a property
another ADR owns, it **consumes** that ADR's conformance surface rather than re-deriving it, and
says so. P21's crash-loop cell consumes [ADR-0016](adr/ADR-0016-client-process-and-privilege-separation.md)'s
PS-9/PS-10/PS-11; what P21 adds is the end-to-end zero-egress assertion across the hold. This is
the §4.1 ownership rule applied within the acceptance set.

**Declared shared mutant.** `M-P20-3` (remove-then-add instead of atomic swap) is **the same mutant**
as `M-P09-3`, declared as shared so it is not counted twice as independent evidence.

**Known limit, stated rather than absorbed.** P20 procedures A, B and D are **not executable on iOS
at all**, and on Play-managed Android run only against the secondary channel. On iOS the
corresponding assurance is **inherited from Apple's channel as an assumption, not a test** — the
single largest such inheritance in the acceptance set.

### 4.2 Adopted test obligations placed on this document by other ADRs

Two ADRs place named testing obligations on this document that are **not** proof tests and had no
home before this section. They are adopted here with a tier and an oracle, because an obligation
recorded in the ADR that needs it and nowhere in the document that owes it is a Phase 1 defect.

**[ADR-0009](adr/ADR-0009-state-consistency.md) §11 (obligation 5) — the four consistency
checks.** These sit at Level 6 (integration) against a real multi-replica control plane, run at
**T3**, and are release-blocking under B-16 because each one falsifies a consistency escalation
the protocol depends on ([docs/protocol.md](protocol.md) §15 E-1/E-2).

| # | Check | Procedure | Oracle |
|---|---|---|---|
| **C-1** | **Linearizability over concurrent revocation admissions across an induced leader failover** | Submit K concurrent `RevocationRecord` admissions to distinct replicas while killing the leader mid-flight; collect the observed admission order at every replica and at every device edge | The observed history is linearizable with respect to a single total order on `net_seq`; no admitted revocation is lost, reordered, or duplicated across the failover. This is the direct test of **E-1** |
| **C-2** | **Monotonic-read under replica churn** | Kill and restart replicas continuously for 30 min while devices poll; record every `(net_seq, trust_epoch, doc_version)` triple a device observes | **No device ever observes a decreasing value in any of the three.** A single decrease is a P1 defect, not a retry — it is the rollback attack arriving as an availability event, and it is exactly what **E-2** claims cannot happen |
| **C-3** | **Fork injection** | Serve two different contents at one version to two devices | `CONTROL.CONSISTENCY.FORKED_HISTORY_DETECTED` is emitted and the fencing path engages. [ADR-0009](adr/ADR-0009-state-consistency.md) states this code **outside a fault-injection test is a security incident**, so this test is also the only legitimate producer of it — its appearance anywhere else in CI is itself a finding |
| **C-4** | **Clock tampering ±30 days** | Step the device clock forward and backward 30 days, in both directions, across the STALE and EXPIRED TTL bands | **No grant widens** (the §11.5 authorization axis stays fail-closed) **and no established `Session` drops** (the connectivity axis stays fail-open). Both halves are asserted; a build that satisfies one and not the other has broken the reconciliation that §11.5 exists to state. Corroborates [ADR-0009](adr/ADR-0009-state-consistency.md) §11.7 K-1: no ordering or security decision depends on a timestamp |

C-1, C-2 and C-3 are the runtime evidence behind §5.2's **I8** row alongside PB-6; C-4 shares the
§2.13 clock-jump chaos row's injection but asserts a stricter, policy-level property.

**[ADR-0008](adr/ADR-0008-idempotency.md) §11 — the control-reorder harness.** Adopted as the
fuzz target `fz-control-reorder` (§2.12), which replays every control operation N times in random
order including interleaved duplicates, stale `if_version` preconditions, and injected crash
points. Its RQ-6 assertion — **replaying an older trust state never un-revokes** — is the same
property P10 variant (d) asserts end-to-end, so the two are deliberate corroborating oracles at
different levels rather than duplicates.

**[docs/architecture.md](architecture.md) A-20 — the I5 negative conformance test.** Discharged
by **P15**; see its pass criteria.

---

## 5. Requirements traceability matrix

Every requirement in [docs/vision.md](vision.md) §5 and every invariant in
[docs/vision.md](vision.md) §4.1 maps here to the test that verifies it. **A requirement with no
covering test is a gap, and is named as one.** [docs/vision.md](vision.md) §6 clause 1 requires
every requirement to map to a mechanism; this section adds the second half of that obligation —
every requirement must map to an *observation*.

**Coverage classes.** `PROOF` — verified by a mandatory proof test (§4). `LEVEL` — verified by a
named taxonomy level (§2) with a stated pass criterion. `PROPERTY` — verified by a named
property (§2.11). `REVIEW` — enforced at review or by a build-time mechanical check, with no
runtime test. `GAP` — no covering test exists.

### 5.1 R-01 … R-24

| Req | Verified by | Class | Note |
|---|---|---|---|
| **R-01** parallel traversal, no single technique | **P01**, **P02**; §2.10 per-class outcomes | PROOF | §2.10's `DIRECT_EXPECTED` class is what stops a give-up-and-relay build passing |
| **R-02** works under symmetric NAT / CGNAT via relay | **P02**; §3.6 budgets; §2.10 `RELAY_EXPECTED` | PROOF | |
| **R-03** no DHCP, deterministic addressing | **P06** addressing oracle (no DHCP frame on `twin0`); PB-9 | PROOF | |
| **R-04** explicit version + capability negotiation | **P11**, **P12**; §2.4 schema diff; §2.5 interop matrix | PROOF | |
| **R-05** `Session` survives `Path` loss | **P04**, **P05**; PB-3 | PROOF | |
| **R-06** automatic unattended reconnect with bounded backoff | **P04**; PB-8 | PROOF | |
| **R-07** roaming migrates without renegotiating identity | **P05** (incl. cross-family roam) | PROOF | |
| **R-08** mobile background lifecycle, resume without leak | **P09** (iOS/Android rows); §2.8 platform level | PROOF | Oracle degrades on iOS — see P09's platform table |
| **R-09** every failure has a defined recovery and terminal condition | §2.2 transition coverage gate; PB-2, PB-8; **P04** positive control | LEVEL | No proof test; the merge-gating transition-coverage requirement in §2.2 is the primary enforcement |
| **R-10** health-aware selection, bounded failover, no `Session` drop | **P03** | PROOF | |
| **R-11** no single point of failure | **P03** (region), **P13** (infrastructure crash-resistance), **P15** (control plane) | PROOF | Honestly bounded by [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.8's total-fleet case |
| **R-12** measured-RTT ranking; life-of-session direct upgrade | **P05** upgrade variant; **P01** dual-stack preference; §2.16 latency budgets | PROOF | Ranking *quality* is a §2.16 measurement, not a correctness assertion |
| **R-13** no untunneled egress while the kill switch is engaged | **P09**; PB-1, PB-10 | PROOF | |
| **R-14** v4 **and** v6 **and** DNS leak prevention simultaneously | **P07**, **P08**, **P09** | PROOF | |
| **R-15** throughput / MTU correctness | §2.16 throughput rows; §2.9 PMTU + MSS clamping incl. the ICMP-blackhole variant | LEVEL | No proof test. Deliberate: throughput is a budget, and a budget is a measurement with a noise band, not a pass/fail composition claim |
| **R-16** many concurrent peers with isolation, policy, accounting | **P06**; §2.16 gateway scaling | PROOF | |
| **R-17** detect interface/address/route conflicts before modifying state | §2.9 (route/rule/address removal and collision detection); §2.6 idempotency; PB-4, PB-9 | LEVEL | **Thin.** No test asserts the *pre-flight conflict report* itself — that a conflict is surfaced rather than overwritten. See G-3 |
| **R-18** legible degradation under third-party firewall/AV | **P02** transport-ladder variants; §2.8 Windows AV row | PROOF | Naming the interfering component is only heuristic; §2.8 asserts the code, not the name's accuracy |
| **R-19** no bespoke stale driver; startup capability probe | §2.8 capability probe as a test artifact | LEVEL | |
| **R-20** enumerated supported-OS matrix with named breakage | §2.18 compatibility level | LEVEL | |
| **R-21** Linux and router-class first class | §2.8 router row (real hardware nightly); §2.16 router throughput; **P06** on a router-class gateway | LEVEL | |
| **R-22** stable `reason_code` + human text + next action | §2.4 checks 3 and 4 (registry append-only + completeness); every §4 oracle keys on codes | LEVEL | The registry-completeness check is the mechanical enforcement; §4 is the evidence the codes are actually emitted |
| **R-23** self-contained connectivity report | **E2E-CR-1** (§2.7); [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.8 | LEVEL | Was the corpus's one uncovered requirement; G-1 closed |
| **R-24** revocation enforced at each peer's own handshake, with the residual window bounded and stated | **P10**; §2.14 revocation battery; [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7 propagation bounds | PROOF | Added when **G-6** closed. P10 previously discharged a threat-model row with no owning R-number — the inverse of a coverage gap |


### 5.1b R-25 … R-49 (application and platform)

| Requirement | Covered by | Status |
|---|---|---|
| **R-25 … R-27** process/privilege separation, supervision, reversible host integration | **P16**; §2.8 platform level | LEVEL + PROOF |
| **R-28 … R-30** one local control contract, authenticated and scoped | **P17**; §2.4 contract level | LEVEL + PROOF |
| **R-31 … R-32** one portable core, gated per-target budgets | §2.16 performance level (per-class gates); §2.18 compatibility | LEVEL |
| **R-33 … R-36** three-part rendering, no positive state from a stale replica, accessibility, GUI/CLI parity | **P18**; **P17** clause A for parity | PROOF |
| **R-37 … R-39** declared custody, no rollback of local state, named recovery | **P19**; §2.14 key-custody battery | LEVEL + PROOF |
| **R-40 … R-43** signed artifacts, monotonic manifests, protection across apply, honest fleet reporting | **P20**; §2.15 upgrade level | LEVEL + PROOF |
| **R-44 … R-46** unattended protected resume, containment that never fails open, gated background budgets | **P21**; §2.17 soak | LEVEL + PROOF |
| **R-47 … R-49** headless enrolment, declarative configuration, embedded envelope | **P22**; §2.8 router row | LEVEL + PROOF |

### 5.2 I1 … I8

| Inv | Verified by | Class | Note |
|---|---|---|---|
| **I1** infrastructure cannot decrypt | **P14** | PROOF | **P14 is the only evidence for I1 anywhere in this corpus.** See G-2 |
| **I2** no novel cryptography | §2.3 `crypto-kat/` corpus (byte-exact agreement with published vectors); ADR review | REVIEW | A known-answer match proves *conformance to* an audited primitive; it cannot prove that no novel construction was introduced elsewhere. See G-4 |
| **I3** fail closed, visibly | **P07**, **P08**, **P09**; PB-1, PB-10; §2.13 SIGSTOP row | PROOF | |
| **I4** identity never leaves the device | §2.14 key-custody battery (no exportable credential); **P10** (custody is the basis of exclusion) | LEVEL | No proof test asserts non-exportability. See G-5 |
| **I5** the data plane outlives the control plane | **P15** (architecture §4.4.5 discharged); **P02**(c), **P03** blackholed variants; **P10** variant (e) | PROOF | |
| **I6** every failure has a name | §2.4 registry completeness; PB-2; **P12**; A-16 assertion inside every §4 oracle | LEVEL | |
| **I7** many peers, always | **P06** | PROOF | |
| **I8** one writer per fact | PB-6; §4.2 **C-1** (linearizability across leader failover), **C-2** (monotonic read under replica churn), **C-3** (fork injection); §2.6 state-authority restart; **P10** variant (d) (local store is the rejection point); **P15** restore step | PROPERTY | §4.2's C-1/C-2 are the runtime evidence for protocol §15's **E-1** and **E-2** escalations, which had no covering test before this revision |

### 5.3 Gaps — named, not smoothed over

**Register status: all ten resolved — nine closed on an applied remedy, one (G-4) formally
accepted as a REVIEW-class control with a named owner and trigger.** The rows are retained in
full rather than deleted: each records what was wrong, what closed it, and where the remedy
lives, and several name a defect *shape* that recurs — a test written against its own
construction (G-10), a summary register drifting from the documents it summarizes (G-8), a
mechanism defeated by a different specified mechanism (the `ElapsedClock` defect). A register
that empties itself loses the only history that makes the next instance recognizable.

**Rule GR-1.** A gap is closed **only** when the remedy is in the owning document, not when it is
proposed, scheduled, or agreed. A row may read *(accepted)* instead, as G-4 does — but the
acceptance must state its owner, its trigger and what it does **not** prove. Silence is not
acceptance, and that distinction is what G-4 itself was raised to force.

| # | Gap | Severity | Remedy owed |
|---|---|---|---|
| **G-1** | *(closed)* **R-23 now has a covering test.** The gap was that no level in §2 and no proof test exercised the connectivity report ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.8) — that it can be produced without a rebuild or a debug binary, that it names every `ConnectionCandidate` tried and what each returned, that it names the blocking constraint, and that it survives the §11.4 redaction rules | — | **CLOSED — remedy applied.** §2.7 registers **E2E-CR-1 `connectivity-report conformance`**, driven from a *failed* `S-NAT-*` scenario, with five oracles, four mutants and a positive control, at T3 and T4. It is a Level 7 case, **not** a proof test: the acceptance set is enumerated in §4 and §4.3 and this document does not extend it. The earlier remedy note said the gap could not be closed "because the fifteen proof tests are fixed by the acceptance criteria" — that conflated *needs a covering test* with *needs a proof test*, and a Level 7 case was always the right instrument |
| **G-2** | *(closed)* **I1's evidence is no longer a single nightly test.** P14 remains the only *proof test* for I1, and its structural strength is conditional on a domain-separation property owned elsewhere ([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.2(a)–(b)) | — | **CLOSED — remedy applied.** `M-P14-1` (the domain-separation tripwire) is promoted to a **standing T1 build-time check** on the key-schedule inputs (§6.2), so a regression is caught at commit rather than at the nightly P14 run. The single-point-of-evidential-failure is retired: I1 now fails the build at T1 *and* fails P14 at T3/T4, which are independent observation channels (**V6**) |
| **G-3** | *(closed)* **R-17's pre-flight conflict report was unasserted.** §2.9 verified correct install and correct removal; nothing verified that a *detected* conflict is surfaced as a named diagnostic rather than silently overwritten — which is the actual defect R-17 retires | — | **CLOSED — remedy applied.** §2.9 registers the **`S-COLL-*`** family: `S-COLL-ADDR`, `S-COLL-IFACE` and `S-COLL-RULE` assert `ROUTE.ADDRESS_COLLISION` / `ROUTE.IFACE_CONFLICT` is emitted, and rule **COLL-1** asserts the host's interfaces, addresses, routes, policy rules and firewall ruleset are **byte-identical after**. Four mutants, including `M-COLL-4` (roll back after a partial install rather than refusing before it), which fails COLL-1 because a rollback is observable in between. T2 and above |
| **G-4** | *(accepted, explicitly)* **I2 has no runtime verification.** The `crypto-kat/` corpus proves the primitives we use match their specifications; it cannot detect a novel construction introduced around them | Medium — accepted | **CLOSED — the acceptance is now explicit rather than implied by silence**, which is exactly what this row asked for. §2.3 registers control **`CR-I2`**, the novel-construction review gate: a T1 path-and-symbol filter (its only mechanical half) triggers a recorded second-engineer review naming every primitive, the specification each is used as specified by, and an explicit statement that no new construction was composed — *"no crypto change" is an acceptable finding; silence is not.* The review binds to the commit under C-5, and a genuinely new construction is **refused**, not risk-accepted. The control does not prove absence; it makes the claim someone's, at a named point |
| **G-5** | *(closed)* **I4's non-exportability was verified only at §2.14**, and on `hardware_backed = false` targets (routers, containers, VMs) the private half demonstrably can leave (TM-13) | — | **CLOSED — remedy applied.** §2.14's key-custody battery now asserts the **flag's accuracy**, not only the key: **KC-1** probe-vs-declaration with `custody_class` = min of both backends; **KC-2** a false `hardware_backed = true` is impossible to produce, asserted by running one build on hardware-backed and deliberately software-only instances of the *same* platform and requiring the flag to differ; **KC-3** export refusal where the flag is true; **KC-4** an **inverted** oracle where it is false — the clone MUST succeed, so a build claiming non-exportability where it is untrue fails; **KC-5** the degradation transition. Four mutants and a discriminating positive control |
| **G-6** | *(closed)* **P10 had no owning requirement.** Device revocation was verified by a mandatory proof test but appeared nowhere in [docs/vision.md](vision.md) §5's R-numbers — the inverse of a coverage gap | — | **CLOSED.** [docs/vision.md](vision.md) **§5.4 R-24** is the owning requirement and covers what P10 proves: enforcement at each peer's own handshake, suspension of granted authority within `T_TRUST_HARD` at a partitioned peer, the residual window **stated rather than implied**, and no reversal by replaying an older trust document. §7's index lists it against ADR-0007 and ADR-0009; §5.1 above now carries its traceability row; P10's *Proves* line cites it instead of recording its absence |
| **G-7** | *(closed)* The ADR-0007 §7.7 / ADR-0009 §11.5 disagreement on the partitioned-peer bound is **resolved**: baseline reachability survives indefinitely, granted authority suspends at `T_TRUST_HARD`. P10 variant (c) and mutants M-P10-6/7 now assert the resolved rule | — | None owed |
| **G-8** | *(closed)* **A-14 was PRESENT as A-21 but NOT SUFFICIENT — the gap is narrowed, not closed.** [docs/architecture.md](architecture.md) §9 gained A-21, but review by [ADR-0018](adr/ADR-0018-shared-core-and-build-architecture.md) §11.8 (the section that must *realize* it) found six residual defects. **(1) Circular ownership:** A-21 declares it depends on this document's A-14, while §3.5 says L-3 is *required of* architecture.md — each names the other and **neither asserts it normatively in its own voice**. **(2) A-21 omits "a timer" from L-3's enumeration**, so a component may hold a correctly injected clock and still call the runtime's `sleep`/`after` — and [docs/reliability.md](reliability.md) §5 defines ~30 named timers, the largest determinism surface in the system. **(3)** "Injectable" is satisfied by a settable global; only *bound at construction* is checkable. **(4) A-21 scopes the duty to components 2.5 and 2.20**, which *implement* the providers — the consumers are 2.3, 2.4, 2.10, 2.12, 2.14, 2.16, 2.17 and the state machine, so read literally [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md)'s HRW hash is out of scope, which is the very case A-21 cites as its reason to exist. **(5) No mechanical-enforcement clause**, though §6.2's T1 row already budgets for "the §3.5 L-3 lint" that no document specifies. **(6)** §3.5's derived-stream rule is a *product-code* requirement (the core must expose `rng_for(consumer_id)`) written as though lab-side. **(7) NEW — suspend/resume discontinuity is unowned:** neither A-21 nor L-3 says whether an injected monotonic clock advances across suspend, and Linux `CLOCK_MONOTONIC` **excludes** it while Darwin's **includes** it — the same spelling, opposite meanings — so two conforming implementations disagree and every timer in [docs/reliability.md](reliability.md) §5 changes meaning ([ADR-0022](adr/ADR-0022-application-lifecycle-and-background-execution.md) LC-8 resolves this as **three** type-distinct clocks) | **High** — defects (2) and (5) would let a nondeterministic build ship green; (1) is why neither is currently anyone's job to fix | **CLOSED — remedy applied.** A-21 is withdrawn from [docs/architecture.md](architecture.md) §9 and **promoted to requirement R-DET-1 in that document's own voice** (§5.2), which discharges all four edits at once: it is stated as a requirement rather than an assumption pointing outward (1); it enumerates **wall-clock, monotonic, elapsed, timers and randomness** and requires them **bound at construction** (2, 3); it places the obligation on the **consumers** — 2.3, 2.4, 2.10, 2.12, 2.14, 2.16, 2.17 and the state machine — not on the providers 2.5/2.20 (4); it names the **three non-interchangeable clock types** of [ADR-0022](adr/ADR-0022-application-lifecycle-and-background-execution.md) LC-8 (7); and R-DET-1a points enforcement at [ADR-0018](adr/ADR-0018-shared-core-and-build-architecture.md) §11.8 **CD-3**, run in T1 — the lint §6.2 already budgets for (5). Item (6), the derived-stream rule, follows from CD-4 being cited there. [docs/reliability.md](reliability.md) §5.3.1 assigns every timer constant to a clock class |
| **G-10** | *(closed)* **Three proof tests had no owning conformance surface** (§4.1): **P01** (ADR-0004 supplied no surface, no R-ID for the direct-path outcome and no `reason_code` for "direct succeeded"), **P13** (ADR-0003 specified rejection semantics but named no parser inventory and no fuzz surface), and **P04** (whose oracle was weak because T20 emitted no cause code) | — | **CLOSED — all three landed.** **P04:** [docs/reliability.md](reliability.md) §4.5 T20 emits `NET.PATH.DEAD_NO_ALTERNATE` with the fault-specific cause in `caused_by`. **P01:** [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md) **§11.6** adds `NAT.DIRECT_ESTABLISHED` / `NAT.DIRECT_UPGRADED`, the candidate ledger including losers, and the **structural** parallelism assertion `relay_gathered_at_ms ≤ first_direct_probe_ms` — an ordering comparison, not a latency threshold a fast machine could pass with a serial build. **P13:** [ADR-0003](adr/ADR-0003-network-contract-schema-format.md) **§11.7** adds the closed twelve-entry parser inventory `PI-1 … PI-12` mapped to §2.12's targets, the three-outcome decode contract with rule **PA-1**, and a **T1 check** that fails the build when a new untrusted-input parser is not added to it. **PT-4 is now unconditional: this document re-derives no oracle** |
| **G-9** | *(closed)* The underscore reason-code namespace is withdrawn corpus-wide; reliability.md §3.4 carries the old→new mapping and networking.md §10 now states the canonical dotted form | — | None owed |

---

## 6. CI/CD gating tiers and release criteria

### 6.1 The four tiers

`Tier` in §2's table refers to this section. A tier is defined by *when it runs* and *what it
blocks*, not by which machine it runs on.

| Tier | Trigger | Wall-clock budget | Blocks | Runs on |
|---|---|---|---|---|
| **T1** | Every push to a pull request, and every commit on `main` | **≤ 15 min** to first verdict; hard fail at 25 min | Merge | Ephemeral runners; no lab, no real hardware |
| **T2** | Every merge into `main` (post-merge), and on demand | **≤ 60 min** | `main` health; a red `main` blocks all merges until green or reverted | Shared TwinLab instance (namespaces only) |
| **T3** | Nightly against `main`, and on every release-candidate tag | **≤ 8 h** | The nightly gate; two consecutive red nights block release-branch creation | Dedicated TwinLab + VM fleet + device farm |
| **T4** | Release candidate, and any change to a release branch | **≤ 96 h** (dominated by the 72 h soak) | **Release** | Full lab, pinned performance rigs, real router hardware, physical device farm |

**Rule C-1.** A tier's budget is a **property of the tier**, not an aspiration. When a tier
exceeds its budget, the response is to move work down a tier or to parallelize it — never to
raise the budget silently. Raising a budget is a reviewed change to this table.

**Rule C-2.** No test may be in a tier that cannot satisfy its determinism class (§3.5). An
`EXPLORATORY` test MUST NOT gate T1 or T2.

### 6.2 What runs in each tier

| Tier | Contents |
|---|---|
| **T1** | Levels 1 (unit), 2 (component, incl. the **transition-coverage merge gate**), 3 (protocol/golden vectors), 4 (contract: schema diff, producer/consumer, `reason_code` registry append-only + completeness), 14-short (property, ≤ 4 min); the **domain-separation tripwire** on the key-schedule inputs (the standing form of `M-P14-1`, promoted per G-2 so an I1 regression is caught at commit rather than at the nightly P14 run — [ADR-0005](adr/ADR-0005-relay-architecture.md) §11.2(a)–(b)); the §3.5 **L-3 lint** (no direct platform time/random call outside a provider); the redaction lint feeding PB-7; and the **[ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §11.8 step-3 dependency-graph assertion** — data-plane modules MUST NOT link the control-plane client library (**P15**'s static half; mutant `M-P15-7` exists to prove this check is live) |
| **T2** | Everything in T1, plus levels 5 (interop, (N,N-1) pairs only), 6 (integration), 9 (networking), 10-subset (NAT traversal: the `DIRECT_EXPECTED` and `RELAY_EXPECTED` classes, 5 runs each), 11 (relay), 12-regression (security regression corpus, incl. every shrunk property counterexample and every past leak), 18-N-1 (upgrade), and a **proof-test smoke set**: P01, P02, P03, P05, P07, P09-A, P12 |
| **T3** | Everything in T2, plus **all twenty-two proof tests P01–P22 with their full mutant sets** (§4 and §4.3), levels 8 (platform, incl. the physical device farm), 10-full (the whole NAT class matrix at the §3.6 run counts), 13 (fuzz, fixed CPU budget against changed targets), 14-deep (property, ≤ 2 h), 15 (chaos), 16-trend (performance trend on pinned rigs), 19 partial (capability probes + E2E smoke per supported target), and the **§4.2 consistency checks C-1…C-4** against a real multi-replica control plane |
| **T4** | Everything in T3, plus levels 5-full (the whole version matrix incl. `below-minimum`), 12-full (the complete adversarial battery of §2.14), 16-gate (performance as a release gate against the noise band), 17 (72 h soak), 18-full (rolling upgrade, downgrade, mixed fleet, interrupted upgrade), 19 (full compatibility matrix on real hardware) |

**Rule C-3 — the proof tests are a T3 gate and a T4 gate.** A subset runs in T2 for fast
feedback, but a T2 pass is never evidence for a release. The **mutant sets run only in T3 and
T4**, because a proof test without its mutants is not known to test anything (**V2**, PT-1).

**Rule C-4 — continuous fuzzing is not a tier.** The fuzz fleet runs continuously against `main`
with a persistent deduplicated corpus. It does not gate a merge; it files, and its findings enter
the release-blocker list of §6.5 immediately.

### 6.3 Flake policy (V7)

**Flake is a bug with an unknown cause.** The policy exists to stop it being managed as noise.

| Rule | Detail |
|---|---|
| **F-1 Detection** | A test is *flaky* when the same test at the same commit and the same seed produces different verdicts. Because seeds are recorded (§3.6), this is decidable rather than a judgement call |
| **F-2 No retry-into-green** | An automatic retry is permitted **only** where the retry is recorded, counted against the flake budget, and attributed to a named test. A green-after-retry result is reported as `FLAKY`, never as `PASS` |
| **F-3 Quarantine and file, together** | A flaky test is quarantined **and** an issue is filed in the same action. Quarantine without a filed issue is prohibited; it is how a suite quietly stops testing |
| **F-4 Budget** | Per tier, per week: T1 ≤ 0.1 %, T2 ≤ 0.3 %, T3 ≤ 0.5 % of executions may be `FLAKY`. Exceeding the budget makes the tier itself red |
| **F-5 Quarantine expiry** | A quarantined test must be fixed or deleted within **14 days**. At 14 days the quarantine expires and the test returns to gating, red |
| **F-6 Proof tests cannot be quarantined** | A flaky **P01–P22**, or a flaky test covering an invariant I1–I8, blocks the release outright. There is no quarantine path for the acceptance criteria |
| **F-7 Determinism regressions** | A scenario declared `BIT` (§3.5) that produces two different event sequences at one seed is not flake — it is a **determinism defect**, filed against the scenario or against L-3, at P1 |

### 6.4 Performance gating

Performance is gated only at T4, against a baseline built the same way, on the same pinned rig,
bound to an exact commit or an immutable dirty-worktree snapshot. The noise band is established
from repeated runs on that rig; **a result outside the band is a failure, not a re-run** (§2.16).
A regression on router-class targets is release-blocking at a lower threshold than on desktop,
because headroom is smallest there (R-21).

### 6.5 Release criteria — what blocks a release

A release candidate is blocked by **any** of the following. The list is exhaustive; anything not
on it does not block, and anything on it is not waivable by schedule.

| # | Blocker |
|---|---|
| **B-1** | Any of **P01–P22** failing, or passing while any mutant in its set also passes, or lacking a green positive control in the same session (PT-1, **V2**, **V4**). The application-layer tests P16–P22 (§4.3) are inside this row, not beside it — they carry the only PROOF-class evidence for R-25 … R-49. Where a procedure is **not executable on a target** (P20 A/B/D on iOS, §4.3), the declared inheritance stands in for it and is recorded as such; a procedure that is merely *skipped* is a failure |
| **B-2** | Any proof test or invariant-covering test in quarantine (F-6) |
| **B-3** | A new unique crash, hang, OOM, or sanitizer report from any fuzz target — regardless of perceived exploitability (§2.12) |
| **B-4** | A non-append-only `reason_code` registry diff, or a registered code missing a required attribute (§2.4 checks 3–4, R-22) |
| **B-5** | A breaking schema diff without the `ProtocolVersion` bump [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) requires, or a changed golden vector without an accompanying wire-format change (§2.3) |
| **B-6** | A `DIRECT_EXPECTED` NAT pair falling back to `RELAYED`, or a `RELAY_EXPECTED` pair claiming `WAN_DIRECT` (§2.10, §3.6) |
| **B-7** | Any leak test negative **without** its positive control green on the same rig in the same session (**V4**) — an unproven observation channel is not a negative result |
| **B-8** | Any supported target in §2.18's matrix failing its capability probe or E2E smoke set, unless it is removed from the supported matrix in the same release |
| **B-9** | A performance result outside the noise band on a pinned rig at T4 (§6.4) |
| **B-10** | An unexplained state transition in the 72 h soak — one is investigated, not averaged (§2.17) |
| **B-11** | A `Session` lost during a rolling upgrade, or a downgrade that crashes, corrupts, or silently discards state (§2.15) |
| **B-12** | A property-based counterexample not yet promoted to a permanent regression test (§2.11) |
| **B-13** | Flake budget exceeded in T3 or T4 (F-4) |
| **B-14** | A determinism defect (F-7) in any scenario a proof test depends on |
| **B-15** | A simulator conformance failure (§3.4.2, **V10**) in the run that produced the release evidence — the results are void, not merely suspect |
| **B-16** | An assumption in §0 contradicted by its owning document without every test carrying that assumption's identifier having been re-derived (§0, assumption discipline) |
| **B-17** | Any of the §4.2 consistency checks **C-1…C-4** failing — a decreasing `(net_seq, trust_epoch, doc_version)` observation (C-2) or a non-linearizable revocation history (C-1) falsifies protocol §15's E-1/E-2 escalations and is P1 |
| **B-18** | `CONTROL.CONSISTENCY.FORKED_HISTORY_DETECTED` emitted anywhere in CI **outside** the C-3 fault-injection test — per [ADR-0009](adr/ADR-0009-state-consistency.md) that is a security incident, not a test result |
| **B-19** | The [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §11.8 dependency-graph assertion absent or disabled. **P15 passing at T3 does not substitute**: ADR-0002 states the static check complements and does not replace the blackhole test, so I5 is undischarged with only one of the two |
| **B-20** | Any released artifact lacking a valid platform signature, an RMK-signed manifest entry, a published SBOM, or a transparency-log inclusion proof ([ADR-0021](adr/ADR-0021-packaging-distribution-and-updates.md) §11.17). Owed to this list by ADR-0021; the second row it owed — P20 failing under the PT-1/V2/V4 shape — is **subsumed by the widened B-1** and is not duplicated here |

**Rule C-5 — evidence binding.** Release evidence is bound to an exact commit or immutable
snapshot, and every verdict cites the §3.6 run record that produced it. A verdict without a run
record does not count toward any criterion above.

**Rule C-6 — the honest-release rule.** A release MAY ship with a **known** limitation named in a
specification (iOS boot enforcement, macOS Recovery, `hardware_backed = false` cloning, total
relay-fleet unavailability, and §5.3's one accepted gap **G-4**). It MUST NOT ship with a limitation that is only
known because a test was disabled, quarantined, or retried into green.
