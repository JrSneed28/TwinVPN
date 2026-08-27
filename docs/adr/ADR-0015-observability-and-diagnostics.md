# ADR-0015: Observability and Diagnostics

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** TESTING
- **Related:** [ADR-0003](ADR-0003-network-contract-schema-format.md), [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md), [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md), [ADR-0005](ADR-0005-relay-architecture.md), [ADR-0006](ADR-0006-relay-discovery-and-failover.md), [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md), [../threat-model.md](../threat-model.md), [../reliability.md](../reliability.md), [../testing-strategy.md](../testing-strategy.md), [../vision.md](../vision.md)

> **Scope.** This ADR decides how TwinVPN observes itself: the structured `reason_code`
> taxonomy and its stability guarantees, the client-side diagnostic surface and the
> self-service connectivity report, log levels and redaction, metrics, traces, health
> reporting, crash reporting, and the remote-support workflow. It also decides the privacy
> posture of all of the above — what is collected by default, what requires opt-in, what is
> never collected — and specifies the mechanism that makes *silent tunnel failure*
> structurally impossible. It discharges requirements **R-18**, **R-22**, **R-23** and is the
> enforcement mechanism for invariant **I6**.
>
> **Related documents:** [docs/vision.md](../vision.md) (requirement IDs R-01…R-24),
> [docs/testing-strategy.md](../testing-strategy.md) (how each claim here is falsified),
> [docs/threat-model.md](../threat-model.md) (adversaries, including the observability
> backend as a trust boundary), [docs/reliability.md](../reliability.md) (the canonical
> `ConnectionState` machine whose transitions this ADR requires to be observable).

---

## 1. Context

The PairVPN defect list contains three failures that are purely observability failures, and a
fourth that is caused by their absence:

| Defect | Requirement | What actually went wrong |
|---|---|---|
| Cryptic error codes | **R-22** | The primary user-facing signal was a bare number or an OS errno. Users could not act; support could not triage; engineering could not reproduce. |
| Insufficient diagnostics | **R-23** | There was no way to learn *which* connection attempt failed and *why* without a debug build. Field failures were unfalsifiable. |
| Firewall / AV conflicts | **R-18** | The system could not name the third-party component interfering with it, so every such failure looked like "connection failed". |
| Silent fallback to non-tunneled networking | **R-13** | Protection was lost and *nothing said so*. This is a security defect (I3), but its proximate cause is that the product had no mechanism that made loss-of-protection an observable, asserted fact. |

Invariant **I6** raises this from a quality concern to an architectural constraint: *every*
failure surfaces a structured, actionable diagnostic. Product principle **P6** ("every failure
has a name") and **P10** ("diagnosability is designed, not added") make it a review gate.

The countervailing constraint is that TwinVPN is a **VPN**. Observability data about a VPN is
exactly the metadata the VPN exists to protect. A telemetry pipeline that reports "device A
connected to peer B via relay in region R at time T" reconstructs the user's private peer
graph and their movements — a dataset that infrastructure is forbidden from holding under
**I1**'s intent, delivered through the back door. Telemetry is therefore not a preference to be
traded against debuggability; it is a **trust boundary and an adversary in its own right**, and
[docs/threat-model.md](../threat-model.md) is the authority on that actor. This ADR must
deliver world-class diagnosability *without* creating a deanonymization channel, and the two
goals genuinely conflict.

A third constraint comes from **I5**: the data plane outlives the control plane. Diagnostics
that require a live control-plane call, or a reachable telemetry collector, are useless in
exactly the situations that most need them — the network is broken. Diagnostics MUST be
local-first and MUST work with zero network connectivity.

A fourth comes from the platform range (R-21): the same observability design must run on a
desktop, on a mobile OS that suspends the process, and on an OpenWrt-class router with tens of
megabytes of RAM and no persistent writable storage worth speaking of.

---

## 2. Requirements

Normative requirements this ADR must satisfy. RFC 2119 keywords.

### 2.1 Diagnostic semantics

| # | Requirement |
|---|---|
| **O-01** | Every terminal and degraded `ConnectionState` MUST carry a stable machine-readable `reason_code`, a human-actionable explanation, and a suggested next action (R-22, I6). |
| **O-02** | A bare numeric code, an OS errno, a raw exception string, or the text "connection failed" MUST NOT be the primary user-facing signal. Underlying OS errno values MAY be carried as *evidence* attached to a `reason_code`, never as a substitute for one. |
| **O-03** | `reason_code` values MUST be stable across releases: append-only, never renamed, never re-pointed at different semantics, never reused after retirement. |
| **O-04** | Every `reason_code` MUST declare a failure **class** (`TRANSIENT` / `PERSISTENT` / `POLICY` / `FATAL`) consistent with the recovery classification in [docs/reliability.md](../reliability.md) (R-09). |
| **O-05** | Every state transition in the canonical `ConnectionState` machine MUST emit exactly one structured transition event carrying `{from, to, trigger, reason_code, session_id, path_id, occurred_at}`. Emission MUST be a property of the transition itself, not of a call site. |

### 2.2 Self-service diagnosis

| # | Requirement |
|---|---|
| **O-06** | The client MUST be able to produce a **connectivity report** explaining, for a failed or degraded connection, every `ConnectionCandidate` that was tried, the result of each, and which constraint blocked success — without a rebuild, a debug binary, a restart, or a log-level change (R-23). |
| **O-07** | The connectivity report MUST be producible with no network connectivity and with the control plane unreachable (I5). |
| **O-08** | The system MUST attempt to name a suspected interfering third-party component (host firewall, endpoint-security product, captive portal, transparent proxy, DNS interceptor) in the diagnostic rather than reporting a generic failure (R-18). |
| **O-09** | The report MUST cover IPv4 and IPv6 as co-equal families. A report that diagnoses v4 reachability and omits v6 is incomplete and MUST be treated as a defect (P9). |
| **O-10** | The user MUST be able to inspect the full contents of any diagnostic artifact **before** it leaves the device. |

### 2.3 Privacy

| # | Requirement |
|---|---|
| **O-11** | No observability mechanism may transmit off-device, by default, any data that identifies a `Device`, an `Owner`, a `TrustedPeer`, a peer pair, or a `Session`. |
| **O-12** | Tunnel plaintext, packet payloads, private key material, pairing secrets, and pre-shared material MUST NEVER be written to any log, metric, trace, crash artifact, or diagnostic bundle at any log level, in any build, including debug builds. |
| **O-13** | Relay and rendezvous infrastructure MUST NOT retain any record that correlates two peers of a `Session` with each other. Aggregate and per-region counters are permitted; the peer-pair tuple is not (I1). |
| **O-14** | Redaction MUST be enforced at **emit** time by schema-level field classification, not at export time by pattern matching over rendered text. |
| **O-15** | Any off-device transmission of diagnostics MUST be user-initiated or explicitly opted into, MUST state what is being sent, and MUST be revocable. |

### 2.4 Anti-silence

| # | Requirement |
|---|---|
| **O-16** | Loss of protection MUST be surfaced as state within a bounded, specified detection interval. "Nothing happened and nothing was said" MUST NOT be a reachable outcome (I3, R-13). |
| **O-17** | The reported protection status MUST be derived from the **enforcement layer's observed state**, not from the agent's belief about what it configured. |
| **O-18** | An agent that has hung, crashed, or been suspended MUST NOT be able to leave a stale "protected" indication displayed. |

### 2.5 Operability

| # | Requirement |
|---|---|
| **O-19** | Observability MUST function on router-class targets: bounded memory, bounded write volume, no mandatory persistent storage, no mandatory outbound telemetry connection (R-21). |
| **O-20** | Infrastructure (relays, rendezvous, control plane) MUST expose health and metrics sufficient to operate an SLO, subject to O-13. |
| **O-21** | Diagnostic artifacts MUST be integrity-protected so that support can distinguish a genuine bundle from a fabricated or truncated one. |

---

## 3. Constraints

| # | Constraint | Source |
|---|---|---|
| **C-1** | Infrastructure is zero-knowledge with respect to user traffic; observability MUST NOT weaken that, including by metadata aggregation. | I1 |
| **C-2** | Diagnostics MUST work while the control plane is down. | I5 |
| **C-3** | `reason_code` is part of the wire contract; its *encoding*, schema, and compatibility rules are owned by [ADR-0003](ADR-0003-network-contract-schema-format.md) and its version negotiation by [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md). This ADR owns the taxonomy and its stability guarantees, not the serialization. | ADR-0003, ADR-0014 |
| **C-4** | The set of `ConnectionState` names is fixed by the shared brief; the transitions are owned by [docs/reliability.md](../reliability.md). This ADR imposes an *emission* obligation on those transitions, it does not define them. | Brief |
| **C-5** | Mobile platforms suspend and terminate the process arbitrarily; the observability store MUST tolerate abrupt termination without corruption and MUST NOT rely on graceful shutdown to flush. | R-08 |
| **C-6** | Router-class targets may have no writable persistent filesystem. The default event store MUST be an in-memory ring buffer; persistence is an opt-in upgrade. | R-21 |
| **C-7** | Telemetry that is off by default cannot be relied on for fleet-wide regression detection. This ADR must accept degraded fleet visibility as a cost, and [docs/testing-strategy.md](../testing-strategy.md) must compensate with pre-release verification. | Privacy posture |
| **C-8** | No novel cryptography, including for any privacy-preserving aggregation scheme; only audited, published constructions. | I2 |

---

## 4. Considered Alternatives

**Alternative A — OpenTelemetry end-to-end.**
One OTel SDK in the client and in every infrastructure component. Traces span the client, the
rendezvous, the relay, and the control plane, correlated by a propagated trace ID. Metrics and
logs are exported over OTLP to a vendor-neutral collector and stored centrally. Sampling and
redaction are handled by collector-side processors.

**Alternative B — Prometheus metrics on infrastructure plus structured local logs on clients.**
Infrastructure exposes a Prometheus scrape endpoint with aggregate counters and histograms; no
client telemetry pipeline exists at all. Clients write structured JSON-lines logs locally, at
a user-controlled level, which the user can find on disk and attach to a support request
manually.

**Alternative C — Bespoke diagnostics bundle.**
The client maintains a purpose-built, always-on, in-memory structured event ledger with a
domain-specific schema (candidate ledger, transition ledger, enforcement-state snapshots). A
single command or button renders a signed, redacted bundle. No continuous export exists;
diagnosis is a discrete artifact-producing act. Infrastructure keeps its own separate
operational metrics.

**Alternative D — Telemetry off by default, local-only diagnostics.**
The strongest privacy posture: nothing observability-related ever leaves the device unless the
user performs an explicit export. No opt-in aggregate channel exists at all. Fleet health is
inferred exclusively from infrastructure-side aggregates that never touch user identity, and
from pre-release testing.

**Alternative E — Local-first diagnostics plus opt-in privacy-preserving aggregate telemetry.**
Alternative C's local ledger and bundle as the always-on substrate; Alternative B's Prometheus
posture on infrastructure with a strict field allowlist; plus a third, separately opted-in
channel that submits only coarse, non-identifying, k-anonymous aggregate counters using a
published aggregation construction (e.g. Prio-style or STAR-style aggregation), carrying no
device identifier, no peer identity, no timestamps finer than a day bucket, and no free text.

---

## 5. Advantages of Each Alternative

| Alternative | Advantages |
|---|---|
| **A — OpenTelemetry end-to-end** | Best-in-class causal debugging: a single trace shows candidate gathering, rendezvous exchange, hole-punch attempts, and relay selection as one connected story. Enormous mature ecosystem — collectors, processors, backends, exemplars, correlation between metric and trace. Vendor-neutral and therefore not a lock-in decision. Fleet-wide regression detection is essentially free. Semantic conventions mean less bespoke schema design. Sampling gives cost control at high volume. |
| **B — Prometheus + structured local logs** | Operationally boring in the best sense; Prometheus is the least surprising choice for relay/control-plane SLOs and alerting, with excellent aggregation and no per-event retention by design. Client side has zero network dependency and zero privacy surface. Very low resource cost — a scrape endpoint on infrastructure, an append-only file on the client. Easy to reason about what infrastructure holds: counters, not events. |
| **C — Bespoke diagnostics bundle** | The schema is designed for the actual questions ("which candidate failed and why"), which generic tracing answers only obliquely. One artifact, one command, works offline, works when the control plane is down. User can inspect exactly what is being shared, which makes O-10 and O-15 trivially satisfiable. Cheap enough for router-class targets. Signing makes the artifact trustworthy for support. |
| **D — Telemetry off, local-only** | Maximal privacy; the deanonymization channel simply does not exist, which is the only truly robust mitigation. Easiest posture to explain to a security-conscious user and to audit. No collector to breach, no retention policy to get wrong, no jurisdiction question, no consent-management machinery. Aligns most directly with I1's spirit. |
| **E — Local-first + opt-in aggregate** | Retains C's offline, high-fidelity, user-controlled diagnosis and B's boring infrastructure SLOs, while recovering *some* of A's fleet visibility for the specific questions that individual bundles cannot answer ("did the NAT-traversal success rate regress in release N?"). The privacy properties of the aggregate channel are structural (no identifier exists to leak, k-anonymity enforced before submission) rather than policy-based. Each of the three tiers can be reasoned about, tested, and audited independently. |

---

## 6. Disadvantages of Each Alternative

| Alternative | Disadvantages |
|---|---|
| **A — OpenTelemetry end-to-end** | Fatal on privacy: a cross-component trace correlating client, rendezvous, and relay *is* a peer-graph and movement record, and it exists on infrastructure by construction. That directly attacks I1 and O-13. Collector-side redaction is the wrong side of the boundary — the data has already left the device (violates O-14). Trace IDs propagated through a relay create a correlation identifier that relay operators can observe. SDK footprint is far too heavy for router-class targets (C-6, O-19). Requires a reachable collector, so it degrades exactly when needed (C-2). Sampling means the one failure you care about is often not recorded. |
| **B — Prometheus + structured local logs** | Client side is not a *diagnostic system*, it is a pile of text: no candidate ledger, no schema guarantees, no redaction guarantee (O-14 is unmet — freeform log lines will eventually contain endpoints and identifiers), and "find the log file and attach it" is exactly the support experience R-23 exists to abolish. Counters cannot answer "why did *this* connection fail". No correlation across components at all. Prometheus cardinality limits make any per-`Session` or per-peer label impossible — which is *good* for privacy but means infrastructure metrics can never explain an individual failure. |
| **C — Bespoke diagnostics bundle** | All schema, storage, rotation, rendering, and tooling is built from scratch and owned forever; no ecosystem. Zero fleet visibility: a regression in NAT-traversal success rate is invisible until users complain, which is the failure mode PairVPN had. Requires the user to *notice* a problem and *act* — it cannot detect problems the user tolerates. Signing, key handling, and bundle-format versioning are additional surface. Diagnosis quality depends on ring-buffer sizing decisions made long before the incident. |
| **D — Telemetry off, local-only** | Accepts C's blindness permanently and forecloses ever fixing it. Release quality becomes entirely dependent on the pre-release lab, so an environment class the lab does not simulate (real CGNAT, a specific carrier's mobile suspension behavior) can regress silently across many releases. Makes prioritization anecdotal: "some users report symmetric-NAT failures" cannot be sized. Infrastructure-side aggregates alone under-represent the failures that never reach infrastructure at all — the most interesting ones. |
| **E — Local-first + opt-in aggregate** | Three mechanisms instead of one: more to build, more to document, more to test, three separate privacy arguments to keep true. The opt-in channel will have low and *biased* take-up (privacy-motivated users decline), so its aggregates are not a representative sample and must never be treated as one. k-anonymity thresholds add latency to signal (rare-but-severe conditions may never reach the threshold, so the aggregate channel is structurally blind to exactly the tail). Privacy-preserving aggregation adds an infrastructure component with real operational cost, and C-8 constrains which constructions are permissible. |

---

## 7. Security Implications

**Selected option: Alternative E.** Implications of the selected design:

- **The telemetry backend is modelled as an adversary, not as trusted infrastructure.** The
  aggregate channel is designed so that a full compromise of the aggregation service yields
  counters and nothing else: no device identifier, no `Owner` identity, no peer pair, no
  endpoint, no fine-grained time. There is no identifier to correlate across submissions,
  because none is generated.
- **Emit-time classification is the security control.** Every field in every event schema
  carries a classification (§11.4). `SECRET`-classified fields have no rendering path at all —
  the code that would print them does not exist, in any build. This makes O-12 a structural
  property rather than a review discipline, and makes it testable (see
  [docs/testing-strategy.md](../testing-strategy.md), fuzz target and the redaction property test).
- **Relay-side observability is the sharpest risk.** A relay sees both ends of a `RELAYED`
  session by necessity; if it *logs* that, it holds the peer graph, defeating I1 in metadata
  even though it never sees plaintext. O-13 therefore forbids retention of the peer-pair
  correlation, and relay metrics are constrained to aggregates without any per-session label.
  This is a real functional loss for relay operators — per-session debugging on a relay is
  deliberately impossible — and it is the correct trade.
- **The diagnostic bundle is a concentrated secret.** It contains, by design, endpoints,
  interface state, candidate results, and timing. It is the single most sensitive artifact the
  product produces. Mitigations: it never leaves the device without an explicit act; it is
  rendered for inspection first (O-10); sensitive fields are pseudonymized with a
  bundle-scoped random mapping so that structure is preserved and identity is not; it is
  signed by the `DeviceKey` (signature, not encryption — the private half never leaves,
  per I4) so support can detect tampering (O-21); and it carries an expiry.
- **Crash artifacts are a leak vector.** A full core dump of a VPN process contains packet
  buffers and key material. Crash reporting is therefore opt-in, stack-and-registers only,
  with key material and packet buffers held in memory regions explicitly excluded from dumps.
- **Diagnostics are an attack surface.** Bundle generation MUST be rate-limited and MUST
  require local user authorization; a remote-triggerable "generate and send diagnostics"
  command is an exfiltration primitive and MUST NOT exist. Support pulls nothing; the user
  pushes.
- **Where a rejected alternative was better:** Alternative D is strictly better on security.
  It has no aggregate channel to attack, no consent state to get wrong, and no aggregation
  service to operate. The selected option takes on D's entire privacy argument *plus* one
  additional opt-in channel that must be independently defended. This ADR accepts that added
  surface only because the channel is default-off, identifier-free, and separately auditable —
  and §14 defines the condition under which we retreat to D.

---

## 8. Reliability Implications

- **Observability must not be able to break the data plane.** Event emission is
  non-blocking, into a fixed-size lock-free ring buffer, with an explicit drop policy and a
  `dropped_events` counter so that loss is itself observable. A full buffer, a full disk, or a
  stalled export MUST never block, delay, or fail a packet-path or state-machine operation.
  This is a hard rule: the observability subsystem is a strict dependency-inverted consumer.
- **Local-first satisfies I5 directly.** The ledger, the connectivity report, and the bundle
  work with the control plane down and with no network at all (C-2, O-07), which is the
  scenario in which they are actually used.
- **Health reporting feeds recovery, and must not confuse the two.** `HealthState` is an input
  to relay selection and failover ([ADR-0006](ADR-0006-relay-discovery-and-failover.md)); the
  observability system *reports* health, it does not *decide* recovery. Keeping the decision in
  the reliability layer avoids a feedback loop where a telemetry outage looks like a network
  outage.
- **Anti-silence adds a watchdog, and watchdogs can be wrong.** The protection-assertion
  mechanism (§11.6) polls the enforcement layer. A false negative (asserting unprotected when
  protection holds) causes a spurious `DEGRADED`/`BLOCKED` presentation — annoying but
  fail-safe. A false positive is the dangerous direction and is why the assertion reads the
  enforcement layer rather than the agent's own belief (O-17).
- **Ring-buffer sizing bounds forensic reach.** An incident whose root cause scrolled out of the
  buffer is undiagnosable. Mitigation: a separate, small, slow-moving "significant events" ring
  (state transitions, `reason_code` emissions, enforcement changes) retained far longer than
  the verbose ring, so the skeleton of any incident survives even when the detail does not.
- **Where a rejected alternative was better:** Alternative A's continuous export would survive
  device loss and would capture incidents on devices the user never reports. Local-first
  diagnosis is lost if the device is wiped or the user never opens the app.

---

## 9. Performance Implications

- **Steady-state cost budget.** Tier-0 emission on the data path is limited to counter
  increments and, on state transitions only, one structured record. Per-packet logging MUST NOT
  exist at any level in a release build; per-packet *counters* are permitted. Budget: < 1% CPU
  and < 8 MB resident for the observability subsystem on the reference desktop target, and
  < 512 KB resident on the router-class target (C-6, O-19).
- **Structured event cost is paid at render, not at emit.** Events are stored in a compact
  binary/columnar form and rendered to human text only when a report or bundle is produced.
  This keeps the hot path cheap and makes the verbose ring affordable.
- **Cardinality discipline on infrastructure.** Prometheus labels are restricted to a fixed
  allowlist of low-cardinality dimensions (`relay_region`, `protocol_version`,
  `reason_code`, `outcome`, `address_family`). Per-`Session`, per-`Device`, per-peer, and
  per-endpoint labels are forbidden — for privacy first (O-13) and for cost second.
- **The connectivity report is allowed to be expensive.** It is user-initiated, bounded, and
  runs off the data path; a multi-second active probe sequence is acceptable there and is not
  acceptable anywhere else.
- **Where a rejected alternative was better:** Alternative B is the cheapest of all — a scrape
  endpoint and an append-only file. The selected option's binary ledger, dual ring buffers,
  redaction classification, and bundle renderer all cost more code and more memory than B.

---

## 10. Operational Implications

- **Support workflow becomes artifact-driven.** The support interaction is: user reproduces →
  user runs one command or clicks one button → user reviews the rendered summary → user shares
  the bundle → support opens it with a bundle viewer. There is no "please enable debug logging
  and reproduce" step, because Tier 0 is always on (R-23).
- **Two-key triage.** Every support case is keyed by a `reason_code` and a bundle. This makes
  triage classifiable and lets us measure, per release, the distribution of `reason_code`s in
  incoming support cases — a fleet signal that does not require telemetry.
- **Bundle format is a long-lived contract.** Support tooling must open bundles from older
  clients. The bundle carries a format version and MUST be readable by any newer viewer within
  the compatibility window defined in [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md).
- **The `reason_code` registry becomes a release artifact.** It is generated, diffed, and
  reviewed on every release; adding a code is routine, changing one is a breaking change
  requiring the alias mechanism (§11.2). CI enforces this
  ([docs/testing-strategy.md](../testing-strategy.md), contract-test tier).
- **Documentation obligation.** Every `reason_code` has a stable documentation anchor. Shipping
  a code without an anchor and a next-action string fails the release gate — this is the
  mechanical enforcement of R-22.
- **Consent lifecycle to operate.** The Tier-2 opt-in requires a consent record, a
  user-visible "what is shared" surface, a revocation path, and a data-deletion story. This is
  ongoing operational and legal overhead that Alternative D would not have incurred.
- **Aggregation service to run.** Tier 2 requires operating a privacy-preserving aggregation
  service with a k-anonymity threshold — another production system with its own availability
  and upgrade concerns, whose outage must be a no-op for clients.
- **Where a rejected alternative was better:** Alternative A's ecosystem means dashboards,
  alerting, and correlation are configuration rather than construction. The selected option
  requires building the bundle viewer and the ledger tooling ourselves.

---

## 11. Decision

**Adopt Alternative E: local-first, three-tier observability with a strict privacy gradient.**

### 11.1 The three tiers

| Tier | Name | Default | Leaves device | Contents | Purpose |
|---|---|---|---|---|---|
| **Tier 0** | Local structured ledger | **Always on**, cannot be disabled | **Never** | Full structured event ledger: state transitions, `ConnectionCandidate` ledger, enforcement-layer snapshots, `reason_code` emissions, counters | Make every failure diagnosable on the device, offline |
| **Tier 1** | Diagnostic bundle / connectivity report | Off (produced on demand) | **Only by explicit user act**, per artifact | Rendered subset of Tier 0 for a bounded window, redacted and pseudonymized, signed, expiring | Self-service diagnosis (R-23) and remote support |
| **Tier 2** | Aggregate outcome telemetry | **Off**, opt-in | Only when opted in | Coarse, identifier-free, k-anonymous counters: `{reason_code, outcome, address_family, nat_class, protocol_version, platform_class, day_bucket}` | Fleet regression detection only |

Infrastructure (relays, rendezvous, control plane) is operator-owned and observed separately
with Prometheus-style aggregate metrics plus internal traces that **terminate at the component
boundary** — no trace context is propagated across a relay, and no per-session identifier is
recorded (O-13). OpenTelemetry as an *internal, infrastructure-side* instrumentation library is
permitted; OpenTelemetry as an *end-to-end client-to-backend pipeline* is rejected.

### 11.2 `reason_code` taxonomy

Format: `DOMAIN.CONDITION` or `DOMAIN.SUBDOMAIN.CONDITION` — uppercase, dot-separated, ASCII,
≤ 64 bytes. The `SUBDOMAIN` segment is **optional** and is used where a domain has enough codes to
warrant grouping (e.g. `POLICY.KILLSWITCH.*`, `POLICY.LEAK.*`, `CONTROL.STALENESS.*`); a two-part
code is equally canonical. **`DOMAIN` is the only segment with registry meaning** — forward
compatibility is by `DOMAIN` prefix (rule 4 below), so a receiver that does not know a code
degrades on its first segment regardless of how many segments follow.

`reason_code` is carried on the wire as a **`string`**, never as an enum: prefix degradation and
unknown-code passthrough both require the receiver to hold the unrecognised code's text, and a
protobuf enum preserves an unknown value only as an integer, which discards the `DOMAIN`. This is
normative for [ADR-0003](ADR-0003-network-contract-schema-format.md) and
[ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md).

| Domain | Owns | Illustrative codes |
|---|---|---|
| `NET` | Local network and reachability, path quality, link and session lifecycle (**owner: [docs/networking.md](../networking.md) for reachability; [docs/reliability.md](../reliability.md) for `NET.PATH.*`, `NET.SESSION.*`, `NET.QOS.*`, `NET.LINK.*`**) | `NET.NO_ROUTE`, `NET.IFACE_DOWN`, `NET.MTU_TOO_SMALL`, `NET.V6_UNREACHABLE`, `NET.CAPTIVE_PORTAL` |
| `NAT` | Traversal outcomes (**owner: [ADR-0004](ADR-0004-nat-traversal-strategy.md), which MUST register its codes in §11.2 form**) | `NAT.SYMMETRIC_BOTH_ENDS`, `NAT.CGNAT_DETECTED`, `NAT.PUNCH_TIMEOUT`, `NAT.NO_SERVER_REFLEXIVE` |
| `RELAY` | Relay selection/health (ADR-0005/0006) | `RELAY.NONE_REACHABLE`, `RELAY.REGION_UNAVAILABLE`, `RELAY.CAPACITY_REJECTED`, `RELAY.FAILOVER_EXHAUSTED` |
| `AUTH` | Identity, pairing, revocation (ADR-0007) | `AUTH.DEVICE_REVOKED`, `AUTH.PEER_UNTRUSTED`, `AUTH.KEY_UNAVAILABLE`, `AUTH.PAIRING_EXPIRED` |
| `CRYPTO` | Handshake and key state (**owner: [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md), which MUST register its codes in §11.2 form**) | `CRYPTO.HANDSHAKE_REJECTED`, `CRYPTO.REKEY_FAILED`, `CRYPTO.REPLAY_DETECTED` |
| `PROTO` | Versioning and contracts (ADR-0003/0014) | `PROTO.VERSION_UNSUPPORTED`, `PROTO.CAPABILITY_MISSING`, `PROTO.DOWNGRADE_REFUSED`, `PROTO.MALFORMED_MESSAGE` |
| `POLICY` | Kill switch, access, egress, leak prevention (ADR-0012/0013) | `POLICY.KILLSWITCH.ENGAGED`, `POLICY.LEAK.IPV6_UNPROTECTED`, `POLICY.EXIT_NOT_PERMITTED`, `POLICY.LAN_ACCESS_DENIED` |
| `DNS` | Resolution and `DNSPolicy` (ADR-0011) | `DNS.RESOLUTION.UPSTREAM_UNREACHABLE`, `DNS.POLICY.RULE_CONFLICT`, `DNS.INTERCEPTION_DETECTED` |
| `ROUTE` | Route and interface programming (**owner: [ADR-0010](ADR-0010-ipv4-ipv6-routing.md), which MUST register its codes in §11.2 form**) | `ROUTE.ADDRESS_COLLISION`, `ROUTE.IFACE_CONFLICT`, `ROUTE.PROGRAMMING_DENIED` |
| `PLATFORM` | OS integration and host-process lifecycle (**owner: [docs/architecture.md](../architecture.md) §2.5, the Platform Network Adapter**; R-17…R-20) | `PLATFORM.VPN_PERMISSION_DENIED`, `PLATFORM.ADAPTER_UNAVAILABLE`, `PLATFORM.THIRD_PARTY_FILTER_SUSPECTED`, `PLATFORM.OS_UNSUPPORTED` |
| `RESOURCE` | Capacity and limits (ADR-0013) | `RESOURCE.PEER_LIMIT_REACHED`, `RESOURCE.MEMORY_EXHAUSTED` |
| `CONTROL` | Control-plane availability, staleness, consistency, event-bus integrity (ADR-0002/0009) | `CONTROL.UNREACHABLE`, `CONTROL.STALENESS.DOCUMENT_STALE`, `CONTROL.CONSISTENCY.REPLICA_BEHIND_CURSOR`, `CONTROL.EVENT_WRONG_PUBLISHER` |
| `INTERNAL` | Defects. Every occurrence is a bug. | `INTERNAL.INVARIANT_VIOLATED`, `INTERNAL.UNEXPECTED_STATE` |
| `MGMT` | The **local management interface**: attachment, authorization, version negotiation, local-client lifecycle (**owner: [ADR-0017](ADR-0017-local-management-interface.md)**, which delegates the `MGMT.CONFIG.*` subdomain to [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)) | `MGMT.UNAVAILABLE`, `MGMT.PRINCIPAL_UNVERIFIABLE`, `MGMT.STREAM_COMPACTED`, `MGMT.DISARM_REQUIRES_LOCAL_AUTH`, `MGMT.CONFIG.*` |
| `STORE` | **Local persistence and secure storage**: vault, sidecars, and the Tier-1 items it owns (**owner: [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md)**). Identity/key conditions remain `AUTH.*` | `STORE.VAULT_CORRUPT`, `STORE.ROLLBACK_DETECTED`, `STORE.CUSTODY_DEGRADED`, `STORE.PRESERVE_RULE_MISSING` |
| `UPDATE` | **Artifact delivery and application**: manifest, verification, staged apply, rollback, managed configuration (**owner: [ADR-0021](ADR-0021-packaging-distribution-and-updates.md)**) | `UPDATE.MANIFEST.ROLLBACK_REFUSED`, `UPDATE.VERIFY.DIGEST_MISMATCH`, `UPDATE.APPLY.WINDOW_EXCEEDED` |

**Mapping the connection-lifecycle conditions (normative).** [docs/reliability.md](../reliability.md)
emits codes for path, session, quality, link, credential, version and peer conditions. These do
**not** get new top-level domains — adding one per concept is how a registry rots. They map onto
existing domains by subdomain:

> **The domain set is closed by an admission rule, not by a count.** It stood at thirteen; the
> application-architecture workstream added three (`MGMT`, `STORE`, `UPDATE`), bringing it to
> **sixteen**. A new top-level domain is admissible **only** when no existing domain is a correct
> owner — because prefix degradation (rule 5) would otherwise produce an actively wrong diagnosis,
> not merely a vague one. The worked case: a local-agent failure spelled `CONTROL.*` would make an
> older client render "the coordination service is unreachable — check your internet connection"
> when the truth is "the local service is not running" — opposite diagnoses with opposite next
> actions. A condition that merely *feels* new takes a subdomain. Every domain names exactly one
> owning document.

| Condition family | Subdomain | Examples |
|---|---|---|
| Path lifecycle and migration | `NET.PATH.*` | `NET.PATH.MIGRATED`, `NET.PATH.MIGRATION_ABORTED`, `NET.PATH.MIGRATION_FAILED`, `NET.PATH.DIRECT_LOST` |
| `Session` lifecycle | `NET.SESSION.*` | `NET.SESSION.RECOVERED`, `NET.SESSION.NEGOTIATION_FAILED`, `NET.SESSION.CLOSED_BY_USER`, `NET.SESSION.RETRY_PRECONDITION_MET` |
| Measured quality violations | `NET.QOS.*` | `NET.QOS.RTT_HIGH`, `NET.QOS.LOSS_HIGH`, `NET.QOS.JITTER_HIGH`, `NET.QOS.DEGRADED_TIMEOUT`, `NET.QOS.RESTORED` |
| Underlay link transitions | `NET.LINK.*` | `NET.LINK.DOWN_WIFI`, `NET.LINK.DOWN_CELLULAR`, `NET.LINK.CHANGED_ETHERNET` |
| Interface and MTU programming | `ROUTE.*` / `NET.*` | `ROUTE.IFACE_MISSING`, `ROUTE.DRIFT_DETECTED`, `NET.MTU_BLACKHOLE_DETECTED` |
| Credential lifecycle | `AUTH.*` | `AUTH.CRED_EXPIRED` — and, where [ADR-0007](ADR-0007-device-identity-and-pairing.md) already registers the condition, **its** code wins (`AUTH.DEVICE_REVOKED`, `AUTH.PEER_UNTRUSTED`) |
| Version incompatibility | `PROTO.*` | `PROTO.VERSION_UNSUPPORTED` — [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)'s code, not a second one |
| Host process lifecycle | `PLATFORM.*` | `PLATFORM.PROCESS_RESTARTED`, `PLATFORM.SUSPENDED`, `PLATFORM.CRASH_LOOP` |

**Rule 7 — segment count.** A code has **two or three** segments. Four or more is malformed and MUST
be rejected by the registry's CI check, because `DOMAIN` is the only segment with forward-compatibility
meaning and deeper nesting buys nothing while breaking prefix degradation.

**Rejected alternative: a flat `TVPN-<FAMILY>` prefix scheme (recorded 2026-08-27).**

During Phase 2 contract implementation a flat family scheme was proposed —
`TVPN-AUTH`, `TVPN-PAIR`, `TVPN-NAT`, `TVPN-RELAY`, `TVPN-TUNNEL`, `TVPN-ROUTE`,
`TVPN-DNS`, `TVPN-IPV4`, `TVPN-IPV6`, `TVPN-POLICY`, `TVPN-PLATFORM`,
`TVPN-PROTOCOL`, `TVPN-CONTROL`, `TVPN-UPDATE`, `TVPN-INTERNAL`. It is
**rejected**, and recorded here so it is not re-proposed. This is conflict
**CF-3** in `contracts/docs/phase1-conflicts.md`.

Three reasons, in order of weight:

1. **A product-name prefix carries no information and destroys the one segment
   that does.** Forward compatibility in this taxonomy is by `DOMAIN` prefix
   (rule 5): a receiver meeting an unknown code degrades on its first segment.
   Under `TVPN-*` the first segment is `TVPN` on every code, so there is nothing
   to degrade on — every unknown code degrades to "it is a TwinVPN error", which
   is what the user already knows. Every code in this product is a TwinVPN code;
   saying so costs five bytes and buys nothing.

2. **`TVPN-IPV4` and `TVPN-IPV6` would make the family asymmetry the corpus
   forbids *expressible*, in the one layer where no owning ADR would look for
   it.** [ADR-0010](ADR-0010-ipv4-ipv6-routing.md) R1 makes the families
   co-equal; [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)
   §11.11 refuses a per-family `scope` parameter on `kill_switch_os/1` in exactly
   these terms, because it would make a v4-only kill switch *expressible,
   negotiable and contagious*. Per-family **domains** do the same thing to the
   diagnostic layer: they make "we have a v4 story and a v6 story" sayable, when
   the design is that there is **one** story covering both. Address family is
   therefore an **evidence field** (`Evidence.family_value`), never a namespace —
   so a v4 failure and a v6 failure are the *same* condition with different
   evidence, and neither can acquire a diagnostic vocabulary the other lacks.

3. **`TVPN-PAIR` and `TVPN-TUNNEL` split conditions that have one owner.**
   Pairing is an identity condition and lives in `AUTH.PAIRING_*`; a separate
   domain would split identity across two prefixes and force prefix degradation
   to choose between them. "Tunnel" spans **two** owners — handshake and key state
   belong to [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)
   (`CRYPTO.*`), path and session lifecycle to
   [docs/reliability.md](../reliability.md) (`NET.PATH.*`, `NET.SESSION.*`) — and a
   single `TVPN-TUNNEL` domain would violate the rule that every domain names
   exactly one owning document.

The scheme's legitimate goal — *"every error must have a stable, greppable,
documented identifier, and no user may ever see a bare `Error 110`"* — is fully
met by the existing taxonomy, and more strongly: every code carries `class`,
`severity`, `terminal`, `user_actionable`, `remediation_class`, `scope`,
`doc_anchor` and declared `evidence_fields`, and a `user_actionable` code without
a `next_action_key` fails the registry's CI check.

**Domain contribution rule.** This ADR owns the taxonomy, the namespace, the required
attributes, and the stability rules. The ADR owning a domain contributes and names the codes
within it. `INTERNAL` is owned here.

**Required attributes of every registered code:**

```
reason_code:            NAT.SYMMETRIC_BOTH_ENDS
class:                  TRANSIENT | PERSISTENT | POLICY | FATAL
severity:               INFO | WARN | ERROR | CRITICAL
terminal:               true | false
user_actionable:        true | false
summary_key:            i18n key for the one-line human explanation
next_action_key:        i18n key for the suggested next action (required if user_actionable)
doc_anchor:             stable documentation anchor
evidence_fields:        declared, classified fields this code may attach
introduced_in:          protocol/registry version
status:                 ACTIVE | DEPRECATED | RETIRED
alias_of:               (DEPRECATED only) the replacement code
```

**Stability guarantees:**

1. The registry is **append-only**. A code MUST NOT be renamed, and its semantics MUST NOT
   change once `ACTIVE`.
2. A retired code's identifier MUST NOT be reused for different semantics, ever.
3. Refining a code (splitting it) MUST add new codes and mark the old one `DEPRECATED` with
   `alias_of` pointing forward; peers within the compatibility window MUST continue to accept
   the deprecated code.
4. The **code is the contract; the human text is not.** Summary and next-action strings MAY be
   reworded or re-translated at any time. Automation, tests, and support tooling MUST key on
   the code and MUST NOT match on text.
5. A receiver encountering an unknown `reason_code` MUST degrade to its `DOMAIN` prefix and
   present a domain-level explanation rather than failing — the taxonomy is
   forward-compatible by prefix. It MUST NOT display the raw unknown code as the primary
   signal (O-02). **Degradation is by *attributes*, not by prefix alone:** every carrier of a
   `Diagnostic` MUST transmit the registry attributes (`class`, `severity`, `terminal`,
   `user_actionable`, `remediation_class`, `scope`, `doc_anchor`) **for unrecognised codes as
   well as known ones**. Prefix alone is insufficient at the application layer — a receiver
   cannot choose a correct affordance from a bare string, and could not tell a `POLICY`-class
   condition that must not be dismissible from an `INFO` one that should be transient. The
   attributes are metadata only: each is an enum, a boolean, or a stable anchor. A carrier MUST
   NOT add a localized `summary`, `message`, or `title` field — that would place a second text
   authority outside the registry and defeat rule 4.
6. The registry ships as a machine-readable artifact and is diffed in CI against the previous
   release; a non-append-only diff fails the build.

#### 11.2.1 The `INTERNAL` registry (owned here, because no other document can own it)

Every other domain is registered by its owning ADR. `INTERNAL` has no owner but this one, so its
codes are enumerated here. Adding a code to this domain is an admission that a defect class exists
and is worth distinguishing — **not** a licence to route ordinary failures into it (§14's revisit
condition on `INTERNAL` support volume exists to catch exactly that drift).

| `reason_code` | class | sev | terminal | user-act. | Condition → next action |
|---|---|---|---|---|---|
| `INTERNAL.INVARIANT_VIOLATED` | FATAL | CRITICAL | yes | no | A state-machine or ownership invariant did not hold. Enforced at the state-machine boundary (§11.6). Every occurrence is a defect |
| `INTERNAL.UNEXPECTED_STATE` | FATAL | CRITICAL | yes | no | A transition was requested from a state that does not permit it. Every occurrence is a defect |
| `INTERNAL.CORE_PANIC` | FATAL | CRITICAL | **instance**-terminal, not `Session`-terminal | no | A panic was caught at the ABI boundary ([ADR-0018](ADR-0018-shared-core-and-build-architecture.md) F-7). The instance is **poisoned**; the shell destroys and re-creates it and the `Session` re-enters `RECONNECTING` from durable state. **Enforcement stays installed** — a contained panic MUST NOT tear down the rule set. Every occurrence is a defect |
| `INTERNAL.ABI_VERSION_MISMATCH` | FATAL | CRITICAL | yes | **yes** | The shell's compiled `abi_major` is outside the loaded core's supported range ([ADR-0018](ADR-0018-shared-core-and-build-architecture.md) VR-4). → "Reinstall the application as one artifact"; on distribution-packaged Linux, "install matching package versions". Carries `next_action_key` as well as `summary_key`, per rule 5's required attributes |

**Note on `CORE_PANIC`'s terminality**, because it is the one row that does not read like the
others: it is terminal for the *core instance* and not for the `Session`. Treating it as
`Session`-terminal would convert a contained, recoverable defect into a user-visible disconnection
and would discard exactly the durable state the recovery path depends on.

### 11.3 The `Diagnostic` record

Every terminal and degraded state carries exactly one of these:

```
Diagnostic {
  reason_code      : string        # the taxonomy code                         [PUBLIC]
  class            : enum          # TRANSIENT|PERSISTENT|POLICY|FATAL         [PUBLIC]
  severity         : enum                                                      [PUBLIC]
  summary          : localized     # one line, human, no jargon                [PUBLIC]
  next_action      : localized     # what the user should do, or null          [PUBLIC]
  doc_anchor       : string                                                    [PUBLIC]
  occurred_at      : timestamp                                                 [OPERATIONAL]
  component        : enum          # which component observed it               [OPERATIONAL]
  state_from       : ConnectionState                                           [OPERATIONAL]
  state_to         : ConnectionState                                           [OPERATIONAL]
  correlation_id   : local-only id # never transmitted off-device              [SENSITIVE]
  evidence         : [Evidence]    # typed, classified, code-declared          [varies]
}
```

`Evidence` is where OS errnos, `getaddrinfo` results, firewall-rule query output, and probe
results live — attached to a code, never in place of one (O-02). Each evidence field's
classification is declared in the registry, which is what makes redaction mechanical (O-14).

### 11.4 Field classification and redaction

| Class | Meaning | Tier 0 (local) | Tier 1 (bundle) | Tier 2 (aggregate) |
|---|---|---|---|---|
| `PUBLIC` | Carries no user-identifying information | stored | included | included |
| `OPERATIONAL` | Timing, states, counters, coarse categories | stored | included | bucketed or dropped |
| `SENSITIVE` | Endpoints, addresses, interface names, `DeviceIdentity`, peer identifiers, hostnames, SSIDs | stored | **pseudonymized** with a per-bundle random mapping | **never** |
| `SECRET` | Key material, pairing secrets, packet payloads, tunnel plaintext | **never stored, never rendered, no code path exists** | never | never |

Pseudonymization preserves structure without identity: `203.0.113.7:51820` becomes
`ipv4-A:port-1`, `2001:db8::5` becomes `ipv6-B`, `wlan0` becomes `iface-1`, a peer becomes
`peer-2`. Two occurrences of the same value map to the same token *within one bundle* and to
different tokens *across bundles*, so support can follow the topology of one incident and
cannot correlate a user across incidents. The mapping is generated per bundle and discarded.

Redaction is applied by the emitter based on the schema classification. There is no
"scrub the log with regexes before sending" step, because that approach fails open (O-14).

### 11.5 Log levels

| Level | Purpose | Default | May contain |
|---|---|---|---|
| `CRITICAL` | Invariant violated; protection state uncertain | on | PUBLIC, OPERATIONAL |
| `ERROR` | A terminal `Diagnostic` was raised | on | PUBLIC, OPERATIONAL, SENSITIVE |
| `WARN` | A degraded `Diagnostic` was raised | on | PUBLIC, OPERATIONAL, SENSITIVE |
| `INFO` | State transitions, candidate outcomes, policy application | on | PUBLIC, OPERATIONAL, SENSITIVE |
| `DEBUG` | Per-attempt protocol detail, timer fires | off, user-enablable, auto-expiring | + SENSITIVE detail |
| `TRACE` | Per-message control-plane detail | off, developer builds, auto-expiring | + SENSITIVE detail |

`DEBUG` and `TRACE` auto-revert after a bounded window so a user cannot leave a verbose,
sensitive ledger accumulating indefinitely. **No level, in any build, may emit `SECRET`.**
Per-packet logging does not exist at any level.

### 11.6 The anti-silence mechanism (how "silent tunnel failure" becomes impossible)

Four mechanisms compose. Silence requires all four to fail simultaneously.

1. **Protection is asserted, not assumed (O-17).** A `ProtectionAssertion` is produced by
   *querying the enforcement layer* — the actual installed firewall/route rule set from
   [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md), for both address families — and
   comparing it against the intended policy. The user-visible protection indicator is a pure
   function of the most recent assertion, never of the agent's belief about what it configured.
   A mismatch raises `CRITICAL` and drives the state machine toward `BLOCKED` or `DEGRADED`.
2. **Assertions expire (O-18).** An assertion is valid for a bounded freshness window. If it is
   not affirmatively renewed — because the agent hung, was suspended, crashed, or was killed —
   the indicator becomes `UNKNOWN`, never `PROTECTED`. Staleness is fail-safe by construction,
   so a dead agent cannot leave a reassuring green indicator on screen.
3. **Every state entry carries a reason (O-05).** `DEGRADED`, `BLOCKED`, `RECONNECTING`, and
   `FAILED` are unenterable without a `reason_code`; a transition without one is
   `INTERNAL.INVARIANT_VIOLATED`. This is enforced at the state-machine boundary in
   [docs/reliability.md](../reliability.md), so no code path can enter a bad state quietly.
4. **Liveness is cross-checked against belief.** A watchdog compares claimed state against data
   plane counters. `WAN_DIRECT`/`LOCAL_DIRECT`/`RELAYED` with zero bytes received across a
   bounded interval while traffic is being offered raises `NET.SILENT_PATH_SUSPECTED` and
   forces a path validation. This catches the black-hole case that every other mechanism
   misses, because the black hole is invisible to configuration inspection.

Presentation obligation: `DEGRADED` and `BLOCKED` MUST be visually distinct from the connected
state in every surface (GUI, CLI, tray, headless status output, router status page). Rendering
`DEGRADED` as connected is a defect, not a UX choice.

### 11.7 Metrics, traces, health

- **Client metrics** are local counters and histograms exposed on a local status interface;
  they do not leave the device except inside a Tier-1 bundle or as a Tier-2 aggregate.
- **Client traces** are local spans over one connection attempt (candidate gathering → probe →
  validation → selection), retained in the ledger. No trace context crosses to infrastructure.
- **Infrastructure metrics** are Prometheus-style with the label allowlist of §9. Relays export
  aggregate throughput, session counts, capacity, and `reason_code` histograms — never a
  per-session or peer-pair label (O-13).
- **Health** is reported as `HealthState` per component and per `Relay`;
  [ADR-0006](ADR-0006-relay-discovery-and-failover.md) consumes it for selection and failover. The
  observability system reports; the reliability layer decides.
- **Crash reporting** is opt-in, stacks and registers only, with packet buffers and key
  material in dump-excluded memory regions, symbolicated server-side, and never containing
  heap contents.

### 11.8 The connectivity report (R-23)

One user-invocable command/button. Runs offline. Produces, for the most recent (or a live)
connection attempt:

1. **Environment**: OS and version, adapter availability, permission state, detected
   conflicting virtual interfaces, detected third-party filtering products (O-08, R-17, R-18).
2. **Address families**: v4 and v6 local addresses, default routes, and reachability, reported
   side by side and always both (O-09).
3. **DNS**: active resolvers, effective `DNSPolicy`, interception detection result.
4. **Candidate ledger**: every `ConnectionCandidate` (host / server-reflexive / relay, per
   family), the attempt outcome, the elapsed time, and the `reason_code` for each failure.
5. **Transport ladder**: the result of each step of the fallback ladder (UDP → UDP:443 →
   TCP/TLS → HTTPS-shaped), which is what lets the report name a suspected blocker (R-18).
6. **Relay**: candidate relays considered, measured RTT, health, selection outcome.
7. **Verdict**: the single `reason_code` that best explains the failure, its human explanation,
   and its next action.
8. **Enforcement snapshot**: the current `ProtectionAssertion` for both families.

The report is rendered for the user first (O-10). Sharing it is a separate, explicit act.

### 11.9 Remote support workflow

1. User reproduces the problem; Tier 0 has already captured it (no "enable logging" step).
2. User generates a bundle for a bounded time window.
3. Client renders a full human-readable preview; the user can inspect every field (O-10).
4. Client pseudonymizes `SENSITIVE` fields, drops `SECRET` by construction, signs the bundle
   with the `DeviceKey`, and stamps an expiry (O-21).
5. User transfers the bundle by a channel of their choosing, or uploads it against a
   support-case identifier they were given.
6. Support opens it with a versioned bundle viewer.

**There is no support-initiated pull.** No remote command can cause a client to generate or
transmit diagnostics. This is a security requirement, not a workflow preference (§7).

### 11.10 Privacy summary — the three-column answer

| Collected by **default** (never leaves device) | Requires **explicit opt-in / user act** | **Never** collected, in any mode |
|---|---|---|
| State transitions and `reason_code`s | Tier-1 bundle contents (per-artifact user act) | Tunnel plaintext or packet payloads |
| `ConnectionCandidate` ledger, per family | Tier-2 aggregate counters (persistent opt-in) | Private key material, pairing secrets |
| Local counters, histograms, local spans | Crash reports (persistent opt-in) | DNS query names transmitted off-device |
| Enforcement snapshots / `ProtectionAssertion` | Extended `DEBUG`/`TRACE` capture (auto-expiring) | Browsing/destination history |

**A distinction the two classifications depend on.** §11.4 classifies a *single* endpoint or
hostname appearing in one `Diagnostic` as `SENSITIVE` — redacted by default, renderable in an
auto-expiring `DEBUG` capture the `Owner` initiates on their own device. **Browsing or destination
*history*** — a retained, time-ordered record of what a peer contacted — is a different asset and is
`SECRET`: no rendering path exists, in any build, at any log level, in any tier. The difference is
retention and correlation, not field type. This is why [ADR-0013](ADR-0013-multi-client-gateway-architecture.md)
§11.7.4 keeps per-peer aggregates only and cannot offer an exit-node `Owner` a per-destination log,
even a `DEBUG`-gated one.
| Endpoints, interface names, peer identifiers *in the local ledger only* | | Peer-pair correlation on infrastructure (O-13) |
| Infrastructure-side aggregate counters (operator's own systems) | | Any stable device/user identifier in Tier 2 |
| | | Continuous background telemetry of any kind |

---

## 12. Why the Selected Option Won

- **It is the only alternative that satisfies both binding constraints at once.** Alternative A
  satisfies diagnosability and fails privacy at the architecture level, not at the
  configuration level — a cross-component trace *is* a peer graph. Alternatives B and D satisfy
  privacy and fail R-23: "find the log file" and "we cannot see anything" are the PairVPN
  status quo. C satisfies R-22/R-23 but permanently accepts fleet blindness. E is C's
  diagnostic quality with a bounded, default-off, structurally identifier-free path to fleet
  visibility.
- **The privacy properties are structural, not procedural.** Tier 0 never leaves the device
  because there is no transport for it. `SECRET` fields are unrenderable because no rendering
  code exists. Tier 2 cannot deanonymize because no identifier is generated to correlate on.
  Each of these is a property a test can falsify
  ([docs/testing-strategy.md](../testing-strategy.md)), which is precisely what a policy-based
  posture cannot offer.
- **Local-first is the only posture compatible with I5 and with the actual failure modes.** The
  moments you need diagnostics are the moments the network is broken. An export-dependent
  design is blind exactly then, which disqualifies A outright.
- **It fits the platform range.** Tier 0 collapses to a small in-memory ring on router-class
  targets; Tier 1 renders on demand; Tier 2 is absent unless enabled. Alternative A's SDK
  footprint does not fit at all.
- **The three tiers are independently auditable.** A privacy reviewer can evaluate "what leaves
  the device" by examining two narrow, explicit code paths rather than reasoning about a
  general-purpose export pipeline with collector-side filtering.
- **What we knowingly gave up:** A's ecosystem and correlation power, and D's simplicity. The
  first is bought back partially by building a good bundle viewer; the second is the price of
  not being blind.

---

## 13. Known Tradeoffs

| Tradeoff | Consequence | Mitigation |
|---|---|---|
| Tier 2 is opt-in and therefore a **biased sample** | Fleet aggregates skew toward less privacy-motivated users and cannot be treated as representative | Never gate a decision solely on Tier-2 data; use it for regression *detection*, not for absolute rates. Corroborate with `reason_code` distribution in support cases. |
| k-anonymity thresholds hide the tail | Rare-but-severe failures may never reach the reporting threshold — exactly the failures worth finding | The pre-release network laboratory ([docs/testing-strategy.md](../testing-strategy.md)) is the primary detector for rare conditions; Tier 2 is a backstop, not a substitute |
| Ring buffers bound forensic reach | An incident whose cause scrolled out is undiagnosable from the bundle | Dual rings: a long-retention "significant events" ring alongside the short verbose ring |
| Relay per-session debugging is deliberately impossible (O-13) | Relay operators cannot investigate an individual user's relay session | Accepted. This is I1 working as intended. Relay-side investigation is limited to aggregates; individual diagnosis happens on the client, which has the full picture anyway |
| No support-initiated pull | Slower support loop; depends on user action | Make the user action one step, always available, never requiring reproduction with special settings |
| Pseudonymization is per bundle | Support cannot correlate two bundles from the same user across incidents | Accepted; the user may voluntarily state that two bundles are theirs. Cross-bundle correlation is the deanonymization channel we are refusing to build |
| Bespoke ledger and bundle viewer | Real, permanent engineering cost with no ecosystem | Keep the schema small and versioned; reuse an existing structured-log serialization rather than inventing one |
| Aggregation service is another production system | Availability and upgrade burden | Its outage MUST be a client no-op: Tier 2 submissions are best-effort, dropped silently, never retried aggressively, never blocking |
| Auto-expiring `DEBUG`/`TRACE` | A rare intermittent bug may not reproduce within the capture window | Window length is user-extendable with a clear warning; the significant-events ring still covers the skeleton |
| Emit-time classification requires schema discipline everywhere | A new field added without a classification is a potential leak | The schema (ADR-0003) MUST make classification a required attribute so an unclassified field fails to compile/validate, and CI must test for it |

---

## 14. Revisit Conditions

Revisit this ADR if any of the following becomes true. Each is falsifiable.

1. **Tier-2 opt-in rate falls below 2% of active devices, sustained over two consecutive
   release cycles.** At that point the aggregate channel is carrying the privacy and
   operational cost of a fleet-visibility mechanism while delivering a sample too small and too
   biased to detect regressions. Retreat to **Alternative D** and delete the channel.
2. **A published attack, or our own red-team exercise, demonstrates re-identification of a
   `Device` or an `Owner` from Tier-2 submissions** at the configured k-threshold and bucket
   granularity. Disable Tier 2 immediately and revisit; do not attempt to patch the bucketing
   without re-deriving the privacy argument.
3. **Two or more post-release incidents in one year are traced to a regression that Tier 0 +
   Tier 1 + the network laboratory could all have detected but did not, because no user
   reported it.** This falsifies the claim that user-initiated diagnosis is a sufficient
   detector, and argues for a broader default-on channel — which would require re-deriving the
   privacy argument from scratch, not simply widening the existing one.
4. **Median support-case time-to-root-cause exceeds 3 business days, or more than 25% of cases
   require a second bundle**, over one quarter. This falsifies the sufficiency of the bundle
   contents and triggers a redesign of the ledger schema and report contents (not necessarily a
   change of tier model).
5. **More than 5% of support cases resolve with a `reason_code` in the `INTERNAL` domain, or
   with no `reason_code` at all.** This falsifies the completeness of the taxonomy; the
   registry needs expansion and the "unenterable without a reason" enforcement needs auditing.
6. **The observability subsystem is measured exceeding its budget** (>1% CPU or >8 MB resident
   on the reference desktop target; >512 KB on the router-class target) in a release
   benchmark. Re-scope Tier 0 rather than accept datapath impact.
7. **A platform removes the ability to query the enforcement layer's installed rule set**
   (the mechanism O-17 depends on) — for example a mobile OS that no longer exposes the
   effective VPN/firewall configuration to the app. `ProtectionAssertion` would then rest on
   belief rather than observation on that platform, and §11.6 mechanism 1 must be redesigned
   there (mechanism 4, the counter-based black-hole detector, becomes load-bearing).
8. **An audited, standardized privacy-preserving aggregation construction becomes available
   that provides formal differential-privacy guarantees at acceptable cost**, or conversely
   **the construction we selected is withdrawn or broken**. Either event changes the
   cost/benefit of Tier 2 materially (subject to I2/C-8: audited constructions only).
9. **A regulatory obligation requires retention of data that O-13 forbids.** This is a
   direct conflict with I1 and MUST escalate to an architecture-level decision about
   jurisdiction and infrastructure siting, not a quiet relaxation of the constraint.
