# ADR-0009: State Consistency

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** ARCHITECTURE
- **Related:** [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) · [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) · [ADR-0003](ADR-0003-network-contract-schema-format.md) · [ADR-0005](ADR-0005-relay-architecture.md) · [ADR-0006](ADR-0006-relay-discovery-and-failover.md) · [ADR-0007](ADR-0007-device-identity-and-pairing.md) · [ADR-0008](ADR-0008-idempotency.md) · [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) · [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) · [ADR-0015](ADR-0015-observability-and-diagnostics.md) · [docs/architecture.md](../architecture.md) §4, §5 · [docs/protocol.md](../protocol.md) §5, §6, §15 · [docs/reliability.md](../reliability.md) · [docs/threat-model.md](../threat-model.md)

**Scope.** This ADR defines TwinVPN's consistency taxonomy, justifies the class assigned to every
row of the state-ownership table ([docs/architecture.md](../architecture.md) §5), decides the
mechanism that discharges the two consistency escalations the protocol declares
([docs/protocol.md](../protocol.md) §15.1 E-1 and E-2), and specifies the signed-document
distribution model — version scheme, anti-rollback rule, TTL semantics, and expiry behaviour per
fact class. It does **not** own the messaging transport or event bus ([ADR-0002] — this ADR states
the delivery interface it requires), idempotency keys or the dedupe mechanism ([ADR-0008] — this
ADR consumes them), identity and revocation cryptography ([ADR-0007] — consumed), or retry timers
and the `ConnectionState` transition table ([docs/reliability.md](../reliability.md) — this ADR
supplies guard inputs and reason codes only, never a state or a transition).

---

## 1. Context

[ADR-0008](ADR-0008-idempotency.md) answered *"what happens when a write arrives twice, or late."*
This ADR answers the other half: *"what does a reader see, when, and what may it never see."*
The two are one argument. Idempotency makes duplicate and out-of-order **writes** harmless;
consistency makes stale and reordered **reads** harmless — or, where they cannot be made harmless,
names exactly what breaks and bounds it.

Three facts about TwinVPN's shape dictate everything that follows.

**First, partition is the normal operating condition, not an incident.** Invariant **I5** promises
that the data plane outlives the control plane; [docs/architecture.md](../architecture.md) §4.4
enforces it by *pre-materializing* every input an established `Session` needs into local durable
state. The direct consequence is that **every device is, by design, permanently running against a
stale cache.** A consistency model that only reasons about the connected case describes a mode
TwinVPN spends a minority of its life in.

**Second, a `TwinNet` is small.** One `Owner`, tens of `Device`s, single-digit ceremonies per
device lifetime, and — critically — [docs/protocol.md](../protocol.md) §15.2 forbids any ordering
requirement *across* `TwinNet`s. The unit of consistency is therefore tiny and completely
independent of every other unit. Designs that pay for global coordination are paying for a
guarantee this system has explicitly refused.

**Third, two facts carry security weight and the rest do not.** Revocation (S-03) and policy
(S-06/S-07) are the only state whose staleness is a *breach* rather than an *inefficiency*.
Everything else is either device-authoritative (and therefore not a distributed problem at all) or
a hint. Uniformly strengthening consistency to protect two rows would surrender availability on
twenty-two rows that never needed it — and would surrender it precisely where **I5** forbids it.

The tension this ADR must resolve is stated in the corpus itself and is genuinely two-sided:
[docs/architecture.md](../architecture.md) §4.4.3 says **"TTL expiry MUST NOT tear down an
established `Session`"**, while [docs/protocol.md](../protocol.md) §13.4 says the shipped default
on an expired `PolicyBundle` is **fail closed**. Both are correct; §11.5 shows where the boundary
between them lies.

## 2. Requirements

| # | Requirement | Source |
|---|---|---|
| **RQ-1** | The taxonomy MUST define `STRONG`, `MONOTONIC`, `EVENTUAL`, `LOCAL` precisely enough to be **testable**, and MUST state each class's operational meaning at the *device edge*, not only at the authority. | [docs/architecture.md](../architecture.md) §5 legend |
| **RQ-2** | Every row S-01…S-24 MUST have a justification stating why its class is sufficient, what breaks if weaker, and what it costs if stronger. | §5 is this ADR's dependent |
| **RQ-3** | Revocation admission MUST be linearizable, backed by a single writer per `TwinNet` revocation log, with monotonic-read semantics for every device across replica failover and no forked history. | [docs/protocol.md](../protocol.md) §15.1 **E-1**, A7 |
| **RQ-4** | `committed_at_net_seq` MUST be a real monotone position in the **same** log the device reads on C2. | [docs/protocol.md](../protocol.md) §15.1 **E-2**, §5.1, A8 |
| **RQ-5** | No consumer may ever observe a version, epoch, or cursor go **backwards**, including across control-plane failover, replica switch, or operator restore. | **I8**, [ADR-0008](ADR-0008-idempotency.md) N-3 |
| **RQ-6** | No consistency mechanism may place a synchronous control-plane call on any established-session path. | **I5**, [docs/architecture.md](../architecture.md) §4.4.2 |
| **RQ-7** | Expiry behaviour MUST be specified **per fact class**, MUST NOT tear down an established `Session`, and MUST NOT silently widen an authorization. | **I3**, **I5**, [docs/architecture.md](../architecture.md) §4.4.3 |
| **RQ-8** | `EVENTUAL` state MUST NEVER gate a connection attempt. | S-09/S-10/S-11, [docs/architecture.md](../architecture.md) §2.13 |
| **RQ-9** | No security decision may depend on wall-clock ordering or on the device's clock being correct. | [docs/threat-model.md](../threat-model.md) scope; **I3** |
| **RQ-10** | The model MUST be satisfiable on a single self-hosted box (topologies T2/T3) with the *same* code path as the hosted topology. | [docs/architecture.md](../architecture.md) §7; [ADR-0008](ADR-0008-idempotency.md) C-4 |
| **RQ-11** | Every staleness, rollback, fork, and version-conflict condition MUST have a stable `reason_code`. | **I6**, R-22 |

Requirements discharged: **R-02**, **R-03**, **R-05**, **R-07**, **R-10**, **R-11**, **R-13**
(adjacent), **R-17**, **R-22**, **R-23**.

## 3. Constraints

- **C-1 (I8)** — exactly one authoritative writer per fact. No mechanism may introduce a second.
- **C-2 (I5)** — the data plane holds no control-plane client reference
  ([docs/architecture.md](../architecture.md) §4.2). Consistency metadata reaches it only through
  the local durable store (2.20).
- **C-3 (I1/I4)** — the control plane is *semi-trusted*. Anti-rollback MUST hold even against a
  hostile or restored-from-backup control plane, therefore it MUST be enforced at the device.
- **C-4 (RQ-10)** — no distributed transaction coordinator, no external consensus service, no
  cloud-managed consensus database as a hard dependency.
- **C-5** — [docs/protocol.md](../protocol.md) §15.2 forbids cross-`TwinNet` ordering, forbids
  consensus on `Session` state, and forbids convergence requirements on hints. Any design that
  needs one of those is out of bounds.
- **C-6 (mobile reality)** — a device may be suspended for hours and resume mid-cursor; monotonic
  clocks stop during suspend on some platforms.
- **C-7** — [ADR-0008](ADR-0008-idempotency.md) already decided declarative desired state,
  monotonic versioned conditional writes, and ceremony idempotency keys. This ADR **composes with**
  those rules and MUST NOT restate or contradict them.

## 4. Considered Alternatives

Three independent decisions are open. Each is enumerated separately; §5 and §6 cover every named
alternative.

**Family A — how consistency classes are assigned.**

- **A1 — Uniform strong consistency.** Every control-plane fact is linearizable; devices read
  through to the authority and never act on a cache.
- **A2 — Uniform eventual consistency with client-side monotonicity.** Everything is eventually
  consistent at the server; devices enforce monotonicity locally via high-water marks.
- **A3 — Per-fact consistency taxonomy.** Four named classes, one assigned per row of
  [docs/architecture.md](../architecture.md) §5, each individually justified.

**Family B — the store backing the escalations E-1 and E-2.**

- **B1 — Single-leader replicated SQL** with synchronous replication and read-your-writes routing.
- **B2 — Raft-replicated log**, one group per service, application state as a deterministic fold.
- **B3 — Multi-leader / CRDT store** with commutative merge across writers.
- **B4 — Globally-distributed consensus database** (Spanner / CockroachDB shaped), external
  consistency from synchronized clocks or hybrid logical clocks.
- **B5 — Per-`TwinNet` single-writer shard** with one append-only `net_seq` log per `TwinNet`;
  intra-shard replication is a deployment choice; no cross-shard coordination exists.

**Family C — expiry semantics for signed documents.**

- **C1 — Hard TTL, uniform fail-closed.** Expiry of any document blocks traffic until refreshed.
- **C2 — No TTL; push-only revocation.** Documents are valid until superseded; freshness comes
  solely from delivery of the next update.
- **C3 — Two-band TTL (`refresh_after` / `not_after`) with per-class expiry semantics**, and a
  grant/deny asymmetry: denials never expire, grants do.

## 5. Advantages of Each Alternative

- **A1** — Trivially correct and trivially explained; no staleness reasoning anywhere; no
  anti-rollback machinery needed because there is nothing to roll back to; a security review needs
  to read one sentence.
- **A2** — Maximum availability; the server tier can be a dumb replicated cache; devices are
  already required to hold high-water marks by [ADR-0008](ADR-0008-idempotency.md) N-3, so the
  client-side half costs nothing new; survives arbitrary replica topologies including a
  self-hosted box restored from a snapshot.
- **A3** — Pays for strength exactly where it is needed and nowhere else. Makes the cost of each
  guarantee individually visible and individually reviewable, which is what turns
  [docs/architecture.md](../architecture.md) §5 from a table into an argument. Directly matches the
  observed structure of the domain: two security-bearing facts, several monotone documents, a
  handful of hints, and a large majority of device-local state.
- **B1** — The most operationally boring option, and boring is an advantage for a system an
  individual must self-host. Read-your-writes is a routing rule, not a protocol. Backup, restore,
  and monitoring are solved problems with mature tooling on every platform.
- **B2** — The log *is* the model: `net_seq` is literally the Raft index, so E-2 is satisfied by
  construction rather than by a mapping layer. Leader election, fencing, and durable commit are one
  mechanism instead of three. Embeddable in a single binary, which suits T2/T3.
- **B3** — Writers never block each other; availability under partition is maximal; converges
  without an election; genuinely the right model for high-frequency last-writer-wins facts like
  presence and relay health.
- **B4** — Provides linearizability *and* geo-distribution simultaneously, with no sharding design
  work: the database makes cross-partition transactions someone else's problem. Multi-region
  failover is automatic. If TwinVPN later needs cross-`TwinNet` invariants, B4 is the only option
  that already supports them.
- **B5** — The unit of consistency matches the unit of the domain exactly: a `TwinNet` is the only
  scope in which ordering is ever required ([docs/protocol.md](../protocol.md) §15.2), and it is
  small enough that a single writer is never a throughput constraint. Scales by adding independent
  shards, which needs no coordination protocol at all. **Degenerates to a single process with one
  shard and zero replicas** — so T2/T3 run the same code as T1 in a degenerate configuration rather
  than a different code path. Blast radius of any consistency bug is one `TwinNet`.
- **C1** — Unambiguous and easy to audit; there is exactly one expiry rule; no reviewer can be
  wrong about what happens at `not_after_ms`; strongest possible posture against stale
  authorization.
- **C2** — Never produces a spurious outage; a device isolated on a LAN forever keeps working,
  which is exactly the [docs/architecture.md](../architecture.md) §7 "LAN-only, no Internet at all"
  guarantee; zero clock dependence.
- **C3** — Separates "should refresh" from "may no longer rely on", so the common case (a brief
  control-plane blip) never reaches an enforcement decision at all. The grant/deny asymmetry means
  expiry can only ever make the device *more* restrictive, which is a property that can be checked
  mechanically rather than argued.

## 6. Disadvantages of Each Alternative

- **A1** — **Disqualifying: it contradicts I5 outright.** Reading through to the authority puts a
  control-plane call on the established-session path, which
  [docs/architecture.md](../architecture.md) §4.4.2 specifically forbids for keepalive, rekey, path
  probing, migration, relay failover, and policy evaluation. It also makes the control plane a
  single point of failure, contradicting **R-11**, and makes T2/T3 self-hosting hostile, because a
  home server's uptime would become the product's uptime.
- **A2** — Cannot satisfy **E-1**. Client-side high-water marks detect a *lagging* replica but are
  blind to a *forked* history: two replicas publishing different content at the same epoch both
  pass the high-water test, and the device that talks to the wrong one keeps trusting a stolen
  device. [docs/protocol.md](../protocol.md) §15.1 says this explicitly. It also cannot give
  read-your-writes for E-2 without an extra token, which reintroduces the machinery A2 was meant to
  avoid.
- **A3** — Four classes is four things to get right, and a misclassified row is a silent defect
  rather than a loud one. Requires per-row justification to stay honest as the system evolves, and
  the justification can rot. It puts real weight on §5 of
  [docs/architecture.md](../architecture.md) being maintained.
- **B1** — Synchronous replication couples write availability to replica health, and a failover
  without a fencing token can admit two leaders long enough to fork the log — precisely the E-1(c)
  failure. Read-your-writes by routing is fragile: any read that escapes to a lagging replica
  silently breaks the guarantee, and nothing in the type system prevents it.
- **B2** — Raft is real operational surface: quorum sizing, membership change, snapshot and
  compaction, and a class of failure modes (a stuck no-quorum group) that are hard to explain to a
  self-hoster. Running Raft with a single node to satisfy T2 means the HA machinery exists but is
  never exercised, which is its own risk. Ecosystem tooling is far thinner than SQL's.
- **B3** — **Rejected on the same security ground [ADR-0008](ADR-0008-idempotency.md) §6 rejected
  ALT-E:** commutative merge over trust state risks un-revocation, and any merge function
  disciplined enough to avoid it has already reimplemented a monotone epoch with a single writer.
  It also cannot provide linearizable *admission*, which is the actual E-1 requirement. CRDT
  metadata growth and the difficulty of explaining a merge outcome are hostile to **R-23**.
- **B4** — Fails **C-4/RQ-10** decisively: a self-hosted `Owner` cannot be asked to operate a
  distributed consensus database, and TwinVPN's T2/T3 topologies are first-class, not niche. It
  buys cross-partition external consistency that [docs/protocol.md](../protocol.md) §15.2
  explicitly says the system must never need. It also introduces a clock-quality dependency at the
  storage layer, which sits badly with RQ-9.
- **B5** — Requires a shard-ownership mechanism (lease, fencing token, migration procedure) that is
  new code rather than a product feature. A hot `TwinNet` cannot be scaled by adding writers, only
  by making the single writer faster — acceptable at tens of devices, a hard ceiling if the product
  ever targets thousands per `TwinNet`. Cross-`TwinNet` reporting becomes a scatter-gather over
  shards rather than a query.
- **C1** — **Directly violates RQ-7 and I5.** Under C1, a control-plane outage lasting longer than
  the policy TTL blocks working tunnels — converting an availability incident into a user-visible
  outage, which is the exact failure I5 exists to prevent. It also breaks the
  [docs/architecture.md](../architecture.md) §7 LAN-only guarantee, since an air-gapped `TwinNet`
  would expire itself into a brick.
- **C2** — Provides no bound at all on the revocation exposure window. A device asleep or
  partitioned when a revocation is issued has no mechanism that ever tells it that it is behind,
  and no deadline that forces it to find out. It also removes the operator's only lever for
  bounding stale-policy blast radius after an incident.
- **C3** — Two bands and per-class semantics is more surface than one rule, and the grant/deny
  asymmetry requires the policy schema to make grants and denials mechanically distinguishable —
  an interface obligation on [ADR-0003](ADR-0003-network-contract-schema-format.md) and
  [ADR-0011](ADR-0011-dns-handling.md), not a free property. A reviewer must check per class
  rather than once.

## 7. Security Implications

1. **Anti-rollback is enforced at the device, so it survives a hostile control plane.** The control
   plane is only semi-trusted ([docs/architecture.md](../architecture.md) §8, B3). Because N-3 of
   [ADR-0008](ADR-0008-idempotency.md) and §11.3 here place rejection at the local store (2.20), a
   compromised or restored-from-backup control plane cannot walk a device backwards to a weaker
   policy or a smaller revoked set. It can withhold updates; it cannot rewind them.
2. **Fork detection is the client's half of E-1.** Single-writer admission *prevents* a fork;
   §11.3 R-4 lets the device *detect* one — equal version with different content hash is refused
   and raised as a security event. This matters because prevention lives on infrastructure the
   `Owner` may not control, while detection lives on the device, which the `Owner` does.
3. **Revocation denials are monotone accumulations, not leases.** A denial once learned is
   permanent (N-7 of [ADR-0008](ADR-0008-idempotency.md)). Consequently document expiry can never
   un-revoke anything — the expiry of a trust list weakens nothing, because the only thing it
   carried that could be weakened is already recorded irreversibly. This is the single most
   important structural property in this ADR: **it makes trust-list TTL a freshness signal rather
   than an authorization lease.**
4. **The residual revocation window is real and is bounded, not hidden.** A device partitioned from
   the control plane keeps honoring its last-known trust list. §11.6 bounds this with two
   independent mechanisms — a short refresh interval and data-plane trust-epoch gossip — and
   §13 states the residue that remains after both.
5. **Peer-carried revocation is replication, not authorship.** §11.6 lets a peer forward an
   `Owner`-signed `RevocationRecord` over an established `Tunnel`. The peer cannot forge it (A-04,
   A5) and can only ever cause the receiver to *add* a denial. This does **not** make a device a
   publisher of the `DeviceRevoked` event — [docs/protocol.md](../protocol.md) §7's single-publisher
   rule is unchanged; the coordination service remains the sole publisher of the durable event, and
   the peer path is an ephemeral in-session carriage of the same signed record.
6. **No security decision depends on the device clock** (RQ-9). Ordering is by monotone integers;
   TTL is evaluated against elapsed time since receipt (§11.7). A user who moves their clock
   forward cannot expire a policy early into a weaker state, and one who moves it back cannot
   extend a grant, because grants are the side that expires and expiry is computed conservatively.
7. **Where a rejected alternative was better:** **A1** (uniform strong) is unambiguously more
   secure in the abstract — a device that always reads through to the authority is never stale.
   We reject it because it trades a bounded, named, measurable staleness window for an unbounded
   availability dependency, and because **I5** makes that trade unavailable to us regardless.

## 8. Reliability Implications

1. **Staleness is a supported operating mode, not a degradation.** Every `MONOTONIC` and `EVENTUAL`
   fact is usable while stale, and the two-band TTL (§11.4) means the ordinary control-plane blip
   never reaches an enforcement decision. Nothing in this ADR can transition a `Session` out of a
   steady state.
2. **This ADR adds no `ConnectionState` and no transition.** It supplies guard *inputs*
   (`policy_grant_expired`, `trust_state_expired`, `trust_epoch_behind`, `cursor_unavailable`) consumed by the existing
   transitions in [docs/reliability.md](../reliability.md) §4.5 — principally T29
   (`EV_POLICY_VIOLATION` → `BLOCKED`) — and reason codes. Relay failover
   (`RELAYED → MIGRATING → RELAYED`) and direct upgrade remain untouched, and neither consults any
   fact governed here beyond the cached relay set (S-09), which is `EVENTUAL` and never a gate.
3. **The reconnection storm after an outage is bounded by the cursor.** Devices resume C2 from a
   stored `net_seq` rather than re-reading everything, so post-outage catch-up is O(events missed),
   and the declarative model of [ADR-0008](ADR-0008-idempotency.md) means a device that reconciles
   twice costs the same as once.
4. **Single-writer per `TwinNet` bounds the blast radius of a consistency defect to one `TwinNet`.**
   There is no shared log, no shared lock, and no cross-tenant contention, so one pathological
   `TwinNet` cannot stall another. This is a direct **R-11** contribution.
5. **New failure modes introduced:** (a) cursor-ahead-of-replica refusals during failover, mitigated
   in §11.2 by leader redirect; (b) device stranding after an operator restores an old backup,
   which is *correct* behaviour ([ADR-0008](ADR-0008-idempotency.md) §10.1) but needs the runbook in
   §10.2; (c) shard-lease flapping, mitigated by a minimum lease term.

## 9. Performance Implications

1. **Steady-state cost is one integer comparison.** A device holds `(net_seq, trust_epoch,
   doc_version[])` and compares on receipt. There is no read-through, no quorum read, and no
   coordination on any hot path.
2. **Data-plane cost is exactly zero** (RQ-6/C-2). Nothing here is consulted during keepalive,
   rekey, path probing, migration, or relay failover. The one data-plane addition — the trust-epoch
   assertion of §11.6 — is a fixed-size field in an existing handshake prologue, exchanged once per
   `Tunnel`, not per packet. Throughput (**R-15**) is unaffected by construction.
3. **Write throughput ceiling is one writer per `TwinNet`.** At the design point (one `Owner`, tens
   of devices, single-digit ceremonies per device lifetime, plus policy edits) the log write rate is
   a handful of events per device per *day*. The ceiling is roughly four orders of magnitude above
   the load. §14.3 makes it a falsifiable revisit trigger rather than an assumption.
4. **Whole-bundle policy transfer** (mandated by [docs/protocol.md](../protocol.md) §15.1 E-3) costs
   bandwidth on every policy change. At personal scale a `PolicyBundle` is kilobytes; the
   alternative — deltas — requires exactly-once delivery, which does not exist.
5. **Where a rejected alternative was better:** **B3** (CRDT) would let devices merge state
   peer-to-peer with no authority round trip, which is strictly cheaper under partition and would
   remove control-plane load entirely. We give that up for the un-revocation risk in §6.

## 10. Operational Implications

1. **One deployment shape, two configurations.** T1 runs many shards with intra-shard replication;
   T2/T3 run one shard, one replica, synchronous local commit. Same binary, same code path, same
   invariants — the difference is a replica count. This is the concrete payoff of B5 over B4.
2. **Restore-from-backup strands devices, and that is correct.** A restored control plane issuing
   documents at versions devices have already passed will be rejected
   ([ADR-0008](ADR-0008-idempotency.md) §10.1). The **supported** recovery is the epoch-bump
   procedure: on restore, the operator MUST advance `trust_epoch` and every `doc_version` strictly
   past the highest value ever issued (recorded in the shard's high-water record, §11.3 R-7) before
   serving devices. Restoring without the bump is an unsupported operation and MUST fail loudly.
3. **`net_seq` reset is permitted only under the epoch bump.** If a shard is rebuilt and `net_seq`
   restarts, every device's stored cursor becomes meaningless. Devices detect this via
   `shard_epoch` (§11.3) and perform a full declarative re-read rather than a resume — a supported,
   named path (`CONTROL.CONSISTENCY.CURSOR_INVALIDATED`), not a stall.
4. **Observability obligations on [ADR-0015](ADR-0015-observability-and-diagnostics.md):** every
   code in §11.8 must be registered; additionally, per-`TwinNet` replication lag, shard-lease
   changes, and the count of devices confirmed at the current `trust_epoch` must be operator-visible
   — the last of these is what makes [docs/protocol.md](../protocol.md) §8.3's
   "revocation pending propagation, N of M confirmed" display possible.
5. **Testing obligations on [docs/testing-strategy.md](../testing-strategy.md):** (a) a
   linearizability check over concurrent revocation admissions across an induced leader failover;
   (b) a monotonic-read check asserting no device ever observes a decreasing `(net_seq,
   trust_epoch, doc_version)` while replicas are killed and restarted; (c) a fork-injection test
   serving two contents at one version, asserting `CONTROL.CONSISTENCY.FORKED_HISTORY_DETECTED`;
   (d) a clock-tampering test moving the device clock ±30 days, asserting no grant widens and no
   established `Session` drops.

## 11. Decision

**TwinVPN adopts A3 (per-fact consistency taxonomy), B5 (per-`TwinNet` single-writer shard over one
append-only `net_seq` log, realized by B1 or B2 as a deployment choice), and C3 (two-band TTL with
denials permanent and grants expiring).** B3 and B4 are rejected outright; A1, A2, C1, and C2 are
rejected as primary models. B3's last-writer-wins register semantics are retained only for presence
and health, exactly as [ADR-0008](ADR-0008-idempotency.md) §11 already provides.

### 11.1 The taxonomy (normative, testable)

| Class | Definition | Test that falsifies it | Meaning **at the device edge** |
|---|---|---|---|
| `STRONG` | Linearizable **at the authority**: there is a single total order of operations consistent with real time, and every read in that order returns the most recent write. | A linearizability checker finds a history with no valid sequential witness. | **None directly.** No device ever observes `STRONG`. What crosses B3 is always a monotone sequence of signed documents. `STRONG` is a property of *admission*, and its only edge-visible consequence is that two conflicting admissions can never both have succeeded. |
| `MONOTONIC` | (i) totally-ordered version; (ii) every consumer holds a high-water mark and rejects any lower version; (iii) content is a **function** of version — no two contents share a version; (iv) lag is permitted and bounded only by TTL. | Any consumer observes a version sequence that decreases, or two distinct contents at one version. | "I may be behind, and I know by how much; I will never go backwards; if I am behind I can say so." The device may act on the value it holds. |
| `EVENTUAL` | If writes stop, all replicas converge within `T_converge`. Arbitrarily stale or wrong in the interim. **MUST NEVER be a gate.** | A value is used as a precondition for admitting, refusing, or deferring a connection attempt. | "A hint. Useful for ordering my attempts, never for deciding whether to attempt." |
| `LOCAL` | Exactly one holder; **no remote replica has authority**. Unavailability of the holder is unavailability of the device. Conflict resolution is "local wins". | A remote value overrides the local one, or a second writer exists. | "This is mine. Nothing over the network can change it, and no partition affects it." |

Two consequences are load-bearing and are stated as rules rather than observations:

- **T-1.** `STRONG` never crosses trust boundary B3. Any design that claims a device reads a
  linearizable value is either wrong or has put a control-plane call on a device path (violating
  **I5**).
- **T-2.** `MONOTONIC` at the edge is what `STRONG` at the authority *becomes* after distribution.
  Rows written `STRONG` at authority / `MONOTONIC` at edge (S-02, S-03) are therefore not hedging;
  they are naming two different guarantees at two different places.

### 11.2 Mechanism for the escalations E-1 and E-2

**The `TwinNet` log.** Each `TwinNet` has exactly one append-only durable log. Every durable event
in [docs/protocol.md](../protocol.md) §7 appends to it and receives a `net_seq`, assigned by the
shard's single writer. There is one log per `TwinNet` and no ordering between logs (C-5).

**Shard ownership and fencing.** Exactly one process holds the write lease for a `TwinNet` shard at
a time. The lease carries a monotonically increasing `shard_epoch`, persisted in the log itself. A
write is admitted only if it presents the current `shard_epoch`; a superseded writer's appends are
refused. Minimum lease term is 10 s to prevent flapping. Intra-shard replication is B1 or B2 at the
operator's choice: both must ack a commit only after it is durable on the leader **and** on ≥1
replica in the hosted topology (T1), or durable locally in the single-box topology (T2/T3, replica
count 0). Both satisfy the same stated interface, which is why the choice is a deployment concern.

**E-1 — revocation.** Discharged in three parts, matching the protocol's three demands:
(a) *linearizable admission* — a `RevocationRecord` is admitted only by the current lease holder,
appended at one `net_seq`, and **the lease holder assigns** the `TwinNet`-wide `trust_epoch` — the
`Owner` authorizes a revocation by signing it, the shard writer *numbers* it, and the two are
deliberately separate ([ADR-0007](ADR-0007-device-identity-and-pairing.md) N-25). An `Owner`-signed
`RevocationRecord` refuses the target peer immediately and offline; only its **epoch advance**
waits on admission, so no partition can mint a competing epoch number; (b) *single writer per
revocation log* — by construction, the shard writer; (c) *monotonic reads across replica failover* —
every device presents its high-water `(net_seq, trust_epoch)` on C1 and on C2 attach, carried in the
`causality_token` reserved for exactly this purpose by [docs/protocol.md](../protocol.md) §5.2. A
replica or newly-elected leader whose applied position is **below** the presented mark MUST refuse
the request with `CONTROL.CONSISTENCY.REPLICA_BEHIND_CURSOR` and redirect, and MUST NOT serve an
older snapshot. Refusal is the correct answer: a device that is told "I cannot serve you yet" keeps
running on its cache (I5) and retries; a device served a stale snapshot un-revokes a stolen laptop.

**E-2 — read-your-writes.** `committed_at_net_seq` returned on a mutating C1 response is the
position in **that same `TwinNet` log** at which the effect committed. Because there is one log,
one writer, and the C2 stream is that log, it is a real monotone position by construction — the
divergence case [docs/protocol.md](../protocol.md) §15.1 warns about (write path and read path on
different shards) is structurally impossible, since a `TwinNet` is never split across shards. The
client obligation of §5.1 (do not report complete until the C2 cursor reaches it) is therefore
satisfiable without an additional token. **Confirmed: A8 holds.**

### 11.3 The signed-document model (normative rules)

Every control-plane document reaching a device (`TRUST_LIST`, `MEMBERSHIP`, `POLICY_BUNDLE`,
`RELAY_SET`) carries this header. Encoding is owned by
[ADR-0003](ADR-0003-network-contract-schema-format.md); the fields are required here.

```
DocumentHeader {
  twinnet_id        : id
  doc_type          : enum
  doc_version       : uint64   // monotone per (twinnet_id, doc_type)
  net_seq           : uint64   // log position where this content committed  [E-2]
  trust_epoch       : uint64   // TwinNet-wide monotone trust generation     [E-1]
  shard_epoch       : uint64   // fencing token of the writer that issued it
  issued_at_ms      : int64
  refresh_after_ms  : int64    // soft band
  not_after_ms      : int64    // hard band
  content_hash      : bytes
  signature         : Owner-authority signature (ADR-0007 A-04 / protocol A5)
}
```

- **R-1** A device MUST verify the signature offline before any other check. An unverifiable
  document is discarded and never compared against the high-water mark.
- **R-2** **Accept** iff `doc_version > stored.doc_version`.
- **R-3** **Idempotent no-op** iff `doc_version == stored.doc_version` **and**
  `content_hash == stored.content_hash`.
- **R-4** **Reject as a fork** iff `doc_version == stored.doc_version` and the content hash differs.
  Emit `CONTROL.CONSISTENCY.FORKED_HISTORY_DETECTED` as a security event. This is the client-side
  detector for E-1(c).
- **R-5** **Reject as rollback** iff `doc_version < stored.doc_version`. Emit
  `CONTROL.CONSISTENCY.VERSION_ROLLBACK_REJECTED` — the reason code for the
  `version_rollback_rejected` event [ADR-0008](ADR-0008-idempotency.md) §10.2 already requires.
- **R-6** `trust_epoch` MUST NOT decrease under any circumstance, in any document type. A document
  of *any* type carrying a lower `trust_epoch` than the device's high-water mark is rejected. Every
  document type therefore acts as a freshness beacon for the trust generation.
- **R-7** The shard MUST persist a high-water record of the maximum `trust_epoch` and
  `doc_version` per type ever issued, outside the log's compaction scope, so that the §10.2 restore
  procedure is mechanically checkable.
- **R-8** A change in `shard_epoch` accompanied by a `net_seq` lower than the device's cursor means
  the log was rebuilt. The device MUST discard its cursor, emit
  `CONTROL.CONSISTENCY.CURSOR_INVALIDATED`, and perform a full declarative re-read. It MUST NOT
  discard any `doc_version` or `trust_epoch` high-water mark when doing so (R-5/R-6 still bind).
- **R-9** High-water marks (§11.9, S-27) are durable and MUST be written before the document they
  admit is acted upon, so a crash between the two cannot lose the floor.

### 11.4 TTL semantics and expiry behaviour, per fact class

Two bands. `refresh_after_ms` is an instruction to the *fetcher*; `not_after_ms` is an instruction
to the *enforcer*. Between them the document governs fully and its use is reported, not restricted.

| Band | Condition | Behaviour |
|---|---|---|
| **FRESH** | `elapsed < refresh_after` | Normal. |
| **STALE** | `refresh_after ≤ elapsed < not_after` | Document **governs fully**. Refresh attempts escalate. Emit `CONTROL.STALENESS.DOCUMENT_STALE` once per document per band entry. No enforcement change. This is the band that covers the ordinary control-plane outage, and it is where [docs/architecture.md](../architecture.md) §2.14's "continue on last known-good signed policy" lives. |
| **EXPIRED** | `elapsed ≥ not_after` | Per class, below. Never a `Session` teardown (RQ-7, **I5**). |

| Fact class | Rows | `refresh_after` | `not_after` | Behaviour when EXPIRED |
|---|---|---|---|---|
| Trust list / revocation | S-03 | 15 min | 24 h | **Every denial remains in force permanently** — denials are monotone accumulations, not leases (§7.3). The device MUST NOT admit a `TrustedPeer` it knows about *only* from an expired membership document. Reconnection to an existing `TrustedPeer` (S-05, `LOCAL`) is **unaffected**, which preserves [docs/architecture.md](../architecture.md) §7's "LAN-only, no Internet at all" guarantee. Emit `CONTROL.STALENESS.TRUST_LIST_EXPIRED`. |
| Membership | S-02 | 15 min | 24 h | As above. Membership *removals* that were already learned remain applied. |
| Policy | S-06, S-07 | 15 min | bundle's own `not_after_ms` | **Grant/deny asymmetry**: every rule whose effect is to *deny* stays in force; every rule whose effect is to *grant* (exit-node use, LAN subnet acceptance, permissive DNS fallback) is **suspended**. Established `Session`s are not torn down. Emit `CONTROL.STALENESS.POLICY_GRANT_SUSPENDED` and set the guard input `policy_grant_expired`. |
| **Trust state (age of the newest verified trust document)** | S-03, S-32 | `T_TRUST_REFRESH` (6 h) | **`T_TRUST_HARD`** (30 d, [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.7) | **This is the row that mechanises the consequence bound.** On crossing `T_TRUST_HARD` the device MUST set the guard input **`trust_state_expired`**, which suspends every *granted* authority — `ExitNode` egress, `LANGateway` access, `Route` acceptance, and new `Pairing` — exactly as the Policy row suspends grants, and leaves every *denial* in force. Baseline reachability to a known `TrustedPeer` is untouched (**R-11**). Emit `AUTH.TRUST_STATE_EXPIRED`. **The effective suspension time for any given grant is `min(the bundle's own not_after_ms, T_TRUST_HARD)`** — the policy bundle and the trust state are two independent clocks and whichever expires first governs. Without this row the 30-day bound is asserted in prose and enforced by nothing, because the Policy row fires on the *bundle's* `not_after_ms`, which an `Owner` may legitimately set far beyond 30 days. |
| Relay set | S-09 | 1 h | 30 d | **Still fully usable.** Expiry has no enforcement effect whatsoever; it only escalates refresh and emits `CONTROL.STALENESS.RELAY_SET_EXPIRED`. Stale-but-usable is normative (S-09, **R-10**, **R-11**); a device that refused to fail over because its relay set was old would be a design defect. |
| Presence / health | S-10, S-11 | n/a | seconds–minutes | Record is dropped. Absence of a record is **not** evidence of absence of a peer (RQ-8). |
| Capability / version advertisement | S-19, S-20 | 1 h | 7 d | Advisory only; the negotiated set bound at handshake governs the `Tunnel` regardless (A-18). |

### 11.5 Reconciling I3 and I5 at expiry — the explicit tradeoff

[docs/architecture.md](../architecture.md) §4.4.3 forbids TTL expiry from tearing down an
established `Session`. [docs/protocol.md](../protocol.md) §13.4 makes fail-closed the shipped
default for an expired `PolicyBundle`. **Both are confirmed. They do not conflict, because they
speak about different axes**, and §11.4 draws the line:

- **The connectivity axis is fail-open.** No expiry, of any document, of any class, transitions a
  `Session` out of `LOCAL_DIRECT`/`WAN_DIRECT`/`RELAYED`. The tunnel is the thing **I5** protects.
- **The authorization axis is fail-closed.** Expiry can only ever make a device *more* restrictive:
  grants suspend, denials persist. There is no expiry path that widens an authorization. This is
  what "fail closed" means for a policy bundle, and it is mechanically checkable — a rule change
  that could widen on expiry is a schema violation.
- **Where the two axes meet** — a `Session` whose entire purpose was an expired grant, e.g. an
  exit-node default route under `FAIL_CLOSED` enforcement — the existing T29
  (`EV_POLICY_VIOLATION` → `BLOCKED`) path in [docs/reliability.md](../reliability.md) §4.5 applies
  unchanged. This ADR supplies the guard input and the reason code; it defines no new state and no
  new transition, and `BLOCKED` retains a `Session` and retries internally, so this is still not a
  teardown.

**The revocation case is deliberately different and the tradeoff is stated rather than dissolved.**
An expired *policy* is a stale opinion; an unreachable *revocation* is a possible live compromise.
We do **not** resolve it by blocking **baseline peer connectivity** on trust-list expiry, because
that would break the air-gapped `TwinNet` and would make the control plane a liveness dependency of
the data plane — exactly what **I5** and **R-11** forbid. Nor do we leave the window entirely open.
**The resolution is this ADR's own grant/deny asymmetry (§11.4), applied to trust state** — and it
is jointly owned with [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.7, which sets the
timer values:

| Trust-state age | Baseline peer connectivity (a new `Tunnel` to a known `TrustedPeer`) | Elevated authority (`ExitNode` use, `LANGateway` access, route acceptance, new `Pairing`) |
|---|---|---|
| < `T_TRUST_REFRESH` | Permitted | Permitted |
| `T_TRUST_REFRESH` … `T_TRUST_STALE` | Permitted; refresh escalates | Permitted |
| `T_TRUST_STALE` … `T_TRUST_HARD` | Permitted; persistent `Diagnostic` `AUTH.TRUST_STATE_STALE`, **no `ConnectionState` change** | Permitted, but re-asserted per use and surfaced |
| ≥ `T_TRUST_HARD` | **Still permitted** (**R-11**, **I5**) — persistent `Diagnostic` `AUTH.TRUST_STATE_EXPIRED`, **no `ConnectionState` change** | **Suspended.** These are *grants*, and §11.4 suspends grants on expiry while denials persist |

**Why this is the right cut.** Baseline reachability between two devices that already hold a
confirmed `Pairing` is not a grant the control plane makes — it is a fact the two devices
established between themselves (**A-02**), so no control-plane silence may withdraw it. Everything
in the right-hand column *is* a grant, and grants are exactly what §11.4 already suspends on
expiry. The stolen-device blast radius therefore shrinks from "full authority indefinitely" to
"can still reach peers that have not heard about the revocation, and can do nothing privileged
through them" — without the control plane ever becoming a liveness dependency.

**The accepted residue, stated precisely:** a device partitioned from the control plane *and* from
every non-stale peer keeps accepting **baseline** connections from a revoked device for as long as
that partition lasts. That residue is unbounded in time and cannot be closed by any design that
also satisfies R-11 — an authority you cannot reach cannot tell you anything. It is bounded in
*consequence* by the table above, and made observable by the 15-minute refresh interval, the
`trust_epoch` beacon on every document type (R-6), the peer-to-peer gossip of §11.6, and a
persistent user-visible staleness indication. §13 carries it;
[docs/threat-model.md](../threat-model.md) owns its analysis, as
[docs/architecture.md](../architecture.md) §4.5(4) directs.

**Timer ownership.** `T_TRUST_REFRESH`, `T_TRUST_STALE` and `T_TRUST_HARD` are defined once, in
[ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.7. This ADR defines the *consequence* of
each band; it does not restate the values. The 15-minute figure above is the S-03
`refresh_after` of §11.4 — the interval at which a *reachable* control plane is polled — and is
not the same quantity as `T_TRUST_REFRESH`, which is the escalation threshold once polling fails.

### 11.6 Bounding the revocation window without a control-plane dependency

- **G-1** Devices MUST assert their `(twinnet_id, trust_epoch)` high-water mark in the in-session
  `TrustEpochAssert` message ([docs/protocol.md](../protocol.md) §16 row 36), sent immediately
  after the handshake completes. It MUST NOT be carried **only** in the handshake prologue: the
  prologue is a local hash input, never transmitted, so a divergent epoch there fails the
  handshake opaquely rather than being *observed* — which is precisely what G-2 forbids
  ([ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) P-3). The epoch is
  additionally bound into `identity_binding_hash` so that agreement is enforced once observed.
- **G-2** A device observing a peer asserting a **higher** `trust_epoch` MUST set the guard input
  `trust_epoch_behind`, emit `CONTROL.STALENESS.TRUST_EPOCH_BEHIND_PEER`, and escalate its refresh
  attempts. It MUST NOT refuse the handshake on this basis alone — the peer is not an authority.
- **G-3** A device holding a newer `Owner`-signed `RevocationRecord` than its peer's asserted epoch
  SHOULD forward that record in-session. The receiver verifies it under the `Owner` authority
  offline (A-04, protocol A5) and applies it under R-6. A peer can therefore only ever cause the
  receiver to *add* a denial, never to remove one; a withholding or malicious peer is no worse than
  a silent one.
- **G-4** This carriage is ephemeral in-session signaling. It does **not** publish `DeviceRevoked`
  and does not alter [docs/protocol.md](../protocol.md) §7. It requires one new row in the §16
  message catalogue (§11.11).

### 11.7 Clock assumptions

- **K-1** All durable ordering is by monotone integers (`net_seq`, `trust_epoch`, `doc_version`,
  `shard_epoch`, `rotation_counter`). **No ordering or security decision depends on a timestamp.**
- **K-2** TTL is evaluated as **elapsed time since receipt on a monotonic clock**, not as a
  comparison of the local wall clock against `not_after_ms`. Remaining life on receipt is
  `not_after_ms − issued_at_ms`, decremented by monotonic elapsed time thereafter. This makes TTL
  evaluation immune to wall-clock skew and to deliberate clock tampering.
- **K-3** Where a platform's monotonic clock stops during suspend (C-6), the device MUST take the
  **larger** of monotonic-elapsed and wall-clock-elapsed — i.e. always the more conservative
  estimate of age.
- **K-4** A device maintains a skew estimate from `issued_at_ms` in verified documents. If
  |skew| > 300 s it emits `CONTROL.CONSISTENCY.CLOCK_SKEW_EXCESSIVE` and subtracts |skew| from every
  remaining-life computation. Excessive skew never blocks a `Session`.
- **K-5** Interface to [ADR-0007](ADR-0007-device-identity-and-pairing.md): `revocation_epoch` MUST
  be a monotone integer, never a timestamp; and `effective_from_ms` on a `RevocationRecord` is
  **informational and audit-only**. Enforcement begins on verification. A future-dated
  `effective_from_ms` MUST NOT defer enforcement — a device whose clock lags must not delay a
  revocation, and pre-dated revocation is a footgun with no compensating benefit.
- **K-6** Interface to [ADR-0005](ADR-0005-relay-architecture.md): the relay capability token MUST
  be evaluable as (issue instant + duration) so a device can age it monotonically; the relay MUST
  validate against **its own** clock, never the device's; and the token lifetime MUST exceed
  (maximum tolerated skew, 300 s) + the relay-failover budget, so that a clock-skewed device cannot
  be locked out of failover. Renewal MUST NOT require a control-plane call (**I5**, A-12).

### 11.8 Partition behaviour, in CAP terms, per fact class

Stated per class rather than for the system, because the system does not have one answer.

| Class | Rows | Choice | Available during partition | Refused during partition |
|---|---|---|---|---|
| `STRONG` @ authority | S-02, S-03, S-04, S-08 | **CP** | Reads from the majority side and from every device's cache. | **Writes** on the minority side: enrolment, pairing confirmation, revocation admission, address allocation. Refusal is explicit and named, never a silent success. |
| `MONOTONIC` @ edge | S-02, S-03, S-06, S-07, S-16, S-23 | **AP for reads, CP for writes** | Every device continues on its cached signed document under §11.4. | Authoring a new version on the minority side. |
| `EVENTUAL` | S-09, S-10, S-11, S-19, S-20, S-22 | **AP** | Everything. Stale values are used freely. | Nothing. Never a gate (RQ-8). |
| `LOCAL` | S-01, S-05, S-12, S-13, S-14, S-15, S-17, S-18, S-21, S-24 | **Not applicable** | Everything. There is no remote replica, so there is no partition to be on the wrong side of. | Nothing. |
| Data plane | — | **AP, absolutely** | Every established `Session`, every path migration, every relay failover, every rekey. | Nothing. This row is **I5**. |

### 11.9 Split-brain analysis

Split-brain requires two entities each believing they are authoritative for one fact. **I8** makes
this structurally impossible for every row; the mechanism differs by class and is stated per case
rather than asserted:

| Case | Rows | Why impossible, or how resolved |
|---|---|---|
| Two control-plane writers for one `TwinNet` | S-02, S-03, S-06, S-07, S-08, S-09 | Prevented by the shard lease + `shard_epoch` fencing (§11.2). A superseded writer's appends are refused at commit, so a fork cannot be created. Detected at the device by R-4 even if prevention failed. |
| Two devices authoritative for one device-scoped fact | S-01, S-12, S-13, S-14, S-15, S-17, S-18, S-21, S-24 | Impossible by construction: the authority *is* the device the fact is scoped to. A second device holds no copy at all. |
| Both ends of a `Pairing` authoritative | S-04, S-05 | Genuinely two owners of two *different* facts: the control plane owns the registered `Pairing`; each device owns its own `TrustedPeer`. Convergence is by the device-signed attestation ([docs/protocol.md](../protocol.md) §8.2) plus the ceremony idempotency key ([ADR-0008](ADR-0008-idempotency.md)); divergent confirmations abort the ceremony rather than producing half-trust. |
| Two devices advertise the same subnet | S-16 | Not split-brain: two devices asserting two *different* facts, each authoritative for its own. Resolution is at the **accepting** device (S-17, `LOCAL`), which surfaces a named conflict (**R-17**) and never silently overwrites. |
| Two devices disagree about a `Session` | S-12 | Resolved by the handshake, never by a quorum ([docs/protocol.md](../protocol.md) §15.2). Each device owns its own direction of the ordered pair, so there is no shared fact to disagree about. |
| Device and control plane disagree about `Capability` | S-19 | The set bound at handshake governs that `Tunnel` for its lifetime (A-18). A later advertisement affects only new `Tunnel`s. |

### 11.10 Interfaces required from other ADRs

| Required from | Interface |
|---|---|
| [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) | **Delivery interface:** one totally-ordered, gap-free, at-least-once, cursor-resumable event stream **per `TwinNet`**, whose positions are the same `net_seq` returned by mutating C1 responses. Every serving replica MUST expose its applied position and MUST refuse (not downgrade) a request presenting a higher cursor. Push (C3) is a wake hint that triggers a declarative re-read, **never** an ordered delta. No exactly-once claim is required or relied upon. |
| [ADR-0003](ADR-0003-network-contract-schema-format.md) | The `DocumentHeader` fields of §11.3 on every distributed document; `causality_token` sized to carry `(net_seq, trust_epoch, shard_epoch)`; and a policy schema in which *grant* and *deny* rules are **mechanically distinguishable**, so §11.4's asymmetry is checkable rather than conventional. |
| [ADR-0007](ADR-0007-device-identity-and-pairing.md) | `Owner`-rooted authority whose signatures verify **offline** (A-04); `revocation_epoch` and `rotation_counter` as monotone integers, never timestamps (K-5); a `RevocationRecord` that is self-contained and verifiable when forwarded by a peer (G-3); `effective_from_ms` explicitly non-enforcing (K-5). |
| [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) | A handshake prologue/transcript input able to carry a fixed-size `(twinnet_id, trust_epoch)` assertion (G-1), and the "reject handshake from this peer key" hook (A-06) driven by the local revoked set. |
| [ADR-0005](ADR-0005-relay-architecture.md) | Capability-token lifetime and validation semantics per K-6. |
| [ADR-0006](ADR-0006-relay-discovery-and-failover.md) | The ranked relay set MUST remain usable past `not_after_ms` (§11.4) and MUST carry ≥2 alternates per `RelayRegion` (A-13). |
| [ADR-0008](ADR-0008-idempotency.md) | Consumed, not restated: N-1 (`version` on every mutable object), N-2 (conditional writes), N-3 (reject lower versions), N-7 (monotone revocation epoch, never-shrinking revoked set), and the 24 h ceremony dedupe window with verbatim response replay (protocol A6). |
| [ADR-0015](ADR-0015-observability-and-diagnostics.md) | Registration of the `CONTROL.CONSISTENCY.*` and `CONTROL.STALENESS.*` subdomains as **owned by this ADR** (§11.11), with the codes in the table below. |
| [docs/reliability.md](../reliability.md) | Consumption of the guard inputs `policy_grant_expired`, `trust_state_expired`, `trust_epoch_behind`, `cursor_unavailable` by the **existing** transitions (principally T29). This ADR adds no state and no transition. |

**Reason codes contributed** (format per [ADR-0015](ADR-0015-observability-and-diagnostics.md)
§11.2, `DOMAIN.SUBDOMAIN.CONDITION`):

| Code | Class | Terminal | Meaning |
|---|---|---|---|
| `CONTROL.CONSISTENCY.VERSION_ROLLBACK_REJECTED` | POLICY | false | A document older than the stored high-water mark was refused (R-5). Security event. |
| `CONTROL.CONSISTENCY.FORKED_HISTORY_DETECTED` | POLICY | false | Equal version, different content (R-4). Security event; strongly implies a fencing failure or a hostile distributor. |
| `CONTROL.CONSISTENCY.REPLICA_BEHIND_CURSOR` | TRANSIENT | false | A replica refused to serve below the device's presented cursor (E-1(c)). |
| `CONTROL.CONSISTENCY.CURSOR_INVALIDATED` | TRANSIENT | false | `shard_epoch` changed with a lower `net_seq`; full re-read required (R-8). |
| `CONTROL.CONSISTENCY.SIGNATURE_UNVERIFIABLE` | PERSISTENT | false | Document discarded before any version comparison (R-1). |
| `CONTROL.CONSISTENCY.CLOCK_SKEW_EXCESSIVE` | PERSISTENT | false | Absolute skew estimate exceeds 300 s; TTLs computed conservatively (K-4). |
| `CONTROL.STALENESS.DOCUMENT_STALE` | TRANSIENT | false | STALE band entered; document still governs. |
| `CONTROL.STALENESS.TRUST_LIST_EXPIRED` | PERSISTENT | false | Trust list past `not_after`; denials still in force. |
| `CONTROL.STALENESS.TRUST_EPOCH_BEHIND_PEER` | PERSISTENT | false | A peer asserted a higher `trust_epoch` (G-2). |
| `CONTROL.STALENESS.POLICY_GRANT_SUSPENDED` | POLICY | false | Policy expired; grants suspended, denials retained. |
| `CONTROL.STALENESS.RELAY_SET_EXPIRED` | INFO | false | Relay set past `not_after`; **still in use**, by design. |

Two codes are **requested from other domain owners** rather than defined here, per
[ADR-0015](ADR-0015-observability-and-diagnostics.md)'s domain-contribution rule:
`AUTH.TRUST.PEER_DENIED_BY_CACHED_REVOCATION` from
[ADR-0007](ADR-0007-device-identity-and-pairing.md), and
`POLICY.EXPIRY.GRANT_WITHDRAWN` from [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md).

### 11.11 New state-ownership rows required in [docs/architecture.md](../architecture.md) §5

| # | State | Authoritative writer | Replicas / caches | Class | Durability | On conflict |
|---|---|---|---|---|---|---|
| **S-27** | *(the same row as [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) §11.8 — one fact, one row, deliberately merged)* Device control-channel cursor: `net_seq` high-water + `causality_token` + per-document-type version high-water marks (`trust_epoch`, `doc_version[]`) | **Local `Device` (2.20)** | None | `LOCAL` | Durable; written **before** the document it admits is acted upon (R-9), and required for gap-free C2 resume across process restart | Local wins; the marks are monotone non-decreasing, and a server-offered cursor below the local high-water MUST be rejected |
| **S-28** | `TwinNet` shard write lease + `shard_epoch` | **Control-plane shard coordinator (2.8)** | Replicas hold it read-only | `STRONG` | Durable, in the log, outside compaction | Highest `shard_epoch` wins; a write presenting a lower one is refused at commit |

Also required in [docs/protocol.md](../protocol.md) §16: one catalogue row for the in-session
trust-epoch carriage of §11.6 — `TrustEpochAssert` / `RevocationTransfer`, device ↔ device, C5/C6,
style PP, ephemeral, auth `B` (`Owner`-signed record) over an `S`-authenticated session, naturally
idempotent by `trust_epoch`, consistency "monotonic, additive-only".

### 11.12 Confirmation of the protocol's per-interaction requirements ([docs/protocol.md](../protocol.md) §15)

| Protocol row | Weakest sufficient guarantee | Satisfied by |
|---|---|---|
| `DeviceIdentity` uniqueness | Linearizable at admission, then monotonic | Single shard writer (§11.2); `MONOTONIC` distribution (§11.3) |
| `Pairing` completion | Linearizable at commit, monotonic propagation | Shard writer + ceremony idempotency key ([ADR-0008](ADR-0008-idempotency.md)) |
| **Revocation** | Linearizable admission + monotonic reads + no forked history | §11.2 E-1 (a)(b)(c) + R-4 fork detection + §11.6 gossip |
| `DeviceKey` rotation | Monotone `rotation_counter`, eventual across peers | R-6-style high-water rule applied to `rotation_counter` (K-5) |
| `AccessPolicy` / `DNSPolicy` | Monotonic reads + eventual convergence + bounded staleness | R-2…R-5 + §11.4 two-band TTL |
| `Route` / `ExitNode` advertisements | Monotone per advertiser, eventual globally, TTL-bounded | S-16 `MONOTONIC` per advertiser; acceptance is `LOCAL` (S-17) |
| `RelayAssignment` | Eventual, advisory, peer-local measurement final | S-09/S-10 `EVENTUAL`, never a gate (RQ-8) |
| `Presence` | Eventual, TTL-bounded, device-local authority | S-11 `EVENTUAL`, TTL drop, never a gate |
| `Session`/`Tunnel`/`Path` | Local-only authority | S-12…S-15 `LOCAL`; **A9 confirmed** |
| `HealthState` | Eventual, lossy, device-local | S-10/S-22 `EVENTUAL` |
| `Capability`/`ProtocolVersion` negotiation result | Local-only, immutable once bound to the transcript | §11.13 S-19 refinement |

### 11.13 Per-row justification for [docs/architecture.md](../architecture.md) §5

The whole table is **confirmed** with two notation refinements (S-04, S-19) flagged below. Columns:
why the class suffices; what breaks if it were weaker; what it would cost if stronger.

| Row | Class | Why sufficient | If weaker | If stronger |
|---|---|---|---|---|
| **S-01** `DeviceKey` | `LOCAL` | The fact has no second holder by construction (**I4**); consistency is vacuous. | Weaker means a replica exists, which is an **I4** violation, not a consistency choice. | No stronger class exists without exporting the key. |
| **S-02** membership | `STRONG`@auth / `MONOTONIC`@edge | Admission must be linearizable so `(twinnet_id, device_pubkey)` uniqueness holds and address allocation cannot collide; the edge only needs to never go backwards. | Non-linearizable admission ⇒ duplicate devices on retry and two devices at one `TwinNet` address ⇒ blackholed traffic (**R-03**). Non-monotonic edge ⇒ a removed member reappears. | `STRONG` at the edge means a control-plane read per handshake: violates **I5** and makes the CP a connectivity dependency (**R-11**). |
| **S-03** revocation / trust epoch | `STRONG`@auth, `MONOTONIC`+short TTL@edge | This is the **only** row that justifies the storage design. Linearizable admission + single writer + monotonic reads is exactly E-1. | **Trust resurrection.** A lagging replica serving epoch 41 after 42 restores a stolen device. This is the worst failure in the system. | `STRONG` at the edge would require a CP call at every handshake — breaking **I5**, **R-11**, and the LAN-only guarantee. §11.6 buys most of the freshness at none of that cost. |
| **S-04** `Pairing` | `STRONG` (registered fact) + `LOCAL` (each `TrustedPeer`) | A `pairing_id` must complete at most once; each device is sole authority for its own half. | Non-linearizable commit ⇒ asymmetric trust: A trusts B, B does not ⇒ every handshake fails with a misleading crypto error. | Making both halves `STRONG` would require a distributed transaction spanning device and CP — forbidden by [docs/protocol.md](../protocol.md) §15.2. **Refinement:** the row reads `STRONG` for both halves; the local `TrustedPeer` half is `LOCAL`. Notation only; §5's "on conflict" text is already correct. |
| **S-05** `TrustedPeer` | `LOCAL` | Locally authoritative trust is precisely what makes control-plane-free reconnect possible (A-02) and what preserves the air-gapped `TwinNet`. | A remote authority for `TrustedPeer` makes the CP a connectivity dependency — the **I5** violation §7 of [docs/protocol.md](../protocol.md) warns about. | Stronger means remote authority; see left. Deletion forced by S-03 is the one permitted override and is additive-only. |
| **S-06** `AccessPolicy` | `MONOTONIC` | A device acting on a slightly old policy is a bounded, named exposure; a device acting on an *older* policy than it already saw is a rollback attack. Monotonicity is the whole security property. | **Policy rollback attack**: a replayed older bundle silently reopens an authorization hole (**R-13** adjacent). | `STRONG` needs a CP read per evaluation — forbidden by [docs/architecture.md](../architecture.md) §4.4.2 and would make every packet-forwarding decision CP-dependent. |
| **S-07** `DNSPolicy` | `MONOTONIC` | Same argument; additionally a stale-but-monotone `DNSPolicy` still blocks the fallback resolver, so **R-14** holds while stale. | An older bundle can re-enable an upstream resolver ⇒ **DNS leak**. | Same cost as S-06, on the hottest local path there is (every resolution). |
| **S-08** address allocation | `STRONG` at allocation, then immutable | Immutability after allocation is what removes DHCP from the datapath (**R-03**) and lets a gateway restart re-derive peer addressing deterministically (S-21). | Non-linearizable allocation ⇒ two devices at one address ⇒ silent blackhole, undiagnosable from either end. | Nothing to strengthen: after allocation the fact never changes, so the strongest and weakest classes coincide. |
| **S-09** relay registry + ranking | `EVENTUAL` | Failover from a cached ranked set with ≥2 alternates works with an arbitrarily old set (**R-10**, **R-11**); the client's own RTT measurement overrides the ranking anyway. | If it were a gate, a CP outage would prevent relay failover — the exact **I5** violation §4.4.4 of [docs/architecture.md](../architecture.md) exists to prevent. | `MONOTONIC` or `STRONG` would tie failover to freshness with **zero** correctness benefit and a catastrophic availability cost. This row is `EVENTUAL` *on purpose*. |
| **S-10** relay `HealthState` | `EVENTUAL` | Health is re-derivable by probing; the device's own probe always outranks a report. | If health gated attempts, a false "unhealthy" would strand a device that could have connected. **RQ-8** forbids it. | Cost is a durable, sequenced log of high-frequency samples — the "presence as durable" antipattern in [docs/protocol.md](../protocol.md) §6.1, including its denial-of-freshness surface. |
| **S-11** presence + last-known `Endpoint` | `EVENTUAL` | A hint that shortens reconnect latency. Only a validated `Path` proves reachability. | If presence gated attempts, "peer offline" would suppress a connection that would have worked — and presence is *routinely* wrong. | A durable presence log is a **permanent movement and IP history of the `Owner`** held by infrastructure — against the spirit of **I1** ([docs/protocol.md](../protocol.md) §6.1). Ephemeral presence is a privacy property. |
| **S-12** `Session` id + last `ConnectionState` | `LOCAL` | The device is the only thing that knows whether its own tunnel is working. Durable so restart resumes into `RECONNECTING` rather than from scratch. | A CP-authoritative `Session` state would put every session into an indeterminate state during an outage, and reconciliation would tear down live tunnels. **A9 confirmed.** | `STRONG` would require consensus on `Session` state — explicitly refused by [docs/protocol.md](../protocol.md) §15.2. |
| **S-13** `Tunnel` key state | `LOCAL`, non-durable | Memory-only key state is a *security requirement* expressed as a consistency class. Loss ⇒ a new handshake, which is cheap. | Persisting or replicating it creates key material at rest and outside B1 — an **I4**/**I1** violation. | Any stronger class necessarily means replication. Forbidden. |
| **S-14** `Path` set + candidate ledger | `LOCAL`, non-durable | Paths are disposable by design (§3.4); only `Endpoint` hints deserve to survive. | Sharing path state gives no benefit and leaks topology. | Durable candidates get replayed hours later against expired NAT mappings and recycled addresses — connection storms and probes at uninvolved third parties ([docs/protocol.md](../protocol.md) §6.1). |
| **S-15** `Endpoint` cache | `LOCAL`, durable | **This row is what makes control-plane-free reconnect work** (**R-11**, §6.3 of [docs/architecture.md](../architecture.md)). Validated path evidence always beats any cached or reported endpoint. | Without durability, a process restart during a CP outage cannot reconnect at all. | A remote authority here would be the presence service, which is `EVENTUAL` by necessity — strengthening it is not available. |
| **S-16** `Route` advertisement | `MONOTONIC` per advertiser | The advertiser is the only entity that knows what it can reach; monotone epochs stop a withdrawn route from being resurrected. | A replayed old advertisement resurrects a withdrawn subnet route ⇒ blackhole, or a stale default route ⇒ **leak**. | Global `STRONG` would require the CP to arbitrate routes — and a CP that can mint routes can redirect an `Owner`'s subnet to an attacker ([docs/protocol.md](../protocol.md) §7). |
| **S-17** `Route` acceptance | `LOCAL` | Each device decides what it installs; that is what makes "a subnet route MUST be explicitly accepted, never auto-installed" (B6) enforceable. | A remote authority over installed routes is a remote authority over the local network stack. | Conflicts with pre-existing system routes surface as **R-17** diagnostics, which is only possible because the decision is local. |
| **S-18** kill-switch engagement | `LOCAL`, durable, OS-level | **I3**. The control plane MUST NOT be able to disengage it; therefore the CP must not be an authority for it at all. | Any remote authority makes "disable every kill switch in the fleet" a reachable state for a compromised CP — jointly voiding **I1** and **I3**. | There is no stronger class that does not introduce a remote writer. This row's class is a security decision wearing a consistency label. |
| **S-19** `Capability` advertisement | `EVENTUAL` globally; bound-at-handshake per `Tunnel` | The advertisement is a hint; what governs is the set negotiated into the transcript (A-18). | A mutable per-`Tunnel` set is a downgrade attack surface ([docs/protocol.md](../protocol.md) §15). | **Refinement:** §5 writes the per-`Session` half as `STRONG`; per §11.1 it is `LOCAL` — immutable once bound, with no authority and nothing to linearize. [docs/protocol.md](../protocol.md) §15 already says "local-only, immutable once bound". Notation only; behaviour unchanged. |
| **S-20** `ProtocolVersion` range | `EVENTUAL` | Only used for fleet reporting and deprecation planning; handshake negotiation is authoritative for a `Tunnel`. | Nothing operationally; a stale fleet report delays a deprecation decision. | Durable sequencing of a rarely-changing advertisement for reporting value only. |
| **S-21** per-peer gateway datapath state | `LOCAL`, non-durable | Deterministic reconstruction is *stronger* than persistence: a gateway restart re-derives the same per-peer addressing, so peers reconnect to the **same** addresses ([ADR-0013](ADR-0013-multi-client-gateway-architecture.md), **R-03**). | Replicating NAT tables and counters creates a second writer for per-peer state (**I8**) and a cross-host consistency problem on the datapath. | Durability would buy nothing that determinism does not already give, at the cost of write amplification on the hottest path in the system. |
| **S-22** telemetry / diagnostics | `EVENTUAL` | The device is the source of truth; the sink is a lossy replica with no authority. Gaps are recorded as gaps. | If the sink were authoritative, a telemetry outage would corrupt the diagnostic record — and **R-23** depends on the local ledger being complete. | Durable exactly-once telemetry does not exist and would put the management plane in the correctness path, which §4.1 of [docs/architecture.md](../architecture.md) forbids. |
| **S-23** released-version registry | `MONOTONIC` | Rollback below the minimum supported version MUST be refused; monotone signed versions give exactly that. | A downgrade attack delivering an older, vulnerable client. | `STRONG` would make the update service a connectivity dependency, which §2.21 of [docs/architecture.md](../architecture.md) explicitly forbids. |
| **S-24** user preferences | `LOCAL` | Preferences are the user's, on their device. Opt-in backup is a replica with no authority. | A remote authority for preferences is a remote authority for behaviour. | Sync conflicts on a fact with no correctness weight — cost without benefit. |

## 12. Why the Selected Option Won

**A3 won** because the alternatives fail on invariants rather than on preference. A1 puts a
control-plane call on the established-session path, which **I5** forbids in the specific terms of
[docs/architecture.md](../architecture.md) §4.4.2. A2 cannot detect a forked history, which is the
one thing [docs/protocol.md](../protocol.md) §15.1 says client-side defence cannot do — and
revocation is the row where that matters. A3's cost is that four classes must each be justified;
§11.13 is that justification, and its existence is the reason the cost is acceptable.

**B5 won** because the unit of consistency it chooses is the unit the domain actually has. A
`TwinNet` is the only scope in which ordering is required, it is small, and
[docs/protocol.md](../protocol.md) §15.2 permanently forbids cross-scope ordering. One writer per
`TwinNet` therefore satisfies E-1 and E-2 *by construction* rather than by mechanism: E-2's failure
case ("the C1 write path and the C2 read path diverge across shards") cannot occur, because a
`TwinNet` is never split. It also collapses to a single process for T2/T3 without a separate code
path — the decisive point against B4, which would ask a self-hosting individual to operate a
distributed consensus database for guarantees the protocol has said it never wants. B1 and B2 are
kept as the two acceptable realizations *within* a shard because both satisfy the same stated
interface, and forcing one on every operator would be a decision without a reason. B3 is rejected
for exactly the reason [ADR-0008](ADR-0008-idempotency.md) §6 rejected CRDTs: commutative merge
over trust state risks un-revocation, and a merge disciplined enough to avoid that has already
reimplemented a monotone epoch behind a single writer.

**C3 won** because it is the only option that satisfies both **I3** and **I5** simultaneously. C1
converts a control-plane outage into a user-visible outage and bricks an air-gapped `TwinNet`; C2
gives no bound on the revocation window and no lever after an incident. C3's grant/deny asymmetry
is the specific insight that dissolves the apparent conflict between
[docs/architecture.md](../architecture.md) §4.4.3 and [docs/protocol.md](../protocol.md) §13.4:
expiry is fail-open on the connectivity axis and fail-closed on the authorization axis, and because
denials are monotone accumulations rather than leases, expiry can never weaken anything. That last
property is what makes trust-list TTL safe to be a freshness signal instead of an authorization
lease — and it is what lets us keep the LAN-only guarantee without keeping a revoked device
trusted for any reason other than an actual partition.

## 13. Known Tradeoffs

| Tradeoff | Consequence | Mitigation |
|---|---|---|
| Revocation is not enforced during a full partition | A device isolated from the control plane **and** from every non-stale peer keeps trusting a revoked device for the duration | 15-minute refresh; `trust_epoch` beacon on every document type (R-6); data-plane gossip (§11.6); persistent user-visible staleness. Residue is stated, not hidden ([docs/architecture.md](../architecture.md) §4.5(4)); [docs/threat-model.md](../threat-model.md) owns the analysis |
| Four consistency classes instead of one | More to review; a misclassified row is a silent defect | §11.13 is normative and exhaustive; a new persistent fact MUST be classified in §5 before it exists |
| Single writer per `TwinNet` | No write scale-out within one `TwinNet`; a hot `TwinNet` is bounded by one writer | Design point is tens of devices and single-digit ceremonies per lifetime; §14.3 is a falsifiable trigger, not a hope |
| Anti-rollback strands devices after an operator restore | Restoring an old backup does not rewind devices; it isolates them | Correct by design ([ADR-0008](ADR-0008-idempotency.md) §10.1); epoch-bump runbook is mandatory (§10.2) and mechanically checkable (R-7) |
| Grant/deny asymmetry needs schema support | A policy schema that cannot distinguish grants from denials cannot implement §11.4 | Stated as an interface obligation on [ADR-0003](ADR-0003-network-contract-schema-format.md) (§11.10), not assumed |
| Peer-carried revocation adds a data-plane path for control-plane content | New surface on the tunnel; a peer can force a receiver to do verification work | Additive-only and `Owner`-signed: a peer can only cause a denial to be added, never removed; rate-limited per peer; **G-2** forbids refusing a handshake on a peer's assertion alone |
| Whole-bundle policy transfer | Bandwidth on every policy change | Mandated by [docs/protocol.md](../protocol.md) §15.1 E-3; kilobytes at personal scale; deltas would require exactly-once delivery, which does not exist |
| Three monotone counters (`net_seq`, `trust_epoch`, `doc_version`) plus `shard_epoch` | More fields to reason about than a single version | Each has a distinct job: log position (E-2), security generation that survives compaction and shard migration, per-type version so a policy update does not force a trust-list refetch, and a fencing token. Collapsing any two would couple unrelated failure modes |
| Refusing a lagging replica rather than serving it | A device can be told "not yet" during failover | It keeps running on its cache (**I5**) and retries; the alternative is un-revoking a stolen device |

## 14. Revisit Conditions

1. **Fork detection fires in the field.** Any occurrence of
   `CONTROL.CONSISTENCY.FORKED_HISTORY_DETECTED` outside a fault-injection test ⇒ the fencing
   mechanism (§11.2) failed or a distributor is hostile. Treat as a **P1 security incident**, not a
   consistency tuning issue.
2. **Rollback rejections outside operator restores.** `CONTROL.CONSISTENCY.VERSION_ROLLBACK_REJECTED`
   observed on more than **0.01 %** of devices in any 7-day window without a corresponding operator
   restore ⇒ investigate replication or a hostile distributor.
3. **Single-writer throughput.** If p99 durable-append latency for any `TwinNet` exceeds **200 ms**,
   or any single `TwinNet` sustains more than **50 durable events/second** for 5 minutes, the B5
   sharding assumption ("a `TwinNet` is small") has been falsified ⇒ re-evaluate B2 with intra-shard
   parallelism, or split the log by `doc_type`.
4. **Revocation propagation.** If the measured p95 time from revocation admission to
   `trust_epoch` confirmation across all online devices exceeds **60 s**, or if more than **5 %** of
   devices are observed more than one `trust_epoch` behind at any sample, the freshness argument in
   §11.5 no longer bounds the window ⇒ shorten `refresh_after`, or escalate §11.6 G-3 from SHOULD to
   MUST.
5. **Staleness in the enforcement band.** If `CONTROL.STALENESS.POLICY_GRANT_SUSPENDED` fires on more
   than **0.5 %** of device-days, the policy `not_after_ms` default is shorter than real-world
   control-plane availability ⇒ lengthen it, or move the affected grants to deny-by-default rules
   that do not expire.
6. **Clock skew.** If `CONTROL.CONSISTENCY.CLOCK_SKEW_EXCESSIVE` exceeds **1 %** of devices, the K-2
   monotonic-elapsed model is being defeated by a platform whose monotonic clock behaves
   unexpectedly across suspend ⇒ re-derive K-3 for that platform.
7. **Cursor invalidation.** If `CONTROL.CONSISTENCY.CURSOR_INVALIDATED` occurs outside a deliberate
   shard rebuild, `net_seq` assignment is not as durable as §11.2 claims.
8. **A dependency changes.** If [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) adopts
   a per-service (rather than per-`TwinNet`) stream, E-2's by-construction argument in §11.2 fails
   and an explicit read-your-writes token becomes mandatory in `causality_token`. If
   [ADR-0007](ADR-0007-device-identity-and-pairing.md) makes `revocation_epoch` a timestamp rather
   than a monotone integer, K-1 and R-6 both break and this ADR must be re-decided. If
   [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) cannot carry the prologue
   assertion of G-1, §11.6 collapses to refresh-interval-only and the §13 residue widens.
9. **Multi-`Owner` support ships** ([docs/vision.md](../vision.md) §3.5). A second `Owner` authority
   in one `TwinNet` introduces a second writer for trust state, breaking **I8** and C-1, and the
   whole of §11.2 must be re-decided — most likely toward B2 with an explicit membership-change
   protocol.
