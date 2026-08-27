# ADR-0008: Idempotency

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** ARCHITECTURE
- **Related:** [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md), [ADR-0003](ADR-0003-network-contract-schema-format.md), [ADR-0007](ADR-0007-device-identity-and-pairing.md), [ADR-0009](ADR-0009-state-consistency.md), [ADR-0013](ADR-0013-multi-client-gateway-architecture.md), [docs/architecture.md](../architecture.md), [docs/reliability.md](../reliability.md), [docs/protocol.md](../protocol.md)

**Scope.** This ADR decides which TwinVPN operations MUST be idempotent, and the mechanism by
which each becomes idempotent. It owns *idempotency semantics*. It does **not** own retry policy
— when, how often, and with what backoff to retry is owned by
[docs/reliability.md](../reliability.md). The division is deliberate: retry policy is only safe
because the operations it retries are idempotent, and those are two separately-reviewable claims.

---

## 1. Context

TwinVPN's defining requirement is that connections establish and recover *without user
intervention* (R-06, R-09). Unattended recovery means aggressive automatic retry, and aggressive
retry across an unreliable network means **every control operation will be delivered more than
once**, will be delivered out of order, and will sometimes be delivered after the client has
already given up on it and moved on.

The failure modes this creates are not hypothetical; they are the mechanism behind several
defects in [docs/vision.md](../vision.md) §5:

- A retried `Pairing` confirmation creating two `Pairing` records, leaving the two devices with
  asymmetric trust (one trusts, one does not) — a connection that fails with no coherent
  explanation (R-22).
- A retried relay assignment leaving orphaned relay flows consuming capacity, degrading the relay
  fleet the product depends on (R-10).
- A partially-applied local network program — routes installed, firewall rules not — which is
  exactly the "virtual-interface conflict" and "route-establishment stall" class (R-17, R-03).
- A late-arriving duplicate of a *stale* policy write silently reverting a newer policy — a
  security downgrade delivered by the retry machinery itself (R-13 adjacent).

Additionally, invariant **I5** means devices operate for long periods against a *cached* view and
then reconcile in a burst when the control plane returns. Reconnection storms after an outage are
the normal case, not an edge case, so idempotency must hold under high duplicate concurrency, not
just under a leisurely single retry.

Finally, **I8** (single-writer state ownership, [docs/architecture.md](../architecture.md) §5)
gives us a lever: because every fact has exactly one authoritative writer, idempotency only ever
needs to be solved at *one* place per fact, not negotiated between competing writers.

## 2. Requirements

| # | Requirement |
|---|---|
| **RQ-1** | Every control-plane mutation MUST be safe to deliver **at least once**, i.e. duplicate delivery MUST NOT change the observable result beyond the first application. |
| **RQ-2** | Every mutation MUST be safe to deliver **out of order**; a late duplicate of a superseded write MUST NOT revert newer state. |
| **RQ-3** | A retried operation MUST be able to learn the *outcome* of the original attempt, not merely "no error" — a client that times out must be able to discover whether the write landed. |
| **RQ-4** | Idempotency MUST hold across client process restart and across control-plane instance failover (the dedup record cannot live only in one server's memory). |
| **RQ-5** | Local OS-state application (interface, `Route`, firewall, resolver) MUST be idempotent and MUST be **all-or-nothing**: never partially applied, always rollbackable (R-17). |
| **RQ-6** | Revocation MUST be idempotent **and** monotonic: replaying an old revocation state MUST NOT un-revoke anything (I1/I4-adjacent security property). |
| **RQ-7** | Idempotency MUST NOT require the control plane during established-session operation (I5) — the data plane's own replay protection is separate and lives in [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md). |
| **RQ-8** | Dedup state MUST have bounded growth; unbounded dedup logs are an availability defect on a self-hosted single-box control plane (topology T2/T3, [docs/architecture.md](../architecture.md) §7). |
| **RQ-9** | Every non-idempotent operation MUST be explicitly justified and enumerated. "Probably fine" is not a classification. |

## 3. Constraints

- **C-1 (I2 / P2)** — no novel cryptography. Idempotency keys are opaque random identifiers, not
  a cryptographic construction with security claims of their own. A replayed *authenticated*
  message is a protocol-layer concern owned by [ADR-0001]/[ADR-0002], not solved here.
- **C-2 (I8)** — exactly one authoritative writer per fact. Idempotency mechanisms MUST NOT
  introduce a second writer (this rules out client-side "just write both places and reconcile").
- **C-3 (I5)** — no mechanism may add a control-plane dependency to an established-session path.
- **C-4 (self-hostable control plane)** — T2/T3 topologies run the control plane on modest
  single-box hardware. Mechanisms requiring a distributed transaction coordinator or an external
  exactly-once broker are effectively excluded (see RQ-8).
- **C-5 (mobile reality)** — a mobile client may be suspended mid-operation for minutes and
  resume expecting to complete. Dedup windows must exceed plausible suspension, not just
  plausible network delay.
- **C-6** — the transport and schema are owned by [ADR-0002] and [ADR-0003]; this ADR specifies
  *fields and semantics required*, and those ADRs specify their encoding.

## 4. Considered Alternatives

- **ALT-A — Client-generated idempotency keys with a server-side dedup log.** Each mutating
  request carries a client-generated unique `idempotency_key`. The server records
  key → (outcome, response) and replays the recorded response for duplicates within a window.
- **ALT-B — Server-side content-hash deduplication.** No client key; the server hashes the
  canonicalized request body plus the caller identity and dedups on that.
- **ALT-C — Declarative desired-state (PUT-style) APIs.** Operations are expressed as "make the
  state be X" rather than "do action Y". Re-applying the same desired state is naturally a no-op.
- **ALT-D — Monotonic sequence numbers / versioned conditional writes.** Every mutable object
  carries a version; writes are conditional (`If-Match: version`) and carry a per-writer monotonic
  sequence number. Stale and duplicate writes fail the precondition.
- **ALT-E — CRDT-style commutative operations.** Model state as conflict-free replicated data
  types so all operations are commutative, associative, and idempotent by construction, and
  ordering stops mattering.
- **ALT-F — Exactly-once delivery via a transactional broker/outbox.** Push the problem into the
  messaging layer: a transactional queue with dedup, plus a transactional outbox on the server, so
  application code can assume single delivery.

## 5. Advantages of Each Alternative

- **ALT-A (client keys + dedup log)** — Works for genuinely non-declarative *ceremonies* (pairing,
  key rotation) where "desired state" is not expressible. Uniquely satisfies **RQ-3**: the client
  can retry and receive the *original* recorded outcome, learning whether the first attempt landed.
  Simple to reason about and to audit. Well-understood industry pattern with clear failure modes.
- **ALT-B (content-hash dedup)** — Zero client cooperation required, so it also protects against
  buggy or old clients. No new wire field. Naturally collapses genuinely identical requests.
- **ALT-C (declarative desired state)** — The strongest form: idempotency is a *property of the
  API shape*, not a mechanism bolted onto it, so it cannot be forgotten, mis-implemented, or
  disabled. No dedup state at all, therefore no RQ-8 growth problem and no dedup-window
  expiry cliff. Composes perfectly with I5: a device reconciling after a long outage simply
  re-asserts desired state rather than replaying a queue of actions. Maps directly onto the signed,
  versioned state documents already required by [docs/architecture.md](../architecture.md) §4.4.3.
- **ALT-D (versioned conditional writes)** — The only alternative that satisfies **RQ-2**
  (out-of-order safety) directly rather than incidentally: a stale write is *rejected*, not merely
  deduplicated. Gives real optimistic concurrency between an owner's admin UI and a device.
  Provides the anti-rollback property RQ-6 needs almost for free. Cheap: one integer per object.
- **ALT-E (CRDTs)** — Ordering-independent by construction; excellent under partition, which is
  TwinVPN's normal condition. Genuinely the right model for presence and health, which are
  high-frequency, low-stakes, and last-writer-wins in nature.
- **ALT-F (transactional broker/outbox)** — Lets every individual handler be written naively.
  Strong operational tooling exists. Centralizes the hard part in one reviewed component.

## 6. Disadvantages of Each Alternative

- **ALT-A** — Requires dedup storage with a TTL, which is exactly the RQ-8/C-4 growth problem, and
  creates a **correctness cliff at window expiry**: a retry arriving after the window is treated as
  a fresh operation. Under C-5 (mobile suspension) the window must be long, which worsens the
  growth problem. Dedup records must survive control-plane failover (RQ-4), so they need durable
  replicated storage — real cost on a single-box self-hosted deployment. Does nothing for RQ-2:
  two *different* keys carrying stale and fresh state still race.
- **ALT-B** — Cannot distinguish "the user genuinely did the same thing twice on purpose" from a
  duplicate, which is wrong for any operation with real repeat semantics. Canonicalization is a
  notorious bug source (field order, optional fields, encoding), and a canonicalization bug becomes
  a *silent* correctness failure. Fails RQ-3 entirely: the caller learns nothing about the original
  outcome. Timestamps or nonces in the body defeat it completely.
- **ALT-C** — Not all operations are expressible as desired state. A `Pairing` ceremony with
  out-of-band verification, a key rotation, and "assign me a relay flow now" are **actions**, not
  states; forcing them into PUT semantics produces contrived, harder-to-audit models. Also, a naive
  PUT is not out-of-order-safe on its own — a stale full-document PUT will happily revert newer
  state (this is precisely RQ-2), so ALT-C is incomplete without ALT-D.
- **ALT-D** — Solves ordering and conflict but **not** RQ-3: a client that times out still does not
  know whether its conditional write applied; it must re-read to find out, which is impossible
  during the very control-plane outage that caused the timeout. Requires the client to hold a
  current version, which is awkward for creation operations (no prior version exists).
- **ALT-E** — For the state that actually matters here — **revocation and policy** — CRDT semantics
  are wrong in a *security-relevant* way. Commutativity means an old "not revoked" assertion can
  merge with a new "revoked" one and, under a poorly chosen merge function, un-revoke a device
  (violating RQ-6). Getting the merge right requires the same monotonic-epoch discipline as ALT-D,
  at which point the CRDT machinery is added complexity for no gain. Also, CRDT metadata grows,
  and debugging merge outcomes is materially harder — hostile to R-23 (diagnosability).
- **ALT-F** — Heavyweight infrastructure, in direct conflict with **C-4**: it makes the
  single-box self-hosted control plane (T2/T3) substantially harder to operate, and T2/T3 are
  first-class topologies, not a niche. Worse, "exactly once" across a *device-to-server* boundary
  is not actually achievable — the broker can guarantee exactly-once *within* its own system, but
  the client's request may still be lost before it reaches the broker or its response lost after,
  so application-level idempotency is still required. It buys less than it appears to.

## 7. Security Implications

Of the selected option (ALT-C + ALT-D + ALT-A, §11):

1. **Anti-rollback is a security control, not a hygiene measure.** The monotonic version from
   ALT-D is what prevents a stale `AccessPolicy`, `DNSPolicy`, or trust-list document from being
   replayed to weaken a device (S-03, S-06, S-07 in [docs/architecture.md](../architecture.md) §5).
   The rule is normative: **a device MUST reject any state document whose version is lower than the
   version it has already accepted**, and MUST record the rejection as a security event
   ([ADR-0015](ADR-0015-observability-and-diagnostics.md)). This is enforced at the local store (2.20),
   so it holds even against a compromised or hostile control plane — a meaningful property given
   the control plane is only *semi*-trusted ([docs/architecture.md](../architecture.md) §8, B3).
2. **Revocation replay.** RQ-6 requires that replaying an older trust list never un-revokes.
   Revocation is therefore expressed as a monotonically increasing epoch plus a
   never-shrinking revoked set, never as a mutable "revoked: true/false" field. Interface required
   from [ADR-0007]: the trust-list document MUST be signed and MUST carry that epoch.
3. **Idempotency keys are not capabilities.** An `idempotency_key` MUST NOT confer authorization.
   Dedup lookup MUST be scoped to the authenticated caller's `DeviceIdentity`, so one device
   cannot probe or replay another device's outcomes by guessing keys. Keys MUST be ≥128 bits of
   randomness to make cross-caller collision negligible even though scoping already prevents it.
4. **Dedup log as an information leak.** The dedup log records what a device did and when. It
   inherits the retention and redaction rules of [ADR-0015] and MUST NOT be retained beyond its
   functional window.
5. **Replay at the wire layer is a different problem.** Cryptographic replay protection for tunnel
   frames and for the handshake belongs to [ADR-0001]; control-message replay protection belongs to
   [ADR-0002]. This ADR assumes both exist and layers *application-level* idempotency above them.
   It would be a serious error to treat idempotency keys as a substitute for either.
6. **Where a rejected alternative was better:** ALT-B (content-hash dedup) is materially better at
   defending against a *buggy or malicious client that omits idempotency keys*, because it needs no
   client cooperation. We accept this loss because the control plane already authenticates every
   caller by `DeviceIdentity` and enforces per-caller limits, so a misbehaving client harms only
   its own state.

## 8. Reliability Implications

1. **This ADR is what makes [docs/reliability.md](../reliability.md)'s retry policy safe.**
   Unattended, aggressive, jittered retry (R-06) is only correct because every retried operation is
   idempotent. The dependency is explicit and one-directional: reliability may retry anything
   classified `IDEMPOTENT` in §11's table, and MUST NOT auto-retry anything classified
   `CEREMONY` without carrying the original `idempotency_key`.
2. **Reconnection storms are the design point.** After a control-plane outage ends, every device
   reconciles at once. Because reconciliation is declarative (ALT-C) rather than a replayed action
   log, the work is O(devices), bounded, and naturally coalescing — a device that reconciles twice
   costs the same as once. An action-replay design would have produced a duplicate-write storm at
   exactly the moment the control plane is most fragile.
3. **RQ-3 is what prevents the worst reliability failure**: a client that cannot determine whether
   its pairing confirmation landed either retries forever (R-09's "retry forever with no diagnosis")
   or gives up and leaves asymmetric trust. The recorded-outcome replay from ALT-A resolves this
   deterministically.
4. **All-or-nothing local application (RQ-5)** removes a whole class of "connected but nothing
   works" states: the OS network program is computed as a complete desired state, validated for
   conflicts against pre-existing system state, applied transactionally where the platform allows
   and with a compensating rollback where it does not, then verified by read-back. A partial apply
   is a failure with a named `reason_code`, never a silent half-configuration (R-17).
5. **Failure modes introduced:** the dedup-window expiry cliff (ALT-A) and precondition-failure
   loops (ALT-D). Both are mitigated in §13.

## 9. Performance Implications

1. **Steady state cost is near zero.** Declarative reconciliation compares versions; when nothing
   changed, the device sends a version and receives "unchanged". Idempotency adds one integer
   comparison, not a round trip.
2. **Dedup log lookup** adds one indexed read plus one write per *ceremony* operation. Ceremonies
   (pairing, rotation, revocation) are rare — single-digit-per-device-lifetime — so the cost is
   irrelevant. It is deliberately **not** applied to high-frequency operations: presence heartbeats
   and telemetry are last-writer-wins and need no dedup log (§11 table).
3. **No data-plane cost.** Nothing in this ADR touches the established-session path (C-3/RQ-7).
   Throughput (R-15) is unaffected by construction.
4. **Where a rejected alternative was better:** ALT-E (CRDTs) would allow devices to merge state
   peer-to-peer without any round trip to an authority, which is strictly better for
   partition-heavy operation and would reduce control-plane load. We give that up deliberately for
   the security reasons in §6/§7.
5. **Storage:** dedup records are bounded by (ceremony rate × window). With a 24-hour window and
   realistic personal-scale ceremony rates this is kilobytes per `TwinNet` — comfortably within C-4.

## 10. Operational Implications

1. **Self-hosted operators (T2/T3) gain a simple mental model**: control-plane state is a set of
   versioned documents; the recovery procedure after a restore-from-backup is "documents with lower
   versions than devices already hold are rejected by the devices". This is safe by default but has
   a sharp operational edge: **restoring an older control-plane backup does not silently rewind
   devices — it strands them.** That is the correct behavior (§7.1) and MUST be documented in the
   operator runbook, with an explicit epoch-bump procedure as the supported recovery.
2. **Observability requirement on [ADR-0015]:** the following MUST be emitted as structured events
   — `idempotent_replay_served` (a duplicate was collapsed), `precondition_failed` (a stale
   conditional write was rejected), `version_rollback_rejected` (a security event), and
   `local_apply_rolled_back`. Without these, duplicate-driven bugs are invisible.
3. **Dedup window is a tunable with a stated default**: 24 hours, chosen to exceed plausible mobile
   suspension (C-5) by a wide margin. It is a control-plane configuration value, not a protocol
   constant, so it can be raised without a `ProtocolVersion` bump.
4. **Testing obligation on [docs/testing-strategy.md](../testing-strategy.md):** a duplicate-and-
   reorder fuzz harness that replays every control operation N times in random order, including
   across a simulated control-plane failover, asserting final-state equivalence. Plus a
   partial-apply fault-injection test for RQ-5 on every supported platform.

## 11. Decision

**TwinVPN adopts a layered idempotency model: declarative desired state (ALT-C) as the default API
shape, monotonic versioned conditional writes (ALT-D) on every mutable object, and client-generated
idempotency keys with a bounded server-side dedup log (ALT-A) for the enumerated set of operations
that are genuinely ceremonies rather than states.** ALT-B, ALT-E, and ALT-F are rejected as primary
mechanisms; ALT-E's last-writer-wins-register semantics are retained *only* for presence and health.

### 11.1 Normative rules

- **N-1** Every mutable control-plane object MUST carry a monotonically increasing `version`.
- **N-2** Every mutating request MUST be conditional on the version the caller believes it is
  updating, except creation, which is conditional on non-existence.
- **N-3** A device MUST reject any received state document whose `version` is lower than the
  version it has already accepted, and MUST emit `version_rollback_rejected`.
- **N-4** Operations classified `CEREMONY` in §11.3 MUST carry a client-generated
  `idempotency_key` of ≥128 bits, scoped to the authenticated `DeviceIdentity`.
- **N-5** The control plane MUST record `(device_id, idempotency_key) → (outcome, response)`
  durably for the dedup window (default 24 h) and MUST replay the recorded response verbatim for
  duplicates within it.
- **N-6** A duplicate arriving **after** the window MUST be evaluated against the version
  precondition (N-2) and therefore MUST fail rather than re-execute. The expiry cliff is closed by
  N-2, not by a longer window.
- **N-7** Revocation MUST be modelled as a monotonic epoch plus a never-shrinking revoked set. An
  operation that would shrink the revoked set MUST be rejected.
- **N-8** Local OS-state application MUST be a reconciliation of a fully-computed desired state,
  MUST be conflict-checked against pre-existing system state before any mutation, and MUST be
  all-or-nothing with verified read-back.
- **N-9** Presence and health writes MUST NOT use the dedup log; they are timestamped
  last-writer-wins registers and are permitted to be lost.
- **N-10** Any operation not classifiable under §11.3 MUST NOT be added to the control plane
  without amending this ADR (RQ-9).

### 11.2 Interfaces required from other ADRs

| Required from | Interface |
|---|---|
| [ADR-0003](ADR-0003-network-contract-schema-format.md) | Wire-level fields: `version` (integer, monotonic) on every mutable object; `if_version` precondition on every mutation; `idempotency_key` (opaque ≥128-bit) on ceremony requests; a `precondition_failed` and a `duplicate_replayed` outcome in the `reason_code` registry |
| [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) | At-least-once delivery with per-message identity; **no** exactly-once claim is required or relied upon; push notifications MUST be treatable as hints that trigger a declarative re-read, never as state deltas that must be applied in order |
| [ADR-0007](ADR-0007-device-identity-and-pairing.md) | The `Pairing` ceremony MUST accept and honor an `idempotency_key`; the trust-list document MUST be signed and carry a monotonic epoch (N-7) |
| [ADR-0005](ADR-0005-relay-architecture.md) / [ADR-0006](ADR-0006-relay-discovery-and-failover.md) | Relay flow establishment MUST be idempotent per `(session_id, relay_id)` so a retried open reuses the existing flow instead of orphaning one |
| [docs/reliability.md](../reliability.md) | Retry policy MUST retry only `IDEMPOTENT`-class operations freely, and MUST reuse the original `idempotency_key` when retrying a `CEREMONY` |
| [ADR-0015](ADR-0015-observability-and-diagnostics.md) | The four structured events in §10.2 |

### 11.3 Operation classification (normative)

`DECLARATIVE` = expressed as desired state, naturally idempotent (ALT-C + ALT-D).
`CEREMONY` = an action with an outcome; requires an idempotency key (ALT-A + ALT-D).
`REGISTER` = last-writer-wins, loss-tolerant (ALT-E semantics, no dedup log).
`LOCAL` = local OS-state reconciliation (N-8).

| Operation | Class | Mechanism | Dedup window | Notes |
|---|---|---|---|---|
| Device enrollment / registration | `CEREMONY` | idempotency key + create-if-absent on `device_id` | 24 h | `device_id` is derived from the public key (A-01), so a duplicate enroll is naturally the *same* device — the key protects the surrounding record creation |
| `Pairing` initiate | `CEREMONY` | idempotency key | 24 h | Duplicate initiate MUST return the original `pairing_id`, never mint a second |
| `Pairing` confirm | `CEREMONY` | idempotency key + `if_version` on the `Pairing` | 24 h | The RQ-3 case: a timed-out client re-sends the same key and learns the recorded outcome. This is what prevents asymmetric trust |
| Device revocation | `CEREMONY` | idempotency key + monotonic epoch (N-7) | 24 h | Re-revoking is a no-op; un-revoking is impossible by construction |
| `DeviceKey` rotation | `CEREMONY` | idempotency key + succession signed by the prior identity | 24 h | Interface from [ADR-0007]; a duplicate rotation MUST NOT create a second successor identity |
| `AccessPolicy` / `DNSPolicy` push | `DECLARATIVE` | full signed document + monotonic version | n/a | Devices reject lower versions (N-3). This is the anti-downgrade control |
| Trust-list / membership distribution | `DECLARATIVE` | signed document + monotonic epoch | n/a | Same, with the security weight of §7.2 |
| `Route` / subnet advertisement | `DECLARATIVE` | desired advertised set + version | n/a | Advertiser is the single writer (S-16) |
| `Capability` advertisement | `DECLARATIVE` | desired capability set + version | n/a | Negotiated set per `Tunnel` is separate (S-19) |
| `TwinNet` address allocation | `DECLARATIVE` | deterministic derivation from `DeviceIdentity`, recorded once, immutable | n/a | Because it is derived and immutable, retry is trivially safe — **this is why no DHCP is needed in the datapath (R-03)** |
| Relay flow open / assignment | `CEREMONY` | idempotency key scoped to `(session_id, relay_id)` | 5 min | Short window: flows are short-lived; a duplicate open MUST return the existing flow handle, never allocate a second (prevents relay capacity leaks, R-10) |
| Relay ranked-set fetch | `DECLARATIVE` | read-only, versioned | n/a | Read-only operations are idempotent trivially |
| Presence heartbeat | `REGISTER` | timestamped LWW | none | Loss-tolerant by design (S-11); MUST NOT gate connection attempts |
| `HealthState` report | `REGISTER` | timestamped LWW | none | Same (S-10) |
| Telemetry event submission | `REGISTER` + event id | server-side dedup on event id, best-effort | 1 h | Duplicate events MUST NOT double-count metrics; loss is permitted but MUST be recorded as a gap |
| Local interface / `Route` / firewall / resolver program | `LOCAL` | N-8 reconciliation with conflict pre-check, transactional apply, verified read-back, rollback | n/a | Discharges R-17 and R-03 |
| Kill-switch engage / disengage | `LOCAL` | desired state; engage is idempotent; **disengage requires explicit `Owner` action** | n/a | Disengage is deliberately *not* auto-retryable (I3 / P3) |
| Update check / download | `DECLARATIVE` | content-addressed artifact + monotonic version | n/a | Rollback below minimum supported version MUST be refused (S-23) |
| `Session` establishment (data plane) | — | out of scope; replay protection is [ADR-0001] | n/a | Listed for completeness so the boundary is explicit (RQ-7) |

### 11.4 Explicitly non-idempotent operations

Per RQ-9, exactly one class of operation is intentionally not idempotent:

| Operation | Why | Safeguard |
|---|---|---|
| Kill-switch **disengage** | Making "stop protecting me" replay-safe and auto-retryable is precisely the silent-fallback defect (R-13). It MUST require a fresh, explicit `Owner` action every time | Never auto-retried; never triggered by reconciliation; requires local user authorization; emits a security event |

## 12. Why the Selected Option Won

The layered choice won because the three mechanisms cover three *different* failure modes and no
single mechanism covers all of them:

- **ALT-C (declarative) won the default** because it makes idempotency a structural property
  rather than a mechanism someone can forget. It also aligns exactly with the signed, versioned,
  cacheable state documents that [docs/architecture.md](../architecture.md) §4.4.3 already requires
  in order to satisfy **I5** — so it costs nothing architecturally and pays for itself twice. A
  device recovering from a long partition re-asserting desired state is the *same* code path as
  normal operation, which is a substantial reliability win over an action-replay model.
- **ALT-D (versioned conditional writes) won the conflict layer** because it is the only candidate
  that addresses RQ-2 (out-of-order safety) head-on, and because its anti-rollback property is a
  genuine security control (§7.1) rather than a correctness nicety. It also closes ALT-A's
  window-expiry cliff (N-6), which was ALT-A's most serious flaw.
- **ALT-A (idempotency keys) won the ceremony layer** because it is the only candidate satisfying
  **RQ-3**, and RQ-3 is the difference between "pairing sometimes leaves the two devices
  disagreeing about whether they trust each other" and a deterministic outcome. Ceremonies are rare,
  so ALT-A's costs (dedup storage, window management) apply to a tiny fraction of traffic.

The rejections were decided on specific grounds, not on preference:

- **ALT-B** was rejected because canonicalization bugs fail *silently* and because it cannot
  satisfy RQ-3. Silent failure modes are disqualifying in a product whose thesis is diagnosability
  (P10).
- **ALT-E** was rejected as a primary mechanism on a security argument: commutative merge applied
  to revocation risks un-revocation (RQ-6), and any CRDT design disciplined enough to avoid that has
  already reimplemented ALT-D's monotonic epoch. Retaining CRDT-like LWW semantics *only* for
  presence and health keeps the benefit where it is free of security weight.
- **ALT-F** was rejected on **C-4**: it would compromise the self-hosted single-box control plane,
  and T2/T3 are first-class topologies. It also does not remove the need for application-level
  idempotency, so it would be added cost for partial coverage.

## 13. Known Tradeoffs

| Tradeoff | Consequence | Mitigation |
|---|---|---|
| Three mechanisms instead of one | More surface to review; a developer must know which class an operation is in | §11.3 is normative and exhaustive; N-10 forbids unclassified operations |
| Every mutable object carries a version | Clients must track versions; creation has no prior version | Creation is conditional-on-absence (N-2); version is a single integer on the wire |
| Anti-rollback strands devices after a control-plane backup restore | An operator restoring old state cannot silently rewind devices; devices reject the older documents | Correct-by-design (§7.1); operator runbook must include the epoch-bump recovery procedure (§10.1) |
| Dedup log is durable state on the control plane | Cost and retention burden, including on a self-hosted box | Ceremony-only scope; 24 h TTL; bounded by ceremony rate (§9.5) |
| Precondition failures can loop | Client retries with a stale version, fails again | Precondition failure MUST trigger a re-read of the current document before the next attempt, not a blind retry (obligation on [docs/reliability.md](../reliability.md)) |
| No exactly-once semantics anywhere | Callers must tolerate duplicates; telemetry counts can be off if event ids collide | Explicit at-least-once contract; telemetry dedups on event id and records gaps rather than guessing |
| Presence/health are permitted to be lost | Reconnect wake-ups can be missed | Presence is never a gate (S-11); timer-driven retry is the backstop (§6.3 of [docs/architecture.md](../architecture.md)) |
| We lose ALT-B's protection against key-omitting clients | A buggy client could create duplicate ceremony records | Damage is scoped to that device's own state by per-caller scoping (N-4) and per-caller rate limits |

## 14. Revisit Conditions

Revisit this ADR if any of the following become true:

1. **Dedup window insufficiency:** measured retry-after-window incidence exceeds **0.1 %** of
   ceremony operations, or any platform's observed process-suspension p99 exceeds **12 hours**
   (half the default window). ⇒ re-evaluate the window and N-6's reliance on preconditions.
2. **Precondition-failure loops:** `precondition_failed` exceeds **1 %** of mutating requests in
   steady state, or any single client emits more than **5** consecutive precondition failures for
   one object. ⇒ ALT-A's role may need to expand, or the object is too coarse-grained.
3. **Dedup storage:** dedup-log storage exceeds **10 MB per `TwinNet`**, or its write rate becomes a
   measurable fraction of control-plane write capacity on reference self-hosted hardware. ⇒ narrow
   the ceremony set or shorten the window.
4. **Rollback rejections in the field:** `version_rollback_rejected` fires outside deliberate
   operator restores. ⇒ investigate as a possible attack or as a control-plane replication bug;
   may indicate the monotonicity source needs strengthening.
5. **Local apply rollback rate:** `local_apply_rolled_back` exceeds **0.5 %** of connection attempts
   on any supported platform. ⇒ N-8's transactional model is not achievable on that platform and the
   Platform Network Adapter contract ([docs/architecture.md](../architecture.md) §2.5) must change.
6. **Relay flow leakage:** orphaned relay flows exceed **0.01 %** of opens, indicating the
   `(session_id, relay_id)` idempotency scope is wrong. ⇒ coordinate with [ADR-0005]/[ADR-0006].
7. **Multi-`Owner` support ships** (deferred per [docs/vision.md](../vision.md) §3.5). Introducing a
   second writer for shared state would break **C-2** and require re-deciding whether ALT-E's
   commutative model is now necessary.
8. **A dependency changes:** if [ADR-0007] adopts server-assigned device identifiers instead of
   derived ones (assumption A-01), the "duplicate enroll is naturally the same device" reasoning in
   §11.3 fails and enrollment idempotency must be redesigned. If [ADR-0002] adopts a delta/patch
   push model instead of hint-plus-re-read, §11.2's ordering assumption breaks.
