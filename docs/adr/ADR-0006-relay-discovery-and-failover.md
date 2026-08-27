# ADR-0006: Relay Discovery and Failover

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** NETWORKING
- **Related:** [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md), [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md), [ADR-0004](ADR-0004-nat-traversal-strategy.md), [ADR-0005](ADR-0005-relay-architecture.md), [ADR-0007](ADR-0007-device-identity-and-pairing.md), [ADR-0009](ADR-0009-state-consistency.md), [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md), [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md), [ADR-0015](ADR-0015-observability-and-diagnostics.md), [docs/architecture.md](../architecture.md), [docs/networking.md](../networking.md), [docs/protocol.md](../protocol.md), [docs/reliability.md](../reliability.md), [docs/testing-strategy.md](../testing-strategy.md), [docs/vision.md](../vision.md)

This ADR owns **which `Relay` a device uses and when it stops using it**: how the candidate set
is obtained and cached, the ranking function and the precedence of client measurement over
server ranking, warm-standby policy, failover detection and attribution, multi-region fallback
and its stampede control, total-fleet exhaustion, control-plane-independent failover, and the
policy governing opportunistic upgrade out of `RELAYED`. It does **not** own relay forwarding,
carriages, framing, the capability token, or per-packet overhead
([ADR-0005](ADR-0005-relay-architecture.md)); the `ConnectionState` machine, its transitions, or
any timer *value* ([docs/reliability.md](../reliability.md)) — it contributes guards, events, and
reason codes only; NAT traversal tactics ([ADR-0004](ADR-0004-nat-traversal-strategy.md)); or
consistency classes ([ADR-0009](ADR-0009-state-consistency.md)).

## 1. Context

[ADR-0005](ADR-0005-relay-architecture.md) built a relay that forwards opaque frames, admits
devices offline from a capability token whose `aud` is an **operator group rather than a single
relay**, holds a warm standby for the price of one coalesced keepalive, and refuses to sit behind
a load balancer. It ends with a five-part interface request (§11.2) addressed to this ADR, and it
deliberately leaves every question of *choice* open.

Choice is where the product's two worst relay defects live. R-10 ("unreliable / unavailable
relays") is a failover problem: the session must survive a relay dying, within a bounded time,
without a teardown. R-12 ("excessive relay latency") is a selection problem: the industry default
of a static geographic assignment produces a relay that is near on a map and far on the wire.

The binding constraint on both is [ADR-0009](ADR-0009-state-consistency.md): S-09 (relay registry
and ranking), S-10 (relay `HealthState`), and S-11 (presence) are **`EVENTUAL`**, and RQ-8 of that
ADR states flatly that `EVENTUAL` state MUST NEVER gate a connection attempt. That single rule
disqualifies the natural design — "ask the selection service which relay to use" — and forces
selection to be a **pure local function over cached state**. `docs/architecture.md` §4.4.4 says
the same thing from the other direction: *relay candidate sets are cached, not queried*, and a
cached set of size 1 is a design error.

So the shape of this ADR is fixed before it starts: the server contributes a *ranked, signed,
long-lived document*; the device contributes *measurement*; measurement wins; and nothing in
either input is permitted to stop an attempt from being made.

## 2. Requirements

| # | Requirement | Source |
|---|---|---|
| RQ1 | A device MUST obtain a relay candidate set with **≥2 alternates per `RelayRegion` across ≥2 failure domains**, usable while arbitrarily stale. | architecture A-13, testing-strategy A-18, ADR-0005 §11.2(b), R-11 |
| RQ2 | Selection MUST be a pure function of **locally held state**; no control-plane call may appear on any selection or failover path. | I5, architecture §4.4.2/§4.4.4, A-12 |
| RQ3 | A client's own measurement MUST override a server ranking, and MUST survive process restart. | S-09/S-10 "on conflict", protocol §11.1 consistency row, R-12 |
| RQ4 | S-09/S-10/S-11 MUST be able to **reorder** candidates and MUST NOT be able to **remove** one. | ADR-0009 RQ-8, architecture §5 |
| RQ5 | Relay failover MUST be `RELAYED → MIGRATING → RELAYED`, preserving `session_id`, `Tunnel` key state, counters, and inner addresses. | architecture A-14, testing-strategy A-01, R-05, R-10 |
| RQ6 | Failover MUST distinguish **relay failure**, **path degradation**, **peer loss**, and **local link failure**, because each has a different correct recovery. | R-09, reliability §2 |
| RQ7 | Two peers MUST be able to agree on a new `Relay` with **no server of any kind reachable**. | protocol A12, I5, R-11 |
| RQ8 | Whole-`RelayRegion` failure MUST be survivable without stampeding an adjacent region. | reliability §2.1, operator duty of care |
| RQ9 | Total relay-fleet unavailability MUST produce a **named state and a named code**, never an unexplained spinner, and MUST NOT produce plaintext egress under a kill switch. | I3, I6, R-22, ADR-0012 |
| RQ10 | Direct-path upgrade out of `RELAYED` MUST continue for the life of the `Session`, without oscillating. | R-12, networking §4.4 |
| RQ11 | A self-hosted `Relay` MUST have a defined rank and a defined trust rule. | ADR-0005 §10 RQ13 |
| RQ12 | Every selection and every failover MUST be reconstructable after the fact from a structured event. | P10, R-23, ADR-0015 |
| RQ13 | Relay retry MUST compose with `docs/reliability.md` §6.1–§6.3 without redefining backoff, and MUST NOT let a relay outage exhaust a peer's reconnect budget. | R8, reliability §6.3 |

## 3. Constraints

| # | Constraint |
|---|---|
| C1 | **S-09/S-10/S-11 are `EVENTUAL` and never a gate** ([ADR-0009](ADR-0009-state-consistency.md) RQ-8). This is the hardest constraint in the document and every design choice below bends to it. |
| C2 | `docs/reliability.md` owns the twelve states, the transition table, and **all timer values**. This ADR may propose constants for registration there; it may not define states or transitions. |
| C3 | ADR-0005 §10: a `Relay` is **per-instance addressable**, never a load-balanced VIP. Anycast is permitted for bootstrap/discovery only, never for a bound flow. |
| C4 | ADR-0005 §11.3: one `RelayCapabilityToken` admits an entire **operator group**. Selection may move freely inside a group; moving across groups needs a different token. |
| C5 | Mobile radio wakeups dominate battery (reliability §6.6, ADR-0005 C5). Probing, standby keepalives, and upgrade probes MUST coalesce into the existing wake window or not happen. |
| C6 | ADR-0005 §11.5 rate limits are hard: `max_binds_per_min` default 30 per `relay_sub`, pending slot 30 s, 64 concurrent half-flows. Any policy that binds must fit inside them. |
| C7 | The relay must not be able to steer a `Session` (protocol §11.2, ADR-0005 §7.5). Any relay-supplied input to selection is therefore advisory and must be validated against signed state. |
| C8 | P9 — dual-stack always. Every region must be selectable by a v6-only device and by a v4-only device. |
| C9 | Selection runs on router-class hardware (N10, R-21). It must be O(n) arithmetic over a few hundred entries, not an optimisation problem. |

## 4. Considered Alternatives

| ID | Alternative |
|---|---|
| **A** | **Control-plane-delivered ranked set only.** The relay-selection service publishes a signed, TTL'd, per-device ranked list; the device uses it in order. No client measurement feeds selection. |
| **B** | **Client-side active measurement of a published fleet list.** The server publishes only an unranked inventory; the device probes every relay in it and ranks purely on its own measurements. |
| **C** | **DNS-based discovery.** `_twinvpn-relay._udp.<region>.relays.example` SRV records with priority/weight, plus A/AAAA; the resolver and the SRV algorithm do the selection. |
| **D** | **Anycast to the nearest relay.** One anycast v4 prefix and one v6 prefix; BGP routes the device to the topologically nearest instance. No client-side choice at all. |
| **E** | **Hybrid: a signed, cached `RelayMap` carrying a coarse server-side ranking, refined by bounded client-side measurement that always wins, with selection as a pure local function and a deterministic pair-keyed fallback when no server is reachable.** |

## 5. Advantages of Each Alternative

**A — server-ranked set only.** The server has the one view no client has: fleet-wide load,
capacity headroom, drain schedules, and aggregated health across thousands of vantage points. It
can therefore balance load *globally*, which no independent client decision can do — clients
optimising individually converge on the same "best" relay and overload it. It is trivially cheap
on the client: zero probes, zero battery, zero extra state. It is also the only option in which
an operator can perform a controlled capacity migration by publishing a new document.

**B — client measures everything.** It is the only option whose ranking is *true by
construction*: the number that decides is the number the user will experience, measured on the
user's actual path, at the current moment, with the current carrier's peering. It needs no
trusted ranking authority at all, so it removes an entire steering attack surface and an entire
availability dependency. It is naturally correct during a control-plane outage, because it never
depended on the control plane.

**C — DNS/SRV.** RFC 2782 priority/weight already encodes exactly the fallback-and-load-share
semantics wanted, and every platform ships a resolver. Operators can re-point a region in seconds
with a TTL change and no client release. Records are cached by the resolver hierarchy, so the
lookup load is absorbed by infrastructure nobody has to run. It also composes with anycast DNS
for global availability.

**D — anycast.** Selection latency is zero and selection state is zero: the device sends to one
address and the network picks. It is genuinely optimal for *topological* proximity, which
correlates well with RTT. It requires no map, no ranking, no probing, no refresh, and no failover
logic for instance-level failure — withdrawing a route reroutes traffic automatically. It is the
simplest possible client.

**E — hybrid.** It takes A's global load view and B's ground truth and makes the composition
explicit rather than implicit: the server term is *bounded* so it can bias but never override,
and the client term is unbounded so a genuinely better path always wins. Because the candidate
set is a signed document rather than an answer, selection is a pure local function and therefore
works unchanged at full fidelity during a total control-plane outage — the same code path, not a
degraded one. Bounded probing (top-N plus one exploration slot) buys most of B's accuracy at a
small fraction of its battery and privacy cost. Adding a deterministic pair-keyed hash over the
same document gives two peers a way to converge on one relay with no channel between them at all,
which is what makes protocol A12 true rather than aspirational.

## 6. Disadvantages of Each Alternative

**A — server-ranked set only.** It is wrong exactly when it matters. A ranking computed from
aggregate vantage points cannot see this subscriber's peering, this carrier's transit, or this
café's uplink; R-12 exists *because* products ship this design. It violates RQ3 outright, and
`docs/protocol.md` §11.1's consistency row already forbids it ("Never treat a
coordination-supplied relay ranking as authoritative — that is how a stale central view produces
the excessive relay latency complaint"). During a control-plane outage the ranking freezes at
whatever it was, including a ranking that points at a relay that has since died, and the device
has no mechanism to disagree. It also concentrates a steering capability in one service.

**B — client measures everything.** Probing a whole fleet is a battery and data cost paid
continuously for information about relays that will never be used; on a 200-relay fleet with
dual-stack probing it is 400 probes per cycle. It is also a **privacy leak**: it announces the
device's presence, source address, and probing schedule to *every* relay operator, including ones
it never binds. It has no load signal whatsoever, so every client independently converges on the
lowest-RTT relay and creates precisely the hot spot RQ8 is about. Cold start is worst-case: a
device with no measurements has no ranking at all and must probe before it can choose, which
directly attacks R-02's relay-first latency target.

**C — DNS/SRV.** It makes relay reachability depend on DNS, which `docs/reliability.md` §2.1
explicitly designs *against*: the relay map carries literal A and AAAA addresses precisely so
that "relay reachability never depends on DNS". Captive portals, split-horizon resolvers,
DNS64 synthesis, and enterprise DNS interception all sit on this path, and a hijacked SRV answer
substitutes an attacker-chosen relay set — SRV records are not signed end-to-end in any
deployment we can assume (DNSSEC validation at the stub is not universally available on our
target platforms). Priority/weight is also far too coarse to express health, capacity, failure
domain, carriage support, or drain state, so the map would have to exist anyway. Finally it
carries no signature the device can verify offline, so it cannot satisfy RQ2's cached-state model.

**D — anycast.** It is structurally incompatible with ADR-0005 §10 (C3): a bound half-flow is
pinned to one instance and one 5-tuple, and both peers must reach the *same* instance. Anycast
guarantees neither — the two peers of a pair are, by definition, in different places and will
land on different instances, so the `pair_tag` never matches. Worse, an anycast route change
mid-session silently redirects packets to an instance with no state, producing exactly the
"random disconnect" class this product exists to remove, with no event to observe. It also
provides no failover *policy* (the network's reconvergence is not a `MIGRATING` transition and
does not preserve anything), no health awareness, and no way to prefer a self-hosted relay. It
remains usable for bootstrap only, which is what ADR-0005 §10 already permits.

**E — hybrid.** It is the most machinery: a signed document format, a scoring function with
tunable weights, a measurement cache with its own durability and privacy questions, a probe
budget, and a deterministic-hash fallback path that is exercised only during outages and will
therefore be under-tested unless deliberately fault-injected. Two ranking inputs mean two ways to
be wrong and a composition rule that must be defended (§11.3). The bounded probe set (top-N)
means a relay that is genuinely excellent but ranked poorly by the server may never be measured —
mitigated by the exploration slot, but the mitigation is a heuristic, not a proof.

## 7. Security Implications

**7.1 The candidate set is a closed, signed set.** The `RelayMap` (§11.1) is signed by the
Owner-rooted relay-map issuer (architecture A-04, ADR-0007) and verified offline. A device MUST
NOT bind a relay whose `relay_id` and static Noise public key are not present in a verified map.
This closes the whole class of "point the client at my relay" attacks, and it is what makes the
peer-to-peer map carriage of §11.9 safe.

**7.2 A relay cannot promote itself.** Every input a relay supplies is advisory and locally
validated:

| Relay-supplied input | Use | Validation |
|---|---|---|
| `RELAY_STATUS{reason_code, retry_after_ms, suggested_alternatives[]}` | shed / overload response | `retry_after_ms` honoured; each `suggested_alternatives[]` entry admitted **only if present in the verified `RelayMap`**, otherwise dropped with `RELAY.SELECT.SUGGESTION_UNKNOWN` |
| `DRAIN{drain_deadline_ms, suggested_alternatives[]}` | scheduled departure | same; the deadline is honoured, the destination is chosen by §11.2 |
| observed leg RTT / loss | measurement | measured by the device on its own clock; a relay can only make itself look *worse* |
| `CAPS` | carriage negotiation | ADR-0014 window; unsupported ⇒ `RELAY.VERSION_UNSUPPORTED` (ADR-0005) |

A relay can degrade or evict itself. It cannot raise its own score, cannot name a relay outside
the signed set, and cannot redirect a `Session` — protocol §11.2 already restricts that to the
peers, and this ADR adds no exception.

**7.3 The steering surface that remains, stated honestly.** A compromised relay-selection service
can bias every device toward one relay by publishing a favourable `server_rank`. Its effect is
**bounded by construction**: the server term contributes at most **+100 points**, and one point is
one millisecond of measured RTT (§11.2). Steering therefore succeeds only among relays that are
already within ~100 ms of each other on the device's real path, and it is defeated outright by any
relay with a materially better measured path. The residual: on a dense regional fleet where all
relays are within 100 ms, the server ranking is effectively decisive, and the harm is metadata
concentration — the steered relay learns the pseudonymous pair graph and byte counts of a larger
share of the fleet (ADR-0005 §7.2). An `Owner` can escape it entirely by running a self-hosted
relay (§11.2, RQ11). The alternative that removes it — purely deterministic pair-keyed selection
with no server term — loses fleet load balancing and is recorded as revisit condition V6.

**7.4 Probing is a disclosure.** Measuring a relay announces this device's source address and
liveness to that relay's operator. Alternative B's fleet-wide probing would disclose to *every*
operator continuously. §11.4's bounded probe set (top-5 by score plus one random exploration slot
per cycle) confines the disclosure to relays the device plausibly uses, and the exploration slot's
randomness is drawn per-cycle so it does not form a stable fingerprint. This is a security reason
for the probe budget, not only a battery reason.

**7.5 Peer-couriered maps (§11.9) cannot forge, only withhold.** A `TrustedPeer` may hand over a
`RelayMap`; the receiver verifies the issuer signature and applies it **only if
`map_version` is strictly greater** than the held version. A lower version is refused with
`RELAY.MAP.VERSION_ROLLBACK_REFUSED` — a security event, matching the S-06/S-03 anti-rollback
discipline. A malicious peer can therefore withhold a newer map (indistinguishable from being
behind) but cannot substitute a set. I8 is preserved: the issuer remains the sole writer of S-09;
the peer is a courier of a signed document, exactly the role rendezvous plays for `CALL` blobs
(protocol A9).

**7.6 The pair-keyed hash is not predictable by a relay.** §11.5's rendezvous-hashing key
`pair_id` is derived from the peers' static-static `PairSecret` (ADR-0005 §11.1(3)). A relay
cannot compute which pairs will select it and therefore cannot pre-position for a specific pair.
`pair_id` MUST be domain-separated from `pair_tag`; this is an interface requirement on
ADR-0005/ADR-0001 (§11.15).

**7.7 Measurement history is a movement record.** S-31 (§11.14) keys relay quality by network
fingerprint, which over time is a record of which networks the device has been on. It is
`LOCAL`, never transmitted, LRU-bounded to 64 networks with 30-day decay, and MUST be redacted
from diagnostic bundles per ADR-0015's classification rules.

## 8. Reliability Implications

- **Attribution before action.** §11.4 exists because the three plausible causes of "traffic
  stopped" demand different recoveries, and the wrong one is expensive: failing over the relay
  when the *peer* is gone costs a migration and fixes nothing; treating a dead relay as peer loss
  costs `T_DEAD` (15 s) instead of a hard signal (<200 ms). ADR-0005 gives the discriminator for
  free — the device↔relay **leg** has its own `PING`/`PONG`, independent of the half-flow — so
  "our side of the relay is alive but the peer is silent" is directly observable rather than
  inferred.
- **The failover budget is dominated by detection, not by switching.** With a bound standby the
  switch is one validation RTT; the honest end-to-end number is therefore set by which detection
  signal fires (§11.4 table). This is why §11.6 holds a standby at all: it converts the expensive
  half of failover into a pre-paid constant.
- **A standby in the same failure domain is worthless**, and reliability §2.1 names this as the
  residual risk of the relay-failure row. §11.6 makes different-`failure_domain` a hard condition
  of `RELAY_STANDBY_READY` (ADR-0005 §11.6 already requires it — confirmed) and emits
  `RELAY.STANDBY.NO_DOMAIN_DIVERSITY` when the map cannot supply one, *before* the failure.
- **A parked mobile device has no standby.** reliability §6.6 stops all keepalives when the app is
  backgrounded and parked. A standby whose keepalive is not running is not warm. §11.6 therefore
  *releases* the standby on park and re-establishes it on wake before traffic resumes, rather than
  pretending a parked standby is warm. Wake-to-traffic remains reliability §11's problem.
- **Region failure is a capacity event, not only a connectivity event.** Recovery that works for
  one device fails for a hundred thousand simultaneously. §11.7 separates devices with
  pre-provisioned capacity (a bound standby — they move immediately, because their capacity was
  accounted at bind time) from devices requesting *new* capacity (they spread over
  `T_REGION_SPREAD`). This distinction is the whole of the stampede answer.
- **`DEGRADED` is not available for fleet exhaustion.** reliability §4.4 defines `DEGRADED` as a
  state in which *traffic continues to flow*. When nothing flows, `DEGRADED` is a lie; §11.8 uses
  `BLOCKED` or `RECONNECTING → FAILED` per enforcement mode instead.

## 9. Performance Implications

**9.1 `RelayMap` size and delivery.** Per-relay entry ≈ 120 B CBOR (`relay_id` 8, `operator_group_id`
4, static key 32, 2×2 endpoint literals ≈ 40, region 4, `failure_domain` 4, carriages 1,
`server_rank` 2, `load_class` 1, `capacity_weight` 2, `admin_state` 1, flags 2, padding). A
200-relay fleet is ≈ 24 KiB plus per-region adjacency and one COSE signature. That exceeds
[ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) §11.4's 16 KiB inline threshold, so
the map is delivered as `StateDocumentAvailable{doc_type: "relay_map", version, size, digest}` on
C2 with a C1 `GetStateDocument` pull — and, per that section, pull alone is sufficient. Refresh is
**not** on the failover path (RQ2): the map is fetched in the background, and a fetch failure is
`RELAY.MAP.STALE`, never a connection error.

**9.2 Probe cost.** Top-5 by score plus one exploration slot, both families where available, one
4-byte `PING`/`PONG` pair per relay per cycle at the coalesced keepalive cadence (60 s default,
reliability §6.6): ≈ 12 exchanges/minute ≈ 1.4 KB/min ≈ 2 MB/day worst case, and **zero additional
radio wakes** because it rides the existing wake window (C5). In mobile background the probe set
reduces to the bound relay plus the standby only. Compare alternative B on a 200-relay fleet:
≈ 400 exchanges/cycle, ~80× the data and a new wake obligation.

**9.3 Selection cost.** Scoring is one pass of fixed-point arithmetic per map entry plus a partial
sort for the top-k: O(n) with a small constant on ≤ a few hundred entries, microseconds on
router-class hardware (C9). Rendezvous hashing (§11.5) is one BLAKE2s per candidate.

**9.4 Failover time budget** (onset → first user byte on the new relay):

| Path | Detection | Switch | Total (target p95) |
|---|---|---|---|
| Hard signal (TCP RST / QUIC `CONNECTION_CLOSE` / ICMP / socket error), standby bound | < 200 ms | 1 validation RTT + commit ≈ 100–300 ms | **≤ 700 ms** |
| `DRAIN` received, standby bound | scheduled inside `[0, deadline − 60 s]` | as above | user-invisible |
| Leg `PING`/`PONG` miss ×3 @ 3 s foreground, standby bound | ≈ 6–9 s | as above | ≤ 9.5 s |
| Hard signal, **no** standby (leg up, not bound) | < 200 ms | +1 `BIND` RTT | ≤ 1.1 s |
| Hard signal, no leg (cold relay) | < 200 ms | leg handshake + `BIND` + validation | ≤ 2.0 s |
| Region failure, no standby | 15–30 s (correlated detector, reliability §2.1) | + `uniform(0, T_REGION_SPREAD)` | ≤ 55 s |

`T_FAILOVER_TARGET` = 300 ms (reliability §5.3) is the **decision → first byte** budget and is met
by the first three rows. R-10 requires "within a bounded time without dropping the `Session`"; the
bound is stated per detection class above rather than as a single number, because a single number
would hide the fact that the timer-backstop path is an order of magnitude slower than the
hard-signal path. ADR-0005 V5 falsifies the design at p95 > 1.5 s with a warm standby; the row
above budgets 700 ms, leaving real margin.

**9.5 Cross-region cost.** A cross-region relay typically adds 30–120 ms RTT. reliability §5.4
enters `DEGRADED` at > 250 ms absolute on a relay path, so a cross-region failover from an
already-marginal region can land in `DEGRADED` — a working-but-worse path, announced with
`RELAY.FAILOVER.CROSS_REGION` at the moment of the move and reliability's `QOS_*` code if the
threshold is then crossed. It is never reported as a full recovery.

## 10. Operational Implications

- **Map publication invariants.** The relay-selection service MUST refuse to publish a map in
  which any `RelayRegion` with live sessions falls below **2 `ACTIVE` relays in ≥2 distinct
  `failure_domain`s** (RQ1, A-13). Retiring a relay is therefore a two-step operation: publish
  `admin_state: DRAINING` (which lowers its score and stops new binds but keeps it usable), wait
  for the drain deadline, then publish `RETIRED` in a map that still satisfies the floor.
- **Drain is the relay's, scheduling is the client's.** ADR-0005 §8 sets the 120 s default deadline
  and requires the relay to honour it; §11.7 here fixes where in `[0, deadline − 60 s]` a device
  moves (uniform, per reliability T37) and where it moves *to*.
- **Capacity weighting.** `capacity_weight` in the map feeds the rendezvous hash (§11.5), so
  redistribution after a failure is proportional to published capacity with no coordination. An
  operator changes fleet balance by publishing weights, not by touching clients.
- **Issuer key rotation.** Devices hold an issuer public-key *set*; a map signed by any key in the
  set verifies. Rotation publishes a map signed by the outgoing key that carries the incoming key,
  then switches. A map that verifies against no held key is `RELAY.MAP.SIGNATURE_INVALID` and the
  **previously held map remains in force** — a bad publish must not disarm the fleet.
- **The map contains no device data**, only fleet inventory. It is therefore identical for every
  device in an operator group, cacheable at the edge, and servable from a CDN — which is itself an
  availability property, since map distribution then does not share a failure domain with the
  control-plane database.
- **Self-hosted relays** register into the `Owner`'s map with `self_hosted: true` and a
  `failure_domain` the `Owner` declares. ADR-0005 §10 already sets their trust level (untrusted,
  identical to hosted) and requires `DRAIN`/`CAPS`; §11.2 sets their rank.
- **Diagnostics.** Every selection emits a structured `RelaySelected` event carrying the full input
  vector (§11.16). Support can answer "why this relay" from the event stream without a debug
  build, which is R-23's actual requirement.

## 11. Decision

**Adopt Alternative E.** A signed, long-lived, stale-but-usable `RelayMap` carrying a **bounded**
server ranking; a device-local score in which **measurement is unbounded and therefore always
wins**; selection as a pure local function that reorders but never removes; a warm standby in a
different failure domain held under stated conditions; failover as make-before-break
`RELAYED → MIGRATING → RELAYED` driven peer-to-peer; and a deterministic pair-keyed rendezvous
hash over the same map for the case where no server and no session exist. **A is rejected on RQ3,
B on cost and privacy and cold start, C on the DNS dependency reliability.md designs against, D on
ADR-0005 §10's per-instance pinning.** D is retained for bootstrap only.

### 11.1 The `RelayMap` — satisfying ADR-0005 §11.2(a)

One signed COSE_Sign1/CBOR document per operator group, `doc_type: "relay_map"`.

| Field | Meaning |
|---|---|
| `map_version` | strictly monotone `uint64`; a lower version MUST be refused (§7.5) |
| `issued_at_ms`, `not_after_ms` | soft freshness only; **expiry has no enforcement effect** (ADR-0009 §11.4) |
| `operator_group_id` | matches the `aud` of the `RelayCapabilityToken` (ADR-0005 §11.3) |
| `regions[]` | `{region_id, geo_hint, adjacent_regions[]{region_id, added_rtt_ms_p50, order}}` |
| `relays[]` | per `Relay`: `relay_id`, `operator_group_id`, `static_noise_pub`, **literal** `endpoints_v4[]`, **literal** `endpoints_v6[]`, `carriages[]` ⊂ {`R-UDP`,`R-QUIC`,`R-TLS`}, `region_id`, **`failure_domain`**, `server_rank` (0–100), `load_class` (0–3), `capacity_weight`, `admin_state` ∈ {`ACTIVE`,`DRAINING`,`RETIRED`}, `self_hosted`, `supports_drain`, `supports_caps` |
| `signature` | issuer Ed25519 over the canonical encoding (ADR-0003) |

Normative rules:

1. Endpoints are **literals**, never hostnames. Relay reachability MUST NOT depend on DNS
   (reliability §2.1). NAT64 synthesis of v4 literals uses the locally learned prefix
   (networking §3.8), never DNS64.
2. Every `RelayRegion` MUST publish relays reachable over **both** families (C8, P9).
3. A map MUST NOT be applied if doing so drops a region **with live sessions** below 2 `ACTIVE`
   relays in ≥2 `failure_domain`s. The device retains the prior map's entries for the deficient
   region and emits `RELAY.SELECT.ALTERNATES_INSUFFICIENT`. This makes A-13's floor self-healing
   at the edge as well as enforced at publication (§10).
4. The map is **stale-but-usable without limit**. Past `not_after_ms` the device continues to use
   it unchanged and emits ADR-0009's `CONTROL.STALENESS.RELAY_SET_EXPIRED`. No expiry, at any age,
   may reduce the candidate set or block an attempt.

### 11.2 The selection score (normative)

`score(r)` is computed locally, in fixed point, base **1000**. One point ≡ one millisecond of RTT.

| Term | Contribution | Bound |
|---|---|---|
| Measured RTT | −1 × EWMA RTT ms (α = 1/8, networking §4.2) | −250 |
| Measured loss | −8 × loss % over the 30 s window | −120 |
| Measured jitter | −0.5 × EWMA jitter ms | −40 |
| **Server rank** | **+`server_rank` × `freshness`**, `freshness` = 1.0 at age ≤ 1 h, decaying linearly to 0.0 at 24 h | **+100 max** |
| `HealthState` (S-10) | `HEALTHY` 0 · `DEGRADED` −40 · `UNHEALTHY` −150 · `UNKNOWN` 0 | −150 |
| `load_class` | 0 → 0, 1 → −20, 2 → −60, 3 → −120 | −120 |
| Region locality | same region 0 · adjacent −(`added_rtt_ms_p50`) · other −200, **replaced by measurement once measured** | −200 |
| Historical bind success (S-31) | +60 × EWMA success rate for this `relay_id` **on this network fingerprint** | +60 |
| Self-hosted | +120 if `self_hosted` ∧ `supports_drain` ∧ `supports_caps`; +0 otherwise | +120 |
| `admin_state = DRAINING` | −300 | −300 |
| Circuit breaker open (reliability §6.3) | −400 | −400 |

**The composition rule that discharges RQ3 and the S-09/S-10 "on conflict" column:** the server's
total contribution is capped at **+100** while the measurement terms are worth up to −410.
Therefore **any relay with a ≥100 ms measured RTT advantage outranks any server preference,
unconditionally**, and a relay the device has actually failed to bind outranks nothing. A stale
server ranking decays to zero influence over 24 h without ever removing a candidate. This is the
arithmetic form of "the client's own measurement overrides a stale ranking".

**Self-hosted preference (RQ11).** +120 points ≈ 120 ms of tolerated extra RTT: an `Owner`'s own
relay wins whenever it is not dramatically worse, which is the intent (metadata locality and
jurisdictional control, ADR-0005 §10), and loses when it genuinely is dramatically worse, which is
also the intent. **Trust is unchanged**: a self-hosted relay is untrusted (B3), I1 applies
identically, and it is admitted only because it is in the `Owner`-signed map. A self-hosted relay
lacking `DRAIN`/`CAPS` gets **no** bonus (ADR-0005 §10 says SHOULD rank below hosted — satisfied by
the absent bonus plus the operational reality that it cannot signal drain). A map whose only
relay is self-hosted emits ADR-0005's `RELAY.SELF_HOSTED_NO_ALTERNATE`.

### 11.3 Selection is a reordering, never a filter (normative)

1. **A `HealthState` of `UNHEALTHY` (S-10), a "peer offline" presence record (S-11), or any age of
   relay set (S-09) MUST NOT suppress a connection attempt.** They contribute score deltas only.
   Selection returns a **total order over the whole candidate set**, never a filtered subset.
2. The **only** permitted reductions of the candidate set, all of them local or structural facts
   rather than `EVENTUAL` state:
   - `admin_state = RETIRED` in a verified map (the relay no longer exists as a signed entity);
   - no endpoint in any address family the device can reach, and no NAT64 synthesis available
     (`RELAY.SELECT.NO_CANDIDATE_FOR_FAMILY`);
   - no `carriages[]` entry the device supports (`RELAY.SELECT.NO_CARRIAGE_SUPPORTED`);
   - `operator_group_id` not matching the held token's `aud` (C4 — the device cannot be admitted).
3. **Circuit-breaker reconciliation.** reliability §6.3 says an open breaker causes a target to be
   "skipped entirely by selection". That is consistent with rule 1 and is **confirmed**, because a
   breaker opens only on the device's **own** direct evidence (5 consecutive failures or budget
   exhaustion), never on reported state. Two clarifications are added: a **first** attempt on a
   relay is never suppressed (reliability §6.3 already charges it no token), and **if every
   candidate's breaker is open, selection MUST return the highest-scoring candidate as the
   half-open probe rather than returning empty**, emitting `RELAY.SELECT.ALL_BREAKERS_OPEN`. An
   empty candidate set is never a legal output of selection while the map is non-empty.
4. Selection runs at: `Session` start (t=0, concurrently with direct probing — ADR-0005 §11.4,
   architecture A-10), standby choice, failover, region failure, map application, and every probe
   cycle for standby re-evaluation. It never runs on the packet path.

### 11.4 Failure attribution and the detection budget (RQ6)

The discriminator is that ADR-0005 gives the device↔relay **leg** its own `PING`/`PONG`,
independent of any half-flow. "Is the relay reachable" and "is the peer talking" are therefore two
separate observations, not one.

| Observation | Attribution | Recovery |
|---|---|---|
| Leg dead: 3 missed leg `PING`/`PONG`, or TCP RST / QUIC `CONNECTION_CLOSE` / socket error / ICMP unreachable; **or** `DRAIN` deadline reached | **Relay failure** | `RELAY_FLOW_FAILING` → §11.5 failover |
| Leg **alive** (`PONG` returning), half-flow silent in both directions | **Peer loss, or the peer's own relay leg failed** | reliability §6.4 dead-peer detection. **Do not fail over the relay** — a working relay is not the problem, and moving costs a migration that cannot help |
| Leg alive, peer traffic flowing, quality over reliability §5.4 thresholds | **Path degradation** | T22 → `DEGRADED`; alternate-relay search; migrate only if an alternate satisfies networking §4.3 `PATH_BETTER` (≥15 points ∧ ≥10 ms) |
| All legs on this interface dead simultaneously, or `EV_LINK_DOWN` | **Local link failure** | Not a relay event. reliability T19/T20 on the interface, not on the relay |
| ≥3 relays in one `RelayRegion` fail within 30 s, or the region's anycast bootstrap is silent on both families (reliability §2.1) | **Region failure** | §11.7 |
| `RELAY_STATUS` carrying `RELAY.OVERLOADED` / `RELAY.FLOW_LIMIT_REACHED` / `RELAY.QUOTA_EXCEEDED` | **Capacity, not fault** | honour `retry_after_ms`; move to a §11.2-selected alternate; `RELAY.CAPACITY_REJECTED` |

Detection latency budget: hard signals < 200 ms; `DRAIN`/`RELAY_STATUS` immediate; leg timer
backstop 3 missed at the coalesced cadence (≈ 6–9 s foreground, ≈ 30 s idle); region detector
15–30 s. These are consumed from reliability §5.2 and §2.1, not redefined here.

### 11.5 Failover mechanism (RQ5, RQ7) — no control plane anywhere

**Live `Session`, standby bound** (the designed path):

```
RELAYED via R1                 ── leg PING/PONG × 3 missed, or RST/CLOSE
   │                              (attribution: relay failure, §11.4)
   ├─ emit EV_RELAY_GONE  ────▶ reliability T19  ⇒  MIGRATING{RELAY→RELAY'}
   │                              Session, Tunnel keys, counters, inner addrs untouched
   ├─ PathOffer{session_nonce, new_path=flow_id@R2, path_epoch+1}
   │     sent INSIDE the encrypted Session, carried OVER THE STANDBY FLOW at R2
   ├─ PathAck{path_epoch, accepted}                        (protocol §11.2)
   ├─ authenticated path validation: ≥2 PING/PONG within 500 ms (networking §4.3)
   ├─ EV_PATH_VALIDATED ─────▶ reliability T15  ⇒  RELAYED via R2
   └─ emit RELAY.FAILOVER.COMPLETED{from, to, region, rtt_delta_ms, onset_to_traffic_ms}
```

Normative:

1. **Where a validated or warm alternate exists**, the transition is exactly
   `RELAYED → MIGRATING → RELAYED`. It MUST NOT pass through `DISCONNECTED` or `RECONNECTING`,
   MUST NOT change `session_id`, and MUST NOT destroy `Tunnel` key state, counters, replay window,
   or inner addresses (ADR-0001 C3, ADR-0005 C3). This covers rows 1–4 of §9.4 — bound standby,
   `DRAIN`, leg-miss, and leg-up-not-bound — because in each the alternate is already validated or
   warm, which is exactly `docs/reliability.md` T19's guard.

   **The cold-relay case is different, and is stated rather than glossed.** §9.4's row 5 (hard
   signal, *no leg* — a relay never probed and never connected) does **not** satisfy T19's guard,
   so `docs/reliability.md` T20 applies and the `Session` passes through **`RECONNECTING`**. That
   is a legal transition and a truthful one: for the ~2 s of leg handshake + `BIND` + validation
   there is genuinely no carrying path, and reporting `MIGRATING` would assert a make-before-break
   that is not happening. Consequently:
   - The A-01 / architecture.md A-14 guarantee ("relay failover never passes through
     `RECONNECTING`") holds for rows 1–4 and **not** for row 5. `docs/testing-strategy.md` P03
     scopes its oracle to the standby and leg-only classes accordingly.
   - `session_id` and `Tunnel` key state survive row 5 regardless — `RECONNECTING` does not
     destroy them (`docs/reliability.md` §4.4, S-13 loss occurs only on rekey failure), so the
     user-visible cost is a ~2 s stall, not a re-handshake or a new `Session`.
   - The design response is to make row 5 rare rather than to relabel it: §11.6's warm-standby
     policy exists precisely so that a cold relay is not the failover target in the common case.
2. Make-before-break: the old flow is released only after the new one commits, whenever the old
   one is still alive. When it is already gone, reliability's `T_MIGRATE_QUEUE` bounded queue
   applies unchanged.
3. The `PathOffer` travels over the **standby flow**, not the dead one. This is the reason a
   standby is worth its cost twice over: it is both the destination and the signalling channel.
4. **Simultaneous offers.** Both peers may detect and offer. `path_epoch` is monotone (protocol
   §11.2); on an *equal* epoch the offer from the device with the lexicographically **lower
   `device_id`** wins and the other is ignored with `RELAY.FAILOVER.EPOCH_CONFLICT`. Both peers can
   evaluate this rule with no coordination, because `device_id` is self-certifying (architecture
   A-01).
5. If no `PathAck` arrives within reliability's `T_MIGRATE` (3 s), reliability T16/T17 govern:
   back to `from` if the old path lives, else `RECONNECTING`. Emit
   `RELAY.FAILOVER.OFFER_UNACKED`.
6. Zero control-plane messages appear anywhere in this sequence.

**No live `Session` (both sides cold, control plane down)** — the case that has no offer/ack
channel. Both peers converge **deterministically** by rendezvous hashing (HRW) over the cached map:

```
pair_id  = HKDF-Expand(RelayPairKey, "twinvpn/relay-pairid/v1", 16)   # ADR-0005 §11.1(3)
w(r)     = BLAKE2s(relay_id ‖ pair_id) interpreted as uint64, scaled by capacity_weight(r)
candidates = the k = 3 highest-w relays among ACTIVE entries admissible under §11.3 rule 2
```

Both devices `BIND` all `k = 3` in parallel (ADR-0005 makes the marginal cost one `BIND` frame on
an existing leg). Convergence fails only if the two maps disagree in the pair's top 3, and the
failure is **self-announcing**: ADR-0005's pending slot expires in 30 s with
`RELAY.PAIR_UNMATCHED`, after which the device advances to HRW ranks 4–6 under the infrastructure
backoff regime (reliability §6.1). HRW is chosen over "lowest `relay_id`" because it spreads pairs
across the fleet proportionally to `capacity_weight` with no coordination — the same property
§11.7 needs for region redistribution, and the property reliability §2.1 already assumes when it
says "select by rendezvous hash over the surviving relay set" (**confirmed**; this ADR supplies
the key and the weight).

**Relay-assisted rendezvous (ADR-0005 §11.2(e), ADR-0002 §11.9(a)).** A signed, sealed `CALL`
blob is carried as the first `DATA` payload on a half-flow bound by `pair_tag` at the HRW relay.
The relay learns nothing beyond ADR-0005 §7.2. To be *callable* with its control channel down, a
device re-`BIND`s a pending slot at its top-`k_rdv` = 2 HRW relays per `TrustedPeer` at ≤ 30 s
intervals (the pending-slot lifetime). Against ADR-0005's default `max_binds_per_min` = 30 per
`relay_sub`, this listening posture scales to **≈ 15 peers per relay**; beyond that the token's
quota must be raised for gateway-class devices (interface requirement, §11.15).

### 11.6 Warm standby policy — WHEN and WHICH (ADR-0005 §11.2(c))

ADR-0005 owns the mechanism and the cost (≈ 86 KB/day, zero extra radio wakes, because the leg is
shared per relay and keepalives coalesce). This ADR owns the conditions.

| Condition | Standby posture |
|---|---|
| `RELAYED` sustained ≥ `T_STANDBY_WARM` (30 s, reliability §5.3 — **confirmed**) | **BOUND** on a second relay |
| Device is a `LANGateway`, `ExitNode`, or user-marked "always reachable" | **BOUND immediately**, no dwell (reliability §6.6's exception class) |
| `RELAYED` for < `T_STANDBY_WARM` | none — brief relay use should not pay for a second relay |
| `WAN_DIRECT`, mains power or unmetered | **LEG-ONLY** (leg established, no `BIND`) — satisfies reliability §4.4's `WAN_DIRECT` invariant ("alternate warm or re-establishable within `T_FAILOVER_TARGET`") at one `BIND` RTT (§9.4 row 4) |
| `WAN_DIRECT`, gateway/exit-node role | **BOUND** |
| Mobile, backgrounded and **parked** (reliability §6.6) | **released**; re-established on wake before traffic resumes. A standby whose keepalive is stopped is not warm and MUST NOT be reported as one |
| Metered link, or battery < 20 % | **LEG-ONLY**; emit `RELAY.STANDBY.SUPPRESSED_METERED` / `RELAY.STANDBY.SUPPRESSED_POWER` (informational, so the weaker failover posture is visible *before* the failure) |
| Fewer than 2 admissible relays | none; emit ADR-0005's `RELAY.STANDBY_UNAVAILABLE` |

**Which relay.** The highest-scoring candidate whose `failure_domain` differs from the primary's
(ADR-0005 §11.6 `RELAY_STANDBY_READY` requires exactly this — **confirmed**). Region preference:

1. Same `RelayRegion` as the primary, if it can supply a different failure domain — preserves the
   latency budget on cutover.
2. Otherwise the highest-scoring relay in the first `adjacent_regions[]` entry, emitting
   `RELAY.STANDBY.CROSS_REGION` so the added RTT at failover is announced in advance.
3. If no different failure domain exists anywhere, take the best same-domain relay and emit
   `RELAY.STANDBY.NO_DOMAIN_DIVERSITY` (POLICY class — this is a stated availability deficiency,
   not a silent one).

**Cost/benefit, stated.** Cost: ≈ 86 KB/day and zero additional wakes while the process is
scheduled. Benefit: failover drops from ≈ 1.1 s (bind on demand) or ≈ 2.0 s (cold) to ≤ 700 ms
(§9.4). The honest caveat is the parked-mobile row above: the cost model depends entirely on
coalescing, and coalescing depends on having scheduler time.

### 11.7 Multi-region failover and stampede control (RQ8)

Detection is reliability §2.1's correlated-failure detector (**consumed, not redefined**).

**Ordering.** Fall back along `regions[].adjacent_regions[]`, ordered by published
`added_rtt_ms_p50` — and **re-rank by measurement as soon as one measurement exists** (§11.2's
locality term is explicitly "replaced by measurement once measured"). The published order is a
starting point, never a decision.

**Three independent stampede controls, because one is insufficient:**

1. **Deterministic proportional spreading.** Redistribution uses the §11.5 HRW function over the
   *surviving* set, weighted by `capacity_weight`. Every pair independently maps to a different
   survivor, proportionally to capacity, with no coordination and no hot spot. Independent
   score-optimising choice — every device picking "the best surviving relay" — is precisely what
   creates the hot spot, and is why HRW rather than score decides *redistribution* while score
   decides *ordinary selection*.
2. **Split jittered start.** Devices holding a **bound** standby move **immediately**: their
   capacity was accounted at bind time, so their move requests nothing new. Devices needing
   **new** capacity draw their move time from `uniform(0, T_REGION_SPREAD)` (proposed 20 s) and
   emit `RELAY.REGION.SHED_DEFERRED`. Delaying a device that already has a destination serves
   nobody; delaying a device that must acquire one is the entire mitigation.
3. **Destination-side shedding with a usable answer.** A relay at capacity replies per ADR-0005
   §11.5 with `RELAY_STATUS{retry_after_ms, suggested_alternatives[]}`. The device MUST honour
   `retry_after_ms`, MUST try a suggested alternative before retrying the same relay, and MUST
   ignore any suggestion absent from the verified map (§7.2). Retries use the **infrastructure**
   decorrelated-jitter regime (reliability §6.1), never the interactive one.

**Global brake.** reliability §6.3's rule is confirmed unchanged: with breakers open on more than
half the reachable relay set, relay retries stop for 60 s and the condition is reported — canonical
code `RELAY.FLEET.UNREACHABLE` (§11.13).

**Honest cost.** Cross-region adds 30–120 ms and may cross reliability §5.4's 250 ms relay
threshold into `DEGRADED`. Recovery is working-but-worse and is announced as such.

### 11.8 Total relay-fleet unavailability (RQ9) — reconciling R-11 honestly

**Definition.** No relay in the verified map reaches `RELAY_FLOW_BOUND` across all supported
carriages and both families, after the retry budget for the `region:` class is exhausted. Guard:
`RELAY_FLEET_EXHAUSTED`.

| Situation | Resulting state | Owner of the state decision |
|---|---|---|
| A direct `Path` (`LOCAL_DIRECT` / `WAN_DIRECT`) is carrying traffic | **no state change**; standby absent ⇒ `RELAY.STANDBY_UNAVAILABLE` (informational) | — |
| No path at all, enforcement `FAIL_CLOSED` | **`BLOCKED`** (reliability T26; I3; ADR-0012). Not `FAILED`: `BLOCKED` retries forever at the floor rate, which is right, because the fleet will return | [docs/reliability.md](../reliability.md) §4 |
| No path at all, enforcement `PERMISSIVE_ANNOUNCED` | **`RECONNECTING`** until `T_RECONNECT_MAX`, then **`FAILED`** with `RELAY.FLEET.UNREACHABLE` | [docs/reliability.md](../reliability.md) §4 |

**`DEGRADED` MUST NOT be used** for this condition: reliability §4.4 defines `DEGRADED` as traffic
continuing to flow, and here nothing flows. This ADR contributes the guard and the codes only;
**state ownership is deferred to `docs/reliability.md` §4**, whose transition table already
supplies T20/T26/T27.

**R-11 reconciled.** R-11 forbids any *single* component's unavailability from preventing a paired
pair from communicating. That is **confirmed and satisfied**: no single relay (≥2 alternates per
region), no single failure domain (≥2 per region), no single region (adjacency fallback), no
single control plane (§11.9), and no single operator (self-hosted relays sit outside the operator's
failure domain entirely). What this ADR explicitly does **not** claim is that a pair can
communicate when *every* direct path and *every* relay is simultaneously unavailable — that is two
independent failure classes coinciding, and it is a network partition, not a component failure. The
honest response is a named state, a named code, a count of what was tried, and a suggested next
action:

> *Not connected to `laptop`: no direct path (symmetric NAT at both ends) and no relay reachable
> (12 of 12 tried, all carriages). This network may be blocking UDP and TCP/443. Traffic is
> blocked because the kill switch is on.*

### 11.9 Control-plane-independent failover — protocol.md A12 **CONFIRMED**

Four things are needed to move a session to a new relay, and none of them touches a server:

| Need | Source | Server contact |
|---|---|---|
| Candidate set | cached signed `RelayMap`, stale-but-usable at any age (S-09, ADR-0009 §11.4) | none |
| Admission | ADR-0005 `RelayCapabilityToken`, `aud` = operator group, verified offline by the relay | **none** — the relay renews the token itself under epoch equality (ADR-0005 §11.3), so admission survives a control-plane partition of any duration |
| Rendezvous inside the new relay | `pair_tag` from the static-static `PairSecret` (ADR-0005 §11.1(3)) | none |
| Agreement between peers | `PathOffer`/`PathAck` in-`Session` (live), or HRW over `pair_id` (cold) — §11.5 | none |

**Keeping maps convergent during a long outage: peer-to-peer map carriage.** Peers include
`relay_map_version` (8 B) in the in-`Session` keepalive. A peer holding a strictly higher version
MAY offer the signed document over the existing encrypted `Session`; the receiver verifies the
issuer signature, refuses any non-increasing version (`RELAY.MAP.VERSION_ROLLBACK_REFUSED`), and
applies it under §11.1 rule 3, emitting `RELAY.MAP.PEER_SUPPLIED_ACCEPTED`. **This creates no
second writer** (I8): the relay-selection service remains the sole writer of S-09 and the sole
publisher of the document (protocol §7); the peer is a courier of signed bytes, the same role
rendezvous plays for `CALL` blobs. Gated by a new `Capability` (§11.15) so a mixed-version
`TwinNet` degrades explicitly (ADR-0014).

### 11.10 Opportunistic upgrade `RELAYED → WAN_DIRECT` — policy (RQ10)

`docs/networking.md` §4.4 owns the **mechanism** (decaying probe cadence 1, 2, 4 … 60 s, reset on
network change, make-before-break migration, session/keys/addresses unchanged) — **confirmed and
not redefined**. `docs/reliability.md` owns the **timer values**. This ADR owns the **policy**:

1. **Cadence budget.** networking §4.4's schedule stands in foreground and on mains power. In
   mobile background the cadence floor is `T_UPGRADE_PROBE_BG` (proposed 300 s) and probes MUST
   align to the coalesced wake window (C5).
2. **Timer-driven → event-driven, never stopped.** After `N_UPGRADE_GIVEUP` (proposed 20)
   consecutive failed upgrade attempts **on the same network fingerprint**, *and* ADR-0004 has
   classified both ends as symmetric or CGNAT with no port mapping, timer-driven probing suspends
   and probing becomes **event-driven**: any network-change event, interface change, RA, wake, NAT
   behaviour change, or `Capability` change restarts the ladder at 1 s. Emit
   `RELAY.UPGRADE.PROBING_SUSPENDED`. R-12's "continue attempting direct-path upgrade for the life
   of a `RELAYED` session" is **confirmed, not overruled** — probing never stops permanently; only
   the pointless 60 s timer on a provably-impossible pair does.
3. **Upgrade guard.** Requires networking §4.3's `PATH_VALIDATED` ∧ `PATH_BETTER` (≥15 points ∧
   ≥10 ms) ∧ `PATH_STABLE` (held ≥3 probe intervals) — **consumed unchanged**. Guard name
   contributed: `DIRECT_UPGRADE_ELIGIBLE`.
4. **Anti-flap dwell (asymmetric, deliberately).** After a `RELAYED → WAN_DIRECT` migration, the
   reverse migration MUST NOT be initiated by **quality** alone for `T_UPGRADE_DWELL` (proposed
   120 s). **A hard failure signal is never suppressed** — `PATH_FAILING`, `EV_LINK_DOWN`, or a
   socket error demotes to relay immediately. Anti-flap must never trap a session on a dead path.
5. **Flap suppression.** If a pair oscillates `RELAYED ↔ WAN_DIRECT` ≥ `N_UPGRADE_FLAP`
   (proposed 3) times within `T_UPGRADE_FLAP_WINDOW` (proposed 10 min), the direct candidate for
   that pair is suppressed for `T_UPGRADE_FLAP_SUPPRESS` (proposed 30 min) **on that network
   fingerprint only**, with `RELAY.UPGRADE.FLAPPING_SUPPRESSED`. A network change clears it.
6. All five constants are **proposed to `docs/reliability.md` §5.3 for registration**; this ADR
   does not own timer values (C2).

### 11.11 Retry budgets — composed, not redefined (RQ13)

`docs/reliability.md` §6.1 (backoff regimes) and §6.3 (token buckets, breakers, global brake) are
consumed unchanged. This ADR adds only composition rules:

| Rule | Specification |
|---|---|
| Bucket assignment | A bind attempt costs one token from `relay:<relay_id>`; a region-wide failover additionally costs one from `region:<RelayRegion>`; a map fetch costs from `control-plane` |
| **Isolation** | A relay bind failure MUST NOT consume the `peer:<DeviceId>` budget. A relay outage must never make a reachable peer look failed |
| First attempt | A first attempt on a newly selected relay costs no token (reliability §6.3), which is what guarantees the fleet stays explorable |
| Regime | Relay bind, standby bind, and map fetch use **infrastructure** decorrelated jitter (base 500 ms, cap 30 s). In-`Session` `PathOffer`/`PathAck` and path validation use **interactive** equal jitter (base 250 ms, cap 15 s) |
| Breaker | Per §11.3 rule 3 |

### 11.12 Guards and events contributed to `docs/reliability.md` (no new states, no new transitions)

| Guard | Value |
|---|---|
| `RELAY_SET_NONEMPTY` | ≥1 admissible entry under §11.3 rule 2 in the verified map |
| `RELAY_STANDBY_SELECTED` | a different-`failure_domain` candidate is chosen per §11.6 (selected, not necessarily bound) |
| `RELAY_FAILOVER_TARGET_READY` | ADR-0005's `RELAY_STANDBY_READY`, or a leg-only standby reachable within `T_FAILOVER_TARGET` |
| `RELAY_REGION_FAILED` | reliability §2.1's correlated-failure detector has fired for this `RelayRegion` |
| `RELAY_FLEET_EXHAUSTED` | §11.8's definition |
| `DIRECT_UPGRADE_ELIGIBLE` | §11.10 rule 3 |
| `UPGRADE_FLAP_SUPPRESSED` | §11.10 rule 5 in force for this pair and network |

**Events.** reliability §4.3 already sources `EV_RELAY_DRAINING{deadline}` and `EV_RELAY_GONE`
from this ADR — **confirmed; this ADR is their publisher.** Region failure introduces **no new
event**: it is expressed as `EV_RELAY_GONE` per affected `Session` plus the `RELAY_REGION_FAILED`
guard, which changes only the selected target, not the transition. Transitions used, all
pre-existing: **T19** (path dead, alternate exists → `MIGRATING`), **T37** (drain, herd-safe),
**T13/T15/T16/T17** (upgrade and migration outcome), **T20/T26/T27** (exhaustion).

### 11.13 Reason codes contributed to the `RELAY` namespace (ADR-0015 §11.2)

ADR-0005 §11.7 reserved the four selection/health codes for this ADR; they are defined here with
their full attribute set. New codes use the three-part `DOMAIN.SUBDOMAIN.CONDITION` form; the four
reserved identifiers keep the exact spelling already registered by ADR-0005 and ADR-0015.

| Code | class | severity | terminal | user_actionable |
|---|---|---|---|---|
| `RELAY.NONE_REACHABLE` | PERSISTENT | ERROR | false | **true** |
| `RELAY.REGION_UNAVAILABLE` | TRANSIENT | WARN | false | false |
| `RELAY.CAPACITY_REJECTED` | TRANSIENT | WARN | false | false |
| `RELAY.FAILOVER_EXHAUSTED` | PERSISTENT | ERROR | false | **true** |
| `RELAY.SELECT.NO_CANDIDATE_FOR_FAMILY` | PERSISTENT | WARN | false | false |
| `RELAY.SELECT.NO_CARRIAGE_SUPPORTED` | PERSISTENT | WARN | false | false |
| `RELAY.SELECT.ALTERNATES_INSUFFICIENT` | POLICY | WARN | false | **true** |
| `RELAY.SELECT.SUGGESTION_UNKNOWN` | TRANSIENT | WARN | false | false |
| `RELAY.SELECT.ALL_BREAKERS_OPEN` | TRANSIENT | WARN | false | false |
| `RELAY.SELECT.SELF_HOSTED_PREFERRED` | TRANSIENT | INFO | false | false |
| `RELAY.FAILOVER.COMPLETED` | TRANSIENT | INFO | false | false |
| `RELAY.FAILOVER.NO_STANDBY` | TRANSIENT | WARN | false | false |
| `RELAY.FAILOVER.OFFER_UNACKED` | TRANSIENT | WARN | false | false |
| `RELAY.FAILOVER.EPOCH_CONFLICT` | TRANSIENT | INFO | false | false |
| `RELAY.FAILOVER.CROSS_REGION` | TRANSIENT | WARN | false | false |
| `RELAY.REGION.DOWN` | TRANSIENT | ERROR | false | false |
| `RELAY.REGION.SHED_DEFERRED` | TRANSIENT | INFO | false | false |
| `RELAY.STANDBY.SUPPRESSED_POWER` | TRANSIENT | INFO | false | false |
| `RELAY.STANDBY.SUPPRESSED_METERED` | TRANSIENT | INFO | false | **true** |
| `RELAY.STANDBY.CROSS_REGION` | TRANSIENT | INFO | false | false |
| `RELAY.STANDBY.NO_DOMAIN_DIVERSITY` | POLICY | WARN | false | **true** |
| `RELAY.UPGRADE.COMPLETED` | TRANSIENT | INFO | false | false |
| `RELAY.UPGRADE.PROBING_SUSPENDED` | TRANSIENT | INFO | false | false |
| `RELAY.UPGRADE.FLAPPING_SUPPRESSED` | TRANSIENT | WARN | false | false |
| `RELAY.MAP.STALE` | TRANSIENT | INFO | false | false |
| `RELAY.MAP.SIGNATURE_INVALID` | FATAL | CRITICAL | true | false |
| `RELAY.MAP.VERSION_ROLLBACK_REFUSED` | FATAL | CRITICAL | true | false |
| `RELAY.MAP.PEER_SUPPLIED_ACCEPTED` | TRANSIENT | INFO | false | false |
| `RELAY.FLEET.UNREACHABLE` | PERSISTENT | ERROR | false | **true** |

Success is a named outcome (`RELAY.FAILOVER.COMPLETED`, `RELAY.UPGRADE.COMPLETED`) because P10
requires every transition to be reconstructable, not only the failures. No duplicate is defined
for map expiry: ADR-0009's `CONTROL.STALENESS.RELAY_SET_EXPIRED` is consumed as-is.

### 11.14 State-ownership changes required in `docs/architecture.md` §5

**S-09 amendment (no new writer; I8 preserved).** The replicas column gains: *"the signed
`RelayMap` document MAY additionally be carried peer-to-peer between `TrustedPeer`s as an opaque
courier payload and is applied only on a strictly greater `map_version`; the Relay-Selection
Service remains the sole authoritative writer."*

**New row S-31:**

| # | State | Authoritative writer | Replicas | Class | Durability | On conflict |
|---|---|---|---|---|---|---|
| **S-31** | Per-`Relay` client-measured quality + bind-success history, keyed by (`relay_id`, network fingerprint) | **Local `Device`** | **None** — never transmitted | `LOCAL` | Durable, LRU-bounded to 64 network fingerprints, 30-day exponential decay | Local wins always. This is what makes "the client's own measurement overrides the server ranking" survive a process restart |

S-29 and S-30 (ADR-0005 §11.8) are consumed unchanged.

### 11.15 Interfaces required from other ADRs and documents

| From | Required interface |
|---|---|
| [ADR-0005](ADR-0005-relay-architecture.md) | (a) `pair_id` for HRW MUST be domain-separated from `pair_tag` under the same `RelayPairKey`; (b) the token `quota.max_binds_per_min` MUST be raisable for gateway-class devices, or the ≈15-peer rendezvous-listening ceiling in §11.5 stands; (c) confirmation that the leg-level `PING`/`PONG` is observable independently of any half-flow — §11.4's whole attribution rests on it |
| [docs/reliability.md](../reliability.md) | (a) register `T_UPGRADE_DWELL` (120 s), `T_UPGRADE_FLAP_WINDOW` (10 min), `N_UPGRADE_FLAP` (3), `T_UPGRADE_FLAP_SUPPRESS` (30 min), `T_UPGRADE_PROBE_BG` (300 s), `N_UPGRADE_GIVEUP` (20), `T_REGION_SPREAD` (20 s) in §5.3; (b) adopt the §11.12 guards; (c) its relay-failover treatment (§2.1, §4.5, §6) MUST consume this ADR rather than restate it; (d) canonicalise its flat relay codes to the ADR-0015 format (§13) |
| [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) | `doc_type: "relay_map"` registered as a signed state document; >16 KiB path (`StateDocumentAvailable` + `GetStateDocument`) confirmed applicable |
| [ADR-0007](ADR-0007-device-identity-and-pairing.md) | The relay-map issuer is `Owner`-rooted and offline-verifiable (architecture A-04) — this is what makes a peer-couriered map trustworthy with no server |
| [ADR-0004](ADR-0004-nat-traversal-strategy.md) | The symmetric/CGNAT-both-ends classification is the input to §11.10 rule 2 |
| [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) | Fleet exhaustion with the kill switch engaged is `BLOCKED`, never plaintext egress (I3) — already asserted in ADR-0005 §11.2 |
| [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) | A `Capability` named `relay_map_gossip` for §11.9's peer-to-peer map carriage |
| [ADR-0015](ADR-0015-observability-and-diagnostics.md) | Registration of §11.13's codes and of the `RelaySelected` event; S-31 classified as redact-from-bundle |

### 11.16 Making testing-strategy P02 and P03 testable

| Proof test | Injection | Oracle |
|---|---|---|
| **P02** — relays are selected automatically when required | ADR-0004 symmetric NAT at both ends, no port mapping | (a) `RELAYED` reached with no user action; (b) a `RelaySelected{session_id, relay_id, region, failure_domain, score, rank, top_k[]{relay_id, score}, map_version, map_age_ms, inputs{measured_rtt_ms, server_rank, health, load_class, breaker_state}}` event is emitted — selection is auditable, not a black box (RQ12, R-23); (c) the ADR-0002 §11.8 dependency assertion shows **zero** control-plane calls on the path |
| **P03** — relay failure triggers automatic failover | kill the in-use relay process (testing-strategy §2.13) | (a) the transition sequence is exactly `RELAYED → MIGRATING → RELAYED`, with no `DISCONNECTED` and no `RECONNECTING`; (b) `session_id` unchanged; (c) no `CRYPTO.*` handshake event — `Tunnel` key state survived; (d) an in-progress inner TCP connection survives; (e) onset→first-byte within §9.4's budget for the fired detection class; (f) `RELAY.FAILOVER.COMPLETED` carries `from`, `to`, and `onset_to_traffic_ms` |
| P03 variants | kill the whole region; kill the standby's failure domain too; blackhole the control plane during failover | region variant asserts §11.7's split jitter and HRW spread; control-plane variant is architecture §4.4.5(c) |

Determinism requires injectable timers and randomness (testing-strategy A-14) — in particular the
`uniform(0, T_REGION_SPREAD)` draw and the HRW hash must be seedable.

### 11.17 Disposition of every assumption directed at this ADR

| Assumption | Source | Disposition |
|---|---|---|
| **A-13** — the delivered relay set contains ≥2 alternates per `RelayRegion` and is usable while stale | architecture §9 | **CONFIRMED and strengthened.** §11.1 rule 3 makes the floor ≥2 `ACTIVE` relays across ≥2 `failure_domain`s, enforced at publication (§10) *and* self-healing at the edge (the device keeps the prior region's entries rather than accepting a deficient map). §11.1 rule 4 makes stale-but-usable unlimited: no age of map may reduce the set or block an attempt. |
| **A-14** — relay failover is a `MIGRATING` transition, never a `Session` teardown | architecture §9 | **CONFIRMED.** §11.5 rule 1: exactly `RELAYED → MIGRATING → RELAYED`, no `DISCONNECTED`, no `RECONNECTING`, `session_id` and `Tunnel` key state preserved. Realised entirely through reliability's existing T19/T37 → T15; no new state, no new transition. |
| **A12** — relay failover can be driven peer-to-peer from cached relay candidates without the control plane | protocol §18 | **CONFIRMED, with the mechanism.** §11.9's four-row table shows every input is local. For a live `Session`, agreement is `PathOffer`/`PathAck` carried over the standby flow; for a cold `Session` with no channel at all, agreement is deterministic HRW over `pair_id` with k=3 parallel binds and a self-announcing 30 s mismatch. §11.9 adds peer-to-peer carriage of the signed map so candidate sets stay convergent through a long outage. |
| **A2** — the relay presents a UDP-shaped primary plus a TCP/443-shaped fallback, ≤32 B header, available from t=0 | networking §11 | **CONFIRMED for the parts this ADR owns** (availability from t=0: §11.3 rule 4, selection runs at t=0 concurrently with direct probing). The header-size clause is ADR-0005 §9.3's, which already refined it; this ADR does not disturb that refinement. |
| **A4** — the state machine treats relay fallback as a normal transition, exposes `MIGRATING` for make-before-break, and owns all retry/backoff timers; networking supplies guards, not transitions | networking §11 | **CONFIRMED, and this ADR holds itself to the same rule.** §11.12 contributes guards and two events; §11.11 composes with reliability §6.1–§6.3 without redefining a single backoff parameter; §11.10 rule 6 refers all proposed constants to reliability §5.3 for registration. |
| **A-01** — relay failover is `RELAYED → MIGRATING → RELAYED` and direct upgrade `RELAYED → MIGRATING → WAN_DIRECT`; neither passes through `DISCONNECTED`/`RECONNECTING`; neither changes `session_id` or tunnel key state | testing-strategy §0 | **CONFIRMED for both.** Failover: §11.5. Upgrade: §11.10, consuming networking §4.4's make-before-break and reliability T13/T15. P03's and P05's oracles are sound as written; §11.16 states them concretely. |
| **A-18** — relays and rendezvous are separate roles with independent failure domains, and a peer holds a *set* of relay candidates | testing-strategy §0 | **CONFIRMED.** ADR-0005 §8 already makes role separation structural; this ADR carries `failure_domain` in the map (§11.1), requires domain diversity for the standby (§11.6), enforces the ≥2-domain floor at publication and at application (§11.1 rule 3), and never reduces the set to one (§11.3). P02, P03, and the region-failure scenarios need no redesign. |
| **ADR-0005 §11.2(a)–(e)** — the five interfaces ADR-0005 requires from this ADR | ADR-0005 | **(a) SATISFIED** — §11.1's `RelayMap` carries every named field including literal dual-family endpoints, carriages, `RelayRegion`, failure-domain label, version, and TTL. **(b) SATISFIED** — §11.1 rule 3. **(c) SATISFIED** — §11.2 (which to bind) and §11.6 (which standby, in a different failure domain). **(d) SATISFIED** — §11.4 (trigger and health aggregation), §11.2 (ranking), §11.7 (`uniform(0, deadline − 60 s)` per reliability T37). **(e) SATISFIED** — §11.5's relay-assisted rendezvous paragraph, including the ≈15-peer listening ceiling and the quota interface it implies. |
| **reliability.md §2.1** — "select by rendezvous hash over the surviving relay set" | reliability §2.1 | **CONFIRMED**; §11.5 and §11.7 supply the hash key (`pair_id`), the weight (`capacity_weight`), and k=3 parallel binds. |
| **ADR-0009 §11.4 / K-6** — the relay set remains usable past `not_after_ms` and carries ≥2 alternates per region | ADR-0009 | **CONFIRMED**; §11.1 rules 3 and 4. `CONTROL.STALENESS.RELAY_SET_EXPIRED` is consumed rather than duplicated. |

### 11.18 Requirements discharged

R-02 (relay fallback available from t=0), **R-10** (health-aware selection, bounded failover, no
teardown), **R-11** (no single point of failure, honestly bounded in §11.8), **R-12** (measured-RTT
ranking and life-of-session direct upgrade), R-09 (every failure has a defined recovery and a
terminal condition), R-22 (§11.13), R-23 (§11.16's `RelaySelected` event).

## 12. Why the Selected Option Won

1. **Only E can be a pure local function and still balance load.** C1 forbids selection from being
   a query. A alone would satisfy that letter while violating its spirit — a frozen ranking is
   cached state that cannot be disagreed with. E keeps the server's global view as a *bias* and
   makes disagreement first-class.
2. **The bound is the design.** Capping the server term at +100 while leaving measurement worth
   −410 is what converts "the client's own probe overrides a stale server ranking" from a sentence
   in the state table into an arithmetic guarantee that can be unit-tested. Neither A nor B has a
   composition rule at all, because neither has two inputs.
3. **B's cost is not paid where the benefit is.** Fleet-wide probing spends battery, data, and
   privacy on relays that will never be bound, and discloses the device to every operator. Top-5
   plus one exploration slot captures the accuracy that changes a decision at ~1/80th the cost,
   and the discarded accuracy is about relays the score already ranks far below the top.
4. **C fails a constraint reliability.md wrote down first.** "Relay reachability never depends on
   DNS" is not this ADR's preference; it is `docs/reliability.md` §2.1's existing design, and the
   literal-endpoint requirement in §11.1 exists to honour it. SRV would reintroduce exactly the
   bootstrap dependency that row eliminates, on the most hostile networks.
5. **D is structurally impossible, not merely worse.** ADR-0005 §10 pins a bound half-flow to one
   instance and requires both peers to reach the *same* instance. Anycast cannot deliver two peers
   in different places to one instance, and a mid-session route change silently redirects to an
   instance with no state — the exact unexplained-disconnect failure mode this product exists to
   remove. It survives as bootstrap only, which ADR-0005 already permits.
6. **HRW is what makes A12 true without a server.** The hard part of control-plane-free failover is
   not admission (ADR-0005 solved it) or rendezvous (`pair_tag` solved it) — it is two peers with
   no channel *agreeing*. A deterministic pair-keyed hash over a document both already hold is the
   only mechanism that requires no message at all, and it doubles as the correct redistribution
   function for §11.7, where independent score-optimising choice would create the very hot spot
   being avoided.
7. **Reordering rather than filtering is what makes RQ-8 enforceable.** Stating "health is never a
   gate" is easy; making it structurally impossible to violate requires selection to return a total
   order over a non-empty set and to enumerate the four non-eventual facts that may shrink it
   (§11.3 rule 2). Any future code that filters on `HealthState` is then a visible contradiction of
   a numbered rule rather than a plausible-looking optimisation.

## 13. Known Tradeoffs

| Tradeoff | Accepted because |
|---|---|
| Two ranking inputs mean a composition rule that must be defended and can be mis-tuned | The alternative is being wrong in one of two ways with no recourse: A cannot see the user's path, B cannot see the fleet. The cap makes the composition auditable in one line. |
| The top-5 probe budget can leave a genuinely excellent, badly-ranked relay unmeasured | Mitigated by the per-cycle random exploration slot and by the historical-success term (S-31), which promotes a relay that has worked before. It is a heuristic, not a proof; V4 falsifies it. |
| A compromised selection service can steer within ±100 points | Bounded by construction (§7.3), escapable via self-hosting, and observable in the `RelaySelected` event. Removing it entirely (pure HRW) costs fleet load balancing — recorded as V6. |
| HRW convergence can fail when two peers hold maps that differ in a pair's top 3 | Self-announcing within 30 s (`RELAY.PAIR_UNMATCHED`), then rank 4–6. k=3 parallel binds make a single-entry map difference harmless. |
| Peer-to-peer map carriage adds a propagation path that is exercised mostly during outages | It is signature-verified, monotone, and capability-gated; it cannot forge, only fail to help. It is the only mechanism that keeps candidate sets convergent across a multi-hour control-plane outage. |
| The parked-mobile standby is released, so mobile failover after a park is ~2 s, not 300 ms | A standby with no keepalive is not warm, and reporting it as warm would be dishonest. reliability §6.6 already accepts binding loss while parked; the design answer is fast wake, not a fictional standby. |
| Cross-region failover can land directly in `DEGRADED` | A working path at 200 ms beats no path. It is announced at the moment of the move rather than discovered by the user. |
| S-31 is a durable per-network history on the device | It never leaves the device, is LRU- and time-bounded, and is redacted from diagnostics. Without it, every restart discards the measurements that make RQ3 true. |
| Region redistribution uses HRW rather than score, so a device may not get its *best* surviving relay | Getting the best relay is the individually optimal, collectively catastrophic choice. Proportional spread with no coordination is worth a few tens of milliseconds. |

## 14. Revisit Conditions

| # | Falsifiable trigger |
|---|---|
| V1 | **Measured p95 relay-to-relay failover with a bound standby exceeds 700 ms** (onset → first user byte, hard-signal class) over a month of fleet telemetry. §9.4's budget is falsified; either detection or the make-before-break commit is slower than modelled, and ADR-0005 V5's 1.5 s falsifier is then within reach. |
| V2 | **More than 10 % of relay failovers are attributed wrongly** — measured as failovers that complete but do not restore traffic, or dead-peer events that trigger a relay migration. §11.4's leg-versus-half-flow discriminator is insufficient and needs a third signal. |
| V3 | **A `RelayRegion` failure causes ≥5 % `RELAY.CAPACITY_REJECTED` on the adjacent region** during redistribution. §11.7's three controls are inadequate together, and capacity headroom (not client policy) is the real answer. |
| V4 | **The exploration slot promotes a relay into the bound position more than 15 % of the time** over a quarter. The top-5 probe budget is systematically missing good relays and N must rise, or `server_rank` is poorly calibrated. |
| V5 | **Fleet-wide median measured RTT spread within a `RelayRegion` falls below 20 ms.** Client measurement can then no longer distinguish relays inside a region, the +100 server cap becomes decisive by default, and selection should collapse to HRW-with-load-weighting inside a region. |
| V6 | A relay operator is found to have received disproportionate traffic traceable to a `server_rank` publication not justified by capacity or health. §7.3's steering bound has been exercised in practice; move to pure HRW selection with server input reduced to health and capacity only. |
| V7 | **More than 2 % of control-plane-free failovers fail HRW convergence** (two `RELAY.PAIR_UNMATCHED` cycles or more). k=3 is too narrow, or maps diverge more than modelled and peer-to-peer carriage (§11.9) is not propagating. |
| V8 | **`RELAY.UPGRADE.FLAPPING_SUPPRESSED` fires for more than 1 % of `RELAYED` sessions per month.** The networking §4.3 hysteresis plus §11.10's dwell is still admitting marginal direct paths, and the `PATH_BETTER` margin — not the dwell — is the wrong parameter. |
| V9 | **Self-hosted relays exceed 25 % of relayed connection-minutes.** The +120 bonus was calibrated for a minority deployment; at that share, `Owner`-run relays become load-bearing infrastructure whose availability the operator cannot see, and `RELAY.SELF_HOSTED_NO_ALTERNATE` handling must be revisited against R-11. |
| V10 | The `RelayMap` exceeds **256 KiB** for any operator group. Whole-document distribution stops being reasonable on metered mobile links, and the map must become region-scoped or delta-encoded — which reopens whether a device can still evaluate a cross-region failover offline. |
