# ADR-0004: NAT Traversal Strategy

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** NETWORKING
- **Related:** [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md),
  [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md),
  [ADR-0003](ADR-0003-network-contract-schema-format.md),
  [ADR-0005](ADR-0005-relay-architecture.md),
  [ADR-0006](ADR-0006-relay-discovery-and-failover.md),
  [ADR-0010](ADR-0010-ipv4-ipv6-routing.md),
  [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md),
  [ADR-0015](ADR-0015-observability-and-diagnostics.md),
  [docs/networking.md](../networking.md), [docs/reliability.md](../reliability.md)

## 1. Context

TwinVPN's value proposition is a **direct** encrypted path between a user's own devices, with
relay as a guaranteed floor rather than the normal case. The defect list this product exists to
fix contains "NAT traversal failures", "symmetric NAT and CGNAT failures", "excessive relay
latency", and "throughput degradation" — all four are downstream of one decision: how a
`Session` between two `Device`s behind arbitrary middleboxes establishes a `Path`.

The environment is genuinely hostile and getting worse. Carrier-grade NAT is now the default on
mobile and increasingly common on fixed-line broadband. Enterprise and campus networks
frequently block outbound UDP entirely. Home CPE varies wildly in mapping behavior, mapping
lifetime, and hairpinning support. At the same time, IPv6 deployment has crossed the point
where a large and growing fraction of client pairs have working end-to-end IPv6 — in which
case NAT traversal is simply not a problem to be solved.

This ADR decides the traversal *strategy*: what is tried, in what order, with what expected
success, and what happens when it does not work. It does **not** decide the relay design
([ADR-0005](ADR-0005-relay-architecture.md)), the tunnel cryptography
([ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)), or the connection
state machine (`docs/reliability.md`).

## 2. Requirements


**Requirements discharged** ([docs/vision.md](../vision.md) §5): **R-01** (a direct path is established whenever the network permits one), **R-02** (relay fallback is automatic and concurrent, not a post-timeout retry, so it costs no added connect latency), **R-12** (symmetric NAT and CGNAT are handled or honestly declared untraversable, never silently retried), and **R-18** (a UDP-blocked or port-restricted network degrades through a stated transport ladder rather than failing).
| # | Requirement |
|---|---|
| R1 | Establish a usable path between any two `TrustedPeer`s **in bounded time**, regardless of NAT class — by direct path where possible, by relay otherwise. Connectivity is never optional. |
| R2 | First user packet MUST be deliverable within a small bounded interval (target: ≤ 1.5 s p95 to *some* path) and MUST NOT wait for direct traversal to fail. |
| R3 | Prefer the lowest-latency correct path; upgrade `RELAYED` → `WAN_DIRECT`/`LOCAL_DIRECT` opportunistically and without user action (N5). |
| R4 | IPv6 MUST be a first-class, first-tried traversal path, not a fallback. |
| R5 | Traversal MUST work with the control plane unavailable for an established `Session` (I5). |
| R6 | Path candidates MUST be authenticated; an off-path attacker MUST NOT be able to steer a path (I1, I4). |
| R7 | Keepalive cadence MUST be adaptive so that a multi-peer `TwinNet` does not destroy mobile battery life. |
| R8 | Every traversal outcome MUST emit a structured, actionable diagnostic including the observed NAT class (I6). |
| R9 | Traversal MUST NOT require infrastructure that can read tunnel plaintext (I1). |
| R10 | The design MUST support many concurrent peer sessions per `Device`, including a gateway serving many clients (I7). |

## 3. Constraints

- **I1** — reflexive-address discovery and rendezvous infrastructure sees only ciphertext and
  metadata; it holds no key that can decrypt tunnel traffic.
- **I2** — no custom cryptography. Probe authentication reuses the primitives selected in
  ADR-0001; this ADR designs no handshake of its own.
- **I4** — peers are identified by `DeviceKey`; probe authentication binds to it.
- **I5** — path re-validation and migration must be drivable by the data plane alone.
- Probing must not look like an attack: no unbounded port scanning, no amplification vector,
  strict per-peer rate limits.
- Mobile platforms suspend processes and close sockets without notice; traversal state must be
  cheaply reconstructible.
- No kernel module of our own on any platform (N7).

## 4. Considered Alternatives

| # | Alternative |
|---|---|
| **A** | **Full ICE (RFC 8445)** with standard STUN (RFC 8489) and TURN (RFC 8656) servers, SDP-style candidate exchange, connectivity checks, nomination. |
| **B** | **Lightweight authenticated disco protocol over the rendezvous service** — our own small `PING`/`PONG`/`CALL` exchange multiplexed on the tunnel socket, with IPv6-first candidate ordering, opportunistic port mapping, and always-parallel relay. (Tailscale-shaped.) |
| **C** | **QUIC-native traversal** — run the tunnel inside QUIC and use QUIC path validation (RFC 9000 §8/§9) plus connection migration as the traversal and roaming primitive. |
| **D** | **Port-mapping-first** — rely on PCP (RFC 6887), NAT-PMP, and UPnP-IGDv2 to obtain explicit inbound mappings; hole punching only as a secondary. |
| **E** | **Aggressive symmetric-NAT defeat** — birthday-paradox / sequential port prediction as a *primary* strategy, with high fan-out probing (hundreds to thousands of sockets and ports). |
| **F** | **IPv6-only direct** — attempt direct paths over IPv6 exclusively; any IPv4-only pair goes straight to relay. |
| **G** | **Relay-always** — no traversal at all; every `Session` is `RELAYED`. (Genuinely viable: it is simple, it always works, and it is what several shipping products effectively do.) |

## 5. Advantages of Each Alternative

**A — Full ICE.** Standardized, interoperable, and battle-tested at enormous scale in WebRTC;
the corner cases (aggressive nomination, candidate pair pruning, role conflicts, TURN
permissions) are already discovered and documented by other people. Off-the-shelf
implementations exist. STUN/TURN servers are commodity infrastructure with many vendors.
Trickle ICE gives incremental candidate delivery. Peer-reviewed security analysis exists.

**B — Lightweight disco.** Minimal on-wire surface; probes multiplex on the *same* socket and
5-tuple as the data plane, so a validated path is validated for the exact flow that will carry
data (ICE's classic weakness is validating a path that the media stream then does not use
identically). No separate TURN credential system — the relay is authenticated with the same
`DeviceKey`. `PONG` carries the observed source address, giving continuous free reflexive
refresh, which makes roaming detection a data-plane property and satisfies I5 directly. Tiny
code footprint fits inside an iOS network extension's memory budget. Candidate ordering is ours
to tune, so IPv6-first is trivial. Proven at scale by Tailscale for exactly this problem shape.

**C — QUIC-native.** Path validation, connection migration, loss recovery, and congestion
control all come in one well-specified package; connection IDs make migration survive address
changes cleanly, which is exactly the roaming requirement. TLS 1.3 handshake satisfies I2 with
no custom crypto. UDP-on-443 shape is friendly to restrictive networks and blends with normal
web traffic. Strong library ecosystem.

**D — Port-mapping-first.** When it works, it is *strictly better* than hole punching: an
explicit mapping defeats even APDM (symmetric) mapping, survives idle periods without
keepalives (huge battery win), and needs no simultaneous-open coordination. PCP in particular
is well-specified, supports both families, and can request long lifetimes.

**E — Aggressive port prediction.** Materially raises direct-connection rates against symmetric
NAT, which is precisely the cell of the traversability matrix where users are most upset. On
NATs with sequential port allocation, a small delta prediction succeeds often. Purely
client-side: no router cooperation, no new infrastructure.

**F — IPv6-only direct.** Radically simple: no NAT semantics to model, no hole punching, no
keepalive tuning for mapping lifetime, no port prediction, no port-mapping protocols. Every
IPv6 cell in the traversability matrix is a direct connect. Correct by construction and cheap
to test. Pushes the world in the right direction.

**G — Relay-always.** The simplest possible design and the most predictable: one code path, one
failure mode, uniform latency, trivially testable, no NAT matrix, no per-platform socket
weirdness. Relay capacity planning becomes the only scaling question. Works identically on
every network including UDP-blocked ones.

## 6. Disadvantages of Each Alternative

**A — Full ICE.** Heavyweight for a 2-party, mutually-authenticated, long-lived VPN session;
ICE is designed for browser-mediated calls between strangers with an SDP offer/answer model we
do not have. TURN introduces a **second credential system** and, in its usual deployment, a
server that terminates and re-originates flows — an awkward fit with I1 unless carefully
constrained. ICE's connectivity checks run over a separate STUN-shaped exchange rather than the
data socket, so a "validated" pair can still differ from the one carrying tunnel traffic. Full
ICE state machines are large; the iOS extension memory budget is a real constraint. Aggressive
nomination timing is tuned for ~seconds of call setup, not for a VPN that must have a path
within a fraction of a second. And ICE still fails on symmetric↔symmetric — it does not solve
our hardest cell, it just relays like everything else.

**B — Lightweight disco.** Non-standard: no interop with anything, and we own every corner case
ourselves, including the ones ICE already found. Requires us to design the probe format and its
authentication binding (mitigated: we design no *primitive*, only a framing, per I2). Requires
our own conformance test matrix (`docs/testing-strategy.md`). Risk of subtly re-inventing ICE badly.

**C — QUIC-native.** Puts a full QUIC stack in the data path for a workload (a VPN tunnel) whose
payload is already reliable-or-not per inner flow — QUIC's own loss recovery and congestion
control then stack on top of the inner transport's, which is the classic TCP-over-TCP
meltdown in modern dress. Even in datagram mode (RFC 9221) the handshake and connection state
are heavier than needed. QUIC path validation validates *reachability*, but it does not perform
hole punching, does not do simultaneous open, and does not defeat symmetric NAT — so it is not
actually a traversal strategy, it is a migration strategy. It also conflicts with ADR-0001 if
that ADR selects WireGuard/Noise.

**D — Port-mapping-first.** Availability is poor and unpredictable: UPnP is widely disabled by
default for good security reasons, PCP is not deployed on most consumer CPE, and **CGNAT almost
never offers any of them**. It is useless in exactly the cases that matter most. It also
requires trusting the local gateway to honor a mapping request, and a hostile LAN gateway can
lie. Cannot be the primary strategy; a strategy that works "when the router is friendly" is not
a strategy.

**E — Aggressive port prediction.** Probabilistic and network-hostile: hundreds of packets to
sequential ports is indistinguishable from a port scan and will trip IDS, get the user
rate-limited, or get the account flagged by a carrier. Battery and data cost on mobile is
significant. Success rate collapses against NATs with random allocation and against CGNAT with
port-block allocation. Needs both ends to fan out simultaneously, which needs coordination
anyway. Fundamentally cannot be relied on for R1.

**F — IPv6-only direct.** Abandons every IPv4-only user pair to relay, which today is a large
fraction — including the enterprise networks that block or do not deploy IPv6 and many
IPv4-only home ISPs. This directly reintroduces "excessive relay latency" for those users. Also
brittle: "has an IPv6 address" and "has working IPv6 connectivity to this peer" are different
propositions, and broken-IPv6 networks are still common.

**G — Relay-always.** Fails the product's central promise. Every session pays relay RTT
(commonly +20–120 ms) and relay throughput limits, permanently. Relay egress cost scales
linearly with all user traffic — an unbounded operating expense. It concentrates a single
point of failure, which is itself on the defect list. It makes LAN-to-LAN transfers between two
devices in the same room traverse the Internet, which users notice immediately and forgive
never.

## 7. Security Implications

Of the selected option (B, in the composite form described in §11):

- **Probe authentication.** Every disco `PING`/`PONG` is encrypted and authenticated to a
  per-peer disco key derived from the peers' `DeviceKey`s under ADR-0001's primitives (I2, I4).
  An off-path attacker cannot forge a candidate, cannot induce a migration, and cannot learn
  which peers are talking by observing probes alone. Path steering is therefore not an
  available attack.
- **Rendezvous knows metadata, not content (I1).** The rendezvous service learns which
  `Device`s are attempting to connect and their reflexive addresses. It cannot decrypt
  anything. This metadata exposure is inherent to any rendezvous-based traversal (ICE's STUN
  server learns the same thing) and is disclosed in `docs/threat-model.md`.
- **Reflexive address disclosure.** Hole punching necessarily reveals each peer's public IP to
  the other peer. Between a user's own devices this is acceptable by definition; it is
  nonetheless stated, because it is a real difference from relay-always, where peers never
  learn each other's addresses. A user who does not want a given peer to learn their address
  can pin that peer to `RELAYED`.
- **Amplification.** `PONG` is never larger than `PING`, and probes are rate-limited per peer
  and per source address, so the disco endpoint is not a reflector.
- **Port prediction restraint.** Bounded to `k ≤ 256` sockets, one attempt per path attempt,
  ≤ 2 s, and only against a peer whose mapping the rendezvous has observed to be port-varying.
  This is a deliberate security-hygiene cap, accepting a lower symmetric-NAT success rate.
- **Where a rejected alternative was better:** **G (relay-always)** is materially better on
  metadata exposure between peers — no peer ever learns another's public address — and on
  attack surface, since no unsolicited inbound packet is ever expected. This is why per-peer
  "always relay" remains a supported user setting rather than being designed out.

## 8. Reliability Implications

- **Relay is gathered in parallel from t=0**, so R1/R2 do not depend on traversal succeeding.
  There is no "wait for direct to fail" timeout on the critical path — the single most common
  source of multi-second connect stalls in comparable products.
- **Adaptive keepalive with learned mapping lifetime** (`docs/networking.md` §3.5) removes the
  "mapping expired silently, looks like a disconnect" failure, which is a principal cause of
  "random tunnel disconnects".
- **Data-plane-driven re-validation** means an established `Session` survives full control-plane
  outage (I5): `PONG`-observed source addresses keep reflexive state fresh with no control-plane
  round trip.
- **Make-before-break migration** means a path upgrade or downgrade drops no packets and the
  application sees no reset (`MIGRATING`, not `RECONNECTING`).
- **Honest failure classes.** APDM↔APDM and CGNAT↔CGNAT over IPv4 are declared relay-by-design.
  The state machine does not retry them indefinitely; it records `NAT.SYMMETRIC_BOTH_ENDS`
  and settles in `RELAYED`, with background upgrade probing at a decaying cadence.
- **Where a rejected alternative was better:** **G** has strictly fewer states and therefore
  fewer ways to be wrong. The composite design pays for its latency advantage with a larger
  test matrix, which is why `docs/testing-strategy.md` must own an explicit NAT-class conformance suite.

## 9. Performance Implications

| Metric | Target | Notes |
|---|---|---|
| Time to *any* path (p95) | ≤ 1.5 s | Relay candidate is available immediately |
| Time to direct path, EIM/EIF or IPv6 (p50) | ≤ 300 ms | One RTT of candidate exchange + one probe RTT |
| Time to direct path, APDF simultaneous open (p95) | ≤ 2 s | Multiple probe rounds |
| `RELAYED` → direct upgrade detection | ≤ 15 s after traversal becomes possible | `PATH_STABLE` guard is 3 probe intervals |
| Direct-path share, dual-stack population | ≥ 90% | Driven by IPv6-first |
| Direct-path share, IPv4-only population | 60–75% | Honest; APDM/CGNAT pairs are relayed |
| Steady-state probe overhead | < 1 kbit/s per active peer | Probes < 100 B |
| Keepalive wakeups, idle mobile peer | ~0 | Direct keepalives suspended; relay carries wake |

Direct paths avoid the relay's added RTT (typically +20–120 ms depending on region) and its
per-session throughput ceiling. **F (IPv6-only)** would be better on code simplicity and equal
on latency for the pairs it serves, but strictly worse in aggregate because it relays every
IPv4-only pair. **E** would improve the IPv4-only figure by perhaps a few points at a
disproportionate cost in packets sent and IDS incidents.

## 10. Operational Implications

- Requires the rendezvous service from
  [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) to support reflexive-address
  observation and `CALL` delivery. This is a small, stateless, horizontally scalable service.
- Requires relay infrastructure per ADR-0005/0006 sized for the **relayed fraction** of traffic
  (planned 10–40% of sessions depending on population), not for all of it — a direct
  consequence of choosing B over G, and the main operating-cost argument for this ADR.
- Support burden shifts from "it doesn't connect" to "explain why this pair is relayed". This
  is why `NET.NAT_CLASS_OBSERVED` and `NET.PORTMAP_FAILED` exist: the diagnostic must tell the
  user "your router's NAT is symmetric; enabling UPnP/PCP or IPv6 would allow a direct path".
- Test infrastructure must include a NAT-class simulation matrix (EIM/ADM/APDM × EIF/ADF/APDF,
  plus CGNAT, plus UDP-blocked, plus hairpin-off). Owned by `docs/testing-strategy.md`.
- Fleet telemetry must report per-NAT-class direct-connection rates so §9's targets are
  falsifiable in production (see §14).

## 11. Decision

**Adopt Alternative B — a lightweight authenticated disco protocol over the rendezvous
service — as the traversal framework, ordered IPv6-first, with D and a bounded form of E as
subordinate techniques inside it, and with the relay (ADR-0005) always gathered in parallel as
a guaranteed floor.**

Concretely, for every peer, in parallel, with the relay candidate live from t=0:

| Order | Technique | Source |
|---|---|---|
| 1 | Native IPv6 candidates (`HOST_V6_GLOBAL`, `SRFLX_V6`) | F, adopted as ordering |
| 2 | LAN candidates (`HOST_V4_PRIVATE`, `HOST_V6_LINKLOCAL`) → `LOCAL_DIRECT` | B |
| 3 | IPv4 reflexive + simultaneous open across APDF filtering | B |
| 4 | Explicit port mapping: PCP → NAT-PMP → UPnP-IGDv2, 250 ms budget each | D, subordinate |
| 5 | Bounded port prediction (`k ≤ 256`, ≤ 2 s, once, only vs. observed port-varying mapping) | E, bounded |
| 6 | `RELAYED` — **by design, not by failure** | ADR-0005/0006 |

Supporting decisions:

- Probes multiplex on the tunnel's own UDP socket, distinguished by a leading type byte, and
  are authenticated under ADR-0001's primitives. No new cryptographic primitive (I2).
- Keepalive is adaptive (25 s → 120 s), learned per network fingerprint, suspended for idle
  peers on battery-constrained devices (R7).
- Simultaneous open is achieved by sending probes on **all** candidate pairs concurrently plus
  a rendezvous-delivered `CALL`; there is no explicit synchronization round.
- **Symmetric↔symmetric and CGNAT↔CGNAT over IPv4 are declared relay-by-design.** They emit
  `NAT.SYMMETRIC_BOTH_ENDS`, settle in `RELAYED`, and continue background upgrade probing.
  This is a designed outcome with an expected rate, not an error path.
- Full ICE (A), QUIC-native traversal (C), port-mapping-first (D as primary), aggressive port
  prediction (E as primary), IPv6-only (F), and relay-always (G) are rejected as *overall
  strategies*; G remains available as a **per-peer user setting**.

## 11.5 `NAT` reason codes (discharging the ADR-0015 §11.2 domain assignment)

[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 assigns the **`NAT`** domain to this
ADR. These are its registered codes. Earlier drafts of this ADR spelled several of these
conditions in the `NET.*` domain; those spellings are **withdrawn** — a traversal outcome belongs
to `NAT`, and a receiver degrading an unknown code by its `DOMAIN` prefix (§11.2 rule 5) must be
told "NAT traversal", not "network".

| Code | Class | Severity | Terminal | User-actionable | Condition |
|---|---|---|---|---|---|
| `NAT.SYMMETRIC_BOTH_ENDS` | PERSISTENT | WARN | no | no | Both ends present Address-and-Port-Dependent Mapping; no direct path is obtainable and the session is relayed (§7.2) |
| `NAT.CGNAT_DETECTED` | PERSISTENT | INFO | no | no | The device is behind carrier-grade NAT; server-reflexive candidates are shared and port prediction is unreliable |
| `NAT.CGNAT_V4_NO_V6` | PERSISTENT | WARN | no | yes | CGNAT on IPv4 with no IPv6 available — the worst traversal case. Actionable: enabling IPv6 on the access network usually restores a direct path |
| `NAT.UDP_BLOCKED` | PERSISTENT | WARN | no | no | UDP egress is blocked; the transport ladder has fallen through to a TCP/TLS-shaped carriage (**R-18**) |
| `NAT.PUNCH_TIMEOUT` | TRANSIENT | INFO | no | no | Hole-punching produced no validated path within its budget; racing continues on other candidates |
| `NAT.NO_SERVER_REFLEXIVE` | TRANSIENT | WARN | no | no | No server-reflexive candidate could be gathered — the rendezvous could not observe this device's mapped address |
| `NAT.PORTMAP_FAILED` | TRANSIENT | INFO | no | no | PCP/NAT-PMP/UPnP port mapping was attempted and refused or unanswered |
| `NAT.HAIRPIN_UNSUPPORTED` | PERSISTENT | INFO | no | no | Two peers behind the same NAT cannot reach each other via the external mapping; the local candidate is used instead |
| `NAT.CLASS_OBSERVED` | TRANSIENT | INFO | no | no | Informational: the measured mapping and filtering class of both ends, for the R-23 connectivity report |

---

## 12. Why the Selected Option Won
1. **It is the only option that satisfies R1 and R2 simultaneously.** Relay-in-parallel gives a
   bounded time-to-connectivity that does not depend on traversal working, while direct probing
   gives the latency the product promises. A, C, D, E, and F all leave R2 dependent on a
   traversal attempt completing or timing out; G satisfies R1/R2 but fails R3.
2. **IPv6-first is nearly free and enormously effective.** It is a candidate-ordering decision,
   not a mechanism, and it converts the entire hard region of the NAT matrix into a trivial
   region for the growing dual-stack population. Adopting F's insight without F's exclusivity
   is strictly dominant.
3. **Probing on the data socket is a correctness property, not an optimization.** ICE's
   separation of connectivity checks from the media path is a genuine source of "validated but
   doesn't work". Multiplexing removes that class of bug entirely.
4. **The iOS network-extension memory budget is a hard constraint** that a full ICE stack (A)
   or a full QUIC stack (C) makes materially harder to meet.
5. **C is not actually a traversal strategy.** QUIC path validation confirms reachability and
   migrates connections; it does not punch holes. Choosing it would still require B underneath,
   plus a conflict with ADR-0001.
6. **D and E are real techniques with narrow applicability**, so they belong *inside* the
   strategy at their true weight, not as the strategy. Elevating either would make the system's
   success rate depend on router friendliness or on luck.
7. **G's operating cost is unbounded and its latency floor is permanent.** Relaying 100% of
   traffic instead of 10–40% is the difference between a viable and a non-viable cost model,
   and it forfeits the LAN case entirely.

## 13. Known Tradeoffs

| Tradeoff | Accepted because |
|---|---|
| Non-standard probe protocol; zero interop with ICE/WebRTC ecosystems | TwinVPN peers only ever talk to TwinVPN peers; interop has no user. Cost is paid in our own test matrix. |
| We own every traversal corner case ICE already solved | Scope is much narrower (2 mutually-authenticated parties, long-lived, one media type), so the corner-case space is genuinely smaller. |
| Symmetric↔symmetric IPv4 pairs get relay latency permanently | Physics. Mitigated by IPv6-first, port mapping, and honest diagnostics that tell the user what would fix it. |
| Peers learn each other's public IP addresses | They are the same user's devices. Per-peer `RELAYED` pinning is available for the exception. |
| Rendezvous learns connection metadata | Inherent to rendezvous traversal; bounded by I1 and documented in the threat model. |
| Bounded port prediction leaves success rate on the table | Unbounded probing is network-hostile and gets users rate-limited or flagged. |
| Adaptive keepalive can briefly mispredict a mapping lifetime after a network change | Falls back to the last known-good interval on first loss; costs one re-punch, not a disconnect. |
| Relay must be provisioned even though most sessions are direct | It is the floor that makes R1 unconditional; ADR-0005/0006 own the capacity model. |

## 14. Revisit Conditions

Revisit this ADR if any of the following becomes true:

1. **Measured direct-path share for the dual-stack population falls below 85%**, or for the
   IPv4-only population below 55%, sustained over 30 days of fleet telemetry.
2. **Measured p95 time-to-first-path exceeds 2.0 s**, or p50 time-to-direct on IPv6-capable
   pairs exceeds 600 ms.
3. **IPv6 end-to-end availability between peer pairs exceeds 90%** in our fleet — at that point
   Alternative F becomes close to viable, and the IPv4 traversal machinery (steps 3–5) could be
   demoted to a legacy path, materially shrinking the code and the test matrix.
4. **IPv6 availability stalls below 40%** *and* CGNAT prevalence continues rising, such that the
   relayed fraction exceeds 50% of sessions — at which point the cost model must be re-derived
   and G's simplicity re-evaluated against a much larger relay fleet.
5. **ADR-0001 selects a QUIC-based data plane**, which would make Alternative C's path
   validation and connection migration free rather than additive; the disco layer would then be
   reduced to candidate gathering and hole punching only.
6. **A platform removes the ability to send unsolicited UDP or to keep a UDP socket alive in the
   background** (e.g. a future iOS/Android release restricting network-extension sockets),
   invalidating the keepalive model in §11.
7. **PCP deployment in consumer CPE exceeds ~50%** as measured in our own fleet, which would
   raise D from a subordinate technique to a co-primary one and would let us drop step 5.
8. **Bounded port prediction is measured to contribute < 2 percentage points** of direct-path
   share across the fleet — remove it, since its IDS and battery cost would then be unjustified.
9. **A standards-track successor to ICE emerges that is small enough for a network extension**
   and gives us interop we can use, changing A's cost/benefit.
