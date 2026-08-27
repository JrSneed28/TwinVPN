# ADR-0005: Relay Architecture

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** NETWORKING
- **Related:** [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md), [ADR-0004](ADR-0004-nat-traversal-strategy.md), [ADR-0006](ADR-0006-relay-discovery-and-failover.md), [ADR-0007](ADR-0007-device-identity-and-pairing.md), [ADR-0010](ADR-0010-ipv4-ipv6-routing.md), [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md), [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md), [ADR-0015](ADR-0015-observability-and-diagnostics.md), [docs/networking.md](../networking.md), [docs/protocol.md](../protocol.md), [docs/reliability.md](../reliability.md), [docs/architecture.md](../architecture.md), [docs/threat-model.md](../threat-model.md)

This ADR owns the **relay data plane**: what a `Relay` is, how it forwards, the wire format and
per-transport overhead of the device↔relay leg, how two peers rendezvous inside a relay without
identifying themselves to it, how a device proves admission without a live control-plane call,
how warm standby and resource control work, and what a relay persists and does on restart. It
does **not** own which `Relay` a device picks, ranking, health aggregation, drain scheduling, or
failover policy — all [ADR-0006](ADR-0006-relay-discovery-and-failover.md), for which §11.2
states the required interface. It does not own tunnel cryptography
([ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)), NAT traversal tactics
([ADR-0004](ADR-0004-nat-traversal-strategy.md)), or the `ConnectionState` machine
([docs/reliability.md](../reliability.md)) — it supplies guards and reason codes only.

## 1. Context

`docs/networking.md` §3.2 declares the APDM↔APDM and CGNAT↔CGNAT IPv4 cells **relay by design**
(tenet N4). `ADR-0004` §11 makes the relay candidate live from t=0 rather than after a
direct-path timeout. `docs/architecture.md` §2.11 places relay infrastructure in the data plane
and **outside the trust boundary** (B3), and states three interface requirements this ADR must
satisfy. `docs/reliability.md` §2.1 already assumes a warm standby relay session, a drain
protocol with a herd-safe deadline, and relay endpoints reachable as literals without DNS.

So the relay is not an escape hatch. It is a **load-bearing floor** that must be:

- available as a `ConnectionCandidate` at t=0 (R-01, R-02, architecture A-10);
- usable with the entire control plane down (I5, R-11, architecture A-12);
- failover-capable within a bounded time without touching `Session` or `Tunnel` state
  (R-10, protocol §11.2);
- structurally incapable of decrypting anything (I1, testing-strategy P14);
- cheap enough per idle peer to hold a standby (architecture A-11, reliability §6.6);
- dual-stack, always (P9, protocol §11.1);
- amplification-safe, because a public packet forwarder is a DDoS weapon by default.

The prior art is well-trodden — TURN, DERP, and various bespoke forwarders — and the interesting
question is not "can packets be forwarded" but **what the relay is allowed to know, and what it
is allowed to be asked for at the moment a device reconnects with no network to the control
plane**. Those two questions drive the whole design.

## 2. Requirements

| # | Requirement | Source |
|---|---|---|
| RQ1 | A `Relay` MUST NOT hold, derive, or be a party to any key that decrypts L-DATA. | I1, P1, R1 of ADR-0001 |
| RQ2 | Relay admission MUST be verifiable **offline** by the relay: no control-plane call per packet, per bind, or per reconnect. | I5, architecture A-12, R-11 |
| RQ3 | A relay flow MUST be openable in parallel with direct-path racing from t=0. | architecture A-10, R-01, R-02 |
| RQ4 | A device MUST be able to hold one warm standby flow on a second `Relay` without materially increasing data or battery cost. | architecture A-11, R-10 |
| RQ5 | Relay loss MUST be a `MIGRATING` transition, never a `Session` teardown. | reliability §2.1, R-05, R-10 |
| RQ6 | Every `Relay` MUST present both IPv4 and IPv6 endpoints, and MUST bridge a v6-only peer to a v4-only peer. | P9, protocol §11.1, R-14 |
| RQ7 | A UDP-shaped primary transport plus at least one TCP/443-shaped fallback MUST exist, with stated per-carriage byte overhead. | networking A2, R-18 |
| RQ8 | Relay amplification factor MUST be ≤ 1.0 and reflection MUST require a completed, source-validated handshake. | operator duty of care |
| RQ9 | Relay overload, shedding, and drain MUST be surfaced with a `reason_code`, never as silent loss. | I6, R-22, R-09 |
| RQ10 | A relay MUST persist nothing durable about flows, peers, or pairs. | I1 defence in depth, P14 |
| RQ11 | The relay MUST learn no more about the peer pair than forwarding structurally requires. | protocol A11 |
| RQ12 | Relay admission MUST honour the S-03 trust epoch with a bounded, stated lag. | S-03, architecture §4.5 |
| RQ13 | A self-hosted `Relay` MUST be supported with a stated trust and authentication story. | architecture §3.3 entity catalogue |
| RQ14 | Per-device and per-flow rate limits, quotas, and fair queuing MUST exist and be enforceable without decrypting. | C5 of ADR-0001, I7 |

## 3. Constraints

| # | Constraint |
|---|---|
| C1 | **I2 — no novel cryptography.** Every construction must be an audited primitive used as specified. |
| C2 | ADR-0001 fixes L-DATA as unmodified WireGuard and defines `T-RELAY` as "L-DATA datagram inside an authenticated device↔relay session". This ADR may define the *carriage* of that session; it may not alter L-DATA. |
| C3 | Switching transport mode MUST NOT re-run the L-DATA handshake, reset counters, or alter any L-DATA property (ADR-0001 §7.2, "the single most important composition rule"). |
| C4 | Relay bandwidth is the dominant recurring operating cost. Every design choice that increases relayed byte count is a direct margin cost. |
| C5 | Mobile radio wakeups are the dominant battery cost (reliability §6.6). Keepalives across all peers and the relay MUST coalesce into one wake window. |
| C6 | Router-class and low-memory targets are first-class (N10, R-21); the relay client must not require a second full protocol stack beyond what ADR-0001 already ships. |
| C7 | The overlay MTU floor is 1280 (networking §6.2). No carriage may make 1280 unachievable on a 1500-byte underlay. |
| C8 | `S-09`/`S-10` are `EVENTUAL` and MUST NEVER gate a connection attempt. A relay may not require a fresh health or selection call to admit a device. |

## 4. Considered Alternatives

| ID | Alternative |
|---|---|
| **A** | **DERP-style forwarder keyed by peer public key** over HTTPS/TLS, with an embedded UDP fast path. Mailbox model: a device connects, announces its public key, and sends frames addressed to a peer's public key; the relay maintains a public-key→connection map. |
| **B** | **Standards-based TURN (RFC 8656)** with TURN-over-TLS/TCP for the blocked-UDP case. Allocations, permissions, `CreatePermission`/`ChannelBind`, long-term credentials (RFC 8489 §9.2). |
| **C** | **Bespoke frame forwarder with a capability-token-admitted, `pair_tag`-addressed half-flow table.** One authenticated device↔relay leg per (device, relay), multiplexing N half-flows; two half-flows joined by a blinded pairing tag; four carriages of that leg. |
| **D** | **Terminating proxy / SFU**: the relay terminates each peer's tunnel and re-originates a second tunnel to the other peer. |
| **E** | **Double-encapsulated peer-relay**: the `Relay` is an ordinary TwinVPN device that has a normal WireGuard tunnel to each endpoint and forwards the inner tunnel as overlay traffic. |

## 5. Advantages of Each Alternative

**A — DERP-style.** Proven at very large scale. HTTPS/TLS carriage traverses almost every
restrictive network, captive portal, and enterprise proxy, so it doubles as the blocked-UDP
answer without a separate mechanism. Addressing by public key is dead simple: no allocation
step, no reservation round trip, no state to negotiate — a device can begin sending to a peer
that has not yet connected, and the relay holds the frame briefly. It gives relay-assisted
rendezvous for free (the relay is already a mailbox), which `docs/reliability.md` §2.1 wants as
a bootstrap fallback. Operationally it is one process, one port, one TLS certificate.

**B — TURN.** It is a real IETF standard with multiple independent, audited implementations
(coturn, eturnal, Pion) that could be deployed today with no bespoke server code at all.
`ChannelData` messages are a genuinely efficient 4-byte framing. TURN-over-TLS/TCP on 443 is
specified, deployed, and understood by every network operator. RFC 8656 §11 already defines
per-allocation lifetime, permissions, and quota semantics, so the abuse-control surface is
pre-analysed. Dual-stack allocation (RFC 8656 §7.2, `ADDITIONAL-ADDRESS-FAMILY`) is specified.
Interop means the relay tier could be outsourced to a commodity provider.

**C — Bespoke `pair_tag` forwarder.** The relay's admission input is a self-contained signed
token, so admission is a pure function of `(token, relay's static config)` — no lookup, no
database, no control-plane dependency, which is the only shape that satisfies RQ2 cleanly. The
half-flow table is keyed by a value derived from the peers' own pairwise secret, so the relay
can join two flows without ever being told who either peer is; identity is replaced by a
rotating pseudonym scoped to one operator and one time bucket. One authenticated leg per
(device, relay) multiplexing N half-flows makes the marginal cost of a warm standby one
keepalive per relay rather than one per peer, which is exactly what RQ4 and C5 need. Because
the framing is ours, the header can be 16 bytes and the MTU accounting is exact.

**D — Terminating proxy.** Best possible throughput shaping: the relay sees packet boundaries
and can do real congestion control, retransmission, and FEC on each leg independently, which is
strictly better on a lossy long-haul path. It can enforce policy on content. It simplifies MTU:
each leg is independently discovered. It is the standard architecture for media relays for
exactly these reasons.

**E — Double-encapsulated peer-relay.** Reuses ADR-0001 wholesale: zero new protocol, zero new
server code, zero new cryptographic surface, and the relay is literally another build of the
client, so the router-class and self-hosted stories are free (C6, RQ13). A self-hosted relay
becomes "add a device and turn on a switch". It reuses ADR-0007's pairing for admission, so
there is no token to design at all.

## 6. Disadvantages of Each Alternative

**A — DERP-style.** Addressing by peer public key hands the relay the **identity graph**: it
learns, in the clear, that device key *X* talks to device key *Y*, across time and across
regions, and that mapping is stable for the life of the identity. That is the single largest
avoidable metadata disclosure in the design and it directly weakens RQ11 and protocol A11. The
mailbox semantics require the relay to buffer for a not-yet-connected peer, which is durable-ish
state and an abuse amplifier. HTTPS-primary carriage pays TLS-over-TCP head-of-line blocking and
TCP-over-TCP interaction on the common path rather than the exceptional one.

**B — TURN.** TURN's `ChannelBind` requires the client to name the **peer's transport address**,
so the relay learns both peers' underlay addresses *and* the explicit permission pairing —
comparable disclosure to A, plus an allocation that is a named, addressable resource. Its
long-term credential mechanism (RFC 8489 §9.2) is a username/password shared secret, which
collides head-on with **I4** ("no passwords, no shared secrets") and requires either a
control-plane call per allocation or a derived static secret that is effectively a bearer
password. RFC 8656 gives no offline-verifiable capability form, so RQ2 would need a
non-standard extension — at which point the interop advantage evaporates. TURN allocates a
**relayed transport address reachable by anyone**, which is an open reflector and a genuine
amplification surface unless permissions are perfect; that is the wrong default for RQ8. TURN
has no drain protocol, no warm-standby concept, and no in-band overload signal (RQ9).

**C — Bespoke forwarder.** We own every corner case and every CVE. There is no third-party
implementation to fall back on and no commodity provider to outsource the tier to. The
`pair_tag` rendezvous adds a derivation both peers must agree on offline, and a clock-bucket
skew window to get wrong. Four carriages is four code paths to test (testing-strategy §2.10
grows). A bespoke server is a bespoke attack surface, and unlike A and B it has not been
adversarially reviewed by anyone outside this project.

**D — Terminating proxy.** **It violates I1 outright and is rejected on that ground alone.** To
re-originate, the relay must hold keys that decrypt user plaintext; every packet of every
`RELAYED` session is available to relay operators, relay hosts, and anyone who compromises
them. It converts a compromised relay from "an on-path attacker who sees ciphertext" into "a
full passive and active adversary". It also destroys testing-strategy **P14** — there is no
structural argument to make — and contradicts architecture §2.11's non-responsibilities and
ADR-0001 §11.1's "never terminated by any infrastructure component". Additionally it forces
`Session` teardown on relay failover (the crypto state is *in* the relay), breaking RQ5, R-05,
and R-10, and its per-connection CPU cost is orders of magnitude above forwarding.

**E — Double-encapsulated peer-relay.** Overhead is doubled: two WireGuard headers plus tags is
64 B before IP/UDP, versus 16 B, and on IPv6 that drops the effective overlay MTU below 1360 for
no benefit (C7 pressure, R-15 cost). Admission would run through `Pairing`, meaning every device
must pair with every relay — an n×m trust explosion that contradicts I4's intent and ADR-0007's
out-of-band ceremony. The relay becomes a `TrustedPeer`, i.e. **inside** trust boundary B2,
which is precisely the categorisation architecture §8 forbids for relays. Abuse control would
have to happen on decrypted overlay packets or not at all, contradicting C5 of ADR-0001. There
is no natural warm-standby or drain mechanism.

## 7. Security Implications

**7.1 The structural argument for P14.** "Relay infrastructure cannot decrypt tunnel payloads"
is made structural by enumerating the relay's *entire* key inventory, which is a closed set of
three items:

| Key held by a relay | Origin | Relationship to the L-DATA key schedule |
|---|---|---|
| Relay static X25519 key `RS` | generated on the relay, published in the signed relay map | **not an input**; the relay is not a party to L-DATA's `Noise_IKpsk2` |
| Issuer public key set | shipped/rotated as signed config | verification-only, public |
| Per-leg key `K_leg` | Noise_IK transport key with a device's `RLK` | domain-separated from L-DATA; used only for the 64-bit frame MAC |

The relay is not a party to L-DATA's handshake, holds no L-DATA static, no ephemeral, and no
`TwinNetPSK`. `pair_tag` is an HKDF output over the peer-pair secret and is therefore one-way.
Therefore any relay decryption capability would require an L-DATA key it structurally cannot
obtain. **P14's oracle becomes an enumeration over a three-element key inventory rather than a
statistical observation over traffic**: dump the relay's complete key material at any instant,
feed the union to the reference L-DATA decryptor, and assert that no captured frame decrypts.
This requires ADR-0001 to hold the interfaces in §11.2 (domain separation of `RLK` and the
`RelayPairSecret` exporter); with them, testing-strategy A-05 is satisfied and P14 is a
structural test.

**7.2 What a relay unavoidably sees — stated honestly (feeds `docs/threat-model.md`).**

| Observable | Why forwarding requires it | Mitigation / residual |
|---|---|---|
| Both peers' underlay IP:port | it must send frames somewhere | none possible; identical to any on-path observer |
| That pseudonym `relay_sub(A)` and `relay_sub(B)` are peers | it must join two half-flows and account quota to a subject | pseudonym is per-operator-group and per-day; **within one operator and one day the relay CAN link all of a device's flows** |
| `pair_tag` | it is the join key | 16 B HKDF output, scoped to one `relay_id` and one 10-minute bucket; useless at another relay or another bucket |
| Frame counts, byte counts, sizes, timing | it forwards and meters | none; ADR-0001 K5 already declines traffic-analysis resistance |
| Token claims: `aud`, `exp`, `epoch`, quota class | admission and metering | `sub` is the pseudonym, never `device_id`; `iss` reveals the TwinNet's issuer, not its membership |
| **Not** seen | `device_id`, TwinNet membership, overlay addresses, DNS, routes, plaintext, peer identity keys | by construction |

Anonymous-credential schemes (blind signatures, BBS+) would remove even the per-operator
pseudonym while preserving quota enforcement. **Rejected under I2/C1**: they are not
commodity-audited in the languages and platforms we ship, and the residual disclosure they
remove is a per-operator per-day linkage, not an identity.

**7.3 Confirming protocol.md A11, with a sharpening.** A11 ("relays authenticate a capability
token and forward opaque frames without learning the peer pair beyond what forwarding requires")
is **CONFIRMED**. The sharpening: forwarding structurally requires joining two half-flows, so the
relay learns a *pseudonymous* pair. It does not learn an *identity* pair. `docs/threat-model.md`
must record 7.2 verbatim.

**7.4 Overruling one field of protocol.md §11.1.** `ReserveRelayReq{session_nonce, peer_key_id,
capability_token}` carries `peer_key_id`, which would hand the relay the peer's identity key and
**contradicts A11 and the Authorization row of §11.1's own table**. `peer_key_id` is
**OVERRULED and replaced by `pair_tag`**; `docs/protocol.md` §11.1 must change. `ReserveRelayResp
.relay_binding_id` maps to `flow_id` in §11.1 of this ADR.

**7.5 A compromised relay.** It can drop (indistinguishable from loss → `PATH_FAILING` →
`MIGRATING`), delay, reorder, or replay (L-DATA's replay window rejects), or forge frames (L-DATA
AEAD rejects). It **cannot** redirect a session: per protocol §11.2 only the peers act on a
`PathOffer`, and `DRAIN` is advisory. It cannot impersonate another relay (relay statics are in
the Owner-signed relay map). It can deny service, which is why R-11 requires ≥2 alternates.

**7.6 Token theft.** The `RelayCapabilityToken` is proof-of-possession bound (RFC 7800 `cnf`) to
a per-device relay-leg key `RLK`; a stolen token without `RLK` is inert. `RLK` is a distinct
key from `DeviceIdentityKey` and from the L-DATA static, so relay-leg compromise does not reach
device identity (I4 is untouched: `RLK` is device-generated and non-exported).

## 8. Reliability Implications

- **Relay restart** kills every in-flight half-flow and persists nothing (RQ10). Both peers see
  frame loss, `PATH_FAILING` fires (networking §4.3), and the `Session` takes
  `RELAYED → MIGRATING → RELAYED` onto the pre-bound warm standby — the transition
  testing-strategy A-01 and architecture §6.4 already assert. `Session`, `Tunnel`, keys, counters,
  and overlay addresses are untouched (ADR-0001 C3). Target cutover with a standby: **one RTT
  plus path validation**, because the standby leg and half-flow are already established.
- **Graceful drain.** On planned shutdown the relay emits `DRAIN{drain_deadline_ms,
  suggested_alternatives[]}` on every bound flow (default deadline 120 s), which is exactly
  reliability.md's `EV_RELAY_DRAINING` and transition **T37**; devices move at a time drawn
  uniformly from `[0, deadline − 60 s]`. Herd safety comes from the relay honouring the deadline
  it announced, not from client heuristics.
- **No standby bound** ⇒ `RELAY.STANDBY_UNAVAILABLE` is emitted as an **informational**-class
  informational at bind time, so the weaker failover posture is visible *before* the failure,
  not discovered during it (I6).
- **Head-of-line blocking on `R-TLS`.** TCP carriage risks TCP-over-TCP meltdown. The relay
  therefore bounds each half-flow's `R-TLS` send queue to `min(64 KiB, 250 ms × flow rate)` and
  **tail-drops** on overflow rather than letting the kernel buffer without limit. This converts
  TCP's unbounded latency growth into datagram-shaped loss, which the inner protocol already
  handles correctly. `R-TLS` is last in the carriage ladder for this reason.
- **Failure-domain independence (testing-strategy A-18).** A `Relay` MUST NOT share a failure
  domain, host, or IP address with a rendezvous, presence, or control-plane instance. This makes
  A-18 structural rather than operational. Relay-assisted rendezvous (reliability §2.1) does not
  violate it: it is a *fallback path through* an already-bound relay flow, not co-deployment.

## 9. Performance Implications

**9.1 Wire format.** One `RelayFrame` header is prepended to the L-DATA datagram, identical
across all four carriages:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+-------+-------+-------------------------------+
|     type      |  ver  | flags |      counter_low (16 bit)     |   4 B
+---------------+-------+-------+-------------------------------+
|                       flow_id (32 bit)                        |   4 B
+---------------------------------------------------------------+
|                    auth_tag (64 bit, truncated)               |   8 B
+---------------------------------------------------------------+
                            = 16 B, then the opaque L-DATA datagram
```

- `type` `0x01` = `DATA`; `0x10..0x1F` = control (`BIND`, `BOUND`, `PING`, `PONG`, `DRAIN`,
  `RELAY_STATUS`, `CAPS`, `REBIND`).
- `counter_low` is the low 16 bits of a 64-bit per-half-flow counter, reconstructed by the
  receiver with a sliding window exactly as **RFC 9147 (DTLS 1.3) §4.2.2** specifies. No new
  construction (C1).
- `auth_tag` is a keyed BLAKE2s MAC under `K_leg` over `(type‖ver‖flags‖counter_full‖flow_id‖
  payload)`, truncated to 64 bits. It protects the relay's own session table from off-path
  injection; it is not a confidentiality mechanism, because the payload is already L-DATA-sealed.
  Online forgery is bounded by the per-flow bind and rate limits in §11.5.
- Reserved bits MUST be zero on send and ignored on receive (ADR-0014 forward compatibility).

**9.2 Exact per-carriage overhead and effective MTU** (L-DATA = 32 B per ADR-0001 §9; underlay
1500 B; overlay MTU = 1500 − underlay headers − 16 (RelayFrame) − 32 (L-DATA)):

| Carriage | Underlay framing below RelayFrame | Family | Bytes below L-DATA | Overlay MTU @1500 |
|---|---|---|---|---|
| `R-UDP` | IP + UDP | v4 | 20+8+16 = **44** | **1424** |
| `R-UDP` | IP + UDP | v6 | 40+8+16 = **64** | **1404** |
| `R-QUIC` | IP + UDP + QUIC short hdr (11) + DATAGRAM type (1) + AEAD tag (16) | v4 | 20+8+28+16 = **72** | **1396** |
| `R-QUIC` | as above | v6 | 40+8+28+16 = **92** | **1376** |
| `R-TLS` | IP + TCP(20, no opts) + TLS rec hdr (5) + inner type (1) + AEAD tag (16) + 2 B length | v4 | 20+20+24+16 = **80** | **1388** |
| `R-TLS` | as above | v6 | 40+20+24+16 = **100** | **1368** |
| `R-TLS` + TCP timestamps | add 12 B of TCP options | either | +12 | −12 |
| any, over 464XLAT / PPPoE | underlay MTU 1480 / 1492 | either | — | correspondingly lower |

These are **ceilings**. The operative MTU is whatever DPLPMTUD (networking §6.2) confirms, and
the 1280 floor always holds — every row above clears 1280 with ≥ 88 B of margin, satisfying C7.
A carriage that cannot carry a 1280-byte overlay packet MUST be abandoned with
`RELAY.MTU_FLOOR_VIOLATED`.

**9.3 Relative to networking.md A2.** A2 assumed "≤ 32 B of added header". `R-UDP` adds **16 B**,
better than assumed. The other three carriages exceed 32 B of *total* added framing because TLS
and QUIC record overhead is unavoidable. **networking.md §6.1's overhead table must gain the four
`R-QUIC`/`R-TLS` rows above.** See §13.

**9.4 Latency.** A relayed path costs one extra network leg. The relay adds no queuing beyond
its DRR scheduler (§11.5) and performs no reassembly, no decryption, and no retransmission, so
its own contribution is a forwarding-table lookup plus a MAC verification — sub-100 µs on
commodity hardware. Latency is dominated by geography, which is `ADR-0006`'s ranking problem
(R-12), and by whether an upgrade to direct is available, which is networking §4.4's.

**9.5 Cost of a warm standby.** A standby half-flow carries only a 4-byte `PING`/`PONG` at the
coalesced keepalive cadence (default 60 s, reliability §6.6). Because the *leg* is shared across
all half-flows to that relay, adding a standby costs one keepalive pair per **relay**, not per
peer: ≈ 60 B/min ≈ 86 KB/day, and **zero additional radio wakes** because it lands in the existing
wake window. Architecture A-11's "without doubling data cost" is confirmed by roughly four orders
of magnitude.

## 10. Operational Implications

- **Stateful in memory, durable in nothing.** A relay persists only: its static Noise key, its
  TLS material, the issuer public-key set, and the current `epoch_floor` (which is re-obtainable
  from any connecting client, so even that is not strictly durable). No flow, peer, pair, or
  token record is ever written to disk (RQ10). Logs carry aggregated counters keyed by a
  *daily re-hash* of `relay_sub`, so operational logs cannot link a device across days;
  retention ≤ 7 days, classified per ADR-0015 §11.4.
- **Horizontal scaling.** A half-flow is bound to a 5-tuple and a Noise leg and therefore
  **cannot** migrate between processes. Both peers must reach the *same* instance, and the join
  key (`pair_tag`) is invisible to an L4 load balancer. Therefore: **relay endpoints published in
  the relay map are per-instance and individually addressable; a `Relay` MUST NOT be a
  load-balanced VIP hiding N instances.** Anycast MAY be used for bootstrap/discovery only
  (reliability §2.1's "anycast bootstrap"), never for a bound flow. Scale by adding independent
  relays and letting ADR-0006's selection spread load — there is no shared state, no session
  replication, and no cross-instance consistency requirement anywhere in the fleet.
  - *Optional deployment pattern:* a cluster MAY consistent-hash `pair_tag` to an owning instance
    and forward the `BIND` internally. This MUST NOT cross a failure domain, or A-18's
    independence claim breaks.
- **Capacity planning.** Per-flow memory is a fixed control block (5-tuple, `flow_id`, counters,
  token bucket, DRR deficit) — a few hundred bytes. A relay's binding constraint is bandwidth and
  packet rate, not memory or CPU, which is what makes the cost model in ADR-0004 §12.7 hold.
- **Self-hosted relays (RQ13).** An `Owner` registers a self-hosted `Relay` into their `TwinNet`'s
  Owner-signed relay map with its static Noise public key and dual-family literal endpoints. Its
  `aud` is a TwinNet-scoped operator group, so it can only ever admit that TwinNet's tokens —
  cross-TwinNet abuse is structurally impossible. **Its trust level is identical to a hosted
  relay: untrusted (B3), I1 unchanged.** Self-hosting buys metadata locality (the pseudonymous
  pair graph and byte counts stay on the owner's hardware) and jurisdictional control — **not**
  confidentiality, which the tunnel already provides against both. A self-hosted relay MUST
  implement `DRAIN` and `CAPS`; if it does not, ADR-0006 SHOULD rank it below hosted relays. A
  relay set consisting solely of one self-hosted relay is a single point of failure and MUST be
  surfaced as `RELAY.SELF_HOSTED_NO_ALTERNATE` (R-11), never silently accepted.
- **Version skew** is handled by the `ver` nibble plus a `CAPS` control frame exchanged at leg
  setup; an unsupported version yields `RELAY.VERSION_UNSUPPORTED` within ADR-0014's window.

## 11. Decision

**Adopt Alternative C — a bespoke frame forwarder with a capability-token-admitted,
`pair_tag`-addressed half-flow table over four carriages — taking A's carriage ladder and
operational shape, and taking B's allocation-lifetime and quota discipline. D is rejected on I1.
E is rejected on overhead and trust-boundary grounds.**

### 11.1 Forwarding model and rendezvous (normative)

1. A device MUST maintain **at most one authenticated leg per (`Device`, `Relay`)**, multiplexing
   N half-flows by `flow_id`. Keepalives for the leg MUST coalesce with all other keepalives (C5).
2. The leg is **Noise_IK** (X25519 / ChaCha20-Poly1305 / BLAKE2s — the identical primitive set
   ADR-0001 already ships, so no new dependency, C1/C6) for `R-UDP`; for `R-QUIC` and `R-TLS` the
   outer TLS 1.3 handshake serves, with the device authenticating by `RLK` as an RFC 7250 raw
   public key and `K_leg` taken from an RFC 8446 exporter with label `"twinvpn relay leg v1"`.
3. Two peers rendezvous by a **blinded pairing tag**, derivable offline by both with **zero
   coordination** — this is what makes relay reconnect work with the control plane, rendezvous,
   and presence all down (architecture §4.4.5(d)):

   ```
   RelayPairSeed   = X25519(my_LDATA_static_priv, peer_LDATA_static_pub)   # no round trip
   RelayPairKey = HKDF-Extract(salt = "twinvpn/relay-pair/v1", ikm = RelayPairSeed)
   bucket       = floor(unix_seconds / 600)                             # 10-minute bucket
   pair_tag     = HKDF-Expand(RelayPairKey, "tag" ‖ relay_id ‖ bucket, 16)
   ```

   Both peers MUST accept `bucket`, `bucket−1`, and `bucket+1` for skew. `pair_tag` is scoped to
   one `relay_id`, so a tag observed at one relay is useless at another, and it rotates every
   10 minutes, so it cannot be used for long-term linkage.
4. The relay's table is keyed by `pair_tag`. The first `BIND` creates a **pending slot**
   (lifetime 30 s, then `RELAY.PAIR_UNMATCHED`); the second `BIND` on the same tag **binds** it
   and both peers receive `BOUND{flow_id}`. A third `BIND` on a bound tag is refused with
   `RELAY.PAIR_COLLISION`; a squatter cannot in any case produce valid L-DATA traffic.
5. The relay MUST forward each authenticated `DATA` frame to exactly the peer half-flow, byte for
   byte, without inspecting, buffering beyond its bounded queue, retransmitting, or padding.
   `flow_id` and `counter_low` are rewritten for the outgoing half-flow; nothing else is touched.
6. The two half-flows of one `pair_tag` **MAY use different address families and different
   carriages**. A relay is therefore the v4↔v6 bridge for a peer pair with no common family
   (RQ6, P9).

### 11.2 Interfaces required from other ADRs

| From | Required interface |
|---|---|
| [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) | (a) `RLK` is a distinct, domain-separated relay-leg key that MUST NOT be derivable from, or used to derive, any L-DATA key; (b) no relay-supplied value is an input to the L-DATA key schedule; (c) confirmation that `T-RELAY` is transport-agnostic and admits the four carriages here; (d) the static-static `PairSecret` of §11.1(3) is available offline from `TrustedPeer` state. |
| [ADR-0006](ADR-0006-relay-discovery-and-failover.md) | (a) a signed, cacheable relay map giving per `Relay`: `relay_id`, `operator_group_id`, static Noise public key, **literal** `endpoints_v4[]` **and** `endpoints_v6[]`, supported carriages, `RelayRegion`, **failure-domain label**, map version, TTL; (b) ≥2 alternates per region across ≥2 failure domains; (c) which relay to bind and which single different-failure-domain relay to hold as standby; (d) failover trigger, health aggregation, ranking, and where within `[0, deadline − 60 s]` to act on a `DRAIN`; (e) semantics of relay-assisted rendezvous over the in-band signalling frame this ADR provides. |
| [ADR-0007](ADR-0007-device-identity-and-pairing.md) | The relay-credential issuer is Owner-rooted and verifiable offline (architecture A-04); `RLK` proof-of-possession is performed at token issuance over L-CONTROL. |
| [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) | `Capability` names `relay_udp`, `relay_quic`, `relay_tls`, `relay_standby` so a mixed-version `TwinNet` degrades explicitly. |
| [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) | A relay flow is a secure path; **exhaustion of all relays with the kill switch engaged is `BLOCKED`, never plaintext egress** (I3). |
| [ADR-0015](ADR-0015-observability-and-diagnostics.md) | Registration of the `RELAY.*` codes in §11.7 into the machine-readable registry. |

### 11.3 The `RelayCapabilityToken` (RCT)

A COSE_Sign1 (RFC 9052) / CBOR object, Ed25519-signed by the TwinNet's relay-credential issuer.
Chosen over JWT for size and over a bespoke format for C1.

| Claim | Value |
|---|---|
| `iss` | issuer key id; the relay holds the issuer public-key set as signed config |
| `aud` | **operator group id, never a single `relay_id`** — one token works across the whole ranked set, which is what makes ADR-0006's offline failover possible |
| `sub` | `relay_sub = HKDF-Expand(HKDF-Extract("", DeviceIdentityPub), "twinvpn/relay-sub/v1" ‖ operator_group_id ‖ epoch_day, 16)` — a per-operator, per-day pseudonym; **never `device_id`** |
| `cnf` | RFC 7800 confirmation claim carrying `RLK_pub`; binds the token to a key the bearer must possess |
| `nbf` / `exp` | lifetime **24 h**, refreshed at 50 % (12 h) |
| `epoch` | the S-03 trust epoch at issuance |
| `quota` | `{max_concurrent_flows, max_bitrate_kbps, max_bytes_per_hour, max_binds_per_min}` |
| `jti` | 16 B random, for the relay's bounded replay cache |

**Verification is a pure function**, performed entirely offline by the relay: COSE signature
against a held issuer key → `aud` matches this operator group → `cnf` equals the presented
relay-leg static → `nbf`/`exp` within skew → `epoch ≥ epoch_floor` → `jti` unseen. **No
control-plane call, per packet, per bind, or per reconnect (RQ2, architecture A-12).**

**Clock skew.** The relay accepts `nbf − 300 s ≤ now ≤ exp + 300 s`. On `RELAY.TOKEN_EXPIRED`
the relay includes its own current time; the device computes an offset, retries **once**, and on
a second failure emits `RELAY.CLOCK_SKEW_EXCESSIVE`. A device MUST NOT set its system clock from
a relay; the offset is held for token-validity evaluation only.

**Revocation and S-03.** The relay holds an Owner-signed, monotone `RelayEpochFloor` document.
It is pushed by the control plane best-effort **and may be piggybacked by any connecting client**
— because it is Owner-signed and monotone, a relay partitioned from the control plane still
learns of revocations from its own users. A token with `epoch < epoch_floor` is refused with
`RELAY.TOKEN_EPOCH_STALE`. **Crucially, relay denial is defence in depth only**: revocation is
enforced at the peer (architecture §4.5, A-03), so a lagging relay leaks no access and no
confidentiality — the revoked device still cannot complete a peer handshake. The relay's
revocation lag is therefore a bounded **resource-abuse** window, capped absolutely at the 24 h
token lifetime and typically minutes.

**Renewal MUST NOT require the control plane** ([ADR-0009](ADR-0009-state-consistency.md) K-6,
architecture.md A-12, **I5**). An earlier draft of this section accepted a 30-hour cliff after
which a control-plane-partitioned device lost relay admission entirely; that is **withdrawn**. It
made the control plane a bounded liveness dependency of the data plane for every relayed pair, and
it breached architecture.md §2.8's stated non-responsibility that the control plane "MUST NOT be
required for a device to re-establish a `Session` with an already-known `TrustedPeer`".

**Relay-issued renewal (normative).** A `Relay` MUST renew a `RelayCapabilityToken` itself, with no
control-plane involvement, when **all** of:

1. the presented token verifies under a known issuer key and has `epoch` **equal to** the relay's
   current `epoch_floor` — epoch equality is the proof that no revocation intervened;
2. the presented token is within `exp + T_RELAY_GRACE` (`= 6 h`);
3. the device demonstrates possession of the bound `RLK` on the live leg.

The renewed token carries the same `sub` and `epoch`, a fresh `exp`, and is marked
`renewed_by_relay`. It is **not** a new grant: a relay can only extend an authority the control
plane already issued, at an epoch the control plane already published, and never above its own
`epoch_floor`.

**Why this is still safe.** Revocation remains enforced, because `epoch_floor` advances are
distributed to relays by the control plane (`RelayEpochFloor`, S-30) and a token below the floor is
refused at rule 1 — so a *reachable* control plane closes admission normally, and an *unreachable*
one cannot silently expand authority either, since the floor cannot advance without it. The
residual is the standard one already accepted in §11.5 of
[ADR-0009](ADR-0009-state-consistency.md): during a control-plane partition a revoked device
retains relay admission until the partition heals. That is bounded by the same grant/deny
asymmetry, not by a credential cliff, and it is the same residual that governs trust state — one
rule, not two. Direct paths are unaffected throughout.

### 11.4 Carriage ladder and parallelism

All carriages are **raced with a staggered start, never tried sequentially after a timeout**:

| t | Carriage | Port | Purpose |
|---|---|---|---|
| 0 ms | `R-UDP` | UDP/41641 and UDP/443, v6 first (RFC 8305, v4 delayed by `T_HE_BIAS` = 250 ms, `docs/reliability.md` §5.1) | primary |
| +250 ms | `R-QUIC` | UDP/443, QUIC DATAGRAM (RFC 9221) | UDP-restricted-to-443, DPI-hostile |
| +750 ms | `R-TLS` | **TCP/443**, TLS 1.3, 2-byte length-prefixed frames; HTTP `CONNECT` via system proxy when one is configured | UDP fully blocked (networking §3.7 `NAT.UDP_BLOCKED`, `NET.PROXY_REQUIRED`), R-18 |

First carriage to reach `BOUND` wins; others are cancelled at 2 s (matching protocol §11.1's 2 s
reservation budget). If no carriage completes: `RELAY.TRANSPORT_UNAVAILABLE`.

**Relay binding starts at t=0, concurrently with candidate gathering and direct probing**, per
networking §3.3 rule 1 and ADR-0004 §11 — never after a direct-path timeout. Because the leg is
shared per relay, the marginal cost of the *n*-th peer's relay candidate is one `BIND` frame.

### 11.5 Resource control and amplification

**Amplification factor is exactly 1.0 by construction:** the relay emits at most one frame per
received frame, of equal payload length; it never fans out, retransmits, or pads; and it emits
**zero bytes** in response to any unauthenticated or unbound frame. The only unsolicited frames
it originates are `DRAIN` and `RELAY_STATUS`, both onto already-bound, authenticated flows.
Handshake amplification is ≤ 1 (Noise_IK msg2 ≤ msg1), and the relay performs **no asymmetric
operation for an unvalidated source address**: above 20 handshakes/s from a source /24 (v4) or
/48 (v6) it issues a stateless cookie challenge first (the WireGuard MAC2 / QUIC Retry pattern).

| Limit | Default | Enforcement | Code |
|---|---|---|---|
| concurrent half-flows per `relay_sub` | 64 | `BIND` refused | `RELAY.FLOW_LIMIT_REACHED` |
| bitrate per `relay_sub` | 20 Mbit/s, 2 s burst | token bucket, **throttle not drop** | `RELAY.RATE_LIMITED` |
| bitrate per half-flow | 10 Mbit/s | token bucket | `RELAY.RATE_LIMITED` |
| bytes/hour per `relay_sub` | 20 GiB | leaky counter | `RELAY.QUOTA_EXCEEDED` |
| `BIND`/min per `relay_sub` | 30 | token bucket | `RELAY.BIND_RATE_LIMITED` |
| handshakes/s per source /24 or /48 | 20 before cookie | stateless cookie | (pre-auth; silent) |
| pending (unmatched) slot | 30 s | slot GC | `RELAY.PAIR_UNMATCHED` |
| idle bound half-flow | 15 min | flow GC | `RELAY.FLOW_IDLE_TIMEOUT` |

Quota values are carried *in the token*, so a relay enforces the issuer's policy without a
lookup. **Scheduling is two-tier deficit round robin**: outer DRR across `relay_sub`, inner DRR
across that subject's half-flows, so one device holding 64 flows cannot starve a device holding
one (I7). Per-flow queue is bounded at `min(64 KiB, 250 ms × flow rate)` with tail-drop.

**Overload is never silent (I6, RQ9).** Whenever the relay throttles, sheds, or drains, it MUST
emit `RELAY_STATUS{reason_code, retry_after_ms, suggested_alternatives[]}` on the affected flow.
A relay that drops without a status frame is a defect. The device surfaces the code as a
informational `Diagnostic`, never as unexplained loss. It is **not** a `DEGRADED` entry:
`docs/reliability.md` R6 reserves `DEGRADED` for measured quality violations, and its state
machine has no "`DEGRADED` guard".

### 11.6 Guards contributed to `docs/reliability.md` (no new states, no new transitions)

| Guard | Value |
|---|---|
| `RELAY_LEG_UP` | Noise/TLS leg established and `K_leg` derived |
| `RELAY_FLOW_BOUND` | `BOUND{flow_id}` received; the flow is a usable `RELAYED` `Path` candidate |
| `RELAY_STANDBY_READY` | a second `Relay` in a **different failure domain** has a `BOUND` half-flow for this `Session` |
| `RELAY_FLOW_FAILING` | 3 consecutive missed `PING`/`PONG` on the leg, or a `DATA` send error, or `DRAIN` deadline reached |
| `RELAY_ADMISSION_DENIED` | any `RELAY.TOKEN_*` or `RELAY.ISSUER_UNKNOWN` outcome |

### 11.7 Reason codes contributed to the `RELAY` namespace (ADR-0015 §11.2)

Selection/health codes (`RELAY.NONE_REACHABLE`, `RELAY.REGION_UNAVAILABLE`,
`RELAY.CAPACITY_REJECTED`, `RELAY.FAILOVER_EXHAUSTED`) remain ADR-0006's. These are the
data-plane codes, contributed to the machine-readable registry with the full attribute set of
ADR-0015 §11.2:

| Code | class | terminal | user_actionable |
|---|---|---|---|
| `RELAY.TOKEN_MISSING` | PERSISTENT | false | false |
| `RELAY.TOKEN_INVALID` | PERSISTENT | false | false |
| `RELAY.TOKEN_EXPIRED` | TRANSIENT | false | false |
| `RELAY.TOKEN_NOT_YET_VALID` | TRANSIENT | false | false |
| `RELAY.TOKEN_AUDIENCE_MISMATCH` | PERSISTENT | false | false |
| `RELAY.TOKEN_EPOCH_STALE` | POLICY | true | true |
| `RELAY.TOKEN_POP_FAILED` | PERSISTENT | false | false |
| `RELAY.TOKEN_REPLAYED` | TRANSIENT | false | false |
| `RELAY.ISSUER_UNKNOWN` | PERSISTENT | true | true |
| `RELAY.CLOCK_SKEW_EXCESSIVE` | PERSISTENT | false | **true** (fix device clock) |
| `RELAY.PAIR_UNMATCHED` | TRANSIENT | false | false |
| `RELAY.PAIR_COLLISION` | TRANSIENT | false | false |
| `RELAY.FLOW_LIMIT_REACHED` | POLICY | false | true |
| `RELAY.BIND_RATE_LIMITED` | TRANSIENT | false | false |
| `RELAY.RATE_LIMITED` | TRANSIENT | false | true |
| `RELAY.QUOTA_EXCEEDED` | POLICY | false | true |
| `RELAY.FLOW_IDLE_TIMEOUT` | TRANSIENT | false | false |
| `RELAY.DRAINING` | TRANSIENT | false | false |
| `RELAY.RESTARTED` | TRANSIENT | false | false |
| `RELAY.OVERLOADED` | TRANSIENT | false | false |
| `RELAY.VERSION_UNSUPPORTED` | PERSISTENT | true | true |
| `RELAY.TRANSPORT_UNAVAILABLE` | PERSISTENT | false | true |
| `RELAY.MTU_FLOOR_VIOLATED` | PERSISTENT | false | false |
| `RELAY.DUAL_STACK_REQUIRED` | POLICY | true | true (registration-time) |
| `RELAY.SELF_HOSTED_NO_ALTERNATE` | POLICY | false | true |
| `RELAY.STANDBY_UNAVAILABLE` | TRANSIENT | false | false |

### 11.8 New state-ownership rows required in `docs/architecture.md` §5

| # | State | Authoritative writer | Replicas | Class | Durability | On conflict |
|---|---|---|---|---|---|---|
| **S-29** | `Relay` half-flow + pending-slot table | **the `Relay` instance**, in memory | **None — MUST NOT be persisted or replicated** | `LOCAL` | **Non-durable by requirement** | Impossible (single writer); loss ⇒ flow death ⇒ `MIGRATING` |
| **S-30** | `RelayCapabilityToken` issuance record | **Control Plane (2.8)**, relay-credential issuer | the `Device` holds its own token **durably** (this is what enables control-plane-free relay reconnect) | `MONOTONIC` (`epoch` non-decreasing) | Durable both sides | Higher `epoch` wins; a token whose `epoch` is below the device's known floor MUST NOT be used |

**S-03 amendment (no new writer, I8 preserved):** S-03's replica column must name the signed,
monotone `RelayEpochFloor` document as the relay-side cache of the trust epoch.

### 11.9 Disposition of every assumption directed at this ADR

| Assumption | Source | Disposition |
|---|---|---|
| **A-10** — "Relay flows are opened **in parallel** with direct-path racing, not sequentially after direct-path timeout" | architecture.md §9 | **CONFIRMED.** §11.4: relay binding starts at t=0 alongside candidate gathering; the carriage ladder itself is staggered-parallel, not sequential. Because the leg is shared per relay, the marginal cost of the n-th peer is one `BIND` frame, so parallelism is affordable at `TwinNet` scale. The R-02 latency claim stands. |
| **A-11** — "A device can hold a **warm standby** relay flow on a second `Relay` without doubling data cost" | architecture.md §9 | **CONFIRMED, with mechanism and numbers.** §11.1(1) (one leg per relay, N half-flows) + §9.5: a standby costs one coalesced `PING`/`PONG` pair per **relay** (≈ 86 KB/day, zero extra radio wakes), not per peer. "Without doubling" is met by ~4 orders of magnitude. Exactly one standby, in a different failure domain (§11.6 `RELAY_STANDBY_READY`); which relay is ADR-0006's choice. |
| **A-12** — "Relay admission does **not** require a live control-plane call per reconnect" | architecture.md §9 | **CONFIRMED, without a time bound.** §11.3: admission is offline verification of a COSE_Sign1 capability token — no call per packet, per bind, or per reconnect — and **renewal is issued by the relay itself** under epoch equality, so a control-plane partition of any duration does not cost relay admission ([ADR-0009](ADR-0009-state-consistency.md) K-6, **I5**). |
| **A11** — "Relays authenticate a capability token and forward opaque frames without learning the peer pair beyond what forwarding requires" | protocol.md §18 | **CONFIRMED, sharpened.** §7.3: the relay learns a *pseudonymous* pair, never an identity pair. §7.2 tabulates exactly what it does and does not see, for `docs/threat-model.md`. **One field of protocol.md §11.1 is OVERRULED**: `ReserveRelayReq.peer_key_id` would defeat A11 and is replaced by `pair_tag` (§7.4). |
| **A12** — "Relay failover can be driven peer-to-peer from cached relay candidates without the control plane" | protocol.md §18 | **CONFIRMED for the data-plane enablers this ADR owns** (the policy is ADR-0006's): the token's `aud` is an **operator group, not a `relay_id`**, so one cached token admits the whole ranked set; the standby half-flow is pre-`BOUND`; `pair_tag` is derivable offline with zero coordination; `PathOffer`/`PathAck` ride inside the existing encrypted `Session`. No control-plane call appears anywhere on that path. |
| **A2** — "The relay presents a **UDP-shaped** primary transport plus at least one TCP/443-shaped fallback, adds ≤ 32 B of header, and is available as a candidate from t=0" | networking.md §11 | **CONFIRMED in part, REFINED in part.** UDP-shaped primary (`R-UDP`): confirmed, and the header is **16 B**, better than the assumed ≤ 32 B. TCP/443-shaped fallback (`R-TLS`): confirmed, plus `R-QUIC`. Candidate from t=0: confirmed. **The "≤ 32 B" bound is overruled for `R-QUIC` and `R-TLS`**, whose total added framing is 72–100 B (§9.2). **`docs/networking.md` §6.1 has been updated accordingly** — it now carries all eight per-carriage rows from §9.2, the exact `R-UDP` overlay MTUs (1424 v4 / 1404 v6, replacing the earlier "≥ 1408 / ≥ 1388" estimates), and the 16 B `RelayFrame` figure in place of the assumed ≤ 32 B bound. |
| **A-13** — "Established tunnels require no control-plane call for keepalive, rekey, path migration, or relay use" | testing-strategy.md §0 | **CONFIRMED.** Relay *use* on a bound flow, relay *re-bind* from a cached token, `pair_tag` derivation, standby cutover, and drain response all execute with the control plane absent. Only token *refresh* touches the control plane, and it is off the established-session path (a background operation with a 12 h lead time against a 24 h + 6 h deadline). **P15** therefore tests the architecture, not an accident. |
| **A-18** — "Relays and rendezvous are separate roles with independent failure domains, and a peer holds a *set* of relay candidates, not one" | testing-strategy.md §0 | **CONFIRMED and strengthened into a structural rule.** §8: a `Relay` MUST NOT share a failure domain, host, or IP address with a rendezvous, presence, or control-plane instance. §11.2 requires ADR-0006's relay map to carry a **failure-domain label** and ≥2 alternates per region across ≥2 domains; §11.6's `RELAY_STANDBY_READY` requires the standby to be in a *different* domain. Relay-assisted rendezvous is a fallback path *through* a bound relay flow, not co-deployment, and does not weaken the separation. |

## 12. Why the Selected Option Won

1. **Only C satisfies RQ2 without a protocol extension.** Offline admission is the hinge of I5:
   a device reconnecting during a total control-plane outage must be admitted by a relay that
   also cannot reach the control plane. A self-contained signed capability with a proof-of-
   possession binding is the only shape that makes admission a pure function. TURN's long-term
   credential (B) is a shared secret and collides with I4; DERP (A) has no admission model of its
   own and in practice defers to a control-plane check.
2. **Only C avoids handing the relay the identity graph.** Both A and B require the client to
   name the peer — by public key (A) or by transport address in `ChannelBind` (B). C replaces
   that with a pairwise-derived, per-relay, per-10-minute tag. This is the difference between a
   relay operator holding a durable social graph of the fleet and holding an unlinkable
   pseudonymous join key, and it is the difference that makes protocol A11 true rather than
   aspirational.
3. **D is disqualified, not merely worse.** I1 is inviolable. Recording the rejection explicitly
   matters because "terminate and re-originate" is the default architecture for relays in the
   media world and will be proposed again; the answer is that it forfeits P14's structural
   argument, contradicts architecture §2.11 and ADR-0001 §11.1, and converts every relay operator
   and relay host into a full adversary.
4. **One leg per relay, N half-flows, is what makes A-11 and C5 hold simultaneously.** Under A's
   or B's per-peer allocation model, a warm standby for a 20-device `TwinNet` means 20 standby
   allocations and 20 keepalive streams. Under C it means one leg and one coalesced keepalive —
   four orders of magnitude cheaper, which is the difference between a standby we can hold by
   default and one we could not afford on mobile.
5. **Exact MTU accounting is only possible when we own the framing.** 16 bytes, and §9.2's table,
   is what lets networking.md §6.1 stop saying "≤ 32" and start stating numbers, which is what
   R-15 and DPLPMTUD's search bounds need.
6. **E's overhead is disqualifying and its trust categorisation is wrong.** 64 B of tunnel
   framing versus 16 B on the highest-cost path in the system, plus a relay that must become a
   `TrustedPeer` inside boundary B2, is the wrong answer to both C4 and architecture §8.
7. **A's carriage ladder is genuinely better than B's and is adopted.** DERP's insight that HTTPS
   carriage is the universal fallback is correct and is taken as `R-TLS`; what is rejected is its
   *addressing*, not its *transport strategy*.

## 13. Known Tradeoffs

| Tradeoff | Accepted because |
|---|---|
| A bespoke relay server: our CVEs, our corner cases, no commodity provider to outsource to | The two properties that matter most (offline admission, no identity graph) are unavailable in any standard. The forwarding logic itself is small and stateless. |
| Within one operator group and one day, the relay **can** link all of a device's flows | Quota enforcement needs a stable subject. Removing this needs anonymous credentials, which C1/I2 forbid. Bounded to one operator, one day, and documented in `docs/threat-model.md`. |
| The relay learns both peers' underlay addresses and the pseudonymous pair | Structurally required to forward. Identical to any on-path observer, which is the trust level B3 already assigns. |
| 64-bit truncated frame MAC rather than 128-bit | It guards only the relay's session table; payload integrity is L-DATA's. Online forgery is bounded by §11.5's rate limits, and a forged frame merely reaches a peer's AEAD and dies. Costs 8 B/packet to fix, on the highest-cost path. |
| Relay-issued renewal means a revoked device keeps relay admission for the duration of a control-plane partition | This is the **same** residual as trust state ([ADR-0009](ADR-0009-state-consistency.md) §11.5) rather than a second, different one, and it is bounded in consequence by the same grant/deny asymmetry. The alternative — a hard credential cliff — was withdrawn because it made the control plane a liveness dependency of the data plane (**I5**, **R-11**). |
| Relays cannot sit behind an L4 load balancer | Both peers must reach the same instance and the join key is invisible below L7. Bought back by making relays cheap, independent, and numerous. |
| Four carriages is four test paths | R-18 and networking §3.7 require the blocked-UDP answer to actually work; an untested fallback is not a fallback. |
| `pair_tag` bucketing introduces a clock dependency between peers | ±1 bucket (10 min) of tolerance, and both peers already need loosely-synced clocks for token validity. |
| A pending slot can be squatted by anyone who learns a `pair_tag` | The squatter cannot produce valid L-DATA; the cost is a 30 s slot and a `RELAY.PAIR_COLLISION`. |

## 14. Revisit Conditions

| # | Falsifiable trigger |
|---|---|
| V1 | **`R-TLS` exceeds 8 % of relayed connection-minutes** fleet-wide for two consecutive months. TCP carriage on the common path justifies a purpose-built stream mode (or revisits ADR-0001 V3's QUIC-native question) rather than a bounded-queue workaround. |
| V2 | Measured **`R-TLS` goodput on a reference lossy path (5 % loss, 80 ms RTT) falls below 50 %** of `R-UDP` goodput on the same path — the bounded-queue mitigation in §8 is insufficient and the carriage needs redesign. |
| V3 | **Relayed traffic exceeds 45 % of all connection-minutes** for a quarter. The cost model in ADR-0004 §12.7 assumed 10–40 %; above 45 % the economics change and per-`relay_sub` quotas (§11.5) must be re-derived, not merely re-tuned. |
| V4 | A **credible, audited, and shipping** anonymous-credential library exists for all five target platforms. The per-operator per-day pseudonym in §7.2 then becomes removable without violating I2, and §11.3's `sub` should be revisited. |
| V5 | Measured **p95 relay failover time exceeds 1.5 s** with a warm standby bound. That falsifies the "one RTT plus validation" claim in §8 and means either the standby mechanism or `RELAY_FLOW_FAILING`'s detection threshold is wrong. |
| V6 | **More than 2 % of `BIND` attempts fail with `RELAY.CLOCK_SKEW_EXCESSIVE`** over a month. The ±300 s skew window and single-retry offset correction are inadequate for the real device population, and token validity needs a skew-independent construction. |
| V7 | A relay operator is compelled to log, or is found to have logged, the `relay_sub`→`device_id` mapping. That is only possible via the issuer, so the trigger requires re-examining whether the issuer and the relay operator can be the same legal entity. |
| V8 | **Observed amplification factor on any deployed relay exceeds 1.0** in a black-box measurement. This ADR's core abuse-safety claim would be falsified and the shed/status path (§11.5) must be re-audited before any further relay deployment. |
| V9 | IPv6 reaches **> 90 % of measured client-relay legs**, making `R-UDP` v4 carriage and the NAT64 synthesis path in §11.4 dead code that should be removed rather than maintained. |
