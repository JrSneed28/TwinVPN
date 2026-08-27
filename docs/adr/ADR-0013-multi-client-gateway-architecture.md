# ADR-0013: Multi-Client Gateway Architecture

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** ARCHITECTURE
- **Related:** [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md),
  [ADR-0003](ADR-0003-network-contract-schema-format.md),
  [ADR-0005](ADR-0005-relay-architecture.md),
  [ADR-0007](ADR-0007-device-identity-and-pairing.md),
  [ADR-0008](ADR-0008-idempotency.md),
  [ADR-0009](ADR-0009-state-consistency.md),
  [ADR-0010](ADR-0010-ipv4-ipv6-routing.md),
  [ADR-0011](ADR-0011-dns-handling.md),
  [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md),
  [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md),
  [ADR-0015](ADR-0015-observability-and-diagnostics.md),
  [docs/architecture.md](../architecture.md), [docs/networking.md](../networking.md),
  [docs/protocol.md](../protocol.md), [docs/reliability.md](../reliability.md),
  [docs/testing-strategy.md](../testing-strategy.md)

This ADR owns the **datapath architecture of a `Device` serving many peers at once** as
`LANGateway` and/or `ExitNode`: the per-peer forwarding model, per-peer isolation and
anti-spoofing, per-peer resource accounting and fairness, connection admission, the concrete
supported peer counts, and how per-peer state is reconstructed after a restart. It does **not**
own the overlay address plan or route programming
([ADR-0010](ADR-0010-ipv4-ipv6-routing.md) — consumed here), kill-switch policy
([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)), DNS
([ADR-0011](ADR-0011-dns-handling.md)), relay selection
([ADR-0006](ADR-0006-relay-discovery-and-failover.md)), the `ConnectionState` machine, timers or
backoff ([docs/reliability.md](../reliability.md)), or the `reason_code` taxonomy
([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 — this ADR contributes codes into
it).

---

## 1. Context

PairVPN's defining defect is that its gateway serves **one client at a time**. A second device
connecting either displaces the first, queues behind it, or produces an unexplained failure.
`docs/vision.md` records this as **R-16**, the invariant register records it as **I7** ("Many
peers, always"), and the enforcing principle is **P7**. Every other document in this corpus has
already been written on the assumption that this ADR fixes it: `docs/architecture.md` §2.2
defines a Gateway role whose non-responsibilities include "MUST NOT serialize peers";
`docs/protocol.md` §13.2 and §13.3 state that grants are per-client; `docs/networking.md` §7.6
defers the capacity model here; `docs/testing-strategy.md` A-11 assumes a specific datapath
shape. This document either confirms those assumptions or names what must change.

One-at-a-time is rarely a deliberate choice. It is the accumulated consequence of small ones: a
NAT table with no owner column, a route table keyed by interface rather than by peer, an
`AccessPolicy` evaluated at connect time and cached globally, an address leased by a DHCP server
that knows how to lease one address per link. Each is individually reasonable and jointly fatal.
The remedy is therefore not a feature but a **shape**: every table on the forwarding path must be
keyed by peer identity, and peer identity must be a cryptographic fact rather than an address
that arrives in a packet header.

"Many peers" without resource accounting is the same defect in different clothes. A gateway that
admits sixteen peers and lets one consume the entire uplink, exhaust the connection-tracking
table, and starve the other fifteen has converted a queueing failure into a fairness failure
that is harder to diagnose. Multi-client means **isolated, accounted, and fair**, or nothing.

Finally, `docs/architecture.md` §5 row **S-21** has already committed to what happens on gateway
restart: per-peer datapath state is `LOCAL`, non-durable, and *deterministically
reconstructible*, and [ADR-0009](ADR-0009-state-consistency.md) §S-21 argues that determinism is
strictly stronger than persistence here. This ADR must show the mechanism, and be honest about
the part determinism does **not** rescue.

---

## 2. Requirements

| # | Requirement | Source |
|---|---|---|
| **G1** | A gateway MUST serve N ≥ 16 concurrent peers with no serialization, no displacement, and no per-peer degradation attributable to the presence of other peers. | I7, R-16 |
| **G2** | Peer identity on the forwarding path MUST be the peer's static public key, established by the handshake, and MUST NOT be inferable from any field an attacker controls. | I4, ADR-0001 |
| **G3** | A peer MUST NOT be able to send packets sourced from another peer's overlay address. | I4, threat model |
| **G4** | Peer-to-peer transit through the gateway MUST be default-deny. | S-06, architecture.md §2.2 |
| **G5** | `AccessPolicy` MUST be evaluated **per peer** on the **forwarding path**, so revocation and policy tightening take effect on the next packet, not the next connection. | networking.md §7.6, protocol.md §13.2 |
| **G6** | Every gateway resource that can be exhausted (bandwidth, conntrack entries, queue memory, CPU, handshake rate) MUST be accounted and capped per peer. | I7, R-16 |
| **G7** | A saturating peer MUST degrade itself. Other peers MUST retain their guaranteed floor share within a bounded time. | R-16 |
| **G8** | Peer overlay addressing MUST be reconstructed after gateway restart without DHCP, without an allocator round trip, and without renegotiating addresses. | R-03, A-15, S-08, S-21 |
| **G9** | Both address families MUST be forwarded, policed, and accounted with equal rigor. A v4-only gateway path is a leak, not a limitation. | P9, R-14 |
| **G10** | Supported peer counts MUST be stated per gateway hardware class with a resource model that justifies them, including router-class targets. | R-21 |
| **G11** | N peers reconnecting simultaneously (gateway reboot, uplink flap) MUST be admitted under an explicit, observable policy — never dropped silently and never allowed to collapse the gateway. | R-09, reliability.md §2.4 |
| **G12** | A single `Device` MUST be able to act as client, `LANGateway`, and `ExitNode` simultaneously, with deterministic routing precedence between those roles. | architecture.md §2.2, §8 |
| **G13** | Every per-peer denial, quota event, and capacity event MUST carry a stable `reason_code`. | I6, R-22 |
| **G14** | Per-peer observability MUST be sufficient to attribute a gateway-side problem to a specific peer, without creating a second, contradictory logging policy. | R-23, ADR-0015 |

---

## 3. Constraints

- **S-21 is already decided.** Per-peer datapath state is owned by the gateway `Device`,
  `LOCAL`, non-durable, deterministically reconstructible. This ADR may not introduce a second
  writer for it (**I8**) and may not make it durable without overruling
  [ADR-0009](ADR-0009-state-consistency.md).
- **S-08 is already decided.** Overlay addresses are immutable for a `Device`'s life, and the
  IPv6 `/128` is derived from the `DeviceKey` public half
  ([ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.1). The gateway consumes this; it does not
  allocate.
- **I5** — the data plane outlives the control plane. A gateway MUST be able to admit a
  previously paired peer, evaluate its policy, and forward for it with the control plane
  entirely down, using the last known-good signed `AccessPolicy` (S-06) and the cached contract.
- **[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) Rule KS-2** — forwarded traffic is
  never eligible for any kill-switch exemption. The gateway's forwarding path is outside the
  exemption table by construction.
- **Router-class targets are first class (R-21).** A design whose per-peer cost only closes on
  a server disqualifies itself: OpenWrt-class devices with 2 GB of RAM, no AES-NI, and a
  userspace or kernel datapath are a primary deployment.
- **iOS and Android cannot be gateways in Phase 1.** Neither `NEPacketTunnelProvider` nor
  `VpnService` exposes a forwarding path for third-party traffic, and both terminate the
  provider process on OS discretion. Gateway roles are supported on Linux, Windows, macOS, and
  OpenWrt-class targets only; requesting a gateway role elsewhere is a configuration error, not
  a silent downgrade.
- **No novel cryptography (I2)** and no per-peer cryptographic construction beyond what
  [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) already specifies.

---

## 4. Considered Alternatives

| # | Alternative |
|---|---|
| **A** | **One shared virtual interface with a per-peer cryptokey-routing table.** A single `twin0` carries every peer. A table maps peer static public key → the set of overlay source addresses that peer is permitted to use, and the reverse map sends a packet to the tunnel whose allowed-source set contains its destination. Per-peer policy, quotas, and counters hang off the same table. (WireGuard's model.) |
| **B** | **One virtual interface per peer.** Each admitted peer gets its own `twinN` device with its own address, its own firewall chain, its own qdisc, and its own routing table. Isolation is delegated to the kernel's existing per-interface machinery. |
| **C** | **Userspace forwarder with per-peer sockets.** A single process holds one UDP socket per peer, decapsulates in userspace, and forwards via a userspace IP stack or a raw socket, with all policy, NAT, and scheduling implemented in-process. |
| **D** | **Per-peer network namespaces / VRFs.** Each peer is confined to its own namespace (Linux netns) or VRF, with a veth pair or VRF binding into a shared forwarding domain. Isolation is a kernel-enforced separation of the entire network stack, not a rule set. |

Sub-decisions treated inside the selected option rather than as separate alternatives, because
they are not independent of it: the fairness scheduler (strict per-peer shaping vs. work-
conserving hierarchical fair queueing), the `LANGateway` source-address mode (routed vs. NAT),
and the `ExitNode` IPv6 egress mode (routed / NPTv6 / stateful NAT66) — each is decided
explicitly in §11 with its own tradeoff, because each could reasonably have gone the other way.

---

## 5. Advantages of Each Alternative

**A — Shared interface, cryptokey routing.** Peer identity is the *decryption key*, which means
identity is established before the packet's own headers are ever trusted: a packet that
decrypts under peer K's transport keys is, by
[ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)'s `Noise_IKpsk2`
construction, from the holder of K's static private key. Source validation then becomes a table
lookup rather than a heuristic, and G3 falls out of the datapath's shape instead of being
bolted on. Cost is O(1) per peer for the table entry and O(0) for OS objects: one interface,
one address pair, one route program, one firewall table, regardless of whether there are 4
peers or 1024. Adding a peer touches no OS global state, so admission cannot fail for
OS-resource reasons unrelated to the peer. It is the model the rest of this corpus already
assumes (`docs/testing-strategy.md` A-11, `docs/networking.md` §7.6, `docs/architecture.md`
§2.2) and the one with the largest body of deployed production experience at this scale.

**B — Interface per peer.** Isolation is enforced by machinery that already exists and is
already hardened: per-interface firewall chains, per-interface qdiscs, per-interface counters,
per-interface routing tables. Per-peer shaping and accounting are essentially free, because that is
what tc and the kernel counters were built for. Debugging is excellent: `tcpdump -i twin7` shows
exactly one peer. It maps neatly onto per-peer VRF designs used in carrier gear.

**C — Userspace forwarder.** Total control: any scheduling discipline, any accounting model,
any policy language can be implemented exactly as specified, identically on every OS, with no
dependence on kernel version, netfilter availability, WFP quirks, or a loadable module. It is
the only option that behaves identically on Windows, macOS, and a kernel too old for the
WireGuard module — a real portability advantage for R-19 and R-21. The forwarder is a pure
function from packets and tables to packets, so per-peer isolation and fairness are
unit-testable without a lab network.

**D — Namespaces / VRFs.** The strongest isolation of the four, and the only one where a bug in
our policy code cannot produce cross-peer leakage, because the peers do not share a routing
domain, a conntrack zone, or an address space in the first place. It naturally supports
overlapping per-peer address spaces, which is a genuine advantage for gateways serving sites
with colliding RFC 1918 prefixes (`docs/networking.md` §7.4). Per-peer limits can attach to the enclosing cgroup, giving CPU and
memory accounting by construction rather than by our own bookkeeping.

---

## 6. Disadvantages of Each Alternative

**A — Shared interface, cryptokey routing.** All peers share one conntrack zone, one interface
queue root, and one firewall table, so isolation is a property of *our rules and our
scheduling*, not of the OS's structure — a bug in the per-peer classifier is a cross-peer leak,
which is the highest-severity failure this ADR can produce. Overlapping per-peer address spaces
are not expressible: two peers cannot both be `100.64.3.7`, which is fine given S-08's globally
unique allocation but forecloses the multi-tenant case. Per-peer bandwidth shaping must be
implemented as an explicit classful hierarchy rather than inherited from per-interface qdiscs.
Packet capture on `twin0` shows every peer at once, which is worse for debugging and better for
privacy.

**B — Interface per peer.** Per-peer OS objects are the problem: N interfaces, N addresses, N
routes, N qdiscs, N firewall chains, N netlink notifications on every change. On Linux this is
tolerable to a few hundred and painful beyond; on Windows, creating a WinTun adapter per peer
is measured in *seconds* and is subject to driver installation and PnP serialization, so a
thundering herd of 64 reconnecting peers becomes minutes of adapter churn — which reintroduces
exactly the serialization defect this ADR exists to remove, at a different layer. Interface
creation requires privilege and can fail for reasons unrelated to the peer. Name and index
exhaustion, netlink storms, and per-adapter memory (a Windows adapter's ring buffers alone are
megabytes) put a hard, low ceiling on N, and the R-17 virtual-interface conflict surface scales
with N.

**C — Userspace forwarder.** Throughput. Every forwarded packet crosses the user/kernel
boundary at least twice more than in A, and a userspace IP stack forfeits GSO/GRO, checksum
offload, and the kernel's own conntrack. On the router-class targets that matter most for R-21,
this is the difference between saturating a 300 Mbit uplink and not, which violates **R-15**
directly. It also means reimplementing conntrack, NAT, PMTUD, and fragmentation
handling — each a known source of subtle, security-relevant bugs — in our own code.

**D — Namespaces / VRFs.** Linux-only in any recognizable form; Windows and macOS have no
equivalent, so it cannot be *the* model and would force a second model for those platforms —
two datapaths to write, test, and keep semantically identical, which is precisely how
family-asymmetric and platform-asymmetric bugs are born. Per-peer namespaces cost a veth pair,
a routing table, and a conntrack zone each, and the setup latency per peer (tens of
milliseconds) is far above A's. Diagnostics require entering a namespace, which is hostile on a
headless router. And D's own correctness still rests on the classifier that decides which
namespace a decrypted packet belongs to — the same classifier A depends on.

---

## 7. Security Implications

- **Cryptokey routing is the security property, not the routing optimization.** The central
  claim is: *a packet's overlay source address is only trusted because the tunnel it arrived on
  proves who sent it.* [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)
  binds both static public keys into the `Noise_IKpsk2` key schedule, so an unknown or revoked
  static cannot complete a handshake and cannot produce a frame that authenticates. The gateway
  therefore knows, per packet, which `DeviceIdentity` sent it — with the same strength as the
  handshake itself. §11.2's ingress source check converts that knowledge into an enforceable
  anti-spoofing rule. This is the single most important sentence in this ADR: **without the
  ingress check, cryptokey routing authenticates the sender and then lets the sender lie about
  who it is inside the envelope.**
- **Default-deny peer-to-peer transit (§11.2, G4)** stops a compromised peer pivoting into its
  siblings. A gateway is by definition the device with reachability to everything, so open
  transit would silently convert a hub-and-spoke trust model into a full mesh, defeating any
  `AccessPolicy` written on the assumption that the spokes were isolated.
- **Policy on the forwarding path, not at connect time (G5).** Evaluating `AccessPolicy` once
  per session and caching the verdict is how revocation becomes advisory. Per-packet evaluation
  against a compiled per-peer rule set means a `PolicyBundleUpdated` (`docs/protocol.md` §13.4)
  or a revocation-epoch bump (S-03) takes effect within one recompile, and live grants that no
  longer pass are withdrawn rather than grandfathered. Boundaries B5 and B6
  (`docs/architecture.md` §8) are enforced exactly here: every packet crossing them is attributed
  to a peer identity first.
- **The exit node's `Owner` is liable for its egress**, and the honest posture is stated in
  §11.7.4 rather than left to the operator to discover. That posture is deliberately built on
  [ADR-0015](ADR-0015-observability-and-diagnostics.md)'s existing tiers so that no second,
  contradictory logging policy exists.
- **Where a rejected alternative was better: D.** Namespace isolation would make cross-peer
  leakage structurally impossible instead of classifier-dependent. A is chosen with that risk
  explicitly accepted and mitigated by §11.16's conformance surface, which exists to make a
  classifier bug a *test failure* rather than a field incident.

---

## 8. Reliability Implications

- **Peer-level failure isolation** (`docs/architecture.md` §2.2): one peer's session collapse,
  quota exhaustion, or policy denial MUST NOT affect other peers. In model A a peer's state is a
  row; removing it is O(1) and touches nothing else.
- **Restart reconstructs addressing deterministically (§11.8, G8).** The cryptokey-routing table
  is a pure function of durable local inputs — the `TrustedPeer` set (S-05, durable) and the
  cached signed contract (S-08, immutable) — plus a local derivation for the IPv6 half
  ([ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.1). No allocator, no DHCP, no negotiation.
- **What restart genuinely costs is stated plainly in §11.8.3 and is not small**: tunnel key
  state is lost (S-13 forbids persisting it), so every peer performs a fresh handshake; and
  conntrack/NAT state is lost, so **every TCP flow traversing the gateway breaks**. Conntrack
  preservation is declared out of scope with a named revisit condition rather than hinted at.
- **The thundering herd is an admission problem, not a backoff problem** (§11.9). The gateway
  provides an explicit, authenticated deferral with a retry hint; the client's retry schedule
  remains owned by `docs/reliability.md` §6.1 (interactive regime) and §6.3 (retry budgets), and
  is not redefined here.
- **A gateway may be `RELAYED` for some peers and direct for others**
  ([ADR-0005](ADR-0005-relay-architecture.md)). Peer identity is the static key, not the 5-tuple,
  so movement between `LOCAL_DIRECT`, `WAN_DIRECT`, and `RELAYED` changes nothing in the
  cryptokey-routing table. Relayed peers consume the same uplink budget (MG-13).
- **Where a rejected alternative was better: B.** Per-interface state makes a peer's teardown
  unambiguously complete — the kernel reclaims the interface and everything hanging off it. In
  A, a leaked table row is our bug to prevent, which §11.16 makes assertable.

---

## 9. Performance Implications

- Model A's per-peer cost is a table entry plus a queue class. The forwarding path is one
  radix lookup for the destination peer, one for the ingress source check, and one policy
  lookup in a per-peer compiled set — all O(log n) on prefix length, none on peer count.
- **Crypto dominates.** On a router-class target without AES-NI, ChaCha20-Poly1305 at roughly
  2–3 cycles/byte across four Cortex-A72 cores is what sets the aggregate ceiling (~300 Mbit/s
  measured class), not the peer count. This is why §11.5's scale table names the *binding
  constraint* per class rather than quoting a peer number without one.
- **Work-conserving fairness beats strict shaping** here: a strict per-peer ceiling wastes the
  uplink whenever peers are idle, which is almost always. §11.4 selects deficit round robin
  between per-peer classes with an fq_codel leaf inside each — a guaranteed floor under
  contention, full uplink use when uncontended, plus flow fairness and bufferbloat control at no
  extra scheduler.
- **Conntrack is the memory bottleneck**, not tunnel state: a per-peer cap of 2048 entries at
  ~320 bytes each is 640 KB, versus ~5.5 KB of fixed per-peer state. §11.5's model makes this
  explicit because it is the number that decides whether a gateway survives one peer running a
  torrent client.
- Handshake cost bounds admission burst: one responder-side `Noise_IKpsk2` handshake is
  approximately 1 ms of CPU on a Cortex-A72, so §11.9's burst allowance of 32 costs ~32 ms — a
  cost worth paying for a fast herd recovery, and cheap enough that the rate limit exists for
  DoS resistance rather than for capacity.
- **Where a rejected alternative was better: B.** Per-interface qdiscs give per-peer shaping
  with zero classifier cost on the fast path. A pays one classification per packet for it.

---

## 10. Operational Implications

- A gateway is the one role with a **capacity number an operator must know**. §11.5 states it
  per hardware class, along with the constraint that binds, so "how many people can use my
  Raspberry Pi" has a defensible answer and a defensible failure mode when exceeded.
- **Admission refusal must be legible.** `RESOURCE.ADMISSION.PEER_LIMIT_REACHED` names the
  limit, the current admitted count, and the configured maximum. A user turned away by a full
  gateway must not see "connection failed".
- **The `LANGateway` forwarding mode is operator-visible and consequential** (§11.6): in NAT
  mode the LAN's own logs attribute all overlay traffic to the gateway, which is a real loss for
  anyone auditing their own network. The resolved mode is displayed at enable time and recorded,
  never silently chosen.
- **Exit-node operators need the abuse-attribution story before they enable the role**, not
  after they receive a notice from their ISP. §11.7.4 states it, bounds it, and ties it to
  [ADR-0015](ADR-0015-observability-and-diagnostics.md)'s existing opt-in tiers.
- Gateway telemetry (Tier 0, local) must report per-peer bytes, drops by reason, conntrack
  occupancy, queue backlog, and fairness-floor violations — the numbers that explain nearly every
  gateway support case — and graceful drain before a planned restart
  (`docs/reliability.md` §2.4) is a required operational procedure, since conntrack preservation
  is out of scope.

---

## 11. Decision

**Adopt Alternative A: one shared virtual interface with a per-peer cryptokey-routing table**,
with the per-peer policy, quota, and accounting structures specified below hanging off that
table. This **confirms `docs/testing-strategy.md` A-11**.

### 11.1 The datapath model (normative)

A gateway `Device` creates exactly **one** overlay interface (`twin0`) carrying its own
`TwinNet` `/32` and `/128` ([ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.1), regardless of how
many peers it serves. Its central structure is the **peer table**:

```
peer_table[peer_static_pubkey] = {
    device_id,                       # derived from the static key (ADR-0007)
    allowed_sources  : { v4 prefixes, v6 prefixes },   # ingress: what this peer may claim
    reachable_via    : tunnel handle,                  # egress: where to send its packets
    grants           : compiled per-peer prefix/port rule set  (S-36, §11.3)
    policy_version   : monotone (S-06)
    quota            : { conntrack, queue, rate, handshake }   (§11.4)
    counters         : per-family byte/packet/drop counters     (§11.11)
    class_id         : scheduler class handle                   (§11.4)
}
```

Two normative maps derive from it:

| Direction | Rule |
|---|---|
| **Ingress** (peer → gateway) | A frame is attributed to peer K **iff** it authenticates under K's transport keys. The gateway MUST then verify `src ∈ allowed_sources(K)` before any other processing. The overlay source address is never used to identify the sender. |
| **Egress** (gateway → peer) | A packet whose destination is an overlay address is sent on the tunnel of the unique peer K with `dst ∈ allowed_sources(K)`. If no such K exists, the packet is dropped, never flooded and never sent to a default peer. |

**Rule MG-1.** `allowed_sources(K)` MUST be exactly the addresses assigned to K in the signed
network contract ([ADR-0003](ADR-0003-network-contract-schema-format.md)) — its `/32` and its
`/128` — plus any prefix K is authorized to source-route under S-16 *and* permitted to by S-06.
For an ordinary client peer this set is exactly two host addresses. Wildcards MUST NOT be
expressible; `0.0.0.0/0` and `::/0` MUST NOT appear in an `allowed_sources` set.

**Rule MG-2.** The `allowed_sources` sets of any two admitted peers MUST be disjoint. Overlap is
refused at admission with `RESOURCE.ADMISSION.SOURCE_SET_OVERLAP` and is a control-plane
allocation bug (S-08 makes it impossible by construction; the check exists because a silent
overlap would be a cross-peer interception primitive).

**Rule MG-3.** Both families are handled by the same table, the same checks, and the same
counters, in the same transaction (**G9**, P9). A build that can populate the v4 half of a peer
row without the v6 half is non-conforming, mirroring
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) Rule KS-5.

### 11.2 Per-peer isolation and anti-spoofing (normative)

**Rule MG-4 (anti-spoofing).** A decapsulated packet from peer K whose source address is not in
`allowed_sources(K)` MUST be dropped, counted against K, and reported as
`POLICY.GATEWAY.SOURCE_SPOOFED` at `CRITICAL`. It MUST NOT be forwarded, MUST NOT be
source-rewritten, and MUST NOT be silently discarded. Enforcement point: the decapsulation
stage of the forwarding path, before route lookup, before conntrack, before policy. This is
cryptokey routing's central security property: the binding of key to identity established by
[ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) and
[ADR-0007](ADR-0007-device-identity-and-pairing.md) is only worth something if the address in
the inner header is checked against it.

**Rule MG-5 (default-deny peer transit).** A packet from peer A whose destination lies in
another admitted peer's `allowed_sources` MUST be dropped with
`POLICY.GATEWAY.PEER_TRANSIT_DENIED` unless an `AccessPolicy` rule (S-06) explicitly permits
A → B transit through this gateway. Transit permission is directional and is not implied by A
and B both being peers of the gateway, nor by A and B being `TrustedPeer`s of each other — a
direct A↔B `Session` is the supported path for that, and it does not consume gateway resources.

**Rule MG-6 (reverse-path).** The gateway configures loose reverse-path filtering on `twin0`
(`docs/networking.md` §7.6) *because* strict RPF would drop legitimate asymmetric overlay
traffic — but MG-4 is the real anti-spoofing control, and MUST NOT be replaced by RPF
configuration, which is a routing heuristic and not identity-bound.

**Rule MG-7.** Per-peer isolation MUST hold across conntrack: NAT/conntrack entries created for
peer A MUST be tagged with A's peer id and MUST NOT be matched by a packet attributed to peer B.
On Linux this is a per-peer conntrack zone or an equivalent mark-based partition; the normative
requirement is the property, not the mechanism.

### 11.3 Gateway-side policy evaluation (normative) — confirms `docs/protocol.md` A14

**`docs/protocol.md` A14 is confirmed**: a `LANGateway`/`ExitNode` maintains per-client state,
and grants are **per client, never global**. A grant issued to peer A creates no reachability
for peer B. `docs/protocol.md` §13.2's `LANAccessGrant` and §13.3's `ExitNodeEngaged` are
per-peer rows in `peer_table[K].grants`.

Evaluation order, per packet, on the forwarding path (**G5**). Every step is default-deny; the
first failure terminates with the named code:

| # | Step | Denial code |
|---|---|---|
| 1 | Authenticate + attribute to peer K (decrypt under K's transport keys) | (frame discarded by the tunnel layer) |
| 2 | `src ∈ allowed_sources(K)` (MG-4) | `POLICY.GATEWAY.SOURCE_SPOOFED` |
| 3 | K not revoked at the current trust epoch (S-03, cached bit) | `POLICY.GATEWAY.PEER_REVOKED` |
| 4 | Destination classification (§11.10 precedence) | `POLICY.GATEWAY.ROLE_PRECEDENCE_CONFLICT` |
| 5 | Destination ∈ K's granted prefix set for that role and family | `POLICY.GATEWAY.PREFIX_NOT_GRANTED` / `POLICY.GATEWAY.EXIT_NOT_ENGAGED` / `POLICY.GATEWAY.PEER_TRANSIT_DENIED` |
| 6 | Port/protocol scope of the matched `AccessPolicy` rule (S-06) | `POLICY.GATEWAY.PORT_SCOPE_DENIED` |
| 7 | Per-peer quota admission (conntrack insert, rate, queue) (§11.4) | `RESOURCE.QUOTA.*` |
| 8 | Forward | — |

**Rule MG-8.** The per-peer rule set is **compiled** from the signed `AccessPolicy` (S-06) plus
the live grants, and is stamped with the `policy_version` it was compiled from. On
`PolicyBundleUpdated` (`docs/protocol.md` §13.4) the gateway recompiles every peer's set within
1 s and withdraws grants that no longer pass, emitting
`POLICY.GATEWAY.GRANT_REVOKED_BY_POLICY` per affected grant. A lower `policy_version` MUST be
refused (S-06 anti-rollback).

**Rule MG-9.** Policy evaluation MUST NOT require a control-plane call (**I5**). With the
control plane unreachable, the gateway forwards on the last known-good signed bundle; if no
signed bundle has ever been received for a peer, the peer is refused
(`docs/architecture.md` §2.14: never fail open).

### 11.4 Per-peer resource accounting, quotas, and fairness (normative)

**Rule MG-10 (the noisy-neighbour rule).** A peer exceeding its share MUST degrade **itself**.
Scheduling is **deficit round robin between per-peer classes with an fq_codel leaf per class**,
work-conserving: a peer MAY consume unused capacity, and MUST be preempted back to its
guaranteed floor within **100 ms** of another admitted peer becoming backlogged. Failure to meet
the floor within that bound is `RESOURCE.FAIRNESS.FLOOR_NOT_MET` and is a defect, not a
condition.

Guaranteed floor share, per peer:

```
floor(K) = max( 256 kbit/s , configured_uplink / max_admitted_peers )
```

Accounted and capped per peer, both families separately counted and jointly capped:

| Resource | Mechanism | Exhaustion code |
|---|---|---|
| Bandwidth (each direction) | DRR class with `floor(K)` guarantee + optional ceiling | `RESOURCE.QUOTA.RATE_LIMITED` |
| Queue memory | per-class backlog byte cap (§11.5), tail-drop above cap | `RESOURCE.QUOTA.QUEUE_OVERFLOW` |
| Conntrack / NAT entries | per-peer soft and hard cap (§11.5); at soft cap, new-flow rate is throttled; at hard cap, new flows are refused, **existing flows are untouched** | `RESOURCE.QUOTA.CONNTRACK_EXHAUSTED` |
| New-flow rate | per-peer token bucket (§11.5) | `RESOURCE.QUOTA.CONNTRACK_EXHAUSTED` |
| Handshake / rekey rate | per-peer token bucket, 1/s sustained, burst 5 | `RESOURCE.QUOTA.HANDSHAKE_RATE_LIMITED` |
| CPU (crypto + forwarding) | the DRR quantum bounds a peer's share of a scheduling round; no peer may hold more than one quantum while another class is backlogged | `RESOURCE.CAPACITY.CPU_SATURATED` (gateway-wide) |
| Fixed per-peer memory | admission-time reservation (§11.5 model); admission refused rather than over-committed | `RESOURCE.CAPACITY.MEMORY_EXHAUSTED` |

**Rule MG-11.** Conntrack exhaustion MUST be per-peer before it is global. A gateway MUST size
`per_peer_conntrack_hard × max_admitted_peers` to at most 80% of its global conntrack capacity,
so that one peer can never make the table unusable for the others; global exhaustion despite
this is `RESOURCE.QUOTA.CONNTRACK_GLOBAL_EXHAUSTED` at `CRITICAL` and is a sizing bug.

**Rule MG-12.** Quota capacity is **reserved at admission**, not at first packet, so an admitted
peer is guaranteed its floor and its fixed state. A gateway that cannot reserve refuses
admission (`RESOURCE.ADMISSION.CAPACITY_RESERVED_UNAVAILABLE`) rather than admitting and
over-committing.

**Rule MG-13.** Traffic a peer sends over a `RELAYED` path
([ADR-0005](ADR-0005-relay-architecture.md)) is accounted against the same per-peer budget and
the same gateway uplink budget as direct traffic. The path class changes latency, not
entitlement.

### 11.5 Scale targets and the resource model (normative floor + reference classes)

**Rule MG-14.** A conforming gateway MUST support at least **16** concurrent admitted peers on
any supported platform. A build that cannot is non-conforming — this is the direct, testable
negation of the R-16 defect.

Fixed per-peer state (measured against the model A implementation):

| Component | Bytes per peer |
|---|---|
| Noise transport keys, nonces, 8192-entry replay bitmap | ~2 048 |
| Peer-table row: static key, `allowed_sources` radix nodes, tunnel handle | ~512 |
| Compiled grant/policy set (8 rules typical) | ~2 048 |
| Counters, histograms, token-bucket state | ~1 024 |
| **Fixed subtotal** | **~5.5 KB** |
| Queue class backlog cap | per class below |
| Conntrack at per-peer hard cap | `hard_cap × 320 B` |

Reference classes and their defaults:

| | **G1 — Router class** | **G2 — Always-on host** | **G3 — Server** |
|---|---|---|---|
| Reference hardware | OpenWrt-class / RPi 4B, 4×Cortex-A72 @1.5 GHz, no AES-NI, 2 GB | 4–8 core x86-64 with AES-NI, 8–16 GB, 1 GbE | 8+ core x86-64 AVX2, 32 GB, 10 GbE |
| `max_admitted_peers` default | **64** | **256** | **1024** |
| Binding constraint | aggregate ChaCha20-Poly1305 throughput (~300 Mbit/s class) | uplink + conntrack | per-peer memory + conntrack |
| Per-peer queue backlog cap | 256 KB | 512 KB | 1 MB |
| Per-peer conntrack soft / hard | 512 / 2 048 | 2 048 / 8 192 | 4 096 / 16 384 |
| Per-peer new-flow rate (burst) | 50/s (200) | 200/s (800) | 800/s (3 200) |
| Gateway handshake admission rate (burst) | 8/s (32) | 64/s (256) | 256/s (1 024) |
| Per-peer memory, typical (200 conntrack entries) | ~326 KB → **~21 MB at 64 peers** | ~600 KB → ~154 MB at 256 | ~1.1 MB → ~1.1 GB at 1024 |
| Per-peer memory, worst case (hard cap reached) | ~900 KB → ~58 MB at 64 peers | ~3.1 MB → ~800 MB at 256 | ~6.3 MB → over budget; see MG-11 sizing |

**Rule MG-15.** `max_admitted_peers` is configurable, but a gateway MUST refuse a configuration
whose worst-case reservation exceeds its measured available memory, at configuration time, with
`RESOURCE.CAPACITY.MEMORY_EXHAUSTED` — not at the moment the last peer connects.

### 11.6 `LANGateway` specifics (normative)

**11.6.1 Advertised subnets.** A `LANGateway` advertises `Route`s per S-16 and
`docs/protocol.md` §13.1, in **both families or with an explicit single-family declaration**
(`docs/networking.md` §7.3). Advertisement is gateway-global; **authorization is per peer**: the
set of advertised prefixes peer K may actually reach is `advertised ∩ granted(K)`, evaluated at
step 5 of §11.3. A peer reaching a prefix it was not granted is
`POLICY.GATEWAY.PREFIX_NOT_GRANTED`, never a silent drop.

**11.6.2 Forwarding mode toward the LAN.** Two modes, both real, decided per gateway:

| Mode | Source the LAN sees | Requires | Loses |
|---|---|---|---|
| **Routed** | The peer's overlay address (`100.64.x.y` / ULA `/128`) | A LAN-side return route for the `TwinNet` prefixes — either the gateway *is* the LAN's router, or the Owner configured a static route on it | Nothing, when the return route exists |
| **NAT** | The gateway's own LAN address (source-NAT / masquerade, v4 and NAT66 for v6) | Nothing | Per-peer attribution **on the LAN**; the site's own logs, ACLs, and per-host firewall rules see only the gateway |

**Rule MG-16.** The default is `AUTO`, resolved **once at gateway-enable time** into an explicit
mode that is displayed and recorded, never re-resolved silently:

1. If the Owner configured a mode explicitly, use it.
2. Else, if the gateway is itself the router for the advertised prefix — it serves RA or DHCP on
   that interface, or its address is the advertised default router for it — resolve **routed**
   (this is the common OpenWrt-class case, R-21).
3. Else resolve **NAT**, and emit `POLICY.GATEWAY.LAN_SNAT_ACTIVE` at `INFO`, naming the loss of
   LAN-side attribution.

NAT is therefore the **default leaf**: it is the mode that works without the Owner touching
equipment they may not control, and the alternative failure — routed mode with no return route —
is a "connected but nothing works" blackhole, which is the archetypal defect class this product
exists to remove. Per-peer attribution is *not* lost by NAT at the gateway: §11.11's counters
are per peer regardless of mode; what is lost is attribution on the LAN itself.

**Rule MG-17.** MG-16 does **not** alter `docs/networking.md` §7.4's route-conflict remediation
ladder, in which gateway-side NAT remains the last and non-default option. That ladder answers a
different question — what to do when the client's own LAN prefix collides with an advertised one
— and source-NAT does not resolve a destination-prefix collision. The two decisions are
orthogonal and both stand.

**11.6.3 IPv6.** A `LANGateway` MUST advertise the site's IPv6 prefix alongside its IPv4 one or
declare the asymmetry (`docs/networking.md` §7.3). In NAT mode the v6 path uses stateful NAT66
to the gateway's LAN address; in routed mode the overlay ULA source is preserved. The per-site
`/96` stateless remap for colliding IPv4 sites remains owned by
[ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.1 and is applied *before* §11.3's evaluation, so
grants are written against the remapped prefixes.

### 11.7 `ExitNode` specifics (normative)

**11.7.1 Many peers, one egress.** All admitted peers egress through the exit's upstream under
§11.4's per-peer accounting. Per-peer egress policy is the same compiled rule set as §11.3;
`docs/protocol.md` §13.3's `granted_default_v4` / `granted_default_v6` are per-peer rows, and an
absent grant is a denial (confirming
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) Rule KS-8).

**11.7.2 IPv4 egress.** Stateful source-NAT (masquerade) to the exit's WAN address, with
per-peer conntrack partitioning (MG-7) and per-peer port-allocation caps equal to the per-peer
conntrack hard cap.

**11.7.3 IPv6 egress — decided explicitly.** Three mechanisms were considered and the default is
**not** the one that looks most "correct":

| Mechanism | Behaviour | Verdict |
|---|---|---|
| **Stateful NAT66 masquerade** to the exit's own GUA | Peers share the exit's global address; no prefix delegation needed | **Default.** Symmetric with v4, works on any upstream, and exposes no per-peer identifier |
| **NPTv6** (RFC 6296), 1:1 checksum-neutral prefix translation from the `TwinNet` `/64` into a delegated `/64` | Each peer gets a stable, globally reachable address | **Opt-in only**, with disclosure — see MG-18 |
| **Native routed**, upstream routes the `TwinNet` `/64` to the exit | No translation at all; cleanest | Available only where the Owner has explicitly configured upstream routing (hosted VPS with a routed prefix); MUST NOT be auto-selected |

**Rule MG-18.** NPTv6 MUST NOT be the default, because
[ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.1 derives the overlay IPv6 IID from the
`DeviceKey` public half and NPTv6 preserves the IID. Under NPTv6 that IID becomes a **stable,
globally visible, key-derived per-device identifier** presented to every destination the peer
contacts. ADR-0010 §7 accepts IID enumerability *on the overlay*, where the ULA is unroutable;
extending it to the open Internet through an exit node — whose common purpose is precisely the
opposite — is a different and unaccepted exposure. Where an Owner enables NPTv6 deliberately
(inbound reachability for self-hosting behind an exit), the gateway MUST emit
`POLICY.GATEWAY.EXIT_V6_IDENTIFIER_EXPOSED` at `WARN` and the client MUST surface it.

**Rule MG-19.** The selected v6 egress mode MUST be declared in the `ExitNodeOffer` and
confirmed in `ExitNodeEngaged` (`docs/protocol.md` §13.3). This requires a new field —
recorded as a required interface in §11.15. A client MUST NOT infer the mode.

**11.7.4 Abuse attribution — the Owner's liability, stated once.** Egress from an exit node
appears to the Internet as originating from the exit's `Owner`. The posture is:

1. The exit node keeps, in [ADR-0015](ADR-0015-observability-and-diagnostics.md)'s **Tier 0**
   (local, never leaves the device, no transport exists for it), **per-peer aggregate** counters:
   bytes and packets per family, flow counts, drop counts by `reason_code`, conntrack occupancy,
   and quota events — the metrics of §11.11. This is sufficient to answer "which of my devices
   generated this volume", which is the question an Owner facing a notice actually needs.
2. **Per-flow destination records are never kept — not by default, and not on request.**
   [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.10 lists browsing and destination
   history in its **"never collected, in any mode"** column, and that column admits no `DEBUG`
   escape: "never collected" means no rendering path exists, in any build, at any log level, in
   any tier. An earlier draft of this clause made per-flow destination capture `DEBUG`-class and
   claimed it created "no second retention policy"; that was wrong on its own terms — a
   `DEBUG`-enablable per-flow destination log *is* a rendering path for destination history — and
   it is **withdrawn**. The gateway therefore keeps per-peer *aggregates* only: bytes, packets,
   flow counts, admission and quota events, keyed by `device_id` and never by destination.
   **No second retention or logging policy is created here**, and ADR-0015 §11.10 is binding on
   the gateway unmodified.
3. Nothing about egress is reported to any infrastructure component. Attribution is a purely
   local capability of a device the Owner controls, consistent with I1 and with T2/T3
   self-hosted topologies.
4. **Stated limitation, not hidden**: an exit `Owner` cannot, by default, tell a third party
   *which destination* a peer contacted, only *which peer* used how much capacity when. An
   Owner who needs more must enable the time-boxed capture in advance; retroactive attribution
   beyond aggregates is impossible by construction. This is the deliberate cost of the privacy
   posture, and exit-node enablement MUST disclose it.

### 11.8 Address stability across gateway restart

**11.8.1 What is reconstructed, and from what.** The peer table is a **pure function of durable
local inputs**, computed at start-up with no network interaction:

```
for each TrustedPeer K in local durable store (S-05):
    v4(K) ← contract.peers[K].v4          # S-08, immutable for K's life, from cached
    v6(K) ← twinnet_prefix64 ||           #       signed contract (ADR-0003)
            truncate64(HKDF(K.static_pub, "twinvpn-v6-iid"))   # ADR-0010 §11.1
    allowed_sources(K) ← { v4(K)/32, v6(K)/128 } ∪ authorized_source_prefixes(K)
    grants(K)         ← compile(last known-good signed AccessPolicy (S-06))
```

No DHCP, no DHCPv6, no SLAAC, no allocator round trip, no renegotiation of addresses — which
**confirms `docs/architecture.md` A-15** and discharges **R-03**. A peer reconnecting to a
restarted gateway is assigned the *same* addresses it had, because the addresses were never
assigned by the gateway in the first place; the gateway merely re-derives what S-08 already
fixed. This is the mechanism behind [ADR-0009](ADR-0009-state-consistency.md) §S-21's claim
that determinism is stronger than persistence.

**11.8.2 Reconstruction is control-plane-independent (I5).** All three inputs are local and
durable. A gateway can restart with the control plane entirely down and serve every previously
paired peer at its correct address under its last known-good policy.

**11.8.3 What a restart actually costs — stated honestly.**

| Lost | Consequence | Why it cannot be otherwise |
|---|---|---|
| `Tunnel` key state (S-13) | Every peer performs a fresh handshake; peers observe `RECONNECTING` per `docs/reliability.md` §2.4 | S-13 forbids persisting or replicating key state |
| **Conntrack / NAT entries (S-21)** | **Every TCP flow traversing the gateway breaks.** A peer's SSH session, file copy, or long-poll through the gateway is severed and must be re-established by the application. UDP flows resume transparently on the next packet with a new mapping | Persisting conntrack means either a durable write on the hottest path in the system, or a second writer for S-21 — both rejected by ADR-0009 §S-21 |
| Per-peer counters and quota state | Accounting windows restart; historical Tier-0 events survive in the local ring buffer | Non-durable by S-21 |

**Rule MG-20.** **Conntrack preservation across restart is explicitly OUT of scope for Phase 1.**
The supported mitigation is a **graceful drain**: before a planned restart the gateway withdraws
its `Route` advertisements and `ExitNodeOffer` (`docs/protocol.md` §13.1, §13.3), lets peers
re-home to an alternate gateway where the `AccessPolicy` names one (`docs/reliability.md` §2.4),
and only then restarts. Drain is a *migration*, not a preservation; where no alternate gateway
exists, flow breakage is unavoidable and MUST be stated in the UI before a restart is
initiated, as `RESOURCE.CAPACITY.RESTART_BREAKS_FLOWS` at `WARN` with the affected flow count.

### 11.9 Admission and the thundering herd

**Rule MG-21.** When `admitted_peers = max_admitted_peers`, a further peer is refused with
`RESOURCE.ADMISSION.PEER_LIMIT_REACHED`, carrying the configured maximum and the current count.
Refusal MUST NOT displace an admitted peer. There is no LRU eviction: silently disconnecting
someone to make room is the one-at-a-time defect in a larger costume.

**Rule MG-22.** Handshake processing is governed by a gateway-wide token bucket (§11.5 rates)
plus the per-peer bucket of §11.4. When the gateway-wide bucket is empty, the gateway MUST
respond with an **authenticated deferral** carrying `RESOURCE.ADMISSION.DEFERRED` and a
`retry_after_ms` hint, rather than dropping the handshake. A silent drop forces the client to
infer congestion from a timeout, which is both slower and indistinguishable from the gateway
being down.

**Rule MG-23.** The client's response to a deferral is the **interactive backoff regime** of
`docs/reliability.md` §6.1 (equal jitter, base 250 ms, cap 15 s) against the retry budget of
§6.3 — **this ADR does not define a schedule and does not modify one**. `retry_after_ms` is a
lower bound on the client's next attempt, not a replacement for its jitter.

**Rule MG-24.** Admission ordering under a herd is **first-come, first-served within the token
bucket**, with no priority tiers in Phase 1. Deterministic ordering is preferred to fairness
heuristics here because a priority scheme that is wrong is worse than none, and because
§11.5's burst allowances make a 64-peer herd on a G1 gateway an ~8 s recovery — acceptable
without prioritisation.

### 11.10 Multi-role devices and routing precedence (normative)

**Rule MG-25.** A single `Device` MAY act simultaneously as a client to peer X, a `LANGateway`
for peer Y, and an `ExitNode` for peer Z. This **confirms `docs/architecture.md` §2.2 and §8**.
The roles share one interface, one peer table, and one policy engine; they are distinguished
only by which grants a given peer row holds.

Destination classification order for a packet attributed to peer K (step 4 of §11.3):

| # | Match | Action |
|---|---|---|
| 1 | `dst` ∈ the gateway's own overlay addresses | Deliver locally to the gateway's own stack (its client role) |
| 2 | `dst` ∈ another admitted peer's `allowed_sources` | Peer transit — **default deny** (MG-5) |
| 3 | `dst` ∈ an advertised `LANGateway` prefix granted to K | LAN forwarding path (§11.6) |
| 4 | `dst` matched only by the default route, and K holds a live `ExitNodeEngaged` grant for that family | Exit egress path (§11.7) |
| 5 | Anything else | Drop, `POLICY.GATEWAY.PREFIX_NOT_GRANTED` |

Within each row, longest-prefix match governs, consistent with
[ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.6 P1. Rows 1–3 are more specific than row 4 by
construction, so the exit path is never chosen for a destination a LAN grant covers; if an
advertised LAN prefix and an exit grant both plausibly cover a destination the ambiguity is
resolved by the table order above and reported as
`POLICY.GATEWAY.ROLE_PRECEDENCE_CONFLICT` at `WARN` — never resolved silently (**I6**).

**Rule MG-26.** The gateway's **own locally-originated** traffic (row 1, its client role) remains
subject to its own kill switch ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)).
Forwarded traffic (rows 2–4) is subject to Rule KS-2 and is never eligible for a kill-switch
exemption. The two dispositions are evaluated by the same rule set on the same interface and
MUST NOT be conflated: a gateway does not gain local exemptions for its peers, and its peers do
not lose protection because their gateway has a portal grant.

### 11.11 Per-peer observable metrics (feeds ADR-0015)

Emitted into [ADR-0015](ADR-0015-observability-and-diagnostics.md)'s **Tier 0** (local,
default-on, never exported), labelled by peer. Per-peer labels are permitted in Tier 0 and are
**forbidden in Tier 2** aggregates, per ADR-0015 §11.10 — this ADR adds no exception.

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `gw_peer_bytes` / `gw_peer_packets` | counter | peer, direction, family | Accounting, abuse attribution (§11.7.4) |
| `gw_peer_drops` | counter | peer, `reason_code`, family | Which peer, why |
| `gw_peer_conntrack_entries` | gauge | peer | Quota headroom |
| `gw_peer_flows_created` | counter | peer | New-flow rate, scan detection |
| `gw_peer_queue_backlog_bytes` / `gw_peer_queue_drops` | gauge / counter | peer | Congestion attribution |
| `gw_peer_floor_share_bps` / `gw_peer_achieved_bps` | gauge | peer | **The P06 fairness oracle** |
| `gw_peer_floor_violation_ms` | histogram | peer | MG-10's 100 ms bound |
| `gw_peer_policy_denials` | counter | peer, rule id | Policy debugging |
| `gw_peer_spoof_drops` | counter | peer | MG-4; any non-zero value is a security event |
| `gw_peer_handshakes` | counter | peer, outcome | Admission, herd behaviour |
| `gw_peer_path_class` | gauge | peer, class | Which peers are `RELAYED` (MG-13) |
| `gw_admitted_peers` / `gw_max_admitted_peers` | gauge | — | Capacity |

### 11.12 Reason codes contributed

Contributed to the machine-readable registry under
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2's
`DOMAIN.SUBDOMAIN.CONDITION` scheme. The `RESOURCE` domain is assigned to this ADR by ADR-0015
§11.2 and is contributed in full. The `POLICY.GATEWAY.*` subdomain is contributed **by
delegation from [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)**, which owns `POLICY`;
this is recorded as a required interface in §11.15.

| `reason_code` | class | severity | terminal | user actionable | Meaning |
|---|---|---|---|---|---|
| `RESOURCE.ADMISSION.PEER_LIMIT_REACHED` | PERSISTENT | ERROR | false | true | Gateway is at `max_admitted_peers`; names limit and current count |
| `RESOURCE.ADMISSION.DEFERRED` | TRANSIENT | INFO | false | false | Handshake bucket empty; carries `retry_after_ms` (MG-22) |
| `RESOURCE.ADMISSION.CAPACITY_RESERVED_UNAVAILABLE` | PERSISTENT | WARN | false | true | Floor share or fixed state could not be reserved (MG-12) |
| `RESOURCE.ADMISSION.SOURCE_SET_OVERLAP` | PERSISTENT | CRITICAL | false | false | Two peers claim overlapping `allowed_sources` (MG-2); a control-plane bug |
| `RESOURCE.QUOTA.RATE_LIMITED` | TRANSIENT | INFO | false | true | Peer is above its ceiling and is being shaped |
| `RESOURCE.QUOTA.QUEUE_OVERFLOW` | TRANSIENT | WARN | false | true | Per-peer backlog cap reached; drops are this peer's |
| `RESOURCE.QUOTA.CONNTRACK_EXHAUSTED` | TRANSIENT | ERROR | false | true | Peer at its conntrack hard cap; new flows refused, existing untouched |
| `RESOURCE.QUOTA.CONNTRACK_GLOBAL_EXHAUSTED` | PERSISTENT | CRITICAL | false | true | Gateway-wide table exhausted despite MG-11 sizing |
| `RESOURCE.QUOTA.HANDSHAKE_RATE_LIMITED` | TRANSIENT | WARN | false | false | Per-peer handshake bucket empty |
| `RESOURCE.CAPACITY.CPU_SATURATED` | TRANSIENT | WARN | false | true | Forwarding CPU saturated; all peers degraded, none preferentially |
| `RESOURCE.CAPACITY.MEMORY_EXHAUSTED` | PERSISTENT | CRITICAL | false | true | Reservation exceeds available memory (MG-15) |
| `RESOURCE.CAPACITY.RESTART_BREAKS_FLOWS` | POLICY | WARN | false | true | Planned restart will sever N forwarded flows (MG-20) |
| `RESOURCE.FAIRNESS.FLOOR_NOT_MET` | PERSISTENT | ERROR | false | false | A backlogged peer did not reach its floor within 100 ms (MG-10); a defect |
| `POLICY.GATEWAY.SOURCE_SPOOFED` | POLICY | CRITICAL | false | false | Inner source address outside the sending peer's `allowed_sources` (MG-4) |
| `POLICY.GATEWAY.PEER_TRANSIT_DENIED` | POLICY | ERROR | false | true | Peer-to-peer transit not explicitly permitted (MG-5) |
| `POLICY.GATEWAY.PREFIX_NOT_GRANTED` | POLICY | ERROR | false | true | Destination outside this peer's granted prefix set |
| `POLICY.GATEWAY.PORT_SCOPE_DENIED` | POLICY | ERROR | false | true | Destination granted but port/protocol scope denies it |
| `POLICY.GATEWAY.EXIT_NOT_ENGAGED` | POLICY | ERROR | false | true | Default-route packet from a peer with no live exit grant for that family |
| `POLICY.GATEWAY.PEER_REVOKED` | POLICY | CRITICAL | true | true | Peer revoked at the current trust epoch (S-03) |
| `POLICY.GATEWAY.GRANT_REVOKED_BY_POLICY` | POLICY | WARN | false | true | A live grant was withdrawn by a policy recompile (MG-8) |
| `POLICY.GATEWAY.LAN_SNAT_ACTIVE` | POLICY | INFO | false | true | NAT mode resolved; LAN-side per-peer attribution is masked (MG-16) |
| `POLICY.GATEWAY.EXIT_V6_IDENTIFIER_EXPOSED` | POLICY | WARN | false | true | NPTv6 egress exposes a stable key-derived IID globally (MG-18) |
| `POLICY.GATEWAY.ROLE_PRECEDENCE_CONFLICT` | POLICY | WARN | false | true | A destination matched two role paths; states which won (MG-25) |

**Naming reconciliation.** ADR-0015 §11.2's illustrative `RESOURCE.PEER_LIMIT_REACHED` and
`RESOURCE.MEMORY_EXHAUSTED` are two-segment, which is **canonical** — ADR-0015 §11.2 makes the
subdomain optional. They are deprecated here on **grouping** grounds, not format grounds: the
`RESOURCE.ADMISSION.*` / `RESOURCE.CAPACITY.*` / `RESOURCE.QUOTA.*` families make the three
distinct failure modes findable. They are
registered canonically as `RESOURCE.ADMISSION.PEER_LIMIT_REACHED` and
`RESOURCE.CAPACITY.MEMORY_EXHAUSTED`, with the two-segment forms as `DEPRECATED` aliases per
ADR-0015 §11.2 stability rule 3.

### 11.13 State ownership

**S-21 is confirmed unchanged**: per-peer gateway datapath state (peer table, conntrack, NAT,
counters, quota) is written by the gateway `Device`, has no replica, is `LOCAL`, non-durable,
and deterministically reconstructible (§11.8). No second writer is introduced.

**One new row is required.** `docs/architecture.md` §5 MUST add:

| # | State | Authoritative writer | Replicas / caches | Consistency class | Durability | On conflict |
|---|---|---|---|---|---|---|
| **S-36** | Live per-client gateway grant set (`LANAccessGrant` / `ExitNodeEngaged` in force) | **The gateway `Device` (2.2)** | The requesting client caches its own grant with the grant TTL | `LOCAL` (gateway is the enforcement authority per `docs/protocol.md` §13.2) | Non-durable; reconstructible from S-06 + S-16 + the client's re-request | Gateway wins — the client's view of policy is advisory (`docs/protocol.md` §13.2) |

This is distinct from S-21 (datapath state) because a grant is a *policy* fact with an
authority question, and from S-06 (`AccessPolicy`, `Owner`-authored and control-plane-distributed) because a grant is
the gateway's local, TTL'd instantiation of that policy for one client.

### 11.14 Assumptions confirmed or overruled

| Assumption | Source | Verdict |
|---|---|---|
| **A-15** — `TwinNet` addressing is deterministically derived per device, **no DHCP anywhere in the datapath** | `docs/architecture.md` §9 | **Confirmed.** §11.8.1 is the mechanism; the gateway allocates nothing and leases nothing |
| **A14** — a `LANGateway`/`ExitNode` maintains per-client state, so grants are per-client not global | `docs/protocol.md` §18 | **Confirmed.** §11.3, S-36 |
| **A-10** — a `TwinNet` address plan exists with a deterministic per-`Device` address in both families, assigned without DHCP | `docs/testing-strategy.md` §0 | **Confirmed.** Consumed from [ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.1; the gateway is a consumer, not a co-author |
| **A-11** — a gateway serves many peers over **one shared virtual interface** with per-peer policy and per-peer resource accounting | `docs/testing-strategy.md` §0 | **Confirmed.** Alternative A selected; §11.1, §11.3, §11.4 |
| **S-21** — per-peer gateway datapath state is `LOCAL`, non-durable, deterministically reconstructible | `docs/architecture.md` §5, [ADR-0009](ADR-0009-state-consistency.md) | **Confirmed**, with §11.8.3 naming the cost determinism does not cover |
| **KS-2** — forwarded traffic is never eligible for a kill-switch exemption | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.1 | **Confirmed.** MG-26 |
| **KS-8** — an absent per-family grant is a denial | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.4 | **Confirmed.** §11.7.1 |
| `docs/networking.md` §7.6 — forwarding enabled both families, per-peer policy on the forwarding path, loose RPF, conntrack sized for many peers | `docs/networking.md` | **Confirmed**, with MG-6 adding that RPF is not the anti-spoofing control and MG-4 is |
| `docs/networking.md` §7.4 — gateway-side NAT is the last, non-default conflict remedy | `docs/networking.md` | **Confirmed and left unchanged.** MG-17 explains why MG-16's default does not touch it |
| `docs/protocol.md` §13.2 / §13.3 "Multi-client (I7)" rows | `docs/protocol.md` | **Confirmed** |

Nothing is overruled.

### 11.15 Interfaces required from other ADRs

| # | Required from | Interface |
|---|---|---|
| **X1** | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) | Delegation of the `POLICY.GATEWAY.*` subdomain to this ADR, ADR-0012 retaining `POLICY` |
| **X2** | [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) + `docs/protocol.md` §13.3 | An `egress_v6_mode ∈ {NAT66, NPTV6, ROUTED}` field in `ExitNodeOffer` and its echo in `ExitNodeEngaged` (MG-19) |
| **X3** | `docs/protocol.md` §13.2 / §13.3 | A `retry_after_ms` field on the refusal/deferral messages so MG-22's deferral is expressible on the wire |
| **X4** | [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) | The decapsulation API MUST expose the authenticated peer static key to the forwarding path, per frame; MG-4 is unimplementable without it |
| **X5** | [ADR-0007](ADR-0007-device-identity-and-pairing.md) | A cheap, cached "is this static key revoked at the current epoch" predicate usable on the per-packet path (step 3 of §11.3) |
| **X6** | [ADR-0003](ADR-0003-network-contract-schema-format.md) | The signed contract MUST carry each peer's `/32` and `/128` in a form a gateway can consume offline (§11.8.1) |
| **X7** | [ADR-0015](ADR-0015-observability-and-diagnostics.md) | Registration of §11.12's codes and §11.11's Tier-0 metrics, and confirmation that per-peer labels remain Tier-0-only |
| **X8** | `docs/architecture.md` §5 | Addition of row **S-36** (§11.13) |

### 11.16 Conformance surface for proof test P06

`docs/testing-strategy.md` P06 ("multiple clients can use one gateway, with isolation and
per-peer accounting oracles", carrying assumptions A-10 and A-11) is made testable by the
following observable oracles. Each is a property a build can fail:

| Oracle | Observation | Falsifying build |
|---|---|---|
| **Concurrency** | 16 peers (the MG-14 floor) admitted simultaneously; all 16 pass traffic in the same 1 s window; `gw_admitted_peers = 16` | Any build that serializes, displaces, or queues |
| **Addressing (A-10)** | Every peer's observed overlay source at the gateway equals the contract's `/32` and the ADR-0010 §11.1 derivation of its `/128`; no DHCP/DHCPv6/SLAAC frame appears on `twin0` in a full packet capture | A build that leases addresses |
| **Single interface (A-11)** | Exactly one overlay interface exists on the gateway for all N peers | A per-peer-interface build |
| **Isolation** | Peer A sends to peer B's overlay address; the packet is dropped and `gw_peer_drops{reason=POLICY.GATEWAY.PEER_TRANSIT_DENIED}` increments for A; B's interface counters do not move | Any build defaulting to open transit |
| **Anti-spoofing** | Peer A sends a frame on its own tunnel with peer B's overlay source; drop, `gw_peer_spoof_drops{peer=A}` increments, `POLICY.GATEWAY.SOURCE_SPOOFED` emitted | A build that trusts the inner source header |
| **Per-peer policy** | A granted prefix for A is not reachable by B; revoking A's grant stops A's *in-flight* traffic within 1 s of `PolicyBundleUpdated` | A build evaluating policy only at connect time |
| **Accounting** | `gw_peer_bytes` per peer sums to the gateway total within 1%; per-peer drop counters attribute every drop | A build with a single global counter set |
| **Fairness / noisy neighbour** | Peer A saturates the uplink; peer B starts; B reaches `floor(B)` within 100 ms; `gw_peer_floor_violation_ms` p99 < 100 ms | Any build with a shared FIFO |
| **Quota isolation** | Peer A exhausts its conntrack hard cap; A gets `RESOURCE.QUOTA.CONNTRACK_EXHAUSTED`; B's new flows still succeed | A shared, unpartitioned conntrack table |
| **Restart determinism** | Gateway restarts; every peer reconnects at the *same* overlay addresses with no control-plane involvement; forwarded TCP flows are observed to break (the honest expectation of §11.8.3, asserted rather than hoped) | A build that renumbers, or one that claims flow survival |
| **Herd admission** | 64 peers reconnect simultaneously on a G1 gateway; every one is either admitted or receives `RESOURCE.ADMISSION.DEFERRED`; none times out silently; all admitted within the burst-derived bound | A build that drops handshakes under load |
| **Dual family (G9)** | Every oracle above is run for v4 and v6 independently and must pass identically | Any family-asymmetric build |

---

## 12. Why the Selected Option Won

1. **Identity precedes addressing, and only A gets that ordering right by construction.** In A a
   packet's sender is known from the key that decrypted it before any header it carries is read.
   B, C, and D can all *implement* that check; none makes it the natural shape of the code — and
   the defect being fixed here is precisely the accumulation of plausible-looking shortcuts.
2. **B fails on the exact axis it was chosen for.** Per-interface isolation is elegant on Linux
   and catastrophic on Windows, where adapter creation is seconds-scale and PnP-serialized. A
   64-peer herd would take minutes of adapter churn — re-creating the one-at-a-time defect one
   layer down. An architecture that reintroduces the defect it exists to remove, on a supported
   platform, disqualifies itself.
3. **C loses R-15 to win portability we do not need.** The userspace/kernel crossings and the
   loss of offload cost exactly the throughput that router-class targets (R-21) do not have to
   spare. A can *fall back* to a userspace datapath where no kernel one exists, keeping C's
   portability as an implementation detail rather than an architecture.
4. **D is the strongest isolation and the wrong scope.** Namespaces are Linux-only, so choosing
   them means writing and maintaining two datapaths with identical semantics — the reliable way
   to produce platform-asymmetric bugs. Its structural guarantee is real and is the one thing A
   genuinely gives up; §11.16 exists to convert that lost structure into enforced tests.
5. **The corpus already assumes A** in four independently written documents. Overruling it would
   have required a benefit large enough to justify rewriting `docs/testing-strategy.md` A-11,
   `docs/architecture.md` §2.2, `docs/networking.md` §7.6, and `docs/protocol.md` §13.2. None of
   B, C, or D offers one.
6. **Determinism, not persistence, solves restart** — and only because S-08 made addresses
   immutable and ADR-0010 made the v6 half derivable. G8 comes free from decisions already
   taken.
7. **The v6 egress default is the one place this ADR chose the less "correct" option
   deliberately**, and it is worth stating why it won: NPTv6 is architecturally cleaner and
   privacy-catastrophic in this specific system, because our IIDs are key-derived. Choosing
   NAT66 by default is choosing the product's actual purpose over the protocol's elegance.

---

## 13. Known Tradeoffs

| Tradeoff | Accepted because |
|---|---|
| Isolation depends on our classifier rather than on kernel structure | §11.16 makes every isolation property an enforced oracle; D's structural guarantee is Linux-only and would cost a second datapath |
| One shared conntrack table, partitioned by tag rather than by construction | MG-7 and MG-11 make the partition explicit and the sizing safe; per-peer zones are available on Linux and the property, not the mechanism, is normative |
| Overlapping per-peer overlay address spaces are inexpressible | S-08 makes overlap impossible in a `TwinNet`; multi-tenant gateways are out of scope for Phase 1 |
| Conntrack is not preserved across gateway restart, so forwarded TCP flows break | Preservation needs a durable write on the hottest path or a second writer for S-21; graceful drain (MG-20) is the supported mitigation and the cost is disclosed, not hidden |
| `LANGateway` NAT default loses per-peer attribution *on the LAN* | Routed mode without a LAN-side return route is a silent blackhole, a worse failure; MG-16 resolves to routed automatically where the gateway is the LAN router, and always discloses the resolution |
| `ExitNode` NAT66 default forfeits per-peer inbound reachability over IPv6 | NPTv6's stable key-derived global IID is a worse exposure for an exit node than losing inbound reachability; NPTv6 remains available opt-in with disclosure |
| Exit-node abuse attribution is aggregate-only by default | ADR-0015's privacy posture is binding and this ADR refuses to create a second logging policy; the limitation is disclosed at enablement |
| Work-conserving fairness means a peer's observed throughput varies with others' idleness | A strict ceiling would waste the uplink almost all the time; the floor is guaranteed and measurable, which is the property that matters |
| No admission priority tiers | A wrong priority scheme is worse than none; burst allowances make herd recovery fast enough without one |
| Gateway roles unavailable on iOS/Android | Neither platform exposes a third-party forwarding path; naming this as unsupported is better than a degraded pretence (R-20) |
| Stated peer counts are per reference hardware class and will not match every device | The binding constraint is named per class, so an operator can reason about their own hardware rather than trusting a number |

---

## 14. Revisit Conditions

1. **If measured cross-peer leakage is ever observed in the field or in P06's isolation oracle
   on a shipped build**, Alternative D's structural isolation must be re-evaluated for the Linux
   gateway target specifically, accepting the two-datapath cost.
2. **If more than 5% of gateway deployments configure `max_admitted_peers` above their class
   default and hit `RESOURCE.CAPACITY.CPU_SATURATED`**, the per-class defaults in §11.5 are
   wrong and must be re-measured on current reference hardware.
3. **If `RESOURCE.FAIRNESS.FLOOR_NOT_MET` exceeds 0.1% of contended intervals on any class**,
   the DRR + fq_codel choice in §11.4 is not delivering MG-10's 100 ms bound and the scheduler
   must be reconsidered (candidates: HTB with explicit rate guarantees, or a per-peer CAKE tin).
4. **If forwarded-flow breakage across planned gateway restarts becomes a top-three support
   category**, MG-20's out-of-scope decision on conntrack preservation must be revisited —
   which requires ADR-0009 to re-open S-21, since preservation cannot be added without touching
   its durability class.
5. **If `POLICY.GATEWAY.LAN_SNAT_ACTIVE` is emitted for more than 60% of `LANGateway`
   enablements**, MG-16's `AUTO` resolution is effectively "always NAT" and the routed path is
   dead code; either the detection in MG-16(2) is too narrow, or the default should be stated
   plainly as NAT with routed as opt-in.
6. **If a supported platform ships a mechanism that lets a decapsulated packet reach the
   forwarding path without the authenticated peer static key attached** (X4 unmet), MG-4 is
   unenforceable on that platform and the gateway role MUST be withdrawn there rather than
   shipped without anti-spoofing.
7. **If IPv6 prefix delegation becomes reliably available on more than 80% of measured exit-node
   upstreams, and inbound reachability is requested by more than 10% of exit users**, re-evaluate
   MG-18 — specifically whether a per-peer *non-derived* egress IID (breaking the NPTv6 1:1
   identity mapping) could give reachability without the identifier exposure.
8. **If multi-tenant gateways (one gateway serving peers from more than one `TwinNet`, with
   possibly overlapping address space) enter scope**, MG-2's disjointness requirement and the
   single shared conntrack table both break, and Alternative D returns as the leading candidate.
9. **If a `Device` acting in all three roles simultaneously produces more than 1% incidence of
   `POLICY.GATEWAY.ROLE_PRECEDENCE_CONFLICT`**, §11.10's precedence table is under-specified for
   real deployments and needs explicit per-role scoping rather than an ordering.
