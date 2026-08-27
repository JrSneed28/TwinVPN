# TwinVPN Networking Architecture

**Scope.** This document specifies how two `Device`s in a `TwinNet` actually get packets to
each other: the overlay address plan, NAT behavior and path establishment, candidate
gathering and path quality, the per-platform network adapter, MTU handling, routing modes,
and LAN discovery. It owns the *networking mechanism*. It does not own the connection state
machine (`docs/reliability.md`), relay design ([ADR-0005](adr/ADR-0005-relay-architecture.md),
[ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md)), the tunnel cryptography
([ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)), the kill-switch
policy ([ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md)), or the wire contract
([ADR-0003](adr/ADR-0003-network-contract-schema-format.md)). Where those decisions are
needed here, the required *interface* is stated and the ADR is referenced.

## Related documents

| Document | Relationship |
|----------|--------------|
| [docs/architecture.md](architecture.md) | Plane separation (I8), component ownership |
| [docs/protocol.md](protocol.md) | Control-plane messaging, contract distribution |
| [docs/reliability.md](reliability.md) | **Authoritative** `ConnectionState` machine, retry/backoff, relay |
| [docs/threat-model.md](threat-model.md) | Threat model, leak threat model, kill-switch policy |
| [docs/testing-strategy.md](testing-strategy.md) | NAT matrix test harness, leak test suite |
| [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md) | NAT traversal strategy (owned here) |
| [ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md) | Address plan and routing (owned here) |
| [ADR-0011](adr/ADR-0011-dns-handling.md) | DNS (owned here) |

## 1. Design tenets (and the defect each one retires)

| # | Tenet | Defect retired |
|---|-------|----------------|
| N1 | Addresses are **assigned by the control plane and carried in the signed contract**, never learned by DHCP on the overlay. | DHCP and route-establishment stalls |
| N2 | Overlay addresses are **stable for the life of the `DeviceIdentity`**, independent of underlay address, NAT, or network change. | Poor roaming; re-pair churn |
| N3 | **IPv6 is a first-class path and a first-class destination**, and is subject to exactly the same tunnel policy as IPv4. | IPv4/IPv6 leaks; IPv6 bypass |
| N4 | Direct connectivity is an **optimization**, relay is a **guaranteed floor**. Falling back to relay is a designed transition, never an error. | NAT traversal failures; symmetric/CGNAT failures |
| N5 | Path selection is **continuous and reversible**: `RELAYED` is opportunistically upgraded to `WAN_DIRECT`/`LOCAL_DIRECT` and demoted back without user action. | Random disconnects; excessive relay latency |
| N6 | MTU is **discovered without depending on ICMP**. | MTU black holes; throughput degradation |
| N7 | The platform adapter **coexists** with host firewalls, AV, other VPNs, and other virtual interfaces; it never requires a third-party kernel driver we do not ship and version. | Virtual-interface conflicts; firewall/AV conflicts; stale drivers; poor modern-OS compatibility |
| N8 | Every networking failure emits a **stable machine-readable reason code** plus a human-actionable explanation (I6), including which NAT class was observed. | Cryptic error codes; insufficient diagnostics |
| N9 | A `LANGateway`/`ExitNode` is **multi-peer by construction** (I7); nothing in the address plan, routing, or NAT design is per-single-client. | One-client-at-a-time limits |
| N10 | Linux, containers, and routers are **first-class targets**, not ports. | No Linux/router support |

## 2. Address plan

### 2.1 Overlay prefixes

The overlay is dual-stack **always**. Every `Device` receives one IPv4 address and one IPv6
address, and both are always present on the interface even when the underlay is single-stack.
This is what makes application behavior identical on an IPv4-only cafe network and an
IPv6-only mobile network.

| Family | Space | Per-`TwinNet` | Per-`Device` |
|--------|-------|---------------|--------------|
| IPv4 | `100.64.0.0/10` (RFC 6598 shared address space) | one or more `/22` blocks allocated by the control plane | a single `/32` |
| IPv6 | the fixed product ULA `fd7c:9e5d:2a10::/48` under `fd00::/8` (RFC 4193; one constant 40-bit global ID for the whole product — see [ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md) §11.1) | one `/64` | a single `/128` |

**Why RFC 6598 for IPv4.** RFC 1918 space collides catastrophically with real home, office,
and cloud LANs — `192.168.0.0/16` and `10.0.0.0/8` are the two most common LANs on earth, and
a full-tunnel or subnet-route deployment that overlaps them breaks the user's own printer.
`100.64.0.0/10` is reserved for provider CGNAT and is essentially never used as an on-link
LAN prefix on a client device. The cost is real and stated: on a connection *behind* a CGNAT
that itself uses `100.64.0.0/10`, the overlay prefix can collide with the underlay's
next-hop/WAN address. Section 7.4 specifies detection and remediation for that case.

**Why ULA for IPv6, not a delegated GUA prefix.** A delegated global prefix would make overlay
addresses globally routable, which (a) requires TwinVPN to run address registry
infrastructure, (b) makes an overlay address a globally reachable target if any policy fails
open, and (c) ties address stability to a commercial allocation. ULA gives stability, zero
registry dependency, and is unroutable off-overlay by construction — a defense-in-depth
property that pairs well with I3. The cost: RFC 6724 default address-selection rules
de-prioritize ULA source addresses relative to GUA, which is handled explicitly in
[ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md) §11 via an installed policy-table row.

### 2.2 Address derivation and stability

- The IPv6 `/128` is **derived deterministically** from the `DeviceKey` public half:
  `addr = twinnet_prefix64 || truncate64(HKDF(pubkey, "twinvpn-v6-iid"))`, with the derived
  IID forced to have the universal/local bit clear (RFC 7136). It is therefore stable across
  roaming, reinstall, and re-pairing **as long as the `DeviceKey` is unchanged**, and it
  requires no allocator round-trip.
- The IPv4 `/32` **cannot** be derived (the space is too small to hash into without
  collisions), so it is allocated by the single authoritative allocator in the control plane
  (single-writer, per I8 and [ADR-0009](adr/ADR-0009-state-consistency.md)) and is **sticky**:
  a `Device` reclaims its previous `/32` on re-pair if it still holds the same
  `DeviceIdentity`. Released addresses are quarantined for ≥ 7 days before reuse so that
  stale peer caches and stale ACLs cannot silently re-target a different device.
- Both addresses are fields of the signed network contract
  ([ADR-0003](adr/ADR-0003-network-contract-schema-format.md)). **No DHCP, no DHCPv6, no
  SLAAC, and no Router Advertisements are used on the overlay interface.** RA is explicitly
  disabled on the overlay interface (`accept_ra=0` and equivalents) so that a hostile or
  confused peer cannot inject a route.

### 2.3 Address assignment sequence

```
DISCOVERING ──► control plane returns signed contract
                  { self: {v4: 100.x.y.z/32, v6: fdT:...::iid/128},
                    peers: [...], routes: [...], dns: {...}, mtu: 1280 }
                        │
                        ▼
              adapter creates interface DOWN
              install addresses (v4 + v6) statically
              install routes                      ◄── no DHCP round-trip, no timeout
              install DNS policy (ADR-0011)
              install firewall policy (ADR-0012)
                        │
                        ▼
              adapter brings interface UP  ── only now can traffic use it
```

The interface is created **down**, fully configured, then brought **up**. The ordering matters:
it means there is never a window in which the interface exists and is routable but has no
policy, which is the window in which PairVPN-class products leak. `BLOCKED`-state firewall
rules are installed *before* the interface comes up and are removed only after teardown
completes, so the fail-closed guarantee (I3) has no gap at either edge. Duration of the whole
sequence is bounded and measured; exceeding the bound is a structured diagnostic
(`NET.IFACE_BRINGUP_TIMEOUT`), never a hang.

### 2.4 Dual-stack behavior when the underlay is single-stack

| Underlay | Overlay v4 | Overlay v6 | Path family used | Notes |
|----------|-----------|------------|------------------|-------|
| IPv4 only | up | up | IPv4 underlay | Overlay v6 traffic is carried inside an IPv4-underlay tunnel |
| IPv6 only | up | up | IPv6 underlay | Overlay v4 traffic is carried inside an IPv6-underlay tunnel; **this is the single best NAT case** |
| Dual-stack | up | up | raced, IPv6 preferred (§4.1) | |
| NAT64/DNS64 only | up | up | IPv6 underlay to relay/peer; native v6 candidates preferred | Endpoint literals must be v6 or synthesized; see §3.8 |

The overlay's address family is completely decoupled from the underlay's. An application on an
IPv4-only network can talk to a peer's overlay IPv6 address, and vice versa.

## 3. NAT and path establishment

### 3.1 NAT behavior taxonomy

TwinVPN classifies middleboxes using RFC 4787 / RFC 5382 terms, **not** the obsolete
"full cone / restricted / symmetric" vocabulary, because mapping and filtering behavior are
independent axes and the old vocabulary conflates them. The legacy names are given only as a
cross-reference.

| Mapping behavior | Filtering behavior | Legacy name | Traversable? |
|---|---|---|---|
| Endpoint-Independent (EIM) | Endpoint-Independent (EIF) | Full cone | Trivially — peer can send unsolicited |
| EIM | Address-Dependent (ADF) | Address-restricted cone | Yes, after we send one packet toward the peer's address |
| EIM | Address-and-Port-Dependent (APDF) | Port-restricted cone | Yes, with simultaneous open |
| Address-and-Port-Dependent Mapping (APDM) | APDF | Symmetric | Only with port prediction, port mapping, or IPv6 |
| APDM behind carrier CGNAT | APDF + shared public IP | CGNAT | Usually not; **relay by design** |

Two further axes matter and are probed independently:

| Axis | Values | Why it matters |
|---|---|---|
| Mapping lifetime | measured, typically 30 s (mobile CGNAT) – 300 s (home CPE) | Sets keepalive cadence and therefore battery cost (§3.5) |
| Hairpinning (RFC 4787 REQ-9) | supported / not | Two peers behind the *same* NAT must reach each other via their reflexive addresses if the local L2 path is blocked (client isolation) |
| Port-mapping protocol | PCP / NAT-PMP / UPnP-IGD / none | An explicit mapping beats hole punching and survives symmetric mapping |
| UDP egress | open / port-limited / blocked | Blocked UDP means relay over a TCP-shaped transport |
| Path family | v4-only / v6-only / dual / NAT64 | IPv6 removes NAT from the problem entirely |

### 3.2 Traversability matrix (honest expectations)

Rows are the local `Device`; columns the remote. `D` = direct expected, `D*` = direct with
port prediction or port mapping (probabilistic), `R` = relay by design.

| | EIM/EIF | EIM/ADF | EIM/APDF | APDM | CGNAT | Native IPv6 |
|---|---|---|---|---|---|---|
| **EIM/EIF** | D | D | D | D* | D* | D |
| **EIM/ADF** | D | D | D | D* | D* | D |
| **EIM/APDF** | D | D | D | D* | R | D |
| **APDM** | D* | D* | D* | **R** | **R** | D |
| **CGNAT** | D* | D* | R | **R** | **R** | D |
| **Native IPv6** | D | D | D | D | D | **D** |

Read the last row and column first: **if both ends have working IPv6, every cell is `D`.**
This is the single highest-leverage fact in the whole traversal design and is why
[ADR-0004](adr/ADR-0004-nat-traversal-strategy.md) makes IPv6 the first-choice path rather
than a fallback. The genuinely hard cells — APDM↔APDM and CGNAT↔CGNAT over IPv4 only — are
declared **relay by design** (N4). They are not failures, they do not produce an error, and
they do not stall the state machine; they transition to `RELAYED` per `docs/reliability.md`.

### 3.3 Candidate gathering

A `ConnectionCandidate` is `{ family, ip, port, candidate_type, priority, source }`.

| `candidate_type` | How obtained | Typical priority |
|---|---|---|
| `HOST_V6_GLOBAL` | enumerate local interfaces, global/ULA-excluded IPv6 | 130 |
| `HOST_V6_LINKLOCAL` | link-local + scope id, LAN only | 126 |
| `HOST_V4_PRIVATE` | enumerate local interfaces | 120 |
| `SRFLX_V6` | reflexive address observed by the rendezvous service | 110 |
| `SRFLX_V4` | reflexive address observed by the rendezvous service | 100 |
| `PORTMAP_V4` | PCP (RFC 6887) → NAT-PMP → UPnP-IGDv2, in that order | 95 |
| `PREDICTED_V4` | birthday-paradox port prediction against APDM (§3.6) | 40 |
| `RELAY` | per [ADR-0005](adr/ADR-0005-relay-architecture.md) | 10 (always present) |

Rules:

1. A `RELAY` candidate is **always** gathered, in parallel, from the first millisecond. It is
   never gathered "after direct fails" — that ordering is exactly what produces the multi-second
   connect stalls in the defect list.
2. Candidate gathering has a hard deadline (default 3 s). Late candidates are still usable for
   an *upgrade* (§4.4) but never delay first-packet delivery.
3. Reflexive discovery uses the rendezvous service described in
   [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md). It observes the source
   address of an authenticated probe. It is **not** a plaintext STUN server, and it never
   sees tunnel plaintext (I1).
4. Candidates are exchanged through the signed contract / rendezvous path and are
   **authenticated**; an off-path attacker MUST NOT be able to inject a candidate and steer a
   path to itself. The authentication construction is derived per
   [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md).

### 3.4 The disco probe

Path establishment runs a small, dedicated probe exchange ("disco") multiplexed on the same
UDP socket as the tunnel data plane, distinguished by a leading type byte that cannot collide
with the tunnel protocol's message types.

```
PING  { tx_id, sender_device_id, sender_epoch }        → encrypted+authenticated to peer disco key
PONG  { tx_id, src_ip, src_port, receiver_epoch }      → echoes observed source = reflexive learn
CALL  { target_device_id }                             → via rendezvous, asks peer to punch back
```

- `PONG` echoing the observed source address gives free continuous reflexive-address
  refresh, so roaming is detected by the data plane itself, not by a control-plane poll.
  This is what satisfies I5: an established `Session` keeps re-validating and migrating paths
  with the control plane completely down.
- Probes are sent on **every** candidate pair simultaneously (not serially), which is what
  produces simultaneous open across APDF filtering without an explicit coordination round.
- Probe payloads are small (< 100 B) and rate-limited per peer to bound the amplification and
  battery cost.

### 3.5 Keepalives, mapping lifetime, and battery

A NAT mapping that expires silently is indistinguishable from a peer that vanished, and is a
major source of "random tunnel disconnects". TwinVPN **measures** the mapping lifetime instead
of guessing it.

| Phase | Behavior |
|---|---|
| Initial | Keepalive every **25 s** (safe under RFC 4787 REQ-5's 2-minute floor and under observed 30 s CGNAT timers) |
| Probing | After the path is stable, additively increase the interval (25 → 35 → 50 → 70 → 100 → 120 s), backing off to the last known-good value on the first mapping loss. Cap at 120 s. |
| Learned | Persist the learned lifetime keyed by *network fingerprint* (gateway MAC + BSSID + reflexive /24) so rejoining a known network starts at the right cadence immediately |
| Idle + battery-constrained | Suspend direct keepalives entirely; hold only the relay session, which the peer can use to wake us. Direct path is re-established on first packet or on peer `CALL`. |

Battery cost is explicit: a 25 s keepalive on a mobile radio is roughly 3,400 radio wakeups
per day per peer. The idle-suspend rule above is what keeps a 20-device `TwinNet` from
destroying a phone battery, and it is why the relay is treated as the always-available
signalling floor rather than a last resort.

### 3.6 Symmetric NAT, port prediction, and honest limits

Against APDM (symmetric) mapping, TwinVPN attempts, in order:

1. **IPv6.** If either end has working IPv6, the NAT is irrelevant. Try this first, always.
2. **Explicit port mapping.** PCP, then NAT-PMP, then UPnP-IGDv2. A successful mapping
   converts a symmetric NAT into an EIM/EIF-equivalent for that port. Requested lifetime
   3600 s, renewed at 50%. Failure is silent and fast (250 ms budget per protocol).
3. **Birthday-paradox port prediction.** Bounded, best-effort: open *k* sockets locally and
   probe *k* predicted remote ports. With `k = 256` on both sides against a NAT allocating
   ports uniformly at random, collision probability is high (>90%); against a NAT allocating
   ports *sequentially*, a much smaller delta-based prediction works. This is attempted at
   most once per path attempt, for at most 2 s, and **only** when the rendezvous service has
   observed the peer's mapping to be port-varying.
4. **Relay.** Not a failure. `RELAYED` per `docs/reliability.md`.

Port prediction is rate-limited and never runs against a target the peer has not consented to
probe, because a burst of 256 probes to sequential ports is indistinguishable from a port scan
and will trip IDS. This is a deliberate cap on aggressiveness.

### 3.7 UDP blocked, restrictive firewalls, captive portals

| Condition | Detection | Response | Reason code |
|---|---|---|---|
| UDP fully blocked | No `PONG` on any candidate incl. relay-over-UDP within 2 s, while TCP/443 to the rendezvous succeeds | Relay over a TCP-shaped transport (owned by [ADR-0005](adr/ADR-0005-relay-architecture.md)); direct paths marked unavailable for this network fingerprint | `NAT.UDP_BLOCKED` |
| Egress restricted to 80/443 | Same as above plus outbound 443 success only | Same as above | `NET.EGRESS_RESTRICTED` |
| Transparent HTTP proxy required | `CONNECT` needed for 443 | Relay via proxy per system proxy settings; **never** fall back to plaintext | `NET.PROXY_REQUIRED` |
| Captive portal | Unencrypted probe to a known endpoint returns a redirect / unexpected body, or DNS returns a portal address for a name with a known answer | Enter `BLOCKED` with `NET.CAPTIVE_PORTAL`; surface a portal-login affordance. **Whether a narrow, time-boxed, user-consented portal exemption is permitted is a kill-switch policy decision owned by [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md).** Networking provides the mechanism (a scoped exemption for the portal's address/DNS for ≤ 300 s); it does not decide the policy. | `NET.CAPTIVE_PORTAL` |
| Hairpinning unsupported, both peers behind one NAT | Local L2 probe fails, reflexive probe to the shared public IP fails | Use `RELAY`; do not spin | `NET.HAIRPIN_UNSUPPORTED` |

### 3.8 NAT64 / DNS64 and 464XLAT

On an IPv6-only access network with NAT64 (common on mobile carriers), an IPv4 endpoint
literal is unreachable directly.

- Native IPv6 candidates are preferred and usually sufficient (peer-to-peer, both on IPv6).
- If a peer or relay is reachable only by IPv4 literal, the client discovers the NAT64 prefix
  via RFC 7050 (`ipv4only.arpa`) or RFC 8781 (PREF64 in Router Advertisements — preferred,
  because it does not depend on DNS) and synthesizes an IPv6 candidate
  `pref64::/n + v4addr`.
- **TwinVPN never relies on DNS64 synthesizing addresses for it**, because the overlay's own
  resolver ([ADR-0011](adr/ADR-0011-dns-handling.md)) may be the one answering, and a resolver
  that both synthesizes and is tunneled produces a circular dependency at bring-up. The
  PREF64 discovery is done once per network fingerprint and cached.
- On 464XLAT handsets, the CLAT interface presents a working IPv4 stack; TwinVPN treats that
  as IPv4 but records `underlay=xlat` because the effective MTU is reduced (§6) and the NAT
  class is that of the carrier's NAT64, i.e. effectively CGNAT.

## 4. Path selection and path quality

### 4.1 Preference order

`LOCAL_DIRECT` > `WAN_DIRECT` > `RELAYED`, with family and quality tie-breaks:

```
score(path) = base(candidate_type)            # table in §3.3
            − rtt_penalty(ewma_rtt_ms)        # 1 point per ms, capped at 60
            − loss_penalty(loss_pct * 8)
            − jitter_penalty(ewma_jitter_ms / 2)
            + family_bonus(IPv6 ? 5 : 0)      # ties broken toward IPv6
            + stability_bonus(min(uptime_s / 60, 20))
```

The `stability_bonus` and the hysteresis rule below are deliberately conservative: flapping
between two near-equal paths is worse for the user than sitting on the slightly worse one,
and path flap is one of the observed causes of "random tunnel disconnects".

### 4.2 Quality signals

| Signal | Source | Window |
|---|---|---|
| RTT | disco `PING`/`PONG` round trip, plus data-plane keepalive timing | EWMA, α = 1/8 |
| RTT variance | as RFC 6298 | EWMA, β = 1/4 |
| Loss | probe sequence gaps + data-plane counters | sliding 30 s |
| Jitter | interarrival variance of keepalives | EWMA |
| Throughput | bytes/s achieved on the path when offered load is present | 10 s buckets, only valid under load |
| Stability | seconds since last path validation failure | monotonic |

Throughput is only ever measured **passively** under real offered load. TwinVPN does not run
synthetic bandwidth tests on user paths; the metered/battery cost is not justifiable and the
result is unreliable on shared links.

### 4.3 Promotion and demotion (mechanism only)

The state machine transitions themselves are owned by `docs/reliability.md`. Networking
supplies the *signals and the guards*:

| Guard | Value |
|---|---|
| `PATH_VALIDATED` | ≥ 2 successful `PING`/`PONG` on the candidate pair within 500 ms of each other |
| `PATH_BETTER` | candidate score exceeds the active path's by ≥ 15 points **and** ≥ 10 ms RTT improvement |
| `PATH_STABLE` | `PATH_BETTER` held continuously for ≥ 3 probe intervals (default 15 s) |
| `PATH_FAILING` | 3 consecutive missed keepalives, or loss > 15% over 10 s, or a data-plane send error |
| `PATH_DEGRADED` | path is carrying traffic but violating an objective (e.g. relay RTT > 250 ms (`docs/reliability.md` §5.4 owns the threshold) when a direct candidate is known-valid) → `DEGRADED`, with reason code |

### 4.4 Opportunistic upgrade from `RELAYED`

While `RELAYED`, direct-path probing **continues in the background** at a decaying cadence
(1 s, 2 s, 4 s, … capped at 60 s, reset on any network change event). When a direct candidate
satisfies `PATH_VALIDATED` and `PATH_STABLE`, the session migrates. Migration is
**make-before-break**: the new path is validated with real traffic before the old one is
retired, and both are held briefly so no packet is dropped at the switch. The session, keys,
and overlay addresses are unchanged across the migration (N2), so applications see nothing —
this is the whole point of decoupling overlay from underlay addressing.

Network-change events (new interface, new default route, RA received, Wi-Fi→cellular, VPN
reconfig, system wake) immediately reset the probe cadence and re-gather candidates. These are
delivered by the platform adapter (§5) — polling for network change is explicitly rejected as
a design, because it is both slow and a battery cost.

## 5. Platform network adapter

### 5.1 The adapter contract

Every platform implements one interface. Anything platform-specific lives behind it; nothing
above it may branch on OS. The contract is deliberately transactional, because partial
application is the leak window (§2.3).

```
create_interface(name, mtu)                     -> Handle   # created DOWN
apply(contract_generation) -> Result             # atomic: addrs + routes + dns + firewall
rollback(contract_generation)                    # restores prior generation exactly
set_link(up|down)
set_ruleset(BLOCKED|PROTECTED)                   # fail-closed rulesets, I3.
                                                 # Transitions are an ATOMIC SWAP between the two;
                                                 # rules are NEVER absent while the latch is UP
                                                 # (ADR-0012 KS-17).
subscribe_network_change(cb)                     # event-driven, never polled
query_link_facts() -> { mtu, families, default_routes, resolvers, metered, low_power }
destroy_interface()                              # idempotent; safe after crash
```

`apply` is all-or-nothing per contract generation and is idempotent on the generation id, so a
retry after a crash converges rather than duplicating routes — the mechanism that prevents the
"stale route / half-configured interface" class of failure. Idempotency semantics follow
[ADR-0008](adr/ADR-0008-idempotency.md).

### 5.2 Per-platform integration

| Platform | Minimum version | Datapath | Route/addr control | Firewall hook | Change events |
|---|---|---|---|---|---|
| Linux | kernel **5.6** (in-tree WireGuard); 5.4 with `wireguard-go` fallback | `wireguard` kernel module; `tun` for userspace fallback | netlink (`rtnetlink`, `RTM_NEWADDR`/`RTM_NEWROUTE`), policy routing table `52` + `fwmark` | **nftables** (`inet` family, one owned table `twinvpn`), `iptables-nft` shim on older distros | `RTNETLINK` multicast groups (`RTNLGRP_LINK`, `IPV4_IFADDR`, `IPV6_IFADDR`, `IPV4_ROUTE`, `IPV6_ROUTE`) |
| Windows | **Windows 10 21H2 / Server 2019** | **WinTun** (signed, shipped by us, versioned with the app) | `IP Helper` API (`CreateUnicastIpAddressEntry`, `CreateIpForwardEntry2`), interface metric | **WFP** sublayer at `FWPM_SUBLAYER` weight above Windows Firewall | `NotifyIpInterfaceChange`, `NotifyRouteChange2`, `NotifyUnicastIpAddressChange`, WNF network-status |
| macOS | **macOS 11 Big Sur** | NetworkExtension `NEPacketTunnelProvider` over `utun` | `NEPacketTunnelNetworkSettings` (IPv4/IPv6 settings objects) | `NEFilter`/system-provided default route + `pf` anchor for the app-scoped case | `NWPathMonitor`, `SCNetworkReachability` |
| iOS | **iOS 15** | `NEPacketTunnelProvider` in the app extension | `NEPacketTunnelNetworkSettings` only (no route API) | on-demand rules + settings; no host firewall available | `NWPathMonitor`, `NEProvider.sleep/wake` |
| Android | **API 26** min, **API 29** target behavior | `VpnService` + `ParcelFileDescriptor` tun | `VpnService.Builder` (`addAddress`, `addRoute`, `addDnsServer`, `addDisallowedApplication`) | none needed: `VpnService` route claim + `setBlocking` is the enforcement point | `ConnectivityManager.NetworkCallback`, `PowerManager` idle callbacks |
| OpenWrt / routers | OpenWrt **21.02** | in-tree `wireguard` | UCI `network` + netifd | `fw4`/nftables | `ubus` `network.interface` events |

### 5.3 Windows: the three defects, and how they are avoided

The defect list is disproportionately Windows-shaped. Each item gets a specific mechanism.

| Defect | Mechanism |
|---|---|
| **"Stale networking driver"** | Ship **WinTun** as a versioned, Microsoft-signed DLL+driver bundled with the app, loaded from the app's own directory, installed and uninstalled by the app. Never depend on a system-wide TAP driver installed by another product, and never leave an adapter behind on uninstall. On startup the adapter compares the loaded driver version against the shipped version and re-installs on mismatch, emitting `NET.DRIVER_REPLACED`. |
| **AV / firewall conflicts** | Use **WFP** rather than modifying Windows Firewall rules, and install into our **own sublayer** with a defined weight. This avoids fighting third-party AV that also writes firewall rules, makes our rules invisible to "reset firewall" actions, and makes teardown atomic (destroy the sublayer). If sublayer registration fails, the product enters `BLOCKED` with `NET.WFP_UNAVAILABLE` rather than running unprotected. |
| **Virtual-interface conflicts** | Adapters are named and GUID-stamped deterministically per install; on start, orphaned TwinVPN adapters (same GUID namespace, no owning process) are reclaimed rather than duplicated. Interface metric is set explicitly rather than left to automatic metric, so a competing VPN's adapter cannot silently outrank ours (or be outranked by ours without us knowing). |
| **Smart multi-homed name resolution** | Disabled for our interface scope via NRPT; see [ADR-0011](adr/ADR-0011-dns-handling.md). This is the classic Windows DNS-leak source. |

### 5.4 Background and suspended operation

> **Scope and ownership.** Retitled from *"Mobile background operation"* in step with
> [docs/reliability.md](reliability.md) §11: **Windows Modern Standby, macOS Power Nap and ordinary
> laptop suspend are the same class of problem** as Doze and App Standby, and the old title is why the
> desktop cases went unchecked. This table specifies what the client **does**; **who decides that it is
> backgrounded** is [docs/reliability.md](reliability.md) **R-BG-1**, and the per-platform event source
> — including synthesis where the OS provides none — is
> [ADR-0022](adr/ADR-0022-application-lifecycle-and-background-execution.md) LC-23a.


| Platform | Hazard | Mechanism |
|---|---|---|
| iOS | Extension is suspended/killed; sockets closed without notice | `NEPacketTunnelProvider` with `includeAllNetworks` where policy demands full protection; on-demand rules to restart the tunnel on network change; on `wake`, immediately re-validate every path rather than assuming continuity; treat every wake as a network-change event |
| iOS / iPadOS | Memory limit on the network extension (tight) | **Corrected — the original wording of this row was a defect.** It read "contract **fetch**/parse and diagnostics live in the app process", and an implementation following it literally builds a deadlock: under `includeAllNetworks` the app process has **no network**, because its traffic is [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) class 1/2 protected and dropped, and it cannot match class 7 — KS-9(1)'s predicate names the **provider**, and iOS has no host firewall to carry an exemption. So the fetch fails exactly when the contract is most needed, and fails silently from the extension's point of view. **The extension FETCHES** (it holds the exempted socket) and hands raw bytes to the app; the app **PARSES AND VERIFIES**. This still discharges the row's intent, because the memory pressure it protects against lives in parse-and-verify — a signature check and a CBOR decode over a multi-KB document — not in fetch, which costs a socket and a buffer |
| Android | Doze / App Standby suspends timers | Keepalives scheduled via the tunnel socket's own kernel-side timer where possible, not app-side alarms; a foreground service with a persistent notification for user-initiated sessions; `setUnderlyingNetworks` kept current so the system accounts and routes correctly across Wi-Fi/cellular handoff |
| Android | Always-on VPN + "Block connections without VPN" (lockdown) | Supported and **recommended** as the platform-native expression of I3. **Corrected: "the app detects whether it is enabled" cannot be built.** For a non-DPC app on Android 10+ there is no API exposing lockdown state, and the obvious in-app probe is **invalid by construction** — under lockdown *our own* sockets are the permitted ones, so a successful reachability test proves nothing. The posture is therefore **three-valued**: `LOCKDOWN_CONFIRMED` (a DPC or managed configuration reports it), `LOCKDOWN_ABSENT` (positively determined), or **`LOCKDOWN_UNVERIFIED`**, which MUST present as **unprotected** — the fail-closed direction. [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.6's limitation table consumes this three-valued posture, not a boolean |
| Both | Roaming Wi-Fi ↔ cellular | Underlay change does not touch overlay addressing (N2); path re-validation + make-before-break migration (§4.4). `MIGRATING`, not `RECONNECTING`. |

### 5.5 Coexistence rules (all platforms)

1. TwinVPN MUST NOT delete or modify routes it did not create. Conflicts are detected and
   reported (§7.4), never resolved by clobbering.
2. TwinVPN MUST NOT disable the host firewall, the host resolver service, or IPv6 globally.
   "Turn off IPv6 to prevent leaks" is an anti-pattern: it breaks IPv6-only networks, it is
   not restored reliably after a crash, and it is user-visible damage. IPv6 is **blocked at
   the policy layer**, per [ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md).
3. All state written outside our own interface (firewall tables, resolver config, policy
   routing rules) MUST be tagged with an owner marker and MUST be reclaimable by a fresh
   process after an unclean exit. A crash must not leave the host either unprotected **or**
   permanently broken.
   **Which process may reclaim it is not open (clarified).** "A fresh process" as originally
   written names no predicate, and owner-tagged state includes the enforcement rule set — so an
   unqualified reclaim right is a disarm primitive available to anything that can start a process.
   Reclaim MUST be gated on **both** the privilege required to have written the state **and** a
   matching **code signature / package identity**, per
   [ADR-0016](adr/ADR-0016-client-process-and-privilege-separation.md) PS-8. A process that holds
   the privilege but does not match the signature MUST refuse the reclaim and report
   `PLATFORM.PRIV.HELPER_UNTRUSTED` rather than adopting the state.
4. Running concurrently with another VPN is **supported but not silently**: detection of a
   second default-route-claiming interface emits `NET.CONCURRENT_VPN` with the competing
   interface named, and the interface-metric relationship is reported rather than forced.

## 6. MTU and fragmentation

### 6.1 Overhead accounting

| Path | Underlay framing | Tunnel hdr + tag | Relay hdr | Total overhead | Overlay MTU at 1500 |
|---|---|---|---|---|---|
| IPv4 direct | 20 IP + 8 UDP | 32 | — | **60** | **1440** |
| IPv6 direct | 40 IP + 8 UDP | 32 | — | **80** | **1420** |
| IPv4 relayed, `R-UDP` | 20 IP + 8 UDP | 32 | 16 | **76** | **1424** |
| IPv6 relayed, `R-UDP` | 40 IP + 8 UDP | 32 | 16 | **96** | **1404** |
| IPv4 relayed, `R-QUIC` | 20 IP + 8 UDP + 28 QUIC | 32 | 16 | **104** | **1396** |
| IPv6 relayed, `R-QUIC` | 40 IP + 8 UDP + 28 QUIC | 32 | 16 | **124** | **1376** |
| IPv4 relayed, `R-TLS` | 20 IP + 20 TCP + 24 TLS | 32 | 16 | **112** | **1388** |
| IPv6 relayed, `R-TLS` | 40 IP + 20 TCP + 24 TLS | 32 | 16 | **132** | **1368** |
| `R-TLS` with TCP timestamps | +12 B TCP options | | | +12 | −12 |
| Over PPPoE (1492) / 464XLAT (1480) | underlay MTU lower | | | — | correspondingly lower |

Tunnel overhead is the WireGuard-shaped **32 bytes** (16 B data header + 16 B AEAD tag) fixed by
[ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.2. Relay overhead is
the **16 B** `RelayFrame` header of [ADR-0005](adr/ADR-0005-relay-architecture.md) §9.1 — better
than the ≤ 32 B this document originally assumed (A2) — plus each carriage's own record framing,
which for `R-QUIC` and `R-TLS` exceeds 32 B because TLS and QUIC record overhead is unavoidable.
**These are ceilings.** The operative MTU is whatever DPLPMTUD (§6.2) confirms; the 1280 floor
always holds, and every row above clears it with ≥ 88 B of margin. A carriage that cannot carry a
1280-byte overlay packet MUST be abandoned with `RELAY.MTU_FLOOR_VIOLATED`.

### 6.2 The decision: 1280 floor + DPLPMTUD, never classic PMTUD

The overlay interface MTU is set to **1280** at bring-up and raised afterwards.

- **1280** is the IPv6 minimum link MTU (RFC 8200). A 1280-byte overlay MTU can be carried
  over any conceivable underlay path in the wild without fragmentation. It is a floor that is
  *always correct*, which means bring-up never has to wait for discovery — no stall.
- The MTU is then raised by **DPLPMTUD (RFC 8899)** — Packetization Layer Path MTU Discovery.
  Probe packets of increasing size are sent as ordinary padded tunnel keepalives with DF/no-frag
  set; success is inferred from an **acknowledgement**, not from the absence of an ICMP error.
- **This is the mechanism that retires the "MTU black hole" defect.** Classic PMTUD (RFC 1191 /
  RFC 8201) depends on receiving ICMP "Fragmentation Needed" / ICMPv6 "Packet Too Big" from a
  router, and those are filtered by a large fraction of real networks. DPLPMTUD requires no
  ICMP at all. ICMP PTB, when it arrives, is treated as a *hint that triggers an immediate
  downward probe*, never as an authoritative instruction.
- Search: binary search between the confirmed floor and the candidate ceiling (link MTU −
  overhead), 4 probes per step, 15 s between raise attempts, re-run on every network-change
  event and every path migration. Per-path MTU is cached keyed by
  `(peer, candidate_type, network_fingerprint)`.

### 6.3 ICMP handling

| Case | Behavior |
|---|---|
| ICMPv6 PTB received, quoting a packet we sent | Validate the quoted inner header against our send history; if valid, clamp immediately and start a downward DPLPMTUD search. Never accept a PTB below 1280. |
| ICMPv4 Frag-Needed received | Same validation; never accept below 576, and never below our 1280 floor for the overlay. |
| Unvalidated / unquoted ICMP | Discarded. Blind PTB is a known off-path attack. |
| ICMP fully filtered | Irrelevant: DPLPMTUD does not need it. |
| ICMP generated **by** us | An `ExitNode`/`LANGateway` MUST generate ICMPv6 PTB and ICMPv4 Frag-Needed toward overlay clients when forwarding requires it, and MUST NOT have those messages silently dropped by its own firewall policy — a gateway that eats ICMP creates black holes for everyone behind it. |

### 6.4 TCP MSS clamping

At every forwarding point (`ExitNode`, `LANGateway`), TCP SYN/SYN-ACK MSS is clamped to
`path_mtu − 40` (IPv4) / `path_mtu − 60` (IPv6) in both directions. MSS clamping is a coarse
tool that only helps TCP, so it is a **complement** to DPLPMTUD, not a substitute — UDP-based
protocols (QUIC, DNS over UDP, WireGuard-in-WireGuard) get correct behavior only from the
1280 floor plus DPLPMTUD.

### 6.5 Fragmentation policy

- Overlay IPv6 packets are **never** fragmented by TwinVPN (RFC 8200 forbids on-path
  fragmentation); oversize packets produce a PTB toward the sender.
- Underlay UDP encapsulation sets DF (IPv4) and never uses IPv6 fragment headers. If a tunnel
  packet cannot fit, the *overlay* MTU was wrong and DPLPMTUD corrects it; we do not paper
  over it with underlay fragmentation, which is a throughput and reliability disaster on
  lossy links (one lost fragment kills the whole datagram).

## 7. Routing modes

### 7.1 The four modes

| Mode | What is routed into the tunnel | Typical use |
|---|---|---|
| **TwinNet-only** (default) | Only the overlay prefixes: the `TwinNet` `/22`(s) and `/64` | Remote access to your own devices without touching your Internet path |
| **Split tunnel** | Overlay prefixes plus explicitly advertised `Route`s (LAN subnets) | Reaching a home/office LAN through a `LANGateway` |
| **Full tunnel (exit node)** | Default routes for **both** families, via a chosen `ExitNode` | Untrusted Wi-Fi; egress from another country |
| **Per-app** | Platform-scoped: only selected applications' traffic | Android (`addAllowedApplication`/`addDisallowedApplication`), Windows (WFP app-id filters), macOS (app-scoped `NETransparentProxy`). **Not available on iOS or Linux**; requesting it there is a configuration error with `NET.PERAPP_UNSUPPORTED`, not a silent downgrade. |

### 7.2 Default-route installation without destroying the host's default route

Full-tunnel mode installs **two /1 routes per family** rather than replacing the default:

```
0.0.0.0/1      via <overlay v4 gw>   dev twin0
128.0.0.0/1    via <overlay v4 gw>   dev twin0
::/1           via <overlay v6 gw>   dev twin0
8000::/1       via <overlay v6 gw>   dev twin0
```

These are more specific than `0.0.0.0/0` and `::/0`, so they win by longest-prefix match while
the host's real default route stays installed and untouched. Consequences:

1. Teardown is trivial and complete — delete four routes; the host's connectivity is exactly
   as it was. No "restore the default route" logic that can fail after a crash.
2. The underlay path to the peer/relay endpoint still resolves via the host default route,
   so there is no routing loop. The tunnel's own encapsulated packets are additionally pinned
   with a policy-routing rule (Linux: `fwmark` + table 52 with a suppress rule; other
   platforms: bind the tunnel socket to the underlay interface), which is the real loop
   guard — the /1 trick alone is not sufficient.
3. **The /1 routes are a routing convenience, not a security control.** The security control
   is the fail-closed firewall layer (§9). Anything that installs its own more-specific route,
   or binds to a specific source address, or uses a raw socket, defeats routing but not the
   firewall. This distinction is the load-bearing one for I3.

### 7.3 Route advertisement and acceptance

- A `LANGateway` **advertises** `Route`s (e.g. `192.168.7.0/24`, `2001:db8:7::/64`); a client
  **accepts** them only if (a) the contract is signed, (b) the `AccessPolicy` grants it, and
  (c) the user has enabled acceptance for that route. Advertised ≠ installed: acceptance is an
  explicit, per-route, per-client decision. Auto-accepting arbitrary advertised prefixes would
  let a compromised peer hijack `0.0.0.0/0`.
- Advertising `0.0.0.0/0` or `::/0` is **only** legal from an `ExitNode`, and is only honored
  when the client has explicitly selected that exit node. A `LANGateway` advertising a default
  route is rejected with `ROUTE.SCOPE_VIOLATION`.
- A gateway MUST advertise both families or explicitly declare single-family. A gateway that
  advertises `192.168.7.0/24` but not the site's IPv6 prefix creates a partial-coverage hole;
  the client surfaces `NET.ROUTE_FAMILY_ASYMMETRY` rather than pretending the site is covered.

### 7.4 Route conflicts (the common real-world case)

Overlapping RFC 1918 is the normal case, not the exception: two homes on `192.168.1.0/24`, or
a client already on `192.168.1.0/24` accepting a gateway that advertises the same.

Precedence rules, applied at contract-install time, before anything is installed:

| # | Rule |
|---|---|
| P1 | Longest prefix match always wins at the forwarding level; we never install two identical prefixes. |
| P2 | An **on-link physical LAN prefix beats an advertised overlay route of the same or shorter length**, by default. Breaking the user's own printer/NAS to reach a remote one is the wrong default. |
| P3 | An explicit per-prefix user pin overrides P2 in either direction. |
| P4 | Between two advertised routes of equal length from different gateways, the one with the better measured path wins; ties break on gateway priority in the contract. |
| P5 | A conflict is **always** surfaced as a structured diagnostic naming both prefixes, both sources, and which one was installed. Silent resolution is forbidden (I6). |

Remediation options offered to the user, in increasing order of intrusiveness:

1. **Do nothing** — the local LAN wins, the remote site is unreachable for that prefix, and
   the reason is displayed. (Default.)
2. **Host-route pin** — install `/32`/`/128` routes for the specific remote hosts the user
   actually needs; these beat the on-link `/24` by longest match without shadowing the LAN.
3. **Site remap** — the `LANGateway` presents its conflicting site inside a synthetic,
   non-conflicting IPv6 prefix: the site's `192.168.1.0/24` is exposed as
   `fdT:...:site:<site-id>:0:0:c0a8:0100/120`, i.e. the IPv4 address embedded in the low 32
   bits of a per-site `/96`. The gateway performs stateless translation on the way in. Two
   sites with identical IPv4 space then coexist because their overlay representations differ.
   This is IPv6-only by construction and is the reason a ULA `/48` with room for per-site
   `/96`s was chosen in §2.1.
4. **Gateway-side NAT** — the `LANGateway` masquerades overlay clients into its LAN. Loses
   client-IP attribution at the site; offered last, never default.

### 7.5 CGNAT-space collision with the overlay's own IPv4 prefix

If the underlay itself uses `100.64.0.0/10` (the client is behind carrier CGNAT that assigns
from it), a `/32` in the overlay could shadow the underlay's next hop.

- Detection: at bring-up, compare on-link underlay prefixes and the underlay default gateway
  against the assigned `TwinNet` `/22`(s).
- Response: the control plane allocates from a **different `/22`** within `100.64.0.0/10` that
  does not overlap the observed underlay prefix, and the client requests reallocation
  (`NET.OVERLAY_PREFIX_COLLISION`). Because per-`TwinNet` allocation is a `/22` out of a `/10`
  (4096 blocks), avoiding a specific colliding `/24` is always possible.
- Underlay-specific host routes for the peer/relay endpoints are installed regardless, so the
  underlay path survives even during the window before reallocation.
- The IPv6 side cannot collide this way (a ULA `/48` under our fixed global ID is ours alone),
  which is a further argument for treating IPv6 as the primary overlay family.

### 7.6 Multi-client gateway forwarding (I7)

A `LANGateway`/`ExitNode` is a router, not a peer with a special flag:

- Forwarding is enabled for both families (`net.ipv4.ip_forward`, `net.ipv6.conf.all.forwarding`
  and equivalents), scoped to the overlay interface.
- Per-peer `AccessPolicy` is enforced on the forwarding path (source overlay address →
  permitted destination prefixes/ports), not merely at connection setup, so revocation takes
  effect on the next packet.
- Reverse-path filtering is configured to not drop overlay-sourced traffic
  (Linux `rp_filter=2` loose mode on the overlay interface, or explicit policy routing).
- Conntrack/NAT state, when gateway NAT is in use, is sized for many concurrent peers and
  its exhaustion is a first-class observable, not a mystery stall. Detailed capacity model is
  owned by [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md).

## 8. LAN discovery

Peers on the same L2 segment should use `LOCAL_DIRECT` — it is faster, cheaper, works with the
Internet down, and keeps traffic off the WAN.

### 8.1 Mechanism

| Property | Value |
|---|---|
| Transport | UDP to `224.0.0.<x>:<port>` (IPv4 local-scope multicast) and `ff02::<x>:<port>` (IPv6 link-local multicast), plus IPv4 subnet broadcast as a fallback for networks that drop multicast |
| Cadence | On network-change, then 1 s / 2 s / 4 s / 8 s, then every 60 s while idle |
| Payload | `{ disco_id, port, proto_version }` — **no** device name, no owner identity, no public key in the clear |
| `disco_id` | `truncate(HMAC(twinnet_discovery_key, floor(unix_time / 3600)))` — a rotating, salted identifier derived from a `TwinNet`-scoped key. Only a peer that already holds the `TwinNet` key can recognize it. |
| Verification | A recognized `disco_id` is only a *hint*; the peer is not trusted until an authenticated disco `PING`/`PONG` succeeds against its `DeviceKey`. Discovery cannot authorize anything. |
| Failure mode | Wireless client isolation, multicast-suppressing APs, and guest VLANs silently break L2 discovery. Detection is by absence; the response is to fall through to `WAN_DIRECT`/`RELAYED` without delay, with `NET.LAN_DISCOVERY_UNAVAILABLE` recorded as an informational (not error) diagnostic. |

mDNS/DNS-SD is **not** used for peer discovery. It would broadcast device names and service
records to every device on an untrusted LAN, including a coffee-shop network.

### 8.2 Privacy consequences (stated plainly)

1. Anyone on the same L2 segment can observe that *a* TwinVPN device is present, from the
   packet's port and shape. This is unavoidable for any LAN discovery scheme and is disclosed.
2. Because `disco_id` rotates hourly and is keyed to the `TwinNet`, an observer cannot use it
   to correlate the same device across networks or across time, and cannot enumerate a
   `TwinNet`'s membership.
3. The rotation window (1 hour) is a deliberate tradeoff: shorter windows leak less but break
   discovery across clock skew. Implementations MUST accept the previous and next window's
   `disco_id` to tolerate ±1 hour of skew.
4. LAN discovery MUST be individually disableable, and MUST default to **off** on networks
   the user has marked untrusted (public/metered profiles where the platform exposes that).

## 9. Networking mechanism for leak prevention

**Policy ownership.** *Whether* traffic is blocked, when, and with what user-visible
affordances is decided by [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) (owner:
SECURITY). This section specifies only the *networking mechanism* that ADR-0012 can rely on.
If ADR-0012 chooses a different policy, these mechanisms still implement it; if it requires a
mechanism not listed here, that is a gap to reconcile.

### 9.1 The four leak channels and their mechanism

| Channel | Mechanism |
|---|---|
| **IPv4 egress outside the tunnel** | Default-deny egress on all non-overlay interfaces, with a narrow allow-list for the tunnel's own encapsulated packets (matched by socket owner / `fwmark` / WFP app-id, not by destination address), DHCP on the underlay, and (if ADR-0012 permits) the captive-portal exemption. |
| **IPv6 egress outside the tunnel** | The **same rule set, in the same table, added at the same instant**. The nftables `inet` family, the WFP filter set, and the `VpnService` route claim all cover both families in one object, so it is structurally impossible to install v4 protection without v6 protection. This is the mechanism for I3 + the IPv6-leak requirement; see [ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md) §11. |
| **IPv6 enabled *after* the tunnel is up** (RA arrives on a new interface, tethering starts, a VM bridge appears) | Rules are **interface-scoped and default-deny**, never destination-prefix allow-lists. A newly appearing interface or a newly learned prefix is denied by the pre-existing rule because it is not the overlay interface — no rule update is required for correctness. The network-change subscription (§5.1) additionally triggers a policy re-assertion within 1 s, which is belt-and-braces, not the primary guarantee. |
| **DNS** | See [ADR-0011](adr/ADR-0011-dns-handling.md) §11: stub resolver + platform split-DNS + port-53 containment + `BLOCKED`-state SERVFAIL with an Extended DNS Error. |

### 9.2 IPv4-only tunnel on an IPv6-capable host

If the negotiated tunnel or the selected `ExitNode` supports only IPv4 (e.g. an older peer per
[ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md)), the host's IPv6
MUST be **blocked**, not left open and not globally disabled:

- Blocked: `::/0` egress denied on non-overlay interfaces for protected traffic.
- Not "disabled": we never set `net.ipv6.conf.all.disable_ipv6=1` or unbind the Windows IPv6
  stack. That is destructive, survives crashes badly, and breaks IPv6-only underlays.
- The resulting state is `DEGRADED` with `POLICY.LEAK.IPV6_UNPROTECTED`, which is
  user-visible: the user is told IPv6 destinations are unreachable and why. Silently working
  "mostly" is the defect we are retiring.

### 9.3 Ordering guarantees

```
set_ruleset(BLOCKED) ──► rules live ──► create iface ──► apply(contract) ──► link up
      ──► path validated + ProtectionAssertion for BOTH families (ADR-0012 KS-18)
      ──► set_ruleset(PROTECTED)      # atomic swap, never a removal
                                                                            ▲
teardown:  link down ──► destroy iface ──► (rules stay live if kill switch on) ─┘
```

The fail-closed ruleset is live **before** the interface exists and stays live **after** it is
destroyed. There is no ordering in which protected traffic can find an open path during a
transition, including a crash (the rules are owner-tagged and reclaimed, §5.5.3).

## 10. Diagnostics contract (I6)

Every networking reason code is stable and spelled in [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2's canonical dotted form (`NET.*`, `NAT.*`, `ROUTE.*` by owning domain), and carries structured context.
The transport, schema, and redaction rules are owned by
[ADR-0015](adr/ADR-0015-observability-and-diagnostics.md); the codes below are the networking
vocabulary it must carry.

| Code | Meaning | Actionable text conveys |
|---|---|---|
| `NET.NAT_CLASS_OBSERVED` | informational: measured mapping/filtering class both ends | why direct did or did not work |
| `NAT.UDP_BLOCKED` | no UDP egress | network blocks UDP; relay in use; expect higher latency |
| `NET.EGRESS_RESTRICTED` | only 80/443 out | as above |
| `NET.PROXY_REQUIRED` | explicit proxy needed | proxy host; whether credentials are needed |
| `NET.CAPTIVE_PORTAL` | portal intercepting | sign in to the network first |
| `NET.HAIRPIN_UNSUPPORTED` | same-NAT peers can't loop back | using relay although peers are adjacent |
| `NAT.SYMMETRIC_BOTH_ENDS` | APDM↔APDM | direct impossible on IPv4; enable IPv6 or accept relay |
| `NET.PORTMAP_FAILED` | PCP/NAT-PMP/UPnP unavailable | enabling UPnP/PCP on the router would allow direct |
| `NET.MTU_CLAMPED` | DPLPMTUD settled below link MTU | effective MTU and where it was lost |
| `NET.MTU_BLACKHOLE_DETECTED` | large packets lost, no ICMP | clamped automatically; no user action needed |
| `ROUTE.CONFLICT_UNRESOLVED` | overlapping prefix | both prefixes, both sources, which won, remedies (§7.4) |
| `ROUTE.SCOPE_VIOLATION` | non-exit node advertised a default route | which peer; rejected |
| `NET.ROUTE_FAMILY_ASYMMETRY` | gateway covers one family only | which family is uncovered |
| `NET.OVERLAY_PREFIX_COLLISION` | overlay `/22` overlaps underlay CGNAT space | reallocation in progress |
| `NET.IFACE_BRINGUP_TIMEOUT` | adapter apply exceeded budget | which step (addr/route/dns/firewall) |
| `NET.DRIVER_REPLACED` | WinTun version mismatch corrected | informational |
| `NET.WFP_UNAVAILABLE` | could not install WFP sublayer | fail-closed; likely AV conflict; name the conflicting product if determinable |
| `NET.CONCURRENT_VPN` | another default-route VPN present | which interface; interaction expectations |
| `NET.PERAPP_UNSUPPORTED` | per-app routing requested on a platform without it | configuration rejected |
| `POLICY.LEAK.IPV6_UNPROTECTED` | tunnel is v4-only; v6 blocked | v6 destinations unreachable, and why |
| `NET.LAN_DISCOVERY_UNAVAILABLE` | multicast suppressed | informational; using WAN/relay path |

## 11. Assumptions about other agents' decisions

These are load-bearing. If any is wrong, this document needs an edit.

| # | Assumption | Owner to confirm |
|---|---|---|
| A1 | The tunnel data plane is a WireGuard/Noise-shaped UDP protocol with ~32 B per-packet overhead, supports rekeying without changing the overlay addresses, and permits multiplexing a small disco message type on the same socket. | [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) |
| A2 | The relay presents a **UDP-shaped** primary transport plus at least one TCP/443-shaped fallback, adds ≤ 32 B of header, and is available as a candidate from t=0. | [ADR-0005](adr/ADR-0005-relay-architecture.md) — **REFINED and applied.** `R-UDP` adds **16 B**, better than assumed. The ≤ 32 B bound is **overruled** for `R-QUIC` (28 B of QUIC framing) and `R-TLS` (24 B of TLS record framing) on top of the 16 B `RelayFrame`; §6.1 above now carries all eight exact per-carriage rows. UDP-primary, TCP/443 fallback and candidate-from-t=0 are all confirmed. |
| A3 | The signed contract is applied atomically per generation with a monotonic `contract_seq`, and carries the address/route/DNS fields in §2.3. | [ADR-0003](adr/ADR-0003-network-contract-schema-format.md) |
| A4 | The state machine treats relay fallback as a normal transition, exposes `MIGRATING` for make-before-break path changes, and owns all retry/backoff timers. Networking supplies guards, not transitions. | `docs/reliability.md` |
| A5 | The kill switch's enforcement point is the mechanism in §9, and ADR-0012 does **not** require TwinVPN to disable the host IPv6 stack or the host firewall. | [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) |
| A6 | A rendezvous service exists that can (a) report an authenticated peer's observed source address and (b) deliver a `CALL` to a peer, and is not required for an established session to survive (I5). | [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) |
| A7 | Capability negotiation can express `ipv6_underlay`, `dplpmtud`, `portmap`, `site_remap`, and `per_app_routing` so that a mixed-version `TwinNet` degrades explicitly rather than silently. | [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) |
