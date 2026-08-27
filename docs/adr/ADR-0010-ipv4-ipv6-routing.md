# ADR-0010: IPv4/IPv6 Addressing and Routing

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** NETWORKING
- **Related:** [ADR-0003](ADR-0003-network-contract-schema-format.md),
  [ADR-0004](ADR-0004-nat-traversal-strategy.md),
  [ADR-0008](ADR-0008-idempotency.md), [ADR-0009](ADR-0009-state-consistency.md),
  [ADR-0011](ADR-0011-dns-handling.md),
  [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md),
  [ADR-0013](ADR-0013-multi-client-gateway-architecture.md),
  [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md),
  [ADR-0015](ADR-0015-observability-and-diagnostics.md),
  [docs/networking.md](../networking.md), [docs/reliability.md](../reliability.md),
  [docs/threat-model.md](../threat-model.md)

## 1. Context

Every `Device` in a `TwinNet` needs an address that other devices can use, that survives
roaming and re-pairing, that does not collide with the LANs those devices actually sit on, and
that works identically whether the underlay is IPv4-only, IPv6-only, or dual-stack. Every
`Device` also needs routes installed on a host OS that already has its own routes, its own
default gateway, possibly another VPN, and — critically — an IPv6 stack that a naive VPN
implementation will leave completely unprotected.

The defect list contains "IPv4/IPv6/DNS leaks", "DHCP and route-establishment stalls", "poor
roaming", and "virtual-interface conflicts". All four are addressing-and-routing defects. The
worst of them is the IPv6 leak: a product that installs an IPv4 default route and ignores IPv6
sends every IPv6-reachable destination — which today includes most large services — outside the
tunnel, while showing the user a connected indicator. Under **I3** that is not a bug to fix
later; it is the definition of a security defect.

This ADR decides the overlay address plan, the dual-stack policy, the route installation
mechanism, route precedence, and — normatively — **the mechanism that makes it impossible for
IPv6 to bypass tunnel policy**. It does not decide the kill switch's *policy*
([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)) or DNS
([ADR-0011](ADR-0011-dns-handling.md)).

## 2. Requirements


**Requirements discharged** ([docs/vision.md](../vision.md) §5): **R-03** (deterministic per-`Device` addressing in both families, with no DHCP anywhere in the datapath), **R-14** (IPv6 is carried and protected with the same rigor as IPv4 — a v4-only guard is a leak), **R-15** (routing imposes no per-packet cost beyond the kernel's own lookup), and **R-17** (route conflicts with pre-existing system routes surface as named diagnostics, never as a silent overwrite).
| # | Requirement |
|---|---|
| R1 | Every `Device` MUST have both an IPv4 and an IPv6 overlay address, always, regardless of underlay family. |
| R2 | Overlay addresses MUST be stable across roaming, reboot, reinstall, and re-pairing, for the life of the `DeviceIdentity`. |
| R3 | Address assignment MUST NOT introduce a bring-up round trip that can stall (no DHCP/DHCPv6/SLAAC on the overlay). |
| R4 | The overlay prefix MUST NOT collide with the LANs real users are on, in the common case. |
| R5 | Route installation MUST be atomic per contract generation and fully reversible, including after an unclean process exit. |
| R6 | **IPv6 MUST NOT be able to bypass tunnel policy** — including when IPv6 appears *after* the tunnel is up, and when the tunnel itself is IPv4-only. |
| R7 | Route conflicts with the host's real LAN MUST be detected and surfaced, never silently resolved (I6). |
| R8 | Dual-stack destination selection MUST be fast and MUST NOT stall on a broken family. |
| R9 | The design MUST work on IPv6-only access networks with NAT64/DNS64 and on 464XLAT handsets. |
| R10 | A `LANGateway`/`ExitNode` MUST route for many peers concurrently (I7). |

## 3. Constraints

- **I3** — fail closed. Any addressing/routing choice that can leave a family unprotected is
  disqualified.
- **I8** — the overlay address allocator is a single-writer authority; clients hold a cache.
- **I6** — conflicts and degradations must be observable with stable reason codes.
- No host-global destructive changes: TwinVPN MUST NOT disable the host IPv6 stack, MUST NOT
  disable the host firewall, and MUST NOT delete routes it did not create (`docs/networking.md`
  §5.5).
- iOS exposes no route API — only `NEPacketTunnelNetworkSettings`. Android exposes only
  `VpnService.Builder`. The design must be expressible in those terms, not only in netlink.
- The IPv4 overlay space must be small enough to be allocable but large enough for realistic
  `TwinNet` sizes and per-site remapping.

## 4. Considered Alternatives

| # | Alternative |
|---|---|
| **A** | **RFC 1918 overlay, dynamically assigned.** Overlay uses `10.0.0.0/8`; addresses assigned by DHCP/DHCPv6 on the overlay interface; IPv6 via SLAAC from a ULA prefix advertised by RA. |
| **B** | **RFC 6598 `100.64.0.0/10` for IPv4 + a fixed product ULA `/48` for IPv6, both statically assigned in the signed contract.** IPv6 IID derived from the `DeviceKey`; IPv4 `/32` allocated by the control plane and sticky. |
| **C** | **IPv6-only overlay.** Devices get only an overlay IPv6 address; legacy IPv4 applications are served by a local NAT46/CLAT-style shim that synthesizes IPv4 addresses locally. |
| **D** | **Delegated global unicast (GUA) prefix.** TwinVPN obtains a real IPv6 allocation and assigns globally routable overlay addresses; IPv4 still from RFC 6598. |
| **E** | **No overlay addressing.** Devices keep their existing LAN addresses; the tunnel is a site-to-site router and peers address each other by their real LAN addresses, with per-site NAT to resolve overlaps. |

Route installation, treated as a sub-decision inside each: replace the host default route vs.
install two `/1` (and `::/1` + `8000::/1`) routes vs. use policy routing exclusively.

## 5. Advantages of Each Alternative

**A — RFC 1918 + dynamic.** Universally familiar; every tool, every firewall rule syntax, every
admin already understands `10.x`. DHCP is a solved, ubiquitous mechanism with mature client
code on every platform. SLAAC + RA is the native IPv6 way to number a link and needs no
allocator service. Trivially large address space for IPv4.

**B — RFC 6598 + fixed ULA, static.** `100.64.0.0/10` essentially never appears as a client LAN
prefix, so R4 is satisfied by construction against the two prefixes that actually collide
(`192.168.0.0/16`, `10.0.0.0/8`). Static assignment from the signed contract removes the entire
DHCP round-trip and its stall modes (R3) and makes bring-up a pure local operation. A
`DeviceKey`-derived IPv6 IID gives R2 for free with no allocator round trip and no allocator
state to lose. A single fixed ULA `/48` gives us a private, unroutable, collision-free IPv6
space with room for per-`TwinNet` `/64`s *and* per-site `/96`s for the overlapping-LAN remap
(`docs/networking.md` §7.4). Unroutable-off-overlay is defense in depth for I3.

**C — IPv6-only overlay.** Conceptually the cleanest: one family, no dual-stack policy, no
IPv4 allocator, no `100.64.0.0/10` collision case, unbounded address space, perfect derivation
from `DeviceKey`. Removes half the routing and firewall surface.

**D — Delegated GUA.** Overlay addresses are globally meaningful, so a peer could in principle
be reached from outside the overlay if a user wanted that; no ULA source-selection penalty
under RFC 6724; no ambiguity with anyone else's ULA.

**E — No overlay addressing.** Zero allocator infrastructure. Devices are reachable at the
addresses admins already know. Natural fit for site-to-site use cases and for existing DNS.

## 6. Disadvantages of Each Alternative

**A — RFC 1918 + dynamic.** `10.0.0.0/8` and `192.168.0.0/16` collide with real user LANs
constantly — this is *the* most common operational failure in comparable products, and it
breaks the user's own printer, NAS, and router UI the moment a full tunnel or subnet route is
enabled. DHCP on the overlay adds a round trip that can stall, retry, and time out on exactly
the flaky networks where the tunnel is most needed — this is literally the "DHCP and
route-establishment stalls" defect. DHCP leases expire and can change addresses, breaking R2.
RA/SLAAC on the overlay means a peer or a bug can *inject a route*, which is a security problem.
Dynamic addresses make ACLs and audit logs unstable.

**B — RFC 6598 + fixed ULA, static.** Requires an allocator service for IPv4 (a real component
with real single-writer consistency obligations, per ADR-0009). `100.64.0.0/10` can collide
with the *underlay* when the user is behind carrier CGNAT that assigns from it — a rarer but
real case requiring detection and reallocation (`docs/networking.md` §7.5). ULA source-address
selection is de-prioritized by RFC 6724's default policy table, so applications on a dual-stack
host may prefer an IPv4 overlay address over the ULA one unless we install a policy row. A
fixed product-wide ULA global ID means two different TwinVPN deployments could theoretically
collide, which RFC 4193's random-global-ID guidance exists to prevent.

**C — IPv6-only overlay.** Breaks every application that takes an IPv4 literal, every legacy
protocol with embedded IPv4 addresses (FTP, SIP, older SMB configurations, many industrial and
IoT devices), and every user who types an IP into a browser. The local NAT46 shim is a
substantial per-platform component that is impossible on iOS (no such API in
`NEPacketTunnelProvider`) and awkward on Android. Users' home LANs and printers are IPv4; a
`LANGateway` to an IPv4-only site cannot be served without translation anyway.

**D — Delegated GUA.** Requires TwinVPN to obtain, hold, and operate an IPv6 allocation and its
routing — a permanent business and operational dependency for zero user-visible benefit, since
overlay peers are reachable only over the overlay regardless. Globally routable overlay
addresses are a *liability* under I3: if any policy fails open, the device is addressable from
the Internet. Ties address stability to a commercial allocation. Adds registry-related failure
modes to a client bring-up path.

**E — No overlay addressing.** Overlapping LANs are no longer an edge case, they are the
default case, and the only remedy is pervasive NAT, which destroys peer-identity attribution
and breaks any protocol carrying addresses. Roaming devices change address constantly, so R2 is
unachievable. Peer-to-peer ACLs cannot be written against stable identities. Mobile devices on
CGNAT have no meaningful "LAN address" to be reached at. This is a site-to-site design being
asked to do a personal-mesh job.

## 7. Security Implications

Of the selected option (B):

- **Address stability is bound to key identity (I4).** Because the IPv6 IID is derived from the
  `DeviceKey`, an address is not transferable: a different key yields a different address. ACLs
  written against overlay addresses therefore inherit the strength of the key binding rather
  than being a soft naming convention. The IPv4 `/32` does *not* have this property (it is
  allocated), so `AccessPolicy` evaluation MUST be keyed on `DeviceIdentity` and MUST treat the
  IPv4 address as a lookup convenience only.
- **`/32` quarantine.** Released IPv4 addresses are quarantined ≥ 7 days before reuse, so a
  stale cache or a stale ACL cannot silently re-target a different device.
- **ULA is unroutable off-overlay**, so a policy failure does not expose the device to the
  Internet at its overlay address. GUA (D) would have been worse on exactly this axis.
- **No RA, no DHCP on the overlay** removes two well-known injection vectors (rogue RA route
  injection; DHCP option injection including option 121 classless static routes, which is a
  known VPN-bypass technique). This is a material security advantage of B over A that is easy
  to overlook.
- **Deterministic IIDs are enumerable in principle** by anyone who knows a device's public key.
  Since the public key is already known to every `TrustedPeer`, and the ULA space is not
  reachable off-overlay, this is accepted and disclosed.
- **The IPv6 bypass mechanism (§11.5) is the security-critical part of this ADR** and is stated
  normatively. It is a *firewall* mechanism, not a routing mechanism; routes alone are never a
  security control.
- **Where a rejected alternative was better:** **C (IPv6-only)** would have a strictly smaller
  attack surface — no IPv4 firewall rules, no IPv4 allocator, no dual-family policy to keep in
  sync — and dual-family policy drift is a genuine risk that §11.5 exists to eliminate.

## 8. Reliability Implications

- **Bring-up is a local, bounded operation.** No DHCP, no DHCPv6, no SLAAC, no allocator round
  trip on the overlay path: addresses arrive with the contract and are installed directly. This
  eliminates the "DHCP and route-establishment stalls" defect class outright.
- **Addresses survive control-plane outage (I5).** The contract is cached; a device that already
  has one can bring the interface up with the control plane completely down.
- **Roaming does not renumber.** Underlay address changes never touch the overlay, so TCP
  sessions and application state survive a Wi-Fi→cellular handoff (`MIGRATING`, not
  `RECONNECTING`).
- **Atomic apply/rollback per contract generation** (R5), idempotent on generation id per
  ADR-0008, so a crash mid-apply converges on retry rather than leaving half a route table.
- **Route conflicts are detected before installation** and surfaced (R7), so the failure mode is
  an explanation rather than a broken LAN.
- **Where a rejected alternative was better:** **A** would tolerate an allocator outage more
  gracefully for *new* devices, since DHCP is served locally per link. B's IPv4 allocator is a
  new dependency for first-time address assignment; mitigated by stickiness (existing devices
  never need it) and by the fact that the IPv6 address needs no allocator at all — a device can
  be fully functional over IPv6 while the IPv4 allocator is unavailable.

## 9. Performance Implications

- Static assignment removes ~50–3000 ms of DHCP latency from every bring-up.
- Two `/1` routes per family cost four route-table entries and no forwarding-path overhead;
  longest-prefix match handles them at line rate.
- Deterministic IPv6 IIDs make peer address lookup a local computation, not a directory query.
- **Happy-eyeballs-style racing** (§11.4) bounds the cost of a broken family to ~250 ms rather
  than a TCP connect timeout, which is the difference between "IPv6 is a bit slow here" and
  "the app hangs".
- The per-site `/96` remap for overlapping LANs is stateless translation at the gateway —
  cheaper than the stateful NAT that Alternative E would require everywhere.
- **C (IPv6-only)** would be marginally faster on the forwarding path (one family, smaller rule
  sets) and would halve the firewall rule count.

## 10. Operational Implications

- Requires an **IPv4 overlay address allocator** as a single-writer control-plane component with
  durable state, stickiness, and quarantine. Its consistency model is owned by
  [ADR-0009](ADR-0009-state-consistency.md).
- Requires publishing the product's fixed ULA `/48` in documentation so administrators can write
  firewall rules and avoid using it themselves.
- Support scripts must be able to explain "why can't I reach 192.168.1.50" in terms of §11.6
  precedence, so route-conflict diagnostics must name both prefixes and both sources.
- Fleet telemetry must report: overlay-prefix/underlay collision rate, route-conflict rate by
  prefix, IPv6 end-to-end availability, and IPv4-only-tunnel-on-IPv6-host incidence — all four
  feed the revisit conditions in §14.
- Per-platform route installation has three genuinely different shapes (netlink, IP Helper,
  `NEPacketTunnelNetworkSettings`/`VpnService.Builder`); the adapter contract in
  `docs/networking.md` §5.1 is the seam, and it must not leak into higher layers.

## 11. Decision

**Adopt Alternative B.**

### 11.1 Address plan (normative)

| Family | Space | Per-`TwinNet` | Per-`Device` | Assignment |
|---|---|---|---|---|
| IPv4 | `100.64.0.0/10` (RFC 6598) | one or more `/22` | one `/32` | control-plane allocator, sticky, ≥ 7-day quarantine on release |
| IPv6 | the fixed product ULA **`fd7c:9e5d:2a10::/48`** under `fd00::/8` | one `/64` | one `/128` | `prefix64 || truncate64(HKDF(DeviceKey_pub, "twinvpn-v6-iid"))`, U/L bit cleared per RFC 7136 |
| IPv6 (site remap) | per-site `/96` inside the same `/48` | per advertised conflicting IPv4 site | — | IPv4 embedded in low 32 bits; stateless translation at the `LANGateway` |

Both addresses MUST be present on the overlay interface at all times (R1). RA MUST be disabled
on the overlay interface. DHCP, DHCPv6, and SLAAC MUST NOT be used on the overlay (R3).

**Rule AP-1 — the product ULA is a pinned constant.** The global ID is
`7c:9e5d:2a10`, giving `fd7c:9e5d:2a10::/48`, generated once per RFC 4193 §3.2.2 and **fixed for
the life of the product**. It is a constant, not a per-`TwinNet` value: `TwinNet` separation is by
`/64` within it. It MUST be identical in every build, because two devices deriving different
prefixes cannot reach each other and the failure looks like a routing bug rather than a version
skew. Changing it is a breaking change requiring a new `ProtocolVersion` epoch
([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)).

**Rule AP-2 — reserved service addresses are excluded from allocation.**
[ADR-0011](ADR-0011-dns-handling.md) DN-3 reserves `100.127.255.0/24` and
`fd7c:9e5d:2a10:ffff::/64` for TwinVPN service addresses — principally the DNS stub's overlay
anycast listeners. The allocator MUST exclude both from every per-`Device` and per-`TwinNet`
allocation. This was previously stated only in ADR-0011: an allocator built from this ADR alone
could hand a device an address inside the resolver's own service range, which would break
resolution for that device in a way that looks like a DNS fault rather than an addressing fault.
The exclusion is asserted at allocation time, not resolved at runtime (S-08's "a collision is a
control-plane bug, refused at allocation").

### 11.2 RFC 6724 source-address selection

Because ULA is de-prioritized relative to GUA by RFC 6724's default policy table, TwinVPN MUST
install a policy-table row raising the product ULA `/48`'s precedence above IPv4-mapped
addresses for overlay destinations (Linux: `/etc/gai.conf` / `ip addrlabel`; Windows:
`netsh interface ipv6 add prefixpolicy`; Apple/Android: handled by the tunnel settings object's
scoped resolver + route claim). Where a platform does not expose the policy table, name-based
access via [ADR-0011](ADR-0011-dns-handling.md) is the mechanism that steers applications to the
right family, by returning only the address family that is actually usable.

### 11.3 Route installation (normative, per platform)

| Platform | Mechanism | Default-route form |
|---|---|---|
| Linux | netlink `RTM_NEWROUTE` into table `52` + `ip rule` with `fwmark`, plus a suppress-prefixlength rule | `0.0.0.0/1` + `128.0.0.0/1` + `::/1` + `8000::/1` |
| Windows | `CreateIpForwardEntry2` + explicit interface metric | same |
| macOS | `NEPacketTunnelNetworkSettings` `IPv4Settings.includedRoutes` / `IPv6Settings.includedRoutes` | `NEIPv4Route.default()` + `NEIPv6Route.default()` |
| iOS | same as macOS (no route API) | same |
| Android | `VpnService.Builder.addRoute("0.0.0.0", 0)` **and** `addRoute("::", 0)` | both, always |
| OpenWrt | UCI + netifd | same as Linux |

The host's own default route is **never deleted or modified**. On platforms where we install
routes directly, the two-`/1`-per-family form wins by longest-prefix match while leaving the
host's default intact, so teardown is a pure deletion and cannot fail to "restore" anything.
Tunnel-encapsulated packets are pinned to the underlay by socket binding and/or `fwmark` policy
routing, which is the actual loop guard.

**On every platform, IPv4 and IPv6 routes MUST be installed in the same `apply()` transaction.
An implementation that can install one family's routes without the other's is non-conforming.**

### 11.4 Dual-stack destination selection

TwinVPN uses happy-eyeballs-style racing (RFC 8305 shape) for its **own** underlay connections
(rendezvous, relay, peer candidates): start the IPv6 attempt first, start the IPv4 attempt after
a 250 ms head-start delay, take the first to succeed, cache the winning family per network
fingerprint for 10 minutes, and re-race on any network-change event. Application traffic inside
the tunnel is not raced by us — the application's own stack does that; our job is to ensure both
families work, which R1 guarantees.

### 11.5 IPv6 MUST NOT bypass tunnel policy (normative — this is the I3 mechanism)

The guarantee is **firewall-based and interface-scoped and default-deny**, never route-based
and never prefix-allow-list-based. Routes are an optimization; the firewall is the control.

1. **Single-object dual-family policy.** The fail-closed rule set is expressed as one object
   covering both families simultaneously: nftables `table inet twinvpn` (the `inet` family
   matches IPv4 and IPv6 in one table), a single WFP sublayer containing both
   `FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `..._V6` filters installed in one transaction, one
   `NEPacketTunnelNetworkSettings` carrying both `IPv4Settings` and `IPv6Settings`, one
   `VpnService.Builder` claiming both default routes. **There is no code path that installs
   IPv4 protection without IPv6 protection**, because there is no separate IPv6 object to
   forget. This is a structural guarantee, not a discipline.
2. **Default deny, scoped by interface, not by destination.** The rule is "protected traffic
   MAY egress only via the overlay interface; all other interfaces deny", expressed without
   reference to any specific prefix. Therefore:
   - **IPv6 enabled after the tunnel is up** — a Router Advertisement arrives, a new prefix is
     configured, tethering starts, a VM bridge or a new physical interface appears — is denied
     by the pre-existing rule, because the new interface/prefix is not the overlay interface.
     **No rule update is required for correctness.** The network-change subscription
     (`docs/networking.md` §5.1) additionally re-asserts policy within 1 s; that is
     defense in depth, not the guarantee.
   - A newly learned IPv6 prefix cannot escape by being unknown to an allow-list, because there
     is no allow-list of prefixes.
3. **IPv4-only tunnel on an IPv6-capable host.** IPv6 MUST be **blocked**, not permitted and not
   globally disabled. The connection enters `DEGRADED` with `POLICY.LEAK.IPV6_UNPROTECTED`, and
   the user is told that IPv6 destinations are unreachable and why. TwinVPN MUST NOT set
   `net.ipv6.conf.all.disable_ipv6=1`, MUST NOT unbind the Windows IPv6 stack, and MUST NOT
   remove IPv6 addresses from host interfaces: those actions are destructive, restore
   unreliably after a crash, and break IPv6-only underlays.
4. **Ordering.** The fail-closed rules are live before the overlay interface is created and
   remain live after it is destroyed (`docs/networking.md` §9.3). Rules are owner-tagged and
   reclaimed by a fresh process after an unclean exit.
5. **Exemptions are narrow and explicit**: the tunnel's own encapsulated packets (matched by
   socket owner / `fwmark` / WFP app-id), underlay DHCP/DHCPv6/ND/RA needed to keep the underlay
   working, and — only if [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) permits it —
   a time-boxed captive-portal exemption. **ND and RA are permitted on the underlay because
   blocking them breaks the underlay itself; they are permitted as link-local control traffic
   only, and never as an egress path for protected traffic.**
6. **The kill-switch *policy* — when the fail-closed state applies, whether it applies to all
   traffic or only to protected traffic, whether a portal exemption exists — is owned by
   ADR-0012.** This ADR supplies the mechanism and asserts only that whatever policy ADR-0012
   chooses is applied to both families identically and atomically.

### 11.6 Route precedence

| # | Rule |
|---|---|
| P1 | Longest prefix match governs forwarding; identical prefixes are never installed twice. |
| P2 | An on-link physical LAN prefix beats an advertised overlay route of equal or shorter length, by default. |
| P3 | An explicit per-prefix user pin overrides P2 in either direction. |
| P4 | Between equal-length advertised routes from different gateways, better measured path wins; ties break on contract priority. |
| P5 | Conflicts are always surfaced (`ROUTE.CONFLICT_UNRESOLVED`) naming both prefixes, both sources, and the winner. Silent resolution is forbidden. |
| P6 | `0.0.0.0/0` and `::/0` may be advertised only by a selected `ExitNode`; otherwise `ROUTE.SCOPE_VIOLATION`. |

### 11.7 IPv6-only, IPv4-only, NAT64 and 464XLAT

| Underlay | Behavior |
|---|---|
| IPv4-only | Overlay dual-stack; underlay paths IPv4; overlay IPv6 traffic is tunneled over IPv4 |
| IPv6-only, no NAT64 | Overlay dual-stack; underlay paths IPv6 only; any IPv4-literal peer/relay is unreachable directly and is reached via an IPv6-reachable relay |
| IPv6-only + NAT64 | PREF64 discovered via RFC 8781 RA option (preferred) or RFC 7050 `ipv4only.arpa` (fallback); IPv4 endpoint literals are synthesized to `pref64::/n + v4`; **TwinVPN never depends on DNS64 to do this for it**, because our own resolver may be the one answering (circular dependency at bring-up) |
| 464XLAT | Treated as IPv4 with `underlay=xlat`; effective MTU reduced (see `docs/networking.md` §6.1); NAT class assumed CGNAT-equivalent |

## 11.8 `ROUTE` reason codes (discharging the ADR-0015 §11.2 domain assignment)

[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 assigns the **`ROUTE`** domain to this
ADR. Earlier drafts spelled these `NET.ROUTE_*`; those spellings are **withdrawn**. **R-17**
requires that a route conflict with a pre-existing system route surface as a named diagnostic and
never as a silent overwrite — these codes are that surface.

| Code | Class | Severity | Terminal | User-actionable | Condition |
|---|---|---|---|---|---|
| `ROUTE.CONFLICT_UNRESOLVED` | PERSISTENT | ERROR | no | **yes** | An accepted `Route` overlaps a pre-existing system route and the conflict could not be resolved by scope. **Never resolved by overwriting** (§11.6, networking.md §7.4); the user is told which prefix and which interface |
| `ROUTE.SCOPE_VIOLATION` | PERSISTENT | ERROR | no | no | A peer advertised a prefix outside what its `AccessPolicy` permits it to advertise; the advertisement is refused |
| `ROUTE.ADDRESS_COLLISION` | FATAL | CRITICAL | yes | yes | An assigned `TwinNet` address collides with an on-link prefix. S-08 refuses collisions at allocation, so this indicates a control-plane defect or a LAN that moved onto the overlay range (§11.7) |
| `ROUTE.IFACE_CONFLICT` | PERSISTENT | ERROR | no | yes | Another product holds an adapter or routing entry TwinVPN requires; never resolved by clobbering (networking.md §5.5) |
| `ROUTE.IFACE_MISSING` | TRANSIENT | ERROR | no | no | The overlay interface disappeared beneath a live `Session`; drives `docs/reliability.md` T29 |
| `ROUTE.PROGRAMMING_DENIED` | PERSISTENT | ERROR | no | **yes** | The OS refused a route or address installation — typically a missing permission or an endpoint-security product. Actionable |
| `ROUTE.FAMILY_ASYMMETRY` | PERSISTENT | WARN | no | no | One family's routes installed and the other's did not. §11.3 makes this non-conforming: both families install in one transaction or neither does |
| `ROUTE.DRIFT_DETECTED` | TRANSIENT | ERROR | no | no | The installed routing table no longer matches the applied contract generation; drives `docs/reliability.md` T29 |

---

## 12. Why the Selected Option Won
1. **R4 and R3 are decided together, and only B satisfies both.** `100.64.0.0/10` avoids the
   collisions that matter, and static contract-borne assignment removes the stall that DHCP
   introduces. A gets neither; C, D, and E each get one at the cost of something larger.
2. **A's dynamic assignment is not merely slow, it is a security regression.** DHCP option 121
   and rogue RA are established VPN-bypass and route-injection techniques. Removing DHCP and RA
   from the overlay removes both categories at once. That argument alone disqualifies A.
3. **`DeviceKey`-derived IPv6 gives R2 with zero infrastructure**, and lets a device be fully
   functional over IPv6 even when the IPv4 allocator is unreachable — a real availability
   property, not a theoretical one.
4. **C is right about the future and wrong about the present.** IPv4 literals, IPv4-only home
   LANs, and IPv4-only industrial devices are the reality of the next decade, and the NAT46
   shim C requires is not implementable on iOS. B keeps C's endgame available: §14 defines the
   measured condition under which the IPv4 overlay could be demoted.
5. **D pays a permanent operational and business cost for a benefit nobody asked for**, and
   makes a policy failure worse rather than better.
6. **E is the wrong shape for a personal device mesh.** It cannot give stable addresses to
   roaming phones, which are the majority of devices in the target use case.
7. **The `/1`-route form plus interface-scoped default-deny firewall is the only combination
   that satisfies R5 and R6 simultaneously** — reversible without restore logic, and secure
   without depending on the route table being correct.

## 13. Known Tradeoffs

| Tradeoff | Accepted because |
|---|---|
| An IPv4 address allocator is a new stateful control-plane component | Stickiness means it is on the path only for first assignment; IPv6 needs no allocator at all |
| `100.64.0.0/10` can collide with a CGNAT underlay | Rarer than RFC 1918 LAN collisions by orders of magnitude; detected and remediated by `/22` reallocation (`docs/networking.md` §7.5) |
| ULA needs an explicit RFC 6724 policy row per platform | One-time per-platform work; name-based access via ADR-0011 covers platforms without a policy table |
| A fixed product-wide ULA global ID departs from RFC 4193's random-ID guidance | Determinism is required so peers can compute each other's addresses without a directory; collision risk with another deployment is accepted and documented |
| Deterministic IIDs are enumerable given a public key | Public keys are already known to peers; ULA is unroutable off-overlay |
| Dual-stack doubles the routing and firewall surface | §11.5's single-object policy makes the two families structurally inseparable, which converts the risk into a non-issue |
| IPv4-only tunnels make IPv6 destinations unreachable rather than untunneled | This is I3. Reachable-but-leaking is the defect we exist to fix. |
| Overlapping-LAN remap is IPv6-only | An IPv4-only client at a site with a colliding prefix falls back to host-route pinning or gateway NAT |

## 14. Revisit Conditions

1. **If measured overlay-prefix/underlay collision (`NET.OVERLAY_PREFIX_COLLISION`) exceeds 1%
   of sessions**, reconsider the IPv4 overlay space (e.g. a smaller, less-used block, or
   per-`TwinNet` selection from multiple candidate ranges).
2. **If fleet IPv6 end-to-end availability exceeds 95% and IPv4-literal usage inside tunnels
   falls below 1% of flows**, re-evaluate Alternative C: demote the IPv4 overlay to opt-in and
   delete the allocator.
3. **If the IPv4 allocator's availability falls below 99.9% or its p99 first-assignment latency
   exceeds 2 s**, revisit stickiness/pre-allocation (e.g. issue a `/32` at pairing time rather
   than at first connect).
4. **If any target platform removes or restricts the ability to install both families' routes in
   one transaction** (§11.3), §11.5's structural guarantee is weakened and the mechanism must be
   redesigned before that OS version is supported.
5. **If a platform ships a mechanism that lets a non-privileged process bind a source address or
   raw socket that escapes interface-scoped filtering**, §11.5 must be re-derived; this is the
   single assumption the IPv6-bypass guarantee rests on.
6. **If ADR-0012 selects a kill-switch policy that requires host-global IPv6 disabling**, this
   ADR is in direct conflict and one of the two must change; §11.5(3) is written to prevent that
   outcome and the conflict must be resolved in ADR-0012's favor only with an explicit,
   documented acceptance of the crash-recovery and IPv6-only-underlay consequences.
7. **If RFC 6598 space begins appearing as a client LAN prefix in more than 2% of observed
   networks**, R4's premise is broken and the address plan must move.
8. **If route-conflict incidents (`ROUTE.CONFLICT_UNRESOLVED`) exceed 5% of subnet-route users**,
   promote the per-site `/96` remap from an advanced option to the default for advertised
   RFC 1918 prefixes.
