# ADR-0011: DNS Handling

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** NETWORKING
- **Related:** [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md),
  [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md),
  [ADR-0003](ADR-0003-network-contract-schema-format.md),
  [ADR-0007](ADR-0007-device-identity-and-pairing.md),
  [ADR-0009](ADR-0009-state-consistency.md),
  [ADR-0010](ADR-0010-ipv4-ipv6-routing.md),
  [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md),
  [ADR-0013](ADR-0013-multi-client-gateway-architecture.md),
  [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md),
  [ADR-0015](ADR-0015-observability-and-diagnostics.md),
  [docs/architecture.md](../architecture.md), [docs/networking.md](../networking.md),
  [docs/protocol.md](../protocol.md), [docs/reliability.md](../reliability.md),
  [docs/testing-strategy.md](../testing-strategy.md), [docs/threat-model.md](../threat-model.md)

This ADR owns **name resolution while TwinVPN is active**: the resolver architecture, the
`TwinNet` naming scheme and its search domain, split-DNS matching and precedence, A/AAAA
disposition, upstream transport and DNSSEC, the per-platform resolver-bypass channels, the
teardown/crash/reboot restoration of the host's prior resolver configuration, and the `DNS.*`
reason codes. It does **not** own the kill-switch policy or the firewall rule set
([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md), consumed here as given), the address
plan or route installation ([ADR-0010](ADR-0010-ipv4-ipv6-routing.md)), LAN peer discovery
([docs/networking.md](../networking.md) §8, which deliberately does not use mDNS), the
`ConnectionState` machine ([docs/reliability.md](../reliability.md) §4), or per-client gateway
DNS policy ([ADR-0013](ADR-0013-multi-client-gateway-architecture.md)). Where those are needed,
the required interface is stated in §11.13 and nothing about their internals is invented.

---

## 1. Context

DNS is the third of the four leak channels in [docs/networking.md](../networking.md) §9.1 and the
only one whose mechanism that document defers wholesale to this ADR. It is also the channel that
leaks most quietly: a device can have a correct dual-family firewall, a correct route set, and a
correct kill switch, and still send every name its user types to the coffee shop's resolver in
cleartext, because the OS resolver is a separate subsystem with its own interface bindings, its own
fallback logic, and — on three of six target platforms — a documented habit of asking *every*
interface at once.

Two obligations frame the decision. `docs/architecture.md` **A-16** requires that DNS handling
"covers v6 transport and AAAA records with the same rigor as v4, and never falls back to the
system resolver while protected". `docs/testing-strategy.md` **A-09** goes further and names the
hard part explicitly: enforcement must hold "including platform-specific bypasses (e.g. resolver
processes outside the tunnel's routing scope)". That parenthesis is the whole problem. A resolver
process is not our process; it does not use our sockets; it is not bound to our interface; and on
Windows it will deliberately race the query across every adapter it can see.

[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) has already decided the containment
*policy* — its §11.2 class 6 makes DNS `DROPPED_FAIL_CLOSED` except to the local stub — and states
in §11.12(a) exactly what it requires from this ADR. This document supplies the resolution mechanism
that lives inside that containment and may not widen ADR-0012's dispositions.

The second half of the problem is positive rather than defensive: a personal device mesh is close to
useless if peers are reachable only by address. `ssh nas` must work, from a phone, with the control
plane down (**I5**) — which requires an authoritative local answer computed from state the device
already holds, and a namespace not stolen from someone else.

## 2. Requirements

| # | Requirement |
|---|---|
| **D1** | While enforcement is armed, resolution MUST NOT fall back to any pre-existing host or network resolver, for either family, by any transport, including from resolver processes outside the tunnel's routing scope (A-16, A-09, ADR-0012 §11.12(a), **R-14**). |
| **D2** | Exactly one process on the device — the TwinVPN stub — may originate resolution while armed. Every other origination is contained by ADR-0012 §11.2 class 6. |
| **D3** | `TwinNet` names MUST resolve with **zero** control-plane round trips, from cached signed state (**I5**, **R-11**). |
| **D4** | A and AAAA MUST be handled with identical rigor. A design that resolves v4 and defers v6 is rejected (**P9**, **R-14**, V5). |
| **D5** | Resolution failure MUST be a typed, named failure — never a silent change of resolver, transport, or scope (**I3**, **I6**, **R-22**). |
| **D6** | The `TwinNet` namespace MUST NOT squat on a name registered to, reserved for, or protocol-assigned to anyone else. |
| **D7** | A crashed, killed, updated, or uninstalled agent MUST NOT leave the host pointed at a resolver that does not answer. Restoration MUST NOT depend on the agent running. |
| **D8** | `DNSPolicy` (**S-07**) MUST be applied monotonically; a device MUST NOT be walked backwards to a weaker DNS policy ([ADR-0009](ADR-0009-state-consistency.md) §11.4, protocol §13.4). |
| **D9** | Every claim this ADR makes MUST be observable, and the leak it prevents MUST be demonstrable on the same rig (V3, V4, proof test **P08**). |
| **D10** | Where a platform's resolver cannot be fully steered, the residual exposure MUST be named, measured, and surfaced — never papered over (**K10**-equivalent, O-17). |

## 3. Constraints

- **I3 / I5 / I6 / P9** — fail closed; the data plane outlives the control plane; every failure
  named; IPv6 is not a feature flag.
- **S-07** — `DNSPolicy` is authored by the `Owner` authority (2.22, ADR-0007) and distributed by the Control Plane, class `MONOTONIC`; every device holds a
  cache. This ADR adds no second writer.
- **[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.2 class 6** — DNS is
  `DROPPED_FAIL_CLOSED` except to the local stub. Consumed, not renegotiated.
- **[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.7 / KS-14…KS-16** — the captive-portal
  grant is user-consented, ≤ 300 s, kernel-expiring, and portal-window answers MUST NOT enter the
  protected resolution path or cache. This ADR implements KS-16; it does not revisit KS-14/KS-15.
- **[docs/networking.md](../networking.md) §5.5** — TwinVPN MUST NOT disable the host resolver
  service, MUST NOT make host-global destructive changes, and all state written outside our own
  interface MUST be owner-tagged and reclaimable after an unclean exit.
- **[docs/networking.md](../networking.md) §8.1** — peer discovery does not use mDNS/DNS-SD, and
  device names are never broadcast on an untrusted LAN. Nothing here may reintroduce that.
- **[docs/networking.md](../networking.md) §3.8 / [ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.7**
  — TwinVPN never depends on DNS64 to synthesize its own endpoint literals, because our resolver
  may be the one answering. The circular dependency is forbidden, not merely discouraged.
- **[ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.1** — both overlay families are present on the
  interface at all times; the v6 address is derived from the `DeviceKey`, the v4 `/32` allocated.
- **Platform reality** — Windows resolves in a shared service with parallel multi-adapter
  behaviour; Apple platforms resolve in `mDNSResponder` with per-interface scoping and a
  protocol-reserved `.local`; Android exposes a user-owned Private DNS setting an app cannot
  change; iOS exposes no host firewall at all.
- **Phase 1 produces no code.**

## 4. Considered Alternatives

Two orthogonal decisions, each with genuine alternatives.

**Group R — resolution architecture (where a query is answered and how the OS is steered).**

| # | Alternative |
|---|---|
| **R1** | **Local stub resolver on a loopback address.** The agent runs a full recursive-capable stub listening on `127.0.0.53`-style loopback; the OS's resolver list is rewritten to point at it; split-horizon forwarding happens inside the agent. |
| **R2** | **OS resolver pointed at a TwinNet-internal resolver address.** No local listener; the OS is pointed at a resolver reachable *over the overlay* — a `TwinNet`-internal service address served by a peer, a gateway, or the control plane. |
| **R3** | **Per-interface / split DNS via native platform APIs only.** No stub of our own: `systemd-resolved` per-link domains, Windows NRPT, Apple `NEDNSSettings` / `NEPacketTunnelNetworkSettings.dnsSettings`, Android `VpnService.Builder.addDnsServer` + `addSearchDomain`. The platform routes names to resolvers we name. |
| **R4** | **DoH/DoT client terminating in the agent.** The agent is an encrypted-DNS forwarder: it accepts Do53 from the host and speaks DoH (RFC 8484) or DoT (RFC 7858) upstream, terminating TLS itself. |
| **R5** | **No DNS handling at all (passthrough).** TwinVPN touches no resolver configuration. Peers are addressed by literal or by whatever the user's existing DNS already publishes. |

**Group N — the `TwinNet` namespace (what a peer is called).**

| # | Alternative |
|---|---|
| **N1** | **RFC 8375 `home.arpa`.** Names are `<device>.home.arpa`; the search domain is `home.arpa`. |
| **N2** | **RFC 6762 `.local`.** Names are `<device>.local`, served by our stub as unicast DNS. |
| **N3** | **ICANN-reserved `.internal`.** Names are `<device>.<twinnet>.internal`. |
| **N4** | **A registered domain under TwinVPN control**, with a deterministic per-`TwinNet` label: `<device>.<twinnet-label>.tnet.twinvpn.net`, delegated publicly as a deliberately empty, provably-insecure zone, and answered authoritatively by the local stub. |

## 5. Advantages of Each Alternative

**R1 — local stub on loopback.** One implementation of the hard logic (split-horizon matching,
caching, DNSSEC, EDE construction, per-scope isolation) shared by every platform, so the behaviour
a test asserts on Linux is the behaviour that ships on Windows. Loopback is reachable before the
overlay interface exists and after it is destroyed — exactly the windows in which a tunnel-resident
resolver is missing. And it makes ADR-0012 class 6 ("only the local stub may originate resolution")
a single checkable filter predicate rather than a property of five OS subsystems.

**R2 — TwinNet-internal resolver address.** No local listener to bind, so no port conflict with
`dnsmasq`, `systemd-resolved`, Pi-hole or a corporate agent — a real and common source of support
load. It is the only shape that works where a VPN cannot point the OS at loopback and can only
supply an address inside the tunnel, and it lets one place hold split-horizon policy for a site.

**R3 — native platform scoped DNS.** The only mechanism that actually steers the *host's* resolver
rather than hoping it cooperates, so the only one that addresses the bypass channels directly: NRPT
suppresses Windows parallel resolution for a matched namespace, `NEDNSSettings.matchDomains` scopes
`mDNSResponder`, `SetLinkDomains(["~."])` makes a link the default DNS route in `systemd-resolved`.
It also disappears with the tunnel object on Apple and Android — precisely the property D7 wants.

**R4 — DoH/DoT terminating in the agent.** Upstream queries become opaque to the local network and
the ISP — a genuine confidentiality gain in split-tunnel mode, where those queries legitimately
traverse the underlay. DoH over 443 also survives the restrictive networks `docs/networking.md` §3.7
catalogues (`NET.EGRESS_RESTRICTED`), and it makes the resolver an authenticated peer rather than
whatever DHCP handed us.

**R5 — passthrough.** Zero host state written, so zero restoration risk, zero coexistence conflict,
and no way to leave a machine pointed at a dead resolver. It is also the only option with no privacy
consequences of its own: we never see a query.

**N1 — `home.arpa`.** Reserved by the IETF exactly for locally-served names, so using it is not
squatting. Short, memorable, and already treated as locally-served by several resolvers, so a query
is less likely to escape to the public DNS.

**N2 — `.local`.** The name users and mobile platforms already associate with "a device on my
network", with zero-configuration semantics people understand, and protocol-reserved, so it will
never be delegated to a stranger.

**N3 — `.internal`.** Reserved by ICANN for private use and guaranteed never delegated in the public
root, so an escaped query cannot reach someone else's server. Short, neutral, no vendor name in it.

**N4 — registered domain.** Globally unique by construction, so two `TwinNet`s — or a `TwinNet` and
the user's employer — can never collide inside one host's namespace. It is delegable, so the escape
case is *defined* rather than undefined, and it can carry a deliberately-insecure DNSSEC delegation
so a validating stub below us does not mark our locally-served answers bogus. A per-`TwinNet` label
derived from `twinnet_id` gives every network its own subtree without a naming authority.

## 6. Disadvantages of Each Alternative

**R1 — local stub on loopback.** On iOS and Android a VPN cannot point the system resolver at
`127.0.0.1`: `NEPacketTunnelNetworkSettings`/`VpnService` take resolver addresses expected to be
reachable *through the tunnel*, so R1 alone is unavailable on two of six platforms. On desktops,
loopback port 53 is frequently taken (`systemd-resolved`, `dnsmasq`, Docker's embedded resolver, a
corporate agent), and binding it is a coexistence fight `docs/networking.md` §5.5 forbids winning by
force. And a stub the OS points at is a *pointer* the OS keeps after we die — D7's defect.

**R2 — TwinNet-internal resolver address.** A resolver on a peer or the control plane needs a live
tunnel, making name resolution control-plane-adjacent and violating **I5**: `ssh nas` would stop
working exactly when the network is worst. It also inverts bring-up — the resolver is unreachable
until routes exist, and routes come from a contract that may itself be fetched by name — and makes
one device a single point of failure for a whole `TwinNet`, contradicting **R-11**.

**R3 — native scoped DNS only.** Five genuinely different dialects with five different expressive
powers and no shared implementation of the logic that matters: NRPT cannot express a per-record-type
policy, Android's `addDnsServer` takes addresses rather than rules so the match set is coarse, and
`systemd-resolved` may be absent on a minimal Linux or an OpenWrt router. It also cannot *answer*
anything — only redirect — so R3 without a resolver of our own is incomplete by construction, and a
platform bug in scoping is a leak we cannot fix.

**R4 — DoH/DoT terminating in the agent.** Encrypting the upstream hop does not decide *which*
upstream, and the gain is against the local network only — the chosen provider still sees every
query, which for many users is a worse counterparty than their ISP. It adds a bootstrap problem (the
server's own name must be resolved or pinned as an address) and a TLS client on the fail-closed path.
Most importantly it is orthogonal to the leak: an encrypted query to a network-supplied resolver
while armed is still a query that escaped the tunnel. R4 solves confidentiality, not containment,
and must never be presented as solving containment.

**R5 — passthrough.** It is the defect. **R-14** names DNS leaks as a defect the product exists to
retire and A-16 forbids exactly this. It also makes `TwinNet` names unresolvable, so the mesh is
address-only, and it leaves the host pointed at a network resolver while the user is told they are
protected — a true claim producing a false impression, which this corpus treats as worse than an
honest failure. **Rejected outright**, and listed only because it is the status quo of several
comparable products.

**N1 — `home.arpa`.** RFC 8375 scopes it to *a single* home network: explicitly not globally unique,
with no per-network structure. A device in a `TwinNet` that also sits behind an HNCP homenet gets two
authorities for one zone with no defined resolution, and an escaped name is undefined rather than
controlled.

**N2 — `.local`.** RFC 6762 §3 reserves `.local` for multicast DNS; answering it over unicast is a
protocol violation, not a stylistic choice. On macOS and iOS `mDNSResponder` sends `.local` to
multicast regardless of what we configure, so names would work inconsistently across the platforms we
ship. It collides with every Bonjour/Avahi device on the LAN, and `docs/networking.md` §8.1 already
decided we do not put device names on an untrusted LAN — `.local` reintroduces that exposure by the
back door.

**N3 — `.internal`.** Reserved for private use means *everyone's* private use: it is not unique. A
user whose employer already runs `corp.internal` gets an ambiguous namespace on one host with no
authority to arbitrate. An escaped query safely gets NXDOMAIN from the root, but the *label* still
leaked and we have no way to define, sign, or observe the escape.

**N4 — registered domain.** It puts a vendor name in every hostname a user types, and creates a soft
dependency on a registration staying renewed and uncompromised — a supply-chain surface N1–N3 do not
have. Escaped queries carry a `TwinNet`-correlatable label to a public resolver, a real privacy
exposure needing an explicit containment rule rather than a shrug, and it requires public
authoritative infrastructure held to a higher availability standard than its function (returning
nothing) suggests.

## 7. Security Implications

- **DNS filtering is not a security control, and this ADR never uses it as one.** Withholding an
  AAAA does not stop a process that holds a literal, ships its own resolver, or reads a cached
  answer. The security control is [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)'s Tier-2
  interface-scoped default-deny; record filtering here exists only to avoid *manufacturing
  unreachable answers* (§11.6). Any claim that DNS policy prevents a leak on its own is a
  misstatement of this design.
- **Containment is the guarantee; steering is the usability layer.** Every platform's scoped-DNS API
  can fail, be overridden by a user setting, or be bypassed by a process opening its own socket. The
  property that survives all three is ADR-0012 class 6: nothing but the stub's registered sockets may
  originate resolution, enforced at the packet filter, both families, one object. §11.9 names each
  bypass *and* the containment rule that holds when steering fails.
- **The bootstrap exception is not a DNS channel.** ADR-0012 KS-10 forbids the agent from exposing
  any interface by which another process can place bytes on a registered socket. The stub is such an
  interface in form, so DN-4 constrains it normatively: it accepts **only** DNS messages, parses them
  fully before acting, and never proxies opaque bytes. A stub that forwarded arbitrary payloads would
  convert the listener into the general-purpose egress proxy KS-10 exists to forbid.
- **Portal-window answers are quarantined** (KS-16). A grant is a 300 s hole; a portal-supplied
  answer that persisted into the protected cache would convert it into a durable redirection of a
  name the user trusts. §11.10 gives the portal scope its own cache, its own upstream set, TTLs
  clamped to the remaining grant, and a hard flush at expiry.
- **The namespace is a privacy surface.** A `TwinNet` label is correlatable, so DN-6 forbids
  forwarding any name in the `TwinNet` zone or any RFC 6761/6303 locally-served zone upstream, under
  any mode — a refusal, not a fallback. The public delegation returning nothing is belt-and-braces
  for hosts *not* running the agent.
- **Device labels are Owner-scoped, not global.** Labels come from the signed contract, whose
  authority is the Control Plane (S-02); they are never learned from a peer or from the network, so
  a peer cannot name itself into another peer's position.
- **DNSSEC failures are refusals, never downgrades** (§11.8). A bogus answer produces SERVFAIL
  with EDE 6 and no second attempt on a different path, because "try an unvalidated route" is the
  same failure shape as "fall back to the system resolver".
- **Where a rejected alternative was better:** **R5 (passthrough)** has a strictly smaller attack
  surface than any design that terminates DNS — no listener, no cache, no parser, no host state.
  We take on a DNS parser on the fail-closed path deliberately, and §11.3's minimality rules plus
  the `fz-dns-response` fuzz corpus (`docs/testing-strategy.md` §2.12) are the price. **N3
  (`.internal`)** is strictly better on the vendor-neutrality and supply-chain axes, and its
  disadvantage is uniqueness, which §11.4's local-refusal rule partially mitigates but does not
  remove.

## 8. Reliability Implications

- **Name resolution survives a total control-plane outage** (**I5**). `TwinNet` names are answered
  from the cached signed contract with zero network I/O — not from a cache of prior answers but from
  the contract itself, the same artifact that supplies addresses and routes. A device that can bring
  its interface up can resolve its peers.
- **The stub is on the fail-closed path, so its failure is a named state, not a silent one.** Bind
  failure, program failure and reconciler-detected reversion all drive `BLOCKED` through the
  existing T29 (`EV_POLICY_VIOLATION`) guard with a `DNS.*` code; this ADR adds no state and no
  transition (§11.11). `docs/reliability.md` §2.4's `DNS.POLICY_NOT_APPLIED` /
  `DNS.LEAK_DETECTED_V4` / `DNS.LEAK_DETECTED_V6` row is confirmed and given canonical `DNS.*`
  codes in §11.12.
- **The dead-resolver defect is addressed by two independent mechanisms** (§11.7): a durable
  `RestorePoint` written *before* the mutation and replayed by a boot-time restore entry point that
  does not require a healthy agent; and, where the platform supports it, a resolver configuration
  owned by the tunnel object so it dies with the object. §11.7's table says which platforms get which.
- **Restoration is ordered after enforcement, never before.** The boot restore unit runs *after*
  ADR-0012 KS-19's OS-applied ruleset is live, so a device never regains a working upstream
  resolver in a window where the kill switch is not yet armed.
- **Suspend/resume and network change re-assert, they do not re-decide.** `docs/reliability.md`
  T34/T35 re-asserts `DNSPolicy` on resume before traffic is emitted; §11.7's reconciler makes that
  a no-op in the common case. The reconciler interval is ≤ 2 s and the canary interval ≤ 5 s, per
  `docs/reliability.md` §2.4 — those values are consumed, not re-set here.
- **Expired policy suspends grants and retains denials**, exactly per
  [ADR-0009](ADR-0009-state-consistency.md) §11.4. §11.12 enumerates which DNS rules are grants
  and which are denials so the asymmetry is mechanically checkable rather than conventional.
- **Where a rejected alternative was better:** **R2** would keep working through a local agent
  restart, because the resolver would not be local. The selected design pays for that with the
  `RestorePoint` and the boot restore unit.

## 9. Performance Implications

- A `TwinNet` name is a lookup in an in-memory index built from the contract: no network I/O, no
  upstream, no cache miss path. Cost is microseconds and is bounded by the peer count, not by
  network conditions.
- Out-of-scope names cost one upstream round trip plus cache. In `FULL` mode that round trip
  traverses the tunnel, adding one tunnel RTT — measurable, and the reason `SPLIT` is the default
  routing-mode pairing.
- **Withholding a record the enforcement layer would drop is a latency win, not a cost** (§11.6).
  Returning an AAAA that the kill switch blocks costs the application a full connect timeout
  before it retries v4; returning NODATA + EDE 17 costs it nothing, because RFC 8305 happy
  eyeballs proceeds immediately on the family that has an answer.
- DNSSEC validation adds chain fetches on cache-cold names. One chain cache is shared across all
  scopes except the portal scope, which is deliberately isolated and pays its own cost for the
  ≤ 300 s of a grant.
- The stub sizes to one host's query rate, not a fleet's. The multi-client gateway case (many peers'
  queries arriving over the overlay) is **not** served by it and belongs to
  [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) (§11.13(f)). TTLs are honoured but
  clamped to a policy ceiling, and the protected cache is never persisted (DN-22).

## 10. Operational Implications

- **A public zone must be operated.** `tnet.twinvpn.net` must be registered, delegated, and served
  as an intentionally empty zone with an insecure (unsigned) delegation. It has no user-visible
  function; its availability exists so a validating resolver elsewhere gets a clean insecure answer
  instead of SERVFAIL. Renewal is a standing obligation and is on the runtime critical path for
  nothing, by design.
- **A service-address reservation must be honoured by the allocator.** §11.2 reserves
  `100.127.255.0/24` inside the IPv4 overlay space and `fd7c:9e5d:2a10:ffff::/64` inside the product ULA.
  The [ADR-0010](ADR-0010-ipv4-ipv6-routing.md) allocator MUST never allocate from them; this is a
  required interface (§11.13(a)) and an amendment ADR-0010 §11.1 needs.
- **Support tooling must answer "why did that name not resolve".** Every negative answer carries an
  EDE whose EXTRA-TEXT contains the `reason_code`, so `dig`-level output is diagnostic without a
  debug build (**R-23**).
- Fleet telemetry must report `DNS.LEAK.QUERY_OBSERVED_OFF_TUNNEL` incidence per platform;
  `DNS.PLATFORM.*` posture distribution; `DNS.STUB.CONFIG_REVERTED` rate; and
  `DNS.STUB.STALE_POINTER_REPAIRED` count, the direct measure of D7. All four feed §14.
- The known-encrypted-resolver endpoint list used for DoH containment (§11.9) ships with the
  reason-code registry, is versioned, and is **explicitly incomplete** — a detection aid, never a
  guarantee.
- Router-class targets (OpenWrt) already run `dnsmasq` as the LAN resolver. TwinVPN adds a
  forwarding stanza and does not replace it; DNS for downstream LAN clients is gateway policy
  ([ADR-0013](ADR-0013-multi-client-gateway-architecture.md)), not this ADR's.

## 11. Decision

**Adopt R1 + R3 as a deliberate hybrid, with R4 available as an upstream transport option inside
it. Adopt N4 for the namespace. R2 and R5 are rejected.**

The stub (R1) is the *resolution engine* and is where all logic lives. The platform's native
scoped-DNS API (R3) is the *steering mechanism* and is genuinely different on every platform. The
honest statement is that neither alone is sufficient: R3 cannot answer, and R1 cannot steer. What
makes the hybrid safe rather than merely pragmatic is that neither is the *guarantee* — ADR-0012
class 6 containment is, and it is uniform.

### 11.1 The three resolution scopes

| Scope | Answered from | Cache | Exists when |
|---|---|---|---|
| **`twinnet`** | The cached signed contract, authoritatively, with no network I/O (**D3**) | None needed; the contract *is* the index | Always, including with the control plane down and the tunnel down |
| **`protected`** | Upstream resolvers named by `DNSPolicy`, reached only over the overlay | In-memory, never persisted | Only while an authorized secure path exists; otherwise every query is a typed failure (§11.5) |
| **`portal`** | The DHCP/RA-supplied resolvers of the attaching interface, over the ADR-0012 §11.7 grant | Separate, TTL-clamped to the remaining grant, flushed at expiry | Only while a `PortalExemptionGrant` is live |
| **`bootstrap`** | The host's configured upstream resolvers, or the DHCP/RA-supplied resolvers of the attaching interface, over a `RESOLVER`-registered socket ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.5) | Separate; TTL-clamped to 300 s; **never** shared with `protected` (DN-1) | **Always, including in `BLOCKED`** |

**Rule DN-0 — the `bootstrap` scope (normative).** `bootstrap` exists because the agent must be
able to resolve **its own** control-plane and rendezvous names in order to recover, and the other
three scopes cannot serve them: `protected` requires a secure path that does not yet exist,
`twinnet` is contract-only, and `portal` requires a grant. Without it, a device in `BLOCKED` whose
control plane is reached by GeoDNS ([ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md)
§11.2) could never re-establish — in full-tunnel mode the lookup would have to traverse the tunnel
that the control plane is needed to establish, which is exactly the circular dependency §3 forbids
by name for DNS64.

It is deliberately the narrowest scope in the table:

- **Agent-originated only.** No host process may resolve in this scope; the stub MUST refuse a
  `bootstrap`-scope query that did not originate from the agent itself.
- **A closed name set.** Only the control-plane and rendezvous FQDNs compiled into the build or
  carried in the signed contract. Any other name in this scope is a defect
  (`INTERNAL.INVARIANT_VIOLATED`).
- **Answers are pinned or validated.** Responses MUST be DNSSEC-validated where the zone is signed,
  and in all cases the resulting address is used only to reach an endpoint that then performs
  mutual authentication — so a hostile answer costs a failed connection, never a leak or a
  misplaced trust decision.
- **`Relay` endpoints are excluded**, because they are IP literals and never hostnames
  ([ADR-0006](ADR-0006-relay-discovery-and-failover.md) §11.2). Relay reachability MUST NOT depend
  on DNS.

**Rule DN-1.** The four scopes share no cache, no chain cache, and no negative cache. An answer
learned in one scope MUST NOT be served in another. This is the normative form of ADR-0012 KS-16
and satisfies §11.12(a)'s fifth clause.

### 11.2 The stub's listening addresses (normative)

| Family | Address | Used on |
|---|---|---|
| IPv4 loopback | `127.0.0.53:53` (UDP+TCP), or the first free address in `127.0.0.0/8` if occupied | Linux, Windows, macOS, OpenWrt |
| IPv6 loopback | `[::1]:53` (UDP+TCP) | Linux, Windows, macOS, OpenWrt |
| IPv4 overlay anycast | `100.127.255.53:53` | All platforms; the **only** option on iOS/Android |
| IPv6 overlay anycast | `fd7c:9e5d:2a10:ffff::53` port 53 | All platforms; the **only** option on iOS/Android |

**Rule DN-2 — the anycast addresses are answered locally and never routed.** Both are served by
the *local* agent on every device. They MUST NOT appear in any `Route` advertisement, MUST NOT be
forwarded to a peer, and MUST be dropped if received on the overlay from a peer. They are anycast
in the sense that every device uses the same literal, not in the sense that packets are routed to
a nearest instance — which is what keeps **I5** and **R-11** intact.

**Rule DN-3 — reservation.** `100.127.255.0/24` and `fd7c:9e5d:2a10:ffff::/64` are reserved service
blocks and MUST NOT be allocated to any `Device`. Required of
[ADR-0010](ADR-0010-ipv4-ipv6-routing.md) (§11.13(a)).

**Rule DN-4 — the stub is a DNS server, not a proxy.** It accepts only well-formed DNS messages
(RFC 1035 + EDNS(0) RFC 6891), parses every message fully before any action, enforces a
`bufsize` ceiling, refuses messages with `QDCOUNT ≠ 1`, refuses unknown OPCODEs, and MUST NOT
carry, tunnel, or relay any payload that is not a DNS RR. This is what keeps the listener from
becoming the egress interface ADR-0012 KS-10 forbids.

**Rule DN-5 — bind before pointing.** The stub MUST be bound and answering on all four addresses
before the host resolver is pointed at it, and the host MUST be pointed away before the stub is
unbound (§11.7). If any listener cannot bind, `DNS.STUB.BIND_FAILED` is raised and the client MUST
NOT enter a protected state — the same disposition as `POLICY.KILLSWITCH.ARM_FAILED`.

### 11.3 The namespace (normative)

```
                  <device-label> . <twinnet-label> . tnet.twinvpn.net
                        │                 │                │
                        │                 │                └─ registered, delegated,
                        │                 │                   deliberately empty,
                        │                 │                   INSECURE delegation
                        │                 └─ t-<base32(truncate80(twinnet_id))>
                        │                    deterministic, not user-chosen
                        └─ Owner-set label, LDH per RFC 1035, lowercase,
                           IDNA2008 A-label if non-ASCII, ≤63 octets,
                           uniqueness enforced by the Control Plane (S-02)
```

| Property | Value |
|---|---|
| Search domain pushed to the host | `<twinnet-label>.tnet.twinvpn.net` — so `ssh nas` resolves |
| Additional local aliases | An `Owner`-chosen vanity label MAY be served **locally only**, never delegated |
| Forward zone | `<twinnet-label>.tnet.twinvpn.net` — served authoritatively by the stub |
| Reverse zones | `64.100.in-addr.arpa` … `127.100.in-addr.arpa` (the 64 zones covering `100.64.0.0/10`) and the `ip6.arpa` zone of the product ULA `/48` — served authoritatively by the stub |
| Public zone contents | Empty. Every query gets NXDOMAIN from the public authoritative servers. No overlay address, device label, or membership fact is ever published publicly |
| DNSSEC status of the delegation | **Unsigned (provably insecure)**, so a validating resolver below or beside us treats our locally-served answers as insecure rather than **bogus** |

**Rule DN-6 — the `TwinNet` zone is never forwarded.** A query in the forward zone or either
reverse zone MUST be answered from the contract or answered NXDOMAIN authoritatively. It MUST NOT
be forwarded upstream in any scope, any mode, or any failure path. This is a containment rule for
the label-correlation exposure of §7, not a performance choice.

**Rule DN-7 — MagicDNS-style answers come from cached state, never a round trip.** The forward and
reverse indices are derived from the signed contract's `peers[]` at apply time (`docs/networking.md`
§2.3). A resolution MUST NOT trigger a control-plane call, a presence lookup, or a peer probe
(**I5**, **D3**). A peer being offline changes nothing about its name resolving — consistent with
S-11's "presence is never a gate".

### 11.4 Split DNS: matching rule precedence (normative)

Every query is classified by exactly one rule. The precedence order is **exact name > longest
matching suffix > default**, evaluated as:

| # | Class | Match | Disposition |
|---|---|---|---|
| 1 | **Exact name rule** | `qname` equals a `DNSPolicy` exact-match entry | As the entry states |
| 2 | **`TwinNet` zones** | `qname` in the forward zone or a reverse zone of §11.3 | Authoritative local answer (DN-6) |
| 3 | **Protocol-reserved / locally-served** | `local.` (RFC 6762); `localhost.`, `invalid.`, `test.`, `example.`, `onion.` (RFC 6761); `home.arpa.` (RFC 8375); `internal.`; the RFC 6303 empty zones | **Never forwarded.** `local.` is excluded from the scoped-DNS match set on every platform so the host's own mDNS handles it; if one still reaches the stub it is REFUSED + EDE 20. The rest are answered locally or NXDOMAIN |
| 4 | **Longest matching suffix** | The longest `split_domains[]` suffix matching `qname` | As the entry states: `TWINNET`, `PROTECTED_UPSTREAM`, or `REFUSE` |
| 5 | **Default** | Everything else | Per `DNSPolicy.mode` (§11.5) |

**Rule DN-8 — ties are a policy defect, not a runtime coin-flip.** Two rules of equal specificity
with different dispositions in one `PolicyBundle` are rejected **at bundle validation** with
`DNS.POLICY.RULE_CONFLICT`; the previous bundle continues to govern. There is no runtime
tie-breaking, because a tie-break that is not in the signed document is a second policy author.

**Rule DN-9 — suffix matching is on whole labels.** `example.com` matches `a.example.com` and
`example.com`, never `notexample.com`. Comparison is case-insensitive per RFC 4343 and performed
on the wire-format labels, not on a presentation string.

### 11.5 Modes and the fallback prohibition (normative)

`DNSPolicy.mode` takes the three values `docs/architecture.md` §3.3 already defines.

| Mode | `twinnet` scope | Default-class queries | Permitted while armed |
|---|---|---|---|
| `SPLIT` (default) | Authoritative local | Forwarded to the **host's pre-existing upstream resolvers**, from the stub, over the underlay — **only** when the routing mode is TwinNet-only or split-tunnel, i.e. only when those destinations are outside ADR-0012 §11.1's protected scope | Yes |
| `FULL` | Authoritative local | Forwarded to the resolvers named by `DNSPolicy.servers_v4[]`/`servers_v6[]` or by `ExitNodeEngaged.dns_servers_v4[]`/`dns_servers_v6[]`, **over the overlay only** | Yes |
| `OFF` | Not served | Untouched; TwinVPN writes no resolver configuration | Only with TwinNet-only routing and an explicit policy setting; **never** with `FULL` routing or an engaged `ExitNode`. Persistent `DNS.POLICY.HANDLING_DISABLED` |

**Rule DN-10 — the prohibition is on *fallback*, and this is the precise reading.** ADR-0012
§11.12(a) forbids "unencrypted fallback to any pre-existing resolver". *Fallback* means resolution
reverting to a pre-existing resolver because TwinVPN's resolution path failed, was not installed,
timed out, or was not matched. It does **not** mean that `SPLIT` mode's deliberate,
policy-directed forwarding of out-of-scope names is forbidden — those names were never in the
protected scope, and forbidding them would make split-tunnel mode mean full-tunnel DNS, which no
document in this corpus decided. Concretely:

1. A query classified `TWINNET` or `PROTECTED_UPSTREAM` MUST NOT, under **any** condition
   including stub error, upstream timeout, `SERVFAIL`, tunnel loss, or policy expiry, be sent to a
   pre-existing host or network resolver. The failure is typed (§11.5, table below).
2. A query classified for underlay forwarding in `SPLIT` mode MUST NOT be retried in-tunnel, and
   an in-tunnel query MUST NOT be retried on the underlay. **Scope never changes on failure.**
3. When the routing mode is full-tunnel, or an `ExitNode` is engaged, *every* default-class query
   is `PROTECTED_UPSTREAM` by construction, so clause 1 covers everything and there is no underlay
   DNS at all.

**Rule DN-11 — every negative outcome is a typed DNS failure, never a silent one, and never
NXDOMAIN.** NXDOMAIN is an assertion that a name does not exist; using it for a blocked or failed
resolution is a lie that gets negatively cached and breaks unrelated software.

| Condition | RCODE | Extended DNS Error (RFC 8914) | `reason_code` |
|---|---|---|---|
| Protected scope, no authorized secure path | `SERVFAIL` | 15 Blocked | `DNS.RESOLUTION.BLOCKED_FAIL_CLOSED` |
| Policy refuses the name | `REFUSED` | 18 Prohibited | `DNS.RESOLUTION.REFUSED_BY_POLICY` |
| Family withheld because the tunnel cannot carry it (§11.6) | `NOERROR` / 0 answers | 17 Filtered | `DNS.RECORDS.FAMILY_WITHHELD` |
| Upstream unreachable through the tunnel | `SERVFAIL` | 22 No Reachable Authority | `DNS.RESOLUTION.UPSTREAM_UNREACHABLE` |
| Upstream timed out | `SERVFAIL` | 23 Network Error | `DNS.RESOLUTION.TIMEOUT_FAIL_CLOSED` |
| DNSSEC bogus | `SERVFAIL` | 6 DNSSEC Bogus | `DNS.DNSSEC.VALIDATION_FAILED` |
| Chain unavailable while validating | `SERVFAIL` | 9 DNSKEY Missing / 10 RRSIGs Missing | `DNS.DNSSEC.CHAIN_UNAVAILABLE` |
| Stub not yet ready | `SERVFAIL` | 14 Not Ready | `DNS.STUB.NOT_READY` |
| `TwinNet` name with no contract entry | `NXDOMAIN` | — (authoritative, and true) | `DNS.NAME.TWINNET_UNKNOWN` |

Every EDE carries EXTRA-TEXT containing the `reason_code`, so the `reason_code` is visible to
`dig` without a debug build (**R-23**, O-02).

### 11.6 A and AAAA with equal rigor (P9, D4)

**Rule DN-12 — a peer with both families always yields both records.** Every `Device` has both an
overlay v4 and an overlay v6 address at all times ([ADR-0010](ADR-0010-ipv4-ipv6-routing.md) R1),
so an in-`TwinNet` name returns both an A and an AAAA. Neither is synthesized; both come from the
contract.

**Rule DN-13 — the *underlay* family is irrelevant to overlay records.** `docs/networking.md` §2.4
is explicit that overlay v6 traffic rides an IPv4 underlay and vice versa. A stub MUST NOT filter
AAAA because the underlay is v4-only. This is the single most common way a v6-aware design
degrades into a v4-only one, and it is forbidden here by name.

**Rule DN-14 — the two cases the design must distinguish.**

| Case | Situation | Why it is what it is | Disposition |
|---|---|---|---|
| **(a) Broken resolution — not a leak** | The answer is an address in the protected scope that the enforcement layer will **drop** (e.g. an overlay AAAA while the negotiated tunnel covers only v4, ADR-0012 KS-6) | The packet never leaves the host. Nothing leaked. What happened is that we handed the application an address that cannot work, costing it a connect timeout | **Withhold that family**: `NOERROR`/0 answers + EDE 17, `DNS.RECORDS.FAMILY_WITHHELD`, emitted alongside `POLICY.LEAK.IPV6_UNPROTECTED`. Happy eyeballs then proceeds immediately on the working family |
| **(b) A real leak** | A globally-routable AAAA for an **upstream** name is returned while the host's v6 traffic would egress **outside** the tunnel | The packet does leave the host, untunneled. This is R-14's defect | **Not fixed here.** The fix is ADR-0012 Tier 2, which drops it. This ADR's obligation is only to be *consistent* with that: DN-15 |

**Rule DN-15 — never return a record the enforcement layer will drop, and never claim that as
security.** Record filtering aligns resolution with enforcement so applications fail fast; it is
not, and MUST NOT be documented, tested, or sold as, leak prevention. A build that filters records
but does not block egress is a leaking build that produces prettier timeouts. Proof test **P08**'s
oracle is the enforcement layer's deny counters and the wire capture, never the resolver's answer.

**Rule DN-16 — no DNS64 synthesis by us.** The stub MUST NOT synthesize AAAA from A. Where the
host is on a NAT64 network and an *upstream* resolver performs DNS64, the answer is passed through
unchanged. TwinVPN's own endpoint-literal synthesis uses PREF64 from RFC 8781 or RFC 7050 and is
owned by [ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.7; it MUST NOT consume this stub's answers,
which is what keeps `docs/networking.md` §3.8's circular dependency closed.

**Rule DN-17 — family steering, refining [ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.2.** ADR-0010
§11.2 states that on platforms without an RFC 6724 policy table, "name-based access via ADR-0011
is the mechanism that steers applications to the right family, by returning only the address family
that is actually usable." That is confirmed for the case DN-14(a) covers — a family that is *not*
usable is withheld. It is **refined, not overruled**, for the case where both families are usable:
the stub MUST NOT withhold a working family to influence preference, because withholding a working
AAAA is a deliberate degradation of the network. On such platforms both records are returned; both
work (R1); the residual is only that an application may prefer the overlay v4 address, which is
benign. `docs/adr/ADR-0010-ipv4-ipv6-routing.md` §11.2's sentence should be amended to say
"returning only the address families that are actually usable".

### 11.7 Host resolver programming, teardown, and the dead-resolver defect (D7)

**Rule DN-18 — `RestorePoint` before mutation.** Before writing any host resolver configuration,
the agent MUST durably persist an owner-tagged `RestorePoint` containing the verbatim prior
configuration, the platform object identifiers needed to restore it, and a `restore_token`. It is
written and flushed **before** the mutation, never after (the same discipline as
[ADR-0009](ADR-0009-state-consistency.md) R-9). This requires one new state row (§11.14).

**Rule DN-19 — ordering.**

```
apply:     stub bound & answering ─► RestorePoint persisted ─► platform scoped-DNS applied
                                     ─► reconciler confirms actual == intended ─► ready

teardown:  point host away (restore RestorePoint) ─► reconciler confirms ─► unbind stub
           (never unbind-then-restore)

crash:     boot: ADR-0012 KS-19 ruleset live ─► restore entry point runs ─► if an owner-tagged
           resolver config exists whose stub does not answer, restore the RestorePoint
```

**Rule DN-20 — restoration MUST NOT require the agent to be healthy.** The restore entry point is
part of the same OS-applied artifact family as ADR-0012 KS-19's boot ruleset (a `systemd` unit, a
Windows service, a `LaunchDaemon`, an OpenWrt init script) and runs **after** enforcement is live,
so the host never regains an upstream resolver in an unarmed window. A successful repair emits
`DNS.STUB.STALE_POINTER_REPAIRED`; a failed one emits `DNS.STUB.TEARDOWN_INCOMPLETE` at `CRITICAL`
and the device stays fail-closed.

**Rule DN-21 — prefer configuration owned by the tunnel object.** Where the platform lets the
resolver configuration live *inside* the tunnel object, that form MUST be used, because it dies
with the object and needs no restoration at all.

| Platform | Steering mechanism | Dies with the tunnel object? | Restoration path |
|---|---|---|---|
| Linux (`systemd-resolved`) | `SetLinkDNS` + `SetLinkDomains(["~."])` + `SetLinkDefaultRoute(true)` + `SetLinkDNSOverTLS` on our link | ✔ per-link config is discarded with the link | None needed; `RestorePoint` is belt-and-braces |
| Linux (no `resolved`) | Owner-tagged `/etc/resolv.conf` rewrite | ✘ | `RestorePoint` + boot restore unit. **This is the weakest desktop case** and races NetworkManager/`dhclient`; containment is the guarantee, not the file |
| Windows | NRPT rules (`DnsPolicyConfig`) for the split domains, and `.` in `FULL` mode; interface-scoped resolver on our adapter | ✘ registry-persistent | `RestorePoint` + boot service. **The highest-risk platform for D7** |
| macOS | `NEPacketTunnelNetworkSettings.dnsSettings` with `matchDomains` (`.local` excluded) | ✔ | None needed |
| iOS | Same as macOS; `NEDNSSettingsManager` where a system-wide profile is used | ✔ | None needed |
| Android | `VpnService.Builder.addDnsServer(<anycast v4>)` + `addDnsServer(<anycast v6>)` + `addSearchDomain` | ✔ | None needed |
| OpenWrt | `dnsmasq` `server=/<zone>/<anycast>` stanza via UCI; `dnsmasq` is **not** replaced | ✘ persisted config | `RestorePoint` + init script |

**Rule DN-22 — the protected cache is never persisted.** It is memory-resident and discarded on
process exit. A persisted DNS cache is both a stale-answer channel across a policy change and a
durable record of the user's browsing; neither is acceptable.

### 11.8 Upstream transport and DNSSEC

**Rule DN-23 — transport per scope.**

| Scope | Transport | Rationale |
|---|---|---|
| `twinnet` | None — local | — |
| `protected`, `FULL` mode | Do53 over the overlay by default; `DoT` (RFC 7858) or `DoH` (RFC 8484) selectable by `DNSPolicy.upstream_transport` | The overlay is already end-to-end encrypted ([ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md), **I1**), so Do53 inside it is not cleartext on any network. DoT/DoH is offered for the case where the `Owner` does not want the `ExitNode` to see the queries |
| `protected`, `SPLIT` mode, underlay-forwarded | Whatever the host was already configured to use, preserved exactly | DN-24 |
| `portal` | Do53/DoT to the DHCP/RA-supplied resolvers only, within the ADR-0012 §11.7 grant's port set | The grant permits exactly UDP/TCP 53 and TCP 853 to those resolvers |

**Rule DN-24 — never silently downgrade an encrypted host configuration.** If the host had DoT or
DoH configured (Android Private DNS strict mode, `systemd-resolved` `DNSOverTLS=yes`, a Windows
DoH template, a macOS `NEDNSSettings` profile), the stub MUST preserve that transport for
underlay-forwarded names, or refuse to forward and emit
`DNS.UPSTREAM.ENCRYPTION_DOWNGRADE_REFUSED`. Turning the user's encrypted DNS into cleartext DNS as
a side effect of connecting a VPN is a security regression, and a common one.

**Rule DN-25 — DNSSEC.** The stub is a validating resolver for the `protected` scope, default
`dnssec = VALIDATE`. A bogus answer is **never** served and **never** retried on a different path
or a different resolver: SERVFAIL + EDE 6, `DNS.DNSSEC.VALIDATION_FAILED`. The `twinnet` scope is an
*insecure* locally-served zone: its authenticity comes from the `Owner`-authority signature on the
contract ([ADR-0003](ADR-0003-network-contract-schema-format.md),
[ADR-0007](ADR-0007-device-identity-and-pairing.md)), which is a stronger binding than DNSSEC and
is verified before the index is built. The stub MUST clear the `AD` bit on `twinnet`-scope answers
rather than claiming a validation it did not perform, and the public delegation is unsigned
(§11.3) so a validator elsewhere sees *insecure*, not *bogus*. The `portal` scope is **not**
validated — a portal MITMs by design — which is a further reason its answers are quarantined
(DN-1).

**Rule DN-26 — app-embedded resolvers are out of scope, stated plainly.** A browser with its own
DoH resolver bypasses the OS resolver entirely; the stub never sees those queries and cannot. What
is true, and all that is claimed:

1. In **full-tunnel** mode the browser's DoH query still egresses through the tunnel — it is a
   *steering* failure (our split-DNS does not apply, so `TwinNet` names fail inside that browser),
   **not** a leak.
2. In **TwinNet-only** mode those queries were never in the protected scope, so they are out of
   scope by definition.
3. Containment blocks DoH to a maintained list of **known** encrypted-resolver endpoints; the list
   is explicitly incomplete and is a detection aid only.
4. Where `DNSPolicy` requests it, the stub answers `use-application-dns.net` with NXDOMAIN to
   trigger the canary-based DoH opt-out some browsers honour. This is a hint that a browser may
   ignore, and is documented as such.
5. **Residual exposure, recorded:** a novel embedded resolver speaking HTTPS to an arbitrary host
   is not detectable at this layer. This confirms `docs/reliability.md` §2.4's identical statement
   rather than contradicting it. Suspicion is surfaced as
   `DNS.PLATFORM.APP_EMBEDDED_RESOLVER_SUSPECTED`; no guarantee is made.

### 11.9 Platform bypass channels, named (A-09, D1, D10)

Each row names the platform's specific bypass, the steering that reduces it, and the containment
that holds when steering fails. **Containment is always ADR-0012 §11.2 class 6 + Tier 2 — one
dual-family object, interface-scoped, default-deny — and it is the guarantee.**

| Platform | The named bypass | Steering | Containment when steering fails | Residual |
|---|---|---|---|---|
| **Windows** | **Smart Multi-Homed Name Resolution (SMHNR).** The `dnscache` service sends the same query out **every** adapter in parallel and takes the first answer, so a query reaches the LAN/ISP resolver even with a correct interface-scoped resolver. It also splits A and AAAA across adapters. `dnscache` is a resolver process outside the tunnel's routing scope — exactly A-09's parenthesis | NRPT rules for every split domain, and for `.` in `FULL` mode, which makes the matched namespace non-parallel; interface-scoped resolver on our adapter | WFP `ALE_AUTH_CONNECT_V4`/`_V6` in ADR-0012's single sublayer deny UDP/TCP 53, TCP 853, and known-DoH endpoints on every non-overlay interface **regardless of which process opened the socket** — which is precisely why containment, not configuration, is the guarantee | Unmatched namespaces still resolve in parallel *within* the containment; observed as `DNS.PLATFORM.PARALLEL_RESOLUTION_SUSPECTED` |
| **macOS** | **`mDNSResponder` per-interface behaviour.** It maintains per-interface resolver configurations and will query an interface's resolvers for names scoped to it; `.local` always goes to multicast | `NEPacketTunnelNetworkSettings.dnsSettings` with `matchDomains` covering the split set (or `[""]` in `FULL` mode), `.local` **excluded** so mDNS keeps working | `pf` anchor `twinvpn`, both families, denying 53/853/known-DoH off-overlay | Apple system services the OS exempts; enumerated as `POLICY.EXEMPT.PLATFORM_MANDATED` |
| **iOS** | Same `mDNSResponder` behaviour, **and no host firewall exists at all** | `NEDNSSettingsManager` / tunnel `dnsSettings`, `.local` excluded | `includeAllNetworks = true` on the provider is the only containment available; there is no packet filter to fall back on | The largest residual in this ADR. Disclosed per ADR-0012's iOS limitation row; measured, not assumed |
| **Android** | **Private DNS.** A user- or DPC-set DoT hostname is honoured by the platform resolver and an app **cannot** change it. In strict mode it overrides the VPN-supplied resolver for queries the platform does not scope to the VPN | `VpnService.Builder.addDnsServer(<anycast>)` for both families + `addSearchDomain` | `VpnService` claiming `0.0.0.0/0` **and** `::/0` carries the DoT traffic **inside** the tunnel — so with a full route claim this is a steering failure, not a leak. Without lockdown, ADR-0012's Android limitation row governs | `TwinNet` names fail to resolve while strict Private DNS is active. Detected and surfaced as `DNS.PLATFORM.PRIVATE_DNS_ACTIVE` with the next action "set Private DNS to Automatic". TwinVPN MUST NOT change the setting (it cannot, and it would be a host-global destructive change forbidden by `docs/networking.md` §5.5) |
| **Linux** | `systemd-resolved` querying **all** links when no link is the DNS default route; or, without `resolved`, NetworkManager/`dhclient` racing our `/etc/resolv.conf` rewrite | `SetLinkDomains(["~."])` + `SetLinkDefaultRoute(true)`; owner-tagged `resolv.conf` otherwise | nftables `table inet twinvpn` denying 53/853/known-DoH on non-overlay interfaces, both families in one table | A local root process can rewrite either; it already holds the privilege to rewrite the rule set (ADR-0012 KS-10's argument) |
| **OpenWrt** | `dnsmasq` serves the LAN and has its own upstream list, which DHCP on the WAN updates | UCI `server=/<zone>/<anycast>`; `dnsmasq` is not replaced | `fw4`/nftables `inet` table | Downstream LAN clients' DNS is gateway policy ([ADR-0013](ADR-0013-multi-client-gateway-architecture.md)), not this ADR's; KS-2 forbids the forwarding path from using any exemption |

### 11.10 Captive portals (reconciling with ADR-0012 §11.7)

ADR-0012 selected **C3** and its KS-14/KS-15 are consumed unchanged: no automatic exemption,
`portal_policy ∈ {PROMPT, NEVER}`, ≤ 300 s, kernel-expiring, scoped to the detected portal
endpoints plus the DHCP/RA-supplied resolvers of the attaching interface. Nothing here widens that.

**Rule DN-27 — the portal scope.** While a `PortalExemptionGrant` is live, the stub serves a
`portal`-scope view in which: `twinnet`-zone names are still answered authoritatively from the
contract; protected-scope names are still `DNS.RESOLUTION.BLOCKED_FAIL_CLOSED`; and default-class
names are forwarded to the grant's resolver set only. Every answer is tagged `portal`, its TTL is
clamped to `min(answer TTL, remaining grant seconds)`, it is written only to the portal cache, and
the entire portal cache is flushed at grant expiry. `DNS.LEAK.PORTAL_ANSWER_QUARANTINED` records the
count as a positive observation that KS-16 held.

**Rule DN-28 — the canary keeps running in the protected scope during a grant**, so a portal
exemption cannot mask a leak (§11.12).

**Rule DN-29 — no portal-scope answer is served after expiry**, including from an in-flight query.
Queries outstanding at expiry are answered `SERVFAIL` + EDE 15.

On iOS the portal case is handled by the system's Captive Network Assistant outside our control
and is disclosed as such — ADR-0012 §11.7 already states this and it is not restated as a
capability.

### 11.11 `ConnectionState` guards contributed (no new states, no new transitions)

| Existing transition | Guard this ADR contributes |
|---|---|
| **T29** `* --EV_POLICY_VIOLATION--> BLOCKED` | The DNS reconciler observed actual ≠ intended resolver configuration; or the canary observed an off-tunnel query; or the stub failed while a protected scope existed. Codes: `DNS.STUB.CONFIG_REVERTED`, `DNS.LEAK.QUERY_OBSERVED_OFF_TUNNEL`, `DNS.STUB.PROGRAM_FAILED` |
| **T30** `BLOCKED --EV_SECURE_PATH_RESTORED-->` steady | In addition to ADR-0012 KS-18's two conditions: the stub is answering on all four addresses and the reconciler confirms the platform scoped-DNS configuration matches intent, for **both** families |
| `→ DEGRADED` | Only `twinnet`-scope resolution is affected (e.g. `DNS.PLATFORM.PRIVATE_DNS_ACTIVE`), while protected resolution is intact — matching `docs/reliability.md` §2.4's "`→ DEGRADED` if only `TwinNet` name resolution is affected" |

This confirms `docs/reliability.md` §2.4's DNS row in full, including its ≤ 2 s reconciler and
≤ 5 s canary intervals, and adds no timer of its own.

### 11.12 Detection: the DNS canary (V3, V4, D9)

Two canaries, both families, at the ≤ 5 s interval `docs/reliability.md` §2.4 sets.

- **Positive canary.** A query for `canary-<nonce>.<twinnet-label>.tnet.twinvpn.net` issued through
  the **host's resolver API** — deliberately not through our own socket, because the property under
  test is that the *host* reaches us. The answer must carry a per-boot authoritative marker. Any
  other answer, or none, is `DNS.STUB.CONFIG_REVERTED`.
- **Negative canary.** A query for a name whose only possible answerer is off-tunnel, emitted from
  a **non-exempt** socket in the protected scope, whose drop must be observed in the enforcement
  layer's own deny counters (the same shape as ADR-0012's §11.9 leak canary). A counter that does
  not increment is `DNS.LEAK.QUERY_OBSERVED_OFF_TUNNEL` at `CRITICAL`, driving T29.

**Making proof test P08 testable exactly as specified.** ADR-0012 §11.9 binds **P08** to "Class 6
containment plus the §11.12(a) interface; `POLICY.LEAK.DNS_UNPROTECTED` and the `DNS.*` codes are
the oracle; the portal-window cache separation of KS-16 is separately assertable", with mutants "a
build that permits egress to the DHCP-supplied resolver while armed, and a build that caches
portal-window answers into protected resolution". This design supplies each piece:

| P08 element | Supplied by |
|---|---|
| Oracle — structured (V6 primary) | `DNS.LEAK.QUERY_OBSERVED_OFF_TUNNEL`, `DNS.STUB.CONFIG_REVERTED`, `DNS.RESOLUTION.BLOCKED_FAIL_CLOSED`, plus ADR-0012's `POLICY.LEAK.DNS_UNPROTECTED` |
| Oracle — wire (V6 corroborating) | Capture on **every** non-overlay interface for UDP/TCP 53, TCP 853, and the known-DoH endpoint list, **both families** (V5) |
| Precondition assertion (V3) | The positive canary proves the host resolver actually reached the stub, so a pass on an inert resolver is impossible |
| Positive control (V4) | The same rig with `mode = OFF` (DN-5's `OFF`), which MUST observe the leak the armed run must not |
| Mutant 1 (ADR-0012's) | A build permitting egress to the DHCP-supplied resolver while armed — fails the negative canary and the wire capture |
| Mutant 2 (ADR-0012's) | A build caching portal-window answers into protected resolution — fails DN-1 by serving a `portal`-scope answer to a `protected`-scope query after expiry |
| Mutant 3 (this ADR's) | A build that falls back to the host resolver on stub failure — fails DN-10 clause 1 |
| Mutant 4 (this ADR's) | A build whose containment covers only v4 — fails V5 on the AAAA canary |

**Reason codes contributed to the `DNS` namespace** ([ADR-0015](ADR-0015-observability-and-diagnostics.md)
§11.2 owns the taxonomy; this ADR owns the `DNS` domain). All are registered with §11.2's full
attribute set; the table gives the discriminating attributes.

| `reason_code` | class | severity | terminal | user_actionable | Condition / next action |
|---|---|---|---|---|---|
| `DNS.STUB.BIND_FAILED` | PERSISTENT | CRITICAL | false | true | A stub listener could not bind; the client refuses to enter a protected state. Next: name the occupying process where determinable |
| `DNS.STUB.PROGRAM_FAILED` | PERSISTENT | CRITICAL | false | true | The platform scoped-DNS configuration could not be applied. Next: named platform mechanism |
| `DNS.STUB.NOT_READY` | TRANSIENT | WARN | false | false | A query arrived before the stub was ready; retry |
| `DNS.STUB.CONFIG_REVERTED` | POLICY | CRITICAL | false | false | The reconciler found the host resolver no longer points at the stub. Next: automatic re-assertion; drives T29 |
| `DNS.STUB.TEARDOWN_INCOMPLETE` | PERSISTENT | CRITICAL | false | true | The prior resolver configuration could not be restored. Next: the privileged local repair command |
| `DNS.STUB.STALE_POINTER_REPAIRED` | POLICY | WARN | false | false | Boot-time restore found the host pointed at a dead stub and restored the `RestorePoint` (D7 met) |
| `DNS.POLICY.RULE_CONFLICT` | POLICY | ERROR | false | true | Two equally specific rules with different dispositions; the bundle is refused at validation (DN-8) |
| `DNS.POLICY.FAMILY_LIST_ABSENT` | POLICY | ERROR | false | true | `servers_v4[]` or `servers_v6[]` absent; protocol §13.4 requires both present (empty ≠ absent). Bundle refused |
| `DNS.POLICY.HANDLING_DISABLED` | PERSISTENT | WARN | false | true | `mode = OFF`; `TwinNet` names do not resolve. Persistent indication |
| `DNS.RESOLUTION.BLOCKED_FAIL_CLOSED` | POLICY | ERROR | false | true | Protected-scope query with no authorized secure path. SERVFAIL + EDE 15 |
| `DNS.RESOLUTION.REFUSED_BY_POLICY` | POLICY | INFO | false | true | The name is refused by `DNSPolicy`. REFUSED + EDE 18 |
| `DNS.RESOLUTION.UPSTREAM_UNREACHABLE` | TRANSIENT | ERROR | false | false | The policy-named upstream is unreachable through the tunnel. SERVFAIL + EDE 22 |
| `DNS.RESOLUTION.TIMEOUT_FAIL_CLOSED` | TRANSIENT | ERROR | false | false | Upstream timed out; **no scope change** (DN-10 clause 2). SERVFAIL + EDE 23 |
| `DNS.RECORDS.FAMILY_WITHHELD` | POLICY | WARN | false | true | A family was withheld because the tunnel cannot carry it (DN-14a). Names the family. NOERROR/0 + EDE 17 |
| `DNS.NAME.TWINNET_UNKNOWN` | POLICY | INFO | false | true | A `TwinNet`-zone name with no contract entry. Authoritative NXDOMAIN |
| `DNS.NAME.LABEL_COLLISION` | POLICY | ERROR | false | true | Two devices claim one label in a contract; refused at validation, the control plane is the authority |
| `DNS.UPSTREAM.ENCRYPTION_DOWNGRADE_REFUSED` | POLICY | ERROR | false | true | The host's encrypted DNS could not be preserved, so forwarding was refused rather than downgraded (DN-24) |
| `DNS.UPSTREAM.FORWARDING_SUSPENDED` | POLICY | WARN | false | true | `DNSPolicy` is EXPIRED, so grant-shaped forwarding is suspended; denials retained (§11.12, ADR-0009 §11.4) |
| `DNS.DNSSEC.VALIDATION_FAILED` | POLICY | ERROR | false | false | Bogus answer; never served, never retried elsewhere. SERVFAIL + EDE 6 |
| `DNS.DNSSEC.CHAIN_UNAVAILABLE` | TRANSIENT | ERROR | false | false | The validation chain could not be fetched. SERVFAIL + EDE 9/10 |
| `DNS.PLATFORM.SCOPED_DNS_UNSUPPORTED` | PERSISTENT | WARN | false | true | The platform exposes no scoped-DNS API; containment still holds, steering does not |
| `DNS.PLATFORM.PARALLEL_RESOLUTION_SUSPECTED` | PERSISTENT | WARN | false | false | Windows SMHNR observed for an unmatched namespace |
| `DNS.PLATFORM.PRIVATE_DNS_ACTIVE` | PERSISTENT | WARN | false | true | Android strict Private DNS overrides the VPN resolver; `TwinNet` names will not resolve. Next: set Private DNS to Automatic |
| `DNS.PLATFORM.MDNS_SCOPE_CONFLICT` | POLICY | INFO | false | true | A `.local` query reached the stub; REFUSED, and the scoped-DNS match set is corrected |
| `DNS.PLATFORM.APP_EMBEDDED_RESOLVER_SUSPECTED` | PERSISTENT | WARN | false | true | An application appears to use its own encrypted resolver; steering does not apply to it (DN-26). No guarantee claimed |
| `DNS.LEAK.QUERY_OBSERVED_OFF_TUNNEL` | POLICY | CRITICAL | false | false | The negative canary's deny counter did not increment. Drives T29 → `BLOCKED` |
| `DNS.LEAK.PORTAL_ANSWER_QUARANTINED` | POLICY | INFO | false | false | A portal-scope answer was kept out of protected resolution (KS-16 held) |

**`DNSPolicy` distribution and expiry — deferring to [ADR-0009](ADR-0009-state-consistency.md),
not inventing a second rule.** S-07 is `MONOTONIC`; a bundle with `policy_version ≤` the stored
high-water mark is refused with ADR-0009's `CONTROL.CONSISTENCY.VERSION_ROLLBACK_REJECTED` (this
ADR defines no rollback code of its own). ADR-0009 §11.4's two-band TTL governs verbatim: **STALE**
(the ordinary control-plane outage) means the bundle **governs fully**; **EXPIRED** means grants
suspend and denials persist, emitting `CONTROL.STALENESS.POLICY_GRANT_SUSPENDED`. Making that
asymmetry mechanically checkable for DNS:

| DNS rule | Grant or deny | Behaviour when the bundle is EXPIRED |
|---|---|---|
| `mode = OFF` | **Grant** (it withdraws handling) | Suspended — the device reverts to `SPLIT` handling with containment |
| A `split_domains[]` entry directing a name to an **underlay** resolver | **Grant** | Suspended; the name becomes `PROTECTED_UPSTREAM`. `DNS.UPSTREAM.FORWARDING_SUSPENDED` |
| `block_fallback = false` for a family | **Grant** | Suspended; the family reverts to blocked |
| A `REFUSE` entry | **Deny** | Retained permanently |
| Containment posture, `FULL`-mode in-tunnel-only forwarding, DN-6, DN-10 | **Deny** | Retained permanently |
| `twinnet`-zone authoritative service | Neither — it is local state, not a grant | Unaffected; **I5** requires names keep resolving |

Established `Session`s are never torn down by expiry ([ADR-0009](ADR-0009-state-consistency.md)
§11.5, **RQ-7**, **I5**).

### 11.13 Interfaces required from other ADRs

| # | Required interface | Owner |
|---|---|---|
| (a) | **Service-address reservation**: `100.127.255.0/24` and `fd7c:9e5d:2a10:ffff::/64` are never allocated to a `Device`, and the resolver anycast addresses are never advertised as a `Route`. Amendment to §11.1 | [ADR-0010](ADR-0010-ipv4-ipv6-routing.md) |
| (b) | **Containment as specified**: §11.2 class 6 (`DROPPED_FAIL_CLOSED` except to the local stub) implemented as a single dual-family object denying UDP/TCP 53, TCP 853, and the known-DoH endpoint list on every non-overlay interface, with "the local stub" expressed as the stub's registered sockets plus the loopback/anycast destinations of §11.2 | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) |
| (c) | **Signed contract fields**: per-`Device` `label`, both overlay addresses, the `twinnet_label`, and the `DNSPolicy` snapshot, applied atomically per generation so the resolver index is rebuilt in the same transaction as routes | [ADR-0003](ADR-0003-network-contract-schema-format.md), [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) |
| (d) | **Policy schema in which grant and deny rules are mechanically distinguishable**, so §11.12's expiry asymmetry is checkable rather than conventional; and `servers_v4[]`/`servers_v6[]` both **present**, empty meaning "block this family" and absent being a schema violation | [ADR-0003](ADR-0003-network-contract-schema-format.md), [ADR-0009](ADR-0009-state-consistency.md), `docs/protocol.md` §13.4 |
| (e) | **Device-label uniqueness within a `TwinNet`**, enforced at the authority (S-02), never negotiated between peers | [ADR-0007](ADR-0007-device-identity-and-pairing.md), [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) |
| (f) | **Gateway-served DNS for downstream clients** (a `LANGateway` answering for LAN hosts) is per-client policy, distinct from this device-local stub, and never uses any ADR-0012 exemption on the forwarding path (KS-2) | [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) |
| (g) | A `Capability` expressing DNS posture (`dns_scoped_api`, `dns_dnssec_validate`, `dns_upstream_dot`, `dns_config_dies_with_tunnel`) so a mixed fleet degrades explicitly | [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) |
| (h) | Registration of the `DNS.*` domain as **owned by this ADR**, with the codes of §11.12 in the machine-readable registry | [ADR-0015](ADR-0015-observability-and-diagnostics.md) |
| (i) | `ExitNodeEngaged.dns_servers_v4[]`/`dns_servers_v6[]` present per family, absent being a denial, consistent with `granted_default_v4`/`granted_default_v6` | `docs/protocol.md` §13.3 |

### 11.14 State ownership

No existing row is duplicated. **S-07 `DNSPolicy`** remains `Owner`-authored, Control-Plane-distributed, and `MONOTONIC`;
the local resolver index and caches are *derived* from it and from the contract
(`docs/architecture.md` §2.15 "State owned: local resolver configuration and cache (derived)") and
therefore need no row. **One new row is required in `docs/architecture.md` §5:**

| # | State | Authoritative writer | Replicas | Class | Durability | On conflict |
|---|---|---|---|---|---|---|
| **S-34** | `HostResolverRestorePoint` (the verbatim prior host resolver configuration + `restore_token`, DN-18) | **Local `Device` (2.15 via 2.5)** | None | `LOCAL` | **Durable, written and flushed before the mutation it protects**, readable by the boot restore entry point without the agent running | Local wins; a `RestorePoint` whose `restore_token` does not match the installed configuration is treated as stale and the platform default is restored, emitting `DNS.STUB.TEARDOWN_INCOMPLETE` |

Durability is the security-and-reliability property here: a `RestorePoint` that did not survive a
crash would leave the host pointed at a dead resolver, which is D7's defect.

## 12. Why the Selected Option Won

1. **R5 is disqualified by A-16 and R-14 in one sentence each**, and is listed only because it is
   the shipped behaviour of several comparable products.
2. **R2 is disqualified by I5.** A resolver on the far side of the tunnel makes `ssh nas` depend on
   the tunnel being up — inverting the point of a resolver that answers from cached signed state —
   and makes one device a single point of failure (**R-11**). Its real advantage, no local port to
   bind, is conceded by §11.2's fallback loopback address plus the always-available overlay anycast.
3. **R1 and R3 answer two different questions, not one.** R3 can steer but not answer; R1 can answer
   but not steer. The honest form is the hybrid, and §11.7/§11.9 say plainly that R3's half differs
   on every platform — on iOS it is the *only* half, on Android it is defeated by a setting we cannot
   change. Claiming one uniform mechanism here would be claiming something false.
4. **R4 is kept as a transport option and refused as a containment story.** An encrypted query to a
   network-supplied resolver while armed has still escaped the tunnel; saying so is what stops DoH
   from being sold internally as the leak fix.
5. **The guarantee is containment, not configuration.** Every steering mechanism in §11.9 can fail
   and three can be overridden by the platform or the user. What holds regardless is ADR-0012 class
   6 — one dual-family, interface-scoped, default-deny object that does not care which process opened
   the socket. That is the direct answer to **A-09**'s "resolver processes outside the tunnel's
   routing scope", and it is why the normative weight sits on DN-10 and §11.12's canary rather than
   on resolver configuration.
6. **N2 is a protocol violation, N1 is not unique, and N3 is not unique either** though otherwise the
   strongest runner-up. **N4 wins on the one axis that cannot be mitigated**: two `TwinNet`s, or a
   `TwinNet` and an employer's network, sharing a host must not share a namespace. It also makes the
   escape case *defined* — an unsigned delegation to an empty zone, so a validator sees insecure
   rather than bogus — and DN-6 closes the label-leak channel on devices running the agent.
7. **The A/AAAA rules are stated as two cases because that is where most designs go wrong.**
   Withholding an unreachable family is a latency fix; blocking a routable one is a firewall's job.
   Conflating them yields either a leaking product with tidy DNS or a product that breaks IPv6 to
   feel safe. §11.6 refuses both.
8. **D7 is treated as a first-class product defect**: a `RestorePoint` written before the mutation, a
   boot restore entry point that needs no healthy agent, ordered after enforcement, and a table that
   says which platforms get the property for free and which — Windows and non-`resolved` Linux — do
   not.

## 13. Known Tradeoffs

| Tradeoff | Accepted because |
|---|---|
| A vendor domain appears in every hostname | Global uniqueness is the one property N1/N3 cannot provide, and namespace collisions on a shared host are unfixable at runtime |
| We operate a public zone whose only job is to return nothing | It makes the escape case defined and provably insecure rather than undefined, and it costs nothing at runtime |
| The stub is a DNS parser on the fail-closed path | Mitigated by DN-4's minimality rules and the `fz-dns-response` structure-aware fuzz corpus already specified in `docs/testing-strategy.md` §2.12; the alternative (R5) is the defect |
| `SPLIT` mode forwards out-of-scope names to pre-existing resolvers over the underlay | Those names were never in the protected scope; forbidding them would silently convert split-tunnel into full-tunnel DNS. DN-10 draws the line at *fallback*, and clause 2 forbids scope changing on failure |
| Android strict Private DNS breaks `TwinNet` name resolution | We cannot change the setting and must not try (`docs/networking.md` §5.5). The honest outcome is `DEGRADED` with a named next action, not a silent mis-resolution |
| iOS has no packet filter, so containment there is the platform's | Stated, not papered over; it is the same residual ADR-0012's iOS limitation row already discloses, and it is measured rather than assumed |
| Browser-embedded DoH is out of scope | Undetectable at this layer for a novel resolver; `docs/reliability.md` §2.4 already says so. Claiming otherwise would be the false guarantee this corpus exists to avoid |
| Withholding a family produces NODATA, which some software handles poorly | The alternative is a connect timeout on every attempt; EDE 17 makes the reason legible, and DN-15 forbids treating this as security |
| Windows and non-`resolved` Linux need a `RestorePoint` and a boot restore unit | They are the two platforms where the resolver pointer outlives the tunnel object; the mechanism is named and the risk is stated rather than assumed away |
| The `DNS` code set is large (27 codes) | Each names a distinct condition with a distinct next action; collapsing them reintroduces **R-22**'s cryptic-error defect, and `dig`-visible EDE text is only useful if the code is specific |

## 14. Revisit Conditions

1. **If `DNS.LEAK.QUERY_OBSERVED_OFF_TUNNEL` fires anywhere outside a deliberate test**, §11.5's
   fallback prohibition or §11.9's containment has a counterexample on that platform. Treat as a
   security incident, freeze the platform's release, and re-derive §11.9's row before shipping again.
2. **If `DNS.STUB.STALE_POINTER_REPAIRED` exceeds 0.5% of boots on any platform**, §11.7's backstop
   is being used as the primary mechanism: clean teardown is not the common path there, and the
   resolver configuration must move to a tunnel-object-owned form or the platform be reclassified.
3. **If `DNS.PLATFORM.PRIVATE_DNS_ACTIVE` exceeds 10% of Android sessions**, the `TwinNet` namespace
   is unresolvable for a tenth of that platform's users and N4 must be paired with a
   platform-specific mechanism (a DPC-managed Private DNS target pointing at our anycast, or an
   in-app resolver for first-party surfaces) rather than a warning.
4. **If `DNS.STUB.BIND_FAILED` exceeds 0.5% of bring-ups on any desktop platform**, loopback port 53
   is contested often enough that the overlay anycast address must become primary there too.
5. **If measured p95 added latency for `PROTECTED_UPSTREAM` resolution in `FULL` mode exceeds 150 ms
   over the direct-resolution baseline**, in-tunnel forwarding is a user-visible cost and
   `upstream_transport = DOH` to a resolver co-located with the `ExitNode` must be evaluated as that
   mode's default.
6. **If a platform ships an API by which a remote management channel can change the device's
   resolver configuration without local authentication**, DN-18's `RestorePoint` no longer bounds
   the blast radius; that platform's row in §11.9 and ADR-0012 KS-22 must be re-derived together.
7. **If queries reaching the stub fall below 90% of a desktop host's total observed DNS volume**
   (app-embedded resolvers dominating), split-DNS steering has stopped being the mechanism that makes
   `TwinNet` names work, and name-based access must be re-derived around per-application integration
   rather than the OS resolver.
8. **If `100.127.255.0/24` or the ULA service `/64` is ever observed in use as a client LAN prefix
   in more than 0.5% of networks**, §11.2's anycast literals collide with a real network and must
   move, together with [ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.1's reservation.
9. **If a future `ProtocolVersion` introduces per-record-type or per-application DNS policy**,
   §11.4's five-class precedence is insufficient (it classifies by name only) and the matching
   model must be re-derived before that policy shape is expressible.
