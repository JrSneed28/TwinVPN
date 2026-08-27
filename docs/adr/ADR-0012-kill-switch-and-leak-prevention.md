# ADR-0012: Kill Switch and Leak Prevention

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** SECURITY
- **Related:** [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md),
  [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md),
  [ADR-0003](ADR-0003-network-contract-schema-format.md),
  [ADR-0005](ADR-0005-relay-architecture.md),
  [ADR-0006](ADR-0006-relay-discovery-and-failover.md),
  [ADR-0007](ADR-0007-device-identity-and-pairing.md),
  [ADR-0010](ADR-0010-ipv4-ipv6-routing.md),
  [ADR-0011](ADR-0011-dns-handling.md),
  [ADR-0013](ADR-0013-multi-client-gateway-architecture.md),
  [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md),
  [ADR-0015](ADR-0015-observability-and-diagnostics.md),
  [docs/architecture.md](../architecture.md), [docs/networking.md](../networking.md),
  [docs/protocol.md](../protocol.md), [docs/reliability.md](../reliability.md),
  [docs/testing-strategy.md](../testing-strategy.md), [docs/threat-model.md](../threat-model.md)

This ADR owns the **kill-switch policy**: what "protected traffic" means, which traffic classes
are permitted when no authorized secure path exists, which enforcement point is used on each
platform, what durability guarantee each platform can actually deliver, the ordering rules that
close the transition and boot windows, the local-authority rule that makes disengagement
impossible for any remote actor, and the `POLICY.*` reason codes for blocked and leak
conditions. It does **not** own the leak-prevention *mechanism* ([docs/networking.md](../networking.md)
§9 and [ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.5), DNS resolution
([ADR-0011](ADR-0011-dns-handling.md)), route installation or the address plan
([ADR-0010](ADR-0010-ipv4-ipv6-routing.md), [docs/networking.md](../networking.md) §7), the
`ConnectionState` machine ([docs/reliability.md](../reliability.md) §4), or per-client gateway
policy ([ADR-0013](ADR-0013-multi-client-gateway-architecture.md)). Where those are needed here,
the required interface is stated in §11.12 and nothing about their internals is invented.

---

## 1. Context

Invariant **I3** says the product fails closed: protected traffic never egresses untunneled while
the kill switch is engaged, and degradation is surfaced as state rather than hidden as recovery.
Requirements **R-13** (no silent fallback to non-tunneled networking) and **R-14** (leak
prevention must cover IPv4 **and** IPv6 **and** DNS simultaneously) are the two defects this ADR
exists to retire, and **R-08** adds the mobile case: OS-initiated process suspension and
termination must not leak on resume.

The mechanism is already decided elsewhere and is strong. `docs/networking.md` §9.1 enumerates
four leak channels and gives each a mechanism; §9.3 gives the ordering guarantee;
[ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.5 makes dual-family policy structurally
inseparable by expressing it as a single object per platform. What is missing — and what a
kill switch actually lives or dies by — is the **policy**: the exact set of traffic classes and
their disposition, and above all the **bootstrap exception**.

The bootstrap exception is the single most dangerous hole in any kill switch. A fail-closed
device that cannot reach a relay or a rendezvous service can never recover, so *something* must
be permitted to leave the machine while the protected scope is blocked. Every real product has
this hole. Most specify it as "our own traffic is allowed", which is not a specification: it is
a destination-unbounded egress permit whose only guard is a process name. §11.5 specifies it
narrowly and proves why it is not usable as a leak channel.

Two further facts shape the design. First, `docs/architecture.md` §5 row **S-18** makes
kill-switch engagement `LOCAL`, durable, OS-level, surviving process death, crash, update and
reboot, and states that **the control plane MUST NOT be able to disengage it** — so the
enforcement point cannot be the agent process, and no wire message may exist that means
"disarm". Second, `docs/reliability.md` §4.4 already defines `BLOCKED` with the disposition
`DROPPED_FAIL_CLOSED` — *always, without exception* — and §4.1 already defines the enforcement
mode pair `FAIL_CLOSED` / `PERMISSIVE_ANNOUNCED` and the traffic-disposition vocabulary. This
ADR supplies the guards and reason codes for those, and introduces no new state and no new
transition.

## 2. Requirements

| # | Requirement |
|---|---|
| **K1** | Protected traffic MUST NOT egress on any interface other than the overlay interface while enforcement is armed and no authorized secure path exists (I3, R-13). |
| **K2** | Enforcement MUST cover IPv4 and IPv6 identically and atomically. A v4-only guard is a leak (R-14, P9). |
| **K3** | Enforcement MUST be installed at OS level, independent of the agent process, and MUST survive agent crash, `SIGKILL`, agent update, and OS reboot (S-18, A-17, A-08). |
| **K4** | The control plane MUST NOT be able to disengage enforcement, and neither may any remote actor, including a fully compromised control plane or a compromised update channel (S-18). |
| **K5** | The `Owner` MUST be able to disengage enforcement deliberately, from the local device, with OS-mediated authentication, and MUST NOT be able to do so accidentally or by remote instruction. |
| **K6** | Every permitted exception MUST be enumerated, narrow, matched by a stable predicate, and provably unusable as a channel for protected traffic. |
| **K7** | Rules MUST be live before the overlay interface can carry traffic, and MUST remain live after it is destroyed, including across an unclean exit and across the boot-time window before the agent starts. |
| **K8** | Every blocked condition MUST surface a stable `reason_code`, human-actionable text, and a next action (I6, R-22, O-01). A silent black hole is the defect being retired. |
| **K9** | An ungranted address family MUST be blocked rather than leaked, per-family and independently (protocol.md A13, ADR-0010 §11.5(3)). |
| **K10** | Where a platform cannot deliver a durability or coverage guarantee, the residual exposure MUST be stated, measured, and surfaced — never papered over. |
| **K11** | Enforcement MUST coexist with host firewalls, endpoint-security filters, other VPNs, and other virtual adapters without disabling any of them (`docs/networking.md` §5.5). |
| **K12** | Enforcement state MUST be observable by querying the installed rules, not by trusting the agent's belief about what it installed (O-17). |

## 3. Constraints

- **I3, I6, P3, P9** — fail closed; every failure named; IPv6 is never a feature flag.
- **S-18** — one writer (the local `Device`), `LOCAL`, durable, OS-level; no remote replica.
- **`docs/networking.md` §5.5** — TwinVPN MUST NOT disable the host firewall, the host resolver
  service, or IPv6 globally; MUST NOT delete or modify routes it did not create; all state
  written outside our own interface MUST be owner-tagged and reclaimable after an unclean exit.
- **[ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.5(3)** — IPv6 is *blocked at the policy layer*,
  never disabled at the host stack.
- **`docs/networking.md` §7.2(3)** — the `/1` routes are a routing convenience, not a security
  control. Anything that installs a more-specific route, binds a source address, or uses a raw
  socket defeats routing but not the firewall.
- **`docs/reliability.md` §4** — `BLOCKED` is the only fail-closed holding state; this ADR may
  supply guards and reason codes, never states or transitions.
- **Platform reality** — iOS exposes no host firewall at all; Android's lockdown mode is a
  Settings/DPC toggle a normal app cannot set programmatically; macOS Recovery and Linux
  single-user mode do not run our daemons.
- **Phase 1 produces no code.**

## 4. Considered Alternatives

Three orthogonal decisions, each with genuine alternatives.

**Group M — arming policy (when enforcement applies).**

| # | Alternative |
|---|---|
| **M1** | **Always-on fail-closed.** Enforcement is armed from first install, at every boot, unconditionally, until an `Owner`-authenticated local disarm. The device has no unprotected state. |
| **M2** | **Fail-closed while a `Session` is intended-up.** A durable local `session_intent` latch (`UP`/`DOWN`) is set by an explicit local user connect and cleared only by an explicit local user disconnect. Enforcement is armed exactly while the latch is `UP` — across crash, kill, update and reboot. |
| **M3** | **Per-route / per-destination scoped blocking.** Enforcement is expressed as a deny list of destination prefixes (the overlay prefixes, accepted `Route`s, and in full-tunnel mode "the Internet"), evaluated against the destination address of each packet. |
| **M4** | **Off.** No enforcement; loss of a secure path results in untunneled egress, announced persistently. This is `docs/reliability.md` §4.1's `PERMISSIVE_ANNOUNCED` mode. |

**Group E — enforcement point (where blocking happens).**

| # | Alternative |
|---|---|
| **E1** | **OS packet-filter rules.** nftables `table inet twinvpn` on Linux/OpenWrt; a dedicated WFP sublayer with persistent and boot-time filters on Windows; a `pf` anchor plus `NEPacketTunnelProvider` settings on macOS; `NEPacketTunnelProvider` with `includeAllNetworks` on iOS; `VpnService` route claim plus OS always-on lockdown on Android. |
| **E2** | **Routing-table blackhole / unreachable routes.** Install `blackhole`/`unreachable`/`prohibit` routes covering the protected scope for both families whenever no authorized path exists. |
| **E3** | **Null-route + firewall hybrid.** E2 as the fast path and E1 as the backstop, with the routing layer treated as a first-class part of the guarantee. |
| **E4** | **Userspace-only.** The agent owns the tun device and simply refuses to forward packets it reads while unprotected; no OS state outside the interface is written. |

**Group C — captive portals (fail-closed on an unauthenticated hotel Wi-Fi).**

| # | Alternative |
|---|---|
| **C1** | **No exemption ever.** The portal is unreachable while armed; the only path is a deliberate `Owner` disarm. |
| **C2** | **Automatic exemption on portal detection.** On `NET.CAPTIVE_PORTAL` the enforcement layer opens a scoped hole automatically, with a notification. |
| **C3** | **Time-boxed, user-consented, kernel-expiring, scope-narrowed exemption.** Portal detection surfaces an affordance; a local user action opens a ≤ 300 s exemption to the detected portal endpoints and the DHCP-supplied resolver only, expiring in the kernel independently of the agent. |

## 5. Advantages of Each Alternative

**M1 — always-on.** The strongest possible property, and the easiest to reason about: there is
no window, no latch to get wrong, no state in which the user believes they are protected and are
not. It is also the only mode that protects against the "I forgot to connect" failure, which is
empirically the most common way people leak. It maps cleanly onto Android's "Block connections
without VPN" and onto iOS supervised Always-On VPN, so on two platforms it is the *native*
expression of I3 rather than something we bolt on.

**M2 — armed on intent.** Fail-closed for every state in which the user believes they are
protected, which is precisely the I3 obligation, while leaving a device that the user has
deliberately disconnected in a working state. Because the latch is durable and OS-level, it
survives every event in K3: a crash, a `kill -9`, an update, and a reboot all resume armed. The
protected scope in the default routing mode (TwinNet-only) is only the overlay prefixes, so
arming costs the user nothing they would notice, which means the setting is not one people learn
to turn off — and a kill switch users disable is worth zero.

**M3 — destination-scoped blocking.** Expressive: it can encode split-tunnel and per-route
policy directly, with one rule per prefix, and it degrades gracefully when only part of the
policy can be installed. It is also the only formulation that maps onto platforms where the only
lever is a route table, and it is trivially auditable prefix by prefix.

**M4 — off.** Maximum availability. Nothing the user does can render the device unreachable, no
support call ever begins with "my internet stopped working". For a user whose threat model is
"I want to reach my NAS", untunneled egress of everything else is not a harm at all.

**E1 — OS packet filter.** The only mechanism that is enforced by the kernel independently of
our process, that covers raw sockets and source-bound sockets, that cannot be defeated by a more
specific route, and that persists across process death by construction. Every platform in the
support matrix exposes one, and `docs/networking.md` §5.2 already names the exact facility per
platform. It is also the only mechanism that can be made structurally dual-family:
[ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.5(1)'s single-object property is a property of
packet filters, not of route tables.

**E2 — routing blackhole.** Cheap, entirely reversible, needs no privileged filter subsystem,
and works identically on router-class targets with minimal userspace. It composes naturally with
the `/1` route form already chosen in `docs/networking.md` §7.2 and is one `apply()` transaction
away from the routes we install anyway. It also produces immediate, legible local errors
(`ENETUNREACH`) rather than silent drops, which applications handle better than black holes.

**E3 — hybrid.** Gets E2's fast, legible local failure for the common case and E1's
completeness for the adversarial case. Defense in depth is a genuine property here: two
independent mechanisms must both fail for a leak to occur, and they fail for different reasons.

**E4 — userspace only.** Requires no elevated privilege beyond creating the tun device, writes
nothing outside our own interface, cannot possibly leave the host permanently broken, and is the
only option on a platform that forbids third-party filtering entirely. It is also trivially
portable — one implementation, no per-OS filter dialect.

**C1 — no portal exemption.** Unambiguous, un-abusable, and needs no detection logic, so a
hostile network cannot manipulate a detector it fully controls. The exemption that does not
exist cannot be widened by a bug.

**C2 — automatic exemption.** Best usability by a wide margin: the hotel Wi-Fi simply works, the
way an unprotected laptop does, and the user never has to understand the interaction between a
kill switch and a portal.

**C3 — consented, time-boxed exemption.** Preserves the fail-closed property for the protected
scope throughout — the exemption never covers protected traffic, only the portal conversation —
while making the network usable. Because it expires in the kernel, agent death cannot leave the
hole open, which is the failure mode that makes portal exemptions dangerous in other products.

## 6. Disadvantages of Each Alternative

**M1 — always-on.** A fresh install that has never completed a connection would black-hole the
device's network at boot before the user has consented to anything, which is both a support
catastrophe and a *security* regression by second-order effect: it teaches users to disable the
kill switch outright, converting a partial protection into none. It also interacts badly with
the bootstrap exception on a device that has no cached relay set yet — there is a genuine
chicken-and-egg state in which nothing can be fetched and nothing can recover. And on a
travelling laptop it makes every captive portal a hard stop.

**M2 — armed on intent.** There is exactly one class of traffic M1 protects and M2 does not:
traffic sent while the user has deliberately and locally set the latch to `DOWN`. That is a real
gap and it is not zero — a user who disconnects "for a minute" and forgets is unprotected. M2
also introduces a durable latch, which is a new persistent fact that can be corrupted, and whose
correctness across update and reboot must itself be tested.

**M3 — destination-scoped blocking.** This is the allow-list-shaped formulation that
[ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.5(2) rules out, and for a specific reason: a
prefix-keyed rule set must be *updated* when a new interface appears, a Router Advertisement
arrives, tethering starts, or a VM bridge is created. Any window between the new prefix existing
and the rule being installed is a leak, and correctness depends on a rule update racing a
network event. It is also structurally family-separable — one prefix list for v4, another for
v6 — which is exactly the drift that produces v4-only guards (R-14).

**M4 — off.** It is the defect. R-13 names "silent fallback to non-tunneled networking" as a
historical defect the product exists to retire; shipping it as the default would make the
product's central claim false.

**E1 — OS packet filter.** Requires elevated privilege and a per-platform implementation in five
genuinely different dialects. It writes state outside our own interface, so a crash can leave the
host either unprotected or — worse — permanently blocked, which is why owner-tagging and offline
recovery (`docs/networking.md` §5.5.3) are mandatory rather than nice. It is also the layer most
likely to collide with endpoint-security products (`NET.WFP_UNAVAILABLE` exists for this reason).

**E2 — routing blackhole.** Routes are not a security control. A process that installs a more
specific route, binds a source address, or opens a raw socket bypasses the route table entirely;
so does any traffic emitted by a component sitting below the routing layer. On iOS and Android
there is no route API that can express a blackhole independently of the tunnel settings object,
so the mechanism is unavailable on two of six platforms. And because route state is per-family
by construction, it is family-separable in exactly the way M3 is.

**E3 — hybrid.** The specific risk is not technical but organisational: with two mechanisms
present, the weaker one accumulates the reasoning. Every "the route is already blackholed" makes
the filter rule feel redundant, and the filter rule is the one that is actually load-bearing.
Held as *defense in depth beneath a filter that stands alone*, the hybrid is fine; held as a
guarantee, it is a slow-motion regression.

**E4 — userspace only.** **A userspace-only kill switch dies with the process.** `SIGKILL`, an
OOM kill, an iOS extension termination, a crash, a panic, or an update that stops the old binary
before starting the new one all remove the enforcement instantly and silently, and the host
resumes egressing over its ordinary default route with no indication. It cannot survive reboot,
it cannot cover traffic that never reaches our tun device (which is all traffic, once our routes
are gone), and it fails K3 and A-08 categorically. This is the alternative that must be listed
and must be rejected.

**C1 — no portal exemption.** Makes hotel, airport, conference and campus Wi-Fi unusable without
a full `Owner` disarm, which is a far larger and far longer-lived hole than the exemption would
have been. It optimises the specification at the cost of the actual outcome: users disarm, use
the network, and forget to re-arm.

**C2 — automatic exemption.** The detector's inputs are entirely controlled by the adversary:
the network supplies DNS and can return a redirect for any probe. An automatic exemption is
therefore an attacker-triggerable egress permit. It also has no natural expiry tied to anything
the attacker does not control.

**C3 — consented, time-boxed exemption.** Still an attacker-*prompted* affordance: a hostile
network can reliably cause the prompt to appear, and users click prompts. It requires an
auto-expiring rule primitive on every platform, which does not exist uniformly (`nftables` set
element timeouts do; WFP needs a scheduled removal plus a watchdog; iOS has no such API at all
and the case is handled entirely by the system's own Captive Network Assistant, outside our
control). And portal DNS must be permitted, which forces a real interface obligation on
[ADR-0011](ADR-0011-dns-handling.md) to keep portal-window answers out of the protected
resolution path.

## 7. Security Implications

- **The bootstrap exception is the whole security argument.** §11.5 binds it to (i) process
  identity established by an OS-mediated predicate, (ii) an explicitly registered socket set,
  and (iii) the structural fact that no application traffic can enter those sockets — the agent
  exposes no proxy, no SOCKS listener, and no packet-injection interface. A local adversary able
  to satisfy (i) already holds the privilege required to rewrite the rule set, so the exemption
  grants them nothing they did not have. This is the argument that makes the hole non-abusable;
  it is not destination scoping, because relay and peer endpoints are legitimately arbitrary.
- **Enforcement is monotone in the safe direction with respect to remote input.** The effective
  enforcement is `max(local_mode, policy_required_mode)`; the `AccessPolicy` schema has no field
  that can narrow enforcement below the local setting (§11.10). A fully compromised control plane
  can therefore only make the device *more* blocked, which is a denial of service — a real harm,
  but a categorically lesser one than a leak, and one that is visible rather than silent.
- **There is no wire message that means "disarm".** This is a structural property required of
  [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) in §11.12, not a check in the
  agent. A check can be bypassed; an absent message type cannot be sent.
- **The management plane is explicitly in scope.** `docs/architecture.md` §4.1 requires that the
  update service must not be able to disable protection without `Owner` action. §11.6 therefore
  requires updates to replace the rule set by atomic swap, never remove-then-add, and requires
  the boot-time rule set to be installed by an artifact the OS applies, not by the updater.
- **IPv6 and per-family grants.** A v4-only tunnel, or an `ExitNode` that grants
  `granted_default_v4` without `granted_default_v6` (`docs/protocol.md` §13), results in the
  ungranted family being **blocked**, surfaced as `POLICY.LEAK.FAMILY_GRANT_MISSING` /
  `POLICY.LEAK.IPV6_UNPROTECTED`, and the connection entering `DEGRADED`. Absent grant is denial,
  never permission.
- **Detection, not only prevention.** §11.9's leak canary is an *active* control: a marked probe
  emitted from a non-exempt socket in the protected scope, both families, whose drop must be
  observed in the enforcement layer's own counters. Prevention that is never observed to work is
  a belief, and O-17 forbids the product from reporting beliefs as protection status.
- **Where a rejected alternative was better:** **M1 (always-on)** is strictly safer than the
  selected M2 on exactly one axis — traffic sent while the user has deliberately disconnected —
  and that gap is real. It is mitigated, not eliminated: M1 remains a first-class, one-toggle
  setting; it is the recommended setting for full-tunnel and untrusted-network use; and it is
  what the product maps onto Android lockdown and iOS supervised always-on. **C1 (no portal
  exemption)** is strictly safer than C3 and is preserved as the `NEVER` setting.

## 8. Reliability Implications

- **`BLOCKED` is a holding state, not a terminal one** (`docs/reliability.md` §4.6). The
  re-establishment loop runs *inside* it at the floor backoff rate, forever, because a device that
  gave up while blocked would be permanently offline with no path back. That loop is precisely
  what the bootstrap exception exists to enable — remove the exception and `BLOCKED` becomes
  absorbing.
- **Recovery is control-plane-free (I5).** Everything the loop needs — cached `Endpoint` set
  (S-15), cached ranked `Relay` set with ≥ 2 alternates per region (S-09), `TrustedPeer` (S-05) —
  is local durable state. The exemption therefore does not need to reach the control plane to
  recover, only a relay or a peer; control-plane reachability is a convenience, not a
  precondition. This is why the exemption can be narrow.
- **Arming must never fail open.** `docs/architecture.md` §2.16: if the rule set cannot be
  installed, the client MUST refuse to enter a protected state and MUST report why
  (`POLICY.KILLSWITCH.ARM_FAILED`). "Couldn't protect, so proceeded unprotected" is the defect
  this component exists to eliminate.
- **Availability cost is real and asymmetric.** A device in `BLOCKED` has no Internet for its
  protected scope. In the default TwinNet-only routing mode that scope is only the overlay
  prefixes, so the cost is "you cannot reach your other devices" — a truthful statement of
  reality. In full-tunnel mode the cost is total, which is why the mode choice and the
  `BLOCKED` reason code must both be visible at all times.
- **Suspend/resume.** `docs/reliability.md` T34/T35 keeps enforcement rules installed across
  suspend and re-asserts `Route`/`DNSPolicy`/firewall on resume before emitting traffic. §11.6's
  ordering makes that re-assertion a no-op in the common case rather than a window.

## 9. Performance Implications

- The steady-state cost is a small number of stateful filter rules per family evaluated once per
  packet on egress. On Linux this is one `inet` table with an interface-match fast path; on
  Windows it is one sublayer with ALE-layer filters evaluated at connect time, not per packet,
  for connection-oriented flows. Neither is measurable against the tunnel's own crypto cost.
- **The single-object dual-family form is also the cheapest form.** One `inet` table matching
  both families avoids duplicated rule traversal, so the structural safety property of
  [ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.5(1) costs nothing.
- Policy re-assertion on network change is bounded at 1 s (`docs/networking.md` §9.1) and is
  belt-and-braces, not the guarantee, so it may be rate-limited under interface churn without
  weakening correctness.
- The leak canary is a single small datagram per family per interval; the interval is a knob, and
  its cost is dominated by the wake it causes on mobile, which is why §11.9 ties it to existing
  wake points rather than to its own timer.
- `BLOCKED` has a real *battery* cost via the internal retry loop; `docs/reliability.md` §6.1
  caps it at a 30 s floor rate specifically so a blocked device does not burn a battery.

## 10. Operational Implications

- **An offline recovery path is mandatory where the platform admits one.** A crash between
  "rules installed" and "agent running" leaves a host blocked with no UI. Every platform on which a
  privileged local command can exist ships one: privileged, local, network-independent, removing the
  owner-tagged rule set and clearing the latch, documented in support material. Without it, a bug in
  this ADR bricks connectivity.
  **Qualified (KS-20a): this is satisfiable on four of the six required platforms, not six.** On
  **iOS/iPadOS** the only unblock is removing the VPN profile in Settings; on **Android** it is the
  always-on toggle or uninstall. **Neither is ours, neither is a command, and the two have different
  consequences** — so the obligation is marked `n/a` for `HC-2` and the platform-native equivalent is
  documented in its place. This is the same qualification §11.6's durability table already applies to
  boot enforcement, and stating it here prevents a claim the product cannot meet.
- **Support must be able to answer "why is nothing working".** The `POLICY.*` code, the routing
  mode, the enforcement mode, and the protected-scope generation are required fields of the
  connectivity report ([ADR-0015](ADR-0015-observability-and-diagnostics.md) O-06), producible
  with no network at all (O-07).
- **Fleet telemetry** must report: time spent in `BLOCKED` by reason code; arm-failure rate by
  platform and by suspected conflicting product; boot-window residual-exposure incidence;
  portal-exemption grant rate and mean duration; and per-family grant asymmetry incidence. All
  five feed the revisit conditions in §14.
- **Third-party conflicts are named, not guessed at.** `PLATFORM.THIRD_PARTY_FILTER_SUSPECTED`
  and `NET.WFP_UNAVAILABLE` already exist; §11.11 adds `POLICY.COEXIST.*` for the two-VPN case.
- **Enterprise deployment** should prefer the platform-native always-on expression (Android DPC
  lockdown, iOS supervised Always-On VPN, Windows via the persistent WFP set) because those are
  enforced by the OS against the user as well as against the network.

## 11. Decision

**Adopt M2 (fail-closed while intended-up) as the default arming policy, with M1 available as a
first-class setting and M4 available as an announced opt-out; adopt E1 (OS packet filter) as the
sole enforcement point, with E2 permitted only as non-load-bearing defense in depth; adopt C3
for captive portals, with C1 available as a setting and C2 rejected outright.**

### 11.1 Protected traffic (normative definition)

A packet is **protected** if and only if it is in the *protected scope*, computed from the
active routing mode (`docs/networking.md` §7.1) and the current contract generation. Enforcement
is expressed in two tiers, and the distinction is load-bearing.

- **Tier 1 — scope selection.** Decides whether a packet is in the protected scope.
- **Tier 2 — enforcement.** For a packet in the protected scope: egress is permitted **only via
  the overlay interface**; on every other interface, deny. Tier 2 is interface-scoped and
  default-deny, is expressed as one object covering both families
  ([ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.5(1)), and **MUST NOT** reference any
  destination prefix.

| Routing mode | Tier-1 protected scope |
|---|---|
| TwinNet-only (default) | Destination ∈ the `TwinNet` `/22`(s) ∪ the `TwinNet` `/64` |
| Split tunnel | The above ∪ every **accepted** `Route` prefix (S-17), both families |
| Full tunnel (`ExitNode`) | **Complement form**: every packet *except* the exempt classes of §11.2. It MUST NOT be expressed as an enumeration of protected prefixes. |
| Per-app | The platform's app set (Android `addAllowedApplication`, Windows WFP app-id, macOS `NETransparentProxy`); unavailable on iOS and Linux (`NET.PERAPP_UNSUPPORTED`) |

**Rule KS-1.** Tier-1 scope changes MUST be applied atomically with the contract generation that
caused them ([ADR-0008](ADR-0008-idempotency.md) idempotency on the generation id). A scope may
never be *narrowed* and a rule set *widened* in two steps; the transition is one transaction.

**Rule KS-2.** Forwarded traffic on a `LANGateway`/`ExitNode` (i.e. packets not locally
originated) is protected by the same Tier-2 rule and is **never** eligible for any exemption in
§11.2. Per-client gateway policy remains owned by
[ADR-0013](ADR-0013-multi-client-gateway-architecture.md); this rule only forbids the exemptions
from reaching the forwarding path.

### 11.2 Traffic classes and their disposition when no authorized secure path exists

Dispositions use `docs/reliability.md` §4.1's vocabulary. "Armed" means enforcement mode is
`FAIL_CLOSED` (M1 or M2 with the latch `UP`).

| # | Traffic class | Disposition | Matched by | Rule |
|---|---|---|---|---|
| 1 | **Protected peer traffic** (dst ∈ overlay prefixes) | `DROPPED_FAIL_CLOSED` | Tier 1 + Tier 2 | Always protected, in every mode |
| 2 | **Exit-node-routed Internet traffic** (full tunnel) | `DROPPED_FAIL_CLOSED` | Tier 1 complement form | Per-family; an ungranted family is dropped, never leaked (§11.4) |
| 3 | **LAN-gateway-routed traffic** (accepted `Route` prefixes) | `DROPPED_FAIL_CLOSED` | Tier 1 | `POLICY.SCOPE.ROUTE_UNGRANTED` |
| 4 | **Local physical LAN traffic** (dst ∈ an on-link prefix of a non-overlay interface) | **Permitted** by default; `DROPPED_FAIL_CLOSED` when `local_network_access = DENY` | on-link prefix of the egress interface **and** the packet is not routed off-link | Never permitted for a *routed* destination; never permitted on the forwarding path (KS-2) |
| 5 | **DHCP / DHCPv6 / ND / RA on the underlay** | **Permitted**, link-local scope only | UDP 67/68, UDP 546/547, ICMPv6 133–137, on a non-overlay interface | Permitted because blocking them breaks the underlay itself ([ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.5(5)); never an egress path for protected traffic |
| 6 | **DNS for names in the Tier-1 protected scope** — plus **all** DNS in full-tunnel mode | `DROPPED_FAIL_CLOSED` except on a `RESOLVER`-registered socket | dst port 53/853/443-DoH per [ADR-0011](ADR-0011-dns-handling.md), **scoped exactly as classes 1–3** | Policy interface required in §11.12; this ADR decides *containment*, not resolution. **The Tier-1 qualifier is load-bearing:** without it a TwinNet-only device in `BLOCKED` would lose *all* name resolution and therefore all Internet, which contradicts §11.1's statement that the cost of `BLOCKED` in that mode is only "you cannot reach your other devices". `SPLIT`-mode out-of-scope names are class 6b |
| 7 | **TwinVPN control-plane and relay/peer traffic** | **Permitted — the bootstrap exception** | §11.5 predicate | The narrowest exception in this table and the most dangerous; §11.5 is normative |
| 8 | **Loopback** | **Permitted** | `lo` / `lo0`, src and dst both loopback | Cannot egress by construction |
| 9 | **Link-local unicast** (`169.254.0.0/16`, `fe80::/10`) | **Permitted** on non-overlay physical interfaces | scope check | Not routable off-link by definition; required for ND and IPv4LL |
| 10 | **mDNS / link-local multicast** (`224.0.0.0/24`, `ff02::/16`) | Follows class 4: permitted iff `local_network_access = ALLOW` | dst multicast in link-local scope, TTL/hop-limit 1 | TwinVPN does not use mDNS for peer discovery (`docs/networking.md` §8.1); this is host OS traffic |
| 6b | **`SPLIT`-mode out-of-scope DNS** (names outside the Tier-1 protected scope, TwinNet-only or split-tunnel routing) | **Permitted** on a `RESOLVER`-registered socket to the host's configured upstream | dst port 53/853, `RESOLVER` socket, non-overlay interface | Deliberate policy-directed forwarding, not a fallback ([ADR-0011](ADR-0011-dns-handling.md) DN-10). Observable to the local network — disclosed in [docs/threat-model.md](../threat-model.md) TM-18 |
| 11 | **Captive-portal conversation** | `DROPPED_FAIL_CLOSED` unless a §11.7 grant is live | portal grant set, kernel-expiring | Never automatic |
| 13 | **Captive-portal *detection* probe** | **Permitted**, rate-limited, agent-originated only | `BOOTSTRAP`-registered socket; dst ∈ {the RFC 7710 `captive-portal` URI if the DHCP/RA option was supplied, the interface's default gateway, the interface's DHCP/RA-supplied resolvers}; attaching interface only; ≤ 4 probes per interface attach, ≤ 1/s | **Exists because detection was otherwise circular**: class 11's grant is scoped to "the portal endpoints observed by detection", so detection must be able to run *before* any grant exists. Deliberately narrower than the grant it produces: no user traffic, no arbitrary destination, no listener |
| 12 | **Platform-mandated exempt traffic** | **Permitted, and disclosed** | out of our control | Enumerated per platform in §11.6; surfaced as `POLICY.EXEMPT.PLATFORM_MANDATED` |

**Rule KS-3.** This table is exhaustive **within the protected scope defined by §11.1**. A packet
in that scope which matches no class is protected and is dropped. Ambiguity resolves closed
(`docs/architecture.md` §2.16).

> **Scope clarification (KS-3a).** "Exhaustive" read without the scope qualifier contradicts §11.1.
> Taken literally it drops every unmatched packet in *every* routing mode, but §11.1 states the cost
> of `BLOCKED` in **TwinNet-only** mode as merely "you cannot reach your other devices" — which
> requires out-of-scope Internet traffic to keep flowing. The two readings differ exactly on
> **agent-originated non-tunnel traffic**, so the qualifier is load-bearing, not editorial. The rule
> is: exhaustive **over the Tier-1 protected set**, which is mode-dependent; traffic outside that set
> is not governed by this table and is not dropped by it.

**Rule KS-4.** `local_network_access` defaults to `ALLOW` in TwinNet-only and split-tunnel modes
and to `ALLOW` in full-tunnel mode with a one-toggle `DENY` (the iOS/macOS `excludeLocalNetworks`
inverse). When `ALLOW`, the permitted set is *on-link prefixes only*, recomputed on every
network-change event, and never includes a destination reachable only via a router.

### 11.3 The four leak channels, bound to policy rules

| `docs/networking.md` §9.1 channel | Policy rule here |
|---|---|
| IPv4 egress outside the tunnel | Tier 2 (§11.1) + classes 1–3 of §11.2; exceptions limited to classes 4, 5, 7–12 |
| IPv6 egress outside the tunnel | The **same** Tier-2 object, same instant ([ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.5(1)). KS-5 below makes a v4-only rule set non-conforming rather than degraded |
| IPv6 enabled *after* the tunnel is up | Tier 2 is interface-scoped and default-deny, so a new interface or prefix is denied by the pre-existing rule with **no rule update required for correctness** (§11.1). The 1 s re-assertion is defense in depth |
| DNS | Class 6 + the required interface in §11.12(a); detection surfaces `POLICY.LEAK.DNS_UNPROTECTED` and `DNS.*` codes owned by [ADR-0011](ADR-0011-dns-handling.md) |

**Rule KS-5.** An implementation that can install the Tier-2 rule set for one family without the
other is **non-conforming**, not degraded. There is no partial-install success result.

### 11.4 IPv6 bypass and per-family grants

**Rule KS-6.** When the negotiated tunnel, the selected `ExitNode`, or the accepted `Route` set
covers only one family, the other family's protected scope MUST be **blocked**, the connection
enters `DEGRADED` (never a silent success), and `POLICY.LEAK.IPV6_UNPROTECTED` (v6 uncovered) or
`POLICY.LEAK.FAMILY_GRANT_MISSING` (a grant field absent per `docs/protocol.md` §13) is emitted
with the uncovered family named.

**Rule KS-7.** TwinVPN MUST NOT disable the host IPv6 stack, MUST NOT unbind the Windows IPv6
stack, MUST NOT remove IPv6 addresses from host interfaces, and MUST NOT disable the host
firewall or the host resolver service. This confirms `docs/networking.md` A5 and
[ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.5(3) and closes ADR-0010 §14 revisit condition 6:
no kill-switch policy in this ADR requires host-global IPv6 disabling.

**Rule KS-8.** An absent per-family grant is a **denial**, never a permission
(`docs/protocol.md` §13, A13 — confirmed).

### 11.5 The bootstrap exception (normative — the most dangerous rule in this ADR)

Class 7 of §11.2 permits TwinVPN's own control-plane, rendezvous, relay and peer-endpoint
traffic to egress while the protected scope is blocked. Without it `BLOCKED` is absorbing and
the device can never recover. It is specified by predicate, not by destination, because relay
and peer endpoints are legitimately arbitrary Internet addresses.

**Rule KS-9 — the predicate.** A packet matches the bootstrap exception if and only if **all**
of the following hold:

1. It is **locally originated** by the TwinVPN agent process, identified by an OS-mediated
   predicate: Linux/OpenWrt — `cgroup v2` path match **and** `fwmark` set via `SO_MARK` by the
   agent; Windows — WFP `FWPM_CONDITION_ALE_APP_ID` for the signed binary **and**
   `FWPM_CONDITION_ALE_USER_ID` for the service SID; macOS — `pf` anchor keyed to the tunnel
   provider's owning uid plus the provider's socket set; iOS/Android — implicit, the provider's
   own sockets are excluded from its own tunnel by construction.
2. It is emitted on a **socket registered with the enforcement layer** at bind time.
   Unregistered sockets of the same process do not match.
   **Corrected (KS-9a): the registration MUST NOT be specified as IPC.** This clause originally
   required registration "via a local, authenticated IPC registration", which is wrong in the
   selected topology and dangerous in any. Under
   [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) PS-1 the sockets and the
   enforcement layer are **in the same process** on `HC-1` and `HC-3`, so the registration is an
   intra-process call and **an intra-process call is not IPC**. Requiring one would mandate a local
   endpoint whose entire purpose is granting egress exemptions — precisely the confused-deputy
   surface KS-10 spends a page arguing away — or would silently presuppose a split topology that
   [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) §12.1 rejects on this ADR's own
   grounds. Normative form: **registered with the enforcement layer at bind time, by whatever
   mechanism the host class makes available**, with no IPC implied on `HC-1`/`HC-3`. On `HC-2` the
   OS owns the boundary and the provider's sockets are excluded by construction (clause 1). This
   also discharges the half of [docs/threat-model.md](../threat-model.md) **O-11** that cited this
   clause: the right answer is that on the selected topology the surface **does not exist**.
3. It is **not** on the forwarding path (KS-2).

**Rule KS-10 — why it cannot carry protected traffic.** The exemption is not destination-scoped,
so its safety must come from what can enter the exempt sockets. Normatively:

- The agent MUST NOT expose a proxy, a SOCKS or HTTP CONNECT listener, a port-forwarder, a
  packet-injection API, or any other interface by which another process can place bytes on a
  registered socket. Adding one is a breaking change to this ADR.
- **The socket registry has two disjoint classes, and this enumeration governs only the first.**

  | Class | Sockets | Permitted payloads | Destination scope |
  |---|---|---|---|
  | `BOOTSTRAP` | Agent control-plane, rendezvous, relay, and peer sockets; the class-13 detection probe | **Exactly three**: mutually-authenticated TLS 1.3 to the control plane / rendezvous (channel-bound per `docs/protocol.md` §C1/C2); encapsulated tunnel frames whose plaintext is already end-to-end protected ([ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)); and the rate-limited class-13 detection probe | Destination-unbounded for the first two (necessarily — see §13); tightly bounded for the third |
  | `RESOLVER` | The stub's **outbound** resolution sockets only ([ADR-0011](ADR-0011-dns-handling.md) §11.13(b)) | DNS only: UDP/TCP 53, TCP 853, and the known-DoH endpoint list | Destination-**bounded** by the active DNS scope: `bootstrap` → the control-plane/rendezvous FQDN set; `SPLIT` out-of-scope → the host's configured upstream; `portal` → the grant's resolver set |
  | **`UPDATE`** | The privileged updater's fetch socket only ([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)) | **Signed manifest and artifact bytes only.** No other payload; the socket is not a general HTTP client | **Destination-BOUNDED** to the pinned update origin(s) of `UpdatePolicy` (S-59) — modelled on class 13, **not** on destination-unbounded `BOOTSTRAP` |

  > **Why the `UPDATE` class exists (KS-10a) — it closes a deadlock, not a convenience.**
  > [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-31(4)(b) names **"a
  > successful self-update"** as the recovery path from a version-incompatibility block. But the
  > update origin is **not** the control plane, so an update fetch was not among the three permitted
  > `BOOTSTRAP` payloads — and under full-tunnel `FAIL_CLOSED` it was dropped. **N-31's own recovery
  > path was unreachable by construction**: a device blocked for being too old could never fetch the
  > version that would unblock it.
  >
  > It is modelled on **class 13** (the captive-portal detection probe) rather than on `BOOTSTRAP`,
  > and the precedent is exact: class 13 exists because portal detection was otherwise circular, and
  > this is the same circularity. Both are **destination-bounded**, rate-limited, agent-originated,
  > and carry one payload shape. The bound is what keeps this from widening the bootstrap exception:
  > the destination set is the pinned origin in S-59, which a compromised control plane cannot
  > rewrite (the RTA pin is build-time, [ADR-0021](ADR-0021-packaging-distribution-and-updates.md)
  > §11.15(d)). Verification is unchanged — bytes arriving on this socket are still subject to the
  > full signature, digest and monotonic-manifest chain before anything is executed.

  None of these is a channel for host application traffic. **`RESOLVER` is not covered by the
  "nothing else can get bytes onto these sockets" argument below**, because the stub is by
  construction a listener that accepts queries from other processes. Its safety rests instead on
  three properties owned by [ADR-0011](ADR-0011-dns-handling.md): the stub parses only DNS and is
  minimal by requirement (DN-4); it emits only DNS, to a destination set bounded per scope; and it
  never forwards a name in the Tier-1 protected scope to the underlay. A `RESOLVER` socket MUST NOT
  be usable for any non-DNS payload, and an implementation that multiplexes one is non-conforming.
- Satisfying predicate (1) requires the privilege that also permits rewriting the rule set. An
  adversary who can forge process identity has already defeated the kill switch by a shorter
  path, so the exemption grants no additional capability. This is the argument; destination
  scoping is not, and must not be claimed as one.

**Rule KS-11 — accounting.** The enforcement layer MUST export byte and packet counters for the
exempt rule, per family. The agent MUST compare exempt egress against its own tunnel and
control-plane frame accounting; a divergence beyond a declared tolerance raises
`POLICY.EXEMPT.EGRESS_ANOMALY` at `CRITICAL` and drives `EV_POLICY_VIOLATION` → `BLOCKED`. The
exemption is thus not merely narrow but *audited*.

**Rule KS-12 — the exception does not widen on failure.** If socket registration fails, the
socket is not exempt and its traffic is dropped. There is no "register everything on error" path.

### 11.6 Durability and the enforcement point per platform

**Enforcement point (E1), both families in every row.**

| Platform | Enforcement object (v4 **and** v6 in one object) | Boot-time pre-network enforcement |
|---|---|---|
| Linux | nftables `table inet twinvpn` (the `inet` family matches both) | `twinvpn-killswitch.service`, `Before=network-pre.target`, `Wants=network-pre.target`, restoring `/etc/twinvpn/killswitch.nft` |
| Windows | One owned WFP sublayer containing `FWPM_LAYER_ALE_AUTH_CONNECT_V4` **and** `_V6` filters, installed in one transaction | `FWPM_FILTER_FLAG_BOOTTIME` coarse deny **plus** `FWPM_FILTER_FLAG_PERSISTENT` full policy reinstated by BFE |
| macOS | `pf` anchor `twinvpn` (both families) + `NEPacketTunnelNetworkSettings` carrying `IPv4Settings` and `IPv6Settings` | `LaunchDaemon` `RunAtLoad` + `/etc/pf.conf` anchor reference |
| iOS | `NEPacketTunnelProvider` with `includeAllNetworks = true` (+ `excludeLocalNetworks` for class 4), on-demand rules with `disconnectOnDemandEnabled = false` | **None available** — see the limitation table |
| Android | `VpnService.Builder` claiming `0.0.0.0/0` **and** `::/0`, plus OS always-on with "Block connections without VPN" (lockdown) | OS lockdown, enforced by the platform from boot |
| OpenWrt | `fw4`/nftables `inet` table via a UCI include | init script ordered before `network`, and the include is part of persisted config |

**Rule KS-13.** E2 (routing blackhole/unreachable routes) MAY be installed as defense in depth
but MUST NOT be counted toward K1. E4 (userspace-only) is **rejected**: it dies with the process
and fails K3 categorically.

**Durability across the six required events.** ✔ = guaranteed by the named mechanism;
◐ = partial, see the limitation table; ✘ = not guaranteed.

| Platform | Agent crash | `SIGKILL` | Uninstall / update | OS reboot | Safe mode / Recovery | User logout |
|---|---|---|---|---|---|---|
| Linux | ✔ kernel-resident nftables | ✔ | ✔ atomic ruleset swap; uninstall removes only the owner-tagged table | ✔ systemd unit before network | ◐ single-user does not reach the unit | ✔ system scope |
| Windows | ✔ WFP filters are kernel objects | ✔ | ✔ persistent filters survive service stop; installer swaps atomically | ✔ BOOTTIME + PERSISTENT | ◐ Safe Mode without Networking has no network; Safe Mode **with** Networking starts BFE, so persistent filters apply | ✔ service/system scope |
| macOS | ✔ `pf` rules are kernel-resident | ✔ | ✔ LaunchDaemon reinstates | ✔ LaunchDaemon `RunAtLoad` | ✘ Recovery/safe boot does not load the daemon | ✔ daemon, not agent |
| iOS | ◐ system restarts the provider on-demand | ◐ | ✘ profile removal removes enforcement | ◐ on-demand re-arms at network attach | ✘ n/a | ✔ |
| Android | ✔ lockdown is OS-enforced | ✔ | ◐ uninstall clears the always-on target | ✔ lockdown persists | ✘ safe mode disables third-party VPN | ◐ per-user profile scope |
| OpenWrt | ✔ | ✔ | **◐** our own upgrade path reloads only our table and never calls `fw4 reload`; but an **operator-triggered `fw4 reload`** (e.g. from LuCI) rebuilds the whole firewall and opens a sub-second window we do not control | ✔ persisted config | ◐ failsafe mode bypasses config | n/a |

**Honest platform-limitation table (K10).**

| Platform | What cannot be guaranteed | Residual exposure | Mitigation and disclosure |
|---|---|---|---|
| iOS | No host firewall exists. Enforcement is the system's, via `includeAllNetworks`; some Apple system services are documented as not tunneled | System-service traffic; the interval between network attachment and provider start on an unsupervised device; total loss if the user deletes the VPN profile | Report posture continuously; `POLICY.EXEMPT.PLATFORM_MANDATED` enumerates what the OS exempts; recommend supervised Always-On VPN for managed fleets; P09 **measures** the attach-to-arm window rather than assuming it is zero |
| Android | Lockdown cannot be enabled programmatically by a non-DPC app; some connectivity-check and system traffic is exempt in lockdown | Everything, until the user enables lockdown | Detect and report lockdown posture (`docs/networking.md` §5.4 — confirmed); surface it as an unmissable, persistent state, not a settings hint; DPC-managed enablement for enterprise |
| macOS | Recovery and safe boot do not load the LaunchDaemon | A device booted to Recovery is unprotected | Disclosed; Recovery has no user session running ordinary applications |
| Linux | Single-user/emergency targets do not reach the unit | Unprotected in single-user mode | Disclosed; single-user brings up no network by default |
| Windows | BOOTTIME filters cannot use ALE app-id conditions, so the bootstrap exception is unavailable during the boot window | The agent cannot connect until BFE and the service start — a *availability* gap, not a leak | Deliberate: the boot window fails **closed**, which is the correct direction |
| All | An `Owner` with local admin can always remove enforcement | By design (K5) | Logged as `POLICY.KILLSWITCH.DISARMED_BY_OWNER` |

### 11.7 Captive portals

A fail-closed VPN on an unauthenticated hotel, airport, or campus Wi-Fi cannot reach the portal
that would authenticate it. This is a genuine usability/security tradeoff and **C3** is selected.
`docs/networking.md` §3.7 already supplies the mechanism — a scoped exemption for the portal's
address and DNS for ≤ 300 s — and explicitly defers the policy here; this section is that policy.

**Rule KS-14 — no automatic exemption.** `portal_policy` takes exactly two values, `PROMPT`
(default) and `NEVER`. There is deliberately **no** `ALWAYS`. Detection of `NET.CAPTIVE_PORTAL`
MUST NOT open any hole by itself; the network controls the detector's inputs, so an automatic
exemption would be an attacker-triggerable egress permit (C2, rejected).

**Rule KS-15 — the grant.** A local user action grants a `PortalExemptionGrant` (S-35) that:

| Property | Value |
|---|---|
| Lifetime | ≤ 300 s, enforced **in the kernel** (nftables set-element `timeout`; WFP filter with a scheduled removal plus an independent watchdog; `pf` table entry with an expiry sweep), so agent death cannot leave it open |
| Destination set | The portal endpoints observed by detection, plus the DHCP/RA-supplied resolver(s) of the attaching interface — nothing else |
| Ports | TCP 80/443 to the portal endpoints; UDP/TCP 53 and TCP 853 to the supplied resolver(s) |
| Interface | The single attaching underlay interface only; never the overlay, never a second interface |
| Scope | The protected scope of §11.1 **remains blocked throughout**. The exemption covers the portal conversation, never protected traffic |
| Renewal | One grant per network fingerprint per attachment; a second grant requires a second user action |
| Durability | **Non-durable by requirement** (S-35): it does not survive process restart or reboot |

**Rule KS-16 — DNS containment across the grant.** Answers obtained during a grant are
`portal-scope` and MUST NOT enter the protected resolution path or its cache. This is a required
interface on [ADR-0011](ADR-0011-dns-handling.md) (§11.12(a)) — a portal-supplied answer that
persisted into protected resolution would convert a 300 s hole into a durable redirection.

The user-visible state throughout is `BLOCKED` with `POLICY.KILLSWITCH.ENGAGED` plus
`POLICY.PORTAL.EXEMPTION_ACTIVE` carrying the remaining seconds and the reachable set, followed
by `POLICY.PORTAL.EXEMPTION_EXPIRED`. On iOS the case is handled entirely by the system's Captive
Network Assistant outside our control, and is disclosed as such rather than claimed.

### 11.8 Ordering, the transition window, and the boot race

**Rule KS-17 — two rule sets, never zero.** There are exactly two fail-closed rule sets:
`RULESET_BLOCKED` (no protected egress on any interface) and `RULESET_PROTECTED` (protected
egress permitted **only** via the overlay interface). Both are fail-closed. Transitions between
them are a single atomic swap. `leave_blocked()` in `docs/networking.md` §5.1 means *swap to
`RULESET_PROTECTED`*, never *remove rules*. This is a clarification of §9.3's semantics, not a
contradiction of it; §9.3's diagram remains exactly correct with this reading.

```
arm:      RULESET_BLOCKED live ─► create iface (DOWN) ─► apply(contract_gen)
                                       ─► link up ─► path validated + assertion OK
                                       ─► atomic swap ─► RULESET_PROTECTED

teardown: link down ─► atomic swap ─► RULESET_BLOCKED ─► destroy iface
                                       (rules stay live while the latch is UP)

boot:     OS applies boot ruleset ─► network stack comes up ─► agent starts
          (the deny predates the first packet the host can emit)
```

**Rule KS-18 — teardown ordering.** `RULESET_PROTECTED` may be entered only after **both**
(a) an authenticated bidirectional path validation (`EV_PATH_VALIDATED`,
`docs/reliability.md` §4.3), and (b) a `ProtectionAssertion`
([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.6(1)) confirming the intended rule set
is installed **for both families**. Either check failing keeps `RULESET_BLOCKED`.

**Rule KS-19 — the boot race.** The rule set that covers the interval between the network stack
coming up and the agent starting MUST be installed by an artifact the **OS itself applies**
(§11.6 column 3), never by the agent. This is where real products leak. Where a platform cannot
do this (iOS), `POLICY.KILLSWITCH.BOOT_ENFORCEMENT_UNAVAILABLE` is emitted at first run, the
residual window is named, and P09 measures it.

**Rule KS-20 — reclamation.** All rule state is owner-tagged and reclaimable by a fresh process
after an unclean exit (`docs/networking.md` §5.5.3 — consumed). A crash must leave the host
blocked, never open; and a privileged local unblock command MUST exist so that "blocked" is not
"bricked" (§10).

### 11.9 `BLOCKED` interaction, detection, and reason codes

Guards contributed to `docs/reliability.md` (states and transitions unchanged):

- **T26 guard** (`RECONNECTING --T_RECONNECT_GRACE--> BLOCKED`): enforcement mode is
  `FAIL_CLOSED` **and** the peer is in the Tier-1 protected scope.
- **T29 guard** (`* --EV_POLICY_VIOLATION--> BLOCKED`): raised by the enforcement reconciler or
  the leak canary on assertion mismatch, ruleset tamper, or observed protected egress.
- **T30 guard** (`BLOCKED --EV_SECURE_PATH_RESTORED-->` steady): KS-18's two conditions both hold.
- **T32 guard** (`BLOCKED --EV_DISCONNECT_REQUESTED--> DISCONNECTED`): the §11.10 local-authority
  action succeeded. This is the *only* guard that permits leaving fail-closed without a path.

**Leak canary (active detection, K12).** Per family, at each existing network-change and
keepalive wake point, the agent emits a uniquely marked datagram from a **non-exempt** socket to
a destination in the protected scope and asserts that the enforcement layer's deny counter for
that family incremented. A canary that does not increment is `POLICY.LEAK.EGRESS_OBSERVED` at
`CRITICAL`. This satisfies testing-strategy V4: absence of a leak is only evidence because the
same rig demonstrably observes the leak in the unprotected control run.

**Reason codes contributed to the `POLICY` namespace** ([ADR-0015](ADR-0015-observability-and-diagnostics.md)
§11.2 owns the taxonomy; this ADR owns the `POLICY` codes). All are registered with the full
attribute set of §11.2; the table gives the discriminating attributes.

| `reason_code` | class | severity | terminal | user_actionable | Condition / next action |
|---|---|---|---|---|---|
| `POLICY.KILLSWITCH.ENGAGED` | POLICY | ERROR | false | true | Protected traffic is blocked because no authorized secure path exists. Next: wait for reconnection, or disconnect deliberately |
| `POLICY.KILLSWITCH.TRAFFIC_RESTORED` | POLICY | INFO | false | false | An authorized secure path was restored and protected traffic resumed; carries the blocked duration. Emitted on the `BLOCKED` **exit** transition (`docs/reliability.md` T30) |
| `POLICY.KILLSWITCH.UNPROTECTED_FALLBACK` | POLICY | WARN | false | true | The `Owner` has enforcement disabled and traffic is flowing **untunneled**. Persistent while it holds — this is the announced-not-silent form of the one case where protected traffic may leave unprotected (`docs/reliability.md` T27) |
| `POLICY.KILLSWITCH.ARM_FAILED` | PERSISTENT | CRITICAL | false | true | The rule set could not be installed; the client refuses to enter a protected state. Next: named suspected conflicting product |
| `POLICY.KILLSWITCH.ASSERTION_MISMATCH` | POLICY | CRITICAL | false | false | Installed rules differ from intended policy (O-17). Next: automatic re-assertion |
| `POLICY.KILLSWITCH.RULESET_TAMPERED` | POLICY | CRITICAL | false | true | The owner-tagged rule set was modified or removed by another component. Next: name the component if determinable |
| `POLICY.KILLSWITCH.BOOT_ENFORCEMENT_UNAVAILABLE` | PERSISTENT | WARN | false | false | No pre-network boot ruleset is possible on this platform; the boot window is named |
| `POLICY.KILLSWITCH.DISARMED_BY_OWNER` | POLICY | WARN | false | false | Enforcement was deliberately disengaged locally; persistent unprotected indication |
| `POLICY.KILLSWITCH.DISARM_REFUSED_REMOTE` | POLICY | CRITICAL | false | false | A disarm was attempted by a non-local authority and refused. Always a security event |
| `POLICY.LEAK.IPV6_UNPROTECTED` | POLICY | WARN | false | true | The tunnel or exit grant is v4-only; IPv6 destinations are blocked and why |
| `POLICY.LEAK.FAMILY_GRANT_MISSING` | POLICY | WARN | false | true | A per-family default-route grant is absent; that family is blocked, not leaked |
| `POLICY.LEAK.EGRESS_OBSERVED` | POLICY | CRITICAL | false | false | The canary observed protected traffic on a non-overlay interface. Drives `BLOCKED` |
| `POLICY.LEAK.DNS_UNPROTECTED` | POLICY | ERROR | false | false | The DNS policy interface of §11.12(a) is unsatisfied; detail codes are `DNS.*` |
| `POLICY.SCOPE.ROUTE_UNGRANTED` | POLICY | ERROR | false | true | Traffic to an accepted `Route` prefix with no live authorized path |
| `POLICY.EXEMPT.LOCAL_NETWORK_ALLOWED` | POLICY | INFO | false | true | Local network access is permitted; states exactly which on-link prefixes |
| `POLICY.EXEMPT.PLATFORM_MANDATED` | POLICY | WARN | false | false | Traffic the platform exempts and we cannot block; enumerated |
| `POLICY.EXEMPT.EGRESS_ANOMALY` | POLICY | CRITICAL | false | false | Bootstrap-exemption volume diverges from tunnel accounting (KS-11) |
| `POLICY.PORTAL.EXEMPTION_ACTIVE` | POLICY | WARN | false | true | A time-boxed portal exemption is live; remaining seconds and reachable set |
| `POLICY.PORTAL.EXEMPTION_EXPIRED` | POLICY | INFO | false | false | The exemption closed; full enforcement resumed |
| `POLICY.COEXIST.SECOND_VPN_DEFAULT_ROUTE` | PERSISTENT | WARN | false | true | Another always-on VPN claims the default route; names it and the metric relationship |
| `POLICY.COEXIST.FILTER_CONFLICT` | PERSISTENT | ERROR | false | true | A third-party network filter conflicts with our sublayer; names it if determinable |

**Testability of the mandatory proof tests (`docs/testing-strategy.md` §4).** This design is
constructed so that P07, P08, and P09 are testable exactly as specified there, each with the
mutant that V2 requires and the positive control that V4 requires.

| Test | What this ADR makes observable | Required mutant (V2) |
|---|---|---|
| **P07** — IPv6 cannot bypass tunnel policy | Tier 2 is one dual-family object (KS-5); the canary asserts the v6 deny counter increments; the rig can add an interface, receive an RA, start tethering, and attach a VM bridge mid-session and observe no rule update was needed (§11.3 row 3) | A build whose Tier-2 object omits the v6 filter, and a build whose Tier 1 is prefix-enumerated rather than complement-form in full-tunnel mode |
| **P08** — DNS cannot bypass tunnel policy | Class 6 containment plus the §11.12(a) interface; `POLICY.LEAK.DNS_UNPROTECTED` and the `DNS.*` codes are the oracle; the portal-window cache separation of KS-16 is separately assertable | A build that permits egress to the DHCP-supplied resolver while armed, and a build that caches portal-window answers into protected resolution |
| **P09** — kill switch fails closed across crash/kill/reboot | The six durability events of §11.6 are each a named mechanism per platform; the boot ruleset is an OS-applied artifact (KS-19); `ruleset_digest` (§11.13) lets the test assert the *same* rule set is present after the event; the iOS attach-to-arm window is measured rather than assumed | A build whose enforcement is process-resident (E4), a build that installs the boot ruleset from the agent rather than from the OS artifact, and a build whose update path removes-then-adds instead of swapping atomically (KS-23) |

The positive control for all three is the same rig with `mode = OFF`, which MUST observe the
leak the protected run must not.

### 11.10 Local authority: who may disarm

**Rule KS-21.** Disarming (M2 latch → `DOWN`, or mode → `OFF`) requires **all** of:

1. A **local interactive action** on the device itself. No network path, no remote management
   channel, and no control-plane document may initiate it.
   **Host-class rule (KS-21a) — what "interactive" means where there is no console.** On `HC-3`
   (headless servers, containers, routers) there is no interactive session, so read literally this
   clause makes disarm impossible — which contradicts **KS-20**'s "blocked must not mean bricked"
   and would leave a misconfigured unattended device permanently unreachable. **A caller on the
   local management socket, authenticated by kernel-supplied peer credentials to an administrator
   principal, satisfies this clause on `HC-3`.** The rule KS-22 protects is *"no remote actor,
   including a compromised control plane"* — and a control plane **cannot produce an authenticated
   local shell**, which is the property that makes this admissible rather than convenient.
   Bounded by three hard limits: it applies **only** where no interactive session exists
   ([ADR-0016](ADR-0016-client-process-and-privilege-separation.md) PS-14 decides this by host
   class, not by preference); the action MUST fail at **request** rather than at commit, so operators
   are never trained to click through prompts for acts that were never going to be permitted
   ([ADR-0017](ADR-0017-local-management-interface.md) MI-17); and **disarm MUST NOT be reachable
   over `ubus`** — `rpcd`/`uhttpd` bridge `ubus` to HTTP, so an `ubus` method behind `rpcd` is an
   HTTP method wearing a local transport's clothes
   ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) EM-40). The residual is stated rather
   than hidden: on `HC-3` the disarm boundary is **whoever holds an authenticated administrator
   shell on that host**, which is the same boundary that already controls the enforcement rule set.
2. **OS-mediated authentication of an `Owner`/administrator principal**: `polkit` on Linux, UAC
   elevation with Administrators membership on Windows, Authorization Services
   `system.privilege.admin` on macOS, the Settings always-on toggle on Android, VPN-profile
   removal on iOS.
3. A **confirmation that names the consequence** ("traffic will leave this device untunneled"),
   and emission of `POLICY.KILLSWITCH.DISARMED_BY_OWNER`, with a persistent
   `PERMISSIVE_ANNOUNCED` indication thereafter (`docs/reliability.md` §4.1).

**Rule KS-22 — no remote actor, including a compromised control plane.** Three independent
structural properties, not three checks:

- **S-18 has one writer and no remote replica.** The control plane has no authoritative copy to
  write back.
- **There is no wire message that means "disarm."** Required of
  [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) in §11.12(d): no message type in
  the control-plane schema may reduce enforcement. An absent message type cannot be forged.
- **Enforcement is monotone in the safe direction.** Effective mode is
  `max(local_mode, policy_required_mode)` over the total order `OFF < ARMED_ON_INTENT <
  ALWAYS_ON`. A remote policy can only raise it. A compromised control plane can therefore cause
  a visible denial of service and cannot cause an invisible leak.

**Rule KS-23 — the update channel is not an exception.** An update MUST replace the rule set by
atomic swap, never remove-then-add, and MUST NOT clear the latch. The management plane must not
be able to disable protection without `Owner` action (`docs/architecture.md` §4.1 — confirmed).

### 11.11 Coexistence

Consuming `docs/networking.md` §5.5 rather than restating it:

| Situation | Policy |
|---|---|
| Host firewall present | Never disabled (§5.5.2). We install into our **own** table/sublayer/anchor so a "reset firewall" action does not remove us and we do not remove them |
| Third-party VPN also claiming the default route | Supported but **not silently**: `NET.CONCURRENT_VPN` from networking plus `POLICY.COEXIST.SECOND_VPN_DEFAULT_ROUTE`. We do **not** force interface metrics to win. Tier 2 still holds: protected traffic may egress only via *our* overlay interface, so the other VPN's interface is a denied interface like any other — the outcome is that protected traffic is blocked, which is correct and visible, not silently tunneled through a stranger's VPN |
| Corporate agent / endpoint-security network filter | `POLICY.COEXIST.FILTER_CONFLICT`, naming the product where determinable (R-18, `PLATFORM.THIRD_PARTY_FILTER_SUSPECTED`). If our filter cannot be installed at all, `POLICY.KILLSWITCH.ARM_FAILED` and we refuse to enter a protected state |
| Other virtual adapters (VM bridges, containers, tethering) | Denied by Tier 2 without a rule update, because they are not the overlay interface (§11.3 row 3) |
| Two **always-on** VPNs | Only one can hold the platform always-on slot on iOS/Android; on Linux/Windows/macOS both rule sets apply and the intersection is enforced. The honest outcome is that the strictest wins and something is blocked. We surface which, and never resolve it by clobbering the other product's rules (§5.5.1) |

### 11.12 Interfaces required from other ADRs

| # | Required interface | Owner |
|---|---|---|
| (a) | **DNS policy interface.** While enforcement is armed: no unencrypted fallback to any pre-existing resolver, both families, including resolver processes outside the tunnel's routing scope; port-53/853/DoH containment such that only the local stub may originate resolution; `BLOCKED`-state responses that are typed failures (SERVFAIL + Extended DNS Error) rather than a fallback; and **answers obtained during a §11.7 portal exemption MUST NOT enter the protected resolution path or cache**. This ADR decides containment policy only; resolution mechanism is not ours | [ADR-0011](ADR-0011-dns-handling.md) |
| (b) | The single-object dual-family fail-closed rule set, interface-scoped, default-deny, with the ordering guarantee and owner-tagged reclamation | [ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.5, `docs/networking.md` §9 |
| (c) | Explicit per-family grant fields on `ExitNodeEngaged` / LAN grants, where an absent field is a denial | `docs/protocol.md` §13, [ADR-0003](ADR-0003-network-contract-schema-format.md) |
| (d) | **No control-plane message type may reduce enforcement**, and none may carry a disarm instruction | [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) |
| (e) | `ProtectionAssertion` derived by querying the installed rule set for both families, with a bounded freshness window that degrades to `UNKNOWN` | [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.6, O-17/O-18 |
| (f) | Forwarded gateway traffic is distinguishable from locally originated traffic at the enforcement layer, so KS-2 is expressible | [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) |
| (g) | A `Capability` expressing platform enforcement posture (e.g. `killswitch_os_enforced`, `killswitch_boot_enforced`) so a mixed fleet degrades explicitly | [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) |
| (h) | The `Owner`/administrator principal that OS-mediated authentication in KS-21(2) authenticates against | [ADR-0007](ADR-0007-device-identity-and-pairing.md) |
| (i) | Relay and rendezvous endpoints reachable from a cached signed set with no control-plane call, so the bootstrap exception need not reach the control plane to recover | [ADR-0005](ADR-0005-relay-architecture.md), [ADR-0006](ADR-0006-relay-discovery-and-failover.md) |

### 11.13 State ownership

**S-18 is extended, not duplicated.** Authoritative writer remains the local `Device` (2.16),
class `LOCAL`, durable, OS-level. Its value becomes a structured `EnforcementRecord`:

```
EnforcementRecord {
  mode:              ALWAYS_ON | ARMED_ON_INTENT | OFF
  session_intent:    UP | DOWN                    # the M2 latch
  local_network:     ALLOW | DENY
  portal_policy:     PROMPT | NEVER               # there is deliberately no ALWAYS
  scope_generation:  contract_seq                 # Tier-1 scope binding
  ruleset_digest:    hash of the installed rule set, for O-17 assertion
  armed_at:          timestamp
}
```

**One new row is required in `docs/architecture.md` §5:**

| # | State | Authoritative writer | Replicas | Class | Durability | On conflict |
|---|---|---|---|---|---|---|
| **S-35** | `PortalExemptionGrant` (the §11.7 grant) | **Local `Device` (2.16)** | None | `LOCAL` | **Non-durable by requirement** — MUST NOT survive process restart or reboot; expiry is enforced in the kernel | Local wins; absence is the safe state |

Non-durability is the security property: a grant that survived a restart would be a permanent
hole opened by a transient user click.

### 11.14 Obligations placed on this ADR by other documents

Every row is explicitly confirmed or overruled. Silence would be a Phase 1 defect.

| ID | Assumption as written | Verdict | Where discharged |
|---|---|---|---|
| `docs/architecture.md` **A-03** | Revocation is enforced at the **data-plane handshake**, with control-plane and relay denial as defense in depth | **Confirmed.** The kill switch takes no part in revocation enforcement and MUST NOT be used as a revocation mechanism — it has no notion of peer identity. Its only interaction: when revocation tears down the last `Session` in the protected scope, enforcement **stays armed** (the M2 latch is not cleared by a peer-side event), so a revoked-peer teardown can never open a hole | §11.13 (`session_intent` is cleared only by KS-21) |
| `docs/architecture.md` **A-17** | The kill switch is installed at OS level, is locally authoritative, survives process death and reboot, and does not require control-plane reachability to stay engaged | **Confirmed** in full, with the per-platform residual exposures of §11.6 stated rather than hidden | K3, §11.6, KS-22 |
| `docs/protocol.md` **A13** | Per-family default-route grants are enforceable by the kill switch, so an ungranted family can be blocked rather than leaked | **Confirmed.** An absent grant field is a denial; the ungranted family's protected scope is blocked and the connection enters `DEGRADED` with the family named | KS-6, KS-8 |
| `docs/networking.md` **A5** | The kill switch's enforcement point is the mechanism in §9, **and** ADR-0012 does not require TwinVPN to disable the host IPv6 stack or the host firewall | **Confirmed, both halves, explicitly.** §9 (with [ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.5) is the sole enforcement mechanism — E1 selects exactly it, and E2/E4 are rejected. No policy in this ADR disables the host IPv6 stack, the host firewall, or the host resolver service; IPv6 is blocked at the policy layer only. This also closes [ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §14 revisit condition 6 in ADR-0010's favour | KS-7, KS-13, §11.6 |
| `docs/testing-strategy.md` **A-08** | The kill switch is enforced by an OS-level rule set installed independently of the agent process, covering IPv4 and IPv6, and surviving agent crash, agent kill, update, and reboot | **Confirmed for Linux, Windows, macOS (running system), Android (lockdown enabled) and OpenWrt; qualified for iOS and for Android without lockdown**, where §11.6's limitation table states the residual exposure. P09 must therefore assert the guarantee where it is claimed and *measure* the window where it is not, rather than testing a happy path | §11.6, §11.9 proof-test table |
| `docs/reliability.md` §4.1 | Enforcement mode is `FAIL_CLOSED` / `PERMISSIVE_ANNOUNCED`; `BLOCKED` disposition is `DROPPED_FAIL_CLOSED` always | **Confirmed and consumed unchanged.** This ADR adds guards and reason codes only — no new state, no new transition, no new disposition value | §11.9 |

**Refinements this ADR requires elsewhere** (not contradictions):

1. `docs/architecture.md` §5 needs **row S-35** added (§11.13), and S-18's description widened to
   name the `EnforcementRecord` fields rather than a bare boolean.
2. `docs/networking.md` §5.1/§9.3: `leave_blocked()` is read as *atomic swap to
   `RULESET_PROTECTED`*, never *remove rules* (KS-17). §9.3's diagram is correct under this
   reading; the clarification is about the adapter contract's semantics, not its ordering.

## 12. Why the Selected Option Won

1. **E4 is disqualified by a single sentence.** A userspace-only kill switch dies with the
   process, so it fails K3, A-08, and every `SIGKILL`/crash/reboot column of §11.6. E2 is
   disqualified by `docs/networking.md` §7.2(3): a more specific route, a bound source address,
   or a raw socket defeats routing and not the filter. E3 is E1 with a comfortable illusion
   attached. Only **E1** can be the control.
2. **M3 is the shape ADR-0010 §11.5(2) already rejected**, and rejected for the right reason: a
   destination-prefix rule set must race a network event to stay correct, and it is
   family-separable. Tier 2 being interface-scoped is what makes "IPv6 appears after the tunnel
   is up" a non-event. M3's legitimate use case — split tunnel — is served by *scope* (Tier 1),
   not by *mechanism* (Tier 2), and separating those two tiers is what lets the product be both
   split-tunnel-capable and structurally leak-proof.
3. **M2 over M1 is the one genuinely close call, and it turns on second-order effects.** M1 is
   strictly safer in the abstract. In practice M1 black-holes a fresh install at boot before any
   consent, creates a bootstrap deadlock on a device with no cached relay set, and makes every
   captive portal a hard stop — and the observable consequence of all three is that users turn
   the kill switch off entirely, which converts partial protection into none. M2 is fail-closed
   in every state where the user believes they are protected, which is the actual content of I3,
   and its latch is durable and OS-level so it survives all six events of §11.6. M1 remains one
   toggle away and is the recommended setting for full-tunnel use.
4. **M4 is the defect (R-13)**, so it can be an announced opt-out and never a default. It is kept
   because a user whose threat model is "reach my NAS" is not served by a device that stops
   working, and `PERMISSIVE_ANNOUNCED` already exists in `docs/reliability.md` §4.1 with a
   persistent unprotected indication.
5. **The bootstrap exception is specified by predicate and defended by structure.** Products that
   specify it as "our process is allowed" have an unbounded egress permit guarded by a process
   name. KS-9 adds registered-socket scoping and forwarding exclusion; KS-10 supplies the actual
   argument (nothing else can get bytes onto those sockets, and forging the identity requires the
   privilege that already defeats the switch); KS-11 makes it audited rather than merely narrow.
   This is the difference between a hole and an interface.
6. **C3 over C1 and C2.** C2 is an attacker-triggerable egress permit, since the network controls
   the detector's inputs — it is not admissible at any usability price. C1 is safer than C3 but
   produces a worse real outcome: users disarm entirely to reach the portal, opening a much
   larger hole for much longer. C3 keeps the protected scope blocked throughout, bounds the hole
   at 300 s in the kernel so agent death cannot leave it open, and requires a human action, and
   C1 remains available as `portal_policy = NEVER`.
7. **The honest platform table is a feature.** iOS cannot deliver boot-window enforcement and
   Android cannot self-enable lockdown. Stating that, measuring it in P09, and surfacing posture
   continuously is worth more than a uniform claim that is false on two platforms — and it is
   what makes A-08's premise checkable rather than assumed.

## 13. Known Tradeoffs

| Tradeoff | Accepted because |
|---|---|
| M2 leaves traffic unprotected while the user has deliberately disconnected | That is the definition of a deliberate local disconnect; M1 is one toggle away and is recommended for full-tunnel use |
| The bootstrap exception is destination-unbounded | Relay and peer endpoints are legitimately arbitrary; safety comes from KS-9/KS-10/KS-11, and a destination allow-list would be both ineffective and falsely reassuring |
| A crash can leave a host blocked with no UI | Blocked is the correct failure direction; a privileged local unblock command (§10) keeps "blocked" from becoming "bricked" |
| `BLOCKED` in full-tunnel mode means no Internet at all | This is I3 stated plainly. The mitigation is visibility (a named reason and next action), not silent egress |
| iOS and Android cannot guarantee boot-window enforcement | Stated, surfaced as `POLICY.KILLSWITCH.BOOT_ENFORCEMENT_UNAVAILABLE`, and measured by P09 rather than assumed away |
| Local-network access defaults to `ALLOW` | Breaking the user's own printer and NAS by default is the wrong default (the same reasoning as `docs/networking.md` §7.4 P2); it is on-link-only, recomputed per network change, and one toggle from `DENY` |
| The portal exemption is attacker-*promptable* | Bounded to ≤ 300 s in the kernel, scoped to the detected portal endpoints and the DHCP-supplied resolver, never automatic, never covering protected traffic, and never cached into protected resolution |
| Two always-on VPNs produce blocking rather than a merged policy | The alternative is clobbering another product's rules, which `docs/networking.md` §5.5.1 forbids and which would make us the leak in someone else's threat model |
| The `POLICY` code set is large (19 codes) | Every one names a distinct condition with a distinct next action; collapsing them would reintroduce the cryptic-error defect (R-22) |

## 14. Revisit Conditions

1. **If measured time-in-`BLOCKED` attributable to `POLICY.KILLSWITCH.ENGAGED` exceeds 1% of
   armed session-time across the fleet**, the availability cost of fail-closed has become a
   product problem rather than a safety property; revisit the `RECONNECTING` grace period with
   `docs/reliability.md` before weakening enforcement.
2. **If the fraction of users who move from `ARMED_ON_INTENT` to `OFF` exceeds 5%**, the default
   is not surviving contact with reality; the correct response is to find which class of §11.2
   is causing it (most likely class 4 or 11) and fix that class, not to weaken the default.
3. **If `POLICY.KILLSWITCH.ARM_FAILED` exceeds 0.5% of bring-ups on any platform**, the
   coexistence strategy of §11.11 for that platform is failing and the enforcement object for it
   must be re-derived.
4. **If any platform ships a mechanism that lets an unprivileged process bind a source address,
   open a raw socket, or otherwise emit packets that escape interface-scoped filtering**, Tier 2's
   guarantee is void on that platform; this is the same single assumption
   [ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §14(5) rests on, and both must be re-derived together.
5. **If P09 measures an iOS attach-to-arm window exceeding 500 ms at p95**, `includeAllNetworks`
   is not delivering what the limitation table assumes and iOS must either be reclassified as
   best-effort in the supported matrix or restricted to supervised Always-On deployments.
6. **If portal-exemption grants exceed 3 per user-month at p50, or mean grant duration exceeds
   120 s**, C3 is being used as a general-purpose disarm and must be narrowed (per-network
   one-shot, or `NEVER` by default on full-tunnel).
7. **If `POLICY.EXEMPT.EGRESS_ANOMALY` fires anywhere outside a deliberate test**, the bootstrap
   exception's KS-10 argument has a counterexample; treat as a security incident and re-derive
   §11.5 before shipping again.
8. **If a platform introduces an API by which a remote management channel can clear the
   enforcement latch without local authentication**, KS-22 is broken on that platform and the
   platform must be reclassified or the feature blocked, with the change reflected in
   `docs/architecture.md` S-18.
9. **If `POLICY.COEXIST.SECOND_VPN_DEFAULT_ROUTE` exceeds 3% of sessions**, concurrent-VPN
   operation is a mainstream case rather than an edge case, and §11.11's "strictest wins, and we
   say so" policy needs a real interoperability design instead of a diagnostic.
