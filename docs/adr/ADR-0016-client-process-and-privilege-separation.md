# ADR-0016: Client Process, Privilege Separation, and Host Integration Model

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** APPLICATION
- **Related:** [ADR-0007](ADR-0007-device-identity-and-pairing.md),
  [ADR-0008](ADR-0008-idempotency.md),
  [ADR-0009](ADR-0009-state-consistency.md),
  [ADR-0010](ADR-0010-ipv4-ipv6-routing.md),
  [ADR-0011](ADR-0011-dns-handling.md),
  [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md),
  [ADR-0013](ADR-0013-multi-client-gateway-architecture.md),
  [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md),
  [ADR-0015](ADR-0015-observability-and-diagnostics.md),
  [ADR-0017](ADR-0017-local-management-interface.md),
  [ADR-0018](ADR-0018-shared-core-and-build-architecture.md),
  [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md),
  [ADR-0021](ADR-0021-packaging-distribution-and-updates.md),
  [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md),
  [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md),
  [docs/vision.md](../vision.md), [docs/architecture.md](../architecture.md),
  [docs/networking.md](../networking.md), [docs/protocol.md](../protocol.md),
  [docs/reliability.md](../reliability.md), [docs/testing-strategy.md](../testing-strategy.md),
  [docs/threat-model.md](../threat-model.md)

This ADR owns the **client process topology and the intra-device privilege boundary**: which
processes exist on each of the ten supported targets, what privilege each holds, which one is the
network and policy authority, which one installs and owns the fail-closed rule set, how each is
supervised across install/start/crash/update/uninstall, which local OS principal may control the
authority, what the gateway role does to that topology, and the sandboxing and entitlement posture
each process runs under. It contributes the `PLATFORM.PRIV.*` and `PLATFORM.SERVICE.*` subdomains
to the `PLATFORM` reason-code domain owned by [docs/architecture.md](../architecture.md) §2.5.

It does **not** own kill-switch policy, the bootstrap exception, or the disarm rule
([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) — this ADR binds to KS-9, KS-19, KS-20,
KS-21 and KS-23 and re-decides none of them); the leak-prevention mechanism
([docs/networking.md](../networking.md) §9); the `ConnectionState` machine
([docs/reliability.md](../reliability.md) §4); secure-storage realization
(**ADR-0020**, constrained by [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3); the
local management **wire contract** ([ADR-0017](ADR-0017-local-management-interface.md) — this ADR decides only who may call it and with
what authority); packaging, signing, notarization and update delivery ([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)); background
and lifecycle scheduling ([ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md)); or the headless/embedded product profile ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)).

> **Sibling-ADR references.** ADR-0017 … ADR-0023 are written concurrently with this one. Links to
> them are given in the expected kebab-case form; **ADR-0020** (local persistence and secure-storage
> realization) is referenced in bold without a link because its file was not present when this ADR
> was written. The integrator owns reconciling any slug that differs.

---

## 1. Context

The corpus already decides *what* must be true on the device and is deliberately silent on *which
process makes it true*. Three places make that silence expensive:

1. **[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) K3** requires enforcement installed
   at OS level, **independent of the agent process**, surviving crash, `SIGKILL`, update and
   reboot. "Independent of the agent process" is a statement about process topology, and no
   document says which process installs the rules, which one owns them afterwards, or what the OS
   does in the interval before that process exists.
2. **KS-9(1)** identifies the bootstrap exemption by an OS-mediated *process* predicate — cgroup
   path, WFP `ALE_APP_ID` + `ALE_USER_ID`, provider uid. **KS-10**'s safety argument is that
   "satisfying predicate (1) requires the privilege that also permits rewriting the rule set."
   That argument is true only if the process identified by the predicate is the privileged one.
   A topology that puts the sockets in an unprivileged process silently voids it.
3. **KS-21(1)** requires disarm to be "a local interactive action on the device itself. No network
   path, no remote management channel." **R-21** simultaneously requires headless Linux and
   router targets to be first-class, and a headless host has no local interactive session at all.
   As written the two are jointly unsatisfiable on exactly the targets R-21 exists to protect.

[docs/threat-model.md](../threat-model.md) §3 **TB-12** models the device↔OS boundary as a single
crossing and **AD-12** grades a hostile local process by two tiers only — "same user, not agent
privilege" and "agent privilege". This ADR introduces a boundary that sits *between* those tiers:
TwinVPN's own user interface, which runs as the user, is written in the largest and most
attack-exposed part of the codebase, and must not be inside the tier that can rewrite the rule
set. §11.4 states that boundary and asks the threat model to adopt it.

[docs/threat-model.md](../threat-model.md) §15 **O-11** names the gap directly and assigns it to
"SECURITY / PLATFORM". This ADR discharges the **privilege and authorization** half of O-11;
[ADR-0017](ADR-0017-local-management-interface.md) owns the wire contract and audit half. Neither closes it alone.

The mobile targets invert the question. On iOS, iPadOS and Android the OS owns the boundary, there
is no root, no privileged helper is expressible, and the only thing left to decide is which of the
two OS-imposed processes holds which responsibility — a decision
[docs/networking.md](../networking.md) §5.4 has already started making for memory reasons. The
embedded tier inverts it again: on a 64 MB OpenWrt router there is one process and it is root, and
the honest answer is to say so and state the residual rather than to invent a separation the
target cannot pay for.

## 2. Requirements

### 2.1 Normative requirements of this ADR

| # | Requirement |
|---|---|
| **Q1** | Exactly one process per host MUST be the **network and policy authority**: the sole holder of the virtual interface, the rule set, the route and resolver program, and the secure-storage key handle. Two authorities on one host is an I8 violation expressed as a process model. |
| **Q2** | The authority's lifetime MUST be independent of any user-interface process, any login session, any desktop session, and any user's presence. Loss of every UI MUST NOT change enforcement, `session_intent`, or any `ConnectionState`. |
| **Q3** | On every platform whose OS permits it, the authority MUST run at a privilege the UI does not hold, and the UI MUST NOT be able to acquire it by any means the OS does not itself gate. |
| **Q4** | Full compromise of the unprivileged process MUST NOT permit: disarming enforcement, rewriting routes/rules/resolver state, obtaining the tunnel file descriptor, using or exporting `DeviceKey`, or placing bytes on a KS-9-registered socket. Where a platform cannot deliver this, the residual MUST be stated (**K10**-style) and MUST NOT be claimed. |
| **Q5** | The authority MUST expose privileged effects **only** as typed, enumerated management operations. No management operation may accept raw rule text, a raw route, an arbitrary filesystem path, a command line, or loadable code. |
| **Q6** | Every privileged operation MUST be classified into exactly one authorization class (`OBSERVE`, `OPERATE`, `ADMINISTER`), and every `ADMINISTER` operation MUST require OS-mediated authentication **per action**, never cached beyond it. |
| **Q7** | The OS-applied artifact that satisfies **KS-19** MUST be owned by the package, MUST be applicable without the authority running, and MUST NOT be authored by the authority at runtime except by atomic replacement. |
| **Q8** | The authority MUST be supervised by the platform's own supervisor, with automatic restart, and with **bounded** crash-loop containment that can neither open a leak nor block boot. |
| **Q9** | Install, update and uninstall MUST be idempotent and re-runnable ([ADR-0008](ADR-0008-idempotency.md)), MUST be ordered so that no step can leave the host permanently unable to reach the network, and uninstall MUST require the same local authority as a disarm (KS-21) because it *is* one. |
| **Q10** | The authority MUST NOT load executable code from any path writable by a principal below its own privilege, and MUST NOT inherit a search path, preload variable, or plugin directory that could supply one. |
| **Q11** | The gateway role MUST NOT introduce a process per peer, a privilege beyond the client's set, or a supervision contract weaker than the client's (I7, R-16). |
| **Q12** | Every host mutation the authority makes outside its own interface MUST have a durable, verbatim restore point written **before** the mutation, readable by an uninstaller that the authority is not running to serve ([docs/networking.md](../networking.md) §5.5.3). |
| **Q13** | Where a required entitlement, capability, or platform approval is unavailable, the authority MUST fail with a named `PLATFORM.PRIV.*` code at startup, never degrade silently to a wider or narrower privilege than it declared. |

### 2.2 New requirements proposed for [docs/vision.md](../vision.md) §5.6

| ID | Historical defect | TwinVPN requirement | Mechanism | Specified in |
|---|---|---|---|---|
| **R-25** | Closing the tray icon, logging out, or having the GUI killed by a memory manager silently drops the tunnel and the leak protection with it | The network and policy authority MUST be a supervised process whose lifetime is independent of any UI process, login session, or desktop session. Termination of every unprivileged TwinVPN process MUST NOT alter enforcement, connection intent, or connection state, and MUST be reported as an informational event rather than as a disconnect. | Privileged long-lived service/daemon (Linux `systemd` system unit, Windows service, macOS NE system extension + `LaunchDaemon`, OpenWrt `procd`) with the UI as a detachable unprivileged client; OS-hosted provider/service on iOS, iPadOS and Android | ADR-0016 §11.2, §11.5, §11.6 |
| **R-26** | The VPN's entire attack surface — UI rendering, URL handling, update UI, image and font decoding — runs with the privilege that can rewrite the host firewall and use the device key | The privilege that can program host network state or use `DeviceKey` MUST be held by a process separate from any process that renders UI or parses untrusted remote content, on every platform whose OS permits the separation. Full compromise of the unprivileged process MUST NOT yield interface, rule-set, resolver, key, or disarm capability. Where a target cannot separate them, the limitation and its residual exposure MUST be declared per target, never implied. | Authority/UI process split with typed, enumerated, per-action-authorized management operations; least-privilege service accounts and capability sets; OS sandbox and hardening directives per target; declared `privilege_separated = false` targets | ADR-0016 §11.3, §11.4, §11.9, §11.10 |
| **R-27** | Uninstalling or crash-looping the client leaves the host either silently unprotected or permanently unable to reach the network, with no recovery that does not require the product that is broken | Install, restart, crash-loop containment, update and uninstall MUST each have a defined terminal state that leaves the host neither silently unprotected nor permanently broken. Crash-loop containment MUST be bounded, MUST NOT disarm enforcement, and MUST NOT block boot. Uninstall MUST require the same local authority as a deliberate disarm, MUST be idempotent and re-runnable, and MUST restore every host mutation from a durable restore point. | Supervisor-native restart with burst limits and a quarantine state; package-owned boot artifact separate from the service unit; ordered idempotent uninstall bound to `HostIntegrationRestorePoint` and `HostResolverRestorePoint`; privileged offline unblock command | ADR-0016 §11.6, §11.11; proof test **P16** |

## 3. Constraints

- **I3, I4, I6, I7, I8** and principles **P3, P4, P6, P7, P8, P10** ([docs/vision.md](../vision.md) §4).
- **[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)** — K3, K5, K7, K10; **KS-9** (the
  process predicate), **KS-10** (the "same privilege" safety argument), **KS-19** (the boot artifact
  must be OS-applied), **KS-20** (owner-tagged reclamation and the privileged unblock command),
  **KS-21** (local authority for disarm), **KS-23** (updates swap, never remove-then-add). This ADR
  binds to all of them and re-decides none.
- **S-18** — one writer, `LOCAL`, durable, OS-level, no remote replica. The process model must not
  create a second writer.
- **[docs/networking.md](../networking.md) §5.1** — the adapter contract is the only seam to the OS
  (**B4**/**TB-12**); §5.5.3 requires owner-tagged, reclaimable-after-unclean-exit state; §5.5.2
  forbids disabling the host firewall, resolver service, or IPv6.
- **[docs/architecture.md](../architecture.md) §2.1** — one binary is client, `ExitNode` and
  `LANGateway`; §4.2 — the data plane reads only local durable state; §2.5.1 already owns
  `PLATFORM.PROCESS_CRASHED`, `PLATFORM.CRASH_LOOP`, `PLATFORM.VPN_PERMISSION_DENIED`,
  `PLATFORM.SUSPENDED`/`RESUMED`, which this ADR consumes rather than redefines.
- **[docs/reliability.md](../reliability.md) §11.4** — "keep all liveness and enforcement inside the
  extension, never in the app process" on mobile; §6.2/R-06 — recovery is unattended, so no design
  may put an authentication prompt on the reconnect path.
- **Platform reality.** iOS and iPadOS have no root, no host firewall, no privileged helper, and a
  documented memory ceiling on the packet-tunnel provider. Android has no root and no programmatic
  lockdown for a non-DPC app. macOS system extensions require the NetworkExtension entitlement (a
  paid-team capability — P-06 as amended 2026-09-04) and user approval, and the App Store sandbox
  forbids the `LaunchDaemon` and `pf` anchor that
  [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6 names for macOS. Windows has no
  OS-hosted VPN extension at all. OpenWrt targets are frequently ≤ 128 MB RAM on a read-only
  rootfs with musl, and often have no second unprivileged identity worth the flash to create.
- **Working hypotheses.** **H1** (one portable core, memory-safe, stable C ABI, thin native shells)
  and **H3** (exactly one local management contract, no privileged GUI side channel) are assumed
  here and recorded in §11.15. **H2** is owned by this ADR and is treated as open in §4.
- **Phase 1 produces no code.**

## 4. Considered Alternatives

Three orthogonal decisions.

### Group T — process topology on a host that has a choice (desktop, server, embedded)

| # | Alternative |
|---|---|
| **A** | **Privileged monolith.** One process holds the UI, the core, the interface, the rule set and the key, and runs elevated (root / `LocalSystem` / admin-launched). This is what most consumer VPN clients that predate WFP and NetworkExtension actually shipped. |
| **B** | **Privileged authority + unprivileged clients.** A long-lived supervised service holds the core, the interface, the rule set, the resolver program and the key handle. The UI, the CLI and any local automation are unprivileged clients of one management contract. (This is **H2**.) |
| **C** | **Unprivileged agent + minimal privileged helper.** The core, state machine and policy evaluation run unprivileged in the user's session; a small privileged helper (setuid binary, `SMJobBless`-class XPC helper, polkit-mediated executable) performs only the enumerated privileged primitives on request. |
| **D** | **Elevate on demand.** No resident privileged process. Each privileged operation is performed by transiently elevating — `pkexec`, a UAC-elevated child, `AuthorizationExecuteWithPrivileges` — at the moment it is needed. |
| **E** | **OS-hosted provider only.** No process of ours holds privilege independently. Everything privileged happens inside the OS's own VPN hosting facility (`NEPacketTunnelProvider`, `VpnService`); the UI is the containing app; no service, no daemon, no helper. |

### Group MX — macOS extension hosting and distribution channel

| # | Alternative |
|---|---|
| **MX-1** | **NetworkExtension *system extension*, Developer ID + notarized.** Runs as root, activated once with admin approval, persists across logout and across "no user logged in". Ships alongside a package-installed `LaunchDaemon`. Not distributable through the Mac App Store. |
| **MX-2** | **NetworkExtension *app extension*, Mac App Store.** Runs inside the containing app's sandbox as the user, tied to the user session, distributed and updated by the App Store. Cannot install a `LaunchDaemon` and cannot write a `pf` anchor. |
| **MX-3** | **No NetworkExtension.** A `LaunchDaemon` creates `utun` directly and programs `pf` and routes itself, with no NE provider at all. |

### Group CA — who, locally, may control the authority

| # | Alternative |
|---|---|
| **CA-1** | **Installing user owns it.** The user who installed/enrolled is the sole controller; other users of the host may only observe. |
| **CA-2** | **Any local interactive user may operate; administrators may administer.** Two classes, group-derived. |
| **CA-3** | **Three classes — `OBSERVE` / `OPERATE` / `ADMINISTER` — with `ADMINISTER` requiring per-action OS-mediated admin authentication**, and the `OPERATE` set seeded at install according to a declared host profile (single-owner vs shared/managed). |
| **CA-4** | **Administrator-only.** Every operation, including connect and disconnect, requires admin authentication. |

## 5. Advantages of Each Alternative

| # | Advantages |
|---|---|
| **A** | Simplest to build and to reason about: no IPC, no contract, no versioning between halves, no authorization model, one crash domain, one log. Nothing can be out of step with anything else. Cheapest on a memory-constrained embedded target, where a second process is a real cost. |
| **B** | The authority's lifetime is decoupled from every session, which is exactly what R-25 and **K3** need. The privileged surface is small, enumerable, and testable in isolation. KS-9's predicate and KS-10's argument hold by construction, because the sockets and the rules are in the same process at the same privilege. Headless, CLI-only and GUI operation are the same product with a different client, which is what R-21 asks for. Multi-user and fast-user-switching become an authorization question rather than a lifecycle question. |
| **C** | The largest body of code — core, policy, state machine — runs unprivileged, which is the strongest possible answer to R-26 for that code. The privileged component can be small enough to review line by line. Familiar on macOS and on Linux desktops. |
| **D** | No resident privileged process at all: the smallest possible standing attack surface, and no service to supervise, install, or uninstall. Every privileged act is visible to the user at the moment it happens. |
| **E** | The OS enforces the boundary, so there is nothing of ours to get wrong. No installer, no driver, no service account, no supervision, no uninstall residue. On iOS, iPadOS and Android it is not merely the best option, it is the only one. Distribution through the platform stores is unblocked. |
| **MX-1** | Root, session-independent, survives logout and fast user switching, and coexists with the `LaunchDaemon` that [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6 names as the macOS boot artifact. Gets NE's on-demand lifecycle, `NEPacketTunnelNetworkSettings`, and system-resolver integration for free ([ADR-0011](ADR-0011-dns-handling.md)). |
| **MX-2** | App Store distribution, automatic updates, no notarization workflow of our own, no admin approval prompt, no system-extension activation UX. The lowest-friction install on macOS by a wide margin. |
| **MX-3** | No NetworkExtension entitlement and no system-extension approval step in System Settings; identical shape to the Linux daemon, so one design covers both. *Amended 2026-09-04: this cell previously read "No Apple entitlement dependency and no approval lead time". There was never a lead time to save — the entitlement is self-service for a paid team (P-06 as amended) — so the advantage that survives is the absent approval step, not a schedule.* |
| **CA-1** | Unambiguous. Matches the single-`Owner` product framing of [docs/vision.md](../vision.md) §2 exactly. |
| **CA-2** | Simple, group-derived, no prompts on ordinary use, and it matches how most desktop VPN clients behave. |
| **CA-3** | Ordinary use (connect, disconnect, observe) is prompt-free, while every operation that can reduce protection or move trust hits KS-21's per-action OS-mediated authentication. The class map is a small, auditable table rather than a scattering of checks. The host profile makes the shared-machine case a deliberate install-time decision instead of an accident. |
| **CA-4** | The strongest possible protection against a non-admin local user weakening protection for everyone on a shared host. |

## 6. Disadvantages of Each Alternative

| # | Disadvantages |
|---|---|
| **A** | Fails **R-26** categorically: font, image, markup and URL parsing run with `CAP_NET_ADMIN`/`SYSTEM`. Fails **Q2**/**R-25**: the UI's crash is the tunnel's crash. Not expressible at all on macOS with NE, on iOS, on iPadOS, or on Android. On Windows it forces either a per-user elevated process (UAC prompt per launch) or a service that also owns a desktop, which has been a documented shatter-attack surface for two decades. |
| **B** | Requires a management contract, its versioning, its authorization model, and its audit — real work, and the thing [docs/threat-model.md](../threat-model.md) O-11 says is currently unspecified. Two crash domains and two update artifacts that can be out of step. An installer and an uninstaller with privilege become mandatory. |
| **C** | **Structurally voids KS-10.** The socket that carries relay/rendezvous/peer traffic would be owned by the unprivileged agent, so KS-9(1)'s predicate would have to name an unprivileged process — at which point "satisfying the predicate requires the privilege that also permits rewriting the rule set" is false, and the bootstrap exemption becomes reachable by any code running as the user. Additionally, either the helper is rich enough to install and swap the fail-closed rule set (in which case it *is* the authority, with a worse-audited surface and a second lifetime), or it is not, in which case **K3** fails. `SMJobBless`-class on-demand privileged helpers are also a well-populated local-privilege-escalation CVE class precisely because they execute privileged work on request from arbitrary local callers. |
| **D** | Fails **K3** and **K7** outright — nothing survives to hold the rule set. Fails **R-06**: unattended reconnection becomes a prompt, and a roaming laptop would prompt on every network change. Fails **Q2**. No boot-time story at all. |
| **E** | On macOS an app extension activates after login and can be deactivated by the user, so it cannot be the KS-19 boot artifact; on Windows there is no OS-hosted VPN provider to be. E is therefore not universal, and adopting it on desktop would mean abandoning boot-window enforcement on two of the three desktop targets. |
| **MX-1** | Requires a paid Apple Developer Program team with the Network Extensions and System Extension capabilities enabled, a Developer ID–signed build whose provisioning profile carries `com.apple.developer.networking.networkextension` with the `packet-tunnel-provider-systemextension` value, and a user-visible admin approval step in System Settings (or a Device-Enrollment MDM System Extensions payload). Forecloses Mac App Store distribution. Adds a second privileged component (the `LaunchDaemon`) to keep small and correct. *Amended 2026-09-04: this cell previously read "Requires Apple to grant … the `packet-tunnel-provider-systemextension` value — an application with real lead time and a real refusal risk." There is no application: the capability has been self-service for a paid team since 2016-11-10, TN3134 lists only `family-controls` and HotspotHelper as request-gated, and Apple's capabilities table withholds both from the free tier — enrolment is the prerequisite, not a grant (P-06).* |
| **MX-2** | The App Store sandbox forbids installing a `LaunchDaemon` and forbids writing `/etc/pf.conf` anchors, so [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6's macOS boot row becomes unimplementable and macOS loses boot-window enforcement — an unstated downgrade of **K7** on a desktop platform. The provider dies with the user session, breaking **Q2** for a multi-user Mac. |
| **MX-3** | Gives up NE's on-demand reactivation, its network settings object, and its system-resolver integration, all of which [ADR-0011](ADR-0011-dns-handling.md) and [docs/networking.md](../networking.md) §5.2 already assume for macOS. Apple has repeatedly narrowed what a non-NE daemon may do to the network stack, so this is the option most likely to be broken by a macOS release. |
| **CA-1** | Breaks on a genuinely shared machine and on a host where the installing account is a provisioning account that never logs in again. Says nothing about administrators. |
| **CA-2** | A non-admin secondary user on a shared laptop can disconnect the tunnel for everyone, and group membership is a poor stand-in for KS-21(2)'s "OS-mediated authentication of an `Owner`/administrator principal" — it is checked once at login, not per action. |
| **CA-3** | Three classes and a host profile is more machinery than the single-`Owner` framing suggests is needed, and mis-assigning the profile at install produces either nuisance prompts or an over-permissive shared host. |
| **CA-4** | Fails **R-06**'s spirit and the product's basic ergonomics: an authentication prompt to reconnect a laptop after a coffee-shop network change is the behaviour that makes users disable VPNs. |

## 7. Security Implications

- **The boundary this ADR adds is an intra-device one, and the threat model does not currently have
  it.** [docs/threat-model.md](../threat-model.md) **TB-12** treats device↔OS as one crossing and
  **AD-12** grades local adversaries as "same user, not agent privilege" or "agent privilege". Under
  alternative B the UI *is* "same user, not agent privilege" — the tier the threat model already
  says is bounded — but it is *our* code, holding the user's trust, rendering remote content, and
  sitting one API call from the authority. §11.4 states what that tier can and cannot do and asks
  for **TB-13** and a split of **AD-12**.
- **KS-10's argument is a topology invariant, not a code invariant.** Any future refactor that moves
  the relay/rendezvous/peer sockets out of the process that owns the rule set silently converts the
  bootstrap exemption from "requires rule-rewriting privilege" into "requires being the user".
  §11.3 makes socket ownership a normative property of the authority, and **P16** Procedure B step 6
  tests it.
- **I4 is a custody question about a process, not only about a keystore.** The secure-storage ACL
  must bind the key's *use* to the authority. Where the platform cannot scope the ACL below the app
  identity (iOS, iPadOS, Android), the app process is inside I4's use boundary and §11.4 says so
  rather than implying a separation the OS does not provide.
- **Least privilege is measured against the enumerated operation set, not against `root`.** §11.3
  enumerates every privileged operation the product performs; §11.9 derives the smallest capability,
  privilege and entitlement set that covers exactly those and no more, and **Q13** makes a
  shortfall a named startup failure instead of a silent widening.
- **Code-load integrity is part of the privilege boundary.** **Q10** exists because an authority that
  can be made to load a library chosen by a lower-privileged principal has no boundary at all. This
  is why `MemoryDenyWriteExecute`, macOS library validation without `disable-library-validation`,
  and Windows `ProcessDynamicCodePolicy`/`ProcessImageLoadPolicy` are normative in §11.9 and not
  advisory.
- **Uninstall is a disarm.** Removing the owner-tagged rule set through the uninstaller and removing
  it through a disarm command have identical effect on **I3**, so **Q9** binds uninstall to KS-21.
  Any packaging path that can uninstall without that authority is a remote-reachable disarm wearing
  a different hat, which is why §11.13(d) states it as a requirement on [ADR-0021](ADR-0021-packaging-distribution-and-updates.md).
- **The authority is not defended against an adversary who already holds its privilege.** That is
  **AD-12** at agent privilege and **N4**; nothing here changes it, and §11.4 does not claim to.

## 8. Reliability Implications

- **R-25 is the reliability payload of this ADR.** The single most common way a consumer VPN drops
  protection is that its GUI died. Under B the UI is a detachable observer; its death is
  `PLATFORM.SERVICE.UI_DETACHED` at `INFO` and changes nothing else. §11.5 names both directions of
  the failure — daemon alive/UI gone, and UI alive/daemon gone — and gives each a defined outcome.
- **Crash-loop containment is a reliability/security conflict resolved in the safe direction.**
  Unbounded restart thrashes and can, on some supervisors, escalate to a reboot loop; bounded
  restart that *disarms* on giving up is a leak. §11.6 resolves it as: stop restarting the full
  authority, keep the rule set installed, keep the management interface answering, keep the
  privileged unblock command reachable. Enforcement never relaxes as a consequence of our own
  instability.
- **The boot artifact must not share a failure domain with the service.** §11.6 makes the KS-19
  artifact a separate, package-owned, `oneshot`-class unit so that a crash-looping authority cannot
  prevent the boot ruleset from applying, and so that a failure to apply the boot ruleset is
  reported as itself rather than absorbed into a restart counter.
- **Supervision is the mechanism behind `PLATFORM.PROCESS_RESTARTED`.**
  [docs/architecture.md](../architecture.md) §2.5.1 already promises peers are told about a planned
  restart so they do not mark the path failed; that promise requires a supervisor that restarts
  promptly and a durable state store the authority rehydrates from ([docs/reliability.md](../reliability.md)
  §6.5). §11.6 names the supervisor and the restart budget per platform.
- **Multi-client operation must not create a second writer.** Several UIs across several logged-in
  users may observe one authority concurrently; **I8** is preserved because none of them is a writer
  — they submit operations and observe the authority's own state transitions, attributed.

## 9. Performance Implications

- **No IPC is in the datapath.** The entire data plane — interface, crypto, path selection, routing,
  enforcement — lives in the authority. The management interface carries control and observation
  only, so the process split costs zero per-packet work. This is the direct consequence of Q1 and is
  the reason B is not a throughput regression against A.
- **The iOS/iPadOS extension memory ceiling is the binding performance constraint of the whole
  application layer.** Apple has historically documented a hard 15 MB resident limit for
  `NEPacketTunnelProvider`, raised for packet-tunnel providers on recent releases; the exact
  ceiling is version-dependent and Apple has changed it without notice. This ADR budgets to the
  **15 MB floor** and treats any headroom above it as unearned. §11.2 therefore keeps contract
  fetch/parse, the diagnostic ring buffer, bundle generation, and all presentation state in the app
  process, per [docs/networking.md](../networking.md) §5.4 — and §14(1) makes the budget a
  falsifiable revisit trigger rather than an assumption.
- **Cold start is a security-relevant latency.** The interval between the network stack coming up and
  the authority reaching `ready` is exactly the window KS-19's boot artifact exists to cover. It is
  not zero-risk to be slow — a slow start widens nothing while the boot ruleset holds, but it delays
  recovery from `BLOCKED`. §14(8) makes 800 ms p95 the trigger.
- **A second process costs memory on the embedded tier and that is why the embedded tier does not
  have one.** §11.10 runs a single process on OpenWrt-class targets deliberately.
- **Per-action authentication is off the reconnect path by construction.** §11.7 places connect,
  disconnect, roam, migrate and reconnect in `OPERATE`; nothing on the automatic recovery path of
  [docs/reliability.md](../reliability.md) §6 can raise a prompt, which is what keeps R-06's
  "unattended" true.

## 10. Operational Implications

- **Every platform ships a privileged, local, network-independent unblock command** — this is
  [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §10's requirement, and §11.6 assigns it a
  process: it is a separate small executable in the package, not a subcommand of the authority,
  precisely because the case it exists for is "the authority will not start".
- **Driver lifecycle is Windows-shaped and is owned by the installer, not the service.** WinTun's
  DLL and driver ship in the application directory, versioned with the app
  ([docs/networking.md](../networking.md) §5.3); the service compares versions at startup and emits
  `NET.DRIVER_REPLACED`; the uninstaller removes the adapter. [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) owns the signing and the
  MSI/MSIX decision; §11.13(d) states what this ADR requires of it.
- **One Google approval is on the critical path and has lead time; the Apple entitlement has
  none.** The NetworkExtension entitlement (iOS/iPadOS `packet-tunnel-provider`, macOS
  `packet-tunnel-provider-systemextension`) is enabled by a paid Developer Program team in
  Certificates, Identifiers & Profiles with no application to Apple (P-06 as amended 2026-09-04),
  and Google Play's VPN policy requires a declaration and review for any app using `VpnService`.
  §11.9 marks both, and §14(2) names the one macOS condition that can still remove MX-1. *Amended
  2026-09-04: this bullet previously read "Two Apple/Google approvals are on the critical path and
  have lead time … is granted by Apple on application … §14(2) makes the macOS one a falsifiable
  schedule trigger."*
- **Support must be able to answer "the app says nothing is running".** `PLATFORM.SERVICE.*`
  distinguishes not-installed, not-running, quarantined, version-mismatched, and
  approval-pending, so the first support question is answered by a code rather than by a screenshot.
- **Fleet telemetry** must report, per platform: quarantine incidence; `PLATFORM.PRIV.DROP_FAILED`
  and `SANDBOX_DEGRADED` rates; `SYSEXT_NOT_APPROVED` conversion; uninstall-incomplete rate;
  `REMOTE_ADMIN_USED` share of `ADMINISTER` actions; and authority cold-start p95. All six feed §14.
- **Enterprise deployment** prefers the platform-native paths for exactly the reasons
  [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §10 gives: Android DPC-managed always-on,
  iOS supervised Always-On VPN, macOS MDM-delivered system-extension approval
  (`SystemExtensionPolicy`) which removes the user approval step, and Windows service install by
  the management agent.

## 11. Decision

**Adopt B (privileged long-lived authority + unprivileged clients) as the process topology on every
target whose OS permits it; adopt E as the topology on iOS, iPadOS and Android, where the OS
imposes it; adopt a single-process root authority on the OpenWrt/embedded tier with the residual
declared. Adopt MX-1 (NetworkExtension system extension, Developer ID + notarized, alongside a
package-installed `LaunchDaemon`) for macOS, and reject MX-2 for the desktop product because it
forfeits KS-19. Adopt CA-3 for local control authority, with the attended/headless host-class rule
of §11.7 resolving KS-21(1) for targets that have no local interactive session.**

This **confirms H2**.

### 11.1 The three host classes, and the one rule that spans them

Every target falls into exactly one class. The class is decided at install, is recorded in **S-38**,
and is an `ADMINISTER`-class setting thereafter.

| Class | Targets | Topology | `privilege_separated` | Local interactive session exists |
|---|---|---|---|---|
| **HC-1 — attended, separable** | Linux desktop, Windows, macOS | B: authority + unprivileged clients | `true` | yes (console seat) |
| **HC-2 — OS-mediated** | iOS, iPadOS, Android | E: OS-hosted provider + app | `os_enforced` | yes, but the OS owns the boundary |
| **HC-3 — headless** | Linux server, containers, OpenWrt/routers, CLI-only | B on Linux server/containers; single root process on OpenWrt-class | `true` / `false` (declared per target) | **no** |

**Rule PS-1 — one authority.** Exactly one process per host is the network and policy authority. It
is the sole holder of the virtual-interface handle, the enforcement rule set handle, the route and
resolver program, the secure-storage key handle, and the KS-9-registered sockets. No other process
of ours holds any of them, on any platform, in any class. A second process claiming any of them is
`INTERNAL.INVARIANT_VIOLATED`.

**Rule PS-2 — the authority is the KS-9 subject.** The process identified by
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-9(1)'s per-platform predicate MUST be the
authority and MUST be the same process that owns the enforcement rule set. Any change that separates
them is a breaking change to KS-10's safety argument and requires ADR-0012 to be reopened.

**Rule PS-3 — UI death is not a disconnect.** Loss of the last management client MUST NOT change
`session_intent`, enforcement mode, the installed rule set, or any `ConnectionState`. The authority
emits `PLATFORM.SERVICE.UI_DETACHED` and continues.

### 11.2 Process topology per platform (normative)

| Platform | Processes | Privilege held | Authority | Supervisor | KS-19 boot artifact owner |
|---|---|---|---|---|---|
| **Linux (HC-1/HC-3)** | `twinvpnd` (system service) · `twinvpn` CLI · `twinvpn-ui` (optional, per-user) · `twinvpn-unblock` (privileged, on demand) | `twinvpnd`: `User=twinvpn`, `AmbientCapabilities=CAP_NET_ADMIN`, bounding set `CAP_NET_ADMIN` only, `NoNewPrivileges=yes`, supplementary group `tss` for `/dev/tpmrm0`. Clients: none | `twinvpnd` | `systemd`, `Type=notify`, `WantedBy=multi-user.target` (**never** `graphical.target`) | `twinvpn-killswitch.service` (`oneshot`, `Before=network-pre.target`), a **separate package-owned unit** applying `/etc/twinvpn/killswitch.nft` |
| **Windows (HC-1)** | `TwinVPNService` (Windows service) · `twinvpn.exe` CLI · `TwinVPN.exe` UI (per-session, medium IL) · `twinvpn-unblock.exe` (elevated) | Service: `LocalSystem` with `SERVICE_SID_TYPE_UNRESTRICTED` service SID `NT SERVICE\TwinVPNService`, `RequiredPrivileges` trimmed to the §11.9 list. Clients: the interactive user's token | `TwinVPNService` | SCM with recovery actions | Installer-written **persistent** WFP filter set (`FWPM_FILTER_FLAG_PERSISTENT`) plus the `FWPM_FILTER_FLAG_BOOTTIME` coarse deny, both owned by BFE, not by the service |
| **macOS (HC-1)** | `<app-bundle-id>.sysext` (NE **system extension**, root — **PS-19**: a system extension's bundle id MUST be prefixed by its containing app's, so the literal `com.twinvpn.sysext` used elsewhere in this ADR is not installable; it is retained below only as shorthand) · `com.twinvpn.ksd` (`LaunchDaemon`, root, minimal) · `TwinVPN.app` (per-user, sandboxed) · `twinvpn` CLI · `twinvpn-unblock` | sysext: root, NE-hosted. `ksd`: root, no network, no core, no key access. App/CLI: user | `com.twinvpn.sysext` | `launchd` for `ksd`; `systemextensionsd` + NE on-demand for the sysext | `com.twinvpn.ksd` (`RunAtLoad=true`), which applies the `/etc/twinvpn/pf.anchor` referenced from `/etc/pf.conf` |
| **iOS / iPadOS (HC-2)** | `TwinVPN.app` (containing app) · `TwinVPNTunnel` (`NEPacketTunnelProvider` **app extension**) | Neither is privileged. The extension holds the tunnel by OS grant | The **extension** | The OS (NE on-demand rules) | **None available** — KS-19 is unsatisfiable; ADR-0012 emits `POLICY.KILLSWITCH.BOOT_ENFORCEMENT_UNAVAILABLE` |
| **Android (HC-2)** | `:main` (UI/activities) · `:tunnel` (`VpnService` in a separate process, foreground service) | Neither is privileged; same UID | The `:tunnel` process | The OS (always-on/lockdown, or the foreground service) | OS always-on lockdown, enabled in Settings or by a DPC |
| **OpenWrt / routers (HC-3)** | `twinvpnd` only | root (optionally `ujail` + seccomp — §11.10) | `twinvpnd` | `procd` (`respawn`) | init script ordered before `network`, applying a UCI-included `fw4`/nftables table |
| **Headless Linux / containers (HC-3)** | as Linux, minus the UI | as Linux | `twinvpnd` | `systemd` (or the container supervisor — §11.10) | as Linux |

**Linux, normatively.** `twinvpnd` starts as root only long enough to open `/dev/net/tun`, the
netlink sockets and the TPM resource manager, then drops to the dedicated system user with an
ambient `CAP_NET_ADMIN`. It MUST NOT hold `CAP_SYS_MODULE`: the `wireguard` module is loaded by a
package-shipped `modules-load.d` entry or by kernel autoload on first netlink use. It MUST NOT hold
`CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`, or `CAP_SYS_PTRACE`. Failure to drop is
`PLATFORM.PRIV.DROP_FAILED` and is **fatal** — the authority MUST NOT continue as root "just this
once". `polkit` is used, but only as the `ADMINISTER`-class authentication mechanism of §11.7; it is
**not** the privilege-acquisition mechanism, and there is **no setuid binary in the product**.

**Windows, normatively.** `LocalService` and `NetworkService` are rejected: neither can open the WFP
engine for write, install a device driver, or program the IP Helper interface stack.
`SERVICE_SID_TYPE_RESTRICTED` is rejected because the WFP engine handle and `SwDevice`-based driver
installation both require access outside a restricted token's reach; the service SID is
`UNRESTRICTED` and is used as the `FWPM_CONDITION_ALE_USER_ID` half of KS-9(1) and as the ACL
principal for the state directory and the management pipe. The service MUST NOT be granted
`SeDebugPrivilege` or `SeTcbPrivilege`.

**macOS, normatively.** The system extension is the authority; the `LaunchDaemon` `ksd` is *not* a
general-purpose privileged helper and MUST NOT accept any request other than (a) apply the boot
anchor and (b) the unblock command's local, admin-authenticated invocation. `SMJobBless`-class
on-demand privileged helpers are **rejected** for this product (§6 C). `ksd` is installed by
`SMAppService.daemon(plistName:)` on macOS 13+ and by `SMJobBless` on macOS 11–12, in both cases
signed with the same Team ID and embedded in the app bundle.

**Amendment PS-25 — how the core gets *into* the system extension, and why the daemon is not the
authority.** The paragraph above says the system extension is the authority. Wave 2's macOS
implementation read `ownership.md` §8's **W-24/W-25** — `twinvpn.h`'s F-9 vtable carries no
`installed_ruleset` read-back, no `current_generation`, no socket provider and no interface
enumerator — concluded that a Swift extension therefore *cannot* be the authority, and put the core
in the `LaunchDaemon` instead. **The conclusion does not follow, and the resulting topology is
wrong.**

W-24 and W-25 are about a shell bound **only to the C vtable**. They are not about a shell that
**links the core as a Rust staticlib**, which is what §11.14 (f) already requires in terms: *"the
portable core MUST link into … a macOS NE **system extension**"*. `ownership.md` §10.4 rules the
same way for the Swift and Kotlin mobile shells — the missing capabilities stay in Rust,
in-process, reached through a per-platform `extern "C"` bridge that is **not** an ABI of record and
carries **no** compatibility obligation, because both sides compile from one commit into one
artifact. That ruling is hereby **general**: it is how every Swift or Kotlin shell obtains the
capabilities F-9 lacks, macOS included.

**The decisive constraint is physical, not editorial.** `NEPacketTunnelProvider.packetFlow` exists
only inside the provider process. The datapath must therefore be in the extension; the core owns
the datapath; and §11.16 (a) / S-47 permit **exactly one process** to hold a mutating core handle.
So there is no split in which the daemon holds the core and the extension pumps packets — it would
put an IPC hop on every packet, and a second core handle where S-47 allows one.

**Normatively, restating §11.2 for macOS with the mechanism named:**

| Component | Holds | Does not hold |
|---|---|---|
| the NE **system extension** | the core (linked as a Rust staticlib through the bridge), the platform adapter, the datapath, the key handle, the management interface over XPC with `audit_token_t` (§11.14 (a)) | — |
| `ksd`, the `LaunchDaemon` | the KS-19 boot anchor, and the unblock command's local admin-authenticated invocation | **no core, no keys, no network sockets, no management interface** |

**The availability question this raises is answered for two of three rules, and the third needed a
correction.** If the authority is the extension and the extension is started on demand, what answers
the management interface when the tunnel is down?

- **MI-A3 / M-P17-17 — answered.** A client connecting to an absent agent receives
  `MGMT.UNAVAILABLE`, the one code ADR-0017 §11.12 has the client mint, rather than a hang. Socket
  activation is named as the defect precisely because it would start the agent from a client
  connection.
- **MI-I5-5 — answered.** "The management channel MUST still answer" is scoped to *"every phase in
  which a process exists at all"*.
- **§11.14 (d) and PS-9 (2) — NOT answered, and an earlier draft of this amendment was wrong to
  claim they were.** That draft said the quarantine stub is "the authority's own degraded form, not
  a second process". On Linux and Windows it is. **On macOS it cannot be:** NE starts the provider
  for a *tunnel*, not for a management request, so a quarantined authority is a process that does
  not exist and cannot be supervised into a stub. §11.6's macOS row compounds it — the authority
  "latches quarantine itself", and a latched authority is exactly the one that is not running.
  Found by `desktop-macos` while implementing this amendment, which is the outcome an
  implementation is for.

**Rule PS-25a — on macOS, and only on macOS, `ksd` serves the degraded-state subset.** `ksd` MAY
answer the management interface **when and only when the authority is absent**, and MAY answer
**only** the read-only operations that report the authority's own lifecycle state — PS-9 (2)'s
`PLATFORM.SERVICE.QUARANTINED`, `PLATFORM.SERVICE.UNAVAILABLE`, `PLATFORM.SERVICE.NOT_INSTALLED`
and the S-40 restart counter §11.6 already requires it to keep durably. Every other operation MUST
be refused by name.

This is a **third accepted request**, added to the paragraph above's (a) and (b), and it is
deliberately the narrowest one that discharges §11.14 (d):

- It **performs no privileged effect and forwards nothing.** It reads durable state the authority
  wrote and reports it. A daemon that proxied MI operations to a running authority would be the
  general-purpose privileged helper §11.2 forbids, and would break §11.14 (a)'s credential chain by
  putting a hop between the caller and the authority; this does neither.
- It holds **no core, no keys and no network sockets**, so §11.2's "the second surface is close to
  nil" survives.
- It is **one contract, not two**: `ksd` answers over `twinvpn_mgmt::envelope` like every other
  carriage, and MUST refuse anything outside the subset rather than implementing a second dialect.
- Without it, `blocked` and `bricked` are indistinguishable on macOS — the failure `M-P17-18` names
  — and KS-20's "blocked must not mean bricked" would hold on two desktops and not the third.

**iOS and iPadOS, normatively.** The capability split follows
[docs/networking.md](../networking.md) §5.4 and is normative here:

| Responsibility | Process | Why |
|---|---|---|
| Tunnel engine, path state, keepalives, enforcement posture, `Session` state machine | **Extension** | [docs/reliability.md](../reliability.md) §11.4 — the extension outlives the app |
| Signed-contract fetch, schema parse, migration, policy document verification | **App** | Memory ceiling; parsing untrusted documents is the largest allocation and the largest attack surface |
| Diagnostic ring buffer beyond a bounded in-extension tail, bundle generation, redaction | **App** | Memory ceiling; [ADR-0015](ADR-0015-observability-and-diagnostics.md) requires local user authorization anyway |
| Pairing ceremony UI, QR/OOB verification | **App** | Requires UI |
| `NETunnelProviderManager` configuration and VPN-profile installation | **App** | Only the app can present the consent flow |
| Durable local store (**2.20**) | Shared App Group container, **written only by the process that owns each fact** | I8: a shared container is not a shared writer. PS-24 assigns the writers |

**iPadOS is not iOS with a bigger screen.** Stage Manager and multi-window mean **several UI scenes,
and on iPadOS several app instances, may be live at once over one tunnel**: the tunnel is
per-device, the management client count is ≥ 1, and the presentation layer MUST tolerate N
concurrent observers of one authority (a requirement this ADR places on [ADR-0017](ADR-0017-local-management-interface.md) and
[ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md)). An iPad with an external display or a hardware keyboard is more likely to be
plugged in and foregrounded for long periods, which makes the app process a *more* reliable partner
for contract fetch than on iPhone — but the design MUST NOT depend on that, because the same binary
runs on an unplugged iPad mini. Background posture, extension memory ceiling, and the absence of a
host firewall are identical to iOS and are not relaxed.

**Android, normatively.** `:tunnel` is declared `android:process=":tunnel"` and hosts the
`VpnService`; `:main` hosts activities. `android:isolatedProcess` is **not** usable for a
`VpnService` (it must be bindable by the system), so `:tunnel` runs under the app's own UID. This
means the Android split is a **fault-isolation and memory boundary, not a privilege boundary**, and
§11.4 records that as a declared residual rather than claiming R-26 is satisfied. `VpnService.prepare()`
requires an `Activity`, so `:main` is architecturally required for *authorization* even though it is
not required for operation — the tunnel process cannot self-authorize, and a first run therefore
always involves the UI.

**Rule PS-24 — a second, unprivileged core instance in the HC-2 app process is permitted, and is not
an H2 conflict.** [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) §11.12 places a
*core-lite* instance — schema, verification, store, trust and diagnostics; no datapath, no
enforcement, no privilege — in the iOS/iPadOS **app** process, to satisfy the extension memory
ceiling that [docs/networking.md](../networking.md) §5.4 already responds to. As owner of the
process model this ADR rules: **this is consistent with H2 and with PS-1.** H2 and PS-1 are
statements about *privilege and authority*, not about how many copies of a library are linked into
how many processes. PS-1 enumerates the authority by what it **holds** — the interface handle, the
rule-set handle, the route and resolver program, the key handle, the KS-9-registered sockets — and
core-lite holds none of them. A second core instance is a linkage fact; a second authority would be
an I8 violation, and core-lite is not one.

The ruling is conditional on four rules, and a design that breaks any of them **is** an H2 conflict:

1. **Scope.** The split is authorized for **HC-2 only**, and only for the responsibilities the §11.2
   table assigns to the app. It MUST NOT be generalized to HC-1 or HC-3: on those classes the
   authority performs contract fetch itself, and moving it into an unprivileged process there would
   re-create alternative C and void KS-10 (§12.1).
2. **One writer per fact (I8), across the App Group container.** A shared container is shared
   *storage*, never shared *authority*. Writers are assigned by origin:

   | Origin of the fact | Writer | Examples |
   |---|---|---|
   | **Learned, measured or negotiated by the datapath** | **Extension** | `Session` identity and last `ConnectionState` (S-12), `Endpoint` cache (S-15), per-relay measured quality (S-31), per-peer negotiation floor (S-37), enforcement posture (S-18) |
   | **Fetched, verified, or authored through the UI** | **App (core-lite)** | Cached signed `AccessPolicy`/`DNSPolicy` (S-06, S-07), membership and revocation caches (S-02, S-03), local `TrustedPeer` set from the pairing ceremony (S-05), pinned anchor and `EpochSeed` set (S-32, S-33), control-channel cursor (S-27), user preferences (S-24) |

   The other process **reads** and MUST NOT write. A cross-write is `INTERNAL.INVARIANT_VIOLATED`,
   not a merge. Because both processes may run simultaneously, per-fact single-writer ownership MUST
   be enforced by the store itself — file-per-fact ownership or a writer lease — which is a
   requirement on **ADR-0020** (§11.14(g)). "Both link the same store code" is not an I8 argument.
3. **Core-lite MUST NOT be on any recovery path.** Under `includeAllNetworks` with no authorized
   secure path, the app process has no network: its control-plane traffic is class 1/2 protected and
   dropped, and it does **not** match [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) class 7,
   whose KS-9(1) predicate names the provider. There is no mechanism on iOS by which it could — no
   host firewall exists to carry an exemption. Every step of
   [docs/reliability.md](../reliability.md) §11.3's wake-to-traffic ladder and every step of a
   reconnect MUST therefore be satisfiable by the extension alone, from the pre-materialized state of
   [docs/architecture.md](../architecture.md) §4.4.1. **A recovery step that requires core-lite to
   fetch anything is unreachable exactly when it is needed** — the same shape as the
   KS-10 / [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) self-update
   deadlock, and it is closed here by prohibition rather than discovered later.
4. **It does not widen the I4 residual; it explains it.** §11.4 already declares that on HC-2 the app
   can use `DeviceKey` as a signing oracle, because the keychain access group cannot be scoped below
   app identity. Core-lite makes that use *purposeful* — the control-plane client needs
   `DeviceIdentityKey` per-message signatures — rather than incidental. The residual is unchanged in
   size and better justified: it is forced by the memory ceiling, not chosen. PS-1's "sole holder of
   the key handle" clause is, on HC-2 and only on HC-2, a declared residual rather than an
   enforceable property, and P16's platform-degradation table already tests it as a declaration.

### 11.3 The privilege boundary as a contract

Every privileged operation the product performs, the process that performs it, and the privilege it
requires. **This table is the enumeration Q5 refers to.** An operation not on this list is not a
privileged operation, and adding one is a change to this ADR.

| # | Operation | Linux | Windows | macOS | iOS / iPadOS | Android | OpenWrt |
|---|---|---|---|---|---|---|---|
| **O1** | Create/destroy virtual interface | `twinvpnd`, `CAP_NET_ADMIN` on `/dev/net/tun` | Service, WinTun via `SwDevice` (SYSTEM) | sysext, NE-granted `utun` | Extension, NE-granted | `:tunnel`, `VpnService.Builder.establish()` | `twinvpnd`, root |
| **O2** | Address + route programming | `twinvpnd`, `rtnetlink` | Service, IP Helper | sysext, `NEPacketTunnelNetworkSettings` | Extension, `NEPacketTunnelNetworkSettings` **only** (no route API) | `:tunnel`, `VpnService.Builder` | `twinvpnd` via netifd/UCI |
| **O3** | Install/swap the fail-closed rule set | `twinvpnd`, nftables `table inet twinvpn` | Service, own WFP sublayer | sysext, `pf` anchor + NE settings | Extension, `includeAllNetworks` (OS-enforced) | `:tunnel`, route claim + OS lockdown | `twinvpnd`, `fw4` include |
| **O4** | Apply the **boot** rule set (KS-19) | `twinvpn-killswitch.service` (package unit) | Installer-written persistent/BOOTTIME WFP set (BFE) | `com.twinvpn.ksd` | **none** | OS lockdown | init script |
| **O5** | Resolver configuration + `HostResolverRestorePoint` (**S-34**) | `twinvpnd` (`systemd-resolved` D-Bus / owner-tagged `resolv.conf`) | Service, NRPT | sysext, NE `dnsSettings` | Extension, NE `dnsSettings` | `:tunnel`, `addDnsServer` | `twinvpnd` |
| **O6** | `DeviceKey` **creation** | `twinvpnd` (TPM under SRK) | Service (CNG/PCP) | sysext (Secure Enclave) | **App or extension** (shared access group) | **`:main` or `:tunnel`** (same UID) | `twinvpnd` (file-backed) |
| **O7** | `DeviceKey` **use** (sign / agree) | `twinvpnd` only | Service only | sysext only | **App or extension** — declared residual | **either process** — declared residual | `twinvpnd` only |
| **O8** | Durable local store write (**2.20**) | `twinvpnd`, `StateDirectory=twinvpn`, mode 0700 | Service, state dir ACL'd to the service SID + Administrators | sysext, `/Library/Application Support/TwinVPN` root-owned | Per-fact writer in the App Group (§11.14) | Per-fact writer in app-private storage | `twinvpnd`, overlay |
| **O9** | Open + KS-9-register relay/rendezvous/peer sockets | `twinvpnd` (cgroup + `SO_MARK`) | Service (`ALE_APP_ID` + service SID) | sysext (provider uid + socket set) | Extension (implicit) | `:tunnel` (implicit) | `twinvpnd` |
| **O10** | Set forwarding sysctls (gateway role) | package `sysctl.d` file, installed as an `ADMINISTER` action — **never** a runtime write | Service, `EnableForwarding` on the interface | sysext, `net.inet.ip.forwarding` via the same install-time mechanism | n/a | n/a | UCI `config` + `/etc/sysctl.d` |
| **O11** | Install/replace the datapath driver | n/a (in-tree module) | Installer (elevated), service verifies version at start | n/a | n/a | n/a | n/a (in-tree) |
| **O12** | Disarm enforcement (KS-21) | `twinvpnd`, gated by `polkit` `auth_admin` | Service, gated by client-token impersonation + Administrators check | sysext, gated by Authorization Services `system.privilege.admin` | n/a — VPN-profile removal, OS-owned | n/a — Settings toggle, OS-owned | `twinvpnd`, gated by §11.7's headless rule |
| **O13** | Offline unblock (no authority running) | `twinvpn-unblock`, run as root | `twinvpn-unblock.exe`, elevated | `twinvpn-unblock` via `ksd` | n/a | n/a | `twinvpn-unblock` |

**Rule PS-4 — no raw pass-through.** No management operation may accept rule text, a route
specification, a resolver address, a filesystem path, a command line, a library path, or an
identifier that the authority resolves to any of those. Every operation is a typed request over a
closed vocabulary, and the authority derives the host mutation itself from its own state.

**Rule PS-5 — no descriptor passing outward.** The authority MUST NOT pass the tunnel file
descriptor, the netlink/WFP/`pf` handle, or any secure-storage handle to any process, by any
mechanism (`SCM_RIGHTS`, `DuplicateHandle`, XPC, Binder). The one platform-mandated exception is the
OS itself receiving the tun descriptor it granted.

**Rule PS-22 — the management server does not link the datapath.** The management-interface server
lives in the authority process (PS-1) but MUST be a module with **no dependency edge** onto the
tunnel engine, packet-routing, or enforcement modules: it reaches them only through the same typed
operation vocabulary PS-4 defines, and it MUST NOT be reachable *from* them. One process is a
privilege domain, not an excuse for a cyclic module graph — this is what keeps a parser defect in
the management server from being a datapath defect. The check is a build-time dependency-graph
assertion and is clause B of [ADR-0017](ADR-0017-local-management-interface.md)'s **P17**.

**Rule PS-6 — restore before mutate.** Every mutation in O5 and O10, and every interface-metric or
forwarding change, MUST have its prior value written verbatim and flushed to **S-34** (resolver) or
**S-41** (everything else) *before* the mutation, readable by `twinvpn-unblock` and by the
uninstaller with the authority absent. This mirrors [ADR-0011](ADR-0011-dns-handling.md)'s S-34
deliberately, because the failure it prevents is the same one.

### 11.4 What a compromised unprivileged process can and cannot do

The adversary is [docs/threat-model.md](../threat-model.md) **AD-12** at "same user, not agent
privilege", holding full code execution inside our own UI or CLI process.

| Capability | HC-1 Linux / Windows / macOS | iOS / iPadOS | Android | OpenWrt (HC-3, `privilege_separated=false`) |
|---|---|---|---|---|
| Read connection state, peers, diagnostics summary | **Yes** (`OBSERVE` is granted) | Yes | Yes | Yes |
| Connect / disconnect / change routing mode | **Yes if the principal holds `OPERATE`** — this is a real grant, see below | Yes | Yes | Yes |
| Disarm enforcement | **No** — requires O12's per-action OS authentication, which the compromised process cannot forge; a forged attempt is `POLICY.KILLSWITCH.DISARM_REFUSED_REMOTE` / `PLATFORM.PRIV.ADMIN_AUTH_FAILED` | No — OS-owned (profile removal is a Settings act) | No — OS-owned (Settings/DPC) | **Yes** |
| Obtain the tun/utun/WinTun descriptor | **No** (PS-5) | No — OS-enforced | No — OS-enforced | **Yes** |
| Write nftables / WFP / `pf` directly | **No** — lacks `CAP_NET_ADMIN` / SYSTEM / root | No — no host firewall exists | No — not root | **Yes** |
| Change routes or resolver configuration | **No** | No | No | **Yes** |
| Use `DeviceKey` as a signing oracle | **No** — the keystore ACL binds use to the authority | **Yes** — shared keychain access group; **declared residual** | **Yes** — same UID; **declared residual** | **Yes** |
| Export `DeviceKey` private material | **No** — non-exportable by construction ([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3) | No | No where `hardware_backed=true` | **Yes** — file-backed ([ADR-0007](ADR-0007-device-identity-and-pairing.md), `hardware_backed=false`) |
| Place bytes on a KS-9-registered socket | **No** — PS-2 keeps the sockets inside the authority, and KS-10 forbids any proxy/injection interface | No — provider sockets are the extension's | No — `:tunnel`'s sockets | **Yes** (it *is* the authority) |
| Inject code into the authority | **No** — Q10 + §11.9 hardening; attempt is `PLATFORM.PRIV.HELPER_UNTRUSTED` | No — OS-enforced | No — OS-enforced | **Yes** |
| Replace the authority binary or the boot artifact | **No** — both are root/SYSTEM-owned and signature-verified at start | No | No | **Yes** |
| Deny service (spam operations, exhaust the socket) | **Yes** — bounded by rate limits (a requirement on [ADR-0017](ADR-0017-local-management-interface.md)) | Yes | Yes | Yes |

**The `OPERATE` grant is real and is stated, not hidden.** A compromised UI at a principal holding
`OPERATE` can disconnect the tunnel. It **cannot** cause traffic to leave unprotected, because
disconnecting with enforcement armed produces `BLOCKED`
([docs/reliability.md](../reliability.md) T32 leaves fail-closed only via
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.10's local-authority action, and that
action is `ADMINISTER`). The worst outcome of a compromised unprivileged
process on HC-1 is therefore **denial of service, visibly**, which is the correct direction.

**Reconciliation with [docs/threat-model.md](../threat-model.md) §3 — this ADR adds a boundary that
document treats coarsely, and says so.** Two refinements are required there (neither is a
contradiction):

1. **Add TB-13 — authority ↔ its own unprivileged clients.** *What crosses:* typed management
   requests and an event stream. *Authenticated by:* OS-mediated peer credentials (`SO_PEERCRED` /
   `getpeereid`, `GetNamedPipeClientProcessId` + token query, XPC `audit_token_t`, Binder UID) plus,
   for `ADMINISTER`, per-action OS authentication. *Confidential to:* the local host. *What the far
   side learns when behaving correctly:* everything in the `OBSERVE` class — peer list, states,
   reason codes, endpoints — which is a real disclosure to any local user granted `OBSERVE` and is
   why §11.7 makes that grant a decision rather than a default of "everyone".
2. **Split AD-12.** The current two tiers ("same user, not agent privilege" / "agent privilege")
   should become three: **AD-12a** hostile local process at *no* TwinVPN authorization; **AD-12b**
   hostile code inside our own unprivileged client, holding whatever class its principal holds —
   the tier this ADR creates; **AD-12c** agent privilege, unchanged and undefended (N4).

### 11.5 The I3 durability rule, per platform

[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.5 (bootstrap), §11.6 (durability and
enforcement point) and §11.8 (KS-19 boot race) are **binding and are not re-decided here**. This
section answers only the question those sections leave open: *which process*.

| Platform | Who installs the runtime rule set | Who owns it after installation | Installing process dies | OS boot, before the authority starts |
|---|---|---|---|---|
| Linux | `twinvpnd` (O3) | **The kernel.** nftables table `inet twinvpn`, owner-tagged | Rules persist unchanged; `PLATFORM.PROCESS_CRASHED`; supervisor restarts and **reclaims** the owner-tagged table (KS-20) rather than recreating it | `twinvpn-killswitch.service`, `Before=network-pre.target`, applies the package-owned `.nft` file. The deny predates the first packet the host can emit |
| Windows | `TwinVPNService` (O3) | **BFE.** Filters are kernel objects; the full policy set is `PERSISTENT` so it survives service stop | Filters persist; service restarts, re-opens the engine, reconciles against `ruleset_digest` | Installer-written `BOOTTIME` coarse deny + `PERSISTENT` full policy, both reinstated by BFE with no process of ours running |
| macOS | `com.twinvpn.sysext` (O3) | **The kernel** (`pf` anchor `twinvpn`) + NE settings | Anchor persists; NE restarts the provider on-demand; `ksd` re-applies the anchor if it was removed | `com.twinvpn.ksd`, `RunAtLoad=true`, applies `/etc/twinvpn/pf.anchor` referenced from `/etc/pf.conf`. **This is why `ksd` exists as a second privileged component**: a sysext can be deactivated by the user, and the boot artifact must not be able to be |
| iOS / iPadOS | Extension, via `includeAllNetworks` | **The OS** | The system restarts the provider per on-demand rules | **None.** ADR-0012 emits `POLICY.KILLSWITCH.BOOT_ENFORCEMENT_UNAVAILABLE`; **P09** measures the attach-to-arm window |
| Android | `:tunnel`, via the route claim; lockdown by the OS | **The OS** | Lockdown persists across process death; the route claim does not, which is why lockdown is the load-bearing half | OS lockdown, enforced from boot |
| OpenWrt | `twinvpnd` (O3) | **The kernel** (`fw4` table) | Rules persist; `procd` respawns and reclaims | init script ordered before `network`, applying the UCI-included table |

**Rule PS-7 — the boot artifact is package-owned, not authority-authored.** The KS-19 artifact
(unit, `LaunchDaemon`, persistent WFP set, init script, and the rule file each applies) is installed
by the package and is modified only by an **atomic replace** performed under `ADMINISTER` authority.
The authority MUST NOT rewrite it as an ordinary runtime action, and MUST NOT be a prerequisite for
it to apply. Its absence at start is `PLATFORM.SERVICE.BOOT_ARTIFACT_UNREGISTERED` at `CRITICAL`.

**Amendment PS-7a — "verified" in the start ordering means *reported*, not *required*.** The start
ordering below reads "(1) the boot artifact's presence is verified (PS-7)", and an implementer can
read `verified` as a gate. All three wave-2 desktop shells read it the other way, independently,
and they are right.

**Normatively: a missing boot artifact MUST NOT prevent the authority from starting.** It is
`PLATFORM.SERVICE.BOOT_ARTIFACT_UNREGISTERED` at `CRITICAL`, and the authority continues. The
reasoning is PS-7's own: the artifact is package-owned precisely so that it applies without the
authority, and refusing to start on its absence would leave the host with **neither** the boot rule
set **nor** a running agent — strictly worse than the state the rule exists to protect against, and
a direct collision with KS-20's "blocked must not mean bricked".

This does not weaken step (2). Reclaiming or re-asserting the owner-tagged rule set **is** a gate,
and it is the step that must read back from the kernel rather than trust that an install call
returned success.

**Rule PS-8 — reclamation is privilege-gated.** [docs/networking.md](../networking.md) §5.5.3
requires owner-tagged state to be reclaimable "by a fresh process after an unclean exit" but does not
say by which. Normatively: only a process that (a) holds the authority's privilege and (b) passes the
platform's code-signature/ownership validation for the installed authority binary may reclaim
owner-tagged TwinVPN state. A reclamation attempt failing (b) is `PLATFORM.PRIV.HELPER_UNTRUSTED`.

**The two named failure modes.**

| Mode | What happens | What MUST NOT happen | Signal |
|---|---|---|---|
| **F-1 — authority alive, every UI gone** (user logged out, tray killed, OOM-killer took the UI, fast user switch) | Nothing changes. Enforcement, `session_intent`, tunnels, keepalives, migration and relay failover all continue. This is the mode R-25 exists for | Enforcement relaxing; `session_intent` clearing; a `Session` transitioning; the authority exiting because its client count reached zero | `PLATFORM.SERVICE.UI_DETACHED`, `INFO` |
| **F-2 — UI alive, authority gone** (crash, quarantine, not installed, refused to start) | The rule set is still in the kernel and still denying, because it is not the authority's to lose. The UI renders `UNKNOWN`, never `PROTECTED` ([ADR-0015](ADR-0015-observability-and-diagnostics.md) O-18: the last `ProtectionAssertion` ages out) | The UI attempting any privileged operation itself; the UI rendering the last known good state as current; a "repair" action that removes the rule set to restore connectivity | `PLATFORM.SERVICE.UNAVAILABLE` or `.NOT_INSTALLED` or `.QUARANTINED`, each with its own next action |
| **F-3 — both gone** | Kernel/OS rules hold; on next boot the KS-19 artifact re-applies them independently | Any path that requires a running process to keep the host protected | ADR-0012's `POLICY.KILLSWITCH.ENGAGED` stands |

### 11.6 Service lifecycle, supervision, and crash-loop containment

| Platform | Supervisor and restart policy | Crash-loop containment | Boot-blocking guard |
|---|---|---|---|
| **Linux** | `systemd`: `Restart=always`, `RestartSec=1s`, `StartLimitIntervalSec=300`, `StartLimitBurst=5` | `StartLimitAction=none` (**never** `reboot`), `OnFailure=twinvpn-quarantine.service` | The authority unit is `WantedBy=multi-user.target` and is **not** `Before=` anything on the boot path; the KS-19 unit is separate, `oneshot`, `TimeoutStartSec=15s`, `FailureAction=none` |
| **Windows** | SCM recovery: restart at 1 s, restart at 5 s, then *run a command* (the quarantine action); `ResetPeriod=86400` | Third failure inside the reset period enters quarantine | The service is `SERVICE_AUTO_START`, **not delayed** ([ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) **LC-12**); it is never a boot-critical service, and the persistent WFP set does not depend on it. *Amended by the wave-2 integration lead: this cell previously read "with delayed start", which contradicts LC-12 — the rule that owns the question and reasons it out (delayed start defers the service by ~2 minutes after boot). ADR-0022 owns lifecycle, LC-12 is the reasoned rule and this was an unreasoned aside, so LC-12 wins. `desktop-windows` followed LC-12 and recorded the conflict in its `.wxs`.* |
| **macOS** | `launchd` for `ksd`: `KeepAlive={SuccessfulExit:false}`, subject to launchd's 10 s throttle. The sysext is restarted by NE/`systemextensionsd` on-demand | launchd has no burst limit, so the authority maintains its **own** durable restart counter (**S-40**) and latches quarantine itself | `ksd` is tiny, has no network dependency, and is the only component on the boot path |
| **iOS / iPadOS** | The OS, via on-demand rules. Restart cadence is not ours to set | Not controllable. A repeatedly-crashing provider is throttled by the OS. We count crashes durably and report | n/a |
| **Android** | The OS: always-on restarts the service; a user-initiated foreground service is restarted per `START_STICKY` | Not controllable; counted durably and reported | n/a |
| **OpenWrt** | `procd`: `procd_set_param respawn 300 5 5` (threshold 300 s, timeout 5 s, retry 5) | `procd` stops respawning after the retry count; the init script then runs the quarantine action | The init script is `START=` after `network`'s firewall include, and never blocks `procd` boot |

**Rule PS-9 — quarantine keeps protection and keeps a way out.** On entering quarantine the host
MUST be left in this exact state, and the state is normative:

1. The enforcement rule set stays installed and unmodified. Quarantine MUST NOT disarm, MUST NOT
   clear the M2 latch, and MUST NOT swap `RULESET_BLOCKED` for anything.
2. The authority stops being restarted in its full form. A minimal supervised stub — no datapath, no
   keys, no network sockets — keeps the management interface answering with
   `PLATFORM.SERVICE.QUARANTINED` so the UI can explain the state rather than showing nothing.
3. `twinvpn-unblock` remains installed and functional (O13). This is what keeps "blocked" from
   becoming "bricked" ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §10, KS-20).
4. Leaving quarantine requires an `ADMINISTER`-class action or a reboot; it MUST NOT clear itself on
   a timer, because a timer converts a persistent defect into an intermittent one.

**Rule PS-10 — detection and containment are different codes.**
`PLATFORM.CRASH_LOOP` ([docs/architecture.md](../architecture.md) §2.5.1) is the **detection**: N
crashes in a window. `PLATFORM.SERVICE.QUARANTINED` is the **containment action** this ADR adds.
Both are emitted; neither replaces the other. `PLATFORM.PROCESS_CRASHED` and
`PLATFORM.PROCESS_RESTARTED` are consumed unchanged.

**Rule PS-11 — an unsupervised authority does not claim supervised guarantees.** If the authority
starts without a recognised supervisor (run by hand, run in a container with PID 1 that does not
restart it, launched from a shell for debugging), it MUST emit
`PLATFORM.SERVICE.SUPERVISOR_ABSENT` at `WARN` and MUST NOT report a supervision posture it does not
have. R-25's guarantee is a property of the supervisor, not of the binary.

**Start ordering, normatively.** The authority reaches `ready` only after: (1) the boot artifact's
presence is verified (PS-7); (2) the owner-tagged rule set is reclaimed or re-asserted (KS-20,
PS-8); (3) privilege drop has succeeded (`PLATFORM.PRIV.DROP_FAILED` otherwise); (4) durable state is
rehydrated ([docs/reliability.md](../reliability.md) §6.5); (5) the capability probe of
[docs/architecture.md](../architecture.md) §2.5 has run. Only then does it accept management
connections. A start that exceeds its budget is `PLATFORM.SERVICE.START_TIMEOUT` and the supervisor
treats it as a failed start, not as a hung success.

### 11.7 Multi-user, sessions, and local control authority

**Rule PS-12 — one authority, three authorization classes.** There is one authority per host, not one
per user (Q1, I8). Every management operation is classified:

| Class | Contains | Default grant on HC-1 | Authentication |
|---|---|---|---|
| `OBSERVE` | Read state, peers, paths, reason codes, quality, enforcement posture, diagnostics summary | Members of the dedicated `OBSERVE` group of PS-12a, per the install profile — **never** a built-in everyone-group | Peer-credential check only |
| `OPERATE` | Connect, disconnect, set routing mode, accept/reject an offered `Route`, request a portal exemption, trigger a diagnostic bundle, force a path re-probe | Members of the **operator set** (below) | Peer-credential check only — **no prompt**, because this class is on the R-06 unattended-recovery path |
| `ADMINISTER` | Disarm or change enforcement mode (KS-21), pair, revoke, rotate keys, change the host profile or the operator set, change the boot artifact, uninstall | **Nobody by default** | **Per action**, OS-mediated: `polkit` `auth_admin` (not `auth_admin_keep`), UAC elevation + client-token Administrators check, Authorization Services `system.privilege.admin` |

**The operator set, decided.** It is seeded at install according to the **install profile**, which is
itself an `ADMINISTER`-class setting recorded in **S-39**:

| Profile | Operator set | Chosen for |
|---|---|---|
| `SINGLE_OWNER` (default on laptops/desktops) | The enrolling user, plus local administrators | The [docs/vision.md](../vision.md) §2 personas: one `Owner`, one machine |
| `SHARED_HOST` | Local administrators only | Family/shared machines, kiosks, lab hosts — where one user disconnecting affects everyone |
| `MANAGED` | Local administrators only, and the operator set is not editable locally | MDM/DPC-managed fleets |

**Rule PS-12a — the named OS principals, owned here.** The classes above are derived from OS
principals at attach time. This ADR **owns the definition** of those principals; **[ADR-0021](ADR-0021-packaging-distribution-and-updates.md)**
owns creating them at install and removing them at uninstall (PS-21 step 7), and
**[ADR-0017](ADR-0017-local-management-interface.md)** owns deriving a scope set from them.

| Platform | `OBSERVE` principal | `OPERATE` principal | `ADMINISTER` principal |
|---|---|---|---|
| Linux | local group `twinvpn` | local group `twinvpn-operators` | `polkit` action `net.twinvpn.administer`, `auth_admin` |
| Windows | local group `TwinVPN Users` | local group `TwinVPN Operators` | `BUILTIN\Administrators` in the client's **elevated** token, verified by impersonation |
| macOS | group `_twinvpn` | group `_twinvpn_op` | Authorization Services right `system.privilege.admin` |
| OpenWrt / headless | `root` (no second identity exists — §11.10) | `root` | §11.7's headless rule (PS-14) |
| iOS / iPadOS / Android | The app itself; there is no second local principal | same | The OS's own Settings/profile surface — not ours |

The daemon MUST NOT accept a self-asserted principal: membership is read from the OS using the
credentials the transport attests (§11.14(a)), never from a field the client supplies. Built-in
`Users`/`staff`-style groups are deliberately **not** used for `OBSERVE`, because "every local
account can enumerate this device's peers and endpoints" should be an install-time decision
(TB-13), not a platform default.

**Scope-to-class mapping (normative for [ADR-0017](ADR-0017-local-management-interface.md)).** Status,
event-stream attach, and diagnostics reads are `OBSERVE`; connect/disconnect, routing mode, `Route`
acceptance, portal-exemption request, path re-probe, and diagnostic-bundle generation are `OPERATE`;
enrolment, pairing, revocation, key rotation, enforcement-mode change, operator-set or host-profile
change, boot-artifact change, and uninstall are `ADMINISTER`. Where a single named scope spans two
classes — "policy" is the common case, since accepting an offered `Route` differs from authoring an
`AccessPolicy` — it MUST be split, and the higher class governs the ambiguous member. A scope that
cannot be split is `ADMINISTER`.

**Rule PS-13 — concurrent clients are served, and actions are attributed.** Several clients, across
several logged-in users and several sessions, MAY be connected at once. Every state-changing
operation carries the acting principal, and the resulting event on the shared stream carries
`actor_principal` so that user B's UI shows *who* disconnected, not merely that something did. This
is a required interface on [ADR-0017](ADR-0017-local-management-interface.md). Attribution is not optional: an unattributed state change on
a multi-user host is the "silent failure" [docs/reliability.md](../reliability.md) §10 forbids,
wearing local clothes.

**Rule PS-23 — the privileged-action record, and the three things it must cover that a management-
interface ledger cannot.** [ADR-0017](ADR-0017-local-management-interface.md) records every mutating
management call with principal, operation and outcome. That is necessary and not sufficient, because
three classes of privileged act never traverse the management interface. The authority — or, where it
is absent, the acting tool — MUST record each of them durably, with the acting principal, the session
type, and the outcome:

1. **Acts performed while the authority is not running**: the offline unblock command (O13) and any
   uninstaller step of PS-21. These occur precisely when there is no management interface to log to,
   so they append to the same durable record independently, and the authority reconciles on next start.
2. **Refusals that never reach an operation handler**: a client rejected at attach on peer credentials,
   `PLATFORM.PRIV.REMOTE_ADMIN_REFUSED`, and an OS-mediated authentication that fails or is declined.
   A refusal logged only by the caller is not a record.
3. **Acts performed by the package rather than by us**: install, update and boot-artifact replacement
   (PS-7), which change the privileged surface without any operation being invoked.

Two constraints on the record. It is subject to
[docs/threat-model.md](../threat-model.md) §9's never-loggable list without exception — a principal
name is loggable, an authentication secret never is. And per
[docs/architecture.md](../architecture.md) §2.19, the record MUST NOT be a connectivity dependency:
if it cannot be written, the privileged action is **refused** and the refusal is surfaced, never
performed unlogged.

**Fast user switching, lock screen, and logout** change nothing about the authority (F-1). The
console user's identity changes, which changes which clients hold which class; a client whose
principal loses a class MUST be told (`PLATFORM.PRIV.CLIENT_UNAUTHORIZED` on its next attempt) rather
than silently downgraded. `PLATFORM.SCREEN_LOCKED` remains informational
([docs/architecture.md](../architecture.md) §2.5.1); an `ADMINISTER` action attempted from a locked
session is handled by the OS's own authentication surface, which is what KS-21(2) delegates to.

**Rule PS-14 — the attended/headless reading of KS-21(1), which is otherwise unsatisfiable.**
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-21(1) requires "a local interactive action
on the device itself. No network path, no remote management channel." **R-21** requires headless
Linux and router targets to be first-class, and those hosts have no local interactive session ever.
This ADR resolves the conflict by host class rather than by weakening KS-21:

| Host class | Meaning of "local interactive action" | Remote session (SSH, RDP, VNC, serial-over-network) |
|---|---|---|
| **HC-1 / HC-2 (attended)** | A session on the physical console: `systemd-logind` seat `seat0`, the Windows interactive console session, the Mac's local login, the device's own screen | **Refused.** `ADMINISTER` from a non-console session emits `PLATFORM.PRIV.REMOTE_ADMIN_REFUSED`; for a disarm specifically, [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)'s `POLICY.KILLSWITCH.DISARM_REFUSED_REMOTE` fires as well |
| **HC-3 (headless)** | There is none. The host declares `admin_channel = LOCAL_TTY_OR_ADMIN_SESSION` at install (**S-38**) | **Permitted**, and only under all of: (a) the platform's own admin authentication succeeds in that session; (b) the action is recorded with the principal, the session type, and the source address; (c) `PLATFORM.PRIV.REMOTE_ADMIN_USED` is emitted at `WARN` |

**Residual exposure, stated.** On a headless host, an adversary with administrative shell access can
disarm enforcement. This grants no capability the adversary did not already have: the same access
permits rewriting the nftables table directly, which is KS-10's own argument applied one level up. The
exception is therefore a *disclosure*, not a widening. HC-3 hosts that do have a physical console
(a router's serial port, a server's IPMI-attached console) SHOULD be configured to `SINGLE_OWNER` +
console-only, and [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) owns whether that is the embedded default.

### 11.8 The gateway / server role

[docs/architecture.md](../architecture.md) §2.2: one binary is client, `ExitNode` and `LANGateway`,
and a device may be all three at once. The process model follows that literally.

| Question | Answer |
|---|---|
| Does the gateway role add a process? | **No.** One authority serves every peer. **Rule PS-15: a process (or thread pool, or namespace) per peer is forbidden** — it is I7's "one-client-at-a-time" defect class re-expressed as a process model, and it makes per-peer isolation depend on process boundaries rather than on the rules and tables [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) §11.2 specifies |
| Does it add privilege? | **One item: forwarding.** Everything else (NAT tables, policy routing, per-peer rules) is already inside `CAP_NET_ADMIN`/SYSTEM/root. Per O10, forwarding is enabled by a package-installed `sysctl.d`/UCI/interface-property change applied as an `ADMINISTER` action at role-enable time, **not** by a runtime write. This keeps `ProtectKernelTunables=yes` in §11.9 for the client and the gateway alike, and puts the change under **S-41** so uninstall restores it |
| Does it change supervision? | **Yes, in one direction.** A gateway restart interrupts N peers, so the gateway profile uses `RestartSec=1s` with no additional delay and MUST reach `ready` before accepting admissions ([ADR-0013](ADR-0013-multi-client-gateway-architecture.md) §11.9's thundering-herd rules apply on the far side). Quarantine on a gateway is *more* consequential and therefore MUST NOT be shortened: PS-9 holds unchanged, and the gateway's peers see a normal unreachable-peer condition, not a policy change |
| Does it change the authorization model? | **No.** A gateway is usually HC-3, so §11.7's headless rule governs; `OBSERVE`/`OPERATE`/`ADMINISTER` are unchanged |
| Does it change address determinism? | **No** — [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) §11.8 owns that, and it is the reason a gateway restart is survivable at all |
| Is the role a build variant? | **No.** Same binary, same package, same unit. The role is configuration in the signed contract and local state, per §2.2. **Rule PS-16: there is no "server build".** A separate server binary would fork the privilege model and the supervision contract, which is exactly what I7 and §2.2 exist to prevent |

### 11.9 Sandboxing, entitlements, and process hardening

| Platform | Normative posture | External approval required |
|---|---|---|
| **Linux** | `NoNewPrivileges=yes` · `CapabilityBoundingSet=CAP_NET_ADMIN` · `AmbientCapabilities=CAP_NET_ADMIN` · `User=twinvpn` · `ProtectSystem=strict` · `ProtectHome=yes` · `PrivateTmp=yes` · `PrivateDevices=yes` with `DeviceAllow=/dev/net/tun rw` and `DeviceAllow=/dev/tpmrm0 rw` · `ProtectKernelModules=yes` · `ProtectKernelTunables=yes` · `ProtectClock=yes` · `ProtectProc=invisible` · `ProcSubset=pid` · `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK` · `RestrictNamespaces=yes` · `RestrictRealtime=yes` · `RestrictSUIDSGID=yes` · `LockPersonality=yes` · `MemoryDenyWriteExecute=yes` · `SystemCallArchitectures=native` · `SystemCallFilter=@system-service` + `~@module @mount @reboot @swap @debug @obsolete @raw-io` · `UMask=0077` · `RuntimeDirectory`/`StateDirectory`/`ConfigurationDirectory=twinvpn` | none |
| **Windows** | Service SID `NT SERVICE\TwinVPNService`, `SERVICE_SID_TYPE_UNRESTRICTED` · `RequiredPrivileges` limited to `SeChangeNotifyPrivilege`, `SeImpersonatePrivilege` (to authorize pipe clients), `SeLoadDriverPrivilege` (WinTun), `SeAssignPrimaryTokenPrivilege` **not** required, `SeDebugPrivilege` and `SeTcbPrivilege` **forbidden** · `SetProcessMitigationPolicy`: `ProcessDynamicCodePolicy{ProhibitDynamicCode}`, `ProcessImageLoadPolicy{NoRemoteImages, NoLowMandatoryLabelImages, PreferSystem32}`, `ProcessExtensionPointDisablePolicy`, `ProcessSignaturePolicy{MicrosoftSignedOnly=0}` with our own catalog · linked `/guard:cf /CETCOMPAT /DYNAMICBASE /HIGHENTROPYVA` · pipe DACL grants connect to `Users`, and every request is authorized by impersonating the client token · state directory ACL: service SID + `BUILTIN\Administrators` only. Protected Process Light is **not** claimed (it requires ELAM signing); noted as future work | Authenticode + EV signing ([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)) |
| **macOS** | App: App Sandbox on, `com.apple.security.network.client`, `com.apple.developer.system-extension.install`. sysext: hardened runtime, library validation **on**, `disable-library-validation` / `allow-dyld-environment-variables` / `allow-unsigned-executable-memory` / `get-task-allow` all **absent** in release; `com.apple.developer.networking.networkextension = [packet-tunnel-provider-systemextension]`. `ksd`: root `LaunchDaemon`, no network entitlement, no keychain access | **A paid Developer Program team with the Network Extensions and System Extension capabilities enabled, and a Developer ID profile carrying the value** — self-service, no application to Apple (P-06 as amended 2026-09-04; this cell previously read "Apple must grant the NetworkExtension entitlement — an application with real lead time"); notarization ([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)) |
| **iOS / iPadOS** | `com.apple.developer.networking.networkextension = [packet-tunnel-provider]` · `com.apple.developer.networking.vpn.api = [allow-vpn]` · shared `keychain-access-groups` and App Group for app+extension · extension memory budgeted to the 15 MB floor (§9) | **A paid team with the Network Extensions capability enabled** — self-service (P-06 as amended 2026-09-04; previously "Apple must grant the NetworkExtension entitlement"); App Store review, which applies the VPN provisions at publication |
| **Android** | `FOREGROUND_SERVICE` · `POST_NOTIFICATIONS` (API 33+) · `RECEIVE_BOOT_COMPLETED` · `BIND_VPN_SERVICE` declared on the service (held by the system) · `android:process=":tunnel"` · `android:foregroundServiceType` **MUST** be declared on API 34+; the type is chosen against the Play policy in force at submission and is a **build-time gate**, not a runtime assumption · per-app routing uses `<queries>` rather than `QUERY_ALL_PACKAGES` wherever the target list is enumerable | **Google Play VPN-policy declaration and review** |
| **OpenWrt** | `procd` `no_new_privs` · seccomp filter where `procd-seccomp` is present · `ujail` **RECOMMENDED** where the target has ≥ 64 MB RAM and `procd-ujail`; on smaller targets the authority runs unjailed as root and §11.10 states the residual | none |

**Rule PS-17 — a hardening directive that cannot be applied is reported, not skipped.** If any
directive in this table fails to apply (an old `systemd` without `ProcSubset`, a Windows build
predating a mitigation, a router without `procd-seccomp`), the authority MUST emit
`PLATFORM.PRIV.SANDBOX_DEGRADED` at `WARN` naming the directive, and the diagnostic bundle MUST carry
the effective posture. Silently running wider than declared is the defect this rule retires.

**Rule PS-18 — entitlement absence is a startup failure, not a degradation.** A missing or unprovisioned
entitlement, capability, or permission is `PLATFORM.PRIV.CAPABILITY_MISSING` at startup, naming the
specific entitlement. The authority MUST NOT start in a mode that cannot arm enforcement while
reporting itself as running.

### 11.10 The future-compatible tier: OpenWrt, routers, headless gateways, CLI-only

| Target | Topology | Honest position |
|---|---|---|
| **OpenWrt / procd routers** | **One process, root**, `procd`-supervised, UCI config, `ubus` status, `opkg` package. No UI, no second identity, no privilege separation | `privilege_separated = false`. **This is a real and correct answer for the target, and the residual is: any code-execution defect in the authority is root on the router.** The mitigations that are actually payable are the ones in §11.9's OpenWrt row (`no_new_privs`, seccomp, `ujail` where RAM permits), plus the small attack surface of a headless build with no UI, no bundle generator, and no document renderer |
| **Headless Linux server / container** | Full HC-1 topology minus the UI: `twinvpnd` + CLI. Privilege separation is retained because it is free here | In a container the supervisor may be the orchestrator rather than `systemd`; PS-11 applies, and the container MUST supply the `CAP_NET_ADMIN` and `/dev/net/tun` the authority needs or `PLATFORM.PRIV.CAPABILITY_MISSING` fires at start |
| **CLI-only desktop** | Identical to HC-1. The CLI is simply another unprivileged client of the same contract (H3), authorized by the same class map | This is the mechanism behind **R-21**'s "same control contract as the GUI": there is one contract and the GUI has no side channel. If the CLI needed a privileged path the GUI did not have, R-21 would be false |
| **Read-only rootfs + overlay** | The authority's writable state lives on the overlay; the boot artifact and the binary live on the read-only image. **This is a security advantage**: PS-8's signature/ownership check is strengthened by an immutable image, and §11.11's uninstall degrades to "remove the overlay's TwinVPN state and revert the config", which is inherently idempotent | Stated so that [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) can build on it rather than rediscover it |
| **No secure element** | Identity custody degrades to file-backed with `hardware_backed = false` — [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3 already decides this and is **not** re-decided here. The process-model consequence is the one added here: with no privilege separation *and* a file-backed key, an unprivileged compromise on such a target is an identity compromise, and the two residuals compound rather than add | **I4 is not upheld on this tier and this ADR does not claim it is.** [docs/threat-model.md](../threat-model.md) TM-12/TM-13 and AD-10 own the analysis |

**Rule PS-19 — declared, not assumed.** Every target's `privilege_separated` value is a declared field
of **S-38**, is reported in the diagnostic bundle, and is the value **P16** tests against. A target
declaring `false` contributes a **declaration** to the release record, never a pass (§11.13).

**What is deferred, explicitly.** The UCI schema, `ubus` object layout, `opkg` packaging, the
low-memory build profile, and the router status page belong to [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) and [ADR-0021](ADR-0021-packaging-distribution-and-updates.md). This
ADR forecloses none of them; it fixes only that the embedded tier runs one supervised root process
that is the authority under PS-1 and PS-2, so that KS-9/KS-10 hold there identically to everywhere
else.

### 11.11 Install, update, and uninstall

**Rule PS-20 — uninstall is a disarm and inherits KS-21.** Removing the owner-tagged rule set through
the uninstaller and removing it through a disarm have identical effect on **I3**. Uninstall therefore
MUST require the same local authority as KS-21 (per §11.7's host-class reading), MUST emit
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)'s `POLICY.KILLSWITCH.DISARMED_BY_OWNER`, and
MUST NOT be triggerable by an update, by a management-plane instruction, or by any remote actor
(KS-23, KS-22).

**Rule PS-21 — the uninstall order is normative, and every step is idempotent
([ADR-0008](ADR-0008-idempotency.md)).** Re-running the uninstaller after an interruption at any point
MUST converge on the same end state.

```
1. authenticate ADMINISTER (PS-20)          — refuse and stop if this fails
2. stop admissions; tear down Sessions      — peers see a normal peer-gone condition
3. restore the resolver from S-34           — BEFORE the interface goes, so name resolution
                                              is never left pointing at a dead stub
4. restore every other host mutation from S-41 (forwarding, metrics, sysctl.d/UCI files)
5. atomic-swap the enforcement rule set to "no TwinVPN rules"   — the disarm proper
6. destroy the interface; remove the adapter/driver (Windows)
7. deregister the boot artifact, the service/unit/extension, and the supervisor entry
8. purge durable local state (S-38..S-41, 2.20)
9. DeviceKey: retained by default; deleted only on an explicit "remove this device's identity"
```

Steps 3 and 4 precede 5 and 6 deliberately: the only ordering that can leave a host *permanently*
broken is one that removes the interface or the rules while the host's resolver or forwarding
configuration still points at TwinVPN state. An abort anywhere leaves the host either still protected
(before step 5) or cleanly restored (after step 6); the window between them is a single atomic swap.
A failure to complete emits `PLATFORM.SERVICE.UNINSTALL_INCOMPLETE` at `ERROR` naming the step, and
`twinvpn-unblock` remains the recovery path.

**Step 9, per platform, stated because the platforms differ and the difference is user-visible:**

| Platform | What happens to `DeviceKey` on uninstall | Consequence |
|---|---|---|
| Linux / OpenWrt | Retained in the TPM / key file unless explicitly removed | Reinstall rejoins the `TwinNet` with the same `DeviceIdentity` and the same overlay addresses ([docs/networking.md](../networking.md) §2.2) |
| Windows | Retained (CNG/TPM key container) unless explicitly removed | as above |
| macOS | Retained (Secure Enclave key + keychain reference) unless explicitly removed | as above |
| iOS / iPadOS | **Removed by the OS** when the app is deleted | The device MUST re-pair. This is not a defect; it is the platform's data-protection behaviour and it is disclosed in the uninstall confirmation |
| Android | **Removed by the OS** (Keystore entries are dropped on uninstall) | as iOS |

**Update.** The authority is replaced by the platform's own mechanism ([ADR-0021](ADR-0021-packaging-distribution-and-updates.md) owns it). Two
rules bind here: KS-23 — the rule set is replaced by atomic swap, never remove-then-add, and the
latch is never cleared; and PS-7 — a change to the boot artifact is an atomic replace under
`ADMINISTER` authority. A client/authority version skew across an update is
`PLATFORM.SERVICE.VERSION_MISMATCH`, and the compatibility window for it is
[ADR-0017](ADR-0017-local-management-interface.md)'s to define under [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)'s
rules — this ADR only requires that the skew be *named* rather than producing undefined behaviour.

### 11.12 Reason codes contributed

[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 assigns the **`PLATFORM`** domain to
[docs/architecture.md](../architecture.md) §2.5. This ADR contributes two subdomains under that
ownership and requires §2.5.1's table to reference them. All codes are ≤ 3 segments, `SCREAMING_SNAKE`,
carried on the wire as strings. Codes already owned by §2.5.1 — `PLATFORM.PROCESS_CRASHED`,
`PLATFORM.PROCESS_RESTARTED`, `PLATFORM.CRASH_LOOP`, `PLATFORM.VPN_PERMISSION_DENIED`,
`PLATFORM.OS_UNSUPPORTED`, `PLATFORM.SUSPENDED`/`RESUMED`, `PLATFORM.SCREEN_LOCKED`,
`PLATFORM.INTERNAL_FAULT` — are **consumed unchanged and are not redefined here**.

| `reason_code` | class | severity | terminal | user_actionable | Meaning · user-facing text · next action |
|---|---|---|---|---|---|
| `PLATFORM.SERVICE.NOT_INSTALLED` | PERSISTENT | ERROR | no | **yes** | The host-integration service is not installed. *"TwinVPN's background service isn't installed on this computer."* Next: run the installer / repair |
| `PLATFORM.SERVICE.UNAVAILABLE` | TRANSIENT | ERROR | no | **yes** | A management client cannot reach the authority. *"TwinVPN can't reach its background service; protection status is unknown."* Next: wait for restart, then repair. The indicator is `UNKNOWN`, never `PROTECTED` (O-18) |
| `PLATFORM.SERVICE.START_TIMEOUT` | TRANSIENT | ERROR | no | no | The authority did not reach `ready` within its budget. Next: automatic supervisor retry; repeated occurrences drive `PLATFORM.CRASH_LOOP` |
| `PLATFORM.SERVICE.QUARANTINED` | PERSISTENT | CRITICAL | no | **yes** | Crash-loop containment latched (PS-9). *"TwinVPN stopped restarting after repeated failures. Your traffic is still blocked, not exposed."* Next: collect a diagnostic bundle; an administrator can clear quarantine or reboot |
| `PLATFORM.SERVICE.SUPERVISOR_ABSENT` | PERSISTENT | WARN | no | no | Started without a recognised supervisor (PS-11); automatic-restart guarantees do not hold and are not claimed |
| `PLATFORM.SERVICE.BOOT_ARTIFACT_UNREGISTERED` | PERSISTENT | CRITICAL | no | **yes** | The OS-applied boot artifact required by KS-19 is not registered with the OS. *"Boot-time protection isn't installed."* Next: repair. Distinct from [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)'s `POLICY.KILLSWITCH.ARM_FAILED`, which is about rule content |
| `PLATFORM.SERVICE.SYSEXT_NOT_APPROVED` | PERSISTENT | ERROR | no | **yes** | macOS: the system extension has not been approved by an administrator (or approval was revoked). *"macOS is waiting for you to allow TwinVPN's system extension."* Next: open System Settings and allow it. Distinct from `PLATFORM.VPN_PERMISSION_DENIED`, which is the VPN profile |
| `PLATFORM.SERVICE.VERSION_MISMATCH` | PERSISTENT | ERROR | no | **yes** | Client and authority builds are outside the supported skew window. Next: finish the update / restart |
| `PLATFORM.SERVICE.UNINSTALL_INCOMPLETE` | PERSISTENT | ERROR | no | **yes** | Uninstall stopped at a named step (PS-21). Next: re-run the uninstaller (idempotent); the offline unblock command is available |
| `PLATFORM.SERVICE.UI_DETACHED` | TRANSIENT | INFO | no | no | The last management client disconnected. Nothing changed (PS-3). This code exists so that "the UI went away" is a recorded fact rather than an absence |
| `PLATFORM.PRIV.CAPABILITY_MISSING` | FATAL | CRITICAL | **yes** | **yes** | A required privilege, capability, entitlement or permission is absent, named explicitly. *"TwinVPN doesn't have the system permission it needs (`CAP_NET_ADMIN`)."* Next: reinstall / grant the entitlement / fix the container's capability set |
| `PLATFORM.PRIV.DROP_FAILED` | FATAL | CRITICAL | **yes** | no | The authority could not drop to its declared reduced privilege set and refuses to continue as a wider principal. Every occurrence is a defect or a hostile environment |
| `PLATFORM.PRIV.SANDBOX_DEGRADED` | PERSISTENT | WARN | no | no | A hardening directive could not be applied (PS-17); names the directive and the effective posture |
| `PLATFORM.PRIV.CLIENT_UNAUTHORIZED` | POLICY | WARN | no | **yes** | A management client requested an operation outside its authorization class. *"This account can't change TwinVPN's connection on this computer."* Next: sign in as an administrator, or ask one |
| `PLATFORM.PRIV.ADMIN_AUTH_REQUIRED` | POLICY | INFO | no | **yes** | An `ADMINISTER` operation needs OS-mediated authentication; the prompt has been raised |
| `PLATFORM.PRIV.ADMIN_AUTH_FAILED` | POLICY | WARN | no | **yes** | The prompt was declined, timed out, or failed. The operation did not occur and nothing changed |
| `PLATFORM.PRIV.REMOTE_ADMIN_REFUSED` | POLICY | CRITICAL | no | **yes** | An `ADMINISTER` action was attempted from a non-console session on an attended-class host and was refused (PS-14). Always a security event. For disarm specifically, `POLICY.KILLSWITCH.DISARM_REFUSED_REMOTE` fires as well |
| `PLATFORM.PRIV.REMOTE_ADMIN_USED` | POLICY | WARN | no | no | An `ADMINISTER` action was taken from a remote administrative session on a headless-class host (PS-14), with principal, session type and source recorded. Permitted and disclosed, never silent |
| `PLATFORM.PRIV.HELPER_UNTRUSTED` | PERSISTENT | CRITICAL | no | **yes** | A component the authority was asked to load, execute, or accept reclamation from failed code-signature or ownership validation (Q10, PS-8). Next: treat as a possible local compromise; reinstall from a trusted source |

### 11.13 Proof test **P16** — privilege separation holds and the authority outlives its UI

| | |
|---|---|
| **Proves** | R-25, R-26, R-27; **I3**, **I4** (custody, where claimed), **I8** |
| **Lab scenario** | `S-PRIV-DETACH-*`, `S-PRIV-ESCALATE-*`, `S-PRIV-LOOP-*`, `S-PRIV-UNINSTALL-*` — four procedures, run per platform of [docs/testing-strategy.md](../testing-strategy.md) §3.7 |
| **Preconditions (V3)** | Enforcement armed and confirmed by a `ProtectionAssertion` for both families; `ruleset_digest` recorded; a pre-install capture of the host's resolver configuration, forwarding state and route table; the marked independent traffic generator of **P09**; the host's declared `privilege_separated` value from **S-38** |
| **Assumptions** | **A-08**, A-17, and this ADR's §11.16 register |

**Procedure A — the authority outlives every unprivileged process.** Establish a `Session` with
enforcement armed. Then, in one run: `SIGKILL`/`TerminateProcess` every TwinVPN process that is not
the authority; close every management connection; log the user out; fast-user-switch to a second
account; log back in.
**Oracle:** `ruleset_digest` is unchanged at every sampling instant; `session_intent` remains `UP`;
no `ConnectionState` transition occurs that is not attributable to the network; zero marked bytes
reach any non-overlay interface, both families; `PLATFORM.SERVICE.UI_DETACHED` is emitted exactly
once per client loss; on re-login the reattached client observes the *same* `Session`, not a new one.

**Procedure B — an unprivileged compromise cannot cross the boundary.** An adversary harness runs
with exactly the UI process's principal, session and privileges — no admin, no elevation — and
attempts, in order: (1) open the tun/utun/WinTun descriptor; (2) write the nftables table / WFP
sublayer / `pf` anchor directly; (3) read, use, or export `DeviceKey`; (4) issue every
`ADMINISTER`-class management operation without OS authentication; (5) issue a malformed and an
oversized management request; (6) place bytes on a KS-9-registered socket, by every route KS-10
enumerates as absent (proxy, SOCKS, CONNECT, port-forward, packet injection); (7) inject a library
into the authority (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `CreateRemoteThread`, ptrace/`task_for_pid`);
(8) replace the authority binary, the boot artifact, or the rule file on disk.
**Oracle:** on a target declaring `privilege_separated = true`, **all eight fail**, each with either
an OS-level denial or a named `PLATFORM.PRIV.*` code, and the authority remains healthy throughout
(no crash, no restart, no `PLATFORM.INTERNAL_FAULT`). **One success is a test failure.** On a target
declaring `false`, steps 1–3 and 6–8 are expected to succeed and the test records a **declaration**,
not a pass (PS-19).

**Procedure C — crash-loop containment.** Fault-inject six aborts within 300 s at declared injection
points, one point per run.
**Oracle:** quarantine latches at the configured burst (5); `ruleset_digest` is unchanged across the
entire loop and after quarantine; `PLATFORM.CRASH_LOOP` then `PLATFORM.SERVICE.QUARANTINED` are both
emitted; the management interface still answers with `QUARANTINED`; `twinvpn-unblock` still works; a
subsequent reboot reaches the platform's normal multi-user/login state within its baseline boot time
+ 2 s (the boot-blocking guard of §11.6); quarantine does not clear itself on any timer over a 30 min
observation.

**Procedure D — uninstall, including interrupted.** Run the real uninstaller.
**Oracle:** it refuses without `ADMINISTER` authentication; `POLICY.KILLSWITCH.DISARMED_BY_OWNER` is
emitted; after completion the host has no owner-tagged rule set, no TwinVPN adapter, no unit /
service / extension / init entry, and its resolver configuration, forwarding state and route table
are **byte-identical to the pre-install capture**; full off-tunnel reachability is restored. The
interrupted variant kills the uninstaller between each of PS-21's nine steps, once per step, and
re-runs it: every re-run converges on the same end state
([ADR-0008](ADR-0008-idempotency.md)), and at no point is the host both unprotected *and* unable to
resolve or route.

**Mutants (V2).**

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P16-1` | The authority exits when its last management client disconnects | A: the tunnel drops and, on platforms where the rule set is process-installed, the digest check has nothing to compare |
| `M-P16-2` | The management interface checks authorization at connect time only, not per action | B step 4 succeeds |
| `M-P16-3` | The tun descriptor is passed to the UI over `SCM_RIGHTS`/`DuplicateHandle` (PS-5 removed) | B step 1 succeeds |
| `M-P16-4` | Supervisor configured `Restart=always` with no burst limit | C never quarantines; the reboot boot-time budget is exceeded |
| `M-P16-5` | Uninstaller removes the rule set and the interface before restoring the resolver (PS-21 steps reordered) | D's interrupted variant leaves a host that is unprotected **and** cannot resolve — the exact R-27 defect |
| `M-P16-6` | The relay/rendezvous sockets are moved to an unprivileged helper (alternative C) | B step 6 succeeds, demonstrating that KS-10's argument is topology-dependent |

**Positive control (V4).** Every procedure is also run against a deliberately monolithic build in
which the UI and the authority are one elevated process. That build MUST **succeed** at Procedure B
steps 1–4 and MUST fail Procedure A. Without this control, "all eight attempts failed" is not
evidence that the harness can detect anything.

**Platform degradation of the oracle, stated rather than papered over.**

| Platform | Oracle | Consequence |
|---|---|---|
| Linux, Windows, macOS | Full | All four procedures assert |
| iOS / iPadOS | No privilege boundary of ours exists; Procedure B degrades to OS-enforced assertions (the app cannot obtain the extension's descriptor; keychain access-group scope is what it is) and steps 3 and 7 are **expected to succeed within the app/extension pair** — the declared residual of §11.4. Procedure C is not runnable (the OS owns restart) and degrades to a **measurement** of the OS restart interval. Procedure D reduces to app deletion | Contributes measurements and declarations, not passes, for B(3,7), C and D |
| Android | As iOS for B(3,7) (same UID) and C; Procedure A is runnable and meaningful (killing `:main` must not disturb `:tunnel`) | A and B(1,2,4,5,8) assert; the rest declare |
| OpenWrt / `privilege_separated=false` | Procedure B is expected to fail by design | Contributes a declaration; A, C and D still assert fully |

**Pass criteria.** All four procedures × all supported platforms: Procedure A green everywhere;
Procedure B green on every target declaring `privilege_separated = true` and *declared* elsewhere;
Procedure C green wherever the supervisor is ours; Procedure D green everywhere; all six mutants
fail; the positive control behaves as specified.

**Known limits.** P16 does not test an adversary already at authority privilege (**AD-12c**/N4 — out
of scope by [docs/threat-model.md](../threat-model.md) §1.2). It does not test the management wire
contract's own robustness beyond steps 4–5; that is [ADR-0017](ADR-0017-local-management-interface.md)'s **P17**. It does not test signing
or notarization; that is [ADR-0021](ADR-0021-packaging-distribution-and-updates.md)'s **P20**.

### 11.14 Interfaces required from other ADRs

| # | Required interface | Owner |
|---|---|---|
| (a) | **Peer-authenticated local transport.** The management transport MUST expose the calling process's OS credentials to the authority without the client asserting them: `SO_PEERCRED`/`getpeereid` on a unix socket, `GetNamedPipeClientProcessId` + token query on a named pipe, `audit_token_t` over XPC, Binder UID. A transport that carries a self-declared identity is unusable for §11.7 | [ADR-0017](ADR-0017-local-management-interface.md) |
| (b) | **Per-operation authorization class.** Every operation in the contract MUST carry exactly one of `OBSERVE` / `OPERATE` / `ADMINISTER`, checked **per request**, never at connect time; and `ADMINISTER` operations MUST be able to carry the result of an OS authentication performed for *that* request | [ADR-0017](ADR-0017-local-management-interface.md) |
| (c) | **Attribution and multi-client fan-out.** Every state-changing event MUST carry `actor_principal`; N concurrent clients across N users and N app instances (iPadOS) MUST be supported; rate limits MUST bound the denial-of-service surface of §11.4's last row | [ADR-0017](ADR-0017-local-management-interface.md) |
| (d) | **Reachability while degraded.** The contract MUST be answerable by the quarantine stub of PS-9 with `PLATFORM.SERVICE.QUARANTINED`, and MUST have a defined client/authority version-skew window (`PLATFORM.SERVICE.VERSION_MISMATCH`) | [ADR-0017](ADR-0017-local-management-interface.md), [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) |
| (e) | **No privileged side channel.** There MUST be exactly one local contract, and the first-party GUI MUST have no path to a privileged effect that the CLI lacks. This is what makes **R-21** true rather than aspirational | [ADR-0017](ADR-0017-local-management-interface.md) (H3) |
| (f) | **Core buildability under this topology.** The portable core MUST link into: a root system daemon; a macOS NE **system extension**; an iOS/iPadOS app extension budgeted to a 15 MB resident floor; and a statically-linked musl binary for the embedded tier. It MUST NOT require writable-executable memory (`MemoryDenyWriteExecute=yes`, macOS library validation) and MUST NOT require a user session, a desktop bus, or a login keyring to initialize | [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) (H1) |
| (g) | **Secure-storage custody bound to the authority.** The key handle MUST be openable by the authority **with no user logged in** (Linux: TPM without a session keyring; macOS: usable from a root sysext with no console user; Windows: machine-scoped CNG/TPM container) and MUST be **unopenable** by the unprivileged client on HC-1. Where the platform cannot scope below app identity (iOS, iPadOS, Android), that MUST be stated as the residual §11.4 already records | **ADR-0020**, constrained by [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3 |
| (h) | **Packaging obligations.** Signed, notarized/attested artifacts for every component named in §11.2; an elevated installer that registers the boot artifact of PS-7 and the supervisor entries of §11.6; driver co-signing and install/uninstall lifecycle for WinTun; update atomicity satisfying KS-23; and an uninstaller implementing PS-20/PS-21. Crucially: **no packaging path may remove the enforcement rule set without the `ADMINISTER` authority of PS-20** | [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) |
| (i) | **Lifecycle events reach the authority, not the UI.** Suspend/resume, network change, background/foreground, Doze and on-demand wake MUST be delivered to (or observable by) the process holding authority. A design that routes them through the app process makes F-1 a functional outage on mobile | [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md), [docs/reliability.md](../reliability.md) §11 |
| (j) | **Presentation of the degraded states.** `PLATFORM.SERVICE.UNAVAILABLE` / `.NOT_INSTALLED` / `.QUARANTINED` and the `UNKNOWN` protection indicator MUST be visually distinct from connected and from disconnected in every surface ([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.6) | [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) |
| (k) | **The embedded profile adopts HC-3.** The headless/router profile MUST adopt §11.7's headless authority rule, PS-19's declaration, and §11.10's single-process topology, or overrule them explicitly | [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) |
| (l) | **Gateway forwarding is distinguishable and peer-count-independent.** Forwarded traffic remains distinguishable from locally-originated traffic at the enforcement layer (KS-2, already required by [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.12(f)), and no gateway mechanism requires a process, namespace, or thread pool per peer (PS-15) | [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) |
| (m) | **`ProtectionAssertion` is producible by the authority alone**, with no UI process running, and ages to `UNKNOWN` when the authority is gone (O-17/O-18). This is what makes F-2 safe | [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.6 |
| (n) | **Confirmation of PS-14.** [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) is asked to confirm or overrule the attended/headless reading of KS-21(1). Silence would leave R-21 targets with an unsatisfiable rule | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) |

**Deliberately *not* required: a negotiated `Capability` for privilege posture.** `privilege_separated`
is a local property that no peer's behaviour depends on, so it is a diagnostic field
([ADR-0015](ADR-0015-observability-and-diagnostics.md)) and **MUST NOT** be added to the
[ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) capability set. Advertising it
on the wire would leak host-hardening posture to peers for no behavioural gain.

### 11.15 State ownership

New rows for [docs/architecture.md](../architecture.md) §5, continuing from S-37. All four are
`LOCAL`: they describe this host's integration with this OS, and no remote party has, or may have, an
authoritative copy.

| # | State | Authoritative writer | Replicas / caches (staleness tolerance) | Consistency class | Durability | On conflict |
|---|---|---|---|---|---|---|
| **S-38** | `ServiceInstallation` — host class (HC-1/2/3), install profile, `privilege_separated`, `admin_channel`, the identity and code-signing subject of the installed authority binary, the registered supervisor and boot-artifact entries, and the datapath driver version | **Local `Device`** — the installer under `ADMINISTER` authority; the authority itself may only *verify* it | None. The diagnostic bundle carries a redacted copy with no authority ([ADR-0015](ADR-0015-observability-and-diagnostics.md)) | `LOCAL` | Durable, outside the authority's own state directory so an authority that will not start can still be diagnosed | Local wins. A mismatch between the recorded signing subject and the running binary is `PLATFORM.PRIV.HELPER_UNTRUSTED`, never silently adopted |
| **S-39** | `LocalControlAuthority` — the operator set, the class map of §11.7, and the console/remote admin rule in force | **Local `Device` (the authority)**, written only under an `ADMINISTER`-authenticated action | None. **The control plane MUST NOT be able to write it**, for the same structural reason S-18 has no remote replica (KS-22) | `LOCAL` | Durable | Local wins always; a document, message, or update that attempts to widen it is refused and logged as a security event |
| **S-40** | `ServiceSupervisionState` — unclean-exit counter and its window, the quarantine latch, and the timestamp and reason of the last containment | **Local `Device` (the authority)**; on quarantine entry, written by the containment action before the process is left down | None | `LOCAL` | **Durable by requirement** — it must survive the crashes it counts, and must be readable by the supervisor and by `twinvpn-unblock` | Local wins. A counter that cannot be persisted degrades to "no containment", which MUST be reported as `PLATFORM.PRIV.SANDBOX_DEGRADED` rather than silently disabling PS-9 |
| **S-41** | `HostIntegrationRestorePoint` — verbatim prior values of every host setting mutated outside our own interface **other than** the resolver (which is S-34): forwarding sysctls/UCI/interface properties, interface metrics, and any package-installed tunable file, each with a `restore_token` | **Local `Device` (2.5 via the authority)** | None | `LOCAL` | **Durable, written and flushed before the mutation it protects**, readable by the uninstaller and by `twinvpn-unblock` with the authority absent (Q12, PS-6) | Local wins. A restore point whose `restore_token` does not match the installed configuration is stale ⇒ restore the platform default and emit `PLATFORM.SERVICE.UNINSTALL_INCOMPLETE`, mirroring S-34's rule deliberately |

**Rows this ADR does not create, and cites instead:** S-01 (`DeviceKey` custody — §11.3 O6/O7 only
assigns *which process* uses it), S-12, S-15, S-18 (`EnforcementRecord` — this ADR assigns the
installing and owning process, never the value), S-24, S-34 (`HostResolverRestorePoint` —
[ADR-0011](ADR-0011-dns-handling.md)), S-35.

### 11.16 Assumptions register

| # | Assumption | Depends on | If it is wrong, this changes |
|---|---|---|---|
| **P-01** | **H1** — one portable core in a memory-safe systems language behind a stable C ABI, with thin native shells, no per-platform business logic | [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) | If the core needs a managed runtime with a JIT, `MemoryDenyWriteExecute=yes`, macOS library validation, and `ProcessDynamicCodePolicy{ProhibitDynamicCode}` in §11.9 must all be relaxed, widening the authority's surface; and the 15 MB iOS extension budget in §11.2/§9 becomes very unlikely to hold |
| **P-02** | **H3** — exactly one local management contract, no privileged GUI side channel | [ADR-0017](ADR-0017-local-management-interface.md) | §11.7's class map has nothing to attach to, R-21's "same control contract as the GUI" becomes aspirational, and §11.4's "cannot disarm" row loses its enforcement point |
| **P-03** | Secure storage is openable by a root/SYSTEM process with **no user session**, and is unopenable by the unprivileged client on HC-1 | **ADR-0020**, [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3 | If the key requires a login session (a user keyring, an unlocked login keychain), the authority cannot complete a handshake before first login — I5's control-plane-free reconnect after reboot fails on HC-1, and headless HC-3 becomes unusable. If the key is readable by the unprivileged client, R-26's I4 column collapses on desktop as it already has on mobile |
| **P-04** | The installer can register the boot artifact, the supervisor entry and the driver, under a single elevation, and the uninstaller can be gated on `ADMINISTER` | [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) | PS-7, PS-20 and PS-21 lose their implementation; if the packaging system can uninstall without our authority gate, uninstall becomes a disarm reachable without KS-21 |
| **P-05** | OS lifecycle events are deliverable to the authority process, not only to the app | [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) | §11.2's mobile capability split must move responsibilities back into the extension, against the memory budget of §9 |
| **P-06** | The team enrols in the paid Apple Developer Program and enables the Network Extensions and System Extension capabilities on `com.twinvpn.app` and `com.twinvpn.app.sysext` in Certificates, Identifiers & Profiles; Developer ID profiles then carry `packet-tunnel-provider-systemextension` (macOS) and the App Store profile carries `packet-tunnel-provider` (iOS/iPadOS). *Amended 2026-09-04: previously "Apple grants the NetworkExtension entitlement for `packet-tunnel-provider-systemextension` (macOS) and `packet-tunnel-provider` (iOS/iPadOS)". Both values are self-service for a paid team (the request process ended 2016-11-10); TN3134 gates only `family-controls` and HotspotHelper; the free tier lacks the capability. No Team ID is configured in the gate as of this date (`TWINVPN_TEAM_ID` unset; the `macos-signature` job skips), so the assumption is unmet by enrolment, not by Apple.* | Apple Developer Program enrolment; [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) | macOS falls back to MX-2 or MX-3: MX-2 forfeits KS-19 boot enforcement and Q2 across logout; MX-3 forfeits NE's settings and resolver integration that [ADR-0011](ADR-0011-dns-handling.md) and [docs/networking.md](../networking.md) §5.2 assume. Either way §11.2's macOS row and [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6's macOS row must be re-derived. §14(2) is the trigger |
| **P-07** | Google Play's VPN policy continues to permit a `VpnService` app with a separate service process and a declared foreground-service type | Google; [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) | §11.2's Android row is void; the `:tunnel` split may have to collapse into one process, losing the fault-isolation benefit (never a privilege benefit — it never had one) |
| **P-08** | WinTun remains available, Microsoft-signed, and shippable in the app directory ([docs/networking.md](../networking.md) §5.3) | [docs/networking.md](../networking.md), [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) | O11 changes shape and the Windows installer's driver lifecycle must be re-derived; R-19's "no bespoke driver where the OS ships an API" argument would need a new mechanism |
| **P-09** | [ADR-0013](ADR-0013-multi-client-gateway-architecture.md)'s per-peer isolation is achieved with rules, tables and queues inside one process, never with a process per peer | [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) | PS-15 is contradicted and §11.8 must be re-derived; I7's resource model would change materially |
| **P-10** | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) accepts PS-14's host-class reading of KS-21(1) | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) | Either headless targets cannot disarm at all (bricking the R-21 tier on any policy mistake), or KS-21(1) must be rewritten. This is the sharpest open seam this ADR touches |
| **P-11** | Timers, clocks and randomness are injectable at component boundaries ([docs/architecture.md](../architecture.md) A-21) | [docs/testing-strategy.md](../testing-strategy.md) | P16 Procedure C's crash-loop window cannot be driven deterministically and degrades to a wall-clock soak |

### 11.17 Obligations discharged, and corpus defects found

**Discharged.**

| Obligation | Verdict |
|---|---|
| [docs/threat-model.md](../threat-model.md) §15 **O-11** ("the local management IPC is unspecified") | **Half discharged.** The *authorization, privilege and audit-classification* half is decided here (§11.3 PS-4/PS-5, §11.7's class map, §11.12's `PLATFORM.PRIV.*` codes). The *wire contract, framing, versioning and rate-limiting* half is [ADR-0017](ADR-0017-local-management-interface.md)'s. O-11 MUST NOT be closed until both land |
| [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) **KS-9/KS-10** | **Confirmed and made structural.** PS-1/PS-2 make the process identified by the KS-9 predicate the same process that owns the rule set, which is the premise KS-10's safety argument rests on. PS-5 and PS-4 close the "another process places bytes on a registered socket" route by construction |
| [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) **KS-19/KS-20** | **Confirmed.** PS-7 assigns the boot artifact to the package, PS-8 gates reclamation on privilege *and* signature, and §11.6 assigns the privileged unblock command its own executable |
| [docs/architecture.md](../architecture.md) **A-17** | **Confirmed.** §11.5 names, per platform, which process installs enforcement and who owns it afterwards; F-1/F-2/F-3 state what happens in each direction |
| [docs/networking.md](../networking.md) **§5.5.3** | **Confirmed and sharpened** — PS-8 answers the question §5.5.3 leaves open: *which* fresh process may reclaim |

**Defects and underspecification found in the existing corpus.** Reported, not smoothed over.

1. **[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-21(1) is unsatisfiable on the exact
   targets R-21 makes first-class.** "A local interactive action on the device itself. No network
   path, no remote management channel" cannot be performed on a headless server or an OpenWrt router.
   §11.7 PS-14 resolves it by host class and states the residual; ADR-0012 must confirm or overrule
   (§11.14(n), P-10).
2. **KS-10's safety argument is topology-dependent, and nothing in the corpus said so.** It is stated
   as a property of the exemption; it is actually a property of *which process owns the sockets*.
   Mutant `M-P16-6` exists specifically to demonstrate this.
3. **[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6's macOS row assumes a
   `LaunchDaemon`**, while [docs/networking.md](../networking.md) §5.2's macOS row assumes an
   `NEPacketTunnelProvider`. Both are correct and they are different processes; no document said how
   they relate. §11.2 and §11.5 decide it (sysext = authority, `ksd` = boot artifact + unblock).
4. **The corpus never states whether the macOS product is Developer ID or Mac App Store**, yet the
   choice silently determines whether [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6's
   macOS boot row is implementable at all. Decided here as MX-1, with §14(2) as the falsifiable
   fallback trigger.
5. **[docs/threat-model.md](../threat-model.md) §3 has no boundary for "our own unprivileged process"**
   and **AD-12**'s two tiers do not contain it. §11.4 proposes **TB-13** and the **AD-12a/b/c** split.
6. **[docs/architecture.md](../architecture.md) §2.5.1 has no code for "the agent is not installed / is
   not running / has been quarantined", as observed by a UI.** It has codes for the agent's own view of
   its crashes only. `PLATFORM.SERVICE.*` fills the gap; §2.5.1's table should reference the subdomain.
7. **Uninstall is nowhere modelled as a disarm.** [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)
   KS-23 covers updates and KS-21 covers disarm, but an uninstaller removing the owner-tagged rule set
   is a disarm by a path neither rule mentions. PS-20 closes it.
8. **Row-number hygiene.** [docs/threat-model.md](../threat-model.md) O-1 records that S-25/S-26 are
   multiply defined across ADR-0005/0007/0012. S-38…S-41 are allocated from the brief's assigned block
   and are believed collision-free, but the integrator should confirm against the renumbering O-1 asks
   for.

## 12. Why the Selected Option Won

1. **C is disqualified by [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md), not by taste.**
   Under an unprivileged-agent-plus-thin-helper design, the relay, rendezvous and peer sockets belong
   to the unprivileged agent, so KS-9(1)'s predicate would have to name an unprivileged process. KS-10's
   entire safety argument — "satisfying predicate (1) requires the privilege that also permits
   rewriting the rule set" — is then false, and the bootstrap exemption becomes reachable by any code
   running as the user. The alternative repair is to make the helper rich enough to own the sockets
   *and* the rule set, at which point the helper is the authority and C has become B with a worse
   audit story and two lifetimes. C also inherits the `SMJobBless`-class on-demand privileged-helper
   pattern, which is a well-populated local-privilege-escalation CVE class for exactly the reason
   PS-4 exists.
2. **D fails K3 and R-06 in one line each.** Nothing survives to hold the rule set, so K7's "live
   before the interface exists and after it is destroyed" is unachievable; and unattended recovery
   (R-06) becomes a `polkit`/UAC prompt on every network change, which is the behaviour that makes
   users turn VPNs off.
3. **A is not expressible on four of the ten targets** — macOS with NE, iOS, iPadOS, Android — and on
   the remaining six it puts the UI's parsing surface inside `CAP_NET_ADMIN`. R-26 exists because that
   is what shipped products did.
4. **E won where it is the only option and lost where it is not universal.** It is adopted verbatim on
   iOS, iPadOS and Android. On desktop it fails because a macOS app extension activates after login
   and can be deactivated by the user — so it cannot be the KS-19 boot artifact — and because Windows
   has no OS-hosted VPN provider to be. Adopting E on desktop would mean quietly dropping boot-window
   enforcement on two of three desktop platforms.
5. **B wins on the one property the other four cannot deliver together:** an enforcement authority
   whose lifetime is decoupled from every session (R-25, Q2, K3) *and* whose privilege the UI does not
   hold (R-26, Q3). Every other candidate gives up one of the two.
6. **MX-1 beat MX-2 on a security property, not on a distribution preference.** The Mac App Store
   sandbox forbids the `LaunchDaemon` and the `pf` anchor that
   [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6 names for macOS, so MX-2 would
   silently downgrade **K7** on a desktop platform while looking like a packaging choice. MX-3 was
   rejected because it discards the NE integration [ADR-0011](ADR-0011-dns-handling.md) and
   [docs/networking.md](../networking.md) §5.2 already depend on, and is the option most exposed to
   Apple narrowing what a non-NE daemon may do.
7. **CA-3 beat CA-2 and CA-4 by splitting the question.** CA-2's group membership is checked at login,
   not per action, which is not what KS-21(2) means by "OS-mediated authentication"; CA-4 puts an
   authentication prompt on the reconnect path and breaks R-06's ergonomics. CA-3 keeps `OPERATE`
   prompt-free and puts every protection-reducing operation behind a per-action OS prompt — the exact
   split KS-21 draws, expressed as an authorization table rather than as scattered checks.
8. **The embedded single-process answer is a decision, not a concession.** On a 64 MB router a second
   process, a second identity and an IPC contract cost real memory and flash to buy a boundary the
   target's own threat picture (no untrusted local users, no UI, no document parsing) barely uses.
   PS-19 makes the honest answer machine-readable and P16 tests the declaration rather than pretending.

## 13. Known Tradeoffs

| Tradeoff | Accepted because |
|---|---|
| B requires a management contract, its versioning, and its authorization model — real work that A and D avoid | It is the only way to get R-25 and R-26 simultaneously, and [docs/threat-model.md](../threat-model.md) O-11 already says the corpus owes this contract regardless |
| Two update artifacts (authority and client) can be out of step | Named rather than prevented: `PLATFORM.SERVICE.VERSION_MISMATCH` plus a defined skew window (§11.14(d)). A single artifact would require a single process, which is A |
| macOS ships **two** privileged components (sysext + `ksd`) | A system extension can be deactivated by the user, and the KS-19 boot artifact must not be able to be. `ksd` is deliberately tiny, network-free and key-free so that the second surface is close to nil |
| macOS is not distributable through the Mac App Store | The sandbox forfeits boot-window enforcement (§12.6). Losing a distribution channel is recoverable; shipping an undisclosed **K7** downgrade is not |
| On iOS, iPadOS and Android the app process can use `DeviceKey` as a signing oracle | The OS does not scope keystore ACLs below app identity. Declared in §11.4 as a residual and tested as a **declaration** in P16, never claimed as separation we do not have |
| The Android `:main`/`:tunnel` split is fault isolation, not privilege separation | Same UID is unavoidable for a `VpnService`. It still buys the F-1 property that matters most: killing the UI does not kill the tunnel |
| A compromised UI holding `OPERATE` can disconnect the tunnel | Disconnecting with enforcement armed produces `BLOCKED`, not egress. The failure direction is correct and visible; requiring `ADMINISTER` to disconnect would break R-06 |
| Quarantine leaves a host blocked with no working product | It is the same trade [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §13 already accepted, with the same mitigation: `twinvpn-unblock` keeps "blocked" from becoming "bricked", and PS-9(3) makes it a normative part of the quarantine state |
| The OpenWrt tier has no privilege separation and, without a secure element, no I4 either | Both residuals are declared per target (**S-38**), reported in diagnostics, and tested as declarations. Requiring separation would exclude the R-21 tier the product exists to serve |
| §11.7 adds a host profile and three authorization classes to a product whose framing is "one `Owner`" | A shared family laptop is a real deployment and CA-1 has nothing to say about it. The profile is one install-time question and an `ADMINISTER` setting thereafter |
| PS-14 permits remote administrative disarm on headless hosts | The same access already permits rewriting the rule set directly — KS-10's argument one level up. It is disclosed (`PLATFORM.PRIV.REMOTE_ADMIN_USED`), never silent |
| 19 new reason codes | Each names a distinct condition with a distinct next action, and the support question this ADR most has to answer — "the app says nothing is running" — has five genuinely different causes |

## 14. Revisit Conditions

1. **If measured p95 resident memory of the iOS/iPadOS packet-tunnel extension exceeds 12 MB (80 % of
   the 15 MB floor) in the reference build**, the §11.2 capability split is under-provisioned: move
   contract parsing, the diagnostic tail, and per-peer working state further into the app process and
   re-measure **before** adding any responsibility to the extension.
2. **If a Developer ID provisioning profile carrying `packet-tunnel-provider-systemextension` cannot
   be generated for `com.twinvpn.app.sysext`** — enrolment in the paid Developer Program refused or
   lapsed, or the capability withdrawn from Developer ID distribution — MX-1 is unavailable: fall
   back to MX-3 (keeping KS-19 via `ksd`) rather than MX-2, and reclassify the macOS row of
   [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6 explicitly rather than shipping an
   unstated gap. *Amended 2026-09-04: this trigger previously read "If Apple has not granted the
   `packet-tunnel-provider-systemextension` entitlement within 90 days of application". No
   application exists to start that clock — the capability is self-service for a paid team (P-06 as
   amended) — so the trigger could never fire, and it is re-based on the one condition that can.
   Whether the gate's two no-executor rows (`MACOS-SYSEXT-LIFECYCLE`, `IOS-NE-FAIL-CLOSED`) stay
   `required` and NOT-EXECUTED until a paid team, a Developer ID build and an MDM-enrolled Mac (or a
   private-device farm and an iOS lab seed) exist, or are deferred in `IOS-SUPERVISED-ALWAYS-ON`'s
   shape, is the wave owner's open decision in `docs/implementation/ownership.md` §12 — both options
   stand; neither is chosen here.*
3. **If `PLATFORM.SERVICE.QUARANTINED` exceeds 0.1 % of installs per month on any platform**, PS-9 is
   masking a defect rather than containing one; treat the underlying crash as a release blocker instead
   of tuning the burst limit.
4. **If `PLATFORM.PRIV.CLIENT_UNAUTHORIZED` is emitted by our own first-party UI at any non-zero rate
   outside tests**, §11.7's class map does not match the product's real flows. The class map is wrong,
   not the UI — re-derive §11.7 rather than widening a class.
5. **If `PLATFORM.PRIV.REMOTE_ADMIN_USED` exceeds 20 % of `ADMINISTER` actions on hosts declared
   attended (HC-1)**, the host class is being mis-assigned at install and PS-14's split is not landing;
   re-derive the install-time question.
6. **If measured authority cold-start to `ready` exceeds 800 ms at p95 on the reference Linux and
   Windows hardware**, recovery from `BLOCKED` after a restart is slower than §11.6's start ordering
   assumes; re-derive the ordering (in particular whether rule-set reclamation must precede state
   rehydration) before adding startup work.
7. **If any platform ships an OS-hosted VPN provider that can install a boot-persistent packet filter
   independently of a user session** — i.e. if E becomes viable on desktop — re-derive Group T for that
   platform, because E's "nothing of ours to get wrong" advantage would then come without the K7 cost.
8. **If any platform ships a supported way for a same-integrity local process to inject code into, or
   replace the binary of, a service running at the authority's privilege** (or, conversely, if ELAM/PPL
   signing becomes available to us on Windows), §11.9's hardening row for that platform is void in one
   direction or improvable in the other; re-derive it and re-run P16 Procedure B steps 7–8.
9. **If [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) selects a runtime requiring writable-executable memory**, `MemoryDenyWriteExecute`,
   macOS library validation, and `ProcessDynamicCodePolicy` must all be relaxed; §11.9 must be
   re-derived and the widened surface stated, not absorbed.
10. **If Google Play's VPN policy or Android's foreground-service-type rules change such that a separate
    `:tunnel` process or the declared service type is refused**, §11.2's Android row is void and the
    collapse to a single process must be recorded as a fault-isolation loss (never as a privilege loss,
    which it never had).
11. **If **ADR-0020** determines that the platform key handle cannot be opened without a user session on
    any HC-1 or HC-3 target**, P-03 is false: control-plane-free reconnect after reboot fails on that
    target and either the key custody or the authority's start ordering must be re-derived before ship.
12. **If P16 Procedure B records a success at steps 1–4 or 6–8 on any target declaring
    `privilege_separated = true`**, that target's declaration is false. Treat as a security incident,
    change the declaration in **S-38**, and re-derive §11.3 for the platform before shipping again.
