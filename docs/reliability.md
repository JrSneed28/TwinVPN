# TwinVPN Reliability Architecture

**Scope.** This document is the authority on TwinVPN's failure model, the canonical
`ConnectionState` machine, recovery semantics, and the availability objectives that bind
them together. It enumerates every failure mode the system must survive, specifies how each
is detected, what it costs, which state transition it causes, how the system recovers, and
what residual risk remains. It defines the twelve-state connection lifecycle that every
other TwinVPN document references but none of them redefine. It does not decide tunnel
cryptography, NAT traversal mechanics, routing, DNS, kill-switch policy, or control-plane
messaging; it consumes those as contracts from the ADRs that own them.

**Related documents**

- [ADR-0005 Relay architecture](adr/ADR-0005-relay-architecture.md) — owned here
- [ADR-0006 Relay discovery and failover](adr/ADR-0006-relay-discovery-and-failover.md) — owned here
- [ADR-0001 Tunnel protocol and cryptographic foundation](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)
- [ADR-0002 Control-plane messaging and event bus](adr/ADR-0002-control-plane-messaging-and-event-bus.md)
- [ADR-0004 NAT traversal strategy](adr/ADR-0004-nat-traversal-strategy.md)
- [ADR-0007 Device identity and pairing](adr/ADR-0007-device-identity-and-pairing.md)
- [ADR-0008 Idempotency](adr/ADR-0008-idempotency.md) · [ADR-0009 State consistency](adr/ADR-0009-state-consistency.md)
- [ADR-0010 IPv4/IPv6 routing](adr/ADR-0010-ipv4-ipv6-routing.md) · [ADR-0011 DNS handling](adr/ADR-0011-dns-handling.md)
- [ADR-0012 Kill-switch and leak prevention](adr/ADR-0012-kill-switch-and-leak-prevention.md) — **owns fail-closed policy; this document consumes it**
- [ADR-0015 Observability and diagnostics](adr/ADR-0015-observability-and-diagnostics.md)

---

## Contents

1. [Reliability principles](#1-reliability-principles)
2. [Failure model](#2-failure-model)
3. [Reason-code catalog](#3-reason-code-catalog)
4. [The canonical connection state machine](#4-the-canonical-connection-state-machine)
5. [Timers and constants](#5-timers-and-constants)
6. [Recovery semantics](#6-recovery-semantics)
7. [Path probing, migration, and degraded mode](#7-path-probing-migration-and-degraded-mode)
8. [Relay failover and multi-region failover](#8-relay-failover-and-multi-region-failover)
9. [Surviving a control-plane outage (invariant I5)](#9-surviving-a-control-plane-outage-invariant-i5)
10. [No silent failure](#10-no-silent-failure)
11. [Background and suspended operation](#11-background-and-suspended-operation)
12. [Availability objectives, SLOs, and error budgets](#12-availability-objectives-slos-and-error-budgets)

---

## 1. Reliability principles

| # | Principle | Consequence |
|---|-----------|-------------|
| R1 | **Every failure is observable.** | A failure that produces no state transition and no reason code is a defect, not a degraded mode. §10 defines the mechanism that makes this checkable. |
| R2 | **Detection is event-driven first, timer-driven second.** | Timers are the backstop for failures the OS does not report. Any failure with an available hard signal (link-down, socket error, ICMP, OS network-change notification) MUST use it; the timer path is the fallback and its latency is documented as worst case. |
| R3 | **The data plane does not depend on the control plane to keep running.** | Invariant I5. Every data-plane recovery action in §6 MUST have a control-plane-free execution path, using cached, signed, offline-verifiable state. |
| R4 | **Recovery is make-before-break wherever the old path is still alive.** | Path migration (§7) validates the new `Path` before retiring the old one. Sessions are not torn down to change paths. |
| R5 | **Degradation is bounded in time.** | No state that is not `LOCAL_DIRECT`, `WAN_DIRECT`, `RELAYED`, or `DISCONNECTED` may persist indefinitely without escalation. Every non-steady state carries a maximum dwell timer (§5). |
| R6 | **Quality violations degrade; policy violations block.** | A slow tunnel is `DEGRADED`. An unprotected packet is `BLOCKED`. These are never confused. Per invariant I3 and [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md). |
| R7 | **Failure handling is symmetric across IPv4 and IPv6.** | Every detection, probe, leak check, and recovery action exists in a v4 form and a v6 form. A recovery that restores v4 while leaving v6 dark or leaking is a failure, not a recovery. |
| R8 | **Retries are budgeted and jittered.** | No unbounded retry loop, no synchronized retry wave. §6.1–6.3. |

---

## 2. Failure model

Each failure below is specified with:

- **Detection** — the concrete mechanism.
- **Latency** — expected time from onset to detection. `hard` values are event-driven (R2); `soft` values are the timer backstop when no event is delivered.
- **Blast radius** — what stops working, and for whom.
- **Transition** — the `ConnectionState` transition it causes (§4).
- **Recovery** — the action taken.
- **Code** — the stable machine-readable reason code (§3), which is the user-visible signal required by invariant I6.
- **Residual risk** — what remains unhandled after recovery.

`P` = affected peer pair (`Session`). `D` = one `Device`. `TN` = the whole `TwinNet`.
`Rly` = one `Relay`. `Rgn` = one `RelayRegion`.

### 2.1 Infrastructure failures

| Failure | Detection | Latency | Blast radius | Transition | Recovery | Code | Residual risk |
|---|---|---|---|---|---|---|---|
| **Rendezvous service failure** | Control-plane transport error or heartbeat gap on the event bus ([ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md)) | hard <1 s (TCP/QUIC error); soft 15 s (heartbeat) | New `Session` establishment to peers with no cached `Endpoint`. Established `Session`s unaffected (I5). | none for established; `DISCOVERING → RECONNECTING` for new attempts | Fall back to: (1) cached peer `Endpoint`s + direct probe, (2) LAN discovery, (3) relay-mediated rendezvous over the cached signed relay map ([ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §relay-assisted rendezvous). Retry control plane with decorrelated jitter. | `CONTROL.UNREACHABLE` | First contact with a *never-before-connected* peer is impossible while rendezvous is down and neither peer is on the LAN. |
| **Relay server failure** | Leg `PING`/`PONG` gap on the device↔relay leg; QUIC idle/close; TCP reset; `DRAIN` deadline reached | hard <200 ms (CONNECTION_CLOSE / RST); soft `T_LEG_DEAD` = 3 missed leg `PING`s (≈6–9 s foreground, ≈30 s idle) — **not** `T_SUSPECT`/`T_DEAD`, which measure the end-to-end `Path` (§5.2) | All `RELAYED` `Session`s pinned to that `Rly`. Direct paths unaffected. | `RELAYED → MIGRATING → RELAYED` (new relay) or `→ RECONNECTING` if no standby | Cut over to the warm standby relay session (§8.1); if none, select by rendezvous hash over the surviving relay set and re-establish. | `RELAY.NONE_REACHABLE` | If the warm standby was in the same failure domain, both die together. Mitigated by the different-failure-domain standby rule (§8.1). |
| **Entire relay region failure** | ≥3 relays in the same `RelayRegion` fail within 30 s, or the region's anycast bootstrap stops answering on both v4 and v6 | 15–30 s (correlated-failure detector) | Every `Session` homed in `Rgn`. Potentially a large fraction of the fleet. | `RELAYED → MIGRATING → RELAYED` (cross-region) or `→ DEGRADED` (higher RTT) | Cross-region failover (§8.2) with rendezvous-hash spreading and per-client jittered start offset to avoid a thundering herd. Announce added latency as `RELAY.FAILOVER.CROSS_REGION`. | `RELAY.REGION.DOWN` | Cross-region relay RTT can exceed the `DEGRADED` threshold, so recovery is a working-but-worse path, not a full recovery. Users on high-latency-sensitive traffic notice. |
| **DNS failure** (public resolution of infrastructure names) | Resolver timeout / SERVFAIL for control-plane or relay hostnames, on v4 and v6 independently | 2–5 s (per-query timeout, 2 attempts) | Bootstrap only. Anything already resolved and cached is unaffected. | none (established); `DISCOVERING` stall for new work | Relay map carries **literal A and AAAA addresses alongside hostnames**, so relay reachability never depends on DNS ([ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md)). Control-plane addresses are likewise cached as literals with a signed TTL. DNS is one of three independent bootstrap channels, not the only one. | `DNS.INFRA_RESOLUTION_FAILED` | A network that blocks the cached literal IPs *and* DNS defeats bootstrap. Covered by UDP-blocking / firewall rows below. |
| **Control-plane database failure** | Control-plane API returns 5xx / unavailable; event-bus writes rejected | <1 s | All mutating control-plane operations: `Pairing`, `TwinNet` membership, `AccessPolicy`/`Route`/`DNSPolicy` changes, credential renewal, relay-map refresh. Read paths may survive on replicas. | none for established `Session`s (I5) | Client operates entirely from durable local cache. Mutations are queued client-side with idempotency keys ([ADR-0008](adr/ADR-0008-idempotency.md)) and replayed on recovery; conflicting concurrent mutations are resolved per [ADR-0009](adr/ADR-0009-state-consistency.md). | `CONTROL.STALE_POLICY_IN_USE` | Queued mutations can be stale on replay (e.g. a policy the user later changed). Idempotency + last-writer rules bound but do not eliminate surprise. There is **no credential cliff**: relay tokens are relay-renewable ([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.3) and identity rotation carries overlap windows (`T_IK_OVERLAP` / `T_TK_OVERLAP`, §5.3), so a long outage degrades *granted authority* rather than stranding the device — §9. |

### 2.2 Path and NAT failures

| Failure | Detection | Latency | Blast radius | Transition | Recovery | Code | Residual risk |
|---|---|---|---|---|---|---|---|
| **Direct P2P path failure** | Authenticated path heartbeat loss (§5); socket error; ICMP unreachable (v4) / ICMPv6 destination unreachable | hard <200 ms (ICMP/socket); soft 6 s SUSPECT, 15 s DEAD | `P` | `WAN_DIRECT → MIGRATING → RELAYED` (make-before-break) | Relay path is already warm whenever `WAN_DIRECT` was established through relay-assisted setup (§7.2), so cutover is sub-second. Continue direct re-probe in the background for upgrade. | `NET.PATH.DIRECT_LOST` | If the relay path was cold and the network is also blocking relay, the `Session` enters `RECONNECTING`. |
| **NAT mapping expiry** | Inbound packets stop while outbound still leave; keepalive ACK gap | 6 s SUSPECT (2 missed 3 s heartbeats) | `P`, and typically all `Session`s behind the same NAT simultaneously | `WAN_DIRECT → MIGRATING` (rebind) | Immediately re-bind: send from the same local port to force a new mapping, re-run path validation, and revert the keepalive interval to the last known-good rung of the §6.6 ladder. | `NAT.MAPPING_EXPIRED` | Some NATs expire mappings in under the minimum practical keepalive interval on battery-constrained devices; those devices will rebind on use rather than hold a binding (§11). |
| **Symmetric NAT** | `ConnectionCandidate` gathering observes different reflexive ports per destination ([ADR-0004](adr/ADR-0004-nat-traversal-strategy.md)) | detected during `DISCOVERING`, <2 s | `D` (all outbound direct attempts from this device to non-LAN peers) | `DISCOVERING → NEGOTIATING → CONNECTING → RELAYED` | Do not burn time on doomed hole punching: per [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md), if either side is symmetric and neither has a port-predictable or port-mapped (UPnP-IGD / NAT-PMP / PCP) path, go relay-first and keep a low-rate direct probe running for the case where the NAT changes behaviour. | `NAT.SYMMETRIC_BOTH_ENDS` | Permanently relayed for that pair unless one side gains a port mapping. This is a throughput and latency cost, not an outage. |
| **CGNAT** | Reflexive address in 100.64.0.0/10, or reflexive address not equal to any local address and no inbound reachability | during `DISCOVERING`, <2 s | `D` | as symmetric NAT | Same as symmetric NAT, plus: prefer IPv6 aggressively — CGNAT'd IPv4 subscribers very often have native, globally routable IPv6, which converts a relayed pair into `WAN_DIRECT`. This is the single highest-value CGNAT mitigation. | `NAT.CGNAT_DETECTED` | Carrier-grade NAT with no IPv6 and no port control is unfixable at the client; relay is the permanent answer. |
| **IPv4-only network** | No global IPv6 source address; no IPv6 default route | <1 s at interface enumeration | `D`, for v6 candidates | none (candidate set is v4-only) | Proceed with v4 candidates and relays reachable over v4. `TwinNet` inner IPv6 still works — inner v6 is carried inside the tunnel regardless of outer family ([ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md)). | `NET.V6_UNAVAILABLE` (informational) | None material. Inner dual-stack is preserved. |
| **IPv6-only network** | No global IPv4 address, or only link-local/APIPA | <1 s | `D`, for v4 candidates and v4-only relays | none | Relay map guarantees every `RelayRegion` has AAAA-reachable relays ([ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md)). Inner IPv4 is carried inside the tunnel. Peers behind v4-only networks are reached via relay (which is dual-stack) — this is a mandatory relay capability, not an optional one. | `NET.V4_UNAVAILABLE` (informational) | A v6-only client and a v4-only peer can never be `WAN_DIRECT`. Relay is structurally required for that pair. |
| **Dual-stack network** | Both families have global addresses and default routes | <1 s | none | none | Gather and probe both families concurrently. Path selection races v4 and v6 candidate pairs with a Happy-Eyeballs-style preference: start both, prefer v6 if it validates within `T_HE_BIAS` (250 ms) of v4, otherwise take whichever validates first. Both families are kept as live alternates for migration. | — | v6 paths that validate but perform badly (broken tunnels, PMTU black holes) are caught by §2.5 MTU and loss rows, not at selection time. |
| **NAT64 / DNS64 network** | Presence of a NAT64 prefix (RFC 7050 `ipv4only.arpa` probe, or RFC 8781 PREF64 RA option); v4 literals unreachable while v6 works | <2 s | `D` | none | Synthesize v6 candidates for v4-only peers and relays through the discovered NAT64 prefix. **Never rely on DNS64 for infrastructure literals** — the relay map's A records are synthesized locally using the learned prefix, which keeps §2.1 DNS-failure independence intact. Inner v4 traffic is unaffected. | `NET.NAT64_ACTIVE` (informational) | NAT64 adds a translation hop and can break PMTU; caught by the MTU row. Some NAT64 deployments have short UDP timeouts, requiring shorter keepalives. |
| **UDP blocking** | All UDP candidate probes fail on 443/3478/custom while TCP/443 succeeds | 3 s (parallel probe of UDP and TCP transports from `t=0`) | `D` | `CONNECTING → RELAYED` over the TCP/TLS relay transport | Relay transports are tried in parallel from the start, not in sequence after a UDP timeout: QUIC/UDP-443 and TLS/TCP-443 are raced. TCP/TLS framing carries the same opaque inner ciphertext (I1 unaffected). | `NAT.UDP_BLOCKED` | TCP-carried tunnels have worse throughput and latency characteristics; see [ADR-0005](adr/ADR-0005-relay-architecture.md) §9 for the TCP-over-TCP meltdown mitigation. |
| **Restrictive firewall / captive portal / DPI** | Handshake fails or connection is reset on every transport and port; or an HTTP interception response is observed | 3–8 s | `D` | `CONNECTING → RECONNECTING → FAILED` (if all transports exhausted) | Escalate through the transport ladder: UDP/443 → TCP/443 with real TLS and HTTP/1.1 or HTTP/3 framing (indistinguishable from a normal HTTPS session at the connection level) → configured HTTP CONNECT proxy from OS proxy settings. Detect captive portals explicitly and surface "sign in to this network" rather than a network error. | `NET.BLOCKED_BY_FIREWALL`, `NET.CAPTIVE_PORTAL` | A network that whitelists destinations cannot be traversed. TwinVPN reports this accurately instead of retrying forever. Deliberate protocol-level censorship circumvention is out of scope for Phase 1. |

### 2.3 Link and mobility failures

| Failure | Detection | Latency | Blast radius | Transition | Recovery | Code | Residual risk |
|---|---|---|---|---|---|---|---|
| **Wi-Fi loss** | OS link-state notification (`NWPathMonitor` / `ConnectivityManager` / netlink `RTM_DELADDR`+`RTM_DELLINK` / `NotifyIpInterfaceChange`) | hard <100 ms | `D` | `WAN_DIRECT|RELAYED → MIGRATING` if another interface exists, else `→ RECONNECTING` | Migrate to the alternate interface if one is up (§7.3). Otherwise hold `Session` state, enter `RECONNECTING`, and enforce fail-closed disposition per [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md). | `NET.LINK.DOWN_WIFI` | Packets in flight at the moment of loss are lost; inner TCP retransmits. |
| **Cellular loss** | OS link-state; radio-state callback | hard <100 ms; soft 6 s in tunnels where the OS reports the interface as up while the radio has no service | `D` | as Wi-Fi loss | as Wi-Fi loss | `NET.LINK.DOWN_CELLULAR` | Mobile OSes sometimes report an interface as up with no forwarding. The soft heartbeat timer is the only backstop, so worst-case detection is 15 s. |
| **Ethernet change** (cable unplug/replug, switch/VLAN change, dock change) | netlink / `NotifyIpInterfaceChange` / `SCNetworkReachability` | hard <100 ms | `D` | `→ MIGRATING` (new link, possibly new IP) or `→ RECONNECTING` | Re-enumerate interfaces, re-run LAN discovery (a new L2 segment may make a peer `LOCAL_DIRECT`), re-validate the path. Re-assert `Route` and `DNSPolicy` because docking stations and VLAN changes commonly reset them. | `NET.LINK.CHANGED_ETHERNET` | A new L2 segment may have a different MTU; PMTU is re-probed (§2.5). |
| **Wi-Fi → cellular roaming** | Wi-Fi link-down or OS "better path" notification; multipath-capable OSes deliver both | hard <100 ms; often *before* Wi-Fi fully dies | `D` | `→ MIGRATING → (previous carrier class)` | Make-before-break: while both interfaces are briefly up, validate the cellular path, then switch (§7.3). The `Session`, keys, and inner addresses survive (§6.5), so application TCP connections do not break. | `NET.PATH.ROAMED_CELLULAR` | If Wi-Fi dies abruptly with no overlap, the switch is break-before-make and costs the detection latency in lost packets. Metered-link policy may require user consent before using cellular, which is a deliberate, announced pause. |
| **Cellular → Wi-Fi roaming** | New interface with a default route becomes available | hard <500 ms (includes DHCP/RA completion) | `D` | `→ MIGRATING → (previous carrier class)` | Same make-before-break. Do **not** switch on interface-up alone: require the new path to pass validation *and* satisfy the hysteresis rule (§7.3) — Wi-Fi that is associated but not yet usable is a classic cause of the "random disconnect" this product exists to eliminate. | `NET.PATH.ROAMED_WIFI` | Captive-portal Wi-Fi looks usable to the OS and is not. Path validation (an authenticated end-to-end challenge, not a reachability check) rejects it. |
| **IP address change** (DHCP lease change, RA prefix change, privacy-address rotation, VPN-on-VPN) | `RTM_NEWADDR`/`RTM_DELADDR`, `NotifyUnicastIpAddressChange`, OS path monitor | hard <100 ms | `D` | `→ MIGRATING` | Re-bind sockets, re-gather reflexive candidates, run path validation from the new address, then commit. Peers learn the new `Endpoint` from the validated probe itself, not from the control plane — so this works with the control plane down (I5). | `NET.PATH.LOCAL_ADDR_CHANGED` | IPv6 privacy-address rotation can change the source address underneath a live path; the tunnel must accept a validated address change without treating it as a new peer. |
| **Laptop suspend / resume** | OS power notification on both sides of the transition (`IORegisterForSystemPower` / `PowerRegisterSuspendResumeNotification` / systemd-logind `PrepareForSleep`) | hard, delivered before suspend and immediately on resume | `D`, all `Session`s | on suspend: `→ RECONNECTING` (parked); on resume: `RECONNECTING → MIGRATING|CONNECTING` | On the suspend signal, proactively mark paths parked and, per [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md), keep fail-closed enforcement installed *across* the suspend so the machine cannot wake with unprotected traffic before the tunnel is back. On resume, immediately re-validate rather than waiting for a heartbeat to fail. | `PLATFORM.SUSPENDED`, `PLATFORM.RESUMED` | Suspend/resume very often coincides with a network change; the resume path assumes nothing survived and re-probes fully. Long suspends exceed the crypto rekey window and force a full handshake (§6.5). |
| **Phone lock / unlock** | OS lifecycle callback | hard | `D` | none (lock alone does not change connection state) | Lock does **not** tear down the tunnel. Locking reduces the heartbeat cadence to the background schedule (§11) but keeps the `Session`. Unlock restores foreground cadence and triggers an immediate liveness probe. | `PLATFORM.SCREEN_LOCKED` (informational) | On some devices, lock coincides with Wi-Fi power-save changes that raise loss and RTT; this manifests as `DEGRADED`, not as a disconnect. |
| **Mobile OS background suspension** | Absence of scheduler time; OS-provided expiration callbacks; wall-clock jump on next wake | detected on wake, latency = suspension duration | `D` | `→ RECONNECTING` on wake, then `MIGRATING` or `CONNECTING` | Treat every wake as "assume the world changed": re-read interfaces and addresses, re-validate paths, re-assert `Route`/`DNSPolicy`/firewall rules, then resume. Target wake-to-traffic under 300 ms on a surviving path. Full analysis in §11. | `PLATFORM.BACKGROUND_SUSPENDED` | This is the single hardest reliability problem in the product. The tunnel process can be frozen for minutes to hours with no ability to send keepalives; NAT bindings and relay sessions will be gone. §11 makes the reconnect cheap rather than pretending suspension can be prevented. |

### 2.4 Host, process, and configuration failures

| Failure | Detection | Latency | Blast radius | Transition | Recovery | Code | Residual risk |
|---|---|---|---|---|---|---|---|
| **Client crash** | Supervisor/service manager notices process exit; peers see path death | local: <1 s; peer-side: 6–15 s | `D` locally; `P` for each peer | local: on restart every `Session` resumes into `RECONNECTING` — S-12 records `Session` identity and last `ConnectionState` durably; peer-side: `→ MIGRATING`/`RECONNECTING` | The kill switch is enforced by OS-level firewall rules that **outlive the process** ([ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md)) — a crash must never open a leak window. The supervisor restarts and the client re-establishes with fresh ephemeral keys. | `PLATFORM.PROCESS_CRASHED` | Ephemeral key material is lost, so re-establishment is a full handshake and inner TCP connections do not survive. Crash-loop protection: exponential backoff on restart with a circuit breaker after 5 crashes in 10 min, reported as `PLATFORM.CRASH_LOOP`. |
| **Gateway crash** (`ExitNode` / `LANGateway`) | Peers' path heartbeats stop; gateway health beacon stops | 6–15 s | Every client `Session` using that gateway — potentially many peers (I7) | client side: `→ RECONNECTING`, then re-home to an alternate gateway if the `AccessPolicy` names one | Clients holding a gateway `Route` MUST fail closed for routes that pointed at the dead gateway rather than falling back to the local default route. Where the `TwinNet` has more than one `ExitNode` with the same policy role, clients re-home with rendezvous-hash spreading to avoid stampeding one survivor. | `POLICY.GATEWAY.UNREACHABLE` | A single-gateway `TwinNet` has no failover target; the honest outcome is `BLOCKED` (kill switch on) or an announced unprotected state (kill switch off), never a silent leak. |
| **Process restart** (upgrade, config reload, service restart) | Planned: internal signal. Unplanned: as crash. | hard | `D` | `→ RECONNECTING` (T25 exits `RECONNECTING` directly to a carrier state; there is no `RECONNECTING → CONNECTING` edge) | Planned restarts perform a graceful handover: persist `Session` metadata and the intended firewall/route/DNS state to durable local storage *before* exit, keep enforcement rules installed, and re-establish on start. Peers are told `PEER_RESTARTING` so they do not mark the path failed. | `PLATFORM.PROCESS_RESTARTED` | Same as crash for ephemeral keys. Upgrades that change `ProtocolVersion` are handled by capability negotiation ([ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md)). |
| **Stale session** (peer thinks a `Session` is alive that is not, or vice versa) | Authenticated packets arriving for an unknown `Session`; replay-window rejects; asymmetric liveness (we hear them, they do not hear us) | 6–15 s | `P` | `→ MIGRATING` or `→ RECONNECTING` | The `Session` is identified by a path-independent identifier; a peer receiving traffic for an unknown `Session` responds with an authenticated `SESSION_UNKNOWN` frame carrying `reason_code = NET.SESSION.UNKNOWN_TO_PEER` so the sender tears down immediately instead of waiting for a timer. Half-open detection is explicit: liveness requires *bidirectional* authenticated evidence within `T_DEAD`, never unidirectional. | `NET.SESSION.STALE`, `NET.SESSION.UNKNOWN_TO_PEER` | Unauthenticated `SESSION_UNKNOWN` would be a trivial DoS, so it is authenticated and rate-limited; that means a genuinely lost peer still costs the full timer. |
| **Credential rotation overrun** (an identity or tunnel key presented past its overlap window; a relay token past `exp`) | Local overlap-window check ahead of time; a peer rejects an out-of-overlap static; a relay rejects with `RELAY.TOKEN_EXPIRED` | proactive: rotation starts at a large fraction of the overlap window remaining; reactive: at next handshake or next `BIND` | `D` | `→ FAILED` with `AUTH.CRED_EXPIRED` (`PERSISTENT`; `retry_precondition` = credential renewed, or the peer has seen the rotation) | There is **no credential cliff**. A `Relay` renews a `RelayCapabilityToken` itself with no control-plane involvement while the token's epoch equals the relay's `epoch_floor` ([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.3), and identity/tunnel-key rotation carries `T_IK_OVERLAP` / `T_TK_OVERLAP` (§5.3) precisely so a peer that has not yet seen a rotation still connects. Established `Session`s are **not** torn down at any expiry boundary (I5; [ADR-0009](adr/ADR-0009-state-consistency.md) §11.5) — only new handshakes presenting a stale key are refused. | `AUTH.CRED_EXPIRED`; `AUTH.KEY_ROTATED_PEER_STALE` for the narrower case of a **peer** presenting a static past its overlap window ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §11.4); `AUTH.KEY_ROTATION_PENDING`; `RELAY.TOKEN_EXPIRED` | A device offline past `T_IK_OVERLAP` (30 d) must come online to re-sync with a rotated peer. A *control-plane* outage does not strand it; a *peer* outage spanning the whole overlap window does. §9 states exactly what survives an outage and what suspends. |
| **Virtual-interface failure** (TUN/utun/WinTun adapter removed, disabled, renamed, or hijacked) | Interface index disappears; ioctl/handle errors; periodic reconciliation of intended vs actual interface state | hard <100 ms on handle error; ≤2 s via the reconciler | `D`, all `Session`s | `→ BLOCKED` (policy: the enforcement surface is gone) | Recreate the interface with a stable, TwinVPN-owned name and a persistent device GUID/identifier so third-party software and stale drivers cannot collide with it. Until it is back with the correct addresses (v4 *and* v6) and the firewall rules re-applied, traffic stays fail-closed. | `ROUTE.IFACE_MISSING`, `ROUTE.IFACE_CONFLICT` | Antivirus/endpoint-protection products and stale filter drivers can persistently break interface creation. The honest outcome is a specific, actionable diagnostic naming the conflicting driver where the OS exposes it — not a generic error. |
| **Routing-table corruption** (third-party VPN, corporate agent, or user overwrote routes/metrics) | Continuous reconciliation of the intended `Route` set against the OS routing table, for v4 and v6 separately; plus route-change notifications | hard <200 ms (notification); ≤2 s (reconciler) | `D` | `→ BLOCKED` if the drift could send protected traffic off-tunnel; `→ DEGRADED` if the drift is non-leaking (e.g. a redundant more-specific route) | Re-assert the intended routes idempotently. If re-assertion loses a fight with another agent twice within 60 s, stop fighting, stay fail-closed, and report the conflict with the competing route's owner where identifiable. | `ROUTE.DRIFT_DETECTED`, `ROUTE.CONFLICT_UNRESOLVED` | Two VPNs both demanding the default route cannot both win. TwinVPN's contract is to be loud and safe, not to win. |
| **DNS configuration failure** (`DNSPolicy` not applied, reverted, or bypassed) | Reconciliation of intended vs actual resolver configuration; plus an active canary query that MUST be answered by the TwinVPN resolver and MUST NOT be answerable off-tunnel; run for v4 and v6 resolvers | ≤2 s (reconciler); ≤5 s (canary interval) | `D` | `→ BLOCKED` if queries could leak; `→ DEGRADED` if only `TwinNet` name resolution is affected | Re-assert per [ADR-0011](adr/ADR-0011-dns-handling.md). Block off-tunnel resolver traffic (v4 and v6, including hardcoded resolvers, DoH bootstrap addresses, and mDNS where policy requires) while the policy is not in force. | `DNS.POLICY_NOT_APPLIED`, `DNS.LEAK.QUERY_OBSERVED_OFF_TUNNEL`, `DNS.LEAK.QUERY_OBSERVED_OFF_TUNNEL` | Applications with embedded DoH/DoT resolvers can bypass system DNS. Detection is by egress blocking of known resolver endpoints plus the leak canary; a fully novel embedded resolver over HTTPS to an arbitrary host is not detectable at this layer and is documented as a known limit. |

### 2.5 Transport pathologies and quality failures

| Failure | Detection | Latency | Blast radius | Transition | Recovery | Code | Residual risk |
|---|---|---|---|---|---|---|---|
| **MTU black hole** (large packets silently dropped; PMTUD broken by ICMP filtering) | Packetization-layer PMTU discovery (RFC 8899 style): probe upward with padded authenticated probes, never rely on ICMP "packet too big" being delivered. Detect asymmetry: small packets pass, large do not. | 2–4 s from path establishment or migration | `P`, and severely — it looks like "the tunnel is connected but nothing works" | `→ DEGRADED` while converging; no state change once clamped | Clamp immediately to a safe floor (1280 bytes of inner payload, the IPv6 minimum MTU, which is also safe for v4) on every new or migrated `Path`, then probe upward. Advertise the resulting MTU to the inner interface for both v4 and v6, and clamp inner TCP MSS on both families. | `NET.MTU_BLACKHOLE_DETECTED`, `NET.MTU_CLAMPED` | Paths whose usable MTU is below the floor (rare, but seen behind stacked tunnels and some NAT64/PPPoE combinations) require inner fragmentation, with a throughput cost. |
| **High packet loss** | Per-path loss estimator over authenticated heartbeats and data sequence numbers, sampled over a sliding window | 10 s (window) | `P` | `→ DEGRADED` above threshold; `→ MIGRATING` if an alternate path is measurably better | Start alternate-path probing immediately; migrate if a candidate is better by the hysteresis margin. Loss above the `DEGRADED` threshold is reported to the user with the measured value, not hidden. | `NET.QOS.LOSS_HIGH` | Loss caused by the last-mile link affects every candidate path equally; migration cannot help and the system says so rather than churning paths. |
| **Latency** (elevated RTT) | EWMA of authenticated round-trip samples against a per-path baseline established over the first 30 s | 15 s | `P` | `→ DEGRADED` above threshold | Probe alternates; consider relay→direct upgrade or relay re-selection (§8). Cross-region relay fallback is announced as a distinct code so a user does not confuse a working-but-distant relay with a broken tunnel. | `NET.QOS.RTT_HIGH`, `RELAY.FAILOVER.CROSS_REGION` | Bufferbloat on the local uplink raises RTT under load in a way path migration cannot fix. Reported honestly with the observation that it correlates with local upload saturation. |
| **Jitter** | Standard deviation of the same RTT samples; inter-arrival variation on the heartbeat stream | 15 s | `P` | `→ DEGRADED` above threshold | Same alternate-path search. Do not attempt to smooth jitter by buffering inside the tunnel; the tunnel is a datagram carrier and adding a jitter buffer would damage every latency-sensitive inner protocol. | `NET.QOS.JITTER_HIGH` | Wi-Fi power-save and cellular scheduling produce jitter that no path choice removes. |
| **Duplicate messages** | Data plane: the tunnel's anti-replay window ([ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)). Control plane: idempotency keys ([ADR-0008](adr/ADR-0008-idempotency.md)). | immediate | `P` | none | Duplicates are dropped, counted, and only escalate to `DEGRADED` if the duplicate rate suggests a path loop or a duplicating middlebox. Control-plane operations are idempotent by construction, so replay is safe by design rather than by luck. | `NET.QOS.DUPLICATES_EXCESSIVE` | An anti-replay window that is too small under heavy reordering causes false drops; the window size is a tunnel-protocol parameter owned by [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md), and this document requires it be large enough to tolerate the reordering the same path exhibits. |
| **Reordered messages** | Sequence-gap statistics per path | 10 s | `P` | none; `→ DEGRADED` only if extreme | Tolerated: the tunnel is a datagram carrier and inner transports handle ordering. Extreme reordering (beyond the anti-replay window) is treated as loss and reported. During `MIGRATING`, reordering across two paths is expected and explicitly accounted for. | `NET.QOS.REORDERING_EXCESSIVE` | Per-packet load balancing across links upstream can exceed any practical replay window. |
| **Network partition** (both endpoints up, no path between them; or a split that separates a client from the control plane but not from relays, or vice versa) | Asymmetric reachability: relays reachable but peer is not, or peer reachable on one family and not the other | 6–15 s | `P`, or a whole network segment | `→ MIGRATING → RELAYED` if a relay bridges the partition; `→ RECONNECTING` otherwise | Relays exist precisely to bridge partitions; try relays in more than one `RelayRegion` before concluding the peer is unreachable, because a single region can be on the wrong side of the split. Distinguish "peer is offline" from "peer is unreachable from here" using the relay's view (the relay knows whether the peer has a live session with it) and report the distinction. | `NET.PARTITION_SUSPECTED`, `NET.PEER_OFFLINE` | A partition that separates the two peers from every mutually reachable relay is unrecoverable until the network heals. TwinVPN reports which side is reachable, which is the diagnostic users actually need. |
| **Relay overload** | Explicit `RELAY_STATUS{reason_code, retry_after_ms, suggested_alternatives[]}` from the relay ([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.5) carrying `RELAY.OVERLOADED` / `RELAY.FLOW_LIMIT_REACHED` / `RELAY.QUOTA_EXCEEDED`; outer-path ECN marking; measured queueing delay and drop rate on the relay leg exceeding the direct-leg baseline | ≤2 s (explicit signal); 10 s (measured) | Every `Session` on that `Rly` | **none.** Attribution is *capacity, not fault* ([ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.4): the device honours `retry_after_ms` and reselects immediately, and reselecting where a *new* allocation lands is not a `ConnectionState` transition. A live `Session` whose own measured quality then crosses §5.4 takes the ordinary T22 path to `DEGRADED` on that evidence, never on the signal alone | Load sheds at **admission**, not mid-session, and the refusal carries a usable answer rather than a bare error: the device MUST honour `retry_after_ms`, MUST try a `suggested_alternatives[]` entry before retrying the same relay, and MUST ignore any suggestion absent from the verified `RelayMap` ([ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.7 rule 3). Retries use the **infrastructure** regime (§6.1). The device additionally re-attempts a direct upgrade (§7.4) and reduces offered load if the `Session` is bulk. | `RELAY.OVERLOADED`, `RELAY.FLOW_LIMIT_REACHED`, `RELAY.QUOTA_EXCEEDED`, `RELAY.CAPACITY_REJECTED` | If every relay in reach is at capacity, sessions degrade rather than fail — which is correct, but the user experiences a slow tunnel. The `NET.QOS.*` codes make it visible instead of mysterious. |

---

## 3. Reason-code catalog

Invariant I6 requires every failure to surface a structured, actionable diagnostic. A reason
code is that structure. It is **not** an error number: it is a stable identifier that names a
condition, carries typed detail, and maps to a human explanation with a concrete next action.

### 3.1 Reason-code contract

The `reason_code` **taxonomy, namespace, required attributes, and stability rules are owned by
[ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2**. This document is a *consumer*
of that taxonomy, not a second authority on it. The `UPPER_SNAKE` identifier form and the
seventeen flat domain prefixes that earlier drafts of this section declared are **withdrawn**;
every code in §2, §4, §5 and §6 is spelled in the ADR-0015 form and, where another ADR had
already registered a code for the same condition, that ADR's spelling is adopted rather than
duplicated (§3.4).

Every reason code emitted by TwinVPN MUST satisfy all of the following.

| Property | Requirement |
|---|---|
| Identifier | `DOMAIN.CONDITION` or `DOMAIN.SUBDOMAIN.CONDITION` — uppercase, dot-separated, ASCII, ≤ 64 bytes. `SUBDOMAIN` is optional; a two-part code is equally canonical. **Two or three segments; four or more is malformed and is rejected by the registry's CI check** ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 rule 7). `DOMAIN` is the only segment with registry meaning, because forward compatibility is by `DOMAIN` prefix, and deeper nesting buys nothing while breaking prefix degradation. |
| Domain | Exactly one of `NET`, `NAT`, `RELAY`, `AUTH`, `CRYPTO`, `PROTO`, `POLICY`, `DNS`, `ROUTE`, `PLATFORM`, `RESOURCE`, `CONTROL`, `INTERNAL`. No other domain exists. A condition that appears to need a new domain is a signal to re-read ADR-0015 §11.2, not to invent one. |
| Stability | **Append-only and permanent.** A code MUST NOT be renamed, MUST NOT be re-pointed at different semantics once `ACTIVE`, and MUST NOT be reused after retirement — **ever**, including at a major `ProtocolVersion` boundary ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) O-03). Refinement is by adding codes and marking the old one `DEPRECATED` with `alias_of`. |
| `class` | `TRANSIENT` · `PERSISTENT` · `POLICY` · `FATAL`. This is the field §6 reads: the retry policy, the backoff regime, and the circuit breaker are all driven by `class`, never guessed from an error type. |
| `severity` | `INFO` · `WARN` · `ERROR` · `CRITICAL`. |
| `terminal` | Whether the code may accompany entry to `FAILED` (§4.4). |
| `user_actionable` | Whether there is something the user can do. Drives whether the UI offers a button or an explanation. |
| `summary_key` / `next_action_key` | i18n keys for the one-line explanation and the suggested next action. `next_action_key` is required when `user_actionable`. The **code is the contract; the text is not** — automation and tests MUST key on the code and MUST NOT match on rendered text. |
| `doc_anchor` | Stable documentation anchor. For codes this document originates, the anchor is a section of this document. |
| `evidence_fields` | The declared, classified fields this code may attach. Numbers a user or a support engineer needs (`measured_rtt_ms`, `threshold_ms`, `failed_relays`, `os_error`) MUST be declared evidence, never embedded in a prose string, and their redaction classification is declared with them ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) O-14). |
| `introduced_in` / `status` / `alias_of` | Registry version, `ACTIVE`/`DEPRECATED`/`RETIRED`, and the forward pointer for a deprecated code. |

**Mapping from the withdrawn `Retryability` attribute onto `class`.** Earlier drafts of this
section carried a `Retryability` field with four values. It is replaced by ADR-0015's `class`,
which the recovery machinery in §6 reads directly:

| Withdrawn `Retryability` | ADR-0015 `class` | Consequence in §6 |
|---|---|---|
| `retryable` | `TRANSIENT` | Ordinary backoff (§6.1), charged against the retry budget (§6.3) |
| `retryable-after` (carried a delay) | `TRANSIENT`, with `retry_after_ms` as a declared evidence field | Backoff floor is `max(regime delay, retry_after_ms)` |
| `non-retryable-until` (carried a named precondition) | `PERSISTENT`, with `retry_precondition` as a declared evidence field | Breaker opens **for the named precondition**, not for a duration (§6.3); T33 revives on precondition |
| *policy violation* | `POLICY` | Always → `BLOCKED` via T29; never satisfied by waiting (R6) |
| `terminal` | `FATAL` | → `FAILED`; no timer-driven retry (§4.6) |

**Two attributes this document additionally requires as declared evidence fields**, because §4.7
aggregation and the UI depend on them and ADR-0015's attribute set does not carry them:

| Evidence field | Values | Used by |
|---|---|---|
| `scope` | `session` · `device` · `relay` · `region` · `twinnet` | §4.7 worst-wins aggregation and blast-radius reporting |
| `remediation_class` | `user-action` · `wait` · `automatic` · `network-operator` · `unsupported` | Which affordance the UI offers. This is a refinement of `user_actionable`, never a contradiction of it |

### 3.2 Worked examples

These illustrate the contract in ADR-0015's attribute form; the full catalog is generated from
the failure model in §2 and is a build artifact validated by the tests specified in
[ADR-0015](adr/ADR-0015-observability-and-diagnostics.md).

```yaml
- reason_code: NAT.SYMMETRIC_BOTH_ENDS        # ADR-0004 owns NAT; adopted, not duplicated
  class: TRANSIENT                            # a NAT or network change may fix it
  severity: WARN
  terminal: false
  user_actionable: true
  summary_key: nat.symmetric_both_ends.summary
  next_action_key: nat.symmetric_both_ends.next
  doc_anchor: reliability#2-2-path-and-nat-failures
  evidence_fields: { peer: DeviceId, local_nat_class: string, peer_nat_class: string,
                     ipv6_available_local: bool, ipv6_available_peer: bool,
                     scope: session, remediation_class: network-operator }
  introduced_in: "1.0"
  status: ACTIVE
  # summary  → "Both devices are behind a network that blocks direct connections, so traffic
  #             is going through an encrypted relay. It still works, but it is slower."
  # next     → "Enabling IPv6 on either network usually restores a direct connection."

- reason_code: DNS.LEAK.QUERY_OBSERVED_OFF_TUNNEL   # ADR-0011 owns DNS; adopted
  class: POLICY
  severity: CRITICAL
  terminal: false
  user_actionable: true
  summary_key: dns.leak.query_off_tunnel.summary
  next_action_key: dns.leak.query_off_tunnel.next
  doc_anchor: reliability#2-4-host-process-and-configuration-failures
  evidence_fields: { family: "ipv4"|"ipv6", resolver: IpAddr, interface: string,
                     query_name: string, policy_id: string,
                     retry_precondition: dns_policy_reasserted,
                     scope: device, remediation_class: automatic }
  introduced_in: "1.0"
  status: ACTIVE
  # The address family is EVIDENCE, not a separate code. The withdrawn per-family spellings
  # collapse into this one code, which keeps O-09 (v4 and v6 reported co-equally) satisfiable
  # without two identifiers for one condition.

- reason_code: RELAY.REGION.DOWN              # ADR-0006 §11.13 owns it; adopted
  class: TRANSIENT
  severity: ERROR
  terminal: false
  user_actionable: false
  summary_key: relay.region.down.summary
  next_action_key: null
  doc_anchor: reliability#8-relay-failover-and-multi-region-failover
  evidence_fields: { region: RelayRegion, failed_relays: [RelayId],
                     failover_region: RelayRegion, added_rtt_ms: int, retry_after_ms: 30000,
                     scope: region, remediation_class: automatic }
  introduced_in: "1.0"
  status: ACTIVE

- reason_code: ROUTE.IFACE_CONFLICT           # ADR-0010 owns ROUTE; adopted
  class: PERSISTENT
  severity: ERROR
  terminal: false
  user_actionable: true
  summary_key: route.iface_conflict.summary
  next_action_key: route.iface_conflict.next
  doc_anchor: reliability#2-4-host-process-and-configuration-failures
  evidence_fields: { interface_name: string, conflicting_component: string|null,
                     os_error: string, retry_precondition: interface_available,
                     scope: device, remediation_class: user-action }
  introduced_in: "1.0"
  status: ACTIVE
```

A worked quality payload, showing that the threshold in the evidence is the one this document
sets in §5.4 and not a second, divergent number:

```yaml
- reason_code: NET.QOS.RTT_HIGH
  class: TRANSIENT
  severity: WARN
  evidence: { peer: DeviceId, relay: RelayId, family: "ipv6",
              measured_rtt_ms: 412, threshold_ms: 250, baseline_rtt_ms: 96,
              scope: session, remediation_class: automatic }
```

### 3.3 Prohibited patterns

| Prohibited | Why |
|---|---|
| A bare numeric code as the primary user-facing signal | Invariant I6. Numbers may accompany a code as OS-level detail; they may not replace it. |
| `UNKNOWN_ERROR` as a terminal user-visible state | Any condition reaching the user MUST have been classified. An unclassified internal fault surfaces as `INTERNAL.UNEXPECTED_STATE` with a diagnostic bundle reference and is treated as a product defect, tracked and burned down. |
| A "connected" indicator with no reason code while traffic is not flowing | This is the silent-failure defect the product exists to eliminate. §10. |
| Reusing one code for both a quality problem and a policy problem | Violates R6 and makes the fail-closed behaviour unpredictable. |
| Minting a code for a condition another ADR has already registered | Two identifiers for one condition break the "code is the contract" rule as surely as renaming one does. §3.4 lists every adoption. |
| A code outside the declared domains (sixteen as of the application-architecture workstream) | It cannot degrade by prefix at a receiver that does not know it ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 rule 5). |

### 3.4 Conversion of this document's codes to the ADR-0015 taxonomy

Every identifier below appeared in an earlier draft of this document in the withdrawn
`UPPER_SNAKE` form. **None was ever `ACTIVE` in the machine-readable registry**, so this is a
pre-registration correction and not a rename — O-03's prohibition on renaming binds from first
registration onward, and no withdrawn spelling may be registered at all.

[ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2's **"Mapping the
connection-lifecycle conditions" table is normative for this document** and supplies the
`NET.PATH.*`, `NET.SESSION.*`, `NET.QOS.*`, `NET.LINK.*`, `ROUTE.*`, `AUTH.*` and `PLATFORM.*`
targets below. Where a code is named there, or another ADR already registered the same
condition, that spelling is used unchanged — this document mints nothing that already exists.
Where the column says *this document*, the code is a **new member of a subdomain ADR-0015 has
already declared**; no new top-level domain and no new subdomain is created, and the code is
contributed to the domain owner for registration (§3.5).

| Withdrawn spelling | Registered code | Adopted from |
|---|---|---|
| `CTRL_RENDEZVOUS_UNREACHABLE` | `CONTROL.UNREACHABLE` | [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) |
| `CTRL_UNAVAILABLE` | `CONTROL.STALE_POLICY_IN_USE` | [docs/protocol.md](protocol.md) §11 / ADR-0002 |
| `RELAY_UNREACHABLE` | `RELAY.NONE_REACHABLE` | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.13 |
| `RELAY_REGION_DOWN` | `RELAY.REGION.DOWN` | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.13 |
| `RELAY_CONGESTED` | `RELAY.OVERLOADED` (carried in `RELAY_STATUS`) | [ADR-0005](adr/ADR-0005-relay-architecture.md) §11.5 |
| `RELAY_AT_CAPACITY` | `RELAY.CAPACITY_REJECTED` | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.13 |
| `RELAY_FLEET_UNREACHABLE` | `RELAY.FLEET.UNREACHABLE` | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.13 |
| `QOS_RELAY_CROSS_REGION` | `RELAY.FAILOVER.CROSS_REGION` | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.13 |
| `PATH_DIRECT_LOST` | `NET.PATH.DIRECT_LOST` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `PATH_MIGRATED` | `NET.PATH.MIGRATED` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `PATH_MIGRATION_ABORTED` | `NET.PATH.MIGRATION_ABORTED` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `PATH_MIGRATION_FAILED` | `NET.PATH.MIGRATION_FAILED` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `PATH_ROAMED_TO_CELLULAR` | `NET.PATH.ROAMED_CELLULAR` | this document, in a subdomain ADR-0015 §11.2 declares |
| `PATH_ROAMED_TO_WIFI` | `NET.PATH.ROAMED_WIFI` | this document, in a subdomain ADR-0015 §11.2 declares |
| `PATH_LOCAL_ADDR_CHANGED` | `NET.PATH.LOCAL_ADDR_CHANGED` | this document, in a subdomain ADR-0015 §11.2 declares |
| — (T20 emitted nothing) | `NET.PATH.DEAD_NO_ALTERNATE` | this document (§4.5), in a subdomain ADR-0015 §11.2 declares |
| `LINK_DOWN_WIFI` | `NET.LINK.DOWN_WIFI` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `LINK_DOWN_CELLULAR` | `NET.LINK.DOWN_CELLULAR` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `LINK_CHANGED_ETHERNET` | `NET.LINK.CHANGED_ETHERNET` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `SESS_STALE` | `NET.SESSION.STALE` | this document, in a subdomain ADR-0015 §11.2 declares |
| `SESS_UNKNOWN_TO_PEER` | `NET.SESSION.UNKNOWN_TO_PEER` | this document, in a subdomain ADR-0015 §11.2 declares |
| `SESS_NEGOTIATION_FAILED` | `NET.SESSION.NEGOTIATION_FAILED` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `SESS_RECOVERED` | `NET.SESSION.RECOVERED` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `SESS_CLOSED_BY_USER` | `NET.SESSION.CLOSED_BY_USER` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `SESS_RETRY_AFTER_PRECONDITION_MET` | `NET.SESSION.RETRY_PRECONDITION_MET` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `SESSION_UNKNOWN` (used as a code) | `NET.SESSION.UNKNOWN_TO_PEER` — `SESSION_UNKNOWN` survives only as the **frame name** | this document, in a subdomain ADR-0015 §11.2 declares |
| `QOS_LOSS_HIGH` | `NET.QOS.LOSS_HIGH` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `QOS_RTT_HIGH` | `NET.QOS.RTT_HIGH` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `QOS_JITTER_HIGH` | `NET.QOS.JITTER_HIGH` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `QOS_DUPLICATES_EXCESSIVE` | `NET.QOS.DUPLICATES_EXCESSIVE` | this document, in a subdomain ADR-0015 §11.2 declares |
| `QOS_REORDERING_EXCESSIVE` | `NET.QOS.REORDERING_EXCESSIVE` | this document, in a subdomain ADR-0015 §11.2 declares |
| `QOS_RESTORED` | `NET.QOS.RESTORED` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `QOS_DEGRADED_TIMEOUT` | `NET.QOS.DEGRADED_TIMEOUT` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| — (§5.4 had a throughput row with no code) | `NET.QOS.THROUGHPUT_LOW` | this document (§5.4), in a subdomain ADR-0015 §11.2 declares |
| `MTU_BLACKHOLE_DETECTED` | `NET.MTU_BLACKHOLE_DETECTED` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `MTU_CLAMPED` | `NET.MTU_CLAMPED` | [docs/networking.md](networking.md) / ADR-0010 |
| `PEER_OFFLINE` | `NET.PEER_OFFLINE` | [docs/networking.md](networking.md) |
| `NAT.SYMMETRIC_BOTH_SIDES` | `NAT.SYMMETRIC_BOTH_ENDS` | [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md) |
| `IFACE_MISSING` | `ROUTE.IFACE_MISSING` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 |
| `IFACE_CONFLICT` | `ROUTE.IFACE_CONFLICT` | [ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md) |
| `ROUTE_DRIFT_DETECTED` | `ROUTE.DRIFT_DETECTED` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `ROUTE_CONFLICT_UNRESOLVED` | `ROUTE.CONFLICT_UNRESOLVED` | this document, in a subdomain ADR-0015 §11.2 declares |
| `DNS.LEAK_DETECTED_V4` / `DNS.LEAK_DETECTED_V6` | `DNS.LEAK.QUERY_OBSERVED_OFF_TUNNEL`, `family` as evidence | [ADR-0011](adr/ADR-0011-dns-handling.md) |
| `HOST_SUSPENDED` | `PLATFORM.SUSPENDED` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `HOST_RESUMED` | `PLATFORM.RESUMED` | this document, in a subdomain ADR-0015 §11.2 declares |
| `HOST_SCREEN_LOCKED` | `PLATFORM.SCREEN_LOCKED` | this document, in a subdomain ADR-0015 §11.2 declares |
| `HOST_BACKGROUND_SUSPENDED` | `PLATFORM.BACKGROUND_SUSPENDED` | this document, in a subdomain ADR-0015 §11.2 declares |
| `HOST_PROCESS_CRASHED` | `PLATFORM.PROCESS_CRASHED` | this document, in a subdomain ADR-0015 §11.2 declares |
| `HOST_CRASH_LOOP` | `PLATFORM.CRASH_LOOP` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `HOST_PROCESS_RESTARTED` | `PLATFORM.PROCESS_RESTARTED` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 (mapping table) |
| `HOST_INTERNAL_FAULT` | `INTERNAL.UNEXPECTED_STATE` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 |
| `GATEWAY_UNREACHABLE` | `POLICY.GATEWAY.UNREACHABLE` | this document → [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md) |
| `CRED_EXPIRED` | `AUTH.CRED_EXPIRED` (credential lifecycle); `AUTH.KEY_ROTATED_PEER_STALE` only for the narrower peer-stale-static case | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2; [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §11.4 |
| `CRED_RENEWAL_PENDING` | `AUTH.KEY_ROTATION_PENDING` | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §11.4 |
| `PEER_UNAUTHORIZED` | `AUTH.PEER_UNTRUSTED` | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §11.4 |
| `PEER_REVOKED` | `AUTH.DEVICE_REVOKED` | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §11.4 |
| `VERSION_INCOMPATIBLE` | `PROTO.VERSION_UNSUPPORTED` | [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) |
| `AUTH_REJECTED` (used as a code in §4.3) | `AUTH.PEER_UNTRUSTED`; `EV_AUTH_REJECTED` remains the **event** name | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) |
| `POLICY_KILLSWITCH_*` | `POLICY.KILLSWITCH.*` | [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) |

`EV_*` identifiers are **events, not reason codes**, and are unaffected by this conversion. They
are internal to the state machine, never surfaced to a user, and never carried on the wire.

### 3.5 Codes this document contributes, and to whom

[ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 declares the subdomains; what
remains for this document to contribute is the **members of those subdomains that §11.2 does not
name individually**. Every one of them is a two- or three-segment code inside an already-declared
domain (rule 7), so none of them widens the taxonomy:

| Namespace | Registrar ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2 is the authority) | Members contributed here |
|---|---|---|
| `NET.PATH.*` | **This document** (ADR-0015 §11.2 assigns the connection-lifecycle subdomains here) | `NET.PATH.ROAMED_CELLULAR`, `NET.PATH.ROAMED_WIFI`, `NET.PATH.LOCAL_ADDR_CHANGED`, `NET.PATH.DEAD_NO_ALTERNATE` (§4.5 T20) |
| `NET.SESSION.*` | **This document** | `NET.SESSION.STALE`, `NET.SESSION.UNKNOWN_TO_PEER` |
| `NET.QOS.*` | **This document** | `NET.QOS.DUPLICATES_EXCESSIVE`, `NET.QOS.REORDERING_EXCESSIVE`, `NET.QOS.THROUGHPUT_LOW` (§5.4) |
| `ROUTE.*` | [ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md) | `ROUTE.CONFLICT_UNRESOLVED` |
| `PLATFORM.*` | [docs/architecture.md](architecture.md) §2.5, the Platform Network Adapter | `PLATFORM.RESUMED`, `PLATFORM.SCREEN_LOCKED`, `PLATFORM.BACKGROUND_SUSPENDED`, `PLATFORM.PROCESS_CRASHED` |
| `POLICY.GATEWAY.*` | [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md) | `POLICY.GATEWAY.UNREACHABLE` |
| `NET.LINK.*` | **This document** | `NET.LINK.DOWN_WIFI`, `NET.LINK.DOWN_CELLULAR`, `NET.LINK.CHANGED_ETHERNET` |
| `NET.*` (flat) | **This document**, for the conditions §2 and §4.5 emit that belong to no subdomain | `NET.NO_USABLE_CANDIDATES` (T04), `NET.V4_UNAVAILABLE`, `NET.V6_UNAVAILABLE`, `NET.NAT64_ACTIVE`, `NET.BLOCKED_BY_FIREWALL`, `NET.PARTITION_SUSPECTED` |
| `NAT.*`, `DNS.*` contributed from §2 | the owning ADR ([ADR-0004](adr/ADR-0004-nat-traversal-strategy.md), [ADR-0011](adr/ADR-0011-dns-handling.md)) | `NAT.MAPPING_EXPIRED`, `DNS.INFRA_RESOLUTION_FAILED`, `DNS.POLICY_NOT_APPLIED` — contributed here, registered there |

Fifteen codes in total. A contribution is a request for registration, not an act of
registration. If an owner has already registered an equivalent code, the owner's spelling wins
and this document is amended — that direction is never reversed.

**One judgement call worth naming.** `POLICY.GATEWAY.UNREACHABLE` describes a *reachability*
fact, which would ordinarily be `NET.*`; it is placed in `POLICY.GATEWAY.*` because the
actionable consequence is a policy one — a client holding a `Route` that pointed at the dead
gateway MUST fail closed rather than fall back to the local default route (§2.4), and grouping it
with ADR-0013's other gateway conditions is what makes that consequence findable. If
[ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md) prefers a `NET.GATEWAY.*` spelling,
that preference wins.

---

## 4. The canonical connection state machine

### 4.1 Scope and instantiation

The state machine is instantiated **per `Session`** — that is, once per `TrustedPeer`
relationship that the local `Device` is maintaining. A `Device` in a `TwinNet` with six peers
runs six instances. A derived `TwinNet`-scope state, using the same twelve names, is computed
by the aggregation rules in §4.7; that derived state is what the user interface shows as "the
connection".

Three orthogonal facts are tracked alongside the state and are **not** encoded as extra states:

| Fact | Values | Owner |
|---|---|---|
| **Traffic disposition** — what actually happens to user packets right now | `TUNNELED_LOCAL_DIRECT`, `TUNNELED_WAN_DIRECT`, `TUNNELED_RELAY`, `TUNNELED_DUAL` (make-before-break window), `QUEUED_BOUNDED`, `DROPPED_FAIL_CLOSED`, `DROPPED_NO_ROUTE`, `UNPROTECTED_ANNOUNCED` | Enforcement per [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md); the mapping from state to disposition is in §4.4 |
| **Enforcement mode** — is the kill switch armed | `FAIL_CLOSED` · `PERMISSIVE_ANNOUNCED` | [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) |
| **`HealthState`** — the *derived, eventually-consistent* opinion held about a `Relay` or a `Device` | `HEALTHY` · `DEGRADED` · `UNHEALTHY` · `UNKNOWN` | Relay-Selection Service for a `Relay` (S-10); the local device for a peer (S-11) |

**`HealthState` is defined here** and has exactly these four members, spelled in upper case.
They are the same four that [docs/architecture.md](architecture.md) §3.3 and
[ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.3 use, and
[docs/testing-strategy.md](testing-strategy.md) A-03 asserts. `HealthState` is **not** a
`ConnectionState`, shares only the name `DEGRADED` with one, and — decisively —
**MUST NOT gate a connection attempt**: it contributes a score delta to relay selection and
nothing more (S-10; ADR-0006 §11.3 rule 1). A device's own probe result always outranks any
reported `HealthState`. `UNKNOWN` is the value before any observation exists and after an
observation goes stale; it is never rendered as healthy.

`UNPROTECTED_ANNOUNCED` exists only when enforcement mode is `PERMISSIVE_ANNOUNCED` — that
is, the user has explicitly disabled the kill switch. Even then it is announced with a
persistent `POLICY.KILLSWITCH.UNPROTECTED_FALLBACK` indication. There is no configuration in which
protected traffic silently leaves the device untunneled (I3).

Two states carry a parameter, written in braces where precision matters. They are still the
canonical single state name:

- `DEGRADED{carrier}` — `carrier` ∈ {`LOCAL_DIRECT`, `WAN_DIRECT`, `RELAYED`} is the path class
  actually carrying traffic while a quality objective is violated.
- `MIGRATING{from → to}` — the outgoing and incoming path classes.

### 4.2 State diagram

```text
                                  ┌───────────────────────────────────────────────┐
                                  │                                               │
                                  ▼                                               │
                          ┌───────────────┐  EV_CONNECT_REQUESTED   ┌──────────────────────┐
              ┌──────────►│ DISCONNECTED  │────────────────────────►│     DISCOVERING      │
              │           └───────────────┘                         │ gather candidates    │
              │                   ▲                                 │ v4 + v6, local/srflx/ │
              │                   │ EV_DISCONNECT_REQUESTED         │ relay-allocated      │
              │                   │ (from any state)                └───────────┬──────────┘
              │                   │                                  EV_CANDIDATES_READY
              │                   │                                             │
              │                   │                                             ▼
              │                   │                                 ┌──────────────────────┐
              │                   │                                 │     NEGOTIATING      │
              │                   │                                 │ version + capability │
              │                   │                                 │ + candidate exchange │
              │                   │                                 └───────────┬──────────┘
              │                   │                                  EV_NEGOTIATION_OK
              │                   │                                             │
              │                   │                                             ▼
              │                   │                                 ┌──────────────────────┐
              │                   │            EV_HANDSHAKE_FAIL    │      CONNECTING      │
              │                   │        ┌────────────────────────┤ race candidate pairs │
              │                   │        │                        │ + tunnel handshake   │
              │                   │        │                        └──┬────────┬──────┬───┘
              │                   │        │      EV_HANDSHAKE_OK{L2}  │        │      │ {relay}
              │                   │        │        ┌──────────────────┘        │      └──────────┐
              │                   │        ▼        ▼                    {wan}  ▼                 ▼
              │           ┌──────────────────┐  ┌──────────────┐    ┌──────────────┐      ┌──────────────┐
              │           │  RECONNECTING    │  │ LOCAL_DIRECT │    │  WAN_DIRECT  │      │   RELAYED    │
              │           │  backoff + probe │  └──────┬───────┘    └──────┬───────┘      └──────┬───────┘
              │           └───┬───────┬──────┘         │                   │                     │
              │               │       │                └────────┬──────────┴─────────────────────┘
              │               │       │                         │  (steady states; all three may
              │  EV_DISCONNECT│       │ T_RECONNECT_GRACE       │   upgrade, migrate, or degrade)
              └───────────────┘       │  && FAIL_CLOSED         │
                                      │                         ├──── EV_QOS_VIOLATION ────►┌──────────┐
                                      ▼                         │◄─── EV_QOS_RESTORED ──────│ DEGRADED │
                              ┌───────────────┐                 │                           └────┬─────┘
                              │    BLOCKED    │                 │                                │
                              │ fail-closed;  │                 │   EV_PATH_UPGRADE_AVAILABLE    │ T_DEGRADED_MAX
                              │ retry loop    │                 │   EV_PATH_SUSPECT              │
                              │ runs inside   │                 │   EV_ADDR_CHANGED              ▼
                              └───┬───────┬───┘                 ├──── EV_LINK_UP(alt) ────►┌───────────┐
                                  │       │                     │                          │ MIGRATING │
        EV_SECURE_PATH_RESTORED   │       │ EV_POLICY_VIOLATION │◄─── EV_PATH_VALIDATED ───│ (make-    │
        ──────────────────────────┘       │   (from any state)  │                          │  before-  │
                                          │                     │      EV_MIGRATION_FAIL   │  break)   │
                                          ▼                     └────────────┬─────────────└───────────┘
                              ┌───────────────────┐                          │
                              │      FAILED       │◄─────────────────────────┘
                              │  terminal for     │   EV_VERSION_INCOMPATIBLE, EV_AUTH_REJECTED,
                              │  this attempt     │   EV_PEER_REVOKED, EV_CRED_EXPIRED,
                              └───────────────────┘   EV_RETRY_BUDGET_EXHAUSTED

  Not drawn, to keep the diagram readable:
   · EV_PATH_DEAD from any established state → MIGRATING (alternate exists) or RECONNECTING (none).
   · EV_POLICY_VIOLATION from any state → BLOCKED. This edge always exists and always wins.
   · EV_DISCONNECT_REQUESTED from any state → DISCONNECTED, except from BLOCKED where leaving
     fail-closed enforcement additionally requires the authenticated user action defined by ADR-0012.
   · BLOCKED and RECONNECTING both run an internal re-establishment loop; on success they
     transition directly to LOCAL_DIRECT / WAN_DIRECT / RELAYED.
```

### 4.3 Events

| Event | Source | Notes |
|---|---|---|
| `EV_CONNECT_REQUESTED` | user, policy, autostart, peer-initiated | Idempotent; a request while already connecting is absorbed |
| `EV_DISCONNECT_REQUESTED` | user, policy | |
| `EV_CANDIDATES_READY` | candidate gatherer ([ADR-0004](adr/ADR-0004-nat-traversal-strategy.md)) | Fires on first usable candidate, not on completion; gathering continues |
| `EV_CANDIDATE_TIMEOUT` | timer `T_DISCOVER` | |
| `EV_NEGOTIATION_OK` / `EV_NEGOTIATION_FAIL` | [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) | |
| `EV_VERSION_INCOMPATIBLE` | [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) | Non-retryable |
| `EV_HANDSHAKE_OK{class}` | tunnel ([ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)) | `class` ∈ {`L2`, `WAN`, `RELAY`} |
| `EV_HANDSHAKE_FAIL` / `EV_AUTH_REJECTED` / `EV_PEER_REVOKED` | tunnel, [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) | `EV_AUTH_REJECTED` (`AUTH.PEER_UNTRUSTED`) and `EV_PEER_REVOKED` (`AUTH.DEVICE_REVOKED`) are non-retryable |
| `EV_RELAY_READY` | relay client | A relay path is allocated and validated |
| `EV_PATH_UPGRADE_AVAILABLE{class}` | background prober | A strictly better path class validated |
| `EV_PATH_SUSPECT` / `EV_PATH_DEAD` | liveness monitor | See §5 |
| `EV_LINK_DOWN` / `EV_LINK_UP` / `EV_ADDR_CHANGED` | OS network monitor | Hard signals (R2) |
| `EV_PATH_VALIDATED{path}` / `EV_MIGRATION_FAIL` | path validator | Authenticated challenge-response on the candidate path |
| `EV_QOS_VIOLATION{metric}` / `EV_QOS_RESTORED` | quality monitor | Thresholds are **§5.4**. Earlier drafts pointed here at "§7.4"; §7.4 is the promotion/demotion *mechanism*, which consumes those thresholds but does not set them. |
| `EV_POLICY_VIOLATION{kind}` | enforcement reconciler, leak canary ([ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md)) | Always wins; always → `BLOCKED` |
| `EV_SECURE_PATH_RESTORED` | enforcement reconciler | Precondition for leaving `BLOCKED` |
| `EV_CRED_EXPIRED` | credential monitor | |
| `EV_SUSPEND` / `EV_RESUME` / `EV_BACKGROUND` / `EV_FOREGROUND` | OS lifecycle | |
| `EV_RETRY_BUDGET_EXHAUSTED` | retry governor (§6.3) | |
| `EV_PEER_CLOSED` / `EV_PEER_RESTARTING` | peer, authenticated | `PEER_RESTARTING` suppresses the failure path for `T_PEER_RESTART_GRACE` |
| `EV_RELAY_DRAINING{deadline}` / `EV_RELAY_GONE` | relay ([ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md)) | |

### 4.4 Per-state invariants

| State | Traffic disposition | Invariants that MUST hold | Active timers | Class |
|---|---|---|---|---|
| `DISCONNECTED` | `DROPPED_FAIL_CLOSED` if `FAIL_CLOSED` and the peer is in the protected scope; otherwise `DROPPED_NO_ROUTE` for `TwinNet`-destined traffic | No `Session` keys held. No relay allocation held. No `Route` installed for this peer. Enforcement rules for the protected scope remain installed if `FAIL_CLOSED`. | none | resting |
| `DISCOVERING` | unchanged from prior state | No packet is sent to the peer over any path yet. Candidate gathering runs for v4 and v6 concurrently. No user traffic may be emitted on an unvalidated path. | `T_DISCOVER`, `T_DISCOVER_SOFT` | transient |
| `NEGOTIATING` | unchanged from prior state | `ProtocolVersion` and `Capability` set are being agreed; nothing is committed until agreement. No user traffic. | `T_NEGOTIATE` | transient |
| `CONNECTING` | unchanged from prior state | Candidate pairs are raced concurrently across v4 and v6 and across direct and relay. Handshake material is per [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md). No user traffic until a path is both cryptographically established and validated. | `T_CONNECT` | transient |
| `LOCAL_DIRECT` | `TUNNELED_LOCAL_DIRECT` | A validated direct path over the same L2 segment carries traffic. End-to-end encryption is in force. Peer identity is authenticated ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md)). Liveness is bidirectional within `T_DEAD`. `Route` and `DNSPolicy` for this peer are reconciled and in force. PMTU is known or clamped. | keepalive, liveness, quality, PMTU probe | steady |
| `WAN_DIRECT` | `TUNNELED_WAN_DIRECT` | As `LOCAL_DIRECT`, plus: a NAT binding keepalive is running at the currently estimated safe interval, and at least one alternate path (usually relay) is either warm or re-establishable within `T_FAILOVER_TARGET`. | keepalive, liveness, quality, PMTU probe, NAT binding | steady |
| `RELAYED` | `TUNNELED_RELAY` | The relay forwards **opaque ciphertext only**; it holds no key capable of decrypting the payload (I1, [ADR-0005](adr/ADR-0005-relay-architecture.md)). A direct-upgrade prober is running. A standby relay in a different failure domain is selected, and warm whenever `RELAYED` has persisted past `T_STANDBY_WARM`. | keepalive, liveness, quality, upgrade probe, relay heartbeat | steady |
| `MIGRATING{from→to}` | `TUNNELED_DUAL` while both paths are alive; `QUEUED_BOUNDED` for at most `T_MIGRATE_QUEUE` if the old path is already gone | The `Session`, its keys, and its inner v4 and v6 addresses are unchanged. The new path is not committed until it passes authenticated path validation. The old path is not released until the new one is committed, whenever the old path is still alive. Inner MTU is clamped to the safe floor for the duration. | `T_MIGRATE`, `T_MIGRATE_QUEUE` | transient |
| `DEGRADED{carrier}` | the carrier's disposition (traffic **continues to flow**) | The violation is a **quality** violation, never a policy or security violation (R6). The specific violated objective and its measured value are attached to the state. An alternate-path search is running. The state is time-bounded by `T_DEGRADED_MAX`. | `T_DEGRADED_MAX`, quality, all carrier timers | steady-but-bounded |
| `RECONNECTING` | `DROPPED_FAIL_CLOSED` if `FAIL_CLOSED`; otherwise `DROPPED_NO_ROUTE` for `TwinNet` traffic and `UNPROTECTED_ANNOUNCED` for exit-node traffic | `Session` context (identity, negotiated capabilities, inner addresses, cached peer endpoints) is retained. Backoff and retry budget (§6) are being honoured. Enforcement rules stay installed. No user traffic is emitted on any path. | `T_RECONNECT_GRACE`, `T_RECONNECT_MAX`, backoff | transient |
| `BLOCKED` | `DROPPED_FAIL_CLOSED` — always, without exception | Entered by **policy**, not by fault: either a policy violation was detected, or fail-closed enforcement is holding traffic while no authorized secure path exists. Traffic stays blocked until an authorized secure path is restored (I3). The enforcement rules are verified present, for v4 and v6, at entry and on every reconciler tick. A re-establishment loop runs **inside** this state. The reason code and its remediation are displayed persistently. | reconciler, backoff, leak canary | holding (recoverable) |
| `FAILED` | as `DISCONNECTED` | Entered only on a `non-retryable` or `non-retryable-until` condition, or on retry-budget exhaustion. Carries the terminal reason code and its precondition for retry. No timers burn CPU or battery in this state; exit is by explicit request or by a qualifying environment event (`EV_LINK_UP`, credential renewed, peer re-authorized). | none (watch only) | terminal for the attempt |

### 4.5 Transition table

Guards are evaluated in the order written. `*` means any state. Actions marked **[E]** are
entry actions of the target state; **[X]** are exit actions of the source state.

**Normative: every row emits exactly one transition event.** Each transition below MUST emit
exactly one structured

```
TransitionEvent { from, to, trigger, reason_code, session_id, path_id, occurred_at }
```

and emission MUST be a **property of the transition itself, not of a call site** — a single
choke point in the state machine, so that no code path can move the machine without producing
the record ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) O-05,
[docs/testing-strategy.md](testing-strategy.md) A-02, P10). Consequences that are load-bearing
elsewhere in the corpus:

1. `trigger` carries the **event or timer that fired**, not just the target state. It is what
   distinguishes T19 from T20 (`EV_PATH_DEAD` with an alternate versus without) and T16 from T17
   (`T_MIGRATE` with the old path alive versus dead). Without `trigger`, the transition-coverage
   merge gate in [docs/testing-strategy.md](testing-strategy.md) §2 cannot tell those pairs
   apart, and this event stream is the primary test oracle for the whole corpus.
2. `path_id` is nullable — `DISCONNECTED`, `DISCOVERING`, and `NEGOTIATING` have no `Path` — but
   `session_id` never is. `session_id` is durable and survives process restart (S-12), which is
   what lets an outage be reconstructed across a crash.
3. `reason_code` is **mandatory on every row whose target is `DEGRADED`, `BLOCKED`,
   `RECONNECTING`, or `FAILED`**, and every such row below therefore carries an explicit emit
   action. A transition into one of those four states without a `reason_code` is itself the
   defect `INTERNAL.INVARIANT_VIOLATED` (§10; ADR-0015 §11.6 rule 3). This is checkable
   table-wide by inspection and is asserted as a static test in §10.2.
4. On a row whose target is a steady or resting state, `reason_code` MAY be null where the
   transition is an ordinary success; where the row names an emit action (T15, T25, T30, T38),
   that code is the transition's `reason_code`, because P10 requires successes to be
   reconstructable too, not only failures.

| # | From | Event | Guard | To | Actions |
|---|---|---|---|---|---|
| T01 | `DISCONNECTED` | `EV_CONNECT_REQUESTED` | credentials valid ∧ peer authorized | `DISCOVERING` | **[E]** start candidate gathering (v4+v6, local/reflexive/relay-allocated in parallel); start `T_DISCOVER`; emit transition event |
| T02 | `DISCONNECTED` | `EV_CONNECT_REQUESTED` | credentials expired | `FAILED` | emit `AUTH.CRED_EXPIRED`; request renewal |
| T03 | `DISCOVERING` | `EV_CANDIDATES_READY` | ≥1 usable candidate | `NEGOTIATING` | **[X]** keep gathering in background; **[E]** start `T_NEGOTIATE`; send offer |
| T04 | `DISCOVERING` | `EV_CANDIDATE_TIMEOUT` | no candidate on either family | `RECONNECTING` | emit `NET.NO_USABLE_CANDIDATES`; start backoff |
| T05 | `NEGOTIATING` | `EV_NEGOTIATION_OK` | — | `CONNECTING` | **[E]** start `T_CONNECT`; begin racing candidate pairs and relay allocation concurrently |
| T06 | `NEGOTIATING` | `EV_VERSION_INCOMPATIBLE` | — | `FAILED` | emit `PROTO.VERSION_UNSUPPORTED` with both version ranges and the required upgrade |
| T07 | `NEGOTIATING` | `EV_NEGOTIATION_FAIL` ∨ `T_NEGOTIATE` | retry budget available | `RECONNECTING` | emit `NET.SESSION.NEGOTIATION_FAILED`; backoff |
| T08 | `CONNECTING` | `EV_HANDSHAKE_OK{L2}` | path validated | `LOCAL_DIRECT` | **[E]** install `Route`/`DNSPolicy`; clamp MTU to floor and start PMTU probe; start keepalive+liveness+quality; establish RTT baseline; cancel losing candidates |
| T09 | `CONNECTING` | `EV_HANDSHAKE_OK{WAN}` | path validated ∧ no L2 path won | `WAN_DIRECT` | as T08 **[E]**, plus start NAT binding keepalive and select a relay standby |
| T10 | `CONNECTING` | `EV_HANDSHAKE_OK{RELAY}` | path validated ∧ no direct path won yet | `RELAYED` | as T08 **[E]**, plus start direct-upgrade prober and relay heartbeat |
| T11 | `CONNECTING` | `EV_AUTH_REJECTED` ∨ `EV_PEER_REVOKED` | — | `FAILED` | emit `AUTH.PEER_UNTRUSTED` / `AUTH.DEVICE_REVOKED`; do **not** retry |
| T12 | `CONNECTING` | `EV_HANDSHAKE_FAIL` ∨ `T_CONNECT` | retry budget available | `RECONNECTING` | emit the most specific transport code observed (`NAT.UDP_BLOCKED`, `NAT.*`, `RELAY.NONE_REACHABLE`, …), never a generic one |
| T13 | `RELAYED` | `EV_PATH_UPGRADE_AVAILABLE{WAN}` | validated ∧ better by hysteresis margin | `MIGRATING{RELAY→WAN}` | **[E]** send on both paths; start `T_MIGRATE` |
| T14 | `RELAYED` ∨ `WAN_DIRECT` | `EV_PATH_UPGRADE_AVAILABLE{L2}` | validated ∧ same L2 confirmed | `MIGRATING{→L2}` | as T13 |
| T15 | `MIGRATING` | `EV_PATH_VALIDATED{to}` | new path committed | `LOCAL_DIRECT` ∨ `WAN_DIRECT` ∨ `RELAYED` (= `to`) | **[X]** release old path resources (relay allocation, sockets); **[E]** re-probe PMTU; reset RTT baseline; emit `NET.PATH.MIGRATED` with from/to and measured deltas |
| T16 | `MIGRATING` | `EV_MIGRATION_FAIL` ∨ `T_MIGRATE` | old path still alive | back to `from` | emit `NET.PATH.MIGRATION_ABORTED`; apply migration cooldown `T_MIGRATE_COOLDOWN` to that candidate |
| T17 | `MIGRATING` | `EV_MIGRATION_FAIL` ∨ `T_MIGRATE` | old path dead | `RECONNECTING` | emit `NET.PATH.MIGRATION_FAILED`; backoff |
| T18 | `LOCAL_DIRECT` ∨ `WAN_DIRECT` ∨ `RELAYED` ∨ `DEGRADED` | `EV_PATH_SUSPECT` | — | *no state change* | start alternate-path probing immediately; raise heartbeat rate; **do not** disturb traffic |
| T19 | `LOCAL_DIRECT` ∨ `WAN_DIRECT` ∨ `RELAYED` ∨ `DEGRADED` | `EV_PATH_DEAD` ∨ `EV_LINK_DOWN` ∨ `EV_RELAY_GONE` | a validated or warm alternate exists | `MIGRATING{dead→alt}` | **[E]** bounded queue for ≤ `T_MIGRATE_QUEUE`; emit the specific cause code |
| T20 | `LOCAL_DIRECT` ∨ `WAN_DIRECT` ∨ `RELAYED` ∨ `DEGRADED` | `EV_PATH_DEAD` ∨ `EV_LINK_DOWN` | no alternate | `RECONNECTING` | **emit `NET.PATH.DEAD_NO_ALTERNATE`** (`TRANSIENT`), with the specific cause as the `caused_by` evidence field (`NET.LINK.DOWN_WIFI`, `NET.LINK.DOWN_CELLULAR`, `NET.PATH.DIRECT_LOST`, `RELAY.NONE_REACHABLE`, …); **[X]** stop emitting user traffic; **[E]** enforce disposition; start `T_RECONNECT_GRACE` and backoff |
| T21 | `LOCAL_DIRECT` ∨ `WAN_DIRECT` ∨ `RELAYED` | `EV_ADDR_CHANGED` | local address changed | `MIGRATING{same class}` | re-bind sockets; re-gather reflexive candidates; validate from the new address before committing |
| T22 | `LOCAL_DIRECT` ∨ `WAN_DIRECT` ∨ `RELAYED` | `EV_QOS_VIOLATION{m}` | violation sustained ≥ `T_QOS_CONFIRM` | `DEGRADED{carrier}` | emit the `NET.QOS.*` code for `m` with its measured value and threshold; start alternate search; start `T_DEGRADED_MAX` |
| T23 | `DEGRADED` | `EV_QOS_RESTORED` | restored ≥ `T_QOS_CLEAR` | back to `carrier` | emit `NET.QOS.RESTORED`; cancel `T_DEGRADED_MAX` |
| T24 | `DEGRADED` | `T_DEGRADED_MAX` | — | `RECONNECTING` | emit `NET.QOS.DEGRADED_TIMEOUT`; force a full re-establishment cycle rather than sitting in a bad path indefinitely (R5) |
| T25 | `RECONNECTING` | `EV_HANDSHAKE_OK{class}` | path validated | `LOCAL_DIRECT` ∨ `WAN_DIRECT` ∨ `RELAYED` | as T08–T10; emit `NET.SESSION.RECOVERED` with outage duration |
| T26 | `RECONNECTING` | `T_RECONNECT_GRACE` | enforcement = `FAIL_CLOSED` | `BLOCKED` | emit the causal code **plus** `POLICY.KILLSWITCH.ENGAGED` ([ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.9); keep the re-establishment loop running inside `BLOCKED` |
| T27 | `RECONNECTING` | `T_RECONNECT_MAX` ∨ `EV_RETRY_BUDGET_EXHAUSTED` | enforcement = `PERMISSIVE_ANNOUNCED` | `FAILED` | **emit** the most specific `FATAL`- or `PERSISTENT`-class code observed during the attempt, never a generic one — and where nothing more specific exists, `RELAY.FLEET.UNREACHABLE` or `NET.NO_USABLE_CANDIDATES` with the full candidate ledger as evidence; announce `POLICY.KILLSWITCH.UNPROTECTED_FALLBACK` ([ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.9) persistently if any traffic is now untunneled |
| T28 | `RECONNECTING` | `EV_CRED_EXPIRED` ∨ `EV_PEER_REVOKED` ∨ `EV_VERSION_INCOMPATIBLE` | — | `FAILED` | **emit** `AUTH.CRED_EXPIRED` / `AUTH.DEVICE_REVOKED` / `PROTO.VERSION_UNSUPPORTED` respectively, each with its `retry_precondition` evidence field set; no timer-driven retry |
| T29 | `*` | `EV_POLICY_VIOLATION{kind}` | — | `BLOCKED` | **immediately** stop emitting user traffic; verify enforcement rules present for v4 **and** v6; emit the specific policy code (`DNS.LEAK.QUERY_OBSERVED_OFF_TUNNEL`, `ROUTE.DRIFT_DETECTED`, `ROUTE.IFACE_MISSING`, …); begin remediation |
| T30 | `BLOCKED` | `EV_SECURE_PATH_RESTORED` | an authorized secure path is established **and** enforcement reconciliation passes | `LOCAL_DIRECT` ∨ `WAN_DIRECT` ∨ `RELAYED` | emit `POLICY.KILLSWITCH.TRAFFIC_RESTORED` ([ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.9) with the blocked duration |
| T31 | `BLOCKED` | backoff tick | retry budget available | *no state change* | run one re-establishment attempt; traffic stays `DROPPED_FAIL_CLOSED` throughout |
| T32 | `BLOCKED` | `EV_DISCONNECT_REQUESTED` | authenticated user action per [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) | `DISCONNECTED` | leaving fail-closed without a restored path is a deliberate, authenticated, logged act — never an automatic one |
| T33 | `FAILED` | `EV_CONNECT_REQUESTED` ∨ qualifying environment event | precondition of the terminal code satisfied | `DISCOVERING` | reset retry budget for this cause class; emit `NET.SESSION.RETRY_PRECONDITION_MET` |
| T34 | `*` | `EV_SUSPEND` ∨ (`EV_BACKGROUND` ∧ ¬`inbound_required`) | — | `RECONNECTING` (parked) | **emit `PLATFORM.SUSPENDED`** on `EV_SUSPEND`, or **`PLATFORM.BACKGROUND_SUSPENDED`** on the mobile background park (§11.2) — both `TRANSIENT`, `remediation_class: automatic`. A park is an ordinary, expected entry to `RECONNECTING`, and naming it is what keeps it from being indistinguishable from a fault; **[X]** cancel timers; **[E]** park; keep enforcement rules installed across suspend; record suspend timestamp |
| T35 | `RECONNECTING` (parked) | `EV_RESUME` | — | `MIGRATING` if a path plausibly survived, else `DISCOVERING` | re-read interfaces/addresses; re-assert `Route`/`DNSPolicy`/firewall; validate before emitting traffic; if wall-clock delta > rekey window, force full handshake |
| T36 | `*` | `EV_BACKGROUND` / `EV_FOREGROUND` | `inbound_required` **or** already parked | *no state change* | switch timer profile (§11); `EV_FOREGROUND` additionally triggers an immediate liveness probe. When `EV_BACKGROUND` fires and **no** peer has declared an inbound reachability requirement, T34 applies instead and the `Session` parks — see §11.2 |
| T37 | `RELAYED` ∨ `DEGRADED{RELAYED}` | `EV_RELAY_DRAINING{deadline}` | — | `MIGRATING{RELAY→RELAY'}` at a time drawn uniformly from `[0, deadline − 60s]` | herd-safe drain (§8.3) |
| T38 | `*` | `EV_DISCONNECT_REQUESTED` | state ≠ `BLOCKED` | `DISCONNECTED` | tear down keys, release relay allocation, remove peer `Route`s, emit `NET.SESSION.CLOSED_BY_USER` |

### 4.6 Terminal versus recoverable

| Class | States | Exit condition |
|---|---|---|
| **Recoverable automatically** | `DISCOVERING`, `NEGOTIATING`, `CONNECTING`, `MIGRATING`, `DEGRADED`, `RECONNECTING` | Timers and the retry governor drive them to a resolution without user action |
| **Recoverable, holding** | `BLOCKED` | Recovers automatically when an authorized secure path returns. **Not** terminal — it retries internally forever, at the floor backoff rate, because giving up on a blocked device would leave a user permanently offline with no path back. It is, however, permanently visible while it lasts. |
| **Resting** | `DISCONNECTED` | User or policy request |
| **Terminal for the attempt** | `FAILED` | Requires either an explicit new request or the satisfaction of the named precondition. Never auto-retried on a timer, because every `FAILED` cause is one that retrying cannot fix. |

`FAILED` is terminal *for a connection attempt*, not for the product: the `Session` object
persists, its diagnostic is displayed, and the qualifying environment events in T33 revive it.
There is no state from which the user cannot recover without reinstalling.

### 4.7 Derived `TwinNet`-scope state

The `TwinNet`-scope `ConnectionState` shown to the user is computed from the per-`Session`
states in this priority order — **worst wins**, so the aggregate never looks healthier than
reality:

```text
BLOCKED  >  FAILED (all sessions)  >  RECONNECTING (any)  >  DEGRADED (any)
         >  MIGRATING (any)  >  RELAYED (any established session on relay)
         >  WAN_DIRECT  >  LOCAL_DIRECT
         >  CONNECTING > NEGOTIATING > DISCOVERING  >  DISCONNECTED
```

Two rules make this honest rather than alarming:

1. If enforcement is `FAIL_CLOSED` and **no** `Session` in the protected scope has a usable
   path, the aggregate is `BLOCKED` regardless of the individual states — this is what makes
   `FAILED` and `BLOCKED` coexist correctly. A `Session` can be `FAILED` while the device as
   a whole is `BLOCKED`, and the user sees the blocking condition (which is what matters to
   them) with the per-`Session` cause attached.
2. The aggregate always carries the reason code of the worst contributing `Session`, plus a
   count of how many `Session`s are healthy. "3 of 4 devices connected; laptop unreachable
   because …" is the target user-facing sentence, not "Connected" or "Error".

---

## 5. Timers and constants

All values are defaults. Every one is a tunable with a documented safe range; none is a magic
number buried in code. Values marked **(mobile bg)** are overridden by the background profile
in §11.

### 5.1 Establishment timers

| Constant | Default | Justification |
|---|---|---|
| `T_DISCOVER_SOFT` | 1.5 s | Emit the first usable candidate early rather than waiting for a complete set. Local and cached-endpoint candidates are available in tens of milliseconds; reflexive candidates need one RTT to a STUN-like service. 1.5 s covers a slow reflexive round trip without stalling the LAN case. |
| `T_DISCOVER` | 5 s | Upper bound on gathering. Beyond this, additional candidates almost never change the outcome, and the user is watching a spinner. |
| `T_NEGOTIATE` | 5 s | One control-plane or relay-mediated round trip plus slack. Exceeding it means the rendezvous path is broken, which is a different failure than "the peer is slow". |
| `T_CONNECT` | 10 s | Enough for ~6 hole-punch attempts at 1 s spacing plus a relay fallback. Tuned so that the *relay* path, which is far more predictable, has completed long before this fires; `T_CONNECT` therefore only expires when nothing at all works. |
| `T_HE_BIAS` | 250 ms | IPv6-over-IPv4 preference window when both validate. Matches the Happy Eyeballs v2 (RFC 8305) resolution-delay reasoning: long enough to let a healthy v6 path win, short enough that a broken v6 path costs a quarter second. **250 ms is the settled value**, and [ADR-0005](adr/ADR-0005-relay-architecture.md) §11.4's carriage ladder and [ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md) already stage against it. Any carriage or probe ladder whose rung offsets were derived against 150 ms must re-derive them against 250 ms; the rung *spacing* is the ADR's to choose, the *bias* is not. |
| `T_RELAY_FIRST_TRAFFIC` | 300 ms target | A relay path should be carrying traffic within 300 ms of `EV_CONNECT_REQUESTED` when the relay session is warm. This is what makes relay-first safe: users never wait on hole punching. |

### 5.2 Liveness timers

| Constant | Default | Justification |
|---|---|---|
| `T_HEARTBEAT_ACTIVE` | 3 s | Authenticated bidirectional liveness probe on the carrying path while the `Session` is active and the device is in the foreground. Three seconds gives 2-missed detection at 6 s, which is under the threshold at which users start reporting "it froze". |
| `T_HEARTBEAT_IDLE` | 15 s | When no user traffic has flowed for 60 s, drop to the NAT-binding cadence. Liveness detection latency rises to ~30 s, which is acceptable because nothing is depending on the path at that moment; the first user packet triggers an immediate probe. |
| `T_SUSPECT` | 6 s (2 missed) — **end-to-end `Path` only** | Entering `PATH_SUSPECT` starts alternate-path probing **without disturbing traffic** (T18). Making this cheap and early is what turns a would-be disconnect into a sub-second migration. |
| `T_DEAD` | 15 s (5 missed) — **end-to-end `Path` only** | Declaring a path dead is expensive (it may cost a handshake), so it needs more evidence than `SUSPECT`. Hard signals (`EV_LINK_DOWN`, socket error, ICMP) bypass this entirely and are the *normal* detection path (R2); 15 s is the backstop for networks that fail silently. |
| `T_LEG_DEAD` | **3 missed** leg `PING`/`PONG` at the coalesced cadence (≈6–9 s foreground, ≈30 s idle) — **device↔relay leg only** | A distinct constant from `T_DEAD`, deliberately. `T_SUSPECT`/`T_DEAD` measure the **end-to-end `Path`** between two peers and answer "is my peer reachable this way". `T_LEG_DEAD` measures the **device↔relay leg**, which [ADR-0005](adr/ADR-0005-relay-architecture.md) gives its own `PING`/`PONG` independent of any half-flow, and answers "is this relay up". They fire on different evidence and mean different things: a dead leg is a *relay* failure and triggers relay failover (§8), while a silent half-flow on a **live** leg is *peer* loss and MUST NOT cause failover ([ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.4 — moving a working relay cannot help). Earlier drafts conflated the two, which is why `docs/networking.md`, ADR-0005 and ADR-0006 all say "3 missed" while this section said 2 and 5; both are correct, of different things. |
| `T_PEER_RESTART_GRACE` | 30 s | An authenticated `PEER_RESTARTING` suppresses failure handling for this long, so a peer's planned upgrade does not produce a fleet-wide reconnect storm. |
| `T_NAT_KEEPALIVE` | **25 s initial; adaptive ladder 25 → 35 → 50 → 70 → 100 → 120 s; cap 120 s** | 25 s is safe under RFC 4787 REQ-5's 2-minute floor *and* under the 30 s timers observed on CGNAT, which is why it is the start rather than a shorter guess. The ladder additively increases while bindings survive and **reverts to the last known-good rung** on the first observed `NAT.MAPPING_EXPIRED` — not a halving, because the last rung that worked is a measurement and half of the current rung is not. The learned value is cached per network fingerprint (§6.6). These are `docs/networking.md` §3.5's and [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md)'s values, adopted here unchanged; this row is the registration, and §6.6 is the mechanism. |

### 5.3 Recovery and dwell timers

| Constant | Default | Justification |
|---|---|---|
| `T_RECONNECT_GRACE` | 20 s | The boundary between `RECONNECTING` (a blip) and `BLOCKED` (a sustained outage). Chosen so that a Wi-Fi→cellular roam, a DHCP renewal, or a suspend/resume resolves inside `RECONNECTING` and never alarms the user, while a genuine outage becomes loudly visible within 20 s. |
| `T_RECONNECT_MAX` | 10 min | Only relevant when enforcement is `PERMISSIVE_ANNOUNCED`; after this the `Session` goes `FAILED` rather than burning battery forever. Under `FAIL_CLOSED` there is no equivalent bound: `BLOCKED` retries indefinitely at the floor rate, because abandoning recovery would strand the user. |
| `T_MIGRATE` | 3 s | Path validation is one to three round trips. Three seconds accommodates a slow cellular path; beyond that the candidate is not actually better. **3 s is the settled value**, matching [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.5(5). `docs/protocol.md` §12.2 states a 500 ms probe cadence bounded by `T_MIGRATE` and elsewhere reads as though 500 ms × 3 = 1.5 s were the bound; **the cadence is protocol.md's to set, the bound is not** — protocol.md §12.2 **now defers** to this constant. A 1.5 s bound abandons a valid candidate on a slow cellular path, which is precisely the gratuitous disconnect this document exists to remove. |
| `T_MIGRATE_QUEUE` | 100 ms / 64 packets | The bounded make-before-break queue used only when the old path is already gone. Deliberately tiny: queueing more than ~100 ms of traffic damages inner congestion control more than the loss it prevents. Drop-oldest on overflow. |
| `T_MIGRATE_COOLDOWN` | 60 s | Per-candidate cooldown after a failed migration, so a flapping candidate cannot cause repeated disruption. |
| `T_QOS_CONFIRM` | 10 s | A quality violation must persist before it becomes `DEGRADED`, so a single bad Wi-Fi moment does not change state. |
| `T_QOS_CLEAR` | 30 s | Asymmetric with `T_QOS_CONFIRM` on purpose: slow to enter is unhelpful, slow to leave prevents flapping between `DEGRADED` and healthy. |
| `T_DEGRADED_MAX` | 10 min | R5: no unbounded degradation. After 10 minutes of a violated objective, force a full re-establishment cycle, which often finds a path the incremental prober would not. |
| `T_STANDBY_WARM` | 30 s | How long a `Session` must remain `RELAYED` before a standby relay session is opened. Avoids paying for a second relay connection during brief relay use. |
| `T_FAILOVER_TARGET` | 300 ms | Design target for relay-to-relay failover with a warm standby. |

**Constants registered here on behalf of other ADRs.** Under C2 no ADR owns a timer value; ADRs
propose, this section registers. Each row names the ADR that submitted it and owns the *policy*
the constant serves; this document owns the *value*.

| Constant | Default | Submitted by | What it governs |
|---|---|---|---|
| `T_UPGRADE_DWELL` | 120 s | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.10(4) | After a `RELAYED → WAN_DIRECT` upgrade, the reverse migration MUST NOT be initiated by **quality** alone for this long. Asymmetric on purpose: a **hard** failure (`PATH_FAILING`, `EV_LINK_DOWN`, socket error) demotes immediately and is never suppressed — anti-flap must never trap a `Session` on a dead path. |
| `T_UPGRADE_FLAP_WINDOW` | 10 min | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.10(5) | Observation window for counting `RELAYED ↔ WAN_DIRECT` oscillations. |
| `N_UPGRADE_FLAP` | 3 | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.10(5) | Oscillations within `T_UPGRADE_FLAP_WINDOW` that trip flap suppression. |
| `T_UPGRADE_FLAP_SUPPRESS` | 30 min | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.10(5) | How long the direct candidate is suppressed for that pair, **on that network fingerprint only**; any network change clears it. |
| `T_UPGRADE_PROBE_BG` | 300 s | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.10(1) | Cadence floor for the direct-upgrade prober in mobile background; probes MUST align to the coalesced wake window (§11). |
| `N_UPGRADE_GIVEUP` | 20 | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.10(2) | Consecutive failed upgrade attempts on one network fingerprint after which timer-driven probing suspends and probing becomes **event-driven**. Probing never stops permanently (R-12). |
| `T_REGION_SPREAD` | 20 s | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.7(2) | Width of the `uniform(0, T_REGION_SPREAD)` start-time draw for devices that must **acquire** new capacity during a region failover. Devices holding a **bound** standby move immediately — their capacity was already accounted at bind time (§8.2). |
| `T_TRUST_REFRESH` | 6 h | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7 | Routine trust-state refresh floor. |
| `T_TRUST_STALE` | 24 h | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7 | Trust state is stale: persistent `Diagnostic` `AUTH.TRUST_STATE_STALE`, **no `ConnectionState` change** (§7.6). Baseline connectivity continues. |
| `T_TRUST_HARD` | 30 d (`Owner`-configurable within [24 h, 90 d]) | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7 | **Granted authority suspends** (`AUTH.TRUST_STATE_EXPIRED`); baseline peer connectivity still continues (§9). |
| `T_IK_OVERLAP` | 30 d | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §11.1 N-23 | Identity-key rotation overlap. A peer that has not yet seen a rotation still connects for this long. |
| `T_TK_OVERLAP` | 14 d | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §11.1 N-23 | Tunnel-key rotation overlap. Rotation never tears down a `Session`. |

None of these introduces a state or a transition. They parameterise the guards registered
immediately below.

#### 5.3.1 Timer clock classes (normative) — and the defect this rule closes

**Not every constant in §5.2 and §5.3 reads the same clock.** Registering short-horizon liveness
constants and long-horizon *policy* deadlines in one table, under one blanket "monotonic clocks for
every timer" rule (§10.2 E5 as originally written), produced a security defect:

> A laptop suspended for sixty days accrues **no monotonic time**, so `T_TRUST_HARD` never expires.
> The device keeps exercising every *granted* authority — exit egress, LAN access, route acceptance,
> new pairing — that **R-24** exists to suspend precisely so an unlearned revocation has a bounded
> blast radius. R-24 silently does not hold on the most ordinary hardware in the product's range.
> This is not a missing feature: it is one specified mechanism defeated by another.

Every timer constant MUST therefore declare its clock class. The three classes are defined by
[ADR-0022](adr/ADR-0022-application-lifecycle-and-background-execution.md) LC-8 and are **not
interchangeable**; that ADR owns the per-platform primitives and this document does not restate them.

| Class | Advances across suspend? | Which constants | Rule |
|---|---|---|---|
| **`MonotonicClock`** | **No** | Every liveness, establishment, migration, dwell and backoff constant in §5.1–§5.3 — `T_DEAD`, `T_HEARTBEAT_*`, `T_MIGRATE*`, `T_QOS_*`, `T_RECONNECT_*`, `T_STANDBY_WARM`, `T_FAILOVER_TARGET`, the `T_UPGRADE_*` family | The default. Pausing is **required**: with an advancing clock, resuming from an eight-hour sleep fires every short-horizon timer's accrued backlog at once, and `T_DEAD` declares every path dead *before* §11.3's wake ladder can re-validate one |
| **`ElapsedClock`** | **Yes** | **Long-horizon policy deadlines**: `T_TRUST_STALE`, `T_TRUST_HARD`, `T_IK_OVERLAP`, `T_TK_OVERLAP`; `PortalExemptionGrant` expiry (S-35); credential expiry; and the suspend-gap measurement of §11.3 | A deadline that exists to **bound an authority** MUST continue to run while the device is asleep, or the bound is not a bound |
| **`WallClock`** | — | **Evidence only.** Never a timer input | Unchanged from E5's original intent |

> **Rule R-CLK-1 (normative).** A constant whose purpose is to **bound a granted authority** MUST
> read `ElapsedClock`, never `MonotonicClock`.
>
> **Rule R-CLK-2 (normative, and preferred over R-CLK-1 where available).** Where the authority is
> carried by a **signed document**, its expiry SHOULD be evaluated against the **validity window in
> the document itself** ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md)) rather than against
> any local elapsed measurement. A signed window **survives a reboot**, which `ElapsedClock` does
> not — so it is the stronger of the two, and `ElapsedClock` is the fallback where no signed window
> exists.
>
> **Rule R-CLK-3.** A constant registered in §5.2 or §5.3 without a declared clock class is a
> **defect in this document**, not a detail left to the implementer.

**Constants adopted from [ADR-0022](adr/ADR-0022-application-lifecycle-and-background-execution.md)**
under the same C2 rule (that ADR proposes, this section registers): `T_REHYDRATE`,
`T_REHYDRATE_MAX`, `T_LIFECYCLE_STOP`, `T_LIFECYCLE_CRASH_WINDOW`, `N_LIFECYCLE_CRASH`,
`N_LIFECYCLE_APPLY_MAX` (the `apply()`/`set_ruleset()` rate limit, which binds **any** restart policy
including one an operator has weakened, because network-stack flap harms the whole host and not only
us), and `T_TRUSTED_NET_PROOF`. All are `MonotonicClock` except `T_LIFECYCLE_CRASH_WINDOW`, which is
`ElapsedClock` so a crash loop spanning a suspend is still counted as one.
`T_UNATTENDED_ALERT` is adopted from
[ADR-0023](adr/ADR-0023-headless-cli-and-embedded-profile.md) (`ElapsedClock`).

**Guards adopted from other ADRs.** These are boolean inputs to the **existing** `Guard` column of
§4.5, discharging [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.15(b). None
introduces a state or a transition; each is computed by its owning ADR and read here.

| Guard | Owner | Read by | Meaning |
|---|---|---|---|
| `RELAY_SET_NONEMPTY` | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.2 | T12 | At least one relay candidate is admissible for this family and carriage |
| `RELAY_STANDBY_SELECTED` | ADR-0006 §11.6 | T19 | A warm standby has been chosen for this `Session` |
| `RELAY_FAILOVER_TARGET_READY` | ADR-0006 §11.5 | T19 | A standby is bound, or a leg-only standby is reachable within `T_FAILOVER_TARGET`. **This is the guard that separates T19 from T20 on relay death**, and its absence is exactly the cold-relay case ADR-0006 §11.5 rule 1 routes through `RECONNECTING` |
| `RELAY_REGION_FAILED` | ADR-0006 §11.8 | T19, T12 | The correlated detector has declared a whole `RelayRegion` down |
| `RELAY_FLEET_EXHAUSTED` | ADR-0006 §11.8 | T20, T26 | No relay in any region is admissible. `DEGRADED` is **not** available here — when nothing flows, `DEGRADED` is a lie (ADR-0006 §11.8) |
| `DIRECT_UPGRADE_ELIGIBLE` | ADR-0006 §11.10 | T13 | A direct candidate has validated and cleared dwell and anti-flap while `RELAYED` |
| `UPGRADE_FLAP_SUPPRESSED` | ADR-0006 §11.10 | T13 | The upgrade path is suppressed after `N_UPGRADE_FLAP` oscillations within `T_UPGRADE_FLAP_WINDOW` |
| `policy_grant_expired`, `trust_state_expired`, `trust_epoch_behind`, `cursor_unavailable` | [ADR-0009](adr/ADR-0009-state-consistency.md) §11.4 / §11.6 | T29 (first two); diagnostic only (last two) | See §7.7 |

### 5.4 Quality thresholds (entry to `DEGRADED`)

| Metric | Threshold | Notes |
|---|---|---|
| Loss | > 2% sustained over `T_QOS_CONFIRM` | Below 2%, inner congestion control absorbs it; above 2%, interactive applications visibly suffer. Code: `NET.QOS.LOSS_HIGH` |
| RTT | > 3× the path's established baseline, or **> 250 ms absolute on a relay path** | Relative catches regressions; absolute catches "it was always bad". **250 ms is the settled value.** `docs/networking.md` §4.3's `PATH_DEGRADED` guard names 150 ms; that figure must be brought to 250 ms, because [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §9.5's cross-region latency budget is derived against 250 ms and a 150 ms threshold would put every ordinary cross-region failover into `DEGRADED` on arrival. Code: `NET.QOS.RTT_HIGH`, evidence `{measured_rtt_ms, threshold_ms: 250, baseline_rtt_ms}` |
| Jitter | > 30 ms standard deviation | The threshold at which real-time audio degrades audibly. Code: `NET.QOS.JITTER_HIGH` |
| Throughput | < 25% of the measured baseline for this path, when the offered load justifies more | Requires offered load; an idle tunnel is not slow. Measured **passively** under real load only — no synthetic bandwidth test is ever run on a user path (`docs/networking.md` §4.2). Code: `NET.QOS.THROUGHPUT_LOW` |
| Effective MTU | < 1280 bytes of inner payload | The IPv6 minimum; below this, inner fragmentation is required |
| Address family coverage | policy requires dual-stack ∧ one family is not carried | If the missing family could **leak**, this is a policy violation → `BLOCKED`, not `DEGRADED` (R6) |

---

## 6. Recovery semantics

### 6.1 Backoff

Two backoff regimes, chosen deliberately for different risk profiles.

| Regime | Algorithm | Parameters | Applies to | Why this algorithm |
|---|---|---|---|---|
| **Infrastructure** | Decorrelated jitter: `sleep = min(cap, uniform(base, sleep × 3))` | `base` 500 ms, `cap` 30 s, floor rate in `BLOCKED` 30 s | Control-plane requests, relay allocation, relay-map fetch, credential renewal | Decorrelated jitter spreads a synchronized fleet faster than exponential-with-full-jitter at the same cap, because each client's next delay depends on its own previous delay rather than only on the attempt number. When ten thousand clients are knocked off a relay region simultaneously, attempt-number-keyed backoff re-synchronizes them at every step; decorrelated jitter does not. It is the right tool where the failure is *correlated across clients*. |
| **Interactive** | Equal jitter: `sleep = d/2 + uniform(0, d/2)` where `d = min(cap, base × 2^n)` | `base` 250 ms, `cap` 15 s | Peer re-handshake, path re-validation, local interface/route re-assertion | These retries are not correlated across the fleet (they target a peer or the local OS, not shared infrastructure), so herd control matters less than a **predictable worst case**. Equal jitter guarantees at least half the nominal delay has elapsed, which bounds how long a user can be told "reconnecting" while the client is actually sleeping. Full jitter, by contrast, can draw a near-zero delay repeatedly and burn the retry budget in a fraction of a second. |

Both regimes reset their state on a success, and both are **capped in total attempts by the
retry budget** (§6.3), not only by the delay cap.

For any retry that crosses the control plane, the retry MUST carry the same idempotency key as
the original attempt ([ADR-0008](adr/ADR-0008-idempotency.md)). Backoff without idempotency
turns a slow response into duplicated state, which is a worse failure than the timeout.

### 6.2 Reconnect behaviour

`RECONNECTING` is not a sleep loop. On entry, and on every backoff tick, it runs the cheapest
recovery that could work, in this order, stopping at the first success:

| Step | Cost | Condition |
|---|---|---|
| 1. Re-validate the existing path from a possibly-new local address | ~1 RTT, no handshake | Local address changed but the peer's `Endpoint` is unchanged — the common roaming case |
| 2. Cut over to a warm standby (relay or alternate interface) | ~1 RTT | A standby exists |
| 3. Re-probe the peer's last-known `Endpoint` set from cache | 1–2 RTT | Cached endpoints not older than the soft TTL |
| 4. Re-allocate a relay from the cached signed relay map and rendezvous there | 2–3 RTT | Works with the control plane **down** (I5) |
| 5. Full `DISCOVERING` → `NEGOTIATING` → `CONNECTING` cycle | seconds | Everything cheaper failed |

Steps 1–4 require no control-plane interaction at all. This ordering is the reason a roam or a
suspend/resume typically restores traffic in well under a second while a genuine topology
change takes a few seconds.

### 6.3 Retry budgets and circuit breaking

Unbounded retry is the mechanism by which a partial outage becomes a total one. TwinVPN
budgets retries client-side.

| Mechanism | Specification |
|---|---|
| **Budget** | A token bucket per *target class* (`control-plane`, `relay:<RelayId>`, `region:<RelayRegion>`, `peer:<DeviceId>`). Refill = 20% of the observed success rate for that class, with a floor of 3 tokens/min and a burst of 10. A retry costs one token; a first attempt costs none. When the bucket is empty, `EV_RETRY_BUDGET_EXHAUSTED` fires. |
| **Rationale** | Tying the retry rate to the *success* rate means a healthy target tolerates aggressive retry while a failing one is protected. The floor guarantees that a target which is failing 100% still gets probed often enough to notice recovery. |
| **Circuit breaker** | Per target. **Open** after 5 consecutive failures or budget exhaustion. **Half-open** after one decorrelated-jitter delay, admitting exactly one probe. **Closed** after 2 consecutive successes. While open, the target is **penalised such that it cannot be selected while any non-breakered candidate exists, and is admitted as the half-open probe only when every candidate's breaker is open** ([ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.3 rule 3, which implements this as a −400 score penalty). Earlier drafts said "skipped entirely by selection"; that is withdrawn, because selection is a **total ordering, never a filter** — an empty candidate set is not a legal output of selection while the map is non-empty, and a relay whose breaker is open is still better than no relay at all. When every breaker is open, selection returns the highest-scoring candidate as the half-open probe and emits `RELAY.SELECT.ALL_BREAKERS_OPEN`. A **first** attempt on a newly selected target is never suppressed and costs no token, which is what keeps the fleet explorable. |
| **Interaction with reason codes** | The breaker keys on the code's `class` field (§3.1). A `PERSISTENT` code opens the breaker for its named `retry_precondition` rather than for a duration; a `FATAL` code opens it permanently — retrying an `EV_AUTH_REJECTED` on a timer is pure waste. A `POLICY` code does not open a breaker at all: it routes to `BLOCKED` via T29, where the re-establishment loop keeps running. |
| **Global brake** | If breakers are open for more than half of the reachable relay set, the client stops relay retries entirely for 60 s and reports `RELAY.FLEET.UNREACHABLE`, because at that point the problem is almost certainly the local network, not the relays. This prevents a firewalled client from hammering the whole fleet. |

### 6.4 Dead-peer detection

Liveness is **bidirectional and authenticated**. Specifically:

- A path is `LIVE` only if an authenticated packet from the peer, on that path, has been
  received within `T_DEAD`, **and** the peer has acknowledged our traffic within `T_DEAD`.
  Unidirectional evidence (we can hear them, or we sent something that was not rejected) is
  explicitly not sufficient. Half-open paths — where one direction works and the other does
  not — are a common NAT and firewall failure and are the classic cause of "connected but
  nothing loads".
- Heartbeats are authenticated with the `Session`'s transport keys ([ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)),
  so an off-path attacker can neither forge liveness nor forge death.
- User data counts as liveness evidence. Heartbeats are suppressed when data has flowed within
  the interval, so an active tunnel pays no heartbeat cost at all.
- Detection escalates rather than jumping: `LIVE → SUSPECT` (start probing alternates, do not
  touch traffic) `→ DEAD` (migrate or reconnect). The `SUSPECT` stage is what allows the
  common case to be repaired before the user notices.

### 6.5 Session resumption — what survives, what does not

This table is a contract. Anything in the "survives" column that the implementation tears down
is a defect.

| Item | Path change / roam / addr change | Relay failover | Process restart | Suspend > rekey window | Credential expiry |
|---|---|---|---|---|---|
| `Session` identity (path-independent) | survives | survives | **survives** (durable, S-12) | survives | survives |
| `DeviceIdentity` / `DeviceKey` | survives | survives | survives (in platform secure storage, I4) | survives | survives (key), credential must renew |
| Negotiated `ProtocolVersion` + `Capability` set | survives | survives | re-negotiated | survives | survives |
| Inner `TwinNet` IPv4 **and** IPv6 addresses | survives | survives | survives (stable per `Device`) | survives | survives |
| Installed `Route` / `DNSPolicy` | survives (re-asserted) | survives | survives (enforcement outlives the process) | survives, re-asserted on resume | survives |
| Transport (data) keys | survives | survives | **lost** | **lost** (rejected after the rekey window) | survives until session end |
| Anti-replay window | survives | survives | lost | lost | survives |
| Application TCP/QUIC connections inside the tunnel | **survive** — this is the point | **survive** | lost | lost | survive |
| Relay allocation / `SessionTag` | released and re-allocated | re-allocated | lost | lost | survives |
| Reflexive `ConnectionCandidate`s | invalidated, re-gathered | unaffected | lost | invalidated | unaffected |
| Path RTT baseline, PMTU, congestion estimates | **reset** (they are properties of the path, not the session) | reset | lost | reset | unaffected |
| Packets in flight | lost on break-before-make; preserved on make-before-break | lost during the cutover gap | lost | lost | unaffected |

The load-bearing consequence: **a roam, an IP change, or a relay failover must not break an
in-progress SSH session, file transfer, or video call**, because the inner addresses and the
transport keys both survive. A process restart or a long suspend unavoidably does break them,
because the ephemeral key material is gone — and the honest design response is to make
re-establishment fast (§6.2 step 1–4) rather than to keep long-lived key material somewhere it
should not be.

**What a process restart does *not* lose is the `Session` itself.** `Session` identity and the
last `ConnectionState` are durable local state with exactly one writer (S-12), so a restarted
client resumes into `RECONNECTING` for each known peer rather than starting from
`DISCONNECTED` — which is what makes the diagnostic continuous across a crash and what
[docs/architecture.md](architecture.md) §3.4, [ADR-0009](adr/ADR-0009-state-consistency.md) and
[ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) all rely on. What is
lost is everything *cryptographic and per-path*: transport keys, the anti-replay window, the
relay allocation, and therefore the inner TCP flows. An earlier draft of this table marked
`Session` identity "lost" on process restart; that was a defect against S-12 and is corrected
above.

### 6.6 Keepalive policy and the mobile battery tradeoff

Keepalives serve two distinct purposes that are often conflated, and separating them is what
makes a sane mobile policy possible:

1. **NAT binding maintenance** — keeping the outer mapping alive so the peer can reach us
   unsolicited. Required only for `WAN_DIRECT` behind NAT.
2. **Liveness detection** — noticing that a path died. Required for all paths, but only at a
   cadence proportional to how quickly we need to notice.

The honest cost analysis on cellular:

| Cadence | Packets/day/peer | Radio behaviour | Verdict |
|---|---|---|---|
| 25 s (the `T_NAT_KEEPALIVE` start) | 3,456 | The LTE/NR RRC connected-state tail is typically 5–10 s. A 25 s cadence still wakes the radio roughly every tail-and-a-half, all day. | **Unacceptable in background**, and it is the *most conservative* rung of the ladder — the reason the ladder climbs to 120 s wherever the network allows. This single choice is the difference between a VPN that costs a few percent of battery per day and one users uninstall. |
| 30 s | 2,880 | Radio wakes ~2,880 times/day, each with a tail. Still dominant over the device's own traffic. | Unacceptable in background |
| 60 s, coalesced | 1,440 wakes shared across **all** peers | One wake serves every `Session`, because keepalives for all peers are aligned into a single window. | Acceptable only when the user has an active reason to be reachable |
| None (park) | 0 | Radio sleeps normally. NAT bindings expire. Re-establishment costs 1–3 RTT on next use. | **Default for background with no inbound requirement** |

The resulting policy:

- **Coalescing is mandatory.** All keepalives across all `Session`s and the relay session are
  aligned to a single periodic wake window. N peers must cost one radio wake, not N.
- **Adaptive binding-lifetime estimation.** Rather than guessing, the client measures. It
  starts at `T_NAT_KEEPALIVE` = **25 s**, lengthens the interval additively along the ladder
  **25 → 35 → 50 → 70 → 100 → 120 s** while bindings survive, caps at **120 s**, and on an
  observed `NAT.MAPPING_EXPIRED` **reverts to the last known-good rung** rather than halving —
  the last rung that actually worked is a measurement, and half of the current rung is a guess.
  The learned lifetime is cached **per network fingerprint** (gateway MAC + BSSID + reflexive
  /24), so rejoining a known network starts at the right cadence immediately instead of
  relearning it. These are `docs/networking.md` §3.5's and
  [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md)'s values, registered in §5.2. An earlier
  draft of this section carried a 15 s start with a 15 → 25 → 40 → 60 ladder and halving; that
  is **withdrawn** — two documents agreed on the other values, and they are the pair that carry
  the per-network-fingerprint learning this bullet depends on.
- **Background parking.** When the app is backgrounded and no peer has declared an inbound
  reachability requirement, TwinVPN stops NAT keepalives entirely and accepts binding loss.
  This is the honest engineering answer: a UDP NAT binding cannot be held open at acceptable
  battery cost on a modern mobile OS. The design response is to make wake-to-traffic fast
  (target < 300 ms, §11) rather than to pretend otherwise.
- **The exception that must be preserved.** A device acting as a `LANGateway` or `ExitNode`,
  or one the user has marked as "always reachable", keeps a maintained path. On mobile, that
  path is held by the **relay** rather than by a raw NAT binding, because a relay session can
  be kept alive through OS-sanctioned mechanisms far more cheaply than a UDP mapping can
  (§11).
- **Data suppresses keepalives.** Any authenticated packet resets the timer. An active tunnel
  never sends a keepalive.

---

## 7. Path probing, migration, and degraded mode

This section specifies how a `Session` finds a better `Path`, notices a worse one, and moves
between them without a teardown. It owns the **timers, the transitions, and the dwell rules**.
It does **not** own the scoring weights, the validation handshake, or the NAT mechanics:
`docs/networking.md` §3–§4 owns those and is consumed here unchanged, and
[ADR-0004](adr/ADR-0004-nat-traversal-strategy.md) owns candidate gathering.

### 7.1 What is probed, and how often

Five probe loops run at different cadences for different reasons. Conflating them is how
implementations end up either slow to notice failure or ruinous on battery.

| Loop | Cadence | Purpose | Runs in states |
|---|---|---|---|
| **Liveness heartbeat** (end-to-end, authenticated, bidirectional) | `T_HEARTBEAT_ACTIVE` 3 s foreground-active; `T_HEARTBEAT_IDLE` 15 s after 60 s with no user traffic; background profile in §11 | Detect that the carrying `Path` died (§6.4). Suppressed entirely by user data. | all steady states, `MIGRATING`, `DEGRADED` |
| **Relay leg `PING`/`PONG`** (device↔relay, independent of any half-flow) | coalesced with the keepalive wake window | Attribute failure to the *relay* rather than to the peer. `T_LEG_DEAD` = 3 missed (§5.2). | `RELAYED`, and wherever a standby leg is held |
| **NAT binding keepalive** | `T_NAT_KEEPALIVE` ladder, 25 → 120 s, per network fingerprint (§6.6) | Hold the outer mapping so the peer can reach us unsolicited. Only needed for `WAN_DIRECT` behind NAT. | `WAN_DIRECT` |
| **Alternate-candidate prober** | idle while healthy; **immediately on `EV_PATH_SUSPECT`** (T18); continuously while `DEGRADED` | Have a validated alternate ready *before* it is needed. This is what turns a would-be disconnect into a sub-second migration. | `LOCAL_DIRECT`, `WAN_DIRECT`, `RELAYED`, `DEGRADED` |
| **Direct-upgrade prober** | decaying ladder 1, 2, 4 … capped at 60 s, reset on any network-change event (`docs/networking.md` §4.4); floor `T_UPGRADE_PROBE_BG` = 300 s in mobile background, aligned to the coalesced wake | Escape a relay when a direct path becomes possible. | `RELAYED`, `DEGRADED{RELAYED}` |

Two rules bind all five:

- **Coalescing is mandatory.** Every loop that must wake the radio aligns to the single periodic
  wake window (§6.6, §11). N peers cost one wake, not N.
- **A hard signal pre-empts every timer.** `EV_LINK_DOWN`, a socket error, an ICMP/ICMPv6
  unreachable, or an OS network-change notification acts immediately; the cadences above are the
  backstop for networks that fail silently (R2).

### 7.2 The candidate ledger, and why a relay path is warm behind a direct one

Every `Session` keeps a **candidate ledger**: every `ConnectionCandidate` gathered, every probe
result, and for each the reason it is not currently carrying traffic. The ledger is `LOCAL`,
in-memory state (S-14), is the substrate for the connectivity report
([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) O-06), and MUST be producible with no
network and with the control plane down (O-07).

Relay allocation begins at **t = 0, concurrently with direct probing** — never after a direct
timeout ([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.4,
[ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.3 rule 4). The consequence used
throughout §2.2 is that a `WAN_DIRECT` path established through relay-assisted setup already has
a warm relay behind it, so `WAN_DIRECT → MIGRATING → RELAYED` on direct-path death is sub-second
rather than a fresh allocation. Where the direct path was found without relay assistance (LAN
discovery, cached endpoint), the `WAN_DIRECT` invariant in §4.4 still requires an alternate that
is *warm or re-establishable within `T_FAILOVER_TARGET`*; ADR-0006 §11.6 satisfies that with a
**leg-only** standby, which costs one `BIND` RTT rather than a full allocation.

### 7.3 Interface migration and the hysteresis rule

An interface change is the most common migration trigger on a real device, and the most common
source of the "random disconnect" this product exists to eliminate. Two failure shapes matter and
they need opposite treatments.

| Shape | Example | Treatment |
|---|---|---|
| **The old link dies with no overlap** | Wi-Fi drops abruptly in a lift | Break-before-make is unavoidable. `EV_LINK_DOWN` fires within ~100 ms (R2); T19 to `MIGRATING` if another interface is up, T20 to `RECONNECTING` if not. The cost is the packets in flight, and inner TCP retransmits them. |
| **A new link appears while the old one still works** | Cellular → Wi-Fi on walking into a building; docking a laptop | **Make-before-break, and never switch on interface-up alone.** |

**The hysteresis rule (normative).** A newly available interface MUST NOT take over traffic until
**all** of the following hold:

1. `PATH_VALIDATED` on the new path — an authenticated end-to-end challenge-response, **not** a
   reachability check. This is what rejects captive-portal Wi-Fi, which looks perfectly usable to
   the OS and is not.
2. `PATH_BETTER` — the new path beats the active one by ≥ 15 points **and** ≥ 10 ms RTT.
3. `PATH_STABLE` — `PATH_BETTER` held continuously for ≥ 3 probe intervals (default 15 s).
4. Policy permits the interface: metered-link and battery policy may require explicit consent
   before using cellular, which is a deliberate, **announced** pause, never a silent refusal.

Wi-Fi that is associated but not yet usable is the classic cause of the mid-sentence video-call
freeze; conditions 1 and 3 exist specifically to refuse it. Migration across address families
(v4 Wi-Fi → v6-only cellular and back) is a first-class case, not an exception: the candidate
carries its `family`, both families are kept as live alternates, and **PMTU is re-probed on every
migration** because a v6 path commonly has a smaller effective MTU and a stale MTU is a leading
cause of "connects but nothing loads".

An address change on the *same* interface (DHCP renewal, RA prefix change, IPv6 privacy-address
rotation, VPN-on-VPN) is T21, not a new-interface case: sockets re-bind, reflexive candidates are
re-gathered, and validation runs from the new address before anything commits. The peer learns
the new `Endpoint` **from the validated probe itself**, never from the control plane — which is
why roaming works with the control plane down (I5). A validated address change under a live
`Session` MUST be accepted as the same peer, not treated as a new one.

### 7.4 Promotion, demotion, and the scoring inputs behind them

#### Scoring inputs

Ranking is `docs/networking.md` §4.1's; the **weights are its to set and are not restated here**.
What this document fixes is *which* inputs are admissible and what may never be one:

| Input | Source | Admissible as |
|---|---|---|
| Candidate class (`LOCAL_DIRECT` > `WAN_DIRECT` > `RELAYED`) | local | base score |
| EWMA RTT, RTT variance | authenticated `PING`/`PONG` and keepalive timing | penalty |
| Loss | probe sequence gaps + data-plane counters, sliding 30 s | penalty |
| Jitter | keepalive inter-arrival variance | penalty |
| Throughput | **passive** measurement under real offered load only — no synthetic bandwidth test is ever run on a user path | penalty, valid only under load |
| Stability | seconds since the last validation failure | bonus |
| Address family | IPv6 preferred on ties | bonus |
| Circuit-breaker state | this device's own consecutive failures (§6.3) | large penalty — **never a filter** (§6.3, ADR-0006 §11.3 rule 3) |
| Relay `HealthState` (S-10), peer presence (S-11), relay-set age (S-09) | control plane, `EVENTUAL` | score delta **only**; MUST NOT suppress an attempt (§4.1) |

The last two rows are the load-bearing ones. **No `EVENTUAL` fact may gate a connection
attempt.** Only a `Path` proves reachability; everything else is a hint, and a device's own
measurement always outranks a reported one.

#### The mechanism

Promotion (moving to a better path class) and demotion (falling back to a worse one) are the same
transition machinery with deliberately **asymmetric** guards: promotion is slow and sceptical,
demotion on a hard signal is immediate.

```text
                 PATH_VALIDATED ∧ PATH_BETTER ∧ PATH_STABLE          promotion
  RELAYED ──────────────────────────────────────────────────────────────────────►  WAN_DIRECT
     ▲            (T13/T14 → MIGRATING → T15)                                          │
     │                                                                                 │
     │   hard: PATH_FAILING ∨ EV_LINK_DOWN ∨ socket error   ── immediate, never ────────┤
     │         (T19 if an alternate exists, T20 if not)        suppressed               │
     │                                                                                 │
     └── quality-only demotion: refused for T_UPGRADE_DWELL (120 s) after a promotion ──┘
```

Guards, consumed unchanged from `docs/networking.md` §4.3:

| Guard | Satisfied when |
|---|---|
| `PATH_VALIDATED` | ≥ 2 successful authenticated `PING`/`PONG` on the candidate pair within 500 ms of each other |
| `PATH_BETTER` | candidate score exceeds the active path's by **≥ 15 points and ≥ 10 ms** RTT improvement |
| `PATH_STABLE` | `PATH_BETTER` held continuously for ≥ 3 probe intervals (default 15 s) |
| `PATH_FAILING` | 3 consecutive missed keepalives, or loss > 15 % over 10 s, or a data-plane send error |
| `DIRECT_UPGRADE_ELIGIBLE` | `PATH_VALIDATED ∧ PATH_BETTER ∧ PATH_STABLE` ([ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.10(3)) |

**Reconciling `PATH_FAILING` with `T_SUSPECT`/`T_DEAD`.** These count the same missed heartbeats
at three different thresholds, and they are not in conflict once their jobs are named:

| Missed heartbeats | Threshold | What it authorises |
|---|---|---|
| 2 (`T_SUSPECT`, 6 s) | `EV_PATH_SUSPECT` | Start probing alternates. **Do not touch traffic** (T18). No state change. |
| 3 (`PATH_FAILING`) | demotion eligibility | A *promoted* path may be demoted back to its previous class now, without waiting for death — but only to a path that is already validated. |
| 5 (`T_DEAD`, 15 s) | `EV_PATH_DEAD` | Migrate (T19) or reconnect (T20). |

`docs/networking.md` §4.3 should record that `PATH_FAILING` is the middle rung and not a synonym
for path death; as written it reads as though 3 missed keepalives killed a path, which would
contradict `T_DEAD`.

**Anti-flap, and its one exception.** After a `RELAYED → WAN_DIRECT` promotion, a **quality-only**
reverse migration is refused for `T_UPGRADE_DWELL` (120 s). A **hard** failure signal is never
suppressed by dwell, by flap suppression, or by cooldown — anti-flap must never trap a `Session`
on a dead path. If a pair oscillates ≥ `N_UPGRADE_FLAP` (3) times within
`T_UPGRADE_FLAP_WINDOW` (10 min), the direct candidate is suppressed for
`T_UPGRADE_FLAP_SUPPRESS` (30 min) **on that network fingerprint only**, emitting
`RELAY.UPGRADE.FLAPPING_SUPPRESSED`; any network change clears it.

### 7.5 `T_MIGRATE` and `T_MIGRATE_COOLDOWN`

| Constant | Semantics |
|---|---|
| `T_MIGRATE` (3 s) | The **total budget for one migration attempt**, measured from entry to `MIGRATING` to `EV_PATH_VALIDATED{to}`. It bounds validation, not the probe cadence inside it — `docs/protocol.md` §12.2 sets the 500 ms probe cadence, and probes continue until the budget expires. On expiry: T16 back to `from` if the old path is alive, T17 to `RECONNECTING` if it is not. |
| `T_MIGRATE_QUEUE` (100 ms / 64 packets) | The bounded make-before-break queue, used **only** when the old path is already gone. Drop-oldest on overflow. Deliberately tiny: queueing more than ~100 ms damages inner congestion control more than the loss it prevents. |
| `T_MIGRATE_COOLDOWN` (60 s) | **Per-candidate**, applied on a *failed* migration (T16), not on a successful one. The candidate is not deleted — it stays in the ledger with its failure reason and is re-eligible after the cooldown. Cooldown does not survive a network-change event: a new network is new evidence. |

`MIGRATING` is bounded by construction: it can only exit via T15 (committed), T16 (back to
`from`), or T17 (`RECONNECTING`). There is no path by which a `Session` sits in `MIGRATING`
indefinitely, which is R5 discharged for this state.

### 7.6 Degraded mode

`DEGRADED{carrier}` is the state for a **quality** violation while traffic continues to flow. It
is never used for a policy violation (that is `BLOCKED`, R6) and never for "nothing is flowing"
(that is `RECONNECTING` or `BLOCKED` — [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md)
§11.8 relies on this distinction).

| Property | Rule |
|---|---|
| Entry | T22, on `EV_QOS_VIOLATION{m}` sustained ≥ `T_QOS_CONFIRM` (10 s) against a §5.4 threshold. The measured value **and** the threshold are attached as evidence. |
| Exit, recovered | T23, on restoration sustained ≥ `T_QOS_CLEAR` (30 s). Asymmetric with entry on purpose: slow to leave prevents flapping. |
| Exit, escalated | T24, at `T_DEGRADED_MAX` (10 min) → `RECONNECTING`. A full re-establishment cycle often finds a path the incremental prober will not. This is R5: no unbounded degradation. |
| While in it | The alternate-path search runs continuously. All the carrier's timers keep running. Traffic keeps flowing on the carrier throughout. |
| Presentation | `DEGRADED` MUST be visually distinct from connected in **every** surface — GUI, CLI, tray, headless status, router status page. Rendering it as connected is a defect, not a UX choice ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.6). |

**Trust staleness does NOT enter `DEGRADED`, and this is deliberate.** An earlier draft of this
section said it did. That is **withdrawn**, for three reasons, each of which is a property of
`DEGRADED` stated above:

1. R6 reserves `DEGRADED` for **measured quality** violations, never policy or security
   conditions. Trust staleness is a security condition with no measured value to attach.
2. T22 is the **only** entry to `DEGRADED` and it requires `EV_QOS_VIOLATION{metric}` against a
   §5.4 threshold. There is no event and no transition that could carry trust staleness into it,
   so the earlier claim named a state the machine cannot reach that way.
3. T24 forces `DEGRADED → RECONNECTING` at `T_DEGRADED_MAX` (10 min). A trust-stale `Session`
   would therefore be kicked into re-establishment every ten minutes for up to thirty days, and
   could never re-enter, because T22's trigger never fires. That is a functional defect, not a
   wording problem.

The correct mechanism is the one [ADR-0009](adr/ADR-0009-state-consistency.md) §11.4 defines:
trust staleness produces a **persistent `Diagnostic`** (`AUTH.TRUST_STATE_STALE`, then
`AUTH.TRUST_STATE_EXPIRED`) and sets the guard input `trust_state_expired`, with **no
`ConnectionState` change at all**. [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7
states this correctly and is the authority. What the user sees is a persistent staleness
indication, not a degraded tunnel — because the tunnel genuinely is not degraded; the authority
behind it is stale, and §9.4 owns how that is worded.

### 7.7 Guard inputs consumed from other ADRs

The state machine consumes four guard inputs it does not itself compute. Each is a boolean set by
its owning subsystem and read by an existing transition; **none introduces a state or a
transition** ([ADR-0009](adr/ADR-0009-state-consistency.md) §11.10).

| Guard input | Set by | Read by | Effect |
|---|---|---|---|
| `policy_grant_expired` | [ADR-0009](adr/ADR-0009-state-consistency.md) §11.4, on a `PolicyBundle` past its `not_after_ms` | T29 | Grants carried by that bundle suspend; denials persist. A grant withdrawal that would leave protected traffic unprotected drives T29 → `BLOCKED` (**I3**). |
| `trust_state_expired` | [ADR-0009](adr/ADR-0009-state-consistency.md) §11.4, at `T_TRUST_HARD` | T29 | Every *granted* authority — `ExitNode` egress, `LANGateway` access, `Route` acceptance, new `Pairing` — suspends. **Baseline reachability to a known `TrustedPeer` is untouched**, so this MUST NOT by itself drive `BLOCKED` or `FAILED` (**R-11**). Effective suspension time for any grant is `min(bundle not_after_ms, T_TRUST_HARD)`. |
| `trust_epoch_behind` | [ADR-0009](adr/ADR-0009-state-consistency.md) §11.6 G-2, on observing a peer at a higher epoch | none — diagnostic only | Escalates refresh. MUST NOT refuse a handshake on this basis alone; the peer is not an authority. |
| `cursor_unavailable` | [ADR-0009](adr/ADR-0009-state-consistency.md) §11.4 | none — diagnostic only | Surfaces that the control-plane read cursor could not be validated. Never a gate. |

---

## 8. Relay failover and multi-region failover

**This section consumes [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md); it does not
re-decide any of it.** ADR-0006 §11.15(b)–(c) asks for exactly that, and the request is
**confirmed**. The division is:

| Owned by [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) | Owned here |
|---|---|
| Which relay is selected, and the scoring that orders the whole candidate set (§11.2, §11.3) | The `ConnectionState` transitions the outcome takes (§4.5) |
| Failure attribution — relay vs peer vs link vs region vs capacity (§11.4) | The timers those attributions read: `T_LEG_DEAD`, `T_SUSPECT`, `T_DEAD`, `T_MIGRATE`, `T_STANDBY_WARM`, `T_FAILOVER_TARGET` (§5) |
| The failover mechanism itself: `PathOffer`/`PathAck` over the standby flow, HRW convergence when both sides are cold, epoch-conflict resolution (§11.5) | Backoff regimes, retry budgets, and circuit breaking that the mechanism composes with (§6.1–§6.3) |
| Warm-standby policy: when a standby is bound and which relay it is (§11.6) | `T_STANDBY_WARM` = 30 s, and the `RELAYED` per-state invariant that requires a standby at all (§4.4) |
| Multi-region ordering and the three stampede controls (§11.7) | `T_REGION_SPREAD` = 20 s (§5.3), and the correlated-failure detector in §2.1 |
| Total-fleet-unavailability definition and codes (§11.8) | Which state results — `BLOCKED` under `FAIL_CLOSED`, `RECONNECTING` → `FAILED` under `PERMISSIVE_ANNOUNCED` (T20/T26/T27) |

### 8.1 Warm standby, and the transitions failover takes

A `Session` that has been `RELAYED` for `T_STANDBY_WARM` (30 s) holds a standby relay session in
a **different failure domain** from the primary; gateway-class and always-reachable devices bind
one immediately with no dwell. A standby whose keepalive has been stopped is **not warm and MUST
NOT be reported as one** — this matters on parked mobile (§11), where ADR-0006 §11.6 releases it.

The transition sequence is fixed and is asserted by
[docs/testing-strategy.md](testing-strategy.md) P03:

```text
RELAYED ──EV_RELAY_GONE (T19, warm alternate exists)──► MIGRATING{RELAY→RELAY'} ──T15──► RELAYED
```

It MUST NOT pass through `DISCONNECTED` or `RECONNECTING`, MUST NOT change `session_id`, and MUST
NOT destroy `Tunnel` key state, counters, the replay window, or the inner addresses. If no
standby exists, this is T19 only when *some* validated or warm alternate exists; otherwise it is
T20 to `RECONNECTING` with `NET.PATH.DEAD_NO_ALTERNATE` and `RELAY.FAILOVER.NO_STANDBY` as
evidence.

### 8.2 Multi-region failover

Region failure introduces **no new event and no new transition**: it is `EV_RELAY_GONE` per
affected `Session` plus ADR-0006's `RELAY_REGION_FAILED` guard, which changes only *which* target
is selected. Detection is §2.1's correlated-failure detector (≥3 relays in one `RelayRegion`
within 30 s, or the region's anycast bootstrap silent on **both** families).

What this document contributes to the stampede problem is the timing, not the algorithm:

- Devices holding a **bound** standby move **immediately** — their capacity was accounted at bind
  time, so their move requests nothing new. Delaying them serves nobody.
- Devices that must **acquire** new capacity draw their start time from
  `uniform(0, T_REGION_SPREAD)` with `T_REGION_SPREAD` = 20 s (§5.3), emitting
  `RELAY.REGION.SHED_DEFERRED` so the deferral is visible rather than looking like a hang.
- Retries during a region failover use the **infrastructure** decorrelated-jitter regime (§6.1),
  never the interactive one. This is the case that regime was chosen for: a failure correlated
  across the whole fleet, where attempt-number-keyed backoff re-synchronises clients at every step.
- §6.3's **global brake** applies unchanged: with breakers open on more than half the reachable
  relay set, relay retries stop for 60 s and the condition is reported as
  `RELAY.FLEET.UNREACHABLE`, because at that point the problem is almost certainly the local
  network.

Cross-region recovery is **working-but-worse and is announced as such**:
`RELAY.FAILOVER.CROSS_REGION` carries the added RTT. It may cross §5.4's 250 ms relay threshold
into `DEGRADED`, which is the honest outcome — a distant relay is not a broken tunnel and must
not be reported as one.

### 8.3 Herd-safe drain

A planned relay drain is not a failure and MUST NOT be handled as one. On
`EV_RELAY_DRAINING{deadline}`, T37 schedules the migration at a time drawn uniformly from
`[0, deadline − 60 s]`, so a fleet leaving a draining relay spreads itself across the drain
window instead of arriving at its replacement together. The 60 s reserve exists so that a device
whose migration fails still has a full `T_MIGRATE` budget and one retry before the deadline.

### 8.4 When there is no relay at all

`RELAY.FLEET.UNREACHABLE` — no relay in the verified map reaches a bound flow, across all
carriages and both families, after the `region:` retry budget is exhausted:

| Situation | State | Why |
|---|---|---|
| A direct `Path` is carrying traffic | **no state change**; `RELAY.STANDBY_UNAVAILABLE` informational | Nothing is broken; the failover posture is weaker, and that is stated in advance rather than discovered at failover |
| No path at all, `FAIL_CLOSED` | **`BLOCKED`** (T26) | `BLOCKED` retries forever at the floor rate, which is right: the fleet will return, and abandoning recovery would strand the user (I3) |
| No path at all, `PERMISSIVE_ANNOUNCED` | `RECONNECTING` until `T_RECONNECT_MAX`, then **`FAILED`** (T27) | Bounded, because burning battery forever on an announced-unprotected device helps no one |

**`DEGRADED` MUST NOT be used for this condition.** `DEGRADED` means traffic is flowing; here
nothing is. Confusing the two is how a product ends up showing "connected" while nothing works.

---

## 9. Surviving a control-plane outage (invariant I5)

I5 says the data plane outlives the control plane. This section states exactly what that buys,
what it does not, and where the line falls — because an invariant that is not enumerated is an
invariant that gets eroded one convenience at a time.

### 9.1 The three-way split

| Continues, indefinitely | Degrades, visibly | Refused, with a named precondition |
|---|---|---|
| Every established `Session`: keepalive, liveness, rekey, PMTU, path migration, relay failover | Trust state ages: persistent `Diagnostic` `AUTH.TRUST_STATE_STALE` at `T_TRUST_STALE` (24 h), **no `ConnectionState` change** (§7.6) | New `Pairing` with a device that is not already a `TrustedPeer` |
| **New** `Session`s to an existing `TrustedPeer`, from the durable `Endpoint` cache (S-15) and the cached signed `RelayMap` (S-09) | Policy documents age: `CONTROL.STALENESS.DOCUMENT_STALE`, then grants suspend per [ADR-0009](adr/ADR-0009-state-consistency.md) §11.4 | First contact with a **never-before-connected** peer, when neither device is on the same LAN |
| Relay admission: a `Relay` renews the `RelayCapabilityToken` itself while the token's epoch equals the relay's `epoch_floor` ([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.3) | Relay map ages: `CONTROL.STALENESS.RELAY_SET_EXPIRED`, with **no enforcement effect whatsoever** — a stale map is used, never blocked on | Elevated authority past `T_TRUST_HARD` (30 d): `ExitNode` use, `LANGateway` access, `Route` acceptance, new pairing |
| Relay failover and multi-region failover, end to end, with **zero** control-plane messages ([ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §11.9) | Queued mutations pile up client-side with idempotency keys ([ADR-0008](adr/ADR-0008-idempotency.md)) and replay on recovery | Mutations that require an authoritative write: membership changes, policy edits, revocation |
| Kill-switch enforcement, which is local, durable, OS-level, and which **the control plane cannot disengage** (S-18, [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md)) | | |

### 9.2 The governing rule is grant/deny asymmetry, not a credential cliff

The rule this document consumes is [ADR-0009](adr/ADR-0009-state-consistency.md) §11.5's, jointly
owned with [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7:

> **Expiry can only ever make a device *more* restrictive. Grants suspend; denials persist.
> There is no expiry path that widens an authorization.**

Applied to a control-plane outage:

| Trust-state age | Baseline peer connectivity (a new `Tunnel` to a known `TrustedPeer`) | Elevated authority |
|---|---|---|
| < `T_TRUST_REFRESH` (6 h) | Permitted | Permitted |
| `T_TRUST_REFRESH` … `T_TRUST_STALE` (24 h) | Permitted; refresh escalates | Permitted |
| `T_TRUST_STALE` … `T_TRUST_HARD` (30 d) | Permitted; persistent `Diagnostic` `AUTH.TRUST_STATE_STALE`, **no `ConnectionState` change** | Permitted, re-asserted per use and surfaced |
| ≥ `T_TRUST_HARD` | **Still permitted** — persistent `Diagnostic` `AUTH.TRUST_STATE_EXPIRED`, **no `ConnectionState` change** | **Suspended** |

**Baseline peer connectivity survives an outage of unbounded length.** It is not a grant the
control plane makes; it is a fact two devices established between themselves, and no
control-plane silence may withdraw it. Making it withdrawable would turn the control plane into a
liveness dependency of the data plane, which is precisely what I5 and R-11 forbid.

**There is no credential-renewal cliff, and this document does not assert one.** An earlier draft
of this section stated that credential renewal falling entirely inside a multi-day outage was
unrecoverable; that statement is **withdrawn**, and any citation of it elsewhere in the corpus
should be dropped. Relay tokens are relay-renewable with no control-plane involvement
([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.3), and identity and tunnel keys rotate with
`T_IK_OVERLAP` (30 d) and `T_TK_OVERLAP` (14 d) overlap windows so that a peer which has not yet
seen a rotation still connects. What an outage costs is *authority*, not *reachability*.

### 9.3 The accepted residue, stated plainly

A device partitioned from the control plane **and** from every non-stale peer keeps accepting
**baseline** connections from a revoked peer for as long as that partition lasts. That residue is
unbounded in time and cannot be closed by any design that also satisfies R-11 — an authority you
cannot reach cannot tell you anything. It is bounded in *consequence* by the table above (the
revoked device can reach, and can do nothing privileged), and it is made observable rather than
silent by the staleness codes and the persistent user-visible staleness indication.
[docs/threat-model.md](threat-model.md) owns its analysis.

### 9.4 What the user is told

An outage is a first-class, named condition, never a connection error. `CONTROL.UNREACHABLE` is
`TRANSIENT`/`WARN` and **informational** — surfacing it as a terminal connection failure is a
defect, because the tunnel is working. The user-facing sentence is of the form:

> *Connected. TwinVPN has not reached the coordination service for 3 days; your devices still
> talk to each other normally. Exit-node access is paused until it reconnects.*

---

## 10. No silent failure

This is the section invariant I6 and requirement R-22 exist for, and the one
[ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.6(3) delegates enforcement to. The
product's founding complaint is a VPN client that says "Connected" while nothing works. The
mechanism below makes that outcome **unreachable by construction** rather than merely discouraged.

### 10.1 The state-machine-boundary rule (normative)

> **`DEGRADED`, `BLOCKED`, `RECONNECTING`, and `FAILED` are unenterable without a
> `reason_code`.** A transition into any of those four states that does not carry one is itself
> the defect `INTERNAL.INVARIANT_VIOLATED`.

Three properties make this an enforceable rule rather than a slogan:

1. **It is enforced at the state-machine boundary**, not at each call site. The transition
   function is the only way to change state, it takes the `reason_code` as a **required
   argument** for those four targets, and it is the single place the transition event is emitted.
   No code path can enter a bad state quietly, because no code path can enter any state except
   through that function.
2. **It is checkable statically.** Every row of §4.5 whose `To` column is one of the four names a
   `reason_code` in its `Actions` column. That is a property of a table, verifiable by reading it
   and by the test in §10.2.
3. **The failure mode is loud.** `INTERNAL.INVARIANT_VIOLATED` is `FATAL`/`CRITICAL` and every
   occurrence is a bug ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.2), so a
   missing code produces a defect report rather than a silent state change.

The rule that made this urgent: **an implementation that omits an emit action turns every
ordinary link-down into an invariant violation.** T20 (path dead, no alternate) and T34 (suspend,
park) are the two most frequently taken transitions in the entire machine on a mobile device, and
both target `RECONNECTING`. They now carry `NET.PATH.DEAD_NO_ALTERNATE` and
`PLATFORM.SUSPENDED` respectively (§4.5). A code-less park is not a theoretical concern; it
is what a literal reading of an earlier draft produced on every screen-off.

### 10.2 The transition event

Every transition emits exactly one:

```
TransitionEvent {
  from         : ConnectionState          # the twelve names of §4, never a free string
  to           : ConnectionState
  trigger      : Event | Timer            # EV_* or T_*: what fired, not what resulted
  reason_code  : string | null            # REQUIRED when `to` ∈ {DEGRADED, BLOCKED,
                                          #                      RECONNECTING, FAILED}
  session_id   : SessionId                # never null; durable across restart (S-12)
  path_id      : PathId | null            # null in DISCONNECTED/DISCOVERING/NEGOTIATING
  occurred_at  : timestamp                # monotonic clock, wall clock carried as evidence
}
```

Normative properties:

| # | Rule |
|---|---|
**`TransitionEvent` and `Diagnostic` are distinct records with distinct lifetimes.**
[ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.3's `Diagnostic` explains a condition
to a human; a `TransitionEvent` records that the machine moved. Where `to` ∈ {`DEGRADED`,
`BLOCKED`, `RECONNECTING`, `FAILED`}, **exactly one `Diagnostic` is emitted alongside the
`TransitionEvent`**, carrying the same `reason_code` and the same `occurred_at`; its `state_from` /
`state_to` duplicate `from` / `to` and MUST agree. E1's "never two" governs `TransitionEvent`s
only — it does not forbid the accompanying `Diagnostic`.

| E1 | Emission is a property of the **transition**, not of a call site ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) O-05, [docs/testing-strategy.md](testing-strategy.md) A-02). One transition, one event — never zero, never two. |
| E2 | `trigger` MUST distinguish transitions that share a `(from, to)` pair. T19/T20 differ only by whether an alternate exists; T16/T17 differ only by whether the old path is alive. Without `trigger` the transition-coverage merge gate cannot tell them apart, and this stream is the primary test oracle for the corpus. |
| E3 | `reason_code` MUST be a registered code (§3.1). A free-text string, an errno, or a raw exception message in this field is a defect (O-02). |
| E4 | The event MUST be produced with the control plane unreachable and with no network at all (O-07). It is local state; it does not require a collector. |
| E5 | `occurred_at` uses the **monotonic** clock, because wall clocks jump across suspend/resume — the single most common transition-producing event on a laptop. Wall-clock time rides along as evidence. **Exception (§5.3.1):** this governs *event stamping and liveness timers only*. **Long-horizon policy deadlines that bound a granted authority MUST read `ElapsedClock`** (suspend-inclusive), or better the signed validity window in the document itself — a `MonotonicClock` deadline never expires on a suspended device, which would void **R-24**. |
| E6 | The event carries no peer-pair correlation off-device (O-11, O-13). `session_id` is local. |
| E7 | A transition into `DEGRADED`, `BLOCKED`, `RECONNECTING`, or `FAILED` with `reason_code = null` MUST itself emit `INTERNAL.INVARIANT_VIOLATED` and MUST be counted as a defect, not swallowed. |

**Static test (the one that makes §10.1 a gate).** A test parses §4.5, asserts that every row
whose `To` column contains `DEGRADED`, `BLOCKED`, `RECONNECTING`, or `FAILED` names an emit
action, and asserts that every code so named exists in the registry with a `class` compatible
with the target state (`POLICY` → `BLOCKED`; `FATAL`/`PERSISTENT` → `FAILED`;
`TRANSIENT`/`PERSISTENT` → `RECONNECTING`; `TRANSIENT` → `DEGRADED`). A table edit that adds a
row without an emit action fails the build.

### 10.3 The four mechanisms silence would have to defeat simultaneously

This document owns the third; the others are consumed from
[ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.6 and
[ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md).

| # | Mechanism | Owner | What it catches |
|---|---|---|---|
| 1 | **Protection is asserted, not assumed.** The protection indicator is a pure function of a `ProtectionAssertion` produced by *querying the enforcement layer* for both families, never of the agent's belief about what it configured | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) O-17, [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) | Rules that were never installed, or were removed by something else |
| 2 | **Assertions expire.** An unrenewed assertion makes the indicator `UNKNOWN`, never `PROTECTED` | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) O-18 | A hung, crashed, killed, or suspended agent leaving a reassuring green indicator |
| 3 | **Every state entry carries a reason** | **this section** | A code path that changes state without saying why |
| 4 | **Liveness is cross-checked against belief.** A watchdog compares claimed state against data-plane counters; `WAN_DIRECT`/`LOCAL_DIRECT`/`RELAYED` with zero bytes received over a bounded interval while traffic is offered raises `NET.SILENT_PATH_SUSPECTED` and forces path validation | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.6(4) | The black hole — invisible to configuration inspection, and the residual case the other three miss |

Silence requires all four to fail at once. Each is independently testable, and none depends on
the others being correct.

### 10.4 What "no silent failure" does not promise

It does not promise that every failure is *fixable*, or that the name is always specific. It
promises that a failure is **named, attributed, and visible**, and that the name is stable enough
to search for. Where the system genuinely cannot tell which of two causes applies, it says so and
reports both, with the evidence for each — an honest ambiguity is a diagnostic; a generic error
is not.

---

## 11. Background and suspended operation

The tunnel process on a modern OS is not a process that runs. It is a process that is
allowed to run occasionally, and the OS decides. Every design in this section follows from
accepting that rather than fighting it.

> **Scope correction (F7).** This section was originally titled *"Mobile background operation"*, and
> the title caused a defect rather than merely under-describing the content. **Windows Modern
> Standby, macOS Power Nap, and ordinary laptop suspend are the same class of problem as Doze and
> App Standby**, and scoping the section to "mobile" meant the desktop cases were never checked
> against it. They are in scope here.

> **Rule R-BG-1 (normative) — who decides the device is backgrounded (F6).** This section and
> [docs/networking.md](networking.md) §5.4 both specify what the client **does** when backgrounded or
> suspended; neither previously specified **who decides that it is**. §4.3 sources `EV_BACKGROUND`
> and `EV_SUSPEND` as "OS lifecycle", which is not an implementable answer on every target:
>
> - **Windows Modern Standby fires no suspend event at all**, so §11.2's park never happens and a
>   laptop runs the **foreground** timer profile with the lid closed all night — precisely the
>   battery arithmetic §6.6 rejects, on the platform nobody checked.
> - **macOS App Nap never applies to a `LaunchDaemon`**, so the desktop authority has no
>   `EV_BACKGROUND` source whatsoever.
>
> Therefore: the event source is **per platform and MUST be named**, and where the OS provides none
> the authority MUST **synthesize** the event rather than silently remain in the foreground profile.
> [ADR-0022](adr/ADR-0022-application-lifecycle-and-background-execution.md) LC-23a owns the
> per-platform source table and the synthesis rule; this document owns the profile that results.
>
> **Rule R-BG-2 (normative).** Correctness-bearing lifecycle events — network change, suspend,
> resume, Doze entry/exit, on-demand wake, address change, `onRevoke` — MUST be delivered to, or
> observable by, **the process holding authority**, and MUST NOT be routed through or conditioned on
> an unprivileged UI process. Routing them through the UI makes "UI dead, authority alive" a
> functional outage on exactly the platforms where it is least visible.

### 11.1 The background timer profile

| Timer | Foreground | Background | Parked (backgrounded, no inbound requirement) |
|---|---|---|---|
| Liveness heartbeat | `T_HEARTBEAT_ACTIVE` 3 s / `T_HEARTBEAT_IDLE` 15 s | 60 s, coalesced across **all** `Session`s | none |
| NAT binding keepalive | `T_NAT_KEEPALIVE` ladder 25 → 120 s | ladder continues, coalesced | **stopped** — the binding is allowed to expire |
| Relay leg `PING` | coalesced | coalesced | relay leg held only for a gateway/exit/always-reachable role, otherwise released |
| Direct-upgrade prober | 1, 2, 4 … 60 s | floor `T_UPGRADE_PROBE_BG` = 300 s, aligned to the wake window | none; restarts event-driven on wake |
| Quality sampling | continuous | on wake only | on wake only |
| PMTU probe | on establish/migrate | on migrate only | on wake, after validation |

`EV_BACKGROUND` and `EV_FOREGROUND` switch timer profiles. `EV_FOREGROUND` is never a state transition, and `EV_BACKGROUND` is not one **while any peer has declared an inbound reachability requirement** (T36). When none has, `EV_BACKGROUND` parks the `Session` via T34 — a real transition to `RECONNECTING` carrying `PLATFORM.BACKGROUND_SUSPENDED`, because a park that entered `RECONNECTING` without a code would be exactly the silent entry §10 exists to make impossible.
`EV_FOREGROUND` additionally triggers an immediate liveness probe, so the first thing a user sees
on unlocking is a fresh answer rather than a stale one.

### 11.2 Parking, and why it is the honest answer

**A UDP NAT binding cannot be held open at acceptable battery cost on a modern mobile OS.** §6.6
does the arithmetic: a 25 s cadence is ~3,456 radio wakes per day, each with an RRC tail, and
that is before any other app runs. The design response is not a cleverer keepalive; it is to stop
pretending the binding can be held, and to make re-establishment cheap:

- When the app is backgrounded and **no peer has declared an inbound reachability requirement**,
  NAT keepalives stop entirely and binding loss is accepted. The `Session` is *parked*, which is
  `RECONNECTING` with `PLATFORM.BACKGROUND_SUSPENDED` — a named, expected condition, not a fault.
- A device with a `LANGateway`, `ExitNode`, or user-marked always-reachable role keeps a
  maintained path, held by the **relay** rather than by a raw NAT binding, because a relay session
  can be kept alive through OS-sanctioned mechanisms far more cheaply than a UDP mapping can.
- A standby relay whose keepalive is stopped is **not warm** and MUST NOT be reported as one
  (§8.1). The failover posture on parked mobile is genuinely weaker, and saying so is the point.

### 11.3 Wake-to-traffic

Every wake is treated as *"assume the world changed"*. The sequence, in order, with the cheapest
step first (this is §6.2's ladder specialised for wake):

```text
wake ─► re-read interfaces + addresses + default routes (v4 and v6)
     ─► re-assert Route / DNSPolicy / firewall rules       [enforcement first, always]
     ─► compare **`ElapsedClock`** delta against the rekey window   [§5.3.1 — NOT wall clock]
     ─► 1. re-validate the existing path from a possibly-new local address   ~1 RTT
        2. cut over to a warm standby, if one survived                       ~1 RTT
        3. re-probe the peer's cached Endpoint set (S-15)                    1–2 RTT
        4. re-allocate a relay from the cached signed RelayMap               2–3 RTT
        5. full DISCOVERING → NEGOTIATING → CONNECTING                       seconds
     ─► emit NET.SESSION.RECOVERED with the outage duration
```

**Target: traffic flowing within 300 ms of wake on a surviving path** (step 1 or 2). Steps 1–4
require **no control-plane interaction at all**, which is what makes the target achievable on a
network the device has seen before.

Two rules make the sequence safe rather than merely fast:

- **Enforcement is re-asserted before traffic is emitted, not after.** Fail-closed rules stay
  installed *across* the suspend ([ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md)), so
  the machine cannot wake with unprotected traffic in flight before the tunnel is back.
- **If the wall-clock delta exceeds the rekey window, a full handshake is forced** (T35). Transport
  keys are gone; pretending otherwise would produce a tunnel that authenticates nothing.

### 11.4 Platform background limits, and what each costs

| Platform behaviour | Consequence | Response |
|---|---|---|
| App frozen with no scheduler time (iOS, Android Doze) | No keepalives; NAT bindings and relay flows expire; detection latency = suspension duration | Park (§11.2); make wake cheap (§11.3). The suspension is detected on wake by the wall-clock jump, not by a timer that never ran |
| OS-provided VPN extension kept alive while the app is not | The data path survives longer than the UI does | Keep all liveness and enforcement inside the extension, never in the app process |
| Push-style wake for inbound traffic | A peer can reach a parked device via the relay | This is why the relay is the always-available signalling floor rather than a last resort |
| Aggressive vendor battery managers that kill background work outright | The agent dies with rules installed | Correct by design: enforcement rules **outlive the process** (S-18), and assertions expire so the indicator goes `UNKNOWN` rather than staying green (§10.3, mechanism 2) |
| Metered-link and low-battery policy | Cellular use may require consent; standby may be suppressed | A deliberate, **announced** pause with `RELAY.STANDBY.SUPPRESSED_METERED` / `RELAY.STANDBY.SUPPRESSED_POWER` — never a silent downgrade |
| Wall-clock jumps and timezone changes across suspend | Timer arithmetic on wall clock is wrong | **Three clock classes, per §5.3.1** — `MonotonicClock` for liveness timers, `ElapsedClock` for deadlines that bound an authority, `WallClock` as evidence only. "Monotonic for every timer" is **withdrawn**: it was the formulation that voided R-24 on a suspended device |

**Screen lock is not a disconnect.** Locking drops the heartbeat to the background cadence and
keeps the `Session` (T36, `PLATFORM.SCREEN_LOCKED`, informational). Wi-Fi power-save around lock
commonly raises loss and RTT, and that manifests as `DEGRADED` — a quality change, correctly
named, rather than a mysterious drop.

---

## 12. Availability objectives, SLOs, and error budgets

### 12.1 How these are measured

Every SLI below is computed from the structured `TransitionEvent` stream of §10.2 and the
`Diagnostic` records attached to it. That is deliberate: the same artifact that makes a failure
visible to a user is the one that makes it countable, so an objective cannot be met by failing to
observe a failure. Client-side SLIs are aggregated only in the privacy-preserving form
[ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) permits — no peer-pair correlation, no
per-`Session` labels off-device (O-11, O-13).

The measurement window is **28 days**, rolling.

### 12.2 Objectives

| # | Objective | Target | SLI |
|---|---|---|---|
| **SLO-1** | **Established-`Session` continuity across a network change.** A roam, an IP-address change, or a relay failover does not break an in-progress inner TCP/QUIC connection | ≥ 99.5 % of migrations | Fraction of `MIGRATING` entries that reach T15 without an intervening `DISCONNECTED` or a `CRYPTO.*` handshake event |
| **SLO-2** | **Time to restore traffic after a path change**, warm alternate available | p50 ≤ 300 ms, p95 ≤ 1 s | `occurred_at` delta from the T19/T21 event to the T15 event |
| **SLO-3** | **Relay-to-relay failover with a warm standby** | p50 ≤ `T_FAILOVER_TARGET` (300 ms), p95 ≤ 700 ms | `RELAY.FAILOVER.COMPLETED{onset_to_traffic_ms}`; the p95 figure is [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §9.4's |
| **SLO-4** | **Time to first traffic on a new `Session`**, relay session warm | p50 ≤ `T_RELAY_FIRST_TRAFFIC` (300 ms), p95 ≤ 2 s cold | T01 event to the first T08/T09/T10 event |
| **SLO-5** | **Wake-to-traffic on mobile**, surviving path | p50 ≤ 300 ms, p95 ≤ 1.5 s | T35 event to `NET.SESSION.RECOVERED` |
| **SLO-6** | **Data-plane availability during a control-plane outage** | **100 %** for established `Session`s | Count of `Session`s leaving a steady state with a `CONTROL.*` `reason_code`. Any non-zero value is an I5 violation, not a budget spend |
| **SLO-7** | **Named-failure coverage.** Every user-visible failure carries a registered `reason_code` | **100 %** | Count of `INTERNAL.INVARIANT_VIOLATED` and `INTERNAL.MISSING_REASON` events. Target is zero |
| **SLO-8** | **No unprotected egress while `FAIL_CLOSED`** | **zero occurrences** | `POLICY.LEAK.*` and `DNS.LEAK.*` events under `FAIL_CLOSED` enforcement |
| **SLO-9** | **Bounded degradation.** No `Session` sits in a non-steady state longer than its dwell timer | ≥ 99.9 % | `DEGRADED` entries exceeding `T_DEGRADED_MAX`, `MIGRATING` exceeding `T_MIGRATE`, `RECONNECTING` under `PERMISSIVE_ANNOUNCED` exceeding `T_RECONNECT_MAX` |
| **SLO-10** | **Honest reporting.** The aggregate `TwinNet` state never looks healthier than the worst contributing `Session` | **100 %** | §4.7 aggregation asserted against the per-`Session` event stream |

### 12.3 The three objectives with a zero error budget

SLO-6, SLO-7, and SLO-8 have **no error budget**. They are not availability targets that may be
traded for velocity; each is the direct expression of an invariant — I5, I6, and I3 respectively
— and a single occurrence is a defect to be fixed, not a budget to be spent. Stating this
explicitly is the point: an SLO with a budget invites the budget to be spent, and none of these
three may be.

SLO-1 through SLO-5, SLO-9, and SLO-10 carry ordinary budgets.

### 12.4 Error-budget policy

| Budget consumed in the 28-day window | Response |
|---|---|
| < 50 % | Normal development |
| 50–100 % | Reliability work is prioritised over feature work for the affected area; the burn is reviewed against the failure model in §2 to check that the cause is a *modelled* failure and not a new one |
| 100 % exhausted | Feature work in the affected area stops until the budget recovers. A failure mode that is not in §2 is added to §2 as part of the fix — the failure model is the deliverable, not the postmortem |
| Any SLO-6 / SLO-7 / SLO-8 occurrence | Treated as a defect immediately, independent of budget state, and linked to the invariant it violated |

### 12.5 What these objectives deliberately do not cover

- **Throughput.** TwinVPN does not promise a bandwidth number: the achievable rate is a property
  of the user's network, and a promise it cannot keep would be dishonest. What it promises is that
  a throughput *collapse* relative to the path's own baseline is detected and named
  (`NET.QOS.THROUGHPUT_LOW`, §5.4).
- **Absolute latency.** Cross-region relay RTT is a property of geography. What is bounded is the
  *announcement*: `RELAY.FAILOVER.CROSS_REGION` carries the added RTT, so a distant relay is
  visible as a distant relay rather than as a broken tunnel.
- **Infrastructure-side SLOs.** Relay, rendezvous, and control-plane service objectives are
  operational and are owned by [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.7 and
  [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) §10, subject to O-13's prohibition on
  peer-pair correlation. This document's objectives are all measured **on the client**, which is
  the only vantage point that can see whether a user's traffic actually flowed.
