# TwinVPN — Product Vision

**Scope.** This document states what TwinVPN is, who it is for, what it deliberately refuses
to be, and the product principles that bind every downstream design decision. Its load-bearing
content is the **defect-to-requirement table** in §5, which converts the enumerated failure
modes of PairVPN-style products into numbered, normative TwinVPN requirements and binds each
one to the document or ADR that specifies its mechanism. Every requirement in that table is
traceable: if a requirement has no owning specification, that is a gap, not a nuance.

**Related documents**

- [docs/architecture.md](architecture.md) — components, domain model, plane separation, state ownership
- [docs/protocol.md](protocol.md) — wire contracts, control-plane messaging, versioning
- [docs/networking.md](networking.md) — NAT traversal, IPv4/IPv6 routing, DNS
- [docs/reliability.md](reliability.md) — connection state machine, relays, failover, recovery
- [docs/threat-model.md](threat-model.md) — adversaries, trust boundaries, security analysis
- [docs/testing-strategy.md](testing-strategy.md) — verification, conformance, failure injection
- [docs/application-architecture.md](application-architecture.md) — application and platform layer: processes, privilege, management interface, packaging, embedded
- [ADR registry](#7-requirement-to-adr-index)

---

## 1. Thesis

TwinVPN is a **personal peer-to-peer private network**. It connects a single `Owner`'s trusted
`Device`s to each other over encrypted tunnels that are **direct whenever the network permits**
and **relayed through zero-knowledge infrastructure whenever it does not** — with the switch
between those two modes being automatic, observable, and never a downgrade in confidentiality.

The set of one `Owner`'s mutually trusted devices is a **`TwinNet`**.

Three claims define the product:

1. **Connectivity is the product.** Competing personal-VPN products fail not because their
   cryptography is weak but because their *connections do not establish, do not survive, and do
   not explain themselves*. TwinVPN treats "the tunnel came up, stayed up across a network
   change, and told you the truth when it could not" as the primary feature.
2. **The infrastructure is untrusted by construction.** Relay and rendezvous services see
   opaque ciphertext and routing metadata only. There is no operator key that can decrypt user
   traffic, so "trust the vendor" is not part of the security argument (invariant **I1**).
3. **Failure is a first-class product surface.** Every degraded or terminal condition carries a
   stable machine-readable reason code and a human-actionable explanation. A VPN that silently
   stops protecting traffic is worse than one that visibly refuses to carry it (invariants
   **I3**, **I6**).

## 2. Who it is for

| Persona | Need | What TwinVPN gives them |
|---|---|---|
| **Individual with several devices** | Reach my desktop, NAS, and phone from anywhere as if they shared a LAN | A `TwinNet` with stable addressing and zero port-forwarding |
| **Remote worker / traveller** | Use my home Internet egress from a hostile or geo-restricted network | `ExitNode` on a home device, with fail-closed guarantees (**I3**) |
| **Home-lab / self-hoster** | Reach an entire home subnet, not just one host; run on Linux and routers | `LANGateway` with subnet routes; first-class Linux and router targets |
| **Small trusted group (family, two-person team)** | Share access to one machine without one-at-a-time queuing | Multi-client gateways by default (**I7**, [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md)) |
| **Operator of a private deployment** | Run the control plane and relays myself; no vendor dependency | Self-hostable control plane and relays; hosted, hybrid, and fully self-hosted topologies |

TwinVPN is explicitly **not** targeted at users whose adversary is the network-level observer
of their *identity*. See §3.

## 3. Non-goals — what TwinVPN deliberately is not

Stating these boundaries is a design act, not modesty: each non-goal removes a requirement that
would otherwise distort the architecture.

### 3.1 It is not a commercial privacy/anonymity VPN

TwinVPN does not sell "hide your traffic from your ISP behind our shared exit IP." An `ExitNode`
in TwinVPN is a device the `Owner` already controls, and egress traffic carries that device's
IP. **Why this boundary is right:** a commercial privacy VPN's core asset is a large pool of
shared exit addresses plus a promise not to log — a *trust* product. TwinVPN's core asset is
zero-knowledge infrastructure — a *verifiable* product. Mixing them would require operator-run
exit nodes that see plaintext egress traffic, which directly violates **I1**. The two products
have incompatible trust models and must not share a codebase's threat assumptions.

### 3.2 It is not an anonymity network

TwinVPN is not Tor, I2P, or a mixnet. It does not defend against traffic-confirmation, timing
correlation, or global passive adversaries; relays are chosen for latency and availability, not
for unlinkability, and a single relay hop sees both endpoints' network addresses.
**Why this boundary is right:** anonymity requires multi-hop onion routing, deliberate latency
and padding, and a large anonymity set — all of which are in direct tension with the product's
first-order requirement (low-latency, high-throughput, reliably-establishing connections between
a handful of known devices). Claiming anonymity we cannot deliver would be a safety defect, so
the threat model states the metadata exposure explicitly rather than papering over it (see
[docs/threat-model.md](threat-model.md)).

### 3.3 It is not a corporate zero-trust / SASE suite

No SSO/SCIM identity federation, no per-application conditional access, no DLP, no compliance
posture engine, no multi-tenant org hierarchy with delegated admin. The unit of ownership is a
single `Owner` and its `TwinNet`. **Why this boundary is right:** enterprise zero-trust demands
an *external* identity authority (an IdP) as the root of trust. TwinVPN's root of trust is a
device-held keypair whose private half never leaves the device (**I4**). Bolting on an IdP as
the authority would reintroduce a server-side credential capable of minting device access — the
exact failure the invariant exists to prevent. `AccessPolicy` in TwinVPN is deliberately
coarse-grained (peer-to-peer, port/protocol, subnet scope) and evaluated at the endpoints.

### 3.4 It is not a general-purpose overlay/SDN or service mesh

No BGP, no arbitrary multi-tenant topologies, no L7 traffic management, no sidecar model.

### 3.5 Deferred, not rejected

These are out of Phase 1 scope but architecturally *not* foreclosed: multi-`Owner` sharing of a
single device, delegated/temporary guest access, mesh subnet routing between multiple
`LANGateway`s, and relay federation across independent operators. The domain model in
[docs/architecture.md](architecture.md) reserves the shape of each.

## 4. Product principles

Each principle derives from a shared invariant and states a *decidable* rule — one you can use
to reject a design at review time.

### 4.1 The shared invariants (normative)

These eight invariants are the load-bearing constraints of the entire TwinVPN design. Every
other document in this corpus cites them by number; this table is their **single canonical
definition**. An invariant is not an aspiration — it is a property that MUST hold in every
design, and a design that violates one is rejected rather than negotiated. Where an invariant
cannot be upheld on a given platform, the limitation MUST be stated explicitly with its residual
exposure (see [docs/threat-model.md](threat-model.md)); it MUST NOT be silently relaxed.

| # | Invariant | Statement | Primary enforcement |
|---|---|---|---|
| **I1** | **Infrastructure cannot decrypt.** | No `Relay`, rendezvous, or control-plane service holds any key capable of decrypting user tunnel traffic. Infrastructure forwards opaque ciphertext and MUST NOT terminate, re-originate, or inspect a tunnel payload. | [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md), [ADR-0005](adr/ADR-0005-relay-architecture.md) |
| **I2** | **No novel cryptography.** | TwinVPN composes audited protocols and primitives only. No new primitive, AEAD construction, key schedule, or handshake may be introduced. Deviation requires a new ADR plus external review. | [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md), [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) |
| **I3** | **Fail closed, visibly.** | While the kill switch is engaged, protected traffic MUST NOT egress untunneled. Loss of protection MUST be surfaced as an explicit state, never resolved by silently relaxing protection. | [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md), [ADR-0011](adr/ADR-0011-dns-handling.md) |
| **I4** | **Identity never leaves the device.** | A `Device`'s identity is a device-held keypair whose private half is generated in, and never exported from, platform secure storage. No password, shared secret, exportable credential, or server-escrowed private key is an authentication path. | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) |
| **I5** | **The data plane outlives the control plane.** | No established-`Tunnel` code path — keepalive, rekey, path probe, path migration, relay use, or relay failover — may require a control-plane call. Control-plane loss degrades *new operations only*. | [docs/architecture.md](architecture.md) §4.4, [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md), [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) |
| **I6** | **Every failure has a name.** | Every terminal (`FAILED`, `BLOCKED`) and degraded condition MUST carry a stable machine-readable `reason_code`, human-actionable text, and a suggested next action. A bare errno, numeric code, or "connection failed" is a defect. | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) |
| **I7** | **Many peers, always.** | No `LANGateway` or `ExitNode` design may assume a single peer in addressing, routing, NAT, policy, or resource accounting. One-client-at-a-time is a defect class, not a limitation. | [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md) |
| **I8** | **One writer per fact.** | Every persistent fact has exactly one authoritative writer. All other holders keep a cache or replica with a declared staleness tolerance and a defined conflict rule. | [docs/architecture.md](architecture.md) §5, [ADR-0009](adr/ADR-0009-state-consistency.md) |

### 4.2 The derived principles

Each principle turns an invariant into a *decidable* review rule.

| # | Principle | Derived from | The rule it lets you enforce |
|---|---|---|---|
| **P1** | **The infrastructure never holds a key that decrypts user traffic.** | I1 | Reject any design where a `Relay` or rendezvous service terminates, re-encrypts, or inspects tunnel payload. Relays forward opaque ciphertext, period. |
| **P2** | **No novel cryptography, ever.** | I2 | Reject any new primitive, AEAD construction, key schedule, or handshake. Composition of audited protocols only. Deviation requires a new ADR and external review, not a code review. |
| **P3** | **Fail closed, and say so.** | I3, I6 | Reject any code path where protected traffic can egress untunneled while the kill switch is engaged, and any path that resolves a failure by *silently* relaxing protection. Degradation MUST be surfaced as state, not hidden as recovery. |
| **P4** | **Identity is a key the device holds and never surrenders.** | I4 | Reject any account password, shared secret, exportable credential, or server-escrowed private key as an authentication path. |
| **P5** | **The data plane outlives the control plane.** | I5 | Reject any established-tunnel code path that depends on a live control-plane call — including keepalives, rekeys, policy refresh, and relay usage. Control-plane loss degrades *new operations only*. |
| **P6** | **Every failure has a name.** | I6 | Reject any terminal or degraded state that surfaces only a numeric code, an OS errno, or "connection failed". Every one carries `reason_code` + human-actionable text + a suggested next action. |
| **P7** | **Many peers, always.** | I7 | Reject any gateway design with a single-peer assumption in addressing, routing, NAT, policy, or resource accounting. One-client-at-a-time is a defect class, not a limitation. |
| **P8** | **One writer per fact.** | I8 | Reject any state with two authoritative writers. Every persistent fact names exactly one authority; everyone else holds a cache with a declared staleness tolerance. |
| **P9** | **IPv6 is not a feature flag.** | Phase rule 5 | Reject any routing, DNS, firewall, or leak-prevention design that handles IPv4 and treats IPv6 as follow-on work. A v4-only leak guard is a leak. |
| **P10** | **Diagnosability is designed, not added.** | I6, I8 | Reject any state transition that cannot be reconstructed after the fact from a structured event. If a user cannot be told *why* a path was chosen or dropped, the design is incomplete. |

## 5. Defect-to-requirement table

Every entry is a **requirement**, not background. Format: the historical defect, the normative
TwinVPN requirement, the mechanism that discharges it, and the specification that owns that
mechanism. Requirements use RFC 2119 keywords.

### 5.1 Connectivity establishment

| ID | Historical defect | TwinVPN requirement | Mechanism | Specified in |
|---|---|---|---|---|
| **R-01** | NAT traversal failures | Connection establishment MUST attempt multiple traversal techniques in parallel and MUST NOT depend on any single one succeeding. | Parallel `ConnectionCandidate` gathering (host / server-reflexive / relay-reflexive, v4 and v6), simultaneous-open hole punching, candidate racing with path validation | [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md), [docs/networking.md](networking.md) |
| **R-02** | Symmetric NAT and CGNAT failures | The system MUST establish a working `Tunnel` even when both peers are behind symmetric NAT or CGNAT, by falling back to `RELAYED`. Direct-path failure MUST NOT be a connection failure. | Birthday/port-prediction attempts where applicable; unconditional relay fallback with a bounded fallback deadline; continued background direct-path probing while `RELAYED` | [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md), [ADR-0005](adr/ADR-0005-relay-architecture.md) |
| **R-03** | DHCP and route-establishment stalls | Virtual-interface addressing MUST NOT depend on DHCP or on any stateful address-lease negotiation. Addresses MUST be deterministically derived and assigned before the interface is brought up. | Deterministic per-`Device` address derived from `DeviceIdentity` within the `TwinNet` address space (v4 CGNAT-range + v6 ULA); static route programming; no DHCP client in the datapath | [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md), [ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md) |
| **R-04** | Weak protocol lifecycle management | Every wire contract MUST carry an explicit `ProtocolVersion` and MUST negotiate `Capability` sets, with a defined compatibility window and a defined behavior on unsupported-version. | Capability negotiation on every session establishment; forward-compatible schema rules; explicit deprecation windows | [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md), [ADR-0003](adr/ADR-0003-network-contract-schema-format.md) |

### 5.2 Connection durability

| ID | Historical defect | TwinVPN requirement | Mechanism | Specified in |
|---|---|---|---|---|
| **R-05** | Random tunnel disconnects | A `Session` MUST survive `Path` loss. Loss of the underlying transport MUST NOT destroy tunnel state, key state, or the application's sockets. | `Session` / `Tunnel` / `Path` separation (see [docs/architecture.md](architecture.md) §3.4): `Path` is disposable, `Tunnel` is rebindable, `Session` is durable | [docs/architecture.md](architecture.md), [docs/reliability.md](reliability.md) |
| **R-06** | Missing auto-reconnect | Recovery MUST be automatic and unattended, with bounded jittered backoff, and MUST NOT require user interaction to resume a previously working `Session`. | `RECONNECTING` state with backoff schedule; persisted `TrustedPeer` and `Endpoint` cache surviving process/OS restart | [docs/reliability.md](reliability.md), [ADR-0009](adr/ADR-0009-state-consistency.md) |
| **R-07** | Poor roaming | A `Device` changing network (Wi-Fi→cellular, address change, interface change) MUST migrate its `Path` without renegotiating identity or tearing down the `Session`. | Endpoint-independent `Session` identifier; `MIGRATING` state; path validation before cutover; make-before-break where the platform allows | [docs/reliability.md](reliability.md), [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) |
| **R-08** | Unreliable mobile background operation | Background operation MUST use platform-sanctioned VPN lifecycle APIs and MUST tolerate OS-initiated process suspension and termination without losing `Session` continuity or leaking traffic on resume. | Platform network adapter component with per-OS lifecycle contract; on-demand reactivation; state rehydration from local durable store; `BLOCKED` held by the OS-level rule set, not by the app process | [docs/architecture.md](architecture.md) §2.5, [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) |
| **R-09** | Inadequate failure recovery | Every failure MUST map to a defined recovery action with a defined terminal condition. "Retry forever with no diagnosis" and "give up silently" are both defects. | Explicit state machine with guards, timers, and terminal states; classified failures (transient / persistent / policy / fatal); per-class recovery policy | [docs/reliability.md](reliability.md), [ADR-0008](adr/ADR-0008-idempotency.md) |

### 5.3 Infrastructure availability

| ID | Historical defect | TwinVPN requirement | Mechanism | Specified in |
|---|---|---|---|---|
| **R-10** | Unreliable / unavailable relays | Relay selection MUST be health-aware and MUST fail over to an alternate `Relay` within a bounded time without dropping the `Session`. | Continuous relay health probing; ranked candidate set per `RelayRegion`; hot standby relay path; failover as a `MIGRATING` transition, not a teardown | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md), [docs/reliability.md](reliability.md) |
| **R-11** | Single points of failure | No single component's unavailability may prevent a previously paired peer pair from communicating. The control plane, any single relay, and any single rendezvous node MUST each be individually non-fatal. | I5-enforcing plane separation; multi-relay and multi-rendezvous candidate sets; locally cached `TrustedPeer` + `Endpoint` state enabling control-plane-free reconnection | [docs/architecture.md](architecture.md) §4, [ADR-0009](adr/ADR-0009-state-consistency.md), [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) |
| **R-12** | Excessive relay latency | Relay selection MUST optimize measured RTT, not static geography, and the system MUST continue attempting direct-path upgrade for the life of a `RELAYED` session. | Measured-latency relay ranking; opportunistic background hole-punching while relayed; automatic upgrade `RELAYED → WAN_DIRECT` via `MIGRATING` | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md), [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md) |

### 5.4 Correctness of protection

| ID | Historical defect | TwinVPN requirement | Mechanism | Specified in |
|---|---|---|---|---|
| **R-13** | Silent fallback to non-tunneled networking | Protected traffic MUST NOT egress outside the tunnel when the kill switch is engaged. Loss of a secure path MUST produce `BLOCKED`, an observable state, never transparent plaintext egress. | OS-level firewall rule set installed independently of the app process; `BLOCKED` as a first-class `ConnectionState`; fail-closed default on crash, update, and boot | [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) |
| **R-14** | IPv4/IPv6/DNS leaks | Leak prevention MUST cover IPv4 **and** IPv6 **and** DNS simultaneously. Disabling one family is not mitigation; a v4-only guard is a leak. | Dual-family firewall rules; explicit IPv6 handling (route, block, or tunnel — never ignore); DNS interception with a defined `DNSPolicy` and no fallback to the unencrypted system resolver while protected | [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md), [ADR-0011](adr/ADR-0011-dns-handling.md), [ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md) |
| **R-24** | A removed or stolen device keeps working | Revoking a `Device` MUST be enforced at each peer's **own handshake**, not only at the control plane, so it survives control-plane unavailability. At any peer that has learned the revocation it MUST prevent a new `Tunnel` outright. At a peer that has **not** yet learned it — one partitioned from both the control plane and every updated peer — every *granted* authority (exit egress, LAN access, route acceptance, new pairing) MUST be suspended within `T_TRUST_HARD`, bounding the blast radius to baseline reachability; that residual window is bounded by the partition, not by a timer, and MUST be stated rather than implied. Revocation MUST NOT be reversible by replaying an older trust document. | `TrustedPeer` deletion plus a monotone `trust_epoch` whose per-device-sealed `EpochSeed` excludes the revoked device, enforced at the data-plane handshake; anti-rollback on the epoch; peer-to-peer relay of `TrustEpochBundle`s so propagation does not require the control plane | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7, [ADR-0009](adr/ADR-0009-state-consistency.md) §11.5, [docs/threat-model.md](threat-model.md) §10.3 |

### 5.5 Performance

| ID | Historical defect | TwinVPN requirement | Mechanism | Specified in |
|---|---|---|---|---|
| **R-15** | Throughput degradation | The datapath MUST sustain a defined fraction of the underlying link on reference hardware, with MTU/MSS handled correctly so that no path is silently reduced to fragment-and-retransmit behavior. | Kernel datapath where available with userspace fallback; path MTU discovery and MSS clamping for v4 and v6; GSO/GRO/offload where supported; measured throughput budgets | [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md), [ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md), [docs/testing-strategy.md](testing-strategy.md) |
| **R-16** | One-client-at-a-time limits | A `Device` acting as `ExitNode` or `LANGateway` MUST serve many concurrent peers, with per-peer isolation, per-peer policy, and per-peer resource accounting. | Multi-peer gateway architecture with a shared virtual interface plus policy routing and per-peer state; explicit connection limits and fairness | [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md) |

### 5.6 Platform integration

| ID | Historical defect | TwinVPN requirement | Mechanism | Specified in |
|---|---|---|---|---|
| **R-17** | Virtual-interface conflicts | The client MUST detect pre-existing virtual interfaces, address-space collisions, and conflicting route/firewall rules **before** modifying system state, and MUST report a conflict rather than silently overwriting. | Pre-flight environment probe; owned-interface naming and tagging; collision detection against the `TwinNet` address space; idempotent, reversible system-state application ([ADR-0008](adr/ADR-0008-idempotency.md)) | [docs/networking.md](networking.md), [ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md), [ADR-0008](adr/ADR-0008-idempotency.md) |
| **R-18** | Firewall / AV conflicts | The system MUST degrade legibly when a third-party firewall or endpoint-security product blocks it, naming the suspected interfering component in the diagnostic. | Transport-level fallback ladder (UDP → UDP:443 → TCP/TLS → HTTPS-shaped) with explicit per-step results; interference detection heuristics feeding `reason_code` | [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md), [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) |
| **R-19** | Stale drivers | The client MUST NOT depend on a bespoke installed kernel driver where the OS ships a supported virtual-network API, and where a driver is unavoidable, version binding and upgrade MUST be explicit and verified at startup. | Platform network adapter abstraction over OS-native facilities (WireGuard kernel module / WinTun / NetworkExtension / VpnService / TUN); startup capability probe with a named failure when unmet | [docs/architecture.md](architecture.md) §2.5 |
| **R-20** | Poor modern-OS compatibility | Supported OS versions MUST be enumerated with the specific API each depends on, and a compatibility break MUST be a named, testable condition — not a field surprise. | Per-platform capability matrix; OS-version conformance suite; `Capability` negotiation reflecting real platform ability | [docs/architecture.md](architecture.md) §2.5, [docs/testing-strategy.md](testing-strategy.md) |
| **R-21** | No Linux / router support | Linux and router-class targets (OpenWrt-class, low-memory, no GUI) MUST be first-class: headless operation, config-file and CLI control, and a userspace datapath option. | Headless daemon with the same control contract as the GUI client; static/relocatable builds; userspace datapath fallback for kernels lacking the module | [docs/architecture.md](architecture.md) §2.1, [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md) |

### 5.7 Operability

| ID | Historical defect | TwinVPN requirement | Mechanism | Specified in |
|---|---|---|---|---|
| **R-22** | Cryptic error codes | Every terminal and degraded state MUST carry a stable machine-readable `reason_code`, a human-actionable explanation, and a suggested next action. A bare numeric code as the primary user-facing signal is a defect. | Enumerated `reason_code` registry, versioned as part of the network contract; localized human text keyed off the code; codes stable across releases | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md), [ADR-0003](adr/ADR-0003-network-contract-schema-format.md) |
| **R-23** | Insufficient diagnostics | The system MUST be able to produce a self-contained connectivity report explaining, for a failed or degraded connection, which `ConnectionCandidate`s were tried, what each returned, and which constraint blocked success — without requiring a rebuild or a debug binary. | Always-on structured event stream; per-attempt candidate ledger; one-command diagnostic bundle with privacy-preserving redaction | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) |


### 5.8 Application and platform architecture

Requirements R-01 … R-24 were derived from the enumerated failure modes of PairVPN-style products.
R-25 … R-49 are derived the same way, from the failure modes of *shipped client applications*
rather than of tunnels: a product can hold a correct tunnel and still fail its user because the
GUI owned the protection, the update dropped the firewall, the store was destroyed by a firmware
upgrade, or the reason code arrived and was rendered as "connection failed". These are owned by
[ADR-0016](adr/ADR-0016-client-process-and-privilege-separation.md) …
[ADR-0023](adr/ADR-0023-headless-cli-and-embedded-profile.md).

| ID | Historical defect | TwinVPN requirement | Mechanism | Specified in |
|---|---|---|---|---|
| **R-25** | Closing the tray icon, logging out, or having the GUI killed by a memory manager silently drops the tunnel and the leak protection with it | The network and policy authority MUST be a supervised process whose lifetime is independent of any UI process, login session, or desktop session. Termination of every unprivileged TwinVPN process MUST NOT alter enforcement, connection intent, or connection state, and MUST be reported as an informational event rather than as a disconnect. | Privileged long-lived service/daemon (Linux `systemd` system unit, Windows service, macOS NE system extension + `LaunchDaemon`, OpenWrt `procd`) with the UI as a detachable unprivileged client; OS-hosted provider/service on iOS, iPadOS and Android | ADR-0016 §11.2, §11.5, §11.6 |
| **R-26** | The VPN's entire attack surface — UI rendering, URL handling, update UI, image and font decoding — runs with the privilege that can rewrite the host firewall and use the device key | The privilege that can program host network state or use `DeviceKey` MUST be held by a process separate from any process that renders UI or parses untrusted remote content, on every platform whose OS permits the separation. Full compromise of the unprivileged process MUST NOT yield interface, rule-set, resolver, key, or disarm capability. Where a target cannot separate them, the limitation and its residual exposure MUST be declared per target, never implied. | Authority/UI process split with typed, enumerated, per-action-authorized management operations; least-privilege service accounts and capability sets; OS sandbox and hardening directives per target; declared `privilege_separated = false` targets | ADR-0016 §11.3, §11.4, §11.9, §11.10 |
| **R-27** | Uninstalling or crash-looping the client leaves the host either silently unprotected or permanently unable to reach the network, with no recovery that does not require the product that is broken | Install, restart, crash-loop containment, update and uninstall MUST each have a defined terminal state that leaves the host neither silently unprotected nor permanently broken. Crash-loop containment MUST be bounded, MUST NOT disarm enforcement, and MUST NOT block boot. Uninstall MUST require the same local authority as a deliberate disarm, MUST be idempotent and re-runnable, and MUST restore every host mutation from a durable restore point. | Supervisor-native restart with burst limits and a quarantine state; package-owned boot artifact separate from the service unit; ordered idempotent uninstall bound to `HostIntegrationRestorePoint` and `HostResolverRestorePoint`; privileged offline unblock command | ADR-0016 §11.6, §11.11; proof test **P16** |
| **R-28** | GUI-first products where the CLI is a lagging second implementation, so headless and router deployments cannot do what a desktop user can — the concrete failure behind "no Linux/router support" | Every control operation MUST be expressible on **one** local management contract. The graphical client MUST NOT hold a privileged side channel, and the CLI MUST NOT contain a control verb that is not an operation of that contract. The set of operations MUST be machine-enumerable at runtime. | Single MI operation catalogue with runtime enumeration (`mi.catalogue.get`); CLI subcommand table **generated** from the catalogue; parity asserted by proof test **P17** clause A | **This ADR** §11.1, §11.9, §11.12 |
| **R-29** | A management UI whose death, hang, or slow consumption stalls or tears down the tunnel — the "kill the tray icon and lose the VPN" defect | The data plane MUST NOT depend on the management interface. An absent, dead, wedged, or slow local client MUST NOT affect an established `Session`, MUST NOT change enforcement, and MUST NOT delay any state transition. | No daemon→client RPC exists; event emission is a non-blocking offer into a bounded per-connection queue with compaction then eviction; MI server module not linked into the datapath module (build-time dependency assertion); asserted by **P17** clause B | **This ADR** §11.10, §11.11 |
| **R-30** | Unauthenticated or coarsely authorized local IPC, where any local process can disable protection or read everything — the local-privilege-escalation class in VPN clients | Every MI call MUST be authenticated to an OS-attested local principal obtained from the kernel, and authorized against a declared scope. No MI operation may lower enforcement. Kill-switch disarm MUST NOT be reachable by scope alone and MUST require the [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) KS-21 ceremony evaluated by the agent against the OS. | Peer-credential attestation (`SO_PEERCRED` / named-pipe client token / XPC audit token / Binder uid); attach-time immutable scope set; monotone-safe enforcement rule; two-phase OS-evaluated disarm ceremony; asserted by **P17** clause C | **This ADR** §11.4, §11.5, §11.14 |
| **R-31** | Per-platform reimplementation drift: the same product behaves differently on each OS because each platform reimplemented connection logic, a fix lands on one platform only, and no single artifact can be tested to conclusion | All `ConnectionState` machine logic, policy evaluation, candidate gathering, path and relay selection, contract handling, and tunnel control MUST exist as **exactly one implementation**, shared unmodified by every supported target. A native shell MUST NOT contain a second implementation of any of it, and MUST NOT contain a branch whose condition is a TwinVPN domain fact | One portable core over a stable C ABI; the §11.1 split rule and the §11.2 component map as the review rule; the §11.7 crate graph asserted in CI; one conformance corpus run against the one core | This ADR §11.1, §11.2, §11.7 |
| **R-32** | "It does not build for that target any more": a supported platform silently falls behind because its toolchain, libc, or a transitive dependency stopped working, and the gap reaches users as a stale or feature-reduced artifact | Every supported target MUST be produced from **one build definition and one pinned toolchain**, MUST meet a declared binary-size and resident-memory budget, and MUST block the release if it cannot be built or its budget is breached. A target that can no longer be supported MUST be withdrawn **explicitly** — named in the support matrix and reported at runtime as `PLATFORM.OS_UNSUPPORTED` — never shipped with a silently different feature set | Single workspace + pinned toolchain manifest (§11.9); per-target size/RSS gate at T4; reproducible-build verification and per-artifact SBOM (§11.10, §11.11); the DP-7 ladder for a dependency with no build for a target | This ADR §11.9–§11.11; [docs/testing-strategy.md](testing-strategy.md) §6.4, §6.5 B-8 |
| **R-33** | Failure text reaching the user as a generic string, a raw code, or an OS errno | Every `Diagnostic` presented to a user MUST render **three parts** — what happened, what it means for that user's traffic at that moment, and a suggested next action selected for the platform — **including** for a `reason_code` the surface does not recognize, where part 1 degrades to the `DOMAIN` prefix and parts 2 and 3 are still produced. A raw code, a bare number, an OS errno, an i18n key, or an empty next action as the **primary** user-facing signal is a defect. | Presentation contract (three-part rendering, disposition-derived consequence sentence, `DOMAIN` fallback table); a single presentation resolver in the shared core used by every surface including the CLI | ADR-0019 §11.4–§11.6; proof test **P18** |
| **R-34** | A VPN client displaying "Connected" after the tunnel, the daemon, or the process behind it had died | No surface may render a **positive** connection or protection state from a replica older than its declared staleness tolerance. Past `T_VM_STALE` the surface MUST render the last-known value explicitly marked stale; past `T_VM_UNKNOWN` it MUST render `UNKNOWN`. On resume from background or a management-stream gap, every cached value is stale **unconditionally**, without wall-clock arithmetic. | `Fresh<T>` render gate with no constructor from a stale value; `vm_seq` gap detection forcing a full resnapshot; the protection indicator as a pure function of the most recent `ProtectionAssertion` | ADR-0019 §11.2, §11.9; **S-48** |
| **R-35** | Connection state conveyed by a coloured dot; a security product unusable with a screen reader or a keyboard | Every graphical surface MUST meet **WCAG 2.2 Level AA** and its platform accessibility API contract. The connection and protection indicators MUST NOT convey state by colour alone. Asynchronous state changes MUST be announced to assistive technology with severity-appropriate politeness. Every action MUST be keyboard-operable. | A11Y-1…A11Y-10; greyscale pairwise-distinguishability and live-region assertions as release gates | ADR-0019 §11.11; proof test **P18** oracle 5 |
| **R-36** | A GUI that could do things the CLI could not, making headless deployments second-class | No UI capability may exist that the local management contract does not expose. Every UI action MUST be an operation of that contract; the GUI MUST have **no privileged side channel**. Text rendered by the GUI and by the CLI for the same `Diagnostic` in the same locale MUST be identical. | Single management-client dependency with a link-time symbol assertion; a generated operation × surface parity matrix as a build gate; one in-core presentation resolver | ADR-0019 §11.12; [ADR-0017](adr/ADR-0017-local-management-interface.md); [ADR-0023](adr/ADR-0023-headless-cli-and-embedded-profile.md) |
| **R-37** | Products claim "hardware-backed keys" uniformly, then fall back to a file on disk on the platforms where it matters most, without telling anyone. | Private identity material MUST be generated inside, and used from, platform secure storage wherever the target provides one, and MUST be marked non-exportable. Where no secure element exists, the `Device` MUST declare a **degraded custody class** that peers and the `Owner` can see, and MUST NOT present itself as hardware-backed. The degradation and its residual exposure MUST be stated, never silently relaxed. | Three-tier storage model with a decidable tier rule; per-platform Tier-1 realization table; `KeyCustodyDescriptor` (S-54) feeding [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md)'s `hardware_backed` claim and the `Capability` advertisement (S-19) | **ADR-0020** §11.1, §11.3, §11.4; [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.3 |
| **R-38** | Restoring an old profile, config file, or device backup silently reinstates a revoked peer, an older `AccessPolicy`, or an older revocation list. | Every monotone local fact MUST be anchored **outside** the durable file, in secure storage, and written **before** the commit it admits. Restoring the durable file alone MUST be detected and refused; no recovery path — including corruption recovery and schema migration — may lower a floor. Where the platform cannot detect the rollback, the limitation MUST be declared as residual exposure. | `StoreAntiRollbackAnchor` (S-53) co-located with the identity key; write-ahead floor commit; hardware monotone counter on TPM targets; `STORE.ROLLBACK_DETECTED` | **ADR-0020** §11.7, §11.11; [ADR-0009](adr/ADR-0009-state-consistency.md) §11.3 R-7/R-9; [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) N-26 |
| **R-39** | A corrupt config file bricks the client, or the client silently resets to defaults — losing protection, losing trust state, or minting a fresh identity that is indistinguishable from a compromise. | Store corruption, exhaustion, read-only media, and temporarily unavailable secure storage MUST each be a **named, recoverable** condition with a defined recovery rung. Recovery MUST NOT regenerate identity, MUST NOT disengage the kill switch, and MUST NOT lower any monotone floor. An in-place update or reinstall MUST NOT destroy the store; a restore onto different hardware MUST NOT yield a working identity. | Recovery ladder L0–L5 with one `STORE.*` code per rung; floors re-seeded from Tier 1, never from the quarantined vault; `StoreBindingToken` (S-56); backup-exclusion obligations on [ADR-0021](adr/ADR-0021-packaging-distribution-and-updates.md) | **ADR-0020** §11.8, §11.11, §11.12 |
| **R-40** | Unsigned, weakly-signed, or transport-trusted updates; a compromised distribution host owning every installed device | Every executable artifact MUST be verifiable **offline** against a build-time-pinned vendor trust anchor **and** against the host platform's own signing chain, and MUST NOT be installed without a verified inclusion proof in an append-only transparency log. Transport security MUST NOT be any part of the trust argument. | `ReleaseManifest` as an [ADR-0003](adr/ADR-0003-network-contract-schema-format.md) B2 signed statement (deterministic CBOR in COSE_Sign1, ES256) under a quorum-held offline anchor; dual verification against the platform signature; mandatory log inclusion proof | ADR-0021 §11.3, §11.5, §11.8 |
| **R-41** | Silent downgrade to a known-vulnerable version; replayed old metadata pinning a device to it | Update metadata and installed-version state MUST be monotonic. A manifest below the stored high-water MUST be refused; a manifest older than the freshness bound MUST be refused; a rollback below the minimum supported `ProtocolVersion` MUST be refused **at install time, before the old binary runs**; any permitted downgrade MUST require a local `Owner`-authenticated action and MUST lower that device's own negotiation floors. | S-57 monotonic high-water + manifest expiry; a pre-execution installer gate on every self-updating channel; local-authority downgrade mirroring [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) KS-21; S-37 floor lowering per [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) N-20/N-32 | ADR-0021 §11.8, §11.13 |
| **R-42** | An update that leaves the host unprotected, half-installed, or without its identity | An update MUST NOT leave the enforcement rule set absent at any instant, MUST NOT destroy the local store or the device identity, and an interrupted update MUST leave exactly the previous or the new version running — never a third state. Where a platform cannot close the unprotected window, the window MUST be **measured and reported as a number**, never assumed to be zero. | Atomic rule-set swap ([ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) KS-23) plus the per-platform apply sequences of §11.10; the S-60 apply journal, fsync'd before every phase transition and readable without the daemon; ADR-0020 pre-migration retention; **P20** | ADR-0021 §11.10, §11.11, §11.13 |
| **R-43** | Deprecation decided by guesswork; an unreachable update service breaking connectivity | The update service MUST publish a fleet version/capability distribution sufficient to evaluate [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) N-25 G2, computed over an identifier that is **not** the `DeviceIdentity` and whose coverage is stated; and the update path MUST be **structurally incapable** of affecting an established `Session`, asserted mechanically rather than by care. | S-58 reporting epoch and the §11.7 fleet report with its stated coverage bias; a build-time dependency-graph assertion extending [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §11.8 step 3; a destination-bounded `UPDATE` socket class that cannot carry host traffic | ADR-0021 §11.7, §11.9 |
| **R-44** | After a reboot, crash, or OS-initiated kill, the client returns as if it had never run: every peer starts cold, the user must reconnect by hand, and the interval between the network coming up and the agent running is unprotected | The client MUST resume **unattended** from durable local state after clean stop, crash, OS-initiated termination, suspend, hibernate and reboot; it MUST re-enter `RECONNECTING` for every peer it was maintaining rather than `DISCONNECTED`-from-scratch; it MUST re-assert and *verify* enforcement **before** emitting any packet; and it MUST NOT require a logged-in user session, a desktop, a keyring daemon, or a session bus to do any of this | Durable `LifecycleJournal` (S-62) with a clean-shutdown marker and `boot_id`; the ordered rehydration contract with a declared budget `T_REHYDRATE`; per-platform OS-supervisor start triggers; single-instance lock enforcing I8 across restarts | ADR-0022 §11.2, §11.3, §11.9 |
| **R-45** | The agent crashes repeatedly, flapping the interface, routes and firewall on every attempt, and the product's eventual "recovery" is to stop protecting | Repeated abnormal termination MUST be detected within a bounded window and contained. Containment MUST NOT relax enforcement, MUST NOT re-apply network configuration faster than a declared rate, MUST quarantine a configuration generation that correlates with the crashes, and MUST leave a working local control path so the device is *blocked, not bricked*. A crash artifact MUST NOT be able to carry `SECRET`-classified material off the device | Restart policy, crash-loop hold, safe mode and generation quarantine are **ADR-0016 §11.6 PS-9/PS-10/PS-11**'s mechanism (ceded, LC-27); this ADR supplies the write-ahead evidence they key on (S-62), the `apply()` rate limit `N_LIFECYCLE_APPLY_MAX`, the surviving-control-path obligation, and the `SecretArena` with platform dump exclusion and a module-range crash-handler filter | **ADR-0016** §11.6; ADR-0022 §11.7 (LC-28, LC-30) |
| **R-46** | Background operation is either a battery disaster the user uninstalls over, or so aggressively throttled that the tunnel is dead and nobody is told | Each background posture MUST have a **declared, measured** battery, wake, memory and CPU budget; the client MUST consume the OS's own `metered`, `low_power` and thermal signals rather than a fixed profile; and no budget-driven reduction may weaken enforcement, lengthen dead-path detection beyond `T_DEAD` while traffic is offered, or defer rekey. Every budget-driven reduction MUST be announced with a `reason_code` | The budget table and its measurement method; the closed list of forbidden reductions; `query_link_facts()` consumption; the iOS/iPadOS extension memory ceiling with pre-emptive shedding before the OS kills the provider | ADR-0022 §11.4, §11.8 |
| **R-47** | The "server build" is the desktop build with the GUI deleted: it still assumes a writable disk, a logged-in user, a camera for enrolment, and an app-store update path. The router target is a README section. | A headless/embedded deployment MUST be a **declared build profile** with a stated, measured resource envelope, and every capability reachable from the GUI MUST be reachable with no GUI, no user session, no camera, no screen, and no app store. A build that cannot enrol, diagnose, or reconfigure a device without a GUI is non-conforming. | Profile taxonomy and per-profile feature matrix (§11.1, §11.2); headless enrolment channels E1–E4 (§11.6); the CLI surface generated from [ADR-0017](adr/ADR-0017-local-management-interface.md)’s operation catalogue under MI-1, asserted by **P17** clause A and re-asserted per build profile by **P22** (§11.9) | ADR-0023, [ADR-0017](adr/ADR-0017-local-management-interface.md), [ADR-0018](adr/ADR-0018-shared-core-and-build-architecture.md) |
| **R-48** | A config change is applied partially, a typo'd key is silently ignored, and an invalid configuration at boot leaves the device either unprotected or unrecoverable. | Configuration MUST be a schema-versioned document, validated **in full before any system state changes**, applied as an all-or-nothing generation with rollback, MUST **reject** unknown keys rather than ignore them, and MUST NOT fail open on an invalid, absent, or unreadable configuration. | Three-stage validation with an offline dry run (§11.3); generation apply/rollback over [docs/networking.md](networking.md) §5.1 and [ADR-0008](adr/ADR-0008-idempotency.md) (§11.5); safe hold plus [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) KS-19's OS-applied boot ruleset (§11.5) | ADR-0023, [ADR-0008](adr/ADR-0008-idempotency.md), [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) |
| **R-49** | An unattended device fails silently, or resolves a failure by dropping protection because nobody is watching and nobody complains. | An unattended deployment MUST escalate every terminal or persistently-degraded condition through at least one channel that requires **no TwinVPN-operated service**, MUST NOT reduce enforcement on any automatic path, and MUST NOT leave enforcement removed after a crash, crash loop, OOM kill, resource-budget exhaustion, or a failed reload. | Escalation ladder with a local-first floor (§11.16); watchdog credential derived from a fresh `ProtectionAssertion` (§11.16); shedding ladder that structurally excludes enforcement (§11.14); KS-21 unreachable from any automatic path (§11.9, §11.16) | ADR-0023, [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md), [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) |

## 6. What "good" looks like (Phase 1 acceptance shape)

Phase 1 produces no code, so these are the properties the *design* must be able to claim, and
[docs/testing-strategy.md](testing-strategy.md) owns how each becomes a measurable test:

1. Every R-01…R-24 requirement maps to at least one named mechanism in a named document.
2. Every mechanism sits in exactly one component with exactly one state authority
   ([docs/architecture.md](architecture.md) §5).
3. No document contradicts another on the meaning of `Session`, `Tunnel`, `Path`, or any
   `ConnectionState`.
4. Every invariant I1–I8 has an *enforcement mechanism* named, not merely an intention stated.
   In particular I5 is enforced structurally (§4 of the architecture document), not by care.
5. Every consequential decision has an ADR with genuine alternatives and falsifiable revisit
   conditions.

## 7. Requirement-to-ADR index

| ADR | Title | Requirements it discharges |
|---|---|---|
| [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) | Tunnel protocol and cryptographic foundation | R-07, R-15 |
| [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) | Control-plane messaging and event bus | R-04, R-11 |
| [ADR-0003](adr/ADR-0003-network-contract-schema-format.md) | Network contract / schema format | R-04, R-22 |
| [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md) | NAT traversal strategy | R-01, R-02, R-12, R-18 |
| [ADR-0005](adr/ADR-0005-relay-architecture.md) | Relay architecture | R-02, R-10 |
| [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) | Relay discovery and failover | R-10, R-11, R-12 |
| [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) | Device identity and pairing | R-03 (address derivation), R-11, **R-24** |
| [ADR-0008](adr/ADR-0008-idempotency.md) | Idempotency | R-09, R-17 |
| [ADR-0009](adr/ADR-0009-state-consistency.md) | State consistency | R-06, R-11, **R-24** |
| [ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md) | IPv4/IPv6 routing | R-03, R-14, R-15, R-17 |
| [ADR-0011](adr/ADR-0011-dns-handling.md) | DNS handling | R-14 |
| [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) | Kill switch and leak prevention | R-08, R-13, R-14 |
| [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md) | Multi-client gateway architecture | R-03, R-16, R-21 |
| [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) | Protocol versioning and capability negotiation | R-04 |
| [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) | Observability and diagnostics | R-18, R-22, R-23 |
| [ADR-0016](adr/ADR-0016-client-process-and-privilege-separation.md) | Client process, privilege separation, host integration | R-25, R-26, R-27 |
| [ADR-0017](adr/ADR-0017-local-management-interface.md) | Local management interface | R-21 (discharges the *same control contract* claim), R-28, R-29, R-30 |
| [ADR-0018](adr/ADR-0018-shared-core-and-build-architecture.md) | Shared core, language/runtime, build architecture | R-15 (datapath cost), R-31, R-32 |
| [ADR-0019](adr/ADR-0019-application-state-model-and-ui-architecture.md) | Application state model and UI architecture | R-22 (the *human* half of I6), R-23, R-33, R-34, R-35, R-36 |
| [ADR-0020](adr/ADR-0020-local-persistence-and-secure-storage.md) | Local persistence and secure-storage realization | R-37, R-38, R-39 |
| [ADR-0021](adr/ADR-0021-packaging-distribution-and-updates.md) | Packaging, distribution, signing, update delivery | R-19, R-20, R-40, R-41, R-42, R-43 |
| [ADR-0022](adr/ADR-0022-application-lifecycle-and-background-execution.md) | Application lifecycle and background execution | R-08, R-44, R-45, R-46 |
| [ADR-0023](adr/ADR-0023-headless-cli-and-embedded-profile.md) | Headless, CLI, router/embedded profile | R-21, R-47, R-48, R-49 |

> Filenames for ADRs owned by other agents are given as the expected kebab-case form. If an
> owner chooses a different title slug, this index is the place to correct it.
