# TwinVPN — Threat Model

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** SECURITY
- **Related:** [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md),
  [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md),
  [ADR-0003](adr/ADR-0003-network-contract-schema-format.md),
  [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md),
  [ADR-0005](adr/ADR-0005-relay-architecture.md),
  [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md),
  [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md),
  [ADR-0009](adr/ADR-0009-state-consistency.md),
  [ADR-0010](adr/ADR-0010-ipv4-ipv6-routing.md),
  [ADR-0011](adr/ADR-0011-dns-handling.md),
  [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md),
  [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md),
  [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md),
  [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md),
  [docs/architecture.md](architecture.md), [docs/vision.md](vision.md),
  [docs/protocol.md](protocol.md), [docs/networking.md](networking.md),
  [docs/reliability.md](reliability.md), [docs/testing-strategy.md](testing-strategy.md)

This document owns the **adversarial analysis** of TwinVPN: what an attacker wants, who the
attackers are, what each of them can and cannot do *given the design as decided*, and what
remains undefended. It does **not** decide mechanism. Every mitigation cited here is owned by an
ADR and is cited to a section; where this document and an ADR disagree, the ADR wins and the
disagreement is a defect recorded in §15. It extends — and must never contradict —
[docs/architecture.md](architecture.md) §8, which states the trust boundaries *structurally*.

> **Section numbering is pinned.**
> [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) already cites
> `docs/threat-model.md` **§6** (metadata and traffic analysis, from §7.7 and K5), **§7**
> (authorization of `ExitNode`/`LANGateway` access, from §7.4), and **§9** (the never-loggable
> list, from §10). Those three numbers are load-bearing and MUST NOT be renumbered.

---

## 1. Scope, and what this model deliberately does not defend against

A threat model that overclaims is worse than none: it converts an honest limitation into a
false promise, and users make decisions on the promise. This section is therefore first, not
last.

### 1.1 In scope

The confidentiality, integrity, and availability of traffic between a single `Owner`'s `Device`s
across a `TwinNet`; the integrity of `TwinNet` membership; the custody of `DeviceKey` material;
the correctness of fail-closed behaviour; and the bounded metadata exposure of the relay,
rendezvous, presence, control-plane, and observability components.

### 1.2 Out of scope — stated up front, not buried

| # | Non-defence | Basis | Consequence for the user |
|---|---|---|---|
| **N1** | **TwinVPN is not an anonymity network.** It is not Tor, I2P, or a mixnet. | [docs/vision.md](vision.md) §3.2 | A `Relay` sees both endpoints' network addresses. There is one hop, chosen for latency, not for unlinkability. |
| **N2** | **No defence against traffic confirmation, timing correlation, or a global passive adversary.** | [docs/vision.md](vision.md) §3.2, [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.7 and K5 | An observer who sees both ends of a flow can confirm that two `Device`s are talking, and infer volume and interactivity. §6 quantifies this. |
| **N3** | **No padding and no cover traffic.** Packet sizes, inter-packet timing, and volume are visible to every on-path party, including relays. | [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) K5; [ADR-0005](adr/ADR-0005-relay-architecture.md) §7.2 | See §6.3. This is a deliberate, revisitable decision, not an oversight. |
| **N4** | **No defence against a compromised endpoint.** A `Device` on which the adversary has code execution *is* that device. | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.8; [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) K2 | Revocation is the only answer, and it is bounded by §10.3 and TM-11. |
| **N5** | **No defence against a coerced `Owner`.** | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.8 | Named, not mitigated. |
| **N6** | **No censorship resistance.** `T-QUIC` and `R-TLS` are camouflage, not steganography. | [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) K6 | A determined national-scale censor can block TwinVPN. The product MUST NOT claim otherwise. |
| **N7** | **No shared-exit privacy product.** Egress at an `ExitNode` carries that device's own IP. | [docs/vision.md](vision.md) §3.1 | TwinVPN does not hide the user from their ISP behind a pool. See §14.1 on attribution. |
| **N8** | **No enterprise identity federation, per-application conditional access, or DLP.** | [docs/vision.md](vision.md) §3.3 | `AccessPolicy` is coarse-grained by design (§7). |

**Rule TM-S1.** Product surfaces, marketing copy, and diagnostics MUST NOT assert any property
in §1.2. A claim of anonymity, traffic-analysis resistance, or undetectability is a **safety
defect**, filed at the same severity as a leak.

### 1.3 The honesty rule

Where a threat has no mitigation in the current design, this document says so and files it in
§15 with a proposed owner. An unmitigated threat that is *named* is a design input; an
unmitigated threat that is *implied to be handled* is a lie in the specification.

---

## 2. Assets, ranked

Ranked by what an attacker gains, not by what is easiest to attack.

| # | Asset | Owning state row | Why an attacker wants it | If lost |
|---|---|---|---|---|
| **A1** | **Tunnel plaintext** (user traffic between two `Device`s) | S-13 (`Tunnel` key state, in memory, never persisted) | It is the product. Everything else is a means to this. | Total confidentiality failure for the affected `Session`s |
| **A2** | **`DeviceKey` private material** — `DeviceIdentityKey` (IK, P-256, non-extractable) and `TunnelStaticKey` (TK, X25519, hardware-*wrapped*) | S-01 (`LOCAL`, no replica by construction) | IK impersonates the device to peers, relays, and the control plane; TK completes the `Noise_IKpsk2` handshake. | Impersonation until revocation lands (§10.3). TK also gives future-session decryption, never past sessions (forward secrecy, [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.1) |
| **A3** | **The `Owner` root of trust** — `OwnerRootKey` (ORK, phrase-derived) and `OwnerSigningKey` (OSK, secure-element resident) | S-32 (`OwnerTrustAnchor`) | It mints membership. Whoever holds it *is* the `Owner` to every device. | **Total compromise.** Attacker enrolls devices, revokes real ones, publishes policy. [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) K2 |
| **A4** | **`TwinNet` membership control** — the ability to add or remove a `TrustedPeer` | S-02, S-03, S-04 | Adding a device is silent lateral access to every peer that accepts it. | Equivalent to A3 in effect, narrower in scope |
| **A5** | **LAN and exit access** — `Route` acceptance, `LANAccessGrant`, `ExitNodeEngaged` | S-06, S-16, S-17 | Reaches resources *behind* the `TwinNet` that were never meant to be Internet-facing. | Lateral movement into a physical home or office LAN (boundary B6) |
| **A6** | **`PairSecret` / `EpochSeed`** | S-05 amendment, S-33 | Feeds `psk2` and therefore the revocation lever and the post-quantum hedge | Revocation lever weakens; PQ hedge is void (§15 O-2) |
| **A7** | **Metadata** — who talks to whom, when, how much, from where | S-11, relay tables, rendezvous state, telemetry | Social graph, presence, travel pattern, activity fingerprint | Not a confidentiality break, but the largest *residual* exposure in the design. §6 |
| **A8** | **Kill-switch engagement** | S-18 (`LOCAL`, durable, OS-level) | Disengaging it turns a fail-closed device into a leaking one, silently | The defect R-13 exists to retire. Structurally defended (§10.1) |
| **A9** | **The diagnostic bundle** | S-22 | A concentrated dossier: endpoints, interfaces, candidate results, timings | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §7 calls it "the single most sensitive artifact the product produces" |

---

## 3. Trust boundaries

[docs/architecture.md](architecture.md) §8 states the boundaries B1–B6 structurally. This section
enumerates every crossing named in the corpus and, for each, answers three questions the
structural statement deliberately leaves open: **what is authenticated**, **what is
confidential**, and **what the far side learns even when it behaves perfectly**. The last column
is the one that matters — a correctly-behaving component that learns too much is a design
finding, not an incident.

| # | Boundary | What crosses | Authenticated by | Confidential to | What the far side learns when behaving correctly |
|---|---|---|---|---|---|
| **TB-1** | `DeviceKey` ↔ the rest of the device (**B1**) | Signature and key-agreement *operations* only | OS keystore ACL; `kSecAccessControlPrivateKeyUsage`, `setUnlockedDeviceRequired`, TPM `fixedTPM\|fixedParent` ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.3) | — | Nothing. Private material MUST NOT cross outward (I4) |
| **TB-2** | Device ↔ `TrustedPeer` (**B2**) | User IP traffic, in-session control messages, `TrustEpochBundle` relay | `Noise_IKpsk2` over the peer's TK, looked up in the local `TrustedPeer` set ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.6) | ChaCha20-Poly1305, keys held only by the two peers | The peer's public IP (`WAN_DIRECT`), its `TwinNet` addresses, its `Capability` set, its `trust_epoch`, and everything it sends. A `TrustedPeer` is trusted, and that is a real grant — see TM-01 |
| **TB-3** | Device ↔ gateway peer (`LANGateway` / `ExitNode`, **B5/B6**) | Forwarded IP traffic plus `LANAccessRequest` / `ExitNodeEngage` | Same as TB-2, plus the gateway's own `AccessPolicy` evaluation ([docs/protocol.md](protocol.md) §13.2, §13.3) | Same as TB-2 up to the gateway; **plaintext beyond it** | The gateway sees the *decrypted* destination of everything it forwards. This is inherent: it is the egress point |
| **TB-4** | Device ↔ untrusted network (underlay) | Ciphertext datagrams, DHCP/ND/RA, portal conversation under a §11.7 grant | Nothing at this layer; L-DATA is self-protecting | Nothing below L-DATA | Both endpoints' IP:port, packet sizes, timing, volume, and the fact that a WireGuard-shaped protocol is in use ([ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §6 A1) |
| **TB-5** | Device ↔ physical LAN | On-link unicast, ND/RA, mDNS, `disco` probes | `disco` `PING`/`PONG` are authenticated to a per-peer disco key ([ADR-0004](adr/ADR-0004-nat-traversal-strategy.md) §7) | disco probes are encrypted | That *a* TwinVPN device is present, from port and packet shape ([docs/networking.md](networking.md) §8.2(1)). `disco_id` rotates hourly and is `TwinNet`-keyed, so it does **not** enable cross-network correlation or membership enumeration |
| **TB-6** | Device ↔ Internet services, at an `ExitNode` (**B5**) | Egress traffic under the exit device's address | — | — | The destination service sees the `ExitNode`'s IP, not the client's. Attribution therefore lands on the `Owner` (§14.1) |
| **TB-7** | Device ↔ rendezvous (**B3**, semi-trusted) | `ConnectOffer`/`CandidateSet`/`PunchSync`, all Rule-B signed; pairing ceremony bytes wrapped under `K_pair` | Mutual TLS 1.3 to `DeviceIdentityKey` (RFC 7250 raw public key) plus per-message `DeviceKey` signatures ([ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.2 L-CONTROL) | Ceremony payloads are `K_pair`-sealed; candidate payloads are signed but **not** confidential to the rendezvous | **Which `device_id` is attempting to reach which `device_id`, and both reflexive addresses.** This is an *identity-level* peer graph ([ADR-0004](adr/ADR-0004-nat-traversal-strategy.md) §7). See §15 O-3 |
| **TB-8** | Device ↔ `Relay` (**B3**, untrusted) | `RelayFrame`-wrapped opaque L-DATA datagrams | `Noise_IK` (`R-UDP`) or TLS 1.3 with `RLK` as an RFC 7250 raw public key (`R-QUIC`/`R-TLS`), plus a `RelayCapabilityToken` with an RFC 7800 `cnf` proof-of-possession ([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.1, §11.3) | L-DATA is opaque; `K_leg` protects only the relay's own frame table | Both underlay IP:ports; that pseudonyms `relay_sub(A)` and `relay_sub(B)` are peers; `pair_tag`; frame counts, byte counts, sizes, timing; token claims. **Not** `device_id`, membership, overlay addresses, DNS, routes, or plaintext ([ADR-0005](adr/ADR-0005-relay-architecture.md) §7.2). §8 |
| **TB-9** | Device ↔ control plane (**B3**, semi-trusted) | Signed, monotone, TTL'd state documents; durable events; heartbeats | mTLS 1.3 raw-public-key **plus** end-to-end per-message `DeviceIdentityKey` signatures, channel-bound via RFC 9266 `tls-exporter` ([ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §7 S-1) | Transport-confidential only; the control plane reads what it routes | Membership, `Pairing` events, revocations, policy, presence, relay-token issuance, heartbeat cadence, and coarse device liveness. It **cannot** decrypt traffic or forge trust (§10) |
| **TB-10** | Operator / administrator ↔ infrastructure | Production access to control-plane, rendezvous, presence, relay-selection, issuer, and relay hosts | Out of scope of every current ADR | — | Everything TB-7, TB-8, and TB-9 learn, **plus** the `relay_sub → device_id` mapping if the issuer and the relay operator are the same legal entity ([ADR-0005](adr/ADR-0005-relay-architecture.md) V7). See §15 O-4 |
| **TB-11** | System ↔ observability (**management plane**) | `Diagnostic` records, Tier-1 bundles, Tier-2 aggregate counters, crash reports | Bundles are `DeviceKey`-**signed**, not encrypted ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §7) | Tier 0 never leaves the device; Tier 1 and 2 require an explicit user act | Tier 2: counters with **no** device identifier. Tier 1: pseudonymized endpoints and peers, per-bundle mapping, not correlatable across bundles ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.4). §9 |
| **TB-12** | TwinVPN ↔ OS / platform (**B4**) | Interface, route, firewall, and resolver programming, via the Platform Network Adapter only | OS-mediated privilege (`polkit`, UAC, Authorization Services) | — | The OS sees everything. A hostile process at agent privilege is inside TB-1's *use* boundary (TM-14) |

**Rule TM-S2.** No component MAY be moved across a boundary by configuration. In particular a
`Relay` MUST NOT become a `TrustedPeer` ([ADR-0005](adr/ADR-0005-relay-architecture.md) §6 E), and
the control plane MUST NOT be granted an `Owner` signing key
([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §6 O3).

---

## 4. Adversary catalogue

Each adversary is defined by **capability**, not by motive. "Cannot" means *cannot, given the
design as decided* — every entry is falsifiable against a cited mechanism.

| # | Adversary | Granted capabilities | Cannot, given the design | Worst realistic outcome |
|---|---|---|---|---|
| **AD-1** | **Passive on-path observer** (ISP, Wi-Fi operator, backbone tap) | Read every byte on the underlay; unlimited retention | Decrypt L-DATA; recover past sessions after a static-key compromise (forward secrecy, [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.1) | Full metadata: endpoints, volume, timing, protocol identification. §6 |
| **AD-2** | **Active on-path attacker** | Inject, drop, delay, reorder, block; run a transparent proxy; spoof DNS and DHCP | Complete a handshake (no `TrustedPeer` entry ⇒ `AUTH.PEER_UNTRUSTED`); replay (TAI64N + 8192-bit window); force a downgrade (D1–D6, prologue binding); MITM a pairing ceremony (§7.4 of ADR-0007) | Denial of service, and forcing `RELAYED` or `T-QUIC` carriage. Blocking is always available to them |
| **AD-3** | **Malicious paired peer** (a `TrustedPeer` the `Owner` deliberately added, behaving badly) | Everything TB-2 grants: send arbitrary traffic into the tunnel, request LAN/exit access, advertise `Route`s, exhaust a gateway's resources | Read another pair's traffic (keys are pairwise); grant itself access (enforcement is at the resource owner, §7); advertise a prefix the receiver's `AccessPolicy` does not permit; forge membership or revocation | Lateral movement to whatever `AccessPolicy` actually permits — which is why the *default* policy matters (§15 O-5) |
| **AD-4** | **Compromised previously-honest peer** | AD-3, plus everything on that device: TK in memory, IK usable-but-not-extractable, `PairSecret`, `EpochSeed`, cached policy | Decrypt traffic recorded *before* the compromise (forward secrecy); survive revocation past its own epoch (`EpochSeed` exclusion, [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7); extract IK where `hardware_backed = true` | Full access for as long as revocation takes to propagate — worst case 30 days against a fully partitioned peer (§10.3) |
| **AD-5** | **Compromised `Relay`** (operator, host, or attacker with root) | Read, drop, delay, reorder, replay, forge, and fabricate frames; full visibility of its own tables; unlimited logging | Decrypt (three-element key inventory, §8.1); redirect a `Session` (only peers act on a `PathOffer`, `DRAIN` is advisory); impersonate another relay (statics are in the `Owner`-signed relay map); learn `device_id` or membership | Denial of service for flows bound to it, plus a per-operator, per-day pseudonymous pair graph (§8.3) |
| **AD-6** | **Compromised rendezvous** | See and drop all signalling; substitute payloads; correlate attempts | Forge a `CandidateSet` (Rule-B signed; unsigned candidates MUST be dropped, [docs/protocol.md](protocol.md) §10.4); steer probes at a victim (targets restricted to signed candidates, §10.5); MITM a pairing ceremony (it never sees `pairing_secret`, [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.4) | Denial of first contact, plus the **identity-level peer graph** of TB-7 |
| **AD-7** | **Compromised control plane** (fully, including its TLS terminators and its database) | Withhold, delay, and lie about availability; forge freshness proofs (`LogHead` key is online, [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §7 S-3); observe all control metadata; refuse new pairings; degrade relay ranking | Decrypt (I1); forge membership, revocation, or policy (`Owner`-rooted COSE_Sign1, verified offline); disengage a kill switch (S-18 has no remote replica and no wire message means "disarm"); roll back a revocation (monotone `trust_epoch`, S-03) | **Bounded denial and metadata. Never a leak, never impersonation.** §10 is the full analysis |
| **AD-8** | **Malicious insider / administrator with production access** | AD-5 ∪ AD-6 ∪ AD-7 simultaneously; plus persistence, log retention beyond policy, and correlation across services; plus, if issuer and relay operator are the same entity, de-pseudonymisation of `relay_sub` | The same things AD-7 cannot: the `Owner` root is not held by any infrastructure component | The **full identity-level communication graph** of the fleet, over time, correlated across rendezvous, relay, and control plane. §15 O-4 |
| **AD-9** | **Thief with an unlocked device** | The device, its unlocked keystore, and the running agent | Nothing — **the thief *is* the device** ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.8) | Full `TwinNet` access until revocation propagates (§13). If that device holds an `ENROLL`/`DELEGATE` OSK, escalates to AD-8-equivalent within the `TwinNet` |
| **AD-10** | **Thief with a locked device** | The hardware and its storage | Use IK before first unlock (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, `setUnlockedDeviceRequired(true)`); extract IK where `hardware_backed = true`; clone the device where `hardware_backed = true` | Nothing, on a hardware-backed platform. On a file-backed target (router, container, VM, pre-T2 Intel Mac) the identity **clones successfully** — TM-12 |
| **AD-11** | **Malicious LAN neighbour** | L2 adjacency: ARP/ND spoofing, rogue RA, rogue DHCP, on-link scanning, rogue captive portal | Decrypt; MITM the tunnel; force a leak (Tier 2 is interface-scoped and default-deny, so a new interface or RA-learned prefix is denied by the *pre-existing* rule, [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.3 row 3) | Denial of service; observation that a TwinVPN device is present (TB-5); prompting a portal-exemption dialog (TM-27). Reaching the device on-link, because `local_network_access` defaults to `ALLOW` (§15 O-6) |
| **AD-12** | **Hostile OS-level process on the device** | Depends entirely on privilege. Same user, not agent privilege: observe, exhaust, attempt IPC. **Agent privilege:** read TK from memory, use IK as a signing oracle, rewrite the rule set | At non-agent privilege: match the bootstrap-exception predicate (KS-9 requires cgroup/app-id/uid **and** an enforcement-layer socket registration, and the agent exposes no proxy, SOCKS, or injection interface — KS-10); extract IK at any privilege where hardware-backed | At agent privilege: everything AD-4 has, on this device. This is N4 — a compromised endpoint is not defended |
| **AD-13** | **Supply-chain attacker** — a compromised build pipeline, a malicious or compromised dependency, or an attacker holding a **release signing key** | Execute arbitrary code **inside the shipped client**, on every device that installs the artifact. Read anything the agent can read, weaken the RNG, corrupt the desired rule set *before* the adapter installs it, exfiltrate identity-operation results | **Forge an artifact without a release key** (dual signature + transparency-log inclusion proof, [ADR-0021](adr/ADR-0021-packaging-distribution-and-updates.md) R-40); **roll a device back** below its `manifest_version_high_water` (S-57) or below the MSPV gate, which is checked in the **installer package** and not only in the updater; **suppress the evidence** — an artifact absent from the log is refused offline | **Total compromise of every device that installs the artifact.** This is the widest blast radius in this document: the `OwnerRootKey` reaches one `TwinNet`, a release key reaches **every `TwinNet`**. Bounded by verification-before-execution, monotonic manifests, staged rollout and log inclusion — **not** by the transport, which is explicitly not part of the trust argument |
| **AD-14** | **MDM administrator on a managed device** (distinct from the `Owner`) | Everything the OS grants a device-management authority: remove the app, remove the VPN payload, remove the Always-On configuration, push a `DeploymentProfile` | **Lower enforcement through configuration** — `KS-22`'s monotone rule makes effective mode `max(local, profile_required)` and a profile has **no expressible field** that reduces it; **author or alter `AccessPolicy`/`DNSPolicy`** (S-06/S-07 are the `Owner` authority's); **change the `OwnerTrustAnchor` pin** (build-time); **obtain any key** | **Removal of protection, not subversion of it.** The administrator can make the product *stop*; they cannot make it lie. Where administrator and `Owner` are different people this is an **unresolvable** authority the OS grants and we cannot refuse — see §14.4 |

---

## 5. Threat table

Every row cites a **real mechanism in a real ADR section**. Rows whose mitigation column reads
**NONE** are the most valuable content in this document and are consolidated in §15.

| # | Attack | Boundary / asset | Mitigating mechanism (owner) | Residual risk | Detection |
|---|---|---|---|---|---|
| **TM-01** | **Malicious peer** abuses the access a `Pairing` granted | TB-2 / A5 | `AccessPolicy` evaluated at the **resource-owning** peer, `Owner`-authority signed, monotone `policy_version` ([docs/protocol.md](protocol.md) §13.2 Authorization, §13.4) | Only as strong as the policy actually configured; the shipped default is unspecified (§15 O-5) | `POLICY.POLICY_DENIED`, per-client gateway accounting ([ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md)) |
| **TM-02** | **Compromised peer** retains access after the `Owner` notices | TB-2 / A4 | Delete `TrustedPeer` locally **and** advance `trust_epoch` with an `EpochSeed` HPKE-sealed per surviving device; the revoked device is simply not a recipient ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7, N-25) | **Baseline reachability: unbounded** against a peer partitioned from both the control plane and every updated peer — bounded by the partition, not by a timer. **Privileged access: ≤ 30 days** (`T_TRUST_HARD`), after which every granted authority suspends ([ADR-0009](adr/ADR-0009-state-consistency.md) §11.4) | `AUTH.DEVICE_REVOKED`; `AUTH.TRUST_STATE_STALE` at 24 h |
| **TM-03** | **Compromised relay** attempts to decrypt | TB-8 / A1 | Structural: the relay's entire key inventory is three items, none an input to the L-DATA schedule ([ADR-0005](adr/ADR-0005-relay-architecture.md) §7.1) | None on confidentiality. Metadata per §8.3 | **P14** — dump the relay's complete key material and assert no captured frame decrypts |
| **TM-04** | **Compromised relay** drops, delays, reorders, replays, or forges frames | TB-8 / availability | Drop ⇒ `RELAY_FLOW_FAILING` ⇒ `RELAYED → MIGRATING → RELAYED` onto a pre-bound warm standby in a different failure domain; replay ⇒ L-DATA replay window; forgery ⇒ L-DATA AEAD ([ADR-0005](adr/ADR-0005-relay-architecture.md) §7.5, §11.6) | Denial of service for flows bound to that relay. R-11 requires ≥ 2 alternates | `RELAY.*` codes; `RELAY.STANDBY_UNAVAILABLE` warns *before* the failure |
| **TM-05** | **Compromised rendezvous** MITMs first contact or pairing | TB-7 / A4 | Candidates are Rule-B signed and unsigned candidates MUST be dropped ([docs/protocol.md](protocol.md) §10.4); the ceremony is `K_pair`-sealed under a secret that never transits the network ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.4) | It still learns the identity-level pair graph (§15 O-3) and can deny first contact | Ceremony failure, never silent success; `AUTH.PAIRING_*` |
| **TM-06** | **Compromised control plane** forges membership, revocation, or policy | TB-9 / A3, A4 | Every trust document is COSE_Sign1 verified offline to the pinned `OwnerTrustAnchor`; the control plane holds no ORK/OSK private half ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.5, N-9) | None on forgery. Censorship and freshness lies remain (§10.2) | Anchor digest cross-check in the handshake prologue; `prev_entry_hash` chain; transparency log (N-14, detection only) |
| **TM-07** | **MITM** on the data plane | TB-4 / A1 | `Noise_IKpsk2` mixes both statics; the responder looks the initiator's TK up in its local `TrustedPeer` set — an unknown static cannot complete ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.6) | Requires TK **and** the current-epoch `psk2`; both are on-device secrets | `AUTH.PEER_UNTRUSTED`, `CRYPTO.HANDSHAKE_AUTH_FAILED` |
| **TM-08** | **Replay** — data packets, handshakes, control messages, relay tokens | all / A1, A4 | Data: 64-bit nonce + 8192-bit RFC 6479-style window. Handshake: monotone TAI64N per peer. Control: `CEREMONY`-class idempotency keys ([ADR-0008](adr/ADR-0008-idempotency.md)). Relay: `jti` replay cache ([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.3) | The relay `jti` cache is **bounded**; a token replayed after eviction is admitted, capped by `exp` | `CRYPTO.REPLAY_DETECTED`, `RELAY.TOKEN_REPLAYED` |
| **TM-09** | **Downgrade** — weaker suite, older `ProtocolVersion`, reduced `Capability` set | TB-2 / A1 | L-DATA has no cipher negotiation to attack. Feature negotiation is **inside** the tunnel with a transcript hash and a per-`TrustedPeer` monotonic floor; the floor is bound into the Noise `prologue` (D1–D6; [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.6, N-20) | A prologue mismatch is indistinguishable from any other handshake failure — an honest limitation ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.6) | `PROTO.DOWNGRADE_REFUSED`; `AUTH.PROLOGUE_OR_EPOCH_MISMATCH` after three failures. **P11** |
| **TM-10** | **Pairing-code brute force** | TB-7 / A4 | C-B (QR): 256 bits, optical, nothing guessable on the network. C-A (SPAKE2/P-256, RFC 9382): a genuine PAKE — the transcript is **not** offline-testable; 9 digits, **5** failed runs per `pairing_id`, single-use, **120 s** expiry, enforced independently at both devices and the rendezvous ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.4, N-17) | ≈ 5 × 10⁻⁹ per ceremony on the C-A path. Rests on attempt limiting being correct in **three** places (K6, V4) | `AUTH.PAIRING_ATTEMPTS_EXCEEDED`; V4 is the falsification trigger |
| **TM-11** | **Stolen pairing code / captured QR** | TB-7 / A4 | 120 s expiry; single-use `pairing_id`; the ceremony still requires an OSK `ENROLL` approval on an existing device ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.4 C-D row) | A QR displayed in a shared office is readable by any lens for 120 s. There is no attempt limiting to fall back on ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §6 C-B). **Headless addition:** where the offer is carried over an operator's shell rather than a screen, it can **persist in scrollback, a `tmux` capture, or `script(1)`** — camera-and-screen leaves no artifact, a terminal does. **The 120 s window bounds the ceremony, not the artifact** ([ADR-0023](adr/ADR-0023-headless-cli-and-embedded-profile.md) EM-27) | Post-hoc fingerprint display on both ends; unexpected device in the member list |
| **TM-12** | **Stolen device** (locked / unlocked) | TB-1 / A2, A3 | Locked: `AfterFirstUnlockThisDeviceOnly` / `setUnlockedDeviceRequired` make IK unusable. Unlocked: **NONE — the thief is the device** ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.8) | Full access until revocation propagates. Escalates to root compromise if the device held an `ENROLL`/`DELEGATE` OSK | `Owner`-initiated only. §13 is the runbook |
| **TM-13** | **Device cloning** (disk image to new hardware) | TB-1 / A2 | Prevented where `hardware_backed = true`: a secure-element key does not clone. **NONE where `hardware_backed = false`** — routers, containers, VMs, pre-T2 Intel Macs ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.8, K9) | On file-backed targets both copies connect successfully. **Router addition:** an H-EMB device is typically **physically accessible, its flash unencrypted, and never inspected** — pulling the flash, mounting the image, or taking a `sysupgrade -b` archive yields a working identity, and the archive contains it by design ([ADR-0023](adr/ADR-0023-headless-cli-and-embedded-profile.md) EM-33). Restoring such an archive onto different hardware produces a **clone, not a migration** | Detection only: `AUTH.IDENTITY_CONCURRENT_USE` (one `device_id` from distinct networks) and non-increasing TAI64N handshake timestamps |
| **TM-14** | **Credential theft / key extraction** | TB-1 / A2 | IK: non-extractable in hardware — an attacker with code execution can *use* it but not *take* it, so the compromise **ends at revocation** instead of outliving the device. TK: hardware-*wrapped*, `mlock`ed, `MADV_DONTDUMP`, core dumps disabled | **TK extraction from process memory is undefended** ([ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) K2; [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.8). Mandatory 180-day TK rotation bounds usefulness, nothing more | Behavioural only |
| **TM-15** | **Unauthorized LAN access** through a `LANGateway` | TB-3 / A5 | The gateway is the enforcement point and evaluates its own `AccessPolicy` against the requesting `DeviceIdentity`; the client's view is advisory; grants are per-client and per-family, re-evaluated on `PolicyBundleUpdated` ([docs/protocol.md](protocol.md) §13.2) | Bounded by the configured policy. `POLICY.PREFIX_COLLIDES_LOCAL` is the common *failure*, not an attack | `POLICY.GRANT_REVOKED_BY_POLICY` |
| **TM-16** | **Unauthorized `ExitNode` use** | TB-3, TB-6 / A5 | The `ExitNode` enforces its own `AccessPolicy`; the client cannot self-authorize; both parties MUST be `TrustedPeer`s at the current `revocation_epoch` ([docs/protocol.md](protocol.md) §13.3) | Attribution risk to the `Owner` remains even when authorization is correct (§14.1) | `POLICY.POLICY_DENIED`; per-client accounting |
| **TM-17** | **Route injection** — a peer advertises `0.0.0.0/0` and `::/0` to capture the `TwinNet` | TB-2 / A5 | A `RouteAdvertisement` is accepted **only if the receiving device's `AccessPolicy` permits that advertiser to advertise that prefix**; acceptance is a local decision, never an infrastructure one; monotone `advertisement_epoch` ([docs/protocol.md](protocol.md) §13.1) | The **default** policy for who may advertise what is unspecified corpus-wide (§15 O-5) | `ROUTE.PREFIX_CONFLICT`; conflicts MUST be surfaced, never silently resolved (R-17) |
| **TM-18** | **DNS manipulation** — rogue resolver, portal answers persisting, DoH bypass | TB-4, TB-5 / A1 | Stub resolver + platform split-DNS + port-53/853/DoH containment, both families. **No fallback *on failure*** — resolution never reverts to a pre-existing resolver because TwinVPN's path failed, was not installed, timed out, or did not match (DN-10) — and **no underlay resolution at all in `FULL` mode**. `BLOCKED`-state answers are typed SERVFAIL + EDE, never a fallback ([ADR-0011](adr/ADR-0011-dns-handling.md) §11; [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.12(a)) | Three, stated plainly. (a) In the **default `SPLIT` mode**, out-of-scope names are *deliberately* forwarded to the host's pre-existing resolver over the underlay, in whatever transport the host had — commonly cleartext Do53 (DN-10, DN-23). That is policy-directed forwarding, not a fallback, but it is observable to the local network. (b) An app-embedded resolver speaking HTTPS to an arbitrary host is undetectable at this layer (DN-26(5)). (c) Portal-window answers are the sharp edge; KS-16 forbids them entering the protected cache | `POLICY.LEAK.DNS_UNPROTECTED`, `DNS.*`. **P08**, with a mutant that caches portal answers |
| **TM-19** | **IPv6 bypass** — v6 enabled after the tunnel is up, RA on a new interface, tethering, a VM bridge | TB-4 / A1 | Tier 2 is **interface-scoped and default-deny**, expressed as one dual-family object, so a new interface or prefix is denied by the *pre-existing* rule with no rule update required for correctness. A rule set installable for one family only is **non-conforming**, not degraded (KS-5) ([ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.3, §11.4) | Bounded by the platform table in §11.6 of ADR-0012, not by the rule design | `POLICY.LEAK.IPV6_UNPROTECTED`, `POLICY.LEAK.FAMILY_GRANT_MISSING`. **P07** |
| **TM-20** | **Traffic leak** — egress outside the tunnel on any interface | TB-4 / A1, A8 | OS packet filter (E1) as the sole enforcement point; two rule sets and never zero (KS-17); arming MUST NOT fail open (`POLICY.KILLSWITCH.ARM_FAILED`); the boot ruleset is applied by the **OS**, not the agent (KS-19) | Per-platform: iOS has no host firewall and no boot enforcement; Android without lockdown is unprotected; macOS Recovery, Linux single-user, and Android safe mode bypass ([ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.6) | **Active** leak canary: a marked datagram from a non-exempt socket whose drop must be observed in the enforcement layer's own counters — `POLICY.LEAK.EGRESS_OBSERVED`. **P09** |
| **TM-21** | **Abuse of the bootstrap exception** as a covert egress channel | TB-4 / A1, A8 | Matched by an OS-mediated process predicate **and** an enforcement-layer socket registration **and** exclusion from the forwarding path (KS-9); the agent MUST NOT expose a proxy, SOCKS, CONNECT listener, port-forwarder, or injection API (KS-10); exempt-rule byte counters are reconciled against tunnel accounting (KS-11) | Destination-unbounded by necessity — relay and peer endpoints are legitimately arbitrary. Safety is structural, not destination scoping | `POLICY.EXEMPT.EGRESS_ANOMALY` at `CRITICAL`, driving `BLOCKED`. Firing outside a test is a security incident (ADR-0012 §14(7)) |
| **TM-22** | **Malicious relay advertisement** — a fake relay inserted into selection | TB-8 / A7, availability | Relay statics and endpoints come from an **`Owner`-signed relay map**; a relay cannot impersonate another; `aud` is an operator group scoped to the `TwinNet`, so cross-`TwinNet` admission is structurally impossible ([ADR-0005](adr/ADR-0005-relay-architecture.md) §7.5, §10) | A compromised **relay-selection service** can degrade ranking toward relays it prefers — a metadata-steering attack, not a decryption one (§10.2) | `RELAY.ISSUER_UNKNOWN`; client-measured RTT locally overrides a stale ranking (S-09) |
| **TM-23** | **Malicious protocol messages** — forged, misrouted, wrong-publisher, or lifted onto another channel | TB-9 / A4 | Rule-B end-to-end signatures; RFC 9266 `tls-exporter` channel binding, so a compromised TLS terminator cannot lift a message; single publisher enforced as a **schema constraint at the log**, not by convention ([ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §7 S-1, S-4) | The bus can withhold, delay, or advance a watermark to force a spurious re-read — never inject or roll back | `CONTROL.CHANNEL_BINDING_MISMATCH` (a security event, never a parse error), `CONTROL.EVENT_WRONG_PUBLISHER` |
| **TM-24** | **Malformed packets / parser attacks** — CBOR, COSE, `RelayFrame`, QUIC, Noise | TB-4, TB-8, TB-9 | Deterministic CBOR (RFC 8949 §4.2.1) inside COSE_Sign1 (RFC 9052), verified **over received octets**, `crit` enforced ([ADR-0003](adr/ADR-0003-network-contract-schema-format.md)); reserved bits MUST be zero on send, ignored on receive ([ADR-0005](adr/ADR-0005-relay-architecture.md) §9.1) | The bespoke relay frame parser is the newest and least adversarially-reviewed surface in the system ([ADR-0005](adr/ADR-0005-relay-architecture.md) §13) | Fuzz targets ([docs/testing-strategy.md](testing-strategy.md) §2.12) and **P13** |
| **TM-25** | **Resource exhaustion** at a relay or gateway | TB-8, TB-3 / availability | Two-tier deficit round robin (outer across `relay_sub`, inner across half-flows) so one device holding 64 flows cannot starve one holding 1; per-subject and per-flow token buckets; bounded per-flow queue with tail-drop; quota carried **in the token** so no lookup is needed ([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.5) | A revoked device can still consume relay quota until its token expires — capped at 24 h, typically minutes ([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.3) | `RELAY.RATE_LIMITED`, `RELAY.QUOTA_EXCEEDED`, `RELAY.OVERLOADED`. Overload is **never silent** (RQ9) |
| **TM-26** | **Amplification / reflection** — using TwinVPN infrastructure as a DDoS weapon | TB-4, TB-7, TB-8 | Relay amplification factor is **exactly 1.0 by construction**: one frame out per frame in, equal length, no fan-out, no padding, **zero bytes** for any unauthenticated or unbound frame; stateless cookie challenge above 20 handshakes/s per source /24 or /48 ([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.5). Rendezvous forwards to a `DeviceId`, never to a caller-supplied address ([ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §7 S-5). Probe targets restricted to addresses in a *signed* `CandidateSet` ([docs/protocol.md](protocol.md) §10.5). WireGuard does not respond to unauthenticated packets | None known | Black-box amplification measurement; ADR-0005 V8 falsifies the claim if any deployed relay exceeds 1.0 |
| **TM-27** | **DDoS against TwinVPN's own infrastructure** | TB-7, TB-8, TB-9 / availability | Established `Session`s are structurally independent of the control plane (I5, §4.4 of architecture); relay admission is an offline pure function (RQ2); ≥ 2 relay alternates per region across ≥ 2 failure domains; QUIC address validation and an application-level `CONTROL.ADMISSION_DEFERRED` rather than a TCP reset ([ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §7 S-5) | **No ADR owns volumetric DDoS defence** for the relay or control-plane tier — no scrubbing, anycast-absorption, or capacity decision exists (§15 O-7) | `CONTROL.ADMISSION_DEFERRED`; `RELAY.NONE_REACHABLE` |
| **TM-28** | **Metadata exposure** across infrastructure | TB-7, TB-8, TB-9, TB-11 / A7 | `pair_tag` rendezvous so the relay never learns identities; `relay_sub` per-operator-per-day pseudonym; daily re-hash of `relay_sub` in relay logs with ≤ 7-day retention; O-13 forbids retaining the peer-pair correlation; Tier 2 telemetry has **no** device identifier ([ADR-0005](adr/ADR-0005-relay-architecture.md) §7.2, §10; [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §7, §11.10) | **The rendezvous holds an identity-level pair graph regardless** (§15 O-3), and a colluding operator can join it to `relay_sub` (§15 O-4). §6 is the full accounting | Not detectable by the user. This is a design property, not an incident class |
| **TM-29** | **Trust-state rollback** — replaying an older revocation list, policy bundle, or anchor | TB-9 / A4, A8 | Rejection is at the **local device store**, so it survives a hostile control plane: `trust_epoch`, `anchor_version`, `generation`, `tk_generation`, and `policy_version` MUST be monotone in durable state ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) N-26; [ADR-0009](adr/ADR-0009-state-consistency.md) §7(1)). Revocation denials are **monotone accumulations, not leases** — expiry can never un-revoke ([ADR-0009](adr/ADR-0009-state-consistency.md) §7(3)) | None on rollback. Withholding remains (§10.2) | `AUTH.TRUST_EPOCH_ROLLBACK`, `AUTH.TRUST_HISTORY_FORKED`. **P10** |
| **TM-30** | **Recovery-phrase compromise** | TB-1 / A3 | **NONE.** The holder is indistinguishable from the `Owner` ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.5, K2) | Total trust-root compromise | Detection only: `AUTH.UNEXPECTED_DELEGATION` from the anchor digest carried in every handshake prologue, plus optional transparency-log inclusion checks (N-14) |
| **TM-31** | **Malicious or forged client artifact** — compromised build pipeline, poisoned dependency, or stolen release key | TB-1, TB-6 / AD-13 | **Bounded, not prevented.** Dual signature (our release key **and** the platform's), offline-verifiable, plus a **mandatory transparency-log inclusion proof** — an artifact that is validly signed but absent from the log is **refused** ([ADR-0021](adr/ADR-0021-packaging-distribution-and-updates.md) R-40). Monotonic manifest with a freshness bound blocks rollback and freeze (R-41); the MSPV gate lives in the **installer package**, so running an old installer directly does not bypass it. Verification precedes execution; the transport is not part of the trust argument. SBOM published per release. **Residual:** an attacker holding *both* a release key and log-inclusion capability is not stopped by this design — only detected afterwards, and only by someone auditing the log |
| **TM-32** | **Platform vendor revokes a valid notarization ticket or signing identity**, disabling already-installed software | TB-6 / availability | **NONE within this design, and this is the only such row.** Apple can revoke a notarization ticket, and revocation reaches software **already installed and running**, not merely future downloads. It is the vendor's action on the vendor's timeline, with no appeal path we control and no in-band way to keep a deployed fleet running. The transparency log gives detection for a *forged* artifact but nothing gives recourse for a *revoked legitimate* one. **This is the only place the corpus asserts a property — that we control our own availability — which a third party can unilaterally void.** Stated so it is a known operational dependency rather than a surprise; Developer ID distribution is chosen with this cost accepted ([ADR-0021](adr/ADR-0021-packaging-distribution-and-updates.md) §11.3) |

---

## 6. Metadata exposure and traffic analysis

*(Cited by [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.7 and K5.)*

### 6.1 The non-goal, restated where it is load-bearing

TwinVPN hides **content**, not **shape**. L-DATA is a fixed-suite AEAD tunnel with no padding
and no cover traffic. Packet sizes, inter-packet timing, burst structure, and total volume are
visible to every party on the path — the local Wi-Fi operator, the ISP, the transit network, and
the relay. An adversary who observes both ends of a flow can confirm that two `Device`s are
communicating with high confidence and can often infer *what kind* of activity is occurring from
volume and interactivity alone. **TwinVPN does not defend against this and MUST NOT claim to.**

### 6.2 What each component learns — the single honest table

| Component | Learns | Explicitly does **not** learn | Retention / rotation | Owner |
|---|---|---|---|---|
| **On-path network observer** (ISP, Wi-Fi, transit) | Both endpoint IP:ports, packet sizes, timing, volume, protocol identification (WireGuard is trivially fingerprintable on `T-UDP`) | Plaintext, `device_id`, `TwinNet` membership, overlay addresses, DNS names | Unbounded, outside our control | [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §6 A1, §7.7 |
| **`Relay`** | Both peers' underlay IP:ports; that `relay_sub(A)` and `relay_sub(B)` are peers; `pair_tag`; frame/byte counts, sizes, timing; token `aud`/`exp`/`epoch`/quota class | `device_id`, membership, overlay addresses, DNS, routes, plaintext, peer identity keys | `relay_sub` rotates **daily** per operator group; `pair_tag` rotates every **10 min** and is scoped to one `relay_id`; logs keyed by a daily re-hash, retention ≤ 7 d; **nothing durable about flows, peers, or pairs** | [ADR-0005](adr/ADR-0005-relay-architecture.md) §7.2, §10, RQ10 |
| **Rendezvous** | **Which `device_id` is attempting to reach which `device_id`**, and both reflexive addresses | Plaintext; the pairing `pairing_secret`; any `CandidateSet` content it could forge undetected | Not bounded by any current ADR | [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md) §7 — **the largest single metadata disclosure in the design** (§15 O-3) |
| **Presence service** | Device liveness and last-known `Endpoint` | Plaintext, peer pairs | S-11 is `EVENTUAL`, TTL seconds–minutes, **never a gate** | [docs/architecture.md](architecture.md) §5 S-11 |
| **Control plane** | Membership, `Pairing` and revocation events, policy, address allocation, relay-token issuance, heartbeat cadence, coarse liveness | Plaintext (I1), private key material (I4), `PairSecret`, `EpochSeed` contents | Durable by design; this is the authoritative membership record | [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §7 |
| **Relay-credential issuer** | The `relay_sub → device_id` mapping (it computes `relay_sub`) | Plaintext | Not bounded by any current ADR (§15 O-4) | [ADR-0005](adr/ADR-0005-relay-architecture.md) §11.3, V7 |
| **Peer `Device`** | The other peer's public IP (on `WAN_DIRECT`), overlay addresses, `Capability` set, `trust_epoch`, and all traffic sent to it | Traffic to *other* peers (keys are pairwise) | Local | [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md) §7 "reflexive address disclosure" |
| **LAN neighbour** | That *a* TwinVPN device is present, from port and packet shape | Which `TwinNet`; membership; correlation of the same device across networks or across time (`disco_id` rotates hourly, `TwinNet`-keyed) | Hourly | [docs/networking.md](networking.md) §8.2 |
| **Telemetry backend (Tier 2)** | Counters, bucketed timings | **No** device identifier, `Owner` identity, peer pair, endpoint, or fine-grained time — *because none is generated* | Default-**off**, persistent opt-in | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §7 |
| **Support (Tier 1 bundle)** | Pseudonymized endpoints, interfaces, peers, candidate results, timings | Real addresses; cross-bundle correlation (per-bundle random mapping) | Per-artifact user act; carries an expiry | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.4 |

### 6.3 Padding and cover traffic are out of scope

Padding and cover traffic would cost battery and bandwidth continuously for a benefit that does
not survive a global observer anyway
([ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) K5). The `Relay`
therefore **MUST NOT** pad, buffer beyond its bounded queue, retransmit, or reshape
([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.1(5)) — reshaping would add cost while
providing no anonymity property, which is the worst of both.

### 6.4 Linkability windows, stated as durations

| Linkage | Window | Set by |
|---|---|---|
| Relay can link all of one device's flows | one operator group, one day | `relay_sub` `epoch_day` ([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.3) |
| Relay can link a specific peer pair | 10 min, one `relay_id` | `pair_tag` bucket ([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.1(3)) |
| LAN observer can link a device across probes | 1 h | `disco_id` ([docs/networking.md](networking.md) §8.2) |
| Support can link two events | one bundle | per-bundle pseudonym mapping ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.4) |
| Rendezvous can link a peer pair | **unbounded — `device_id` is stable for life** | §15 O-3 |

Anonymous-credential schemes (blind signatures, BBS+) would remove even the per-operator
pseudonym, and are rejected under I2/C1 because they are not commodity-audited on the five
target platforms ([ADR-0005](adr/ADR-0005-relay-architecture.md) §7.2, V4).

---

## 7. Authorization: LAN access, exit-node use, and route acceptance

*(Cited by [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.4.)*

Three rules make a compromised control plane, and a compromised client, unable to grant access.

**Rule TM-A1 — enforcement is at the resource owner.** The `LANGateway` evaluates its own
`AccessPolicy` against the requesting `DeviceIdentity`; the `ExitNode` evaluates its own. The
client's view of policy is **advisory** ([docs/protocol.md](protocol.md) §13.2, §13.3). This is
what makes a compromised client unable to grant itself access, and it is why per-flow
authorization is never a control-plane call (which would also violate I5).

**Rule TM-A2 — `AccessPolicy` is `Owner`-authority signed, not control-plane authored.** The
coordination service distributes `PolicyBundle`s but cannot author them
([docs/protocol.md](protocol.md) §13.4 Authorization). Were it able to, a compromised
coordination service could disable every kill switch in the fleet, which would make I1 and I3
jointly worthless.

**Rule TM-A3 — policy is monotone and absent grants are denials.** A device MUST reject any
bundle with `policy_version` ≤ its high-water mark (S-06). `granted_default_v4` and
`granted_default_v6` are independent, and an **absent field is a denial, never a permission**
([docs/protocol.md](protocol.md) §13.3; [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md)
KS-8). A single-family grant with the other family leaking to the local ISP is the exact defect
R-14 exists to retire.

**Route acceptance** is the sharpest edge. A `RouteAdvertisement` is accepted only if the
*receiving* device's `AccessPolicy` permits that advertiser to advertise that prefix
([docs/protocol.md](protocol.md) §13.1) — without this, one compromised device advertising
`0.0.0.0/0` and `::/0` captures the whole `TwinNet`'s traffic. The corpus states the rule but
not the **shipped default**, which is filed as §15 O-5. This threat model's position: the default
MUST be that no prefix is accepted without an explicit `Owner` grant, and a conflict MUST be
surfaced as `ROUTE.PREFIX_CONFLICT` rather than silently resolved (R-17).

---

## 8. The compromised relay, bounded

### 8.1 Why a relay structurally cannot decrypt (proof test P14)

The argument is an **enumeration over a closed key inventory**, not a statistical observation
over traffic ([ADR-0005](adr/ADR-0005-relay-architecture.md) §7.1). A relay holds exactly three
keys:

| Key | Origin | Relationship to the L-DATA key schedule |
|---|---|---|
| Relay static X25519 `RS` | generated on the relay, published in the `Owner`-signed relay map | **not an input** — the relay is not a party to `Noise_IKpsk2` |
| Issuer public-key set | shipped/rotated as signed config | verification-only, public |
| Per-leg key `K_leg` | Noise_IK / TLS-exporter transport key with the device's `RLK` | domain-separated from L-DATA; used only for the 64-bit frame MAC |

The relay holds no L-DATA static, no L-DATA ephemeral, and no `TwinNetPSK`. `pair_tag` is an
HKDF output over a peer-pair secret and is one-way. **P14 is therefore executable as: dump the
relay's complete key material at any instant, feed the union to the reference L-DATA decryptor,
and assert that no captured frame decrypts.** This holds only while
[ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) maintains the domain
separation of `RLK` required in [ADR-0005](adr/ADR-0005-relay-architecture.md) §11.2(a)–(b); if
that separation were ever relaxed, P14 collapses from a structural test to a weak negative
observation ([docs/testing-strategy.md](testing-strategy.md) §0 A-05).

### 8.2 What a compromised relay can do

Drop (indistinguishable from loss ⇒ `RELAY_FLOW_FAILING` ⇒ `MIGRATING`), delay, reorder, replay
(rejected by the L-DATA replay window), forge (rejected by the L-DATA AEAD), and refuse
admission. It **cannot** redirect a `Session` — only the peers act on a `PathOffer`, and `DRAIN`
is advisory — and it cannot impersonate another relay, because relay statics live in the
`Owner`-signed relay map ([ADR-0005](adr/ADR-0005-relay-architecture.md) §7.5). Denial of
service is genuinely available to it, which is why R-11 requires ≥ 2 alternates per region
across ≥ 2 failure domains, and why the warm standby is pre-`BOUND`.

A stolen `RelayCapabilityToken` is inert without the device's `RLK`, to which it is bound by an
RFC 7800 `cnf` claim; `RLK` is a distinct, device-generated, non-exported key, so relay-leg
compromise does not reach device identity ([ADR-0005](adr/ADR-0005-relay-architecture.md) §7.6).

### 8.3 What a relay does learn — honestly

Everything in the `Relay` row of §6.2. In summary: **traffic volume, timing, packet sizes, and
the fact that two capability-token holders are communicating.** Within one operator group and one
day, the relay **can** link all of a device's flows — this is the price of enforcing a per-subject
quota without anonymous credentials, and it is bounded to one operator and one day
([ADR-0005](adr/ADR-0005-relay-architecture.md) §13). It learns both peers' underlay addresses,
which is identical to what any on-path observer learns — exactly the trust level B3 already
assigns.

**Self-hosting a relay buys metadata locality and jurisdictional control. It does not buy
confidentiality**, which the tunnel already provides against a hosted relay and a self-hosted one
alike; a self-hosted relay's trust level is identical: untrusted (B3), I1 unchanged
([ADR-0005](adr/ADR-0005-relay-architecture.md) §10).

### 8.4 Padding and cover traffic are not in scope at the relay

Per §6.3 and [docs/vision.md](vision.md) §3.2 — stated here explicitly because "add padding at
the relay" is the intuitive fix a reviewer will propose. It would not produce an anonymity
property against the adversary that matters (a global or bi-endpoint observer), and it would
multiply the dominant recurring operating cost ([ADR-0005](adr/ADR-0005-relay-architecture.md)
C4).

---

## 9. Observability, diagnostics, and the never-loggable list

*(Cited by [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §10.)*

The observability system is **inside** this threat model, not outside it. The telemetry backend
is modelled as an adversary, not as trusted infrastructure
([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §7).

**The never-loggable list.** The following are `SECRET`-classified. `SECRET` means **no rendering
path exists, in any build, at any log level, in any tier**
([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.4, §11.5):

| Never logged, rendered, or transmitted | Source |
|---|---|
| Tunnel plaintext and packet payloads | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.4 |
| Any private key material: IK, TK, `RLK`, ORK, OSK | I4; [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §10 |
| `pairing_secret`, `PairSecret`, `EpochSeed`, `K_pair`, `K_leg`, `TwinNetPSK` | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §10 |
| The 24-word recovery phrase — shown once, confirmed by re-entry, never displayed again | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §10, N-12 |
| DNS query names transmitted off-device; browsing or destination history | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.10 |
| The peer-pair correlation, on any infrastructure component (O-13) | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §7 |
| Any stable device or user identifier in Tier 2 | [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.10 |

**Loggable**: `device_id`, public fingerprints, `trust_epoch`, `anchor_version`, `generation`,
`reason_code`s, state transitions, and counters
([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §10).

**Three specific observability threats.**

1. **Relay-side logging is the sharpest risk.** A relay sees both ends of a `RELAYED` session by
   necessity; if it *logs* that, it holds the peer graph and defeats I1 in metadata even though it
   never sees plaintext. O-13 forbids retention of the peer-pair correlation and constrains relay
   metrics to aggregates with no per-session label. Per-session debugging on a relay is
   deliberately impossible, and that is the correct trade
   ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §7).
2. **The diagnostic bundle is a concentrated secret** (A9). It never leaves the device without an
   explicit act, is rendered for inspection first, is pseudonymized per bundle, is
   `DeviceKey`-**signed** (not encrypted — the private half never leaves, I4), and carries an
   expiry.
3. **Diagnostics are an exfiltration primitive if remotely triggerable.** Bundle generation MUST
   be rate-limited, MUST require local user authorization, and **a remote "generate and send
   diagnostics" command MUST NOT exist**. Support pulls nothing; the user pushes
   ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §7). Crash reporting is opt-in,
   stack-and-registers only, with key material and packet buffers in dump-excluded memory regions.

Redaction is applied by the **emitter from the schema classification**. There is no
"scrub the log before sending" step, because that approach fails open
([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.4, O-14).

---

## 10. The compromised control plane, bounded

This is TwinVPN's central security claim, so it is stated as four prohibitions with structural
reasons, followed by an honest inventory of the real damage that remains.

### 10.1 What a fully compromised control plane cannot do

| Prohibition | Structural reason (not a check) | Owner |
|---|---|---|
| **Decrypt tunnel traffic (I1)** | It holds no key in the L-DATA schedule. `Noise_IKpsk2` keys derive from two device statics, two ephemerals, and `psk2 = TwinNetPSK(A,B,e)`; the control plane holds none of them | [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.4 |
| **Forge membership** | Every trust document is COSE_Sign1 under an `OwnerSigningKey` delegated by an `OwnerRootKey` that exists on **no server** and, between ceremonies, in **no device's storage**. Devices pin the `OwnerTrustAnchor` at enrolment and verify offline. Alternative O3 (control-plane-held root with a transparency log) was rejected **precisely because** it would have falsified this | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.5, N-9, §6 O3 |
| **Disengage a kill switch** | Three independent structural properties: S-18 has **one writer and no remote replica**, so there is no authoritative copy to write back; **no wire message type means "disarm"**, and an absent message type cannot be forged; and effective enforcement is `max(local_mode, policy_required_mode)`, monotone in the safe direction, so remote policy can only make a device *more* blocked | [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) KS-22, §11.12(d) |
| **Roll back a revocation** | Rejection of a lower `trust_epoch` happens at the **local device store**, and revocation denials are monotone accumulations rather than leases — document expiry can never un-revoke anything | [ADR-0009](adr/ADR-0009-state-consistency.md) §7(1), §7(3); [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) N-26 |

It additionally cannot forge a device statement (every control message is end-to-end signed by
`DeviceIdentityKey`, so TLS termination is not the trust anchor), cannot grant `ExitNode` or
`LANGateway` access (§7), and cannot narrow a device's acceptable version/suite set (D4).

### 10.2 What it *can* do — real damage, precisely bounded

| Capability | Effect | Bound |
|---|---|---|
| **Deny new pairings** | No device can join the `TwinNet` | Existing `Session`s and existing `TrustedPeer`s are unaffected (I5). Total outage of *growth*, not of *operation* |
| **Withhold or delay a revocation** | A revoked device keeps reaching peers it can still contact | Staleness timers force `DEGRADED` at `T_TRUST_STALE = 24 h` and **suspend every granted authority** (egress, LAN access, route acceptance, new pairing) at `T_TRUST_HARD = 30 d`, bounding what the revoked device can do to baseline reachability only; peer-relayable `TrustEpochBundle`s route around it entirely if any updated peer is reachable ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7, N-28) |
| **Forge freshness** | Say "nothing new to fetch" indefinitely | The `LogHead` signing key is **online**, so a compromised control plane can forge freshness. It cannot forge trust. Explicitly acknowledged as residual in [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §7 S-3 |
| **Degrade relay selection** | Steer devices onto relays the attacker prefers, or onto `RELAYED` paths generally | S-09/S-10 are `EVENTUAL` and **MUST NEVER gate a connection attempt** (C8); client-measured RTT locally overrides a stale ranking. The gain is metadata steering (§6), never decryption |
| **Withhold relay tokens** | Relay admission is lost after the token's life | relay admission survives a control-plane partition of **any** duration — the relay renews the capability token itself under epoch equality ([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.3), and the former 30-hour cliff is **withdrawn**. Direct paths are unaffected throughout ([ADR-0005](adr/ADR-0005-relay-architecture.md) §11.3) |
| **Raise enforcement** | Force devices into `BLOCKED` | A visible denial of service, categorically lesser than an invisible leak ([ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §7) |
| **Observe control metadata** | Membership, pairing and revocation events, policy, address allocation, heartbeat cadence, liveness | Unbounded. §6.2 |
| **Advance a bus watermark** | Force a spurious re-read | Cannot inject, forge, reorder-into-effect, or roll back — the bus carries only `{twinnet_id, net_seq, revocation_epoch}` watermarks, never event bodies ([ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §7 S-2) |

### 10.3 The bound, stated as one sentence

**A fully compromised control plane is a metadata observer and a denial-of-service actor with a
30-day upper bound on the *privileged* blast radius of a suppressed revocation. Baseline
reachability to a fully partitioned peer is bounded by the partition rather than by a timer, and
relay admission is not bounded at all, because the relay renews its own capability tokens under
epoch equality. It is never a decryption, impersonation, membership-forgery, or leak actor.** That
bound is the reason the control plane is classified semi-trusted (B3) rather than trusted, and
it is what makes I1 and I4 verifiable claims rather than promises.

---

## 11. Cryptographic posture

**Rule TM-C1 — no novel cryptography (I2 / P2).** Every primitive and every protocol MUST come
from a published, audited specification. The only TwinVPN-designed elements are the *composition*
of layers and HKDF derivations that use HKDF exactly as specified
([ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §11(7);
[ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) Q14). Proof obligation **P2** is that no
build contains a bespoke primitive, AEAD, handshake, or key schedule.

| Layer | Protocol / primitive | Standard | Owner |
|---|---|---|---|
| L-DATA (user tunnel) | WireGuard: `Noise_IKpsk2`, X25519, ChaCha20-Poly1305, BLAKE2s | Noise / RFC 8439 | [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.2 |
| L-DATA replay | 64-bit counter nonce + 8192-bit sliding window | RFC 6479 style | [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.1 |
| L-TRANSPORT | `T-UDP`; `T-QUIC` (QUIC DATAGRAM, RFC 9221) | RFC 9000/9001/9221 | [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.2 |
| L-CONTROL | QUIC + TLS 1.3 mutual auth, RFC 7250 raw public keys, RFC 9266 exporter channel binding, **0-RTT prohibited** | RFC 8446 / 7250 / 9266 | [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.2; [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §7 S-1 |
| Relay leg | `Noise_IK` (X25519 / ChaCha20-Poly1305 / BLAKE2s) or TLS 1.3 with `RLK`; DTLS 1.3-style counter reconstruction | Noise / RFC 8446 / RFC 9147 §4.2.2 | [ADR-0005](adr/ADR-0005-relay-architecture.md) §11.1, §9.1 |
| Identity signing | ES256 (P-256 / SHA-256), deterministic ECDSA where software-signed | RFC 6979 | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) N-1, N-8 |
| Trust documents | COSE_Sign1 over deterministic CBOR, verified over received octets, `crit` enforced | RFC 9052 / RFC 8949 §4.2.1 | [ADR-0003](adr/ADR-0003-network-contract-schema-format.md); [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) C3 |
| Pairing (fallback) | SPAKE2 over P-256 with the RFC-specified M and N | RFC 9382 | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) N-17 |
| Epoch-seed distribution | HPKE Base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305 | RFC 9180 | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7 |
| Recovery phrase | 24 words / 256-bit entropy, BIP-39 English; HMAC-DRBG(SHA-256) + FIPS 186-4 B.4.2 | — | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) N-10 |

**Post-quantum posture: deferred, with a defined hook.** No PQ key agreement ships in Phase 1.
The migration path is the `Noise_IKpsk2` `psk2` slot: a store-now-decrypt-later adversary who
later breaks X25519 still faces an unknown symmetric secret
([ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.5(1), R16). The
revisit trigger is falsifiable: **a hybrid PQ key agreement (e.g. ML-KEM-768 + X25519) is
standardised for the Noise/WireGuard PSK path *and* has a published independent audit**
([ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) V2). The identity layer
has its own hook: the `twd1` text prefix versions to `twd2` for a PQ identity key
([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.2, V8).

> **The PQ hedge is currently unsound as specified.** It depends on `psk2` containing entropy an
> X25519-breaking adversary does not obtain. Two ADRs define `PairSecret` — which feeds `psk2` —
> incompatibly, and one of the two definitions is a plain static-static X25519 output that such
> an adversary computes directly. This is filed as §15 **O-2** and MUST be resolved before the
> PQ-hedge claim is made to users.

---

## 12. Key lifecycle security

Sourced from [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.3, §7.5, §7.7, and N-5,
N-7, N-10, N-19, N-21, N-25, N-27.

| Phase | `DeviceIdentityKey` (IK) | `TunnelStaticKey` (TK) | `OwnerRootKey` (ORK) | `OwnerSigningKey` (OSK) | `PairSecret` / `EpochSeed` |
|---|---|---|---|---|---|
| **Generation** | Inside platform secure storage, marked non-exportable (N-5) | On-device X25519 | Deterministically from a 24-word BIP-39 phrase via HMAC-DRBG(SHA-256) (N-10) | Inside the secure element of each admin `Device` | `PairSecret`: HKDF at ceremony completion over the ceremony key and a fresh ephemeral DH. `EpochSeed`: 32 random bytes at the revoking OSK device |
| **Storage** | Secure Enclave / StrongBox / TPM 2.0 / kernel keyring; file at 0600 only where no secure element exists (`hardware_backed = false`) | Sealed under a hardware-bound wrapping key; plaintext only in `mlock`ed, `MADV_DONTDUMP` memory, core dumps disabled | **Stored nowhere.** Materialised only during TwinNet creation and recovery, zeroized immediately after (N-10) | Non-extractable, secure element | Durable in `TrustedPeer` (S-05 amendment). MUST NOT be transmitted, backed up, or replicated (N-19) |
| **Use** | L-CONTROL mTLS client key; signs every device COSE_Sign1 statement, `TunnelKeyBinding`, and `PairingAttestation` | The `Noise_IKpsk2` static | Signs `OwnerDelegation` and, alone or via quorum, a new anchor | Signs `DeviceCertificate`, `RevocationRecord`, `TrustEpochBundle`, `PolicyBundle` | `PairSecret` + `EpochSeed` ⇒ `TwinNetPSK(A,B,e)` ⇒ the `psk2` slot |
| **Rotation** | Creates a new `DeviceIdentity` (`generation`+1) with an `IdentitySuccession` **dual-signed by old and new** IK. `device_id` does **not** change. Overlap `T_IK_OVERLAP = 30 d` (N-21, N-23) | **MUST be rotated at least every 180 days** (N-21). Overlap `T_TK_OVERLAP = 14 d` | Only via a new anchor at a strictly higher `anchor_version` | Minted by ORK, or by `k = min(2, n_osk)` independent OSK signatures excluding the target (N-11) | New `EpochSeed` per revocation; each device retains the current and two preceding epochs |
| **Revocation** | `RevocationRecord` (OSK-signed, hash-chained, monotone `trust_epoch`) plus deletion of `TrustedPeer` at every peer (N-25) | Follows IK revocation; also excluded from the new `EpochSeed` recipient set | Superseded by a higher-`anchor_version` anchor | Revoking an `ENROLL`/`DELEGATE` OSK is a **high-power** operation requiring ORK or a 2-OSK quorum (N-11) | A revoked device is simply not a recipient of the HPKE seal, so it cannot compute the PSK at epoch `e` **even if a peer's `TrustedPeer` deletion failed** |
| **Recovery** | **None.** No cloud restore of a device identity (I4/K3). A restored backup or re-image arrives with no usable key ⇒ `AUTH.IDENTITY_MISSING` ⇒ re-enrolment, which is a first-class flow, not an error path (N-7) | Same | From the 24-word phrase, on a freshly enrolled device | From ORK, or from a surviving OSK quorum | Re-obtained by fetching the current `TrustEpochBundle` — from the control plane **or from any updated peer inside an established tunnel** (N-28) |
| **Expiration** | `DeviceCertificate` carries a **backstop** `not_after` of enrolment + 10 years — deliberately long, so renewal never requires an `Owner` device to be online (Q15, N-27) | Bounded by the 180-day rotation, not by certificate expiry | None | None | Freshness is enforced by `T_TRUST_REFRESH = 6 h`, `T_TRUST_STALE = 24 h`, `T_TRUST_HARD = 30 d` (`Owner`-configurable within [24 h, 90 d]) |
| **Destruction** | Key handle deleted; failure to load MUST fail closed and MUST NOT silently mint a replacement (N-7) | Zeroized at `REJECT_AFTER_TIME`; session keys zeroed at 180 s | Zeroized after each ceremony | Deleted on device decommission via a high-power revocation | Two-epoch retention, then discarded |

**Rule TM-K1.** A downgrade of `hardware_backed` (secure-element migration, OS re-image) MUST
force IK rotation and re-attestation, and peers MUST surface `AUTH.HARDWARE_BACKING_LOST` (N-24).
A peer MUST NOT treat an *unattested* `hardware_backed = true` as evidence of anything (N-6).

---

### 12.1 Release and distribution keys (AD-13)

The table above enumerates every key **the product holds**. It did not enumerate the keys that
**produce** the product — and a signing key appearing in no key-lifecycle table has, by omission, no
custody, rotation, or compromise-recovery story at all. That is a worse gap than a missing threat
row, because §12 is the table whose whole purpose is to be exhaustive.

| | **ReleaseManifestKey (RMK)** — ours | **Platform signing identities** — Apple / Microsoft / Google | **Transparency-log key** |
|---|---|---|---|
| **Held by** | The organization, **HSM- or cloud-KMS-resident, never on a developer workstation** | Vendor-issued; **Play App Signing and App Store signing mean a third party holds a key that can produce an artifact users will accept** | The log operator |
| **Custody class** | Hardware-backed, quorum-gated for use | Vendor-defined; **outside our control by construction** | Log-operator-defined |
| **Rotation** | Scheduled, with an overlap window; the *new* key is published in a manifest signed by the *old* one, so a client that has seen either can verify the transition | Vendor process; a change is visible to clients as a platform-signature change | Log operator's process |
| **Compromise recovery** | Revoke via the released-version registry (S-23) and the transparency log; **the log is what makes a forged-but-signed artifact detectable** — signature alone cannot distinguish it | **Not ours.** See **TM-32**: a vendor may also revoke *us*, disabling installed software | Log misbehaviour is detectable by any auditor holding a prior view |
| **Blast radius if compromised** | **Every device in every `TwinNet`** — strictly wider than the `OwnerRootKey`, which reaches one | Same, on that platform | Enables a forged artifact to appear legitimately logged; must be combined with an RMK compromise to be useful |

> **Rule TM-K2 (normative).** No single human may cause a release artifact to be produced and
> signed. RMK use is quorum-gated, and every release is recorded in the transparency log **before**
> it is served. This is the separation-of-duties control that **O-4** observes is absent for
> infrastructure operators, applied here to the one key whose blast radius exceeds the `Owner`'s.
>
> **Rule TM-K3.** The update transport is **not** part of the trust argument. Artifacts are
> verified offline against the RMK, the platform signature, the manifest's monotonic version, and a
> log inclusion proof. A compromised mirror, CDN, or TLS terminator therefore gains nothing — which
> is what allows self-hosted operators to mirror our artifacts without becoming trusted
> ([ADR-0021](adr/ADR-0021-packaging-distribution-and-updates.md) §11.15(d)).

---

## 13. Lost or stolen device, and the `Owner`-loses-everything case

**Runbook — lost or stolen device.**

| Step | Action | Mechanism | Timing |
|---|---|---|---|
| 1 | Establish whether the device was **locked** at the time of loss | If locked and `hardware_backed = true`, IK is unusable before first unlock; the exposure is materially lower ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.8) | immediate |
| 2 | Revoke from **any** `REVOKE`-powered OSK device | `RevocationRecord`, `trust_epoch`+1, new `EpochSeed` HPKE-sealed to every **surviving** device (N-25) | seconds |
| 3 | If the lost device held an `ENROLL` or `DELEGATE` OSK, this is a **high-power** operation | Requires one ORK signature **or** `k = min(2, n_osk)` independent OSK signatures, excluding the target's own OSK (N-11) | one ceremony |
| 4 | Confirm propagation | p95 ≤ 30 s / p99 ≤ 5 min for control-plane-reachable devices; ≤ 120 s (one rekey interval) for a device reached only via an updated peer | minutes |
| 5 | Account for partitioned peers | A peer partitioned from **both** the control plane and every updated peer keeps accepting the revoked device at **baseline** for as long as the partition lasts; all *granted* authority (egress, LAN, routes, new pairing) is suspended at `T_TRUST_HARD` (default **30 d**) | baseline: unbounded by partition; privileged: ≤ 30 d |
| 6 | If the device was file-backed (`hardware_backed = false`), assume the identity **cloned** | TM-13; watch for `AUTH.IDENTITY_CONCURRENT_USE` | ongoing |
| 7 | Re-enrol a replacement | First-class flow: the `Owner` approves the new identity from an OSK device, the `TwinNet` label and role carry over, and the old `device_id` is revoked in the same operation | one ceremony |

**Rule TM-L1.** Existing `Session`s on a partitioned peer MUST NOT be torn down at the
`T_TRUST_HARD` boundary — that would violate I5 — and at `T_TRUST_HARD` every *granted* authority — exit egress, LAN access, route acceptance, new pairing — is **suspended** (N-27). A **baseline** handshake to an already-known `TrustedPeer` is still accepted: refusing it would make the control plane a liveness dependency of the data plane and break **R-11**.
Shortening `T_TRUST_HARD` strengthens revocation and penalises genuinely offline deployments; that
tradeoff belongs to the `Owner` and is configurable within [24 h, 90 d].

**The `Owner`-loses-everything case.**

| Scenario | Recovery | Cost |
|---|---|---|
| Non-admin device lost | Any `REVOKE`-powered OSK signs a `RevocationRecord` | none |
| One admin device lost, ≥ 2 remain | The remaining two OSKs jointly revoke and re-delegate | none; no phrase needed |
| Only admin device lost, **phrase held** | Enrol a replacement, reconstitute ORK from the phrase on it, publish anchor v+1 revoking the lost OSK and delegating a fresh one, zeroize ORK | one manual ceremony |
| Only admin device lost, **phrase lost** | **Unrecoverable.** No party — including the control plane, by design — can mint a delegation. The `TwinNet` must be destroyed and every device re-enrolled | total re-enrolment |
| Recovery phrase compromised | **No recovery.** The attacker is indistinguishable from the `Owner` | total trust-root compromise (TM-30) |

Two mitigations are mandatory because the "phrase lost" row is unrecoverable: TwinNet creation
MUST NOT complete until the `Owner` re-enters three randomly chosen words (N-12), and the client
MUST display a recurring warning while `n_osk == 1` (N-13). Both are pressure against the failure,
not a fix for it.

---

## 14. Abuse and misuse

### 14.1 `ExitNode` abuse and attribution

Egress at an `ExitNode` carries **that device's own IP address** ([docs/vision.md](vision.md)
§3.1). If a compromised or malicious `TrustedPeer` routes abusive traffic through an `Owner`'s
`ExitNode`, the abuse is attributed to the `Owner` — by their ISP, by the destination service, and
by any subsequent legal process. Two design facts make this sharper than it looks:

1. Authorization is enforced at the `ExitNode` (§7), so the `Owner` *can* prevent it — but only
   with a policy they actually configured.
2. [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) §11.10 places browsing and
   destination history in the "never collected, in any mode" column. **An `Owner` therefore has no
   record with which to demonstrate that traffic originated from a specific peer.** This is a
   deliberate privacy choice with a real cost, and it is filed as §15 O-8: the corpus must decide
   whether per-peer *volume* counters at an `ExitNode` (which are `OPERATIONAL`, not `SENSITIVE`)
   are sufficient, or whether an opt-in local-only attribution log is needed.

Per-peer NAT state, accounting, and policy at an `ExitNode` are required by I7 and owned by
[ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md).

### 14.2 `Relay` abuse as an amplifier or open proxy

The relay is a public packet forwarder, which is a DDoS weapon by default. Three properties make
it not one:

- **Amplification factor is exactly 1.0 by construction** — one frame out per frame in, of equal
  payload length, never fanned out, retransmitted, or padded, and **zero bytes** emitted in
  response to any unauthenticated or unbound frame ([ADR-0005](adr/ADR-0005-relay-architecture.md)
  §11.5). Handshake amplification is ≤ 1 (Noise_IK msg2 ≤ msg1).
- **No asymmetric operation for an unvalidated source address**: above 20 handshakes/s from a
  source /24 (v4) or /48 (v6), the relay issues a stateless cookie challenge first.
- **It is not an open proxy.** Unlike TURN, which allocates a relayed transport address reachable
  by anyone, a TwinVPN relay forwards only between two half-flows joined by a `pair_tag`, and only
  under a valid `RelayCapabilityToken` bound to the bearer's `RLK`
  ([ADR-0005](adr/ADR-0005-relay-architecture.md) §6 B, §11.3).

Residual: a `pair_tag` squatter can occupy a pending slot for 30 s, producing
`RELAY.PAIR_COLLISION` — the squatter cannot produce valid L-DATA, so the cost is a slot and a
diagnostic. A revoked device can consume relay quota until its token expires (≤ 24 h), because
relay denial is defence in depth only.

### 14.3 Pairing spam

A ceremony requires an OSK `ENROLL` approval on an existing device (C-D), so an outsider cannot
enrol. The spam surfaces are: unmatched `BIND`s at a relay (bounded by a 30 s pending slot and
`RELAY.BIND_RATE_LIMITED` at 30/min per subject), and rendezvous mailbox pressure (per-target and
small, [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §11.5). SPAKE2 runs are
capped at **5 failures per `pairing_id`** with a 120 s single-use expiry (N-17). No corpus rule
currently limits how many concurrent ceremonies one device may initiate; the exposure is local
resource use rather than trust, so it is recorded here rather than escalated.

---

### 14.4 Managed devices — the MDM administrator as an `Owner`-class principal

On a supervised or MDM-managed device the administrator can remove the app, the VPN payload, or the
Always-On configuration. **The OS grants them that authority and TwinVPN cannot refuse it.** Where
the administrator and the `Owner` are the same person this is unremarkable. Where they are different
people — a corporate-managed laptop carrying a personal `TwinNet`, a family device under a school
profile — **the administrator can remove protection and the `Owner` cannot prevent it.**

Stated precisely, because the boundary is narrower than it first appears:

| The MDM administrator **can** | The MDM administrator **cannot** |
|---|---|
| Remove the application entirely | Lower the enforcement mode through configuration — **KS-22**'s monotone rule makes the effective mode `max(local, profile_required)`, and the `DeploymentProfile` schema has **no expressible field** that reduces it ([ADR-0021](adr/ADR-0021-packaging-distribution-and-updates.md) §11.15) |
| Remove the VPN payload or the Always-On configuration | Author or alter `AccessPolicy` / `DNSPolicy` — S-06/S-07 are the `Owner` authority's, and a profile carrying either is **rejected wholesale**, never field-by-field |
| Pin the update channel and raise the enforcement floor | Change the `OwnerTrustAnchor` pin, which is build-time — a mirror may serve bytes, it may not change who signs them |
| Cause the device to stop being protected | Obtain any key, forge membership, or make the product **misreport** its own state |

**The mitigation is visibility, not prevention**, and that is the honest form: the client reports
configuration removal as an unmissable standing state ([ADR-0019](adr/ADR-0019-application-state-model-and-ui-architecture.md)
owns the presentation). **Detection only** — recorded as an accepted residual below rather than
claimed as a defence, because a design that cannot refuse an authority should not imply it can.

---

## 15. Open issues and residual risks

Numbered, each with a proposed owner. **O-1 through O-6 are defects in the current corpus, not
merely accepted risks.**

| # | Issue | Why it matters | Proposed owner |
|---|---|---|---|
| **O-1** | *(closed)* **State-ownership row-number collision — resolved.** Verified: only [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) declares **S-25** and **S-26**; the ADR-0005 / ADR-0007 / ADR-0012 duplicates were renumbered. `scripts/validate-docs.sh` check 4 enforces this continuously (no duplicate `S-` owners), with **S-27** the one deliberately-shared row | The state ownership table is the load-bearing artifact for I8. Three writers nominally sharing one row id makes "one writer per fact" unverifiable. | — None owed |
| **O-2** | **`PairSecret` is defined twice, incompatibly.** [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.4 defines it as `HKDF(ceremony_key ‖ X25519(e_A,e_B), salt = transcript_hash)` — **forward-secret** against later static-key compromise. [ADR-0005](adr/ADR-0005-relay-architecture.md) §11.1(3) and §11.2(d) define it as `X25519(my_LDATA_static_priv, peer_LDATA_static_pub)` — a plain **static-static** DH. | `PairSecret` feeds `TwinNetPSK` ⇒ `psk2`. Under the static-static definition, an adversary who breaks X25519 recovers `psk2` directly, which **voids the post-quantum hedge** of [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.5(1) and weakens forward secrecy for the PSK contribution. It also makes `pair_tag` computable from static keys alone. | SECURITY + NETWORKING — ADR-0007's definition should win; ADR-0005 §11.1(3) needs a distinct name (e.g. `RelayPairSeed`) or must consume ADR-0007's value from `TrustedPeer` |
| **O-3** | **The rendezvous holds an identity-level peer graph.** [ADR-0005](adr/ADR-0005-relay-architecture.md) §6 calls handing a relay the identity graph "the single largest avoidable metadata disclosure in the design" and spends the whole `pair_tag` mechanism avoiding it — yet the rendezvous learns exactly that, keyed on `device_id`, which is **stable for life** ([ADR-0004](adr/ADR-0004-nat-traversal-strategy.md) §7). | The system's strongest metadata mitigation is bypassed by a component nobody applied it to. | NETWORKING + SECURITY — evaluate a rotating rendezvous handle analogous to `pair_tag`, or state the exposure as accepted with a rotation and retention bound |
| **O-4** | **No separation-of-duties rule for infrastructure operators.** Nothing forbids the relay-credential issuer, the relay operator, and the rendezvous operator from being the same legal entity. If they are, `relay_sub` de-pseudonymises trivially (the issuer computes it) and can be joined to the rendezvous graph. [ADR-0005](adr/ADR-0005-relay-architecture.md) V7 names the trigger but no ADR sets the rule. | AD-8 (malicious insider) is the adversary with the widest metadata reach and the thinnest documented constraint. No audit, break-glass, or retention requirement for production access exists anywhere in the corpus. | SECURITY + OPERATIONS — a new ADR or an ADR-0005 amendment |
| **O-5** | **The default `AccessPolicy` is unspecified.** [docs/protocol.md](protocol.md) §13.1 requires route advertisements to be permitted by the *receiver's* `AccessPolicy` and names the `0.0.0.0/0` capture attack — but no document states the shipped default for route acceptance, LAN grants, or exit grants. Nor does any document state which devices receive `ENROLL`/`DELEGATE` OSK powers by default. | If the default is permissive, TM-01/TM-17 have no real mitigation and AD-3 escalates to AD-8-within-the-`TwinNet`. If every device gets `ENROLL`, compromising any one device compromises membership. | SECURITY — an `AccessPolicy` defaults section, in [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md) or a policy ADR |
| **O-6** | **Wall-clock dependence contradicts [ADR-0009](adr/ADR-0009-state-consistency.md) K-1**, which states "no ordering or **security decision** depends on a timestamp". Relay admission depends on `nbf`/`exp` ±300 s; pairing expiry is 120 s wall-clock; `pair_tag` buckets are wall-clock; `DeviceCertificate` `not_after` is wall-clock. | Either K-1 must be narrowed to *durable ordering* explicitly, or the four wall-clock security decisions must be re-derived. As written the corpus asserts a property it does not have. | ARCHITECTURE — reconcile ADR-0009 §11.7 K-1 with ADR-0005 §11.3 and ADR-0007 §10 |
| **O-7** | **No ADR owns volumetric DDoS defence** for the relay or control-plane tier (TM-27). Amplification is solved; absorption capacity, scrubbing, and anycast strategy are not decided anywhere. | R-11 ("no single point of failure") is argued from redundancy, not from capacity. | OPERATIONS / NETWORKING |
| **O-8** | **`ExitNode` attribution has no supporting record** (§14.1): destination history is never collected in any mode, so an `Owner` cannot demonstrate which peer originated traffic attributed to them. | A privacy guarantee and an accountability need are in direct conflict, and the conflict is currently unresolved rather than decided. | SECURITY + [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md) |
| **O-9** | **Signature-algorithm inconsistency.** [ADR-0005](adr/ADR-0005-relay-architecture.md) §11.3 specifies the `RelayCapabilityToken` as **Ed25519**-signed, while [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.1/N-1 makes the entire `Owner` hierarchy **ES256**, and §6 H2 rejects Ed25519 explicitly for adding a second verifier surface. ADR-0005 §11.2 also places a requirement on ADR-0007 (an `Owner`-rooted, offline-verifiable relay-credential issuer) that ADR-0007 does not discharge — the issuer is not mentioned there at all. | Two signature algorithms in one trust hierarchy doubles verifier surface for no stated gain, and an undischarged interface means the issuer's root of trust is unspecified. | SECURITY — ADR-0007 must define the relay-credential issuer delegation; ADR-0005 should adopt ES256 |
| **O-10** | *(closed)* **`docs/testing-strategy.md` §4 exists.** "The mandatory proof tests P01–P15" is present and complete, and the application-architecture workstream extended it with **§4.3 (P16–P22)**, raising the acceptance set to twenty-two. **T-09** in §16 resolves with it | Every structural security claim in the corpus (notably P14) is currently unverifiable because its oracle is undefined. | — None owed |
| **O-11** | *(closed — **jointly**, and MUST NOT be closed against either ADR alone)* **The local management IPC is now specified.** **Authentication:** [ADR-0017](adr/ADR-0017-local-management-interface.md)'s peer-credential transport attestation plus [ADR-0016](adr/ADR-0016-client-process-and-privilege-separation.md) §11.7's per-action OS authentication. **Authorization:** ADR-0016's class map and PS-12a principals with ADR-0017's per-request scope check against an attach-time immutable scope set. **Audit:** ADR-0017's MI-D7 ledger (made load-bearing by MI-19's non-lossy rule) plus ADR-0016's PS-23, covering the three act-classes that never traverse the interface — acts performed while the authority is not running, refusals that never reach an operation handler, and acts performed by the package. **The KS-9(2) half resolved differently than expected:** [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) **KS-9a** now records that mandating a *local authenticated IPC* was itself the defect — on the selected topology the sockets and the enforcement layer are in one process, so the registration is intra-process and the mandated endpoint would have *been* the confused-deputy surface KS-9 exists to deny | Both are the shortest path from local privilege escalation to a disarmed kill switch. KS-9(1) bounds the damage but does not define the surface. | — None owed |
| **O-12** | **`local_network_access` defaults to `ALLOW` on every network**, including hostile ones, while LAN *discovery* defaults to **off** on networks marked untrusted ([docs/networking.md](networking.md) §8.2(4)). | An inconsistent posture: we suppress discovery on a hostile LAN but leave on-link reachability open (AD-11). At minimum the two defaults should be derived from the same "untrusted network" signal. | SECURITY — [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) KS-4 |

**Accepted residual risks** (known, bounded, and deliberately not fixed): TM-12 (unlocked stolen
device), TM-13 (cloning where `hardware_backed = false`), TM-14 (TK extraction at agent
privilege), TM-30 (recovery-phrase compromise), N2/N3 (traffic analysis and no padding), N5
(coerced `Owner`), the `T_TRUST_HARD` revocation window (30 d on *privileged* access; baseline reachability to a
fully partitioned peer is unbounded), and the per-platform kill-switch limitations of
[ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.6 (iOS boot window, Android
without lockdown, macOS Recovery, Linux single-user, Android safe mode).

**Added by the application-architecture workstream**, each known, bounded and deliberately not fixed:

- **TM-32 / vendor revocation.** Apple may revoke a notarization ticket and disable *already
  installed* software. No mechanism of ours reduces it; the transparency log gives detection for a
  forged artifact but nothing gives recourse for a revoked legitimate one.
- **AD-14 / managed devices (§14.4).** On a managed device the MDM administrator is an
  `Owner`-class principal for KS-21(2). Detection only.
- **The iOS/iPadOS update window.** The **only** platform where applying an update costs
  *protection* rather than *availability*: the provider **is** the enforcement, so it is absent
  while being replaced, and the window is **not bounded a priori** — the OS restarts the provider at
  the next network event. It is **measured by P20-C, not asserted to be zero**, and is closable only
  with a supervised-device Always-On payload, which is an MDM capability and not an app capability.
  On every other platform an update costs availability: the tunnel may drop, but protected traffic
  is **dropped, not leaked**, because the enforcement object is independent of the process being
  replaced ([ADR-0021](adr/ADR-0021-packaging-distribution-and-updates.md) §11.10).
- **TM-31 residual.** An attacker holding *both* a release key and log-inclusion capability is
  detected only afterwards, and only by someone auditing the log.
- **Headless enrolment-offer scrollback** (TM-11) and **router physical access** (TM-13), above.
- **I4 on targets with no secure element.** On routers, containers and CLI-only installs the private
  half is a file: **I4 is not upheld**, and what remains is revocation, `EpochSeed` exclusion, and
  `AUTH.IDENTITY_CONCURRENT_USE` — *containment, not prevention*. The device declares its
  `custody_class` (S-54) and a `SOFTWARE_PORTABLE` device MUST NOT hold an `ENROLL`/`REVOKE`/`DELEGATE`
  OSK ([ADR-0023](adr/ADR-0023-headless-cli-and-embedded-profile.md) EM-31).

**Pending amendments already agreed by their owners**, tracked here so they are not lost:
[ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.5 item 2 (TwinNet-wide
PSK secret) and §7.7/K2 (short `DeviceCertificate` lifetime) are overruled by
[ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §11.5;
[docs/protocol.md](protocol.md) §11.1 `ReserveRelayReq.peer_key_id` is overruled by
[ADR-0005](adr/ADR-0005-relay-architecture.md) §7.4.

---

## 16. Assumptions register

Each row is an assumption this document makes about another owner's area. If a row is wrong, the
named section here must change.

| # | Assumption | Owner to confirm | Impact if wrong |
|---|---|---|---|
| **T-01** | `PairSecret` is the forward-secret ceremony-derived value of [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.4, not a static-static DH | SECURITY / NETWORKING (O-2) | §11's post-quantum posture and §2 A6 are both wrong; the PQ-hedge claim must be withdrawn |
| **T-02** | The relay-credential issuer is `Owner`-rooted and offline-verifiable, per [ADR-0005](adr/ADR-0005-relay-architecture.md) §11.2 | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) (O-9) | TB-8's authentication column and TM-22 lose their root; a compromised issuer could mint relay admission for arbitrary parties |
| **T-03** | The default `AccessPolicy` denies route advertisement, LAN grants, and exit grants absent an explicit `Owner` grant | [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md) (O-5) | TM-01, TM-15, TM-16, TM-17 lose their mitigation and AD-3's "worst outcome" becomes lateral movement across the whole `TwinNet` |
| **T-04** | [ADR-0011](adr/ADR-0011-dns-handling.md) delivers the containment interface of [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.12(a), including portal-window cache separation | [ADR-0011](adr/ADR-0011-dns-handling.md) | TM-18 has no mitigation; DNS becomes the leak channel R-14 exists to close |
| **T-05** | [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) delivers in-tunnel transcript confirmation and the monotonic floor consumed by the Noise prologue | [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) | TM-09 degrades to prologue-binding only; the transcript half of D2 is missing and P11 has no oracle |
| **T-06** | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) delivers an `Owner`-signed relay map with failure-domain labels and ≥ 2 alternates per region across ≥ 2 domains | [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md) | TM-22 loses its root of trust and TM-04's availability argument loses its ≥ 2-alternate premise |
| **T-07** | [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md) makes forwarded traffic distinguishable from locally originated traffic at the enforcement layer, and provides per-peer isolation at B5/B6 | [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md) | KS-2 is inexpressible, so gateway forwarding could reach a §11.2 exemption; TB-3 isolation is unenforced |
| **T-08** | [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) contains **no** message type that reduces enforcement, and none that carries a disarm instruction | [ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §11.12(d) | §10.1's third prohibition becomes a runtime check rather than a structural property, and AD-7 gains leak capability |
| **T-09** | ~~[docs/testing-strategy.md](testing-strategy.md) §4 will define P10, P11, P13, and P14~~ — **RESOLVED.** §4 exists and defines P01–P15 with the mutant and positive-control discipline (V2, V4) this row required; §4.3 adds P16–P22 | TESTING (O-10) | **Confirmed.** §8.1 and §10.1's structural claims now rest on defined oracles; P14 in particular has its mutant set |
| **T-10** | `relay_sub` is computed only by the issuer, and relay operators receive no mapping to `device_id` | [ADR-0005](adr/ADR-0005-relay-architecture.md) / OPERATIONS (O-4) | §6.2's relay row and §8.3 are wrong; the relay holds an identity graph and AD-5 collapses into AD-8 |
| **T-11** | This document **is** `docs/threat-model.md` — the file every other document links to. No second security document may be created; security content that is not threat analysis belongs to its owning ADR | ARCHITECTURE | Resolved: the five dangling `docs/security.md` links were repaired to point here |
| **T-12** | Platform attestation APIs (`SecKeyCreateAttestation`, Android Key Attestation, `TPM2_Certify`) remain available on their platforms | [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) V9 | `hardware_backed` becomes uncorroborated on the affected platform; TM-13 and TM-14's "prevented where hardware-backed" columns lose their evidence |
