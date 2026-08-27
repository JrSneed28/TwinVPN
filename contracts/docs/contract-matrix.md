# TwinVPN contract matrix

Ownership, producer, consumer, authority, durability, consistency, retryability,
idempotency, trust boundary, and versioning expectation for every contract
family in `packages`-equivalent `/contracts`.

This is the review artifact. If a question about a contract cannot be answered
from this table, the table is wrong.

Authority for every row: [docs/protocol.md](../../docs/protocol.md) §6 (the
ephemeral/durable test), §7 (single publisher per event type), §16 (the message
catalogue); [docs/architecture.md](../../docs/architecture.md) §5 (the state
ownership table); [ADR-0009](../../docs/adr/ADR-0009-state-consistency.md) §11
(the consistency classes).

---

## 1. The five categories, and why they must not be conflated

Phase 1 draws five distinct lines. Collapsing any two of them is a specific,
named defect, not a stylistic simplification.

| # | Category | Where it lives | Delivery | If misclassified |
|---|---|---|---|---|
| **1** | **Internal shared-core types** | `common.proto`, `errors.proto`, and the local-only messages in `diagnostics.proto` and `peer.proto` | never on a wire, or local ledger only | A local fact that reaches infrastructure is a privacy regression; `NegotiationFloor` in particular becomes remotely lowerable, deleting the anti-rollback property ([ADR-0014](../../docs/adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) N-20) |
| **2** | **Control-plane API contracts** (C1) | `control_commands.proto` | request/response, at-least-once, idempotency key | An RPC that should have been a durable event loses its cursor, so an offline device never learns it happened |
| **3** | **Durable control-plane events** (C2) | `control_events.proto`, `EVENT_DURABILITY_DURABLE` | at-least-once, cursor-resumable, total order per TwinNet | **Treating a durable event as ephemeral is a SECURITY failure**: a device asleep during a revocation broadcast wakes still trusting a stolen laptop, and nothing will ever correct it ([docs/protocol.md](../../docs/protocol.md) §6.1) |
| **4** | **Ephemeral signaling** (C4, and ephemeral C2) | `signaling.proto`, `candidate.proto`, the ephemeral arm of `control_events.proto` | at-most-once, unordered, TTL'd, never logged | **Treating an ephemeral message as durable is a COST, PRIVACY and DENIAL-OF-FRESHNESS failure**: durable presence is a permanent movement and IP history of the Owner, and draining it delays the one `DeviceRevoked` that matters |
| **5** | **Peer-to-peer negotiation and in-session protocol** (C5/C6) | `signaling.proto` path/session messages, `gateway.proto` grants | in-session, ordered by a monotone epoch | Putting a two-party session fact on the control plane breaks **I5**: a control-plane blip would prevent re-establishing a session whose keys and endpoints are already cached |

**Data-plane packets (C5/C6 payload) appear in no contract in this package.**
[ADR-0003](../../docs/adr/ADR-0003-network-contract-schema-format.md) §11 B4:
"A serialization library MUST NOT appear in the packet path." Fixed-layout
binary framing is owned by
[ADR-0001](../../docs/adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md).
This is a reliability property as much as a performance one: the highest-rate,
hardest-to-debug path is immune to serialization bugs by construction.

---

## 2. Core domain contracts

| Contract | File | Producer | Consumer | Authoritative source | Durability | Consistency | Trust boundary |
|---|---|---|---|---|---|---|---|
| `Device` | `device.proto` | Coordination service | Every device | Coordination (S-02) | durable | `STRONG` @ authority, `MONOTONIC` @ edge | B1 semi-trusted |
| `DeviceIdentity` | `identity.proto` | The device itself (derived) | Every peer, offline | The device (self-certifying) | durable | `MONOTONIC` by `generation` | B1/B2; verifiable with no network |
| `DevicePlatform`, `DevicePlatformInfo` | `device.proto` | The device | Coordination, peers | The device | durable | `EVENTUAL` | B1 |
| `Capability`, `CapabilitySet` | `capability.proto` | The advertising device (S-19) | The negotiating peer | The device's **real platform probe** | durable advertisement; per-`Tunnel` negotiated set | `EVENTUAL` globally, `STRONG` per `Session` | **B3 pre-auth** |
| `TrustedPeer` | `peer.proto` | The local device (S-05) | Local only | The local device | durable local; **no remote replica** | `LOCAL` | B1 for the transmissible projection |
| `PeerTrust` | `peer.proto` | Derived locally | Local UI and policy | Derived; never transmitted as authority | non-durable | `LOCAL` | none |
| `PeerPermission` | `peer.proto` | **Owner authority** (OSK with `POLICY`) | Enforcement points | Owner (S-06) | durable, inside the signed bundle | `MONOTONIC` | B2 signed |
| `Pairing`, `PairingRequest/Challenge/Approval/Result/Revocation` | `pairing.proto` | Coordination (fact); both devices (attestations) | Both devices | Coordination for the fact; the **devices** sign the statements | durable | `STRONG` at commit, `MONOTONIC` propagation | B1 + B2 |
| `PairingAttestation` | `pairing.proto` | Each pairing device | The other device, and every peer | The signing device (Rule B) | durable | `STRONG` | **B2 — coordination transports what it cannot forge** |
| `Presence`, `Heartbeat` | `presence.proto` | The device, **for itself only** | Peers | The device (S-11) | **ephemeral, TTL'd** | `EVENTUAL`; **never a gate** | B1 |
| `Endpoint`, `IPAddress`, `IPPrefix` | `common.proto` | Whoever observes | Everyone | contextual | contextual | contextual | contextual |
| `NetworkInterface` | `candidate.proto` | Platform adapter | **Local diagnostics only** | The device | non-durable | `LOCAL` | **never transmitted** |
| `ConnectionCandidate`, `CandidateSet` | `candidate.proto` | The gathering device | The peer, via untrusted rendezvous | The device (Rule B signed) | **ephemeral, ~30 s** | none | **B3 — worst case, pre-auth, attacker-reachable** |
| `NetworkPath` | `connection.proto` | The local device (S-14) | Local | The device | non-durable | `LOCAL` | none |
| `ConnectionSession` | `connection.proto` | The owning device (S-12) | Local; lossy telemetry replica | **The device, always** | durable identity + last state | `LOCAL` | none |
| `TunnelDescriptor`, `TunnelState` | `tunnel.proto` | Tunnel engine (S-13) | Local | The device | **non-durable by requirement** | `LOCAL` | none |
| `ConnectionState` | `connection.proto` | The state machine | Every surface | [docs/reliability.md](../../docs/reliability.md) §4 | derived | `LOCAL` | none |
| `ConnectionHealth` | `connection.proto` | The measuring device | Local; peer via `PeerHealthReport`; collector | The device (S-10/S-22) | ephemeral | `EVENTUAL` | B1/C5/C7 |
| `LanGateway`, `ExitNode` | `gateway.proto` | The acting device | Every device (offers) | The **acting device**, signed | durable, TTL'd | `MONOTONIC` per offerer | B2 signed |
| `GatewayCapability` | `gateway.proto` | The acting device | Peers | The device's probe | durable | `EVENTUAL` | B3 |
| `LanAccessPolicy` | `gateway.proto` | Owner authority | The gateway | Owner (S-06) | durable | `MONOTONIC` | B2 signed |
| `LanAccessGrant`, `ExitNodeGrant` | `gateway.proto` | **The gateway / exit node** (S-36) | The requesting client | The gateway; the client's view is advisory | non-durable | `LOCAL` at the gateway | C5 in-session |
| `AccessPolicy` (`PolicyBundle`) | `policy.proto` | **Owner authority** | Every device | Owner (S-06/S-07); coordination cannot author | durable | `MONOTONIC` reads mandatory | **B2 signed** |
| `RoutePolicy`, `RoutePrefix`, `Route` | `routing.proto` | Owner (policy); the advertiser (advertisement); the local device (acceptance) | Routing engine | split: S-06 / S-16 / S-17 | durable (policy, advertisement), derived (acceptance) | `MONOTONIC` / `LOCAL` | B2 signed |
| `RouteAdvertisement` | `routing.proto` | The advertising device | Every device | **The advertiser** (S-16), signed | durable, TTL'd | `MONOTONIC` per advertiser | B2 signed |
| `DNSPolicy` | `dns.proto` | Owner authority | The DNS subsystem | Owner (S-07) | durable | `MONOTONIC` | B2 signed |
| `DNSProtectionAssertion` | `dns.proto` | The enforcement layer, **by query** | Local UI and diagnostics | The device | non-durable, **expiring** | `LOCAL` | never transmitted as authority |
| `Relay`, `RelayRegion` | `relay.proto` | Relay-fleet operator | Every device | The **signed relay map** (S-09) | durable, cached | `EVENTUAL` | B2 signed map |
| `RelayHealth` | `relay.proto` | Relay-selection service (S-10) | Devices | Aggregated self-reports | non-durable | `EVENTUAL`; **never a gate** | B1 |
| `RelayAssignment` | `relay.proto` | Coordination | The device | Coordination, **advisory only** | **ephemeral** | `EVENTUAL`, no convergence requirement | B1 |
| `RelayBinding` | `relay.proto` | The relay instance (S-29) | The device leg | The relay | **non-durable by requirement** | `LOCAL` | C6 |
| `RelayCapabilityTokenDescriptor` | `relay.proto` | Relay-credential issuer (S-30) | Relays, offline | The issuer, signed | durable both sides | `MONOTONIC` by `epoch` | B2 signed |
| `ProtocolVersion`, `NegotiatedProtocolVersion` | `common.proto` | The device build + local policy (S-20) | The peer | The device; **not narrowable by the control plane** | durable | `EVENTUAL` globally, immutable per `Tunnel` | B3 |
| `SchemaDescriptor` | `common.proto` | The build | Diagnostics | The artifact | immutable per artifact | `LOCAL` | never a compatibility gate |
| `ErrorEnvelope` | `errors.proto` | Whoever observes | Everyone | the **registry**, for attributes | contextual | n/a | received attributes are a claim, not a fact |
| `DiagnosticContext` | `diagnostics.proto` | The emitting device (S-22) | Local ledger; opt-in bundle | The device | Tier-0 durable ring | `EVENTUAL`, lossy | never authoritative |

---

## 3. Control-plane commands (C1)

All are **request/response**, at-least-once with client retry, server dedup on
`idempotency_key`, per-stream FIFO with no cross-stream ordering.

| Command | Class ([ADR-0008](../../docs/adr/ADR-0008-idempotency.md) §11.3) | Idempotency | Retryable | Consistency | Notes |
|---|---|---|---|---|---|
| `RegisterDevice` | `CEREMONY` | key required, 24 h | yes, same key | **linearizable** on `(twinnet_id, device_pubkey)` | `device_id_echo` is an **echo, never an assignment** |
| `UpdateDeviceMetadata` | `DECLARATIVE` | `if_version` | yes | `MONOTONIC` | addresses and identity are **not** mutable here |
| `RevokeDevice` | `CEREMONY` | key required | yes, same key | **linearizable admission + monotonic reads** — the strongest requirement in TwinVPN | two signers: Owner authorizes, writer orders |
| `RotateDeviceCredential` | `CEREMONY` | key required | yes | `MONOTONIC` per counter | `IdentitySuccession` is **dual-signed** |
| `BeginPairing` | `CEREMONY` | key required | yes | **linearizable** | duplicate returns the **original** `pairing_id` |
| `CompletePairing` | `CEREMONY` | key + `if_version` | yes | **linearizable** | replay returns the **original outcome** — this is what prevents asymmetric trust |
| `CancelPairing` | `CEREMONY` | key required | yes | linearizable | burns the `pairing_id`; it is single-use |
| `RevokePairing` | `CEREMONY` | key required | yes | linearizable | **distinct from device revocation** — removes one relationship, revokes nobody |
| `DiscoverPeers` | read-only | trivially idempotent | yes | `MONOTONIC` | snapshot + delta via `since_net_seq`; on outage, **use the cache and keep connecting** |
| `PublishPresence` | `REGISTER` | LWW, **no dedup log** | yes, and **permitted to be lost** | `EVENTUAL` | never a gate |
| `PutRouteAdvertisement` / `Withdraw` | `DECLARATIVE` | monotone `advertisement_epoch` | yes | `MONOTONIC` per advertiser | whole desired set, never a delta |
| `PutExitNodeOffer` / `Withdraw` | `DECLARATIVE` | monotone `offer_epoch` | yes | `MONOTONIC` per offerer | |
| `PutPolicy` | `CEREMONY` | key + `if_version` | yes | **linearizable, quorum-committed** | **the only policy mutation in the contract set** |
| `SubscribeEvents` | streaming | n/a | yes | `MONOTONIC` | resume, do not reload |
| `GetStateDocument` | read-only | trivially idempotent | yes | `MONOTONIC` | pull is **always sufficient**; push only reduces latency |

### 3.1 Requests that Phase 1 places elsewhere

The Phase 2 objective lists these as control-plane requests. Phase 1 places each
somewhere else, by name, with a stated reason. They are implemented where Phase 1
puts them.

| Requested name | Where it actually lives | Phase 1 reason |
|---|---|---|
| `BeginConnection` | `ConnectOffer` / `ConnectAnswer`, **C4 ephemeral signaling** | §10.1: it is "*not* a control-plane RPC, because the coordination service must not be in the critical path of every reconnect (**I5**)" |
| `ExchangeCandidates` | `CandidateSet`, **C4** | §10.4: the canonical ephemeral case; persisting candidates produces reconnect storms against expired mappings and recycled addresses |
| `RequestRelay` / `ReleaseRelay` | `BIND` / `BOUND`, **device↔relay on C6** | §16 row 21 **withdrawn**. §11.1: "Routing reservations through coordination would put the control plane in the data path and break **I5**" |
| `ResumeSession` | `ResumeSession`, **peer-direct C5** | §12.1: resumption "MUST work with the control plane completely down"; a control-plane round trip is the root cause of "missing auto-reconnect" |
| `EndSession` | `EndSession`, **peer-direct C5** | same; and it is a courtesy, not a requirement — a crashed device sends nothing |
| `UpdatePeerPermissions` | `PutPolicy` (`access_rules[]`) | §13.4: a separate command would create a **second policy author** |
| `UpdateRoutePolicy` | `PutPolicy` (`route_policy`) | same |
| `UpdateDNSPolicy` | `PutPolicy` (`dns_policy`) | same |
| `AdvertiseGateway` / `WithdrawGateway` | `PutRouteAdvertisement` and `PutExitNodeOffer` | there is no generic "gateway" object; a gateway is a **role** of a `Device` |
| `ReportConnectionHealth` | `HealthSample`, **C7 management plane** | §14: ephemeral, batched, loss-tolerant, and "MUST NOT affect the control or data plane" |
| `DiscoverPeer` | `DiscoverPeers` (`GetPeersReq`) | snapshot-plus-delta is the general pattern for every cached collection |

---

## 4. Control-plane events (C2)

**Sole publisher per type is enforced at the log, not by convention.** A receiver
MUST reject an event whose publisher does not match
[docs/protocol.md](../../docs/protocol.md) §7, with
`CONTROL.EVENT_WRONG_PUBLISHER`, treated as a **security event**.

### 4.1 Durable

Each fails at least one check of the four-part test in §6, so ephemeral delivery
would be a defect.

| Event | Publisher | E1 re-derivable | E2 decays | E3 miss ⇒ wrong state | E4 replay harmful |
|---|---|---|---|---|---|
| `DeviceRegistered` | coordination | **no** | no | device invisible forever | **yes** |
| `DeviceMetadataUpdated` | coordination | no | no | stale label/roles | yes |
| `DeviceRevoked` | coordination (Owner-signed inside) | **no** | no | **stolen device stays trusted** | **trust resurrection** |
| `DeviceCredentialRotated` | coordination (device-signed inside) | no | no | peer pins a dead key | key downgrade |
| `PairingRequested` | coordination | no | no | ceremony invisible | yes |
| `PairingApproved` | coordination (device-signed inside) | **no** | no | **asymmetric trust** | trust injection |
| `PairingRejected` / `PairingExpired` / `PairingRevoked` | coordination | no | no | stale pending state | yes |
| `PeerAdded` / `PeerUpdated` / `PeerRemoved` | coordination | no | no | wrong peer set | yes |
| `PolicyBundleUpdated` | coordination (Owner-signed inside) | **no** | no | **enforces stale policy — a silent authorization hole** | **policy rollback attack** |
| `RouteAdvertised` / `RouteWithdrawn` | coordination (device-signed inside) | partially | slow | subnet blackholed indefinitely | mildly |
| `ExitNodeAdvertised` / `ExitNodeWithdrawn` | coordination (device-signed inside) | partially | slow | egress unavailable / stale default route | yes |
| `RelayRegionPolicyChanged` | coordination | no | no | wrong region preference | yes |
| `RelayEpochFloorAdvanced` | coordination (Owner-signed inside) | no | no | relay admits a revoked device longer | **yes** |

### 4.2 Ephemeral, delivered on C2 for latency only

`net_seq == 0`. Not logged, not resumable, not replayed
([ADR-0002](../../docs/adr/ADR-0002-control-plane-messaging-and-event-bus.md) N-9).

| Event | Publisher | Why ephemeral |
|---|---|---|
| `PresenceUpdated` | coordination (aggregating) | passes all four checks; durable presence is a cost, privacy **and** freshness defect |
| `RelayAssignmentHint` | coordination | re-derivable by discovery, decays in minutes, losing it picks a worse relay |

### 4.3 Stream control

| Event | Durability | Purpose |
|---|---|---|
| `StreamCompacted` | in-band, in-order | Announces a **deliberate** gap. Silent omission is prohibited |
| `StateDocumentAvailable` | ephemeral | A document above the 16 KiB inline cap exists; pull it |
| `LogHead` | ephemeral, **B2 signed** | Freshness proof. **Does not defend against a compromised control plane** — the key is online and carries no trust power |

### 4.4 Events the objective lists that are **local, not control-plane**

[docs/protocol.md](../../docs/protocol.md) §7 makes `SessionStateChanged`
local-authority, and calls it load-bearing: *"If the coordination service were
authoritative for `Session` state, a control-plane outage would put every session
into an indeterminate state, and any reconciliation logic would eventually tear
tunnels down."*

All of the following are therefore in `diagnostics.proto` as `SessionEvent`
bodies — device-authoritative, ephemeral, Tier-0 local ledger:

`ConnectionRequested`, `ConnectionNegotiated`, `CandidateUpdated`,
`DirectPathEstablished`, `RelayBindRequested` (the objective's
`RelayRequested`), `RelayBound` (`RelayAssigned`), `RelayUnavailable`,
`RelayChanged`, `SessionStarted`, `SessionResumed`, `SessionEnded`,
`PathChanged`, `TunnelStateChanged`, `ConnectionHealthChanged`.

`PeerOnline` and `PeerOffline` are **not** separate events either: they are
values of `PresenceState` inside one `PresenceUpdated`. Modelling them as
distinct events would imply an ordering guarantee presence explicitly does not
have (§9.2: "**NO ORDERING GUARANTEE** — consumers MUST tolerate reordering"),
and a reordered Online/Offline pair would leave the wrong terminal value. A
single state assertion carrying an absolute `expires_at_ms` cannot be reordered
into the wrong answer.

---

## 5. Delivery semantics, per hop

From [ADR-0002](../../docs/adr/ADR-0002-control-plane-messaging-and-event-bus.md)
§11.12. **No hop claims exactly-once delivery** — it is unachievable over an
unreliable network. Exactly-once *effect* is achieved by idempotency and monotone
versions, which is the guarantee that actually matters.

| Hop | Delivery | Effect | Mechanism |
|---|---|---|---|
| Device → control plane (C1) | at-least-once | **exactly-once effect** | stable `idempotency_key` + `if_version` |
| Control plane → durable log | exactly-once | exactly-once | same transaction as the mutation; no dual write exists to be lost |
| Log → internal bus | at-least-once | **idempotent by construction** | the bus carries only a monotone watermark, a last-writer-wins register |
| Control plane → device (C2) | at-least-once, cursor-resumable, compaction-permitted | idempotent | every event independently applicable; monotone versions rejected on regression |
| Push gateway → device (C3) | at-most-once, best-effort | **none — non-authoritative** | wake hint only |
| Rendezvous `CALL` (C4) | at-most-once, unordered | none required | re-derivable, TTL'd, generation-numbered |
| Device → collector (C7) | at-least-once, loss-tolerant | idempotent by `(device_id, sample_epoch)` | bounded ring; drops reported as `INTERNAL.BUFFER_OVERFLOW` |

---

## 6. Versioning expectation, per family

| Family | Versioned by | Bumps `ProtocolEpoch`? |
|---|---|---|
| Wire/schema shape | `SchemaDescriptor.schema_digest` (a **content identity**, not a version) | **No** — additive changes are compatible by construction |
| Peer protocol behaviour (C4/C5/C6) | `ProtocolVersion` (V-2) | Yes, when a receiver must behave differently |
| Control-plane API behaviour (C1/C2/C7) | `ProtocolVersion` (V-3), same number space | Yes, same rule |
| Capability semantics | `major` in `name/major` | No — a new major is a **distinct capability** |
| Reason codes | `reason_registry_version`, append-only | No |
| Signed statement shape | the `crit` set | Yes if a `crit` member changes |
| Per-object state | monotone `version` / `epoch` per object | No |

See [versioning.md](versioning.md).
