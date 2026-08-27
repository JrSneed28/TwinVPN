# TwinVPN Protocol and Component Contracts

This document is the authoritative specification of **every contract between TwinVPN
components**: the control-plane message envelope, the transport bindings, the event
ownership and delivery model, the ephemeral-versus-durable classification rule, the full
catalogue of protocol interactions (registration through health reporting), and the
consistency requirement that each interaction imposes on the state tier. It defines
*contracts*, not implementations: it says what is exchanged, over which channel, with what
ordering, authorization, idempotency and failure semantics, and which `ConnectionState`
transitions the exchange causes. It does not define tunnel cryptography, NAT traversal
tactics, relay placement, routing tables, or the connection state machine's transition
guards — those belong to the ADRs and documents listed below.

## Related documents

| Document | Relationship |
|---|---|
| [ADR-0001 Tunnel protocol and cryptographic foundation](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) | Supplies all crypto primitives, the handshake, and the transcript this document binds negotiation into. |
| [ADR-0002 Control-plane messaging and event bus](adr/ADR-0002-control-plane-messaging-and-event-bus.md) | **Owned here.** How control messages and durable events physically move. |
| [ADR-0003 Network contract / schema format](adr/ADR-0003-network-contract-schema-format.md) | **Owned here.** The encoding of every payload sketched in this document. |
| [ADR-0004 NAT traversal strategy](adr/ADR-0004-nat-traversal-strategy.md) | Consumes the candidate-exchange and NAT-signaling contracts defined here. |
| [ADR-0005 Relay architecture](adr/ADR-0005-relay-architecture.md) | Consumes relay assignment and relay-forward framing. |
| [ADR-0006 Relay discovery and failover](adr/ADR-0006-relay-discovery-and-failover.md) | Consumes relay assignment / failover contracts. |
| [ADR-0007 Device identity and pairing](adr/ADR-0007-device-identity-and-pairing.md) | Supplies `DeviceIdentity`, `DeviceKey`, and the pairing trust ceremony this document transports. |
| [ADR-0008 Idempotency](adr/ADR-0008-idempotency.md) | Owns idempotency *semantics*; this document only states which interactions require them. |
| [ADR-0009 State consistency](adr/ADR-0009-state-consistency.md) | Owns the state-ownership table and adjudicates the consistency requirements enumerated in §14. |
| [ADR-0014 Protocol versioning and capability negotiation](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) | **Owned here.** Version and `Capability` negotiation rules. |
| [ADR-0015 Observability and diagnostics](adr/ADR-0015-observability-and-diagnostics.md) | Owns the reason-code registry referenced by every failure clause here. |
| [docs/reliability.md](reliability.md) | Owns the authoritative `ConnectionState` machine. This document references states, never redefines transitions. |
| [docs/networking.md](networking.md) | Owns IPv4/IPv6 routing, DNS, and address-family behaviour. |
| [docs/threat-model.md](threat-model.md) | Owns the trust model this document's authorization column assumes. |
| [docs/architecture.md](architecture.md) | Owns component decomposition and plane separation (I8). |

---

## 1. Planes, components, and who talks to whom

Per invariant **I8**, three planes exist with different trust, availability, and consistency
properties. Every contract in this document belongs to exactly one plane.

| Plane | Purpose | Availability requirement | If it is down |
|---|---|---|---|
| **Control plane** | Trust distribution, discovery, signaling, policy, relay assignment | Best-effort; outage is survivable | Established `Session`s keep running (**I5**). New pairings, new discovery, and policy changes stall. |
| **Data plane** | Encrypted `Tunnel` traffic over a `Path` | Hard requirement | Traffic stops or `BLOCKED` per **I3**. |
| **Management plane** | Health, diagnostics, telemetry, admin | Lowest | Diagnostics degrade; nothing else is affected. |

Components referenced by name throughout:

| Component | Plane(s) | Trust |
|---|---|---|
| `Device` agent (client/gateway/`ExitNode`/`LANGateway`) | all three | Holds `DeviceKey`. Fully trusted by its `Owner`. |
| **Coordination service** | control | Semi-trusted. Sees metadata and public keys. Never sees tunnel plaintext or any tunnel key (**I1**). |
| **Rendezvous service** | control | Same trust as coordination. Blind forwarder of signed signaling blobs. |
| `Relay` | data | **Untrusted.** Forwards opaque ciphertext only (**I1**). |
| **Push gateway** (APNs / FCM / WNS) | control (wakeup only) | **Untrusted third party.** May carry a wake hint. MUST NOT carry state, secrets, or anything authoritative. |
| **Diagnostics collector** | management | Semi-trusted; receives only what policy permits. |

```
                       +-------------------------+
   push wake hint  --->|      Device agent       |<--- Owner / local UI
   (APNs/FCM, C3)      +------+-----------+------+
                              |           |
                 C1 RPC /     |           |  C5 peer-direct (Noise/WireGuard, ADR-0001)
                 C2 events    |           +--------------------------------+
                 (one QUIC    |                                            |
                  conn)       v                                            v
                    +---------------------+   C4 signaling        +-----------------+
                    |  Coordination svc   |<------------------->  |  Peer Device    |
                    |  + Rendezvous svc   |   (blind relay of     +--------+--------+
                    +----------+----------+    signed blobs)               |
                               |                                           |
                    internal durable log                        C6 relay-forward
                    (broker, never exposed)                     (opaque ciphertext)
                               |                                           |
                               v                                           v
                    +---------------------+                      +-----------------+
                    | TwinNet event log   |                      |     Relay       |
                    | (per-TwinNet, seq)  |                      |  (zero-knowledge)|
                    +---------------------+                      +-----------------+
```

**Load-bearing structural rule:** a `Device` never speaks to a message broker. The durable
event log is an implementation detail *behind* the coordination API (see ADR-0002). Devices
see only a resumable, sequenced stream. This keeps the attack surface, the auth model, and
the mobile wakeup story singular.

---

## 2. The message envelope

All control-plane messages (channels C1, C2, C4, C7) share one envelope. The encoding is
Protocol Buffers per [ADR-0003](adr/ADR-0003-network-contract-schema-format.md); signed
inner statements are deterministic CBOR carried as opaque `bytes`, also per ADR-0003.

```proto
// Framing: length-delimited on stream channels; one envelope per datagram on C4.
// Max envelope size: 64 KiB (C1/C2/C7), 1200 B (C4, to stay under the worst-case
// IPv6 path MTU without fragmentation; see docs/networking.md).

message ControlEnvelope {
  uint32  proto_version   = 1;  // ADR-0014. Monotonic integer. Present on EVERY message.
  bytes   message_id      = 2;  // 16B UUIDv7. Unique per emission. Time-sortable.
  bytes   correlation_id  = 3;  // message_id this responds to / was caused by. 0 = origin.
  bytes   causality_token = 4;  // opaque; see §5. Devices echo, never interpret.
  uint64  sender_time_ms  = 5;  // sender wall clock. ADVISORY ONLY. Never a guard.
  string  twinnet_id      = 6;  // TwinNet scope. Every message is TwinNet-scoped.
  string  sender_id       = 7;  // DeviceId, or "coord"/"rendezvous"/"relay:<region>".
  uint64  net_seq         = 8;  // durable log position. NON-ZERO only on durable events.
  bytes   idempotency_key = 9;  // ADR-0008. Required on mutating requests. Client-chosen.
  Auth    auth            = 10; // see below
  oneof body { /* full catalogue in §16 */ }
}

message Auth {
  // Exactly one of the following applies, per the rule in §3.
  bytes channel_binding = 1;  // TLS exporter value; proves same authenticated channel
  bytes detached_sig    = 2;  // signature over the deterministic-CBOR signed_payload
  bytes signed_payload  = 3;  // opaque octets; signature covers THESE bytes verbatim
  string signer_key_id  = 4;  // DeviceKey fingerprint, per ADR-0007
  uint64 not_before_ms  = 5;  // signed statements only
  uint64 not_after_ms   = 6;  // signed statements only; bounded lifetime is mandatory
}
```

Field semantics that are normative:

| Field | Rule |
|---|---|
| `proto_version` | MUST be present. A receiver that cannot parse the version field MUST drop the message and emit `PROTO.UNPARSEABLE_ENVELOPE`. Version is *not* negotiated per message — it is fixed for the life of a connection by ADR-0014. |
| `message_id` | MUST be unique per emission, including per retransmission of a logically identical request. Retries reuse `idempotency_key`, **not** `message_id`. This separation is what lets diagnostics distinguish "retried once" from "duplicated by the network". |
| `correlation_id` | Responses MUST echo the request's `message_id`. Events caused by a request SHOULD echo it, which is what makes an Owner-visible causal trace possible (**I6**). |
| `sender_time_ms` | **Advisory only.** No protocol decision may depend on a peer's clock. Freshness is enforced by nonces and monotonic counters, never by timestamps. Mobile devices sleep, resume with skewed clocks, and cross timezones; a clock-guarded protocol fails exactly when the user is roaming. Bounded-lifetime signed statements (`not_after_ms`) are the one exception and are evaluated against *local* time with an explicit skew allowance, with the failure surfacing as `AUTH.STATEMENT_EXPIRED` rather than a silent drop. |
| `net_seq` | Non-zero only on durable events (C2). Strictly increasing within a `twinnet_id`. It is the resume cursor. |
| `idempotency_key` | Required on every mutating C1 request. Semantics owned by [ADR-0008](adr/ADR-0008-idempotency.md); this document only states *which* interactions need one and what the retry-visible behaviour must be. |

---

## 3. Authentication model: sign only what leaves the channel

TwinVPN does **not** sign every control message. Signing everything is expensive on mobile,
adds no security inside an already-mutually-authenticated channel, and creates a large
corpus of long-lived signed artifacts that leak metadata. Instead:

> **Rule A — channel-authenticated messages.** A message that travels *only* over a
> mutually authenticated, integrity-protected channel between its origin and its final
> consumer is authenticated by the channel. `Auth.channel_binding` is used; no per-message
> signature is required.
>
> **Rule B — transitively forwarded messages.** A message that is forwarded by, stored by,
> or reconstructed by any party other than its origin and final consumer MUST carry a
> detached signature over a deterministic encoding of the payload, and the verifier MUST
> verify over the exact received octets, never over a re-encoding.

| Message class | Rule | Why |
|---|---|---|
| Device→coordination RPC (C1) | A | mTLS to `DeviceKey` per ADR-0007; coordination *is* the consumer. |
| Coordination→device events (C2) | A, **except** transitive payloads below | Same channel. |
| `PairingAttestation`, `RevocationRecord`, `DeviceIdentityRecord`, `PolicyBundle`, `RouteAdvertisement` | **B** | These are *statements about trust or reachability* that the coordination service merely warehouses and fans out. A compromised or coerced coordination service MUST NOT be able to forge them. This is the concrete mechanism by which the coordination tier is semi-trusted rather than trusted. |
| Candidate blobs through rendezvous (C4) | **B** | Rendezvous is a blind forwarder; without a signature it could inject candidates and steer a peer at an attacker-controlled `Endpoint`. |
| Peer-direct messages (C5) | A | Noise/WireGuard transport per ADR-0001 already authenticates both ends. |
| Relay-forwarded data frames (C6) | n/a | Opaque ciphertext; the relay authenticates nothing about content by design (**I1**). |
| Telemetry (C7) | A | Channel-authenticated; content is not trust-bearing. |

Signature primitives, key hierarchy, and `DeviceKey` custody are owned by
[ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) and
[ADR-0007](adr/ADR-0007-device-identity-and-pairing.md). This document requires only that:
(a) the signature scheme has a deterministic canonical input encoding, and (b) verification
is defined over received octets. Both requirements are discharged by ADR-0003's choice of
deterministic CBOR for signed statements.

---

## 4. Channels and transport bindings

| ID | Channel | Transport binding | Direction | Delivery | Ordering | Plane |
|---|---|---|---|---|---|---|
| **C1** | Control RPC | QUIC (RFC 9000) + HTTP/3, request/response and client streams, on one long-lived connection. Fallback: HTTPS/1.1 over TCP with long-poll. | Device → coordination | **At-least-once** (client retries; server dedupes on `idempotency_key`) | Per-stream FIFO; no cross-stream order | control |
| **C2** | Durable event stream | Server-initiated stream on the *same* QUIC connection; resumable by `net_seq` cursor | Coordination → device | **At-least-once**, resumable, per TwinNet, and either gap-free or explicitly compacted: a gap MUST be announced in band and in order as `StreamCompacted{up_to_net_seq}` ([ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) N-8), never silently omitted, and the receiver MUST respond with a declarative re-read | **Total order per `twinnet_id`** by `net_seq` | control |
| **C3** | Push wake | APNs / FCM / WNS | Push gateway → device | **At-most-once, best-effort** | None | control |
| **C4** | Ephemeral signaling | UDP datagrams relayed blindly by rendezvous; DTLS-free, payload is signed+sealed per ADR-0001; also carried inline over C1/C2 when UDP is blocked | Device ↔ device via rendezvous | **At-most-once**, lossy | None | control |
| **C5** | Peer-direct | Noise/WireGuard transport per ADR-0001, over UDP, IPv4 **and** IPv6 | Device ↔ device | At-most-once (datagram) | None; anti-replay counter per ADR-0001 | data |
| **C6** | Relay forward | Opaque frame forwarding per ADR-0005 | Device ↔ relay ↔ device | At-most-once | None | data |
| **C7** | Telemetry / health | Batched HTTPS POST, coalesced, backoff-scheduled | Device → collector | At-least-once, loss-tolerant | None | management |

### 4.1 Address-family rules (IPv4 and IPv6 are co-equal)

- C1/C2 endpoints MUST publish both `A` and `AAAA` records and MUST be reachable over both
  families. A device MUST attempt Happy Eyeballs v2 (RFC 8305) across families and MUST
  NOT treat IPv6 failure as fatal, nor prefer IPv4 by default.
- C4 signaling MUST carry candidates of both families in a single exchange. A candidate set
  containing only one family MUST be flagged `NAT.SINGLE_FAMILY_CANDIDATES` in
  diagnostics, because it is the leading cause of "works at home, fails on cellular".
- C5 MUST support IPv6 `Endpoint`s natively, including link-local scoped addresses on the
  `LOCAL_DIRECT` path, which requires carrying the zone/scope index in the candidate.
- C6 relays MUST be dual-stack, and a device MUST be able to reach a `Relay` over IPv6 when
  it has no usable IPv4 path at all (IPv6-only cellular with NAT64 is a first-class case).
- The 1200-byte C4 datagram cap is chosen for the worst-case IPv6 path MTU minus headers,
  not the IPv4 576-byte floor, because C4 is never fragmented and IPv6 forbids in-network
  fragmentation.

### 4.2 Why one connection carries both C1 and C2

Multiplexing RPC and the event stream onto a single QUIC connection is deliberate:

- One handshake, one mutual authentication, one channel binding, one set of NAT/firewall
  state to keep alive — the dominant cost on battery-constrained devices is *distinct
  connections*, not bytes.
- Head-of-line blocking between RPCs and events is avoided by QUIC's independent streams,
  which a single TCP connection could not provide.
- Connection migration (QUIC's `CID`-based path migration) survives Wi-Fi↔cellular
  handover **without** re-authenticating, which directly attacks the "poor roaming" failure
  mode in the product requirements.

The HTTPS/TCP fallback loses stream independence and connection migration; that degradation
MUST be surfaced as `HealthState` reason `CONTROL.TRANSPORT_DEGRADED_TCP`, never hidden (**I6**).

---

## 5. Ordering, causality, and delivery semantics

### 5.1 Ordering guarantees, stated precisely

| Scope | Guarantee | Mechanism |
|---|---|---|
| Durable events within one `TwinNet` | **Total order**, gap-free, resumable | `net_seq`, assigned by the single writer of the TwinNet log |
| Durable events across TwinNets | None | TwinNets are independent scopes; no cross-scope ordering is ever needed or promised |
| C1 responses relative to C2 events | **Read-your-writes only** | A C1 mutating response returns the `net_seq` its effect was committed at; the device MUST NOT consider the operation observable until its C2 cursor reaches that `net_seq` |
| C4 signaling | **None** | Explicitly unordered. Consumers MUST be order-insensitive. |
| C5 / C6 data frames | **None** | Datagram semantics; ADR-0001's anti-replay window is the only sequencing |

The `read-your-writes` mechanism deserves emphasis because it is the seam where most
distributed bugs in products of this shape live: a device pairs a peer, gets `200 OK`, and
immediately tries to connect — but its local `TrustedPeer` cache has not yet seen the
pairing event. The contract closes this: **every mutating C1 response carries
`committed_at_net_seq`, and the client library MUST NOT report the operation complete to
the UI until the C2 cursor has advanced to or past it.** That is a protocol obligation, not
a client convenience.

### 5.2 Causality

`causality_token` is an opaque value minted by the coordination service and echoed by
devices. Devices MUST NOT parse it. It exists so that:

1. An event can be attributed to the request that caused it, across process and device
   boundaries, for **I6** diagnostics.
2. ADR-0009 has a place to carry version/consistency metadata (e.g. a session token for
   monotonic reads) without another envelope revision.

Devices treat it as a cookie: store the newest one seen per `twinnet_id`, send it back on
every C1 request. This is deliberately the weakest possible client-side contract, because
any client-side interpretation of causality metadata becomes a compatibility landmine
across ADR-0014 version boundaries.

### 5.3 Delivery semantics, per channel, with justification

| Channel | Semantics | Why *this* and not the alternative |
|---|---|---|
| C1 | At-least-once + idempotency key | At-most-once would silently lose a pairing or a revocation on a flaky cellular link. Exactly-once delivery is unachievable over an unreliable network; exactly-once *effect* via ADR-0008 is achievable and is what actually matters. |
| C2 | At-least-once, resumable, and **either gap-free or explicitly compacted** | The stream carries trust-bearing state. A dropped `DeviceRevoked` is a security failure, so loss is unacceptable. Duplicates are acceptable because every event is idempotent by construction (§14). |
| C3 | At-most-once, best-effort | Push is a third-party best-effort service that is *rate-limited and may be dropped by the OS*. Building any correctness on it is a defect. It carries a wake hint only; correctness comes from C2 resume. |
| C4 | At-most-once | Candidates are re-derivable and time-decaying. Reliable delivery of a stale candidate is worse than losing it — see §7. |
| C5/C6 | At-most-once | Datagram tunnel semantics; the inner protocol handles its own loss. Adding reliability here would rebuild TCP-over-TCP meltdown. |
| C7 | At-least-once, loss-tolerant | Diagnostics must survive a reconnect, but a lost health sample must never block or degrade the data plane. |

---

## 6. Ephemeral versus durable: the classification rule

This distinction is the single most consequential classification in the protocol, so it is
defined by a **test**, not by a list. A message is **durable** if it fails *any* of these
four checks; otherwise it is **ephemeral**.

| # | Check | Interpretation |
|---|---|---|
| **E1 — Re-derivability** | Can the receiver reconstruct the information on demand, from a live query or its own observation, without the sender's cooperation? | A presence state can be re-derived by probing. A revocation cannot be re-derived by anyone but the `Owner`. |
| **E2 — Time decay** | Does the value of the message decay to zero within seconds-to-minutes? | A `ConnectionCandidate` naming an ephemeral NAT mapping is worthless in minutes. A `Pairing` is worth the same in a year. |
| **E3 — Miss consequence** | If a receiver *never* sees this message, does it settle into a persistently *wrong* state? | Missing a candidate ⇒ you fall back to relay: suboptimal, correct. Missing a revocation ⇒ you keep trusting a stolen device: **wrong, indefinitely, and a security breach**. |
| **E4 — Replay harm** | Is replay of an old copy actively harmful, or merely useless? | Replayed candidate ⇒ a wasted probe. Replayed *un*-revocation ⇒ trust resurrection. |

Applying the test:

| Interaction | E1 | E2 | E3 | E4 | Class |
|---|---|---|---|---|---|
| Candidate exchange | re-derivable | decays in ~30 s | falls back to `RELAYED` | useless only | **Ephemeral signaling** |
| Presence update | re-derivable by probe | decays in ~60 s | stale UI, self-healing | useless only | **Ephemeral signaling** |
| NAT traversal signaling | re-derivable | decays in seconds | falls back to `RELAYED` | useless only | **Ephemeral signaling** |
| Relay assignment | re-derivable by discovery | decays in minutes | picks a worse relay | useless only | **Ephemeral (advisory)** |
| Health sample | re-derivable | decays in minutes | diagnostics gap | useless only | **Ephemeral (management)** |
| Pairing completion | **not** re-derivable | no decay | peer never trusted | harmful (trust injection) | **Durable event** |
| Device registration | **not** re-derivable | no decay | device invisible forever | harmful | **Durable event** |
| Device revocation | **not** re-derivable | no decay | **stolen device stays trusted** | **trust resurrection** | **Durable event** |
| Key rotation | **not** re-derivable | no decay | peer pins a dead key | harmful (downgrade to old key) | **Durable event** |
| Policy synchronization | **not** re-derivable | no decay | enforces stale `AccessPolicy` | harmful (policy rollback) | **Durable event** |
| Route advertisement | partially | slow decay (minutes–hours) | subnet unreachable | mildly harmful (blackhole) | **Durable event, TTL'd** |

### 6.1 Consequences of misclassifying

**Treating a durable event as ephemeral** — the security failure mode:

- *Revocation as ephemeral.* A device that was asleep during the revocation broadcast wakes
  up still trusting a stolen laptop, and there is no mechanism that will ever correct it,
  because ephemeral messages are not replayed. The revocation window becomes unbounded and
  silent. This is the exact class of bug that makes "we support device revocation" a
  false claim.
- *Pairing as ephemeral.* Trust becomes non-convergent: device A believes B is a
  `TrustedPeer`, B does not believe A is. Every connection attempt fails at the handshake
  with a mutual-authentication error that looks like a crypto bug and is actually a
  delivery bug — precisely the "cryptic error code" failure mode this product exists to fix.
- *Policy as ephemeral.* A tightened `AccessPolicy` silently does not apply on the one
  device that was offline, producing a policy island. Because ephemeral channels have no
  cursor, nothing detects it.

**Treating an ephemeral message as durable** — the cost, privacy, and correctness failure mode:

- *Presence as durable.* Every heartbeat from every `Device` becomes a replicated,
  sequenced, persisted log entry. With N devices at a 30-second heartbeat, the durable log
  write rate is dominated by information with a 60-second shelf life. Log compaction,
  storage, replication bandwidth, and mobile catch-up cost all scale with noise instead of
  signal. Worse, on reconnect a device must drain thousands of obsolete presence events
  before it reaches the one `DeviceRevoked` event that matters — a **denial of freshness**
  attack surface that an adversary can trigger simply by flapping a device.
- *Presence as durable, second-order.* A durable presence log is a **permanent movement and
  IP-address history of the `Owner`**, held by infrastructure. That is a retention liability
  squarely against the spirit of **I1**: infrastructure that cannot read your traffic but
  can reconstruct where you were every hour for two years has not achieved zero knowledge.
  Ephemeral presence with TTL is a privacy property, not just an efficiency one.
- *Candidates as durable.* On reconnect a device replays a candidate set minted hours ago,
  probing NAT mappings that expired and IP addresses now belonging to someone else. It
  produces connection storms, misleading diagnostics, and — if the address was recycled —
  probe traffic to an uninvolved third party. Reliable delivery makes this *worse*, because
  the stale data is guaranteed to arrive.

### 6.2 The bridge rule

Some interactions have an ephemeral body and a durable *fact*. The rule is: **split them.**
Relay assignment is the canonical case — the assignment itself is ephemeral advice
(C4/C2-transient), but "this TwinNet is configured to prefer region X" is durable policy.
Never promote the whole interaction to satisfy the durable half.

---

## 7. Event ownership: single publisher per event type

Per **I8**, exactly one component is the sole publisher of each durable event type. No
other component may emit it, and a receiver MUST reject an event whose publisher does not
match this table (`CONTROL.EVENT_WRONG_PUBLISHER`).

| Event type | Sole publisher | Authoritative state owner (adjudicated by ADR-0009) | Durability |
|---|---|---|---|
| `DeviceRegistered` | Coordination service | Coordination (`DeviceIdentity` record); private key never leaves device (**I4**) | Durable |
| `DeviceRenamed` / `DeviceRoleChanged` | Coordination service | Coordination | Durable |
| `PairingProposed` / `PairingCompleted` / `PairingRejected` | Coordination service (transporting an `Owner`-signed attestation) | Coordination, but the *statement* is signed by the pairing devices | Durable |
| `DeviceRevoked` | Coordination service (transporting an `Owner`-signed `RevocationRecord`) | Coordination; monotonic epoch | Durable |
| `DeviceKeyRotated` | Coordination service (transporting a device-signed rotation statement) | Coordination | Durable |
| `PolicyBundleUpdated` | Coordination service | Coordination | Durable |
| `RouteAdvertised` / `RouteWithdrawn` | Coordination service (transporting the advertising device's signed advertisement) | The **advertising device** is authoritative for its own routes; coordination is a replica | Durable, TTL'd |
| `ExitNodeOffered` / `ExitNodeWithdrawn` | Coordination service (device-signed) | Advertising device | Durable, TTL'd |
| `RelayRegionPolicyChanged` | Coordination service | Coordination | Durable |
| `PresenceChanged` | Coordination service (aggregating device heartbeats) | **The device itself** is authoritative for its own presence | Ephemeral |
| `RelayAssignmentHint` | Coordination service | Coordination, advisory only | Ephemeral |
| `SessionStateChanged` | **The device that owns the `Session`** | **Local device only.** Coordination holds a lossy cache and is NEVER authoritative. | Ephemeral (management mirror) |
| `HealthSample` | Emitting device | Emitting device | Ephemeral |
| Candidate / NAT signaling messages | Originating device | Originating device | Ephemeral, not logged |

Two entries in this table are load-bearing and must not be softened:

1. **`SessionStateChanged` is local-authority.** This is the mechanism that makes **I5**
   true. If the coordination service were authoritative for `Session` state, a control-plane
   outage would put every session into an indeterminate state, and any reconciliation logic
   would eventually tear tunnels down. Because the device owns it, the coordination service
   losing the whole event log changes nothing about a running `Tunnel`.
2. **Route and exit-node advertisements are device-authoritative statements that
   coordination merely warehouses.** A coordination service that could mint routes could
   redirect an `Owner`'s traffic for a subnet to an attacker-controlled device. Signing
   under `DeviceKey` (Rule B, §3) removes that capability from the infrastructure.

---

## 8. Interaction contracts — identity and trust

Each interaction below is specified with the same nine-field contract. "Transitions" names
`ConnectionState` transitions caused; the authoritative transition table is
[docs/reliability.md](reliability.md).

### 8.1 Device registration

| Field | Value |
|---|---|
| **Participants** | New `Device` agent → coordination service |
| **Trigger** | User adds a device to a `TwinNet`; agent has generated a `DeviceKey` in platform-native secure storage (**I4**, ADR-0007) |
| **Style** | **Request/response API** (C1). Justification: it is a single, synchronous, uniqueness-establishing commit with an answer the caller needs immediately, and there is exactly one caller. Modeling it as an event would leave the caller polling for its own identity. |
| **Payload** | `RegisterDeviceReq{ device_pubkey, key_attestation (ADR-0007), platform{os, os_version, arch, agent_version}, declared_roles[CLIENT\|GATEWAY\|EXIT_NODE\|LAN_GATEWAY], proto_version_min, proto_version_max, capabilities[], enrollment_proof }` → `RegisterDeviceResp{ device_id_echo, twinnet_id, assigned_twinnet_addr_v4, assigned_twinnet_addr_v6, coordination_endpoints[], committed_at_net_seq }` |<br><br>**`device_id_echo` is an echo, never an assignment (normative).** `device_id` is *derived* on-device from the generation-0 identity public key ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) N-2) and is already known to the device before it contacts the coordination service. The device MUST compare `device_id_echo` to its own derived value and MUST abort registration with `AUTH.IDENTITY_MISMATCH` on disagreement. It MUST NOT adopt the server's value. A server-assigned identifier would break self-certifying identity and the S-08 address derivation that depends on it (architecture.md A-01).
| **Ordering / delivery** | C1 at-least-once. Response is authoritative once `committed_at_net_seq` is reached on C2 (§5.1). |
| **Idempotency** | **Required.** Key derived from a device-local enrollment nonce so that a retry after a lost response returns the *same* `device_id` rather than creating a duplicate device. Semantics per [ADR-0008](adr/ADR-0008-idempotency.md). Registering the same `device_pubkey` twice MUST be idempotent, not an error — duplicate-device-on-retry is a classic failure of this product category. |
| **Failure / timeout** | 10 s connect budget, 30 s total, exponential backoff with jitter capped at 5 min. Failure states: `AUTH.KEY_ATTESTATION_FAILED`, `AUTH.ENROLLMENT_EXPIRED`, `AUTH.QUOTA_EXCEEDED`, `PROTO.VERSION_UNSUPPORTED` (see ADR-0014 MSPV). All carry human-actionable text (**I6**). |
| **Authorization** | An `Owner`-scoped enrollment credential (ADR-0007). The `DeviceKey` private half never transits (**I4**). |
| **Consistency requirement** | **Strong / linearizable** on `(twinnet_id, device_pubkey)` uniqueness. Flagged to ADR-0009. |
| **Transitions** | None. Registration is a precondition of `DISCONNECTED`, not a connection state. |
| **IPv4/IPv6** | Both `assigned_twinnet_addr_v4` and `assigned_twinnet_addr_v6` are assigned at registration. A device MUST receive both, even on a v4-only or v6-only network; addressing inside the `TwinNet` is independent of underlay reachability (see [docs/networking.md](networking.md)). |

### 8.2 Secure pairing

| Field | Value |
|---|---|
| **Participants** | `Device` A ↔ `Device` B, mediated by coordination service; ceremony defined by ADR-0007 |
| **Trigger** | Owner initiates pairing (QR or short-code), authorized by an existing device holding an OSK with the `ENROLL` power ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.5). There is no "owner account" — authorization is a key held by a device, never a credential held by a server |
| **Style** | **Request/response API for each step, plus a durable control-plane event on completion.** Justification: the ceremony's steps are synchronous and interactive (a human is waiting), but the *outcome* must reach every other device in the `TwinNet` reliably and permanently — E3 and E4 both fail, so completion is durable. |
| **Payload** | `ProposePairingReq{ peer_hint, ceremony_type, owner_challenge }` → `ProposePairingResp{ expires_at, committed_at_net_seq }`.<br><br>**`pairing_id` is not minted here.** It is computed by the joining device as `SHA-256(pairing_secret)[0..15]` and *carried to* the coordination service in the request ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.4); it doubles as the HKDF salt for the ceremony channel, so a server-minted value would break both roles and would let the rendezvous correlate a handle to a secret it must never see. **`verification_words[]` is not returned here either** — a SAS is displayed *after* completion for recognition and is explicitly **not** a security gate (ADR-0007 §7.4 C-C), because a distracted user comparing words produces silent compromise rather than a failed ceremony; `ConfirmPairingReq{ pairing_id, attestation }` where `attestation` is a **deterministic-CBOR, `DeviceKey`-signed** `PairingAttestation{ pairing_id, peer_key_id, own_key_id, transcript_hash, not_after_ms }`. Durable event: `PairingCompleted{ pairing_id, attestation_a, attestation_b }`. |
| **Ordering / delivery** | Steps: per-stream FIFO on C1. Completion event: total-ordered on C2, at-least-once. |
| **Idempotency** | **Required** on both steps. `ConfirmPairingReq` replay MUST return the original outcome. |
| **Failure / timeout** | Ceremony expires (default 120 s, ADR-0007 owns the value). `AUTH.PAIRING_EXPIRED`, `AUTH.PAIRING_CODE_MISMATCH`, `AUTH.PAIRING_PEER_UNREACHABLE`, `AUTH.DEVICE_REVOKED`. Timeout MUST be surfaced as a distinct, actionable state, never a generic failure. |
| **Authorization** | Owner-authenticated ceremony + both devices' `DeviceKey` signatures. **Rule B**: the coordination service transports attestations it cannot forge, so it cannot inject a `TrustedPeer`. |
| **Consistency requirement** | **Strong** at commit (a `pairing_id` completes exactly once); **monotonic** on propagation. |
| **Transitions** | None directly. Enables `DISCONNECTED → DISCOVERING` for the new `TrustedPeer`. |

### 8.3 Device revocation

| Field | Value |
|---|---|
| **Participants** | `Owner` (via any authorized device) → coordination service → **all** devices in the `TwinNet`, and separately → all `Relay`s holding sessions for the revoked device |
| **Trigger** | Device lost, stolen, decommissioned, or compromised |
| **Style** | **Durable control-plane event**, with a request/response admission step. Justification: E1 fails (nobody can re-derive it), E3 fails catastrophically (a device that misses it trusts a stolen device forever), E4 fails (replaying an older state resurrects trust). Ephemeral delivery of a revocation is a security defect, full stop. |
| **Payload** | `RevokeDeviceReq{ target_device_id, reason, revocation_statement }` where `revocation_statement` is deterministic-CBOR, **`Owner`-authority-signed**: `RevocationStatement{ twinnet_id, target_device_id, target_identity_id, effective_from_ms, reason_code, issuer_osk_id }` ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.7). The coordination service admits it under its shard lease and **assigns** the ordering, wrapping it as `RevocationEntry{ statement, trust_epoch, net_seq, prev_entry_hash }`, which is what the durable event carries. The two signers are deliberately separate: the `Owner` authorizes, the writer orders (ADR-0007 N-25). A `RevocationEntry` whose inner statement signature does not verify MUST be rejected outright — a well-formed wrapper authorizes nothing. Durable event `DeviceRevoked{ entry, trust_epoch_bundle }`. |
| **Ordering / delivery** | C2 at-least-once, total order, **plus** a monotone `revocation_epoch` carried in every C1 response and C2 event so a device can detect it is behind without draining the log. Push wake (C3) is used to hasten delivery but is never relied on. |
| **Idempotency** | Naturally idempotent: applying the same `RevocationRecord` twice is a no-op. Re-issuing with a *lower* epoch MUST be rejected. |
| **Failure / timeout** | Admission is retried until it commits; the initiating UI MUST show "revocation pending propagation" with the count of devices confirmed at the new epoch, and MUST NOT show "done" prematurely. `AUTH.NOT_PROPAGATED` is a real, surfaced state (**I6**). |
| **Authorization** | Owner authority per ADR-0007. A device MUST NOT be able to revoke a peer on its own authority. |
| **Consistency requirement** | **Strong at admission + monotonic reads at every consumer.** See §15.1 — this is the one place where the protocol requires a guarantee stronger than eventual consistency, and it is escalated to ADR-0009 explicitly. |
| **Transitions** | For any `Session` with the revoked peer: immediate `* → FAILED` with reason `AUTH.DEVICE_REVOKED`. If the local device is the revoked one and the kill switch is on: `* → BLOCKED` (**I3**), never a silent drop to untunneled networking. |
| **Data-plane enforcement** | Revocation MUST also be enforced at the `Relay` (drop forwarding for the revoked key) and at the peer's Noise handshake (reject the key). Relay-side enforcement is a **liveness** improvement, not a security guarantee — the security guarantee is peer-side rejection, because relays are untrusted (**I1**) and a compromised relay would simply not enforce. |

### 8.4 Key rotation

| Field | Value |
|---|---|
| **Participants** | Rotating `Device` → coordination service → all `TrustedPeer`s |
| **Trigger** | Scheduled rotation, platform key-store migration, OS reinstall preserving identity, or suspected exposure |
| **Style** | **Durable control-plane event** with a request/response commit. Justification: same as revocation — a peer that misses it pins a dead key and the connection fails permanently with a misleading crypto error. |
| **Payload** | `RotateKeyReq{ new_pubkey, new_key_attestation, rotation_statement }` where `rotation_statement` is deterministic-CBOR signed by **both** the old and the new key: **two distinct statements**, because TwinVPN has two key types with different rotation semantics ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) N-21/N-22):<br>• `IdentitySuccession{ device_id, old_identity_id, new_identity_id, generation, not_after_ms }` — **dual-signed by both the old and the new IK**, creates a new `DeviceIdentity` at `generation`+1, and does **not** change `device_id`. Overlap `T_IK_OVERLAP` = 30 d.<br>• `TunnelKeyBinding{ device_id, identity_id, new_tk_pub, tk_generation, not_after_ms }` — IK-signed, rotates the X25519 tunnel key **without** changing `DeviceIdentity`. MUST be rotated at least every 180 days; overlap `T_TK_OVERLAP` = 14 d. This is the mechanism that bounds an extracted tunnel key, and it replaced certificate expiry in that role. Durable event `DeviceKeyRotated{ rotation_statement }`. |
| **Ordering / delivery** | C2 total order; Peers store **two** high-water marks per `device_id` — `highest_generation_seen` and `highest_tk_generation_seen` — and MUST reject any statement whose counter is ≤ the corresponding mark (ADR-0007 N-22) (anti-rollback). |
| **Idempotency** | Idempotent by `generation` (for `IdentitySuccession`) or `tk_generation` (for `TunnelKeyBinding`). |
| **Failure / timeout** | Overlap window: the old key remains valid for a bounded period (value owned by ADR-0007) so a peer that has not yet seen the rotation can still connect. When the overlap expires and a peer still presents the old key, the failure MUST be `AUTH.KEY_ROTATED_PEER_STALE`, which tells the user to bring the peer online — not a generic handshake failure. |
| **Authorization** | Dual signature (old ∧ new). A single-signature rotation would let a stolen key rotate itself into permanence, and an old-key-only signature would let a compromised old key install an attacker's new key. |
| **Consistency requirement** | **Monotonic** per device — `generation` and `tk_generation` each never regress. Eventual across peers, with `T_IK_OVERLAP` (30 d) and `T_TK_OVERLAP` (14 d) covering propagation delay. |
| **Transitions** | Existing `Session`s continue on their established keys (**I5** — rotation does not tear down the data plane). New handshakes use the new key. Peers still on the old key: `WAN_DIRECT/RELAYED → DEGRADED` with `AUTH.KEY_ROTATION_PENDING` when the overlap window is within 20 % of expiry. |

---

## 9. Interaction contracts — discovery and presence

### 9.1 Peer discovery

| Field | Value |
|---|---|
| **Participants** | `Device` → coordination service (WAN discovery); `Device` ↔ `Device` (LAN discovery) |
| **Trigger** | Agent start, network change, C2 reconnect, user-initiated connect |
| **Style** | **Request/response API for the snapshot, plus subscription to durable events for deltas** (C1 + C2). Justification: a cold start needs a bounded, complete answer (a stream alone would require replaying the whole log); steady state needs deltas (a poll would burn battery). This snapshot-plus-delta pairing is the general pattern for every cached collection in TwinVPN. |
| **Payload** | `GetPeersReq{ since_net_seq }` → `GetPeersResp{ peers[TrustedPeer{ device_id, key_id, twinnet_addr_v4, twinnet_addr_v6, roles[], capabilities[], proto_version_range }], revocation_epoch, snapshot_net_seq }` |
| **LAN variant** | mDNS/DNS-SD **and** an IPv6 link-local multicast probe on `ff02::/16`, plus IPv4 `224.0.0.251`. Discovery responses on the LAN are unauthenticated hints only; a discovered `Endpoint` is trusted **only** after a successful Noise handshake against a known `TrustedPeer` key. LAN discovery MUST NOT be able to introduce a peer. |
| **Ordering / delivery** | Snapshot: at-least-once C1. Deltas: total-ordered C2. `since_net_seq` makes the two composable without a gap. |
| **Idempotency** | Read-only; trivially idempotent. |
| **Failure / timeout** | On control-plane unavailability the device MUST use its last cached peer set and enter discovery from cache, surfacing `CONTROL.STALE_POLICY_IN_USE`. Per **I5** this MUST NOT prevent connecting to a known peer. |
| **Authorization** | Channel-authenticated; scoped to the caller's `twinnet_id`. Cross-TwinNet discovery is not expressible in the API. |
| **Consistency requirement** | **Monotonic** (a device must not see peers appear and then disappear due to replica lag). Eventual convergence is acceptable *except* for `revocation_epoch`, which is strong/monotonic per §15.1. |
| **Transitions** | `DISCONNECTED → DISCOVERING`. |

### 9.2 Presence updates

| Field | Value |
|---|---|
| **Participants** | `Device` → coordination service → other devices in the `TwinNet` |
| **Trigger** | Heartbeat timer, network change, app foreground/background, imminent suspend |
| **Style** | **Ephemeral signaling**, expressed as a lightweight C1 heartbeat and an ephemeral C2 notification. Justification: passes all four checks in §6 — re-derivable by probing, decays within a minute, missing it only makes the UI stale, and replay is useless. Making it durable would flood the log and create an IP/location history (§6.1). |
| **Payload** | `Heartbeat{ device_id, presence{ONLINE\|IDLE\|SUSPENDING\|OFFLINE}, reachability{has_v4, has_v6, nat64_present, network_class}, ttl_ms }` → `HeartbeatAck{ suggested_interval_ms, revocation_epoch, pending_net_seq }`. Notification: `PresenceChanged{ device_id, presence, expires_at_ms }`. |
| **Ordering / delivery** | At-most-once semantics are acceptable; last-writer-wins by arrival at the aggregator. **No ordering guarantee** — consumers MUST tolerate reordering, which is why presence carries an absolute `expires_at_ms` rather than a relative delta. |
| **Idempotency** | Idempotent by construction (state assertion, not a command). |
| **Failure / timeout** | Presence expires by TTL. A missed heartbeat degrades to `OFFLINE` after TTL, never immediately, to avoid flapping on mobile radio transitions. |
| **Authorization** | Channel-authenticated. A device may assert presence **only for itself**. |
| **Consistency requirement** | **Eventual, local authority, TTL-bounded.** The device is authoritative for its own presence; nobody may override it. |
| **Transitions** | None directly. Feeds `DISCOVERING` candidate selection and `DEGRADED` diagnostics. |
| **Mobile note** | `HeartbeatAck.pending_net_seq` lets a device learn it is behind on durable events **without opening the event stream**, so a background-suspended device can decide whether waking is worthwhile. This is the main battery lever in the protocol. |

---

## 10. Interaction contracts — connection establishment

### 10.1 Connection negotiation

| Field | Value |
|---|---|
| **Participants** | Initiating `Device` ↔ target `Device`, with rendezvous as blind forwarder |
| **Trigger** | User connect, policy-driven auto-connect, or a route to a subnet a peer advertises |
| **Style** | **Ephemeral signaling**, request/response-shaped but carried over the unreliable C4 path with application-level retry. Justification: negotiation state is entirely re-derivable, decays with NAT mappings, and is never useful to persist. It is *not* a durable event, and it is *not* a control-plane RPC, because the coordination service must not be in the critical path of every reconnect (**I5**: a control-plane blip must not prevent re-establishing a session for which both keys and last-known endpoints are already cached). |
| **Payload** | `ConnectOffer{ session_nonce, initiator_key_id, proto_version, capabilities[], candidates[], relay_fallback_hint[], transcript_commitment }` / `ConnectAnswer{ session_nonce, responder_key_id, min_supported, max_supported, capabilities[], selected_proto_version, selected_capabilities[], candidates[], transcript_commitment }`. Both are **Rule B signed** — rendezvous forwards, and must not be able to substitute a key, a version, or a capability set. |
| **Ordering / delivery** | Unordered, at-most-once, retried with backoff by the initiator. `session_nonce` correlates. Duplicate offers MUST be collapsed by `session_nonce`. |
| **Idempotency** | Idempotent by `session_nonce`: a repeated offer with the same nonce MUST NOT create a second `Session`. Semantics per ADR-0008; note this is *peer-local* idempotency, not server-side. |
| **Failure / timeout** | Offer timeout 5 s per attempt, 3 attempts, then fall back to relay-first negotiation. If both fail: `NET.NO_ANSWER`, `NET.PEER_OFFLINE`, or `PROTO.VERSION_UNSUPPORTED` (ADR-0014). Glare (simultaneous mutual offers) is resolved deterministically by lower `key_id` wins; the loser adopts the winner's `session_nonce`. |
| **Authorization** | Both parties MUST already be `TrustedPeer`s at the current `revocation_epoch`. An offer from a revoked key MUST be dropped without an answer, and logged as `AUTH.DEVICE_REVOKED`. |
| **Consistency requirement** | **Local-only authority.** The two peers are jointly authoritative; no server adjudicates. |
| **Transitions** | `DISCOVERING → NEGOTIATING` on offer sent/received; `NEGOTIATING → CONNECTING` on answer. |

### 10.2 Protocol version negotiation

| Field | Value |
|---|---|
| **Participants** | Device ↔ device (peer protocol); device ↔ coordination (control channel) |
| **Trigger** | Every new connection or control-channel establishment |
| **Style** | **Direct peer protocol message**, folded into `ConnectOffer`/`ConnectAnswer` — never a separate round trip. Justification: an extra RTT on every connection is unacceptable on high-latency mobile paths, and a *separate*, unauthenticated pre-handshake negotiation is exactly the shape that enables downgrade attacks. |
| **Payload** | `proto_version` (offer: highest supported; answer: selected), plus `min_supported` on both sides. Rules in [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md). |
| **Ordering / delivery** | Inline with 10.1. |
| **Idempotency** | Pure function of the two inputs; deterministic. |
| **Failure / timeout** | If the intersection is empty: `PROTO.VERSION_UNSUPPORTED` naming both ranges and the required upgrade — never a bare numeric code (**I6**). |
| **Authorization** | The selected version MUST be committed into the ADR-0001 handshake transcript (as the Noise prologue) so that tampering by the rendezvous or the network breaks the handshake. Detail in ADR-0014 §11. |
| **Consistency requirement** | Local-only. |
| **Transitions** | Failure: `NEGOTIATING → FAILED`. |

### 10.3 Capability negotiation

| Field | Value |
|---|---|
| **Participants** | Device ↔ device; device ↔ coordination |
| **Trigger** | Same as 10.2 |
| **Style** | **Direct peer protocol message**, inline with the offer/answer. Justification: identical to 10.2 — inline, authenticated, no extra RTT, no unprotected pre-negotiation. |
| **Payload** | `capabilities[]` as named registry tokens (ADR-0014), e.g. `path_migration/1`, `multipath_probe/1`, `exit_node/2`, `lan_gateway/1`, `relay_multiplex/1`, `dns_split/1` — spellings are **normative** and come from [ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) §11.11, which is the sole source of token names. Answer returns the **intersection**, which is then hashed into the transcript. |
| **Ordering / delivery** | Inline. |
| **Idempotency** | Deterministic function of the two sets. |
| **Failure / timeout** | Missing a capability is never fatal by itself; it degrades a feature. Degradation MUST be surfaced (e.g. `PROTO.NO_PATH_MIGRATION_PEER` explains why roaming will drop the session) — silent feature loss is an **I6** violation. |
| **Authorization** | The negotiated intersection MUST be confirmed under the handshake transcript so an attacker cannot strip a capability (a capability-stripping downgrade is the realistic attack: strip `path_migration/1` to force reconnects, or strip a stronger relay mode to force a weaker path). ADR-0014 §11 specifies the confirmation. |
| **Consistency requirement** | Local-only. |
| **Transitions** | None directly. An absent capability produces a `PROTO.CAPABILITY_MISSING` diagnostic and **no** `ConnectionState` change ([ADR-0014](adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) N-17(5)). If local policy *requires* the absent capability the disposition is **`BLOCKED`** under **I3** with `PROTO.CAPABILITY_REQUIRED_UNAVAILABLE` (N-17(6)) — **never `DEGRADED`**, because `DEGRADED` means traffic continues to flow and a policy violation must not (`docs/reliability.md` R6). |

### 10.4 Candidate exchange

| Field | Value |
|---|---|
| **Participants** | Device ↔ device via rendezvous (C4); also inline in `ConnectOffer`/`ConnectAnswer` |
| **Trigger** | Negotiation start; new candidate discovered mid-negotiation (trickle) |
| **Style** | **Ephemeral signaling.** The canonical ephemeral case: candidates are re-derived every time (E1), NAT mappings expire in tens of seconds (E2), losing one costs a fallback to `RELAYED` not correctness (E3), and replay is merely wasteful (E4). Persisting candidates is an anti-pattern that produces reconnect storms against expired mappings and recycled addresses (§6.1). |
| **Payload** | `CandidateSet{ session_nonce, generation, candidates[ConnectionCandidate{ family:V4\|V6, kind:HOST\|SERVER_REFLEXIVE\|PORT_RESTRICTED\|RELAYED, addr, port, zone_index (IPv6 link-local), priority, mtu_hint, expires_at_ms }] }`, Rule B signed. |
| **Ordering / delivery** | **At-most-once, unordered.** Trickle updates carry a monotone `generation`; a receiver discards a lower generation. Loss is normal and expected. |
| **Idempotency** | Idempotent set-merge keyed on `(family, kind, addr, port)`. |
| **Failure / timeout** | Candidates expire at `expires_at_ms` (default 30 s). Empty intersection → relay path. Diagnostics MUST report which families/kinds were gathered, because "no IPv6 candidates were gathered" and "IPv6 candidates were gathered but unreachable" are different user problems with different fixes. |
| **Authorization** | Signed under `DeviceKey` (Rule B). An unsigned candidate MUST be dropped — otherwise rendezvous, or anyone who can inject a datagram, can steer probing traffic at a chosen victim, turning TwinVPN into a reflection amplifier. |
| **Consistency requirement** | **None.** Explicitly no consistency requirement; this is a hint stream. |
| **Transitions** | Feeds `NEGOTIATING`/`CONNECTING`; tactics owned by [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md). |
| **IPv4/IPv6** | Both families MUST be gathered and exchanged in the same `CandidateSet`. IPv6 link-local host candidates MUST carry `zone_index` or they are unusable on multi-interface hosts. NAT64/DNS64 environments MUST be detected and reported via `nat64_present` in presence, so an IPv6-only peer can be reached. |

### 10.5 NAT traversal signaling

| Field | Value |
|---|---|
| **Participants** | Device ↔ device via rendezvous; device ↔ STUN-equivalent reflexive service |
| **Trigger** | Candidate exchange complete; hole-punch coordination needed |
| **Style** | **Ephemeral signaling.** Tightly time-coupled: a punch instruction is worthless a second late. Reliable or ordered delivery would actively harm it by delivering stale synchronization instructions. |
| **Payload** | `PunchSync{ session_nonce, generation, punch_at_ms_relative, pairs[(local_cand_idx, remote_cand_idx)], birthday_port_hints[] }`, `PunchProbe{ session_nonce, probe_id, family }`, `PunchResult{ session_nonce, probe_id, rtt_us, outcome }`. Rule B signed. |
| **Ordering / delivery** | At-most-once, unordered, high-rate, short-lived. Retried by re-sending with a new `generation`. |
| **Idempotency** | Probes are idempotent; duplicates are harmless and expected. |
| **Failure / timeout** | Per-strategy budget owned by [ADR-0004](adr/ADR-0004-nat-traversal-strategy.md). Exhaustion → relay path, with a reason code naming the *observed NAT class per family*, e.g. `NAT.SYMMETRIC_BOTH_ENDS`, `NAT.CGNAT_V4_NO_V6`, `NAT.UDP_BLOCKED`. Naming the actual cause is required by **I6**; "connection failed" is not acceptable. |
| **Authorization** | Signed, `session_nonce`-scoped, and rate-limited per peer. Probe targets MUST be restricted to addresses that appeared in a *signed* `CandidateSet` from the peer, which is the anti-amplification control. |
| **Consistency requirement** | None. |
| **Transitions** | `NEGOTIATING → CONNECTING`; on exhaustion, `CONNECTING → RELAYED` or `CONNECTING → FAILED` per reliability.md. |
| **IPv4/IPv6** | Punching MUST be attempted on both families concurrently, not sequentially. IPv6 frequently succeeds where IPv4 CGNAT fails; serializing families is the difference between a 200 ms and a 6 s connect on mobile. |

### 10.6 Tunnel establishment

| Field | Value |
|---|---|
| **Participants** | Device ↔ device (direct or via `Relay`) |
| **Trigger** | A candidate pair is validated, or the relay path is selected |
| **Style** | **Direct peer protocol message.** The handshake is a peer-to-peer cryptographic exchange defined entirely by [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md). No infrastructure participates, which is what makes **I1** and **I5** true simultaneously. |
| **Payload** | Opaque to this document: ADR-0001 handshake messages, with the ADR-0014 negotiated result bound in as the prologue/transcript input. |
| **Ordering / delivery** | Datagram, at-most-once, with ADR-0001's own retransmission and anti-replay. |
| **Idempotency** | Handshake retries produce a fresh session; the losing half-open session MUST be garbage-collected by `session_nonce` so retries do not leak state. |
| **Failure / timeout** | Handshake timeout per ADR-0001. Failures MUST distinguish: `CRYPTO.PEER_KEY_UNKNOWN` (not paired), `AUTH.DEVICE_REVOKED`, `AUTH.KEY_ROTATED_PEER_STALE`, `PROTO.TRANSCRIPT_MISMATCH` (**tampering/downgrade — this is a security event, not a network error**), `CRYPTO.NO_RESPONSE` (path dead). Collapsing these into one code is the failure this product exists to fix. |
| **Authorization** | Mutual `DeviceKey` authentication (**I4**), peer must be a `TrustedPeer` at the current `revocation_epoch`. |
| **Consistency requirement** | **Local-only authority.** The resulting `Session` exists only on the two peers. |
| **Transitions** | `CONNECTING → LOCAL_DIRECT` \| `WAN_DIRECT` \| `RELAYED`; failure → `RECONNECTING` or `FAILED`; with kill switch on and no path, → `BLOCKED` (**I3**). |

---

## 11. Interaction contracts — relay

### 11.1 Relay assignment

| Field | Value |
|---|---|
| **Participants** | `Device` → coordination service (hint); `Device` ↔ `Relay` (actual reservation) |
| **Trigger** | Negotiation begins (relay is pre-warmed in parallel with direct attempts), or direct traversal fails |
| **Style** | **Split: ephemeral advisory event for the hint, request/response API for the reservation.** Justification per the §6.2 bridge rule. The *hint* ("region eu-west looks best for you two right now") is re-derivable, decays in minutes, and losing it only costs a worse choice — ephemeral. The *reservation* is a synchronous resource acquisition with an answer the caller needs — request/response, directly with the `Relay`, **not** through the coordination service. Routing reservations through coordination would put the control plane in the data path and break **I5**. |
| **Payload** | Hint: `RelayAssignmentHint{ regions[RelayRegion{ id, endpoints_v4[], endpoints_v6[], observed_rtt_ms, load_class }], expires_at_ms }`. Binding: `BIND{ pair_tag, capability_token, rlk_proof }` → `BOUND{ flow_id }` on the device↔relay leg (C6). The relay's table is keyed by `pair_tag`; the first `BIND` creates a pending slot and the second on the same tag binds it ([ADR-0005](adr/ADR-0005-relay-architecture.md) §7.4). There is no `peer_key_id` — the relay never learns which two devices are talking beyond what forwarding requires. Idempotent **naturally**, by `pair_tag`; no idempotency key is used. |
| **Ordering / delivery** | Hint: ephemeral C2, at-most-once, TTL'd. Reservation: at-least-once with idempotency key on C1-to-relay. |
| **Idempotency** | **Required** on reservation, keyed on `session_nonce`. A retry MUST return the same `relay_binding_id` — otherwise a flaky link leaks relay reservations, which is a direct cause of the "unreliable/unavailable relay" failure mode. |
| **Failure / timeout** | 2 s to reserve, then try the next region. `RELAY.REGION_UNAVAILABLE`, `RELAY.CAPACITY_REJECTED`, `RELAY.TOKEN_INVALID`, `RELAY.ALL_REGIONS_FAILED`. Policy for region ranking and pre-warming is owned by [ADR-0006](adr/ADR-0006-relay-discovery-and-failover.md). |
| **Authorization** | The device presents a `capability_token` issued by coordination that authorizes relay use **without identifying the peer pair to the relay beyond what forwarding requires**, and which conveys no ability to decrypt (**I1**). The relay authenticates the token, not the user. |
| **Consistency requirement** | **Eventual, advisory.** The device's own measured RTT always overrides the hint. Never treat a coordination-supplied relay ranking as authoritative — that is how a stale central view produces the "excessive relay latency" complaint. |
| **Transitions** | `CONNECTING → RELAYED` on successful establishment through the relay. |
| **IPv4/IPv6** | A relay MUST publish both `endpoints_v4` and `endpoints_v6`. A device on IPv6-only cellular MUST be able to reserve and use a relay with no IPv4 path whatsoever. |

### 11.2 Relay failover

| Field | Value |
|---|---|
| **Participants** | `Device` ↔ `Relay` (old), `Device` ↔ `Relay` (new), peer `Device` |
| **Trigger** | Relay health degrades (loss, latency, throughput), relay signals drain, relay becomes unreachable, or a better path appears |
| **Style** | **Direct peer protocol message plus request/response reservation.** Justification: failover must work while the control plane is unreachable (**I5**), so it is driven peer-to-peer using cached relay candidates, with the coordination hint used only when available. A control-plane-mediated failover would make relay outages and control outages correlated — precisely the single-point-of-failure the product forbids. |
| **Payload** | `RelayDrain{ relay_binding_id, drain_deadline_ms, suggested_alternatives[] }` (relay → device); `PathOffer{ session_nonce, new_path{relay_binding_id \| direct endpoint}, path_epoch }` (peer → peer, over the existing encrypted `Session`); `PathAck{ session_nonce, path_epoch, accepted }`. |
| **Ordering / delivery** | `PathOffer`/`PathAck` travel **inside the existing encrypted `Session`**, so they inherit its authentication and are ordered by `path_epoch`. A lower `path_epoch` MUST be ignored. |
| **Idempotency** | Idempotent by `path_epoch`. Re-offering the same epoch is a no-op. |
| **Failure / timeout** | Make-before-break: the new path MUST be validated before the old one is torn down. If validation fails within the drain deadline, `docs/reliability.md` T16/T17 govern: the `Session` returns to the path class it came from if the old path is still alive (applying `T_MIGRATE_COOLDOWN` to the rejected candidate), or enters `RECONNECTING` if the old path is already gone. Never a silent drop — and never `DEGRADED`, because a failed path validation is not a measured quality violation (R6). If no relay is reachable and the kill switch is on, the derived `TwinNet`-scope state is `BLOCKED` (**I3**, `docs/reliability.md` §4.7 rule 1). Reason codes: `RELAY.DRAINING`, `RELAY.FAILOVER_VALIDATED`, `RELAY.FAILOVER_EXHAUSTED`. |
| **Authorization** | In-session, therefore already mutually authenticated. A relay can *ask* a device to leave (`RelayDrain`) but can never redirect a session by itself — the peers decide. This prevents a compromised relay from steering traffic to a chosen relay. |
| **Consistency requirement** | **Local-only authority**, monotonic `path_epoch`. |
| **Transitions** | `RELAYED → MIGRATING → RELAYED` (new relay); or `RELAYED → MIGRATING → WAN_DIRECT` if a direct path became available; on failure `→ DEGRADED → RECONNECTING`. |

---

## 12. Interaction contracts — session lifecycle

### 12.1 Session resumption

| Field | Value |
|---|---|
| **Participants** | Device ↔ peer device |
| **Trigger** | Path loss, endpoint change (roam), wake from suspend, or link change. **Not** process restart — resumption keys are in-memory only (S-13, [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) RS-1), so a restarted agent re-establishes with a full handshake from cached `TrustedPeer` state, which is still control-plane-free. |
| **Style** | **Direct peer protocol message.** Justification: resumption MUST work with the control plane completely down (**I5**). It uses only locally cached material: peer key, last-known `Endpoint`s, and the resumption secret from ADR-0001. Requiring a control-plane round trip to resume is the root cause of "missing auto-reconnect" and "unreliable mobile background operation". |
| **Payload** | ADR-0001 resumption exchange, carrying `{ session_nonce, resumption_id, new_endpoint_hint, path_epoch }`. |
| **Ordering / delivery** | At-most-once datagram with retry; `path_epoch` orders. |
| **Idempotency** | Idempotent by `(session_nonce, path_epoch)`. A duplicate resume MUST NOT create a second `Session` or reset counters. |
| **Failure / timeout** | Resumption attempted first (cheap, ~1 RTT). On failure within its budget, fall back to a full negotiation from cache, then to control-plane-assisted discovery. Each fallback step MUST be visible: `NET.RESUME_OK`, `NET.RESUME_STALE`, `NET.FULL_RENEGOTIATE`. |
| **Authorization** | Resumption secret bound to the original mutually-authenticated handshake (ADR-0001), plus a `revocation_epoch` check: a device MUST refuse to resume with a peer revoked since the session began. |
| **Consistency requirement** | **Local-only authority.** No server involvement whatsoever. |
| **Transitions** | `RECONNECTING → LOCAL_DIRECT \| WAN_DIRECT \| RELAYED`; failure → `RECONNECTING` (retry) or `FAILED`; kill switch on → the derived `TwinNet`-scope state is `BLOCKED` throughout (`docs/reliability.md` §4.7 rule 1). |
| **Kill-switch interaction** | While resumption is in flight and the kill switch is enabled, protected traffic stays blocked (**I3**). Resumption speed is therefore a *user-visible availability* property, not just an optimization. |

### 12.2 Path migration

| Field | Value |
|---|---|
| **Participants** | Device ↔ peer device |
| **Trigger** | Local address change (Wi-Fi↔cellular, new prefix via IPv6 RA, VPN-on-VPN, DHCP renew), or a better path becomes available |
| **Style** | **Direct peer protocol message.** Justification: it is a two-party fact about a live `Session`, must survive control-plane outage, and must complete in well under a second to avoid a visible stall. Any infrastructure involvement would add an RTT to every roam. |
| **Payload** | `PathOffer{ session_nonce, path_epoch, candidate{family, addr, port, mtu_hint} }` → `PathProbe`/`PathProbeAck` (validate) → `PathAck{ path_epoch, accepted }`. All inside the encrypted session. |
| **Ordering / delivery** | Ordered by monotone `path_epoch`; at-most-once per attempt with retry. |
| **Idempotency** | Idempotent by `path_epoch`. |
| **Failure / timeout** | **Make-before-break is mandatory.** The old path MUST remain usable until the new one passes an explicit reachability probe. Probe cadence 500 ms, bounded by `T_MIGRATE` (`docs/reliability.md` §5.3). On failure, remain on the old path and apply `T_MIGRATE_COOLDOWN` to the rejected candidate (T16); if the old path is already gone, `RECONNECTING` (T17). The `Session` is **not** marked `DEGRADED` — R6 reserves that for measured quality violations. The probe budget is bounded by `docs/reliability.md`'s `T_MIGRATE` (3 s), which owns it. Never tear down before validating — premature teardown is the "random tunnel disconnect" symptom. |
| **Authorization** | In-session. An unvalidated path MUST NOT carry traffic, which is also the anti-migration-hijack control. |
| **Consistency requirement** | **Local-only authority**, monotonic `path_epoch`. |
| **Transitions** | `WAN_DIRECT/RELAYED/LOCAL_DIRECT → MIGRATING → (new state)`; failure → `DEGRADED` or `RECONNECTING`. |
| **IPv4/IPv6** | Migration across address families is a first-class case (v4 Wi-Fi → v6-only cellular and back). The new candidate carries its `family`; MTU MUST be re-probed on migration because v6 paths commonly have a smaller effective MTU and stale MTU is a top cause of "throughput degradation" and "connects but nothing loads". |

---

## 13. Interaction contracts — routing, access, and policy

### 13.1 Route advertisement

| Field | Value |
|---|---|
| **Participants** | Advertising `Device` (a `LANGateway` or subnet router) → coordination service → all devices in the `TwinNet` |
| **Trigger** | Device configured to advertise a subnet; interface/prefix change; advertisement TTL refresh; withdrawal |
| **Style** | **Durable control-plane event carrying a device-signed statement.** Justification: E1 fails — no other device can re-derive that 10.7.0.0/24 lives behind that gateway. E3 fails — a device that misses the advertisement blackholes the subnet indefinitely and the user sees "the VPN is connected but I can't reach my NAS", the archetypal cryptic failure. TTL'd because a crashed gateway must not advertise forever. |
| **Payload** | `RouteAdvertisement` (deterministic CBOR, `DeviceKey`-signed): `{ advertiser_device_id, prefixes_v4[], prefixes_v6[], metric, advertisement_epoch, not_after_ms, requires_capability[] }`. Durable events `RouteAdvertised` / `RouteWithdrawn`. |
| **Ordering / delivery** | C2 total order; per-advertiser monotone `advertisement_epoch`. A lower epoch from the same advertiser MUST be ignored. |
| **Idempotency** | Idempotent by `(advertiser_device_id, advertisement_epoch)`. |
| **Failure / timeout** | Advertisements expire at `not_after_ms` (default 1 h, refreshed at ½ TTL). Expiry MUST produce a visible `ROUTE.ADVERTISEMENT_EXPIRED`, not a silent route disappearance. Conflicting advertisements for overlapping prefixes are resolved by `metric` then by `advertiser_device_id`, and the conflict MUST be surfaced as `ROUTE.PREFIX_CONFLICT` — silently picking a winner is how traffic ends up at the wrong gateway. |
| **Authorization** | Signed by the advertiser (**Rule B**), and **accepted only if the receiving device's `AccessPolicy` permits that advertiser to advertise that prefix.** Acceptance is a local policy decision, never an infrastructure decision. Without this, a single compromised device could advertise `0.0.0.0/0` and `::/0` and capture the whole `TwinNet`'s traffic. |
| **Consistency requirement** | **Monotonic per advertiser, eventual globally**, with TTL bounding staleness. |
| **Transitions** | None directly; changes the `Route` table, which may move a `Session` to/from `DEGRADED` if a policy-required prefix becomes unreachable. |
| **IPv4/IPv6** | `prefixes_v4` and `prefixes_v6` are **separate, co-equal lists**, and an advertisement MAY contain only one. A device MUST NOT infer v6 reachability from a v4 advertisement or vice versa. Advertising `0.0.0.0/0` without `::/0` (or the reverse) is a **leak condition** and MUST be rejected with `ROUTE.DEFAULT_SINGLE_FAMILY` unless the local `DNSPolicy`/kill-switch configuration explicitly blocks the unadvertised family (**I3**; enforcement owned by ADR-0012, routing semantics by ADR-0010). |

### 13.2 LAN access

| Field | Value |
|---|---|
| **Participants** | Client `Device` ↔ `LANGateway` `Device` |
| **Trigger** | Client needs a resource on a subnet the gateway advertises |
| **Style** | **Direct peer protocol message over the established `Session`**, with the *permission* coming from durable policy (13.4) and the *route* from durable advertisement (13.1). Justification: the access itself is data-plane forwarding between two peers; putting per-flow authorization on the control plane would violate **I5** and add latency to every new flow. |
| **Payload** | In-session control message `LANAccessRequest{ prefix, family }` → `LANAccessGrant{ prefix, family, ttl_ms, mtu, dns_servers_v4[], dns_servers_v6[], search_domains[] }` or `LANAccessDenied{ reason_code }`. |
| **Ordering / delivery** | In-session, ordered, at-least-once with in-session retry. |
| **Idempotency** | Idempotent: re-requesting an already-granted prefix returns the existing grant. |
| **Failure / timeout** | 2 s. `POLICY.NOT_ADVERTISED`, `POLICY.POLICY_DENIED`, `POLICY.PREFIX_COLLIDES_LOCAL` (the client's own LAN uses the same RFC 1918 range — an extremely common real-world failure that MUST be named precisely, with the colliding prefix in the diagnostic). |
| **Authorization** | The gateway evaluates its own `AccessPolicy` (13.4) against the requesting `DeviceIdentity`. **The gateway is the enforcement point**; the client's view of policy is advisory. Enforcement at the resource owner, not at the requester, is what makes a compromised client unable to grant itself access. |
| **Consistency requirement** | **Eventual** for the policy input, **local authority** for the grant. The gateway MUST re-evaluate on `PolicyBundleUpdated` and revoke live grants that no longer pass, surfacing `POLICY.GRANT_REVOKED_BY_POLICY`. |
| **Transitions** | None; may drive `DEGRADED` if a policy-required prefix is denied. |
| **Multi-client (I7)** | A `LANGateway` MUST serve many concurrent clients with independent grants, per-client `Route` scoping, and per-client accounting. Grants MUST NOT be global gateway state. Architecture owned by [ADR-0013](adr/ADR-0013-multi-client-gateway-architecture.md). |
| **IPv4/IPv6** | Grants are per-family. A gateway advertising a dual-stack subnet MUST issue both, and if it can only forward one family it MUST say so (`POLICY.FAMILY_UNSUPPORTED`) rather than granting v4 and silently blackholing v6 — silent single-family grants are a leak/blackhole class defect. |

### 13.3 Exit-node negotiation

| Field | Value |
|---|---|
| **Participants** | Client `Device` ↔ `ExitNode` `Device`; offers distributed via coordination |
| **Trigger** | User or policy selects an `ExitNode` for default-route egress |
| **Style** | **Durable control-plane event for the *offer*, direct peer protocol message for the *use*.** Justification: "device X is willing to be an exit node" is not re-derivable and must reach devices that were offline (durable, TTL'd). "Client Y is now egressing through X" is a two-party session fact that must survive control-plane outage (peer-direct). |
| **Payload** | Offer: `ExitNodeOffer` (device-signed CBOR) `{ device_id, egress_families[V4,V6], supports_default_v4, supports_default_v6, geo_hint, bandwidth_class, offer_epoch, not_after_ms }`. Use: in-session `ExitNodeEngage{ request_default_v4, request_default_v6, dns_mode }` → `ExitNodeEngaged{ granted_default_v4, granted_default_v6, dns_servers_v4[], dns_servers_v6[], mtu, ttl_ms }` \| `ExitNodeRefused{ reason_code }`. |
| **Ordering / delivery** | Offer: C2 total order, monotone `offer_epoch`. Engagement: in-session, ordered. |
| **Idempotency** | Offer idempotent by epoch; engagement idempotent by `session_nonce`. |
| **Failure / timeout** | 3 s to engage. `POLICY.CAPACITY`, `POLICY.POLICY_DENIED`, `POLICY.OFFLINE`, `POLICY.NO_V6_EGRESS`. |
| **Authorization** | The `ExitNode` enforces its own `AccessPolicy`; the client cannot self-authorize. Both must be `TrustedPeer`s at the current `revocation_epoch`. |
| **Consistency requirement** | Offer: **eventual, TTL-bounded, monotone per offerer.** Engagement: **local-only authority.** |
| **Transitions** | Engaging or losing an exit node changes the `Route` set; loss with kill switch on → `BLOCKED` (**I3**). |
| **IPv4/IPv6 — critical** | `granted_default_v4` and `granted_default_v6` are independent. **If a client requests full-tunnel egress and the exit node grants only one family, the client MUST block the ungranted family rather than letting it egress locally.** A v4-only exit grant with v6 leaking to the local ISP is the exact IPv6 leak this product must never ship. The protocol therefore requires an explicit per-family grant/deny, with no defaulting: an absent field is a denial, not a permission. Enforcement mechanism owned by [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md); the *contract obligation to state both families explicitly* is owned here. |
| **Multi-client (I7)** | An `ExitNode` serves many concurrent clients with per-client NAT/state, per-client accounting, and per-client policy. Per ADR-0013. |

### 13.4 Policy synchronization

| Field | Value |
|---|---|
| **Participants** | `Owner` (via an authorized device or admin surface) → coordination service → all devices |
| **Trigger** | `AccessPolicy` or `DNSPolicy` change; new device joins; periodic refresh |
| **Style** | **Durable control-plane event carrying a signed, versioned bundle.** Justification: E1 fails (policy is a decision, not an observation), E3 fails badly (a device that misses a tightening keeps enforcing the old, looser policy — a silent authorization hole), E4 fails (replaying an older bundle is a **policy rollback attack**). |
| **Payload** | `PolicyBundle` (deterministic CBOR, `Owner`-authority-signed): `{ twinnet_id, policy_version (monotone), access_rules[], dns_policy{ mode, servers_v4[], servers_v6[], split_domains[], block_fallback }, exit_policy, relay_region_policy, killswitch_floor, not_after_ms }`. Durable event `PolicyBundleUpdated{ policy_version, bundle }`.<br><br>**`killswitch_floor` is a floor, never a ceiling (normative).** It contributes only to `policy_required_mode`, and the effective enforcement is `max(local_mode, policy_required_mode)` ([ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) §11.10). There is **no encoding** of this field, or of any other field in this bundle, that lowers enforcement below the device's local setting, and no receiver may implement one. `block_fallback` is likewise deny-shaped: `true` is honoured, and `false` is a *grant* that suspends on bundle expiry per [ADR-0009](adr/ADR-0009-state-consistency.md) §11.4. This is the schema-level guarantee behind [ADR-0012](adr/ADR-0012-kill-switch-and-leak-prevention.md) KS-22 and [docs/threat-model.md](threat-model.md) AD-7 — **a fully compromised coordination service can make a device more blocked, never less.** |
| **Ordering / delivery** | C2 total order; **monotone `policy_version` is mandatory** and a device MUST reject any bundle with `policy_version` ≤ its high-water mark. Bundles are whole-state, not deltas — a delta scheme requires exactly-once delivery, which does not exist, and a missed delta silently forks policy. |
| **Idempotency** | Idempotent by `policy_version`. |
| **Failure / timeout** | Bundles carry `not_after_ms`. **Behaviour on an expired bundle is NOT a policy input and is NOT remotely selectable** — it is fixed by [ADR-0009](adr/ADR-0009-state-consistency.md) §11.4's grant/deny asymmetry: on expiry, *grants* carried by the bundle suspend and *denials* persist, so an expired bundle can only ever become more restrictive. An established `Session` is never torn down by expiry (**I5**). Surfaced as `POLICY.EXPIRY.BUNDLE_EXPIRED`. |
| **Authorization** | Owner-authority signature (**Rule B**). The coordination service distributes but cannot author policy — otherwise a compromised coordination service could disable every kill switch in the fleet, which would make **I1** and **I3** jointly worthless. |
| **Consistency requirement** | **Monotonic reads mandatory, eventual convergence acceptable.** Never allow a device to move backwards in `policy_version`. |
| **Transitions** | A tightening policy may drive `WAN_DIRECT/RELAYED → DEGRADED` (objective violated) or `→ BLOCKED` (**I3**). |
| **IPv4/IPv6** | `dns_policy` MUST specify servers for both families and MUST state `block_fallback` per family. A DNS policy that configures v4 resolvers and leaves v6 resolvers to the OS is a DNS leak; the schema forbids expressing it by requiring both lists to be present (empty list = "block this family", which is different from absent). Semantics owned by [ADR-0011](adr/ADR-0011-dns-handling.md). |

---

## 14. Interaction contract — health reporting

| Field | Value |
|---|---|
| **Participants** | `Device` → diagnostics collector (C7); `Device` ↔ peer (in-session health); `Relay` → operator telemetry |
| **Trigger** | Sampling timer, state transition, threshold breach, user-initiated "collect diagnostics" |
| **Style** | **Asynchronous event on the management plane**, batched and coalesced. Justification: health data is re-derivable, decays, and losing it is a diagnostics gap, not a correctness failure — ephemeral by every check in §6. It is explicitly *not* a durable control-plane event, because telemetry volume would otherwise dominate the trust-bearing log (§6.1). |
| **Payload** | `HealthSample{ device_id, sample_epoch, connection_state, health_state, per_session[{ session_nonce, path_kind, family, rtt_p50_us, rtt_p95_us, loss_ppm, goodput_bps, mtu, pmtud_blackhole_detected, relay_binding_id? }], per_interface[{ family, has_default_route, dns_servers_configured, leak_probe_result }], reason_codes[], agent_version, proto_version }`. In-session: `PeerHealthProbe`/`PeerHealthReport` for the *peer's* view of the same path. |
| **Ordering / delivery** | At-least-once, unordered, loss-tolerant, batched. Samples carry absolute `sample_epoch`; the collector reorders. |
| **Idempotency** | Idempotent by `(device_id, sample_epoch)`. |
| **Failure / timeout** | Collector unavailability MUST NOT affect the control or data plane. Samples are buffered with a bounded ring and dropped oldest-first; the drop is itself reported as `INTERNAL.BUFFER_OVERFLOW`. |
| **Authorization** | Channel-authenticated. Content scope is governed by the `Owner`'s diagnostics policy; per **I1** a sample MUST NOT contain tunnel plaintext, and MUST NOT contain peer IP addresses beyond what the reporting device already knows. |
| **Consistency requirement** | **Eventual, local authority.** The device is authoritative for its own health; the collector never corrects it. |
| **Transitions** | Health thresholds *drive* `DEGRADED` entry/exit, but the thresholds and transitions are owned by [docs/reliability.md](reliability.md); this contract only guarantees the observations are delivered. |
| **I6 obligation** | Every terminal (`FAILED`, `BLOCKED`) and degraded state MUST carry at least one stable machine-readable reason code plus human-actionable text. `reason_codes[]` is **not optional** — a `HealthSample` reporting `DEGRADED` or `FAILED` with an empty `reason_codes[]` is a malformed message and MUST be rejected by the collector with `INTERNAL.MISSING_REASON`. This is the protocol-level teeth behind **I6**. |
| **Two-sided view** | `PeerHealthReport` exists because one-sided measurements systematically misdiagnose asymmetric paths. "Your upload is fine, the peer sees 40 % loss inbound" is actionable; "connection is bad" is not. |

---

## 15. Consistency requirements imposed by the protocol

[ADR-0009](adr/ADR-0009-state-consistency.md) owns the state-ownership table and adjudicates
how these requirements are met. This section states, for each piece of state, **the weakest
guarantee under which the protocol contracts above remain correct**. Anything weaker is a
defect; anything stronger is acceptable but may cost availability.

| State | Weakest sufficient guarantee | Imposed by | If the guarantee is not met |
|---|---|---|---|
| `DeviceIdentity` existence and `(twinnet_id, device_pubkey)` uniqueness | **Linearizable at admission**, then monotonic | §8.1 | Duplicate devices on retry; two devices with the same `TwinNet` address; address-collision blackholes |
| `Pairing` completion | **Linearizable at commit** (a `pairing_id` completes at most once), monotonic propagation | §8.2 | Asymmetric trust: A trusts B, B does not trust A; every handshake fails with a misleading crypto error |
| **Revocation** | **Linearizable admission + monotonic reads at every consumer + no forked history** | §8.3 | **Trust resurrection.** A stolen device regains access. See §15.1 — this is escalated. |
| `DeviceKey` rotation | **Monotonic** per device — `generation` and `tk_generation` each never regress; eventual across peers within `T_IK_OVERLAP` / `T_TK_OVERLAP` | §8.4 | Key rollback: a compromised old key is reinstated |
| `AccessPolicy` / `DNSPolicy` bundle | **Monotonic reads** (`policy_version` never regresses) + eventual convergence + bounded staleness via `not_after_ms` | §13.4 | Policy rollback attack; silent authorization holes; DNS leak from a stale `DNSPolicy` |
| `Route` / `ExitNode` advertisements | **Monotonic per advertiser** (`advertisement_epoch` / `offer_epoch`), eventual globally, TTL-bounded | §13.1, §13.3 | Blackholed subnets; traffic sent to a withdrawn gateway; stale default route → leak |
| `RelayAssignment` | **Eventual, advisory only.** No convergence requirement. Peer-local measurement is final. | §11.1 | Only a worse relay choice — by design this cannot cause incorrectness |
| `Presence` | **Eventual, TTL-bounded, device-local authority.** Explicitly no convergence requirement. | §9.2 | Stale UI only, self-healing at TTL |
| `Session` / `Tunnel` / `Path` state | **Local-only authority.** The coordination tier holds a lossy cache and is NEVER authoritative. | §10.6, §12.1, §12.2 | **I5 breaks.** A control-plane outage would put sessions in an indeterminate state and reconciliation would tear down live tunnels |
| `HealthState` samples | **Eventual, lossy, device-local authority** | §14 | Diagnostics gaps only |
| `Capability` / `ProtocolVersion` negotiation result | **Local-only, per-connection, immutable once bound to the transcript** | §10.2, §10.3 | Downgrade attack becomes possible |

### 15.1 Escalations — where the protocol needs more than eventual consistency

Three requirements are called out explicitly because they are stronger than a
default "eventually consistent control plane" would provide, and ADR-0009 must
adjudicate them rather than let them be assumed.

**E-1. Revocation requires monotonic reads and a non-forked history.**
Eventual consistency permits a replica to serve an *older* snapshot after serving a newer
one. For revocation that is not a latency artifact, it is **un-revocation**: a device that
correctly learned `revocation_epoch = 42` and then reads `epoch = 41` from a lagging replica
would restore trust in a stolen device. The protocol defends partially — every device keeps
a high-water mark and rejects any lower epoch (§8.3) — but client-side defence is not
sufficient on its own, because it cannot detect a *forked* history in which two replicas
publish different content at the same epoch. The protocol therefore requires from ADR-0009:
(a) linearizable admission of a `RevocationRecord`; (b) a single writer per `TwinNet`
revocation log; (c) monotonic-read session semantics for any device across replica
failover. **This is the strongest consistency requirement in TwinVPN and it should be the
only one that constrains the storage design.**

**E-2. Read-your-writes across the C1/C2 boundary.**
A mutating C1 response and the C2 event it causes travel on different streams. Without a
guarantee, a device sees "pairing succeeded" and then a peer list that does not contain the
peer. §5.1 discharges this with `committed_at_net_seq`, but that only works if ADR-0009
guarantees the returned sequence number is a *real, monotone position in the same log the
device is reading*. If ADR-0009 chooses a design where the C1 write path and the C2 read
path can diverge (e.g. different shards), the protocol needs an explicit
read-your-writes token instead, and `causality_token` (§5.2) is the reserved carrier for it.

**E-3. Policy bundles must be whole-state, and that is a consistency choice, not a schema
choice.** Delta-encoded policy requires exactly-once delivery to stay correct. Exactly-once
delivery does not exist. The protocol therefore mandates whole-bundle transfer with a
monotone `policy_version`, accepting the bandwidth cost, so that a device that missed an
arbitrary number of updates converges on a single message. If ADR-0009 or a future
optimisation wants deltas, it must first supply a gap-detecting, gap-repairing mechanism —
the monotone version number alone is not enough, because it detects a gap without repairing
it.

### 15.2 What the protocol deliberately does *not* require

- **No global ordering across TwinNets.** Ever. It would be a scalability trap for zero benefit.
- **No consensus on `Session` state.** Two peers disagreeing about whether a session exists
  is resolved by the handshake, not by a quorum.
- **No convergence for presence or relay hints.** They are hints; requiring convergence
  would convert a cheap ephemeral channel into an expensive durable one for no correctness gain.
- **No distributed transaction spanning device and coordination state.** Every multi-step
  interaction here is decomposed into independently idempotent steps precisely to avoid one.

---

## 16. Message catalogue

Legend — **Style**: RR = request/response, ST = streaming, AE = asynchronous event,
PP = direct peer protocol, DE = durable control-plane event, ES = ephemeral signaling.
**Auth**: A = channel-authenticated (§3 Rule A), B = detached signature (§3 Rule B),
S = in-session (ADR-0001), — = none by design.
**Idem**: key = ADR-0008 idempotency key required; nat = naturally idempotent; — = n/a.

| # | Message | From → To | Chan | Style | Durability | Auth | Idem | Consistency |
|---|---|---|---|---|---|---|---|---|
| 1 | `RegisterDeviceReq` / `Resp` | device → coord | C1 | RR | durable effect | A | key | linearizable |
| 2 | `DeviceRegistered` | coord → devices | C2 | DE | durable | A | nat | monotonic |
| 3 | `ProposePairingReq` / `Resp` | device → coord | C1 | RR | durable effect | A | key | linearizable |
| 4 | `ConfirmPairingReq` / `Resp` | device → coord | C1 | RR | durable effect | A + B | key | linearizable |
| 5 | `PairingCompleted` / `PairingRejected` | coord → devices | C2 | DE | durable | B | nat | monotonic |
| 6 | `RevokeDeviceReq` / `Resp` | device → coord | C1 | RR | durable effect | A + B | key | **linearizable** |
| 7 | `DeviceRevoked` | coord → devices | C2 | DE | durable | B | nat | **monotonic reads** |
| 8 | `RotateKeyReq` / `Resp` | device → coord | C1 | RR | durable effect | A + B(×2) | key | monotonic |
| 9 | `DeviceKeyRotated` | coord → devices | C2 | DE | durable | B | nat | monotonic |
| 10 | `GetPeersReq` / `Resp` | device → coord | C1 | RR | read | A | nat | monotonic |
| 11 | `PeerAdded` / `PeerRemoved` / `PeerUpdated` | coord → devices | C2 | DE | durable | A | nat | monotonic |
| 12 | LAN discovery probe / response | device ↔ device | LAN mcast | ES | ephemeral | — (hint only) | nat | none |
| 13 | `Heartbeat` / `HeartbeatAck` | device → coord | C1 | RR (lightweight) | ephemeral | A | nat | eventual |
| 14 | `PresenceChanged` | coord → devices | C2 | AE (ephemeral) | ephemeral | A | nat | eventual, TTL |
| 15 | `WakeHint` | push gw → device | C3 | AE | **non-authoritative** | — | nat | none |
| 16 | `ConnectOffer` / `ConnectAnswer` | device ↔ device via rendezvous | C4 | ES | ephemeral | B | nat (`session_nonce`) | local-only |
| 17 | `CandidateSet` (incl. trickle) | device ↔ device via rendezvous | C4 | ES | ephemeral | B | nat (set merge) | none |
| 18 | `PunchSync` / `PunchProbe` / `PunchResult` | device ↔ device | C4/C5 | ES | ephemeral | B | nat | none |
| 19 | ADR-0001 handshake messages | device ↔ device | C5/C6 | PP | ephemeral | ADR-0001 | nat | local-only |
| 20 | `RelayAssignmentHint` | coord → device | C2 | AE (ephemeral) | ephemeral | A | nat | eventual, advisory |
| 21 | *(withdrawn — superseded by row 42 `BIND`/`BOUND`)* | — | — | — | — | — | — | Replaced by [ADR-0005](adr/ADR-0005-relay-architecture.md) §7.4's `pair_tag`-keyed binding. The former `peer_key_id` field is removed: it would have told the relay which two devices are talking, defeating A11 |
| 22 | `RelayDrain` | relay → device | C6 | AE | ephemeral | relay-authenticated | nat | advisory |
| 23 | `PathOffer` / `PathProbe` / `PathProbeAck` / `PathAck` | device ↔ device | C5/C6 in-session | PP | ephemeral | S | nat (`path_epoch`) | local-only |
| 24 | ADR-0001 resumption exchange | device ↔ device | C5/C6 | PP | ephemeral | ADR-0001 | nat | local-only |
| 25 | `RouteAdvertisement` → `RouteAdvertised` / `RouteWithdrawn` | device → coord → devices | C1/C2 | RR + DE | durable, TTL'd | B | nat (epoch) | monotonic/advertiser |
| 26 | `LANAccessRequest` / `Grant` / `Denied` | device ↔ gateway | C5/C6 in-session | PP | ephemeral | S | nat | local authority |
| 27 | `ExitNodeOffer` → `ExitNodeOffered` / `Withdrawn` | device → coord → devices | C1/C2 | RR + DE | durable, TTL'd | B | nat (epoch) | monotonic/offerer |
| 28 | `ExitNodeEngage` / `Engaged` / `Refused` | device ↔ exit node | C5/C6 in-session | PP | ephemeral | S | nat | local authority |
| 29 | `PutPolicyReq` / `Resp` | device → coord | C1 | RR | durable effect | A + B | key | linearizable |
| 30 | `PolicyBundleUpdated` | coord → devices | C2 | DE | durable | B | nat (version) | **monotonic reads** |
| 31 | `HealthSample` (batched) | device → collector | C7 | AE | ephemeral | A | nat | eventual |
| 32 | `PeerHealthProbe` / `PeerHealthReport` | device ↔ device | C5/C6 in-session | PP | ephemeral | S | nat | local authority |
| 33 | `SubscribeEventsReq` (cursor resume) | device → coord | C1 | ST | — | A | nat | monotonic |
| 34 | `EventBatch` | coord → device | C2 | ST | mixed | A | nat | total order/TwinNet |
| 35 | `NegotiationConfirm` | device ↔ device | C5 | PP | ephemeral | ADR-0001 transcript | nat | local-only |
| 36 | `TrustEpochAssert` | device ↔ device | C5 | PP | ephemeral | ADR-0001 transcript | nat | monotonic | Carries `(twinnet_id, trust_epoch, anchor_version, delegation_set_digest)`. The **observable** carrier for [ADR-0009](adr/ADR-0009-state-consistency.md) G-1/G-2 and [ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.5 — see [ADR-0001](adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) P-3 |
| 37 | `RevocationTransfer` | device ↔ device | C5 | PP | ephemeral carriage of a **durable** B2 statement | Owner-authority signature (**B**) | nat | monotonic | Peer-to-peer carriage of a `RevocationRecord` under [ADR-0009](adr/ADR-0009-state-consistency.md) G-3. The sender is a courier, never a publisher — it does **not** publish `DeviceRevoked` (§7) |
| 38 | `StreamCompacted` | coord → device | C2 | AE | ephemeral | A | nat | total order/TwinNet | `{up_to_net_seq}`. Announces a deliberate gap in the C2 sequence ([ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) N-8). Receiver MUST respond with a declarative re-read |
| 39 | `StateDocumentAvailable` | coord → device | C2 | AE | ephemeral | A | nat | monotonic | Notification that a newer signed document version exists |
| 40 | `GetStateDocumentReq` / `Resp` | device → coord | C1 | RR | — | A | nat | monotonic | Declarative re-read of a signed state document by type + version |
| 41 | `LogHead` | coord → device | C2 | AE | ephemeral | **B** (COSE_Sign1) | nat | monotonic | Signed freshness proof ([ADR-0002](adr/ADR-0002-control-plane-messaging-and-event-bus.md) §11.2). The signing key is an **online** control-plane key with **no** delegated trust power ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) §7.9) — it proves liveness, never trust |
| 42 | `BIND` / `BOUND` | device ↔ relay | C6 | RR | ephemeral | `RelayCapabilityToken` + `K_leg` MAC | nat by `pair_tag` | local-only | Relay slot binding ([ADR-0005](adr/ADR-0005-relay-architecture.md) §7.4). Replaces the former `ReserveRelayReq`; keyed by `pair_tag`, never by `peer_key_id` |
| 43 | `PING` / `PONG` / `DRAIN` / `CAPS` / `REBIND` / `RELAY_STATUS` | device ↔ relay | C6 | mixed | ephemeral | `K_leg` MAC | nat | local-only | Relay leg control frames ([ADR-0005](adr/ADR-0005-relay-architecture.md) §7.3) |
| 44 | `RelayEpochFloor` | coord → device | C2 | AE | durable | **B** | nat | monotonic | Anti-rollback floor for `RelayCapabilityToken` epochs |
| 45 | `TrustEpochBundleTransfer` | device ↔ device | C5 | PP | ephemeral carriage of a **durable** B2 statement | `Owner`-authority signature (**B**) | nat by `trust_epoch` | monotonic | Peer-to-peer carriage of a `TrustEpochBundle` ([ADR-0007](adr/ADR-0007-device-identity-and-pairing.md) N-28). Each `EpochSeed` inside is HPKE-sealed to its recipient, so a courier peer forwards seals it cannot open. **This is the carriage for the second revocation lever:** `RevocationTransfer` (row 37) propagates *refusal*, but only this row lets a lagging peer advance `min_acceptable_epoch` and derive `psk2` at the new epoch. Without it the PSK-epoch lever has no path around a control-plane outage |

---

## 17. Reason codes and diagnostics obligations (I6)

Reason codes use the taxonomy owned by [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md)
§11.2: `DOMAIN.CONDITION` or `DOMAIN.SUBDOMAIN.CONDITION`, uppercase, dot-separated, carried on the
wire as a string. This document defines **no** namespace of its own. The **registry** — the
authoritative list, the human-readable text, the remediation guidance, and the stability
policy — is owned by [ADR-0015](adr/ADR-0015-observability-and-diagnostics.md). This
document owns only the following protocol-level obligations:

1. Every response that is not a success MUST carry at least one reason code.
2. Every transition into `DEGRADED`, `BLOCKED`, `FAILED`, or a fallback path MUST carry at
   least one reason code.
3. Reason codes are **stable identifiers**, never renumbered. New codes may be added; old
   codes are deprecated per ADR-0014's deprecation policy, never reused.
4. A receiver encountering an **unknown** reason code MUST degrade to its `DOMAIN` prefix and
   present a domain-level explanation, and MUST NOT swallow it ([ADR-0015](adr/ADR-0015-observability-and-diagnostics.md)
   §11.2 rule 5). The raw code MUST remain available in the diagnostic detail but MUST NOT be the
   primary user-facing signal — a bare identifier plus a generic message is exactly the outcome
   O-02 classifies as a defect. Unknown-code swallowing turns a forward-compatible
   diagnostic into a cryptic silence, which is the failure mode **I6** exists to prevent.
5. Domains used in this document are drawn from ADR-0015 §11.2's thirteen: `PROTO`, `AUTH`,
   `NET`, `NAT`, `RELAY`, `POLICY`, `DNS`, `ROUTE`, `CRYPTO`, `CONTROL`, `INTERNAL`. This document
   MUST NOT introduce a domain that ADR-0015 does not declare; a genuinely new domain is added to
   **its** table, never invented here.

---

## 18. Assumptions this document makes about other ADRs

Recorded explicitly so contradictions surface at review rather than at integration.

| # | Assumption | Owner to confirm |
|---|---|---|
| A1 | The control channel is mutually authenticated to `DeviceKey`, giving a TLS-exporter channel binding usable as `Auth.channel_binding`. | ADR-0001 / ADR-0007 |
| A2 | The peer handshake accepts an application-supplied prologue/transcript input, so the negotiated version + capability set can be bound into it. | ADR-0001 |
| A3 | A signature scheme with a deterministic canonical input encoding is available, and verification is performed over received octets. | ADR-0001 / ADR-0003 |
| A4 | Session resumption exists at the tunnel layer and requires no control-plane round trip. | ADR-0001 |
| A5 | `Owner` authority can sign `RevocationRecord` and `PolicyBundle` such that the coordination service cannot forge them. | ADR-0007 |
| A6 | Idempotency keys are client-generated, dedupe window ≥ 24 h, and a replay returns the original response body rather than a conflict. | ADR-0008 |
| A7 | Revocation admission is linearizable and devices get monotonic reads across replica failover (escalation E-1). | ADR-0009 |
| A8 | `committed_at_net_seq` is a real monotone position in the same log the device reads (escalation E-2). | ADR-0009 |
| A9 | `Session`/`Tunnel`/`Path` are device-authoritative in the state-ownership table. | ADR-0009 |
| A10 | NAT traversal consumes `CandidateSet`/`PunchSync` as specified and does not require durable candidate storage. | ADR-0004 |
| A11 | Relays authenticate a capability token and forward opaque frames without learning the peer pair beyond what forwarding requires. | ADR-0005 |
| A12 | Relay failover can be driven peer-to-peer from cached relay candidates without the control plane. | ADR-0006 |
| A13 | Per-family default-route grants are enforceable by the kill switch, so an ungranted family can be blocked rather than leaked. | ADR-0012 |
| A14 | A `LANGateway`/`ExitNode` maintains per-client state, so grants are per-client not global. | ADR-0013 |
| A15 | The reason-code registry is stable-identifier based and supports unknown-code passthrough. | ADR-0015 |
