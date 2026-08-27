# ADR-0002: Control-Plane Messaging and Event Bus

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** PROTOCOL
- **Related:** [docs/protocol.md](../protocol.md) (§2 envelope, §4 channels, §5 ordering, §6 ephemeral/durable, §7 event ownership, §15 consistency, §16 catalogue) · [docs/architecture.md](../architecture.md) (§2.8, §2.9, §2.12, §2.13, §4, §5, §9) · [docs/reliability.md](../reliability.md) (§2.1, §4, §6) · [docs/networking.md](../networking.md) (§11 A6) · [docs/testing-strategy.md](../testing-strategy.md) (§0 A-12, A-13) · [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) (L-CONTROL transport, channel binding) · [ADR-0003](ADR-0003-network-contract-schema-format.md) (encoding — already decided) · [ADR-0004](ADR-0004-nat-traversal-strategy.md) · [ADR-0005](ADR-0005-relay-architecture.md) · [ADR-0006](ADR-0006-relay-discovery-and-failover.md) · [ADR-0007](ADR-0007-device-identity-and-pairing.md) · [ADR-0008](ADR-0008-idempotency.md) · [ADR-0009](ADR-0009-state-consistency.md) · [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) · [ADR-0015](ADR-0015-observability-and-diagnostics.md)

This ADR decides **how control-plane messages physically move**: the transport binding for the
device↔control-plane channel (protocol.md channels C1/C2), the substrate of the server-side
durable event log and the internal fan-out bus, the delivery semantics of every hop, the
push-versus-pull shape of signed state documents, the delivery path for an ephemeral rendezvous
`CALL`, and the backpressure, admission-control, and multi-region availability behaviour of the
control plane. It does **not** decide wire encoding or schema evolution ([ADR-0003](ADR-0003-network-contract-schema-format.md)),
tunnel or relay cryptography ([ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)),
consistency classes or the state-ownership adjudication ([ADR-0009](ADR-0009-state-consistency.md) —
this ADR supplies the delivery mechanism those classes need and states the interface it requires
in §11.9), relay data-plane forwarding ([ADR-0005](ADR-0005-relay-architecture.md)), NAT traversal
tactics ([ADR-0004](ADR-0004-nat-traversal-strategy.md)), or any data-plane timer, backoff, or
state transition ([docs/reliability.md](../reliability.md) owns all of those; this ADR supplies
guards and reason codes only).

---

## 1. Context

[docs/protocol.md](../protocol.md) §4 already fixes the *shape* of the channels: C1 request/response,
C2 a resumable totally-ordered durable event stream, C3 best-effort push wake, C4 ephemeral signaling
through a blind rendezvous forwarder, C7 batched telemetry. It also fixes one structural rule that
this ADR must make true (§1): **a `Device` never speaks to a message broker.** The durable event log
is an implementation detail behind the coordination API; devices see only a resumable, sequenced
stream. Everything below is downstream of that rule.

Four forces make this decision non-obvious.

**The control plane is semi-trusted, not trusted.** It warehouses statements it must not be able
to forge (protocol.md §3 Rule B). The messaging substrate therefore has to be safe under the
assumption that a front-end node, and even the broker itself, is hostile — a constraint that
eliminates any design in which the transport is the authority for trust-bearing content.

**The control plane is allowed to be down.** Invariant **I5** and architecture.md §4.4 make outage
a *supported operating mode*. This inverts the usual availability engineering: the substrate does
not need five nines, it needs to fail in a way that is legible (**I6**) and that no data-plane code
path can observe. That is a structural property, not an SLO.

**Two escalations already constrain the storage.** protocol.md §15.1 **E-1** requires linearizable
revocation admission, a single writer per `TwinNet` revocation log, and monotonic reads across
replica failover. **E-2** requires that `committed_at_net_seq`, returned by a C1 mutating response,
be *a real monotone position in the same log the device reads on C2*. E-2 is the interesting one:
it is a dual-write problem in disguise. Any architecture that commits state to a database and then
publishes to a separate broker cannot honour E-2 without an outbox, and an outbox is already
most of a log.

**Two deployment topologies, not one.** architecture.md §7 requires the control plane to be
deployable "as a single self-contained unit an individual can run" (T2/T3), not only as a
horizontally-scaled service. A substrate that presupposes an operations team is not a substrate;
it is a topology restriction disguised as a technology choice.

---

## 2. Requirements

| # | Requirement | Source |
|---|---|---|
| **RQ-1** | The device↔control-plane binding MUST carry C1 and C2 on one mutually-authenticated connection, and MUST expose a channel binding usable as `Auth.channel_binding`. | protocol.md §2, §4.2, A1 |
| **RQ-2** | The binding MUST work on hostile networks: UDP-blocked, DPI-filtered, TLS-intercepting-middlebox, and HTTP-proxy-only. Every rung of the fallback MUST be individually observable. | R-18, reliability.md §2.2 |
| **RQ-3** | C2 MUST be resumable by `net_seq` cursor with no silent omission, and MUST survive process restart, suspend, and roam. | protocol.md §4, §5.1 |
| **RQ-4** | `committed_at_net_seq` MUST be a real monotone position in the log the device reads (E-2), without a dual write. | protocol.md §15.1 |
| **RQ-5** | Revocation admission MUST be linearizable with a single writer per `TwinNet` log and monotonic reads across replica failover (E-1). | protocol.md §15.1, S-03 |
| **RQ-6** | Every durable event MUST be **independently applicable** — a receiver MUST be able to apply it, or ignore it and re-read declaratively, without any predecessor event. | ADR-0008 §11.2 |
| **RQ-7** | An ephemeral rendezvous `CALL` MUST reach a NAT'd peer with a stated latency budget, MUST NOT become durable, and its absence MUST NOT block establishment. | protocol.md §6, §10.1; networking.md A6 |
| **RQ-8** | No established-session code path may require a control-plane call. This MUST be structurally checkable, not merely asserted. | **I5**, architecture.md §4.4, testing-strategy A-13 |
| **RQ-9** | The substrate MUST bound fan-out cost, MUST shed load without silent data loss, and MUST survive a full control-plane restart of the whole fleet without a self-sustaining connection storm. | R-11, reliability.md §6.1 |
| **RQ-10** | Every control-channel failure mode MUST carry a stable `reason_code` in the ADR-0015 `CONTROL` namespace. | **I6**, R-22 |
| **RQ-11** | The entire substrate MUST run as a single self-contained process for T2/T3, degrading in *scale*, never in *semantics*. | architecture.md §7 |
| **RQ-12** | The control channel MUST NOT add a radio wake on mobile beyond the coalesced wake window already budgeted. | R-08, reliability.md §6.6 |

---

## 3. Constraints

| # | Constraint | Consequence |
|---|---|---|
| **C-1** | Encoding is fixed: protobuf at B1, deterministic CBOR in COSE_Sign1 for signed statements, protobuf-wrapping-CBOR at B3 ([ADR-0003](ADR-0003-network-contract-schema-format.md) §11). | The transport must carry length-delimited protobuf on streams and one envelope per datagram on C4. No transport may require its own serialization (rules out any binding whose framing is a competing schema system). |
| **C-2** | Envelope caps: 64 KiB on C1/C2/C7, 1200 B on C4 (protocol.md §2). | C4 cannot carry a large candidate set; the transport must not need to. |
| **C-3** | ADR-0001 fixes L-CONTROL as QUIC + TLS 1.3, mutual RFC 7250 raw-public-key auth to `DeviceIdentityKey` (P-256), server auth against a pinned key set, **0-RTT prohibited**. | The primary rung is already decided at the crypto layer; this ADR decides the application binding on top of it and the fallback rungs below it. |
| **C-4** | I1/I4: infrastructure holds no tunnel key and no `DeviceKey` private half. | The messaging substrate never holds decryption capability; a compromised broker is a metadata and availability problem, never a confidentiality one. |
| **C-5** | I8 / protocol.md §7: single publisher per durable event type. | The bus MUST NOT permit a second publisher of any event type, and a receiver MUST reject one. |
| **C-6** | Devices must never address the broker (protocol.md §1). | The bus is strictly internal; no device-facing broker protocol may leak. |
| **C-7** | Timers, backoff, and `ConnectionState` transitions belong to reliability.md. | This ADR reuses `control-plane`-class backoff and the retry budget verbatim; it defines no new state and no new transition. |
| **C-8** | Clocks are advisory (protocol.md §2). | Ordering may not be derived from wall clocks anywhere in this design. |

---

## 4. Considered Alternatives

### 4.1 Device↔control-plane transport binding

| # | Alternative |
|---|---|
| **T-1** | **QUIC + HTTP/3 on one long-lived mTLS connection**, C1 as bidirectional streams, C2 as a long-lived server-initiated stream, with a TCP fallback ladder. |
| **T-2** | **WebSocket over TLS (RFC 6455) on TCP/443**, one connection, application-level multiplexing of RPC and events inside the frame stream. |
| **T-3** | **gRPC bidirectional streaming** over HTTP/2, one stream per logical channel. |
| **T-4** | **Plain request/response HTTPS with long-polling** for C2 — no persistent stream abstraction at all. |
| **T-5** | **MQTT v5 over TLS**, topics per `TwinNet` and per device, QoS 1, session persistence for offline delivery. |
| **T-6** | **Raw QUIC with a bespoke application protocol** (no HTTP/3 layer), streams assigned by convention. |

### 4.2 Server-side durable event substrate

| # | Alternative |
|---|---|
| **B-1** | **Append-only durable partitioned log** (Kafka/Redpanda-shaped), partition per `TwinNet`, offset = `net_seq`. |
| **B-2** | **Classic broker with durable streams** (NATS JetStream / RabbitMQ streams) as the system of record. |
| **B-3** | **The log is a table.** A per-`TwinNet` append-only `event` relation in the *same* transactional store as control-plane state; `net_seq` allocated by a per-`TwinNet` monotone counter **inside the same transaction as the state mutation**. Fan-out notification via an internal bus that carries **only watermarks**, never payloads. |
| **B-4** | **Direct synchronous RPC fan-out** between control-plane services; no durable log; C2 reconstructed by querying state. |
| **B-5** | **Database-backed outbox + external broker**: state committed to the DB with an outbox row, a relay process publishes to Kafka/NATS, devices read from a stream service fed by the broker. |

---

## 5. Advantages of Each Alternative

### 5.1 Transport

| # | Advantages |
|---|---|
| **T-1** | Independent streams eliminate head-of-line blocking between an RPC and a large event batch — a single TCP connection structurally cannot. QUIC connection migration (RFC 9000 §9) survives Wi-Fi↔cellular handover with **no re-authentication**, which is the direct answer to R-07-adjacent control-channel churn. UDP/443 is the same shape as ordinary HTTP/3 web traffic. Already the ADR-0001 L-CONTROL decision, so it costs no additional crypto surface. HTTP/3 gives `GOAWAY` for graceful drain (RFC 9114 §5.2) and a standard proxying story. Degrades to HTTP/2 and HTTP/1.1 with the *same* application semantics, so one server implementation serves every rung. |
| **T-2** | Ubiquitous, survives almost every middlebox because it is an HTTP upgrade, trivially proxied, and mature client libraries exist on every platform including constrained routers. Full duplex on a single socket with a tiny framing overhead (2–14 B). |
| **T-3** | Excellent generated-code ergonomics, first-class streaming, deadline/cancellation propagation, and a mature interceptor model for auth and observability. Native fit with protobuf, which C-1 already mandates at B1. |
| **T-4** | Maximum reachability: works through literally any HTTP-capable path, including corporate proxies that terminate and re-originate. Statelessness on the server makes horizontal scaling and restart trivial — there is no connection state to lose. Simplest possible failure model. |
| **T-5** | Purpose-built for exactly this problem shape: many intermittently-connected devices, topic fan-out, QoS 1 at-least-once with server-side offline session persistence, small keepalive frames tuned for battery. Mature on constrained hardware. |
| **T-6** | Every byte of framing is under our control; no HTTP semantics to fight; smallest possible per-message overhead; no risk of an HTTP/3 implementation quirk in the security path. |

### 5.2 Event substrate

| # | Advantages |
|---|---|
| **B-1** | The offset model is *exactly* `net_seq`: a durable, monotone, per-partition position with consumer-managed cursors, which is precisely the C2 abstraction. Proven at fleet scale, with strong retention, replay, and compaction tooling. Partition-per-`TwinNet` gives total order per scope and no cross-scope coupling — matching protocol.md §15.2 exactly. |
| **B-2** | Far lighter operationally than B-1; NATS JetStream in particular runs as a single small binary, supports durable consumers with cursors, and gives both queue and stream semantics. Good latency, good clustering story, and a credible self-hosted footprint. |
| **B-3** | **E-2 becomes structural rather than engineered.** `net_seq` is allocated in the same transaction as the mutation it describes, in the same store the C2 reader reads, so a returned `committed_at_net_seq` cannot be a position that does not exist or that the reader cannot reach. **E-1 falls out of the same property**: one writer per `TwinNet` log is one row-lock/leader, and admission linearizability is a transaction, not a protocol. No dual write anywhere. Because the fan-out bus carries only a monotone watermark (`TwinNet` T is at `net_seq` N), at-least-once on the bus is idempotent *by construction* — a watermark is a last-writer-wins register, so duplicates and reorders are free. Runs as one process with one store for T2/T3 (**RQ-11**); the bus degrades to in-process pub/sub with no semantic change. Backup and restore are one artifact because state and log are one artifact. |
| **B-4** | Simplest possible topology; no additional infrastructure; no retention policy; no replay tooling. Lowest end-to-end latency for a fan-out that succeeds. |
| **B-5** | Keeps the transactional guarantee (the outbox row commits with the state) while gaining the broker's fan-out, retention, and multi-consumer ecosystem. The standard industry answer to the dual-write problem. |

---

## 6. Disadvantages of Each Alternative

### 6.1 Transport

| # | Disadvantages |
|---|---|
| **T-1** | UDP/443 is blocked or throttled on a real and non-trivial fraction of enterprise and hotel networks, so the fallback ladder is **mandatory, not optional** — the design must pay for two transports. QUIC in userspace costs more CPU per byte than kernel TCP, which matters on router-class targets (R-21). HTTP/3 implementation maturity on the least-common platforms is the weakest link. |
| **T-2** | One TCP connection means head-of-line blocking: a 60 KiB event batch stalls an urgent revocation RPC behind it, which is the exact failure protocol.md §4.2 calls out. No connection migration — every roam drops the control channel and pays a full mTLS handshake. Multiplexing must be re-invented in the application, and a hand-rolled multiplexer is a new bug surface in an authenticated path. |
| **T-3** | gRPC's HTTP/2 binding inherits TCP head-of-line blocking and has no migration. Its streaming model has no *resumable cursor* — a broken stream is a broken stream, and resumption must be re-implemented above it anyway, so the framework's main advantage does not apply to C2. gRPC-over-QUIC is not a settled standard. Heavy dependency for a headless router build. |
| **T-4** | Long-polling burns a radio wake per poll interval, which collides head-on with **RQ-12** and reliability.md §6.6's coalesced-wake budget: it is the single worst option for mobile battery. Event latency is bounded below by the poll interval, so rendezvous `CALL` delivery (**RQ-7**) degrades from ~150 ms to seconds. It also cannot express a channel binding that spans the RPC and the event read, because they are different connections — breaking protocol.md A1's single-channel premise. |
| **T-5** | MQTT is a *broker* protocol: adopting it puts a broker on the device-facing surface, directly violating **C-6** and protocol.md §1's structural rule. Its QoS 1/2 and persistent-session machinery would tempt exactly the durable-ephemeral misclassification protocol.md §6.1 forbids (offline-persisted candidate sets). Its authorization model is topic ACLs, which is a poor fit for `TwinNet`-scoped, device-key-authenticated, Rule-B-signed statements. It duplicates the request/response layer badly. |
| **T-6** | Loses `GOAWAY`, standard proxy traversal, and every off-the-shelf load balancer and observability tool. A bespoke stream-numbering convention is a compatibility landmine across ADR-0014 version boundaries. Buys a few bytes per message in exchange for the entire operations ecosystem — a bad trade at the 1 event/s/`TwinNet` rate this channel actually runs at. |

### 6.2 Event substrate

| # | Disadvantages |
|---|---|
| **B-1** | **Fails RQ-11 outright**: asking a home-lab owner to operate Kafka or Redpanda to run their own `TwinNet` is not a viable self-hosted story, and T2/T3 are explicitly not an afterthought (architecture.md §7). It also **does not solve E-2 on its own** — state still lives in a database, so a dual write reappears and an outbox is needed anyway (which is B-5). Offsets are per-partition and change on repartition; retention and compaction semantics are subtle enough to be a footgun for a security-bearing log. |
| **B-2** | Better on footprint than B-1 but shares the fatal property: it is a **second** system of record beside the state store, so `committed_at_net_seq` requires a dual write and E-2 is engineered rather than structural. JetStream's own durability tier must then be reasoned about jointly with the database's, doubling the failure analysis for the one guarantee protocol.md calls its strongest (E-1). |
| **B-3** | Per-`TwinNet` write throughput is capped by a single writer — fine at the budgeted rate, but a hard ceiling. Cross-`TwinNet` scale is by sharding only, and a single very large `TwinNet` cannot be split. Requires building the cursor, retention, and compaction mechanics that B-1/B-2 ship for free. A relational store is a less natural fit for very long retention windows than a log-structured one. |
| **B-4** | No cursor, therefore **no resumable C2** and no gap-free resume — a device that was offline cannot learn what it missed except by full re-snapshot, which turns every reconnect into an O(state) fetch. A fan-out RPC that fails has no retry substrate, so a `DeviceRevoked` can simply be lost: a **security** failure by protocol.md §6's E3 test. Directly contradicts protocol.md §4's C2 definition. |
| **B-5** | Two systems of record to operate, back up, and reason about, with a relay process that is itself a failure domain and a source of duplicate publishes. It gives the broker's ecosystem, but the *only* consumer that matters here is the C2 stream service — so it pays full operational cost for an ecosystem with one user. And it still fails RQ-11: the self-hoster now runs a database *and* a broker *and* a relay. |

---

## 7. Security Implications

**S-1. The channel binding is what makes protocol.md §3 Rule A safe.** The control channel is
mutually authenticated to `DeviceIdentityKey` (ADR-0001 L-CONTROL). `Auth.channel_binding` is the
RFC 9266 `tls-exporter` value — a 32-byte exporter with label `EXPORTER-Channel-Binding`, empty
context, taken from the TLS 1.3 handshake underlying the QUIC connection (RFC 9001) or the direct
TLS 1.3 connection on the TCP rungs. This binds a channel-authenticated message to *this* connection,
so a compromised TLS terminator cannot lift a message onto another channel. A mismatch is
`CONTROL.CHANNEL_BINDING_MISMATCH` and MUST be treated as a security event, never a parse error.

**S-2. The bus carries no trust.** Because the internal fan-out bus carries only
`{twinnet_id, net_seq, revocation_epoch}` watermarks and never event bodies, an attacker who
fully controls the bus can **withhold** or **delay**, and can advance a watermark to cause a
spurious re-read. It cannot inject, forge, reorder-into-effect, or roll back any trust-bearing
statement, because every such statement is Rule-B signed (protocol.md §3) and every state document
is monotone-versioned with device-side rollback rejection (S-03, S-06, ADR-0008 N-3). This is the
concrete reason the substrate is allowed to be operationally simple: it is not in the trust path.

**S-3. Denial of freshness is the residual attack, and it is named.** A front-end that simply says
"nothing new" indefinitely delays a revocation. Three defences, in order of strength:
1. Every signed state document carries `not_after_ms`; expiry behaviour is a policy input whose
   shipped default is fail-closed (protocol.md §13.4, **I3**).
2. `HeartbeatAck.pending_net_seq` and `revocation_epoch` (protocol.md §9.2) let a device detect it
   is behind on a cheap C1 round trip without opening the event stream.
3. A periodic **`LogHead` freshness proof**: a small deterministic-CBOR COSE_Sign1 statement
   `{twinnet_id, net_seq, revocation_epoch, issued_at_ms, not_after_ms}` emitted on C2 every 60 s
   and on demand. A device that receives no valid, unexpired `LogHead` within 3 intervals MUST emit
   `CONTROL.FRESHNESS_PROOF_MISSING` and MUST begin treating its cached documents as approaching
   expiry.

   **Stated limitation, not hidden:** the `LogHead` key is online at the control plane, so a
   *compromised* control plane can forge freshness. It cannot forge trust — that requires the
   Owner authority (ADR-0007) — but it can lie about there being nothing to fetch. `LogHead`
   therefore defends against a partitioned, buggy, or partially-failed front-end and against a
   network attacker who drops events; it does **not** defend against a fully compromised control
   plane. That residual is exactly the semi-trusted boundary B3 in architecture.md §8 and belongs
   to [docs/threat-model.md](../threat-model.md) to analyse.

**S-4. Single publisher is enforced at the log, not by convention.** The `event` relation records
the publishing service principal per row; a row whose publisher does not match the protocol.md §7
table is rejected at write time, and a device that receives one rejects it with
`CONTROL.EVENT_WRONG_PUBLISHER`. **I8**/C-5 becomes a schema constraint rather than a code review.

**S-5. Amplification, reflection, and attach floods.** The rendezvous `CALL` path forwards a signed
blob to a peer identified by `DeviceId`, never to a caller-supplied address, so it cannot be used as
a reflector; mailbox capacity is per-target and small (§11.5), so it cannot be used as a memory
amplifier. At attach, cost asymmetry is bounded by QUIC address validation (RFC 9000 §8) and the
0-RTT prohibition (ADR-0001 R8), which removes the replayable-early-data vector entirely. The accept
limiter (§11.7) answers over-limit attaches with an application-level
`CONTROL.ADMISSION_DEFERRED{retry_after_ms}` rather than a TCP reset, because a reset is
indistinguishable from network failure and drives clients into the aggressive *interactive* backoff
regime, amplifying the very flood it was meant to shed.

---

## 8. Reliability Implications

**R-a. Control-channel failure is invisible to the data plane, by construction.** The control-channel
liveness signal MUST NOT emit `EV_PATH_SUSPECT`, `EV_PATH_DEAD`, `EV_LINK_DOWN`, or any event in
reliability.md §4.3, and MUST NOT consume a token from the `peer:<DeviceId>` retry-budget class
(reliability.md §6.3). Its only outputs are (a) a `HealthState` contribution at **device** scope and
(b) a `CONTROL.*` reason code. It maps to reliability.md §2.1's *"Rendezvous service failure"* and
*"Control-plane database failure"* rows and adds no new ones.

**R-b. Reuse, do not redefine, the retry policy.** The control channel uses the **infrastructure**
backoff regime (decorrelated jitter, base 500 ms, cap 30 s, reliability.md §6.1), the
`control-plane` retry-budget class, and the per-target circuit breaker verbatim. This ADR sets no
timer values that reliability.md already owns. Where a value below is not in reliability.md, it is
new and is named as such.

**R-c. Compaction sheds bytes, never facts.** When a device's C2 backlog exceeds the watermark
(§11.6), the server discards queued event *bodies* and sends an ordered, in-band
`StreamCompacted{up_to_net_seq}`. This preserves gap-freeness in the sense that matters — the
device is never silently skipped past anything; it is told exactly which position it lands on and
that it must re-read declaratively. RQ-6 is what makes this safe: every durable event is
independently applicable, and every state document is whole-state and monotone-versioned, so
"re-read the current documents" is always a sufficient recovery.

**R-d. Restart is a drain, not a kill.** Planned restarts use HTTP/3 `GOAWAY` carrying a drain
deadline; each client picks its reattach instant uniformly from `[0, deadline)` — the same herd-safe
pattern reliability.md T37 already uses for relay drain.

**R-e. Total control-plane outage.** Fully specified by architecture.md §4.4 and reliability.md §6.2;
this ADR confirms it and adds only the reattach discipline in §11.13. No established `Session`
transitions. Health surfaces `CONTROL.UNREACHABLE`, then `CONTROL.STALE_POLICY_IN_USE` once cached
documents pass half their TTL.

**R-f. Bus loss is a latency event, not a correctness event.** With the watermark bus entirely down,
C2 fan-out falls back to a per-connection poll of the log at 5 s (foreground) / 30 s (background):
delivery latency degrades from ~150 ms to seconds and nothing else changes. This is possible only
because the bus is not the system of record.

---

## 9. Performance Implications

| Quantity | Budget | Note |
|---|---|---|
| Control-channel attach (rung 1, warm DNS) | 1 RTT QUIC handshake + 1 RTT resume; p95 ≤ 400 ms | 0-RTT prohibited (ADR-0001 R8), so 1-RTT is the floor. |
| Ladder fall-through, worst case (all rungs) | ≤ 23 s to `CONTROL.UNREACHABLE` | Sum of §11.2 per-rung budgets. Establishment does not wait on it (§11.5). |
| Rendezvous `CALL`, peer attached | **p50 ≤ 150 ms, p95 ≤ 500 ms** ingress→egress | New budget, owned here. |
| Rendezvous `CALL`, peer detached, push wake | p50 ≈ 2 s, p95 unbounded (OS-controlled) | Initiator MUST NOT block on it (§11.5). |
| Durable event fan-out, `TwinNet` of ≤ 64 devices | p95 ≤ 800 ms commit→last attached device | Bus watermark + per-connection read. |
| Durable-event write rate, per `TwinNet` | **≤ 1/s sustained, burst 20** | Over-budget rejected with `CONTROL.EVENT_RATE_EXCEEDED`. Directly bounds the "denial of freshness by log flooding" attack in protocol.md §6.1. |
| E-1-class commit (revocation, membership, pairing) | quorum commit, p95 ≤ 50 ms in-region | Response withheld until quorum. |
| Non-E-1-class commit | region commit, p95 ≤ 10 ms | |
| C2 event body | ≤ 16 KiB inline; larger ⇒ notify-and-pull (§11.4) | Envelope cap is 64 KiB (C-2); the inline cap is lower so a single policy bundle cannot monopolise a stream. |
| Mobile radio cost | **zero additional wakes** | §11.10: foreground keepalive joins the existing coalesced window; background drops the connection entirely and relies on C3 + wake-time resume. |

The dominant performance fact is that this channel is **low-rate and latency-sensitive**, not
high-rate. At ≤ 1 durable event/s per `TwinNet`, throughput optimisation is irrelevant and every
byte spent on legibility, resumability, and observability is well spent. This is the reason T-6's
framing savings evaluate to nothing.

---

## 10. Operational Implications

**O-1. One artifact.** Because the log is a table in the state store (B-3), backup, restore,
point-in-time recovery, and schema migration are one procedure over one artifact. There is no
"the database and the broker disagree" state to diagnose.

**O-2. Restore has a mandatory step, and it is not optional.** Devices reject any `revocation_epoch`
or document `version` below their high-water mark (S-03, S-06, ADR-0008 N-3). Therefore **after
restoring a `TwinNet` from a backup, the operator MUST advance that `TwinNet`'s `revocation_epoch`
and every state-document `version` past the highest value ever issued before resuming service.**
A restore without this step presents as a fleet-wide, fail-closed, correctly-diagnosed refusal
(`CONTROL.STALE_POLICY_IN_USE`, then policy expiry) — which is the right outcome, but it must be
in the runbook, not discovered.

**O-3. T2/T3 single-process mode.** One binary, one embedded or single relational store, the bus
degraded to in-process pub/sub, the write lease trivially held. The single-node deployment loses
quorum durability for E-1-class writes; this is a **disclosed** reduction, surfaced to the Owner at
setup, not a silent one. Semantics — ordering, monotonicity, single-publisher, rollback rejection —
are identical in both modes.

**O-4. `TwinNet` is the unit of sharding, placement, and blast radius.** A `TwinNet` is homed to one
write leader; leaders are spread across nodes and regions. There is no cross-`TwinNet` transaction,
consistent with protocol.md §15.2.

**O-5. Observability.** Required control-plane metrics: attach rate and rung distribution, C2 lag
per `TwinNet` (commit→delivered), compaction rate, admission-deferral rate, mailbox drop rate,
`CALL` delivery latency histogram split by attached/push/undeliverable, and write-leader failover
count. Rung distribution is the leading indicator for RQ-2: a rising rung-2 share means the
network population changed under us (§14).

**O-6. Rollout.** `proto_version` is fixed for the life of a control connection (protocol.md §2), so
a version bump is a coordinated reconnect, not an in-place upgrade. Front-ends therefore MUST be
able to serve at least two adjacent `proto_version`s simultaneously during a rollout window whose
length is owned by [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md).

---

## 11. Decision

**Adopt T-1 for the device↔control-plane binding and B-3 for the durable event substrate.**

Concretely: **one long-lived QUIC + HTTP/3 connection per device, mutually authenticated to
`DeviceIdentityKey` per ADR-0001 L-CONTROL, carrying C1 as bidirectional streams and C2 as a
resumable server-initiated stream, with a four-rung TCP/TLS fallback ladder; behind it, a
per-`TwinNet` append-only event log stored transactionally alongside control-plane state, with
`net_seq` allocated inside the mutating transaction, fanned out by an internal bus that carries
only monotone watermarks and never payloads.** T-2, T-3, T-4, T-5, T-6, B-1, B-2, B-4, and B-5 are
rejected.

### 11.1 Normative rules

- **N-1** The control channel MUST be a single connection per `Device` carrying both C1 and C2.
  A second concurrent control connection for the same `DeviceIdentity` MUST cause the older one to
  be closed with `CONTROL.SUPERSEDED_BY_NEW_ATTACH`.
- **N-2** `Auth.channel_binding` MUST be the RFC 9266 `tls-exporter` value of the current control
  connection. A receiver MUST verify it against its own exporter and MUST reject a mismatch with
  `CONTROL.CHANNEL_BINDING_MISMATCH`.
- **N-3** `net_seq` MUST be allocated by a per-`TwinNet` monotone counter **inside the same
  transaction** that commits the state mutation it describes. A mutating C1 response MUST NOT return
  `committed_at_net_seq` before that transaction has committed (and, for E-1-class operations, before
  quorum commit).
- **N-4** There MUST be exactly one writer per `TwinNet` log at any instant, held by a lease. A
  service without the lease MUST refuse the write with `CONTROL.WRITE_LEADER_UNAVAILABLE` rather
  than writing optimistically.
- **N-5** Every durable event MUST be **independently applicable**: it MUST carry either the whole
  signed state document or a `{doc_type, version, digest}` reference sufficient to pull it, and it
  MUST NOT be expressed as a delta against a predecessor event.
- **N-6** The internal fan-out bus MUST carry only `{twinnet_id, net_seq, revocation_epoch}`
  watermarks. Publishing an event body onto the bus is prohibited.
- **N-7** No device-facing endpoint may expose a broker protocol. Devices address only the
  coordination API (**C-6**).
- **N-8** A C2 stream MAY be compacted under backpressure, and a compaction MUST be announced in
  band and in order as `StreamCompacted{up_to_net_seq}`. Silent omission is prohibited.
- **N-9** Rendezvous `CALL` and candidate-exchange payloads MUST NOT be written to the durable log,
  MUST NOT be replayed from a cursor, and MUST NOT survive their TTL. The rendezvous mailbox
  (§11.5) is a bounded, TTL'd jitter buffer and is not durability.
- **N-10** No message defined in this ADR may appear on any established-session code path
  (§11.8). Compliance is a build-time dependency assertion, not a review convention.
- **N-11** Every failure enumerated in §11.11 MUST be surfaced with its `CONTROL.*` code; a control
  channel that fails without a code is a defect (**I6**).

### 11.2 The control-channel transport ladder

Distinct from, and aligned in shape with, ADR-0004's data-plane ladder (testing-strategy A-17).
Rungs are tried in order; within rung 1 the two address families are raced per Happy Eyeballs v2
with a 250 ms IPv6 bias (protocol.md §4.1). Falling to any rung below 1 MUST be surfaced.

| Rung | Binding | Budget | Code emitted on entry | What is lost |
|---|---|---|---|---|
| 1 | **QUIC + HTTP/3, UDP:443**, mTLS 1.3 raw-public-key | 3 s | — | — |
| 2 | **HTTP/2 over TLS 1.3, TCP:443** | 5 s | `CONTROL.TRANSPORT_DEGRADED_TCP` | Connection migration; cross-stream HOL independence |
| 3 | **HTTP/1.1 long-poll over TLS 1.3, TCP:443** | 5 s | `CONTROL.TRANSPORT_DEGRADED_POLL` | Multiplexing; sub-second event latency |
| 4 | Rung 2 or 3 through the **OS-configured HTTP CONNECT proxy** | 10 s | `CONTROL.TRANSPORT_VIA_PROXY` | Everything above, plus proxy-imposed idle limits |
| — | exhausted | — | `CONTROL.UNREACHABLE` | The control plane, entirely — and **nothing else** (**I5**) |

Rung 2 keeps identical application semantics (same HTTP methods, same protobuf bodies, same cursor);
only the multiplexing substrate changes. Because rung 2 reintroduces TCP head-of-line blocking, the
compaction watermark on rung 2 is halved (§11.6) so a stalled event body cannot starve an urgent
revocation RPC. Rung 3 carries C1 as ordinary requests and C2 as a long-poll with a 25 s server-side
hold; it is the only rung that costs a radio wake per interval, and it is therefore prohibited as the
*background* binding on mobile — a device that can only reach rung 3 MUST drop the control channel in
background and rely on C3 wake (§11.10).

### 11.3 The durable event log

```
event(twinnet_id, net_seq, event_type, publisher_principal, body_or_ref,
      causality, committed_at)     PRIMARY KEY (twinnet_id, net_seq)
counter(twinnet_id, next_net_seq)  -- monotone; allocated in the mutating txn
```

- `net_seq` is dense and monotone per `twinnet_id`; there is no cross-`TwinNet` order (protocol.md §15.2).
- **Retention floor:** the greater of 30 days or 10^6 events per `TwinNet`. A cursor below the
  retained floor is answered with `CONTROL.CURSOR_TOO_OLD` and the device performs a full
  declarative re-snapshot — which is always correct because of N-5.
- `publisher_principal` is checked against the protocol.md §7 single-publisher table at write time
  (**S-4**).
- The write path for an E-1-class operation (`RevokeDeviceReq`, `RegisterDeviceReq`,
  `ConfirmPairingReq`, `PutPolicyReq`) MUST commit to a quorum before responding; all other writes
  commit in-region. If quorum is unreachable, the operation is refused with
  `CONTROL.QUORUM_UNAVAILABLE` — **never** committed locally with a promise to reconcile, because a
  forked revocation history is exactly what E-1 forbids.

**Monotonic reads across replica failover (E-1(c)).** `causality_token` (protocol.md §5.2, reserved
for precisely this) is a control-plane-sealed CBOR value
`{twinnet_id, min_net_seq, min_revocation_epoch, issued_at_ms}`. Devices echo it opaquely. A replica
serving any read MUST have applied at least `min_net_seq`; if it has not, it MUST wait up to 250 ms
and then refuse with `CONTROL.READ_TOO_STALE{retry_after_ms}`. A replica MUST NOT serve a read it
cannot satisfy. This is the mechanism that makes replica failover safe for revocation.

### 11.4 Push and pull for signed state documents — architecture.md A-07 **confirmed**

Both, with a size rule:

| Document size | C2 event carries | Device action |
|---|---|---|
| ≤ 16 KiB | The whole signed document inline | Verify signature, check version monotonicity, apply |
| > 16 KiB | `StateDocumentAvailable{doc_type, version, size, sha-256 digest}` | Pull via C1 `GetStateDocument(doc_type, version)`, verify digest **and** signature, apply |

Pull is always available independently of push: `GetPeersReq{since_net_seq}` (protocol.md §9.1) and
`GetStateDocument` are the snapshot half of the snapshot-plus-delta pattern. **A device MUST be able
to reach a correct state using pull alone**, with push serving only to reduce latency. This is what
discharges ADR-0008 §11.2's requirement that push notifications be treatable as hints triggering a
declarative re-read, and it is what makes compaction (§11.6) safe.

### 11.5 Rendezvous `CALL` delivery — networking.md A6 **confirmed**

A `CALL` (a `ConnectOffer` / `CandidateSet` blob, Rule-B signed and opaque to infrastructure) is
delivered by the first of these that applies:

```
  rendezvous ingress
        │
        ├─[1] target has a live control channel?  ──yes──▶ deliver on its C2 stream
        │            (lookup: ControlChannelAttachment, S-25)        p50 ≤150ms
        │
        ├─[2] target has a valid push token?      ──yes──▶ C3 wake hint (at-most-once)
        │                                                  + hold in mailbox
        │
        ├─[3] mailbox: TTL 30 s, capacity 8/target, drop-oldest
        │                                                  ▶ CONTROL.MAILBOX_OVERFLOW
        └─[4] none of the above                            ▶ CONTROL.CALL_UNDELIVERABLE
```

- **The mailbox is not durability.** Applying protocol.md §6's four checks: the content is
  re-derivable (E1 pass), it decays inside the 30 s TTL that the buffer itself enforces (E2 pass),
  missing it costs a fall back to `RELAYED`, never a wrong persistent state (E3 pass), and it is
  never replayed from a cursor so an old copy cannot resurface (E4 pass). It is a jitter buffer
  sized to the decay window, and N-9 forbids it from being anything else.
- **The initiator never blocks on it.** Per architecture.md A-10 and §6.2, relay-first
  establishment starts at *t=0* in parallel with direct racing. `CONTROL.PEER_NOT_ATTACHED` is
  informational (severity INFO, non-terminal) and MUST NOT gate an attempt — presence is never a
  gate (S-11).
- **Rendezvous also reports the observed source address** of an authenticated peer (networking.md
  A6(a)); that is a C1 response field on the same connection, so it inherits the channel binding.
- **Rendezvous is not required for an established session** (A6(c)): §11.8 proves it structurally.
- **Relay-assisted rendezvous fallback.** reliability.md §2.1 already promises that when the
  rendezvous service is unreachable, a `CALL` may be carried over the cached signed relay map. This
  ADR confirms that is sound — the blob is Rule-B signed and sealed, so a `Relay` is exactly as
  (un)trusted a courier as the rendezvous service — and records it as a required interface from
  ADR-0005/ADR-0006 in §11.9.

### 11.6 Backpressure, flow control, and fan-out

| Mechanism | Rule |
|---|---|
| **Transport flow control** | QUIC connection and stream windows (RFC 9000 §4). C2 gets a dedicated stream so an event backlog cannot consume the RPC window. |
| **C2 backlog watermark** | 256 KiB **or** 512 pending events per device, whichever first. Halved on rung 2 (128 KiB / 256 events) because TCP HOL blocking makes a backlog costlier. |
| **On watermark breach** | Discard queued event **bodies**, emit ordered `StreamCompacted{up_to_net_seq}` (N-8), advance the device's cursor to that position. Device re-reads declaratively (§11.4). Emit `CONTROL.STREAM_COMPACTED`. |
| **Per-`TwinNet` write budget** | ≤ 1 durable event/s sustained, burst 20. Over budget ⇒ `CONTROL.EVENT_RATE_EXCEEDED`, write refused. Bounds log-flooding denial-of-freshness (protocol.md §6.1). |
| **Fan-out cost** | O(N) stream writes per durable event for a `TwinNet` of N devices. At the budgeted rate this is bounded; compaction is the relief valve when a device is slow. |
| **Snapshot admission** | Snapshot/`GetStateDocument` requests are admission-controlled separately from attach, so a fleet-wide re-snapshot cannot starve new attaches. |
| **Priority** | `revocation_epoch` and `pending_net_seq` are served in the attach response itself, before any event body, so the security-critical fact arrives in RTT 1 regardless of queue depth. |

### 11.7 Connection storms and reconnect discipline

1. **Planned restart is a drain.** HTTP/3 `GOAWAY` (or an application close frame on the TCP rungs)
   carries `drain_deadline_ms`, default **120 s**. Each client picks its reattach instant uniformly
   from `[0, drain_deadline_ms)`. Same pattern as reliability.md T37.
2. **Unplanned restart uses the infrastructure backoff regime** — decorrelated jitter, base 500 ms,
   cap 30 s (reliability.md §6.1), which is already the right tool because control-plane failure is
   correlated across the fleet.
3. **Accept limiter.** Each front-end admits at a token-bucket rate (default 200 attaches/s
   sustained, burst 1000). Over-limit attaches receive an application-level
   `CONTROL.ADMISSION_DEFERRED{retry_after_ms}` and MUST honour `retry_after_ms`. A TCP reset or a
   silent drop is prohibited here (**S-6**).
4. **Resume, do not reload.** A device whose cursor is still within the retention floor MUST resume
   from it. Re-snapshotting on every reconnect is prohibited — it converts a reconnect storm into a
   bandwidth storm.

### 11.8 Structural proof of I5 compliance

**Claim.** No established-`Session` code path can require a control-plane call.

*Step 1 — architectural.* architecture.md §4.2 forbids the data plane from holding a reference to
any control-plane client; all control-plane influence is mediated by the local durable store (2.20).
This ADR adds nothing that crosses that edge: every message defined here terminates at the
control-plane client, which writes only to the store.

*Step 2 — enumerative.* Walking protocol.md §16, the messages a device exchanges with the control
plane are rows 1–15, 20, 25, 27, 29, 30, 33, 34. Classifying each by whether an **established**
`Session` needs it:

| Message class (protocol.md §16 rows) | Needed by an established `Session`? |
|---|---|
| Registration, pairing, revocation admission, key rotation (1–9) | **No** — preconditions of `DISCONNECTED`, not of a live session |
| Peer snapshot / delta (10, 11, 33, 34) | **No** — S-15 `Endpoint` cache and the local `TrustedPeer` set are pre-materialised (architecture.md §4.4.1) |
| Heartbeat / presence (13, 14) | **No** — presence is never a gate (S-11) |
| Push wake (15) | **No** — a hint only |
| Relay assignment **hint** (20) | **No** — advisory; the cached ranked set (S-09, ≥2 alternates) is what failover uses |
| Route / exit offers (25, 27) | **No** — TTL'd cached documents |
| Policy (29, 30) | **No** — cached signed bundle governs; TTL expiry changes what *new* operations are permitted, never tears down a session (architecture.md §4.4.3) |
| Relay **reservation** (21) | **No, and it is not on this channel at all** — see the naming note in §13 |

Every established-session activity — keepalive, rekey, path probing, path migration, relay
failover, in-tunnel LAN/exit negotiation, DNS of `TwinNet` names, policy evaluation — is carried on
C5/C6 or reads only the local store. None appears in the list above.

*Step 3 — mechanical, and this is the part that makes it testable.* The data-plane modules MUST NOT
link the control-plane client library. This is a dependency-graph assertion checkable in CI, and it
is what turns "we were careful" into "the build fails". It is the artifact
[docs/testing-strategy.md](../testing-strategy.md) A-13 and architecture.md §4.4.5 need, and it
complements — does not replace — the blackhole conformance test in §4.4.5.

*Step 4 — negative.* The control-channel liveness signal is wired to nothing in reliability.md §4.3
(**R-a**). A control-plane outage therefore cannot even *express* itself as a data-plane event.

### 11.9 Interfaces required from other ADRs

| Required from | Interface |
|---|---|
| [ADR-0009](ADR-0009-state-consistency.md) | (a) The C1 write path and the C2 read path MUST resolve to the **same** per-`TwinNet` log — no split shard (if ADR-0009 chooses otherwise, E-2 breaks and the `causality_token` read-your-writes carrier must be implemented instead); (b) single-writer lease per `TwinNet`; (c) monotonic-read token semantics as in §11.3; (d) the per-class behaviour on cached-document TTL expiry (ADR-0009 §11); (e) confirmation of new rows S-25, S-26, S-27 (§11.10). |
| [ADR-0003](ADR-0003-network-contract-schema-format.md) | `.proto` definitions for `StreamCompacted`, `StateDocumentAvailable`, `GetStateDocumentReq/Resp`, and `LogHead`; a `retry_after_ms` field on deferral responses; the `CONTROL.*` code strings in the reason-code enum. `LogHead` is a B2 deterministic-CBOR COSE_Sign1 statement. |
| [ADR-0007](ADR-0007-device-identity-and-pairing.md) | (a) `DeviceIdentityKey` usable as the mTLS client raw public key (already stated by ADR-0001); (b) provenance, scope, and rotation of the **online** `LogHead` signing key, which must be incapable of granting trust; (c) binding of a C3 push token to a `DeviceIdentity` so a token cannot be claimed by another device. |
| [ADR-0005](ADR-0005-relay-architecture.md) / [ADR-0006](ADR-0006-relay-discovery-and-failover.md) | (a) A `Relay` MUST be able to forward an opaque signed `CALL` blob when the rendezvous service is unreachable, as reliability.md §2.1 already promises; (b) confirmation that the device↔relay reservation channel is **not** this ADR's C1 and shares none of its availability. |
| [ADR-0004](ADR-0004-nat-traversal-strategy.md) | Confirmation that the control-channel ladder (§11.2) is separate from the data-plane ladder and that a device may be on different rungs for the two simultaneously. |
| [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) | `proto_version` is fixed for the life of a control connection; a version change forces a reconnect. The dual-version rollout window length (§O-6). |
| [ADR-0015](ADR-0015-observability-and-diagnostics.md) | Registration of the `CONTROL.*` codes in §11.11 into the machine-readable registry. |
| [ADR-0008](ADR-0008-idempotency.md) | Already satisfied in both directions: this ADR provides at-least-once with per-message identity (`message_id`) and claims no exactly-once (§11.12); push is a hint triggering declarative re-read (§11.4). |

### 11.10 New state-ownership rows required

`docs/architecture.md` §5 MUST add three rows. None introduces a second writer for an existing fact.

| # | State | Authoritative writer | Replicas / caches | Class | Durability | On conflict |
|---|---|---|---|---|---|---|
| **S-25** | `ControlChannelAttachment` — `device_id →` {front-end node, connection epoch, `expires_at`} | **Device-Presence Service (2.13)** | None; front-ends read | `EVENTUAL` | Non-durable, TTL 90 s | Highest connection epoch wins. **Never a gate** — a missing attachment MUST NOT suppress a `CALL` attempt or a connection attempt |
| **S-26** | Per-`TwinNet` event-log position (`net_seq` counter + retained event window) | **Control Plane (2.8)**, single writer per `TwinNet` under lease | Read replicas (monotonic-read constrained, §11.3) | `STRONG` at the writer, `MONOTONIC` at the edge | Durable, quorum-replicated for E-1-class writes | Single writer by construction; a lease-less write is refused, never reconciled |
| **S-27** | Device control-channel cursor (`net_seq` high-water + `causality_token`) | **Local `Device`** | None | `LOCAL` | Durable — required for gap-free resume across process restart | Local wins; a server-offered cursor below the local high-water MUST be rejected |

**Mobile note (RQ-12).** In foreground, the QUIC keepalive PING joins the existing coalesced wake
window (reliability.md §6.6) and adds **no** wake; the QUIC `max_idle_timeout` is 5 min with a PING
at 4 min. In background the control connection is **allowed to die**; re-attach on wake is cheaper
than holding it, and C3 push plus `HeartbeatAck.pending_net_seq` cover the latency. This is the same
honest conclusion reliability.md §6.6 reaches for NAT keepalives, applied to the control channel.

### 11.11 Reason codes contributed to the `CONTROL` namespace

Contributed to the machine-readable registry owned by
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2, which owns the `CONTROL` domain's
taxonomy and stability rules. Format follows the registry's own illustrative codes.

| `reason_code` | class | severity | terminal | user_actionable | Meaning |
|---|---|---|---|---|---|
| `CONTROL.UNREACHABLE` | TRANSIENT | WARN | false | false | Every ladder rung exhausted. Established sessions unaffected (**I5**) |
| `CONTROL.STALE_POLICY_IN_USE` | TRANSIENT | WARN | false | false | Operating from cached signed documents past half their TTL |
| `CONTROL.TRANSPORT_DEGRADED_TCP` | TRANSIENT | INFO | false | false | On rung 2; connection migration lost, roaming will drop the control channel |
| `CONTROL.TRANSPORT_DEGRADED_POLL` | TRANSIENT | WARN | false | false | On rung 3; event latency now bounded by the poll interval |
| `CONTROL.TRANSPORT_VIA_PROXY` | TRANSIENT | INFO | false | false | On rung 4, through the OS-configured HTTP proxy |
| `CONTROL.HANDSHAKE_REJECTED` | PERSISTENT | ERROR | false | true | Control-channel mTLS rejected (unknown/revoked device key, pin mismatch). Distinct from `CRYPTO.HANDSHAKE_REJECTED`, which is the tunnel |
| `CONTROL.CHANNEL_BINDING_MISMATCH` | FATAL | CRITICAL | true | false | `Auth.channel_binding` does not match the exporter — a **security event** |
| `CONTROL.ADMISSION_DEFERRED` | TRANSIENT | INFO | false | false | Accept limiter engaged; carries `retry_after_ms` |
| `CONTROL.SUPERSEDED_BY_NEW_ATTACH` | TRANSIENT | INFO | false | false | An older control connection for this identity was closed (N-1) |
| `CONTROL.STREAM_COMPACTED` | TRANSIENT | INFO | false | false | Server shed the C2 backlog; declarative re-read required |
| `CONTROL.CURSOR_TOO_OLD` | TRANSIENT | WARN | false | false | Cursor below the retention floor; full re-snapshot required |
| `CONTROL.READ_TOO_STALE` | TRANSIENT | WARN | false | false | Replica cannot satisfy the monotonic-read token; carries `retry_after_ms` |
| `CONTROL.EVENT_RATE_EXCEEDED` | PERSISTENT | ERROR | false | false | Per-`TwinNet` durable-write budget exceeded; write refused |
| `CONTROL.WRITE_LEADER_UNAVAILABLE` | TRANSIENT | WARN | false | false | `TwinNet` write leader failing over; mutations deferred |
| `CONTROL.QUORUM_UNAVAILABLE` | PERSISTENT | ERROR | false | true | An E-1-class mutation (revocation, membership, pairing, policy) cannot reach quorum and was refused, not partially applied |
| `CONTROL.PEER_NOT_ATTACHED` | TRANSIENT | INFO | false | false | `CALL` target has no live control channel. **Informational — never a gate** |
| `CONTROL.CALL_UNDELIVERABLE` | TRANSIENT | INFO | false | false | No live channel, no push token, mailbox expired or full |
| `CONTROL.MAILBOX_OVERFLOW` | TRANSIENT | INFO | false | false | Rendezvous mailbox drop-oldest fired for this target |
| `CONTROL.PUSH_TOKEN_INVALID` | PERSISTENT | WARN | false | true | Push gateway rejected the token; wake-hint delivery is unavailable for this device |
| `CONTROL.FRESHNESS_PROOF_MISSING` | TRANSIENT | WARN | false | false | No valid `LogHead` within 3 intervals; cached documents treated as approaching expiry |
| `CONTROL.EVENT_WRONG_PUBLISHER` | FATAL | CRITICAL | true | false | A durable event arrived from a principal that is not its sole publisher (protocol.md §7) — a **security event** |

### 11.12 Delivery semantics, per hop

| Hop | Delivery | Effect semantics | Mechanism |
|---|---|---|---|
| Device → control plane (C1) | **At-least-once** | **Exactly-once effect** | Client retry with a stable `idempotency_key` + `if_version` precondition (ADR-0008 N-2, N-4, N-5); `message_id` distinguishes a retry from a network duplicate (protocol.md §2) |
| Control plane → durable log | **Exactly-once** | Exactly-once | Same transaction as the state mutation (N-3). No dual write exists to be lost |
| Log → internal fan-out bus | **At-least-once** | Idempotent **by construction** | The bus carries only a monotone watermark, which is a last-writer-wins register: duplicates and reorders are no-ops (N-6) |
| Control plane → device (C2) | **At-least-once**, cursor-resumable, compaction-permitted | Idempotent | Every event independently applicable (N-5); monotone document versions rejected on regression (ADR-0008 N-3) |
| Push gateway → device (C3) | **At-most-once**, best-effort | None — non-authoritative | Wake hint only; correctness comes from C2 resume (protocol.md §5.3) |
| Rendezvous `CALL` (C4) | **At-most-once**, unordered | None required | Re-derivable, TTL'd, generation-numbered (protocol.md §10.4) |
| Device → collector (C7) | **At-least-once**, loss-tolerant | Idempotent by `(device_id, sample_epoch)` | Bounded ring buffer; drops reported as `INTERNAL.BUFFER_OVERFLOW` |

**No hop claims exactly-once delivery.** ADR-0008 §11.2 explicitly does not require it and explicitly
does not rely on it; protocol.md §5.3 states it is unachievable over an unreliable network. Exactly-once
*effect* is achieved by idempotency and monotone versions, which is the guarantee that actually matters.

### 11.13 Multi-region and availability shape

```
   device ──rung 1..4──▶ [ front-end fleet: stateless, anycast/GeoDNS, A + AAAA ]
                                │ holds C1/C2 connections; terminates TLS; holds no authority
                                ▼
                         [ coordination service ]
                                │ single writer lease per TwinNet
                                ▼
        ┌───────── region R1 (write leader for TwinNets {…}) ─────────┐
        │  state + event log, one transactional store, quorum-replicated│
        └──────────────────────┬───────────────────────────────────────┘
                async replication (monotonic-read constrained)
                               ▼
              region R2 read replicas / standby leader
```

- Front-ends are **stateless and hold no authority**; losing one costs its devices a reattach.
- A `TwinNet`'s write leader is held by lease; failover promotes a quorum-current replica. E-1-class
  writes are refused, never speculatively applied, while no leader holds the lease.
- Reads may be served by any replica that satisfies the caller's `causality_token` (§11.3).
- **Total outage:** established `Session`s are entirely unaffected (§11.8). New pairings, revocation
  admission, policy authorship, and first contact with a never-connected peer stall. Devices operate
  from cached signed documents, surface `CONTROL.UNREACHABLE` then `CONTROL.STALE_POLICY_IN_USE`,
  reconnect with decorrelated jitter, and on reattach fetch `revocation_epoch` first, resume the
  cursor second, and re-snapshot only if the cursor is stale.

### 11.14 Assumptions confirmed or overruled

| Assumption | Verdict | Note |
|---|---|---|
| **architecture.md A-07** — control-plane state reaches devices as signed, monotonically versioned, TTL'd documents, push **and** pull | **CONFIRMED** | §11.4. Refined, not overruled: documents > 16 KiB are pushed as a `StateDocumentAvailable` reference and pulled, and pull alone is always sufficient |
| **architecture.md A-12** — relay admission does not require a live control-plane call per reconnect | **CONFIRMED** from this side | No message defined here appears in the relay reservation or failover path (§11.8). The reservation channel is not C1 — see the naming defect reported in §11.9 |
| **protocol.md A1** — control channel mutually authenticated to `DeviceKey`, giving a TLS-exporter channel binding usable as `Auth.channel_binding` | **CONFIRMED** | RFC 9266 `tls-exporter`, 32 bytes, over the TLS 1.3 handshake underlying QUIC (RFC 9001) or the direct TLS on rungs 2–4. Normative as N-2 |
| **protocol.md A8** — `committed_at_net_seq` is a real monotone position in the same log the device reads (E-2) | **CONFIRMED**, and made structural | N-3: allocated in the mutating transaction, in the store the C2 reader reads. Notably this adds **no** storage constraint beyond E-1's single-writer-per-`TwinNet` log, so protocol.md §15.1's claim that E-1 "should be the only one that constrains the storage design" survives intact |
| **networking.md A6** — rendezvous can report an authenticated peer's observed source address **and** deliver a `CALL`, and is not required for an established session to survive | **CONFIRMED** on all three clauses | §11.5 (a, b), §11.8 (c) |
| **testing-strategy.md A-12** — control-plane messages are schema-defined, versioned, machine-validatable | **CONFIRMED** | Encoding from ADR-0003; the channel/delivery matrix in §11.12 and the ladder in §11.2 are contract-testable, and the reason-code table in §11.11 is a diffable artifact |
| **testing-strategy.md A-13** — established tunnels require no control-plane call for keepalive, rekey, path migration, or relay use | **CONFIRMED**, with a mechanical check | §11.8 step 3 supplies the dependency-graph assertion that makes P15 a test of the architecture rather than of an accident |

Nothing in this ADR overrules any assumption directed at it.

### 11.15 Requirements discharged

**R-11** (no single point of failure — stateless front-ends, per-`TwinNet` leases, outage is a
supported mode), **R-22** (named failures — §11.11), **R-18** (legible degradation — the ladder's
per-rung codes), **R-06** and **R-09** (unattended recovery — reuse of the reliability.md retry
machinery, resumable cursor), **R-08** (mobile background — §11.10), **R-23** (connectivity report
inputs — rung, cursor lag, `CALL` outcome), and **R-04** in part (versioned control contracts,
fixed per connection).

---

## 12. Why the Selected Option Won

1. **B-3 makes the two hardest guarantees structural instead of engineered.** E-2 is a dual-write
   problem; the only way to not have a dual-write problem is to not have two writes. Putting
   `net_seq` allocation inside the mutating transaction removes the failure mode rather than
   compensating for it, and E-1's single-writer-per-`TwinNet` requirement then costs one lease
   instead of a distributed-log configuration. B-1, B-2, and B-5 all end up building an outbox to
   reach the same place, at the price of a second system of record.

2. **RQ-11 is a hard filter and it eliminates the log brokers outright.** architecture.md §7 makes
   self-hosting a first-class topology. "Run Kafka" and "run JetStream plus Postgres plus a relay"
   are not answers an individual can act on. B-3 degrades to one process and one store with
   *identical semantics* — the deployment loses quorum durability and gains nothing else, and that
   loss is disclosed rather than silent.

3. **T-1 was already half-decided and the other half is forced.** ADR-0001 fixes L-CONTROL as QUIC +
   TLS 1.3 mutual raw-public-key. Choosing T-2, T-3, or T-5 would mean running a *second* control
   transport with a second authentication story. What remained genuinely open was the fallback
   ladder, and rung 2's choice of HTTP/2 over WebSocket is deliberate: it keeps one set of HTTP
   application semantics across all four rungs, so the server implements the channel once.

4. **Head-of-line independence is not a nicety here.** The C2 stream carries policy bundles up to
   16 KiB while C1 carries revocation admission. Under T-2 or T-3, a bundle in flight delays a
   revocation on the same TCP connection. Independent QUIC streams remove that coupling by
   construction, and where the ladder reintroduces it (rung 2) the compaction watermark is halved to
   bound the damage.

5. **T-4 loses on the requirement that is hardest to recover from later.** Long-poll's cost is a
   radio wake per interval, which collides with RQ-12 and reliability.md §6.6's entire mobile
   argument, and it cannot express a single channel binding spanning RPC and events, which would
   force protocol.md §3 Rule A to be rewritten as per-message signing everywhere. It survives only
   as rung 3, where it belongs: a reachability floor, not a design.

6. **T-5 is disqualified structurally, not on merit.** MQTT is a good protocol for a shape TwinVPN
   deliberately does not have. protocol.md §1 states that a `Device` never speaks to a broker,
   because that keeps the attack surface, the authorization model, and the mobile wakeup story
   singular. Adopting MQTT means adopting topic ACLs as an authorization model beside device-key
   mTLS and Rule-B signatures — three authorization systems where the design specifies one.

7. **The watermark-only bus is the small idea that pays repeatedly.** It makes at-least-once bus
   delivery idempotent for free, keeps trust-bearing content out of a component that is easy to
   compromise, permits the bus to be entirely absent in single-node mode, and reduces total bus
   failure from a correctness event to a latency event.

8. **B-4 fails the security test in protocol.md §6.** Without a cursor there is no gap-free resume,
   so a `DeviceRevoked` delivered to an offline device is simply lost. That fails check E3 —
   persistently wrong state — which is the exact defect the ephemeral/durable classification exists
   to prevent.

---

## 13. Known Tradeoffs

1. **Per-`TwinNet` write throughput has a single-writer ceiling.** Far above the 1 event/s budget,
   but a `TwinNet` that ever needs high durable-write throughput cannot be scaled by adding writers —
   only by splitting, which the model does not support. Accepted because a durable event describes a
   trust or policy change, and those are rare by nature; if they are not, something has been
   misclassified against protocol.md §6 (see §14).
2. **Building cursor, retention, and compaction mechanics that B-1/B-2 ship for free.** Real
   engineering cost, paid to keep one system of record and a self-hostable footprint.
3. **Rungs 2–4 lose QUIC connection migration**, so on hostile networks the control channel drops on
   every roam and pays a full mTLS handshake to reattach. Bounded by **I5**: the data plane does not
   notice. Surfaced as `CONTROL.TRANSPORT_DEGRADED_TCP`.
4. **Compaction costs bandwidth exactly when bandwidth is worst.** A device on a bad link that falls
   behind is told to re-snapshot. The alternative — unbounded server-side buffering — trades a
   bandwidth spike for a memory-exhaustion vector, which is worse.
5. **`CALL` delivery to a fully detached peer is best-effort.** First contact between two
   never-connected peers who are both detached is not possible. reliability.md §2.1 already states
   this residual risk; this ADR does not remove it, and the relay-assisted rendezvous fallback
   narrows but does not close it.
6. **The single-writer lease is a small consensus dependency** — an extra moving part for the
   multi-node operator, and degenerate (therefore free) for the single-node one.
7. **The `LogHead` freshness proof does not defend against a compromised control plane** (§S-3). It
   is deliberately scoped to partition, bug, and network-drop cases, and the limit is stated rather
   than papered over.
8. **Single-node self-hosted deployments have no quorum**, so E-1-class writes are durable only to
   one node. Disclosed at setup; the alternative — refusing to run single-node — would delete T2/T3.
9. **Rung 3 is prohibited as a background binding on mobile**, so a device that can only reach rung 3
   is not reachable in background except via C3 push. Honest consequence of the battery budget.

---

## 14. Revisit Conditions

Each is a measurement that falsifies a premise of this decision.

1. **Rung-1 reachability.** If measured QUIC/UDP:443 attach success at rung 1 falls below **90 %** of
   attach attempts across the fleet over a 30-day window, the ladder's default ordering must be
   re-evaluated and rung 2 considered as the primary binding for the affected network classes.
2. **Rung-2 modal share.** If rung 2 becomes the modal rung for more than **20 %** of devices, the
   halved compaction watermark and the loss of connection migration stop being edge cases and the
   TCP path needs first-class treatment (including an application-level migration token).
3. **Durable-write rate.** If more than **1 %** of `TwinNet`s sustain more than 1 durable event/s over
   a 7-day window, something ephemeral has been misclassified as durable. Audit against protocol.md
   §6 **before** raising the budget — raising the budget first is how the presence-as-durable failure
   in §6.1 happens.
4. **Compaction frequency.** If `CONTROL.STREAM_COMPACTED` fires on more than **0.5 %** of C2
   attachments in a 7-day window, compaction has become a normal path rather than an emergency one,
   and either the watermark or the fan-out design is wrong.
5. **Fan-out latency.** If p95 commit→last-attached-device latency for a `TwinNet` of ≥ 64 devices
   exceeds **2 s**, the per-connection read path must be replaced with a shared, pre-serialised
   fan-out buffer.
6. **`TwinNet` size.** If the p99 `TwinNet` exceeds **256 devices**, the O(N) fan-out and the
   single-writer ceiling must both be re-derived at the new size.
7. **`CALL` delivery.** If `CONTROL.CALL_UNDELIVERABLE` exceeds **5 %** of `CALL` attempts, the
   attach model (S-25) or the push-token lifecycle is not working and a persistent-attach mode for
   `LANGateway`/`ExitNode` roles must be considered.
8. **Storage split.** If [ADR-0009](ADR-0009-state-consistency.md) adopts a design in which the C1
   write path and the C2 read path resolve to different shards, **E-2 breaks immediately** and the
   `causality_token` read-your-writes carrier (protocol.md §5.2) must be implemented before that
   change ships.
9. **Self-hosted share.** If single-node self-hosted deployments exceed **30 %** of `TwinNet`s, the
   quorum requirement for E-1-class writes is meaningless for most of the fleet and a formally
   specified single-node degraded mode for revocation admission must be written rather than left
   implicit.
10. **Restart herd.** If a full front-end restart produces a reattach peak exceeding **3×** the
    steady-state attach rate despite the drain and the accept limiter, the drain deadline and the
    limiter parameters are wrong and must be re-derived from measured fleet size.
