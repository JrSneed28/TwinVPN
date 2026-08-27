# `twinvpn-presence`

The device-presence aggregator. A **hint service, never an authority**
([`docs/architecture.md`](../../docs/architecture.md) §2.13).

**Owner:** `rendezvous-connectivity`
([`docs/implementation/ownership.md`](../../docs/implementation/ownership.md) §2).

---

## 1. The three sentences that determine everything else

**S-11 / [`presence.proto`](../../contracts/proto/twinvpn/v1/presence.proto):**
presence is published *by the device, for itself only*. This service aggregates;
it is not the authority, and it may never override a device's assertion about
itself.

**`architecture.md` §2.13:** it **"MUST NOT gate connection attempts —
'presence says offline' MUST NOT prevent an attempt"**, and its unavailability
"degrades reconnect **latency**, not reconnect **capability**".

**`docs/protocol.md` §6.1:** a durable presence log is "a permanent movement and
IP-address history of the `Owner`, held by infrastructure. Infrastructure that
cannot read your traffic but can reconstruct where you were every hour for two
years has not achieved zero knowledge."

So: ephemeral, TTL'd, `EVENTUAL`, reordering-tolerant, bounded, never a gate, and
with **no database client at all** — see `Cargo.toml`'s own comment and §8.

---

## 2. Build, test, run

```bash
source build/toolchain/env.sh
cd services
cargo build -p twinvpn-presence
cargo test  -p twinvpn-presence
```

```bash
TWINVPN_PRESENCE_LISTEN_TCP=127.0.0.1:8445 \
TWINVPN_PRESENCE_TLS_CERT_PATH=./infra/secrets/presence/tls.crt \
TWINVPN_PRESENCE_TLS_KEY_PATH=./infra/secrets/presence/tls.key \
TWINVPN_LIMITS_PATH=./contracts/registry/limits.json \
TWINVPN_REASON_CODES_PATH=./contracts/registry/reason_codes.json \
cargo run -p twinvpn-presence
```

Under compose the admin port is published on `127.0.0.1:19003`:

```bash
curl -s http://127.0.0.1:19003/readyz  | jq
curl -s http://127.0.0.1:19003/metrics | grep twinvpn_presence
```

---

## 3. Environment configuration

| Variable | Type | Default | Required | If absent |
|---|---|---|---|---|
| `TWINVPN_PRESENCE_LISTEN_TCP` | socket addr | `[::]:443` | no | `[::]:443`, dual stack |
| `TWINVPN_PRESENCE_LISTEN_QUIC` | socket addr | `[::]:443` | no | parsed; **not bound** (§9) |
| `TWINVPN_PRESENCE_TLS_CERT_PATH` | path | `/run/secrets/presence/tls.crt` | yes (file) | **startup fails** |
| `TWINVPN_PRESENCE_TLS_KEY_PATH` | path | `/run/secrets/presence/tls.key` | yes (file) | **startup fails** |
| `TWINVPN_PRESENCE_CONTROL_PLANE_URL` | URL | `https://control-plane:443` | no | recorded; never called on the publish or readiness path |
| `TWINVPN_PRESENCE_HEARTBEAT_INTERVAL_MS` | u64 ms | `30000` | no | returned as `HeartbeatAck.suggested_interval_ms`; **advisory** — a device coalesces it into an existing wake window rather than adding a wake (ADR-0002 §11.10) |
| `TWINVPN_PRESENCE_RECORD_TTL_MS` | u64 ms | `180000` | no | how long a record is served, **and** the ceiling on how far ahead a device may place its own `expires_at_ms` |
| `TWINVPN_DATABASE_URL` | secret | none | no | **validated when present and then deliberately unused** — §8. A `CHANGE-ME` value still fails at startup |

### 3.1 Added by this domain

| Variable | Type | Default | What it bounds |
|---|---|---|---|
| `TWINVPN_PRESENCE_MAX_DEVICES` | u64 | `65536` | device records held at once |
| `TWINVPN_PRESENCE_FRAME_READ_TIMEOUT_MS` | u64 ms | `5000` | how long a **partially received** frame may take to finish |
| `TWINVPN_PRESENCE_MAX_CONNECTIONS` | u64 | `16384` | concurrently served connections |

Everything in `twinvpn-service-common`'s README §3.2 also applies.

---

## 4. The wire

```
magic "TVP1" (4) │ version (1) │ opcode (1) │ body_len (4, big-endian)
```

Presence is **C1**, not C4 (`docs/protocol.md` §16 row 13), so the caps are
`envelope.c1_c2_c7_max_bytes` (65536) and `c1_c2_c7_max_depth` (8) — still
checked before any allocation proportional to a declared length.

| Opcode | Direction | Body |
|---|---|---|
| `0x01 BIND` | client → service | `device_id` (exactly 32 bytes) — who this connection speaks for |
| `0x02 PUBLISH` | client → service | `twinvpn.v1.PublishPresenceRequest` |
| `0x03 SUBSCRIBE` | client → service | empty |
| `0x81 ACK` | service → client | `twinvpn.v1.PublishPresenceResponse` |
| `0x82 EVENT` | service → client | `twinvpn.v1.ControlEvent` carrying `PresenceUpdated` |

**One event shape, and no other.** `control_events.proto` on `PresenceUpdated`:
"what an application might call `PeerOnline` and `PeerOffline` … are not separate
event types, they are values of `PresenceState`. Modelling them as distinct
events would imply an ordering guarantee that presence explicitly does not have,
and a reordered Online/Offline pair would leave the wrong terminal value." This
service publishes `PresenceUpdated` with `durability = EPHEMERAL`, `net_seq = 0`
(ADR-0002 N-9) and `publisher = ORIGINATING_DEVICE` (the device owns the fact;
this process transports it).

---

## 5. Reordering, LWW, and the one refinement of the written rule

`docs/protocol.md` §9.2 says "last-writer-wins **by arrival at the aggregator**",
and in the same row says there is **no ordering guarantee** and that this is "why
presence carries an absolute `expires_at_ms` rather than a relative delta".

Taken literally, arrival-order LWW lets a delayed `OFFLINE` overwrite a newer
`ONLINE` — the exact outcome the absolute instant exists to prevent. So this
store resolves by **`expires_at_ms`, with arrival order as the tiebreak**:

- the assertion the device made later carries the later expiry and wins;
- an assertion already expired on arrival is **dropped, not stored**;
- an assertion claiming an expiry beyond `RECORD_TTL_MS` is **refused, never
  clamped** — clamping silently rewrites a device's own assertion, and accepting
  would let a device pin itself `ONLINE` for ever;
- arrival-order LWW is recovered exactly when the two agree, which is the ordered
  case.

A refused or superseded heartbeat is answered **without an error**. ADR-0008 N-9
says presence is "PERMITTED TO BE LOST", and an error would teach a client to
retry a heartbeat — the one thing it must not do. `tests/presence_flow.rs`
covers both halves.

Subscribers use a bounded broadcast buffer and **lose updates rather than
disconnecting or back-pressuring a publisher**, for the same reason.

---

## 6. What is retained, exactly

Per device: a `PresenceState`, a `Reachability` (`has_v4`, `has_v6`,
`nat64_present`, a coarse `NetworkClass`), an absolute `expires_at_ms`, a local
monotonic expiry, and an arrival counter. That is the whole record.

**No endpoint. No IP address. No coarse location. No previous value. No history.**
`presence.proto`: "`Reachability` says what families work, not where the device
is. Endpoints reach peers through the SIGNED `CandidateSet` on C4, not through a
presence record warehoused by infrastructure."
`tests/never_a_gate.rs::a_presence_record_carries_no_address` asserts the
rendering.

`nat64_present` is carried because ADR-0010 and `protocol.md` §10.4 require
NAT64/DNS64 detection to be reported "so an IPv6-only peer can be reached" —
IPv6-only cellular with NAT64 is a first-class case here, not an edge case.

---

## 7. What this service can still observe about users

**It can observe, transiently:**

1. **That a device with a given `device_id` is online, idle, suspending or
   offline, and until when.** That is the whole point of the service, and it is
   the sensitive part: an aggregate of these over time *would be* a movement
   history. It is bounded by the TTL and there is no history to accumulate.
2. **What address families a device currently has**, and whether it is on Wi-Fi,
   cellular, ethernet or other. `NETWORK_CLASS_CELLULAR` is a weak location
   signal (it says "moving", not "where"); it is in the frozen contract and is
   what makes a connection attempt order sensibly.
3. **A source address at the transport**, for the life of a connection. It is
   never stored, never logged, never labelled.

**It cannot observe:** a device's address, its candidates, its peers, who it
connects to, or any traffic. None of those are in the record and none reach this
process.

**What reaches a log or a metric:** a `device_id` never does. `src/ingress.rs`'s
`Labeller` converts it to a **per-process sequential pseudonym** — `peer-1`,
`peer-2` — assigned on first sight, a function of arrival order and nothing else.
That is also what goes into the `observed_publisher` evidence field of an S-11
violation, so a security event names a pseudonym rather than an identifier.

**The residual, honestly:** a compromised presence aggregator learns the
online/offline pattern of every device in every `TwinNet` that publishes to it,
in real time, for as long as it is compromised. It cannot learn where they are.
Retention is the TTL and nothing survives a restart, so the *historical* half of
the movement-history risk is closed structurally; the *real-time* half is
inherent to a presence service existing at all, and a user who does not want it
can simply not publish — presence is never a gate, so a device that publishes
nothing still connects.

---

## 8. Findings for the integration lead

| # | Kind | Finding |
|---|---|---|
| **PR-1** | **architecture conflict** | **`docker-compose.yml` requires `TWINVPN_PRESENCE_DATABASE_URL` and `infra/README.md` §5 gives this service readiness "Postgres reachable".** This service has **no database client**: a presence record is ephemeral by contract and a durable one is the privacy defect protocol.md §6.1 names. The variable is loaded and validated (so an unedited `CHANGE-ME` still fails at startup) and then dropped, with a `WARN` at startup saying it is unused. **Needs a ruling:** either the compose requirement and the readiness row are dropped, or someone states what durable presence data is intended and why §6.1 does not apply. |
| **PR-2** | **architecture conflict** | **`architecture.md` §2.13 says this service tracks "last-known `Endpoint`s".** `presence.proto` deliberately carries **no endpoint** — "this message deliberately carries NO endpoint, NO IP address, and NO coarse location". The frozen contract wins (`ownership.md` §3) and no endpoint is stored. §2.13's phrase looks like a prose survival from before the field was removed, in the same class as W-3. **Needs §2.13 amended.** |
| **PR-3** | ruling taken locally | **LWW by `expires_at_ms` rather than by arrival** (§5). protocol.md §9.2 says "by arrival at the aggregator" and, one line later, that there is no ordering guarantee and that the absolute instant exists for exactly this. Arrival-order LWW makes a reordered pair settle wrong, which is the failure `PresenceUpdated`-as-one-event exists to prevent. Implemented as the reordering-tolerant reading; **§9.2's wording should be tightened** so the next implementer does not choose the other one. |
| **PR-4** | note | **`HeartbeatAck.revocation_epoch` and `pending_net_seq` are returned as 0.** Both are the control plane's to answer (ADR-0002 §11.4) and this service must not call it on this path (I5). `pending_net_seq` is described as "the main battery lever in the protocol", so a device that wants it must get it from the control plane's own C1 heartbeat, not from here. Worth a line in protocol.md §9.2 saying which endpoint answers it, since the same `Heartbeat`/`HeartbeatAck` pair is used in both places. |
| **PR-5** | note | **`ReadinessPolicy::NoControlPlaneCalls`**, where `infra/README.md` §5 says `AnyDependency`. Same reasoning as the rendezvous's RZ-2: this service holds nothing durable, so there is no dependency whose absence could make its answer wrong, and reporting NOT READY on someone else's outage converts a latency degradation into a capability one. |
| **PR-6** | note | **Three `TWINVPN_PRESENCE_*` ceilings added** (§3.1), all with defaults. |

---

## 9. Known limitations

1. **TLS is not terminated and QUIC is not bound** — identical to the
   rendezvous's limitation 1, same cause, same consequence. Without channel
   authentication a `BIND` is an unauthenticated claim, so a caller could bind
   another device's `device_id` and publish presence for it. The S-11 check
   compares the assertion against the *bound* identity, so it catches a mismatch
   within one connection but cannot verify the binding itself. **This must be
   closed before the service is exposed.**
2. **No container has been built or run.** Docker is absent from this host. The
   tests run a real listener on loopback over IPv4 and IPv6.
3. **No persistence, deliberately** (PR-1). A restart empties the table; every
   device re-asserts within one heartbeat interval, which is the designed
   recovery and the reason presence is classified ephemeral.
4. **No `TwinNet` scoping on the fan-out.** A subscriber receives every
   `PresenceUpdated` this process sees, and the `twinnet_id` is echoed from the
   publisher's own metadata. Real scoping needs an authenticated channel to
   decide what a subscriber is entitled to, which limitation 1 blocks. Recorded
   rather than half-built.
5. **`suggested_interval_ms` is the configured constant**, not a computed
   back-off. Adapting it to load is a real feature; a fabricated adaptive value
   would be worse than an honest constant.

---

## 10. Debugging

| Symptom | First thing to check |
|---|---|
| startup warns `unused_dependency` | `TWINVPN_DATABASE_URL` is set. It is deliberately unused — PR-1 |
| a heartbeat is acked but nothing is stored | it was superseded, already expired, or claimed an expiry past `RECORD_TTL_MS`. `twinvpn_presence_heartbeats_ignored_total`. A loss is not an error (§5) |
| `CONTROL.EVENT_WRONG_PUBLISHER` | a connection asserted presence for a `device_id` it did not bind. FATAL/CRITICAL — a **security event**, not a parse error |
| `twinvpn_presence_frames_rejected_total` climbing | malformed C1. The `WARN` carries the registered code and the cap that fired |
| a subscriber missed updates | it fell behind the broadcast buffer. By design: presence is at-most-once and permitted to be lost |
| `/readyz` red | the table exceeded its ceiling. Everything else about this service is local |

```bash
RUST_LOG=twinvpn_presence=debug cargo test -p twinvpn-presence -- --nocapture
```
