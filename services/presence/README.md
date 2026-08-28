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
with **no database client at all** — see `Cargo.toml`'s own comment and §9.

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

### 2.1 What each test file is for

| File | Subject |
|---|---|
| `tests/presence_flow.rs` | the heartbeat → `PresenceUpdated` path, S-11, LWW under reordering |
| `tests/hostile_input.rs` | every malformed shape refused without a state change |
| `tests/never_a_gate.rs` | the structural half of §1 — the connection path does not link this crate |
| `tests/tls_binding.rs` | the channel, and the binding that makes S-11 enforceable |
| `tests/hint_under_adversity.rs` | the behavioural half of §1: duplicate heartbeats, expired records reading as *unknown* rather than *offline*, publishers that vanish and return, restart, a table at its ceiling, an unreachable dependency, and a subscriber that never reads |

---

## 3. Environment configuration

| Variable | Type | Default | Required | If absent |
|---|---|---|---|---|
| `TWINVPN_PRESENCE_LISTEN_TCP` | socket addr | `[::]:443` | no | `[::]:443`, dual stack |
| `TWINVPN_PRESENCE_LISTEN_QUIC` | socket addr | `[::]:443` | no | parsed; **not bound** (§10) |
| `TWINVPN_PRESENCE_TLS_CERT_PATH` | path | `/run/secrets/presence/tls.crt` | yes (file) | **startup fails** if unreadable. **Not used** — RFC 7250 carries no certificate |
| `TWINVPN_PRESENCE_TLS_KEY_PATH` | path | `/run/secrets/presence/tls.key` | yes (file) | **startup fails.** The server's whole identity; a key that will not parse stops the process rather than degrading to plaintext |
| `TWINVPN_PRESENCE_CONTROL_PLANE_URL` | URL | `https://control-plane:443` | no | recorded; never called on the publish or readiness path |
| `TWINVPN_PRESENCE_HEARTBEAT_INTERVAL_MS` | u64 ms | `30000` | no | returned as `HeartbeatAck.suggested_interval_ms`; **advisory** — a device coalesces it into an existing wake window rather than adding a wake (ADR-0002 §11.10) |
| `TWINVPN_PRESENCE_RECORD_TTL_MS` | u64 ms | `180000` | no | how long a record is served, **and** the ceiling on how far ahead a device may place its own `expires_at_ms` |
| `TWINVPN_DATABASE_URL` | secret | none | no | **validated when present and then deliberately unused** — §9. A `CHANGE-ME` value still fails at startup |

### 3.1 Added by this domain

| Variable | Type | Default | What it bounds |
|---|---|---|---|
| `TWINVPN_PRESENCE_MAX_DEVICES` | u64 | `65536` | device records held at once |
| `TWINVPN_PRESENCE_FRAME_READ_TIMEOUT_MS` | u64 ms | `5000` | how long a **partially received** frame may take to finish |
| `TWINVPN_PRESENCE_MAX_CONNECTIONS` | u64 | `16384` | concurrently served connections |
| `TWINVPN_PRESENCE_BINDING_TTL_MS` | u64 ms | `600000` | how long a `device_id`↔channel binding outlives its connection |
| `TWINVPN_PRESENCE_MAX_BINDINGS` | u64 | `16384` | concurrently held bindings |

Everything in `twinvpn-service-common`'s README §3.2 also applies.

---

## 4. Authentication, and why S-11 needs it

**TLS 1.3, mutual RFC 7250 raw public keys, client authentication mandatory,
0-RTT prohibited** — ADR-0001 §7.2's L-CONTROL, from
[`twinvpn_service_common::tls`](../twinvpn-service-common/src/tls/mod.rs). This
was `src/tls.rs` here and an identical `src/tls.rs` in the rendezvous until the
shared crate absorbed both (RZ-8); see `services/rendezvous/README.md` §4.1 for
the reasoning, which has not changed.

The reason it matters *here* is S-11. `presence.proto`: "a device may assert
presence **only for itself**. A `Presence` naming another `device_id` is
rejected." Without an authenticated channel that rule could only be checked
against another unauthenticated claim — a `BIND` saying "I am D" compared with a
`Presence` saying "I am D". Both were the attacker's to choose, so the check
proved nothing.

Now `BIND` is answerable to the key that completed the handshake
([`twinvpn_service_common::binding`](../twinvpn-service-common/src/binding.rs)),
with the same one-to-one invariant the rendezvous uses:

> **A `device_id` belongs to at most one channel identity, and a channel
> identity speaks for at most one `device_id`, for the life of the binding.**

A mismatch is **`CONTROL.CHANNEL_BINDING_MISMATCH`** — FATAL, CRITICAL, "a
security event, never a parse error" (`trust-boundaries.md` §4) — and the answer
names no `device_id`, structurally: the frozen registry declares no evidence
fields for that code and the `twinvpn-types` builder drops an undeclared key, so
no call can attach the contested identity even by mistake. A **full table** is a
different refusal, `CONTROL.ADMISSION_DEFERRED`, because the identity is not
contested — the server is.

The S-11 check then runs *on top* of that: a channel legitimately bound to A
still may not assert for B, and that is still `CONTROL.EVENT_WRONG_PUBLISHER`.
Authentication did not replace S-11; it made it mean something.

**A connection releases exactly what it claimed.** This service previously
released by channel alone, unconditionally at teardown — so a *refused*
connection sharing a key with a live one dropped that connection's hold, and one
key could then publish presence for two identities. S-11 forbids exactly that.
`release` now takes the subject and is called only on the accepted path;
`tests/tls_binding.rs::a_refused_sibling_connection_cannot_release_a_live_connections_hold`
is the guard, over real sockets. See RZ-11 in `services/rendezvous/README.md` §9
for why neither service's unit tests could see it.

**A repeated `BIND` is a refresh, not a second hold.** `claim` increments a
holder count that teardown decrements exactly once, and a *held* entry is neither
swept at its TTL nor evictable for capacity — so `BIND(D)` sent *n* times on one
socket left *n−1* holds nothing could reclaim. One authenticated client could
fill the table with unevictable entries, after which every other device's first
`BIND` is refused for capacity — and under S-11 a device that cannot bind cannot
speak for itself at all. A re-claim of the subject this connection already holds
therefore releases first. RZ-13 in `services/rendezvous/README.md` §9, which
carried the identical defect on `ATTACH`.

**The binding is derived-preferred, not merely channel-pinned** — RZ-10, closed.
A `BIND` whose TLS key derives to the claimed `device_id`
(`contracts/docs/identifiers.md` §2) is **proven**, and a proven claim takes the
subject from a merely pinned holder. That matters more here than anywhere: S-11
says the device is authoritative for its **own** presence, and a binding that
merely pins the first claimant makes *the first claimant* authoritative until the
TTL lapses — an attacker who binds `D` before the real `D` ever does publishes
`D`'s presence, which is precisely the override S-11 forbids. Now the rightful
device takes its name back.

A device that has **rotated** its identity key presents a generation-N key that
derives to something other than its `device_id` (ADR-0007 §11) and so cannot
prove; it still binds by first claim, because derived-**only** would lock it out
permanently and this service holds no `IdentitySuccession` chain and must not
fetch one per connection (**I5**). See `services/rendezvous/README.md` §4.3 for
the full rule and the table.

---

## 5. The wire

```
 offset  size  field
      0     4  magic      = 0x54 0x56 0x50 0x31  ("TVP1")
      4     1  version    = 0x01
      5     1  opcode     (table below)
      6     4  body_len   unsigned, big-endian, <= 65536
     10     n  body       exactly body_len octets
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

## 6. Reordering, LWW, and the one refinement of the written rule

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

## 7. What is retained, exactly

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

## 8. What this service can still observe about users

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

## 9. Findings for the integration lead

| # | Kind | Finding |
|---|---|---|
| **PR-1** | **architecture conflict** | **`docker-compose.yml` requires `TWINVPN_PRESENCE_DATABASE_URL` and `infra/README.md` §5 gives this service readiness "Postgres reachable".** This service has **no database client**: a presence record is ephemeral by contract and a durable one is the privacy defect protocol.md §6.1 names. The variable is loaded and validated (so an unedited `CHANGE-ME` still fails at startup) and then dropped, with a `WARN` at startup saying it is unused. **Needs a ruling:** either the compose requirement and the readiness row are dropped, or someone states what durable presence data is intended and why §6.1 does not apply. |
| **PR-2** | **architecture conflict** | **`architecture.md` §2.13 says this service tracks "last-known `Endpoint`s".** `presence.proto` deliberately carries **no endpoint** — "this message deliberately carries NO endpoint, NO IP address, and NO coarse location". The frozen contract wins (`ownership.md` §3) and no endpoint is stored. §2.13's phrase looks like a prose survival from before the field was removed, in the same class as W-3. **Needs §2.13 amended.** |
| **PR-3** | ruling taken locally | **LWW by `expires_at_ms` rather than by arrival** (§6). protocol.md §9.2 says "by arrival at the aggregator" and, one line later, that there is no ordering guarantee and that the absolute instant exists for exactly this. Arrival-order LWW makes a reordered pair settle wrong, which is the failure `PresenceUpdated`-as-one-event exists to prevent. Implemented as the reordering-tolerant reading; **§9.2's wording should be tightened** so the next implementer does not choose the other one. |
| **PR-4** | note | **`HeartbeatAck.revocation_epoch` and `pending_net_seq` are returned as 0.** Both are the control plane's to answer (ADR-0002 §11.4) and this service must not call it on this path (I5). `pending_net_seq` is described as "the main battery lever in the protocol", so a device that wants it must get it from the control plane's own C1 heartbeat, not from here. Worth a line in protocol.md §9.2 saying which endpoint answers it, since the same `Heartbeat`/`HeartbeatAck` pair is used in both places. |
| **PR-5** | note | **`ReadinessPolicy::NoControlPlaneCalls`**, where `infra/README.md` §5 says `AnyDependency`. Same reasoning as the rendezvous's RZ-2: this service holds nothing durable, so there is no dependency whose absence could make its answer wrong, and reporting NOT READY on someone else's outage converts a latency degradation into a capability one. |
| **PR-6** | note | **Five `TWINVPN_PRESENCE_*` ceilings added** (§3.1), all with defaults. |
| **PR-7** | **closed by the integration lead** | `src/tls.rs` and `src/binding.rs` duplicated the rendezvous's exactly; both now live in `twinvpn-service-common` and this crate's copies are deleted. Absorbing them found the `release()` defect this service carried — RZ-11 in `services/rendezvous/README.md` §9. || **PR-8** | **defect this domain shipped, now fixed** | **A repeated `BIND` on one connection pinned a binding-table entry for the life of the process** — the identical defect the rendezvous carried on `ATTACH`, recorded as RZ-13 in `services/rendezvous/README.md` §9. Fixed in both, in the services rather than in the shared crate: a re-claim of the subject this connection already holds releases first. Worth noting *why* it appeared in both — the two services were written from the same design, so a defect in that design is a defect in both copies, which is the same lesson RZ-8 and RZ-11 taught from the other direction. |
| **PR-9** | note | **The binding table is now swept on this service's own timer**, beside the presence table, rather than only as a side effect of the next `BIND`. `docs/protocol.md` §6.1 is explicit about what infrastructure holding device history amounts to; a lapsed binding held because no unrelated traffic arrived is retention by inaction. |
| **PR-10** | note | **`DerivedPreferred` adopted** (§4), closing RZ-10 here as well. Two counters follow it: `twinvpn_presence_binding_displacements_total` (a device took its own name back from an impostor — worth an alert, not an error, since nothing was refused) and `twinvpn_presence_binding_unprovable_keys_total` (claims on keys no `device_id` derives from, which fall back to pinning — a rotation campaign explains a rise, and nothing else should). |

---

## 10. Known limitations

1. **QUIC is not bound** — same as the rendezvous's limitation 1, same cause.
   TLS 1.3 with mutual raw public keys is terminated; QUIC is a binding to add.
2. **First-contact impersonation is closed for every device that has not rotated
   its identity key, and open for those that have** — §4, and RZ-10 in the
   rendezvous README for the full rule. A rotated device cannot derive, so it
   cannot displace an impostor that bound its `device_id` first, and that
   impostor publishes presence for it until the binding lapses. Presence is a
   hint and never a gate (§1), so the blast radius is a wrong hint rather than a
   wrong decision — but under S-11 it is still the wrong device speaking.
3. **No container has been built or run.** Docker is absent from this host. The
   tests run a real TLS 1.3 listener on loopback over IPv4 and IPv6.
4. **No persistence, deliberately** (PR-1). A restart empties the table; every
   device re-asserts within one heartbeat interval, which is the designed
   recovery and the reason presence is classified ephemeral.
5. **No `TwinNet` scoping on the fan-out.** A subscriber receives every
   `PresenceUpdated` this process sees, and the `twinnet_id` is echoed from the
   publisher's own metadata. The channel is now authenticated, so a subscriber
   *has* an identity to scope against — but deciding which `TwinNet`s a
   `device_id` belongs to is control-plane state this service does not hold and
   must not fetch per connection. **This is now a real gap rather than a blocked
   one, and it is the next thing to close.** Recorded rather than half-built.
6. **`suggested_interval_ms` is the configured constant**, not a computed
   back-off. Adapting it to load is a real feature; a fabricated adaptive value
   would be worse than an honest constant.

---

## 11. Debugging

| Symptom | First thing to check |
|---|---|
| startup warns `unused_dependency` | `TWINVPN_DATABASE_URL` is set. It is deliberately unused — PR-1 |
| `twinvpn_presence_binding_displacements_total` climbing | a device proved a `device_id` an impostor was holding and took it back (§4). Under S-11 each one is a device recovering the right to speak for itself. **Worth an alert; not an error** |
| `twinvpn_presence_binding_unprovable_keys_total` climbing | `BIND`s are arriving on keys no `device_id` derives from and falling back to first-claim pinning. A rotation campaign explains it; without one, something is presenting a key shape the conversion does not handle |
| a heartbeat is acked but nothing is stored | it was superseded, already expired, or claimed an expiry past `RECORD_TTL_MS`. `twinvpn_presence_heartbeats_ignored_total`. A loss is not an error (§6) |
| `CONTROL.EVENT_WRONG_PUBLISHER` | a connection asserted presence for a `device_id` it did not bind. FATAL/CRITICAL — a **security event**, not a parse error |
| `twinvpn_presence_frames_rejected_total` climbing | malformed C1. The `WARN` carries the registered code and the cap that fired |
| a subscriber missed updates | it fell behind the broadcast buffer. By design: presence is at-most-once and permitted to be lost |
| `/readyz` red | the table exceeded its ceiling. Everything else about this service is local |
| a client cannot connect | it must offer TLS 1.3, present an RFC 7250 raw public key, and pin this server's key. `twinvpn_presence_tls_handshakes_refused_total` |
| `twinvpn_presence_binding_mismatches_total` climbing | a `device_id` is being claimed on a channel not entitled to it — a security event, not a client bug |

```bash
RUST_LOG=twinvpn_presence=debug cargo test -p twinvpn-presence -- --nocapture
```
