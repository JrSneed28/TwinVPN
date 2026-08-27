# `twinvpn-rendezvous`

The C4 ephemeral signaling meeting point: where two devices that cannot yet
reach each other exchange `ConnectOffer` / `ConnectAnswer` / `CandidateSet`
blobs, **without the control plane being in the path**.

**Owner:** `rendezvous-connectivity`
([`docs/implementation/ownership.md`](../../docs/implementation/ownership.md) §2).

**This is not the NAT traversal implementation.** Candidate gathering, racing,
validation and the [ADR-0004](../../docs/adr/ADR-0004-nat-traversal-strategy.md)
ladder live in `core/crates/twinvpn-path`, owned by `core-dataplane`
(ADR-0018 §11.2 row 2.10). Nothing here decides a path, ranks a candidate, or
schedules a punch. This is the untrusted courier those clients use.

---

## 1. Why this is a service and not an RPC

[`docs/protocol.md`](../../docs/protocol.md) §10.1 states it directly:
connection negotiation "is **not** a durable event, and it is **not** a
control-plane RPC, because the coordination service must not be in the critical
path of every reconnect (**I5**: a control-plane blip must not prevent
re-establishing a session for which both keys and last-known endpoints are
already cached)."

Everything below follows from that one sentence plus the four properties in
`src/lib.rs`: **B3 is the boundary**, **at-most-once and never durable**,
**forward verbatim**, and **learn as little as possible**.

---

## 2. Build, test, run

```bash
source build/toolchain/env.sh
cd services
cargo build -p twinvpn-rendezvous
cargo test  -p twinvpn-rendezvous
```

The gate, exactly as it is run before reporting:

```bash
cd services
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd .. && make test-contracts        # must remain 35801 checks, 0 failures
```

Locally, with no container runtime:

```bash
TWINVPN_RZ_LISTEN_TCP=127.0.0.1:8444 \
TWINVPN_RZ_TLS_CERT_PATH=./infra/secrets/rendezvous/tls.crt \
TWINVPN_RZ_TLS_KEY_PATH=./infra/secrets/rendezvous/tls.key \
TWINVPN_LIMITS_PATH=./contracts/registry/limits.json \
TWINVPN_REASON_CODES_PATH=./contracts/registry/reason_codes.json \
cargo run -p twinvpn-rendezvous
```

Under compose the admin port is published on `127.0.0.1:19002`:

```bash
curl -s http://127.0.0.1:19002/readyz  | jq
curl -s http://127.0.0.1:19002/healthz | jq
curl -s http://127.0.0.1:19002/metrics | grep twinvpn_rendezvous
```

The runtime image has **no shell**, so `docker compose exec rendezvous sh` will
not work; probe from the published admin port or from a container that has one.

---

## 3. Environment configuration

Names are `infra/env.example`'s and `docker-compose.yml`'s. The **frozen** column
means `infra/README.md` §4.3 marks the value frozen; this service reads it anyway
and **fails startup if it disagrees with the compiled-in registry**, because a
frozen value that is merely ignored is one nobody notices being wrong.

| Variable | Type | Default | Frozen | If absent / if wrong |
|---|---|---|---|---|
| `TWINVPN_RZ_LISTEN_TCP` | socket addr | `[::]:443` | no | `[::]:443`, dual stack |
| `TWINVPN_RZ_LISTEN_QUIC` | socket addr | `[::]:443` | no | parsed and validated; **not bound** (§9) |
| `TWINVPN_RZ_TLS_CERT_PATH` | path | `/run/secrets/rendezvous/tls.crt` | no | **startup fails** — the file must exist and be readable |
| `TWINVPN_RZ_TLS_KEY_PATH` | path | `/run/secrets/rendezvous/tls.key` | no | **startup fails** |
| `TWINVPN_RZ_CONTROL_PLANE_URL` | URL | `https://control-plane:443` | no | recorded; **never called on the `CALL` path or the readiness path** (I5) |
| `TWINVPN_RZ_MAILBOX_TTL_MS` | u64 ms | `30000` | **yes** | any other value is a startup failure |
| `TWINVPN_RZ_MAILBOX_CAPACITY_PER_TARGET` | u64 | `8` | **yes** | as above |
| `TWINVPN_RZ_MAILBOX_OVERFLOW_POLICY` | `drop-oldest` | `drop-oldest` | **yes** | as above |
| `TWINVPN_RZ_CALL_DELIVERY_P50_BUDGET_MS` | u64 ms | `150` | no | ADR-0002 §9's budget |
| `TWINVPN_RZ_C4_MAX_BYTES` | u64 | `1200` | **yes** | **a startup failure.** Widening the hostile boundary from a compose file is the one misconfiguration this service refuses loudest |
| `TWINVPN_RZ_C4_MAX_DEPTH` | u64 | `4` | **yes** | as above |
| `TWINVPN_RZ_MAX_CANDIDATES_PER_SET` | u64 | `32` | **yes** | as above |
| `TWINVPN_RZ_CANDIDATE_EXPIRY_MS` | u64 ms | `30000` | **yes** | as above |

### 3.1 Added by this domain (`infra/README.md` §4.3 does not list them)

Every one is a resource ceiling. They are reported to the integration lead in §8;
each has a working default, so compose needs no change.

| Variable | Type | Default | What it bounds |
|---|---|---|---|
| `TWINVPN_RZ_MAX_MAILBOX_TARGETS` | u64 | `8192` | distinct targets holding a mailbox |
| `TWINVPN_RZ_MAX_MAILBOX_BYTES` | u64 | `33554432` | process-wide retained mailbox bytes |
| `TWINVPN_RZ_MAX_ATTACHMENTS` | u64 | `8192` | concurrently attached devices |
| `TWINVPN_RZ_SOURCE_RATE_PER_SEC` | f64 | `20` | sustained `CALL`s from one source address |
| `TWINVPN_RZ_SOURCE_BURST` | u64 | `40` | burst depth for the above |
| `TWINVPN_RZ_FRAME_READ_TIMEOUT_MS` | u64 ms | `5000` | how long a **partially received** frame may take to finish — the slowloris bound |
| `TWINVPN_RZ_MAX_CONNECTIONS` | u64 | `16384` | concurrently served connections |

Everything in `twinvpn-service-common`'s README §3.2 also applies.

---

## 4. The wire

A fixed-layout header, then an opaque body:

```
magic "TVR1" (4) │ version (1) │ opcode (1) │ body_len (2, big-endian)
```

| Opcode | Direction | Body |
|---|---|---|
| `0x01 ATTACH` | client → service | `device_id` (exactly 32 bytes) |
| `0x02 CALL` | client → service | `target device_id` (32) ‖ opaque C4 payload (1‥1200) |
| `0x81 ACK` | service → client | an encoded `twinvpn.v1.ErrorEnvelope`, or empty for success |
| `0x82 DELIVER` | service → client | the `CALL` payload, **byte for byte as it arrived** |
| `0x83 REFLEXIVE` | service → client | an encoded `twinvpn.v1.Endpoint` — the observed source address |

Three things about this table are load-bearing.

**A `CALL` names a `DeviceId`, never an address.** ADR-0002 S-5: the path
"forwards a signed blob to a peer identified by `DeviceId`, never to a
caller-supplied address, so it cannot be used as a reflector." There is no field
here in which a caller could put an address.

**`DELIVER` carries no sender.** The blob is Rule-B signed and already names its
signer, so a sender field would tell this courier a pairing it does not need —
the same instinct that removed `peer_key_id` from the relay binding (CF-7, A11).

**The `CALL` payload is never decoded.** It is validated as *shape* (≤ 1200
bytes, nesting ≤ 4) by `Verbatim::from_received` and then forwarded unchanged.
See §6.

`ACK` is not sent for a malformed frame. `contracts/docs/trust-boundaries.md` §2:
"drop, emit `PROTO.MALFORMED_MESSAGE`, **NO state change, NO answer**. Answering
would confirm the target exists." The connection is closed and a metric is
incremented; the sender learns nothing.

**There is no frozen message for this envelope**, and that is a contract gap, not
a choice — see §8.

---

## 5. The `CALL` ladder and the resource envelope

ADR-0002 §11.5:

```
[1] target has a live control channel  ──▶ deliver on it            p50 ≤ 150 ms
[2] target has a valid push token      ──▶ C3 wake hint      NOT IMPLEMENTED (§9)
[3] mailbox: TTL 30 s, capacity 8/target, drop-oldest ──▶ CONTROL.MAILBOX_OVERFLOW
[4] none of the above                                ──▶ CONTROL.CALL_UNDELIVERABLE
```

The whole mutable state of this process is three bounded, TTL'd, in-memory
tables. There is no store, no path, no connection string and no `persist` flag —
the durable option **does not exist** rather than defaulting off, because
`contracts/docs/contract-matrix.md` §1 category 4 makes treating an ephemeral
message as durable a cost, privacy **and** denial-of-freshness failure.

| Bound | Default | Authority |
|---|---|---|
| C4 envelope | 1200 B | `limits.json envelope.c4_max_bytes` |
| Parser depth | 4 | `limits.json envelope.c4_max_depth` |
| Mailbox TTL | 30 s | ADR-0002 §11.5 |
| Mailbox depth per target | 8, drop-oldest | ADR-0002 §11.5 |
| Distinct mailbox targets | 8192 | this domain |
| Total retained mailbox bytes | 32 MiB | this domain |
| Attachments | 8192, TTL 90 s | S-25 for the TTL |
| Per-source rate | 20/s, burst 40 | this domain |
| Concurrent connections | 16384 | this domain |
| Partial-frame deadline | 5 s | this domain |

An unauthenticated attacker cannot make this process allocate: the declared
length is checked before any buffer exists, the payload cap is checked before the
octets are retained, and every table evicts oldest-first rather than growing.

---

## 6. Forward-verbatim (finding W-4)

`prost` 0.13 **drops unknown protobuf fields on decode and cannot re-emit them**,
measured by `core-foundation` and recorded as CF-2. A forwarder that decodes and
re-encodes therefore silently deletes every field a future peer added.

This is the clearest case of that finding in the system, and it is closed by
**never decoding at all**: a `CALL` body is a
[`twinvpn_service_common::Verbatim`] from the moment it arrives to the moment it
leaves, `Router::route_call` takes and returns one, and there is no `encode` on
the path.

`tests/call_flow.rs::a_call_to_an_attached_peer_is_forwarded_byte_for_byte` sends
a payload with a field number this build has no name for and asserts the octets
arrive unchanged. `tests/frame_proptest.rs` asserts the same as a property over
every payload length from 2 to 1200.

---

## 7. What this service can still observe about users

Stated plainly, because a rendezvous is a metadata chokepoint and ADR-0004 §7
already concedes that "the rendezvous service learns which `Device`s are
attempting to connect and their reflexive addresses."

**It can observe, transiently:**

1. **That a device with a given `device_id` attached, and from which source
   address** — for as long as the connection lives. This is inherent: delivery
   rung [1] is "hand the bytes to that device's socket".
2. **That some caller wants to reach a given target `device_id`** — the `CALL`
   header. It cannot see who is calling unless the caller also attached on the
   same connection, and the two are not linked by anything this process stores.
3. **A source IP address**, for rate limiting. The **address only, never the
   port**, held in a capped table evicted oldest-first, and never rendered.
4. **Sizes and timing** — how large a `CALL` is and when it arrived.

**It cannot observe:**

- The contents of any `CALL`. The payload is opaque octets; the shape check
  (record sequence, depth ≤ 4) reads structure, never values, and no field is
  ever decoded.
- Any candidate, endpoint, port or NAT class a peer gathered. Those live inside
  the signed blob.
- Which two devices are talking, from a `CALL` alone. A `CALL` names one target;
  the initiator is inside the signed body this process does not open.

**What reaches a log or a metric:** neither of the above. A `device_id` is
converted by `src/label.rs` into a **per-process sequential pseudonym** —
`peer-1`, `peer-2` — assigned on first sight. That is a function of arrival order
and nothing else: no key to leak, no inversion over the population, no
correlation across restarts or across instances. It is the same instinct as the
relay's per-operator-per-day `sub` and 10-minute-bucketed `pair_tag`
(`trust-boundaries.md` §5). Source addresses are never labelled, logged, or put
in a metric — `metrics::Label`'s five-value allowlist has no dimension that could
hold one.

**The residual, honestly:** an operator who captured this process's *memory*, or
who ran a packet capture on its listener, could correlate attachments to source
addresses in real time. Nothing in a log or a metric enables that after the fact,
and nothing is retained past the TTLs. Reducing it further needs the transport
to hide the source address, which no rendezvous design can do for itself.

**No device-enumeration oracle.** A fabricated `device_id` and a real detached one
take the identical path and get the identical answer, because this process holds
no device registry to distinguish them — asking the control plane per `CALL` is
what I5 forbids. `tests/…::a_fabricated_target_is_indistinguishable_from_a_detached_real_one`.

---

## 8. Findings for the integration lead

| # | Kind | Finding |
|---|---|---|
| **RZ-1** | **contract gap** | **No frozen message expresses the rendezvous `CALL` envelope.** ADR-0002 §11.5 and S-5 require a `CALL` to name its target *by `DeviceId`* — the whole anti-reflection control — but `ConnectOffer`, `ConnectAnswer` and `CandidateSet` carry no recipient and `MessageMetadata` has `sender_id` with no counterpart. `contracts/` is frozen, so this service carries the target in a **fixed-layout binary header** (§4) rather than inventing a protobuf message. That is also the shape ADR-0003 §11 B4 prefers on a hostile path. **Needs a ruling:** either a `CallEnvelope` is added to `signaling.proto` under the §3 amendment procedure, or the fixed-layout framing is blessed and documented. |
| **RZ-2** | **architecture conflict** | **`infra/README.md` §5 gives this service `ReadinessPolicy::AnyDependency` with "the control-plane authorization endpoint reachable".** Implemented as **`NoControlPlaneCalls`** instead. A rendezvous that reports NOT READY on a control-plane blip is removed from service, which stops peers exchanging candidates, which puts the control plane back in the critical path of every reconnect — exactly what protocol.md §10.1 and I5 forbid. `architecture.md` §2.9's "Depends on: Control Plane for authorization" is about authorizing a *caller*, not about liveness. **Needs the lead's ruling**, and `infra/README.md` §5 amended if this reading is accepted. |
| **RZ-3** | **contract gap** | **`errors.proto` has no `COMPONENT_RENDEZVOUS_SERVICE`.** It has `COMPONENT_RENDEZVOUS_CLIENT` (7), the device-side component, and `COMPONENT_COORDINATION_SERVICE` (21). This service reports 21 — the closest truthful answer, since `architecture.md` §2.9 places the rendezvous in the control plane — rather than claiming to be the client. The registry is append-only, so adding one breaks nothing. |
| **RZ-4** | gap | **Rung [2], the C3 push wake, is not implemented** (§9). No push credential store exists and a push gateway is an untrusted third party. A detached device's `CALL` falls straight to the mailbox. This costs latency, never correctness — the initiator never blocks on delivery (ADR-0002 §11.5). |
| **RZ-5** | note | **Seven `TWINVPN_RZ_*` resource ceilings added** (§3.1), all with defaults, none in `infra/README.md` §4.3. A pre-authentication surface with no connection bound, no per-source rate bound and no partial-frame deadline is a descriptor- and memory-exhaustion primitive; these are not optional. Should be added to `infra/README.md` §4.3 when infrastructure next touches it. |
| **RZ-6** | note | **`services/Cargo.lock` changed mechanically** — `proptest` 1.11 as a **dev**-dependency of this crate and `presence`, plus its 13 transitive dev-only entries (`autocfg`, `bit-set`, `bit-vec`, `fastrand`, `linux-raw-sys`, `num-traits`, `quick-error`, `rand_xorshift`, `rustix`, `rusty-fork`, `tempfile`, `unarray`, `wait-timeout`). No runtime dependency moved and no version of an existing dependency changed. `ownership.md` §6 makes the B3 parser's "never panics, never allocates unboundedly" a **property**, and a property needs a property test. The lockfile is the integration lead's to reconcile. |

---

## 9. Known limitations

Stated here rather than discovered later.

1. **TLS is not terminated and QUIC is not bound.** `TWINVPN_RZ_LISTEN_TCP` is
   bound and speaks the §4 framing in the clear.
   `TWINVPN_RZ_LISTEN_QUIC`, `_TLS_CERT_PATH` and `_TLS_KEY_PATH` are parsed and
   the files are required to exist, but no handshake happens: `rustls` is a
   workspace dependency and `tokio-rustls` is not, and adding a dependency is the
   integration lead's call. **Consequence:** there is no channel authentication in
   this wave, so an `ATTACH` is an unauthenticated claim and a device could
   attach as another device's `device_id` and receive its `CALL`s. The blobs are
   Rule-B signed end to end, so the attacker learns ciphertext it cannot open and
   cannot answer — but it can deny delivery. **This must be closed before the
   service is exposed anywhere.**
2. **No container has been built or run.** Docker is absent from this host
   (`infra/README.md` §9). Everything in §2 involving `docker compose` is
   unexercised. The tests run a **real** listener on loopback, over both IPv4 and
   IPv6, and drive real sockets.
3. **Rung [2] (C3 push wake) is absent** — RZ-4.
4. **`Verbatim::from_received` applies a *shape* check to the payload**, not only
   a size check: `twinvpn_schema::depth::check` refuses octets that are not a
   well-formed protobuf record sequence. That is the depth guard doing its job
   pre-parse, and it is conservative in the safe direction, but it does mean a
   future C4 body that is *not* protobuf-shaped would be refused. Recorded
   because "the rendezvous never looks at the payload" is true of its *values*
   and not quite true of its *framing*.
5. **The 1200-byte C4 cap is enforced; the IPv6 path MTU it is derived from is
   not measured.** On TCP the envelope never fragments, so the cap here is a
   protocol bound rather than a path property.
6. **No relay-assisted fallback.** ADR-0002 §11.5 records that a `Relay` may
   carry a `CALL` when the rendezvous is unreachable. That is the relay's side
   and belongs to `relay-plane`; nothing here prevents it.

---

## 10. Debugging

| Symptom | First thing to check |
|---|---|
| startup fails naming `TWINVPN_RZ_C4_MAX_BYTES` | something set a frozen bound. The message names the value and the expectation |
| startup fails naming a TLS path | the file does not exist or is not readable |
| `ConfigError::RegistryMismatch` | the mounted `contracts/registry` is not the one this binary was built against |
| `/readyz` says `no_probes` | a wiring defect; reported red rather than green |
| `twinvpn_rendezvous_frames_rejected_total` climbing | someone is sending malformed C4. The `WARN` line carries the registered code and the cap that fired — never the bytes |
| a `CALL` never arrives | is the target attached? `twinvpn_rendezvous_attached_devices`. If not it is in the mailbox for 30 s and then gone, by design |
| `CONTROL.MAILBOX_OVERFLOW` | one target is being called faster than it attaches. Drop-oldest fired; the newest `CALL` survived |
| `CONTROL.ADMISSION_DEFERRED` in a client's logs | that source exceeded its bucket. It carries `retry_after_ms` and must honour it |
| a forwarded `CALL` lost a field | something decoded and re-encoded it. There is no such path in this crate; check the client (§6) |

```bash
RUST_LOG=twinvpn_rendezvous=debug cargo test -p twinvpn-rendezvous -- --nocapture
```

`DEBUG` and `TRACE` auto-revert after `TWINVPN_LOG_LEVEL_EXPIRY_MS`
(ADR-0015 §11.5). Nothing at any level renders a payload, a candidate, an
endpoint or a `device_id`.
