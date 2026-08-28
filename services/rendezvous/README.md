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
| `TWINVPN_RZ_LISTEN_QUIC` | socket addr | `[::]:443` | no | parsed and validated; **not bound** (§10) |
| `TWINVPN_RZ_TLS_CERT_PATH` | path | `/run/secrets/rendezvous/tls.crt` | no | **startup fails** if unreadable. **Not used** — RFC 7250 carries no certificate; the key *is* the identity (§4.1) |
| `TWINVPN_RZ_TLS_KEY_PATH` | path | `/run/secrets/rendezvous/tls.key` | no | **startup fails.** This is the server's whole identity. A key that will not parse stops the process; there is no path to a plaintext listener |
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

Every one is a resource ceiling. They are reported to the integration lead in §9;
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
| `TWINVPN_RZ_BINDING_TTL_MS` | u64 ms | `600000` | how long a `device_id`↔channel binding outlives its connection (§4.2) |
| `TWINVPN_RZ_MAX_BINDINGS` | u64 | `16384` | concurrently held bindings |

Everything in `twinvpn-service-common`'s README §3.2 also applies.

---

## 4. Authentication

### 4.1 The channel

**TLS 1.3, mutual RFC 7250 raw public keys, client authentication mandatory,
0-RTT prohibited.** ADR-0001 §7.2's L-CONTROL block, implemented in
[`twinvpn_service_common::tls`](../twinvpn-service-common/src/tls/mod.rs) —
this domain's module until the shared crate absorbed it (RZ-8, now closed):

```
Transport     : TLS 1.3 over TCP (QUIC is §10's gap, not a substitution)
Client auth   : RFC 7250 raw public key, possession proved by CertificateVerify
Server auth   : the server's own raw public key, for the client to pin
0-RTT         : PROHIBITED — max_early_data_size is 0 and asserted at startup
TLS 1.2       : not offered; a 1.2 downgrade is a downgrade of the authentication
```

**Why raw public keys.** A `device_id` *is* a hash of the device's identity key
(`identifiers.md` §2), so device identity is self-certifying and there is no
authority to chain to. A PKI here would be a second, weaker naming system over a
self-certifying one — ADR-0001 §6's "certificate/PKI baggage", declined.

**There is no certificate.** `TWINVPN_RZ_TLS_KEY_PATH` is the whole of the
server's identity; `ServerTls::public_key()` returns the SPKI an operator
publishes for devices to pin, which is what ADR-0001's "pinned control-plane
public key set, shipped in the build" means in practice.

**What is authenticated, and what is not.** The handshake proves the peer holds
the private half of the key it presented. It does **not** decide *which* keys may
connect: this service is an untrusted courier with no trust store, the `CALL`
bodies are Rule-B signed end to end, and asking the control plane per connection
would put it back in the reconnect path (**I5**). That constraint is now stated
on `ClientKeyPolicy` itself rather than remembered, so an implementor reads it
at the point of temptation; this service ships `AcceptAnyWellFormedKey`. Any
well-formed key may connect — but it may only speak for itself, which is §4.2.

### 4.2 The binding — `ATTACH` is answerable to the key

Before this, `ATTACH` was an unauthenticated **claim**: anyone with a socket
could say "I am `device_id` D" and receive D's `CALL`s.
[`twinvpn_service_common::binding`](../twinvpn-service-common/src/binding.rs)
makes the claim answerable:

> **A `device_id` belongs to at most one channel identity, and a channel
> identity speaks for at most one `device_id`, for the life of the binding.**

- the first `ATTACH(D)` on a channel holding key `K` records `K ↔ D`;
- `ATTACH(D')` on that channel with `D' ≠ D` is refused;
- `ATTACH(D)` from any channel holding `K' ≠ K` is refused while `K ↔ D` is live.

Refusal is **`CONTROL.CHANNEL_BINDING_MISMATCH`** — FATAL, CRITICAL, and
`trust-boundaries.md` §4's words for it are "**a security event, never a parse
error**". The answer names nothing, and that is now **structural rather than
careful**: the frozen registry declares no evidence fields for the code and the
`twinvpn-types` builder drops an undeclared key, so no call can attach the
contested `device_id` even by mistake. Echoing it would make the refusal an
oracle for which devices are attached.

**A full table is a different refusal.** `CONTROL.ADMISSION_DEFERRED`, not a
mismatch — the `device_id` is not contested, the server is, and answering "held
by another channel" would tell a caller its subject was taken when it was not.
S-6 makes answering mandatory there rather than resetting.

The binding **outlives its connection** by `TWINVPN_RZ_BINDING_TTL_MS`, so a
device that drops and reconnects finds its own binding and an attacker racing
that reconnect finds it taken. It does lapse, so a device that legitimately
rotates its identity key is not locked out for ever.

**A connection releases exactly what it claimed.** `release` takes the subject
as well as the channel, and this service calls it only on the accepted path.
The earlier shape — channel-only, called unconditionally at teardown — let a
*refused* connection sharing a key with a live one drop **that connection's**
hold, after which one channel could speak for a second `device_id` and a held
binding became evictable for capacity. Neither this service's unit tests nor
`presence`'s caught it, because both released from a single synthetic channel;
it needs a long-lived connection to appear. `tests/tls_binding.rs::
a_refused_sibling_connection_cannot_release_a_live_connections_hold` is the
service-level guard, and it runs against real sockets on both families.

**What this is not.** It is channel-pinned, not derived. It closes impersonation
of a device that is attached or has attached within the binding TTL — which is
every device in normal operation. It does **not** close *first-contact*
impersonation: an attacker who attaches as D before the real D ever does holds
the binding until it lapses.

`derive_device_id_checked` is now reachable (`twinvpn-crypto`, RZ-7 closed), so
the derived binding the `Binding` trait was written for is buildable — but a
**derived-only** binding would lock out every device that has ever rotated its
identity key, permanently. RZ-10 in §9 states why and what to build instead.

---

## 5. The wire

A fixed-layout header, then an opaque body, **inside the authenticated
channel**:

```
 offset  size  field
      0     4  magic      = 0x54 0x56 0x52 0x31  ("TVR1")
      4     1  version    = 0x01
      5     1  opcode     (table below)
      6     2  body_len   unsigned, big-endian, <= 1232
      8     n  body       exactly body_len octets; no padding, no trailer
```

`body_len`'s ceiling is `identifiers.device_id_bytes` (32) plus
`envelope.c4_max_bytes` (1200). It is validated **before** a body buffer exists.
Trailing octets past `body_len` are a framing error, not something to skip: a
tolerated tail is a place to smuggle bytes past a length check.

The integration lead has blessed this framing (RZ-1) and asked that it be written
down precisely so a future `CallEnvelope` contract can be specified against what
shipped. The above is that specification; `src/frame.rs` is its only
implementation and `tests/frame_proptest.rs` its executable statement.

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
a choice — see RZ-1 in §9.

---

## 6. The `CALL` ladder and the resource envelope

ADR-0002 §11.5:

```
[1] target has a live control channel  ──▶ deliver on it            p50 ≤ 150 ms
[2] target has a valid push token      ──▶ C3 wake hint     NOT IMPLEMENTED (§10)
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

## 7. Forward-verbatim (finding W-4)

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

## 8. What this service can still observe about users

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

## 9. Findings for the integration lead

| # | Kind | Finding |
|---|---|---|
| **RZ-1** | **contract gap** | **No frozen message expresses the rendezvous `CALL` envelope.** ADR-0002 §11.5 and S-5 require a `CALL` to name its target *by `DeviceId`* — the whole anti-reflection control — but `ConnectOffer`, `ConnectAnswer` and `CandidateSet` carry no recipient and `MessageMetadata` has `sender_id` with no counterpart. `contracts/` is frozen, so this service carries the target in a **fixed-layout binary header** (§4) rather than inventing a protobuf message. That is also the shape ADR-0003 §11 B4 prefers on a hostile path. **Needs a ruling:** either a `CallEnvelope` is added to `signaling.proto` under the §3 amendment procedure, or the fixed-layout framing is blessed and documented. |
| **RZ-2** | **architecture conflict** | **`infra/README.md` §5 gives this service `ReadinessPolicy::AnyDependency` with "the control-plane authorization endpoint reachable".** Implemented as **`NoControlPlaneCalls`** instead. A rendezvous that reports NOT READY on a control-plane blip is removed from service, which stops peers exchanging candidates, which puts the control plane back in the critical path of every reconnect — exactly what protocol.md §10.1 and I5 forbid. `architecture.md` §2.9's "Depends on: Control Plane for authorization" is about authorizing a *caller*, not about liveness. **Needs the lead's ruling**, and `infra/README.md` §5 amended if this reading is accepted. |
| **RZ-3** | **contract gap** | **`errors.proto` has no `COMPONENT_RENDEZVOUS_SERVICE`.** It has `COMPONENT_RENDEZVOUS_CLIENT` (7), the device-side component, and `COMPONENT_COORDINATION_SERVICE` (21). This service reports 21 — the closest truthful answer, since `architecture.md` §2.9 places the rendezvous in the control plane — rather than claiming to be the client. The registry is append-only, so adding one breaks nothing. |
| **RZ-4** | gap | **Rung [2], the C3 push wake, is not implemented** (§9). No push credential store exists and a push gateway is an untrusted third party. A detached device's `CALL` falls straight to the mailbox. This costs latency, never correctness — the initiator never blocks on delivery (ADR-0002 §11.5). |
| **RZ-5** | note | **Seven `TWINVPN_RZ_*` resource ceilings added** (§3.1), all with defaults, none in `infra/README.md` §4.3. A pre-authentication surface with no connection bound, no per-source rate bound and no partial-frame deadline is a descriptor- and memory-exhaustion primitive; these are not optional. Should be added to `infra/README.md` §4.3 when infrastructure next touches it. |
| **RZ-7** | **closed by the integration lead** | The `device_id` derivation was unreachable from a service artifact. `derive_device_id_checked` now lives in `twinvpn-crypto`, which `services/Cargo.toml` already permits, and it proves RFC 8949 §4.2.1 canonicality and ES256 **before** hashing — the right variant for a key presented on a wire. Re-deriving it here would have been W-23 verbatim, and the corpus's answer was to move the hash rather than drag a trust engine into three server artifacts. **Superseded by RZ-10**, which is what stands between a reachable derivation and a shipped one. |
| **RZ-8** | **closed by the integration lead** | `tls.rs` and `binding.rs` were byte-for-byte the same design in both services, and `relay-plane` would have been the third. Both now live in `twinvpn-service-common`; this domain's copies are deleted and both services consume the shared modules. Absorbing them **found a defect neither copy could see** — see RZ-11. |
| **RZ-10** | **decision needed — do not ship a derived-only binding** | **A derived-only binding would permanently lock out every device that has ever rotated its identity key.** `device_id` pins the **generation-0** key; ADR-0007 §11 (lines 372–377) is explicit that IK rotation creates a new `DeviceIdentity` at `generation+1` while *"`device_id` does not change"*, and that after a rotation `device_id` is self-certifying **only transitively** — "a verifier checks the succession chain from generation 0 to the presented generation", which the ADR itself calls "a real cost of the design". A rotated device therefore presents a generation-N key on TLS that derives to something that is **not** its `device_id`, and this service holds no `IdentitySuccession` chain and must not fetch one per connection (**I5**). Shipping derived-only trades an unbounded first-contact window for an unbounded lockout, which is the worse trade and the fleet-wide-irreversible kind. **Recommended instead — derived-preferred, channel-pinned fallback, derived wins:** a claim whose presented key derives to the claimed `device_id` is *proven* and **takes the binding from a merely pinned holder**; a claim that does not derive falls back to first-claim pinning. That closes first-contact impersonation against every generation-0 device — all of them until they rotate — because an attacker can no longer *hold* a `device_id` against its rightful owner, while a rotated device still binds. **Where it belongs:** `service-common`, beside `ChannelPinned`. It needs an SPKI→dCBOR-COSE_Key conversion (the RFC 7250 channel identity is an SPKI; `derive_device_id_checked` takes a COSE_Key), and that is a specified encoding — exactly the thing RZ-8 just proved must not exist twice. I did not build it in two service crates for that reason. |
| **RZ-11** | **defect this domain shipped, fixed in the shared crate** | `release(&channel, now)` decremented the holder count of **every** entry the channel held, and both services called it at teardown — so a *refused* connection sharing a key with a live one dropped that connection's hold, after which one channel could speak for a second subject and a held binding became evictable for capacity. Self-scoped (the attacker must own the key) but it falsifies the invariant §4.2 states, and for `presence` it is one key publishing presence for two identities, which S-11 forbids. **The rendezvous carried a second form of it: it never called `release` at all**, so holder counts only ever went up and were reclaimed by the TTL — a slower path to the same table-at-capacity outcome. Both are fixed: `release` takes the subject, and this service calls it only on the accepted path. **Why neither copy's tests caught it, carried forward as the lesson:** both released from a single synthetic channel, so the bug needed a long-lived connection to appear. Two independent copies both passed their own tests. Service-level regression tests now exist in both. |
| **RZ-9** | **closed** | The `aws-lc-rs` dev-dependency and `tests/common/keys.rs` are gone from both crates. Key material now comes from `twinvpn-service-common`'s `tls::testkit` behind its `test-support` feature, so there is one generator rather than two and no crypto crate named in a service manifest. |
| **RZ-6** | note | **`services/Cargo.lock` now changes only subtractively**: migrating to the shared modules removes `rustls`, `rustls-pemfile`, `rustls-pki-types` and `aws-lc-rs` from **both** services' direct dependencies — 8 deletions, no crate added, no version moved. The earlier history, for the record: **`services/Cargo.lock` changed mechanically**, twice. First: `proptest` 1.11 as a **dev**-dependency plus 13 transitive dev-only entries — `ownership.md` §6 makes the B3 parser's "never panics, never allocates unboundedly" a **property**, and a property needs a property test. Second: the TLS work resolves `rustls`, `tokio-rustls`, `rustls-pemfile`, `rustls-pki-types`, `rustls-webpki`, `aws-lc-rs`/`aws-lc-sys` and their build-time helpers (`cc`, `cmake`, `jobserver`, `shlex`, `pkg-config`, `dunce`, `fs_extra`, `find-msvc-tools`, `getrandom`, `r-efi`, `ring`, `untrusted`, and the `windows-*` target shims). All follow from the three lines the lead added to the workspace manifest. **`aws-lc-sys` compiles C**, and it built on this host **without `cmake` installed** — worth knowing before a CI image is trimmed. No existing dependency changed version. The lockfile is the lead's to reconcile. |

---

## 10. Known limitations

Stated here rather than discovered later.

1. **QUIC is not bound.** ADR-0001's L-CONTROL is QUIC + TLS 1.3; this is the
   same authentication over TCP, which ADR-0002 §11.2's rung 2 already
   contemplates as a degraded binding. What is lost is connection migration and
   cross-stream head-of-line independence — a mobile device roaming between
   networks re-handshakes rather than migrating. `quinn` is in the workspace
   manifest, and the `tls.rs` `ServerConfig` is the one a QUIC endpoint would
   take, so this is a binding to add rather than a design to change.
2. **First-contact impersonation is open** — RZ-10, and §4.2 says exactly what
   that means. An attacker who attaches as a `device_id` *before* the real device
   ever has holds the binding until it lapses. It cannot read the `CALL`s (Rule-B
   signed, opaque) and cannot answer them, but it can deny delivery. The
   derivation is now reachable; what is missing is the **derived-preferred**
   design RZ-10 specifies, and one shared place to put the SPKI→COSE_Key
   conversion it needs.
3. **No container has been built or run.** Docker is absent from this host
   (`infra/README.md` §9). Everything in §2 involving `docker compose` is
   unexercised. The tests run a **real** TLS 1.3 listener on loopback, over both
   IPv4 and IPv6, and drive real mutually authenticated sockets.
4. **`infra/scripts/bootstrap-local.sh` generates an Ed25519 key and a
   self-signed certificate.** The key loads fine and the certificate is ignored,
   which is correct for RFC 7250 — but an operator reading that script would
   reasonably expect the certificate to matter. Worth a line there; raised with
   `infrastructure` via RZ-5's channel rather than edited from here.
5. **Rung [2] (C3 push wake) is absent** — RZ-4.
6. **`Verbatim::from_received` applies a *shape* check to the payload**, not only
   a size check: `twinvpn_schema::depth::check` refuses octets that are not a
   well-formed protobuf record sequence. That is the depth guard doing its job
   pre-parse, and it is conservative in the safe direction, but it does mean a
   future C4 body that is *not* protobuf-shaped would be refused. Recorded
   because "the rendezvous never looks at the payload" is true of its *values*
   and not quite true of its *framing*.
7. **The 1200-byte C4 cap is enforced; the IPv6 path MTU it is derived from is
   not measured.** On TCP the envelope never fragments, so the cap here is a
   protocol bound rather than a path property.
8. **No relay-assisted fallback.** ADR-0002 §11.5 records that a `Relay` may
   carry a `CALL` when the rendezvous is unreachable. That is the relay's side
   and belongs to `relay-plane`; nothing here prevents it.

---

## 11. Debugging

| Symptom | First thing to check |
|---|---|
| startup fails naming `TWINVPN_RZ_C4_MAX_BYTES` | something set a frozen bound. The message names the value and the expectation |
| startup fails naming a TLS path | the file does not exist, is unreadable, or is not a parsable private key. There is no fallback to a plaintext listener, by design |
| a client cannot connect at all | it must offer TLS 1.3, present an RFC 7250 raw public key, and pin this server's key. `twinvpn_rendezvous_tls_handshakes_refused_total` counts every failure without distinguishing them — deliberately, since the peer is unauthenticated |
| `twinvpn_rendezvous_binding_mismatches_total` climbing | a `device_id` is being claimed on a channel not entitled to it. **A security event** (`CONTROL.CHANNEL_BINDING_MISMATCH`, FATAL/CRITICAL), not a client bug — unless a device rotated its identity key inside the binding TTL, which §4.2 covers |
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
