# `twinvpn-control-plane`

The server side of channels **C1** (request/response) and **C2** (the resumable
durable event stream). Its client is
[`twinvpn-cp-client`](../../core/crates/twinvpn-cp-client/), a different artifact
in a different cargo workspace; this crate is its exact counterpart and links no
core crate but `twinvpn-schema` and `twinvpn-types` (ADR-0018 §11.2 row 2.8).

Architecture: [ADR-0002](../../docs/adr/ADR-0002-control-plane-messaging-and-event-bus.md).
Idempotency: [ADR-0008](../../docs/adr/ADR-0008-idempotency.md).
Consistency: [ADR-0009](../../docs/adr/ADR-0009-state-consistency.md).
Ownership: [`docs/implementation/ownership.md`](../../docs/implementation/ownership.md) §2.
Shared plumbing: [`twinvpn-service-common`](../twinvpn-service-common/README.md).

---

## 1. The one sentence that shapes every decision here

**This service is authenticated but not trusted.** `policy.proto` says the
coordination service "WAREHOUSES AND DISTRIBUTES; IT CANNOT AUTHOR", and
`protocol.md` §7 says a coordination service that could mint routes could
redirect an `Owner`'s subnet to an attacker. So every capability that would let
this process *create* authority is removed structurally, not by policy:

| It cannot | Because |
|---|---|
| author a `PolicyBundle`, a `RevocationStatement`, a `RouteAdvertisement`, an `ExitNodeOffer` | each arrives as opaque [`verify::SignedOctets`] and is admitted only if a `StatementVerifier` says it verified **over the received octets** against the authority `required_authority` names for its type |
| assign a `device_id` | `RegisterDevice` copies the one the device derived; there is no branch that computes one |
| take a trust decision from a `LogHead` | nothing reads one; its key is online and carries no trust power |
| shrink the revoked set or lower an epoch | `NetTx` has no `un_revoke`, and every monotone check is unconditional |
| forge a device's statement | verification is against the COSE_Key **this service recorded at registration**, never one the request carried |
| publish an event under another principal | `DurableEvent::new` stamps the sole publisher and has no setter (§4) |

**`RevokeDevice` and `PutPolicy` have two signers.** The `Owner` authorizes by
signing; this service *orders* by assigning `trust_epoch` and `net_seq` under a
fenced lease. `domain::device::revoke` reaches `tx.revoke` — the only thing that
assigns an epoch — **after** `verify::admit` has returned an `Owner`-authority
`Verified`, and there is no branch on which an unverified statement reaches the
numbering.

---

## 2. Build and test

```bash
source build/toolchain/env.sh
cd services
cargo build -p twinvpn-control-plane
cargo test  -p twinvpn-control-plane
```

The gate, exactly as it is run before reporting:

```bash
cd services
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd .. && make test-contracts          # 35801 checks, 0 failures
```

`make test-contracts` needs `node_modules/.bin/buf`, which `npm ci` installs at
the repository root. In a `git worktree` that directory is absent; symlink it
from the primary checkout and remove the symlink afterwards.

---

## 3. Environment configuration

Every variable, its default, whether it is required, and **what happens when it
is absent**. These names are `infra/env.example`'s and `docker-compose.yml`'s;
this crate invents none of them, and `infra/README.md` §4.3 is the source.

The variables `twinvpn-service-common` loads — `TWINVPN_SERVICE_NAME`,
`TWINVPN_LOG_*`, `TWINVPN_ADMIN_ADDR`, `TWINVPN_SHUTDOWN_*`,
`TWINVPN_ADDRESS_FAMILIES`, `TWINVPN_OTEL_ENABLED`, `OTEL_*`,
`TWINVPN_LIMITS_PATH`, `TWINVPN_REASON_CODES_PATH` — are in
[its README §3](../twinvpn-service-common/README.md#3-environment-configuration)
and are not repeated here.

| Variable | Type | Default | Required | If absent |
|---|---|---|---|---|
| `TWINVPN_CP_DATABASE_URL` | secret URL | **none** | **YES** | **startup fails**, naming the variable. `Loader::secret` has no signature taking a default and refuses a value still containing `CHANGE-ME` |
| `TWINVPN_CP_LISTEN_QUIC` | socket addr | `[::]:443` | no | `[::]:443` — see §6 on why the wildcard is `[::]` |
| `TWINVPN_CP_LISTEN_TCP` | socket addr | `[::]:443` | no | `[::]:443`. **Rungs 2–4 are not implemented**; see §7 |
| `TWINVPN_CP_QUIC_ZERO_RTT` | bool | `false` | no | `false`. **A value that parses as `true` is a startup failure**, and so is one that parses as neither — a misspelling silently meaning "off" would be luck rather than safety |
| `TWINVPN_CP_OWNER_ANCHOR_PATH` | path | `/run/secrets/control-plane/owner-anchors.hex` | no | **an empty anchor set.** One base16 COSE_Key per line; `#` comments and blank lines ignored. Absent means every `Owner`-authority statement is refused with `AUTH.KEY_UNAVAILABLE` — a capability lost, not a startup failure. A line that is present but not base16 **is** a startup failure: a silently skipped key produces a service that refuses statements a correct one would admit. **New variable**, not yet in `infra/README.md` §4.3 (§11 finding 8) |
| `TWINVPN_CP_TLS_CERT_PATH` | path | `/run/secrets/control-plane/tls.crt` | no | the default path |
| `TWINVPN_CP_TLS_KEY_PATH` | path | `/run/secrets/control-plane/tls.key` | no | the default path |
| `TWINVPN_CP_DATABASE_MAX_CONNECTIONS` | u32 | `16` | no | 16 |
| `TWINVPN_CP_EVENT_BUS` | string | `postgres-notify` | no | `postgres-notify` |
| `TWINVPN_CP_WRITE_LEASE_TTL_MS` | u64 ms | `15000` | no | 15 s — ADR-0002 N-4 |
| `TWINVPN_CP_ATTACH_RATE_SUSTAINED` | f64 /s | `200` | no | 200 attaches/s |
| `TWINVPN_CP_ATTACH_RATE_BURST` | u32 | `1000` | no | 1000 |
| `TWINVPN_CP_DRAIN_DEADLINE_MS` | u64 ms | `120000` | no | 120 s — §11.7 rule 1 |
| `TWINVPN_CP_READ_STALENESS_WAIT_MS` | u64 ms | `250` | no | 250 ms — §11.3 |
| `TWINVPN_CP_QUORUM_REPLICAS` | u32 | `0` | no | `0`, the single-box topology (T2/T3). `≥1` is the hosted one; named so a T1 deployment cannot silently run as a T2 one |

### 3.1 The frozen bounds are read, and a disagreement is a startup failure

`infra/README.md` marks these "frozen": they come from
`contracts/registry/limits.json`, are compiled in, and **cannot be widened from
the environment**. Setting one to anything other than its registry value fails
startup rather than being silently ignored — "it uses a sensible default" and
"it fails to start" are very different facts, and only one of them is safe.

| Variable | Frozen value | `limits.json` key |
|---|---|---|
| `TWINVPN_CP_RETENTION_FLOOR_DAYS` | `30` | `control_plane.retention_floor_days` |
| `TWINVPN_CP_RETENTION_FLOOR_EVENTS` | `1000000` | `control_plane.retention_floor_events` |
| `TWINVPN_CP_EVENT_RATE_SUSTAINED` | `1` | `control_plane.durable_events_per_second_sustained` |
| `TWINVPN_CP_EVENT_RATE_BURST` | `20` | `control_plane.durable_events_burst` |
| `TWINVPN_CP_C2_WATERMARK_BYTES` | `262144` | `control_plane.c2_backlog_watermark_bytes` |
| `TWINVPN_CP_C2_WATERMARK_EVENTS` | `512` | `control_plane.c2_backlog_watermark_events` |
| `TWINVPN_CP_IDEMPOTENCY_WINDOW_MS` | `86400000` | `control_plane.idempotency_dedup_window_ms` |

---

## 4. Sole publisher, in three independent layers

`protocol.md` §7 says sole-publisher is enforced **at the log, not by
convention**. Three layers do it, and they fail independently:

1. **Construction.** `DurableEvent::new` takes a body and stamps
   `publisher = kind.sole_publisher()`. There is no `publisher` parameter and no
   setter. The only way to build a wrong one is `forged_for_test`, which exists
   behind `cfg(test)`/`feature = "test-support"` so layer 2 has something to
   reject — without it the rejection test would be vacuous.
2. **Append.** `DurableEvent::check_publisher` runs on every `NetTx::append` and
   answers `CONTROL.EVENT_WRONG_PUBLISHER`, `FATAL`/`CRITICAL`.
3. **Schema.** `migrations/0002_event_log.sql` carries
   `CHECK (publisher_principal = 'coordination_service')` and a second `CHECK`
   listing only the durable event types, so a write that reached the database by
   any other path is still refused *by the database*.

A fourth check runs at `session::Attachment::pump`, the last point before the
octets leave the process, and the client checks a fifth time on receipt.

---

## 5. Durability, and the direction that is a security failure

`contract-matrix.md` §1 states the two directions and they are not symmetrical:

> *Treating a durable event as ephemeral is a **SECURITY** failure: a device
> asleep during a revocation broadcast wakes still trusting a stolen laptop, and
> nothing will ever correct it.*

> *Treating an ephemeral message as durable is a **COST, PRIVACY and
> DENIAL-OF-FRESHNESS** failure.*

`EphemeralEvent::new` refuses a durable body and `DurableEvent::new` refuses an
ephemeral one, so neither misclassification is expressible. `net_seq == 0` on an
ephemeral event and `net_seq > 0` on a durable one are structural, not checked.
`tests/client_agreement.rs` reads `twinvpn-cp-client`'s own classification table
as text and fails if the two artifacts ever disagree — they cannot link each
other, and a disagreement is invisible from either side alone.

---

## 6. IPv4, IPv6, dual stack, IPv6-only

ADR-0010 R1: there is no "v4 story and a v6 story", and this service has no
per-family branch.

- **The listener** binds `[::]` and does **not** set `IPV6_V6ONLY`, so one socket
  serves both families on a dual-stack host and the same code serves an
  IPv6-only host unchanged. A v4-only host binds `0.0.0.0` through
  `TWINVPN_CP_LISTEN_QUIC` and nothing else differs.
- **Address allocation** hands out **both** overlay addresses or neither
  (`domain::addressing::allocate` returns a pair; there is no way to obtain one
  half). `device.proto`: "A `Device` with one set and not the other is malformed
   — that asymmetry is exactly how a v6-aware design degrades into a v4-only one."
- **The v6 address is the one the client derives.** ADR-0010 §11.1:
  `prefix64 ‖ truncate64(HKDF(DeviceKey_pub, "twinvpn-v6-iid"))`, U/L bit cleared
  per RFC 7136 — computed with **`twinvpn-crypto`'s** HKDF-SHA-256, the same
  audited provider `twinvpn-route`'s client-side binding calls. A second
  implementation in this workspace would be the DP-8 second provider whose
  agreement with the core's is untested, and byte-for-byte agreement is exactly
  what an independently-derived address needs.
  `tests/client_agreement.rs::the_v6_derivation_matches_the_clients_address_plan`
  asserts the `info` string, the ULA, both reserved ranges and the U/L clear
  against `twinvpn-route`'s `plan.rs` and against `device.proto`'s normative
  sentence.
- **Both reserved service ranges are honoured**: the allocator skips
  `100.127.255.0/24` (AP-2) and no derivation can land in
  `fd7c:9e5d:2a10:ffff::/64` (DN-3), so no address this service issues is one
  `twinvpn-route`'s own `check_device_v4` would reject.
- **Route advertisements** validate `prefixes_v4` and `prefixes_v6` with the same
  validator and the same cap.

**Exercised how?** The socket bind is not exercised on this host (§9). The
family-independent halves — the derivation, allocation, prefix validation, the
`[::]` default — are unit-tested, and the derivation is pinned against
`twinvpn-crypto` directly rather than against itself.

---

## 7. What is bound, and what a composition root must still bind

**Signature verification is real.** `verify::CryptoVerifier` verifies COSE_Sign1
**over the received octets** through `twinvpn-crypto` — the audited provider, the
one the client verifies with. Which key a statement is checked against is the
*caller's* decision, made by `verify::SignerKey`:

| Statement | Signer key | Status |
|---|---|---|
| `PairingAttestation`, `IdentitySuccession`, `TunnelKeyBinding`, `RouteAdvertisement`, `ExitNodeOffer` | `SignerKey::Device` — the COSE_Key **this service recorded at registration**, never one the request carried | **fully verified** |
| `RevocationStatement`, `PolicyBundle`, `RelayEpochFloor`, `PairingRevocation`, `OwnerDelegation` | `SignerKey::OwnerAnchors` — the pinned `OwnerTrustAnchor` set from `TWINVPN_CP_OWNER_ANCHOR_PATH` | **signature verified against the pinned set**; the delegation chain is not evaluated — see below |

`verify::admit` checks the authority table **before** any signature arithmetic
(a `PolicyBundle` offered against a device key never reaches the verifier) **and
again afterwards** (a verifier that claimed the wrong authority is caught). The
table is this crate's rule, not the binding's.

Two things remain unbound, and each ships a **fail-closed** default announced in
a startup `WARN` rather than discovered from a refusal:

| Not bound | Shipped behaviour | What it costs | Why not here |
|---|---|---|---|
| The `Owner` **delegation chain** (S-32) — whether the OSK that signed carries `ENROLL`, `POLICY` or `REVOKE`, and whether its delegation is current for the anchor version | with an anchor configured, an `Owner`-signed statement is admitted on the **signature** alone; with none, every one is refused with `AUTH.KEY_UNAVAILABLE` | power *scoping*. An OSK that can sign can sign anything the `Owner` can | chain evaluation is `twinvpn-trust`'s (S-32) and this artifact does not link it. `twinvpn-crypto` decodes an `OwnerDelegation`; deciding what it authorises is a different crate's job |
| `quic::PeerIdentityVerifier` | `RefuseUnidentified` — `CONTROL.HANDSHAKE_REJECTED` | every mTLS handshake, so the QUIC listener is configured but not accepted on | RFC 7250 raw-public-key verification against a pinned key set is `twinvpn-crypto`'s under W-12, and the mapping from a presented key to a `device_id` needs the identity derivation the device performed |

One more half-verified case, stated rather than implied: an
**`IdentitySuccession` is dual-signed** by the old *and* the new IK (ADR-0007
N-21). This service verifies the **old** key's half, because that is the identity
it holds; the new key's half is verified by the peer that pins it, which is where
`twinvpn-crypto`'s own `verify_succession_pair` lives.

**Rungs 2–4 of the ADR-0002 §11.2 ladder are not implemented.** Rung 1 (QUIC +
TLS 1.3, `quic.rs`) is. `tokio-rustls` is now in the workspace so rungs 2–3 are
unblocked; the integration lead's instruction is to implement rung 1 well and
leave 2–4 declared-and-unimplemented rather than half-built, and that is what
this does. `session::Rung` carries the halved-watermark rule so it is written
once when they land.

### 7.1 The C1 framing, and the contract gap it closes

`control_commands.proto` defines seventeen request messages and **no
discriminated union over them**, and `MessageMetadata` carries no method name.
The client's seam is byte-oriented — `ControlConnection::request(&[u8])` — so
nothing in the frozen contracts tells a receiver which of the seventeen a body
is. An HTTP/3 binding would carry it in `:path`; this crate carries C1 directly
over QUIC bidirectional streams and carries it in a two-byte header:

**The framing, precisely, so a future contract can be written against what
shipped.** All integers are **big-endian**. `src/wire.rs` is the implementation
and `wire::tests` is the conformance suite.

```text
  C1 request   (one QUIC bidirectional stream, client-opened):
      offset 0  u16  command_code      big-endian, from the table below
      offset 2  u32  body_len          big-endian, <= 65536
      offset 6  ..   body              the protobuf request message

  C1 response  (the same stream, server-written, then FIN):
      offset 0  u16  command_code      ECHOED, so a response is self-describing
      offset 2  u32  body_len          big-endian, <= 65536
      offset 6  ..   body              the protobuf response message

  C2 record    (one QUIC unidirectional stream, server-opened, many records):
      offset 0  u32  body_len          big-endian, <= 65536
      offset 4  ..   body              a `twinvpn.v1.ControlEvent`
```

There is **no separate error frame**. A refusal is the command's own response
message with its `error` field set to an `ErrorEnvelope`, which is why every
response in `control_commands.proto` has one; a response that could not be built
at all closes the stream with a QUIC application error code. This keeps the
framing's vocabulary to one shape and keeps `CF-4` true — there is no envelope
here for a message string to be added to.

**Command codes.** Assigned once and never reused: a code is a wire identity, and
re-pointing one would make an old client's `RevokeDevice` arrive as something
else. Each decade is one section heading of `control_commands.proto`; the gaps
are deliberate room for that section to grow.

| Code | Command | Code | Command |
|---|---|---|---|
| `10` | `RegisterDevice` | `40` | `PutRouteAdvertisement` |
| `11` | `UpdateDeviceMetadata` | `41` | `WithdrawRouteAdvertisement` |
| `12` | `RevokeDevice` | `42` | `PutExitNodeOffer` |
| `13` | `RotateDeviceCredential` | `43` | `WithdrawExitNodeOffer` |
| `20` | `BeginPairing` | `50` | `PutPolicy` |
| `21` | `CompletePairing` | `60` | `SubscribeEvents` |
| `22` | `CancelPairing` | `61` | `GetStateDocument` |
| `23` | `RevokePairing` | | |
| `30` | `DiscoverPeers` | | |
| `31` | `PublishPresence` | | |

An **unassigned code is rejected, never guessed**: `CommandCode::from_wire` has
no default arm, and an unknown value is `PROTO.UNPARSEABLE_ENVELOPE`.

`body_len` is checked against `envelope.c1_c2_c7_max_bytes` **before** the body
buffer is allocated, so a declared length of `0xFFFF_FFFF` costs six bytes of
reading and a typed reject. The bound is applied on the way **out** as well: a
service that can emit an over-cap frame has a peer that must either reject it or
raise its own cap, and both are worse than failing at the sender.

The header is outside the protobuf body and adds no field to any frozen message,
so an HTTP/3 front-end can strip it and put `command_code` in `:path` without
either side changing. **Reported as a contract gap (§11), not patched into
`contracts/`.**

Also note: this crate implements QUIC streams directly rather than **HTTP/3**,
which ADR-0002 §11.2 names. `services/Cargo.toml` declares no `h3` crate. The
`ControlTransport` seam is byte-oriented and does not observe the difference, but
it is a divergence from the ADR and is listed in §11.

---

## 8. Where the cryptography comes from, and why not from here

Three values in this service must agree with the client **byte for byte**: the v6
interface identifier, the SHA-256 digest announced in `StateDocumentRef`, and
every COSE_Sign1 signature. All three come from `twinvpn-crypto`, a permitted
`/core` edge for the services workspace.

That is ADR-0018 **DP-8**, not convenience. The fleet is bounded at two crypto
providers because "they double the assurance surface", and both must pass the
*identical* golden-vector corpus. Adding `hkdf`, `sha2` or `p256` to
`services/Cargo.toml` would create a third provider whose agreement with the
core's is untested — and untested agreement is exactly what an
independently-derived address and an independently-verified digest cannot afford.
Depending on `twinvpn-crypto` is not itself a cryptographic dependency: it is the
crate that *encapsulates* them, so this artifact inherits the audited
implementation rather than a parallel one. The same applies to test fixtures:
`twinvpn-crypto/test-support` signs the vectors in `verify.rs` rather than this
crate naming `p256` as a dev-dependency, because CD-I2 covers dev-dependencies
too.

**Two earlier divergences are closed.** This service previously derived the v6
address as `truncate64(device_id)` and announced a 256-bit FNV-1a fold as the
document digest. Both had the right *shape* — deterministic, collision-refused,
32 bytes — and both disagreed with the client for every device and every pull.
`tests/client_agreement.rs` now asserts each against the client's own source and
against the frozen contract text, so a future divergence fails the build rather
than a deployment.

## 9. What was **not** executed on this host

Stated here rather than discovered later.

1. **No PostgreSQL.** `store::pg::PgStore` and every statement in `migrations/`
   are **compiled, not run**. This host has no `psql`, no PostgreSQL server and
   no Docker — the same absence `infra/README.md` §9 records for the
   `infrastructure` domain. The transactional properties that *are* executed run
   against `store::mem::MemStore`, which takes the same per-`TwinNet` write lock,
   runs the same `crate::domain` and `crate::tx` code, and commits by swapping a
   working copy under the lock that read the original. The SQL `CHECK`
   constraints and triggers in `migrations/` are asserted only as **text**
   (`store::pg::tests`), which proves the durable-event list matches the code and
   proves nothing about PostgreSQL's behaviour.
2. **No QUIC handshake.** `quic::server_config`, `bind` and `accept` are
   compiled and their pure halves (`check_channel_binding`, the 0-RTT source
   check, the ALPN and exporter constants) are tested. No connection has been
   made, because `RefuseUnidentified` would refuse it and because the TLS
   material and the client-certificate verifier are integration items (§7).
   Signature verification, by contrast, **is** exercised end to end: real
   COSE_Sign1 statements are signed with `twinvpn-crypto`'s fixtures, verified,
   tampered with and re-verified.
3. **No container.** Nothing in this component has been built into an image or
   run under `docker compose`.
4. **No OTLP collector.** Observability goes through `service-common`, whose own
   README §11 records the same gap.

---

## 10. Known limitations

1. **`PgStore::load` materialises the whole `TwinNet` slice per command.** That
   is correct — one writer per `TwinNet`, everything under one `SELECT … FOR
   UPDATE` — and it is O(devices + pairings) per command, so it does not scale to
   a very large `TwinNet`. It is the right first implementation for a design
   whose single-box topology is first-class, and it is a known cost rather than a
   surprise.
2. **The write budget is per-process, not per-`TwinNet`-cluster.** A multi
   front-end deployment sharing one `TwinNet` would admit N× the budget. The
   budget belongs in the database alongside the counter; ADR-0002 §11.6 does not
   say where it lives.
3. **Quorum is a boolean, not a count.** `Ctx::quorum_available` is supplied by
   the caller; nothing here counts replica acknowledgements, because nothing here
   replicates. `TWINVPN_CP_QUORUM_REPLICAS` records the operator's intent so a T1
   deployment cannot silently run as a T2 one, and the refusal path
   (`CONTROL.QUORUM_UNAVAILABLE`, never a partial apply) is implemented and
   tested.
4. **The `Owner` delegation chain is not evaluated** (§7). An anchor-signed
   statement is admitted on its signature; power scoping is `twinvpn-trust`'s.
5. **`causality_token` is not yet minted or checked.** ADR-0002 §11.3 makes it a
   control-plane-sealed CBOR value, which needs the sealing key this build does
   not have. The read path that would use it — a replica behind the caller's mark
   — has its code (`codes::read_too_stale`, `codes::replica_behind_cursor`) and
   no replica to apply it to, because this deployment has one writer and no read
   replicas.
6. **The dispatcher decodes a ceremony body twice** — once to read
   `MessageMetadata.idempotency_key` before the handler runs, once in the
   handler. Both decodes are bounded by the 64 KiB envelope cap, so the cost is
   bounded; it is noted because it is visible in a profile.
7. **`StreamCompacted` is emitted by the session layer, not appended to the log
   by it.** `session::Attachment::pump` reports `Pumped::Compacted` and the
   caller must append the announcement; the append path exists
   (`EventKind::StreamCompacted` is durable) and the wiring from the accept loop
   is not, because the accept loop is not wired (§7).
8. **No `LogHead` is emitted.** It is signed by an online control-plane key this
   build does not have, and it "does not defend against a compromised control
   plane" — losing it costs a freshness proof and nothing else.

---

## 11. Findings, and what the integration lead must decide

| # | Kind | Finding |
|---|---|---|
| 1 | **contract gap, resolution accepted** | `control_commands.proto` declares no discriminated union over its seventeen requests and `MessageMetadata` carries no method name, so the frozen contracts do not say *which request a C1 body is*. Closed by the two-byte transport header documented precisely in §7.1, outside the protobuf body; an HTTP/3 front-end moves the same value to `:path` with no change either side. |
| 2 | **defect** | ADR-0008 §11.2 requires a `precondition_failed` **and** a `duplicate_replayed` outcome in the registry. Neither exists among the 201 codes. `duplicate_replayed` needs none in practice. `precondition_failed` is mapped onto `AUTH.TRUST_EPOCH_ROLLBACK`, which **loses the ability to distinguish a lost update from a trust-epoch rollback and degrades a consistency failure into an auth one** — under ADR-0015 §11.2's prefix-degradation model, an older client told the wrong story with the wrong next action. The mapping stays, documented at `codes::PRECONDITION_FAILED`, and `codes::tests::the_registry_still_declares_no_precondition_failure_code` is the tripwire: registering the correct spelling fails the build and points at the line to delete. |
| 3 | **closed** | `Verbatim::from_received` ran a protobuf record scan over COSE_Sign1. `service-common` now has `Verbatim::from_opaque` (size cap only) and this crate uses it for every signed statement; the local `SignedOctets` is gone. |
| 4 | **W-4 residue, unavoidable under the freeze** | This service re-encodes the *decoded view* of a device-authored sub-message when it publishes the event about it (`RouteAdvertised.advertisement`, `ExitNodeAdvertised.offer`), because prost gives no way to splice a sub-message's original octets into a new message. Any unknown field a future client adds **inside** `RouteAdvertisement` is dropped. What survives verbatim is the `signed` COSE blob, and `routing.proto` is explicit that a receiver "MUST verify `signed` and MUST re-read the decoded fields FROM THE VERIFIED PAYLOAD, not from the protobuf fields above" — so the authorization-bearing content is preserved. The one place W-4 cannot be fully discharged. |
| 5 | **closed** | The v6 derivation and the `StateDocumentRef` digest now come from `twinvpn-crypto` (§8), with agreement asserted against the client's source and the frozen contract text. |
| 6 | **note** | `rustls` is deliberately **not** named in this crate's manifest, and the manifest now says why at length: it would compile `aws-lc-rs` alongside quinn's `ring` through feature unification and give one artifact two `CryptoProvider`s — a DP-8 violation arriving through a feature flag rather than a dependency line. Use `quinn::rustls::…`. |
| 7 | **decision** | HTTP/3 (`h3`) and an HTTP `CONNECT` client are still absent, so rung 4 and the literal HTTP/3 binding of §11.2 are not implemented. Accepted per the integration lead: implement rung 1 well. |
| 8 | **new variable** | `TWINVPN_CP_OWNER_ANCHOR_PATH` (§3) is not in `infra/README.md` §4.3. It needs a row there, and the compose topology needs the secret mount, before an anchor can be provisioned in the local stack. |
| 9 | **still open** | The `Owner` **delegation chain** is not evaluated (§7, §10 item 4). Binding it needs `twinvpn-trust` or an equivalent, and it is the difference between "the anchor signed this" and "an OSK carrying `REVOKE` signed this". |

---

## 12. Local startup and debugging

```bash
# From the repository root, with .env prepared per infra/README.md §4.1.
docker compose up control-plane                 # not exercised here; see §9
curl -s http://127.0.0.1:19001/readyz  | jq     # the admin listener
curl -s http://127.0.0.1:19001/healthz | jq
curl -s http://127.0.0.1:19001/metrics | grep twinvpn_
```

The runtime image has **no shell**, so `docker compose exec control-plane sh`
will not work. Probe from a container that has one (`prometheus`, `postgres`) or
from the host via the published admin port.

| Symptom | First thing to check |
|---|---|
| startup fails naming `TWINVPN_CP_DATABASE_URL` | it is unset, empty, or still says `CHANGE-ME` |
| startup fails naming `TWINVPN_CP_QUIC_ZERO_RTT` | it is set to `true`, or to something that parses as neither — both are refused |
| startup fails naming a frozen bound | §3.1: those come from `limits.json` and are not environment-tunable |
| `ConfigError::RegistryMismatch` | the mounted `contracts/registry` is not the one this binary was built against |
| `/readyz` 503, `/healthz` 200 | the datastore is unreachable. The JSON body names the probe and its registered code. A restart will not help |
| an `Owner`-signed command answers `AUTH.KEY_UNAVAILABLE` | no `Owner` trust anchor is bound — `TWINVPN_CP_OWNER_ANCHOR_PATH` is unset, absent or empty (§3). The startup log says so |
| an `Owner`-signed command answers `AUTH.BINDING_INVALID` | an anchor **is** bound and did not sign this statement. Not a misconfiguration: something presented a statement the pinned anchor did not author |
| a device-signed command answers `AUTH.BINDING_INVALID` | the statement was not signed by the key this service recorded for the caller at registration |
| startup fails naming `TWINVPN_CP_OWNER_ANCHOR_PATH` | a line in the anchor file is present but is not base16. A malformed key is refused rather than skipped |
| every handshake answers `CONTROL.HANDSHAKE_REJECTED` | no peer-identity verifier is bound (§7) |
| a mutation answers `CONTROL.WRITE_LEADER_UNAVAILABLE` | this process does not hold the `TwinNet` write lease. Transient; the client retries |
| a mutation answers `CONTROL.EVENT_RATE_EXCEEDED` | the per-`TwinNet` durable write budget (1/s sustained, burst 20). The write is **refused**, not queued |
| a subscribe answers `CONTROL.CURSOR_TOO_OLD` | the cursor is below the retention floor; the device must re-snapshot declaratively, which is always correct |
| `CONTROL.EVENT_WRONG_PUBLISHER` anywhere | **a security event.** Something tried to publish an event under a principal that is not its sole publisher |
| `CONTROL.CHANNEL_BINDING_MISMATCH` | **a security event.** The presented `Auth.channel_binding` is not this connection's `tls-exporter` value |

```bash
RUST_LOG=twinvpn_control_plane=debug cargo test -p twinvpn-control-plane -- --nocapture
```

**Never logged**, per `ownership.md` §6 rule 11: private keys, session keys,
pairing secrets, authentication tokens. `TlsMaterial`'s `Debug` prints a chain
length; `SignedOctets`' prints a byte count; `ServiceError` has no message field
and never encodes one, so a `sqlx` error's text — which can name a host, a user
and a constraint — stays in `source_detail()` for a log line and never reaches
the wire.

---

## 13. Migrations

Forward-only, in `migrations/`, run with `PgStore::migrate` (`sqlx::migrate!`,
which records what it applied and refuses a file whose checksum changed).

| File | Contents | Reversible? |
|---|---|---|
| `0001_twinnet_and_membership.sql` | `twinnet` (S-26, S-28, the lease), `device` (S-02, S-08), `revocation` (S-03) | **Yes** — dropping restores an empty database, destroying its data |
| `0002_event_log.sql` | `event`, the sole-publisher `CHECK`, the durable-type `CHECK`, append-only and density triggers | **No, deliberately.** Dropping destroys the revocation history; a rebuilt empty log presents a lower `net_seq` under the same `shard_epoch`, which devices read as a rebuilt log (R-8) and answer with a fleet-wide re-read. The recovery procedure is ADR-0008 §10.1's epoch bump, not a schema reversal |
| `0003_ceremonies_documents_and_dedup.sql` | `pairing` (S-04), `state_document` (S-06/S-07/S-32/S-33), `route_set` (S-16), `exit_offer`, `relay_token` (S-30), `idempotency` | **Partially.** Everything but `idempotency` can be rebuilt from the log, because every durable event is independently applicable (N-5). `idempotency` holds recorded ceremony outcomes that exist nowhere else; losing one turns a client's retry into a re-executed ceremony |

Every file is **idempotent to re-run**: every statement is `IF NOT EXISTS` or
`CREATE OR REPLACE`.

**The schema enforces the invariants; it does not trust the application.** Every
monotone rule is a `CHECK`, a `UNIQUE`, or a trigger, *and* is enforced again in
`src/tx.rs`. That duplication is deliberate: ADR-0008 §7.1 calls the
anti-rollback property "a genuine security control", and a security control with
exactly one enforcement point is one bug away from absent.

**There is no `relay` table here.** Finding **W-3** rules that `architecture.md`
§5 wins over §2.8's prose: the relay fleet registry **and** its ranking (S-09)
are `relay-directory`'s and live in `twinvpn_relay_directory`. This database
keeps only **S-30**, the `RelayCapabilityToken` issuance record, which a relay
never reads — it verifies an `Owner`-rooted token offline, which is what makes
relay admission survive a partition of any duration.

---

## 14. Tests

`cargo test -p twinvpn-control-plane` — **169 tests**, all executed.

| File | What it proves |
|---|---|
| `tests/idempotency_ceremony.rs` (10) | a `CompletePairing` replay returns the original outcome **byte for byte, even when the retry carries a different attestation**; a duplicate `BeginPairing` returns the original `pairing_id` and the original window; a cancelled id is burnt; a duplicate outside the 24 h window is refused by the precondition, not the window; one device cannot replay another's key; a key reused across commands is refused; nothing `Owner`-signed is admitted without an anchor |
| `tests/ordering_and_publisher.rs` (17) | a forged publisher cannot reach the log and consumes no position; a durable event cannot be emitted ephemerally and an ephemeral one cannot be logged; presence appends nothing and carries `net_seq == 0`; `net_seq` is dense; an advertisement epoch must strictly advance; a device cannot advertise another's routes; an `Owner`-signed advertisement is refused; the revoked set never shrinks; a lease-less write is refused; an E-1-class write without quorum is refused, never partially applied; **an event carries the causation of the request that produced it and no `correlation_id`** |
| `tests/atomicity_and_policy.rs` (10) | **the crash between the mutation and its event loses both**; a refused write appends nothing; the dedup record and the effect land together; a device-signed, unsigned, unconditional or rolled-back policy is refused; a fork is a security event; the bundle is warehoused and served verbatim |
| `tests/stream_and_backpressure.rs` (12) | a cursor inside the floor resumes rather than reloads; one below it is refused with the floor named; a breached backlog **announces** the gap; the TCP rungs halve the watermark; the write budget refuses a flood; reads and ceremony replays are not charged; a second attach supersedes the older; an over-limit attach is deferred **with a number** |
| `tests/client_agreement.rs` (10) | every event's durability and publisher match `twinvpn-cp-client`'s own table, read as text; the server knows exactly the 24 events `control_events.proto` declares; the ceremony set and the document types match the matrix and the client; the eleven §3.1 requests are forbidden on both sides; **the v6 derivation's `info` string, ULA, both reserved ranges and U/L clear match `twinvpn-route`'s `plan.rs` and `device.proto`**; the document digest is SHA-256 |
| unit tests (110) | the framing bounds, the reason-code evidence, the config refusals, the address derivation against `twinvpn-crypto` and the allocator's reserved-range skips, the transaction, **real COSE_Sign1 verification — a genuine signature admitted, the wrong device's key refused, a flipped byte refused, an impostor against the pinned anchor refused**, the 0-RTT source check, the migration `CHECK` lists |

The **security** tests specifically: `a_complete_pairing_replay_returns_the_original_outcome_byte_for_byte`,
`a_forged_publisher_cannot_reach_the_log_and_leaves_nothing_behind`,
`a_durable_event_can_never_be_emitted_ephemerally`,
`a_policy_bundle_signed_by_a_device_is_not_a_policy_bundle`,
`an_advertisement_that_verified_against_the_owner_chain_is_refused`,
`a_transaction_abandoned_after_the_mutation_loses_the_mutation_too`,
`the_revoked_set_never_shrinks_and_the_epoch_never_decreases`,
`nothing_owner_signed_is_admitted_without_an_anchor`,
`a_breached_backlog_announces_the_gap_and_never_omits_it`,
`nothing_in_this_module_calls_into_0rtt`,
`a_real_signature_verifies_and_the_wrong_device_key_does_not`,
`a_flipped_byte_breaks_the_signature`,
`an_owner_signed_statement_verifies_against_the_pinned_anchor`,
`the_real_verifier_admits_no_owner_statement_without_an_anchor`,
`the_v6_derivation_matches_the_clients_address_plan`.
