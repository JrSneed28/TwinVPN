# `twinvpn-control-plane`

The server side of channels **C1** (request/response) and **C2** (the resumable
durable event stream). Its client is
[`twinvpn-cp-client`](../../core/crates/twinvpn-cp-client/), a different artifact
in a different cargo workspace; this crate is its exact counterpart and links no
core crate but `twinvpn-schema` and `twinvpn-types` (ADR-0018 §11.2 row 2.8).

**Status: implemented.** The C1 command surface, the C2 durable event stream,
the QUIC listener, mutual RFC 7250 authentication, the `Owner` delegation chain,
idempotency, the transactional outbox, the PostgreSQL store, migrations, health,
readiness and observability are all built and tested — 215 tests, `cargo fmt
--check`, `clippy -D warnings` and the broken-intra-doc-link gate clean. Two
gaps remain and both are **environment**, not design: `PgStore` is compiled but
has never executed, because this host has no PostgreSQL and no container runtime
(§9), and no OTLP collector has received a span. Everything else that is
deliberately absent is listed in §10 with its reason.

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
| `TWINVPN_CP_OWNER_DELEGATIONS_PATH` | path | `/run/secrets/control-plane/owner-delegations.hex` | no | **an empty set, which is a posture rather than a misconfiguration** — and it is announced at startup as a `WARN`, not discovered from a refusal. One base16 COSE_Sign1 `OwnerDelegation` per line, each **ORK-signed**; `#` comments and blank lines ignored. Empty means only a statement the **root key itself** signed is admitted, which ADR-0007 O5 does not expect for routine work. A line that is present but not base16, or a delegation the pinned anchor did not sign, **is a startup failure**. **New variable**, see §11 finding 8 |
| `TWINVPN_CP_OWNER_ANCHOR_VERSION` | u64 | `0` | no | `0`, which does not check. Non-zero refuses at startup any delegation naming a different anchor generation — S-32's "a delegation issued under an older anchor does not survive an anchor advance by default", so a half-applied anchor rotation fails loudly. Operator-supplied for the same reason `TWINVPN_CP_SHARD_EPOCH` is. **New variable**, see §11 finding 8 |
| `TWINVPN_CP_TLS_CERT_PATH` | path | `/run/secrets/control-plane/tls.crt` | no | the default path. **Unread by rung 1**: RFC 7250 carries the `SubjectPublicKeyInfo` alone, which is derived from the key, so there is no certificate to load. The variable is kept because `infra/README.md` §4.3 declares it and a TCP rung may yet want one |
| `TWINVPN_CP_TLS_KEY_PATH` | path | `/run/secrets/control-plane/tls.key` | no | the default path. **A key that cannot be read or parsed is a startup failure**, never a fallback to an unauthenticated listener: there is no code path in `service-common`'s TLS builder that produces a plaintext or client-auth-optional configuration |
| `TWINVPN_CP_DATABASE_MAX_CONNECTIONS` | u32 | `16` | no | 16 |
| `TWINVPN_CP_COORDINATION_ENDPOINTS` | comma-separated names | *(empty)* | no | **an empty list, which is legal.** These are the endpoints `RegisterDevice` returns, as **names** so GeoDNS reaches the nearest front-end (ADR-0011 DN-0) — a literal address here would pin every device that ever enrolled to one box. Blanks and a trailing comma are dropped: a templated compose file with one variable unset must not produce a hostname that does not resolve. **New variable**, not yet in `infra/README.md` §4.3 (§11 finding 8) |
| `TWINVPN_CP_SHARD_EPOCH` | u64 | `1` | no | `1`, the single-writer deployment that has never failed over. ADR-0009 §11.2's fencing token, presented on every write; **bumped by the operator on failover**, which is what stops a partitioned old leader writing behind the new one. It is configuration and not a value this process invents, because a process that could choose its own token could choose one high enough to win. **New variable**, see §11 finding 8 |
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

**Peer identity is bound and the listener accepts.** `identity::ChannelDerivedIdentity`
is the shipped verifier and `serve::ControlPlane` is the accept loop; §7.2 is how
a presented key becomes a `device_id`.

**The `Owner` delegation chain is evaluated.** See §7.3. Nothing on the
`Owner`-authority path is admitted on a signature alone any more.

One half-verified case remains, stated rather than implied: an
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

### 7.2 How a presented key becomes a `device_id`

ADR-0007 **N-32**: the `DeviceIdentityKey` **is** the RFC 7250 raw public key, and
"no separate transport credential exists". So the caller on a connection is not
looked up in a table this service could be persuaded to write — it is *derived*
from the key the peer proved possession of in the handshake, in two steps:

```text
  presented SPKI ──derive──▶ identity_id ──look up──▶ device_id
   identity.rs, pure, no I/O       device table, per request
```

**Step one** is `service-common`'s `binding::spki`, the single home for that
conversion in this workspace — "two copies that disagree both produce canonical
CBOR, of two different keys". It builds the dCBOR COSE_Key
`{1: 2, -1: 1, -2: x, -3: y}` and hashes it exactly as `identifiers.md` §2
defines, so the value this service computes is the one the device computed for
itself.

**Step two is the part only this service can do**, and it is worth stating why.
`service-common`'s `DerivedPreferred` binding documents that a rotated device
presents a *generation-N* key whose derivation is **not** its `device_id`, and
that closing that gap "needs the succession chain" — which the rendezvous and
presence may not fetch on a reconnect path (**I5**), so they pin a first claim
instead. This service **is** the chain: `RotateDeviceCredential` is one of its own
commands, and it re-indexes `device.identity_id` onto the successor the verified
`IdentitySuccession` names. So it does the strict thing the other services
cannot — `store::device_for_identity` resolves the derived identity through a row
this service wrote itself.

Three consequences follow, each of which is a test:

1. **A miss resolves to the derived value itself.** For a generation-0 key that
   *is* the `device_id`, and it is the only name that key can speak for. That is
   not a grant: every handler refuses it with `AUTH.PEER_UNTRUSTED` until a
   `RegisterDevice` admits it, and `register` refuses a `device_id` that is not
   the caller's — **a device enrols itself or not at all**.
2. **A rotated device keeps serving.** Its successor key derives to the
   `identity_id` its own record names, so it resolves to its original
   `device_id`, and `domain::caller_key` accepts that key as the signer for
   device-signed statements — the succession carries no public key, so the
   record cannot hold one, and the proof that this *is* the nominated successor
   is the derivation matching what the old key signed.
3. **The superseded key stops serving.** The predecessor's `identity_id` no
   longer resolves, and resolution is per request rather than cached per
   connection precisely so that a device which rotates on a live connection stops
   being served on the key it just superseded.

### 7.3 `Owner` power is scoped, and where that check lives

ADR-0007 **O5** is a two-tier hierarchy: an offline, phrase-derived
`OwnerRootKey` and a hardware-resident, ORK-delegated `OwnerSigningKey` per
admin device, so that "routine operations (enroll, revoke, publish policy) use a
hardware-resident OSK" and "the common path has no phrase and no ritual". Every
routine `Owner` operation is therefore **OSK-signed**, and each names a power:
`RevocationStatement` needs an "`Owner` OSK with `REVOKE`" (§11), policy needs
"one OSK signature with the matching power" (§535), enrolment needs "an OSK
device holding `ENROLL` power" (§463). §290 is explicit that "verifiers must
implement a delegation-chain check".

**What it looked like without one.** `CryptoVerifier` admitted only statements
signed by a key in the pinned anchor file. With the ORK public key there — which
is what an `OwnerTrustAnchor` is — an OSK-signed revocation, policy or pairing
revocation verified against nothing and was refused, so the recovery phrase had
to be reconstituted for every routine operation. The workaround an operator
reaches for is to put the **OSK** keys in the anchor file, and then every admin
key silently carries every power: a phone delegated only `ENROLL` could revoke
the whole fleet and publish a policy bundle. Both branches are wrong, and the
second is the one that actually happens.

**How it works now.** `TWINVPN_CP_OWNER_DELEGATIONS_PATH` holds ORK-signed
`OwnerDelegation` statements. `CryptoVerifier::with_delegations` verifies each
against the pinned anchor **once, at startup** — a delegation the root did not
sign is a startup failure, not a refusal nobody sees until someone tries to
revoke a stolen laptop — and decodes it through `twinvpn-crypto`, which owns the
CDDL, the closed `OskPower` enum and the rule that "an unrecognised power is a
**rejection**, not an ignored entry". `verify::admit` then applies
`StatementKind::required_power` to whoever signed.

Two documents are checked, for different reasons:

| | Checked against | Because |
|---|---|---|
| the **signer's** delegation | `required_power` for the statement kind | a key may do only what the `Owner` granted it |
| the **statement's own** delegation, for the enrolment proof | `ENROLL` | `RegisterDevice`'s authorisation *is* a delegation, and one granting only `POLICY` is not permission to join, however impeccably it is signed |

The root itself is unscoped, deliberately: `signer_delegation` is `None` when the
ORK signed, and checking a power against the root would be checking it against a
grant it issues. Expiry is checked at **use**, not at load — this process
outlives the file it read, and a delegation that lapses at 03:00 must stop
working at 03:00 rather than at the next restart (`AUTH.CRED_EXPIRED`). An absent
power is `AUTH.UNEXPECTED_DELEGATION`, carrying the `osk_id` the registry
declares as its evidence field, because an operator needs to know *which* admin
key was asked to do something it was not delegated.

**Why this is not `twinvpn-trust`'s job after all.** An earlier draft of this
README said chain evaluation belonged there and that this artifact could not do
it. That was wrong twice over. `twinvpn-trust` depends on `twinvpn-env`,
`twinvpn-store` and `twinvpn-platform` — linking it is not a dependency line, it
is the core, which ADR-0018 §11.2 row 2.8 forbids outright. And it is not
needed: the decoders, the closed power enum, the unknown-power rejection and the
signature verification all live in `twinvpn-crypto`, already a permitted edge.
What is left here is a comparison of decoded fields against a table — the same
shape as `admit`'s authority table and the succession checks — and it is written
once, in one place.

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

   **The shipped binary nevertheless runs on `PgStore` and nothing else.**
   `MemStore` is reachable from tests and from no configuration. The pool is
   built with `connect_lazy`, so a database that is restarting produces
   `/healthz` 200 with `/readyz` 503 rather than a crash loop during exactly the
   window an operator is trying to observe.
2. **No container.** Nothing in this component has been built into an image or
   run under `docker compose`.
3. **No OTLP collector.** Observability goes through `service-common`, whose own
   README §11 records the same gap.

**What *is* now executed, and was not before:** the QUIC listener.
`tests/serve_end_to_end.rs` starts the real `serve::ControlPlane` on a loopback
port and drives it with a real `quinn` client presenting a real RFC 7250 raw
public key — a real TLS 1.3 handshake, a real RFC 9266 exporter compared across
the two sides, real C1 frames, real transactions and a real C2 record. Signature
verification is likewise exercised end to end elsewhere: real COSE_Sign1
statements signed with `twinvpn-crypto`'s fixtures, verified, tampered with and
re-verified.

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
4. **The `Owner` delegation chain is evaluated from a provisioned set** (§7.3),
   not from a chain presented per request. The frozen contracts give no request
   field for one — `RevokeDeviceRequest` carries a `revocation_statement` and
   nothing else — so the delegations are pinned alongside the anchor, exactly as
   the anchor itself is. That is a real limitation: a freshly minted OSK does not
   work until it is provisioned here. It is also the only shape the contracts
   admit, and it is reported as such (§11 finding 15).
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
7. **No `LogHead` is emitted.** It is signed by an online control-plane key this
   build does not have, and it "does not defend against a compromised control
   plane" — losing it costs a freshness proof and nothing else.
8. **The C2 pump polls the log; there is no broadcast bus.** `serve` asks
   `events_from` every 50 ms when a stream is idle. Polling, not a bus, on
   purpose: the log is the only thing that knows the committed order, and a bus
   would be a second ordering to keep in step with it. ADR-0002 N-5 makes every
   durable event independently applicable, so a device that learns of one 50 ms
   late applies it identically. The cost is one indexed query per attached device
   per interval, and it is a real cost at fleet scale — the replacement is
   `LISTEN`/`NOTIFY` on the same transaction, which `TWINVPN_CP_EVENT_BUS` names
   and this build does not implement.
9. **`StreamCompacted` is announced on the connection, not appended to the log.**
   `session::Attachment::pump` reports `Pumped::Compacted`, `serve` writes the
   announcement as a C2 record built through `DurableEvent` — so its publisher
   and durability come from the one table the client checks — and only then moves
   the cursor. It is deliberately **not** logged: a shed backlog is a fact about
   one connection's queue, and logging it would hand every other device a
   position describing a queue it does not have. `EventKind::StreamCompacted`
   remains classified durable because that is what `control_events.proto` and the
   client's table say, and `tests/client_agreement.rs` pins the agreement.
10. **Each connection serves one C2 stream, started by its first
    `SubscribeEvents`.** A second subscribe on the same connection is answered as
    the read it is and starts no second pump: one identity with two cursors over
    one log is the defect N-1 exists to prevent, and a device that wants a
    different cursor reconnects.

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
| 8 | **new variables** | `TWINVPN_CP_OWNER_ANCHOR_PATH`, `TWINVPN_CP_COORDINATION_ENDPOINTS` and `TWINVPN_CP_SHARD_EPOCH` (§3) are not in `infra/README.md` §4.3. Each needs a row there; the anchor path additionally needs the compose secret mount before an anchor can be provisioned in the local stack. |
| 9 | **defect, fixed** | The `Owner` **delegation chain** was not evaluated, and the earlier reading of that gap was too kind. ADR-0007 O5 makes every routine `Owner` operation OSK-signed, so with the ORK key in the anchor file an OSK-signed revocation, policy or pairing revocation **verified against nothing** — the recovery phrase was required for routine work — and the workaround an operator reaches for (OSK keys in the anchor file) makes every admin key unscoped: an `ENROLL`-only phone could revoke the fleet. Now evaluated (§7.3) through `twinvpn-crypto`, which was a permitted edge all along; `twinvpn-trust` was never the answer, because it pulls in `twinvpn-env`, `twinvpn-store` and `twinvpn-platform` and ADR-0018 §11.2 row 2.8 forbids linking the core. |
| 15 | **contract gap, resolution stated** | No request message carries an `OwnerDelegation` alongside the statement it authorises, so a signer's chain cannot travel with the operation. ADR-0007 §486 gives the chain to **devices** during pairing and says nothing about the coordination service. Resolved by **provisioning**: the delegations are pinned beside the anchor (`TWINVPN_CP_OWNER_DELEGATIONS_PATH`), which is reviewable, is verified against the root at startup, and needs no contract change — at the cost that a newly minted OSK does not work until it is provisioned. Reported rather than patched into `contracts/`. |
| 10 | **defect, fixed** | `CompletePairing` verified the attestation against the caller's own key and then never compared the attestation's `pairing_id` to the ceremony it was completing. **Any registered device could complete any pending pairing** by signing an attestation of its own: the signature verified, the request's `pairing_id` selected the victim's row, and the two were never compared. `pairing.proto` says the coordination service "TRANSPORTS attestations it CANNOT FORGE, so it cannot inject a `TrustedPeer`" — forging is not the only way to inject one, and mis-routing a genuine attestation is the other. Now refused with `AUTH.PAIRING_NOT_AUTHORIZED`, fail-closed (a binding that cannot be read is not established). `tests/authorization.rs`. |
| 11 | **defect, fixed** | `CancelPairing` checked no participant at all, so **any member could cancel any ceremony** — and cancelling burns the id permanently, so it was a fleet-wide denial of pairing one id at a time, recorded in the durable log as a `PairingRejected` attributed to nobody. Now restricted to `row.initiator`, which is the only participant this service knows: `PairingRequest` names no responder. |
| 12 | **defect, fixed** | `RegisterDevice` never compared the body's `device_id` to the authenticated caller. With the peer verifier unbound this was unreachable; with it bound it was live, and the enrolment proof does not close it — that proof says an OSK approved *a* join, not *which device* is joining, because it is issued before the joining device ever contacts this service. A holder of one could have taken another device's name, its **immutable** S-08 addresses and its place in the peer set. Now `AUTH.IDENTITY_MISMATCH`, with the enrolled key required to be the key on the wire whenever there is a connection to check against. |
| 13 | **contract gap, resolution stated** | `IdentitySuccession` names `new_identity_id` and carries **no public key**, and `RotateDeviceCredentialRequest` has no field for one — so a rotated device's successor key can never be recorded. Resolved without a contract change: the record is re-indexed onto `new_identity_id`, and `domain::caller_key` accepts the connection's proven key as the signer when it derives to that value. The proof is the derivation matching what the old key signed. Reported rather than patched into `contracts/`. |
| 14 | **schema addition** | `migrations/0004_identity_index.sql` adds `UNIQUE (twinnet_id, identity_id)`. It is a **security control**, not an optimisation: without it one presented key could name two devices and whichever row the planner returned first would become the authenticated caller. 0001 could not see this case because it predates the binding. |

---

## 12. Local startup and debugging

```bash
# From the repository root, with .env prepared per infra/README.md §4.1.
#
# MIGRATIONS ARE A SEPARATE, DELIBERATE ACT. The serving path never touches the
# schema; `migrate` applies migrations/ and exits, connecting EAGERLY because an
# operator running one is present and waiting to be told the database is
# unreachable.
docker compose run --rm control-plane migrate   # not exercised here; see §9
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
| `/readyz` 503, `/healthz` 200 | the datastore is unreachable. The JSON body names the probe and its registered code. A restart will not help. **This is the designed answer while PostgreSQL is restarting** — the pool connects lazily precisely so the process does not crash-loop through that window |
| startup fails naming `TWINVPN_CP_TLS_KEY_PATH`'s file | the key is missing or unparseable. There is no fallback to an unauthenticated listener, by construction |
| every request answers `AUTH.PEER_UNTRUSTED` | the caller's key resolves to no device in this `TwinNet`. Either it has not registered, or it **rotated** and this is the superseded key — see §7.2 |
| `RegisterDevice` answers `AUTH.IDENTITY_MISMATCH` | the body's `device_id`, or its `identity_public_key`, is not the caller's. A device enrols itself or not at all |
| `CompletePairing` answers `AUTH.PAIRING_NOT_AUTHORIZED` | the attestation names a different ceremony, or the row does not exist. Not a signature failure: the signature verified |
| an `Owner`-signed command answers `AUTH.UNEXPECTED_DELEGATION` | the signing key's delegation does not carry the power that command needs. The log line names the `osk_id`. **Not a signature failure** — the signature verified and the key is genuinely delegated, just not for this |
| an `Owner`-signed command answers `AUTH.CRED_EXPIRED` | the delegation's own `not_after_ms` has passed. Re-issue and re-provision it; restarting will not help |
| `RegisterDevice` answers `AUTH.UNEXPECTED_DELEGATION` | the enrolment proof is a delegation that does not grant `ENROLL` |
| startup fails naming `TWINVPN_CP_OWNER_DELEGATIONS_PATH` | a line is not base16, or a delegation is not one the pinned anchor signed. Both are refused rather than skipped |
| startup warns that **no delegations are loaded** | only the root key can author. See §7.3 — this is the posture that either needs the offline phrase for every operation, or means OSK keys were put in the anchor file where their powers are not scoped |
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

| `0004_identity_index.sql` | `UNIQUE (twinnet_id, identity_id)` — the peer binding's single-row lookup | **Yes** — dropping destroys no data and restores 0001's weaker guarantee |

Every file is **idempotent to re-run**: every statement is `IF NOT EXISTS` or
`CREATE OR REPLACE`.

**They are never run by the service.** `PgStore::migrate` is reachable only from
`twinvpn-control-plane migrate` (§12), which applies them and exits. A service
that migrated on startup would mutate a production schema on every deployment,
from every replica at once, before any review, with no operator present to read
the failure.

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

`cargo test -p twinvpn-control-plane` — **215 tests**, all executed.

| File | What it proves |
|---|---|
| `tests/idempotency_ceremony.rs` (10) | a `CompletePairing` replay returns the original outcome **byte for byte, even when the retry carries a different attestation**; a duplicate `BeginPairing` returns the original `pairing_id` and the original window; a cancelled id is burnt; a duplicate outside the 24 h window is refused by the precondition, not the window; one device cannot replay another's key; a key reused across commands is refused; nothing `Owner`-signed is admitted without an anchor |
| `tests/ordering_and_publisher.rs` (17) | a forged publisher cannot reach the log and consumes no position; a durable event cannot be emitted ephemerally and an ephemeral one cannot be logged; presence appends nothing and carries `net_seq == 0`; `net_seq` is dense; an advertisement epoch must strictly advance; a device cannot advertise another's routes; an `Owner`-signed advertisement is refused; the revoked set never shrinks; a lease-less write is refused; an E-1-class write without quorum is refused, never partially applied; **an event carries the causation of the request that produced it and no `correlation_id`** |
| `tests/atomicity_and_policy.rs` (10) | **the crash between the mutation and its event loses both**; a refused write appends nothing; the dedup record and the effect land together; a device-signed, unsigned, unconditional or rolled-back policy is refused; a fork is a security event; the bundle is warehoused and served verbatim |
| `tests/stream_and_backpressure.rs` (12) | a cursor inside the floor resumes rather than reloads; one below it is refused with the floor named; a breached backlog **announces** the gap; the TCP rungs halve the watermark; the write budget refuses a flood; reads and ceremony replays are not charged; a second attach supersedes the older; an over-limit attach is deferred **with a number** |
| `tests/client_agreement.rs` (10) | every event's durability and publisher match `twinvpn-cp-client`'s own table, read as text; the server knows exactly the 24 events `control_events.proto` declares; the ceremony set and the document types match the matrix and the client; the eleven §3.1 requests are forbidden on both sides; **the v6 derivation's `info` string, ULA, both reserved ranges and U/L clear match `twinvpn-route`'s `plan.rs` and `device.proto`**; the document digest is SHA-256 |
| `tests/authorization.rs` (19) | **a device enrols itself or not at all** — another device's name is refused, and so is a key it did not present; **one member cannot cancel another's ceremony**, and the initiator can cancel its own; **an attestation for another ceremony cannot complete this one**, and neither can one whose binding cannot be read; a rotation re-indexes the identity and **keeps the `device_id`**; the successor resolves to the original name and the superseded identity stops resolving; a succession that renames the device, skips a generation, or cannot be read is refused; **an `ENROLL`-only key cannot revoke a device or publish policy**, the key that holds the power can, an expired delegation authorises nothing, an enrolment proof granting only `POLICY` is not an approval, and the root is unscoped because every delegation chains to it |
| `tests/serve_end_to_end.rs` (9) | **the service, over a real mutually authenticated QUIC connection.** A device registers and the echo is the value it derived; a device presenting one key **cannot register under another key's name over the wire**; a channel binding that is not this connection's is refused, and so is a request carrying none; an idempotent retry returns the recorded outcome and the log does not grow; **a C2 record actually reaches the device**, with the sole publisher and the position; an unassigned command code is refused and never guessed; **a client presenting no key cannot complete a handshake**; a second connection for one identity **closes the older one** |
| unit tests (128) | the framing bounds, the reason-code evidence, the config refusals, the address derivation against `twinvpn-crypto` and the allocator's reserved-range skips, the transaction, **real COSE_Sign1 verification — a genuine signature admitted, the wrong device's key refused, a flipped byte refused, an impostor against the pinned anchor refused**, the 0-RTT source check, the migration `CHECK` lists, the SPKI→`identity_id` derivation against `twinvpn-crypto`'s own, **a real ORK→OSK delegation chain scoping a real ES256 signature** (a `REVOKE`-only key admitted for a revocation and refused for a policy, an undelegated key refused however well it signs, a forged delegation and a superseded anchor version both failing startup), and **which key a device-signed statement is checked against** (the recorded one; a channel key that is not the recorded identity is ignored; a proven successor is admitted) |

The **security** tests specifically: `a_real_delegation_chain_scopes_a_real_signature`,
`an_undelegated_key_is_not_the_owner_however_well_it_signs`,
`a_delegation_the_anchor_did_not_sign_fails_startup`,
`a_delegation_from_a_superseded_anchor_fails_startup`,
`an_enroll_only_key_cannot_revoke_a_device`,
`an_enroll_only_key_cannot_publish_policy`,
`an_expired_delegation_authorises_nothing`,
`an_enrolment_proof_that_grants_no_enroll_power_is_not_an_approval`,
`a_device_cannot_register_under_another_devices_name_over_the_wire`,
`a_device_cannot_enrol_a_record_under_another_devices_name`,
`a_device_cannot_enrol_a_key_it_did_not_present`,
`a_member_cannot_cancel_another_members_pairing`,
`an_attestation_for_another_ceremony_cannot_complete_this_one`,
`a_completion_whose_binding_cannot_be_read_is_refused`,
`a_channel_binding_that_is_not_this_connections_is_refused`,
`a_request_carrying_no_binding_at_all_is_refused_the_same_way`,
`a_client_that_presents_no_key_cannot_complete_a_handshake`,
`a_second_connection_for_one_identity_closes_the_older_one`,
`a_succession_that_renames_the_device_is_refused`,
`a_succession_that_skips_a_generation_is_refused`,
`a_channel_key_that_is_not_the_recorded_identity_is_ignored`,
`nothing_but_one_raw_p256_key_is_identified`,
`a_complete_pairing_replay_returns_the_original_outcome_byte_for_byte`,
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
