# `twinvpn-relay-directory`

The Relay-Selection Service: the authoritative relay-fleet registry **and**
ranking (S-09), and the signed, versioned, cacheable `RelayMap`.

**Owner:** `relay-plane`.
**Authority:** [ADR-0006](../../docs/adr/ADR-0006-relay-discovery-and-failover.md)
§11.1–§11.7, `docs/architecture.md` §2.12 and §5 rows **S-09**/**S-31**,
[`contracts/proto/twinvpn/v1/relay.proto`](../../contracts/proto/twinvpn/v1/relay.proto).

---

## 1. Why this service owns the registry as well as the ranking

`architecture.md` §2.8's prose calls the Control Plane "the single authoritative
writer for … relay-fleet registry"; §5 row **S-09** assigns "`Relay` fleet registry
+ ranking" to the Relay-Selection Service (2.12). Both cannot hold under I8.

Finding **W-3** in `ownership.md` §8 rules that **§5 wins**, because
`architecture.md` names §5 as its own authority for single-writer questions.
Registry *and* ranking are this service's; the control plane keeps **S-30**, the
`RelayCapabilityToken` issuance record. `infra/postgres/initdb/10-databases.sh`
already reflects the split, and this crate implements it.

---

## 2. The three properties that shape every type here

### 2.1 The ranked set is cached state, never a per-connection call

ADR-0006 C1 and §11.3 rule 4: selection "never runs on the packet path".
`relay.proto`'s CF-7 entry is blunter — routing reservations through coordination
"would put the control plane in the data path and **BREAK I5**".

So a per-connection dependency is **not expressible**, not merely discouraged:

- **one route**, `GET /v1/relay-map/{operator_group_id}`, serving one whole
  document;
- its **only input is an operator group** — the unit of admission, shared by every
  device in a fleet;
- **no request body and no query string**, so no future field can smuggle one in;
- no `session_id`, `device_id`, `pair_tag`, `flow_id` or `relay_id` is nameable
  anywhere in [`src/api.rs`](src/api.rs).

[`tests/not_per_connection.rs`](tests/not_per_connection.rs) asserts all four
against the router and the source, so adding a per-connection route fails the
build rather than a review.

### 2.2 The client's own measurement overrides this service's ranking

S-31, R-12, ADR-0006 §11.2. The server's `server_rank` term is capped at **+100**
while the measurement terms are worth up to **−410**, so "any relay with a ≥100 ms
measured RTT advantage outranks any server preference, unconditionally".

[`rank`](src/rank.rs) implements that arithmetic, the server-side input type is
named **`ServerAdvice`**, and `measurement_always_beats_server_preference` pins
the guarantee. **The computed score is never published** — only `server_rank`,
`load_class`, `capacity_weight` and `admin_state` go into the map, because
publishing a computed ranking makes it authoritative in practice however it is
labelled (§12).

### 2.3 A cached set of size 1 is a design error

architecture §2.12, ADR-0006 §11.1 rule 3. `PublicationFloor::check` refuses to
publish a map in which any region falls below **2 `ACTIVE` relays across ≥2
`failure_domain`s**, and — separately — refuses a region not reachable over both
address families. A `DRAINING` relay does not count toward the floor, which is why
retiring is the two-step operation §10 describes.

---

## 3. Build and test

```bash
source build/toolchain/env.sh
cd services
cargo build -p twinvpn-relay-directory
cargo test  -p twinvpn-relay-directory
```

The full gate is the same as `services/relay/README.md` §3.

---

## 4. Environment configuration

`infra/README.md` §4.7's variables, plus every `twinvpn-service-common` one.

| Variable | Default | Required | If absent / if wrong |
|---|---|---|---|
| `TWINVPN_RELAYDIR_LISTEN_TCP` / `_QUIC` | `[::]:443` | no | — |
| `TWINVPN_RELAYDIR_TLS_CERT_PATH` / `_KEY_PATH` | `/run/secrets/relay-directory/tls.*` | **yes (file)** | startup fails |
| `TWINVPN_DATABASE_URL` ← `TWINVPN_RELAYDIR_DATABASE_URL` | **none** | **yes** | startup fails; a secret has no default, ever |
| `TWINVPN_RELAYDIR_MAP_SIGNING_KEY_PATH` | `/run/secrets/relay-directory/map-signing.key` | **yes (file)** | startup fails; no map can be signed |
| `TWINVPN_RELAYDIR_OPERATOR_GROUP_ID` | — | **yes** | startup fails |
| `TWINVPN_RELAYDIR_MIN_ALTERNATES_PER_REGION` | `2` | frozen | **lowering it is a startup failure** |
| `TWINVPN_RELAYDIR_MIN_FAILURE_DOMAINS_PER_REGION` | `2` | frozen | as above. Raising either is permitted |
| `TWINVPN_RELAYDIR_REQUIRE_LITERAL_ENDPOINTS` | `true` | frozen | `false` is a **startup failure**: relay reachability must not depend on DNS |
| `TWINVPN_RELAYDIR_REQUIRE_BOTH_FAMILIES` | `true` | frozen | relaxed only in the v4-only/v6-only overrides, where the relaxation is visible in configuration |
| `TWINVPN_RELAYDIR_MAP_TTL_MS` | `3600000` | no | **soft freshness only** |
| `TWINVPN_RELAYDIR_MAP_EXPIRY_ENFORCED` | `false` | **must stay false** | `true` is a **startup failure** (§11.1 rule 4) |
| `TWINVPN_RELAYDIR_REGION_SPREAD_MS` | `20000` | no | `T_REGION_SPREAD` |

**Endpoints are literals by type, not by validator.**
`fleet::RelayRecord::endpoints_v4`/`_v6` are `SocketAddr`, which **cannot hold a
hostname**. There is no parse step to forget, because a name has nowhere to go.
`TWINVPN_RELAYDIR_REQUIRE_LITERAL_ENDPOINTS` is therefore a declaration, and
setting it `false` would be declaring something untrue — hence the refusal.

**The map is stale-but-usable without limit.** `map.rs` has no `is_expired`, no
`valid_at` and no clock read at all, and a test asserts their absence: a method
like that is how an expiry check appears three refactors later.

---

## 5. Health and readiness

`infra/README.md` §5 for this service: *Postgres reachable; signing key loaded;
the current map satisfies ≥2 alternates / ≥2 failure domains.*

| Probe | Red when |
|---|---|
| `map_signing_key` | no signer is installed — an unsigned map is never published |
| `alternates_floor` | the registry's current contents would breach `PublicationFloor` |

The floor probe is the interesting one: a directory serving a map that breaches the
floor is handing every device a candidate set that cannot survive one failure, so
it reports **not ready** rather than serving quietly. That makes the floor an
operational fact, not only a publication-time check.

Devices with a cached map are unaffected by any of this — §11.1 rule 4 — which is
why an unready directory is not an outage for anyone already running.

---

## 6. HRW, and why redistribution does not use the score

ADR-0006 §11.7: "Independent score-optimising choice — every device picking 'the
best surviving relay' — is precisely what creates the hot spot, and is why HRW
rather than score decides *redistribution* while score decides *ordinary
selection*."

`rank::hrw_top_k` implements `w(r) = hash(relay_id ‖ pair_id) × capacity_weight`
by way of [`rank::hrw_weight`](src/rank.rs),
takes the top `k = 3`, breaks ties on `relay_id` so two devices with the same map
agree exactly, and skips non-`ACTIVE` relays. Tested for proportional spread,
determinism, and capacity-weight sensitivity — "an operator changes fleet balance
by publishing weights, not by touching clients" (§10).

The hash is injected (`rank::Hrw64`) for the same CD-I2 reason as §7, and because
testing-strategy A-14 requires it to be **seedable** for a deterministic
region-failure test. §7.1 records that the reduction is now byte-identical to
`twinvpn-relay-client`'s, and that the digest itself is not yet bindable.

---

## 7. Signing — the contract document, with one seam left

ADR-0006 §11.1: one COSE_Sign1/CBOR document per operator group, "issuer Ed25519
over the canonical encoding (ADR-0003)". `twinvpn-crypto` is now a permitted edge
for the relay plane, and most of that is bound for real.

**What changed, and why it matters.** An earlier revision signed a bespoke
big-endian byte layout. It had the *determinism* a signature needs — fixed field
order, sorted collections, no map iteration — but nothing else: **no device could
have verified it, because it was not the document the contract defines**.
`map_version` being covered by a signature is worth nothing if the thing signed is
not a `relay-map`.

[`map_cbor`](src/map_cbor.rs) now encodes the frozen
`contracts/cddl/twinvpn/v1/signed_statements.cddl` §15 `relay-map` — with the CDDL
key number in every field's comment — as ADR-0003 deterministic CBOR through
`twinvpn_crypto::emit`, and wraps it in a real RFC 9052 §4.4 `Sig_structure` with
`alg` in the **protected** header. `render` serves the assembled envelope **and
nothing beside it**: anything beside it is unsigned by construction and invites a
reader to use it.

Two consequences worth naming:

- **Endpoints are `[bstr .size 4|16, uint]`.** A hostname has no representation in
  that shape, so ADR-0006 §11.1 rule 1 holds at the *encoding* as well as at
  `RelayRecord`'s `SocketAddr`. A family mismatch is dropped, not coerced.
- **The `crit` set names `map_version`** (CDDL key 5), so a verifier that does not
  understand version monotonicity must refuse the document rather than apply it —
  which is what stops an older build silently accepting a rollback.

**The one seam left is the raw Ed25519 operation.** `twinvpn-crypto` verifies
(`verify_cose_sign1`) and assembles, but signing goes through a custody boundary —
its own docs hand `to_be_signed()` to `IdentityCustody::identity_sign` — and there
is no server-side custody implementation. So [`sign::MapSigner`](src/sign.rs) is
the seam for exactly that one operation, [`sign::Unsigned`] is the default, and an
unsigned map is **refused rather than published**: §10 says "a bad publish must
not disarm the fleet", and a failed publish does not advance `map_version` (a
test pins it).

**Decision needed:** a server-side Ed25519 signing path for the map issuer —
either an `IdentityCustody` implementation for `services/`, or a signing entry
point on `twinvpn-crypto` for keys that legitimately live in a file.

### 7.1 HRW is now byte-identical to the client's

ADR-0006 §11.5's cold-start convergence works only if the device and this service
compute the *same* function — "both devices compute this from their own cached
maps, with no message exchanged". [`rank::hrw_weight`](src/rank.rs) is therefore
`twinvpn-relay-client::hrw::weight` transcribed exactly: the **leading eight
bytes** of the digest, as a **little-endian** `u64`, `>> 16`, times
`capacity_weight` — with `HRW_K = 3` to match, and a test that pins each of those
four choices. An earlier revision here used a `u128` product over a `u64` hash and
clamped capacity up to 1; the second of those would have let a relay an operator
drained to zero keep taking pairs.

The digest itself is `BLAKE2s(relay_id ‖ pair_id)` and is **not bindable**:
`twinvpn-crypto` exposes no BLAKE2s. `twinvpn-relay-client/src/hrw.rs` carries the
identical open item, so it is one shared gap — see `services/relay/README.md` §8.

## 8. Known limitations

1. **The fleet registry is in memory.** `fleet::FleetStore` is a trait so the
   Postgres implementation lands without touching anything above it. `sqlx` is
   declared in `services/Cargo.toml`'s workspace set but no member has ever built
   it, so it is absent from `services/Cargo.lock` and cannot be resolved on this
   host (no network). `twinvpn_relay_directory` **is not durable yet**, and S-09 is
   a durable, authoritative row.
2. **Nothing signs.** §7 — the document is now the contract's, but the raw
   Ed25519 operation has no server-side implementation, so `MapBuilder::publish`
   refuses rather than emitting an unverifiable map.
3. **The map is served over plain HTTP.** The TLS paths are loaded and validated,
   but `rustls` is likewise absent from the lock. The map is a signed document, so
   its *integrity* does not depend on the transport — but the transport is not what
   `infra/README.md` §4.7 describes.
4. **No publication loop.** `MapBuilder::publish` is complete and tested; the
   periodic rebuild-and-publish task is not wired, because with (1) there is
   nothing to rebuild *from*.
5. **No container has been built or run.** Docker is absent from this host.
6. **HRW cannot be computed in production.** §7.1 — the reduction matches the
   client byte for byte, but `BLAKE2s` is unavailable to either side.
7. **The frozen `relay-map` has no regions field.** `map_cbor` therefore does not
   encode adjacency, and it is flagged in the module rather than invented:
   adjacency reaches a device through `RelayAssignment` in `relay.proto` instead.
   If ADR-0006 §11.1's `regions[]` is meant to be *inside* the signed document,
   the CDDL and the ADR disagree and the CDDL is frozen.
8. **The `+100` cap and the `+120` self-hosted bonus.** §11.2's composition
   sentence says "the server's total contribution is capped at +100", while its own
   table lists `Self-hosted +120`. This crate reads the cap as applying to the
   `server_rank` term, which is what §11.2's self-hosted paragraph then says
   explicitly ("+120 points ≈ 120 ms of tolerated extra RTT"). Flagged to the
   integration lead as a wording ambiguity rather than resolved silently; the
   reading is recorded in `rank.rs`'s tests.
