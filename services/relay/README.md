# `twinvpn-relay`

The ciphertext-only relay data plane: authenticated `Noise_IK` legs,
`BIND`/`BOUND` keyed by `pair_tag`, opaque frame forwarding, offline
`RelayCapabilityToken` admission, resource control, and herd-safe drain.

**Owner:** `relay-plane` ([`docs/implementation/ownership.md`](../../docs/implementation/ownership.md) §2).
**Authority:** [ADR-0005](../../docs/adr/ADR-0005-relay-architecture.md) (the whole
document), [ADR-0006](../../docs/adr/ADR-0006-relay-discovery-and-failover.md) §11.4/§11.5,
[`contracts/proto/twinvpn/v1/relay.proto`](../../contracts/proto/twinvpn/v1/relay.proto),
`docs/architecture.md` §5 rows **S-29** and **S-30**.

---

## 1. The one property everything else is subordinate to

**I1 / invariant P1: relay infrastructure must never require plaintext access to
TwinVPN tunnel payloads.** A relay is on the data plane and *outside* the trust
boundary (architecture §8, B3). It forwards frames it cannot interpret.

ADR-0005 §7.1 makes that structural rather than aspirational by enumerating the
relay's *entire* key inventory as a closed set of three items:

| Key | Where it is here | Relationship to L-DATA |
|---|---|---|
| relay static X25519 | a **path** in [`config`](src/config.rs); read once into the locked allocator by [`admit::LegSetup`](src/admit.rs) | not a party to `Noise_IKpsk2` |
| issuer public-key set | [`issuer::IssuerKeySet`](src/issuer.rs) | verification-only, public |
| per-leg `K_leg` | [`crypto::LegKey`](src/crypto.rs) | domain-separated; **MAC only** |

Eight checkable properties, in [`tests/cannot_decrypt.rs`](tests/cannot_decrypt.rs):

1. `the_key_inventory_is_exactly_three_items` — reads `src/crypto.rs` and
   `src/config.rs` and fails if a fourth key type appears anywhere.
2. `no_decrypt_operation_exists_anywhere` — `RelayCrypto` declares exactly four
   methods (`verify_statement`, `verify_frame_mac`, `frame_mac`, `digest16`) and
   nothing in the crate calls a decryption verb.
3. `the_payload_type_has_no_reader` — the payload is a
   `twinvpn_service_common::Verbatim` built through `Verbatim::from_opaque`: no
   decode, no `Display`, no `Serialize`, and a `Debug` that prints a length, a
   channel and the framing token.
4. `the_payload_survives_forwarding_byte_for_byte` — over a corpus including
   bytes that *would* decode as protobuf with an unknown field, which is W-4's trap.

The leg handshake added four more, and they are the ones that had to be written
the moment a `Noise_IK` responder landed here. A `Noise_IK` handshake naturally
ends in a transport session holding two ChaCha20-Poly1305 keys — a **fourth**
entry in §7.1's inventory, and one with an `open()` on it:

5. `the_handshake_returns_a_mac_key_and_no_cipher` — the handshake is completed
   inside `twinvpn-crypto`, and the only thing that crosses back is
   [`CompletedLeg`](../../core/crates/twinvpn-crypto/src/relay_leg.rs), whose
   entire surface is `k_leg`, `remote_static` and `payload`. Asserted on **both**
   sides: no `TransportSession`, `into_transport`, `seal` or AEAD name appears in
   this crate, and the producer never enters Noise transport mode.
6. `the_relay_leg_is_a_different_protocol_from_l_data` — `Noise_IK_25519_ChaChaPoly_BLAKE2s`,
   not L-DATA's `Noise_IKpsk2_…`. Different pattern, different prologue, **no psk
   slot**, so `TwinNetPSK` cannot be an input; and this crate never imports the
   L-DATA Noise driver at all.
7. `the_relays_static_key_is_read_only_behind_the_leg_seam` — exactly four files
   may name it, each for a reason a reviewer checks in one line.
8. `the_handshake_payload_is_a_token_and_never_a_tunnel_key` —
   [`TokenPresentation`](src/admit.rs)'s whole field set.

Properties 1–3 and 5–8 are **source assertions**, deliberately. A decrypt path is
something that must not *exist*, and only reading the source can assert absence.

---

## 2. What a relay operator can still observe

Stated plainly, because ADR-0005 §7.2 requires it to be. This is the designed
maximum, not a gap.

| Observable | Why forwarding requires it | What this build does about it |
|---|---|---|
| **Both peers' underlay IP:port** | it must send frames somewhere | nothing possible. Identical to any on-path observer, which is the trust level B3 already assigns. Never logged, never a metric label |
| **That two half-flows are joined** | it must forward between them | the join key is a `pair_tag`, not an identity. `PairTag` has a redacted `Debug` and no `Display` |
| **`pair_tag`** | it is the join key | 16-byte HKDF output, scoped to one `relay_id` and one 10-minute bucket (frozen in `limits.json`), useless at another relay or bucket. Never rendered |
| **Frame counts, byte counts, sizes, timing** | it forwards and meters | nothing. ADR-0001 K5 already declines traffic-analysis resistance |
| **Token claims: `aud`, `exp`, `epoch`, quota class** | admission and metering | `sub` is a per-operator per-day pseudonym, never `device_id` |
| **Within one operator group and one day, all of a device's flows** | quota needs a stable subject | the residual §7.2 and §13 accept. Removing it needs anonymous credentials, which I2/C1 forbid |

**Not observable, by construction:** `device_id`, TwinNet membership, overlay
addresses, DNS, routes, plaintext, peer identity keys, and — the one this build
adds — *cross-day* linkage in operational logs, because a subject reaches a log
line only as a **daily re-hash** ([`subject::LogSubject`](src/subject.rs), ADR-0005 §10).

What was done to minimise the rest:

- `TWINVPN_RELAY_RETAIN_PEER_PAIR=true` is a **startup failure**, not a warning.
- The metric label allowlist is frozen to ADR-0015 §9's five; a sixth is a
  startup failure.
- `peer_key_id` and every equivalent name is absent from the whole crate, asserted
  by [`tests/privacy_and_persistence.rs`](tests/privacy_and_persistence.rs).
- There is **no relay-specific HTTP route** and no flow-dump endpoint. Per-session
  relay debugging is deliberately impossible (ADR-0015 §13).

---

## 2.1 The `DATA` payload bound, derived

`frame::MAX_DATA_PAYLOAD_BYTES` is **1456 bytes**, and it is argued rather than
looked up — `limits.json` has no B4 entry, which is consistent with B4's schema
artifact being *absent by design*.

The first version bounded the payload against `Channel::PeerDatagram` (1200 B,
`envelope.c4_max_bytes`). That is the **C4 rendezvous datagram** cap — a
pre-authentication signalling channel, deliberately given "the smallest safe
parser" — and a relay leg is bounded by **path MTU**, not by C4. It was not merely
the nearest available number: `docs/networking.md` §6.2 and ADR-0005 C7 fix an
overlay MTU floor of **1280**, §9.2 adds 32 B of L-DATA overhead beneath it, so
the smallest payload a conforming relay must carry is `1280 + 32 = 1312` — **above
1200**. The old bound made the 1280 floor unachievable on every carriage.

The derivation, from ADR-0005 §9.2's overhead table. A relay forwards one L-DATA
datagram byte for byte and never fragments (§11.1(5)), so the ceiling is the
carriage with the **least framing beneath `RelayFrame`** — `R-UDP` over IPv4:

```text
  1500   Ethernet underlay MTU (§9.2's stated basis)
  -  20  IPv4 header
  -   8  UDP header
  -  16  RelayFrame (§9.1)
  ------
  = 1456
```

which is §9.2's own arithmetic read the other way: that row's 1424-byte overlay
MTU plus 32 B of L-DATA overhead. Every other row — `R-UDP` v6, both `R-QUIC`,
both `R-TLS` — is smaller, because each adds framing beneath `RelayFrame`, so the
v4 `R-UDP` row binds across all four carriages and both families.

**At the top end** it is conservative on purpose. A link above 1500 could deliver
more, but nothing in Phase 1 contemplates one: §9.2 states 1500 as its basis and
lists only *lower* underlays (464XLAT 1480, PPPoE 1492), and DPLPMTUD searches
downward. Admitting jumbo frames would widen an attacker-driven allocation on the
highest-rate path in the system for traffic no ADR describes.

The margin is comfortable where it matters: 1456 clears the 1312 the floor
requires by **144 bytes**, and a violation is a **silent drop** — §11.5's zero
bytes for anything unauthenticated — so an oversized datagram costs an attacker a
packet and earns nothing.

---

## 3. Build and test

```bash
source build/toolchain/env.sh
cd services
cargo build -p twinvpn-relay
cargo test  -p twinvpn-relay

# The benchmarks print a table; --release matters (§13).
cargo test -p twinvpn-relay --release --test benchmarks -- --nocapture
```

The test binaries, and what each is for:

| Binary | What it holds |
|---|---|
| `--lib` | every module's unit tests: the framing, the limits, the DRR, the drain, the leg registry, the cookie |
| [`tests/cannot_decrypt.rs`](tests/cannot_decrypt.rs) | §1's eight properties. **Read this one first** |
| [`tests/privacy_and_persistence.rs`](tests/privacy_and_persistence.rs) | §2's minimisation claims, asserted from the source |
| [`tests/leg_and_traffic.rs`](tests/leg_and_traffic.rs) | a real device: leg, bind, forward, reconnect, restart, malformed input, unauthorized clients, expired tokens |
| [`tests/pressure_and_failover.rs`](tests/pressure_and_failover.rs) | abusive clients, overload, drain, cookies, loss, queue pressure, regional failover |
| [`tests/benchmarks.rs`](tests/benchmarks.rs) | §13 |
| [`tests/common`](tests/common/mod.rs) | the test device. **Nothing in it is a cryptographic stand-in** — real Ed25519 tokens, a real `Noise_IK` leg, real MACs, real sockets |

The gate, exactly as it is run:

```bash
cd services
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd .. && make test-contracts          # 35801 checks, 0 failures
```

`make test-contracts` needs `node_modules/.bin/buf`, which is absent in a
`git worktree`; symlink it from the primary checkout and remove it afterwards.

---

## 4. Environment configuration

Every variable is `infra/README.md` §4.6's and `docker-compose.yml`'s; this crate
invents none. Loading goes through `twinvpn_service_common::config::Loader`, so
"no secret has a default" and the typed-error behaviour are the same as everywhere.

| Variable | Default | Required | If absent / if wrong |
|---|---|---|---|
| `TWINVPN_RELAY_ID` | — | **yes** | startup fails. 16 lowercase hex = 8 bytes (`limits.json identifiers.relay_id_bytes`) |
| `TWINVPN_RELAY_REGION` | — | **yes** | startup fails; bounded by `region_id_max_bytes` |
| `TWINVPN_RELAY_FAILURE_DOMAIN` | — | **yes** | startup fails. The standby must be in a *different* one |
| `TWINVPN_RELAY_OPERATOR_GROUP_ID` | — | **yes** | startup fails; must match a token's `aud` |
| `TWINVPN_RELAY_ADMIN_STATE` | `ACTIVE` | no | `DRAINING`/`RETIRED` refuse new binds |
| `TWINVPN_RELAY_SELF_HOSTED` | `false` | no | affects ADR-0006 ranking only; **trust is unchanged** |
| `TWINVPN_RELAY_CARRIAGES` | `R-UDP,R-QUIC,R-TLS` | no | an unknown or empty list is a startup failure |
| `TWINVPN_RELAY_LISTEN_UDP` / `_UDP_443` / `_QUIC` / `_TLS` | `[::]:41641` / `[::]:443` ×3 | no | see §6 for which are actually served |
| `TWINVPN_RELAY_ISSUER_KEYS_PATH` | `/run/secrets/relay/issuer-keys.json` | **yes (file)** | startup fails. An **empty** set is legal and means *admit nothing* |
| `TWINVPN_RELAY_STATIC_KEY_PATH` | `/run/secrets/relay/static-noise.key` | **yes (file)** | startup fails. Never read into memory by this crate |
| `TWINVPN_RELAY_TOKEN_LIFETIME_MS` | `86400000` | frozen | any other value is a startup failure (`limits.json`) |
| `TWINVPN_RELAY_TOKEN_CLOCK_SKEW_MS` | `300000` | frozen | as above |
| `TWINVPN_RELAY_TOKEN_GRACE_MS` | `21600000` | no | `T_RELAY_GRACE`, relay-issued renewal |
| `TWINVPN_RELAY_PAIR_TAG_BUCKET_SECONDS` | `600` | frozen | a longer bucket is a longer linkage window |
| `TWINVPN_RELAY_PAIR_TAG_ACCEPTED_SKEW` | `1` | frozen | accept `bucket`, `bucket−1`, `bucket+1` |
| `TWINVPN_RELAY_MAX_FLOWS_PER_SUBJECT` | `64` | no | ⇒ `RELAY.FLOW_LIMIT_REACHED` |
| `TWINVPN_RELAY_RATE_PER_SUBJECT_MBPS` | `20` | no | token bucket, **throttle not drop** |
| `TWINVPN_RELAY_RATE_PER_FLOW_MBPS` | `10` | no | as above |
| `TWINVPN_RELAY_QUOTA_BYTES_PER_HOUR` | `21474836480` | no | leaky counter ⇒ `RELAY.QUOTA_EXCEEDED` |
| `TWINVPN_RELAY_BIND_PER_MINUTE_PER_SUBJECT` | `30` | no | ⇒ `RELAY.BIND_RATE_LIMITED` |
| `TWINVPN_RELAY_COOKIE_THRESHOLD_HANDSHAKES_PER_S` | `20` | no | per source **/24 (v4) or /48 (v6)** |
| `TWINVPN_RELAY_PENDING_SLOT_TTL_MS` | `30000` | no | ⇒ `RELAY.PAIR_UNMATCHED` |
| `TWINVPN_RELAY_IDLE_FLOW_TIMEOUT_MS` | `900000` | no | ⇒ `RELAY.FLOW_IDLE_TIMEOUT` |
| `TWINVPN_RELAY_FLOW_QUEUE_MAX_BYTES` | `65536` | no | `min(64 KiB, 250 ms × rate)`, tail-drop |
| `TWINVPN_RELAY_RETAIN_PEER_PAIR` | `false` | **must stay false** | `true` is a **startup failure** (O-13) |
| `TWINVPN_RELAY_METRICS_LABEL_ALLOWLIST` | ADR-0015 §9's five | frozen | any change is a **startup failure** |
| `TWINVPN_RELAY_MAX_TOTAL_FLOWS` | `65536` | no | **added by this domain, not in §4.6** — see below |
| `TWINVPN_RELAY_MAX_LEGS` | `65536` | fixed | **added by this domain**; a leg is created by a source that was unauthenticated one round trip ago, so the registry needs a ceiling (§6 rule 10) |
| *(compiled)* `MAX_LEGS_PER_PREFIX` | `1024` | fixed | **added by this domain**; the ceiling a global cap misses — see §8.1 |
| *(compiled)* `LEG_IDLE_TIMEOUT_MS` | `900000` | fixed | **added by this domain**; the same 15 minutes §11.5 gives an idle half-flow |

Plus every `twinvpn-service-common` variable (`TWINVPN_LOG_LEVEL`,
`TWINVPN_ADMIN_ADDR`, `TWINVPN_SHUTDOWN_*`, `TWINVPN_LIMITS_PATH`, …).

**`TWINVPN_RELAY_MAX_TOTAL_FLOWS` is an addition, stated as one.** ADR-0005 §11.5
bounds flows *per `relay_sub`*: 64 each. That bounds one attacker; it does not
bound how many subjects exist, so without a relay-wide ceiling the flow table has
no memory bound at all (`ownership.md` §6 rule 10). The default of 65 536 is 1 024
subjects at their full per-subject allowance.

**There is no control-plane variable, and that absence is load-bearing** (I5,
ADR-0005 RQ2, architecture A-12). `infra/README.md` §2.3 records the same absence
in the compose topology.

---

## 5. Health and readiness

| Path | Question | 503 when |
|---|---|---|
| `/healthz` | is the forwarder running? | the process is wedged |
| `/readyz` | can it serve? | issuer key set unloadable, or a configured carriage not bound |

The registry is built with **`ReadinessPolicy::NoControlPlaneCalls`**, which
*refuses* any probe declaring `ProbeKind::ControlPlane`. That is I5 made
structural: a relay cannot acquire a control-plane readiness dependency by
accident, because the builder returns an error.

**An empty issuer key set is ready.** `infra/README.md` §5 asks for "issuer key set
loaded and parsable", not "non-empty". A relay with no issuers is correctly
configured and correctly admitting nothing; reporting it not-ready would hide the
far more useful signal that a relay whose *file* is missing is genuinely broken.
It logs a `WARN` at startup instead.

---

## 6. Carriages — what is actually served

| Carriage | Status | Why |
|---|---|---|
| `R-UDP` (UDP/41641 and UDP/443) | **bound and serving**, IPv4, IPv6, dual-stack and IPv6-only | a real `tokio::net::UdpSocket` with a live receive loop ([`loop_udp`](src/loop_udp.rs)) |
| `R-QUIC` (UDP/443, QUIC DATAGRAM) | **not bound** | `quinn` is in `services/Cargo.toml`'s workspace set but no member has built it, so it is absent from `services/Cargo.lock` and cannot be resolved on this host; the leg additionally needs the RFC 8446 exporter no provider supplies |
| `R-TLS` (TCP/443, TLS 1.3) | **not bound** | same two reasons (`rustls`, and RFC 7250 raw-public-key client auth) |

`CarriageSet::bind` **fails closed**: an unavailable carriage is recorded, logged
at `ERROR`, and makes `/readyz` red. It does **not** bind a bare TCP socket on 443
and call it `R-TLS` — a listener that accepts a connection it cannot secure is
worse than no listener, because a device races to it and succeeds at the wrong
thing.

`net::observe_families` reports what a socket **actually** got rather than what was
configured, because `[::]` is dual-stack or v6-only depending on `bindv6only` and
`infra/`'s IPv6-only profile depends on the difference.

---

## 7. Observability

Structured logging and OTel through `twinvpn-service-common`'s `obs`, with one
service-specific rule.

**ADR-0015 O-13 — this service is the one stated exception to correlation
propagation.** `infra/otel/collector-config.yaml`'s
`transform/relay-severs-context` clears the parent span id and deletes
`twinvpn.correlation_id`, `twinvpn.causation_id` and `twinvpn.message_id` on every
`twinvpn-relay` span. O-14 requires redaction at *emit* time, and this crate's emit
side agrees:

- `observe::RelaySpan::root` starts every span with `parent: None`, so there is no
  remote parent for the collector to sever.
- `observe::RelayEvent` has **no** correlation, causation or message-id field and
  no constructor that takes one. `twinvpn_service_common::correlation` is never
  imported.
- No `pair_tag`, no `flow_id`, no peer address, no device identifier appears in a
  log line or a metric label. The only subject dimension is the daily re-hash, and
  it is a **log field only** — never a metric label, because a per-subject series
  is a per-device cardinality dimension on infrastructure.

`ownership.md` §6 rule 6 requires correlation ids across every component boundary.
The relay is the stated exception (`infra/README.md` §6.3), and the reason is that
a relay is not a component boundary in that sense — it is a forwarder that must
not know what it forwards.

**Payload capture is prevented structurally, not by filtering.** The payload's
`Verbatim` has no `Display` and a `Debug` that prints a length, a channel and the
framing token, so an enclosing `#[derive(Debug)]` renders
`Verbatim(1200 B on c1_c2_c7, opaque, <not rendered>)`. `crypto::LegKey` wraps
`Secret<[u8; 32]>`.

---

## 8. Cryptography — `twinvpn-crypto`, behind the seam

`services/Cargo.toml` now declares `twinvpn-crypto` as a permitted edge for the
relay plane (ADR-0018 **CD-I2**, and **DP-8**: at most two crypto providers
fleet-wide, so one audited crate rather than four primitive ones). The seam
[`crypto::RelayCrypto`](src/crypto.rs) is **kept** — it is what let every
admission policy be tested with no provider at all — and
[`provider::CryptoProvider`](src/provider.rs) binds the real implementation
behind it. [`crypto::FailClosed`](src/crypto.rs) remains the default when none is
configured, so an unconfigured relay is still a closed relay.

| Primitive | ADR | Bound to |
|---|---|---|
| COSE_Sign1 verification **over the received octets** | §11.3 | `twinvpn_crypto::verify_cose_sign1` |
| keyed BLAKE2s frame MAC, truncated to 64 bits | §9.1 | `twinvpn_crypto::frame_mac` / `verify_frame_mac` |
| one-way 16-byte digest (daily `relay_sub` re-hash) | §10 | `twinvpn_crypto::hkdf_sha256` |

All three are real. `frame_mac_available()` is kept rather than deleted: a build
that again could not MAC must say so in one startup `ERROR`, not present as a
flood of dropped frames.

**The truncation is the part worth checking twice.** ADR-0005 §9.1 says
"truncated to 64 bits", and BLAKE2 parameterises output length *inside the
initialisation block* — so `BLAKE2s(digest_length = 8)` and
`BLAKE2s(digest_length = 32)[0..8]` are **different functions over the same key
and the same input**. "Truncated" is the second. This crate pins it from the
consumer side, because the consequence lands here — a relay computing the other
reading verifies nothing while looking correctly configured.

**Both readings are imported, not copied** (W-33). `twinvpn_crypto::blake2s::vectors`
is a plain public module carrying the §9.1 and §11.7 vectors once, so the two
ends of the wire fail together rather than separately. An earlier revision of this
crate held its own copies and — pinning a rejected-reading pair taken from a
*different* key and input — made the discrimination pass for free. Importing
`FRAME_MAC_TAG` and `FRAME_MAC_TAG_SHORT_OUTPUT_REJECTED` means the `assert_ne!`
is bound to *this* key and *this* input, and `vectors::self_consistency()` proves
the published constants still agree with the implementation they describe.

**The assembled `FRAME_MAC_INPUT` is deliberately *not* imported as a literal.**
`this_crates_mac_input_matches_the_shared_golden_vector` imports the **field**
constants, builds the frame through **this crate's own** `RelayFrame::mac_input`,
and compares byte for byte. `twinvpn-crypto` owns the MAC and the truncation; this
crate owns the frame layout; if the two disagree about §9.1's field order or
widths, every legitimate frame is dropped and both sides look correct. Copying the
assembled bytes in would prove only that this crate can copy.

**The MAC input is not length-prefixed, deliberately.** §9.1's fields are
fixed-width except `payload`, which is last, so the encoding is already
unambiguous — the opposite call from the ADR-0020 §11.5 record AAD, where two
*variable-length* fields genuinely were ambiguous. Prefixing a specified wire
format would make this relay reject every legitimate frame.

### 8.1 Verification order, and why it changed

The first version checked `aud`, the validity window and `cnf` *before* the
signature, to avoid an asymmetric operation for obviously-wrong input. That
concern is real but was solved in the wrong place: `relay.proto` is normative that
a verifier "MUST verify the COSE signature and read the claims **FROM THE VERIFIED
PAYLOAD**", and ADR-0005 §11.3's order puts the signature first.

The anti-amplification control §11.5 actually specifies is the **cookie gate** —
"no asymmetric operation for an unvalidated source address" above 20 handshakes/s
per source /24 or /48 — which [`resource::CookieGate`](src/resource.rs) already
implements and which runs before any of this. So the ordering was re-solving a
solved problem at the cost of reading attacker-controlled claims. It now follows
the ADR, and [`token::PresentedToken`](src/token.rs) carries **only** the issuer
key id and the COSE_Sign1 envelope — there are no decoded claims on it to be
tempted by.

---

## 8.1 The leg — `Noise_IK`, and the fourth key that never crosses back

ADR-0005 §11.1(2): the leg is **`Noise_IK`** (X25519 / ChaCha20-Poly1305 /
BLAKE2s) for `R-UDP`. It lives in
[`twinvpn_crypto::relay_leg`](../../core/crates/twinvpn-crypto/src/relay_leg.rs)
— CD-I2 puts it there — and this crate drives it from [`leg`](src/leg.rs) and
[`admit`](src/admit.rs).

**The design decision worth reading twice.** A `Noise_IK` handshake ends in a
transport session with two ChaCha20-Poly1305 keys. That would be a *fourth* entry
in §7.1's three-item inventory, and one with an `open()` on it — so the handshake
is **completed inside `twinvpn-crypto`**, and the only thing that crosses back is:

```rust
CompletedLeg { k_leg: [u8; 32], remote_static: [u8; 32], payload: Vec<u8> }
```

`K_leg = HKDF-Expand(HKDF-Extract("", h), "twinvpn relay leg v1", 32)` over the
handshake hash — *not* either transport key, which is what lets the relay hold it
in ordinary memory for the life of a leg. The label is the one §11.1(2) already
fixes for `R-QUIC`/`R-TLS`'s RFC 8446 exporter, so all four carriages name one
value rather than three. `LegResponder::respond` consumes `self`, so the `snow`
state is dropped at the end of the call, and the private `finish` takes a
**shared** reference to the handshake state rather than the owned value — with
only `&HandshakeState` there is no way to complete into transport mode at all,
which makes the absence a property of a signature rather than of remembering not
to write a line.

It is deliberately **not** L-DATA's handshake:

```text
L-DATA     Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
relay leg  Noise_IK_25519_ChaChaPoly_BLAKE2s
```

Different pattern, different prologue, and **no psk slot**, so `TwinNetPSK`
cannot be an input. ADR-0005 §11.2 row ADR-0001(a) requires `RLK` to be
non-derivable from an L-DATA key; the strongest available form of that is no
shared key schedule at all.

### The order of operations *is* the anti-amplification argument

| # | Step | Cost to the relay | What it costs an attacker |
|---|---|---|---|
| 1 | length bounds | a comparison | — |
| 2 | per-prefix handshake rate | a counter | — |
| 3 | **cookie challenge** above the threshold | one 16-byte digest, ≤ 1 datagram | a round trip it can only complete from a real address |
| 4 | the X25519 handshake | **the first asymmetric operation** — 198 µs | a completed round trip |
| 5 | COSE_Sign1 token verification | the second — 30 µs | an Owner-signed token |
| 6 | `cnf` against the proved `RLK` | a comparison | possession of the bound key |
| 7 | bounded registry admission | an insert | — |

Step 3 before step 4 is the whole of §11.5's "**no asymmetric operation for an
unvalidated source address**". Steps 5 and 6 are §11.3's order, and step 6 is
what makes a *stolen* token inert: `IK` proves which `RLK` the initiator holds,
and `cnf` proves which one the token was issued for.

The cookie is derived through `RelayCrypto::digest16` over
`secret ‖ family ‖ address ‖ port ‖ window`, with a 120-second window and the
previous one accepted for the edge. **The port is included**, because a NAT puts
many devices behind one address and a cookie bound only to the address would let
one of them mint challenges the others spend. The comparison is constant-time: a
16-byte value compared against an attacker-supplied one with `==` is a
prefix-matching oracle.

**The cookie secret is not a fourth key**, and the distinction is not a word
game: it authenticates nothing and decrypts nothing. Disclosing it costs exactly
the anti-DoS property and no confidentiality, integrity or admission property
anywhere — which is why it may live in ordinary memory and be regenerated at will.

### The leg registry is bounded three ways

| Ceiling | Bounds | Without it |
|---|---|---|
| `MAX_LEGS` = 65 536 | total memory | one attacker fills the table |
| `MAX_LEGS_PER_PREFIX` = 1 024 | legs from one source /24 or /48 | **one attacker still fills it**, from one subnet, since a /64 is 2^64 addresses |
| `LEG_IDLE_TIMEOUT_MS` = 900 000 | how long an abandoned leg holds a slot | a table that only grows |

The second is the one a single global cap misses, and it is **an addition, stated
as one**: §11.5 rate-limits handshakes per /24 and /48 but bounds no *occupancy*,
so a rate limit alone only slows the fill down.

---

## 8.2 The control frames

ADR-0005 §9.1 assigns `0x10..0x1F` to control and names eight of the sixteen.
This build routes all eight and allocates three more inside that reserved space:

| Type | Frame | Direction | Body |
|---|---|---|---|
| `0x01` | `DATA` | device ↔ device | opaque L-DATA, ≤ 1456 B |
| `0x10` | `BIND` | device → relay | `pair_tag ‖ bucket ‖ carriage ‖ family` |
| `0x11` | `BOUND` | relay → device | `state ‖ pending_ttl_ms` |
| `0x12`/`0x13` | `PING`/`PONG` | device → relay | empty; answered **without** a bound flow |
| `0x14` | `DRAIN` | relay → device | `deadline_ms ‖ ≤ 3 relay ids` |
| `0x15` | `RELAY_STATUS` | relay → device | `reason_code ‖ retry_after_ms ‖ alternates` |
| `0x16` | `CAPS` | device ↔ relay | version window ‖ capability bitmap ‖ payload ceiling |
| `0x17` | `REBIND` | device → relay | as `BIND` (§11 item 7) |
| **`0x18`** | `HANDSHAKE_INIT` | device → relay | `[cookie] ‖ Noise_IK msg 1` |
| **`0x19`** | `HANDSHAKE_RESP` | relay → device | `Noise_IK msg 2`, carrying `CAPS` |
| **`0x1A`** | `COOKIE_CHALLENGE` | relay → device | 16-octet cookie |

**The three allocations are a proposal, recorded as one.** The leg handshake has
to arrive in *some* datagram on the same socket, and the alternatives were worse:
multiplexing it onto `CAPS` would make one type mean two things at different
points in a leg's life, and a separate UDP port would be a fifth carriage nothing
in ADR-0006's map can describe. The bodies are likewise proposed — §9.1 specifies
none, and ADR-0003 R7 keeps B4 free of a serialization framework by design, so
there is nothing to generate from. Each is versioned by the frame's `ver` nibble
(the token presentation by its own first octet), so changing one is an ADR-0014
event. See [`control`](src/control.rs) and [`admit`](src/admit.rs).

**Direction is checked on receive, not only on send.** W-32 ruled that a device
accepting a `BIND` *from* a relay is a confused deputy; the mirror holds here, and
`FrameType::device_may_send` refuses `BOUND`, `PONG`, `DRAIN`, `RELAY_STATUS`,
`HANDSHAKE_RESP` and `COOKIE_CHALLENGE` **before** the leg lookup — so a spoofed
`RELAY_STATUS` reaches no state at all, even when correctly MACed.

**`BIND` is authenticated by the leg, not by a second token check.** The token is
verified once, in the handshake, and the `VerifiedToken` is held on the leg. A
`BIND` on an established leg is already authenticated: its MAC verifies under
`K_leg`, and `K_leg` exists only because that token verified and the device proved
possession of the `RLK` it was issued for. Re-verifying per bind would put 30 µs
of Ed25519 on a path a listening device uses at ADR-0006 §11.5's cadence — up to
30 binds/min/subject by the frozen limit.

**Both peers receive `BOUND{flow_id}`** (§11.1(4)). The half-flow that was already
waiting is told through `Pump::pending_announcements`, drained by the caller — it
is not a second reply to the received datagram but an announcement onto an
already-bound, authenticated flow, the same class §11.5 permits for `DRAIN` and
`RELAY_STATUS`. Making it a field rather than a hidden send is what keeps
`Action`'s "at most one datagram" true.

---

## 9. Reason codes

Every refusal is a registered `reason_code` through
[`condition::Condition`](src/condition.rs), which is the only bridge to the wire.

**A finding, made visible rather than papered over.** ADR-0005 §11.7 contributes
26 `RELAY.*` codes and ADR-0006 §11.13 a further 29.
`contracts/registry/reason_codes.json` contains **twelve**. Forty-three names those
ADRs use have no registry entry, so `twinvpn-types` has no constant for them and
this crate physically cannot emit them. `contracts/` is frozen, so the mapping
degrades onto the nearest registered code and **never leaves the `RELAY` domain**
(ADR-0015 §11.2 rule 5's prefix degradation). `Condition::fidelity` says which of
the 26 the registry expresses exactly — currently **five**.

The cost, stated: a device cannot distinguish "your peer never arrived at the
pending slot" from "I am at capacity"; both degrade to `RELAY.CAPACITY_REJECTED`.

---

## 10. Local startup and debugging

```bash
docker compose up -d relay-a relay-b
curl -s http://127.0.0.1:19004/readyz  | jq      # relay-a admin
curl -s http://127.0.0.1:19005/healthz | jq      # relay-b admin
curl -s http://127.0.0.1:19004/metrics | grep twinvpn_relay_
```

The runtime image has no shell, so `docker compose exec relay-a sh` will not work.

| Symptom | First thing to check |
|---|---|
| startup fails naming `TWINVPN_RELAY_RETAIN_PEER_PAIR` | it was set to `true`. It cannot be (O-13) |
| startup fails naming a frozen limit | a `limits.json`-derived value was overridden |
| `/readyz` red, `carriages_bound` failing | `R-QUIC`/`R-TLS` are configured but not served in this build (§6) |
| no flow is ever admitted | `issuer-keys.json` is the empty bootstrap stub, or no crypto provider is installed (§8). Both are fail-closed by design |
| startup logs `outcome="no_legs"` | the static Noise key is unreadable or not 32 bytes / 64 hex chars, or `/dev/urandom` could not be opened. **No device can establish a leg**; see §8.1 |
| every handshake gets a `COOKIE_CHALLENGE` and no leg forms | the device is not answering it. Above 20 handshakes/s per source /24 or /48 the challenge is mandatory (§11.5), and the relay does no public-key work until it is answered |
| devices are refused with `RELAY.TOKEN_INVALID` on a token that looks fine | the map entry's `static_noise_public_key` does not match the key this process loaded, so `cnf` is being compared against a different `RLK`. Compare it against the `outcome="registration_record"` line this relay logs at startup (§8.1, `register`) |
| legs form but no `BIND` ever binds | the two peers' `pair_tag` buckets are more than one apart — the relay answers `RELAY_STATUS`, it does not ignore them |
| `RELAY.TOKEN_EPOCH_STALE` | the device's token predates the relay's `epoch_floor`. Defence in depth only — revocation is enforced at the peer |
| a flow vanished after a restart | **that is the design.** S-29 is non-durable by requirement; the client migrates |
| you want to trace one session across the relay | you cannot, and that is deliberate (ADR-0015 §13) |

---

## 11. Known limitations

Stated here rather than discovered later.

1. **`R-QUIC` and `R-TLS` are not served.** §6. `R-UDP` is, on all four address
   configurations, with the receive loop running and legs establishing on it.
2. **No container has been built or run.** Docker is absent from this host, as
   `infra/README.md` §9 records. Everything in §10 involving `docker compose` is
   unexercised.
3. **Five control-frame bodies are proposed, not frozen** (§8.2), as is the
   `HANDSHAKE_INIT`/`HANDSHAKE_RESP`/`COOKIE_CHALLENGE` type allocation and the
   token-presentation envelope. ADR-0005 §9.1 assigns type bytes and specifies no
   body, and B4 has no schema artifact by design (ADR-0003 R7), so there was
   nothing to generate from. Each is versioned so that changing it is an ADR-0014
   event. **Recorded for ADR-0005's owner.**
4. **`limits.json` has no B4 cap family.** [`frame::MAX_DATA_PAYLOAD_BYTES`](src/frame.rs)
   is derived from ADR-0005 §9.2 and enforced first; the `Channel` handed to
   `Verbatim::from_opaque` is only an outer backstop. One visible consequence: a
   relay payload's `Verbatim` renders as `on c1_c2_c7`, which is an artefact of
   `Channel` having no B4 variant to name. Commented at the call site.
5. **The tests assert self-consistency, not interoperability.** The test device
   in [`tests/common`](tests/common/mod.rs) re-derives the wire format from this
   crate's own public constants, because `twinvpn-relay-client` is in the *other*
   workspace and importing it would be a fourth edge into `/core` (ADR-0018
   §11.2). The two ends therefore agree by construction here and have **not** been
   run against each other. A cross-workspace interop test belongs in `tests/` or
   `lab/`, and is the single highest-value thing still outstanding.
6. **`twinvpn-relay-client` has no leg handshake yet.** This crate implements the
   responder; the device side of `Noise_IK` is `core-dataplane`'s and does not
   exist. Both ends can now be built from **one** implementation —
   `twinvpn_crypto::relay_leg` vends `LegInitiator` as well as `LegResponder`,
   deliberately, so the two cannot derive `K_leg` differently and fail as *every
   frame dropped* with both sides looking correct.
7. **`REBIND` is routed as a `BIND`.** ADR-0005 §9.1 assigns it a type byte and
   specifies no distinct semantics, and ADR-0006 §11.9 describes migration in
   terms a device drives. Treating it as a bind on a possibly-new `pair_tag` is
   the smallest behaviour consistent with both; a genuinely distinct
   move-this-flow semantic needs the ADR to say what it is.
8. **A relay does not enrol itself in the directory**, and that is a decision
   rather than a gap — see [`register`](src/register.rs). The relay map is
   Owner-signed and is the root of relay trust for every device; a relay that
   could write into it could add a relay of its choosing. What this build does is
   make an operator's enrolment *exact*, by deriving the record — including the
   **public** half of the static key the process actually loaded — and emitting it
   at startup. `relay-directory`'s fleet is still populated by nothing, which is
   that service's own gap.
9. **`relay-health` still has no prober loop.** It builds an aggregate and serves
   it; nothing fills it. Out of scope here, recorded because "relay health" is
   only half-true without it.

## 12. What is actually exercised, and what is not

| Property | How | Real? |
|---|---|---|
| **a real device establishes a leg, binds a pair and relays traffic** | `Noise_IK` + a real Ed25519-signed token + real sockets | **yes** |
| the relay cannot decrypt | 8 source + behavioural assertions | **yes** |
| the handshake yields `K_leg` and no cipher | source, both sides of the seam | **yes** |
| the relay leg is a different protocol from L-DATA | parameter string, prologue, no psk | **yes** |
| bytes out equal bytes in, incl. protobuf-with-unknown-field | corpus test, over a socket | **yes** |
| protobuf framing refuses ciphertext, opaque framing carries it | both halves in one test | **yes** |
| the payload bound clears the 1280 overlay floor | derivation + a 1456-byte frame end to end | **yes** |
| the frame MAC is a truncation, not a short-output BLAKE2s | `twinvpn-crypto`'s imported vector, both readings | **yes** |
| this crate's `mac_input` matches the imported `FRAME_MAC_INPUT` | byte-for-byte, built by this crate | **yes** |
| **COSE_Sign1 token verification with a VALID token** | a real Ed25519 fixture issuer | **yes** — §11.7's old gap is closed |
| `cnf` proof-of-possession | a stolen token presented by a device holding a different `RLK` | **yes** |
| a replayed `jti` is refused | second leg, same token | **yes** |
| an expired, not-yet-valid, wrong-audience or stale-epoch token | four separate tests | **yes** |
| **an attacker with its own valid leg cannot touch another flow** | R-5, over sockets | **yes** |
| a relay-only frame arriving *from* a device reaches nothing | W-32, correctly MACed | **yes** |
| **zero bytes** for unsolicited, forged or malformed input | a 20-entry corpus on a real socket | **yes** |
| the stateless cookie gates asymmetric work | flood + forged cookie + answered challenge | **yes** |
| one source prefix cannot fill the leg table | three real legs from one loopback /24 | **yes** |
| a subject cannot exceed its own flow ceiling | four binds, fourth refused **and told** | **yes** |
| throttling emits `RELAY_STATUS`, never silence | registered code checked on the wire | **yes** |
| a drain refuses new binds and keeps carrying | both halves in one test | **yes** |
| a `DRAIN` is authenticated and names no endpoint | device verifies it; a bit-flip does not | **yes** |
| a restart kills every flow | two instances, before and after | **yes** |
| **one token admits at every relay in the operator group** | two instances, two regions, two failure domains | **yes** |
| a pair re-rendezvouses at a second relay | new tag, new instance | **yes** |
| a third bind on a bound tag is refused | `PAIR_COLLISION` degraded onto its registered code | **yes** |
| a pending slot that never pairs is reclaimed | driven through the collector | **yes** |
| loss does not wedge a flow; the relay never retransmits | 20 burned counters | **yes** |
| a replayed `DATA` frame is dropped and the flow survives | identical datagram twice | **yes** |
| a burst is carried in order without the queue growing | 32 frames | **yes** |
| the daily `relay_sub` re-hash rotates | real HKDF-SHA-256 | **yes** |
| a drain does not stampede | 10 000 draws, bucketed | **yes** |
| two-tier DRR fairness | measured, and on the forwarding path | **yes** |
| **performance, measured** | [`tests/benchmarks.rs`](tests/benchmarks.rs) | **yes** — see §13 |
| a device speaking `twinvpn-relay-client` | — | **no**: §11 item 5 |
| anything in a container | — | **no**: no Docker |
| `R-QUIC` / `R-TLS` legs | — | **no**: §6 |

---

## 13. Performance

[`tests/benchmarks.rs`](tests/benchmarks.rs) measures the paths ADR-0005 §9.4 and
§11.5 make claims about, prints a table, and asserts only generous ceilings.

```bash
cd services && cargo test -p twinvpn-relay --release --test benchmarks -- --nocapture
```

`--release` matters: the debug numbers are roughly an order of magnitude worse
and are not a baseline for anything.

**Observed on the development host** (x86-64, `--release`, single core). These are
a baseline for comparison, not a specification:

| Operation | Per op | Rate |
|---|---|---|
| parse a 1456-byte `DATA` frame | ~10 ns | ~100 M/s |
| assemble the §9.1 MAC input | ~45 ns | ~22 M/s |
| verify the truncated BLAKE2s frame MAC | 1.7 µs | 577 k/s |
| **`Pump::step` over a bound flow (1200 B)** | **3.3 µs** | **307 k/s ≈ 2.9 Gbit/s** |
| `Noise_IK` responder handshake + `K_leg` | 198 µs | 5 k/s |
| COSE_Sign1 / Ed25519 token verification | 30 µs | 33 k/s |
| device → relay → peer over loopback UDP | 205–235 µs | ~4.5 k/s |

Three things worth reading off that table rather than leaving implicit:

1. **The per-packet path clears ADR-0005 §9.4's "sub-100 µs" budget by a factor
   of thirty**, and the whole of it is one MAC verify (1.7 µs) plus one MAC
   compute — the lookup, the replay window, the quota charge and both DRR
   operations together are under a microsecond. §10's claim that "a relay's
   binding constraint is bandwidth and packet rate, not memory or CPU" holds:
   2.9 Gbit/s on one core is well past any link a single instance will terminate.
2. **The handshake costs 60× a forwarded frame**, which is exactly why §11.5 puts
   a cookie gate in front of it. At the frozen threshold of 20 handshakes/s per
   source /24, an unvalidated prefix commands ≈ 4 ms of CPU per second — 0.4 % of
   one core. Without the gate, the same source commands 100 % of it.
3. **Token verification is once per *leg*, not per bind.** `crate::admit` holds
   the `VerifiedToken` on the leg for this reason: a listening device re-`BIND`s
   at ADR-0006 §11.5's cadence, up to 30 binds/min/subject, and 30 µs of Ed25519
   on each would be an asymmetric operation on a path a device uses routinely.

The assertions in that file are set two to three orders of magnitude above these
numbers on purpose. What they catch is a **structural** regression — a lock
convoy, a per-frame allocation, a lookup, or a control-plane call appearing on
the packet path (which I5 forbids and which would show up here as milliseconds).
