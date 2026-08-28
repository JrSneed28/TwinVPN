# `twinvpn-relay`

The ciphertext-only relay data plane: `BIND`/`BOUND` keyed by `pair_tag`, opaque
frame forwarding, offline `RelayCapabilityToken` admission, resource control, and
herd-safe drain.

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
| relay static X25519 | a **path** in [`config`](src/config.rs); this crate never loads it | not a party to `Noise_IKpsk2` |
| issuer public-key set | [`issuer::IssuerKeySet`](src/issuer.rs) | verification-only, public |
| per-leg `K_leg` | [`crypto::LegKey`](src/crypto.rs) | domain-separated; **MAC only** |

Four checkable properties, in [`tests/cannot_decrypt.rs`](tests/cannot_decrypt.rs):

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

Properties 1–3 are **source assertions**, deliberately. A decrypt path is
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
```

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
| `TWINVPN_RELAY_MAX_LEGS` | `65536` | fixed | **added by this domain**; a leg is created by an unauthenticated source, so the registry needs a ceiling (§6 rule 10) |

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
| `RELAY.TOKEN_EPOCH_STALE` | the device's token predates the relay's `epoch_floor`. Defence in depth only — revocation is enforced at the peer |
| a flow vanished after a restart | **that is the design.** S-29 is non-durable by requirement; the client migrates |
| you want to trace one session across the relay | you cannot, and that is deliberate (ADR-0015 §13) |

---

## 11. Known limitations

Stated here rather than discovered later.

1. **No leg can be established.** `K_leg` comes from the Noise_IK handshake
   (`R-UDP`) or an RFC 8446 exporter (`R-QUIC`/`R-TLS`) — ADR-0005 §11.1(2) —
   and neither is implemented. [`pump::LegRegistry`](src/pump.rs) is therefore
   empty in production and every received datagram is dropped with **zero bytes**
   in reply. That is the fail-closed direction, it is asserted over a real socket
   (§12), and a `WARN` at startup says so. **This is now the only thing between
   the relay and a working data plane**: with legs supplied by a test, a real
   frame traverses a real relay between two real sockets today.
2. **`R-QUIC` and `R-TLS` are not served.** §6. `R-UDP` is, on all four address
   configurations, with the receive loop running.
3. **No container has been built or run.** Docker is absent from this host, as
   `infra/README.md` §9 records. Everything in §10 involving `docker compose` is
   unexercised.
4. **The `RELAY_STATUS` body encoding is proposed, not frozen.** ADR-0005 §9.1
   assigns the type byte but specifies no body, and B4 has no schema artifact by
   design (ADR-0003 R7). [`status`](src/status.rs) contributes the smallest
   encoding satisfying §11.5 and §11.7, versioned by the frame's `ver` nibble so
   changing it is an ADR-0014 event. Recorded for ADR-0005's owner.
5. **`BIND`, `BOUND`, `DRAIN`, `CAPS` and `REBIND` are not routed by the pump.**
   They are the leg-setup and control surface and belong with the leg state
   machine in (1); routing them on the forwarding path would put admission on the
   packet path. `RelayEngine::bind` and `DrainPlan` implement the transitions and
   are tested; what is missing is the frame parsing that feeds them.
6. **`limits.json` has no B4 cap family.** [`frame::MAX_DATA_PAYLOAD_BYTES`](src/frame.rs)
   is derived from ADR-0005 §9.2 and enforced first; the `Channel` handed to
   `Verbatim::from_opaque` is only an outer backstop. One visible consequence: a
   relay payload's `Verbatim` renders as `on c1_c2_c7`, which is an artefact of
   `Channel` having no B4 variant to name. Commented at the call site.
7. **The COSE_Sign1 token path has no golden vector here.** It is exercised
   against malformed input and against the real `twinvpn-crypto`, but producing a
   *valid* token needs an Ed25519 keypair this build cannot sign with — the same
   custody gap as the map issuer. The admission *policy* is fully tested against
   a double.

## 12. What is actually exercised, and what is not

| Property | How | Real? |
|---|---|---|
| the relay cannot decrypt | 4 source + behavioural assertions | **yes** |
| bytes out equal bytes in, incl. protobuf-with-unknown-field | corpus test | **yes** |
| protobuf framing refuses ciphertext, opaque framing carries it | both halves in one test | **yes** |
| the payload bound clears the 1280 overlay floor | derivation + parse test | **yes** |
| the frame MAC is a truncation, not a short-output BLAKE2s | `twinvpn-crypto`'s imported vector, both readings | **yes** |
| this crate's `mac_input` matches the imported `FRAME_MAC_INPUT` | byte-for-byte, built by this crate | **yes** |
| the MAC covers type, flags, full counter, `flow_id`, payload | six negative assertions | **yes** |
| a forged or cross-key tag is refused | real constant-time verify | **yes** |
| **a real frame traverses a real relay between two real sockets** | UDP loopback, real MAC both legs | **yes** |
| the forwarded tag verifies under the **egress** key and not the ingress one | same test | **yes** |
| **zero bytes** for unsolicited or forged input | real UDP socket, v4 and v6 | **yes** |
| the loop survives a flood and stops cleanly | 200 datagrams on loopback | **yes** |
| the daily `relay_sub` re-hash rotates | real HKDF-SHA-256 | **yes** |
| a drain does not stampede | 10 000 draws, bucketed | **yes** |
| two-tier DRR fairness | measured, and on the forwarding path | **yes** |
| `RELAY_STATUS` on throttle | pump test, end to end through the engine | **yes** |
| COSE_Sign1 token verification | real `twinvpn-crypto` | **partly** — malformed input yes, a valid token no (§11.7) |
| a device establishing a leg | — | **no**: no handshake (§11.1) |
| anything in a container | — | **no**: no Docker |
