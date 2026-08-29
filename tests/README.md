# `tests/` — the tests that cross a domain boundary

**Owner:** `test-engineering` ([`docs/implementation/ownership.md`](../docs/implementation/ownership.md) §1).

Every other test in this repository lives inside one domain. `core-dataplane`
tests `twinvpn-route` against fakes; `control-plane` tests its own handlers;
`relay-plane` tests the relay. **Nothing tested what happens when they meet** —
and the space between two individually correct components is where this wave's
cross-domain defects turned out to be.

---

## 1. Running them

```bash
source build/toolchain/env.sh
cd tests
cargo test --workspace          # 210 tests, ~12 s after the first build
```

`tests/` is a fifth cargo workspace and is in the `Makefile`'s `WORKSPACES`, so
`make lint` and `make test` run everything here.

It is deliberately **not** a member of the core workspace: a test workspace that
shared the product's manifest could silently add a dependency to a shipped
crate. `services/` is deliberately absent from its dependency list for the same
kind of reason — see §7.

---

## 2. Layout, and what each level is for

| Path | Level (§2 of `docs/testing-strategy.md`) | Tests |
|---|---|---|
| `e2e/composed_core.rs` | 7 — end-to-end, the real `twinvpn_core::Core` | 28 |
| `e2e/session_lifecycle.rs` | 7 — end-to-end, the leaf-crate pipeline | 12 |
| `e2e/fail_closed_leak.rs` | 7 + 12 — end-to-end, security | 15 |
| `e2e/real_crypto_crossing.rs` | 7 + 12 — end-to-end, **real `Noise_IKpsk2`** | 8 |
| `e2e/real_crypto_relay_leg.rs` | 7 + 12 — end-to-end, the same crossing over a relay leg | 4 |
| `integration/dual_stack_parity.rs` | 6 + 9 — integration, networking | 12 |
| `integration/cross_component_agreement.rs` | 4 — contract | 20 |
| `integration/tunnel_wire_agreement.rs` | 6 — sender against receiver | 8 |
| `chaos/outage_and_failover.rs` | 15 — chaos | 11 |
| `chaos/journal_write_behind.rs` | 15 — chaos, **W-28** measured | 7 |
| `chaos/store_outage.rs` | 15 — chaos, §2.13's database outage at the real store seam | 5 |
| `integration/revocation_at_the_peer.rs` | 6 + 14 — integration, security: **A-06** | 4 |
| `compatibility/golden_vectors.rs` | 3 + 19 — protocol, compatibility | 8 |
| `e2e/scenario_matrix.rs` | 7 — the named scenario matrix (§8) | 24 |
| `fuzz/wire_decoders.rs` | 13 — fuzzing, network-supplied decoders (§9) | 13 |
| `fuzz/statement_decoders.rs` | 13 — fuzzing, peer-authored signed statements | 6 |
| `fuzz/persistence_decoders.rs` | 13 — fuzzing, decoders that read local storage | 11 |
| `fuzz/handshake_and_platform_decoders.rs` | 13 — fuzzing, the pre-auth handshake reader and the platform parsers | 7 |
| `system/` | the shared rigs (`Rig`, `ComposedRig`, `AdapterStore`, `block_on`) and the fuzz engine | 7 |
| `vectors/crypto-kat/` | §2.3's `crypto-kat/` corpus | 7 vectors |

`system/Cargo.toml` declares each file as a `[[test]]` target with an explicit
`path`, so the directories say what level a file belongs to without anyone
having to open it.

### The two real-cryptography files

`core/crates/twinvpn-core/tests/datapath.rs` runs two `Pump`s against each other
and is the strongest existing proof that the product carries a packet. Its own
support file says the rest: the transport keys are `StubKeys`, "**not
cryptography**", because reaching `twinvpn_tunnel::bind::SessionKeys` needs a
`VerifiedTunnelKey`, hence a signed `TunnelKeyBinding`, hence
`twinvpn-crypto`'s `test-support` fixtures — a dev-dependency feature
`twinvpn-core`'s manifest does not enable. **So the test that proved a packet
crosses proved it through a stub cipher.**

This workspace already enables that feature, so `e2e/real_crypto_crossing.rs`
closes it: two composed endpoints, a genuine `Noise_IKpsk2` handshake through
`twinvpn_crypto::noise` and `twinvpn_tunnel::bind`, production `SessionKeys`,
`twinvpn_core::datapath::Pump` on both ends over `MockAdapter`, and an on-path
observer that hands every datagram over by hand. The shared rig is
`system/src/noise.rs` (the key material) and `system/src/crossing.rs` (the
fabric).

`e2e/real_crypto_relay_leg.rs` carries the same real record over
`twinvpn_core::relay` and `Sealed::{from_tunnel, into_tunnel}`. Its relay is
**not** another hand-written one: §8's server artifacts mean the stand-in can be
built from `twinvpn_relay`'s own `LegHandshake`, `RelayFrame::parse`,
`CounterWindow`, `control::encode_frame`, `RelayFrame::reframe` and production
`CryptoProvider` MAC, so a green test means the two ends agree rather than that
one end agrees with itself.

### The rig

`Rig::new(host_family, seed)` composes a deterministic `twinlab::LabEnv`
(virtual clocks + CD-4 seeded streams), a `MockAdapter` bound as the platform
(**CD-5**), the real `SessionMachine`, and the real route / DNS / enforcement
pipeline. It is parameterised by **underlay** address family — `V4Only`,
`V6Only`, `Dual` — because ADR-0010 **R1** is one story covering both and a rig
that could only be built for IPv4 would quietly make that untestable.

`ComposedRig` is the same idea one level up: the real `twinvpn_core::Core`,
built from **this crate's** `CoreParts` rather than `twinvpn_core::testing`'s.
That difference is the whole point. `twinvpn_core::testing` binds a
`CountingEntropy` behind a `SystemRngSource`, which answers
`is_deterministic() == false`; a scenario that cannot say it is deterministic
may not declare `BIT` (§3.5). `ComposedRig` asserts determinism at
construction, so every assertion in `e2e/composed_core.rs` is over a run a
recorded `scenario_seed` reproduces.

`ComposedRig::with_store_entropy` is the one exception, and it says so: opening
a real `twinvpn_store::Store` needs entropy that produces bytes, so those rigs
bind `twinlab::CountingEntropy` — deterministic, obviously so, and never to be
used where unpredictability is the property under test.

`AdapterStore` forwards `SecureStore` to a `MockAdapter`'s own, because
`MockStore`'s constructor is `pub(super)` and `Store::open` wants an `Arc`.
It adds no behaviour: a forwarder that quietly answered `Ok(None)` for a
missing item would make the ADR-0020 recovery ladder read a torn vault as a
first run.

---

## 3. The shape every test here takes

**A test that cannot fail is not a test.** Every property asserted below is
paired with something that breaks it:

- the leak canary's negative result is paired, *in the same test*, with a
  positive control that proves the observation channel works (**B-7**);
- the family-asymmetry guard is exercised by handing it a plan with the v6 half
  removed, so "the assembler refuses a leak" is not vacuous;
- the golden-vector runner is exercised by a provider that is wrong in exactly
  one byte, so "the corpus agrees" is not "the corpus compares nothing";
- the real-cryptography crossing's "the plaintext is not on the wire" is paired
  with the same detector run against a datagram whose body *is* the plaintext,
  and its rig asserts that the family it was asked for is the family it bound —
  so a v6 arm that silently ran v4 twice fails rather than passing;
- the NAT class-pair matrix is parsed from `docs/networking.md` §3.2 rather than
  restated, so a change to the document changes the expectations;
- every family-shaped assertion is a loop over `[V4, V6]` that fails if either
  arm is missing.

### Enumerate the property, not the files or the literals

The cross-workspace agreement tests were first written as `include_str!` of the
other side's source. That reasoning was sound — separate cargo workspaces cannot
link each other — and the conclusion was wrong. It broke four times in one wave,
twice in this domain's own tests:

- a `HEADER_LEN` tripwire scanned `map.rs` and `bind.rs`; the device relay frame
  landed in a *new* `frame.rs` and it stayed green through exactly the change it
  was built to catch;
- a MAC-vector check scraped `services/relay/src/provider.rs` for four literal
  declarations, and failed with *"the two golden vectors have drifted"* on the
  day `relay-plane` **deleted** those literals in favour of one shared artifact.
  The opposite of drift, reported as drift.

**A check that enumerates its subject's source form fails loudest exactly when
the subject improves.** The rule that replaced it:

| Read | Do not read |
|---|---|
| a **frozen contract** — `relay.proto`, `limits.json`, `reason_codes.json`, the generated bindings | another crate's **source** |
| a **specification** — an ADR's normative sentence, the ABI header | another crate's **literals** |
| a **shared artifact** by value — `twinvpn_crypto::blake2s::vectors` | a file list, or a variant list, restated here |

Two consequences worth naming. Where the two sides share one artifact, agreement
becomes a value comparison and this suite stops being where it is checked — the
relay frame's MAC vector now lives in `twinvpn_crypto::blake2s::vectors`, all
three sides import it, and each compares its own assembler's output against it.
Where they cannot share, an **exhaustive match** against the generated bindings
moves the check to the compiler: adding a `Carriage` or `AdminState` variant on
either side now fails to build rather than failing a string search.

One residual is named rather than hidden. `services/rendezvous`'s framing is
finding **RZ-1** — `contracts/` declares no message for it — so its README §5
table is the specification of record and `src/frame.rs` is the only
implementation. There is nothing to compare by value and nothing frozen to
compare against, so that one check is still a source read. It is the residual of
a missing contract, and it goes away the day RZ-1 does.

---

## 4. The defect tripwires are gone, and what replaced them

`tests/defects/tripwires.rs` recorded five defects in other domains' components
as executable evidence — each asserting the defective behaviour, naming the
correct one in its comment, and designed to fail the day it was fixed.
`core-dataplane` fixed all five, so the file was deleted with them.

Two things survive it, and they are the parts worth keeping.

**The shape that found the worst one.** `integration/tunnel_wire_agreement.rs`
runs a sender against a receiver. That composition is what surfaced **W-31** —
the first data packet of every tunnel rejected as a replay — and neither owning
crate's suite could see it, because *every existing test started at counter 1*.
The replay window was thoroughly tested for the attack it defends against and
untested at its own origin. Those tests are now permanent regressions in their
positive form.

**The reasoning behind the fix.** `core-dataplane` moved the *receiver's*
origin, not the sender's: a conforming peer sends counter 0 first, so a receiver
refusing it is broken against every correct implementation regardless of its own
sender. Moving `SendCounter` to 1 would have made two TwinVPN devices agree with
each other and left both wrong against WireGuard.
`interoperability_is_what_fixing_the_receiver_bought` asserts that rather than
remembering it. Fixing W-31 also surfaced a second defect nobody had flagged —
the replay window was **2048** counters where ADR-0001 §7.1 specifies **8192** —
and `the_replay_window_is_the_width_adr_0001_specifies` now anchors the constant
to the ADR's own text.

Two of this domain's original filings were corrected on the way, and both
corrections are preserved as pins rather than quietly dropped:

- **D-2's crossover is the ADR's own weighting, not a defect.** §11.2 floors RTT
  at −250 and gives `UNHEALTHY` −150, so the 150 ms crossover is intended. The
  real defect was **unboundedness** — a 5 s RTT cost −5000 against a declared
  floor of −410 — and
  `d2_no_measurement_can_drive_the_score_past_the_declared_floor` asserts the
  bound over an extreme sweep, because the defect was invisible at realistic
  magnitudes where an inert floor and a working one agree.
- **D-5 had no correct option on offer.** DN-23 makes DoH a selectable upstream,
  so deleting 443 was wrong; KS-10 bounds it to the known-DoH endpoint *list*,
  which a port-only predicate cannot express. The predicate was replaced — a
  genuine tightening, since any 443 destination was previously permitted.

**Two of this domain's own checks went blind, and the lesson is now §3's
rule.** `the_relay_data_frame_still_has_no_device_side_implementation` scanned
`map.rs` and `bind.rs`; the device frame landed in a new `frame.rs`. And the
MAC-vector check scraped `provider.rs` for literals that were then deleted in
favour of a shared artifact — reporting drift on the day drift became
impossible. Both are replaced by value comparisons; neither reads anyone's
source.

---

## 5. What the golden-vector corpus does and does not claim

`vectors/crypto-kat/manifest.json` is §2.3's `crypto-kat/` class. Every entry is
transcribed from its published specification (FIPS 180-4, RFC 5869) except the
last, which pins CD-4's own derivation and was computed by an implementation
**outside this workspace**.

ADR-0018 **DP-8** requires *two* cryptographic providers to pass an *identical*
corpus. Only one exists today. The claim is therefore made **checkable** rather
than claimed: the corpus names no provider (asserted), the runner takes a
`Provider` trait, and a second implementation is a binding rather than a second
corpus.

The protobuf half runs the **frozen** `contracts/tests/fixtures/*.binpb` through
the Rust bindings the product actually ships. The Python harness checks those
fixtures against `buf` and protobuf.js; **nothing checked them against `prost`**,
so a round-trip that reordered or dropped a field would have been invisible
until a device met a server. The fixtures are read from the frozen tree, never
copied, so there is exactly one corpus.

`an_unknown_field_survives_a_decode_and_re_encode` states the **measured**
behaviour rather than the desired one: `prost` 0.13 drops unknown fields, which
is finding **W-4**, and the test says so in its assertion message.

---

## 6. Cost per tier

| Tier | What of `tests/` belongs there | Measured cost |
|---|---|---|
| **T1** | `integration/*`, `compatibility/golden_vectors.rs` — pure, no I/O, no privilege | **< 0.1 s** |
| **T2** | `e2e/*`, `chaos/outage_and_failover.rs` — real components against `MockAdapter` | **< 0.1 s** |
| **T2** | `chaos/journal_write_behind.rs` — a real vault under `target/`, so it touches the filesystem | **≈ 0.05 s** |
| **T1** | `e2e/scenario_matrix.rs` — pure, the state machine driven trigger by trigger | **< 0.01 s** |
| **T1** | `fuzz/wire_decoders.rs`, `fuzz/persistence_decoders.rs` — pure decoders over ~6 000 inputs each | **≈ 0.35 s** |
| **T1** | `fuzz/statement_decoders.rs` — pure, but every input costs a real ES256 verification | **≈ 5.7 s** |
| **T1** | `fuzz/handshake_and_platform_decoders.rs` — pure, but every input costs a fresh `Noise_IKpsk2` responder | **≈ 5.6 s** |
| **T3** | nothing yet — the levels that need TwinLab's namespace rig live in `lab/`, and nothing here needs a network | — |
| **T4** | nothing yet | — |

The whole suite is **≈ 12 s** — of which about eleven are the two
cryptographic fuzz targets (ECDSA verifications, and one fresh `Noise_IKpsk2`
responder per input), and everything else is under a second. Both are capped by
a per-file iteration count chosen against that measurement, because a fuzz
target that dominated the suite would be the first one somebody disabled. The
rest is deliberate: everything here is a decision the core makes, and CD-5's mock is
what keeps that affordable. Nothing in this directory opens a socket or needs a
privilege, and the only filesystem it touches is
`target/system-test-vaults/`, cleared per test.

---

## 7. Limits, stated

- **No service is exercised in-process.** `services/` is a separate cargo
  workspace and `tests/` deliberately does not link it: pulling in axum, tokio
  and a Postgres client would give the system tests the services' dependency
  graph rather than the product's. Cross-service agreement is therefore checked
  the way `services/control-plane/tests/client_agreement.rs` checks it — by
  reading the other side as text at compile time.
- **No container runs.** Docker is not installed on this host and
  `infra/`'s compose topology is untouched by this suite. No claim here rests on
  a running service.
- **No network namespace is created.** Everything here is in-process against
  `MockAdapter`. The namespace-backed half is `lab/`'s, and `lab/README.md` §2
  says exactly what that could and could not produce.
- **The two real-cryptography files still inject deterministic entropy.**
  `system/src/noise.rs`'s `SeededEntropy` is a reproducible stream and says so.
  A handshake's *correctness* does not depend on unpredictable ephemerals; its
  forward secrecy does, and that is a property of the `Env` a shell injects
  (**W-7**) which nothing in this workspace can observe. Reaching the platform
  CSPRNG here would be an ADR-0018 CD-3 violation as well as a source of
  flakiness.
- **No key material is committed.** The `ReversibleKeys` stand-in in
  `integration/tunnel_wire_agreement.rs` is explicitly not cryptography and says
  so; the crypto corpus is published test vectors. `chaos/journal_write_behind.rs`
  opens a real vault, which derives a store key at run time into
  `target/system-test-vaults/` — generated per run, never reused, never
  committed.
- **W-24 and W-25 are asserted, not re-discovered.** The F-9 vtable has no
  `installed_ruleset` read-back and no socket provider, so a `ProtectionAssertion`
  cannot be produced across the ABI and a vtable-only shell cannot do NAT
  traversal. `integration/cross_component_agreement.rs` §6 asserts both absences
  against `twinvpn.h`, so the day the vtable gains either, the test says which
  refusal to delete.

---

## 8. The named scenario matrix

`e2e/scenario_matrix.rs` exists for a reason that is worth stating, because
otherwise it looks like duplication: **every scenario in it was already covered,
and none of them was findable.**

The wave-1 objective lists seventeen scenarios by name. The coverage for them
was real but scattered — a `Row::T13` assertion in `twinvpn-session`'s
transition table, a relay-death test in `chaos/outage_and_failover.rs`, a latch
test in `e2e/fail_closed_leak.rs`. A reviewer asking *"is relay-to-direct upgrade
tested?"* had to know that the answer was spelled `T13`, and a `grep` for
`upgrade` across every test name in the repository returned **nothing**.

So this file is a **traceability surface**, named in the objective's own
vocabulary. Where a scenario is tested more deeply elsewhere, the test here says
where and does not duplicate that depth.

| Objective's scenario | Test |
|---|---|
| direct connection | `scenario_direct_connection` |
| local direct connection | `scenario_local_direct_connection` |
| relayed connection | `scenario_relayed_connection` |
| direct-to-relay fallback | `scenario_direct_to_relay_fallback` |
| relay-to-direct upgrade where supported | `scenario_relay_to_direct_upgrade_where_supported`, and its negative half |
| path migration | `scenario_path_migration_commits_and_rolls_back` |
| network loss | `scenario_network_loss_with_no_alternate_reconnects_with_a_named_code` |
| reconnect | `scenario_reconnect_returns_to_a_steady_carrier_on_every_family` |
| stale session | `scenario_stale_session_past_the_rekey_window_rediscovers_rather_than_resuming` (+ the path-only case) |
| duplicate messages | `scenario_duplicate_messages_are_refused_exactly_once_each` |
| reordered messages | `scenario_reordered_messages_are_accepted_within_the_window_and_still_deduplicated` |
| unsupported capability | `scenario_an_unsupported_capability_*` (3 tests: selection, name shape, S-37 floor) |
| incompatible protocol version | `scenario_an_incompatible_protocol_version_fails_with_the_registered_code` |
| peer revocation | `scenario_peer_revocation_is_terminal_and_never_retried_into` |
| kill-switch state transitions | `scenario_kill_switch_*` (3 tests: entry, the two exits, T29's precedence) |
| cancellation | `scenario_cancellation_is_accepted_from_every_state_except_blocked` |
| concurrent clients | `scenario_concurrent_clients_are_admitted_attributed_and_isolated` (+ the collision case) |

Two rules the file holds to, both of which are §3's rules applied here:

- **Every scenario with an address family loops over `HostFamily::ALL`.** A
  matrix that quietly covered only the v4 arm would make the objective's "no v6
  later" rule untestable, which is the exact failure ADR-0010 **R1** exists to
  forbid.
- **Every guard has a negative.** `where supported` in "relay-to-direct upgrade
  where supported" is a *guard*, so the file asserts that an unvalidated path, a
  path that is not better, and a path the anti-flap suppressor is holding all
  **fail** to upgrade. A guard nobody has seen refuse is not a guard.

---

## 9. Fuzzing the protocol decoders

`fuzz/` covers **every decoder in the core that reads bytes this device did not
write**. `ownership.md` §6 rules 9 and 10 — validate before allocating, bound
every allocation an untrusted input can drive — are properties under
*adversarial* input, and an example-based test cannot measure them: the examples
are the ones the author thought of.

### Why this is not `cargo fuzz`

`cargo fuzz` needs libFuzzer, which needs nightly. `rust-toolchain.toml` pins one
exact stable version and ADR-0018 §11.3 makes advancing it a reviewed commit that
re-runs the whole §11.9 matrix. **A fuzz harness that cannot run in the gate is a
fuzz harness nobody runs**, so this one runs under `cargo test` on the pinned
toolchain.

The trade is stated rather than hidden. There is **no coverage feedback**, so
this does not find what a coverage-guided fuzzer finds; if libFuzzer becomes
available, these targets are the corpus to point it at. What it gives that
libFuzzer does not is that every input is a pure function of a `u64` seed, so a
failure reproduces exactly, in the gate, a year later — the same property CD-4
gives the product's own random draws. The corpus compensates for the missing
feedback by seeding from *valid* encodings and mutating them, which is where a
structure-aware fuzzer spends its time anyway.

### The three properties every target asserts

1. **Totality.** No input panics — not a slice index, not an `unwrap`, not a
   debug-build overflow, not a recursion that overflows the stack. A panic in a
   decoder that reads an attacker's bytes is a remote denial of service.
2. **Determinism.** The same bytes decode to the same outcome twice.
3. **No partial accept.** A rejection yields no value, held structurally by
   every decoder returning `Result` or `Option`.

Two more are asserted per target where they apply: that the run **reached the
accepting path at all** — a fuzz run that only ever rejected tested the first
length check and nothing else, which is the failure mode a fuzz suite is most
likely to have and least likely to notice — and that declared lengths past the
cap are refused rather than allocated.

### The three files, and why the split is by adversary

| File | The bytes come from | The adversary |
|---|---|---|
| `wire_decoders.rs` | C1/C2/C7, C4, the relay leg, a DNS query name | anyone who can send a datagram |
| `statement_decoders.rs` | COSE_Sign1 signed statements, COSE keys | a legitimate peer, or a stolen key |
| `persistence_decoders.rs` | the vault, the anchor, the session journal, the peer cache | anyone with disk access, or a torn write |
| `handshake_and_platform_decoders.rs` | the `Noise_IKpsk2` initiation, netlink, `nft --json`, the resolver restore point, a peer's `reason_code` text | anyone who can send a datagram to the tunnel port; the kernel; the disk |

`statement_decoders.rs` is the one worth reading. The naive fuzz — flip a bit in
a signed envelope — tests almost nothing, because every mutation fails the
signature and the payload decoder is never reached. The adversary that matters
holds a key and can therefore sign **whatever payload it likes**, so those
targets generate random CBOR trees, sign them with a real ES256 key, verify them
through the real `verify_cose_sign1`, and only then hand them to the decoder.
That is the exact path a hostile peer's statement takes.

`persistence_decoders.rs` exists because it is tempting to treat local storage as
trusted. ST-15's whole rung ladder is built on the premise that what comes back
may not be what went in, and the kill switch, the revocation floors and the trust
epoch are all restored from those bytes.

`handshake_and_platform_decoders.rs` covers the two surfaces the other three
cannot reach. `Handshake::read_message` on a **responder** is the decoder an
unsolicited datagram to the tunnel port hits before any key has authorised
anything — ADR-0001 A1's "silence on unauthenticated input" is what a caller
does with a *failure*, and a panic is neither silence nor a failure. Its target
asserts `accepted == 0`: a responder accepting a forged initiation would be the
defect, not the coverage. And the platform half fuzzes the three things
`twinvpn-platform-linux` parses that this process did not write. The kernel is
trusted; a declared length arriving from a socket is still a declared length,
and the restore point is read by `twinvpn-unblock` with the agent absent, so a
panic there is a machine that will not restore its resolver.

One exclusion is stated rather than left as an unexplained gap:
`TransportSession::open` is not fuzzed, because reaching it needs a completed
handshake, which needs a `VerifiedTunnelKey`, which is only constructible
through a signed and verified `TunnelKeyBinding`. Its replay behaviour is
covered by `integration/tunnel_wire_agreement.rs` and by §8's matrix; its AEAD
is `snow`'s.

### The engine is itself tested

`system/src/fuzz.rs` carries seven tests that plant a decoder with a known defect
— one that panics, one that is not deterministic — and assert the engine reports
it, names it, and prints the input in a form that can be pasted back. This is
`core/README.md` §6's principle applied here: *a lint nobody has seen fail is not
a lint*, and the same is true of a fuzz harness. A refactor that turned `fuzz`
into a no-op fails there rather than passing everything for the rest of the
project's life.

### Adding a decoder

A decoder with no entry in `fuzz/` is a decoder nobody has fuzzed. Add a target
beside its neighbours: build a corpus with `fuzz::corpus(seed, iterations,
max_len, &valid_seeds)`, call `fuzz::fuzz(name, &corpus, |b| ...)`, and assert
the report reached both paths.


---

## 8. The two suites that needed both sides of a wire

§7 explains why `services/` was deliberately absent from this workspace's
dependency list, and why the integration lead later added the server artifacts
anyway: **no test in this repository could link a client crate and a server crate
at the same time**, and that was the shared cause of the wave's cross-artifact
defects. These two are what that change bought.

### `integration/revocation_at_the_peer.rs` — assumption **A-06**

> Device revocation is enforced at the **peer** and not solely at the control
> plane, so revocation survives control-plane unavailability with a bounded
> propagation delay. […] **P10** must be reframed as "revoked devices cannot
> reconnect *while the control plane is reachable*", a materially weaker
> property.

`services/control-plane/tests/authorization.rs` proves the server half.
`twinvpn-trust`'s own tests prove the device half. **Neither can show that the
statement the server verified is the statement the device acts on**, because
neither can link the other — and that is exactly the claim A-06 makes.

The device half runs with no control plane in the process at all: not a mocked
one, not an unreachable one. The `RevocationState` is constructed, the Owner's
statement is applied, the peer is refused, in code that has never heard of
`ControlStore`. That is what "survives control-plane unavailability" has to mean
if it is to mean anything.

### `chaos/store_outage.rs` — §2.13's database outage

`PgStore` **has never been run** — no PostgreSQL, no Docker, and
`services/control-plane/README.md` §9 says so. Killing a database that is not
there would test nothing.

What is real is the **seam**. `ControlStore` is the trait every command goes
through, both stores implement it, and every rule an outage could break — the
dedup log, `net_seq` allocation inside the mutating transaction, the
never-shrinking revoked set — lives above it. So a store that starts failing
takes the same refusal path, and the properties that matter are decidable: the
refusal carries a **registered** code, the log head does not move, the durable
log stays **dense** across the outage, and the identical command commits once the
store returns without being served as a replay of one that never committed.

Two outages are kept apart, because §3.4 and `infra/README.md` §5 keep them
apart: an unreachable datastore, and a reachable one whose write lease this
process cannot obtain.

**One assertion in this file was wrong and the service was right.** It first
asserted that a lease-less writer must report not-ready. It must not: mutations
are refused with a `TRANSIENT`, retryable `CONTROL.WRITE_LEADER_UNAVAILABLE`, and
taking every follower out of service during a normal leader handover would turn a
handover into an outage. The test now asserts the contract the service
documents — the condition must be **visible** in `lease_held`, and the follower
must stay in service — and records that it was asserting a design its author
assumed rather than the one that exists.
