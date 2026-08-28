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
cargo test --workspace          # 121 tests, ~1 s after the first build
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
| `integration/dual_stack_parity.rs` | 6 + 9 — integration, networking | 12 |
| `integration/cross_component_agreement.rs` | 4 — contract | 20 |
| `integration/tunnel_wire_agreement.rs` | 6 — sender against receiver | 8 |
| `chaos/outage_and_failover.rs` | 15 — chaos | 11 |
| `chaos/journal_write_behind.rs` | 15 — chaos, **W-28** measured | 7 |
| `compatibility/golden_vectors.rs` | 3 + 19 — protocol, compatibility | 8 |
| `system/` | the shared rigs (`Rig`, `ComposedRig`, `AdapterStore`, `block_on`) | — |
| `vectors/crypto-kat/` | §2.3's `crypto-kat/` corpus | 7 vectors |

`system/Cargo.toml` declares each file as a `[[test]]` target with an explicit
`path`, so the directories say what level a file belongs to without anyone
having to open it.

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
| **T3** | nothing yet — the levels that need TwinLab's namespace rig live in `lab/`, and nothing here needs a network | — |
| **T4** | nothing yet | — |

The whole suite is **≈ 1 s** including compilation of the composed core, which
is deliberate: everything here is a decision the core makes, and CD-5's mock is
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
