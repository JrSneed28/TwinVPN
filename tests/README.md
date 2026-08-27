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
cargo test --workspace          # 80 tests, ~1 s after the first build
```

> **INTEGRATION-LEAD ACTION REQUESTED.** `tests/` is a fifth cargo workspace and
> the `Makefile`'s `WORKSPACES := core services shells/linux lab` does not
> include it, so **`make lint` and `make test` do not run anything here today**.
> One line closes that:
>
> ```make
> WORKSPACES := core services shells/linux lab tests
> ```
>
> A test suite outside the gate is a suite that will rot. This is the single most
> important integration action this domain asks for.

---

## 2. Layout, and what each level is for

| Path | Level (§2 of `docs/testing-strategy.md`) | Tests |
|---|---|---|
| `e2e/session_lifecycle.rs` | 7 — end-to-end | 13 |
| `e2e/fail_closed_leak.rs` | 7 + 12 — end-to-end, security | 15 |
| `integration/dual_stack_parity.rs` | 6 + 9 — integration, networking | 12 |
| `integration/cross_component_agreement.rs` | 4 — contract | 13 |
| `chaos/outage_and_failover.rs` | 15 — chaos | 11 |
| `compatibility/golden_vectors.rs` | 3 + 19 — protocol, compatibility | 8 |
| `defects/tripwires.rs` | — | 8 |
| `system/` | the shared rig (`Rig`, `HostFamily`, `block_on`, the DNS-policy builder) | — |
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

It does **not** drive `twinvpn-core`. That crate contained no items while this
was written; `composition_root_is_populated()` is an executable observation of
that, and `the_composition_root_is_still_empty` fails the day the composition
root lands — which is when these tests should be re-pointed at it.

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

---

## 4. `defects/tripwires.rs` — read this before trusting the suite

Five defects in **other domains'** components are recorded here as executable
evidence. Each test asserts the **defective behaviour that exists today**, names
the correct behaviour in its comment, and **fails the moment the defect is
fixed** — at which point the test is deleted.

That is deliberate, and it is the only honest option this domain has:

- asserting the *correct* behaviour would leave a red suite, which under §6.3
  **F-3** is a quarantine, and a quarantine hides the finding;
- fixing the component would breach ownership — `ownership.md` §2 says a domain
  "files findings, does not silently rewrite".

The pattern is the wave's own (finding **W-18**: "a tripwire test asserting the
spelling is still absent, so registering a code fails the build and points at
the line to delete").

**Every test in that file is a bug report with a `cargo test` attached. None of
them is an endorsement.**

| # | Defect | Severity | Owner |
|---|---|---|---|
| **D-1** | The **first data packet of every tunnel is rejected as a replay.** `SendCounter` issues counter 0 first; `ReplayWindow::would_accept(0)` is `false` on a fresh window. | **P1** | `core-dataplane` (`twinvpn-tunnel`) |
| **D-2** | The relay score's measurement floors never apply — `-x.max(-250)` parses as `-(x.max(-250))`, so `MAX_MEASUREMENT_PENALTY = -410` is not enforced and one bad RTT sample can rank a healthy relay below an `UNHEALTHY` one. | **P2** | `core-dataplane` (`twinvpn-relay-client`) |
| **D-3** | `RouteError::DefaultSingleFamily` is unreachable: the family is blocked before the guard tests whether it was blocked, so the diagnostic is never emitted. | P3 | `core-dataplane` (`twinvpn-route`) |
| **D-4** | `RestorePoint` derives `Debug` over the host's verbatim prior resolver configuration; the `RestorePointRedactionMarker` in the same file is attached to nothing. | P3 | `core-dataplane` (`twinvpn-dns`) |
| **D-5** | A `RESOLVER`-class exempt socket is port-permitted to **443**, wider than the function's own documentation. | P3 | `core-dataplane` (`twinvpn-dns`) |

Two more findings live in `integration/cross_component_agreement.rs` as
tripwires rather than in the table above, because they are *absences*:

- **the relay data frame has no device-side implementation.** `services/relay`
  implements ADR-0005 §9.1's 16-byte header; nothing in
  `core/crates/twinvpn-relay-client` does. The device can select, bind and fail
  over between relays and cannot put a byte on the wire to one.
- **`services/relay/src/lib.rs` says the forwarding payload is
  `twinvpn_service_common::Verbatim`; `src/forward.rs` uses
  `crate::frame::Opaque`.** One of the two is stale.

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
| **T1** | `integration/cross_component_agreement.rs`, `compatibility/golden_vectors.rs`, `defects/tripwires.rs` — all pure, no I/O, no privilege | **< 0.2 s** |
| **T2** | `e2e/*`, `integration/dual_stack_parity.rs`, `chaos/outage_and_failover.rs` — real components against `MockAdapter` | **< 0.1 s** |
| **T3** | nothing yet — the levels that need TwinLab's namespace rig live in `lab/`, and nothing in this directory needs a network | — |
| **T4** | nothing yet | — |

The whole suite is **≈ 1 s**, which is deliberate: everything here is a decision
the core makes, and CD-5's mock is what keeps that affordable. Nothing in this
directory opens a socket, touches the filesystem outside `target/`, or needs a
privilege.

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
- **No key material is generated or stored.** The `ReversibleKeys` stand-in in
  `defects/tripwires.rs` is explicitly not cryptography and says so; the crypto
  corpus is published test vectors.
