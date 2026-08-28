# `core/` — the TwinVPN shared core

One cargo workspace, every `twinvpn-*` crate (ADR-0018 §11.12). This file covers
what a developer needs to build, test, debug and extend it. The *architecture* is
[ADR-0018](../docs/adr/ADR-0018-shared-core-and-build-architecture.md); the
*ownership map* is [`docs/implementation/ownership.md`](../docs/implementation/ownership.md).

---

## 1. Getting a build

```bash
source build/toolchain/env.sh      # puts the pinned toolchain on PATH
cd core
cargo build --workspace --all-targets
```

The Rust toolchain is pinned exactly, in [`rust-toolchain.toml`](../rust-toolchain.toml).
ADR-0018 §11.3 requires "one exact toolchain version … advanced only by a
reviewed commit that re-runs the full §11.9 matrix", so `rustup` will fetch that
version rather than use whatever is default.

`cargo` needs no network for a normal build once `cargo fetch` has run once; add
`--offline` to be sure it is not reaching out.

---

## 2. The gate, exactly as CI runs it

```bash
source build/toolchain/env.sh
cd core
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -q -p xtask -- lint      # the ADR-0018 T1 architectural lints
cd ..
make test-contracts                # must report 0 failures
```

`make test-contracts` needs `node_modules/.bin/buf`, which `npm ci` installs at
the repository root. In a `git worktree` that directory is absent (it is
git-ignored, so it lives only in the primary checkout); symlink it or run `npm ci`
inside the worktree.

---

## 3. The crates this directory currently contains

`core-foundation` owns the four crates below and `xtask`. Every other crate is a
skeleton until its domain lands; see `ownership.md` §2 and §7.

| Crate | What it is | Depends on |
|---|---|---|
| [`twinvpn-types`](crates/twinvpn-types) | the domain vocabulary: identifiers, addresses, `ConnectionState`, `reason_code`, evidence, `Diagnostic` | no workspace crate; `thiserror`, `zeroize`, `subtle` |
| [`twinvpn-env`](crates/twinvpn-env) | **the only source of time, timers, randomness and the runtime** | `twinvpn-types`, `futures-core`, `tokio` (optional) |
| [`twinvpn-schema`](crates/twinvpn-schema) | the frozen contract bindings, and validation of untrusted input | `twinvpn-types`, `prost` |
| [`twinvpn-platform`](crates/twinvpn-platform) | the platform adapter **trait** — the seam | `twinvpn-types`, `twinvpn-env` |
| [`xtask`](xtask) | the T1 architectural lints | `serde_json` |

### Feature flags

| Crate | Feature | Default | What it turns on |
|---|---|---|---|
| `twinvpn-env` | `runtime-tokio` | **on** | ADR-0018 §11.3's work-stealing and single-threaded `Runtime` bindings |
| `twinvpn-env` | `test-support` | off | `virtual_time::VirtualTime` — the virtual-clock driver TwinLab drives |
| `twinvpn-platform` | `mock` | off | the in-memory binding of every trait (CD-5) |

Neither `test-support` nor `mock` is ever shipped. `cargo test --workspace`
enables both, through each crate's dev-dependency on itself.

---

## 4. Environment configuration

**The core reads no environment variable, no configuration file and no ambient
setting.** That is not an omission; it is CD-2:

> Every component takes its `Env` at construction. No global, no `OnceCell`
> clock, no ambient default.

Everything a component needs — the three clocks, the timer, the runtime, the
CSPRNG, the per-consumer random streams — arrives as
[`twinvpn_env::Env`](crates/twinvpn-env/src/env.rs), which the composition root
builds and passes down. A component that reads a global is a defect
`cargo run -p xtask -- lint` is there to catch.

The variables that *do* matter are all build-time or tooling:

| Variable | Set by | Effect |
|---|---|---|
| `RUST_LOG` | you | the `tracing` filter, when a shell installs a subscriber. The core emits spans and events; it installs no subscriber of its own |
| `CARGO_TERM_COLOR` | you | cargo output only |
| `CARGO` | cargo | `xtask` uses it to find the cargo that invoked it |
| `RUST_BACKTRACE` | you | a backtrace on a test failure |

Nothing in the core reads `TZ`, `HOME`, `TMPDIR` or a proxy variable. The vault
directory is *vended by the shell* through
[`SecureStore::store_root`](crates/twinvpn-platform/src/custody.rs), never
discovered from the environment (CB-7).

---

## 5. Debugging

### Tracing

Structured logging is `tracing`. A shell installs the subscriber; the core never
does, because installing one is a process-global side effect and there may be
two cores in one process.

```bash
RUST_LOG=twinvpn_env=trace,twinvpn_schema=debug cargo test -p twinvpn-env -- --nocapture
```

**What is never logged**, per `ownership.md` §6 rule 11: private keys, session
keys, raw tunnel payloads, pairing secrets, authentication tokens. The types
enforce it where they can — `DeviceId`, `ChannelBinding`, `SharedSecret`,
`SecureItem`, `V4Addr`, `V6Addr` and `InterfaceName` all have a **redacted
`Debug`**, so a value cannot reach a log through a derived `Debug` on some
enclosing struct. Where you genuinely need the bytes, `to_hex()` and
`as_bytes()` are explicit and greppable.

The secret-bearing types — `ChannelBinding`, `SharedSecret`, `SecureItem` —
derive `ZeroizeOnDrop`, so the scrub is a volatile write with a compiler fence
rather than an elidable `fill(0)`, and `SharedSecret::expose_for_kdf` /
`SecureItem::into_bytes` hand back a `Zeroizing<Vec<u8>>` so the scrub follows
the bytes rather than stopping at the type boundary. `ChannelBinding::verify_against`
uses `subtle::ConstantTimeEq`. Neither `zeroize` nor `subtle` is a cryptographic
implementation, so CD-I2 does not restrict them — see the exemption and its
reasoning in `xtask/src/checks.rs`.

### Making time deterministic

Anything that hangs, races, or "works on my machine" is usually a clock. Bind the
virtual-time driver instead of the real one:

```rust
use twinvpn_env::virtual_time::VirtualTime;
use twinvpn_env::{Env, EnvParts, WallClockReading};

let vt = VirtualTime::new(WallClockReading::Unset);   // an RTC-less GC-0 device
let env = Env::new(EnvParts {
    monotonic: vt.monotonic(),
    elapsed:   vt.elapsed(),
    wall:      vt.wall(),
    timer:     vt.timer(),
    runtime:   vt.runtime(),
    entropy:   my_entropy,
    rng:       my_rng_source,
});

vt.advance(Duration::from_secs(5));       // all three clocks
vt.suspend(Duration::from_secs(8 * 3600)); // elapsed + wall ONLY; no timer fires
```

`runtime.block_on(..)` advances virtual time to the next deadline whenever the
future stalls, so an eight-hour scenario costs no wall time at all.

`vt.timers_fired()` and `vt.timers_pending()` are cheap `BIT` assertions when a
timer is not firing when you expect.

### Reproducing a random decision

Every draw comes from `Env::rng_for(consumer)` with a `const` consumer id. Under
the seeded binding the stream is a pure function of `(scenario_seed, consumer_id)`,
so a scenario reproduces exactly — and **adding a consumer does not shift an
existing consumer's stream**, which is what makes a seed still useful a year
later. See `crates/twinvpn-env/src/rng.rs`.

### Reading a rejection

A validator returns a typed
[`Reject`](crates/twinvpn-schema/src/reject.rs) that names the `limits.json` key
it violated. `reject.diagnostic(component)` turns it into the registered
`reason_code` with its declared evidence:

```
PROTO.MALFORMED_MESSAGE  cap_violated=device_id_bytes observed=31 limit=32
```

`reason.doc_anchor()` gives the ADR section that owns the condition.

---

## 6. The T1 lints, and what to do when one fires

```bash
cargo run -q -p xtask -- lint
```

| Rule | Fires when | The fix |
|---|---|---|
| **CD-3** | a deny-listed time or randomness API appears outside `crates/twinvpn-env/src/binding/` | take the capability from `Env`. `MonotonicClock` for a timer, `ElapsedClock` across a suspend, `WallClock` for evidence only |
| **CD-I2** | a crate other than `twinvpn-crypto` declares a cryptographic **implementation** | ask `core-security` for the operation behind a trait; do not add the crate. `zeroize` and `subtle` are exempt — they implement no cryptography; see `CD_I2_NOT_CRYPTO_IMPLEMENTATIONS` |
| **CD-I5** | a data-plane crate reaches `twinvpn-cp-client`, directly or transitively, or the reverse | route it through `twinvpn-store`. Only `twinvpn-core` may name both planes |
| **CD-CB3** | `#[cfg(target_os = …)]` outside a `twinvpn-platform-*` crate | branch on a **declared capability** instead: `Datapath`, `EnforcementCustody`, `RecordAeadCustody`, `SupportedFamilies`, `LinkClass` |

The lints ignore comments and string literals, so documenting a banned API does
not trip them. Each one has a test in `xtask/tests/lints_fire.rs` that plants a
deliberate violation and asserts it fires — a lint nobody has seen fail is not a
lint.

---

## 7. Extending the core

1. **Take `Env` at construction.** No global, no `Default`, no lazily-initialised
   clock.
2. **Validate every untrusted input** through `twinvpn_schema::validate`, and do
   it *before* any allocation proportional to a declared length.
3. **Return a registered `reason_code`.** `twinvpn_types::codes` has all 201 of
   them; there is no way to name one that is not in the frozen registry.
4. **Consider both address families.** `PerFamily<T>` and `OverlayAddresses` make
   forgetting the v6 half a compile error rather than a review comment.
5. **Keep `#![forbid(unsafe_code)]`.** None of these crates is on the DP-4
   allowlist.
6. **Do not edit `Cargo.toml` at the workspace root**, `contracts/`, or another
   domain's crate. Ask the integration lead.

---

## 8. Known gaps in this directory

Stated here rather than discovered later:

- **There is no production `ElapsedClock`.** `std` has no suspend-inclusive
  clock; the shell supplies one through
  `twinvpn_env::binding::system::ElapsedClockFn`. Substituting the monotonic
  clock compiles and is invisible on Linux CI.
- **There is no production `Entropy`.** CD-3 bans `getrandom`; the shell supplies
  the platform CSPRNG.
- **CD-4's HKDF is supplied by the binding**, not by `twinvpn-env`, because
  CD-I2 restricts cryptographic dependencies to `twinvpn-crypto`. See
  `crates/twinvpn-env/src/rng.rs`.
- **`prost` 0.13 drops unknown protobuf fields.** A forwarding component must
  forward received octets verbatim rather than decode-then-re-encode. Measured by
  `unknown_fields_are_dropped_by_prost_0_13`.
- **Capability names validate against 32, not `limits.json`'s 24.** An open
  contract defect; see `ownership.md` §4.3 and
  `crates/twinvpn-schema/src/limits.rs`.
