# `twinvpn-core` — the composition root

The **only** crate that may name both planes (ADR-0018 CD-I5). Eight domains'
worth of components take their capabilities and decide nothing about where those
capabilities come from; this crate is where they come from.

**Authority:** [ADR-0018](../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
§11.4, §11.6, §11.7, §11.8, §11.12, §11.17. **Owner:** `core-composition`.

---

## 1. Building and testing

```bash
source build/toolchain/env.sh
cd core
cargo test -p twinvpn-core                                     # the full profile
cargo test -p twinvpn-core --no-default-features --features core-lite
cargo run -q -p xtask -- lint                                  # CD-I5 lives here
```

`cargo run -p xtask -- lint` is not optional for this crate: `cd_i5` asserts that
no crate *below* the composition root names both planes, and
`cd_i5_composition_root_wired` asserts the positive half — that **this** crate
really does name both. Both must pass, and the second is what stops CD-I5
passing trivially on a workspace where nothing is connected.

---

## 2. Environment configuration

**This crate reads no environment variable, no configuration file and no ambient
setting at run time.** That is CD-2: every component takes its `Env` at
construction, and `CoreParts` has no `Default`, no builder with optional fields,
and no way to be constructed with a capability missing.

Two variables are read **at build time** by `build.rs`, and both are facts about
the build rather than configuration:

| Variable | Read by | Effect |
|---|---|---|
| `TARGET` | cargo → `build.rs` | `CoreBuildIdentity.target_triple` — the triple this artifact was built **for** |
| `TWINVPN_SOURCE_COMMIT` | the release pipeline | `CoreBuildIdentity.source_commit`. **Never read from git**: a dirty worktree would otherwise produce a commit-labelled artifact matching no commit. Absent, it is empty, which renders as "unstamped" |

---

## 3. Local startup and debugging

### Bringing a core up with no shell

```rust
use twinvpn_core::{testing, Core};

let core = testing::core().expect("a mock-bound core");
core.submit(&twinvpn_mgmt::Submission::bare(twinvpn_mgmt::CoreCommand::StatusGet))?;
let event = core.next_event(std::time::Duration::from_millis(100));
```

`testing` is behind the `test-support` feature and is **never shipped**. It binds
`twinvpn-platform`'s mock adapter and `twinvpn-env`'s virtual clock, which is
CD-5's "100% of the decision logic on a Linux CI runner with no VM and no device
farm".

### Making time deterministic

```rust
let (env, vt) = twinvpn_core::testing::env();
vt.advance(Duration::from_secs(5));        // all three clocks
vt.suspend(Duration::from_secs(8 * 3600)); // elapsed + wall ONLY; no timer fires
```

Anything that hangs or "works on my machine" is usually a clock. The rule this
crate enforces at the arming site: **every timer takes `MonotonicClock`**, and
`session_loop::Timers::arm` panics on a constant that declares any other class.

### Tracing

Structured logging is `tracing`. **This crate installs no subscriber** — that is
a process-global side effect, there may be two cores in one process, and it is
the shell's job.

```bash
RUST_LOG=twinvpn::session=debug cargo test -p twinvpn-core -- --nocapture
```

---

## 4. The `core-lite` profile

ADR-0018 §11.12. A feature profile of the **same source** with no data-plane
crate:

```bash
cargo test -p twinvpn-core --no-default-features --features core-lite
cargo tree -p twinvpn-core --no-default-features --features core-lite -e normal
```

Measured on the current tree: **0** data-plane or control-plane-client crates in
the `core-lite` graph, **16** in the full one. `tests/core_lite_profile.rs`
asserts the manifest property that produces it, and `lite::capabilities()` refuses
`Fetch` and `Recover` — §11.12's *"`core-lite` MUST NOT sit on a fetch path or on
any recovery path"*.

---

## 5. Where the crates this composes disagreed

Recorded here because the next person to touch this crate will meet them.

### 5.1 `SessionJournal` is sync; `Store` is async and `&mut`

| | `twinvpn_session::journal::SessionJournal` | `twinvpn_store::Store` |
|---|---|---|
| Mutability | `&self` | `commit(&mut self)` |
| Sync/async | synchronous | `async` |
| Granularity | one record per call | one multi-key `Transaction` (ST-12b) |

`journal::CoreSessionJournal` bridges them with a write-behind queue that
`bridge::StoreBridge::flush` drains into **one** transaction. **The cost:** after
this adapter, a successful `persist` means *queued*, not *durable*. `reliability.md`
§6.5's guarantee holds as long as the composition root flushes before it can
crash; a crash inside that window loses the most recent transition, not the
`Session`. Making `SessionJournal` async would preserve the trait's wording and
is a change to another domain's crate.

### 5.2 `ControlPlaneStore` wants a `StoredDocumentMark` the store cannot build

`cp_binding::ControlPlaneBinding::document_version` returns `Ok(None)`.
`StoredDocumentMark` carries `issued_at_ms`, `refresh_after_ms` and
`not_after_ms` — three facts that live **inside the signed payload**, which the
bridge stores verbatim and never decodes (ST-13, W-4). Returning a mark with
invented band boundaries would make the client's staleness ladder run on fiction.

### 5.3 `ControlTransport` has no production binding anywhere

`ownership.md` §8 **W-12** puts `rustls` in `twinvpn-crypto` and permits `quinn`
in `twinvpn-cp-client`, with `twinvpn-core` wiring the two. Neither crate declares
its half — `twinvpn-crypto` ships no TLS module and no `CryptoProvider`;
`twinvpn-cp-client` ships the trait and scripted test doubles. Both are other
domains' crates. **The composed core therefore has no L-CONTROL transport.**

---

## 6. What this crate does, and what it refuses

> **Correction, recorded rather than quietly edited.** An earlier revision of
> this section said *"`Core::submit` executes a subset"* and listed fourteen
> unimplemented operations. That was **false in the most damaging direction**: it
> implied the other thirty-three executed. None did — `submit` performed the
> admission checks, published an empty `CommandCompleted` and returned `Ok`
> having called no component. The claim was relayed upward on this crate's
> authority, so the correction stays visible.

### 6.1 `Core::submit`, step by step

An admission gate followed by a **dispatcher**:

1. refuse if the instance is poisoned (F-7);
2. refuse if the ADR-0008 precondition the catalogue row declares (`key`/`ver`)
   is absent;
3. refuse if a required parameter is missing or malformed — **before any work**,
   so a command is never partially applied;
4. consult `dispatch::disposition`; a `NotWired` operation is **refused by
   name**, never a false success;
5. `execute::execute` performs it;
6. an operation that reports success with **zero observable effects** is itself
   reported as `INTERNAL.INVARIANT_VIOLATED` — the dispatcher said it executes
   and it did nothing.

`dispatch::disposition` and `execute::execute` are **two exhaustive matches over
the same enum**. A new `CoreCommand` fails to compile in both until someone
states whether it executes or why it does not. That mechanism is what the
earlier revision lacked.

### 6.2 The register

`core::executes(op)` and `core::unimplemented()` are **derived from
`dispatch::disposition`** — there is no second list to drift.
`tests/command_path.rs` submits **all 47** catalogue operations and asserts each
one either completes with an effect or is refused with a registered code; there
is no third outcome, and an operation returning `Ok` with nothing behind it fails
that test.

**16 execute.** `status.get`, `session.list`, `session.get`, `path.list`,
`version.get`, `metrics.get`, `lifecycle.get`, `session.connect`,
`session.disconnect`, `session.reconnect`, `net.up`, `net.down`,
`event.subscribe`, `event.unsubscribe`, `host.network_changed`,
`host.lifecycle`.

**31 are refused**, each with a registered code and a stated reason. The reasons
cluster into five causes, and none of them is this crate's to fix alone:

| Cause | Operations |
|---|---|
| **W-12** — no `ControlTransport` exists in the workspace | `peer.*`, `policy.get`, `device.revoke`, `key.rotate`, `dns.preference.set`, `route.accept.set`, `exitnode.select` |
| **W-24** — F-9 has no `installed_ruleset` read-back, so the `ProtectionAssertion` cannot be produced | `killswitch.get`, `killswitch.exempt.get`, `killswitch.mode.set`, `diag.report` |
| **D4-adjacent** — the operation is vault-backed and needs `open_store` | `settings.*`, `autostart.set`, `diag.bundle.create`, `diag.log.tail`, `diag.capture.set` |
| **W-21** — `PairingOffer` appears nowhere in `contracts/` | `pair.*` |
| **no owner built it** — ADR-0021's delivery, ADR-0016's local auth, `DiscoAuth` | `update.*`, `killswitch.disarm.*`, `path.probe`, `capability.get` |

### 6.3 What `session.connect` actually does

The operation a Phase 4 gate opens with, and the one that forces the chain:

1. **gathers on the platform** — `supported_families`, `enumerate`, and one
   `bind_udp` **per family** (ADR-0010 R1; `tests/command_path.rs` asserts two
   sockets open);
2. drives **T01** through the real §4.5 table, then **T03** or **T04** on the
   gathered set;
3. admits the candidates into `twinvpn-path`'s `Ledger` and schedules its `Race`;
4. **probes** — a bounded, keyless reachability datagram from the socket whose
   family matches the peer endpoint, marking the candidate `Probing` and **never**
   `Validated` (ADR-0007 N-4);
5. persists the `Session` to the journal (S-12);
6. publishes the §4.4 `ConnectionRequested` event and every transition on the one
   ordered stream.

It is **naturally idempotent** (§11.9's `nat`) because the `SessionId` is derived
from the peer's `device_id`: connecting twice reaches one `Session`.

`Core::tick()` is the step a daemon runs on each wake — §4.4 staggers the race by
the Happy-Eyeballs bias, so the v4 half is not due at t=0 and a one-shot
`connect` would never probe it.

### 6.4 The vault (D4)

`Core::open_store()` opens the vault, hydrates the `BridgeState` and the session
journal from it, and reports the ST-24 outcome. `Core::flush()` drains every
queued write into **one** transaction (ST-12b). `Core::shutdown()` flushes
**before** it stops accepting work — `begin_shutdown` is synchronous and cannot.

**Until a host calls `open_store`, the core is memory-only, and it says so.**
`Core::vault_state()` answers `Absent`, `flush` refuses with
`STORE.CUSTODY_DEGRADED` rather than reporting success, and every vault-backed
operation is refused. `Core::create` cannot open it itself: `Store::open` is
`async` and needs a runtime that is not running at construction.

### 6.5 Still not wired

- **The tunnel.** `session.connect` reaches `NEGOTIATING`; it does not program a
  kernel WireGuard peer or install a network contract. `twinvpn-tunnel`'s
  handshake driver needs a `NoiseHandshake` binding `twinvpn-crypto` exposes only
  for verification, and `apply` needs the encoded plan F-9 defines no encoding
  for (`twinvpn-ffi/README.md` §5).
- **`credentials_valid` and `peer_authorized` are supplied as `true`.**
  `twinvpn-trust`'s peer set is populated over C2 and there is no transport
  (W-12), so this build cannot check them. **A real weakness**, not a
  simplification: a build with a trust store must supply the real values.
- **Nothing subscribes to `InterfaceProvider::subscribe`.** `host.network_changed`
  re-enumerates on submission; there is no running task feeding
  `event_for_change`, because the F-9 vtable carries no interface stream.
- **`twinvpn-cp-client` is bound to the store and driven by nothing** (W-12).
- **`EPOCH_TABLE` declares `1..=1`** on the integration lead's authority to
  confirm. VR-3 forbids inferring it, so the table declares it and says so.
- **The seam cannot report an interface's own address.** `InterfaceFacts.addresses`
  is `Vec<IpPrefix>`, and `IpPrefix::new` rejects any set host bit while
  `address()` is *"the network address"*. `establish::host_address` accepts only
  a single-host prefix (`/32`, `/128`) and reports
  `FamilyOutcome::AddressNotReportable` for anything else, because a network
  address as a candidate would probe somewhere nothing answers and look like a
  NAT fault. The fix belongs in `twinvpn-platform`.
