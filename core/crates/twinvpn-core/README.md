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

## 6. Known gaps in this crate

> **Correction, recorded rather than quietly edited.** An earlier revision of this
> section said *"`Core::submit` executes a subset"* and listed the fourteen
> operations in `UNIMPLEMENTED`. That was **false in the most damaging
> direction**: it implied the other thirty-three executed. None did. The claim was
> relayed upward on this crate's authority, so the correction is left visible.

### 6.1 What `Core::submit` does today

**It performs admission checks and then does nothing.** In full, `core.rs`:

1. refuses if the instance is poisoned (F-7);
2. refuses if the ADR-0008 precondition its catalogue row declares (`key` or
   `ver`) is absent;
3. refuses with the `MGMT.OP_UNKNOWN` substitute if the operation is in
   [`core::UNIMPLEMENTED`];
4. increments the S-47 `generation` if the row is mutating;
5. publishes `CommandCompleted { result: <empty> }`;
6. returns `Ok(())`.

There is no step that calls a component. `CoreCommand` declares **47** variants
and `UNIMPLEMENTED` names **14**; the other **33 — `session.connect` among
them — report success and execute no work.** `core.rs` names no data-plane or
control-plane crate at all:

```bash
grep -cE "twinvpn_(session|path|relay_client|tunnel|cp_client|trust|route|dns|enforce)" \
  core/crates/twinvpn-core/src/core.rs      # 0
```

Every operation returns an empty result. There is no query path either: a
`status.get` submission publishes an empty `CommandCompleted` and tells the
caller nothing.

**What *is* wired and tested** is everything around that hole: the CD-I5 ports
(`planes.rs`), the store bridge (`bridge.rs`), the `ControlPlaneStore` adapter
(`cp_binding.rs`), the `SessionJournal` adapter (`journal.rs`), the `Env`-driven
timer and event mapping (`session_loop.rs`), S-46, the ordered event stream and
the poison path. The components below are real. **The join is not made.**

Consequence for anyone building on this: **do not read `Ok(())` from `submit` as
evidence that anything happened.** Until §6.2 is closed, the only honest reading
is "the submission was admissible".

### 6.2 The vault is never opened (D4)

`StoreBridge::new` is constructed **nowhere** in `core/`, `services/` or
`shells/`. `Core::create` initialises an empty `BridgeState` and never hydrates
it, and `Core::begin_shutdown` closes the event stream and the adapter **without
flushing**, because the `Core` holds no bridge.

So S-12, S-15, S-27, S-30 and S-37 are **memory-only**, and §5.1's crash window
is not "the last transition" — it is the **entire process lifetime**. Nothing
`reliability.md` §9.1 promises about an outage holds on this build.

A live sub-defect sits behind it: `bridge.rs`'s `encode_peer` writes
`endpoints.len()` as a `u32` and then **discards the endpoints**, and no
`decode_peer` exists. `PeerRecord.endpoints` is documented as *"what a reconnect
during a total outage uses"*. Its unit test asserts a fixed `bytes.len() == 65`,
which can only be right *because* the endpoints are dropped.

### 6.3 The rest

- **The session loop is a driver, not a daemon.** `SessionRuntime` arms
  deadlines, fires them and applies triggers, but nothing subscribes to
  `InterfaceProvider::subscribe` and feeds `event_for_change` into it on a running
  task — the F-9 vtable carries no interface stream.
- **`SessionRuntime` re-arms only on a state *change*** (W-34). A timer that
  fires and matches no row leaves its deadline consumed with nothing re-arming
  it, which is the shape of an unbounded state that §4.4 bounds deliberately.
- **`twinvpn-cp-client` is bound to the store and driven by nothing**, because no
  `ControlTransport` implementation exists in the workspace (W-12, §5.3).
- **`EPOCH_TABLE` declares `1..=1` on the integration lead's authority to
  confirm.** No Phase 1 document states the numeric launch epoch; VR-3 forbids
  inferring it, so the table declares it and says so.
