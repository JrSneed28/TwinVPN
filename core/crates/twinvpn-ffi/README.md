# `twinvpn-ffi` — the `twinvpn.h` C ABI

`core/ffi/include/twinvpn.h` is the **ABI of record**. It is hand-written
(ADR-0018 §11.4 adopts alternative H), nothing generates it, and
`tests/header_matches_rust.rs` fails if it and this crate drift.

**Authority:** ADR-0018 §11.4 (F-1…F-10), §11.5, §11.6, §11.12 (VR-2, VR-4),
§11.13 (PB-1), DP-4. **Owner:** `core-composition`.

---

## 1. Building and testing

```bash
source build/toolchain/env.sh
cd core
cargo test -p twinvpn-ffi                      # includes the drift test
cargo build -p twinvpn-ffi --release           # staticlib + cdylib + rlib
```

Artifacts land in `core/target/<profile>/`: `libtwinvpn_ffi.a` for a static link
(Windows service, Linux `twinvpnd`) and `libtwinvpn_ffi.so`/`.dylib` for the
Swift and Kotlin bindings (§11.5).

## 2. Environment configuration

**None at run time.** Every capability arrives through `tw_host_vtable` (CD-2).

---

## 3. The surface, function by function

Twelve exported functions. F-1: *"every exported function is a compatibility
obligation forever; convenience added here is permanent."*

| Symbol | Blocking | Purpose |
|---|---|---|
| `tw_abi_major` / `tw_abi_minor` | no | V-B. **In-process only** (VR-2): never a compatibility input across a wire, never branched on by a receiver |
| `tw_build_identity` | no | S-46, encoded. Static storage, **never freed** — the value is a property of the loaded binary |
| `tw_reason_registry_version` | no | the registry this build compiled against; reaches a bundle with no live instance |
| `tw_render_diagnostic` | no | **F-10**, F-1's one exception. Pure, instance-free, callable while poisoned |
| `tw_core_create` | no | checks `abi_major` **first** (VR-4), assembles the `Env` from the vtable, builds the adapter |
| `tw_core_destroy` | no | graceful shutdown; **does not** tear down the installed rule set (CB-6) |
| `tw_core_submit` | **no** | one command from the same set the MI carries |
| `tw_core_next_event` | **yes** | the **only** blocking call; explicit timeout, cancellable |
| `tw_core_wake` | no | cancels it, **from any thread** |
| `tw_buf_bytes` / `tw_buf_free` | no | core-allocated buffers (F-2) |

`tests/header_matches_rust.rs` asserts the list in both directions, pins its size
at twelve, checks the vtable's field **order** (F-9's `size` field makes order
load-bearing), and asserts that no `tw_send`/`tw_recv`/`tw_packet` symbol exists
— PB-1's zero-crossings budget, checked rather than assumed.

---

## 4. `unsafe` (DP-4)

**23 `unsafe` blocks in production code.** Every one carries a `// SAFETY:`
comment naming its invariant, and `the_unsafe_block_count_is_pinned` fails on a
net increase so a security reviewer sees it.

They fall into four groups:

| Group | Where | Count | Invariant |
|---|---|---|---|
| Slice reads | `abi::TwSlice::as_bytes` and its call sites | 6 | non-null + non-zero length ⇒ the caller's documented `tw_slice` contract; null or empty ⇒ the empty slice, never a dereference |
| Buffer lifecycle | `abi::TwBuf::{into_raw, release}`, `tw_buf_free`, `tw_core_destroy` | 4 | the pointer came from this crate's `Box::into_raw` and has not been released |
| Out-parameters | `abi::write_out` and its call sites | 6 | null-tolerant; a caller that declines a value gets no write |
| Instance and vtable reads | `abi::as_ref_opt`, `vtable::HostFns::copy_from` | 7 | null-checked first; the vtable's `size` is validated before any field beyond it is read |

Two `unsafe impl`s exist, both with their reasoning written at the definition:
`Send`/`Sync` for `abi::HostCtx` (an opaque token the core never dereferences)
and for `vtable::HostFns` (function pointers plus that token).

---

## 5. F-9's gaps, found by implementing it

Three things the core needs that the vtable §11.4 specifies does not carry. This
crate returns a **typed** `PLATFORM.ADAPTER_UNAVAILABLE` or
`PLATFORM.OS_UNSUPPORTED` from each rather than inventing ABI entries: extending
`twinvpn.h` is a permanent compatibility obligation and not this domain's to
create unilaterally.

1. **No `installed_ruleset` read-back. This is the one that matters.**
   ADR-0015 §11.6 rule 1: *"A `ProtectionAssertion` is produced by **querying the
   enforcement layer** … The user-visible protection indicator is a pure function
   of the most recent assertion, **never of the agent's belief about what it
   configured**."* F-9 offers `set_ruleset` and no getter, so across this ABI the
   assertion **cannot be produced at all**. Answering `Ok(None)` would be worse
   than failing — `None` reads as "no ruleset installed", the opposite of the
   truth — so the typed refusal makes the indicator render `UNKNOWN`, which is
   O-18's fail-safe direction. Same absence for `current_generation`, which
   `NetworkConfig` calls "the recovery entry point".
2. **No socket provider and no interface enumerator.** ADR-0018 §11.2 row 2.10
   puts all NAT traversal in the core with "sockets via the adapter", and
   `PlatformAdapter` requires `sockets()` and `interfaces()`. Neither has a
   vtable entry, so a shell that binds *only* this ABI cannot do NAT traversal.
   (§11.5's Rust hosts link the `staticlib` and use `twinvpn-platform-*`
   directly, so this bites the Swift and Kotlin consumers.)
3. **No `set_mtu`, and no encoding for `LinkFacts` or the `apply` plan.**
   DPLPMTUD raises and lowers the MTU as it probes (`networking.md` §6.2), and
   `query_link_facts` returns a blob whose shape no document defines. Decoding a
   shape nobody has specified would be inventing a contract.

**Four entries this crate added to the header**, all as minor-version additions
that F-9's `size` field permits, each with its reason in the header:
`buf_bytes` (F-2 makes the shell's allocation the shell's to free, so the core
must ask to read it), `identity_agree` (§11.6 lists it as a seam direction while
§11.4's struct omits it), `elapsed_millis` and `boot_id` (`ownership.md` §8
**W-7**: three required shell interfaces §11.16 does not list).

---

## 6. What is bound, and what is not

`env::assemble` builds the **real** production `Env` from the vtable: the system
monotonic clock, the shell's suspend-inclusive clock, a three-state wall clock, a
tokio runtime (work-stealing or single-threaded per §11.3), the platform CSPRNG
and the per-consumer RNG streams. It **refuses** rather than substituting when
`os_csprng` or `elapsed_millis` is absent — W-7's failure is invisible on Linux CI
and wrong on a phone.

`vtable::HostAdapter` binds `IdentityCustody`, `SecureStore`, `TunnelDevice` and
`NetworkConfig` to the vtable, and returns typed refusals for `sockets()` and
`interfaces()` per §5 above.

Not bound: `tw_core_submit` currently accepts an operation **name** rather than a
full encoded command with parameters, and drops the idempotency material. The
command-parameter encoding is a `contracts/` shape that does not exist yet
(OQ-2 excluded an MI transport schema), so the alternative was to invent one.
