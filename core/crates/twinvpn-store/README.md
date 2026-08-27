# `twinvpn-store`

The Tier-2 vault, its transaction engine, and the anti-rollback machinery.

**Owner:** `core-security`. **Authority:** ADR-0020 in full; ADR-0018 CB-7 (where
the store splits), CB-5 row 3 and CB-6a (the SEK's custody); ADR-0009 R-9 and
§11.4; ADR-0007 N-26.

## What is here, and what is the shell's

CB-7 draws the line at "all decision", not at the word "store".

| Concern | Side | Where |
|---|---|---|
| Record envelopes, AEAD use, namespaces, schema, migration, monotone-floor rejection, the recovery ladder, **multi-key commit** | **Core** | this crate |
| Tier-2 vault file I/O | **Core**, beneath a vended `store_root` | `vault.rs` |
| Vending `store_root`, the file-protection class, backup exclusion | **Shell** | `twinvpn_platform::SecureStore::store_root` |
| Tier-1 secure items — `SEK`, `K_bind`, the S-53 anchor | **Shell** | `secure_item_*` |
| The identity private half | **Shell only** | CB-5, untouched |

## Environment configuration

**None, and deliberately.** ST-12e: "`store_root` is vended at construction,
never discovered. The core MUST receive `store_root` as an injected value whose
platform attributes are **already applied**, and MUST NOT derive, probe for, or
fall back to a path of its own choosing."

`Store::open` takes an `Env` and an `Arc<dyn SecureStore>`. There is no path
constant, no `$HOME` lookup, and no default directory anywhere in this crate.

## The file set, beneath the vended root

```
<store_root>/
  vault.tv        the transactional vault
  vault.lock      the single-opener lock and its owner record
  vault.tv.tmp    transient, during a commit
  vault.corrupt.<store_seq>   quarantined at rung L3; never deleted
  vault.v<N>.bak  the pre-migration copy ST-15 rule 3 retains
```

## Local startup and debugging

```bash
source build/toolchain/env.sh
cd core
cargo test -p twinvpn-store                 # 49 unit tests
cargo test -p twinvpn-store --test ladder   # 11 ST-23/ST-24 attack tests
```

`tests/ladder.rs` interrupts a commit at each ST-23 step and asserts the
classification, so the ladder's rungs are entered rather than merely described.

### Reading an open outcome

`Store::open` returns an `OpenOutcome` rather than logging. Act on it:

| Field | Meaning |
|---|---|
| `state` | ST-24's classification — `Healthy`, `VaultRolledBack`, `Forked`, `AnchorBehind`, `AnchorMissingIdentityPresent`, `AnchorAndIdentityMissing`, `VaultAbsent`, `FirstRun` |
| `rung` | which rung of §11.11 the ladder entered at |
| `suspend_granted_authority` | exit use, LAN access, route acceptance and new pairing must be suspended until a fresh signed document at or above the floors verifies. **Never** a reason to refuse a handshake to a known peer or to tear down a session (ST-35, R-11, I5) |
| `vault_rebuilt` | rung L3 quarantined the vault and rebuilt it empty |
| `floors` | the floors in force after the ladder ran |
| `sek_custody` | CB-6a's declared per-target fact, as a stable tag for `CoreBuildIdentity` (S-46) and the diagnostic bundle |

### When a commit is refused

`StoreError::FloorWouldDecrease` carries `AUTH.TRUST_EPOCH_ROLLBACK` and means
ST-23 step 2 fired: **nothing was written**, not the anchor and not the vault.
That is the whole point of the ordering — the refusal happens before any side
effect.

### Known gaps, stated

- **The `STORE.*` registry gap.** ADR-0020 §11.12 registers twenty codes;
  `contracts/registry/reason_codes.json` contains six. `error.rs` documents each
  mapping and why it was chosen. Reported to the integration lead.
- **The engine is not the `redb`-class CoW B-tree ADR-0020 names.** `redb` is
  not in the workspace dependency table. This wave commits by
  `write → fsync → rename → fsync(dir)`, which meets ST-12's E1–E4 and E6–E8 but
  is O(vault size) per commit and reads the file whole — E5's second clause.
  `vault.rs`'s module documentation has the property-by-property assessment.
- **No hardware counter.** ST-23 step 4 and ST-25 need a monotonic NV counter,
  and `SecureStore` offers whole-blob items only.
  `FloorProposal::advances_a_trust_floor()` carries the signal so a shell that
  gains one can act on it.

## Features

| Feature | Default | Contents |
|---|---|---|
| `test-support` | off | `testenv` — a virtual-clock `Env`, a deterministic non-cryptographic entropy source, and a blocking driver. Never enabled in a shipped build |
