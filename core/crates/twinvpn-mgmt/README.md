# `twinvpn-mgmt` — one vocabulary, two carriages

**Authority:** [ADR-0017](../../../docs/adr/ADR-0017-local-management-interface.md)
MI-1, MI-15, MI-20, MI-21, §11.5, §11.7, §11.9, §11.12; ADR-0018 F-5 and
§11.16 (b) and (o); `contracts/docs/phase1-conflicts.md` OQ-2.
**Owner:** `core-composition`.

---

## 1. Building and testing

```bash
source build/toolchain/env.sh
cd core && cargo test -p twinvpn-mgmt
```

## 2. Environment configuration

**None.** No environment variable, no configuration file (CD-2).

---

## 3. The one thing this crate is for

ADR-0018 §11.16 (b) asks for *"the same command set the core exposes over the ABI
— one contract, two carriages, **never two contracts**"*. MI-20 grants it: the MI
catalogue is **derived from the core's command/event set**, not specified beside
it.

```text
          twinvpn-mgmt::CoreCommand          <- the one vocabulary
                 |                    \
   twinvpn-core dispatches it     twinvpn-mgmt::catalogue derives from it
                 |                  (exhaustive match, NO wildcard arm)
          twinvpn-ffi carries it                    |
           over tw_core_submit             the CLI verb table (MI-C1)
```

**Why the enum is declared here and not in `twinvpn-core`.** ADR-0018 §11.7 puts
this crate *above* the composition root, so `twinvpn-core` depends on it and not
the reverse. Declaring `CoreCommand` here means the core dispatches **this** enum
and cannot invent an operation, because there is no other enum to invent one in.
Declaring it in `twinvpn-core` would leave this crate free to write a parallel
list — which is precisely the "independently-named MI vocabulary" MI-20's second
paragraph forbids and ADR-0018 B-02 says collapses F-1.

`catalogue::entry` is a single exhaustive `match` with no wildcard. Adding a core
command without a catalogue row is a **compile error**, which is MI-20's *"a core
command with no catalogue entry … is a build failure, not a review finding"*.

---

## 4. What this crate deliberately does not contain

- **No transport schema.** `contracts/docs/phase1-conflicts.md` OQ-2 excluded one
  from Phase 2 so the MI could not acquire an independent vocabulary. None is
  created here.
- **No rendered human text (MI-15).** Codes and typed evidence only; rendering is
  `twinvpn_diag::render`'s, on the consumer's own side.
- **No fifth transport operation.** MI-21's set is closed at four, and
  `transport::assert_closed` says so at run time as well as in the type.

---

## 5. The `MGMT.*` registry gap (W-18)

ADR-0017 owns the `MGMT` domain. `ownership.md` §8 **W-18** measures **38 `MGMT`
codes** named across Phase 1 against **4** in the frozen registry. Sixteen
spellings this crate needs are missing, including — in §11.9's own words — the
four that are *"possible on **every** operation"*.

`codes::SUBSTITUTIONS` records each one with its citation **and its cost**, and a
tripwire test asserts every specified spelling is still absent from the registry,
so registering one fails the build and names the row to delete.

The two costs worth reading before anything else:

| Spelling | Emitted instead | Why it matters |
|---|---|---|
| `MGMT.RESYNC_REQUIRED` | `MGMT.STREAM_COMPACTED` | MI-9a exists **specifically** to keep these apart: compaction is mid-stream and the client's prior state is a valid base; `RESYNC_REQUIRED` is attach-time and it is not. This substitution makes them indistinguishable, which is the failure MI-9a spends a paragraph forbidding |
| `MGMT.PRECONDITION_FAILED` | `POLICY.POLICY_DENIED` | An `if_version` mismatch is the caller's to retry after re-reading; a policy denial is not retryable at all. The substitution tells a correct client to give up |

Two of the sixteen name **successes** — `MGMT.DIAG.BUNDLE_CREATED` and
`MGMT.UNBLOCK_INVOKED`. Every registered `MGMT` code is a failure, so this build
emits **no reason code** for those two and carries them as typed events;
reporting a success as a failure would be worse than losing the namespace.

---

## 6. Known gaps

- **The catalogue carries no parameter or result schemas.** `Entry` names the
  operation, its scope, its mutation posture, its ADR-0008 idempotency
  requirement and whether §11.14's ADMINISTER ceremony gates it. Parameters cross
  as encoded blobs (ADR-0018 F-8) and their shapes come from `contracts/`; adding
  a schema here would be the second contract OQ-2 excluded.
- **`catalogue_digest` is FNV-1a, not a cryptographic digest**, and does not
  pretend to be one. Nothing trusts it; it only has to change when the table
  does. Using SHA-256 would put a cryptographic dependency in a crate CD-I2 does
  not permit one in.
- **Scope enforcement is not here.** This crate declares which scope each
  operation requires; checking a principal's granted set against it is the
  agent's, and the principal itself comes from ADR-0016's per-platform
  authentication table.
