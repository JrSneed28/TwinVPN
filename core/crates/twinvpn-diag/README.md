# `twinvpn-diag` — the Tier-0 ring, redaction, bundles, and the resolver

**Authority:** [ADR-0015](../../../docs/adr/ADR-0015-observability-and-diagnostics.md)
in whole; ADR-0018 CB-4 and §11.4 F-4/F-10; ADR-0019 §11.5 (LT-3, LT-4, LT-5).
**Owner:** `core-composition`.

---

## 1. Building and testing

```bash
source build/toolchain/env.sh
cd core && cargo test -p twinvpn-diag
```

The build script compiles the presentation catalogue; a change to
`contracts/registry/reason_codes.json` or to `catalogue/en.json` re-runs it.

---

## 2. Environment configuration

**None.** This crate reads no environment variable, no configuration file, and —
crucially — **no ambient locale and no ambient platform**. `resolve::render` is a
pure function of its four parameters (ADR-0018 F-10), which is what lets
ADR-0019's P18 drive every platform's next-action variants exhaustively from one
Linux CI runner, and what lets a **poisoned** core still render the diagnostic
describing the fault that poisoned it.

`ledger::Ledger`'s capacity is a constructor argument, not a constant: the same
source builds a desktop daemon and a 128 MB router.

---

## 3. Debugging

```bash
# What does a code actually render as?
cargo test -p twinvpn-diag resolve:: -- --nocapture
```

`resolve::render` never fails and never returns an empty string. A code the
registry does not carry degrades on its `DOMAIN` prefix **with the attributes**
(ADR-0015 §11.2 rule 5), and a code that does not even parse degrades to
`INTERNAL`.

`resolve::authored_entries()` and `resolve::total_entries()` report how much of
the catalogue is hand-authored — see §5.

---

## 4. What this crate will never do

- **Capture a secret.** `twinvpn_types::FieldClassification` has three variants
  and none is `SECRET`, because "never stored, never rendered, **no code path
  exists**" and giving it an enum value creates the code path. There is no type
  here that can hold a key, a session key, a pairing secret or a tunnel payload.
- **Reach the control plane.** The fourteen `SessionEvent` bodies are local and
  device-authoritative (`contract-matrix.md` §4.4). This crate has no dependency
  on `twinvpn-cp-client` and, sitting above the composition root in ADR-0018
  §11.7's arrows, cannot acquire one without failing `cargo xtask lint`.
- **Install a `tracing` subscriber.** The shell's job.
- **Fail open.** ADR-0015 §11.4: redaction is applied **by the emitter from the
  schema classification**, so `redact` is a total function over an
  already-classified value. A `SENSITIVE` value with no pseudonym mapping is
  **dropped**, never carried.

---

## 5. The catalogue: what is real and what is not

ADR-0018 CB-4 requires the catalogue to ship **embedded in the artifact**. It is,
and it is complete: every one of the 201 registered codes has a summary entry and
every one of the 107 `user_actionable` codes has a **neutral** next-action entry,
so ADR-0019 LT-3c holds by construction rather than by review.

**How that completeness is achieved is worth stating plainly.** The table has two
sources:

| Source | Covers | Quality |
|---|---|---|
| the **seed**, derived by `build.rs` from the frozen registry's `condition` field | all 201 codes | technical prose written for a reviewer, not for a user |
| the **overlay**, `catalogue/en.json` | a small hand-authored set | real user-facing copy, and the only source of LT-3 platform variants |

So the *mechanism* — completeness, purity, LT-3a/b/c variant selection, LT-4's
named placeholders bound to registry-declared evidence — is finished and tested.
The *copy* is not: most entries currently render the registry's condition
sentence rather than the "one line, human, no jargon" ADR-0015 §11.3 asks for.
Authoring ~300 sentences is a content deliverable, and pretending otherwise by
shipping empty strings would have violated R-33 instead.

`AUTHORED_ENTRIES` / `TOTAL_ENTRIES` make the gap measurable, which is what
ADR-0019 §11.5 asks of a fallback in the first place.

### Adding copy

Edit `catalogue/en.json`. The build script enforces three rules:

1. A key that names no registered code's `summary_key` or `next_action_key`
   **fails the build** — that is how a typo silently disables copy someone wrote.
2. A `next_action` with variants and no `neutral` **fails the build** (LT-3c).
3. A `{placeholder}` naming an evidence key the registry does not declare for
   that code **fails the build** (LT-4) — at render time it could only be a hole.

---

## 6. Known gaps

- **Only the source locale (`en`) ships.** `FallbackRung` distinguishes a
  requested-locale hit from a source-locale fallback and counts them, so the gap
  is measurable; the other rungs of ADR-0019 §11.5's chain have nothing to fall
  back *to* yet.
- **`ConnectivityReport` is a shape, not a collector.** All eight of ADR-0015
  §11.8's parts are modelled and `resolve_verdict` runs the real renderer, but
  nothing populates the candidate ledger, the transport ladder or the relay rows
  — those come from `twinvpn-path`, `twinvpn-relay-client` and the composition
  root's loops.
- **A bundle is not signed here.** `Bundle::signing_payload` produces the bytes
  and `attach_signature` takes the result; the `DeviceKey` is on the far side of
  the CB-5 vtable and the core never holds it.
- **`Tier::Bundle` re-encoding of a `SessionEvent` re-maps identifiers but does
  not re-run evidence classification**, because the ledger keeps the frozen form
  rather than the typed original. A `Diagnostic` recorded in the ledger *is*
  re-encoded from its typed form and is fully re-redacted.
