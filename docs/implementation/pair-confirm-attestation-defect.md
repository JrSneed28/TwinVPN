# `pair.confirm` — `PairingAttestation.transcript_hash` has no defined preimage

**A defect raised under [`ownership.md`](ownership.md) §3, step 1.**

**Status: ASK. Nothing under `contracts/` has been touched, and nothing under
`docs/adr/` has been touched.** §3 steps 1, 2, 4 and 5 are answered below. Steps
3, 6, 7 and 8 — the integration lead's review, the explicit approval, the
contract-test update and the `contracts/FROZEN` re-declaration — are not this
document's to perform, and in this case step 6's approval is owed by **ADR-0007's
owner** before `contracts/` is reached at all. `make gate` fails on an unapproved
`contracts/` change, and that is the point: this stops at the ask.

**Raised by:** the `pair.confirm` blocker pass, 2026-08-29.
**Register rows:** [`ownership.md`](ownership.md) §11.2, **G-25** and **G-26**.
**Precedent for the form:**
[`w21-pairing-offer-amendment.md`](w21-pairing-offer-amendment.md), and
Amendments 1–6 in [`contracts/FROZEN`](../../contracts/FROZEN).

---

## 0. What is being asked for, in one page

| | |
|---|---|
| **The defect** | `transcript_hash` — the value both devices must agree on for a ceremony to confirm — has **no defined preimage**. Its construction appears exactly once in the corpus, as one sentence of §7.4 *rationale*, and is never restated as a normative rule |
| **Who must decide** | **ADR-0007's owner.** The fix is a normative rule in §11.1, in the form ADR-0001 §7.3.1 **P-1** already uses for the Noise prologue |
| **Second gap** | `peer_key_id` / `own_key_id` have a **type** (`tstr .size (1..64)`) and **no format**. Nothing in the corpus says what string goes in them |
| **What is NOT defective** | `signed_statements.cddl`'s `pairing-attestation` (line 140). The statement's six-key map, its labels, its types and its `crit` set are **frozen, complete, and correct**. The previous report that "the structure is not unambiguously specified" is **wrong about the statement** and right about the hash |
| **NOT changed by this document** | no `.cddl`, no `.proto`, no registry, no ADR, no generated binding. `contracts/gen/**` byte-identical; `SchemaDescriptor.schema_digest` does not move |
| **What was implemented** | **No emitter.** §8 states why, including why the half that *is* determined was deliberately left unwritten |
| **Independent blocker** | Even with the preimage fixed, `pair.confirm` stays refused: N-18 needs **both** attestations and the peer's crosses the rendezvous, which has no transport (**W-12**). Closing this defect is **necessary and not sufficient** |

---

## 1. §3 step 1 — the defect, and why it is not an implementation inconvenience

### 1.1 First, what is *not* defective — the statement itself is frozen and complete

The blocker was handed over with the report that `PairingAttestation`'s
"structure is not unambiguously specified … no CDDL". That is **incorrect**, and
correcting it matters, because it changes what is being asked for.

`contracts/cddl/twinvpn/v1/signed_statements.cddl` line 134:

```cddl
; --- 4. PairingAttestation ----------------------------------------------------
; One device's half of a completed ceremony. DeviceKey-signed.
;
; Rule B: the coordination service TRANSPORTS attestations it CANNOT FORGE, so
; it cannot inject a TrustedPeer.

pairing-attestation = {
  1: pairing-id,
  2: key-id,          ; peer_key_id
  3: key-id,          ; own_key_id
  4: digest256,       ; transcript_hash of the ceremony
  5: epoch-ms,        ; not_after_ms. Ceremony expiry is 120 s (N-17).
  6: crit-set,
}
```

That is a complete, frozen, normative wire definition. It is reachable from the
file's top-level statement choice (line 510), it is governed by the file's
non-negotiable encoding rules 1–6, and `decode_pairing_attestation` is its exact
reader. **An emitter for the statement invents nothing.** Six labels, five typed
fields, one `crit` set, deterministic CBOR, COSE_Sign1. Every decision an emitter
would face at *that* level is already made.

So the ask below is **not** "define `PairingAttestation`". It is narrower and
harder to notice, which is why it was mis-stated on handover.

### 1.2 The actual defect — the hash is opaque on both sides of the boundary

`transcript_hash` is `digest256` — thirty-two bytes. The CDDL says what it *is*
and never what it is *over*. Neither does the decoder:

`core/crates/twinvpn-crypto/src/statements/identity.rs:235`

```rust
pub fn decode_pairing_attestation(s: &VerifiedStatement) -> Result<PairingAttestation> {
    ATTESTATION_SCHEMA.check(s)?;
    Ok(PairingAttestation {
        pairing_id: fixed::<16>(s, 1, "pairing_id")?,
        peer_key_id: text(s, 2, "peer_key_id")?,
        own_key_id: text(s, 3, "own_key_id")?,
        transcript_hash: fixed::<32>(s, 4, "transcript_hash")?,
        not_after_ms: uint(s, 5, "not_after_ms")?,
    })
}
```

`fixed::<32>` copies thirty-two bytes out. The decoder **never constructs a
transcript and never checks one**, so it is not a de facto specification of the
preimage — it is a de facto specification of everything *except* the preimage.

`check_attestation_pair` (`identity.rs:261`) is the same story, and this is the
part with a security consequence:

```rust
if a.transcript_hash != b.transcript_hash {
    return Err(bad("attestations disagree on the ceremony transcript"));
}
```

It checks the two halves **agree**. It cannot check that either is *correct*,
because correctness is undefined. Two devices running the same wrong construction
agree perfectly; two devices running two *different* reasonable readings of §7.4
disagree, and the ceremony fails with `attestations disagree on the ceremony
transcript` — a message that points at the peer rather than at the specification.

### 1.3 The whole of what ADR-0007 says, quoted

`docs/adr/ADR-0007-device-identity-and-pairing.md:556`, §7.4, "Ceremony
completion":

> **Ceremony completion.** `transcript_hash = SHA-256` over the ordered
> concatenation of `pairing_id`, both `ik_pub`, both `tk_pub`, both
> `TunnelKeyBinding`s, the ceremony method, `anchor_version`, and both offered
> `ProtocolVersion` ranges and `Capability` hashes. Each side emits a
> `PairingAttestation` (the structure named in [docs/protocol.md](../protocol.md)
> §8.2) signed by its IK over `transcript_hash`.

That sentence is the **only** occurrence in the entire corpus. Verified:

| Search | Result |
|---|---|
| `transcript_hash` in ADR-0007 | lines 556, 560, 564 — one definition, two back-references |
| `transcript` in ADR-0007 **§11.1 (normative rules)** | **one hit, N-15**, and it is about offline-testability, not construction |
| `transcript` in `pairing.proto` | lines 31–33, the same N-15 point. The `PairingAttestation` comment (line 102) restates the field list and no construction |
| `transcript` in `signed_statements.cddl` | one comment: `; transcript_hash of the ceremony` |
| golden or conformance vectors for `pairing.attestation` | **none** |
| any code in `core/` or `shells/` that builds a pairing transcript | **none.** The two `transcript_hash` symbols outside the statement module are `twinvpn-trust`'s `Spake2Exchange::transcript_hash` — the **SPAKE2 exchange's own** transcript, C-A only, implementor-supplied — and a `[0x7c; 32]` test fixture |

**The construction has no normative rule.** §7.4 is inside §7, *Security
Implications* — analysis and rationale. §11.1 is where ADR-0007 states rules, and
it contains N-15 through N-19 on the ceremony without ever fixing the transcript.
The contrast is visible three rules later, in **N-20**:

> **N-20** This ADR contributes `identity_binding_hash` **exactly as defined in
> §7.6** to the Noise `prologue` owned by ADR-0001 §7.3.1 (rule P-1).

There is no N-rule that says "contributes `transcript_hash` exactly as defined in
§7.4". The corpus knows how to make a §7 construction normative. It did not do it
here.

**This is a defect and not an inconvenience**, by §3's own test. The
implementation cannot be adapted to the contract, because on this point the
contract is silent; and it is not silent in a way an implementer may resolve,
because the value's entire purpose is that **two independent implementations
compute it identically**. A choice made in `twinvpn-crypto` binds `shells/ios`,
`shells/macos`, `shells/android` and every future peer, and it binds them
invisibly — the failure is a ceremony that never completes across platforms,
surfacing as a peer-blaming error.

---

## 2. §3 step 2 — the incompatibility, precisely: nine decisions an implementer must invent

Each row is a decision §7.4 does not make. Each has at least two defensible
readings, and **every one produces a different 32-byte digest** — so any two
implementations differing on any single row never pair.

| # | Decision | Readings available | Divergence it causes |
|---|---|---|---|
| **E-1** | **Domain separator** | none stated. ADR-0001 §7.3.1 prefixes every hash (`"TWINVPN-IDBIND-v1"`, `"TWINVPN-NEG-v1"`); §7.4 prefixes nothing | A digest with no domain tag is reusable in any other SHA-256 context in the protocol. Cross-protocol collision surface, and no version handle for a future v2 transcript |
| **E-2** | **Length framing** | none stated. "concatenation" taken literally is unframed | **The one with a real collision.** `TunnelKeyBinding` is a variable-length COSE_Sign1 `bstr`; capability token lists are variable. Unframed concatenation of variable-length members is not injective — two distinct ceremonies can produce one preimage. Framed (length-prefixed, or dCBOR-array) is injective. Both are "the ordered concatenation" |
| **E-3** | **Ordering of the paired members** | "both `ik_pub`", "both `tk_pub`", "both `TunnelKeyBinding`s". Candidates: joiner-then-approver; initiator-then-responder; lexicographic by `device_id`; lexicographic by key octets | The two devices occupy **different** roles and must still agree. ADR-0001 §7.3.1 solved the same problem by naming the roles in the field: `device_id_init(32) || device_id_resp(32)`. §7.4 names no roles |
| **E-4** | **Grouping of the paired members** | `ik_A ‖ ik_B ‖ tk_A ‖ tk_B` (field-major, the sentence's own order) vs `ik_A ‖ tk_A ‖ ik_B ‖ tk_B` (device-major) | Different digest. Both are "the ordered concatenation of … both `ik_pub`, both `tk_pub`" |
| **E-5** | **`ik_pub` octets** | the dCBOR `COSE_Key` (Amendment 6 / **G-20** fixed the *point form* as uncompressed `{1:2, -1:1, -2:x, -3:y}`, so this is narrower than it was) vs the raw point | G-20 settled the point form for `identity_id`; it did **not** state that the transcript mixes the CBOR-wrapped key rather than the bare coordinates. One reading is 8-ish bytes longer than the other |
| **E-6** | **`TunnelKeyBinding` octets** | the COSE_Sign1 octets as received, or the decoded fields re-encoded | **Only the first is admissible**, by ADR-0003 §11 rule 1 — "a signed statement MUST NOT be represented in more than one encoding anywhere in the system" — but §7.4 does not say so, and re-encoding is the reading an implementer reaches for when the binding arrives already parsed. An implementation that re-encodes is *both* non-interoperable *and* in breach of rule 1, and nothing today would tell it |
| **E-7** | **"the ceremony method"** | `PairingCeremonyType` enum number (`1` for SPAKE2_CODE) — and as what width? — vs the proto enum **name** (`"PAIRING_CEREMONY_TYPE_SPAKE2_CODE"`) vs the Rust discriminant of `twinvpn_trust::CeremonyType` (`Spake2Code`/`Qr`, declared in the opposite order to the proto) vs a short tstr (`"C-A"`/`"C-B"`) | Four candidate byte spellings of a two-valued field, one of which (the Rust discriminant) numbers the two ceremonies **the other way round** from the proto. The failure mode is that C-A and C-B silently swap |
| **E-8** | **`anchor_version`** | `u32` BE (the width `prologue.rs` and `session_table/keying.rs` both use), `u32` LE, `u64` BE, or dCBOR `uint` | Four spellings, four digests. §7.4 states no width and no endianness for any integer it names |
| **E-9** | **"both offered `ProtocolVersion` ranges and `Capability` hashes"** | *Ranges*: `common.proto` declares `ProtocolVersion{ v_max = 1; v_min = 2 }` — **field order is `v_max` first, range order is `[v_min, v_max]`**, so even "encode the message's fields in order" is ambiguous against the prose word "ranges". *Capability hashes*: hash of **what**? Each `path_migration/1` token individually; the sorted token list; a dCBOR array of them; with which hash; sorted by what collation; and is it the **offered** set or the intersection? | The largest single gap. "`Capability` hashes" is a plural noun with no referent in the corpus — the only adjacent term, `floor_capability_hash` (ADR-0007:638, 936), is a *negotiation-floor* input from a different mechanism and is itself never constructed anywhere |

Nine binary-or-worse decisions is, conservatively, several hundred distinct
`transcript_hash` functions consistent with the sentence as written. That is the
incompatibility §3 step 2 asks to be documented precisely.

---

## 3. The corpus already knows what an adequate specification looks like

This is the strongest argument that §7.4 is under-specified rather than merely
terse: **the same repository specifies the same kind of object properly, one ADR
away**, and the implementation of that one exists and is correct.

ADR-0001 §7.3.1, quoted by `core/crates/twinvpn-crypto/src/prologue.rs`:

```text
identity_binding_hash = SHA-256( "TWINVPN-IDBIND-v1"
                               || twinnet_id(16)
                               || device_id_init(32) || device_id_resp(32)
                               || trust_epoch(u64 BE) || psk_epoch(u64 BE)
                               || anchor_version(u32 BE)
                               || delegation_set_digest(32) )
```

with **P-1**: *"The `prologue` MUST be exactly the 83-byte concatenation above. No
other document may define, extend, or reorder it."*

Against the nine rows of §2, that single block answers **E-1** (a labelled domain
separator), **E-2** (every member fixed-width, so framing is free and the total
length is stated), **E-3** (`_init`/`_resp` name the roles), **E-4** (the order is
literal), **E-8** (`u32 BE`, written out), and it answers **E-6**'s hazard
structurally by mixing only fixed-width digests and one explicitly
`det_CBOR(Selection)` blob.

`prologue.rs` implements it in twenty lines and could, because there was nothing
left to decide:

```rust
sha256_parts(&[
    IDBIND_LABEL,
    self.twinnet.as_bytes(),
    &self.device_id_init,
    &self.device_id_resp,
    &self.trust_epoch.to_be_bytes(),
    &self.psk_epoch.to_be_bytes(),
    &self.anchor_version.to_be_bytes(),
    &self.delegation_set_digest,
])
```

**The ask of §7.4 is exactly this, and nothing more than this.** Not a redesign —
a block of the form above, plus one N-rule in §11.1 binding it, in the wording
N-20 already uses for §7.6.

`prologue.rs` also demonstrates the *house discipline for the case where an ADR is
nearly-but-not-quite sufficient*, and it is worth quoting because it marks the
line this document is declining to cross. Facing `twinnet_id(16)` against a
frozen `tstr .size (1..64)`, that module chose a contraction — and recorded it as

> "a decision taken here and reported to the integration lead as an ADR-0001
> §7.3.1 / contract-set inconsistency, **not presented as a reading of the ADR**."

That was legitimate because §7.3.1 had fixed the *layout* and left exactly **one**
field in tension, with exactly one length-safe resolution. §7.4 leaves the entire
layout open and has no forced answer on any of the nine rows. The same discipline
applied to §7.4 does not produce a decision; it produces this document.

---

## 4. The second gap — `peer_key_id` and `own_key_id` have a type and no format

Independent of the transcript, and confirmed:

- `signed_statements.cddl:62` — `key-id = tstr .size (1..64)`. A **type** and a
  length bound.
- `contracts/docs/identifiers.md` — the corpus's identifier authority, with a
  table of exact sizes and a §5 that makes every size "exact and enforced on
  receipt". **`key_id` is not in it.** The file's only occurrence of the string is
  at line 205, recording that a *different* `peer_key_id` — protocol.md §16 row
  21, on the relay path — was **withdrawn** and replaced by `pair_tag`, because it
  "would have told the relay which two devices are talking".
- `decode_pairing_attestation` reads both through `text()`, which enforces
  non-empty and ≤ 64 bytes and nothing else.

So an emitter must decide what a key id *is* — the `device_id` hex? the
`identity_id` hex? a COSE `kid`? a base64url thumbprint? with which case? — and
that decision is load-bearing, because `check_attestation_pair` compares these
strings **byte-for-byte** in the check that stops a coordination service pairing
two unrelated attestations:

```rust
if a.peer_key_id != b.own_key_id || b.peer_key_id != a.own_key_id {
    return Err(bad("attestations do not name each other"));
}
```

Two implementations that agree on every one of §2's nine rows still fail here if
one lowercases its hex. Note also the direction of the identifiers.md precedent:
the corpus's most recent recorded thought about a field named `peer_key_id` was to
**remove** one for a privacy reason. Whether that reasoning reaches this field —
the coordination service sees both halves — is a question for the same owner, and
this document raises it rather than answering it.

---

## 5. §3 step 4 — Phase 1 architectural implications, and the independent blocker

**Closing this defect is necessary and not sufficient.** `pair.confirm` has two
blockers and this document addresses one.

`core/crates/twinvpn-core/src/dispatch.rs:184`, the current refusal, which is
accurate:

```rust
C::PairConfirm => Disposition::NotWired {
    code: codes::CONTROL_UNREACHABLE,
    why: "N-18 confirms a ceremony on both devices or on neither, so it needs BOTH \
          PairingAttestations, and this build can produce neither half. The peer's \
          crosses the rendezvous, which has no transport (W-12). ...",
},
```

N-18 is categorical — *"A `Pairing` MUST complete on both devices or on neither"* —
and `check_attestation_pair` takes two arguments because of it. The peer's half
arrives over the rendezvous; **W-12** (§8) recorded that `core-controlplane`
"shipped the ladder policy without a production binding", and no C1 transport has
landed since. So even a fully specified, fully implemented, fully tested
`emit_pairing_attestation` leaves `pair.confirm` refused — with a *different*
reason, one that names only W-12.

That is the correct sequencing and it is worth stating plainly: **this defect is
not on W-12's critical path, and W-12 is not on this defect's.** They are
independent, both are required, and neither is fixable by the other's owner.

---

## 6. §3 step 5 — compatibility analysis

| Question | Answer |
|---|---|
| Does the fix move `SchemaDescriptor.schema_digest`? | **Only if it lands in `contracts/`.** An ADR-0007 §11.1 rule alone does not. A `.cddl` comment block or a `registry/` entry making the preimage machine-checkable would, exactly as Amendments 1–6 did |
| Does it change the wire? | **No.** `pairing-attestation`'s six labels and types are untouched. `transcript_hash` stays `digest256`. What changes is which 32 bytes a conforming implementation puts there |
| Is anything deployed affected? | **No.** Nothing in the tree emits a `PairingAttestation`; no golden vector pins one; `pair.confirm` is refused on every shipped composition. The set of implementations that could disagree is currently empty. **This is the cheapest possible moment to fix it, and that will not stay true** |
| Backward compatibility of a later fix? | **There is none available.** `transcript_hash` has no version field, no algorithm agility, and the statement's `crit` set has no required member (`required_crit: &[]`). Two devices on two transcript versions produce `attestations disagree on the ceremony transcript` with no way to detect *why*. If a v2 is ever needed, the handle must be designed in now — which is E-1's domain separator earning its place |
| Does the fix conflict with any frozen artifact? | **No.** The CDDL constrains the field's type only, and every candidate construction yields 32 bytes |

---

## 7. What must be decided, and by whom

**Owner: ADR-0007's owner.** Not `core-crypto`, not `core-composition`, and not
this pass — §3's own words: *"If the contract genuinely cannot express what Phase 1
requires, that is a finding to report, not a patch to land."*

Required, in order:

1. **ADR-0007 §7.4 gains an exact preimage block**, in ADR-0001 §7.3.1 P-1's
   form: a domain-separation label, every member with an explicit width or an
   explicit framing, roles named where a member is paired, and a statement of
   what the variable-length members contribute. All nine rows of §2 answered.
2. **ADR-0007 §11.1 gains a normative rule** binding it — the wording N-20
   already uses: *"contributes `transcript_hash` exactly as defined in §7.4"*,
   plus P-1's closing clause, *"No other document may define, extend, or reorder
   it."* Without step 2, step 1 is still rationale.
3. **`key_id`'s format is fixed**, in `contracts/docs/identifiers.md` §4 beside
   the other identifiers, with the §5 exact-size discipline — and with §4's
   privacy question above answered.
4. **Then, and only then**, the implementation follows: `emit_pairing_attestation`
   plus a transcript builder in `twinvpn-crypto`, round-trip and single-bit
   sensitivity tests, and at least one golden vector under `contracts/` so the
   Swift and Kotlin shells are checked against the same bytes rather than against
   the Rust implementation's behaviour. Steps 3 and 4 of that list are where a
   `contracts/` amendment enters and where §3 steps 3, 6, 7 and 8 apply.

**A decision is required even to decide that the current sentence is enough.** If
ADR-0007's owner reads §7.4 as already determinate, that reading is itself the
missing artifact and should be recorded as the N-rule — at which point §2's nine
rows are the checklist it must survive.

---

## 8. Why no emitter was written — including the half that *is* determined

§1.1 establishes that the **statement** is fully specified, so an
`emit_pairing_attestation` that is the literal inverse of
`decode_pairing_attestation` — taking `transcript_hash: [u8; 32]` as an opaque
input, exactly as the decoder yields it opaquely — would invent nothing. It was
still not written, deliberately, and the reasoning is recorded here rather than
left as an absence:

1. **It does not unblock `pair.confirm`.** The blocker is the hash, and §5's W-12
   is a second blocker behind it. The emitter would move nothing.
2. **It has no caller.** `install_pairing_enrolment`'s F-2A history is the
   cautionary precedent in this very module: a correct, tested producer with no
   production caller was indistinguishable from a working feature for as long as
   nobody looked.
3. **It converts a hard stop into a soft one, in the wrong direction.** Today the
   refusal reads *"there is no emitter, so there is nothing to sign"* — a fact a
   reader cannot route around. An emitter taking an opaque 32-byte parameter reads
   as *"the blocker is solved; supply the hash"*, and the cheapest way to supply
   it is to pick one of §2's readings. The next implementer would then have
   invented the transcript format **downstream of the crate that owns encodings**,
   with no review and no vector, which is the precise outcome this pass was told
   to avoid.
4. **`contracts/` and `docs/adr/` are both out of this pass's ownership**, so the
   specification cannot be landed in the same change that would consume it.

The determined half is small and will stay easy: when §7 step 1 lands, the emitter
is the inverse of a decoder that already exists, in a crate whose
`emit_tunnel_key_binding` (`binding.rs:302`) and `emit.rs`
(`StatementToSign::to_be_signed` / `assemble_cose_sign1`) already supply the house
pattern for signing a statement. Nothing is being deferred that will be harder
later. What is being refused is the guess.

---

## 9. Findings raised while writing this, recorded under `ownership.md` §11.2

Two rows, **G-25** and **G-26**. G-26 is this defect. **G-25 is unrelated to it**
and was surfaced by reading `pairing/enrol.rs` in full: the C-D authorization
residual that F-2 shipped is stated in that module's doc and reported by the shell
at every daemon start, but had never reached the register — so the one place a
reviewer looks for open residuals did not list it. It is recorded now.
