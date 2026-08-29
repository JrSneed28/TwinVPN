# W-21 — `PairingOffer` has no contract message

**A proposed Amendment 4 to the Phase 2 contract freeze, under
[`ownership.md`](ownership.md) §3.**

**Status: PROPOSAL. Nothing under `contracts/` has been touched.** §3 steps 1, 2,
4 and 5 are answered below and the exact diff is printed in §6. Steps 3, 6, 7 and
8 — the integration lead's review, the explicit approval, the contract-test
update and the `contracts/FROZEN` re-declaration — are not this document's to
perform. `make gate` fails on an unapproved `contracts/` change, and that is the
point: this stops at the ask.

**Raised by:** the W-21/W-24 pass, 2026-08-29.
**Register row:** [`ownership.md`](ownership.md) §8, **W-21**.
**Precedent for the form:** Amendments 1, 2 and 3 in
[`contracts/FROZEN`](../../contracts/FROZEN).

---

## 0. What is being asked for, in one page

| | |
|---|---|
| **One new file** | `contracts/cddl/twinvpn/v1/pairing_offer.cddl` |
| **Six new keys** | under the existing `pairing` object in `contracts/registry/limits.json`, `registry_version` 2 → 3 |
| **One test change** | `contracts/tests/test_registries.py` asserts the six bounds and the limits `registry_version` |
| **NOT changed** | no `.proto`; no reason code added, renamed or reclassified; the other three registries untouched; `contracts/gen/**` **byte-identical** |
| **Wire-visible consequence** | `SchemaDescriptor.schema_digest` moves, exactly as it did for Amendments 1, 2 and 3. That is what the field is for |

**Why a `.cddl` and not a `.proto`** is §3 below, and it is the part of this
proposal most worth arguing with, because `contracts/proto/twinvpn/v1/pairing.proto`
already exists and looks like the obvious home. It is not, and its own header
says so.

---

## 1. §3 step 1 — the defect, and why it is not an implementation inconvenience

**The finding as the register states it.** `PairingOffer` — the deterministic-CBOR
payload the C-B ceremony actually carries — is specified normatively in
[ADR-0007](../adr/ADR-0007-device-identity-and-pairing.md) §7.4, printed there as
a seven-field structure, and **appears nowhere in `contracts/`**. It is named
again in [`architecture.md`](../architecture.md) S-67, in
[ADR-0017](../adr/ADR-0017-local-management-interface.md) §11.3 and §11.9's
`pair.begin` row, and in
[ADR-0023](../adr/ADR-0023-headless-cli-and-embedded-profile.md) EM-22 (four
enrolment channels, all C-B), EM-24 (offer handling) and S-67.

**Why it is a defect and not an inconvenience.** §3's own test is whether the
contract can express what Phase 1 requires. It cannot, and the gap is not
cosmetic in three separate ways:

1. **Four of the five enrolment channels in the product are C-B, and C-B *is*
   this payload.** ADR-0023 EM-22 gives E1 (terminal QR), E2 (text offer), E3
   (reverse ceremony) and E4 (first-boot provisioning) — all four "C-B, 256-bit"
   — and the SPAKE2 9-digit code is "retained as the last resort only". W-22
   already established that C-A is unimplementable (no audited RFC 9382 P-256
   Rust implementation exists). So **every enrolment path this product can
   actually ship carries a payload the contract does not define.** That is not
   one message missing; it is the whole of enrolment.

2. **It is an untrusted input with no registered bounds, and it is the *most*
   untrusted input in the system.** `ownership.md` §6 rule 9 requires every
   untrusted input to be validated "against `contracts/registry/limits.json`
   *before* any allocation proportional to a declared length". The offer arrives
   from a camera, a paste buffer, a serial console or a file written by a
   provisioning system, is parsed by a device that holds **no trust anchor yet**,
   and there is nothing to verify it against — the optical channel *is* the
   authentication. `limits.json` has a `pairing` object; it bounds
   `ceremony_expiry_ms`, `max_failed_runs`, `max_peer_hint_bytes` and
   `max_ceremony_payload_bytes`, and **nothing about the offer**. Two independent
   implementations of the joiner and the approver would therefore each pick their
   own caps, which is exactly the divergence a frozen registry exists to prevent.

3. **Two independently-written implementations would not interoperate, and would
   not find out until a real ceremony.** ADR-0007 §7.4 prints field names and
   CBOR-ish types; it does not say whether `ik_pub` is an embedded COSE_Key or a
   `bstr`-wrapped one, whether unknown keys are rejected or preserved, what the
   canonicalisation obligation is, or what any field's maximum length is. Every
   one of those decisions changes the bytes. A QR that one implementation
   produces and another refuses is a failed enrolment with no diagnosis, and it
   is the class of bug ADR-0003 §11 rule 1 ("a signed statement MUST NOT be
   represented in more than one encoding anywhere in the system") exists to
   eliminate — applied here to a payload that is not a signed statement and
   therefore fell outside the rule's reach.

**What the implementation did instead, and why it is correct as far as it goes.**
`twinvpn-core`'s dispatch refuses `pair.begin`, `pair.confirm`, `pair.cancel` and
`pair.status` with `AUTH.PAIRING_NOT_AUTHORIZED` and the stated reason "the C-B
ceremony carries a `PairingOffer`, which appears NOWHERE in `contracts/` (W-21)".
Refusing by name is the right behaviour under the freeze — §3's "adapt the
implementation to the contract" has no adaptation available when the contract is
silent — but it means **enrolment is not implemented at all**, and the register
records that plainly.

---

## 2. §3 step 2 — the incompatibility, precisely

### 2.1 The seven fields, each with its authority and its bound

ADR-0007 §7.4 prints:

```
PairingOffer {
  1 pairing_secret : bstr(32)      # optical-confidential; never transits the network
  2 ik_pub         : COSE_Key      # P-256, compressed point
  3 tk_pub         : bstr(32)      # X25519
  4 binding        : bstr          # COSE_Sign1(IK) over TunnelKeyBinding
  5 attestation    : bstr / null   # platform attestation blob, if any
  6 rendezvous_hint: tstr
  7 not_after_ms   : uint          # issued + 120 000
}
```

Field by field, with the bound each needs and where that bound comes from:

| # | Field | Authority | Proposed CDDL | Bound, and its source | Measured bytes |
|---|---|---|---|---|---|
| 1 | `pairing_secret` | ADR-0007 §7.4: "generates `pairing_secret` (**32 random bytes**)"; `pairing_id = SHA-256(pairing_secret)[0..15]` | `bstr .size 32` | **NEW** `pairing.secret_bytes = 32`. Nothing in `limits.json` bounds it today, and it is the one field whose length is fixed by a derivation the whole ceremony rests on | 35 |
| 2 | `ik_pub` | ADR-0007 §7.4 "COSE_Key, P-256, compressed point"; §7.3 IK is ES256/P-256 | `cose-key` (= `bstr .size (1..pairing.max_offer_cose_key_bytes)`) | **NEW** `pairing.max_offer_cose_key_bytes = 80`. A deterministic COSE_Key EC2 P-256 compressed measures **43** bytes; 80 also admits the uncompressed form (~75) so a conforming-but-uncompressed producer is refused by the CDDL's own words rather than by a length accident | 45 |
| 3 | `tk_pub` | ADR-0007 §7.4 "bstr(32) X25519" | `bstr .size 32` | Fixed by the primitive. **See finding F-2 below**: `signed_statements.cddl`'s `tunnel-key-binding` carries `tk_pub` as `cose-key`, not as a bare `bstr .size 32`, so the corpus spells the same key two ways | 35 |
| 4 | `binding` | ADR-0007 §7.4 "COSE_Sign1(IK) over TunnelKeyBinding"; the payload's schema is `signed_statements.cddl` §2 | `bstr .size (1..pairing.max_offer_binding_bytes)` | **NEW** `pairing.max_offer_binding_bytes = 256`. The measured COSE_Sign1 over a conforming `tunnel-key-binding` is **216** bytes; 256 leaves room for a longer `crit` set | 219 |
| 5 | `attestation` | ADR-0007 §7.4 "bstr / null — platform attestation blob, if any"; ADR-0018 §11.16 (l) requires `hardware_backed` reported truthfully | `null` | **NEW** `pairing.max_offer_attestation_bytes = 0`. **This is the proposal's one substantive narrowing of an ADR, and it is a finding rather than a preference — see F-1.** No real platform attestation blob fits in this payload's channel | 2 |
| 6 | `rendezvous_hint` | ADR-0007 §7.4 `tstr`; `pairing.proto`'s `PairingRequest.peer_hint` is the same concept, "opaque and size-capped at 256 bytes" | `tstr .size (0..pairing.max_offer_hint_bytes)` | **NEW** `pairing.max_offer_hint_bytes = 64`, deliberately **tighter** than `max_peer_hint_bytes = 256`. The wire hint travels a 64 KiB C1 envelope; this one has to survive a QR photographed off a terminal | 30 |
| 7 | `not_after_ms` | ADR-0007 §7.4 "issued + 120 000"; §7.4's table "Expiry 120 s"; ADR-0023 EM-24 "invalidated at the daemon on first use or at 120 s, whichever is first" | `epoch-ms` | Existing `pairing.ceremony_expiry_ms = 120000`. A receiver refuses an offer whose `not_after_ms` is more than that beyond its own clock — the bound is on the **window**, not on the field's encoding | 10 |
| — | map header | 7 entries | | | 1 |
| | | | | **TOTAL** | **377** |

Plus one whole-payload cap:

| Key | Value | Source |
|---|---|---|
| **NEW** `pairing.max_offer_bytes` | **512** | The sum of every per-field bound at its maximum, each with its own CBOR key and length header, is **493** (35 + 83 + 35 + 260 + 2 + 67 + 10 + 1). 512 is the smallest round value at or above it, and it matches the existing `pairing.max_ceremony_payload_bytes = 512`, which bounds the other payload on the same channel |

**The whole-payload cap is enforced first, before any field is parsed.** That
ordering is stated in the CDDL, and it is what stops the per-field caps and the
payload cap from disagreeing in the dangerous direction — the failure Amendment 1
recorded under "WHAT IT COST" when `max_name_bytes × 32` was found to exceed
`max_advertisement_bytes`. Here the relation is asserted rather than hoped for:
493 ≤ 512, and the contract test proposed in §6.3 checks the arithmetic so it
cannot silently stop holding.

### 2.2 How the numbers above were obtained

They are **measured, not estimated**. A minimal RFC 8949 §4.2.1 encoder — shortest-form
arguments, definite lengths, integer keys in sorted order — was used to encode a
representative offer: a real 8-byte-argument `epoch-ms`, a COSE_Key EC2 P-256
compressed `{1:2, -1:1, -2:bstr(32), -3:bool}`, a `tunnel-key-binding` built
exactly as `signed_statements.cddl` §2 declares it (142 bytes), wrapped in a
COSE_Sign1 `[protected{1:-7}, {}, payload, sig(64)]` (216 bytes), and a 27-character
rendezvous hint. The script is reproducible from the table above; it is a
measurement, not an artifact this proposal asks anyone to keep.

---

## 3. Where it belongs, and the two places it does not

### 3.1 Not in `pairing.proto` — that file forbids it, in terms

`contracts/proto/twinvpn/v1/pairing.proto` opens with:

> **SECRET-FIELD PROHIBITION:** `pairing_secret`, the SPAKE2 password, `K_pair`,
> and `PairSecret` NEVER appear in this schema and MUST NOT be added.
> `pairing_id = SHA-256(pairing_secret)[0..15]` is the PUBLIC rendezvous handle
> and doubles as the HKDF salt for the ceremony channel; the secret it is
> derived from is entered by a human out of band and never transits.

`PairingOffer` field 1 **is** `pairing_secret`. Adding the message to that file
would delete the prohibition its own header states, and the prohibition is right:
`pairing.proto`'s messages are C1/C2 wire messages, and the whole security
argument of C-B is that `pairing_secret` **never transits the network**. A
protobuf definition invites exactly one mistake — putting the offer in a
`PairingRequest` — and that mistake is unrecoverable, because it hands the
rendezvous the secret it must never see and collapses "MITM at the rendezvous is
defeated by construction" (ADR-0007 §7.4) into "MITM at the rendezvous is
trivial".

**So the absence of a `PairingOffer` message from `pairing.proto` is not the
defect. It is correct, and it should be made explicit rather than left to
inference.** The defect is that there is no definition *anywhere*.

### 3.2 Not in `signed_statements.cddl` — it is not a signed statement

`signed_statements.cddl` is the schema of COSE_Sign1-wrapped B2 statements. Its
six normative encoding rules require every member to be COSE_Sign1-wrapped
(rule 2), verified over the received octets (rule 3), carried as an opaque
protobuf `bytes` (rule 4), rejected on unknown non-`crit` fields (rule 5), and
carry a mandatory `not_after_ms` and a `crit-set` (rule 6).

`PairingOffer` satisfies exactly one of those — the lifetime bound — and fails
the rest for one reason: **there is no key the receiver could verify it against.**
The joining device is, by definition, not yet enrolled; it holds no
`OwnerTrustAnchor` and no `TrustedPeer`. C-B's authentication is the *channel*
(optical confidentiality, 256 bits), not a signature. Wrapping the offer in a
COSE_Sign1 nobody can check would be security theatre in the most literal sense:
bytes shaped like a proof, verified by no one.

There is a second reason, and it is structural rather than cryptographic.
`signed_statements.cddl` ends with a **closed inventory** of seventeen statement
types and records that ADR-0003 §14 revisit trigger 7 fires at about twenty.
Spending one of those three remaining slots on a payload that is not a signed
statement would move the trigger closer for no reason and would make
`signed-statement` a union whose members no longer share the property the union
is named for.

### 3.3 Therefore: a new file, `contracts/cddl/twinvpn/v1/pairing_offer.cddl`

It is CDDL because ADR-0007 §7.4 says "deterministic-CBOR payload" and
ADR-0023 E2 says the text channel renders "the same **dCBOR bytes** as Crockford
base32" — the encoding is named by Phase 1, not chosen here. It is a **separate
file** because it is the one dCBOR payload in the system that is *not* a signed
statement, and a reader who opens `signed_statements.cddl` must not find a
counter-example to its own rule 2 sitting inside it.

**Consuming crates, and what each would do with it:**

| Crate | Domain | What it does |
|---|---|---|
| `twinvpn-crypto` | `core-security` | Decode and validate, on `dcbor::parse_canonical` — which already implements RFC 8949 §4.2.1 strictly, allocates nothing before checking a declared length against the remaining input, and deliberately contains **no encoder** (its module header explains why). The offer's decoder is a straight application of it. **Encoding** the offer is the joiner's side and needs the one thing `dcbor.rs` does not have; where that encoder lives is a `core-security` decision, not this proposal's |
| `twinvpn-schema` | `core-foundation` | Derives the six bounds from `limits.json` into `limits_generated.rs`, the way `CAPABILITY_MAX_NAME_BYTES` is derived rather than pinned (§4.3's rule). No validator anywhere takes a literal |
| `twinvpn-core` | `core-composition` | `dispatch.rs`'s four `pair.*` refusals lose their stated cause. They become wiring, not a contract gap |
| `twinvpn-mgmt` | `core-composition` | ADR-0017 §11.3 already fixes the carriage: a statement passing *through* MI is "carried as opaque `bytes`", never re-serialized. No MI schema change follows from this amendment |
| `shells/linux` `twinvpnctl` | `desktop-linux` | ADR-0023 E1/E2's renderers. **They consume the byte string; they never parse it** (CB-2) |

---

## 4. §3 step 4 — Phase 1 architectural implications

Four were checked. Three are clean; the fourth is a real consequence and is
stated rather than buried.

**(a) I4 — the identity private half never leaves the platform element.**
Untouched. The offer carries `ik_pub` and `tk_pub`, both public. `pairing_secret`
is not an identity key, does not derive one, does not wrap one and does not
escrow one — ADR-0023 §11.7 argues this in three steps and concludes "**I4** is
untouched". The CDDL has no field of any private-key type, which is the same
structural argument `twinvpn-ffi`'s `HostIdentity` makes: the private half is not
withheld, it is **not representable**.

**(b) P4 — no shared secret as an authentication path.** Untouched, on
ADR-0023 §11.7's reasoning, which this proposal adopts rather than re-derives:
`pairing_secret` authenticates a *channel*, for 120 seconds, once, and no
subsequent authentication consults it. Adding a contract for it does not change
what it is for. It does make the 120-second bound and the single-use rule
machine-checkable, which is a strengthening.

**(c) ADR-0015 §11.4 `SECRET` classification and EM-24.** This is where a
contract could do harm and must not. ADR-0023 EM-24: the offer "is classified
`SECRET` … **no rendering path into the ledger, syslog, bundle, or any log level
exists**", and `architecture.md` S-67 repeats it. A contract message is a
temptation to add a `Debug`, to attach the decoded struct as `Evidence`, or to
log a parse failure with the offending bytes. The CDDL in §6.1 therefore carries
the prohibition in its own text, in the same voice `pairing.proto` uses for its
secret-field prohibition, so a future reader meets the rule at the definition
rather than three documents away. `twinvpn-diag`'s redaction already names
pairing; W-33 and R-9's hand-written `Debug` pattern is the mechanism the
consuming crate would follow.

**(d) The consequence that is real: ADR-0007 §7.4's `attestation` field cannot be
carried on C-B's own primary channel.** This is finding **F-1** in §8 and it is
the reason `pairing.max_offer_attestation_bytes` is proposed at **0** rather than
at some plausible blob size. Setting a non-zero bound would put a field in the
contract that the channel provably cannot deliver, which is worse than a
narrowing that says so.

---

## 5. §3 step 5 — compatibility analysis

**It is additive in the strongest available sense: nothing that exists today
changes.**

- **No `.proto` moves.** No field number, no enum value, no message, no wire
  format. `contracts/gen/**` — all 649 generated files across Rust, Swift, Kotlin
  and C# — is **byte-identical**, because the code generators consume
  `contracts/proto/**` and nothing else. This is the same claim Amendments 1, 2
  and 3 each made and each verified.
- **No reason code is added, renamed or reclassified.** Every condition this
  payload can produce already has a registered code, checked by name against the
  455-code registry: a non-canonical encoding is `PROTO.NON_CANONICAL_CBOR`
  (registered, `PERSISTENT`/`ERROR`, ADR-0003); over-length is
  `PROTO.SIZE_EXCEEDED`; excessive nesting is `PROTO.DEPTH_EXCEEDED`; an expired
  offer is `AUTH.PAIRING_EXPIRED`; a second presentation of a consumed
  `pairing_id` is `AUTH.PAIRING_ATTEMPTS_EXCEEDED`, which is exactly what
  ADR-0023 EM-24 and `architecture.md` S-67 already require. **The registry needs
  nothing.** This amendment is therefore strictly smaller than any of the three
  before it.
- **The other three registries are untouched** and stay at `registry_version` 2.
  `limits.json` goes 2 → 3 because it changed. Version parity was Amendment 1's
  convenience and Amendment 2 already ruled it is not a rule: bumping an
  unchanged registry claims a change a reader cannot find.
- **`check_registry_append_only.py` is not engaged.** Its `FROZEN_REASON_ATTRS`
  govern reason-code attributes; no reason code is touched. The `pairing` object
  in `limits.json` gains six keys and **no existing key changes value**, so a
  validator compiled against the old registry enforces exactly what it enforced
  before.
- **No S-37 compatibility event arises.** Nothing is deprecated, retired,
  renamed, or reclassified.
- **One wire-visible consequence, and it is the intended one.**
  `contracts/SCHEMA_DIGEST` is computed over `proto/**` + `cddl/**` +
  `registry/*.json`, so a new `.cddl` and a changed `limits.json` both move it,
  and `SchemaDescriptor.schema_digest` moves with it. That is what the field is
  for (ADR-0003 §11 rule 4: it names an immutable published artifact set; a new
  artifact set gets a new name). Every one of Amendments 1, 2 and 3 moved it for
  the same reason — the three digests are recorded in `contracts/FROZEN` — so
  this is precedent, not a new class of change. VR-3's prohibition on *inferring*
  a version from another is unaffected: the digest is read from the table, never
  derived.
- **The one direction of incompatibility, stated because it is real.** A device
  built before this amendment refuses `pair.*` outright, so there is no deployed
  producer or consumer of an offer to be incompatible *with*. That is what makes
  the amendment free now and expensive later: once one implementation ships an
  offer, the encoding is frozen by deployment rather than by decision, and the
  four `NEW` per-field bounds become unchangeable in the tightening direction.

---

## 6. The exact diff

**Not applied.** Reproduced here so the review is of the change itself rather
than of a description of it.

### 6.1 NEW FILE — `contracts/cddl/twinvpn/v1/pairing_offer.cddl`

```cddl
; TwinVPN PairingOffer — the C-B ceremony payload, deterministic CBOR.
;
; Authority: ADR-0007 §7.4 (the ceremony, and this structure's seven fields),
; ADR-0023 §11.6 EM-22..EM-26 (the four enrolment channels that carry it, and
; the handling rules), ADR-0017 §11.3 (carriage through MI as opaque bytes),
; docs/architecture.md S-67 (HeadlessEnrolmentOffer, the in-flight state),
; contracts/registry/limits.json `pairing` (every bound below).
;
; =============================================================================
; WHAT THIS IS, AND WHY IT IS NOT IN THE FILES NEXT TO IT
; =============================================================================
; This payload crosses an OUT-OF-BAND, CONFIDENTIAL CHANNEL: a QR photographed
; off a screen, a Crockford-base32 block pasted between terminals, a 0600 file,
; a serial console, a ubus event (ADR-0023 EM-22 E1..E4). It is the ONE dCBOR
; payload in this contract set that is NOT a signed statement.
;
; NOT IN signed_statements.cddl. Every member of that file is COSE_Sign1-wrapped
; and VERIFIED. This payload cannot be: the joining device is BY DEFINITION not
; yet enrolled, holds no OwnerTrustAnchor and no TrustedPeer, and therefore has
; no key to verify a signature against. C-B's channel authentication IS the
; optical confidentiality (256 bits), not a signature. A COSE_Sign1 nobody can
; check would be bytes shaped like a proof, verified by no one. Its closed
; inventory of seventeen statements is also not the place to spend a slot
; against ADR-0003 §14 revisit trigger 7.
;
; NOT IN pairing.proto, AND THAT FILE SAYS SO. Its header states the
; SECRET-FIELD PROHIBITION: "pairing_secret, the SPAKE2 password, K_pair, and
; PairSecret NEVER appear in this schema and MUST NOT be added". Field 1 below
; IS pairing_secret. pairing.proto's messages are C1/C2 WIRE messages, and the
; entire security argument of C-B is that pairing_secret NEVER TRANSITS THE
; NETWORK — ADR-0007 §7.4: "MITM at the rendezvous is defeated by construction:
; the adversary never sees pairing_secret". A protobuf definition invites
; exactly one mistake, embedding this in a PairingRequest, and that mistake
; hands the rendezvous the one value it must never see.
;
; =============================================================================
; SECRET HANDLING — NORMATIVE. ADR-0023 EM-24, ADR-0015 §11.4.
; =============================================================================
; The whole payload is classified SECRET. There is NO RENDERING PATH into the
; diagnostic ledger, syslog, a Tier-1 bundle, or ANY log level, at any severity,
; in any build profile.
;
;   - `pairing_id` (= SHA-256(pairing_secret)[0..15]) is PUBLIC and MAY be
;     logged. `pairing_secret` MUST NOT be, ever, including inside a parse
;     error, a hex dump, a Debug rendering, or an Evidence attachment.
;   - A decode failure is reported as a bare registered reason_code with NO
;     evidence drawn from the input. "The offer did not parse" is the whole of
;     what may be said about it.
;   - The decoded value is zeroized on consumption or at expiry, whichever is
;     first (ADR-0023 EM-24, architecture.md S-67: "non-durable BY REQUIREMENT
;     — it MUST NOT survive process restart").
;
; =============================================================================
; ENCODING RULES — NORMATIVE
; =============================================================================
;   1. RFC 8949 §4.2.1 CORE DETERMINISTIC ENCODING, exactly as
;      signed_statements.cddl rule 1 requires of a signed statement. Two
;      conforming producers MUST emit byte-identical output for the same
;      logical value, because ADR-0023 E2 renders THESE BYTES as Crockford
;      base32 for a human to copy and E1 renders THESE BYTES as a QR.
;      Non-canonical input MUST BE REJECTED with PROTO.NON_CANONICAL_CBOR,
;      NEVER NORMALIZED.
;
;   2. THE TOTAL ENCODED LENGTH IS CHECKED FIRST, BEFORE ANY FIELD IS PARSED,
;      against `pairing.max_offer_bytes`. Over-length is PROTO.SIZE_EXCEEDED.
;      This ordering is the reason the per-field bounds below can never
;      disagree with the payload bound in the direction that matters: their sum
;      (493) is at or below the payload cap (512), and a receiver that enforces
;      the payload cap first can meet no field it has not already budgeted for.
;
;   3. UNKNOWN KEYS ARE REJECTED. There is no wildcard entry in the map below
;      and none may be added. Unlike an unsigned transport message, nothing
;      here is forwarded, so a preserved-but-uninterpreted field would be a
;      place to smuggle bytes past a human who is about to photograph them.
;      ADR-0003 §7's asymmetry, applied to a payload with no verifier at all.
;
;   4. NO FLOAT appears in this schema. Depth is 2 (the map, and the array
;      inside the embedded COSE_Sign1's own encoding, which is opaque here).
;      Nesting beyond the parser's limit is PROTO.DEPTH_EXCEEDED.
;
;   5. `not_after_ms` is MANDATORY and is evaluated against LOCAL time. A
;      receiver MUST refuse an offer whose window exceeds
;      `pairing.ceremony_expiry_ms` beyond its own clock: ADR-0007 §7.4 fixes
;      the expiry at 120 s "enforced INDEPENDENTLY by both devices and the
;      rendezvous", and an offer that names its own longer window is a producer
;      trying to widen a bound the receiver owns.
; =============================================================================

; --- Primitives ---------------------------------------------------------------
; Deliberately spelled here rather than imported: CDDL has no include, and
; signed_statements.cddl's copies carry rules (crit-set, mandatory COSE
; wrapping) that do not apply to this file. Where a name is shared, the
; definition is character-identical, and contracts/tests asserts it.

epoch-ms   = uint            ; UTC milliseconds
cose-key   = bstr .size (1..80)
                             ; COSE_Key, deterministic CBOR, carried as an
                             ; embedded bstr for the same reason
                             ; signed_statements.cddl carries one: the inner
                             ; encoding is verified as received, never
                             ; re-serialized. `pairing.max_offer_cose_key_bytes`.
                             ; A P-256 compressed EC2 key measures 43 bytes; the
                             ; bound admits the uncompressed form so a producer
                             ; that ignores §7.4's "compressed point" is refused
                             ; by THIS FILE'S words rather than by a length
                             ; accident.

; --- PairingOffer -------------------------------------------------------------
; ADR-0007 §7.4, C-B (the QR path, primary). The joining device generates
; `pairing_secret` and displays / emits this.
;
; pairing_id = SHA-256(pairing_secret)[0..15] is the PUBLIC rendezvous handle
; and is NOT a field here — it is DERIVED, and carrying it would create a second
; place for it to disagree with the secret it names.
;
; K_pair = HKDF-SHA-256(salt = pairing_id, ikm = pairing_secret,
;                       info = "TwinVPN/Pair/v1")
; wraps every subsequent ceremony message. Neither K_pair nor any value derived
; from it appears in this schema and neither MUST BE ADDED.

pairing-offer = {
  1: bstr .size 32,          ; pairing_secret. THE SECRET. 32 random bytes
                             ; (ADR-0007 §7.4). `pairing.secret_bytes`.
                             ; Optical-confidential; NEVER transits the network.
  2: cose-key,               ; ik_pub. ES256 / P-256, compressed point.
  3: bstr .size 32,          ; tk_pub. X25519, raw.
                             ; NOTE, and it is a finding rather than a choice:
                             ; signed_statements.cddl's tunnel-key-binding
                             ; carries tk_pub as `cose-key`, so the corpus
                             ; spells one key two ways. §7.4's `bstr(32)` is
                             ; followed here because this file's authority is
                             ; §7.4; ownership.md §11 G-9 carries the divergence.
  4: bstr .size (1..256),    ; binding. COSE_Sign1(IK) over the TunnelKeyBinding
                             ; of signed_statements.cddl §2, carried as opaque
                             ; octets and VERIFIED OVER THE RECEIVED OCTETS.
                             ; ADR-0007 N-4: the receiver MUST verify this
                             ; BEFORE writing TK into TrustedPeer, and the check
                             ; MUST NOT be skippable by configuration — a
                             ; skipped check is a full authentication bypass.
                             ; `pairing.max_offer_binding_bytes`. Measured: 216.
  5: null,                   ; attestation. ADR-0007 §7.4 writes `bstr / null`.
                             ; `pairing.max_offer_attestation_bytes` is 0, so
                             ; `null` is the only admissible value on this
                             ; payload, AND THAT IS A NARROWING OF §7.4 THAT
                             ; NEEDS THE ADR'S OWNER: the channel cannot carry a
                             ; platform attestation blob. The measured offer
                             ; with attestation ABSENT is 377 bytes; ADR-0023
                             ; E1's declared 71-column terminal admits a QR of
                             ; at most 61 modules with a conforming 4-module
                             ; quiet zone, which is version 11, which holds 321
                             ; bytes at EC level L. The offer is ALREADY 56
                             ; bytes over its own primary channel with this
                             ; field empty. See ownership.md §11 G-9, finding F-1.
  6: tstr .size (0..64),     ; rendezvous_hint. `pairing.max_offer_hint_bytes`.
                             ; Tighter than pairing.proto's peer_hint (256) on
                             ; purpose: that one travels a 64 KiB C1 envelope,
                             ; this one has to survive being photographed.
  7: epoch-ms,               ; not_after_ms. issued + pairing.ceremony_expiry_ms.
                             ; Rule 5 above: the RECEIVER owns the window.
}
```

### 6.2 `contracts/registry/limits.json`

```diff
 {
-  "registry_version": 2,
+  "registry_version": 3,
   "_comment": "Validation limits for untrusted input. ...",
@@
   "pairing": {
     "ceremony_expiry_ms": 120000,
     "max_failed_runs": 5,
     "max_peer_hint_bytes": 256,
-    "max_ceremony_payload_bytes": 512
+    "max_ceremony_payload_bytes": 512,
+    "secret_bytes": 32,
+    "max_offer_bytes": 512,
+    "max_offer_cose_key_bytes": 80,
+    "max_offer_binding_bytes": 256,
+    "max_offer_attestation_bytes": 0,
+    "max_offer_hint_bytes": 64,
+    "_offer_note": "The six offer bounds are ADR-0007 §7.4's PairingOffer, defined in cddl/twinvpn/v1/pairing_offer.cddl. max_offer_bytes is checked BEFORE any field is parsed; the per-field bounds sum to 493, at or below it, so the two cannot disagree. max_offer_attestation_bytes is 0 because ADR-0007 §7.4's `bstr / null` attestation does not fit ADR-0023 E1's channel: the offer measures 377 bytes with it absent, and a 71-column terminal admits a QR of at most 321 bytes at EC level L with a conforming quiet zone. Recorded as finding F-1 under docs/implementation/ownership.md §11 G-9."
   },
```

### 6.3 `contracts/tests/test_registries.py`

Three assertions, in the file's existing style:

```python
case("the limits registry declares the PairingOffer bounds")
pairing = limits["pairing"]
check_eq(limits["registry_version"], 3, "limits registry_version")
for key, value in {
    "secret_bytes": 32,
    "max_offer_bytes": 512,
    "max_offer_cose_key_bytes": 80,
    "max_offer_binding_bytes": 256,
    "max_offer_attestation_bytes": 0,
    "max_offer_hint_bytes": 64,
}.items():
    check_eq(pairing[key], value, f"pairing.{key}")

case("the PairingOffer per-field bounds fit inside the payload bound")
# Amendment 1's recorded cost was a per-field cap that exceeded its envelope
# cap and passed because nothing compared them. This compares them, and it
# computes the CBOR head length rather than hardcoding one: a bound crossing
# 24, 256 or 65536 grows its own header, which is exactly the arithmetic a
# reader would get wrong by hand.
def head_len(n):
    """Bytes in an RFC 8949 shortest-form head for argument `n`."""
    return 1 if n < 24 else 2 if n < 0x100 else 3 if n < 0x10000 else 5

def field(payload_len):
    """One map entry: a 1-byte integer key, a head, and the payload."""
    return 1 + head_len(payload_len) + payload_len

worst = (
    field(pairing["secret_bytes"])                 # 1 pairing_secret
    + field(pairing["max_offer_cose_key_bytes"])   # 2 ik_pub
    + field(32)                                    # 3 tk_pub, X25519, fixed
    + field(pairing["max_offer_binding_bytes"])    # 4 binding
    + 1 + 1                                        # 5 attestation = null
    + field(pairing["max_offer_hint_bytes"])       # 6 rendezvous_hint
    + 1 + 9                                        # 7 not_after_ms, uint64 head
    + 1                                            # the map head, 7 entries
)
check_eq(worst, 493, "the offer's worst-case encoded length")
check(worst <= pairing["max_offer_bytes"],
      f"the offer's field bounds sum to {worst}, over max_offer_bytes")
check_eq(pairing["max_offer_attestation_bytes"], 0,
         "attestation is null-only on this payload; see ownership.md F-1")

case("pairing.proto still carries no secret field")
# The SECRET-FIELD PROHIBITION in pairing.proto's header is the reason the
# offer is CDDL. A tripwire, so adding the message to the proto fails here.
src = (ROOT / "proto" / "twinvpn" / "v1" / "pairing.proto").read_text()
for forbidden in ("pairing_secret", "PairingOffer", "k_pair", "pair_secret"):
    check(forbidden not in src,
          f"pairing.proto must not name {forbidden} (its own header forbids it)")
```

---

## 7. What lands after approval, and what does not

**Inside `contracts/`:** the three items in §6, plus the `contracts/FROZEN`
re-declaration as Amendment 4 with the evidence line (`.proto` count unchanged,
649 generated files byte-identical, the contract-check count, the new digest).
Steps 7 and 8 of §3.

**Outside `contracts/`, and NOT part of this ask:**

- `twinvpn-schema` derives the six bounds into `limits_generated.rs`. No
  validator anywhere takes a literal — §4.3's rule, and the reason the last
  registry move failed a test instead of silently disagreeing with a validator.
- `twinvpn-crypto` gains the decoder on `dcbor::parse_canonical`, with the
  negative tests that module's header calls for: a non-canonical map order, a
  duplicate key, an unknown key, an over-length payload refused **before** the
  first field is read, an over-length field, a non-null `attestation`, an expired
  window, and a `Debug` tripwire asserting the secret's own bytes are absent
  (R-9's pattern, which found a `PresentedToken` test that passed only because
  `Vec<u8>` renders as digits).
- `twinvpn-core`'s four `pair.*` refusals lose their stated cause and become
  wiring.
- `shells/linux` gains E1's and E2's renderers.

**The order matters and is not negotiable:** the contract lands first. Every one
of the above is an implementation of a frozen definition, which is the shape §3
exists to produce.

---

## 8. Findings raised while writing this, recorded under `ownership.md` §11 G-9

Three, none of which this proposal resolves.

**F-1 — `PairingOffer` does not fit ADR-0023 E1's declared terminal, measured.**
ADR-0023 EM-22 E1 makes the terminal QR the **default** enrolment channel
"whenever the terminal is ≥ 71 columns × 37 rows". A conforming QR needs a
4-module quiet zone on every side, so 71 columns admits a symbol of at most 63
modules — **version 11, 61 modules, 321 bytes at EC level L**. The offer measures
**377 bytes** with `attestation` absent and a 27-character hint: 56 bytes over,
before any attestation blob, at the *weakest* error-correction level, for a
symbol that is going to be photographed off a glowing screen. Level M — the
level one would actually choose for that — holds 251 at version 11 and 331 at
version 13. Version 13 (69 modules) fits inside 71 columns only with a 1-module
quiet zone, which is non-conforming.

Three things follow, and the corpus decides none of them: **no document fixes the
QR version, the error-correction level, or the quiet zone**, and those three
together decide whether the product's default enrolment channel works at all.

Two exits exist and both are somebody else's:
1. **E1's geometry grows.** A 377-byte offer at version 13 with a conforming
   quiet zone needs **79 columns × 41 rows**, not 71 × 37 — this document first
   said 77 × 39, which omitted the 1-character border E1's own 71 × 37 implies
   (61 + 8 + 2 = 71); corrected when EM-22a pinned the model. That is an ADR-0023
   EM-22 edit.
2. **`binding` shrinks.** It is **219 of the 377 bytes — 58% of the payload** —
   and the `TunnelKeyBinding` inside it re-states `tk_pub`, which the offer
   already carries in field 3, alongside a `device-id` and an `identity-id` the
   offer does not otherwise have. A binding carried by reference, or a bare
   ES256 signature over a payload the receiver reconstructs from the offer's own
   fields, removes roughly 150 bytes and brings the offer under 321. That is an
   ADR-0007 §7.4 question and explicitly not one an implementation agent may
   answer — W-23 is the wave's standing lesson that **a specified derivation is
   not ours to improve**.

**F-2 — `tk_pub` is spelled two ways in the corpus.** ADR-0007 §7.4's
`PairingOffer` field 3 is `bstr(32)`, raw X25519. `signed_statements.cddl`'s
`tunnel-key-binding` field 3 is `cose-key`, and `device-identity-record` field 6
is `cose-key` too. So the same key is a bare 32-byte string in one structure and
a COSE_Key in the two structures that bind it. The offer's `binding` field
carries the COSE_Key form *inside* the payload whose field 3 carries the raw
form, in the same 377 bytes. This proposal follows §7.4 for §7.4's own structure
and records the divergence rather than harmonising it, because harmonising it
either changes a frozen CDDL or changes an ADR. It also costs bytes F-1 says are
not available: the raw form is 13 bytes cheaper.

**F-3 — `contracts/registry/limits.json`'s `_max_name_bytes_note` is still
stale.** §4.3 records that the note "still reads 'Recorded as an open contract
defect in `ownership.md` §4.3 with a live workaround in production code'" when
there is no live workaround any more, and rules that it is **not worth an
amendment on its own** but should be folded "into the next one that opens
`contracts/` for a real reason". **This is that amendment**, and §6.2 above
deliberately does *not* fold it in, because doing so would put a second, unasked
edit in front of the approver. If Amendment 4 is approved, correcting that note
in the same commit is the cheapest it will ever be, and §4.3 already pre-approved
the substance. It is called out here so the opportunity is taken deliberately
rather than missed twice.
