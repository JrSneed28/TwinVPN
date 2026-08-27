# ADR-0003: Network Contract / Schema Format

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** PROTOCOL
- **Related:** ADR-0001 (tunnel crypto), ADR-0002 (control-plane messaging), ADR-0007 (identity/pairing), ADR-0014 (versioning), [docs/protocol.md](../protocol.md), [docs/threat-model.md](../threat-model.md), [docs/architecture.md](../architecture.md)

## 1. Context

TwinVPN has four distinct encoding boundaries, and treating them as one problem produces a
bad answer for at least three of them.

| Boundary | Traffic | Who parses it | Rate | Trust of input |
|---|---|---|---|---|
| **B1 — Control plane** | RPC and durable events between `Device` and the coordination service (channels C1/C2/C7 in [docs/protocol.md](../protocol.md)) | Coordination service, device agent | ~1–100 msg/min/device | Semi-trusted peer over an authenticated channel; still attacker-reachable |
| **B2 — Signed statements** | `PairingAttestation`, `RevocationRecord`, `DeviceIdentityRecord`, `PolicyBundle`, `RouteAdvertisement`, `ExitNodeOffer`, `IdentitySuccession`, `TunnelKeyBinding`, `OwnerTrustAnchor`, `OwnerDelegation`, `TrustEpochBundle`, `RelayCapabilityToken`, `RelayEpochFloor`, the signed relay map, `LogHead`, and the **signed network contract** | Every device, possibly years after issuance | Rare | **Trust-bearing.** Forgery = total compromise. |
| **B3 — Ephemeral signaling** | `ConnectOffer`, `CandidateSet`, `PunchSync` (channel C4) | Peer device; **forwarded by an untrusted rendezvous** | 10s–100s of msgs per connection attempt | **Fully attacker-reachable, pre-authentication.** |
| **B4 — Data plane** | Tunnel packets (channels C5/C6) | Kernel/userspace fast path; relays forward opaquely | **Millions of packets/sec aggregate** | Attacker-reachable, but post-AEAD-authentication |

Plus a fifth, non-network boundary: **B5 — local config, CLI output, and diagnostic
bundles**, which humans read and paste into support tickets.

The failure modes TwinVPN exists to fix put specific pressure on this decision. "Cryptic
error codes" and "insufficient diagnostics" push toward human-readable encodings.
"Throughput degradation" pushes toward zero-cost encoding in the data path. "Weak protocol
lifecycle management" pushes toward a schema with real evolution semantics. And invariant
**I2** (no custom cryptography) combined with the need to sign trust-bearing statements
pushes hard toward an encoding with a *specified, testable canonical form* — because
"canonicalize then sign" without a canonicalization spec is exactly how you accidentally
design a novel construction with signature-malleability holes.

## 2. Requirements


**Requirements discharged** ([docs/vision.md](../vision.md) §5): **R-04** (protocol and schema evolve without breaking deployed devices; unknown fields are handled by a stated rule, not by chance) and **R-22** (every terminal or degraded outcome carries a stable machine-readable `reason_code` field on the wire — this ADR owns the field's presence and encoding; [ADR-0015](ADR-0015-observability-and-diagnostics.md) owns its taxonomy).
| ID | Requirement |
|---|---|
| R1 | A **deterministic, specified canonical encoding** MUST exist for every signed statement (B2, B3), such that two conforming implementations produce byte-identical output for the same logical value. |
| R2 | Verification MUST be definable over **received octets**, so no implementation is ever required to re-serialize before verifying. |
| R3 | Schema evolution MUST support adding fields without breaking old readers, and MUST define unknown-field behaviour precisely (see ADR-0014). |
| R4 | The B3 parser MUST be safe on fully hostile, pre-authentication input, with a small, auditable, fuzzable attack surface. |
| R5 | Wire size on B1/B3 MUST be small enough that a mobile radio wakeup is not dominated by encoding overhead. |
| R6 | Encode/decode cost on B1/B3 MUST be negligible relative to a network RTT on a low-end mobile CPU. |
| R7 | B4 MUST have **zero** serialization framework in the packet path. |
| R8 | Cross-language tooling MUST cover at minimum Go, Rust, Swift, Kotlin, C, and TypeScript (device agents across five OS families plus server and UI). **Amended 2026-08-27 — see §2.1.** |
| R9 | B5 MUST be human-readable and diffable without tooling. |
| R10 | The chosen format(s) MUST be expressible in a machine-checkable schema so contract drift between components is caught in CI, not in the field. |
| R11 | Signed statements MUST support a "critical field" concept so that a security-relevant extension cannot be silently ignored by an old reader. |

### 2.1 What R8 is, and is not (amendment, 2026-08-27)

R8 is a **selection criterion on the format's ecosystem**, not a generation
manifest. It was written to discriminate between candidate encodings — the
question it answers is *"does this format have mature codegen everywhere we
might plausibly need it?"*, which is why it names the union of every language
the product could touch, and why it says **"at minimum"**.

It is **not** a list of bindings that must be generated. The bindings actually
generated are fixed by
[ADR-0018](ADR-0018-shared-core-and-build-architecture.md) §11.12 —
**Rust, Swift, Kotlin and C#** — one per real consumer:

| Binding | Consumer | Source |
|---|---|---|
| Rust | the shared core, the Linux/Windows/OpenWrt shells, the relay server | ADR-0018 §11.3, §11.9 |
| Swift | the iOS, iPadOS and macOS shells | ADR-0018 §11.9 |
| Kotlin (+ Java) | the Android shell | ADR-0018 §11.9 |
| C# | the Windows WinUI application shell | ADR-0018 §11.9, §12 item 9 |

**Go, C and TypeScript are not generated**, because ADR-0018 assigns no Phase 1
component to any of them. Generating an unassigned binding is not free: it
becomes a permanent CI, review and compatibility obligation — every schema change
must keep compiling in a language nobody consumes, and a language that cannot
express a change would block it for no benefit.

**This amendment resolves conflict CF-2** recorded in
`contracts/docs/phase1-conflicts.md`. R8's *substance* is unchanged and still
holds: protobuf was selected partly because its tooling reaches all six, and that
reach is what makes adding a fifth binding a decision rather than a migration.

**One measured constraint on ever adding a JS/TypeScript binding.** §11's B1 row
requires unknown fields to be **preserved and forwarded**. The Phase 2 contract
tests measured this across two runtimes: the Go implementation preserves unknown
fields; **protobufjs does not**. Any language chosen for a component that
*forwards* a message it does not fully understand — the coordination service, the
rendezvous, a relay carrying an opaque `CALL` — MUST use a runtime with
preserve-and-forward, and that MUST be verified rather than assumed.

## 3. Constraints

- **I1** — nothing in the encoding may require a `Relay` to parse user payloads. Relays see framing only.
- **I2** — no novel cryptography. This forbids inventing a canonicalization scheme; it must be a published, audited one.
- **I6** — every failure surfaces a structured diagnostic, so parse failures must be distinguishable and describable, not a generic "bad message".
- Device agents run on constrained hardware (routers, older phones); a format requiring a large runtime or heavy codegen is a real cost.
- Signed statements may be verified **years** after issuance by an implementation compiled from a newer schema. The canonical form must be stable across that gap.
- The rendezvous service (B3) is deliberately dumb; it must not need to parse the payloads it forwards. This means B3 payloads must be opaque-forwardable.

## 4. Considered Alternatives

1. **Protocol Buffers (proto3)** everywhere it applies (B1–B3), no framework in B4.
2. **FlatBuffers** everywhere it applies.
3. **Cap'n Proto** everywhere it applies.
4. **JSON** (with JCS, RFC 8785, for canonicalization) everywhere it applies.
5. **CBOR** (RFC 8949) with core deterministic encoding, plus COSE (RFC 9052) for signatures, everywhere it applies.
6. **MessagePack** everywhere it applies.
7. **Layered selection (SELECTED):** Protocol Buffers for B1/B3 transport schemas; **deterministic CBOR** for B2 signed statements and for the signed inner payload of B3 messages, carried as opaque `bytes`; **no serialization framework at all** for B4; **JSON** for B5.

### 4.1 Evaluation matrix

Scores: ●●● strong, ●● adequate, ● weak.

| Criterion | Protobuf | FlatBuffers | Cap'n Proto | JSON | CBOR | MessagePack |
|---|---|---|---|---|---|---|
| Wire size | ●●● | ● (padding, vtables) | ● (padding, pointers) | ● | ●●● | ●●● |
| Encode cost | ●● | ●●● (build-in-place) | ●●● | ● | ●●● | ●●● |
| Decode cost | ●● | ●●● (zero-copy) | ●●● (zero-copy) | ● | ●●● | ●●● |
| Zero-copy suitability for a data path | ●● | ●●● | ●●● | ● | ● | ● |
| Schema evolution | ●●● | ●●● | ●●● | ●● (convention only) | ●● (convention or CDDL) | ● (none) |
| Unknown-field handling | ●●● (preserved since 3.5) | ●● (skipped) | ●● (preserved in some impls) | ●● (ad hoc) | ●● (ad hoc; CDDL can specify) | ● |
| **Deterministic/canonical encoding** | ● **(explicitly not guaranteed)** | ● (padding is unspecified) | ● (segment layout varies) | ●● (JCS exists, but float/number pitfalls) | ●●● **(RFC 8949 §4.2 core deterministic encoding — a normative spec)** | ● (no spec) |
| Cross-language tooling | ●●● | ●● | ● | ●●● | ●●● | ●● |
| **Parser security surface on hostile input** | ●● (large generated surface, but heavily fuzzed; historical DoS CVEs, e.g. recursion/`ParseFromString` issues) | ● (**verifier is optional**; skipping it yields raw pointer arithmetic on attacker data) | ● (pointer/segment arithmetic; historical OOB CVEs, e.g. CVE-2015-2310, CVE-2017-7892) | ●● (many parsers, many historical bugs, but no pointer arithmetic) | ●●● (tiny grammar, trivially fuzzable, no pointers) | ●● (tiny grammar, but no schema to constrain shapes) |
| Human debuggability | ●● (needs a schema to decode) | ● | ● | ●●● | ●● (diagnostic notation, RFC 8949 §8) | ● |
| Schema language for CI contract checks | ●●● (`.proto`) | ●●● (`.fbs`) | ●●● (`.capnp`) | ●● (JSON Schema) | ●● (CDDL, RFC 8610) | ● |

Two rows decide most of this ADR.

**Deterministic encoding.** Protocol Buffers explicitly does **not** guarantee that
serialization is deterministic across languages, versions, or even builds — the
documentation says so, unknown fields and map ordering are the classic hazards, and
`deterministic=true` in some runtimes is documented as *not* a canonical-form guarantee.
Building a signature scheme on "serialize the protobuf and sign it" is therefore a latent
break: the day a peer's runtime reorders a map or reserializes with a preserved unknown
field, previously valid signatures stop verifying, or worse, two distinct logical values
sign identically. RFC 8949 §4.2 core deterministic encoding is, by contrast, a normative
specification with a fixed integer encoding, fixed key ordering, and no indefinite-length
items — and COSE (RFC 9052) is an audited, IETF-standardized signing envelope built on it,
which satisfies **I2**'s "no custom cryptography" by letting us adopt rather than invent.

**Parser security surface on hostile input.** B3 is the worst-case boundary: pre-
authentication, forwarded by an untrusted rendezvous, reachable by anyone who can send a
UDP datagram. FlatBuffers and Cap'n Proto achieve zero-copy precisely by doing pointer
arithmetic on attacker-controlled bytes. FlatBuffers' verifier is *optional* and, in
practice, frequently skipped for the performance it was chosen for — which converts the
format's main advantage into its main vulnerability. Cap'n Proto has a documented history
of out-of-bounds and integer-overflow issues in pointer/segment handling. CBOR's grammar is
small enough to fuzz to saturation. That asymmetry matters far more than a few hundred
nanoseconds of decode time on a message that is preceded by a 40 ms RTT.

## 5. Advantages of Each Alternative

**Protocol Buffers.** Best-in-class schema evolution with a decade of production semantics
behind it; unknown fields preserved since proto3 3.5, which makes middleboxes and mixed-
version fleets safe; excellent codegen for every language TwinVPN targets, including the
constrained ones; `.proto` files are a genuinely good CI contract artifact; compact varint
encoding; gRPC integration means the B1 transport (ADR-0002) comes with it rather than
being bolted on; the largest fuzzing corpus and the most implementation review of any
alternative here.

**FlatBuffers.** True zero-copy access with no decode step, so field access is O(1) into
the received buffer; excellent for a data path or for large, mostly-unread structures;
strong schema evolution via vtables; low steady-state allocation, which matters on mobile.

**Cap'n Proto.** Zero-copy like FlatBuffers plus a mature RPC layer with promise pipelining,
which would reduce round trips; extremely fast; strong schema evolution; a well-designed
capability model that maps conceptually well onto TwinVPN's relay capability tokens.

**JSON.** Unbeatable debuggability — a support engineer can read a captured message with no
tooling, which directly serves **I6**; universal library support in every language and
every scripting environment; JCS (RFC 8785) provides a real canonicalization spec; trivial
for third-party integrations and for the local config file a user may hand-edit.

**CBOR.** A normative deterministic-encoding profile (RFC 8949 §4.2), which no other
alternative here provides at the same quality; a tiny grammar with a correspondingly tiny
parser attack surface; compact binary sizes comparable to MessagePack; an audited signing
standard on top (COSE / RFC 9052) already used by WebAuthn, FIDO2, and EAT, so adopting it
is adopting reviewed cryptographic packaging rather than designing it; diagnostic notation
(RFC 8949 §8) gives adequate human readability; CDDL (RFC 8610) supplies a schema language
for CI checks; excellent library support including constrained-device implementations.

**MessagePack.** Very compact, very fast, dead simple, ubiquitous library support, minimal
runtime footprint.

**Layered selection.** Gets the best property at each boundary instead of the least-bad
compromise across all of them: protobuf's evolution and tooling where evolution and tooling
dominate, CBOR's determinism and small parser where signing and hostile input dominate,
nothing at all where throughput dominates, and JSON where a human is the consumer.

## 6. Disadvantages of Each Alternative

**Protocol Buffers.** *Fatal for signed statements:* no canonical encoding guarantee, so R1
cannot be met without inventing a canonicalization profile — which **I2** forbids in
spirit and which would be a genuine footgun in practice. Also: generated code is bulky on
constrained targets; the reflection/descriptor surface is large; historical DoS issues from
deeply nested messages require explicit depth limits; a `.proto` alone does not express
required-vs-optional strongly in proto3, so validation still has to be hand-written at the
boundary.

**FlatBuffers.** The verifier being optional is a structural security problem for B3, not a
usage problem — a single code path that forgets it becomes a memory-safety bug on
attacker-controlled input. Wire size is materially larger than protobuf/CBOR because of
alignment padding and vtables, which is the wrong trade on a radio wakeup. No canonical
encoding: padding bytes and vtable layout are not specified byte-for-byte, so R1 fails.
Debuggability is poor. Tooling outside C++/Java/Go/Rust is thinner than protobuf.

**Cap'n Proto.** The same no-canonical-form problem (segment layout and padding vary), so
R1 fails. Pointer arithmetic over hostile bytes is the highest-risk parser model in the
comparison, with a real CVE history in exactly that code. Ecosystem breadth is the weakest
of the six for Swift/Kotlin/TypeScript, which are non-negotiable targets for TwinVPN
clients. Its RPC layer is powerful but would couple the control plane to a niche transport
right where ADR-0002 needs mobile-friendly, boring, widely-deployed behaviour.

**JSON.** 2–5× the wire size of the binary alternatives, paid on every mobile radio wakeup.
Slow to parse relative to everything else. Number handling is a genuine correctness hazard
(no integer/float distinction in the spec; 64-bit integers are not safely representable in
several ecosystems) — a `net_seq` or `revocation_epoch` silently losing precision is a
catastrophic, near-undebuggable bug. JCS canonicalization exists but inherits the number
problem, so R1 is met only with additional restrictions. No native binary type, so every
key and signature needs base64, adding 33 % on the most size-sensitive fields. No schema
evolution semantics beyond convention.

**CBOR.** Weaker schema-evolution tooling than protobuf: CDDL is a good schema language but
the codegen ecosystem is far thinner, so more hand-written mapping code and more room for
drift between components (a direct R10 risk). Debuggability is worse than JSON without a
tool. Tag-space handling varies across libraries. Not zero-copy, so a poor fit for a data
path — irrelevant here because B4 uses no framework, but it rules out CBOR as a universal
answer.

**MessagePack.** No schema, therefore no evolution semantics, no unknown-field policy, no
machine-checkable contract, and no canonical form — it fails R1, R3, R10, and R11
simultaneously. Its size/speed advantage over CBOR is negligible while its
specification-quality deficit is large. It is included because it is a common choice, and
it should be rejected on the record so nobody re-proposes it.

**Layered selection.** Two formats plus JSON means two schema toolchains, two sets of
fuzzing targets, two code-review disciplines, and a real risk that a developer serializes a
signed statement with the wrong one. It also creates a boundary where a protobuf message
wraps opaque CBOR bytes, which is less obvious to a newcomer than a single format. These
costs are real and are mitigated in §11, not denied.

## 7. Security Implications

Of the selected option.

- **Signature integrity is structural, not conventional.** Signed statements are
  deterministic CBOR carried in a protobuf `bytes` field, and §3 Rule B of
  [docs/protocol.md](../protocol.md) requires verification over the **received octets**.
  Nothing ever re-serializes before verifying, so a canonicalization mismatch cannot produce
  a signature bypass or a spurious verification failure. This is the "sign the bytes you
  received, forward the bytes you received" discipline used by Certificate Transparency and
  COSE-based systems, and it eliminates an entire bug class rather than testing for it.
- **The hostile-input parser is the smallest one available.** B3's pre-authentication path
  parses a minimal protobuf envelope (a handful of fields, strict depth limit of 4, strict
  size cap of 1200 bytes) and then a CBOR inner payload. No pointer arithmetic on attacker
  bytes anywhere. Both parsers are continuously fuzzed as a release gate (see
  [docs/testing-strategy.md](../testing-strategy.md) and ADR-0015).
- **Critical-field semantics (R11).** Signed statements carry a `crit` set naming fields
  whose semantics a verifier MUST understand, following the X.509 critical-extension and
  COSE `crit` pattern. A verifier encountering an unrecognized critical field MUST reject
  the statement. Without this, adding a future restriction (e.g. "this route advertisement
  is valid only for family v6") would be silently ignored by old devices, which converts a
  tightening into a no-op — a silent authorization hole.
- **Unknown-field policy is asymmetric on purpose.** Unsigned transport messages preserve
  and forward unknown fields (protobuf default) for forward compatibility. Signed statements
  **reject** unknown non-`crit` fields at the trust boundary rather than preserving them,
  because a preserved-but-unverified field is a place to smuggle data past a policy check.
  ADR-0014 §11 owns the full rule.
- **Rejected alternatives that were materially better on a security axis:** none. JSON is
  better on auditability-by-eye, which is a security-adjacent property, and that is why it
  is retained for B5 diagnostic bundles. FlatBuffers and Cap'n Proto are strictly worse on
  the axis that matters most here.
- **Where the selection is weaker:** two parsers means two attack surfaces to maintain and
  fuzz, versus one for a single-format choice. Accepted, and mitigated by keeping the CBOR
  surface restricted to a deterministic-only profile that rejects indefinite-length items,
  non-canonical integers, duplicate keys, and unknown tags outright.

## 8. Reliability Implications

- **Schema drift is caught in CI.** `.proto` for B1/B3 and CDDL for B2 are both
  machine-checkable, so a component that changes a contract fails the build rather than
  failing in a user's living room (R10).
- **Mixed-version fleets keep working.** Protobuf's preserve-unknown-fields behaviour means
  an old coordination service can relay a message containing a new field without corrupting
  it — which matters because TwinVPN devices update on wildly different schedules (a router
  may lag a phone by a year).
- **The data path cannot be broken by a schema change**, because it has no schema
  framework. This is a reliability property, not just a performance one: the highest-rate,
  hardest-to-debug path is immune to serialization bugs by construction.
- **A determinism bug cannot cause a fleet-wide trust outage.** Under a protobuf-signing
  design, a runtime upgrade that changed serialization could invalidate every stored
  attestation at once. Under deterministic CBOR with verify-over-received-octets, stored
  signatures are verified against stored bytes and are immune to encoder changes entirely.
- **Weaker than the alternatives on:** CBOR's thinner codegen means more hand-written
  mapping code for B2, which is where hand-written bugs live. Mitigated by keeping B2's
  schema set small (seven statement types) and by round-trip property tests against CDDL.

## 9. Performance Implications

| Boundary | Cost | Assessment |
|---|---|---|
| B1 control RPC | Protobuf encode/decode, ~µs for typical 200–2000 B messages | Negligible against a 20–200 ms RTT. Size matters more than CPU here, and protobuf varints are near-optimal. |
| B2 signed statements | CBOR encode + signature. Signature dominates by 2–3 orders of magnitude. | Encoding choice is performance-irrelevant; determinism is what matters. |
| B3 signaling | Protobuf envelope + CBOR inner, ≤1200 B, ~10–100 messages per connection attempt | Sub-millisecond total. The bottleneck is the network and the NAT, never the parser. |
| B4 data plane | **Zero.** Fixed-layout binary framing per ADR-0001. | This is where the throughput requirement lives, and it is discharged by using no framework at all. |
| B5 local/diagnostics | JSON | Irrelevant; not on any hot path. |

**Where a rejected alternative was materially better:** FlatBuffers and Cap'n Proto are
genuinely faster and allocation-free on decode, and if TwinVPN ran a *serialized* data
plane they would be the right answer. It does not. Their advantage applies only to B4,
which uses no serialization framework, so the advantage evaluates to zero while their
security and determinism costs remain. This is the clearest case in the ADR of an option
whose headline strength is irrelevant to the actual workload.

The one place the layered choice pays a real cost is B1 message size versus a
CBOR-everywhere design: protobuf field tags plus length prefixes are marginally larger than
canonical CBOR for small messages. Measured impact is single-digit bytes per message,
which is far below the mobile radio wakeup cost that dominates (see ADR-0002).

## 10. Operational Implications

- **Two toolchains to run:** `protoc` with language plugins for B1/B3, and a CDDL validator
  plus hand-maintained mappers for B2. Both must run in CI on every PR.
- **Wire debugging** needs the `.proto` files to decode captures. A `twinvpn debug decode`
  subcommand that renders a captured envelope as JSON is a **required deliverable**, not a
  nice-to-have — without it, the loss of JSON's read-it-by-eye property becomes a support
  cost, and "insufficient diagnostics" is an explicit anti-requirement for this product.
- **Diagnostic bundles are JSON** so a user can inspect what they are sending before they
  send it. That transparency is worth the size cost for a privacy-sensitive product.
- **A schema registry** (versioned `.proto` + `.cddl` artifacts, published per release) is
  needed so a device can be told exactly which contract version a peer speaks. ADR-0014
  owns the version semantics; this ADR owns the requirement that the artifacts be published
  and immutable per release.
- **Fuzzing is a release gate** for both parsers, with corpora seeded from real captures.
- **Deterministic-encoding conformance vectors** must be published and cross-tested between
  the Go, Rust, Swift, and Kotlin implementations. A determinism bug that only shows up on
  one platform is exactly the bug this choice exists to prevent, so it must be tested for
  explicitly rather than assumed.

## 11. Decision

**Adopt the layered selection.**

| Boundary | Format | Normative rule |
|---|---|---|
| **B1 control plane** (C1/C2/C7) | **Protocol Buffers (proto3)**, length-delimited framing | All RPC and event bodies. Unknown fields preserved and forwarded. Depth limit 8, size limit 64 KiB, enforced before parse. |
| **B2 signed statements** | **Deterministic CBOR** (RFC 8949 §4.2.1 core deterministic encoding) inside a **COSE_Sign1** envelope (RFC 9052) | Carried as an opaque protobuf `bytes` field. Signature MUST be verified over received octets; implementations MUST NOT re-serialize. Non-canonical input MUST be rejected, not normalized. `crit` field set is mandatory and MUST be enforced. |
| **B3 ephemeral signaling** (C4) | **Protocol Buffers** envelope wrapping a **deterministic CBOR** signed inner payload | Envelope ≤ 1200 B, depth limit 4. Rendezvous forwards the payload as opaque octets and MUST NOT parse it. |
| **B4 data plane** (C5/C6) | **No serialization framework.** Fixed-layout binary framing defined by ADR-0001. | A serialization library MUST NOT appear in the packet path. Relay framing is a length + opaque-bytes header only. |
| **B5 local config, CLI, diagnostics** | **JSON** (UTF-8, RFC 8259) | Human-readable and diffable. Never a trust boundary; never signed in this form. |

Additional normative rules:

1. A signed statement MUST NOT be represented in more than one encoding anywhere in the
   system. There is exactly one byte representation of a `RevocationRecord`, and it is the
   one that was signed.
2. Integers on the wire MUST be explicitly sized. JSON at B5 MUST render 64-bit integers as
   strings, because several target ecosystems cannot represent them as JSON numbers, and
   silent precision loss on `net_seq` or `revocation_epoch` would be a critical, near-invisible bug.
3. Every parse failure MUST produce a specific reason code (`PROTO.UNPARSEABLE_ENVELOPE`,
   `PROTO.DEPTH_EXCEEDED`, `PROTO.SIZE_EXCEEDED`, `PROTO.NON_CANONICAL_CBOR`,
   `PROTO.UNKNOWN_CRITICAL_FIELD`) per **I6**. A generic "malformed message" is not acceptable.
4. Contract artifacts (`.proto`, `.cddl`) MUST be published immutably per release and must
   be the input to CI compatibility checks.

## 11.5 The signed network contract, and the B2 count (discharging networking.md A3)

`docs/networking.md` A3 is directed at this ADR by name and was previously undischarged: the
signed network contract — which [ADR-0010](ADR-0010-ipv4-ipv6-routing.md),
[ADR-0011](ADR-0011-dns-handling.md) and [ADR-0013](ADR-0013-multi-client-gateway-architecture.md)
all consume **offline** — was not among the B2 statement types, had no CDDL, no `crit` set, and no
atomicity rule. It is now a B2 statement, with these normative rules:

- **NC-1** The network contract is a **B2 signed statement**: deterministic CBOR inside COSE_Sign1,
  verified over received octets, never re-serialized before verification.
- **NC-2** A contract generation applies **atomically**. A device either installs the whole
  generation — addresses, routes, DNS fields — or none of it. There is no partial application, and
  a failure mid-apply reverts to the previous generation.
- **NC-3** Generations are identified by a **monotone `contract_seq`**. A device MUST reject a
  contract whose `contract_seq` is at or below its high-water mark (S-27), which is the
  anti-rollback rule for this document type.
- **NC-4** The `crit` set for the network contract is `{contract_seq, address_v4, address_v6,
  routes, dns}`. A device that does not understand a member of `crit` MUST reject the contract
  rather than apply it partially — this is the mechanism that stops a future field restriction from
  being silently ignored by an old device.

**A note on B2's size, and on §14 item 7.** §6 justified thin CBOR codegen partly on B2 being a
small set — "seven statement types". It is no longer seven: the ADRs written since have added
`IdentitySuccession`, `TunnelKeyBinding`, `OwnerTrustAnchor`, `OwnerDelegation`, `TrustEpochBundle`,
`RelayCapabilityToken`, `RelayEpochFloor`, the signed relay map, `LogHead`, and this contract,
bringing the real count to **seventeen**. §14's revisit trigger is ~20. The mitigation
("hand-written mappers are affordable because the set is small") is therefore close to expiring and
is restated honestly here rather than left resting on a stale number.

---

## 11.6 `PROTO` parse-failure reason codes

These are contributed into [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)'s
`PROTO` domain, which [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 assigns jointly
to ADR-0003 and ADR-0014: ADR-0014 owns version and capability conditions, this ADR owns parse and
encoding conditions. They are the oracle for proof test **P13** — a malformed input must produce
one of these, never a crash and never a silent accept.

| Code | Class | Severity | Terminal | User-actionable | Condition |
|---|---|---|---|---|---|
| `PROTO.UNPARSEABLE_ENVELOPE` | PERSISTENT | ERROR | no | no | The outer envelope did not decode |
| `PROTO.NON_CANONICAL_CBOR` | PERSISTENT | ERROR | no | no | A signed statement's encoding is not RFC 8949 §4.2.1 deterministic. **Rejected, never normalized** (§7) — normalizing would break verify-over-received-octets |
| `PROTO.DEPTH_EXCEEDED` | PERSISTENT | ERROR | no | no | Nesting depth exceeded the parser's configured limit |
| `PROTO.SIZE_EXCEEDED` | PERSISTENT | ERROR | no | no | The message exceeded its size cap |
| `PROTO.UNKNOWN_CRITICAL_FIELD` | PERSISTENT | ERROR | no | no | A field in the statement's `crit` set is not understood; the statement MUST be rejected rather than partially applied |

---

## 11.7 Fuzz conformance surface and parser inventory for P13 (discharging testing-strategy G-10)

[docs/testing-strategy.md](../testing-strategy.md) §4.1 recorded that **P13 had no owning
conformance surface**: this ADR specified canonical encoding and rejection semantics but named no
**parser inventory** and no fuzz surface, so the test rested on §2.3's corpora rather than on a
mechanism this ADR guarantees. That is the gap this section closes, in the shape the other nine
ADRs used. **PT-4 applies.**

**(a) The parser inventory — normative and closed.** Every entry point below decodes
attacker-reachable octets. **The list is closed: a new parser of untrusted input MUST be added
here in the same change that introduces it**, and the T1 check of (d) fails the build otherwise.
Each maps to the §2.12 fuzz target that must exist for it.

| # | Parser entry point | Input reachable from | Fuzz target (§2.12) |
|---|---|---|---|
| PI-1 | Outer envelope decoder | any peer, any relay, the control plane | `fz-control-decoder` |
| PI-2 | Tunnel packet/frame parser | any host that can send to the bound UDP socket | `fz-packet-parser` |
| PI-3 | Handshake message decoder | any host reaching the handshake port | `fz-handshake-state` |
| PI-4 | Signed-statement (deterministic CBOR) decoder | control plane, peer relay of trust documents | `fz-trust-document` |
| PI-5 | Network-contract decoder | the signed contract fetch | `fz-config-parser` |
| PI-6 | Relay frame decoder | any relay | `fz-relay-frame` |
| PI-7 | Trust/epoch bundle decoder | peers, control plane | `fz-bundle-parser` |
| PI-8 | Capability-token decoder | relays, peers | `fz-capability-token` |
| PI-9 | Attestation blob decoder | pairing peer | `fz-attestation-blob` |
| PI-10 | Pairing URI / invite decoder | a QR code or a pasted string — **user-supplied, and the only one an attacker delivers through the human** | `fz-uri-and-invite` |
| PI-11 | DNS response parser | the network | `fz-dns-response` |
| PI-12 | Control-message reordering/reassembly | control plane | `fz-control-reorder` |

**(b) The decode-outcome contract — what P13 asserts on.** Every parser in (a) MUST terminate in
exactly one of three **typed** outcomes, and the set is exhaustive:

1. **Accept**, with a decoded structure and — for signed statements — verification performed over
   the **received octets**, never over a re-encoding (§7).
2. **Reject**, with one of §11.6's `PROTO.*` codes. A bare error, an untyped exception, or a
   boolean false is **not** a reject; it is the "zero unclassified decode outcomes" failure.
3. **Reject-and-no-effect**, the same as (2) plus the assertion that **no state changed** — the
   partial-application defect `M-P13-5` injects.

**Rule PA-1.** There is no fourth outcome. A panic, an abort, a hang, an allocation proportional
to a declared length, or a silent accept is a defect at P1, regardless of perceived
exploitability — which is the same standard §6.5 **B-3** already applies to the fuzz fleet.

**(c) Guaranteed observables.** Each parser emits, per input: the outcome class of (b); the
`PROTO.*` code on reject; the parser id (`PI-*`), so a corpus finding is attributable to an entry
point rather than to "the decoder"; and, for PI-4, the digest of the octets verification ran over,
which is what makes `M-P13-2` (verify over a re-encoding) mechanically detectable rather than a
code-reading exercise.

**(d) Mechanical enforcement, at T1.** A build-time check asserts that (i) every symbol reachable
from an untrusted-input boundary appears in (a), and (ii) every row in (a) has a live fuzz target
in §2.12's set. An inventory that silently falls behind the code is the failure mode this whole
section exists to prevent, and it is exactly how P13 lost its surface the first time.

**(e) Known limit.** The inventory bounds *where* untrusted octets are parsed. It does not bound
what the accepted structures then reach — that is [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)'s
version and capability surface and §2.14's business, not this one's.

---

## 12. Why the Selected Option Won
1. **No single format was best at more than two of the five boundaries.** The boundaries
   have genuinely opposed requirements — determinism versus evolution tooling, zero-copy
   versus small parser, compactness versus readability. Forcing one format means choosing
   which boundary to do badly at, and the two candidates for "do badly" were signing
   (unacceptable — it is a trust boundary) and the data path (unacceptable — it is the
   throughput requirement).
2. **Deterministic encoding for signing is a hard requirement, and only CBOR supplies it as
   a normative spec.** Protobuf explicitly disclaims it; FlatBuffers and Cap'n Proto leave
   padding and layout unspecified; MessagePack has no spec at all; JSON has JCS but drags in
   number-representation hazards. Choosing anything else means writing a canonicalization
   profile ourselves, which is designing cryptographic packaging — against **I2**.
3. **The zero-copy formats' advantage evaluates to zero here.** Their selling point applies
   to a serialized high-rate data path. TwinVPN's high-rate path uses fixed binary framing
   with no framework. So FlatBuffers and Cap'n Proto would be paying their security and
   determinism costs to buy something the architecture does not need.
4. **Protobuf's evolution tooling is the best available and B1 is where evolution actually
   hurts.** Mixed-version fleets with year-old routers are the norm for this product;
   preserve-and-forward unknown fields and a strong `.proto` contract are worth a lot there,
   and cost nothing at the boundaries where CBOR wins.
5. **The hostile-input surface is minimized where it is actually hostile.** B3 is
   pre-authentication and reachable by anyone. Putting a pointer-arithmetic parser there
   would be the single worst decision available in this ADR.
6. **JSON stays exactly where a human is the consumer**, preserving the debuggability that
   directly serves **I6** without paying its size and precision costs on the wire.

## 13. Known Tradeoffs

| Tradeoff | Accepted because | Mitigation |
|---|---|---|
| Two wire formats and two toolchains | The boundaries genuinely differ; a single format would be worse at signing or at throughput | Sharp, documented boundary: *if it is signed, it is CBOR; otherwise it is protobuf*. Lint rule and code review checklist enforce it. |
| A protobuf message wrapping opaque CBOR is non-obvious | It is what makes verify-over-received-octets possible | Named consistently (`signed_payload`), documented in [docs/protocol.md](../protocol.md) §3, and the only way to construct one is a shared helper that both signs and wraps. |
| Losing JSON's read-by-eye property on the wire | Size and precision costs are paid on every mobile wakeup | `twinvpn debug decode` is a required deliverable; diagnostic bundles remain JSON. |
| Thin CBOR codegen ⇒ hand-written mappers for B2 | B2 has only seven statement types and changes rarely | CDDL schema + round-trip property tests + cross-language conformance vectors. |
| No zero-copy anywhere | The only place it would matter uses no framework | Revisit if a future feature puts structured data in the packet path (see §14). |
| Protobuf's proto3 optional/required weakness | Universal to the format | Explicit validation at every boundary, generated from the same `.proto` where possible. |
| Deterministic CBOR rejects rather than normalizes non-canonical input | Normalizing attacker input before verifying is a signature-bypass pattern | Documented; conformance vectors include non-canonical negatives. |

## 14. Revisit Conditions

Falsifiable triggers. Any one of these reopens this ADR.

1. **Protobuf gains a normative canonical encoding** specified at the same quality as
   RFC 8949 §4.2 and implemented consistently in Go, Rust, Swift, and Kotlin. Then B2 could
   collapse into B1 and one toolchain would disappear.
2. **Measured B1 control-plane bytes exceed 2 % of total device data volume** in production
   telemetry, or a p95 mobile wakeup is measured to spend more than 5 ms in encode/decode on
   the reference low-end device. Then a more compact or faster format for B1 is worth the churn.
3. **A structured, high-rate payload appears in the data path** — for example a multipath
   scheduler that must exchange per-packet metadata at line rate. That would make zero-copy
   relevant for the first time and would justify re-evaluating FlatBuffers for B4 *only*,
   with a mandatory-verifier rule.
4. **A CBOR parser CVE with memory-safety impact is found in two or more of our target
   language implementations within a 12-month window.** That would falsify the "smallest
   safe parser" premise and force a reassessment of B2/B3.
5. **Cross-language determinism conformance fails in production** — i.e. a signature
   produced on one platform fails verification on another due to encoding, despite the
   conformance vectors. That falsifies the core premise of the B2 choice and requires
   either a stricter profile or a different format.
6. **`protoc` codegen ceases to support a target platform** TwinVPN must ship on (a new
   mobile OS, a constrained router toolchain), making B1 tooling a blocker.
7. **A signed-statement schema grows past ~20 types or starts changing more than twice a
   year.** At that point CBOR's thin codegen becomes a real defect-source and the
   evolution-tooling argument may outweigh the determinism argument, pushing toward
   protobuf-with-an-explicit-canonicalization-profile — which would then require a formal
   security review under **I2**.
8. **The rendezvous service is ever required to inspect B3 payloads** (for example for
   abuse mitigation). That would break the opaque-forwarding premise and change the parser
   threat model materially.
