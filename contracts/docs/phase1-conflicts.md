# Phase 1 conflicts discovered while implementing the contracts

**Status: all conflicts resolved.** Each was referred to architecture review and
each has now been dispositioned by an **amendment to the owning Phase 1
document**, dated 2026-08-27 and carrying its rationale. Nothing was resolved by
inventing an architecture, and nothing was resolved by silently editing a
contract to match a document it disagreed with.

Where a Phase 2 contract requirement conflicted with a Phase 1 ADR, the ADR won
and the conflict is recorded. Where two Phase 1 documents conflict with each
other, the more specific and later decision was followed, the conflict is
recorded, and — where it is not already flagged by an ADR — it is left open.

Legend: **CF-n** conflict, **OQ-n** open question.

---

## CF-1 — Contract package path

| | |
|---|---|
| **Phase 2 objective** | Create `packages/contracts` |
| **Phase 1** | [ADR-0018](../../docs/adr/ADR-0018-shared-core-and-build-architecture.md) §11.12 fixes the repository layout: `/contracts/` is the single source, `/contracts/gen/{rust,swift,kotlin,csharp}/` the committed output |
| **Resolution** | **Phase 1 followed.** The package is at `/contracts`, not `packages/contracts` |
| **Why it matters** | §11.12 is a layout with three siblings that reference it — `/core`, `/shells/*`, `/build` — and the codegen rule ("`/contracts` is the single source; `/contracts/gen/**` is committed and CI re-generates and diffs it") is written against that path. Moving it would have made the ADR's own text wrong |
| **Status** | **Closed.** No architecture action needed |

---

## CF-2 — TypeScript, Go and C bindings

| | |
|---|---|
| **Phase 2 objective** | Generate Rust, Swift, Kotlin; "also generate TypeScript **if Phase 1 assigns TypeScript** to control-plane, management, test tooling, or other first-wave components" |
| **Phase 1, source A** | [ADR-0003](../../docs/adr/ADR-0003-network-contract-schema-format.md) **R8**: "Cross-language tooling MUST cover at minimum **Go, Rust, Swift, Kotlin, C, and TypeScript**" |
| **Phase 1, source B** | [ADR-0018](../../docs/adr/ADR-0018-shared-core-and-build-architecture.md) §11.12: `/contracts/gen/{rust,swift,kotlin,**csharp**}/`. §11.3 selects **Rust** for the core; §11.9's shells are Swift, Kotlin, Rust and **C#**. Go and C appear nowhere. §12 item 9: "C# for the shells is **four languages**" |
| **Resolution** | **Rust, Swift, Kotlin and C# generated. TypeScript, Go and C not generated.** |
| **Reasoning** | R8 is a *requirement on the format's tooling ecosystem* — a criterion for choosing protobuf over CBOR-everywhere — written before the implementation architecture existed. §11.12 is the *implementation decision*, is later, is more specific, and names each target's consumer. No Phase 1 component is assigned to TypeScript, Go or C. Generating an unassigned binding creates a permanent CI, review and maintenance obligation for a consumer that does not exist |
| **Note** | **C# is generated although the objective does not list it**, because ADR-0018 §11.12 requires it for the Windows WinUI shell. The objective's rule — "do not introduce an implementation language simply because the original template used it" — cuts the same way in reverse: the binding set follows Phase 1 |
| **Status** | **RESOLVED 2026-08-27.** [ADR-0003 §2.1](../../docs/adr/ADR-0003-network-contract-schema-format.md) added: R8 is recorded as a *selection criterion on the format's ecosystem*, not a generation manifest, with a table naming each generated binding's real consumer. R8's substance is unchanged — protobuf was selected partly because its tooling reaches all six languages, and that reach is what makes adding a fifth binding a decision rather than a migration |

### A measured constraint on any future JS/TS binding

[ADR-0003](../../docs/adr/ADR-0003-network-contract-schema-format.md) §11 B1
requires unknown fields to be **preserved and forwarded**. The contract tests
measured this: the Go runtime preserves them; **protobufjs does not**. Any
language chosen for a component that *forwards* a message it does not fully
understand — the coordination service, the rendezvous, a relay carrying an opaque
`CALL` — must use a runtime with preserve-and-forward. Not a Phase 2 blocker,
since no Phase 1 component is assigned to a JS runtime; recorded so a future
proposal is evaluated against the fact.

---

## CF-3 — The `TVPN-*` error family scheme

| | |
|---|---|
| **Phase 2 objective** | "Define stable error families such as `TVPN-AUTH`, `TVPN-PAIR`, `TVPN-NAT`, `TVPN-RELAY`, `TVPN-TUNNEL`, `TVPN-ROUTE`, `TVPN-DNS`, **`TVPN-IPV4`**, **`TVPN-IPV6`**, `TVPN-POLICY`, `TVPN-PLATFORM`, `TVPN-PROTOCOL`, `TVPN-CONTROL`, `TVPN-UPDATE`, `TVPN-INTERNAL`" |
| **Phase 1** | [ADR-0015](../../docs/adr/ADR-0015-observability-and-diagnostics.md) §11.2 owns the taxonomy: format `DOMAIN.CONDITION` or `DOMAIN.SUBDOMAIN.CONDITION`, uppercase, dot-separated, ASCII, ≤64 B, **two or three segments**, with a **closed set of sixteen domains** admitted by rule |
| **Resolution** | **Phase 1's taxonomy implemented. The `TVPN-` prefix and the family list are not.** |
| **Status** | **RESOLVED 2026-08-27.** [ADR-0015 §11.2](../../docs/adr/ADR-0015-observability-and-diagnostics.md) now records the `TVPN-*` scheme as an explicitly **rejected alternative**, with the three reasons below, so it is closed rather than re-proposed. The Phase 1 taxonomy stands unchanged |

**Why the Phase 1 scheme was kept.** Three of its properties are load-bearing and
the `TVPN-*` scheme has none of them:

1. **Forward compatibility is by `DOMAIN` prefix.** A receiver that meets an
   unknown code degrades on its first segment. A flat `TVPN-X` namespace has no
   prefix to degrade on.
2. **The domain set is closed by an admission rule**: a new top-level domain is
   admissible only when no existing domain is a correct owner, *because prefix
   degradation would otherwise produce an actively wrong diagnosis rather than a
   merely vague one*. ADR-0015 works the example: a local-agent failure spelled
   `CONTROL.*` would make an older client render *"the coordination service is
   unreachable — check your internet connection"* when the truth is *"the local
   service is not running"* — **opposite diagnoses with opposite next actions**.
3. **Every domain names exactly one owning document**, so a code has one author.

**Per-family mapping.** Every requested family is expressible; three are not
domains for stated reasons.

| Requested | Phase 1 | Note |
|---|---|---|
| `TVPN-AUTH` | `AUTH` | direct |
| `TVPN-PAIR` | `AUTH.PAIRING_*` | Pairing is an identity condition. A separate domain would split identity across two prefixes and make prefix degradation choose between them |
| `TVPN-NAT` | `NAT` | direct |
| `TVPN-RELAY` | `RELAY` | direct |
| `TVPN-TUNNEL` | `CRYPTO` + `NET.SESSION.*` / `NET.PATH.*` | "Tunnel" spans two owners: handshake and key state belong to ADR-0001, path and session lifecycle to reliability.md |
| `TVPN-ROUTE` | `ROUTE` | direct |
| `TVPN-DNS` | `DNS` | direct |
| **`TVPN-IPV4` / `TVPN-IPV6`** | **refused as domains**; family is an **evidence field** | See below |
| `TVPN-POLICY` | `POLICY` | direct |
| `TVPN-PLATFORM` | `PLATFORM` | direct |
| `TVPN-PROTOCOL` | `PROTO` | direct |
| `TVPN-CONTROL` | `CONTROL` | direct |
| `TVPN-UPDATE` | `UPDATE` | direct |
| `TVPN-INTERNAL` | `INTERNAL` | direct |
| — | `CRYPTO`, `NET`, `RESOURCE`, `MGMT`, `STORE` | five Phase 1 domains the objective did not list |

**Why per-family domains are refused, specifically.** Making the address family a
*namespace* rather than an *evidence field* creates exactly the asymmetry the
corpus forbids by name.
[ADR-0014](../../docs/adr/ADR-0014-protocol-versioning-and-capability-negotiation.md)
§11.11 rejects a per-family `scope` parameter on `kill_switch_os/1` in these
terms: it would make a v4-only kill switch *expressible, negotiable and — under
INTERSECT — contagious across the pair*, "re-introducing the family asymmetry
**P9** exists to forbid, **in the one layer where neither owning ADR would look
for it**". A `TVPN-IPV4` / `TVPN-IPV6` split does the same thing to the
diagnostic layer: it makes "we have a v4 story and a v6 story" *sayable*, when
[ADR-0010](../../docs/adr/ADR-0010-ipv4-ipv6-routing.md) R1's whole design is
that there is one story covering both. Family is therefore carried as
`Evidence.family_value` on codes where it matters — and it matters on many.

**Every registered code has documented semantics.** 201 codes across all sixteen
domains, each with class, severity, terminality, actionability, remediation
class, scope, doc anchor, declared evidence fields, owning document and a
one-line condition:
[`registry/reason_codes.json`](../registry/reason_codes.json). The objective's
requirement — "do not recreate PairVPN-style unexplained errors such as
Error 110, Local3-57, err=35" — is discharged structurally: a code with no
registry entry fails [`tests/test_registries.py`](../tests/test_registries.py),
and a user-actionable code with no `next_action_key` fails too.

---

## CF-4 — `ErrorEnvelope` and "user-facing summary or safe message"

| | |
|---|---|
| **Phase 2 objective** | `ErrorEnvelope` should include a "user-facing summary key **or safe message**" |
| **Phase 1** | [ADR-0015](../../docs/adr/ADR-0015-observability-and-diagnostics.md) §11.2 rule 5 and [ADR-0018](../../docs/adr/ADR-0018-shared-core-and-build-architecture.md) F-4: a carrier **MUST NOT** add a localized `summary`, `message` or `title` field |
| **Resolution** | **`summary_key` and `next_action_key` only. No message string.** |
| **Reasoning** | A text field on the wire would place a **second text authority outside the registry**, defeating rule 4 ("the code is the contract; the human text is not"), breaching ADR-0018 CB-4 (the core owns no user-visible string), and breaching ADR-0017 MI-15 (no rendered human text on the wire). It would also be a place for an attacker-influenced string to reach a UI |
| **Status** | **Closed.** The objective's "summary key **or** safe message" permits the key form |

There is also no top-level `ErrorEnvelope` named in Phase 1 — the corpus has
`Diagnostic` (ADR-0015 §11.3) and the ABI's `{reason_code, evidence, resolved}`
(ADR-0018 F-4). `ErrorEnvelope` here is the **wire form of both**, with the field
set of the former and the `resolved` attribute block of the latter. It carries no
field either lacks.

---

## CF-5 — `ProtocolVersion` as a semantic version

| | |
|---|---|
| **Phase 1, source A** | [docs/architecture.md](../../docs/architecture.md) §3.3: `ProtocolVersion` identity is "**semantic version** — *derived*" |
| **Phase 1, source B** | [ADR-0014](../../docs/adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) N-1: a `uint32` **monotonic integer epoch**. §11.10 required-edit 1 explicitly says architecture.md §3.3 "must read **monotonic integer epoch**" |
| **Resolution** | **ADR-0014 followed.** `uint32` epoch |
| **Status** | **RESOLVED 2026-08-27.** Corrected in [architecture.md §3.3](../../docs/architecture.md). **Correction to an earlier claim in this register:** it previously said none of ADR-0014 §11.10's seven edits had been applied. On verification, **five of the seven were already applied** in `docs/` — only edit 1 (this one) and edit 7 (threat-model) were outstanding. Both are now done |

### The other six edits ADR-0014 §11.10 requires and that remain unapplied

| # | Document | Required edit | This contract |
|---|---|---|---|
| 1 | architecture.md §3.3 | `ProtocolVersion` identity must read **monotonic integer epoch** | **APPLIED 2026-08-27.** Was the one genuinely outstanding edit |
| 2 | architecture.md §5 | add row **S-37** | Already applied |
| 3 | protocol.md §10.1/§10.2 | `ConnectAnswer` must carry the responder's **`max_supported`** and **full `capabilities[]`** | **Implemented.** Without both, the T2/T3 downgrade defence does not exist |
| 4 | protocol.md §10.3 | capability examples are kebab-case; N-11 fixes snake_case | **Already applied** — protocol.md §10.3 uses `path_migration/1` etc. |
| 5 | protocol.md §10.3 | a policy-required capability shortfall is `BLOCKED`, not `DEGRADED` | **Already applied** in protocol.md §10.3 |
| 6 | reason-code format | ADR-0015 owns the taxonomy and permits three segments | **Already applied** — protocol.md §17 cites ADR-0015 §11.2's form |
| 7 | threat-model.md | record the advertisement metadata exposure of ADR-0014 §7.4 | **Not a contract change.** Documented in [trust-boundaries.md](trust-boundaries.md) §4 |

All seven edits are now applied. The source documents and the frozen contracts
agree.

---

## CF-6 — `dns_config_dies_with_tunnel/1` violates ADR-0014 N-11

| | |
|---|---|
| **Rule** | [ADR-0014](../../docs/adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) N-11: a capability name matches `[a-z][a-z0-9_]{0,23}` — **at most 24 characters** |
| **Observed** | The token [ADR-0011](../../docs/adr/ADR-0011-dns-handling.md) §11.7 defines, and which **ADR-0014 §11.11 itself lists verbatim in its own registry table**, is `dns_config_dies_with_tunnel` — **27 characters** |
| **Resolution** | **RESOLVED 2026-08-27 by option 1**: [ADR-0014 N-11](../../docs/adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) amended from `{0,23}` to `{0,31}` — at most 32 characters. The token keeps its Phase 1 spelling |
| **Why not just rename it** | Renaming a token that two ADRs name by hand would be silently replacing a Phase 1 decision. The token is also `security_relevant`, so it participates in the S-37 monotonic floor, where a rename is a **compatibility event**, not an editorial change |
| **Status** | **RESOLVED.** The waiver has been **removed** from `capabilities.json` and from the test — a stale waiver would suppress a real future violation. `capabilities.cddl` and the test regex now carry the 32-character bound, and the test asserts the waiver is gone |

**Why option 1 over renaming.** The token is `security_relevant`, so it
participates in the **S-37 monotonic floor**: renaming it is a *compatibility
event* that would refuse connections against any peer whose floor recorded the
old spelling — not an editorial change. Relaxing the bound costs at most 8 bytes
per over-long token against the 512 B advertisement reservation, which the N-10
CI test already asserts the whole registry fits. **N-10's 32-token and 512 B caps
are unchanged** and remain the binding limits.

---

## CF-7 — Relay reservation as a control-plane command

| | |
|---|---|
| **Phase 2 objective** | Define `RequestRelay` and `ReleaseRelay` among the control-plane commands |
| **Phase 1** | [docs/protocol.md](../../docs/protocol.md) §16 row 21 is **withdrawn**; §11.1 places the reservation directly with the `Relay` on C6, keyed by `pair_tag` |
| **Resolution** | **Modelled as `BIND`/`BOUND` on the device↔relay leg** ([`relay.proto`](../proto/twinvpn/v1/relay.proto) `RelayBinding`), not as control-plane commands |
| **Reasoning** | §11.1, verbatim: "Routing reservations through coordination would put the control plane in the data path and **break I5**." The former `peer_key_id` field was removed because it "would have told the relay which two devices are talking, defeating **A11**" |
| **Status** | **Closed.** Documented in [contract-matrix.md](contract-matrix.md) §3.1 |

The same reasoning relocates `BeginConnection`, `ExchangeCandidates`,
`ResumeSession`, `EndSession`, `UpdatePeerPermissions`, `UpdateRoutePolicy`,
`UpdateDNSPolicy` and `ReportConnectionHealth`. Full table in
[contract-matrix.md](contract-matrix.md) §3.1.

---

## CF-8 — `abi_*` on a wire: ADR-0018 VR-2 versus S-46

| | |
|---|---|
| **Source A** | [ADR-0018](../../docs/adr/ADR-0018-shared-core-and-build-architecture.md) **VR-2**: "`abi_*` MUST NOT appear on **any wire**... A message carrying an `abi_*` value on the wire **is a defect**" |
| **Source B** | **S-46** (same ADR, §11.17): `CoreBuildIdentity` — whose declared field set **includes `abi_major` and `abi_minor`** — is such that "every diagnostic bundle embeds it; **telemetry holds a lossy replica**" |
| **The tension** | Telemetry is channel **C7**, which is a wire. So S-46 places on a wire a record VR-2 says must not appear on one |
| **Resolution** | **Conservative, and the tension is referred rather than decided.** `CoreBuildIdentity` is defined in [`diagnostics.proto`](../proto/twinvpn/v1/diagnostics.proto) with its full S-46 field set, marked **local and diagnostic-bundle only**, and appears as the body of **no** C1/C2/C4/C5/C6 message. An emitter targeting Tier-2 aggregate telemetry MUST omit the `abi_*` fields |
| **Reading that reconciles them** | VR-2's concern is that an `abi_*` value never be used as a **compatibility decision** on a wire — it is an in-process shell↔core concern. S-46's replica is **diagnostic provenance**. Both hold if `abi_*` is never a gate |
| **Status** | **RESOLVED 2026-08-27.** [ADR-0018 VR-2](../../docs/adr/ADR-0018-shared-core-and-build-architecture.md) reworded from "MUST NOT appear on any wire" to "MUST NOT be used as a **compatibility input** outside one process", with four normative consequences: `abi_*` MAY appear in a Tier-1 bundle and in `CoreBuildIdentity`; MUST NOT appear in any C1/C2/C4/C5/C6 message; **MUST be omitted from Tier-2 aggregate telemetry**; and no receiver may branch on a received value |

---

## CF-9 — B2 statement count approaching the ADR-0003 revisit trigger

Not a conflict; a **tripwire that this contract moves closer to firing**.

[ADR-0003](../../docs/adr/ADR-0003-network-contract-schema-format.md) §6
justified thin CBOR codegen on B2 being small — "seven statement types". §11.5
corrects the real count to **seventeen** and states plainly that §14 revisit
trigger 7 fires at **~20**, so "the mitigation is close to expiring and is
restated honestly here rather than left resting on a stale number".

[`cddl/signed_statements.cddl`](../cddl/twinvpn/v1/signed_statements.cddl)
implements exactly those seventeen and states the count in the file. **Three
slots remain** before ADR-0003 must be reopened.

**RESOLVED 2026-08-27 by making the trigger mechanical.** A number restated in
prose goes stale again — which is exactly how the count drifted from seven to
seventeen unnoticed. [`tests/test_registries.py`](../tests/test_registries.py)
now parses the CDDL's `signed-statement` union and asserts the count: an
eighteenth statement emits a NOTE, and a **twentieth fails the build** until
ADR-0003 is reopened. The whole point of a falsifiable revisit condition is that
something notices when it fires.

---

## CF-10 — Proto3 implicit presence versus "no defaulting"

**Discovered by the contract tests, not by review.**

| | |
|---|---|
| **Phase 1** | [docs/protocol.md](../../docs/protocol.md) §13.3: "an explicit per-family grant/deny, **with no defaulting**: an absent field is a denial, not a permission." §13.4: `block_fallback` is deny-shaped — `true` is honoured, **`false` is a *grant*** |
| **The problem** | Under proto3 **implicit presence** a bare `bool` cannot express "no defaulting": absent and `false` are one wire state. For a *grant*-shaped field that is merely unprovable. For a **deny-shaped** field it is unsafe — an omitted `block_fallback_v6` silently authors the **permissive** value, which is a DNS leak authored by omission |
| **How it surfaced** | The cross-implementation test found two runtimes encoding one logical `ExitNodeGrant` differently, because protobufjs emits an explicit zero where the Go runtime omits the field. Investigating *why they could differ* exposed that the schema could not distinguish "denied" from "not considered" |
| **Resolution** | **Thirteen fields given proto3 explicit presence (`optional`)**, changing no field name, no field number and no Phase 1 semantics: `ExitNode.supports_default_v4/v6`, `ExitNodeGrant.granted_default_v4/v6`, `LanAccessGrant.granted`, `LanAccessRule.allow`, `PeerPermission.allow`, `DNSPolicy.block_fallback_v4/v6`, `DNSPolicy.servers_declared_v4/v6`, `RoutePolicy.default_route_v4/v6` |
| **Status** | **Closed by construction.** Asserted in [`tests/test_semantics.py`](../tests/test_semantics.py). No ADR change needed — this implements a Phase 1 requirement that the obvious encoding would have quietly failed |

A related case, handled the same way: `DNSPolicy.servers_v4/v6` are repeated
fields where **an empty list is a meaningful value** ("block this family") and
must be distinguishable from absence — §13.4 says the schema must **forbid
expressing** "v4 configured, v6 left to the OS". Proto3 cannot distinguish an
empty repeated field from an absent one, so explicit `servers_declared_v4/v6`
presence bits carry the distinction, and a policy with either bit unset is
**malformed**, not "v6 unconfigured".

---

## OQ-1 — Which `SessionEvent` bodies belong in a Tier-2 aggregate

`SessionEvent` bodies are Tier-0 local, and may enter a Tier-1 bundle by explicit
user act. [ADR-0015](../../docs/adr/ADR-0015-observability-and-diagnostics.md)
§11.1 defines the Tier-2 shape as
`{reason_code, outcome, address_family, nat_class, protocol_version,
platform_class, day_bucket}` — but does not enumerate which *events* contribute.
`NAT.DIRECT_ESTABLISHED` and `NAT.DIRECT_UPGRADED` look like natural Tier-2
contributors (they are the success outcomes ADR-0004 §11.6 added precisely so
success is assertable), but that is an inference, not a Phase 1 statement.

**Not a blocker:** the contracts define the events and their classification; the
Tier-2 projection is an emitter policy, not a schema. **Referred to ADR-0015's
owner.**

---

## OQ-2 — Local management interface contracts

[ADR-0017](../../docs/adr/ADR-0017-local-management-interface.md) defines the
local management interface and MI-20/MI-21 keep its catalogue **derived from the
core command set** rather than a second contract. Whether the MI transport
schema belongs in this package or beside ADR-0017 is not stated in Phase 1.

**Excluded from this phase.** It is not in the objective's scope list, and
ADR-0018 §11.16 (b) requires it to carry "**the same command set** the core
exposes over the ABI — one contract, two carriages, **never two contracts**", so
defining an MI schema here would risk creating the second contract that rule
forbids. **Referred to ADR-0017's owner** for the first implementation wave.

---

## Summary

| ID | Severity | Status | Owner |
|---|---|---|---|
| CF-1 path | none | closed | — |
| CF-2 binding set | low | **resolved** | ADR-0003 / ADR-0018 |
| CF-3 `TVPN-*` families | **medium** | **resolved** | ADR-0015 |
| CF-4 error text field | none | closed | — |
| CF-5 `ProtocolVersion` form + 2 unapplied edits | **medium** | **resolved** | architecture.md, protocol.md, threat-model.md |
| CF-6 capability name length | low | **resolved** | ADR-0011 / ADR-0014 |
| CF-7 relay reservation | none | closed | — |
| CF-8 `abi_*` on a wire | low | **resolved** | ADR-0018 |
| CF-9 B2 count near trigger | low | **resolved** — now a build tripwire at 20 | ADR-0003 |
| CF-10 implicit presence | none | closed by construction | — |
| OQ-1 Tier-2 projection | low | open question | ADR-0015 |
| OQ-2 MI contracts | low | open question | ADR-0017 |

**All conflicts are resolved and no conflict blocks the contract freeze.** Each
was dispositioned by amending the owning Phase 1 document rather than by bending
a contract to match a document it disagreed with, and each amendment carries its
date and its reasoning in situ.

Two open questions remain, and neither blocks: **OQ-1** (which `SessionEvent`
bodies feed a Tier-2 aggregate) is an emitter policy, not a schema; **OQ-2**
(local management interface contracts) is deliberately out of this phase's scope
because ADR-0018 §11.16 (b) requires the MI catalogue to stay *derived* from the
core command set, and defining an MI schema here would risk creating the second
contract that rule forbids.

### Amendments made to Phase 1 documents

| Document | Section | Change |
|---|---|---|
| [ADR-0003](../../docs/adr/ADR-0003-network-contract-schema-format.md) | new **§2.1** | R8 recorded as a tooling-selection criterion, not a generation manifest; binding set and consumers tabulated; the measured protobufjs preserve-and-forward constraint recorded |
| [ADR-0014](../../docs/adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) | **N-11** | capability name bound `{0,23}` → `{0,31}`; N-10's caps unchanged |
| [ADR-0015](../../docs/adr/ADR-0015-observability-and-diagnostics.md) | **§11.2** | `TVPN-*` recorded as a rejected alternative with three reasons |
| [ADR-0018](../../docs/adr/ADR-0018-shared-core-and-build-architecture.md) | **VR-2** | reworded from "any wire" to "compatibility input outside one process", with four normative consequences |
| [architecture.md](../../docs/architecture.md) | **§3.3** | `ProtocolVersion` identity: "semantic version" → **monotonic integer epoch** |
| [threat-model.md](../../docs/threat-model.md) | **§5** | new row **TM-33**, negotiation-advertisement fingerprinting |
