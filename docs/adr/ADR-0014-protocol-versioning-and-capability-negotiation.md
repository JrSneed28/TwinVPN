# ADR-0014: Protocol Versioning and Capability Negotiation

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** PROTOCOL
- **Related:** [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) (handshake, prologue, downgrade requirements D1–D6) · [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) (control-connection version lifecycle, §O-6) · [ADR-0003](ADR-0003-network-contract-schema-format.md) (encoding and serialization-layer schema evolution) · [ADR-0005](ADR-0005-relay-architecture.md) (relay capability names) · [ADR-0007](ADR-0007-device-identity-and-pairing.md) · [ADR-0009](ADR-0009-state-consistency.md) · [ADR-0010](ADR-0010-ipv4-ipv6-routing.md) · [ADR-0011](ADR-0011-dns-handling.md) · [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) · [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) · [ADR-0015](ADR-0015-observability-and-diagnostics.md) (reason-code taxonomy) · [docs/protocol.md](../protocol.md) §2, §10.1–§10.3, §10.6, §16, §17, §18 · [docs/architecture.md](../architecture.md) §2.5, §2.21, §3.3, §5, §9 · [docs/networking.md](../networking.md) §11 · [docs/reliability.md](../reliability.md) §4.3 · [docs/testing-strategy.md](../testing-strategy.md) §0, §2.5, §2.15, §2.18

This ADR owns **what a version number means, how two peers agree on one, what a `Capability`
is, how the negotiated set is made tamper-evident, and how versions and capabilities are
deprecated and removed**. It does **not** own the wire encoding or serialization-level schema
evolution — [ADR-0003](ADR-0003-network-contract-schema-format.md) decides those and this ADR
consumes them (the layer boundary is stated normatively in §11.6). It does not own the
handshake cryptography — [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)
does, and this ADR consumes its prologue interface rather than building a parallel one. It does
not own control-plane transport ([ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md))
or the update and release process beyond the S-23 interaction in §11.9.

## 1. Context

TwinVPN's founding defect list names **weak protocol lifecycle management** (R-04) as a
first-class failure. The observed symptoms in the predecessor product were not "the version
number was wrong"; they were: a client and a peer that both supported a feature failed to use
it, a fleet that could not be upgraded because nobody knew what was deployed, a rollback that
silently disabled leak protection, and connection failures reporting nothing more useful than a
numeric code.

Three separate things are commonly, and wrongly, called "the protocol version": the **encoding
contract** (which fields exist, what an old reader does with a field it has never seen — already
decided by [ADR-0003](ADR-0003-network-contract-schema-format.md)); the **peer protocol** (what
a `Device` must *do* on receipt: which migration rules, which relay framing, which in-session
messages); and the **control-plane API** (the RPC and event contract, fixed for the life of a
control connection — [docs/protocol.md](../protocol.md) §2,
[ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) §O-6). Conflating them produces
the two classic failures: an epoch bump for a purely additive field (churn nobody needed), or a
behaviour change smuggled in without a bump (a field appears, an old peer ignores it, and a
*tightening* becomes a no-op). §11.1 and §11.6 separate them; that tri-layer separation is the
single most reusable thing in this document.

The security context is sharper. `ConnectOffer`/`ConnectAnswer` traverse an **untrusted
rendezvous** ([docs/protocol.md](../protocol.md) §10.1) and are reachable pre-authentication by
anyone who can send a datagram. Version and capability advertisements are the *only* negotiated
values in the entire system —
[ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) deliberately fixes the
cipher suite so there is nothing else to downgrade — which makes them the **entire** downgrade
attack surface. Stripping `path_migration/1` to force reconnect storms, or `kill_switch_os/1` to
make a peer believe protection is unenforceable, are realistic attacks with real user harm.

Finally, `TwinNet`s update at wildly different rates; a router may lag a phone by a year
([ADR-0003](ADR-0003-network-contract-schema-format.md) §8). A mixed-version `TwinNet` must keep
working, and where it cannot it must say so **explicitly** rather than quietly losing a feature
(**I3**, **I6**, **P3**).

## 2. Requirements

| # | Requirement | Source |
|---|---|---|
| **R1** | Every wire contract MUST carry an explicit `ProtocolVersion`, and every `Session` establishment MUST negotiate a `Capability` set, with a defined compatibility window and a defined behaviour on unsupported-version. | **R-04** |
| **R2** | A `Device` MUST express a supported *range*; a `Tunnel` MUST negotiate exactly *one* version. | [docs/architecture.md](../architecture.md) §3.3 |
| **R3** | Selection MUST be a deterministic, total, symmetric function of the two advertisements, computable independently by both peers with **zero additional round trips**. | [docs/protocol.md](../protocol.md) §10.2 |
| **R4** | An empty intersection MUST produce a clean typed refusal (`PROTO.VERSION_UNSUPPORTED`) with no half-open state and no retry storm — never an undefined state. | [docs/testing-strategy.md](../testing-strategy.md) §0 A-07, §2.5, §2.15 |
| **R5** | An on-path adversary MUST NOT be able to force two peers that both support epoch N down to N-1, nor strip a capability both peers offer. Tampering MUST be *detectable by both peers*. | **I2**, ADR-0001 R6/D1–D6, **P11** |
| **R6** | A `Capability` MUST be declared from a **real platform probe**, never from a build-time constant. A device MUST NOT advertise what its OS will not let it do. | [docs/architecture.md](../architecture.md) §2.5, **R-20** |
| **R7** | The negotiated set MUST be per-`Session`, immutable for the life of the `Tunnel`, and unaffected by later advertisement changes. | [docs/architecture.md](../architecture.md) A-18, S-19 |
| **R8** | A mixed-version `TwinNet` MUST degrade **explicitly**: every capability shortfall that costs the user a feature produces a named `reason_code` and human-actionable text. | **I3**, **I6**, **P3**, [docs/networking.md](../networking.md) A7 |
| **R9** | The compatibility window, the deprecation window, and the minimum-supported-version bump procedure MUST be stated as concrete, evidence-gated numbers. | **R-04**, [docs/architecture.md](../architecture.md) §2.21 |
| **R10** | A rolling upgrade MUST NOT terminate a `Session`; an N-version skew guarantee MUST be stated concretely. | [docs/testing-strategy.md](../testing-strategy.md) §2.15 |
| **R11** | A device below the network's minimum supported version MUST fail with a named, actionable reason — never silently stop connecting. Rollback below it MUST be refused. | S-23, **R-22** |
| **R12** | Version and capability negotiation MUST NOT add a round trip, and MUST fit the 1200 B C4 datagram budget alongside candidates. | [docs/protocol.md](../protocol.md) §2 |
| **R13** | Every failure mode introduced here MUST contribute codes in the [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 namespace scheme. | **I6**, testing A-15 |

## 3. Constraints

- **C1** — `proto_version` is a `uint32` present on **every** control message and is *not*
  negotiated per message; it is fixed for the life of a connection
  ([docs/protocol.md](../protocol.md) §2). Any scheme that is not an unsigned integer is
  already excluded at the control plane.
- **C2** — [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) fixes the
  L-DATA suite (`Noise_IKpsk2` / X25519 / ChaCha20-Poly1305 / BLAKE2s). **The handshake is
  version-invariant in Phase 1.** Nothing this ADR negotiates selects cryptography. This is
  what makes pre-handshake negotiation safe at all; if it ceases to be true, §14 V7 fires.
- **C3** — The C4 datagram is capped at **1200 B** and carries the offer's candidates *and* its
  advertisement. The advertisement competes for that budget.
- **C4** — The rendezvous is an untrusted forwarder that MUST NOT parse the payload
  ([ADR-0003](ADR-0003-network-contract-schema-format.md) §11, B3).
- **C5** — **I5**: no established-tunnel code path may require a control-plane call. Negotiation
  therefore cannot be adjudicated by the coordination service.
- **C6** — **I8**: one writer per fact. Any persisted negotiation state needs exactly one
  authority and a row in [docs/architecture.md](../architecture.md) §5.
- **C7** — ADR-0001 D6: **no pre-authentication message may cause persistent state change**.
  The advertisement arrives pre-authentication, so nothing may be written from it.
- **C8** — `DEGRADED` is reserved for **quality** violations
  ([docs/reliability.md](../reliability.md) R6). A capability shortfall is not a quality
  violation and MUST NOT be expressed as one.

## 4. Considered Alternatives

Two axes are being decided, and each is decided explicitly.

### 4.1 Axis A — the versioning scheme

| ID | Alternative |
|---|---|
| **VA-1** | **Single monotonic integer epoch, one shared number space, a contiguous supported range per device per axis.** Every wire surface stamps `proto_version` from one counter; each of the three layers (§11.6) defines behaviour for every epoch value, so most bumps are semantic no-ops on two of three layers. |
| **VA-2** | **Semantic versioning** (`major.minor`), with major = incompatible and minor = additive-compatible, and compatibility defined as "same major, any minor". |
| **VA-3** | **Pure capability negotiation, no protocol version at all.** Feature flags only; compatibility is the intersection of feature sets. |
| **VA-4** | **Date-based versions** (`2026.08`), ordered lexically. |
| **VA-5** | **Three independent integer counters**, one per layer (`schema_rev`, `peer_proto`, `control_api`), each with its own range and its own deprecation clock. |

### 4.2 Axis B — where negotiation happens and how it is bound

| ID | Alternative |
|---|---|
| **VB-1** | **Advertise pre-handshake, bind BOTH FULL advertisements into the ADR-0001 Noise prologue, confirm in-session.** Offer/answer carry each peer's complete range and complete capability set; both peers derive the same prologue; `NegotiationConfirm` re-checks after the handshake. |
| **VB-2** | **Post-handshake only.** Establish the tunnel at a fixed bootstrap epoch, then negotiate inside the encrypted session. This is ADR-0001 D1 read literally. |
| **VB-3** | **Bind only the selected version and capability set** into the prologue (the naive reading of [docs/protocol.md](../protocol.md) §10.2). |
| **VB-4** | **No cryptographic binding.** Rely solely on the Rule-B detached signatures already required on `ConnectOffer`/`ConnectAnswer`. |
| **VB-5** | **Control-plane adjudication.** The coordination service knows every device's range and capability set (S-19, S-20) and tells each peer what to use. |

**VA-1 + VB-1 is the selected combination.**

## 5. Advantages of Each Alternative

**VA-1 — single monotonic integer epoch.** Satisfies C1 without translation. A total order
makes "highest mutually supported" a *unique* maximum, so the selection function needs **no
tie-breaking rule at all** — and a tie-break is exactly where an attacker looks for asymmetry.
Range intersection is two integer comparisons: trivially auditable, trivially fuzzable at a
hostile boundary. One number for operators, one ledger, one deprecation clock. Contiguity holds
because a release that changes one layer still defines the other layers' behaviour at the new
epoch as identical to the previous one, so no layer develops gaps.

**VA-2 — semantic versioning.** Universally understood, and a major bump *announces* a break.
Additive changes need not touch the compatibility boundary, and the major/minor split maps
naturally onto "must both understand" versus "nice to have". Rich tooling exists for range
expressions.

**VA-3 — pure capability negotiation.** The most honest model of what actually matters: peers
care what each can *do*, not what number each was assigned. It removes the "version says yes but
the feature is broken" mismatch class, degrades continuously with no cliff, and is the only
scheme with no deprecation clock — a feature simply stops being advertised.

**VA-4 — date-based versions.** Immediately communicates age, which is what support staff
actually want ("your router's build is from 2025-03"). Deprecation windows become arithmetic on
the version itself, and lexical ordering keeps it totally ordered.

**VA-5 — three independent counters.** Each clock advances only when its layer changes, so the
numbers carry real information: a `peer_proto` bump genuinely means peer behaviour changed. No
wasted increments and no "this epoch is a no-op here" footnote. Each layer gets a deprecation
window sized to its own churn rate — the control plane can move fast while the peer protocol
stays glacial.

**VB-1 — pre-handshake advertise, full-advertisement prologue binding, in-session confirm.**
Zero added round trips (R3, R12, and [docs/protocol.md](../protocol.md) §10.2's explicit
justification). The negotiated result can parameterise the handshake, keeping a future epoch's
options open. Tampering does not produce a wrong session — it produces **no** session, because
Noise mixes the prologue into the handshake hash before the AEAD tags are computed. It composes
with, rather than replaces, the Rule-B signatures already mandated on the offer and answer,
giving two independent detection layers plus the in-session confirmation as a third.

**VB-2 — post-handshake only.** The advertisement is confidential: no on-path observer or
rendezvous learns which OS features a device has — a genuine privacy and anti-fingerprinting
win. It satisfies ADR-0001 D1 with no interpretation required, makes mid-session renegotiation
structurally possible, and shrinks the pre-authentication parser surface to almost nothing.

**VB-3 — bind only the selection.** Smallest transcript input (a few dozen bytes), trivially
implemented, and it matches the most natural reading of "the selected version MUST be committed
into the handshake transcript".

**VB-4 — signatures only.** No new mechanism: it reuses [docs/protocol.md](../protocol.md) §3
Rule B verbatim, and verification over received octets is already mandated
([ADR-0003](ADR-0003-network-contract-schema-format.md) §7), so there is nothing to build and
nothing new to audit. A tampered advertisement is rejected *before* the handshake, which yields
the most precise possible diagnostic.

**VB-5 — control-plane adjudication.** One authority means one implementation of the selection
rule and therefore no cross-implementation divergence. The control plane can enforce fleet
policy centrally ("nobody below epoch 8"), roll a capability out gradually, and report the
distribution for free. It is what several commercial products do.

## 6. Disadvantages of Each Alternative

**VA-1.** A shared number space means most bumps change nothing at two of three layers, so the
number over-reports churn and a reader must consult the ledger to learn what moved. It carries
no semantic hint — 8 → 9 does not say whether the change was cosmetic or breaking — and it
couples release cadences: a fast-moving control plane drags the peer-protocol number upward.

**VA-2.** *Fatal against C1:* `proto_version` is a `uint32` on every envelope, so encoding
`major.minor` means either packing two fields into one integer (a bespoke convention ADR-0003
§11 rule 2 exists to prevent) or changing an already-decided wire contract. Worse, "same major,
any minor" is a **partial** order, so two peers can both be "compatible" while neither is
highest — reintroducing a tie-break where none is needed. SemVer's real value is communicating
intent to a human reading a changelog; here the consumer is a range-intersection function on
hostile input, and it wants a scalar.

**VA-3.** No total order ⇒ no unique maximum ⇒ an unavoidable tie-breaking rule, and a tie-break
in an attacker-reachable negotiation is precisely the asymmetry an adversary exploits. It also
cannot express a **floor**: "refuse anything older than X" is inexpressible in a flag set
without inventing a synthetic flag meaning "is at least version X" — a version number in a
costume. Every behaviour change becomes a new flag, so the registry grows without bound and
nothing can ever be removed. Deprecation has no clock and no lever. And it fails **R2**
outright: a `Device` supporting a *range* while a `Tunnel` negotiates *one* presupposes an
ordered scalar.

**VA-4.** Dates encode *when* a release was cut, not *what* it does; two releases branched from
the same tree can carry dates implying an ordering that does not hold. `20260827` fits a
`uint32`, but arithmetic on it is calendar arithmetic, and off-by-one around month boundaries is
a real defect source. A hotfix needs a sub-day component, and the scheme has grown a second
field. "Support the last three" becomes calendar arithmetic rather than subtraction.

**VA-5.** Three counters means three deprecation clocks, three fleet-distribution reports, three
CI compatibility matrices, and — the real cost — **three ways for a support conversation to go
wrong**, because "what version are you on" now has three answers and the user will read whichever
the UI shows. It also multiplies the combinations interoperability testing must cover
([docs/testing-strategy.md](../testing-strategy.md) §2.5's matrix is already version-pairs ×
transport × family × path). The information it buys — which layer moved — is free from a
published ledger keyed on one number.

**VB-1.** The advertisement is signed but **not encrypted**, so the rendezvous and any on-path
observer learn both peers' version ranges and capability sets: a real fingerprinting surface (OS
family, feature availability, whether a kill switch is enforceable). That is the strongest
argument against this option, and §7.4 states the exposure honestly. It also places a parser on
a pre-authentication path, requiring hard caps (N-10), and it requires a wording refinement to
ADR-0001 D1 (§11.10) — a cross-document cost.

**VB-2.** *Fatal on latency:* an extra round trip on every connection, on exactly the
high-latency mobile paths TwinVPN exists to fix, which [docs/protocol.md](../protocol.md) §10.2
rejects explicitly. Worse, it creates a bootstrap-version problem: the tunnel must be
established at some fixed epoch before negotiation, and that epoch can **never** be deprecated —
a permanent, immortal compatibility floor, which is the exact opposite of the lifecycle
management R-04 demands. It also forecloses ever letting the negotiated result parameterise the
handshake.

**VB-3.** **Cryptographically insufficient, and this is the crux of the ADR.** An attacker who
rewrites *both* advertisements consistently — lowering A's advertised maximum in transit to B
*and* B's in transit to A — makes both peers compute the same lowered selection, bind the same
selection, and complete the handshake. The downgrade succeeds undetected. Binding the selection
binds the *output*; the attack is on the *inputs*. §7.1 tabulates it.

**VB-4.** Signatures protect against the rendezvous and the network, but leave the binding
outside the handshake, so any future path carrying an advertisement without a Rule-B signature —
a LAN discovery shortcut, a resumption fast path — silently loses all protection. Defence that
depends on remembering to sign is defence that will eventually not be there. It also gives no
protection against two peers *computing* different selections from the same inputs, an
implementation-divergence bug that would silently produce mismatched behaviour on an established
tunnel.

**VB-5.** *Fatal against I5 and I1.* It puts the control plane in the critical path of every
connection, which **I5** forbids outright and which reintroduces the single-point-of-failure
defect **R-11** exists to eliminate. It also lets a compromised control plane force a downgrade
— a capability [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.4
explicitly denies it ("roll a device back to a weaker configuration") and which ADR-0001 D4
forbids by name ("a control-plane-supplied list MUST NOT be able to *narrow* it"). Rejected on
invariants, not on preference.

## 7. Security Implications

### 7.1 Why full-advertisement binding detects downgrade, and selection-binding does not

Both peers construct the prologue from **their own advertisement as sent** plus **the peer's
advertisement as received**. An attacker must make both peers' transcript inputs identical
while changing at least one of them — and it cannot alter what a peer knows it sent.

| # | Attack | VB-3 (bind selection only) | VB-1 (bind both full advertisements) |
|---|---|---|---|
| **T1** | Rewrite A's `v_max` 9 → 8 in transit to B only | B selects 8, A selects 9. Selections differ ⇒ handshake fails, but the failure is indistinguishable from a bug | A binds `A=[7,9]`, B binds `A=[7,8]`. Transcripts differ ⇒ **handshake fails**; the offer's Rule-B signature also fails, giving a precise cause |
| **T2** | Rewrite **both** maxima 9 → 8 consistently | Both compute selection = 8, both bind `8`. Transcripts match ⇒ **handshake succeeds at 8. Downgrade undetected.** | A binds `{A=[7,9] own, B=[7,8] recv}`; B binds `{A=[7,8] recv, B=[7,9] own}`. Transcripts differ ⇒ **handshake fails** |
| **T3** | Strip `path_migration/1` from both advertisements | Both compute the same reduced intersection and bind it. **Undetected.** | Same asymmetry as T2 ⇒ **handshake fails** |
| **T4** | Replay a stale advertisement from an earlier attempt | Selection may match by coincidence | `session_nonce` and `key_id` are inside each half ⇒ transcripts differ |
| **T5** | Rendezvous substitutes its own key or set | Rule-B signature fails first | Rule-B signature fails first; prologue binding is the backstop |

T2 and T3 are the whole argument. **Binding the negotiated result is not downgrade
resistance; binding the negotiation inputs is.**

### 7.2 Layered detection, and the diagnostic each layer yields

1. **Rule-B signature over the offer/answer** — catches rendezvous and network tampering
   *before* the handshake, with a precise, pre-authentication cause:
   `PROTO.NEGOTIATION_TAMPERED`.
2. **Noise prologue binding** — catches everything the signature layer misses, including a
   future unsigned path. Failure mode is a handshake that does not complete, i.e. **fail
   closed** (**I3**). Because the offer and answer signatures verified and the peer is a
   non-revoked `TrustedPeer`, a handshake failure at this point is attributable by elimination
   and MUST carry `PROTO.TRANSCRIPT_MISMATCH` alongside ADR-0001's
   `CRYPTO.HANDSHAKE_REJECTED`.
3. **In-session `NegotiationConfirm`** ([docs/protocol.md](../protocol.md) §16 message 35) —
   catches implementation divergence in the selection function, and satisfies ADR-0001 D2's
   requirement for a confirmed transcript inside the session. Mismatch ⇒ tear down the
   `Tunnel` with `PROTO.TRANSCRIPT_MISMATCH`.

### 7.3 What this does **not** protect against

- **A genuinely old peer.** If the peer really only supports epoch 7, there is no attack and no
  defence; the advertisement is truthful. The monotonic floor (§11.5) is the only signal, and
  only on a peer pair that previously reached a higher epoch.
- **First contact with a new peer.** No floor exists yet, so version selection on the first
  successful negotiation is trust-on-first-use *over versions*. This is materially less severe
  than TOFU over identity — an active attacker still cannot rewrite the advertisement (§7.1),
  so the only residual is a peer whose *own software* was rolled back before the pair ever
  negotiated.
- **A compromised peer device.** It can advertise anything, including a low range. The floor
  plus an explicit Owner action is the only recourse; the cryptographic layer cannot
  distinguish a compromised peer from an honest old one, and claiming otherwise would be false.
- **Advertisement confidentiality.** See §7.4.

### 7.4 The metadata cost, stated plainly

Under VB-1 the advertisement is signed but readable. The rendezvous and any on-path observer
learn: both peers' supported epoch ranges, and the full capability token list — which leaks OS
family, feature availability, and whether OS-level kill-switch enforcement is possible on that
device. This is a genuine privacy regression against VB-2 and it is accepted for the round trip
VB-2 would cost. Mitigations, all normative in §11.2: only tokens whose probe **succeeded** are
advertised (so the list is not a static platform fingerprint); tokens are canonically sorted
(so ordering leaks nothing); no free-form strings and no version banners are permitted in the
advertisement. `docs/threat-model.md` should record this exposure explicitly (§11.10).

### 7.5 Pre-authentication hardening

Per **C7** / ADR-0001 D6, the advertisement is parsed pre-authentication and **MUST NOT** cause
any persistent state change. The monotonic floor is written only after a completed handshake
*and* a matching `NegotiationConfirm`. Hard caps in §11.2 N-10 bound the parser. Range values
are validated (`v_min ≤ v_max ≤ current_epoch + 64`) so an absurd maximum cannot be used as a
probe oracle or an allocation lever.

## 8. Reliability Implications

- **Rolling upgrade does not break a `Session`.** Upgrading one peer restarts the process; that
  path is already `→ RECONNECTING` ([docs/reliability.md](../reliability.md) §2.4,
  process restart), from which T25 exits directly to a carrier state — there is no
  `RECONNECTING → CONNECTING` edge. `session_id` is durable and local (S-12) and survives; a **new `Tunnel`** is
  created with a freshly negotiated `(V, C)`. This discharges
  [docs/testing-strategy.md](../testing-strategy.md) §2.15's "no `Session` loss during rolling
  upgrade".
- **The three-epoch skew guarantee (§11.7) makes a mixed fleet a supported state, not a transient.** A
  `TwinNet` spanning three consecutive epochs is fully functional; the operator is never forced
  into a flag-day upgrade, which is the failure mode that produces "we can't update the router,
  so nobody can update".
- **Refusal is bounded, not a storm.** An empty intersection maps to
  `EV_VERSION_INCOMPATIBLE`, which [docs/reliability.md](../reliability.md) §4.3 already
  classifies **non-retryable**. §11.8 N-26 gives the retry floor so a permanently incompatible
  peer costs one diagnostic, not a loop.
- **Capability loss mid-session does not corrupt the negotiated set.** S-19's "governs for its
  lifetime" is preserved by rebuilding the `Tunnel` rather than mutating it (§11.4), which
  keeps the `Session`/`Tunnel`/`Path` decomposition intact
  ([docs/architecture.md](../architecture.md) §3.4).
- **Where this is weaker than the alternatives:** VB-2 could renegotiate in place on an
  established session without a new `Tunnel`. Under VB-1 a capability change always costs a
  re-handshake. Accepted: re-handshake is ~1 RTT with no plaintext window (ADR-0001 §7.2), and
  mid-session capability change is rare (an OS permission revocation), whereas the extra RTT
  VB-2 costs would be paid on *every* connection.

## 9. Performance Implications

| Cost | Magnitude | Assessment |
|---|---|---|
| Additional round trips | **Zero** | Folded into `ConnectOffer`/`ConnectAnswer` per [docs/protocol.md](../protocol.md) §10.2 |
| Range fields on the wire | 8 B per peer (`v_min`, `v_max` as varints) | Negligible |
| Capability tokens | ~20 B per token; typical probe result 10–14 tokens ⇒ **200–280 B**; hard cap **512 B / 32 tokens** | **The real cost.** It competes with candidates inside the 1200 B C4 datagram (C3) |
| `transcript_commitment` | 32 B per message | Negligible |
| Selection function | sort + intersect over n ≤ 32 | Sub-microsecond |
| Transcript hash | one SHA-256 over ≤ 1 KiB | ~2 µs; three orders of magnitude below the X25519 operations that follow |
| Platform probe | one-time at startup, TTL'd (§11.3) | Off the connection path entirely |

The datagram budget is the one place this design costs something real. It is survivable because
candidate exchange already supports **trickle** with a monotone `generation`
([docs/protocol.md](../protocol.md) §10.4): candidates can spill into subsequent datagrams,
whereas the advertisement cannot (it must be complete and atomic to be bound into the
prologue). §11.2 N-10 therefore gives the advertisement a fixed 512 B reservation and requires a
CI contract test that serialises the **entire current registry** and asserts it fits — so
registry growth fails the build rather than the field. §14 V2 is the falsifiable trigger if it
ever does not.

Caching a peer's capability set in `TrustedPeer` (S-05) is permitted for UI and pre-flight
prediction but **MUST NOT** be used to omit the advertisement, because the advertisement is
precisely what gets bound. A cached set is a hint; the wire is the contract.

## 10. Operational Implications

- **One published epoch ledger**, append-only, recording per epoch: allocation date, which of
  the three layers changed, a one-line description, and the introducing release. Without it,
  VA-1's headline weakness — an opaque number — becomes real.
- **The capability registry is a machine-readable artifact** (`capabilities.cddl` +
  `capabilities.json`), published immutably per release alongside the `.proto`/`.cddl` artifacts
  ([ADR-0003](ADR-0003-network-contract-schema-format.md) §11 rule 4) and diffed in CI as
  **append-only**, on the same discipline as the `reason_code` registry
  ([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2).
- **Deprecation is evidence-gated, not calendar-only.** The update service already reports fleet
  `ProtocolVersion`/`Capability` distribution ([docs/architecture.md](../architecture.md) §2.21,
  S-23); §11.7 turns that into the concrete gate.
- **`twinvpn debug negotiation <peer>` is a required deliverable**, rendering both half
  advertisements, the computed selection, the `negotiation_hash`, and the local floor. Without
  it a transcript mismatch is undiagnosable in the field — the same argument
  [ADR-0003](ADR-0003-network-contract-schema-format.md) §10 makes for `debug decode`.
- **Front-ends serve three epochs concurrently**, setting the window
  [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) §O-6 defers here and aligning it
  with the peer-protocol skew guarantee, so operators have one number rather than two.
- **Interoperability CI** ([docs/testing-strategy.md](../testing-strategy.md) §2.5) gains a
  concrete matrix: (N,N), (N,N-1), (N,N-2), (N,N-3 ⇒ must refuse cleanly), (N, MSPV),
  (N, below-MSPV ⇒ must refuse cleanly).

## 11. Decision

**Adopt VA-1 (single monotonic integer epoch, contiguous supported range per device) combined
with VB-1 (pre-handshake advertisement, full-advertisement Noise-prologue binding, in-session
confirmation).**

### 11.1 The three version axes

| Axis | Name | What it versions | Owner | Form | Negotiated | Independent? |
|---|---|---|---|---|---|---|
| **V-1** | **Wire / schema contract** | How bytes become values: field numbers, `.proto`/`.cddl` shape, unknown-field and `crit` handling | [ADR-0003](ADR-0003-network-contract-schema-format.md) | Immutable per-release artifact set + digest | **Not negotiated.** Compatibility is by construction (additive fields, preserve-and-forward) | Advances independently; an additive schema change needs **no** epoch bump (N-1) |
| **V-2** | **Peer protocol** | What a `Device` must *do* on C4/C5/C6: message set, migration rules, framing semantics | **This ADR** | `uint32` epoch | **Yes** — §11.2, bound into the ADR-0001 prologue | Yes, as a range |
| **V-3** | **Control-plane API** | The C1/C2/C7 RPC and event contract | [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) for behaviour; **this ADR** for numbering and window | Same `uint32` epoch, **same number space**, fixed for the life of a control connection | **Yes**, at connection setup (client offers, front-end accepts or `GOAWAY`) | Yes, as a range |

**One number space, three independent positions in it.** Every epoch value has defined
semantics on all three axes; a release that changes only V-3 still advances the epoch, and V-2's
semantics at the new epoch are *defined as identical to the previous epoch*. This keeps each
axis's supported set contiguous while giving operators, support staff, and telemetry a single
integer.

### 11.2 Normative rules — versioning and negotiation

**N-1.** A **`ProtocolEpoch`** is a `uint32`, strictly monotonically increasing, allocated by
the PROTOCOL owner and recorded in the epoch ledger (§10). An epoch bump is **REQUIRED** when
and only when a receiver's required behaviour changes on any axis. An additive schema change
that is compatible under [ADR-0003](ADR-0003-network-contract-schema-format.md) MUST NOT
trigger a bump.

**N-2.** Each `Device` declares, per axis, a **contiguous** supported range `[v_min, v_max]`
with `v_min ≤ v_max`. `v_min` is the device's **Minimum Supported Protocol Version (MSPV)** and
is the value carried as `min_supported` in [docs/protocol.md](../protocol.md) §10.2. The range
comes from the local build plus local policy only; a control-plane-supplied list MUST NOT be
able to narrow it (ADR-0001 D4). A removed epoch MUST be **un-negotiable in the build**, not
merely deprioritised (ADR-0001 D5).

**N-3.** A `Tunnel` negotiates exactly **one** epoch, immutable for its lifetime (R2, R7).

**N-4 — the selection function.** Both peers compute, independently and without an extra round
trip:

```
SELECT( (a_min, a_max, A_caps), (b_min, b_max, B_caps) ):
    lo = max(a_min, b_min)
    hi = min(a_max, b_max)
    if hi < lo:                       REFUSE  PROTO.VERSION_UNSUPPORTED
    V  = hi                                        # highest mutually supported
    C  = { t : t.name/t.major in A_caps AND t.name/t.major in B_caps }
         with each parameter reduced by its registry-declared rule
    C  = canonical_sort(C)  by (name ASC, major ASC)
    if V < local_floor(peer):         REFUSE  PROTO.DOWNGRADE_REFUSED
    return (V, C)
```

The function is **total, deterministic, and symmetric**. Because the epoch space is totally
ordered, `hi` is a unique maximum: **there is no tie-breaking rule, by construction.** Glare
(simultaneous mutual offers, resolved for `Session` identity by lower `key_id` per
[docs/protocol.md](../protocol.md) §10.1) does not affect selection, which depends only on the
two advertisements.

**N-5 — the wire exchange.**

```
  A (initiator)                  rendezvous (untrusted)            B (responder)
      |                                  |                               |
      |-- ConnectOffer{ session_nonce, proto_version=a_max,              |
      |     min_supported=a_min, capabilities[], candidates[],           |
      |     transcript_commitment=H_A }  ---->|---------------------->   |
      |                                  |                               |
      |   <---- ConnectAnswer{ session_nonce, selected_proto_version=V,  |
      |     min_supported=b_min, max_supported=b_max,   [NEW FIELD]      |
      |     capabilities[],            [NEW: B's FULL set]               |
      |     selected_capabilities=C, candidates[],                       |
      |     transcript_commitment=H_B } ------|-----------------------   |
      |                                                                  |
      |   both compute (V,C) = SELECT(...) and negotiation_hash          |
      |                                                                  |
      |== ADR-0001 Noise_IKpsk2 initiation, prologue bound ============> |
      |<= Noise response ============================================== |
      |                                                                  |
      |-- NegotiationConfirm{ negotiation_hash, V, C } (in-session) ---> |
      |<- NegotiationConfirm{ negotiation_hash, V, C } ----------------- |
```

**N-6 — transcript construction.** Encoding is deterministic CBOR per
[ADR-0003](ADR-0003-network-contract-schema-format.md) §11 (B2 profile).

```
HalfAdvertisement := { 1: session_nonce, 2: key_id, 3: role(0=init,1=resp),
                       4: v_min, 5: v_max, 6: capabilities (canonically sorted) }
Selection         := { 1: selected_version, 2: selected_capabilities (canonically sorted) }

H_X                = SHA-256( "TWINVPN-NEG-HALF-v1" || det_CBOR(HalfAdvertisement_X) )
negotiation_hash   = SHA-256( "TWINVPN-NEG-v1" || H_initiator || H_responder
                                                || det_CBOR(Selection) )
# negotiation_hash is CONTRIBUTED to the prologue owned by ADR-0001 S7.3.1:
# prologue = "TWINVPN-PROLOGUE-v1" || identity_binding_hash || negotiation_hash   (83 bytes)
```

`H_X` is exactly the `transcript_commitment` field already present in
[docs/protocol.md](../protocol.md) §10.1's offer and answer payloads. `prologue` is the
application-supplied prologue input of ADR-0001's handshake (protocol.md A2).

**N-7.** Each peer MUST construct `HalfAdvertisement` for **itself from what it sent** and for
**the peer from what it received**, verbatim, over the received octets
([ADR-0003](ADR-0003-network-contract-schema-format.md) §7). An implementation MUST NOT
re-serialize a peer's advertisement before hashing it.

**N-8.** `NegotiationConfirm` ([docs/protocol.md](../protocol.md) §16 message 35) MUST be the
first in-session message each peer sends and MUST carry `negotiation_hash`, `V`, and `C`. A
mismatch MUST tear down the `Tunnel` and emit `PROTO.TRANSCRIPT_MISMATCH` classified
`FATAL`/`CRITICAL`. This discharges ADR-0001 D1 (the binding result is confirmed inside the
established session) and D2 (a transcript hash covering the full negotiation is confirmed by
both peers).

**N-9.** No `Session` state, no floor, and no cached advertisement may be written from an offer
or answer before the handshake completes and `NegotiationConfirm` matches (ADR-0001 D6).

**N-10 — pre-authentication caps.** Per advertisement: ≤ **32** capability tokens; ≤ **512 B**
total for `capabilities[]`; token `name` ≤ 24 B; ≤ 8 parameters per token; ≤ 256 B of parameters
total; `v_min ≤ v_max ≤ current_epoch + 64`. Violation ⇒ drop, emit
`PROTO.MALFORMED_MESSAGE`, no state change, no answer. A CI contract test MUST serialise the
complete current registry and assert it fits the 512 B reservation.

### 11.3 Normative rules — capabilities

**N-11 — naming.** A capability token is `name/major` where `name` matches
`[a-z][a-z0-9_]{0,23}` (snake_case) and `major` is a decimal integer ≥ 1 with no leading zeros.
This matches the form already used by [docs/networking.md](../networking.md) A7
(`ipv6_underlay`, …) and [ADR-0005](ADR-0005-relay-architecture.md) §11 (`relay_udp`, …).

**N-12 — intersection.** A token is negotiated iff `(name, major)` appears in **both**
advertisements. Different majors of the same name are **distinct capabilities** and do not
intersect; a device MAY advertise several majors of one name. There is no implicit
"higher major implies lower".

**N-13 — parameters.** A parameterised capability declares, in the registry, a reduction rule
per parameter: `MIN`, `MAX`, `INTERSECT` (sets), or `EQUAL` (mismatch drops the token). Reduction
MUST NOT be role-dependent — "initiator wins" would be an asymmetric-authority downgrade lever.

**N-14 — real-probe rule (R6).** A `Capability` MUST be advertised only if the Platform Network
Adapter's probe ([docs/architecture.md](../architecture.md) §2.5) **observed** the ability in
this process, on this OS build, with the permissions currently granted. A build-time constant,
a compile flag, or an OS-version table MUST NOT be the sole basis. Where the ability cannot be
observed non-destructively, the probe MUST perform a rollback-guaranteed install-then-remove
and record the result — never infer it. The probe result is re-taken on: process start, OS
version change, application upgrade, permission-change notification, virtual-interface
recreation, and resume from suspend.

**N-15 — registry discipline (the anti-rot rule).** A capability exists **only** when a peer
must *do* something differently. Adding an optional field is not a capability — that case is
already covered by [ADR-0003](ADR-0003-network-contract-schema-format.md)'s additive-field
rules. A capability MUST NOT be introduced to obtain compatibility ADR-0003 already provides.

### 11.4 Per-`Session` immutability and mid-session capability loss

**N-16.** [docs/architecture.md](../architecture.md) **A-18 is CONFIRMED**: the negotiated
`(V, C)` is per-`Session`, is recorded on the `Tunnel`
([docs/architecture.md](../architecture.md) §3.3), and governs that `Tunnel` for its lifetime
regardless of any later advertisement change. **S-19 is CONFIRMED** unchanged. Rekey in place
does **not** renegotiate.

**N-17.** When a capability genuinely disappears mid-session (the OS revoked a permission, an
interface was destroyed, an entitlement lapsed):

1. The `Device` MUST stop using the capability immediately.
2. It MUST emit `PROTO.CAPABILITY_REVOKED_LOCAL` naming the token and the OS-level cause.
3. The negotiated set is **NOT mutated**. **Renegotiation requires a new `Tunnel`, never a
   mutated one.**
4. If the registry marks the token `session_critical: true` (the peer's correct behaviour
   depends on it), the `Device` MUST tear down the `Tunnel` and re-handshake. The `Session` and
   its `session_id` survive (S-12, [docs/architecture.md](../architecture.md) §3.4); the new
   `Tunnel` negotiates a fresh `(V, C)`.
5. If it is not `session_critical`, no `Tunnel` teardown occurs; the feature stops and the
   diagnostic stands. **No `ConnectionState` change** — per **C8**, a capability shortfall is
   not a quality violation and MUST NOT be reported as `DEGRADED`.
6. If **local policy requires** the lost capability, the outcome is a *policy* violation:
   protected traffic MUST NOT continue to flow on a tunnel that cannot honour the policy, so
   the disposition is `BLOCKED` under **I3** /
   [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) — never `DEGRADED`, never silent.

### 11.5 The monotonic floor (state row S-37)

**N-18.** Each `Device` persists, per `TrustedPeer`, a **negotiation floor**: the highest
`ProtocolEpoch` ever successfully negotiated with that peer, and the set of
`security_relevant` capability tokens ever successfully negotiated with that peer. An offer
strictly below the floor MUST be refused with `PROTO.DOWNGRADE_REFUSED`.

**N-19 — refinement of ADR-0001 D3.** D3 says the floor covers "the strongest `Capability` set
ever negotiated". A monotonic floor over the *whole* capability set is **overruled as written**:
capability sets are a partial order and a capability can legitimately vanish (an OS revokes a
permission), so a whole-set ratchet would permanently brick an honest device. The floor
therefore covers (a) the epoch, strictly, and (b) only tokens the registry marks
`security_relevant: true`. Losing a non-security capability is a legitimate, surfaced
degradation; losing a security-relevant one is refused. See §11.10.

**N-20.** Clearing or lowering a floor MUST require an **authenticated local management-plane
action by the `Owner`** (ADR-0001 D3), MUST name the peer, the recorded floor, and the offered
value, and MUST NOT be triggerable by the control plane or by any peer.

**New state-ownership row required in [docs/architecture.md](../architecture.md) §5:**

| # | Fact | Authoritative writer | Replicas | Consistency class | Durability | Conflict rule |
|---|---|---|---|---|---|---|
| **S-37** | Per-`TrustedPeer` negotiation floor (highest epoch + security-relevant capability set ever negotiated) | **The local `Device`** | None by construction — never transmitted, never replicated | `MONOTONIC` (MUST NOT decrease) | Durable on device; survives process death and reboot | Higher wins; a lower value is only accepted via an authenticated local `Owner` action (N-20). The control plane MUST NOT be able to write or lower it |

This is a **new persistent fact** and is deliberately *not* folded into S-05 (`TrustedPeer`,
class `LOCAL`): the monotonicity guarantee is the whole point and would be invisible inside a
`LOCAL` row.

### 11.6 The layer boundary with ADR-0003 (serialization) — normative

**N-21.** [ADR-0003](ADR-0003-network-contract-schema-format.md) owns the **serialization**
layer: canonical encoding, unknown-field behaviour (protobuf preserve-and-forward on unsigned
transport messages; reject-unknown-non-`crit` on signed statements), the `crit` set, and the
immutable per-release artifacts. This ADR owns the **semantic** layer: what a value *means* at
an epoch, whether two peers may talk at all, which optional behaviours are live for a `Tunnel`,
and the lifecycle of versions and capabilities.

**N-22.** ADR-0003's unknown-field rules are **never** overridden by an epoch. A peer at epoch N
receiving a field introduced at N+1 applies ADR-0003's rules — preserve-and-forward, or reject
if `crit` — **not** an ADR-0014 rule. There is no such thing as a version-gated field ignore,
and this ADR does not restate, narrow, or extend ADR-0003 §11's unknown-field policy.

**N-23.** Conversely (with N-15): a capability or an epoch bump MUST NOT be used to obtain
compatibility ADR-0003 already provides. The test is behavioural, not structural: *does a
conforming receiver have to act differently?*

### 11.7 Compatibility, deprecation, and the skew guarantee

**N-24 — the three-epoch skew guarantee.** Every release MUST support at least the current epoch and
the two preceding ones (`v_max - v_min ≥ 2`). Concretely: **a `TwinNet` whose devices span up to
three consecutive epochs (N, N-1, N-2) remains fully functional**, with per-pair feature sets
reduced to the intersection and every reduction surfaced (§11.8). Control-plane front-ends MUST
serve the same three epochs concurrently, which discharges
[ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) §O-6's "at least two adjacent"
and sets its rollout-window length: **≥ 30 days** between a front-end accepting epoch N and any
client being required to use it.

**N-25 — deprecation window.** An epoch enters `DEPRECATED` when superseded and may be removed
only when **all** of the following hold:

| Gate | Condition |
|---|---|
| **G1 — time** | ≥ **12 months** since the epoch that superseded it shipped |
| **G2 — evidence** | Fleet share of that epoch < **1%** for ≥ **30 consecutive days**, measured by the update service's fleet distribution report ([docs/architecture.md](../architecture.md) §2.21, S-23) |
| **G3 — warning** | A release that emits `PROTO.VERSION_DEPRECATED` on every negotiation selecting that epoch has been in the field ≥ **90 days** |
| **G4 — isolation** | The MSPV bump ships in a release that does **not** also change its own `v_min` on any other axis, so the bump is not itself a compatibility event |
| **G5 — removal** | The epoch is removed from the **build**, not merely deprioritised (ADR-0001 D5) |

**N-26 — reason-code deprecation window.** [docs/protocol.md](../protocol.md) §17.3 defers the
reason-code deprecation policy here. A code marked `DEPRECATED` per
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 rule 3 MUST continue to be accepted
for the full compatibility window — **three epochs or 12 months, whichever is longer** — before
moving to `RETIRED`. Retired identifiers are never reused (ADR-0015 rule 2).

### 11.8 Explicit degradation — what the user is told

**N-27.** Every capability present in the local advertisement but absent from the negotiated set
MUST produce **exactly one** `Diagnostic` per (`Session`, token, `Tunnel`) — loud once, never a
per-packet or per-attempt source. It MUST name the peer by its user-visible label, state the
lost behaviour in user terms, and state the next action.

| Absent token | What the user is told | `reason_code` |
|---|---|---|
| `path_migration/1` | "Moving between Wi-Fi and cellular will drop this connection to *Study PC*, which is running an older TwinVPN. Update *Study PC*." | `PROTO.CAPABILITY_MISSING` |
| `ipv6_underlay/1` | "*Study PC* cannot use IPv6, so this connection uses IPv4 only and may fall back to a relay more often." | `PROTO.CAPABILITY_MISSING` |
| `dns_split/1` | "Split DNS is unavailable with *Study PC*; the full-tunnel DNS policy is in force." | `PROTO.CAPABILITY_MISSING` |
| `kill_switch_os/1` (local) | "This device cannot enforce OS-level leak protection. Protected traffic is blocked." | `POLICY.KILLSWITCH.ENGAGED` + `PROTO.CAPABILITY_MISSING` |
| `per_app_routing/1`, policy requires it | "Per-app routing is required by policy but unavailable on this OS build. Traffic is blocked rather than sent unprotected." | `PROTO.CAPABILITY_REQUIRED_UNAVAILABLE` |

**N-28.** Silence is a defect. A negotiated set smaller than the local advertisement with no
`Diagnostic` is an **I6** violation and a P1 test failure
([docs/testing-strategy.md](../testing-strategy.md) §2.11).

### 11.9 Below-minimum devices and rollback (S-23 reconciliation)

**N-29.** **S-23 is CONFIRMED** unchanged: the released-version registry is `MONOTONIC` and
rollback below the minimum supported version MUST be refused. Refinement: "minimum supported"
means the MSPV recorded in the `TwinNet`'s currently-signed released-version registry entry, not
the local build's `v_min`.

**N-30.** A rollback below MSPV MUST be refused by the updater **at install time, before the old
binary runs**, with `PROTO.VERSION_UNSUPPORTED`. Refusing after the rollback would leave a
running binary that cannot connect and that may read state it does not understand
([docs/testing-strategy.md](../testing-strategy.md) §2.15, "Downgrade N → N-1").

**N-31.** A `Device` whose `v_max` is below a peer's `v_min` MUST:

1. refuse with `PROTO.VERSION_UNSUPPORTED`, naming **both ranges** and the required upgrade —
   never a bare numeric code (**I6**);
2. emit `EV_VERSION_INCOMPATIBLE` (non-retryable per
   [docs/reliability.md](../reliability.md) §4.3), yielding `NEGOTIATING → FAILED` — or
   under `FAIL_CLOSED` the **derived `TwinNet`-scope** state is `BLOCKED` (**I3**,
   `docs/reliability.md` §4.7 rule 1) while the per-`Session` state stays `FAILED`;
3. hold **no** half-open state and retain **no** resources after the refusal
   ([docs/testing-strategy.md](../testing-strategy.md) §2.5);
4. retry only on (a) explicit user action, (b) a successful self-update, or (c) a **6 h**
   floor — never a storm;
5. **keep the diagnostic visible** as the connection's standing state reason. Silently
   ceasing to connect is the defect **R-22** exists to eliminate.

**N-32 — the legitimate-rollback sharp edge.** A device rolled back *within* the supported
window (N → N-1, both ≥ MSPV) will be refused by peers whose S-37 floor records N. This is
correct and deliberate: the alternative is a remotely-triggerable downgrade. An authorised
rollback therefore MUST lower the rolling-back device's own floors (N-20), and the `Owner` MUST
be told, by peer name, that each affected peer also needs an explicit "accept downgrade for
*this device*" action. See §13 K-4.

### 11.10 Cross-document assumptions confirmed, refined, or overruled

| Obligation | Disposition | Where |
|---|---|---|
| **[docs/architecture.md](../architecture.md) A-18** — `Capability` negotiation is per-`Session`; the negotiated set governs that `Tunnel` for its lifetime regardless of later advertisement changes | **CONFIRMED**, unchanged | N-16, N-17 |
| **[docs/protocol.md](../protocol.md) A2** — the peer handshake accepts an application-supplied prologue/transcript input so the negotiated version + capability set can be bound into it | **CONFIRMED**, and sharpened: the prologue binds **both full advertisements**, not only the negotiated result (§7.1) | N-6, N-7 |
| **[docs/networking.md](../networking.md) A7** — negotiation can express `ipv6_underlay`, `dplpmtud`, `portmap`, `site_remap`, `per_app_routing` so a mixed-version `TwinNet` degrades explicitly | **CONFIRMED.** All five appear verbatim as token names in §11.11; explicit degradation is N-27/N-28 | §11.11 |
| **[docs/testing-strategy.md](../testing-strategy.md) A-07** — negotiation is integrity-protected so a downgrade attempt is detectable by both peers, and an unsupported version produces a clean typed refusal `PROTO.VERSION_UNSUPPORTED` | **CONFIRMED.** Detection by both peers: §7.1–§7.2. Clean typed refusal: N-31. **P11** oracle = §7.1 T1–T5; **P12** oracle = N-31 (1)–(5) | §7, N-31 |
| **[ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) D1** — negotiation MUST occur inside the established L-DATA session, never in cleartext before it | **REFINED.** As literally written it contradicts [docs/protocol.md](../protocol.md) §10.2/§10.3, which fold negotiation into the offer/answer to avoid a round trip. Adopted reading: *no negotiated result becomes authoritative until it is confirmed inside the established session* (N-8). **ADR-0001 §7.3 D1 must be reworded** accordingly | N-5, N-8 |
| **ADR-0001 D2** — a transcript hash covering the full negotiation confirmed by both peers; mismatch tears down the `Session` | **CONFIRMED.** Code renamed: `PROTO.DOWNGRADE_REFUSED` is not in any [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 domain (`SEC` does not exist) ⇒ `PROTO.TRANSCRIPT_MISMATCH`. **ADR-0001 §7.3 D2 must adopt that spelling** | N-8, §11.12 |
| **ADR-0001 D3** — monotonic floor over highest version *and strongest capability set* | **CONFIRMED for the version; NARROWED for capabilities** to `security_relevant` tokens only, because a whole-set ratchet bricks a device whose OS revokes a permission. **ADR-0001 §7.3 D3 must be narrowed** | N-18, N-19 |
| **ADR-0001 D4, D5, D6** | **CONFIRMED**, unchanged | N-2, N-9, N-10 |
| **[ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) §O-6** — dual-version rollout window length owned here | **CONFIRMED and set:** three concurrent epochs, ≥ 30-day window | N-24 |
| **[docs/architecture.md](../architecture.md) S-19, S-20, S-23** | **CONFIRMED** unchanged; **S-37 is new** and must be added | §11.5, N-29 |
| **[docs/protocol.md](../protocol.md) §17.3** — reason codes deprecated per ADR-0014's policy | **CONFIRMED and set** | N-26 |

**Required edits in other documents** (reported, not made — this ADR owns only its own file):

1. **[docs/architecture.md](../architecture.md) §3.3**, `ProtocolVersion` identity column reads
   "semantic version"; it must read **"monotonic integer epoch"** to match
   [docs/protocol.md](../protocol.md) §2's `uint32 proto_version` and N-1.
2. **[docs/architecture.md](../architecture.md) §5** must gain row **S-37** (§11.5).
3. **[docs/protocol.md](../protocol.md) §10.1/§10.2** — `ConnectAnswer` must additionally carry
   the responder's **`max_supported`** and its **full `capabilities[]`**, not only
   `selected_*`. Without both, the initiator cannot verify that the responder selected the
   highest mutually supported epoch, and the T2/T3 defence in §7.1 does not exist.
4. **[docs/protocol.md](../protocol.md) §10.3** — capability examples are kebab-case
   (`path-migration/1`); N-11 fixes snake_case, matching
   [docs/networking.md](../networking.md) A7 and
   [ADR-0005](ADR-0005-relay-architecture.md). Rename to `path_migration/1` etc.
5. **[docs/protocol.md](../protocol.md) §10.3** — "may cause `DEGRADED` entry after connection
   if a policy-required capability is absent" conflicts with
   [docs/reliability.md](../reliability.md) R6 (*quality* violations degrade, *policy*
   violations block). Per N-17(5)/(6) the outcome is no state change, or `BLOCKED`.
6. **Reason-code format.** [docs/protocol.md](../protocol.md) §17 and
   [ADR-0003](ADR-0003-network-contract-schema-format.md) §11 rule 3 use `DOMAIN.CONDITION`;
   [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 **owns the taxonomy** and uses
   `DOMAIN.SUBDOMAIN.CONDITION`, as do
   [docs/testing-strategy.md](../testing-strategy.md) A-07 and
   [ADR-0005](ADR-0005-relay-architecture.md). This ADR emits the dotted form. Aliases:
   `PROTO.VERSION_UNSUPPORTED` → `PROTO.VERSION_UNSUPPORTED`;
   `PROTO.VERSION_UNSUPPORTED` → `PROTO.VERSION_UNSUPPORTED`;
   `PROTO.TRANSCRIPT_MISMATCH` → `PROTO.TRANSCRIPT_MISMATCH`;
   `PROTO.VERSION_UNSUPPORTED` → `PROTO.VERSION_UNSUPPORTED`;
   `PROTO.NO_PATH_MIGRATION_PEER` → `PROTO.CAPABILITY_MISSING` with `capability` evidence.
7. **`docs/threat-model.md`** should record the advertisement metadata exposure of §7.4.

### 11.11 Initial capability registry

**Why `kill_switch_os/1` is parameterless (normative).** An earlier draft parameterised it with
`scope ∈ {v4, v6, dns}` under INTERSECT. That is withdrawn: a per-family `scope` makes a v4-only
kill switch *expressible*, *negotiable*, and — under INTERSECT — *contagious across the pair*,
which is exactly the posture [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-5 calls
**non-conforming rather than degraded** and [ADR-0010](ADR-0010-ipv4-ipv6-routing.md) §11.5 calls a
structural guarantee. Encoding it here would have re-introduced the family asymmetry **P9** exists
to forbid, in the one layer where neither owning ADR would look for it. Dual-family coverage is not
negotiable; a device that cannot deliver both families MUST NOT advertise the token at all.

Legend — **sec** = `security_relevant` (participates in the S-37 floor, N-19); **crit** =
`session_critical` (loss forces a new `Tunnel`, N-17(4)). Every row's owning ADR MUST confirm or
rename its tokens (§11.12 interface I-6).

| Token | Parameters (reduction) | Owning ADR / doc | sec | crit | Probe evidence required (N-14) | Absent ⇒ |
|---|---|---|---|---|---|---|
| `ipv6_underlay/1` | — | [ADR-0010](ADR-0010-ipv4-ipv6-routing.md), networking | no | no | bind a v6 socket and obtain a routable source address | No v6 candidates gathered; higher relay incidence |
| `dplpmtud/1` | `floor_mtu`(MAX), `ceiling_mtu`(MIN) | [ADR-0010](ADR-0010-ipv4-ipv6-routing.md) | no | no | emit a padded authenticated probe on the tunnel socket | MTU stays clamped at the 1280 B floor; throughput cost only |
| `portmap/1` | `protocols` ∈ {`pcp`,`nat_pmp`,`upnp_igd`} (INTERSECT) | [ADR-0004](ADR-0004-nat-traversal-strategy.md) | no | no | issue a real PCP/NAT-PMP request to the default gateway | Fewer server-reflexive candidates |
| `site_remap/1` | `max_prefixes`(MIN) | [ADR-0010](ADR-0010-ipv4-ipv6-routing.md), [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) | **yes** | no | policy-routing table writable + per-prefix translation programmable | Overlapping LAN prefixes cannot be disambiguated; the route is **refused**, not mis-delivered |
| `per_app_routing/1` | `selector` ∈ {`uid`,`pid`,`bundle_id`,`cgroup`} (INTERSECT) | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md), architecture §2.5 | **yes** | no | per-app VPN binding API present **and** entitlement granted | Split-by-app policy unenforceable; policy fails closed |
| `path_migration/1` | — | [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md), [ADR-0004](ADR-0004-nat-traversal-strategy.md) | **yes** | **yes** | tunnel engine supports endpoint rebinding in this build | Roaming drops the `Session` (**R-07** lost) |
| `multipath_probe/1` | `max_concurrent`(MIN) | [ADR-0004](ADR-0004-nat-traversal-strategy.md) | no | no | concurrent probe sockets available | Direct-path upgrade while `RELAYED` is slower (**R-12**) |
| `relay_udp/1` | — | [ADR-0005](ADR-0005-relay-architecture.md) | no | no | relay handshake completes over UDP | — |
| `relay_quic/1` | — | [ADR-0005](ADR-0005-relay-architecture.md) | no | no | relay handshake completes over QUIC | Loses the UDP:443 rung |
| `relay_tls/1` | — | [ADR-0005](ADR-0005-relay-architecture.md) | no | no | relay handshake completes over TCP/TLS | UDP-blocked networks lose the last rung (**R-18**) |
| `relay_standby/1` | `max_standby`(MIN) | [ADR-0005](ADR-0005-relay-architecture.md), [ADR-0006](ADR-0006-relay-discovery-and-failover.md) | no | no | a second relay flow can be held warm | Failover is cold; the **R-10** bound is not met |
| `relay_multiplex/1` | — | [ADR-0005](ADR-0005-relay-architecture.md) | no | no | multiple peer flows on one relay binding | One relay flow per peer pair |
| `exit_node/2` | `families` ∈ {`v4`,`v6`} (INTERSECT) | [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) | **yes** | no | forwarding **and** source translation programmable, per family | The family is not offered — never silently forwarded untranslated |
| `lan_gateway/1` | `max_prefixes`(MIN) | [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) | **yes** | no | forwarding + per-peer policy hooks installable | Subnet routes are not accepted (**R-17** diagnostics apply) |
| `gateway_multiclient/1` | `max_peers`(MIN) | [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) | no | no | per-peer state and accounting available | The **I7** gateway role is unavailable |
| `dns_split/1` | `max_domains`(MIN) | [ADR-0011](ADR-0011-dns-handling.md) | **yes** | no | per-domain resolver API present (NRPT / resolved / NE) | Split DNS unavailable; policy picks full or off — never system-resolver fallback (**R-14**) |
| `dns_full/1` | — | [ADR-0011](ADR-0011-dns-handling.md) | **yes** | no | global resolver override installable | Full-tunnel DNS unavailable |
| `kill_switch_os/1` | **none — parameterless, deliberately** | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) | **yes** | **yes** | install-then-remove a dual-family probe rule in the OS filter engine; both families or neither | **I3** unenforceable; the device MUST NOT claim protection it cannot deliver |
| `kill_switch_boot/1` | none | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6 | **yes** | no | verify the boot-time rule set is present before the agent starts | The boot window is unprotected; disclosed per platform, observable fleet-wide |
| `dns_scoped_api/1` | none | [ADR-0011](ADR-0011-dns-handling.md) §11.9 | **yes** | no | probe the platform split-DNS API (NRPT / `matchDomains` / per-link `resolved`) | Steering degrades to containment-only; `DNS.PLATFORM.*` diagnostic |
| `dns_dnssec_validate/1` | none | [ADR-0011](ADR-0011-dns-handling.md) | no | no | validate a known-good and known-bad zone | Validation not performed; stated, not silent |
| `dns_upstream_dot/1` | none | [ADR-0011](ADR-0011-dns-handling.md) | no | no | open a DoT connection to the configured upstream | Upstream is Do53 inside the overlay |
| `dns_config_dies_with_tunnel/1` | none | [ADR-0011](ADR-0011-dns-handling.md) §11.7 | **yes** | no | platform property: resolver configuration is scoped to the interface lifetime | Requires `HostResolverRestorePoint` (S-34) and a boot restore unit; this token is the discriminator ADR-0011 §11.7's table is built around |
| `relay_map_gossip/1` | none | [ADR-0006](ADR-0006-relay-discovery-and-failover.md) §11.9 | no | no | accept a peer-carried signed relay map | Relay map refresh requires the control plane |
| `kernel_datapath/1` | — | [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) | no | no | open the kernel WireGuard / WinTun-class device | Userspace throughput budget applies (**R-15**) |
| `rekey_in_place/1` | — | [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) | **yes** | **yes** | in-process | Listed so its absence is nameable; mandatory at every Phase 1 epoch |
| `psk_epoch/1` | — | [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.5, [ADR-0007](ADR-0007-device-identity-and-pairing.md) | **yes** | **yes** | in-process | The **R-13** revocation lever is unavailable ⇒ refuse |
| `diag_bundle/1` | — | [ADR-0015](ADR-0015-observability-and-diagnostics.md) | no | no | in-process | No **R-23** connectivity report obtainable from that peer |

### 11.12 Reason codes contributed to the `PROTO` namespace

Contributed to the machine-readable registry owned by
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2, in its
`DOMAIN.SUBDOMAIN.CONDITION` scheme.

| `reason_code` | class | severity | terminal | user_actionable | Meaning / declared `evidence_fields` |
|---|---|---|---|---|---|
| `PROTO.VERSION_UNSUPPORTED` | `PERSISTENT` | `ERROR` | true | true | Empty range intersection, or a peer below MSPV. `{local_min, local_max, peer_min, peer_max, required_epoch, peer_label}` |
| `PROTO.VERSION_DEPRECATED` | `POLICY` | `WARN` | false | true | The selected epoch is `DEPRECATED` (N-25 G3). `{selected_epoch, removal_after}` |
| `PROTO.DOWNGRADE_REFUSED` | `POLICY` | `ERROR` | true | true | The offer is below the S-37 floor. `{peer_label, recorded_floor, offered_epoch, lost_security_capabilities[]}` |
| `PROTO.TRANSCRIPT_MISMATCH` | `FATAL` | `CRITICAL` | true | false | `negotiation_hash` disagreement — **a security event, not a network error**. `{local_hash, peer_hash, phase}` |
| `PROTO.NEGOTIATION_TAMPERED` | `FATAL` | `CRITICAL` | true | false | Rule-B signature invalid over an advertisement. `{message_kind, signer_key_id}` |
| `PROTO.CAPABILITY_MISSING` | `POLICY` | `WARN` | false | true | Advertised locally, absent from the negotiated set. `{capability, peer_label, peer_epoch, required_epoch}` |
| `PROTO.CAPABILITY_REQUIRED_UNAVAILABLE` | `POLICY` | `ERROR` | true | true | Local policy requires a capability that is not negotiated ⇒ fail closed. `{capability, policy_id, policy_version}` |
| `PROTO.CAPABILITY_REVOKED_LOCAL` | `PERSISTENT` | `WARN` | false | true | The OS withdrew a capability mid-session (N-17). `{capability, os_cause}` |
| `PROTO.CAPABILITY_PARAM_INCOMPATIBLE` | `POLICY` | `WARN` | false | false | An `EQUAL`-reduction parameter mismatched; the token was dropped. `{capability, parameter, local, peer}` |
| `PROTO.MALFORMED_MESSAGE` | `TRANSIENT` | `WARN` | false | false | An advertisement exceeded an N-10 cap. `{cap_violated, observed, limit}` — shared with [ADR-0003](ADR-0003-network-contract-schema-format.md) |

`PROTO.VERSION_UNSUPPORTED` is spelled exactly as
[docs/testing-strategy.md](../testing-strategy.md) A-07 and
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 require.

### 11.13 Interfaces required from other ADRs

| # | Required of | Interface |
|---|---|---|
| **I-1** | [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) | **Satisfied by ADR-0001 §7.3.1.** The handshake accepts one 83-byte application-supplied prologue, mixed into the handshake hash before any key-derivation output is used, into which this ADR contributes `negotiation_hash` (N-6) alongside ADR-0007's `identity_binding_hash`; a prologue mismatch fails the handshake without producing session keys. This ADR does **not** define the prologue |
| **I-2** | [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) | Reword §7.3 **D1**, rename **D2**'s code, and narrow **D3** per §11.10 |
| **I-3** | [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) | Front-ends serve three concurrent epochs; a client offering an unserved epoch receives a typed `GOAWAY` carrying `PROTO.VERSION_UNSUPPORTED`, never a bare close |
| **I-4** | [ADR-0003](ADR-0003-network-contract-schema-format.md) | `capabilities.cddl` joins the immutable per-release artifact set and its CI diff is append-only |
| **I-5** | [docs/reliability.md](../reliability.md) §4.3 | SHOULD add `EV_CAPABILITY_LOST` as a distinct ADR-0014-sourced event so N-17(4) re-handshakes are attributable; without it, capability-driven re-handshake is indistinguishable from a generic reconnect in the transition log (**P10** telemetry, **A-02**) |
| **I-6** | ADR-0004/0005/0006/0010/0011/0012/0013/0015 | Each confirms or renames its rows in the §11.11 registry, including `sec`/`crit` flags and probe evidence |
| **I-7** | [docs/architecture.md](../architecture.md) | Add **S-37**; correct §3.3's `ProtocolVersion` identity to a monotonic integer epoch |
| **I-8** | [ADR-0009](ADR-0009-state-consistency.md) | Confirm S-37's `MONOTONIC` class and that no control-plane path can write it (**I8**, one writer) |

## 12. Why the Selected Option Won

1. **The constraint was already set.** `proto_version` is a `uint32` on every envelope
   ([docs/protocol.md](../protocol.md) §2) and the entity catalogue says a `Device` supports a
   *range* while a `Tunnel` negotiates exactly *one*
   ([docs/architecture.md](../architecture.md) §3.3). VA-1 satisfies both with no translation
   layer; VA-2 and VA-4 require bending an already-decided wire contract, and VA-3 fails R2
   outright.
2. **A total order eliminates the tie-break, and the tie-break is where the attack lives.**
   Highest-mutually-supported over integers has a unique answer. VA-3's partial order forces a
   tie-breaking rule into an attacker-reachable negotiation, which is precisely the asymmetry an
   adversary probes.
3. **Only VA-1 can express a floor.** "Refuse anything older than X" is the anti-rollback
   primitive (ADR-0001 D3, S-37) and it is inexpressible in a flag set without smuggling a
   version number in as a synthetic flag.
4. **VA-5's information is available for free.** Three counters buy the knowledge of which layer
   moved; a published ledger keyed on one number buys the same knowledge without three
   deprecation clocks, three fleet reports, and three answers to "what version are you on".
5. **Binding the negotiation *inputs* is the only thing that actually resists downgrade.**
   §7.1's T2/T3 show that VB-3 — the natural reading of the requirement — is defeated by a
   consistent double rewrite, while VB-1 is not, because a peer cannot be made to forget what it
   sent. This asymmetry is the technical core of the ADR and it is not obtainable any other way
   without a round trip.
6. **VB-2 is right on privacy and wrong on everything else.** It costs an RTT on every
   connection on exactly the mobile paths this product exists to fix, and it creates an
   immortal bootstrap epoch that can never be deprecated — a permanent lifecycle defect in the
   ADR whose whole purpose is lifecycle management. The metadata cost of VB-1 is recorded
   honestly in §7.4 rather than denied.
7. **VB-4 and VB-5 fail on structure, not on quality.** VB-4's protection depends on remembering
   to sign; VB-5 puts the control plane in the connection path, violating **I5** and handing a
   compromised control plane the downgrade lever ADR-0001 §7.4 explicitly denies it.
8. **Layer separation is what makes the whole thing tractable.** §11.6's N-21/N-22/N-23 mean the
   registry cannot rot into a flag per field, the epoch cannot be burned on cosmetic changes,
   and [ADR-0003](ADR-0003-network-contract-schema-format.md)'s unknown-field rules are never
   second-guessed at a different layer.

## 13. Known Tradeoffs

| # | Tradeoff | Accepted because | Mitigation |
|---|---|---|---|
| **K-1** | The advertisement is signed but readable by the rendezvous and any on-path observer — a real fingerprinting surface | The alternative (VB-2) costs an RTT on every connection and creates an immortal bootstrap epoch | Only probe-verified tokens are advertised, so the list is not a static platform fingerprint; canonical sort; no free-form strings. Recorded in `docs/threat-model.md` (§11.10 item 7) |
| **K-2** | A shared epoch counter over-reports churn: most bumps are no-ops on two of three layers | One number for operators, support, and telemetry beats three | The published epoch ledger (§10) states exactly what moved at each epoch |
| **K-3** | The advertisement consumes 200–512 B of a 1200 B datagram, competing with candidates | Candidates trickle across datagrams; the advertisement cannot, because it must be atomic to be bound | 512 B reservation, 32-token cap, and a CI test that serialises the whole registry (N-10). §14 V2 is the trigger |
| **K-4** | A legitimate rollback within the window is refused by peers holding a higher S-37 floor | The alternative is a remotely-triggerable downgrade | The refusal names the peer, the floor, and the offered epoch, and the `Owner` gets an explicit per-peer "accept downgrade" action (N-32) |
| **K-5** | A mid-session capability loss costs a full re-handshake rather than an in-place renegotiation | Preserves S-19 and the `Session`/`Tunnel`/`Path` decomposition; ~1 RTT with no plaintext window | Only `session_critical` tokens force it; the `Session` and `session_id` survive |
| **K-6** | Version selection on first contact is trust-on-first-use over versions (no floor exists yet) | An active attacker still cannot rewrite the advertisement (§7.1), so the residual is narrow | §7.3 states it explicitly; the floor closes it from the second negotiation onward |
| **K-7** | The real-probe rule (N-14) makes startup slower and requires destructive-looking probes (install-then-remove firewall rules) | A device that advertises what its OS will not permit is the exact defect **R-20** names | Probes are cached with a TTL and re-taken only on the six listed triggers (N-14) |
| **K-8** | Three epochs of concurrent support means three code paths in every version-sensitive behaviour | A narrower window forces flag-day upgrades, which routers cannot do | Interoperability CI covers every pair in the window (§10); §14 V1/V9 are the triggers to widen or narrow |
| **K-9** | Two documents must change wording for this ADR to be coherent (ADR-0001 D1/D2/D3; protocol.md `ConnectAnswer`) | The contradiction is real and pre-existing; hiding it would leave the T2/T3 defence undeliverable | All required edits enumerated in §11.10, none made here |

## 14. Revisit Conditions

Any one of these reopens this ADR.

- **V1.** More than **5%** of connection attempts across the fleet in any 30-day window fail with
  `PROTO.VERSION_UNSUPPORTED` ⇒ the three-epoch window (N-24) is too narrow for real update
  behaviour, or the deprecation gates in N-25 are firing too early.
- **V2.** A shipping platform's real probe result serialises to more than **512 B** of
  `capabilities[]` ⇒ the token encoding must change. Candidate replacements (registry indices,
  or a digest plus a pull) both cost forward compatibility or **I5**, so this is a genuine
  redesign, not a tuning knob.
- **V3.** The registry exceeds **64** tokens, or more than **8** tokens are added in any
  12-month window ⇒ the flat-namespace intersection model should be re-evaluated against
  grouped capability profiles, and N-15's anti-rot rule is not holding.
- **V4.** Two shipped implementations are observed computing different `SELECT` outputs from
  identical advertisements ⇒ N-4 is under-specified; published conformance vectors become a
  release gate before the next epoch, on the model of
  [ADR-0003](ADR-0003-network-contract-schema-format.md) §10's determinism vectors.
- **V5.** Any shipped client is found advertising a capability from a build-time constant rather
  than a probe — detectable at [docs/testing-strategy.md](../testing-strategy.md) §2.18 when a
  nightly target's probe disagrees with its advertisement ⇒ N-14 needs mechanical enforcement
  (the advertisement API must take a probe receipt, not a boolean).
- **V6.** `PROTO.DOWNGRADE_REFUSED` fires more than **1 per 10 000** sessions with no attacker
  present — i.e. driven by legitimate rollbacks ⇒ the strict floor's operational cost exceeds
  its security value and the ratchet needs a bounded grace policy.
- **V7.** [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) adopts runtime
  crypto agility (for example a selectable hybrid post-quantum suite, its own §14 V-conditions)
  ⇒ **C2 dies**: the version axis would then select cryptography, negotiation placement must be
  reopened, and VB-2's confidentiality argument becomes much stronger.
- **V8.** The rendezvous is ever required to read the advertisement (for abuse mitigation, per
  [ADR-0003](ADR-0003-network-contract-schema-format.md) §14 item 8) ⇒ the opaque-forwarding
  and metadata-exposure analysis of §7.4 changes materially.
- **V9.** Fleet telemetry shows more than **1%** of `TwinNet`s spanning more than three
  consecutive epochs at steady state ⇒ the three-epoch skew guarantee does not match how users actually
  update, and N-24 must widen.
- **V10.** A capability is found to need renegotiation mid-`Tunnel` more than once per 1000
  session-hours in the field ⇒ N-16's per-`Tunnel` immutability is costing more re-handshakes
  than it is worth, and architecture.md A-18 should be revisited jointly.
