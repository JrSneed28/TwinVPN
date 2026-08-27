# Versioning and capability negotiation

Implements [ADR-0014](../../docs/adr/ADR-0014-protocol-versioning-and-capability-negotiation.md)
and the layer boundary it draws with
[ADR-0003](../../docs/adr/ADR-0003-network-contract-schema-format.md).

---

## 1. The version numbers, kept separate

Conflating these is a named defect class
([ADR-0018](../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
§11.12). Six numbers exist; **one of them is negotiated**.

| # | Number | Versions | Form | Compared between | Negotiated? |
|---|---|---|---|---|---|
| **V-1** | schema contract | `.proto` / `.cddl` shape, field numbers, unknown-field and `crit` handling | **immutable artifact set + digest** | nobody — compatibility is by construction | **No** |
| **V-2** | peer protocol | what a device must *do* on C4/C5/C6 | `uint32` `ProtocolEpoch` | peer ↔ peer | **Yes**, per `Tunnel`, immutable for its life |
| **V-3** | control-plane API | the C1/C2/C7 contract | **the same `uint32`, same number space** | device ↔ control plane | **Yes**, fixed for the life of a connection |
| **V-A** | `core_version` | the shared core's own release | SemVer | humans, support, telemetry | No |
| **V-B** | `abi_major`/`abi_minor` | the `twinvpn.h` C ABI | two `uint32` | a shell and a core **in one process** | No — **and never on any wire** |
| **V-C** | app/installer version | the shipped package | store/installer form | the update service | No |

**One number space, three independent positions in it.** Every epoch value has
defined semantics on all three of V-1/V-2/V-3; a release that changes only V-3
still advances the epoch, and V-2's semantics at the new epoch are *defined as
identical to the previous one*. That keeps each axis's supported set contiguous
while giving operators, support staff and telemetry **a single integer**.

The alternative — three counters — was rejected for a specific reason: it means
three deprecation clocks, three fleet-distribution reports, three CI matrices,
and, decisively, **three ways for a support conversation to go wrong**, because
*"what version are you on"* would have three answers and the user will read
whichever the UI shows.

### What appears in this contract set

- `ProtocolVersion { v_max, v_min }` — a device's contiguous supported range.
  `v_min` is the **MSPV**. It comes from the local build plus local policy only;
  **a control-plane-supplied list MUST NOT be able to narrow it**
  ([ADR-0001](../../docs/adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) D4).
- `NegotiatedProtocolVersion { epoch }` — the single epoch a `Tunnel` negotiated.
- `SchemaDescriptor { namespace, schema_digest, reason_registry_version }` — V-1
  as a **content identity, not a version**, and explicitly **not** a
  compatibility gate.
- `CoreBuildIdentity` — V-A, V-B, V-C together, **local and diagnostic-bundle
  only**. The VR-2/S-46 tension this raised is resolved; see
  [phase1-conflicts.md](phase1-conflicts.md) CF-8.

`abi_major` and `abi_minor` **MUST NOT be a compatibility input outside one
process** (ADR-0018 VR-2, as clarified 2026-08-27). Concretely: they MAY appear
in a Tier-1 diagnostic bundle and in `CoreBuildIdentity`; they MUST NOT appear in
any C1/C2/C4/C5/C6 message; they MUST be **omitted from Tier-2 aggregate
telemetry**; and no receiver may branch on a received value. They are absent from
every wire message in this package.

---

## 2. When the epoch bumps — and when it must not

> **N-1.** An epoch bump is **REQUIRED** when and only when a receiver's required
> behaviour changes on any axis. **An additive schema change that is compatible
> under ADR-0003 MUST NOT trigger a bump.**

> **N-23.** Conversely, a capability or an epoch bump **MUST NOT** be used to
> obtain compatibility ADR-0003 already provides.

The test is **behavioural, not structural**: *does a conforming receiver have to
act differently?*

This is what keeps the two layers from eating each other. Without N-1, the epoch
would advance on cosmetic changes and stop meaning anything; without N-23, the
capability registry would rot into a flag per field.

[`tests/test_compatibility.py`](../tests/test_compatibility.py) asserts both
directions: the breaking detector **fires** on nine forbidden changes, and does
**not** fire on four additive ones.

---

## 3. Compatibility rules

### Unknown fields — asymmetric on purpose

| Boundary | Rule |
|---|---|
| **Unsigned transport messages** (B1, B3) | **Preserved and forwarded.** An old coordination service must be able to relay a message containing a new field without corrupting it — TwinVPN devices update on wildly different schedules, and a router may lag a phone by a year |
| **Signed statements** (B2) | **Rejected** if unknown and not in `crit`. A preserved-but-unverified field is a place to **smuggle data past a policy check** |

[ADR-0014](../../docs/adr/ADR-0014-protocol-versioning-and-capability-negotiation.md)
N-22: ADR-0003's unknown-field rules are **never overridden by an epoch**. There
is no such thing as a version-gated field ignore.

**Measured constraint.** The contract tests verify preserve-and-forward against
the Go runtime, which has it, and record that **protobufjs does not**. Any
language chosen for a component that *forwards* a message it does not fully
understand must use a runtime with preserve-and-forward. No Phase 1 component is
assigned to a JS runtime, so this is a constraint on future proposals rather than
a present gap.

### Unknown enum values

Preserved as their numeric value for forwarding; interpreted as the
`_UNSPECIFIED` sentinel by a reader that does not know them. Every enum in this
package has exactly one zero value and it ends in `_UNSPECIFIED`, asserted by
[`tests/test_schema_structure.py`](../tests/test_schema_structure.py).

This is why **`reason_code` is a string and never an enum**: prefix degradation
and unknown-code passthrough both require the receiver to hold the unrecognised
code's *text*, and a protobuf enum preserves an unknown value only as an integer,
which discards the `DOMAIN`.

### Field reservation, removal, rename, deprecation

| Change | Rule |
|---|---|
| Removing a field | **Reserve the number AND the name.** Both, always |
| Reusing a removed number | **Never.** Old bytes on the wire would be silently reinterpreted |
| Reusing a removed name | **Never.** JSON encodings and generated accessors would silently rebind |
| Renaming a field | A breaking change (JSON name). Add a new field, deprecate the old |
| Changing a field's meaning | **Prohibited.** Add a new field |
| Deprecating | Mark `[deprecated = true]`, keep it accepted for the full window, then reserve |
| Enum value removal | Reserve the number and name |
| Changing an enum number | **Prohibited.** Every stored transition record and every `ErrorEnvelope.state_from` would silently rebind |

### Rolling upgrades and the skew guarantee

**N-24 — three-epoch skew.** Every release supports the current epoch and the two
preceding (`v_max - v_min >= 2`). A TwinNet spanning three consecutive epochs is
**fully functional**, with per-pair feature sets reduced to the intersection and
**every reduction surfaced**.

This makes a mixed fleet a *supported state, not a transient*. The operator is
never forced into a flag day — which is the failure mode that produces *"we
can't update the router, so nobody can update"*.

Control-plane front-ends serve the same three epochs concurrently, with **≥30
days** between a front-end accepting epoch N and any client being required to
use it. `proto_version` is fixed for the life of a control connection, so a
version bump is a coordinated reconnect, not an in-place upgrade.

**A rolling upgrade does not lose a `Session`.** Upgrading a peer restarts the
process, which is already a `→ RECONNECTING` path; `session_id` is durable
(S-12) and survives, and a **new `Tunnel`** is created with a freshly negotiated
`(V, C)`.

### Deprecation gates

An epoch may be removed only when **all five** hold
([ADR-0014](../../docs/adr/ADR-0014-protocol-versioning-and-capability-negotiation.md) N-25):

| Gate | Condition |
|---|---|
| G1 time | ≥ **12 months** since the superseding epoch shipped |
| G2 evidence | Fleet share < **1 %** for ≥ **30 consecutive days**, measured |
| G3 warning | A release emitting `PROTO.VERSION_DEPRECATED` has been in the field ≥ **90 days** |
| G4 isolation | The MSPV bump ships in a release that changes no other `v_min` |
| G5 removal | Removed from **the build**, not merely deprioritised |

Deprecation is **evidence-gated, not calendar-only**. Reason codes get their own
window: a `DEPRECATED` code stays accepted for **three epochs or 12 months,
whichever is longer**, and retired identifiers are never reused.

### Minimum supported protocol version

A device whose `v_max` is below a peer's `v_min` MUST refuse with
`PROTO.VERSION_UNSUPPORTED`, **naming both ranges and the required upgrade —
never a bare numeric code**; emit a non-retryable event; hold **no** half-open
state; retry only on explicit user action, a successful self-update, or a **6 h**
floor; and **keep the diagnostic visible** as the connection's standing reason.
Silently ceasing to connect is the defect this rule exists to eliminate.

A rollback below MSPV is refused **at install time, before the old binary runs** —
refusing afterwards would leave a running binary that cannot connect and that may
read state it does not understand.

---

## 4. Capability negotiation

### The selection function

```
SELECT( (a_min, a_max, A_caps), (b_min, b_max, B_caps) ):
    lo = max(a_min, b_min)
    hi = min(a_max, b_max)
    if hi < lo:               REFUSE  PROTO.VERSION_UNSUPPORTED
    V = hi
    C = { t : t.name/t.major in A_caps AND in B_caps }, each parameter reduced
        by its registry-declared rule
    C = canonical_sort(C) by (name ASC, major ASC)
    if V < local_floor(peer): REFUSE  PROTO.DOWNGRADE_REFUSED
    return (V, C)
```

**Total, deterministic, symmetric.** Because the epoch space is totally ordered,
`hi` is a unique maximum: **there is no tie-breaking rule, by construction** —
and a tie-break in an attacker-reachable negotiation is precisely the asymmetry
an adversary probes.

### Why the *inputs* are bound, not the result

This is the technical core of
[ADR-0014](../../docs/adr/ADR-0014-protocol-versioning-and-capability-negotiation.md)
and the reason `ConnectAnswer` carries the responder's **full** range and
**full** capability set rather than only `selected_*`.

An attacker who rewrites **both** advertisements consistently — lowering A's
maximum in transit to B *and* B's in transit to A — makes both peers compute the
**same** lowered selection and bind the **same** value. **Binding the selection
therefore leaves the downgrade undetected.** Binding each peer's own
advertisement *as sent* alongside the peer's *as received* cannot be defeated
that way, because **a peer cannot be made to forget what it sent**.

```
HalfAdvertisement := { session_nonce, key_id, role, v_min, v_max, capabilities }
H_X              = SHA-256("TWINVPN-NEG-HALF-v1" || dCBOR(HalfAdvertisement_X))
negotiation_hash = SHA-256("TWINVPN-NEG-v1" || H_init || H_resp || dCBOR(Selection))
```

`negotiation_hash` is **contributed** to the Noise prologue owned by ADR-0001;
this contract does not define the prologue. Each peer constructs its own half
**from what it sent** and the peer's **from what it received, verbatim, over the
received octets** — never re-serializing.

Three detection layers, each catching what the others cannot:

1. **Rule-B signature** over offer/answer — catches rendezvous and network
   tampering *before* the handshake: `PROTO.NEGOTIATION_TAMPERED`.
2. **Noise prologue binding** — catches everything the signature misses,
   including a future unsigned path. Fails closed.
3. **`NegotiationConfirm`** in-session — catches two honest peers *computing*
   different selections, which no cryptographic layer can see.
   `PROTO.TRANSCRIPT_MISMATCH`, **a security event, not a network error**.

### The metadata cost, stated

The advertisement is **signed but not encrypted**. The rendezvous and any on-path
observer learn both peers' epoch ranges and full capability lists — which leaks
OS family, feature availability, and whether OS-level kill-switch enforcement is
possible on that device. This is a genuine privacy regression against a
post-handshake negotiation, and it is accepted for the round trip that would
cost on every connection.

Mitigations, all normative: **only probe-verified tokens are advertised**, so the
list is not a static platform fingerprint; tokens are **canonically sorted**, so
ordering leaks nothing; **no free-form strings and no version banners** are
permitted in the advertisement.

### Capability rules

- **Naming (N-11):** `name/major`, `name` matching `[a-z][a-z0-9_]{0,31}` (at most 32 characters, raised from 24 by the 2026-08-27 amendment — the original bound contradicted ADR-0014 §11.11's own registry table; see [phase1-conflicts.md](phase1-conflicts.md) CF-6).
- **Intersection (N-12):** negotiated iff `(name, major)` appears in **both**.
  **Different majors of the same name are distinct capabilities and do not
  intersect.** There is no implicit "higher major implies lower"; a device that
  means to interoperate with both must advertise both.
- **Parameters (N-13):** reduced by `MIN` / `MAX` / `INTERSECT` / `EQUAL` per the
  registry. **Reduction MUST NOT be role-dependent** — "initiator wins" would be
  an asymmetric-authority downgrade lever.
- **The real-probe rule (N-14):** a capability is advertised **only if the
  platform probe OBSERVED the ability in this process, on this OS build, with the
  permissions currently granted**. A build-time constant, a compile flag, or an
  OS-version table MUST NOT be the sole basis. Where the ability cannot be
  observed non-destructively, the probe performs a rollback-guaranteed
  install-then-remove and **records** the result.
- **The anti-rot rule (N-15):** a capability exists **only when a peer must *do*
  something differently**. Adding an optional field is not a capability.

### Per-`Session` immutability and mid-session loss

The negotiated `(V, C)` is recorded on the `Tunnel` and governs it for its
lifetime regardless of any later advertisement change. When a capability
genuinely disappears mid-session, **the negotiated set is NOT mutated**:

1. Stop using it immediately.
2. Emit `PROTO.CAPABILITY_REVOKED_LOCAL` naming the token and the OS cause.
3. **Renegotiation requires a new `Tunnel`, never a mutated one.**
4. If `session_critical`: tear down the `Tunnel` and re-handshake. The `Session`
   and its `session_id` survive.
5. If not: the feature stops, the diagnostic stands, and there is **no
   `ConnectionState` change** — a capability shortfall is not a quality violation
   and MUST NOT be reported as `DEGRADED`.
6. If **local policy requires** it: the disposition is **`BLOCKED`** under **I3**
   — never `DEGRADED`, never silent, because protected traffic must not continue
   to flow on a tunnel that cannot honour the policy.

### The monotonic floor (S-37)

Each device persists, per `TrustedPeer`, the highest epoch ever successfully
negotiated and the set of **`security_relevant`** tokens ever negotiated. An
offer strictly below is refused with `PROTO.DOWNGRADE_REFUSED`.

**The floor covers only `security_relevant` tokens, not the whole set.** A
whole-set ratchet is unsound: capability sets are a **partial order**, and a
capability can legitimately vanish when an OS revokes a permission, so a
whole-set ratchet would permanently brick an honest device. Losing a
non-security capability is a legitimate, surfaced degradation; losing a
security-relevant one is refused.

The floor is **never transmitted and never replicated**. Clearing or lowering it
requires an **authenticated local Owner action** and **MUST NOT be triggerable by
the control plane or by any peer** — a floor that could be transmitted could be
lowered remotely, deleting the anti-rollback property entirely.

**The legitimate-rollback sharp edge, stated:** a device rolled back *within* the
supported window will be refused by peers whose floor records the higher epoch.
This is correct and deliberate — the alternative is a remotely-triggerable
downgrade — and it means an authorised rollback requires an explicit
"accept downgrade for *this device*" action at each affected peer.

### Explicit degradation

Every capability present locally but absent from the negotiated set produces
**exactly one** diagnostic per `(Session, token, Tunnel)` — **loud once, never a
per-packet source** — naming the peer **by its user-visible label**, the lost
behaviour in user terms, and the next action.

**Silence is a defect.** A negotiated set smaller than the local advertisement
with no diagnostic is an **I6** violation and a P1 test failure.

### The registry byte budget

The advertisement gets a **fixed 512 B reservation** inside the 1200 B C4
datagram, **≤32 tokens**, and a CI contract test serialises the current registry
and asserts it fits — so **registry growth fails the build rather than the
field**.

Candidates can trickle across datagrams; **the advertisement cannot**, because it
must be complete and atomic to be bound into the prologue. That asymmetry is why
the budget is a hard gate rather than a guideline.

---

## 5. The frozen namespace

`twinvpn.v1`, under `contracts/proto/twinvpn/v1/`. A new major namespace is a
**new directory**, never a mutation of this one — which is what makes "the
artifacts are immutable per release" mechanically true rather than aspirational.
