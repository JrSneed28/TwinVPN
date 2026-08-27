# Trust boundaries and contract security review

Every contract family reviewed as an attacker would: who can produce this
message, what a forgery buys, what must be validated, and what is structurally
prevented rather than checked.

---

## 1. The boundaries

From [ADR-0003](../../docs/adr/ADR-0003-network-contract-schema-format.md) §1 and
[docs/architecture.md](../../docs/architecture.md) §8.

| ID | Boundary | Who can reach it | Trust | Contracts |
|---|---|---|---|---|
| **B1** | Control plane (C1/C2/C7) | Any authenticated device; the control plane itself | **Semi-trusted.** Warehouses statements it must not be able to forge | `control_commands`, `control_events`, `presence`, `device`, `peer` |
| **B2** | Signed statements | Anyone who can deliver bytes; verified possibly **years** later | **Trust-bearing. Forgery = total compromise** | `cddl/signed_statements.cddl`, `SignedStatement` |
| **B3** | Ephemeral signaling (C4) | **Anyone who can send a UDP datagram.** Forwarded by an untrusted rendezvous | **Fully attacker-reachable, PRE-AUTHENTICATION** | `signaling`, `candidate`, `capability` |
| **B4** | Data plane (C5/C6) | Any host reaching the socket | Attacker-reachable, post-AEAD | **none — no serialization framework in the packet path** |
| **B5** | Local config, CLI, diagnostic bundles | The Owner, and whoever they share a bundle with | Not a trust boundary; never signed in this form | `diagnostics` (rendered as JSON) |

**Relays are untrusted.** They forward opaque ciphertext and are never a party to
the tunnel handshake. **Push gateways are untrusted third parties** that may carry
a wake hint and **must not carry state, secrets, or anything authoritative**.

---

## 2. B3 — the worst case, and what bounds it

Pre-authentication, forwarded blind, reachable by anyone with a UDP socket. This
is where a parser bug is a remote memory-safety bug.

**Bounds enforced BEFORE any allocation proportional to a declared length:**

| Bound | Value | Why |
|---|---|---|
| Envelope | **1200 B** | Worst-case IPv6 path MTU minus headers — *not* the IPv4 576 B floor, because C4 is never fragmented and IPv6 forbids in-network fragmentation |
| Parser depth | **4** | Half the C1 limit. The hostile boundary gets the tighter bound |
| Capability tokens | **32**, **512 B** total | A fixed reservation the whole registry is CI-tested to fit |
| Token name | **24 B** | |
| Parameters | **8** per token, **256 B** total | |
| Range sanity | `v_min ≤ v_max ≤ current_epoch + 64` | An absurd maximum must not be a probe oracle or an allocation lever |
| Candidates | **32** per set | |

Violation ⇒ **drop, emit `PROTO.MALFORMED_MESSAGE`, NO state change, NO answer.**
Answering would confirm the target exists.

**No state may be written pre-authentication.** No `Session` state, no
negotiation floor, no cached advertisement is written until the handshake
completes **and** `NegotiationConfirm` matches
([ADR-0014](../../docs/adr/ADR-0014-protocol-versioning-and-capability-negotiation.md)
N-9, [ADR-0001](../../docs/adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) D6).

**The decode-outcome contract** — [ADR-0003](../../docs/adr/ADR-0003-network-contract-schema-format.md)
§11.7 rule PA-1. Exactly three outcomes exist:

1. **Accept**, with verification over the received octets.
2. **Reject**, with a specific `PROTO.*` code. A bare error, an untyped exception
   or a boolean `false` is **not** a reject.
3. **Reject-and-no-effect**, the same plus "no state changed".

**There is no fourth outcome.** A panic, an abort, a hang, an allocation
proportional to a declared length, or a silent accept is a **P1 defect regardless
of perceived exploitability**. [`tests/test_wire.py`](../tests/test_wire.py)
exercises ten malformed inputs including a declared 4 GiB length, and asserts
both that the input is refused and that decoding terminated.

### Anti-amplification

**Signed candidates.** `CandidateSet` is Rule-B signed and an unsigned candidate
is **dropped**. Without the signature, the rendezvous — or anyone who can inject
a datagram — could steer probing traffic at a chosen victim, **turning TwinVPN
into a reflection amplifier**.

**The matching structural control:** `PunchSync` carries **indices into the two
signed candidate sets, never addresses**. An index cannot name an address that
did not appear in a signed set. This is the anti-amplification control expressed
in the type system rather than as a runtime check that could be forgotten.

**The rendezvous cannot reflect.** A `CALL` is forwarded to a peer identified by
`DeviceId`, never to a caller-supplied address, and the mailbox is per-target and
small, so it cannot be a memory amplifier.

---

## 3. B2 — signed statements

**Verification is over the received octets. An implementation MUST NOT
re-serialize before verifying.** Signed statements are deterministic CBOR
(RFC 8949 §4.2.1) in COSE_Sign1 (RFC 9052), carried in this package as an
**opaque protobuf `bytes` field**.

This is not a stylistic layering. Protobuf **explicitly does not guarantee**
deterministic serialization across languages, versions, or even builds. A
signature scheme built on "serialize the protobuf and sign it" is a latent break:
the day a peer's runtime reorders a map or reserializes with a preserved unknown
field, previously valid signatures stop verifying — or worse, two distinct
logical values sign identically.

**This suite measured that hazard on this schema.** Two independent runtimes
produced different bytes for one logical `ExitNodeGrant` value, because protobufjs
emits an explicit zero where the Go runtime omits a proto3 implicit-presence
field. Both encodings are valid; neither is canonical. That is exactly why B2 is
CBOR, and the divergence is recorded in
[`tests/test_wire.py`](../tests/test_wire.py) rather than asserted away.

**Non-canonical input is REJECTED, never normalized.** Normalizing attacker input
before verifying is a signature-bypass pattern. `PROTO.NON_CANONICAL_CBOR`.

**Unknown-field policy is asymmetric.** Transport messages preserve and forward;
signed statements **reject** unknown non-`crit` fields, because a
preserved-but-unverified field is a place to smuggle data past a policy check.

**The `crit` set.** A verifier encountering an unrecognized critical field MUST
**reject** the statement. Without this, a future *restriction* would be silently
ignored by old devices — converting a tightening into a no-op, which is **a
silent authorization hole**.

**Every decoded field is a view until the signature verifies.** `PolicyBundle`,
`RouteAdvertisement`, `ExitNode` and `RelayCapabilityTokenDescriptor` each carry
both a decoded projection and the signed original. **Enforcement reads the
verified payload**; the protobuf fields are attacker-controlled until then.

### What a forgery at each statement would buy

| Statement | Forgery buys | Prevented by |
|---|---|---|
| `RevocationStatement` | Revoking an honest device, or **un-revoking a stolen one** | Owner-authority signature; monotone epoch; never-shrinking set |
| `PolicyBundle` | Disabling every kill switch in the fleet | Owner-authority signature; **`killswitch_floor` is a floor, never a ceiling** |
| `PairingAttestation` | **Injecting a `TrustedPeer`** | Both devices sign; coordination transports what it cannot forge |
| `RouteAdvertisement` | Advertising `0.0.0.0/0` + `::/0` and **capturing the TwinNet's traffic** | Advertiser signature **and** local `AccessPolicy` acceptance — acceptance is a local decision, never an infrastructure one |
| `ExitNodeOffer` | Attracting egress traffic | Device signature; local policy; explicit per-family grant |
| `TunnelKeyBinding` | **Full authentication bypass** — substituting a tunnel key | Non-skippable verification (N-4) with dedicated conformance vectors |
| `IdentitySuccession` | Installing an attacker key as a successor | **Dual signature**: old ∧ new |
| `RelayCapabilityToken` | Free relay capacity | Issuer signature; `cnf` proof-of-possession; `epoch ≥ epoch_floor` |
| `LogHead` | **Lying about freshness** | *Not fully prevented* — see below |
| `NetworkContract` | Redirecting addressing and DNS | Signature; monotone `contract_seq`; **atomic application**; fixed `crit` set |

**The one honest gap.** The `LogHead` signing key is an **online control-plane
key**. A *compromised* control plane **can forge freshness** — it cannot forge
trust, which requires the Owner authority, but it can lie about there being
nothing to fetch. `LogHead` defends against a partitioned, buggy or
partially-failed front-end and against a network attacker who drops events. It
does **not** defend against a fully compromised control plane, and it carries no
delegated trust power. Stated rather than papered over.

---

## 4. B1 — the semi-trusted control plane

The design assumption is that a front-end node, **and even the broker itself**,
may be hostile.

**What a fully compromised control plane can do:** withhold, delay, advance a
watermark to cause a spurious re-read, forge freshness (above), and see metadata.

**What it cannot do:**

| Cannot | Because |
|---|---|
| Forge a trust statement | Every trust-bearing statement is Rule-B signed by the Owner authority or a device |
| Roll a device back | Every state document is monotone-versioned with **device-side** rejection at the local store |
| Author policy | The bundle is Owner-signed; coordination distributes only |
| **Lower any device's enforcement** | `killswitch_floor` contributes only to `max(local, policy_required)`. **There is no encoding that lowers enforcement below the local setting, and no receiver may implement one** |
| Disengage a kill switch | S-18 has no remote replica; disengage requires an authenticated local Owner action and is deliberately non-idempotent |
| Lower a negotiation floor | S-37 is never transmitted; only a local Owner action can lower it |
| Redirect a route | `RouteAdvertisement` is device-signed, and **acceptance is local** |
| Force a downgrade | The negotiation binds the inputs into the Noise prologue; the control plane is not in the connection path at all |
| Read tunnel traffic | **I1** — it holds no tunnel key |
| Tear down a running Session | `Session` state is **device-authoritative** (S-12); an outage changes nothing about a running `Tunnel` |

**Channel binding.** `Auth.channel_binding` is the RFC 9266 `tls-exporter` value,
so a message cannot be lifted onto another channel by a compromised TLS
terminator. A mismatch is `CONTROL.CHANNEL_BINDING_MISMATCH`, **a security event,
never a parse error**.

**Single publisher.** A durable event from a principal that is not its sole
publisher is `CONTROL.EVENT_WRONG_PUBLISHER`, FATAL/CRITICAL, a security event —
enforced as a **schema constraint at the log**, not by code review.

---

## 5. Relay contracts — the zero-plaintext-access model

A fully compromised relay learns: *that some bearer of a valid capability token
is forwarding some bytes between two legs.* **That is the designed maximum.**

Three structural removals, each recorded here because each was a field somebody
would naturally have added:

1. **No `peer_key_id`.** [docs/protocol.md](../../docs/protocol.md) §16 row 21 is
   **withdrawn**; the table is keyed by `pair_tag`, a one-way HKDF output scoped
   to one relay and one 10-minute bucket. A tag observed at one relay is useless
   at another.
2. **`sub` is a per-operator, per-day pseudonym, never `device_id`.**
3. **No per-session or peer-pair label on relay telemetry** — forbidden outright
   by [ADR-0015](../../docs/adr/ADR-0015-observability-and-diagnostics.md) O-13
   and asserted in [`tests/test_semantics.py`](../tests/test_semantics.py).

**Relay denial is defence in depth only.** Revocation is enforced **at the peer**,
so a lagging relay leaks no access and no confidentiality — the revoked device
still cannot complete a peer handshake. The relay's revocation lag is a bounded
**resource-abuse** window, capped at the 24 h token lifetime.

**A relay can ask a device to leave; it can never redirect a session.** The peers
decide, inside their encrypted `Session`. This prevents a compromised relay from
steering traffic to a relay of its choosing.

---

## 6. Secret-field prohibition

**Never present in any contract, and mechanically enforced.**

| Class | Authority |
|---|---|
| Identity private keys (IK, OSK, ORK) | **I4**; [ADR-0018](../../docs/adr/ADR-0018-shared-core-and-build-architecture.md) CB-5 row 1 — never held by the core, never leaves the element |
| Tunnel static private key (TK) | Sealed under a hardware-bound key; unsealed only into locked, non-swappable, non-dumpable memory |
| Session keys, chaining keys, resumption secrets | S-13: **non-durable by requirement**; no replica exists |
| `PairSecret` | [ADR-0007](../../docs/adr/ADR-0007-device-identity-and-pairing.md) N-19 — **MUST NOT be transmitted, backed up, or replicated** |
| `pairing_secret` / the SPAKE2 password | Entered out of band; only its hash (`pairing_id`) exists |
| `EpochSeed` plaintext | S-33 — only HPKE seals addressed to a recipient exist |
| Store encryption key | Core-held on most targets, never serialized |
| Authentication tokens | Not required by any contract here |
| **Packet payloads / tunnel plaintext** | **I1** |
| **DNS query names** | [ADR-0015](../../docs/adr/ADR-0015-observability-and-diagnostics.md) §11.10 NEVER column |
| **Browsing / destination history** | `SECRET`: **no rendering path exists, in any build, at any log level, in any tier** |

Also **never a compatibility input outside one process**: `abi_major`/`abi_minor`
(ADR-0018 VR-2 as clarified 2026-08-27). They are build provenance, not a
negotiation value, and are omitted from Tier-2 aggregate telemetry entirely.

**Enforcement.** [`tests/test_schema_structure.py`](../tests/test_schema_structure.py)
matches every field name in the compiled image against a substring blocklist,
with a three-entry allowlist for explicitly public halves. It is deliberately
broader than the exact Phase 1 wording: the point is to make an accidental
addition impossible, not to enumerate the ones already known.

`FieldClassification` has **no `SECRET` member**, because
[ADR-0015](../../docs/adr/ADR-0015-observability-and-diagnostics.md) §11.4 says
SECRET material is *"never stored, never rendered, no code path exists"* — and
giving it an enum value would create the code path.

---

## 7. Observability privacy

**Three tiers, one direction.**

| Tier | Default | Leaves the device |
|---|---|---|
| **0** Local ledger | **Always on, cannot be disabled** | **Never** |
| **1** Diagnostic bundle | Off | **Only by explicit user act, per artifact** |
| **2** Aggregate telemetry | **Off**, opt-in | Only when opted in |

**Redaction is applied by the emitter from the schema classification.** There is
no "scrub with regexes before sending" step, because that approach **fails open**.

`SENSITIVE` fields are **pseudonymized with a per-bundle random mapping**: two
occurrences of one value map to the same token *within* a bundle and to
*different* tokens *across* bundles — so support can follow the topology of one
incident and **cannot correlate a user across incidents**. The mapping is
generated per bundle and discarded.

**There is no support-initiated pull.** No remote command can cause a client to
generate or transmit diagnostics. This is a security requirement, not a workflow
preference.

**The retention distinction that shapes the schema.** A *single* endpoint or
hostname in one diagnostic is `SENSITIVE`. A retained, time-ordered record of
*what a peer contacted* is a different asset and is `SECRET`. The difference is
**retention and correlation, not field type** — which is why `DiagnosticContext`
has no `destinations` or `queries` field, and why one may not be added.

`NetworkInterface` is **local-only and never transmitted**: an interface
inventory would hand a semi-trusted party a stable device fingerprint and a
topology map of the user's home network, for no protocol benefit, since
candidates already carry every address that matters — and carry it signed.

---

## 8. Untrusted-field validation checklist

Every field arriving from a peer, a relay, a client, or the control plane is
attacker-controlled until validated.

| Field class | Validation |
|---|---|
| Identifiers | **Exact length.** A mismatch is `PROTO.MALFORMED_MESSAGE` — never a truncation, never a pad |
| `IPv4Address` | Exactly 4 octets |
| `IPv6Address` | Exactly 16 octets; **IPv4-mapped (`::ffff:0:0/96`) REJECTED, not unmapped** — one logical address must not arrive under two encodings, or every prefix-match check that depends on a canonical form is defeated |
| `IPv6Address.zone_index` | Non-zero **required** for `fe80::/10`; zero otherwise |
| `IPPrefix` | `prefix_len` in range for the family; **every bit below it zero**. A non-canonical prefix is **REJECTED, never normalized** — normalizing before a policy check is how a rule meant for one network comes to match another |
| `Endpoint.port` | 1–65535; port 0 is malformed |
| `reason_code` | Format, ≤64 B, 2–3 segments, `domain` matches the prefix. **A mismatched pair is an attempt to render a condition under the wrong domain** and is rejected |
| Evidence keys | Registry-declared for that code. An undeclared key is an **unclassified** key, and an unclassified key cannot be redacted correctly — so it is dropped |
| Capability tokens | Name regex, count, byte, parameter caps; **the receiver's own registry rule wins** on a reduction disagreement, so a peer cannot pick the reduction that favours it |
| Repeated fields | Count caps from [`limits.json`](../registry/limits.json), enforced before allocation |
| Monotone counters | Rejected if `≤` high-water mark |
| Signed statements | Signature over received octets; `crit` enforced; canonical encoding required |
| `statement_type` | **A dispatch hint only.** The authoritative type is inside the signed payload and is re-checked after verification |
| `EventDurability` / `EventPublisher` | Asserted against the expected classification and the §7 publisher table |
