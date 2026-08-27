# ADR-0007: Device Identity and Pairing

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** SECURITY
- **Related:** [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md), [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md), [ADR-0003](ADR-0003-network-contract-schema-format.md), [ADR-0008](ADR-0008-idempotency.md), [ADR-0009](ADR-0009-state-consistency.md), [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md), [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md), [ADR-0015](ADR-0015-observability-and-diagnostics.md), [docs/architecture.md](../architecture.md), [docs/protocol.md](../protocol.md), [docs/reliability.md](../reliability.md), [docs/threat-model.md](../threat-model.md)

This ADR decides *who a `Device` is* and *how two `Device`s come to trust each other*: the
`DeviceIdentity` key hierarchy, the derivation of `device_id` from public key material,
per-platform custody of `DeviceKey`, the `Owner` root of trust and its recovery, the `Pairing`
ceremony, mutual authentication at the data-plane handshake, key rotation, and revocation. It
does **not** decide the tunnel handshake or AEAD — those are
[ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md), which this ADR consumes
verbatim; it does not decide consistency classes ([ADR-0009](ADR-0009-state-consistency.md)),
idempotency mechanism ([ADR-0008](ADR-0008-idempotency.md)), version/capability negotiation
([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)), or the threat model
([docs/threat-model.md](../threat-model.md)) — it supplies the identity-layer material each of
those needs and states what it requires from them.

## 1. Context

Every other security claim in TwinVPN reduces to one question: *when a `Device` completes a
handshake, on what basis does the other end believe it is who it says it is?* Four facts fix
the shape of the answer before any alternative is weighed.

**1. `DeviceKey` private material cannot leave the device (I4 / P4).** There is no password,
no shared secret, no escrow, no export. This is not a preference; it is the invariant that
makes "a compromised control plane cannot impersonate a device" true rather than aspirational.
It also removes cloud key restore from the product, permanently, and that cost has to be paid
somewhere visible (§7.3, §13 K3).

**2. The control plane must not be able to forge membership** ([docs/protocol.md](../protocol.md)
A5, [docs/architecture.md](../architecture.md) A-04). Devices must verify membership and
revocation **offline**, against a root that no infrastructure component holds. But the `Owner`
is a human being whose only key-bearing hardware is the very devices being enrolled. The root
of trust therefore has to live somewhere that survives losing any one device — without living
on a server. This is the hardest problem in the ADR; §4 Group O and §7.5 treat it as such.

**3. The data plane outlives the control plane (I5 / P5).** A confirmed `Pairing` must leave
both devices holding *everything* needed to re-establish a `Tunnel` with zero control-plane
involvement ([docs/architecture.md](../architecture.md) A-02, §4.4.1). Identity material is
part of "everything", so identity cannot be a runtime lookup.

**4. Revocation is the deliberate exception** ([docs/architecture.md](../architecture.md) §4.5).
It is the one fact allowed to reach into a running data plane and end a relationship. Because
it is enforced at the peer rather than at the infrastructure, its propagation delay *is* the
security boundary, and this ADR must state that delay as a number rather than as a hope.

Two constraints from [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) are
already binding and are not re-litigated here: `DeviceIdentityKey` is a non-extractable
**P-256** key in the platform secure element (its §11 item 4 and C1), and the L-DATA tunnel
static is **X25519**, hardware-*wrapped* rather than hardware-*resident*. The gap between
those two keys — and the signature that closes it — is this ADR's to specify.

## 2. Requirements


**Requirements discharged** ([docs/vision.md](../vision.md) §5): **R-03** — `device_id` is derived from the generation-0 identity key and is stable for the device's life (N-2), which is what makes the deterministic address allocation of S-08 possible without DHCP; and **R-11** — a confirmed `Pairing` writes enough durable local state (N-19) for two devices to re-establish a `Tunnel` with **zero** control-plane involvement, so no single component's unavailability can prevent a previously paired pair from communicating. This ADR additionally discharges **R-06**, **R-21**, **R-22** and **R-23** as cited in situ.
| # | Requirement | Source |
|---|---|---|
| Q1 | `device_id` MUST be derived from device-held public key material, not assigned by a server, and MUST be verifiable offline by any peer. | [docs/architecture.md](../architecture.md) A-01, §2.6 |
| Q2 | Private key material MUST NOT cross boundary B1 outward: no export, no backup, no escrow, no transmission. | I4, [docs/architecture.md](../architecture.md) §8 |
| Q3 | A confirmed `Pairing` MUST yield a `TrustedPeer` on **both** devices sufficient to re-establish a `Tunnel` with zero control-plane involvement. | [docs/architecture.md](../architecture.md) A-02, I5 |
| Q4 | `Pairing` MUST include an out-of-band human verification step and MUST NOT be completable by a network adversary who controls the rendezvous and the control plane. | [docs/architecture.md](../architecture.md) §2.7 |
| Q5 | Membership and revocation documents MUST be verifiable offline against an `Owner`-rooted authority that no infrastructure component can impersonate. | [docs/architecture.md](../architecture.md) A-04, [docs/protocol.md](../protocol.md) A5 |
| Q6 | Revocation MUST be enforced at the data-plane handshake, with control-plane and relay denial as defence in depth only. | [docs/architecture.md](../architecture.md) A-03, [docs/testing-strategy.md](../testing-strategy.md) A-06 |
| Q7 | Revocation propagation delay MUST be bounded and the bound MUST be stated numerically. | A-06, I6 |
| Q8 | Trust state MUST be rollback-resistant: a lower `trust_epoch` or `generation` MUST be refused, and a forked history MUST be locally detectable. | S-03, [docs/protocol.md](../protocol.md) E-1 |
| Q9 | Key rotation MUST be dual-signed (old ∧ new), monotone, and MUST NOT tear down established `Session`s. | [docs/protocol.md](../protocol.md) §8.4, I5 |
| Q10 | The peer handshake MUST bind the negotiated `ProtocolVersion` floor and `Capability` floor into its transcript via an application-supplied prologue. | [docs/protocol.md](../protocol.md) A2, [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) D1–D3 |
| Q11 | Every identity, pairing, and revocation failure MUST carry a stable `reason_code` with human-actionable text. | I6, R-22 |
| Q12 | An identity that cannot be loaded MUST fail closed and MUST NOT be silently regenerated. | [docs/architecture.md](../architecture.md) §2.6 failure behaviour |
| Q13 | Pairing MUST be idempotent and replay-safe; an interrupted ceremony MUST leave no partial trust. | [ADR-0008](ADR-0008-idempotency.md), [docs/architecture.md](../architecture.md) §2.7 |
| Q14 | No novel cryptography. Every primitive and every protocol used here MUST come from a published, audited specification. | I2 |
| Q15 | A device offline for months MUST be recoverable without an `Owner` device being online, unless it was revoked. | §10, R-06 |

## 3. Constraints

- **C1** Platform secure elements are P-256 engines. Secure Enclave, StrongBox, and TPM 2.0
  do not perform X25519 or Ed25519 private-key operations. Any hardware-resident key is P-256
  ([ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) C1).
- **C2** [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) fixes the L-DATA
  handshake as `Noise_IKpsk2` over X25519. Noise authenticates **static X25519 keys**, not
  P-256 identity keys. The two must be bound, and the binding must be checked before trust.
- **C3** [ADR-0003](ADR-0003-network-contract-schema-format.md) fixes the signed-statement
  encoding: deterministic CBOR (RFC 8949 §4.2.1) inside COSE_Sign1 (RFC 9052), verified over
  received octets, `crit` enforced. All trust documents here MUST use it.
- **C4** Some enrolment targets have no camera and no screen: headless Linux servers,
  OpenWrt routers, NAS boxes reachable only over SSH. A camera-only ceremony excludes R-21.
- **C5** Some targets have no secure element at all (routers, containers, VMs, pre-T2 Intel
  Macs). `hardware_backed` cannot be a precondition for enrolment without excluding R-21.
- **C6** The `Owner` is one human. Any scheme requiring the simultaneous presence of three
  devices, a hardware token, or an operational security ritual will be worked around.
- **C7** Revocation must work while the control plane is unreachable (A-06), so revocation
  material must be peer-relayable, and relaying it must not let a relay or the control plane
  read or forge it (I1).
- **C8** ECDSA is catastrophic under nonce reuse. Any software ECDSA signer here MUST use
  deterministic ECDSA (RFC 6979).

## 4. Considered Alternatives

Three genuinely independent decisions are in scope. Each is enumerated separately; §5 and §6
cover **every** listed option by name.

### Group H — Key hierarchy

| ID | Alternative |
|---|---|
| **H1** | **Single Ed25519 identity key**, used for signing and, via birational conversion to X25519, for the Noise static. One key, one `device_id`. |
| **H2** | **Separate Ed25519 signing key + X25519 static**, bound by a self-signature from the signing key. |
| **H3** | **X.509 device certificate chain** rooted at an `Owner` CA, with standard path validation, CRL/OCSP, and `KeyUsage` extensions. |
| **H4** | **Hardware-attested P-256 identity key + software X25519 tunnel static**, bound by a P-256-signed `TunnelKeyBinding`, with platform attestation of the identity key at enrolment. Trust documents are COSE_Sign1 over deterministic CBOR, not X.509. *(selected)* |

### Group O — `Owner` root of trust

| ID | Alternative |
|---|---|
| **O1** | **Root key on the first enrolled device.** The first device's secure element holds the only `Owner` authority. |
| **O2** | **Threshold-split `Owner` key** across k-of-n devices using a threshold signature scheme (FROST-style). |
| **O3** | **Control-plane-held `Owner` key with transparency-log accountability.** The control plane signs membership; an append-only log makes misbehaviour detectable after the fact. |
| **O4** | **Passphrase-derived offline recovery key only.** A recovery phrase deterministically derives the sole `Owner` root; it is materialised for each administrative action. |
| **O5** | **Two-tier: offline phrase-derived `OwnerRootKey` (ORK) + hardware-resident, ORK-delegated `OwnerSigningKey` (OSK) per admin device, with a plain multi-signature counting rule for quorum operations.** *(selected)* |

### Group C — Pairing ceremony

| ID | Alternative |
|---|---|
| **C-A** | **Short numeric code over a PAKE** (SPAKE2, RFC 9382, or CPace). |
| **C-B** | **Full public key material carried over a confidential out-of-band channel** to the approving device. **A QR code read by a camera is one such channel, not the definition (clarified, N-24d).** Any channel that is confidential and out-of-band qualifies — including an operator's own authenticated shell session, which is what lets a headless device keep C-B's **2^256** strength instead of falling back to C-A's ~2^29.9 ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) EM-21). The security property is the channel's confidentiality, never the optics. |
| **C-C** | **SAS / emoji comparison after an unauthenticated ECDH** (Noise-style short-authentication-string confirmation). |
| **C-D** | **Existing-device-approves-new-device** via an `Owner`-authenticated control-plane approval, with no device-to-device out-of-band channel. |
| **C-E** | **Layered: C-D as the authorization gate, C-B as the primary channel authenticator, C-A (SPAKE2/P-256) as the fallback where no camera exists, C-C demoted to a post-hoc confirmation display.** *(selected)* |

## 5. Advantages of Each Alternative

**H1 — single Ed25519.** One key, one `device_id`, one algorithm in every verifier: the
smallest possible identity surface and the smallest possible chance of a binding bug. Ed25519
(RFC 8032) is deterministic by construction, so C8 evaporates. The Ed25519→X25519 conversion
is published and widely deployed. No `TunnelKeyBinding` exists, so it cannot be skipped.

**H2 — separate Ed25519 + X25519.** Clean cryptographic hygiene: a signing key is never used
in a key-agreement context, so the cross-protocol analysis is trivial rather than merely
believed. Each key can rotate on its own schedule. Ed25519 is deterministic (C8 solved) and
signatures are 64 bytes with fast verification.

**H3 — X.509 chain.** The most tooling of any option: OpenSSL, every HSM, every platform TLS
stack, every auditor. `KeyUsage`/`ExtendedKeyUsage`, `NotBefore`/`NotAfter`, path length
constraints, and name constraints are already specified and already implemented. Attestation
formats on Android and Windows *are* X.509 chains, so no conversion is needed. mTLS on
L-CONTROL would use certificates natively.

**H4 — attested P-256 + bound X25519 (selected).** The only option in which the identity key
is genuinely **non-extractable in hardware on every platform that has hardware** (C1) — an
attacker with code execution can *use* it but cannot *take* it, so the compromise dies with
the revocation instead of outliving the device. Platform attestation (Secure Enclave, Android
Key Attestation, TPM certify) is available natively for exactly this key type. It composes
without friction with [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md):
Noise gets its X25519 static, L-CONTROL gets its RFC 7250 raw public key, and one signature
algorithm (COSE `ES256`) covers every trust document in the corpus. COSE_Sign1 over
deterministic CBOR is already mandated by [ADR-0003](ADR-0003-network-contract-schema-format.md),
so trust documents cost ~120 bytes rather than ~800.

**O1 — root on the first device.** Simplest thing that works. No phrase, no ceremony, no
recovery UX. The root is hardware-resident and non-extractable, which is the strongest
possible custody. Zero user education.

**O2 — threshold split.** The strongest security story: no single device compromise yields
the root, and losing one device below the threshold is survivable without any user-held
secret. Quorum is enforced cryptographically rather than by a counting rule a buggy verifier
could get wrong. Produces a single signature that verifiers check with ordinary code.

**O3 — control-plane key + transparency log.** Operationally the easiest: recovery is a
support ticket, device loss is trivially handled, and the user never sees a phrase. The log
makes equivocation detectable, and detectability deters a commercial operator effectively.
Scales to multi-owner and organisational deployments without redesign.

**O4 — passphrase-derived key only.** The root survives the loss of *every* device, which is
the one failure mode no device-held scheme survives. Nothing to compromise on any machine
between ceremonies. Reconstitution is deterministic and offline; it needs no infrastructure.

**O5 — two-tier ORK + OSK (selected).** Routine operations (enroll, revoke, publish policy)
use a hardware-resident OSK, so the common path has no phrase and no ritual (C6). The phrase
is needed only for the two rare events that genuinely warrant it: TwinNet creation, and
recovery from losing every admin device. Quorum semantics for high-power operations are
obtained with **plain multi-signature plus a counting rule** — two independent ES256
signatures and an integer comparison — which needs no threshold-crypto library and is
straightforward to audit (I2). The `Owner` root private half exists on no server and, between
ceremonies, in no device's storage.

**C-A — PAKE short code.** Works with no camera, no screen sharing, no scanner — a nine-digit
code can be read aloud, typed over SSH, or copied from a serial console (C4, R-21). SPAKE2
(RFC 9382) is standards-track with published P-256 parameters and gives the defining PAKE
property: **the transcript is not offline-testable against the password**, so an attacker gets
one guess per protocol run and nothing else. Familiar UX.

**C-B — QR with full public key.** Removes low-entropy secrets from the design entirely. The
optical channel is confidential and line-of-sight, so a network adversary — including one that
owns both the rendezvous and the control plane — has no position from which to attack. It is
also fast: one scan, no typing, no comparison step, which is the lowest-abandonment ceremony
of the four.

**C-C — SAS after unauthenticated ECDH.** No pre-shared anything and no camera: the two
devices just talk, then show matching words. It is what Signal, Matrix, and Bluetooth Secure
Simple Pairing use, so the interaction is culturally familiar. It works symmetrically over any
channel and needs no rendezvous cooperation.

**C-D — existing device approves.** The only option that expresses *authorization* rather than
*channel authentication*: it answers "should this device be in the TwinNet at all?", which the
other three do not. It requires no proximity, so enrolling a colocated server from home works.
It is where the `Owner`'s intent is actually captured.

**C-E — layered (selected).** Each mechanism is used only for the property it actually
provides: C-D for authorization, C-B/C-A for channel authentication, C-C for confirmation
display. Coverage is complete across form factors (C4, C5) without any device having to fall
back to a weaker *security* mechanism — only to a different *interaction*. Both authenticating
paths make human error produce a **failure**, never a silent compromise.

## 6. Disadvantages of Each Alternative

**H1 — single Ed25519.** Fatal against C1: **no shipping secure element performs Ed25519 or
X25519 private-key operations**, so the single key would be software-resident on every
platform, discarding hardware non-extractability and platform attestation entirely. It also
uses one key across two primitives (EdDSA signing and X25519 agreement), which is exactly the
cross-protocol reuse that key-separation hygiene exists to forbid; the conversion is safe in
the published analyses, but "safe under the analyses we have read" is a weaker position than
"never reused". And a single key means identity rotation and tunnel-key rotation are the same
event, so a routine 180-day tunnel-key hygiene rotation would churn `device_id`.

**H2 — separate Ed25519 + X25519.** Solves the reuse problem but not C1: the Ed25519 signing
key is still software-resident everywhere, so it can be *extracted* by an attacker with code
execution and then used indefinitely from other hardware. Platform attestation is unavailable
for Ed25519 on all four platforms, so the `hardware_backed` claim would have no corroboration
anywhere. It also adds a second signature algorithm alongside the P-256 that
[ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) already requires for
L-CONTROL mTLS, doubling the verifier surface for no gain.

**H3 — X.509 chain.** Brings the entire PKI apparatus into a system that needs none of it:
ASN.1 DER parsing (a historically rich source of memory-safety and parser-differential bugs),
path-building ambiguity, name constraints, and a revocation story (CRL/OCSP) that is
online-dependent and therefore in direct conflict with I5 and Q6. Certificates are ~700–900
bytes against ~120 for COSE_Sign1, which matters when trust documents are relayed inside
handshake prefaces over lossy mobile links. It would also introduce a **second** signed-object
encoding alongside [ADR-0003](ADR-0003-network-contract-schema-format.md)'s deterministic
CBOR, breaking the "verify over received octets" discipline that ADR-0003 chose specifically
to eliminate a bug class. Finally, X.509 expiry semantics push toward short-lived certificates
and therefore toward an online renewal dependency — the opposite of Q15.

**H4 — attested P-256 + bound X25519 (selected).** Two keys that MUST stay bound, and the
binding check is a single mandatory verification whose omission is a total authentication
bypass ([ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) K3). ECDSA
requires the RFC 6979 discipline of C8, where EdDSA would have been safe by construction. The
tunnel static remains hardware-*wrapped* rather than hardware-*resident*, so K2 of ADR-0001 is
inherited unchanged: code execution as the service on an unlocked device extracts the tunnel
key. Two rotation schedules must be tracked instead of one.

**O1 — root on the first device.** Loss, theft, or destruction of that one device destroys the
TwinNet's ability to enroll or revoke anything, forever. It also makes that device a
disproportionately valuable target while giving the `Owner` no signal that it is special. In a
two-device household — the modal TwinVPN deployment — this is not a tail risk; it is a
likely event within the product's lifetime.

**O2 — threshold split.** Requires a threshold signature implementation. FROST is standardised
but its mature implementations are Ed25519/secp256k1, not P-256-in-a-secure-element, and no
secure element exposes the partial-signing primitives a threshold scheme needs — so the shares
would be software keys, forfeiting the hardware custody that motivated H4. It is also the
option most likely to violate I2 in spirit: a distributed key generation and signing protocol
is precisely the kind of composition where "audited primitive, unaudited protocol" bites. And
with n = 1 (a brand-new TwinNet with one device) a k-of-n scheme is either degenerate or
unusable.

**O3 — control-plane key + transparency log.** Directly contradicts
[docs/protocol.md](../protocol.md) A5 and [docs/architecture.md](../architecture.md) A-04: a
compromised or coerced control plane could sign a membership document admitting an
attacker-controlled device into the TwinNet, and every peer would accept it. A transparency
log makes that **detectable after the fact**, not prevented — and detection requires the
victim to be monitoring, online, and able to distinguish a malicious delegation from one the
`Owner` performed on another device. Trading prevention for detection is the exact move that
I1 and the "semi-trusted, never trusted" posture of B3 exist to forbid. It is retained as
defence in depth (§11.1 N-14), never as the root.

**O4 — passphrase-derived key only.** Every administrative action — enrolling a device,
revoking a lost one, publishing a policy change — requires the `Owner` to find and type a
24-word phrase. Against C6 that is not a security control, it is a guarantee that the phrase
ends up in a password manager, a photograph, or a text file, at which point it is worse than a
device-held key because it is copyable and its copy is undetectable. Materialising the root
scalar in application memory on every operation also maximises its exposure surface.

**O5 — two-tier ORK + OSK (selected).** The `Owner` must record a recovery phrase at TwinNet
creation, which is the single worst moment in the onboarding funnel and the point at which
users are least attentive. Verifiers must implement a delegation-chain check (record → OSK →
ORK → pinned anchor) and a quorum counting rule; a counting-rule bug is an authorization
bypass and it is our code, not a library's. Losing every admin device **and** the phrase is
unrecoverable (§7.5) — O3 would have survived that, and does not.

**C-A — PAKE short code.** A nine-digit code is 29.9 bits: security rests entirely on strict
online-attempt limiting being implemented correctly in three places (both devices and the
rendezvous), and a bug in any of them silently converts a strong ceremony into a weak one.
SPAKE2 needs correct handling of the fixed group elements M and N and correct point validation;
these are small but real implementation hazards. Typing nine digits on a TV remote or a
router's serial console is slow enough that some users will lower the code length, which is a
standing pressure to weaken the design.

**C-B — full public key over a confidential out-of-band channel.** The *camera-and-screen* realization requires a camera on one side and a screen on the other,
which excludes headless servers and routers outright (C4). It is also the most
capture-sensitive: a QR displayed on a screen in a shared office is readable by anything with
a lens, and unlike C-A there is no attempt limiting to fall back on — a captured
`pairing_secret` is a complete compromise of that ceremony run until it expires.

**C-C — SAS after unauthenticated ECDH.** The security boundary is human attentiveness. An
adversary who MITMs the rendezvous succeeds whenever the user clicks "yes" without comparing,
and the published usability literature on Bluetooth numeric comparison and on messenger safety
numbers is unambiguous that a large fraction of users do exactly that. That makes it the only
option in Group C where human error produces **silent compromise** rather than failure. It
also needs an extra round trip and an extra screen in a flow already competing with the user's
patience.

**C-D — existing device approves.** It authorizes but does not authenticate: on its own,
whatever public key the rendezvous hands the approving device is what gets approved, so a
malicious rendezvous substituting its own key is undetected. It is a necessary component and a
catastrophically insufficient whole.

**C-E — layered (selected).** Two authenticating ceremonies to implement, test, and document
instead of one, with two sets of failure modes and two sets of reason codes. The `Owner` sees
different flows on different device types, which is a support and documentation burden. The
fallback path (C-A) is measurably weaker than the primary (C-A: ~2^29.9 with attempt limiting
versus C-B: 2^256), so the ceremony a device gets depends on its hardware — an asymmetry that
must be surfaced in the pairing record rather than hidden (§11.1 N-16).

## 7. Security Implications

### 7.1 The key hierarchy and what each key authenticates

```
  OwnerRootKey (ORK)  ES256, derived from a 24-word recovery phrase, materialised
        │             only during TwinNet creation and recovery; stored nowhere.
        │ signs OwnerDelegation
        ▼
  OwnerSigningKey (OSK)  ES256, non-extractable in the secure element of each
        │                admin Device; powers ⊆ {ENROLL, REVOKE, POLICY, DELEGATE}
        │ signs DeviceCertificate, RevocationRecord, TrustEpochBundle, PolicyBundle
        ▼
  DeviceIdentityKey (IK)  ES256, non-extractable, per Device, attested where possible.
        │                 Authenticates: L-CONTROL mTLS (RFC 7250 raw public key),
        │                 every COSE_Sign1 device statement, PairingAttestation.
        │ signs TunnelKeyBinding
        ▼
  TunnelStaticKey (TK)   X25519, generated on-device, sealed under a hardware-bound
                         wrapping key. The Noise_IKpsk2 static of ADR-0001 §7.2.
```

The binding is the load-bearing edge. `Noise_IKpsk2` authenticates **TK**, not IK. A peer
therefore trusts TK because, at pairing, it verified `TunnelKeyBinding` — an IK signature over
TK — and IK was itself vouched for by the ceremony and by an OSK-signed `DeviceCertificate`.
Verification of the binding is mandatory and non-skippable (N-4); omitting it is a complete
authentication bypass, which is why it is a single explicit check with its own test vector
rather than an implicit consequence of parsing.

### 7.2 `device_id` derivation and collision analysis

```
identity_id  = SHA-256( "TwinVPN/DeviceIdentity/v1" || 0x00 || dCBOR(COSE_Key(IK_pub)) )
device_id    = identity_id of generation 0   (the enrolment identity; stable for life)
text form    = "twd1" || base32-lower-nopad(device_id)          # 4 + 52 = 56 chars
fingerprint  = crockford-base32( device_id[0..12] >> 4 )        # 100 bits, 20 chars
               rendered in 5 groups of 4: K7QD-2M9F-XB3T-N5W8-J4RC
```

`device_id` is the **full 256-bit digest**; it is not truncated. On the wire it is 32 raw
bytes. The `twd1` text prefix is an algorithm/version tag, so a future post-quantum identity
key becomes `twd2` without ambiguity.

`device_id` pins the **generation-0** public key. IK rotation creates a new `DeviceIdentity`
(new `identity_id`, `generation`+1) linked to its predecessor by a dual-signed
`IdentitySuccession`, but **`device_id` does not change** — otherwise S-08's deterministic,
immutable `TwinNet` address allocation would break on every rotation. After a rotation,
`device_id` is self-certifying *transitively*: a verifier checks the succession chain from
generation 0 to the presented generation. That is a real cost of the design and it is stated
here rather than buried (§13 K5).

**Collision analysis.** For `device_id` itself the relevant bound is SHA-256 collision
resistance: 2^128 generic, with no truncation to erode it. For the 100-bit human
`fingerprint`, the attack that matters is **second preimage** — grinding a key whose
fingerprint equals a *specific* target's — which costs 2^100 and is infeasible. Birthday
collisions (any two keys matching each other) cost 2^50 and are findable on rented GPUs, but
they give an attacker nothing: both colliding keys would have to be attacker-controlled. The
real hazard is **prefix grinding**: matching the first two displayed groups costs only 2^40.
The UI therefore MUST render all twenty characters and MUST NOT offer a truncated comparison
(N-3). Independently, the fingerprint is never a trust boundary — trust is established by the
ceremony transcript, and the fingerprint exists only so a human can tell two of their own
devices apart in a list.

### 7.3 Key custody per platform

| Platform | IK custody | TK sealing | Hardware backing | Attestation | Honest fallback |
|---|---|---|---|---|---|
| iOS / iPadOS | Secure Enclave, `SecKeyCreateRandomKey` P-256 with `kSecAttrTokenIDSecureEnclave`, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, `kSecAccessControlPrivateKeyUsage` | `SecKeyCreateEncryptedData` under a second SE key; plaintext only in `mlock`ed memory | Yes (SEP) | `SecKeyCreateAttestation`, DCRK-rooted | none needed |
| macOS | Secure Enclave (Apple silicon / T2) | as iOS | Yes, except pre-T2 Intel | as iOS | Pre-T2 Intel: Keychain file item, `hardware_backed = false` |
| Android | Android Keystore, EC P-256, `setIsStrongBoxBacked(true)`, **`setUnlockedDeviceRequired(false)` — corrected, see N-24a**, `setAttestationChallenge(nonce)` | Keystore AES-256-GCM wrapping key, same `SecurityLevel` | StrongBox, else TEE | Android Key Attestation chain to the Google root, carrying `SecurityLevel` | Software keymaster ⇒ `hardware_backed = false` |
| Windows | CNG, Microsoft Platform Crypto Provider (TPM 2.0), `ECDSA_P256`, `NCRYPT_ALLOW_EXPORT_FLAG` **not** set | DPAPI-NG `NCryptProtectSecret` to a local, TPM-bound descriptor | TPM 2.0 | `TPM2_Certify` under an AK, with the EK certificate chain where present | Software KSP ⇒ `hardware_backed = false` |
| Linux (desktop/server) | TPM 2.0 via tpm2-tss, key created under the SRK with `fixedTPM \| fixedParent`; handle held in the kernel keyring | TPM-sealed wrapping key; plaintext in `mlock`ed, `MADV_DONTDUMP` memory, core dumps disabled | TPM 2.0 where present | `TPM2_Certify` quote | No TPM: file at mode 0600 in a 0700 directory, optionally Argon2id-passphrase-wrapped; `hardware_backed = false` |
| Router / OpenWrt | file-backed | file-backed | No | none | `hardware_backed = false`, always |

**What `hardware_backed` means to a relying peer.** It is a claim in the
`DeviceCertificate` about where the private half lives, corroborated — where the platform
supports it — by a platform attestation blob that is verified **once, by the approving OSK
device at enrolment**, and never by every peer at every handshake. Peers treat it as advisory
metadata and as a policy input; a peer MUST NOT treat an unattested `hardware_backed = true`
as proof of anything (N-6). The `Owner` MAY set a TwinNet policy requiring
`hardware_backed = true` with a verified attestation for enrolment, in which case a
non-conforming device is refused with `AUTH.ATTESTATION_REQUIRED`. If a device's backing is
ever downgraded (secure element migration, OS re-image), it MUST rotate IK and re-attest, and
peers surface `AUTH.HARDWARE_BACKING_LOST` (N-24).

**The cost of I4, paid explicitly.** Because the private half never leaves the device, there
is **no cloud restore of a device identity**. A restored backup, a re-imaged machine, or a
migrated OS profile arrives with no usable key. The agent MUST detect this (key handle absent
or invalid) and fail closed with `AUTH.IDENTITY_MISSING`, prompting re-enrolment — it MUST NOT
silently mint a replacement identity, because a silently rotated identity is indistinguishable
from a compromise ([docs/architecture.md](../architecture.md) §2.6). Re-enrolment is therefore
designed as a **first-class flow**, not an error path: the `Owner` approves the new identity
from an OSK device, the `TwinNet` label and role are carried over, and the old `device_id` is
revoked in the same operation.

#### 7.3.1 Key availability class (N-24a) — corrected, and newly stated

**N-24a — `setUnlockedDeviceRequired(true)` is withdrawn on Android, because it is a
random-disconnect defect shipping as a security decision.** That flag makes the identity key usable
only while the device is **currently unlocked**, which is strictly stronger than the
`AfterFirstUnlock` posture this same table chooses for iOS/iPadOS — an asymmetry with no stated
justification. Its consequence is that **a phone whose screen locks mid-session cannot rekey**,
which is an **R-05**-class random disconnect: exactly the defect family
[docs/vision.md](../vision.md) §5.2 exists to retire. The correct Android equivalent of the iOS
posture is `setUnlockedDeviceRequired(false)` with `setUserAuthenticationRequired(false)` for the
identity key, leaving StrongBox/TEE hardware backing and attestation unchanged. Interactive
authentication remains required for **`Owner`-authority (OSK) operations**, which are ceremonies a
user is present for, not datapath operations that must survive a locked screen.

**N-24b — every target MUST declare a key AVAILABILITY CLASS, not only a custody class.** This ADR
specified *where* `DeviceKey` lives and *how well* it is protected, but never *when it can be used* —
and boot-start protection and **I4** pull in opposite directions here without the corpus naming the
tradeoff. On iOS/iPadOS before first unlock, and on any target with an unlock-bound key, a
boot-started authority **has no key**. Each row of §7.3 therefore declares one of:

| Availability class | Meaning | Consequence for a boot-started authority |
|---|---|---|
| `ALWAYS` | Usable from boot, no user presence required | Full control-plane-free reconnect at boot (**I5**) |
| `AFTER_FIRST_UNLOCK` | Usable after the first post-boot unlock, then continuously | Reconnect deferred until first unlock; the tunnel does **not** come up on a rebooted, never-unlocked phone |
| `WHILE_UNLOCKED` | Usable only while currently unlocked | **Not permitted for `DeviceKey`** (N-24a). Permitted for OSK only |

Where the class is not `ALWAYS`, the gap MUST fail **closed** and be named —
`PLATFORM.LIFECYCLE.KEY_UNAVAILABLE_PRE_UNLOCK`
([ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md)) — never resolved by
generating a replacement identity or by starting unprotected. **A headless target
(`HC-3`) whose key is not `ALWAYS` is non-conforming**, because no user will ever be present to
unlock it.

### 7.4 The pairing ceremony

Three concerns are separated and each is discharged by the mechanism that actually provides it:

| Concern | Mechanism | Always required? |
|---|---|---|
| **Authorization** — may this device join this `TwinNet`? | C-D: an OSK device holding `ENROLL` power approves | Yes |
| **Channel authentication** — am I talking to *that* device? | C-B (QR) where a camera and a screen exist; C-A (SPAKE2/P-256) otherwise | Yes, exactly one |
| **Confirmation** — did the right thing happen? | Post-hoc display of the peer's label and 20-char fingerprint on both ends | Display only |

**C-B, the QR path (primary).** The joining device generates `pairing_secret` (32 random
bytes) and displays a QR encoding a deterministic-CBOR payload:

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
`pairing_id = SHA-256(pairing_secret)[0..15]` is the public rendezvous handle;
`K_pair = HKDF-SHA-256(salt = pairing_id, ikm = pairing_secret, info = "TwinVPN/Pair/v1")`
wraps every subsequent ceremony message in ChaCha20-Poly1305. The rendezvous forwards opaque
bytes. **MITM at the rendezvous is defeated by construction**: the adversary never sees
`pairing_secret`, so it can neither read nor produce a valid ceremony message, and the
approving device's response — which carries the `OwnerTrustAnchor` and delegation chain the
joiner must pin — is authenticated by `K_pair` and by the OSK signature together.

**C-A, the SPAKE2 path (fallback, no camera).** SPAKE2 (RFC 9382) over P-256 with the
RFC-specified M and N, password = a **9-digit code** displayed on one device and entered on
the other. The derived shared key replaces `pairing_secret` as the input to `K_pair`.

**C-C is demoted, deliberately.** A SAS comparison is displayed after completion for
recognition ("you paired *NAS-Attic*, K7QD-2M9F-…"), but it is **not** a security gate. The
reason is stated in §6: with C-C as the primary mechanism, an adversary who MITMs the
rendezvous wins whenever a user clicks through, so human inattention produces silent
compromise. Under C-B and C-A, human error produces a *failed* ceremony instead.

**Pairing-code brute force, concretely.**

| Path | Secret entropy | Offline attack | Online attack | Attempt limit | Expiry |
|---|---|---|---|---|---|
| C-B (QR) | 256 bits, optical | infeasible (2^256) | no guessable ciphertext is exposed | n/a | 120 s |
| C-A (SPAKE2, 9 digits) | ~2^29.9 | **none, by the PAKE property** — the transcript is not an offline-testable function of the code | 1 guess per protocol run | **5 failed runs per `pairing_id`; the code is single-use and a failure burns it** | 120 s |
| *Rejected*: encrypt the key exchange under `KDF(code)` | ~2^29.9 | **10^9 guesses ≈ tens of seconds on one GPU** | — | irrelevant | — |

The third row is why **any ceremony in which the code is offline-attackable is prohibited**
(N-15). With C-A, an adversary's success probability against a single ceremony is at most
5 / 10^9 ≈ 5 × 10⁻⁹, and the 120-second expiry leaves no room to retry across codes.

**Ceremony completion.** `transcript_hash = SHA-256` over the ordered concatenation of
`pairing_id`, both `ik_pub`, both `tk_pub`, both `TunnelKeyBinding`s, the ceremony method,
`anchor_version`, and both offered `ProtocolVersion` ranges and `Capability` hashes. Each side
emits a `PairingAttestation` (the structure named in [docs/protocol.md](../protocol.md) §8.2)
signed by its IK over `transcript_hash`. Both sides then derive

```
PairSecret(A,B) = HKDF-SHA-256( ikm  = ceremony_key || X25519(e_A, e_B),
                                salt = transcript_hash,
                                info = "TwinVPN/PairSecret/v1" )
```

where `e_A`, `e_B` are fresh ephemerals exchanged inside the ceremony channel, so `PairSecret`
is forward-secret against later compromise of either static key. `PairSecret` is written into
`TrustedPeer` on both devices and never leaves either.

### 7.5 The `Owner` root, device loss, and `Owner`-key loss

`OwnerTrustAnchor` is a COSE_Sign1 document, self-signed by ORK, carrying `twinnet_id`,
`anchor_version` (monotone), the ORK public key, and the current set of `OwnerDelegation`s. It
is pinned by every device at enrolment and verified offline thereafter. Devices accept a new
anchor only at a strictly higher `anchor_version` **and** signed by ORK, or signed by a quorum
under the rule below.

**Quorum without threshold cryptography.** A high-power operation — minting a new OSK,
revoking an `ENROLL`- or `DELEGATE`-powered device, or publishing a new anchor — requires
**either** one ORK signature **or** `k = min(2, n_osk)` independent OSK signatures, where the
target device's own OSK does not count toward `k`. Verification is two ES256 checks and an
integer comparison. Ordinary operations (enrolling a device, revoking a non-admin device,
publishing policy) need one OSK signature with the matching power.

| Loss scenario | Recovery path | Cost |
|---|---|---|
| Non-admin device lost | Any `REVOKE`-powered OSK signs a `RevocationRecord`; the peer refusal is immediate and offline-capable, the `trust_epoch` advance is assigned at control-plane admission (N-25) | None |
| One admin device lost, ≥ 2 remain | The remaining two OSKs jointly revoke it and re-delegate | None; no phrase needed |
| Only admin device lost, phrase held | Enroll a replacement, reconstitute ORK from the phrase on it, publish anchor v+1 revoking the lost OSK and delegating a fresh one, zeroize ORK | One manual ceremony |
| **Only admin device lost, phrase lost** | **Unrecoverable.** No party can mint a delegation — including the control plane, by design (A5). The `TwinNet` must be destroyed and every device re-enrolled from scratch | Total re-enrolment |
| Recovery phrase compromised | Attacker can mint delegations and is indistinguishable from the `Owner`. **Total compromise of the trust root.** | See mitigations below |
| Control plane compromised | Cannot forge anything; can only censor, delay, or lie about availability | Bounded by §7.7 |

Two mitigations are mandatory because the "phrase lost" row is unrecoverable: TwinNet creation
MUST NOT complete until the `Owner` re-enters three randomly chosen words from the phrase
(N-12), and the client MUST display a persistent, dismissible-but-recurring warning while
`n_osk == 1` (N-13). Against phrase *compromise*, every device binds the current
`anchor_version` and `delegation_set_digest` into `identity_binding_hash` (§7.6) **and asserts
both in the in-session `TrustEpochAssert` message** (§7.7); a peer observing a delegation set it
did not expect raises `AUTH.UNEXPECTED_DELEGATION`. The prologue binding makes an unexpected
delegation set *unusable*; the in-session assertion is what makes it *observable* — a prologue
mismatch alone is indistinguishable from any other handshake failure
([ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) P-3), so detection MUST NOT
rest on the prologue. Detection accordingly covers the case where the attacker's delegations
chain to the *same* anchor; a wholly forked anchor fails the handshake and yields only the
weaker `AUTH.PROLOGUE_OR_EPOCH_MISMATCH` hypothesis. Additionally,
the control plane SHOULD publish an append-only, Merkle-tree transparency log (RFC 9162-style)
of every `OwnerDelegation` and `RevocationRecord`, and devices SHOULD cross-check inclusion
(N-14). Both of these are **detection**, not prevention, and are labelled as such.

### 7.6 Mutual authentication at the data-plane handshake

In steady state the handshake carries no certificates. The responder's `Noise_IKpsk2`
processing yields the initiator's static TK; the responder looks TK up in its local
`TrustedPeer` set (S-05). A TK not present, or present under a `TrustedPeer` deleted by
revocation, fails the handshake. **That is the whole of the mutual-authentication check**, and
it is what makes Q3/A-02 true: no control-plane call, no certificate parsing, 1-RTT preserved.

Version and capability floors are bound into the handshake through Noise's `prologue`
(discharging [docs/protocol.md](../protocol.md) A2), using only values both sides already hold
locally:

```
identity_binding_hash = SHA-256( "TWINVPN-IDBIND-v1"
                               || twinnet_id(16)
                               || device_id_init(32) || device_id_resp(32)
                               || trust_epoch(u64 BE) || psk_epoch(u64 BE)
                               || anchor_version(u32 BE)
                               || delegation_set_digest(32) )
```

**This is a contribution, not the prologue.** The Noise `prologue` is a single field owned by
[ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.3.1, which composes
`identity_binding_hash` (this ADR) with `negotiation_hash`
([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-6). The version floor
(`floor_version`, `floor_capability_hash`) is a **negotiation** input and is carried in
ADR-0014's half — it MUST NOT be duplicated here (ADR-0001 P-2).

`delegation_set_digest` is `SHA-256` over the deterministic-CBOR encoding of the ordered active
`OwnerDelegation` set (S-32). It is included so that a peer presenting an unexpected delegation
set cannot complete a handshake — but see the observability rule below.

A mismatch in any field makes the handshake AEAD fail, which is indistinguishable from any
other handshake failure — an honest limitation. The initiator MUST NOT retry with a lower
floor (that would be the downgrade
[ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) D3 forbids); after three
failures it emits `AUTH.PROLOGUE_OR_EPOCH_MISMATCH` as a diagnostic *hypothesis* with the
action "bring the peer online to refresh trust state". The full negotiated set is confirmed
**inside** the established tunnel with a transcript hash, which is
[ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)'s to specify (§11.3).

### 7.7 Revocation: mechanism, propagation, and the residual window

Revocation is **two nested structures with two different signers**, because N-25 splits
authorization from epoch assignment and a single structure cannot carry both. The `Owner` signs
what it knows; the shard writer adds what only it can assign.

```
RevocationStatement {                        # OSK-signed. The Owner CAN know every field.
  1 twinnet_id        : bstr(16)
  2 target_device_id  : bstr(32)
  3 target_identity_id: bstr(32) / null      # null = every generation
  4 effective_from_ms : uint
  5 reason_code       : tstr                 # an AUTH.* code
  6 issuer_osk_id     : bstr(32)
}

RevocationEntry {                            # control-plane-signed wrapper.
  1 statement         : RevocationStatement  # the OSK signature is over THIS, unmodified
  2 trust_epoch       : uint                 # assigned by the shard writer (N-25(2)), strictly increasing
  3 net_seq           : uint                 # the log position it was admitted at
  4 prev_entry_hash   : bstr(32)             # chains the list; makes a fork locally detectable
}
```

**Why the split is necessary, and what each half is trusted for.** An earlier form of this
structure put `trust_epoch` and `prev_record_hash` *inside* the OSK-signed object. That is
unimplementable under N-25: the `Owner` cannot sign an epoch number the shard writer has not yet
assigned, and an offline OSK cannot know the chain head. Leaving them inside the signature while
letting the writer fill them in would mean the signature does not actually cover them — which
would let a hostile control plane renumber and re-chain records while the signature still
verified.

| Half | Signer | Trusted for | NOT trusted for |
|---|---|---|---|
| `RevocationStatement` | `Owner` OSK with `REVOKE` | **The revocation itself.** This is the only half peer refusal depends on (N-25(1)), which is why refusal works offline, with no epoch and no control-plane reachability. A compromised control plane cannot forge one. | Ordering. It carries no position. |
| `RevocationEntry` | Control plane (shard writer) | **Ordering and fork detection.** The chain is a control-plane *integrity artifact*: a break raises `AUTH.TRUST_HISTORY_FORKED` and tells a device the log it is reading is inconsistent. | Authorizing anything. A well-formed `RevocationEntry` wrapping a statement whose OSK signature does not verify MUST be rejected outright. |

This is what keeps §7.8's "control plane forges membership — **defended**" true: the control plane
can reorder, withhold, or fork the *entry* layer, and every one of those is detectable and none of
them creates trust. N-26's chain verification therefore applies to `prev_entry_hash`, and its
guarantee is scoped to detection, not to prevention.

Deleting `TrustedPeer` is the primary exclusion mechanism, and it is entirely local — hence
Q6/A-06 hold with the control plane down. The **second, independent** lever is the epoch seed:

```
EpochSeed(e)      : 32 random bytes, generated by the revoking OSK device
TwinNetPSK(A,B,e) = HKDF-SHA-256( ikm  = PairSecret(A,B) || EpochSeed(e),
                                  salt = twinnet_id || e (u64 BE),
                                  info = "TwinVPN/psk2/v1" )   -> the psk2 slot of ADR-0001 §7.5
```

`EpochSeed(e)` reaches each **surviving** device as an HPKE (RFC 9180, Base mode,
DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305) seal to that device's TK,
bundled into a `TrustEpochBundle`. A revoked device is simply not a recipient, so it cannot
compute the PSK at epoch `e` **even if it retained its `PairSecret` and even if a peer's
`TrustedPeer` deletion failed**. Because each seal is openable only by its recipient, the
bundle is safely **peer-relayable**: an up-to-date peer hands a lagging peer its own sealed
seed inside an established tunnel, so propagation does not require the control plane (C7, I5)
and neither a relay nor the control plane can read or forge it (I1).

This corrects a claim in
[ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.5: derived from a
*TwinNet-wide* secret, the PSK epoch would **not** be a revocation lever, because the revoked
device would know that secret and could derive any later epoch's PSK. Derived from a *pairwise*
secret plus an OSK-generated, per-device-sealed epoch seed, it is.

A device MUST NOT accept a handshake below its own `min_acceptable_epoch` (the highest epoch at
which it has applied a `RevocationRecord`). Retaining the previous two epochs' seeds bounds
disruption to legitimate peers while giving a revoked device no epoch it can use.

**Propagation bound — the number A-06 requires.**

| Device's situation | Bound on learning a revocation |
|---|---|
| Control-plane reachable, push (C3) delivered | p95 ≤ 30 s, p99 ≤ 5 min |
| Control-plane unreachable, talks to any updated peer | ≤ one rekey interval after that contact — ≤ 120 s ([ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.2 `REKEY_AFTER_TIME`) |
| Routine refresh floor | `T_TRUST_REFRESH = 6 h` |
| Staleness warning (persistent `Diagnostic`, `AUTH.TRUST_STATE_STALE`; **no `ConnectionState` change**) | `T_TRUST_STALE = 24 h` |
| **Suspension of elevated authority** (`AUTH.TRUST_STATE_EXPIRED`) | **`T_TRUST_HARD = 30 d`** |

**What `T_TRUST_HARD` does, precisely.** At `T_TRUST_HARD` the device suspends every *granted*
authority — `ExitNode` use, `LANGateway` access, route acceptance, and new `Pairing` — under
[ADR-0009](ADR-0009-state-consistency.md) §11.5's grant/deny asymmetry. It does **not** refuse
baseline connectivity to an already-known `TrustedPeer`. An earlier draft of this ADR did refuse
new handshakes outright; that is **withdrawn**, because a confirmed `Pairing` is a fact the two
devices established between themselves (**A-02**) and no control-plane silence may withdraw it —
refusing it would make the control plane a liveness dependency of the data plane and break
**R-11** for an honest pair on an isolated LAN.

**The residual window, stated plainly: a revoked device can still reach — at baseline only — a peer
partitioned from both the control plane and every updated peer, and that window is bounded by the
partition, not by a timer.** What *is* bounded at 30 days is everything the revoked device could do
*through* such a peer: at `T_TRUST_HARD` it can obtain no egress, no LAN access, no accepted route,
and no new pairing. Existing `Session`s are never torn down at any boundary (**I5**). `T_TRUST_HARD` is `Owner`-configurable within
[24 h, 90 d]; shortening it strengthens revocation and penalises genuinely offline
deployments (the cabin, the air-gapped lab), and that tradeoff belongs to the `Owner`.

### 7.8 Attacks: defended, and not

| Attack | Defended | Mechanism, and the honest limit | Detection |
|---|---|---|---|
| Stolen device, locked, not yet unlocked since boot | Yes | `AfterFirstUnlockThisDeviceOnly` / `setUnlockedDeviceRequired` make IK unusable before first unlock | — |
| Stolen device, unlocked | **No** | The thief *is* the device. Revocation is the only answer, bounded by §7.7 | `Owner`-initiated |
| Device cloning (disk image to new hardware) | Yes where `hardware_backed = true`; **no** where false | A secure-element key does not clone. On a file-backed Linux/router install, cloning succeeds and both copies connect — the honest cost of C5 | **Duplicate-identity detection:** concurrent `Session`s for one `device_id` from distinct networks raise `AUTH.IDENTITY_CONCURRENT_USE`; a clone racing the original produces non-increasing TAI64N handshake timestamps ([ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.2), which are logged. Detection, not prevention |
| TK extraction from process memory | **No** | Inherited from [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) K2. `mlock`, no core dumps, and the `PairSecret`-derived PSK raise the bar, but both live in the same address space, so this is a weak mitigation and is not claimed as more | Behavioural only |
| IK extraction | Yes where hardware-backed | The attacker can *use* IK while resident but cannot *take* it; the compromise ends at revocation instead of outliving the device | — |
| Control plane forges membership | **Yes** | It holds no ORK/OSK private half; every trust document is COSE_Sign1 verified to the pinned anchor (A5) | Anchor digest cross-check, hash chain, transparency log |
| Control plane censors a revocation | Partially | Staleness surfaces `AUTH.TRUST_STATE_STALE` at 24 h and **suspends every granted authority** at 30 d (N-27); baseline reachability to a known `TrustedPeer` is **not** refused (R-11) | `AUTH.TRUST_STATE_STALE` |
| Rendezvous MITM during pairing | **Yes** | C-B: nothing guessable transits the network. C-A: one online guess per run, 5 runs, 120 s | `AUTH.PAIRING_ATTEMPTS_EXCEEDED` |
| Recovery-phrase compromise | **No** | Total trust-root compromise; the attacker is indistinguishable from the `Owner` | `AUTH.UNEXPECTED_DELEGATION`, transparency log |
| Coerced `Owner` | **No** | Named and out of scope, not mitigated | — |

### 7.9 Control-plane operational keys — why freshness is not trust

[ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) §11 places three interfaces on this
ADR that were previously undischarged. They are discharged here because each is an identity
question, and because `docs/threat-model.md` §10.1 asserts that a compromised control plane
"cannot forge trust" — an assertion that needs a stated reason.

| # | Rule |
|---|---|
| **N-29** | The **`LogHead` signing key** is a control-plane **operational** key. It is online by necessity (it signs a freshness beacon continuously) and therefore MUST hold **no delegated power under the `OwnerTrustAnchor`**. It is not an OSK, carries no `ENROLL`/`REVOKE`/`POLICY` capability, and appears in no delegation chain. A device MUST verify `LogHead` against the control-plane operational key set **only**, and MUST NOT accept a `LogHead` signature as evidence for any membership, revocation, or policy fact. This is what makes "a compromised control plane can forge freshness, but not trust" a structural statement rather than a hope: the two key sets are disjoint by construction, and the trust-bearing half is rooted in a key that exists on no server (§7.5). |
| **N-30** | Compromise of the `LogHead` key lets an attacker assert that stale state is fresh — which suppresses a *refresh*, exactly like withholding one. It is therefore bounded by the same grant/deny asymmetry: staleness bands still advance on the device's own monotonic clock (K-2), so a forged freshness beacon cannot hold a device below `T_TRUST_HARD` indefinitely. It cannot mint, alter, or roll back any B2 statement. |
| **N-31** | A **C3 push token** MUST be bound to a `DeviceIdentity` by an IK signature over `(device_id, token, not_after)` at registration, so a token observed or stolen in transit cannot be claimed by another device. A push token is a delivery hint and MUST NOT be treated as an authenticator for any operation. |
| **N-32** | The `DeviceIdentityKey` is usable directly as the RFC 7250 raw public key for mTLS client authentication on C1/C2, which is what supplies the RFC 9266 `tls-exporter` channel binding protocol.md A1 depends on. No separate transport credential exists. |

Additionally, the `DeviceRevoked` durable event MUST carry the full `TrustEpochBundle`
(ADR-0002 §11), so a device learning of a revocation from the event stream obtains the sealed
`EpochSeed` it needs in the same delivery, rather than requiring a second fetch that a partition
could deny.

---

## 8. Reliability Implications

- **A-02 is discharged structurally.** At ceremony completion each device durably holds: peer
  `device_id` and `ik_pub`, peer `tk_pub` plus the verified `TunnelKeyBinding`, `PairSecret`,
  the pinned `OwnerTrustAnchor` and delegation chain, the current `EpochSeed` set, and the
  negotiated floor. Every input the handshake needs is local, so re-establishment during a
  total control-plane outage is a pure data-plane operation
  ([docs/architecture.md](../architecture.md) §4.4.1, §6.3).
- **Revocation does not require the control plane at connection time**, only at propagation
  time — exactly the framing of [docs/architecture.md](../architecture.md) §4.5. Peer-relayable
  epoch bundles shorten propagation in partitioned topologies rather than lengthening it.
- **No new `ConnectionState`s and no new transitions.** This ADR supplies guards and reason
  codes for existing events only: `EV_AUTH_REJECTED`, `EV_PEER_REVOKED`, `EV_CRED_EXPIRED`
  ([docs/reliability.md](../reliability.md) §4.3). Revocation drives `* → FAILED`; trust
  staleness drives `→ DEGRADED`; a revoked *local* device with the kill switch armed drives
  `* → BLOCKED` ([docs/protocol.md](../protocol.md) §8.3, I3).
- **Rotation never tears down a `Session`** (Q9). Overlap windows (`T_IK_OVERLAP = 30 d`,
  `T_TK_OVERLAP = 14 d`) mean a peer that has not yet seen a rotation still connects; only
  after the window does it get the specific `AUTH.KEY_ROTATED_PEER_STALE` rather than a generic
  crypto error.
- **Failure to load an identity is terminal, not silent** (Q12): `AUTH.IDENTITY_MISSING` /
  `AUTH.KEY_STORE_UNAVAILABLE`, both `FAILED`, both user-actionable.
- **Pairing is idempotent by consumption, not by re-invention.** Both ceremony steps carry
  client-generated idempotency keys in [ADR-0008](ADR-0008-idempotency.md)'s `CEREMONY` class
  with a 24 h dedupe window; a replayed confirm returns the recorded outcome. This ADR adds
  only that a `pairing_id` is single-use and that a failed ceremony leaves no partial trust on
  either side.

## 9. Performance Implications

| Operation | Cost | Frequency |
|---|---|---|
| `device_id` derivation | one SHA-256 over ~90 bytes | once at enrolment, then cached |
| `TunnelKeyBinding` verification | one ES256 verify (~60 µs desktop, ~250 µs mobile) | once per `TrustedPeer`, at pairing; re-checked only on TK rotation |
| Trust-chain verification (record → OSK → ORK → anchor) | two ES256 verifies + one hash-chain step | per document, not per handshake |
| Steady-state handshake identity cost | **zero additional asymmetric operations** — TK lookup in a local map | per handshake |
| Pairing ceremony, C-B | 1 X25519 + 2 ES256 sign + 2 ES256 verify + AEAD | once per peer, ever |
| Pairing ceremony, C-A | SPAKE2/P-256: 2 scalar mults per side, plus the above | once per peer, ever |
| `TrustEpochBundle` generation | n HPKE seals ≈ n × (1 X25519 + 1 AEAD); ~80 bytes per recipient | per revocation |
| `TrustEpochBundle` size | ~120 B + 80 B × n; n = 20 ⇒ ~1.7 kB | per revocation |
| Epoch seed opening | one HPKE open | per epoch per device |

The design deliberately pushes **all** asymmetric identity work to enrolment, rotation, and
revocation — events that happen a handful of times per device lifetime — and leaves the
per-handshake path with a hash-map lookup. That is why the identity layer adds nothing
measurable to the 1-RTT budget of
[ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) R8.

## 10. Operational Implications

- **Onboarding has two flows**, chosen by hardware probe, and the chosen method is recorded in
  the `Pairing` record and shown in diagnostics. Support must be able to answer "which
  ceremony did this pair use?" from the bundle alone (R-23).
- **The recovery phrase is the single worst UX moment in the product** and is treated as such:
  shown once, confirmed by re-entry of three random words, never displayed again, never
  transmitted, never written to logs or telemetry.
- **`n_osk == 1` is a persistent warning state**, not a silent condition.
- **The six-months-offline device.** `DeviceCertificate` deliberately carries a long backstop
  `not_after` (enrolment + 10 years), **not** a short expiry, so renewal never requires an
  `Owner` device to be online (Q15). Freshness is enforced by the trust-epoch staleness timers
  of §7.7, which a device can satisfy by reaching the **control plane alone** — the control
  plane cannot forge a `TrustEpochBundle` but can serve one. A device returning after six
  months therefore: fetches the current bundle, opens the seal that was created for it months
  earlier, advances to the current epoch, and is immediately current. If it was revoked while
  offline, no seal exists for it, and it learns it is revoked → `AUTH.DEVICE_REVOKED` →
  `FAILED`, or `BLOCKED` if the kill switch is armed.
  This **overrules** the "short `DeviceCertificate` lifetime" mitigation asserted in
  [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.7 and K2. The
  property ADR-0001 actually wanted — a bound on how long an extracted tunnel key is useful —
  is preserved by mandatory **TK rotation every 180 days** (N-21), which does not create an
  online dependency. ADR-0001 §7.7 and K2 must be amended to cite TK rotation instead of
  certificate expiry.
- **Diagnostics never print private material**, and never print `pairing_secret`,
  `PairSecret`, `EpochSeed`, or the recovery phrase. Public fingerprints, `device_id`,
  `trust_epoch`, `anchor_version`, and `generation` are loggable.
- **Clock dependence.** `not_after_ms`, `effective_from_ms`, and ceremony expiry are wall-clock.
  A device with a badly wrong clock MUST **report** `AUTH.CLOCK_IMPLAUSIBLE` — and MUST NOT treat it as terminal (N-24c) — consistent with
  [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)'s `AUTH.CLOCK_IMPLAUSIBLE`.
- **Migration and re-image are re-enrolment**, and the UI says so before the user starts.

## 11. Decision

### 11.1 Normative rules

**Identity and derivation**

- **N-1** `DeviceIdentity` MUST comprise an ES256 (P-256 / SHA-256) `DeviceIdentityKey` (IK)
  and an X25519 `TunnelStaticKey` (TK). Alternative H4 is adopted; H1, H2, H3 are rejected.
- **N-2** `identity_id` MUST be `SHA-256("TwinVPN/DeviceIdentity/v1" || 0x00 || dCBOR(COSE_Key(IK_pub)))`,
  untruncated. `device_id` MUST be the `identity_id` of **generation 0** and MUST NOT change on
  rotation. Text form MUST be `"twd1" || base32-lower-nopad(device_id)`.
- **N-3** The human `fingerprint` MUST be the leading 100 bits of `device_id` in Crockford
  base32, rendered as five groups of four. UIs MUST render all twenty characters and MUST NOT
  offer a truncated comparison. The fingerprint MUST NOT be used as a trust decision input.
- **N-4** A peer MUST verify `TunnelKeyBinding` (COSE_Sign1 by IK over
  `{device_id, identity_id, tk_pub, tk_generation, not_after_ms}`) before writing TK into
  `TrustedPeer`. This check MUST NOT be skippable by configuration and MUST have dedicated
  conformance vectors.
- **N-5** IK private material MUST be generated inside platform secure storage and MUST be
  marked non-exportable. TK MUST be sealed under a hardware-bound wrapping key and unsealed
  only into locked, non-swappable, non-dumpable memory.
- **N-6** `hardware_backed` MUST be verified against a platform attestation at enrolment by the
  approving OSK device where the platform provides one. A peer MUST NOT treat an unattested
  `hardware_backed = true` as evidence.
- **N-7** If IK cannot be loaded, the `Device` MUST fail closed with `AUTH.IDENTITY_MISSING` or
  `AUTH.KEY_STORE_UNAVAILABLE` and MUST NOT generate a replacement identity.
- **N-8** Software ECDSA signers MUST use deterministic ECDSA (RFC 6979).

**Owner root of trust**

- **N-9** The root MUST be an `OwnerTrustAnchor` (COSE_Sign1, ORK-signed) pinned by every
  device at enrolment. Alternative O5 is adopted; O1, O2, O3, O4 are rejected as roots.
- **N-10** ORK MUST be derived deterministically from a 24-word recovery phrase (256-bit
  entropy, BIP-39 English wordlist) via HMAC-DRBG(SHA-256) and FIPS 186-4 B.4.2 candidate
  testing. ORK private material MUST be zeroized immediately after each ceremony and MUST NOT
  be persisted.
- **N-11** High-power operations (mint an OSK, revoke an `ENROLL`/`DELEGATE` device, publish an
  anchor) MUST carry either one ORK signature or `k = min(2, n_osk)` independent OSK
  signatures, excluding any OSK belonging to the target. Ordinary operations require one OSK
  signature bearing the matching power.
- **N-12** TwinNet creation MUST NOT complete until the `Owner` re-enters three randomly
  chosen words of the recovery phrase.
- **N-13** The client MUST display a recurring warning while `n_osk == 1`.
- **N-14** The control plane SHOULD publish an append-only transparency log of every
  `OwnerDelegation` and `RevocationRecord`; devices SHOULD cross-check inclusion. This is
  detection only and MUST NOT be described as prevention.

**Pairing**

- **N-15** Every ceremony MUST be resistant to offline dictionary attack on any human-entered
  secret. A ceremony whose transcript permits offline testing of the code MUST NOT be
  implemented. Alternative C-E is adopted; C-A/C-B/C-C/C-D are adopted only in the roles §7.4
  assigns them.
- **N-16** The ceremony method MUST be recorded in the `Pairing` record and surfaced in
  diagnostics.
- **N-17** C-A MUST use SPAKE2 (RFC 9382) with the RFC-specified P-256 parameters, a 9-digit
  code, at most **5** failed runs per `pairing_id`, single-use codes, and a **120 s** expiry
  enforced independently by both devices and the rendezvous.
- **N-18** A `Pairing` MUST complete on both devices or on neither. Both steps MUST honour an
  [ADR-0008](ADR-0008-idempotency.md) `CEREMONY`-class idempotency key.
- **N-19** On completion both devices MUST durably write a `TrustedPeer` containing peer
  `device_id`, `ik_pub`, `tk_pub`, the verified `TunnelKeyBinding`, `PairSecret`, the pinned
  anchor and delegation chain, and the current `EpochSeed`. `PairSecret` MUST NOT be
  transmitted, backed up, or replicated.

**Handshake, rotation, revocation**

- **N-20** This ADR contributes `identity_binding_hash` exactly as defined in §7.6 to the Noise `prologue` owned by [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.3.1 (rule P-1). It does **not** define the prologue itself. An initiator MUST
  NOT retry a failed handshake with a lower `floor_version` or `floor_capability_hash`.
- **N-21** IK rotation MUST produce a new `DeviceIdentity` with `generation`+1 and an
  `IdentitySuccession` signed by **both** the old and the new IK. TK rotation MUST NOT change
  `DeviceIdentity`. TK MUST be rotated at least every **180 days**.
- **N-22** Peers MUST store `highest_generation_seen` and `highest_tk_generation_seen` per
  `device_id` and MUST reject any statement at or below the stored value.
- **N-23** Overlap windows MUST be `T_IK_OVERLAP = 30 d` and `T_TK_OVERLAP = 14 d`; expiry MUST
  produce `AUTH.KEY_ROTATED_PEER_STALE`, never a generic handshake error.
- **N-24** A downgrade of `hardware_backed` MUST force IK rotation and re-attestation, and
  peers MUST surface `AUTH.HARDWARE_BACKING_LOST`.
- **N-25** Revocation has **two separable effects, with two different authorities** — this is what
  lets it work offline without forking the epoch history:
  1. **Peer refusal** (`TrustedPeer` deletion and handshake rejection) is **local** (S-05) and
     takes effect the instant a device verifies an `Owner`-signed `RevocationRecord`, whatever its
     provenance — control plane, peer relay (N-28), or manual import. It requires **no** epoch
     number and **no** control-plane reachability. This is the effect that must survive a
     partition, and it does.
  2. **`trust_epoch` advance** (which rotates `EpochSeed` and so removes the revoked device's
     ability to derive `psk2`) is a **totally ordered** operation. The `Owner` **authorizes** it by
     signing; the control-plane shard writer **assigns** the epoch number at admission under its
     fenced lease ([ADR-0009](ADR-0009-state-consistency.md) §11.2). An `Owner`-signed
     `RevocationRecord` that has not yet been admitted is fully effective for (1) and is
     **pending** for (2); it MUST NOT be assigned an epoch locally.

  Splitting them this way is what makes a forked history structurally impossible rather than
  merely detectable: two OSKs signing while partitioned produce two valid records, both of which
  refuse the same device immediately, and which the shard writer then admits in *some* order,
  yielding one chain. `prev_entry_hash` verification (N-26) remains the backstop.
  The `TrustEpochBundle` carrying the new `EpochSeed` is HPKE-sealed per surviving device. A device MUST NOT accept a handshake below its `min_acceptable_epoch`. It MUST retain
  the two preceding epochs' seeds.
- **N-26** `trust_epoch`, `anchor_version`, `generation`, and `tk_generation` MUST be monotone
  in durable local state. A lower value MUST be refused with `AUTH.TRUST_EPOCH_ROLLBACK`, not
  applied. `prev_entry_hash` MUST be verified on the `RevocationEntry` layer; a break MUST raise `AUTH.TRUST_HISTORY_FORKED`. This is **detection** of an inconsistent log, not prevention — peer refusal rests on the inner `RevocationStatement`'s OSK signature alone (N-25(1)), so a forked or withheld chain cannot un-revoke a device at a peer that has already seen the statement.
- **N-27** `DeviceCertificate` MUST carry a backstop `not_after` of enrolment + 10 years.
  Freshness MUST be enforced by `T_TRUST_REFRESH = 6 h`, `T_TRUST_STALE = 24 h`,
  `T_TRUST_HARD = 30 d` (`Owner`-configurable within [24 h, 90 d]). Exceeding `T_TRUST_HARD`
  MUST suspend every **granted** authority — `ExitNode` use, `LANGateway` access, route
  acceptance, and new `Pairing` — per [ADR-0009](ADR-0009-state-consistency.md) §11.5. It MUST
  **NOT** refuse a new handshake to an already-known `TrustedPeer` (**R-11**, **A-02**), and
  established `Session`s MUST continue (**I5**). The `Session` is `DEGRADED` with
  `AUTH.TRUST_STATE_EXPIRED` throughout.
- **N-28** `TrustEpochBundle`s MUST be relayable peer-to-peer inside an established tunnel. The carriage is `TrustEpochBundleTransfer` (`docs/protocol.md` §16 row 45), a peer-direct C5 message; the courier peer forwards HPKE seals it cannot open. This is distinct from `RevocationTransfer` (row 37), which propagates *refusal* only — without row 45 a lagging peer can refuse the revoked device but cannot advance `min_acceptable_epoch` or derive `psk2` at the new epoch, so the second revocation lever would have no path around a control-plane outage.

### 11.2 Interfaces required from other ADRs

| Required from | Interface |
|---|---|
| [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) | Application-supplied Noise `prologue` (§7.6); `psk2` fed from `TwinNetPSK(A,B,e)` (§7.7); a "reject handshake from this static" hook (A-06); amendment of §7.5 item 2, §7.7, and K2 per §7.7/§10 here |
| [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) | The `DeviceRevoked` durable event MUST carry the full `TrustEpochBundle`; `OwnerDelegation` and `OwnerTrustAnchor` MUST be Rule-B transitive payloads the control plane warehouses but cannot forge |
| [ADR-0003](ADR-0003-network-contract-schema-format.md) | COSE_Sign1 over deterministic CBOR with `crit` enforcement and verify-over-received-octets for every structure in §11.3 |
| [ADR-0008](ADR-0008-idempotency.md) | `CEREMONY`-class idempotency for both pairing steps, for `RotateKeyReq`, and for `RevokeDeviceReq` |
| [ADR-0009](ADR-0009-state-consistency.md) | Linearizable revocation admission with monotonic reads (E-1); `STRONG` on `(twinnet_id, IK_pub)` uniqueness; `MONOTONIC` on `trust_epoch` and `anchor_version` at the edge |
| [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) | Local revocation MUST drive `BLOCKED` under `FAIL_CLOSED`, never a silent drop to untunneled networking |
| [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) | In-tunnel transcript confirmation of the negotiated set; the monotonic floor values consumed by the prologue |
| [ADR-0015](ADR-0015-observability-and-diagnostics.md) | Registration of the `AUTH.*` codes in §11.4 with class, severity, and next-action keys |
| [docs/reliability.md](../reliability.md) | Registration of `T_TRUST_REFRESH`, `T_TRUST_STALE`, `T_TRUST_HARD`, `T_IK_OVERLAP`, `T_TK_OVERLAP` in §5 as credential-lifecycle constants; no new states or transitions are requested |

### 11.3 State-ownership rows required

Two new rows for [docs/architecture.md](../architecture.md) §5, and one amendment:

| # | State | Authoritative writer | Replicas | Class | Durability | On conflict |
|---|---|---|---|---|---|---|
| **S-32** | `OwnerTrustAnchor` + `OwnerDelegation` set | **`Owner` authority** (ORK, or an OSK quorum under N-11) | Control plane warehouses and fans out; every `Device` pins a copy | `MONOTONIC` (`anchor_version` MUST NOT decrease) | Durable on every device | Higher `anchor_version` with a valid signature wins; equal version with different content ⇒ `AUTH.TRUST_HISTORY_FORKED` |
| **S-33** | `EpochSeed` set (current + two preceding epochs) | **`Owner` authority** at generation; each `Device` holds only the seal addressed to it | None openable by any other party (HPKE-sealed) | `MONOTONIC` by `trust_epoch` | Durable local | Higher epoch wins; a lower epoch is a rollback attempt |

**Amendment to S-05.** `TrustedPeer` MUST be recorded as additionally containing `PairSecret`
and the verified `TunnelKeyBinding`, with "no remote replica, by construction" stated as for
S-01.

There is **no I8 violation** between S-32 and S-02/S-03: "which keys the `Owner` authorizes" has
exactly one writer (the `Owner` authority), and "the admitted revocation epoch and its
linearizable ordering" has exactly one writer (the control plane). They are different facts.

### 11.4 Reason codes contributed to the `AUTH` namespace

Contributed to [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2's machine-readable
registry, in its `DOMAIN.CONDITION` form.

| Code | Class | Terminal | Actionable | Meaning |
|---|---|---|---|---|
| `AUTH.DEVICE_REVOKED` | POLICY | yes | yes | This peer, or this device, has been revoked by the `Owner` |
| `AUTH.PEER_UNTRUSTED` | PERSISTENT | yes | yes | No `TrustedPeer` record for the presented static |
| `AUTH.KEY_UNAVAILABLE` | PERSISTENT | yes | yes | The key store refused a required operation |
| `AUTH.IDENTITY_MISSING` | FATAL | yes | yes | No identity present; re-enrolment required (restored backup / re-image) |
| `AUTH.KEY_STORE_UNAVAILABLE` | TRANSIENT | no | yes | Secure element or keyring temporarily unreachable |
| `AUTH.BINDING_INVALID` | PERSISTENT | yes | no | `TunnelKeyBinding` failed verification |
| `AUTH.PAIRING_EXPIRED` | PERSISTENT | yes | yes | Ceremony exceeded 120 s |
| `AUTH.PAIRING_CODE_MISMATCH` | PERSISTENT | no | yes | SPAKE2 run failed; the code was wrong |
| `AUTH.PAIRING_ATTEMPTS_EXCEEDED` | POLICY | yes | yes | Five failed runs for this `pairing_id`; request a new code |
| `AUTH.PAIRING_NOT_AUTHORIZED` | POLICY | yes | yes | No OSK with `ENROLL` power approved the join |
| `AUTH.ATTESTATION_REQUIRED` | POLICY | yes | yes | TwinNet policy demands verified hardware backing |
| `AUTH.ATTESTATION_INVALID` | PERSISTENT | yes | yes | Attestation chain did not verify to a trusted platform root |
| `AUTH.HARDWARE_BACKING_LOST` | PERSISTENT | no | yes | A peer's `hardware_backed` claim was downgraded |
| `AUTH.KEY_ROTATED_PEER_STALE` | PERSISTENT | yes | yes | Peer presents a key past its overlap window; bring it online |
| `AUTH.KEY_ROTATION_PENDING` | TRANSIENT | no | yes | Overlap window within 20 % of expiry |
| `AUTH.TRUST_EPOCH_ROLLBACK` | POLICY | yes | no | A lower `trust_epoch` was offered and refused |
| `AUTH.TRUST_HISTORY_FORKED` | FATAL | yes | yes | Two different records at one epoch, or a broken `prev_record_hash` |
| `AUTH.TRUST_STATE_STALE` | TRANSIENT | no | yes | No trust refresh for `T_TRUST_STALE`; `→ DEGRADED` |
| `AUTH.TRUST_STATE_EXPIRED` | PERSISTENT | no | yes | No trust refresh for `T_TRUST_HARD`; **granted authority suspended** (egress, LAN, routes, new pairing). Baseline peer connectivity continues |
| `AUTH.UNEXPECTED_DELEGATION` | PERSISTENT | no | yes | A delegation appeared that this device did not expect |
| `AUTH.IDENTITY_CONCURRENT_USE` | PERSISTENT | no | yes | One `device_id` observed in concurrent use from distinct networks |
| `AUTH.PROLOGUE_OR_EPOCH_MISMATCH` | PERSISTENT | no | yes | Repeated handshake failure consistent with divergent trust or floor state |
| `AUTH.CLOCK_IMPLAUSIBLE` | PERSISTENT | **no — reports, does not gate (N-24c)** | **conditional: `true` only on an attended host** | Wall clock too far off to evaluate validity windows. **It MUST NOT be terminal.** Under [ADR-0009](ADR-0009-state-consistency.md) K-1/RQ-9 no security decision may depend on the device's clock being correct, so a bad clock is a condition to *report*, never a gate. On an unattended RTC-less router — much OpenWrt-class hardware has no RTC and boots to epoch 0 every power cycle — a terminal, `user_actionable` state has **no one present to perform its remediation**, so `user_actionable = true` is simply **false for that tier**, and gating rather than reporting is the difference between one slow boot and a bricked device. Recovery is [ADR-0005](ADR-0005-relay-architecture.md) §11.3's relay-returned time offset, which needs no egress; the device MUST attempt the bind even with no offset. See [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) EM-77/EM-78 |
| `AUTH.IDENTITY_ALG_UNSUPPORTED` | PERSISTENT | yes | yes | Identity key algorithm outside this build's supported set |
| `AUTH.ANCHOR_VERSION_UNSUPPORTED` | PERSISTENT | yes | yes | `OwnerTrustAnchor` requires a newer client — the identity-layer sibling of `PROTO.VERSION_UNSUPPORTED` |
| `AUTH.CERT_PROFILE_UNSUPPORTED` | PERSISTENT | yes | yes | `DeviceCertificate` carries an unrecognized `crit` field |
| `AUTH.ATTESTATION_FORMAT_UNSUPPORTED` | PERSISTENT | no | yes | Attestation format not recognized; treated as `hardware_backed = false` |

### 11.5 Binding obligations, confirmed or overruled

| ID | Disposition |
|---|---|
| [docs/architecture.md](../architecture.md) **A-01** | **Confirmed, with one refinement.** `device_id` is derived from the public key (N-2). Refinement: it pins the **generation-0** key, so §3.3's `DeviceIdentity` row should record that a rotation creates a new `DeviceIdentity` **without** changing `device_id`. Without this, S-08's immutable address allocation would break on every rotation. |
| **A-02** | **Confirmed.** N-19 enumerates exactly what a confirmed `Pairing` writes on both devices; §8 shows it is complete for control-plane-free re-establishment. |
| **A-03** | **Confirmed.** §7.7: `TrustedPeer` deletion plus epoch-seed exclusion at the handshake; control-plane and relay denial are defence in depth only. |
| **A-04** | **Confirmed.** §7.5: ORK-rooted `OwnerTrustAnchor`, pinned, verified offline; the control plane holds no signing key. |
| [docs/protocol.md](../protocol.md) **A1** | **Confirmed.** IK is the RFC 7250 raw public key for L-CONTROL mTLS, giving an RFC 9266-style exporter binding for `Auth.channel_binding`. |
| **A3** | **Confirmed.** ES256 over deterministic CBOR in COSE_Sign1, verified over received octets ([ADR-0003](ADR-0003-network-contract-schema-format.md)). |
| **A5** | **Confirmed.** `RevocationRecord` and `PolicyBundle` are OSK-signed under an ORK-rooted anchor; the control plane cannot forge them. O3 was rejected precisely because it would have falsified A5. |
| **A2** | **Confirmed** (§7.6), with the honest limit that the prologue carries only values both sides hold *a priori*; the full negotiated set is confirmed in-tunnel by [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md). |
| [docs/testing-strategy.md](../testing-strategy.md) **A-06** | **Confirmed, and quantified — with a correction to what is bounded.** Peer-side enforcement survives control-plane unavailability. *Propagation* is bounded only where the device can hear: p95 ≤ 30 s via the control plane, ≤ 120 s via any updated peer (§7.7). For a peer partitioned from **both**, propagation is **unbounded** — an authority you cannot reach cannot tell you anything. `T_TRUST_HARD` = 30 d bounds the **consequence**, not the propagation: at 30 d every *granted* authority suspends, leaving baseline reachability only. A-06 asked for a propagation bound; the honest answer is "unbounded propagation, bounded consequence", and testing-strategy.md P10 must assert the latter. |
| [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.5 item 2 | **Overruled.** A TwinNet-wide PSK secret makes the epoch worthless as a revocation lever. Replaced by pairwise `PairSecret` + per-device-sealed `EpochSeed` (§7.7). ADR-0001 §7.5 must be amended. |
| [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §7.7 / K2 | **Overruled in part.** "Short `DeviceCertificate` lifetime" is replaced by mandatory 180-day TK rotation (N-21), because short certificates would create the online renewal dependency Q15 forbids. ADR-0001 §7.7 and K2 must cite TK rotation instead. |

## 12. Why the Selected Option Won

- **H4 won on C1, and nothing else came close.** H1 and H2 both put the identity key in
  software on every platform, which forfeits non-extractability and forfeits attestation
  entirely — and non-extractability is the property that makes a device compromise *end* at
  revocation instead of outliving the hardware. H3 had the best tooling and lost on its
  revocation model: CRL/OCSP is online-dependent, and I5 plus Q6 require offline verification.
  H4 also happens to be the only option that composes with
  [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) without amendment.
- **O5 won because it is the only option that survives the two failures that actually happen.**
  O1 dies on device loss, which in a two-device household is likely rather than exotic. O4 dies
  on C6: a phrase required for routine work becomes a photograph. O2 dies on C1 and on I2 — no
  secure element exposes threshold partial-signing, so the shares would be software keys, and a
  DKG protocol is exactly the "audited primitive, unaudited protocol" shape I2 forbids. O3 dies
  on A5: it would let a coerced control plane admit a device, trading prevention for
  after-the-fact detection. O5 keeps the phrase for the two events that warrant it, keeps
  routine operations hardware-resident, and gets quorum semantics from two signatures and an
  integer comparison rather than from a threshold library.
- **C-E won because Group C is not one question.** C-D authorizes but does not authenticate.
  C-B authenticates beautifully and excludes every headless target (C4, R-21). C-A covers those
  targets with a genuine PAKE and no offline attack. C-C is the only one whose security
  boundary is human attentiveness, so it is the only one where a distracted user produces
  *silent compromise* rather than a failed ceremony — which is why it is a display, not a gate.
- **The deciding argument overall is that every steady-state handshake does zero identity
  work.** All of the asymmetric cost, all of the chain verification, and all of the human
  ceremony is paid at enrolment, rotation, and revocation — a handful of events per device
  lifetime. That is what lets A-02 be true, keeps the 1-RTT budget intact, and keeps the data
  plane genuinely independent of the control plane.

## 13. Known Tradeoffs

| # | Tradeoff | Accepted because | Residual risk |
|---|---|---|---|
| K1 | Losing every admin device **and** the recovery phrase destroys the `TwinNet` | The alternative is a root the control plane can forge, which falsifies A5 | Total re-enrolment. Mitigated by N-12 and N-13, not eliminated |
| K2 | Recovery-phrase compromise is total trust-root compromise | Any offline root has this property; the phrase never transits the network | Detection only, via anchor cross-check and the transparency log |
| K3 | No cloud restore of a device identity (I4) | Exporting a key would falsify the entire trust model | Re-enrolment after every re-image or device replacement; designed as a first-class flow |
| K4 | Two keys per device that MUST stay bound | No secure element does X25519; the alternative is losing hardware custody or losing WireGuard | A skipped `TunnelKeyBinding` check is a full authentication bypass — hence N-4's non-skippable requirement and dedicated vectors |
| K5 | `device_id` is only *transitively* self-certifying after rotation | Changing `device_id` on rotation would break S-08's immutable address allocation | Verifiers must walk the succession chain; a chain-walk bug is an authentication bug |
| K6 | Two pairing ceremonies with different strengths (2^256 vs ~2^29.9 + limits) | Excluding headless targets would kill R-21 | Devices differ in ceremony strength; N-16 requires it to be recorded and surfaced rather than hidden |
| K7 | A 30-day residual revocation window for fully partitioned peers | Shortening it breaks genuinely offline deployments; I5 forbids tearing down live sessions at the boundary | A revoked device can reach a 30-day-partitioned peer. Owner-configurable within [24 h, 90 d] |
| K8 | Advancing `trust_epoch` briefly excludes legitimate peers that have not received the new seed | Accepting a lower epoch would re-admit the revoked device | Mitigated to near-zero by peer-relayable bundles (N-28) and two-epoch retention; not zero |
| K9 | Device cloning is undefended where `hardware_backed = false` | Requiring hardware backing would exclude routers and containers (C5) | Detection only (`AUTH.IDENTITY_CONCURRENT_USE`, TAI64N regression) |
| K10 | ECDSA rather than EdDSA, so C8 is a standing implementation obligation | Secure elements do P-256 and nothing else | A nonce-reuse bug in a software signer leaks the key; N-8 plus test vectors, not a structural guarantee |
| K11 | Quorum is a counting rule in our code, not a threshold signature | Threshold signing forfeits hardware custody and adds an unaudited protocol (I2) | A counting-rule bug is an authorization bypass; requires dedicated negative tests |
| K12 | `TrustEpochBundle` size grows linearly with device count | ~80 bytes per device; ~1.7 kB at n = 20 | Becomes material only well beyond the Phase 1 personal-TwinNet scale (see V6) |

## 14. Revisit Conditions

| # | Falsifiable trigger |
|---|---|
| V1 | A secure element in general availability on two or more supported platforms performs X25519 or Ed25519 private-key operations in hardware. Then H1/H2 become viable, `TunnelKeyBinding` (K4) can be retired, and the hierarchy collapses to one hardware-resident key. |
| V2 | Field telemetry shows the recovery phrase is not retained: more than **2 %** of `TwinNet`s reach the "only admin device lost, phrase lost" state (K1) within two years of creation. Then O5's recovery half is failing in practice and an `Owner`-held hardware token, or an explicitly opt-in escrow with published semantics, must be evaluated. |
| V3 | More than **10 %** of pairings use the C-A fallback for two consecutive quarters. That means headless enrolment is the common case rather than the exception, and a dedicated high-entropy headless ceremony (for example, a file-transported `PairingOffer` over an existing SSH session) should replace the 9-digit code. |
| V4 | Any single ceremony run is observed to permit more than one online guess, or SPAKE2 attempt limiting is found unenforced at any of the three enforcement points. That falsifies the §7.4 brute-force table and C-A must be suspended until repaired. |
| V5 | Measured revocation propagation exceeds **5 min at p99** for control-plane-reachable devices for two consecutive months, or any revocation is observed to take more than **24 h** to reach a device that was online throughout. The §7.7 bound is then not real and the enforcement timers must tighten. |
| V6 | A `TwinNet` routinely exceeds **64 devices**, at which point `TrustEpochBundle` size (K12) and the O(n) reseal cost per revocation stop being negligible and a group-key or per-region seed structure must be evaluated. |
| V7 | An `Owner`-scope requirement appears for more than one human `Owner` per `TwinNet` (vision §3.5 multi-owner). O5's single-phrase root does not extend to it, and the anchor's delegation model must be re-opened rather than stretched. |
| V8 | A practical attack on ES256 (P-256 ECDSA), SHA-256 collision resistance, HPKE Base mode, or SPAKE2 is published. Emergency revisit; `AUTH.IDENTITY_ALG_UNSUPPORTED` and the `twd1`/`twd2` prefix are the migration hooks. |
| V9 | A platform removes or materially restricts the attestation API this ADR depends on (`SecKeyCreateAttestation`, Android Key Attestation, `TPM2_Certify`), such that `hardware_backed` can no longer be corroborated on that platform. N-6's enrolment-time verification then has no basis there and the `Owner` policy in §7.3 must be re-scoped. |
| V10 | An independent security review finds that the two-key binding (§7.1) or the quorum counting rule (N-11) admits an authentication or authorization bypass that neither mechanism admits alone. That falsifies the central composition claim of this ADR. |
