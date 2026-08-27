# `twinvpn-trust`

Device identity, pairing, revocation, and the Owner root of trust.

**Owner:** `core-security`. **Authority:** ADR-0007 in full; `docs/architecture.md`
§2.22 and §4.5; ADR-0018 CB-5, CD-I4, CD-I5; ADR-0008 N-3 and N-7; ADR-0009
§11.4 and §11.5.

## What it decides

`twinvpn-crypto` answers "does this signature verify over these octets". This
crate answers what follows: **whose** key was that, **may** that key do this, **is
this newer** than what we hold, and **what happens now**.

| Module | Answers |
|---|---|
| `identity` | who this device is (N-2), and what a `hardware_backed` claim is worth (N-6) |
| `owner` | which anchor is pinned (S-32), which OSK may do what (N-11's quorum, including the target exclusion) |
| `peer` | may this peer's key be trusted (N-4), is it newer (N-22), how fresh is our trust (N-27) |
| `revocation` | is this peer refused (N-25(1)), and what epoch are we at (N-25(2)) |
| `policy` | did the Owner author this, and is it newer than what we enforce |
| `pairing` | did the ceremony complete on **both** devices, and is this a replay |

## Environment configuration

**None.** No clock, no randomness, no files. Every time-dependent decision takes
its reading as a parameter: `TrustedPeer::trust` takes an elapsed-seconds value
and `PolicyState::disposition` takes the caller's `ValidityClock` verdict, both
because CD-2 puts clocks behind `twinvpn_env::Env` and this crate takes none.

Identity operations are vtable calls through `SignerHandle`, which names *which*
element-resident key and carries no material (CD-I4).

## Local startup and debugging

```bash
source build/toolchain/env.sh
cd core
cargo test -p twinvpn-trust   # 61 tests
```

`RUST_LOG` has no effect: this crate emits no `tracing` events. Its outputs are
typed values and `TrustError`s carrying registered `AUTH.*` codes.

### Reading a refusal

| Code | What it means, and what it does **not** |
|---|---|
| `AUTH.DEVICE_REVOKED` | terminal. Refuses the handshake and requires a teardown |
| `AUTH.TRUST_EPOCH_ROLLBACK` | a lower monotone value was **refused, not applied**. The state is unchanged |
| `AUTH.TRUST_HISTORY_FORKED` | detection only. The refusal it accompanied has already landed |
| `AUTH.TRUST_STATE_STALE` | 24 h without refresh. The session goes `DEGRADED`; connectivity continues |
| `AUTH.TRUST_STATE_EXPIRED` | 30 d without refresh. **Granted** authority is suspended. It does **not** refuse a handshake to a known peer (R-11) and does **not** tear down a session (I5) |
| `AUTH.BINDING_INVALID` | the `TunnelKeyBinding` did not verify or named a different device |
| `AUTH.PAIRING_*` | four distinct user problems with four distinct next actions; never coarsened into one |

## The three rules a reviewer should check first

1. **No `un_revoke`.** `RevocationState` holds a set that only grows and an epoch
   that only rises (ADR-0008 N-7). There is no removal method.
2. **No unverified tunnel key.** `TrustedPeer` can only be built from a
   `twinvpn_crypto::VerifiedTunnelKey`, which has no public constructor (N-4).
3. **No policy from a non-Owner.** `PolicyState::offer` checks the signer
   **before** the version, so a wrong-signer bundle can never advance the
   high-water mark whatever version it claims.

## Known gap, stated

**SPAKE2 (ceremony C-A) is not implemented, and the seam stays empty by
integration-lead ruling.**

N-17 requires SPAKE2 **RFC 9382 with the RFC-specified P-256 parameters**.
Nothing on crates.io meets both that and ADR-0018 DP-3's requirement of "a
published independent audit or an assurance argument recorded in the dependency
ledger": the well-known `spake2` crate is Ed25519-group rather than RFC 9382
P-256, and the crates that do claim RFC 9382 are obscure and unaudited. Adding
one would be a worse I2/DP-3 violation than leaving the seam, and DP-3 makes
this a ledger decision rather than a dependency bump inside an implementation
wave. `pairing::Spake2Exchange` is the seam; **do not fill it with a PAKE.**
Substituting a hash comparison is separately forbidden — N-15: "A ceremony whose
transcript permits offline dictionary attack on a 9-digit human-entered secret
MUST NOT be implemented."

**What this blocks is narrower than "headless pairing".** ADR-0007 §11 C-E makes
C-A the *fallback* channel authenticator and C-B the primary, and ADR-0007
§7.4's table reads "C-B (QR) where a camera and a screen exist; C-A otherwise".
But N-24d and **ADR-0023 EM-21** supersede the optical reading:

> "the C-B ceremony **does not require a camera; it requires a confidential
> channel** … An operator's authenticated shell session on the device, plus
> their own eyes, is another, and it carries the same 256 bits. **Headless
> targets therefore use C-B, unchanged, and do not fall back to C-A's
> ~2^29.9.**"

ADR-0023 EM-22 gives four such channels — terminal QR, text offer, reverse
ceremony, first-boot provisioning — all C-B at 256 bits. So headless, CLI and
embedded pairing are **not** blocked by the empty C-A seam. What is blocked is
the residue: a device with **no confidential out-of-band channel of any kind**,
where the nine-digit PAKE code is the only remaining channel authenticator.

**The honest limit on C-B, which is a separate gap.** The ceremony-agnostic half
is implemented and tested here — the five-attempt budget, the 120-second window,
the single-use `pairing_id`, the idempotency rules, the mutual-attestation
check — and it is shared by both ceremonies. **`PairingOffer` is not**: ADR-0007
§7.4 defines it as a deterministic-CBOR payload, it appears nowhere in
`contracts/`, and this crate has no decoder for it. Until someone owns that
payload, C-B is not end-to-end either. Reported to the integration lead.

## Features

| Feature | Default | Contents |
|---|---|---|
| `test-support` | off | `testkit` — builds a `VerifiedTunnelKey` the only way one can be built, by signing and verifying a real `TunnelKeyBinding`. Never enabled in a shipped build |
