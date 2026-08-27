# `twinvpn-crypto`

The **only** crate permitted a cryptographic dependency (ADR-0018 CD-I2), and
the DP-4 `unsafe` allowlist member.

**Owner:** `core-security`. **Authority:** ADR-0001 §7.2, §7.3, §7.3.1, §7.5,
§11; ADR-0007 N-4/N-5; ADR-0018 CB-5, CB-6a, CD-I2, CD-I4, CD-4;
`contracts/cddl/twinvpn/v1/signed_statements.cddl`.

## What it is

Primitives, and the compositions ADR-0001 §11 fixes. It drives no protocol:
`twinvpn-tunnel` runs the handshake and the rekey schedule, `twinvpn-trust`
decides what a verified statement *means*, `twinvpn-store` decides what a commit
means.

| Module | Contents |
|---|---|
| `noise` | `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` over `snow`, the §7.2 rekey constants, the stateless transport |
| `psk` | `TwinNetPSK(A,B,epoch)` — the one TwinVPN-designed derivation. **ADR-0007 §7.7 lines 654-657 is the operative text**; ADR-0001 §7.5 writes it with an ellipsis and is overruled by ADR-0007 §10. Pinned with a golden vector |
| `prologue` | the 83-byte §7.3.1 prologue and its two contributed digests |
| `binding` | `TunnelKeyBinding` verification; `VerifiedTunnelKey` has **no public constructor** |
| `cose` | COSE_Sign1 verification **over the received octets**; `VerifiedStatement` has **no public constructor** |
| `dcbor` | a strict RFC 8949 §4.2.1 parser that validates canonicity while reading, and never normalizes |
| `emit` | the deterministic encoder for statements this device authors; `Item` does **not** convert from `dcbor::Value` |
| `statements` | the seventeen B2 statement types, decodable only from a `VerifiedStatement` |
| `replay` | the 8192-bit RFC 6479 window and the send counter; neither can be reset |
| `transcript` | §7.3 D2's constant-time confirmation and the S-37 monotone floor |
| `aead` | XChaCha20-Poly1305 record sealing and the ADR-0020 §11.6 key hierarchy |
| `locked` | the `mlock`/`MADV_DONTDUMP` allocator for `TK` and `SEK` (CB-5 rows 2 and 3) |
| `kdf` | HKDF-SHA-256, `HKDF-Expand-Label`, and the CD-4 `StreamDerivation` binding |

## Environment configuration

**None.** CD-2: everything time- or randomness-related arrives as
`twinvpn_env::Env`, passed at construction. This crate reads no environment
variable, no file, and no global. `Handshake::new` and `aead::seal` take an
`&Env` and draw their randomness from `Env::entropy()`.

## Local startup and debugging

It is a library; there is nothing to start. To exercise it:

```bash
source build/toolchain/env.sh
cd core
cargo test -p twinvpn-crypto                       # 95 unit tests
cargo test -p twinvpn-crypto --test signed_statements  # 29 attack tests
cargo test -p twinvpn-crypto --test noise_handshake    # 8 end-to-end tests
```

`RUST_LOG` has no effect: this crate emits no `tracing` events, because every
value it handles is either a key, a nonce, or a payload.

**What is never logged:** anything. `LockedBytes`, `StoreKey`, `TwinNetPsk` and
`Prologue` all have hand-written `Debug` impls that render a length and a
protection tag and nothing else, and each has a test asserting it.

### When a verification fails

Every failure is a `CryptoError` carrying a registered `reason_code`. The
`step` and `kind` fields name the structural check that failed and never carry
content, so a `Debug` of one is safe to log.

- `PROTO.NON_CANONICAL_CBOR` — the octets are not RFC 8949 §4.2.1. `step` names
  the rule: `non-shortest argument`, `indefinite length`, `map keys unsorted or
  duplicated`, `trailing bytes`, …
- `PROTO.UNKNOWN_CRITICAL_FIELD` — a `crit` member this build does not
  understand, or a required one omitted. Update the client; do not relax it.
- `AUTH.BINDING_INVALID` — the `TunnelKeyBinding` did not verify or named a
  different device. A skipped check here is a full authentication bypass.
- `CRYPTO.HANDSHAKE_REJECTED` — deliberately indistinguishable between causes
  (§7.3.1 P-3, and A1's silence on unauthenticated input).

## The `twinnet_id` has two encodings

Deliberately, because the two sites impose opposite constraints:

- **`prologue`** contracts it to `SHA-256(twinnet_id)[0..16]`, because §7.3.1's
  `identity_binding_hash` is a preimage of concatenated **fixed-width** fields
  and declares `twinnet_id(16)`, while `contracts/` declares the identifier a
  `tstr .size (1..64)`.
- **`psk`** uses the **raw UTF-8 bytes**, because ADR-0007 §7.7's
  `salt = twinnet_id || e (u64 BE)` feeds HKDF, whose salt is variable-length by
  construction (RFC 5869 §2.2).

`the_twinnet_contraction_is_for_the_prologue_and_not_for_the_psk_salt` pins the
distinction. Applying one answer at the other site breaks interoperability in
one direction and field alignment in the other.

## `unsafe`

Every `unsafe` block is in `locked.rs` — the page-aligned allocation, the two
`libc` advisory calls, the deallocation, the two slice reconstructions, and the
`Send`/`Sync` impls. Each carries a `// SAFETY:` comment naming its invariant.
Nothing else in the crate uses `unsafe`.

`locked.rs`'s module documentation states plainly what the locking does and does
**not** achieve on Linux without privileges. It does not stop `ptrace`,
`/proc/<pid>/mem`, or a debugger running as the same user — `docs/threat-model.md`
TM-14 already records TK extraction from process memory as undefended.

## Features

| Feature | Default | Contents |
|---|---|---|
| `test-support` | off | `testkit::FixtureIdentity` — deterministic ES256 signing for other crates' tests. CD-I2 covers dev-dependencies, so a crate that needs a signature in a test takes it from here rather than naming `p256` itself. Never enabled in a shipped build |
