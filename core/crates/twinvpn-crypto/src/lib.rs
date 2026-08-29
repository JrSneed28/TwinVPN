//! `twinvpn-crypto` — the ONLY crate permitted a cryptographic dependency
//! (ADR-0018 CD-I2).
//!
//! **Authority:** [ADR-0001](../../../../docs/adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)
//! §7.2 (the concrete specification), §7.3 (downgrade resistance), §7.3.1 (the
//! prologue), §7.5 (the PSK slot), §11 (the decision); ADR-0007 N-4/N-5
//! (`TunnelKeyBinding`); ADR-0018 CB-5, CB-6a, CD-I2, CD-I4, CD-4;
//! `contracts/cddl/twinvpn/v1/signed_statements.cddl`.
//!
//! **Owner:** `core-security`.
//!
//! # What this crate is, in one paragraph
//!
//! It holds the primitives, the compositions ADR-0001 §11 fixes, and nothing
//! else. It **drives no protocol**: `twinvpn-tunnel` runs the handshake and the
//! rekey schedule, `twinvpn-trust` decides what a verified statement means, and
//! `twinvpn-store` decides what a record commit means. This crate answers
//! narrow questions — *does this signature verify over these octets*, *is this
//! counter a replay*, *what is the PSK for this pair at this epoch* — and holds
//! the two keys CB-5 permits the core.
//!
//! # No novel cryptography (I2), including no novel compositions
//!
//! ADR-0001 §11 item 7:
//!
//! > "No custom primitives, no custom AEAD, no custom handshake, no custom key
//! > schedule (I2). The only TwinVPN-designed element is the composition of
//! > these layers and the HKDF derivation of `TwinNetPSK`, which uses HKDF
//! > exactly as specified."
//!
//! So the Noise state machine is [`snow`]'s, the AEAD is
//! [`chacha20poly1305`]'s, the hash is [`sha2`]'s and [`blake2`]'s, HKDF is
//! [`hkdf`]'s, ECDSA is [`p256`]'s, EdDSA is [`ed25519_dalek`]'s, X25519 is
//! [`x25519_dalek`]'s, and COSE is [`coset`]'s. What this crate writes itself is
//! the *arrangement*: [`psk`]'s derivation, [`prologue`]'s 83 bytes,
//! [`dcbor`]'s canonicity check, and the type-level gates in [`binding`] and
//! [`cose`].
//!
//! # The three gates that are types rather than comments
//!
//! | Rule | Where a comment would have gone | The type instead |
//! |---|---|---|
//! | "peers MUST verify the `TunnelKeyBinding` before trusting a static key" (ADR-0001 §11.4, K3) | a `// remember to verify` | [`binding::VerifiedTunnelKey`] has no public constructor, and [`noise::HandshakeConfig`] takes one |
//! | "VERIFIED OVER THE RECEIVED OCTETS … MUST NOT re-serialize before verifying" (CDDL rule 3) | a `// do not re-encode` | [`cose::VerifiedStatement`] has no public constructor, and [`emit::Item`] does not convert from [`dcbor::Value`] |
//! | "MUST NOT reset the L-DATA nonce counter or replay window" (ADR-0001 §7.2, §7.3.2 RS-3) | a `// do not reset` | [`replay::ReplayWindow`] has no `reset`, and its only mutation moves forward |
//!
//! # `unsafe`, and where
//!
//! This crate is the DP-4 allowlist member. Every `unsafe` block lives in
//! [`locked`] — the page-aligned allocation, the two `libc` advisory calls, the
//! deallocation, and the two slice reconstructions — and each carries a
//! `// SAFETY:` comment naming its invariant. Nothing else in the crate uses
//! `unsafe`, and [`locked`]'s module documentation states plainly what the
//! locking does and does not achieve, because TM-14 already records TK
//! extraction from process memory as undefended.
//!
//! # CD-I4: no identity private scalar, anywhere
//!
//! > "no type in the workspace may carry an identity private scalar."
//!
//! Held here by construction: [`cose::PublicVerifyingKey`] has no private
//! variant, [`cose::PublicVerifyingKey::from_cose_key`] **refuses** a COSE_Key
//! carrying `d` rather than ignoring it, and there is no signing key type in the
//! crate at all. Statements this device authors are prepared by [`emit`] and
//! signed by `twinvpn_platform::IdentityCustody`, out in the shell.

// DP-4 unsafe allowlist member: `unsafe` is permitted here and NOWHERE else.
// Every `unsafe` block MUST carry a `// SAFETY:` comment stating the invariant.
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// As in `twinvpn-types`: these fire on product and protocol nouns in prose, and
// on a crate with one uniform error type whose variants are individually
// documented.
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod aead;
pub mod binding;
pub mod blake2s;
pub mod cose;
pub mod dcbor;
pub mod deviceid;
pub mod emit;
// Private: the erasing wrapper is reachable only by holding a
// `noise::TransportSession`, which is the only thing that can own one. Making it
// public would create a second way to hold `snow` transport state, and the whole
// point of the type is that there is no such thing as an unerased one.
mod erase;
pub mod error;
pub mod kdf;
pub mod locked;
pub mod noise;
pub mod pairing_offer;
pub mod prologue;
pub mod psk;
pub mod relay_leg;
pub mod replay;
pub mod statements;

#[cfg(any(test, feature = "test-support"))]
pub mod testkit;
pub mod tk;
pub mod transcript;

pub use aead::{AeadOpenError, StoreKey};
pub use binding::{emit_tunnel_key_binding, verify_tunnel_key_binding, VerifiedTunnelKey};
pub use blake2s::{frame_mac, hrw_weight_digest, verify_frame_mac};
pub use cose::{verify_cose_sign1, x25519_cose_key, PublicVerifyingKey, VerifiedStatement};
pub use deviceid::{
    derive_device_id, derive_device_id_checked, derive_identity_id, derive_identity_id_checked,
};
pub use error::{CryptoError, Result, StatementKind};
pub use kdf::{hkdf_expand_label, hkdf_sha256, sha256, HkdfSha256};
pub use locked::{LockedBytes, LockedMemoryReport};
pub use pairing_offer::{OfferReject, PairingOffer};
pub use prologue::{IdentityBinding, NegotiationBinding, Prologue, TwinnetTag};
pub use psk::TwinNetPsk;
pub use relay_leg::{CompletedLeg, LegInitiator, LegResponder};
pub use replay::{ReplayWindow, SendCounter};
