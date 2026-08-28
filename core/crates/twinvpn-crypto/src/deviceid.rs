//! `identity_id` and `device_id` — the N-2 derivation.
//!
//! **Authority:** `contracts/docs/identifiers.md` §2, ADR-0007 N-2 and Q1,
//! `contracts/proto/twinvpn/v1/identity.proto`.
//!
//! # Why this primitive lives in `twinvpn-crypto`
//!
//! It is SHA-256 over deterministic CBOR of a COSE_Key. All three of those are
//! this crate's — [`crate::dcbor`] enforces the encoding rules, [`crate::cose`]
//! parses the key, and [`crate::sha256`] is the hash — so this is where the
//! derivation belongs, not in a crate that happened to need it first.
//!
//! The practical reason is CD-I5's shape: `twinvpn-trust` is the
//! control-plane-**client**-side trust engine, and `services/Cargo.toml` does
//! not permit a service artifact an edge to it. `services/rendezvous` and
//! `services/presence` need this derivation to bind a TLS channel identity to a
//! claimed `device_id`, and both correctly refused to re-implement it, citing
//! W-23. A hash should not drag a trust engine into three server artifacts, so
//! the hash moved instead. `twinvpn-trust` re-exports it and nothing that
//! already called it changed.
//!
//! # The derivation, quoted
//!
//! `identifiers.md` §2:
//!
//! ```text
//! identity_id = SHA-256("TwinVPN/DeviceIdentity/v1" || 0x00 || dCBOR(COSE_Key(IK_pub)))
//! device_id   = identity_id of generation 0
//! ```
//!
//! Every byte matters, and the `0x00` most of all: it separates a fixed-length
//! label from a variable-length encoding, and dropping it would change every
//! `device_id` in the fleet.
//!
//! # Checked and unchecked, and which to use
//!
//! The derivation is defined over **deterministic** CBOR, so a non-canonical
//! encoding of the same key yields a different `identity_id` — a different
//! device. Two entry points, because the two callers genuinely differ:
//!
//! | Function | Use when |
//! |---|---|
//! | [`derive_identity_id`] / [`derive_device_id`] | the octets came from a source that has **already** proved them canonical — a [`crate::VerifiedStatement`]'s payload, or this crate's own [`crate::emit`] encoder |
//! | [`derive_identity_id_checked`] / [`derive_device_id_checked`] | the octets came from anywhere else. A server deriving a `device_id` from a key presented on a wire is this case |
//!
//! The checked pair rejects rather than normalizing, which is the same rule the
//! signed statements get and for the same reason: normalizing attacker input
//! before deriving an identifier from it lets one key claim two names.

use twinvpn_types::{DeviceId, IdentityId};

use crate::cose::PublicVerifyingKey;
use crate::error::StatementKind;
use crate::kdf::sha256;
use crate::{CryptoError, Result};

/// The N-2 domain label, verbatim from `identifiers.md` §2.
pub const IDENTITY_LABEL: &[u8] = b"TwinVPN/DeviceIdentity/v1";

/// The single-byte separator between the label and the key encoding.
///
/// Named rather than inlined because it is the easiest byte in the corpus to
/// drop by accident and the most expensive to drop: without it, a key encoding
/// beginning with the tail of the label would collide with a different one, and
/// every `device_id` would move.
pub const IDENTITY_SEPARATOR: u8 = 0x00;

/// Derives `identity_id` from a **canonical** dCBOR COSE_Key.
///
/// The caller asserts the encoding is canonical. Where that is not already
/// established, use [`derive_identity_id_checked`].
#[must_use]
pub fn derive_identity_id(ik_pub_cose: &[u8]) -> IdentityId {
    let mut buf = Vec::with_capacity(IDENTITY_LABEL.len() + 1 + ik_pub_cose.len());
    buf.extend_from_slice(IDENTITY_LABEL);
    buf.push(IDENTITY_SEPARATOR);
    buf.extend_from_slice(ik_pub_cose);
    IdentityId::from_array(sha256(&buf))
}

/// Derives `device_id` from the **generation-0** identity key.
///
/// `identifiers.md` §2: "The generation-0 `identity_id` **is** the `device_id`."
/// Passing a later generation's key produces a value that is not this device's
/// name, which is why the parameter is named for what it must be.
#[must_use]
pub fn derive_device_id(generation_zero_ik_pub_cose: &[u8]) -> DeviceId {
    derive_identity_id(generation_zero_ik_pub_cose).as_generation_zero_device_id()
}

/// Derives `identity_id`, first proving the octets are what the derivation is
/// defined over.
///
/// Two checks, in order:
///
/// 1. RFC 8949 §4.2.1 core deterministic encoding — because the derivation says
///    `dCBOR`, and a non-canonical encoding of one key derives two names;
/// 2. that it is a COSE_Key this build recognises as an **identity** key
///    (ADR-0007 N-1 fixes ES256), so an identifier is never derived from
///    something that is not the thing it claims to name.
///
/// # Errors
///
/// [`CryptoError::NonCanonicalCbor`] or [`CryptoError::IdentityAlgUnsupported`].
pub fn derive_identity_id_checked(ik_pub_cose: &[u8]) -> Result<IdentityId> {
    crate::dcbor::require_canonical(ik_pub_cose)
        .map_err(|e| e.into_crypto_error(StatementKind::DeviceIdentityRecord))?;
    match PublicVerifyingKey::from_cose_key(ik_pub_cose, StatementKind::DeviceIdentityRecord)? {
        PublicVerifyingKey::Es256(_) => Ok(derive_identity_id(ik_pub_cose)),
        // An Ed25519 COSE_Key is a valid key and is used for the
        // relay-credential issuer, so it parses — and must be refused *here*,
        // where the role is device identity (N-1).
        PublicVerifyingKey::Ed25519(_) => Err(CryptoError::IdentityAlgUnsupported {
            algorithm: "an identity key must be ES256 (ADR-0007 N-1)",
        }),
    }
}

/// Derives `device_id` from a **generation-0** identity key, with
/// [`derive_identity_id_checked`]'s checks.
///
/// # Errors
///
/// As [`derive_identity_id_checked`].
pub fn derive_device_id_checked(generation_zero_ik_pub_cose: &[u8]) -> Result<DeviceId> {
    derive_identity_id_checked(generation_zero_ik_pub_cose)
        .map(IdentityId::as_generation_zero_device_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_types::Identifier;

    /// The NIST P-256 generator `G`, from SP 800-186 / SEC 2.
    ///
    /// A **publicly specified point that is genuinely on the curve**, so the
    /// fixture is a valid key and the checked path accepts it. An arbitrary
    /// 32-byte pattern is not a point, and `derive_identity_id_checked` refuses
    /// it — correctly, which is how this fixture came to be a real point.
    const GX: [u8; 32] = [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ];
    const GY: [u8; 32] = [
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
        0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
        0x51, 0xf5,
    ];

    /// A canonical dCBOR COSE_Key for EC2/P-256, assembled from raw octets so
    /// the golden vector below does not depend on this crate's own encoder.
    ///
    /// `{1: 2, -1: 1, -2: bstr(32) Gx, -3: bstr(32) Gy}`, keys in canonical
    /// order (`0x01`, `0x20`, `0x21`, `0x22`). Anyone can rebuild these bytes
    /// from SP 800-186 and RFC 9052 and re-derive the vector below.
    fn handmade_cose_key() -> Vec<u8> {
        let mut k = vec![0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20];
        k.extend_from_slice(&GX);
        k.extend_from_slice(&[0x22, 0x58, 0x20]);
        k.extend_from_slice(&GY);
        k
    }

    /// **The golden vector**, taken from `contracts/docs/identifiers.md` §2's
    /// text and computed outside this code.
    ///
    /// ```text
    /// identity_id = SHA-256("TwinVPN/DeviceIdentity/v1" || 0x00 || dCBOR(COSE_Key(IK_pub)))
    /// ```
    ///
    /// Same discipline as the corrected `TwinNetPSK` vector and for the same
    /// reason: two implementations of one identifier is how devices end up with
    /// different names for each other. Moving this literal renames every device
    /// in the fleet.
    #[test]
    fn the_derivation_matches_identifiers_md_section_2() {
        let id = derive_identity_id(&handmade_cose_key());
        assert_eq!(
            id.to_hex(),
            "dbf92e8931ed0d297354a7faa2f0dc8bdb70df9696fadf83b33911649ceead03"
        );
        assert_eq!(id.as_bytes().len(), 32, "untruncated");
    }

    /// The preimage is exactly label ‖ 0x00 ‖ key, assembled here independently.
    #[test]
    fn the_preimage_is_the_label_the_separator_and_the_key() {
        let key = handmade_cose_key();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"TwinVPN/DeviceIdentity/v1");
        expected.push(0x00);
        expected.extend_from_slice(&key);
        assert_eq!(derive_identity_id(&key).as_bytes(), &sha256(&expected));
        assert_eq!(IDENTITY_LABEL, b"TwinVPN/DeviceIdentity/v1");
        assert_eq!(IDENTITY_SEPARATOR, 0x00);
    }

    /// **Attack test.** The separator is what stops a key encoding that begins
    /// with the tail of the label from colliding with a different one.
    #[test]
    fn the_separator_prevents_a_label_boundary_collision() {
        assert_ne!(derive_identity_id(b"\x00X"), derive_identity_id(b"X"));
    }

    #[test]
    fn the_generation_zero_identity_is_the_device_id() {
        let key = handmade_cose_key();
        assert_eq!(
            derive_device_id(&key).as_bytes(),
            derive_identity_id(&key).as_bytes()
        );
    }

    /// **Attack test.** The derivation is over *deterministic* CBOR, so a
    /// second encoding of one key must be refused rather than normalized — a
    /// normalizing derivation would let one key claim two names.
    #[test]
    fn a_non_canonical_cose_key_is_refused_by_the_checked_path() {
        let good = handmade_cose_key();
        derive_identity_id_checked(&good).expect("canonical");

        // The map head 0xa4 rewritten as 0xb8 0x04: same logical value, second
        // encoding, forbidden by RFC 8949 §4.2.1 (a).
        let mut bad = vec![0xb8, 0x04];
        bad.extend_from_slice(&good[1..]);
        let err = derive_identity_id_checked(&bad).expect_err("must refuse");
        assert_eq!(err.reason_code().as_str(), "PROTO.NON_CANONICAL_CBOR");

        // And the two encodings genuinely derive different names, which is why
        // the check is not cosmetic.
        assert_ne!(derive_identity_id(&good), derive_identity_id(&bad));
    }

    /// **Attack test.** N-1 fixes ES256 for the identity key. A valid key of
    /// another kind must not be given a `device_id`.
    #[test]
    fn a_non_es256_key_is_refused_by_the_checked_path() {
        // OKP/X25519 — a well-formed agreement key, and not an identity.
        let mut k = vec![0xa3, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20];
        k.extend_from_slice(&[0x11; 32]);
        assert!(derive_identity_id_checked(&k).is_err());
        assert!(derive_device_id_checked(&k).is_err());
    }

    /// The checked and unchecked paths agree whenever the checked one accepts.
    /// If they could diverge, the choice between them would be a choice of
    /// identifier.
    #[test]
    fn the_checked_and_unchecked_paths_agree_on_canonical_input() {
        let key = handmade_cose_key();
        assert_eq!(
            derive_identity_id_checked(&key).expect("canonical"),
            derive_identity_id(&key)
        );
        assert_eq!(
            derive_device_id_checked(&key).expect("canonical"),
            derive_device_id(&key)
        );
    }

    /// Distinct keys get distinct names.
    ///
    /// Exercises the **unchecked** path deliberately: flipping a coordinate bit
    /// leaves a point that is not on the curve, which the checked path would
    /// refuse before hashing. The property under test is the hash's, not the
    /// curve's.
    #[test]
    fn a_different_key_derives_a_different_identity() {
        let a = handmade_cose_key();
        let mut b = a.clone();
        b[8] ^= 0x01;
        assert_ne!(derive_identity_id(&a), derive_identity_id(&b));
    }
}
