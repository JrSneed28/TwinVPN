//! SPKI → dCBOR COSE_Key, the one conversion that must not exist twice.
//!
//! **Authority:** `contracts/docs/identifiers.md` §2 (the `device_id`
//! derivation), ADR-0007 N-1 (an identity key is ES256), RFC 5480 §2 (the
//! `SubjectPublicKeyInfo` for an EC key), RFC 8949 §4.2.1 (deterministic CBOR),
//! RFC 9052 §7 (COSE_Key), and finding **RZ-8**.
//!
//! # Why this is here and not in the services
//!
//! The RFC 7250 channel identity a TLS peer presents is a
//! `SubjectPublicKeyInfo`. `twinvpn_crypto::derive_device_id_checked` takes a
//! **dCBOR COSE_Key**. Something has to convert one to the other, and that
//! conversion is a **specified encoding** — the exact map
//! `{1: 2, -1: 1, -2: x, -3: y}`, canonically encoded — not a convenience.
//! RZ-8's finding is that a specified encoding must not exist in two places,
//! because two copies that disagree by one byte derive two different names for
//! one device, and nothing fails until a device cannot bind.
//!
//! So there is one copy, here, and the four service domains call it.
//!
//! # Why the parse is a byte-exact match rather than a DER walk
//!
//! DER is canonical, and for one key type — `id-ecPublicKey` with `prime256v1`
//! and an uncompressed point — every length and every tag is determined. There
//! is exactly one valid encoding, it is 91 bytes, and 26 of them are fixed.
//! Matching those 26 bytes is not a shortcut past a parser; it **is** the
//! specification, and it means there is no parser here to get wrong on an
//! attacker-reachable input (ADR-0003 R7's argument, one layer down).
//!
//! Strictness is safe here in a way it usually is not, and the reason is worth
//! stating plainly: **a conversion failure is not a refusal.** A key this module
//! cannot convert simply does not *prove* a claim, and the caller falls back to
//! pinning (see [`super::DerivedPreferred`]). Nothing is locked out by being
//! strict — the only cost is that such a device gets the weaker binding, which is
//! exactly what it would have had anyway.
//!
//! # What it refuses
//!
//! Anything that is not that encoding: a compressed point, an Ed25519 or RSA
//! key, a truncated or padded SPKI. And `derive_device_id_checked` then refuses
//! anything this module produced that is not a point on the curve — so a
//! malformed input is rejected rather than hashed into **some other device's
//! name**, which is the failure that would matter.

use twinvpn_types::DeviceId;

use crate::tls::ChannelIdentity;

/// The fixed prefix of a P-256 `SubjectPublicKeyInfo` carrying an uncompressed
/// point, RFC 5480 §2:
///
/// ```text
/// 30 59            SEQUENCE (89)
///    30 13         SEQUENCE (19)
///       06 07 2A 86 48 CE 3D 02 01        OID 1.2.840.10045.2.1   id-ecPublicKey
///       06 08 2A 86 48 CE 3D 03 01 07     OID 1.2.840.10045.3.1.7 prime256v1
///    03 42 00      BIT STRING (66), 0 unused bits
/// ```
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// The SEC 1 tag for an uncompressed point.
const SEC1_UNCOMPRESSED: u8 = 0x04;

/// Exactly 91 bytes: the prefix, the tag, and two 32-byte coordinates.
pub const P256_SPKI_LEN: usize = 26 + 1 + 32 + 32;

/// Why an SPKI could not be converted.
///
/// Carries **no bytes**. A conversion failure is reported alongside a claim, and
/// a claim's diagnostics must not become a channel for echoing what a peer
/// presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SpkiError {
    /// Not 91 bytes, so not a P-256 SPKI with an uncompressed point.
    #[error("the presented key is not a 91-byte P-256 SubjectPublicKeyInfo")]
    WrongLength,
    /// The algorithm identifier is not `id-ecPublicKey` with `prime256v1`, or
    /// the DER framing differs. An Ed25519 or RSA key lands here, as does a
    /// compressed point.
    #[error("the presented key is not an uncompressed-point P-256 key")]
    NotP256Uncompressed,
}

/// Why a `device_id` could not be derived from a channel identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DerivationError {
    /// The SPKI is not the one encoding this module converts.
    #[error(transparent)]
    Spki(#[from] SpkiError),
    /// The COSE_Key was built but `twinvpn-crypto` refused it — most usually a
    /// coordinate pair that is not a point on P-256.
    ///
    /// Carries a **static** description, never the key.
    #[error("the presented key is not a usable ES256 identity key")]
    NotAnIdentityKey,
}

/// Converts an RFC 7250 P-256 `SubjectPublicKeyInfo` into the dCBOR COSE_Key the
/// `device_id` derivation is defined over.
///
/// The output is `{1: 2, -1: 1, -2: x, -3: y}` in RFC 8949 §4.2.1 core
/// deterministic encoding — byte-identical to what a device encodes when it
/// derives its own `device_id`, which is the whole requirement.
///
/// # Errors
///
/// [`SpkiError`], for anything that is not that exact encoding.
pub fn spki_to_es256_cose_key(spki: &[u8]) -> Result<Vec<u8>, SpkiError> {
    if spki.len() != P256_SPKI_LEN {
        return Err(SpkiError::WrongLength);
    }
    if spki[..P256_SPKI_PREFIX.len()] != P256_SPKI_PREFIX {
        return Err(SpkiError::NotP256Uncompressed);
    }
    let point = &spki[P256_SPKI_PREFIX.len()..];
    if point[0] != SEC1_UNCOMPRESSED {
        return Err(SpkiError::NotP256Uncompressed);
    }
    // The map itself is `twinvpn-crypto`'s to build, not this module's. RZ-8 is
    // the finding that a specified encoding must not exist in two places, and
    // assembling `{1: 2, -1: 1, -2: x, -3: y}` here was the second place —
    // in a different workspace from the device that derives its own name the
    // same way. CD-I2 says the same thing from the other end: a key encoding
    // belongs to the one crate permitted a cryptographic dependency.
    //
    // What stays here is the DER half: proving these 91 bytes are that exact
    // SPKI, and finding the two coordinates inside it.
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&point[1..33]);
    y.copy_from_slice(&point[33..65]);
    Ok(twinvpn_crypto::cose::es256_cose_key(&x, &y))
}

/// Derives the `device_id` a channel identity speaks for, if it speaks for one.
///
/// Uses `derive_device_id_checked`, **not** the unchecked form: these octets came
/// off a wire, which is precisely the case the checked pair exists for. It proves
/// RFC 8949 §4.2.1 canonicality and ES256 before hashing, so a wrong conversion
/// is rejected rather than silently hashed into a wrong name.
///
/// That check does **not** make a *duplicated* conversion safe — two copies that
/// disagree both produce canonical CBOR, of two different keys. Only being
/// single-homed does that, which is why this function has one home.
///
/// # Errors
///
/// [`DerivationError`].
pub fn derive_device_id_for(channel: &ChannelIdentity) -> Result<DeviceId, DerivationError> {
    let cose = spki_to_es256_cose_key(channel.as_bytes())?;
    twinvpn_crypto::derive_device_id_checked(&cose).map_err(|_| DerivationError::NotAnIdentityKey)
}
