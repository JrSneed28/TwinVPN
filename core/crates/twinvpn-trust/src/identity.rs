//! Device identity: the N-2 derivation, the use-site protocol, and the
//! attestation record.
//!
//! **Authority:** ADR-0007 N-1..N-8, N-24; ADR-0018 CB-5 and CD-I4;
//! `contracts/proto/twinvpn/v1/identity.proto`;
//! `contracts/docs/identifiers.md` §2.
//!
//! # CD-I4, and what this module deliberately cannot do
//!
//! > "no type in the workspace may carry an identity private scalar. Identity
//! > operations are vtable calls out to the shell via `twinvpn-platform`'s
//! > `IdentityCustody`."
//!
//! So [`SignerHandle`] wraps an `Arc<dyn IdentityCustody>` and an
//! [`twinvpn_platform::custody::IdentityKeyRef`] — *which* key, never the key.
//! There is no field, method, or constructor in this module that accepts or
//! returns private key material, and `IdentityCustody` has none to return.
//!
//! # N-2, exactly
//!
//! > "`identity_id` MUST be `SHA-256("TwinVPN/DeviceIdentity/v1" || 0x00 ||
//! > dCBOR(COSE_Key(IK_pub)))`, untruncated. `device_id` MUST be the
//! > `identity_id` of **generation 0** and MUST NOT change on rotation."
//!
//! [`derive_identity_id`] is that expression and nothing else. The `0x00`
//! separator is present because the ADR writes it; dropping it would produce a
//! different `device_id` for every device in the fleet.
//!
//! # N-7: a missing identity is never replaced
//!
//! > "If IK cannot be loaded, the `Device` MUST fail closed with
//! > `AUTH.IDENTITY_MISSING` or `AUTH.KEY_STORE_UNAVAILABLE` and **MUST NOT
//! > generate a replacement identity**."
//!
//! There is no key-generation function in this crate. Generating an identity is
//! an enrolment ceremony performed inside the platform element, and the core has
//! no API that could do it by accident.

use std::sync::Arc;

use twinvpn_crypto::{PublicVerifyingKey, StatementKind};
use twinvpn_platform::custody::{
    IdentityAttestation, IdentityCustody, IdentityKeyRef, IdentityPublic, Signature,
};
use twinvpn_types::{DeviceId, Identifier};

use crate::error::{Result, TrustError};

/// The N-2 derivation, re-exported from where it now lives.
///
/// # Why it moved, and why this re-export exists
///
/// `identity_id = SHA-256("TwinVPN/DeviceIdentity/v1" || 0x00 ||
/// dCBOR(COSE_Key(IK_pub)))` is SHA-256 over deterministic CBOR of a COSE_Key —
/// all three of which are `twinvpn-crypto`'s. It was implemented here first
/// because this is where identity lives, but `services/rendezvous` and
/// `services/presence` need it to bind a TLS channel identity to a claimed
/// `device_id`, and `services/Cargo.toml` does not permit a service artifact an
/// edge to `twinvpn-trust` — CD-I5 puts this crate on the control-plane-client
/// side, and a hash should not drag a trust engine into three server artifacts.
///
/// Both services correctly refused to re-implement it, citing W-23: a specified
/// derivation is not ours to improve, and a wrong one here names the wrong
/// device. So the primitive moved to [`twinvpn_crypto::deviceid`] and this
/// re-export keeps every existing call site unchanged.
///
/// `identity_derivation_agrees_across_both_paths` asserts the two paths produce
/// identical bytes, so the re-export cannot drift from the original.
pub use twinvpn_crypto::deviceid::{
    derive_device_id, derive_device_id_checked, derive_identity_id, derive_identity_id_checked,
    IDENTITY_LABEL,
};

/// Checks a server's `device_id_echo` against the local derivation.
///
/// `device.proto`: the echo is "an echo, never an assignment", and a device
/// "MUST abort with `AUTH.IDENTITY_MISMATCH` on disagreement rather than adopt
/// the server's value".
///
/// # Errors
///
/// [`TrustError::IdentityMismatch`].
pub fn check_device_id_echo(local: &DeviceId, echoed: &[u8]) -> Result<()> {
    // Compared as bytes of the *derived* value, never adopted. There is
    // deliberately no function in this crate that writes a `device_id` from a
    // wire field.
    if local.as_bytes() == echoed {
        Ok(())
    } else {
        Err(TrustError::IdentityMismatch)
    }
}

/// A handle to an element-resident signing key (CB-5, CD-I4).
///
/// Names *which* key and how to reach the element. Carries no key material and
/// has no method that could return any — `IdentityCustody`'s surface is
/// `sign`, `agree`, `public_identity` and `attestation`, and none of them
/// returns a private half.
#[derive(Clone)]
pub struct SignerHandle {
    custody: Arc<dyn IdentityCustody>,
    key: IdentityKeyRef,
}

impl SignerHandle {
    /// Names a key held inside the element.
    #[must_use]
    pub fn new(custody: Arc<dyn IdentityCustody>, key: IdentityKeyRef) -> Self {
        Self { custody, key }
    }

    /// Which key this handle names.
    #[must_use]
    pub const fn key(&self) -> IdentityKeyRef {
        self.key
    }

    /// Signs `message` inside the element.
    ///
    /// The message is the `Sig_structure` from
    /// [`twinvpn_crypto::emit::StatementToSign::to_be_signed`]. This crate never
    /// builds a signature itself.
    ///
    /// # Errors
    ///
    /// [`TrustError::KeyUnavailable`] on a locked device, a revoked entitlement,
    /// or an element that has lost its backing.
    pub async fn sign(&self, message: &[u8]) -> Result<Signature> {
        self.custody
            .identity_sign(self.key, message)
            .await
            .map_err(Into::into)
    }

    /// The public identity, its generation, and its identifiers.
    ///
    /// # Errors
    ///
    /// [`TrustError::KeyUnavailable`].
    pub async fn public_identity(&self) -> Result<IdentityPublic> {
        self.custody.public_identity().await.map_err(Into::into)
    }

    /// The platform's truthful hardware-backing report (ADR-0018 §11.16 (l)).
    ///
    /// # Errors
    ///
    /// [`TrustError::KeyUnavailable`].
    pub async fn attestation(&self) -> Result<IdentityAttestation> {
        self.custody
            .identity_attestation()
            .await
            .map_err(Into::into)
    }
}

impl core::fmt::Debug for SignerHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignerHandle")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// What a peer's `hardware_backed` claim is actually worth.
///
/// N-6: "A peer MUST NOT treat an **unattested** `hardware_backed = true` as
/// evidence." Three states rather than a `bool`, because a `bool` cannot
/// distinguish "attested true" from "claimed true", and the whole rule is that
/// distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareBacking {
    /// Claimed and verified against a platform attestation.
    Attested,
    /// Claimed but **not** attested. Recorded, never treated as evidence.
    ClaimedUnattested,
    /// Not claimed.
    None,
}

impl HardwareBacking {
    /// Whether this may be used as evidence in an authorization decision.
    ///
    /// Only [`HardwareBacking::Attested`] may. A call site that wanted the
    /// looser reading would have to write `!= None`, which is visible.
    #[must_use]
    pub const fn is_evidence(self) -> bool {
        matches!(self, HardwareBacking::Attested)
    }
}

/// A peer's attestation record, as this device holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationRecord {
    /// What the claim is worth (N-6).
    pub backing: HardwareBacking,
    /// The attestation format tag, where the platform produced one.
    pub format: Option<String>,
}

impl AttestationRecord {
    /// Evaluates a claim against an attestation.
    ///
    /// `verified` is the caller's result from checking the attestation chain
    /// against a trusted platform root — a platform-specific operation that is
    /// not this crate's. Passing `false` for a device whose platform produces no
    /// attestation is correct and is **not** a failure: N-6 says the peer must
    /// not treat the claim as evidence, not that it must refuse the peer.
    #[must_use]
    pub fn evaluate(claim: bool, verified: bool, format: Option<&str>) -> Self {
        let backing = match (claim, verified) {
            (true, true) => HardwareBacking::Attested,
            (true, false) => HardwareBacking::ClaimedUnattested,
            (false, _) => HardwareBacking::None,
        };
        Self {
            backing,
            format: format.map(ToOwned::to_owned),
        }
    }

    /// Whether a transition from `previous` to `self` is the N-24 downgrade.
    ///
    /// > "A downgrade of `hardware_backed` MUST force IK rotation and
    /// > re-attestation, and peers MUST surface `AUTH.HARDWARE_BACKING_LOST`."
    ///
    /// Attested → anything weaker is a downgrade. Unattested → none is **also**
    /// a downgrade: the claim was recorded, and its disappearance is the same
    /// observable event even though it was never evidence.
    #[must_use]
    pub const fn is_downgrade_from(&self, previous: HardwareBacking) -> bool {
        matches!(
            (previous, self.backing),
            (
                HardwareBacking::Attested,
                HardwareBacking::ClaimedUnattested | HardwareBacking::None
            ) | (HardwareBacking::ClaimedUnattested, HardwareBacking::None)
        )
    }
}

/// Parses the identity public key from a verified `DeviceIdentityRecord`.
///
/// N-1 fixes ES256 for the identity key in this epoch, so anything else is
/// `AUTH.IDENTITY_ALG_UNSUPPORTED` rather than a silently accepted alternative.
///
/// # Errors
///
/// [`TrustError::Crypto`] carrying the algorithm refusal.
pub fn parse_identity_key(ik_pub_cose: &[u8]) -> Result<PublicVerifyingKey> {
    let key = PublicVerifyingKey::from_cose_key(ik_pub_cose, StatementKind::DeviceIdentityRecord)?;
    match key {
        PublicVerifyingKey::Es256(_) => Ok(key),
        // N-1: "MUST comprise an ES256 (P-256 / SHA-256) DeviceIdentityKey".
        // Ed25519 is a valid COSE key and is used for the relay-credential
        // issuer, so it parses — and must be refused *here*, where the role is
        // identity.
        PublicVerifyingKey::Ed25519(_) => Err(TrustError::Crypto(
            twinvpn_crypto::CryptoError::IdentityAlgUnsupported {
                algorithm: "an identity key must be ES256 (ADR-0007 N-1)",
            },
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The re-export and the implementation are the same function.
    ///
    /// The derivation moved to `twinvpn_crypto::deviceid` so `services/` could
    /// reach it without an edge to this crate, and it is re-exported here so no
    /// existing call site changed. **Two implementations of one identifier is
    /// how devices end up with different names for each other**, so this test
    /// asserts there is only one: both paths, over the same input, byte for
    /// byte.
    ///
    /// The derivation's own golden vector lives with the implementation, in
    /// `twinvpn_crypto::deviceid::tests::the_derivation_matches_identifiers_md_section_2`.
    #[test]
    fn identity_derivation_agrees_across_both_paths() {
        // A canonical dCBOR COSE_Key (EC2/P-256) over the NIST P-256 generator
        // `G` — a real point on the curve, so the checked path accepts it and
        // all four entry points can be compared.
        const GX: [u8; 32] = [
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96,
        ];
        const GY: [u8; 32] = [
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
            0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
            0x37, 0xbf, 0x51, 0xf5,
        ];
        let mut key = vec![0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20];
        key.extend_from_slice(&GX);
        key.extend_from_slice(&[0x22, 0x58, 0x20]);
        key.extend_from_slice(&GY);

        // The re-export (`crate::identity::…`) against the original.
        assert_eq!(
            derive_identity_id(&key),
            twinvpn_crypto::deviceid::derive_identity_id(&key)
        );
        assert_eq!(
            derive_device_id(&key),
            twinvpn_crypto::deviceid::derive_device_id(&key)
        );
        assert_eq!(
            derive_identity_id_checked(&key).expect("canonical"),
            twinvpn_crypto::deviceid::derive_identity_id_checked(&key).expect("canonical")
        );
        assert_eq!(
            derive_device_id_checked(&key).expect("canonical"),
            twinvpn_crypto::deviceid::derive_device_id_checked(&key).expect("canonical")
        );

        // And the checked path agrees with the unchecked one on canonical
        // input, so which entry point a caller picks is never a choice of
        // identifier.
        assert_eq!(
            derive_device_id_checked(&key).expect("canonical"),
            derive_device_id(&key)
        );

        // The label came across with them.
        assert_eq!(IDENTITY_LABEL, b"TwinVPN/DeviceIdentity/v1");
    }

    /// **Attack test.** `device_id_echo` is an echo. A server that returns a
    /// different value must abort the registration, not be believed.
    #[test]
    fn a_disagreeing_device_id_echo_aborts_rather_than_being_adopted() {
        let local = derive_device_id(b"my-key");
        assert!(check_device_id_echo(&local, local.as_bytes()).is_ok());
        let err = check_device_id_echo(&local, &[0xff; 32]).expect_err("must abort");
        assert!(matches!(err, TrustError::IdentityMismatch));
        assert_eq!(err.reason_code().as_str(), "AUTH.IDENTITY_MISMATCH");
    }

    /// A truncated or over-long echo is a mismatch, never a prefix comparison.
    #[test]
    fn a_short_echo_is_a_mismatch() {
        let local = derive_device_id(b"my-key");
        assert!(check_device_id_echo(&local, &local.as_bytes()[..16]).is_err());
    }

    /// **N-6.** An unattested claim is recorded but is not evidence.
    #[test]
    fn an_unattested_hardware_claim_is_not_evidence() {
        let claimed = AttestationRecord::evaluate(true, false, None);
        assert_eq!(claimed.backing, HardwareBacking::ClaimedUnattested);
        assert!(
            !claimed.backing.is_evidence(),
            "an unattested claim must never be evidence"
        );
        let attested = AttestationRecord::evaluate(true, true, Some("android-key"));
        assert!(attested.backing.is_evidence());
        let none = AttestationRecord::evaluate(false, false, None);
        assert!(!none.backing.is_evidence());
    }

    /// **N-24.** A downgrade is detected in every direction that loses ground.
    #[test]
    fn a_hardware_backing_downgrade_is_detected() {
        let unattested = AttestationRecord::evaluate(true, false, None);
        let none = AttestationRecord::evaluate(false, false, None);
        let attested = AttestationRecord::evaluate(true, true, None);

        assert!(unattested.is_downgrade_from(HardwareBacking::Attested));
        assert!(none.is_downgrade_from(HardwareBacking::Attested));
        assert!(none.is_downgrade_from(HardwareBacking::ClaimedUnattested));
        // And an upgrade is not a downgrade.
        assert!(!attested.is_downgrade_from(HardwareBacking::None));
        assert!(!attested.is_downgrade_from(HardwareBacking::Attested));
    }

    /// N-1: an identity key must be ES256. An Ed25519 COSE_Key parses as a
    /// verifying key — it is a valid one — and must still be refused here.
    #[test]
    fn a_non_es256_identity_key_is_refused() {
        use twinvpn_crypto::emit::{encode, int_item, Item};
        // A valid Ed25519 point: the basepoint's encoding.
        let ed = [
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ];
        let cose = encode(&Item::Map(vec![
            (Item::Uint(1), Item::Uint(1)),
            (int_item(-1), Item::Uint(6)),
            (int_item(-2), Item::Bytes(ed.to_vec())),
        ]))
        .expect("encode");
        // Whether the point is on the curve or not, the refusal must be about
        // the *role*, so both outcomes are failures and neither is an accept.
        assert!(parse_identity_key(&cose).is_err());
    }
}
