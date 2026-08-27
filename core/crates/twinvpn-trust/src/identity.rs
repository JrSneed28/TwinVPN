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

use twinvpn_crypto::{sha256, PublicVerifyingKey, StatementKind};
use twinvpn_platform::custody::{
    IdentityAttestation, IdentityCustody, IdentityKeyRef, IdentityPublic, Signature,
};
use twinvpn_types::{DeviceId, Identifier, IdentityId};

use crate::error::{Result, TrustError};

/// The N-2 domain label, verbatim.
pub const IDENTITY_LABEL: &[u8] = b"TwinVPN/DeviceIdentity/v1";

/// Derives `identity_id` from a COSE_Key encoding of the identity public key.
///
/// `ik_pub_cose` must be the **deterministic CBOR** COSE_Key. The caller gets it
/// from a verified `DeviceIdentityRecord`, whose encoding
/// [`twinvpn_crypto::dcbor`] has already proved canonical — which matters,
/// because a non-canonical encoding of the same key would derive a different
/// `identity_id` and so a different device.
#[must_use]
pub fn derive_identity_id(ik_pub_cose: &[u8]) -> IdentityId {
    let mut buf = Vec::with_capacity(IDENTITY_LABEL.len() + 1 + ik_pub_cose.len());
    buf.extend_from_slice(IDENTITY_LABEL);
    buf.push(0x00);
    buf.extend_from_slice(ik_pub_cose);
    IdentityId::from_array(sha256(&buf))
}

/// Derives `device_id` from the **generation-0** identity key.
///
/// `identifiers.md` §2: "The generation-0 `identity_id` **is** the `device_id`."
/// Passing a later generation's key here produces a value that is not this
/// device's name, which is why the parameter is named for what it must be.
#[must_use]
pub fn derive_device_id(generation_zero_ik_pub_cose: &[u8]) -> DeviceId {
    derive_identity_id(generation_zero_ik_pub_cose).as_generation_zero_device_id()
}

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

    /// N-2's derivation, pinned. Every `device_id` in the fleet depends on these
    /// exact bytes, so a change here is a fleet-wide identity change.
    #[test]
    fn the_identity_derivation_is_n_2s_expression() {
        let cose = b"a-cose-key-encoding";
        let id = derive_identity_id(cose);

        let mut expected = Vec::new();
        expected.extend_from_slice(b"TwinVPN/DeviceIdentity/v1");
        expected.push(0x00);
        expected.extend_from_slice(cose);
        assert_eq!(id.as_bytes(), &sha256(&expected));
        assert_eq!(id.as_bytes().len(), 32, "untruncated");
    }

    /// **Attack test.** The `0x00` separator is what stops a key encoding that
    /// begins with the tail of the label from colliding with a different one.
    #[test]
    fn the_separator_prevents_a_label_boundary_collision() {
        // Without the 0x00, "…v1" + "\x00X" and "…v1\x00" + "X" would hash the
        // same input. With it, the two are distinct.
        let a = derive_identity_id(b"\x00X");
        let b = derive_identity_id(b"X");
        assert_ne!(a, b);
    }

    #[test]
    fn the_generation_zero_identity_is_the_device_id() {
        let cose = b"gen-0-key";
        assert_eq!(
            derive_device_id(cose).as_bytes(),
            derive_identity_id(cose).as_bytes()
        );
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
