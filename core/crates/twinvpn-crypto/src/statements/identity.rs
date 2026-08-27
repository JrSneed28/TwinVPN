//! `DeviceIdentityRecord`, `IdentitySuccession` and `PairingAttestation`.
//!
//! **Authority:** `signed_statements.cddl` §1, §3, §4; ADR-0007 N-2, N-6, N-21,
//! N-22; `contracts/proto/twinvpn/v1/identity.proto` and `pairing.proto`.

use super::{fixed, text, uint, Schema};
use crate::cose::VerifiedStatement;
use crate::error::StatementKind;
use crate::{CryptoError, Result};

// --- 1. DeviceIdentityRecord -----------------------------------------------

const DIR_SCHEMA: Schema = Schema {
    kind: StatementKind::DeviceIdentityRecord,
    labels: &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    crit_label: 11,
    understood_crit: &[
        "twinnet_id",
        "device_id",
        "identity_id",
        "generation",
        "ik_pub",
        "tk_pub",
        "tk_generation",
        "hardware_backed",
        "not_before_ms",
        "not_after_ms",
    ],
    // The CDDL: "MUST include \"generation\" and \"tk_generation\"".
    required_crit: &["generation", "tk_generation"],
};

/// The public identity, self-certifying and verifiable offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentityRecord {
    /// The `TwinNet` this identity belongs to.
    pub twinnet_id: String,
    /// The device's permanent name.
    pub device_id: [u8; 32],
    /// This generation's identity.
    pub identity_id: [u8; 32],
    /// Rotation generation. **Monotone**: ADR-0007 N-22 has a peer hold
    /// `highest_generation_seen` and reject any statement at or below it.
    pub generation: u64,
    /// COSE_Key octets for the ES256 identity public key.
    pub ik_pub_cose: Vec<u8>,
    /// COSE_Key octets for the X25519 tunnel public key.
    pub tk_pub_cose: Vec<u8>,
    /// Separately monotone from `generation`.
    pub tk_generation: u64,
    /// **A self-report.** ADR-0007 N-6: "a peer MUST NOT treat an UNATTESTED
    /// `true` as evidence". The field is named `hardware_backed_claim` here so a
    /// call site cannot read it as a verified fact.
    pub hardware_backed_claim: bool,
    /// Validity window start.
    pub not_before_ms: u64,
    /// Validity window end. A backstop of enrolment + 10 years; real freshness
    /// is ADR-0007 N-27's `T_TRUST_*` ladder.
    pub not_after_ms: u64,
}

/// Decodes a verified `DeviceIdentityRecord`.
///
/// # Errors
///
/// [`CryptoError::NonCanonicalCbor`], [`CryptoError::UnknownCriticalField`] or
/// [`CryptoError::MissingCriticalField`].
pub fn decode_device_identity_record(s: &VerifiedStatement) -> Result<DeviceIdentityRecord> {
    DIR_SCHEMA.check(s)?;
    Ok(DeviceIdentityRecord {
        twinnet_id: text(s, 1, "twinnet_id")?,
        device_id: fixed::<32>(s, 2, "device_id")?,
        identity_id: fixed::<32>(s, 3, "identity_id")?,
        generation: uint(s, 4, "generation")?,
        ik_pub_cose: super::bytes(s, 5, "ik_pub")?.to_vec(),
        tk_pub_cose: super::bytes(s, 6, "tk_pub")?.to_vec(),
        tk_generation: uint(s, 7, "tk_generation")?,
        hardware_backed_claim: super::boolean(s, 8, "hardware_backed")?,
        not_before_ms: uint(s, 9, "not_before_ms")?,
        not_after_ms: uint(s, 10, "not_after_ms")?,
    })
}

// --- 3. IdentitySuccession -------------------------------------------------

const SUCCESSION_SCHEMA: Schema = Schema {
    kind: StatementKind::IdentitySuccession,
    labels: &[1, 2, 3, 4, 5, 6],
    crit_label: 6,
    understood_crit: &[
        "device_id",
        "old_identity_id",
        "new_identity_id",
        "generation",
        "not_after_ms",
    ],
    required_crit: &["generation"],
};

/// A credential rotation, **dual-signed** by both the old and the new identity
/// key.
///
/// This type is one half of the check. Verifying it requires **two**
/// `VerifiedStatement`s over the same payload octets — one under each key — and
/// [`verify_succession_pair`] is what enforces that, because the CDDL is
/// explicit: "a verifier that accepts one is non-conforming."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentitySuccession {
    /// Unchanged across succession: "otherwise S-08's immutable address
    /// allocation would break on every rotation."
    pub device_id: [u8; 32],
    /// The identity being replaced.
    pub old_identity_id: [u8; 32],
    /// The replacement.
    pub new_identity_id: [u8; 32],
    /// "Exactly old generation + 1."
    pub generation: u64,
    /// `T_IK_OVERLAP = 30 d`.
    pub not_after_ms: u64,
}

/// Decodes one signature's view of a succession.
///
/// **Not sufficient on its own.** Use [`verify_succession_pair`].
///
/// # Errors
///
/// As [`decode_device_identity_record`].
pub fn decode_identity_succession(s: &VerifiedStatement) -> Result<IdentitySuccession> {
    SUCCESSION_SCHEMA.check(s)?;
    Ok(IdentitySuccession {
        device_id: fixed::<32>(s, 1, "device_id")?,
        old_identity_id: fixed::<32>(s, 2, "old_identity_id")?,
        new_identity_id: fixed::<32>(s, 3, "new_identity_id")?,
        generation: uint(s, 4, "generation")?,
        not_after_ms: uint(s, 5, "not_after_ms")?,
    })
}

/// Verifies a succession's **two** signatures agree on one statement.
///
/// The CDDL, ADR-0007 N-21 and `docs/protocol.md` §8.4 all say the same thing
/// and give both reasons:
///
/// > "a single-signature rotation would let a STOLEN KEY ROTATE ITSELF INTO
/// > PERMANENCE; an old-key-only signature would let a COMPROMISED OLD KEY
/// > INSTALL AN ATTACKER'S NEW KEY. Both signatures are required, and a verifier
/// > that accepts one is non-conforming."
///
/// The caller verifies the same octets twice — once under the **old** identity
/// key, once under the **new** one — and passes both results here. This function
/// then checks that the two payloads are identical, which is what stops an
/// attacker pairing a genuine old-key signature over one payload with a
/// new-key signature over another.
///
/// `expected_old_generation` is the generation the verifier currently holds; the
/// successor must be exactly one above it, so a rotation cannot skip generations
/// and land a device on a key nobody witnessed being installed.
///
/// # Errors
///
/// [`CryptoError::NonCanonicalCbor`] if the two payloads disagree,
/// [`CryptoError::MonotoneRollback`] if the generation does not advance by
/// exactly one.
pub fn verify_succession_pair(
    signed_by_old: &VerifiedStatement,
    signed_by_new: &VerifiedStatement,
    expected_old_generation: u64,
) -> Result<IdentitySuccession> {
    let a = decode_identity_succession(signed_by_old)?;
    let b = decode_identity_succession(signed_by_new)?;
    if a != b {
        return Err(CryptoError::NonCanonicalCbor {
            kind: StatementKind::IdentitySuccession,
            step: "the two succession signatures cover different payloads",
        });
    }
    if a.generation != expected_old_generation.saturating_add(1) {
        return Err(CryptoError::MonotoneRollback {
            offered: a.generation,
            high_water: expected_old_generation,
        });
    }
    if a.old_identity_id == a.new_identity_id {
        return Err(CryptoError::NonCanonicalCbor {
            kind: StatementKind::IdentitySuccession,
            step: "a succession to the same identity_id",
        });
    }
    Ok(a)
}

// --- 4. PairingAttestation -------------------------------------------------

const ATTESTATION_SCHEMA: Schema = Schema {
    kind: StatementKind::PairingAttestation,
    labels: &[1, 2, 3, 4, 5, 6],
    crit_label: 6,
    understood_crit: &[
        "pairing_id",
        "peer_key_id",
        "own_key_id",
        "transcript_hash",
        "not_after_ms",
    ],
    // The CDDL states no required member for this statement's crit set.
    required_crit: &[],
};

/// One device's half of a completed ceremony.
///
/// Rule B: "the coordination service TRANSPORTS attestations it CANNOT FORGE,
/// so it cannot inject a `TrustedPeer`." The verification that makes that true
/// is that each half is signed by **its own** device's key, which
/// [`crate::verify_cose_sign1`] performs before this decoder runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingAttestation {
    /// `SHA-256(pairing_secret)[0..15]`.
    pub pairing_id: [u8; 16],
    /// The other device's key id.
    pub peer_key_id: String,
    /// This device's key id.
    pub own_key_id: String,
    /// The ceremony transcript both sides must agree on.
    pub transcript_hash: [u8; 32],
    /// Ceremony expiry is 120 s (ADR-0007 N-17).
    pub not_after_ms: u64,
}

/// Decodes a verified `PairingAttestation`.
///
/// # Errors
///
/// As [`decode_device_identity_record`].
pub fn decode_pairing_attestation(s: &VerifiedStatement) -> Result<PairingAttestation> {
    ATTESTATION_SCHEMA.check(s)?;
    Ok(PairingAttestation {
        pairing_id: fixed::<16>(s, 1, "pairing_id")?,
        peer_key_id: text(s, 2, "peer_key_id")?,
        own_key_id: text(s, 3, "own_key_id")?,
        transcript_hash: fixed::<32>(s, 4, "transcript_hash")?,
        not_after_ms: uint(s, 5, "not_after_ms")?,
    })
}

/// Checks that two attestations are the mutually consistent halves of one
/// ceremony.
///
/// ADR-0007 N-18: "a `Pairing` MUST complete on BOTH devices or on NEITHER.
/// There is no state meaning 'confirmed on one side', because asymmetric trust
/// is the defect this ceremony exists to prevent."
///
/// Consistency means: the same `pairing_id`, the same `transcript_hash`, and
/// each half naming the other's key as `peer_key_id`. The last is what stops a
/// coordination service pairing two unrelated attestations into a `Pairing`
/// neither device agreed to.
///
/// # Errors
///
/// [`CryptoError::NonCanonicalCbor`] naming the inconsistency.
pub fn check_attestation_pair(a: &PairingAttestation, b: &PairingAttestation) -> Result<()> {
    let bad = |step| CryptoError::NonCanonicalCbor {
        kind: StatementKind::PairingAttestation,
        step,
    };
    if a.pairing_id != b.pairing_id {
        return Err(bad("attestations name different pairing_ids"));
    }
    if a.transcript_hash != b.transcript_hash {
        return Err(bad("attestations disagree on the ceremony transcript"));
    }
    if a.own_key_id == b.own_key_id {
        return Err(bad("both attestations were produced by the same key"));
    }
    if a.peer_key_id != b.own_key_id || b.peer_key_id != a.own_key_id {
        return Err(bad("attestations do not name each other"));
    }
    Ok(())
}
