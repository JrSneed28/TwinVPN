//! The Owner-authority statements: revocation, epochs, anchors, delegations and
//! policy.
//!
//! **Authority:** `signed_statements.cddl` §5–§10, ADR-0007 N-11, N-25, N-26,
//! N-28, ADR-0008 N-7, `docs/architecture.md` §2.22 and §4.5,
//! `contracts/proto/twinvpn/v1/policy.proto`.

use super::{array, bytes, fixed, text, uint, Schema};
use crate::cose::VerifiedStatement;
use crate::dcbor::Value;
use crate::error::StatementKind;
use crate::{CryptoError, Result};

// --- 5. RevocationStatement -------------------------------------------------

const REVOCATION_SCHEMA: Schema = Schema {
    kind: StatementKind::RevocationStatement,
    labels: &[1, 2, 3, 4, 5, 6, 7],
    crit_label: 7,
    understood_crit: &[
        "twinnet_id",
        "target_device_id",
        "target_identity_id",
        "effective_from_ms",
        "reason_code",
        "issuer_osk_id",
    ],
    required_crit: &["target_device_id"],
};

/// The Owner-signed revocation of a device.
///
/// # The absent field is the design
///
/// The CDDL: "NOTE the deliberate ABSENCE of a `revoked: bool`. ADR-0008 N-7:
/// revocation is a MONOTONE EPOCH PLUS A NEVER-SHRINKING SET. A mutable boolean
/// is exactly the shape that permits UN-REVOCATION by replaying an older
/// record."
///
/// So there is no `revoked` field on this struct either, and there is no
/// constructor that could add one. A revocation is a fact whose only content is
/// *who*, and its effect is set-membership, not a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationStatement {
    /// Which `TwinNet`.
    pub twinnet_id: String,
    /// The device being revoked.
    pub target_device_id: [u8; 32],
    /// The specific generation, or `None` meaning **every** generation.
    ///
    /// `None` is the *broader* reading, so a decoder that got the `null` case
    /// wrong would revoke less than intended, never more.
    pub target_identity_id: Option<[u8; 32]>,
    /// When the revocation takes effect.
    pub effective_from_ms: u64,
    /// A code from the `AUTH` domain.
    pub reason_code: String,
    /// The `OwnerSigningKey` that authorised it.
    pub issuer_osk_id: String,
}

/// Decodes a verified `RevocationStatement`.
///
/// # Errors
///
/// [`CryptoError::NonCanonicalCbor`] and the `crit` errors.
pub fn decode_revocation_statement(s: &VerifiedStatement) -> Result<RevocationStatement> {
    REVOCATION_SCHEMA.check(s)?;
    let target_identity_id = match super::field(s, 3, "target_identity_id")? {
        Value::Null => None,
        v => Some(
            v.as_bytes()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or(CryptoError::NonCanonicalCbor {
                    kind: StatementKind::RevocationStatement,
                    step: "target_identity_id",
                })?,
        ),
    };
    Ok(RevocationStatement {
        twinnet_id: text(s, 1, "twinnet_id")?,
        target_device_id: fixed::<32>(s, 2, "target_device_id")?,
        target_identity_id,
        effective_from_ms: uint(s, 4, "effective_from_ms")?,
        reason_code: text(s, 5, "reason_code")?,
        issuer_osk_id: text(s, 6, "issuer_osk_id")?,
    })
}

// --- 6. RevocationEntry -----------------------------------------------------

const ENTRY_SCHEMA: Schema = Schema {
    kind: StatementKind::RevocationEntry,
    labels: &[1, 2, 3, 4, 5],
    crit_label: 5,
    understood_crit: &["inner", "trust_epoch", "net_seq", "prev_entry_hash"],
    required_crit: &[],
};

/// The **admitted** form of a revocation: the writer's wrapper, assigning the
/// ordering.
///
/// The two signers are deliberately separate — the Owner authorises, the writer
/// orders. The CDDL is emphatic about what follows:
///
/// > "A `RevocationEntry` whose INNER statement signature does not verify MUST
/// > BE REJECTED OUTRIGHT: **A WELL-FORMED WRAPPER AUTHORIZES NOTHING.**"
///
/// This decoder therefore returns the inner statement as **opaque COSE_Sign1
/// octets**, not as a decoded `RevocationStatement`. The caller must verify
/// those octets under the Owner authority before it can read them, and there is
/// no accessor that skips that step — which is the same received-octets
/// discipline applied one level in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationEntry {
    /// The inner `RevocationStatement`, as COSE_Sign1 octets, **unverified**.
    pub inner_cose_sign1: Vec<u8>,
    /// The epoch the writer assigned at admission. **Monotone.**
    pub trust_epoch: u64,
    /// The writer's sequence number.
    pub net_seq: u64,
    /// The chain link. N-26 verifies this as a chain; a break raises
    /// `AUTH.TRUST_HISTORY_FORKED`. **Detection, not prevention** — peer refusal
    /// rests on the inner OSK signature alone, so a forked or withheld chain
    /// cannot un-revoke a device at a peer that has already seen the statement.
    pub prev_entry_hash: [u8; 32],
}

/// Decodes a verified `RevocationEntry`.
///
/// # Errors
///
/// [`CryptoError::NonCanonicalCbor`] and the `crit` errors.
pub fn decode_revocation_entry(s: &VerifiedStatement) -> Result<RevocationEntry> {
    ENTRY_SCHEMA.check(s)?;
    Ok(RevocationEntry {
        inner_cose_sign1: bytes(s, 1, "inner")?.to_vec(),
        trust_epoch: uint(s, 2, "trust_epoch")?,
        net_seq: uint(s, 3, "net_seq")?,
        prev_entry_hash: fixed::<32>(s, 4, "prev_entry_hash")?,
    })
}

// --- 7. TrustEpochBundle ----------------------------------------------------

const BUNDLE_SCHEMA: Schema = Schema {
    kind: StatementKind::TrustEpochBundle,
    labels: &[1, 2, 3, 4, 5],
    crit_label: 5,
    understood_crit: &["twinnet_id", "trust_epoch", "seals", "not_after_ms"],
    required_crit: &["trust_epoch"],
};

/// The cap on seals in one bundle.
///
/// A bundle carries one seal per device in the `TwinNet`. `AUTH.QUOTA_EXCEEDED`
/// bounds a TwinNet's device count; 1024 is far above any Phase 1 fleet and
/// bounds the allocation a hostile bundle can drive.
pub const MAX_EPOCH_SEALS: usize = 1024;

/// One recipient's HPKE-sealed `EpochSeed`.
///
/// The plaintext seed appears nowhere in the schema and must not be added: S-33
/// says each device holds only the seal addressed to it, openable by no other
/// party. A courier peer forwards seals it cannot open (N-28).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochSeal {
    /// Who the seal is for.
    pub recipient_device_id: [u8; 32],
    /// Opaque ciphertext. This crate never opens it — HPKE is not in the
    /// workspace's dependency table and adding it is an ADR change, not a
    /// review comment.
    pub sealed: Vec<u8>,
}

/// Distributes the new `EpochSeed` after a `trust_epoch` advance.
///
/// The CDDL calls this "the carriage for the SECOND revocation lever":
/// `RevocationTransfer` propagates refusal, and only this lets a lagging peer
/// advance `min_acceptable_epoch` and derive `psk2` at the new epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustEpochBundle {
    /// Which `TwinNet`.
    pub twinnet_id: String,
    /// **Monotone**: "a lower value is `AUTH.TRUST_EPOCH_ROLLBACK`, refused
    /// rather than applied."
    pub trust_epoch: u64,
    /// One seal per recipient.
    pub seals: Vec<EpochSeal>,
    /// Expiry.
    pub not_after_ms: u64,
}

/// Decodes a verified `TrustEpochBundle`.
///
/// # Errors
///
/// [`CryptoError::NonCanonicalCbor`] and the `crit` errors.
pub fn decode_trust_epoch_bundle(s: &VerifiedStatement) -> Result<TrustEpochBundle> {
    BUNDLE_SCHEMA.check(s)?;
    let raw = array(s, 3, "seals")?;
    // `[+ epoch-seal]` — at least one, and capped before the `Vec` is grown.
    if raw.is_empty() || raw.len() > MAX_EPOCH_SEALS {
        return Err(CryptoError::NonCanonicalCbor {
            kind: StatementKind::TrustEpochBundle,
            step: "seal count outside bounds",
        });
    }
    let bad = CryptoError::NonCanonicalCbor {
        kind: StatementKind::TrustEpochBundle,
        step: "epoch seal",
    };
    let mut seals = Vec::with_capacity(raw.len());
    for v in raw {
        let recipient = v
            .map_get(1)
            .and_then(Value::as_bytes)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| bad.clone())?;
        let sealed = v
            .map_get(2)
            .and_then(Value::as_bytes)
            .ok_or_else(|| bad.clone())?;
        // Reject an unknown key inside the seal, as encoding rule 5 requires of
        // every part of a signed statement, not only its outermost map.
        if v.map_keys() != vec![1, 2] {
            return Err(bad.clone());
        }
        seals.push(EpochSeal {
            recipient_device_id: recipient,
            sealed: sealed.to_vec(),
        });
    }
    Ok(TrustEpochBundle {
        twinnet_id: text(s, 1, "twinnet_id")?,
        trust_epoch: uint(s, 2, "trust_epoch")?,
        seals,
        not_after_ms: uint(s, 4, "not_after_ms")?,
    })
}

// --- 8. OwnerTrustAnchor ----------------------------------------------------

const ANCHOR_SCHEMA: Schema = Schema {
    kind: StatementKind::OwnerTrustAnchor,
    labels: &[1, 2, 3, 4, 5],
    crit_label: 5,
    understood_crit: &["twinnet_id", "anchor_version", "ork_pub", "not_after_ms"],
    required_crit: &["anchor_version"],
};

/// The root of the Owner authority, ORK-signed and pinned at enrolment.
///
/// S-32: "higher `anchor_version` with a valid signature wins; **EQUAL VERSION
/// WITH DIFFERENT CONTENT is `AUTH.TRUST_HISTORY_FORKED`**" — which is why
/// `anchor_version` is content-determining rather than merely monotone, and why
/// [`OwnerTrustAnchor`] derives `PartialEq`: comparing two anchors at one
/// version is the fork detector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerTrustAnchor {
    /// Which `TwinNet`.
    pub twinnet_id: String,
    /// **Monotone, MUST NOT decrease.**
    pub anchor_version: u64,
    /// COSE_Key octets for the `OwnerRootKey` public half.
    pub ork_pub_cose: Vec<u8>,
    /// Expiry.
    pub not_after_ms: u64,
}

/// Decodes a verified `OwnerTrustAnchor`.
///
/// # Errors
///
/// [`CryptoError::NonCanonicalCbor`] and the `crit` errors.
pub fn decode_owner_trust_anchor(s: &VerifiedStatement) -> Result<OwnerTrustAnchor> {
    ANCHOR_SCHEMA.check(s)?;
    Ok(OwnerTrustAnchor {
        twinnet_id: text(s, 1, "twinnet_id")?,
        anchor_version: uint(s, 2, "anchor_version")?,
        ork_pub_cose: bytes(s, 3, "ork_pub")?.to_vec(),
        not_after_ms: uint(s, 4, "not_after_ms")?,
    })
}

// --- 9. OwnerDelegation -----------------------------------------------------

const DELEGATION_SCHEMA: Schema = Schema {
    kind: StatementKind::OwnerDelegation,
    labels: &[1, 2, 3, 4, 5, 6, 7],
    crit_label: 7,
    understood_crit: &[
        "twinnet_id",
        "osk_id",
        "osk_pub",
        "powers",
        "anchor_version",
        "not_after_ms",
    ],
    required_crit: &["powers"],
};

/// A power an `OwnerSigningKey` may carry.
///
/// A closed enum, not a string: an unrecognised power must be a **rejection**,
/// because a delegation naming a power a verifier does not understand is a
/// delegation whose scope the verifier cannot bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OskPower {
    /// Approve a device joining the `TwinNet`.
    Enroll,
    /// Author a `RevocationStatement`.
    Revoke,
    /// Author a `PolicyBundle`.
    Policy,
    /// Mint another OSK.
    Delegate,
    /// Administer the `TwinNet`.
    Administer,
}

impl OskPower {
    /// Parses the CDDL's `osk-power` text.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ENROLL" => Some(OskPower::Enroll),
            "REVOKE" => Some(OskPower::Revoke),
            "POLICY" => Some(OskPower::Policy),
            "DELEGATE" => Some(OskPower::Delegate),
            "ADMINISTER" => Some(OskPower::Administer),
            _ => None,
        }
    }
}

/// The cap on powers in one delegation: the enum has five members, and a
/// canonical delegation cannot name more without repeating one.
pub const MAX_OSK_POWERS: usize = 5;

/// An `OwnerSigningKey` and the powers it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerDelegation {
    /// Which `TwinNet`.
    pub twinnet_id: String,
    /// The key's identifier.
    pub osk_id: String,
    /// COSE_Key octets for the OSK public half.
    pub osk_pub_cose: Vec<u8>,
    /// The powers, sorted and deduplicated.
    pub powers: Vec<OskPower>,
    /// Which anchor this delegation is bound to. A delegation issued under an
    /// older anchor does not survive an anchor advance by default.
    pub anchor_version: u64,
    /// Expiry.
    pub not_after_ms: u64,
}

impl OwnerDelegation {
    /// Whether this delegation carries `power`.
    #[must_use]
    pub fn has(&self, power: OskPower) -> bool {
        self.powers.contains(&power)
    }
}

/// Decodes a verified `OwnerDelegation`.
///
/// An unrecognised power is a **rejection**, not an ignored entry.
///
/// # Errors
///
/// [`CryptoError::NonCanonicalCbor`] and the `crit` errors.
pub fn decode_owner_delegation(s: &VerifiedStatement) -> Result<OwnerDelegation> {
    DELEGATION_SCHEMA.check(s)?;
    let raw = array(s, 4, "powers")?;
    if raw.is_empty() || raw.len() > MAX_OSK_POWERS {
        return Err(CryptoError::NonCanonicalCbor {
            kind: StatementKind::OwnerDelegation,
            step: "power count outside bounds",
        });
    }
    let mut powers = Vec::with_capacity(raw.len());
    for v in raw {
        let name = v.as_text().ok_or(CryptoError::NonCanonicalCbor {
            kind: StatementKind::OwnerDelegation,
            step: "power is not text",
        })?;
        // An unknown power is refused rather than dropped: a verifier that
        // silently ignored one would treat a delegation as narrower than the
        // Owner wrote it, and would then accept operations it should refuse
        // *and* refuse ones it should accept — both wrong, in opposite
        // directions.
        let p = OskPower::parse(name).ok_or(CryptoError::NonCanonicalCbor {
            kind: StatementKind::OwnerDelegation,
            step: "unrecognised osk power",
        })?;
        powers.push(p);
    }
    powers.sort();
    powers.dedup();
    Ok(OwnerDelegation {
        twinnet_id: text(s, 1, "twinnet_id")?,
        osk_id: text(s, 2, "osk_id")?,
        osk_pub_cose: bytes(s, 3, "osk_pub")?.to_vec(),
        powers,
        anchor_version: uint(s, 5, "anchor_version")?,
        not_after_ms: uint(s, 6, "not_after_ms")?,
    })
}

// --- 10. PolicyBundle -------------------------------------------------------

const POLICY_SCHEMA: Schema = Schema {
    kind: StatementKind::PolicyBundle,
    labels: &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    crit_label: 11,
    understood_crit: &[
        "twinnet_id",
        "policy_version",
        "policy_id",
        "access_rules",
        "dns_policy",
        "route_policy",
        "exit_policy",
        "relay_region_policy",
        "killswitch_floor",
        "not_after_ms",
    ],
    required_crit: &["policy_version", "killswitch_floor"],
};

/// The verified `PolicyBundle` payload.
///
/// The five nested policy documents are held as **opaque deterministic-CBOR
/// octets**, exactly as the CDDL declares them (`bstr`). They are not decoded
/// here because their shapes belong to ADR-0010, ADR-0011, ADR-0012 and
/// ADR-0013, and `twinvpn-crypto` decoding them would put policy semantics in
/// the crypto crate. What this decoder guarantees is that they arrived inside a
/// signature the Owner authority made.
///
/// # `killswitch_floor` is a floor
///
/// `policy.proto`: "**A FLOOR, NEVER A CEILING.** … Effective enforcement is
/// `max(local_mode, policy_required_mode)`. THERE IS NO ENCODING OF THIS FIELD
/// THAT LOWERS ENFORCEMENT BELOW THE DEVICE'S LOCAL SETTING." The value is
/// carried as the raw `uint` the CDDL declares, ordered so higher is stricter,
/// and `twinvpn-enforce` takes the maximum. There is no representation here of
/// "lower the local setting", because there is no encoding of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBundleHeader {
    /// Which `TwinNet`.
    pub twinnet_id: String,
    /// **Monotone.** "A device MUST reject `<=` its high-water mark. Replaying
    /// an older bundle is a POLICY ROLLBACK ATTACK."
    pub policy_version: u64,
    /// The document lineage, constant across versions.
    pub policy_id: String,
    /// Opaque deterministic-CBOR access rules.
    pub access_rules: Vec<u8>,
    /// Opaque DNS policy.
    pub dns_policy: Vec<u8>,
    /// Opaque route policy.
    pub route_policy: Vec<u8>,
    /// Opaque exit policy.
    pub exit_policy: Vec<u8>,
    /// Opaque relay-region policy.
    pub relay_region_policy: Vec<u8>,
    /// Ordered so higher is stricter. Contributes only to
    /// `policy_required_mode`.
    pub killswitch_floor: u64,
    /// Expiry. On expiry **grants suspend and denials persist** (ADR-0009
    /// §11.4); behaviour on expiry is not a policy input and is not remotely
    /// selectable.
    pub not_after_ms: u64,
}

/// The cap on one nested policy document, applied before the `Vec` is grown.
///
/// A bundle is whole-state rather than a delta, so it is the largest statement a
/// device receives. 32 KiB per document with five documents sits under
/// [`crate::cose::MAX_STATEMENT_BYTES`] with room for the envelope.
pub const MAX_POLICY_DOCUMENT_BYTES: usize = 32 * 1024;

/// Decodes a verified `PolicyBundle` header.
///
/// # Errors
///
/// [`CryptoError::NonCanonicalCbor`] and the `crit` errors.
pub fn decode_policy_bundle(s: &VerifiedStatement) -> Result<PolicyBundleHeader> {
    POLICY_SCHEMA.check(s)?;
    let doc = |label: u64, what: &'static str| -> Result<Vec<u8>> {
        let b = bytes(s, label, what)?;
        if b.len() > MAX_POLICY_DOCUMENT_BYTES {
            return Err(CryptoError::NonCanonicalCbor {
                kind: StatementKind::PolicyBundle,
                step: "policy document over cap",
            });
        }
        // Each nested document is itself declared as deterministic CBOR, so its
        // encoding is checked here rather than being taken on trust by whichever
        // crate later parses it.
        crate::dcbor::require_canonical(b)
            .map_err(|e| e.into_crypto_error(StatementKind::PolicyBundle))?;
        Ok(b.to_vec())
    };
    Ok(PolicyBundleHeader {
        twinnet_id: text(s, 1, "twinnet_id")?,
        policy_version: uint(s, 2, "policy_version")?,
        policy_id: text(s, 3, "policy_id")?,
        access_rules: doc(4, "access_rules")?,
        dns_policy: doc(5, "dns_policy")?,
        route_policy: doc(6, "route_policy")?,
        exit_policy: doc(7, "exit_policy")?,
        relay_region_policy: doc(8, "relay_region_policy")?,
        killswitch_floor: uint(s, 9, "killswitch_floor")?,
        not_after_ms: uint(s, 10, "not_after_ms")?,
    })
}
