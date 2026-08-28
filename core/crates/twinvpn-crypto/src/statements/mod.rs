//! The seventeen B2 signed statements, decoded **only** from a verified
//! envelope.
//!
//! **Authority:** `contracts/cddl/twinvpn/v1/signed_statements.cddl` in full,
//! ADR-0003 §11 and §11.5, ADR-0007, ADR-0005 §11.3, ADR-0002 §S-3.
//!
//! # The shape of every decoder here
//!
//! Each type's entry point takes a [`crate::cose::VerifiedStatement`] — never
//! `&[u8]`, never a [`crate::dcbor::Value`] — so a payload that has not been
//! verified over its received octets has no decoder. Each then applies the same
//! three checks, in this order, before reading a single field:
//!
//! 1. the statement kind is the one the caller asked for;
//! 2. **no unknown field** (encoding rule 5: "a preserved-but-unverified field
//!    is a place to smuggle data past a policy check");
//! 3. the **`crit` set** is fully understood and contains every member the CDDL
//!    says it MUST (rule 5 and ADR-0003 §7 R11).
//!
//! Only then are fields read, and every one is mandatory: the CDDL uses no
//! optional members, so an absent field is a malformed statement rather than a
//! default. A `null` is admitted only where the CDDL writes `/ null`, which is
//! exactly one place — `revocation-statement`'s `target_identity_id`, where it
//! means "every generation" and is therefore the **broader** reading, never the
//! narrower one.
//!
//! # `not_after_ms` is returned, never evaluated
//!
//! Every statement carries a mandatory `not_after_ms` and none of these
//! decoders checks it. Evaluating a validity window needs a
//! [`twinvpn_env::ValidityClock`], and this crate takes no `Env` (CD-2). More
//! importantly the *meaning* of an expired statement is ADR-0007 N-27's
//! freshness ladder, which is `twinvpn-trust`'s decision: `PEER_TRUST_EXPIRED`
//! "withdraws grants; it does not withdraw identity". A decoder that quietly
//! rejected on expiry would collapse that ladder into a boolean.

use crate::cose::VerifiedStatement;
use crate::dcbor::Value;
use crate::error::StatementKind;
use crate::{CryptoError, Result};

mod identity;
mod owner;
mod peerdocs;

pub use identity::{
    check_attestation_pair, decode_device_identity_record, decode_identity_succession,
    decode_pairing_attestation, verify_succession_pair, DeviceIdentityRecord, IdentitySuccession,
    PairingAttestation,
};
pub use owner::{
    decode_owner_delegation, decode_owner_trust_anchor, decode_policy_bundle,
    decode_revocation_entry, decode_revocation_statement, decode_trust_epoch_bundle, EpochSeal,
    OskPower, OwnerDelegation, OwnerTrustAnchor, PolicyBundleHeader, RevocationEntry,
    RevocationStatement, TrustEpochBundle,
};
pub use peerdocs::{
    decode_exit_node_offer, decode_log_head, decode_network_contract, decode_relay_epoch_floor,
    decode_route_advertisement, ExitNodeOffer, LogHead, NetworkContractHeader, RelayEpochFloor,
    RouteAdvertisement,
};

/// A statement's frozen schema: which labels exist, which `crit` names this
/// build understands, and which the CDDL says MUST be present.
///
/// One `const` per statement type, all in one place, so a reviewer can diff this
/// module against the CDDL rather than against seventeen scattered literals.
pub struct Schema {
    /// Which statement this describes.
    pub kind: StatementKind,
    /// Every integer label the CDDL defines for this statement.
    pub labels: &'static [u64],
    /// The label holding the `crit-set`.
    pub crit_label: u64,
    /// Field names this build understands.
    pub understood_crit: &'static [&'static str],
    /// `crit` members the CDDL requires.
    pub required_crit: &'static [&'static str],
}

impl Schema {
    /// Runs the three pre-field checks every decoder shares.
    ///
    /// # Errors
    ///
    /// [`CryptoError::NonCanonicalCbor`] for a wrong kind or an unknown field,
    /// [`CryptoError::UnknownCriticalField`] or
    /// [`CryptoError::MissingCriticalField`] for a `crit` failure.
    pub fn check(&self, s: &VerifiedStatement) -> Result<()> {
        if s.kind() != self.kind {
            return Err(CryptoError::NonCanonicalCbor {
                kind: self.kind,
                step: "statement kind does not match the schema applied",
            });
        }
        s.check_no_unknown_fields(self.labels)?;
        s.check_crit(self.crit_label, self.understood_crit, self.required_crit)
    }
}

// ---------------------------------------------------------------------------
// Field accessors. Every one of these REJECTS rather than defaulting, and every
// fixed-width identifier is rejected on a width mismatch rather than truncated
// or padded (`contracts/docs/identifiers.md` §5).
// ---------------------------------------------------------------------------

pub(crate) fn field<'a>(
    s: &'a VerifiedStatement,
    label: u64,
    what: &'static str,
) -> Result<&'a Value> {
    s.payload()
        .map_get(label)
        .ok_or(CryptoError::NonCanonicalCbor {
            kind: s.kind(),
            step: what,
        })
}

pub(crate) fn uint(s: &VerifiedStatement, label: u64, what: &'static str) -> Result<u64> {
    field(s, label, what)?
        .as_uint()
        .ok_or(CryptoError::NonCanonicalCbor {
            kind: s.kind(),
            step: what,
        })
}

pub(crate) fn boolean(s: &VerifiedStatement, label: u64, what: &'static str) -> Result<bool> {
    field(s, label, what)?
        .as_bool()
        .ok_or(CryptoError::NonCanonicalCbor {
            kind: s.kind(),
            step: what,
        })
}

pub(crate) fn bytes<'a>(
    s: &'a VerifiedStatement,
    label: u64,
    what: &'static str,
) -> Result<&'a [u8]> {
    field(s, label, what)?
        .as_bytes()
        .ok_or(CryptoError::NonCanonicalCbor {
            kind: s.kind(),
            step: what,
        })
}

pub(crate) fn fixed<const N: usize>(
    s: &VerifiedStatement,
    label: u64,
    what: &'static str,
) -> Result<[u8; N]> {
    let b = bytes(s, label, what)?;
    b.try_into().map_err(|_| CryptoError::NonCanonicalCbor {
        kind: s.kind(),
        step: what,
    })
}

/// The cap on any `tstr` field, matching the CDDL's `.size (1..64)` where it
/// states one and bounding the rest so a decoded statement cannot carry an
/// unbounded string into a diagnostic.
pub(crate) const MAX_TSTR_BYTES: usize = 64;

pub(crate) fn text(s: &VerifiedStatement, label: u64, what: &'static str) -> Result<String> {
    let t = field(s, label, what)?
        .as_text()
        .ok_or(CryptoError::NonCanonicalCbor {
            kind: s.kind(),
            step: what,
        })?;
    if t.is_empty() || t.len() > MAX_TSTR_BYTES {
        return Err(CryptoError::NonCanonicalCbor {
            kind: s.kind(),
            step: "text field outside its size bound",
        });
    }
    Ok(t.to_owned())
}

pub(crate) fn array<'a>(
    s: &'a VerifiedStatement,
    label: u64,
    what: &'static str,
) -> Result<&'a [Value]> {
    field(s, label, what)?
        .as_array()
        .ok_or(CryptoError::NonCanonicalCbor {
            kind: s.kind(),
            step: what,
        })
}
