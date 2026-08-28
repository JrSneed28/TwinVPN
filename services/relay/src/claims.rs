//! The claims a relay reads **out of a verified payload**, never off the wire.
//!
//! `contracts/proto/twinvpn/v1/relay.proto` is normative and blunt:
//!
//! > A verifier MUST verify the COSE signature and read the claims **FROM THE
//! > VERIFIED PAYLOAD**. The decoded fields here are attacker-controlled until
//! > then.
//!
//! So the types in this module have **no public constructor from wire bytes**.
//! The only way to obtain one is [`crate::crypto::RelayCrypto::verify_statement`],
//! which returns them and nothing else — every field here has already been
//! covered by an issuer signature by the time a caller can name it.
//!
//! The field numbering is `contracts/cddl/twinvpn/v1/signed_statements.cddl`'s
//! §13 (`relay-capability-token`) and §14 (`relay-epoch-floor`). It is reproduced
//! in the doc comments so a reader can go from a field here to the frozen schema
//! without a second file open.

/// The quota claims a token carries (CDDL key 8, ADR-0005 §11.3).
///
/// Quota values travel **in the token**, so a relay enforces the issuer's policy
/// with no lookup (§11.5). [`crate::resource::Ceilings::clamp`] takes the lesser
/// of these and the relay's own configured ceiling, field by field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    /// CDDL 8/1. ADR-0005 §11.5 default 64.
    pub max_concurrent_flows: u32,
    /// CDDL 8/2. Default 20 Mbit/s.
    pub max_bitrate_kbps: u32,
    /// CDDL 8/3. Default 20 GiB.
    pub max_bytes_per_hour: u64,
    /// CDDL 8/4. Default 30. ADR-0006 §11.15(b) requires this to be raisable for
    /// gateway-class devices, or the ~15-peer rendezvous-listening ceiling stands.
    pub max_binds_per_min: u32,
}

impl Default for Quota {
    fn default() -> Self {
        Self {
            max_concurrent_flows: 64,
            max_bitrate_kbps: 20_000,
            max_bytes_per_hour: 20 * 1024 * 1024 * 1024,
            max_binds_per_min: 30,
        }
    }
}

/// A `RelayCapabilityToken`'s claims, **after** the COSE signature verified.
///
/// Deliberately carries no signature, no issuer key and no raw octets: past
/// verification they are spent, and keeping them reachable would invite a second,
/// weaker check somewhere downstream.
#[derive(Debug, Clone)]
pub struct TokenClaims {
    /// CDDL 1 — `iss`, the issuer key id.
    pub issuer_key_id: String,
    /// CDDL 2 — `aud`. **The operator group, never a single `relay_id`**, which
    /// is what makes ADR-0006's offline failover possible across the ranked set.
    pub audience_operator_group_id: String,
    /// CDDL 3 — `sub`, the per-operator per-day pseudonym. **Never `device_id`.**
    pub subject: [u8; 16],
    /// CDDL 4 — `cnf` (RFC 7800), the COSE_Key octets carrying `RLK_pub`.
    ///
    /// Compared against the leg key the device actually proved possession of, so
    /// a stolen token without `RLK` is inert (ADR-0005 §7.6).
    pub confirmation_key: Vec<u8>,
    /// CDDL 5 — `nbf`.
    pub not_before_ms: u64,
    /// CDDL 6 — `exp`. 24 h lifetime, refreshed at 50 %.
    pub not_after_ms: u64,
    /// CDDL 7 — the S-03 trust epoch at issuance.
    pub epoch: u64,
    /// CDDL 8 — the issuer's quota policy.
    pub quota: Quota,
    /// CDDL 9 — 16 random bytes, for the relay's bounded replay cache.
    pub jti: [u8; 16],
    /// CDDL 10 — set when a relay itself renewed the token under the
    /// epoch-equality rule. **Not a new grant.**
    pub renewed_by_relay: bool,
}

/// A `RelayEpochFloor`'s claims, after the Owner signature verified.
#[derive(Debug, Clone)]
pub struct EpochFloorClaims {
    /// CDDL 1 — the TwinNet this floor belongs to.
    pub twinnet_id: String,
    /// CDDL 2 — the operator group.
    pub operator_group_id: String,
    /// CDDL 3 — **monotone**. A relay applies it only if strictly higher.
    pub epoch_floor: u64,
    /// CDDL 4 — advisory freshness.
    pub not_after_ms: u64,
}

/// What a verified statement turned out to be.
///
/// The caller names the [`crate::crypto::Statement`] it expects, and gets back
/// the matching variant or nothing — so a `RelayEpochFloor` can never be
/// mistaken for a token by a caller that asked for one.
#[derive(Debug, Clone)]
pub enum VerifiedClaims {
    /// A `RelayCapabilityToken`. Boxed: it is much larger than the other variant.
    Token(Box<TokenClaims>),
    /// A `RelayEpochFloor`.
    EpochFloor(EpochFloorClaims),
}

impl VerifiedClaims {
    /// The token claims, if that is what this is.
    #[must_use]
    pub fn as_token(&self) -> Option<&TokenClaims> {
        match self {
            VerifiedClaims::Token(t) => Some(t),
            VerifiedClaims::EpochFloor(_) => None,
        }
    }

    /// The epoch-floor claims, if that is what this is.
    #[must_use]
    pub const fn as_epoch_floor(&self) -> Option<&EpochFloorClaims> {
        match self {
            VerifiedClaims::EpochFloor(f) => Some(f),
            VerifiedClaims::Token(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_quota_defaults_are_adr_0005_11_5s() {
        let q = Quota::default();
        assert_eq!(q.max_concurrent_flows, 64);
        assert_eq!(q.max_bitrate_kbps, 20_000);
        assert_eq!(q.max_bytes_per_hour, 20 * 1024 * 1024 * 1024);
        assert_eq!(q.max_binds_per_min, 30);
    }

    #[test]
    fn a_caller_asking_for_one_statement_kind_cannot_receive_another() {
        let floor = VerifiedClaims::EpochFloor(EpochFloorClaims {
            twinnet_id: "t".into(),
            operator_group_id: "g".into(),
            epoch_floor: 7,
            not_after_ms: 0,
        });
        assert!(floor.as_token().is_none());
        assert_eq!(floor.as_epoch_floor().expect("floor").epoch_floor, 7);
    }
}
