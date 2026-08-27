//! Every condition ADR-0005 §11.7 names, mapped to a **registered** reason code.
//!
//! # The finding this module exists to make visible
//!
//! ADR-0005 §11.7 contributes 26 `RELAY.*` codes and ADR-0006 §11.13 contributes
//! a further 29. `contracts/registry/reason_codes.json` contains **twelve**
//! `RELAY.*` codes in total. Forty-three of the names those two ADRs use have no
//! registry entry, so `twinvpn-types` has no constant for them and — by design
//! (`twinvpn_types::reason`: "a code that is not in the registry has no constant
//! to name") — this crate physically cannot emit them.
//!
//! `contracts/` is frozen (`ownership.md` §3), so this is reported, not patched.
//! The interim rule is the same one the integration lead accepted for W-11:
//! **degrade onto the nearest registered code, and never leave the `RELAY`
//! domain**, because ADR-0015 §11.2 rule 5's whole forward-compatibility story is
//! prefix degradation — a receiver that meets `NET.*` where a relay condition
//! occurred degrades to the wrong diagnosis.
//!
//! [`Condition::fidelity`] says, per condition, whether the registry can express
//! it exactly. `mapping_is_total_and_honest` enumerates every variant.
//!
//! **The cost, stated plainly:** a device cannot currently distinguish "your peer
//! never arrived at the pending slot" from "I am at capacity" — both degrade to
//! `RELAY.CAPACITY_REJECTED`. That is a real diagnostic loss and is exactly why
//! the amendment procedure is needed rather than a better local guess.

use twinvpn_service_common::ServiceError;
use twinvpn_types::evidence::EvidenceValue;
use twinvpn_types::{codes, ReasonCode};

/// Whether the frozen registry can express a condition exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fidelity {
    /// The registry has the code ADR-0005 / ADR-0006 names.
    Exact,
    /// The registry does not. The nearest registered `RELAY.*` code is used and
    /// the specific condition is lost to the receiver.
    Degraded,
}

/// A relay-side condition, named exactly as ADR-0005 §11.7 names it.
///
/// This enum is the vocabulary; [`Condition::reason_code`] is the only bridge to
/// the wire, so no relay code path can invent an unregistered string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Condition {
    /// No token was presented on the leg.
    TokenMissing,
    /// The COSE signature did not verify, or the payload was malformed.
    TokenInvalid,
    /// `now > exp + skew`.
    TokenExpired,
    /// `now < nbf - skew`. Registry has no distinct code; see the module note.
    TokenNotYetValid,
    /// `aud` is not this relay's operator group.
    TokenAudienceMismatch,
    /// `epoch < epoch_floor` (ADR-0005 §11.3 revocation, defence in depth).
    TokenEpochStale,
    /// The `cnf` claim did not match the presented relay-leg static key.
    TokenPopFailed,
    /// The `jti` was already seen inside the bounded replay window.
    TokenReplayed,
    /// The token's `iss` is not in the held issuer key set — including the case
    /// where the set is **empty**, which is the fail-closed default.
    IssuerUnknown,
    /// A second failure after the offset retry (ADR-0005 §11.3).
    ClockSkewExcessive,
    /// A pending slot expired without a second `BIND` (30 s).
    PairUnmatched,
    /// A third `BIND` arrived on an already-bound `pair_tag`.
    PairCollision,
    /// `max_concurrent_flows` for this `relay_sub` is reached.
    FlowLimitReached,
    /// `max_binds_per_min` for this `relay_sub` is reached.
    BindRateLimited,
    /// A token bucket throttled — per-subject or per-flow.
    RateLimited,
    /// `max_bytes_per_hour` for this `relay_sub` is reached.
    QuotaExceeded,
    /// A bound half-flow was reclaimed after 15 minutes idle.
    FlowIdleTimeout,
    /// The relay is draining. ADR-0005 §8 / reliability T37.
    Draining,
    /// The relay restarted and every half-flow died with it (RQ10).
    Restarted,
    /// The relay is shedding under load.
    Overloaded,
    /// The `ver` nibble names a version this build does not speak.
    VersionUnsupported,
    /// No configured carriage reached a serving state.
    TransportUnavailable,
    /// A carriage cannot carry a 1280-byte overlay packet (ADR-0005 §9.2).
    MtuFloorViolated,
    /// Registration-time: a relay must publish both address families.
    DualStackRequired,
    /// The only relay in the map is self-hosted (R-11).
    SelfHostedNoAlternate,
    /// No second relay in a different failure domain could be offered.
    StandbyUnavailable,
}

impl Condition {
    /// The registered `reason_code` this condition is emitted as.
    ///
    /// Never leaves the `RELAY` domain except where the registry offers no
    /// `RELAY.*` code at all for the shape of the condition.
    #[must_use]
    pub const fn reason_code(self) -> ReasonCode {
        match self {
            // --- exact ---
            Condition::TokenInvalid
            // --- degraded onto TOKEN_INVALID: same class (PERSISTENT), same
            // remediation, and all of them mean "this token does not admit you".
            | Condition::TokenMissing
            | Condition::TokenAudienceMismatch
            | Condition::TokenPopFailed
            | Condition::TokenReplayed
            | Condition::IssuerUnknown => codes::RELAY_TOKEN_INVALID,

            Condition::TokenExpired
            // TRANSIENT, and it clears on its own once the clock or the token
            // moves — the same retry behaviour a NOT_YET_VALID needs. Mapping it
            // onto TOKEN_INVALID would be worse: that code is `terminal`.
            | Condition::TokenNotYetValid => codes::RELAY_TOKEN_EXPIRED,

            Condition::TokenEpochStale => codes::RELAY_TOKEN_EPOCH_STALE,
            Condition::ClockSkewExcessive => codes::RELAY_CLOCK_SKEW_EXCESSIVE,
            Condition::Draining => codes::RELAY_DRAINING,

            // --- degraded onto CAPACITY_REJECTED: TRANSIENT, non-terminal,
            // relay-scoped, and every one of them is "this relay will not carry
            // this flow right now, try elsewhere", which is the behaviour the
            // device needs. What is lost is *which* of them it was.
            Condition::PairUnmatched
            | Condition::PairCollision
            | Condition::FlowLimitReached
            | Condition::BindRateLimited
            | Condition::RateLimited
            | Condition::QuotaExceeded
            | Condition::FlowIdleTimeout
            | Condition::Restarted
            | Condition::Overloaded
            | Condition::StandbyUnavailable
            | Condition::SelfHostedNoAlternate => codes::RELAY_CAPACITY_REJECTED,

            // --- degraded onto NONE_REACHABLE: PERSISTENT, and from the
            // device's side a relay whose carriage, version or MTU it cannot use
            // is a relay it cannot reach.
            Condition::TransportUnavailable
            | Condition::VersionUnsupported
            | Condition::MtuFloorViolated
            | Condition::DualStackRequired => codes::RELAY_NONE_REACHABLE,
        }
    }

    /// Whether the frozen registry expresses this condition exactly.
    #[must_use]
    pub const fn fidelity(self) -> Fidelity {
        match self {
            Condition::TokenInvalid
            | Condition::TokenExpired
            | Condition::TokenEpochStale
            | Condition::ClockSkewExcessive
            | Condition::Draining => Fidelity::Exact,
            _ => Fidelity::Degraded,
        }
    }

    /// The ADR-0005 §11.7 / ADR-0006 §11.13 name, for a log line and for the
    /// finding register. **Never put on the wire** — it is not a registered code.
    #[must_use]
    pub const fn adr_name(self) -> &'static str {
        match self {
            Condition::TokenMissing => "RELAY.TOKEN_MISSING",
            Condition::TokenInvalid => "RELAY.TOKEN_INVALID",
            Condition::TokenExpired => "RELAY.TOKEN_EXPIRED",
            Condition::TokenNotYetValid => "RELAY.TOKEN_NOT_YET_VALID",
            Condition::TokenAudienceMismatch => "RELAY.TOKEN_AUDIENCE_MISMATCH",
            Condition::TokenEpochStale => "RELAY.TOKEN_EPOCH_STALE",
            Condition::TokenPopFailed => "RELAY.TOKEN_POP_FAILED",
            Condition::TokenReplayed => "RELAY.TOKEN_REPLAYED",
            Condition::IssuerUnknown => "RELAY.ISSUER_UNKNOWN",
            Condition::ClockSkewExcessive => "RELAY.CLOCK_SKEW_EXCESSIVE",
            Condition::PairUnmatched => "RELAY.PAIR_UNMATCHED",
            Condition::PairCollision => "RELAY.PAIR_COLLISION",
            Condition::FlowLimitReached => "RELAY.FLOW_LIMIT_REACHED",
            Condition::BindRateLimited => "RELAY.BIND_RATE_LIMITED",
            Condition::RateLimited => "RELAY.RATE_LIMITED",
            Condition::QuotaExceeded => "RELAY.QUOTA_EXCEEDED",
            Condition::FlowIdleTimeout => "RELAY.FLOW_IDLE_TIMEOUT",
            Condition::Draining => "RELAY.DRAINING",
            Condition::Restarted => "RELAY.RESTARTED",
            Condition::Overloaded => "RELAY.OVERLOADED",
            Condition::VersionUnsupported => "RELAY.VERSION_UNSUPPORTED",
            Condition::TransportUnavailable => "RELAY.TRANSPORT_UNAVAILABLE",
            Condition::MtuFloorViolated => "RELAY.MTU_FLOOR_VIOLATED",
            Condition::DualStackRequired => "RELAY.DUAL_STACK_REQUIRED",
            Condition::SelfHostedNoAlternate => "RELAY.SELF_HOSTED_NO_ALTERNATE",
            Condition::StandbyUnavailable => "RELAY.STANDBY_UNAVAILABLE",
        }
    }

    /// Every variant, so a test can enumerate the mapping exhaustively.
    #[must_use]
    pub const fn all() -> &'static [Condition] {
        &[
            Condition::TokenMissing,
            Condition::TokenInvalid,
            Condition::TokenExpired,
            Condition::TokenNotYetValid,
            Condition::TokenAudienceMismatch,
            Condition::TokenEpochStale,
            Condition::TokenPopFailed,
            Condition::TokenReplayed,
            Condition::IssuerUnknown,
            Condition::ClockSkewExcessive,
            Condition::PairUnmatched,
            Condition::PairCollision,
            Condition::FlowLimitReached,
            Condition::BindRateLimited,
            Condition::RateLimited,
            Condition::QuotaExceeded,
            Condition::FlowIdleTimeout,
            Condition::Draining,
            Condition::Restarted,
            Condition::Overloaded,
            Condition::VersionUnsupported,
            Condition::TransportUnavailable,
            Condition::MtuFloorViolated,
            Condition::DualStackRequired,
            Condition::SelfHostedNoAlternate,
            Condition::StandbyUnavailable,
        ]
    }

    /// A `ServiceError` carrying this condition's registered code.
    ///
    /// Evidence is attached **only** where the registry declares a key for it;
    /// `Diagnostic::builder` drops an undeclared key, so this is an offer.
    /// Nothing here carries a `pair_tag`, a `flow_id`, a subject or a peer.
    #[must_use]
    pub fn error(self, relay_id: &str) -> ServiceError {
        ServiceError::new(self.reason_code(), crate::COMPONENT)
            .evidence("relay_id", EvidenceValue::Text(relay_id.to_owned()))
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_types::Domain;

    #[test]
    fn mapping_is_total_and_stays_in_the_relay_domain() {
        for c in Condition::all() {
            let code = c.reason_code();
            assert_eq!(
                code.domain(),
                Domain::Relay,
                "{} degraded out of the RELAY domain, which breaks ADR-0015 \
                 §11.2 rule 5's prefix degradation",
                c.adr_name()
            );
        }
    }

    #[test]
    fn every_adr_name_is_distinct_and_the_registry_covers_only_five_exactly() {
        let mut names: Vec<&str> = Condition::all().iter().map(|c| c.adr_name()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate ADR name");

        let exact = Condition::all()
            .iter()
            .filter(|c| c.fidelity() == Fidelity::Exact)
            .count();
        assert_eq!(
            exact, 5,
            "the frozen registry expresses five of ADR-0005 §11.7's twenty-six \
             conditions exactly. If this number changed, the registry moved and \
             the finding in this module's docs must be re-checked."
        );
    }

    #[test]
    fn a_not_yet_valid_token_is_not_terminal() {
        // A token that is merely early becomes valid by waiting. Degrading it
        // onto the terminal TOKEN_INVALID would tell the device to give up.
        assert!(!Condition::TokenNotYetValid.reason_code().terminal());
        assert!(Condition::TokenInvalid.reason_code().terminal());
    }

    #[test]
    fn an_empty_issuer_set_produces_a_refusal_not_an_admission() {
        // IssuerUnknown is the code an empty key set yields; it must be a
        // refusal, never anything a caller could read as "proceed".
        let e = Condition::IssuerUnknown.error("0000000000000a01");
        assert_eq!(e.code(), codes::RELAY_TOKEN_INVALID);
    }
}
