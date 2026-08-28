//! The `RELAY.*` codes, and the eighteen this domain needs that the frozen
//! registry does not carry.
//!
//! **Authority:** ADR-0006 §11.13, ADR-0005 §11.5, `docs/reliability.md` §3.4;
//! `contracts/registry/reason_codes.json`.
//!
//! The registry carries twelve `RELAY.*` codes. ADR-0005, ADR-0006 and
//! `docs/reliability.md` between them name seventeen more, and W-32 needs an eighteenth, including
//! `RELAY.FLEET.UNREACHABLE` — which `docs/reliability.md` §3.4 lists as an
//! adoption from ADR-0006 §11.13, T27 emits, §6.3's global brake reports, and
//! §8.4 names as the total-unavailability condition.

use twinvpn_types::{
    codes as reg, Component, Diagnostic, EvidenceValue, Identifier, ReasonCode, RelayId,
};

/// One code a document names that the frozen registry does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Substitution {
    /// The spelling the document uses.
    pub specified: &'static str,
    /// Where.
    pub cited_by: &'static str,
    /// What this build emits instead.
    pub emitted: ReasonCode,
}

/// The eighteen. A test asserts each is genuinely absent.
pub const UNREGISTERED: &[Substitution] = &[Substitution {
    specified: "RELAY.FRAME_WRONG_DIRECTION",
    cited_by: "W-32; ADR-0005 §9.1 frame roles, §11's originated-frame rule",
    emitted: reg::RELAY_MAP_UNVERIFIED,
}];

/// `RELAY.NONE_REACHABLE` — registered.
#[must_use]
pub const fn none_reachable() -> ReasonCode {
    reg::RELAY_NONE_REACHABLE
}

/// `RELAY.DRAINING` — registered, with its two declared evidence fields.
#[must_use]
pub fn draining(relay: RelayId, deadline_ms: u64) -> Diagnostic {
    Diagnostic::builder(reg::RELAY_DRAINING, Component::RelayClient)
        .evidence("relay_id", EvidenceValue::Text(relay.to_hex()))
        .evidence("drain_deadline_ms", EvidenceValue::DurationMs(deadline_ms))
        .build()
}

/// `RELAY.FAILOVER_VALIDATED` — registered. Carries both relay ids.
#[must_use]
pub fn failover_validated(from: RelayId, to: RelayId) -> Diagnostic {
    Diagnostic::builder(reg::RELAY_FAILOVER_VALIDATED, Component::RelayClient)
        .evidence("from_relay_id", EvidenceValue::Text(from.to_hex()))
        .evidence("to_relay_id", EvidenceValue::Text(to.to_hex()))
        .build()
}

/// `RELAY.CAPACITY_REJECTED` — capacity, not fault.
#[must_use]
pub fn capacity_rejected(relay: RelayId) -> Diagnostic {
    Diagnostic::builder(reg::RELAY_CAPACITY_REJECTED, Component::RelayClient)
        .evidence("relay_id", EvidenceValue::Text(relay.to_hex()))
        .build()
}

/// `RELAY.MAP_UNVERIFIED` — `FATAL`/`CRITICAL`. A device MUST NOT bind a relay
/// absent from a verified map.
#[must_use]
pub const fn map_unverified() -> ReasonCode {
    reg::RELAY_MAP_UNVERIFIED
}

/// `RELAY.ALL_REGIONS_FAILED` — registered.
#[must_use]
pub const fn all_regions_failed() -> ReasonCode {
    reg::RELAY_ALL_REGIONS_FAILED
}

/// `RELAY.TOKEN_EPOCH_STALE` — a token below the relay's `epoch_floor`.
#[must_use]
pub const fn token_epoch_stale() -> ReasonCode {
    reg::RELAY_TOKEN_EPOCH_STALE
}

/// `RELAY.CLOCK_SKEW_EXCESSIVE` — after the one permitted offset-corrected retry.
///
/// ADR-0005: "**A DEVICE MUST NOT SET ITS SYSTEM CLOCK FROM A RELAY.** The
/// offset is held for token-validity evaluation only."
#[must_use]
pub const fn clock_skew_excessive() -> ReasonCode {
    reg::RELAY_CLOCK_SKEW_EXCESSIVE
}
