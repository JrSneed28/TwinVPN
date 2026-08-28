//! The three observability tiers, and the one question every emission asks.
//!
//! **Authority:** [ADR-0015](../../../../docs/adr/ADR-0015-observability-and-diagnostics.md)
//! §11.1 (the tier table) and §11.4 (classification and redaction),
//! `contracts/proto/twinvpn/v1/diagnostics.proto` `ObservabilityTier`.

use twinvpn_types::FieldClassification;

/// Which tier a record is being rendered for.
///
/// Mirrors `twinvpn.v1.ObservabilityTier` exactly. There is no `Unspecified`
/// variant here: an emitter that has not decided which tier it is writing for
/// cannot decide what to redact, and defaulting that decision is how `SENSITIVE`
/// data reaches an export (§11.4's "there is no scrub-the-log step, because that
/// approach fails open").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// Tier 0. **Always on, cannot be disabled, never leaves the device.**
    LocalLedger,
    /// Tier 1. Produced on demand; leaves the device **only by explicit user
    /// act**, per artifact. Redacted, pseudonymized, signed, expiring.
    Bundle,
    /// Tier 2. **Off by default**, opt-in. Coarse, identifier-free, k-anonymous
    /// counters only.
    Aggregate,
}

impl Tier {
    /// The wire value of `twinvpn.v1.ObservabilityTier`.
    #[must_use]
    pub const fn to_wire(self) -> i32 {
        match self {
            Tier::LocalLedger => 1,
            Tier::Bundle => 2,
            Tier::Aggregate => 3,
        }
    }

    /// Decodes a wire value. `UNSPECIFIED` is refused rather than defaulted.
    #[must_use]
    pub const fn from_wire(value: i32) -> Option<Self> {
        match value {
            1 => Some(Tier::LocalLedger),
            2 => Some(Tier::Bundle),
            3 => Some(Tier::Aggregate),
            _ => None,
        }
    }

    /// Whether a record at this tier may leave the device at all.
    #[must_use]
    pub const fn leaves_device(self) -> bool {
        !matches!(self, Tier::LocalLedger)
    }

    /// A stable, non-localised tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Tier::LocalLedger => "tier0-local",
            Tier::Bundle => "tier1-bundle",
            Tier::Aggregate => "tier2-aggregate",
        }
    }
}

/// What §11.4's table says to do with one classified field at one tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Carry the value unchanged.
    Include,
    /// Replace the value with a per-bundle pseudonym that preserves structure
    /// and not identity.
    Pseudonymize,
    /// Replace a precise value with a coarse bucket.
    Bucket,
    /// Do not carry the field at all.
    Drop,
}

/// §11.4's table, as a total function.
///
/// `SECRET` is deliberately not an input: `FieldClassification` has no such
/// variant, because "never stored, never rendered, **no code path exists**" and
/// giving it an enum value creates the code path. The absence is the mechanism.
#[must_use]
// Several arms share `Include`. They are written out per (class, tier) pair
// rather than merged because §11.4's table IS the specification: a reader
// checking this against the ADR must be able to find each row, and merging them
// would hide which cell each answer came from.
#[allow(clippy::match_same_arms)]
pub const fn disposition(class: FieldClassification, tier: Tier) -> Disposition {
    match (class, tier) {
        (FieldClassification::Public, _) => Disposition::Include,
        (FieldClassification::Operational, Tier::LocalLedger | Tier::Bundle) => {
            Disposition::Include
        }
        // "bucketed or dropped" — this implementation buckets, because a dropped
        // counter and a zero counter are indistinguishable to a fleet query.
        (FieldClassification::Operational, Tier::Aggregate) => Disposition::Bucket,
        (FieldClassification::Sensitive, Tier::LocalLedger) => Disposition::Include,
        (FieldClassification::Sensitive, Tier::Bundle) => Disposition::Pseudonymize,
        (FieldClassification::Sensitive, Tier::Aggregate) => Disposition::Drop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_never_reaches_tier_two() {
        assert_eq!(
            disposition(FieldClassification::Sensitive, Tier::Aggregate),
            Disposition::Drop
        );
    }

    #[test]
    fn sensitive_is_pseudonymized_in_a_bundle_never_included_verbatim() {
        assert_eq!(
            disposition(FieldClassification::Sensitive, Tier::Bundle),
            Disposition::Pseudonymize
        );
    }

    #[test]
    fn tier_wire_values_round_trip_and_reject_unspecified() {
        for t in [Tier::LocalLedger, Tier::Bundle, Tier::Aggregate] {
            assert_eq!(Tier::from_wire(t.to_wire()), Some(t));
        }
        assert_eq!(Tier::from_wire(0), None);
        assert_eq!(Tier::from_wire(4), None);
    }

    #[test]
    fn only_tier_zero_stays_on_device() {
        assert!(!Tier::LocalLedger.leaves_device());
        assert!(Tier::Bundle.leaves_device());
        assert!(Tier::Aggregate.leaves_device());
    }
}
