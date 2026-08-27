//! Tier-2 aggregate telemetry: the seven-dimension tuple, and nothing else.
//!
//! **Authority:** ADR-0015 §11.1 (Tier 2 is "coarse, IDENTIFIER-FREE,
//! k-anonymous counters:
//! `{reason_code, outcome, address_family, nat_class, protocol_version,
//! platform_class, day_bucket}`"), ADR-0018 VR-2 consequence 3 (`abi_*` MUST be
//! omitted from Tier-2 aggregate telemetry), ADR-0015 §13 (Tier-2 take-up is low
//! and **biased**, so its aggregates "must never be treated as a representative
//! sample").
//!
//! # Adding a dimension is a deliberate act
//!
//! [`Tier2Sample`] is a struct with exactly seven non-optional fields and no
//! `extra`, no map, no `with_attribute`. Adding an eighth dimension is a source
//! change to this file that a reviewer sees, which is the property §11.1's
//! restrictive shape exists to have. `the_tier2_tuple_is_closed` fails the build
//! if the emitted attribute set ever differs from
//! [`crate::obs::attrs::TIER2_TUPLE`].
//!
//! # Server-side note
//!
//! Tier 2 is a **client** channel, off by default and opt-in. Nothing in the
//! compose topology feeds it (`infra/otel/collector-config.yaml`). This module
//! exists so that the aggregation service — when it is built — shares one
//! definition of the tuple with the services rather than inventing a second, and
//! so the shape is testable now.

use twinvpn_types::{AddressFamily, ReasonCode};

use super::attrs::{self, AttrKey};

/// A coarse, low-cardinality token.
///
/// `&'static str` rather than `String`: a Tier-2 dimension is drawn from a fixed
/// vocabulary the emitter compiles in. A runtime string would let a value
/// derived from an observation — and therefore, eventually, from a peer — become
/// a dimension, which is how an identifier-free aggregate stops being one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoarseToken(&'static str);

impl CoarseToken {
    /// Wraps a compile-time token.
    #[must_use]
    pub const fn new(token: &'static str) -> Self {
        Self(token)
    }
    /// The token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// The NAT classes ADR-0004 distinguishes, as Tier-2 dimensions.
pub mod nat_class {
    use super::CoarseToken;
    /// No NAT observed.
    pub const OPEN: CoarseToken = CoarseToken::new("open");
    /// Endpoint-independent mapping.
    pub const ENDPOINT_INDEPENDENT: CoarseToken = CoarseToken::new("endpoint_independent");
    /// Address-dependent mapping.
    pub const ADDRESS_DEPENDENT: CoarseToken = CoarseToken::new("address_dependent");
    /// Address- and port-dependent mapping (symmetric).
    pub const SYMMETRIC: CoarseToken = CoarseToken::new("symmetric");
    /// Carrier-grade NAT.
    pub const CGNAT: CoarseToken = CoarseToken::new("cgnat");
    /// Not determined.
    pub const UNKNOWN: CoarseToken = CoarseToken::new("unknown");
}

/// Coarse platform classes.
pub mod platform_class {
    use super::CoarseToken;
    /// Desktop-class host.
    pub const DESKTOP: CoarseToken = CoarseToken::new("desktop");
    /// Mobile-class host.
    pub const MOBILE: CoarseToken = CoarseToken::new("mobile");
    /// Router-class host (C-6's constrained target).
    pub const ROUTER: CoarseToken = CoarseToken::new("router");
    /// Server-side artifact.
    pub const SERVER: CoarseToken = CoarseToken::new("server");
}

/// Coarse outcomes. Also the `twinvpn.outcome` metric label of ADR-0015 §9.
pub mod outcome {
    use super::CoarseToken;
    /// The operation completed.
    pub const SUCCESS: CoarseToken = CoarseToken::new("success");
    /// A deliberate refusal.
    pub const REFUSED: CoarseToken = CoarseToken::new("refused");
    /// A bounded wait elapsed.
    pub const TIMEOUT: CoarseToken = CoarseToken::new("timeout");
    /// A transient failure.
    pub const TRANSIENT_FAILURE: CoarseToken = CoarseToken::new("transient_failure");
    /// A persistent failure.
    pub const PERSISTENT_FAILURE: CoarseToken = CoarseToken::new("persistent_failure");
}

/// A whole-day bucket of wall-clock time.
///
/// The only temporal resolution Tier 2 admits. §11.1: "anything finer than a day
/// bucket is a correlation handle, so it is refused rather than rounded" — which
/// is why there is no constructor taking a timestamp *and* a granularity, and why
/// [`DayBucket::from_wall_clock_ms`] discards the intra-day component rather than
/// carrying it in a wider type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DayBucket(u64);

impl DayBucket {
    /// Days since the Unix epoch, from an advisory wall-clock reading.
    ///
    /// The reading is advisory (`common.proto` `WallClockMillis`); a wrong clock
    /// costs a mis-bucketed aggregate and nothing else, which is the only use a
    /// wall clock is permitted here.
    #[must_use]
    pub const fn from_wall_clock_ms(ms: u64) -> Self {
        Self(ms / 86_400_000)
    }

    /// The bucket index.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// One Tier-2 aggregate observation.
///
/// Every field is required. There is no builder, no `Option`, and no escape
/// hatch, because the tuple is the privacy argument: a sample that carries six
/// of the seven is not "mostly compliant", it is a different aggregate with a
/// different k-anonymity property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tier2Sample {
    /// The registered code being counted.
    pub reason_code: ReasonCode,
    /// A coarse outcome token.
    pub outcome: CoarseToken,
    /// Which family the attempt used.
    pub address_family: AddressFamily,
    /// The observed NAT class.
    pub nat_class: CoarseToken,
    /// The negotiated protocol epoch.
    pub protocol_version: u32,
    /// The coarse platform class.
    pub platform_class: CoarseToken,
    /// The day bucket.
    pub day_bucket: DayBucket,
}

impl Tier2Sample {
    /// The exact attribute set this sample contributes.
    ///
    /// Seven pairs, in [`crate::obs::attrs::TIER2_TUPLE`] order. No
    /// `service.instance.id`, no `source_commit`, no `abi_major`, no
    /// `abi_minor` — the collector strips those on the Tier-2 pipeline
    /// (`attributes/tier2-strip-abi`) and this emitter never produces them, so
    /// the strip is a backstop rather than the only control.
    #[must_use]
    pub fn attributes(&self) -> [(AttrKey, String); 7] {
        [
            (attrs::REASON_CODE, self.reason_code.as_str().to_owned()),
            (attrs::OUTCOME, self.outcome.as_str().to_owned()),
            (
                attrs::ADDRESS_FAMILY,
                match self.address_family {
                    AddressFamily::V4 => "v4".to_owned(),
                    AddressFamily::V6 => "v6".to_owned(),
                },
            ),
            (attrs::NAT_CLASS, self.nat_class.as_str().to_owned()),
            (attrs::PROTOCOL_VERSION, self.protocol_version.to_string()),
            (
                attrs::PLATFORM_CLASS,
                self.platform_class.as_str().to_owned(),
            ),
            (attrs::DAY_BUCKET, self.day_bucket.as_u64().to_string()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_types::codes;

    fn sample() -> Tier2Sample {
        Tier2Sample {
            reason_code: codes::NAT_PUNCH_TIMEOUT,
            outcome: outcome::TIMEOUT,
            address_family: AddressFamily::V6,
            nat_class: nat_class::SYMMETRIC,
            protocol_version: 1,
            platform_class: platform_class::DESKTOP,
            day_bucket: DayBucket::from_wall_clock_ms(1_756_252_800_000),
        }
    }

    #[test]
    fn the_tier2_tuple_is_closed() {
        let s = sample();
        let keys: Vec<&str> = s.attributes().iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys.len(), attrs::TIER2_TUPLE.len());
        assert_eq!(keys, attrs::TIER2_TUPLE.to_vec());
    }

    #[test]
    fn abi_and_build_provenance_never_appear() {
        let s = sample();
        for (k, _) in s.attributes() {
            assert!(
                !matches!(
                    k.as_str(),
                    "twinvpn.abi_major"
                        | "twinvpn.abi_minor"
                        | "twinvpn.source_commit"
                        | "twinvpn.schema_digest"
                        | "twinvpn.target_triple"
                        | "service.instance.id"
                ),
                "{k} is forbidden on Tier 2 (ADR-0018 VR-2 consequence 3)"
            );
        }
    }

    #[test]
    fn no_tier2_attribute_is_forbidden_or_unknown() {
        for (k, _) in sample().attributes() {
            assert_eq!(attrs::verdict(k.as_str()), attrs::KeyVerdict::Allowed);
        }
    }

    #[test]
    fn a_day_bucket_discards_the_intra_day_component() {
        let midnight = 1_756_252_800_000u64;
        let later = midnight + 86_400_000 - 1;
        assert_eq!(
            DayBucket::from_wall_clock_ms(midnight),
            DayBucket::from_wall_clock_ms(later)
        );
        assert_ne!(
            DayBucket::from_wall_clock_ms(midnight),
            DayBucket::from_wall_clock_ms(midnight + 86_400_000)
        );
    }

    #[test]
    fn both_families_are_expressible_and_neither_is_a_default() {
        for f in [AddressFamily::V4, AddressFamily::V6] {
            let s = Tier2Sample {
                address_family: f,
                ..sample()
            };
            let rendered = s.attributes()[2].1.clone();
            assert!(rendered == "v4" || rendered == "v6");
        }
    }
}
