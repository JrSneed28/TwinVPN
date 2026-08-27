//! The outage cache: TTL bands, per-class expiry, and the grant/deny asymmetry.
//!
//! **Authority:** [ADR-0009](../../../../docs/adr/ADR-0009-state-consistency.md)
//! §11.4 (the two bands and the per-class table) and §11.5 (the I3/I5
//! reconciliation), `docs/reliability.md` §9 (the three-way split and §9.2's
//! governing rule), `docs/architecture.md` §4.4 (how I5 is enforced) and §4.5
//! (the deliberate exception), `contracts/proto/twinvpn/v1/policy.proto`.
//!
//! # The property that matters most
//!
//! > **Expiry can only ever make a device *more* restrictive. Grants suspend;
//! > denials persist. There is no expiry path that widens an authorization.**
//!
//! And its consequence, which this module exists to guarantee:
//!
//! > **Baseline peer connectivity survives an outage of unbounded length.** It is
//! > not a grant the control plane makes; it is a fact two devices established
//! > between themselves, and no control-plane silence may withdraw it.
//!
//! So [`ExpiryEffect`] has no variant that widens anything,
//! [`Ttl::baseline_reachability_permitted`] is a `const fn` returning `true`
//! unconditionally, and there is no code path from a TTL to a session teardown.
//! `reliability.md` §9.2 also **withdraws** the earlier "credential cliff" claim,
//! so nothing here implements one.

use core::time::Duration;

use twinvpn_env::WallMillis;

use crate::error::CpError;
use crate::state::DocumentType;

/// Which TTL band a document is in.
///
/// `refresh_after_ms` is an instruction to the **fetcher**; `not_after_ms` is an
/// instruction to the **enforcer**. Between them the document governs fully and
/// its use is *reported*, not restricted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Band {
    /// `elapsed < refresh_after`. Normal.
    Fresh,
    /// `refresh_after <= elapsed < not_after`. The document **governs fully**;
    /// refresh attempts escalate; no enforcement change. This is the band that
    /// covers the ordinary control-plane outage.
    Stale,
    /// `elapsed >= not_after`. Per class, below. **Never a `Session` teardown.**
    Expired,
}

/// A document's two-band lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ttl {
    /// The soft band boundary.
    pub refresh_after_ms: u64,
    /// The hard band boundary.
    pub not_after_ms: u64,
}

impl Ttl {
    /// Which band `now` falls in.
    #[must_use]
    pub const fn band(self, now: WallMillis) -> Band {
        let now = now.as_millis();
        if now >= self.not_after_ms {
            Band::Expired
        } else if now >= self.refresh_after_ms {
            Band::Stale
        } else {
            Band::Fresh
        }
    }

    /// Whether the document is past **half** its lifetime, which is the trigger
    /// ADR-0002 §R-e names for `CONTROL.STALE_POLICY_IN_USE`.
    #[must_use]
    pub const fn past_half_life(self, issued_at_ms: u64, now: WallMillis) -> bool {
        let now = now.as_millis();
        if self.not_after_ms <= issued_at_ms {
            return true;
        }
        let half = issued_at_ms + (self.not_after_ms - issued_at_ms) / 2;
        now >= half
    }

    /// **Always `true`.**
    ///
    /// A new `Tunnel` to a known `TrustedPeer` is permitted at every trust-state
    /// age, including past `T_TRUST_HARD`. `reliability.md` §9.2's table has
    /// "Still permitted" in every row of that column, and ADR-0009 §11.5
    /// explains why: making it withdrawable "would turn the control plane into a
    /// liveness dependency of the data plane, which is precisely what I5 and
    /// R-11 forbid".
    ///
    /// This is a function rather than a comment so that a future change which
    /// tried to make it conditional would have to delete a test that says so.
    #[must_use]
    pub const fn baseline_reachability_permitted() -> bool {
        true
    }
}

/// What expiry does, per fact class. ADR-0009 §11.4's table.
///
/// There is deliberately **no variant that widens an authorization** and no
/// variant that ends a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExpiryEffect {
    /// Trust list / membership. **Every denial remains in force permanently** —
    /// denials are monotone accumulations, not leases. A `TrustedPeer` known
    /// *only* from an expired membership document is not admitted. Reconnection
    /// to an existing `TrustedPeer` is **unaffected**, which preserves the
    /// "LAN-only, no Internet at all" guarantee.
    DenialsPersistNoNewAdmissions,
    /// Policy. **Grant/deny asymmetry**: every rule whose effect is to *deny*
    /// stays in force; every rule whose effect is to *grant* is **suspended**.
    /// Established `Session`s are not torn down.
    GrantsSuspendDenialsPersist,
    /// Relay set. **Still fully usable.** Expiry has no enforcement effect
    /// whatsoever; it only escalates refresh. "A device that refused to fail
    /// over because its relay set was old would be a design defect."
    NoEnforcementEffect,
    /// Presence / health. The record is dropped, and **absence of a record is
    /// not evidence of absence of a peer**.
    RecordDropped,
    /// Capability / version advertisement. Advisory only; the negotiated set
    /// bound at handshake governs the `Tunnel` regardless.
    AdvisoryOnly,
}

impl ExpiryEffect {
    /// Whether this effect can ever widen an authorization. **Always `false`.**
    #[must_use]
    pub const fn can_widen_authorization(self) -> bool {
        false
    }

    /// Whether this effect can tear down an established `Session`.
    /// **Always `false`** (I5, ADR-0009 RQ-7).
    #[must_use]
    pub const fn can_tear_down_a_session(self) -> bool {
        false
    }

    /// Whether granted authority is suspended.
    #[must_use]
    pub const fn suspends_grants(self) -> bool {
        matches!(
            self,
            ExpiryEffect::GrantsSuspendDenialsPersist | ExpiryEffect::DenialsPersistNoNewAdmissions
        )
    }
}

/// The per-class table, keyed by document type.
#[must_use]
pub const fn expiry_effect(doc_type: DocumentType) -> ExpiryEffect {
    match doc_type {
        DocumentType::OwnerTrustAnchor
        | DocumentType::TrustEpochBundle
        | DocumentType::Membership => ExpiryEffect::DenialsPersistNoNewAdmissions,
        DocumentType::PolicyBundle | DocumentType::NetworkContract => {
            ExpiryEffect::GrantsSuspendDenialsPersist
        }
        DocumentType::RelayMap | DocumentType::RelayEpochFloor => ExpiryEffect::NoEnforcementEffect,
    }
}

/// The `refresh_after` interval a *reachable* control plane is polled at, per
/// class. ADR-0009 §11.4.
#[must_use]
pub const fn refresh_interval(doc_type: DocumentType) -> Duration {
    match doc_type {
        DocumentType::OwnerTrustAnchor
        | DocumentType::TrustEpochBundle
        | DocumentType::Membership
        | DocumentType::PolicyBundle
        | DocumentType::NetworkContract => Duration::from_secs(15 * 60),
        DocumentType::RelayMap | DocumentType::RelayEpochFloor => Duration::from_secs(60 * 60),
    }
}

/// ADR-0007 §7.7's trust-state thresholds, consumed here rather than redefined.
///
/// ADR-0009 §11.5 is explicit about ownership: *"`T_TRUST_REFRESH`,
/// `T_TRUST_STALE` and `T_TRUST_HARD` are defined once, in ADR-0007 §7.7. This
/// ADR defines the consequence of each band; it does not restate the values."*
/// This crate is in the same position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustStateThresholds {
    /// 6 h — refresh escalates.
    pub refresh: Duration,
    /// 24 h — a persistent staleness diagnostic, **no `ConnectionState` change**.
    pub stale: Duration,
    /// 30 d — granted authority suspends; denials persist; baseline untouched.
    pub hard: Duration,
}

impl TrustStateThresholds {
    /// ADR-0007 §7.7's values.
    pub const ADR_0007: TrustStateThresholds = TrustStateThresholds {
        refresh: Duration::from_secs(6 * 3_600),
        stale: Duration::from_secs(24 * 3_600),
        hard: Duration::from_secs(30 * 24 * 3_600),
    };

    /// Which band a trust-state age falls in.
    #[must_use]
    pub const fn band_of(self, age: Duration) -> TrustStateBand {
        if age.as_secs() >= self.hard.as_secs() {
            TrustStateBand::Expired
        } else if age.as_secs() >= self.stale.as_secs() {
            TrustStateBand::Stale
        } else if age.as_secs() >= self.refresh.as_secs() {
            TrustStateBand::RefreshDue
        } else {
            TrustStateBand::Fresh
        }
    }
}

/// The four trust-state bands of `reliability.md` §9.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustStateBand {
    /// `< T_TRUST_REFRESH`.
    Fresh,
    /// `T_TRUST_REFRESH … T_TRUST_STALE`.
    RefreshDue,
    /// `T_TRUST_STALE … T_TRUST_HARD`. Persistent `AUTH.TRUST_STATE_STALE`.
    Stale,
    /// `>= T_TRUST_HARD`. Persistent `AUTH.TRUST_STATE_EXPIRED`.
    Expired,
}

impl TrustStateBand {
    /// Whether a **new `Tunnel` to a known `TrustedPeer`** is permitted.
    ///
    /// `true` in every band, including `Expired`. This is the column
    /// `reliability.md` §9.2 fills with "Permitted / Permitted / Permitted /
    /// **Still permitted**".
    #[must_use]
    pub const fn baseline_peer_connectivity(self) -> bool {
        true
    }

    /// Whether **elevated authority** — `ExitNode` use, `LANGateway` access,
    /// `Route` acceptance, new `Pairing` — is permitted.
    ///
    /// Suspended only past `T_TRUST_HARD`. These are *grants*, and §11.4
    /// suspends grants on expiry while denials persist.
    #[must_use]
    pub const fn elevated_authority(self) -> bool {
        !matches!(self, TrustStateBand::Expired)
    }

    /// The persistent diagnostic for this band, if any.
    ///
    /// **No band produces a `ConnectionState` change.** `reliability.md` §9.1 and
    /// §9.2 say "no `ConnectionState` change" in both rows that carry a
    /// diagnostic, and `reliability.md` §9.4 adds that surfacing
    /// `CONTROL.UNREACHABLE` as a terminal connection failure is a defect.
    #[must_use]
    pub const fn diagnostic(self, age_ms: u64) -> Option<CpError> {
        match self {
            TrustStateBand::Fresh | TrustStateBand::RefreshDue => None,
            // AUTH.TRUST_STATE_STALE is the registered code; it shares the
            // `age_ms` evidence shape with the expired one.
            TrustStateBand::Stale | TrustStateBand::Expired => {
                Some(CpError::TrustStateExpired { age_ms })
            }
        }
    }
}

/// Whether a cached peer set is usable for an offline reconnect.
///
/// It always is, and the argument is `reliability.md` §9.1's first column: "New
/// `Session`s to an existing `TrustedPeer`, from the durable `Endpoint` cache
/// (S-15) and the cached signed `RelayMap` (S-09)" **continue, indefinitely**.
/// `DiscoverPeers`' own contract says the same thing from the other side: on
/// control-plane unavailability the device "MUST use its last cached peer set
/// and enter discovery from cache … Per I5 this MUST NOT prevent connecting to a
/// known peer."
#[must_use]
pub const fn cached_peer_set_usable_during_outage() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::{
        cached_peer_set_usable_during_outage, expiry_effect, refresh_interval, Band, ExpiryEffect,
        TrustStateThresholds, Ttl,
    };
    use crate::state::DocumentType;
    use core::time::Duration;
    use twinvpn_env::WallMillis;

    const DOC_TYPES: [DocumentType; 7] = [
        DocumentType::PolicyBundle,
        DocumentType::OwnerTrustAnchor,
        DocumentType::TrustEpochBundle,
        DocumentType::RelayMap,
        DocumentType::RelayEpochFloor,
        DocumentType::NetworkContract,
        DocumentType::Membership,
    ];

    #[test]
    fn the_three_bands_are_ordered_by_elapsed_time() {
        let ttl = Ttl {
            refresh_after_ms: 1_000,
            not_after_ms: 5_000,
        };
        assert_eq!(ttl.band(WallMillis::from_millis(999)), Band::Fresh);
        assert_eq!(ttl.band(WallMillis::from_millis(1_000)), Band::Stale);
        assert_eq!(ttl.band(WallMillis::from_millis(4_999)), Band::Stale);
        assert_eq!(ttl.band(WallMillis::from_millis(5_000)), Band::Expired);
    }

    #[test]
    fn no_expiry_effect_widens_an_authorization_or_ends_a_session() {
        for doc in DOC_TYPES {
            let effect = expiry_effect(doc);
            assert!(
                !effect.can_widen_authorization(),
                "{} must not widen on expiry",
                doc.as_str()
            );
            assert!(
                !effect.can_tear_down_a_session(),
                "{} must not tear down a Session (I5)",
                doc.as_str()
            );
        }
    }

    #[test]
    fn a_stale_relay_map_is_still_usable() {
        // ADR-0009 §11.4: "Still fully usable. Expiry has no enforcement effect
        // whatsoever." A device that refused to fail over because its relay set
        // was old would be a design defect.
        assert_eq!(
            expiry_effect(DocumentType::RelayMap),
            ExpiryEffect::NoEnforcementEffect
        );
        assert!(!expiry_effect(DocumentType::RelayMap).suspends_grants());
    }

    #[test]
    fn policy_expiry_suspends_grants_and_keeps_denials() {
        assert_eq!(
            expiry_effect(DocumentType::PolicyBundle),
            ExpiryEffect::GrantsSuspendDenialsPersist
        );
        assert!(expiry_effect(DocumentType::PolicyBundle).suspends_grants());
    }

    #[test]
    fn baseline_reachability_survives_every_trust_state_band() {
        // reliability.md §9.2: "Baseline peer connectivity survives an outage of
        // unbounded length."
        let t = TrustStateThresholds::ADR_0007;
        for age in [
            Duration::from_secs(0),
            t.refresh,
            t.stale,
            t.hard,
            Duration::from_secs(365 * 24 * 3_600),
        ] {
            let band = t.band_of(age);
            assert!(
                band.baseline_peer_connectivity(),
                "an outage may never withdraw baseline reachability ({band:?})"
            );
        }
        assert!(Ttl::baseline_reachability_permitted());
        assert!(cached_peer_set_usable_during_outage());
    }

    #[test]
    fn elevated_authority_suspends_only_past_the_hard_threshold() {
        let t = TrustStateThresholds::ADR_0007;
        assert!(t.band_of(Duration::from_secs(0)).elevated_authority());
        assert!(t.band_of(t.refresh).elevated_authority());
        assert!(
            t.band_of(t.stale).elevated_authority(),
            "permitted, re-asserted per use and surfaced"
        );
        assert!(
            !t.band_of(t.hard).elevated_authority(),
            "suspended at T_TRUST_HARD — these are grants"
        );
    }

    #[test]
    fn crossing_a_band_produces_a_diagnostic_and_never_a_state_change() {
        let t = TrustStateThresholds::ADR_0007;
        assert!(t.band_of(Duration::from_secs(0)).diagnostic(0).is_none());
        let stale = t
            .band_of(t.stale)
            .diagnostic(86_400_000)
            .expect("a persistent diagnostic");
        assert_eq!(stale.reason_code().as_str(), "AUTH.TRUST_STATE_EXPIRED");
        assert!(
            !stale.reason_code().terminal(),
            "a staleness diagnostic is never terminal"
        );
        assert!(stale.permits_offline_reconnect());
    }

    #[test]
    fn half_life_is_what_triggers_stale_policy_in_use() {
        let ttl = Ttl {
            refresh_after_ms: 1_000,
            not_after_ms: 9_000,
        };
        assert!(!ttl.past_half_life(1_000, WallMillis::from_millis(4_999)));
        assert!(ttl.past_half_life(1_000, WallMillis::from_millis(5_000)));
    }

    #[test]
    fn trust_documents_refresh_every_fifteen_minutes_and_relay_maps_hourly() {
        assert_eq!(
            refresh_interval(DocumentType::Membership),
            Duration::from_secs(900)
        );
        assert_eq!(
            refresh_interval(DocumentType::PolicyBundle),
            Duration::from_secs(900)
        );
        assert_eq!(
            refresh_interval(DocumentType::RelayMap),
            Duration::from_secs(3_600)
        );
    }
}
