//! The leak canary's counters, folded out of WFP net events.
//!
//! **Authority:** ADR-0012 §11.9 (the leak canary), KS-11 (per-family exempt
//! accounting), K12 (observability by query); ADR-0015 §11.6 mechanism 4.
//!
//! # Windows has no counter objects, so the counters are a fold
//!
//! `nftables` exports named counters and `desktop-linux` reads them straight
//! out of the kernel's own answer. WFP has nothing equivalent: a `FWPM_FILTER0`
//! carries no byte or packet count. What it has is the **net-event stream** —
//! `FwpmNetEventEnum0` / `FwpmNetEventSubscribe0`, enabled by
//! `FwpmEngineSetOption0(FWPM_ENGINE_COLLECT_NET_EVENTS)` — in which every
//! classify-drop carries the `filterId` that dropped it.
//!
//! So on this platform KS-11's counters are **derived by folding events keyed on
//! our own filters**, and this module is that fold. It is a pure function of a
//! slice, so the arithmetic — which is the part that decides whether a leak is
//! reported — is host-testable in full; only the subscription that produces the
//! slice needs Windows.
//!
//! # Two consequences of the mechanism, stated rather than discovered
//!
//! 1. **The stream can drop.** `FWPM_NET_EVENT` delivery is best-effort and the
//!    engine's buffer is finite. A fold over a stream that lost events
//!    under-counts, and under-counting a *deny* counter is the direction that
//!    reports a leak that did not happen — the safe direction, but still a fact
//!    a caller must know. [`CounterSnapshot::lost_events`] carries it, and
//!    [`canary_verdict`] refuses to answer `Denied` from a lossy window.
//! 2. **Events are per connection, not per byte.** ALE classify-drop fires once
//!    per connection attempt, so a "byte count" is not available at this layer
//!    and this module counts *events*. KS-11 asks for "byte and packet counters
//!    for the exempt rule"; what Windows can supply here is a connection count.
//!    That is a **reported shortfall**, not a substitution dressed up as the
//!    thing asked for — see [`CounterSnapshot::unit`].

use twinvpn_types::{AddressFamily, PerFamily};

use super::readback::class_of;
use super::{Guid, TrafficClass};

/// What a counter in a [`CounterSnapshot`] counts.
///
/// One value today, and an enum rather than a doc comment because KS-11 asks for
/// bytes and this platform supplies connections: the shortfall travels with the
/// number so a comparison against the agent's own frame accounting cannot
/// silently compare a byte count with a connection count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterUnit {
    /// One count per ALE connection classification.
    Connections,
}

/// One WFP net event, reduced to what the fold needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetEvent {
    /// What the engine did.
    pub kind: NetEventKind,
    /// The family the classification happened in.
    pub family: AddressFamily,
    /// The filter that made the decision, when the engine attributed one.
    ///
    /// `None` is common and is not an error: a drop by a Microsoft default
    /// filter, or by another product's, has no key of ours. Those are counted in
    /// [`CounterSnapshot::unattributed`] rather than charged to us, because
    /// charging somebody else's drop to our deny counter would make the canary
    /// pass on a host where our rules are gone.
    pub filter: Option<Guid>,
}

/// The event kinds the fold reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetEventKind {
    /// `FWPM_NET_EVENT_TYPE_CLASSIFY_DROP`.
    ClassifyDrop,
    /// `FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW`.
    ClassifyAllow,
}

/// The counters ADR-0012 §11.9 compares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterSnapshot {
    /// Drops charged to a Tier-1 scope deny, per family.
    ///
    /// Per family, because the canary runs per family and a single combined
    /// counter would let a v6 leak hide behind v4 drops.
    pub deny: PerFamily<u64>,
    /// Permits charged to an exempt class, per family (KS-11).
    pub exempt: PerFamily<u64>,
    /// Drops charged to the DNS containment rule.
    ///
    /// Its own number, not one of [`Self::deny`]'s, because ADR-0011's negative
    /// canary asks a different question from ADR-0012's — "was my off-tunnel DNS
    /// query dropped" rather than "was my off-tunnel protected packet dropped".
    pub dns_deny: u64,
    /// Classifications the engine did not attribute to a filter of ours.
    pub unattributed: u64,
    /// Whether the engine reported that events were dropped from the stream.
    pub lost_events: bool,
    /// What the numbers count.
    pub unit: CounterUnit,
}

impl CounterSnapshot {
    /// An all-zero snapshot over a stream that lost nothing.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            deny: PerFamily::new(0, 0),
            exempt: PerFamily::new(0, 0),
            dns_deny: 0,
            unattributed: 0,
            lost_events: false,
            unit: CounterUnit::Connections,
        }
    }
}

/// Folds a window of net events into the counters.
///
/// `lost` is what the engine said about its own buffer; it is carried through
/// rather than inferred, because "we saw no events" and "we were not told about
/// the events" are different facts with different consequences.
#[must_use]
pub fn fold(events: &[NetEvent], lost: bool) -> CounterSnapshot {
    let mut snapshot = CounterSnapshot {
        lost_events: lost,
        ..CounterSnapshot::empty()
    };
    for event in events {
        let class = event.filter.and_then(class_of);
        match (event.kind, class) {
            (NetEventKind::ClassifyDrop, Some(TrafficClass::ProtectedScopeDeny)) => {
                *snapshot.deny.get_mut(event.family) += 1;
            }
            (NetEventKind::ClassifyDrop, Some(TrafficClass::DnsContainment)) => {
                snapshot.dns_deny += 1;
            }
            (NetEventKind::ClassifyAllow, Some(class)) if class.is_exempt_egress() => {
                *snapshot.exempt.get_mut(event.family) += 1;
            }
            // A permit charged to a class that is not exempt egress — loopback,
            // the overlay itself — is ours and is deliberately not counted:
            // KS-11's comparison is against the agent's own frame accounting,
            // and a floor that has nothing to do with the bootstrap channel
            // would make every window look anomalous.
            (_, Some(_)) => {}
            (_, None) => snapshot.unattributed += 1,
        }
    }
    snapshot
}

/// What the canary observed.
///
/// ADR-0012 §11.9: "the agent emits a uniquely marked datagram from a
/// **non-exempt** socket to a destination in the protected scope and asserts that
/// the enforcement layer's deny counter for that family incremented."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryVerdict {
    /// The deny counter for that family incremented. The rule is live.
    Denied,
    /// It did not. `POLICY.LEAK.EGRESS_OBSERVED`'s condition, at `CRITICAL`.
    EgressObserved,
    /// The window lost events, so no conclusion is available.
    ///
    /// **Not `Denied`.** A lossy window under-counts, and under-counting the
    /// deny counter would report a leak that did not happen; but treating
    /// "we do not know" as "the rule is live" is the failure that lets a real
    /// leak through, so the third value exists rather than a `bool`.
    Indeterminate,
}

/// Compares two snapshots for one family.
#[must_use]
pub fn canary_verdict(
    before: &CounterSnapshot,
    after: &CounterSnapshot,
    family: AddressFamily,
) -> CanaryVerdict {
    if before.lost_events || after.lost_events {
        return CanaryVerdict::Indeterminate;
    }
    if after.deny.get(family) > before.deny.get(family) {
        CanaryVerdict::Denied
    } else {
        CanaryVerdict::EgressObserved
    }
}

/// Whether exempt egress diverged from what the agent accounts for (KS-11).
///
/// > divergence beyond tolerance → `POLICY.EXEMPT.EGRESS_ANOMALY` at `CRITICAL`
///
/// The *tolerance* is the core's, not this adapter's: an adapter that chose one
/// would be making a policy decision CB-2 puts on the other side of the seam.
/// What this returns is the observed difference, per family, and the caller
/// compares it against whatever tolerance the policy carries.
#[must_use]
pub fn exempt_divergence(observed: &CounterSnapshot, accounted: PerFamily<u64>) -> PerFamily<i64> {
    let diff = |family: AddressFamily| {
        let obs = i64::try_from(*observed.exempt.get(family)).unwrap_or(i64::MAX);
        let acc = i64::try_from(*accounted.get(family)).unwrap_or(i64::MAX);
        obs.saturating_sub(acc)
    };
    PerFamily::new(diff(AddressFamily::V4), diff(AddressFamily::V6))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wfp::filters::filter_key;
    use crate::wfp::Layer;

    fn drop_on(class: TrafficClass, family: AddressFamily) -> NetEvent {
        NetEvent {
            kind: NetEventKind::ClassifyDrop,
            family,
            filter: Some(filter_key(class, Layer::for_family(family), 0)),
        }
    }

    fn allow_on(class: TrafficClass, family: AddressFamily) -> NetEvent {
        NetEvent {
            kind: NetEventKind::ClassifyAllow,
            family,
            filter: Some(filter_key(class, Layer::for_family(family), 0)),
        }
    }

    #[test]
    fn a_v6_drop_never_lands_in_the_v4_counter() {
        // The whole reason the counters are per family: a single combined
        // counter lets a v6 leak hide behind v4 drops.
        let snapshot = fold(
            &[
                drop_on(TrafficClass::ProtectedScopeDeny, AddressFamily::V6),
                drop_on(TrafficClass::ProtectedScopeDeny, AddressFamily::V6),
            ],
            false,
        );
        assert_eq!(*snapshot.deny.get(AddressFamily::V6), 2);
        assert_eq!(*snapshot.deny.get(AddressFamily::V4), 0);
    }

    #[test]
    fn dns_containment_has_its_own_number() {
        // ADR-0011's negative canary asks a different question from ADR-0012's.
        let snapshot = fold(
            &[
                drop_on(TrafficClass::DnsContainment, AddressFamily::V4),
                drop_on(TrafficClass::ProtectedScopeDeny, AddressFamily::V4),
            ],
            false,
        );
        assert_eq!(snapshot.dns_deny, 1);
        assert_eq!(*snapshot.deny.get(AddressFamily::V4), 1);
    }

    #[test]
    fn another_products_drop_is_never_charged_to_our_deny_counter() {
        // If it were, the canary would pass on a host where our rules had been
        // removed and somebody else's firewall happened to drop the probe.
        let snapshot = fold(
            &[
                NetEvent {
                    kind: NetEventKind::ClassifyDrop,
                    family: AddressFamily::V4,
                    filter: None,
                },
                NetEvent {
                    kind: NetEventKind::ClassifyDrop,
                    family: AddressFamily::V4,
                    filter: Some(Guid([0xAB; 16])),
                },
            ],
            false,
        );
        assert_eq!(*snapshot.deny.get(AddressFamily::V4), 0);
        assert_eq!(snapshot.unattributed, 2);
    }

    #[test]
    fn the_canary_reports_a_leak_when_the_counter_did_not_move() {
        let before = CounterSnapshot::empty();
        let after = fold(&[], false);
        assert_eq!(
            canary_verdict(&before, &after, AddressFamily::V4),
            CanaryVerdict::EgressObserved
        );
        let after = fold(
            &[drop_on(TrafficClass::ProtectedScopeDeny, AddressFamily::V4)],
            false,
        );
        assert_eq!(
            canary_verdict(&before, &after, AddressFamily::V4),
            CanaryVerdict::Denied
        );
        // ...and the other family is unaffected by the first family's result.
        assert_eq!(
            canary_verdict(&before, &after, AddressFamily::V6),
            CanaryVerdict::EgressObserved
        );
    }

    #[test]
    fn a_lossy_window_is_indeterminate_and_never_denied() {
        // "We do not know" must not be reported as "the rule is live"; that is
        // the failure that lets a real leak through.
        let before = CounterSnapshot::empty();
        let after = fold(
            &[drop_on(TrafficClass::ProtectedScopeDeny, AddressFamily::V4)],
            true,
        );
        assert_eq!(
            canary_verdict(&before, &after, AddressFamily::V4),
            CanaryVerdict::Indeterminate
        );
        // A loss in the BEFORE window is equally disqualifying: the baseline is
        // what the increment is measured from.
        let lossy_before = fold(&[], true);
        assert_eq!(
            canary_verdict(&lossy_before, &fold(&[], false), AddressFamily::V4),
            CanaryVerdict::Indeterminate
        );
    }

    #[test]
    fn only_exempt_egress_classes_count_toward_ks11() {
        let snapshot = fold(
            &[
                allow_on(TrafficClass::BootstrapExemption, AddressFamily::V4),
                allow_on(TrafficClass::UpdateExemption, AddressFamily::V4),
                allow_on(TrafficClass::Loopback, AddressFamily::V4),
                allow_on(TrafficClass::OverlayEgress, AddressFamily::V4),
            ],
            false,
        );
        assert_eq!(
            *snapshot.exempt.get(AddressFamily::V4),
            2,
            "loopback never leaves the host and the overlay is not an exemption"
        );
        assert_eq!(snapshot.unattributed, 0);
    }

    #[test]
    fn the_divergence_is_reported_and_the_tolerance_is_never_this_adapters() {
        // CB-2: an adapter that chose a tolerance would be making a policy
        // decision on the wrong side of the seam.
        let observed = fold(
            &[
                allow_on(TrafficClass::BootstrapExemption, AddressFamily::V4),
                allow_on(TrafficClass::BootstrapExemption, AddressFamily::V4),
                allow_on(TrafficClass::BootstrapExemption, AddressFamily::V6),
            ],
            false,
        );
        let divergence = exempt_divergence(&observed, PerFamily::new(2, 0));
        assert_eq!(*divergence.get(AddressFamily::V4), 0);
        assert_eq!(*divergence.get(AddressFamily::V6), 1);
    }

    #[test]
    fn the_unit_travels_with_the_number() {
        // KS-11 asks for bytes; ALE classification supplies connections. The
        // shortfall is carried so a comparison cannot silently mix the two.
        assert_eq!(CounterSnapshot::empty().unit, CounterUnit::Connections);
        assert_eq!(fold(&[], false).unit, CounterUnit::Connections);
    }
}
