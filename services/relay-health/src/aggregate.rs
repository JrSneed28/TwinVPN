//! Aggregating relay self-reports into a `RelayHealth` (S-10).
//!
//! The four states are `TWINVPN_RELAYHEALTH_STATES`' and testing-strategy A-03's:
//! `HEALTHY,DEGRADED,UNHEALTHY,UNKNOWN`. Their score deltas are ADR-0006 §11.2's:
//! `HEALTHY 0 · DEGRADED −40 · UNHEALTHY −150 · UNKNOWN 0`.
//!
//! # `UNKNOWN` costs exactly zero, and that is the availability property
//!
//! A relay this service has never heard from, or has not heard from recently,
//! is `UNKNOWN` — and `UNKNOWN` contributes **0**, identically to `HEALTHY`. So a
//! relay-health outage does not push any relay down the ranking; it removes a
//! *negative* signal from relays that deserve one. The fleet ranks by measurement
//! alone, which is what S-31 says should dominate anyway.
//!
//! Making the outage state cost −40 or −150 would be worse than useless: it would
//! turn one service's failure into a fleet-wide ranking distortion, which is the
//! shape of failure ADR-0006 §11.3 rule 1 exists to forbid.
//!
//! # Probing the admin listener, not the data port
//!
//! `infra/README.md` §4.8: "Targets are the relays' **admin** listeners, not their
//! data ports: a prober that opened a relay flow would be indistinguishable from a
//! peer and would consume the fleet's own quota." A [`SelfReport`] is therefore
//! what a relay says about itself on `:9090`, not what a prober inferred by
//! binding a flow.

use std::collections::BTreeMap;

/// A relay's own report about itself, from its admin listener.
///
/// **No per-session or peer-pair label**, per ADR-0015 O-13 and `relay.proto`.
/// There is no `session_id` field, no `pair_tag`, no peer address and no device
/// identifier — and no constructor that takes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfReport {
    /// 8 bytes (`limits.json identifiers.relay_id_bytes`).
    pub relay_id: [u8; twinvpn_schema::limits::RELAY_ID_BYTES],
    /// 0–3, coarse. Values above 3 are clamped rather than rejected: a relay
    /// reporting nonsense about its own load should not vanish from the fleet.
    pub load_class: u8,
    /// Whether the relay answered its admin probe at all.
    pub reachable: bool,
    /// Round-trip to the admin listener, milliseconds. `None` when unreachable.
    pub probe_rtt_ms: Option<u32>,
    /// When this observation was taken, in milliseconds.
    pub observed_at_ms: u64,
}

/// `relay.proto HealthState`, with its ADR-0006 §11.2 score delta.
///
/// **W-20's disposition, executed (R-14).** This module used to hand-write a
/// FOUR-variant copy of the frozen five-variant enum, re-encoding §11.2's
/// deltas as literals. The omitted variant was `HEALTH_STATE_UNSPECIFIED`, the
/// proto3 zero an unset field decodes to — the one value a service reading
/// another party's report is most likely to meet, and the one a four-variant
/// model has to invent an answer for.
///
/// This is a re-export of `twinvpn-types`' canonical enum. `score_delta` and
/// `as_str` come from there, so the numbers this service ranks by and the ones
/// the client ranks by are the same definition rather than two that agree
/// today.
pub use twinvpn_types::state::HealthState;

/// How a report becomes a state.
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    /// `TWINVPN_RELAYHEALTH_DEGRADED_RTT_MS`, 250 — `docs/reliability.md` §5.4's
    /// relay threshold.
    pub degraded_rtt_ms: u32,
    /// How long an observation stays meaningful. Past it, `UNKNOWN` (delta 0),
    /// never `UNHEALTHY`: "we have not looked recently" and "it is broken" are
    /// different facts, and conflating them turns a prober outage into a
    /// fleet-wide penalty.
    pub staleness_ms: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            degraded_rtt_ms: 250,
            staleness_ms: 60_000,
        }
    }
}

/// The `EVENTUAL`, non-durable, recomputed aggregate.
///
/// Freshest observation wins (`relay.proto`), so a report is replaced rather than
/// merged, and an older report never overwrites a newer one.
#[derive(Debug, Default)]
pub struct Aggregate {
    thresholds: Thresholds,
    latest: BTreeMap<[u8; twinvpn_schema::limits::RELAY_ID_BYTES], SelfReport>,
}

impl Aggregate {
    /// An empty aggregate.
    #[must_use]
    pub fn new(thresholds: Thresholds) -> Self {
        Self {
            thresholds,
            latest: BTreeMap::new(),
        }
    }

    /// Records a report. **Freshest wins**; an out-of-order older report is dropped.
    pub fn observe(&mut self, report: SelfReport) {
        match self.latest.get(&report.relay_id) {
            Some(existing) if existing.observed_at_ms > report.observed_at_ms => {}
            _ => {
                self.latest.insert(report.relay_id, report);
            }
        }
    }

    /// How many relays have been observed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.latest.len()
    }

    /// Whether nothing has been observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.latest.is_empty()
    }

    /// The state for a relay, as of `now_ms`.
    ///
    /// A relay with no report, or only a stale one, is `Unknown` — **not**
    /// `Unhealthy`. That distinction is the whole of "a health service outage
    /// degrades ranking quality and nothing else".
    #[must_use]
    pub fn state_for(
        &self,
        relay_id: &[u8; twinvpn_schema::limits::RELAY_ID_BYTES],
        now_ms: u64,
    ) -> HealthState {
        let Some(r) = self.latest.get(relay_id) else {
            return HealthState::Unknown;
        };
        if now_ms.saturating_sub(r.observed_at_ms) > self.thresholds.staleness_ms {
            return HealthState::Unknown;
        }
        if !r.reachable {
            return HealthState::Unhealthy;
        }
        let slow = r
            .probe_rtt_ms
            .is_some_and(|rtt| rtt > self.thresholds.degraded_rtt_ms);
        if slow || r.load_class >= 2 {
            return HealthState::Degraded;
        }
        HealthState::Healthy
    }

    /// The coarse load class a relay reported, clamped to 0–3.
    #[must_use]
    pub fn load_class_for(
        &self,
        relay_id: &[u8; twinvpn_schema::limits::RELAY_ID_BYTES],
    ) -> Option<u8> {
        self.latest.get(relay_id).map(|r| r.load_class.min(3))
    }

    /// Drops observations older than the staleness window.
    ///
    /// The aggregate is **recomputed**, not accumulated: an unbounded map keyed by
    /// relay ids the service has ever seen is a slow leak on a long-lived process.
    pub fn collect(&mut self, now_ms: u64) -> usize {
        let staleness = self.thresholds.staleness_ms;
        let before = self.latest.len();
        self.latest
            .retain(|_, r| now_ms.saturating_sub(r.observed_at_ms) <= staleness.saturating_mul(10));
        before - self.latest.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> [u8; twinvpn_schema::limits::RELAY_ID_BYTES] {
        [n; twinvpn_schema::limits::RELAY_ID_BYTES]
    }

    fn report(n: u8, reachable: bool, rtt: Option<u32>, at: u64) -> SelfReport {
        SelfReport {
            relay_id: id(n),
            load_class: 0,
            reachable,
            probe_rtt_ms: rtt,
            observed_at_ms: at,
        }
    }

    #[test]
    fn the_four_states_carry_adr_0006s_deltas() {
        assert_eq!(HealthState::Healthy.score_delta(), 0);
        assert_eq!(HealthState::Degraded.score_delta(), -40);
        assert_eq!(HealthState::Unhealthy.score_delta(), -150);
        assert_eq!(HealthState::Unknown.score_delta(), 0);
    }

    #[test]
    fn a_health_service_outage_costs_nothing() {
        // THE property. An aggregate with no data at all reports UNKNOWN for
        // every relay, and UNKNOWN contributes exactly the same delta as HEALTHY.
        // So the fleet ranks by measurement alone, which is what S-31 wants.
        let a = Aggregate::new(Thresholds::default());
        assert!(a.is_empty());
        for n in 0..10_u8 {
            assert_eq!(a.state_for(&id(n), 1_000_000), HealthState::Unknown);
            assert_eq!(a.state_for(&id(n), 1_000_000).score_delta(), 0);
        }
        assert_eq!(
            HealthState::Unknown.score_delta(),
            HealthState::Healthy.score_delta(),
            "an outage must degrade ranking QUALITY and nothing else"
        );
    }

    #[test]
    fn a_stale_observation_is_unknown_and_never_unhealthy() {
        // "We have not looked recently" and "it is broken" are different facts.
        // Conflating them turns a prober outage into a fleet-wide penalty.
        let mut a = Aggregate::new(Thresholds::default());
        a.observe(report(1, true, Some(10), 0));
        assert_eq!(a.state_for(&id(1), 60_000), HealthState::Healthy);
        assert_eq!(a.state_for(&id(1), 60_001), HealthState::Unknown);
        assert_eq!(a.state_for(&id(1), 10_000_000).score_delta(), 0);
    }

    #[test]
    fn an_unreachable_relay_is_unhealthy_but_still_a_candidate() {
        // ADR-0006 §11.3 rule 1: UNHEALTHY contributes a delta; it does not
        // suppress an attempt. The only thing a HealthState can produce is a
        // number.
        let mut a = Aggregate::new(Thresholds::default());
        a.observe(report(1, false, None, 0));
        let s = a.state_for(&id(1), 1_000);
        assert_eq!(s, HealthState::Unhealthy);
        assert_eq!(s.score_delta(), -150);
    }

    #[test]
    fn a_slow_relay_is_degraded_at_the_reliability_threshold() {
        let mut a = Aggregate::new(Thresholds::default());
        a.observe(report(1, true, Some(250), 0));
        assert_eq!(a.state_for(&id(1), 0), HealthState::Healthy);
        a.observe(report(1, true, Some(251), 1));
        assert_eq!(a.state_for(&id(1), 1), HealthState::Degraded);
    }

    #[test]
    fn a_heavily_loaded_relay_is_degraded() {
        let mut a = Aggregate::new(Thresholds::default());
        let mut r = report(1, true, Some(5), 0);
        r.load_class = 2;
        a.observe(r);
        assert_eq!(a.state_for(&id(1), 0), HealthState::Degraded);
    }

    #[test]
    fn the_freshest_observation_wins_and_an_older_one_does_not_overwrite_it() {
        let mut a = Aggregate::new(Thresholds::default());
        a.observe(report(1, true, Some(10), 1_000));
        a.observe(report(1, false, None, 500)); // arrives late, older
        assert_eq!(
            a.state_for(&id(1), 1_000),
            HealthState::Healthy,
            "relay.proto: freshest observation wins"
        );
        a.observe(report(1, false, None, 1_500));
        assert_eq!(a.state_for(&id(1), 1_500), HealthState::Unhealthy);
    }

    #[test]
    fn the_aggregate_is_recomputed_rather_than_accumulated() {
        let mut a = Aggregate::new(Thresholds::default());
        for n in 0..50_u8 {
            a.observe(report(n, true, Some(1), 0));
        }
        assert_eq!(a.len(), 50);
        assert_eq!(a.collect(600_001), 50);
        assert!(a.is_empty());
    }

    #[test]
    fn a_nonsense_load_class_is_clamped_rather_than_rejected() {
        // A relay reporting nonsense about its own load should not vanish from
        // the fleet's ranking inputs.
        let mut a = Aggregate::new(Thresholds::default());
        let mut r = report(1, true, Some(1), 0);
        r.load_class = 200;
        a.observe(r);
        assert_eq!(a.load_class_for(&id(1)), Some(3));
        assert_eq!(a.state_for(&id(1), 0), HealthState::Degraded);
    }
}
