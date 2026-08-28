//! ADR-0005/0006's device-leg rules, asserted.

use core::time::Duration;
use std::sync::Arc;

use twinvpn_env::virtual_time::VirtualTime;
use twinvpn_env::{ConsumerId, Entropy, Env, EnvError, EnvParts, Rng, RngSource, WallClockReading};
use twinvpn_relay_client::bind::{self, BindRequest};
use twinvpn_relay_client::codes::UNREGISTERED;
use twinvpn_relay_client::failover::{
    self, Attribution, FleetExhausted, Observation, OfferOutcome, RegionMoveTiming, ShedResponse,
};
use twinvpn_relay_client::hrw::{self, HrwHash, Weight};
use twinvpn_relay_client::map::{
    self, AdminState, Carriage, DeviceCapability, Excluded, HealthState, Relay, RelayMap,
};
use twinvpn_relay_client::select::{self, Observations, Scored, Selection};
use twinvpn_relay_client::standby::{self, Conditions, Posture, PowerPosture, Role};
use twinvpn_types::{
    AddressFamily, DeviceId, Endpoint, IpAddr, PairTag, PathClass, PerFamily, Port, RegionId,
    RelayId, V4Addr, V6Addr,
};

// -- fixtures ----------------------------------------------------------------

struct CounterRng(u64);
impl Rng for CounterRng {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for b in dst.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}
struct Src;
impl RngSource for Src {
    fn rng_for(&self, c: ConsumerId) -> Result<Box<dyn Rng>, EnvError> {
        let seed = c.as_str().bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x1000_0000_01b3)
        });
        Ok(Box::new(CounterRng(seed)))
    }
    fn is_deterministic(&self) -> bool {
        true
    }
}
struct Ent;
impl Entropy for Ent {
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
        dst.fill(0x5a);
        Ok(())
    }
}

fn env() -> Env {
    let vt = Arc::new(VirtualTime::new(WallClockReading::Unset));
    Env::new(EnvParts {
        monotonic: vt.monotonic(),
        elapsed: vt.elapsed(),
        wall: vt.wall(),
        timer: vt.timer(),
        runtime: vt.runtime(),
        entropy: Arc::new(Ent),
        rng: Arc::new(Src),
    })
}

/// A deterministic stand-in for `twinvpn-crypto`'s BLAKE2s.
struct FakeHash;
impl HrwHash for FakeHash {
    fn weight_digest(&self, relay: RelayId, pair_id: &[u8; 16]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for b in relay.to_array().iter().chain(pair_id.iter()) {
            h = (h ^ u64::from(*b)).wrapping_mul(0x1000_0000_01b3);
        }
        out[..8].copy_from_slice(&h.to_le_bytes());
        out
    }
}

fn relay(id: u8, domain: &str, region: &str) -> Relay {
    Relay {
        id: RelayId::from_array([id; 8]),
        operator_group_id: "grp".into(),
        region: RegionId::new(region).unwrap(),
        endpoints: PerFamily::new(
            vec![Endpoint::new(
                IpAddr::V4(V4Addr::from_octets([203, 0, 113, id])),
                Port::new(443).unwrap(),
            )],
            vec![Endpoint::new(
                IpAddr::V6(
                    V6Addr::new(
                        [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, id],
                        None,
                    )
                    .unwrap(),
                ),
                Port::new(443).unwrap(),
            )],
        ),
        carriages: vec![Carriage::Udp, Carriage::Quic],
        failure_domain: domain.into(),
        server_rank: 50,
        load_class: 0,
        capacity_weight: 100,
        admin_state: AdminState::Active,
        self_hosted: false,
        supports_drain: true,
        supports_caps: true,
    }
}

fn device() -> DeviceCapability {
    DeviceCapability {
        families: PerFamily::new(true, true),
        nat64_available: false,
        carriages: vec![Carriage::Udp],
        token_operator_group_id: "grp".into(),
    }
}

// -- the bind leg ------------------------------------------------------------

#[test]
fn a_bind_request_carries_no_peer_identifier_of_any_kind() {
    // A11 / CF-7: `peer_key_id` was removed so the relay cannot learn which two
    // devices are talking. Destructuring the whole struct is what makes the
    // field set assertable — adding a peer identifier would fail to compile.
    let req = BindRequest {
        pair_tag: PairTag::from_array([7; 16]),
        bucket: 3,
        carriage: Carriage::Udp,
        family: AddressFamily::V4,
    };
    let BindRequest {
        pair_tag,
        bucket,
        carriage,
        family,
    } = req;
    assert_eq!(pair_tag, PairTag::from_array([7; 16]));
    assert_eq!(bucket, 3);
    assert_eq!(carriage, Carriage::Udp);
    assert_eq!(family, AddressFamily::V4);
    // And the relay holds no key that can decrypt the payload (I1).
    assert!(!bind::relay_can_decrypt_payload());
}

#[test]
fn the_pair_tag_bucket_accepts_one_step_of_skew_and_never_underflows() {
    assert!(bind::bucket_accepted(5, 4));
    assert!(bind::bucket_accepted(5, 5));
    assert!(bind::bucket_accepted(5, 6));
    assert!(!bind::bucket_accepted(5, 3));
    assert!(!bind::bucket_accepted(5, 7));
    // At bucket zero a subtraction would underflow to u64::MAX and accept
    // everything; the comparison form does not.
    assert!(bind::bucket_accepted(0, 0));
    assert!(bind::bucket_accepted(0, 1));
    assert!(!bind::bucket_accepted(0, 9));
    assert_eq!(bind::BUCKET_SECONDS, 600);
    assert_eq!(bind::bucket_for(1_200), 2);
}

#[test]
fn the_listening_posture_ceiling_is_the_one_adr_0006_states() {
    assert_eq!(
        bind::listening_peer_ceiling(bind::DEFAULT_MAX_BINDS_PER_MIN),
        15
    );
}

// -- admissibility -----------------------------------------------------------

#[test]
fn only_four_local_or_structural_facts_may_reduce_the_candidate_set() {
    let d = device();
    // Retired.
    let mut r = relay(1, "a", "eu");
    r.admin_state = AdminState::Retired;
    assert_eq!(map::exclusion(&r, &d), Some(Excluded::Retired));
    // Wrong operator group: the device cannot be admitted at all.
    let mut r = relay(1, "a", "eu");
    r.operator_group_id = "other".into();
    assert_eq!(map::exclusion(&r, &d), Some(Excluded::NotInOperatorGroup));
    // No carriage in common.
    let mut r = relay(1, "a", "eu");
    r.carriages = vec![Carriage::Tls];
    assert_eq!(map::exclusion(&r, &d), Some(Excluded::NoCarriageSupported));
    // No endpoint in a family the device can reach.
    let mut r = relay(1, "a", "eu");
    r.endpoints = PerFamily::new(Vec::new(), Vec::new());
    assert_eq!(map::exclusion(&r, &d), Some(Excluded::NoCandidateForFamily));
    // Draining is NOT an exclusion: it is a −300 score penalty.
    let mut r = relay(1, "a", "eu");
    r.admin_state = AdminState::Draining;
    assert_eq!(map::exclusion(&r, &d), None);
}

#[test]
fn a_v6_only_device_can_still_bind_a_v4_relay_over_nat64() {
    let mut d = device();
    d.families = PerFamily::new(false, true);
    let mut r = relay(1, "a", "eu");
    r.endpoints = PerFamily::new(
        vec![Endpoint::new(
            IpAddr::V4(V4Addr::from_octets([203, 0, 113, 1])),
            Port::new(443).unwrap(),
        )],
        Vec::new(),
    );
    assert_eq!(map::exclusion(&r, &d), Some(Excluded::NoCandidateForFamily));
    d.nat64_available = true;
    assert_eq!(map::exclusion(&r, &d), None);
}

#[test]
fn a_stale_map_is_used_never_blocked_on() {
    let m = RelayMap {
        version: 3,
        relays: vec![relay(1, "a", "eu")],
    };
    // There is no freshness gate to fail: admissibility never consults age.
    assert_eq!(map::admissible(&m, &device()).len(), 1);
    // Version is monotone for the peer-carriage path.
    assert!(m.accepts_version(4));
    assert!(!m.accepts_version(3));
    assert!(!m.accepts_version(2));
}

// -- selection ---------------------------------------------------------------

#[test]
fn every_measurement_floor_actually_fires() {
    // D-2's regression test. `-x.max(-250)` parses as `-(x.max(-250))` with
    // `x >= 0`, so the floors were inert and a single observation could drive
    // the score arbitrarily far down. The old suite pinned the CONSTANT and
    // never pinned the BEHAVIOUR.
    let r = relay(1, "a", "eu");
    let clean = select::score(&r, Observations::default());

    for (label, obs, floor) in [
        (
            "rtt",
            Observations {
                ewma_rtt_ms: 5_000,
                ..Observations::default()
            },
            select::RTT_FLOOR,
        ),
        (
            "loss",
            Observations {
                loss_pct: 100,
                ..Observations::default()
            },
            select::LOSS_FLOOR,
        ),
        (
            "jitter",
            Observations {
                ewma_jitter_ms: 2_000,
                ..Observations::default()
            },
            select::JITTER_FLOOR,
        ),
    ] {
        let penalty = select::score(&r, obs) - clean;
        assert_eq!(
            penalty, floor,
            "the {label} term must saturate at its declared floor, not run past it"
        );
    }

    // All three at once still cannot exceed the declared total.
    let everything = select::score(
        &r,
        Observations {
            ewma_rtt_ms: 5_000,
            loss_pct: 100,
            ewma_jitter_ms: 2_000,
            ..Observations::default()
        },
    ) - clean;
    assert_eq!(everything, select::MAX_MEASUREMENT_PENALTY);
}

#[test]
fn a_bad_measurement_can_no_longer_sink_a_relay_below_the_whole_fleet() {
    // The consequence D-2's fix actually removes. With the floors inert a 5 s
    // EWMA RTT cost −5000, which put one relay below every other candidate
    // including a DRAINING one (−300) with an open breaker (−400) — so a single
    // hostile or merely broken observation could reorder the fleet arbitrarily.
    let good = relay(1, "a", "eu");
    let awful = relay(2, "b", "eu");

    let worst_measured = select::score(
        &awful,
        Observations {
            ewma_rtt_ms: 5_000,
            loss_pct: 100,
            ewma_jitter_ms: 2_000,
            ..Observations::default()
        },
    );
    let draining_and_breakered = select::score(
        &{
            let mut r = good.clone();
            r.admin_state = AdminState::Draining;
            r
        },
        Observations {
            breaker_penalty: select::BREAKER_FLOOR,
            ..Observations::default()
        },
    );
    assert!(
        worst_measured > draining_and_breakered,
        "a relay with the worst possible MEASUREMENTS ({worst_measured}) must \
         still outrank a DRAINING one with an open breaker \
         ({draining_and_breakered}): measurement is bounded at {} and those two \
         structural penalties are not",
        select::MAX_MEASUREMENT_PENALTY
    );
}

#[test]
fn health_state_is_bounded_against_measurement_exactly_as_the_table_weights_it() {
    // §11.2 gives HealthState UNHEALTHY a −150 delta and floors measured RTT at
    // −250, so the crossover sits at 150 ms and is deliberate: below it a
    // measured relay wins, above it the report does. This pins the crossover so
    // a future re-weighting has to be a decision rather than a drift.
    let r = relay(3, "c", "eu");
    let unhealthy = select::score(
        &r,
        Observations {
            health: HealthState::Unhealthy,
            ..Observations::default()
        },
    );
    let mildly_slow = select::score(
        &r,
        Observations {
            ewma_rtt_ms: 100,
            health: HealthState::Healthy,
            ..Observations::default()
        },
    );
    assert!(
        mildly_slow > unhealthy,
        "inside the crossover a measured relay wins ({mildly_slow} vs {unhealthy})"
    );

    let very_slow = select::score(
        &r,
        Observations {
            ewma_rtt_ms: 400,
            health: HealthState::Healthy,
            ..Observations::default()
        },
    );
    assert!(
        very_slow < unhealthy,
        "and past it the report wins — §11.2's chosen weighting, not a defect"
    );

    // What S-10 forbids is GATING, and selection has no filter to gate with:
    // the unhealthy relay is still in the total order.
    let order = Selection::order(vec![
        Scored {
            id: r.id,
            score: unhealthy,
            breaker_open: false,
        },
        Scored {
            id: RelayId::from_array([9; 8]),
            score: very_slow,
            breaker_open: false,
        },
    ]);
    assert!(
        order.is_total_over(2),
        "a score delta never removes a candidate"
    );
}

#[test]
fn the_caller_supplied_deltas_are_clamped_to_their_declared_bounds() {
    // The locality term and the breaker penalty arrive from other crates. An
    // out-of-range value from either would break §11.2's composition rule just
    // as thoroughly as an inert floor did, so both are clamped here.
    let r = relay(4, "d", "eu");
    let clean = select::score(&r, Observations::default());

    let wild_locality = select::score(
        &r,
        Observations {
            region_locality_penalty: -100_000,
            ..Observations::default()
        },
    ) - clean;
    assert_eq!(wild_locality, select::LOCALITY_FLOOR);

    let wild_breaker = select::score(
        &r,
        Observations {
            breaker_penalty: -100_000,
            ..Observations::default()
        },
    ) - clean;
    assert_eq!(wild_breaker, select::BREAKER_FLOOR);

    // A positive value in a penalty slot cannot become a bonus either.
    let bogus_bonus = select::score(
        &r,
        Observations {
            breaker_penalty: 5_000,
            ..Observations::default()
        },
    ) - clean;
    assert_eq!(bogus_bonus, 0, "a penalty term must never add points");
}

#[test]
fn a_hundred_millisecond_measured_advantage_outranks_any_server_preference() {
    // §11.2's composition rule: the server contributes at most +100 and the
    // measurement terms up to −410.
    assert_eq!(select::MAX_SERVER_CONTRIBUTION, 100);
    assert_eq!(select::MAX_MEASUREMENT_PENALTY, -410);

    let mut favoured = relay(1, "a", "eu");
    favoured.server_rank = 100; // the operator's strongest possible preference
    let plain = relay(2, "b", "eu");

    let favoured_but_slow = select::score(
        &favoured,
        Observations {
            ewma_rtt_ms: 120,
            ..Observations::default()
        },
    );
    let plain_and_fast = select::score(&plain, Observations::default());
    assert!(
        plain_and_fast > favoured_but_slow,
        "the client's own measurement overrides a stale ranking"
    );
}

#[test]
fn a_stale_server_ranking_decays_to_zero_influence_over_24_hours() {
    let mut r = relay(1, "a", "eu");
    r.server_rank = 100;
    let fresh = select::score(&r, Observations::default());
    let stale = select::score(
        &r,
        Observations {
            map_age_hours: 24,
            ..Observations::default()
        },
    );
    assert_eq!(fresh - stale, 100, "freshness decays linearly to zero");
    // And it never removes the candidate.
    assert!(stale > 0);
}

#[test]
fn health_state_is_a_delta_and_unknown_never_renders_as_healthy() {
    assert_eq!(HealthState::Healthy.delta(), 0);
    assert_eq!(HealthState::Degraded.delta(), -40);
    assert_eq!(HealthState::Unhealthy.delta(), -150);
    assert_eq!(HealthState::Unknown.delta(), 0);
    assert!(HealthState::Healthy.renders_healthy());
    assert!(!HealthState::Unknown.renders_healthy());
    assert!(!HealthState::Degraded.renders_healthy());
}

#[test]
fn selection_returns_the_whole_set_and_never_an_empty_one() {
    let scored = vec![
        Scored {
            id: RelayId::from_array([1; 8]),
            score: 900,
            breaker_open: true,
        },
        Scored {
            id: RelayId::from_array([2; 8]),
            score: 800,
            breaker_open: true,
        },
    ];
    let sel = Selection::order(scored.clone());
    assert!(sel.is_total_over(2), "a total ordering, never a filter");
    assert!(sel.all_breakers_open);
    assert_eq!(
        sel.best().unwrap().id,
        RelayId::from_array([1; 8]),
        "the highest-scoring candidate is returned as the half-open probe"
    );
    // An empty candidate set is never a legal output while the map is non-empty.
    assert!(!sel.order.is_empty());
}

#[test]
fn a_self_hosted_relay_that_cannot_signal_drain_gets_no_bonus_rather_than_a_penalty() {
    let mut good = relay(1, "a", "eu");
    good.self_hosted = true;
    let mut poor = relay(2, "b", "eu");
    poor.self_hosted = true;
    poor.supports_drain = false;
    let hosted = relay(3, "c", "eu");

    let g = select::score(&good, Observations::default());
    let p = select::score(&poor, Observations::default());
    let h = select::score(&hosted, Observations::default());
    assert_eq!(g - h, 120, "+120 for a fully-capable self-hosted relay");
    assert_eq!(p, h, "no bonus, and no penalty either");
}

#[test]
fn a_standby_must_be_in_a_different_failure_domain() {
    let r1 = relay(1, "domain-a", "eu");
    let r2 = relay(2, "domain-a", "eu"); // same domain: not a standby
    let r3 = relay(3, "domain-b", "eu");
    let relays = [&r1, &r2, &r3];
    let sel = Selection::order(vec![
        Scored {
            id: r2.id,
            score: 900,
            breaker_open: false,
        },
        Scored {
            id: r3.id,
            score: 800,
            breaker_open: false,
        },
    ]);
    let chosen = select::standby_for(&sel, &relays, r1.id).expect("a standby exists");
    assert_eq!(
        chosen.id, r3.id,
        "a standby that fails with its primary is not a standby"
    );
}

// -- HRW ---------------------------------------------------------------------

#[test]
fn two_cold_peers_with_the_same_map_converge_with_no_messages() {
    let relays: Vec<Relay> = (1..=6).map(|i| relay(i, "d", "eu")).collect();
    let refs: Vec<&Relay> = relays.iter().collect();
    let pair_id = [0x11u8; 16];

    let ours = hrw::top_k(&FakeHash, &refs, &pair_id, hrw::K);
    let theirs = hrw::top_k(&FakeHash, &refs, &pair_id, hrw::K);
    assert_eq!(ours, theirs, "the same map yields the same list");
    assert_eq!(ours.len(), 3);
    assert!(hrw::converges(&ours, &theirs));

    // A different pair maps somewhere else — the spread HRW exists for.
    let other = hrw::top_k(&FakeHash, &refs, &[0x22u8; 16], hrw::K);
    assert_ne!(ours, other);
}

#[test]
fn a_zero_capacity_relay_takes_no_new_pairs() {
    let mut zero = relay(1, "d", "eu");
    zero.capacity_weight = 0;
    let normal = relay(2, "d", "eu");
    let w0 = hrw::weight(&FakeHash, &zero, &[1u8; 16]);
    let w1 = hrw::weight(&FakeHash, &normal, &[1u8; 16]);
    assert_eq!(w0.weight, 0);
    assert!(w1.weight > 0);
}

#[test]
fn an_unmatched_pair_advances_to_the_next_hrw_band() {
    let relays: Vec<Relay> = (1..=9).map(|i| relay(i, "d", "eu")).collect();
    let refs: Vec<&Relay> = relays.iter().collect();
    let pair_id = [0x33u8; 16];
    let first = hrw::top_k(&FakeHash, &refs, &pair_id, hrw::K);
    let second = hrw::next_band(&FakeHash, &refs, &pair_id, 1);
    assert_eq!(second.len(), 3);
    for w in &second {
        assert!(
            !first.iter().any(|f: &Weight| f.relay == w.relay),
            "ranks 4-6 are disjoint from ranks 1-3"
        );
    }
}

// -- standby posture ---------------------------------------------------------

fn conditions(carrier: PathClass, duration: Duration) -> Conditions {
    Conditions {
        carrier,
        carrier_duration: duration,
        role: Role::Peer,
        power: PowerPosture {
            metered: false,
            battery_pct: Some(90),
            parked: false,
        },
        admissible_relays: 3,
        mains_or_unmetered: true,
    }
}

#[test]
fn a_relayed_session_binds_a_standby_only_after_the_dwell() {
    let brief = conditions(PathClass::Relayed, Duration::from_secs(10));
    assert_eq!(standby::posture(brief), Posture::None);
    let sustained = conditions(PathClass::Relayed, standby::T_STANDBY_WARM);
    assert_eq!(standby::posture(sustained), Posture::Bound);
}

#[test]
fn a_gateway_binds_immediately_with_no_dwell() {
    let mut c = conditions(PathClass::Relayed, Duration::ZERO);
    c.role = Role::AlwaysReachable;
    assert_eq!(standby::posture(c), Posture::Bound);
}

#[test]
fn a_parked_standby_is_released_and_must_not_be_reported_as_warm() {
    let mut c = conditions(PathClass::Relayed, Duration::from_secs(600));
    c.power.parked = true;
    let p = standby::posture(c);
    assert_eq!(p, Posture::Released);
    assert!(!p.is_warm(), "the failover posture is genuinely weaker");
    assert!(!p.failover_target_ready());
}

#[test]
fn a_leg_only_standby_still_satisfies_the_wan_direct_invariant() {
    let c = conditions(PathClass::WanDirect, Duration::from_secs(600));
    let p = standby::posture(c);
    assert_eq!(p, Posture::LegOnly);
    assert!(!p.is_warm(), "leg-only is one BIND RTT away, not bound");
    assert!(
        p.failover_target_ready(),
        "reachable within T_FAILOVER_TARGET is what §4.4 requires"
    );
    assert_eq!(standby::T_FAILOVER_TARGET, Duration::from_millis(300));
}

#[test]
fn a_metered_or_low_battery_device_announces_its_weaker_posture() {
    let mut metered = conditions(PathClass::Relayed, Duration::from_secs(600));
    metered.power.metered = true;
    let p = standby::posture(metered);
    assert_eq!(p, Posture::LegOnly);
    assert_eq!(
        standby::suppression_reason(metered, p),
        Some("RELAY.STANDBY.SUPPRESSED_METERED")
    );

    let mut low = conditions(PathClass::Relayed, Duration::from_secs(600));
    low.power.battery_pct = Some(9);
    assert_eq!(
        standby::suppression_reason(low, standby::posture(low)),
        Some("RELAY.STANDBY.SUPPRESSED_POWER")
    );

    let mut alone = conditions(PathClass::Relayed, Duration::from_secs(600));
    alone.admissible_relays = 1;
    assert_eq!(
        standby::suppression_reason(alone, standby::posture(alone)),
        Some("RELAY.STANDBY_UNAVAILABLE")
    );
}

// -- attribution and failover ------------------------------------------------

fn healthy_observation() -> Observation {
    Observation {
        missed_leg_pings: 0,
        leg_hard_signal: false,
        drain_deadline_reached: false,
        half_flow_silent: false,
        quality_violated: false,
        all_legs_on_interface_dead: false,
        capacity_rejected: false,
        region_failed: false,
    }
}

#[test]
fn a_silent_half_flow_on_a_live_leg_is_peer_loss_and_never_a_failover() {
    let o = Observation {
        half_flow_silent: true,
        ..healthy_observation()
    };
    let a = failover::attribute(o);
    assert_eq!(a, Attribution::PeerLoss);
    assert!(!a.triggers_failover(), "moving a working relay cannot help");
}

#[test]
fn three_missed_leg_pings_are_a_relay_failure() {
    let o = Observation {
        missed_leg_pings: 3,
        ..healthy_observation()
    };
    assert_eq!(failover::attribute(o), Attribution::RelayFailure);
    // Two are not.
    let o = Observation {
        missed_leg_pings: 2,
        ..healthy_observation()
    };
    assert_eq!(failover::attribute(o), Attribution::Healthy);
}

#[test]
fn a_dead_interface_is_not_a_relay_event() {
    let o = Observation {
        all_legs_on_interface_dead: true,
        missed_leg_pings: 5,
        ..healthy_observation()
    };
    assert_eq!(failover::attribute(o), Attribution::LocalLinkFailure);
}

#[test]
fn capacity_is_honoured_rather_than_treated_as_a_fault() {
    let o = Observation {
        capacity_rejected: true,
        ..healthy_observation()
    };
    assert_eq!(failover::attribute(o), Attribution::Capacity);
    let verified = [RelayId::from_array([2; 8])];
    let shed = ShedResponse {
        retry_after: Duration::from_secs(5),
        suggested: vec![RelayId::from_array([2; 8]), RelayId::from_array([9; 8])],
    };
    assert_eq!(
        shed.admissible_suggestions(&verified),
        vec![RelayId::from_array([2; 8])],
        "a suggestion absent from the verified map is ignored"
    );
    assert!(shed.must_try_alternative_first(&verified));
}

#[test]
fn simultaneous_offers_resolve_on_the_lower_device_id_at_an_equal_epoch() {
    let low = DeviceId::from_array([1; 32]);
    let high = DeviceId::from_array([2; 32]);
    assert_eq!(
        failover::resolve_offers(5, low, 5, high),
        OfferOutcome::Ours
    );
    assert_eq!(
        failover::resolve_offers(5, high, 5, low),
        OfferOutcome::Theirs
    );
    // A higher epoch wins outright, whatever the device ids.
    assert_eq!(
        failover::resolve_offers(6, high, 5, low),
        OfferOutcome::Ours
    );
}

#[test]
fn a_cold_relay_is_not_make_before_break_and_says_so() {
    assert!(failover::failover_is_make_before_break(true));
    assert!(
        !failover::failover_is_make_before_break(false),
        "reporting MIGRATING would assert a make-before-break that is not happening"
    );
}

#[test]
fn the_drain_offset_leaves_a_sixty_second_reserve() {
    let e = env();
    let deadline = Duration::from_secs(600);
    for _ in 0..8 {
        let off = failover::drain_offset(&e, deadline).unwrap();
        assert!(
            off <= deadline - failover::DRAIN_RESERVE,
            "a device whose migration fails still needs a full T_MIGRATE budget"
        );
    }
    // A deadline already inside the reserve means move now.
    assert_eq!(
        failover::drain_offset(&e, Duration::from_secs(30)).unwrap(),
        Duration::ZERO
    );
}

#[test]
fn a_bound_standby_moves_immediately_and_everyone_else_is_spread() {
    let e = env();
    assert_eq!(
        failover::region_move_timing(&e, true).unwrap(),
        RegionMoveTiming::Immediate,
        "their capacity was accounted at bind time"
    );
    match failover::region_move_timing(&e, false).unwrap() {
        RegionMoveTiming::Deferred(d) => {
            assert!(d <= failover::T_REGION_SPREAD);
        }
        RegionMoveTiming::Immediate => panic!("a device acquiring capacity must be spread"),
    }
}

#[test]
fn total_fleet_unavailability_is_never_degraded() {
    assert_eq!(
        failover::fleet_exhausted(true, true),
        FleetExhausted::NoStateChange
    );
    assert_eq!(
        failover::fleet_exhausted(false, true),
        FleetExhausted::Blocked,
        "BLOCKED retries forever at the floor rate, because the fleet will return"
    );
    assert_eq!(
        failover::fleet_exhausted(false, false),
        FleetExhausted::ReconnectingThenFailed
    );
    // There is deliberately no DEGRADED variant: here nothing flows.
}

// -- the contract defect -----------------------------------------------------

#[test]
fn every_unregistered_relay_code_is_still_absent_from_the_frozen_registry() {
    for s in UNREGISTERED {
        assert!(
            twinvpn_types::ReasonCode::lookup(s.specified).is_none(),
            "{} is now registered — remove its substitution ({})",
            s.specified,
            s.cited_by
        );
    }
    assert_eq!(UNREGISTERED.len(), 18);
}
