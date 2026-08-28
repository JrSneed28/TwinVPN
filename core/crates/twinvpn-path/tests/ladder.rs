//! ADR-0004's ladder and `docs/reliability.md` §7's rules, asserted — including
//! the four mutants ADR-0004 §11.6(d) guarantees are catchable.

use core::time::Duration;

use twinvpn_env::MonotonicInstant;
use twinvpn_path::candidate::{self, C4Caps, Candidate, GatherPlan, Kind};
use twinvpn_path::codes::UNREGISTERED;
use twinvpn_path::ledger::{Ledger, Standing};
use twinvpn_path::nat::{
    self, Filtering, Mapping, NatClass, PortMapProtocol, PortPrediction, Traversability, MAX_K,
};
use twinvpn_path::race::{self, Race, T_HE_BIAS};
use twinvpn_path::score::{self, AntiFlap, Inputs};
use twinvpn_path::validate::{Hysteresis, Migration, Validation};
use twinvpn_schema::v1;
use twinvpn_types::{
    AddressFamily, CandidateId, Endpoint, IpAddr, Nat64Prefix, Port, TrafficDisposition, V4Addr,
    V6Addr, ZoneIndex,
};

fn ep_v4(o: [u8; 4], p: u16) -> Endpoint {
    Endpoint::new(IpAddr::V4(V4Addr::from_octets(o)), Port::new(p).unwrap())
}

fn ep_v6(last: u8, p: u16) -> Endpoint {
    let mut o = [0u8; 16];
    o[0] = 0x20;
    o[1] = 0x01;
    o[15] = last;
    Endpoint::new(
        IpAddr::V6(V6Addr::new(o, None).unwrap()),
        Port::new(p).unwrap(),
    )
}

fn cand(id: u8, kind: Kind, endpoint: Endpoint, at: MonotonicInstant) -> Candidate {
    Candidate {
        id: CandidateId::from_array([id; 8]),
        kind,
        endpoint,
        gathered_at: at,
        mtu_hint: 1400,
    }
}

// ---------------------------------------------------------------------------
// The ladder's ordering
// ---------------------------------------------------------------------------

#[test]
fn native_ipv6_outranks_everything_and_the_relay_is_the_floor() {
    // ADR-0004 §11's order: native IPv6, LAN, IPv4 reflexive, port mapping,
    // prediction, relay.
    let order = [
        Kind::HostV6Global,
        Kind::HostV6LinkLocal,
        Kind::HostV4Private,
        Kind::SrflxV6,
        Kind::SrflxV4,
        Kind::PortmapV4,
        Kind::PredictedV4,
        Kind::Relay,
    ];
    for w in order.windows(2) {
        assert!(
            w[0].priority() > w[1].priority(),
            "{:?} must outrank {:?}",
            w[0],
            w[1]
        );
    }
    // networking.md §3.3's exact priorities.
    assert_eq!(Kind::HostV6Global.priority(), 130);
    assert_eq!(Kind::HostV6LinkLocal.priority(), 126);
    assert_eq!(Kind::HostV4Private.priority(), 120);
    assert_eq!(Kind::SrflxV6.priority(), 110);
    assert_eq!(Kind::SrflxV4.priority(), 100);
    assert_eq!(Kind::PortmapV4.priority(), 95);
    assert_eq!(Kind::PredictedV4.priority(), 40);
    assert_eq!(Kind::Relay.priority(), 10);
}

#[test]
fn a_link_local_candidate_without_a_zone_index_is_malformed() {
    let now = MonotonicInstant::ORIGIN;
    let mut o = [0u8; 16];
    o[0] = 0xfe;
    o[1] = 0x80;
    o[15] = 1;
    // With a zone index: well formed.
    let with_zone = Endpoint::new(
        IpAddr::V6(V6Addr::new(o, ZoneIndex::new(3)).unwrap()),
        Port::new(51820).unwrap(),
    );
    assert!(cand(1, Kind::HostV6LinkLocal, with_zone, now).is_well_formed());
    // Without: `twinvpn-types` refuses to build the address at all, which is a
    // stronger guarantee than a per-candidate check — protocol.md §10.4's rule
    // is enforced one level below this crate.
    assert!(
        V6Addr::new(o, None).is_err(),
        "an IPv6 link-local address without a zone index is unrepresentable"
    );
    // And an endpoint whose family disagrees with the kind is still refused
    // here, because the two must agree.
    let wrong_family = ep_v4([10, 0, 0, 1], 51820);
    assert!(!cand(2, Kind::HostV6LinkLocal, wrong_family, now).is_well_formed());
}

#[test]
fn gathering_starts_both_families_and_the_relay_at_the_same_instant() {
    let now = MonotonicInstant::ORIGIN;
    let plan = GatherPlan::new(now);
    assert!(plan.both_families_gathered());
    assert_eq!(plan.relay_gathered_at, plan.started_at);
    assert!(plan.relay_gathered_before(now.saturating_add(Duration::from_millis(1))));
}

#[test]
fn a_single_family_candidate_set_is_flagged_not_accepted_quietly() {
    let now = MonotonicInstant::ORIGIN;
    let only_v4 = [cand(
        1,
        Kind::HostV4Private,
        ep_v4([10, 0, 0, 1], 51820),
        now,
    )];
    assert_eq!(
        candidate::single_family(&only_v4),
        Some(AddressFamily::V4),
        "the leading cause of 'works at home, fails on cellular'"
    );
    let both = [
        cand(1, Kind::HostV4Private, ep_v4([10, 0, 0, 1], 51820), now),
        cand(2, Kind::HostV6Global, ep_v6(1, 51820), now),
    ];
    assert_eq!(candidate::single_family(&both), None);
}

#[test]
fn nat64_synthesis_is_ours_and_never_dns64s() {
    let pref = Nat64Prefix::well_known();
    let synth = candidate::synthesize_nat64(pref, V4Addr::from_octets([192, 0, 2, 1]));
    assert_eq!(
        pref.extract(synth),
        Some(V4Addr::from_octets([192, 0, 2, 1]))
    );
}

// ---------------------------------------------------------------------------
// C4 — the B3 parser surface
// ---------------------------------------------------------------------------

#[test]
fn the_c4_caps_are_the_frozen_ones() {
    assert_eq!(C4Caps::MAX_BYTES, 1200);
    assert_eq!(C4Caps::MAX_DEPTH, 4);
    assert_eq!(C4Caps::MAX_CANDIDATES, 32);
    assert_eq!(C4Caps::MAX_PORT_HINTS, 64);
}

#[test]
fn an_oversized_candidate_set_is_rejected_before_a_single_endpoint_is_validated() {
    let mut set = v1::CandidateSet {
        session_nonce: vec![0u8; 16],
        generation: 1,
        candidates: Vec::new(),
    };
    // 33 candidates, each with a deliberately malformed endpoint. If the count
    // cap were checked second, the endpoint error would surface instead.
    for _ in 0..33 {
        set.candidates.push(v1::ConnectionCandidate {
            candidate_id: vec![0u8; 3], // wrong width
            family: 99,                 // invalid
            kind: 0,
            endpoint: None,
            priority: 0,
            mtu_hint: 0,
            expires_at_ms: 0,
        });
    }
    let err = candidate::validate_set(&set).unwrap_err();
    // The COUNT cap fires, not the identifier or family error, which proves the
    // ordering: "a set claiming ten thousand candidates is rejected before ten
    // thousand endpoints are validated".
    match err {
        twinvpn_schema::Reject::CapViolated {
            cap_violated,
            observed,
            limit,
        } => {
            assert_eq!(cap_violated, "candidates.max_candidates_per_set");
            assert_eq!(observed, 33);
            assert_eq!(limit as usize, C4Caps::MAX_CANDIDATES);
        }
        other => panic!("expected the count cap first, got {other:?}"),
    }
}

#[test]
fn a_punch_sync_index_outside_the_signed_set_is_rejected_never_skipped() {
    let sync = v1::PunchSync {
        session_nonce: vec![0u8; 16],
        generation: 1,
        punch_at_ms_relative: 50,
        pairs: vec![
            v1::CandidatePair {
                local_candidate_index: 0,
                remote_candidate_index: 0,
            },
            v1::CandidatePair {
                local_candidate_index: 0,
                remote_candidate_index: 7, // outside a 2-member set
            },
        ],
        birthday_port_hints: Vec::new(),
    };
    assert!(
        race::pairs_from_sync(&sync, 2, 2).is_err(),
        "skipping would let a peer silently change which pair is raced"
    );
    // With every index in range, both pairs survive.
    let ok = v1::PunchSync {
        pairs: vec![v1::CandidatePair {
            local_candidate_index: 1,
            remote_candidate_index: 1,
        }],
        ..sync
    };
    assert_eq!(race::pairs_from_sync(&ok, 2, 2).unwrap().len(), 1);
}

#[test]
fn more_than_sixty_four_port_hints_is_a_cap_violation() {
    let sync = v1::PunchSync {
        session_nonce: vec![0u8; 16],
        generation: 1,
        punch_at_ms_relative: 0,
        pairs: Vec::new(),
        birthday_port_hints: (1..=65u32).collect(),
    };
    assert!(race::pairs_from_sync(&sync, 0, 0).is_err());
}

// ---------------------------------------------------------------------------
// Racing
// ---------------------------------------------------------------------------

#[test]
fn every_pair_is_scheduled_at_once_staggered_only_by_the_250ms_family_bias() {
    let now = MonotonicInstant::ORIGIN;
    let cands = [
        cand(1, Kind::HostV6Global, ep_v6(1, 51820), now),
        cand(2, Kind::HostV4Private, ep_v4([10, 0, 0, 1], 51820), now),
        cand(3, Kind::Relay, ep_v4([203, 0, 113, 5], 443), now),
    ];
    let race = Race::schedule(&cands, now);
    assert!(race.covers_both_families());
    // v6 goes immediately.
    let due_now = race.due(now);
    assert_eq!(due_now.len(), 1);
    assert_eq!(due_now[0].kind, Kind::HostV6Global);
    // v4 follows after the settled 250 ms bias — a stagger, not a filter.
    assert_eq!(T_HE_BIAS, Duration::from_millis(250));
    let after_bias = now.saturating_add(T_HE_BIAS);
    assert_eq!(race.due(after_bias).len(), 3);
}

#[test]
fn declaring_a_winner_cancels_every_loser_and_they_stay_in_the_ledger() {
    let now = MonotonicInstant::ORIGIN;
    let cands = [
        cand(1, Kind::HostV6Global, ep_v6(1, 51820), now),
        cand(2, Kind::HostV4Private, ep_v4([10, 0, 0, 1], 51820), now),
    ];
    let mut race = Race::schedule(&cands, now);
    let mut ledger = Ledger::new();
    for c in cands {
        ledger.record(c);
    }
    let cancelled = race.declare_winner(cands[0].id);
    assert_eq!(cancelled.len(), 1);
    assert_eq!(race.winner().unwrap().id, cands[0].id);
    for c in cancelled {
        assert!(ledger.set_standing(c.id, Standing::CancelledLoser));
    }
    // The ledger keeps winners AND losers.
    assert_eq!(ledger.rows().len(), 2);
}

#[test]
fn the_punch_instant_is_relative_to_receipt_on_the_monotonic_clock() {
    let received = MonotonicInstant::ORIGIN.saturating_add(Duration::from_secs(5));
    let sync = v1::PunchSync {
        session_nonce: vec![0u8; 16],
        generation: 1,
        punch_at_ms_relative: 120,
        pairs: Vec::new(),
        birthday_port_hints: Vec::new(),
    };
    assert_eq!(
        race::punch_at(received, &sync),
        received.saturating_add(Duration::from_millis(120))
    );
}

// ---------------------------------------------------------------------------
// The ledger, and §11.6(d)'s mutants
// ---------------------------------------------------------------------------

#[test]
fn mutant_relay_gathered_after_direct_timeout_is_caught_structurally() {
    let t0 = MonotonicInstant::ORIGIN;
    let late = t0.saturating_add(Duration::from_secs(10));

    // The conforming build: relay at t=0.
    let mut good = Ledger::new();
    good.record(cand(1, Kind::Relay, ep_v4([203, 0, 113, 5], 443), t0));
    good.record_first_direct_probe(t0.saturating_add(Duration::from_millis(1)));
    assert_eq!(good.relay_gathered_from_t_zero(), Some(true));

    // The mutant: relay gathered only after the direct-path timeout.
    let mut bad = Ledger::new();
    bad.record_first_direct_probe(t0);
    bad.record(cand(1, Kind::Relay, ep_v4([203, 0, 113, 5], 443), late));
    assert_eq!(bad.relay_gathered_from_t_zero(), Some(false));
}

#[test]
fn mutant_serialized_racing_shows_up_as_non_overlapping_gather_windows() {
    let t0 = MonotonicInstant::ORIGIN;
    let later = t0.saturating_add(Duration::from_secs(2));

    let mut parallel = Ledger::new();
    parallel.record(cand(1, Kind::HostV6Global, ep_v6(1, 51820), t0));
    parallel.record(cand(
        2,
        Kind::HostV4Private,
        ep_v4([10, 0, 0, 1], 51820),
        t0,
    ));
    assert!(parallel.gathering_was_parallel());

    let mut serial = Ledger::new();
    serial.record(cand(1, Kind::HostV6Global, ep_v6(1, 51820), t0));
    serial.record(cand(
        2,
        Kind::HostV4Private,
        ep_v4([10, 0, 0, 1], 51820),
        later,
    ));
    assert!(!serial.gathering_was_parallel());
}

#[test]
fn the_report_is_producible_with_no_network_and_names_both_families() {
    let t0 = MonotonicInstant::ORIGIN;
    let mut l = Ledger::new();
    l.record(cand(1, Kind::HostV6Global, ep_v6(1, 51820), t0));
    l.record(cand(
        2,
        Kind::HostV4Private,
        ep_v4([10, 0, 0, 1], 51820),
        t0,
    ));
    l.record(cand(3, Kind::Relay, ep_v4([203, 0, 113, 5], 443), t0));
    l.set_standing(CandidateId::from_array([1; 8]), Standing::Carrying);
    l.set_standing(
        CandidateId::from_array([2; 8]),
        Standing::Failed(twinvpn_types::codes::NAT_PUNCH_TIMEOUT),
    );
    // No arguments, no I/O, cannot fail.
    let r = l.report();
    assert_eq!(r.total, 3);
    assert_eq!(*r.per_family.get(AddressFamily::V6), 1);
    assert_eq!(*r.per_family.get(AddressFamily::V4), 2);
    assert_eq!(r.validated, 1);
    assert_eq!(r.failed, 1);
}

#[test]
fn an_unvalidated_candidate_may_never_carry_traffic() {
    for s in [
        Standing::Gathered,
        Standing::Probing,
        Standing::Failed(twinvpn_types::codes::NAT_PUNCH_TIMEOUT),
        Standing::CancelledLoser,
    ] {
        assert!(!s.may_carry_traffic(), "{s:?}");
    }
    for s in [Standing::Validated, Standing::Carrying, Standing::Warm] {
        assert!(s.may_carry_traffic(), "{s:?}");
    }
}

#[test]
fn a_cooled_down_candidate_is_kept_with_its_reason_and_becomes_eligible_again() {
    let now = MonotonicInstant::ORIGIN;
    let until = now.saturating_add(Duration::from_secs(60));
    let s = Standing::CoolingDown {
        until,
        reason: twinvpn_types::codes::NET_PATH_MIGRATION_ABORTED,
    };
    assert!(!s.is_eligible(now));
    assert!(s.is_eligible(until));
}

// ---------------------------------------------------------------------------
// Validation and migration
// ---------------------------------------------------------------------------

#[test]
fn validation_needs_two_authenticated_exchanges_inside_500ms() {
    let t0 = MonotonicInstant::ORIGIN;
    let mut v = Validation::new();
    v.observe_authenticated_exchange(t0);
    assert!(!v.is_validated(), "one exchange is not evidence");
    v.observe_authenticated_exchange(t0.saturating_add(Duration::from_millis(400)));
    assert!(v.is_validated());

    // Two exchanges too far apart do not validate.
    let mut w = Validation::new();
    w.observe_authenticated_exchange(t0);
    w.observe_authenticated_exchange(t0.saturating_add(Duration::from_secs(3)));
    assert!(!w.is_validated());
}

#[test]
fn make_before_break_refuses_to_commit_early_or_release_early() {
    let unvalidated = Migration {
        new_validated: false,
        old_alive: true,
    };
    assert!(!unvalidated.may_commit());
    assert!(!unvalidated.may_release_old());
    assert_eq!(unvalidated.disposition(), TrafficDisposition::TunneledDual);

    let committed = Migration {
        new_validated: true,
        old_alive: true,
    };
    assert!(committed.may_commit() && committed.may_release_old());

    // The old path is already gone: a bounded queue, not dual delivery.
    let broken = Migration {
        new_validated: false,
        old_alive: false,
    };
    assert_eq!(broken.disposition(), TrafficDisposition::QueuedBounded);
    assert!(broken.may_release_old(), "there is nothing left to hold");
}

#[test]
fn the_hysteresis_rule_needs_all_four_conditions_and_names_the_one_that_failed() {
    let all = Hysteresis {
        validated: true,
        better: true,
        stable: true,
        policy_permits: true,
    };
    assert!(all.may_take_over());
    assert_eq!(all.blocked_by(), None);

    // Associated-but-not-usable Wi-Fi: conditions 1 and 3 refuse it.
    let portal_wifi = Hysteresis {
        validated: false,
        ..all
    };
    assert!(!portal_wifi.may_take_over());
    assert_eq!(portal_wifi.blocked_by(), Some("PATH_VALIDATED"));

    // A metered link needing consent is an ANNOUNCED pause, never a silent
    // refusal — which is why the blocker is nameable.
    let metered = Hysteresis {
        policy_permits: false,
        ..all
    };
    assert_eq!(metered.blocked_by(), Some("policy"));
}

// ---------------------------------------------------------------------------
// Scoring, and the anti-flap exception
// ---------------------------------------------------------------------------

#[test]
fn ipv6_wins_a_tie_and_the_breaker_is_a_penalty_never_a_filter() {
    let inputs = Inputs::default();
    let v6 = score::score(Kind::SrflxV6, AddressFamily::V6, inputs);
    let v4 = score::score(Kind::SrflxV4, AddressFamily::V4, inputs);
    assert!(v6 > v4, "ties break toward IPv6");

    // A −400 breaker penalty lowers the score and does not remove the candidate:
    // there is no admissibility predicate in the module at all.
    let breakered = Inputs {
        breaker_penalty: -400,
        ..inputs
    };
    let s = score::score(Kind::Relay, AddressFamily::V4, breakered);
    assert!(s < score::score(Kind::Relay, AddressFamily::V4, inputs));
}

#[test]
fn an_eventual_health_hint_is_a_delta_and_never_a_gate() {
    // A reported "unhealthy" relay is penalised by exactly its delta, and the
    // candidate is still scored — there is no admissibility predicate anywhere
    // in the module to suppress it with.
    let base = score::score(Kind::Relay, AddressFamily::V4, Inputs::default());
    let hinted = Inputs {
        health_delta: -50,
        ..Inputs::default()
    };
    assert_eq!(
        score::score(Kind::Relay, AddressFamily::V4, hinted),
        base - 50
    );
    // The device's own measurement is an independent term, so no hint can mask
    // a measurement and no measurement can mask a hint.
    let measured = Inputs {
        ewma_rtt_ms: 30,
        ..Inputs::default()
    };
    assert_eq!(
        score::score(Kind::Relay, AddressFamily::V4, measured),
        base - 30
    );
    let both = Inputs {
        ewma_rtt_ms: 30,
        health_delta: -50,
        ..Inputs::default()
    };
    assert_eq!(
        score::score(Kind::Relay, AddressFamily::V4, both),
        base - 80
    );
}

#[test]
fn path_better_needs_both_margins() {
    // Score margin met, RTT margin not.
    assert!(!score::path_better(100, 80, 50, 55));
    // RTT margin met, score margin not.
    assert!(!score::path_better(85, 80, 20, 50));
    // Both.
    assert!(score::path_better(100, 80, 20, 50));
}

#[test]
fn path_failing_is_the_middle_rung_and_not_path_death() {
    assert!(!score::path_failing(2, 0, false), "2 missed is SUSPECT");
    assert!(score::path_failing(3, 0, false), "3 missed is FAILING");
    assert!(score::path_failing(0, 16, false));
    assert!(score::path_failing(0, 0, true));
}

#[test]
fn anti_flap_never_traps_a_session_on_a_dead_path() {
    let t0 = MonotonicInstant::ORIGIN;
    let mut a = AntiFlap::new();
    a.observe_promotion(t0);
    // Quality-only demotion is refused for T_UPGRADE_DWELL.
    assert!(!a.quality_demotion_admissible(t0.saturating_add(Duration::from_secs(60))));
    assert!(a.quality_demotion_admissible(t0.saturating_add(Duration::from_secs(121))));
    // A HARD failure is never suppressed by dwell, flap suppression or cooldown.
    assert!(a.hard_demotion_admissible());
}

#[test]
fn three_oscillations_suppress_the_direct_candidate_and_a_network_change_clears_it() {
    let t0 = MonotonicInstant::ORIGIN;
    let mut a = AntiFlap::new();
    for i in 0..3 {
        a.observe_promotion(t0.saturating_add(Duration::from_secs(i * 10)));
    }
    assert!(a.is_suppressed(t0.saturating_add(Duration::from_secs(100))));
    // On that network fingerprint only: any network change clears it.
    a.on_network_change();
    assert!(!a.is_suppressed(t0.saturating_add(Duration::from_secs(100))));
    // And suppression expires on its own after 30 min.
    let mut b = AntiFlap::new();
    for i in 0..3 {
        b.observe_promotion(t0.saturating_add(Duration::from_secs(i * 10)));
    }
    assert!(!b.is_suppressed(t0.saturating_add(Duration::from_secs(1900))));
}

#[test]
fn probing_becomes_event_driven_but_never_stops_permanently() {
    assert!(score::timer_driven_probing(19));
    assert!(!score::timer_driven_probing(20));
    // The upgrade prober's decaying ladder, and its background floor.
    assert_eq!(
        race::upgrade_probe_interval(0, false),
        Duration::from_secs(1)
    );
    assert_eq!(
        race::upgrade_probe_interval(2, false),
        Duration::from_secs(4)
    );
    assert_eq!(
        race::upgrade_probe_interval(9, false),
        Duration::from_secs(60)
    );
    assert_eq!(
        race::upgrade_probe_interval(0, true),
        Duration::from_secs(300)
    );
}

// ---------------------------------------------------------------------------
// The NAT taxonomy and the two bounded techniques
// ---------------------------------------------------------------------------

fn cls(mapping: Mapping, filtering: Filtering, cgnat: bool, v6: bool) -> NatClass {
    NatClass {
        mapping,
        filtering,
        cgnat,
        native_v6: v6,
    }
}

#[test]
fn if_both_ends_have_ipv6_every_cell_is_direct() {
    let worst = cls(
        Mapping::AddressAndPortDependent,
        Filtering::AddressAndPortDependent,
        true,
        true,
    );
    assert_eq!(traversability_of(worst, worst), Traversability::Direct);
}

fn traversability_of(a: NatClass, b: NatClass) -> Traversability {
    nat::traversability(a, b)
}

#[test]
fn the_two_hard_cells_are_relay_by_design_and_not_a_failure() {
    let apdm = cls(
        Mapping::AddressAndPortDependent,
        Filtering::AddressAndPortDependent,
        false,
        false,
    );
    let cgnat = cls(
        Mapping::AddressAndPortDependent,
        Filtering::AddressAndPortDependent,
        true,
        false,
    );
    assert_eq!(traversability_of(apdm, apdm), Traversability::RelayByDesign);
    assert_eq!(
        traversability_of(cgnat, cgnat),
        Traversability::RelayByDesign
    );
    // An easy pair is direct.
    let eim = cls(
        Mapping::EndpointIndependent,
        Filtering::EndpointIndependent,
        false,
        false,
    );
    assert_eq!(traversability_of(eim, eim), Traversability::Direct);
    // One hard side is probabilistic.
    assert_eq!(
        traversability_of(apdm, eim),
        Traversability::DirectProbabilistic
    );
}

#[test]
fn the_legacy_names_are_a_cross_reference_and_the_axes_are_independent() {
    assert_eq!(
        cls(
            Mapping::EndpointIndependent,
            Filtering::EndpointIndependent,
            false,
            false
        )
        .legacy_name(),
        "full cone"
    );
    assert_eq!(
        cls(
            Mapping::EndpointIndependent,
            Filtering::AddressAndPortDependent,
            false,
            false
        )
        .legacy_name(),
        "port-restricted cone"
    );
    assert_eq!(
        cls(
            Mapping::AddressAndPortDependent,
            Filtering::AddressAndPortDependent,
            false,
            false
        )
        .legacy_name(),
        "symmetric"
    );
}

#[test]
fn port_prediction_is_bounded_once_and_only_against_an_observed_port_varying_peer() {
    let base = PortPrediction {
        k: 256,
        peer_mapping_observed_port_varying: true,
        already_attempted: false,
    };
    assert!(base.permitted());
    // Never against a peer whose mapping was not observed to vary.
    assert!(!PortPrediction {
        peer_mapping_observed_port_varying: false,
        ..base
    }
    .permitted());
    // At most once per path attempt.
    assert!(!PortPrediction {
        already_attempted: true,
        ..base
    }
    .permitted());
    // k is capped at 256: "a deliberate cap on aggressiveness".
    assert_eq!(PortPrediction { k: 4096, ..base }.effective_k(), MAX_K);
    assert!(!PortPrediction { k: 4096, ..base }.permitted());
    assert_eq!(nat::PREDICTION_BUDGET, Duration::from_secs(2));
}

#[test]
fn the_port_mapping_ladder_is_pcp_then_natpmp_then_upnp_with_a_250ms_budget_each() {
    assert_eq!(
        PortMapProtocol::LADDER,
        [
            PortMapProtocol::Pcp,
            PortMapProtocol::NatPmp,
            PortMapProtocol::UpnpIgd
        ]
    );
    assert_eq!(nat::PORTMAP_BUDGET, Duration::from_millis(250));
    assert_eq!(nat::PORTMAP_LIFETIME, Duration::from_secs(3600));
}

#[test]
fn udp_blocked_needs_all_three_observations() {
    assert!(nat::udp_blocked(false, false, true));
    assert!(!nat::udp_blocked(true, false, true), "a PONG arrived");
    assert!(!nat::udp_blocked(false, true, true), "the relay answered");
    assert!(
        !nat::udp_blocked(false, false, false),
        "TCP/443 also failed: this is not UDP-specific"
    );
}

#[test]
fn hairpin_failure_goes_to_the_relay_rather_than_spinning() {
    assert!(nat::hairpin_requires_relay(true, true, false));
    assert!(!nat::hairpin_requires_relay(true, true, true));
    assert!(!nat::hairpin_requires_relay(false, true, false));
}

// ---------------------------------------------------------------------------
// The contract defect
// ---------------------------------------------------------------------------

// `const_is_empty` fires because the table IS a const empty slice today. That
// is exactly what this asserts and exactly what must not change silently:
// the point is to fail when a row comes back, not to observe that none is
// there now. Suppressed at the assertion rather than rewritten as a length
// comparison, which `len_zero` then objects to.
#[allow(clippy::const_is_empty)]
#[test]
fn no_traversal_code_is_substituted_any_more() {
    // Inverted, not deleted. This asserted the six ADR-0004 spellings were
    // STILL absent and named the substitution to remove when one landed.
    // registry_version 2 registered all six and it fired exactly as designed.
    assert!(
        UNREGISTERED.is_empty(),
        "a traversal code is being substituted again: {:?}",
        UNREGISTERED.iter().map(|s| s.specified).collect::<Vec<_>>()
    );
    for spelling in [
        "NAT.PORTMAP_FAILED",
        "NAT.HAIRPIN_UNSUPPORTED",
        "NAT.CLASS_OBSERVED",
        "NET.EGRESS_RESTRICTED",
        "NET.PROXY_REQUIRED",
        "NET.HAIRPIN_UNSUPPORTED",
    ] {
        assert!(
            twinvpn_types::ReasonCode::lookup(spelling).is_some(),
            "{spelling} is named by ADR-0004 and is not registered"
        );
    }
}

#[test]
fn the_direct_success_outcome_carries_all_four_declared_evidence_fields() {
    let d = twinvpn_path::codes::direct_established(AddressFamily::V6, Kind::HostV6Global, 412, 0);
    assert_eq!(d.code().as_str(), "NAT.DIRECT_ESTABLISHED");
    for key in [
        "family",
        "candidate_type",
        "elapsed_ms",
        "relay_gathered_at_ms",
    ] {
        assert!(
            d.evidence().get(key).is_some(),
            "{key} is declared by the registry for this code"
        );
        assert!(
            d.code().declares_evidence(key),
            "{key} must be declared, not smuggled"
        );
    }
}
