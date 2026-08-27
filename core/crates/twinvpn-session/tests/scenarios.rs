//! The scenarios `docs/reliability.md` names as the ones that must not break.
//!
//! Suspend/resume, interface flap, path death with and without an alternate,
//! relay drain — each run twice where it matters: once under `FAIL_CLOSED` and
//! once under `PERMISSIVE_ANNOUNCED`, because §4.4's dispositions differ and
//! getting the fail-closed half right is the whole product.

mod common;

use core::time::Duration;

use common::{healthy, session_id, test_env};
use twinvpn_session::backoff::{Backoff, Regime, BLOCKED_FLOOR};
use twinvpn_session::budget::{Breaker, BreakerState, GlobalBrake, RetryBudget};
use twinvpn_session::event::LinkKind;
use twinvpn_session::keepalive::{NatKeepalive, WakeWindow};
use twinvpn_session::liveness::{Liveness, PathLiveness};
use twinvpn_session::machine::Outcome;
use twinvpn_session::resumption::{fate, next_step, Disruption, Fate, Item, RecoveryStep, WakeStep};
use twinvpn_session::state::EnforcementMode;
use twinvpn_session::timers::{self, ClockClass, TimerProfile};
use twinvpn_session::{Context, Event, Guards, Row, SessionMachine, SessionState, TimerId};
use twinvpn_types::{PathClass, TrafficDisposition};

fn drive(m: &mut SessionMachine, ev: impl Into<twinvpn_session::Trigger>, g: Guards) -> Row {
    match m.apply(ev.into(), g, Context::default()) {
        Outcome::Transitioned(r) => r.row,
        Outcome::Ignored { state, trigger } => {
            panic!("{state:?} ignored {trigger:?}")
        }
    }
}

fn established(carrier: PathClass) -> (SessionMachine, Guards) {
    let (env, _vt) = test_env();
    let mut m = SessionMachine::new(env, session_id());
    let g = healthy();
    drive(&mut m, Event::ConnectRequested, g);
    drive(&mut m, Event::CandidatesReady, g);
    drive(&mut m, Event::NegotiationOk, g);
    drive(&mut m, Event::HandshakeOk(carrier), g);
    assert_eq!(m.state(), SessionState::Steady(carrier));
    (m, g)
}

// ---------------------------------------------------------------------------
// Suspend / resume
// ---------------------------------------------------------------------------

#[test]
fn suspend_parks_with_a_named_code_and_never_silently() {
    let (mut m, g) = established(PathClass::WanDirect);
    let row = drive(&mut m, Event::Suspend, g);
    assert_eq!(row, Row::T34);
    assert_eq!(m.state(), SessionState::Reconnecting { parked: true });
    // §10.1 and §11.1: "a park that entered RECONNECTING without a code would be
    // exactly the silent entry §10 exists to make impossible."
    let rec = m.history().last().unwrap();
    assert!(rec.reason_code.is_some());
    assert_eq!(m.profile(), TimerProfile::Parked);
    // §8.1 / §11.2: a standby whose keepalive stopped is NOT warm.
    assert!(!m.profile().standby_may_be_warm());
    assert!(!m.profile().nat_keepalive_runs());
    assert!(m.profile().heartbeat(false).is_none());
}

#[test]
fn resume_with_a_surviving_path_migrates_and_with_a_stale_key_re_discovers() {
    // A path plausibly survived and the rekey window did not expire.
    let (mut m, mut g) = established(PathClass::WanDirect);
    drive(&mut m, Event::Suspend, g);
    g.path_plausibly_survived = true;
    assert_eq!(drive(&mut m, Event::Resume, g), Row::T35);
    assert!(matches!(m.state(), SessionState::Migrating { .. }));

    // §11.3: "If the ElapsedClock delta exceeds the rekey window, a full
    // handshake is forced." Transport keys are gone; pretending otherwise would
    // produce a tunnel that authenticates nothing.
    let (mut m, mut g) = established(PathClass::WanDirect);
    drive(&mut m, Event::Suspend, g);
    g.path_plausibly_survived = true;
    g.rekey_window_exceeded = true;
    assert_eq!(drive(&mut m, Event::Resume, g), Row::T35);
    assert_eq!(m.state(), SessionState::Discovering);
}

#[test]
fn a_long_suspend_does_not_fire_the_short_horizon_timers() {
    // ADR-0018 CD-1's third reason, measured: with an advancing clock, resuming
    // from an eight-hour sleep fires every short-horizon timer at once and
    // T_DEAD declares every path dead before the wake ladder can re-validate one.
    let (env, vt) = test_env();
    let before = env.now_monotonic();
    vt.suspend(Duration::from_secs(8 * 3600));
    let after = env.now_monotonic();
    assert_eq!(
        before, after,
        "the monotonic clock MUST NOT advance across suspend"
    );
    assert_eq!(vt.timers_fired(), 0);
    // The elapsed clock, which §11.3's rekey comparison reads, DOES advance.
    assert!(env.now_elapsed().as_micros() >= 8 * 3600 * 1_000_000);
}

#[test]
fn the_wake_sequence_re_asserts_enforcement_before_it_emits_traffic() {
    let seq = WakeStep::SEQUENCE;
    let enforce = seq
        .iter()
        .position(|s| *s == WakeStep::ReassertEnforcement)
        .unwrap();
    let recover = seq
        .iter()
        .position(|s| *s == WakeStep::RecoveryLadder)
        .unwrap();
    assert!(
        enforce < recover,
        "§11.3: enforcement is re-asserted BEFORE traffic is emitted, not after"
    );
    // And the delta is compared on the elapsed clock, not the wall clock.
    let cmp = seq
        .iter()
        .position(|s| *s == WakeStep::CompareElapsedDelta)
        .unwrap();
    assert!(cmp < recover);
}

// ---------------------------------------------------------------------------
// Interface flap and path death
// ---------------------------------------------------------------------------

#[test]
fn path_death_with_an_alternate_migrates_and_without_one_reconnects() {
    // With: T19, and §8.1 forbids passing through RECONNECTING.
    let (mut m, mut g) = established(PathClass::Relayed);
    g.relay_failover_target_ready = true;
    assert_eq!(drive(&mut m, Event::RelayGone, g), Row::T19);
    assert!(matches!(m.state(), SessionState::Migrating { .. }));
    assert!(m
        .history()
        .iter()
        .all(|r| r.to != SessionState::Reconnecting { parked: false }));

    // Without: T20, with a named cause.
    let (mut m, g) = established(PathClass::WanDirect);
    assert_eq!(drive(&mut m, Event::LinkDown(LinkKind::Cellular), g), Row::T20);
    assert_eq!(m.state(), SessionState::Reconnecting { parked: false });
    assert!(m.history().last().unwrap().reason_code.is_some());
}

#[test]
fn an_interface_flap_under_fail_closed_reaches_blocked_and_drops_every_packet() {
    let (mut m, g) = established(PathClass::WanDirect);
    assert!(g.fail_closed());
    drive(&mut m, Event::LinkDown(LinkKind::WiFi), g);
    assert_eq!(
        m.state().disposition(true),
        TrafficDisposition::DroppedFailClosed
    );
    assert_eq!(drive(&mut m, TimerId::ReconnectGrace, g), Row::T26);
    assert_eq!(m.state(), SessionState::Blocked);
    // §4.4: BLOCKED is DROPPED_FAIL_CLOSED "always, without exception" — the
    // enforcement mode is not even consulted.
    assert_eq!(
        m.state().disposition(false),
        TrafficDisposition::DroppedFailClosed
    );
}

#[test]
fn an_interface_flap_under_permissive_announced_bounds_itself_at_failed() {
    let (mut m, mut g) = established(PathClass::WanDirect);
    g.enforcement = Some(EnforcementMode::PermissiveAnnounced);
    drive(&mut m, Event::PathDead, g);
    // Under PERMISSIVE_ANNOUNCED the grace timer does NOT reach BLOCKED.
    let outcome = m.apply(TimerId::ReconnectGrace.into(), g, Context::default());
    assert!(matches!(outcome, Outcome::Ignored { .. }));
    assert_eq!(drive(&mut m, TimerId::ReconnectMax, g), Row::T27);
    assert_eq!(m.state(), SessionState::Failed);
}

#[test]
fn leaving_blocked_requires_the_authenticated_user_action() {
    let (mut m, mut g) = established(PathClass::WanDirect);
    drive(&mut m, Event::PathDead, g);
    drive(&mut m, TimerId::ReconnectGrace, g);
    assert_eq!(m.state(), SessionState::Blocked);

    // Without the authenticated action, a disconnect request is refused — T38's
    // guard is `state != BLOCKED` and T32's guard is not met.
    let outcome = m.apply(Event::DisconnectRequested.into(), g, Context::default());
    assert!(
        matches!(outcome, Outcome::Ignored { .. }),
        "leaving fail-closed without a restored path must never be automatic"
    );
    assert_eq!(m.state(), SessionState::Blocked);

    g.authenticated_disarm = true;
    assert_eq!(drive(&mut m, Event::DisconnectRequested, g), Row::T32);
    assert_eq!(m.state(), SessionState::Disconnected);
}

#[test]
fn a_policy_violation_wins_from_every_state() {
    use twinvpn_session::event::PolicyViolationKind;
    for start in [
        PathClass::LocalDirect,
        PathClass::WanDirect,
        PathClass::Relayed,
    ] {
        let (mut m, g) = established(start);
        assert_eq!(
            drive(
                &mut m,
                Event::PolicyViolation(PolicyViolationKind::RouteDrift),
                g
            ),
            Row::T29
        );
        assert_eq!(m.state(), SessionState::Blocked);
    }
}

// ---------------------------------------------------------------------------
// Relay drain
// ---------------------------------------------------------------------------

#[test]
fn a_relay_drain_is_not_handled_as_a_failure() {
    let (mut m, g) = established(PathClass::Relayed);
    assert_eq!(drive(&mut m, Event::RelayDraining, g), Row::T37);
    assert!(matches!(m.state(), SessionState::Migrating { .. }));
    // §8.3: "A planned relay drain is not a failure and MUST NOT be handled as
    // one" — so no reason-bearing state is entered.
    assert!(m
        .history()
        .iter()
        .all(|r| !r.to.requires_reason_code() || r.reason_code.is_some()));
    assert!(m.history().iter().all(|r| r.to != SessionState::Blocked));
}

#[test]
fn the_drain_draw_is_reproducible_from_the_seeded_stream() {
    // §8.3's uniform draw and ADR-0006's region spread both come from a named
    // consumer, which is what makes a herd-control decision testable at all.
    let (env, _vt) = test_env();
    let mut a = env
        .rng_for(twinvpn_env::consumers::RELAY_REGION_SPREAD)
        .unwrap();
    let mut b = env
        .rng_for(twinvpn_env::consumers::RELAY_REGION_SPREAD)
        .unwrap();
    let span = timers::T_REGION_SPREAD.default;
    assert_eq!(a.uniform_duration(span), b.uniform_duration(span));
    // A different consumer draws a different stream, and adding one does not
    // shift an existing one (CD-4).
    let mut other = env.rng_for(twinvpn_env::consumers::RELAY_HRW).unwrap();
    assert_ne!(a.uniform_duration(span), other.uniform_duration(span));
}

// ---------------------------------------------------------------------------
// §5.3.1's clock classes, §6.1's regimes, §6.3's budgets, §6.4, §6.5, §6.6
// ---------------------------------------------------------------------------

#[test]
fn every_registered_constant_declares_a_clock_class_and_r_clk_1_holds() {
    for c in timers::REGISTERED {
        // R-CLK-3: a constant without a declared class is a defect. Declaring is
        // structural here, so the assertion is R-CLK-1's.
        if c.bounds_authority {
            assert_eq!(
                c.clock,
                ClockClass::Elapsed,
                "R-CLK-1: {} bounds an authority and MUST read the elapsed clock",
                c.name
            );
        } else {
            assert_eq!(
                c.clock,
                ClockClass::Monotonic,
                "{} is a liveness/recovery constant and MUST read the monotonic clock",
                c.name
            );
        }
        assert_ne!(c.clock, ClockClass::Wall, "the wall clock is evidence only");
    }
    // The four §5.3.1 names, spot-checked against the document.
    assert_eq!(timers::T_TRUST_HARD.clock, ClockClass::Elapsed);
    assert_eq!(timers::T_TK_OVERLAP.clock, ClockClass::Elapsed);
    assert_eq!(timers::T_DEAD.clock, ClockClass::Monotonic);
    assert_eq!(timers::T_HEARTBEAT_ACTIVE.clock, ClockClass::Monotonic);
}

#[test]
fn the_settled_values_are_the_settled_values() {
    assert_eq!(timers::T_HE_BIAS.default, Duration::from_millis(250));
    assert_eq!(timers::T_MIGRATE.default, Duration::from_secs(3));
    assert_eq!(timers::QOS_RTT_RELAY_ABSOLUTE_MS, 250);
    assert_eq!(timers::NAT_LADDER, [25, 35, 50, 70, 100, 120]);
    assert_eq!(timers::T_RECONNECT_GRACE.default, Duration::from_secs(20));
}

#[test]
fn both_backoff_regimes_stay_inside_their_caps_and_reset_on_success() {
    let (env, _vt) = test_env();
    for regime in [Regime::Infrastructure, Regime::Interactive] {
        let mut b = Backoff::new(regime);
        for _ in 0..40 {
            let d = b.next_delay(&env).unwrap();
            assert!(d <= regime.cap(), "{regime:?} exceeded its cap: {d:?}");
        }
        assert!(b.attempt() > 0);
        b.reset();
        assert_eq!(b.attempt(), 0);
    }
    // Equal jitter guarantees at least half the nominal delay has elapsed.
    let mut b = Backoff::new(Regime::Interactive);
    for _ in 0..8 {
        let _ = b.next_delay(&env).unwrap();
    }
    let d = b.next_delay(&env).unwrap();
    assert!(d >= Regime::Interactive.cap() / 2);
    // BLOCKED's floor rate is 30 s, forever.
    assert_eq!(BLOCKED_FLOOR, Duration::from_secs(30));
}

#[test]
fn an_open_breaker_penalises_selection_and_never_filters_it() {
    let mut b = Breaker::new();
    for _ in 0..5 {
        b.observe_failure(twinvpn_types::ErrorClass::Transient);
    }
    assert_eq!(b.state(), BreakerState::Open);
    assert_eq!(b.score_penalty(), twinvpn_session::budget::OPEN_BREAKER_PENALTY);
    // §6.3: a POLICY code opens no breaker at all.
    let mut p = Breaker::new();
    for _ in 0..10 {
        p.observe_failure(twinvpn_types::ErrorClass::Policy);
    }
    assert_eq!(p.state(), BreakerState::Closed);
    // A FATAL code opens it permanently: no timer revives it.
    let mut f = Breaker::new();
    f.observe_failure(twinvpn_types::ErrorClass::Fatal);
    assert!(!f.try_half_open());
    f.precondition_met();
    assert_eq!(f.state(), BreakerState::HalfOpen);
    // Two consecutive successes close it.
    f.observe_success();
    f.observe_success();
    assert_eq!(f.state(), BreakerState::Closed);
}

#[test]
fn the_retry_budget_floors_at_three_per_minute_even_when_everything_fails() {
    let (env, vt) = test_env();
    let mut budget = RetryBudget::new(env.now_monotonic());
    for _ in 0..100 {
        budget.observe_failure();
    }
    assert!(
        budget.refill_per_min() >= twinvpn_session::budget::REFILL_FLOOR_PER_MIN,
        "a target failing 100% must still be probed often enough to notice recovery"
    );
    // Drain, then let a minute pass and confirm the floor refilled it.
    while budget.spend(env.now_monotonic()) {}
    vt.advance(Duration::from_secs(60));
    assert!(budget.spend(env.now_monotonic()));
}

#[test]
fn the_global_brake_engages_past_half_the_reachable_relay_set() {
    let (env, vt) = test_env();
    let mut brake = GlobalBrake::new();
    assert!(!brake.evaluate(2, 10, env.now_monotonic()));
    assert!(brake.evaluate(6, 10, env.now_monotonic()));
    assert!(brake.is_engaged(env.now_monotonic()));
    vt.advance(Duration::from_secs(61));
    assert!(!brake.is_engaged(env.now_monotonic()));
}

#[test]
fn liveness_needs_evidence_in_both_directions() {
    let (env, vt) = test_env();
    let mut p = PathLiveness::new();
    p.observe_inbound(env.now_monotonic());
    // Only one direction: §6.4 says that is explicitly not sufficient.
    assert_eq!(p.evaluate(env.now_monotonic()), Liveness::Dead);
    assert!(p.is_half_open(env.now_monotonic()));

    p.observe_outbound_acked(env.now_monotonic());
    assert_eq!(p.evaluate(env.now_monotonic()), Liveness::Live);
    assert!(!p.is_half_open(env.now_monotonic()));

    // The ladder escalates rather than jumping.
    p.observe_missed();
    p.observe_missed();
    assert_eq!(p.evaluate(env.now_monotonic()), Liveness::Suspect);
    p.observe_missed();
    assert_eq!(p.evaluate(env.now_monotonic()), Liveness::Failing);
    p.observe_missed();
    p.observe_missed();
    assert_eq!(p.evaluate(env.now_monotonic()), Liveness::Dead);

    // A hard signal bypasses every timer (R2).
    let mut q = PathLiveness::new();
    q.observe_inbound(env.now_monotonic());
    q.observe_outbound_acked(env.now_monotonic());
    q.observe_hard_failure();
    assert_eq!(q.evaluate(env.now_monotonic()), Liveness::Dead);

    // T_DEAD is a real deadline on the monotonic clock.
    let mut r = PathLiveness::new();
    r.observe_inbound(env.now_monotonic());
    r.observe_outbound_acked(env.now_monotonic());
    vt.advance(timers::T_DEAD.default + Duration::from_secs(1));
    assert_eq!(r.evaluate(env.now_monotonic()), Liveness::Dead);
}

#[test]
fn a_peer_restart_suppresses_the_failure_path_for_the_grace_window() {
    let (env, vt) = test_env();
    let mut p = PathLiveness::new();
    p.observe_peer_restarting(env.now_monotonic());
    // Even with no evidence at all, the grace window holds it LIVE.
    assert_eq!(p.evaluate(env.now_monotonic()), Liveness::Live);
    vt.advance(timers::T_PEER_RESTART_GRACE.default + Duration::from_secs(1));
    assert_eq!(p.evaluate(env.now_monotonic()), Liveness::Dead);
}

#[test]
fn the_nat_ladder_climbs_additively_and_reverts_to_the_last_known_good_rung() {
    let mut k = NatKeepalive::new();
    assert_eq!(k.interval(), Duration::from_secs(25));
    k.observe_binding_survived();
    assert_eq!(k.interval(), Duration::from_secs(35));
    k.observe_binding_survived();
    assert_eq!(k.interval(), Duration::from_secs(50));
    // The 50 s rung failed: revert to 35 s, the last rung that actually worked —
    // NOT to 25 s, which halving would give.
    k.observe_mapping_expired();
    assert_eq!(k.interval(), Duration::from_secs(35));
    assert_eq!(k.learned_seconds(), 35);
    // The ladder caps at 120 s.
    for _ in 0..20 {
        k.observe_binding_survived();
    }
    assert_eq!(k.interval(), Duration::from_secs(120));
    // A known network resumes at the right cadence immediately.
    assert_eq!(NatKeepalive::resume_at(70).interval(), Duration::from_secs(70));
}

#[test]
fn coalescing_rounds_up_so_n_peers_cost_one_wake() {
    let w = WakeWindow::new(Duration::from_secs(60));
    assert_eq!(w.align(Duration::from_secs(25)), Duration::from_secs(60));
    assert_eq!(w.align(Duration::from_secs(61)), Duration::from_secs(120));
}

#[test]
fn a_roam_and_a_relay_failover_do_not_break_inner_flows() {
    // §6.5's load-bearing consequence, asserted as the contract it is called.
    for d in [Disruption::PathChange, Disruption::RelayFailover] {
        assert_eq!(fate(Item::InnerFlows, d), Fate::Survives, "{d:?}");
        assert_eq!(fate(Item::TransportKeys, d), Fate::Survives);
        assert_eq!(fate(Item::InnerAddresses, d), Fate::Survives);
        assert_eq!(fate(Item::SessionIdentity, d), Fate::Survives);
        // Path properties are reset, because they belong to the path.
        assert_eq!(fate(Item::PathEstimates, d), Fate::Reset);
    }
    // A process restart loses the cryptographic and per-path state, and keeps
    // the Session — the correction §6.5 records against an earlier draft.
    assert_eq!(
        fate(Item::SessionIdentity, Disruption::ProcessRestart),
        Fate::Survives
    );
    assert_eq!(
        fate(Item::TransportKeys, Disruption::ProcessRestart),
        Fate::Lost
    );
    assert_eq!(
        fate(Item::ReplayWindow, Disruption::ProcessRestart),
        Fate::Lost
    );
}

#[test]
fn the_recovery_ladder_prefers_the_cheapest_step_that_could_work() {
    let mut g = Guards::default();
    assert_eq!(
        next_step(g, true),
        Some(RecoveryStep::RevalidateExisting),
        "the common roaming case costs ~1 RTT and no handshake"
    );
    g.relay_standby_selected = true;
    assert_eq!(next_step(g, false), Some(RecoveryStep::WarmStandby));
    g.relay_standby_selected = false;
    assert_eq!(next_step(g, false), Some(RecoveryStep::CachedEndpoints));
    // Steps 1-4 need no control plane at all (I5).
    for s in [
        RecoveryStep::RevalidateExisting,
        RecoveryStep::WarmStandby,
        RecoveryStep::CachedEndpoints,
        RecoveryStep::CachedRelayMap,
    ] {
        assert!(!s.benefits_from_control_plane());
    }
}

#[test]
fn a_restarted_client_resumes_into_reconnecting_not_disconnected() {
    use twinvpn_session::journal::{DurableSession, EphemeralJournal, SessionJournal};
    let j = EphemeralJournal::new();
    let rec = DurableSession {
        session_id: session_id(),
        peer: twinvpn_types::DeviceId::from_array([1u8; 32]),
        last_state: SessionState::Steady(PathClass::WanDirect),
        last_reason: None,
    };
    j.persist(&rec).unwrap();
    let loaded = j.load_all().unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(
        loaded[0].resume_state(),
        SessionState::Reconnecting { parked: false }
    );
    // A Session the user closed stays closed.
    let closed = DurableSession {
        last_state: SessionState::Disconnected,
        ..rec
    };
    assert_eq!(closed.resume_state(), SessionState::Disconnected);
}

// ---------------------------------------------------------------------------
// §4.7 aggregation
// ---------------------------------------------------------------------------

#[test]
fn the_twinnet_aggregate_never_looks_healthier_than_reality() {
    use twinvpn_session::aggregate::{aggregate, Contribution};
    use twinvpn_types::ConnectionState;

    let healthy_peer = Contribution {
        state: SessionState::Steady(PathClass::LocalDirect),
        reason_code: None,
        in_protected_scope: true,
        has_usable_path: true,
    };
    let broken_peer = Contribution {
        state: SessionState::Reconnecting { parked: false },
        reason_code: Some(twinvpn_types::codes::NET_NO_ROUTE),
        in_protected_scope: true,
        has_usable_path: false,
    };

    let a = aggregate(&[healthy_peer, healthy_peer, healthy_peer, broken_peer], true);
    assert_eq!(a.state, ConnectionState::Reconnecting, "worst wins");
    assert_eq!(a.healthy, 3);
    assert_eq!(a.total, 4);
    assert!(a.reason_code.is_some(), "the aggregate carries the cause");

    // Rule 1: fail-closed with no protected session usable is BLOCKED, even
    // though every session is merely FAILED.
    let failed_peer = Contribution {
        state: SessionState::Failed,
        reason_code: Some(twinvpn_types::codes::AUTH_CRED_EXPIRED),
        in_protected_scope: true,
        has_usable_path: false,
    };
    let b = aggregate(&[failed_peer, failed_peer], true);
    assert_eq!(b.state, ConnectionState::Blocked);
    assert!(b.reason_code.is_some());

    // One failed peer among healthy ones does not make the TwinNet failed.
    let c = aggregate(&[healthy_peer, failed_peer], false);
    assert_ne!(c.state, ConnectionState::Failed);
}
