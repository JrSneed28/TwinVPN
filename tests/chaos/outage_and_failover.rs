//! **Chaos.** Components killed and restarted mid-flow, and the properties
//! Phase 1 promises survive it.
//!
//! **Authority:** `docs/testing-strategy.md` §2.13, §6.5 blockers **B-19**,
//! **B-1** (P15); `docs/reliability.md` §6 (recovery), §8 (relay failover), §9
//! (control-plane outage); ADR-0002 §11.8; invariant **I5**.
//!
//! # The three promises under test
//!
//! 1. **I5.** A control-plane outage never prevents re-establishing a session
//!    with a known `TrustedPeer`. §9 implements this as a *guard* change, so the
//!    test is: set exactly the guards an outage produces, and assert the machine
//!    still reaches a steady carrier state.
//! 2. **A relay loss migrates rather than dropping.** T19 against T20, driven
//!    from `twinvpn-relay-client`'s own attribution of the same observation —
//!    the two crates must agree about what "the relay died" means.
//! 3. **A crash between a mutation and its event loses both.** `control-plane`
//!    tests this in-process; here it is tested **across the platform seam**,
//!    which is the boundary the client actually crashes at.
//!
//! # I5's static half is not tested here, and that is deliberate
//!
//! **B-19** requires ADR-0002 §11.8's dependency-graph assertion — data-plane
//! modules MUST NOT link the control-plane client — and states plainly that P15
//! passing at T3 does not substitute. That check belongs to `core/xtask`'s
//! `arch-lint`, not to a test binary, and this file does not pretend to be it.
//! `the_dependency_graph_assertion_is_not_this_files_job` records where it lives.

use twinvpn_env::MonotonicInstant;
use twinvpn_platform::{ContractGeneration, PlatformAdapter, PlatformError, Ruleset};
use twinvpn_relay_client::failover::{
    attribute, fleet_exhausted, Attribution, FleetExhausted, Observation,
};
use twinvpn_relay_client::standby::Posture;
use twinvpn_route::program::RoutingMode;
use twinvpn_session::{
    Context as SessionContext, EnforcementMode, Event, Guards, SessionMachine, SessionState,
    Trigger,
};
use twinvpn_types::{PathClass, PerFamily, SessionId};

use twinvpn_system_tests::{block_on, dns_policy, stub_addresses, HostFamily, Rig};

const XTASK_CHECKS: &str = include_str!("../../core/xtask/src/checks.rs");

// ---------------------------------------------------------------------------
// I5 — the control plane is down and a known peer is still reachable.
// ---------------------------------------------------------------------------

/// The guard set §9 produces during a control-plane outage: the cursor is
/// unavailable and the trust state has aged out, but the peer is still an
/// authorized `TrustedPeer` and no policy grant was withdrawn.
fn outage_guards(carrier: PathClass) -> Guards {
    Guards {
        credentials_valid: true,
        peer_authorized: true,
        usable_candidate: true,
        path_validated: true,
        retry_budget_available: true,
        relay_set_nonempty: true,
        no_l2_path_won: carrier != PathClass::LocalDirect,
        no_direct_path_won: carrier == PathClass::Relayed,
        // The outage itself:
        cursor_unavailable: true,
        trust_state_expired: true,
        trust_epoch_behind: true,
        // …and the thing that is NOT true, which is the whole of R-11:
        policy_grant_expired: false,
        enforcement: Some(EnforcementMode::FailClosed),
        ..Guards::default()
    }
}

#[test]
fn i5_a_control_plane_outage_never_prevents_reaching_a_known_trusted_peer() {
    // On every underlay family, and over every carrier class, because "we can
    // still relay" is not the same promise as "we can still connect".
    for family in HostFamily::ALL {
        for carrier in [
            PathClass::LocalDirect,
            PathClass::WanDirect,
            PathClass::Relayed,
        ] {
            let mut rig = Rig::new(family, 21);
            let g = outage_guards(carrier);
            for trigger in [
                Trigger::Event(Event::ConnectRequested),
                Trigger::Event(Event::CandidatesReady),
                Trigger::Event(Event::NegotiationOk),
                Trigger::Event(Event::HandshakeOk(carrier)),
            ] {
                rig.session.apply(trigger, g, SessionContext::default());
            }
            assert_eq!(
                rig.session.state(),
                SessionState::Steady(carrier),
                "{} / {carrier:?}: a control-plane outage prevented reaching a \
                 known TrustedPeer, which I5 forbids",
                family.name()
            );
        }
    }
}

#[test]
fn r11_an_expired_trust_state_alone_never_blocks_and_a_withdrawn_grant_does() {
    // The negative control for I5, and R-11's exact wording: "Baseline
    // reachability to a known TrustedPeer is untouched, so this MUST NOT by
    // itself drive BLOCKED or FAILED." A test that only asserted the positive
    // would pass for a build that never blocks at all.
    let expired_only = Guards {
        trust_state_expired: true,
        ..Guards::default()
    };
    assert!(
        !expired_only.trust_expiry_blocks(),
        "an expired trust state alone contributed to BLOCKED"
    );

    let both = Guards {
        trust_state_expired: true,
        policy_grant_expired: true,
        ..Guards::default()
    };
    assert!(
        both.trust_expiry_blocks(),
        "the positive control: a withdrawn grant compounded by trust expiry must \
         be able to block"
    );
}

#[test]
fn a_restarted_client_resumes_into_reconnecting_carrying_a_code() {
    // §6.5 / S-12: "a restarted client resumes into RECONNECTING for each known
    // peer rather than starting from DISCONNECTED", and §10.1 makes a state that
    // requires a code unable to exist without one.
    let rig = Rig::new(HostFamily::Dual, 22);
    let resumed = SessionMachine::resumed(
        rig.env.env_owned(),
        SessionId::from_array([22; 16]),
        SessionState::Reconnecting { parked: false },
        None,
    );
    assert_eq!(
        resumed.state(),
        SessionState::Reconnecting { parked: false }
    );
    assert!(
        resumed.reason().is_some(),
        "a resumed RECONNECTING without a reason code is the silent failure §10.1 \
         forbids"
    );
    assert!(resumed.state_and_reason_agree());
    assert!(
        resumed.history().is_empty(),
        "a resumed machine must not invent a transition it did not observe"
    );
}

// ---------------------------------------------------------------------------
// Relay loss: migrate, do not drop. Two crates must agree about the same event.
// ---------------------------------------------------------------------------

#[test]
fn a_relay_death_with_a_warm_standby_migrates_and_never_drops_the_session() {
    for family in HostFamily::ALL {
        let mut rig = Rig::new(family, 23);
        rig.establish(PathClass::Relayed);
        assert_eq!(
            rig.session.state(),
            SessionState::Steady(PathClass::Relayed)
        );

        // `twinvpn-relay-client` attributes the observation…
        let observed = Observation {
            missed_leg_pings: 3,
            leg_hard_signal: false,
            drain_deadline_reached: false,
            half_flow_silent: false,
            quality_violated: false,
            all_legs_on_interface_dead: false,
            capacity_rejected: false,
            region_failed: false,
        };
        assert_eq!(attribute(observed), Attribution::RelayFailure);
        assert!(attribute(observed).triggers_failover());

        // …and `twinvpn-session` must turn it into a migration, not a drop.
        let guards = Guards {
            relay_failover_target_ready: true,
            relay_set_nonempty: true,
            retry_budget_available: true,
            enforcement: Some(EnforcementMode::FailClosed),
            ..Guards::default()
        };
        rig.session.apply(
            Trigger::Event(Event::RelayGone),
            guards,
            SessionContext::default(),
        );
        assert_eq!(
            rig.session.state(),
            SessionState::Migrating {
                from: PathClass::Relayed,
                to: PathClass::Relayed,
            },
            "{}: a relay death with a warm standby dropped instead of migrating \
             (§8.1: RELAYED → MIGRATING{{RELAY→RELAY'}} → RELAYED, never through \
             RECONNECTING)",
            family.name()
        );
    }
}

#[test]
fn a_relay_death_with_no_standby_reconnects_and_names_why() {
    // The negative control. Without it, a machine that migrated unconditionally
    // would pass the test above.
    let mut rig = Rig::new(HostFamily::Dual, 24);
    rig.establish(PathClass::Relayed);
    let guards = Guards {
        // No warm standby.
        relay_failover_target_ready: false,
        retry_budget_available: true,
        enforcement: Some(EnforcementMode::FailClosed),
        ..Guards::default()
    };
    rig.session.apply(
        Trigger::Event(Event::RelayGone),
        guards,
        SessionContext::default(),
    );
    assert_eq!(
        rig.session.state(),
        SessionState::Reconnecting { parked: false }
    );
    let reason = rig.session.reason().expect("RECONNECTING carries a code");
    assert!(
        reason.as_str().starts_with("NET.") || reason.as_str().starts_with("RELAY."),
        "the reason for reconnecting was `{}`",
        reason.as_str()
    );
}

#[test]
fn a_parked_standby_is_never_reported_as_failover_ready() {
    // The two crates' shared vocabulary: `Posture::failover_target_ready` is
    // what the session's `relay_failover_target_ready` guard means, and a posture
    // that over-reported it would make T19 fire with nothing to migrate to.
    assert!(Posture::Bound.failover_target_ready());
    assert!(Posture::LegOnly.failover_target_ready());
    assert!(!Posture::Released.failover_target_ready());
    assert!(!Posture::None.failover_target_ready());
    // Only a bound standby is warm; a leg-only one is ready but not warm.
    assert!(Posture::Bound.is_warm());
    assert!(!Posture::LegOnly.is_warm());
}

#[test]
fn total_fleet_unavailability_is_named_rather_than_degraded() {
    // ADR-0006: `DEGRADED` is not available for a fleet-wide loss. A build that
    // reported it would look healthier than it is on every dashboard.
    assert_eq!(
        fleet_exhausted(true, true),
        FleetExhausted::NoStateChange,
        "a live direct path is unaffected by the relay fleet being gone"
    );
    assert_eq!(fleet_exhausted(false, true), FleetExhausted::Blocked);
    assert_eq!(
        fleet_exhausted(false, false),
        FleetExhausted::ReconnectingThenFailed
    );
}

// ---------------------------------------------------------------------------
// A crash between a mutation and its event, across the platform seam.
// ---------------------------------------------------------------------------

#[test]
fn a_crash_between_a_mutation_and_its_event_loses_both() {
    // `control-plane` proves this in-process for the event log. The client's
    // equivalent boundary is the platform seam: if the apply did not complete,
    // the installed generation must not have moved, so a restarted core
    // re-reading `current_generation` converges on the old state rather than
    // believing in a generation that was never installed.
    let mut rig = Rig::new(HostFamily::Dual, 25);
    let plan = rig
        .route_plan(RoutingMode::TwinnetOnly, PerFamily::new(false, false))
        .expect("plan");
    let policy = dns_policy(twinvpn_dns::Mode::Split, true);
    let g1 = rig
        .contract(&plan, &policy, stub_addresses(), Ruleset::Protected)
        .expect("assemble");
    let installed = rig.apply(&g1).expect("a generation is in force");

    // The "crash": the next mutation fails part-way.
    let mut g2 = g1.clone();
    g2.generation = ContractGeneration(g1.generation.0 + 1);
    rig.adapter
        .fail_next_apply(PlatformError::RouteProgrammingDenied(None));
    assert!(block_on(rig.adapter.network_config().apply(&g2)).is_err());

    // The restarted core's recovery entry point.
    let after =
        block_on(rig.adapter.network_config().current_generation()).expect("current_generation");
    assert_eq!(
        after,
        Some(installed),
        "the generation moved despite the mutation failing: a restarted core \
         would converge on a state that was never installed"
    );

    // And the enforcement ruleset is unchanged, so the crash did not open a gap.
    assert_eq!(
        block_on(rig.adapter.network_config().installed_ruleset()).expect("read back"),
        Some(Ruleset::Protected)
    );
}

#[test]
fn a_reapplied_generation_after_a_crash_converges_rather_than_duplicating() {
    // ADR-0008's recovery half: the retry after the crash must be idempotent.
    let mut rig = Rig::new(HostFamily::Dual, 26);
    let plan = rig
        .route_plan(RoutingMode::TwinnetOnly, PerFamily::new(false, false))
        .expect("plan");
    let policy = dns_policy(twinvpn_dns::Mode::Split, true);
    let contract = rig
        .contract(&plan, &policy, stub_addresses(), Ruleset::Protected)
        .expect("assemble");

    rig.apply(&contract);
    let calls_before = rig.adapter.config_mock().apply_calls();
    rig.apply(&contract);
    let after = rig.adapter.config_mock().apply_calls();
    assert!(
        after > calls_before,
        "the retry must reach the adapter rather than being short-circuited"
    );
    assert_eq!(
        rig.adapter
            .config_mock()
            .current_contract()
            .map(|c| c.generation),
        Some(contract.generation),
        "the re-applied generation is the one in force"
    );
}

// ---------------------------------------------------------------------------
// The suspend/resume path, which is where a clock confusion becomes a bug.
// ---------------------------------------------------------------------------

#[test]
fn a_long_suspend_is_visible_on_the_elapsed_clock_and_not_the_monotonic_one() {
    // CD-1's non-interchangeable clocks, exercised through the rig's env rather
    // than through `twinvpn-env`'s own tests: the guard T35 reads
    // (`rekey_window_exceeded`) is computed from the ELAPSED delta, and a build
    // that read the monotonic clock would never force a rehandshake after a
    // laptop lid closed for a week.
    let rig = Rig::new(HostFamily::Dual, 27);
    let m0 = rig.env.env().now_monotonic();
    let e0 = rig.env.env().now_elapsed();
    rig.env
        .time()
        .suspend(core::time::Duration::from_secs(7 * 24 * 3600));
    assert_eq!(rig.env.env().now_monotonic(), m0);
    assert_eq!(
        rig.env.env().now_elapsed().duration_since(e0).as_secs(),
        7 * 24 * 3600
    );
    assert!(
        twinvpn_tunnel::rekey::KeyState::force_full_handshake(
            rig.env.env().now_elapsed().duration_since(e0)
        ),
        "a week-long suspend must force a full handshake"
    );
    assert!(
        !twinvpn_tunnel::rekey::KeyState::force_full_handshake(
            MonotonicInstant::ORIGIN.duration_since(MonotonicInstant::ORIGIN)
        ),
        "the control: no elapsed gap must not force one"
    );
}

// ---------------------------------------------------------------------------
// B-19: where I5's static half actually lives.
// ---------------------------------------------------------------------------

#[test]
fn the_dependency_graph_assertion_is_not_this_files_job() {
    // B-19: "The ADR-0002 §11.8 dependency-graph assertion absent or disabled.
    // P15 passing at T3 does not substitute." This test does not implement that
    // check — it asserts that the place that does still contains it, so a
    // reviewer reading the chaos suite is not left believing the runtime test
    // discharged I5 on its own.
    assert!(
        XTASK_CHECKS.contains("cp-client") || XTASK_CHECKS.contains("cp_client"),
        "core/xtask no longer mentions the control-plane client; the CD-I5 \
         dependency-graph assertion may have been removed, which B-19 makes \
         release-blocking on its own"
    );
}
