//! **End-to-end.** One session, from `ConnectRequested` to an applied network
//! contract, across every component that has to agree for that to work.
//!
//! **Authority:** `docs/testing-strategy.md` §2.7, §2.6; `docs/reliability.md`
//! §4.5, §10.1; `docs/networking.md` §2.1; ADR-0008 (idempotency); ADR-0010 R1;
//! ADR-0018 CD-5.
//!
//! # What is new here
//!
//! `twinvpn-session`'s own suite drives the machine; `twinvpn-route`'s drives
//! the planner; `twinvpn-platform`'s drives the seam. **Nothing joins them.**
//! Every test in this file spans at least two domains, so a defect that lives in
//! the space between two correct components is visible for the first time.
//!
//! This file drives the **leaf crates** directly, which is still the right
//! level for it: the route planner meeting the enforcement assembler meeting the
//! adapter is a composition the composition root does not add anything to.
//! `e2e/composed_core.rs` is the file that drives `twinvpn_core::Core` itself.

use twinvpn_platform::mock::MockAdapter;
use twinvpn_platform::mock::MockOptions;
use twinvpn_platform::{ContractGeneration, PlatformAdapter, PlatformError, Ruleset};
use twinvpn_route::program::RoutingMode;
use twinvpn_session::{
    Context as SessionContext, EnforcementMode, Event, Guards, SessionState, Trigger,
};
use twinvpn_types::{AddressFamily, PathClass, PerFamily};

use twinvpn_system_tests::{block_on, dns_policy, preconditions, stub_addresses, HostFamily, Rig};

// ---------------------------------------------------------------------------
// The happy path, on every underlay family.
// ---------------------------------------------------------------------------

#[test]
fn a_session_reaches_a_steady_carrier_state_on_every_underlay_family() {
    // L-5: a family with only a v4 instantiation fails review. The interesting
    // half is v6-only — the mobile network — which no other suite exercises
    // against a host that genuinely cannot open a v4 socket.
    for family in HostFamily::ALL {
        let mut rig = Rig::new(family, 1);
        let path = rig.establish(PathClass::WanDirect);
        assert_eq!(
            rig.session.state().connection_state(),
            twinvpn_types::ConnectionState::WanDirect,
            "{}: reached {:?} instead of a steady WAN_DIRECT carrier state",
            family.name(),
            rig.session.state()
        );
        assert_eq!(
            path,
            [
                SessionState::Discovering,
                SessionState::Negotiating,
                SessionState::Connecting,
                SessionState::Steady(PathClass::WanDirect),
            ],
            "{}: the state path is not §4.5's happy path",
            family.name()
        );
    }
}

#[test]
fn every_transition_the_session_took_carries_a_record_that_is_well_formed() {
    // §10.1: a silent transition must be unrepresentable. This asserts it over a
    // whole session rather than one row, which is the only place a record that
    // is well-formed alone but inconsistent in sequence would show up.
    let mut rig = Rig::new(HostFamily::Dual, 2);
    rig.establish(PathClass::WanDirect);
    let history: Vec<_> = rig.session.history().to_vec();
    assert!(!history.is_empty());
    for r in &history {
        assert!(r.is_well_formed(), "malformed transition record: {r:?}");
        assert!(
            r.invariant_violation().is_none(),
            "transition reported an invariant violation: {r:?}"
        );
    }
    assert_eq!(rig.session.invariant_violations(), 0);
    assert!(rig.session.state_and_reason_agree());
}

// ---------------------------------------------------------------------------
// The claim that spans networking.md §2.1, twinvpn-route and twinvpn-enforce.
// ---------------------------------------------------------------------------

#[test]
fn the_overlay_carries_both_families_even_when_the_underlay_is_single_stack() {
    // `docs/networking.md` §2.1: "both are always present on the interface even
    // when the underlay is single-stack. This is what makes application
    // behaviour identical on an IPv4-only cafe network and an IPv6-only mobile
    // network." Neither `twinvpn-route`'s suite nor `twinvpn-platform`'s can
    // assert this, because neither knows what the other's underlay looks like.
    for family in HostFamily::ALL {
        let mut rig = Rig::new(family, 3);
        let plan = rig
            .route_plan(RoutingMode::TwinnetOnly, PerFamily::new(false, false))
            .expect("a TwinnetOnly plan");
        for af in [AddressFamily::V4, AddressFamily::V6] {
            assert!(
                plan.carries(af),
                "{}: the plan does not carry {af:?}; §2.1 requires both overlay \
                 addresses regardless of the underlay",
                family.name()
            );
            assert!(
                !plan.addresses.get(af).is_empty(),
                "{}: no {af:?} overlay address",
                family.name()
            );
        }
        assert!(!plan.is_family_asymmetric(), "{}", family.name());
    }
}

#[test]
fn the_assembled_contract_points_the_host_at_a_resolver_in_both_families() {
    // ADR-0011 §13.4's shape: a contract that names v4 resolvers and leaves v6
    // to the OS is a leak, and it is assembled from THREE components' outputs.
    for family in HostFamily::ALL {
        let mut rig = Rig::new(family, 4);
        let plan = rig
            .route_plan(RoutingMode::TwinnetOnly, PerFamily::new(false, false))
            .expect("plan");
        let policy = dns_policy(twinvpn_dns::Mode::Split, true);
        let contract = rig
            .contract(&plan, &policy, stub_addresses(), Ruleset::Protected)
            .expect("assemble");
        for af in [AddressFamily::V4, AddressFamily::V6] {
            assert!(
                !contract.dns.resolvers.get(af).is_empty(),
                "{}: the contract names no {af:?} resolver",
                family.name()
            );
            assert!(
                !contract.addresses.get(af).is_empty(),
                "{}: the contract carries no {af:?} address",
                family.name()
            );
        }
    }
}

#[test]
fn a_plan_that_lost_one_family_is_refused_rather_than_installed() {
    // The negative control for the two tests above. Without it, an assembler
    // that never checked anything would pass them both. This is the guard
    // ADR-0010 R1 exists to be — and it is asserted from outside the crate that
    // owns it, against a plan the route planner actually produced.
    let mut rig = Rig::new(HostFamily::Dual, 5);
    let mut plan = rig
        .route_plan(RoutingMode::TwinnetOnly, PerFamily::new(false, false))
        .expect("plan");
    plan.addresses.v6.clear();
    plan.routes.v6.clear();
    assert!(
        plan.is_family_asymmetric(),
        "a plan with no v6 half must read as asymmetric"
    );
    let policy = dns_policy(twinvpn_dns::Mode::Split, true);
    let err = rig
        .contract(&plan, &policy, stub_addresses(), Ruleset::Protected)
        .expect_err("assembly must refuse a family-asymmetric plan");
    assert_eq!(
        err.reason_code().as_str(),
        "POLICY.LEAK.IPV6_UNPROTECTED",
        "the refusal must name the leak, not a generic failure"
    );
    assert_eq!(err.uncovered_family(true), AddressFamily::V6);
}

// ---------------------------------------------------------------------------
// Across the platform seam: ADR-0008 idempotency, and all-or-nothing.
// ---------------------------------------------------------------------------

#[test]
fn applying_the_same_generation_twice_converges_rather_than_duplicating() {
    // ADR-0008, asserted end to end: the contract is produced by the real route
    // and enforcement pipeline, not hand-built, so an idempotency bug that only
    // shows up for a *realistic* contract is reachable here.
    let mut rig = Rig::new(HostFamily::Dual, 6);
    let plan = rig
        .route_plan(RoutingMode::TwinnetOnly, PerFamily::new(false, false))
        .expect("plan");
    let policy = dns_policy(twinvpn_dns::Mode::Split, true);
    let contract = rig
        .contract(&plan, &policy, stub_addresses(), Ruleset::Protected)
        .expect("assemble");

    let first = rig.apply(&contract);
    let second = rig.apply(&contract);
    assert_eq!(first, second, "re-applying a generation changed the state");
    assert_eq!(first, Some(contract.generation));

    let installed = block_on(rig.adapter.network_config().installed_ruleset()).expect("read back");
    assert_eq!(installed, Some(Ruleset::Protected));
}

#[test]
fn a_failed_apply_leaves_the_previous_generation_exactly_as_it_was() {
    // The all-or-nothing half of ADR-0008. Unreachable on a real adapter without
    // a hostile kernel, which is exactly why CD-5's mock exists — and why this
    // test can only be written where the mock and the real contract meet.
    let mut rig = Rig::new(HostFamily::Dual, 7);
    let plan = rig
        .route_plan(RoutingMode::TwinnetOnly, PerFamily::new(false, false))
        .expect("plan");
    let policy = dns_policy(twinvpn_dns::Mode::Split, true);
    let good = rig
        .contract(&plan, &policy, stub_addresses(), Ruleset::Protected)
        .expect("assemble");
    let before = rig.apply(&good);

    let mut next = good.clone();
    next.generation = ContractGeneration(good.generation.0 + 1);
    rig.adapter
        .fail_next_apply(PlatformError::RouteProgrammingDenied(None));
    let failed = block_on(rig.adapter.network_config().apply(&next));
    assert!(failed.is_err(), "the injected failure did not fire");

    let after =
        block_on(rig.adapter.network_config().current_generation()).expect("current_generation");
    assert_eq!(
        before, after,
        "a failed apply moved the installed generation; ADR-0008 requires the \
         system to be exactly as it was"
    );
}

#[test]
fn enforcement_survives_the_core_going_away() {
    // CB-6. The kill switch's whole value is that it outlives the process that
    // armed it, and this is the only place the enforcement expectation
    // (`twinvpn-enforce`) and the custody model (`twinvpn-platform`) are checked
    // against each other.
    let mut rig = Rig::new(HostFamily::Dual, 8);
    let plan = rig
        .route_plan(RoutingMode::TwinnetOnly, PerFamily::new(false, false))
        .expect("plan");
    let policy = dns_policy(twinvpn_dns::Mode::Split, true);
    let contract = rig
        .contract(&plan, &policy, stub_addresses(), Ruleset::Blocked)
        .expect("assemble");
    rig.apply(&contract);

    rig.adapter.begin_shutdown();

    let installed = block_on(rig.adapter.network_config().installed_ruleset()).expect("read back");
    assert_eq!(
        installed,
        Some(Ruleset::Blocked),
        "shutting the core down dropped the installed ruleset; CB-6 says the OS \
         keeps custody so the core going away cannot drop protection"
    );
    assert!(
        rig.adapter
            .network_config()
            .enforcement_custody()
            .survives_core_exit
    );
}

#[test]
fn a_target_whose_rules_die_with_the_process_reports_that_rather_than_hiding_it() {
    // The negative control for the test above: the mock can model a target
    // WITHOUT durable custody, and the enforcement layer must classify it
    // differently rather than reporting the same posture.
    let weak = MockAdapter::new(&MockOptions {
        enforcement_survives_core_exit: false,
        ..MockOptions::default()
    });
    // `boot_enforcement_available` is no longer a field: it is DERIVED from the
    // custody's `boot_enforcement`, which is four-valued so that Windows'
    // "the OS holds it from power-on" and macOS' "Recovery and safe boot do not
    // load the LaunchDaemon" stop collapsing onto one bool.
    let posture = twinvpn_enforce::latch::DurabilityPosture {
        custody: weak.network_config().enforcement_custody(),
    };
    assert!(
        !posture.survives_core_exit(),
        "a target without durable custody must not report that it has it"
    );
    assert!(
        posture.requires_disclosure(),
        "ADR-0012: a target whose rules die with the process must disclose it"
    );
}

// ---------------------------------------------------------------------------
// The latch, driven by a plan the route planner produced.
// ---------------------------------------------------------------------------

#[test]
fn the_latch_leaves_blocked_only_when_the_real_plan_covers_both_families() {
    for family in HostFamily::ALL {
        let mut rig = Rig::new(family, 9);
        let plan = rig
            .route_plan(RoutingMode::TwinnetOnly, PerFamily::new(false, false))
            .expect("plan");
        assert_eq!(
            rig.latch.desired(),
            Ruleset::Blocked,
            "KS-19: starts blocked"
        );

        rig.latch.set_intended_up(true);
        // Not yet validated: the swap must be refused.
        assert_eq!(
            rig.latch.leave_blocked(preconditions(&plan, false)),
            Ruleset::Blocked,
            "{}: the latch left BLOCKED without a validated path",
            family.name()
        );
        // Validated, and the plan covers both families.
        assert_eq!(
            rig.latch.leave_blocked(preconditions(&plan, true)),
            Ruleset::Protected,
            "{}: the latch refused a fully covered, validated path",
            family.name()
        );
    }
}

// ---------------------------------------------------------------------------
// The state machine meeting the enforcement mode.
// ---------------------------------------------------------------------------

#[test]
fn a_policy_violation_beats_everything_and_lands_in_blocked_with_a_code() {
    // §4.3: "EV_POLICY_VIOLATION{kind}. Always wins; always → BLOCKED." Asserted
    // from an Established session that the full pipeline produced, and paired
    // with the requirement that BLOCKED carries a reason code.
    let mut rig = Rig::new(HostFamily::Dual, 10);
    rig.establish(PathClass::WanDirect);
    let guards = Guards {
        enforcement: Some(EnforcementMode::FailClosed),
        ..Guards::default()
    };
    rig.session.apply(
        Trigger::Event(Event::PolicyViolation(
            twinvpn_session::PolicyViolationKind::DnsQueryOffTunnel,
        )),
        guards,
        SessionContext::default(),
    );
    assert_eq!(rig.session.state(), SessionState::Blocked);
    let reason = rig
        .session
        .reason()
        .expect("BLOCKED without a reason code is the silent failure §10.1 forbids");
    assert!(
        reason.as_str().starts_with("POLICY.") || reason.as_str().starts_with("DNS."),
        "a DNS-off-tunnel violation reported `{}`",
        reason.as_str()
    );
}

#[test]
fn fail_closed_is_the_disposition_whenever_the_enforcement_mode_is_unset() {
    // `Guards::fail_closed` reads `None` as fail-closed. Asserted here rather
    // than only in the session crate because the *consumer* of that reading is
    // `twinvpn-enforce`, and the two must agree about what "we were not told"
    // means.
    let unset = Guards::default();
    assert!(
        unset.fail_closed(),
        "an unset enforcement mode must read as fail-closed"
    );
    assert_eq!(
        SessionState::Blocked.disposition(unset.fail_closed()),
        twinvpn_types::TrafficDisposition::DroppedFailClosed
    );
    let permissive = Guards {
        enforcement: Some(EnforcementMode::PermissiveAnnounced),
        ..Guards::default()
    };
    assert!(
        !permissive.fail_closed(),
        "the negative control: an explicitly permissive mode is not fail-closed"
    );
}
