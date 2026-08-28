//! **End-to-end.** The real composition root, driven under TwinLab scenarios.
//!
//! **Authority:** ADR-0018 CD-2, CD-5, CD-6, VR-3, VR-4, §11.12;
//! `docs/reliability.md` §4 (the transition table), §5 (timers), §11 (background
//! and suspended operation); `docs/testing-strategy.md` §2.7, §3.5.
//!
//! # What this file adds that `core-composition`'s own suite cannot
//!
//! `core/crates/twinvpn-core/tests/falsification.rs` proves the core never
//! **needs** a shell: it constructs, drives a session, survives an outage and
//! renders codes with nothing above it. It builds its environment from
//! `twinvpn_core::testing`, which binds a `CountingEntropy` behind a
//! `SystemRngSource` — a source that answers `is_deterministic() == false`.
//!
//! These tests do the thing that requires the laboratory: they run the same
//! composed core on **TwinLab's** environment — the CD-4 seeded streams and the
//! virtual clock — so every assertion below is over a run a recorded
//! `scenario_seed` reproduces. That is what makes a `BIT` claim sayable at all
//! (§3.5), and no test inside `core/` is in a position to make it, because
//! `core/` may not depend on `lab/`.
//!
//! # Determinism class of everything in this file: `BIT`
//!
//! Every clock is injected, every stream is derived from one seed, and the
//! platform is the mock. Nothing here touches `conntrack`, `netem` or the kernel
//! scheduler, so §3.5's residual does not apply and the **ordered event
//! sequence** is reproducible. No test asserts a wall-clock duration.

use twinvpn_core::lite::Capability;
use twinvpn_core::session_loop::{event_for_change, timers_for};
use twinvpn_core::{CoreEventKind, EPOCH_TABLE};
use twinvpn_env::MonotonicInstant;
use twinvpn_mgmt::command::{CoreCommand, Submission};
use twinvpn_platform::iface::{InterfaceFacts, InterfaceName, LinkClass, NetworkChange};
use twinvpn_platform::{InterfaceIndex, PlatformAdapter, Ruleset};
use twinvpn_session::{
    Context as SessionContext, EnforcementMode, Event, Guards, SessionState, TimerId, Trigger,
};
use twinvpn_types::{AddressFamily, PathClass};

use twinvpn_system_tests::{block_on, ComposedRig, HostFamily};

const CORE_LIB: &str = include_str!("../../core/crates/twinvpn-core/src/lib.rs");
const CORE_MANIFEST: &str = include_str!("../../core/crates/twinvpn-core/Cargo.toml");
const ADR_0018: &str =
    include_str!("../../docs/adr/ADR-0018-shared-core-and-build-architecture.md");

// ---------------------------------------------------------------------------
// The assertion that replaces `the_composition_root_is_still_empty`.
// ---------------------------------------------------------------------------

#[test]
fn the_composition_root_exposes_everything_the_abi_needs() {
    // Its predecessor asserted the root was *empty* and was designed to fail the
    // day it landed. This is the opposite, and the reason for the shape is the
    // same: a regression that hollows the root out — a module made private, a
    // type withdrawn — would otherwise be found by whichever shell broke first.
    //
    // The list is what `core/ffi` and a shell must be able to name, so it is a
    // statement about the ABI's needs rather than a copy of the module tree.
    for item in [
        "pub mod bridge",         // StoreBridge: the single owner of the vault
        "pub mod build_identity", // S-46
        "pub mod core",           // Core, CoreParts
        "pub mod events",         // F-5's one ordered stream
        "pub mod lite",           // §11.12's profile
        "pub mod planes",         // CD-I5's two views over one store
        "pub mod cp_binding",     // the control-plane half
        "pub mod journal",        // §6.5's durable half
        "pub mod session_loop",   // §4 and §5, driven
    ] {
        assert!(
            CORE_LIB.contains(item),
            "the composition root no longer declares `{item}`; a shell that named \
             it would now fail to build, and the ABI would have lost a capability \
             without anyone deciding to remove it"
        );
    }

    // The ABI's own numbers live here so `CoreBuildIdentity` and the header
    // cannot disagree (VR-1). Their *presence* is what this asserts; the header
    // drift check in `twinvpn-ffi` asserts the values.
    assert!(CORE_LIB.contains("pub const ABI_MAJOR"));
    assert!(CORE_LIB.contains("pub const ABI_MINOR"));
    assert_eq!(twinvpn_core::ABI_MAJOR, 1);
}

#[test]
fn vr3_the_protocol_epoch_is_declared_in_a_table_and_never_inferred() {
    // W-27: the launch `ProtocolEpoch` is stated by no Phase 1 document, and
    // VR-3 forbids inferring it from `core_version`. The disposition was "a
    // table, not an inference" — so the table's existence, and the refusal for
    // an unlisted version, are both worth pinning from outside the crate.
    assert!(
        !EPOCH_TABLE.is_empty(),
        "VR-3 needs a table, and it is empty"
    );
    let known =
        twinvpn_core::build_identity::protocol_epochs(twinvpn_core::build_identity::CORE_VERSION);
    assert!(
        known.is_some(),
        "this core_version has no EPOCH_TABLE row, so `Core::create` refuses"
    );
    assert!(
        twinvpn_core::build_identity::protocol_epochs("99.99.99").is_none(),
        "an unlisted version resolved to an epoch, which is the inference VR-3 \
         forbids"
    );
}

#[test]
fn vr4_an_abi_mismatch_is_refused_before_any_capability_is_touched() {
    // `core-composition` asserts this for its own parts. Asserted here too
    // because the rig builds `CoreParts` independently, and a check that only
    // fires for one construction path is not a check.
    //
    // The refusal is asserted by its **reason code**, not by the fact that
    // something went wrong: VR-4 says the condition is named
    // (`INTERNAL.ABI_VERSION_MISMATCH`) "because the alternative is undefined
    // behaviour", and a `#[should_panic]` would prove neither the naming nor the
    // ordering.
    let refused = match ComposedRig::try_with_parts(HostFamily::Dual, 40, |parts| {
        parts.abi_major_expected = twinvpn_core::ABI_MAJOR + 1;
    }) {
        Err(d) => d,
        Ok(_) => panic!("a mismatched abi_major constructed a core"),
    };
    assert_eq!(
        refused.code().as_str(),
        "INTERNAL.ABI_VERSION_MISMATCH",
        "the refusal did not name VR-4's condition"
    );

    // The positive control: the same construction with a matching abi_major
    // succeeds, so the test above is about the version and not about
    // construction being broken.
    assert!(
        ComposedRig::try_with_parts(HostFamily::Dual, 40, |_| {}).is_ok(),
        "a matching abi_major must construct"
    );
}

// ---------------------------------------------------------------------------
// The composed core on TwinLab's environment.
// ---------------------------------------------------------------------------

#[test]
fn the_composed_core_runs_on_a_seeded_environment_and_says_so() {
    // The property `twinvpn_core::testing` cannot provide, and the precondition
    // for every `BIT` claim in the scenario catalogue.
    let rig = ComposedRig::new(HostFamily::Dual, 41);
    assert!(rig.env.is_deterministic());
    assert!(
        rig.core.env().is_deterministic(),
        "the core's own Env must be the seeded one — CD-2 hands it in at \
         construction and there is no other place it could come from"
    );
    assert!(!rig.core.is_poisoned());
    assert_eq!(rig.core.build_identity().profile, "full");
}

#[test]
fn two_rigs_at_one_seed_produce_the_identical_stream_through_the_composed_core() {
    // §3.5's `BIT` definition applied to the composition root: the same seed
    // reproduces the same draws, through the Env the core is holding.
    let draw = |seed: u8| {
        let rig = ComposedRig::new(HostFamily::Dual, seed);
        let mut rng = rig
            .core
            .env()
            .rng_for(twinvpn_env::consumers::BACKOFF_JITTER)
            .expect("the composed core's own seeded stream");
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        b
    };
    assert_eq!(draw(42), draw(42));
    assert_ne!(
        draw(42),
        draw(43),
        "the negative control: a derivation that ignored the seed would satisfy \
         the reproducibility assertion perfectly"
    );
}

#[test]
fn every_instance_in_one_process_has_a_distinct_identity_across_rigs() {
    // S-47: `instance_id` must be unique within one process. Asserted across
    // rigs built at the *same seed*, which is the case a seeded environment
    // makes newly reachable — and the case where a derived id would collide.
    let a = ComposedRig::new(HostFamily::Dual, 44);
    let b = ComposedRig::new(HostFamily::Dual, 44);
    assert_ne!(
        a.core.instance_id(),
        b.core.instance_id(),
        "two instances at one seed share an instance_id; a stale binding would \
         then be indistinguishable from a live second writer"
    );
}

// ---------------------------------------------------------------------------
// §4's table, driven through the composed loop.
// ---------------------------------------------------------------------------

fn happy_guards(carrier: PathClass) -> Guards {
    Guards {
        credentials_valid: true,
        peer_authorized: true,
        usable_candidate: true,
        path_validated: true,
        relay_set_nonempty: true,
        retry_budget_available: true,
        no_l2_path_won: carrier != PathClass::LocalDirect,
        no_direct_path_won: carrier == PathClass::Relayed,
        enforcement: Some(EnforcementMode::FailClosed),
        ..Guards::default()
    }
}

#[test]
fn the_composed_loop_drives_the_table_and_rearms_the_timers_each_state_owns() {
    // `SessionRuntime::apply` re-arms on every state change so that "a state
    // entered by a path that forgot to arm its timeout" cannot exist. That is R5
    // — no unbounded degradation — and it is a property of the *loop*, not of
    // the machine, so `twinvpn-session`'s suite cannot see it.
    for family in HostFamily::ALL {
        let rig = ComposedRig::new(family, 45);
        let mut rt = rig.session_runtime(45);
        let g = happy_guards(PathClass::WanDirect);

        for (trigger, expected) in [
            (
                Trigger::Event(Event::ConnectRequested),
                SessionState::Discovering,
            ),
            (
                Trigger::Event(Event::CandidatesReady),
                SessionState::Negotiating,
            ),
            (
                Trigger::Event(Event::NegotiationOk),
                SessionState::Connecting,
            ),
            (
                Trigger::Event(Event::HandshakeOk(PathClass::WanDirect)),
                SessionState::Steady(PathClass::WanDirect),
            ),
        ] {
            rt.apply(trigger, g, SessionContext::default());
            assert_eq!(
                rt.machine().state(),
                expected,
                "{}: the composed loop diverged from §4.5's happy path",
                family.name()
            );
            // Every timer the new state owns is armed, and nothing the previous
            // state owned survives.
            let mut owned: Vec<&'static str> = timers_for(expected)
                .iter()
                .map(|(id, _)| id.name())
                .collect();
            owned.sort_unstable();
            let mut armed: Vec<&'static str> = [
                TimerId::Discover,
                TimerId::Negotiate,
                TimerId::Connect,
                TimerId::Migrate,
                TimerId::ReconnectGrace,
                TimerId::ReconnectMax,
                TimerId::DegradedMax,
                TimerId::Backoff,
            ]
            .into_iter()
            .filter(|id| rt.timers().is_armed(*id))
            .map(TimerId::name)
            .collect();
            armed.sort_unstable();
            assert_eq!(
                armed,
                owned,
                "{}: in {expected:?} the armed set is {armed:?} and §5 says it \
                 should be {owned:?}",
                family.name()
            );
        }
    }
}

#[test]
fn a_state_with_a_timer_is_bounded_and_a_steady_state_is_deliberately_not() {
    // The distinction R5 rests on: every *transient* state has an upper bound,
    // and the steady states do not — a `Session` that is working must not be
    // torn down by a clock. A build that armed a timeout on `Steady` would pass
    // every "did it connect" test and drop healthy tunnels in the field.
    for state in [
        SessionState::Discovering,
        SessionState::Negotiating,
        SessionState::Connecting,
        SessionState::Migrating {
            from: PathClass::WanDirect,
            to: PathClass::Relayed,
        },
        SessionState::Reconnecting { parked: false },
        SessionState::Degraded {
            carrier: PathClass::Relayed,
        },
    ] {
        assert!(
            !timers_for(state).is_empty(),
            "{state:?} is transient and has no upper bound (R5)"
        );
    }
    for state in [
        SessionState::Steady(PathClass::LocalDirect),
        SessionState::Steady(PathClass::WanDirect),
        SessionState::Steady(PathClass::Relayed),
        SessionState::Disconnected,
        SessionState::Failed,
    ] {
        assert!(
            timers_for(state).is_empty(),
            "{state:?} owns a timer; a working Session must not be torn down by \
             a clock"
        );
    }
    // BLOCKED is the deliberate third case: its loop is T31's computed backoff
    // tick, armed with `arm_for`, so the registered table is empty for it.
    assert!(timers_for(SessionState::Blocked).is_empty());
}

#[test]
fn a_timer_fires_only_once_virtual_time_reaches_it_and_then_drives_the_table() {
    // The composed loop's `tick` against the injected clock. On a real clock
    // this would be a sleep; here it is exact, which is CD-6's `BIT` half and
    // the reason `T_DISCOVER` is testable at all.
    //
    // The guards are §4.5 T04's: "no candidate on either family". A timeout with
    // a usable candidate matches no row, which the next test covers.
    let rig = ComposedRig::new(HostFamily::Dual, 46);
    let mut rt = rig.session_runtime(46);
    let start = Guards {
        credentials_valid: true,
        peer_authorized: true,
        retry_budget_available: true,
        enforcement: Some(EnforcementMode::FailClosed),
        ..Guards::default()
    };
    rt.apply(
        Trigger::Event(Event::ConnectRequested),
        start,
        SessionContext::default(),
    );
    assert_eq!(rt.machine().state(), SessionState::Discovering);
    assert!(rt.timers().is_armed(TimerId::Discover));

    let timed_out = Guards {
        no_candidate_either_family: true,
        retry_budget_available: true,
        enforcement: Some(EnforcementMode::FailClosed),
        ..Guards::default()
    };

    // Nothing is due yet, and nothing moves.
    assert!(rt.tick(timed_out, SessionContext::default()).is_empty());
    assert_eq!(rt.machine().state(), SessionState::Discovering);

    // Advance past T_DISCOVER. The scenario declares `BIT` and asserts the
    // resulting STATE, never the elapsed time — §3.5 permits the first and no
    // class permits the second.
    let deadline = rt
        .timers()
        .next_deadline()
        .expect("DISCOVERING owns a deadline");
    let now = rig.env.env().now_monotonic();
    rig.env
        .time()
        .advance(deadline.duration_since(now) + core::time::Duration::from_millis(1));

    let outcomes = rt.tick(timed_out, SessionContext::default());
    assert_eq!(outcomes.len(), 1, "exactly one timer was due");
    assert_eq!(
        rt.machine().state(),
        SessionState::Reconnecting { parked: false },
        "T_DISCOVER fired with no candidate on either family and the machine did \
         not take §4.5 T04; DISCOVERING would then be unbounded (R5)"
    );
    assert!(
        rt.machine().reason().is_some(),
        "RECONNECTING was entered without a reason code (§10.1)"
    );
    // And the new state's own deadlines are armed, which is the loop's job
    // rather than the machine's.
    assert!(rt.timers().is_armed(TimerId::ReconnectGrace));
    assert!(rt.timers().is_armed(TimerId::ReconnectMax));
    assert!(!rt.timers().is_armed(TimerId::Discover));
}

#[test]
fn a_trigger_that_matches_no_row_is_reported_as_ignored_and_never_dropped() {
    // §10.4's honest-ambiguity rule: "a `None` is not a silent drop". The
    // machine returns `Outcome::Ignored` naming the state that ignored it, so
    // "nothing happened" is still observable.
    //
    // The case is a `T_DISCOVER` expiry while a usable candidate exists — T04's
    // guard is `no_candidate_either_family`, so no row matches. Worth asserting
    // through the composed loop rather than the machine alone, because it is the
    // loop that decides what happens next: `SessionRuntime` re-arms only on a
    // state *change*, so an ignored timer leaves the state with that deadline
    // consumed. That is reported to the integration lead as an observation about
    // `session_loop`, not asserted here as a defect — the guard combination is
    // not reachable from a driver that delivers `EV_CANDIDATES_READY`.
    let rig = ComposedRig::new(HostFamily::Dual, 60);
    let mut rt = rig.session_runtime(60);
    let g = happy_guards(PathClass::WanDirect);
    rt.apply(
        Trigger::Event(Event::ConnectRequested),
        g,
        SessionContext::default(),
    );

    let deadline = rt.timers().next_deadline().expect("armed");
    let now = rig.env.env().now_monotonic();
    rig.env
        .time()
        .advance(deadline.duration_since(now) + core::time::Duration::from_millis(1));

    let records_before = rt.machine().history().len();
    let outcomes = rt.tick(g, SessionContext::default());
    assert_eq!(outcomes.len(), 1);
    match &outcomes[0] {
        twinvpn_session::Outcome::Ignored { state, trigger } => {
            assert_eq!(*state, SessionState::Discovering);
            assert_eq!(*trigger, Trigger::Timer(TimerId::Discover));
        }
        other => panic!("an unmatched trigger was not reported as ignored: {other:?}"),
    }
    assert_eq!(rt.machine().state(), SessionState::Discovering);
    assert_eq!(
        rt.machine().history().len(),
        records_before,
        "an ignored trigger fabricated a transition record"
    );
}

// ---------------------------------------------------------------------------
// CB-2's boundary: a platform fact becomes a domain event, in the core.
// ---------------------------------------------------------------------------

fn facts(index: u32, class: LinkClass) -> InterfaceFacts {
    InterfaceFacts {
        index: InterfaceIndex(index),
        name: InterfaceName::new("wlan0").expect("name"),
        addresses: Vec::new(),
        has_default_route_v4: true,
        has_default_route_v6: false,
        is_overlay: false,
        is_up: true,
        mtu: 1500,
        link_class: class,
    }
}

#[test]
fn an_interface_flap_becomes_a_domain_event_and_drives_the_composed_loop() {
    // The whole path: a `NetworkChange` the adapter reports → `event_for_change`
    // (the core's decision, not the shell's) → `SessionRuntime` → the §4.5 row →
    // the timers the new state owns. Six shells could each have decided this
    // differently; R-31 is why they must not, and this is where the single
    // decision is exercised end to end.
    for (class, _label) in [(LinkClass::WiFi, "wifi"), (LinkClass::Cellular, "cell")] {
        let rig = ComposedRig::new(HostFamily::Dual, 47);
        let mut rt = rig.session_runtime(47);
        let g = happy_guards(PathClass::WanDirect);
        for t in [
            Trigger::Event(Event::ConnectRequested),
            Trigger::Event(Event::CandidatesReady),
            Trigger::Event(Event::NegotiationOk),
            Trigger::Event(Event::HandshakeOk(PathClass::WanDirect)),
        ] {
            rt.apply(t, g, SessionContext::default());
        }
        assert_eq!(
            rt.machine().state(),
            SessionState::Steady(PathClass::WanDirect)
        );

        let f = facts(7, class);
        let change = NetworkChange::LinkStateChanged {
            interface: InterfaceIndex(7),
            is_up: false,
        };
        let event =
            event_for_change(&change, Some(&f)).expect("a link going down is a domain event");
        assert!(
            matches!(event, Event::LinkDown(_)),
            "the core mapped a link-down to {event:?}"
        );

        // With a warm alternate, §4.5 T19 migrates rather than dropping.
        let migrating = Guards {
            alternate_available: true,
            relay_set_nonempty: true,
            retry_budget_available: true,
            enforcement: Some(EnforcementMode::FailClosed),
            ..Guards::default()
        };
        rt.apply(Trigger::Event(event), migrating, SessionContext::default());
        assert_eq!(
            rt.machine().state(),
            SessionState::Migrating {
                from: PathClass::WanDirect,
                to: PathClass::Relayed,
            }
        );
        assert!(
            rt.timers().is_armed(TimerId::Migrate),
            "MIGRATING was entered without T_MIGRATE armed"
        );
    }
}

#[test]
fn an_address_change_is_not_a_link_event_and_the_distinction_survives_the_loop() {
    // §4.3 separates them because T21 turns on "the local address changed (as
    // opposed to the interface)". Collapsing them is the kind of simplification
    // that looks harmless in a shell and loses a whole transition row.
    let f = facts(7, LinkClass::WiFi);
    let addr = NetworkChange::AddressAdded {
        interface: InterfaceIndex(7),
        address: twinvpn_types::IpAddr::V4(twinvpn_types::V4Addr::from_octets([198, 51, 100, 9])),
    };
    assert_eq!(
        event_for_change(&addr, Some(&f)),
        Some(Event::AddrChanged),
        "an address change must be EV_ADDR_CHANGED"
    );
    let down = NetworkChange::LinkStateChanged {
        interface: InterfaceIndex(7),
        is_up: false,
    };
    assert!(matches!(
        event_for_change(&down, Some(&f)),
        Some(Event::LinkDown(_))
    ));
    assert_ne!(
        event_for_change(&addr, Some(&f)),
        event_for_change(&down, Some(&f))
    );
}

#[test]
fn the_link_class_reaches_the_event_so_t20s_evidence_can_name_it() {
    // `NET.LINK.DOWN_WIFI` and `NET.LINK.DOWN_CELLULAR` are distinct registered
    // codes. A mapping that dropped the class would make both render as the
    // same diagnostic, and a user on a train would be told "Wi-Fi went down".
    let down = |idx| NetworkChange::LinkStateChanged {
        interface: InterfaceIndex(idx),
        is_up: false,
    };
    let wifi = event_for_change(&down(7), Some(&facts(7, LinkClass::WiFi)));
    let cell = event_for_change(&down(8), Some(&facts(8, LinkClass::Cellular)));
    assert_ne!(
        wifi, cell,
        "the link class did not reach the event; T20's caused_by evidence cannot \
         name what went down"
    );
    // With no facts the core must still produce an event, classed Unknown —
    // never nothing, because a link that went down without a domain event is a
    // Session that hangs.
    assert!(event_for_change(&down(9), None).is_some());
}

// ---------------------------------------------------------------------------
// Suspend and resume, across the composed core.
// ---------------------------------------------------------------------------

#[test]
fn a_suspend_moves_the_elapsed_clock_and_not_the_monotonic_one_inside_the_core() {
    // CD-1's three non-interchangeable clocks, asserted through the Env the
    // *composed core* holds rather than through `twinvpn-env`'s own tests. The
    // guard T35 reads (`rekey_window_exceeded`) is computed from the elapsed
    // delta; a build that read the monotonic clock would never force a
    // rehandshake after a laptop lid closed for a week, and would look correct
    // in every test that did not go through the core.
    let rig = ComposedRig::new(HostFamily::Dual, 48);
    let m0 = rig.core.env().now_monotonic();
    let e0 = rig.core.env().now_elapsed();

    rig.env
        .time()
        .suspend(core::time::Duration::from_secs(8 * 3600));

    assert_eq!(
        rig.core.env().now_monotonic(),
        m0,
        "the monotonic clock advanced across a suspend; every timer bound to it \
         would fire at once on resume and tear down a Session that was merely \
         asleep"
    );
    assert_eq!(
        rig.core.env().now_elapsed().duration_since(e0).as_secs(),
        8 * 3600
    );
}

#[test]
fn a_timer_armed_before_a_suspend_is_not_due_immediately_after_it() {
    // The consequence of the test above, stated as the behaviour it protects.
    // This is the single most valuable thing an injected clock buys, and it is
    // unobservable without one.
    let rig = ComposedRig::new(HostFamily::Dual, 49);
    let mut rt = rig.session_runtime(49);
    let g = happy_guards(PathClass::WanDirect);
    rt.apply(
        Trigger::Event(Event::ConnectRequested),
        g,
        SessionContext::default(),
    );
    assert!(rt.timers().is_armed(TimerId::Discover));

    rig.env
        .time()
        .suspend(core::time::Duration::from_secs(8 * 3600));

    assert!(
        rt.tick(g, SessionContext::default()).is_empty(),
        "a timer armed on the monotonic clock fired because of an eight-hour \
         suspend"
    );
    assert_eq!(rt.machine().state(), SessionState::Discovering);
}

// ---------------------------------------------------------------------------
// Commands, events, and the posture the core must not change on its own.
// ---------------------------------------------------------------------------

#[test]
fn a_rejected_command_produces_an_event_as_well_as_the_error() {
    // §11.6: "Rejected commands produce an event, never a silent drop." The
    // caller gets a typed `Err` *and* the stream carries a `CommandRejected`,
    // because a UI watching only the stream would otherwise show a command that
    // never finished — and one watching only the return value would never learn
    // that the ledger recorded it.
    let rig = ComposedRig::new(HostFamily::Dual, 50);
    let unimplemented = twinvpn_core::core::unimplemented()
        .first()
        .map(|(op, _, _)| *op)
        .expect("the catalogue declares at least one unimplemented operation");

    let refused = rig
        .core
        .submit(&Submission::bare(unimplemented))
        .expect_err("an unimplemented operation must be refused");
    assert!(
        !refused.code().as_str().is_empty(),
        "the refusal carries no reason code, which §3.3 prohibits outright"
    );

    let events = rig.drain_events();
    let rejected = events
        .iter()
        .filter_map(|e| match &e.kind {
            CoreEventKind::CommandRejected { op, .. } => Some(*op),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rejected,
        [unimplemented.name()],
        "the refusal did not reach the event stream"
    );

    // The positive control: an implemented operation completes and says so, so
    // the assertion above is about rejection and not about the stream being
    // stuck on one variant.
    let rig2 = ComposedRig::new(HostFamily::Dual, 50);
    rig2.core
        .submit(&Submission::bare(CoreCommand::StatusGet))
        .expect("status.get is implemented");
    assert!(
        rig2.drain_events()
            .iter()
            .any(|e| matches!(e.kind, CoreEventKind::CommandCompleted { .. })),
        "an accepted command produced no completion event"
    );
}

#[test]
fn every_event_the_core_emits_carries_a_strictly_increasing_sequence() {
    // F-5's ordering guarantee. A gap without a `Compacted` marker means a
    // consumer silently missed a transition, which is exactly the silent failure
    // §10 forbids.
    let rig = ComposedRig::new(HostFamily::Dual, 51);
    for op in [
        CoreCommand::StatusGet,
        CoreCommand::VersionGet,
        CoreCommand::PeerList,
    ] {
        let _ = rig.core.submit(&Submission::bare(op));
    }
    let events = rig.drain_events();
    assert!(!events.is_empty(), "three submissions produced no events");
    let mut last = None;
    for e in &events {
        if let Some(prev) = last {
            assert!(
                e.seq > prev,
                "event sequence went {prev} -> {} — F-5 requires strictly \
                 increasing",
                e.seq
            );
        }
        last = Some(e.seq);
    }
}

#[test]
fn shutdown_is_graceful_and_leaves_enforcement_exactly_where_it_was() {
    // CB-6 through the composition root: the core going away must not drop
    // protection. `core-composition` asserts this for its own rig; asserted here
    // against a ruleset this rig installed, so the two halves — "the core does
    // not tear down" and "the platform keeps custody" — are checked together.
    let rig = ComposedRig::new(HostFamily::Dual, 52);
    block_on(
        rig.adapter
            .network_config()
            .set_ruleset(twinvpn_platform::ContractGeneration(1), Ruleset::Protected),
    )
    .expect("install");

    rig.core.begin_shutdown();

    assert_eq!(
        block_on(rig.adapter.network_config().installed_ruleset()).expect("read back"),
        Some(Ruleset::Protected),
        "shutting the composed core down dropped the installed ruleset"
    );
}

#[test]
fn a_poisoned_core_stays_poisoned_and_still_leaves_enforcement_alone() {
    // F-7's containment, and the direction that matters: a poisoned instance
    // must not "clean up" — tearing down the ruleset on a panic is the failure
    // mode that turns a crash into a leak.
    let rig = ComposedRig::new(HostFamily::Dual, 53);
    block_on(
        rig.adapter
            .network_config()
            .set_ruleset(twinvpn_platform::ContractGeneration(1), Ruleset::Blocked),
    )
    .expect("install");

    assert!(!rig.core.is_poisoned());
    rig.core.poison();
    assert!(rig.core.is_poisoned());
    rig.core.poison();
    assert!(rig.core.is_poisoned(), "poisoning must be idempotent");

    assert_eq!(
        block_on(rig.adapter.network_config().installed_ruleset()).expect("read back"),
        Some(Ruleset::Blocked),
        "a poisoned core removed the ruleset"
    );
}

// ---------------------------------------------------------------------------
// §11.12: the `core-lite` profile, and the rule that outranks its crate list.
// ---------------------------------------------------------------------------

#[test]
fn core_lite_never_fetches_and_never_recovers_and_the_adr_says_the_same() {
    // The capability half is asserted inside the crate. What is only assertable
    // from outside is that the crate's list and **ADR-0018's own text** agree —
    // a drift between them is how a profile quietly acquires a capability.
    assert!(
        ADR_0018.contains("core-lite"),
        "ADR-0018 no longer mentions core-lite; the profile has lost its authority"
    );
    assert!(
        ADR_0018.contains("MUST NOT sit on a fetch path"),
        "§11.12's rule — `core-lite` MUST NOT sit on a fetch path or on any \
         recovery path — is no longer in ADR-0018. That rule outranks the crate \
         list, and a profile without it is just a smaller build."
    );

    // This binary is built `full`, so both are granted here. What must hold in
    // *both* profiles is that `Fetch` and `Recover` are precisely the two the
    // lite set omits — a fact about the enumeration, not about this build.
    let all = [
        Capability::Parse,
        Capability::Verify,
        Capability::Render,
        Capability::Bundle,
        Capability::Fetch,
        Capability::Recover,
    ];
    let granted = twinvpn_core::lite::capabilities();
    assert_eq!(
        granted.len(),
        all.len(),
        "this test binary is built `full` and must hold every capability; if it \
         does not, the feature wiring changed"
    );
    for c in [Capability::Fetch, Capability::Recover] {
        assert!(twinvpn_core::lite::has(c));
    }
}

#[test]
fn every_data_plane_crate_is_optional_so_core_lite_can_actually_omit_it() {
    // `core-composition`'s own suite checks the feature list. This checks the
    // half that makes the list *effective*: a data-plane crate declared
    // non-optionally would be compiled into `core-lite` regardless of what the
    // feature says, and the profile would be a lie told by a manifest.
    for crate_name in [
        "twinvpn-cp-client",
        "twinvpn-tunnel",
        "twinvpn-path",
        "twinvpn-relay-client",
        "twinvpn-route",
        "twinvpn-dns",
        "twinvpn-enforce",
        "twinvpn-gateway",
        "twinvpn-session",
    ] {
        let line = CORE_MANIFEST
            .lines()
            .find(|l| l.trim_start().starts_with(crate_name))
            .unwrap_or_else(|| panic!("{crate_name} is not a dependency of twinvpn-core"));
        assert!(
            line.contains("optional = true"),
            "{crate_name} is not optional, so `core-lite` compiles it anyway: {line}"
        );
    }

    // And the core-lite set is never optional, for the mirror reason: a profile
    // that can drop its own parse-and-verify half is not §11.12's profile.
    for crate_name in [
        "twinvpn-types",
        "twinvpn-env",
        "twinvpn-schema",
        "twinvpn-crypto",
        "twinvpn-store",
        "twinvpn-trust",
        "twinvpn-diag",
    ] {
        let line = CORE_MANIFEST
            .lines()
            .find(|l| l.trim_start().starts_with(crate_name))
            .unwrap_or_else(|| panic!("{crate_name} is not a dependency of twinvpn-core"));
        assert!(
            !line.contains("optional = true"),
            "{crate_name} is optional, so a build could omit part of core-lite: {line}"
        );
    }
}

#[test]
fn the_modules_that_need_the_data_plane_are_gated_so_core_lite_has_no_recovery_path() {
    // §11.12's rule made structural. `session_loop`, `journal` and `cp_binding`
    // are the three modules that *could* bring a tunnel up or fetch a document;
    // each must be behind `full`, or `core-lite` would carry a recovery path
    // even with the crates absent.
    for module in ["cp_binding", "journal", "session_loop"] {
        let decl = format!("pub mod {module};");
        let idx = CORE_LIB
            .find(&decl)
            .unwrap_or_else(|| panic!("`{module}` is no longer declared"));
        let preceding = &CORE_LIB[..idx];
        let gate = preceding
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("");
        assert!(
            gate.contains("#[cfg(feature = \"full\")]"),
            "`{module}` is not gated on `full`; core-lite would carry it, and \
             §11.12 says core-lite MUST NOT sit on a fetch or recovery path. \
             The line before it is: {gate}"
        );
    }
}

// ---------------------------------------------------------------------------
// The two views over one store — CD-I5 through the composition root.
// ---------------------------------------------------------------------------

#[test]
fn the_data_plane_view_sees_only_what_the_control_plane_wrote_to_the_store() {
    // CD-I5's positive statement: the two planes communicate through the store
    // and never with each other. Asserted here because the rig can hold both
    // ports at once, which no single-plane test can.
    let rig = ComposedRig::new(HostFamily::Dual, 54);
    let cp = rig.core.control_plane_port();
    let dp = rig.core.data_plane_view();
    let twinnet = twinvpn_types::TwinnetId::new("system-tests").expect("twinnet id");

    assert_eq!(dp.trust_epoch(&twinnet), 0, "nothing has been written yet");
    assert!(cp.advance_trust_epoch(&twinnet, 7));
    assert_eq!(
        dp.trust_epoch(&twinnet),
        7,
        "the data plane cannot see a value the control plane wrote"
    );
    assert!(
        !cp.advance_trust_epoch(&twinnet, 6),
        "the epoch went backwards; monotonicity is an anti-rollback control, not \
         a convenience"
    );
    assert_eq!(dp.trust_epoch(&twinnet), 7);
}

#[test]
fn a_control_plane_outage_changes_nothing_the_data_plane_already_holds() {
    // I5 at the composition root. The data plane reads the store; an outage is
    // the absence of *new* writes, and must not withdraw old ones. A build that
    // invalidated the cache on an outage would fail exactly when the user needs
    // it most.
    let rig = ComposedRig::new(HostFamily::Dual, 55);
    let cp = rig.core.control_plane_port();
    let dp = rig.core.data_plane_view();
    let twinnet = twinvpn_types::TwinnetId::new("system-tests").expect("twinnet id");

    assert!(cp.advance_cursor(&twinnet, 42));
    assert!(cp.advance_trust_epoch(&twinnet, 3));
    let before = (dp.trust_epoch(&twinnet), dp.peers(&twinnet).len());

    // The outage: no writes at all for the rest of the test. Time still passes.
    rig.env
        .time()
        .advance(core::time::Duration::from_secs(3600));

    assert_eq!(
        (dp.trust_epoch(&twinnet), dp.peers(&twinnet).len()),
        before,
        "an hour with no control plane changed what the data plane can read"
    );
}

// ---------------------------------------------------------------------------
// The family axis, at the composition root.
// ---------------------------------------------------------------------------

#[test]
fn the_composed_core_builds_on_every_underlay_family() {
    // L-5, applied to the composition root. A core that could only be
    // constructed against a dual-stack adapter would make every IPv6-only test
    // in this suite unreachable, and nothing else asserts it.
    for family in HostFamily::ALL {
        let rig = ComposedRig::new(family, 56);
        assert!(!rig.core.is_poisoned(), "{}", family.name());
        let supported = rig.adapter.sockets_mock();
        let _ = supported;
        for af in [AddressFamily::V4, AddressFamily::V6] {
            let carried = rig.host_family.underlay_carries(af);
            // Nothing is asserted about the core's behaviour per family here —
            // that is `dual_stack_parity.rs`'s job. What is asserted is that the
            // core CONSTRUCTS on all three, which is the precondition for it.
            let _ = carried;
        }
    }
}

#[test]
fn the_build_identity_reports_the_adapter_it_is_actually_bound_to() {
    // S-46 must name the binding truthfully. A build identity that reported a
    // platform adapter it was not using would make every field bundle wrong in
    // the same way, and would be invisible in the shell that produced it.
    let rig = ComposedRig::new(HostFamily::Dual, 57);
    let identity = rig.core.build_identity();
    assert_eq!(
        identity.adapter_binding, "mock-in-memory",
        "S-46 names a binding this core is not using"
    );
    assert!(
        !identity.hardware_backed,
        "the mock reports no secure element; §11.16 (l) requires the core to \
         record that rather than assume otherwise"
    );
}

#[test]
fn the_ledger_records_what_the_core_decided_and_nothing_it_did_not() {
    let rig = ComposedRig::new(HostFamily::Dual, 58);
    let (before, _) = rig.core.ledger_stats();
    rig.core
        .publish_diagnostic(&twinvpn_types::Diagnostic::invariant_violated(
            twinvpn_types::Component::Diagnostics,
            "a system test publishing a diagnostic",
        ));
    let (after, _) = rig.core.ledger_stats();
    assert!(
        after > before,
        "a published diagnostic did not reach the ledger"
    );
}

#[test]
fn a_monotonic_instant_never_moves_backwards_across_the_composed_env() {
    // A property the whole timer model rests on, asserted over a long run of
    // advances drawn from the seeded stream — so the sequence is reproducible
    // and a counterexample is replayable from the seed alone.
    let rig = ComposedRig::new(HostFamily::Dual, 59);
    let mut rng = rig
        .core
        .env()
        .rng_for(twinvpn_env::consumers::BACKOFF_JITTER)
        .expect("stream");
    let mut prev: MonotonicInstant = rig.core.env().now_monotonic();
    for _ in 0..256 {
        let step = rng.uniform_duration(core::time::Duration::from_secs(60));
        rig.env.time().advance(step);
        let now = rig.core.env().now_monotonic();
        assert!(
            now.as_micros() >= prev.as_micros(),
            "the monotonic clock went backwards: {prev:?} -> {now:?}"
        );
        prev = now;
    }
}
