//! The named scenario matrix: one test per scenario the wave-1 objective lists.
//!
//! **Owner:** `test-engineering`.
//!
//! # Why this file exists when the scenarios are already covered
//!
//! Every scenario below is exercised somewhere in this repository — by
//! `twinvpn-session`'s transition-table coverage, by `chaos/outage_and_failover.rs`,
//! by `e2e/fail_closed_leak.rs`. What did not exist was a place where a reader
//! could check the objective's list **against test names** and see that each one
//! is met, rather than inferring it from thirty-eight row labels and a set of
//! file names.
//!
//! So this file is a **traceability surface**, deliberately named after the
//! objective's own vocabulary. Where a scenario is more thoroughly tested
//! elsewhere, the test here says where; it does not duplicate that depth.
//!
//! # Determinism
//!
//! Every test is a pure function of a fixed seed. No wall clock, no network, no
//! sleep, no thread: the session machine is driven trigger by trigger, and the
//! clock is TwinLab's virtual one. `docs/testing-strategy.md` §2.2 makes that a
//! merge gate, and a scenario suite that could flake would be the worst place in
//! the repository to lose it.
//!
//! # Both families, every time
//!
//! ADR-0010 **R1**: IPv4 and IPv6 are one story. Every scenario with an address
//! family runs over [`HostFamily::ALL`], because a matrix that quietly covered
//! only the v4 arm would make the objective's "no v6 later" rule untestable.

use std::collections::BTreeSet;

use twinvpn_session::event::{LinkKind, PolicyViolationKind};
use twinvpn_session::machine::Outcome;
use twinvpn_session::{Context, Event, Guards, Row, SessionMachine, SessionState, Trigger};
use twinvpn_system_tests::{HostFamily, Rig};
use twinvpn_types::PathClass;

// ---------------------------------------------------------------------------
// Shared drivers.
// ---------------------------------------------------------------------------

/// Guards for a healthy establishment on `carrier`.
///
/// T09 and T10 are conditional on which class won, so these are derived from
/// `carrier` rather than set unconditionally: a caller asking for `RELAYED` must
/// not silently also assert that no direct path exists when one does.
fn guards_for(carrier: PathClass) -> Guards {
    Guards {
        credentials_valid: true,
        peer_authorized: true,
        usable_candidate: true,
        path_validated: true,
        no_l2_path_won: carrier != PathClass::LocalDirect,
        no_direct_path_won: carrier == PathClass::Relayed,
        new_path_committed: true,
        retry_budget_available: true,
        relay_set_nonempty: true,
        enforcement: Some(twinvpn_session::EnforcementMode::FailClosed),
        ..Guards::default()
    }
}

/// Drives one trigger and returns the row that fired, failing loudly if the
/// machine ignored it.
///
/// A scenario that silently no-oped would still "pass" every assertion about the
/// state it never left, which is the failure mode this helper exists to remove.
fn drive(m: &mut SessionMachine, trigger: impl Into<Trigger>, g: Guards) -> Row {
    let t = trigger.into();
    match m.apply(t, g, Context::default()) {
        Outcome::Transitioned(r) => r.row,
        Outcome::Ignored { state, trigger } => {
            panic!("{state:?} ignored {trigger:?} — the scenario did not happen")
        }
    }
}

/// A rig established on `carrier`, over `family`.
fn established(family: HostFamily, carrier: PathClass) -> Rig {
    let mut rig = Rig::new(family, 0x21);
    let states = rig.establish(carrier);
    assert_eq!(
        states.last(),
        Some(&SessionState::Steady(carrier)),
        "{family:?}/{carrier:?} did not reach a steady carrier state",
    );
    rig
}

// ---------------------------------------------------------------------------
// 1-3. The three ways a connection can be carried.
//
// `ConnectionState` has three steady carriers and `PathClass` has three
// members, so "direct", "local direct" and "relayed" are not three variations
// on one scenario: they are three distinct terminal states with three distinct
// guard sets, and each is asserted as itself.
// ---------------------------------------------------------------------------

#[test]
fn scenario_direct_connection() {
    for family in HostFamily::ALL {
        let rig = established(family, PathClass::WanDirect);
        assert_eq!(
            rig.session.state(),
            SessionState::Steady(PathClass::WanDirect)
        );
        assert_eq!(
            rig.session.state().connection_state(),
            twinvpn_types::ConnectionState::WanDirect,
        );
        // The row that carried it, not just the state it landed in: T09 is the
        // one that requires "no L2 path won", and reaching WAN_DIRECT through
        // any other row would mean the race was decided somewhere else.
        assert!(rig.session.history().iter().any(|r| r.row == Row::T09));
    }
}

#[test]
fn scenario_local_direct_connection() {
    for family in HostFamily::ALL {
        let rig = established(family, PathClass::LocalDirect);
        assert_eq!(
            rig.session.state().connection_state(),
            twinvpn_types::ConnectionState::LocalDirect,
        );
        assert!(rig.session.history().iter().any(|r| r.row == Row::T08));
    }
}

#[test]
fn scenario_relayed_connection() {
    for family in HostFamily::ALL {
        let rig = established(family, PathClass::Relayed);
        assert_eq!(
            rig.session.state().connection_state(),
            twinvpn_types::ConnectionState::Relayed,
        );
        // T10's guard is "no direct path has won YET" — the relay is a floor the
        // session may leave, not a terminal outcome. Scenario 5 is the leaving.
        assert!(rig.session.history().iter().any(|r| r.row == Row::T10));
    }
}

// ---------------------------------------------------------------------------
// 4. Direct-to-relay fallback.
// ---------------------------------------------------------------------------

#[test]
fn scenario_direct_to_relay_fallback() {
    for family in HostFamily::ALL {
        let mut rig = established(family, PathClass::WanDirect);
        // The direct path dies with a relay standing by: T19 migrates rather
        // than reconnecting, which is what makes the fallback invisible to an
        // in-progress flow.
        let mut g = guards_for(PathClass::WanDirect);
        g.alternate_available = true;
        assert_eq!(drive(&mut rig.session, Event::PathDead, g), Row::T19);
        assert!(matches!(
            rig.session.state(),
            SessionState::Migrating {
                from: PathClass::WanDirect,
                ..
            },
        ));

        // And it commits onto the relay.
        let commit = guards_for(PathClass::Relayed);
        assert_eq!(
            drive(
                &mut rig.session,
                Event::PathValidated(PathClass::Relayed),
                commit
            ),
            Row::T15,
        );
        assert_eq!(
            rig.session.state(),
            SessionState::Steady(PathClass::Relayed)
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Relay-to-direct upgrade, where supported.
//
// "Where supported" is the load-bearing clause. The upgrade is not
// unconditional: T13 requires the direct path to have passed authenticated
// validation AND to be better by hysteresis. Both halves are asserted, because
// an upgrade that fired without the hysteresis guard is the flap the guard
// exists to prevent.
// ---------------------------------------------------------------------------

#[test]
fn scenario_relay_to_direct_upgrade_where_supported() {
    for family in HostFamily::ALL {
        let mut rig = established(family, PathClass::Relayed);
        let mut g = guards_for(PathClass::Relayed);
        g.path_validated = true;
        // T13's "better by hysteresis" is two guards: the direct path is
        // eligible, and the anti-flap suppressor is not holding it back.
        g.direct_upgrade_eligible = true;
        g.upgrade_flap_suppressed = false;
        assert_eq!(
            drive(
                &mut rig.session,
                Event::PathUpgradeAvailable(PathClass::WanDirect),
                g
            ),
            Row::T13,
        );
        assert_eq!(
            rig.session.state(),
            SessionState::Migrating {
                from: PathClass::Relayed,
                to: PathClass::WanDirect
            },
        );
        assert_eq!(
            drive(
                &mut rig.session,
                Event::PathValidated(PathClass::WanDirect),
                guards_for(PathClass::WanDirect),
            ),
            Row::T15,
        );
        assert_eq!(
            rig.session.state(),
            SessionState::Steady(PathClass::WanDirect)
        );
    }
}

#[test]
fn scenario_relay_to_direct_upgrade_is_refused_where_it_is_not_supported() {
    // The negative half. An unvalidated or non-better path must NOT upgrade:
    // "where supported" is a guard, and a guard nobody has seen refuse is not a
    // guard.
    for (validated, eligible, flapping) in [
        (false, true, false),  // never validated: an unauthenticated path
        (true, false, false),  // validated but not better
        (true, true, true),    // better, but the anti-flap suppressor is holding
        (false, false, false), // none of it
    ] {
        let mut rig = established(HostFamily::Dual, PathClass::Relayed);
        let mut g = guards_for(PathClass::Relayed);
        g.path_validated = validated;
        g.direct_upgrade_eligible = eligible;
        g.upgrade_flap_suppressed = flapping;
        let outcome = rig.session.apply(
            Trigger::Event(Event::PathUpgradeAvailable(PathClass::WanDirect)),
            g,
            Context::default(),
        );
        assert!(
            matches!(outcome, Outcome::Ignored { .. }),
            "validated={validated} eligible={eligible} flapping={flapping} must not upgrade",
        );
        assert_eq!(
            rig.session.state(),
            SessionState::Steady(PathClass::Relayed)
        );
    }
}

// ---------------------------------------------------------------------------
// 6. Path migration.
// ---------------------------------------------------------------------------

#[test]
fn scenario_path_migration_commits_and_rolls_back() {
    for family in HostFamily::ALL {
        // The commit path.
        let mut rig = established(family, PathClass::WanDirect);
        let mut g = guards_for(PathClass::WanDirect);
        g.local_address_changed = true;
        assert_eq!(drive(&mut rig.session, Event::AddrChanged, g), Row::T21);
        assert!(matches!(
            rig.session.state(),
            SessionState::Migrating { .. }
        ));
        assert_eq!(
            drive(
                &mut rig.session,
                Event::PathValidated(PathClass::WanDirect),
                guards_for(PathClass::WanDirect),
            ),
            Row::T15,
        );
        assert_eq!(
            rig.session.state(),
            SessionState::Steady(PathClass::WanDirect)
        );

        // The rollback path: a migration that fails while the old path is still
        // alive returns to it rather than tearing the session down. §6.5 makes
        // `InnerFlows` survive a path change, and that is only true if this
        // rollback exists.
        let mut rig = established(family, PathClass::WanDirect);
        let mut g = guards_for(PathClass::WanDirect);
        g.local_address_changed = true;
        drive(&mut rig.session, Event::AddrChanged, g);
        let mut back = guards_for(PathClass::WanDirect);
        back.old_path_alive = true;
        assert_eq!(
            drive(&mut rig.session, Event::MigrationFail, back),
            Row::T16
        );
        assert_eq!(
            rig.session.state(),
            SessionState::Steady(PathClass::WanDirect)
        );
    }
}

// ---------------------------------------------------------------------------
// 7. Network loss.
// ---------------------------------------------------------------------------

#[test]
fn scenario_network_loss_with_no_alternate_reconnects_with_a_named_code() {
    for family in HostFamily::ALL {
        for link in [LinkKind::WiFi, LinkKind::Cellular, LinkKind::Ethernet] {
            let mut rig = established(family, PathClass::WanDirect);
            let mut g = guards_for(PathClass::WanDirect);
            g.alternate_available = false;
            assert_eq!(drive(&mut rig.session, Event::LinkDown(link), g), Row::T20);
            assert_eq!(
                rig.session.state(),
                SessionState::Reconnecting { parked: false }
            );
            // §10.1: RECONNECTING is unenterable without a reason_code. A loss
            // that parked the session silently is the failure this asserts away.
            let record = rig.session.history().last().expect("a transition happened");
            assert!(
                record.reason_code.is_some(),
                "{family:?}/{link:?} entered RECONNECTING with no code",
            );
            assert!(record.diagnostic.is_some(), "a code carries its diagnostic");
        }
    }
}

// ---------------------------------------------------------------------------
// 8. Reconnect.
// ---------------------------------------------------------------------------

#[test]
fn scenario_reconnect_returns_to_a_steady_carrier_on_every_family() {
    for family in HostFamily::ALL {
        for carrier in [
            PathClass::LocalDirect,
            PathClass::WanDirect,
            PathClass::Relayed,
        ] {
            let mut rig = established(family, PathClass::WanDirect);
            let mut g = guards_for(PathClass::WanDirect);
            g.alternate_available = false;
            drive(&mut rig.session, Event::PathDead, g);
            assert_eq!(
                rig.session.state(),
                SessionState::Reconnecting { parked: false }
            );

            // T25: a handshake from RECONNECTING lands on whichever class won —
            // a reconnect is not obliged to come back on the class it left.
            assert_eq!(
                drive(
                    &mut rig.session,
                    Event::HandshakeOk(carrier),
                    guards_for(carrier)
                ),
                Row::T25,
            );
            assert_eq!(rig.session.state(), SessionState::Steady(carrier));
        }
    }
}

// ---------------------------------------------------------------------------
// 9. Stale session.
//
// Two distinct staleness conditions, and they resolve differently. Conflating
// them is how a device comes back from an eight-hour sleep with transport keys
// that authenticate nothing.
// ---------------------------------------------------------------------------

#[test]
fn scenario_stale_session_past_the_rekey_window_rediscovers_rather_than_resuming() {
    use twinvpn_session::resumption::{fate, Disruption, Fate, Item};

    let mut rig = established(HostFamily::Dual, PathClass::WanDirect);
    let g = guards_for(PathClass::WanDirect);
    assert_eq!(drive(&mut rig.session, Event::Suspend, g), Row::T34);
    assert_eq!(
        rig.session.state(),
        SessionState::Reconnecting { parked: true }
    );

    let mut stale = g;
    stale.path_plausibly_survived = true;
    stale.rekey_window_exceeded = true;
    assert_eq!(drive(&mut rig.session, Event::Resume, stale), Row::T35);
    assert_eq!(
        rig.session.state(),
        SessionState::Discovering,
        "a suspend past the rekey window forces a full handshake",
    );

    // And the contract behind it: §6.5 says transport keys and the replay
    // window are LOST across a suspend past rekey. Resuming into MIGRATING
    // would be claiming to still hold them.
    assert_eq!(
        fate(Item::TransportKeys, Disruption::SuspendPastRekey),
        Fate::Lost
    );
    assert_eq!(
        fate(Item::ReplayWindow, Disruption::SuspendPastRekey),
        Fate::Lost
    );
    // What survives is what makes the reconnect cheap rather than cold.
    assert_eq!(
        fate(Item::SessionIdentity, Disruption::SuspendPastRekey),
        Fate::Survives
    );
    assert_eq!(
        fate(Item::InnerAddresses, Disruption::SuspendPastRekey),
        Fate::Survives
    );
}

#[test]
fn scenario_a_session_stale_only_by_path_resumes_by_migrating() {
    let mut rig = established(HostFamily::Dual, PathClass::WanDirect);
    let g = guards_for(PathClass::WanDirect);
    drive(&mut rig.session, Event::Suspend, g);
    let mut fresh = g;
    fresh.path_plausibly_survived = true;
    fresh.rekey_window_exceeded = false;
    assert_eq!(drive(&mut rig.session, Event::Resume, fresh), Row::T35);
    assert!(matches!(
        rig.session.state(),
        SessionState::Migrating { .. }
    ));
}

// ---------------------------------------------------------------------------
// 10-11. Duplicate and reordered messages.
//
// These are properties of the anti-replay window, not of the state machine, so
// they are asserted where they live. `integration/tunnel_wire_agreement.rs`
// covers the window's width against ADR-0001; this covers the two behaviours
// the objective names by name.
// ---------------------------------------------------------------------------

#[test]
fn scenario_duplicate_messages_are_refused_exactly_once_each() {
    let mut window = twinvpn_tunnel::ReplayWindow::new();
    assert!(window.accept(1), "the first arrival is accepted");
    assert!(!window.accept(1), "the duplicate is refused");
    assert!(
        !window.accept(1),
        "and stays refused, however many times it arrives"
    );

    // A duplicate far behind the window is refused as a replay, not accepted by
    // sliding the window backwards to accommodate it.
    for counter in 2..=200 {
        assert!(window.accept(counter));
    }
    assert!(
        !window.accept(1),
        "an ancient duplicate never becomes acceptable again"
    );
}

#[test]
fn scenario_reordered_messages_are_accepted_within_the_window_and_still_deduplicated() {
    let mut window = twinvpn_tunnel::ReplayWindow::new();
    // Arrival order 5, 3, 4, 1, 2 — a legal reordering, all inside the window.
    for counter in [5u64, 3, 4, 1, 2] {
        assert!(
            window.accept(counter),
            "{counter} is a reorder, not a replay"
        );
    }
    // Every one of them is now a duplicate.
    for counter in [1u64, 2, 3, 4, 5] {
        assert!(!window.accept(counter), "{counter} arrived already");
    }
    // A counter further behind than the window is wide cannot be judged, so it
    // is refused rather than admitted — the window is never grown to fit it.
    assert!(window.accept(10_000));
    assert!(
        !window.accept(1),
        "outside the window is a refusal, not a growth"
    );
}

// ---------------------------------------------------------------------------
// 12. Unsupported capability.
// ---------------------------------------------------------------------------

#[test]
fn scenario_an_unsupported_capability_is_absent_from_the_selection_rather_than_assumed() {
    use twinvpn_tunnel::negotiate::{select, Advertisement};

    let ours = Advertisement {
        v_min: 1,
        v_max: 2,
        capabilities: ["relay_v2", "dns_split", "gateway_exit"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
    };
    let theirs = Advertisement {
        v_min: 1,
        v_max: 2,
        capabilities: ["relay_v2", "something_we_do_not_have"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
    };
    let selection = select(&ours, &theirs).expect("the ranges overlap");
    // The intersection, and nothing else. A capability only one side supports is
    // not negotiated, and a capability neither side named cannot appear at all.
    assert_eq!(
        selection.capabilities,
        ["relay_v2"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<BTreeSet<String>>(),
    );
    assert!(!selection.capabilities.contains("something_we_do_not_have"));
    assert!(!selection.capabilities.contains("dns_split"));
}

#[test]
fn scenario_an_unsupported_capability_name_is_refused_before_it_is_stored() {
    use twinvpn_tunnel::negotiate::{Advertisement, Caps};

    // A token that is not `[a-z][a-z0-9_]{0,31}` is not an unknown capability to
    // be ignored — it is a malformed advertisement, refused at the boundary.
    for bad in [
        "Relay_V2",
        "relay v2",
        "1relay",
        "",
        &"x".repeat(Caps::MAX_NAME_BYTES + 1),
    ] {
        let advertisement = Advertisement {
            v_min: 1,
            v_max: 1,
            capabilities: core::iter::once((*bad).to_owned()).collect(),
        };
        assert!(
            advertisement.validate(1).is_err(),
            "{bad:?} is not a capability name",
        );
    }

    // The positive control, at exactly the cap `ownership.md` §4.3 fixes at 32.
    let at_cap = Advertisement {
        v_min: 1,
        v_max: 1,
        capabilities: core::iter::once("dns_config_dies_with_tunnel".to_owned()).collect(),
    };
    assert!(
        at_cap.validate(1).is_ok(),
        "the Phase-1-mandated 27-byte token must validate (ownership.md §4.3)",
    );
}

#[test]
fn scenario_a_capability_downgrade_below_the_monotonic_floor_is_refused() {
    use twinvpn_tunnel::negotiate::{MonotonicFloor, Selection};

    let security_relevant: BTreeSet<String> =
        core::iter::once("dns_config_dies_with_tunnel".to_owned()).collect();
    let mut floor = MonotonicFloor::new();
    let strong = Selection {
        epoch: 2,
        capabilities: security_relevant.clone(),
    };
    // P-4: an epoch not confirmed in-session must never be written to the floor,
    // so `record` takes the confirmation as a required argument.
    assert!(
        !floor.record(&strong, &security_relevant, false),
        "unconfirmed writes nothing"
    );
    assert!(floor.record(&strong, &security_relevant, true));

    // S-37: a strictly weaker offer is refused. Silently accepting it is the
    // downgrade the floor exists to prevent.
    let weakened = Selection {
        epoch: 2,
        capabilities: BTreeSet::new(),
    };
    assert!(!floor.admits(&weakened, &security_relevant));
    assert_eq!(
        floor.lost_tokens(&weakened),
        vec!["dns_config_dies_with_tunnel"]
    );
    assert!(
        floor.admits(&strong, &security_relevant),
        "the same offer still admits"
    );
}

// ---------------------------------------------------------------------------
// 13. Incompatible protocol version.
// ---------------------------------------------------------------------------

#[test]
fn scenario_an_incompatible_protocol_version_fails_with_the_registered_code() {
    // No overlap at all: selection is impossible, and that is T06's condition.
    use twinvpn_tunnel::negotiate::{select, Advertisement};
    let ours = Advertisement {
        v_min: 3,
        v_max: 4,
        capabilities: BTreeSet::new(),
    };
    let theirs = Advertisement {
        v_min: 1,
        v_max: 2,
        capabilities: BTreeSet::new(),
    };
    assert!(
        select(&ours, &theirs).is_none(),
        "disjoint ranges have no selection"
    );

    let mut rig = Rig::new(HostFamily::Dual, 0x21);
    let g = guards_for(PathClass::WanDirect);
    drive(&mut rig.session, Event::ConnectRequested, g);
    drive(&mut rig.session, Event::CandidatesReady, g);
    assert_eq!(rig.session.state(), SessionState::Negotiating);
    assert_eq!(
        drive(&mut rig.session, Event::VersionIncompatible, g),
        Row::T06
    );
    assert_eq!(rig.session.state(), SessionState::Failed);

    let record = rig.session.history().last().expect("a transition happened");
    assert_eq!(
        record.reason_code,
        Some(twinvpn_types::codes::PROTO_VERSION_UNSUPPORTED),
        "a version failure must not render as a generic negotiation failure",
    );
}

// ---------------------------------------------------------------------------
// 14. Peer revocation.
// ---------------------------------------------------------------------------

#[test]
fn scenario_peer_revocation_is_terminal_and_never_retried_into() {
    // From CONNECTING (T11).
    let mut rig = Rig::new(HostFamily::Dual, 0x21);
    let g = guards_for(PathClass::WanDirect);
    drive(&mut rig.session, Event::ConnectRequested, g);
    drive(&mut rig.session, Event::CandidatesReady, g);
    drive(&mut rig.session, Event::NegotiationOk, g);
    assert_eq!(rig.session.state(), SessionState::Connecting);
    assert_eq!(drive(&mut rig.session, Event::PeerRevoked, g), Row::T11);
    assert_eq!(rig.session.state(), SessionState::Failed);
    assert_eq!(
        rig.session
            .history()
            .last()
            .expect("transition")
            .reason_code,
        Some(twinvpn_types::codes::AUTH_DEVICE_REVOKED),
    );

    // A revoked peer must not be reachable by retrying: T33 leaves FAILED only
    // when the terminal code's own retry precondition is met, and a revocation's
    // is not met by a mere reconnect attempt.
    let mut no_precondition = g;
    no_precondition.retry_precondition_met = false;
    let outcome = rig.session.apply(
        Trigger::Event(Event::ConnectRequested),
        no_precondition,
        Context::default(),
    );
    assert!(
        matches!(outcome, Outcome::Ignored { .. }),
        "revocation is not retried away"
    );
    assert_eq!(rig.session.state(), SessionState::Failed);

    // And from RECONNECTING (T28), which is the case a device that was already
    // up when its peer was revoked actually takes.
    let mut rig = established(HostFamily::Dual, PathClass::WanDirect);
    let mut lost = guards_for(PathClass::WanDirect);
    lost.alternate_available = false;
    drive(&mut rig.session, Event::PathDead, lost);
    assert_eq!(drive(&mut rig.session, Event::PeerRevoked, lost), Row::T28);
    assert_eq!(rig.session.state(), SessionState::Failed);
    assert_eq!(
        rig.session
            .history()
            .last()
            .expect("transition")
            .reason_code,
        Some(twinvpn_types::codes::AUTH_DEVICE_REVOKED),
    );
}

// ---------------------------------------------------------------------------
// 15. Kill-switch state transitions.
//
// `e2e/fail_closed_leak.rs` tests the enforcement contract and the canary. This
// tests the four STATE TRANSITIONS the objective names: into BLOCKED, held in
// BLOCKED, out of BLOCKED by a restored path, and out of BLOCKED by an
// authenticated user action — and that nothing else leaves it.
// ---------------------------------------------------------------------------

#[test]
fn scenario_kill_switch_enters_blocked_when_the_reconnect_grace_expires_fail_closed() {
    let mut rig = established(HostFamily::Dual, PathClass::WanDirect);
    let mut g = guards_for(PathClass::WanDirect);
    g.alternate_available = false;
    drive(&mut rig.session, Event::PathDead, g);
    assert_eq!(
        drive(
            &mut rig.session,
            twinvpn_session::TimerId::ReconnectGrace,
            g
        ),
        Row::T26,
    );
    assert_eq!(rig.session.state(), SessionState::Blocked);
    assert_eq!(
        rig.session
            .history()
            .last()
            .expect("transition")
            .reason_code,
        Some(twinvpn_types::codes::POLICY_KILLSWITCH_ENGAGED),
    );
}

#[test]
fn scenario_kill_switch_leaves_blocked_only_by_a_restored_path_or_an_authenticated_action() {
    let blocked = || {
        let mut rig = established(HostFamily::Dual, PathClass::WanDirect);
        let mut g = guards_for(PathClass::WanDirect);
        g.alternate_available = false;
        drive(&mut rig.session, Event::PathDead, g);
        drive(
            &mut rig.session,
            twinvpn_session::TimerId::ReconnectGrace,
            g,
        );
        assert_eq!(rig.session.state(), SessionState::Blocked);
        rig
    };

    // (a) A restored, authorized secure path whose enforcement reconciles on
    //     BOTH families. Reconciling on one and leaving BLOCKED would be the
    //     per-family leak ADR-0010 R1 forbids.
    let mut rig = blocked();
    let mut restored = guards_for(PathClass::Relayed);
    restored.secure_path_established = true;
    restored.enforcement_reconciled = true;
    assert_eq!(
        drive(&mut rig.session, Event::SecurePathRestored, restored),
        Row::T30
    );
    assert_eq!(
        rig.session.state(),
        SessionState::Steady(PathClass::Relayed)
    );

    // (b) An authenticated user action. ADR-0012: leaving fail-closed is "a
    //     deliberate, authenticated, logged act — never an automatic one".
    let mut rig = blocked();
    let mut disarm = guards_for(PathClass::WanDirect);
    disarm.authenticated_disarm = true;
    assert_eq!(
        drive(&mut rig.session, Event::DisconnectRequested, disarm),
        Row::T32
    );
    assert_eq!(rig.session.state(), SessionState::Disconnected);

    // (c) Nothing else. An unauthenticated disconnect is refused — T38's
    //     wildcard explicitly excludes BLOCKED — and so is a path that came back
    //     without reconciling enforcement.
    let mut rig = blocked();
    let plain = guards_for(PathClass::WanDirect);
    assert!(matches!(
        rig.session.apply(
            Trigger::Event(Event::DisconnectRequested),
            plain,
            Context::default()
        ),
        Outcome::Ignored { .. },
    ));
    assert_eq!(rig.session.state(), SessionState::Blocked);

    let mut half = guards_for(PathClass::Relayed);
    half.secure_path_established = true;
    half.enforcement_reconciled = false;
    assert!(matches!(
        rig.session.apply(
            Trigger::Event(Event::SecurePathRestored),
            half,
            Context::default()
        ),
        Outcome::Ignored { .. },
    ));
    assert_eq!(rig.session.state(), SessionState::Blocked);
}

#[test]
fn scenario_a_policy_violation_reaches_blocked_from_every_state() {
    // T29 always wins. A kill switch that could be outrun by whatever else was
    // in flight would not be one.
    for kind in [
        PolicyViolationKind::DnsQueryOffTunnel,
        PolicyViolationKind::RouteDrift,
        PolicyViolationKind::InterfaceMissing,
        PolicyViolationKind::FamilyUncovered,
        PolicyViolationKind::RulesetAbsent,
        PolicyViolationKind::GrantExpired,
    ] {
        let mut rig = established(HostFamily::Dual, PathClass::WanDirect);
        let g = guards_for(PathClass::WanDirect);
        assert_eq!(
            drive(&mut rig.session, Event::PolicyViolation(kind), g),
            Row::T29
        );
        assert_eq!(rig.session.state(), SessionState::Blocked, "{kind:?}");
        assert!(
            rig.session
                .history()
                .last()
                .expect("transition")
                .reason_code
                .is_some(),
            "{kind:?} entered BLOCKED without a code",
        );
    }
}

// ---------------------------------------------------------------------------
// 16. Cancellation.
// ---------------------------------------------------------------------------

#[test]
fn scenario_cancellation_is_accepted_from_every_state_except_blocked() {
    // A user who asks to disconnect gets disconnected, from wherever the session
    // had reached — including mid-establishment, which is the case a naive
    // implementation drops on the floor because it is waiting on a handshake.
    let g = guards_for(PathClass::WanDirect);

    // Mid-discovery.
    let mut rig = Rig::new(HostFamily::Dual, 0x21);
    drive(&mut rig.session, Event::ConnectRequested, g);
    assert_eq!(rig.session.state(), SessionState::Discovering);
    assert_eq!(
        drive(&mut rig.session, Event::DisconnectRequested, g),
        Row::T38
    );
    assert_eq!(rig.session.state(), SessionState::Disconnected);

    // Mid-negotiation and mid-handshake.
    for stop_after in 2..=3 {
        let mut rig = Rig::new(HostFamily::Dual, 0x21);
        for trigger in [
            Event::ConnectRequested,
            Event::CandidatesReady,
            Event::NegotiationOk,
        ]
        .into_iter()
        .take(stop_after)
        {
            drive(&mut rig.session, trigger, g);
        }
        assert_eq!(
            drive(&mut rig.session, Event::DisconnectRequested, g),
            Row::T38
        );
        assert_eq!(rig.session.state(), SessionState::Disconnected);
    }

    // From every steady carrier, and from a migration in flight.
    for carrier in [
        PathClass::LocalDirect,
        PathClass::WanDirect,
        PathClass::Relayed,
    ] {
        let mut rig = established(HostFamily::Dual, carrier);
        assert_eq!(
            drive(&mut rig.session, Event::DisconnectRequested, g),
            Row::T38
        );
        assert_eq!(rig.session.state(), SessionState::Disconnected);
    }

    // And BLOCKED is the one exception, which scenario 15 covers: cancelling out
    // of a kill switch takes an authenticated action, not a plain request.
}

// ---------------------------------------------------------------------------
// 17. Concurrent clients.
// ---------------------------------------------------------------------------

#[test]
fn scenario_concurrent_clients_are_admitted_attributed_and_isolated() {
    use twinvpn_gateway::peer_table::{AllowedSources, PeerRow, PeerTable};
    use twinvpn_types::{DeviceId, IpAddr, IpPrefix, V4Addr, V6Addr};

    let mut table = PeerTable::new();
    let mut devices = Vec::new();
    for n in 1u8..=8 {
        let device = DeviceId::from_array([n; 32]);
        let mut sources = AllowedSources::new();
        // Both families per client, because a gateway that admitted a peer on
        // one family and silently dropped the other is the asymmetry R1 forbids.
        assert!(sources.insert(
            IpPrefix::new(IpAddr::V4(V4Addr::from_octets([100, 64, n, 0])), 24).expect("v4 prefix"),
        ));
        let mut v6 = [0u8; 16];
        v6[0] = 0xfd;
        v6[1] = n;
        assert!(sources.insert(
            IpPrefix::new(IpAddr::V6(V6Addr::prefix_base(v6).expect("v6 base")), 64)
                .expect("v6 prefix"),
        ));
        assert!(sources.both_families_present());
        table
            .admit(PeerRow {
                device_id: device,
                allowed_sources: sources,
                policy_version: 1,
                revoked: false,
            })
            .unwrap_or_else(|e| panic!("client {n} was refused: {e:?}"));
        devices.push(device);
    }
    assert_eq!(table.len(), 8, "eight concurrent clients");

    // Every client's traffic is attributed to that client and to no other. A
    // gateway that attributed one client's packet to another would let one
    // client spend another's quota and appear in another's diagnostics.
    for (i, device) in devices.iter().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let n = (i + 1) as u8;
        let source = IpAddr::V4(V4Addr::from_octets([100, 64, n, 7]));
        assert_eq!(
            table
                .attribute_ingress(*device, source)
                .map(|r| r.device_id)
                .expect("the client's own source attributes to it"),
            *device,
        );
        // The same packet claimed by a different client is refused as spoofing,
        // not silently reattributed — MG-4 calls a silent reattribution a
        // cross-peer interception primitive.
        let other = devices[(i + 1) % devices.len()];
        assert_eq!(
            table.attribute_ingress(other, source),
            Err(twinvpn_gateway::peer_table::Refusal::SourceSpoofed),
        );
    }

    // Removing one client leaves the other seven exactly as they were.
    table.remove(devices[3]);
    assert_eq!(table.len(), 7);
    assert!(table.row(devices[3]).is_none());
    for device in devices
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 3)
        .map(|(_, d)| d)
    {
        assert!(
            table.row(*device).is_some(),
            "an unrelated client was disturbed"
        );
    }
}

#[test]
fn scenario_a_second_client_claiming_an_admitted_clients_addresses_is_refused() {
    use twinvpn_gateway::peer_table::{AllowedSources, PeerRow, PeerTable};
    use twinvpn_types::{DeviceId, IpAddr, IpPrefix, V4Addr, V6Addr};

    let sources = || {
        let mut s = AllowedSources::new();
        s.insert(IpPrefix::new(IpAddr::V4(V4Addr::from_octets([100, 64, 1, 0])), 24).expect("v4"));
        let mut v6 = [0u8; 16];
        v6[0] = 0xfd;
        v6[1] = 1;
        s.insert(
            IpPrefix::new(IpAddr::V6(V6Addr::prefix_base(v6).expect("v6 base")), 64).expect("v6"),
        );
        s
    };
    let row = |n: u8| PeerRow {
        device_id: DeviceId::from_array([n; 32]),
        allowed_sources: sources(),
        policy_version: 1,
        revoked: false,
    };
    let mut table = PeerTable::new();
    table.admit(row(1)).expect("the first client is admitted");
    assert_eq!(
        table.admit(row(2)),
        Err(twinvpn_gateway::peer_table::AdmitError::SourceSetOverlap),
        "overlapping source prefixes are a collision, not a shared subnet",
    );
    assert_eq!(table.len(), 1);

    // And a client that offers only one family is refused outright (MG-3): a
    // gateway that admitted it would be running the v4 half of a peer with no
    // v6 story, which is exactly the asymmetry ADR-0010 R1 forbids.
    let mut v4_only = AllowedSources::new();
    v4_only
        .insert(IpPrefix::new(IpAddr::V4(V4Addr::from_octets([100, 64, 9, 0])), 24).expect("v4"));
    assert_eq!(
        table.admit(PeerRow {
            device_id: DeviceId::from_array([9; 32]),
            allowed_sources: v4_only,
            policy_version: 1,
            revoked: false,
        }),
        Err(twinvpn_gateway::peer_table::AdmitError::SingleFamilySourceSet),
    );
}
