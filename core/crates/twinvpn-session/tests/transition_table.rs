//! Transition coverage: every row of `docs/reliability.md` §4.5, driven and
//! asserted.
//!
//! `docs/testing-strategy.md` §2.2 makes transition coverage a merge gate. This
//! file is the measurement: it drives each of the thirty-eight rows from a state
//! the machine actually reached, asserts the row that fired is the row intended,
//! and finally asserts that the union covers **all thirty-eight** — so adding a
//! row to §4.5 without exercising it fails the build.

mod common;

use std::collections::BTreeSet;

use common::{healthy, session_id, test_env};
use twinvpn_session::event::{LinkKind, PolicyViolationKind, QosMetric};
use twinvpn_session::machine::Outcome;
use twinvpn_session::state::EnforcementMode;
use twinvpn_session::{
    Context, Event, Guards, Row, SessionMachine, SessionState, TimerId, Trigger,
};
use twinvpn_types::PathClass;

/// Drives one trigger and asserts which row fired.
fn expect(
    m: &mut SessionMachine,
    trigger: impl Into<Trigger>,
    guards: Guards,
    row: Row,
) -> SessionState {
    let t = trigger.into();
    let outcome = m.apply(t, guards, Context::default());
    match outcome {
        Outcome::Transitioned(r) => {
            assert_eq!(
                r.row,
                row,
                "expected {} from {:?} on {:?}, got {}",
                row.label(),
                r.from,
                t,
                r.row.label()
            );
            assert!(
                r.is_well_formed(),
                "{} produced a malformed record: {r:?}",
                row.label()
            );
            r.to
        }
        Outcome::Ignored { state, trigger } => {
            panic!("expected {} but {state:?} ignored {trigger:?}", row.label())
        }
    }
}

fn machine() -> SessionMachine {
    let (env, _vt) = test_env();
    SessionMachine::new(env, session_id())
}

/// Every row, driven once, collected into one coverage set.
#[test]
fn every_row_of_section_4_5_is_reachable_and_well_formed() {
    let mut covered: BTreeSet<Row> = BTreeSet::new();
    let mut record = |rows: Vec<Row>| covered.extend(rows);

    // --- T01, T03, T05, T08: the happy LAN path ---------------------------
    {
        let mut m = machine();
        let g = healthy();
        expect(&mut m, Event::ConnectRequested, g, Row::T01);
        expect(&mut m, Event::CandidatesReady, g, Row::T03);
        expect(&mut m, Event::NegotiationOk, g, Row::T05);
        let s = expect(
            &mut m,
            Event::HandshakeOk(PathClass::LocalDirect),
            g,
            Row::T08,
        );
        assert_eq!(s, SessionState::Steady(PathClass::LocalDirect));
        record(m.rows_covered());
    }

    // --- T02: expired credentials ----------------------------------------
    {
        let mut m = machine();
        let g = Guards {
            credentials_expired: true,
            ..Guards::default()
        };
        expect(&mut m, Event::ConnectRequested, g, Row::T02);
        record(m.rows_covered());
    }

    // --- T04: no candidate on either family ------------------------------
    {
        let mut m = machine();
        let mut g = healthy();
        expect(&mut m, Event::ConnectRequested, g, Row::T01);
        g.no_candidate_either_family = true;
        expect(&mut m, TimerId::Discover, g, Row::T04);
        record(m.rows_covered());
    }

    // --- T06, T07: negotiation outcomes ----------------------------------
    for (trigger, row) in [
        (Trigger::from(Event::VersionIncompatible), Row::T06),
        (Trigger::from(TimerId::Negotiate), Row::T07),
    ] {
        let mut m = machine();
        let g = healthy();
        expect(&mut m, Event::ConnectRequested, g, Row::T01);
        expect(&mut m, Event::CandidatesReady, g, Row::T03);
        expect(&mut m, trigger, g, row);
        record(m.rows_covered());
    }

    // --- T09, T10, T11, T12: connecting outcomes -------------------------
    for (trigger, row) in [
        (
            Trigger::from(Event::HandshakeOk(PathClass::WanDirect)),
            Row::T09,
        ),
        (
            Trigger::from(Event::HandshakeOk(PathClass::Relayed)),
            Row::T10,
        ),
        (Trigger::from(Event::PeerRevoked), Row::T11),
        (Trigger::from(TimerId::Connect), Row::T12),
    ] {
        let mut m = machine();
        let g = healthy();
        expect(&mut m, Event::ConnectRequested, g, Row::T01);
        expect(&mut m, Event::CandidatesReady, g, Row::T03);
        expect(&mut m, Event::NegotiationOk, g, Row::T05);
        expect(&mut m, trigger, g, row);
        record(m.rows_covered());
    }

    // --- T13, T15: relay -> WAN upgrade, committed -----------------------
    {
        let mut m = relayed();
        let mut g = healthy();
        g.direct_upgrade_eligible = true;
        let s = expect(
            &mut m,
            Event::PathUpgradeAvailable(PathClass::WanDirect),
            g,
            Row::T13,
        );
        assert_eq!(
            s,
            SessionState::Migrating {
                from: PathClass::Relayed,
                to: PathClass::WanDirect
            }
        );
        let s = expect(
            &mut m,
            Event::PathValidated(PathClass::WanDirect),
            g,
            Row::T15,
        );
        assert_eq!(s, SessionState::Steady(PathClass::WanDirect));
        record(m.rows_covered());
    }

    // --- T14: upgrade to L2 ----------------------------------------------
    {
        let mut m = relayed();
        let mut g = healthy();
        g.same_l2_confirmed = true;
        expect(
            &mut m,
            Event::PathUpgradeAvailable(PathClass::LocalDirect),
            g,
            Row::T14,
        );
        record(m.rows_covered());
    }

    // --- T16: migration aborted, old path alive --------------------------
    {
        let mut m = migrating();
        let mut g = healthy();
        g.old_path_alive = true;
        let s = expect(&mut m, TimerId::Migrate, g, Row::T16);
        assert_eq!(s, SessionState::Steady(PathClass::Relayed));
        record(m.rows_covered());
    }

    // --- T17: migration failed, old path dead ----------------------------
    {
        let mut m = migrating();
        let g = healthy(); // old_path_alive defaults false
        let s = expect(&mut m, Event::MigrationFail, g, Row::T17);
        assert_eq!(s, SessionState::Reconnecting { parked: false });
        record(m.rows_covered());
    }

    // --- T18: suspect, no state change -----------------------------------
    {
        let mut m = relayed();
        let g = healthy();
        let before = m.state();
        let s = expect(&mut m, Event::PathSuspect, g, Row::T18);
        assert_eq!(s, before, "T18 must not disturb traffic");
        record(m.rows_covered());
    }

    // --- T19: path dead WITH an alternate --------------------------------
    {
        let mut m = relayed();
        let mut g = healthy();
        g.relay_failover_target_ready = true;
        let s = expect(&mut m, Event::RelayGone, g, Row::T19);
        assert_eq!(
            s,
            SessionState::Migrating {
                from: PathClass::Relayed,
                to: PathClass::Relayed
            },
            "§8.1: relay failover MUST NOT pass through RECONNECTING"
        );
        record(m.rows_covered());
    }

    // --- T20: path dead WITHOUT an alternate ------------------------------
    {
        let mut m = wan_direct();
        let g = healthy(); // alternate_available defaults false
        let s = expect(&mut m, Event::LinkDown(LinkKind::WiFi), g, Row::T20);
        assert_eq!(s, SessionState::Reconnecting { parked: false });
        record(m.rows_covered());
    }

    // --- T21: local address changed --------------------------------------
    {
        let mut m = wan_direct();
        let mut g = healthy();
        g.local_address_changed = true;
        expect(&mut m, Event::AddrChanged, g, Row::T21);
        record(m.rows_covered());
    }

    // --- T22, T23: degrade and recover ------------------------------------
    {
        let mut m = wan_direct();
        let mut g = healthy();
        g.qos_violation_sustained = true;
        let s = expect(&mut m, Event::QosViolation(QosMetric::Loss), g, Row::T22);
        assert_eq!(
            s,
            SessionState::Degraded {
                carrier: PathClass::WanDirect
            }
        );
        g.qos_restored_sustained = true;
        let s = expect(&mut m, Event::QosRestored, g, Row::T23);
        assert_eq!(s, SessionState::Steady(PathClass::WanDirect));
        record(m.rows_covered());
    }

    // --- T24: degraded timeout --------------------------------------------
    {
        let mut m = degraded();
        let g = healthy();
        let s = expect(&mut m, TimerId::DegradedMax, g, Row::T24);
        assert_eq!(s, SessionState::Reconnecting { parked: false });
        record(m.rows_covered());
    }

    // --- T25: recovery from RECONNECTING ----------------------------------
    {
        let mut m = reconnecting();
        let g = healthy();
        let s = expect(&mut m, Event::HandshakeOk(PathClass::Relayed), g, Row::T25);
        assert_eq!(s, SessionState::Steady(PathClass::Relayed));
        record(m.rows_covered());
    }

    // --- T26: grace expired under FAIL_CLOSED ------------------------------
    {
        let mut m = reconnecting();
        let g = healthy();
        let s = expect(&mut m, TimerId::ReconnectGrace, g, Row::T26);
        assert_eq!(s, SessionState::Blocked);
        record(m.rows_covered());
    }

    // --- T27: reconnect max under PERMISSIVE_ANNOUNCED ---------------------
    {
        let mut m = reconnecting();
        let mut g = healthy();
        g.enforcement = Some(EnforcementMode::PermissiveAnnounced);
        let s = expect(&mut m, TimerId::ReconnectMax, g, Row::T27);
        assert_eq!(s, SessionState::Failed);
        record(m.rows_covered());
    }

    // --- T28: credential expiry while reconnecting -------------------------
    {
        let mut m = reconnecting();
        let g = healthy();
        expect(&mut m, Event::CredExpired, g, Row::T28);
        record(m.rows_covered());
    }

    // --- T29: policy violation always wins ---------------------------------
    {
        let mut m = wan_direct();
        let g = healthy();
        let s = expect(
            &mut m,
            Event::PolicyViolation(PolicyViolationKind::DnsQueryOffTunnel),
            g,
            Row::T29,
        );
        assert_eq!(s, SessionState::Blocked);
        record(m.rows_covered());
    }

    // --- T30, T31, T32: inside BLOCKED --------------------------------------
    {
        let mut m = blocked();
        let mut g = healthy();
        // T31: the internal loop runs without leaving the state.
        let s = expect(&mut m, TimerId::Backoff, g, Row::T31);
        assert_eq!(s, SessionState::Blocked, "T31 must not leave BLOCKED");
        // T30: recovery.
        g.secure_path_established = true;
        g.enforcement_reconciled = true;
        let s = expect(&mut m, Event::SecurePathRestored, g, Row::T30);
        assert_eq!(s, SessionState::Steady(PathClass::Relayed));
        record(m.rows_covered());
    }
    {
        let mut m = blocked();
        let mut g = healthy();
        g.authenticated_disarm = true;
        let s = expect(&mut m, Event::DisconnectRequested, g, Row::T32);
        assert_eq!(s, SessionState::Disconnected);
        record(m.rows_covered());
    }

    // --- T33: FAILED revived by a satisfied precondition --------------------
    {
        let mut m = failed();
        let mut g = healthy();
        g.retry_precondition_met = true;
        let s = expect(&mut m, Event::LinkUp(LinkKind::Ethernet), g, Row::T33);
        assert_eq!(s, SessionState::Discovering);
        record(m.rows_covered());
    }

    // --- T34, T35: park and wake --------------------------------------------
    {
        let mut m = wan_direct();
        let mut g = healthy();
        let s = expect(&mut m, Event::Suspend, g, Row::T34);
        assert_eq!(s, SessionState::Reconnecting { parked: true });
        g.path_plausibly_survived = true;
        let s = expect(&mut m, Event::Resume, g, Row::T35);
        assert!(matches!(s, SessionState::Migrating { .. }));
        record(m.rows_covered());
    }

    // --- T36: background with an inbound requirement -------------------------
    {
        let mut m = wan_direct();
        let mut g = healthy();
        g.inbound_required = true;
        let before = m.state();
        let s = expect(&mut m, Event::Background, g, Row::T36);
        assert_eq!(s, before, "T36 is not a state transition");
        record(m.rows_covered());
    }

    // --- T37: herd-safe drain -------------------------------------------------
    {
        let mut m = relayed();
        let g = healthy();
        let s = expect(&mut m, Event::RelayDraining, g, Row::T37);
        assert!(matches!(s, SessionState::Migrating { .. }));
        record(m.rows_covered());
    }

    // --- T38: ordinary disconnect ---------------------------------------------
    {
        let mut m = wan_direct();
        let g = healthy();
        let s = expect(&mut m, Event::DisconnectRequested, g, Row::T38);
        assert_eq!(s, SessionState::Disconnected);
        record(m.rows_covered());
    }

    let missing: Vec<&str> = Row::ALL
        .iter()
        .filter(|r| !covered.contains(r))
        .map(|r| r.label())
        .collect();
    assert!(
        missing.is_empty(),
        "reliability.md §4.5 rows never exercised: {missing:?}"
    );
    assert_eq!(covered.len(), 38, "§4.5 has thirty-eight rows");
}

// --- helpers that reach a state the honest way, through the machine ---------

fn relayed() -> SessionMachine {
    let mut m = machine();
    let g = healthy();
    expect(&mut m, Event::ConnectRequested, g, Row::T01);
    expect(&mut m, Event::CandidatesReady, g, Row::T03);
    expect(&mut m, Event::NegotiationOk, g, Row::T05);
    expect(&mut m, Event::HandshakeOk(PathClass::Relayed), g, Row::T10);
    m
}

fn wan_direct() -> SessionMachine {
    let mut m = machine();
    let g = healthy();
    expect(&mut m, Event::ConnectRequested, g, Row::T01);
    expect(&mut m, Event::CandidatesReady, g, Row::T03);
    expect(&mut m, Event::NegotiationOk, g, Row::T05);
    expect(
        &mut m,
        Event::HandshakeOk(PathClass::WanDirect),
        g,
        Row::T09,
    );
    m
}

fn migrating() -> SessionMachine {
    let mut m = relayed();
    let mut g = healthy();
    g.same_l2_confirmed = true;
    expect(
        &mut m,
        Event::PathUpgradeAvailable(PathClass::LocalDirect),
        g,
        Row::T14,
    );
    m
}

fn degraded() -> SessionMachine {
    let mut m = wan_direct();
    let mut g = healthy();
    g.qos_violation_sustained = true;
    expect(&mut m, Event::QosViolation(QosMetric::Rtt), g, Row::T22);
    m
}

fn reconnecting() -> SessionMachine {
    let mut m = wan_direct();
    let g = healthy();
    expect(&mut m, Event::PathDead, g, Row::T20);
    m
}

fn blocked() -> SessionMachine {
    let mut m = reconnecting();
    let g = healthy();
    expect(&mut m, TimerId::ReconnectGrace, g, Row::T26);
    m
}

fn failed() -> SessionMachine {
    let mut m = reconnecting();
    let mut g = healthy();
    g.enforcement = Some(EnforcementMode::PermissiveAnnounced);
    expect(&mut m, TimerId::ReconnectMax, g, Row::T27);
    m
}
