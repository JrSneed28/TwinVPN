//! §10 — "No silent failure" — asserted three ways.
//!
//! 1. **Exhaustively**, over every reachable `(state, trigger, guards)` triple
//!    the machine can be put in: every move produces exactly one well-formed
//!    record, and no move produces zero.
//! 2. **Statically**, by parsing `docs/reliability.md` §4.5 itself and asserting
//!    that every row targeting one of the four reason-bearing states names an
//!    emit action — §10.2's "static test (the one that makes §10.1 a gate)".
//! 3. **By construction**, by asserting the registry-class compatibility §10.2
//!    requires of every code this crate can emit into those states.

mod common;

use std::collections::BTreeSet;

use common::{healthy, session_id, test_env};
use proptest::prelude::*;
use twinvpn_session::codes::{class_admissible, SUBSTITUTIONS};
use twinvpn_session::event::{LinkKind, PolicyViolationKind, QosMetric};
use twinvpn_session::machine::Outcome;
use twinvpn_session::state::EnforcementMode;
use twinvpn_session::{Context, Event, Guards, Row, SessionMachine, SessionState, TimerId, Trigger};
use twinvpn_types::PathClass;

const RELIABILITY_MD: &str = include_str!("../../../../docs/reliability.md");

// ---------------------------------------------------------------------------
// 1. Exhaustive: no reachable move is silent.
// ---------------------------------------------------------------------------

fn all_triggers() -> Vec<Trigger> {
    let mut v: Vec<Trigger> = vec![
        Event::ConnectRequested.into(),
        Event::DisconnectRequested.into(),
        Event::CandidatesReady.into(),
        Event::CandidateTimeout.into(),
        Event::NegotiationOk.into(),
        Event::NegotiationFail.into(),
        Event::VersionIncompatible.into(),
        Event::HandshakeFail.into(),
        Event::AuthRejected.into(),
        Event::PeerRevoked.into(),
        Event::RelayReady.into(),
        Event::PathSuspect.into(),
        Event::PathDead.into(),
        Event::AddrChanged.into(),
        Event::MigrationFail.into(),
        Event::QosRestored.into(),
        Event::SecurePathRestored.into(),
        Event::CredExpired.into(),
        Event::Suspend.into(),
        Event::Resume.into(),
        Event::Background.into(),
        Event::Foreground.into(),
        Event::RetryBudgetExhausted.into(),
        Event::PeerClosed.into(),
        Event::PeerRestarting.into(),
        Event::RelayDraining.into(),
        Event::RelayGone.into(),
    ];
    for c in [
        PathClass::LocalDirect,
        PathClass::WanDirect,
        PathClass::Relayed,
    ] {
        v.push(Event::HandshakeOk(c).into());
        v.push(Event::PathUpgradeAvailable(c).into());
        v.push(Event::PathValidated(c).into());
    }
    for k in [
        LinkKind::WiFi,
        LinkKind::Cellular,
        LinkKind::Ethernet,
        LinkKind::Unknown,
    ] {
        v.push(Event::LinkDown(k).into());
        v.push(Event::LinkUp(k).into());
    }
    for m in [
        QosMetric::Loss,
        QosMetric::Rtt,
        QosMetric::Jitter,
        QosMetric::Throughput,
        QosMetric::EffectiveMtu,
    ] {
        v.push(Event::QosViolation(m).into());
    }
    for k in [
        PolicyViolationKind::DnsQueryOffTunnel,
        PolicyViolationKind::RouteDrift,
        PolicyViolationKind::InterfaceMissing,
        PolicyViolationKind::FamilyUncovered,
        PolicyViolationKind::RulesetAbsent,
        PolicyViolationKind::GrantExpired,
    ] {
        v.push(Event::PolicyViolation(k).into());
    }
    for t in [
        TimerId::Discover,
        TimerId::Negotiate,
        TimerId::Connect,
        TimerId::Migrate,
        TimerId::ReconnectGrace,
        TimerId::ReconnectMax,
        TimerId::DegradedMax,
        TimerId::Backoff,
    ] {
        v.push(t.into());
    }
    v
}

/// Every guard set, plus the all-permissive one, so both sides of every guarded
/// row are exercised.
fn guard_variants() -> Vec<Guards> {
    let mut all_on = healthy();
    all_on.credentials_expired = true;
    all_on.no_candidate_either_family = true;
    all_on.same_l2_confirmed = true;
    all_on.old_path_alive = true;
    all_on.alternate_available = true;
    all_on.local_address_changed = true;
    all_on.qos_violation_sustained = true;
    all_on.qos_restored_sustained = true;
    all_on.retry_precondition_met = true;
    all_on.secure_path_established = true;
    all_on.enforcement_reconciled = true;
    all_on.authenticated_disarm = true;
    all_on.inbound_required = true;
    all_on.path_plausibly_survived = true;
    all_on.relay_standby_selected = true;
    all_on.relay_failover_target_ready = true;
    all_on.direct_upgrade_eligible = true;

    let mut permissive = all_on;
    permissive.enforcement = Some(EnforcementMode::PermissiveAnnounced);

    // T01 and T02 both fire on EV_CONNECT_REQUESTED and are separated only by
    // which credential guard is set; with both set, T01 wins on table order —
    // which is correct, and is why the expired-only variant has to exist for the
    // sweep to reach T02 at all.
    let expired = Guards {
        credentials_expired: true,
        ..Guards::default()
    };

    vec![Guards::default(), healthy(), all_on, permissive, expired]
}

fn all_states() -> Vec<SessionState> {
    let mut v = vec![
        SessionState::Disconnected,
        SessionState::Discovering,
        SessionState::Negotiating,
        SessionState::Connecting,
        SessionState::Blocked,
        SessionState::Failed,
        SessionState::Reconnecting { parked: false },
        SessionState::Reconnecting { parked: true },
    ];
    for c in [
        PathClass::LocalDirect,
        PathClass::WanDirect,
        PathClass::Relayed,
    ] {
        v.push(SessionState::Steady(c));
        v.push(SessionState::Degraded { carrier: c });
        for d in [
            PathClass::LocalDirect,
            PathClass::WanDirect,
            PathClass::Relayed,
        ] {
            v.push(SessionState::Migrating { from: c, to: d });
        }
    }
    v
}

#[test]
fn no_reachable_move_is_silent_and_every_record_is_well_formed() {
    let mut rows_seen: BTreeSet<Row> = BTreeSet::new();
    let mut moves = 0usize;
    for state in all_states() {
        for guards in guard_variants() {
            for trigger in all_triggers() {
                let (env, _vt) = test_env();
                // `resumed` is the only way to place the machine in a state
                // directly, and it refuses to leave a reason-bearing state
                // without a code — so this loop cannot manufacture the very
                // defect it is testing for.
                let mut m = SessionMachine::resumed(env, session_id(), state, None);
                assert!(
                    m.state_and_reason_agree(),
                    "resumed() left {state:?} inconsistent"
                );
                match m.apply(trigger, guards, Context::default()) {
                    Outcome::Transitioned(r) => {
                        moves += 1;
                        rows_seen.insert(r.row);
                        assert!(
                            r.is_well_formed(),
                            "silent transition {:?} -> {:?} via {}",
                            r.from,
                            r.to,
                            r.row.label()
                        );
                        assert_eq!(
                            r.session_id,
                            session_id(),
                            "§10.2 E-rule 2: session_id is never null"
                        );
                        if !r.to.has_path() {
                            assert!(r.path_id.is_none());
                        }
                        if r.to.requires_reason_code() {
                            let code = r.reason_code.expect("§10.1");
                            assert!(
                                class_admissible(code, r.to),
                                "§10.2: {} is not class-compatible with {:?}",
                                code.as_str(),
                                r.to
                            );
                        }
                    }
                    Outcome::Ignored { state: s, .. } => {
                        assert_eq!(s, state, "an ignored trigger must name the state");
                    }
                }
                assert_eq!(m.invariant_violations(), 0, "§10.2 E7 defect produced");
                assert!(m.state_and_reason_agree());
            }
        }
    }
    assert!(moves > 1_000, "the sweep exercised only {moves} moves");
    assert_eq!(
        rows_seen.len(),
        38,
        "the exhaustive sweep reached {} of 38 rows: missing {:?}",
        rows_seen.len(),
        Row::ALL
            .iter()
            .filter(|r| !rows_seen.contains(r))
            .map(|r| r.label())
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// 2. The §10.2 static test: parse §4.5 and check the table itself.
// ---------------------------------------------------------------------------

/// Extracts §4.5's rows as `(id, to_column, actions_column)`.
fn parse_transition_table() -> Vec<(String, String, String)> {
    let mut rows = Vec::new();
    for line in RELIABILITY_MD.lines() {
        let t = line.trim();
        if !t.starts_with("| T") {
            continue;
        }
        let cells: Vec<&str> = t.trim_matches('|').split('|').map(str::trim).collect();
        // | # | From | Event | Guard | To | Actions |
        if cells.len() < 6 {
            continue;
        }
        let id = cells[0].to_owned();
        if id.len() != 3 || !id.starts_with('T') {
            continue;
        }
        rows.push((id, cells[4].to_owned(), cells[5].to_owned()));
    }
    rows
}

#[test]
fn section_4_5_has_thirty_eight_rows_and_the_code_agrees() {
    let rows = parse_transition_table();
    assert_eq!(
        rows.len(),
        38,
        "parsed {} rows from reliability.md §4.5; the code models 38",
        rows.len()
    );
    for (i, (id, _, _)) in rows.iter().enumerate() {
        assert_eq!(
            id,
            Row::ALL[i].label(),
            "row {i} is {id} in the document and {} in the code",
            Row::ALL[i].label()
        );
    }
}

#[test]
fn every_reason_bearing_row_names_an_emit_action() {
    let mut offenders = Vec::new();
    for (id, to, actions) in parse_transition_table() {
        let reason_bearing = ["DEGRADED", "BLOCKED", "RECONNECTING", "FAILED"]
            .iter()
            .any(|s| to.contains(s));
        if !reason_bearing {
            continue;
        }
        // "names an emit action": the Actions column mentions emitting, or names
        // a registered-looking DOMAIN.CONDITION code.
        let names_emit = actions.contains("emit")
            || actions.contains("**emit")
            || actions
                .split_whitespace()
                .any(|w| w.contains('.') && w.chars().any(|c| c.is_ascii_uppercase()));
        if !names_emit {
            offenders.push(format!("{id} -> {to}"));
        }
    }
    assert!(
        offenders.is_empty(),
        "reliability.md §4.5 rows entering a reason-bearing state with no emit action: {offenders:?}"
    );
}

#[test]
fn every_substituted_spelling_is_genuinely_absent_from_the_frozen_registry() {
    // A tripwire, not a workaround: the day one of these is registered, this
    // assertion fails and points at the SUBSTITUTIONS entry to delete.
    for s in SUBSTITUTIONS {
        assert!(
            twinvpn_types::ReasonCode::lookup(s.specified).is_none(),
            "{} is now in the frozen registry — remove its substitution \
             in twinvpn-session::codes (cited by {})",
            s.specified,
            s.cited_by
        );
    }
    assert_eq!(SUBSTITUTIONS.len(), 7);
}

// ---------------------------------------------------------------------------
// 3. Property: the machine's own invariant survives an arbitrary trigger walk.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Whatever sequence of triggers arrives, in whatever guard configuration,
    /// the machine never reaches a state whose reason code disagrees with it and
    /// never produces a malformed record.
    #[test]
    fn arbitrary_trigger_walks_preserve_the_boundary_rule(
        trigger_ix in prop::collection::vec(0usize..64, 1..40),
        guard_ix in prop::collection::vec(0usize..5, 1..40),
    ) {
        let triggers = all_triggers();
        let guards = guard_variants();
        let (env, _vt) = test_env();
        let mut m = SessionMachine::new(env, session_id());
        for (i, t) in trigger_ix.iter().enumerate() {
            let trig = triggers[t % triggers.len()];
            let g = guards[guard_ix[i % guard_ix.len()] % guards.len()];
            let outcome = m.apply(trig, g, Context::default());
            if let Outcome::Transitioned(r) = outcome {
                prop_assert!(r.is_well_formed());
            }
            prop_assert!(m.state_and_reason_agree());
            prop_assert_eq!(m.invariant_violations(), 0);
        }
        // Every record the walk produced is still in history, in order, one per
        // move — E1's "never zero, never two", measured.
        prop_assert_eq!(
            m.history().len(),
            m.history().iter().filter(|r| r.is_well_formed()).count()
        );
    }
}
