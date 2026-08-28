//! **S-10 is never a gate**, asserted as an absence.
//!
//! `relay.proto`'s `RelayHealth`: "A CLIENT'S OWN PROBE FAILURE ALWAYS OUTRANKS A
//! 'HEALTHY' REPORT. Per `docs/reliability.md` §4.1 this MUST NOT gate a
//! connection attempt — it contributes a score delta to selection and nothing
//! more." ADR-0006 §11.3 rule 1 says the same from the selection side.
//!
//! A behavioural test can only show that today's callers do not gate. What has to
//! be true is that **no API here can be used to gate**, so the checks are about
//! what does not exist:
//!
//! - no method returning `bool` about usability;
//! - no method returning a filtered or reduced set of relays;
//! - the only thing a `HealthState` produces is a number.
//!
//! Plus the behavioural half that matters most: **a health-service outage costs a
//! ranking exactly zero.**

use std::path::Path;

use twinvpn_relay_health::aggregate::{Aggregate, HealthState, SelfReport, Thresholds};

/// The canonical `HealthState`'s own source, in `twinvpn-types`.
///
/// Read across the workspace boundary deliberately: this guard is about a
/// property of the enum, and after R-14 the enum is defined once, elsewhere. A
/// guard that stopped at this crate's own `src/` would report success the
/// moment the thing it guards moved.
fn canonical_source() -> String {
    let p =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../core/crates/twinvpn-types/src/state.rs");
    std::fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!(
            "read the canonical HealthState at {}: {e}. If twinvpn-types moved, \
             this guard must follow it rather than be deleted.",
            p.display()
        )
    })
}

fn source(name: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(name);
    let s = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    let end = s.find("#[cfg(test)]").unwrap_or(s.len());
    s[..end]
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("//") {
                ""
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn no_api_here_can_be_used_as_a_gate() {
    let src = source("aggregate.rs");
    for forbidden in [
        "fn is_healthy",
        "fn is_usable",
        "fn is_available",
        "fn admits",
        "fn allow",
        "fn candidates",
        "fn filter",
        "fn usable_relays",
        "impl From<HealthState> for bool",
    ] {
        assert!(
            !src.contains(forbidden),
            "aggregate.rs provides `{forbidden}`. S-10 MUST NOT gate a connection \
             attempt (relay.proto, reliability §4.1, ADR-0006 §11.3 rule 1); it \
             contributes a score delta and nothing more."
        );
    }
    // The one permitted conversion.
    //
    // R-14 moved the enum itself to `twinvpn-types` — three hand-written copies
    // of one frozen enum was the drift W-20 named — so this module now
    // RE-EXPORTS it. That must not silently defeat the guard: the assertion
    // follows the definition to its new home rather than passing vacuously
    // because the text left this file.
    assert!(
        src.contains("pub use twinvpn_types::state::HealthState;"),
        "the canonical enum is the one this service must use; a local copy is \
         the R-14 divergence returning"
    );
    let canonical = canonical_source();
    assert!(canonical.contains("pub const fn score_delta(self) -> i32"));
    for forbidden in [
        "fn is_healthy",
        "fn is_usable",
        "fn is_available",
        "fn may_connect",
        "fn may_attempt",
        "impl From<HealthState> for bool",
    ] {
        assert!(
            !canonical.contains(forbidden),
            "twinvpn-types' HealthState provides `{forbidden}`: S-10 MUST NOT gate \
             a connection attempt, wherever the enum lives"
        );
    }

    // And the sharper form: no `bool` is ever returned for a RELAY. The only two
    // `-> bool` methods in the module are `Aggregate::is_empty` — a collection
    // predicate about this process's own state — and nothing else. A `bool`
    // keyed by relay_id is precisely the shape of a gate.
    let relay_keyed_bools = src
        .lines()
        .filter(|l| l.contains("-> bool"))
        .filter(|l| l.contains("relay_id") || l.contains("relay"))
        .count();
    assert_eq!(
        relay_keyed_bools, 0,
        "aggregate.rs returns a bool for a relay: that is a gate however it is named"
    );
    assert_eq!(
        src.matches("-> bool").count(),
        1,
        "the only bool here is Aggregate::is_empty; a second one needs a reason"
    );
}

#[test]
fn a_health_state_can_only_become_a_number() {
    // Every state maps to an i32 delta. There is no other exit.
    for s in [
        HealthState::Healthy,
        HealthState::Degraded,
        HealthState::Unhealthy,
        HealthState::Unknown,
    ] {
        let _delta: i32 = s.score_delta();
        let _label: &str = s.as_str();
    }
    assert_eq!(HealthState::Unhealthy.score_delta(), -150);
}

#[test]
fn the_health_service_being_down_costs_a_ranking_exactly_zero() {
    // The property the task names: "a health service outage must degrade ranking
    // quality and nothing else."
    let empty = Aggregate::new(Thresholds::default());
    for n in 0..64_u8 {
        let id = [n; twinvpn_schema::limits::RELAY_ID_BYTES];
        let state = empty.state_for(&id, 999_999_999);
        assert_eq!(state, HealthState::Unknown);
        assert_eq!(
            state.score_delta(),
            0,
            "an unobserved relay must cost the same as a healthy one, or one \
             service's outage becomes a fleet-wide ranking distortion"
        );
    }
}

#[test]
fn a_previously_healthy_fleet_going_unobserved_loses_no_ground() {
    // The sharper version: a fleet that WAS observed and then goes unobserved
    // must end up exactly where an unobserved fleet is — not worse.
    let mut a = Aggregate::new(Thresholds::default());
    for n in 0..4_u8 {
        a.observe(SelfReport {
            relay_id: [n; twinvpn_schema::limits::RELAY_ID_BYTES],
            load_class: 0,
            reachable: true,
            probe_rtt_ms: Some(5),
            observed_at_ms: 0,
        });
    }
    let fresh: i32 = (0..4_u8)
        .map(|n| {
            a.state_for(&[n; twinvpn_schema::limits::RELAY_ID_BYTES], 0)
                .score_delta()
        })
        .sum();
    let stale: i32 = (0..4_u8)
        .map(|n| {
            a.state_for(&[n; twinvpn_schema::limits::RELAY_ID_BYTES], 10_000_000)
                .score_delta()
        })
        .sum();
    assert_eq!(fresh, 0);
    assert_eq!(stale, 0, "going unobserved must not push relays down");
}

#[test]
fn an_unhealthy_relay_is_still_returned_and_still_a_candidate() {
    // §11.3 rule 1: selection returns "a total order over the whole candidate
    // set, never a filtered subset". This service never removes anything —
    // `state_for` answers for any relay id, including one it has never seen.
    let mut a = Aggregate::new(Thresholds::default());
    a.observe(SelfReport {
        relay_id: [1; twinvpn_schema::limits::RELAY_ID_BYTES],
        load_class: 3,
        reachable: false,
        probe_rtt_ms: None,
        observed_at_ms: 0,
    });
    assert_eq!(
        a.state_for(&[1; twinvpn_schema::limits::RELAY_ID_BYTES], 0),
        HealthState::Unhealthy
    );
    // And an id it has never heard of answers too, rather than erroring.
    assert_eq!(
        a.state_for(&[99; twinvpn_schema::limits::RELAY_ID_BYTES], 0),
        HealthState::Unknown
    );
}

#[test]
fn nothing_here_is_durable() {
    // S-10: EVENTUAL, non-durable, recomputed. No datastore, no file, no replica.
    for name in ["aggregate.rs", "config.rs", "lib.rs"] {
        let src = source(name);
        for forbidden in [
            "sqlx",
            "std::fs::write",
            "File::create",
            "OpenOptions",
            "to_writer",
        ] {
            assert!(
                !src.contains(forbidden),
                "{name} contains `{forbidden}`: S-10 is non-durable and recomputed"
            );
        }
    }
}

#[test]
fn no_per_session_or_peer_pair_label_can_reach_a_report() {
    // relay.proto: "ADR-0015 O-13 forbids any per-session or peer-pair label on
    // relay telemetry, so this message carries no session_id, no pair_tag, and no
    // device identifier."
    let src = source("aggregate.rs");
    for forbidden in [
        "session_id",
        "pair_tag",
        "device_id",
        "flow_id",
        "peer_key_id",
        "correlation_id",
    ] {
        assert!(
            !src.contains(forbidden),
            "aggregate.rs names `{forbidden}` — O-13 forbids it on relay telemetry"
        );
    }
    // And the report's Debug carries only the four permitted dimensions.
    let r = SelfReport {
        relay_id: [1; twinvpn_schema::limits::RELAY_ID_BYTES],
        load_class: 1,
        reachable: true,
        probe_rtt_ms: Some(10),
        observed_at_ms: 5,
    };
    let rendered = format!("{r:?}");
    assert!(rendered.contains("relay_id"));
    assert!(rendered.contains("load_class"));
    assert!(!rendered.contains("session"));
}
