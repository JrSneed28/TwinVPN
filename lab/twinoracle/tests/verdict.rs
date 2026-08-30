//! The verdict is the whole product. These tests are the runnable check that it
//! cannot be talked into a PASS by a sequence that proved nothing.
//!
//! The failure mode they exist for: an oracle nobody could reach records zero
//! observations during the armed window, which is byte-for-byte what a perfect
//! kill switch records. Every test below is about keeping those two apart.

use std::net::IpAddr;

use twinoracle::{
    Expectation, Family, Observation, PathKind, Phase, ResolverEntry, SentinelBeat,
    SentinelEvidence, Session, Verdict,
};

/// A session already carrying the evidence a PASS now requires: a live
/// sentinel, DUT attempt counters over the configured floor, and a resolver map
/// that gives the two DNS paths distinguishable identities. Every test below
/// starts from this and mutates ONE property, so a failing assertion names the
/// property rather than the scaffolding.
fn session() -> Session {
    let mut s = Session::new(
        "sess".into(),
        "tok".into(),
        "deadbeef".into(),
        "42".into(),
        "windows".into(),
        "WINDOWS-WFP-KILLSWITCH".into(),
        0,
    );
    s.run_attempt = "1".into();
    // Beats every 50ms across the whole window every test below operates in,
    // with 60ms of tolerance. Any SILENCE phase inside 0..=600 is covered.
    let mut beats = Vec::new();
    for at in (0..=600).step_by(50) {
        for family in Family::ALL {
            beats.push(SentinelBeat {
                family,
                source: "192.0.2.200".parse().unwrap(),
                at_ms: at,
            });
        }
    }
    s.sentinel = Some(SentinelEvidence {
        token: "sentinel-tok".into(),
        max_gap_ms: 60,
        host: Some("sentinel-host.example".into()),
        beats,
    });
    for family in Family::ALL {
        s.attempts.insert(family, 120);
        s.attempt_minimums.insert(family, 30);
    }
    s.resolver_map.insert(
        "198.51.100.10".parse().unwrap(),
        ResolverEntry {
            id: "isp-recursive".into(),
            path: PathKind::Unprotected,
        },
    );
    s.resolver_map.insert(
        "203.0.113.9".parse().unwrap(),
        ResolverEntry {
            id: "twinvpn-dns".into(),
            path: PathKind::Protected,
        },
    );
    s
}

fn phase(name: &str, exp: Expectation, at: u64) -> Phase {
    Phase {
        name: name.into(),
        expectation: exp,
        started_at_ms: at,
        ended_at_ms: None,
        require_families: Family::ALL.to_vec(),
        sources_disjoint_from: None,
        sources_subset_of: None,
        // The path each named phase drives traffic over, so the oracle can
        // collect protected and unprotected source addresses and check the two
        // sets are actually distinguishable.
        path: match name {
            "BASELINE" => Some(PathKind::Unprotected),
            "TUNNELLED" | "RESTORED" => Some(PathKind::Protected),
            _ => None,
        },
    }
}

fn obs(family: Family, source: &str, at: u64) -> Observation {
    Observation {
        family,
        source: source.parse::<IpAddr>().unwrap(),
        at_ms: at,
        seq: at.to_string(),
        path_tag: None,
    }
}

/// Every family live in the baseline, every family live through the tunnel from
/// a different address, silence while armed, and resumption only through the
/// tunnel address. This is the ten-step sequence, and it is the only shape that
/// may pass.
#[test]
fn the_full_kill_switch_sequence_passes() {
    let mut s = session();
    s.begin_phase(phase("BASELINE", Expectation::Observe, 100));
    for f in Family::ALL {
        s.record(obs(f, "198.51.100.10", 110));
    }
    let mut tunnelled = phase("TUNNELLED", Expectation::Observe, 200);
    tunnelled.sources_disjoint_from = Some("BASELINE".into());
    s.begin_phase(tunnelled);
    for f in Family::ALL {
        s.record(obs(f, "203.0.113.9", 210));
    }
    s.begin_phase(phase("ARMED", Expectation::Silence, 300));
    let mut restored = phase("RESTORED", Expectation::Observe, 400);
    restored.sources_subset_of = Some("TUNNELLED".into());
    s.begin_phase(restored);
    for f in Family::ALL {
        s.record(obs(f, "203.0.113.9", 410));
    }
    s.close(500);

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Pass, "{:#?}", r);
    assert!(r.unauthorized_observations.is_empty());
    assert_eq!(r.families_proven_live.len(), 3);
}

/// One packet during the armed window is one leak, and it is named.
#[test]
fn a_single_observation_while_armed_fails_and_is_recorded_in_full() {
    let mut s = session();
    s.begin_phase(phase("BASELINE", Expectation::Observe, 100));
    for f in Family::ALL {
        s.record(obs(f, "198.51.100.10", 110));
    }
    s.begin_phase(phase("ARMED", Expectation::Silence, 300));
    s.record(obs(Family::Ipv6, "2001:db8::1", 350));
    s.close(500);

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Fail);
    assert_eq!(r.unauthorized_observations.len(), 1);
    assert_eq!(r.unauthorized_observations[0].family, Family::Ipv6);
    assert!(r.failures.iter().any(|f| f.contains("SILENCE")));
}

/// THE TEST THIS FILE EXISTS FOR. Nothing was ever observed, so the armed
/// window's silence is silence about nothing. It must not read as a pass.
#[test]
fn silence_with_no_positive_control_is_inconclusive_and_never_a_pass() {
    let mut s = session();
    s.begin_phase(phase("BASELINE", Expectation::Observe, 100));
    s.begin_phase(phase("ARMED", Expectation::Silence, 300));
    s.close(500);

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Inconclusive);
    assert!(r.failures.is_empty(), "this is not a product defect");
    assert!(r
        .inconclusive
        .iter()
        .any(|m| m.contains("positive control") || m.contains("never observed")));
}

/// IPv4 and DNS proven live, IPv6 never seen: the run cannot claim IPv6 was
/// blocked, because it never showed IPv6 could get out in the first place.
#[test]
fn a_family_that_was_never_live_cannot_be_claimed_blocked() {
    let mut s = session();
    let mut baseline = phase("BASELINE", Expectation::Observe, 100);
    baseline.require_families = vec![Family::Ipv4, Family::Dns];
    s.begin_phase(baseline);
    s.record(obs(Family::Ipv4, "198.51.100.10", 110));
    s.record(obs(Family::Dns, "192.0.2.53", 111));
    s.begin_phase(phase("ARMED", Expectation::Silence, 300));
    s.close(500);

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Inconclusive);
    assert!(r.inconclusive.iter().any(|m| m.starts_with("ipv6")));
}

/// The tunnel phase egressing from the baseline address means nothing entered
/// the tunnel — a green "connected" state over an unprotected path.
#[test]
fn tunnelled_egress_from_the_baseline_address_does_not_count_as_tunnelled() {
    let mut s = session();
    s.begin_phase(phase("BASELINE", Expectation::Observe, 100));
    for f in Family::ALL {
        s.record(obs(f, "198.51.100.10", 110));
    }
    let mut tunnelled = phase("TUNNELLED", Expectation::Observe, 200);
    tunnelled.sources_disjoint_from = Some("BASELINE".into());
    s.begin_phase(tunnelled);
    for f in Family::ALL {
        s.record(obs(f, "198.51.100.10", 210));
    }
    s.begin_phase(phase("ARMED", Expectation::Silence, 300));
    s.close(500);

    let r = s.report();
    assert_ne!(r.verdict, Verdict::Pass);
    assert!(r
        .inconclusive
        .iter()
        .any(|m| m.contains("did not move into the tunnel")));
}

/// Step 9: traffic must resume ONLY through TwinVPN. Resumption from the
/// unprotected address is a restore that bypassed the tunnel.
#[test]
fn restored_egress_outside_the_tunnel_source_set_is_refused() {
    let mut s = session();
    s.begin_phase(phase("BASELINE", Expectation::Observe, 100));
    for f in Family::ALL {
        s.record(obs(f, "198.51.100.10", 110));
    }
    let mut tunnelled = phase("TUNNELLED", Expectation::Observe, 200);
    tunnelled.sources_disjoint_from = Some("BASELINE".into());
    s.begin_phase(tunnelled);
    for f in Family::ALL {
        s.record(obs(f, "203.0.113.9", 210));
    }
    s.begin_phase(phase("ARMED", Expectation::Silence, 300));
    let mut restored = phase("RESTORED", Expectation::Observe, 400);
    restored.sources_subset_of = Some("TUNNELLED".into());
    s.begin_phase(restored);
    for f in Family::ALL {
        s.record(obs(f, "198.51.100.10", 410));
    }
    s.close(500);

    let r = s.report();
    assert_ne!(r.verdict, Verdict::Pass);
    assert!(r
        .inconclusive
        .iter()
        .any(|m| m.contains("did not resume through TwinVPN")));
}

/// Phases are back-to-back by construction, so an observation cannot land in a
/// gap between the tunnel dying and the armed window opening.
#[test]
fn a_new_phase_closes_the_previous_one_so_there_is_no_gap_to_leak_into() {
    let mut s = session();
    s.begin_phase(phase("BASELINE", Expectation::Observe, 100));
    for f in Family::ALL {
        s.record(obs(f, "198.51.100.10", 110));
    }
    s.begin_phase(phase("ARMED", Expectation::Silence, 200));
    // Arrives after ARMED opened and before anything else did.
    s.record(obs(Family::Ipv4, "198.51.100.10", 250));
    s.close(300);

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Fail);
    assert_eq!(r.unauthorized_observations.len(), 1);
}

/// An unclosed session may still be receiving, so its silence is provisional.
#[test]
fn an_unclosed_session_is_never_a_pass() {
    let mut s = session();
    s.begin_phase(phase("BASELINE", Expectation::Observe, 100));
    for f in Family::ALL {
        s.record(obs(f, "198.51.100.10", 110));
    }
    s.begin_phase(phase("ARMED", Expectation::Silence, 200));

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Inconclusive);
    assert!(r.inconclusive.iter().any(|m| m.contains("never closed")));
}

/// A session that never armed anything asked no question. It must not pass on
/// the strength of a working baseline.
#[test]
fn a_session_with_no_silence_phase_asked_nothing() {
    let mut s = session();
    s.begin_phase(phase("BASELINE", Expectation::Observe, 100));
    for f in Family::ALL {
        s.record(obs(f, "198.51.100.10", 110));
    }
    s.close(200);

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Inconclusive);
    assert!(r
        .inconclusive
        .iter()
        .any(|m| m.contains("no SILENCE phase")));
}
