//! Adversarial tests for the two things a SILENCE phase's emptiness cannot
//! establish on its own: that the oracle was still listening, and that the two
//! egress paths were ever distinguishable.
//!
//! Every test starts from [`golden`] — a complete session that PASSES — and
//! mutates exactly ONE property. That is the whole discipline here: if a test
//! fails, the property it mutated is the reason, and nothing else can be.
//!
//! The failure mode all of this exists for: an oracle whose listener died
//! records zero arrivals during the armed window, which is byte-for-byte what a
//! perfect kill switch records. `tests/verdict.rs` keeps a session that proved
//! nothing from passing. This file keeps a session whose MEASUREMENT died from
//! passing.

mod common;

use common::{golden, kill_sentinel, obs, PROTECTED_V4, PROTECTED_V6};
use twinoracle::{Family, PathKind, SentinelBeat, Verdict};

// ===========================================================================
// The clean sweep
// ===========================================================================

/// Zero forbidden arrivals + all three sentinels continuous + attempts over the
/// floor + positive controls + distinguishable paths. This is the ONLY shape
/// that may pass, and every other test in this file is it minus one property.
#[test]
fn zero_leaks_healthy_sentinels_and_sufficient_attempts_pass() {
    let r = golden().report();
    assert_eq!(r.verdict, Verdict::Pass, "{r:#?}");

    assert_eq!(
        (r.ipv4_observed, r.ipv6_observed, r.dns_observed),
        (0, 0, 0)
    );
    assert_eq!(
        (r.ipv4_attempts, r.ipv6_attempts, r.dns_attempts),
        (120, 120, 120)
    );
    assert!(r.ipv4_sentinel_continuous);
    assert!(r.ipv6_sentinel_continuous);
    assert!(r.dns_sentinel_continuous);
    assert_eq!(r.ipv4_identity_distinct, Some(true));
    assert_eq!(r.ipv6_identity_distinct, Some(true));
    assert_eq!(r.dns_identity_distinct, Some(true));
    assert!(!r.dns_resolver_identity_ambiguous);
    assert_eq!(r.run_attempt, "1");
    assert!(r.failures.is_empty() && r.inconclusive.is_empty(), "{r:#?}");
}

/// The field names are a cross-process contract with
/// `build/acceptance/report.py`. A rename here is a silently missing key there,
/// and a missing key is exactly the shape that reads as "not a leak".
#[test]
fn the_report_serializes_every_contract_field_under_its_exact_name() {
    let json = serde_json::to_value(golden().report()).expect("serialisable");
    for key in [
        "run_attempt",
        "ipv4_attempts",
        "ipv6_attempts",
        "dns_attempts",
        "ipv4_observed",
        "ipv6_observed",
        "dns_observed",
        "ipv4_sentinel_continuous",
        "ipv6_sentinel_continuous",
        "dns_sentinel_continuous",
        "ipv4_identity_distinct",
        "ipv6_identity_distinct",
        "dns_identity_distinct",
        "dns_resolver_identity_ambiguous",
    ] {
        assert!(json.get(key).is_some(), "the report must carry `{key}`");
    }
    assert_eq!(json["verdict"], "PASS");
}

// ===========================================================================
// Workstream 1 — the sentinel died
// ===========================================================================

/// THE TEST THIS FILE EXISTS FOR. The oracle stops listening partway through
/// the armed window. Nothing arrives, because nothing COULD arrive. That is not
/// a kill switch working; it is a measurement that stopped.
#[test]
fn an_oracle_that_dies_during_silence_is_inconclusive_and_never_a_pass() {
    let mut s = golden();
    kill_sentinel(&mut s, None);

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Inconclusive, "{r:#?}");
    assert!(
        r.failures.is_empty(),
        "a dead oracle is not a product defect: {r:#?}"
    );
    assert!(!r.ipv4_sentinel_continuous);
    assert!(!r.ipv6_sentinel_continuous);
    assert!(!r.dns_sentinel_continuous);
    assert!(r.inconclusive.iter().any(|m| m.contains("went quiet")));
}

/// Each listener is a separate task and each can die alone. One dead family is
/// enough, because the criterion claims all three.
#[test]
fn the_ipv4_sentinel_dying_alone_is_inconclusive() {
    let mut s = golden();
    kill_sentinel(&mut s, Some(Family::Ipv4));

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Inconclusive, "{r:#?}");
    assert!(!r.ipv4_sentinel_continuous);
    assert!(r.ipv6_sentinel_continuous, "only ipv4 was mutated");
    assert!(r.dns_sentinel_continuous, "only ipv4 was mutated");
    assert!(r
        .inconclusive
        .iter()
        .any(|m| m.starts_with("the ipv4 sentinel")));
}

#[test]
fn the_ipv6_sentinel_dying_alone_is_inconclusive() {
    let mut s = golden();
    kill_sentinel(&mut s, Some(Family::Ipv6));

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Inconclusive, "{r:#?}");
    assert!(!r.ipv6_sentinel_continuous);
    assert!(r.ipv4_sentinel_continuous && r.dns_sentinel_continuous);
    assert!(r
        .inconclusive
        .iter()
        .any(|m| m.starts_with("the ipv6 sentinel")));
}

#[test]
fn the_dns_sentinel_dying_alone_is_inconclusive() {
    let mut s = golden();
    kill_sentinel(&mut s, Some(Family::Dns));

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Inconclusive, "{r:#?}");
    assert!(!r.dns_sentinel_continuous);
    assert!(r.ipv4_sentinel_continuous && r.ipv6_sentinel_continuous);
    assert!(r
        .inconclusive
        .iter()
        .any(|m| m.starts_with("the dns sentinel")));
}

/// A session with no sentinel section at all — an older report, a probe that
/// never wired it up, a hand-assembled JSON. The absent key must read as "no
/// evidence", not as "no gaps". A silent `true` here would reopen the entire
/// hole this workstream closed.
#[test]
fn a_session_with_no_sentinel_section_at_all_is_inconclusive_never_a_silent_true() {
    let mut s = golden();
    s.sentinel = None;

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Inconclusive, "{r:#?}");
    assert!(!r.ipv4_sentinel_continuous);
    assert!(!r.ipv6_sentinel_continuous);
    assert!(!r.dns_sentinel_continuous);
    assert!(r.sentinel_beats.is_empty());
    assert!(r
        .inconclusive
        .iter()
        .any(|m| m.contains("no sentinel evidence at all")));

    // And the same through the wire, because that is how `report.py` sees it.
    let json = serde_json::to_value(r).expect("serialisable");
    assert_eq!(json["ipv4_sentinel_continuous"], false);
    assert_eq!(json["ipv6_sentinel_continuous"], false);
    assert_eq!(json["dns_sentinel_continuous"], false);
}

// ===========================================================================
// Workstream 1 — the probe barely ran
// ===========================================================================

/// A window nothing was sent into is silent for the wrong reason.
#[test]
fn zero_dut_probe_attempts_is_inconclusive() {
    let mut s = golden();
    s.attempts.insert(Family::Ipv4, 0);

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Inconclusive, "{r:#?}");
    assert_eq!(r.ipv4_attempts, 0);
    assert!(r
        .inconclusive
        .iter()
        .any(|m| m.contains("0 ipv4 probe attempt(s)")));
}

/// Below the configured floor, but not zero: a probe that fired twice and then
/// crashed proves as little as one that never fired.
#[test]
fn dut_probe_attempts_below_the_configured_minimum_are_inconclusive() {
    let mut s = golden();
    s.attempts.insert(Family::Dns, 5);

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Inconclusive, "{r:#?}");
    assert_eq!(r.dns_attempts, 5);
    assert!(r
        .inconclusive
        .iter()
        .any(|m| m.contains("5 dns probe attempt(s)") && m.contains("minimum of 30")));
}

// ===========================================================================
// Workstream 1 — forbidden arrivals, and precedence
// ===========================================================================

#[test]
fn a_forbidden_ipv4_arrival_during_silence_fails() {
    let mut s = golden();
    s.record(obs(Family::Ipv4, PROTECTED_V4, 350, None));

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Fail, "{r:#?}");
    assert_eq!(r.ipv4_observed, 1);
    assert_eq!((r.ipv6_observed, r.dns_observed), (0, 0));
    assert_eq!(r.unauthorized_observations.len(), 1);
}

#[test]
fn a_forbidden_ipv6_arrival_during_silence_fails() {
    let mut s = golden();
    s.record(obs(Family::Ipv6, PROTECTED_V6, 350, None));

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Fail, "{r:#?}");
    assert_eq!(r.ipv6_observed, 1);
    assert_eq!((r.ipv4_observed, r.dns_observed), (0, 0));
}

#[test]
fn a_forbidden_dns_arrival_during_silence_fails() {
    let mut s = golden();
    s.record(obs(
        Family::Dns,
        PROTECTED_V4,
        350,
        Some(PathKind::Protected),
    ));

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Fail, "{r:#?}");
    assert_eq!(r.dns_observed, 1);
    assert_eq!((r.ipv4_observed, r.ipv6_observed), (0, 0));
}

/// PRECEDENCE. A run that both leaked and lost its sentinel is a FAIL. "The
/// measurement was flawed" must never launder an observed packet into a softer
/// verdict — the packet arrived either way, and INCONCLUSIVE is the verdict a
/// broken rig gets, not the verdict a leak gets when the rig also broke.
#[test]
fn a_leak_outranks_a_dead_sentinel_and_the_verdict_is_fail() {
    let mut s = golden();
    s.record(obs(Family::Ipv4, PROTECTED_V4, 350, None));
    kill_sentinel(&mut s, None);

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Fail, "{r:#?}");
    assert_eq!(r.ipv4_observed, 1);
    assert!(!r.ipv4_sentinel_continuous, "the sentinel really was dead");
    assert!(
        !r.inconclusive.is_empty(),
        "the broken measurement is still reported, it just does not decide"
    );
}

// ===========================================================================
// Workstream 1 — the sentinel must actually be independent
// ===========================================================================

/// The sentinel token is deliberately never handed to the device — it comes
/// from `POST /v1/sessions/{id}/sentinel`, which only the sentinel operator
/// calls. But a token that leaks is a token that leaks, and a device beating it
/// from its own address during the armed window would otherwise be filed as
/// PROOF THE ORACLE WAS ALIVE.
///
/// INCONCLUSIVE rather than FAIL, deliberately: a sentinel behind the same NAT
/// as the device presents the device's public address too, so the oracle cannot
/// tell the two apart and must not accuse the product on the strength of a
/// network layout. INCONCLUSIVE blocks the gate exactly as a failure does.
#[test]
fn a_sentinel_beat_from_the_devices_own_address_is_not_independent_evidence() {
    let mut s = golden();
    let sentinel = s.sentinel.as_mut().expect("the golden session has one");
    sentinel.beats.push(SentinelBeat {
        family: Family::Ipv4,
        source: PROTECTED_V4.parse().expect("test address"),
        at_ms: 350,
    });

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Inconclusive, "{r:#?}");
    assert!(
        r.failures.is_empty(),
        "a sentinel sharing the device's egress path is not a product defect: {r:#?}"
    );
    assert!(r
        .inconclusive
        .iter()
        .any(|m| m.contains("an address the device itself was observed egressing from")));
}

/// The same beat outside the armed window is not a leak, but it is still not
/// independent evidence — it must not be able to paper over a real gap.
#[test]
fn a_device_sourced_beat_does_not_count_towards_continuity() {
    let mut s = golden();
    kill_sentinel(&mut s, Some(Family::Ipv4));
    let sentinel = s.sentinel.as_mut().expect("the golden session has one");
    // Dense enough to close the gap it just opened, if it counted. It does not.
    for at_ms in [320, 340, 360, 380] {
        sentinel.beats.push(SentinelBeat {
            family: Family::Ipv4,
            source: PROTECTED_V4.parse().expect("test address"),
            at_ms,
        });
    }

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Inconclusive, "{r:#?}");
    assert!(
        !r.ipv4_sentinel_continuous,
        "a beat from the device cannot establish that the oracle was listening"
    );
    assert_eq!(r.ipv4_observed, 0, "it was never counted as a leak either");
}

/// A DNS beat arrives from a RESOLVER whether the sentinel or the device sent
/// it, so its source address cannot separate the two — the same reason `lib.rs`
/// keeps DNS out of the phase source sets. Applying the address check to DNS
/// would drop every sentinel beat that shares a recursive resolver with the
/// device and report a dead sentinel that was alive the whole time.
#[test]
fn the_independence_check_does_not_apply_to_dns_beats() {
    let mut s = golden();
    let sentinel = s.sentinel.as_mut().expect("the golden session has one");
    for beat in sentinel
        .beats
        .iter_mut()
        .filter(|b| b.family == Family::Dns)
    {
        beat.source = PROTECTED_V4.parse().expect("test address");
    }

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Pass, "{r:#?}");
    assert!(r.dns_sentinel_continuous);
}

/// The sentinel's host is unverifiable by construction, so it travels into the
/// report to be read rather than trusted.
#[test]
fn the_sentinel_host_is_carried_into_the_report() {
    let r = golden().report();
    assert_eq!(r.sentinel_host.as_deref(), Some("sentinel-host.example"));
}
