//! The fixture every adversarial test starts from.
//!
//! It is a COMPLETE, VALID, PASSING session: every family proven live over both
//! paths, a silent armed window, a sentinel that covered all of it, attempt
//! counters over the floor, and a resolver map that gives the two DNS paths
//! distinguishable identities.
//!
//! Each test mutates exactly ONE property of it. That is the whole discipline:
//! if a test fails, the property it mutated is the reason, and nothing else
//! can be.

#![allow(dead_code)]

use std::net::IpAddr;

use twinoracle::{
    Expectation, Family, Observation, PathKind, Phase, ResolverEntry, SentinelBeat,
    SentinelEvidence, Session,
};

pub const UNPROTECTED_V4: &str = "198.51.100.10";
pub const UNPROTECTED_V6: &str = "2001:db8:1::10";
pub const PROTECTED_V4: &str = "203.0.113.9";
pub const PROTECTED_V6: &str = "2001:db8:2::9";
/// A resolver that is in no map entry, so the oracle cannot say which path
/// resolved a query that came from it.
pub const UNMAPPED_RESOLVER: &str = "192.0.2.53";

pub const ARMED_START: u64 = 300;
pub const ARMED_END: u64 = 400;
pub const MAX_GAP_MS: u64 = 60;

pub fn ip(s: &str) -> IpAddr {
    s.parse().expect("test address must parse")
}

pub fn phase(name: &str, expectation: Expectation, at: u64, path: Option<PathKind>) -> Phase {
    Phase {
        name: name.into(),
        expectation,
        started_at_ms: at,
        ended_at_ms: None,
        require_families: Family::ALL.to_vec(),
        sources_disjoint_from: None,
        sources_subset_of: None,
        path,
    }
}

pub fn obs(family: Family, source: &str, at: u64, path_tag: Option<PathKind>) -> Observation {
    Observation {
        family,
        source: ip(source),
        at_ms: at,
        seq: format!("{}-{at}", family.as_str()),
        path_tag,
    }
}

/// Beacons for one leg of the sequence: IPv4 and IPv6 from the leg's own
/// addresses, and a DNS query arriving from the leg's own resolver carrying the
/// `path_tag` the probe intended.
pub fn leg(s: &mut Session, at: u64, path: PathKind) {
    let (v4, v6) = match path {
        PathKind::Protected => (PROTECTED_V4, PROTECTED_V6),
        PathKind::Unprotected => (UNPROTECTED_V4, UNPROTECTED_V6),
    };
    s.record(obs(Family::Ipv4, v4, at, None));
    s.record(obs(Family::Ipv6, v6, at, None));
    // The DNS query arrives from the RESOLVER, which is why the resolver map
    // and not the address itself is what gives it an identity.
    s.record(obs(Family::Dns, v4, at, Some(path)));
}

/// A complete, valid, PASSING session: every family proven live over both
/// paths, a silent armed window, a sentinel that covered all of it, attempt
/// counters over the floor, and a resolver map that makes the two DNS paths
/// distinguishable.
pub fn golden() -> Session {
    let mut s = Session::new(
        "sess".into(),
        "probe-tok".into(),
        "deadbeef".into(),
        "42".into(),
        "windows".into(),
        "WINDOWS-WFP-KILLSWITCH".into(),
        0,
    );
    s.run_attempt = "1".into();

    s.begin_phase(phase(
        "BASELINE",
        Expectation::Observe,
        100,
        Some(PathKind::Unprotected),
    ));
    leg(&mut s, 110, PathKind::Unprotected);

    let mut tunnelled = phase(
        "TUNNELLED",
        Expectation::Observe,
        200,
        Some(PathKind::Protected),
    );
    tunnelled.sources_disjoint_from = Some("BASELINE".into());
    s.begin_phase(tunnelled);
    leg(&mut s, 210, PathKind::Protected);

    s.begin_phase(phase("ARMED", Expectation::Silence, ARMED_START, None));

    let mut restored = phase(
        "RESTORED",
        Expectation::Observe,
        ARMED_END,
        Some(PathKind::Protected),
    );
    restored.sources_subset_of = Some("TUNNELLED".into());
    s.begin_phase(restored);
    leg(&mut s, 410, PathKind::Protected);
    s.close(500);

    // The sentinel: an independent source, on its own token, beating at all
    // three listeners every 50ms with 60ms of tolerance.
    let mut beats = Vec::new();
    for at in (0..=600).step_by(50) {
        for family in Family::ALL {
            beats.push(SentinelBeat {
                family,
                source: ip("192.0.2.200"),
                at_ms: at as u64,
            });
        }
    }
    s.sentinel = Some(SentinelEvidence {
        token: "sentinel-tok".into(),
        max_gap_ms: MAX_GAP_MS,
        host: Some("sentinel-host.example".into()),
        beats,
    });
    assert_ne!(
        s.sentinel.as_ref().unwrap().token,
        s.probe_token,
        "the sentinel token MUST differ from the probe token, or every heartbeat proving the \
         oracle was alive during the armed window would be recorded as a leak"
    );

    for family in Family::ALL {
        s.attempts.insert(family, 120);
        s.attempt_minimums.insert(family, 30);
    }

    s.resolver_map.insert(
        ip(UNPROTECTED_V4),
        ResolverEntry {
            id: "isp-recursive".into(),
            path: PathKind::Unprotected,
        },
    );
    s.resolver_map.insert(
        ip(PROTECTED_V4),
        ResolverEntry {
            id: "twinvpn-dns".into(),
            path: PathKind::Protected,
        },
    );
    s
}

/// Silence the sentinel across the armed window — with `family` `None` meaning
/// all three. This is how "the oracle process died mid-run" is modelled: the
/// beats simply stop, exactly as they would if the accept loop had panicked.
pub fn kill_sentinel(s: &mut Session, family: Option<Family>) {
    let sentinel = s.sentinel.as_mut().expect("the golden session has one");
    sentinel.beats.retain(|b| {
        let inside = b.at_ms > ARMED_START && b.at_ms < ARMED_END;
        let matches = family.is_none_or(|f| b.family == f);
        !(inside && matches)
    });
}
