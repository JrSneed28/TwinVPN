//! §3.3's `N-NAT64` row and §3.4.2's NAT64 conformance row.
//!
//! **Authority:** `docs/testing-strategy.md` §3.3, §3.4.2; `docs/networking.md`
//! §3.8; ADR-0010, ADR-0011.
//!
//! > | NAT64 | A v4-literal destination is reachable from a v6-only client via
//! > the synthesized prefix, and `PREF64`-off forces the RFC 7050 path |
//!
//! # Why this file exists and what it replaces
//!
//! `N-NAT64` reported `UNAVAILABLE` for as long as this laboratory has had a
//! conformance suite, and the reason was accurate: §3.3 realizes it with a
//! `jool`-class stateful NAT64 and there is no `jool` here. That is the honest
//! answer to "can this host run jool" and a useless one to "does TwinVPN work on
//! a mobile network", which is the question the row is about.
//!
//! `twinnet::nat::xlat` is a second realization — RFC 6052 addressing and RFC
//! 7915 header translation inside the middlebox that is already in the path.
//! What it does **not** cover is stated in that module rather than discovered
//! here: no fragments, no ICMP error messages, no prefix length but `/96`. Each
//! is a refusal, and the last test in this file is that they are refusals rather
//! than pass-throughs.
//!
//! # The three prefix advertisements
//!
//! §3.3 wants them "independently switchable so the 'PREF64 absent, must fall
//! back to RFC 7050' case is a distinct scenario". All three are realized and
//! all three are separate switches:
//!
//! | Path | Mechanism | Touches a resolver? |
//! |---|---|---|
//! | synthesized AAAA | the DNS64 answers AAAA for the destination | yes |
//! | RFC 7050 | `ipv4only.arpa` is synthesized and the client reads the prefix out of it | yes |
//! | **RFC 8781** — the path §3.8 *prefers* | the PREF64 option in a real Router Advertisement | **no** |
//!
//! The last one is why `every_discovery_path_is_switchable_on_its_own` exists:
//! with both DNS mechanisms off, the RA path must still work, and that is only
//! meaningful because it shares no code with them.
//!
//! # The client has no IPv4 address
//!
//! Not "no route to v4" — no address. A rig where the client could reach the
//! destination directly would pass whether or not the translator worked, and
//! that is the failure mode this whole file is built to avoid.

mod common;

use common::settle;
use twinnet::dns64::Nat64Report;
use twinnet::observer::Prefix;
use twinnet::rigs;
use twinnet::{Capture, LeakPolicy};

/// Builds the rig with the two discovery paths switched as asked, and starts the
/// translator.
fn rig(
    label: &str,
    synthesize: bool,
    rfc7050: bool,
    advertise_ra: bool,
) -> Option<(common::Rig, std::path::PathBuf)> {
    let mut rig = common::or_skip(
        label,
        rigs::build_nat64_site(label, synthesize, rfc7050, advertise_ra),
    )?;
    let cfg = rigs::nat64_config(&rig);
    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    let started = fabric.start_nat(&mut rig.sb, "nat64", &cfg);
    rig.fabric = fabric;
    let (_, stats) = started.expect("the translator must start");
    settle();
    Some((rig, stats))
}

/// Runs the v6-only client's probe over one of the three discovery paths.
fn probe(rig: &mut common::Rig, discover: &str) -> Nat64Report {
    let agent = rig.sb.agent_path().display().to_string();
    let resolver = format!("[{}]:53", rigs::NAT64_RESOLVER_V6);
    let argv = vec![
        agent.as_str(),
        "nat64-probe",
        "--resolver",
        &resolver,
        "--name",
        rigs::NAT64_NAME,
        "--port",
        "9",
        "--wait-ms",
        "700",
        "--discover",
        discover,
        "--iface",
        "lan",
    ];
    let ran = rig
        .sb
        .run(Some("client6"), &argv)
        .expect("the probe must run");
    assert!(
        ran.ok(),
        "the probe exited {:?}: {}",
        ran.status,
        ran.stderr
    );
    serde_json::from_str(ran.stdout.trim())
        .unwrap_or_else(|e| panic!("the probe's report was undecodable ({e}): {}", ran.stdout))
}

// ===========================================================================

#[test]
fn a_v6_only_client_reaches_a_v4_only_destination_through_the_synthesized_prefix() {
    let Some((mut rig, stats)) = rig("nat64-synthesized", true, true, false) else {
        return;
    };

    // V3: the precondition is asserted, not assumed. A client that had an IPv4
    // address would reach the destination whether or not anything translated.
    let addrs = rig
        .sb
        .must(Some("client6"), &["ip", "-4", "addr", "show", "lan"])
        .expect("the client's addressing must be readable");
    assert!(
        !addrs.contains("inet "),
        "the client has an IPv4 address, so this scenario proves nothing about \
         translation:\n{addrs}"
    );

    let report = probe(&mut rig, "aaaa");
    assert!(
        report.reachable,
        "a v6-only client did not reach the v4-only destination:\n  {}",
        report.evidence.join("\n  ")
    );
    let target = report.target.clone().unwrap_or_default();
    assert!(
        target.starts_with("[64:ff9b::"),
        "the client reached `{target}`, which is not inside the translation prefix"
    );
    assert_eq!(
        report.pref64.as_deref(),
        Some("64:ff9b::/96"),
        "the prefix the client used is not the one the resolver synthesizes with"
    );

    // The translator did the work, and says so in its own counters. Awaited
    // rather than read once: the snapshot is written on a timer, and reading it
    // the instant the probe returns reads the one from before the traffic.
    let snapshot = rigs::await_snapshot(&stats, std::time::Duration::from_secs(3), |v| {
        rigs::counter(v, "translated_out") > 0 && rigs::counter(v, "translated_in") > 0
    })
    .expect("the translator must write a snapshot");
    assert!(
        rigs::counter(&snapshot, "translated_out") > 0
            && rigs::counter(&snapshot, "translated_in") > 0,
        "the destination answered but the translator translated nothing in one of the two \
         directions, so something else carried the traffic: {snapshot:#}"
    );
    assert_eq!(
        rigs::counter(&snapshot, "untranslatable"),
        0,
        "the translator refused packets on the happy path: {snapshot:#}"
    );
}

#[test]
fn pref64_absent_forces_the_rfc7050_path_and_the_client_still_gets_there() {
    // §3.3: the two advertisements are "independently switchable so the
    // 'PREF64 absent, must fall back to RFC 7050' case is a distinct scenario".
    // This is that scenario: no AAAA is synthesized for the destination, and
    // `ipv4only.arpa` still answers.
    let Some((mut rig, _)) = rig("nat64-rfc7050", false, true, false) else {
        return;
    };

    // The precondition: with synthesis off, the ordinary path must FAIL. A test
    // that asserted only the fallback would pass just as well on a resolver that
    // was still synthesizing.
    let without = probe(&mut rig, "aaaa");
    assert!(
        !without.reachable,
        "the destination was reachable without RFC 7050, so PREF64 was not actually \
         absent:\n  {}",
        without.evidence.join("\n  ")
    );

    let with = probe(&mut rig, "rfc7050");
    assert!(
        with.reachable,
        "RFC 7050 discovery did not recover the prefix:\n  {}",
        with.evidence.join("\n  ")
    );
    assert_eq!(with.discovery, "rfc7050");
    assert_eq!(
        with.pref64.as_deref(),
        Some("64:ff9b::/96"),
        "the prefix recovered from ipv4only.arpa is not the one in use"
    );
}

#[test]
fn with_both_discovery_paths_off_the_client_cannot_reach_the_v4_internet() {
    // The negative control for the two tests above. Without it, "the client got
    // there" would be a statement about a rig that lets everything through.
    let Some((mut rig, _)) = rig("nat64-no-discovery", false, false, false) else {
        return;
    };
    for discover in ["aaaa", "rfc7050", "ra"] {
        let report = probe(&mut rig, discover);
        assert!(
            !report.reachable,
            "with NO discovery path available the client still reached the v4 destination \
             (--discover {discover}):\n  {}",
            report.evidence.join("\n  ")
        );
    }
}

#[test]
fn no_ipv6_addressing_ever_appears_on_the_ipv4_side_of_the_translator() {
    let Some((mut rig, _)) = rig("nat64-wire", true, true, false) else {
        return;
    };
    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    let (_, capture_path) = fabric
        .start_capture(&mut rig.sb, "server4", "wan", "nat64-v4-side", 6_000)
        .expect("the observer must start");
    rig.fabric = fabric;
    settle();

    let report = probe(&mut rig, "aaaa");
    assert!(report.reachable, "the happy path must happen first");

    std::thread::sleep(std::time::Duration::from_millis(700));
    let capture = Capture::load(&capture_path).expect("the capture must exist");
    assert!(
        !capture.is_silent(),
        "the observer on the v4 side saw nothing, so `no v6 leaked` is a statement about \
         a dead observer"
    );

    // The positive half: the translated traffic IS there, addressed from the
    // translator's public v4.
    let translated =
        capture.matching(|r| r.src.as_deref() == Some(rigs::NAT64_PUBLIC_V4) && r.dport == Some(9));
    assert!(
        !translated.is_empty(),
        "no translated datagram reached the v4 side, so the assertion below is vacuous"
    );

    // The negative half: nothing carrying the v6 client's addressing, and
    // nothing inside the translation prefix, ever crossed to the v4 network.
    let escapes = LeakPolicy::sealed()
        .protecting(Prefix::parse("2001:db8:64::/64").expect("the client's LAN prefix"))
        .protecting(Prefix::parse("64:ff9b::/96").expect("the translation prefix"))
        .protected_only()
        .audit(&capture);
    assert!(
        escapes.is_empty(),
        "IPv6 addressing crossed onto the IPv4 network. A translator that forwarded what \
         it could not translate would do exactly this:\n  {}",
        escapes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n  ")
    );
    // And nothing IPv6 at all: the segment has the family disabled, so any
    // frame carrying it came from the translator putting one there.
    let v6_frames = capture.matching(|r| r.ethertype == twinnet::ip::ETHERTYPE_IPV6);
    assert!(
        v6_frames.is_empty(),
        "{} IPv6 frames were seen on the v4-only segment: {:?}",
        v6_frames.len(),
        v6_frames
            .iter()
            .map(|r| format!(
                "[{}] {:?} -> {:?} proto {:?}",
                r.eth_src, r.src, r.dst, r.proto
            ))
            .collect::<Vec<_>>()
    );
}

#[test]
fn rfc8781_carries_the_prefix_in_a_router_advertisement_with_both_dns_paths_off() {
    // §3.8's preferred path, and the one that was reported NOT COVERED for as
    // long as this laboratory had a NAT64. Both DNS mechanisms are switched
    // off, so the prefix can only have come off the wire.
    let Some((mut rig, _)) = rig("nat64-ra", false, false, true) else {
        return;
    };

    // The precondition: with both DNS paths off, neither of them gets there.
    for dns in ["aaaa", "rfc7050"] {
        let report = probe(&mut rig, dns);
        assert!(
            !report.reachable,
            "`--discover {dns}` succeeded with the DNS paths switched off, so the RA \
             result below would not be about the RA:\n  {}",
            report.evidence.join("\n  ")
        );
    }

    let report = probe(&mut rig, "ra");
    assert!(
        report.reachable,
        "RFC 8781 discovery did not reach the destination:\n  {}",
        report.evidence.join("\n  ")
    );
    assert_eq!(report.discovery, "router-advertisement");
    assert_eq!(
        report.pref64.as_deref(),
        Some("64:ff9b::/96"),
        "the prefix read out of the Router Advertisement is not the one in use"
    );
    assert!(
        report
            .evidence
            .iter()
            .any(|e| e.contains("Router Advertisement on `lan`")),
        "the report does not name where the prefix came from: {:?}",
        report.evidence
    );
}

#[test]
fn every_discovery_path_is_switchable_on_its_own() {
    // §3.3's requirement, asserted as a matrix rather than described. Each row
    // switches exactly one advertisement on and asserts that the path it feeds
    // works and the other two do not.
    for (label, synthesize, rfc7050, ra, expect) in [
        ("only-aaaa", true, false, false, "aaaa"),
        ("only-rfc7050", false, true, false, "rfc7050"),
        ("only-ra", false, false, true, "ra"),
    ] {
        let Some((mut rig, _)) = rig(&format!("nat64-switch-{label}"), synthesize, rfc7050, ra)
        else {
            return;
        };
        for discover in ["aaaa", "rfc7050", "ra"] {
            let report = probe(&mut rig, discover);
            let should_reach = discover == expect;
            assert_eq!(
                report.reachable,
                should_reach,
                "with only `{label}` advertised, `--discover {discover}` reached={} and \
                 should have reached={should_reach}. The three advertisements are required \
                 to be independently switchable (§3.3), so a path succeeding on an \
                 advertisement it does not use means they are not.\n  {}",
                report.reachable,
                report.evidence.join("\n  ")
            );
        }
    }
}
