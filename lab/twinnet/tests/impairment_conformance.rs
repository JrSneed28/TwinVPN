//! §3.4.2's conformance rows for the impairment shims, and §3.4's blocked-egress
//! conditions.
//!
//! **Authority:** `docs/testing-strategy.md` §3.4, §3.4.2, rule **L-1**.
//!
//! > | Loss / duplication / reorder shim | Measured rate over 10⁵ packets is
//! > within the declared tolerance of the configured rate |
//!
//! # The population, honestly stated
//!
//! §3.4.2 asks for 10⁵ packets. This file uses a few hundred, and says so rather
//! than quietly measuring less than it claims: at 10⁵ packets each of these
//! assertions takes minutes, which belongs to a T3 tier and not to a suite a
//! developer runs before pushing. `TWINNET_IMPAIR_PACKETS` raises the population
//! for that tier. The tolerances below are widened to match the smaller sample,
//! and they are still narrow enough to fail against an unimpaired link — which
//! is the failure that actually matters, because an impairment silently not
//! applied is a scenario that reports a pass for the unimpaired case.
//!
//! # Why the assertions are bounds and not equalities
//!
//! `netem` is a kernel scheduler artefact, not a deterministic drop schedule.
//! §3.5 classifies every one of these as `STATISTICAL` for exactly that reason,
//! and `twinlab::determinism::Class` refuses a scenario that declares `BIT`
//! while carrying one. A test that asserted "exactly 20 % were dropped" would be
//! asserting against the tolerance of the mechanism rather than against the
//! mechanism.

mod common;

use common::{settle, PERSONALITIES, REFLECT_A};
use twinnet::fabric::Impair;
use twinnet::nat::config::Egress;

#[derive(Debug, serde::Deserialize)]
struct Measured {
    sent: u32,
    received: u32,
    unique: u32,
    duplicates: u32,
    out_of_order: u32,
    min_rtt_us: u64,
    #[allow(dead_code)]
    max_rtt_us: u64,
    median_rtt_us: u64,
}

fn packets() -> u32 {
    std::env::var("TWINNET_IMPAIR_PACKETS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300)
}

/// Builds the single-site rig with a middlebox and an echo beyond it.
fn rig(label: &str, egress: Egress) -> Option<common::Rig> {
    let mut rig = common::or_skip(label, common::build(label, false))?;
    let mut cfg = common::nat_config(&rig, &PERSONALITIES[3]); // N-EIM-APDF
    cfg.egress = egress;
    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    fabric
        .start_nat(&mut rig.sb, "cpe", &cfg)
        .expect("the middlebox must start");
    rig.fabric = fabric;

    let agent = rig.sb.agent_path().display().to_string();
    let log = rig.scratch.join("echo.log");
    for port in ["9", "443"] {
        let bind = format!("{REFLECT_A}:{port}");
        rig.sb
            .spawn(
                Some("reflector"),
                &[&agent, "udp-echo", "--bind", &bind, "--ms", "120000"],
                Some(&log),
            )
            .expect("the echo must start");
    }
    settle();
    Some(rig)
}

/// A measurement sent back to back, for the shaping assertions where the send
/// interval is what a token bucket refills against.
fn measure_fast(rig: &mut common::Rig, port: &str, count: u32) -> Measured {
    measure_with(rig, port, count, "0", "3000")
}

fn measure(rig: &mut common::Rig, port: &str, count: u32) -> Measured {
    measure_with(rig, port, count, "2", "1500")
}

fn measure_with(
    rig: &mut common::Rig,
    port: &str,
    count: u32,
    interval_ms: &str,
    wait_ms: &str,
) -> Measured {
    let agent = rig.sb.agent_path().display().to_string();
    let to = format!("{REFLECT_A}:{port}");
    let count = count.to_string();
    let ran = rig
        .sb
        .run(
            Some("client"),
            &[
                &agent,
                "measure",
                "--to",
                &to,
                "--count",
                &count,
                "--interval-ms",
                interval_ms,
                "--wait-ms",
                wait_ms,
            ],
        )
        .expect("the measurement must run");
    serde_json::from_str(ran.stdout.trim())
        .unwrap_or_else(|e| panic!("the measurement was undecodable ({e}): {}", ran.stdout))
}

/// Applies an impairment set to the transit side of the link, never the device.
fn impair(rig: &mut common::Rig, set: &[Impair]) {
    let fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    fabric
        .impair(&mut rig.sb, "cpe", "wan", set)
        .expect("the impairment must apply — a host that cannot impair must not run this");
    rig.fabric = fabric;
    settle();
}

// ===========================================================================

#[test]
fn a_clean_link_is_the_baseline_every_other_assertion_is_read_against() {
    let Some(mut rig) = rig("impair-baseline", Egress::Allow) else {
        return;
    };
    let n = packets();
    let m = measure(&mut rig, "9", n);
    assert!(
        m.unique * 100 >= m.sent * 95,
        "an unimpaired link lost {} of {} datagrams, so no impairment measured against \
         it means anything: {m:?}",
        m.sent - m.unique,
        m.sent
    );
    assert_eq!(m.duplicates, 0, "an unimpaired link duplicated: {m:?}");
    assert_eq!(m.out_of_order, 0, "an unimpaired link reordered: {m:?}");
    assert!(
        m.median_rtt_us < 50_000,
        "an unimpaired link's median round trip was {} us: {m:?}",
        m.median_rtt_us
    );
}

#[test]
fn configured_latency_appears_in_the_measured_round_trip() {
    let Some(mut rig) = rig("impair-latency", Egress::Allow) else {
        return;
    };
    let baseline = measure(&mut rig, "9", 60);
    impair(
        &mut rig,
        &[Impair::Delay {
            ms: 60,
            jitter_ms: 0,
        }],
    );
    let delayed = measure(&mut rig, "9", 60);

    // One direction is impaired, so the round trip gains one delay, not two.
    assert!(
        delayed.median_rtt_us >= baseline.median_rtt_us + 50_000,
        "60 ms of one-way delay did not appear in the round trip: baseline median {} us, \
         impaired median {} us. An impairment that silently failed to apply reports the \
         unimpaired case as a pass.",
        baseline.median_rtt_us,
        delayed.median_rtt_us
    );
    assert!(
        delayed.min_rtt_us >= 40_000,
        "the fastest round trip was {} us, below the configured one-way delay: {delayed:?}",
        delayed.min_rtt_us
    );
}

#[test]
fn configured_loss_appears_in_the_measured_rate_and_a_clean_link_does_not() {
    let Some(mut rig) = rig("impair-loss", Egress::Allow) else {
        return;
    };
    let n = packets();
    impair(&mut rig, &[Impair::Loss { pct: 20.0 }]);
    let m = measure(&mut rig, "9", n);
    let lost_pct = f64::from(m.sent - m.unique) * 100.0 / f64::from(m.sent.max(1));
    assert!(
        (8.0..40.0).contains(&lost_pct),
        "20 % configured loss measured {lost_pct:.1} % over {} datagrams. The band is wide \
         because `netem` is statistical (§3.5) and the sample is small; it is still narrow \
         enough that an impairment which never applied lands outside it. {m:?}",
        m.sent
    );
}

#[test]
fn configured_duplication_appears_as_duplicate_sequence_numbers() {
    let Some(mut rig) = rig("impair-duplicate", Egress::Allow) else {
        return;
    };
    let n = packets();
    impair(&mut rig, &[Impair::Duplicate { pct: 10.0 }]);
    let m = measure(&mut rig, "9", n);
    assert!(
        m.duplicates > 0,
        "10 % configured duplication produced no duplicate sequence number over {} \
         datagrams: {m:?}",
        m.sent
    );
    assert!(
        m.received > m.unique,
        "duplication must show up as more receipts than distinct sequence numbers: {m:?}"
    );
}

#[test]
fn reordering_is_measured_and_an_inert_netem_option_is_reported_as_unavailable() {
    let Some(mut rig) = rig("impair-reorder", Egress::Allow) else {
        return;
    };
    let n = packets();
    // §3.4's specified mechanism, emitted verbatim: `netem delay <d> reorder <p>
    // <corr>`. The delay is required — without a queue there is nothing to take
    // a packet out of turn from, and the option silently does nothing.
    impair(
        &mut rig,
        &[
            Impair::Delay {
                ms: 20,
                jitter_ms: 0,
            },
            Impair::Reorder {
                pct: 50.0,
                correlation_pct: 0.0,
            },
        ],
    );
    let specified = measure(&mut rig, "9", n);
    if specified.out_of_order > 0 {
        return;
    }

    // The specified mechanism delivered nothing out of order. Two things could
    // be true and they must not be confused: this host's `netem` does not
    // honour `reorder`, or this measurement cannot see reordering at all. The
    // second would make every reordering scenario in the catalogue vacuous, so
    // it is the one that must be ruled out — with a control that reorders by a
    // different mechanism.
    impair(
        &mut rig,
        &[Impair::Delay {
            ms: 20,
            jitter_ms: 15,
        }],
    );
    let control = measure(&mut rig, "9", n);
    assert!(
        control.out_of_order > 0,
        "neither `netem reorder` nor `netem delay` with jitter delivered anything out of \
         order, so this measurement cannot detect reordering and every reordering \
         scenario built on it would pass vacuously.\n  specified: {specified:?}\n  control:   {control:?}"
    );
    // The channel works and the option does not. That is a facility this host
    // lacks, and §3.1's rule applies to it exactly as it applies to a missing
    // `nft`: it is reported, not converted into a pass and not blamed on the
    // system under test.
    eprintln!(
        "UNAVAILABLE netem-reorder: `netem delay 20ms reorder 50%` delivered {} of {} \
         datagrams out of order on this kernel, while `netem delay 20ms 15ms` delivered \
         {} of {}. §3.4's reordering row cannot be realized here; the measurement channel \
         is sound. Reordering scenarios are Unavailable on this host, not passing.",
        specified.out_of_order, specified.sent, control.out_of_order, control.sent
    );
}

#[test]
fn a_bandwidth_limit_bounds_the_measured_goodput() {
    let Some(mut rig) = rig("impair-bandwidth", Egress::Allow) else {
        return;
    };
    impair(&mut rig, &[Impair::Bandwidth { kbit: 64 }]);
    // The population has to exceed the token bucket's burst, and this is the
    // measurement that established the number rather than a guess. `tbf`'s burst
    // here is 4 kB; 120 datagrams of about 48 bytes is 5.8 kB, and at a 2 ms
    // send interval the bucket refills faster than the deficit accumulates — so
    // a 64 kbit/s shaper passed every one of them untouched and a smaller
    // population would have reported "no shaper in the path" for a shaper that
    // was in the path. 800 datagrams sent back to back is 38 kB against a
    // 4 kB burst and an 8 kB/s drain, which the bucket cannot absorb.
    let m = measure_fast(&mut rig, "9", 800);
    assert!(
        m.unique < m.sent || m.median_rtt_us > 20_000,
        "a 64 kbit/s shaper neither dropped nor delayed {} datagrams, so it was not in \
         the path: {m:?}",
        m.sent
    );
}

#[test]
fn blocked_udp_stops_every_datagram_and_the_permitted_port_variant_stops_all_but_one() {
    let Some(mut total) = rig("egress-block-udp", Egress::BlockUdp) else {
        return;
    };
    let blocked = measure(&mut total, "9", 20);
    assert_eq!(
        blocked.unique, 0,
        "UDP was blocked at the middlebox and datagrams still got through: {blocked:?}"
    );
    drop(total);

    let Some(mut partial) = rig(
        "egress-block-udp-except-443",
        Egress::BlockUdpExcept { ports: vec![443] },
    ) else {
        return;
    };
    let still_blocked = measure(&mut partial, "9", 20);
    let permitted = measure(&mut partial, "443", 20);
    assert_eq!(
        still_blocked.unique, 0,
        "a port outside the exception list got through: {still_blocked:?}"
    );
    assert!(
        permitted.unique > 0,
        "the permitted port was blocked too, so `all but 443` blocked everything and the \
         scenario is indistinguishable from a total block: {permitted:?}"
    );
}

#[test]
fn an_mtu_below_the_ipv6_floor_is_installed_and_visible_to_the_stack() {
    let Some(mut rig) = rig("impair-mtu", Egress::Allow) else {
        return;
    };
    let fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    fabric
        .mtu(&mut rig.sb, "cpe", "wan", 1_280)
        .expect("the MTU must be settable");
    rig.fabric = fabric;
    let shown = rig
        .sb
        .must(Some("cpe"), &["ip", "link", "show", "wan"])
        .expect("the interface must be readable");
    assert!(
        shown.contains("mtu 1280"),
        "the transit MTU was not applied; `ip link show` said: {shown}"
    );
}
