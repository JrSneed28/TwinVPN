//! The kill switch, the control-plane outage, and the restart — each judged by
//! the wire.
//!
//! **Authority:** ADR-0012 §11.9 (P07, P09); `docs/architecture.md` **I5**;
//! `docs/reliability.md` §9; `docs/testing-strategy.md` §2.13, §3.4.
//!
//! # The two questions, kept apart
//!
//! A fail-closed guarantee has a positive half and a negative half, and
//! conflating them is how a suite ends up green against a device with no
//! network:
//!
//! - **Nothing escaped.** Asserted by auditing a capture of the underlay.
//! - **Something would have.** Asserted, on the same capture, by a deliberate
//!   leak the same oracle catches, and by a mutant route that makes the escape
//!   real.
//!
//! Every test below carries both.

mod common;

use common::{
    settle, CP_UNDERLAY, EXIT_OVERLAY_V4, EXIT_UNDERLAY, OVERLAY_V4, OVERLAY_V6, ROGUE_UNDERLAY,
    TUNNEL_PORT,
};
use twinnet::observer::{Prefix, Reason};
use twinnet::{Capture, LeakPolicy};

fn policy() -> LeakPolicy {
    LeakPolicy::sealed()
        .protecting(Prefix::parse(OVERLAY_V4).expect("the overlay v4 prefix"))
        .protecting(Prefix::parse(OVERLAY_V6).expect("the overlay v6 prefix"))
        .allowing(
            EXIT_UNDERLAY.parse().expect("a literal"),
            Some(TUNNEL_PORT),
            "the tunnel's own underlay endpoint",
        )
        .allowing(
            CP_UNDERLAY.parse().expect("a literal"),
            Some(8443),
            "the control plane",
        )
        .resolver(EXIT_OVERLAY_V4.parse().expect("a literal"))
}

fn agent(rig: &common::Rig) -> String {
    rig.sb.agent_path().display().to_string()
}

fn observe(
    rig: &mut common::Rig,
    node: &str,
    iface: &str,
    label: &str,
    ms: u64,
) -> std::path::PathBuf {
    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    let (_, path) = fabric
        .start_capture(&mut rig.sb, node, iface, label, ms)
        .expect("the observer must start");
    rig.fabric = fabric;
    settle();
    path
}

fn send(rig: &mut common::Rig, to: &str, count: &str) -> twinnet::Ran {
    let a = agent(rig);
    rig.sb
        .run(
            Some("device"),
            &[
                &a,
                "udp-send",
                "--to",
                to,
                "--count",
                count,
                "--interval-ms",
                "30",
                "--wait-ms",
                "150",
            ],
        )
        .expect("the sender must run")
}

fn received(ran: &twinnet::Ran) -> u32 {
    #[derive(serde::Deserialize)]
    struct R {
        received: u32,
    }
    serde_json::from_str::<R>(ran.stdout.trim()).map_or(0, |r| r.received)
}

fn load(path: &std::path::Path) -> Capture {
    std::thread::sleep(std::time::Duration::from_millis(700));
    Capture::load(path).expect("the capture must exist — a missing one is not an empty one")
}

fn protected_escapes(capture: &Capture) -> Vec<String> {
    policy()
        .audit(capture)
        .into_iter()
        .filter(|e| {
            matches!(
                e.reason,
                Reason::ProtectedSource { .. }
                    | Reason::ProtectedDestination { .. }
                    | Reason::UnauthorizedDns { .. }
            )
        })
        .map(|e| e.to_string())
        .collect()
}

// ===========================================================================

#[test]
fn an_established_tunnel_keeps_carrying_traffic_while_the_control_plane_is_blackholed() {
    let Some(mut rig) = common::or_skip(
        "i5-control-plane-blackhole",
        common::build_tunnel_site("i5-control-plane-blackhole"),
    ) else {
        return;
    };
    common::start_tunnel(&mut rig).expect("the tunnel must come up");
    let path = observe(&mut rig, "device", "wan", "cp-blackhole", 9_000);

    // V3: the preconditions are asserted, not assumed. Both must hold, or the
    // outage that follows proves nothing.
    let cp = format!("{CP_UNDERLAY}:8443");
    let overlay = format!("{EXIT_OVERLAY_V4}:9");
    assert!(
        received(&send(&mut rig, &cp, "2")) > 0,
        "the control plane was not reachable before the outage"
    );
    let before = received(&send(&mut rig, &overlay, "3"));
    assert!(
        before > 0,
        "the tunnel was not carrying traffic before the outage"
    );

    // The outage: a blackholed control plane, not a killed one. §3.4 makes the
    // distinction, and it is the harder case — a killed service refuses, a
    // blackholed one is silent.
    let fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    fabric
        .set_link(&mut rig.sb, "cp", "wan", false)
        .expect("the control plane's link must go down");
    rig.fabric = fabric;
    settle();

    assert_eq!(
        received(&send(&mut rig, &cp, "2")),
        0,
        "the control plane answered after its link went down, so it was never out"
    );
    let after = received(&send(&mut rig, &overlay, "3"));
    assert!(
        after > 0,
        "an established tunnel stopped carrying traffic when the control plane went away. \
         I5: a control-plane outage MUST NOT tear down an established tunnel."
    );

    // And it did not start leaking while it was doing so.
    let capture = load(&path);
    let escapes = protected_escapes(&capture);
    assert!(
        escapes.is_empty(),
        "the tunnel survived the outage but put protected addressing on the underlay \
         while doing it:\n  {}",
        escapes.join("\n  ")
    );
}

#[test]
fn when_the_tunnel_dies_protected_traffic_stops_because_this_rig_has_no_other_way_out() {
    let Some(mut rig) = common::or_skip(
        "kill-switch-fail-closed",
        common::build_tunnel_site("kill-switch-fail-closed"),
    ) else {
        return;
    };
    let tunnel = common::start_tunnel(&mut rig)
        .expect("the tunnel must come up")
        .device;
    let path = observe(&mut rig, "device", "wan", "kill-switch", 9_000);

    let overlay = format!("{EXIT_OVERLAY_V4}:9");
    assert!(
        received(&send(&mut rig, &overlay, "3")) > 0,
        "the tunnel was not carrying traffic before it was killed"
    );

    assert!(
        rig.sb.signal(tunnel, 9).expect("the signal must be sent"),
        "the tunnel process was already dead, so killing it proves nothing"
    );
    settle();

    // The overlay must now be unreachable. A TUN device dies with the process
    // that opened it, and the route through it dies with the device.
    //
    // **What this test does and does not show, stated because its name used to
    // overclaim.** This rig's device has no default route: with `tun0` gone
    // there is no route to the overlay at all, so the traffic stops for a
    // *topological* reason. That is worth asserting — a tunnel's own teardown
    // must not leave a path behind — but it is **not** evidence that a kill
    // switch works, because nothing here is enforcing one.
    //
    // The claim ADR-0012 actually makes needs a device that *has* another way
    // out. `lab/twinnet/tests/kill_switch_behind_nat.rs` is that: a default
    // route through the declared middlebox, an OS-level blackhole as the kill
    // switch, and a mutant that disarms it and watches the same traffic escape.
    let after = send(&mut rig, &overlay, "3");
    assert_eq!(
        received(&after),
        0,
        "protected traffic was still being answered after the tunnel died"
    );

    let capture = load(&path);
    let escapes = protected_escapes(&capture);
    assert!(
        escapes.is_empty(),
        "protected addressing reached the underlay after the tunnel died:\n  {}",
        escapes.join("\n  ")
    );

    // The positive control, AFTER the kill, on the same capture: the observer
    // is still watching, so the silence above is a property of the device and
    // not of a dead observer.
    let a = agent(&rig);
    let rogue = format!("{ROGUE_UNDERLAY}:53");
    let _ = rig.sb.run(
        Some("device"),
        &[
            &a,
            "dns-query",
            "--server",
            &rogue,
            "--name",
            "after.twinvpn.invalid",
            "--wait-ms",
            "200",
        ],
    );
    let control = load(&path);
    assert!(
        policy()
            .audit(&control)
            .iter()
            .any(|e| matches!(&e.reason, Reason::UnauthorizedDns { qname }
                if qname.as_deref() == Some("after.twinvpn.invalid"))),
        "the observer stopped seeing the interface after the kill, so `nothing leaked` \
         was a statement about the observer"
    );
}

#[test]
fn a_fallback_route_that_survives_the_tunnel_is_the_leak_this_oracle_exists_to_catch() {
    let Some(mut rig) = common::or_skip(
        "kill-switch-mutant",
        common::build_tunnel_site("kill-switch-mutant"),
    ) else {
        return;
    };
    let tunnel = common::start_tunnel(&mut rig)
        .expect("the tunnel must come up")
        .device;
    let path = observe(&mut rig, "device", "wan", "kill-switch-mutant", 8_000);

    let _ = rig.sb.signal(tunnel, 9);
    settle();
    // The mutant (V2): a device whose overlay route falls back to the underlay
    // when the tunnel goes away. Every product this laboratory could be pointed
    // at either has this defect or does not, and a fail-closed suite that could
    // not tell the two apart would be worth nothing.
    rig.sb
        .must(
            Some("device"),
            &[
                "ip",
                "-4",
                "route",
                "replace",
                OVERLAY_V4,
                "via",
                EXIT_UNDERLAY,
                "dev",
                "wan",
            ],
        )
        .expect("the mutant route must install");

    let overlay = format!("{EXIT_OVERLAY_V4}:9");
    let _ = send(&mut rig, &overlay, "3");
    let capture = load(&path);

    let escapes = protected_escapes(&capture);
    assert!(
        !escapes.is_empty(),
        "a device with a fallback route sent overlay traffic straight out the underlay \
         and this oracle called it clean. The sealed-tunnel assertions in this file are \
         only as good as this one."
    );
}

#[test]
fn a_client_restart_re_establishes_the_tunnel_and_leaks_nothing_across_the_gap() {
    let Some(mut rig) = common::or_skip(
        "client-restart",
        common::build_tunnel_site("client-restart"),
    ) else {
        return;
    };
    let tunnel = common::start_tunnel(&mut rig)
        .expect("the tunnel must come up")
        .device;
    let path = observe(&mut rig, "device", "wan", "client-restart", 12_000);
    let overlay = format!("{EXIT_OVERLAY_V4}:9");
    assert!(
        received(&send(&mut rig, &overlay, "3")) > 0,
        "before the restart"
    );

    let _ = rig.sb.signal(tunnel, 9);
    settle();
    assert_eq!(
        received(&send(&mut rig, &overlay, "2")),
        0,
        "the gap must actually be a gap"
    );

    // The restart. The far end never went away, which is the case that matters:
    // a client that cannot resume against a peer that never moved has a client
    // problem, not a network one.
    let a = agent(&rig);
    let device_bind = format!("{}:{TUNNEL_PORT}", common::DEVICE_UNDERLAY);
    let exit_bind = format!("{EXIT_UNDERLAY}:{TUNNEL_PORT}");
    let log = rig.scratch.join("tunnel-device-2.log");
    rig.sb
        .spawn(
            Some("device"),
            &[
                &a,
                "tunnel",
                "--dev",
                "tun0",
                "--bind",
                &device_bind,
                "--peer",
                &exit_bind,
                "--ms",
                "60000",
            ],
            Some(&log),
        )
        .expect("the tunnel must restart");
    settle();
    for argv in [
        vec!["ip", "addr", "add", "100.64.0.2/32", "dev", "tun0"],
        vec!["ip", "link", "set", "tun0", "up"],
        vec!["ip", "-4", "route", "replace", OVERLAY_V4, "dev", "tun0"],
    ] {
        rig.sb
            .must(Some("device"), &argv)
            .expect("the restarted tunnel must be reconfigured");
    }
    settle();

    assert!(
        received(&send(&mut rig, &overlay, "4")) > 0,
        "the tunnel did not resume after the client restarted"
    );
    let capture = load(&path);
    let escapes = protected_escapes(&capture);
    assert!(
        escapes.is_empty(),
        "protected addressing reached the underlay across the restart gap:\n  {}",
        escapes.join("\n  ")
    );
    let _ = OVERLAY_V6;
}

#[test]
fn the_underlay_path_disappearing_does_not_push_protected_traffic_onto_the_lan() {
    let Some(mut rig) = common::or_skip(
        "path-disappearance",
        common::build_tunnel_site("path-disappearance"),
    ) else {
        return;
    };
    common::start_tunnel(&mut rig).expect("the tunnel must come up");
    // Watch the LAN, not the underlay: the failure this test is looking for is a
    // device that reroutes protected traffic onto whatever interface is left.
    let lan = observe(&mut rig, "device", "lan", "path-gone-lan", 8_000);

    let overlay = format!("{EXIT_OVERLAY_V4}:9");
    assert!(
        received(&send(&mut rig, &overlay, "3")) > 0,
        "before the path went away"
    );

    let fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    fabric
        .set_link(&mut rig.sb, "device", "wan", false)
        .expect("the underlay must go down");
    rig.fabric = fabric;
    settle();

    assert_eq!(
        received(&send(&mut rig, &overlay, "3")),
        0,
        "the overlay was still answered after its only underlay went down"
    );

    let capture = load(&lan);
    let escapes = LeakPolicy::sealed()
        .protecting(Prefix::parse(OVERLAY_V4).expect("the overlay v4 prefix"))
        .protecting(Prefix::parse(OVERLAY_V6).expect("the overlay v6 prefix"))
        .protected_only()
        .audit(&capture);
    assert!(
        escapes.is_empty(),
        "protected addressing appeared on the LAN after the underlay disappeared:\n  {}",
        escapes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

#[test]
fn a_gateway_restart_is_recovered_from_without_the_client_being_restarted() {
    let Some(mut rig) = common::or_skip(
        "gateway-restart",
        common::build_tunnel_site("gateway-restart"),
    ) else {
        return;
    };
    let ends = common::start_tunnel(&mut rig).expect("the tunnel must come up");
    let path = observe(&mut rig, "device", "wan", "gateway-restart", 14_000);
    let overlay = format!("{EXIT_OVERLAY_V4}:9");
    assert!(
        received(&send(&mut rig, &overlay, "3")) > 0,
        "the tunnel was not carrying traffic before the gateway restarted"
    );

    // The FAR end dies. The client is untouched — that is the whole distinction
    // from the client-restart case, and it is the one that matters operationally:
    // a gateway is restarted by its operator, on a schedule the client knows
    // nothing about, and a client that needed its own restart to recover would
    // turn every deploy into an outage for everyone behind it.
    assert!(
        rig.sb
            .signal(ends.exit, 9)
            .expect("the signal must be sent"),
        "the gateway was already dead, so restarting it proves nothing"
    );
    settle();
    assert_eq!(
        received(&send(&mut rig, &overlay, "2")),
        0,
        "the gap must actually be a gap"
    );

    let a = agent(&rig);
    let device_bind = format!("{}:{TUNNEL_PORT}", common::DEVICE_UNDERLAY);
    let exit_bind = format!("{EXIT_UNDERLAY}:{TUNNEL_PORT}");
    let log = rig.scratch.join("tunnel-exit-2.log");
    rig.sb
        .spawn(
            Some("exit"),
            &[
                &a,
                "tunnel",
                "--dev",
                "tun0",
                "--bind",
                &exit_bind,
                "--peer",
                &device_bind,
                "--ms",
                "60000",
            ],
            Some(&log),
        )
        .expect("the gateway must restart");
    settle();
    for argv in [
        vec!["ip", "addr", "add", "100.64.0.3/32", "dev", "tun0"],
        vec!["ip", "link", "set", "tun0", "up"],
        vec!["ip", "-4", "route", "replace", OVERLAY_V4, "dev", "tun0"],
    ] {
        rig.sb
            .must(Some("exit"), &argv)
            .expect("the restarted gateway must be reconfigured");
    }
    let echo = format!("{EXIT_OVERLAY_V4}:9");
    rig.sb
        .spawn(
            Some("exit"),
            &[&a, "udp-echo", "--bind", &echo, "--ms", "60000"],
            Some(&log),
        )
        .expect("the gateway's in-overlay service must come back");
    settle();

    assert!(
        received(&send(&mut rig, &overlay, "4")) > 0,
        "the tunnel did not resume after the gateway restarted, and the client was never \
         touched — so recovery required a client restart it should not have"
    );
    let capture = load(&path);
    let escapes = protected_escapes(&capture);
    assert!(
        escapes.is_empty(),
        "protected addressing reached the underlay across the gateway restart:\n  {}",
        escapes.join("\n  ")
    );
}
