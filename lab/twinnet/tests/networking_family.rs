//! §3.4's PMTU black hole and interface-change rows — the `S-NET-*` family.
//!
//! **Authority:** `docs/testing-strategy.md` §3.4 and §3.4.2; `docs/networking.md`
//! §2.9; ADR-0010.
//!
//! > | PMTU black hole | Reduced MTU **plus** `nft` drop of ICMPv4 type 3 code 4
//! > and ICMPv6 type 2 in the transit namespace |
//!
//! > | PMTU black hole | A 1500-byte DF probe is dropped and **no** ICMP
//! > fragmentation-needed is observed at the sender |
//!
//! > | Interface change (roam) | Move the device's `veth` leg from `br-wifi` to
//! > `br-cell` and re-address, producing genuine `EV_LINK_DOWN` /
//! > `EV_ADDR_CHANGED` |
//!
//! # The roam is the network-migration scenario
//!
//! Two access networks behind a router, and one far end reachable from both. The
//! device changes address, gateway and path; the tunnel process is **not**
//! restarted, and the far end learns where its peer went from the first datagram
//! that arrives. A scenario that restarted the tunnel would be measuring a
//! reconnection, which is a different property with a different name.

mod common;

use common::settle;
use twinnet::observer::Prefix;
use twinnet::rigs;
use twinnet::{Capture, LeakPolicy};

fn received(ran: &twinnet::Ran) -> u32 {
    #[derive(serde::Deserialize)]
    struct R {
        received: u32,
    }
    serde_json::from_str::<R>(ran.stdout.trim()).map_or(0, |r| r.received)
}

// ===========================================================================

#[test]
fn a_pmtu_black_hole_swallows_the_only_message_that_would_have_reported_it() {
    // The control first, in its own rig: with the black hole OFF, the same
    // oversize probe IS reported. Without this, "no ICMP arrived" would pass
    // against a middlebox that was never able to send one.
    if let Some(mut control) =
        common::or_skip("pmtu-reported", common::build("pmtu-reported", false))
    {
        let mut cfg = common::nat_config(&control, &common::PERSONALITIES[3]);
        cfg.egress_mtu = Some(1_280);
        cfg.drop_pmtu_icmp = false;
        let mut fabric = std::mem::replace(
            &mut control.fabric,
            twinnet::fabric::Fabric::new(&control.scratch),
        );
        let started = fabric.start_nat(&mut control.sb, "cpe", &cfg);
        control.fabric = fabric;
        let (_, stats) = started.expect("the control middlebox must start");
        settle();
        let _ = control.sb.run(
            Some("client"),
            &[
                "ping",
                "-c",
                "2",
                "-W",
                "1",
                "-M",
                "do",
                "-s",
                "1400",
                common::REFLECT_A,
            ],
        );
        let snapshot = rigs::await_snapshot(&stats, std::time::Duration::from_secs(3), |v| {
            rigs::counter(v, "pmtu_reported") > 0
        })
        .expect("the control middlebox must write a snapshot");
        assert!(
            rigs::counter(&snapshot, "pmtu_reported") > 0,
            "with the black hole off, an oversize packet must be REPORTED. If it is not, \
             the middlebox cannot send the message the black hole is defined by \
             swallowing, and the assertion below is vacuous: {snapshot:#}"
        );
    }

    let Some(mut rig) = common::or_skip("pmtu-blackhole", common::build("pmtu-blackhole", false))
    else {
        return;
    };
    let mut cfg = common::nat_config(&rig, &common::PERSONALITIES[3]);
    // §3.4: reduced MTU **plus** the ICMP drop. Either alone is a different
    // condition — a clamp whose report gets through is an ordinary MTU
    // mismatch, which PMTU discovery resolves.
    cfg.egress_mtu = Some(1_280);
    cfg.drop_pmtu_icmp = true;
    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    let started = fabric.start_nat(&mut rig.sb, "cpe", &cfg);
    rig.fabric = fabric;
    let (_, stats) = started.expect("the middlebox must start");
    settle();

    let agent = rig.sb.agent_path().display().to_string();
    let echo = format!("{}:9", common::REFLECT_A);
    let log = rig.scratch.join("echo.log");
    rig.sb
        .spawn(
            Some("reflector"),
            &[&agent, "udp-echo", "--bind", &echo, "--ms", "60000"],
            Some(&log),
        )
        .expect("the echo must start");
    settle();

    // Watch the device's own side: §3.4.2 asks that **no** ICMP
    // fragmentation-needed be observed *at the sender*, which is a statement
    // about this interface and nothing else.
    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    let (_, capture) = fabric
        .start_capture(&mut rig.sb, "client", "lan", "pmtu", 8_000)
        .expect("the observer must start");
    rig.fabric = fabric;
    settle();

    // A small datagram gets through, so the path is known good.
    let small = rig
        .sb
        .run(
            Some("client"),
            &[
                &agent,
                "udp-send",
                "--to",
                &echo,
                "--count",
                "2",
                "--wait-ms",
                "300",
            ],
        )
        .expect("the small probe must run");
    assert!(
        received(&small) > 0,
        "the path was already broken before the MTU mattered: {}",
        small.stdout
    );

    // Now one that cannot fit. `udp-send`'s payload is small, so the oversize
    // probe is sent with `ping -s` and the DF bit, which is what §3.4.2 names.
    let _ = rig.sb.run(
        Some("client"),
        &[
            "ping",
            "-c",
            "3",
            "-W",
            "1",
            "-M",
            "do",
            "-s",
            "1400",
            common::REFLECT_A,
        ],
    );
    std::thread::sleep(std::time::Duration::from_millis(700));

    let capture = Capture::load(&capture).expect("the capture must exist");
    assert!(
        !capture.is_silent(),
        "the observer saw nothing, so `no ICMP arrived` is a statement about a dead \
         observer"
    );
    // ICMPv4 type 3 code 4 is the only message that would have told the sender
    // the path's MTU. A black hole is defined by its absence.
    let told = capture.matching(|r| {
        r.proto == Some(twinnet::ip::proto::ICMP) && r.dst.as_deref() == Some(common::CLIENT_V4)
    });
    assert!(
        told.is_empty(),
        "the sender was told the path MTU, so this is an ordinary MTU mismatch and not a \
         black hole: {:?}",
        told.iter()
            .map(|r| format!("{:?} -> {:?}", r.src, r.dst))
            .collect::<Vec<_>>()
    );

    // And the condition was actually produced: the middlebox swallowed
    // something. Without this, a path that never attempted PMTU discovery would
    // look identical to a black hole.
    let snapshot = rigs::await_snapshot(&stats, std::time::Duration::from_secs(3), |v| {
        rigs::counter(v, "pmtu_dropped") > 0
    })
    .expect("the middlebox must write a snapshot");
    assert!(
        rigs::counter(&snapshot, "pmtu_dropped") > 0,
        "the black hole swallowed nothing, so PMTU discovery was never attempted and the \
         silence above means nothing: {snapshot:#}"
    );
}

#[test]
fn a_roam_between_access_networks_keeps_the_session_without_restarting_it() {
    let Some(mut rig) = common::or_skip("roam", rigs::build_roam_site("roam")) else {
        return;
    };
    let tunnel = rigs::start_roam_tunnel(&mut rig).expect("the tunnel must come up over wifi");

    let agent = rig.sb.agent_path().display().to_string();
    let overlay = format!("{}:9", rigs::EXIT_OVERLAY_V4);
    let send = |rig: &mut common::Rig| {
        rig.sb
            .run(
                Some("device"),
                &[
                    &agent,
                    "udp-send",
                    "--to",
                    &overlay,
                    "--count",
                    "3",
                    "--interval-ms",
                    "30",
                    "--wait-ms",
                    "300",
                ],
            )
            .expect("the sender must run")
    };

    let before = send(&mut rig);
    assert!(
        received(&before) > 0,
        "the session was not carrying traffic on the first access network: {}",
        before.stdout
    );
    let on_wifi = rig
        .sb
        .must(Some("device"), &["ip", "-4", "addr", "show", "wan"])
        .expect("addressing must be readable");
    assert!(
        on_wifi.contains(rigs::ROAM_WIFI_ADDR),
        "the device did not start on the Wi-Fi access network:\n{on_wifi}"
    );

    // The roam. The tunnel process is untouched.
    rigs::roam_to_cell(&mut rig).expect("the leg must move to the cellular segment");
    settle();

    let on_cell = rig
        .sb
        .must(Some("device"), &["ip", "-4", "addr", "show", "wan"])
        .expect("addressing must be readable");
    assert!(
        on_cell.contains(rigs::ROAM_CELL_ADDR) && !on_cell.contains(rigs::ROAM_WIFI_ADDR),
        "the device did not move to the cellular access network:\n{on_cell}"
    );
    let route = rig
        .sb
        .must(Some("device"), &["ip", "-4", "route", "show", "default"])
        .expect("the default route must be readable");
    assert!(
        route.contains(rigs::ROAM_CELL_GW),
        "the default route did not follow the address:\n{route}"
    );

    // The session must resume, and the tunnel process must be the same one:
    // a restart would make this a reconnection test.
    let (exited, _) = rig
        .sb
        .wait(tunnel, 0)
        .expect("the tunnel handle must answer");
    assert!(
        !exited,
        "the tunnel process died during the roam, so what resumed below is a new session"
    );

    let mut carried = 0;
    for _ in 0..5 {
        carried = received(&send(&mut rig));
        if carried > 0 {
            break;
        }
    }
    assert!(
        carried > 0,
        "the session did not survive the roam. The far end learns its peer from the first \
         datagram after the move, so a failure here means the datagram never arrived or \
         the far end refused to follow it."
    );
}

#[test]
fn a_roam_puts_no_protected_addressing_on_either_access_network() {
    let Some(mut rig) = common::or_skip("roam-leak", rigs::build_roam_site("roam-leak")) else {
        return;
    };
    rigs::start_roam_tunnel(&mut rig).expect("the tunnel must come up");
    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    let (_, capture) = fabric
        .start_capture(&mut rig.sb, "device", "wan", "roam-leak", 10_000)
        .expect("the observer must start");
    rig.fabric = fabric;
    settle();

    let agent = rig.sb.agent_path().display().to_string();
    let overlay = format!("{}:9", rigs::EXIT_OVERLAY_V4);
    let send = |rig: &mut common::Rig| {
        let _ = rig.sb.run(
            Some("device"),
            &[
                &agent,
                "udp-send",
                "--to",
                &overlay,
                "--count",
                "3",
                "--interval-ms",
                "30",
                "--wait-ms",
                "300",
            ],
        );
    };
    send(&mut rig);
    rigs::roam_to_cell(&mut rig).expect("the roam must happen");
    settle();
    for _ in 0..4 {
        send(&mut rig);
    }

    std::thread::sleep(std::time::Duration::from_millis(700));
    let capture = Capture::load(&capture).expect("the capture must exist");
    assert!(
        !capture.is_silent(),
        "the observer saw nothing across the roam"
    );
    let escapes = LeakPolicy::sealed()
        .protecting(Prefix::parse(rigs::OVERLAY_V4).expect("the overlay v4 prefix"))
        .protecting(Prefix::parse(rigs::OVERLAY_V6).expect("the overlay v6 prefix"))
        .protected_only()
        .audit(&capture);
    assert!(
        escapes.is_empty(),
        "protected addressing appeared on an access network across the roam. The window \
         between losing one path and learning the next is exactly where a device sends \
         in the clear:\n  {}",
        escapes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}
