//! The kill switch on the topology its own document declares.
//!
//! **Authority:** `docs/testing-strategy.md` §3.6 (`S-KS-*`); ADR-0012 §11.9.
//!
//! Every `S-KS-*` scenario declares one site behind `N-EIM-APDF`:
//!
//! ```text
//! sites = [ { id = "a", nat = "N-EIM-APDF", lifetime_s = 120, hairpin = false, portmap = "none" } ]
//! ```
//!
//! `lab/twinnet/tests/fail_closed_packets.rs` asserts the fail-closed property
//! at packet level and asserts it well — but on a rig with **no middlebox**, and
//! `twinlab-scenarios run` therefore reported those ids `NOT-EXECUTABLE` rather
//! than running them on a topology that is not the one they describe.
//!
//! This file is that topology. Nothing about the oracle changes; what changes is
//! that a NAT is in the path, so the device's underlay source address is private,
//! its public endpoint is allocated by the middlebox rather than configured, and
//! the far end has to learn where its peer is.
//!
//! # The address that does not change
//!
//! The device's *public* address is `198.18.0.2` in both topologies — it is the
//! device's own without a middlebox and the middlebox's with one. So the exit,
//! the control plane, the rogue resolver and every leak policy name the same
//! endpoints either way, and a difference in a result is a difference the
//! middlebox made rather than a difference in the rig's addressing.

mod common;

use common::settle;
use twinnet::nat::config::{Filtering, Mapping};
use twinnet::observer::{Prefix, Reason};
use twinnet::rigs::{self, Personality};
use twinnet::{Capture, LeakPolicy};

/// §3.3's `N-EIM-APDF`, which every `S-KS-*` document declares.
const EIM_APDF: Personality = Personality {
    name: "N-EIM-APDF",
    mapping: Mapping::EndpointIndependent,
    filtering: Filtering::AddressPortDependent,
};

fn policy() -> LeakPolicy {
    LeakPolicy::sealed()
        .protecting(Prefix::parse(rigs::OVERLAY_V4).expect("the overlay v4 prefix"))
        .protecting(Prefix::parse(rigs::OVERLAY_V6).expect("the overlay v6 prefix"))
        .resolver(rigs::EXIT_OVERLAY_V4.parse().expect("a literal"))
}

/// The names this test leaks on purpose, as its positive controls.
///
/// They are excluded by **name**, not by suppressing DNS findings: the oracle
/// still reports every other off-tunnel lookup, and a real DNS leak with any
/// other name still fails. Excluding the whole category would have made the
/// canary's own success hide the thing it exists to prove is catchable.
const DELIBERATE: [&str; 2] = ["canary.twinvpn.invalid", "after.twinvpn.invalid"];

fn protected_escapes(capture: &Capture) -> Vec<String> {
    policy()
        .audit(capture)
        .into_iter()
        .filter(|e| match &e.reason {
            Reason::ProtectedSource { .. } | Reason::ProtectedDestination { .. } => true,
            Reason::UnauthorizedDns { qname } => {
                !qname.as_deref().is_some_and(|q| DELIBERATE.contains(&q))
            }
            _ => false,
        })
        .map(|e| e.to_string())
        .collect()
}

fn received(ran: &twinnet::Ran) -> u32 {
    #[derive(serde::Deserialize)]
    struct R {
        received: u32,
    }
    serde_json::from_str::<R>(ran.stdout.trim()).map_or(0, |r| r.received)
}

fn send(rig: &mut common::Rig, to: &str, count: &str) -> twinnet::Ran {
    let agent = rig.sb.agent_path().display().to_string();
    let bind = if to.starts_with('[') {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    rig.sb
        .run(
            Some("device"),
            &[
                &agent,
                "udp-send",
                "--to",
                to,
                "--bind",
                bind,
                "--count",
                count,
                "--interval-ms",
                "30",
                "--wait-ms",
                "200",
            ],
        )
        .expect("the sender must run")
}

fn load(path: &std::path::Path) -> Capture {
    std::thread::sleep(std::time::Duration::from_millis(700));
    Capture::load(path).expect("the capture must exist — a missing one is not an empty one")
}

// ===========================================================================

#[test]
fn s_ks_fail_closed_holds_with_the_declared_middlebox_in_the_path() {
    let Some(mut rig) = common::or_skip(
        "ks-behind-nat",
        rigs::build_tunnel_site_with("ks-behind-nat", Some(&EIM_APDF)),
    ) else {
        return;
    };
    let ends = rigs::start_tunnel(&mut rig).expect("the tunnel must come up through the NAT");
    // ADR-0012's kill switch, as an OS-level blackhole for each overlay prefix.
    // The tunnel's own route is longer-prefix and wins while `tun0` exists; when
    // the tunnel dies the blackhole is what is left.
    rigs::arm_kill_switch(&mut rig).expect("the kill switch must arm");

    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    let (_, capture) = fabric
        .start_capture(&mut rig.sb, "device", "wan", "ks-behind-nat", 12_000)
        .expect("the observer must start");
    rig.fabric = fabric;
    settle();

    // V3: the middlebox is really in the path. The device's underlay source is
    // private, and if it were not, this whole file would be the no-middlebox rig
    // wearing a different label.
    let addrs = rig
        .sb
        .must(Some("device"), &["ip", "-4", "addr", "show", "wan"])
        .expect("the device's addressing must be readable");
    assert!(
        addrs.contains(rigs::DEVICE_PRIVATE),
        "the device is not on the private segment, so no middlebox is in the path:\n{addrs}"
    );

    // B-7: the canary's positive control, green in the same session. A capture
    // that recorded nothing is indistinguishable from a sealed tunnel.
    let agent = rig.sb.agent_path().display().to_string();
    let rogue = format!("{}:53", rigs::ROGUE_UNDERLAY);
    let _ = rig.sb.run(
        Some("device"),
        &[
            &agent,
            "dns-query",
            "--server",
            &rogue,
            "--name",
            "canary.twinvpn.invalid",
            "--wait-ms",
            "250",
        ],
    );
    let control = load(&capture);
    assert!(
        policy().audit(&control).iter().any(|e| matches!(
            &e.reason,
            Reason::UnauthorizedDns { qname } if qname.as_deref() == Some("canary.twinvpn.invalid")
        )),
        "the positive control did not leak, so nothing below proves anything"
    );

    // Protected traffic, per family, as the document requires.
    let v4 = format!("{}:9", rigs::EXIT_OVERLAY_V4);
    let v6 = format!("[{}]:9", rigs::EXIT_OVERLAY_V6);
    assert!(
        received(&send(&mut rig, &v4, "3")) > 0,
        "the tunnel carried nothing through the middlebox, so `nothing leaked` is a \
         statement about a dead tunnel"
    );
    let _ = send(&mut rig, &v6, "3");

    let sealed = load(&capture);
    let escapes = protected_escapes(&sealed);
    assert!(
        escapes.is_empty(),
        "protected addressing reached the underlay from behind the middlebox:\n  {}",
        escapes.join("\n  ")
    );

    // Fail-closed: the tunnel dies, protected traffic stops rather than finding
    // another way out, and the observer is still watching afterwards.
    assert!(
        rig.sb
            .signal(ends.device, 9)
            .expect("the signal must be sent"),
        "the tunnel was already dead, so killing it proves nothing"
    );
    settle();
    assert_eq!(
        received(&send(&mut rig, &v4, "3")),
        0,
        "protected traffic was still answered after the tunnel died"
    );
    let _ = rig.sb.run(
        Some("device"),
        &[
            &agent,
            "dns-query",
            "--server",
            &rogue,
            "--name",
            "after.twinvpn.invalid",
            "--wait-ms",
            "250",
        ],
    );
    let after = load(&capture);
    assert!(
        policy().audit(&after).iter().any(|e| matches!(
            &e.reason,
            Reason::UnauthorizedDns { qname } if qname.as_deref() == Some("after.twinvpn.invalid")
        )),
        "the observer stopped seeing the interface after the kill, so `nothing leaked` \
         would be a statement about the observer"
    );
    let escapes = protected_escapes(&after);
    assert!(
        escapes.is_empty(),
        "protected addressing reached the underlay after the tunnel died:\n  {}",
        escapes.join("\n  ")
    );

    // The mutant (V2), in the same session. Disarm the kill switch and the very
    // same traffic escapes in the clear through the default route — so the
    // silence above is the kill switch's doing and not the topology's.
    rigs::disarm_kill_switch(&mut rig).expect("the kill switch must disarm");
    let _ = send(&mut rig, &v4, "3");
    let mutant = load(&capture);
    let caught = protected_escapes(&mutant);
    assert!(
        !caught.is_empty(),
        "with the kill switch disarmed and the tunnel dead, protected traffic did NOT \
         escape — so `nothing escaped` while it was armed says nothing about the kill \
         switch. Every assertion above is only as good as this one."
    );
}
