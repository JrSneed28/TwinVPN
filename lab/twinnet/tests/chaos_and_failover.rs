//! Chaos: what happens when the infrastructure goes away.
//!
//! **Authority:** `docs/testing-strategy.md` §2.13 and §3.4's fault rows;
//! `docs/architecture.md` invariant **I5**; `docs/reliability.md` §9.
//!
//! # The invariant these tests exist for
//!
//! > **I5** — *a control-plane outage must not tear down established tunnels.*
//!
//! `tests/chaos/outage_and_failover.rs` asserts I5 the way a state machine can:
//! it shows that no control-plane event exists in the data plane's alphabet, so
//! an outage cannot even *express* itself as a data-plane transition. That is a
//! structural argument and it is the stronger one.
//!
//! This file asserts the other half, which no in-process test can: that with a
//! real path between two real sockets across a real middlebox, **removing the
//! rendezvous does not stop the datagrams**. Each test establishes a path,
//! holds it, and destroys something while it is held. `held_received` is the
//! oracle — and it is a count of packets that arrived, not a state the system
//! reported about itself.
//!
//! # What "the control plane" is here, said plainly
//!
//! These are `twinnet`'s own reflector and forwarder, not `twinvpn-rendezvous`
//! and `twinvpn-relay`. The property under test is topological — *does an
//! established path need the thing that set it up?* — and it is answered by the
//! packets. Nothing here should be read as evidence about the real services'
//! admission, tokens or wire; that evidence belongs to `lab/twinsim` and to
//! `services/*/tests`, which drive the real binaries.

mod common;

use common::{
    settle, Personality, PERSONALITIES, PORT_A, REFLECT_A, RELAY_EU, RELAY_PORT, RELAY_US,
};
use twinnet::relay::RelayedReport;
use twinnet::traffic::P2pReport;

fn eim_eif() -> &'static Personality {
    &PERSONALITIES[1]
}

fn symmetric() -> &'static Personality {
    &PERSONALITIES[4]
}

/// Installs a personality on both middleboxes.
fn install(rig: &mut common::Rig, local: &Personality, remote: &Personality) {
    for handle in rig.fabric.processes().to_vec() {
        let _ = rig.sb.signal(handle, 9);
    }
    let cfg_a = common::site_nat(rig, "a", local);
    let cfg_b = common::site_nat(rig, "b", remote);
    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    fabric
        .start_nat(&mut rig.sb, "cpe-a", &cfg_a)
        .expect("site a's middlebox must start");
    fabric
        .start_nat(&mut rig.sb, "cpe-b", &cfg_b)
        .expect("site b's middlebox must start");
    rig.fabric = fabric;
    settle();
}

/// Runs both peers through the relay list and returns what each observed.
fn relayed_pair(rig: &mut common::Rig, relays: &str, tag: &str) -> (RelayedReport, RelayedReport) {
    let agent = rig.sb.agent_path().display().to_string();
    let out = rig.scratch.join(format!("relayed-a-{tag}.json"));
    let _ = std::fs::remove_file(&out);
    let handle = rig
        .sb
        .spawn(
            Some("peer-a"),
            &[
                &agent,
                "relayed",
                "--relays",
                relays,
                "--tag",
                tag,
                "--rounds",
                "12",
                "--interval-ms",
                "50",
                "--bind-wait-ms",
                "400",
            ],
            Some(&out),
        )
        .expect("peer a must start");
    let ran = rig
        .sb
        .run(
            Some("peer-b"),
            &[
                &agent,
                "relayed",
                "--relays",
                relays,
                "--tag",
                tag,
                "--rounds",
                "12",
                "--interval-ms",
                "50",
                "--bind-wait-ms",
                "400",
            ],
        )
        .expect("peer b must run");
    let _ = rig.sb.wait(handle, 8_000);
    let a_text = std::fs::read_to_string(&out).unwrap_or_default();
    let decode = |text: &str, who: &str| -> RelayedReport {
        serde_json::from_str(text.trim())
            .unwrap_or_else(|e| panic!("{who}'s relayed report was undecodable ({e}): {text}"))
    };
    (decode(&a_text, "peer-a"), decode(&ran.stdout, "peer-b"))
}

/// Punches a direct path and holds it, running `during` at the midpoint.
fn punch_and_hold(
    rig: &mut common::Rig,
    hold_ms: u64,
    during: impl FnOnce(&mut common::Rig),
) -> (P2pReport, P2pReport) {
    let agent = rig.sb.agent_path().display().to_string();
    let a_ep = rig.scratch.join("hold-a.endpoint");
    let b_ep = rig.scratch.join("hold-b.endpoint");
    let a_out = rig.scratch.join("hold-a.json");
    let b_out = rig.scratch.join("hold-b.json");
    for f in [&a_ep, &b_ep, &a_out, &b_out] {
        let _ = std::fs::remove_file(f);
    }
    let reflector = format!("{REFLECT_A}:{PORT_A}");
    let hold = hold_ms.to_string();
    let (a_ep_s, b_ep_s) = (a_ep.display().to_string(), b_ep.display().to_string());

    let args = |mine: &str, theirs: &str| {
        vec![
            "p2p".to_owned(),
            "--reflector".to_owned(),
            reflector.clone(),
            "--mine".to_owned(),
            mine.to_owned(),
            "--theirs".to_owned(),
            theirs.to_owned(),
            "--rounds".to_owned(),
            "8".to_owned(),
            "--interval-ms".to_owned(),
            "50".to_owned(),
            "--wait-ms".to_owned(),
            "4000".to_owned(),
            "--hold-ms".to_owned(),
            hold.clone(),
        ]
    };
    let spawn = |rig: &mut common::Rig, node: &str, argv: Vec<String>, out: &std::path::Path| {
        let mut full = vec![agent.clone()];
        full.extend(argv);
        let refs: Vec<&str> = full.iter().map(String::as_str).collect();
        rig.sb
            .spawn(Some(node), &refs, Some(out))
            .expect("a peer must start")
    };
    let ha = spawn(rig, "peer-a", args(&a_ep_s, &b_ep_s), &a_out);
    let hb = spawn(rig, "peer-b", args(&b_ep_s, &a_ep_s), &b_out);

    // Act while the path is held, not while it is being established: the
    // property is about an ESTABLISHED path, and killing the rendezvous during
    // discovery would test something else entirely.
    std::thread::sleep(std::time::Duration::from_millis(1_500));
    during(rig);

    let _ = rig.sb.wait(ha, 30_000);
    let _ = rig.sb.wait(hb, 30_000);
    let decode = |path: &std::path::Path, who: &str| -> P2pReport {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        serde_json::from_str(text.trim())
            .unwrap_or_else(|e| panic!("{who}'s report was undecodable ({e}): {text}"))
    };
    (decode(&a_out, "peer-a"), decode(&b_out, "peer-b"))
}

// ===========================================================================

#[test]
fn a_pair_that_cannot_meet_directly_is_carried_by_a_relay() {
    let Some(mut rig) = common::or_skip("relay-fallback", common::build_two_site("relay-fallback"))
    else {
        return;
    };
    install(&mut rig, symmetric(), symmetric());
    let relays = format!("{RELAY_EU}:{RELAY_PORT},{RELAY_US}:{RELAY_PORT}");
    let (a, b) = relayed_pair(&mut rig, &relays, "fallback");

    assert!(
        a.bound && b.bound,
        "neither leg bound to a relay: a {a:?} b {b:?}"
    );
    assert_eq!(
        a.relay.as_deref(),
        Some(format!("{RELAY_EU}:{RELAY_PORT}").as_str()),
        "the first relay in the list answered, so it must be the one chosen"
    );
    assert!(
        a.received > 0 && b.received > 0,
        "a relay-by-design pair bound to a relay and still exchanged nothing: a {a:?} b {b:?}"
    );
}

#[test]
fn relay_termination_fails_over_to_the_standby_with_no_user_action() {
    let Some(mut rig) = common::or_skip(
        "relay-termination",
        common::build_two_site("relay-termination"),
    ) else {
        return;
    };
    install(&mut rig, symmetric(), symmetric());
    let relays = format!("{RELAY_EU}:{RELAY_PORT},{RELAY_US}:{RELAY_PORT}");

    // The precondition is asserted, not assumed (V3): failover to a standby
    // means nothing unless the primary was the one being used first.
    let (before, _) = relayed_pair(&mut rig, &relays, "before");
    assert_eq!(
        before.relay.as_deref(),
        Some(format!("{RELAY_EU}:{RELAY_PORT}").as_str()),
        "the primary must be in use before its death can be a failover"
    );

    let primary = rig.process("relay-eu").expect("the primary relay's handle");
    assert!(
        rig.sb.signal(primary, 9).expect("the signal must be sent"),
        "the primary relay was already dead, so killing it proves nothing"
    );
    settle();

    let (a, b) = relayed_pair(&mut rig, &relays, "after");
    assert!(
        a.bound && b.bound,
        "after the primary died neither leg reached the standby: a {a:?} b {b:?}"
    );
    assert_eq!(
        a.relay.as_deref(),
        Some(format!("{RELAY_US}:{RELAY_PORT}").as_str()),
        "the standby must be the relay in use after the primary died"
    );
    assert_eq!(
        a.attempts, 2,
        "the primary must have been tried and failed first"
    );
    assert!(
        a.received > 0 && b.received > 0,
        "the pair failed over and then carried nothing: a {a:?} b {b:?}"
    );
}

#[test]
fn a_whole_region_disappearing_fails_over_the_same_way_as_a_process_dying() {
    let Some(mut rig) = common::or_skip("region-outage", common::build_two_site("region-outage"))
    else {
        return;
    };
    install(&mut rig, symmetric(), symmetric());
    let relays = format!("{RELAY_EU}:{RELAY_PORT},{RELAY_US}:{RELAY_PORT}");

    // A region outage is not a process dying: the relay is healthy and
    // unreachable. The distinction matters because a client that only handles
    // the first case hangs on the second, waiting for a refusal that a
    // blackholed path never sends.
    let fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    fabric
        .set_link(&mut rig.sb, "relay-eu", "wan", false)
        .expect("the region's link must go down");
    rig.fabric = fabric;
    settle();

    let (a, b) = relayed_pair(&mut rig, &relays, "region");
    assert_eq!(
        a.relay.as_deref(),
        Some(format!("{RELAY_US}:{RELAY_PORT}").as_str()),
        "a blackholed region must be left behind, not waited on: {a:?}"
    );
    assert!(a.received > 0 && b.received > 0, "a {a:?} b {b:?}");
}

#[test]
fn total_relay_unavailability_is_named_rather_than_reported_as_a_working_path() {
    let Some(mut rig) = common::or_skip(
        "relay-total-outage",
        common::build_two_site("relay-total-outage"),
    ) else {
        return;
    };
    install(&mut rig, symmetric(), symmetric());
    for node in ["relay-eu", "relay-us"] {
        let handle = rig.process(node).expect("a relay handle");
        let _ = rig.sb.signal(handle, 9);
    }
    settle();

    let relays = format!("{RELAY_EU}:{RELAY_PORT},{RELAY_US}:{RELAY_PORT}");
    let (a, b) = relayed_pair(&mut rig, &relays, "total");
    assert!(
        !a.bound && !b.bound,
        "every relay was dead and a leg still reported a binding: a {a:?} b {b:?}"
    );
    assert_eq!(a.attempts, 2, "both relays must have been tried");
    assert_eq!(
        a.received, 0,
        "a leg that bound to nothing must not report traffic"
    );
}

#[test]
fn an_established_direct_path_survives_the_rendezvous_being_killed() {
    let Some(mut rig) = common::or_skip(
        "i5-rendezvous-death",
        common::build_two_site("i5-rendezvous-death"),
    ) else {
        return;
    };
    install(&mut rig, eim_eif(), eim_eif());

    let (a, b) = punch_and_hold(&mut rig, 3_000, |rig| {
        let reflector = rig.process("reflector").expect("the reflector's handle");
        assert!(
            rig.sb
                .signal(reflector, 9)
                .expect("the signal must be sent"),
            "the rendezvous was already dead, so killing it proves nothing"
        );
    });

    assert!(
        a.direct && b.direct,
        "the path was never established, so its survival is not what was measured: a {a:?} b {b:?}"
    );
    assert!(
        a.held_sent > 0 && b.held_sent > 0,
        "no traffic was attempted during the hold, so nothing was measured"
    );
    assert!(
        a.held_received > 0 && b.held_received > 0,
        "an established direct path stopped carrying traffic when the rendezvous died. \
         I5 says a control-plane outage must not tear down an established tunnel; \
         a: {a:?}\nb: {b:?}"
    );
}
