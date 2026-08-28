//! Address families, local-direct, and the CGNAT tier.
//!
//! **Authority:** `docs/networking.md` §2.1, §3.2 (last row and column), §3.6;
//! `docs/testing-strategy.md` §3.3 (`N-CGNAT`, `N-NAT64`), §3.4.2, rule **L-5**.
//!
//! # §3.2's last row is the claim worth testing hardest
//!
//! > Read the last row and column first: **if both ends have working IPv6, every
//! > cell is `D`.** This is the single highest-leverage fact in the whole
//! > traversal design.
//!
//! A laboratory that only ever ran IPv4 would leave that claim entirely
//! unmeasured while reporting a large green matrix. The v6 tests here run the
//! **same** peers over a native v6 underlay through the **same** middleboxes —
//! configured with a symmetric IPv4 personality, so a v6 regression shows up as
//! a pair that stops being direct and nothing else changes.

mod common;

use common::{settle, Personality, PERSONALITIES, PORT_A, REFLECT_A6};
use twinnet::nat::config::{Filtering, Mapping, Neighbour};
use twinnet::traffic::P2pReport;

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

fn punch(rig: &mut common::Rig, reflector: &str, label: &str) -> (P2pReport, P2pReport) {
    let agent = rig.sb.agent_path().display().to_string();
    let a_ep = rig.scratch.join(format!("{label}-a.endpoint"));
    let b_ep = rig.scratch.join(format!("{label}-b.endpoint"));
    let a_out = rig.scratch.join(format!("{label}-a.json"));
    let b_out = rig.scratch.join(format!("{label}-b.json"));
    for f in [&a_ep, &b_ep, &a_out, &b_out] {
        let _ = std::fs::remove_file(f);
    }
    let (a_ep_s, b_ep_s) = (a_ep.display().to_string(), b_ep.display().to_string());
    let spawn =
        |rig: &mut common::Rig, node: &str, mine: &str, theirs: &str, out: &std::path::Path| {
            rig.sb
                .spawn(
                    Some(node),
                    &[
                        &agent,
                        "p2p",
                        "--reflector",
                        reflector,
                        "--mine",
                        mine,
                        "--theirs",
                        theirs,
                        "--rounds",
                        "10",
                        "--interval-ms",
                        "60",
                        "--wait-ms",
                        "4000",
                    ],
                    Some(out),
                )
                .expect("a peer must start")
        };
    let ha = spawn(rig, "peer-a", &a_ep_s, &b_ep_s, &a_out);
    let hb = spawn(rig, "peer-b", &b_ep_s, &a_ep_s, &b_out);
    let _ = rig.sb.wait(ha, 20_000);
    let _ = rig.sb.wait(hb, 20_000);
    let decode = |path: &std::path::Path, who: &str| -> P2pReport {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        serde_json::from_str(text.trim())
            .unwrap_or_else(|e| panic!("{who}'s report was undecodable ({e}): {text}"))
    };
    (decode(&a_out, "peer-a"), decode(&b_out, "peer-b"))
}

// ===========================================================================

#[test]
fn native_ipv6_is_direct_even_between_two_symmetric_ipv4_middleboxes() {
    let Some(mut rig) = common::or_skip(
        "v6-native-direct",
        common::build_two_site("v6-native-direct"),
    ) else {
        return;
    };
    // The hardest IPv4 pair §3.2 has: APDM x APDM is declared relay-by-design
    // over v4, and `traversal_matrix.rs` asserts it does NOT reach a direct path.
    // The same pair over v6 must, because nothing translates v6.
    install(&mut rig, &PERSONALITIES[4], &PERSONALITIES[4]);

    let reflector = format!("[{REFLECT_A6}]:{PORT_A}");
    let (a, b) = punch(&mut rig, &reflector, "v6");
    assert!(
        a.direct && b.direct,
        "IPv6 was not direct between two symmetric IPv4 middleboxes. §3.2's last row is \
         unconditional and is the reason ADR-0004 makes IPv6 the first-choice path rather \
         than a fallback.\n  a: {a:?}\n  b: {b:?}"
    );
    let mapped = a.mapped.clone().unwrap_or_default();
    assert!(
        mapped.contains("2001:db8:a:"),
        "the v6 endpoint the reflector observed was `{mapped}`, which is not the peer's own \
         address — something translated v6, and nothing in this topology should"
    );
}

#[test]
fn a_dual_stack_site_reaches_its_peer_in_both_families_from_one_topology() {
    let Some(mut rig) = common::or_skip("dual-stack", common::build_two_site("dual-stack")) else {
        return;
    };
    // A pair §3.2 marks `D` over IPv4, so both families are expected to succeed
    // and a failure in either is attributable to that family alone. Rule L-5:
    // every scenario is instantiated for v4-only, v6-only and dual, and this is
    // the instantiation where a family-asymmetric regression is visible.
    install(&mut rig, &PERSONALITIES[1], &PERSONALITIES[1]);

    let v4 = format!("{}:{}", common::REFLECT_A, PORT_A);
    let (a4, b4) = punch(&mut rig, &v4, "dual-v4");
    let v6 = format!("[{REFLECT_A6}]:{PORT_A}");
    let (a6, b6) = punch(&mut rig, &v6, "dual-v6");

    assert!(a4.direct && b4.direct, "the v4 half failed: {a4:?} {b4:?}");
    assert!(a6.direct && b6.direct, "the v6 half failed: {a6:?} {b6:?}");
    assert_ne!(
        a4.mapped, a6.mapped,
        "both families reported the same mapped endpoint, so one of the two runs did not \
         use the family it was asked for"
    );
}

#[test]
fn two_hosts_behind_one_middlebox_reach_each_other_on_the_lan_without_traversing_it() {
    let Some(mut rig) = common::or_skip("local-direct", common::build("local-direct", true)) else {
        return;
    };
    let cfg = common::nat_config(&rig, &PERSONALITIES[3]);
    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    let (_, stats) = fabric
        .start_nat(&mut rig.sb, "cpe", &cfg)
        .expect("the middlebox must start");
    rig.fabric = fabric;
    settle();

    // `client` and `client2` are two hosts on one bridged LAN behind the same
    // middlebox. Reaching each other must not involve the middlebox at all —
    // that is `ObservedPath::LocalDirect`, the path ADR-0004 prefers above every
    // other, and the assertion below is that the public one was never used.
    let agent = rig.sb.agent_path().display().to_string();
    let log = rig.scratch.join("local-echo.log");
    rig.sb
        .spawn(
            Some("client2"),
            &[&agent, "udp-echo", "--bind", "10.0.1.3:9", "--ms", "30000"],
            Some(&log),
        )
        .expect("the local peer must start");
    settle();

    let ran = rig
        .sb
        .run(
            Some("client"),
            &[
                &agent,
                "udp-send",
                "--to",
                "10.0.1.3:9",
                "--count",
                "3",
                "--interval-ms",
                "30",
                "--wait-ms",
                "300",
            ],
        )
        .expect("the local sender must run");
    #[derive(serde::Deserialize)]
    struct R {
        received: u32,
    }
    let r: R = serde_json::from_str(ran.stdout.trim()).expect("a send report");
    assert!(
        r.received > 0,
        "two hosts on the same middlebox could not reach each other locally: {}",
        ran.stdout
    );

    // And the public path was not what carried it: no mapping was allocated,
    // because nothing was translated.
    let snapshot = std::fs::read_to_string(&stats).unwrap_or_default();
    assert!(
        !snapshot.contains("\"external_port\""),
        "a local exchange allocated a public mapping, so it did not stay local:\n{snapshot}"
    );
}

#[test]
fn the_cgnat_tier_shares_one_public_address_across_subscribers_with_disjoint_port_budgets() {
    let Some(mut rig) = common::or_skip("cgnat", common::build("cgnat", true)) else {
        return;
    };
    // §3.3's `N-CGNAT`: "`N-EIM-APDF` at the CPE chained into a shared
    // `N-APDM-APDF` carrier namespace ... whose public address is shared by >= 2
    // subscriber trees. Port budget per subscriber is capped so exhaustion is
    // reachable."
    //
    // This rig runs the carrier tier directly, with two subscriber hosts sharing
    // one public address out of a deliberately tiny budget. What §3.4.2 asks for
    // is asserted below: one shared public address, disjoint port ranges, and a
    // reachable exhaustion.
    let mut cfg = common::nat_config(&rig, &PERSONALITIES[4]);
    cfg.personality = "N-CGNAT".to_owned();
    cfg.mapping = Mapping::AddressPortDependentRandom;
    cfg.filtering = Filtering::AddressPortDependent;
    cfg.port_low = 40_000;
    cfg.port_high = 40_007; // eight ports, so exhaustion is reachable in seconds
    cfg.outside_neighbours = vec![Neighbour {
        addr: common::REFLECT_A.to_owned(),
        mac: rig
            .fabric
            .mac("reflector", "wan")
            .expect("the reflector's MAC"),
    }];
    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    let (_, stats) = fabric
        .start_nat(&mut rig.sb, "cpe", &cfg)
        .expect("the carrier tier must start");
    rig.fabric = fabric;
    settle();

    let agent = rig.sb.agent_path().display().to_string();
    let reflector = format!("{}:{}", common::REFLECT_A, PORT_A);
    let mut mapped: Vec<(String, String)> = Vec::new();
    for subscriber in ["client", "client2"] {
        for _ in 0..3 {
            let ran = rig
                .sb
                .run(
                    Some(subscriber),
                    &[
                        &agent,
                        "udp-send",
                        "--to",
                        &reflector,
                        "--payload",
                        "PROBE",
                        "--count",
                        "1",
                        "--wait-ms",
                        "600",
                    ],
                )
                .expect("the subscriber's probe must run");
            #[derive(serde::Deserialize)]
            struct R {
                replies: Vec<String>,
            }
            if let Ok(r) = serde_json::from_str::<R>(ran.stdout.trim()) {
                for reply in r.replies {
                    let mut parts = reply.split_whitespace();
                    if parts.next() == Some("MAPPED") {
                        if let (Some(ip), Some(port)) = (parts.next(), parts.next()) {
                            mapped.push((subscriber.to_owned(), format!("{ip}:{port}")));
                        }
                    }
                }
            }
        }
    }

    assert!(
        mapped.len() >= 4,
        "not enough subscriber probes were mapped to say anything about sharing: {mapped:?}"
    );
    let addresses: std::collections::BTreeSet<&str> = mapped
        .iter()
        .map(|(_, ep)| ep.split(':').next().unwrap_or(""))
        .collect();
    assert_eq!(
        addresses.len(),
        1,
        "the two subscriber trees did not observe the SAME public address, which is what \
         makes this a carrier tier rather than two NATs: {mapped:?}"
    );

    let ports_of = |who: &str| -> std::collections::BTreeSet<&str> {
        mapped
            .iter()
            .filter(|(s, _)| s == who)
            .map(|(_, ep)| ep.rsplit(':').next().unwrap_or(""))
            .collect()
    };
    let a = ports_of("client");
    let b = ports_of("client2");
    assert!(
        a.intersection(&b).next().is_none(),
        "two subscribers were given overlapping external ports, so one subscriber's \
         traffic could be delivered to the other: {mapped:?}"
    );

    // Exhaustion must be REACHABLE, not merely possible: §3.3 says so, and a
    // carrier tier whose exhaustion path is never taken is a carrier tier whose
    // exhaustion path is untested.
    for subscriber in ["client", "client2"] {
        for _ in 0..8 {
            let _ = rig.sb.run(
                Some(subscriber),
                &[
                    &agent,
                    "udp-send",
                    "--to",
                    &reflector,
                    "--payload",
                    "PROBE",
                    "--count",
                    "1",
                    "--wait-ms",
                    "60",
                ],
            );
        }
    }
    let snapshot = twinnet::rigs::await_snapshot(&stats, std::time::Duration::from_secs(3), |v| {
        v["exhaustions"].as_u64().unwrap_or(0) > 0
    })
    .expect("the middlebox must write a snapshot");
    assert!(
        snapshot["exhaustions"].as_u64().unwrap_or(0) > 0
            && twinnet::rigs::counter(&snapshot, "exhausted") > 0,
        "an eight-port carrier budget was never exhausted by sixteen distinct flows, so \
         the exhaustion path §3.3 requires to be reachable was not reached:\n{snapshot:#}"
    );
}
