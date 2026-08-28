//! The leak matrix: IPv4, IPv6 and DNS, asserted over the **constructed pf
//! anchor** in every state the enforcement state machine can reach.
//!
//! **Authority:** ADR-0012 K1, K2 ("a v4-only guard is a leak"), K9, K12, KS-3,
//! KS-5, KS-6, KS-9, KS-11, KS-17, KS-18, §11.2 (the traffic-class table), §11.9
//! (the leak canary); ADR-0010 R1; ADR-0011 §11.9 and §11.12; ADR-0015 §11.6
//! rule 1.
//!
//! # What a leak test can and cannot be, on this host
//!
//! There is no `pfctl` here, no Darwin kernel and no packet. So this suite does
//! not claim to observe a leak; it claims something narrower and checkable: **the
//! anchor this adapter constructs denies the family in question in every state
//! the state machine can reach**, and it asserts that over the data rather than
//! by sampling one or two cases.
//!
//! The state space is enumerated explicitly — two postures × three routing modes
//! × two `local_network_access` settings × two KS-9 predicates, 24 states — and
//! every invariant below is checked in all of them. What is *not* checked is that
//! Apple's pf parses the text and behaves as pf is documented to; that needs a
//! Mac and is named as a gap in `shells/macos/README.md` §7.

use std::collections::BTreeSet;

use twinvpn_platform::{ContractGeneration, DnsConfig, NetworkContract, Ruleset};
use twinvpn_platform_macos::pf::{
    self, EnforcementConfig, ExemptPredicate, DENY_LABEL, DNS_DENY_LABEL, EXEMPT_LABEL, SCOPE_TABLE,
};
use twinvpn_platform_macos::pfread;
use twinvpn_platform_macos::testkit::{self, table_names_in};
use twinvpn_types::PerFamily;

/// ADR-0012 §11.1's three routing modes, as the contract shapes that express
/// them. The core decides which is in force; this adapter only ever renders what
/// it was handed (CB-2), so the test drives all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// The overlay space only.
    TwinNetOnly,
    /// The overlay space plus an accepted LAN-gateway route.
    Split,
    /// The four `/1` routes of `docs/networking.md` §7.2.
    FullTunnel,
}

impl Mode {
    const ALL: [Self; 3] = [Self::TwinNetOnly, Self::Split, Self::FullTunnel];

    fn contract(self, generation: u64, ruleset: Ruleset) -> NetworkContract {
        match self {
            Mode::TwinNetOnly => testkit::contract_with(generation, ruleset),
            Mode::Split => {
                let mut c = testkit::contract_with(generation, ruleset);
                c.routes.v4.push(twinvpn_platform::RouteEntry {
                    destination: testkit::v4([10, 0, 0, 0], 8),
                    via: None,
                    interface: twinvpn_platform::InterfaceIndex(9),
                    metric: None,
                });
                c.routes.v6.push(twinvpn_platform::RouteEntry {
                    destination: testkit::v6(0x20, 0x01, 32),
                    via: None,
                    interface: twinvpn_platform::InterfaceIndex(9),
                    metric: None,
                });
                c
            }
            Mode::FullTunnel => testkit::full_tunnel_contract(generation, ruleset),
        }
    }
}

/// Every state the enforcement state machine can reach.
fn states() -> Vec<(Ruleset, Mode, bool, ExemptPredicate)> {
    let mut out = Vec::new();
    for ruleset in [Ruleset::Blocked, Ruleset::Protected] {
        for mode in Mode::ALL {
            for lan in [true, false] {
                for exempt in [
                    ExemptPredicate::ProviderUidAndSocketSet { uid: 501 },
                    ExemptPredicate::UidOnly { uid: 501 },
                ] {
                    out.push((ruleset, mode, lan, exempt));
                }
            }
        }
    }
    out
}

fn config(lan: bool, exempt: ExemptPredicate) -> EnforcementConfig {
    EnforcementConfig {
        local_network_access: lan,
        exempt,
        ..testkit::enforcement()
    }
}

/// Every `pass` line in a rendered anchor, with its label.
fn pass_labels(anchor: &str) -> Vec<String> {
    anchor
        .lines()
        .filter(|line| line.trim_start().starts_with("pass "))
        .filter_map(|line| line.split("label \"").nth(1))
        .filter_map(|rest| rest.split('"').next())
        .map(str::to_owned)
        .collect()
}

/// Every `block drop` line in a rendered anchor, with its label.
fn block_labels(anchor: &str) -> Vec<String> {
    anchor
        .lines()
        .filter(|line| line.trim_start().starts_with("block drop "))
        .filter_map(|line| line.split("label \"").nth(1))
        .filter_map(|rest| rest.split('"').next())
        .map(str::to_owned)
        .collect()
}

fn render(state: (Ruleset, Mode, bool, ExemptPredicate), generation: u64) -> String {
    let (ruleset, mode, lan, exempt) = state;
    pf::render(
        &mode.contract(generation, ruleset),
        ruleset,
        &config(lan, exempt),
    )
}

// ---------------------------------------------------------------------------
// IPv4 leaks
// ---------------------------------------------------------------------------

#[test]
fn ipv4_the_protected_scope_is_dropped_in_every_reachable_state() {
    // K1: protected traffic MUST NOT egress on any interface other than the
    // overlay while enforcement is armed. In `Blocked` that is every interface;
    // in `Protected` the overlay is the one exception, and both are fail-closed.
    for state in states() {
        let anchor = render(state, 1);
        assert!(
            anchor.contains(&format!(
                "block drop out quick inet from any to <{}> label \"{}\"",
                SCOPE_TABLE[0].0, DENY_LABEL[0].0
            )),
            "no v4 Tier-2 drop in state {state:?}\n{anchor}"
        );
    }
}

#[test]
fn ipv4_the_scope_table_is_never_empty_so_the_drop_covers_something() {
    // The R-6 shape: a "fail-closed" ruleset whose drop rule names an empty table
    // drops nothing, and reads back as armed. The baseline makes it
    // unrepresentable.
    for state in states() {
        let anchor = render(state, 1);
        let line = anchor
            .lines()
            .find(|l| l.starts_with(&format!("table <{}>", SCOPE_TABLE[0].0)))
            .unwrap_or_else(|| panic!("no v4 scope table in state {state:?}"));
        assert!(
            line.contains('{'),
            "the v4 scope table is empty in state {state:?}: {line}"
        );
    }
}

// ---------------------------------------------------------------------------
// IPv6 leaks
// ---------------------------------------------------------------------------

#[test]
fn ipv6_gets_exactly_what_ipv4_gets_in_every_reachable_state() {
    // K2: "enforcement MUST cover IPv4 and IPv6 identically and atomically. A
    // v4-only guard is a leak." KS-5 raises it further: one family without the
    // other is NON-CONFORMING, not degraded.
    for state in states() {
        let anchor = render(state, 1);
        assert!(
            anchor.contains(&format!(
                "block drop out quick inet6 from any to <{}> label \"{}\"",
                SCOPE_TABLE[1].0, DENY_LABEL[1].0
            )),
            "no v6 Tier-2 drop in state {state:?}\n{anchor}"
        );
        // Symmetry, counted rather than eyeballed.
        assert_eq!(
            anchor.matches(DENY_LABEL[0].0).count(),
            anchor.matches(DENY_LABEL[1].0).count(),
            "a v4 drop with no v6 counterpart in state {state:?}"
        );
        assert_eq!(
            anchor.matches(EXEMPT_LABEL[0].0).count(),
            anchor.matches(EXEMPT_LABEL[1].0).count(),
            "a v4 exemption with no v6 counterpart in state {state:?}"
        );
    }
}

#[test]
fn ipv6_appearing_after_the_tunnel_is_up_needs_no_rule_update() {
    // ADR-0010 §11.5 clause 2 and K9: Tier 2 is INTERFACE-scoped and
    // default-deny, so a v6 address or a whole new interface appearing after the
    // anchor is installed is already denied. The property that makes it true is
    // that the drop rule names NO interface — a rule scoped to the interfaces
    // that existed at render time would not cover a new one.
    for state in states() {
        let anchor = render(state, 1);
        for line in anchor.lines().filter(|l| l.starts_with("block drop out")) {
            if line.contains(SCOPE_TABLE[0].0) || line.contains(SCOPE_TABLE[1].0) {
                assert!(
                    !line.contains(" on "),
                    "the Tier-2 drop is interface-scoped in state {state:?}, so an \
                     interface that appears later would escape it: {line}"
                );
            }
        }
    }
}

#[test]
fn a_family_with_no_routes_still_gets_a_drop() {
    // The asymmetry R1 forbids, at its sharpest: a contract that names no v6
    // route must not produce an anchor that denies no v6 traffic.
    for ruleset in [Ruleset::Blocked, Ruleset::Protected] {
        let mut contract = testkit::contract_with(9, ruleset);
        contract.routes.v6.clear();
        let anchor = pf::render(&contract, ruleset, &testkit::enforcement());
        assert!(anchor.contains(&format!("label \"{}\"", DENY_LABEL[1].0)));
        assert!(
            anchor.contains("fd7c:9e5d:2a10::/48"),
            "the v6 baseline floor"
        );

        let mut contract = testkit::contract_with(9, ruleset);
        contract.routes.v4.clear();
        let anchor = pf::render(&contract, ruleset, &testkit::enforcement());
        assert!(anchor.contains(&format!("label \"{}\"", DENY_LABEL[0].0)));
        assert!(anchor.contains("100.64.0.0/10"), "the v4 baseline floor");
    }
}

// ---------------------------------------------------------------------------
// DNS leaks
// ---------------------------------------------------------------------------

#[test]
fn dns_is_contained_off_overlay_in_every_reachable_state() {
    // ADR-0011 §11.9's macOS containment row: "a `pf` anchor `twinvpn`, both
    // families, denying 53/853/known-DoH off-overlay". One dual-family rule, so
    // the containment cannot be present for v4 and missing for v6.
    for state in states() {
        let anchor = render(state, 1);
        assert!(
            anchor.contains(&format!(
                "block drop out quick on ! utun7 proto {{ tcp, udp }} from any to any \
                 port {{ 53, 853 }} label \"{DNS_DENY_LABEL}\""
            )),
            "no DNS containment in state {state:?}\n{anchor}"
        );
        assert!(
            anchor.contains(&format!("port 443 label \"{DNS_DENY_LABEL}\"")),
            "no DoH containment in state {state:?}"
        );
    }
}

#[test]
fn the_dns_containment_is_never_relaxed_by_local_network_access() {
    // KS-4 governs class 4, not class 6. A build that let "allow my LAN" also
    // allow LAN DNS would leak every query on a hostile network, and the two
    // settings are deliberately not connected.
    for lan in [true, false] {
        let anchor = pf::render(
            &testkit::contract(1),
            Ruleset::Protected,
            &config(lan, ExemptPredicate::ProviderUidAndSocketSet { uid: 501 }),
        );
        assert!(anchor.contains(&format!("port {{ 53, 853 }} label \"{DNS_DENY_LABEL}\"")));
    }
}

// ---------------------------------------------------------------------------
// The kill switch itself
// ---------------------------------------------------------------------------

#[test]
fn ks18_blocked_permits_no_protected_egress_on_any_interface_including_the_overlay() {
    // In `Blocked` the path is not validated and the ProtectionAssertion has not
    // been made, so the overlay is not an exception either.
    for state in states().into_iter().filter(|s| s.0 == Ruleset::Blocked) {
        let anchor = render(state, 1);
        assert!(
            !anchor.contains("twinvpn.protected.v4"),
            "BLOCKED permits protected v4 egress in state {state:?}"
        );
        assert!(
            !anchor.contains("twinvpn.protected.v6"),
            "BLOCKED permits protected v6 egress in state {state:?}"
        );
    }
}

#[test]
fn protected_permits_the_scope_only_on_the_overlay_and_in_both_families() {
    for state in states().into_iter().filter(|s| s.0 == Ruleset::Protected) {
        let anchor = render(state, 1);
        for (label, table) in [
            ("twinvpn.protected.v4", SCOPE_TABLE[0].0),
            ("twinvpn.protected.v6", SCOPE_TABLE[1].0),
        ] {
            let line = anchor
                .lines()
                .find(|l| l.contains(label))
                .unwrap_or_else(|| panic!("no {label} rule in state {state:?}"));
            assert!(line.starts_with("pass out quick on utun7 "), "{line}");
            assert!(line.contains(&format!("<{table}>")), "{line}");
        }
    }
}

#[test]
fn the_only_permitted_classes_are_the_ones_adr_0012_11_2_authorises() {
    // KS-6: "every permitted exception MUST be enumerated, narrow, matched by a
    // stable predicate". The set equality is checked in BOTH directions, so a
    // rule nobody authorised cannot be added silently and an authorised class
    // cannot go missing.
    let authorised: BTreeSet<&str> = [
        "twinvpn.loopback",       // class 8
        "twinvpn.exempt.v4",      // class 7
        "twinvpn.exempt.v6",      // class 7
        "twinvpn.underlay.dhcp4", // class 5
        "twinvpn.underlay.dhcp6", // class 5
        "twinvpn.underlay.nd",    // class 5
        "twinvpn.linklocal.v4",   // class 9
        "twinvpn.linklocal.v6",   // class 9
        "twinvpn.lan.v4",         // class 4
        "twinvpn.lan.v6",         // class 4
        "twinvpn.mcast.v4",       // class 10
        "twinvpn.mcast.v6",       // class 10
        "twinvpn.protected.v4",   // Tier 2, PROTECTED only
        "twinvpn.protected.v6",   // Tier 2, PROTECTED only
    ]
    .into_iter()
    .collect();

    for state in states() {
        let (ruleset, _, lan, _) = state;
        let anchor = render(state, 1);
        let seen: BTreeSet<String> = pass_labels(&anchor).into_iter().collect();
        for label in &seen {
            assert!(
                authorised.contains(label.as_str()),
                "the anchor permits {label}, which ADR-0012 §11.2 does not \
                 authorise, in state {state:?}"
            );
        }
        // And the classes that must always be there.
        for required in [
            "twinvpn.loopback",
            "twinvpn.exempt.v4",
            "twinvpn.exempt.v6",
            "twinvpn.underlay.dhcp4",
            "twinvpn.underlay.dhcp6",
            "twinvpn.underlay.nd",
            "twinvpn.linklocal.v4",
            "twinvpn.linklocal.v6",
        ] {
            assert!(seen.contains(required), "{required} missing in {state:?}");
        }
        assert_eq!(
            seen.contains("twinvpn.lan.v4"),
            lan,
            "class 4 must follow local_network_access exactly, in {state:?}"
        );
        assert_eq!(
            seen.contains("twinvpn.protected.v4"),
            ruleset == Ruleset::Protected
        );

        // Nothing is blocked that is not the scope or DNS.
        let blocked: BTreeSet<String> = block_labels(&anchor).into_iter().collect();
        for label in &blocked {
            assert!(
                matches!(
                    label.as_str(),
                    "twinvpn.deny.v4" | "twinvpn.deny.v6" | "twinvpn.deny.dns"
                ),
                "unexpected block rule {label} in {state:?}"
            );
        }
    }
}

#[test]
fn ks2_the_exemption_cannot_match_a_forwarded_packet() {
    // "Forwarded traffic is protected by the same Tier-2 rule and is NEVER
    // eligible for any exemption in §11.2." pf resolves `user` from the packet's
    // local socket, and a forwarded packet has none — so the exemption is
    // structurally unreachable for one. The property that must hold is that
    // EVERY class-7 rule is user-keyed; a single one without it would be the hole.
    for state in states() {
        let anchor = render(state, 1);
        for line in anchor
            .lines()
            .filter(|l| l.contains("twinvpn.exempt.v4") || l.contains("twinvpn.exempt.v6"))
        {
            assert!(
                line.contains("user = 501"),
                "a class-7 rule with no user predicate would be reachable by a \
                 forwarded packet, in state {state:?}: {line}"
            );
        }
    }
}

#[test]
fn ks9_the_missing_half_of_the_predicate_is_reported_and_not_implied() {
    // ADR-0012 KS-9(1) on macOS is "the tunnel provider's owning uid PLUS the
    // provider's socket set". pf has no socket-set selector, so one binding
    // satisfies both halves and the other satisfies one. The anchor text is the
    // same; the difference is a fact the shell reports.
    let complete = config(true, ExemptPredicate::ProviderUidAndSocketSet { uid: 501 });
    let weaker = config(true, ExemptPredicate::UidOnly { uid: 501 });
    assert!(complete.ks9_complete());
    assert!(!weaker.ks9_complete());
    assert_eq!(
        pf::render(&testkit::contract(1), Ruleset::Protected, &complete),
        pf::render(&testkit::contract(1), Ruleset::Protected, &weaker),
        "the anchor cannot express the difference, which is exactly why \
         `ks9_complete()` has to"
    );
}

// ---------------------------------------------------------------------------
// The read-back (W-24)
// ---------------------------------------------------------------------------

#[test]
fn what_was_rendered_is_what_reads_back_in_every_reachable_state() {
    // ADR-0015 §11.6 rule 1: the assertion is a QUERY. This drives the renderer
    // and the `pfctl -s Tables` parser end to end, so a marker table that were
    // renamed on one side and not the other would fail here rather than on a Mac.
    for (index, state) in states().into_iter().enumerate() {
        let generation = index as u64 + 1;
        let anchor = render(state, generation);
        let installed = pfread::parse_tables(&table_names_in(&anchor))
            .unwrap_or_else(|| panic!("the anchor does not read back in state {state:?}"));
        assert_eq!(installed.ruleset, state.0, "{state:?}");
        assert_eq!(installed.generation, Some(ContractGeneration(generation)));
        assert!(
            installed.covers_a_scope(),
            "the read-back says the drop covers nothing in state {state:?}"
        );
        assert!(pfread::Assertion {
            status: pfread::PfStatus::Enabled,
            installed: Some(installed),
        }
        .supports(state.0));
    }
}

#[test]
fn a_disabled_packet_filter_supports_no_assertion_whatever_the_anchor_says() {
    // The failure this catches is real and easy: an anchor loads successfully into
    // a pf that is switched off, `pfctl -a twinvpn -s Tables` lists our tables,
    // and a read-back that asked only that question would report ARMED.
    let anchor = pf::render(
        &testkit::contract(1),
        Ruleset::Protected,
        &testkit::enforcement(),
    );
    let installed = pfread::parse_tables(&table_names_in(&anchor));
    for status in [pfread::PfStatus::Disabled, pfread::PfStatus::Unknown] {
        assert!(!pfread::Assertion { status, installed }.supports(Ruleset::Protected));
    }
}

#[test]
fn the_canary_reads_a_per_family_counter_and_a_missing_one_is_zero() {
    // ADR-0012 §11.9: "a canary that does not increment is
    // POLICY.LEAK.EGRESS_OBSERVED at CRITICAL". The adapter's job is to report
    // the number; the code is the core's to emit.
    let labels = pfread::parse_labels("twinvpn.deny.v4 3 3 192\n");
    assert_eq!(pfread::packets_on(&labels, DENY_LABEL[0].0), 3);
    assert_eq!(
        pfread::packets_on(&labels, DENY_LABEL[1].0),
        0,
        "an absent v6 deny label and a v6 deny label at zero are the same \
         negative answer, and both are a v6 leak when the canary fired"
    );
}

// ---------------------------------------------------------------------------
// The swap (KS-17 / KS-23)
// ---------------------------------------------------------------------------

#[test]
fn the_two_postures_differ_only_in_whether_the_overlay_is_an_exception() {
    // KS-17's "atomic swap between the two" is only meaningful if the two are
    // otherwise identical: a swap that also changed the scope would be a scope
    // change disguised as a posture change.
    for mode in Mode::ALL {
        let blocked = pf::render(
            &mode.contract(7, Ruleset::Blocked),
            Ruleset::Blocked,
            &testkit::enforcement(),
        );
        let protected = pf::render(
            &mode.contract(7, Ruleset::Protected),
            Ruleset::Protected,
            &testkit::enforcement(),
        );
        let only_in_protected: Vec<&str> = protected
            .lines()
            .filter(|line| !blocked.contains(*line))
            .collect();
        assert_eq!(
            only_in_protected.len(),
            3,
            "the swap changed more than the posture marker and the two overlay \
             passes, in {mode:?}: {only_in_protected:?}"
        );
        assert!(only_in_protected
            .iter()
            .any(|l| l.contains("tv_posture_protected")));
        assert!(only_in_protected
            .iter()
            .any(|l| l.contains("twinvpn.protected.v4")));
        assert!(only_in_protected
            .iter()
            .any(|l| l.contains("twinvpn.protected.v6")));
    }
}

#[test]
fn rendering_is_deterministic_so_a_reconciler_sees_no_phantom_drift() {
    for state in states() {
        assert_eq!(render(state, 5), render(state, 5), "{state:?}");
    }
}

#[test]
fn a_contract_with_no_routes_at_all_still_denies_both_families() {
    // The most dangerous input this function can be handed.
    for ruleset in [Ruleset::Blocked, Ruleset::Protected] {
        let contract = NetworkContract {
            generation: ContractGeneration(1),
            addresses: PerFamily::new(Vec::new(), Vec::new()),
            routes: PerFamily::new(Vec::new(), Vec::new()),
            dns: DnsConfig {
                resolvers: PerFamily::new(Vec::new(), Vec::new()),
                search_domains: Vec::new(),
                split_domains: Vec::new(),
                is_default_resolver: false,
            },
            ruleset,
            mtu: 1280,
            tunnel_remote_address: None,
        };
        let anchor = pf::render(&contract, ruleset, &testkit::enforcement());
        let installed = pfread::parse_tables(&table_names_in(&anchor)).expect("reads back");
        assert!(
            installed.covers_a_scope(),
            "an empty contract produced a ruleset that drops nothing"
        );
        assert_eq!(installed.scope, PerFamily::new(1, 1));
    }
}

/// **X-9.** A subscriber behind CGNAT holds an on-link address inside the
/// very RFC 6598 `/10` the Tier-1 baseline protects.
///
/// Denying it does not protect anything — the overlay's own traffic leaves
/// by the overlay interface either way — it only severs the underlay, which
/// is the same argument ADR-0010 §11.5 clause 5 makes for DHCP. So it is
/// passed off-overlay regardless of KS-4, and KS-4 is not widened.
#[test]
fn x9_a_cgnat_underlay_prefix_is_passed_even_when_ks4_denies_the_lan() {
    use twinvpn_types::{IpAddr, IpPrefix, V4Addr};

    let cgnat =
        IpPrefix::new(IpAddr::V4(V4Addr::from_octets([100, 96, 0, 0])), 12).expect("prefix");
    let lan = IpPrefix::new(IpAddr::V4(V4Addr::from_octets([192, 168, 1, 0])), 24).expect("prefix");

    let denied = EnforcementConfig {
        local_network_access: false,
        on_link_prefixes: vec![cgnat, lan],
        ..testkit::enforcement()
    };
    let anchor = pf::render(
        &testkit::full_tunnel_contract(1, Ruleset::Blocked),
        Ruleset::Blocked,
        &denied,
    );

    assert!(
        anchor.contains("twinvpn.underlay.cgnat"),
        "the underlay path is passed off-overlay regardless of KS-4"
    );
    assert!(
        anchor.contains("100.96.0.0/12"),
        "and it names the host's own prefix"
    );
    // KS-4 is NOT widened: the ordinary LAN is still denied. Checked on the
    // `pass` lines rather than on the whole anchor, because the contract's own
    // scope may legitimately NAME that prefix in a `block drop`.
    assert!(
        !anchor
            .lines()
            .filter(|l| l.trim_start().starts_with("pass "))
            .any(|l| l.contains("192.168.1.0/24")),
        "KS-4 still costs the user their printer when they ask it to"
    );
    // Every X-9 RULE is off-overlay: a peer at 100.64.0.7 is still reached
    // through the tunnel and nowhere else. `table <...> persist { … }` lines
    // are declarations, not rules, and carry no interface at all.
    for line in anchor
        .lines()
        .map(str::trim_start)
        .filter(|l| l.starts_with("pass ") || l.starts_with("block "))
        .filter(|l| l.contains("100.96.0.0/12"))
    {
        assert!(line.contains("on ! "), "off-overlay only: {line}");
    }
}
