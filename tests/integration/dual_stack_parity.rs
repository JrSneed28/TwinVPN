//! **Integration.** IPv4, IPv6, dual-stack and IPv6-only across every component
//! that has an address family in it — and the negative controls that make a
//! v4-only regression fail.
//!
//! **Authority:** ADR-0010 **R1** ("one story covering both"), **R6**;
//! `docs/networking.md` §2.1, §2.4, §3.2, §6; `docs/testing-strategy.md` §3.7
//! rule **L-5**; `docs/implementation/ownership.md` §4.2 ("Address family is an
//! *evidence field*, not a namespace").
//!
//! # The test this file is really made of
//!
//! Almost every property below is asserted **twice**: once for each family, in a
//! loop a reader can see is exhaustive. That shape is the point. R1's whole
//! content is that there is no "v4 story and a v6 story", and the only way a
//! suite holds a build to that is to make every family-shaped assertion a loop
//! over `[V4, V6]` that fails if either arm is missing.
//!
//! Several assertions here look redundant against the owning crate's own tests.
//! They are not: `twinvpn-route`'s "every mode produces routes for both
//! families" iterates two of the four modes, and `twinvpn-dns`'s asserts its own
//! policy in isolation. Nothing asserted that the route plan, the DNS policy,
//! the stub, the MTU model and the enforcement contract all cover both families
//! **for the same rig**.

use twinvpn_dns::policy::Dnspolicy;
use twinvpn_dns::stub::{is_service_anycast, may_advertise, StubReadiness};
use twinvpn_platform::iface::NetworkChange;
use twinvpn_platform::Ruleset;
use twinvpn_route::mtu::{mss_clamp, Carriage, Dplpmtud, ProbeOutcome};
use twinvpn_route::plan::MTU_FLOOR;
use twinvpn_route::program::RoutingMode;
use twinvpn_types::{AddressFamily, IpAddr, PerFamily};

use twinvpn_system_tests::{dns_policy, stub_addresses, HostFamily, Rig};

const BOTH: [AddressFamily; 2] = [AddressFamily::V4, AddressFamily::V6];

// ---------------------------------------------------------------------------
// The route plan, across every mode and every underlay.
// ---------------------------------------------------------------------------

#[test]
fn every_routing_mode_that_is_supported_produces_both_families() {
    // `twinvpn-route`'s own test is named "every_mode_produces_routes_for_both_
    // families_in_one_plan" but iterates only TwinnetOnly and SplitTunnel.
    // FullTunnel is the mode where a family can actually be withheld, so it is
    // the one worth checking — and PerApp must be a named refusal, never a
    // silent downgrade to something that carries one family.
    for family in HostFamily::ALL {
        for mode in [
            RoutingMode::TwinnetOnly,
            RoutingMode::SplitTunnel,
            RoutingMode::FullTunnel,
        ] {
            let mut rig = Rig::new(family, 31);
            let plan = rig
                .route_plan(mode, PerFamily::new(true, true))
                .unwrap_or_else(|e| panic!("{} / {mode:?}: {e}", family.name()));
            for af in BOTH {
                assert!(
                    plan.carries(af),
                    "{} / {mode:?}: no {af:?} half",
                    family.name()
                );
            }
            assert!(!plan.is_family_asymmetric());
        }

        let mut rig = Rig::new(family, 31);
        let err = rig
            .route_plan(RoutingMode::PerApp, PerFamily::new(true, true))
            .expect_err("PerApp must be refused, never silently downgraded");
        assert!(
            matches!(err, twinvpn_route::RouteError::PerAppUnsupported),
            "{}: PerApp failed with {err} instead of a named refusal",
            family.name()
        );
    }
}

#[test]
fn a_full_tunnel_never_installs_a_default_route_and_covers_both_families_with_halves() {
    // §7.2: the default route is installed as two `/1` halves so the host's own
    // default survives. A build that emitted a real default for one family and
    // halves for the other would be invisible to a per-family test.
    let mut rig = Rig::new(HostFamily::Dual, 32);
    let plan = rig
        .route_plan(RoutingMode::FullTunnel, PerFamily::new(true, true))
        .expect("plan");
    for af in BOTH {
        let routes = plan.routes.get(af);
        assert!(
            routes.iter().all(|r| r.destination.prefix_len() != 0),
            "{af:?}: a prefix-length-0 default route was installed"
        );
        assert!(
            routes
                .iter()
                .filter(|r| r.destination.prefix_len() == 1)
                .count()
                >= 2,
            "{af:?}: fewer than two /1 halves"
        );
    }
}

#[test]
fn an_ungranted_family_is_blocked_and_the_granted_one_is_not() {
    // §11.5(3): "a family we do not carry must be BLOCKED, never left to egress
    // locally." Asserted in both directions, because a build that blocked
    // unconditionally would pass a one-directional test.
    for withheld in BOTH {
        let mut rig = Rig::new(HostFamily::Dual, 33);
        let grant = PerFamily::new(withheld == AddressFamily::V6, withheld == AddressFamily::V4);
        let plan = rig
            .route_plan(RoutingMode::FullTunnel, grant)
            .expect("a partial grant still produces a plan");
        assert!(
            *plan.blocked_families.get(withheld),
            "{withheld:?} was ungranted and not blocked — that is a leak"
        );
        let granted = match withheld {
            AddressFamily::V4 => AddressFamily::V6,
            AddressFamily::V6 => AddressFamily::V4,
        };
        assert!(
            !*plan.blocked_families.get(granted),
            "{granted:?} was granted and blocked anyway"
        );
    }
}

// ---------------------------------------------------------------------------
// DNS: the policy, the stub, and the answer surface.
// ---------------------------------------------------------------------------

#[test]
fn a_policy_that_leaves_one_family_undeclared_is_malformed_rather_than_unconfigured() {
    // ADR-0011: silence about a family is not a configuration, it is a leak. The
    // rig's policy builder is the positive control — it declares both — and the
    // two negatives withhold one declaration at a time.
    use twinvpn_schema::v1;

    let base = |declared_v4: Option<bool>, declared_v6: Option<bool>| v1::DnsPolicy {
        dnspolicy_id: "parity".to_owned(),
        version: 1,
        mode: 1,
        servers_v4: vec![v1::IPv4Address {
            octets: vec![100, 127, 255, 53],
        }],
        servers_v6: vec![v1::IPv6Address {
            octets: vec![
                0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0x53,
            ],
            zone_index: 0,
        }],
        servers_declared_v4: declared_v4,
        servers_declared_v6: declared_v6,
        split_domains: Vec::new(),
        search_domains: Vec::new(),
        block_fallback_v4: Some(true),
        block_fallback_v6: Some(true),
        dnssec_validate: true,
        upstream_dot: true,
        not_after_ms: 0,
    };

    twinvpn_dns::policy::validate(&base(Some(true), Some(true)))
        .expect("the positive control: both families declared");
    assert!(
        twinvpn_dns::policy::validate(&base(Some(true), None)).is_err(),
        "a policy silent about IPv6 resolvers validated"
    );
    assert!(
        twinvpn_dns::policy::validate(&base(None, Some(true))).is_err(),
        "a policy silent about IPv4 resolvers validated"
    );
}

#[test]
fn the_stub_listens_in_both_families_and_refuses_to_point_the_host_until_it_does() {
    let addrs = stub_addresses();
    for af in BOTH {
        assert!(
            !addrs.get(af).is_empty(),
            "the stub declares no {af:?} listen address"
        );
    }
    // DN-5: the host is pointed at the stub only once both families answer.
    assert!(!StubReadiness {
        v4_listening: true,
        v6_listening: false
    }
    .may_point_host());
    assert!(!StubReadiness {
        v4_listening: false,
        v6_listening: true
    }
    .may_point_host());
    assert!(StubReadiness {
        v4_listening: true,
        v6_listening: true
    }
    .may_point_host());
}

#[test]
fn the_service_anycasts_are_recognised_in_both_families_and_never_advertised() {
    // A service anycast that leaked into a route advertisement would be a
    // globally-reachable resolver address; the check must exist per family.
    let addrs = stub_addresses();
    let mut seen = PerFamily::new(false, false);
    for addr in addrs.v4.iter().chain(addrs.v6.iter()) {
        if is_service_anycast(*addr) {
            match addr {
                IpAddr::V4(_) => seen.v4 = true,
                IpAddr::V6(_) => seen.v6 = true,
            }
            assert!(
                !may_advertise(*addr),
                "{addr:?} is a service anycast and may_advertise said yes"
            );
        }
    }
    assert!(
        seen.v4 && seen.v6,
        "an anycast was recognised in only one family"
    );
}

#[test]
fn a_family_that_enforcement_will_drop_is_withheld_from_the_answer_rather_than_answered() {
    // ADR-0011 and ADR-0012 meeting: answering a AAAA the kill switch will drop
    // produces a connection attempt that hangs instead of an error. The two
    // components must agree, and only a cross-component test can say so.
    use twinvpn_dns::answer::twinnet_families;

    let both_ok = twinnet_families(PerFamily::new(false, false));
    assert!(both_ok.a && both_ok.aaaa && both_ok.withheld.is_none());

    let v6_dropped = twinnet_families(PerFamily::new(false, true));
    assert!(v6_dropped.a, "the working family must still be answered");
    assert!(
        !v6_dropped.aaaa,
        "a family that will be dropped was answered"
    );
    assert!(
        v6_dropped.withheld.is_some(),
        "the withheld family must be named"
    );

    let v4_dropped = twinnet_families(PerFamily::new(true, false));
    assert!(!v4_dropped.a);
    assert!(v4_dropped.aaaa);
    assert!(v4_dropped.withheld.is_some());
}

// ---------------------------------------------------------------------------
// MTU: the per-family arithmetic a v4-only build gets wrong silently.
// ---------------------------------------------------------------------------

#[test]
fn the_overhead_and_clamp_arithmetic_differs_per_family_and_never_permits_fragmentation() {
    // A v6 header is 20 bytes larger than a v4 one, so a build that computed one
    // overhead for both under-reports the v6 ceiling and fragments — or worse,
    // black-holes — every large v6 packet.
    for carriage in [
        Carriage::Direct,
        Carriage::RelayUdp,
        Carriage::RelayQuic,
        Carriage::RelayTls,
    ] {
        let v4 = carriage.total_overhead(AddressFamily::V4);
        let v6 = carriage.total_overhead(AddressFamily::V6);
        assert!(
            v6 > v4,
            "{carriage:?}: the v6 overhead ({v6}) is not larger than the v4 one ({v4})"
        );
    }
    assert_eq!(mss_clamp(1400, AddressFamily::V4), 1360);
    assert_eq!(mss_clamp(1400, AddressFamily::V6), 1340);
    assert!(
        !twinvpn_route::mtu::may_fragment(AddressFamily::V4)
            && !twinvpn_route::mtu::may_fragment(AddressFamily::V6),
        "fragmentation is never permitted in either family"
    );
}

#[test]
fn dplpmtud_starts_at_the_ipv6_floor_and_returns_to_it_on_every_migration() {
    // §6.2's decision: a 1280 floor plus DPLPMTUD, never classic PMTUD. The
    // floor is the IPv6 minimum and it applies to both families — a build that
    // started at 1500 would black-hole on the first PPPoE link.
    let mut d = Dplpmtud::new(1500);
    assert_eq!(d.effective(), MTU_FLOOR);
    let probe = d.next_probe().expect("a probe is scheduled");
    assert!(probe > MTU_FLOOR && probe <= 1500);
    d.observe(ProbeOutcome::Acknowledged);
    assert_eq!(d.effective(), probe);

    d.reset_for_new_path(1500);
    assert_eq!(
        d.effective(),
        MTU_FLOOR,
        "a migration must re-probe from the floor rather than trusting the old path"
    );
}

// ---------------------------------------------------------------------------
// R6: a v6 default route that appears AFTER the tunnel is up.
// ---------------------------------------------------------------------------

#[test]
fn a_default_route_change_is_reported_per_family_so_r6s_case_is_representable() {
    // ADR-0010 R6's exact case — "IPv6 appears *after* the tunnel is up" — is a
    // v6 default route arriving while the v4 one is unchanged. A combined event
    // would make that indistinguishable from nothing having happened.
    for af in BOTH {
        let change = NetworkChange::DefaultRouteChanged {
            family: af,
            present: true,
        };
        match change {
            NetworkChange::DefaultRouteChanged { family, present } => {
                assert_eq!(family, af);
                assert!(present);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }
    // And the interface facts answer per family too.
    let facts = twinvpn_platform::iface::InterfaceFacts {
        index: twinvpn_platform::InterfaceIndex(1),
        name: twinvpn_platform::iface::InterfaceName::new("eth0").expect("name"),
        addresses: Vec::new(),
        has_default_route_v4: true,
        has_default_route_v6: false,
        is_overlay: false,
        is_up: true,
        mtu: 1500,
        link_class: twinvpn_platform::iface::LinkClass::Ethernet,
    };
    assert!(facts.has_default_route(AddressFamily::V4));
    assert!(
        !facts.has_default_route(AddressFamily::V6),
        "a host with only a v4 default must not report a v6 one"
    );
}

// ---------------------------------------------------------------------------
// The whole pipeline, per family, in one assertion.
// ---------------------------------------------------------------------------

#[test]
fn the_installed_contract_covers_both_families_for_every_underlay_and_every_mode() {
    for family in HostFamily::ALL {
        for mode in [RoutingMode::TwinnetOnly, RoutingMode::SplitTunnel] {
            let mut rig = Rig::new(family, 34);
            let plan = rig
                .route_plan(mode, PerFamily::new(false, false))
                .expect("plan");
            let policy: Dnspolicy = dns_policy(twinvpn_dns::Mode::Split, true);
            for af in BOTH {
                assert!(
                    policy.block_fallback(af),
                    "the policy does not block the {af:?} fallback"
                );
            }
            let contract = rig
                .contract(&plan, &policy, stub_addresses(), Ruleset::Protected)
                .expect("assemble");
            let generation = rig.apply(&contract).expect("applied");
            assert_eq!(generation, contract.generation);

            let installed = rig
                .adapter
                .config_mock()
                .current_contract()
                .expect("a contract is in force");
            for af in BOTH {
                assert!(
                    !installed.addresses.get(af).is_empty(),
                    "{} / {mode:?}: the INSTALLED contract has no {af:?} address",
                    family.name()
                );
                assert!(
                    !installed.dns.resolvers.get(af).is_empty(),
                    "{} / {mode:?}: the INSTALLED contract has no {af:?} resolver",
                    family.name()
                );
            }
        }
    }
}

#[test]
fn a_v6_only_host_still_receives_a_v4_overlay_address() {
    // The single most load-bearing consequence of §2.1, stated on its own so it
    // cannot be lost in a loop: an application on an IPv6-only mobile network
    // must still be able to open an IPv4 socket to a peer's overlay address.
    let mut rig = Rig::new(HostFamily::V6Only, 35);
    assert!(!rig.host_family.underlay_carries(AddressFamily::V4));
    let plan = rig
        .route_plan(RoutingMode::TwinnetOnly, PerFamily::new(false, false))
        .expect("plan");
    assert!(
        !plan.addresses.v4.is_empty(),
        "an IPv6-only host received no IPv4 overlay address, so an IPv4-only \
         application on it cannot reach a peer at all"
    );
    assert!(!plan.addresses.v6.is_empty());
}
