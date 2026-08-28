//! ADR-0010 R1, R6 and §11.3, asserted: there is no route plan with one family
//! in it.

use twinvpn_platform::{ContractGeneration, InterfaceIndex};
use twinvpn_route::conflict::{Candidate, Source};
use twinvpn_route::mtu::{mss_clamp, Carriage, Dplpmtud, ProbeOutcome};
use twinvpn_route::plan::{self, V6InterfaceIdSource};
use twinvpn_route::program::{compute, default_route_halves, PlanInputs, RoutingMode};
use twinvpn_route::{RouteError, MTU_FLOOR};
use twinvpn_types::{AddressFamily, DeviceId, IpAddr, IpPrefix, PerFamily, V4Addr, V6Addr};

struct FixedIid([u8; 8]);
impl V6InterfaceIdSource for FixedIid {
    fn interface_id(&self) -> [u8; 8] {
        self.0
    }
}

fn twinnet_prefix64() -> IpPrefix {
    let mut o = [0u8; 16];
    o[..6].copy_from_slice(&[0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10]);
    o[6] = 0x00;
    o[7] = 0x01;
    IpPrefix::new(IpAddr::V6(V6Addr::new(o, None).unwrap()), 64).unwrap()
}

fn overlay() -> twinvpn_types::OverlayAddresses {
    plan::overlay_addresses(
        V4Addr::from_octets([100, 100, 0, 7]),
        twinnet_prefix64(),
        &FixedIid([0xff, 1, 2, 3, 4, 5, 6, 7]),
    )
    .unwrap()
}

fn inputs(mode: RoutingMode) -> PlanInputs {
    PlanInputs {
        mode,
        overlay: overlay(),
        twinnet_prefixes: PerFamily::new(
            vec![IpPrefix::new(IpAddr::V4(V4Addr::from_octets([100, 100, 0, 0])), 22).unwrap()],
            vec![twinnet_prefix64()],
        ),
        accepted: Vec::new(),
        on_link: Vec::new(),
        excluded: Vec::new(),
        interface: InterfaceIndex(3),
        selected_exit_node: None,
        mtu: 1400,
        exit_grant: PerFamily::new(false, false),
    }
}

#[test]
fn r1_every_device_has_both_overlay_addresses_whatever_the_underlay() {
    let a = overlay();
    // Both fields are non-optional in `OverlayAddresses`, so the assertion is
    // about the *values* being real, not about the halves existing.
    assert!(plan::check_device_v4(a.v4).is_ok());
    // RFC 7136: the U/L bit is cleared.
    assert_eq!(a.v6.octets()[8] & 0b0000_0010, 0);
    assert!(a.v6.is_product_ula());
}

#[test]
fn ap_2_refuses_an_address_inside_the_reserved_service_ranges() {
    // 100.127.255.5 is inside ADR-0011 DN-3's reserved /24.
    assert_eq!(
        plan::check_device_v4(V4Addr::from_octets([100, 127, 255, 5])),
        Err(plan::PlanError::ReservedServiceRange)
    );
    // Outside 100.64.0.0/10 entirely.
    assert_eq!(
        plan::check_device_v4(V4Addr::from_octets([10, 0, 0, 1])),
        Err(plan::PlanError::OutsideTwinnetSpace)
    );
    // The reserved v6 /64.
    let mut o = [0u8; 16];
    o[..8].copy_from_slice(&[0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0xff, 0xff]);
    let reserved = IpPrefix::new(IpAddr::V6(V6Addr::new(o, None).unwrap()), 64).unwrap();
    assert_eq!(
        plan::device_v6(reserved, &FixedIid([0; 8])),
        Err(plan::PlanError::ReservedServiceRange)
    );
}

#[test]
fn ap_1_the_product_ula_is_pinned_and_a_foreign_prefix_is_refused() {
    let ula = plan::product_ula().unwrap();
    assert_eq!(ula.prefix_len(), 48);
    let mut o = [0u8; 16];
    o[..6].copy_from_slice(&[0xfd, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let foreign = IpPrefix::new(IpAddr::V6(V6Addr::new(o, None).unwrap()), 64).unwrap();
    assert_eq!(
        plan::device_v6(foreign, &FixedIid([0; 8])),
        Err(plan::PlanError::NotInsideProductUla)
    );
}

#[test]
fn every_mode_produces_routes_for_both_families_in_one_plan() {
    for mode in [RoutingMode::TwinnetOnly, RoutingMode::SplitTunnel] {
        let plan = compute(&inputs(mode), ContractGeneration(1)).unwrap();
        assert!(plan.carries(AddressFamily::V4), "{mode:?} lost IPv4");
        assert!(plan.carries(AddressFamily::V6), "{mode:?} lost IPv6");
        assert!(
            !plan.is_family_asymmetric(),
            "§11.3: a one-family install is non-conforming"
        );
        // R1: both addresses are on the interface regardless of mode.
        assert_eq!(plan.addresses.get(AddressFamily::V4).len(), 1);
        assert_eq!(plan.addresses.get(AddressFamily::V6).len(), 1);
    }
}

#[test]
fn full_tunnel_installs_two_slash_one_routes_per_family_and_never_a_default() {
    let exit = DeviceId::from_array([9u8; 32]);
    let mut i = inputs(RoutingMode::FullTunnel);
    i.selected_exit_node = Some(exit);
    i.exit_grant = PerFamily::new(true, true);
    let plan = compute(&i, ContractGeneration(2)).unwrap();

    for family in [AddressFamily::V4, AddressFamily::V6] {
        let halves = default_route_halves(family).unwrap();
        for h in halves {
            assert!(
                plan.routes.get(family).iter().any(|r| r.destination == h),
                "{family:?} is missing a /1 half"
            );
        }
        // networking.md §7.2: the host's default route is never installed over.
        assert!(
            plan.routes
                .get(family)
                .iter()
                .all(|r| r.destination.prefix_len() != 0),
            "a 0-length default route would replace the host's own"
        );
    }
}

#[test]
fn a_one_family_exit_grant_blocks_the_other_family_rather_than_leaking_it() {
    // protocol.md §13.3: "A v4-only exit grant with v6 leaking to the local ISP
    // is the exact IPv6 leak this product must never ship."
    let exit = DeviceId::from_array([9u8; 32]);
    let mut i = inputs(RoutingMode::FullTunnel);
    i.selected_exit_node = Some(exit);
    i.exit_grant = PerFamily::new(true, false);
    let plan = compute(&i, ContractGeneration(3)).unwrap();
    assert!(
        *plan.blocked_families.get(AddressFamily::V6),
        "the ungranted family MUST be blocked, not left to egress locally"
    );
    assert!(!plan.is_family_asymmetric());

    // D-3's regression: blocking without NAMING is a user told the wrong story
    // about why their default route is gone. KS-6 requires both.
    assert_eq!(
        plan.single_family_grant,
        Some(AddressFamily::V6),
        "the uncovered family must be named on the plan"
    );
    let d = plan
        .single_family_diagnostic()
        .expect("an asymmetric grant carries a diagnostic");
    assert_eq!(d.code().as_str(), "ROUTE.DEFAULT_SINGLE_FAMILY");
    assert!(
        d.code().declares_evidence("family"),
        "the family is declared evidence, not prose"
    );
    assert!(d.evidence().get("family").is_some());
}

#[test]
fn an_asymmetric_grant_is_named_in_both_directions_and_a_symmetric_one_is_silent() {
    let exit = DeviceId::from_array([9u8; 32]);

    for (granted, uncovered) in [
        (PerFamily::new(true, false), AddressFamily::V6),
        (PerFamily::new(false, true), AddressFamily::V4),
    ] {
        let mut i = inputs(RoutingMode::FullTunnel);
        i.selected_exit_node = Some(exit);
        i.exit_grant = granted;
        let plan = compute(&i, ContractGeneration(11)).expect("the plan is still produced");
        assert_eq!(
            plan.single_family_grant,
            Some(uncovered),
            "the UNCOVERED family is the one named, not the granted one"
        );
        assert!(*plan.blocked_families.get(uncovered));
        assert!(plan.single_family_diagnostic().is_some());
    }

    // A symmetric grant says nothing, because there is nothing to say.
    let mut ok = inputs(RoutingMode::FullTunnel);
    ok.selected_exit_node = Some(exit);
    ok.exit_grant = PerFamily::new(true, true);
    let plan = compute(&ok, ContractGeneration(12)).unwrap();
    assert_eq!(plan.single_family_grant, None);
    assert!(plan.single_family_diagnostic().is_none());
}

#[test]
fn p6_refuses_a_default_route_from_anything_but_the_selected_exit_node() {
    let gateway = DeviceId::from_array([4u8; 32]);
    let mut i = inputs(RoutingMode::SplitTunnel);
    i.accepted = vec![Candidate {
        prefix: IpPrefix::new(IpAddr::V4(V4Addr::from_octets([0, 0, 0, 0])), 0).unwrap(),
        source: Source::LanGateway(gateway),
        measured_score: 0,
        metric: 0,
    }];
    let err = compute(&i, ContractGeneration(4)).unwrap_err();
    assert!(matches!(err, RouteError::ScopeViolation { .. }));
    assert_eq!(
        err.reason_code().as_str(),
        "ROUTE.SCOPE_VIOLATION",
        "the refusal is a registered code, never a raw error"
    );
}

#[test]
fn per_app_routing_is_a_named_refusal_and_never_a_silent_downgrade() {
    let err = compute(&inputs(RoutingMode::PerApp), ContractGeneration(5)).unwrap_err();
    assert!(matches!(err, RouteError::PerAppUnsupported));
}

#[test]
fn p2_lets_the_local_lan_win_and_p5_still_reports_the_conflict() {
    // networking.md §7.4's normal case: the client is on 192.168.1.0/24 and a
    // gateway advertises the same.
    let gateway = DeviceId::from_array([4u8; 32]);
    let lan = IpPrefix::new(IpAddr::V4(V4Addr::from_octets([192, 168, 1, 0])), 24).unwrap();
    let mut i = inputs(RoutingMode::SplitTunnel);
    i.on_link = vec![lan];
    i.accepted = vec![Candidate {
        prefix: lan,
        source: Source::LanGateway(gateway),
        measured_score: 100,
        metric: 0,
    }];
    let plan = compute(&i, ContractGeneration(6)).unwrap();
    assert!(
        !plan.conflicts.is_empty(),
        "P5: silent resolution is forbidden"
    );
    let c = plan.conflicts[0];
    assert_eq!(
        c.winner.source,
        Source::OnLinkPhysical,
        "P2: breaking the user's own printer to reach a remote one is the wrong default"
    );
    // And the losing advertised route is not installed by us.
    assert!(plan
        .routes
        .get(AddressFamily::V4)
        .iter()
        .all(|r| r.destination != lan));
}

#[test]
fn p3_lets_a_user_pin_override_p2_in_either_direction() {
    let lan = IpPrefix::new(IpAddr::V4(V4Addr::from_octets([192, 168, 1, 0])), 24).unwrap();
    let mut i = inputs(RoutingMode::SplitTunnel);
    i.on_link = vec![lan];
    i.accepted = vec![Candidate {
        prefix: lan,
        source: Source::UserPin,
        measured_score: 0,
        metric: 0,
    }];
    let plan = compute(&i, ContractGeneration(7)).unwrap();
    assert_eq!(plan.conflicts[0].winner.source, Source::UserPin);
}

#[test]
fn the_cgnat_collision_case_is_detected_rather_than_clobbered() {
    let twinnet = IpPrefix::new(IpAddr::V4(V4Addr::from_octets([100, 100, 0, 0])), 22).unwrap();
    let underlay = IpPrefix::new(IpAddr::V4(V4Addr::from_octets([100, 100, 0, 0])), 24).unwrap();
    assert!(twinvpn_route::conflict::cgnat_space_collision(
        &[twinnet],
        &[underlay]
    ));
    let elsewhere = IpPrefix::new(IpAddr::V4(V4Addr::from_octets([192, 168, 0, 0])), 24).unwrap();
    assert!(!twinvpn_route::conflict::cgnat_space_collision(
        &[twinnet],
        &[elsewhere]
    ));
}

// -- MTU ---------------------------------------------------------------------

#[test]
fn the_overhead_table_matches_networking_md_6_1() {
    // Every row of §6.1's table, at a 1500-byte underlay.
    let cases = [
        (Carriage::Direct, AddressFamily::V4, 1440),
        (Carriage::Direct, AddressFamily::V6, 1420),
        (Carriage::RelayUdp, AddressFamily::V4, 1424),
        (Carriage::RelayUdp, AddressFamily::V6, 1404),
        (Carriage::RelayQuic, AddressFamily::V4, 1396),
        (Carriage::RelayQuic, AddressFamily::V6, 1376),
        (Carriage::RelayTls, AddressFamily::V4, 1388),
        (Carriage::RelayTls, AddressFamily::V6, 1368),
    ];
    for (carriage, family, expected) in cases {
        assert_eq!(
            carriage.overlay_ceiling(family, 1500),
            expected,
            "{carriage:?}/{family:?}"
        );
        assert!(
            carriage.clears_floor(family, 1500),
            "every row clears the 1280 floor with margin"
        );
    }
    // The timestamps row costs 12 more.
    assert_eq!(
        Carriage::RelayTlsTimestamps.overlay_ceiling(AddressFamily::V4, 1500),
        1388 - 12
    );
}

#[test]
fn dplpmtud_starts_at_the_floor_and_never_stalls_bring_up() {
    let mut d = Dplpmtud::new(1440);
    assert_eq!(
        d.effective(),
        MTU_FLOOR,
        "bring-up never waits for discovery"
    );
    // Raise by acknowledgement, never by the absence of an ICMP error.
    let probe = d.next_probe().unwrap();
    assert!(probe > MTU_FLOOR && probe <= 1440);
    d.observe(ProbeOutcome::Acknowledged);
    assert_eq!(d.effective(), probe);
}

#[test]
fn a_black_hole_lowers_the_ceiling_and_is_named() {
    let mut d = Dplpmtud::new(1440);
    let probe = d.next_probe().unwrap();
    for _ in 0..4 {
        d.observe(ProbeOutcome::Lost);
    }
    assert!(d.blackhole_suspected(), "NET.MTU_BLACKHOLE_DETECTED");
    assert_eq!(d.effective(), MTU_FLOOR, "the floor always holds");
    let next = d.next_probe();
    assert!(next.is_none() || next.unwrap() < probe);
}

#[test]
fn an_unvalidated_or_sub_floor_icmp_ptb_is_discarded() {
    let mut d = Dplpmtud::new(1440);
    let _ = d.next_probe();
    d.observe(ProbeOutcome::Acknowledged);
    // Blind PTB is a known off-path attack.
    assert_eq!(d.observe_icmp_ptb(1300, false), None);
    // Never accept a PTB below 1280.
    assert_eq!(d.observe_icmp_ptb(1000, true), None);
    // A validated one below the current MTU is a hint that triggers a downward
    // search — the MTU is not set from it.
    let before = d.effective();
    assert!(before > 1300);
    assert_eq!(d.observe_icmp_ptb(1300, true), Some(1300));
    assert_eq!(d.effective(), MTU_FLOOR, "search restarts from the floor");
}

#[test]
fn pmtu_is_re_probed_on_every_migration() {
    let mut d = Dplpmtud::new(1440);
    let _ = d.next_probe();
    d.observe(ProbeOutcome::Acknowledged);
    assert!(d.effective() > MTU_FLOOR);
    d.reset_for_new_path(1400);
    assert_eq!(d.effective(), MTU_FLOOR);
}

#[test]
fn mss_is_clamped_per_family_and_fragmentation_is_never_permitted() {
    assert_eq!(mss_clamp(1400, AddressFamily::V4), 1360);
    assert_eq!(mss_clamp(1400, AddressFamily::V6), 1340);
    for f in [AddressFamily::V4, AddressFamily::V6] {
        assert!(!twinvpn_route::mtu::may_fragment(f));
    }
}

#[test]
fn the_unregistered_route_spelling_is_still_absent_from_the_frozen_registry() {
    for (spelling, note) in twinvpn_route::error::UNREGISTERED_SPELLINGS {
        assert!(
            twinvpn_types::ReasonCode::lookup(spelling).is_none(),
            "{spelling} is now registered — remove the substitution ({note})"
        );
    }
}
