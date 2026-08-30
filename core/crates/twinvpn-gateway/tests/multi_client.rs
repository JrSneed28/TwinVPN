//! ADR-0013's per-peer isolation, grants and fairness, asserted.

use core::time::Duration;

use twinvpn_gateway::grant::{
    self, GatewayPolicy, Grant, Granted, Refusal as GrantRefusal, Request,
};
use twinvpn_gateway::peer_table::{self, AdmitError, AllowedSources, PeerRow, PeerTable, Refusal};
use twinvpn_gateway::quota::{self, Capacity, PeerQuota, PeerUsage, QuotaRefusal};
use twinvpn_types::{AddressFamily, DeviceId, IpAddr, IpPrefix, PerFamily, V4Addr, V6Addr};

fn v4(o: [u8; 4], len: u32) -> IpPrefix {
    IpPrefix::new(IpAddr::V4(V4Addr::from_octets(o)), len).unwrap()
}

fn v6_host(last: u8) -> IpPrefix {
    let mut o = [0u8; 16];
    o[..6].copy_from_slice(&[0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10]);
    o[15] = last;
    IpPrefix::new(IpAddr::V6(V6Addr::new(o, None).unwrap()), 128).unwrap()
}

fn sources(last: u8) -> AllowedSources {
    let mut s = AllowedSources::new();
    assert!(s.insert(v4([100, 100, 0, last], 32)));
    assert!(s.insert(v6_host(last)));
    s
}

fn peer(id: u8) -> PeerRow {
    PeerRow {
        device_id: DeviceId::from_array([id; 32]),
        allowed_sources: sources(id),
        policy_version: 3,
        revoked: false,
    }
}

// ---------------------------------------------------------------------------
// §11.1 / §11.2 — the peer table
// ---------------------------------------------------------------------------

#[test]
fn mg_1_refuses_a_wildcard_in_an_allowed_sources_set() {
    let mut s = AllowedSources::new();
    assert!(
        !s.insert(v4([0, 0, 0, 0], 0)),
        "a wildcard would make MG-4's check vacuous"
    );
    let mut o = [0u8; 16];
    o[0] = 0;
    let default_v6 = IpPrefix::new(IpAddr::V6(V6Addr::new(o, None).unwrap()), 0).unwrap();
    assert!(!s.insert(default_v6));
    // An ordinary peer's set is exactly two host addresses.
    assert!(s.insert(v4([100, 100, 0, 7], 32)));
    assert!(s.insert(v6_host(7)));
    assert!(s.both_families_present());
}

#[test]
fn mg_3_refuses_a_peer_row_with_only_one_family() {
    let mut half = AllowedSources::new();
    half.insert(v4([100, 100, 0, 1], 32));
    let row = PeerRow {
        device_id: DeviceId::from_array([1; 32]),
        allowed_sources: half,
        policy_version: 1,
        revoked: false,
    };
    let mut t = PeerTable::new();
    assert_eq!(t.admit(row), Err(AdmitError::SingleFamilySourceSet));
    assert!(t.is_empty());
}

#[test]
fn mg_2_refuses_overlapping_source_sets() {
    let mut t = PeerTable::new();
    t.admit(peer(1)).unwrap();
    // A second peer claiming the same /32 would be a cross-peer interception
    // primitive.
    let mut clash = peer(2);
    clash.allowed_sources = sources(1);
    assert_eq!(t.admit(clash), Err(AdmitError::SourceSetOverlap));
    assert_eq!(t.len(), 1);
    // A disjoint peer is admitted.
    t.admit(peer(2)).unwrap();
    assert_eq!(t.len(), 2);
}

#[test]
fn mg_4_drops_a_spoofed_source_and_never_forwards_or_rewrites_it() {
    let mut t = PeerTable::new();
    t.admit(peer(1)).unwrap();
    t.admit(peer(2)).unwrap();

    let honest = t
        .attribute_ingress(
            DeviceId::from_array([1; 32]),
            IpAddr::V4(V4Addr::from_octets([100, 100, 0, 1])),
        )
        .expect("its own address");
    assert_eq!(honest.device_id, DeviceId::from_array([1; 32]));

    // Peer 1 claiming peer 2's address.
    assert_eq!(
        t.attribute_ingress(
            DeviceId::from_array([1; 32]),
            IpAddr::V4(V4Addr::from_octets([100, 100, 0, 2]))
        ),
        Err(Refusal::SourceSpoofed)
    );
    // And in v6, checked by the same table and the same code path (MG-3).
    let mut o = [0u8; 16];
    o[..6].copy_from_slice(&[0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10]);
    o[15] = 2;
    assert_eq!(
        t.attribute_ingress(
            DeviceId::from_array([1; 32]),
            IpAddr::V6(V6Addr::new(o, None).unwrap())
        ),
        Err(Refusal::SourceSpoofed)
    );
}

#[test]
fn a_revoked_peer_is_refused_from_a_cached_bit_and_never_a_control_plane_call() {
    let mut t = PeerTable::new();
    let mut p = peer(1);
    p.revoked = true;
    t.admit(p).unwrap();
    assert_eq!(
        t.attribute_ingress(
            DeviceId::from_array([1; 32]),
            IpAddr::V4(V4Addr::from_octets([100, 100, 0, 1]))
        ),
        Err(Refusal::PeerRevoked)
    );
}

#[test]
fn egress_never_floods_and_never_uses_a_default_peer() {
    let mut t = PeerTable::new();
    t.admit(peer(1)).unwrap();
    t.admit(peer(2)).unwrap();
    assert_eq!(
        t.egress_peer(IpAddr::V4(V4Addr::from_octets([100, 100, 0, 2])))
            .unwrap()
            .device_id,
        DeviceId::from_array([2; 32])
    );
    assert!(
        t.egress_peer(IpAddr::V4(V4Addr::from_octets([100, 100, 0, 9])))
            .is_none(),
        "an unknown destination is dropped, never sent to a default peer"
    );
}

#[test]
fn mg_5_peer_transit_is_recognised_and_is_not_implied_by_co_membership() {
    let mut t = PeerTable::new();
    t.admit(peer(1)).unwrap();
    t.admit(peer(2)).unwrap();
    assert!(t.is_peer_transit(
        DeviceId::from_array([1; 32]),
        IpAddr::V4(V4Addr::from_octets([100, 100, 0, 2]))
    ));
    // A peer's own address is not transit.
    assert!(!t.is_peer_transit(
        DeviceId::from_array([1; 32]),
        IpAddr::V4(V4Addr::from_octets([100, 100, 0, 1]))
    ));
}

#[test]
fn mg_6_and_mg_7_are_stated_rather_than_assumed() {
    assert!(
        !peer_table::rpf_is_the_antispoofing_control(),
        "RPF is a routing heuristic and not identity-bound"
    );
    let a = DeviceId::from_array([1; 32]);
    let b = DeviceId::from_array([2; 32]);
    assert!(peer_table::conntrack_entry_matches(a, a));
    assert!(
        !peer_table::conntrack_entry_matches(a, b),
        "A's conntrack entry must not be matched by B's packet"
    );
}

// ---------------------------------------------------------------------------
// §11.3 — grants, and CF-10's explicit presence
// ---------------------------------------------------------------------------

fn policy() -> GatewayPolicy {
    GatewayPolicy {
        advertised: PerFamily::new(
            vec![v4([192, 168, 7, 0], 24)],
            vec![IpPrefix::new(
                IpAddr::V6(
                    V6Addr::new(
                        [0x20, 0x01, 0x0d, 0xb8, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        None,
                    )
                    .unwrap(),
                ),
                64,
            )
            .unwrap()],
        ),
        permitted: vec![(DeviceId::from_array([1; 32]), v4([192, 168, 7, 0], 24))],
        egress_families: PerFamily::new(true, true),
        exit_permitted: true,
        policy_version: 3,
        has_signed_bundle: true,
        ttl_ms: 3_600_000,
    }
}

#[test]
fn an_absent_grant_field_is_a_denial_and_never_a_permission() {
    assert!(!Granted::from_optional(None).is_granted());
    assert!(!Granted::from_optional(Some(false)).is_granted());
    assert!(Granted::from_optional(Some(true)).is_granted());
}

#[test]
fn the_gateway_authors_the_grant_and_it_belongs_to_exactly_one_peer() {
    let g = grant::decide(
        &policy(),
        DeviceId::from_array([1; 32]),
        &Request::LanAccess {
            prefix: v4([192, 168, 7, 0], 24),
            family: AddressFamily::V4,
        },
        &[],
    );
    assert_eq!(g.peer(), DeviceId::from_array([1; 32]));
    assert!(g.permits(AddressFamily::V4));

    // A grant issued to peer 1 creates no reachability for peer 2.
    let other = grant::decide(
        &policy(),
        DeviceId::from_array([2; 32]),
        &Request::LanAccess {
            prefix: v4([192, 168, 7, 0], 24),
            family: AddressFamily::V4,
        },
        &[],
    );
    assert!(!other.permits(AddressFamily::V4));
    assert!(matches!(
        other,
        Grant::LanAccess {
            refusal: Some(GrantRefusal::PolicyDenied),
            ..
        }
    ));
}

#[test]
fn a_colliding_client_lan_is_named_precisely_rather_than_described() {
    let g = grant::decide(
        &policy(),
        DeviceId::from_array([1; 32]),
        &Request::LanAccess {
            prefix: v4([192, 168, 7, 0], 24),
            family: AddressFamily::V4,
        },
        // The client is already on the same RFC 1918 range.
        &[v4([192, 168, 7, 0], 24)],
    );
    assert!(matches!(
        g,
        Grant::LanAccess {
            refusal: Some(GrantRefusal::PrefixCollidesLocal),
            ..
        }
    ));
    // And the prefix rides along in the grant, so the diagnostic can name it.
    if let Grant::LanAccess { prefix, .. } = g {
        assert_eq!(prefix, v4([192, 168, 7, 0], 24));
    }
}

#[test]
fn an_unadvertised_prefix_is_refused_with_its_own_code() {
    let g = grant::decide(
        &policy(),
        DeviceId::from_array([1; 32]),
        &Request::LanAccess {
            prefix: v4([10, 0, 0, 0], 24),
            family: AddressFamily::V4,
        },
        &[],
    );
    assert!(matches!(
        g,
        Grant::LanAccess {
            refusal: Some(GrantRefusal::NotAdvertised),
            ..
        }
    ));
}

#[test]
fn a_one_family_exit_grant_is_never_a_silent_success() {
    let mut p = policy();
    *p.egress_families.get_mut(AddressFamily::V6) = false;
    let g = grant::decide(
        &p,
        DeviceId::from_array([1; 32]),
        &Request::ExitNode {
            request_v4: true,
            request_v6: true,
        },
        &[],
    );
    assert!(g.permits(AddressFamily::V4));
    assert!(!g.permits(AddressFamily::V6));
    assert!(
        g.is_partial(),
        "the client must be told which family was withheld"
    );
    assert!(matches!(
        g,
        Grant::ExitNode {
            refusal: Some(GrantRefusal::NoV6Egress),
            ..
        }
    ));
}

#[test]
fn mg_9_refuses_a_peer_with_no_signed_bundle_rather_than_failing_open() {
    let mut p = policy();
    p.has_signed_bundle = false;
    let lan = grant::decide(
        &p,
        DeviceId::from_array([1; 32]),
        &Request::LanAccess {
            prefix: v4([192, 168, 7, 0], 24),
            family: AddressFamily::V4,
        },
        &[],
    );
    assert!(!lan.permits(AddressFamily::V4));
    let exit = grant::decide(
        &p,
        DeviceId::from_array([1; 32]),
        &Request::ExitNode {
            request_v4: true,
            request_v6: true,
        },
        &[],
    );
    assert!(!exit.permits(AddressFamily::V4) && !exit.permits(AddressFamily::V6));
}

#[test]
fn mg_8_refuses_a_lower_policy_version_and_withdraws_grants_that_no_longer_pass() {
    assert!(grant::accepts_policy_version(3, 4));
    assert!(!grant::accepts_policy_version(3, 3));
    assert!(!grant::accepts_policy_version(3, 2));

    let live = vec![grant::decide(
        &policy(),
        DeviceId::from_array([1; 32]),
        &Request::LanAccess {
            prefix: v4([192, 168, 7, 0], 24),
            family: AddressFamily::V4,
        },
        &[],
    )];
    // Nothing changed: nothing is withdrawn.
    assert!(grant::withdraw_after_policy_change(&policy(), &live, &[]).is_empty());
    // The peer loses its permission: the live grant is withdrawn.
    let mut tightened = policy();
    tightened.permitted.clear();
    assert_eq!(
        grant::withdraw_after_policy_change(&tightened, &live, &[]).len(),
        1
    );
    assert_eq!(grant::RECOMPILE_WITHIN, core::time::Duration::from_secs(1));
}

// ---------------------------------------------------------------------------
// §11.4 / §11.5 — quotas, fairness and scale
// ---------------------------------------------------------------------------

#[test]
fn mg_14_supports_at_least_sixteen_peers_on_any_platform() {
    assert_eq!(quota::MIN_ADMITTED_PEERS, 16);
    // A gateway configured for fewer is clamped up, because a build that cannot
    // manage sixteen is non-conforming.
    let c = Capacity::new(1 << 30, 4);
    assert_eq!(c.max_peers(), 16);
}

#[test]
fn the_guaranteed_floor_is_the_larger_of_the_share_and_256_kbit() {
    // A generous uplink shared sixteen ways beats the minimum.
    assert_eq!(quota::floor_bits_per_sec(100_000_000, 16), 6_250_000);
    // A thin uplink falls back to the minimum rather than to nothing.
    assert_eq!(quota::floor_bits_per_sec(1_000_000, 16), 256_000);
    assert_eq!(
        quota::PREEMPTION_BOUND,
        core::time::Duration::from_millis(100)
    );
}

/// The fairness pair ADR-0013 §11.11 designates, as arithmetic.
///
/// `docs/testing-strategy.md` §P06: "the assertion is
/// `gw_peer_achieved_bps(B) >= gw_peer_floor_share_bps(B)` sustained, reached
/// within 100 ms". What this crate can hold is the comparison and the
/// conversion; the measurement needs a forwarding data plane, which `lib.rs`
/// says in terms this crate does not have.
#[test]
fn the_designated_fairness_pair_compares_achieved_against_the_floor() {
    let floor = quota::floor_bits_per_sec(100_000_000, 16);
    assert_eq!(floor, 6_250_000);

    // One second of traffic at exactly the floor. 6_250_000 bits is 781_250
    // bytes.
    let at_floor = quota::achieved_bits_per_sec(781_250, Duration::from_secs(1));
    assert_eq!(at_floor, floor);
    assert!(
        quota::meets_floor(at_floor, floor),
        "the comparison is >=, so a peer exactly at its floor meets it"
    );

    // The noisy-neighbour case MG-10 calls "a defect, not a condition".
    let starved = quota::achieved_bits_per_sec(781_250 / 4, Duration::from_secs(1));
    assert!(!quota::meets_floor(starved, floor));

    // A sub-second window is the one the 100 ms preemption bound is measured
    // over, so the conversion must be right there too.
    assert_eq!(
        quota::achieved_bits_per_sec(78_125, quota::PREEMPTION_BOUND),
        floor,
        "a tenth of the bytes in a tenth of a second is the same rate"
    );

    // No time has passed, so there is no rate. Answering anything else would
    // let a zero-length sample satisfy the floor by accident.
    assert_eq!(quota::achieved_bits_per_sec(1_000_000, Duration::ZERO), 0);
    assert!(!quota::meets_floor(
        quota::achieved_bits_per_sec(1_000_000, Duration::ZERO),
        floor
    ));
}

#[test]
fn mg_12_refuses_admission_rather_than_over_committing() {
    let q = PeerQuota::new(100_000_000, 16);
    // Just enough for two peers.
    let mut c = Capacity::new(q.reserved_bytes() * 2, 16);
    assert!(c.reserve(q).is_ok());
    assert!(c.reserve(q).is_ok());
    assert_eq!(
        c.reserve(q),
        Err(AdmitError::CapacityReservedUnavailable),
        "a gateway that cannot reserve refuses admission"
    );
    assert_eq!(c.admitted(), 2);
    c.release(q);
    assert!(c.reserve(q).is_ok());
}

#[test]
fn the_peer_ceiling_refuses_the_seventeenth_peer_rather_than_degrading_everyone() {
    let q = PeerQuota {
        conntrack_hard: 1,
        ..PeerQuota::new(100_000_000, 16)
    };
    let mut c = Capacity::new(u64::MAX / 2, 16);
    for _ in 0..16 {
        assert!(c.reserve(q).is_ok());
    }
    assert_eq!(c.reserve(q), Err(AdmitError::PeerLimitReached));
}

#[test]
fn a_peer_at_its_hard_conntrack_cap_loses_new_flows_and_keeps_existing_ones() {
    let q = PeerQuota::new(100_000_000, 16);
    let at_cap = PeerUsage {
        conntrack: q.conntrack_hard,
        ..PeerUsage::new()
    };
    assert_eq!(
        quota::admit_flow(q, at_cap, 0, 100_000),
        Err(QuotaRefusal::ConntrackExhausted)
    );
    // Below the hard cap but above the soft cap: throttled, not refused.
    let soft = PeerUsage {
        conntrack: q.conntrack_soft,
        ..PeerUsage::new()
    };
    assert!(quota::admit_flow(q, soft, 0, 100_000).is_ok());
    assert!(quota::throttle_new_flows(q, soft));
    assert!(!quota::throttle_new_flows(q, PeerUsage::new()));
}

#[test]
fn mg_11_sizes_per_peer_conntrack_so_one_peer_cannot_starve_the_table() {
    // 4096 × 16 = 65 536, which is under 80 % of 100 000.
    assert!(quota::conntrack_sizing_is_conforming(4_096, 16, 100_000));
    // 4096 × 32 = 131 072, which is not.
    assert!(!quota::conntrack_sizing_is_conforming(4_096, 32, 100_000));
    // Global exhaustion despite the sizing is a distinct, CRITICAL condition.
    let q = PeerQuota::new(100_000_000, 16);
    assert_eq!(
        quota::admit_flow(q, PeerUsage::new(), 100, 100),
        Err(QuotaRefusal::ConntrackGlobalExhausted)
    );
}

#[test]
fn counters_are_kept_per_family_so_a_v6_campaign_cannot_hide_behind_v4() {
    let mut u = PeerUsage::new();
    u.observe_forward(AddressFamily::V4, 1_000);
    u.observe_drop(AddressFamily::V6);
    u.observe_drop(AddressFamily::V6);
    assert_eq!(*u.bytes.get(AddressFamily::V4), 1_000);
    assert_eq!(*u.bytes.get(AddressFamily::V6), 0);
    assert_eq!(*u.drops.get(AddressFamily::V4), 0);
    assert_eq!(*u.drops.get(AddressFamily::V6), 2);
}

#[test]
fn mg_13_gives_relayed_traffic_no_separate_budget() {
    assert!(
        !quota::relayed_traffic_has_its_own_budget(),
        "the path class changes latency, not entitlement"
    );
}
