//! The kill switch's rules, asserted — including the P07 mutants ADR-0012 §11.9
//! names.

use core::time::Duration;

use twinvpn_enforce::canary::{Canary, Probe, Verdict, WakePoint};
use twinvpn_enforce::codes::UNREGISTERED;
use twinvpn_enforce::contract::{ArmStep, TeardownStep};
use twinvpn_enforce::exempt::{
    self, BootstrapPredicate, Class, Disposition, ExemptAccounting, SocketClass, SocketRegistry,
};
use twinvpn_enforce::latch::{
    ArmingPolicy, DisarmAuthority, DurabilityPosture, Latch, ProtectedPreconditions,
};
use twinvpn_enforce::portal::{
    GrantLedger, PortalGrant, PortalPolicy, ReachableSet, UserAction, MAX_LIFETIME,
};
use twinvpn_enforce::reconciler::{
    Assertion, Posture, Reclamation, ReclamationAction, Reconciler, TickOutcome,
};
use twinvpn_enforce::scope::{LocalNetworkAccess, Tier1, Tier2};
use twinvpn_env::{ElapsedInstant, MonotonicInstant};
use twinvpn_platform::{
    ContractGeneration, EnforcementCustody, InterfaceIndex, Ruleset,
};
use twinvpn_route::RoutingMode;
use twinvpn_types::{
    AddressFamily, Endpoint, IpAddr, IpPrefix, PerFamily, Port, TrafficDisposition, V4Addr, V6Addr,
};

const OVERLAY: InterfaceIndex = InterfaceIndex(9);
const WIFI: InterfaceIndex = InterfaceIndex(2);

fn v4(o: [u8; 4]) -> IpAddr {
    IpAddr::V4(V4Addr::from_octets(o))
}

// ---------------------------------------------------------------------------
// §11.1 — the two tiers
// ---------------------------------------------------------------------------

#[test]
fn tier_2_permits_only_the_overlay_interface_and_names_no_prefix() {
    let t2 = Tier2 {
        overlay_interface: OVERLAY,
    };
    assert!(t2.permits(OVERLAY));
    assert!(!t2.permits(WIFI));
    // The answer does not depend on a destination, which is the whole of
    // ADR-0010 §11.5(2): a new interface or prefix is denied by the pre-existing
    // rule, with NO rule update required for correctness.
    assert!(!t2.permits(InterfaceIndex(77)));
    for f in [AddressFamily::V4, AddressFamily::V6] {
        assert!(t2.covers(f), "one object covers both families (KS-5)");
    }
}

#[test]
fn full_tunnel_tier_1_is_complement_form_and_never_prefix_enumerated() {
    // The P07 mutant: "a build whose Tier 1 is prefix-enumerated rather than
    // complement-form in full-tunnel mode".
    let full = Tier1::for_mode(RoutingMode::FullTunnel, Vec::new(), Vec::new());
    assert!(!full.is_prefix_enumerated());
    assert!(full.contains(v4([1, 1, 1, 1])), "everything is in scope");

    let overlay =
        IpPrefix::new(v4([100, 100, 0, 0]), 22).unwrap();
    let twinnet_only = Tier1::for_mode(RoutingMode::TwinnetOnly, vec![overlay], Vec::new());
    assert!(twinnet_only.contains(v4([100, 100, 0, 7])));
    // KS-3a: traffic outside the Tier-1 set is NOT governed by the §11.2 table
    // and is not dropped by it. Without this, a TwinNet-only device in BLOCKED
    // would lose all name resolution and therefore all Internet.
    assert!(!twinnet_only.contains(v4([1, 1, 1, 1])));
}

#[test]
fn ks_2_forwarded_traffic_is_never_exemptible() {
    assert!(!twinvpn_enforce::scope::forwarded_traffic_is_exemptible());
}

// ---------------------------------------------------------------------------
// §11.2 — the class table
// ---------------------------------------------------------------------------

#[test]
fn the_three_routed_classes_are_always_dropped_fail_closed() {
    for class in [
        Class::ProtectedPeer,
        Class::ExitRouted,
        Class::LanGatewayRouted,
        Class::ProtectedDns,
    ] {
        // Neither KS-4 nor a portal grant can widen these.
        for local in [true, false] {
            for portal in [true, false] {
                assert_eq!(
                    Disposition::for_class(class, local, portal),
                    TrafficDisposition::DroppedFailClosed,
                    "{class:?}"
                );
            }
        }
    }
}

#[test]
fn ks_3_drops_an_unmatched_in_scope_packet() {
    assert_eq!(
        Disposition::unmatched_in_scope(),
        TrafficDisposition::DroppedFailClosed,
        "ambiguity resolves closed"
    );
}

#[test]
fn ks_4_gates_local_lan_and_link_local_multicast_together() {
    for class in [Class::LocalPhysicalLan, Class::LinkLocalMulticast] {
        assert_eq!(
            Disposition::for_class(class, true, false),
            TrafficDisposition::UnprotectedAnnounced
        );
        assert_eq!(
            Disposition::for_class(class, false, false),
            TrafficDisposition::DroppedFailClosed
        );
    }
    assert_eq!(
        LocalNetworkAccess::default_for(RoutingMode::FullTunnel),
        LocalNetworkAccess::Allow
    );
}

#[test]
fn the_portal_conversation_is_dropped_without_a_live_grant() {
    assert_eq!(
        Disposition::for_class(Class::PortalConversation, true, false),
        TrafficDisposition::DroppedFailClosed
    );
    assert_eq!(
        Disposition::for_class(Class::PortalConversation, true, true),
        TrafficDisposition::UnprotectedAnnounced
    );
}

#[test]
fn underlay_control_traffic_is_permitted_for_both_families() {
    assert!(exempt::is_underlay_control(AddressFamily::V4, 67, None));
    assert!(exempt::is_underlay_control(AddressFamily::V4, 68, None));
    assert!(exempt::is_underlay_control(AddressFamily::V6, 546, None));
    assert!(exempt::is_underlay_control(AddressFamily::V6, 547, None));
    for t in 133u8..=137 {
        assert!(exempt::is_underlay_control(AddressFamily::V6, 0, Some(t)));
    }
    // Not an egress path for anything else.
    assert!(!exempt::is_underlay_control(AddressFamily::V4, 443, None));
    assert!(!exempt::is_underlay_control(AddressFamily::V6, 0, Some(128)));
}

#[test]
fn link_local_unicast_is_recognised_in_both_families() {
    assert!(exempt::is_link_local_unicast(v4([169, 254, 1, 1])));
    assert!(!exempt::is_link_local_unicast(v4([10, 0, 0, 1])));
    let mut o = [0u8; 16];
    o[0] = 0xfe;
    o[1] = 0x80;
    let ll = V6Addr::new(o, twinvpn_types::ZoneIndex::new(3)).unwrap();
    assert!(exempt::is_link_local_unicast(IpAddr::V6(ll)));
}

// ---------------------------------------------------------------------------
// KS-9 … KS-12 — the bootstrap exception
// ---------------------------------------------------------------------------

#[test]
fn ks_9_requires_all_three_clauses_and_there_is_no_two_of_three() {
    let all = BootstrapPredicate {
        agent_originated: true,
        registered_at_bind: true,
        not_forwarded: true,
    };
    assert!(all.matches());
    for drop in 0..3 {
        let mut p = all;
        match drop {
            0 => p.agent_originated = false,
            1 => p.registered_at_bind = false,
            _ => p.not_forwarded = false,
        }
        assert!(!p.matches(), "clause {drop} must be load-bearing");
    }
}

#[test]
fn ks_12_a_failed_registration_leaves_the_socket_unexempt() {
    let mut r = SocketRegistry::new();
    r.register(1, SocketClass::Bootstrap);
    assert_eq!(r.class_of(1), Some(SocketClass::Bootstrap));
    r.registration_failed(1);
    assert_eq!(
        r.class_of(1),
        None,
        "there is no 'register everything on error' path"
    );
    // An unregistered socket of the same process never matches.
    assert_eq!(r.class_of(999), None);
}

#[test]
fn ks_10_keeps_resolver_and_update_destination_bounded() {
    assert!(!SocketClass::Bootstrap.destination_bounded());
    assert!(
        SocketClass::Resolver.destination_bounded(),
        "bounded per DNS scope"
    );
    assert!(
        SocketClass::Update.destination_bounded(),
        "KS-10a: modelled on class 13, not on BOOTSTRAP"
    );
}

#[test]
fn ks_11_flags_exempt_egress_that_diverges_from_our_own_accounting() {
    let ok = ExemptAccounting {
        observed_bytes: 1_000,
        accounted_bytes: 1_000,
    };
    assert!(!ok.is_anomalous(64));
    // Less on the wire than we accounted for is ordinary.
    let fewer = ExemptAccounting {
        observed_bytes: 900,
        accounted_bytes: 1_000,
    };
    assert!(!fewer.is_anomalous(0));
    // More is the anomaly.
    let more = ExemptAccounting {
        observed_bytes: 2_000,
        accounted_bytes: 1_000,
    };
    assert!(more.is_anomalous(64));
}

// ---------------------------------------------------------------------------
// KS-17, KS-18, KS-19, KS-21 — the latch
// ---------------------------------------------------------------------------

fn both_present() -> PerFamily<bool> {
    PerFamily::new(true, true)
}

#[test]
fn ks_19_starts_blocked_so_the_deny_predates_the_first_packet() {
    let l = Latch::new(ArmingPolicy::WhileIntendedUp);
    assert_eq!(l.desired(), Ruleset::Blocked);
}

#[test]
fn ks_18_refuses_the_swap_unless_both_conditions_hold_for_both_families() {
    let mut l = Latch::new(ArmingPolicy::WhileIntendedUp);
    l.set_intended_up(true);

    // No path validation.
    let no_path = ProtectedPreconditions {
        path_validated: false,
        ruleset_present: both_present(),
    };
    assert_eq!(l.leave_blocked(no_path), Ruleset::Blocked);

    // Path validated, but the v6 half of the ruleset is missing.
    let half = ProtectedPreconditions {
        path_validated: true,
        ruleset_present: PerFamily::new(true, false),
    };
    assert_eq!(l.leave_blocked(half), Ruleset::Blocked);
    assert_eq!(half.missing_family(), Some(AddressFamily::V6));

    // Both conditions, both families.
    let ok = ProtectedPreconditions {
        path_validated: true,
        ruleset_present: both_present(),
    };
    assert_eq!(l.leave_blocked(ok), Ruleset::Protected);

    // Tightening never needs a precondition.
    assert_eq!(l.enter_blocked(), Ruleset::Blocked);
}

#[test]
fn ks_21_refuses_every_non_local_disarm_authority() {
    for authority in [
        DisarmAuthority::Remote,
        DisarmAuthority::ControlPlaneDocument,
    ] {
        let mut l = Latch::new(ArmingPolicy::WhileIntendedUp);
        l.set_intended_up(true);
        assert!(!l.disarm(authority), "{authority:?} must be refused");
        assert!(l.is_up());
        assert!(
            authority.refusal_is_security_event(),
            "always a security event"
        );
    }
    // A local interactive action succeeds, and so does KS-21a's local admin on
    // HC-3 — because "a control plane cannot produce an authenticated local
    // shell", and KS-20 says blocked must not mean bricked.
    for authority in [
        DisarmAuthority::LocalInteractive,
        DisarmAuthority::LocalAdminOnManagementSocket,
    ] {
        let mut l = Latch::new(ArmingPolicy::WhileIntendedUp);
        l.set_intended_up(true);
        assert!(l.disarm(authority));
        assert!(!l.is_up());
        assert!(!authority.refusal_is_security_event());
    }
}

#[test]
fn the_arming_policies_behave_as_m1_m2_and_m4() {
    assert!(ArmingPolicy::Always.latch_up(false));
    assert!(!ArmingPolicy::WhileIntendedUp.latch_up(false));
    assert!(ArmingPolicy::WhileIntendedUp.latch_up(true));
    assert!(!ArmingPolicy::PermissiveAnnounced.latch_up(true));
}

#[test]
fn a_target_whose_rules_die_with_the_process_must_disclose_it() {
    let good = DurabilityPosture {
        custody: EnforcementCustody {
            survives_core_exit: true,
            swap_is_atomic: true,
        },
        boot_enforcement_available: true,
    };
    assert!(!good.requires_disclosure());

    // E4 (userspace-only) is rejected precisely because it fails K3.
    let bad = DurabilityPosture {
        custody: EnforcementCustody {
            survives_core_exit: false,
            swap_is_atomic: true,
        },
        boot_enforcement_available: true,
    };
    assert!(bad.requires_disclosure());
    assert!(!bad.survives_core_exit());

    // iOS: no pre-network boot ruleset is possible; the window is named.
    let ios = DurabilityPosture {
        boot_enforcement_available: false,
        ..good
    };
    assert!(ios.requires_disclosure());
}

// ---------------------------------------------------------------------------
// §11.8's orderings
// ---------------------------------------------------------------------------

#[test]
fn the_interface_comes_up_only_after_the_contract_is_applied() {
    let s = ArmStep::SEQUENCE;
    let blocked = s.iter().position(|x| *x == ArmStep::BlockedLive).unwrap();
    let create = s
        .iter()
        .position(|x| *x == ArmStep::CreateInterfaceDown)
        .unwrap();
    let apply = s.iter().position(|x| *x == ArmStep::ApplyContract).unwrap();
    let up = s.iter().position(|x| *x == ArmStep::LinkUp).unwrap();
    let swap = s
        .iter()
        .position(|x| *x == ArmStep::SwapToProtected)
        .unwrap();
    assert!(blocked < create, "the deny predates the interface");
    assert!(create < apply && apply < up, "created DOWN, then configured");
    assert!(up < swap, "KS-18 is checked after the link is up");
}

#[test]
fn teardown_swaps_to_blocked_before_destroying_the_interface() {
    let s = TeardownStep::SEQUENCE;
    let swap = s
        .iter()
        .position(|x| *x == TeardownStep::SwapToBlocked)
        .unwrap();
    let destroy = s
        .iter()
        .position(|x| *x == TeardownStep::DestroyInterface)
        .unwrap();
    assert!(swap < destroy, "rules stay live while the latch is UP");
}

// ---------------------------------------------------------------------------
// §11.9 — the reconciler and the canary
// ---------------------------------------------------------------------------

fn assertion(present: PerFamily<bool>, installed: Option<Ruleset>) -> Assertion {
    Assertion {
        generation: ContractGeneration(1),
        installed,
        present,
        asserted_at: MonotonicInstant::ORIGIN,
        freshness_window: Duration::from_secs(10),
    }
}

#[test]
fn a_stale_assertion_is_unknown_and_never_protected() {
    let a = assertion(both_present(), Some(Ruleset::Blocked));
    let now = MonotonicInstant::ORIGIN.saturating_add(Duration::from_secs(11));
    assert_eq!(a.posture(Ruleset::Blocked, now), Posture::Unknown);
}

#[test]
fn a_missing_family_is_never_reported_as_protected() {
    let a = assertion(PerFamily::new(true, false), Some(Ruleset::Blocked));
    let now = MonotonicInstant::ORIGIN;
    assert!(matches!(
        a.posture(Ruleset::Blocked, now),
        Posture::Unprotected(_)
    ));
    assert!(a.is_partial_install(), "KS-5: non-conforming, not degraded");
    assert_eq!(a.missing_family(), Some(AddressFamily::V6));
}

#[test]
fn a_tampered_or_absent_ruleset_drives_blocked() {
    let mut r = Reconciler::new();
    assert!(r.set_desired(ContractGeneration(1), Ruleset::Protected));
    let now = MonotonicInstant::ORIGIN;

    // Removed entirely.
    let gone = assertion(both_present(), None);
    let outcome = r.tick(gone, now);
    assert!(outcome.drives_blocked());

    // Present, but the wrong ruleset — someone swapped it under us.
    let wrong = assertion(both_present(), Some(Ruleset::Blocked));
    assert!(r.tick(wrong, now).drives_blocked());

    // Converged.
    let ok = assertion(both_present(), Some(Ruleset::Protected));
    assert_eq!(r.tick(ok, now), TickOutcome::Converged);

    let (ticks, violations) = r.counters();
    assert_eq!(ticks, 3);
    assert_eq!(violations, 2);
}

#[test]
fn a_lower_generation_is_refused_rather_than_applied() {
    let mut r = Reconciler::new();
    assert!(r.set_desired(ContractGeneration(5), Ruleset::Protected));
    assert!(!r.set_desired(ContractGeneration(4), Ruleset::Blocked));
    assert_eq!(r.desired_generation(), ContractGeneration(5));
    assert_eq!(r.desired_ruleset(), Ruleset::Protected);
}

#[test]
fn ks_20_leaves_a_crashed_host_blocked_and_never_open() {
    // Nothing found: install BLOCKED before anything else.
    let none = Reclamation {
        owner_tag: "twinvpn".into(),
        found: None,
    };
    assert_eq!(none.action(), ReclamationAction::InstallBlocked);
    // Blocked found: adopt it.
    let blocked = Reclamation {
        owner_tag: "twinvpn".into(),
        found: Some(Ruleset::Blocked),
    };
    assert_eq!(blocked.action(), ReclamationAction::Adopt);
    // PROTECTED found with no tunnel behind it: tighten. Adopting would leave a
    // hole, and tightening is always safe.
    let protected = Reclamation {
        owner_tag: "twinvpn".into(),
        found: Some(Ruleset::Protected),
    };
    assert_eq!(protected.action(), ReclamationAction::TightenToBlocked);
}

#[test]
fn the_canary_runs_per_family_and_a_missing_deny_is_a_leak() {
    let mut c = Canary::new();
    // The deny counter incremented: enforcement is working.
    assert_eq!(
        c.observe(
            Probe {
                family: AddressFamily::V4,
                mark: 1,
                from_non_exempt_socket: true
            },
            1
        ),
        Verdict::Denied
    );
    // It did not: the packet was NOT dropped.
    let v = c.observe(
        Probe {
            family: AddressFamily::V6,
            mark: 2,
            from_non_exempt_socket: true,
        },
        0,
    );
    assert_eq!(v, Verdict::EgressObserved);
    assert!(v.drives_blocked());
    assert!(v.reason_code().is_some());
    assert!(c.both_families_probed());
}

#[test]
fn a_probe_from_an_exempt_socket_proves_nothing_and_says_so() {
    let mut c = Canary::new();
    let v = c.observe(
        Probe {
            family: AddressFamily::V4,
            mark: 1,
            from_non_exempt_socket: false,
        },
        0,
    );
    assert_eq!(
        v,
        Verdict::Invalid,
        "an exempt socket is permitted by design; the probe would invert the test"
    );
    assert!(!v.drives_blocked());
    assert_eq!(c.probes(AddressFamily::V4), 0);
}

#[test]
fn a_v4_only_canary_is_not_reported_as_having_tested_the_channel() {
    let mut c = Canary::new();
    c.observe(
        Probe {
            family: AddressFamily::V4,
            mark: 1,
            from_non_exempt_socket: true,
        },
        1,
    );
    assert!(!c.both_families_probed());
    let _ = WakePoint::NetworkChange;
    assert!(twinvpn_enforce::canary::runs_during_portal_grant());
}

// ---------------------------------------------------------------------------
// §11.7 — the portal
// ---------------------------------------------------------------------------

fn reachable() -> ReachableSet {
    ReachableSet {
        portal_endpoints: vec![Endpoint::new(v4([192, 0, 2, 1]), Port::new(443).unwrap())],
        resolvers: vec![v4([192, 0, 2, 53])],
        interface: WIFI,
        network_fingerprint: [1u8; 16],
    }
}

#[test]
fn ks_14_never_grants_automatically_and_has_no_always_value() {
    let now = ElapsedInstant::ORIGIN;
    assert!(PortalGrant::request(
        PortalPolicy::Never,
        UserAction::performed_locally(),
        now,
        MAX_LIFETIME,
        reachable()
    )
    .is_none());
    assert!(PortalGrant::request(
        PortalPolicy::Prompt,
        UserAction::performed_locally(),
        now,
        MAX_LIFETIME,
        reachable()
    )
    .is_some());
}

#[test]
fn a_grant_is_capped_scoped_to_one_interface_and_expires() {
    let now = ElapsedInstant::ORIGIN;
    let g = PortalGrant::request(
        PortalPolicy::Prompt,
        UserAction::performed_locally(),
        now,
        Duration::from_secs(3600), // asks for an hour
        reachable(),
    )
    .unwrap();
    assert!(g.remaining(now) <= MAX_LIFETIME, "capped at 300 s");

    let portal = Endpoint::new(v4([192, 0, 2, 1]), Port::new(443).unwrap());
    assert!(g.permits(now, WIFI, portal));
    // Never the overlay, never a second interface.
    assert!(!g.permits(now, OVERLAY, portal));
    assert!(!g.permits(now, InterfaceIndex(3), portal));
    // Nothing outside the destination set.
    let elsewhere = Endpoint::new(v4([203, 0, 113, 9]), Port::new(443).unwrap());
    assert!(!g.permits(now, WIFI, elsewhere));
    // The resolver, on DNS ports only.
    let dns = Endpoint::new(v4([192, 0, 2, 53]), Port::new(53).unwrap());
    assert!(g.permits(now, WIFI, dns));
    let dns_wrong_port = Endpoint::new(v4([192, 0, 2, 53]), Port::new(80).unwrap());
    assert!(!g.permits(now, WIFI, dns_wrong_port));
    // And it expires.
    let later = now.saturating_add(Duration::from_secs(301));
    assert!(!g.is_live(later));
    assert!(!g.permits(later, WIFI, portal));

    assert!(PortalGrant::protected_scope_stays_blocked());
}

#[test]
fn a_second_grant_needs_a_second_user_action() {
    let mut ledger = GrantLedger::new();
    let fp = [1u8; 16];
    assert!(!ledger.may_auto_renew(&fp));
    ledger.record(fp);
    assert!(ledger.already_granted(&fp));
    assert!(!ledger.may_auto_renew(&fp));
    ledger.on_detach();
    assert!(!ledger.already_granted(&fp));
}

#[test]
fn ks_16_keeps_portal_answers_out_of_the_protected_cache_at_both_ends() {
    assert!(!twinvpn_enforce::portal::portal_answers_may_enter_protected_cache());
    // The other end: twinvpn-dns has no cross-scope lookup at all.
    use twinvpn_dns::cache::ScopedCaches;
    use twinvpn_dns::Scope;
    let mut c = ScopedCaches::new();
    c.insert(
        Scope::Portal,
        b"portal".to_vec(),
        vec![1],
        Duration::from_secs(60),
        Some(Duration::from_secs(300)),
        MonotonicInstant::ORIGIN,
    );
    assert!(c
        .get(Scope::Protected, b"portal", MonotonicInstant::ORIGIN)
        .is_none());
}

// ---------------------------------------------------------------------------
// The contract defect
// ---------------------------------------------------------------------------

#[test]
fn every_unregistered_adr_0012_code_is_still_absent_from_the_frozen_registry() {
    for s in UNREGISTERED {
        assert!(
            twinvpn_types::ReasonCode::lookup(s.specified).is_none(),
            "{} is now registered — remove its substitution in twinvpn-enforce::codes",
            s.specified
        );
    }
    assert_eq!(
        UNREGISTERED.len(),
        17,
        "ADR-0012 §11.9 contributes 21 POLICY codes; the registry carries 4"
    );
}

#[test]
fn the_four_registered_killswitch_codes_are_the_ones_this_build_emits() {
    for code in [
        twinvpn_enforce::codes::killswitch_engaged(),
        twinvpn_enforce::codes::ruleset_absent(),
        twinvpn_enforce::codes::unprotected_fallback(),
        twinvpn_enforce::codes::ipv6_unprotected(),
    ] {
        assert!(twinvpn_types::ReasonCode::lookup(code.as_str()).is_some());
    }
}
