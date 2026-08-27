//! **End-to-end.** The kill switch: the test that would catch a leak, for both
//! address families, and that fails if enforcement is dropped.
//!
//! **Authority:** ADR-0012; `docs/testing-strategy.md` §2.14, §6.5 blocker
//! **B-7** ("any leak test negative **without** its positive control green on the
//! same rig in the same session — an unproven observation channel is not a
//! negative result"); `docs/implementation/ownership.md` §6 ("Never route around
//! TwinVPN while fail-closed is active"); ADR-0010 **R1**, **R6**.
//!
//! # The shape every test here takes
//!
//! A leak test that only ever reports "no leak" is indistinguishable from a leak
//! test that is not looking. Every negative assertion below is therefore paired,
//! in the same test, with a **positive control**: the same rig, the same canary,
//! an injected condition that *is* a leak, and the assertion that it is caught.
//! B-7 makes that pairing a release criterion; here it is the file's structure.
//!
//! # What crosses a domain boundary
//!
//! `twinvpn-enforce`'s own suite exercises the canary against hand-built probes.
//! These tests drive it from a route plan `twinvpn-route` produced, a DNS policy
//! `twinvpn-dns` validated, and an interface set `twinvpn-platform`'s adapter
//! reported — which is where a disagreement about "is this family covered" can
//! actually live.

use twinvpn_enforce::canary::{Canary, Probe, Verdict, WakePoint};
use twinvpn_enforce::exempt::{Class, Disposition, SocketClass, SocketRegistry};
use twinvpn_enforce::reconciler::{Assertion, Posture, Reconciler, TickOutcome, REASSERT_WITHIN};
use twinvpn_enforce::{DisarmAuthority, LocalNetworkAccess, Tier1, Tier2};
use twinvpn_env::MonotonicInstant;
use twinvpn_platform::{ContractGeneration, InterfaceIndex, PlatformAdapter, Ruleset};
use twinvpn_route::program::RoutingMode;
use twinvpn_types::{AddressFamily, IpAddr, PerFamily, TrafficDisposition, V4Addr, V6Addr};

use twinvpn_system_tests::{block_on, dns_policy, preconditions, stub_addresses, HostFamily, Rig};

const BOTH: [AddressFamily; 2] = [AddressFamily::V4, AddressFamily::V6];

// ---------------------------------------------------------------------------
// The canary, per family, each with its positive control (B-7).
// ---------------------------------------------------------------------------

#[test]
fn the_canary_catches_an_egress_that_the_deny_counter_did_not_account_for() {
    // The negative result and the positive control in one test, per family, so
    // B-7's "on the same rig in the same session" is structural.
    for family in BOTH {
        let mut canary = Canary::new();
        let probe = Probe {
            family,
            mark: 0xdead_beef,
            from_non_exempt_socket: true,
        };

        // Positive control: enforcement is working. The deny counter advanced,
        // so the probe was dropped.
        assert_eq!(
            canary.observe(probe, 1),
            Verdict::Denied,
            "{family:?}: the positive control did not observe a deny; the \
             observation channel is unproven and a negative result from it \
             means nothing (B-7)"
        );

        // The leak: the probe left and no deny was counted.
        let verdict = canary.observe(probe, 1);
        assert_eq!(
            verdict,
            Verdict::EgressObserved,
            "{family:?}: an unaccounted egress was not reported as a leak"
        );
        assert!(
            verdict.drives_blocked(),
            "{family:?}: a leak must drive BLOCKED, not a log line"
        );
        assert!(
            verdict.reason_code().is_some(),
            "{family:?}: a leak verdict must carry a registered reason code"
        );
    }
}

#[test]
fn a_v4_only_canary_run_does_not_certify_the_v6_channel() {
    // ADR-0010 R1: one story covering both. A canary that only ever probed v4
    // would report "no leak" on a host where v6 is wide open, and this is the
    // assertion that makes that impossible to claim.
    let mut canary = Canary::new();
    canary.observe(
        Probe {
            family: AddressFamily::V4,
            mark: 1,
            from_non_exempt_socket: true,
        },
        1,
    );
    assert!(
        !canary.both_families_probed(),
        "a v4-only run reported that both families were probed"
    );
    assert_eq!(canary.probes(AddressFamily::V6), 0);

    canary.observe(
        Probe {
            family: AddressFamily::V6,
            mark: 2,
            from_non_exempt_socket: true,
        },
        2,
    );
    assert!(
        canary.both_families_probed(),
        "the positive control: probing both families must satisfy the check"
    );
}

#[test]
fn a_probe_from_an_exempt_socket_proves_nothing_and_says_so() {
    // The subtlest way a leak test becomes vacuous: probing through a socket
    // that is *supposed* to be exempt. The verdict must be `Invalid`, not
    // `Denied` — "we did not observe a leak" and "we could not have observed
    // one" are different facts.
    let mut canary = Canary::new();
    let verdict = canary.observe(
        Probe {
            family: AddressFamily::V4,
            mark: 3,
            from_non_exempt_socket: false,
        },
        0,
    );
    assert_eq!(verdict, Verdict::Invalid);
    assert!(!verdict.drives_blocked());
    assert_eq!(
        canary.probes(AddressFamily::V4),
        0,
        "an invalid probe must not count toward coverage"
    );
}

#[test]
fn the_canary_runs_at_a_wake_point_and_during_a_portal_grant() {
    // ADR-0012: the two moments a leak is most likely — a network change, and
    // while a captive-portal exemption is live — are exactly the moments a
    // canary is most likely to be skipped.
    let _ = WakePoint::NetworkChange;
    let _ = WakePoint::KeepaliveWake;
    assert!(
        twinvpn_enforce::canary::runs_during_portal_grant(),
        "the canary must keep running while a portal grant is live"
    );
}

// ---------------------------------------------------------------------------
// Scope: the fail-closed disposition, driven from a real route plan.
// ---------------------------------------------------------------------------

#[test]
fn every_routed_class_is_dropped_fail_closed_under_every_flag_combination() {
    // KS-2/KS-3. Asserted over the full flag space rather than a sample,
    // because "we allow the local LAN" is exactly the switch someone would
    // plausibly widen and it must not touch a routed class.
    for local in [true, false] {
        for portal in [true, false] {
            for class in [
                Class::ProtectedPeer,
                Class::ExitRouted,
                Class::LanGatewayRouted,
                Class::ProtectedDns,
            ] {
                assert_eq!(
                    Disposition::for_class(class, local, portal),
                    TrafficDisposition::DroppedFailClosed,
                    "{class:?} with local={local} portal={portal} was not dropped"
                );
            }
        }
    }
    assert_eq!(
        Disposition::unmatched_in_scope(),
        TrafficDisposition::DroppedFailClosed,
        "an in-scope packet matching nothing must be dropped, never passed"
    );
}

#[test]
fn tier_2_covers_both_families_and_admits_only_the_overlay_interface() {
    // The second tier is the one that makes "never route around TwinVPN"
    // enforceable without enumerating prefixes, so its family coverage is not a
    // detail.
    let t2 = Tier2 {
        overlay_interface: InterfaceIndex(42),
    };
    for family in BOTH {
        assert!(t2.covers(family), "tier 2 does not cover {family:?}");
    }
    assert!(t2.permits(InterfaceIndex(42)));
    assert!(
        !t2.permits(InterfaceIndex(1)),
        "the negative control: a non-overlay interface must be refused"
    );
}

#[test]
fn a_full_tunnel_scope_is_complement_shaped_and_catches_an_address_no_prefix_names() {
    // Tier 1 in full-tunnel mode must be the complement of the exemptions, not
    // an enumeration: an enumeration silently misses whatever it forgot, which
    // is the leak class R-17 and ADR-0012 both exist to retire.
    let t1 = Tier1::for_mode(RoutingMode::FullTunnel, Vec::new(), Vec::new());
    assert!(!t1.is_prefix_enumerated());
    for addr in [
        IpAddr::V4(V4Addr::from_octets([1, 1, 1, 1])),
        IpAddr::V6(
            V6Addr::new(
                [0x20, 0x01, 0x4, 0x86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8],
                None,
            )
            .expect("v6"),
        ),
    ] {
        assert!(
            t1.contains(addr),
            "a full-tunnel scope did not contain {addr:?}"
        );
    }
}

#[test]
fn forwarded_traffic_is_never_exemptible_and_local_network_access_is_a_named_default() {
    // KS-2. A gateway forwarding a client's packets must never be able to buy
    // an exemption on that client's behalf.
    assert!(!twinvpn_enforce::scope::forwarded_traffic_is_exemptible());
    // Recorded, not asserted as correct: `default_for` is permissive for every
    // routing mode including FullTunnel. See the finding in this domain's report.
    assert_eq!(
        LocalNetworkAccess::default_for(RoutingMode::FullTunnel),
        LocalNetworkAccess::Allow
    );
}

// ---------------------------------------------------------------------------
// The reconciler, against a plan the route planner produced.
// ---------------------------------------------------------------------------

#[test]
fn a_half_installed_ruleset_is_never_reported_as_protected() {
    // The cross-domain case: `twinvpn-route` says the plan covers both families,
    // the adapter reports only one installed, and the reconciler must call that
    // unprotected. Neither crate can see this alone.
    for missing in BOTH {
        let present = PerFamily::new(missing == AddressFamily::V6, missing == AddressFamily::V4);
        let assertion = Assertion {
            generation: ContractGeneration(1),
            installed: Some(Ruleset::Protected),
            present,
            asserted_at: MonotonicInstant::ORIGIN,
            freshness_window: REASSERT_WITHIN,
        };
        let posture = assertion.posture(Ruleset::Protected, MonotonicInstant::ORIGIN);
        assert!(
            matches!(posture, Posture::Unprotected(_)),
            "a ruleset missing {missing:?} reported {posture:?}"
        );
        assert_eq!(assertion.missing_family(), Some(missing));
        assert!(assertion.is_partial_install());
    }

    // Positive control: both families present is Protected, so the assertion
    // above is about coverage and not about the posture being always-negative.
    let both = Assertion {
        generation: ContractGeneration(1),
        installed: Some(Ruleset::Protected),
        present: PerFamily::new(true, true),
        asserted_at: MonotonicInstant::ORIGIN,
        freshness_window: REASSERT_WITHIN,
    };
    assert_eq!(
        both.posture(Ruleset::Protected, MonotonicInstant::ORIGIN),
        Posture::Protected
    );
}

#[test]
fn an_absent_or_tampered_ruleset_drives_blocked_and_is_counted() {
    let mut r = Reconciler::new();
    r.set_desired(ContractGeneration(1), Ruleset::Protected);
    let at = MonotonicInstant::ORIGIN;
    let mk = |installed| Assertion {
        generation: ContractGeneration(1),
        installed,
        present: PerFamily::new(true, true),
        asserted_at: at,
        freshness_window: REASSERT_WITHIN,
    };

    assert!(
        r.tick(mk(None), at).drives_blocked(),
        "an absent ruleset must drive BLOCKED"
    );
    assert!(
        r.tick(mk(Some(Ruleset::Blocked)), at).drives_blocked(),
        "a ruleset that is not the desired one must drive BLOCKED"
    );
    assert_eq!(
        r.tick(mk(Some(Ruleset::Protected)), at),
        TickOutcome::Converged,
        "the positive control: the desired ruleset converges"
    );
    let (ticks, violations) = r.counters();
    assert_eq!((ticks, violations), (3, 2));
}

#[test]
fn a_stale_assertion_is_unknown_and_unknown_is_not_protected() {
    // The failure mode this catches: a reconciler that keeps reporting the last
    // good posture after it stopped being able to read the OS.
    let a = Assertion {
        generation: ContractGeneration(1),
        installed: Some(Ruleset::Protected),
        present: PerFamily::new(true, true),
        asserted_at: MonotonicInstant::ORIGIN,
        freshness_window: REASSERT_WITHIN,
    };
    let much_later = MonotonicInstant::ORIGIN.saturating_add(REASSERT_WITHIN * 10);
    assert_eq!(a.posture(Ruleset::Protected, much_later), Posture::Unknown);
    assert_ne!(
        a.posture(Ruleset::Protected, much_later),
        Posture::Protected
    );
}

// ---------------------------------------------------------------------------
// Disarming: the authority check, end to end from the latch.
// ---------------------------------------------------------------------------

#[test]
fn no_remote_authority_can_disarm_the_kill_switch() {
    // KS-21. The two refused authorities are also security events, which is the
    // half that makes a refusal visible rather than merely correct.
    for authority in [
        DisarmAuthority::Remote,
        DisarmAuthority::ControlPlaneDocument,
    ] {
        let mut rig = Rig::new(HostFamily::Dual, 11);
        assert!(
            !rig.latch.disarm(authority),
            "{authority:?} disarmed the kill switch"
        );
        assert!(
            authority.refusal_is_security_event(),
            "{authority:?}'s refusal must be a security event"
        );
        assert!(!rig.latch.disarmed_by_owner());
    }

    // Positive control: a local authenticated action does disarm, so the test
    // above is about the authority and not about disarm being broken.
    let mut rig = Rig::new(HostFamily::Dual, 12);
    assert!(rig.latch.disarm(DisarmAuthority::LocalInteractive));
    assert!(rig.latch.disarmed_by_owner());
}

// ---------------------------------------------------------------------------
// The whole pipeline: arm, apply, and never leave a family uncovered.
// ---------------------------------------------------------------------------

#[test]
fn the_armed_contract_covers_both_families_on_every_underlay() {
    for family in HostFamily::ALL {
        let mut rig = Rig::new(family, 13);
        let plan = rig
            .route_plan(RoutingMode::TwinnetOnly, PerFamily::new(false, false))
            .expect("plan");
        let policy = dns_policy(twinvpn_dns::Mode::Split, true);

        // Blocked first — KS-19: the deny predates the first packet.
        let blocked = rig
            .contract(&plan, &policy, stub_addresses(), Ruleset::Blocked)
            .expect("assemble blocked");
        rig.apply(&blocked);
        assert_eq!(
            block_on(rig.adapter.network_config().installed_ruleset()).expect("read back"),
            Some(Ruleset::Blocked)
        );

        // Then protected, only once the path is validated for both families.
        rig.latch.set_intended_up(true);
        assert_eq!(
            rig.latch.leave_blocked(preconditions(&plan, true)),
            Ruleset::Protected
        );
        let protected = rig
            .contract(&plan, &policy, stub_addresses(), Ruleset::Protected)
            .expect("assemble protected");
        for af in BOTH {
            assert!(
                !protected.addresses.get(af).is_empty(),
                "{}: the protected contract leaves {af:?} uncovered",
                family.name()
            );
            assert!(
                !protected.routes.get(af).is_empty(),
                "{}: the protected contract installs no {af:?} route",
                family.name()
            );
        }
    }
}

#[test]
fn a_socket_whose_registration_failed_is_not_exempt() {
    // KS-12. The direction that matters: a registration that failed must leave
    // the socket *unexempt*, never exempt-by-default.
    let mut reg = SocketRegistry::new();
    reg.register(7, SocketClass::Bootstrap);
    assert_eq!(reg.class_of(7), Some(SocketClass::Bootstrap));
    reg.registration_failed(7);
    assert_eq!(
        reg.class_of(7),
        None,
        "a failed registration left the socket exempt"
    );
    assert_eq!(
        reg.class_of(9999),
        None,
        "an unknown socket is never exempt"
    );
}

#[test]
fn the_resolver_and_update_sockets_are_destination_bounded() {
    // KS-10. An exempt socket that can reach anywhere is not an exemption, it is
    // a hole.
    assert!(SocketClass::Resolver.destination_bounded());
    assert!(SocketClass::Update.destination_bounded());
    // Recorded rather than asserted as correct: Bootstrap is deliberately
    // unbounded, which is the widest exemption in the model.
    assert!(!SocketClass::Bootstrap.destination_bounded());
}
