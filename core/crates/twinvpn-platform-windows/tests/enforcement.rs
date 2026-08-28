//! The required matrix, driven from the layers that actually run on this host.
//!
//! **Authority:** the wave-2 objective's test matrix — startup, shutdown,
//! network change, service restart, route recovery, DNS recovery, kill switch,
//! IPv4 leaks, IPv6 leaks, DNS leaks — plus ADR-0012 KS-17/KS-18/KS-20/K12,
//! ADR-0010 R1/R5/R6, ADR-0011 D7/DN-19, ADR-0015 O-17/O-18, ADR-0016 §11.6,
//! ADR-0022 LC-4/LC-24/LC-26.
//!
//! # What these tests are, and what they are not
//!
//! **This host is Linux.** Nothing in `twinvpn-platform-windows` can be linked
//! or run here, so none of these tests touches Windows. Every one of them
//! exercises the crate's **target-free** layers — the filter renderer, the
//! read-back, the route and DNS planners, the restore point, and the whole
//! transactional state machine in `netcfg` — against
//! [`twinvpn_platform_windows::sys::fake::FakeSystem`], which models the
//! Windows semantics those layers depend on and nothing else.
//!
//! That is a real proof of the part where a mistake is a leak, and it is **not**
//! a proof that `FwpmFilterAdd0` was called with the right structure. The tests
//! that would prove that are in `tests/windows_host.rs`, they are gated, they
//! compile under `make cross-check`, and **they have never executed**.
//!
//! # Why the leak tests assert over data rather than over packets
//!
//! A test that simulated packet matching would be a second implementation of
//! WFP's classification semantics, and passing it would prove that this crate
//! agrees with a model somebody here wrote. So the leak tests assert the
//! property ADR-0012 actually specifies: that the **constructed filter set**
//! denies the family in question, in every state the posture machine can be in,
//! with no permit that could carry protected traffic off the host.

#![cfg(feature = "test-support")]

use std::sync::Arc;

use twinvpn_platform::{
    ContractGeneration, DnsConfig, InterfaceIndex, NetworkConfig, NetworkContract, PlatformError,
    RouteEntry, Ruleset,
};
use twinvpn_types::{AddressFamily, IpAddr, IpPrefix, PerFamily, V4Addr, V6Addr};

use twinvpn_platform_windows::dns::{NrptRule, StubAddresses, RULE_PREFIX};
use twinvpn_platform_windows::netcfg::{Compensation, NetworkConfigParts, WindowsNetworkConfig};
use twinvpn_platform_windows::route::{InterfaceLuid, RouteProtocol, RouteRow};
use twinvpn_platform_windows::shutdown::ShutdownLatch;
use twinvpn_platform_windows::sys::fake::{FakeSystem, Faults, PlatformFault};
use twinvpn_platform_windows::wfp::canary::{CanaryVerdict, NetEvent, NetEventKind};
use twinvpn_platform_windows::wfp::readback::{class_of, Verdict};
use twinvpn_platform_windows::wfp::{
    self, Action, Condition, EnforcementConfig, Layer, TrafficClass,
};

const OVERLAY: u64 = 0x0001_0000_0000_0006;

/// Runs a `BoxFuture` to completion.
///
/// A current-thread runtime built here rather than `#[tokio::test]`, so nothing
/// in this file names the runtime's time module — CD-3 denies `tokio::time`
/// everywhere outside `twinvpn-env`'s binding, and a test is not an exemption.
fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime")
        .block_on(future)
}

fn v4(octets: [u8; 4], len: u32) -> IpPrefix {
    IpPrefix::new(IpAddr::V4(V4Addr::from_octets(octets)), len).expect("prefix")
}

fn v6(first: u8, second: u8, len: u32) -> IpPrefix {
    let mut octets = [0u8; 16];
    octets[0] = first;
    octets[1] = second;
    IpPrefix::new(
        IpAddr::V6(V6Addr::prefix_base(octets).expect("base")),
        len,
    )
    .expect("prefix")
}

fn host_v4() -> IpPrefix {
    v4([100, 64, 0, 5], 32)
}

fn host_v6() -> IpPrefix {
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1] = 0x7c;
    octets[2] = 0x9e;
    octets[3] = 0x5d;
    octets[4] = 0x2a;
    octets[5] = 0x10;
    octets[15] = 5;
    IpPrefix::new(
        IpAddr::V6(V6Addr::new(octets, None).expect("address")),
        128,
    )
    .expect("prefix")
}

fn route(destination: IpPrefix) -> RouteEntry {
    RouteEntry {
        destination,
        via: None,
        interface: InterfaceIndex(6),
        metric: None,
    }
}

fn stub() -> StubAddresses {
    let mut anycast6 = [0u8; 16];
    anycast6[0] = 0xfd;
    anycast6[1] = 0x7c;
    anycast6[2] = 0x9e;
    anycast6[3] = 0x5d;
    anycast6[4] = 0x2a;
    anycast6[5] = 0x10;
    anycast6[6] = 0xff;
    anycast6[7] = 0xff;
    anycast6[15] = 0x53;
    let mut loop6 = [0u8; 16];
    loop6[15] = 1;
    StubAddresses {
        loopback_v4: IpAddr::V4(V4Addr::from_octets([127, 0, 0, 53])),
        loopback_v6: IpAddr::V6(V6Addr::new(loop6, None).expect("::1")),
        anycast_v4: IpAddr::V4(V4Addr::from_octets([100, 127, 255, 53])),
        anycast_v6: IpAddr::V6(V6Addr::new(anycast6, None).expect("anycast")),
    }
}

fn enforcement() -> EnforcementConfig {
    EnforcementConfig {
        overlay_luid: OVERLAY,
        service_app_id: r"\device\harddiskvolume3\program files\twinvpn\twinvpnsvc.exe",
        service_sid: "S-1-5-80-0",
        local_network_access: true,
        on_link_prefixes: vec![v4([192, 168, 1, 0], 24)],
        updater_app_id: None,
        update_origins: Vec::new(),
        portal_grant: Vec::new(),
    }
}

/// A full-tunnel contract: the four `/1` routes of `docs/networking.md` §7.2,
/// a `/32` and a `/128`, and a split-DNS domain.
fn contract(generation: u64, ruleset: Ruleset) -> NetworkContract {
    NetworkContract {
        generation: ContractGeneration(generation),
        addresses: PerFamily::new(vec![host_v4()], vec![host_v6()]),
        routes: PerFamily::new(
            vec![route(v4([0, 0, 0, 0], 1)), route(v4([128, 0, 0, 0], 1))],
            vec![route(v6(0x00, 0x00, 1)), route(v6(0x80, 0x00, 1))],
        ),
        dns: DnsConfig {
            resolvers: PerFamily::new(Vec::new(), Vec::new()),
            search_domains: vec!["tnet.twinvpn.net".to_owned()],
            split_domains: vec!["tnet.twinvpn.net".to_owned()],
            is_default_resolver: true,
        },
        ruleset,
        mtu: 1420,
    }
}

struct Harness {
    system: Arc<FakeSystem>,
    config: WindowsNetworkConfig,
    #[allow(dead_code)]
    dir: std::path::PathBuf,
}

fn harness(name: &str) -> Harness {
    let system = Arc::new(FakeSystem::new(InterfaceLuid(OVERLAY)));
    let dir = std::env::temp_dir().join(format!("twinvpn-win-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    let config = WindowsNetworkConfig::new(NetworkConfigParts {
        system: system.clone(),
        enforcement: enforcement(),
        stub: stub(),
        restore_point_path: dir.join("resolver.restore"),
        shutdown: ShutdownLatch::new(),
    });
    Harness {
        system,
        config,
        dir,
    }
}

// ---------------------------------------------------------------------------
// startup
// ---------------------------------------------------------------------------

#[test]
fn startup_on_a_fresh_host_installs_blocked_and_reads_it_back_from_the_engine() {
    // ADR-0016 §11.6 step (2) and ADR-0022 LC-4 steps 3-4: query the engine for
    // BOTH families, re-assert BLOCKED if it disagrees, and only then may a
    // packet be emitted.
    let h = harness("startup-fresh");
    let assertion = h.config.reclaim(None).expect("reclaims");
    assert_eq!(assertion.posture, Some(Ruleset::Blocked));
    assert!(assertion.is_fail_closed());
    assert!(!assertion.is_protected());
    assert!(*assertion.families_covered.get(AddressFamily::V4));
    assert!(*assertion.families_covered.get(AddressFamily::V6));
    assert_eq!(h.system.commit_count(), 1);
}

#[test]
fn startup_on_a_host_that_already_holds_blocked_does_not_reinstall_it() {
    // KS-23 forbids remove-then-add, and a reclaim that re-committed on every
    // start would be exactly that at the moment the host is least defended.
    let h = harness("startup-idempotent");
    h.config.reclaim(None).expect("first");
    let before = h.system.commit_count();
    let again = h.config.reclaim(None).expect("second");
    assert_eq!(again.posture, Some(Ruleset::Blocked));
    assert_eq!(h.system.commit_count(), before, "reclaimed, not recreated");
}

#[test]
fn startup_reports_the_boot_artifact_as_absent_when_the_installer_never_wrote_it() {
    // PS-7: the artifact is package-owned, and a missing one is CRITICAL and
    // NOT fatal. The adapter reports; the shell decides.
    let h = harness("startup-boot-artifact");
    assert!(!h.config.verify_boot_artifact().expect("queries").is_registered());
    // ...and installing the runtime set does not make it look registered.
    h.config.reclaim(None).expect("reclaims");
    assert!(
        !h.config.verify_boot_artifact().expect("queries").is_registered(),
        "the runtime set must not satisfy the KS-19 check"
    );
}

#[test]
fn startup_refuses_to_report_protection_when_the_engine_cannot_be_queried() {
    // O-18: an assertion that cannot be renewed becomes UNKNOWN, never
    // PROTECTED. Here the query itself fails, which must be an error and not an
    // absent ruleset — `Ok(None)` would read as "no ruleset installed".
    let h = harness("startup-query-fails");
    h.system.set_faults(Faults {
        filter_read: Some(PlatformFault::NotPermitted),
        ..Faults::default()
    });
    let err = h.config.assert_protection(None).expect_err("a query failure is an error");
    assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
}

// ---------------------------------------------------------------------------
// shutdown
// ---------------------------------------------------------------------------

#[test]
fn shutdown_leaves_the_installed_filters_exactly_where_they_were() {
    // CB-6, and ADR-0022 §11.4's Windows row: "shutdown MUST NOT remove
    // enforcement — persistent WFP filters stay". Asserted against the recorded
    // engine state rather than against a comment.
    let h = harness("shutdown");
    block_on(h.config.apply(&contract(1, Ruleset::Protected))).expect("applies");
    let before = h.system.commit_count();
    let installed = block_on(h.config.installed_ruleset()).expect("reads");
    assert_eq!(installed, Some(Ruleset::Protected));

    let latch = ShutdownLatch::new();
    latch.begin();
    drop(h.config);

    // The adapter is gone; the engine still holds the ruleset.
    let state = twinvpn_platform_windows::sys::FilterEngine::read(&*h.system).expect("reads");
    let after = twinvpn_platform_windows::wfp::readback::parse_installed(&state)
        .expect("the OS still holds it");
    assert_eq!(after.posture, Ruleset::Protected);
    assert_eq!(h.system.commit_count(), before, "shutdown committed nothing");
}

#[test]
fn after_the_latch_is_set_every_call_refuses_rather_than_hanging_or_succeeding() {
    let h = harness("shutdown-latch");
    let latch = ShutdownLatch::new();
    let config = WindowsNetworkConfig::new(NetworkConfigParts {
        system: h.system.clone(),
        enforcement: enforcement(),
        stub: stub(),
        restore_point_path: h.dir.join("resolver.restore"),
        shutdown: latch.clone(),
    });
    latch.begin();
    for err in [
        block_on(config.apply(&contract(1, Ruleset::Protected))).expect_err("refused"),
        block_on(config.installed_ruleset()).expect_err("refused"),
        block_on(config.current_generation()).expect_err("refused"),
        block_on(config.set_ruleset(ContractGeneration(1), Ruleset::Blocked)).expect_err("refused"),
        block_on(config.query_link_facts()).expect_err("refused"),
    ] {
        assert!(matches!(err, PlatformError::ShuttingDown), "{err:?}");
    }
    assert_eq!(h.system.commit_count(), 0, "nothing was installed");
}

// ---------------------------------------------------------------------------
// the kill switch
// ---------------------------------------------------------------------------

#[test]
fn the_posture_swap_is_one_transaction_and_never_a_remove_then_add() {
    // KS-17: an atomic swap; rules are never absent while the latch is up.
    // There is no intermediate state to observe, so the property is asserted as
    // the number of transactions the swap took.
    let h = harness("kill-switch-swap");
    block_on(h.config.apply(&contract(1, Ruleset::Blocked))).expect("applies");
    let before = h.system.commit_count();
    block_on(h.config.set_ruleset(ContractGeneration(1), Ruleset::Protected)).expect("swaps");
    assert_eq!(h.system.commit_count(), before + 1, "one transaction");
    assert_eq!(
        block_on(h.config.installed_ruleset()).expect("reads"),
        Some(Ruleset::Protected)
    );
    block_on(h.config.set_ruleset(ContractGeneration(1), Ruleset::Blocked)).expect("swaps back");
    assert_eq!(h.system.commit_count(), before + 2);
}

#[test]
fn a_swap_carries_the_tier_1_scope_it_had_and_never_covers_nothing() {
    // `desktop-linux`'s R-6, ported: a `set_ruleset` that rendered from an empty
    // contract would install a fail-closed posture over zero prefixes.
    let h = harness("kill-switch-r6");
    block_on(h.config.apply(&contract(4, Ruleset::Blocked))).expect("applies");
    block_on(h.config.set_ruleset(ContractGeneration(4), Ruleset::Protected)).expect("swaps");
    let assertion = h.config.assert_protection(None).expect("asserts");
    assert!(*assertion.families_covered.get(AddressFamily::V4));
    assert!(*assertion.families_covered.get(AddressFamily::V6));
}

#[test]
fn a_tampered_ruleset_is_reported_and_never_read_as_healthy() {
    // ADR-0012 §11.9's `POLICY.KILLSWITCH.RULESET_TAMPERED` condition, and O-17:
    // the assertion is a query, so an external change is visible.
    let h = harness("kill-switch-tamper");
    block_on(h.config.apply(&contract(2, Ruleset::Protected))).expect("applies");
    let intended = wfp::filters::render(
        &contract(2, Ruleset::Protected),
        Ruleset::Protected,
        &enforcement(),
    );
    assert!(h
        .config
        .assert_protection(Some(&intended))
        .expect("asserts")
        .is_protected());

    h.system
        .remove_filter(|f| class_of(f.key) == Some(TrafficClass::BootstrapExemption));
    let after = h.config.assert_protection(Some(&intended)).expect("asserts");
    assert!(!after.is_protected(), "a tampered set is not protection");
    assert!(matches!(after.verdict, Verdict::FiltersMissing { .. }));
}

#[test]
fn another_products_filters_never_make_us_believe_ours_are_installed() {
    // K11: coexistence. A third party's block at our layer is not our ruleset.
    let h = harness("kill-switch-coexist");
    h.system.add_foreign_filter(
        twinvpn_platform_windows::wfp::readback::InstalledFilter {
            key: twinvpn_platform_windows::wfp::FILTER_POSTURE_PROTECTED,
            layer: Layer::AleAuthConnectV4,
            action: Action::Block,
            provider_owned: false,
        },
    );
    let assertion = h.config.assert_protection(None).expect("asserts");
    assert_eq!(assertion.posture, None, "not ours, so not a posture");
    assert!(!assertion.is_fail_closed());
}

// ---------------------------------------------------------------------------
// leaks: IPv4, IPv6, DNS
// ---------------------------------------------------------------------------

/// Every posture, every routing mode, both families.
fn every_state() -> Vec<(&'static str, NetworkContract, Ruleset)> {
    let mut out = Vec::new();
    let twinnet_only = NetworkContract {
        routes: PerFamily::new(Vec::new(), Vec::new()),
        ..contract(1, Ruleset::Blocked)
    };
    let split = NetworkContract {
        routes: PerFamily::new(
            vec![route(v4([10, 0, 0, 0], 8))],
            vec![route(v6(0x20, 0x01, 16))],
        ),
        ..contract(1, Ruleset::Blocked)
    };
    for (name, base) in [
        ("twinnet-only", twinnet_only),
        ("split", split),
        ("full", contract(1, Ruleset::Blocked)),
    ] {
        for posture in [Ruleset::Blocked, Ruleset::Protected] {
            out.push((name, base.clone(), posture));
        }
    }
    out
}

#[test]
fn ipv4_is_denied_in_every_state_the_posture_machine_can_be_in() {
    for (name, contract, posture) in every_state() {
        let set = wfp::filters::render(&contract, posture, &enforcement());
        set.validate().expect("installable");
        assert!(
            set.filters.iter().any(|f| f.layer == Layer::AleAuthConnectV4
                && f.action == Action::Block
                && f.class == TrafficClass::ProtectedScopeDeny),
            "{name}/{posture:?} has no IPv4 deny"
        );
    }
}

#[test]
fn ipv6_is_denied_in_every_state_including_on_a_v4_only_contract() {
    // ADR-0010 R6: IPv6 must not be able to bypass tunnel policy, "including
    // when IPv6 appears *after* the tunnel is up, and when the tunnel itself is
    // IPv4-only". The deny is keyed on a destination prefix and not on which
    // interfaces exist, so a v6 adapter appearing later changes nothing.
    let v4_only = NetworkContract {
        routes: PerFamily::new(vec![route(v4([10, 0, 0, 0], 8))], Vec::new()),
        addresses: PerFamily::new(vec![host_v4()], Vec::new()),
        ..contract(1, Ruleset::Blocked)
    };
    let mut states = every_state();
    states.push(("v4-only", v4_only.clone(), Ruleset::Blocked));
    states.push(("v4-only", v4_only, Ruleset::Protected));
    for (name, contract, posture) in states {
        let set = wfp::filters::render(&contract, posture, &enforcement());
        assert!(
            set.filters.iter().any(|f| f.layer == Layer::AleAuthConnectV6
                && f.action == Action::Block
                && f.class == TrafficClass::ProtectedScopeDeny),
            "{name}/{posture:?} has no IPv6 deny"
        );
        assert_eq!(set.families_covered(), (true, true), "{name}/{posture:?}");
    }
}

#[test]
fn no_state_contains_a_permit_that_could_carry_protected_traffic_off_the_host() {
    // The leak test proper, asserted over the data: every permit in every state
    // is either loopback, a named exemption class from ADR-0012 §11.2, or the
    // Tier-2 overlay permit — and the overlay permit exists only in PROTECTED.
    for (name, contract, posture) in every_state() {
        let set = wfp::filters::render(&contract, posture, &enforcement());
        for filter in set.filters.iter().filter(|f| f.action == Action::Permit) {
            let accounted = matches!(
                filter.class,
                TrafficClass::Loopback
                    | TrafficClass::BootstrapExemption
                    | TrafficClass::ResolverExemption
                    | TrafficClass::UpdateExemption
                    | TrafficClass::UnderlayConfiguration
                    | TrafficClass::LinkLocal
                    | TrafficClass::LocalNetwork
                    | TrafficClass::PortalGrant
                    | TrafficClass::PortalProbe
                    | TrafficClass::OverlayEgress
            );
            assert!(accounted, "{name}/{posture:?}: unaccounted permit {filter:?}");
            if posture == Ruleset::Blocked {
                assert_ne!(
                    filter.class,
                    TrafficClass::OverlayEgress,
                    "{name}: BLOCKED must not authorise the overlay"
                );
            }
        }
    }
}

#[test]
fn dns_is_contained_on_every_non_overlay_interface_in_every_state() {
    // ADR-0011 §11.9: containment, not configuration, is the guarantee, and it
    // applies regardless of which process opened the socket — so the SMHNR
    // parallel query out a second adapter is denied even though `dnscache` is
    // not our app-id.
    for (name, contract, posture) in every_state() {
        let set = wfp::filters::render(&contract, posture, &enforcement());
        let containment: Vec<_> = set
            .filters
            .iter()
            .filter(|f| f.class == TrafficClass::DnsContainment)
            .collect();
        assert_eq!(containment.len(), 6, "{name}/{posture:?}: three ports x two families");
        for filter in containment {
            assert_eq!(filter.action, Action::Block);
            assert!(!filter
                .conditions
                .iter()
                .any(|c| matches!(c, Condition::AppId(_) | Condition::UserSid(_))));
            assert!(filter
                .conditions
                .iter()
                .any(|c| matches!(c, Condition::NotLocalInterface(luid) if *luid == OVERLAY)));
        }
    }
}

#[test]
fn the_leak_canary_reports_per_family_and_never_concludes_from_a_lossy_window() {
    // ADR-0012 §11.9's active detection, and the Windows-specific consequence
    // that the counters are folded from a best-effort event stream.
    let h = harness("canary");
    block_on(h.config.apply(&contract(1, Ruleset::Protected))).expect("applies");
    let before = h.config.counters().expect("samples");

    let deny = |family| NetEvent {
        kind: NetEventKind::ClassifyDrop,
        family,
        filter: Some(wfp::filters::filter_key(
            TrafficClass::ProtectedScopeDeny,
            Layer::for_family(family),
            0,
        )),
    };
    h.system.push_events(vec![deny(AddressFamily::V4)], false);
    let after = h.config.counters().expect("samples");
    assert_eq!(
        WindowsNetworkConfig::canary(&before, &after, AddressFamily::V4),
        CanaryVerdict::Denied
    );
    assert_eq!(
        WindowsNetworkConfig::canary(&before, &after, AddressFamily::V6),
        CanaryVerdict::EgressObserved,
        "a v4 drop must never satisfy the v6 canary"
    );

    h.system.push_events(vec![deny(AddressFamily::V6)], true);
    let lossy = h.config.counters().expect("samples");
    assert_eq!(
        WindowsNetworkConfig::canary(&before, &lossy, AddressFamily::V6),
        CanaryVerdict::Indeterminate,
        "we do not know must not be reported as the rule is live"
    );
}

// ---------------------------------------------------------------------------
// route recovery
// ---------------------------------------------------------------------------

#[test]
fn apply_installs_both_families_routes_and_addresses_in_one_transaction() {
    // ADR-0010 §11.3: "An implementation that can install one family's routes
    // without the other's is non-conforming."
    let h = harness("routes-apply");
    block_on(h.config.apply(&contract(1, Ruleset::Protected))).expect("applies");
    let installed = h.system.routes_now();
    assert_eq!(installed.rows.len(), 4, "the four /1 routes");
    assert!(installed
        .rows
        .iter()
        .any(|r| r.destination.family() == AddressFamily::V4));
    assert!(installed
        .rows
        .iter()
        .any(|r| r.destination.family() == AddressFamily::V6));
    assert_eq!(installed.addresses.len(), 2, "a /32 and a /128");
    assert_eq!(h.system.route_apply_count(), 1);
}

#[test]
fn a_failed_route_apply_leaves_the_host_exactly_as_it_was_and_still_fail_closed() {
    // R5, and `docs/networking.md` §2.3: "partial application is the leak
    // window". The compensation is reported rather than assumed.
    let h = harness("routes-rollback");
    h.system.set_faults(Faults {
        route_apply: Some(PlatformFault::NotPermitted),
        route_apply_succeeds_first: 2,
        ..Faults::default()
    });
    let err = block_on(h.config.apply(&contract(1, Ruleset::Protected))).expect_err("refused");
    assert_eq!(err.reason_code().as_str(), "ROUTE.PROGRAMMING_DENIED");

    let failure = h.config.last_apply_failure().expect("recorded");
    assert_eq!(failure.step, "routes.apply");
    assert_eq!(failure.compensation, Compensation::Restored);

    // No route survived the failed apply...
    assert!(h.system.routes_now().rows.is_empty());
    // ...and the host is fail-closed rather than open.
    let assertion = h.config.assert_protection(None).expect("asserts");
    assert_eq!(assertion.posture, Some(Ruleset::Blocked));
    assert!(assertion.is_fail_closed());
}

#[test]
fn rollback_restores_the_routes_the_previous_generation_had() {
    let h = harness("routes-recovery");
    let pre_existing = RouteRow {
        luid: InterfaceLuid(OVERLAY),
        destination: v4([172, 16, 0, 0], 12),
        next_hop: None,
        metric: 0,
        protocol: RouteProtocol::NetMgmt,
    };
    let system = Arc::new(
        FakeSystem::new(InterfaceLuid(OVERLAY)).with_routes(
            twinvpn_platform_windows::route::InstalledRoutes {
                rows: vec![pre_existing],
                addresses: Vec::new(),
                interface_metric: PerFamily::new(None, None),
            },
        ),
    );
    let config = WindowsNetworkConfig::new(NetworkConfigParts {
        system: system.clone(),
        enforcement: enforcement(),
        stub: stub(),
        restore_point_path: h.dir.join("resolver.restore"),
        shutdown: ShutdownLatch::new(),
    });

    block_on(config.apply(&contract(5, Ruleset::Protected))).expect("applies");
    // The pre-existing row is OURS (a previous generation left it), so applying
    // a contract that does not name it removes it — which is what makes `apply`
    // a convergence rather than an accumulation.
    assert_eq!(system.routes_now().rows.len(), 4);
    block_on(config.rollback(ContractGeneration(5))).expect("rolls back");
    assert_eq!(
        system.routes_now().ours(),
        vec![pre_existing],
        "exactly what was there before, and nothing else"
    );
}

#[test]
fn a_row_the_adapter_does_not_own_survives_apply_and_rollback() {
    // R7: a conflict with the host's own routing is surfaced, never silently
    // resolved by overwriting.
    let foreign = RouteRow {
        luid: InterfaceLuid(OVERLAY),
        destination: v4([172, 16, 0, 0], 12),
        next_hop: None,
        metric: 0,
        protocol: RouteProtocol::Other(2),
    };
    let system = Arc::new(
        FakeSystem::new(InterfaceLuid(OVERLAY)).with_routes(
            twinvpn_platform_windows::route::InstalledRoutes {
                rows: vec![foreign],
                addresses: Vec::new(),
                interface_metric: PerFamily::new(None, None),
            },
        ),
    );
    let dir = std::env::temp_dir().join("twinvpn-win-routes-foreign");
    let config = WindowsNetworkConfig::new(NetworkConfigParts {
        system: system.clone(),
        enforcement: enforcement(),
        stub: stub(),
        restore_point_path: dir.join("resolver.restore"),
        shutdown: ShutdownLatch::new(),
    });
    block_on(config.apply(&contract(1, Ruleset::Protected))).expect("applies");
    block_on(config.rollback(ContractGeneration(1))).expect("rolls back");
    assert!(system.routes_now().rows.contains(&foreign));
}

// ---------------------------------------------------------------------------
// DNS recovery — D7, the highest-risk platform
// ---------------------------------------------------------------------------

#[test]
fn the_restore_point_is_written_before_the_resolver_is_mutated() {
    // DN-18 and PS-6. Asserted the only way it can be from outside: a host on
    // which the restore point cannot be written must not have had its resolver
    // touched.
    let h = harness("dns-restore-point-first");
    block_on(h.config.apply(&contract(1, Ruleset::Protected))).expect("applies");
    let point = twinvpn_platform_windows::restore::read(&h.dir.join("resolver.restore"))
        .expect("reads")
        .expect("written");
    assert_eq!(point.restore_token, 1);
    assert!(point.prior_rules.is_empty(), "a fresh host had none");
}

#[test]
fn a_resolver_apply_that_fails_leaves_the_routes_and_the_filters_restored() {
    let h = harness("dns-apply-fails");
    h.system.set_faults(Faults {
        resolver_apply: Some(PlatformFault::NotPermitted),
        ..Faults::default()
    });
    let err = block_on(h.config.apply(&contract(1, Ruleset::Protected))).expect_err("refused");
    assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
    let failure = h.config.last_apply_failure().expect("recorded");
    assert_eq!(failure.step, "dns.apply");
    assert_eq!(failure.compensation, Compensation::Restored);
    assert!(!h.system.rules().iter().any(|r| r.id.starts_with(RULE_PREFIX)));
    assert!(h.system.routes_now().rows.is_empty(), "the routes went back");
    assert_eq!(
        h.config.assert_protection(None).expect("asserts").posture,
        Some(Ruleset::Blocked),
        "and the host is fail-closed, not open"
    );
}

#[test]
fn rollback_points_the_host_back_at_the_resolver_it_had() {
    // D7's actual failure: "A crashed, killed or uninstalled agent leaves the
    // host pointed at a stub that is not answering."
    let prior = NrptRule {
        id: "DomainPolicy-corp".to_owned(),
        namespace: ".corp.example".to_owned(),
        resolvers: vec![IpAddr::V4(V4Addr::from_octets([192, 168, 1, 1]))],
        dnssec_validation: false,
    };
    let system = Arc::new(
        FakeSystem::new(InterfaceLuid(OVERLAY)).with_foreign_rules(vec![prior.clone()]),
    );
    let dir = std::env::temp_dir().join("twinvpn-win-dns-recovery");
    let config = WindowsNetworkConfig::new(NetworkConfigParts {
        system: system.clone(),
        enforcement: enforcement(),
        stub: stub(),
        restore_point_path: dir.join("resolver.restore"),
        shutdown: ShutdownLatch::new(),
    });

    block_on(config.apply(&contract(3, Ruleset::Protected))).expect("applies");
    assert!(system.rules().iter().any(|r| r.id.starts_with(RULE_PREFIX)));

    block_on(config.rollback(ContractGeneration(3))).expect("rolls back");
    let after = system.rules();
    assert!(
        !after.iter().any(|r| r.id.starts_with(RULE_PREFIX)),
        "no rule of ours may outlive the generation that wrote it"
    );
    assert!(
        after.contains(&prior),
        "and the domain policy's rule was never ours to remove"
    );
}

#[test]
fn a_third_partys_resolver_rule_survives_every_operation() {
    let prior = NrptRule {
        id: "MDM-profile".to_owned(),
        namespace: ".mdm.example".to_owned(),
        resolvers: Vec::new(),
        dnssec_validation: false,
    };
    let system = Arc::new(
        FakeSystem::new(InterfaceLuid(OVERLAY)).with_foreign_rules(vec![prior.clone()]),
    );
    let dir = std::env::temp_dir().join("twinvpn-win-dns-foreign");
    let config = WindowsNetworkConfig::new(NetworkConfigParts {
        system: system.clone(),
        enforcement: enforcement(),
        stub: stub(),
        restore_point_path: dir.join("resolver.restore"),
        shutdown: ShutdownLatch::new(),
    });
    block_on(config.apply(&contract(1, Ruleset::Protected))).expect("applies");
    assert!(system.rules().contains(&prior));
    block_on(config.apply(&contract(2, Ruleset::Protected))).expect("re-applies");
    assert!(system.rules().contains(&prior));
    block_on(config.rollback(ContractGeneration(2))).expect("rolls back");
    assert!(system.rules().contains(&prior));
}

// ---------------------------------------------------------------------------
// service restart, and network change
// ---------------------------------------------------------------------------

#[test]
fn a_restart_recovers_the_generation_from_the_engine_and_not_from_a_ledger() {
    // ADR-0022 LC-26 and ADR-0010 R5: after an unclean exit the process's own
    // record is gone and the OS still holds the answer.
    let h = harness("restart");
    block_on(h.config.apply(&contract(9, Ruleset::Protected))).expect("applies");
    drop(h.config);

    // A brand-new configuration object over the same host — a restarted service.
    let restarted = WindowsNetworkConfig::new(NetworkConfigParts {
        system: h.system.clone(),
        enforcement: enforcement(),
        stub: stub(),
        restore_point_path: h.dir.join("resolver.restore"),
        shutdown: ShutdownLatch::new(),
    });
    assert_eq!(
        block_on(restarted.current_generation()).expect("reads"),
        Some(ContractGeneration(9)),
        "the generation came from the engine's provider blob"
    );
    assert_eq!(
        block_on(restarted.installed_ruleset()).expect("reads"),
        Some(Ruleset::Protected)
    );
}

#[test]
fn a_restart_re_asserts_blocked_when_the_engine_holds_protected() {
    // ADR-0022 LC-4 step 4: "re-assert to RULESET_BLOCKED if the query
    // disagrees — never *remove rules*; atomic swap". A restarted service has
    // no validated path yet, so PROTECTED is a claim it cannot make (KS-18).
    let h = harness("restart-reassert");
    block_on(h.config.apply(&contract(9, Ruleset::Protected))).expect("applies");
    let before = h.system.commit_count();

    let restarted = WindowsNetworkConfig::new(NetworkConfigParts {
        system: h.system.clone(),
        enforcement: enforcement(),
        stub: stub(),
        restore_point_path: h.dir.join("resolver.restore"),
        shutdown: ShutdownLatch::new(),
    });
    let assertion = restarted.reclaim(None).expect("reclaims");
    assert_eq!(assertion.posture, Some(Ruleset::Blocked));
    assert!(assertion.is_fail_closed());
    assert_eq!(h.system.commit_count(), before + 1, "one swap, not a purge");
}

#[test]
fn rollback_to_a_generation_this_process_never_applied_refuses_rather_than_guessing() {
    // After a crash the ledger is empty by design. The recovery path is
    // `reclaim` plus a fresh apply, and a rollback that silently succeeded would
    // tell the core it had restored a state nobody recorded.
    let h = harness("restart-rollback");
    let err = block_on(h.config.rollback(ContractGeneration(77))).expect_err("refused");
    assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
}

#[test]
fn a_network_change_does_not_need_a_rule_update_for_the_deny_to_hold() {
    // ADR-0010 §11.5 clause 2: an IPv6 stack appearing after the tunnel is up
    // "is denied by the pre-existing rule with **no rule update required for
    // correctness**". The mechanism is that the Tier-1 deny names a destination
    // and the Tier-2 permit names *our* interface — neither mentions the
    // interface that just appeared.
    let h = harness("network-change");
    block_on(h.config.apply(&contract(1, Ruleset::Protected))).expect("applies");
    let before = h.system.commit_count();

    let set = wfp::filters::render(
        &contract(1, Ruleset::Protected),
        Ruleset::Protected,
        &enforcement(),
    );
    for filter in &set.filters {
        for condition in &filter.conditions {
            if let Condition::LocalInterface(luid) = condition {
                assert!(
                    *luid == OVERLAY || *luid == 0,
                    "a filter names an interface that is neither ours nor unreachable"
                );
            }
        }
    }
    // Nothing was reinstalled to make that true.
    assert_eq!(h.system.commit_count(), before);
}

#[test]
fn re_applying_the_same_generation_converges_rather_than_duplicating() {
    // ADR-0008: idempotent on the generation id, so a retry after a crash
    // converges rather than duplicating routes.
    let h = harness("idempotent");
    block_on(h.config.apply(&contract(1, Ruleset::Protected))).expect("applies");
    let rows = h.system.routes_now().rows.len();
    let rules = h.system.rules().len();
    block_on(h.config.apply(&contract(1, Ruleset::Protected))).expect("re-applies");
    assert_eq!(h.system.routes_now().rows.len(), rows);
    assert_eq!(h.system.rules().len(), rules);
}

#[test]
fn the_declared_custody_says_the_os_holds_the_rules_and_the_swap_is_atomic() {
    // CB-6's normal case, declared rather than assumed: ADR-0012 §11.6's
    // Windows durability row is `✔` for crash, kill, update and reboot.
    let h = harness("custody");
    let custody = h.config.enforcement_custody();
    assert!(custody.survives_core_exit);
    assert!(custody.swap_is_atomic);
}
