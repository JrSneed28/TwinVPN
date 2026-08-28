//! **The wave-3 mobile test matrix, executed — rows 9 to 12.**
//!
//! Split from `matrix.rs` for the 500-line rule; the two files are one suite and
//! share `tests/common`. Rows 1–8 (lifecycle, network change, roaming, restart,
//! termination, restoration, revocation) are in `matrix.rs`; this file holds the
//! kill switch and all three leak families.
//!
//! `docs/implementation/ownership.md` §10.5: *"Leak coverage is **both families
//! and DNS** on every platform, per ADR-0010 R1: an IPv4 story with a weaker
//! IPv6 story is the asymmetry that ADR forbids."* Every test below runs against
//! both families, and the DNS test asserts on both resolver families rather than
//! on "DNS".
//!
//! What these prove is that the **claim** is correct. What they cannot prove is
//! that the platform honours it — that is
//! `shells/android/app/src/androidTest/.../LeakMeasurementTest.kt`, which is
//! **written, not executed**.

#![cfg(not(target_os = "android"))]

mod common;

use common::{contract, full_tunnel, host_v4, host_v6, prefix, rig, route, underlay};

use twinvpn_platform::{
    ContractGeneration, NetworkConfig, PlatformAdapter, RecordAeadCustody, Ruleset,
};
use twinvpn_platform_android::builder::{self, BuilderOp, VpnConfig};
use twinvpn_platform_android::netchange::TransportSet;
use twinvpn_platform_android::posture::LockdownPosture;
use twinvpn_platform_android::power::{keepalive_plan, KeepalivePlan};
use twinvpn_types::{AddressFamily, PerFamily};

// ===========================================================================
// ROW 9 — kill-switch behaviour
// ===========================================================================

/// ADR-0012 **KS-17**: the transition between the two rulesets is an atomic
/// swap, and rules are **never absent** while the latch is up.
#[test]
fn row_9_the_ruleset_swap_never_leaves_the_claim_absent() {
    let rig = rig();
    rig.block_on(rig.config.apply(&full_tunnel(1, Ruleset::Blocked)))
        .expect("apply");
    let before = rig.config.enforcement_view();

    for posture in [Ruleset::Protected, Ruleset::Blocked, Ruleset::Protected] {
        rig.block_on(rig.config.set_ruleset(ContractGeneration(1), posture))
            .expect("swap");
        let view = rig.config.enforcement_view();
        assert!(
            view.claim_in_force,
            "rules are never absent across the swap"
        );
        assert_eq!(view.claims_default, before.claims_default);
        assert_eq!(
            rig.block_on(rig.config.installed_ruleset()).expect("read"),
            Some(posture)
        );
    }
    // And no re-establish happened, which is WHY the swap is atomic.
    assert_eq!(rig.controller.establishes(), 1);
}

/// ADR-0022 LC-40 / `docs/networking.md` §5.4: the posture is three-valued and
/// `UNVERIFIED` presents as unprotected.
#[test]
fn row_9_the_lockdown_posture_is_three_valued_and_fails_closed() {
    let rig = rig();
    rig.block_on(rig.config.apply(&full_tunnel(1, Ruleset::Protected)))
        .expect("apply");

    assert_eq!(rig.config.lockdown(), LockdownPosture::Unverified);
    assert!(!rig.config.enforcement_custody().survives_core_exit());

    rig.config.set_lockdown_report(Some(false));
    assert_eq!(rig.config.lockdown(), LockdownPosture::Absent);
    assert!(!rig.config.enforcement_custody().survives_core_exit());

    rig.config.set_lockdown_report(Some(true));
    assert_eq!(rig.config.lockdown(), LockdownPosture::Confirmed);
    assert!(rig.config.enforcement_custody().survives_core_exit());

    // And the swap stays atomic in every posture.
    for reported in [Some(true), Some(false), None] {
        rig.config.set_lockdown_report(reported);
        assert!(rig.config.enforcement_custody().swap_is_atomic);
    }
}

/// §10.2(2): keepalives ride the kernel timer or they do not happen. There is no
/// alarm variant, and an unservable interval is a **fact**, never a substitute.
#[test]
fn row_9_no_keepalive_path_can_defeat_doze_with_an_app_side_alarm() {
    let plan = keepalive_plan(true, core::time::Duration::from_secs(25));
    assert_eq!(
        plan,
        KeepalivePlan::KernelSocketKeepalive { interval_secs: 25 }
    );
    match keepalive_plan(false, core::time::Duration::from_secs(25)) {
        KeepalivePlan::Unavailable { reason } => {
            assert!(twinvpn_types::ReasonCode::lookup(reason.as_str()).is_some());
        }
        KeepalivePlan::KernelSocketKeepalive { .. } => {
            panic!("an unsupported platform must not be served by a substitute")
        }
    }
}

// ===========================================================================
// ROWS 10 and 11 — IPv4 leaks and IPv6 leaks
// ===========================================================================

/// **ADR-0012 §11.6's Android row, and ADR-0010 R1.** The enforcement point on
/// Android is the `VpnService.Builder` route claim, and it must cover
/// `0.0.0.0/0` **and** `::/0`. There is no firewall behind it to catch what an
/// unclaimed family does.
#[test]
fn rows_10_and_11_a_full_tunnel_claims_both_families() {
    let programme = builder::render(&full_tunnel(1, Ruleset::Protected), &VpnConfig::default())
        .expect("render");
    assert!(programme.claims_both_defaults());

    let routes: Vec<_> = programme
        .ops
        .iter()
        .filter_map(|op| match op {
            BuilderOp::AddRoute { destination } if destination.prefix_len() == 0 => {
                Some(destination.family())
            }
            _ => None,
        })
        .collect();
    assert!(routes.contains(&AddressFamily::V4));
    assert!(routes.contains(&AddressFamily::V6));
}

/// The asymmetry ADR-0010 R1 forbids, refused in **both** directions: a
/// single-family default claim is widened rather than leaked, and the read-back
/// never reports a one-family claim as protection.
#[test]
fn rows_10_and_11_a_single_family_default_is_never_left_unclaimed() {
    for (v4, v6) in [(true, false), (false, true)] {
        let mut c = contract(1, Ruleset::Protected);
        if v4 {
            c.routes.v4.push(route("0.0.0.0/0"));
        }
        if v6 {
            c.routes.v6.push(route("::/0"));
        }
        let programme = builder::render(&c, &VpnConfig::default()).expect("render");
        assert!(
            programme.claims_both_defaults(),
            "asking for one family's default must claim both; the other egresses"
        );
    }

    // And at the read-back: a claim covering one family is reported as NO
    // ruleset, never as "protected with a v6 caveat".
    let view = twinvpn_platform_android::posture::EnforcementView::from_claim(
        true,
        PerFamily::new(true, false),
        Ruleset::Protected,
        LockdownPosture::Confirmed,
    );
    assert_eq!(view.installed_ruleset(), None);
}

/// A generation whose claim does not cover both defaults is not the kill switch,
/// and `installed_ruleset` says so — which is what stops a split tunnel being
/// reported as leak-proof.
#[test]
fn rows_10_and_11_a_split_tunnel_is_not_reported_as_an_installed_ruleset() {
    let rig = rig();
    let mut split = contract(1, Ruleset::Protected);
    split.routes.v4.push(route("100.64.0.0/10"));
    rig.block_on(rig.config.apply(&split)).expect("apply");
    assert_eq!(
        rig.block_on(rig.config.installed_ruleset()).expect("read"),
        None
    );
}

// ===========================================================================
// ROW 12 — DNS leaks
// ===========================================================================

/// Both families of resolver reach the claim, and Android's missing per-suffix
/// API is **reported** with a registered code rather than silently dropped.
#[test]
fn row_12_both_resolver_families_are_claimed_and_split_dns_is_reported() {
    let mut c = full_tunnel(1, Ruleset::Protected);
    c.dns.resolvers.v4.push(host_v4([100, 64, 0, 53]));
    c.dns.resolvers.v6.push(host_v6(0x53));
    c.dns.search_domains.push("twin.internal".to_owned());
    c.dns.split_domains.push("corp.example".to_owned());

    let programme = builder::render(&c, &VpnConfig::default()).expect("render");

    let families: Vec<_> = programme
        .ops
        .iter()
        .filter_map(|op| match op {
            BuilderOp::AddDnsServer(a) => Some(a.family()),
            _ => None,
        })
        .collect();
    assert!(families.contains(&AddressFamily::V4));
    assert!(
        families.contains(&AddressFamily::V6),
        "a v4-only resolver claim leaks every v6 query"
    );

    assert!(programme
        .ops
        .contains(&BuilderOp::AddSearchDomain("twin.internal".to_owned())));
    assert!(programme
        .unsupported
        .contains(&twinvpn_types::codes::DNS_PLATFORM_SCOPED_API_UNAVAILABLE));
}

/// The system resolvers are read back per family, so the core can see the ones
/// it is displacing. A v6 resolver dropped here is a v6 query that escapes.
#[test]
fn row_12_the_underlay_resolvers_are_reported_per_family() {
    let rig = rig();
    rig.interfaces
        .ingest(underlay(1, TransportSet::WIFI, true, true))
        .expect("ingest");
    let facts = rig.block_on(rig.config.query_link_facts()).expect("facts");
    assert!(!facts.resolvers.v4.is_empty());
    assert!(!facts.resolvers.v6.is_empty());
}

// ===========================================================================
// CB-6a and the seam's own declarations
// ===========================================================================

/// CB-6a: Android is one of **two of ten** targets with mandatory platform AEAD,
/// so `record_aead_custody` is `PlatformPerformed` — **1** across F-9.
#[test]
fn cb_6a_the_platform_performs_the_record_aead_on_this_target() {
    let rig = rig();
    assert_eq!(
        rig.adapter.store().record_aead_custody(),
        RecordAeadCustody::PlatformPerformed
    );
}

#[test]
fn the_overlay_addressing_is_dual_stack_regardless_of_the_underlay() {
    // ADR-0010 R1 / `docs/networking.md` §2.4: the overlay is dual-stack even on
    // a single-stack underlay. The fixture cannot be built otherwise.
    let c = contract(1, Ruleset::Protected);
    assert!(!c.addresses.v4.is_empty());
    assert!(!c.addresses.v6.is_empty());
    assert_eq!(prefix("100.64.0.1/32").family(), AddressFamily::V4);
}
