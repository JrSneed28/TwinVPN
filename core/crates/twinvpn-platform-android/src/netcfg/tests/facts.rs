//! `query_link_facts`, and the underlying-network set that follows a handoff.
//!
//! Split from the `apply`/`rollback`/swap tests for the 500-line rule; the two
//! files are one suite and share the rig above them.

use super::*;
use twinvpn_types::Nat64Prefix;

// ---------------------------------------------------------------------------
// link facts and the underlay
// ---------------------------------------------------------------------------

#[tokio::test]
async fn link_facts_report_both_families_separately_and_the_smallest_underlay_mtu() {
    let rig = rig(false).await;
    let mut wifi = underlay(1, TransportSet::WIFI, true, true);
    wifi.mtu = 1500;
    let mut cell = underlay(2, TransportSet::CELLULAR, true, true);
    cell.mtu = 1420;
    rig.interfaces.ingest(wifi).expect("ingest");
    rig.interfaces.ingest(cell).expect("ingest");

    let facts = rig.config.query_link_facts().await.expect("facts");
    assert!(*facts.default_routes.get(AddressFamily::V4));
    assert!(*facts.default_routes.get(AddressFamily::V6));
    assert_eq!(facts.families, UnderlayFamilies::DualStack);
    assert_eq!(
        facts.mtu, 1420,
        "the smallest, because a tunnel sized to the largest black-holes on handoff"
    );
    assert!(!facts.resolvers.v4.is_empty());
    assert!(
        !facts.resolvers.v6.is_empty(),
        "the v6 resolver half must not be forgotten"
    );
}

#[tokio::test]
async fn an_ipv6_only_underlay_carries_its_nat64_prefix() {
    let rig = rig(false).await;
    let mut cell = underlay(1, TransportSet::CELLULAR, false, true);
    cell.nat64 = Some(Nat64Prefix::well_known());
    rig.interfaces.ingest(cell).expect("ingest");

    let facts = rig.config.query_link_facts().await.expect("facts");
    assert_eq!(
        facts.families,
        UnderlayFamilies::V6Only {
            nat64: Some(Nat64Prefix::well_known())
        }
    );
    assert!(!*facts.default_routes.get(AddressFamily::V4));
    assert!(facts.families.carries(AddressFamily::V6));
}

#[tokio::test]
async fn our_own_tunnel_is_excluded_from_the_underlay_facts() {
    let rig = rig(false).await;
    rig.interfaces
        .ingest(underlay(1, TransportSet::VPN, true, true))
        .expect("ingest");
    let facts = rig.config.query_link_facts().await.expect("facts");
    assert!(!*facts.default_routes.get(AddressFamily::V4));
    assert!(!*facts.default_routes.get(AddressFamily::V6));
    assert!(facts.resolvers.v4.is_empty());
}

/// §5.4's roaming row: `setUnderlyingNetworks` kept current across handoff.
#[tokio::test]
async fn the_underlying_network_set_follows_a_wifi_to_cellular_handoff() {
    let rig = rig(false).await;
    rig.interfaces
        .ingest(underlay(11, TransportSet::WIFI, true, true))
        .expect("ingest");
    rig.config
        .apply(&full_tunnel(1, Ruleset::Protected))
        .await
        .expect("apply");
    assert_eq!(
        rig.controller.underlying.lock().expect("lock").last(),
        Some(&vec![11u64])
    );

    // Wi-Fi is lost, cellular arrives.
    rig.interfaces.forget(11).expect("lost");
    rig.interfaces
        .ingest(underlay(22, TransportSet::CELLULAR, true, true))
        .expect("ingest");
    rig.config.refresh_underlying_networks().expect("refresh");
    assert_eq!(
        rig.controller.underlying.lock().expect("lock").last(),
        Some(&vec![22u64]),
        "the system must account and route against the underlay we are on"
    );
}

#[tokio::test]
async fn the_power_posture_reaches_link_facts_so_lc31_has_its_inputs() {
    let rig = rig(false).await;
    rig.interfaces
        .ingest(underlay(1, TransportSet::CELLULAR, true, true))
        .expect("ingest");
    rig.interfaces.set_power(true, true).expect("posture");
    let facts = rig.config.query_link_facts().await.expect("facts");
    assert!(facts.metered);
    assert!(facts.low_power);
}

#[tokio::test]
async fn a_host_with_no_underlay_reports_no_default_route_rather_than_failing() {
    let rig = rig(false).await;
    let facts = rig.config.query_link_facts().await.expect("facts");
    assert!(!*facts.default_routes.get(AddressFamily::V4));
    assert!(!*facts.default_routes.get(AddressFamily::V6));
    assert_eq!(facts.mtu, crate::builder::MTU_FLOOR);
}

/// ADR-0022 LC-4 makes `current_generation` the recovery entry point, so it must
/// answer even while the previous process is on its way out.
#[tokio::test]
async fn current_generation_answers_during_shutdown() {
    let latch = ShutdownLatch::new();
    let controller = FakeController::new(false);
    let tunnel = AndroidTunnelDevice::new(controller.clone(), latch.clone());
    let interfaces = AndroidInterfaceProvider::new(latch.clone());
    let config = AndroidNetworkConfig::new(
        controller,
        tunnel.clone(),
        interfaces,
        VpnConfig::default(),
        latch.clone(),
    );
    let name = InterfaceName::new("twin0").expect("name");
    let handle = tunnel.create_interface(&name, 1400).await.expect("create");
    config.bind_handle(handle);
    config
        .apply(&full_tunnel(4, Ruleset::Blocked))
        .await
        .expect("apply");
    latch.begin();
    assert_eq!(
        config.current_generation().await.expect("still answers"),
        Some(ContractGeneration(4))
    );
}

/// A split-tunnel contract claims neither default, and the read-back says so
/// rather than reporting the tunnel as the kill switch.
#[tokio::test]
async fn a_split_tunnel_generation_is_not_reported_as_an_installed_ruleset() {
    let rig = rig(false).await;
    let mut split = contract(1, Ruleset::Protected);
    split.routes.v4.push(route("100.64.0.0/10"));
    split.routes.v6.push(route("::/0"));
    // Asking for a v6 default widens BOTH, so build a genuinely partial one.
    let mut narrow = contract(2, Ruleset::Protected);
    narrow.routes.v4.push(route("100.64.0.0/10"));
    let _ = IpPrefix::new(host_v4([100, 64, 0, 0]), 10);

    rig.config.apply(&split).await.expect("apply widened");
    assert_eq!(
        rig.config.installed_ruleset().await.expect("read"),
        Some(Ruleset::Protected)
    );

    rig.config.apply(&narrow).await.expect("apply narrow");
    assert_eq!(
        rig.config.installed_ruleset().await.expect("read"),
        None,
        "a claim that covers only some prefixes is not the kill switch"
    );
}
