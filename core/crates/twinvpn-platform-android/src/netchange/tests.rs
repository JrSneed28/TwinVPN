//! The `NetworkCallback` decoder and its diff, exhaustively, with no device.
//!
//! This is the layer `ownership.md` §10.3 names first in its **executed** row:
//! event decoding is target-free by construction, so every roaming, address and
//! default-route case runs here rather than on a farm.

use super::*;
use crate::testkit::{host_v4, host_v6, iface_addr};

fn net(handle: u64, transports: u32, up: bool) -> AndroidNetwork {
    AndroidNetwork {
        handle,
        name: InterfaceName::new(if transports & TransportSet::WIFI != 0 {
            "wlan0"
        } else {
            "rmnet0"
        })
        .expect("name"),
        transports: TransportSet::from_bits(transports),
        addresses: Vec::new(),
        default_routes: PerFamily::new(true, true),
        resolvers: Vec::new(),
        mtu: 1500,
        metered: transports & TransportSet::CELLULAR != 0,
        nat64: None,
        private_dns_active: false,
        is_up: up,
    }
}

fn snapshot(networks: Vec<AndroidNetwork>) -> Snapshot {
    let mut s = Snapshot::new();
    for n in networks {
        s.ingest(n).expect("within bound");
    }
    s
}

#[test]
fn a_vpn_network_is_reported_as_a_tunnel_even_when_it_also_carries_wifi() {
    // §5.5 rule 4: a second default-route-claiming interface must be
    // detected and named, not absorbed into the underlay.
    let both = TransportSet::from_bits(TransportSet::VPN | TransportSet::WIFI);
    assert_eq!(link_class(both), LinkClass::Tunnel);
    assert_eq!(
        link_class(TransportSet::from_bits(TransportSet::WIFI)),
        LinkClass::WiFi
    );
    assert_eq!(
        link_class(TransportSet::from_bits(TransportSet::CELLULAR)),
        LinkClass::Cellular
    );
    assert_eq!(
        link_class(TransportSet::from_bits(TransportSet::ETHERNET)),
        LinkClass::Ethernet
    );
    assert_eq!(link_class(TransportSet::default()), LinkClass::Unknown);
}

/// **The roaming row, as facts.** Wi-Fi is lost while cellular arrives. The
/// adapter reports what happened; `tests/falsification.rs` shows the core
/// turning it into `MIGRATING`.
#[test]
fn a_wifi_to_cellular_handoff_produces_facts_and_no_verdict() {
    let wifi = net(0x1_0000_0001, TransportSet::WIFI, true);
    let cell = net(0x1_0000_0002, TransportSet::CELLULAR, true);
    let before = snapshot(vec![wifi.clone()]);
    let after = snapshot(vec![cell.clone()]);

    let changes = diff(&before, &after);
    assert!(changes.contains(&NetworkChange::InterfaceRemoved(wifi.index())));
    assert!(changes.contains(&NetworkChange::InterfaceAdded(cell.index())));
    // Both underlays carry both families, so the default-route facts did
    // NOT change -- which is the point: the overlay's addressing is
    // untouched by an underlay change (N2), and the adapter says so by
    // emitting nothing about it.
    assert!(!changes
        .iter()
        .any(|c| matches!(c, NetworkChange::DefaultRouteChanged { .. })));
}

/// ADR-0010 R6: IPv6 appearing after the tunnel is up must be
/// distinguishable from nothing having happened.
#[test]
fn a_v6_default_arriving_alone_is_its_own_event() {
    let mut wifi_v4_only = net(1, TransportSet::WIFI, true);
    wifi_v4_only.default_routes = PerFamily::new(true, false);
    let before = snapshot(vec![wifi_v4_only.clone()]);

    let mut wifi_dual = wifi_v4_only.clone();
    wifi_dual.default_routes = PerFamily::new(true, true);
    let after = snapshot(vec![wifi_dual]);

    let changes = diff(&before, &after);
    assert_eq!(
        changes
            .iter()
            .filter(|c| matches!(c, NetworkChange::DefaultRouteChanged { .. }))
            .collect::<Vec<_>>(),
        vec![&NetworkChange::DefaultRouteChanged {
            family: AddressFamily::V6,
            present: true,
        }],
        "the v4 half was unchanged and must not be re-announced"
    );
}

/// Our own tunnel carries a default route by construction. Counting it would
/// make "the underlay has a way out" permanently true.
#[test]
fn our_own_vpn_interface_does_not_count_as_an_underlay_default_route() {
    let vpn = net(9, TransportSet::VPN | TransportSet::WIFI, true);
    let s = snapshot(vec![vpn]);
    assert!(!s.underlay_has_default(AddressFamily::V4));
    assert!(!s.underlay_has_default(AddressFamily::V6));
}

#[test]
fn a_link_going_down_is_a_state_change_not_a_removal() {
    let up = net(1, TransportSet::WIFI, true);
    let mut down = up.clone();
    down.is_up = false;
    let changes = diff(&snapshot(vec![up.clone()]), &snapshot(vec![down]));
    assert!(changes.contains(&NetworkChange::LinkStateChanged {
        interface: up.index(),
        is_up: false,
    }));
    assert!(!changes
        .iter()
        .any(|c| matches!(c, NetworkChange::InterfaceRemoved(_))));
}

#[test]
fn address_deltas_are_reported_in_both_families() {
    let mut before = net(1, TransportSet::WIFI, true);
    before.addresses = vec![iface_addr("192.168.1.0/24")];
    let mut after = before.clone();
    after.addresses = vec![InterfaceAddress::new(host_v6(0x20), 128).expect("v6 host")];

    let changes = diff(&snapshot(vec![before.clone()]), &snapshot(vec![after]));
    assert!(changes
        .iter()
        .any(|c| matches!(c, NetworkChange::AddressRemoved { .. })));
    assert!(changes
        .iter()
        .any(|c| matches!(c, NetworkChange::AddressAdded { .. })));
}

#[test]
fn a_new_network_does_not_replay_its_addresses_as_change_events() {
    // `InterfaceProvider::subscribe`'s contract: the stream carries changes,
    // not initial state. A caller that has just subscribed enumerates.
    let mut fresh = net(1, TransportSet::WIFI, true);
    fresh.addresses = vec![iface_addr("192.168.1.0/24")];
    let changes = diff(&Snapshot::new(), &snapshot(vec![fresh]));
    assert!(!changes
        .iter()
        .any(|c| matches!(c, NetworkChange::AddressAdded { .. })));
    assert_eq!(
        changes
            .iter()
            .filter(|c| matches!(c, NetworkChange::InterfaceAdded(_)))
            .count(),
        1
    );
}

#[test]
fn a_resolver_change_on_the_underlay_is_announced() {
    let mut before = net(1, TransportSet::WIFI, true);
    before.resolvers = vec![host_v4([192, 168, 1, 1])];
    let mut after = before.clone();
    after.resolvers = vec![host_v4([1, 1, 1, 1])];
    assert!(diff(&snapshot(vec![before]), &snapshot(vec![after]))
        .contains(&NetworkChange::ResolversChanged));
}

#[test]
fn two_underlays_disagreeing_about_nat64_report_no_prefix_rather_than_a_guess() {
    let mut a = net(1, TransportSet::WIFI, true);
    a.nat64 = Some(Nat64Prefix::well_known());
    let mut b = net(2, TransportSet::CELLULAR, true);
    let mut other = [0u8; 16];
    other[0] = 0x20;
    other[1] = 0x01;
    b.nat64 = Some(Nat64Prefix::new(other, 96).expect("rfc 6052 length"));
    assert_eq!(nat64_of(&snapshot(vec![a.clone(), b])), None);
    assert_eq!(
        nat64_of(&snapshot(vec![a])),
        Some(Nat64Prefix::well_known())
    );
}

#[test]
fn the_power_posture_is_its_own_event() {
    let mut before = snapshot(vec![net(1, TransportSet::WIFI, true)]);
    let mut after = before.clone();
    assert!(after.set_power(true, true));
    assert!(!before.set_power(false, false), "unchanged is unchanged");
    assert!(
        diff(&before, &after).contains(&NetworkChange::LinkPostureChanged {
            metered: true,
            low_power: true,
        })
    );
}

#[test]
fn the_tracked_network_set_is_bounded_and_a_refusal_is_not_an_eviction() {
    let mut s = Snapshot::new();
    for handle in 0..MAX_TRACKED_NETWORKS as u64 {
        s.ingest(net(handle, TransportSet::WIFI, true))
            .expect("fits");
    }
    let err = s
        .ingest(net(999, TransportSet::WIFI, true))
        .expect_err("over the bound");
    assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
    assert_eq!(
        s.networks().len(),
        MAX_TRACKED_NETWORKS,
        "refusing must not evict: an eviction becomes a link-down that did not happen"
    );
}

#[test]
fn ingesting_the_same_handle_twice_replaces_rather_than_duplicates() {
    let mut s = Snapshot::new();
    s.ingest(net(1, TransportSet::WIFI, true)).expect("first");
    s.ingest(net(1, TransportSet::WIFI, false)).expect("second");
    assert_eq!(s.networks().len(), 1);
    assert!(!s.networks()[0].is_up);
    assert!(s.forget(1));
    assert!(!s.forget(1), "forget is idempotent");
}

#[test]
fn diffing_a_snapshot_against_itself_produces_nothing() {
    let s = snapshot(vec![
        net(1, TransportSet::WIFI, true),
        net(2, TransportSet::CELLULAR, true),
    ]);
    assert!(diff(&s, &s).is_empty());
}
