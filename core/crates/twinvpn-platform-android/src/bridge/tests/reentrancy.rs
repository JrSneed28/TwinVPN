//! **M-19: the `establish()` fan-out, delivered back to the process that made
//! it.**
//!
//! `ConnectivityWatcher` registers its callback with `NET_CAPABILITY_NOT_VPN`
//! removed, which lifts the `NOT_VPN` filter `NetworkRequest.Builder` applies by
//! default. `VpnService.Builder.establish()` therefore fires a fresh
//! `CALLBACK_AVAILABLE` fan-out for the app's **own** network straight back into
//! `nativeOnNetwork`. Observing a VPN network is deliberate — see
//! [`super::super::AndroidBridge::on_revoked`] — and what had never been
//! exercised anywhere is the re-entrancy: what those callbacks do to an adapter
//! that is already holding the underlay it is about to be handed a tunnel over.
//!
//! It cannot be exercised on a device from `src/androidTest/` either, and
//! `NativeLinkRunTest`'s class documentation carries the account of why. This is
//! where it *is* exercised: the fan-out is three payloads, the codec writes them
//! deterministically from what `ConnectivityManager` hands it, and everything
//! they touch — decode, snapshot, diff, the underlying-network set — is
//! target-free Rust that runs on this host.

use std::sync::Arc;

use super::*;

/// A controller that **records** what `set_underlying_networks` was handed.
///
/// [`super::StubController`] discards the handles, so every test beside it could
/// only assert that the refresh did not fail — never *what* the adapter told the
/// platform the tunnel runs over. That is exactly the fact M-19 asks about.
#[derive(Debug, Default)]
struct RecordingController {
    underlying: std::sync::Mutex<Vec<Vec<u64>>>,
}

impl RecordingController {
    /// The most recent list handed to `VpnService.setUnderlyingNetworks`.
    fn last_underlying(&self) -> Vec<u64> {
        self.underlying
            .lock()
            .expect("recorder")
            .last()
            .cloned()
            .unwrap_or_default()
    }
}

impl TunnelController for RecordingController {
    fn name(&self) -> &'static str {
        "recording"
    }
    fn establish(&self, _programme: &Programme) -> Result<RawFd, PlatformError> {
        Err(PlatformError::OsUnsupported(None))
    }
    fn close_tun(&self, _fd: RawFd) -> Result<(), PlatformError> {
        Ok(())
    }
    fn set_underlying_networks(&self, handles: &[u64]) -> Result<(), PlatformError> {
        self.underlying
            .lock()
            .expect("recorder")
            .push(handles.to_vec());
        Ok(())
    }
    fn protect_socket(&self, _fd: RawFd) -> Result<(), PlatformError> {
        Ok(())
    }
    fn request_keepalive(&self, _fd: RawFd, _plan: KeepalivePlan) -> Result<(), PlatformError> {
        Ok(())
    }
}

fn recording_bridge() -> (AndroidBridge, Arc<RecordingController>) {
    let controller = Arc::new(RecordingController::default());
    let bridge = AndroidBridge::new(AndroidPlatformAdapter::new(AndroidAdapterParts {
        controller: controller.clone(),
        element: Arc::new(StubElement),
        store_root: std::path::PathBuf::from("/vault"),
        vpn_config: VpnConfig::default(),
    }));
    (bridge, controller)
}

/// What `ConnectivityWatcher` writes for a `Network` whose `NetworkCapabilities`
/// have not been observed.
///
/// `NetworkCodec.encode(network, null, null, isUp = true)`, field for field:
/// `interfaceName` is absent so the name is the literal `"unknown"`, the
/// transport bitset is **empty** because `transportBits(null)` is `0`, and there
/// is no MTU, no address, no resolver and no route.
fn network_with_no_capabilities_yet(handle: u64) -> AndroidNetwork {
    AndroidNetwork {
        handle,
        name: InterfaceName::new("unknown").expect("NetworkCodec's own fallback"),
        transports: TransportSet::from_bits(0),
        addresses: Vec::new(),
        default_routes: PerFamily::new(false, false),
        resolvers: Vec::new(),
        mtu: 0,
        metered: false,
        nat64: None,
        private_dns_active: false,
        is_up: true,
    }
}

/// **M-19: the whole `establish()` fan-out, re-entrant, in order.**
///
/// `ConnectivityWatcher` removes `NET_CAPABILITY_NOT_VPN` from its request, so
/// `VpnService.Builder.establish()` fans a fresh `CALLBACK_AVAILABLE` for the
/// app's OWN network straight back into `nativeOnNetwork`. Observing a VPN
/// network is deliberate — [`AndroidBridge::on_revoked`] documents why — and
/// what had never been exercised is the re-entrancy: what those three callbacks
/// do to an adapter that already holds the underlay.
///
/// The trap is the FIRST of them. `NetworkCallback.onAvailable(Network)` runs
/// before either half of the description has been delivered, so
/// `NetworkCodec.encode(network, null, null, isUp = true)` writes an **empty
/// transport set**, and
/// [`crate::netcfg::AndroidNetworkConfig::refresh_underlying_networks`] selects
/// underlays by `!transports.has(VPN)`. Before the guard in
/// [`AndroidBridge::on_network`], that unclassified observation read as "not a
/// VPN" and our own tunnel was handed to `VpnService.setUnderlyingNetworks` as
/// one of the networks it runs over: `[11, 22]` where `22` is the tunnel itself.
///
/// The second and third callbacks cover M-19's other question. It reports that
/// the system hands a caller a non-null but **empty** `LinkProperties` for its
/// own VPN; that has not been measured on a device here, so the case is covered
/// rather than assumed. An empty one is what the codec turns into the name
/// `"unknown"` with no address, no resolver and no route, and what this asserts
/// is that such a payload is **accepted rather than refused** — `"unknown"` is a
/// valid `InterfaceName`, so no `TWINVPN_BRIDGE_REFUSED` is produced — and that
/// it moves none of the aggregates. A populated `LinkProperties` is the ordinary
/// case `a_populated_address_set_reaches_the_snapshot_intact` already covers.
#[test]
fn the_first_observation_of_our_own_tunnel_is_not_named_as_the_network_it_runs_over() {
    let (bridge, controller) = recording_bridge();

    // The underlay, fully described, as it is by the time a tunnel exists.
    bridge
        .on_network(&wire::encode_network(&network(11, TransportSet::WIFI)))
        .expect("the underlay is ingested");
    assert_eq!(
        controller.last_underlying(),
        vec![11],
        "the Wi-Fi underlay is what the tunnel runs over"
    );

    // 1. `establish()` -> `onAvailable(ourOwnVpn)`, capabilities not yet given.
    bridge
        .on_network(&wire::encode_network(&network_with_no_capabilities_yet(22)))
        .expect("an observation with no capabilities is a fact, not a refusal");
    assert_eq!(
        controller.last_underlying(),
        vec![11],
        "handle 22 is our own tunnel; naming it as its own underlying network \
         asks the platform to account for a loop"
    );
    // Deferred, never dropped: the fact itself is in the snapshot regardless.
    let snapshot = bridge
        .adapter()
        .interface_provider()
        .snapshot()
        .expect("snapshot");
    assert_eq!(
        snapshot.networks().len(),
        2,
        "the unclassified observation is still recorded; only the refresh waits"
    );

    // 2. `onCapabilitiesChanged` -> now it is classifiable, and it is a tunnel.
    //    The `LinkProperties` half is still absent, so the name is the codec's
    //    `"unknown"` fallback and there are no addresses.
    let mut established = network(22, TransportSet::VPN | TransportSet::WIFI);
    established.name = InterfaceName::new("unknown").expect("the codec's fallback");
    established.default_routes = PerFamily::new(false, false);
    established.mtu = 0;
    bridge
        .on_network(&wire::encode_network(&established))
        .expect("the capabilities callback is ingested");
    assert_eq!(
        controller.last_underlying(),
        vec![11],
        "a classified tunnel is filtered out of its own underlay"
    );

    // 3. `onLinkPropertiesChanged` carrying the EMPTY `LinkProperties` M-19
    //    reports for a caller's own VPN. Accepted, and it moves nothing.
    bridge
        .on_network(&wire::encode_network(&established))
        .expect("an empty LinkProperties is accepted, not refused");

    let snapshot = bridge
        .adapter()
        .interface_provider()
        .snapshot()
        .expect("snapshot");
    assert_eq!(controller.last_underlying(), vec![11]);
    assert!(
        snapshot.underlay_has_default(twinvpn_types::AddressFamily::V4),
        "the Wi-Fi underlay still carries the default route"
    );
    assert_eq!(
        crate::netchange::link_class(snapshot.networks()[1].transports),
        twinvpn_platform::iface::LinkClass::Tunnel
    );
}

/// The tunnel goes away again: `onLost` restores exactly the underlay set that
/// was in force before `establish()`.
#[test]
fn losing_our_own_tunnel_leaves_the_underlay_where_it_was() {
    let (bridge, controller) = recording_bridge();
    bridge
        .on_network(&wire::encode_network(&network(11, TransportSet::WIFI)))
        .expect("underlay");
    bridge
        .on_network(&wire::encode_network(&network(
            22,
            TransportSet::VPN | TransportSet::WIFI,
        )))
        .expect("our own tunnel");
    bridge.on_network_lost(22).expect("onLost");
    assert_eq!(controller.last_underlying(), vec![11]);
}
