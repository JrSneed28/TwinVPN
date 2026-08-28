//! Fixtures for the executed matrix: a rig with no JVM, and a session machine
//! on virtual time.
//!
//! Nothing here reaches the OS beyond a `socketpair`. That is CD-5's payoff
//! applied to wave 3: *"100% of the decision logic on a Linux CI runner with no
//! VM and no device farm"*.

#![allow(dead_code)]
// Two integration binaries (`matrix` and `leaks`) share this module and each
// uses a different subset of it, so a re-export unused by one is not dead code.
#![allow(unused_imports)]

mod fakes;
mod session;

pub use fakes::{FakeController, FakeElement};
pub use session::{
    assert_adapter_names_no_connection_state, blocked_session, connected_session, context, healthy,
    restored, resumed_session,
};

use std::task::{Context as TaskContext, Poll, Waker};

use futures_core::future::BoxFuture;
use futures_core::Stream;

use std::sync::Arc;
use twinvpn_platform::iface::{InterfaceFacts, InterfaceName, LinkClass, NetworkChange};

use twinvpn_platform::{
    ContractGeneration, DnsConfig, NetworkContract, RouteEntry, Ruleset, TunnelDevice, TunnelHandle,
};
use twinvpn_platform_android::builder::VpnConfig;
use twinvpn_platform_android::netchange::{diff, AndroidNetwork, Snapshot, TransportSet};
use twinvpn_platform_android::{
    AndroidAdapterParts, AndroidInterfaceProvider, AndroidNetworkConfig, AndroidPlatformAdapter,
    AndroidTunnelDevice,
};
use twinvpn_types::{IpAddr, IpPrefix, PerFamily, V4Addr, V6Addr};

// ---------------------------------------------------------------------------
// The controller and the element
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// The rig
// ---------------------------------------------------------------------------

/// One adapter with every capability bound and no JVM anywhere.
pub struct Rig {
    /// A current-thread runtime with the I/O driver enabled.
    ///
    /// `AndroidTunnelDevice` drives the tun descriptor through tokio's readiness
    /// driver ([`crate`-level note in `src/tun.rs`]), so `establish` needs a
    /// reactor. It is a **current-thread** runtime deliberately: the real
    /// `VpnService` datapath is one reader and one writer, and a multi-threaded
    /// harness would hide a `!Send` mistake that a device would find.
    runtime: tokio::runtime::Runtime,
    pub adapter: AndroidPlatformAdapter,
    pub controller: Arc<FakeController>,
    pub element: Arc<FakeElement>,
    pub tunnel: AndroidTunnelDevice,
    pub interfaces: AndroidInterfaceProvider,
    pub config: AndroidNetworkConfig,
}

impl Rig {
    /// Runs a seam future to completion.
    ///
    /// The adapter's futures either complete on the first poll or wait on a
    /// descriptor this rig does not use, so a single-threaded spin is enough and
    /// the test needs no runtime.
    pub fn block_on<T>(&self, future: BoxFuture<'_, T>) -> T {
        self.runtime.block_on(future)
    }
}

/// Builds the rig, with the tunnel handle already created and bound.
pub fn rig() -> Rig {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("current-thread runtime with the I/O driver");
    let controller = FakeController::new();
    let element = FakeElement::new();
    let adapter = AndroidPlatformAdapter::new(AndroidAdapterParts {
        controller: controller.clone(),
        element: element.clone(),
        store_root: std::path::PathBuf::from("/data/user/0/net.twinvpn.android/files/vault"),
        vpn_config: VpnConfig::default(),
    });
    let tunnel = adapter.tunnel_device().clone();
    let interfaces = adapter.interface_provider().clone();
    let config = adapter.network().clone();

    let name = InterfaceName::new("twin0").expect("name");
    let handle: TunnelHandle = runtime
        .block_on(tunnel.create_interface(&name, 1400))
        .expect("create");
    config.bind_handle(handle);

    Rig {
        runtime,
        adapter,
        controller,
        element,
        tunnel,
        interfaces,
        config,
    }
}

/// One item from a change stream, or `None` if nothing is pending.
pub fn poll(
    stream: &mut std::pin::Pin<Box<dyn Stream<Item = NetworkChange> + Send>>,
) -> Option<NetworkChange> {
    let waker = Waker::noop();
    let mut cx = TaskContext::from_waker(waker);
    match stream.as_mut().poll_next(&mut cx) {
        Poll::Ready(item) => item,
        Poll::Pending => None,
    }
}

// ---------------------------------------------------------------------------
// Contracts and networks
// ---------------------------------------------------------------------------

/// A minimal but complete contract: both overlay families addressed.
pub fn contract(generation: u64, ruleset: Ruleset) -> NetworkContract {
    NetworkContract {
        generation: ContractGeneration(generation),
        addresses: PerFamily::new(
            vec![prefix("100.64.0.1/32")],
            vec![IpPrefix::new(host_v6(1), 128).expect("overlay /128")],
        ),
        routes: PerFamily::new(Vec::new(), Vec::new()),
        dns: DnsConfig {
            resolvers: PerFamily::new(Vec::new(), Vec::new()),
            search_domains: Vec::new(),
            split_domains: Vec::new(),
            is_default_resolver: false,
        },
        ruleset,
        mtu: 1400,
    }
}

/// A contract claiming both default routes.
pub fn full_tunnel(generation: u64, ruleset: Ruleset) -> NetworkContract {
    let mut c = contract(generation, ruleset);
    c.routes.v4.push(route("0.0.0.0/0"));
    c.routes.v6.push(route("::/0"));
    c
}

/// A route entry over `spec`.
pub fn route(spec: &str) -> RouteEntry {
    RouteEntry {
        destination: prefix(spec),
        via: None,
        interface: twinvpn_platform::InterfaceIndex(10),
        metric: None,
    }
}

/// Parses a `a.b.c.d/len` or `::/len` literal.
pub fn prefix(spec: &str) -> IpPrefix {
    let (addr, len) = spec.split_once('/').expect("prefix literal has a /");
    let len: u32 = len.parse().expect("prefix length");
    let address = if addr.contains(':') {
        assert_eq!(addr, "::", "only :: is supported by this fixture");
        IpAddr::V6(V6Addr::UNSPECIFIED)
    } else {
        let mut octets = [0u8; 4];
        for (slot, part) in octets.iter_mut().zip(addr.split('.')) {
            *slot = part.parse().expect("octet");
        }
        IpAddr::V4(V4Addr::from_octets(octets))
    };
    IpPrefix::new(address, len).expect("canonical prefix")
}

/// A v4 host address.
pub fn host_v4(octets: [u8; 4]) -> IpAddr {
    IpAddr::V4(V4Addr::from_octets(octets))
}

/// A v6 host address inside the product ULA.
pub fn host_v6(low: u16) -> IpAddr {
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1] = 0x7c;
    octets[2] = 0x9e;
    octets[3] = 0x5d;
    octets[4] = 0x2a;
    octets[5] = 0x10;
    octets[14] = u8::try_from(low >> 8).expect("high octet");
    octets[15] = u8::try_from(low & 0xff).expect("low octet");
    IpAddr::V6(V6Addr::new(octets, None).expect("global v6 needs no zone"))
}

/// One `Network` as `ConnectivityManager` would describe it.
pub fn underlay(handle: u64, transports: u32, v4: bool, v6: bool) -> AndroidNetwork {
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
        default_routes: PerFamily::new(v4, v6),
        resolvers: vec![host_v4([192, 168, 1, 1]), host_v6(0x53)],
        mtu: 1500,
        metered: transports & TransportSet::CELLULAR != 0,
        nat64: None,
        private_dns_active: false,
        is_up: true,
    }
}

/// The deltas an actual Wi-Fi→cellular handoff produces.
pub fn wifi_to_cellular() -> Vec<NetworkChange> {
    let mut before = Snapshot::new();
    before
        .ingest(underlay(1, TransportSet::WIFI, true, true))
        .expect("wifi");
    let mut after = Snapshot::new();
    after
        .ingest(underlay(2, TransportSet::CELLULAR, true, true))
        .expect("cellular");
    diff(&before, &after)
}

/// An `InterfaceFacts` of the given class, for `event_for_change`'s `LinkKind`.
pub fn facts_for(link_class: LinkClass) -> InterfaceFacts {
    InterfaceFacts {
        index: twinvpn_platform::InterfaceIndex(1),
        name: InterfaceName::new("wlan0").expect("name"),
        addresses: Vec::new(),
        has_default_route_v4: true,
        has_default_route_v6: true,
        is_overlay: false,
        is_up: false,
        mtu: 1500,
        link_class,
    }
}
