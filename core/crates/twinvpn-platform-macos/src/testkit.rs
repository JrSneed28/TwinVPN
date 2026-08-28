//! Contract fixtures, shared by this crate's unit tests and its integration
//! tests.
//!
//! `#[doc(hidden)]` and unconditional rather than `#[cfg(test)]`: an integration
//! test in `tests/` links the library as an ordinary dependency and cannot see a
//! `cfg(test)` module, and a second copy of these builders in `tests/common/`
//! would be a second definition of "what a TwinVPN contract looks like" — the
//! shape MI-20 forbids for the command catalogue and that is no better here.
//!
//! Nothing in this module is used by the adapter itself.

use twinvpn_platform::{
    ContractGeneration, DnsConfig, InterfaceIndex, NetworkContract, RouteEntry, Ruleset,
};
use twinvpn_types::{IpAddr, IpPrefix, PerFamily, V4Addr, V6Addr};

/// A canonical IPv4 prefix. Panics on a non-canonical one, which is a test bug.
#[must_use]
pub fn v4(octets: [u8; 4], len: u32) -> IpPrefix {
    IpPrefix::new(IpAddr::V4(V4Addr::from_octets(octets)), len).expect("canonical v4 prefix")
}

/// A canonical IPv6 prefix from its first two octets.
#[must_use]
pub fn v6(first: u8, second: u8, len: u32) -> IpPrefix {
    let mut octets = [0u8; 16];
    octets[0] = first;
    octets[1] = second;
    IpPrefix::new(
        IpAddr::V6(V6Addr::new(octets, None).expect("valid v6 address")),
        len,
    )
    .expect("canonical v6 prefix")
}

/// A one-route-per-family contract at `generation`, in `Ruleset::Protected`.
#[must_use]
pub fn contract(generation: u64) -> NetworkContract {
    contract_with(generation, Ruleset::Protected)
}

/// The same, with the posture chosen.
#[must_use]
pub fn contract_with(generation: u64, ruleset: Ruleset) -> NetworkContract {
    NetworkContract {
        generation: ContractGeneration(generation),
        addresses: PerFamily::new(vec![v4([100, 64, 0, 0], 32)], vec![v6(0xfd, 0x7c, 128)]),
        routes: PerFamily::new(
            vec![RouteEntry {
                destination: v4([100, 64, 0, 0], 10),
                via: None,
                interface: InterfaceIndex(9),
                metric: None,
            }],
            vec![RouteEntry {
                destination: v6(0xfd, 0x7c, 48),
                via: None,
                interface: InterfaceIndex(9),
                metric: None,
            }],
        ),
        dns: DnsConfig {
            resolvers: PerFamily::new(Vec::new(), Vec::new()),
            search_domains: Vec::new(),
            split_domains: Vec::new(),
            is_default_resolver: false,
        },
        ruleset,
        mtu: 1280,
    }
}

/// A full-tunnel contract: the four `/1` routes of `docs/networking.md` §7.2.
#[must_use]
pub fn full_tunnel_contract(generation: u64, ruleset: Ruleset) -> NetworkContract {
    let mut c = contract_with(generation, ruleset);
    let mut v4_routes = Vec::new();
    let mut v6_routes = Vec::new();
    for destination in crate::route::full_tunnel_destinations() {
        let entry = RouteEntry {
            destination,
            via: None,
            interface: InterfaceIndex(9),
            metric: None,
        };
        match destination.family() {
            twinvpn_types::AddressFamily::V4 => v4_routes.push(entry),
            twinvpn_types::AddressFamily::V6 => v6_routes.push(entry),
        }
    }
    c.routes = PerFamily::new(v4_routes, v6_routes);
    c
}

/// An enforcement configuration with both KS-9 halves present.
#[must_use]
pub fn enforcement() -> crate::pf::EnforcementConfig {
    crate::pf::EnforcementConfig {
        overlay_interface: "utun7".to_owned(),
        exempt: crate::pf::ExemptPredicate::ProviderUidAndSocketSet { uid: 501 },
        local_network_access: true,
        // A ULA rather than `fe80::/10`: `twinvpn-types` cannot represent a
        // link-local PREFIX at all — `V6Addr::new` requires a zone on `fe80::/10`
        // and `IpPrefix::new` rejects one. The class-9 link-local allowance is
        // emitted as a literal in `pf::render` for exactly that reason.
        on_link_prefixes: vec![v4([192, 168, 1, 0], 24), v6(0xfd, 0x00, 8)],
        doh_endpoints: vec![v4([1, 1, 1, 1], 32)],
    }
}
