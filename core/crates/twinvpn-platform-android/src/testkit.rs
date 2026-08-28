//! Small constructors the unit tests in this crate share.
//!
//! `#[cfg(test)]` only: nothing here ships. It exists so that a test asserting
//! on a rendered programme spends its lines on the assertion rather than on
//! building a `NetworkContract` by hand for the fourth time.

use twinvpn_platform::{ContractGeneration, DnsConfig, NetworkContract, RouteEntry, Ruleset};
use twinvpn_types::{InterfaceAddress, IpAddr, IpPrefix, PerFamily, V4Addr, V6Addr};

/// A minimal but complete contract: both overlay families addressed, no routes,
/// no resolvers, MTU at the §6.2 floor.
///
/// Both families are addressed because ADR-0010 R1 requires the overlay to be
/// dual-stack regardless of what the underlay offers, so a fixture without a v6
/// address would be testing a shape the product does not have.
pub fn contract(generation: u64, ruleset: Ruleset) -> NetworkContract {
    NetworkContract {
        generation: ContractGeneration(generation),
        addresses: PerFamily::new(
            vec![iface_addr("100.64.0.1/32")],
            vec![InterfaceAddress::new(IpAddr::V6(v6(1)), 128).expect("overlay /128")],
        ),
        routes: PerFamily::new(Vec::new(), Vec::new()),
        // The contract carries the remote the tunnel rides. `None` is a real
        // answer: in `Blocked` no path is validated, so there is no remote.
        tunnel_remote_address: None,
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

/// A route entry over `spec`, pointing at interface index 10.
pub fn route(spec: &str) -> RouteEntry {
    RouteEntry {
        destination: prefix(spec),
        via: None,
        interface: twinvpn_platform::InterfaceIndex(10),
        metric: None,
    }
}

/// Parses a `a.b.c.d/len` or `::/len`-shaped literal into an [`IpPrefix`].
///
/// Deliberately tiny and deliberately panicking: it is a test fixture, and a
/// fixture that silently produced the wrong prefix would make every assertion
/// above it meaningless.
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

/// The same literal shape, parsed into an [`InterfaceAddress`].
///
/// Separate from [`prefix`] because X-10 made the two different kinds of value:
/// a route destination is a *range* and must be canonical, an interface address
/// is a *host* address whose bits are the whole point.
pub fn iface_addr(spec: &str) -> InterfaceAddress {
    let (addr, len) = spec.split_once('/').expect("address literal has a /");
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
    InterfaceAddress::new(address, len).expect("interface address")
}

/// A v4 host address.
pub fn host_v4(octets: [u8; 4]) -> IpAddr {
    IpAddr::V4(V4Addr::from_octets(octets))
}

/// A v6 host address inside the product ULA, with `low` in the last two octets.
pub fn host_v6(low: u16) -> IpAddr {
    IpAddr::V6(v6(low))
}

/// The product ULA `fd7c:9e5d:2a10::/48` with `low` in the final two octets.
pub fn v6(low: u16) -> V6Addr {
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1] = 0x7c;
    octets[2] = 0x9e;
    octets[3] = 0x5d;
    octets[4] = 0x2a;
    octets[5] = 0x10;
    octets[14] = (low >> 8) as u8;
    octets[15] = (low & 0xff) as u8;
    V6Addr::new(octets, None).expect("global v6 needs no zone")
}
