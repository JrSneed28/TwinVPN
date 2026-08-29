//! Renders the nftables ruleset to stdout, so a real `nft(8)` can parse it.
//!
//! **Why this exists.** `nft.rs`'s tests assert on the rendered *string*, which
//! cannot tell a valid ruleset from a plausible-looking one — a typo in a `set`
//! literal or a wrong keyword order reads the same to `String::contains`. The
//! DoH containment rules F-3 added emit two long address sets per family, which
//! is exactly the shape where that gap bites. Piping this into `nft -c -f -`
//! checks them against the real parser.
//!
//! `-c` is a **check**: it parses and validates without committing anything, so
//! this touches no kernel state even when run as root.
//!
//! ```sh
//! # the full registry, both families
//! cargo run -p twinvpn-platform-linux --example dump_ruleset \
//!   | unshare --user --map-root-user --net -- nft -c -f -
//!
//! # and with NO endpoints, which is the registry's `consumer_rule`: an empty
//! # list must leave the port-based denial intact rather than weaken it
//! cargo run -p twinvpn-platform-linux --example dump_ruleset -- empty \
//!   | unshare --user --map-root-user --net -- nft -c -f -
//! ```

use twinvpn_platform::{
    ContractGeneration, DnsConfig, InterfaceIndex, NetworkContract, RouteEntry, Ruleset,
};
use twinvpn_platform_linux::{nft, EnforcementConfig, DEFAULT_FWMARK};
use twinvpn_types::{InterfaceAddress, IpAddr, IpPrefix, PerFamily, V4Addr, V6Addr};

fn v4(o: [u8; 4], len: u32) -> IpPrefix {
    IpPrefix::new(IpAddr::V4(V4Addr::from_octets(o)), len).expect("canonical")
}

/// The pinned product ULA, ADR-0010 §11.1 / AP-1.
fn ula(len: u32) -> IpPrefix {
    let mut o = [0u8; 16];
    o[..6].copy_from_slice(&[0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10]);
    if len == 128 {
        o[15] = 1;
    }
    IpPrefix::new(IpAddr::V6(V6Addr::new(o, None).expect("valid")), len).expect("canonical")
}

fn main() {
    let empty = std::env::args().any(|a| a == "empty");

    let contract = NetworkContract {
        generation: ContractGeneration(1),
        addresses: PerFamily::new(
            vec![
                InterfaceAddress::new(IpAddr::V4(V4Addr::from_octets([100, 64, 0, 1])), 32)
                    .expect("valid"),
            ],
            vec![InterfaceAddress::new(ula(128).address(), 128).expect("valid")],
        ),
        routes: PerFamily::new(
            vec![RouteEntry {
                destination: v4([100, 64, 0, 0], 12),
                via: None,
                interface: InterfaceIndex(3),
                metric: None,
            }],
            vec![RouteEntry {
                destination: ula(48),
                via: None,
                interface: InterfaceIndex(3),
                metric: None,
            }],
        ),
        dns: DnsConfig {
            resolvers: PerFamily::new(Vec::new(), Vec::new()),
            search_domains: Vec::new(),
            split_domains: Vec::new(),
            is_default_resolver: false,
        },
        ruleset: Ruleset::Protected,
        mtu: 1280,
        tunnel_remote_address: None,
    };

    let config = EnforcementConfig {
        overlay_interface: "twin0".to_owned(),
        firewall_mark: DEFAULT_FWMARK,
        cgroup_path: None,
        local_network_access: true,
        on_link_prefixes: vec![v4([192, 168, 1, 0], 24)],
        doh_endpoints: if empty {
            Vec::new()
        } else {
            twinvpn_enforce::doh::KnownResolvers::embedded()
                .expect("the embedded registry parses")
                .endpoints()
        },
    };

    print!("{}", nft::render(&contract, Ruleset::Protected, &config));
}
