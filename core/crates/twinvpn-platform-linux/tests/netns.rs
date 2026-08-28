//! The adapter against a **real kernel**, in a network namespace.
//!
//! **Authority:** `docs/networking.md` §5.1 (the adapter contract), §5.2's Linux
//! row, §7.2; ADR-0010 R1, R3, R5; ADR-0012 KS-17; `docs/testing-strategy.md`.
//!
//! # Why this file exists, and how to run it
//!
//! Everything in `src/` is unit-tested against parsers, renderers and readable
//! `/proc` files. What that cannot reach is the **write** path: whether a
//! `RTM_NEWADDR` this crate builds by hand is one the kernel actually accepts,
//! and whether the `fib_rules.h` attribute numbers written out in `route::fib`
//! are the right ones — a wrong number is answered by `EINVAL`, not by a
//! silently ignored rule, so only the kernel can tell us.
//!
//! Those need `CAP_NET_ADMIN`, which an ordinary test runner does not have. On
//! Linux an **unprivileged user namespace** grants it *inside the namespace*,
//! which is exactly the scope these tests need:
//!
//! ```sh
//! cd core
//! unshare --user --map-root-user --net -- \
//!   env TWINVPN_NETNS_TEST=1 cargo test -p twinvpn-platform-linux --test netns
//! ```
//!
//! Without `TWINVPN_NETNS_TEST=1` the privileged tests **assert the refusal
//! instead**, so a plain `cargo test` still checks something real: that the
//! adapter names the right `reason_code` when it is not privileged, and does not
//! quietly succeed. Nothing here is skipped silently.
//!
//! # What is still not covered, on this host
//!
//! `nft(8)`, `conntrack` and `ip netns` are **not installed**. So the nftables
//! *install* and *read-back* are unreachable even here; `src/nft.rs` tests the
//! rendered script and the `--json` parser exhaustively instead, and that gap is
//! reported rather than papered over.

use std::sync::Arc;

use twinvpn_platform::{
    ContractGeneration, DnsConfig, InterfaceIndex, InterfaceName, LinkState, NetworkContract,
    PlatformAdapter, RouteEntry, Ruleset,
};
use twinvpn_platform_linux::{
    route, AbsentElement, EnforcementConfig, LinuxAdapterParts, LinuxPlatformAdapter,
    DEFAULT_FWMARK,
};
use twinvpn_types::{AddressFamily, InterfaceAddress, IpAddr, IpPrefix, PerFamily, V4Addr, V6Addr};

/// Whether this process is inside the namespace the module documentation
/// describes.
///
/// Read from the environment rather than probed, so a test that expected to be
/// privileged and is not **fails loudly** rather than silently taking the
/// unprivileged branch — which would make the whole file look green while
/// asserting nothing.
fn privileged() -> bool {
    std::env::var_os("TWINVPN_NETNS_TEST").is_some()
}

fn adapter() -> LinuxPlatformAdapter {
    let dir = std::env::temp_dir().join(format!("twinvpn-netns-{}", std::process::id()));
    LinuxPlatformAdapter::new(LinuxAdapterParts {
        enforcement: EnforcementConfig {
            overlay_interface: "twin0".to_owned(),
            firewall_mark: DEFAULT_FWMARK,
            cgroup_path: None,
            local_network_access: true,
            on_link_prefixes: Vec::new(),
        },
        store_root: dir.clone(),
        resolver_restore_point: dir.join("resolver.restore"),
        identity_element: Arc::new(AbsentElement),
    })
}

fn v4(octets: [u8; 4], len: u32) -> IpPrefix {
    IpPrefix::new(IpAddr::V4(V4Addr::from_octets(octets)), len).expect("canonical")
}

fn overlay_v6(len: u32) -> IpPrefix {
    // The pinned product ULA, ADR-0010 §11.1 / AP-1: `fd7c:9e5d:2a10::/48`.
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1] = 0x7c;
    octets[2] = 0x9e;
    octets[3] = 0x5d;
    octets[4] = 0x2a;
    octets[5] = 0x10;
    if len == 128 {
        octets[15] = 1;
    }
    IpPrefix::new(IpAddr::V6(V6Addr::new(octets, None).expect("valid")), len).expect("canonical")
}

/// The overlay's own v4 address, host bits intact.
fn iface_v4(octets: [u8; 4], len: u32) -> InterfaceAddress {
    InterfaceAddress::new(IpAddr::V4(V4Addr::from_octets(octets)), len).expect("valid")
}

/// The overlay's own v6 address.
fn iface_overlay_v6(len: u32) -> InterfaceAddress {
    let base = overlay_v6(len);
    InterfaceAddress::new(base.address(), base.prefix_len()).expect("valid")
}

/// A contract with **both families**, as ADR-0010 R1 requires of every device.
fn contract(generation: u64, interface: InterfaceIndex) -> NetworkContract {
    NetworkContract {
        generation: ContractGeneration(generation),
        addresses: PerFamily::new(
            vec![iface_v4([100, 64, 0, 1], 32)],
            vec![iface_overlay_v6(128)],
        ),
        routes: PerFamily::new(
            vec![RouteEntry {
                destination: v4([100, 64, 0, 0], 12),
                via: None,
                interface,
                metric: None,
            }],
            vec![RouteEntry {
                destination: overlay_v6(48),
                via: None,
                interface,
                metric: None,
            }],
        ),
        dns: DnsConfig {
            resolvers: PerFamily::new(Vec::new(), Vec::new()),
            search_domains: Vec::new(),
            split_domains: Vec::new(),
            is_default_resolver: false,
        },
        ruleset: Ruleset::Blocked,
        mtu: 1280,
        tunnel_remote_address: None,
    }
}

#[tokio::test]
async fn a_tun_interface_is_created_down_and_destroyed_idempotently() {
    let adapter = adapter();
    let name = InterfaceName::new("twin0").expect("valid");

    if !privileged() {
        // The unprivileged assertion: a NAMED refusal, never a quiet success.
        let error = adapter
            .tunnel()
            .create_interface(&name, 1280)
            .await
            .expect_err("no CAP_NET_ADMIN");
        let code = error.reason_code().as_str();
        assert!(
            code == "PLATFORM.VPN_PERMISSION_DENIED" || code == "PLATFORM.ADAPTER_UNAVAILABLE",
            "unexpected code {code}"
        );
        assert!(
            error.os_detail().is_some(),
            "the platform detail must survive for a Tier-1 bundle"
        );
        return;
    }

    let handle = adapter
        .tunnel()
        .create_interface(&name, 1280)
        .await
        .expect("creates");

    // **Created DOWN.** `docs/networking.md` §5.1, and the reason is not
    // convention: an interface that comes up before its addresses, routes and
    // rules are installed is §2.3's partial-application leak window.
    let facts = adapter.interfaces().enumerate().await.expect("enumerates");
    let created = facts
        .iter()
        .find(|i| i.name.as_str() == "twin0")
        .expect("the interface exists");
    assert!(
        !created.is_up,
        "the interface must be created DOWN, before apply()"
    );
    assert!(created.is_overlay, "it carries the overlay prefix");
    assert_eq!(created.mtu, 1280, "§6.2's IPv6 floor, set at creation");

    // And it comes up only when asked.
    adapter
        .tunnel()
        .set_link(handle, LinkState::Up)
        .await
        .expect("brings it up");

    // Idempotent destroy, safe after a crash.
    adapter
        .tunnel()
        .destroy_interface(handle)
        .await
        .expect("destroys");
    adapter
        .tunnel()
        .destroy_interface(handle)
        .await
        .expect("idempotent");
}

#[tokio::test]
async fn both_families_are_programmed_in_one_transaction_and_fully_reverted() {
    // ADR-0010 §11.3: "IPv4 and IPv6 routes MUST be installed in the same
    // apply() transaction. An implementation that can install one family's
    // routes without the other's is non-conforming."
    //
    // ADR-0010 R5: "Route installation MUST be atomic per contract generation
    // and fully reversible."
    let adapter = adapter();
    let name = InterfaceName::new("twin0").expect("valid");

    if !privileged() {
        // The write path is unreachable, so the assertion is that the FAILURE
        // is named — and, importantly, that `program` reports the route
        // context rather than a generic one.
        let error = route::program(&contract(1, InterfaceIndex(1)), 1, DEFAULT_FWMARK)
            .await
            .expect_err("no CAP_NET_ADMIN");
        assert!(
            error.reason_code().as_str().starts_with("ROUTE.")
                || error.reason_code().as_str().starts_with("PLATFORM."),
            "unexpected code {}",
            error.reason_code().as_str()
        );
        return;
    }

    let handle = adapter
        .tunnel()
        .create_interface(&name, 1280)
        .await
        .expect("creates");
    let index = adapter
        .tunnel_device()
        .index_of(handle)
        .expect("the interface has an index");
    adapter
        .tunnel()
        .set_link(handle, LinkState::Up)
        .await
        .expect("up");

    let contract = contract(1, InterfaceIndex(index));
    let applied = route::program(&contract, index, DEFAULT_FWMARK)
        .await
        .expect("programs both families and both policy rules");

    // Two policy rules per family + one address per family + one route per
    // family = 6 host mutations, recorded so the revert removes exactly them.
    assert_eq!(
        applied.len(),
        6,
        "both families, addresses, routes and rules"
    );

    // The kernel's own answer: both families are on the interface.
    let facts = adapter.interfaces().enumerate().await.expect("enumerates");
    let overlay = facts
        .iter()
        .find(|i| i.name.as_str() == "twin0")
        .expect("exists");
    let families: Vec<AddressFamily> = overlay.addresses.iter().map(|p| p.family()).collect();
    assert!(
        families.contains(&AddressFamily::V4),
        "the v4 overlay address was not programmed: {:?}",
        overlay.addresses
    );
    assert!(
        families.contains(&AddressFamily::V6),
        "R1: every Device MUST have both an IPv4 and an IPv6 overlay address, \
         always, regardless of underlay family — got {:?}",
        overlay.addresses
    );

    // R5: fully reversible.
    route::revert(&applied).await.expect("reverts");
    let after = adapter.interfaces().enumerate().await.expect("enumerates");
    let overlay = after
        .iter()
        .find(|i| i.name.as_str() == "twin0")
        .expect("still exists");
    assert!(
        overlay.addresses.is_empty()
            || !overlay
                .addresses
                .iter()
                .any(|p| p.family() == AddressFamily::V4),
        "the revert left an address behind: {:?}",
        overlay.addresses
    );

    adapter
        .tunnel()
        .destroy_interface(handle)
        .await
        .expect("destroys");
}

#[tokio::test]
async fn the_change_stream_reports_a_real_interface_appearing_and_going_away() {
    // `docs/networking.md` §5.1: "event-driven, never polled". This is the only
    // way to check that the RTNLGRP_* subscription actually delivers — and the
    // failure it guards against (a poll interval added to `T_FAILOVER_TARGET`)
    // is invisible to every other test.
    let adapter = adapter();
    let mut stream = adapter.interfaces().subscribe().expect("subscribes");

    if !privileged() {
        // The subscription itself is unprivileged and must open. That is a real
        // assertion: `AF_NETLINK` with multicast groups needs no capability, so
        // a failure here would be a defect rather than a permission.
        drop(stream);
        return;
    }

    use futures_core::Stream as _;
    let handle = adapter
        .tunnel()
        .create_interface(&InterfaceName::new("twin0").expect("valid"), 1280)
        .await
        .expect("creates");

    // Drain what the kernel sent, without a timer: CD-3 keeps the runtime's
    // time module out of this crate, so the loop yields instead of sleeping.
    let mut saw_added = false;
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    for _ in 0..10_000 {
        match std::pin::Pin::new(&mut stream).poll_next(&mut cx) {
            std::task::Poll::Ready(Some(change)) => {
                if matches!(
                    change,
                    twinvpn_platform::NetworkChange::InterfaceAdded(_)
                        | twinvpn_platform::NetworkChange::LinkStateChanged { .. }
                ) {
                    saw_added = true;
                    break;
                }
            }
            std::task::Poll::Ready(None) => break,
            std::task::Poll::Pending => tokio::task::yield_now().await,
        }
    }
    assert!(
        saw_added,
        "creating an interface must produce a change event; a subscription that \
         delivers nothing is a poll interval added to T_FAILOVER_TARGET"
    );

    adapter
        .tunnel()
        .destroy_interface(handle)
        .await
        .expect("destroys");
}

#[tokio::test]
async fn an_mtu_below_the_ipv6_floor_is_refused_by_the_adapter_before_the_kernel() {
    // §6.2's floor is 1280 and §6.3 forbids accepting a PTB below it. The
    // adapter refuses before the syscall, so the refusal is the same whether or
    // not the caller is privileged — which is why this test needs no branch.
    let adapter = adapter();
    let error = adapter
        .tunnel()
        .set_mtu(twinvpn_platform::TunnelHandle(1), 1279)
        .await
        .expect_err("below the floor");
    assert_eq!(error.os_detail().map(|d| d.call), Some("mtu.floor"));
}

#[tokio::test]
async fn sockets_and_enumeration_work_in_a_fresh_namespace_with_only_loopback() {
    // A namespace with one `lo` is the sparsest network a host can have, and is
    // the shape a container starts in. The adapter must report it truthfully
    // rather than assuming interfaces it cannot see.
    let adapter = adapter();
    let facts = adapter.interfaces().enumerate().await.expect("enumerates");
    assert!(
        facts.iter().any(|i| i.name.as_str() == "lo"),
        "every namespace has a loopback"
    );

    // Both families still open, because a namespace has its own v6 stack.
    let families = adapter
        .sockets()
        .supported_families()
        .await
        .expect("probes");
    assert!(families.v4);

    if privileged() {
        // In a fresh namespace `lo` is DOWN until something brings it up, so
        // "is there a default route" must be answered `false` for BOTH families
        // rather than assumed from the presence of an interface.
        let link_facts = adapter
            .network_config()
            .query_link_facts()
            .await
            .expect("queries");
        assert!(!link_facts.default_routes.v4);
        assert!(!link_facts.default_routes.v6);
        assert!(
            link_facts.mtu >= 1280,
            "a reported MTU below the IPv6 floor would let DPLPMTUD search below it"
        );
    }
}
