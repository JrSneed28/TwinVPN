//! A driver that programs a contract and **prints what the kernel then holds**,
//! so the netlink assertions in `netns.rs` can be checked against `iproute2`'s
//! own view rather than only against themselves.
//!
//! Run it the same way, and read its output:
//!
//! ```sh
//! cd core
//! cargo test -p twinvpn-platform-linux --test state_dump --no-run
//! unshare --user --map-root-user --net -- \
//!   env TWINVPN_NETNS_TEST=1 ./target/debug/deps/state_dump-<hash> \
//!   --nocapture --test-threads=1
//! ```
//!
//! It is a test rather than an example so it compiles in CI and cannot rot, and
//! it asserts the same facts it prints — the printing is for a human, the
//! assertions are for the build.

use std::sync::Arc;

use twinvpn_platform::{
    ContractGeneration, DnsConfig, InterfaceIndex, InterfaceName, LinkState, NetworkContract,
    PlatformAdapter, RouteEntry, Ruleset,
};
use twinvpn_platform_linux::{
    route, AbsentElement, EnforcementConfig, LinuxAdapterParts, LinuxPlatformAdapter,
    DEFAULT_FWMARK,
};
use twinvpn_types::{AddressFamily, InterfaceAddress, IpAddr, PerFamily, V4Addr, V6Addr};

fn privileged() -> bool {
    std::env::var_os("TWINVPN_NETNS_TEST").is_some()
}

#[tokio::test]
async fn program_a_contract_and_show_what_the_kernel_holds() {
    if !privileged() {
        // The unprivileged assertion is `netns.rs`'s; this driver has nothing to
        // add there and says so rather than pretending to have run.
        eprintln!(
            "state_dump: not in a network namespace. Run it under \
             `unshare --user --map-root-user --net` with TWINVPN_NETNS_TEST=1."
        );
        return;
    }

    let dir = std::env::temp_dir().join(format!("twinvpn-dump-{}", std::process::id()));
    let adapter = LinuxPlatformAdapter::new(LinuxAdapterParts {
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
    });

    let handle = adapter
        .tunnel()
        .create_interface(&InterfaceName::new("twin0").expect("valid"), 1280)
        .await
        .expect("creates");
    let index = adapter
        .tunnel_device()
        .index_of(handle)
        .expect("has an index");
    adapter
        .tunnel()
        .set_link(handle, LinkState::Up)
        .await
        .expect("up");

    let mut v6 = [0u8; 16];
    v6[0] = 0xfd;
    v6[1] = 0x7c;
    v6[2] = 0x9e;
    v6[3] = 0x5d;
    v6[4] = 0x2a;
    v6[5] = 0x10;
    let mut v6_host = v6;
    v6_host[15] = 1;

    let contract = NetworkContract {
        generation: ContractGeneration(1),
        addresses: PerFamily::new(
            vec![
                InterfaceAddress::new(IpAddr::V4(V4Addr::from_octets([100, 64, 0, 1])), 32)
                    .expect("valid"),
            ],
            vec![InterfaceAddress::new(
                IpAddr::V6(V6Addr::new(v6_host, None).expect("valid")),
                128,
            )
            .expect("valid")],
        ),
        // `docs/networking.md` §7.2's full-tunnel form: four `/1` routes, two per
        // family, and NEVER a real default route — "the host's own default route
        // is never deleted or modified".
        routes: PerFamily::new(
            route::full_tunnel_destinations()
                .into_iter()
                .filter(|p| p.family() == AddressFamily::V4)
                .map(|destination| RouteEntry {
                    destination,
                    via: None,
                    interface: InterfaceIndex(index),
                    metric: None,
                })
                .collect(),
            route::full_tunnel_destinations()
                .into_iter()
                .filter(|p| p.family() == AddressFamily::V6)
                .map(|destination| RouteEntry {
                    destination,
                    via: None,
                    interface: InterfaceIndex(index),
                    metric: None,
                })
                .collect(),
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
    };

    let applied = route::program(&contract, index, DEFAULT_FWMARK)
        .await
        .expect("programs the full-tunnel form, both families");

    println!("\n=== what the adapter programmed =======================");
    show("ip -brief link show");
    show("ip -brief addr show");
    println!("--- table 52 (docs/networking.md §5.2) ---");
    show("ip -4 route show table 52");
    show("ip -6 route show table 52");
    println!("--- policy rules (ADR-0010 §11.3) ---");
    show("ip -4 rule show");
    show("ip -6 rule show");
    println!("--- the host's MAIN table, which we never touch (§7.2) ---");
    show("ip -4 route show table main");
    println!("=======================================================\n");

    // The assertions the printing exists to make checkable.
    let facts = adapter.interfaces().enumerate().await.expect("enumerates");
    let overlay = facts
        .iter()
        .find(|i| i.name.as_str() == "twin0")
        .expect("exists");
    assert!(overlay.is_up);
    assert_eq!(overlay.mtu, 1280);
    let families: Vec<AddressFamily> = overlay.addresses.iter().map(|p| p.family()).collect();
    assert!(families.contains(&AddressFamily::V4));
    assert!(families.contains(&AddressFamily::V6), "R1: both, always");
    // Four routes + two addresses + two rule pairs.
    assert_eq!(applied.len(), 8);

    route::revert(&applied).await.expect("reverts");
    println!("--- after the revert (ADR-0010 R5: fully reversible) ---");
    show("ip -4 route show table 52");
    show("ip -6 route show table 52");
    show("ip -4 rule show");

    adapter
        .tunnel()
        .destroy_interface(handle)
        .await
        .expect("destroys");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Runs one `iproute2` command and prints it, or says why it could not.
fn show(command: &str) {
    let mut parts = command.split_whitespace();
    let Some(program) = parts.next() else { return };
    match std::process::Command::new(program).args(parts).output() {
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stdout);
            if text.trim().is_empty() {
                println!("$ {command}\n  (empty)");
            } else {
                println!("$ {command}");
                for line in text.lines() {
                    println!("  {line}");
                }
            }
        }
        Err(_) => println!("$ {command}\n  (iproute2 is not installed on this host)"),
    }
}
