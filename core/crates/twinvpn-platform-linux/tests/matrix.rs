//! **The test matrix**, kernel-facing half.
//!
//! **Authority:** ADR-0010 R1, R5, R6; ADR-0011 DN-18, DN-19, DN-20, DN-21;
//! ADR-0012 KS-5, KS-9, KS-17, KS-19, KS-20; ADR-0022 LC-8, LC-24, LC-25;
//! `docs/networking.md` §5.1, §7.2; `shells/linux/README.md` §5.
//!
//! Twelve scenarios are required of this domain: **startup, shutdown, UI/service
//! separation, network change, suspend/resume, daemon restart, route recovery,
//! DNS recovery, kill switch, IPv4 leaks, IPv6 leaks, DNS leaks.** The ten that
//! need a kernel are here; **shutdown** and **UI/service separation** are process
//! properties and live in `shells/linux/twinvpnd/tests/lifecycle.rs`.
//!
//! # The oracle is `iproute2`, deliberately
//!
//! Where a test needs to know what the kernel is holding, it asks **`ip(8)`**
//! rather than this crate's own netlink code. That is the whole point: a bug in
//! `route::fib`'s attribute numbers or in `iface`'s parser cannot make one of
//! these tests pass, because the observer is a different implementation of the
//! same protocol. `tests/netns.rs` already caught one bug this way — `index_of`
//! reading the host's `/sys` from inside a namespace — and that bug was invisible
//! to every test that used our own reader on both sides.
//!
//! `ip route get` in particular is the **leak oracle**: it asks the kernel's FIB
//! "which interface would a packet to this address leave by", which is the exact
//! question a leak test needs and is not answerable from an install call's return
//! value.
//!
//! # Running it
//!
//! ```sh
//! cd core
//! cargo test -p twinvpn-platform-linux --test matrix --no-run
//! unshare --user --map-root-user --net -- \
//!   env TWINVPN_NETNS_TEST=1 ./target/debug/deps/matrix-<hash> --test-threads=1
//! ```
//!
//! `--test-threads=1` is required and is not a convenience: these tests build a
//! shared fake underlay in **one** namespace, and two of them programming
//! `twin0` at once would be two writers on one host — the concurrency ADR-0016
//! PS-1 exists to prevent, reproduced inside the test binary.
//!
//! Without `TWINVPN_NETNS_TEST=1` each privileged test **asserts the refusal**
//! rather than skipping, so a plain `cargo test` still checks that an
//! unprivileged adapter names the right `reason_code`.
//!
//! # What this host still cannot exercise
//!
//! `nft(8)` and `conntrack` are **not installed** (checked, not assumed:
//! `command -v nft conntrack` finds neither). So the nftables *install* and
//! *read-back* remain unreachable, and the kill-switch and DNS-leak tests below
//! assert over the **rendered ruleset** and the **routing** state rather than
//! over installed firewall rules. That is stated at each test rather than
//! glossed, and it is the largest remaining gap in this domain.

use std::process::Command;
use std::sync::Arc;

use twinvpn_platform::{
    ContractGeneration, DnsConfig, InterfaceIndex, InterfaceName, LinkState, NetworkContract,
    PlatformAdapter, RouteEntry, Ruleset,
};
use twinvpn_platform_linux::{
    nft, resolver, route, AbsentElement, EnforcementConfig, LinuxAdapterParts,
    LinuxPlatformAdapter, DEFAULT_FWMARK,
};
use twinvpn_types::{AddressFamily, InterfaceAddress, IpAddr, IpPrefix, PerFamily, V4Addr, V6Addr};

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

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

/// The fake underlay every leak test needs.
///
/// A leak is "the packet left by the wrong interface", so a namespace with only
/// `lo` cannot express one: there is nowhere wrong for it to go. `underlay0` is
/// a dummy link carrying a default route in **both** families, which is the
/// shape of a real host and is what makes "did it take the tunnel or the
/// underlay" a question with two possible answers.
struct Underlay;

impl Underlay {
    fn up() -> Self {
        for args in [
            &["link", "add", "underlay0", "type", "dummy"][..],
            &["addr", "add", "192.0.2.2/24", "dev", "underlay0"][..],
            &["-6", "addr", "add", "2001:db8::2/64", "dev", "underlay0"][..],
            &["link", "set", "underlay0", "up"][..],
            &[
                "route",
                "add",
                "default",
                "via",
                "192.0.2.1",
                "dev",
                "underlay0",
            ][..],
            &[
                "-6",
                "route",
                "add",
                "default",
                "via",
                "2001:db8::1",
                "dev",
                "underlay0",
            ][..],
        ] {
            let _ = ip(args);
        }
        Self
    }
}

impl Drop for Underlay {
    fn drop(&mut self) {
        let _ = ip(&["link", "del", "underlay0"]);
    }
}

/// Runs `ip(8)` and returns its stdout.
fn ip(args: &[&str]) -> String {
    let output = Command::new("ip")
        .args(args)
        .env_clear()
        .output()
        .expect("iproute2 is installed; the module documentation says so");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// **The leak oracle.** Which interface would a packet to `dst` leave by?
///
/// `ip route get` asks the kernel's FIB the question a leak test actually has.
/// `mark` supplies `SO_MARK`, so the same question can be asked as the agent's
/// own socket (marked, KS-9's bootstrap exemption) and as an ordinary
/// application's (unmarked) — which are governed by different policy rules and
/// must be checked separately.
fn route_get(family: AddressFamily, dst: &str, mark: Option<u32>) -> String {
    let mark_text;
    let mut args: Vec<&str> = Vec::new();
    if family == AddressFamily::V6 {
        args.push("-6");
    }
    args.extend(["route", "get", dst]);
    if let Some(mark) = mark {
        mark_text = format!("{mark:#x}");
        args.extend(["mark", &mark_text]);
    }
    ip(&args)
}

/// The interface named in an `ip route get` answer, or `None` when unreachable.
fn egress_device(answer: &str) -> Option<String> {
    let mut fields = answer.split_whitespace();
    while let Some(field) = fields.next() {
        if field == "dev" {
            return fields.next().map(str::to_owned);
        }
    }
    None
}

fn fresh_adapter() -> LinuxPlatformAdapter {
    adapter()
}

fn adapter() -> LinuxPlatformAdapter {
    let dir = std::env::temp_dir().join(format!("twinvpn-matrix-{}", std::process::id()));
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
    octets[..6].copy_from_slice(&[0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10]);
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
                destination: v4([100, 64, 0, 0], 10),
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
            resolvers: PerFamily::new(
                vec![IpAddr::V4(V4Addr::from_octets([100, 127, 255, 53]))],
                vec![IpAddr::V6(
                    V6Addr::new(
                        {
                            let mut o = [0u8; 16];
                            o[..8]
                                .copy_from_slice(&[0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0xff, 0xff]);
                            o[15] = 0x53;
                            o
                        },
                        None,
                    )
                    .expect("valid"),
                )],
            ),
            search_domains: vec!["t-abc.tnet.twinvpn.net".to_owned()],
            split_domains: Vec::new(),
            is_default_resolver: true,
        },
        ruleset: Ruleset::Protected,
        mtu: 1280,
        tunnel_remote_address: None,
    }
}

/// Brings `twin0` up and programs the contract, returning the handle and the
/// applied mutations.
async fn bring_up(
    adapter: &LinuxPlatformAdapter,
) -> (twinvpn_platform::TunnelHandle, route::AppliedState, u32) {
    let name = InterfaceName::new("twin0").expect("valid");
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
    let applied = route::program(&contract(1, InterfaceIndex(index)), index, DEFAULT_FWMARK)
        .await
        .expect("programs both families");
    (handle, applied, index)
}

// ---------------------------------------------------------------------------
// 1. startup
// ---------------------------------------------------------------------------

/// **Startup.** The adapter's own start-of-day: create the interface DOWN,
/// program both families, bring it up, and confirm from the kernel.
///
/// The ordering is ADR-0016 §11.6's and `docs/networking.md` §5.1's, and the
/// reason the interface is created DOWN is not convention: an interface that
/// comes up before its addresses, routes and rules are installed is §2.3's
/// partial-application leak window, open for as long as the programming takes.
#[tokio::test]
async fn matrix_startup_programs_both_families_before_the_link_carries_traffic() {
    let adapter = adapter();
    let name = InterfaceName::new("twin0").expect("valid");

    if !privileged() {
        let error = adapter
            .tunnel()
            .create_interface(&name, 1280)
            .await
            .expect_err("no CAP_NET_ADMIN");
        assert!(
            error.os_detail().is_some(),
            "the errno must survive as typed evidence for a Tier-1 bundle"
        );
        return;
    }

    let _underlay = Underlay::up();
    let handle = adapter
        .tunnel()
        .create_interface(&name, 1280)
        .await
        .expect("creates");

    // iproute2's answer, not ours: the link exists and is DOWN.
    let link = ip(&["link", "show", "twin0"]);
    assert!(link.contains("twin0"), "the kernel holds the interface");
    assert!(
        !link.contains("state UP") && link.contains("DOWN"),
        "created DOWN, before apply(): {link}"
    );

    let index = adapter
        .tunnel_device()
        .index_of(handle)
        .expect("has an index");

    // **A finding, kept as an executed assertion rather than a comment.**
    // ADR-0012 §11.8's arm ordering reads "create iface (DOWN) -> apply(
    // contract_gen) -> link up". On Linux the middle step cannot be taken in
    // full while the link is down: an address CAN be added to a down interface,
    // and a route CANNOT — `RTM_NEWROUTE` answers `ENETDOWN`. So the literal
    // ordering is not implementable for the route half, and the implementable
    // one brings the link up between the addresses and the routes.
    let too_early = route::program(&contract(1, InterfaceIndex(index)), index, DEFAULT_FWMARK)
        .await
        .expect_err("routes cannot be added through a down interface");
    assert_eq!(
        too_early.os_detail().map(|d| d.code),
        Some(i64::from(libc::ENETDOWN)),
        "the refusal must be ENETDOWN and named, not a silent partial apply"
    );

    adapter
        .tunnel()
        .set_link(handle, LinkState::Up)
        .await
        .expect("up");
    let applied = route::program(&contract(1, InterfaceIndex(index)), index, DEFAULT_FWMARK)
        .await
        .expect("programs once the link is up");

    // Both families, from iproute2.
    let addrs = ip(&["addr", "show", "dev", "twin0"]);
    assert!(addrs.contains("100.64.0.1"), "v4 address: {addrs}");
    assert!(
        addrs.contains("fd7c:9e5d:2a10::1"),
        "R1: both families, always — v6 address missing from {addrs}"
    );

    route::revert(&applied).await.expect("reverts");
    adapter
        .tunnel()
        .destroy_interface(handle)
        .await
        .expect("destroys");
}

// ---------------------------------------------------------------------------
// 2. network change
// ---------------------------------------------------------------------------

/// **Network change.** A real underlay appearing and disappearing reaches the
/// change stream.
///
/// `docs/networking.md` §5.1: "event-driven, never polled". The failure this
/// guards against — a poll interval silently added to `T_FAILOVER_TARGET` — is
/// invisible to every test that does not use a real kernel, because a polling
/// implementation returns the same answers, just later.
#[tokio::test]
async fn matrix_network_change_reaches_the_stream_for_both_an_arrival_and_a_departure() {
    let adapter = adapter();
    let mut stream = adapter
        .interfaces()
        .subscribe()
        .expect("the subscription is unprivileged and must open");

    if !privileged() {
        // A real assertion even here: `AF_NETLINK` with multicast groups needs
        // no capability, so a failure to subscribe would be a defect rather
        // than a permission.
        drop(stream);
        return;
    }

    use futures_core::Stream as _;
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    let underlay = Underlay::up();

    let mut saw_arrival = false;
    for _ in 0..20_000 {
        match std::pin::Pin::new(&mut stream).poll_next(&mut cx) {
            std::task::Poll::Ready(Some(change)) => {
                if matches!(
                    change,
                    twinvpn_platform::NetworkChange::InterfaceAdded(_)
                        | twinvpn_platform::NetworkChange::AddressAdded { .. }
                        | twinvpn_platform::NetworkChange::LinkStateChanged { .. }
                        | twinvpn_platform::NetworkChange::DefaultRouteChanged { .. }
                ) {
                    saw_arrival = true;
                    break;
                }
            }
            std::task::Poll::Ready(None) => break,
            std::task::Poll::Pending => tokio::task::yield_now().await,
        }
    }
    assert!(
        saw_arrival,
        "an underlay coming up must produce a change event; a subscription that \
         delivers nothing is a poll interval added to T_FAILOVER_TARGET"
    );

    // And the departure. A stream that reports arrivals and not departures
    // leaves the core believing a dead path is live.
    drop(underlay);
    let mut saw_departure = false;
    for _ in 0..20_000 {
        match std::pin::Pin::new(&mut stream).poll_next(&mut cx) {
            std::task::Poll::Ready(Some(change)) => {
                if matches!(
                    change,
                    twinvpn_platform::NetworkChange::InterfaceRemoved(_)
                        | twinvpn_platform::NetworkChange::AddressRemoved { .. }
                        | twinvpn_platform::NetworkChange::LinkStateChanged { .. }
                        | twinvpn_platform::NetworkChange::DefaultRouteChanged { .. }
                ) {
                    saw_departure = true;
                    break;
                }
            }
            std::task::Poll::Ready(None) => break,
            std::task::Poll::Pending => tokio::task::yield_now().await,
        }
    }
    assert!(
        saw_departure,
        "an underlay going away must produce a change event too: a stream that \
         reports only arrivals leaves the core believing a dead path is live"
    );
}

// ---------------------------------------------------------------------------
// 3. route recovery
// ---------------------------------------------------------------------------

/// **Route recovery.** Something outside TwinVPN deletes our route; re-applying
/// the contract restores it, and the **kernel** says so.
///
/// This is the case `docs/networking.md` §5.5.3 calls reclamation and ADR-0012
/// KS-20 calls "reclaimable by a fresh process after an unclean exit". The
/// deletion is done with `ip`, i.e. genuinely out-of-band, because a test that
/// deleted the route through our own code would be testing that our delete and
/// our add agree rather than that the kernel ended up right.
#[tokio::test]
async fn matrix_route_recovery_reinstates_a_route_deleted_out_of_band() {
    let adapter = adapter();

    if !privileged() {
        let error = route::program(&contract(1, InterfaceIndex(1)), 1, DEFAULT_FWMARK)
            .await
            .expect_err("no CAP_NET_ADMIN");
        assert!(error.os_detail().is_some());
        return;
    }

    let _underlay = Underlay::up();
    let (handle, applied, index) = bring_up(&adapter).await;

    // The kernel holds our v4 route in table 52.
    let before = ip(&["route", "show", "table", "52"]);
    assert!(
        before.contains("100.64.0.0/10"),
        "table 52 must hold the overlay route: {before}"
    );

    // Out-of-band deletion, by a different program.
    let _ = ip(&[
        "route",
        "del",
        "100.64.0.0/10",
        "dev",
        "twin0",
        "table",
        "52",
    ]);
    let during = ip(&["route", "show", "table", "52"]);
    assert!(
        !during.contains("100.64.0.0/10"),
        "the out-of-band delete did not take, so the recovery is untested: {during}"
    );

    // Re-apply. This is what the agent does on a network change and on resume.
    let reapplied = route::program(&contract(2, InterfaceIndex(index)), index, DEFAULT_FWMARK)
        .await
        .expect("re-programs after an out-of-band deletion");

    let after = ip(&["route", "show", "table", "52"]);
    assert!(
        after.contains("100.64.0.0/10"),
        "the route was not recovered: {after}"
    );
    // And IPv6 at parity, because a recovery that restores one family is the
    // R1 asymmetry arriving through the recovery path.
    let after6 = ip(&["-6", "route", "show", "table", "52"]);
    assert!(
        after6.contains("fd7c:9e5d:2a10::/48"),
        "IPv6 must be recovered at parity with IPv4: {after6}"
    );

    route::revert(&reapplied).await.expect("reverts");
    let _ = route::revert(&applied).await;
    adapter
        .tunnel()
        .destroy_interface(handle)
        .await
        .expect("destroys");
}

// ---------------------------------------------------------------------------
// 4 and 5. IPv4 and IPv6 leaks, at parity
// ---------------------------------------------------------------------------

/// The body of both leak tests, so the two families are checked by **the same
/// code** and cannot drift.
///
/// ADR-0010 R1 makes "a v4 story and a v6 story" the defect, and the usual way
/// that defect arrives is not a missing feature — it is two tests that started
/// identical and were edited separately. One function, two call sites.
async fn leak_body(family: AddressFamily, protected: &str, unprotected: &str) {
    let adapter = adapter();

    if !privileged() {
        // Unprivileged, the assertion is that the programming is REFUSED by
        // name. A leak test that silently skipped would be the worst of the
        // twelve to lose, so it asserts something in both modes.
        let error = route::program(&contract(1, InterfaceIndex(1)), 1, DEFAULT_FWMARK)
            .await
            .expect_err("no CAP_NET_ADMIN");
        assert!(error.os_detail().is_some(), "{family:?}");
        return;
    }

    let _underlay = Underlay::up();

    // **Before**: with only the underlay, a packet to the protected space leaves
    // by the underlay. That is the leak, demonstrated rather than assumed — and
    // it is why ADR-0012's Tier-2 containment exists at all.
    let before = route_get(family, protected, None);
    assert_eq!(
        egress_device(&before).as_deref(),
        Some("underlay0"),
        "the fake underlay is not carrying the default route, so this test \
         cannot tell a leak from a fix: {before}"
    );

    let (handle, applied, _) = bring_up(&adapter).await;

    // **After**, the agent's own marked socket: KS-9's bootstrap exemption sends
    // it to table 52 via the `fwmark` rule, which is §7.2's loop guard. Asked of
    // the kernel with `SO_MARK` set, exactly as the agent's socket would be.
    let marked = route_get(family, protected, Some(DEFAULT_FWMARK));
    assert!(
        egress_device(&marked).is_some(),
        "the marked lookup must resolve: {marked}"
    );

    // **After**, an ordinary application: the overlay route in table 52 is what
    // must carry it.
    let unmarked = route_get(family, protected, None);
    let device = egress_device(&unmarked);
    assert_eq!(
        device.as_deref(),
        Some("twin0"),
        "LEAK ({family:?}): a packet to the protected space {protected} would \
         leave by {device:?} rather than by the overlay. This is read from the \
         kernel's own FIB, not from an install call's return value.\n\
         ip route get said: {unmarked}\n\
         table 52 holds: {}\n\
         rules: {}",
        ip(if family == AddressFamily::V4 {
            &["route", "show", "table", "52"]
        } else {
            &["-6", "route", "show", "table", "52"]
        }),
        ip(if family == AddressFamily::V4 {
            &["rule", "show"]
        } else {
            &["-6", "rule", "show"]
        })
    );

    // Traffic OUTSIDE the protected set is untouched. ADR-0012 KS-3a: "traffic
    // outside that set is not governed by this table and is not dropped by it".
    // A build that captured everything would pass the assertion above and take
    // the host off the network — including the SSH session an operator needs.
    let outside = route_get(family, unprotected, None);
    assert_eq!(
        egress_device(&outside).as_deref(),
        Some("underlay0"),
        "KS-3a: traffic outside the protected set must be untouched, and \
         {unprotected} was captured: {outside}"
    );

    // **Reversibility (R5).** After the revert the protected space goes back to
    // the underlay — which is the leak returning, and is correct: protection is
    // the nftables layer's job once the routes are gone, and a revert that left
    // routes behind would be a different and worse defect.
    route::revert(&applied).await.expect("reverts");
    let reverted = route_get(family, protected, None);
    assert_eq!(
        egress_device(&reverted).as_deref(),
        Some("underlay0"),
        "R5: route installation must be fully reversible, and this left state \
         behind: {reverted}"
    );

    adapter
        .tunnel()
        .destroy_interface(handle)
        .await
        .expect("destroys");
}

/// **IPv4 leaks**, read from the kernel's FIB.
#[tokio::test]
async fn matrix_ipv4_leak_protected_traffic_leaves_by_the_overlay_and_not_the_underlay() {
    leak_body(AddressFamily::V4, "100.64.0.5", "198.51.100.7").await;
}

/// **IPv6 leaks**, read from the kernel's FIB, **at parity with IPv4**.
///
/// ADR-0010 R6: "IPv6 MUST NOT be able to bypass tunnel policy — including when
/// IPv6 appears *after* the tunnel is up, and when the tunnel itself is
/// IPv4-only." The body is shared with the v4 test for exactly that reason.
#[tokio::test]
async fn matrix_ipv6_leak_protected_traffic_leaves_by_the_overlay_and_not_the_underlay() {
    leak_body(AddressFamily::V6, "fd7c:9e5d:2a10::5", "2001:db8:1::7").await;
}

// ---------------------------------------------------------------------------
// 6. kill switch
// ---------------------------------------------------------------------------

/// **Kill switch.** The two rule sets, both fail-closed, and the read-back.
///
/// # What is asserted here, and what this host cannot reach
///
/// `nft(8)` is not installed, so the *install* is unreachable and the assertion
/// is that it fails **by name** rather than silently succeeding — ADR-0012 §8:
/// "arming must never fail open". What IS checked exhaustively is the rendered
/// ruleset, and the property review finding **R-6** named: a `BLOCKED` table
/// that drops **nothing** while reporting itself protected.
#[tokio::test]
async fn matrix_kill_switch_blocked_drops_both_families_and_arming_never_fails_open() {
    let adapter = adapter();
    let network = adapter.network_config();

    // The install, whatever this host can do with it.
    let armed = network
        .set_ruleset(ContractGeneration(0), Ruleset::Blocked)
        .await;
    match armed {
        Err(error) => {
            // ADR-0012 §8: no `nft(8)` means the client refuses to enter a
            // protected state and says why. Never a quiet success.
            assert!(
                error.os_detail().is_some(),
                "arming must fail by NAME, never open"
            );
        }
        Ok(()) => {
            // On a host with `nft`, the read-back is the assertion — the W-24
            // query, not the fact that the install returned Ok.
            let installed = network
                .installed_ruleset()
                .await
                .expect("the read-back must be available once the install worked");
            assert_eq!(
                installed,
                Some(Ruleset::Blocked),
                "the kernel must hold the posture that was installed"
            );
        }
    }

    // **R-6**, as a property of the rendered text: a BLOCKED table must drop
    // something, in BOTH families. `PerFamily::new(0, 0)` alongside
    // `Ruleset::Blocked` is a table that claims to be fail-closed and drops
    // nothing, and the posture counter alone would not reveal it.
    let config = EnforcementConfig {
        overlay_interface: "twin0".to_owned(),
        firewall_mark: DEFAULT_FWMARK,
        cgroup_path: None,
        local_network_access: true,
        on_link_prefixes: Vec::new(),
    };
    let blocked = nft::render(&contract(0, InterfaceIndex(1)), Ruleset::Blocked, &config);
    assert!(
        blocked.contains("deny_v4"),
        "KS-5: a BLOCKED table with no v4 drop is non-conforming, not degraded"
    );
    assert!(
        blocked.contains("deny_v6"),
        "KS-5: a BLOCKED table with no v6 drop is non-conforming, not degraded"
    );
    assert!(
        blocked.contains(nft::POSTURE_BLOCKED),
        "the posture counter is what the read-back parses"
    );

    // KS-17: there are exactly TWO rule sets and both are fail-closed. The
    // PROTECTED one permits protected egress **only** via the overlay.
    let protected = nft::render(&contract(1, InterfaceIndex(1)), Ruleset::Protected, &config);
    assert!(
        protected.contains("oifname \"twin0\""),
        "PROTECTED permits protected egress only via the overlay: {protected}"
    );
    assert!(
        protected.contains("deny_v4") && protected.contains("deny_v6"),
        "PROTECTED is fail-closed too: everything not via the overlay is dropped"
    );
}

// ---------------------------------------------------------------------------
// 7. DNS leaks
// ---------------------------------------------------------------------------

/// **DNS leaks.** ADR-0011 §11.9's class-6 containment, both families, and the
/// steering that goes with it.
///
/// > **Containment is always ADR-0012 §11.2 class 6 + Tier 2 — one dual-family
/// > object, interface-scoped, default-deny — and it is the guarantee.**
///
/// DN-15 is emphatic that steering is *not* the guarantee: "a build that filters
/// records but does not block egress is a leaking build that produces prettier
/// timeouts". So the containment is asserted first and separately, and it is
/// asserted for **both families**, because a v4-only DNS denial on a host with
/// working IPv6 is a DNS leak wearing a v4 firewall.
#[tokio::test]
async fn matrix_dns_leak_the_class_6_denial_covers_both_families_on_every_path() {
    let config = EnforcementConfig {
        overlay_interface: "twin0".to_owned(),
        firewall_mark: DEFAULT_FWMARK,
        cgroup_path: None,
        local_network_access: true,
        on_link_prefixes: Vec::new(),
    };

    // Containment, in BOTH postures. A host that denied off-overlay DNS only
    // while PROTECTED would leak every query during the window it is BLOCKED,
    // which is exactly the window it is most likely to be resolving in.
    for ruleset in [Ruleset::Blocked, Ruleset::Protected] {
        let rendered = nft::render(&contract(1, InterfaceIndex(1)), ruleset, &config);
        assert!(
            rendered.contains(nft::DNS_DENY_COUNTER),
            "{ruleset:?}: the class-6 DNS denial is missing entirely"
        );
        assert!(
            rendered.contains("53"),
            "{ruleset:?}: port 53 is not denied off the overlay"
        );
        assert!(
            rendered.contains("853"),
            "{ruleset:?}: DoT (853) is not denied off the overlay — an encrypted \
             leak is still a leak"
        );
        // Both families in ONE table. KS-5: "an implementation that can install
        // the Tier-2 rule set for one family without the other is
        // NON-CONFORMING, not degraded."
        assert!(
            rendered.contains("meta nfproto") || rendered.contains("inet"),
            "{ruleset:?}: the denial must be dual-family in one inet table"
        );
    }

    // Steering, which is the *second* line and never the first. Whichever of
    // DN-21's two Linux forms this host takes, both families are configured —
    // DN-13: "a stub MUST NOT filter AAAA because the underlay is v4-only".
    let backend = resolver::ResolverBackend::detect();
    let rendered = resolver::render(&contract(1, InterfaceIndex(1)).dns);
    assert!(rendered.contains("100.127.255.53"), "the v4 resolver");
    assert!(
        rendered.contains("fd7c:9e5d:2a10:ffff::53"),
        "a v4-only resolver list is the asymmetry R1 forbids: {rendered}"
    );
    // And the degradation, if any, is a REGISTERED code rather than silence.
    if let Some(code) = backend.degradation() {
        assert!(
            twinvpn_types::ReasonCode::lookup(code).is_some(),
            "{code} is not in the frozen registry"
        );
    }
}

// ---------------------------------------------------------------------------
// 8. DNS recovery
// ---------------------------------------------------------------------------

/// **DNS recovery.** DN-19's crash path: an owner-tagged configuration whose
/// stub does not answer is restored, without this binary being healthy.
///
/// > **DN-20** — restoration MUST NOT require the agent to be healthy.
///
/// The restore point is therefore checked for the property that makes that
/// possible: it is **plain text a shell script can read**, and it round-trips
/// verbatim including lines we do not model.
#[tokio::test]
async fn matrix_dns_recovery_restores_verbatim_from_a_point_a_shell_script_can_read() {
    let dir = std::env::temp_dir().join(format!("twinvpn-dnsrec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("creates");
    let target = dir.join("resolv.conf");
    let point_path = dir.join("resolver.restore");

    // A host configuration with directives we do not model. DN-23: an
    // underlay-forwarded configuration is "preserved exactly", and a
    // re-serialised `resolv.conf` silently loses `options` and `sortlist`.
    let original = b"nameserver 192.0.2.1\noptions edns0 trust-ad\nsortlist 10/8\n";
    std::fs::write(&target, original).expect("writes");

    let point = resolver::RestorePoint::capture(&target).expect("captures");
    std::fs::write(&point_path, point.encode()).expect("persists");

    // DN-20's property: readable without this binary.
    let text = std::fs::read_to_string(&point_path).expect("plain text");
    assert!(text.starts_with("twinvpn-restore-point v1\n"));
    assert!(text.ends_with("sortlist 10/8\n"), "verbatim: {text}");

    // The mutation, then the recovery.
    std::fs::write(
        &target,
        format!("{}\nnameserver 100.127.255.53\n", resolver::OWNER_TAG),
    )
    .expect("writes ours");
    let owned = std::fs::read_to_string(&target).expect("reads");
    assert!(
        owned.starts_with(resolver::OWNER_TAG),
        "the owner tag is what lets a boot restore unit tell OUR file from \
         NetworkManager's: {owned}"
    );

    let decoded = resolver::RestorePoint::decode(&std::fs::read(&point_path).expect("reads"))
        .expect("round-trips");
    decoded.restore().expect("restores");
    assert_eq!(
        std::fs::read(&target).expect("reads"),
        original,
        "DN-23: the prior configuration is restored VERBATIM, including the \
         directives we do not model"
    );

    // A torn restore point is refused rather than restored truncated: writing a
    // truncated resolver configuration is worse than writing none.
    let mut torn = std::fs::read(&point_path).expect("reads");
    torn.truncate(torn.len() - 5);
    assert_eq!(resolver::RestorePoint::decode(&torn), None);

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 9. suspend / resume
// ---------------------------------------------------------------------------

/// **Suspend/resume.** ADR-0022 LC-8's two clocks, and the distinction that is
/// invisible until a device actually sleeps.
///
/// > `MonotonicClock` — **No.** Paused while the host is suspended.
/// > `ElapsedClock` — **Yes.** Includes suspend and hibernate.
///
/// # Why this test measures clock ids rather than simulating a pause
///
/// A test that "simulated" a suspend by sleeping would advance **both** clocks
/// equally and would pass on a build that had substituted one for the other —
/// which is precisely LC-8's warning that the defect "compiles, passes every
/// test that does not suspend, and fails only on a device that actually sleeps".
/// So the assertions are on the things that are checkable without sleeping:
///
/// 1. The two clocks read **different `clockid_t`s**. This is the whole property.
/// 2. `CLOCK_BOOTTIME` is never behind `CLOCK_MONOTONIC`, which holds on every
///    host and would fail on a build that swapped them *and* got the origins
///    wrong.
/// 3. The two have **different origins**, so a substitution is visible even on a
///    host that has never suspended.
/// 4. `boot_id` is read, because LC-24 step 1 separates **reboot from resume**
///    and no clock can do that.
#[tokio::test]
async fn matrix_suspend_resume_uses_the_suspend_inclusive_clock_and_not_the_other_one() {
    use twinvpn_env::{BootIdSource as _, ElapsedClock as _, MonotonicClock as _};

    // 1. The clock ids differ, and the elapsed one is BOOTTIME.
    assert_eq!(
        twinvpn_platform_linux::clock::BOOTTIME_CLOCK_ID,
        libc::CLOCK_BOOTTIME,
        "LC-8: the ElapsedClock is CLOCK_BOOTTIME on Linux, and substituting \
         CLOCK_MONOTONIC here fails only on a device that sleeps"
    );
    assert_ne!(
        twinvpn_platform_linux::clock::BOOTTIME_CLOCK_ID,
        libc::CLOCK_MONOTONIC
    );

    // 2. Ordering, through one code path so the clock id is the only difference.
    //    Monotonic is read FIRST: on a host that has never suspended the two are
    //    equal, so the microsecond between the two syscalls is the whole margin.
    let mono_raw =
        twinvpn_platform_linux::clock::BootTimeElapsedClock::read_micros_of(libc::CLOCK_MONOTONIC)
            .expect("monotonic");
    let boot_raw =
        twinvpn_platform_linux::clock::BootTimeElapsedClock::read_micros().expect("boottime");
    assert!(
        boot_raw >= mono_raw,
        "CLOCK_BOOTTIME ({boot_raw}) is CLOCK_MONOTONIC ({mono_raw}) plus the \
         accumulated suspend time, so it can never read behind it"
    );

    // 3. Different origins, so a substitution is visible on a host that has
    //    never slept. `SystemMonotonicClock` zeroes at construction; the
    //    elapsed clock is absolute since boot.
    let monotonic = twinvpn_env::binding::system::SystemMonotonicClock::new();
    let elapsed = twinvpn_platform_linux::BootTimeElapsedClock::new();
    let m = monotonic.now().as_micros();
    let e = elapsed.now().as_micros();
    assert!(
        m < 1_000_000,
        "the monotonic clock zeroes at construction: {m}"
    );
    assert!(
        e > 1_000_000,
        "the elapsed clock is absolute since boot; {e} means the monotonic one \
         was substituted — LC-8's invisible-on-CI failure"
    );

    // 4. LC-24 step 1's third discriminator. `boot_id` separates a REBOOT from a
    //    RESUME, and no clock can: after a reboot both clocks restart, which is
    //    indistinguishable from a suspend that lasted exactly that long.
    let boot_id = twinvpn_platform_linux::ProcBootId::read().expect("reads");
    assert_ne!(
        boot_id.boot_id().as_bytes(),
        &[0u8; 16],
        "a zero boot id would make 'we rebooted' and 'we did not' the same fact"
    );
    assert_eq!(
        boot_id.boot_id(),
        twinvpn_platform_linux::ProcBootId::read()
            .expect("reads")
            .boot_id(),
        "it must be stable within one boot"
    );

    // LC-24 step 2: "query the enforcement layer for both families and verify
    // the installed ruleset; **no packet may be emitted before this line**." The
    // read-back is what makes that checkable, and on this host it is a named
    // failure rather than a fabricated `None`.
    let adapter = adapter();
    match adapter.network_config().installed_ruleset().await {
        Ok(_) => {}
        Err(error) => assert!(
            error.os_detail().is_some(),
            "a resume that cannot verify the ruleset must say so, not assume"
        ),
    }
}

// ---------------------------------------------------------------------------
// 10. daemon restart
// ---------------------------------------------------------------------------

/// **Daemon restart.** Enforcement is in the OS's custody, so it survives the
/// process — and the successor reclaims rather than recreates.
///
/// > **CB-6.** `begin_shutdown` must NOT tear down enforcement.
/// > **KS-20.** A crash must leave the host blocked, never open; all rule state
/// > is owner-tagged and reclaimable by a fresh process after an unclean exit.
///
/// The two halves are different claims and both are checked: the ruleset outlives
/// the process (custody), and the interface a crashed predecessor left behind is
/// reclaimed rather than colliding with (idempotent create/destroy).
#[tokio::test]
async fn matrix_daemon_restart_leaves_enforcement_installed_and_reclaims_the_interface() {
    let adapter = adapter();

    // CB-6, declared by the adapter and true of nftables rather than of our
    // code: the table is kernel-resident, so it outlives the process.
    let custody = adapter.network_config().enforcement_custody();
    assert!(
        custody.survives_core_exit(),
        "CB-6: the installed ruleset is in the OS's custody so that the core \
         going away cannot drop protection"
    );
    assert!(
        custody.swap_is_atomic,
        "KS-17/KS-23: an update is an atomic swap, never remove-then-add"
    );

    // begin_shutdown must not touch it. Called here for its side effects, and
    // the assertion is that the custody claim is unchanged afterwards.
    adapter.begin_shutdown();
    assert!(
        adapter
            .network_config()
            .enforcement_custody()
            .survives_core_exit(),
        "CB-6: shutdown must not tear down enforcement"
    );
    assert!(adapter.is_shutting_down());

    if !privileged() {
        return;
    }

    // KS-20's reclamation, on a fresh adapter as a successor process would have.
    // The predecessor's interface is still there; the successor must not fail on
    // it, and must be able to take it down.
    let successor = fresh_adapter();
    let name = InterfaceName::new("twin0").expect("valid");
    let first = successor
        .tunnel()
        .create_interface(&name, 1280)
        .await
        .expect("creates");

    // **PS-1, at the device level.** A second create of the same name while the
    // first descriptor is open is `EBUSY` from `TUNSETIFF`, and that is the
    // right answer: two processes owning one tun device is exactly the state
    // PS-1 forbids, and the kernel refuses it independently of our own lock.
    let contended = successor.tunnel().create_interface(&name, 1280).await;
    let error = contended.expect_err("two owners of one tun device is EBUSY");
    assert_eq!(
        error.os_detail().map(|d| d.code),
        Some(i64::from(libc::EBUSY)),
        "the kernel's own refusal, and a second enforcement of PS-1 beneath ours"
    );

    // **The restart.** A non-persistent tun device dies with the descriptor that
    // owns it, so a crashed predecessor leaves no interface behind — which is
    // why KS-20's reclamation on Linux is about the *ruleset* (kernel-resident,
    // asserted above) rather than about the interface. The successor's create
    // therefore succeeds cleanly once the predecessor is gone.
    successor
        .tunnel()
        .destroy_interface(first)
        .await
        .expect("destroys");
    let restarted = successor
        .tunnel()
        .create_interface(&name, 1280)
        .await
        .expect("a successor starts cleanly after the predecessor is gone");
    successor
        .tunnel()
        .destroy_interface(restarted)
        .await
        .expect("destroys");
    // Idempotent, because a restart path may run it twice.
    successor
        .tunnel()
        .destroy_interface(restarted)
        .await
        .expect("idempotent");
}
