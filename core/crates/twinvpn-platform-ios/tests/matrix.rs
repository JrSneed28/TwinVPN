//! `docs/implementation/ownership.md` **§10.5**'s mobile test matrix, for the
//! rows that can be executed on the Linux build host.
//!
//! **Authority:** `ownership.md` §10.3, §10.5 rules 1 and 2; ADR-0010 R1;
//! ADR-0012 KS-5, KS-17, §11.6; ADR-0022 LC-2, LC-7, LC-17, LC-23b, LC-24;
//! ADR-0018 CD-5, CB-2.
//!
//! # §10.5 rule 1, taken literally
//!
//! > "**Every row that can be a host-runnable test over the mock adapter MUST be
//! > one.** … Writing these only as device tests would put them in the
//! > *written, not executed* row for no reason."
//!
//! Every test in this file **executes**. The rows that genuinely cannot — the OS
//! terminating the extension, the jetsam memory kill, profile revocation from
//! Settings, real leak measurement, and ADR-0012 §11.9's P09 attach-to-arm
//! window — are XCTest cases under `shells/ios/TwinVPNTests/`, and this file does
//! not pretend to cover them. Each row below says which half it is exercising.
//!
//! # Where the line between adapter and core falls, per row
//!
//! CB-2 puts every TwinVPN decision in the core. A roaming migration is
//! `MIGRATING` rather than `RECONNECTING`; a revoked peer produces a new contract
//! generation; a restored connection resumes a `Session`. **None of those
//! verdicts is this crate's**, so what is asserted here is the *adapter-side
//! observable* of each: the facts delivered, the programme rendered, the
//! generation read back. A test that asserted a `ConnectionState` from this crate
//! would be asserting that a decision had leaked into it.
//!
//! # The mock as an oracle
//!
//! CD-5 calls the mock adapter "the payoff", and its own header warns that "a
//! mock that is laxer than the contract lets the core pass tests it would fail on
//! a real adapter". This file runs the **inverse** check: for each contract the
//! mock implements faithfully, the iOS adapter is asserted to behave the same
//! way, so a core tested against the mock is not being tested against a weaker
//! promise than the device gives it.

use std::sync::Arc;

use twinvpn_platform::mock::{MockAdapter, MockOptions};
use twinvpn_platform::{
    ContractGeneration, Datapath, DnsConfig, InterfaceIndex, NetworkContract, PlatformAdapter,
    PlatformError, RouteEntry, Ruleset, SecureItem, SecureItemKey, SocketFamily, SocketOptions,
    UdpBindSpec,
};
use twinvpn_types::{AddressFamily, InterfaceAddress, IpAddr, IpPrefix, PerFamily, V4Addr, V6Addr};

use twinvpn_platform_ios::enforce::{AttachToArm, EnforcementPosture, InterfaceTypeMatch};
use twinvpn_platform_ios::host::{HostStatus, RecordingHost};
use twinvpn_platform_ios::lifecycle::{
    ForegroundLease, MemoryPosture, ProviderStopReason, StartClassification, ThermalState,
};
use twinvpn_platform_ios::{
    settings, EnclaveElement, IosAdapterParts, IosPlatformAdapter, KeychainConfig,
};

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

/// Drains a change stream without a runtime.
///
/// A local no-op waker rather than `futures_util::StreamExt`: nothing else in
/// this workspace reaches `futures-util`, so naming it here would move
/// `core/Cargo.lock`, which is the integration lead's file (`ownership.md` §1).
/// Twelve lines is a cheap price for not editing across a boundary.
fn drain(
    stream: &mut std::pin::Pin<
        Box<dyn futures_core::Stream<Item = twinvpn_platform::NetworkChange> + Send>,
    >,
) -> Vec<twinvpn_platform::NetworkChange> {
    use std::task::{Poll, RawWaker, RawWakerVTable, Waker};
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    // SAFETY: every function in VTABLE ignores its data pointer, so the null
    // pointer is never dereferenced; clone returns an equally inert waker.
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = std::task::Context::from_waker(&waker);
    let mut out = Vec::new();
    while let Poll::Ready(Some(change)) = stream.as_mut().poll_next(&mut cx) {
        out.push(change);
    }
    out
}

fn block_on<T>(future: impl core::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("runtime")
        .block_on(future)
}

fn v4(a: u8, b: u8, c: u8, d: u8, len: u32) -> IpPrefix {
    IpPrefix::new(IpAddr::V4(V4Addr::from_octets([a, b, c, d])), len).expect("prefix")
}

fn v6(octets: [u8; 16], len: u32) -> IpPrefix {
    IpPrefix::new(IpAddr::V6(V6Addr::prefix_base(octets).expect("v6")), len).expect("prefix")
}

fn route(destination: IpPrefix) -> RouteEntry {
    RouteEntry {
        destination,
        via: None,
        interface: InterfaceIndex(0),
        metric: None,
    }
}

/// An interface's OWN address. Distinct from `v4`/`v6`, which name route
/// destinations: X-10 split the two because a host address's bits are the whole
/// point and `IpPrefix` requires them to be zero.
fn addr_v4(a: u8, b: u8, c: u8, d: u8, len: u32) -> InterfaceAddress {
    InterfaceAddress::new(IpAddr::V4(V4Addr::from_octets([a, b, c, d])), len).expect("address")
}

fn addr_v6(octets: [u8; 16], len: u32) -> InterfaceAddress {
    InterfaceAddress::new(IpAddr::V6(V6Addr::prefix_base(octets).expect("v6")), len)
        .expect("address")
}

/// A full-tunnel contract: both families addressed, both defaults routed, the
/// overlay resolver default for everything.
fn full_tunnel(generation: u64, ruleset: Ruleset) -> NetworkContract {
    NetworkContract {
        generation: ContractGeneration(generation),
        addresses: PerFamily::new(
            vec![addr_v4(100, 64, 0, 7, 32)],
            vec![addr_v6(
                [
                    0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
                ],
                128,
            )],
        ),
        routes: PerFamily::new(vec![route(v4(0, 0, 0, 0, 0))], vec![route(v6([0; 16], 0))]),
        dns: DnsConfig {
            resolvers: PerFamily::new(
                vec![IpAddr::V4(V4Addr::from_octets([100, 127, 255, 53]))],
                vec![IpAddr::V6(
                    V6Addr::prefix_base([
                        0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0x53,
                    ])
                    .expect("v6"),
                )],
            ),
            search_domains: Vec::new(),
            split_domains: Vec::new(),
            is_default_resolver: true,
        },
        ruleset,
        // A protected generation asserts a validated path, and a validated path
        // has a remote. `None` is the `Blocked` shape.
        tunnel_remote_address: Some(IpAddr::V4(V4Addr::from_octets([198, 51, 100, 7]))),
        mtu: 1280,
    }
}

fn adapter(host: Arc<RecordingHost>) -> IosPlatformAdapter {
    let keychain =
        KeychainConfig::new("ABCDE12345.group.com.twinvpn", "com.twinvpn.client").expect("config");
    IosPlatformAdapter::new(IosAdapterParts {
        identity_element: Arc::new(EnclaveElement::new(host.clone(), keychain.clone())),
        host,
        keychain,
        enforcement: EnforcementPosture::default(),
        tunnel_remote_address: "100.64.0.1".to_owned(),
    })
}

fn host() -> Arc<RecordingHost> {
    Arc::new(RecordingHost::new("/tmp/twinvpn-ios-matrix"))
}

const WIFI_V4: &str = r#"{"interfaces":[{"index":1,"name":"en0","interface_type":"wifi",
    "is_up":true,"mtu":1500,"addresses":[{"address":{"octets":[192,168,1,20]},
    "prefix_length":32}]}],"supports_v4":true,"supports_v6":false,"supports_dns":true,
    "metered":false,"constrained":false,"overlay_name_prefix":"utun"}"#;

const CELLULAR_DUAL: &str = r#"{"interfaces":[{"index":2,"name":"pdp_ip0",
    "interface_type":"cellular","is_up":true,"mtu":1428,
    "addresses":[{"address":{"octets":[100,80,0,5]},"prefix_length":32}]}],
    "supports_v4":true,"supports_v6":true,"supports_dns":true,"metered":true,
    "constrained":false,"overlay_name_prefix":"utun"}"#;

// ---------------------------------------------------------------------------
// row: foreground / background
// ---------------------------------------------------------------------------

/// **Executed.** ADR-0022 LC-23b: foreground state is *optimization-bearing*, so
/// the provider runs the background profile by default and enters the foreground
/// profile only under an unexpired app-liveness lease.
///
/// The row's device half — that the tunnel keeps working with the app force-quit
/// (LC-23) — is `shells/ios/TwinVPNTests/LifecycleTests.swift`, unrun.
#[test]
fn foreground_and_background_ride_an_expiring_lease_and_a_dead_app_is_the_default() {
    let lease = ForegroundLease {
        renewed_us: 1_000_000,
        ttl_ms: 3_000,
    };
    assert!(lease.is_held(1_000_000), "just renewed");
    assert!(lease.is_held(3_999_000), "still inside the TTL");
    assert!(!lease.is_held(4_000_000), "expired at the TTL");
    // A dead app renews nothing, and LC-23b calls the resulting background
    // profile "the battery-optimal default, not degraded".
    assert!(!lease.is_held(600_000_000));
    // A backwards reading — which a suspend across the boundary can produce if
    // the wrong clock is read — expires rather than extends.
    assert!(!lease.is_held(0));
}

// ---------------------------------------------------------------------------
// row: lock / unlock
// ---------------------------------------------------------------------------

/// **Executed.** ADR-0020 ST-5 and `ownership.md` §10.1: an item unavailable
/// while the device is locked must be "a designed state with a registered
/// `reason_code`, not a surprise `errSecInteractionNotAllowed`".
#[test]
fn lock_and_unlock_are_designed_states_with_registered_names() {
    let host = host();
    let adapter = adapter(host.clone());
    let key = SecureItemKey::new("sek").expect("key");

    // Unlocked: the item round-trips, and its query carries the one accessibility
    // class ST-5 permits — the weakest that lets the provider rekey while the
    // screen is locked.
    block_on(
        adapter
            .store()
            .secure_item_write_atomic(&key, &SecureItem::new(vec![7; 32])),
    )
    .expect("writes");
    assert!(host
        .state()
        .keychain
        .keys()
        .all(|q| q.contains("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly")));

    // Locked before first unlock: a NAMED condition, not a fault and not an
    // absence. Conflating it with absence would re-enrol the device on every
    // reboot.
    host.fail_next(HostStatus::OsStatus(
        twinvpn_platform_ios::oserr::ERR_SEC_INTERACTION_NOT_ALLOWED,
    ));
    let err = block_on(
        adapter
            .store()
            .secure_item_write_atomic(&key, &SecureItem::new(vec![1])),
    )
    .expect_err("refuses");
    assert_eq!(err.reason_code().as_str(), "AUTH.KEY_STORE_UNAVAILABLE");

    // Unlocked again: the same item is still there. The lock did not destroy it.
    let value = block_on(adapter.store().secure_item_read(&key))
        .expect("reads")
        .expect("present");
    assert_eq!(value.as_bytes(), &[7u8; 32]);
}

// ---------------------------------------------------------------------------
// row: network changes
// ---------------------------------------------------------------------------

/// **Executed.** `docs/networking.md` §5.1: event-driven, never polled — and
/// ADR-0010 R6's per-family default-route event.
#[test]
fn a_network_change_is_delivered_as_events_and_a_v6_arrival_is_its_own() {
    let host = host();
    let adapter = adapter(host);
    let interfaces = adapter.interface_provider();

    interfaces.push_snapshot(WIFI_V4).expect("delivers");
    let mut stream = adapter.interfaces().subscribe().expect("subscribes");

    let mut v6_up: String = WIFI_V4.to_owned();
    v6_up = v6_up.replace("\"supports_v6\":false", "\"supports_v6\":true");
    interfaces.push_snapshot(&v6_up).expect("delivers");

    let changes = drain(&mut stream);
    assert_eq!(
        changes.first().cloned().expect("an event"),
        twinvpn_platform::NetworkChange::DefaultRouteChanged {
            family: AddressFamily::V6,
            present: true
        },
        "R6's case — IPv6 appearing AFTER the tunnel is up — is its own event, \
         not folded into a combined one that would look like nothing happened"
    );
}

// ---------------------------------------------------------------------------
// row: cellular <-> Wi-Fi migration
// ---------------------------------------------------------------------------

/// **Executed, adapter half.** `docs/networking.md` §5.4: "Underlay change does
/// not touch overlay addressing (N2) … `MIGRATING`, not `RECONNECTING`."
///
/// The **verdict** is the core's, so what is asserted here is that the adapter
/// delivers the facts a core needs to reach it — and, critically, that the
/// overlay contract is untouched by the roam.
#[test]
fn a_wifi_to_cellular_roam_changes_the_underlay_and_not_the_overlay() {
    let host = host();
    let adapter = adapter(host.clone());
    let interfaces = adapter.interface_provider();

    interfaces.push_snapshot(WIFI_V4).expect("delivers");
    block_on(
        adapter
            .network_config()
            .apply(&full_tunnel(1, Ruleset::Protected)),
    )
    .expect("applies");
    let before = host.state().settings_applied.clone();

    interfaces.push_snapshot(CELLULAR_DUAL).expect("delivers");

    // N2: the roam produced NO new settings object. The overlay addresses and
    // routes are unchanged, which is the property that makes a migration a
    // migration rather than a reconnect.
    assert_eq!(host.state().settings_applied, before);

    // And the facts the core needs are all present: the link class changed, the
    // v6 default arrived, and the link is now metered.
    let facts = block_on(adapter.interfaces().enumerate()).expect("enumerates");
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].link_class, twinvpn_platform::LinkClass::Cellular);
    assert!(facts[0].has_default_route_v6);
    assert!(
        block_on(adapter.network_config().query_link_facts())
            .expect("facts")
            .metered
    );
}

// ---------------------------------------------------------------------------
// row: tunnel restart
// ---------------------------------------------------------------------------

/// **Executed.** ADR-0012 KS-17's arm and teardown sequences, and the seam's
/// "destroy_interface is idempotent; safe after a crash".
#[test]
fn a_tunnel_restart_never_leaves_the_profile_without_a_ruleset() {
    let host = host();
    let adapter = adapter(host.clone());
    let tunnel = adapter.tunnel();

    let handle = block_on(tunnel.create_interface(
        &twinvpn_platform::InterfaceName::new("utun7").expect("name"),
        1280,
    ))
    .expect("creates");
    block_on(
        adapter
            .network_config()
            .apply(&full_tunnel(1, Ruleset::Blocked)),
    )
    .expect("applies");
    block_on(tunnel.set_link(handle, twinvpn_platform::LinkState::Up)).expect("up");
    block_on(
        adapter
            .network_config()
            .set_ruleset(ContractGeneration(1), Ruleset::Protected),
    )
    .expect("swaps");

    // Teardown, then a fresh bring-up. At no point is the enforcement removed.
    block_on(
        adapter
            .network_config()
            .set_ruleset(ContractGeneration(1), Ruleset::Blocked),
    )
    .expect("swaps back");
    block_on(tunnel.destroy_interface(handle)).expect("destroys");
    assert!(
        host.state().installed_enforcement.is_some(),
        "KS-17: rules are NEVER absent while the latch is up"
    );
    assert_eq!(
        block_on(adapter.network_config().installed_ruleset()).expect("reads"),
        Some(Ruleset::Blocked)
    );

    let handle = block_on(tunnel.create_interface(
        &twinvpn_platform::InterfaceName::new("utun8").expect("name"),
        1280,
    ))
    .expect("creates again");
    block_on(
        adapter
            .network_config()
            .apply(&full_tunnel(2, Ruleset::Protected)),
    )
    .expect("applies");
    assert_eq!(
        block_on(adapter.network_config().current_generation()).expect("reads"),
        Some(ContractGeneration(2))
    );
    block_on(tunnel.destroy_interface(handle)).expect("destroys");
}

// ---------------------------------------------------------------------------
// row: process termination
// ---------------------------------------------------------------------------

/// **Executed, rehydration half.** ADR-0022 LC-4 step 3 and LC-7: after a jetsam
/// kill the new provider process reads what is installed rather than what it
/// remembers, *because it remembers nothing*.
///
/// The device half — that the OS actually kills the extension at the memory
/// ceiling, with no notice — is `shells/ios/TwinVPNTests/MemoryPressureTests.swift`,
/// unrun.
#[test]
fn process_termination_is_survived_by_reading_the_os_rather_than_a_cache() {
    let host = host();
    {
        let adapter = adapter(host.clone());
        block_on(
            adapter
                .network_config()
                .apply(&full_tunnel(5, Ruleset::Protected)),
        )
        .expect("applies");
    } // the provider process is gone; every in-memory field with it.

    let restarted = adapter(host);
    assert_eq!(
        block_on(restarted.network_config().current_generation()).expect("reads"),
        Some(ContractGeneration(5)),
    );
    assert_eq!(
        block_on(restarted.network_config().installed_ruleset()).expect("reads"),
        Some(Ruleset::Protected),
    );

    // LC-24 step 1: a reboot is not a resume at any gap, and a stop this build
    // cannot name is not evidence of an orderly one.
    assert_eq!(
        twinvpn_platform_ios::lifecycle::classify_start(Some([1; 16]), [2; 16], 0, 9_000_000),
        StartClassification::ColdStart
    );
    assert!(!ProviderStopReason::from_raw(4242).os_attributes_to_user_or_policy());

    // LC-17/LC-31's ladder, which is what the OS acts on before it kills us.
    assert!(MemoryPosture::observe(10 * 1024 * 1024).shed_indicated);
    assert!(MemoryPosture::observe(16 * 1024 * 1024).over_ceiling);
    assert!(ThermalState::from_raw(99).is_pressured());
}

// ---------------------------------------------------------------------------
// row: restored connection
// ---------------------------------------------------------------------------

/// **Executed, adapter half.** ADR-0022 LC-2 rehydrates a live state to
/// `RECONNECTING` — a **core** decision. What the adapter owes a restore is that
/// the exact generation is recoverable and the wake is reported as a gap.
#[test]
fn a_restored_connection_recovers_the_exact_generation_and_reports_the_gap() {
    let host = host();
    let adapter = adapter(host.clone());
    let interfaces = adapter.interface_provider();
    interfaces.push_snapshot(WIFI_V4).expect("delivers");
    block_on(
        adapter
            .network_config()
            .apply(&full_tunnel(3, Ruleset::Protected)),
    )
    .expect("applies");
    let installed = host
        .state()
        .settings_applied
        .last()
        .cloned()
        .expect("applied");

    // A newer generation, then a rollback: the earlier settings come back byte
    // for byte rather than being re-derived.
    block_on(
        adapter
            .network_config()
            .apply(&full_tunnel(9, Ruleset::Protected)),
    )
    .expect("applies");
    host.state().settings_applied.clear();
    block_on(adapter.network_config().rollback(ContractGeneration(9))).expect("rolls back");
    assert_eq!(host.state().settings_applied, vec![installed]);

    // And the wake that follows a restore is a network-change event, whether or
    // not the path looks the same (§5.4).
    let mut stream = adapter.interfaces().subscribe().expect("subscribes");
    interfaces
        .push_snapshot_after_wake(WIFI_V4)
        .expect("delivers");
    assert_eq!(
        drain(&mut stream).first().cloned().expect("an event"),
        twinvpn_platform::NetworkChange::EventsLost { count: None }
    );
}

// ---------------------------------------------------------------------------
// row: revoked peers
// ---------------------------------------------------------------------------

/// **Executed, adapter half.** Revocation is a core decision (ADR-0007); the
/// adapter's obligation is that the generation which no longer routes the peer
/// is installed **atomically** and that the previous one is not left half in
/// force.
#[test]
fn a_revoked_peer_is_installed_atomically_and_leaves_no_route_behind() {
    let host = host();
    let adapter = adapter(host.clone());

    // Generation 1 routes a peer prefix on both families.
    let mut with_peer = full_tunnel(1, Ruleset::Protected);
    with_peer
        .routes
        .get_mut(AddressFamily::V4)
        .push(route(v4(100, 64, 5, 0, 24)));
    with_peer.routes.get_mut(AddressFamily::V6).push(route(v6(
        [
            0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        64,
    )));
    block_on(adapter.network_config().apply(&with_peer)).expect("applies");
    assert!(host.state().settings_applied[0].contains("100.64.5.0"));

    // Generation 2 does not. One transaction; nothing is "removed" separately,
    // so there is no window in which half the peer's routes are gone.
    let without_peer = full_tunnel(2, Ruleset::Protected);
    block_on(adapter.network_config().apply(&without_peer)).expect("applies");
    let now = host.state().settings_applied[1].clone();
    assert!(!now.contains("100.64.5.0"), "the v4 route is gone");
    assert!(!now.contains("fd7c:9e5d:2a10:5::"), "and so is the v6 one");
    assert_eq!(host.state().settings_applied.len(), 2, "one call, not two");
}

// ---------------------------------------------------------------------------
// row: kill-switch behaviour
// ---------------------------------------------------------------------------

/// **Executed.** ADR-0012 KS-17: "transitions are an **atomic swap** between the
/// two; rules are **never absent** while the latch is UP."
#[test]
fn the_kill_switch_swaps_atomically_and_has_no_third_value() {
    let host = host();
    let adapter = adapter(host.clone());
    block_on(
        adapter
            .network_config()
            .apply(&full_tunnel(1, Ruleset::Blocked)),
    )
    .expect("applies");

    for ruleset in [Ruleset::Protected, Ruleset::Blocked, Ruleset::Protected] {
        host.state().enforcement_applied.clear();
        block_on(
            adapter
                .network_config()
                .set_ruleset(ContractGeneration(1), ruleset),
        )
        .expect("swaps");
        assert_eq!(
            host.state().enforcement_applied.len(),
            1,
            "one call — not a remove-then-add, which KS-23 names as the mutant"
        );
        assert_eq!(
            block_on(adapter.network_config().installed_ruleset()).expect("reads"),
            Some(ruleset)
        );
    }

    // The custody declaration is pessimistic in O-18's direction AND carries
    // the re-arm as its own fact: ADR-0012 gives iOS `◐`, and since M-6 the
    // seam has a third value for exactly that rather than a rounded bool.
    let custody = adapter.network_config().enforcement_custody();
    assert!(!custody.survives_core_exit());
    assert!(custody.ruleset_custody.os_rearms());
    assert!(custody.swap_is_atomic);

    // P09 measures the attach-to-arm window rather than assuming it is zero, and
    // §14 condition 5's threshold is a check rather than a sentence.
    assert!(AttachToArm {
        attached_us: 0,
        armed_us: 501_000
    }
    .exceeds_revisit_threshold());
    assert!(!AttachToArm {
        attached_us: 0,
        armed_us: 120_000
    }
    .exceeds_revisit_threshold());
}

// ---------------------------------------------------------------------------
// rows: IPv4 leaks, IPv6 leaks, DNS leaks
// ---------------------------------------------------------------------------

/// **Executed.** ADR-0012 KS-5's shape, applied to this platform: there is no
/// per-family enforcement object, so a v6-only leak is structurally
/// unrepresentable.
///
/// The device half — measuring that no packet of either family escapes with the
/// tunnel down — is `shells/ios/TwinVPNTests/LeakTests.swift`, unrun.
#[test]
fn no_enforcement_programme_can_capture_one_family_and_not_the_other() {
    // ADR-0010 R1 forbids "a v4 story and a v6 story". The check is that the
    // rendered enforcement carries NO family-keyed field at all: there is no
    // v6 half to forget, because there is no v6 half.
    for local in [false, true] {
        for full in [false, true] {
            let posture = EnforcementPosture {
                local_network_access: local,
                full_protection_required: full,
                restart_on: vec![InterfaceTypeMatch::Any],
                connect_ssids: Vec::new(),
            };
            for ruleset in [Ruleset::Blocked, Ruleset::Protected] {
                let json = posture.programme(ContractGeneration(1), ruleset).to_json();
                for family_word in ["ipv4", "ipv6", "v4", "v6", "family"] {
                    assert!(
                        !json.contains(family_word),
                        "the enforcement programme must carry no per-family field; \
                         found {family_word} in {json}"
                    );
                }
            }
        }
    }
}

/// **Executed.** ADR-0010 R1 and §11.3's normative rule: "IPv4 and IPv6 routes
/// MUST be installed in the same `apply()` transaction. An implementation that
/// can install one family's routes without the other's is non-conforming."
#[test]
fn both_families_are_routed_and_resolved_in_one_transaction() {
    let host = host();
    let adapter = adapter(host.clone());
    block_on(
        adapter
            .network_config()
            .apply(&full_tunnel(1, Ruleset::Protected)),
    )
    .expect("applies");

    assert_eq!(host.state().settings_applied.len(), 1, "one transaction");
    let programme = host.state().settings_applied[0].clone();

    // Both default markers, in one object.
    let ipv4 = programme
        .split("\"ipv4\":")
        .nth(1)
        .expect("an ipv4 section")
        .to_owned();
    let ipv6 = programme
        .split("\"ipv6\":")
        .nth(1)
        .expect("an ipv6 section")
        .to_owned();
    assert!(ipv4.contains("\"default\":true"), "{ipv4}");
    assert!(ipv6.contains("\"default\":true"), "{ipv6}");

    // Both families' resolvers, and the overlay resolver claiming everything —
    // which is how a DNS leak is closed on a platform whose only resolver hook
    // is the settings object (ADR-0011 §11.7's iOS row).
    assert!(programme.contains("100.127.255.53"));
    assert!(programme.contains("fd7c:9e5d:2a10:ffff::53"));
    assert!(programme.contains("\"match_domains\":[\"\"]"));
}

/// **Executed.** ADR-0011 N2 and §11.7's iOS row: `.local` is excluded from
/// `matchDomains`, because `mDNSResponder` sends it to multicast regardless and
/// a resolver posture that claims otherwise is a claim the OS contradicts.
#[test]
fn the_dns_programme_never_claims_a_domain_the_os_will_not_honour() {
    let mut contract = full_tunnel(1, Ruleset::Protected);
    contract.dns.is_default_resolver = false;
    contract.dns.split_domains = vec![
        "corp.example".to_owned(),
        "local".to_owned(),
        "printer.local".to_owned(),
    ];
    let programme = settings::render(&contract).expect("renders");
    assert_eq!(programme.dns.match_domains, vec!["corp.example".to_owned()]);
    assert_eq!(
        programme
            .residuals
            .iter()
            .filter(|r| matches!(r, settings::SettingsResidual::MdnsDomainNotClaimable { .. }))
            .count(),
        2,
        "and the two drops are stated rather than silent"
    );
}

// ---------------------------------------------------------------------------
// CD-5: the mock as a conformance oracle
// ---------------------------------------------------------------------------

/// **Executed.** The mock is a faithful implementation of every contract the
/// traits state. This asserts the iOS adapter is **no laxer**, so a core tested
/// against the mock is not being tested against a weaker promise than the device
/// gives it.
#[test]
fn the_ios_adapter_is_no_laxer_than_the_seams_own_mock() {
    let mock = MockAdapter::new(&MockOptions {
        datapath: Datapath::Userspace,
        ..MockOptions::default()
    });
    let host = host();
    let ios = adapter(host);

    block_on(async {
        for adapter in [&mock as &dyn PlatformAdapter, &ios as &dyn PlatformAdapter] {
            let name = adapter.binding_name();

            // 1. `apply` is idempotent on the generation id.
            let contract = full_tunnel(1, Ruleset::Blocked);
            adapter.network_config().apply(&contract).await.expect(name);
            adapter.network_config().apply(&contract).await.expect(name);

            // 2. `set_ruleset` is an atomic swap and the ruleset is never absent.
            adapter
                .network_config()
                .set_ruleset(ContractGeneration(1), Ruleset::Protected)
                .await
                .expect(name);
            assert_eq!(
                adapter
                    .network_config()
                    .installed_ruleset()
                    .await
                    .expect(name),
                Some(Ruleset::Protected),
                "{name}"
            );

            // 3. `create_interface` yields a handle and `destroy_interface` is
            //    idempotent.
            let handle = adapter
                .tunnel()
                .create_interface(
                    &twinvpn_platform::InterfaceName::new("utun9").expect("name"),
                    1280,
                )
                .await
                .expect(name);
            adapter
                .tunnel()
                .destroy_interface(handle)
                .await
                .expect(name);
            adapter
                .tunnel()
                .destroy_interface(handle)
                .await
                .expect(name);

            // 4. A cross-family send is refused rather than attempted.
            let socket = adapter
                .sockets()
                .bind_udp(&UdpBindSpec {
                    family: SocketFamily::V4,
                    local: None,
                    options: SocketOptions::default(),
                })
                .await
                .expect(name);
            let mut octets = [0u8; 16];
            octets[15] = 1;
            let v6_target = twinvpn_types::Endpoint::new(
                IpAddr::V6(V6Addr::from_slice(&octets, 0).expect("v6")),
                twinvpn_types::Port::new(9).expect("port"),
            );
            assert!(
                socket.send_to(b"x", &v6_target).await.is_err(),
                "{name}: a cross-family send must be refused"
            );

            // 5. An absent secure item is `Ok(None)`, not an error.
            let key = SecureItemKey::new("absent_item").expect("key");
            assert!(
                adapter
                    .store()
                    .secure_item_read(&key)
                    .await
                    .expect(name)
                    .is_none(),
                "{name}"
            );

            // 6. After `begin_shutdown`, calls refuse by name rather than hanging
            //    or silently succeeding — and enforcement is NOT torn down.
            adapter.begin_shutdown();
            assert_eq!(
                adapter
                    .network_config()
                    .apply(&full_tunnel(2, Ruleset::Blocked))
                    .await,
                Err(PlatformError::ShuttingDown),
                "{name}"
            );
            assert_eq!(
                adapter
                    .network_config()
                    .installed_ruleset()
                    .await
                    .expect(name),
                Some(Ruleset::Protected),
                "{name}: CB-6 — the core going away does not drop protection"
            );
        }
    });
}
