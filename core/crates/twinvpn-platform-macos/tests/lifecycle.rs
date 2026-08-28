//! Startup, shutdown, UI/service separation, network change, suspend/resume and
//! daemon restart — the lifecycle half of the required matrix.
//!
//! **Authority:** ADR-0016 PS-3 ("UI death is not a disconnect"), PS-5, PS-17,
//! PS-18, PS-19, §11.6 (the start sequence); ADR-0018 CB-2, CB-3, CB-6, CD-5,
//! S-46, S-47, §11.16 (l); ADR-0022 (sleep/wake, LC-8); ADR-0010 R6;
//! `docs/networking.md` §5.1.

use std::sync::Arc;

use futures_util::StreamExt as _;
use twinvpn_platform::mock::{MockAdapter, MockOptions};
use twinvpn_platform::{
    InterfaceIndex, InterfaceName, InterfaceProvider, LinkClass, NetworkChange, PlatformAdapter,
    PlatformError, Ruleset, TunnelHandle,
};
use twinvpn_platform_macos::custody::{AbsentElement, Accessibility, KeychainItemSpec};
use twinvpn_platform_macos::iface::{classify, sc_type, MacosInterfaceProvider, RawInterface};
use twinvpn_platform_macos::power::{msg, PowerJournal, PowerPhase};
use twinvpn_platform_macos::utun::{
    decode_frame, encode_frame, family_of_packet, FrameError, QueuePort, FRAME_HEADER_LEN,
};
use twinvpn_platform_macos::{
    testkit, MacosAdapterParts, MacosPlatformAdapter, ShutdownLatch, TunnelProvenance, BINDING_NAME,
};
use twinvpn_types::AddressFamily;

fn parts(provenance: TunnelProvenance) -> (MacosAdapterParts, testkit::Recorders) {
    let (carriers, recorders) = testkit::daemon_carriers();
    (
        MacosAdapterParts {
            enforcement: testkit::enforcement(),
            carriers,
            tunnel_provenance: provenance,
            store_root: std::env::temp_dir().join("twinvpn-macos-adapter-test"),
            identity_element: Arc::new(AbsentElement),
            keychain: KeychainItemSpec {
                service: "net.twinvpn".to_owned(),
                access_group: None,
                accessibility: Accessibility::SystemKeychain,
            },
        },
        recorders,
    )
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

#[test]
fn one_object_carries_all_six_capabilities_and_names_itself() {
    // S-47: "a core that assembled its platform from six independently-supplied
    // pieces could not state which adapter it was talking to."
    let (parts, _rec) = parts(TunnelProvenance::OsProvidedFlow);
    let adapter = MacosPlatformAdapter::new(parts);
    let _ = adapter.sockets();
    let _ = adapter.tunnel();
    let _ = adapter.network_config();
    let _ = adapter.interfaces();
    let _ = adapter.identity();
    let _ = adapter.store();
    assert_eq!(adapter.binding_name(), BINDING_NAME);
    assert_eq!(adapter.binding_name(), "macos-pf");
}

#[test]
fn the_posture_is_declared_at_startup_rather_than_discovered_by_a_user() {
    // PS-17's principle applied to the adapter: a degraded posture is a fact the
    // shell reports, not one a user finds out about.
    let (parts, _rec) = parts(TunnelProvenance::OsProvidedFlow);
    let adapter = MacosPlatformAdapter::new(parts);
    let posture = adapter.posture();
    // `pfctl` is absent on this host, which is itself the fact worth declaring:
    // the shell turns it into a startup refusal rather than arming without a
    // firewall (ADR-0012 §8, PS-18).
    assert!(!posture.pfctl_present);
    assert!(!posture.route_binary_present);
    assert!(posture.ks9_complete);
    // §11.16 (l): reported TRUTHFULLY. `AbsentElement` has no element and says so.
    assert_eq!(
        posture.custody_class,
        twinvpn_platform_macos::CustodyClass::Absent
    );
    assert!(posture.datapath_is_os_provided);
}

#[test]
fn the_datapath_is_userspace_on_both_provenances_so_nothing_above_branches_on_os() {
    // CB-3. The two macOS bindings differ completely in how the interface comes
    // into existence and not at all in what the core does with it.
    for provenance in [
        TunnelProvenance::OsProvidedFlow,
        TunnelProvenance::AdapterCreatedUtun,
    ] {
        let (parts, _rec) = parts(provenance);
        let adapter = MacosPlatformAdapter::new(parts);
        assert_eq!(
            adapter.tunnel().datapath(),
            twinvpn_platform::Datapath::Userspace
        );
    }
}

#[test]
fn the_enforcement_custody_is_declared_and_matches_what_pf_actually_gives() {
    let (parts, _rec) = parts(TunnelProvenance::OsProvidedFlow);
    let adapter = MacosPlatformAdapter::new(parts);
    let custody = adapter.network_config().enforcement_custody();
    // ADR-0012 §11.6's macOS durability row: "pf rules are kernel-resident".
    assert!(custody.survives_core_exit);
    // A single `pfctl -f` load is one transaction (KS-17).
    assert!(custody.swap_is_atomic);
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

#[tokio::test]
async fn shutdown_latches_and_does_not_touch_the_installed_anchor() {
    // CB-6: the OS holds the rules precisely so the core going away does not drop
    // protection. A shutdown that removed them would defeat it.
    let (parts, rec) = parts(TunnelProvenance::OsProvidedFlow);
    let adapter = MacosPlatformAdapter::new(parts);
    adapter
        .network_config()
        .apply(&testkit::contract(1))
        .await
        .expect("applies");
    let loads = rec.pf.load_count();

    assert!(!adapter.is_shutting_down());
    adapter.begin_shutdown();
    adapter.begin_shutdown(); // idempotent
    assert!(adapter.is_shutting_down());

    assert_eq!(rec.pf.load_count(), loads, "no anchor load on the way out");
    assert_eq!(
        adapter
            .network_config()
            .installed_ruleset()
            .await
            .expect("the read-back still answers"),
        Some(Ruleset::Protected),
        "protection outlives the adapter"
    );
}

#[tokio::test]
async fn after_shutdown_calls_refuse_rather_than_hanging_or_silently_succeeding() {
    // The two failure modes a shutdown flag exists to prevent: a hang looks like
    // work in progress, and a silent success looks like the work was done.
    let (parts, _rec) = parts(TunnelProvenance::OsProvidedFlow);
    let adapter = MacosPlatformAdapter::new(parts);
    adapter.begin_shutdown();

    let error = adapter
        .network_config()
        .apply(&testkit::contract(1))
        .await
        .expect_err("refused");
    assert!(matches!(error, PlatformError::ShuttingDown));
    assert_eq!(error.reason_code().as_str(), "INTERNAL.UNEXPECTED_STATE");
    assert!(adapter.interfaces().subscribe().is_err());
}

#[tokio::test]
async fn rollback_is_still_possible_during_shutdown() {
    // Refusing it would leave the host mutated on an orderly stop, which is the
    // one case where a shutdown guard does more harm than good.
    let (parts, rec) = parts(TunnelProvenance::OsProvidedFlow);
    let adapter = MacosPlatformAdapter::new(parts);
    adapter
        .network_config()
        .apply(&testkit::contract(1))
        .await
        .expect("applies");
    adapter.begin_shutdown();
    adapter
        .network_config()
        .rollback(twinvpn_platform::ContractGeneration(1))
        .await
        .expect("rolls back during shutdown");
    assert!(rec.route.live_destinations().is_empty());
}

// ---------------------------------------------------------------------------
// UI / service separation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ps3_every_subscriber_going_away_changes_no_enforcement_state() {
    // "Loss of the last management client MUST NOT change session_intent,
    // enforcement mode, installed rule set, or ConnectionState."
    let (parts, rec) = parts(TunnelProvenance::OsProvidedFlow);
    let adapter = MacosPlatformAdapter::new(parts);
    adapter
        .network_config()
        .apply(&testkit::contract(1))
        .await
        .expect("applies");

    let stream = adapter.interfaces().subscribe().expect("subscribes");
    let loads = rec.pf.load_count();
    drop(stream);

    assert_eq!(rec.pf.load_count(), loads);
    assert_eq!(
        adapter
            .network_config()
            .installed_ruleset()
            .await
            .expect("queries"),
        Some(Ruleset::Protected)
    );
    assert!(rec.route.live_destinations().len() == 2);
}

#[test]
fn ps5_no_method_on_this_adapter_hands_a_descriptor_outward() {
    // "The authority MUST NOT pass the tunnel fd, netlink/WFP/pf handle, or any
    // secure-storage handle to any process by any mechanism." The seam makes it
    // structural: `TunnelHandle` is an opaque `u64` allocated by this adapter and
    // is not a file descriptor, so there is nothing to pass.
    let (parts, _rec) = parts(TunnelProvenance::OsProvidedFlow);
    let adapter = MacosPlatformAdapter::new(parts);
    let port = Arc::new(QueuePort::new());
    adapter.tunnel_device().set_pending_port(port);
    let name = InterfaceName::new("utun7").expect("valid");
    let handle = adapter.tunnel_device().adopt(&name).expect("adopts");
    // The handle is ours, not the kernel's.
    assert_eq!(handle, TunnelHandle(1));
    assert_eq!(adapter.tunnel_device().index_of(handle), Some(7));
}

// ---------------------------------------------------------------------------
// Network change
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_decoded_route_message_reaches_a_subscriber_as_a_per_family_fact() {
    // ADR-0010 R6: a v6 default route arriving while the v4 one is unchanged must
    // be its own event, or it is indistinguishable from nothing happening.
    let provider = MacosInterfaceProvider::new(ShutdownLatch::new());
    let mut stream = provider.subscribe().expect("subscribes");
    provider.publish(NetworkChange::DefaultRouteChanged {
        family: AddressFamily::V6,
        present: true,
    });
    assert_eq!(
        stream.next().await,
        Some(NetworkChange::DefaultRouteChanged {
            family: AddressFamily::V6,
            present: true,
        })
    );
}

#[tokio::test]
async fn two_subscribers_both_see_every_change() {
    let provider = MacosInterfaceProvider::new(ShutdownLatch::new());
    let mut a = provider.subscribe().expect("subscribes");
    let mut b = provider.subscribe().expect("subscribes");
    assert_eq!(provider.subscriber_count(), 2);
    provider.publish(NetworkChange::ResolversChanged);
    assert_eq!(a.next().await, Some(NetworkChange::ResolversChanged));
    assert_eq!(b.next().await, Some(NetworkChange::ResolversChanged));
}

#[tokio::test]
async fn a_subscriber_that_falls_behind_is_told_how_many_it_missed() {
    // ADR-0018 §11.6: "a dropped event is itself recorded". An adapter that
    // silently coalesced would leave the core believing it has a complete picture.
    let provider = MacosInterfaceProvider::new(ShutdownLatch::new());
    let mut stream = provider.subscribe().expect("subscribes");
    for _ in 0..(twinvpn_platform_macos::iface::CHANGE_BUFFER + 8) {
        provider.publish(NetworkChange::ResolversChanged);
    }
    let first = stream.next().await.expect("an item");
    match first {
        NetworkChange::EventsLost { count } => {
            assert!(
                count.is_some(),
                "the count is known here and must be reported"
            );
            assert!(count.expect("some") >= 8);
        }
        other => panic!("expected an EventsLost, got {other:?}"),
    }
    // And the stream keeps delivering: a lag is a gap, never an end.
    assert_eq!(stream.next().await, Some(NetworkChange::ResolversChanged));
}

#[test]
fn is_overlay_is_answered_by_ownership_and_never_by_the_utun_name() {
    // Darwin names `utun` interfaces itself, so `utun3` may be Tailscale's.
    // Treating any `utun` as ours would make the interface-scoped Tier-2 rule
    // permit somebody else's tunnel.
    let provider = MacosInterfaceProvider::new(ShutdownLatch::new());
    let ours = RawInterface {
        name: "utun7".to_owned(),
        index: 7,
        addresses: Vec::new(),
        is_up: true,
        mtu: 1280,
        sc_type: None,
        has_default_route_v4: false,
        has_default_route_v6: false,
    };
    let theirs = RawInterface {
        name: "utun3".to_owned(),
        index: 3,
        ..ours.clone()
    };
    provider.own_interface(InterfaceIndex(7));
    let owned = [7u32].into_iter().collect();
    assert!(
        twinvpn_platform_macos::iface::facts_from(&ours, &owned)
            .expect("valid")
            .is_overlay
    );
    assert!(
        !twinvpn_platform_macos::iface::facts_from(&theirs, &owned)
            .expect("valid")
            .is_overlay,
        "another product's utun must never be treated as ours"
    );
    provider.disown_interface(InterfaceIndex(7));
    assert!(!provider.owns(InterfaceIndex(7)));
}

#[test]
fn wifi_and_ethernet_are_told_apart_by_the_sc_type_and_never_by_the_name() {
    // Both are `enN` on macOS and the number tells you nothing: a Mac mini has
    // Ethernet on en0, a laptop has Wi-Fi there. Guessing would emit
    // NET.LINK.DOWN_WIFI for an unplugged cable.
    assert_eq!(classify("en0", Some(sc_type::WIFI)), LinkClass::WiFi);
    assert_eq!(
        classify("en0", Some(sc_type::ETHERNET)),
        LinkClass::Ethernet
    );
    assert_eq!(
        classify("en0", None),
        LinkClass::Unknown,
        "unknown, not a guess"
    );
    assert_eq!(classify("lo0", None), LinkClass::Loopback);
    assert_eq!(classify("utun7", None), LinkClass::Tunnel);
    assert_eq!(classify("ipsec0", None), LinkClass::Tunnel);
    assert_eq!(classify("pdp_ip0", None), LinkClass::Cellular);
    assert_eq!(classify("en5", Some(sc_type::WWAN)), LinkClass::Cellular);
    assert_eq!(classify("awdl0", None), LinkClass::WiFi);
    assert_eq!(
        classify("bridge0", Some(sc_type::BRIDGE)),
        LinkClass::Ethernet
    );
}

#[tokio::test]
async fn enumeration_refuses_rather_than_reporting_an_empty_host() {
    // "This host has no interfaces" is a FACT the core would act on; "we could not
    // look" is a refusal. Collapsing them is how a failed enumeration becomes a
    // decision to tear everything down.
    let provider = MacosInterfaceProvider::new(ShutdownLatch::new());
    assert!(provider.enumerate().await.is_err());
}

// ---------------------------------------------------------------------------
// Suspend / resume
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_resume_forces_a_re_enumeration_before_anything_can_look_green() {
    // ADR-0022: a resume must not render a confident, stale green. The adapter
    // reports the fact; the core decides. `EventsLost` arrives FIRST, so there is
    // no moment in which the core has a fresh-looking, unchanged picture.
    let provider = MacosInterfaceProvider::new(ShutdownLatch::new());
    let mut stream = provider.subscribe().expect("subscribes");
    let mut journal = PowerJournal::new();

    provider.publish_all(journal.observe_message(msg::SYSTEM_WILL_SLEEP).0);
    assert_eq!(journal.phase(), PowerPhase::Sleeping);
    assert_eq!(
        stream.next().await,
        Some(NetworkChange::LinkPostureChanged {
            metered: false,
            low_power: true,
        })
    );

    provider.publish_all(journal.observe_message(msg::SYSTEM_HAS_POWERED_ON).0);
    assert_eq!(
        stream.next().await,
        Some(NetworkChange::EventsLost { count: None }),
        "the gap is reported before anything else"
    );
    assert_eq!(
        stream.next().await,
        Some(NetworkChange::LinkPostureChanged {
            metered: false,
            low_power: false,
        })
    );
    assert!(journal.slept_across_last_wake());
}

#[tokio::test]
async fn a_sleep_tears_nothing_down() {
    // CB-6 again: a sleep is the core going quiet, and the anchor is the OS's.
    let (parts, rec) = parts(TunnelProvenance::OsProvidedFlow);
    let adapter = MacosPlatformAdapter::new(parts);
    adapter
        .network_config()
        .apply(&testkit::contract(1))
        .await
        .expect("applies");
    let loads = rec.pf.load_count();

    let mut journal = PowerJournal::new();
    let (events, needs_ack) = journal.observe_message(msg::SYSTEM_WILL_SLEEP);
    adapter.interface_provider().publish_all(events);
    assert!(
        needs_ack,
        "an unacknowledged WillSleep stalls the machine for thirty seconds and \
         then sleeps anyway"
    );
    assert_eq!(rec.pf.load_count(), loads);
    assert_eq!(
        adapter
            .network_config()
            .installed_ruleset()
            .await
            .expect("queries"),
        Some(Ruleset::Protected)
    );
}

#[test]
fn the_advisory_sleep_query_is_answered_and_never_vetoed() {
    // A VPN that held a laptop awake would be a worse product than one that
    // reconnected on wake, and ADR-0022 licenses no veto. The state machine has
    // no path that produces one.
    let mut journal = PowerJournal::new();
    let (events, needs_ack) = journal.observe_message(msg::CAN_SYSTEM_SLEEP);
    assert!(events.is_empty());
    assert!(needs_ack, "it must still be answered — with allow");
    assert_eq!(journal.phase(), PowerPhase::Awake);
}

// ---------------------------------------------------------------------------
// Daemon restart, and the datapath across it
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_provider_restarting_onto_an_existing_interface_adopts_it() {
    // The reclaim path. A provider that restarts is handed the SAME interface the
    // OS created for the previous instance, and a `create` that insisted on a
    // fresh one would fail on every restart.
    let (parts, _rec) = parts(TunnelProvenance::OsProvidedFlow);
    let adapter = MacosPlatformAdapter::new(parts);
    let port = Arc::new(QueuePort::new());
    adapter.tunnel_device().set_pending_port(port);
    let name = InterfaceName::new("utun7").expect("valid");

    let first = adapter
        .tunnel()
        .create_interface(&name, 1400)
        .await
        .expect("creates");
    let second = adapter
        .tunnel()
        .create_interface(&name, 1400)
        .await
        .expect("adopts the same one");
    assert_eq!(
        first, second,
        "two handles for one interface would let the core destroy one and \
         believe the other still lived"
    );
    assert_eq!(adapter.tunnel_device().mtu_of(first), Some(1400));
}

#[tokio::test]
async fn destroying_an_interface_is_idempotent_and_safe_after_a_crash() {
    let (parts, _rec) = parts(TunnelProvenance::OsProvidedFlow);
    let adapter = MacosPlatformAdapter::new(parts);
    adapter
        .tunnel_device()
        .set_pending_port(Arc::new(QueuePort::new()));
    let name = InterfaceName::new("utun7").expect("valid");
    let handle = adapter
        .tunnel()
        .create_interface(&name, 1400)
        .await
        .expect("creates");
    adapter
        .tunnel()
        .destroy_interface(handle)
        .await
        .expect("destroys");
    adapter
        .tunnel()
        .destroy_interface(handle)
        .await
        .expect("a handle we do not hold is success, not an error");
    adapter
        .tunnel()
        .destroy_interface(TunnelHandle(999))
        .await
        .expect("and so is one we never had");
}

#[tokio::test]
async fn an_mtu_below_the_ipv6_floor_is_refused_rather_than_carried() {
    // §6.2's 1280 floor. Accepting it would produce a tunnel that is up and
    // cannot pass v6 — the asymmetry R1 exists to forbid.
    let (parts, _rec) = parts(TunnelProvenance::OsProvidedFlow);
    let adapter = MacosPlatformAdapter::new(parts);
    adapter
        .tunnel_device()
        .set_pending_port(Arc::new(QueuePort::new()));
    let name = InterfaceName::new("utun7").expect("valid");
    assert!(adapter
        .tunnel()
        .create_interface(&name, 1279)
        .await
        .is_err());
    assert!(adapter.tunnel().create_interface(&name, 1280).await.is_ok());
}

#[tokio::test]
async fn a_packet_round_trips_through_the_utun_framing_in_both_families() {
    // PB-1's one permitted crossing, exercised end to end on this host: the
    // 4-byte family header is added on write and stripped on read, and the family
    // comes from the packet's own version nibble so the header and the payload
    // cannot disagree.
    let (parts, _rec) = parts(TunnelProvenance::OsProvidedFlow);
    let adapter = MacosPlatformAdapter::new(parts);
    let port = Arc::new(QueuePort::new());
    adapter.tunnel_device().set_pending_port(port.clone());
    let name = InterfaceName::new("utun7").expect("valid");
    let handle = adapter
        .tunnel()
        .create_interface(&name, 1400)
        .await
        .expect("creates");

    for (version, family) in [(4u8, AddressFamily::V4), (6u8, AddressFamily::V6)] {
        let mut packet = vec![0u8; 40];
        packet[0] = version << 4;
        packet[39] = 0xAB;

        // Out: the core writes, the provider drains a framed packet.
        let written = adapter
            .tunnel()
            .write_packet(handle, &packet)
            .await
            .expect("writes");
        assert_eq!(written, packet.len(), "the caller counts payload bytes");
        let frame = port.take_outbound().expect("a frame");
        let (decoded_family, payload) = decode_frame(&frame).expect("well formed");
        assert_eq!(decoded_family, family);
        assert_eq!(payload, packet.as_slice());

        // In: the provider pushes a framed packet, the core reads the payload.
        port.push_inbound(frame);
        let mut buf = vec![0u8; 1500];
        let read = adapter
            .tunnel()
            .read_packet(handle, &mut buf)
            .await
            .expect("reads");
        assert_eq!(&buf[..read], packet.as_slice());
    }
}

#[test]
fn the_family_header_is_network_byte_order_and_darwins_number() {
    // A little-endian write produces AF_INET as 0x02000000, which the kernel reads
    // as family 33554432 and drops — silently, with no error on the write.
    let mut frame = Vec::new();
    encode_frame(AddressFamily::V6, &[0x60, 0, 0, 0], &mut frame);
    assert_eq!(&frame[..FRAME_HEADER_LEN], &[0, 0, 0, 30]);
    encode_frame(AddressFamily::V4, &[0x45, 0, 0, 0], &mut frame);
    assert_eq!(&frame[..FRAME_HEADER_LEN], &[0, 0, 0, 2]);
}

#[test]
fn a_malformed_frame_is_refused_and_never_truncated_into_validity() {
    assert_eq!(decode_frame(&[]), Err(FrameError::TooShort));
    assert_eq!(decode_frame(&[0, 0, 0]), Err(FrameError::TooShort));
    assert_eq!(decode_frame(&[0, 0, 0, 2]), Err(FrameError::Empty));
    assert_eq!(
        decode_frame(&[0, 0, 0, 10, 0x45]),
        Err(FrameError::UnknownFamily(10)),
        "10 is LINUX's AF_INET6 and must not be accepted as v6 here"
    );
    assert_eq!(family_of_packet(&[0x45]), Some(AddressFamily::V4));
    assert_eq!(family_of_packet(&[0x60]), Some(AddressFamily::V6));
    assert_eq!(family_of_packet(&[0x00]), None);
    assert_eq!(family_of_packet(&[]), None);
}

// ---------------------------------------------------------------------------
// CB-2's falsification test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_mock_and_this_adapter_answer_the_same_questions_the_same_way() {
    // CD-5 calls the mock "the payoff": with every shell deleted and a mock
    // adapter bound, the core must still make every decision correctly. What that
    // means concretely for this adapter is that the two are interchangeable
    // through the trait — so a core written against one behaves identically
    // against the other, and any place they differ is a place where a decision
    // could hide.
    let mock = MockAdapter::new(&MockOptions::default());
    let (parts, _rec) = parts(TunnelProvenance::OsProvidedFlow);
    let macos = MacosPlatformAdapter::new(parts);

    let adapters: [&dyn PlatformAdapter; 2] = [&mock, &macos];
    for adapter in adapters {
        // Both name themselves, and the names differ — which is the point of
        // S-46: the bundle says which binding was loaded.
        assert!(!adapter.binding_name().is_empty());
        // Both start un-shut-down, and both latch on request without touching
        // enforcement.
        adapter.begin_shutdown();
        assert!(matches!(
            adapter
                .network_config()
                .apply(&testkit::contract(1))
                .await
                .expect_err("both refuse after shutdown"),
            PlatformError::ShuttingDown
        ));
    }
    assert_ne!(mock.binding_name(), macos.binding_name());
}
