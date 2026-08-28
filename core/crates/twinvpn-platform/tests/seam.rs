//! The seam's contracts, asserted against the mock binding.
//!
//! Every test here is a contract the *real* adapters must also satisfy. A mock
//! that were laxer than the contract would let the core pass tests it would fail
//! on a device, which is the one way a mock can be worse than no mock at all.

use std::sync::Arc;

use twinvpn_platform::mock::{MockAdapter, MockNetwork, MockOptions};
use twinvpn_platform::{
    ContractGeneration, Datapath, DnsConfig, IdentityKeyRef, InterfaceName, LinkState,
    NetworkChange, NetworkContract, PlatformAdapter, PlatformError, Ruleset, SecureItem,
    SecureItemKey, SocketFamily, SocketOptions, SupportedFamilies, UdpBindSpec,
};
use twinvpn_types::{
    codes, AddressFamily, Endpoint, InterfaceAddress, IpAddr, PerFamily, Port, V4Addr, V6Addr,
};

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    // A minimal executor: every mock future either completes on the first poll
    // or is woken by another future's completion within the same test, so a
    // parked thread is all that is needed and no runtime dependency is pulled in.
    struct Park(std::thread::Thread);
    impl std::task::Wake for Park {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(Arc::new(Park(std::thread::current())));
    let mut cx = std::task::Context::from_waker(&waker);
    let mut f = Box::pin(f);
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::park_timeout(std::time::Duration::from_millis(50));
    }
}

fn v4(o: [u8; 4], port: u16) -> Endpoint {
    Endpoint::new(
        IpAddr::V4(V4Addr::from_octets(o)),
        Port::new(port).expect("port"),
    )
}

fn v6_ep(port: u16) -> Endpoint {
    let mut o = [0u8; 16];
    o[0] = 0x20;
    o[1] = 0x01;
    o[15] = 1;
    Endpoint::new(
        IpAddr::V6(V6Addr::new(o, None).expect("v6")),
        Port::new(port).expect("port"),
    )
}

fn contract(generation: u64, ruleset: Ruleset) -> NetworkContract {
    NetworkContract {
        generation: ContractGeneration(generation),
        // ADR-0010 R1: both families, always. `PerFamily` makes the v6 half a
        // compile error to omit.
        addresses: PerFamily::new(
            vec![
                InterfaceAddress::new(IpAddr::V4(V4Addr::from_octets([100, 64, 0, 1])), 32).unwrap(),
            ],
            vec![InterfaceAddress::new(
                IpAddr::V6(
                    V6Addr::new(
                        [
                            0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                        ],
                        None,
                    )
                    .unwrap(),
                ),
                128,
            )
            .unwrap()],
        ),
        routes: PerFamily::new(Vec::new(), Vec::new()),
        dns: DnsConfig {
            resolvers: PerFamily::new(Vec::new(), Vec::new()),
            search_domains: Vec::new(),
            split_domains: Vec::new(),
            is_default_resolver: false,
        },
        ruleset,
        mtu: 1280,
        tunnel_remote_address: None,
    }
}

// ---------------------------------------------------------------------------
// CB-2: with every shell deleted and a mock bound, the core can still act
// ---------------------------------------------------------------------------

#[test]
fn the_whole_adapter_is_reachable_through_the_trait_alone() {
    let adapter = MockAdapter::new(&MockOptions::default());
    let a: &dyn PlatformAdapter = &adapter;
    assert_eq!(a.binding_name(), "mock-in-memory");
    // Every capability, through the trait, with no concrete type named.
    let _ = a.sockets();
    let _ = a.tunnel();
    let _ = a.network_config();
    let _ = a.interfaces();
    let _ = a.identity();
    let _ = a.store();
}

// ---------------------------------------------------------------------------
// Sockets: v4, v6, dual-stack, IPv6-only
// ---------------------------------------------------------------------------

#[test]
fn both_families_bind_and_neither_is_special() {
    let adapter = MockAdapter::new(&MockOptions::default());
    for family in [
        SocketFamily::V4,
        SocketFamily::V6Only,
        SocketFamily::V6DualStack,
    ] {
        let spec = UdpBindSpec {
            family,
            local: None,
            options: SocketOptions::default(),
        };
        let socket = block_on(adapter.sockets().bind_udp(&spec)).expect("bind");
        assert_eq!(socket.family(), family);
        block_on(socket.close()).expect("close");
    }
    assert_eq!(adapter.sockets_mock().opened(), 3);
}

#[test]
fn an_ipv6_only_host_reports_the_fact_rather_than_substituting_v4() {
    let adapter = MockAdapter::new(&MockOptions {
        supported_families: SupportedFamilies {
            v4: false,
            v6: true,
            dual_stack_socket: false,
        },
        ..MockOptions::default()
    });
    let spec = UdpBindSpec {
        family: SocketFamily::V4,
        local: None,
        options: SocketOptions::default(),
    };
    let Err(err) = block_on(adapter.sockets().bind_udp(&spec)) else {
        panic!("v4 must be reported unavailable, never substituted");
    };
    assert_eq!(err.reason_code(), codes::PLATFORM_OS_UNSUPPORTED);
    // v6 still binds: an IPv6-only host is a first-class situation, not a fault.
    let spec6 = UdpBindSpec {
        family: SocketFamily::V6Only,
        local: None,
        options: SocketOptions::default(),
    };
    assert!(block_on(adapter.sockets().bind_udp(&spec6)).is_ok());
}

#[test]
fn two_adapters_on_one_network_exchange_datagrams_in_both_families() {
    let network = MockNetwork::new();
    let a = MockAdapter::on_network(&network, &MockOptions::default());
    let b = MockAdapter::on_network(&network, &MockOptions::default());

    for (family, local, peer) in [
        (
            SocketFamily::V4,
            v4([10, 0, 0, 1], 5000),
            v4([10, 0, 0, 2], 5001),
        ),
        (SocketFamily::V6Only, v6_ep(6000), v6_ep(6001)),
    ] {
        let sock_a = block_on(a.sockets().bind_udp(&UdpBindSpec {
            family,
            local: Some(local),
            options: SocketOptions::default(),
        }))
        .expect("bind a");
        let sock_b = block_on(b.sockets().bind_udp(&UdpBindSpec {
            family,
            local: Some(peer),
            options: SocketOptions::default(),
        }))
        .expect("bind b");

        block_on(sock_a.send_to(b"disco", &peer)).expect("send");
        let mut buf = [0u8; 64];
        let dg = block_on(sock_b.recv_from(&mut buf)).expect("recv");
        assert_eq!(&buf[..dg.len], b"disco");
        assert_eq!(dg.source, local);
        assert!(!dg.truncated);
        block_on(sock_a.close()).expect("close");
        block_on(sock_b.close()).expect("close");
    }
}

#[test]
fn a_truncated_datagram_is_reported_never_silently_shortened() {
    let network = MockNetwork::new();
    let a = MockAdapter::on_network(&network, &MockOptions::default());
    let local = v4([10, 0, 0, 1], 7000);
    let peer = v4([10, 0, 0, 2], 7001);
    let s1 = block_on(a.sockets().bind_udp(&UdpBindSpec {
        family: SocketFamily::V4,
        local: Some(local),
        options: SocketOptions::default(),
    }))
    .expect("bind");
    let s2 = block_on(a.sockets().bind_udp(&UdpBindSpec {
        family: SocketFamily::V4,
        local: Some(peer),
        options: SocketOptions::default(),
    }))
    .expect("bind");
    block_on(s1.send_to(&[7u8; 100], &peer)).expect("send");
    let mut small = [0u8; 10];
    let dg = block_on(s2.recv_from(&mut small)).expect("recv");
    assert_eq!(dg.len, 10);
    assert!(
        dg.truncated,
        "a silently truncated datagram fails authentication for a reason nobody can see"
    );
}

#[test]
fn a_cross_family_send_is_refused_not_coerced() {
    let network = MockNetwork::new();
    let a = MockAdapter::on_network(&network, &MockOptions::default());
    let sock = block_on(a.sockets().bind_udp(&UdpBindSpec {
        family: SocketFamily::V6Only,
        local: Some(v6_ep(8000)),
        options: SocketOptions::default(),
    }))
    .expect("bind");
    let err = block_on(sock.send_to(b"x", &v4([10, 0, 0, 9], 9000)))
        .expect_err("a v6-only socket cannot reach a v4 peer");
    assert_eq!(err.reason_code(), codes::NET_NO_ROUTE);
}

#[test]
fn multicast_announcements_reach_every_joined_member() {
    use twinvpn_platform::{InterfaceIndex, MulticastOptions};

    let network = MockNetwork::new();
    let a = MockAdapter::on_network(&network, &MockOptions::default());
    let group = v4([239, 1, 2, 3], 5353);
    let mc = MulticastOptions {
        group: group.address,
        interface: InterfaceIndex(2),
        loopback: true,
        hop_limit: 1,
    };
    let listener = block_on(a.sockets().bind_udp(&UdpBindSpec {
        family: SocketFamily::V4,
        local: Some(v4([10, 0, 0, 5], 5353)),
        options: SocketOptions {
            multicast: Some(mc.clone()),
            ..SocketOptions::default()
        },
    }))
    .expect("bind listener");
    let sender = block_on(a.sockets().bind_udp(&UdpBindSpec {
        family: SocketFamily::V4,
        local: Some(v4([10, 0, 0, 6], 5354)),
        options: SocketOptions::default(),
    }))
    .expect("bind sender");

    block_on(sender.send_to(b"announce", &group)).expect("send");
    let mut buf = [0u8; 64];
    let dg = block_on(listener.recv_from(&mut buf)).expect("recv");
    assert_eq!(&buf[..dg.len], b"announce");

    listener.leave_multicast(&mc).expect("leave");
    let before = network.counters().1;
    block_on(sender.send_to(b"again", &group)).expect("send");
    assert_eq!(
        network.counters().1,
        before + 1,
        "after leaving, the announcement is dropped rather than delivered"
    );
}

#[test]
fn closing_a_socket_is_idempotent() {
    let adapter = MockAdapter::new(&MockOptions::default());
    let sock = block_on(adapter.sockets().bind_udp(&UdpBindSpec {
        family: SocketFamily::V4,
        local: None,
        options: SocketOptions::default(),
    }))
    .expect("bind");
    assert!(block_on(sock.close()).is_ok());
    assert!(block_on(sock.close()).is_ok());
}

// ---------------------------------------------------------------------------
// The tunnel device
// ---------------------------------------------------------------------------

#[test]
fn an_interface_is_created_down() {
    let adapter = MockAdapter::new(&MockOptions::default());
    let name = InterfaceName::new("twn0").expect("name");
    let handle = block_on(adapter.tunnel().create_interface(&name, 1280)).expect("create");
    assert_eq!(
        adapter.tunnel_mock().link_state(handle),
        Some(LinkState::Down),
        "an interface that comes up before its rules are installed is the leak window"
    );
    block_on(adapter.tunnel().set_link(handle, LinkState::Up)).expect("up");
    assert_eq!(
        adapter.tunnel_mock().link_state(handle),
        Some(LinkState::Up)
    );
}

#[test]
fn destroy_interface_is_idempotent_and_safe_after_a_crash() {
    let adapter = MockAdapter::new(&MockOptions::default());
    let name = InterfaceName::new("twn0").expect("name");
    let handle = block_on(adapter.tunnel().create_interface(&name, 1280)).expect("create");
    assert!(block_on(adapter.tunnel().destroy_interface(handle)).is_ok());
    // Again, as after an unclean exit where the core does not know what it left.
    assert!(block_on(adapter.tunnel().destroy_interface(handle)).is_ok());
    assert_eq!(adapter.tunnel_mock().destroy_calls(), 2);
}

#[test]
fn a_kernel_offload_target_refuses_packet_io() {
    let adapter = MockAdapter::new(&MockOptions {
        datapath: Datapath::KernelOffload,
        ..MockOptions::default()
    });
    assert_eq!(adapter.tunnel().datapath(), Datapath::KernelOffload);
    let name = InterfaceName::new("wg0").expect("name");
    let handle = block_on(adapter.tunnel().create_interface(&name, 1420)).expect("create");
    let mut buf = [0u8; 64];
    // PB-1: on this target the core never sees a packet.
    assert!(block_on(adapter.tunnel().read_packet(handle, &mut buf)).is_err());
    assert!(block_on(adapter.tunnel().write_packet(handle, b"p")).is_err());
}

#[test]
fn a_userspace_target_carries_packets_both_ways() {
    let adapter = MockAdapter::new(&MockOptions::default());
    let name = InterfaceName::new("utun3").expect("name");
    let handle = block_on(adapter.tunnel().create_interface(&name, 1280)).expect("create");
    adapter.tunnel_mock().push_inbound(b"inbound".to_vec());
    let mut buf = [0u8; 64];
    let n = block_on(adapter.tunnel().read_packet(handle, &mut buf)).expect("read");
    assert_eq!(&buf[..n], b"inbound");
    block_on(adapter.tunnel().write_packet(handle, b"outbound")).expect("write");
    assert_eq!(adapter.tunnel_mock().written(), vec![b"outbound".to_vec()]);
}

#[test]
fn the_mtu_can_be_raised_and_lowered_as_dplpmtud_probes() {
    let adapter = MockAdapter::new(&MockOptions::default());
    let name = InterfaceName::new("twn0").expect("name");
    let handle = block_on(adapter.tunnel().create_interface(&name, 1280)).expect("create");
    block_on(adapter.tunnel().set_mtu(handle, 1420)).expect("raise");
    assert_eq!(adapter.tunnel_mock().mtu(handle), Some(1420));
    block_on(adapter.tunnel().set_mtu(handle, 1280)).expect("lower");
    assert_eq!(adapter.tunnel_mock().mtu(handle), Some(1280));
}

// ---------------------------------------------------------------------------
// apply / rollback / set_ruleset — the transactional contract
// ---------------------------------------------------------------------------

#[test]
fn apply_is_idempotent_on_the_generation_id() {
    let adapter = MockAdapter::new(&MockOptions::default());
    let c = contract(1, Ruleset::Protected);
    block_on(adapter.network_config().apply(&c)).expect("apply");
    // A retry after a crash converges rather than duplicating routes.
    block_on(adapter.network_config().apply(&c)).expect("re-apply");
    assert_eq!(adapter.config_mock().apply_calls(), 2);
    assert_eq!(
        block_on(adapter.network_config().current_generation()).expect("read"),
        Some(ContractGeneration(1))
    );
}

#[test]
fn a_failed_apply_leaves_the_previous_generation_exactly_intact() {
    let adapter = MockAdapter::new(&MockOptions::default());
    block_on(
        adapter
            .network_config()
            .apply(&contract(1, Ruleset::Protected)),
    )
    .expect("apply 1");

    adapter.fail_next_apply(PlatformError::RouteProgrammingDenied(None));
    let err = block_on(
        adapter
            .network_config()
            .apply(&contract(2, Ruleset::Blocked)),
    )
    .expect_err("apply 2 must fail");
    assert_eq!(err.reason_code(), codes::ROUTE_PROGRAMMING_DENIED);

    // All-or-nothing: generation 1 is still in force, with its ruleset.
    assert_eq!(
        block_on(adapter.network_config().current_generation()).expect("read"),
        Some(ContractGeneration(1))
    );
    assert_eq!(
        block_on(adapter.network_config().installed_ruleset()).expect("read"),
        Some(Ruleset::Protected)
    );
}

#[test]
fn rollback_restores_the_previous_generation_exactly() {
    let adapter = MockAdapter::new(&MockOptions::default());
    block_on(
        adapter
            .network_config()
            .apply(&contract(1, Ruleset::Protected)),
    )
    .expect("1");
    block_on(
        adapter
            .network_config()
            .apply(&contract(2, Ruleset::Blocked)),
    )
    .expect("2");
    block_on(adapter.network_config().rollback(ContractGeneration(2))).expect("rollback");
    assert_eq!(
        block_on(adapter.network_config().current_generation()).expect("read"),
        Some(ContractGeneration(1))
    );
    assert_eq!(
        block_on(adapter.network_config().installed_ruleset()).expect("read"),
        Some(Ruleset::Protected)
    );
}

#[test]
fn the_ruleset_swap_is_atomic_and_the_rules_are_never_absent() {
    let adapter = MockAdapter::new(&MockOptions::default());
    let cfg = adapter.network_config();
    block_on(cfg.apply(&contract(1, Ruleset::Blocked))).expect("apply");
    assert_eq!(
        block_on(cfg.installed_ruleset()).expect("read"),
        Some(Ruleset::Blocked)
    );
    block_on(cfg.set_ruleset(ContractGeneration(1), Ruleset::Protected)).expect("swap");
    assert_eq!(
        block_on(cfg.installed_ruleset()).expect("read"),
        Some(Ruleset::Protected)
    );
    // There is no API by which a caller can remove the ruleset: KS-17's "rules
    // are NEVER absent" is expressed by the absence of the operation.
    assert!(cfg.enforcement_custody().swap_is_atomic);
}

/// CB-6: a core crash cannot drop protection, because the OS holds the rules.
#[test]
fn shutdown_does_not_tear_down_enforcement() {
    let adapter = MockAdapter::new(&MockOptions::default());
    block_on(
        adapter
            .network_config()
            .apply(&contract(1, Ruleset::Blocked)),
    )
    .expect("apply");
    adapter.begin_shutdown();
    assert_eq!(
        block_on(adapter.network_config().installed_ruleset()).expect("read"),
        Some(Ruleset::Blocked),
        "CB-6: the OS holds the ruleset, so shutting the core down must not clear it"
    );
    // New work is refused rather than silently accepted.
    let err = block_on(
        adapter
            .network_config()
            .apply(&contract(2, Ruleset::Protected)),
    )
    .expect_err("refused after shutdown");
    assert_eq!(err, PlatformError::ShuttingDown);
}

#[test]
fn a_target_whose_rules_die_with_the_process_declares_it() {
    let weak = MockAdapter::new(&MockOptions {
        enforcement_survives_core_exit: false,
        ..MockOptions::default()
    });
    assert!(
        !weak
            .network_config()
            .enforcement_custody()
            .survives_core_exit,
        "a target without CB-6's guarantee must say so rather than let it be inferred"
    );
}

#[test]
fn link_facts_report_both_families_separately() {
    let adapter = MockAdapter::new(&MockOptions::default());
    let facts = block_on(adapter.network_config().query_link_facts()).expect("facts");
    assert!(*facts.default_routes.get(AddressFamily::V4));
    assert!(*facts.default_routes.get(AddressFamily::V6));
    assert!(facts.families.carries(AddressFamily::V6));
}

// ---------------------------------------------------------------------------
// Interface changes are events
// ---------------------------------------------------------------------------

#[test]
fn interface_changes_arrive_as_events_and_a_dropped_event_is_itself_reported() {
    let adapter = MockAdapter::new(&MockOptions::default());
    let mut stream = adapter.interfaces().subscribe().expect("subscribe");
    let ifaces = adapter.interfaces_mock();

    // ADR-0010 R6's case: IPv6 appears AFTER the tunnel is up. It must be its
    // own event, per family, or it is indistinguishable from nothing happening.
    ifaces.emit(&NetworkChange::DefaultRouteChanged {
        family: AddressFamily::V6,
        present: true,
    });
    ifaces.emit(&NetworkChange::EventsLost { count: Some(3) });

    let mut seen = Vec::new();
    for _ in 0..2 {
        seen.push(block_on(std::future::poll_fn(|cx| {
            futures_core::Stream::poll_next(stream.as_mut(), cx)
        })));
    }
    assert_eq!(
        seen[0],
        Some(NetworkChange::DefaultRouteChanged {
            family: AddressFamily::V6,
            present: true
        })
    );
    assert_eq!(seen[1], Some(NetworkChange::EventsLost { count: Some(3) }));
}

#[test]
fn interface_names_are_bounded_and_redacted() {
    assert!(InterfaceName::new("eth0").is_ok());
    assert!(InterfaceName::new("").is_err());
    assert!(InterfaceName::new(&"a".repeat(256)).is_err());
    assert!(InterfaceName::new("bad\nname").is_err());
    let name = InterfaceName::new("wlan0").expect("name");
    assert!(!format!("{name:?}").contains("wlan0"));
}

// ---------------------------------------------------------------------------
// CB-5: the identity private half never crosses the seam
// ---------------------------------------------------------------------------

#[test]
fn identity_operations_return_a_signature_never_a_key() {
    let adapter = MockAdapter::new(&MockOptions::default());
    adapter.identity_mock().allow_insecure_stub_signer();
    let public = block_on(adapter.identity().public_identity()).expect("public");
    assert_eq!(public.generation, 0);

    let sig = block_on(
        adapter
            .identity()
            .identity_sign(IdentityKeyRef::Identity { generation: 0 }, b"transcript"),
    )
    .expect("sign");
    assert_eq!(sig.as_bytes().len(), 32);
    // A signature's Debug must not dump it into a support bundle.
    assert!(!format!("{sig:?}").contains("00"));
    assert_eq!(adapter.identity_mock().sign_calls(), 1);
}

#[test]
fn rotation_changes_the_identity_id_and_leaves_the_device_id_alone() {
    let adapter = MockAdapter::new(&MockOptions::default());
    let before = block_on(adapter.identity().public_identity()).expect("public");
    adapter
        .identity_mock()
        .rotate(twinvpn_types::IdentityId::from_array([0xee; 32]));
    let after = block_on(adapter.identity().public_identity()).expect("public");
    assert_eq!(
        after.device_id, before.device_id,
        "identifiers.md §2: rotation MUST NOT change device_id"
    );
    assert_ne!(after.identity_id, before.identity_id);
    assert_eq!(after.generation, before.generation + 1);
}

#[test]
fn a_locked_device_reports_auth_key_unavailable() {
    let adapter = MockAdapter::new(&MockOptions::default());
    adapter.identity_mock().allow_insecure_stub_signer();
    adapter.identity_mock().set_unavailable(true);
    let err = block_on(
        adapter
            .identity()
            .identity_sign(IdentityKeyRef::Identity { generation: 0 }, b"x"),
    )
    .expect_err("locked");
    assert_eq!(err.reason_code(), codes::AUTH_KEY_UNAVAILABLE);
}

#[test]
fn hardware_backing_is_reported_truthfully() {
    let adapter = MockAdapter::new(&MockOptions::default());
    let attestation = block_on(adapter.identity().identity_attestation()).expect("attestation");
    assert!(
        !attestation.hardware_backed,
        "§11.16 (l): reported truthfully; the core MUST NOT assume an element it does not have"
    );
}

#[test]
fn in_element_agree_is_not_required_and_says_so() {
    let adapter = MockAdapter::new(&MockOptions::default());
    let err = block_on(adapter.identity().identity_agree(
        IdentityKeyRef::Identity { generation: 0 },
        &twinvpn_platform::PeerPublicKey(vec![1; 32]),
    ))
    .expect_err("not required per §11.16 (c)");
    assert_eq!(err.reason_code(), codes::PLATFORM_OS_UNSUPPORTED);
}

#[test]
fn a_shared_secret_is_redacted_move_only_and_scrubbed() {
    use twinvpn_platform::SharedSecret;
    let secret = SharedSecret::new(vec![0x5a; 32]);
    assert_eq!(secret.len(), 32);
    assert!(!format!("{secret:?}").contains("5a"));
    // The only accessor is named for its one legitimate destination and consumes
    // the value, so a shared secret cannot be used twice by accident.
    let bytes = secret.expose_for_kdf();
    assert_eq!(bytes.len(), 32);
}

// ---------------------------------------------------------------------------
// CB-7: Tier-1 items and the vended store root
// ---------------------------------------------------------------------------

#[test]
fn secure_items_round_trip_and_absence_is_not_an_error() {
    let adapter = MockAdapter::new(&MockOptions::default());
    let key = SecureItemKey::new("store.sek").expect("key");
    // "Absent" is a normal first-run state and must not be confused with
    // "unavailable", which must not enrol.
    assert!(block_on(adapter.store().secure_item_read(&key))
        .expect("read")
        .is_none());
    block_on(
        adapter
            .store()
            .secure_item_write_atomic(&key, &SecureItem::new(vec![9u8; 32])),
    )
    .expect("write");
    let item = block_on(adapter.store().secure_item_read(&key))
        .expect("read")
        .expect("present");
    assert_eq!(item.as_bytes(), &[9u8; 32]);
    assert!(!format!("{item:?}").contains('9'));
    block_on(adapter.store().secure_item_delete(&key)).expect("delete");
    // Idempotent.
    block_on(adapter.store().secure_item_delete(&key)).expect("delete again");
}

#[test]
fn an_unavailable_store_is_distinguishable_from_an_absent_item() {
    let adapter = MockAdapter::new(&MockOptions::default());
    let key = SecureItemKey::new("store.sek").expect("key");
    adapter.store_mock().set_unavailable(true);
    let err = block_on(adapter.store().secure_item_read(&key)).expect_err("unavailable");
    assert_eq!(err.reason_code(), codes::AUTH_KEY_STORE_UNAVAILABLE);
}

#[test]
fn secure_item_keys_are_bounded_and_shape_checked() {
    assert!(SecureItemKey::new("store.sek").is_ok());
    assert!(SecureItemKey::new("k_bind-2").is_ok());
    assert!(SecureItemKey::new("").is_err());
    assert!(SecureItemKey::new("Upper").is_err());
    assert!(SecureItemKey::new("has space").is_err());
    assert!(SecureItemKey::new(&"a".repeat(129)).is_err());
}

#[test]
fn the_store_root_is_vended_with_its_attributes_already_applied() {
    let adapter = MockAdapter::new(&MockOptions::default());
    // Unvended: an error, not an invented path.
    assert!(block_on(adapter.store().store_root()).is_err());
    adapter
        .store_mock()
        .set_store_root(std::path::PathBuf::from("/vault"));
    let root = block_on(adapter.store().store_root()).expect("root");
    assert_eq!(root.path, std::path::PathBuf::from("/vault"));
    assert!(root.attributes.backup_excluded);
    assert!(root.attributes.owner_only);
}

#[test]
fn record_aead_custody_is_a_declared_per_target_fact() {
    use twinvpn_platform::RecordAeadCustody;
    // The common case — 8 of 10 real targets, per ADR-0020's survey.
    let software = MockAdapter::new(&MockOptions::default());
    assert_eq!(
        software.store().record_aead_custody(),
        RecordAeadCustody::CoreHeld
    );
    let hardware = MockAdapter::new(&MockOptions {
        platform_performs_record_aead: true,
        ..MockOptions::default()
    });
    assert_eq!(
        hardware.store().record_aead_custody(),
        RecordAeadCustody::PlatformPerformed
    );
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[test]
fn every_platform_error_maps_to_a_registered_code_and_never_to_a_bare_number() {
    use twinvpn_platform::OsDetail;
    let detail = OsDetail {
        code: 13,
        call: "bind",
    };
    let errors = [
        PlatformError::AdapterUnavailable(Some(detail)),
        PlatformError::VpnPermissionDenied(None),
        PlatformError::NotPermitted(Some(detail)),
        PlatformError::OsUnsupported(None),
        PlatformError::ThirdPartyFilterSuspected(None),
        PlatformError::NoRoute(None),
        PlatformError::InterfaceDown(None),
        PlatformError::RouteProgrammingDenied(None),
        PlatformError::SecureStoreUnavailable(None),
        PlatformError::IdentityKeyUnavailable(None),
        PlatformError::Cancelled,
        PlatformError::ShuttingDown,
        PlatformError::Transient(None),
    ];
    for e in errors {
        let code = e.reason_code();
        // Registered, by construction — `ReasonCode` cannot name an unregistered
        // code — and the rendered form is the code, never the errno.
        assert!(twinvpn_types::ReasonCode::lookup(code.as_str()).is_some());
        let d = e.diagnostic(twinvpn_types::Component::PlatformAdapter);
        assert_eq!(d.code(), code);
    }
    // The OS's own number is available for a support case, and only there.
    assert_eq!(
        PlatformError::NotPermitted(Some(detail)).os_detail(),
        Some(detail)
    );
    assert_eq!(PlatformError::Cancelled.os_detail(), None);
}
