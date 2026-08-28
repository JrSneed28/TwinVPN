//! IPv4, IPv6, and the dual-stack listener in between.
//!
//! `docs/implementation/ownership.md` §6: "IPv4 and IPv6 are equally required —
//! there is no 'v6 later'. Every networking component considers IPv4, IPv6, dual
//! stack, IPv6-only, NAT64 where ADR-0010 requires it."
//!
//! The server-reflexive report is the **one candidate class this service is the
//! source of** (`networking.md` A6(a), ADR-0004 §5's free reflexive refresh), so
//! it is where that rule has teeth here. Everything else on this wire — host,
//! link-local, relay and peer-reflexive candidates — is opaque payload the
//! service forwards without looking at, which `call_flow.rs` covers.
//!
//! The case that motivated this file is the dual-stack one, because it fails
//! **silently**: a listener on `[::]` sees an IPv4 peer as `::ffff:a.b.c.d`, and
//! `twinvpn-types` rejects the IPv4-mapped form outright, so reporting it
//! verbatim produces an `Endpoint` every conformant client must refuse. No error
//! is logged anywhere — the deployment simply has no server-reflexive rung.

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use prost::Message as _;
use twinvpn_rendezvous as rz;

/// Reads the unsolicited `REFLEXIVE` and returns the validated endpoint.
async fn reflexive_of(c: &mut common::Client) -> twinvpn_types::Endpoint {
    let body = common::within(c.read_until(rz::frame::Opcode::Reflexive))
        .await
        .expect("networking.md A6(a): the reflexive report");
    let ep = twinvpn_schema::v1::Endpoint::decode(&body[..]).expect("an Endpoint");
    twinvpn_schema::validate::endpoint(&ep)
        .expect("the frozen contract must accept what this service emits")
}

#[tokio::test]
async fn a_v4_peer_on_a_dual_stack_listener_is_told_a_usable_v4_address() {
    // The listener is `[::]`, which is dual-stack on Linux, and the client comes
    // in over IPv4 — the deployed shape of every dual-stack rendezvous.
    let h = common::start(IpAddr::V6(Ipv6Addr::UNSPECIFIED)).await;
    let v4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), h.addr.port());

    let key = common::TestKey::generate();
    let mut c = common::Client::connect_as(v4_addr, &key, &h.server_spki).await;

    let ep = reflexive_of(&mut c).await;
    assert_eq!(
        ep.family(),
        twinvpn_types::AddressFamily::V4,
        "a v4 peer must be told a v4 address, not `::ffff:` — which the contract \
         rejects, costing the deployment its whole server-reflexive rung"
    );
    let twinvpn_types::IpAddr::V4(v4) = ep.address else {
        panic!("family said v4");
    };
    assert_eq!(v4.octets(), [127, 0, 0, 1]);
    h.stop().await;
}

#[tokio::test]
async fn a_v6_peer_on_a_dual_stack_listener_is_told_a_v6_address() {
    // The other half, on the same listener: unmapping must not have collapsed
    // both families onto one answer.
    let h = common::start(IpAddr::V6(Ipv6Addr::UNSPECIFIED)).await;
    let v6_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), h.addr.port());

    let key = common::TestKey::generate();
    let mut c = common::Client::connect_as(v6_addr, &key, &h.server_spki).await;

    let ep = reflexive_of(&mut c).await;
    assert_eq!(ep.family(), twinvpn_types::AddressFamily::V6);
    h.stop().await;
}

#[tokio::test]
async fn both_families_carry_a_full_exchange_on_one_dual_stack_listener() {
    // A v6 responder and a v4 initiator, meeting through one process. This is
    // what `networking.md` §3.8's NAT64 row and its dual-stack row reduce to at
    // this layer: the courier must not care which family either side used, and
    // the payload must cross unchanged.
    let h = common::start(IpAddr::V6(Ipv6Addr::UNSPECIFIED)).await;
    let port = h.addr.port();

    let device = common::TestKey::generate();
    let target = common::proven_device_id(&device);
    let mut responder = common::Client::connect_as(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        &device,
        &h.server_spki,
    )
    .await;
    responder
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &target))
        .await;
    common::within(responder.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("attach acked");

    let caller_key = common::TestKey::generate();
    let mut caller = common::Client::connect_as(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        &caller_key,
        &h.server_spki,
    )
    .await;
    let payload = vec![0xf8, 0x01, 0x2a, 0xf2, 0x01, 0x02, 0x07, 0x07];
    caller
        .write(&rz::testkit::call_frame(target, &payload))
        .await;

    let delivered = common::within(responder.read_until(rz::frame::Opcode::Deliver))
        .await
        .expect("a v4 initiator reaches a v6 responder through one listener");
    assert_eq!(delivered, payload, "and the octets cross unchanged");
    h.stop().await;
}
