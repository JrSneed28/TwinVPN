//! The `CALL` ladder end to end, over real sockets, on both address families.

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use twinvpn_rendezvous as rz;
use twinvpn_rendezvous::testkit;

/// The payload every forwarding test uses: a protobuf record whose field number
/// this build has no name for.
///
/// That is the point. Finding W-4 is that `prost` 0.13 **drops unknown fields on
/// decode and cannot re-emit them**, so a forwarder that decodes and re-encodes
/// silently deletes exactly this. If the octets arrive unchanged, the service
/// did not decode them.
fn unknown_field_payload() -> Vec<u8> {
    // field 31 (0xf8 0x01), varint 42 — then a length-delimited field 30 whose
    // contents this build also does not know.
    vec![0xf8, 0x01, 0x2a, 0xf2, 0x01, 0x03, 0x01, 0x02, 0x03]
}

#[tokio::test]
async fn a_call_to_an_attached_peer_is_forwarded_byte_for_byte() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let target = [0x11u8; 32];
    let payload = unknown_field_payload();

    let mut responder = common::Client::connect(h.addr).await;
    responder
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &target))
        .await;
    common::within(responder.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("attach acked");

    let mut initiator = common::Client::connect(h.addr).await;
    initiator
        .write(&testkit::call_frame(target, &payload))
        .await;

    let delivered = common::within(responder.read_until(rz::frame::Opcode::Deliver))
        .await
        .expect("the CALL reached the attached peer");
    assert_eq!(
        delivered, payload,
        "W-4: the received octets must be forwarded verbatim, unknown fields included"
    );
    h.stop().await;
}

#[tokio::test]
async fn a_call_to_a_detached_peer_is_mailboxed_and_delivered_on_attach() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let target = [0x22u8; 32];
    let payload = unknown_field_payload();

    let mut initiator = common::Client::connect(h.addr).await;
    initiator
        .write(&testkit::call_frame(target, &payload))
        .await;
    let ack = common::within(initiator.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("an informational answer");
    assert_eq!(
        common::reason_code(&ack).as_deref(),
        Some("CONTROL.PEER_NOT_ATTACHED"),
        "informational, never a gate"
    );

    // The peer arrives afterwards; the jitter buffer hands it over.
    let mut responder = common::Client::connect(h.addr).await;
    responder
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &target))
        .await;
    let delivered = common::within(responder.read_until(rz::frame::Opcode::Deliver))
        .await
        .expect("the buffered CALL arrived");
    assert_eq!(delivered, payload);
    h.stop().await;
}

#[tokio::test]
async fn a_mailboxed_call_is_never_replayed_to_a_second_attach() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let target = [0x23u8; 32];

    let mut initiator = common::Client::connect(h.addr).await;
    initiator
        .write(&testkit::call_frame(target, &testkit::payload(16)))
        .await;
    common::within(initiator.read_until(rz::frame::Opcode::Ack)).await;

    let mut first = common::Client::connect(h.addr).await;
    first
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &target))
        .await;
    common::within(first.read_until(rz::frame::Opcode::Deliver))
        .await
        .expect("delivered once");
    drop(first);

    // ADR-0002 N-9: a CALL is not replayed from a cursor, and the mailbox is not
    // durability. A second attach gets nothing.
    let mut second = common::Client::connect(h.addr).await;
    second
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &target))
        .await;
    let ack = common::within(second.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("attach acked");
    assert!(ack.is_empty(), "attach succeeded");
    let replayed = tokio::time::timeout(
        Duration::from_millis(250),
        second.read_until(rz::frame::Opcode::Deliver),
    )
    .await;
    assert!(replayed.is_err(), "N-9: a CALL must never be replayed");
    h.stop().await;
}

#[tokio::test]
async fn the_service_reports_the_observed_source_address_on_both_families() {
    use prost::Message as _;

    for host in [
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    ] {
        let h = common::start(host).await;
        let mut c = common::Client::connect(h.addr).await;
        let body = common::within(c.read_until(rz::frame::Opcode::Reflexive))
            .await
            .expect("networking.md A6(a): the reflexive report");
        let ep = twinvpn_schema::v1::Endpoint::decode(&body[..]).expect("an Endpoint");
        let parsed = twinvpn_schema::validate::endpoint(&ep).expect("a valid Endpoint");
        // The reported family must match the family the connection arrived on —
        // v4 and v6 side by side, never one mapped into the other.
        let expected = if host.is_ipv6() {
            twinvpn_types::AddressFamily::V6
        } else {
            twinvpn_types::AddressFamily::V4
        };
        assert_eq!(parsed.family(), expected);
        h.stop().await;
    }
}

#[tokio::test]
async fn a_second_attach_supersedes_the_first_and_the_first_is_told() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let target = [0x33u8; 32];

    let mut first = common::Client::connect(h.addr).await;
    first
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &target))
        .await;
    common::within(first.read_until(rz::frame::Opcode::Ack)).await;

    let mut second = common::Client::connect(h.addr).await;
    second
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &target))
        .await;
    common::within(second.read_until(rz::frame::Opcode::Ack)).await;

    // ADR-0002 N-1 and S-6: answered, never reset.
    let told = common::within(async {
        loop {
            let (op, body) = first.read_frame().await?;
            if op == rz::frame::Opcode::Ack.as_wire() {
                if let Some(code) = common::reason_code(&body) {
                    return Some(code);
                }
            }
        }
    })
    .await;
    assert_eq!(told.as_deref(), Some("CONTROL.SUPERSEDED_BY_NEW_ATTACH"));
    h.stop().await;
}

#[tokio::test]
async fn a_flood_from_one_source_is_deferred_with_a_retry_hint_not_reset() {
    let h = common::start_with(IpAddr::V6(Ipv6Addr::LOCALHOST), |mut c| {
        c.admission.sustained_per_sec = 1.0;
        c.admission.burst = 2;
        c
    })
    .await;

    let mut c = common::Client::connect(h.addr).await;
    let frame = testkit::call_frame([0x44u8; 32], &testkit::payload(16));
    let mut codes = Vec::new();
    for _ in 0..6 {
        c.write(&frame).await;
    }
    for _ in 0..6 {
        let body = common::within(c.read_until(rz::frame::Opcode::Ack))
            .await
            .expect("every CALL is answered");
        codes.push(common::reason_code(&body));
    }
    assert!(
        codes
            .iter()
            .any(|c| c.as_deref() == Some("CONTROL.ADMISSION_DEFERRED")),
        "S-6: over-limit must be answered, never reset: {codes:?}"
    );
    h.stop().await;
}

#[tokio::test]
async fn the_drain_stops_accepting_and_reports_honestly() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let addr = h.addr;
    let report = h.stop().await;
    assert!(
        report.drained,
        "the drain completed within the grace period"
    );
    // A drained listener is closed; a new connection either fails or reads
    // nothing. Either is a clean stop — what must not happen is serving.
    if let Ok(mut c) = tokio::net::TcpStream::connect(addr).await {
        use tokio::io::AsyncReadExt as _;
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_millis(250), c.read(&mut buf)).await;
        assert!(
            matches!(n, Ok(Ok(0)) | Err(_)),
            "a drained service must not serve"
        );
    }
}
