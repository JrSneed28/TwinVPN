//! Presence semantics end to end, over real sockets, on both address families.

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use twinvpn_presence as pr;
use twinvpn_presence::testkit;
use twinvpn_schema::v1;

fn now_ms() -> u64 {
    pr::server::now_ms()
}

#[tokio::test]
async fn a_heartbeat_is_accepted_and_fanned_out_as_one_presence_updated() {
    use prost::Message as _;

    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let device = [0x11u8; 32];

    let mut subscriber = h.client().await;
    subscriber
        .write(&pr::frame::encode(pr::frame::Opcode::Subscribe, &[]))
        .await;
    common::within(subscriber.read_until(pr::frame::Opcode::Ack)).await;

    let mut publisher = h.client().await;
    publisher.bind(device).await;
    publisher
        .write(&testkit::publish_frame(&testkit::heartbeat(
            device,
            v1::PresenceState::Online,
            now_ms() + 60_000,
        )))
        .await;
    let ack = common::within(publisher.read_until(pr::frame::Opcode::Ack))
        .await
        .expect("acked");
    let resp = common::response(&ack);
    assert!(resp.error.is_none(), "{:?}", resp.error);
    assert_eq!(
        resp.ack.unwrap().suggested_interval_ms,
        30_000,
        "advisory cadence, coalesced into an existing wake window"
    );

    let event_bytes = common::within(subscriber.read_until(pr::frame::Opcode::Event))
        .await
        .expect("fanned out");
    let event = v1::ControlEvent::decode(&event_bytes[..]).expect("a ControlEvent");
    // ADR-0002 N-9: ephemeral, no cursor position, never replayed.
    assert_eq!(event.durability, v1::EventDurability::Ephemeral as i32);
    assert_eq!(event.metadata.as_ref().unwrap().net_seq, 0);
    // S-11: the device owns the fact; this service only transports it.
    assert_eq!(
        event.publisher,
        v1::EventPublisher::OriginatingDevice as i32
    );
    let Some(v1::control_event::Event::PresenceUpdated(u)) = event.event else {
        panic!("presence publishes exactly one event shape")
    };
    let presence = u.presence.unwrap();
    assert_eq!(presence.state, v1::PresenceState::Online as i32);
    assert_eq!(presence.device_id, device.to_vec());
    h.stop().await;
}

#[tokio::test]
async fn a_device_cannot_assert_another_devices_presence() {
    // S-11 and presence.proto: "a device may assert presence ONLY FOR ITSELF.
    // A Presence naming another device_id is rejected."
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let mut c = h.client().await;
    c.bind([0x22u8; 32]).await;
    c.write(&testkit::publish_frame(&testkit::heartbeat(
        [0x99u8; 32],
        v1::PresenceState::Online,
        now_ms() + 60_000,
    )))
    .await;
    let body = common::within(c.read_until(pr::frame::Opcode::Ack))
        .await
        .expect("answered");
    let resp = common::response(&body);
    let err = resp.error.expect("a refusal");
    assert_eq!(err.reason_code, "CONTROL.EVENT_WRONG_PUBLISHER");
    // The evidence must name a pseudonym, never the device identifier it saw.
    let rendered = format!("{err:?}");
    assert!(
        !rendered.contains("153, 153"),
        "an identifier reached an evidence field: {rendered}"
    );
    assert_eq!(h.shared.store.lock().await.len(), 0, "nothing was stored");
    h.stop().await;
}

#[tokio::test]
async fn a_reordered_pair_settles_on_the_right_answer() {
    // docs/protocol.md §9.2: NO ORDERING GUARANTEE, consumers MUST tolerate
    // reordering. The absolute expires_at_ms is what makes that survivable.
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let device = [0x33u8; 32];
    let base = now_ms();

    let mut c = h.client().await;
    c.bind(device).await;

    // The device emitted OFFLINE first and ONLINE second, and they arrive the
    // other way round.
    for (state, expiry) in [
        (v1::PresenceState::Online, base + 90_000),
        (v1::PresenceState::Offline, base + 30_000),
    ] {
        c.write(&testkit::publish_frame(&testkit::heartbeat(
            device, state, expiry,
        )))
        .await;
        common::within(c.read_until(pr::frame::Opcode::Ack)).await;
    }

    let state = h
        .shared
        .store
        .lock()
        .await
        .get(device, std::time::Instant::now())
        .map(|r| r.state);
    assert_eq!(
        state,
        Some(v1::PresenceState::Online as i32),
        "a reordered OFFLINE must not overwrite a newer ONLINE"
    );
    h.stop().await;
}

#[tokio::test]
async fn a_lost_heartbeat_is_not_an_error_on_the_wire() {
    // ADR-0008 N-9: presence is "PERMITTED TO BE LOST". A superseded heartbeat
    // must not be answered with an error, because that would teach a client to
    // retry a heartbeat.
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let device = [0x44u8; 32];
    let base = now_ms();
    let mut c = h.client().await;
    c.bind(device).await;

    for expiry in [base + 90_000, base + 30_000] {
        c.write(&testkit::publish_frame(&testkit::heartbeat(
            device,
            v1::PresenceState::Online,
            expiry,
        )))
        .await;
        let body = common::within(c.read_until(pr::frame::Opcode::Ack))
            .await
            .expect("answered");
        assert!(
            common::response(&body).error.is_none(),
            "a loss is not an error"
        );
    }
    h.stop().await;
}

#[tokio::test]
async fn an_expiry_beyond_the_record_ttl_is_refused_never_clamped() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let device = [0x55u8; 32];
    let mut c = h.client().await;
    c.bind(device).await;
    c.write(&testkit::publish_frame(&testkit::heartbeat(
        device,
        v1::PresenceState::Online,
        now_ms() + 31_536_000_000, // a year
    )))
    .await;
    common::within(c.read_until(pr::frame::Opcode::Ack)).await;
    assert_eq!(
        h.shared.store.lock().await.len(),
        0,
        "a device must not be able to pin itself ONLINE past the record TTL"
    );
    h.stop().await;
}

#[tokio::test]
async fn presence_works_identically_over_ipv4() {
    let h = common::start(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    let device = [0x66u8; 32];
    let mut c = h.client().await;
    c.bind(device).await;
    c.write(&testkit::publish_frame(&testkit::heartbeat(
        device,
        v1::PresenceState::Idle,
        now_ms() + 60_000,
    )))
    .await;
    let body = common::within(c.read_until(pr::frame::Opcode::Ack))
        .await
        .expect("answered");
    assert!(common::response(&body).error.is_none());
    assert_eq!(h.shared.store.lock().await.len(), 1);
    h.stop().await;
}

#[tokio::test]
async fn an_unbound_connection_cannot_assert_anything() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let mut c = h.client().await;
    c.write(&testkit::publish_frame(&testkit::heartbeat(
        [0x77u8; 32],
        v1::PresenceState::Online,
        now_ms() + 60_000,
    )))
    .await;
    let body = common::within(c.read_until(pr::frame::Opcode::Ack))
        .await
        .expect("answered");
    assert!(common::response(&body).error.is_some());
    assert_eq!(h.shared.store.lock().await.len(), 0);
    h.stop().await;
}

#[tokio::test]
async fn the_drain_completes() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    assert!(h.stop().await.drained);
}
