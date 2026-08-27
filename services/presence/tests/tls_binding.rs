//! Authentication, and what it makes enforceable — tested by **refusal**.
//!
//! S-11 and `presence.proto`: "a device may assert presence **only for
//! itself**." Before TLS that rule could only be checked against another
//! unauthenticated claim, which is to say it could not be enforced. These tests
//! assert the refusals that make it real.

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use twinvpn_presence as pr;
use twinvpn_presence::testkit;
use twinvpn_schema::v1;

fn now_ms() -> u64 {
    pr::server::now_ms()
}

#[tokio::test]
async fn a_client_with_no_key_never_reaches_the_parser() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let outcome = common::within(h.anonymous_handshake()).await;
    assert!(
        outcome.is_err(),
        "a connection with no client key completed a handshake"
    );
    h.stop().await;
}

#[tokio::test]
async fn plaintext_framing_at_the_tls_port_is_refused() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let device = [1u8; 32];
    let mut raw = tokio::net::TcpStream::connect(h.addr)
        .await
        .expect("connect");
    {
        use tokio::io::AsyncWriteExt as _;
        let _ = raw
            .write_all(&testkit::publish_frame(&testkit::heartbeat(
                device,
                v1::PresenceState::Online,
                now_ms() + 60_000,
            )))
            .await;
    }
    let mut buf = [0u8; 256];
    let n = {
        use tokio::io::AsyncReadExt as _;
        tokio::time::timeout(Duration::from_millis(500), raw.read(&mut buf))
            .await
            .map(Result::ok)
            .ok()
            .flatten()
            .unwrap_or(0)
    };
    assert!(
        !buf[..n].starts_with(&pr::frame::MAGIC),
        "plaintext framing was served a presence frame back"
    );
    assert_eq!(
        h.shared.store.lock().await.len(),
        0,
        "a plaintext heartbeat was stored"
    );
    h.stop().await;
}

#[tokio::test]
async fn a_client_pinning_the_wrong_server_key_refuses_the_server() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let wrong = common::TestKey::generate();
    let client_key = common::TestKey::generate();
    let tcp = tokio::net::TcpStream::connect(h.addr)
        .await
        .expect("connect");
    let connector = tokio_rustls::TlsConnector::from(client_key.client_config(&wrong.spki));
    let outcome = common::within(connector.connect(common::keys::server_name(), tcp)).await;
    assert!(outcome.is_err(), "a mispinned server key was accepted");
    h.stop().await;
}

#[tokio::test]
async fn a_tls_1_2_client_is_refused() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let tcp = tokio::net::TcpStream::connect(h.addr)
        .await
        .expect("connect");
    let connector =
        tokio_rustls::TlsConnector::from(common::TestKey::tls12_only_client_config(&h.server_spki));
    let outcome = common::within(connector.connect(common::keys::server_name(), tcp)).await;
    assert!(outcome.is_err(), "a TLS 1.2 client completed a handshake");
    h.stop().await;
}

#[tokio::test]
async fn the_configuration_permits_no_early_data() {
    // ADR-0001 R8.
    let key = common::TestKey::generate();
    let path = key.write_pem("pr-early-data-probe");
    let cfg = pr::tls::server_config(&path).expect("a usable key");
    assert_eq!(cfg.max_early_data_size, 0);
    assert!(pr::tls::assert_no_early_data(&cfg).is_ok());
}

/// The attack: publish presence as somebody else by claiming their `device_id`.
#[tokio::test]
async fn a_second_key_cannot_bind_as_a_bound_device() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let victim_key = common::TestKey::generate();
    let attacker_key = common::TestKey::generate();
    let device = [0x51u8; 32];

    let mut victim = h.client_as(&victim_key).await;
    victim.bind(device).await;

    let mut attacker = h.client_as(&attacker_key).await;
    attacker
        .write(&pr::frame::encode(pr::frame::Opcode::Bind, &device))
        .await;
    let body = common::within(attacker.read_until(pr::frame::Opcode::Ack))
        .await
        .expect("the attacker is answered");
    let err = common::response(&body).error.expect("a refusal");
    assert_eq!(err.reason_code, "CONTROL.CHANNEL_BINDING_MISMATCH");
    h.stop().await;
}

/// And the consequence: the impostor's presence assertion never lands.
#[tokio::test]
async fn an_impostor_cannot_change_a_devices_presence() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let victim_key = common::TestKey::generate();
    let attacker_key = common::TestKey::generate();
    let device = [0x52u8; 32];
    let base = now_ms();

    let mut victim = h.client_as(&victim_key).await;
    victim.bind(device).await;
    victim
        .write(&testkit::publish_frame(&testkit::heartbeat(
            device,
            v1::PresenceState::Online,
            base + 60_000,
        )))
        .await;
    common::within(victim.read_until(pr::frame::Opcode::Ack)).await;

    // The impostor binds (refused), then tries to publish anyway.
    let mut attacker = h.client_as(&attacker_key).await;
    attacker
        .write(&pr::frame::encode(pr::frame::Opcode::Bind, &device))
        .await;
    common::within(attacker.read_until(pr::frame::Opcode::Ack)).await;
    attacker
        .write(&testkit::publish_frame(&testkit::heartbeat(
            device,
            v1::PresenceState::Offline,
            base + 90_000,
        )))
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;

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
        "an impostor changed a device's presence"
    );
    h.stop().await;
}

#[tokio::test]
async fn one_channel_cannot_speak_for_two_devices() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let key = common::TestKey::generate();

    let mut first = h.client_as(&key).await;
    first.bind([1u8; 32]).await;

    let mut second = h.client_as(&key).await;
    second
        .write(&pr::frame::encode(pr::frame::Opcode::Bind, &[2u8; 32]))
        .await;
    let body = common::within(second.read_until(pr::frame::Opcode::Ack))
        .await
        .expect("answered");
    let err = common::response(&body).error.expect("a refusal");
    assert_eq!(err.reason_code, "CONTROL.CHANNEL_BINDING_MISMATCH");
    h.stop().await;
}

#[tokio::test]
async fn a_binding_survives_the_devices_disconnect() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let victim_key = common::TestKey::generate();
    let attacker_key = common::TestKey::generate();
    let device = [0x53u8; 32];

    let mut victim = h.client_as(&victim_key).await;
    victim.bind(device).await;
    drop(victim);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut attacker = h.client_as(&attacker_key).await;
    attacker
        .write(&pr::frame::encode(pr::frame::Opcode::Bind, &device))
        .await;
    let body = common::within(attacker.read_until(pr::frame::Opcode::Ack))
        .await
        .expect("answered");
    assert!(
        common::response(&body).error.is_some(),
        "the binding must outlive the connection"
    );

    // The real device reattaches on its own key.
    let mut again = h.client_as(&victim_key).await;
    again.bind(device).await;
    h.stop().await;
}

#[tokio::test]
async fn the_refusal_names_no_device() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let device = [0xb3u8; 32];
    let mut victim = h.client().await;
    victim.bind(device).await;

    let mut attacker = h.client().await;
    attacker
        .write(&pr::frame::encode(pr::frame::Opcode::Bind, &device))
        .await;
    let body = common::within(attacker.read_until(pr::frame::Opcode::Ack))
        .await
        .expect("answered");
    assert!(
        !body.windows(32).any(|w| w == device),
        "the refusal echoed the contested device_id"
    );
    h.stop().await;
}

#[tokio::test]
async fn the_binding_holds_identically_over_ipv4() {
    let h = common::start(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    let device = [0x54u8; 32];
    let mut victim = h.client().await;
    victim.bind(device).await;

    let mut attacker = h.client().await;
    attacker
        .write(&pr::frame::encode(pr::frame::Opcode::Bind, &device))
        .await;
    let body = common::within(attacker.read_until(pr::frame::Opcode::Ack))
        .await
        .expect("answered");
    let err = common::response(&body).error.expect("a refusal");
    assert_eq!(err.reason_code, "CONTROL.CHANNEL_BINDING_MISMATCH");
    h.stop().await;
}

#[tokio::test]
async fn s11_still_refuses_a_cross_device_assertion_on_an_authenticated_channel() {
    // Authentication does not replace the S-11 check, it makes it meaningful:
    // a channel legitimately bound to A still may not assert for B.
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let mut c = h.client().await;
    c.bind([0x55u8; 32]).await;
    c.write(&testkit::publish_frame(&testkit::heartbeat(
        [0x56u8; 32],
        v1::PresenceState::Online,
        now_ms() + 60_000,
    )))
    .await;
    let body = common::within(c.read_until(pr::frame::Opcode::Ack))
        .await
        .expect("answered");
    let err = common::response(&body).error.expect("a refusal");
    assert_eq!(err.reason_code, "CONTROL.EVENT_WRONG_PUBLISHER");
    assert_eq!(h.shared.store.lock().await.len(), 0);
    h.stop().await;
}
