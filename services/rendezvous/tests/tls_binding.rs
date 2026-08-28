//! Authentication, and the hole it closes — tested by **refusal**, not by
//! acceptance.
//!
//! An authentication test that only shows the good case passing shows nothing:
//! a service with authentication removed passes it too. Every test here asserts
//! that something is *refused*, and the two that matter most are the two
//! spellings of the attack the integration lead named:
//!
//! > an attacker attaches as another device's `device_id` and receives its
//! > `CALL`s.
//!
//! `contracts/docs/trust-boundaries.md` §4 fixes the classification: a binding
//! mismatch is "**a security event, never a parse error**".

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use twinvpn_rendezvous as rz;
use twinvpn_rendezvous::testkit;

// ---------------------------------------------------------------------------
// The handshake itself
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_client_with_no_key_never_reaches_the_parser() {
    // ADR-0001 §7.2: client auth is RFC 7250 raw public key, and
    // `client_auth_mandatory` is true and not configurable. A peer that presents
    // nothing does not get to send a frame at all.
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
    // The exact bytes that worked before TLS. They must now go nowhere.
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let mut raw = tokio::net::TcpStream::connect(h.addr)
        .await
        .expect("connect");
    {
        use tokio::io::AsyncWriteExt as _;
        let _ = raw
            .write_all(&testkit::call_frame([1u8; 32], &testkit::payload(16)))
            .await;
    }
    // What comes back is a TLS alert, not a rendezvous frame. The distinction is
    // the whole assertion: the framing layer was never reached.
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
        !buf[..n].starts_with(&rz::frame::MAGIC),
        "plaintext framing was served a rendezvous frame back"
    );
    // A TLS record begins with a content type; an alert is 0x15. Anything else
    // that is not a rendezvous frame is equally fine — what matters is that no
    // CALL was accepted.
    assert_eq!(
        h.shared.router.lock().await.mailboxes.total_bytes(),
        0,
        "a plaintext CALL reached the mailbox"
    );
    h.stop().await;
}

#[tokio::test]
async fn a_client_pinning_the_wrong_server_key_refuses_the_server() {
    // The other direction of mutual authentication: ADR-0001's "pinned
    // control-plane public key set". A client that pins a different key must not
    // complete, or this service could be impersonated to a device.
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let wrong = common::TestKey::generate();
    let client_key = common::TestKey::generate();
    let tcp = tokio::net::TcpStream::connect(h.addr)
        .await
        .expect("connect");
    let connector = tokio_rustls::TlsConnector::from(client_key.client_config(&wrong.spki));
    let outcome = common::within(connector.connect(common::server_name(), tcp)).await;
    assert!(outcome.is_err(), "a mispinned server key was accepted");
    h.stop().await;
}

#[tokio::test]
async fn the_configuration_permits_no_early_data() {
    // ADR-0001 R8: 0-RTT is PROHIBITED. Asserted rather than assumed, because
    // "we left the default alone" is not a property.
    let key = common::TestKey::generate();
    let built = twinvpn_service_common::tls::ServerTlsBuilder::from_pkcs8_der(key.pkcs8().to_vec())
        .build()
        .expect("a usable key");
    assert_eq!(built.config().max_early_data_size, 0);
    assert!(twinvpn_service_common::tls::assert_no_early_data(&built.config()).is_ok());
}

#[tokio::test]
async fn a_tls_1_2_client_is_refused() {
    // A 1.2 downgrade is a downgrade of the authentication itself: the RFC 9266
    // `tls-exporter` binding ADR-0002 N-2 needs is a 1.3 property, and 1.2 has
    // no raw-public-key client auth of the shape ADR-0001 §7.2 specifies.
    // Tested by attempting one, not by reading the config back.
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let tcp = tokio::net::TcpStream::connect(h.addr)
        .await
        .expect("connect");
    let connector =
        tokio_rustls::TlsConnector::from(common::TestKey::tls12_only_client_config(&h.server_spki));
    let outcome = common::within(connector.connect(common::server_name(), tcp)).await;
    assert!(outcome.is_err(), "a TLS 1.2 client completed a handshake");
    h.stop().await;
}

// ---------------------------------------------------------------------------
// The binding: a device_id is answerable to the channel
// ---------------------------------------------------------------------------

/// The attack, in its plainest form.
#[tokio::test]
async fn a_second_key_cannot_attach_as_an_attached_device() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let victim_key = common::TestKey::generate();
    let attacker_key = common::TestKey::generate();
    let device = [0x42u8; 32];

    let mut victim = h.client_as(&victim_key).await;
    victim
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &device))
        .await;
    let ack = common::within(victim.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("the victim attaches");
    assert!(
        common::reason_code(&ack).is_none(),
        "the victim attached cleanly"
    );

    let mut attacker = h.client_as(&attacker_key).await;
    attacker
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &device))
        .await;
    let refusal = common::within(attacker.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("the attacker is answered");
    assert_eq!(
        common::reason_code(&refusal).as_deref(),
        Some("CONTROL.CHANNEL_BINDING_MISMATCH"),
        "the impersonation was not refused"
    );
    h.stop().await;
}

/// And the consequence: the redirected `CALL` reaches the victim, not the
/// attacker. This is the assertion that says the hole is actually closed, as
/// opposed to merely reported.
#[tokio::test]
async fn a_call_still_reaches_the_real_device_when_an_impostor_is_present() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let victim_key = common::TestKey::generate();
    let attacker_key = common::TestKey::generate();
    let device = [0x43u8; 32];
    let payload = testkit::payload(24);

    let mut victim = h.client_as(&victim_key).await;
    victim
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &device))
        .await;
    common::within(victim.read_until(rz::frame::Opcode::Ack)).await;

    let mut attacker = h.client_as(&attacker_key).await;
    attacker
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &device))
        .await;
    common::within(attacker.read_until(rz::frame::Opcode::Ack)).await;

    let mut caller = h.client().await;
    caller.write(&testkit::call_frame(device, &payload)).await;

    let delivered = common::within(victim.read_until(rz::frame::Opcode::Deliver))
        .await
        .expect("the CALL reached the real device");
    assert_eq!(delivered, payload);

    // The impostor's connection was closed on refusal and carries no delivery.
    let stolen = tokio::time::timeout(
        Duration::from_millis(300),
        attacker.read_until(rz::frame::Opcode::Deliver),
    )
    .await;
    assert!(
        matches!(stolen, Ok(None) | Err(_)),
        "the impostor received a CALL: {stolen:?}"
    );
    h.stop().await;
}

#[tokio::test]
async fn one_channel_cannot_speak_for_two_devices() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let key = common::TestKey::generate();
    let mut c = h.client_as(&key).await;

    c.write(&rz::frame::encode(rz::frame::Opcode::Attach, &[1u8; 32]))
        .await;
    common::within(c.read_until(rz::frame::Opcode::Ack)).await;

    let mut second = h.client_as(&key).await;
    second
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &[2u8; 32]))
        .await;
    let refusal = common::within(second.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("answered");
    assert_eq!(
        common::reason_code(&refusal).as_deref(),
        Some("CONTROL.CHANNEL_BINDING_MISMATCH")
    );
    h.stop().await;
}

#[tokio::test]
async fn a_binding_survives_the_victims_disconnect_so_a_reconnect_race_is_lost() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let victim_key = common::TestKey::generate();
    let attacker_key = common::TestKey::generate();
    let device = [0x44u8; 32];

    let mut victim = h.client_as(&victim_key).await;
    victim
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &device))
        .await;
    common::within(victim.read_until(rz::frame::Opcode::Ack)).await;
    drop(victim);
    // Let the server observe the close.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut attacker = h.client_as(&attacker_key).await;
    attacker
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &device))
        .await;
    let refusal = common::within(attacker.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("answered");
    assert_eq!(
        common::reason_code(&refusal).as_deref(),
        Some("CONTROL.CHANNEL_BINDING_MISMATCH"),
        "the binding must outlive the connection, or a reconnect is a race"
    );

    // And the real device gets its own binding back.
    let mut again = h.client_as(&victim_key).await;
    again
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &device))
        .await;
    let ack = common::within(again.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("answered");
    assert!(common::reason_code(&ack).is_none(), "the device reattached");
    h.stop().await;
}

#[tokio::test]
async fn the_refusal_names_no_device_and_is_a_security_event() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let device = [0xa7u8; 32];
    let mut victim = h.client().await;
    victim
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &device))
        .await;
    common::within(victim.read_until(rz::frame::Opcode::Ack)).await;

    let mut attacker = h.client().await;
    attacker
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &device))
        .await;
    let body = common::within(attacker.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("answered");

    // Not a parse error: FATAL, CRITICAL (`trust-boundaries.md` §4).
    let code = twinvpn_types::ReasonCode::lookup("CONTROL.CHANNEL_BINDING_MISMATCH")
        .expect("a registered code");
    assert_eq!(code.severity(), twinvpn_types::ErrorSeverity::Critical);

    // And it names nothing: a refusal that echoed the contested device_id would
    // be an oracle for which devices are attached.
    assert!(
        !body.windows(32).any(|w| w == device),
        "the refusal echoed the contested device_id"
    );
    h.stop().await;
}

#[tokio::test]
async fn the_binding_holds_identically_over_ipv4() {
    let h = common::start(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    let device = [0x45u8; 32];
    let mut victim = h.client().await;
    victim
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &device))
        .await;
    common::within(victim.read_until(rz::frame::Opcode::Ack)).await;

    let mut attacker = h.client().await;
    attacker
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &device))
        .await;
    let refusal = common::within(attacker.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("answered");
    assert_eq!(
        common::reason_code(&refusal).as_deref(),
        Some("CONTROL.CHANNEL_BINDING_MISMATCH")
    );
    h.stop().await;
}

#[tokio::test]
async fn an_authenticated_peer_is_still_not_a_trusted_one() {
    // The property that keeps the B3 work load-bearing: authentication says who
    // you are, not that your bytes are well formed. A peer that completes the
    // handshake and then sends a 1201-byte payload is still refused, and still
    // without an answer.
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let mut c = h.client().await;
    let mut body = [1u8; 32].to_vec();
    body.extend_from_slice(&testkit::payload(1201));
    c.write(&testkit::declared_length_frame(
        rz::frame::Opcode::Call,
        u16::try_from(body.len()).unwrap(),
        &body,
    ))
    .await;
    let answered = common::within(async {
        let mut seen = Vec::new();
        while let Some((op, b)) = c.read_frame().await {
            if op != rz::frame::Opcode::Reflexive.as_wire() {
                seen.push((op, b));
            }
        }
        seen
    })
    .await;
    assert!(
        answered.is_empty(),
        "an oversized payload was answered: {answered:?}"
    );
    assert_eq!(h.shared.router.lock().await.mailboxes.total_bytes(), 0);
    h.stop().await;
}

/// **The `release()` regression, at the level that can see it.**
///
/// The shared crate's absorption found a defect both this service's and
/// `presence`'s copies carried: `release` took only the channel and decremented
/// **every** entry that channel held, and both services called it
/// unconditionally at teardown. So a *refused* connection sharing a key with a
/// live one released **that connection's** hold — after which one channel could
/// speak for a second subject, and a held binding became evictable for capacity.
///
/// Neither copy's unit tests caught it because both released from a single
/// synthetic channel. It only appears against a **long-lived** connection, which
/// is what this harness has. That is the whole reason this test lives here and
/// not in a unit module.
#[tokio::test]
async fn a_refused_sibling_connection_cannot_release_a_live_connections_hold() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let key = common::TestKey::generate();
    let attacker_key = common::TestKey::generate();
    let held = [0x61u8; 32];
    let other = [0x62u8; 32];

    // 1. A long-lived connection on key K holds `held`.
    let mut live = h.client_as(&key).await;
    live.write(&rz::frame::encode(rz::frame::Opcode::Attach, &held))
        .await;
    let ack = common::within(live.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("the live connection attaches");
    assert!(common::reason_code(&ack).is_none());

    // 2. A sibling on the SAME key claims a second subject and is refused.
    {
        let mut sibling = h.client_as(&key).await;
        sibling
            .write(&rz::frame::encode(rz::frame::Opcode::Attach, &other))
            .await;
        let refusal = common::within(sibling.read_until(rz::frame::Opcode::Ack))
            .await
            .expect("the sibling is answered");
        assert_eq!(
            common::reason_code(&refusal).as_deref(),
            Some("CONTROL.CHANNEL_BINDING_MISMATCH"),
            "one channel must not speak for a second subject"
        );
        // 3. ...and tears down. Under the defect, this released the LIVE
        //    connection's hold on `held`.
    }
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 4. A different key must still be unable to take `held`.
    let mut attacker = h.client_as(&attacker_key).await;
    attacker
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &held))
        .await;
    let refusal = common::within(attacker.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("the attacker is answered");
    assert_eq!(
        common::reason_code(&refusal).as_deref(),
        Some("CONTROL.CHANNEL_BINDING_MISMATCH"),
        "a refused sibling's teardown released a live connection's hold"
    );

    // 5. And the original channel still may not acquire a second subject.
    let mut again = h.client_as(&key).await;
    again
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &other))
        .await;
    let refusal = common::within(again.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("answered");
    assert_eq!(
        common::reason_code(&refusal).as_deref(),
        Some("CONTROL.CHANNEL_BINDING_MISMATCH"),
        "the invariant survived a refused sibling's teardown"
    );
    h.stop().await;
}

/// A full binding table answers `CONTROL.ADMISSION_DEFERRED`, not a mismatch.
///
/// They are different facts: the subject is not contested, the server is.
/// Answering "held by another channel" would tell a caller its `device_id` was
/// taken when it was not — an oracle, and a wrong one.
#[tokio::test]
async fn a_full_binding_table_defers_rather_than_claiming_the_subject_is_taken() {
    let h = common::start_with(IpAddr::V6(Ipv6Addr::LOCALHOST), |mut c| {
        c.binding.max_bindings = 1;
        c
    })
    .await;

    let mut first = h.client().await;
    first
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &[0x71u8; 32]))
        .await;
    common::within(first.read_until(rz::frame::Opcode::Ack)).await;

    // A different key, a subject nobody holds — but no room to record it.
    let mut second = h.client().await;
    second
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &[0x72u8; 32]))
        .await;
    let refusal = common::within(second.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("answered, never reset — S-6");
    assert_eq!(
        common::reason_code(&refusal).as_deref(),
        Some("CONTROL.ADMISSION_DEFERRED"),
        "capacity must not be reported as a contested subject"
    );
    h.stop().await;
}
