//! Authentication, and the hole it closes — tested by **refusal**, not by
//! acceptance.
//!
//! Ported from `services/rendezvous/tests/tls_binding.rs`, which
//! `rendezvous-connectivity` wrote and which is the model. Its opening argument
//! is why these are here at all:
//!
//! > An authentication test that only shows the good case passing shows nothing:
//! > a service with authentication removed passes it too.
//!
//! Every test in this file asserts that something is **refused**. The harness is
//! a real TLS listener built from `twinvpn_service_common::tls`, speaking a
//! minimal claim protocol over it, so the assertions are about wire behaviour and
//! not about reading a config struct back.
//!
//! `contracts/docs/trust-boundaries.md` §4 fixes the classification: a binding
//! mismatch is "**a security event, never a parse error**".

mod harness;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use harness::Answer;
use twinvpn_service_common::tls::testkit::TestKey;
use twinvpn_service_common::tls::{self, ServerTlsBuilder};

// ---------------------------------------------------------------------------
// The handshake itself
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_client_with_no_key_never_reaches_the_parser() {
    // ADR-0001 §7.2: client auth is RFC 7250 raw public key, and
    // `client_auth_mandatory` is true and not configurable. A peer that presents
    // nothing does not get to send a frame at all.
    let h = harness::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let outcome = h.anonymous_handshake().await;
    assert!(
        outcome.is_err(),
        "a connection with no client key completed a handshake"
    );
    assert_eq!(h.accepted_claims(), 0);
    h.stop().await;
}

#[tokio::test]
async fn plaintext_framing_at_the_tls_port_is_refused() {
    // The exact bytes that worked before TLS. They must now go nowhere.
    let h = harness::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let mut raw = tokio::net::TcpStream::connect(h.addr)
        .await
        .expect("connect");
    {
        use tokio::io::AsyncWriteExt as _;
        let _ = raw.write_all(&harness::claim_frame([1u8; 32])).await;
    }
    // What comes back is a TLS alert, not a claim answer. The distinction is the
    // whole assertion: the framing layer was never reached.
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
        !buf[..n].starts_with(&harness::MAGIC),
        "plaintext framing was served an answer back"
    );
    assert_eq!(
        h.accepted_claims(),
        0,
        "a plaintext claim was accepted by the binding table"
    );
    h.stop().await;
}

#[tokio::test]
async fn a_client_pinning_the_wrong_server_key_refuses_the_server() {
    // The other direction of mutual authentication: ADR-0001's "pinned
    // control-plane public key set". A client that pins a different key must not
    // complete, or the service could be impersonated to a device.
    let h = harness::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let wrong = TestKey::generate();
    let client = TestKey::generate();
    let tcp = tokio::net::TcpStream::connect(h.addr)
        .await
        .expect("connect");
    let connector = tokio_rustls::TlsConnector::from(client.client_config(&wrong.spki));
    let outcome = harness::within(connector.connect(harness::server_name(), tcp)).await;
    assert!(
        !matches!(outcome, Some(Ok(_))),
        "a mispinned server key was accepted"
    );
    h.stop().await;
}

#[tokio::test]
async fn a_tls_1_2_client_is_refused() {
    // A 1.2 downgrade is a downgrade of the authentication itself: the RFC 9266
    // `tls-exporter` binding ADR-0002 N-2 needs is a 1.3 property, and 1.2 has no
    // raw-public-key client auth of the shape ADR-0001 §7.2 specifies.
    // **Tested by attempting one, not by reading the config back.**
    let h = harness::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let tcp = tokio::net::TcpStream::connect(h.addr)
        .await
        .expect("connect");
    let connector =
        tokio_rustls::TlsConnector::from(TestKey::tls12_only_client_config(&h.server_spki));
    let outcome = harness::within(connector.connect(harness::server_name(), tcp)).await;
    assert!(
        !matches!(outcome, Some(Ok(_))),
        "a TLS 1.2 client completed a handshake"
    );
    assert_eq!(h.accepted_claims(), 0);
    h.stop().await;
}

#[tokio::test]
async fn a_stalled_handshake_is_dropped_at_its_deadline() {
    // The handshake takes the same stall deadline a partial frame does: a peer
    // that opens a socket and then says nothing is the slowloris case one layer
    // down, and rustls will wait as long as the peer makes it.
    let h = harness::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let stalled = tokio::net::TcpStream::connect(h.addr)
        .await
        .expect("connect");
    // Say nothing at all, then wait past the harness deadline.
    tokio::time::sleep(harness::HANDSHAKE_DEADLINE + Duration::from_millis(250)).await;
    assert!(
        h.handshakes_refused() >= 1,
        "the stalled peer was not dropped"
    );
    drop(stalled);
    h.stop().await;
}

// ---------------------------------------------------------------------------
// Configuration properties, asserted structurally
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_constructed_config_permits_no_early_data() {
    // ADR-0001 R8: 0-RTT is PROHIBITED. Asserted rather than assumed, because
    // "we left the default alone" is not a property — and asserted on every
    // constructor, because a future edit takes whichever one is convenient.
    let key = TestKey::generate();
    for cfg in [
        ServerTlsBuilder::from_pkcs8_der(key.pkcs8().to_vec())
            .build()
            .expect("in-memory key")
            .config(),
        ServerTlsBuilder::from_pkcs8_der(key.pkcs8().to_vec())
            .with_alpn(["h3"])
            .build()
            .expect("with alpn")
            .config(),
    ] {
        assert_eq!(cfg.max_early_data_size, 0);
        assert!(tls::assert_no_early_data(&cfg).is_ok());
    }
}

#[tokio::test]
async fn the_early_data_assertion_can_actually_fail() {
    // The negative control. Without this, the test above passes against an
    // `assert_no_early_data` that returns `Ok(())` unconditionally.
    let key = TestKey::generate();
    let built = ServerTlsBuilder::from_pkcs8_der(key.pkcs8().to_vec())
        .build()
        .expect("a usable key");
    let mut cfg = (*built.config()).clone();
    cfg.max_early_data_size = 1;
    assert!(matches!(
        tls::assert_no_early_data(&cfg),
        Err(tls::TlsError::EarlyDataEnabled)
    ));
}

#[tokio::test]
async fn a_missing_key_file_is_a_startup_failure_not_a_plaintext_listener() {
    let err = tls::server_config(std::path::Path::new("/nonexistent/tls.key")).unwrap_err();
    assert!(
        matches!(err, tls::TlsError::KeyUnreadable { .. }),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_file_that_is_not_a_key_is_a_startup_failure() {
    let err = tls::server_config(std::path::Path::new("Cargo.toml")).unwrap_err();
    assert!(matches!(err, tls::TlsError::KeyUnusable { .. }), "{err:?}");
}

#[tokio::test]
async fn the_pem_path_and_the_in_memory_path_agree() {
    // The deployment shape is a PEM file at /run/secrets; the in-memory shape is
    // for a secret store. They must not be two different servers.
    let key = TestKey::generate();
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    let path = key.write_pem(dir, "svc-common-pem-agreement");
    let from_file = tls::server_public_key(&path).expect("a usable key");
    let from_memory = ServerTlsBuilder::from_pkcs8_der(key.pkcs8().to_vec())
        .build()
        .expect("a usable key")
        .public_key()
        .to_vec();
    assert_eq!(from_file, from_memory);
    assert_eq!(from_file, key.spki);
}

#[tokio::test]
async fn a_channel_identity_never_renders_its_bytes() {
    let id = tls::ChannelIdentity::new(&[0xab; 64]);
    let rendered = format!("{id:?}");
    assert!(!rendered.contains("ab"), "{rendered}");
    assert!(rendered.contains("64 B"));
    assert!(rendered.contains("<not rendered>"));
}

// ---------------------------------------------------------------------------
// The binding, over a real connection
// ---------------------------------------------------------------------------

/// The attack, in its plainest form.
#[tokio::test]
async fn a_second_key_cannot_attach_as_an_attached_device() {
    let h = harness::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let victim_key = TestKey::generate();
    let attacker_key = TestKey::generate();
    let device = [0x42u8; 32];

    // The victim holds its connection open, as a real device does.
    let mut victim = h
        .connect_as(&victim_key)
        .await
        .expect("the victim connects");
    assert_eq!(
        victim.claim(device).await,
        Answer::Accepted,
        "the victim attached cleanly"
    );

    let mut attacker = h
        .connect_as(&attacker_key)
        .await
        .expect("the attacker completes a handshake with its OWN key");
    assert_eq!(
        attacker.claim(device).await,
        Answer::refused("CONTROL.CHANNEL_BINDING_MISMATCH"),
        "the impersonation was not refused"
    );

    // And the consequence: the impostor's connection is closed and it gets
    // nothing further on it. This is the assertion that says the hole is
    // actually closed, as opposed to merely reported.
    assert_eq!(
        attacker.claim(device).await,
        Answer::Silence,
        "a refused impostor was still being served"
    );
    assert_eq!(h.accepted_claims(), 1, "exactly one claim was accepted");
    h.stop().await;
}

#[tokio::test]
async fn one_channel_cannot_speak_for_two_devices() {
    // Two LIVE connections holding the same key: the converse half of the
    // invariant, and the half `BindingCardinality` names. One authenticated
    // channel does not get to multiplex identities.
    let h = harness::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let key = TestKey::generate();

    let mut first = h.connect_as(&key).await.expect("connects");
    assert_eq!(first.claim([1u8; 32]).await, Answer::Accepted);

    let mut second = h.connect_as(&key).await.expect("connects");
    assert_eq!(
        second.claim([2u8; 32]).await,
        Answer::refused("CONTROL.CHANNEL_BINDING_MISMATCH")
    );

    // ...and on the very same connection, too.
    assert_eq!(
        first.claim([3u8; 32]).await,
        Answer::refused("CONTROL.CHANNEL_BINDING_MISMATCH")
    );
    h.stop().await;
}

#[tokio::test]
async fn a_binding_survives_the_victims_disconnect_so_a_reconnect_race_is_lost() {
    let h = harness::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let victim_key = TestKey::generate();
    let attacker_key = TestKey::generate();
    let device = [0x44u8; 32];

    // The victim claims, then its connection goes away entirely.
    assert_eq!(h.claim_once(&victim_key, device).await, Answer::Accepted);

    // The attacker races the reconnect and must lose.
    assert_eq!(
        h.claim_once(&attacker_key, device).await,
        Answer::refused("CONTROL.CHANNEL_BINDING_MISMATCH"),
        "the binding must outlive the connection, or a reconnect is a race"
    );

    // And the real device gets its own binding back.
    assert_eq!(
        h.claim_once(&victim_key, device).await,
        Answer::Accepted,
        "the device could not reattach"
    );
    h.stop().await;
}

#[tokio::test]
async fn the_refusal_names_no_device_and_is_a_security_event() {
    let h = harness::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let device = [0xa7u8; 32];

    assert_eq!(
        h.claim_once(&TestKey::generate(), device).await,
        Answer::Accepted
    );
    let Answer::Refused(body) = h.claim_once(&TestKey::generate(), device).await else {
        panic!("the impersonation was not refused");
    };

    // Not a parse error: FATAL, CRITICAL (`trust-boundaries.md` §4).
    let code = twinvpn_types::ReasonCode::lookup("CONTROL.CHANNEL_BINDING_MISMATCH")
        .expect("a registered code");
    assert_eq!(code.severity(), twinvpn_types::ErrorSeverity::Critical);
    assert_eq!(code.class(), twinvpn_types::ErrorClass::Fatal);

    // And it names nothing: a refusal that echoed the contested device_id would
    // be an oracle for which devices are attached. The answer is the code and
    // only the code — which is structural, not incidental: the frozen registry
    // declares NO evidence fields for CONTROL.CHANNEL_BINDING_MISMATCH, and
    // `twinvpn-types`' builder drops an undeclared key.
    assert_eq!(body, "CONTROL.CHANNEL_BINDING_MISMATCH");
    assert!(
        !body.as_bytes().windows(32).any(|w| w == device),
        "the refusal echoed the contested device_id"
    );
    let envelope = twinvpn_service_common::binding::Refusal::SubjectHeldByAnotherChannel
        .to_error(twinvpn_service_common::Component::RendezvousClient)
        .envelope();
    assert!(
        envelope.evidence.is_empty(),
        "the refusal carried evidence: {:?}",
        envelope.evidence
    );
    h.stop().await;
}

#[tokio::test]
async fn the_binding_holds_identically_over_ipv4() {
    // ADR-0010 R1: IPv4 and IPv6 are co-equal. A refusal that only held on one
    // family would be exactly the asymmetry the corpus forbids.
    let h = harness::start(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    let device = [0x45u8; 32];
    assert_eq!(
        h.claim_once(&TestKey::generate(), device).await,
        Answer::Accepted
    );
    assert_eq!(
        h.claim_once(&TestKey::generate(), device).await,
        Answer::refused("CONTROL.CHANNEL_BINDING_MISMATCH")
    );
    h.stop().await;
}

#[tokio::test]
async fn an_authenticated_peer_is_still_not_a_trusted_one() {
    // The property that keeps the input-validation work load-bearing:
    // authentication says who you are, not that your bytes are well formed. A
    // peer that completes the handshake and then sends a malformed frame is
    // still refused, and still without an answer.
    let h = harness::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let key = TestKey::generate();
    let mut s = h.connect_as(&key).await.expect("the handshake succeeds");
    // 36 bytes, the right LENGTH, the wrong magic.
    let mut malformed = b"XXXX".to_vec();
    malformed.extend_from_slice(&[0x11u8; 32]);
    assert_eq!(
        s.send_raw(&malformed).await,
        Answer::Silence,
        "a malformed frame was answered"
    );
    assert_eq!(h.accepted_claims(), 0);
    h.stop().await;
}
