//! The relay plane, end to end: leg, bind, forward — over real sockets, with
//! real cryptography on both sides.
//!
//! **Authority:** ADR-0005 §11.1 (forwarding and rendezvous), §11.3 (offline
//! admission), §11.5 (resource control and amplification), §10 (a restart kills
//! every flow); `docs/testing-strategy.md` P14.
//!
//! Every test here drives the relay the way a device does: a `Noise_IK`
//! handshake carrying a real COSE_Sign1 `RelayCapabilityToken`, then `BIND`,
//! then `DATA` — each frame MACed under a `K_leg` the two ends derived
//! independently. See `common/mod.rs` for what is real and what is not.

mod common;

use common::{
    bucket_now, client_socket, protobuf_shaped_payload, recv, Device, Issuer, TestRelay, TokenSpec,
    NOW_MS,
};
use twinvpn_relay::control::{BoundBody, BoundState, CapsBody};
use twinvpn_relay::frame::{FrameType, HEADER_LEN, MAX_DATA_PAYLOAD_BYTES};

/// Establishes a leg for `device` and asserts it completed.
///
/// Answers a cookie challenge if one comes back: every loopback address is in
/// one `/24`, so any test that opens more than a handful of legs crosses
/// ADR-0005 §11.5's 20 handshakes/s threshold and MUST complete the round trip,
/// exactly as a real device does.
async fn establish(
    device: &mut Device,
    socket: &tokio::net::UdpSocket,
    relay: &TestRelay,
    issuer: &Issuer,
    subject: u8,
    jti: u8,
) {
    let token = issuer.mint(&TokenSpec::valid_for(&device.rlk_public, subject, jti));
    assert!(
        device
            .establish_answering_challenges(socket, relay.addr, &relay.static_public, &token)
            .await,
        "the relay did not complete a leg for subject {subject}"
    );
    assert!(device.k_leg.is_some(), "K_leg was derived");
}

/// A bound pair: two devices on one `pair_tag`, both holding a `flow_id`.
async fn bound_pair(
    relay: &TestRelay,
    issuer: &Issuer,
    tag: [u8; 16],
) -> (Device, tokio::net::UdpSocket, Device, tokio::net::UdpSocket) {
    let (mut a, mut b) = (Device::new(0x0A), Device::new(0x0B));
    let (sa, sb) = (client_socket().await, client_socket().await);
    establish(&mut a, &sa, relay, issuer, 1, 1).await;
    establish(&mut b, &sb, relay, issuer, 2, 2).await;

    let first = a
        .bind(&sa, relay.addr, tag, bucket_now())
        .await
        .expect("BOUND");
    let body = BoundBody::decode(&first[HEADER_LEN..]).expect("body");
    assert_eq!(
        body.state,
        BoundState::Pending,
        "the FIRST bind on a tag creates a pending slot (§11.1(4))"
    );

    let second = b
        .bind(&sb, relay.addr, tag, bucket_now())
        .await
        .expect("BOUND");
    let body = BoundBody::decode(&second[HEADER_LEN..]).expect("body");
    assert_eq!(body.state, BoundState::Bound, "the SECOND bind binds it");

    // The half-flow that was already waiting is told too — both peers receive
    // `BOUND{flow_id}`.
    let announced = recv(&sa).await.expect("the waiting half was announced to");
    assert_eq!(announced[0], FrameType::Bound.to_wire());
    (a, sa, b, sb)
}

// ===========================================================================
// Normal relay traffic
// ===========================================================================

#[tokio::test]
async fn a_real_device_establishes_a_leg_binds_a_pair_and_relays_traffic() {
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let (mut a, sa, b, sb) = bound_pair(&relay, &issuer, [0x11; 16]).await;

    assert_eq!(relay.leg_count(), 2);
    assert_eq!(relay.bound_count(), 1);

    // A payload chosen to be hostile to a forwarder that peeks: bytes that WOULD
    // decode as protobuf with an unknown field (W-4's trap).
    let payload = protobuf_shaped_payload();
    a.send_data(&sa, relay.addr, &payload).await;

    let received = recv(&sb).await.expect("the peer received the frame");
    assert_eq!(received[0], FrameType::Data.to_wire());
    assert_eq!(
        &received[HEADER_LEN..],
        &payload[..],
        "the payload crossed the relay BYTE FOR BYTE: §11.1(5) forbids inspecting, \
         padding or re-encoding, and W-4 is that a decode-then-re-encode drops \
         unknown fields"
    );
    // The egress frame names the PEER's flow, not the sender's — §11.1(5)'s
    // "flow_id and counter_low are rewritten for the outgoing half-flow".
    let egress_flow = u32::from_be_bytes([received[4], received[5], received[6], received[7]]);
    assert_eq!(egress_flow, b.flow_id.expect("bound"));
    assert_ne!(egress_flow, a.flow_id.expect("bound"));

    relay.stop().await;
}

#[tokio::test]
async fn traffic_flows_in_both_directions_and_the_largest_legal_payload_fits() {
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let (mut a, sa, mut b, sb) = bound_pair(&relay, &issuer, [0x12; 16]).await;

    // The derived B4 ceiling, which clears the 1280 overlay floor by 144 bytes.
    let big = vec![0xC3_u8; MAX_DATA_PAYLOAD_BYTES];
    a.send_data(&sa, relay.addr, &big).await;
    assert_eq!(
        &recv(&sb).await.expect("forwarded")[HEADER_LEN..],
        &big[..],
        "a payload at MAX_DATA_PAYLOAD_BYTES must traverse: anything less makes \
         the 1280-byte overlay floor unachievable (ADR-0005 C7)"
    );

    b.send_data(&sb, relay.addr, b"reverse").await;
    assert_eq!(
        &recv(&sa).await.expect("forwarded")[HEADER_LEN..],
        b"reverse",
        "a relay is a bidirectional forwarder, not a one-way pipe"
    );
    relay.stop().await;
}

#[tokio::test]
async fn a_payload_one_byte_over_the_ceiling_is_dropped_in_silence() {
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let (mut a, sa, _b, sb) = bound_pair(&relay, &issuer, [0x13; 16]).await;

    let over = vec![0xC3_u8; MAX_DATA_PAYLOAD_BYTES + 1];
    a.send_data(&sa, relay.addr, &over).await;
    assert!(
        recv(&sb).await.is_none(),
        "an oversized payload reaches no peer"
    );
    assert!(
        recv(&sa).await.is_none(),
        "and earns ZERO BYTES in reply (§11.5): an oversized datagram must cost \
         an attacker a packet and gain nothing"
    );
    relay.stop().await;
}

// ===========================================================================
// Many concurrent sessions
// ===========================================================================

#[tokio::test]
async fn sixty_four_concurrent_sessions_all_carry_their_own_traffic() {
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;

    const PAIRS: usize = 32;
    let mut pairs = Vec::with_capacity(PAIRS);
    for i in 0..PAIRS {
        let tag = [u8::try_from(i).expect("small") + 1; 16];
        let subject = u8::try_from(i).expect("small") * 2;
        let (mut a, sa) = (
            Device::new(0x20 + u8::try_from(i).expect("small")),
            client_socket().await,
        );
        let (mut b, sb) = (
            Device::new(0x60 + u8::try_from(i).expect("small")),
            client_socket().await,
        );
        establish(&mut a, &sa, &relay, &issuer, subject, subject).await;
        establish(&mut b, &sb, &relay, &issuer, subject + 1, subject + 1).await;
        a.bind(&sa, relay.addr, tag, bucket_now())
            .await
            .expect("pending");
        b.bind(&sb, relay.addr, tag, bucket_now())
            .await
            .expect("bound");
        let _ = recv(&sa).await;
        pairs.push((a, sa, b, sb));
    }

    assert_eq!(relay.leg_count(), PAIRS * 2);
    assert_eq!(relay.bound_count(), PAIRS);

    // Every pair carries its own bytes, and — the property that matters — each
    // arrives at ITS OWN peer. A relay that crossed two flows would be a
    // confidentiality failure even though the payload is sealed.
    for (i, (a, sa, _b, sb)) in pairs.iter_mut().enumerate() {
        let marker = format!("pair-{i}-payload").into_bytes();
        a.send_data(sa, relay.addr, &marker).await;
        let got = recv(sb)
            .await
            .unwrap_or_else(|| panic!("pair {i} forwarded"));
        assert_eq!(
            &got[HEADER_LEN..],
            &marker[..],
            "pair {i} got its own bytes"
        );
    }
    relay.stop().await;
}

// ===========================================================================
// Disconnect / reconnect, and relay restart
// ===========================================================================

#[tokio::test]
async fn a_device_that_re_handshakes_replaces_its_own_leg_rather_than_adding_one() {
    // ADR-0005 §11.1(1): "at most one authenticated leg per (Device, Relay)".
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let mut device = Device::new(0x0A);
    let socket = client_socket().await;

    establish(&mut device, &socket, &relay, &issuer, 1, 1).await;
    let first_key = device.k_leg.expect("derived");
    assert_eq!(relay.leg_count(), 1);

    // A reconnect from the same 5-tuple. A fresh `jti`, because the replay cache
    // is doing its job and would otherwise refuse the second presentation.
    establish(&mut device, &socket, &relay, &issuer, 1, 2).await;
    assert_eq!(relay.leg_count(), 1, "one leg, not two");
    assert_ne!(
        device.k_leg.expect("derived"),
        first_key,
        "a reconnect derives a FRESH K_leg: the responder's ephemeral is new, so \
         a captured handshake cannot resurrect the old key"
    );
    relay.stop().await;
}

#[tokio::test]
async fn a_replayed_token_is_refused_on_a_second_leg() {
    // ADR-0005 §11.3's last check: `jti` unseen, against a bounded cache.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let mut device = Device::new(0x0A);
    let socket = client_socket().await;
    let token = issuer.mint(&TokenSpec::valid_for(&device.rlk_public, 1, 1));

    assert!(device
        .establish(&socket, relay.addr, &relay.static_public, &token, None)
        .await
        .is_some());

    // The same token, from a different source. This is the captured-credential
    // case, and it must not admit.
    let mut thief = Device::new(0x0A);
    let thief_socket = client_socket().await;
    assert!(
        thief
            .establish(
                &thief_socket,
                relay.addr,
                &relay.static_public,
                &token,
                None
            )
            .await
            .is_none(),
        "a replayed jti earns ZERO BYTES"
    );
    assert_eq!(relay.leg_count(), 1);
    relay.stop().await;
}

#[tokio::test]
async fn a_relay_restart_kills_every_flow_and_that_is_the_design() {
    // S-29 is "NON-DURABLE BY REQUIREMENT". RQ10: no flow, peer, pair or token
    // record is ever written to disk, so a restart cannot resume one.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let (mut a, sa, _b, sb) = bound_pair(&relay, &issuer, [0x14; 16]).await;
    a.send_data(&sa, relay.addr, b"before").await;
    assert!(recv(&sb).await.is_some());

    relay.stop().await;
    let mut restarted = TestRelay::start(&issuer).await;
    assert_eq!(restarted.leg_count(), 0);
    assert_eq!(restarted.bound_count(), 0);

    // The device's old frames reach the new instance and are dropped with zero
    // bytes: it has no leg there, and the client's recovery is to migrate.
    a.send_data(&sa, restarted.addr, b"after").await;
    assert!(recv(&sb).await.is_none());
    assert!(recv(&sa).await.is_none());
    restarted.stop().await;
}

// ===========================================================================
// Unauthorized clients and malformed input
// ===========================================================================

#[tokio::test]
async fn every_malformed_or_unauthenticated_datagram_earns_exactly_zero_bytes() {
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let socket = client_socket().await;

    let mut corpus: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x01],
        vec![0x01; HEADER_LEN - 1],
        // Every known type, with no leg and a junk MAC.
        vec![0x00; HEADER_LEN + 8],
        vec![0xFF; HEADER_LEN + 64],
    ];
    for kind in [
        0x01_u8, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1F, 0x7F,
    ] {
        let mut d = vec![kind, 0x10, 0, 0, 0, 0, 0, 1];
        d.extend_from_slice(&[0xAB; 8]);
        d.extend_from_slice(b"payload");
        corpus.push(d);
    }
    // A wrong version nibble.
    corpus.push({
        let mut d = vec![0x01, 0x90, 0, 0, 0, 0, 0, 1];
        d.extend_from_slice(&[0; 8]);
        d
    });

    for (i, datagram) in corpus.iter().enumerate() {
        socket.send_to(datagram, relay.addr).await.expect("send");
        assert!(
            recv(&socket).await.is_none(),
            "corpus entry {i} produced bytes; ADR-0005 §11.5 requires ZERO in \
             reply to anything unauthenticated, which is what pins the \
             amplification factor at 1.0"
        );
    }
    assert_eq!(relay.leg_count(), 0, "and none of it created state");
    relay.stop().await;
}

#[tokio::test]
async fn a_relay_only_frame_arriving_from_a_device_reaches_nothing() {
    // W-32's ruling, on the receive side. A device sending `BOUND`, `DRAIN` or
    // `RELAY_STATUS` is confused or probing; acting on either would be a
    // confused-deputy surface.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let mut device = Device::new(0x0A);
    let socket = client_socket().await;
    establish(&mut device, &socket, &relay, &issuer, 1, 1).await;

    for kind in [
        FrameType::Bound,
        FrameType::Pong,
        FrameType::Drain,
        FrameType::RelayStatus,
        FrameType::HandshakeResp,
        FrameType::CookieChallenge,
    ] {
        // Correctly MACed under a real K_leg — so only the DIRECTION rule can
        // refuse it, which is exactly what is under test.
        let datagram = device.encode(kind, 0, b"body");
        socket.send_to(&datagram, relay.addr).await.expect("send");
        assert!(
            recv(&socket).await.is_none(),
            "a correctly MACed {kind:?} from a device was answered"
        );
    }
    relay.stop().await;
}

#[tokio::test]
async fn a_token_for_another_operator_group_never_admits() {
    // ADR-0005 §10: `aud` scoping is what makes cross-TwinNet abuse structurally
    // impossible, so this is the test that keeps that claim true.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let mut device = Device::new(0x0A);
    let socket = client_socket().await;

    let mut spec = TokenSpec::valid_for(&device.rlk_public, 1, 1);
    spec.audience = "some-other-operator".into();
    let token = issuer.mint(&spec);
    assert!(device
        .establish(&socket, relay.addr, &relay.static_public, &token, None)
        .await
        .is_none());
    assert_eq!(relay.leg_count(), 0);
    relay.stop().await;
}

#[tokio::test]
async fn a_stolen_token_is_inert_without_the_key_it_is_bound_to() {
    // ADR-0005 §7.6: `cnf` binds the token to a key the bearer must possess. The
    // thief presents a VALID, unexpired, correctly-audienced token — and cannot
    // use it, because `IK` proves which RLK it actually holds.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let victim = Device::new(0x0A);
    let token = issuer.mint(&TokenSpec::valid_for(&victim.rlk_public, 1, 1));

    let mut thief = Device::new(0xEE);
    let socket = client_socket().await;
    assert!(
        thief
            .establish(&socket, relay.addr, &relay.static_public, &token, None)
            .await
            .is_none(),
        "possession of the token is not possession of the RLK"
    );
    assert_eq!(relay.leg_count(), 0);
    relay.stop().await;
}

// ===========================================================================
// Expired assignments and stale sessions
// ===========================================================================

#[tokio::test]
async fn an_expired_or_not_yet_valid_token_is_refused() {
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;

    type Bend = fn(&mut TokenSpec);
    let cases: [(&str, Bend); 2] = [
        ("expired", |s: &mut TokenSpec| {
            // Beyond `exp + 300 s`: inside the frozen skew it would still admit,
            // and asserting on a token one millisecond past `exp` would assert
            // the skew away.
            s.not_before_ms = NOW_MS - 86_400_000;
            s.not_after_ms = NOW_MS - 600_000;
        }),
        ("not yet valid", |s: &mut TokenSpec| {
            s.not_before_ms = NOW_MS + 600_000;
            s.not_after_ms = NOW_MS + 86_400_000;
        }),
    ];
    for (label, adjust) in cases {
        let mut device = Device::new(0x0A);
        let socket = client_socket().await;
        let mut spec = TokenSpec::valid_for(&device.rlk_public, 1, 1);
        adjust(&mut spec);
        let token = issuer.mint(&spec);
        assert!(
            device
                .establish(&socket, relay.addr, &relay.static_public, &token, None)
                .await
                .is_none(),
            "an {label} token admitted a leg"
        );
    }
    assert_eq!(relay.leg_count(), 0);
    relay.stop().await;
}

#[tokio::test]
async fn a_token_below_the_epoch_floor_is_refused() {
    // Defence in depth only — revocation is enforced at the peer — but a lagging
    // relay must still close admission when it does know (ADR-0005 §11.3).
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let mut device = Device::new(0x0A);
    let socket = client_socket().await;

    let mut spec = TokenSpec::valid_for(&device.rlk_public, 1, 1);
    spec.epoch = common::EPOCH - 1;
    let token = issuer.mint(&spec);
    assert!(device
        .establish(&socket, relay.addr, &relay.static_public, &token, None)
        .await
        .is_none());
    relay.stop().await;
}

#[tokio::test]
async fn a_bind_for_a_bucket_outside_the_skew_is_told_rather_than_ignored() {
    // A tag from a distant bucket cannot match — the peer derived a different
    // one — so it is refused. And ADR-0005 §11.5 requires the refusal be VISIBLE:
    // a device whose clock has drifted must learn that, not retry for ever.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let mut device = Device::new(0x0A);
    let socket = client_socket().await;
    establish(&mut device, &socket, &relay, &issuer, 1, 1).await;

    let reply = device
        .bind(&socket, relay.addr, [0x15; 16], bucket_now() + 5)
        .await
        .expect("the relay answered");
    assert_eq!(
        reply[0],
        FrameType::RelayStatus.to_wire(),
        "a refused bind is a RELAY_STATUS, never silence: 'a relay that drops \
         without a status frame is a defect' (§11.5)"
    );
    assert_eq!(relay.pending_count(), 0);

    // The adjacent buckets ARE accepted — both peers accept bucket, bucket−1 and
    // bucket+1 for skew (§11.1(3)), and a relay that refused them would break
    // every pair whose derivation straddled a bucket boundary.
    for bucket in [bucket_now() - 1, bucket_now(), bucket_now() + 1] {
        let reply = device
            .bind(&socket, relay.addr, [bucket as u8; 16], bucket)
            .await
            .expect("answered");
        assert_eq!(reply[0], FrameType::Bound.to_wire(), "bucket {bucket}");
    }
    relay.stop().await;
}

// ===========================================================================
// Leg liveness and capability negotiation
// ===========================================================================

#[tokio::test]
async fn a_leg_ping_is_answered_independently_of_any_half_flow() {
    // ADR-0006 §11.15(c): the whole of §11.4's failure attribution rests on the
    // leg heartbeat being observable WITHOUT a bound flow — otherwise "the relay
    // is gone" and "the peer is silent" are the same observation.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let mut device = Device::new(0x0A);
    let socket = client_socket().await;
    establish(&mut device, &socket, &relay, &issuer, 1, 1).await;
    assert_eq!(relay.bound_count(), 0, "no flow exists yet");

    let reply = device
        .send_control(&socket, relay.addr, FrameType::Ping, 0, b"")
        .await
        .expect("PONG");
    assert_eq!(reply[0], FrameType::Pong.to_wire());
    relay.stop().await;
}

#[tokio::test]
async fn caps_negotiation_states_the_version_window_and_the_payload_ceiling() {
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let mut device = Device::new(0x0A);
    let socket = client_socket().await;
    establish(&mut device, &socket, &relay, &issuer, 1, 1).await;

    let mine = CapsBody::of_this_build().encode();
    let reply = device
        .send_control(&socket, relay.addr, FrameType::Caps, 0, &mine)
        .await
        .expect("CAPS");
    assert_eq!(reply[0], FrameType::Caps.to_wire());
    let theirs = CapsBody::decode(&reply[HEADER_LEN..]).expect("body");
    assert!(theirs.speaks(twinvpn_relay::frame::VERSION));
    assert_eq!(
        usize::from(theirs.max_data_payload_bytes),
        MAX_DATA_PAYLOAD_BYTES,
        "a device must size its L-DATA datagram from the relay's number, not \
         from a compiled-in copy of it"
    );

    // A device whose window excludes this relay's version is refused, and told.
    let mut incompatible = CapsBody::of_this_build();
    incompatible.version_min = twinvpn_relay::frame::VERSION + 1;
    incompatible.version_max = twinvpn_relay::frame::VERSION + 2;
    let reply = device
        .send_control(
            &socket,
            relay.addr,
            FrameType::Caps,
            0,
            &incompatible.encode(),
        )
        .await
        .expect("answered");
    assert_eq!(reply[0], FrameType::RelayStatus.to_wire());
    relay.stop().await;
}
