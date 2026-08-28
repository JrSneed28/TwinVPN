//! The device side of ADR-0005 §9.1's frame, against the format
//! `services/relay` already ships.

use bytes::Bytes;
use twinvpn_relay_client::frame::{
    self, CounterWindow, FrameError, FrameType, InboundFrame, LegKey, LegSendCounter,
    OutboundFrame, Payload, HEADER_LEN, L_DATA_OVERHEAD_BYTES, MAX_DATA_PAYLOAD_BYTES,
    OVERLAY_MTU_FLOOR, VERSION,
};

fn key(b: u8) -> LegKey {
    LegKey::from_array([b; 32])
}

fn data_frame(flow_id: u32, payload: &[u8]) -> OutboundFrame {
    OutboundFrame::new(FrameType::Data, 0, flow_id, Bytes::copy_from_slice(payload))
        .expect("a well-formed DATA frame")
}

// ---------------------------------------------------------------------------
// The wire format, against the relay's
// ---------------------------------------------------------------------------

#[test]
fn the_header_is_the_sixteen_bytes_adr_0005_9_1_lays_out() {
    let k = key(0x4b);
    let f = data_frame(0xdead_beef, &[0xab; 16]);
    let wire = f.encode(&k, 0x0102_0304_0506_0708);

    assert_eq!(HEADER_LEN, 16);
    assert_eq!(wire.len(), HEADER_LEN + 16);

    assert_eq!(wire[0], 0x01, "type = DATA");
    assert_eq!(
        wire[1],
        VERSION << 4,
        "ver in the high nibble, flags in the low"
    );
    // counter_low is the LOW 16 bits of the full counter, big-endian.
    assert_eq!(&wire[2..4], &0x0708u16.to_be_bytes());
    assert_eq!(&wire[4..8], &0xdead_beefu32.to_be_bytes());
    // 8..16 is the truncated 64-bit MAC; the payload follows verbatim.
    assert_eq!(&wire[16..], &[0xab; 16]);
}

#[test]
fn the_mac_input_matches_twinvpn_cryptos_shared_golden_vector_byte_for_byte() {
    // `twinvpn-crypto`'s `fixture_mac_input` is exactly this frame, and the
    // relay side pins the same bytes. If the two ends ever disagree about the
    // MAC input, every legitimate frame is dropped and the relay looks
    // correctly configured while doing it.
    let f = data_frame(0xdead_beef, &[0xab; 16]);
    let input = f.mac_input(0x0102_0304_0506_0708);

    let mut expected = Vec::new();
    expected.push(0x01u8); // type = DATA
    expected.push(1 << 4); // ver = 1, flags = 0
    expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
    expected.extend_from_slice(&0xdead_beefu32.to_be_bytes());
    expected.extend_from_slice(&[0xab; 16]);
    assert_eq!(input, expected);

    // And the tag this build puts on the wire is the golden one.
    let wire = f.encode(&key(0x4b), 0x0102_0304_0506_0708);
    let tag: Vec<String> = wire[8..16].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        tag.concat(),
        "d04f9be2b57fc15b",
        "the truncated 256-bit MAC, not a short-output BLAKE2s"
    );
}

#[test]
fn the_mac_covers_the_full_counter_and_not_the_wire_sixteen_bits() {
    // Two counters that share their low 16 bits must produce different tags,
    // or a 16-bit wrap becomes a forgery oracle.
    let f = data_frame(1, b"x");
    let a = f.encode(&key(1), 0x0000_0000_0000_0001);
    let b = f.encode(&key(1), 0x0001_0000_0000_0001);
    assert_eq!(&a[2..4], &b[2..4], "the same counter_low reaches the wire");
    assert_ne!(&a[8..16], &b[8..16], "but the tags differ");
}

#[test]
fn the_mac_covers_type_flags_flow_id_and_payload() {
    let k = key(7);
    let base = data_frame(1, b"payload").encode(&k, 5);

    let other_type = OutboundFrame::new(FrameType::Ping, 0, 1, Bytes::from_static(b"payload"))
        .unwrap()
        .encode(&k, 5);
    let other_flags = OutboundFrame::new(FrameType::Data, 0x0F, 1, Bytes::from_static(b"payload"))
        .unwrap()
        .encode(&k, 5);
    let other_flow = data_frame(2, b"payload").encode(&k, 5);
    let other_payload = data_frame(1, b"payloae").encode(&k, 5);

    for (label, v) in [
        ("type", other_type),
        ("flags", other_flags),
        ("flow_id", other_flow),
        ("payload", other_payload),
    ] {
        assert_ne!(
            &base[8..16],
            &v[8..16],
            "{label} must be covered by the MAC"
        );
    }
}

// ---------------------------------------------------------------------------
// Round trip and authentication
// ---------------------------------------------------------------------------

#[test]
fn a_frame_this_device_sends_verifies_on_the_way_back_in() {
    let k = key(9);
    let mut send = LegSendCounter::new();
    let mut window = CounterWindow::new();

    let counter = send.take_next();
    assert_eq!(counter, 0, "the leg counter starts at 0, like the wire");
    let wire = data_frame(42, b"an opaque L-DATA datagram").encode(&k, counter);

    let parsed = InboundFrame::parse(&wire).expect("parses");
    assert_eq!(parsed.kind(), FrameType::Data);
    assert_eq!(parsed.flow_id(), 42);

    let verified = parsed.verify(&k, &mut window).expect("verifies");
    assert_eq!(verified.counter(), 0);
    assert_eq!(verified.payload().as_bytes(), b"an opaque L-DATA datagram");
    assert!(window.has_accepted_any());
}

#[test]
fn a_forged_or_cross_key_tag_is_refused() {
    let mut window = CounterWindow::new();
    let wire = data_frame(1, b"hello").encode(&key(1), 0);

    // A different leg key: off-path injection is what the MAC exists to stop.
    let err = InboundFrame::parse(&wire)
        .unwrap()
        .verify(&key(2), &mut window)
        .unwrap_err();
    assert_eq!(err, FrameError::AuthenticationFailed);
    assert!(
        !window.has_accepted_any(),
        "a forged frame must not advance the window, or it locks out the peer"
    );

    // A flipped payload byte under the right key.
    let mut tampered = wire.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let err = InboundFrame::parse(&Bytes::from(tampered))
        .unwrap()
        .verify(&key(1), &mut window)
        .unwrap_err();
    assert_eq!(err, FrameError::AuthenticationFailed);
}

#[test]
fn a_replayed_frame_is_refused_after_it_authenticates() {
    let k = key(3);
    let mut window = CounterWindow::new();
    let wire = data_frame(1, b"once").encode(&k, 7);

    assert!(InboundFrame::parse(&wire)
        .unwrap()
        .verify(&k, &mut window)
        .is_ok());
    assert_eq!(
        InboundFrame::parse(&wire)
            .unwrap()
            .verify(&k, &mut window)
            .unwrap_err(),
        FrameError::ReplayedCounter
    );
}

// ---------------------------------------------------------------------------
// Bounds, direction and hygiene
// ---------------------------------------------------------------------------

#[test]
fn the_payload_bound_is_derived_and_clears_the_1280_overlay_floor() {
    assert_eq!(MAX_DATA_PAYLOAD_BYTES, 1_456);
    assert_eq!(
        MAX_DATA_PAYLOAD_BYTES,
        1500 - 20 - 8 - HEADER_LEN,
        "R-UDP over IPv4 is the row with the least framing beneath RelayFrame"
    );
    // A conforming relay must carry the 1280 overlay floor plus L-DATA
    // overhead. The margin is asserted rather than the inequality, so the test
    // says how much room there is rather than merely that there is some.
    let floor_requirement = OVERLAY_MTU_FLOOR + L_DATA_OVERHEAD_BYTES;
    assert_eq!(floor_requirement, 1_312);
    assert_eq!(
        MAX_DATA_PAYLOAD_BYTES - floor_requirement,
        144,
        "the bound clears the 1280 floor by 144 bytes"
    );
    // NOT C4's 1200, which is too small to be legal on this path: a 1200-byte
    // bound would make the 1280 floor unachievable on every carriage.
    assert_eq!(
        MAX_DATA_PAYLOAD_BYTES - 1_200,
        256,
        "C4's cap is the pre-authentication rendezvous datagram's, not B4's"
    );
}

#[test]
fn an_oversized_payload_is_refused_before_it_is_retained() {
    let too_big = Bytes::from(vec![0u8; MAX_DATA_PAYLOAD_BYTES + 1]);
    assert_eq!(
        Payload::new(too_big.clone()).unwrap_err(),
        FrameError::PayloadTooLarge {
            observed: MAX_DATA_PAYLOAD_BYTES + 1,
            limit: MAX_DATA_PAYLOAD_BYTES,
        }
    );
    // And on the receive path, from a datagram an attacker controls.
    let mut wire = vec![0u8; HEADER_LEN];
    wire[0] = FrameType::Data.to_wire();
    wire[1] = VERSION << 4;
    wire.extend_from_slice(&vec![0u8; MAX_DATA_PAYLOAD_BYTES + 1]);
    assert!(matches!(
        InboundFrame::parse(&Bytes::from(wire)).unwrap_err(),
        FrameError::PayloadTooLarge { .. }
    ));
    // Exactly at the bound is fine.
    assert!(Payload::new(Bytes::from(vec![0u8; MAX_DATA_PAYLOAD_BYTES])).is_ok());
}

#[test]
fn a_short_unknown_or_wrong_version_datagram_is_dropped() {
    assert_eq!(
        InboundFrame::parse(&Bytes::from_static(&[0u8; 15])).unwrap_err(),
        FrameError::TooShort
    );

    let mut unknown = vec![0u8; HEADER_LEN];
    unknown[0] = 0x99;
    unknown[1] = VERSION << 4;
    assert_eq!(
        InboundFrame::parse(&Bytes::from(unknown)).unwrap_err(),
        FrameError::UnknownType
    );

    let mut old = vec![0u8; HEADER_LEN];
    old[0] = FrameType::Data.to_wire();
    old[1] = 2 << 4;
    assert_eq!(
        InboundFrame::parse(&Bytes::from(old)).unwrap_err(),
        FrameError::UnsupportedVersion
    );
}

#[test]
fn reserved_bits_are_ignored_on_receive_rather_than_rejected() {
    // ADR-0014 forward compatibility: zero on send, IGNORED on receive. A build
    // that rejected them could not talk to a later relay.
    let k = key(5);
    let mut window = CounterWindow::new();
    let f = OutboundFrame::new(FrameType::Data, 0x0F, 1, Bytes::from_static(b"x")).unwrap();
    let wire = f.encode(&k, 0);
    let parsed = InboundFrame::parse(&wire).expect("flags do not make it unparseable");
    assert!(parsed.verify(&k, &mut window).is_ok());
}

#[test]
fn a_device_cannot_send_a_frame_type_only_the_relay_sends() {
    for kind in [FrameType::Bound, FrameType::Drain, FrameType::RelayStatus] {
        assert!(!kind.device_may_send(), "{kind:?}");
        assert_eq!(
            OutboundFrame::new(kind, 0, 1, Bytes::new()).unwrap_err(),
            FrameError::WrongDirection
        );
    }
    for kind in [
        FrameType::Data,
        FrameType::Bind,
        FrameType::Ping,
        FrameType::Pong,
        FrameType::Caps,
        FrameType::Rebind,
    ] {
        assert!(kind.device_may_send(), "{kind:?}");
        assert!(OutboundFrame::new(kind, 0, 1, Bytes::new()).is_ok());
    }
}

#[test]
fn every_frame_type_round_trips_through_the_wire_byte() {
    for kind in [
        FrameType::Data,
        FrameType::Bind,
        FrameType::Bound,
        FrameType::Ping,
        FrameType::Pong,
        FrameType::Drain,
        FrameType::RelayStatus,
        FrameType::Caps,
        FrameType::Rebind,
    ] {
        assert_eq!(FrameType::from_wire(kind.to_wire()), Some(kind));
    }
    // The relay's exact wire bytes, so the two ends cannot drift silently.
    assert_eq!(FrameType::Data.to_wire(), 0x01);
    assert_eq!(FrameType::Bind.to_wire(), 0x10);
    assert_eq!(FrameType::Bound.to_wire(), 0x11);
    assert_eq!(FrameType::Ping.to_wire(), 0x12);
    assert_eq!(FrameType::Pong.to_wire(), 0x13);
    assert_eq!(FrameType::Drain.to_wire(), 0x14);
    assert_eq!(FrameType::RelayStatus.to_wire(), 0x15);
    assert_eq!(FrameType::Caps.to_wire(), 0x16);
    assert_eq!(FrameType::Rebind.to_wire(), 0x17);
}

#[test]
fn a_payload_and_a_leg_key_never_render_their_contents() {
    // ownership.md §6 rule 11: a tunnel payload must not reach a log, and a key
    // must not reach one through a derive on an enclosing struct.
    let p = Payload::new(Bytes::from_static(b"SECRETCIPHERTEXT")).unwrap();
    let rendered = format!("{p:?}");
    assert!(!rendered.contains("SECRET"), "{rendered}");
    assert!(rendered.contains("16 B opaque"), "{rendered}");

    let k = key(0xAB);
    let rendered = format!("{k:?}");
    assert!(!rendered.contains("ab"), "{rendered}");
    assert!(rendered.contains("redacted"), "{rendered}");

    // And an InboundFrame's derived Debug is safe because Payload's is.
    let wire = data_frame(1, b"SECRETCIPHERTEXT").encode(&key(1), 0);
    let parsed = InboundFrame::parse(&wire).unwrap();
    assert!(!format!("{parsed:?}").contains("SECRET"));
}

#[test]
fn a_leg_never_fragments() {
    assert!(!frame::leg_may_fragment());
}

// ---------------------------------------------------------------------------
// RFC 9147 §4.2.2 counter reconstruction
// ---------------------------------------------------------------------------

#[test]
fn the_counter_window_reconstructs_across_a_sixteen_bit_wrap() {
    let mut w = CounterWindow::new();
    // Nothing seen: the wire value IS the counter.
    assert_eq!(w.reconstruct(0), 0);
    assert!(w.accept(0));

    // Walk up to just below the wrap.
    assert!(w.accept(0xFFFF));
    assert_eq!(w.highest(), 0xFFFF);

    // The next frame's low bits are 0x0000 — nearest candidate is 0x1_0000,
    // not 0. Picking 0 would read a fresh frame as an ancient replay.
    assert_eq!(w.reconstruct(0x0000), 0x1_0000);
    assert!(w.accept(0x1_0000));
    assert_eq!(w.highest(), 0x1_0000);
}

#[test]
fn the_counter_window_accepts_reordering_and_refuses_a_replay_or_an_ancient_frame() {
    let mut w = CounterWindow::new();
    assert!(w.accept(100));
    assert!(w.accept(102));
    assert!(w.accept(101), "ordinary reordering inside the window");
    assert!(!w.accept(101), "but only once");
    assert!(
        !w.accept(100 - CounterWindow::WIDTH),
        "too old to judge is refused rather than guessed at"
    );
}

#[test]
fn the_counter_window_distinguishes_nothing_seen_from_counter_zero_seen() {
    // The same conflation that made the first L-DATA record of every tunnel a
    // replay (D-1). The leg window must not repeat it.
    let mut w = CounterWindow::new();
    assert!(!w.has_accepted_any());
    assert!(w.accept(0), "counter 0 is a real first frame");
    assert!(w.has_accepted_any());
    assert!(!w.accept(0), "and a replay the second time");
}
