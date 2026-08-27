//! Component tests for the forward-verbatim primitive and its two framings.
//!
//! Kept out of `src/forward.rs` so that file stays under the 500-line limit in
//! `CLAUDE.md`, and because every property asserted here is a property of the
//! **public** surface the four service domains consume.
//!
//! Two pairs of tests carry the whole argument, and each pair needs both halves
//! to mean anything:
//!
//! * **CF-2 / unknown fields** — `prost` 0.13 drops them on decode
//!   (`the_failing_control_decode_then_re_encode_drops_the_unknown_field`), and
//!   `Forwarded::forward` does not
//!   (`forward_verbatim_preserves_the_unknown_field`).
//! * **ADR-0003 R7 / B4 framing** — the protobuf mode refuses a WireGuard L-DATA
//!   datagram (`the_failing_control_the_protobuf_mode_still_refuses_l_data`), and
//!   the opaque mode carries it byte for byte
//!   (`the_opaque_mode_carries_l_data_byte_for_byte`).

use bytes::Bytes;
use prost::Message as _;
use twinvpn_schema::{v1, Channel, Reject};

use twinvpn_service_common::forward::*;

/// A protobuf key/varint pair for a field number this build does not know.
fn append_unknown_varint_field(buf: &mut Vec<u8>, field_number: u32, value: u64) {
    let mut tag = u64::from(field_number) << 3; // wire type 0 = varint
    loop {
        let mut byte = u8::try_from(tag & 0x7f).expect("masked");
        tag >>= 7;
        if tag != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if tag == 0 {
            break;
        }
    }
    let mut v = value;
    loop {
        let mut byte = u8::try_from(v & 0x7f).expect("masked");
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if v == 0 {
            break;
        }
    }
}

/// A `MessageMetadata` plus a field number 1000 that `twinvpn.v1` does not
/// define — a future peer's additive extension, exactly the case ADR-0003
/// §11 B1's preserve-and-forward rule exists for.
fn message_with_an_unknown_field() -> Bytes {
    let known = v1::MessageMetadata {
        proto_version: 1,
        message_id: vec![7u8; 16],
        twinnet_id: "tn-1".to_owned(),
        ..Default::default()
    };
    let mut buf = known.encode_to_vec();
    append_unknown_varint_field(&mut buf, 1000, 42);
    Bytes::from(buf)
}

#[test]
fn the_failing_control_decode_then_re_encode_drops_the_unknown_field() {
    // This half is the reason the other half exists. If this ever starts
    // passing, `prost` gained preserve-and-forward and CF-2's constraint on
    // this crate can be revisited.
    let original = message_with_an_unknown_field();
    let decoded = v1::MessageMetadata::decode(original.clone()).expect("decodes");
    let re_encoded = Bytes::from(decoded.encode_to_vec());

    assert_ne!(
        re_encoded, original,
        "prost 0.13 is expected to DROP unknown fields; if this passes, \
         re-read contracts/docs/phase1-conflicts.md CF-2"
    );
    assert!(
        re_encoded.len() < original.len(),
        "the dropped field should make the re-encoding shorter"
    );
}

#[test]
fn forward_verbatim_preserves_the_unknown_field() {
    let original = message_with_an_unknown_field();
    let f =
        Forwarded::<v1::MessageMetadata>::decode(original.clone(), Channel::ControlAndTelemetry)
            .expect("valid");

    // The view is usable for routing decisions...
    assert_eq!(f.view().twinnet_id, "tn-1");
    assert_eq!(f.view().proto_version, 1);

    // ...and what goes on the wire is what arrived, byte for byte.
    assert_eq!(f.forward(), original);
}

#[test]
fn the_two_halves_disagree_which_is_the_whole_finding() {
    let original = message_with_an_unknown_field();
    let re_encoded = Bytes::from(
        v1::MessageMetadata::decode(original.clone())
            .unwrap()
            .encode_to_vec(),
    );
    let forwarded =
        Forwarded::<v1::MessageMetadata>::decode(original.clone(), Channel::ControlAndTelemetry)
            .unwrap()
            .forward();

    assert_eq!(forwarded, original);
    assert_ne!(re_encoded, original);
    assert_ne!(forwarded, re_encoded);
}

#[test]
fn the_explicit_rewrite_really_does_drop_it() {
    let original = message_with_an_unknown_field();
    let rewritten =
        Forwarded::<v1::MessageMetadata>::decode(original.clone(), Channel::ControlAndTelemetry)
            .unwrap()
            .rewrite_dropping_unknown_fields(|m| m.proto_version = 2);

    assert_ne!(rewritten, original);
    let back = v1::MessageMetadata::decode(rewritten).unwrap();
    assert_eq!(back.proto_version, 2);
}

#[test]
fn an_oversized_message_is_refused_before_any_decode() {
    let big = Bytes::from(vec![0u8; Channel::PeerDatagram.max_bytes() + 1]);
    let e = Verbatim::from_received(big, Channel::PeerDatagram).expect_err("must reject");
    assert!(matches!(
        e,
        Reject::SizeExceeded {
            parser_id: "c4",
            ..
        }
    ));
    assert_eq!(e.reason_code(), twinvpn_types::codes::PROTO_SIZE_EXCEEDED);
}

#[test]
fn c4_gets_the_tighter_bound_because_b3_is_the_hostile_boundary() {
    // limits.json: c4_max_bytes = 1200, c1_c2_c7_max_bytes = 65536.
    let mid = Bytes::from(vec![0u8; 2000]);
    assert!(Verbatim::from_received(mid.clone(), Channel::PeerDatagram).is_err());
    // The same octets are within the control channel's cap; whether they
    // parse is a separate question, which is why this asserts only the cap.
    assert!(mid.len() < Channel::ControlAndTelemetry.max_bytes());
}

/// A WireGuard L-DATA datagram, the shape a relay actually forwards.
///
/// ADR-0001 §11: unmodified WireGuard. A transport-data message is a 4-byte
/// type field, a 4-byte receiver index, an 8-byte counter, then AEAD
/// ciphertext and its 16-byte Poly1305 tag. None of that is a protobuf
/// record sequence, and none of it may be parsed by a relay (I1).
fn wireguard_l_data() -> Bytes {
    let mut v = vec![4_u8, 0, 0, 0]; // message type 4 = transport data
    v.extend_from_slice(&0x1234_5678_u32.to_le_bytes()); // receiver index
    v.extend_from_slice(&7_u64.to_le_bytes()); // counter
    v.extend_from_slice(&[0xC3; 64]); // ciphertext
    v.extend_from_slice(&[0x9E; 16]); // Poly1305 tag
    Bytes::from(v)
}

#[test]
fn the_failing_control_the_protobuf_mode_still_refuses_l_data() {
    // Half one of the pair. `from_received` runs `depth::check`, a protobuf
    // record scan, and a WireGuard datagram is not a record sequence. This is
    // the defect `relay-plane` measured, preserved as a control so the two
    // modes are shown to differ in exactly one respect.
    let err = Verbatim::from_received(wireguard_l_data(), Channel::PeerDatagram)
        .expect_err("protobuf framing must still refuse ciphertext");
    assert!(
        matches!(err, Reject::Unparseable { parser_id: "c4" }),
        "{err:?}"
    );
}

#[test]
fn the_opaque_mode_carries_l_data_byte_for_byte() {
    // Half two. Same bytes, same channel, same cap — one difference.
    let original = wireguard_l_data();
    let v = Verbatim::from_opaque(original.clone(), Channel::PeerDatagram)
        .expect("ciphertext is carriable");
    assert_eq!(v.as_bytes(), &original[..]);
    assert_eq!(v.to_bytes(), original);
    assert_eq!(v.len(), original.len());
    assert_eq!(v.framing(), Framing::Opaque);
    assert_eq!(v.channel(), Channel::PeerDatagram);
    assert_eq!(v.into_bytes(), original);
}

#[test]
fn the_two_modes_differ_in_exactly_one_respect() {
    let bytes = wireguard_l_data();
    assert!(Verbatim::from_received(bytes.clone(), Channel::PeerDatagram).is_err());
    assert!(Verbatim::from_opaque(bytes.clone(), Channel::PeerDatagram).is_ok());

    // ...and on bytes that ARE a well-formed record sequence, both accept
    // and both carry the identical octets. The difference is the check, not
    // the carriage.
    let proto = message_with_an_unknown_field();
    let a = Verbatim::from_received(proto.clone(), Channel::ControlAndTelemetry).unwrap();
    let b = Verbatim::from_opaque(proto.clone(), Channel::ControlAndTelemetry).unwrap();
    assert_eq!(a.as_bytes(), b.as_bytes());
    assert_eq!(a.as_bytes(), &proto[..]);
    assert_ne!(a.framing(), b.framing());
}

#[test]
fn the_opaque_mode_carries_every_byte_value() {
    // 0x00..=0xFF in order, then reversed, then a run of 0x00 and a run of
    // 0xFF. A carrier that "helpfully" trimmed, terminated on a NUL, or
    // treated a high bit as a continuation would fail one of these.
    let mut v: Vec<u8> = (0u8..=255).collect();
    v.extend((0u8..=255).rev());
    v.extend(std::iter::repeat_n(0x00, 32));
    v.extend(std::iter::repeat_n(0xFF, 32));
    let original = Bytes::from(v.clone());

    let carried = Verbatim::from_opaque(original.clone(), Channel::ControlAndTelemetry)
        .expect("no byte value is special")
        .into_bytes();
    assert_eq!(carried, original);
    assert_eq!(carried.len(), 576);
    for (i, b) in carried.iter().enumerate() {
        assert_eq!(*b, v[i], "byte {i} changed");
    }
}

#[test]
fn the_opaque_mode_runs_no_structural_scan_at_all() {
    // Bytes chosen to be maximally hostile to a protobuf record scan: a tag
    // claiming a 4 GiB length-delimited field, and a deeply nested group.
    // The opaque mode must not care, because it must not look.
    let hostile = Bytes::from(vec![0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x42, 0x42]);
    assert!(
        Verbatim::from_received(hostile.clone(), Channel::ControlAndTelemetry).is_err(),
        "the protobuf mode must reject a hostile declared length"
    );
    let v = Verbatim::from_opaque(hostile.clone(), Channel::ControlAndTelemetry)
        .expect("opaque octets have no declared length to honour");
    assert_eq!(v.as_bytes(), &hostile[..]);
}

#[test]
fn the_protobuf_mode_still_enforces_the_depth_cap() {
    // The guard the control plane and the rendezvous must not lose. Nest
    // length-delimited field 1 deeper than C4's limit of 4.
    let mut buf = vec![0x42_u8];
    for _ in 0..12 {
        let mut next = vec![0x0a, u8::try_from(buf.len()).expect("small")];
        next.extend_from_slice(&buf);
        buf = next;
    }
    let deep = Bytes::from(buf);
    let err = Verbatim::from_received(deep.clone(), Channel::PeerDatagram)
        .expect_err("the depth cap must still bite");
    assert_eq!(
        err.reason_code(),
        twinvpn_types::codes::PROTO_DEPTH_EXCEEDED
    );
    // The opaque mode carries it, because depth is a protobuf concept.
    assert!(Verbatim::from_opaque(deep, Channel::PeerDatagram).is_ok());
}

#[test]
fn both_modes_enforce_the_same_size_cap() {
    let cap = Channel::PeerDatagram.max_bytes();
    let over = Bytes::from(vec![0u8; cap + 1]);

    for err in [
        Verbatim::from_received(over.clone(), Channel::PeerDatagram).unwrap_err(),
        Verbatim::from_opaque(over.clone(), Channel::PeerDatagram).unwrap_err(),
    ] {
        assert!(matches!(err, Reject::SizeExceeded { parser_id: "c4", limit, .. } if limit == cap));
        assert_eq!(err.reason_code(), twinvpn_types::codes::PROTO_SIZE_EXCEEDED);
    }

    // Exactly at the cap the opaque mode accepts: never a truncation, never
    // a pad. (The protobuf mode would additionally have to parse.)
    assert!(Verbatim::from_opaque(Bytes::from(vec![0u8; cap]), Channel::PeerDatagram).is_ok());
}

#[test]
fn the_general_form_agrees_with_the_named_constructors() {
    let proto = message_with_an_unknown_field();
    assert_eq!(
        Verbatim::with_framing(
            proto.clone(),
            Channel::ControlAndTelemetry,
            Framing::ProtobufRecords
        )
        .unwrap(),
        Verbatim::from_received(proto.clone(), Channel::ControlAndTelemetry).unwrap()
    );
    let cipher = wireguard_l_data();
    assert_eq!(
        Verbatim::with_framing(cipher.clone(), Channel::PeerDatagram, Framing::Opaque).unwrap(),
        Verbatim::from_opaque(cipher, Channel::PeerDatagram).unwrap()
    );
    assert!(Framing::ProtobufRecords.checks_depth());
    assert!(!Framing::Opaque.checks_depth());
}

#[test]
fn forwarded_is_always_the_protobuf_framing() {
    // `Forwarded` holds a decoded view, so there is nothing an opaque framing
    // could mean on it. The depth guard is therefore unconditional there.
    let f = Forwarded::<v1::MessageMetadata>::decode(
        message_with_an_unknown_field(),
        Channel::ControlAndTelemetry,
    )
    .unwrap();
    assert_eq!(f.verbatim().framing(), Framing::ProtobufRecords);
}

#[test]
fn an_opaque_debug_still_renders_no_octets() {
    let v = Verbatim::from_opaque(wireguard_l_data(), Channel::PeerDatagram).unwrap();
    let d = format!("{v:?}");
    assert!(d.contains("<not rendered>"), "{d}");
    assert!(d.contains("opaque"), "{d}");
    assert!(d.contains("96 B"), "{d}"); // 4 + 4 + 8 + 64 + 16
                                        // No octet of the ciphertext, in any rendering, at any level.
    assert!(!d.contains("C3"), "{d}");
    assert!(!d.contains("c3"), "{d}");
    assert!(!d.contains("195"), "{d}");
}

#[test]
fn debug_never_renders_the_octets() {
    let v = Verbatim::from_received(
        Bytes::from_static(b"\x08\x01secret-looking-payload"),
        Channel::ControlAndTelemetry,
    );
    // Whether it validates is irrelevant; what matters is that if it does,
    // its Debug carries no content.
    if let Ok(v) = v {
        let d = format!("{v:?}");
        assert!(!d.contains("secret-looking-payload"), "{d}");
        assert!(d.contains("<not rendered>"), "{d}");
    }
}

#[test]
fn forwarding_several_hops_is_still_the_original_octets() {
    let original = message_with_an_unknown_field();
    let mut carried = original.clone();
    for _ in 0..5 {
        carried = Forwarded::<v1::MessageMetadata>::decode(carried, Channel::ControlAndTelemetry)
            .unwrap()
            .into_forwarded();
    }
    assert_eq!(carried, original);
}
