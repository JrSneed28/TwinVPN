//! Fuzzing every decoder that reads bytes off a **network** wire.
//!
//! **Owner:** `test-engineering`.
//!
//! `ownership.md` §6 rules 9 and 10 say every untrusted input is validated
//! before any allocation proportional to a declared length, and that every such
//! allocation is bounded. Those are properties of a decoder under *adversarial*
//! input, and an example-based test cannot measure them: the examples are the
//! ones the author thought of.
//!
//! Each target below names where its bytes come from and who can choose them.
//! A decoder with no entry in this file is a decoder nobody has fuzzed.
//!
//! The engine, and why it is not `cargo fuzz`, is
//! [`twinvpn_system_tests::fuzz`].

use bytes::Bytes;
use prost::Message as _;
use twinvpn_schema::{limits, v1, Channel};
use twinvpn_system_tests::fuzz::{corpus, fuzz, outcome_of, Outcome};
use twinvpn_types::{IpAddr, V4Addr};

/// One seed per target family, so a failure names which corpus produced it.
const SEED: u64 = 0x7717_4E17_5EED_0001;

/// Per-shape iterations. The corpus is `3 * ITERATIONS + seeds * ITERATIONS`.
const ITERATIONS: usize = 1_500;

// ---------------------------------------------------------------------------
// Valid seeds. Mutating a valid encoding is what reaches the code past the
// first length check; a uniformly random string is refused by byte three.
// ---------------------------------------------------------------------------

/// A populated `ConnectionCandidate`, both families represented across the set.
fn candidate_set() -> v1::CandidateSet {
    let v4 = v1::ConnectionCandidate {
        candidate_id: vec![0u8; 8],
        family: 1,
        kind: 1,
        endpoint: Some(v1::Endpoint {
            address: Some(twinvpn_schema::envelope::encode_address(IpAddr::V4(
                V4Addr::from_octets([10, 0, 0, 1]),
            ))),
            port: 5000,
        }),
        priority: 1,
        mtu_hint: 1280,
        expires_at_ms: 0,
    };
    let v6 = v1::ConnectionCandidate {
        family: 2,
        endpoint: Some(v1::Endpoint {
            address: Some(v1::IpAddress {
                address: Some(v1::ip_address::Address::V6(v1::IPv6Address {
                    octets: vec![0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                    zone_index: 0,
                })),
            }),
            port: 5001,
        }),
        ..v4.clone()
    };
    v1::CandidateSet {
        session_nonce: vec![0u8; 16],
        generation: 1,
        candidates: vec![v4, v6],
    }
}

/// A well-formed envelope, produced by the encoder the peer would have used.
fn error_envelope() -> v1::ErrorEnvelope {
    use twinvpn_types::{codes, AddressFamily, Component, Diagnostic, EvidenceValue};
    twinvpn_schema::envelope::encode(
        &Diagnostic::builder(codes::NAT_PUNCH_TIMEOUT, Component::NatTraversal)
            .evidence("family", EvidenceValue::Family(AddressFamily::V6))
            .occurred_at_ms(Some(1_800_000_000_000))
            .build(),
    )
}

// ---------------------------------------------------------------------------
// C1 / C2 / C7 — the control channel. The peer is the control plane, which is
// authenticated but is still not this device.
// ---------------------------------------------------------------------------

#[test]
fn the_control_channel_decoder_is_total_over_arbitrary_bytes() {
    let seeds = vec![
        v1::ControlEvent::default().encode_to_vec(),
        error_envelope().encode_to_vec(),
    ];
    let inputs = corpus(SEED, ITERATIONS, 2_048, &seeds);
    let report = fuzz(
        "schema::validate::decode<ControlEvent>[C1/C2/C7]",
        &inputs,
        |b| {
            outcome_of(&twinvpn_schema::validate::decode::<v1::ControlEvent>(
                b,
                Channel::ControlAndTelemetry,
            ))
        },
    );
    assert!(report.reached_accept(), "{report:?} never reached a decode");
    assert!(report.reached_reject(), "{report:?} never reached a reject");
}

#[test]
fn no_input_over_the_channel_cap_is_ever_accepted() {
    // The cap is checked before `prost` allocates. An input one byte over must
    // be refused whatever it contains — including a perfectly valid message
    // padded to length, which is the shape an attacker would actually send.
    let cap = Channel::ControlAndTelemetry.max_bytes();
    let mut padded = v1::ControlEvent::default().encode_to_vec();
    padded.resize(cap + 1, 0);
    let err =
        twinvpn_schema::validate::decode::<v1::ControlEvent>(&padded, Channel::ControlAndTelemetry)
            .expect_err("one byte over the cap");
    assert_eq!(err.reason_code(), twinvpn_types::codes::PROTO_SIZE_EXCEEDED);
}

// ---------------------------------------------------------------------------
// C4 — the peer datagram channel. The bytes are chosen by another *device*,
// which is the least trusted party that reaches this decoder at all.
// ---------------------------------------------------------------------------

#[test]
fn the_peer_datagram_decoder_is_total_over_arbitrary_bytes() {
    let seeds = vec![candidate_set().encode_to_vec()];
    let inputs = corpus(SEED ^ 0x11, ITERATIONS, limits::C4_MAX_BYTES, &seeds);
    let report = fuzz("schema::validate::decode<CandidateSet>[C4]", &inputs, |b| {
        outcome_of(&twinvpn_schema::validate::decode::<v1::CandidateSet>(
            b,
            Channel::PeerDatagram,
        ))
    });
    assert!(report.reached_accept(), "{report:?}");
    assert!(report.reached_reject(), "{report:?}");
}

#[test]
fn the_depth_scanner_is_total_and_never_recurses_on_the_hosts_stack() {
    // The scanner runs BEFORE the decode, on every byte an attacker sends, and
    // its whole job is to survive an input built to blow a recursive parser's
    // stack. A panic here is the denial of service it exists to prevent.
    let seeds = vec![
        candidate_set().encode_to_vec(),
        error_envelope().encode_to_vec(),
    ];
    for channel in [Channel::ControlAndTelemetry, Channel::PeerDatagram] {
        let inputs = corpus(SEED ^ 0x22, ITERATIONS, 4_096, &seeds);
        let report = fuzz("schema::depth::check", &inputs, move |b| {
            outcome_of(&twinvpn_schema::depth::check(b, channel))
        });
        assert!(report.reached_accept(), "{channel:?}: {report:?}");
        assert!(report.reached_reject(), "{channel:?}: {report:?}");
    }

    // A deliberately pathological input, outside the random corpus, because a
    // random walk will not build two thousand correctly nested length-delimited
    // fields — and a correctly nested one is the input that would recurse.
    let mut nested: Vec<u8> = Vec::new();
    for _ in 0..2_000 {
        let mut next = Vec::with_capacity(nested.len() + 6);
        next.push(0x0a); // field 1, wire type 2 (length-delimited)
        let mut remaining = nested.len() as u64;
        loop {
            #[allow(clippy::cast_possible_truncation)]
            let byte = (remaining & 0x7f) as u8;
            remaining >>= 7;
            if remaining == 0 {
                next.push(byte);
                break;
            }
            next.push(byte | 0x80);
        }
        next.extend_from_slice(&nested);
        nested = next;
    }
    let err = twinvpn_schema::depth::check(&nested, Channel::ControlAndTelemetry)
        .expect_err("two thousand levels must be refused, not recursed");
    assert_eq!(
        err.reason_code(),
        twinvpn_types::codes::PROTO_DEPTH_EXCEEDED
    );
}

// ---------------------------------------------------------------------------
// The error envelope. Two decoders, and the composite is what a peer reaches:
// bytes -> ErrorEnvelope -> DecodedEnvelope.
// ---------------------------------------------------------------------------

#[test]
fn the_error_envelope_decoder_is_total_over_arbitrary_bytes() {
    let seeds = vec![error_envelope().encode_to_vec()];
    let inputs = corpus(SEED ^ 0x33, ITERATIONS, 4_096, &seeds);
    let report =
        fuzz(
            "schema::envelope::decode",
            &inputs,
            |b| match twinvpn_schema::validate::decode::<v1::ErrorEnvelope>(
                b,
                Channel::ControlAndTelemetry,
            ) {
                Ok(msg) => outcome_of(&twinvpn_schema::envelope::decode(&msg)),
                Err(e) => Outcome::reject(format!("{e:?}")),
            },
        );
    assert!(report.reached_accept(), "{report:?}");
    assert!(report.reached_reject(), "{report:?}");
}

// ---------------------------------------------------------------------------
// The control-plane client's own entry point. Same channel, but this is the
// function the C2 stream actually calls, so it is fuzzed as itself rather than
// assumed equivalent to the layer under it.
// ---------------------------------------------------------------------------

#[test]
fn the_cp_client_event_decoder_is_total_over_arbitrary_bytes() {
    let seeds = vec![v1::ControlEvent::default().encode_to_vec()];
    let inputs = corpus(SEED ^ 0x44, ITERATIONS, 4_096, &seeds);
    let report = fuzz("cp_client::decode_event", &inputs, |b| {
        let octets = twinvpn_cp_client::octets::ReceivedOctets::from_wire(b);
        outcome_of(&twinvpn_cp_client::decode_event(&octets))
    });
    assert!(report.reached_accept(), "{report:?}");
    assert!(report.reached_reject(), "{report:?}");
}

// ---------------------------------------------------------------------------
// The relay leg. Unauthenticated at parse time by construction — `InboundFrame`
// exists so "parsed" and "authentic" cannot be confused — which makes this the
// single most exposed decoder in the core: anyone who can send a UDP datagram
// to the device's relay socket reaches it.
// ---------------------------------------------------------------------------

#[test]
fn the_relay_frame_parser_is_total_over_arbitrary_datagrams() {
    // A valid DATA frame header: type, ver|flags, counter_low, flow_id, tag.
    let mut valid = vec![0x01, 0x10, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef];
    valid.extend_from_slice(&[0u8; 8]);
    valid.extend_from_slice(&[0x45u8; 64]);
    let seeds = vec![valid, vec![0u8; 16]];
    let inputs = corpus(SEED ^ 0x55, ITERATIONS, 2_048, &seeds);
    let report = fuzz("relay_client::InboundFrame::parse", &inputs, |b| {
        outcome_of(&twinvpn_relay_client::frame::InboundFrame::parse(
            &Bytes::copy_from_slice(b),
        ))
    });
    assert!(report.reached_accept(), "{report:?}");
    assert!(report.reached_reject(), "{report:?}");
}

#[test]
fn a_relay_datagram_over_the_payload_ceiling_is_refused_before_it_is_retained() {
    let mut over = vec![0x01, 0x10, 0x00, 0x01, 0, 0, 0, 1];
    over.extend_from_slice(&[0u8; 8]);
    over.resize(
        16 + twinvpn_relay_client::frame::MAX_DATA_PAYLOAD_BYTES + 1,
        0x41,
    );
    assert!(
        twinvpn_relay_client::frame::InboundFrame::parse(&Bytes::from(over)).is_err(),
        "the ceiling is checked before the slice is retained"
    );
}

// ---------------------------------------------------------------------------
// Peer-supplied candidates, and the control-plane-supplied DNS policy. Both
// take a decoded message, so the target is the composite an attacker reaches.
// ---------------------------------------------------------------------------

#[test]
fn the_candidate_set_validator_is_total_over_arbitrary_bytes() {
    let seeds = vec![candidate_set().encode_to_vec()];
    let inputs = corpus(SEED ^ 0x66, ITERATIONS, limits::C4_MAX_BYTES, &seeds);
    let report =
        fuzz(
            "path::candidate::validate_set",
            &inputs,
            |b| match twinvpn_schema::validate::decode::<v1::CandidateSet>(b, Channel::PeerDatagram)
            {
                Ok(set) => outcome_of(&twinvpn_path::candidate::validate_set(&set)),
                Err(e) => Outcome::reject(format!("{e:?}")),
            },
        );
    assert!(report.reached_accept(), "{report:?}");
    assert!(report.reached_reject(), "{report:?}");
}

#[test]
fn the_dns_policy_validator_is_total_over_arbitrary_bytes() {
    let seeds = vec![v1::DnsPolicy::default().encode_to_vec()];
    let inputs = corpus(SEED ^ 0x77, ITERATIONS, 4_096, &seeds);
    let report = fuzz(
        "dns::policy::validate",
        &inputs,
        |b| match twinvpn_schema::validate::decode::<v1::DnsPolicy>(b, Channel::ControlAndTelemetry)
        {
            Ok(policy) => outcome_of(&twinvpn_dns::policy::validate(&policy)),
            Err(e) => Outcome::reject(format!("{e:?}")),
        },
    );
    assert!(report.reached_reject(), "{report:?}");
}

// ---------------------------------------------------------------------------
// The resolver's own input: a query name, chosen by whatever asked.
// ---------------------------------------------------------------------------

#[test]
fn the_dns_name_classifier_is_total_over_arbitrary_text() {
    let seeds = vec![
        b"host.twinnet.internal".to_vec(),
        b"1.0.0.10.in-addr.arpa".to_vec(),
        vec![b'.'; 512],
    ];
    let inputs = corpus(SEED ^ 0x88, ITERATIONS, 1_024, &seeds);
    let report = fuzz("dns::classify::wire_labels", &inputs, |b| {
        // A query name arrives as bytes; a non-UTF-8 one is not a name, and the
        // conversion must not be where the panic is either.
        match core::str::from_utf8(b) {
            Ok(name) => {
                let labels = twinvpn_dns::classify::wire_labels(name);
                let reverse = twinvpn_dns::classify::is_twinnet_reverse(&labels);
                Outcome::accept(format!("{}:{reverse}", labels.len()))
            }
            Err(e) => Outcome::reject(format!("{e:?}")),
        }
    });
    assert!(report.reached_accept(), "{report:?}");
}

// ---------------------------------------------------------------------------
// Every fixed-width identifier and address that crosses a wire boundary. These
// are the smallest decoders in the core and the most called: one of them runs
// on every field of every message above.
// ---------------------------------------------------------------------------

#[test]
fn every_wire_boundary_identifier_validator_is_total() {
    let inputs = corpus(
        SEED ^ 0x99,
        ITERATIONS,
        600,
        &[vec![0u8; 32], vec![0u8; 16]],
    );
    let report = fuzz("schema::validate::{identifiers}", &inputs, |b| {
        // Every one of these is reached from a peer-supplied field. A length
        // mismatch must be a typed reject, never a truncation and never a pad.
        let mut fingerprint = String::new();
        macro_rules! probe {
            ($f:path) => {
                fingerprint.push_str(if $f(b).is_ok() { "1" } else { "0" });
            };
        }
        probe!(twinvpn_schema::validate::device_id);
        probe!(twinvpn_schema::validate::identity_id);
        probe!(twinvpn_schema::validate::pairing_id);
        probe!(twinvpn_schema::validate::session_id);
        probe!(twinvpn_schema::validate::tunnel_id);
        probe!(twinvpn_schema::validate::path_id);
        probe!(twinvpn_schema::validate::candidate_id);
        probe!(twinvpn_schema::validate::relay_id);
        probe!(twinvpn_schema::validate::pair_tag);
        probe!(twinvpn_schema::validate::message_id);
        probe!(twinvpn_schema::validate::correlation_id);
        probe!(twinvpn_schema::validate::digest);
        probe!(twinvpn_schema::validate::session_nonce);
        probe!(twinvpn_schema::validate::channel_binding);
        probe!(twinvpn_schema::validate::idempotency_key);
        probe!(twinvpn_schema::validate::causality_token);
        // An all-rejecting input is still a valid outcome; the property is
        // totality, not acceptance.
        if fingerprint.contains('1') {
            Outcome::accept(fingerprint)
        } else {
            Outcome::reject(fingerprint)
        }
    });
    assert!(report.reached_accept(), "{report:?}");
    assert!(report.reached_reject(), "{report:?}");
}

#[test]
fn the_address_family_decoder_never_guesses() {
    // `AddressFamily` is the field ADR-0010 R1 turns on: a decoder that guessed
    // a family would make "we have a v4 story and a v6 story" sayable.
    let inputs: Vec<Vec<u8>> = (-8i32..=8).map(|v| v.to_be_bytes().to_vec()).collect();
    let report = fuzz("schema::validate::address_family", &inputs, |b| {
        let value = i32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        outcome_of(&twinvpn_schema::validate::address_family(value))
    });
    assert_eq!(report.accepted, 2, "exactly IPv4 and IPv6, never a third");
}
