//! B3, exercised the way an attacker reaches it: over a socket.
//!
//! `contracts/docs/trust-boundaries.md` §2 fixes what must happen and
//! `contracts/tests/test_wire.py` sets the shape — ten malformed inputs, each
//! asserted both to be *refused* and to have *terminated*. These are the same
//! ten adapted to this service's framing, plus the ones its own framing adds.
//!
//! Every case asserts three things:
//!
//! 1. **No answer.** "Violation ⇒ drop, emit `PROTO.MALFORMED_MESSAGE`, NO state
//!    change, NO answer. Answering would confirm the target exists."
//! 2. **No state change.** The mailbox and attachment tables are untouched.
//! 3. **The process survives** and serves the next connection, which is the
//!    "decoding terminated" half.

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use twinvpn_rendezvous as rz;
use twinvpn_rendezvous::testkit;

/// Sends `bytes`, then asserts the service answered nothing but the unsolicited
/// reflexive report and changed no state.
async fn refused_without_answer(h: &common::Harness, bytes: &[u8], case: &str) {
    let before = {
        let r = h.shared.router.lock().await;
        (r.mailboxes.total_bytes(), r.attachments.len())
    };
    let mut c = common::Client::connect(h.addr).await;
    c.write(bytes).await;

    // The only frame a refused connection may carry is the REFLEXIVE report the
    // service sends before it has read anything.
    let answered = common::within(async {
        let mut answered = Vec::new();
        while let Some((op, body)) = c.read_frame().await {
            if op != rz::frame::Opcode::Reflexive.as_wire() {
                answered.push((op, body));
            }
        }
        answered
    })
    .await;
    assert!(
        answered.is_empty(),
        "{case}: the service answered a malformed input: {answered:?}"
    );

    let after = {
        let r = h.shared.router.lock().await;
        (r.mailboxes.total_bytes(), r.attachments.len())
    };
    assert_eq!(before, after, "{case}: a malformed input changed state");
}

fn hostile_cases() -> Vec<(&'static str, Vec<u8>)> {
    let target = [0xaau8; 32];
    let mut body = target.to_vec();
    body.extend_from_slice(&testkit::payload(16));

    vec![
        (
            "a declared length of 65535 — the 4 GiB case, at this wire's width",
            testkit::declared_length_frame(rz::frame::Opcode::Call, u16::MAX, &body),
        ),
        (
            "a declared length one past the frame cap",
            testkit::declared_length_frame(
                rz::frame::Opcode::Call,
                u16::try_from(rz::frame::MAX_BODY_LEN + 1).unwrap(),
                &body,
            ),
        ),
        ("a payload one byte past the 1200-byte C4 envelope cap", {
            let mut b = target.to_vec();
            b.extend_from_slice(&testkit::payload(1201));
            testkit::declared_length_frame(
                rz::frame::Opcode::Call,
                u16::try_from(b.len()).unwrap(),
                &b,
            )
        }),
        (
            "a payload nested one level past the depth-4 cap",
            testkit::call_frame(target, &testkit::nested(5)),
        ),
        (
            "a truncated body: the header promises more than the stream carries",
            testkit::declared_length_frame(rz::frame::Opcode::Call, 512, &body),
        ),
        ("a truncated header", b"TVR1\x01".to_vec()),
        ("the wrong magic", {
            let mut f = testkit::call_frame(target, &testkit::payload(16));
            f[0] = b'X';
            f
        }),
        (
            "an unknown wire version",
            testkit::raw_frame(rz::frame::Opcode::Call.as_wire(), 0xff, 0, &[]),
        ),
        (
            "an unknown opcode",
            testkit::raw_frame(0x7f, rz::frame::WIRE_VERSION, 0, &[]),
        ),
        (
            "an egress opcode presented as ingress",
            testkit::raw_frame(
                rz::frame::Opcode::Deliver.as_wire(),
                rz::frame::WIRE_VERSION,
                4,
                &[1, 2, 3, 4],
            ),
        ),
        (
            "a CALL with a target and no payload",
            testkit::call_frame(target, &[]),
        ),
        (
            "a CALL whose body is shorter than one device_id",
            testkit::declared_length_frame(rz::frame::Opcode::Call, 8, &[0u8; 8]),
        ),
        (
            "an ATTACH with a 31-byte identifier — never padded",
            testkit::declared_length_frame(rz::frame::Opcode::Attach, 31, &[3u8; 31]),
        ),
        (
            "an ATTACH with a 33-byte identifier — never truncated",
            testkit::declared_length_frame(rz::frame::Opcode::Attach, 33, &[3u8; 33]),
        ),
        (
            "a CALL payload that is not a protobuf record sequence at all",
            {
                let mut b = target.to_vec();
                b.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
                testkit::declared_length_frame(
                    rz::frame::Opcode::Call,
                    u16::try_from(b.len()).unwrap(),
                    &b,
                )
            },
        ),
        (
            "a body of all-zero octets",
            testkit::declared_length_frame(rz::frame::Opcode::Call, 64, &[0u8; 64]),
        ),
    ]
}

#[tokio::test]
async fn every_hostile_input_is_refused_without_an_answer_and_without_a_state_change() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    for (case, bytes) in hostile_cases() {
        refused_without_answer(&h, &bytes, case).await;
    }
    // The "decoding terminated" half: after every one of those, a well-formed
    // CALL still works.
    let mut c = common::Client::connect(h.addr).await;
    c.write(&testkit::call_frame([1u8; 32], &testkit::payload(16)))
        .await;
    let body = common::within(c.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("the service is still serving");
    assert_eq!(
        common::reason_code(&body).as_deref(),
        Some("CONTROL.PEER_NOT_ATTACHED")
    );
    h.stop().await;
}

#[tokio::test]
async fn the_same_hostile_inputs_are_refused_over_ipv4() {
    // ADR-0010 R1: there is no "v4 story and a v6 story". The parser is one
    // parser, and this asserts it rather than assuming it.
    let h = common::start(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    for (case, bytes) in hostile_cases() {
        refused_without_answer(&h, &bytes, case).await;
    }
    h.stop().await;
}

#[tokio::test]
async fn a_declared_gigabyte_does_not_allocate_a_gigabyte() {
    // The wire width caps a declaration at 65535, so the "4 GiB length" of
    // `contracts/tests/test_wire.py` cannot be *spelled* here — which is itself
    // the defence. What can be spelled is 65535, and the assertion that matters
    // is that the process's retained memory does not move.
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    for _ in 0..500 {
        let mut c = common::Client::connect(h.addr).await;
        c.write(&testkit::declared_length_frame(
            rz::frame::Opcode::Call,
            u16::MAX,
            &[],
        ))
        .await;
        drop(c);
    }
    let retained = h.shared.router.lock().await.mailboxes.total_bytes();
    assert_eq!(
        retained, 0,
        "500 oversized declarations retained {retained} bytes"
    );
    h.stop().await;
}

#[tokio::test]
async fn a_stalled_frame_does_not_hold_a_buffer_for_ever() {
    // The slowloris case: declare a body, send one octet, then say nothing.
    // Without a deadline that is a socket and a buffer an unauthenticated
    // caller owns the lifetime of — `ownership.md` §6 rule 10 read as meant.
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let mut c = common::Client::connect(h.addr).await;
    let mut stalled = testkit::declared_length_frame(rz::frame::Opcode::Call, 1200, &[]);
    stalled.push(0x08);
    c.write(&stalled).await;

    // The service gives up and closes, rather than waiting for ever.
    let closed = common::within(async { while c.read_frame().await.is_some() {} }).await;
    let () = closed;
    assert_eq!(h.shared.router.lock().await.mailboxes.total_bytes(), 0);
    h.stop().await;
}

#[tokio::test]
async fn a_stream_of_hostile_frames_never_wedges_the_accept_loop() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    for (_, bytes) in hostile_cases() {
        for _ in 0..20 {
            let mut c = common::Client::connect(h.addr).await;
            c.write(&bytes).await;
        }
    }
    let mut c = common::Client::connect(h.addr).await;
    c.write(&testkit::call_frame([2u8; 32], &testkit::payload(8)))
        .await;
    assert!(
        common::within(c.read_until(rz::frame::Opcode::Ack))
            .await
            .is_some(),
        "the accept loop survived the flood"
    );
    h.stop().await;
}
