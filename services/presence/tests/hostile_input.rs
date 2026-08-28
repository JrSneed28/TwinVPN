//! The presence parser under hostile input, over a real socket.
//!
//! Presence is C1, not C4, so the caps are 65536 bytes and depth 8. The rule is
//! the same: validated before any allocation proportional to a declared length,
//! a typed `PROTO.*` reject, and no state change (`ownership.md` §6 rules 9–10).

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use twinvpn_presence as pr;
use twinvpn_presence::frame::{Frame, Opcode};
use twinvpn_presence::testkit;

fn hostile_cases() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "a declared length of 4 GiB",
            testkit::declared_length_frame(Opcode::Publish, u32::MAX, &[]),
        ),
        (
            "a declared length one past the C1 envelope cap",
            testkit::declared_length_frame(
                Opcode::Publish,
                u32::try_from(twinvpn_schema::limits::C1_C2_C7_MAX_BYTES + 1).unwrap(),
                &[],
            ),
        ),
        (
            "a body nested one level past the depth-8 cap",
            pr::frame::encode(Opcode::Publish, &testkit::nested(9)),
        ),
        ("a truncated header", b"TVP1\x01\x02".to_vec()),
        (
            "the wrong magic",
            testkit::raw_frame(Opcode::Publish.as_wire(), pr::frame::WIRE_VERSION, 0, &[])
                .into_iter()
                .enumerate()
                .map(|(i, b)| if i == 0 { b'X' } else { b })
                .collect(),
        ),
        (
            "an unknown wire version",
            testkit::raw_frame(Opcode::Publish.as_wire(), 0xff, 0, &[]),
        ),
        (
            "an unknown opcode",
            testkit::raw_frame(0x40, pr::frame::WIRE_VERSION, 0, &[]),
        ),
        (
            "an egress opcode presented as ingress",
            testkit::raw_frame(Opcode::Event.as_wire(), pr::frame::WIRE_VERSION, 0, &[]),
        ),
        (
            "a BIND of 31 bytes — never padded",
            pr::frame::encode(Opcode::Bind, &[1u8; 31]),
        ),
        (
            "a BIND of 33 bytes — never truncated",
            pr::frame::encode(Opcode::Bind, &[1u8; 33]),
        ),
        (
            "a SUBSCRIBE with a body",
            pr::frame::encode(Opcode::Subscribe, &[1u8; 4]),
        ),
        (
            "a PUBLISH whose body is not a protobuf record sequence",
            pr::frame::encode(Opcode::Publish, &[0xff, 0xff, 0xff, 0xff]),
        ),
        (
            "a truncated body: the header promises more than the stream carries",
            testkit::declared_length_frame(Opcode::Publish, 4096, &[0x08, 0x01]),
        ),
    ]
}

async fn refused_without_state_change(h: &common::Harness, bytes: &[u8], case: &str) {
    let before = h.shared.store.lock().await.len();
    let mut c = h.client().await;
    c.write(bytes).await;
    let answered = common::within(async {
        let mut seen = Vec::new();
        while let Some(f) = c.read_frame().await {
            seen.push(f);
        }
        seen
    })
    .await;
    assert!(answered.is_empty(), "{case}: answered a malformed input");
    assert_eq!(
        before,
        h.shared.store.lock().await.len(),
        "{case}: a malformed input changed state"
    );
}

#[tokio::test]
async fn every_hostile_input_is_refused_without_a_state_change() {
    for host in [
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    ] {
        let h = common::start(host).await;
        for (case, bytes) in hostile_cases() {
            refused_without_state_change(&h, &bytes, case).await;
        }
        // The service is still serving afterwards.
        let device = [0x01u8; 32];
        let mut c = h.client().await;
        c.bind(device).await;
        c.write(&testkit::publish_frame(&testkit::heartbeat(
            device,
            twinvpn_schema::v1::PresenceState::Online,
            pr::server::now_ms() + 60_000,
        )))
        .await;
        let body = common::within(c.read_until(Opcode::Ack))
            .await
            .expect("still serving");
        assert!(common::response(&body).error.is_none());
        h.stop().await;
    }
}

#[tokio::test]
async fn a_declared_four_gigabytes_does_not_allocate_four_gigabytes() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    for _ in 0..500 {
        let mut c = h.client().await;
        c.write(&testkit::declared_length_frame(
            Opcode::Publish,
            u32::MAX,
            &[],
        ))
        .await;
        drop(c);
    }
    assert_eq!(h.shared.store.lock().await.len(), 0);
    h.stop().await;
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// The three-outcome contract, for any byte string.
    #[test]
    fn arbitrary_bytes_produce_an_accept_or_a_typed_reject(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        if let Err(r) = Frame::parse(&bytes) {
            let code = r.reason_code().as_str().to_owned();
            prop_assert!(code.starts_with("PROTO."), "got {code}");
        }
    }

    /// A BIND is accepted at exactly one width.
    #[test]
    fn bind_is_accepted_at_exactly_one_width(len in 0usize..=128) {
        let bytes = pr::frame::encode(Opcode::Bind, &vec![0x5au8; len]);
        prop_assert_eq!(
            Frame::parse(&bytes).is_ok(),
            len == twinvpn_schema::limits::DEVICE_ID_BYTES
        );
    }

    /// A header never admits a declaration past the C1 cap.
    #[test]
    fn a_header_never_admits_a_declaration_past_the_cap(
        header in any::<[u8; pr::frame::HEADER_LEN]>()
    ) {
        if let Ok((_, declared)) = pr::frame::parse_header(&header) {
            prop_assert!(declared <= twinvpn_schema::limits::C1_C2_C7_MAX_BYTES);
        }
    }
}
