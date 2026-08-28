//! Component tests for `twinvpn_service_common::transport`.
//!
//! Every bound asserted here comes from `contracts/registry/limits.json`.

use bytes::Bytes;
use std::time::{Duration, Instant};
use twinvpn_schema::{Channel, Reject};
use twinvpn_service_common::transport::*;
use twinvpn_types::codes;

#[test]
fn an_over_long_declared_length_is_refused_before_allocation() {
    let e =
        check_declared_length(1_000_000, Channel::ControlAndTelemetry).expect_err("must reject");
    assert!(matches!(
        e,
        Reject::SizeExceeded {
            parser_id: "c1_c2_c7",
            observed: 1_000_000,
            limit: 65_536
        }
    ));
    assert_eq!(e.reason_code(), codes::PROTO_SIZE_EXCEEDED);
}

#[test]
fn c4_carries_the_tighter_bound() {
    assert!(check_declared_length(1201, Channel::PeerDatagram).is_err());
    assert!(check_declared_length(1200, Channel::PeerDatagram).is_ok());
}

#[tokio::test]
async fn read_frame_refuses_a_hostile_declaration_without_reading_it() {
    // A four-byte prefix claiming 4 GiB, followed by nothing. A reader that
    // allocated first would take the process down; this one rejects.
    let bytes = vec![0xff, 0xff, 0xff, 0xff];
    let mut cursor = std::io::Cursor::new(bytes);
    let e = read_frame(&mut cursor, LengthPrefix::U32, Channel::ControlAndTelemetry)
        .await
        .expect_err("must reject");
    assert_eq!(e.reason_code(), codes::PROTO_SIZE_EXCEEDED);
}

#[tokio::test]
async fn read_frame_round_trips_a_valid_frame() {
    let payload = b"hello".to_vec();
    let mut wire = (u32::try_from(payload.len()).unwrap())
        .to_be_bytes()
        .to_vec();
    wire.extend_from_slice(&payload);
    let mut cursor = std::io::Cursor::new(wire);
    let got = read_frame(&mut cursor, LengthPrefix::U32, Channel::ControlAndTelemetry)
        .await
        .expect("valid");
    assert_eq!(got, Bytes::from_static(b"hello"));
}

#[tokio::test]
async fn a_truncated_frame_is_unparseable_not_a_short_read() {
    let mut wire = 10u32.to_be_bytes().to_vec();
    wire.extend_from_slice(b"abc");
    let mut cursor = std::io::Cursor::new(wire);
    let e = read_frame(&mut cursor, LengthPrefix::U32, Channel::ControlAndTelemetry)
        .await
        .expect_err("must reject");
    assert_eq!(e.reason_code(), codes::PROTO_UNPARSEABLE_ENVELOPE);
}

#[test]
fn rung_2_halves_the_watermark_because_tcp_hol_makes_a_backlog_costlier() {
    assert_eq!(BacklogWatermark::for_rung(1), BacklogWatermark::rung1());
    assert_eq!(BacklogWatermark::for_rung(2), BacklogWatermark::rung2());
    assert_eq!(BacklogWatermark::for_rung(4), BacklogWatermark::rung2());
    assert_eq!(
        BacklogWatermark::rung2().max_bytes * 2,
        BacklogWatermark::rung1().max_bytes
    );
    assert_eq!(
        BacklogWatermark::rung2().max_events * 2,
        BacklogWatermark::rung1().max_events
    );
}

#[test]
fn breaching_the_event_watermark_compacts_to_the_highest_net_seq() {
    let mut q = EventQueue::new(BacklogWatermark {
        max_bytes: 1_000_000,
        max_events: 3,
    });
    for seq in 1..=3 {
        assert_eq!(q.push(seq, Bytes::from_static(b"x")), PushOutcome::Queued);
    }
    assert_eq!(
        q.push(4, Bytes::from_static(b"x")),
        PushOutcome::Compacted { up_to_net_seq: 4 }
    );
    assert!(q.is_empty(), "bodies are discarded, the cursor advances");
    assert_eq!(q.compactions(), 1);
    assert_eq!(
        EventQueue::compaction_reason_code(),
        codes::CONTROL_STREAM_COMPACTED
    );
}

#[test]
fn breaching_the_byte_watermark_compacts_too() {
    let mut q = EventQueue::new(BacklogWatermark {
        max_bytes: 16,
        max_events: 1_000_000,
    });
    assert_eq!(q.push(1, Bytes::from(vec![0u8; 10])), PushOutcome::Queued);
    assert_eq!(
        q.push(2, Bytes::from(vec![0u8; 10])),
        PushOutcome::Compacted { up_to_net_seq: 2 }
    );
}

#[test]
fn popping_returns_events_in_order_and_tracks_bytes() {
    let mut q = EventQueue::new(BacklogWatermark::rung1());
    q.push(1, Bytes::from_static(b"aa"));
    q.push(2, Bytes::from_static(b"bbb"));
    assert_eq!(q.queued_bytes(), 5);
    assert_eq!(q.pop().unwrap().0, 1);
    assert_eq!(q.queued_bytes(), 3);
    assert_eq!(q.pop().unwrap().0, 2);
    assert!(q.pop().is_none());
}

#[test]
fn admission_defers_with_a_retry_after_rather_than_dropping() {
    let t0 = Instant::now();
    let mut b = TokenBucket::new(10.0, 2, t0);
    assert_eq!(b.try_admit(t0), Admission::Admitted);
    assert_eq!(b.try_admit(t0), Admission::Admitted);
    match b.try_admit(t0) {
        Admission::Deferred { retry_after_ms } => {
            // 10/s means one token every 100 ms.
            assert_eq!(retry_after_ms, 100);
        }
        Admission::Admitted => panic!("the burst is exhausted"),
    }
    // S-6: the caller has something to say, so a reset or a drop is never
    // the only option available to it.
    assert_eq!(Admission::reason_code(), codes::CONTROL_ADMISSION_DEFERRED);
}

#[test]
fn a_bucket_refills_at_the_sustained_rate_and_no_faster() {
    let t0 = Instant::now();
    let mut b = TokenBucket::new(10.0, 2, t0);
    let _ = b.try_admit(t0);
    let _ = b.try_admit(t0);
    assert!(matches!(b.try_admit(t0), Admission::Deferred { .. }));
    assert_eq!(
        b.try_admit(t0 + Duration::from_millis(100)),
        Admission::Admitted
    );
    // The burst caps the refill: an hour idle still yields only `burst`.
    let mut c = TokenBucket::new(10.0, 2, t0);
    let _ = c.try_admit(t0);
    let _ = c.try_admit(t0);
    let far = t0 + Duration::from_secs(3600);
    assert_eq!(c.try_admit(far), Admission::Admitted);
    assert_eq!(c.try_admit(far), Admission::Admitted);
    assert!(matches!(c.try_admit(far), Admission::Deferred { .. }));
}

#[test]
fn the_write_budget_refuses_rather_than_queues() {
    let t0 = Instant::now();
    let mut w = WriteBudget::frozen_default(t0);
    for _ in 0..20 {
        w.try_write(t0).expect("within the burst");
    }
    assert_eq!(
        w.try_write(t0).expect_err("over budget"),
        codes::CONTROL_EVENT_RATE_EXCEEDED
    );
    // One event per second sustained.
    w.try_write(t0 + Duration::from_secs(1)).expect("refilled");
}

#[test]
fn the_frozen_write_budget_matches_limits_json() {
    // limits.json control_plane.durable_events_per_second_sustained = 1,
    // durable_events_burst = 20.
    let t0 = Instant::now();
    let mut w = WriteBudget::frozen_default(t0);
    let mut admitted = 0;
    while w.try_write(t0).is_ok() {
        admitted += 1;
        assert!(admitted <= 100, "burst must be bounded");
    }
    assert_eq!(admitted, 20);
}

#[test]
fn admission_is_a_pure_function_of_now() {
    let t0 = Instant::now();
    let mut a = TokenBucket::new(1.0, 1, t0);
    let mut b = TokenBucket::new(1.0, 1, t0);
    for step in 0..5 {
        let t = t0 + Duration::from_millis(step * 250);
        assert_eq!(a.try_admit(t), b.try_admit(t), "step {step}");
    }
}
