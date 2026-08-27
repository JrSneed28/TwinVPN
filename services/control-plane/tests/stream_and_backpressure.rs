//! Cursor resume, compaction announced in band, the write budget, and the
//! attach discipline.
//!
//! **Authority:** ADR-0002 §11.6 (the watermark, the write budget, the priority
//! rule), §11.7 (the accept limiter, "resume, do not reload"), N-1, N-8;
//! `contract-matrix.md` §5.

mod common;

use std::time::Duration;

use common::{dev, key, meta, owner, register, revoke_request, Net};
use prost::Message;
use twinvpn_control_plane::session::{AcceptLimiter, Attachment, Attachments, Pumped, Rung};
use twinvpn_control_plane::CommandCode;
use twinvpn_schema::v1;
use twinvpn_service_common::Metrics;

fn subscribe(net: &Net, caller: u8, from: u64) -> Result<v1::SubscribeEventsResponse, String> {
    net.run(
        dev(caller),
        CommandCode::SubscribeEvents,
        &v1::SubscribeEventsRequest {
            metadata: meta(&[]),
            from_net_seq: from,
        }
        .encode_to_vec(),
        9_000,
        Duration::from_secs(600),
        &owner(),
    )
    .map(|c| v1::SubscribeEventsResponse::decode(c.response.as_slice()).expect("decodes"))
    .map_err(|e| e.code().as_str().to_owned())
}

#[test]
fn a_cursor_inside_the_retention_floor_resumes_rather_than_reloads() {
    // ADR-0002 §11.7 rule 4: "Re-snapshotting on every reconnect is PROHIBITED —
    // it converts a reconnect storm into a bandwidth storm."
    let net = Net::new();
    register(&net, 1, 0);
    register(&net, 2, 0);
    register(&net, 3, 0);

    let resp = subscribe(&net, 1, 2).expect("resumes");
    assert_eq!(resp.current_net_seq, net.head());
    let delta = net.events(2).expect("retained");
    assert!(
        delta.iter().all(|e| e.net_seq > 2),
        "the stream continues from the cursor"
    );
    assert_eq!(delta.len(), net.head() as usize - 2);
}

#[test]
fn a_cursor_below_the_retention_floor_is_refused_with_the_floor_named() {
    // The device must be TOLD to re-snapshot, not silently handed a gap.
    let net = Net::new();
    for id in 1..=5u8 {
        register(&net, id, 0);
    }
    net.store.compact_below(common::TWINNET, 4);

    assert_eq!(
        subscribe(&net, 1, 1).expect_err("below the floor"),
        "CONTROL.CURSOR_TOO_OLD"
    );
    let err = net.events(1).expect_err("below the floor");
    assert_eq!(err.code().as_str(), "CONTROL.CURSOR_TOO_OLD");
    assert!(
        twinvpn_control_plane::codes::carries(&err, &["cursor", "retention_floor"]),
        "the device is told WHERE the floor is"
    );

    // At the floor it resumes normally.
    assert!(subscribe(&net, 1, 3).is_ok());
}

#[test]
fn a_breached_backlog_announces_the_gap_and_never_omits_it() {
    // ADR-0002 N-8: "SILENT OMISSION IS PROHIBITED."
    let mut at = Attachment::new(dev(1), 1, Rung::Quic, 0, Metrics::new());
    let (max_bytes, _) = (Rung::Quic.watermark().max_bytes, 0);
    let big = max_bytes / 3 + 1;
    let events: Vec<twinvpn_control_plane::model::StoredEvent> = (1..=6)
        .map(|n| twinvpn_control_plane::model::StoredEvent {
            net_seq: n,
            event_type: twinvpn_control_plane::EventKind::DeviceRegistered,
            publisher: twinvpn_control_plane::Publisher::CoordinationService,
            encoded: vec![0u8; big],
            committed_at_ms: 0,
        })
        .collect();

    match at.pump(&events).expect("pumps") {
        Pumped::Compacted { up_to_net_seq } => {
            assert!(up_to_net_seq >= 1);
            assert_eq!(
                at.cursor(),
                up_to_net_seq,
                "the device resumes from the announced position"
            );
        }
        Pumped::Records(_) => panic!("the watermark must have been breached"),
    }
}

#[test]
fn the_tcp_rungs_halve_the_watermark_because_head_of_line_blocking_costs_more() {
    let quic = Rung::Quic.watermark();
    let tcp = Rung::Tcp.watermark();
    assert_eq!(tcp.max_bytes * 2, quic.max_bytes);
    assert_eq!(tcp.max_events * 2, quic.max_events);
    assert_eq!(quic.max_bytes, 262_144, "the frozen limits.json value");
    assert_eq!(quic.max_events, 512);
}

#[test]
fn the_per_twinnet_write_budget_refuses_a_flood_rather_than_queueing_it() {
    // ADR-0002 §11.6: 1/s sustained, burst 20, and "a queued over-budget write
    // is the flood, delayed".
    let net = Net::new();
    register(&net, 1, 0);
    register(&net, 2, 0);

    // Twenty durable writes at one instant exhaust the burst; the next is
    // REFUSED, not deferred into a queue.
    let mut refused = None;
    for n in 0..40u8 {
        let r = net.run(
            dev(1),
            CommandCode::PutRouteAdvertisement,
            &common::put_route_request(1, u64::from(n) + 1),
            1_000,
            Duration::from_secs(300),
            &common::device(),
        );
        if let Err(e) = r {
            refused = Some(e);
            break;
        }
    }
    let err = refused.expect("the budget must engage");
    assert_eq!(err.code().as_str(), "CONTROL.EVENT_RATE_EXCEEDED");
}

#[test]
fn a_read_is_never_charged_against_the_durable_write_budget() {
    // Reads and presence append nothing, so charging them would make a device
    // polling its own peer set look like a log flood.
    let net = Net::new();
    register(&net, 1, 0);
    for n in 0..200 {
        net.run(
            dev(1),
            CommandCode::DiscoverPeers,
            &v1::DiscoverPeersRequest {
                metadata: meta(&[]),
                since_net_seq: 0,
            }
            .encode_to_vec(),
            1_000 + n,
            Duration::from_secs(300),
            &owner(),
        )
        .expect("a read is never rate-limited by the WRITE budget");
    }
}

#[test]
fn a_ceremony_retry_is_not_charged_against_the_write_budget() {
    // A retry of a ceremony that already committed appends nothing, so charging
    // it would make a client's CORRECT retry behaviour look like a flood.
    let net = Net::new();
    register(&net, 1, 0);
    for n in 0..100 {
        let out = net
            .run(
                dev(1),
                CommandCode::RegisterDevice,
                &common::register_request(1, &key(1)),
                2_000 + n,
                Duration::from_secs(120),
                &owner(),
            )
            .expect("a replay costs nothing");
        assert!(out.idempotent_replay);
    }
}

#[test]
fn a_second_attach_supersedes_the_older_connection() {
    // ADR-0002 N-1.
    let attachments = Attachments::new();
    let first = attachments.attach(dev(1));
    let second = attachments.attach(dev(1));
    assert!(second.superseded_previous);
    assert!(!attachments.is_current(&dev(1), first.epoch));
    assert!(attachments.is_current(&dev(1), second.epoch));
}

#[test]
fn an_over_limit_attach_is_deferred_with_a_number_never_reset_or_dropped() {
    // ADR-0002 §11.7 rule 3 / S-6.
    let now = std::time::Instant::now();
    let limiter = AcceptLimiter::new(200.0, 2, now);
    assert!(limiter.admit(now).is_ok());
    assert!(limiter.admit(now).is_ok());
    let err = limiter.admit(now).expect_err("burst exhausted");
    assert_eq!(err.code().as_str(), "CONTROL.ADMISSION_DEFERRED");
    assert!(twinvpn_control_plane::codes::carries(
        &err,
        &["retry_after_ms"]
    ));
    assert!(!err.code().terminal(), "a deferral is transient");
}

#[test]
fn the_attach_response_carries_the_revocation_epoch_before_any_event_body() {
    // ADR-0002 §11.6: the security-critical fact arrives in RTT 1 regardless of
    // queue depth.
    let net = Net::new();
    register(&net, 1, 0);
    register(&net, 2, 0);
    net.run(
        dev(1),
        CommandCode::RevokeDevice,
        &revoke_request(2, &key(202)),
        1_000,
        Duration::from_secs(120),
        &owner(),
    )
    .expect("revokes");

    let resp = subscribe(&net, 1, 0).expect("attaches");
    assert_eq!(resp.revocation_epoch, 1);
    assert_eq!(resp.current_net_seq, net.head());
}

#[test]
fn every_c1_response_carries_the_revocation_epoch() {
    // "Carried on EVERY C1 response so a device detects it is behind without
    // draining the log."
    let net = Net::new();
    register(&net, 1, 0);
    register(&net, 2, 0);
    net.run(
        dev(1),
        CommandCode::RevokeDevice,
        &revoke_request(2, &key(202)),
        1_000,
        Duration::from_secs(120),
        &owner(),
    )
    .expect("revokes");

    let out = net
        .run(
            dev(1),
            CommandCode::PutRouteAdvertisement,
            &common::put_route_request(1, 1),
            2_000,
            Duration::from_secs(180),
            &common::device(),
        )
        .expect("advertises");
    let resp = v1::PutRouteAdvertisementResponse::decode(out.response.as_slice()).expect("decodes");
    assert_eq!(resp.result.expect("result").revocation_epoch, 1);

    let out = net
        .run(
            dev(1),
            CommandCode::DiscoverPeers,
            &v1::DiscoverPeersRequest {
                metadata: meta(&[]),
                since_net_seq: 0,
            }
            .encode_to_vec(),
            3_000,
            Duration::from_secs(240),
            &owner(),
        )
        .expect("discovers");
    let resp = v1::DiscoverPeersResponse::decode(out.response.as_slice()).expect("decodes");
    assert_eq!(resp.revocation_epoch, 1);
}

#[test]
fn a_hostile_frame_is_bounded_before_anything_is_allocated() {
    use twinvpn_control_plane::wire::{C1Frame, CommandCode as Code};
    let header = [0x00, 0x0c, 0xff, 0xff, 0xff, 0xff];
    let err = C1Frame::parse_header(&header).expect_err("over cap");
    assert_eq!(err.reason_code().as_str(), "PROTO.SIZE_EXCEEDED");

    // And an over-cap body reaching dispatch is refused there too, before any
    // handler sees it.
    let net = Net::new();
    let err = net
        .run(
            dev(1),
            Code::DiscoverPeers,
            &vec![0u8; 65_537],
            0,
            Duration::from_secs(0),
            &owner(),
        )
        .expect_err("over cap");
    assert_eq!(err.code().as_str(), "PROTO.SIZE_EXCEEDED");
}
