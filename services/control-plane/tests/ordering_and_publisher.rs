//! Sole publisher, durability, `net_seq` density, and the monotone refusals.
//!
//! **Authority:** `docs/protocol.md` §6 and §7, `contract-matrix.md` §4,
//! ADR-0002 N-3/N-5/N-8/S-4, ADR-0008 N-1/N-3/N-7, ADR-0009 §11.3 R-2…R-6.

mod common;

use std::time::Duration;

use common::{
    cose, dev, device, key, meta, owner, put_route_request, register, revoke_request, Net,
};
use prost::Message;
use twinvpn_control_plane::event::{Durability, DurableEvent, EphemeralEvent, Publisher};
use twinvpn_control_plane::model::{NetState, StoredEvent};
use twinvpn_control_plane::store::ControlStore;
use twinvpn_control_plane::tx::{NetTx, WriteLease};
use twinvpn_control_plane::{CommandCode, EventKind};
use twinvpn_schema::v1;
use twinvpn_schema::v1::control_event::Event as EventBody;

// ---------------------------------------------------------------------------
// Sole publisher — protocol.md §7, "enforced at the log, not by convention".
// ---------------------------------------------------------------------------

#[test]
fn a_forged_publisher_cannot_reach_the_log_and_leaves_nothing_behind() {
    let mut tx = NetTx::open(NetState::new("tn"), WriteLease { shard_epoch: 1 }, 0).expect("lease");
    let forged = DurableEvent::forged_for_test(
        EventBody::DeviceRevoked(v1::DeviceRevoked::default()),
        Publisher::OriginatingDevice,
    );
    let err = tx.append(&forged).expect_err("refused at the log");
    assert_eq!(err.code().as_str(), "CONTROL.EVENT_WRONG_PUBLISHER");
    assert!(err.code().terminal(), "a security event, not a warning");

    let (journal, state, _) = tx.into_journal();
    assert!(journal.is_empty());
    assert!(state.events.is_empty());
    assert_eq!(
        state.next_net_seq, 1,
        "and no position was consumed, so the log stays dense"
    );
}

#[test]
fn every_event_this_service_appends_carries_the_sole_publisher() {
    let net = Net::new();
    register(&net, 1, 0);
    register(&net, 2, 0);
    net.run(
        dev(1),
        CommandCode::RevokeDevice,
        &revoke_request(2, &key(201)),
        1_000,
        Duration::from_secs(120),
        &owner(),
    )
    .expect("revokes");

    let events = net.events(0).expect("retained");
    assert!(!events.is_empty());
    for e in &events {
        assert_eq!(
            e.publisher,
            Publisher::CoordinationService,
            "{} must have the sole publisher §7 names",
            e.event_type.as_str()
        );
        assert_eq!(
            e.event_type.durability(),
            Durability::Durable,
            "{} reached the log",
            e.event_type.as_str()
        );
    }
}

#[test]
fn a_stored_event_with_a_wrong_publisher_never_reaches_the_wire() {
    // The last check before the octets leave the process.
    use twinvpn_control_plane::session::{Attachment, Rung};
    let mut at = Attachment::new(
        dev(1),
        1,
        Rung::Quic,
        0,
        twinvpn_service_common::Metrics::new(),
    );
    let forged = StoredEvent {
        net_seq: 1,
        event_type: EventKind::PolicyBundleUpdated,
        publisher: Publisher::OriginatingDevice,
        encoded: vec![0u8; 8],
        committed_at_ms: 0,
    };
    let err = at.pump(&[forged]).expect_err("refused");
    assert_eq!(err.code().as_str(), "CONTROL.EVENT_WRONG_PUBLISHER");
}

// ---------------------------------------------------------------------------
// Durability — the SECURITY direction and the PRIVACY direction.
// ---------------------------------------------------------------------------

#[test]
fn a_durable_event_can_never_be_emitted_ephemerally() {
    // contract-matrix.md §1: "a device asleep during a revocation broadcast
    // wakes still trusting a stolen laptop, and nothing will ever correct it."
    for body in [
        EventBody::DeviceRevoked(v1::DeviceRevoked::default()),
        EventBody::PolicyBundleUpdated(v1::PolicyBundleUpdated::default()),
        EventBody::PairingApproved(v1::PairingApproved::default()),
        EventBody::PeerRemoved(v1::PeerRemoved::default()),
        EventBody::StreamCompacted(v1::StreamCompacted::default()),
    ] {
        let kind = EventKind::of_body(&body);
        assert_eq!(kind.durability(), Durability::Durable, "{}", kind.as_str());
        assert!(
            EphemeralEvent::new(body).is_err(),
            "{} must not be expressible as ephemeral",
            kind.as_str()
        );
    }
}

#[test]
fn an_ephemeral_event_can_never_be_written_to_the_log() {
    // The other direction: durable presence is "a permanent movement and IP
    // history of the Owner", and draining it delays the one DeviceRevoked that
    // matters.
    for body in [
        EventBody::PresenceUpdated(v1::PresenceUpdated::default()),
        EventBody::RelayAssignmentHint(v1::RelayAssignmentHint::default()),
        EventBody::LogHead(v1::LogHead::default()),
        EventBody::StateDocumentAvailable(v1::StateDocumentAvailable::default()),
    ] {
        let kind = EventKind::of_body(&body);
        assert_eq!(
            kind.durability(),
            Durability::Ephemeral,
            "{}",
            kind.as_str()
        );
        assert!(
            DurableEvent::new(body).is_err(),
            "{} must not be expressible as durable",
            kind.as_str()
        );
    }
}

#[test]
fn presence_appends_nothing_and_carries_net_seq_zero() {
    let net = Net::new();
    register(&net, 1, 0);
    let before = net.head();

    let out = net
        .run(
            dev(1),
            CommandCode::PublishPresence,
            &v1::PublishPresenceRequest {
                metadata: meta(&[]),
                heartbeat: Some(v1::Heartbeat::default()),
            }
            .encode_to_vec(),
            1_000,
            Duration::from_secs(60),
            &owner(),
        )
        .expect("publishes");

    assert_eq!(net.head(), before, "REGISTER class appends nothing durable");
    assert!(out.appended.is_empty());
    assert_eq!(out.ephemeral.len(), 1);
    let wire = out.ephemeral[0].to_wire(
        common::TWINNET,
        1_000,
        &twinvpn_service_common::Correlation::empty(),
    );
    assert_eq!(
        wire.metadata.expect("metadata").net_seq,
        0,
        "ADR-0002 N-9: an ephemeral event has no log position"
    );
    assert_eq!(wire.durability, Durability::Ephemeral.to_wire());
    let _ = cose(0);
}

// ---------------------------------------------------------------------------
// net_seq — allocated inside the transaction, dense, and never reused.
// ---------------------------------------------------------------------------

#[test]
fn net_seq_is_dense_and_strictly_increasing_across_commands() {
    let net = Net::new();
    register(&net, 1, 0);
    register(&net, 2, 0);
    register(&net, 3, 0);
    net.run(
        dev(1),
        CommandCode::RevokeDevice,
        &revoke_request(3, &key(203)),
        5_000,
        Duration::from_secs(240),
        &owner(),
    )
    .expect("revokes");

    let seqs: Vec<u64> = net
        .events(0)
        .expect("retained")
        .into_iter()
        .map(|e| e.net_seq)
        .collect();
    assert_eq!(
        seqs,
        (1..=seqs.len() as u64).collect::<Vec<_>>(),
        "dense and monotone per TwinNet"
    );
    assert_eq!(net.head(), *seqs.last().expect("events"));
}

#[test]
fn a_mutating_response_names_the_position_its_effect_committed_at() {
    // ADR-0002 N-3 / E-2: `committed_at_net_seq` is a real position in the SAME
    // log the device reads on C2, and the client must not report the operation
    // complete until its cursor reaches it.
    let net = Net::new();
    let out = register(&net, 1, 0);
    assert!(out.committed_at_net_seq > 0);
    let events = net.events(out.committed_at_net_seq - 1).expect("retained");
    assert_eq!(events[0].net_seq, out.committed_at_net_seq);
    assert_eq!(events[0].event_type, EventKind::DeviceRegistered);

    let resp = v1::RegisterDeviceResponse::decode(out.response.as_slice()).expect("decodes");
    let result = resp.result.expect("MutationResult");
    assert_eq!(result.committed_at_net_seq, out.committed_at_net_seq);
}

// ---------------------------------------------------------------------------
// Monotone refusals.
// ---------------------------------------------------------------------------

#[test]
fn an_advertisement_epoch_that_does_not_strictly_advance_is_refused() {
    let net = Net::new();
    register(&net, 1, 0);
    net.run(
        dev(1),
        CommandCode::PutRouteAdvertisement,
        &put_route_request(1, 5),
        1_000,
        Duration::from_secs(120),
        &device(),
    )
    .expect("advertises");

    for stale in [5u64, 4, 1] {
        let err = net
            .run(
                dev(1),
                CommandCode::PutRouteAdvertisement,
                &put_route_request(1, stale),
                2_000,
                Duration::from_secs(180),
                &device(),
            )
            .expect_err("a reused epoch is a delta in disguise");
        assert_eq!(err.code().as_str(), "AUTH.TRUST_EPOCH_ROLLBACK");
    }

    // A withdrawal is a HIGHER epoch with an empty set, so it cannot be
    // reordered ahead of the advertisement it withdraws.
    net.run(
        dev(1),
        CommandCode::WithdrawRouteAdvertisement,
        &v1::WithdrawRouteAdvertisementRequest {
            metadata: meta(&[]),
            advertiser_device_id: dev(1).to_vec(),
            advertisement_epoch: 6,
            signed: Some(cose(1)),
        }
        .encode_to_vec(),
        3_000,
        Duration::from_secs(240),
        &device(),
    )
    .expect("withdraws");
}

#[test]
fn a_device_cannot_advertise_another_devices_routes() {
    // S-16: "the advertiser is the single writer". A second writer for one row
    // is the I8 violation, and a control plane that could mint a route "could
    // redirect an Owner's traffic for a subnet to an attacker-controlled
    // device".
    let net = Net::new();
    register(&net, 1, 0);
    register(&net, 2, 0);
    let err = net
        .run(
            dev(1),
            CommandCode::PutRouteAdvertisement,
            &put_route_request(2, 1),
            1_000,
            Duration::from_secs(120),
            &device(),
        )
        .expect_err("not the advertiser");
    assert_eq!(err.code().as_str(), "AUTH.PEER_UNTRUSTED");
}

#[test]
fn an_advertisement_that_verified_against_the_owner_chain_is_refused() {
    // The Rule-B property, at the server: coordination must not be able to mint
    // a route by presenting one the Owner signed.
    let net = Net::new();
    register(&net, 1, 0);
    let err = net
        .run(
            dev(1),
            CommandCode::PutRouteAdvertisement,
            &put_route_request(1, 1),
            1_000,
            Duration::from_secs(120),
            &owner(),
        )
        .expect_err("wrong authority");
    assert_eq!(err.code().as_str(), "AUTH.UNEXPECTED_DELEGATION");
}

#[test]
fn the_revoked_set_never_shrinks_and_the_epoch_never_decreases() {
    let net = Net::new();
    register(&net, 1, 0);
    register(&net, 2, 0);
    assert_eq!(net.trust_epoch(), 0);

    net.run(
        dev(1),
        CommandCode::RevokeDevice,
        &revoke_request(2, &key(202)),
        1_000,
        Duration::from_secs(120),
        &owner(),
    )
    .expect("revokes");
    assert_eq!(net.trust_epoch(), 1);

    // Re-revoking under a fresh key is a no-op: the epoch does not advance
    // twice for one device (ADR-0008 N-7).
    net.run(
        dev(1),
        CommandCode::RevokeDevice,
        &revoke_request(2, &key(203)),
        2_000,
        Duration::from_secs(180),
        &owner(),
    )
    .expect("no-op");
    assert_eq!(net.trust_epoch(), 1, "re-revoking is a no-op");

    let state = net.store.snapshot(common::TWINNET).expect("net");
    assert!(state.is_revoked(&dev(2)));
    assert!(
        state.devices.get(&dev(2)).expect("row").revoked,
        "false -> true only; there is no API that could reverse it"
    );
}

#[test]
fn a_revoked_device_is_refused_and_disappears_from_the_peer_set() {
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

    // architecture.md §4.5 item 1: enforcement is at the peer, and PeerRemoved
    // is what removes it from every other device's cached view.
    assert!(net.event_types().contains(&EventKind::PeerRemoved));

    let err = net
        .run(
            dev(2),
            CommandCode::DiscoverPeers,
            &v1::DiscoverPeersRequest {
                metadata: meta(&[]),
                since_net_seq: 0,
            }
            .encode_to_vec(),
            2_000,
            Duration::from_secs(180),
            &owner(),
        )
        .expect_err("revoked");
    assert_eq!(err.code().as_str(), "AUTH.DEVICE_REVOKED");
    assert!(err.code().terminal());

    // And a re-snapshot by a live device cannot re-learn the revoked peer.
    let out = net
        .run(
            dev(1),
            CommandCode::DiscoverPeers,
            &v1::DiscoverPeersRequest {
                metadata: meta(&[]),
                since_net_seq: 0,
            }
            .encode_to_vec(),
            2_000,
            Duration::from_secs(180),
            &owner(),
        )
        .expect("discovers");
    let resp = v1::DiscoverPeersResponse::decode(out.response.as_slice()).expect("decodes");
    assert!(
        resp.peers
            .iter()
            .all(|p| p.peer_device_id != dev(2).to_vec()),
        "a re-snapshot must not resurrect a revoked peer"
    );
    assert_eq!(resp.revocation_epoch, 1);
}

#[test]
fn a_lease_less_writer_is_refused_rather_than_writing_optimistically() {
    // ADR-0002 N-4 / ADR-0009 §11.2: "a superseded writer's appends are
    // refused." Never reconciled afterwards.
    let store = twinvpn_control_plane::store::mem::MemStore::fenced_out(9);
    store.seed_shard_epoch(common::TWINNET, 9);
    let err = futures::executor::block_on(store.execute(twinvpn_control_plane::store::Request {
        twinnet_id: common::TWINNET,
        caller: dev(1),
        now_ms: 0,
        now: std::time::Instant::now(),
        verifier: &owner(),
        quorum_available: true,
        correlation: twinvpn_service_common::Correlation::empty(),
        coordination_endpoints: &[],
        code: CommandCode::RegisterDevice,
        body: &common::register_request(1, &key(1)),
    }))
    .expect_err("fenced out");
    assert_eq!(err.code().as_str(), "CONTROL.WRITE_LEADER_UNAVAILABLE");
    assert!(
        store
            .snapshot(common::TWINNET)
            .expect("net")
            .events
            .is_empty(),
        "and nothing was written optimistically"
    );
}

#[test]
fn an_e1_class_write_without_quorum_is_refused_never_partially_applied() {
    // ADR-0002 §11.3: "never committed locally with a promise to reconcile,
    // because a forked revocation history is exactly what E-1 forbids."
    let net = Net::new();
    for code in [
        CommandCode::RegisterDevice,
        CommandCode::RevokeDevice,
        CommandCode::CompletePairing,
        CommandCode::PutPolicy,
    ] {
        let body = match code {
            CommandCode::RegisterDevice => common::register_request(1, &key(1)),
            CommandCode::RevokeDevice => revoke_request(2, &key(2)),
            CommandCode::CompletePairing => common::complete_pairing_request(9, &key(3), 1, 1),
            _ => common::put_policy_request(1, 0, &key(4), 1),
        };
        let err = net
            .run_without_quorum(dev(1), code, &body, 0, &owner())
            .expect_err("quorum unavailable");
        assert_eq!(err.code().as_str(), "CONTROL.QUORUM_UNAVAILABLE");
    }
    assert_eq!(net.head(), 0, "nothing was partially applied");
    assert_eq!(net.trust_epoch(), 0);
}

// ---------------------------------------------------------------------------
// Correlation across the C1 -> C2 boundary.
// ---------------------------------------------------------------------------

#[test]
fn an_event_carries_the_causation_of_the_request_that_produced_it() {
    // ownership.md §6 rule 6: correlation_id and causation_id survive every
    // component boundary. C1 -> C2 is the seam where a trace is normally lost —
    // the event is emitted after the response that caused it has returned.
    //
    // common.proto's worked example is exactly this shape: causation set,
    // correlation ABSENT. An event is not a *reply* to the request that caused
    // it, and a correlation_id would tell every other device in the TwinNet that
    // this event answers a message they never sent.
    let net = Net::new();
    let message_id = vec![0x5au8; 16];
    let mut req =
        v1::RegisterDeviceRequest::decode(common::register_request(1, &key(1)).as_slice())
            .expect("decodes");
    if let Some(md) = req.metadata.as_mut() {
        md.message_id.clone_from(&message_id);
    }

    let out = net
        .run(
            dev(1),
            CommandCode::RegisterDevice,
            &req.encode_to_vec(),
            0,
            Duration::from_secs(0),
            &owner(),
        )
        .expect("registers");

    assert_eq!(out.appended.len(), 1);
    let wire = v1::ControlEvent::decode(out.appended[0].encoded.as_slice()).expect("decodes");
    let md = wire.metadata.expect("metadata");
    assert_eq!(
        md.causation_id, message_id,
        "the trace crosses the boundary"
    );
    assert!(
        md.correlation_id.is_empty(),
        "an event is a consequence, not a reply"
    );
    assert_eq!(md.twinnet_id, common::TWINNET);
    assert_eq!(md.net_seq, out.committed_at_net_seq);
}

#[test]
fn a_malformed_correlation_id_is_a_typed_reject_not_a_dropped_trace() {
    let net = Net::new();
    let mut req =
        v1::RegisterDeviceRequest::decode(common::register_request(1, &key(1)).as_slice())
            .expect("decodes");
    if let Some(md) = req.metadata.as_mut() {
        md.message_id = vec![0u8; 15]; // limits.json identifiers.message_id_bytes = 16
    }
    let err = net
        .run(
            dev(1),
            CommandCode::RegisterDevice,
            &req.encode_to_vec(),
            0,
            Duration::from_secs(0),
            &owner(),
        )
        .expect_err("wrong width");
    assert_eq!(err.code().as_str(), "PROTO.MALFORMED_MESSAGE");
}
