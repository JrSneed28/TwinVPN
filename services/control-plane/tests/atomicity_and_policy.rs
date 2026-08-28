//! The mutation and its event commit together, and only the `Owner` authors
//! policy.
//!
//! **Authority:** `contract-matrix.md` §5 ("control plane → durable log:
//! exactly-once … same transaction as the mutation; **no dual write exists to be
//! lost**"), ADR-0002 N-3; `policy.proto` ("the control plane WAREHOUSES AND
//! DISTRIBUTES; IT CANNOT AUTHOR"); ADR-0009 §11.3 R-2…R-5.

mod common;

use std::time::Duration;

use common::{
    cose_at_version, dev, device, key, meta, mismatched_policy_request, mismatched_revoke_request,
    owner, put_policy_request, register, Net, NO_ANCHOR,
};
use prost::Message;
use twinvpn_control_plane::event::DurableEvent;
use twinvpn_control_plane::model::{DocumentType, NetState};
use twinvpn_control_plane::tx::{NetTx, WriteLease};
use twinvpn_control_plane::{CommandCode, EventKind};
use twinvpn_schema::v1;
use twinvpn_schema::v1::control_event::Event as EventBody;

// ---------------------------------------------------------------------------
// The crash between the mutation and its event.
// ---------------------------------------------------------------------------

#[test]
fn a_transaction_abandoned_after_the_mutation_loses_the_mutation_too() {
    // There is no interval in which one half is durable and the other is not.
    // The transaction is dropped WITHOUT `into_journal`, which is the crash.
    let base = NetState::new("tn");
    {
        let mut tx =
            NetTx::open(base.clone(), WriteLease { shard_epoch: 1 }, 1_000).expect("lease");
        tx.revoke(dev(2));
        tx.append(
            &DurableEvent::new(EventBody::DeviceRevoked(v1::DeviceRevoked::default()))
                .expect("durable"),
        )
        .expect("appends");
        // …and the process dies here.
    }
    assert!(base.revoked.is_empty(), "the mutation did not land");
    assert!(base.events.is_empty(), "and neither did its event");
    assert_eq!(base.trust_epoch, 0);
    assert_eq!(base.next_net_seq, 1, "no position was burnt");
}

#[test]
fn a_handler_that_fails_after_appending_leaves_no_event_behind() {
    // The same property through the real store: `PutPolicy` appends only after
    // `put_document` has accepted, and a refusal anywhere leaves the log clean.
    let net = Net::new();
    register(&net, 1, 0);
    let head_before = net.head();

    // A rollback: version 1 accepted, then version 1 again with DIFFERENT
    // content — ADR-0009 R-4's fork, refused at the writer.
    net.run(
        dev(1),
        CommandCode::PutPolicy,
        &put_policy_request(1, 0, &key(50), 0xaa),
        1_000,
        Duration::from_secs(120),
        &owner(),
    )
    .expect("first bundle");
    let head_after_first = net.head();
    assert!(head_after_first > head_before);

    let err = net
        .run(
            dev(1),
            CommandCode::PutPolicy,
            &put_policy_request(1, 1, &key(51), 0xbb),
            2_000,
            Duration::from_secs(180),
            &owner(),
        )
        .expect_err("a fork");
    assert_eq!(err.code().as_str(), "AUTH.TRUST_HISTORY_FORKED");
    assert!(err.code().terminal(), "a security event");
    assert_eq!(
        net.head(),
        head_after_first,
        "a refused write appends nothing"
    );

    let state = net.store.snapshot(common::TWINNET).expect("net");
    let held = state
        .documents
        .get(&DocumentType::PolicyBundle)
        .expect("the first bundle is still the one held");
    assert_eq!(held.version, 1);
    assert_eq!(state.policy_version, 1);
}

#[test]
fn the_dedup_record_and_the_effect_land_in_the_same_transaction() {
    // A dedup record written after the effect is a dual write, and the crash
    // between them loses exactly the record a retry needs.
    let net = Net::new();
    register(&net, 1, 0);
    let state = net.store.snapshot(common::TWINNET).expect("net");
    assert!(
        state.idempotency.contains_key(&(dev(1), key(1))),
        "the dedup record committed with the registration"
    );
    assert!(
        state.devices.contains_key(&dev(1)),
        "and so did the membership row"
    );
    assert_eq!(state.events.len(), 1);
}

// ---------------------------------------------------------------------------
// Policy authority.
// ---------------------------------------------------------------------------

#[test]
fn a_policy_bundle_signed_by_a_device_is_not_a_policy_bundle() {
    // policy.proto: AUTHORED by the Owner authority. A control plane that could
    // admit a device-signed bundle would be a second policy author.
    let net = Net::new();
    register(&net, 1, 0);
    let err = net
        .run(
            dev(1),
            CommandCode::PutPolicy,
            &put_policy_request(1, 0, &key(60), 1),
            1_000,
            Duration::from_secs(120),
            &device(),
        )
        .expect_err("wrong authority");
    assert_eq!(err.code().as_str(), "AUTH.UNEXPECTED_DELEGATION");
    assert_eq!(
        net.store
            .snapshot(common::TWINNET)
            .expect("net")
            .policy_version,
        0
    );
}

#[test]
fn an_unsigned_policy_bundle_is_refused() {
    let net = Net::new();
    register(&net, 1, 0);
    let mut req = v1::PutPolicyRequest::decode(put_policy_request(1, 0, &key(61), 1).as_slice())
        .expect("decodes");
    if let Some(b) = req.bundle.as_mut() {
        b.signed = None;
    }
    let err = net
        .run(
            dev(1),
            CommandCode::PutPolicy,
            &req.encode_to_vec(),
            1_000,
            Duration::from_secs(120),
            &owner(),
        )
        .expect_err("unsigned");
    assert_eq!(err.code().as_str(), "AUTH.BINDING_INVALID");
}

#[test]
fn a_policy_bundle_is_refused_outright_with_no_anchor_bound() {
    let net = Net::new();
    register(&net, 1, 0);
    let err = net
        .run(
            dev(1),
            CommandCode::PutPolicy,
            &put_policy_request(1, 0, &key(62), 1),
            1_000,
            Duration::from_secs(120),
            &NO_ANCHOR,
        )
        .expect_err("no anchor");
    assert_eq!(err.code().as_str(), "AUTH.KEY_UNAVAILABLE");
}

#[test]
fn a_policy_write_without_a_precondition_is_refused() {
    // ADR-0008 N-2: EVERY mutating request is conditional. An unconditional
    // write is the lost update the mechanism exists to stop.
    let net = Net::new();
    register(&net, 1, 0);
    let mut req = v1::PutPolicyRequest::decode(put_policy_request(1, 0, &key(63), 1).as_slice())
        .expect("decodes");
    req.precondition = None;
    let err = net
        .run(
            dev(1),
            CommandCode::PutPolicy,
            &req.encode_to_vec(),
            1_000,
            Duration::from_secs(120),
            &owner(),
        )
        .expect_err("unconditional");
    assert_eq!(err.code().as_str(), "AUTH.TRUST_EPOCH_ROLLBACK");
}

#[test]
fn a_policy_rollback_is_refused_and_the_held_version_does_not_move() {
    let net = Net::new();
    register(&net, 1, 0);
    for (version, precondition, k) in [(1u64, 0u64, 70u8), (2, 1, 71), (3, 2, 72)] {
        net.run(
            dev(1),
            CommandCode::PutPolicy,
            &put_policy_request(version, precondition, &key(k), version as u8),
            version * 1_000,
            Duration::from_secs(120 + version * 60),
            &owner(),
        )
        .expect("accepted");
    }
    assert_eq!(
        net.store
            .snapshot(common::TWINNET)
            .expect("net")
            .policy_version,
        3
    );

    // A replayed older bundle "silently reopens an authorization hole".
    let err = net
        .run(
            dev(1),
            CommandCode::PutPolicy,
            &put_policy_request(2, 3, &key(73), 2),
            9_000,
            Duration::from_secs(600),
            &owner(),
        )
        .expect_err("rollback");
    assert_eq!(err.code().as_str(), "AUTH.TRUST_EPOCH_ROLLBACK");
    assert_eq!(
        net.store
            .snapshot(common::TWINNET)
            .expect("net")
            .policy_version,
        3
    );
}

#[test]
fn the_policy_bundle_is_warehoused_verbatim_and_pullable() {
    // ADR-0002 §11.4: pull is ALWAYS sufficient. The octets served are the ones
    // that arrived, not a re-encoding.
    let net = Net::new();
    register(&net, 1, 0);
    net.run(
        dev(1),
        CommandCode::PutPolicy,
        &put_policy_request(1, 0, &key(80), 0x5a),
        1_000,
        Duration::from_secs(120),
        &owner(),
    )
    .expect("accepted");

    let out = net
        .run(
            dev(1),
            CommandCode::GetStateDocument,
            &v1::GetStateDocumentRequest {
                metadata: meta(&[]),
                doc_type: DocumentType::PolicyBundle.to_wire(),
                version: 0,
            }
            .encode_to_vec(),
            2_000,
            Duration::from_secs(180),
            &owner(),
        )
        .expect("pulls");
    let resp = v1::GetStateDocumentResponse::decode(out.response.as_slice()).expect("decodes");
    let document = resp.document.expect("document");
    assert_eq!(
        document.cose_sign1,
        cose_at_version(0x5a, 1).cose_sign1,
        "the received octets, byte for byte"
    );
    let reference = resp.reference.expect("reference");
    assert_eq!(reference.version, 1);
    assert_eq!(
        reference.size_bytes,
        cose_at_version(0x5a, 1).cose_sign1.len() as u64
    );

    // A version this shard does not hold is refused rather than answered with
    // an older one — serving the older document would be R-5's rollback.
    let err = net
        .run(
            dev(1),
            CommandCode::GetStateDocument,
            &v1::GetStateDocumentRequest {
                metadata: meta(&[]),
                doc_type: DocumentType::PolicyBundle.to_wire(),
                version: 99,
            }
            .encode_to_vec(),
            3_000,
            Duration::from_secs(240),
            &owner(),
        )
        .expect_err("not held");
    assert_eq!(err.code().as_str(), "CONTROL.STALENESS.DOCUMENT_STALE");
}

#[test]
fn the_policy_event_is_durable_and_carries_the_bundle_or_a_reference() {
    // ADR-0002 N-5: every durable event is INDEPENDENTLY APPLICABLE — the whole
    // signed document, or a {doc_type, version, digest} reference sufficient to
    // pull it. Never a delta.
    let net = Net::new();
    register(&net, 1, 0);
    let out = net
        .run(
            dev(1),
            CommandCode::PutPolicy,
            &put_policy_request(1, 0, &key(90), 1),
            1_000,
            Duration::from_secs(120),
            &owner(),
        )
        .expect("accepted");

    assert_eq!(out.appended.len(), 1);
    let stored = &out.appended[0];
    assert_eq!(stored.event_type, EventKind::PolicyBundleUpdated);
    let wire = v1::ControlEvent::decode(stored.encoded.as_slice()).expect("decodes");
    let Some(EventBody::PolicyBundleUpdated(body)) = wire.event else {
        panic!("wrong body");
    };
    assert!(body.reference.is_some(), "always pullable");
    assert!(body.bundle.is_some(), "a small bundle travels inline");
    assert_eq!(body.policy_version, 1);
}

// ---------------------------------------------------------------------------
// R-4 — the verified payload is the authority, not the wire field beside it.
// ---------------------------------------------------------------------------

#[test]
fn a_revocation_cannot_be_retargeted_at_a_different_device() {
    // The attack: Owner-signed revocations are distributed to every device by
    // design, so anyone holding one can re-wrap it. Before R-4 the service
    // verified the Owner's signature and then revoked whatever
    // `target_device_id` the CALLER named — so one leaked revocation of a
    // decommissioned laptop revoked any device in the TwinNet on demand.
    let net = Net::new();
    register(&net, 1, 0);
    register(&net, 2, 0);
    register(&net, 3, 0);

    let err = net
        .run(
            dev(1),
            CommandCode::RevokeDevice,
            // The Owner signed for device 3; the wire says device 2.
            &mismatched_revoke_request(2, 3, &key(120)),
            1_000,
            Duration::from_secs(120),
            &owner(),
        )
        .expect_err("the wire target is not the signed target");
    assert_eq!(err.code().as_str(), "AUTH.PEER_UNTRUSTED");

    let state = net.store.snapshot(common::TWINNET).expect("net");
    assert!(state.revoked.is_empty(), "no device was revoked");
    assert_eq!(state.trust_epoch, 0, "and the epoch did not advance");
}

#[test]
fn a_policy_bundle_cannot_be_rewrapped_at_a_higher_version() {
    // Two attacks from one hole, both with a genuinely Owner-signed bundle:
    // re-wrap an old one at a HIGHER wire version and the rollback is accepted
    // as an advance; re-wrap any one at `u64::MAX` and the monotone floor moves
    // past every version the Owner can ever sign again.
    let net = Net::new();
    register(&net, 1, 0);

    for (wire, signed) in [(9u64, 1u64), (u64::MAX, 1)] {
        let err = net
            .run(
                dev(1),
                CommandCode::PutPolicy,
                &mismatched_policy_request(wire, signed, &key(121)),
                1_000,
                Duration::from_secs(120),
                &owner(),
            )
            .expect_err("the wire version is not the signed version");
        assert_eq!(err.code().as_str(), "AUTH.BINDING_INVALID");
        assert_eq!(
            net.store
                .snapshot(common::TWINNET)
                .expect("net")
                .policy_version,
            0,
            "the floor did not move"
        );
    }
}
