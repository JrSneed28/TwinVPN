//! **A `CEREMONY` replay returns the original outcome.**
//!
//! `contract-matrix.md` §3 on `CompletePairing`: *"a replay returns the
//! **original outcome** — this is what prevents asymmetric trust."* ADR-0009 §5
//! row S-04 names the failure it prevents: *"A trusts B, B does not ⇒ every
//! handshake fails with a misleading crypto error."*
//!
//! Every test here goes through the real dispatch path: the dedup log, the
//! handler, the journal, the commit.

mod common;

use std::time::Duration;

use common::{
    begin_pairing_request, complete_pairing_request, cose, dev, device, key, meta, owner, register,
    revoke_request, Net, NO_ANCHOR,
};
use prost::Message;
use twinvpn_control_plane::config::IDEMPOTENCY_WINDOW_MS;
use twinvpn_control_plane::CommandCode;
use twinvpn_schema::v1;

fn begin(net: &Net, caller: u8, pairing: u8, k: u8, now_ms: u64) -> v1::BeginPairingResponse {
    let out = net
        .run(
            dev(caller),
            CommandCode::BeginPairing,
            &begin_pairing_request(pairing, &key(k)),
            now_ms,
            Duration::from_secs(0),
            &owner(),
        )
        .expect("begins");
    v1::BeginPairingResponse::decode(out.response.as_slice()).expect("decodes")
}

#[test]
fn a_complete_pairing_replay_returns_the_original_outcome_byte_for_byte() {
    let net = Net::new();
    register(&net, 1, 0);
    begin(&net, 1, 9, 100, 1_000);

    let first = net
        .run(
            dev(1),
            CommandCode::CompletePairing,
            &complete_pairing_request(9, &key(102), 1, 0xaa),
            1_100,
            Duration::from_secs(30),
            &device(),
        )
        .expect("completes");
    assert!(!first.idempotent_replay);
    assert!(first.committed_at_net_seq > 0);

    // The retry: SAME key, and — this is the case that matters — a DIFFERENT
    // attestation. A server that re-derived would produce a second, different
    // outcome, and the two devices would disagree about whether they trust each
    // other.
    let replay = net
        .run(
            dev(1),
            CommandCode::CompletePairing,
            &complete_pairing_request(9, &key(102), 1, 0xbb),
            1_200,
            Duration::from_secs(60),
            &device(),
        )
        .expect("replays");

    assert!(replay.idempotent_replay, "ADR-0008 §10.2's observable");
    assert_eq!(
        replay.committed_at_net_seq, first.committed_at_net_seq,
        "the ORIGINAL position, not a second one"
    );

    let a = v1::CompletePairingResponse::decode(first.response.as_slice()).expect("decodes");
    let b = v1::CompletePairingResponse::decode(replay.response.as_slice()).expect("decodes");
    assert_eq!(
        a.result_detail, b.result_detail,
        "the recorded outcome, not a re-derivation"
    );
    assert!(!a.result.expect("result").idempotent_replay);
    assert!(b.result.expect("result").idempotent_replay);

    // And the replay appended NOTHING. A ceremony that logged a second event
    // would give every other device two contradictory PairingApproved records.
    assert!(replay.appended.is_empty());
}

#[test]
fn a_duplicate_begin_pairing_returns_the_original_id_and_never_mints_a_second() {
    let net = Net::new();
    register(&net, 1, 0);

    let first = begin(&net, 1, 9, 100, 1_000);
    let again = begin(&net, 1, 9, 100, 2_000);
    assert_eq!(first.pairing_id, again.pairing_id);
    assert_eq!(
        first.expires_at_ms, again.expires_at_ms,
        "the ORIGINAL 120 s window, not a fresh one — a reissued window would \
         reset the attempt budget"
    );

    // A different key on the same ceremony id is the same duplicate.
    let third = begin(&net, 1, 9, 107, 3_000);
    assert_eq!(third.pairing_id, first.pairing_id);

    let pairings = net.store.snapshot(common::TWINNET).expect("net").pairings;
    assert_eq!(pairings.len(), 1, "never a second pairing_id");
}

#[test]
fn a_cancelled_pairing_id_is_burnt_and_never_reissued() {
    let net = Net::new();
    register(&net, 1, 0);
    begin(&net, 1, 9, 100, 1_000);

    net.run(
        dev(1),
        CommandCode::CancelPairing,
        &v1::CancelPairingRequest {
            metadata: meta(&key(103)),
            pairing_id: vec![9u8; 16],
            reason_code: String::new(),
        }
        .encode_to_vec(),
        1_100,
        Duration::from_secs(30),
        &owner(),
    )
    .expect("cancels");

    // Completing a burnt id is refused, not re-run.
    let err = net
        .run(
            dev(1),
            CommandCode::CompletePairing,
            &complete_pairing_request(9, &key(104), 2, 0xaa),
            1_200,
            Duration::from_secs(60),
            &device(),
        )
        .expect_err("burnt");
    assert_eq!(err.code().as_str(), "AUTH.PAIRING_NOT_AUTHORIZED");

    // And so is beginning it again under a fresh key: cancelling burns the id,
    // "it is single-use, and a cancelled id is never reissued".
    let reissued = begin(&net, 1, 9, 105, 1_300);
    let detail = net.store.snapshot(common::TWINNET).expect("net");
    let row = detail.pairings.get(&[9u8; 16]).expect("row");
    assert_eq!(
        row.state,
        twinvpn_control_plane::model::PairingState::Cancelled,
        "reissuing would reset the 5-attempt budget"
    );
    assert_eq!(reissued.pairing_id, vec![9u8; 16]);
}

#[test]
fn a_duplicate_outside_the_window_is_refused_by_the_precondition_not_the_window() {
    // ADR-0008 N-6: "the expiry cliff is closed by N-2, not by a longer window."
    let net = Net::new();
    register(&net, 1, 0);
    begin(&net, 1, 9, 100, 1_000);
    net.run(
        dev(1),
        CommandCode::CompletePairing,
        &complete_pairing_request(9, &key(102), 1, 0xaa),
        1_100,
        Duration::from_secs(30),
        &device(),
    )
    .expect("completes");

    // Long past the 24 h dedup window, so the dedup log says nothing.
    let late = 1_100 + IDEMPOTENCY_WINDOW_MS + 1;
    let out = net
        .run(
            dev(1),
            CommandCode::CompletePairing,
            &complete_pairing_request(9, &key(102), 1, 0xcc),
            late,
            Duration::from_secs(120),
            &device(),
        )
        .expect("the recorded outcome is still the answer");
    assert!(
        out.idempotent_replay,
        "the terminal pairing state answers even when the dedup window has expired"
    );
    assert!(out.appended.is_empty(), "and nothing was re-executed");
}

#[test]
fn one_device_cannot_replay_anothers_ceremony_key() {
    // ADR-0008 N-4: the key is scoped to the authenticated DeviceIdentity.
    let net = Net::new();
    register(&net, 1, 0);
    register(&net, 2, 0);
    begin(&net, 1, 9, 100, 1_000);

    // Device 2 presents device 1's key on a ceremony it does not own.
    let err = net
        .run(
            dev(2),
            CommandCode::BeginPairing,
            &begin_pairing_request(9, &key(100)),
            2_000,
            Duration::from_secs(30),
            &owner(),
        )
        .expect_err("not the initiator");
    assert_eq!(err.code().as_str(), "AUTH.PAIRING_NOT_AUTHORIZED");
}

#[test]
fn a_key_reused_across_two_different_commands_is_refused() {
    let net = Net::new();
    register(&net, 1, 0);
    // `register` already recorded key(1) under RegisterDevice. Presenting it for
    // a revocation must not be answered with the registration's response.
    let err = net
        .run(
            dev(1),
            CommandCode::RevokeDevice,
            &revoke_request(1, &key(1)),
            5_000,
            Duration::from_secs(60),
            &owner(),
        )
        .expect_err("cross-served");
    assert_eq!(err.code().as_str(), "PROTO.MALFORMED_MESSAGE");
}

#[test]
fn a_ceremony_with_a_short_or_absent_key_is_refused() {
    // ADR-0008 N-4: >= 128 bits, required. A ceremony admitted without one is a
    // ceremony whose retry duplicates it.
    let net = Net::new();
    for bad in [Vec::new(), vec![1u8; 15], vec![1u8; 65]] {
        let err = net
            .run(
                dev(1),
                CommandCode::BeginPairing,
                &begin_pairing_request(9, &bad),
                1_000,
                Duration::from_secs(0),
                &owner(),
            )
            .expect_err("key required");
        assert_eq!(err.code().as_str(), "PROTO.MALFORMED_MESSAGE");
    }
}

#[test]
fn a_register_retry_with_the_same_key_returns_the_same_device_and_addresses() {
    let net = Net::new();
    let first = register(&net, 1, 0);
    let a = v1::RegisterDeviceResponse::decode(first.response.as_slice()).expect("decodes");

    let retry = net
        .run(
            dev(1),
            CommandCode::RegisterDevice,
            &common::register_request(1, &key(1)),
            10_000,
            Duration::from_secs(120),
            &owner(),
        )
        .expect("retries");
    assert!(retry.idempotent_replay);
    let b = v1::RegisterDeviceResponse::decode(retry.response.as_slice()).expect("decodes");

    assert_eq!(a.device_id_echo, b.device_id_echo);
    assert_eq!(a.assigned_twinnet_addr_v4, b.assigned_twinnet_addr_v4);
    assert_eq!(
        a.assigned_twinnet_addr_v6, b.assigned_twinnet_addr_v6,
        "S-08: an address is allocated once and is immutable"
    );
    let devices = net.store.snapshot(common::TWINNET).expect("net").devices;
    assert_eq!(devices.len(), 1, "a duplicate enrol is the SAME device");
}

#[test]
fn nothing_owner_signed_is_admitted_without_an_anchor() {
    // The fail-closed default, end to end. A control plane that could admit an
    // unverifiable RevocationStatement would be granting authority it does not
    // have.
    let net = Net::new();
    let err = net
        .run(
            dev(1),
            CommandCode::RegisterDevice,
            &common::register_request(1, &key(1)),
            0,
            Duration::from_secs(0),
            &NO_ANCHOR,
        )
        .expect_err("no anchor");
    assert_eq!(err.code().as_str(), "AUTH.KEY_UNAVAILABLE");

    let err = net
        .run(
            dev(1),
            CommandCode::RevokeDevice,
            &revoke_request(2, &key(202)),
            0,
            Duration::from_secs(0),
            &NO_ANCHOR,
        )
        .expect_err("no anchor");
    assert_eq!(err.code().as_str(), "AUTH.KEY_UNAVAILABLE");
    assert_eq!(net.trust_epoch(), 0, "and no epoch was assigned");
}

#[test]
fn an_enrolment_without_a_tunnel_key_binding_is_refused() {
    // ADR-0007 N-4: the IK-signed TunnelKeyBinding is what binds the X25519 key
    // to the hardware-held identity key. A record with none is one no peer can
    // ever admit.
    let net = Net::new();
    let mut req =
        v1::RegisterDeviceRequest::decode(common::register_request(1, &key(1)).as_slice())
            .expect("decodes");
    if let Some(identity) = req.identity.as_mut() {
        identity.tunnel_key_binding = None;
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
        .expect_err("no binding");
    assert_eq!(err.code().as_str(), "AUTH.BINDING_INVALID");
    let _ = cose(0);
}
