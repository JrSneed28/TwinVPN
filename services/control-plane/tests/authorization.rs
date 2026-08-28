//! Authorization, enforced server-side and independently of every claim in a
//! body.
//!
//! **Authority:** `docs/protocol.md` §7 (`Auth` Rule A: the caller is the
//! connection's identity and a `sender_id` in the body is a claim), ADR-0007
//! §7.5 and N-21, `contracts/proto/twinvpn/v1/pairing.proto` (the coordination
//! service "TRANSPORTS attestations it CANNOT FORGE, so it cannot inject a
//! `TrustedPeer`"), `contracts/docs/identifiers.md` §2.
//!
//! Every test here asks the same question in a different place: **can a
//! authenticated member do something that is not its to do?** The answer must be
//! no in each of them, and it must be no because of a check on the server and
//! not because a client would not have sent it.

mod common;

use std::time::Duration;

use common::{
    begin_pairing_request, complete_pairing_request, cose, dev, device_attesting, key, meta, owner,
    register, register_request, Net,
};
use prost::Message;
use twinvpn_control_plane::verify::testing::ScriptedVerifier;
use twinvpn_control_plane::verify::Succession;
use twinvpn_control_plane::CommandCode;
use twinvpn_schema::v1;

/// The COSE_Key a device would present on TLS, for the seed `label`.
fn cose_key(label: &[u8]) -> Vec<u8> {
    twinvpn_crypto::testkit::FixtureIdentity::from_seed(label).cose_key()
}

/// The `identity_id` that key derives to — the value the peer binding computes
/// from the presented `SubjectPublicKeyInfo`.
fn identity_of(cose: &[u8]) -> [u8; 32] {
    twinvpn_crypto::deviceid::derive_identity_id(cose).to_array()
}

// ---------------------------------------------------------------------------
// Enrolment binds to the caller
// ---------------------------------------------------------------------------

#[test]
fn a_device_cannot_enrol_a_record_under_another_devices_name() {
    // The enrolment proof says an OSK with the ENROLL power approved *a* join.
    // It does not say WHICH device is joining — it is issued before the joining
    // device ever contacts this service. So a party holding one could otherwise
    // take another device's name, its immutable S-08 addresses and its place in
    // the peer set before the real device ever connected.
    let net = Net::new();
    let err = net
        .run(
            dev(7),
            CommandCode::RegisterDevice,
            &register_request(1, &key(1)),
            1_000,
            Duration::ZERO,
            &owner(),
        )
        .expect_err("a device enrols itself or not at all");
    assert_eq!(err.code().as_str(), "AUTH.IDENTITY_MISMATCH");
    assert!(
        net.events(0).expect("retained").is_empty(),
        "nothing landed"
    );
}

#[test]
fn a_device_cannot_enrol_a_key_it_did_not_present() {
    // `identity_public_key` is what every later device-signed statement is
    // verified against. A record enrolled with somebody else's key would make
    // this service verify that third party's signatures as though they were the
    // caller's.
    let net = Net::new();
    let err = net
        .run_with_channel_key(
            dev(1),
            &cose_key(b"somebody else"),
            CommandCode::RegisterDevice,
            &register_request(1, &key(1)),
            1_000,
            Duration::ZERO,
            &owner(),
        )
        .expect_err("the enrolled key must be the key on the wire");
    assert_eq!(err.code().as_str(), "AUTH.IDENTITY_MISMATCH");
}

#[test]
fn a_device_enrolling_the_key_it_presented_is_admitted() {
    // The check must not be a lockout: the honest case is that the key in the
    // body and the key on the wire are the same key, and it goes through.
    let net = Net::new();
    let committed = net
        .run_with_channel_key(
            dev(1),
            // `register_request` puts exactly these octets in
            // `identity.identity_public_key`.
            &[1u8, 1, 1, 1],
            CommandCode::RegisterDevice,
            &register_request(1, &key(1)),
            1_000,
            Duration::ZERO,
            &owner(),
        )
        .expect("registers");
    let resp = v1::RegisterDeviceResponse::decode(committed.response.as_slice()).expect("decodes");
    assert_eq!(
        resp.device_id_echo,
        dev(1).to_vec(),
        "an echo, not an assignment"
    );
}

// ---------------------------------------------------------------------------
// A pairing belongs to its participants
// ---------------------------------------------------------------------------

#[test]
fn a_member_cannot_cancel_another_members_pairing() {
    // Cancelling BURNS the id: a cancelled pairing is terminal and a later
    // CompletePairing on it is refused. A member that could cancel another's
    // ceremony could deny pairing to the whole TwinNet one id at a time.
    let net = Net::new();
    register(&net, 1, 1_000);
    register(&net, 2, 2_000);
    net.run(
        dev(1),
        CommandCode::BeginPairing,
        &begin_pairing_request(9, &key(101)),
        3_000,
        Duration::from_secs(300),
        &owner(),
    )
    .expect("device 1 opens the ceremony");

    let err = net
        .run(
            dev(2),
            CommandCode::CancelPairing,
            &v1::CancelPairingRequest {
                metadata: meta(&key(102)),
                pairing_id: vec![9u8; 16],
                reason_code: String::new(),
            }
            .encode_to_vec(),
            4_000,
            Duration::from_secs(360),
            &owner(),
        )
        .expect_err("it is not device 2's ceremony to close");
    assert_eq!(err.code().as_str(), "AUTH.PAIRING_NOT_AUTHORIZED");
}

#[test]
fn the_initiator_can_cancel_its_own_pairing() {
    let net = Net::new();
    register(&net, 1, 1_000);
    net.run(
        dev(1),
        CommandCode::BeginPairing,
        &begin_pairing_request(9, &key(101)),
        3_000,
        Duration::from_secs(300),
        &owner(),
    )
    .expect("opens");

    net.run(
        dev(1),
        CommandCode::CancelPairing,
        &v1::CancelPairingRequest {
            metadata: meta(&key(102)),
            pairing_id: vec![9u8; 16],
            reason_code: String::new(),
        }
        .encode_to_vec(),
        4_000,
        Duration::from_secs(360),
        &owner(),
    )
    .expect("its own ceremony closes");
}

#[test]
fn an_attestation_for_another_ceremony_cannot_complete_this_one() {
    // Forging is not the only way to inject a TrustedPeer; MIS-ROUTING a genuine
    // attestation is the other. Without the binding check the signature would
    // verify — it is the caller's own key — the `pairing_id` in the request
    // would select the victim's row, and the two would never be compared.
    let net = Net::new();
    register(&net, 1, 1_000);
    register(&net, 2, 2_000);
    net.run(
        dev(1),
        CommandCode::BeginPairing,
        &begin_pairing_request(9, &key(101)),
        3_000,
        Duration::from_secs(300),
        &owner(),
    )
    .expect("opens ceremony 9");

    let err = net
        .run(
            dev(2),
            CommandCode::CompletePairing,
            &complete_pairing_request(9, &key(102), 1, 0xaa),
            4_000,
            Duration::from_secs(360),
            // A genuine attestation — for ceremony 8, not 9.
            &device_attesting(8),
        )
        .expect_err("the attestation names a different ceremony");
    assert_eq!(err.code().as_str(), "AUTH.PAIRING_NOT_AUTHORIZED");
}

#[test]
fn a_completion_whose_binding_cannot_be_read_is_refused() {
    // Fail-closed: a binding that cannot be read is a binding that is not
    // established. A verifier that reported nothing must not pass the check by
    // saying nothing.
    let net = Net::new();
    register(&net, 1, 1_000);
    net.run(
        dev(1),
        CommandCode::BeginPairing,
        &begin_pairing_request(9, &key(101)),
        3_000,
        Duration::from_secs(300),
        &owner(),
    )
    .expect("opens");

    let err = net
        .run(
            dev(1),
            CommandCode::CompletePairing,
            &complete_pairing_request(9, &key(102), 1, 0xaa),
            4_000,
            Duration::from_secs(360),
            &ScriptedVerifier::device(),
        )
        .expect_err("no binding, no completion");
    assert_eq!(err.code().as_str(), "AUTH.PAIRING_NOT_AUTHORIZED");
}

// ---------------------------------------------------------------------------
// Rotation moves the identity and never the name
// ---------------------------------------------------------------------------

/// A `RotateDeviceCredentialRequest` carrying an `IdentitySuccession`.
fn succession_request(device: u8, k: &[u8]) -> Vec<u8> {
    v1::RotateDeviceCredentialRequest {
        metadata: meta(k),
        device_id: dev(device).to_vec(),
        rotation: Some(
            v1::rotate_device_credential_request::Rotation::IdentitySuccession(cose(device)),
        ),
    }
    .encode_to_vec()
}

/// A verifier reporting the succession `dev(1)` → `to`, at generation 1.
fn succeeding(to: [u8; 32]) -> ScriptedVerifier {
    ScriptedVerifier::device().succeeding_to(Succession {
        device_id: dev(1),
        old_identity_id: dev(1),
        new_identity_id: to,
        generation: 1,
    })
}

#[test]
fn a_rotation_reindexes_the_identity_and_keeps_the_device_id() {
    // ADR-0007 N-21 and identifiers.md §2: the successor keeps `device_id` —
    // otherwise S-08's immutable address allocation would break on every
    // rotation — and `identity_id` is what moves.
    let net = Net::new();
    register(&net, 1, 1_000);
    let successor = identity_of(&cose_key(b"successor"));

    net.run(
        dev(1),
        CommandCode::RotateDeviceCredential,
        &succession_request(1, &key(50)),
        2_000,
        Duration::from_secs(300),
        &succeeding(successor),
    )
    .expect("rotates");

    let record = net.record(dev(1)).expect("still there under its own name");
    assert_eq!(record.device_id, dev(1), "the name never moves");
    assert_eq!(record.identity_id, successor, "the identity does");
    assert_eq!(record.generation, 1);
}

#[test]
fn a_rotated_devices_new_key_resolves_to_its_original_device_id() {
    // This is what makes the peer binding survive a rotation. `device_id` is the
    // hash of the generation-0 key, which the device no longer holds and never
    // presents; the presented generation-1 key derives to `new_identity_id`, and
    // the device table is what turns that back into the name.
    let net = Net::new();
    register(&net, 1, 1_000);
    let successor = identity_of(&cose_key(b"successor"));

    assert_eq!(net.device_for_identity(dev(1)), Some(dev(1)), "before");
    net.run(
        dev(1),
        CommandCode::RotateDeviceCredential,
        &succession_request(1, &key(50)),
        2_000,
        Duration::from_secs(300),
        &succeeding(successor),
    )
    .expect("rotates");

    assert_eq!(net.device_for_identity(successor), Some(dev(1)), "after");
    assert_eq!(
        net.device_for_identity(dev(1)),
        None,
        "the superseded identity stops resolving, so the old key stops serving"
    );
}

#[test]
fn a_succession_that_renames_the_device_is_refused() {
    // A succession naming another device would move a `device_id` — and with it
    // an immutable address allocation — onto a record the caller does not own.
    let net = Net::new();
    register(&net, 1, 1_000);
    register(&net, 2, 2_000);

    let err = net
        .run(
            dev(1),
            CommandCode::RotateDeviceCredential,
            &succession_request(1, &key(50)),
            3_000,
            Duration::from_secs(300),
            &ScriptedVerifier::device().succeeding_to(Succession {
                device_id: dev(2),
                old_identity_id: dev(1),
                new_identity_id: identity_of(&cose_key(b"successor")),
                generation: 1,
            }),
        )
        .expect_err("a succession speaks about its own device");
    assert_eq!(err.code().as_str(), "AUTH.IDENTITY_MISMATCH");
    assert_eq!(net.record(dev(1)).expect("unchanged").identity_id, dev(1));
}

#[test]
fn a_succession_that_skips_a_generation_is_refused() {
    // ADR-0007 N-21: "exactly old generation + 1", so a rotation cannot skip
    // generations and land a device on a key nobody witnessed being installed.
    let net = Net::new();
    register(&net, 1, 1_000);

    let err = net
        .run(
            dev(1),
            CommandCode::RotateDeviceCredential,
            &succession_request(1, &key(50)),
            2_000,
            Duration::from_secs(300),
            &ScriptedVerifier::device().succeeding_to(Succession {
                device_id: dev(1),
                old_identity_id: dev(1),
                new_identity_id: identity_of(&cose_key(b"successor")),
                generation: 4,
            }),
        )
        .expect_err("generations do not skip");
    assert_eq!(err.code().as_str(), "AUTH.TRUST_EPOCH_ROLLBACK");
}

#[test]
fn a_rotation_with_no_readable_succession_is_refused() {
    // Fail-closed again: the successor is the whole point of the command, and a
    // verifier that reported none must not leave the record silently unmoved.
    let net = Net::new();
    register(&net, 1, 1_000);

    let err = net
        .run(
            dev(1),
            CommandCode::RotateDeviceCredential,
            &succession_request(1, &key(50)),
            2_000,
            Duration::from_secs(300),
            &ScriptedVerifier::device(),
        )
        .expect_err("no successor, no rotation");
    // `codes::SIGNATURE_INVALID` is the crate's name for AUTH.BINDING_INVALID —
    // the registry has no signature-invalid spelling of its own.
    assert_eq!(err.code().as_str(), "AUTH.BINDING_INVALID");
    assert_eq!(
        net.record(dev(1)).expect("unchanged").generation,
        0,
        "the record is left where it was, not silently unmoved past a rotation"
    );
}

// ---------------------------------------------------------------------------
// Owner power is scoped: a key may do only what its delegation grants
// ---------------------------------------------------------------------------
//
// ADR-0007 O5 keeps the `OwnerRootKey` offline behind a recovery phrase and
// does routine work — enrol, revoke, publish policy — with per-admin-device
// `OwnerSigningKey`s, each delegated a subset of
// {`ENROLL`, `REVOKE`, `POLICY`, `DELEGATE`, `ADMINISTER`}. Before the chain
// check, verifying the signature was the whole of the authorisation: **an admin
// phone delegated only `ENROLL` could revoke every device in the `TwinNet` and
// publish a policy bundle.** These are the tests that say it cannot.

use common::{owner_osk, revoke_request};
use twinvpn_crypto::statements::OskPower;

#[test]
fn an_enroll_only_key_cannot_revoke_a_device() {
    let net = Net::new();
    register(&net, 1, 1_000);
    register(&net, 2, 2_000);

    let err = net
        .run(
            dev(1),
            CommandCode::RevokeDevice,
            &revoke_request(2, &key(60)),
            3_000,
            Duration::from_secs(300),
            &owner_osk(&[OskPower::Enroll]),
        )
        .expect_err("ENROLL is not REVOKE");
    assert_eq!(err.code().as_str(), "AUTH.UNEXPECTED_DELEGATION");
    assert!(
        !net.record(dev(2)).expect("still enrolled").revoked,
        "and the device is untouched"
    );
    assert_eq!(net.trust_epoch(), 0, "no epoch was assigned");
}

#[test]
fn an_enroll_only_key_cannot_publish_policy() {
    let net = Net::new();
    register(&net, 1, 1_000);

    let err = net
        .run(
            dev(1),
            CommandCode::PutPolicy,
            &common::put_policy_request(1, 0, &key(61), 0x5a),
            3_000,
            Duration::from_secs(300),
            &owner_osk(&[OskPower::Enroll]),
        )
        .expect_err("ENROLL is not POLICY");
    assert_eq!(err.code().as_str(), "AUTH.UNEXPECTED_DELEGATION");
}

#[test]
fn the_key_that_holds_the_power_is_admitted() {
    // The check must not be a lockout. A REVOKE-powered key revokes, and the
    // epoch advances — which is the half that proves the refusals above are
    // about the POWER and not about the delegation path being broken.
    let net = Net::new();
    register(&net, 1, 1_000);
    register(&net, 2, 2_000);

    net.run(
        dev(1),
        CommandCode::RevokeDevice,
        &revoke_request(2, &key(60)),
        3_000,
        Duration::from_secs(300),
        &owner_osk(&[OskPower::Revoke]),
    )
    .expect("a REVOKE-powered key revokes");
    assert!(net.record(dev(2)).expect("row kept").revoked);
    assert_eq!(net.trust_epoch(), 1, "the epoch advanced exactly once");
}

#[test]
fn an_expired_delegation_authorises_nothing() {
    // Checked at USE and not at load: this process outlives the file it read,
    // and a delegation that expires at 03:00 must stop working at 03:00 rather
    // than at the next restart.
    let net = Net::new();
    register(&net, 1, 1_000);
    register(&net, 2, 2_000);

    let expired = ScriptedVerifier::owner()
        .held_by(twinvpn_control_plane::verify::Delegation {
            osk_id: "osk-stale".to_owned(),
            osk_pub_cose: vec![0xa5; 8],
            powers: vec![OskPower::Revoke],
            anchor_version: 1,
            not_after_ms: 2_500,
        })
        .granting(common::delegation("osk-stale", &[OskPower::Enroll]));

    let err = net
        .run(
            dev(1),
            CommandCode::RevokeDevice,
            &revoke_request(2, &key(60)),
            3_000,
            Duration::from_secs(300),
            &expired,
        )
        .expect_err("the delegation lapsed at 2500ms");
    assert_eq!(err.code().as_str(), "AUTH.CRED_EXPIRED");
}

#[test]
fn an_enrolment_proof_that_grants_no_enroll_power_is_not_an_approval() {
    // `RegisterDevice`'s authorisation is the delegation INSIDE the proof, not
    // whoever signed it. A delegation granting only `POLICY` is impeccably
    // signed and is still not permission to join a TwinNet.
    let net = Net::new();
    let policy_only =
        ScriptedVerifier::owner().granting(common::delegation("osk-policy", &[OskPower::Policy]));

    let err = net
        .run(
            dev(1),
            CommandCode::RegisterDevice,
            &register_request(1, &key(1)),
            1_000,
            Duration::ZERO,
            &policy_only,
        )
        .expect_err("POLICY is not ENROLL");
    assert_eq!(err.code().as_str(), "AUTH.UNEXPECTED_DELEGATION");
    assert!(net.record(dev(1)).is_none(), "nothing was enrolled");
}

#[test]
fn an_enrolment_proof_whose_grant_cannot_be_read_is_refused() {
    // Fail-closed. A proof whose delegation does not decode is not a narrower
    // proof; it is not a proof.
    let net = Net::new();
    let err = net
        .run(
            dev(1),
            CommandCode::RegisterDevice,
            &register_request(1, &key(1)),
            1_000,
            Duration::ZERO,
            &ScriptedVerifier::owner(),
        )
        .expect_err("no readable grant, no enrolment");
    assert_eq!(err.code().as_str(), "AUTH.BINDING_INVALID");
}

#[test]
fn the_root_key_is_unscoped_because_every_delegation_chains_to_it() {
    // `signer_delegation: None` is the ORK. Checking a power against it would be
    // checking the root against a grant the root issues — there is no key above
    // it to have scoped it.
    let net = Net::new();
    register(&net, 1, 1_000);
    register(&net, 2, 2_000);
    net.run(
        dev(1),
        CommandCode::RevokeDevice,
        &revoke_request(2, &key(60)),
        3_000,
        Duration::from_secs(300),
        &owner(),
    )
    .expect("the root revokes without holding a delegation");
    assert!(net.record(dev(2)).expect("row kept").revoked);
}
