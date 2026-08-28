//! The attack tests for signed-statement verification.
//!
//! Each test names the attack it refutes. A security property with only a
//! happy-path test is untested, so every rule in
//! `contracts/cddl/twinvpn/v1/signed_statements.cddl`'s encoding-rules header
//! has a test here that breaks it and asserts the refusal.

mod common;

use common::{crit, x25519_cose_key, TestIdentity};
use twinvpn_crypto::emit::{encode, Item};
use twinvpn_crypto::statements::{
    check_attestation_pair, decode_device_identity_record, decode_owner_delegation,
    decode_pairing_attestation, decode_policy_bundle, decode_revocation_statement,
    decode_trust_epoch_bundle, verify_succession_pair, OskPower,
};
use twinvpn_crypto::{verify_cose_sign1, CryptoError, StatementKind};

const DEVICE_A: [u8; 32] = [0xa1; 32];
const DEVICE_B: [u8; 32] = [0xb2; 32];
const IDENTITY_A: [u8; 32] = [0xc3; 32];
const TK_A: [u8; 32] = [0xd4; 32];

fn identity_record_payload() -> Item {
    Item::Map(vec![
        (Item::Uint(1), Item::Text("tn-1".to_owned())),
        (Item::Uint(2), Item::Bytes(DEVICE_A.to_vec())),
        (Item::Uint(3), Item::Bytes(IDENTITY_A.to_vec())),
        (Item::Uint(4), Item::Uint(0)),
        (
            Item::Uint(5),
            Item::Bytes(TestIdentity::from_seed(b"ik").cose_key()),
        ),
        (Item::Uint(6), Item::Bytes(x25519_cose_key(&TK_A))),
        (Item::Uint(7), Item::Uint(1)),
        (Item::Uint(8), Item::Bool(true)),
        (Item::Uint(9), Item::Uint(1_700_000_000_000)),
        (Item::Uint(10), Item::Uint(2_000_000_000_000)),
        (Item::Uint(11), crit(&["generation", "tk_generation"])),
    ])
}

fn binding_payload(tk: &[u8; 32], device: &[u8; 32], identity: &[u8; 32]) -> Item {
    Item::Map(vec![
        (Item::Uint(1), Item::Bytes(device.to_vec())),
        (Item::Uint(2), Item::Bytes(identity.to_vec())),
        (Item::Uint(3), Item::Bytes(x25519_cose_key(tk))),
        (Item::Uint(4), Item::Uint(3)),
        (Item::Uint(5), Item::Uint(2_000_000_000_000)),
        (Item::Uint(6), crit(&["tk_generation"])),
    ])
}

// ---------------------------------------------------------------------------
// The happy path, so the negative tests below are known to be testing something
// ---------------------------------------------------------------------------

#[test]
fn a_well_formed_statement_verifies_and_decodes() {
    let ik = TestIdentity::from_seed(b"device-a");
    let octets = ik.sign_statement(&identity_record_payload());
    let verified = verify_cose_sign1(
        &octets,
        StatementKind::DeviceIdentityRecord,
        &ik.verifying_key(),
    )
    .expect("verify");
    let rec = decode_device_identity_record(&verified).expect("decode");
    assert_eq!(rec.device_id, DEVICE_A);
    assert_eq!(rec.generation, 0);
    assert!(rec.hardware_backed_claim);
}

// ---------------------------------------------------------------------------
// ATTACK: a re-encoded copy
// ---------------------------------------------------------------------------

/// **Attack test — the one the CDDL's rule 3 exists for.** An attacker who can
/// get a verifier to re-serialize before verifying can smuggle a difference
/// through the round trip. The defence here is structural: the only input to
/// `verify_cose_sign1` is `&[u8]`, and the decoded payload
/// (`VerifiedStatement::payload()`, a `dcbor::Value`) has **no** conversion into
/// `emit::Item`. This test states the property that makes that true — the two
/// directions share no type — and asserts the one thing a test can assert: that
/// verification is a function of the octets, so any change to them fails.
#[test]
fn verification_is_a_function_of_the_received_octets() {
    let ik = TestIdentity::from_seed(b"device-a");
    let octets = ik.sign_statement(&identity_record_payload());

    // Every single-byte perturbation must fail. If verification consulted a
    // re-encoding rather than these bytes, some of these would pass.
    for i in 0..octets.len() {
        let mut tampered = octets.clone();
        tampered[i] ^= 0x01;
        assert!(
            verify_cose_sign1(
                &tampered,
                StatementKind::DeviceIdentityRecord,
                &ik.verifying_key()
            )
            .is_err(),
            "a byte flip at offset {i} was accepted"
        );
    }
}

/// **Attack test.** A statement signed by one key must not verify under
/// another. This is the base case of "the coordination service transports
/// attestations it cannot forge".
#[test]
fn a_statement_does_not_verify_under_a_different_key() {
    let signer = TestIdentity::from_seed(b"device-a");
    let other = TestIdentity::from_seed(b"device-b");
    let octets = signer.sign_statement(&identity_record_payload());
    let err = verify_cose_sign1(
        &octets,
        StatementKind::DeviceIdentityRecord,
        &other.verifying_key(),
    )
    .expect_err("must not verify");
    assert!(matches!(err, CryptoError::SignatureInvalid { .. }));
}

// ---------------------------------------------------------------------------
// ATTACK: non-canonical encodings
// ---------------------------------------------------------------------------

/// **Attack test.** A non-canonical envelope must be refused *before* any
/// signature check, so a verifier never spends a verification on octets it would
/// have to normalize to interpret.
#[test]
fn a_non_canonical_envelope_is_refused_before_any_signature_check() {
    let ik = TestIdentity::from_seed(b"device-a");
    let octets = ik.sign_statement(&identity_record_payload());

    // Rewrite the outer array head from the immediate form 0x84 to the
    // one-byte-argument form 0x98 0x04. Same logical value, different octets —
    // exactly what §4.2.1 (a) forbids.
    assert_eq!(octets[0], 0x84, "the envelope is a four-element array");
    let mut noncanonical = vec![0x98, 0x04];
    noncanonical.extend_from_slice(&octets[1..]);

    let err = verify_cose_sign1(
        &noncanonical,
        StatementKind::DeviceIdentityRecord,
        &ik.verifying_key(),
    )
    .expect_err("must refuse");
    match err {
        CryptoError::NonCanonicalCbor { step, .. } => {
            assert_eq!(step, "non-shortest argument");
        }
        other => panic!("expected a canonicity refusal, got {other:?}"),
    }
    assert_eq!(
        err.reason_code().as_str(),
        "PROTO.NON_CANONICAL_CBOR",
        "the refusal must carry the registered code, never a generic error"
    );
}

/// **Attack test.** Trailing bytes after the envelope: a valid statement with a
/// smuggled suffix. A parser that ignored the remainder would verify a prefix
/// while a downstream reader saw the whole thing.
#[test]
fn trailing_bytes_after_the_envelope_are_refused() {
    let ik = TestIdentity::from_seed(b"device-a");
    let mut octets = ik.sign_statement(&identity_record_payload());
    octets.push(0x00);
    assert!(verify_cose_sign1(
        &octets,
        StatementKind::DeviceIdentityRecord,
        &ik.verifying_key()
    )
    .is_err());
}

// ---------------------------------------------------------------------------
// ATTACK: the crit set
// ---------------------------------------------------------------------------

/// **Attack test.** An unrecognised `crit` member must reject the statement.
/// Without it, "adding a future RESTRICTION would be silently ignored by old
/// devices, which converts a tightening into a no-op — A SILENT AUTHORIZATION
/// HOLE."
#[test]
fn an_unrecognised_critical_field_rejects_the_statement() {
    let ik = TestIdentity::from_seed(b"device-a");
    let Item::Map(mut fields) = identity_record_payload() else {
        unreachable!()
    };
    fields.retain(|(k, _)| *k != Item::Uint(11));
    fields.push((
        Item::Uint(11),
        crit(&["generation", "tk_generation", "future_restriction"]),
    ));
    let octets = ik.sign_statement(&Item::Map(fields));
    let verified = verify_cose_sign1(
        &octets,
        StatementKind::DeviceIdentityRecord,
        &ik.verifying_key(),
    )
    .expect("the signature itself is fine");
    let err = decode_device_identity_record(&verified).expect_err("must reject");
    match err {
        CryptoError::UnknownCriticalField { ref field, .. } => {
            assert_eq!(field, "future_restriction");
        }
        other => panic!("expected an unknown-crit refusal, got {other:?}"),
    }
    assert_eq!(err.reason_code().as_str(), "PROTO.UNKNOWN_CRITICAL_FIELD");
}

/// **Attack test.** A producer that omits a required `crit` member is inviting
/// the verifier to treat a monotone field as optional.
#[test]
fn a_missing_required_critical_field_rejects_the_statement() {
    let ik = TestIdentity::from_seed(b"device-a");
    let Item::Map(mut fields) = identity_record_payload() else {
        unreachable!()
    };
    fields.retain(|(k, _)| *k != Item::Uint(11));
    fields.push((Item::Uint(11), crit(&["generation"])));
    let octets = ik.sign_statement(&Item::Map(fields));
    let verified = verify_cose_sign1(
        &octets,
        StatementKind::DeviceIdentityRecord,
        &ik.verifying_key(),
    )
    .expect("signature is fine");
    let err = decode_device_identity_record(&verified).expect_err("must reject");
    assert!(matches!(
        err,
        CryptoError::MissingCriticalField {
            field: "tk_generation",
            ..
        }
    ));
}

/// **Attack test.** Encoding rule 5: an unknown *non*-`crit` field is also
/// refused. "a preserved-but-unverified field is a place to smuggle data past a
/// policy check."
#[test]
fn an_unknown_field_in_a_signed_statement_is_refused() {
    let ik = TestIdentity::from_seed(b"device-a");
    let Item::Map(mut fields) = identity_record_payload() else {
        unreachable!()
    };
    fields.push((Item::Uint(99), Item::Uint(1)));
    let octets = ik.sign_statement(&Item::Map(fields));
    let verified = verify_cose_sign1(
        &octets,
        StatementKind::DeviceIdentityRecord,
        &ik.verifying_key(),
    )
    .expect("signature is fine");
    assert!(decode_device_identity_record(&verified).is_err());
}

// ---------------------------------------------------------------------------
// ATTACK: TunnelKeyBinding
// ---------------------------------------------------------------------------

#[test]
fn a_matching_binding_yields_the_tunnel_key() {
    let ik = TestIdentity::from_seed(b"device-a");
    let octets = ik.sign_statement(&binding_payload(&TK_A, &DEVICE_A, &IDENTITY_A));
    let verified = verify_cose_sign1(
        &octets,
        StatementKind::TunnelKeyBinding,
        &ik.verifying_key(),
    )
    .expect("verify");
    let key = twinvpn_crypto::verify_tunnel_key_binding(&verified, &DEVICE_A, &IDENTITY_A)
        .expect("binding");
    assert_eq!(key.tk_pub(), &TK_A);
    assert_eq!(key.tk_generation(), 3);
}

/// **Attack test — ADR-0001 K3, "a full authentication bypass".** A binding that
/// verifies under some key but names a *different* device must be refused: the
/// binding is what ties a software-held tunnel key to the element-held identity
/// that authorizes it, and a mismatch means it authorizes something else.
#[test]
fn a_binding_naming_a_different_device_is_refused() {
    let ik = TestIdentity::from_seed(b"device-a");
    let octets = ik.sign_statement(&binding_payload(&TK_A, &DEVICE_B, &IDENTITY_A));
    let verified = verify_cose_sign1(
        &octets,
        StatementKind::TunnelKeyBinding,
        &ik.verifying_key(),
    )
    .expect("signature is fine");
    let err = twinvpn_crypto::verify_tunnel_key_binding(&verified, &DEVICE_A, &IDENTITY_A)
        .expect_err("must refuse");
    assert!(matches!(err, CryptoError::BindingInvalid { .. }));
    assert_eq!(err.reason_code().as_str(), "AUTH.BINDING_INVALID");
}

/// **Attack test.** Same, for `identity_id`: a binding made by an older
/// generation must not authorize a key for the current one.
#[test]
fn a_binding_naming_a_different_identity_is_refused() {
    let ik = TestIdentity::from_seed(b"device-a");
    let octets = ik.sign_statement(&binding_payload(&TK_A, &DEVICE_A, &[0x99; 32]));
    let verified = verify_cose_sign1(
        &octets,
        StatementKind::TunnelKeyBinding,
        &ik.verifying_key(),
    )
    .expect("signature is fine");
    assert!(twinvpn_crypto::verify_tunnel_key_binding(&verified, &DEVICE_A, &IDENTITY_A).is_err());
}

/// **Attack test.** The all-zero X25519 point makes every agreement produce a
/// zero shared secret, and `x25519-dalek` does not fail on it. A peer offering
/// it must never reach a handshake.
#[test]
fn a_binding_over_the_all_zero_point_is_refused() {
    let ik = TestIdentity::from_seed(b"device-a");
    let octets = ik.sign_statement(&binding_payload(&[0u8; 32], &DEVICE_A, &IDENTITY_A));
    let verified = verify_cose_sign1(
        &octets,
        StatementKind::TunnelKeyBinding,
        &ik.verifying_key(),
    )
    .expect("signature is fine");
    assert!(twinvpn_crypto::verify_tunnel_key_binding(&verified, &DEVICE_A, &IDENTITY_A).is_err());
}

/// **Attack test.** A signing key in the `tk_pub` slot is a kind confusion, and
/// the parser refuses it by curve rather than accepting any 32 bytes.
#[test]
fn a_signing_key_in_the_tunnel_key_slot_is_refused() {
    let ik = TestIdentity::from_seed(b"device-a");
    let payload = Item::Map(vec![
        (Item::Uint(1), Item::Bytes(DEVICE_A.to_vec())),
        (Item::Uint(2), Item::Bytes(IDENTITY_A.to_vec())),
        // An EC2/P-256 COSE_Key where an OKP/X25519 one belongs.
        (Item::Uint(3), Item::Bytes(ik.cose_key())),
        (Item::Uint(4), Item::Uint(3)),
        (Item::Uint(5), Item::Uint(2_000_000_000_000)),
        (Item::Uint(6), crit(&["tk_generation"])),
    ]);
    let octets = ik.sign_statement(&payload);
    let verified = verify_cose_sign1(
        &octets,
        StatementKind::TunnelKeyBinding,
        &ik.verifying_key(),
    )
    .expect("signature is fine");
    assert!(twinvpn_crypto::verify_tunnel_key_binding(&verified, &DEVICE_A, &IDENTITY_A).is_err());
}

/// **Attack test.** A `DeviceIdentityRecord` presented where a
/// `TunnelKeyBinding` is expected must be refused by kind, not silently read as
/// whichever fields happen to line up.
#[test]
fn a_statement_of_the_wrong_kind_is_refused_by_the_binding_check() {
    let ik = TestIdentity::from_seed(b"device-a");
    let octets = ik.sign_statement(&identity_record_payload());
    let verified = verify_cose_sign1(
        &octets,
        StatementKind::DeviceIdentityRecord,
        &ik.verifying_key(),
    )
    .expect("verify");
    assert!(twinvpn_crypto::verify_tunnel_key_binding(&verified, &DEVICE_A, &IDENTITY_A).is_err());
}

// ---------------------------------------------------------------------------
// ATTACK: IdentitySuccession
// ---------------------------------------------------------------------------

fn succession_payload(gen: u64, old: [u8; 32], new: [u8; 32]) -> Item {
    Item::Map(vec![
        (Item::Uint(1), Item::Bytes(DEVICE_A.to_vec())),
        (Item::Uint(2), Item::Bytes(old.to_vec())),
        (Item::Uint(3), Item::Bytes(new.to_vec())),
        (Item::Uint(4), Item::Uint(gen)),
        (Item::Uint(5), Item::Uint(2_000_000_000_000)),
        (Item::Uint(6), crit(&["generation"])),
    ])
}

#[test]
fn a_dual_signed_succession_is_accepted() {
    let old = TestIdentity::from_seed(b"gen0");
    let new = TestIdentity::from_seed(b"gen1");
    let payload = succession_payload(1, IDENTITY_A, [0xee; 32]);
    let by_old = verify_cose_sign1(
        &old.sign_statement(&payload),
        StatementKind::IdentitySuccession,
        &old.verifying_key(),
    )
    .expect("old");
    let by_new = verify_cose_sign1(
        &new.sign_statement(&payload),
        StatementKind::IdentitySuccession,
        &new.verifying_key(),
    )
    .expect("new");
    let s = verify_succession_pair(&by_old, &by_new, 0).expect("succession");
    assert_eq!(s.generation, 1);
    assert_eq!(
        s.device_id, DEVICE_A,
        "device_id must not change on rotation"
    );
}

/// **Attack test — "a STOLEN KEY ROTATING ITSELF INTO PERMANENCE".** Both
/// signatures must cover the *same* payload; pairing a genuine old-key signature
/// with a new-key signature over different content must be refused.
#[test]
fn two_signatures_over_different_payloads_are_refused() {
    let old = TestIdentity::from_seed(b"gen0");
    let new = TestIdentity::from_seed(b"gen1");
    let by_old = verify_cose_sign1(
        &old.sign_statement(&succession_payload(1, IDENTITY_A, [0xee; 32])),
        StatementKind::IdentitySuccession,
        &old.verifying_key(),
    )
    .expect("old");
    let by_new = verify_cose_sign1(
        // A different successor identity.
        &new.sign_statement(&succession_payload(1, IDENTITY_A, [0xff; 32])),
        StatementKind::IdentitySuccession,
        &new.verifying_key(),
    )
    .expect("new");
    assert!(verify_succession_pair(&by_old, &by_new, 0).is_err());
}

/// **Attack test.** A rotation that skips generations would land a device on a
/// key nobody witnessed being installed.
#[test]
fn a_succession_that_skips_a_generation_is_refused() {
    let old = TestIdentity::from_seed(b"gen0");
    let new = TestIdentity::from_seed(b"gen1");
    let payload = succession_payload(5, IDENTITY_A, [0xee; 32]);
    let by_old = verify_cose_sign1(
        &old.sign_statement(&payload),
        StatementKind::IdentitySuccession,
        &old.verifying_key(),
    )
    .expect("old");
    let by_new = verify_cose_sign1(
        &new.sign_statement(&payload),
        StatementKind::IdentitySuccession,
        &new.verifying_key(),
    )
    .expect("new");
    let err = verify_succession_pair(&by_old, &by_new, 0).expect_err("must refuse");
    assert!(matches!(err, CryptoError::MonotoneRollback { .. }));
}

/// **Attack test.** A succession that does not change the identity is a
/// no-op that would still advance the generation, giving an attacker a way to
/// burn generations or to look like a rotation happened.
#[test]
fn a_succession_to_the_same_identity_is_refused() {
    let old = TestIdentity::from_seed(b"gen0");
    let new = TestIdentity::from_seed(b"gen1");
    let payload = succession_payload(1, IDENTITY_A, IDENTITY_A);
    let by_old = verify_cose_sign1(
        &old.sign_statement(&payload),
        StatementKind::IdentitySuccession,
        &old.verifying_key(),
    )
    .expect("old");
    let by_new = verify_cose_sign1(
        &new.sign_statement(&payload),
        StatementKind::IdentitySuccession,
        &new.verifying_key(),
    )
    .expect("new");
    assert!(verify_succession_pair(&by_old, &by_new, 0).is_err());
}

// ---------------------------------------------------------------------------
// ATTACK: PairingAttestation
// ---------------------------------------------------------------------------

fn attestation_payload(peer_kid: &str, own_kid: &str, transcript: [u8; 32]) -> Item {
    Item::Map(vec![
        (Item::Uint(1), Item::Bytes(vec![0x5a; 16])),
        (Item::Uint(2), Item::Text(peer_kid.to_owned())),
        (Item::Uint(3), Item::Text(own_kid.to_owned())),
        (Item::Uint(4), Item::Bytes(transcript.to_vec())),
        (Item::Uint(5), Item::Uint(2_000_000_000_000)),
        (Item::Uint(6), crit(&["pairing_id"])),
    ])
}

#[test]
fn two_consistent_attestations_form_one_ceremony() {
    let a = TestIdentity::from_seed(b"pair-a");
    let b = TestIdentity::from_seed(b"pair-b");
    let t = [0x7c; 32];
    let va = verify_cose_sign1(
        &a.sign_statement(&attestation_payload("kb", "ka", t)),
        StatementKind::PairingAttestation,
        &a.verifying_key(),
    )
    .expect("a");
    let vb = verify_cose_sign1(
        &b.sign_statement(&attestation_payload("ka", "kb", t)),
        StatementKind::PairingAttestation,
        &b.verifying_key(),
    )
    .expect("b");
    let da = decode_pairing_attestation(&va).expect("decode a");
    let db = decode_pairing_attestation(&vb).expect("decode b");
    check_attestation_pair(&da, &db).expect("consistent");
}

/// **Attack test — N-18's asymmetric trust.** Two attestations that do not name
/// each other are not a ceremony. A coordination service that could pair
/// unrelated attestations could inject a `TrustedPeer`, which is exactly what
/// Rule B exists to prevent.
#[test]
fn attestations_that_do_not_name_each_other_are_refused() {
    let a = TestIdentity::from_seed(b"pair-a");
    let b = TestIdentity::from_seed(b"pair-b");
    let t = [0x7c; 32];
    let va = verify_cose_sign1(
        &a.sign_statement(&attestation_payload("kb", "ka", t)),
        StatementKind::PairingAttestation,
        &a.verifying_key(),
    )
    .expect("a");
    let vb = verify_cose_sign1(
        // Names a third party as its peer.
        &b.sign_statement(&attestation_payload("kc", "kb", t)),
        StatementKind::PairingAttestation,
        &b.verifying_key(),
    )
    .expect("b");
    let da = decode_pairing_attestation(&va).expect("decode a");
    let db = decode_pairing_attestation(&vb).expect("decode b");
    assert!(check_attestation_pair(&da, &db).is_err());
}

/// **Attack test.** Two halves that disagree on the ceremony transcript are two
/// different ceremonies, and accepting them would establish trust neither device
/// consented to.
#[test]
fn attestations_over_different_transcripts_are_refused() {
    let a = TestIdentity::from_seed(b"pair-a");
    let b = TestIdentity::from_seed(b"pair-b");
    let va = verify_cose_sign1(
        &a.sign_statement(&attestation_payload("kb", "ka", [0x01; 32])),
        StatementKind::PairingAttestation,
        &a.verifying_key(),
    )
    .expect("a");
    let vb = verify_cose_sign1(
        &b.sign_statement(&attestation_payload("ka", "kb", [0x02; 32])),
        StatementKind::PairingAttestation,
        &b.verifying_key(),
    )
    .expect("b");
    let da = decode_pairing_attestation(&va).expect("decode a");
    let db = decode_pairing_attestation(&vb).expect("decode b");
    assert!(check_attestation_pair(&da, &db).is_err());
}

/// **Attack test.** One device signing both halves is a self-pairing, which
/// would let a single compromised device manufacture a peer relationship.
#[test]
fn one_device_signing_both_halves_is_refused() {
    let a = TestIdentity::from_seed(b"pair-a");
    let t = [0x7c; 32];
    let v1 = verify_cose_sign1(
        &a.sign_statement(&attestation_payload("ka", "ka", t)),
        StatementKind::PairingAttestation,
        &a.verifying_key(),
    )
    .expect("v1");
    let d = decode_pairing_attestation(&v1).expect("decode");
    assert!(check_attestation_pair(&d, &d.clone()).is_err());
}

// ---------------------------------------------------------------------------
// Owner statements
// ---------------------------------------------------------------------------

#[test]
fn a_revocation_statement_with_a_null_identity_targets_every_generation() {
    let osk = TestIdentity::from_seed(b"osk");
    let payload = Item::Map(vec![
        (Item::Uint(1), Item::Text("tn-1".to_owned())),
        (Item::Uint(2), Item::Bytes(DEVICE_B.to_vec())),
        (Item::Uint(3), Item::Null),
        (Item::Uint(4), Item::Uint(1_700_000_000_000)),
        (Item::Uint(5), Item::Text("AUTH.DEVICE_REVOKED".to_owned())),
        (Item::Uint(6), Item::Text("osk-1".to_owned())),
        (Item::Uint(7), crit(&["target_device_id"])),
    ]);
    let v = verify_cose_sign1(
        &osk.sign_statement(&payload),
        StatementKind::RevocationStatement,
        &osk.verifying_key(),
    )
    .expect("verify");
    let r = decode_revocation_statement(&v).expect("decode");
    assert_eq!(r.target_device_id, DEVICE_B);
    assert_eq!(
        r.target_identity_id, None,
        "null must mean every generation, the broader reading"
    );
}

/// **Attack test.** An `OwnerDelegation` naming a power this build does not
/// understand must be refused, not narrowed: a verifier that silently dropped it
/// would both accept operations it should refuse and refuse ones it should
/// accept.
#[test]
fn an_unrecognised_owner_power_rejects_the_delegation() {
    let ork = TestIdentity::from_seed(b"ork");
    let payload = Item::Map(vec![
        (Item::Uint(1), Item::Text("tn-1".to_owned())),
        (Item::Uint(2), Item::Text("osk-1".to_owned())),
        (Item::Uint(3), Item::Bytes(ork.cose_key())),
        (
            Item::Uint(4),
            Item::Array(vec![
                Item::Text("ENROLL".to_owned()),
                Item::Text("SUPERUSER".to_owned()),
            ]),
        ),
        (Item::Uint(5), Item::Uint(1)),
        (Item::Uint(6), Item::Uint(2_000_000_000_000)),
        (Item::Uint(7), crit(&["powers"])),
    ]);
    let v = verify_cose_sign1(
        &ork.sign_statement(&payload),
        StatementKind::OwnerDelegation,
        &ork.verifying_key(),
    )
    .expect("signature is fine");
    assert!(decode_owner_delegation(&v).is_err());
}

#[test]
fn a_delegation_carries_exactly_the_powers_it_names() {
    let ork = TestIdentity::from_seed(b"ork");
    let payload = Item::Map(vec![
        (Item::Uint(1), Item::Text("tn-1".to_owned())),
        (Item::Uint(2), Item::Text("osk-1".to_owned())),
        (Item::Uint(3), Item::Bytes(ork.cose_key())),
        (
            Item::Uint(4),
            Item::Array(vec![
                Item::Text("ENROLL".to_owned()),
                Item::Text("POLICY".to_owned()),
            ]),
        ),
        (Item::Uint(5), Item::Uint(1)),
        (Item::Uint(6), Item::Uint(2_000_000_000_000)),
        (Item::Uint(7), crit(&["powers"])),
    ]);
    let v = verify_cose_sign1(
        &ork.sign_statement(&payload),
        StatementKind::OwnerDelegation,
        &ork.verifying_key(),
    )
    .expect("verify");
    let d = decode_owner_delegation(&v).expect("decode");
    assert!(d.has(OskPower::Enroll));
    assert!(d.has(OskPower::Policy));
    assert!(!d.has(OskPower::Revoke), "a power not named is not granted");
}

#[test]
fn a_policy_bundle_decodes_its_header_and_leaves_the_documents_opaque() {
    let osk = TestIdentity::from_seed(b"osk");
    let doc = encode(&Item::Map(vec![(Item::Uint(1), Item::Uint(0))])).expect("doc");
    let payload = Item::Map(vec![
        (Item::Uint(1), Item::Text("tn-1".to_owned())),
        (Item::Uint(2), Item::Uint(42)),
        (Item::Uint(3), Item::Text("policy-main".to_owned())),
        (Item::Uint(4), Item::Bytes(doc.clone())),
        (Item::Uint(5), Item::Bytes(doc.clone())),
        (Item::Uint(6), Item::Bytes(doc.clone())),
        (Item::Uint(7), Item::Bytes(doc.clone())),
        (Item::Uint(8), Item::Bytes(doc)),
        (Item::Uint(9), Item::Uint(2)),
        (Item::Uint(10), Item::Uint(2_000_000_000_000)),
        (
            Item::Uint(11),
            crit(&["policy_version", "killswitch_floor"]),
        ),
    ]);
    let v = verify_cose_sign1(
        &osk.sign_statement(&payload),
        StatementKind::PolicyBundle,
        &osk.verifying_key(),
    )
    .expect("verify");
    let h = decode_policy_bundle(&v).expect("decode");
    assert_eq!(h.policy_version, 42);
    assert_eq!(h.killswitch_floor, 2);
}

/// **Attack test.** `killswitch_floor` is in the required `crit` set precisely
/// so a future restriction on it cannot be ignored. Omitting it must reject.
#[test]
fn a_policy_bundle_omitting_killswitch_floor_from_crit_is_refused() {
    let osk = TestIdentity::from_seed(b"osk");
    let doc = encode(&Item::Map(vec![(Item::Uint(1), Item::Uint(0))])).expect("doc");
    let payload = Item::Map(vec![
        (Item::Uint(1), Item::Text("tn-1".to_owned())),
        (Item::Uint(2), Item::Uint(42)),
        (Item::Uint(3), Item::Text("policy-main".to_owned())),
        (Item::Uint(4), Item::Bytes(doc.clone())),
        (Item::Uint(5), Item::Bytes(doc.clone())),
        (Item::Uint(6), Item::Bytes(doc.clone())),
        (Item::Uint(7), Item::Bytes(doc.clone())),
        (Item::Uint(8), Item::Bytes(doc)),
        (Item::Uint(9), Item::Uint(2)),
        (Item::Uint(10), Item::Uint(2_000_000_000_000)),
        (Item::Uint(11), crit(&["policy_version"])),
    ]);
    let v = verify_cose_sign1(
        &osk.sign_statement(&payload),
        StatementKind::PolicyBundle,
        &osk.verifying_key(),
    )
    .expect("signature is fine");
    assert!(matches!(
        decode_policy_bundle(&v),
        Err(CryptoError::MissingCriticalField {
            field: "killswitch_floor",
            ..
        })
    ));
}

/// **Attack test.** A `TrustEpochBundle` with an empty seal list would advance
/// the epoch while giving nobody the seed — a denial of service dressed as a
/// key rotation.
#[test]
fn a_trust_epoch_bundle_with_no_seals_is_refused() {
    let osk = TestIdentity::from_seed(b"osk");
    let payload = Item::Map(vec![
        (Item::Uint(1), Item::Text("tn-1".to_owned())),
        (Item::Uint(2), Item::Uint(9)),
        (Item::Uint(3), Item::Array(vec![])),
        (Item::Uint(4), Item::Uint(2_000_000_000_000)),
        (Item::Uint(5), crit(&["trust_epoch"])),
    ]);
    let v = verify_cose_sign1(
        &osk.sign_statement(&payload),
        StatementKind::TrustEpochBundle,
        &osk.verifying_key(),
    )
    .expect("signature is fine");
    assert!(decode_trust_epoch_bundle(&v).is_err());
}

#[test]
fn a_trust_epoch_bundle_carries_only_sealed_material() {
    let osk = TestIdentity::from_seed(b"osk");
    let payload = Item::Map(vec![
        (Item::Uint(1), Item::Text("tn-1".to_owned())),
        (Item::Uint(2), Item::Uint(9)),
        (
            Item::Uint(3),
            Item::Array(vec![Item::Map(vec![
                (Item::Uint(1), Item::Bytes(DEVICE_A.to_vec())),
                (Item::Uint(2), Item::Bytes(vec![0xaa; 48])),
            ])]),
        ),
        (Item::Uint(4), Item::Uint(2_000_000_000_000)),
        (Item::Uint(5), crit(&["trust_epoch"])),
    ]);
    let v = verify_cose_sign1(
        &osk.sign_statement(&payload),
        StatementKind::TrustEpochBundle,
        &osk.verifying_key(),
    )
    .expect("verify");
    let b = decode_trust_epoch_bundle(&v).expect("decode");
    assert_eq!(b.trust_epoch, 9);
    assert_eq!(b.seals.len(), 1);
    assert_eq!(b.seals[0].recipient_device_id, DEVICE_A);
    assert_eq!(b.seals[0].sealed.len(), 48);
}
