//! **F-2, fail-closed.** Every way the composed C-B ceremony refuses, and the
//! registered code each refusal carries.
//!
//! **Authority:** ADR-0007 §7.4 (C-D authorization, "always required"), N-2,
//! N-15, N-16, N-17, N-18, N-25(1); ADR-0018 CD-1a, §11.16 (l);
//! `contracts/cddl/twinvpn/v1/pairing_offer.cddl`; `ownership.md` W-22, W-12.
//!
//! The working half lives in `tests/pairing.rs`; both share
//! `tests/pairing/harness.rs`.
//!
//! Each test asserts **two** things: the registered code, and — where the
//! refusal is supposed to happen before the ceremony touches anything — that the
//! element was never asked to sign. A refusal that arrived after the element had
//! already signed would still be a refusal, and would still be wrong.
//!
//! | Case the finding asks for | Test |
//! |---|---|
//! | unauthorized | [`a_core_with_no_enrolment_record_refuses_to_begin_a_pairing`], [`an_approver_without_enroll_power_cannot_begin_a_pairing`] |
//! | expired | [`the_ceremony_window_expires_and_cancelling_burns_the_id_as_expired`] |
//! | revoked | [`a_revoked_device_does_not_get_to_enrol_a_peer`] |

#[path = "pairing/harness.rs"]
mod harness;

use std::time::Duration;

use harness::{
    bare, begin, begin_with, body_from_events, delegation, enrolled, enrolled_with, named,
    pairing_id_from_events, refused, status_of, APPROVER, DEVICE_IK_SEED, EXPIRED, PENDING,
    WALL_MS,
};
use twinvpn_core::pairing::{Ceremony, PairingEnrolment};
use twinvpn_crypto::statements::{OskPower, RevocationStatement};
use twinvpn_crypto::testkit::FixtureIdentity;
use twinvpn_env::WallClockReading;
use twinvpn_mgmt::{CoreCommand, Submission};
use twinvpn_trust::owner::VerifiedSigner;
use twinvpn_trust::{AnchorChain, RevocationState};
use twinvpn_types::{codes, Identifier as _};

// ---------------------------------------------------------------------------
// Unauthorized
// ---------------------------------------------------------------------------

/// **Unauthorized (a).** ADR-0007 §7.4 marks authorization "always required",
/// and a core with no Owner chain cannot check it. It refuses rather than
/// proceeding without the check — which is the whole difference between a
/// device that will not enrol and one that enrols anybody.
///
/// **The code is `AUTH.IDENTITY_MISSING`, not the authorization spelling, and
/// the distinction is the point.** "This device is not enrolled" and "the
/// approver lacks ENROLL power" are two different operator problems with two
/// different next actions, and only one of them is fixed by getting an OSK
/// approval. `enforce.rs`'s `arm` already sets the precedent for the first.
/// `an_approver_without_enroll_power_cannot_begin_a_pairing` is the other half
/// of this pair and still asserts `AUTH.PAIRING_NOT_AUTHORIZED`, so a build that
/// merged the two would fail one of them.
#[test]
fn a_core_with_no_enrolment_record_refuses_to_begin_a_pairing() {
    let (core, adapter, _time) = bare();
    assert_eq!(
        refused(&core, &begin(b"key-unenrolled")),
        codes::AUTH_IDENTITY_MISSING
    );
    assert_eq!(
        adapter.identity_mock().sign_calls(),
        0,
        "an unauthorized device's element is never asked to sign"
    );
}

/// **Unauthorized (b).** C-D requires the `ENROLL` power specifically: "an OSK
/// device holding `ENROLL` power approves". An OSK that may set policy may not
/// enrol a device, `AnchorChain::authorize` is where that distinction lives, and
/// this proves the composed core consults it rather than checking mere presence.
#[test]
fn an_approver_without_enroll_power_cannot_begin_a_pairing() {
    let h = enrolled_with(vec![OskPower::Policy], RevocationState::new());
    assert_eq!(
        refused(&h.core, &begin(b"key-wrong-power")),
        codes::AUTH_PAIRING_NOT_AUTHORIZED
    );
    assert_eq!(h.adapter.identity_mock().sign_calls(), 0);
}

/// **Attack test.** The enrolment record injects this device's `COSE_Key`,
/// because the platform seam declares no encoding for the element's own — see
/// `twinvpn_core::pairing`'s module documentation. N-2 is what stops that
/// injection being a way in: `identity_id = SHA-256(ik_pub_cose)`, so a
/// perfectly well-formed key belonging to somebody else cannot be enrolled.
#[test]
fn a_cose_key_that_is_not_this_devices_key_is_refused() {
    let (core, adapter, _time) = bare();

    let mut chain = AnchorChain::new();
    chain
        .install_delegation(delegation(vec![OskPower::Enroll]))
        .expect("install");
    let impostor = FixtureIdentity::from_seed(b"somebody-elses-ik").cose_key();
    core.install_pairing_enrolment(
        PairingEnrolment::new(
            chain,
            vec![VerifiedSigner::osk(APPROVER)],
            RevocationState::new(),
            impostor,
            "rv.example".to_owned(),
        )
        .expect("well-formed"),
    );

    assert_eq!(
        refused(&core, &begin(b"key-impostor")),
        codes::AUTH_IDENTITY_MISMATCH
    );
    assert_eq!(adapter.identity_mock().sign_calls(), 0);
}

/// **Unauthorized (c), and the reason the two codes must not merge — F-2A.**
///
/// A device that knows its own identity and has no `ENROLL`-powered OSK is
/// **constructible** and is refused `AUTH.PAIRING_NOT_AUTHORIZED` at the first
/// ceremony, by `AnchorChain::authorize` — not at construction.
///
/// This test used to assert the opposite, and the change is F-2A's. Refusing an
/// empty approver set at construction meant a composition root that had proved
/// this device's key but held no Owner material could install **nothing**, so
/// `pair.begin` answered `AUTH.IDENTITY_MISSING` on a device whose identity was
/// perfectly well known — a refusal wrong in the optimistic direction, which is
/// `ownership.md` §11.2 G-14's own defect class.
///
/// Read with `a_core_with_no_enrolment_record_refuses_to_begin_a_pairing`: same
/// operation, two different missing facts, two different codes. A build that
/// merged them would fail one of the two.
#[test]
fn a_device_that_knows_its_identity_and_holds_no_approval_is_not_authorized() {
    let (core, adapter, _time) = bare();
    let cose = FixtureIdentity::from_seed(DEVICE_IK_SEED).cose_key();
    adapter
        .identity_mock()
        .rotate(twinvpn_trust::derive_identity_id(&cose));

    // An empty chain and an empty approver set: no Owner has authorized this
    // device to enrol anyone. The record is still well formed.
    let enrolment = PairingEnrolment::new(
        AnchorChain::new(),
        Vec::new(),
        RevocationState::new(),
        cose,
        String::new(),
    )
    .expect("a record with a key and no approver is well formed");
    core.install_pairing_enrolment(enrolment);

    assert_eq!(
        refused(&core, &begin(b"key-unapproved")),
        codes::AUTH_PAIRING_NOT_AUTHORIZED
    );
    // And it refused before asking the element for anything, which is the order
    // §7.4's table fixes: authorization first.
    assert_eq!(adapter.identity_mock().sign_calls(), 0);
}

/// **F-2A's N-2 proof, and the thing it must never do.**
///
/// `IdentityPublic::public_key` carries "the public key bytes, **in the
/// element's own encoding**" with no declared encoding to parse, so the
/// composition root cannot *choose* one — `ownership.md` G-21. It proves one
/// instead: a candidate is this device's key **iff** `SHA-256` over it equals
/// the `identity_id` the element reports, which is ADR-0007 N-2's definition.
///
/// The three cases below are the whole of that rule. The third is the one that
/// matters: an element reporting a well-formed key that names some *other*
/// device yields `None`, so nothing is installed and `pair.begin` refuses
/// `AUTH.IDENTITY_MISSING` rather than enrolling under a name this device cannot
/// prove.
#[test]
fn a_key_is_admitted_only_when_n2_says_it_names_this_device() {
    use twinvpn_core::pairing::enrol::ik_pub_cose_for;
    use twinvpn_platform::custody::IdentityPublic;

    let ik = FixtureIdentity::from_seed(DEVICE_IK_SEED);
    let cose = ik.cose_key();
    let identity = |public_key: Vec<u8>| IdentityPublic {
        device_id: twinvpn_crypto::derive_device_id(&cose),
        identity_id: twinvpn_crypto::derive_identity_id(&cose),
        generation: 0,
        public_key,
    };

    // (a) The element vends the dCBOR COSE_Key itself.
    assert_eq!(
        ik_pub_cose_for(&identity(cose.clone())).as_ref(),
        Some(&cose)
    );

    // (b) It vends an SPKI — the encoding `cose::es256_cose_key_from_verifying_key`
    //     documents as the device's own IK path. The same octets come back,
    //     because the COSE encoding has exactly one home.
    assert_eq!(
        ik_pub_cose_for(&identity(ik.spki_der())).as_ref(),
        Some(&cose)
    );

    // (c) It vends **someone else's** key, well formed and wrong. N-2 refuses
    //     it: the digest does not match the identity_id this element reports.
    let stranger = FixtureIdentity::from_seed(b"some-other-device");
    assert!(ik_pub_cose_for(&identity(stranger.spki_der())).is_none());
    assert!(ik_pub_cose_for(&identity(stranger.cose_key())).is_none());

    // And bytes that are neither encoding are refused without a guess.
    assert!(ik_pub_cose_for(&identity(vec![0xff; 91])).is_none());
    assert!(ik_pub_cose_for(&identity(Vec::new())).is_none());
}

/// A record with **no key at all** is still refused at construction, and with
/// the identity spelling: a record that cannot name this device is not a record.
#[test]
fn an_enrolment_record_with_no_identity_key_is_refused_at_construction() {
    let refusal = PairingEnrolment::new(
        AnchorChain::new(),
        vec![VerifiedSigner::osk(APPROVER)],
        RevocationState::new(),
        Vec::new(),
        String::new(),
    )
    .expect_err("a record with no COSE_Key names no device");
    assert_eq!(refusal.code(), codes::AUTH_IDENTITY_MISSING);
}

// ---------------------------------------------------------------------------
// Expired
// ---------------------------------------------------------------------------

/// **Expired.** N-17's 120-second window, "enforced independently by both
/// devices AND the rendezvous". This is one of the three, and it burns the id:
/// `identifiers.md` says an id is never reissued "not even after expiry or
/// cancellation", because reissuing would reset the five-attempt budget that
/// makes a short code safe.
///
/// The timeout is surfaced as `AUTH.PAIRING_EXPIRED` and never as a generic
/// abort, which `pairing.proto` requires in terms.
#[test]
fn the_ceremony_window_expires_and_cancelling_burns_the_id_as_expired() {
    let h = enrolled();
    h.core.submit(&begin(b"key-expiring")).expect("pair.begin");
    let pairing_id = pairing_id_from_events(&h.core);

    // Inside the window, the ceremony is live.
    h.time.advance(Duration::from_secs(119));
    assert_eq!(status_of(&h.core, &pairing_id), PENDING);

    // One second past it, the read already says so — without burning anything,
    // because `pair.status` is `Idempotency::ReadOnly` and burning is an act.
    h.time.advance(Duration::from_secs(2));
    assert_eq!(status_of(&h.core, &pairing_id), EXPIRED);

    // The next operation that *acts* is where the burn happens.
    assert_eq!(
        refused(&h.core, &named(CoreCommand::PairCancel, &pairing_id)),
        codes::AUTH_PAIRING_EXPIRED
    );

    // And the recorded terminal outcome is EXPIRED, not ABORTED: a second
    // cancel returns the original rather than overwriting it with a fresh one.
    assert_eq!(status_of(&h.core, &pairing_id), EXPIRED);
    h.core
        .submit(&named(CoreCommand::PairCancel, &pairing_id))
        .expect("cancel is idempotent over a burned id");
    assert_eq!(
        body_from_events(&h.core, CoreCommand::PairCancel)[0],
        EXPIRED,
        "a replayed cancel returns the ORIGINAL outcome, not a fresh abort"
    );
}

/// **CD-1a.** A device with no usable wall clock cannot state field 7's expiry.
/// It refuses rather than emitting an offer dated to 1970 — the worst possible
/// direction, since that offer's `exp` check fails at every peer with no
/// diagnosis on either side.
#[test]
fn a_device_with_no_wall_clock_refuses_rather_than_dating_an_offer_to_1970() {
    let h = enrolled();
    h.time.set_wall(WallClockReading::Unset);
    assert_eq!(
        refused(&h.core, &begin(b"key-no-clock")),
        codes::AUTH_CLOCK_IMPLAUSIBLE
    );
    assert_eq!(h.adapter.identity_mock().sign_calls(), 0);
}

/// An id this core never began burns nothing. Without this a caller could
/// consume identifiers it does not own, and a `pairing_id` is single-use for
/// life.
#[test]
fn an_unknown_pairing_id_is_refused_by_both_local_reads() {
    let h = enrolled();
    assert_eq!(
        refused(&h.core, &named(CoreCommand::PairCancel, &[0x77; 16])),
        codes::AUTH_PAIRING_NOT_AUTHORIZED
    );
    assert_eq!(
        refused(&h.core, &named(CoreCommand::PairStatus, &[0x77; 16])),
        codes::AUTH_PAIRING_NOT_AUTHORIZED
    );
}

// ---------------------------------------------------------------------------
// Revoked
// ---------------------------------------------------------------------------

/// **Revoked.** N-25(1): peer refusal is **local** and "takes effect the instant
/// a device verifies an Owner-signed `RevocationRecord`". A device the Owner has
/// revoked does not get to hand out an offer that would enrol a peer into a
/// TwinNet it is no longer in.
#[test]
fn a_revoked_device_does_not_get_to_enrol_a_peer() {
    // The identity the mock reports once the fixture key is installed.
    let cose = FixtureIdentity::from_seed(DEVICE_IK_SEED).cose_key();
    let identity_id = twinvpn_trust::derive_identity_id(&cose);

    let mut revocation = RevocationState::new();
    revocation.refuse_on_statement(&RevocationStatement {
        twinnet_id: "tn-test".to_owned(),
        // The mock element's `device_id`, which a rotation leaves unchanged
        // (`identifiers.md` §2).
        target_device_id: [0xd0; 32],
        target_identity_id: Some(<[u8; 32]>::try_from(identity_id.as_bytes()).expect("32 bytes")),
        effective_from_ms: WALL_MS,
        reason_code: "AUTH.DEVICE_REVOKED".to_owned(),
        issuer_osk_id: APPROVER.to_owned(),
    });

    let h = enrolled_with(vec![OskPower::Enroll], revocation);
    assert_eq!(
        refused(&h.core, &begin(b"key-revoked")),
        codes::AUTH_DEVICE_REVOKED
    );
    assert_eq!(
        h.adapter.identity_mock().sign_calls(),
        0,
        "a revoked device's element is never asked to sign"
    );
}

// ---------------------------------------------------------------------------
// The ceremonies and capabilities this build does not have
// ---------------------------------------------------------------------------

/// **C-A fails closed.** W-22: no audited RFC 9382 P-256 implementation is in
/// the dependency table, `twinvpn_trust::pairing::Spake2Exchange` has no
/// implementation anywhere in the workspace, and N-15 forbids substituting a
/// construction that permits offline testing of a nine-digit code.
///
/// So the ceremony type that would need it is refused by name — never quietly
/// run as C-B instead, which N-16 would make unanswerable after the fact.
#[test]
fn the_human_code_ceremony_is_refused_by_name() {
    let h = enrolled();
    assert_eq!(
        refused(&h.core, &begin_with(Ceremony::HumanCode, b"key-spake2")),
        codes::PROTO_CAPABILITY_MISSING
    );
    assert_eq!(h.adapter.identity_mock().sign_calls(), 0);
}

/// A `pair.begin` that names no ceremony at all is refused before anything is
/// touched. N-16 makes the method an audit fact, so there is no default.
#[test]
fn a_begin_that_names_no_ceremony_is_refused_before_any_work() {
    let h = enrolled();
    let mut submission = begin(b"key-no-selector");
    submission.params.clear();
    assert_eq!(
        refused(&h.core, &submission),
        codes::PROTO_MALFORMED_MESSAGE
    );
    assert_eq!(h.adapter.identity_mock().sign_calls(), 0);
}

/// **§11.16 (l).** A device whose element will not sign is refused, not signed
/// for by something else: "the core MUST NOT substitute a file-backed signer
/// silently."
#[test]
fn a_device_whose_element_is_unavailable_is_refused_not_substituted_for() {
    let h = enrolled();
    h.adapter.identity_mock().set_unavailable(true);
    assert_eq!(
        refused(&h.core, &begin(b"key-locked")),
        codes::AUTH_KEY_UNAVAILABLE
    );
}

/// **The secret never crosses the MI.** `pairing_offer.cddl` gives the offer NO
/// rendering path into the diagnostic ledger, syslog, a Tier-1 bundle or any log
/// level in any build profile. So `pair.begin`'s body is the PUBLIC `pairing_id`
/// and the offer leaves only through the scoped borrow.
#[test]
fn the_offer_never_crosses_the_management_interface() {
    let h = enrolled();
    h.core.submit(&begin(b"key-secret")).expect("pair.begin");
    let pairing_id = pairing_id_from_events(&h.core);

    let secret = h
        .core
        .with_pairing_offer(&pairing_id, |offer| *offer.pairing_secret())
        .expect("in flight");

    // What the MI published for the operation.
    assert!(
        !pairing_id.windows(secret.len()).any(|w| w == secret),
        "the pairing secret must not appear in a command result"
    );
    // And what any `Debug` rendering of the instance would put in a bundle.
    let rendered = format!("{:?}", h.core);
    let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        !rendered.contains(&hex),
        "no Debug rendering may carry the pairing secret"
    );
}

/// The `pair.confirm` refusal that legitimately remains, and the reason it
/// carries.
///
/// N-18 confirms a ceremony "on both devices or on neither", so it needs both
/// `PairingAttestation`s — and this build can produce neither half. If somebody
/// later writes an emitter for this device's own and a rendezvous for the
/// peer's, this test is what tells them the dispatcher still says otherwise.
#[test]
fn pair_confirm_still_refuses_and_says_why() {
    let h = enrolled();
    match twinvpn_core::dispatch::disposition(CoreCommand::PairConfirm) {
        twinvpn_core::dispatch::Disposition::NotWired { code, why } => {
            assert_eq!(code, codes::CONTROL_UNREACHABLE);
            assert!(
                why.contains("emit_pairing_attestation"),
                "the reason must name what is missing, re-measured: {why}"
            );
        }
        twinvpn_core::dispatch::Disposition::Executes => {
            panic!("pair.confirm cannot execute without both attestations (N-18)")
        }
    }
    // And the refusal is what a caller actually meets, not just what the
    // register claims.
    let submission = Submission {
        op: CoreCommand::PairConfirm,
        params: Vec::new(),
        idempotency_key: Some(b"key-confirm".to_vec()),
        if_version: None,
        actor_principal: None,
    };
    assert_eq!(refused(&h.core, &submission), codes::CONTROL_UNREACHABLE);
}
