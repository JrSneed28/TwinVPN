//! Wire-level session resumption: the flow, and the attacks against it.
//!
//! **Authority:** ADR-0001 §7.3.2 RS-1 to RS-7; `docs/protocol.md` §12.1;
//! `docs/reliability.md` §4.5 T35, §6.2, §6.5; ADR-0018 CD-1, CD-2.
//!
//! Every test drives two real `SessionRuntime`s — one per peer — against a
//! shared `VirtualTime`. Nothing here reads a wall clock, sleeps, or opens a
//! socket: the datagram is handed from one peer to the other as bytes, which is
//! the whole of §12.1's transport requirement, and time moves only where a test
//! says it does.
//!
//! Freshness, revocation, reconnect and restart live in
//! `tests/resume_lifecycle.rs`.

#[path = "resume/support.rs"]
mod support;

use prost::Message as _;
use support::{armed_elsewhere, armed_pair, hint, nonce, park, ESTABLISHED_EPOCH};
use twinvpn_core::resume::ResumeRefusal;
use twinvpn_core::testing;
use twinvpn_session::state::SessionState;
use twinvpn_session::{Context, Guards};
use twinvpn_types::{codes, Identifier as _, SessionNonce};

use support::trusting;

// ---------------------------------------------------------------------------
// 1. Success
// ---------------------------------------------------------------------------

/// **The producer and the consumer, meeting.** One datagram, no key exchange,
/// no control plane — §12.1's whole contract — and the transition it earns.
#[test]
fn a_resume_that_authenticates_is_accepted_and_re_binds_the_tunnel() {
    let (mut a, mut b, _vt) = armed_pair();
    park(&mut b);

    let datagram = a
        .offer_resume(Some(hint(9, 51_820)), trusting())
        .expect("the initiator holds fresh material");

    // The datagram really is a `ResumeSession` plus a tag, and it names the
    // handle the responder answers to — nothing here is a private encoding.
    let body = &datagram[..datagram.len() - 16];
    let decoded = twinvpn_schema::v1::ResumeSession::decode(body).expect("a frozen ResumeSession");
    assert_eq!(decoded.session_nonce, nonce().as_bytes());
    assert_eq!(
        decoded.resumption_id.as_slice(),
        b.resumption().expect("armed").resumption_id().as_slice(),
        "both peers derive one resumption_id from one handshake"
    );
    assert!(
        decoded.path_epoch > ESTABLISHED_EPOCH,
        "RS-4: the first resume must present a strictly greater path_epoch"
    );

    let (verdict, _outcome) =
        b.resume_on_wire(&datagram, trusting(), Guards::default(), Context::default());
    let accepted = verdict.expect("the responder must accept its peer's resume");
    assert_eq!(accepted.path_epoch, ESTABLISHED_EPOCH + 1);
    assert_eq!(accepted.reason_code(), codes::NET_RESUME_OK);
    assert_eq!(
        accepted.new_endpoint_hint.map(|e| e.port.get()),
        Some(51_820),
        "the roaming hint survives the round trip"
    );

    // §4.5 T35's first arm: an existing `Tunnel` re-bound to a new `Path`
    // (RS-3), not a second `Session`.
    assert!(
        matches!(b.machine().state(), SessionState::Migrating { .. }),
        "an authenticated resume must migrate, not re-discover; state was {:?}",
        b.machine().state()
    );
    assert_eq!(
        b.resumption()
            .expect("still armed")
            .highest_accepted_epoch(),
        Some(ESTABLISHED_EPOCH + 1)
    );
}

// ---------------------------------------------------------------------------
// 2. Replay
// ---------------------------------------------------------------------------

/// **Attack test — RS-4.** The same datagram, twice.
///
/// The second copy authenticates perfectly: it is the first copy. Only the
/// `path_epoch` rule separates them, which is why RS-4 exists and why this is
/// the test that would catch its removal.
#[test]
fn a_replayed_resume_is_refused_and_forces_a_full_handshake() {
    let (mut a, mut b, _vt) = armed_pair();
    park(&mut b);
    let datagram = a.offer_resume(None, trusting()).expect("fresh material");

    b.resume_on_wire(&datagram, trusting(), Guards::default(), Context::default())
        .0
        .expect("the first copy is accepted");
    let highest = b
        .resumption()
        .expect("armed")
        .highest_accepted_epoch()
        .expect("one accepted");

    park(&mut b);
    let (verdict, _) =
        b.resume_on_wire(&datagram, trusting(), Guards::default(), Context::default());
    assert_eq!(
        verdict,
        Err(ResumeRefusal::Replayed {
            path_epoch: ESTABLISHED_EPOCH + 1
        })
    );
    let refusal = verdict.expect_err("replayed");
    assert_eq!(refusal.reason_code(), codes::CRYPTO_REPLAY_DETECTED);
    assert!(refusal.falls_back_to_full_handshake());
    assert!(
        refusal.silent_on_the_wire(),
        "RS-4: a stale path_epoch is dropped silently, never answered"
    );
    assert_eq!(
        b.resumption().expect("armed").highest_accepted_epoch(),
        Some(highest),
        "a replay must not move the window it failed against"
    );
    assert_eq!(
        b.machine().state(),
        SessionState::Discovering,
        "every refusal falls back to a full handshake (§12.1)"
    );
}

/// **Attack test — RS-4 is stricter than the window it reads, and this is the
/// case that separates them.**
///
/// A `path_epoch` below the high-water mark but never seen is precisely what an
/// anti-replay *window* exists to accept: reordering on a lossy data path is
/// normal, and `ReplayWindow::accept` admits it. A resume is not a data frame.
/// RS-4 says "at or below the highest seen MUST be dropped", so the strict
/// comparison sits on top of the window — and if it were removed, an attacker
/// who recorded an old resume could re-bind the `Session` to a stale
/// `new_endpoint_hint` while the window happily called it fresh.
#[test]
fn a_resume_below_the_high_water_mark_is_refused_even_though_it_was_never_seen() {
    let (mut a, mut b, _vt) = armed_pair();
    let old = a.offer_resume(None, trusting()).expect("epoch 8");
    let _skipped = a.offer_resume(None, trusting()).expect("epoch 9");
    let newest = a.offer_resume(None, trusting()).expect("epoch 10");

    park(&mut b);
    let accepted = b
        .accept_resume_offer(&newest, trusting())
        .expect("the newest resume is accepted");
    assert_eq!(accepted.path_epoch, ESTABLISHED_EPOCH + 3);

    // Never seen, well inside the window's 8192-bit reach, and still refused.
    assert_eq!(
        b.accept_resume_offer(&old, trusting()),
        Err(ResumeRefusal::Replayed {
            path_epoch: ESTABLISHED_EPOCH + 1
        }),
        "RS-4 refuses an unseen counter below the high-water mark; a bare \
         sliding window would have taken it"
    );
    assert_eq!(
        b.resumption().expect("armed").highest_accepted_epoch(),
        Some(ESTABLISHED_EPOCH + 3)
    );
}

/// **Attack test — reflection.** The initiator's own datagram, sent back at it.
///
/// Both peers hold the same `resumption_secret`, so a MAC that did not name a
/// direction would verify here and let an off-path attacker advance the
/// victim's window using nothing but the victim's own bytes.
#[test]
fn a_resume_reflected_back_at_its_sender_does_not_authenticate() {
    let (mut a, _b, _vt) = armed_pair();
    let datagram = a.offer_resume(None, trusting()).expect("fresh material");
    assert_eq!(
        a.accept_resume_offer(&datagram, trusting()),
        Err(ResumeRefusal::Unauthenticated)
    );
}

// ---------------------------------------------------------------------------
// 4. Malformed state
// ---------------------------------------------------------------------------

/// **Attack test.** Nothing malformed, forged or misdirected may move the
/// window, and none of it may be accepted.
#[test]
fn malformed_forged_and_misdirected_resumes_are_all_refused_without_moving_the_window() {
    let (mut a, mut b, _vt) = armed_pair();
    let good = a.offer_resume(None, trusting()).expect("fresh material");
    let before = b.resumption().expect("armed").highest_accepted_epoch();

    // Too short to hold a tag at all.
    assert!(matches!(
        b.accept_resume_offer(&good[..8], trusting()),
        Err(ResumeRefusal::Malformed { .. })
    ));
    // A body that is not a `ResumeSession` at all.
    let mut junk = vec![0xffu8; 24];
    junk.extend_from_slice(&[0u8; 16]);
    assert!(matches!(
        b.accept_resume_offer(&junk, trusting()),
        Err(ResumeRefusal::Malformed { .. })
    ));
    // A well-formed message with an unparseable endpoint hint: rejected on the
    // *field*, after the MAC, which is why it is built and signed properly.
    let mut broken_hint = hint(9, 51_820);
    broken_hint.port = 0; // `common.proto`: port 0 is malformed.
    let with_bad_hint = a
        .offer_resume(Some(broken_hint), trusting())
        .expect("fresh material");
    let refusal = b
        .accept_resume_offer(&with_bad_hint, trusting())
        .expect_err("port 0 is malformed");
    assert!(matches!(refusal, ResumeRefusal::Malformed { .. }));

    // A single flipped bit in the tag.
    let mut forged = good.clone();
    let last = forged.len() - 1;
    forged[last] ^= 0x01;
    assert_eq!(
        b.accept_resume_offer(&forged, trusting()),
        Err(ResumeRefusal::Unauthenticated)
    );
    // A single flipped bit in the body, with the original tag.
    let mut tampered = good.clone();
    tampered[0] ^= 0x01;
    assert!(matches!(
        b.accept_resume_offer(&tampered, trusting()),
        Err(ResumeRefusal::Malformed { .. } | ResumeRefusal::Unauthenticated)
    ));
    // A perfectly good resume for a different `Session`.
    let (other_env, _other_vt) = testing::env();
    let mut other = armed_elsewhere(
        &other_env,
        3,
        SessionNonce::from_slice(&[0x22; 16]).expect("16"),
    );
    let elsewhere = other.offer_resume(None, trusting()).expect("fresh");
    assert_eq!(
        b.accept_resume_offer(&elsewhere, trusting()),
        Err(ResumeRefusal::WrongSession)
    );

    assert_eq!(
        b.resumption().expect("armed").highest_accepted_epoch(),
        before,
        "no refused datagram may advance the anti-replay window"
    );
    // The genuine article still works afterwards, so none of the above poisoned
    // the state — the failure mode a window advanced by forged input produces.
    assert!(b.accept_resume_offer(&good, trusting()).is_ok());
}
