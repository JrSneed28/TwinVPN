//! Session resumption over time: freshness, revocation, reconnect and restart.
//!
//! **Authority:** ADR-0001 §7.3.2 RS-1 (in-memory only, S-13), RS-5 (refuse a
//! revoked peer), RS-6 (bounded by the rekey schedule); `docs/protocol.md`
//! §12.1 (the trigger list, and "**Not** process restart");
//! `docs/reliability.md` §6.5 (the survival table), §11.3 (the wake sequence).
//!
//! The flow itself, and the attacks against it, live in `tests/resume.rs`.

#[path = "resume/support.rs"]
mod support;

use core::time::Duration;

use support::{armed_pair, hint, park, trusting, ESTABLISHED_EPOCH};
use twinvpn_core::resume::{PeerTrustFacts, ResumeRefusal, RESUMPTION_LIFETIME};
use twinvpn_core::session_loop::{ResumeVerdict, SessionRuntime};
use twinvpn_core::testing;
use twinvpn_platform::iface::ResumeFacts;
use twinvpn_session::resumption::{wire_resume_admissible, Disruption};
use twinvpn_session::state::SessionState;
use twinvpn_session::{Context, Guards, SessionMachine};
use twinvpn_types::{codes, SessionId};

// ---------------------------------------------------------------------------
// 3. Expiry and revocation
// ---------------------------------------------------------------------------

/// **RS-6.** Past the rekey window the material is gone, on the *elapsed*
/// clock — the one a suspend advances.
#[test]
fn a_resume_past_the_rekey_window_is_refused_as_expired_and_the_material_is_dropped() {
    let (mut a, mut b, vt) = armed_pair();
    park(&mut b);

    // A suspend advances the elapsed clock and not the monotonic one, which is
    // exactly the case §11.3 says decides between a resume and a handshake.
    vt.suspend(RESUMPTION_LIFETIME + Duration::from_secs(1));

    let refused = a
        .offer_resume(None, trusting())
        .expect_err("the sender refuses before spending an RTT");
    assert_eq!(refused, ResumeRefusal::Expired);
    assert_eq!(refused.reason_code(), codes::NET_RESUME_STALE);
    assert!(
        a.resumption().is_none(),
        "expired material must be dropped, not retried"
    );

    // And the receiver refuses independently — the rule does not depend on the
    // peer having been correct.
    let (mut fresh_a, mut fresh_b, vt2) = armed_pair();
    let datagram = fresh_a.offer_resume(None, trusting()).expect("fresh");
    vt2.suspend(RESUMPTION_LIFETIME + Duration::from_secs(1));
    park(&mut fresh_b);
    let (verdict, _) =
        fresh_b.resume_on_wire(&datagram, trusting(), Guards::default(), Context::default());
    assert_eq!(verdict, Err(ResumeRefusal::Expired));
    assert!(fresh_b.resumption().is_none());
    assert_eq!(fresh_b.machine().state(), SessionState::Discovering);
}

/// **RS-6's boundary is the rekey-DUE instant, not the key-DEATH instant.**
///
/// The rule is "a `Tunnel` that would rekey MUST rekey rather than resume
/// indefinitely", and a `Tunnel` at 120 s is exactly one that would rekey —
/// `REKEY_AFTER_TIME` is where "the initiator begins a new handshake".
/// `RESUMPTION_LIFETIME` was `REJECT_AFTER_TIME` (180 s, where the keys are
/// zeroed), which admitted a resume across the whole 60 s window RS-6 reserves
/// for the rekey.
///
/// The other tests in this file are written in terms of `RESUMPTION_LIFETIME`,
/// so they passed under either value — which is why this one names the two
/// constants directly. It fails if the bound is moved back to the outer one.
#[test]
fn the_resumption_bound_is_the_rekey_deadline_and_not_the_key_death_deadline() {
    use twinvpn_crypto::noise::{REJECT_AFTER_TIME, REKEY_AFTER_TIME};

    assert_eq!(
        RESUMPTION_LIFETIME, REKEY_AFTER_TIME,
        "RS-6 bounds resumption at the instant the rekey is DUE"
    );
    assert!(
        RESUMPTION_LIFETIME < REJECT_AFTER_TIME,
        "and that instant is strictly before the keys die, or the rule is empty"
    );

    // Behaviourally: one second past the rekey deadline the tunnel would rekey,
    // so a resume must be refused even though the transport keys are still live
    // for another 59 seconds.
    let (mut a, _b, vt) = armed_pair();
    vt.suspend(REKEY_AFTER_TIME + Duration::from_secs(1));
    assert!(REKEY_AFTER_TIME + Duration::from_secs(1) < REJECT_AFTER_TIME);
    assert_eq!(
        a.offer_resume(None, trusting())
            .expect_err("would rekey, so must not resume"),
        ResumeRefusal::Expired
    );
}

/// **RS-5.** A peer revoked since the handshake cannot resume, and the material
/// does not survive the attempt.
#[test]
fn a_resume_from_a_revoked_peer_is_refused() {
    let (mut a, mut b, _vt) = armed_pair();
    park(&mut b);
    let datagram = a.offer_resume(None, trusting()).expect("fresh material");

    let revoked = PeerTrustFacts {
        peer_revoked: true,
        ..trusting()
    };
    let (verdict, _) = b.resume_on_wire(&datagram, revoked, Guards::default(), Context::default());
    assert_eq!(verdict, Err(ResumeRefusal::PeerRevoked));
    assert_eq!(
        verdict.expect_err("revoked").reason_code(),
        codes::AUTH_DEVICE_REVOKED
    );
    assert!(
        b.resumption().is_none(),
        "a revoked peer's material must not stay armed"
    );
    assert_eq!(b.machine().state(), SessionState::Discovering);

    // And the initiating side refuses too, rather than announcing itself to a
    // peer it already knows is revoked.
    assert_eq!(
        a.offer_resume(None, revoked),
        Err(ResumeRefusal::PeerRevoked)
    );
}

/// The contract's own words for field 5: "a lagging peer can refuse rather than
/// resume into a stale trust state".
#[test]
fn a_resumer_whose_revocation_epoch_is_behind_ours_is_refused() {
    let (mut a, mut b, _vt) = armed_pair();
    park(&mut b);
    let datagram = a.offer_resume(None, trusting()).expect("fresh material");

    let ahead = PeerTrustFacts {
        revocation_epoch: trusting().revocation_epoch + 1,
        peer_revoked: false,
    };
    let (verdict, _) = b.resume_on_wire(&datagram, ahead, Guards::default(), Context::default());
    assert_eq!(
        verdict,
        Err(ResumeRefusal::TrustEpochBehind {
            offered: 3,
            local: 4
        })
    );
    assert_eq!(
        verdict.expect_err("behind").reason_code(),
        codes::AUTH_TRUST_EPOCH_ROLLBACK
    );
    assert_eq!(b.machine().state(), SessionState::Discovering);
}

// ---------------------------------------------------------------------------
// 5. Reconnect
// ---------------------------------------------------------------------------

/// A roam, then another roam. §12.1's trigger list, twice, on one `Session`.
#[test]
fn successive_reconnects_resume_on_strictly_increasing_epochs() {
    let (mut a, mut b, vt) = armed_pair();

    for (round, last_octet) in [(1u64, 9u8), (2, 10), (3, 11)] {
        park(&mut b);
        // Time passes between roams, but stays inside the rekey window.
        vt.advance(Duration::from_secs(5));
        let datagram = a
            .offer_resume(Some(hint(last_octet, 51_820)), trusting())
            .expect("still fresh");
        let (verdict, _) =
            b.resume_on_wire(&datagram, trusting(), Guards::default(), Context::default());
        let accepted = verdict.unwrap_or_else(|e| panic!("round {round} refused: {e:?}"));
        assert_eq!(accepted.path_epoch, ESTABLISHED_EPOCH + round);
        assert!(matches!(
            b.machine().state(),
            SessionState::Migrating { .. }
        ));
    }
    assert_eq!(
        b.resumption().expect("armed").highest_accepted_epoch(),
        Some(ESTABLISHED_EPOCH + 3)
    );

    // §6.5's survival contract for the disruptions a reconnect is made of.
    assert!(wire_resume_admissible(Disruption::PathChange));
    assert!(wire_resume_admissible(Disruption::RelayFailover));
}

/// The wake decision, on the elapsed clock, against the same constant the
/// material is bounded by.
#[test]
fn the_wake_verdict_and_the_material_agree_on_one_rekey_window() {
    let short = ResumeVerdict::decide_for_wire_resume(
        &ResumeFacts {
            suspended_for: Some(RESUMPTION_LIFETIME / 2),
            boot_id: None,
            announced_by_os: true,
            hibernated: None,
        },
        None,
    );
    assert!(short.wire_resume_admissible());
    assert_eq!(short.inadmissible_reason(), None);

    let long = ResumeVerdict::decide_for_wire_resume(
        &ResumeFacts {
            suspended_for: Some(RESUMPTION_LIFETIME + Duration::from_secs(1)),
            boot_id: None,
            announced_by_os: true,
            hibernated: None,
        },
        None,
    );
    assert!(!long.wire_resume_admissible());
    assert_eq!(long.inadmissible_reason(), Some(codes::NET_RESUME_STALE));

    // An unmeasured gap is not a short gap, one level down as well.
    let unknown = ResumeVerdict::decide_for_wire_resume(
        &ResumeFacts {
            suspended_for: None,
            boot_id: None,
            announced_by_os: false,
            hibernated: None,
        },
        None,
    );
    assert!(!unknown.wire_resume_admissible());
}

// ---------------------------------------------------------------------------
// 6. Restart
// ---------------------------------------------------------------------------

/// **RS-1 / S-13, and the finding's core claim.** A process restart is *not* a
/// resume.
///
/// The journal restores `RECONNECTING` — which is what `core.rs` already did,
/// and which is what the finding said was mistaken for resumption. This asserts
/// the difference: a restored runtime holds no resumption material, refuses to
/// resume by name, and the code it reports is the one that names a full
/// negotiation.
#[test]
fn a_process_restart_holds_no_resumption_material_and_runs_a_full_handshake() {
    let (mut a, _b, _vt) = armed_pair();
    let datagram = a.offer_resume(None, trusting()).expect("fresh material");

    // The peer restarts: a brand-new runtime for the same `Session`, restored
    // the way `Core::open_store` restores one. Nothing carries the secrets
    // across, because nothing may.
    let (env, _vt2) = testing::env();
    let mut restarted = SessionRuntime::new(
        env.clone(),
        SessionMachine::resumed(
            env,
            SessionId::from_slice(&[2; 16]).expect("16"),
            SessionState::Reconnecting { parked: false },
            None,
        ),
    );
    assert!(
        restarted.resumption().is_none(),
        "RS-1: resumption keys are in-memory only and cannot survive a restart"
    );

    let refusal = restarted
        .accept_resume_offer(&datagram, trusting())
        .expect_err("a restarted peer cannot resume");
    assert_eq!(refusal, ResumeRefusal::NotArmed);
    assert_eq!(refusal.reason_code(), codes::NET_FULL_RENEGOTIATE);
    assert!(refusal.falls_back_to_full_handshake());

    // §6.5's table says the same thing, and says it first: the transport keys
    // are `Lost` across a restart, so the resumption material is too.
    assert!(!wire_resume_admissible(Disruption::ProcessRestart));
    assert!(!wire_resume_admissible(Disruption::SuspendPastRekey));

    // A reboot is classified as a cold start before any datagram is spent.
    let cold = ResumeVerdict::decide_for_wire_resume(
        &ResumeFacts {
            suspended_for: Some(Duration::from_secs(1)),
            boot_id: Some(twinvpn_env::BootId::from_array([2u8; 16])),
            announced_by_os: true,
            hibernated: None,
        },
        Some(twinvpn_env::BootId::from_array([1u8; 16])),
    );
    assert!(!cold.wire_resume_admissible());
    assert_eq!(
        cold.inadmissible_reason(),
        Some(codes::NET_FULL_RENEGOTIATE)
    );
}
