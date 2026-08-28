//! The binding table, tested by refusal.
//!
//! Ported from the unit tests `rendezvous-connectivity` wrote in
//! `services/rendezvous/src/binding.rs` and duplicated in `services/presence`,
//! plus the regression for a defect the port exposed
//! (`a_refused_connection_does_not_release_a_hold_it_never_took`).

use std::time::{Duration, Instant};

use twinvpn_service_common::binding::{
    Binding, BindingCardinality, BindingLimits, ChannelPinned, Claim, Refusal,
};
use twinvpn_service_common::tls::ChannelIdentity;
use twinvpn_service_common::Component;

type Device = [u8; 32];

fn key(n: u8) -> ChannelIdentity {
    ChannelIdentity::new(&[n; 64])
}

fn device(n: u8) -> Device {
    [n; 32]
}

// ---------------------------------------------------------------------------
// The invariant
// ---------------------------------------------------------------------------

#[test]
fn a_first_claim_is_accepted() {
    let mut b: ChannelPinned<Device> = ChannelPinned::default();
    assert_eq!(b.claim(&key(1), device(1), Instant::now()), Claim::Accepted);
}

#[test]
fn a_second_key_cannot_take_a_bound_subject() {
    // The attack, in its plainest form.
    let mut b: ChannelPinned<Device> = ChannelPinned::default();
    let now = Instant::now();
    assert_eq!(b.claim(&key(1), device(7), now), Claim::Accepted);
    assert_eq!(
        b.claim(&key(2), device(7), now),
        Claim::Refused(Refusal::SubjectHeldByAnotherChannel)
    );
    assert_eq!(b.refusals(), 1);
}

#[test]
fn a_channel_cannot_speak_for_a_second_subject() {
    let mut b: ChannelPinned<Device> = ChannelPinned::default();
    let now = Instant::now();
    assert_eq!(b.claim(&key(1), device(1), now), Claim::Accepted);
    assert_eq!(
        b.claim(&key(1), device(2), now),
        Claim::Refused(Refusal::ChannelSpeaksForAnotherSubject)
    );
}

#[test]
fn the_same_key_may_reclaim_freely() {
    let mut b: ChannelPinned<Device> = ChannelPinned::default();
    let now = Instant::now();
    assert_eq!(b.claim(&key(1), device(3), now), Claim::Accepted);
    b.release(&key(1), &device(3), now);
    assert_eq!(b.claim(&key(1), device(3), now), Claim::Accepted);
}

#[test]
fn a_binding_outlives_the_connection_so_a_reconnect_race_is_lost_by_the_attacker() {
    let mut b: ChannelPinned<Device> = ChannelPinned::default();
    let t0 = Instant::now();
    b.claim(&key(1), device(4), t0);
    b.release(&key(1), &device(4), t0);
    // The victim's connection is gone; the attacker tries immediately.
    assert_eq!(
        b.claim(&key(9), device(4), t0 + Duration::from_millis(1)),
        Claim::Refused(Refusal::SubjectHeldByAnotherChannel)
    );
}

#[test]
fn a_binding_does_lapse_so_a_rotated_key_is_not_locked_out_for_ever() {
    let mut b: ChannelPinned<Device> = ChannelPinned::default();
    let t0 = Instant::now();
    b.claim(&key(1), device(5), t0);
    b.release(&key(1), &device(5), t0);
    let later = t0 + Duration::from_millis(600_001);
    assert_eq!(b.claim(&key(2), device(5), later), Claim::Accepted);
}

// ---------------------------------------------------------------------------
// The regression this port exposed
// ---------------------------------------------------------------------------

#[test]
fn a_refused_connection_does_not_release_a_hold_it_never_took() {
    // THE DEFECT, as it was. `release` took only a channel and decremented every
    // entry that channel held. So: a device opens connection A and binds D. It
    // opens connection B with the SAME key, claims D' and is refused. B closes,
    // and the server — which releases at teardown, as `presence/src/server.rs`
    // does — dropped A's hold on D while A was still live. The channel could
    // then speak for a second subject, which is exactly the invariant this
    // module exists to enforce.
    //
    // `release` now takes the subject the caller actually claimed, so a refused
    // connection has nothing to release and cannot express the bug.
    let mut b: ChannelPinned<Device> = ChannelPinned::default();
    let now = Instant::now();

    // Connection A, live, holding D.
    assert_eq!(b.claim(&key(1), device(1), now), Claim::Accepted);

    // Connection B, same key, refused.
    assert_eq!(
        b.claim(&key(1), device(2), now),
        Claim::Refused(Refusal::ChannelSpeaksForAnotherSubject)
    );

    // B tears down. It took nothing, so it releases nothing — and the only
    // subject it could name is one it does not hold.
    b.release(&key(1), &device(2), now);

    // A is still live and still holds D exclusively.
    assert_eq!(
        b.claim(&key(1), device(3), now),
        Claim::Refused(Refusal::ChannelSpeaksForAnotherSubject),
        "the refused connection's teardown released the live connection's hold"
    );
    assert_eq!(
        b.claim(&key(2), device(1), now),
        Claim::Refused(Refusal::SubjectHeldByAnotherChannel),
        "the binding became takeable while its holder was still connected"
    );
}

#[test]
fn a_channel_cannot_release_a_subject_it_does_not_hold() {
    // The other half of the same fix: naming the subject is not enough, because
    // a caller could otherwise release someone else's binding by guessing one.
    let mut b: ChannelPinned<Device> = ChannelPinned::default();
    let now = Instant::now();
    assert_eq!(b.claim(&key(1), device(1), now), Claim::Accepted);

    b.release(&key(2), &device(1), now);

    assert_eq!(
        b.claim(&key(2), device(1), now),
        Claim::Refused(Refusal::SubjectHeldByAnotherChannel),
        "an unrelated channel released a binding it did not hold"
    );
}

#[test]
fn two_connections_on_one_key_each_release_exactly_one_hold() {
    let mut b: ChannelPinned<Device> = ChannelPinned::default();
    let t0 = Instant::now();
    // The same device, connected twice, claiming its own subject on both.
    assert_eq!(b.claim(&key(1), device(1), t0), Claim::Accepted);
    assert_eq!(b.claim(&key(1), device(1), t0), Claim::Accepted);

    // One connection drops. The binding is still held by the other, so it is
    // still exclusive.
    b.release(&key(1), &device(1), t0);
    assert_eq!(
        b.claim(&key(1), device(2), t0),
        Claim::Refused(Refusal::ChannelSpeaksForAnotherSubject)
    );
}

// ---------------------------------------------------------------------------
// Capacity
// ---------------------------------------------------------------------------

#[test]
fn a_held_binding_is_never_evicted_for_capacity() {
    let mut b: ChannelPinned<Device> = ChannelPinned::new(BindingLimits {
        max_bindings: 2,
        ..BindingLimits::default()
    });
    let now = Instant::now();
    b.claim(&key(1), device(1), now);
    b.claim(&key(2), device(2), now);
    // Both are held; a third must be refused rather than evicting a live binding
    // and handing away the subject it protects.
    assert_eq!(
        b.claim(&key(3), device(3), now),
        Claim::Refused(Refusal::TableAtCapacity)
    );
    assert!(b.len() <= 2);
}

#[test]
fn a_capacity_refusal_is_not_a_binding_mismatch() {
    // It is a different fact and gets a different code. Answering
    // CHANNEL_BINDING_MISMATCH here would tell a caller its subject was taken
    // when it was not — an oracle, and a wrong one.
    assert_eq!(
        Refusal::TableAtCapacity.reason_code(),
        twinvpn_service_common::codes::CONTROL_ADMISSION_DEFERRED
    );
    for r in [
        Refusal::ChannelSpeaksForAnotherSubject,
        Refusal::SubjectHeldByAnotherChannel,
    ] {
        assert_eq!(
            r.reason_code(),
            twinvpn_service_common::codes::CONTROL_CHANNEL_BINDING_MISMATCH
        );
    }
}

#[test]
fn an_unheld_binding_is_evictable_so_the_table_stays_bounded() {
    let mut b: ChannelPinned<Device> = ChannelPinned::new(BindingLimits {
        max_bindings: 4,
        ..BindingLimits::default()
    });
    let now = Instant::now();
    for i in 0..1000u32 {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&i.to_be_bytes());
        let k = ChannelIdentity::new(&i.to_be_bytes());
        b.claim(&k, id, now);
        b.release(&k, &id, now);
    }
    assert!(b.len() <= 4, "held {}", b.len());
}

// ---------------------------------------------------------------------------
// The refusal is a security event and names nothing
// ---------------------------------------------------------------------------

#[test]
fn the_refusal_is_fatal_critical_and_names_no_subject() {
    // `trust-boundaries.md` §4: "a security event, never a parse error".
    let code = Refusal::SubjectHeldByAnotherChannel.reason_code();
    assert_eq!(code.severity(), twinvpn_types::ErrorSeverity::Critical);
    assert_eq!(code.class(), twinvpn_types::ErrorClass::Fatal);
    assert!(code.terminal());

    // Structurally cannot name the subject: the frozen registry declares no
    // evidence fields for this code at all.
    assert!(
        code.evidence_fields().is_empty(),
        "the registry gained evidence fields for a binding mismatch: {:?}",
        code.evidence_fields()
    );
    let env = Refusal::SubjectHeldByAnotherChannel
        .to_error(Component::RendezvousClient)
        .envelope();
    assert_eq!(env.reason_code, "CONTROL.CHANNEL_BINDING_MISMATCH");
    assert!(env.evidence.is_empty());
}

#[test]
fn the_table_debug_prints_counts_and_never_a_subject() {
    let mut b: ChannelPinned<Device> = ChannelPinned::default();
    let now = Instant::now();
    b.claim(&key(0xAB), device(0xCD), now);
    let rendered = format!("{b:?}");
    assert!(rendered.contains("bound: 1"), "{rendered}");
    assert!(!rendered.contains("205"), "{rendered}"); // 0xCD
    assert!(!rendered.contains("171"), "{rendered}"); // 0xAB
}

// ---------------------------------------------------------------------------
// The relay's shape
// ---------------------------------------------------------------------------

#[test]
fn many_subjects_per_channel_relaxes_only_the_converse_half() {
    // A relay carrying several flows for one `relay_sub` legitimately speaks for
    // several subjects on one authenticated channel.
    let mut b: ChannelPinned<Device> = ChannelPinned::new(BindingLimits {
        cardinality: BindingCardinality::ManySubjectsPerChannel,
        ..BindingLimits::default()
    });
    let now = Instant::now();
    assert_eq!(b.claim(&key(1), device(1), now), Claim::Accepted);
    assert_eq!(
        b.claim(&key(1), device(2), now),
        Claim::Accepted,
        "a relay must be able to carry a second flow"
    );

    // But the impersonation half does NOT relax, under any cardinality.
    assert_eq!(
        b.claim(&key(2), device(1), now),
        Claim::Refused(Refusal::SubjectHeldByAnotherChannel),
        "the anti-impersonation half relaxed with the cardinality"
    );
    assert_eq!(
        b.claim(&key(2), device(2), now),
        Claim::Refused(Refusal::SubjectHeldByAnotherChannel)
    );
}

#[test]
fn the_default_cardinality_is_the_strict_one() {
    // A service that says nothing gets the device shape, not the relay shape.
    assert_eq!(
        BindingLimits::default().cardinality,
        BindingCardinality::OneSubjectPerChannel
    );
    let b: ChannelPinned<Device> = ChannelPinned::default();
    assert_eq!(
        b.limits().cardinality,
        BindingCardinality::OneSubjectPerChannel
    );
}

#[test]
fn a_subject_need_not_be_a_device_id() {
    // The generalisation axis: a relay binds a `relay_sub`, not a device_id.
    let mut b: ChannelPinned<String> = ChannelPinned::default();
    let now = Instant::now();
    assert_eq!(
        b.claim(&key(1), "relay-sub-local-1".to_owned(), now),
        Claim::Accepted
    );
    assert_eq!(
        b.claim(&key(2), "relay-sub-local-1".to_owned(), now),
        Claim::Refused(Refusal::SubjectHeldByAnotherChannel)
    );
}

#[test]
fn a_swept_binding_is_gone_rather_than_merely_expired() {
    let mut b: ChannelPinned<Device> = ChannelPinned::default();
    let t0 = Instant::now();
    b.claim(&key(1), device(1), t0);
    b.release(&key(1), &device(1), t0);
    assert_eq!(b.len(), 1);
    b.sweep(t0 + Duration::from_millis(600_001));
    assert_eq!(b.len(), 0);
    assert!(b.is_empty());
}
