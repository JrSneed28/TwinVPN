//! ADR-0001's composition rule, rekey schedule, replay window and endpoint
//! migration, asserted against a stub crypto binding.

use core::time::Duration;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use twinvpn_env::MonotonicInstant;
use twinvpn_tunnel::crypto::{CryptoUnavailable, Prologue, TransportKeys};
use twinvpn_tunnel::engine::{Tunnel, TunnelError, TunnelState};
use twinvpn_tunnel::negotiate::{self, Advertisement, MonotonicFloor, OwnerLocalAction, Selection};
use twinvpn_tunnel::rekey::{self, Action, KeepalivePolicy, KeyState};
use twinvpn_tunnel::replay::{ReplayWindow, SendCounter, WINDOW_BITS};
use twinvpn_tunnel::transport::{self, TransportMode};
use twinvpn_types::{Endpoint, IpAddr, Port, SessionId, TunnelId, V4Addr};

/// A stub standing in for `twinvpn-crypto`. It performs no cryptography — it
/// exists to prove the engine drives the boundary and never crosses it.
struct StubKeys {
    zeroized: Arc<AtomicUsize>,
    fail: bool,
}

impl TransportKeys for StubKeys {
    fn seal(
        &self,
        counter: u64,
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoUnavailable> {
        if self.fail {
            return Err(CryptoUnavailable);
        }
        out.extend_from_slice(&counter.to_le_bytes());
        out.extend_from_slice(plaintext);
        Ok(())
    }
    fn open(
        &self,
        _counter: u64,
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoUnavailable> {
        if self.fail {
            return Err(CryptoUnavailable);
        }
        out.extend_from_slice(ciphertext);
        Ok(())
    }
    fn zeroize(&mut self) {
        self.zeroized.fetch_add(1, Ordering::SeqCst);
    }
}

fn endpoint(last: u8) -> Endpoint {
    Endpoint::new(
        IpAddr::V4(V4Addr::from_octets([203, 0, 113, last])),
        Port::new(51820).unwrap(),
    )
}

fn established(zeroized: &Arc<AtomicUsize>) -> Tunnel {
    let now = MonotonicInstant::ORIGIN;
    let mut t = Tunnel::absent(
        TunnelId::from_array([1; 16]),
        SessionId::from_array([2; 16]),
        now,
    );
    t.handshake_completed(
        Box::new(StubKeys {
            zeroized: Arc::clone(zeroized),
            fail: false,
        }),
        endpoint(1),
        7,
        now,
    );
    t.confirm_negotiation(&[9u8; 32], &[9u8; 32]).unwrap();
    assert_eq!(t.state(), TunnelState::Established);
    t
}

// ---------------------------------------------------------------------------
// §7.3.1 — the prologue
// ---------------------------------------------------------------------------

#[test]
fn the_prologue_is_exactly_eighty_three_bytes_and_redacts_itself() {
    let p = Prologue::new([1u8; 32], [2u8; 32]);
    assert_eq!(Prologue::LEN, 83);
    assert_eq!(p.as_bytes().len(), 83);
    assert_eq!(&p.as_bytes()[..19], Prologue::LABEL);
    assert_eq!(&p.as_bytes()[19..51], &[1u8; 32]);
    assert_eq!(&p.as_bytes()[51..83], &[2u8; 32]);
    // P-3: it is never transmitted, so it never renders either.
    assert_eq!(format!("{p:?}"), "Prologue(<83 B redacted>)");
}

// ---------------------------------------------------------------------------
// §7.2's composition rule — the one this ADR calls the most important
// ---------------------------------------------------------------------------

#[test]
fn switching_transport_changes_nothing_l_data_cares_about() {
    let z = Arc::new(AtomicUsize::new(0));
    let mut t = established(&z);
    // Send and receive so the counters are non-trivial.
    let mut out = Vec::new();
    t.seal(b"hello", &mut out).unwrap();
    t.seal(b"again", &mut out).unwrap();
    let mut plain = Vec::new();
    t.open(5, b"ciphertext", &mut plain).unwrap();

    let before = t.security_snapshot();
    for mode in [
        TransportMode::Relay,
        TransportMode::Quic,
        TransportMode::Udp,
    ] {
        let after = t.switch_transport(mode);
        assert!(
            after.unchanged_from(&before),
            "switching to {mode:?} disturbed L-DATA state"
        );
        assert_eq!(t.transport(), mode);
        assert_eq!(t.state(), TunnelState::Established, "no re-handshake");
        assert!(!mode.requires_handshake());
        assert!(!mode.contributes_to_l_data_security());
    }
    assert!(!transport::transport_change_costs_a_handshake());
    assert_eq!(z.load(Ordering::SeqCst), 0, "no key was zeroed");
}

// ---------------------------------------------------------------------------
// §7.6 — endpoint migration
// ---------------------------------------------------------------------------

#[test]
fn a_staged_endpoint_receives_only_the_probe_until_it_validates() {
    let z = Arc::new(AtomicUsize::new(0));
    let mut t = established(&z);
    assert_eq!(t.authoritative_endpoint(), Some(endpoint(1)));

    t.offer_endpoint(endpoint(2));
    assert_eq!(
        t.authoritative_endpoint(),
        Some(endpoint(1)),
        "the previous endpoint remains authoritative"
    );
    assert!(!t.may_carry_bulk(endpoint(2)));
    assert!(t.may_carry_bulk(endpoint(1)));

    // A failed validation MUST NOT tear down the Session, and must not commit.
    assert!(!t.commit_endpoint(false));
    assert_eq!(t.state(), TunnelState::Established);
    assert_eq!(t.authoritative_endpoint(), Some(endpoint(1)));

    // A successful one commits.
    assert!(t.commit_endpoint(true));
    assert_eq!(t.authoritative_endpoint(), Some(endpoint(2)));
    assert!(t.may_carry_bulk(endpoint(2)));
}

// ---------------------------------------------------------------------------
// §7.2's rekey schedule
// ---------------------------------------------------------------------------

#[test]
fn the_rekey_constants_are_the_ones_adr_0001_fixes() {
    assert_eq!(rekey::REKEY_AFTER_TIME, Duration::from_secs(120));
    assert_eq!(rekey::REJECT_AFTER_TIME, Duration::from_secs(180));
    assert_eq!(rekey::REKEY_ATTEMPT_TIME, Duration::from_secs(90));
    assert_eq!(rekey::REKEY_AFTER_MESSAGES, 1u64 << 60);
    assert_eq!(rekey::REJECT_AFTER_MESSAGES, u64::MAX - (1 << 13) - 1);
    // The 60 s overlap is the reliability property, not an accident.
    assert_eq!(
        rekey::REJECT_AFTER_TIME - rekey::REKEY_AFTER_TIME,
        rekey::REKEY_OVERLAP
    );
    assert_eq!(KeyState::overlap_window(), Duration::from_secs(60));
}

#[test]
fn a_rekey_begins_at_120s_and_the_keys_die_at_180s() {
    let t0 = MonotonicInstant::ORIGIN;
    let mut k = KeyState::new(t0);
    assert_eq!(k.evaluate(t0), Action::Continue);
    assert_eq!(
        k.evaluate(t0.saturating_add(Duration::from_secs(119))),
        Action::Continue
    );
    assert_eq!(
        k.evaluate(t0.saturating_add(rekey::REKEY_AFTER_TIME)),
        Action::BeginRekey
    );
    // Keys are still usable through the overlap.
    assert!(k.keys_usable(t0.saturating_add(Duration::from_secs(179))));
    k.begin_rekey(t0.saturating_add(rekey::REKEY_AFTER_TIME));
    assert_eq!(
        k.evaluate(t0.saturating_add(rekey::REJECT_AFTER_TIME)),
        Action::ZeroizeKeys
    );
    assert!(!k.keys_usable(t0.saturating_add(rekey::REJECT_AFTER_TIME)));
}

#[test]
fn a_broken_handshake_is_a_bounded_reportable_event_rather_than_a_hang() {
    let t0 = MonotonicInstant::ORIGIN;
    let mut k = KeyState::new(t0);
    k.begin_rekey(t0);
    assert_eq!(
        k.evaluate(t0.saturating_add(Duration::from_secs(89))),
        Action::Continue
    );
    assert_eq!(
        k.evaluate(t0.saturating_add(rekey::REKEY_ATTEMPT_TIME)),
        Action::AttemptExhausted,
        "turns 'it just hangs' into a bounded event with a reason code"
    );
}

#[test]
fn a_rekey_is_in_place_and_never_creates_a_new_tunnel() {
    let z = Arc::new(AtomicUsize::new(0));
    let mut t = established(&z);
    let id_before = t.id();
    let gen_before = t.key_generation();
    let now = MonotonicInstant::ORIGIN.saturating_add(rekey::REKEY_AFTER_TIME);
    t.begin_rekey(now);
    assert_eq!(t.state(), TunnelState::Rekeying);
    assert!(
        t.state().carries_traffic(),
        "the overlap keeps traffic flowing"
    );
    t.complete_rekey(
        Box::new(StubKeys {
            zeroized: Arc::clone(&z),
            fail: false,
        }),
        now,
    );
    assert_eq!(t.id(), id_before, "same Tunnel, new key generation");
    assert_eq!(t.key_generation(), gen_before + 1);
    assert_eq!(t.state(), TunnelState::Established);
}

#[test]
fn a_long_suspend_forces_a_full_handshake_on_the_elapsed_clock() {
    // reliability §11.3 and T35: the ElapsedClock delta decides, not the
    // monotonic one, which does not advance across suspend.
    assert!(!KeyState::force_full_handshake(Duration::from_secs(60)));
    assert!(KeyState::force_full_handshake(Duration::from_secs(
        8 * 3600
    )));
}

#[test]
fn the_persistent_keepalive_runs_only_behind_nat_or_on_a_relay() {
    let direct = KeepalivePolicy {
        peer_behind_nat: false,
        relayed: false,
    };
    assert!(!direct.persistent_runs());
    assert_eq!(
        direct.interval(false),
        None,
        "a clean direct path pays nothing"
    );
    assert_eq!(
        direct.interval(true),
        Some(rekey::PASSIVE_KEEPALIVE),
        "10 s after receiving data with nothing to send"
    );
    for p in [
        KeepalivePolicy {
            peer_behind_nat: true,
            relayed: false,
        },
        KeepalivePolicy {
            peer_behind_nat: false,
            relayed: true,
        },
    ] {
        assert!(p.persistent_runs());
        assert_eq!(p.interval(false), Some(rekey::PERSISTENT_KEEPALIVE));
    }
}

// ---------------------------------------------------------------------------
// The replay window
// ---------------------------------------------------------------------------

#[test]
fn the_window_starts_where_the_protocol_starts_and_accepts_counter_zero() {
    // D-1's regression test. Every previous test in this file started at
    // counter 1, so the seam between the sender's first counter and the
    // receiver's window origin was the one place nobody looked.
    let mut w = ReplayWindow::new();

    // An empty window has accepted nothing — NOT "counter 0 has been seen".
    assert!(
        !w.has_accepted_any(),
        "a fresh window must distinguish 'nothing received' from 'counter 0 received'"
    );
    assert!(
        w.would_accept(0),
        "a conforming peer sends counter 0 first; refusing it breaks every \
         correct implementation regardless of what our own sender does"
    );

    assert!(w.accept(0), "the first record of every tunnel");
    assert!(w.has_accepted_any());
    assert_eq!(w.highest(), 0);

    // And exactly once: counter 0 is a replay the second time.
    assert!(
        !w.accept(0),
        "a duplicate counter 0 is still CRYPTO.REPLAY_DETECTED"
    );
    assert!(!w.would_accept(0));

    // The sequence continues normally from there.
    assert!(w.accept(1));
    assert!(!w.accept(1));
    assert_eq!(w.highest(), 1);
    // ...and counter 0 is still remembered after the window slid forward.
    assert!(!w.accept(0), "sliding the window must not forget counter 0");
}

#[test]
fn a_sender_and_a_receiver_agree_from_the_very_first_record() {
    // The end-to-end shape the tripwire used: one tunnel seals, its peer opens.
    // Neither crate's suite ran a sender against a receiver before, which is
    // why an off-by-one at the origin survived a green suite.
    let z = Arc::new(AtomicUsize::new(0));
    let mut sender = established(&z);
    let mut receiver = established(&z);

    for expected in 0u64..4 {
        let mut wire = Vec::new();
        let counter = sender.seal(b"payload", &mut wire).expect("seal");
        assert_eq!(counter, expected, "the counter sequence is 0-based");
        let mut plain = Vec::new();
        receiver
            .open(counter, &wire, &mut plain)
            .unwrap_or_else(|e| panic!("record {counter} rejected: {e:?}"));
    }

    // And a replay of the first record is still refused.
    let mut wire = Vec::new();
    sender.seal(b"payload", &mut wire).expect("seal");
    let mut plain = Vec::new();
    assert_eq!(
        receiver.open(0, &wire, &mut plain),
        Err(TunnelError::Replay),
        "replaying the first record must still be FATAL"
    );
}

#[test]
fn the_window_is_the_eight_thousand_one_hundred_ninety_two_adr_0001_specifies() {
    // ADR-0001 §7.1: "64-bit nonce counter + 8192-bit sliding receive window
    // (RFC 6479 style)". ADR-0013 §11.5 sizes per-peer memory against the same
    // 8192-entry bitmap. This build shipped 2048 until D-1's fix.
    assert_eq!(WINDOW_BITS, 8_192);
}

#[test]
fn the_replay_window_refuses_a_duplicate_and_accepts_ordinary_reordering() {
    let mut w = ReplayWindow::new();
    assert!(w.accept(1));
    assert!(w.accept(2));
    assert!(!w.accept(2), "a duplicate is CRYPTO.REPLAY_DETECTED");
    assert!(!w.accept(1));
    // Reordering inside the window is fine.
    assert!(w.accept(10));
    assert!(w.accept(5));
    assert!(!w.accept(5));
    assert_eq!(w.highest(), 10);
}

#[test]
fn a_counter_more_than_the_window_behind_is_refused_rather_than_growing_the_window() {
    let mut w = ReplayWindow::new();
    assert!(w.accept(WINDOW_BITS + 100));
    assert!(
        !w.accept(1),
        "a bigger window would be an unbounded allocation an attacker drives"
    );
    assert!(w.accept(WINDOW_BITS + 99));
}

#[test]
fn the_send_counter_refuses_to_wrap_because_it_is_the_aead_nonce() {
    let mut c = SendCounter::new();
    assert_eq!(c.take_next(), Some(0));
    assert_eq!(c.take_next(), Some(1));
    assert_eq!(c.issued(), 2);
    assert!(!c.rekey_due());
}

#[test]
fn an_exhausted_counter_refuses_to_seal_rather_than_reusing_a_nonce() {
    // The engine surfaces it as a typed error, not as a wrapped counter.
    let z = Arc::new(AtomicUsize::new(0));
    let mut t = established(&z);
    let mut out = Vec::new();
    // A healthy send works.
    assert!(t.seal(b"x", &mut out).is_ok());
    // A failing crypto binding is a drop, not a degraded accept.
    let mut broken = Tunnel::absent(
        TunnelId::from_array([3; 16]),
        SessionId::from_array([4; 16]),
        MonotonicInstant::ORIGIN,
    );
    broken.handshake_completed(
        Box::new(StubKeys {
            zeroized: Arc::clone(&z),
            fail: true,
        }),
        endpoint(1),
        7,
        MonotonicInstant::ORIGIN,
    );
    broken.confirm_negotiation(&[1u8; 32], &[1u8; 32]).unwrap();
    assert_eq!(broken.seal(b"x", &mut out), Err(TunnelError::Crypto));
}

#[test]
fn a_replayed_counter_surfaces_as_a_typed_error_from_the_engine() {
    let z = Arc::new(AtomicUsize::new(0));
    let mut t = established(&z);
    let mut plain = Vec::new();
    assert!(t.open(1, b"c", &mut plain).is_ok());
    assert_eq!(t.open(1, b"c", &mut plain), Err(TunnelError::Replay));
}

// ---------------------------------------------------------------------------
// N-8, N-9 and D2 — negotiation is confirmed inside the tunnel
// ---------------------------------------------------------------------------

#[test]
fn traffic_does_not_flow_until_the_transcript_matches() {
    let z = Arc::new(AtomicUsize::new(0));
    let now = MonotonicInstant::ORIGIN;
    let mut t = Tunnel::absent(
        TunnelId::from_array([1; 16]),
        SessionId::from_array([2; 16]),
        now,
    );
    t.handshake_completed(
        Box::new(StubKeys {
            zeroized: Arc::clone(&z),
            fail: false,
        }),
        endpoint(1),
        7,
        now,
    );
    assert_eq!(t.state(), TunnelState::Confirming);
    assert!(!t.state().carries_traffic(), "N-9: the gap is named");
    let mut out = Vec::new();
    assert_eq!(t.seal(b"x", &mut out), Err(TunnelError::NotEstablished));
}

#[test]
fn a_transcript_mismatch_tears_down_the_tunnel_and_zeroes_the_keys() {
    let z = Arc::new(AtomicUsize::new(0));
    let now = MonotonicInstant::ORIGIN;
    let mut t = Tunnel::absent(
        TunnelId::from_array([1; 16]),
        SessionId::from_array([2; 16]),
        now,
    );
    t.handshake_completed(
        Box::new(StubKeys {
            zeroized: Arc::clone(&z),
            fail: false,
        }),
        endpoint(1),
        7,
        now,
    );
    assert_eq!(
        t.confirm_negotiation(&[1u8; 32], &[2u8; 32]),
        Err(TunnelError::TranscriptMismatch)
    );
    assert_eq!(t.state(), TunnelState::Closed);
    assert_eq!(
        z.load(Ordering::SeqCst),
        1,
        "keys are zeroed, not left around"
    );
    // The Session survives a Tunnel teardown.
    assert_eq!(t.session(), SessionId::from_array([2; 16]));
}

// ---------------------------------------------------------------------------
// ADR-0014 — selection, the caps, and the monotonic floor
// ---------------------------------------------------------------------------

fn ad(v_min: u32, v_max: u32, caps: &[&str]) -> Advertisement {
    Advertisement {
        v_min,
        v_max,
        capabilities: caps.iter().map(|s| (*s).to_owned()).collect(),
    }
}

#[test]
fn selection_takes_the_highest_mutually_supported_epoch_and_the_intersection() {
    let ours = ad(1, 5, &["relay_udp", "rekey_in_place", "dns_split"]);
    let theirs = ad(3, 7, &["relay_udp", "dns_split", "site_remap"]);
    let s = negotiate::select(&ours, &theirs).expect("the ranges overlap");
    assert_eq!(s.epoch, 5);
    assert_eq!(
        s.capabilities,
        ["dns_split", "relay_udp"]
            .iter()
            .map(|x| (*x).to_owned())
            .collect::<BTreeSet<_>>()
    );
    // Non-overlapping ranges are PROTO.VERSION_UNSUPPORTED, not a guess.
    assert!(negotiate::select(&ad(1, 2, &[]), &ad(5, 7, &[])).is_none());
}

/// CF-6 amended ADR-0014 N-11 from 24 to 32 and `registry_version` 2 carried
/// that into `limits.json`, so the cap is now **derived** from the frozen
/// registry rather than pinned against a disagreeing one. The 27-byte
/// `security_relevant` token CF-6 declined to rename is what would fail if the
/// two ever disagreed again.
#[test]
fn the_capability_name_cap_is_thirty_two_and_comes_from_the_registry() {
    assert_eq!(negotiate::Caps::MAX_NAME_BYTES, 32);
    // The Phase-1-mandated 27-byte token validates.
    let a = ad(1, 1, &["dns_config_dies_with_tunnel"]);
    assert!(a.validate(1).is_ok());
}

#[test]
fn an_over_cap_advertisement_is_rejected_before_anything_is_allocated_from_it() {
    let many: Vec<String> = (0..40).map(|i| format!("cap_{i}")).collect();
    let a = Advertisement {
        v_min: 1,
        v_max: 1,
        capabilities: many.into_iter().collect(),
    };
    assert!(a.validate(1).is_err());
    // An epoch far above the current one is refused too.
    let far = ad(1, 10_000, &[]);
    assert!(far.validate(1).is_err());
}

#[test]
fn the_floor_refuses_a_downgrade_and_names_what_would_be_lost() {
    let secrel: BTreeSet<String> = ["relay_udp".to_owned(), "dns_split".to_owned()]
        .into_iter()
        .collect();
    let mut floor = MonotonicFloor::new();
    let strong = Selection {
        epoch: 5,
        capabilities: secrel.clone(),
    };
    assert!(floor.record(&strong, &secrel, true));
    assert_eq!(floor.epoch(), 5);

    // A lower epoch is refused.
    let older = Selection {
        epoch: 4,
        capabilities: secrel.clone(),
    };
    assert!(!floor.admits(&older, &secrel));

    // A same-epoch offer missing a security-relevant token is refused, and the
    // diagnostic can name it.
    let weakened = Selection {
        epoch: 5,
        capabilities: ["relay_udp".to_owned()].into_iter().collect(),
    };
    assert!(!floor.admits(&weakened, &secrel));
    assert_eq!(floor.lost_tokens(&weakened), vec!["dns_split".to_owned()]);
}

#[test]
fn the_floor_covers_only_the_security_relevant_subset() {
    // N-19: an honest device whose OS revokes a NON-security-relevant permission
    // must still be able to reconnect.
    let secrel: BTreeSet<String> = ["relay_udp".to_owned()].into_iter().collect();
    let mut floor = MonotonicFloor::new();
    let full = Selection {
        epoch: 3,
        capabilities: ["relay_udp".to_owned(), "portmap".to_owned()]
            .into_iter()
            .collect(),
    };
    floor.record(&full, &secrel, true);
    assert_eq!(floor.security_relevant().len(), 1);

    let without_portmap = Selection {
        epoch: 3,
        capabilities: ["relay_udp".to_owned()].into_iter().collect(),
    };
    assert!(
        floor.admits(&without_portmap, &secrel),
        "losing a non-security-relevant token must not brick reconnection"
    );
}

#[test]
fn an_unconfirmed_selection_is_never_written_to_the_floor() {
    let secrel: BTreeSet<String> = ["relay_udp".to_owned()].into_iter().collect();
    let mut floor = MonotonicFloor::new();
    let s = Selection {
        epoch: 9,
        capabilities: secrel.clone(),
    };
    // P-4: not confirmed in-session, so nothing is written.
    assert!(!floor.record(&s, &secrel, false));
    assert_eq!(floor.epoch(), 0);
    assert!(floor.security_relevant().is_empty());
}

#[test]
fn clearing_the_floor_requires_an_authenticated_local_owner_action() {
    let secrel: BTreeSet<String> = ["relay_udp".to_owned()].into_iter().collect();
    let mut floor = MonotonicFloor::new();
    floor.record(
        &Selection {
            epoch: 5,
            capabilities: secrel.clone(),
        },
        &secrel,
        true,
    );
    assert_eq!(floor.epoch(), 5);
    // The only way to clear it takes the proof as an argument.
    floor.clear(OwnerLocalAction::authenticated());
    assert_eq!(floor.epoch(), 0);
    assert!(floor.security_relevant().is_empty());
}

#[test]
fn the_negotiated_set_is_immutable_for_the_tunnels_lifetime() {
    assert!(
        !negotiate::negotiated_set_is_mutable_mid_session(),
        "renegotiation requires a NEW Tunnel, never a mutated one"
    );
}
