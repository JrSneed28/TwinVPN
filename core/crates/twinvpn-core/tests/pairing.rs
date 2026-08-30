//! **F-2.** The composed C-B pairing ceremony, driven end to end with no shell:
//! the cases where it **works**.
//!
//! **Authority:** ADR-0007 §7.4, N-2, N-4, N-16, N-17; ADR-0008 §11.3 and N-4;
//! ADR-0018 CB-2 (the falsification test), CD-5; `ownership.md` §11.4 D-6,
//! §11.2 G-14, G-17, G-21.
//!
//! Every test binds a mock adapter and a virtual clock, so the whole ceremony
//! runs on a plain CI runner — CB-2's requirement that "with every shell deleted
//! and a mock adapter bound, the core must still make every decision correctly".
//!
//! The fail-closed half lives in `tests/pairing_refusals.rs`; both share
//! `tests/pairing/harness.rs`.
//!
//! | Case the finding asks for | Test |
//! |---|---|
//! | positive | [`an_enrolled_device_mints_one_offer_and_opens_its_ceremony`] |
//! | replayed | [`a_duplicate_begin_returns_the_original_pairing_id_and_one_ceremony`] |
//! | concurrent / idempotent | [`eight_concurrent_begins_produce_one_ceremony`] |

#[path = "pairing/harness.rs"]
mod harness;

use std::time::Duration;

use harness::{
    begin, body_from_events, enrolled, named, pairing_id_from_events, status_of, ABORTED, EXPIRED,
    PENDING, WALL_MS,
};
use twinvpn_core::pairing::PAIRING_ID_BYTES;
use twinvpn_mgmt::CoreCommand;

// ---------------------------------------------------------------------------
// Positive
// ---------------------------------------------------------------------------

/// **The positive case.** An enrolled device with an `ENROLL`-powered approver,
/// a usable clock and a live element begins one C-B ceremony, and the offer it
/// mints carries all four of `pairing_offer.cddl`'s producer-owned fields.
///
/// This is what F-2 said did not exist: the ledger is `twinvpn-trust`'s, the
/// three producers are `twinvpn-crypto`'s, and until now nothing connected them.
#[test]
fn an_enrolled_device_mints_one_offer_and_opens_its_ceremony() {
    let h = enrolled();
    h.core.submit(&begin(b"key-1")).expect("pair.begin");
    let pairing_id = pairing_id_from_events(&h.core);

    // The element was actually asked to sign field 4. Without this assertion the
    // ceremony could be satisfied by a blob the core signed for itself, which is
    // exactly what §11.16 (l) forbids.
    assert_eq!(
        h.adapter.identity_mock().sign_calls(),
        1,
        "field 4 is a COSE_Sign1 the element produced (N-4)"
    );

    let encoded = h
        .core
        .with_pairing_offer(&pairing_id, |offer| {
            // Field 1 names the ceremony: `pairing_id = SHA-256(secret)[0..16]`.
            assert_eq!(offer.pairing_id(), pairing_id);
            // Field 2, the ES256 COSE_Key (G-21's single home).
            assert!(!offer.ik_pub_cose().is_empty());
            // Field 3, this device's X25519 static, and never the zero point.
            assert_ne!(offer.tk_pub(), &[0u8; 32]);
            // Field 4, the TunnelKeyBinding.
            assert!(!offer.binding().is_empty());
            // Field 7: `issued + 120 000`, ADR-0007 §7.4.
            assert_eq!(offer.not_after_ms(), WALL_MS + 120_000);
            // And the offer encodes to the bytes ADR-0023 E1 and E2 are two
            // views of — a producer that could not encode would be a refusal at
            // every peer, found here rather than there.
            twinvpn_crypto::pairing_offer::encode(offer).expect("the offer encodes")
        })
        .expect("the offer is in flight");
    assert!(!encoded.is_empty());

    // And the ceremony is open, reported by the read that does not act.
    assert_eq!(status_of(&h.core, &pairing_id), PENDING);
}

/// The offer this device emits is one a receiver accepts. Encoding rule 1
/// requires that "two conforming producers MUST emit byte-identical output for
/// the same logical value", and the cheapest proof that the composed producer
/// conforms is that `twinvpn-crypto`'s own decoder takes its output back.
#[test]
fn the_emitted_offer_decodes_at_a_receiver() {
    let h = enrolled();
    h.core.submit(&begin(b"key-roundtrip")).expect("pair.begin");
    let pairing_id = pairing_id_from_events(&h.core);

    let octets = h
        .core
        .with_pairing_offer(&pairing_id, |offer| {
            twinvpn_crypto::pairing_offer::encode(offer).expect("encode")
        })
        .expect("in flight");

    let received = twinvpn_crypto::pairing_offer::decode(&octets).expect("a receiver decodes it");
    assert_eq!(received.pairing_id(), pairing_id);
    // Rule 5, the half the receiver owns: the window this device named is inside
    // `pairing.ceremony_expiry_ms` of the receiver's own now.
    twinvpn_crypto::pairing_offer::check_window(&received, WALL_MS).expect("the window is honest");
    // And the ceremony channel key derives, which is what every subsequent
    // message is wrapped under.
    received.derive_k_pair().expect("K_pair derives");
}

/// N-16: "the ceremony method MUST be recorded … 'which ceremony did this trust
/// come from' is an audit question that cannot be answered retroactively."
///
/// The recorded method is only reachable through the ledger, and cancelling is
/// what reads it back out.
#[test]
fn a_cancelled_ceremony_reaches_a_recorded_terminal_state() {
    let h = enrolled();
    h.core.submit(&begin(b"key-recorded")).expect("pair.begin");
    let pairing_id = pairing_id_from_events(&h.core);
    assert_eq!(status_of(&h.core, &pairing_id), PENDING);

    h.core
        .submit(&named(CoreCommand::PairCancel, &pairing_id))
        .expect("pair.cancel");
    assert_eq!(
        body_from_events(&h.core, CoreCommand::PairCancel)[0],
        ABORTED
    );
    assert_eq!(status_of(&h.core, &pairing_id), ABORTED);
}

// ---------------------------------------------------------------------------
// Replayed
// ---------------------------------------------------------------------------

/// **Replayed.** `contract-matrix.md` §3: "`BeginPairing` duplicate → the
/// **original** `pairing_id`." A retry reuses its `idempotency_key` (ADR-0008
/// N-4), and the second call must find the first's answer rather than mint a
/// second secret and burn a second identifier.
#[test]
fn a_duplicate_begin_returns_the_original_pairing_id_and_one_ceremony() {
    let h = enrolled();
    h.core.submit(&begin(b"key-retried")).expect("first");
    let first = pairing_id_from_events(&h.core);

    h.core.submit(&begin(b"key-retried")).expect("retry");
    let second = pairing_id_from_events(&h.core);

    assert_eq!(first, second, "a retry gets the original pairing_id");
    assert_eq!(
        h.adapter.identity_mock().sign_calls(),
        1,
        "a retry does not ask the element for a second signature"
    );

    // A genuinely new operation is a new key, and that IS a second ceremony —
    // idempotency must not collapse two distinct pairings into one.
    h.core.submit(&begin(b"key-different")).expect("new");
    assert_ne!(first, pairing_id_from_events(&h.core));
}

/// A replay after the ceremony is over still returns the recorded outcome.
///
/// The contract calls this the rule that prevents asymmetric trust: a replay
/// that produced a *different* answer is how two devices come to disagree about
/// whether they trust each other, "which produces a mutual-authentication
/// failure at every subsequent handshake that looks like a crypto bug and is
/// actually a delivery bug".
#[test]
fn a_replay_after_cancellation_still_returns_the_recorded_pairing_id() {
    let h = enrolled();
    h.core.submit(&begin(b"key-then-cancel")).expect("begin");
    let pairing_id = pairing_id_from_events(&h.core);
    h.core
        .submit(&named(CoreCommand::PairCancel, &pairing_id))
        .expect("cancel");

    h.core.submit(&begin(b"key-then-cancel")).expect("replay");
    assert_eq!(
        pairing_id_from_events(&h.core),
        pairing_id,
        "the recorded outcome stands; the id is never reissued"
    );
}

// ---------------------------------------------------------------------------
// Concurrent
// ---------------------------------------------------------------------------

/// **Concurrent, and the property idempotency exists for.** Eight `pair.begin`
/// calls carrying one `idempotency_key`, submitted from eight threads at once,
/// must produce **one** ceremony.
///
/// ADR-0008 N-4 puts the whole burden on a stable key; this asserts the core
/// honours it under a race rather than only in sequence. One mutex on `Core` is
/// the mechanism, so this is the test that would fail if somebody later split
/// the ledger and the dedup log across two locks.
#[test]
fn eight_concurrent_begins_produce_one_ceremony() {
    let h = enrolled();
    let core = &h.core;

    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                core.submit(&begin(b"key-raced")).expect("pair.begin");
            });
        }
    });

    let mut seen: Vec<[u8; PAIRING_ID_BYTES]> = Vec::new();
    while let Some(event) = core.next_event(Duration::ZERO) {
        if let twinvpn_core::CoreEventKind::CommandCompleted { op, result } = event.kind {
            if op == CoreCommand::PairBegin.name() {
                seen.push(<[u8; PAIRING_ID_BYTES]>::try_from(result.as_slice()).expect("id"));
            }
        }
    }
    assert_eq!(seen.len(), 8, "every submission was answered");
    assert!(
        seen.windows(2).all(|w| w[0] == w[1]),
        "racing retries named more than one ceremony"
    );
    assert_eq!(
        h.adapter.identity_mock().sign_calls(),
        1,
        "exactly one ceremony was opened, so the element signed exactly once"
    );
}

// ---------------------------------------------------------------------------
// The offer's lifetime — S-67 and ADR-0017 MI-P1 rule 2
// ---------------------------------------------------------------------------

/// **The agent frees the secret when the window passes.**
///
/// `architecture.md` S-67 makes the in-flight offer "non-durable BY
/// REQUIREMENT" and zeroized "on consumption or at expiry, whichever is first",
/// and ADR-0017 MI-P1 rule 2 puts the same 120-second deadline on the client.
/// Nothing enforced the agent's half: an expired ceremony's `pairing_secret`
/// stayed in the map for the life of the process.
///
/// The sweep runs on the next operation that **acts**, which is `pair.begin` —
/// `pair.status` is `Idempotency::ReadOnly` and burning is an act.
#[test]
fn an_expired_offer_is_freed_rather_than_held_for_the_life_of_the_process() {
    let h = enrolled();
    h.core.submit(&begin(b"key-first")).expect("pair.begin");
    let first = pairing_id_from_events(&h.core);
    assert!(
        h.core.with_pairing_offer(&first, |_| ()).is_some(),
        "the offer is in flight"
    );

    // Past N-17's window, and then an operation that acts.
    h.time.advance(Duration::from_secs(121));
    h.core.submit(&begin(b"key-second")).expect("pair.begin");
    let second = pairing_id_from_events(&h.core);

    assert!(
        h.core.with_pairing_offer(&first, |_| ()).is_none(),
        "the expired offer must be dropped, which zeroizes its pairing_secret"
    );
    assert!(
        h.core.with_pairing_offer(&second, |_| ()).is_some(),
        "the sweep must not take the ceremony that is still in flight"
    );
    // And the sweep burned the id rather than leaving it Pending, so the ledger
    // and the offer map agree about what happened.
    assert_eq!(status_of(&h.core, &first), EXPIRED);
}

/// **`Core::submit_response` is the offer's only exit, it diverges from the
/// published body, and it stops when the ceremony does.**
///
/// ADR-0017 §11.9 and MI-P1. The return value carries `pairing_id ‖
/// dCBOR(offer)` to the caller that submitted, while the `CommandCompleted` the
/// same call published carries the `pairing_id` alone — the two are asserted
/// against each other here, because "the response carries more than the event"
/// is the whole property and a test that read only one of them would not see it.
///
/// After the ceremony ends there is no offer to return, so the response shrinks
/// to ADR-0008's recorded outcome rather than carrying a secret nothing can
/// still use.
#[test]
fn the_response_body_carries_the_offer_only_while_the_ceremony_is_in_flight() {
    let h = enrolled();
    let body = h
        .core
        .submit_response(&begin(b"key-render"))
        .expect("pair.begin")
        .expect("a live ceremony answers with its offer");
    let pairing_id = pairing_id_from_events(&h.core);

    // The published half: the 16-byte PUBLIC handle, and nothing more.
    // `pairing_id_from_events` reads the CommandCompleted every subscriber sees
    // and refuses anything that is not exactly `PAIRING_ID_BYTES` wide.
    assert_eq!(&body[..PAIRING_ID_BYTES], pairing_id);
    assert!(
        body.len() > PAIRING_ID_BYTES,
        "the response must carry MORE than the event did, or MI-P1 has nothing \
         to govern and no shell can render an offer"
    );
    let offer = twinvpn_crypto::pairing_offer::decode(&body[PAIRING_ID_BYTES..])
        .expect("the response body carries a decodable offer");
    assert_eq!(offer.pairing_id(), pairing_id);

    h.core
        .submit(&named(CoreCommand::PairCancel, &pairing_id))
        .expect("pair.cancel");
    // The same submission again is ADR-0008's replay: the recorded `pairing_id`
    // is published, and there is no offer left to return.
    assert!(
        h.core
            .submit_response(&begin(b"key-render"))
            .expect("the replay is answered")
            .is_none(),
        "a cancelled ceremony has no offer to return"
    );
    assert_eq!(
        pairing_id_from_events(&h.core),
        pairing_id,
        "the replay still publishes the original pairing_id (ADR-0008 N-4)"
    );
}
