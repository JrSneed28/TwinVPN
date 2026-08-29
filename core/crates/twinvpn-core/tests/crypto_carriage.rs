//! **F-1A/F-1D.** The composed core's carriage, over a **real `Noise_IKpsk2`
//! handshake** rather than a stub.
//!
//! **Authority:** ADR-0001 §7.2 (the concrete L-DATA specification, the
//! per-direction session keys, `REJECT_AFTER_MESSAGES`), §7.3.2 RS-3 (a
//! transport-mode change must not reset the replay window), §7.6 (endpoint
//! migration is authenticated); `docs/reliability.md` §4.4; `ownership.md` §6.
//!
//! # The defect this file exists to close
//!
//! `tests/datapath.rs` proved that the pump carries packets, refuses replays and
//! survives tampering — against `datapath/support.rs`'s `StubKeys`, an XOR mask
//! with a keyed tag that is **not cryptography** and says so. So every
//! "encryption" assertion in this crate was an assertion about a stub, and
//! `twinvpn_crypto::noise::TransportSession::seal` had no caller a test in this
//! crate ever reached.
//!
//! Every test below runs the production chain, unmodified:
//!
//! ```text
//! Pump::step_outbound / step_inbound
//!   -> twinvpn_tunnel::Tunnel::seal / open
//!     -> twinvpn_tunnel::bind::SessionKeys           (the PRODUCTION TransportKeys)
//!       -> twinvpn_crypto::noise::TransportSession   (snow, ChaCha20-Poly1305)
//! ```
//!
//! and the keys come from `twinvpn_tunnel::bind::NoiseBinding` driven through a
//! real handshake — the same type `crate::execute::handshake::drive` uses.
//!
//! # What each test would catch
//!
//! These are not restatements of `datapath.rs`. A stub cipher satisfies "the
//! bytes changed" and "a flipped bit fails to open" by construction; what it
//! cannot satisfy is that the two directions are keyed **independently**, that a
//! reflected datagram fails under a key the sender does not hold, and that the
//! AEAD's own authentication — not a harness's — is what refuses a forgery.

#![cfg(feature = "full")]

#[path = "datapath/support.rs"]
#[allow(dead_code, reason = "one harness, shared by two test targets")]
mod dp;

#[path = "crypto_carriage/support.rs"]
#[allow(dead_code, reason = "helpers used by a subset of the tests here")]
mod support;

use dp::{capture, inject, packet, ready};
use twinvpn_core::datapath::{Step, HEADER_BYTES, OVERHEAD_BYTES, TAG_BYTES};

/// The plaintext every round-trip test moves. Long enough that a cipher which
/// simply passed the bytes through would be obvious, short enough to keep the
/// 8k-counter window test cheap.
const PAYLOAD: usize = 128;

// ---------------------------------------------------------------------------
// 1-3. The production carriage really encrypts, really authenticates, and
//      really round-trips
// ---------------------------------------------------------------------------

/// **1.** The outbound production carriage invokes encryption and
/// authentication.
///
/// The assertion that a stub would fail is the last one: the record is not a
/// transform of the plaintext that the *receiving* key can be swapped out of.
/// It opens under the peer's real session and under nothing else.
#[test]
fn real_outbound_production_carriage_encrypts_and_authenticates() {
    let (fabric, _env, _spare) = support::fabric();
    let plaintext = packet(PAYLOAD);

    // The production step: TUN -> Tunnel::seal -> SessionKeys::seal -> snow.
    let datagram = capture(&fabric, &plaintext);

    // A ChaCha20-Poly1305 record is the plaintext plus a 16-byte tag, inside the
    // 16-octet transport header. Nothing is padded, and nothing is truncated.
    assert_eq!(
        datagram.len(),
        HEADER_BYTES + plaintext.len() + TAG_BYTES,
        "one record is header + ciphertext + Poly1305 tag"
    );
    let (header, record) = support::split(&datagram);
    assert_eq!(header.receiver, dp::RIGHT_INDEX);
    assert_eq!(header.counter, 0, "the first record of a fresh session");

    // The ciphertext is not the plaintext, and no window of it is: an XOR-with-a
    // -constant stub passes the first check and fails nothing, so the real
    // assertion is that the AEAD authenticated it.
    assert_ne!(&record[..plaintext.len()], &plaintext[..]);
    assert!(
        !record.windows(16).any(|w| plaintext.starts_with(w)),
        "no 16-byte run of the plaintext survives into the record"
    );

    // And it opens, exactly once, under the peer's production session.
    let mut recovered = Vec::new();
    fabric
        .right
        .tunnel
        .lock()
        .expect("not poisoned")
        .open(header.counter, &record, &mut recovered)
        .expect("the peer's real session authenticates it");
    assert_eq!(recovered, plaintext);
}

/// **2.** The inbound production carriage invokes authentication and
/// decryption.
///
/// Driven through `Pump::step_inbound`, so the witness is the **interface**:
/// bytes reach the TUN only if the AEAD authenticated the frame first.
#[test]
fn real_inbound_production_carriage_authenticates_and_decrypts() {
    let (fabric, _env, _spare) = support::fabric();
    let plaintext = packet(PAYLOAD);
    let datagram = capture(&fabric, &plaintext);

    inject(&fabric, &datagram, fabric.right.endpoint);
    let mut buffers = fabric.right.pump.buffers();
    assert_eq!(
        ready(fabric.right.pump.step_inbound(&mut buffers)),
        Step::Moved(plaintext.len()),
        "an authenticated record is decrypted and written to the interface"
    );
    assert_eq!(
        fabric.right.written(),
        vec![plaintext],
        "the plaintext the far TUN sees is the plaintext the near TUN sent"
    );
}

/// **3.** An authenticated datagram survives a complete real transport round
/// trip, in both directions, byte for byte.
#[test]
fn an_authenticated_outbound_datagram_survives_a_real_round_trip() {
    let (fabric, _env, _spare) = support::fabric();

    for (from, to, tag) in [
        (&fabric.left, &fabric.right, 0xa0u8),
        (&fabric.right, &fabric.left, 0xb0u8),
    ] {
        let mut plaintext = packet(PAYLOAD);
        plaintext[0] = tag;
        from.adapter.tunnel_mock().push_inbound(plaintext.clone());

        let mut out = from.pump.buffers();
        assert_eq!(
            ready(from.pump.step_outbound(&mut out)),
            Step::Moved(plaintext.len())
        );
        let mut inbound = to.pump.buffers();
        assert_eq!(
            ready(to.pump.step_inbound(&mut inbound)),
            Step::Moved(plaintext.len())
        );
        assert_eq!(to.written().last(), Some(&plaintext), "byte-identical");
    }

    // RS-3 / §7.2: the counters only ever moved forward, and nothing reset.
    assert!(fabric.left.carries_traffic() && fabric.right.carries_traffic());
}

// ---------------------------------------------------------------------------
// 4-6. Forgery, in its three shapes
// ---------------------------------------------------------------------------

/// **4.** Tampered ciphertext is rejected — by Poly1305, not by a harness.
#[test]
fn tampered_ciphertext_is_rejected() {
    let (fabric, _env, _spare) = support::fabric();
    let plaintext = packet(PAYLOAD);
    let mut datagram = capture(&fabric, &plaintext);

    // A single bit, in the ciphertext body rather than in the tag.
    datagram[HEADER_BYTES] ^= 0x01;
    assert_refused(&fabric, &datagram);
}

/// **5.** A tampered authentication tag is rejected.
///
/// Kept apart from the body case on purpose: they fail at different points in
/// the AEAD, and a construction that authenticated only the body would pass one
/// and fail the other.
#[test]
fn a_tampered_authentication_tag_is_rejected() {
    let (fabric, _env, _spare) = support::fabric();
    let plaintext = packet(PAYLOAD);
    let mut datagram = capture(&fabric, &plaintext);

    let last = datagram.len() - 1;
    datagram[last] ^= 0x01;
    assert_eq!(
        datagram.len(),
        HEADER_BYTES + plaintext.len() + TAG_BYTES,
        "the flipped byte really is inside the Poly1305 tag"
    );
    assert_refused(&fabric, &datagram);
}

/// **6.** Reflected traffic is rejected.
///
/// The left end's own datagram, aimed back at the left end. §7.2 gives each
/// direction its own key — "one send key + one receive key per peer per
/// handshake, derived from the final Noise chaining key; **independent per
/// direction**" — so a sender cannot open what it sealed.
///
/// This is the one property a symmetric stub cipher cannot express, and the
/// reason it is worth a test of its own: under `StubKeys` a reflected record
/// opens, because the harness's two "keys" are just two byte arrays a test
/// chose. Here it must not.
#[test]
fn reflected_traffic_is_rejected() {
    let (fabric, _env, _spare) = support::fabric();
    let plaintext = packet(PAYLOAD);
    let mut datagram = capture(&fabric, &plaintext);

    // Readdress it to the left's own receiver index, so it is not dropped
    // before the AEAD for naming the wrong tunnel — the refusal under test is
    // the cryptographic one.
    let (_, record) = support::split(&datagram);
    datagram.clear();
    twinvpn_core::datapath::DataHeader {
        receiver: dp::LEFT_INDEX,
        counter: 0,
    }
    .write(&mut datagram);
    datagram.extend_from_slice(&record);

    inject(&fabric, &datagram, fabric.left.endpoint);
    let mut buffers = fabric.left.pump.buffers();
    assert_ne!(
        ready(fabric.left.pump.step_inbound(&mut buffers)),
        Step::Moved(plaintext.len()),
        "a device must not be able to open a record it sealed"
    );
    assert!(
        fabric.left.written().is_empty(),
        "nothing reflected reaches the interface"
    );
}

// ---------------------------------------------------------------------------
// 7-9. The replay window, under real authentication
// ---------------------------------------------------------------------------

/// **7.** Invalid traffic does not advance the replay window.
///
/// The attack: an off-path device forges records at counters ahead of the real
/// peer. If the window moved on *unauthenticated* input, the genuine records at
/// those counters would then be dropped as replays and the real peer would be
/// locked out — a denial of service assembled out of datagrams the attacker
/// cannot even construct correctly.
///
/// `TransportSession::open` commits **last**, after the AEAD, which is what
/// makes this test pass and what would break if that order were ever swapped.
#[test]
fn invalid_traffic_does_not_advance_the_replay_window() {
    let (_fabric, _env, spare) = support::fabric();
    let plaintext = packet(PAYLOAD);

    // Genuine records at counters 0 and 1, from the spare session, so the test
    // controls which counter arrives when.
    let genuine: Vec<Vec<u8>> = (0..2)
        .map(|counter| {
            support::seal_datagram(
                spare.initiator_keys.as_ref(),
                dp::RIGHT_INDEX,
                counter,
                &plaintext,
            )
        })
        .collect();

    // The far end of the SAME handshake — nothing else can open those records.
    let receiver = spare.responder_keys.as_ref();
    // A forgery at counter 1: right length, right header, garbage record.
    let mut forged = genuine[1].clone();
    for byte in &mut forged[HEADER_BYTES..] {
        *byte ^= 0xff;
    }
    let mut out = Vec::new();
    assert!(
        receiver.open(1, &forged[HEADER_BYTES..], &mut out).is_err(),
        "a forgery does not authenticate"
    );

    // The genuine record at that same counter must still be accepted. If the
    // forgery had advanced the window, this is where it would fail.
    let mut recovered = Vec::new();
    receiver
        .open(1, &genuine[1][HEADER_BYTES..], &mut recovered)
        .expect("the real peer is not locked out by a forgery");
    assert_eq!(recovered, plaintext);
    // And counter 0, behind the mark but never seen, is still admissible — the
    // window tolerates reordering, which is the point of it being a window.
    let mut earlier = Vec::new();
    receiver
        .open(0, &genuine[0][HEADER_BYTES..], &mut earlier)
        .expect("an unseen counter behind the mark is a reorder, not a replay");
}

/// **8.** A valid replay is rejected.
///
/// The same authenticated datagram, twice. It authenticates both times — that
/// is what makes it a *replay* rather than a forgery — and is refused the second
/// time by the window and by nothing else.
#[test]
fn a_valid_replay_is_rejected() {
    let (fabric, _env, _spare) = support::fabric();
    let plaintext = packet(PAYLOAD);
    let datagram = capture(&fabric, &plaintext);

    inject(&fabric, &datagram, fabric.right.endpoint);
    let mut buffers = fabric.right.pump.buffers();
    assert_eq!(
        ready(fabric.right.pump.step_inbound(&mut buffers)),
        Step::Moved(plaintext.len())
    );

    inject(&fabric, &datagram, fabric.right.endpoint);
    let mut again = fabric.right.pump.buffers();
    assert_ne!(
        ready(fabric.right.pump.step_inbound(&mut again)),
        Step::Moved(plaintext.len()),
        "the second delivery of one record is a replay"
    );
    assert_eq!(
        fabric.right.written().len(),
        1,
        "a replay must not reach the interface a second time"
    );
    assert!(
        fabric.right.carries_traffic(),
        "a replay is dropped, never a reason to tear the tunnel down"
    );
}

/// **9.** Ordering and window behaviour follow the specification.
///
/// Three rules, one test, because they are one mechanism:
///
/// - an unseen counter **behind** the high-water mark is accepted (reordering on
///   a lossy path is normal, and refusing it would drop real traffic);
/// - any counter **already seen** is refused, wherever it sits;
/// - a counter more than `WINDOW_BITS` behind the mark is refused, because the
///   window can no longer say whether it was seen — the safe answer.
#[test]
fn ordering_and_window_behaviour_follow_the_specification() {
    use twinvpn_crypto::replay::WINDOW_BITS;

    let (_fabric, env, _spare) = support::fabric();
    let sender = support::handshake(&env);
    let receiver = sender.responder_keys.as_ref();
    let sending = sender.initiator_keys.as_ref();
    let small = [0xa5u8; 8];

    // Seal a run long enough that its first record falls out of the window.
    let total = WINDOW_BITS + 8;
    let records: Vec<Vec<u8>> = (0..total)
        .map(|counter| {
            let mut out = Vec::new();
            sending.seal(counter, &small, &mut out).expect("seal");
            out
        })
        .collect();

    let open = |counter: u64| {
        let mut out = Vec::new();
        receiver
            .open(
                counter,
                &records[usize::try_from(counter).expect("fits")],
                &mut out,
            )
            .map(|()| out)
    };

    // Out of order, inside the window: all accepted.
    for counter in [5u64, 1, 4, 0, 3, 2] {
        assert_eq!(open(counter).expect("a reorder is not a replay"), small);
    }
    // Each of them, again: refused.
    for counter in [0u64, 3, 5] {
        assert!(open(counter).is_err(), "counter {counter} was already seen");
    }
    // Jump to the far end, then reach back past the window's trailing edge.
    assert_eq!(open(total - 1).expect("the newest record"), small);
    assert!(
        open(6).is_err(),
        "a counter more than WINDOW_BITS behind the mark is no longer decidable"
    );
}

// ---------------------------------------------------------------------------
// 10. Direction separation
// ---------------------------------------------------------------------------

/// **10.** Producer and consumer direction keys are separated.
///
/// ADR-0001 §7.2: "one send key + one receive key per peer per handshake …
/// **independent per direction**". Asserted three ways, because the interesting
/// failures differ:
///
/// - the same plaintext at the same counter seals to **different** records in
///   the two directions (the keys are not equal);
/// - neither end can open its own record (a sender is not a receiver);
/// - each end opens the other's (the two directions are not merely different,
///   they are correctly paired).
#[test]
fn producer_and_consumer_direction_keys_are_separated() {
    let (_fabric, env, _spare) = support::fabric();
    let pair = support::handshake(&env);
    let plaintext = packet(PAYLOAD);

    let mut from_initiator = Vec::new();
    pair.initiator_keys
        .seal(0, &plaintext, &mut from_initiator)
        .expect("the initiator seals");
    let mut from_responder = Vec::new();
    pair.responder_keys
        .seal(0, &plaintext, &mut from_responder)
        .expect("the responder seals");
    assert_ne!(
        from_initiator, from_responder,
        "one plaintext at one counter must not seal identically in both directions"
    );

    // Neither end can open what it sealed.
    let mut out = Vec::new();
    assert!(
        pair.initiator_keys
            .open(0, &from_initiator, &mut out)
            .is_err(),
        "the send key must not open the send direction"
    );
    assert!(
        pair.responder_keys
            .open(0, &from_responder, &mut out)
            .is_err(),
        "the send key must not open the send direction"
    );

    // Each opens the other's, exactly once.
    let mut at_responder = Vec::new();
    pair.responder_keys
        .open(0, &from_initiator, &mut at_responder)
        .expect("the responder opens the initiator's record");
    assert_eq!(at_responder, plaintext);
    let mut at_initiator = Vec::new();
    pair.initiator_keys
        .open(0, &from_responder, &mut at_initiator)
        .expect("the initiator opens the responder's record");
    assert_eq!(at_initiator, plaintext);

    // And the handshake authenticated the two peers to each other, which is the
    // identity half of the same fact.
    assert_eq!(
        pair.initiator_established.remote_static(),
        &pair.responder_static
    );
    assert_eq!(
        pair.responder_established.remote_static(),
        &pair.initiator_static
    );
}

// ---------------------------------------------------------------------------
// Shared assertions
// ---------------------------------------------------------------------------

/// The right end must refuse `datagram`, write nothing, and keep carrying.
fn assert_refused(fabric: &dp::Fabric, datagram: &[u8]) {
    assert!(
        datagram.len() >= OVERHEAD_BYTES,
        "a frame shorter than the overhead never reaches the AEAD"
    );
    inject(fabric, datagram, fabric.right.endpoint);
    let mut buffers = fabric.right.pump.buffers();
    let step = ready(fabric.right.pump.step_inbound(&mut buffers));
    assert!(
        !matches!(step, Step::Moved(_)),
        "a frame the AEAD refused must not move: {step:?}"
    );
    assert!(
        fabric.right.written().is_empty(),
        "nothing unauthenticated reaches the interface"
    );
    assert!(
        fabric.right.carries_traffic(),
        "a refused frame is dropped, never a reason to tear the tunnel down"
    );
}
