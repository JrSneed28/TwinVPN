//! **End-to-end.** A real IP packet crosses between two composed endpoints
//! under real `Noise_IKpsk2` cryptography — and the octets between them are not
//! the packet.
//!
//! **Authority:** ADR-0001 §7.2, §7.3 D1/D2, §7.3.1 P-1..P-3, §7.5 item 2, §7.6,
//! §11 items 1 and 2; ADR-0007 N-4/N-5; ADR-0010 **R1**; ADR-0014 N-8/N-9;
//! ADR-0018 §11.2 row 2.3, CB-1, CD-5, CD-I2; `docs/testing-strategy.md` §6.5
//! blocker **B-7**; `docs/implementation/ownership.md` §6 rules 9, 10 and 11.
//!
//! # The gap this file closes
//!
//! Wave 1's gate found the product could not carry a packet, and five blockers
//! were closed to make it able to. The strongest surviving proof that it does —
//! `core/crates/twinvpn-core/tests/datapath.rs` — runs two `Pump`s against each
//! other over `StubKeys`, which that file's own header calls "**not
//! cryptography**". It is honest about why (`twinvpn-core`'s manifest cannot
//! enable `twinvpn-crypto`'s `test-support`, and a `VerifiedTunnelKey` has no
//! other constructor), and the consequence stands regardless: **the test that
//! proves a packet crosses proves it through a stub cipher.**
//!
//! Everything below runs over `twinvpn_crypto::noise` and
//! `twinvpn_tunnel::bind` — a genuine `Noise_IKpsk2` handshake, production
//! `SessionKeys`, and `twinvpn_core::datapath::Pump` on both ends over
//! `twinvpn_platform`'s `MockAdapter`. Nothing between the two TUN devices is a
//! stand-in for a primitive.
//!
//! # The shape every test here takes
//!
//! `e2e/fail_closed_leak.rs` states the rule this file inherits, from
//! `docs/testing-strategy.md` §6.5 blocker **B-7**: every negative assertion is
//! paired **in the same test** with a positive control — an injected condition
//! that *is* the failure, and the assertion that it is caught. A crossing test
//! that passes because both ends are broken is not a proof, so each test below
//! says in its doc comment how it is known to fail for the right reason.
//!
//! # Both families, or neither (ADR-0010 R1)
//!
//! Every test loops over [`BOTH`]. `ownership.md` §4.2 records why per-family
//! error namespaces were refused: they make "we have a v4 story and a v6 story"
//! sayable. A test file that only ever ran the v4 arm would make it *true*.
//!
//! # What this file does not prove
//!
//! - **Forward secrecy, and unpredictability of any kind.** The ephemerals come
//!   from `twinvpn_system_tests::noise::SeededEntropy`, which is deterministic
//!   and says so. That is a property of the `Env` a production shell injects
//!   (W-7 names `Entropy` as a required shell interface) and nothing here can
//!   observe it. The primitives are proved against known vectors in
//!   `twinvpn-crypto`'s own suite and in `tests/compatibility/golden_vectors.rs`.
//! - **That the handshake messages themselves are well-formed on the wire.**
//!   The two ends are handed each other's messages directly. The initiation as
//!   an *untrusted decoder input* is fuzzed by
//!   `fuzz/handshake_and_platform_decoders.rs`; the refusals around it —
//!   disagreeing prologue, unexpected peer static, role confusion, spent binding
//!   — are `core/crates/twinvpn-tunnel/tests/l_data_binding.rs`'s.
//! - **Rekey, counter exhaustion, or a session lifetime.** ADR-0001 §7.2's
//!   `REJECT_AFTER_*` limits are the engine's and are asserted in
//!   `twinvpn-tunnel`'s own tests; nothing here advances a clock.
//! - **A relay leg.** That is `e2e/real_crypto_relay_leg.rs`.

use twinvpn_core::datapath::{Reject, Step, HEADER_BYTES, TAG_BYTES};
use twinvpn_types::AddressFamily;

use twinvpn_system_tests::crossing::{
    contains, payload, unsealed_datagram, Crossing, Direction, SHARED_EPOCH_SEED,
};

/// ADR-0010 R1: one story covering both.
const BOTH: [AddressFamily; 2] = [AddressFamily::V4, AddressFamily::V6];

/// Both directions, so a test cannot pass because only the initiator's key
/// schedule works. `Noise_IKpsk2` derives two independent transport keys.
const WAYS: [Direction; 2] = [Direction::LeftToRight, Direction::RightToLeft];

/// A payload long enough that a substring search for it cannot match by
/// accident, and short enough to sit well inside the overlay MTU.
const SENTINEL: &[u8] = b"SENTINEL-plaintext-IP-packet-that-must-never-appear-on-the-underlay-wire";

// ---------------------------------------------------------------------------
// 1. The crossing itself
// ---------------------------------------------------------------------------

/// **The headline.** A plaintext packet written into one endpoint's TUN device
/// emerges byte-identical from the peer's, over a real `Noise_IKpsk2` session,
/// on both address families and in both directions.
///
/// # How this is known to fail for the right reason
///
/// Three ways, all exercised by mutation during development:
///
/// - Corrupting one byte of the sealed record before delivery turns
///   `Step::Moved` into `Step::Rejected(Reject::Unauthenticated)` and the
///   equality assertion is never reached — so the AEAD is genuinely in the path
///   rather than a pass-through. That mutation is
///   [`a_tampered_datagram_is_dropped_and_the_tunnel_survives_it`], kept as a
///   permanent test rather than a note.
/// - Handing the receiver a datagram from a *different* crossing's keys is
///   refused, which is
///   [`a_datagram_from_another_session_does_not_open_at_this_receiver`]. A
///   receiver that accepted anything would pass this test with no cryptography
///   at all.
/// - The equality is against the bytes the mock TUN device actually received,
///   read back through `MockTunnel::written`. A pump that never called
///   `write_packet` yields an empty list and the length assertion fires first.
#[test]
fn a_real_ip_packet_crosses_between_two_composed_endpoints_under_real_noise_ikpsk2() {
    for family in BOTH {
        let crossing = Crossing::open(family);
        assert!(
            crossing.left.carries_traffic() && crossing.right.carries_traffic(),
            "{family:?}: N-8/N-9 — both tunnels confirmed their transcript before \
             anything was sent"
        );

        for direction in WAYS {
            let packet = payload(600);
            crossing.cross(direction, &packet);

            let received = crossing.receiver(direction).written();
            assert_eq!(
                received.len(),
                1,
                "{family:?}/{direction:?}: exactly one packet reached the peer's TUN device"
            );
            assert_eq!(
                received[0], packet,
                "{family:?}/{direction:?}: the packet that arrived is not the packet that was \
                 sent — a crossing that changes the payload is not a crossing"
            );
        }
    }
}

/// A whole burst crosses, in order, with the nonce advancing — so the headline
/// above is not an artefact of the very first record.
///
/// **W-31 is the reason this is worth stating separately.** The first data
/// packet of every tunnel was once rejected as a replay, and neither owning
/// crate's suite could see it because *every existing test started at counter
/// 1*. Here the first record is counter 0 and there are nine more behind it.
///
/// # How this is known to fail for the right reason
///
/// Each packet is distinct — `payload(n)` for a different `n` — so a pump that
/// delivered the same packet ten times, or delivered them out of order, fails
/// the per-index equality rather than a count.
#[test]
fn a_burst_of_packets_crosses_in_order_from_the_first_nonce() {
    for family in BOTH {
        let crossing = Crossing::open(family);
        let packets: Vec<Vec<u8>> = (1..=10).map(|n| payload(n * 37)).collect();

        for packet in &packets {
            crossing.cross(Direction::LeftToRight, packet);
        }

        let received = crossing.right.written();
        assert_eq!(
            received.len(),
            packets.len(),
            "{family:?}: every packet arrived"
        );
        for (index, (sent, got)) in packets.iter().zip(received.iter()).enumerate() {
            assert_eq!(
                sent, got,
                "{family:?}: packet {index} arrived changed or out of order"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 2. The wire carries ciphertext (ADR-0001 §11 item 1)
// ---------------------------------------------------------------------------

/// The octets between the two endpoints are **not** the plaintext — and the
/// detector that says so is proved to work in the same test (B-7).
///
/// # How this is known to fail for the right reason
///
/// This is exactly the failure mode B-7 exists for: a substring search that
/// never matches is indistinguishable from a substring search that is not
/// looking. So the same [`contains`] call, on the same rig, in the same test, is
/// run against [`unsealed_datagram`] — a datagram framed the way a real one is
/// whose body *is* the plaintext — and asserted to fire. The negative result is
/// only reported after the positive control is green.
///
/// The search is a substring scan rather than an equality check on purpose: a
/// header change, a tag change or a framing change must not be able to hide a
/// leak by shifting it.
#[test]
fn the_bytes_on_the_wire_are_not_the_plaintext_and_the_detector_proves_it() {
    for family in BOTH {
        let crossing = Crossing::open(family);

        for direction in WAYS {
            // Positive control first: the detector must catch a leak that IS
            // there before its silence means anything.
            assert!(
                contains(&unsealed_datagram(SENTINEL), SENTINEL),
                "{family:?}/{direction:?}: the leak detector did not find a plaintext it was \
                 handed directly — an unproven observation channel is not a negative result (B-7)"
            );

            // `emit` rather than `cross`: the wire is inspected BEFORE the
            // datagram is delivered, so a build that put the plaintext on the
            // wire is reported as a leak here rather than as a failed open two
            // steps later. That ordering was chosen after watching the mutation
            // — shipping `buffers.packet` instead of `buffers.record` — and
            // seeing it surface as `Rejected(Unauthenticated)`, which is a true
            // failure with the wrong diagnosis.
            let wire = crossing.emit(direction, SENTINEL);

            assert!(
                !contains(&wire, SENTINEL),
                "{family:?}/{direction:?}: the plaintext appeared on the underlay wire"
            );
            // Nor any substantial run of it: a cipher that leaked a prefix would
            // pass a whole-payload search.
            assert!(
                !contains(&wire, &SENTINEL[..16]),
                "{family:?}/{direction:?}: a 16-byte prefix of the plaintext appeared on the wire"
            );
            assert!(
                !contains(&wire, &SENTINEL[SENTINEL.len() - 16..]),
                "{family:?}/{direction:?}: a 16-byte suffix of the plaintext appeared on the wire"
            );

            // The record is the plaintext plus exactly one AEAD tag, behind the
            // 16-byte L-DATA header. Stated so that a change which started
            // shipping the payload twice, or in the clear beside the record,
            // fails here rather than passing a substring search on a longer
            // datagram.
            assert_eq!(
                wire.len(),
                HEADER_BYTES + SENTINEL.len() + TAG_BYTES,
                "{family:?}/{direction:?}: the datagram is not header + record + tag"
            );

            // And it still crosses: a "wire" that carried nothing readable
            // because it carried nothing usable would satisfy everything above.
            assert_eq!(
                crossing.deliver(direction, &wire),
                Step::Moved(SENTINEL.len()),
                "{family:?}/{direction:?}: the inspected datagram did not open at the peer"
            );
            assert_eq!(
                crossing.receiver(direction).written(),
                vec![SENTINEL.to_vec()]
            );
        }
    }
}

/// Two crossings of the *same* plaintext do not produce the same record.
///
/// A cipher that produced identical ciphertext for identical plaintext would
/// pass every assertion above — the plaintext is still absent from the wire —
/// and would leak the repetition structure of the traffic. The counter is the
/// AEAD nonce (ADR-0001 §7.2), so two records under two counters must differ.
///
/// # How this is known to fail for the right reason
///
/// The two records are compared *after* their headers, so the assertion cannot
/// be satisfied by the counter field alone: it is about the sealed bytes.
#[test]
fn two_records_of_one_plaintext_differ_because_the_counter_is_the_nonce() {
    for family in BOTH {
        let crossing = Crossing::open(family);
        let first = crossing.cross(Direction::LeftToRight, SENTINEL);
        let second = crossing.cross(Direction::LeftToRight, SENTINEL);

        assert_ne!(
            &first[HEADER_BYTES..],
            &second[HEADER_BYTES..],
            "{family:?}: the same plaintext sealed twice produced the same record — the nonce is \
             not reaching the AEAD"
        );
        assert_eq!(
            &first[..8],
            &second[..8],
            "{family:?}: only the counter field may differ in the header of two records of one \
             session"
        );
        assert_ne!(
            &first[8..HEADER_BYTES],
            &second[8..HEADER_BYTES],
            "{family:?}: the counter did not advance between two records"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. The adversarial cases, end to end
// ---------------------------------------------------------------------------

/// **Attack test.** A replayed datagram is refused, and the tunnel survives it.
///
/// ADR-0001 §7.1's replay window, reached the way an on-path attacker reaches it
/// — by capturing the exact octets that crossed and putting them back on the
/// wire — rather than by calling `Tunnel::open` twice at a unit boundary.
///
/// The registry row for `CRYPTO.REPLAY_DETECTED` is `FATAL`/`CRITICAL` and
/// **`terminal = false`**, so a replay is a dropped datagram and not a teardown:
/// `Reject::tears_down` answers `false`, and the assertion that traffic still
/// crosses afterwards is what makes that observable end to end.
///
/// # How this is known to fail for the right reason
///
/// The first delivery of the same octets is asserted to be `Step::Moved` **in
/// this test**. That is the positive control: it proves the datagram is one this
/// receiver accepts, so the refusal of the second delivery is attributable to
/// the replay and not to a rig that rejects everything. Removing the receiver's
/// replay window turns the second delivery into a second `Step::Moved` and the
/// test fails on the variant, not on a count.
#[test]
fn a_replayed_datagram_is_refused_and_the_tunnel_survives_it() {
    for family in BOTH {
        for direction in WAYS {
            let crossing = Crossing::open(family);
            let packet = payload(256);
            let wire = crossing.emit(direction, &packet);

            // Positive control: these exact octets are acceptable to this
            // receiver.
            assert_eq!(
                crossing.deliver(direction, &wire),
                Step::Moved(packet.len()),
                "{family:?}/{direction:?}: the captured datagram was not accepted once, so a \
                 refusal of the replay would prove nothing"
            );

            // The attack.
            assert_eq!(
                crossing.deliver(direction, &wire),
                Step::Rejected(Reject::Replay),
                "{family:?}/{direction:?}: a replayed datagram was not refused as a replay"
            );
            assert!(
                !Reject::Replay.tears_down(),
                "{family:?}/{direction:?}: a replay is a dropped datagram, not a teardown"
            );

            // The tunnel survived: it still carries traffic, and a fresh packet
            // crosses. Both halves matter — a session that reported
            // `Established` but refused every subsequent packet would satisfy
            // only the first.
            assert!(crossing.receiver(direction).carries_traffic());
            let next = payload(300);
            crossing.cross(direction, &next);
            let written = crossing.receiver(direction).written();
            assert_eq!(
                written,
                vec![packet, next],
                "{family:?}/{direction:?}: the replay was counted as delivered, or the tunnel \
                 stopped carrying traffic after it"
            );
        }
    }
}

/// **Attack test.** A tampered datagram is dropped, and the tunnel survives it.
///
/// Every mutable region of the frame is exercised, because they fail through
/// different code and a test that only flipped a ciphertext byte would leave the
/// header unproven:
///
/// | Region | Bytes | Expected |
/// |---|---|---|
/// | the counter, which is the AEAD nonce | `8..16` | `Reject::Unauthenticated` |
/// | the sealed record | `16..len-16` | `Reject::Unauthenticated` |
/// | the AEAD tag | the last 16 | `Reject::Unauthenticated` |
/// | the receiver index | `4..8` | `Reject::ForeignReceiver`, a pre-AEAD shed |
/// | the reserved bytes | `1..4` | `Reject::Malformed` |
///
/// # How this is known to fail for the right reason
///
/// The **pristine** datagram is delivered last, in the same test, on the same
/// rig, and asserted to be accepted. That is the positive control: every
/// refusal above is attributable to the byte that was changed, because the
/// datagram with none of them changed still crosses. A receiver that had simply
/// stopped working would fail that final assertion.
///
/// The order also matters and is deliberate: the tampered copies are delivered
/// **before** the pristine one, so none of them can be refused as a replay of
/// it. A refusal that was really a replay would be the wrong reason for a
/// green test.
#[test]
fn a_tampered_datagram_is_dropped_and_the_tunnel_survives_it() {
    for family in BOTH {
        for direction in WAYS {
            let crossing = Crossing::open(family);
            let packet = payload(256);
            let wire = crossing.emit(direction, &packet);
            let last = wire.len() - 1;

            let cases: [(&str, usize, Reject); 5] = [
                ("the counter", 8, Reject::Unauthenticated),
                (
                    "the sealed record",
                    HEADER_BYTES + 4,
                    Reject::Unauthenticated,
                ),
                ("the AEAD tag", last, Reject::Unauthenticated),
                ("the receiver index", 4, Reject::ForeignReceiver),
                ("a reserved byte", 1, Reject::Malformed),
            ];

            for (what, index, expected) in cases {
                let mut tampered = wire.clone();
                tampered[index] ^= 0x01;
                assert_eq!(
                    crossing.deliver(direction, &tampered),
                    Step::Rejected(expected),
                    "{family:?}/{direction:?}: one flipped bit in {what} was not refused as \
                     {expected:?}"
                );
                assert!(
                    !expected.tears_down(),
                    "{family:?}/{direction:?}: one bad datagram from an untrusted peer is not a \
                     teardown"
                );
                assert!(
                    crossing.receiver(direction).written().is_empty(),
                    "{family:?}/{direction:?}: a refused datagram must leave no plaintext on the \
                     peer's TUN device"
                );
            }

            // Positive control, last so that no tampered copy above could have
            // been refused merely as its replay.
            assert_eq!(
                crossing.deliver(direction, &wire),
                Step::Moved(packet.len()),
                "{family:?}/{direction:?}: the untampered datagram did not cross, so the \
                 refusals above are not attributable to the tampering"
            );
            assert_eq!(crossing.receiver(direction).written(), vec![packet]);
        }
    }
}

/// **Attack test — ADR-0001 §7.5 item 2, the hard revocation lever.** A peer
/// presenting the wrong `TwinNetPSK` never establishes, so there is no session
/// for it to carry a packet over.
///
/// This is what makes revocation cryptographic rather than advisory: a device
/// that holds a valid static but was not a recipient of the current `EpochSeed`
/// cannot complete `Noise_IKpsk2`, and the `psk2` slot is what buys that.
///
/// # How this is known to fail for the right reason
///
/// The **only** difference between the refused attempt and the accepted one is
/// the `EpochSeed` — same statics, same tags, same prologue, same code path
/// through `Crossing::attempt`. The accepted one is asserted in this test, so a
/// refusal cannot be blamed on a rig that never handshakes. Restoring the
/// matching seed turns the refusal into a live crossing, which is the second
/// half of the test.
///
/// A stale *epoch number* is asserted to be the same refusal, not a
/// distinguishable one: §7.3.1 P-3 requires the two to be indistinguishable to
/// an observer, and a test that accepted a different error here would be
/// blessing an oracle.
#[test]
fn a_wrong_psk_peer_never_establishes() {
    for family in BOTH {
        // Positive control: the same construction with agreeing key material
        // does establish and does carry a packet.
        let agreeing = Crossing::attempt(family, &SHARED_EPOCH_SEED, &SHARED_EPOCH_SEED)
            .expect("agreeing peers establish");
        let packet = payload(128);
        agreeing.cross(Direction::LeftToRight, &packet);
        assert_eq!(
            agreeing.right.written(),
            vec![packet],
            "{family:?}: the control crossing did not carry a packet, so a refusal below would \
             not be attributable to the PSK"
        );

        // The attack: a device presenting stale material for the same epoch.
        let other_seed = [0x02; 32];
        assert!(
            Crossing::attempt(family, &SHARED_EPOCH_SEED, &other_seed).is_err(),
            "{family:?}: a PSK mismatch produced a session — revocation is advisory, not \
             cryptographic"
        );
        assert!(
            Crossing::attempt(family, &other_seed, &SHARED_EPOCH_SEED).is_err(),
            "{family:?}: the refusal must not depend on which end holds the stale seed"
        );
    }
}

/// **Attack test.** A datagram sealed by a *different* session does not open at
/// this receiver, whatever its header says.
///
/// Without this, every assertion in this file is compatible with a receiver that
/// accepts anything addressed to its index: the crossing test would pass, the
/// tamper test would pass for the wrong reason, and only a coincidence would
/// separate them. This is the assertion that the keys are the peer's and nobody
/// else's.
///
/// # How this is known to fail for the right reason
///
/// The foreign datagram is produced by a second [`Crossing`] with the same
/// indices, the same MTU and the same framing — so it is byte-compatible with
/// this receiver's parser and differs only in the key that sealed it. It is
/// delivered at counter 0, which this receiver has not yet used, so a refusal
/// cannot be a replay. And the receiver's *own* first datagram is delivered
/// afterwards and asserted to cross, which is the positive control.
#[test]
fn a_datagram_from_another_session_does_not_open_at_this_receiver() {
    for family in BOTH {
        let ours = Crossing::open(family);
        let theirs = Crossing::attempt(family, &[0x77; 32], &[0x77; 32])
            .expect("a second, independently keyed session");

        let packet = payload(200);
        let foreign = theirs.emit(Direction::LeftToRight, &packet);

        assert_eq!(
            ours.deliver(Direction::LeftToRight, &foreign),
            Step::Rejected(Reject::Unauthenticated),
            "{family:?}: a datagram from another session opened at this receiver"
        );
        assert!(
            ours.right.written().is_empty(),
            "{family:?}: a failed open must leave no plaintext behind"
        );

        // Positive control: this receiver is working.
        let mine = payload(201);
        ours.cross(Direction::LeftToRight, &mine);
        assert_eq!(ours.right.written(), vec![mine]);
    }
}
