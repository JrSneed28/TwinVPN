//! Fuzzing every decoder that reads a **peer-authored signed statement**.
//!
//! **Owner:** `test-engineering`.
//!
//! # The threat model this file is built around
//!
//! `wire_decoders.rs` fuzzes unauthenticated bytes. These decoders sit *behind*
//! a signature, which makes the naive fuzz — flip a bit in the envelope — test
//! almost nothing: every mutation fails the signature check, and the payload
//! decoder is never reached.
//!
//! The adversary that matters here is a **legitimate peer**, or a stolen key.
//! It holds a signing key and can therefore sign whatever payload it likes, so
//! the interesting input is not a corrupted envelope but a **validly signed,
//! arbitrarily shaped payload**. Every target below is therefore generated as a
//! random CBOR tree, signed with a real ES256 key, verified through the real
//! `verify_cose_sign1`, and only then handed to the decoder — which is the exact
//! path a hostile peer's statement takes.
//!
//! Both halves are covered: the envelope parser is fuzzed with unsigned garbage
//! (it must reject, and must not panic doing it), and the payload decoders are
//! fuzzed with signed garbage (they must reject, and must not panic doing it).

use twinvpn_crypto::emit::{encode, int_item, Item};
use twinvpn_crypto::statements;
use twinvpn_crypto::testkit::FixtureIdentity;
use twinvpn_crypto::{dcbor, PublicVerifyingKey, StatementKind, VerifiedStatement};
use twinvpn_system_tests::fuzz::{corpus, fuzz, outcome_of, Fuzzer, Outcome};

const SEED: u64 = 0x7717_4E17_5EED_0002;
const ITERATIONS: usize = 1_200;

/// The signing identity. Deterministic: CD-3 bans reaching for a CSPRNG here,
/// and a fuzz failure that cannot be replayed is a bug report nobody can act on.
fn identity() -> FixtureIdentity {
    FixtureIdentity::from_seed(b"twinvpn fuzz statement identity")
}

/// A structurally plausible `DeviceIdentityRecord` payload, for a mutation seed.
fn identity_record_payload() -> Item {
    Item::Map(vec![
        (Item::Uint(1), Item::Text("twinnet-fuzz".to_owned())),
        (Item::Uint(2), Item::Bytes(vec![0x11; 32])),
        (Item::Uint(3), Item::Bytes(vec![0x22; 32])),
        (Item::Uint(4), Item::Uint(1)),
        (Item::Uint(5), Item::Bytes(identity().cose_key())),
        (Item::Uint(6), Item::Bytes(vec![0x33; 40])),
        (Item::Uint(7), Item::Uint(1)),
        (Item::Uint(8), Item::Bool(true)),
        (Item::Uint(9), Item::Uint(1_700_000_000_000)),
        (Item::Uint(10), Item::Uint(2_000_000_000_000)),
        // Label 11 is the `crit-set`. The CDDL requires `generation` and
        // `tk_generation` to be in it, and a seed that omitted them would make
        // the positive control below vacuous.
        (
            Item::Uint(11),
            Item::Array(vec![
                Item::Text("generation".to_owned()),
                Item::Text("tk_generation".to_owned()),
            ]),
        ),
    ])
}

// ---------------------------------------------------------------------------
// Deterministic CBOR. Every signed statement, every anchor and every COSE key in
// the product passes through this parser first, so it is the single decoder with
// the widest blast radius in the core.
// ---------------------------------------------------------------------------

#[test]
fn the_deterministic_cbor_parser_is_total_over_arbitrary_bytes() {
    let seeds = vec![
        identity().cose_key(),
        encode(&identity_record_payload()).expect("encode"),
        encode(&Item::Array(vec![
            Item::Null,
            Item::Bool(false),
            int_item(-1),
        ]))
        .expect("encode"),
    ];
    let inputs = corpus(SEED, ITERATIONS, 2_048, &seeds);
    let report = fuzz("crypto::dcbor::parse_canonical", &inputs, |b| {
        outcome_of(&dcbor::parse_canonical(b))
    });
    assert!(report.reached_accept(), "{report:?}");
    assert!(report.reached_reject(), "{report:?}");
}

#[test]
fn a_deeply_nested_cbor_input_is_refused_rather_than_recursed() {
    // Indefinite-length array heads, two thousand deep. A recursive-descent
    // parser with no depth bound overflows the host's stack here, which is a
    // remote crash rather than a parse failure.
    let mut nested = vec![0x9fu8; 2_000];
    nested.extend(std::iter::repeat_n(0xffu8, 2_000));
    assert!(
        dcbor::parse_canonical(&nested).is_err(),
        "indefinite-length heads are not canonical and must be refused"
    );

    // The same shape with definite-length single-element arrays, which *are*
    // canonical individually and so must be refused on depth alone.
    let mut definite = vec![0x81u8; 2_000];
    definite.push(0x00);
    assert!(
        dcbor::parse_canonical(&definite).is_err(),
        "two thousand levels must be bounded, not recursed"
    );
}

// ---------------------------------------------------------------------------
// COSE keys. A peer's identity key arrives as one of these, before anything
// about the peer has been established.
// ---------------------------------------------------------------------------

#[test]
fn the_cose_key_parser_is_total_over_arbitrary_bytes() {
    let seeds = vec![
        identity().cose_key(),
        twinvpn_crypto::testkit::x25519_cose_key(&[0x44; 32]),
    ];
    let inputs = corpus(SEED ^ 0x11, ITERATIONS, 1_024, &seeds);
    let report = fuzz("crypto::PublicVerifyingKey::from_cose_key", &inputs, |b| {
        outcome_of(&PublicVerifyingKey::from_cose_key(
            b,
            StatementKind::DeviceIdentityRecord,
        ))
    });
    assert!(report.reached_accept(), "{report:?}");
    assert!(report.reached_reject(), "{report:?}");
}

#[test]
fn the_trust_identity_key_parser_is_total_over_arbitrary_bytes() {
    let seeds = vec![identity().cose_key()];
    let inputs = corpus(SEED ^ 0x12, ITERATIONS, 1_024, &seeds);
    let report = fuzz("trust::identity::parse_identity_key", &inputs, |b| {
        outcome_of(&twinvpn_trust::identity::parse_identity_key(b))
    });
    assert!(report.reached_reject(), "{report:?}");
    // N-1 fixes ES256 here, so the fixture's own key must be the accepted case
    // and nothing the fuzzer stumbled onto should join it.
    assert!(
        twinvpn_trust::identity::parse_identity_key(&identity().cose_key()).is_ok(),
        "the positive control must still pass"
    );
}

// ---------------------------------------------------------------------------
// The COSE_Sign1 envelope, with an unsigned attacker: the bytes arrive before
// any key has authorised anything.
// ---------------------------------------------------------------------------

#[test]
fn the_cose_sign1_verifier_is_total_over_arbitrary_envelopes() {
    let id = identity();
    let key = id.verifying_key();
    let seeds = vec![
        id.sign(&identity_record_payload()),
        id.sign(&Item::Map(vec![])),
    ];
    let inputs = corpus(SEED ^ 0x13, ITERATIONS / 4, 2_048, &seeds);
    let report = fuzz("crypto::verify_cose_sign1", &inputs, |b| {
        outcome_of(&twinvpn_crypto::verify_cose_sign1(
            b,
            StatementKind::DeviceIdentityRecord,
            &key,
        ))
    });
    assert!(report.reached_accept(), "{report:?} — the unmutated seed");
    assert!(report.reached_reject(), "{report:?}");
}

// ---------------------------------------------------------------------------
// The payload decoders, with a SIGNING adversary.
// ---------------------------------------------------------------------------

/// A bounded random CBOR tree.
///
/// Bounded at depth four and sixteen members, because the property under test is
/// the *decoder's* totality and an unbounded generator would be measuring the
/// signer instead.
fn arbitrary_item(f: &mut Fuzzer, depth: usize) -> Item {
    let leaf = depth == 0;
    match f.below(if leaf { 6 } else { 8 }) {
        0 => Item::Uint(f.next_u64() >> f.below(64)),
        1 => Item::Nint(f.next_u64() >> f.below(64)),
        2 => Item::Bytes(f.random_bytes(48)),
        3 => Item::Text(
            String::from_utf8(f.random_bytes(32)).unwrap_or_else(|_| "\u{fffd}".repeat(f.below(8))),
        ),
        4 => Item::Bool(f.one_in(2)),
        5 => Item::Null,
        6 => Item::Array(
            (0..f.below(6))
                .map(|_| arbitrary_item(f, depth - 1))
                .collect(),
        ),
        _ => Item::Map(
            (0..f.below(16))
                .map(|_| {
                    // Integer labels, because that is what every statement
                    // schema uses — a generator that mostly produced text keys
                    // would never reach a field accessor.
                    (Item::Uint(f.below(24) as u64), arbitrary_item(f, depth - 1))
                })
                .collect(),
        ),
    }
}

/// Every payload decoder, run over one verified statement of its own kind.
///
/// The `kind` is a **caller** label, not a wire field — `VerifiedStatement`'s
/// own documentation says `statement_type` on the wire "is a HINT for dispatch
/// only … an attacker controls this value" — so the same octets are verified
/// once per kind and handed to the decoder that claims them.
fn run_every_payload_decoder(
    octets: &[u8],
    key: &PublicVerifyingKey,
    verify_as: StatementKind,
) -> String {
    /// `(kind, decoder)`, as one table, so a decoder added without a fuzz entry
    /// is a visible omission rather than an invisible one.
    type Decoder = fn(&VerifiedStatement) -> String;
    fn render<T: core::fmt::Debug, E: core::fmt::Debug>(r: &Result<T, E>) -> String {
        match r {
            Ok(v) => format!("ok:{v:?}"),
            Err(e) => format!("err:{e:?}"),
        }
    }
    const TABLE: &[(StatementKind, Decoder)] = &[
        (StatementKind::DeviceIdentityRecord, |s| {
            render(&statements::decode_device_identity_record(s))
        }),
        (StatementKind::IdentitySuccession, |s| {
            render(&statements::decode_identity_succession(s))
        }),
        (StatementKind::PairingAttestation, |s| {
            render(&statements::decode_pairing_attestation(s))
        }),
        (StatementKind::RevocationStatement, |s| {
            render(&statements::decode_revocation_statement(s))
        }),
        (StatementKind::RevocationEntry, |s| {
            render(&statements::decode_revocation_entry(s))
        }),
        (StatementKind::TrustEpochBundle, |s| {
            render(&statements::decode_trust_epoch_bundle(s))
        }),
        (StatementKind::OwnerTrustAnchor, |s| {
            render(&statements::decode_owner_trust_anchor(s))
        }),
        (StatementKind::OwnerDelegation, |s| {
            render(&statements::decode_owner_delegation(s))
        }),
        (StatementKind::PolicyBundle, |s| {
            render(&statements::decode_policy_bundle(s))
        }),
        (StatementKind::RouteAdvertisement, |s| {
            render(&statements::decode_route_advertisement(s))
        }),
        (StatementKind::ExitNodeOffer, |s| {
            render(&statements::decode_exit_node_offer(s))
        }),
        (StatementKind::RelayEpochFloor, |s| {
            render(&statements::decode_relay_epoch_floor(s))
        }),
        (StatementKind::LogHead, |s| {
            render(&statements::decode_log_head(s))
        }),
        (StatementKind::NetworkContract, |s| {
            render(&statements::decode_network_contract(s))
        }),
    ];

    // ONE signature verification per input, not fourteen. An ES256 verify in a
    // debug build costs milliseconds; fourteen of them per input turned this
    // test into a minute of CI time that measured the same thing fourteen times.
    // The kind is rotated across the corpus instead, so every decoder still sees
    // statements verified under its own label, and every decoder additionally
    // sees a statement verified under someone else's — which is the mismatch
    // `Schema::check` exists to refuse.
    let mut fingerprint = String::new();
    match twinvpn_crypto::verify_cose_sign1(octets, verify_as, key) {
        Ok(verified) => {
            for (_, decoder) in TABLE {
                fingerprint.push_str(&decoder(&verified));
                fingerprint.push('|');
            }
        }
        Err(e) => fingerprint.push_str(&format!("verify:{e:?}")),
    }
    fingerprint
}

/// The kinds the table covers, in table order, for the rotation above.
const KINDS: [StatementKind; 14] = [
    StatementKind::DeviceIdentityRecord,
    StatementKind::IdentitySuccession,
    StatementKind::PairingAttestation,
    StatementKind::RevocationStatement,
    StatementKind::RevocationEntry,
    StatementKind::TrustEpochBundle,
    StatementKind::OwnerTrustAnchor,
    StatementKind::OwnerDelegation,
    StatementKind::PolicyBundle,
    StatementKind::RouteAdvertisement,
    StatementKind::ExitNodeOffer,
    StatementKind::RelayEpochFloor,
    StatementKind::LogHead,
    StatementKind::NetworkContract,
];

#[test]
fn every_statement_payload_decoder_is_total_under_a_signing_adversary() {
    let id = identity();
    let key = id.verifying_key();

    // Signed inputs, so the corpus is built here rather than by `corpus()`: the
    // engine mutates bytes, and a mutated byte never survives a signature.
    let mut f = Fuzzer::new(SEED ^ 0x14);
    let mut signed: Vec<Vec<u8>> = Vec::with_capacity(ITERATIONS + 2);
    signed.push(id.sign(&identity_record_payload()));
    signed.push(id.sign(&Item::Map(vec![])));
    for _ in 0..ITERATIONS {
        let item = arbitrary_item(&mut f, 4);
        // `encode` refuses a payload it cannot render canonically; that is the
        // signer's job, not the decoder's, so such a draw is simply skipped.
        if let Ok(payload) = encode(&item) {
            if let Ok(parsed) = dcbor::parse_canonical(&payload) {
                let _ = parsed;
                signed.push(id.sign(&item));
            }
        }
    }

    // The rotation has to be a pure function of the input, not of a counter:
    // the engine calls each input twice and compares, so a stateful closure
    // would report itself as non-deterministic.
    let report = fuzz("crypto::statements::decode_*", &signed, |b| {
        let rotation = b.iter().fold(0usize, |a, x| a ^ *x as usize) % KINDS.len();
        Outcome::accept(run_every_payload_decoder(b, &key, KINDS[rotation]))
    });
    assert!(
        report.inputs > ITERATIONS as u32 / 2,
        "the generator produced almost nothing signable: {report:?}"
    );

    // A positive control, so a generator that silently stopped producing
    // well-formed payloads would fail rather than pass vacuously.
    let good = id.sign(&identity_record_payload());
    let verified =
        twinvpn_crypto::verify_cose_sign1(&good, StatementKind::DeviceIdentityRecord, &key)
            .expect("the fixture verifies");
    assert!(
        statements::decode_device_identity_record(&verified).is_ok(),
        "the positive control must still decode"
    );
}
