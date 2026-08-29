//! The refusals `pairing_offer.cddl` requires, and the rendering it forbids.
//!
//! **Authority:** `contracts/cddl/twinvpn/v1/pairing_offer.cddl` (Amendment 4);
//! ADR-0007 §7.4; `contracts/registry/limits.json` `pairing`.
//!
//! Every test here is a *negative* except the two round-trips, because the
//! offer's whole security argument is what it refuses. The CDDL names eight
//! conditions; each one has a test below whose name is the rule.

use twinvpn_crypto::emit::{encode as emit_encode, Item};
use twinvpn_crypto::pairing_offer::{self, PairingOffer};
use twinvpn_schema::limits;
use twinvpn_types::codes;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A distinctive secret, so `the_debug_rendering_carries_no_secret_byte` is
/// searching for a byte pattern that could not appear by accident.
const SECRET: [u8; 32] = [0xA7; 32];
const TK_PUB: [u8; 32] = [0x5C; 32];

fn ik_pub() -> Vec<u8> {
    // 43 bytes: the measured size of a P-256 compressed EC2 COSE_Key. The
    // contents do not matter here — this module decodes the offer, it does not
    // parse the key.
    vec![0x11; 43]
}

fn binding() -> Vec<u8> {
    // 216 bytes: the measured size of the COSE_Sign1(TunnelKeyBinding) the
    // amendment's arithmetic is built on.
    vec![0x22; 216]
}

fn valid_offer() -> PairingOffer {
    pairing_offer::build(
        SECRET,
        ik_pub(),
        TK_PUB,
        binding(),
        "rendezvous.example".to_owned(),
        1_000_000,
    )
    .expect("the fixture is within every bound")
}

/// The seven fields as `Item`s, so a test can corrupt exactly one.
fn offer_items() -> Vec<(Item, Item)> {
    vec![
        (Item::Uint(1), Item::Bytes(SECRET.to_vec())),
        (Item::Uint(2), Item::Bytes(ik_pub())),
        (Item::Uint(3), Item::Bytes(TK_PUB.to_vec())),
        (Item::Uint(4), Item::Bytes(binding())),
        (Item::Uint(5), Item::Null),
        (Item::Uint(6), Item::Text("rendezvous.example".to_owned())),
        (Item::Uint(7), Item::Uint(1_000_000)),
    ]
}

fn encoded(items: Vec<(Item, Item)>) -> Vec<u8> {
    emit_encode(&Item::Map(items)).expect("fixture encodes")
}

// ---------------------------------------------------------------------------
// The round trip, and the byte-identity rule 1 rests on
// ---------------------------------------------------------------------------

#[test]
fn a_conforming_offer_round_trips_through_both_directions() {
    let bytes = pairing_offer::encode(&valid_offer()).expect("encodes");
    let back = pairing_offer::decode(&bytes).expect("decodes");
    assert_eq!(back.pairing_secret(), &SECRET);
    assert_eq!(back.tk_pub(), &TK_PUB);
    assert_eq!(back.ik_pub_cose(), ik_pub().as_slice());
    assert_eq!(back.binding(), binding().as_slice());
    assert_eq!(back.rendezvous_hint(), "rendezvous.example");
    assert_eq!(back.not_after_ms(), 1_000_000);
}

/// Encoding rule 1: "Two conforming producers MUST emit byte-identical output
/// for the same logical value, because ADR-0023 E2 renders THESE BYTES as
/// Crockford base32 for a human to copy and E1 renders THESE BYTES as a QR."
///
/// Two producers cannot be run here, so the property is asserted the way it can
/// be: an encode, a decode and a re-encode agree byte for byte, which is the
/// half of determinism a single implementation can prove.
#[test]
fn the_encoding_is_byte_identical_across_a_decode_and_a_re_encode() {
    let first = pairing_offer::encode(&valid_offer()).expect("encodes");
    let decoded = pairing_offer::decode(&first).expect("decodes");
    let second = pairing_offer::encode(&decoded).expect("re-encodes");
    assert_eq!(first, second);
}

/// The encoded size, pinned — because finding F-1's whole argument is a size.
///
/// Amendment 4 measured the offer at **377 bytes** for "a COSE_Key EC2 P-256
/// compressed key (43 B), a tunnel-key-binding … inside a COSE_Sign1 (216 B),
/// and a 27-character hint", and ADR-0023 EM-22a derived the 79x41 terminal
/// geometry from that figure. So the number is load-bearing twice over, and a
/// silent drift in the encoder would move a published ADR rule underneath it.
///
/// This encoder puts the amendment's own inputs at **378**, one byte above the
/// recorded figure. The byte is not in this fixture and not in the encoder: the
/// amendment's note does not state the `not_after_ms` it measured, and a real
/// epoch-millisecond timestamp needs CBOR's 8-byte `uint` head (9 bytes, plus
/// the key) while any value below 2^32 needs only 5. **Recorded rather than
/// reconciled by adjusting an assertion to whatever the code emits** — the
/// direction is the safe one (the offer is one byte *larger* than the geometry
/// was derived for, and EM-22a's v13-at-level-L symbol holds 425), and closing
/// it belongs to whoever owns the measurement.
#[test]
fn the_encoded_size_is_pinned_and_matches_the_amendment_arithmetic() {
    // This fixture: an 18-character hint and a `not_after_ms` under 2^32.
    let bytes = pairing_offer::encode(&valid_offer()).expect("encodes");
    assert_eq!(bytes.len(), 364, "the encoder drifted");
    assert!(bytes.len() <= limits::PAIRING_MAX_OFFER_BYTES);

    // The amendment's own inputs: a 27-character hint and a real epoch-ms.
    let as_measured = pairing_offer::build(
        SECRET,
        ik_pub(),
        TK_PUB,
        binding(),
        "x".repeat(27),
        1_787_995_789_742,
    )
    .expect("within every bound");
    let measured = pairing_offer::encode(&as_measured).expect("encodes");
    assert_eq!(
        measured.len(),
        378,
        "the encoder no longer agrees with Amendment 4's stated inputs"
    );
    assert!(
        measured.len() <= limits::PAIRING_MAX_OFFER_BYTES,
        "the offer must fit its own payload cap at the measured size"
    );
}

// ---------------------------------------------------------------------------
// Rule 2 — the payload cap, checked before any field is parsed
// ---------------------------------------------------------------------------

#[test]
fn an_over_length_payload_is_refused_before_the_first_field_is_read() {
    // Deliberately not valid CBOR past its first byte. If the length check did
    // not come first, the parser would reach it and report a *canonicity*
    // failure — so the code asserted here is the evidence of the ordering, not
    // just of the refusal.
    let oversized = vec![0xA7; limits::PAIRING_MAX_OFFER_BYTES + 1];
    let err = pairing_offer::decode(&oversized).expect_err("refused");
    assert_eq!(err.reason_code(), codes::PROTO_SIZE_EXCEEDED);
}

#[test]
fn an_offer_at_exactly_the_payload_cap_is_not_refused_for_its_length() {
    let at_cap = vec![0xA7; limits::PAIRING_MAX_OFFER_BYTES];
    let err = pairing_offer::decode(&at_cap).expect_err("still not valid CBOR");
    assert_ne!(
        err.reason_code(),
        codes::PROTO_SIZE_EXCEEDED,
        "the cap is inclusive; an off-by-one here would refuse a conforming offer"
    );
}

// ---------------------------------------------------------------------------
// Rule 1 — deterministic CBOR, refused rather than normalised
// ---------------------------------------------------------------------------

#[test]
fn a_map_in_non_canonical_key_order_is_refused_and_never_normalised() {
    // Hand-built so the keys arrive as 7,1,2,3,4,5,6 — `emit::encode` sorts, so
    // the emitter cannot produce this and the bytes have to be assembled here.
    let mut bytes = vec![0xA7]; // map(7)
    let mut push = |k: u8, mut v: Vec<u8>| {
        bytes.push(k);
        bytes.append(&mut v);
    };
    push(0x07, vec![0x1A, 0x00, 0x0F, 0x42, 0x40]); // 7: 1000000
    push(0x01, {
        let mut v = vec![0x58, 0x20];
        v.extend_from_slice(&SECRET);
        v
    });
    let err = pairing_offer::decode(&bytes).expect_err("refused");
    assert_eq!(err.reason_code(), codes::PROTO_NON_CANONICAL_CBOR);
}

#[test]
fn a_duplicate_key_is_refused() {
    // Two entries for key 1. Canonical ordering is *strictly* increasing, so a
    // duplicate is caught by the same rule that catches an unsorted map — which
    // is why the CDDL does not need a separate clause for it.
    let mut bytes = vec![0xA2, 0x01, 0x41, 0x00, 0x01, 0x41, 0x00];
    bytes.shrink_to_fit();
    let err = pairing_offer::decode(&bytes).expect_err("refused");
    assert_eq!(err.reason_code(), codes::PROTO_NON_CANONICAL_CBOR);
}

// ---------------------------------------------------------------------------
// Rule 3 — unknown keys are rejected, and so are missing ones
// ---------------------------------------------------------------------------

#[test]
fn an_unknown_key_is_refused_rather_than_ignored() {
    let mut items = offer_items();
    items.push((Item::Uint(8), Item::Uint(0)));
    let err = pairing_offer::decode(&encoded(items)).expect_err("refused");
    assert_eq!(err.reason_code(), codes::PROTO_NON_CANONICAL_CBOR);
}

#[test]
fn a_missing_key_is_refused() {
    let mut items = offer_items();
    items.retain(|(k, _)| *k != Item::Uint(6));
    let err = pairing_offer::decode(&encoded(items)).expect_err("refused");
    assert_eq!(err.reason_code(), codes::PROTO_NON_CANONICAL_CBOR);
}

// ---------------------------------------------------------------------------
// The per-field bounds
// ---------------------------------------------------------------------------

#[test]
fn a_secret_of_the_wrong_width_is_refused() {
    let mut items = offer_items();
    items[0].1 = Item::Bytes(vec![0xA7; 31]);
    let err = pairing_offer::decode(&encoded(items)).expect_err("refused");
    assert_eq!(err.reason_code(), codes::PROTO_NON_CANONICAL_CBOR);
}

#[test]
fn an_over_length_cose_key_is_refused() {
    let mut items = offer_items();
    items[1].1 = Item::Bytes(vec![0x11; limits::PAIRING_MAX_OFFER_COSE_KEY_BYTES + 1]);
    let err = pairing_offer::decode(&encoded(items)).expect_err("refused");
    assert_eq!(err.reason_code(), codes::PROTO_NON_CANONICAL_CBOR);
}

#[test]
fn an_over_length_binding_is_refused() {
    let mut items = offer_items();
    items[3].1 = Item::Bytes(vec![0x22; limits::PAIRING_MAX_OFFER_BINDING_BYTES + 1]);
    let err = pairing_offer::decode(&encoded(items)).expect_err("refused");
    assert_eq!(err.reason_code(), codes::PROTO_NON_CANONICAL_CBOR);
}

#[test]
fn an_over_length_hint_is_refused() {
    let mut items = offer_items();
    items[5].1 = Item::Text("x".repeat(limits::PAIRING_MAX_OFFER_HINT_BYTES + 1));
    let err = pairing_offer::decode(&encoded(items)).expect_err("refused");
    assert_eq!(err.reason_code(), codes::PROTO_NON_CANONICAL_CBOR);
}

/// `max_offer_attestation_bytes` is 0, so `null` is the only admissible value.
///
/// This is the narrowing of ADR-0007 §7.4 that finding F-1 records. A build that
/// starts accepting a `bstr` here has changed the contract, and this test is
/// where that shows up.
#[test]
fn a_non_null_attestation_is_refused_because_this_channel_admits_no_other_value() {
    let mut items = offer_items();
    items[4].1 = Item::Bytes(vec![0x33; 1]);
    let err = pairing_offer::decode(&encoded(items)).expect_err("refused");
    assert_eq!(err.reason_code(), codes::PROTO_NON_CANONICAL_CBOR);
}

// ---------------------------------------------------------------------------
// Rule 5 — the receiver owns the window
// ---------------------------------------------------------------------------

#[test]
fn an_offer_past_its_own_expiry_is_refused() {
    let offer = valid_offer();
    let err = pairing_offer::check_window(&offer, offer.not_after_ms()).expect_err("refused");
    assert_eq!(err.reason_code(), codes::AUTH_PAIRING_EXPIRED);
}

/// "An offer that names its own longer window is a producer trying to widen a
/// bound the receiver owns."
#[test]
fn an_offer_naming_a_window_longer_than_the_ceremony_is_refused() {
    let far = pairing_offer::build(
        SECRET,
        ik_pub(),
        TK_PUB,
        binding(),
        String::new(),
        u64::from(u32::MAX),
    )
    .expect("within every byte bound");
    let err = pairing_offer::check_window(&far, 0).expect_err("refused");
    assert_eq!(err.reason_code(), codes::AUTH_PAIRING_EXPIRED);
}

#[test]
fn an_offer_inside_the_ceremony_window_is_accepted() {
    let offer = valid_offer();
    let now = offer.not_after_ms() - 1_000;
    pairing_offer::check_window(&offer, now).expect("inside the window");
}

// ---------------------------------------------------------------------------
// The secret, and the rendering the CDDL forbids
// ---------------------------------------------------------------------------

/// R-9's pattern. The earlier `PresentedToken` tripwire passed only because
/// `Vec<u8>` renders as decimal digits, so a `Debug` that *did* leak the bytes
/// looked clean to a substring search for hex. This searches for the decimal
/// rendering as well, which is the one a derived `Debug` would actually emit.
#[test]
fn the_debug_rendering_carries_no_secret_byte() {
    let rendered = format!("{:?}", valid_offer());
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(!rendered.contains("167"), "decimal 0xA7 leaked: {rendered}");
    assert!(!rendered.contains("a7"), "hex 0xA7 leaked: {rendered}");
    assert!(!rendered.contains("A7"), "hex 0xA7 leaked: {rendered}");
    assert!(
        !rendered.contains("rendezvous.example"),
        "the hint leaked: {rendered}"
    );
}

/// `pairing_id = SHA-256(pairing_secret)[0..16]`, derived rather than carried.
#[test]
fn the_pairing_id_is_derived_from_the_secret_and_is_the_registered_width() {
    let offer = valid_offer();
    let id = offer.pairing_id();
    assert_eq!(id.len(), limits::PAIRING_ID_BYTES);
    // Two offers with the same secret name the same ceremony; that is the whole
    // point of deriving rather than carrying it.
    assert_eq!(id, valid_offer().pairing_id());
}

/// `K_pair = HKDF-SHA-256(salt = pairing_id, ikm = pairing_secret,
/// info = "TwinVPN/Pair/v1")`.
#[test]
fn k_pair_is_derived_deterministically_and_is_not_the_secret() {
    let offer = valid_offer();
    let k = offer.derive_k_pair().expect("derives");
    assert_eq!(k, valid_offer().derive_k_pair().expect("derives"));
    assert_ne!(k, SECRET, "K_pair must not be the secret itself");
}

// ---------------------------------------------------------------------------
// The producer path enforces the same bounds as the receiver
// ---------------------------------------------------------------------------

/// An offer this device emits that its peer would refuse is a defect this device
/// should find. So `build` rejects what `decode` rejects, rather than letting a
/// producer discover its own bug at a real ceremony.
#[test]
fn the_builder_refuses_what_the_decoder_would_refuse() {
    for (ik, bind, hint) in [
        (vec![0x11; 200], binding(), String::new()),
        (ik_pub(), vec![0x22; 500], String::new()),
        (ik_pub(), binding(), "x".repeat(65)),
    ] {
        let err =
            pairing_offer::build(SECRET, ik, TK_PUB, bind, hint, 1_000).expect_err("out of bounds");
        assert_eq!(err.reason_code(), codes::PROTO_SIZE_EXCEEDED);
    }
}

// ---------------------------------------------------------------------------
// E2 — the text offer
// ---------------------------------------------------------------------------

/// EM-22 E2 renders "the same dCBOR bytes", so the text form and the QR form are
/// two views of one encoding and must reach the same peer state.
#[test]
fn the_text_offer_is_the_same_bytes_and_round_trips() {
    let offer = valid_offer();
    let text = pairing_offer::render_text(&offer).expect("renders");
    assert!(text.contains('-'), "E2 renders in groups of eight");
    let back = pairing_offer::parse_text(&text).expect("parses");
    assert_eq!(back.pairing_secret(), &SECRET);
    assert_eq!(
        pairing_offer::encode(&back).expect("re-encodes"),
        pairing_offer::encode(&offer).expect("encodes"),
        "the text channel changed the bytes"
    );
}

/// The tolerance E2 exists for. A serial console is where this gets retyped.
#[test]
fn a_text_offer_survives_case_folding_and_confusable_characters() {
    let offer = valid_offer();
    let text = pairing_offer::render_text(&offer).expect("renders");
    let mangled: String = text
        .chars()
        .map(|c| match c {
            '0' => 'O',
            '1' => 'I',
            c => c.to_ascii_lowercase(),
        })
        .collect();
    let back = pairing_offer::parse_text(&mangled).expect("tolerant");
    assert_eq!(back.pairing_secret(), &SECRET);
}

/// Rule 2 holds on the text path too: the cap is applied to the decoded length
/// before a buffer grows to meet it, and before `decode` sees a byte.
#[test]
fn an_over_long_text_offer_is_refused_by_size_not_by_a_parse_failure() {
    let long = twinvpn_types::crockford::encode_groups(
        &vec![0u8; limits::PAIRING_MAX_OFFER_BYTES + 64],
        8,
    );
    let err = pairing_offer::parse_text(&long).expect_err("refused");
    assert_eq!(err.reason_code(), codes::PROTO_SIZE_EXCEEDED);
}

#[test]
fn text_that_is_not_base32_at_all_is_refused_with_one_sentence() {
    let err = pairing_offer::parse_text("this is not an offer $$$").expect_err("refused");
    assert_eq!(err.reason_code(), codes::PROTO_NON_CANONICAL_CBOR);
}
