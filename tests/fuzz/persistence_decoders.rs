//! Fuzzing every decoder that reads bytes back off **local storage**.
//!
//! **Owner:** `test-engineering`.
//!
//! # Why local storage is an untrusted input
//!
//! It is tempting to treat the vault, the anchor and the session journal as
//! trusted because this device wrote them. They are not:
//!
//! - **ST-15 / ST-24 exist because they can be corrupted.** A truncated write,
//!   a half-flushed page, a filesystem that reordered two writes across a power
//!   loss — the store's whole rung ladder is built on the premise that what
//!   comes back may not be what went in.
//! - **An attacker with disk access is in the threat model.** The kill switch,
//!   the revocation floors and the trust epoch are all restored from these
//!   bytes. A decoder that panicked on a crafted vault would turn "someone
//!   touched the file" into "the daemon does not start", and a decoder that
//!   *partially accepted* one would turn it into a silent downgrade — which is
//!   why every decoder here refuses rather than repairs.
//!
//! So the same three properties apply, for the same reason:
//! [`twinvpn_system_tests::fuzz`].

use twinvpn_store::{Anchor, FloorId, FloorSet, Vault};
use twinvpn_system_tests::fuzz::{corpus, fuzz, outcome_of, Outcome};

const SEED: u64 = 0x7717_4E17_5EED_0003;
const ITERATIONS: usize = 1_500;

// ---------------------------------------------------------------------------
// The vault image. ST-15's rung-3 detector, and the largest attacker-writable
// length field in the product.
// ---------------------------------------------------------------------------

fn populated_vault() -> Vault {
    let mut vault = Vault::empty([0x5a; 16]);
    vault.store_seq = 42;
    vault
        .records
        .insert("peer/aabbcc".to_owned(), vec![0x01; 96]);
    vault
        .records
        .insert("policy/killswitch".to_owned(), vec![0x02; 32]);
    vault
}

#[test]
fn the_vault_decoder_is_total_over_arbitrary_images() {
    let seeds = vec![Vault::empty([0u8; 16]).encode(), populated_vault().encode()];
    let inputs = corpus(SEED, ITERATIONS, 4_096, &seeds);
    let report = fuzz("store::Vault::decode", &inputs, |b| {
        outcome_of(&Vault::decode(b))
    });
    assert!(report.reached_accept(), "{report:?}");
    assert!(report.reached_reject(), "{report:?}");
}

#[test]
fn a_vault_header_declaring_more_records_than_the_file_holds_is_refused() {
    // The count is a u32 an attacker writes. Rule 10: it is checked against what
    // the remaining bytes can hold BEFORE anything is reserved, so a header
    // claiming four billion records must be a refusal rather than an OOM.
    let mut image = populated_vault().encode();
    // record_count sits at magic(8) + schema(4) + store_id(16) + store_seq(8).
    image[36..40].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(
        Vault::decode(&image).is_err(),
        "a count the file cannot hold is a refusal, not an allocation"
    );
}

#[test]
fn a_vault_whose_checksum_does_not_cover_its_body_is_refused() {
    let mut image = populated_vault().encode();
    let last = image.len() - 33;
    image[last] ^= 0x01;
    assert!(
        Vault::decode(&image).is_err(),
        "a body edit must fail the checksum, not decode to a different vault"
    );
}

// ---------------------------------------------------------------------------
// The Tier-1 anchor. Deterministic CBOR, and the input a tamper-into-rebuild
// downgrade would target: `Anchor::decode`'s own contract is that a malformed
// anchor is NOT "absent".
// ---------------------------------------------------------------------------

fn populated_anchor() -> Anchor {
    // A fixed floor and a per-peer one, because `Anchor::encode` elides the
    // per-peer half to fit the cap and a seed with only fixed floors would never
    // exercise that branch.
    let floors = FloorSet::from_pairs([
        (FloorId::TrustEpoch, 7),
        (FloorId::MinAcceptableEpoch, 3),
        (FloorId::AnchorVersion, 2),
        (FloorId::ContractSeq, 11),
        (FloorId::StoreSeq, 42),
        (FloorId::PeerGeneration(vec![0x11; 32]), 19),
    ]);
    Anchor::new([0x5a; 16], 42, [0xab; 32], &floors)
}

#[test]
fn the_anchor_decoder_is_total_over_arbitrary_bytes() {
    let seeds = vec![populated_anchor().encode().expect("encode")];
    let inputs = corpus(SEED ^ 0x11, ITERATIONS, 2_048, &seeds);
    let report = fuzz("store::Anchor::decode", &inputs, |b| {
        outcome_of(&Anchor::decode(b))
    });
    assert!(report.reached_accept(), "{report:?}");
    assert!(report.reached_reject(), "{report:?}");
}

#[test]
fn a_malformed_anchor_is_an_error_and_never_reads_as_absent() {
    // Treating a tampered anchor as "no anchor" is the downgrade the decoder's
    // own doc comment names. Asserted here rather than assumed, because it is a
    // property of the *return type* and a refactor could quietly lose it.
    for spoiled in [
        vec![],
        vec![0xa0],     // an empty map: canonical, wrong shape
        vec![0xff; 64], // not CBOR at all
        populated_anchor().encode().expect("encode")[..8].to_vec(), // truncated
    ] {
        assert!(
            Anchor::decode(&spoiled).is_err(),
            "a malformed anchor must be an error, not an absence"
        );
    }
}

// ---------------------------------------------------------------------------
// The session journal. What a reconnect after a crash is rebuilt from — and
// `SessionJournal::load_all`'s contract is that an error here must NOT be read
// as "no sessions", because that silently drops every peer.
// ---------------------------------------------------------------------------

/// A valid record, laid out as `journal::encode` writes it.
///
/// Hand-built because `encode` is private, which is correct — it is an
/// implementation detail of the journal — and because writing the layout out
/// here is what makes a change to it fail this test rather than pass silently.
fn journal_record(reason: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x07; 16]); // session_id
    out.extend_from_slice(&[0x11; 32]); // peer device_id
    out.push(8); // tag 8 = RECONNECTING
    out.push(0); // param: not parked
    match reason {
        Some(code) => {
            out.push(u8::try_from(code.len()).expect("short code"));
            out.extend_from_slice(code.as_bytes());
        }
        None => out.push(0),
    }
    out
}

#[test]
fn the_session_journal_decoder_is_total_over_arbitrary_records() {
    let seeds = vec![
        journal_record(None),
        journal_record(Some("NET.PATH.DEAD")),
        journal_record(Some("A.CODE_NO_REGISTRY_HAS")),
    ];
    let inputs = corpus(SEED ^ 0x22, ITERATIONS, 512, &seeds);
    let report = fuzz("core::journal::decode", &inputs, |b| {
        outcome_of(&twinvpn_core::journal::decode(b))
    });
    assert!(report.reached_accept(), "{report:?}");
    assert!(report.reached_reject(), "{report:?}");
}

#[test]
fn a_journal_record_whose_reason_length_runs_past_the_end_is_refused() {
    let mut record = journal_record(None);
    record[50] = 200; // a declared reason length the record cannot hold
    assert!(
        twinvpn_core::journal::decode(&record).is_err(),
        "a length that runs past the end is refused, not read"
    );
}

// ---------------------------------------------------------------------------
// The cached peer record. S-15's cache is what a reconnect during a total
// control-plane outage uses, so a decoder that half-accepted one would make
// "we still have the peer" false without anyone noticing.
// ---------------------------------------------------------------------------

/// A valid peer record, laid out as `bridge::encode_peer` writes it.
fn peer_record(endpoints: &[(u8, &[u8], u16)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x11; 32]); // device_id
    out.extend_from_slice(&7u32.to_be_bytes()); // generation
    out.extend_from_slice(&3u32.to_be_bytes()); // tk_generation
    out.push(1); // tunnel_key_binding_verified
    out.extend_from_slice(&[100, 64, 0, 5]); // overlay v4
    out.extend_from_slice(&[0xfdu8; 16]); // overlay v6
    out.extend_from_slice(&u32::try_from(endpoints.len()).expect("small").to_be_bytes());
    for (family, address, port) in endpoints {
        out.push(*family);
        out.extend_from_slice(address);
        if *family == 6 {
            out.extend_from_slice(&0u32.to_be_bytes()); // zone index
        }
        out.extend_from_slice(&port.to_be_bytes());
    }
    out
}

#[test]
fn the_peer_record_decoder_is_total_over_arbitrary_records() {
    // Both families, because ADR-0010 R1 is one story covering both and a
    // corpus that only exercised the v4 arm would leave the v6 endpoint framing
    // — which carries an extra four zone-index bytes — unfuzzed.
    let seeds = vec![
        peer_record(&[]),
        peer_record(&[(4, &[192, 0, 2, 1], 51820)]),
        peer_record(&[(
            6,
            &[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            51820,
        )]),
        peer_record(&[
            (4, &[192, 0, 2, 1], 51820),
            (
                6,
                &[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                51821,
            ),
        ]),
    ];
    let inputs = corpus(SEED ^ 0x33, ITERATIONS, 512, &seeds);
    let report = fuzz("core::bridge::decode_peer", &inputs, |b| {
        outcome_of(&twinvpn_core::bridge::decode_peer(b))
    });
    assert!(report.reached_accept(), "{report:?}");
    assert!(report.reached_reject(), "{report:?}");
}

#[test]
fn a_peer_record_declaring_more_endpoints_than_it_carries_is_refused() {
    let mut record = peer_record(&[(4, &[192, 0, 2, 1], 51820)]);
    record[61..65].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(
        twinvpn_core::bridge::decode_peer(&record).is_err(),
        "the count is bounded by what the remaining bytes hold"
    );
}

// ---------------------------------------------------------------------------
// Record keys. The flat `namespace/key` form, read back from a vault an
// attacker may have written.
// ---------------------------------------------------------------------------

#[test]
fn the_record_key_parser_is_total_over_arbitrary_text() {
    let seeds = vec![
        b"peer/aabbccdd".to_vec(),
        b"policy/killswitch".to_vec(),
        vec![b'/'; 256],
    ];
    let inputs = corpus(SEED ^ 0x44, ITERATIONS, 512, &seeds);
    let report = fuzz(
        "store::RecordKey::parse",
        &inputs,
        |b| match core::str::from_utf8(b) {
            Ok(flat) => outcome_of(&twinvpn_store::RecordKey::parse(flat)),
            Err(e) => Outcome::reject(format!("{e:?}")),
        },
    );
    assert!(report.reached_accept(), "{report:?}");
    assert!(report.reached_reject(), "{report:?}");
}

// ---------------------------------------------------------------------------
// The diagnostics platform context. F-10's rule is that this decoder MUST NOT
// fail — "the moment it is called is often the moment nothing else works" — so
// its property is stronger than the others: it is total AND it never errors.
// ---------------------------------------------------------------------------

#[test]
fn the_platform_context_decoder_never_fails_and_never_falls_back_to_this_host() {
    use prost::Message as _;
    let seeds = vec![
        twinvpn_schema::v1::DevicePlatformInfo::default().encode_to_vec(),
        twinvpn_schema::v1::DevicePlatformInfo {
            platform: 2,
            os_version: "14.1".to_owned(),
            ..Default::default()
        }
        .encode_to_vec(),
    ];
    let inputs = corpus(SEED ^ 0x55, ITERATIONS, 1_024, &seeds);
    let report = fuzz("diag::PlatformContext::decode", &inputs, |b| {
        // Infallible by contract, so every input is an "accept" — and the
        // fingerprint is the whole decoded context, which is what makes the
        // determinism half of the engine meaningful for a decoder that cannot
        // signal a rejection at all.
        Outcome::accept(format!("{:?}", twinvpn_diag::PlatformContext::decode(b)))
    });
    assert_eq!(
        report.rejected, 0,
        "F-10 requires this decoder to be infallible: {report:?}"
    );
    // A slice that does not decode is the NEUTRAL context, never this host's own
    // platform: rendering a peer's diagnostic against the local platform is how
    // a support bundle acquires a fact nobody observed.
    assert_eq!(
        twinvpn_diag::PlatformContext::decode(&[0xff, 0xff, 0xff]),
        twinvpn_diag::PlatformContext::neutral(),
    );
}
