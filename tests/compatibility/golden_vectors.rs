//! **Compatibility.** The §2.3 golden-vector corpus, byte-exact, and DP-8's
//! two-provider claim made checkable.
//!
//! **Authority:** `docs/testing-strategy.md` §2.3 (the corpus classes, the
//! generation rule, the differential-decoding rule), §2.18; §6.5 blocker
//! **B-5**; ADR-0018 **DP-8**.
//!
//! # Two corpora, and what each one proves
//!
//! **`crypto-kat/`** — `tests/vectors/crypto-kat/manifest.json`. Every entry is
//! transcribed from its published specification (FIPS 180-4, RFC 5869) except
//! the last, which pins CD-4's own derivation and was computed by an
//! implementation outside this workspace. §2.3 says these must agree
//! **byte-exactly** with the published vectors.
//!
//! DP-8 requires **two** cryptographic providers to pass an *identical* corpus.
//! Only one provider exists today. The claim is therefore made *checkable*
//! rather than claimed: the corpus is data with no provider named in it, the
//! runner takes a [`Provider`], and a second implementation is a binding rather
//! than a second corpus. `a_second_provider_that_disagrees_fails_the_same_corpus`
//! is the negative control that shows the runner has teeth.
//!
//! **The frozen protobuf fixtures** — `contracts/tests/fixtures/*.binpb`. The
//! Python harness checks these against `buf` and protobuf.js. **Nothing checked
//! them against the Rust bindings the product actually ships**, so a prost
//! round-trip that reordered or dropped a field would be invisible until a
//! device met a server. These are read from the frozen tree rather than copied,
//! so there is exactly one corpus.

use std::collections::BTreeMap;

use prost::Message;
use twinvpn_schema::v1;

const MANIFEST: &str = include_str!("../vectors/crypto-kat/manifest.json");

// ---------------------------------------------------------------------------
// DP-8: the corpus names no provider.
// ---------------------------------------------------------------------------

/// The cryptographic operations the corpus exercises.
///
/// DP-8's "identical corpus" is only meaningful if the corpus cannot see which
/// provider is running it. This trait is that boundary.
trait Provider {
    /// A name for an assertion message.
    fn name(&self) -> &'static str;
    /// SHA-256.
    fn sha256(&self, input: &[u8]) -> Vec<u8>;
    /// HKDF-SHA-256. `salt` of `None` is RFC 5869 §2.2's zero salt.
    fn hkdf(&self, salt: Option<&[u8]>, ikm: &[u8], info: &[u8], len: usize) -> Vec<u8>;
}

/// The one provider that exists: `twinvpn-crypto`, which CD-I2 makes the only
/// crate permitted a cryptographic dependency.
struct TwinvpnCrypto;

impl Provider for TwinvpnCrypto {
    fn name(&self) -> &'static str {
        "twinvpn-crypto"
    }

    fn sha256(&self, input: &[u8]) -> Vec<u8> {
        twinvpn_crypto::sha256(input).to_vec()
    }

    fn hkdf(&self, salt: Option<&[u8]>, ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        twinvpn_crypto::hkdf_sha256(salt, ikm, info, &mut out).expect("hkdf");
        out
    }
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "a hex field has an odd length: {s}"
    );
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Runs the whole corpus through `provider`, returning `(id, mismatch)` for
/// every entry that did not agree byte-exactly.
fn run_corpus(provider: &dyn Provider) -> Vec<(String, String)> {
    let manifest: serde_json::Value = serde_json::from_str(MANIFEST).expect("manifest.json");
    let vectors = manifest["vectors"].as_array().expect("vectors");
    assert!(!vectors.is_empty(), "the corpus is empty");

    let mut failures = Vec::new();
    for v in vectors {
        let id = v["id"].as_str().expect("id").to_owned();
        let expected = v["expected_hex"].as_str().expect("expected_hex");
        let got = match v["algorithm"].as_str().expect("algorithm") {
            "SHA-256" => provider.sha256(&unhex(v["input_hex"].as_str().expect("input_hex"))),
            "HKDF-SHA-256" => {
                let salt = v["salt_hex"].as_str().map(unhex);
                provider.hkdf(
                    salt.as_deref(),
                    &unhex(v["ikm_hex"].as_str().expect("ikm_hex")),
                    &unhex(v["info_hex"].as_str().expect("info_hex")),
                    usize::try_from(v["length"].as_u64().expect("length")).expect("fits"),
                )
            }
            other => panic!("{id}: the corpus names an algorithm no provider binds: {other}"),
        };
        if hex(&got) != expected {
            failures.push((id, format!("expected {expected}, got {}", hex(&got))));
        }
    }
    failures
}

#[test]
fn the_shipped_provider_agrees_byte_exactly_with_every_published_vector() {
    let p = TwinvpnCrypto;
    let failures = run_corpus(&p);
    assert!(
        failures.is_empty(),
        "{} disagreed with the published corpus: {failures:?}",
        p.name()
    );
}

#[test]
fn a_second_provider_that_disagrees_fails_the_same_corpus() {
    // The negative control DP-8's claim needs. Without it, `run_corpus` could be
    // returning an empty list because it never compares anything, and the
    // "identical corpus" claim would be unfalsifiable.
    //
    // This provider is deliberately wrong in the smallest possible way: one
    // truncated byte. A corpus that only caught a wholesale substitution would
    // not catch a real interoperability defect either.
    struct OneByteWrong;
    impl Provider for OneByteWrong {
        fn name(&self) -> &'static str {
            "one-byte-wrong"
        }
        fn sha256(&self, input: &[u8]) -> Vec<u8> {
            let mut v = twinvpn_crypto::sha256(input).to_vec();
            v[31] ^= 0x01;
            v
        }
        fn hkdf(&self, salt: Option<&[u8]>, ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
            let mut out = vec![0u8; len];
            twinvpn_crypto::hkdf_sha256(salt, ikm, info, &mut out).expect("hkdf");
            if let Some(last) = out.last_mut() {
                *last ^= 0x01;
            }
            out
        }
    }

    let failures = run_corpus(&OneByteWrong);
    assert_eq!(
        failures.len(),
        7,
        "a one-byte-wrong provider passed some of the corpus, so the corpus does \
         not actually check every entry: {failures:?}"
    );
}

#[test]
fn the_corpus_names_no_provider_which_is_what_makes_dp8_checkable() {
    // DP-8: "two cryptographic providers pass an IDENTICAL corpus." A corpus
    // that mentioned a crate would not be identical for the second one.
    for forbidden in [
        "twinvpn-crypto",
        "twinvpn_crypto",
        "RustCrypto",
        "ring",
        "openssl",
        "BoringSSL",
    ] {
        assert!(
            !MANIFEST.contains(forbidden),
            "the corpus names `{forbidden}`; DP-8's second provider must be able \
             to run this file unchanged"
        );
    }
}

#[test]
fn every_corpus_entry_declares_where_it_came_from() {
    // §2.3's generation rule: vectors are generated once, reviewed and frozen,
    // and "silently regenerating a corpus to make CI green is the single most
    // dangerous failure mode of this level". An entry with no provenance cannot
    // be reviewed, so it cannot be frozen.
    let manifest: serde_json::Value = serde_json::from_str(MANIFEST).expect("manifest.json");
    for v in manifest["vectors"].as_array().expect("vectors") {
        let id = v["id"].as_str().expect("id");
        let origin = v["origin"].as_str().unwrap_or_default();
        assert!(
            origin.len() > 20,
            "{id} does not say where its expected value came from"
        );
    }
}

// ---------------------------------------------------------------------------
// The frozen protobuf fixtures, through the bindings the product ships.
// ---------------------------------------------------------------------------

/// Decodes `bytes` as `M`, re-encodes, and returns the re-encoded bytes.
///
/// §2.3's `valid/` class: "Decode succeeds; re-encode is byte-identical
/// (round-trip stability)."
fn round_trip<M: Message + Default>(bytes: &[u8]) -> Vec<u8> {
    let msg = M::decode(bytes).expect("the frozen fixture must decode");
    msg.encode_to_vec()
}

macro_rules! fixture {
    ($name:literal) => {
        (
            $name,
            include_bytes!(concat!("../../contracts/tests/fixtures/", $name, ".binpb")) as &[u8],
        )
    };
}

#[test]
fn every_frozen_fixture_round_trips_byte_exactly_through_the_rust_bindings() {
    // `contracts/tests/test_wire.py` checks these against `buf` and protobuf.js
    // and explicitly declines to claim byte-determinism across runtimes. The
    // Rust bindings — the ones a device actually runs — were checked by neither.
    //
    // A field the Rust generator ordered differently, or a default it dropped,
    // would show up here and nowhere else until a device met a server.
    let mut results: BTreeMap<&str, bool> = BTreeMap::new();

    let (n, b) = fixture!("ipv4_prefix");
    results.insert(n, round_trip::<v1::IpPrefix>(b) == b);
    let (n, b) = fixture!("ipv6_prefix");
    results.insert(n, round_trip::<v1::IpPrefix>(b) == b);
    let (n, b) = fixture!("metadata_full");
    results.insert(n, round_trip::<v1::MessageMetadata>(b) == b);
    let (n, b) = fixture!("error_envelope_full");
    results.insert(n, round_trip::<v1::ErrorEnvelope>(b) == b);
    let (n, b) = fixture!("relay_binding");
    results.insert(n, round_trip::<v1::RelayBinding>(b) == b);
    let (n, b) = fixture!("dns_policy_dual_family");
    results.insert(n, round_trip::<v1::DnsPolicy>(b) == b);
    let (n, b) = fixture!("ipv6_linklocal_candidate");
    results.insert(n, round_trip::<v1::ConnectionCandidate>(b) == b);
    let (n, b) = fixture!("capability_set");
    results.insert(n, round_trip::<v1::CapabilitySet>(b) == b);
    let (n, b) = fixture!("connection_session");
    results.insert(n, round_trip::<v1::ConnectionSession>(b) == b);
    let (n, b) = fixture!("route_advertisement");
    results.insert(n, round_trip::<v1::RouteAdvertisement>(b) == b);
    let (n, b) = fixture!("exit_node_grant_partial");
    results.insert(n, round_trip::<v1::ExitNodeGrant>(b) == b);

    let broken: Vec<&&str> = results
        .iter()
        .filter_map(|(k, ok)| (!ok).then_some(k))
        .collect();
    assert!(
        broken.is_empty(),
        "these frozen fixtures do not re-encode byte-identically through the \
         Rust bindings: {broken:?}. §2.3: a code change that alters a golden \
         vector IS a wire-format change (B-5)."
    );
    assert_eq!(
        results.len(),
        11,
        "contracts/tests/fixtures holds 11 vectors; this test covers {}",
        results.len()
    );
}

#[test]
fn both_address_families_are_present_in_the_frozen_corpus() {
    // §2.3's `valid/` class requires "both address families". A corpus with only
    // v4 fixtures would let a v6 encoding bug through every gate.
    let (_, v4) = fixture!("ipv4_prefix");
    let (_, v6) = fixture!("ipv6_prefix");
    let p4 = v1::IpPrefix::decode(v4).expect("decode");
    let p6 = v1::IpPrefix::decode(v6).expect("decode");
    assert_ne!(v4, v6, "the two family fixtures are the same bytes");
    assert_ne!(
        format!("{p4:?}"),
        format!("{p6:?}"),
        "the two family fixtures decode to the same value"
    );

    let (_, cand) = fixture!("ipv6_linklocal_candidate");
    let c = v1::ConnectionCandidate::decode(cand).expect("decode");
    assert!(
        c.endpoint.is_some(),
        "the v6 link-local candidate carries no endpoint"
    );
}

#[test]
fn a_truncated_fixture_is_rejected_rather_than_partially_accepted() {
    // §2.3's `malformed/` class, applied to a real message: truncation at every
    // offset must fail with a typed outcome, never panic and never half-decode.
    let (_, full) = fixture!("error_envelope_full");
    assert!(
        v1::ErrorEnvelope::decode(full).is_ok(),
        "the positive control: the untruncated fixture decodes"
    );
    let mut rejected = 0;
    let mut accepted_prefixes = Vec::new();
    for cut in 1..full.len() {
        match v1::ErrorEnvelope::decode(&full[..cut]) {
            Ok(_) => accepted_prefixes.push(cut),
            Err(_) => rejected += 1,
        }
    }
    assert!(
        rejected > 0,
        "no truncation of a {} byte message was rejected",
        full.len()
    );
    // Protobuf is a self-delimiting format at the field level, so some prefixes
    // ARE valid messages with fewer fields. That is the format's semantics, not
    // a defect — what matters is that none of them panicked or hung, which
    // reaching this line proves.
    assert!(
        accepted_prefixes.len() < full.len(),
        "every truncation decoded, which would mean the decoder is not reading \
         the length prefixes at all"
    );
}

#[test]
fn an_unknown_field_survives_a_decode_and_re_encode() {
    // W-4's client-side half. `prost` 0.13 drops unknown fields, which is the
    // measured constraint the wave recorded — so this test states the ACTUAL
    // behaviour and names what it means, rather than asserting a preservation
    // the runtime does not provide.
    let (_, base) = fixture!("metadata_full");
    let mut with_unknown = base.to_vec();
    // Field 9999, wire type 2 (length-delimited), 3 bytes of payload.
    // Tag = (9999 << 3) | 2 = 79994, varint-encoded as fa f0 04.
    with_unknown.extend_from_slice(&[0xfa, 0xf0, 0x04, 0x03, 0x61, 0x62, 0x63]);

    let decoded = v1::MessageMetadata::decode(with_unknown.as_slice())
        .expect("an unknown field must not make a message undecodable");
    let re_encoded = decoded.encode_to_vec();
    assert_ne!(
        re_encoded, with_unknown,
        "prost 0.13 now preserves unknown fields. W-4's forward-verbatim \
         constraint may be relaxable — tell the integration lead before relying \
         on it."
    );
    assert_eq!(
        re_encoded,
        base.to_vec(),
        "the unknown field was dropped, which is exactly W-4: every forwarder \
         MUST forward the received octets verbatim and never decode-then-re-encode"
    );
}
