//! CD-4, closed end to end — the assignment finding **W-1** left to `lab/`.
//!
//! **Authority:** ADR-0018 §11.8 **CD-4**, `docs/testing-strategy.md` §3.5,
//! `docs/implementation/ownership.md` §8 finding **W-1**.
//!
//! # What was still open, and what this file closes
//!
//! W-1 split CD-4 in two because CD-I2 forbids `twinvpn-env` a cryptographic
//! dependency:
//!
//! - `twinvpn-env` owns and tests the **structural** half — that `info` is
//!   `"twinlab/v1/" ‖ consumer_id`, and that streams are independent. Its tests
//!   use a `RecordingDerivation` that is deliberately **not HKDF**.
//! - `twinvpn-crypto` owns and tests the **cryptographic** half —
//!   `HkdfSha256` against known vectors.
//! - Neither crate constructs the pair, so **neither can show that the lab's
//!   injected derivation actually is that HKDF.** W-1 says "`lab/` asserts it end
//!   to end". This file is that assertion.
//!
//! # Why the oracle is not Rust
//!
//! Checking `HkdfSha256` against the `hkdf` crate would be checking a crate
//! against itself. Every expected value below was computed by a standalone
//! Python implementation of RFC 5869 built on `hmac`/`hashlib` — no shared code
//! with this workspace, no shared code with RustCrypto — and that implementation
//! was first validated against **RFC 5869 Test Case 1**, which is also asserted
//! here so the oracle's own credentials are in the suite rather than in a
//! commit message.
//!
//! The xoshiro256\*\* expansion below is likewise reimplemented from the
//! published algorithm rather than reused from `twinvpn-env`, so the chain
//! `seed → HKDF → PRNG state → bytes out of Env::rng_for` is pinned at both
//! ends by something that is not the code under test.

use std::sync::Arc;

use twinlab::seed::{cd4_derivation, LabEnv, ScenarioSeed};
use twinvpn_crypto::{hkdf_sha256, HkdfSha256};
use twinvpn_env::{consumers, ConsumerId, EnvError, StreamDerivation, CD4_INFO_PREFIX};

// ---------------------------------------------------------------------------
// The independently computed corpus.
//
//   scenario_seed = 000102030405060708090a0b0c0d0e0f
//   info          = "twinlab/v1/" || consumer_id
//   okm           = HKDF-SHA-256(salt = absent, ikm = seed, info, L = 32)
//   stream        = the first 32 bytes of xoshiro256** seeded with okm
// ---------------------------------------------------------------------------

const SEED: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

struct Vector {
    consumer: ConsumerId,
    okm_hex: &'static str,
    stream_hex: &'static str,
}

const VECTORS: [Vector; 4] = [
    Vector {
        consumer: consumers::RELAY_HRW,
        okm_hex: "830eb2df6c871281664c56b9dbd829373513194b4971d26eebe4ca82fc4ca6bf",
        stream_hex: "51f7b615ca4f8f2d0ec9b0c30a57a17e8d279a6660d7c7d3fb7fc166e99ff06d",
    },
    Vector {
        consumer: consumers::RELAY_REGION_SPREAD,
        okm_hex: "dd957bdeae33106f715e597fae6c6f24b895c63e943c0ffec4809390a58e3941",
        stream_hex: "b3f1cc5a31560dcb6dc444920d90c0603ab6dae2c5d773ceb8c2cb80b1845e48",
    },
    Vector {
        consumer: consumers::CANDIDATE_RACE_TIEBREAK,
        okm_hex: "5de12231a73e0807ca622fd3948606eb0564658f8d64e10d44038bf2c4ca1a5a",
        stream_hex: "a3c32eaa8f14d412d4565ab89dbce69408355f700c5dba360850ae8f1278935d",
    },
    Vector {
        consumer: consumers::LOSS_SCHEDULE,
        okm_hex: "b98fb33e3f9db0b0f2b21a432f48cec382c6c01b87f937031e9a4ccfa1f8eade",
        stream_hex: "b148bad8652758a1582ba150804e6b6ed33167618494026edc9d728194792e36",
    },
];

/// `HKDF-SHA-256(ikm = SEED, info = "relay/hrw")` — the CD-4 prefix **absent**.
const OKM_WITHOUT_CD4_PREFIX: &str =
    "e841bad67c5e58d2049c22ca9cfee119f7d818eb2a9f4f732d6f1d1fad5deca2";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------------------
// An independent xoshiro256** — the published algorithm, reimplemented here so
// the expansion step is not checked against itself.
// ---------------------------------------------------------------------------

struct Xoshiro256ss([u64; 4]);

impl Xoshiro256ss {
    fn from_seed(seed: &[u8]) -> Self {
        let mut s = [0u64; 4];
        for (i, slot) in s.iter_mut().enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&seed[i * 8..i * 8 + 8]);
            *slot = u64::from_le_bytes(b);
        }
        if s == [0; 4] {
            s = [0x9e37_79b9_7f4a_7c15, 1, 2, 3];
        }
        Self(s)
    }

    fn next(&mut self) -> u64 {
        let s = &mut self.0;
        let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        result
    }

    fn fill(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            out.extend_from_slice(&self.next().to_le_bytes());
        }
        out.truncate(n);
        out
    }
}

// ---------------------------------------------------------------------------
// 1. The oracle's own credentials.
// ---------------------------------------------------------------------------

#[test]
fn the_primitive_matches_rfc_5869_test_case_1() {
    // Everything below rests on the Python oracle being HKDF-SHA-256. That
    // oracle was validated against this vector; asserting it here through
    // `twinvpn-crypto` puts the same check inside the suite, so a reader does
    // not have to take the provenance of the other constants on trust.
    let mut okm = [0u8; 42];
    hkdf_sha256(
        Some(&unhex("000102030405060708090a0b0c")),
        &[0x0b; 22],
        &unhex("f0f1f2f3f4f5f6f7f8f9"),
        &mut okm,
    )
    .expect("hkdf");
    assert_eq!(
        hex(&okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
}

// ---------------------------------------------------------------------------
// 2. The injected derivation genuinely is CD-4's HKDF.
// ---------------------------------------------------------------------------

#[test]
fn the_injected_derivation_is_hkdf_sha256_with_the_rfc_5869_zero_salt() {
    let derivation = cd4_derivation();
    for v in &VECTORS {
        let mut out = [0u8; 32];
        derivation
            .derive(&SEED, &v.consumer.info_bytes(), &mut out)
            .expect("derive");
        assert_eq!(
            hex(&out),
            v.okm_hex,
            "consumer `{}` — the derivation TwinLab injects is not \
             HKDF-SHA-256(ikm = scenario_seed, info = \"twinlab/v1/\" || consumer_id) \
             with the RFC 5869 §2.2 zero salt",
            v.consumer.as_str()
        );
    }
}

#[test]
fn the_cd4_info_is_the_prefix_followed_by_the_consumer_id_and_nothing_else() {
    assert_eq!(CD4_INFO_PREFIX, "twinlab/v1/");
    for v in &VECTORS {
        let info = v.consumer.info_bytes();
        assert_eq!(
            info,
            format!("twinlab/v1/{}", v.consumer.as_str()).into_bytes()
        );
    }
}

#[test]
fn dropping_the_cd4_prefix_changes_every_derived_stream() {
    // The negative control for the two tests above. Without it, an `info` that
    // silently lost its prefix would still satisfy "the derivation is HKDF",
    // and every recorded seed would stop reproducing its run.
    let mut out = [0u8; 32];
    hkdf_sha256(None, &SEED, b"relay/hrw", &mut out).expect("hkdf");
    assert_eq!(hex(&out), OKM_WITHOUT_CD4_PREFIX);
    assert_ne!(
        hex(&out),
        VECTORS[0].okm_hex,
        "the prefix must be load-bearing"
    );
}

// ---------------------------------------------------------------------------
// 3. The whole chain, through the public `Env` surface a component sees.
// ---------------------------------------------------------------------------

#[test]
fn env_rng_for_yields_the_stream_the_independent_oracle_predicts() {
    let env = LabEnv::new(ScenarioSeed::from_bytes(SEED));
    for v in &VECTORS {
        // (a) the recorded stream, straight out of the public API.
        let mut rng = env.rng_for(v.consumer).expect("rng_for");
        let mut got = [0u8; 32];
        rng.fill_bytes(&mut got);
        assert_eq!(
            hex(&got),
            v.stream_hex,
            "consumer `{}` — `Env::rng_for` did not produce the stream an \
             HKDF-SHA-256 oracle computed outside this workspace",
            v.consumer.as_str()
        );

        // (b) the same value, recomputed here from the golden OKM through an
        // independently written xoshiro256**, so the expansion step is pinned
        // too and not merely the derivation.
        let predicted = Xoshiro256ss::from_seed(&unhex(v.okm_hex)).fill(32);
        assert_eq!(hex(&predicted), v.stream_hex);
    }
}

#[test]
fn a_derivation_that_is_not_hkdf_fails_the_same_assertion() {
    // The negative control that gives the test above teeth. If `Env::rng_for`
    // ignored the injected derivation — or if the vectors were not actually
    // HKDF's — this would pass too, and the whole file would prove nothing.
    struct NotHkdf;
    impl StreamDerivation for NotHkdf {
        fn derive(&self, ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), EnvError> {
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = ikm[i % ikm.len()] ^ info[i % info.len()];
            }
            Ok(())
        }
    }

    let source = twinvpn_env::SeededRngSource::new(SEED, Arc::new(NotHkdf));
    let mut rng = twinvpn_env::RngSource::rng_for(&source, consumers::RELAY_HRW).expect("rng");
    let mut got = [0u8; 32];
    rng.fill_bytes(&mut got);
    assert_ne!(
        hex(&got),
        VECTORS[0].stream_hex,
        "a non-HKDF derivation produced CD-4's stream, so the assertion in \
         `env_rng_for_yields_the_stream_the_independent_oracle_predicts` cannot fail"
    );
}

// ---------------------------------------------------------------------------
// 4. CD-4's structural property, asserted against the real derivation.
// ---------------------------------------------------------------------------

#[test]
fn adding_a_consumer_does_not_shift_an_existing_consumers_stream() {
    // CD-4's stated reason for a per-consumer derivation: "adding a consumer
    // does not shift any existing consumer's stream — the property that makes a
    // seed useful a year later." `twinvpn-env` asserts this for an injective
    // stand-in; this asserts it for the derivation that actually ships.
    let env = LabEnv::new(ScenarioSeed::from_bytes(SEED));
    let before = {
        let mut r = env.rng_for(consumers::RELAY_HRW).expect("rng");
        let mut b = [0u8; 32];
        r.fill_bytes(&mut b);
        b
    };

    // A consumer that did not exist when the seed was chosen.
    let newcomer = ConsumerId::new("lab/a-consumer-added-later");
    let mut n = env.rng_for(newcomer).expect("rng");
    let mut nb = [0u8; 32];
    n.fill_bytes(&mut nb);

    let after = {
        let mut r = env.rng_for(consumers::RELAY_HRW).expect("rng");
        let mut b = [0u8; 32];
        r.fill_bytes(&mut b);
        b
    };

    assert_eq!(
        hex(&before),
        hex(&after),
        "drawing for a new consumer shifted an existing consumer's stream"
    );
    assert_eq!(hex(&after), VECTORS[0].stream_hex);
    assert_ne!(
        hex(&nb),
        hex(&before),
        "two consumers must not share a stream"
    );
}

#[test]
fn every_consumer_section_3_5_names_has_an_independent_stream() {
    // §3.5's list of consumers that MUST be seeded. A collision between any two
    // would make one of them unreproducible in a way no single-consumer test
    // could see.
    let env = LabEnv::new(ScenarioSeed::from_bytes(SEED));
    let all = [
        consumers::RELAY_HRW,
        consumers::RELAY_REGION_SPREAD,
        consumers::RELAY_SCORE_TIEBREAK,
        consumers::CANDIDATE_RACE_TIEBREAK,
        consumers::BACKOFF_JITTER,
        consumers::PORT_PREDICTION,
        consumers::LOSS_SCHEDULE,
        consumers::FAULT_SCHEDULE,
    ];
    let mut seen: Vec<(String, String)> = Vec::new();
    for c in all {
        let mut r = env.rng_for(c).expect("rng");
        let mut b = [0u8; 32];
        r.fill_bytes(&mut b);
        let h = hex(&b);
        if let Some((other, _)) = seen.iter().find(|(_, x)| *x == h) {
            panic!("consumers `{other}` and `{}` share a stream", c.as_str());
        }
        seen.push((c.as_str().to_owned(), h));
    }
    assert_eq!(seen.len(), 8);
}

#[test]
fn the_type_level_guarantee_behind_the_const_consumer_id_still_holds() {
    // CD-4: "`consumer_id` is a `const` at each consumer, so adding a consumer
    // cannot shift an existing consumer's stream." `ConsumerId::new` takes
    // `&'static str`, which is the mechanism. Asserted as a `const` binding so
    // that widening it to `String` breaks this test at compile time.
    const _RUNTIME_NAMES_ARE_IMPOSSIBLE: ConsumerId = ConsumerId::new("lab/compile-time-only");
    assert_eq!(
        _RUNTIME_NAMES_ARE_IMPOSSIBLE.as_str(),
        "lab/compile-time-only"
    );
}

#[test]
fn the_derivation_is_a_zero_sized_type_with_no_configurable_variant() {
    // There is exactly one correct answer to "what is CD-4's derivation", so a
    // configurable implementation would be a way to get it wrong. This is a
    // structural assertion, not a behavioural one, and it is stated as such.
    assert_eq!(core::mem::size_of::<HkdfSha256>(), 0);
}
