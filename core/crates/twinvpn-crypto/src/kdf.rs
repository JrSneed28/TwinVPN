//! HKDF-SHA-256, and the CD-4 stream derivation `twinvpn-env` deliberately left
//! to this crate.
//!
//! **Authority:** ADR-0018 CD-4, ADR-0001 §7.5 and §7.3.2, RFC 5869, RFC 8446
//! §7.1 (the `HKDF-Expand-Label` construction ADR-0001 §7.3.2 names).
//!
//! # Why this module exists at all
//!
//! `twinvpn-env` declares [`twinvpn_env::StreamDerivation`] and implements
//! nothing, because CD-I2 restricts cryptographic dependencies to this crate and
//! §11.7's dependency arrow already points from here to `twinvpn-env` — an HKDF
//! there would be a cycle *and* a CD-I2 violation. `core-foundation` flagged the
//! gap; [`HkdfSha256`] closes it.
//!
//! CD-4 is exact, and so is [`HkdfSha256`]:
//!
//! > `Env::rng_for(consumer_id)` derives
//! > `HKDF-SHA-256(ikm = scenario_seed, info = "twinlab/v1/" || consumer_id)`.
//!
//! `salt` is absent from that expression, so extraction uses the all-zero salt
//! RFC 5869 §2.2 specifies for the "not provided" case. That is asserted against
//! the RFC's own test vectors in [`tests`], not merely stated.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use twinvpn_env::{EnvError, StreamDerivation};

use crate::{CryptoError, Result};

/// SHA-256's output length, in bytes. HKDF's `L` cap is `255 * HASH_LEN`.
pub const HASH_LEN: usize = 32;

/// The largest output HKDF-SHA-256 can produce (RFC 5869 §2.3).
pub const MAX_OKM_LEN: usize = 255 * HASH_LEN;

/// `HKDF-Extract` then `HKDF-Expand` with SHA-256, in one call.
///
/// `salt = None` uses the all-zero `HashLen` salt of RFC 5869 §2.2.
///
/// # Errors
///
/// [`CryptoError::DerivationFailed`] if `out.len()` exceeds [`MAX_OKM_LEN`].
/// That is a caller defect — the length is never attacker-supplied at any call
/// site in this workspace — which is why it maps to
/// `INTERNAL.INVARIANT_VIOLATED` rather than a `PROTO.*` reject.
pub fn hkdf_sha256(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    if out.len() > MAX_OKM_LEN {
        return Err(CryptoError::DerivationFailed {
            invariant: "hkdf output length is at most 255 * HashLen",
        });
    }
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, out)
        .map_err(|_| CryptoError::DerivationFailed {
            invariant: "hkdf expand rejected the requested length",
        })
}

/// SHA-256 of `data`.
///
/// Present so the rest of the crate has one spelling of "hash these bytes" and
/// `sha2` appears in exactly one module.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; HASH_LEN] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// SHA-256 over a sequence of parts, with **no separator inserted**.
///
/// Every call site in this crate concatenates fixed-width fields under a
/// domain-separating label, so length-extension ambiguity between adjacent
/// fields cannot arise. A caller with variable-width parts must length-prefix
/// them itself; this function will not do it silently, because a silent
/// separator is a difference between two implementations of the same spec.
#[must_use]
pub fn sha256_parts(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// TLS 1.3's `HKDF-Expand-Label` (RFC 8446 §7.1), which ADR-0001 §7.3.2 names by
/// that spelling for the tunnel resumption secrets.
///
/// ```text
/// struct {
///     uint16 length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
///
/// ADR-0001 §7.3.2 writes `HKDF-Expand-Label(handshake_secret, "twinvpn resume",
/// "", 32)`. RFC 8446's construction prefixes `"tls13 "`, and this
/// implementation keeps that prefix: the ADR names the RFC's function, and
/// silently dropping the prefix would be a TwinVPN-designed variant of a
/// standard construction — precisely what I2 forbids. Stated here so that
/// `twinvpn-tunnel`, which drives resumption, inherits the same reading.
///
/// # Errors
///
/// [`CryptoError::DerivationFailed`] if `label` or `context` exceeds the
/// encoding's own bounds, or if `len` exceeds `u16::MAX` or [`MAX_OKM_LEN`].
pub fn hkdf_expand_label(secret: &[u8], label: &str, context: &[u8], out: &mut [u8]) -> Result<()> {
    const PREFIX: &str = "tls13 ";
    let bounds = CryptoError::DerivationFailed {
        invariant: "HkdfLabel label and context are each at most 255 bytes",
    };
    let labelled_len = u8::try_from(PREFIX.len() + label.len()).map_err(|_| bounds.clone())?;
    let context_len = u8::try_from(context.len()).map_err(|_| bounds)?;
    let Ok(out_len) = u16::try_from(out.len()) else {
        return Err(CryptoError::DerivationFailed {
            invariant: "HkdfLabel length field is a uint16",
        });
    };
    let mut hkdf_label = Vec::with_capacity(2 + 1 + usize::from(labelled_len) + 1 + context.len());
    hkdf_label.extend_from_slice(&out_len.to_be_bytes());
    hkdf_label.push(labelled_len);
    hkdf_label.extend_from_slice(PREFIX.as_bytes());
    hkdf_label.extend_from_slice(label.as_bytes());
    hkdf_label.push(context_len);
    hkdf_label.extend_from_slice(context);

    Hkdf::<Sha256>::from_prk(secret)
        .map_err(|_| CryptoError::DerivationFailed {
            invariant: "HKDF-Expand-Label secret is at least HashLen bytes",
        })?
        .expand(&hkdf_label, out)
        .map_err(|_| CryptoError::DerivationFailed {
            invariant: "hkdf expand rejected the requested length",
        })
}

/// The CD-4 derivation, bound into `twinvpn-env`'s deterministic RNG binding.
///
/// This is the implementation `core-foundation` left to `core-security`, and it
/// is deliberately a zero-sized type: there is no state, no configuration, and
/// no way to construct a variant that derives something else.
#[derive(Debug, Clone, Copy, Default)]
pub struct HkdfSha256;

impl HkdfSha256 {
    /// A value to inject as `Arc<dyn StreamDerivation>`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl StreamDerivation for HkdfSha256 {
    /// `HKDF-SHA-256(ikm, info)` with the RFC 5869 §2.2 zero salt.
    ///
    /// CD-4 names no salt, so there is none — and it is the *absence* that must
    /// be reproducible, because a scenario seed is expected to still reproduce a
    /// run a year later.
    fn derive(
        &self,
        ikm: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> core::result::Result<(), EnvError> {
        // `EnvError::StreamDerivationFailed` names the consumer, but a
        // `StreamDerivation` is handed the assembled `info` rather than the
        // `ConsumerId` — so the derivation is named instead of the consumer. The
        // only condition that reaches here is an out-of-range output length,
        // which is a caller defect, not a per-consumer fact.
        hkdf_sha256(None, ikm, info, out).map_err(|_| EnvError::StreamDerivationFailed {
            consumer: "CD-4 HKDF-SHA-256",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_env::{ConsumerId, CD4_INFO_PREFIX};

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// RFC 5869 Appendix A.1 — Basic test case with SHA-256.
    #[test]
    fn hkdf_sha256_matches_rfc_5869_a1() {
        let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        let mut okm = [0u8; 42];
        hkdf_sha256(Some(&salt), &ikm, &info, &mut okm).expect("derive");
        assert_eq!(
            okm.to_vec(),
            unhex(
                "3cb25f25faacd57a90434f64d0362f2a\
                 2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                 34007208d5b887185865"
            )
        );
    }

    /// RFC 5869 Appendix A.2 — longer inputs and outputs, SHA-256.
    #[test]
    fn hkdf_sha256_matches_rfc_5869_a2() {
        let ikm: Vec<u8> = (0u8..=0x4f).collect();
        let salt: Vec<u8> = (0x60u8..=0xaf).collect();
        let info: Vec<u8> = (0xb0u8..=0xff).collect();
        let mut okm = [0u8; 82];
        hkdf_sha256(Some(&salt), &ikm, &info, &mut okm).expect("derive");
        assert_eq!(
            okm.to_vec(),
            unhex(
                "b11e398dc80327a1c8e7f78c596a4934\
                 4f012eda2d4efad8a050cc4c19afa97c\
                 59045a99cac7827271cb41c65e590e09\
                 da3275600c2f09b8367793a9aca3db71\
                 cc30c58179ec3e87c14c01d5c1f3434f\
                 1d87"
            )
        );
    }

    /// RFC 5869 Appendix A.3 — **zero-length salt and info**, SHA-256.
    ///
    /// This is the vector CD-4 actually rides on: CD-4's expression names no
    /// salt, so the derivation must use the all-zero `HashLen` salt of RFC 5869
    /// §2.2, and A.3 is the RFC's own answer for that case. If `salt = None`
    /// were ever implemented as "extract with an empty-string salt" instead,
    /// this vector is what would catch it.
    #[test]
    fn hkdf_sha256_matches_rfc_5869_a3_the_no_salt_case() {
        let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let mut okm = [0u8; 42];
        hkdf_sha256(None, &ikm, &[], &mut okm).expect("derive");
        assert_eq!(
            okm.to_vec(),
            unhex(
                "8da4e775a563c18f715f802a063c5a31\
                 b8a11f5c5ee1879ec3454e5f3c738d2d\
                 9d201395faa4b61a96c8"
            )
        );
    }

    /// The named obligation from the integration lead: `StreamDerivation` is
    /// **exactly** `HKDF-SHA-256(ikm = scenario_seed, info = "twinlab/v1/" ||
    /// consumer_id)`, asserted against a known HKDF vector rather than against
    /// itself.
    ///
    /// The vector is computed the RFC's way — zero salt, the CD-4 `info` bytes —
    /// and pinned as a literal. A change to either half of the derivation moves
    /// this value, which is the whole point: `docs/testing-strategy.md` §3.5
    /// needs a seed to still reproduce a scenario a year from now, and that is a
    /// claim about *these bytes*, not about the code that produced them.
    #[test]
    fn cd4_stream_derivation_is_hkdf_sha256_over_the_declared_info() {
        const SCENARIO_SEED: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let consumer = ConsumerId::new("relay/hrw");

        // The `info` CD-4 specifies, assembled here independently of
        // `ConsumerId::info_bytes` so the test would catch a change to either.
        let mut info = Vec::new();
        info.extend_from_slice(b"twinlab/v1/");
        info.extend_from_slice(b"relay/hrw");
        assert_eq!(info, consumer.info_bytes());
        assert_eq!(CD4_INFO_PREFIX, "twinlab/v1/");

        let mut expected = [0u8; 32];
        hkdf_sha256(None, &SCENARIO_SEED, &info, &mut expected).expect("derive");

        // The pinned answer. Produced by the RFC 5869 construction with an
        // all-zero SHA-256-length salt; regenerating it requires deliberately
        // editing this literal, which is a reviewable event.
        assert_eq!(
            expected.to_vec(),
            unhex("07fd45ff8da2eb5b9c46b4ddeaf0d7aed86b89f60ca6af3a2de06f8b43229877"),
            "the CD-4 stream seed moved; a scenario seed no longer reproduces"
        );

        // And the trait binding produces the same bytes as the free function.
        let mut through_trait = [0u8; 32];
        StreamDerivation::derive(
            &HkdfSha256::new(),
            &SCENARIO_SEED,
            &info,
            &mut through_trait,
        )
        .expect("derive");
        assert_eq!(through_trait, expected);
    }

    /// CD-4's independence property, at the derivation layer: two consumers get
    /// unrelated streams from one seed, and neither depends on how many other
    /// consumers exist.
    #[test]
    fn two_consumers_derive_independent_seeds_from_one_scenario_seed() {
        let seed = [0x5au8; 16];
        let a = ConsumerId::new("relay/hrw");
        let b = ConsumerId::new("reliability/backoff-jitter");
        let mut sa = [0u8; 32];
        let mut sb = [0u8; 32];
        let d = HkdfSha256::new();
        StreamDerivation::derive(&d, &seed, &a.info_bytes(), &mut sa).expect("a");
        StreamDerivation::derive(&d, &seed, &b.info_bytes(), &mut sb).expect("b");
        assert_ne!(sa, sb);
    }

    #[test]
    fn an_output_longer_than_255_hashlen_is_refused_rather_than_truncated() {
        let mut out = vec![0u8; MAX_OKM_LEN + 1];
        let err = hkdf_sha256(None, b"ikm", b"info", &mut out).expect_err("must refuse");
        assert!(matches!(err, CryptoError::DerivationFailed { .. }));
    }

    #[test]
    fn expand_label_encodes_the_rfc_8446_structure() {
        // The structure is asserted by construction: two derivations that differ
        // only in the label must differ, and one that differs only in the
        // context must differ. A hand-rolled encoder that dropped a length byte
        // would collide here.
        let secret = [0x42u8; 32];
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut c = [0u8; 32];
        hkdf_expand_label(&secret, "twinvpn resume", b"", &mut a).expect("a");
        hkdf_expand_label(&secret, "twinvpn resume id", b"", &mut b).expect("b");
        hkdf_expand_label(&secret, "twinvpn resume", b"x", &mut c).expect("c");
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn expand_label_refuses_an_over_long_label_or_context() {
        let secret = [0x42u8; 32];
        let mut out = [0u8; 32];
        let long = "x".repeat(256);
        assert!(hkdf_expand_label(&secret, &long, b"", &mut out).is_err());
        assert!(hkdf_expand_label(&secret, "ok", &vec![0u8; 256], &mut out).is_err());
    }

    #[test]
    fn sha256_parts_concatenates_without_inserting_anything() {
        assert_eq!(sha256_parts(&[b"abc"]), sha256(b"abc"));
        assert_eq!(sha256_parts(&[b"a", b"b", b"c"]), sha256(b"abc"));
    }
}
