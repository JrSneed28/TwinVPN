//! The production [`RelayCrypto`] binding, on top of `twinvpn-crypto`.
//!
//! **Authority:** ADR-0018 CD-I2 and DP-8, ADR-0005 §11.3 and §9.1,
//! `contracts/cddl/twinvpn/v1/signed_statements.cddl` §13 and §14.
//!
//! # What is bound
//!
//! | Primitive | ADR | Bound to |
//! |---|---|---|
//! | COSE_Sign1 verification over received octets | §11.3 | `twinvpn_crypto::verify_cose_sign1` |
//! | keyed BLAKE2s frame MAC, truncated to 64 bits | §9.1 | `twinvpn_crypto::frame_mac` / `verify_frame_mac` |
//! | one-way 16-byte digest (daily `relay_sub` re-hash) | §10 | `twinvpn_crypto::hkdf_sha256` |
//!
//! All three are real. [`crate::crypto::FailClosed`] remains the default when no
//! provider is configured, so an unconfigured relay is still a closed relay.
//!
//! # The truncation, and the failure it would otherwise cause
//!
//! ADR-0005 §9.1 says "truncated to 64 bits", and BLAKE2 parameterises output
//! length **inside the initialisation block** — so `BLAKE2s(digest_length = 8)`
//! and `BLAKE2s(digest_length = 32)[0..8]` are *different functions over the same
//! key and the same input*. "Truncated" selects the second reading: compute the
//! full 256-bit keyed MAC, then take the leading eight bytes.
//!
//! `twinvpn-crypto` implements that reading and pins both, naming the rejected
//! one. This module pins it **again from the consumer side**
//! (`the_frame_mac_is_a_truncation_not_a_short_output_blake2s`), because the
//! consequence lands here: a relay computing the other reading verifies nothing
//! while looking correctly configured — the exact failure this binding was held
//! back to avoid. Two independent assertions of one wire value is the right
//! amount when disagreeing is silent.
//!
//! # The MAC input is not length-prefixed, deliberately
//!
//! [`crate::frame::RelayFrame::mac_input`] assembles ADR-0005 §9.1's
//! `type ‖ ver|flags ‖ counter_full ‖ flow_id ‖ payload`, and
//! `twinvpn_crypto::frame_mac` takes those octets and **adds nothing**. Every
//! field is fixed-width except `payload`, which is last, so the encoding is
//! already unambiguous. This is the opposite call from the ADR-0020 §11.5 record
//! AAD, where two *variable-length* fields genuinely were ambiguous — and adding
//! a prefix to a specified wire format would make this relay reject every
//! legitimate frame.
//!
//! # Verification order, and why it changed
//!
//! The first version of [`crate::token::verify`] checked `aud`, the validity
//! window and `cnf` *before* the signature, to avoid an asymmetric operation for
//! obviously-wrong input. That was a real concern solved in the wrong place:
//! `relay.proto` is normative that a verifier "MUST verify the COSE signature and
//! read the claims **FROM THE VERIFIED PAYLOAD**", and ADR-0005 §11.3's order
//! puts the signature first.
//!
//! The anti-amplification control ADR-0005 §11.5 actually specifies is the
//! **cookie gate** — "the relay performs no asymmetric operation for an
//! unvalidated source address: above 20 handshakes/s from a source /24 (v4) or
//! /48 (v6) it issues a stateless cookie challenge first" — which
//! [`crate::resource::CookieGate`] already implements and which runs before any
//! of this. So the ordering was solving an already-solved problem at the cost of
//! reading attacker-controlled claims. It now follows the ADR.

use twinvpn_crypto::cose::PublicVerifyingKey;
use twinvpn_crypto::dcbor::Value;
use twinvpn_crypto::{frame_mac, verify_cose_sign1, verify_frame_mac, StatementKind};

use crate::claims::{EpochFloorClaims, Quota, TokenClaims, VerifiedClaims};
use crate::crypto::{IssuerPublicKey, LegKey, RelayCrypto, Statement};

/// Domain separator for the daily `relay_sub` re-hash.
const DIGEST16_INFO: &[u8] = b"twinvpn/relay/log-subject/v1";

/// The production provider.
///
/// Holds nothing: every operation is a pure function of its arguments and the
/// key the caller passes. A provider with state would be a provider that could
/// accumulate one.
#[derive(Debug, Clone, Copy, Default)]
pub struct CryptoProvider;

impl CryptoProvider {
    /// A provider.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Whether the frame MAC is available in this build.
    ///
    /// `true` since `twinvpn-crypto` gained keyed BLAKE2s. Kept rather than
    /// deleted: it is what `main` reports at startup, and a build that again
    /// could not MAC should say so once rather than present as every frame being
    /// dropped.
    #[must_use]
    pub const fn frame_mac_available(self) -> bool {
        true
    }
}

impl RelayCrypto for CryptoProvider {
    fn verify_statement(
        &self,
        key: &IssuerPublicKey,
        kind: Statement,
        envelope: &[u8],
    ) -> Option<VerifiedClaims> {
        let statement_kind = match kind {
            Statement::RelayCapabilityToken => StatementKind::RelayCapabilityToken,
            Statement::RelayEpochFloor => StatementKind::RelayEpochFloor,
        };
        // The COSE_Key is parsed per verification rather than cached, so a key
        // set edited under a running relay cannot leave a stale parsed key alive.
        let verifying = PublicVerifyingKey::from_cose_key(&key.key, statement_kind).ok()?;
        // `envelope` goes in exactly as it arrived. No re-encode, no
        // canonicalisation of our own: `verify_cose_sign1` itself requires the
        // octets to already be canonical and refuses them otherwise.
        let verified = verify_cose_sign1(envelope, statement_kind, &verifying).ok()?;

        // Every field below is read from `verified.payload()`, which is reachable
        // only from a VerifiedStatement. Nothing attacker-controlled has been
        // consulted before this line.
        match kind {
            Statement::RelayCapabilityToken => {
                decode_token(verified.payload()).map(|c| VerifiedClaims::Token(Box::new(c)))
            }
            Statement::RelayEpochFloor => {
                decode_epoch_floor(verified.payload()).map(VerifiedClaims::EpochFloor)
            }
        }
    }

    fn verify_frame_mac(&self, k_leg: &LegKey, mac_input: &[u8], tag: [u8; 8]) -> bool {
        // Constant-time in `twinvpn-crypto`. The tag arrives on the wire and is
        // attacker-controlled, so a variable-time compare would be a
        // prefix-matching oracle for forging into the relay's session table.
        verify_frame_mac(k_leg.expose(), mac_input, &tag)
    }

    fn frame_mac(&self, k_leg: &LegKey, mac_input: &[u8]) -> Option<[u8; 8]> {
        // `mac_input` is already ADR-0005 §9.1's byte sequence; nothing is added.
        Some(frame_mac(k_leg.expose(), mac_input))
    }

    fn digest16(&self, domain: &[u8], input: &[u8]) -> Option<[u8; 16]> {
        // HKDF-SHA-256, salted by the caller's domain separator. One-way, and no
        // interop depends on the choice: this value never leaves the process, it
        // only keys an aggregate counter in a log line (ADR-0005 §10). The
        // primitive is therefore free to be the one `twinvpn-crypto` already
        // audits, unlike the frame MAC above.
        let mut okm = [0_u8; 16];
        twinvpn_crypto::hkdf_sha256(Some(domain), input, DIGEST16_INFO, &mut okm).ok()?;
        Some(okm)
    }
}

/// CDDL §13 `relay-capability-token`, read from a verified payload.
fn decode_token(payload: &Value) -> Option<TokenClaims> {
    Some(TokenClaims {
        issuer_key_id: payload.map_get(1)?.as_text()?.to_owned(),
        audience_operator_group_id: payload.map_get(2)?.as_text()?.to_owned(),
        subject: exact16(payload.map_get(3)?.as_bytes()?)?,
        confirmation_key: payload.map_get(4)?.as_bytes()?.to_vec(),
        not_before_ms: payload.map_get(5)?.as_uint()?,
        not_after_ms: payload.map_get(6)?.as_uint()?,
        epoch: payload.map_get(7)?.as_uint()?,
        quota: decode_quota(payload.map_get(8)?)?,
        jti: exact16(payload.map_get(9)?.as_bytes()?)?,
        renewed_by_relay: payload.map_get(10)?.as_bool()?,
    })
}

/// CDDL §13 key 8.
fn decode_quota(v: &Value) -> Option<Quota> {
    Some(Quota {
        max_concurrent_flows: u32::try_from(v.map_get(1)?.as_uint()?).ok()?,
        max_bitrate_kbps: u32::try_from(v.map_get(2)?.as_uint()?).ok()?,
        max_bytes_per_hour: v.map_get(3)?.as_uint()?,
        max_binds_per_min: u32::try_from(v.map_get(4)?.as_uint()?).ok()?,
    })
}

/// CDDL §14 `relay-epoch-floor`, read from a verified payload.
fn decode_epoch_floor(payload: &Value) -> Option<EpochFloorClaims> {
    Some(EpochFloorClaims {
        twinnet_id: payload.map_get(1)?.as_text()?.to_owned(),
        operator_group_id: payload.map_get(2)?.as_text()?.to_owned(),
        epoch_floor: payload.map_get(3)?.as_uint()?,
        not_after_ms: payload.map_get(4)?.as_uint()?,
    })
}

/// A width check, not a truncation. `limits.json identifiers.pair_tag_bytes` and
/// the CDDL both say 16; anything else is a refusal.
fn exact16(b: &[u8]) -> Option<[u8; 16]> {
    <[u8; 16]>::try_from(b).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> IssuerPublicKey {
        IssuerPublicKey {
            key_id: "k1".into(),
            alg: "Ed25519".into(),
            key: vec![0xA0, 0x00],
        }
    }

    #[test]
    fn a_malformed_envelope_verifies_as_nothing() {
        let p = CryptoProvider::new();
        for bad in [
            &b""[..],
            &b"not cbor at all"[..],
            &[0xFF; 64][..],
            &[0x00, 0x01, 0x02][..],
        ] {
            assert!(p
                .verify_statement(&key(), Statement::RelayCapabilityToken, bad)
                .is_none());
            assert!(p
                .verify_statement(&key(), Statement::RelayEpochFloor, bad)
                .is_none());
        }
    }

    #[test]
    fn an_unusable_issuer_key_verifies_nothing_rather_than_panicking() {
        let p = CryptoProvider::new();
        let junk = IssuerPublicKey {
            key_id: "k1".into(),
            alg: "Ed25519".into(),
            key: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        assert!(p
            .verify_statement(&junk, Statement::RelayCapabilityToken, b"anything")
            .is_none());
    }

    #[test]
    fn the_digest_is_real_deterministic_and_domain_separated() {
        let p = CryptoProvider::new();
        let a = p.digest16(b"domain-a", b"subject").expect("digest");
        let b = p.digest16(b"domain-a", b"subject").expect("digest");
        let c = p.digest16(b"domain-b", b"subject").expect("digest");
        let d = p.digest16(b"domain-a", b"other").expect("digest");

        assert_eq!(a, b, "the same inputs must key the same log aggregate");
        assert_ne!(a, c, "a different domain must not collide");
        assert_ne!(a, d, "a different subject must not collide");
        assert_ne!(
            a, [0_u8; 16],
            "an all-zero digest would be a silent failure"
        );
    }

    #[test]
    fn the_daily_re_hash_actually_rotates_through_the_real_provider() {
        // The end-to-end privacy property, now with a real primitive underneath:
        // operational logs must not link a device across days (ADR-0005 §10).
        let p = CryptoProvider::new();
        let sub = crate::subject::RelaySub::from_verified_claim([7; 16]);
        let d1 = sub.log_subject(&p, 20_000).expect("digest").label();
        let d2 = sub.log_subject(&p, 20_001).expect("digest").label();
        assert_ne!(d1, d2);
        assert_eq!(d1, sub.log_subject(&p, 20_000).expect("digest").label());
    }

    #[test]
    fn the_frame_mac_is_bound_and_round_trips() {
        let p = CryptoProvider::new();
        assert!(p.frame_mac_available());
        let k = LegKey::new([1; 32]);
        let tag = p.frame_mac(&k, b"mac-input").expect("bound");
        assert!(p.verify_frame_mac(&k, b"mac-input", tag));
        assert_ne!(tag, [0_u8; 8], "an all-zero tag would be a silent failure");
    }

    /// `K_leg` for the shared golden vector — `twinvpn-crypto`'s own fixture key.
    const PIN_KEY: [u8; 32] = [0x4b; 32];

    /// The accepted reading: `BLAKE2s-256(key)[0..8]`, from `twinvpn-crypto`'s
    /// `the_frame_mac_truncates_and_is_not_a_short_output_blake2s`.
    const TRUNCATED_READING: [u8; 8] = [0xd0, 0x4f, 0x9b, 0xe2, 0xb5, 0x7f, 0xc1, 0x5b];

    /// The reading ADR-0005 §9.1 **rejects**: `BLAKE2s(digest_length = 8)`,
    /// recorded so the divergence is visible in the source, not only in a comment.
    const SHORT_OUTPUT_READING: [u8; 8] = [0x77, 0x42, 0x14, 0xe9, 0x63, 0x46, 0xc3, 0xfa];

    /// The golden vector's frame, built through **this crate's own assembler**.
    ///
    /// Deliberately not a literal copy of `twinvpn-crypto`'s fixture bytes: the
    /// cross-crate risk is that the two disagree about §9.1's field order or
    /// widths, and only building it through [`crate::frame::RelayFrame::mac_input`]
    /// can catch that.
    fn pin_frame() -> crate::frame::RelayFrame {
        use bytes::Bytes;
        let mut v = vec![0x01_u8, 1 << 4]; // type = DATA, ver = 1, flags = 0
        v.extend_from_slice(&0x0708_u16.to_be_bytes()); // counter_low
        v.extend_from_slice(&0xdead_beef_u32.to_be_bytes()); // flow_id
        v.extend_from_slice(&[0x00; 8]); // auth_tag, not part of the MAC input
        v.extend_from_slice(&[0xab; 16]); // payload
        crate::frame::RelayFrame::parse(Bytes::from(v)).expect("parses")
    }

    /// The golden vector's `counter_full`.
    const PIN_COUNTER: u64 = 0x0102_0304_0506_0708;

    #[test]
    fn this_crates_mac_input_matches_the_shared_golden_vector() {
        // The assertion that actually protects against a cross-crate divergence:
        // `twinvpn-crypto` owns the MAC and the truncation, this crate owns the
        // frame layout, and if the two disagree about §9.1's order or widths every
        // legitimate frame is dropped while both sides look correct.
        let mut expected = Vec::new();
        expected.push(0x01_u8); // type
        expected.push(1 << 4); // ver | flags
        expected.extend_from_slice(&PIN_COUNTER.to_be_bytes()); // counter_full, BE
        expected.extend_from_slice(&0xdead_beef_u32.to_be_bytes()); // flow_id, BE
        expected.extend_from_slice(&[0xab; 16]); // payload, last and variable
        assert_eq!(pin_frame().mac_input(PIN_COUNTER), expected);

        // And nothing is length-prefixed: the assembled input is exactly the sum
        // of its fields. Prefixing a specified wire format would make this relay
        // reject every legitimate frame (the opposite call from ADR-0020 §11.5).
        assert_eq!(expected.len(), 1 + 1 + 8 + 4 + 16);
    }

    #[test]
    fn the_frame_mac_is_a_truncation_not_a_short_output_blake2s() {
        // THE assertion this binding was held back for. BLAKE2 parameterises
        // output length inside its init block, so BLAKE2s(digest_length = 8) and
        // BLAKE2s(digest_length = 32)[0..8] are different functions over the same
        // key and the same input. ADR-0005 §9.1's "truncated" is the SECOND.
        //
        // `twinvpn-crypto` pins this on the producer side; it is pinned again
        // here because the consequence lands on this side — a relay computing the
        // other reading verifies nothing while looking correctly configured.
        let p = CryptoProvider::new();
        let tag = p
            .frame_mac(&LegKey::new(PIN_KEY), &pin_frame().mac_input(PIN_COUNTER))
            .expect("bound");

        assert_eq!(
            tag, TRUNCATED_READING,
            "the tag must be the leading eight bytes of the FULL 256-bit keyed MAC"
        );
        assert_ne!(
            tag, SHORT_OUTPUT_READING,
            "the tag is a short-output BLAKE2s, which is a different function; \
             a relay computing it verifies nothing while looking configured"
        );
        // The two readings genuinely differ for this vector, so the pair above is
        // a real discrimination and not two assertions about the same value.
        assert_ne!(TRUNCATED_READING, SHORT_OUTPUT_READING);
    }

    #[test]
    fn a_tampered_frame_fails_verification() {
        let p = CryptoProvider::new();
        let k = LegKey::new([7; 32]);
        let tag = p.frame_mac(&k, b"the-original-input").expect("bound");

        // A different input under the same key.
        assert!(!p.verify_frame_mac(&k, b"the-tampered-input", tag));
        // The same input under a different key: an off-path injector without
        // K_leg cannot forge into the relay's session table.
        assert!(!p.verify_frame_mac(&LegKey::new([8; 32]), b"the-original-input", tag));
        // A flipped bit in the tag itself.
        let mut flipped = tag;
        flipped[0] ^= 0x01;
        assert!(!p.verify_frame_mac(&k, b"the-original-input", flipped));
    }

    #[test]
    fn the_mac_covers_every_field_of_the_frame_header() {
        // ADR-0005 §9.1's input is type ‖ ver|flags ‖ counter_full ‖ flow_id ‖
        // payload. Changing any one must change the tag, or that field is
        // malleable in flight.
        use crate::frame::RelayFrame;
        use bytes::Bytes;

        let build = |kind: u8, verflags: u8, flow: u32, payload: &[u8]| {
            let mut v = vec![kind, verflags];
            v.extend_from_slice(&1_u16.to_be_bytes());
            v.extend_from_slice(&flow.to_be_bytes());
            v.extend_from_slice(&[0xAA; 8]);
            v.extend_from_slice(payload);
            RelayFrame::parse(Bytes::from(v)).expect("parses")
        };
        let p = CryptoProvider::new();
        let k = LegKey::new([3; 32]);
        let mac =
            |f: &RelayFrame, counter: u64| p.frame_mac(&k, &f.mac_input(counter)).expect("bound");

        let base = build(0x01, 0x10, 42, b"payload");
        let baseline = mac(&base, 7);
        assert_ne!(baseline, mac(&build(0x12, 0x10, 42, b"payload"), 7), "type");
        assert_ne!(
            baseline,
            mac(&build(0x01, 0x1F, 42, b"payload"), 7),
            "flags"
        );
        assert_ne!(
            baseline,
            mac(&build(0x01, 0x10, 43, b"payload"), 7),
            "flow_id"
        );
        assert_ne!(
            baseline,
            mac(&build(0x01, 0x10, 42, b"payloae"), 7),
            "payload"
        );
        assert_ne!(baseline, mac(&base, 8), "counter_full");
        // A 16-bit wrap must not reproduce the tag: the MAC covers the FULL
        // counter, which is why a wrap is not a forgery oracle.
        assert_ne!(baseline, mac(&base, 7 + 65_536), "counter wrap");
    }

    #[test]
    fn a_token_claim_of_the_wrong_width_is_refused_not_truncated() {
        assert!(exact16(&[0_u8; 15]).is_none());
        assert!(exact16(&[0_u8; 17]).is_none());
        assert_eq!(exact16(&[3_u8; 16]), Some([3_u8; 16]));
    }
}
