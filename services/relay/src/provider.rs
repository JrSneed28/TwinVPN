//! The production [`RelayCrypto`] binding, on top of `twinvpn-crypto`.
//!
//! **Authority:** ADR-0018 CD-I2 and DP-8, ADR-0005 §11.3 and §9.1,
//! `contracts/cddl/twinvpn/v1/signed_statements.cddl` §13 and §14.
//!
//! # What is bound, and what is not — stated up front
//!
//! | Primitive | ADR | Bound to | Status |
//! |---|---|---|---|
//! | COSE_Sign1 verification over received octets | §11.3 | `twinvpn_crypto::verify_cose_sign1` | **real** |
//! | one-way 16-byte digest (daily `relay_sub` re-hash) | §10 | `twinvpn_crypto::hkdf_sha256` | **real** |
//! | keyed BLAKE2s frame MAC, truncated to 64 bits | §9.1 | — | **not bound** |
//!
//! The third is not an oversight and not a shortcut. `twinvpn-crypto` declares
//! `blake2` as a dependency but **exposes no BLAKE2s function** — its public API
//! is `verify_cose_sign1`, `hkdf_sha256`, `hkdf_expand_label`, `sha256`,
//! `sha256_parts`, the Noise session types and the statement decoders. There is
//! no keyed-MAC entry point of any kind.
//!
//! Substituting SHA-256 would be worse than leaving it unbound, because the frame
//! MAC is **on the wire**: ADR-0005 §9.1 fixes it as "a keyed BLAKE2s MAC under
//! `K_leg` … truncated to 64 bits", and the peer's `twinvpn-relay-client` computes
//! the same value. A relay that MACs with a different primitive rejects every
//! legitimate frame while looking configured. `core-dataplane`'s
//! `twinvpn-relay-client/src/hrw.rs` carries the *same* open integration item in
//! its own words — "`twinvpn-crypto` supplies `blake2s(relay_id ‖ pair_id)`" — so
//! this is one shared gap with two waiting consumers, not a local one.
//!
//! Until it lands, [`CryptoProvider::frame_mac`] and
//! [`CryptoProvider::verify_frame_mac`] behave exactly like [`FailClosed`]: no
//! `DATA` frame verifies and none is emitted. Admission, the epoch floor and the
//! log subject are all fully live.
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
use twinvpn_crypto::{verify_cose_sign1, StatementKind};

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
    /// `false` until `twinvpn-crypto` exposes keyed BLAKE2s. Exposed so startup
    /// can say so in one `WARN` rather than leaving an operator to infer it from
    /// every frame being dropped.
    #[must_use]
    pub const fn frame_mac_available(self) -> bool {
        false
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

    fn verify_frame_mac(&self, _k_leg: &LegKey, _mac_input: &[u8], _tag: [u8; 8]) -> bool {
        // See the module docs. Keyed BLAKE2s is not in `twinvpn-crypto`'s public
        // API, and SHA-256 is not a substitute for a value that is on the wire.
        false
    }

    fn frame_mac(&self, _k_leg: &LegKey, _mac_input: &[u8]) -> Option<[u8; 8]> {
        None
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
    fn the_frame_mac_is_honestly_unavailable_rather_than_silently_substituted() {
        // If this ever starts failing, `twinvpn-crypto` gained keyed BLAKE2s and
        // the binding in this module should be completed. Until then a relay
        // built on the real provider forwards no DATA frame, which is visible
        // rather than silent.
        let p = CryptoProvider::new();
        assert!(!p.frame_mac_available());
        assert!(p.frame_mac(&LegKey::new([1; 32]), b"input").is_none());
        assert!(!p.verify_frame_mac(&LegKey::new([1; 32]), b"input", [0; 8]));
    }

    #[test]
    fn a_token_claim_of_the_wrong_width_is_refused_not_truncated() {
        assert!(exact16(&[0_u8; 15]).is_none());
        assert!(exact16(&[0_u8; 17]).is_none());
        assert_eq!(exact16(&[3_u8; 16]), Some([3_u8; 16]));
    }
}
