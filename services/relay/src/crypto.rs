//! The injected cryptographic seam, and the fail-closed default.
//!
//! # Why the primitives are injected rather than implemented
//!
//! ADR-0018 **CD-I2** makes `twinvpn-crypto` the only crate permitted a
//! cryptographic dependency, and `ownership.md` §6 forbids inventing
//! cryptographic primitives. `services/Cargo.toml` now declares `twinvpn-crypto`
//! as a permitted edge for the relay plane, and [`crate::provider`] binds it
//! behind this trait.
//!
//! **The seam stays** even though the provider exists, for three reasons that
//! all still hold:
//!
//! 1. It is what let every admission *policy* — ordering, skew, epoch floor,
//!    replay, proof of possession, renewal — be tested with no provider at all.
//! 2. [`FailClosed`] remains the **default**, so a relay with no provider
//!    configured refuses every signature, every MAC and every digest. **An
//!    unconfigured relay is a closed relay**, exactly as the empty issuer key set
//!    `infra/scripts/bootstrap-local.sh` ships is a closed relay.
//! 3. One primitive is still absent from `twinvpn-crypto`'s public API — the
//!    keyed BLAKE2s frame MAC of ADR-0005 §9.1 — so the trait is currently the
//!    only place that partial binding is visible. See [`crate::provider`].
//!
//! # The key inventory, and why it cannot decrypt
//!
//! ADR-0005 §7.1 enumerates a relay's *entire* key inventory as three items. Two
//! of them appear here: the issuer public-key set (verification-only, public) and
//! [`LegKey`] (`K_leg`, domain-separated from L-DATA, used only for the 64-bit
//! truncated frame MAC). Neither is an input to L-DATA's `Noise_IKpsk2` key
//! schedule, and this trait exposes **no decrypt operation at all** — there is no
//! method on [`RelayCrypto`] that takes ciphertext and returns plaintext, so a
//! relay built on it has no decryption path to reach for.
//!
//! # Verification is over the received octets
//!
//! [`RelayCrypto::verify_statement`] takes the **whole COSE_Sign1 envelope
//! exactly as it arrived** and returns typed claims read from the verified
//! payload. There is no step between receipt and verification in which the bytes
//! could be re-encoded, and there is no way to obtain a
//! [`crate::claims::TokenClaims`] without having gone through it — which is
//! `relay.proto`'s rule ("read the claims FROM THE VERIFIED PAYLOAD") expressed
//! as a type rather than as a comment.

use twinvpn_service_common::Secret;

use crate::claims::VerifiedClaims;

/// `K_leg` — the per-leg transport key.
///
/// ADR-0005 §7.1: "domain-separated from L-DATA; used only for the 64-bit frame
/// MAC". Wrapped in [`Secret`], which has no `Display` and no `Serialize`; the
/// one way out is `expose()`, which is greppable.
pub struct LegKey(Secret<[u8; 32]>);

impl LegKey {
    /// Wraps 32 bytes taken from a Noise_IK transport key or an RFC 8446
    /// exporter with label `"twinvpn relay leg v1"` (ADR-0005 §11.1(2)).
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(Secret::new(bytes))
    }

    /// The raw key, for a [`RelayCrypto`] implementation only.
    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        self.0.expose()
    }
}

impl std::fmt::Debug for LegKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LegKey(<redacted>)")
    }
}

/// An issuer's **public** verification key, as held in the issuer key set.
///
/// Public material: a relay verifies, it never signs
/// (`infra/scripts/bootstrap-local.sh`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerPublicKey {
    /// The `iss` claim value this key answers to.
    /// CDDL `key-id = tstr .size (1..64)`.
    pub key_id: String,
    /// The algorithm label from the key set, e.g. `"Ed25519"`.
    ///
    /// ADR-0005 §11.3 fixes Ed25519 for the relay-credential issuer. It is held
    /// as declared configuration so a key set naming something else fails at
    /// startup rather than at the first token.
    pub alg: String,
    /// The **COSE_Key** octets, deterministic CBOR (CDDL `cose-key = bstr`).
    ///
    /// Not a raw point: the algorithm and curve live inside the COSE_Key, so a
    /// key cannot be reinterpreted under a different algorithm than the one it
    /// was published for.
    pub key: Vec<u8>,
}

/// Which Owner-rooted statement is being verified.
///
/// The caller commits to the kind *before* verification, so a `RelayEpochFloor`
/// can never be accepted where a `RelayCapabilityToken` was expected —
/// `SignedStatement.statement_type` on the wire is "a HINT for dispatch only …
/// an attacker controls this value".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Statement {
    /// ADR-0005 §11.3; CDDL §13 `relay-capability-token`.
    RelayCapabilityToken,
    /// ADR-0005 §11.3 "Revocation and S-03"; CDDL §14 `relay-epoch-floor`.
    RelayEpochFloor,
}

/// The four primitives a relay needs and may not implement.
///
/// # Deliberately absent
///
/// There is no `decrypt`, no `open`, no `unseal` and no `derive_ldata_key`. The
/// trait's *shape* is half of I1's structural argument: a relay built against it
/// has no method to call that would yield plaintext.
pub trait RelayCrypto: Send + Sync + 'static {
    /// Verifies a COSE_Sign1 envelope **over the received octets** and returns
    /// the claims read from the verified payload.
    ///
    /// `envelope` is passed exactly as it arrived and is never re-encoded — the
    /// same rule `Auth.signed_payload` already states ("the verifier MUST verify
    /// over the exact received octets … and MUST NOT re-serialize"), applied to
    /// the relay's two Owner-rooted statements.
    ///
    /// `None` means "did not verify", for any reason. A verifier that
    /// distinguished *why* on a pre-authentication path would be an oracle; the
    /// caller maps every failure onto one registered code.
    fn verify_statement(
        &self,
        key: &IssuerPublicKey,
        kind: Statement,
        envelope: &[u8],
    ) -> Option<VerifiedClaims>;

    /// Verifies the 64-bit truncated BLAKE2s frame MAC under `K_leg`.
    ///
    /// ADR-0005 §9.1: computed over
    /// `(type‖ver‖flags‖counter_full‖flow_id‖payload)`. It protects the relay's
    /// own session table from off-path injection; it is **not** a confidentiality
    /// mechanism, because the payload is already L-DATA-sealed.
    fn verify_frame_mac(&self, k_leg: &LegKey, mac_input: &[u8], tag: [u8; 8]) -> bool;

    /// Computes the same MAC for an outgoing frame.
    fn frame_mac(&self, k_leg: &LegKey, mac_input: &[u8]) -> Option<[u8; 8]>;

    /// A domain-separated one-way 16-byte digest.
    ///
    /// The only use is the **daily re-hash of `relay_sub`** for operational log
    /// keys (ADR-0005 §10), so that logs cannot link a device across days.
    /// Returning `None` means no subject label is emitted at all, which is the
    /// fail-closed direction for a privacy control.
    fn digest16(&self, domain: &[u8], input: &[u8]) -> Option<[u8; 16]>;
}

/// The default provider: **refuses everything**.
///
/// A relay wired with `FailClosed` starts, serves `/healthz` and `/readyz`,
/// binds its carriages — and admits no flow, because no statement verifies and no
/// frame MAC checks. That is the same shape as the empty issuer key set: "a relay
/// that admitted flows because it had no issuer keys would be an open relay"
/// (`infra/scripts/bootstrap-local.sh`).
#[derive(Debug, Clone, Copy, Default)]
pub struct FailClosed;

impl RelayCrypto for FailClosed {
    fn verify_statement(
        &self,
        _key: &IssuerPublicKey,
        _kind: Statement,
        _envelope: &[u8],
    ) -> Option<VerifiedClaims> {
        None
    }

    fn verify_frame_mac(&self, _k_leg: &LegKey, _mac_input: &[u8], _tag: [u8; 8]) -> bool {
        false
    }

    fn frame_mac(&self, _k_leg: &LegKey, _mac_input: &[u8]) -> Option<[u8; 8]> {
        None
    }

    fn digest16(&self, _domain: &[u8], _input: &[u8]) -> Option<[u8; 16]> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_provider_admits_nothing() {
        let c = FailClosed;
        let k = IssuerPublicKey {
            key_id: "k1".into(),
            alg: "Ed25519".into(),
            key: vec![0; 32],
        };
        assert!(c
            .verify_statement(&k, Statement::RelayCapabilityToken, b"anything")
            .is_none());
        assert!(c
            .verify_statement(&k, Statement::RelayEpochFloor, b"anything")
            .is_none());
        assert!(!c.verify_frame_mac(&LegKey::new([0; 32]), b"x", [0; 8]));
        assert!(c.frame_mac(&LegKey::new([0; 32]), b"x").is_none());
        assert!(c.digest16(b"d", b"x").is_none());
    }

    #[test]
    fn a_leg_key_has_no_rendering_path() {
        let k = LegKey::new([0xAB; 32]);
        let rendered = format!("{k:?}");
        assert_eq!(rendered, "LegKey(<redacted>)");
        assert!(!rendered.contains("ab") && !rendered.contains("171"));
    }
}
