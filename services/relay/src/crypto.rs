//! The injected cryptographic seam, and the fail-closed default.
//!
//! # Why the primitives are injected rather than implemented
//!
//! ADR-0018 **CD-I2** makes `twinvpn-crypto` the only crate permitted a
//! cryptographic dependency, and `ownership.md` §6 forbids inventing
//! cryptographic primitives. `services/Cargo.toml`'s `[workspace.dependencies]`
//! — owned by the integration lead, not by this domain — declares no
//! `ed25519-dalek`, no `blake2`, no `coset` and no `ciborium`, and its own
//! comment restricts the edge into `/core` to `twinvpn-schema` and the framing
//! crate. So this crate has three choices: violate CD-I2, edit a manifest it
//! does not own, or take the primitives as a seam. It takes the seam.
//!
//! The consequence is deliberate and is the *safe* direction: [`FailClosed`] —
//! the default provider — refuses every signature, every MAC and every digest.
//! **An unconfigured relay is a closed relay**, exactly as the empty issuer key
//! set `infra/scripts/bootstrap-local.sh` ships is a closed relay.
//!
//! What a production wiring needs is recorded in `README.md` §8 and reported to
//! the integration lead: either `twinvpn-crypto` becomes a permitted edge for
//! `services/relay`, or the four primitive crates enter
//! `services/Cargo.toml`'s workspace set.
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

use twinvpn_service_common::Secret;

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
    pub key_id: String,
    /// The algorithm label from the key set, e.g. `"Ed25519"`.
    pub alg: String,
    /// The raw public key bytes.
    pub key: Vec<u8>,
}

/// The three primitives a relay needs and may not implement.
///
/// # Deliberately absent
///
/// There is no `decrypt`, no `open`, no `unseal` and no `derive_ldata_key`. The
/// trait's *shape* is half of I1's structural argument: a relay built against it
/// has no method to call that would yield plaintext.
pub trait RelayCrypto: Send + Sync + 'static {
    /// Verifies a detached signature over `message` under a held issuer key.
    ///
    /// Used for the `RelayCapabilityToken` (COSE_Sign1, ADR-0005 §11.3) and for
    /// the Owner-signed `RelayEpochFloor` (§11.3 "Revocation and S-03").
    fn verify_signature(&self, key: &IssuerPublicKey, message: &[u8], signature: &[u8]) -> bool;

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
/// binds its carriages — and admits no flow, because no token verifies and no
/// frame MAC checks. That is the same shape as the empty issuer key set: "a
/// relay that admitted flows because it had no issuer keys would be an open
/// relay" (`infra/scripts/bootstrap-local.sh`).
#[derive(Debug, Clone, Copy, Default)]
pub struct FailClosed;

impl RelayCrypto for FailClosed {
    fn verify_signature(&self, _key: &IssuerPublicKey, _message: &[u8], _signature: &[u8]) -> bool {
        false
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
        assert!(!c.verify_signature(&k, b"anything", b"anything"));
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
