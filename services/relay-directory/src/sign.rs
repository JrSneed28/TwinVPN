//! Signing the `RelayMap` — and what happens when nobody can.
//!
//! ADR-0006 §11.1: one COSE_Sign1/CBOR document per operator group, "issuer
//! Ed25519 over the canonical encoding (ADR-0003)". `infra/scripts/bootstrap-local.sh`
//! provisions the key at `relay-directory/map-signing.key`.
//!
//! Ed25519 is a cryptographic primitive and ADR-0018 CD-I2 keeps those in
//! `twinvpn-crypto`, which this workspace's manifest does not make available to
//! `services/` (see `README.md` §7). The signer is therefore an injected seam,
//! and the default provider [`Unsigned`] **signs nothing**.
//!
//! # Why an unsigned map is refused rather than published
//!
//! ADR-0006 §10: "A map that verifies against no held key is
//! `RELAY.MAP.SIGNATURE_INVALID` and the **previously held map remains in force**
//! — a bad publish must not disarm the fleet." A device that received an unsigned
//! document would refuse it and keep the map it has, which is correct; publishing
//! one anyway would burn a `map_version` for a document nobody can apply and, on
//! a device with no prior map, would leave it with an empty candidate set.
//!
//! So [`sign`] returns an error rather than an unsigned document, and the service
//! reports **not ready** while no signer is installed — `infra/README.md` §5's
//! relay-directory readiness set names "signing key loaded" for exactly this.

use std::path::Path;

use twinvpn_service_common::Secret;

/// The signing key material, read from `TWINVPN_RELAYDIR_MAP_SIGNING_KEY_PATH`.
///
/// Wrapped in [`Secret`]: no `Display`, no `Serialize`, redacted `Debug`. The one
/// way out is `expose()`, and the only caller entitled to it is a [`MapSigner`]
/// implementation.
pub struct SigningKey(Secret<Vec<u8>>);

impl SigningKey {
    /// Reads the key file.
    ///
    /// # Errors
    ///
    /// [`SignError::KeyUnreadable`]. The error names the **path**, never the
    /// contents.
    pub fn load(path: &Path) -> Result<Self, SignError> {
        let bytes = std::fs::read(path).map_err(|_| SignError::KeyUnreadable {
            path: path.display().to_string(),
        })?;
        if bytes.is_empty() {
            return Err(SignError::KeyUnreadable {
                path: path.display().to_string(),
            });
        }
        Ok(Self(Secret::new(bytes)))
    }

    /// The raw key, for a [`MapSigner`] implementation only.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningKey(<redacted>)")
    }
}

/// Why a map was not signed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// The key file is missing, unreadable, or empty.
    #[error("map signing key at {path}: cannot read")]
    KeyUnreadable {
        /// The configured path; never the contents.
        path: String,
    },
    /// No signer is installed. An unsigned map is never published.
    #[error("no map signer is installed; an unsigned RelayMap is never published")]
    NoSigner,
}

/// Produces the COSE_Sign1 signature over a map's canonical encoding.
pub trait MapSigner: Send + Sync {
    /// Signs `canonical_bytes`.
    ///
    /// # Errors
    ///
    /// [`SignError::NoSigner`] when the provider cannot sign.
    fn sign(&self, canonical_bytes: &[u8]) -> Result<Vec<u8>, SignError>;

    /// The `iss` key id this signer's key answers to, for the map header.
    fn key_id(&self) -> &str;
}

/// The default provider: signs nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unsigned;

impl MapSigner for Unsigned {
    fn sign(&self, _canonical_bytes: &[u8]) -> Result<Vec<u8>, SignError> {
        Err(SignError::NoSigner)
    }

    fn key_id(&self) -> &str {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_provider_signs_nothing() {
        assert_eq!(Unsigned.sign(b"anything"), Err(SignError::NoSigner));
        assert!(Unsigned.key_id().is_empty());
    }

    #[test]
    fn a_signing_key_has_no_rendering_path() {
        let k = SigningKey(Secret::new(vec![0xAB; 32]));
        assert_eq!(format!("{k:?}"), "SigningKey(<redacted>)");
    }

    #[test]
    fn a_missing_key_file_names_the_path_and_not_the_contents() {
        let e = SigningKey::load(Path::new("/run/secrets/relay-directory/map-signing.key"))
            .unwrap_err();
        assert!(e.to_string().contains("map-signing.key"));
        assert!(matches!(e, SignError::KeyUnreadable { .. }));
    }
}
