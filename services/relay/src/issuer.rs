//! The issuer public-key set — and why an empty one is the correct default.
//!
//! ADR-0005 §11.3: the relay holds the issuer public-key set **as signed config**
//! and verifies a `RelayCapabilityToken` against it entirely offline. That is
//! what lets relay admission survive a control-plane partition of any duration
//! (architecture A-12, testing-strategy A-13).
//!
//! `infra/scripts/bootstrap-local.sh` ships `issuers: []`, and its comment states
//! the rule this module enforces:
//!
//! > An EMPTY key set means NO TOKEN VERIFIES, which is the correct fail-closed
//! > default: a relay that admitted flows because it had no issuer keys would be
//! > an open relay.
//!
//! So [`IssuerKeySet::find`] on an empty set returns `None`, [`token::verify`]
//! turns that into [`Condition::IssuerUnknown`], and the flow is refused. The
//! **readiness** probe still reports ready — `infra/README.md` §5 asks for
//! "issuer key set loaded and parsable", not "non-empty" — because a relay with
//! no issuers is correctly configured and correctly admitting nothing, and
//! reporting it not-ready would hide the far more useful signal that a relay
//! whose *file* is missing or corrupt is genuinely broken.
//!
//! [`token::verify`]: crate::token::verify
//! [`Condition::IssuerUnknown`]: crate::condition::Condition::IssuerUnknown

use std::path::Path;

use serde::Deserialize;

use crate::crypto::IssuerPublicKey;

/// A parse or read failure on the issuer key set. Always fatal at startup.
#[derive(Debug, thiserror::Error)]
pub enum IssuerKeySetError {
    /// The file could not be read.
    #[error("issuer key set at {path}: cannot read")]
    Unreadable {
        /// The configured path. The *contents* never appear in an error.
        path: String,
    },
    /// The file is not the expected JSON shape.
    #[error("issuer key set at {path}: not the expected JSON shape")]
    Malformed {
        /// The configured path.
        path: String,
    },
    /// The file names a different operator group from this relay's.
    #[error("issuer key set at {path}: operator group mismatch")]
    OperatorGroupMismatch {
        /// The configured path.
        path: String,
    },
    /// A key entry was structurally unusable — an empty id, or empty key bytes.
    #[error("issuer key set at {path}: key entry {index} is unusable")]
    UnusableKey {
        /// The configured path.
        path: String,
        /// Which entry.
        index: usize,
    },
}

#[derive(Debug, Deserialize)]
struct RawKeySet {
    operator_group_id: String,
    issuers: Vec<RawIssuer>,
}

#[derive(Debug, Deserialize)]
struct RawIssuer {
    key_id: String,
    #[serde(default = "default_alg")]
    alg: String,
    /// Lowercase hex. Public material only.
    public_key_hex: String,
}

fn default_alg() -> String {
    "Ed25519".to_owned()
}

/// The set of issuer public keys this relay will verify a token against.
#[derive(Debug, Clone)]
pub struct IssuerKeySet {
    operator_group_id: String,
    keys: Vec<IssuerPublicKey>,
}

impl IssuerKeySet {
    /// Loads and validates the set, asserting it belongs to `operator_group_id`.
    ///
    /// # Errors
    ///
    /// Any read, parse, group-mismatch or unusable-entry failure. All are fatal:
    /// a relay whose issuer configuration it cannot understand must not run,
    /// because the alternative is running with a *partially* understood one.
    pub fn load(path: &Path, operator_group_id: &str) -> Result<Self, IssuerKeySetError> {
        let display = path.display().to_string();
        let raw = std::fs::read_to_string(path).map_err(|_| IssuerKeySetError::Unreadable {
            path: display.clone(),
        })?;
        Self::parse(&raw, operator_group_id, &display)
    }

    /// The parse half, separated so it is testable without a filesystem.
    ///
    /// # Errors
    ///
    /// As [`IssuerKeySet::load`], minus the read failure.
    pub fn parse(
        raw: &str,
        operator_group_id: &str,
        display: &str,
    ) -> Result<Self, IssuerKeySetError> {
        let parsed: RawKeySet =
            serde_json::from_str(raw).map_err(|_| IssuerKeySetError::Malformed {
                path: display.to_owned(),
            })?;

        if parsed.operator_group_id != operator_group_id {
            return Err(IssuerKeySetError::OperatorGroupMismatch {
                path: display.to_owned(),
            });
        }

        let mut keys = Vec::with_capacity(parsed.issuers.len());
        for (index, issuer) in parsed.issuers.into_iter().enumerate() {
            let bytes =
                decode_hex(&issuer.public_key_hex).ok_or(IssuerKeySetError::UnusableKey {
                    path: display.to_owned(),
                    index,
                })?;
            if issuer.key_id.is_empty() || bytes.is_empty() || issuer.alg.is_empty() {
                return Err(IssuerKeySetError::UnusableKey {
                    path: display.to_owned(),
                    index,
                });
            }
            keys.push(IssuerPublicKey {
                key_id: issuer.key_id,
                alg: issuer.alg,
                key: bytes,
            });
        }

        Ok(Self {
            operator_group_id: parsed.operator_group_id,
            keys,
        })
    }

    /// The operator group these issuers are scoped to.
    #[must_use]
    pub fn operator_group_id(&self) -> &str {
        &self.operator_group_id
    }

    /// How many keys are held. **Zero is legal and means "admit nothing".**
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the set is empty — i.e. whether this relay is closed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The key a token's `iss` names, if held.
    ///
    /// `None` on an empty set, which is what makes the fail-closed default work
    /// without a special case anywhere else.
    #[must_use]
    pub fn find(&self, key_id: &str) -> Option<&IssuerPublicKey> {
        self.keys.iter().find(|k| k.key_id == key_id)
    }
}

/// Strict lowercase-hex decode with an even-length requirement.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    // Bounded by the input length, which is bounded by the config file the
    // operator installed — not by an attacker-supplied declared length.
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

const fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOTSTRAP_STUB: &str = r#"{
      "_comment": "…",
      "operator_group_id": "local-operator",
      "issuers": []
    }"#;

    #[test]
    fn the_bootstrap_stub_parses_and_is_empty() {
        let set = IssuerKeySet::parse(BOOTSTRAP_STUB, "local-operator", "stub").expect("parses");
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn an_empty_set_finds_no_issuer_which_is_how_it_fails_closed() {
        let set = IssuerKeySet::parse(BOOTSTRAP_STUB, "local-operator", "stub").expect("parses");
        assert!(set.find("any-issuer").is_none());
        assert!(set.find("").is_none());
    }

    #[test]
    fn a_key_set_for_another_operator_group_is_refused() {
        let e = IssuerKeySet::parse(BOOTSTRAP_STUB, "someone-else", "stub").unwrap_err();
        assert!(matches!(e, IssuerKeySetError::OperatorGroupMismatch { .. }));
    }

    #[test]
    fn a_populated_set_finds_its_key() {
        let raw = r#"{"operator_group_id":"g","issuers":[
            {"key_id":"k1","alg":"Ed25519","public_key_hex":"00ff10"}]}"#;
        let set = IssuerKeySet::parse(raw, "g", "x").expect("parses");
        assert_eq!(set.len(), 1);
        let k = set.find("k1").expect("held");
        assert_eq!(k.key, vec![0x00, 0xff, 0x10]);
        assert!(set.find("k2").is_none());
    }

    #[test]
    fn a_malformed_key_is_a_startup_failure_not_a_skipped_entry() {
        let raw = r#"{"operator_group_id":"g","issuers":[
            {"key_id":"k1","alg":"Ed25519","public_key_hex":"zz"}]}"#;
        assert!(matches!(
            IssuerKeySet::parse(raw, "g", "x").unwrap_err(),
            IssuerKeySetError::UnusableKey { index: 0, .. }
        ));
    }

    #[test]
    fn an_error_never_carries_the_file_contents() {
        let e = IssuerKeySet::parse("{ not json", "g", "/run/secrets/relay/issuer-keys.json")
            .unwrap_err();
        let rendered = e.to_string();
        assert!(rendered.contains("issuer-keys.json"));
        assert!(!rendered.contains("not json"));
    }
}
