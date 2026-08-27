//! COSE_Sign1 verification **over the received octets**, and the COSE_Key
//! parsing that feeds it.
//!
//! **Authority:** `contracts/cddl/twinvpn/v1/signed_statements.cddl` encoding
//! rules 1–5, ADR-0003 §11 and §7 (the `crit` rule, R11), ADR-0001 §13.1 A3,
//! RFC 9052, RFC 8152 §13 (COSE_Key), RFC 8949 §4.2.1.
//!
//! # The one rule this module is built around
//!
//! > "**VERIFIED OVER THE RECEIVED OCTETS.** An implementation MUST NOT
//! > re-serialize before verifying. This is the 'sign the bytes you received,
//! > forward the bytes you received' discipline; it eliminates a bug class
//! > rather than testing for it."
//!
//! Making that *structural* rather than documented needs one thing: there must
//! be **no way to obtain a decoded statement payload except as the output of a
//! verification**. So:
//!
//! - [`verify_cose_sign1`] is the only function in the crate that produces a
//!   [`VerifiedStatement`], and it takes `&[u8]` — the wire octets — not a
//!   parsed anything.
//! - [`VerifiedStatement`] has **no public constructor**. `twinvpn-trust`'s
//!   statement decoders take `&VerifiedStatement`; there is no `&Value`
//!   overload, so "decode first, verify later" does not typecheck.
//! - The crate's one CBOR **emitter** ([`crate::emit`]) — which exists because a
//!   device must author its own `DeviceIdentityRecord`, `TunnelKeyBinding`,
//!   `PairingAttestation` and `RouteAdvertisement` — takes [`crate::emit::Item`],
//!   a type with **no conversion from [`crate::dcbor::Value`]**. So the decoded
//!   payload of a received statement cannot be fed back into the encoder: the
//!   round trip that "verify a re-encoded copy" requires does not typecheck. The
//!   two directions share no type.
//!
//! # Why `coset` is used, and where it is not trusted
//!
//! [`coset`] parses the COSE_Sign1 array and computes the RFC 9052
//! `Sig_structure`, retaining the *original* protected-header octets so
//! `tbs_data` is built from what arrived rather than from a re-encoding. What
//! `coset` does **not** do is enforce RFC 8949 §4.2.1, because `ciborium`
//! accepts non-canonical CBOR. So [`verify_cose_sign1`] runs
//! [`crate::dcbor::require_canonical`] over the **whole received envelope** and
//! over the payload **before** `coset` sees either. Non-canonical input is
//! refused; it is never normalized.

use coset::{CborSerializable, CoseSign1};

use crate::dcbor::{self, Value};
use crate::error::StatementKind;
use crate::{CryptoError, Result};

/// The cap on one signed statement's octets.
///
/// `contracts/docs/trust-boundaries.md` size-caps each statement type; this is
/// the ceiling across all of them, applied before any parse so that a hostile
/// length cannot drive work. `relay-map` is the largest realistic statement.
pub const MAX_STATEMENT_BYTES: usize = 64 * 1024;

/// The cap on one `crit` entry's length.
///
/// `crit` names field names. The longest in the CDDL is
/// `"supports_default_v6"`, nineteen bytes; 64 leaves room and bounds the string
/// that reaches [`CryptoError::UnknownCriticalField`], which is rendered into a
/// diagnostic.
pub const MAX_CRIT_ENTRY_BYTES: usize = 64;

/// The cap on the number of `crit` entries.
pub const MAX_CRIT_ENTRIES: usize = 16;

// COSE header labels (RFC 9052 §3.1).
const HDR_ALG: i64 = 1;
const HDR_KID: i64 = 4;

// COSE algorithm values (IANA COSE Algorithms registry).
const ALG_ES256: i64 = -7;
const ALG_EDDSA: i64 = -8;

// COSE_Key labels (RFC 8152 §7.1 / RFC 9052).
const KEY_KTY: i64 = 1;
const KEY_CRV: i64 = -1;
const KEY_X: i64 = -2;
const KEY_Y: i64 = -3;
const KEY_D: i64 = -4;

// COSE key types.
const KTY_OKP: u64 = 1;
const KTY_EC2: u64 = 2;

// COSE elliptic curves.
const CRV_P256: u64 = 1;
const CRV_X25519: u64 = 4;
const CRV_ED25519: u64 = 6;

/// A public key that can verify a TwinVPN signed statement.
///
/// **Public halves only.** CD-I4 — "no type in the workspace may carry an
/// identity private scalar" — is enforced here by there being no private
/// variant and no constructor that accepts one. The `d` label of a COSE_Key is
/// explicitly refused by [`PublicVerifyingKey::from_cose_key`] rather than
/// ignored, because a key delivered with its private half is a delivery defect
/// the core must surface, not silently strip.
#[derive(Debug, Clone)]
pub enum PublicVerifyingKey {
    /// ES256 — P-256 with SHA-256, COSE `alg` −7. ADR-0007 N-1 fixes this for
    /// the `DeviceIdentityKey`.
    Es256(Box<p256::ecdsa::VerifyingKey>),
    /// EdDSA over Ed25519, COSE `alg` −8. ADR-0005 §11.3 uses it for the
    /// `RelayCapabilityToken` issuer.
    Ed25519(Box<ed25519_dalek::VerifyingKey>),
}

impl PublicVerifyingKey {
    /// The COSE `alg` value this key verifies.
    #[must_use]
    pub const fn alg(&self) -> i64 {
        match self {
            PublicVerifyingKey::Es256(_) => ALG_ES256,
            PublicVerifyingKey::Ed25519(_) => ALG_EDDSA,
        }
    }

    /// Parses a COSE_Key from deterministic CBOR.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::NonCanonicalCbor`] if the encoding is not RFC 8949
    ///   §4.2.1.
    /// - [`CryptoError::IdentityAlgUnsupported`] for a key type or curve outside
    ///   this build's set, **including a key that carries a private half**.
    /// - [`CryptoError::KeyLength`] for a coordinate of the wrong width.
    pub fn from_cose_key(bytes: &[u8], kind: StatementKind) -> Result<Self> {
        let v = dcbor::parse_canonical(bytes).map_err(|e| e.into_crypto_error(kind))?;
        // A COSE_Key delivered with `d` present is a private key on a public
        // path. Refusing is CD-I4 held at the boundary: this crate must not be
        // the place that quietly discards a private scalar it should never have
        // been sent.
        if map_get_label(&v, KEY_D).is_some() {
            return Err(CryptoError::IdentityAlgUnsupported {
                algorithm: "COSE_Key carrying a private half",
            });
        }
        let kty = map_get_label(&v, KEY_KTY).and_then(Value::as_uint).ok_or(
            CryptoError::IdentityAlgUnsupported {
                algorithm: "COSE_Key without kty",
            },
        )?;
        let crv = map_get_label(&v, KEY_CRV).and_then(Value::as_uint).ok_or(
            CryptoError::IdentityAlgUnsupported {
                algorithm: "COSE_Key without crv",
            },
        )?;
        let x = map_get_label(&v, KEY_X).and_then(Value::as_bytes).ok_or(
            CryptoError::IdentityAlgUnsupported {
                algorithm: "COSE_Key without x",
            },
        )?;

        match (kty, crv) {
            (KTY_EC2, CRV_P256) => {
                let y = map_get_label(&v, KEY_Y).and_then(Value::as_bytes).ok_or(
                    CryptoError::IdentityAlgUnsupported {
                        algorithm: "EC2 COSE_Key without y",
                    },
                )?;
                if x.len() != 32 {
                    return Err(CryptoError::KeyLength {
                        expected: 32,
                        observed: x.len(),
                    });
                }
                if y.len() != 32 {
                    return Err(CryptoError::KeyLength {
                        expected: 32,
                        observed: y.len(),
                    });
                }
                let mut sec1 = [0u8; 65];
                sec1[0] = 0x04;
                sec1[1..33].copy_from_slice(x);
                sec1[33..65].copy_from_slice(y);
                let parsed = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| {
                    CryptoError::IdentityAlgUnsupported {
                        algorithm: "P-256 point not on curve",
                    }
                })?;
                Ok(PublicVerifyingKey::Es256(Box::new(parsed)))
            }
            (KTY_OKP, CRV_ED25519) => {
                let raw: [u8; 32] = x.try_into().map_err(|_| CryptoError::KeyLength {
                    expected: 32,
                    observed: x.len(),
                })?;
                let parsed = ed25519_dalek::VerifyingKey::from_bytes(&raw).map_err(|_| {
                    CryptoError::IdentityAlgUnsupported {
                        algorithm: "Ed25519 point not on curve",
                    }
                })?;
                Ok(PublicVerifyingKey::Ed25519(Box::new(parsed)))
            }
            // X25519 is a key-agreement key, never a signing key. It appears in
            // the CDDL as `TK public`, and mistaking it for a verifier is
            // exactly the kind/usage confusion `TunnelKeyBinding` exists to
            // prevent, so it is named rather than lumped in with "unsupported".
            (KTY_OKP, CRV_X25519) => Err(CryptoError::IdentityAlgUnsupported {
                algorithm: "X25519 is an agreement key, not a signing key",
            }),
            _ => Err(CryptoError::IdentityAlgUnsupported {
                algorithm: "kty/crv outside this build's set",
            }),
        }
    }

    fn verify(&self, tbs: &[u8], signature: &[u8]) -> bool {
        match self {
            PublicVerifyingKey::Es256(k) => {
                // COSE carries ECDSA as the fixed-width r || s concatenation
                // (RFC 9053 §2.1), never DER. Accepting DER here would admit a
                // second encoding of one signature, which is the same class of
                // defect canonical CBOR exists to close.
                if signature.len() != 64 {
                    return false;
                }
                let Ok(sig) = p256::ecdsa::Signature::from_slice(signature) else {
                    return false;
                };
                <p256::ecdsa::VerifyingKey as p256::ecdsa::signature::Verifier<
                    p256::ecdsa::Signature,
                >>::verify(k, tbs, &sig)
                .is_ok()
            }
            PublicVerifyingKey::Ed25519(k) => {
                let Ok(raw) = <[u8; 64]>::try_from(signature) else {
                    return false;
                };
                let sig = ed25519_dalek::Signature::from_bytes(&raw);
                // `verify_strict` rejects small-order and non-canonical public
                // keys and signature components. The permissive `verify` admits
                // signatures that are valid under some but not all conforming
                // verifiers, which is a fork in what "signed" means.
                k.verify_strict(tbs, &sig).is_ok()
            }
        }
    }
}

/// A COSE_Sign1 whose signature has been verified over the octets it arrived in.
///
/// **There is no public constructor.** The only way to hold one is to have
/// called [`verify_cose_sign1`], which is what makes "verified over the received
/// octets" a property of the type rather than a rule in a comment.
#[derive(Debug, Clone)]
pub struct VerifiedStatement {
    kind: StatementKind,
    payload: Value,
    key_id: Option<Vec<u8>>,
    alg: i64,
}

impl VerifiedStatement {
    /// Which statement type this was verified as.
    ///
    /// The caller named it; `SignedStatement.statement_type` on the wire is "a
    /// HINT for dispatch only … an attacker controls this value", so the
    /// authoritative type is the one the verifier committed to and the payload's
    /// own shape, which `twinvpn-trust` re-checks after verification.
    #[must_use]
    pub const fn kind(&self) -> StatementKind {
        self.kind
    }

    /// The verified, canonical payload.
    ///
    /// Reachable only from a `VerifiedStatement`, which is the point.
    #[must_use]
    pub const fn payload(&self) -> &Value {
        &self.payload
    }

    /// The protected header's `kid`, if it carried one.
    #[must_use]
    pub fn key_id(&self) -> Option<&[u8]> {
        self.key_id.as_deref()
    }

    /// The protected header's `alg`.
    #[must_use]
    pub const fn alg(&self) -> i64 {
        self.alg
    }

    /// Enforces the `crit` rule (CDDL encoding rule 5, ADR-0003 §7 R11).
    ///
    /// `crit_field` is the payload map key holding the `crit-set`; `understood`
    /// is every field name this verifier knows; `required` is the set the CDDL
    /// says the `crit` set MUST include.
    ///
    /// Both halves matter, and for different reasons:
    ///
    /// - An **unrecognised** `crit` member is refused, because "adding a future
    ///   RESTRICTION would be silently ignored by old devices, which converts a
    ///   tightening into a no-op — A SILENT AUTHORIZATION HOLE."
    /// - A **missing** required member is refused, because a producer that omits
    ///   `"generation"` from a `crit` set is inviting the verifier to treat a
    ///   monotone field as optional.
    ///
    /// # Errors
    ///
    /// [`CryptoError::UnknownCriticalField`] or
    /// [`CryptoError::MissingCriticalField`], and
    /// [`CryptoError::NonCanonicalCbor`] if the `crit` set is not a bounded
    /// array of text.
    pub fn check_crit(
        &self,
        crit_field: u64,
        understood: &[&str],
        required: &[&'static str],
    ) -> Result<()> {
        let entries = self
            .payload
            .map_get(crit_field)
            .and_then(Value::as_array)
            .ok_or(CryptoError::NonCanonicalCbor {
                kind: self.kind,
                step: "crit set absent or not an array",
            })?;
        // `crit-set = [+ tstr]` — at least one, and bounded so a hostile
        // statement cannot make the diagnostic path do unbounded work.
        if entries.is_empty() || entries.len() > MAX_CRIT_ENTRIES {
            return Err(CryptoError::NonCanonicalCbor {
                kind: self.kind,
                step: "crit set empty or over cap",
            });
        }
        let mut present: Vec<&str> = Vec::with_capacity(entries.len());
        for e in entries {
            let name = e.as_text().ok_or(CryptoError::NonCanonicalCbor {
                kind: self.kind,
                step: "crit entry is not text",
            })?;
            if name.len() > MAX_CRIT_ENTRY_BYTES {
                return Err(CryptoError::NonCanonicalCbor {
                    kind: self.kind,
                    step: "crit entry over cap",
                });
            }
            if !understood.contains(&name) {
                return Err(CryptoError::UnknownCriticalField {
                    kind: self.kind,
                    field: name.to_owned(),
                });
            }
            present.push(name);
        }
        for r in required {
            if !present.contains(r) {
                return Err(CryptoError::MissingCriticalField {
                    kind: self.kind,
                    field: r,
                });
            }
        }
        Ok(())
    }

    /// Refuses any payload map key outside `permitted` (CDDL encoding rule 5).
    ///
    /// Signed statements reject unknown fields, unlike unsigned transport
    /// messages which preserve and forward them. ADR-0003 §7: "the asymmetry is
    /// deliberate — a preserved-but-unverified field is a place to smuggle data
    /// past a policy check."
    ///
    /// # Errors
    ///
    /// [`CryptoError::NonCanonicalCbor`] naming the offending shape.
    pub fn check_no_unknown_fields(&self, permitted: &[u64]) -> Result<()> {
        let Value::Map(entries) = &self.payload else {
            return Err(CryptoError::NonCanonicalCbor {
                kind: self.kind,
                step: "statement payload is not a map",
            });
        };
        for (k, _) in entries {
            let Some(label) = k.as_uint() else {
                return Err(CryptoError::NonCanonicalCbor {
                    kind: self.kind,
                    step: "statement payload key is not an integer",
                });
            };
            if !permitted.contains(&label) {
                return Err(CryptoError::NonCanonicalCbor {
                    kind: self.kind,
                    step: "unknown field in signed statement",
                });
            }
        }
        Ok(())
    }
}

/// Verifies a COSE_Sign1 over the octets it arrived in.
///
/// `octets` are the contents of `twinvpn.v1.SignedStatement.cose_sign1`,
/// unmodified. `kind` is what the caller intends to read it as; it appears only
/// in diagnostics and does not select a key.
///
/// The order of operations is load-bearing and is asserted by the integration
/// test `a_non_canonical_envelope_is_refused_before_any_signature_check`:
///
/// 1. size cap, before anything;
/// 2. RFC 8949 §4.2.1 over the **whole received envelope**;
/// 3. structural parse by `coset`, retaining the original protected octets;
/// 4. RFC 8949 §4.2.1 over the payload;
/// 5. `alg` agreement between the protected header and the supplied key;
/// 6. the signature, over `coset`'s `Sig_structure` built from those octets.
///
/// # Errors
///
/// [`CryptoError::MalformedCose`], [`CryptoError::NonCanonicalCbor`],
/// [`CryptoError::IdentityAlgUnsupported`] or
/// [`CryptoError::SignatureInvalid`], in the order above.
pub fn verify_cose_sign1(
    octets: &[u8],
    kind: StatementKind,
    key: &PublicVerifyingKey,
) -> Result<VerifiedStatement> {
    if octets.is_empty() || octets.len() > MAX_STATEMENT_BYTES {
        return Err(CryptoError::MalformedCose {
            kind,
            step: "statement size outside bounds",
        });
    }
    // (2) The whole envelope, before `coset` allocates anything from it.
    dcbor::require_canonical(octets).map_err(|e| e.into_crypto_error(kind))?;

    // (3) `from_slice` accepts the untagged COSE_Sign1 array. The CDDL says
    // statements are "wrapped in a COSE_Sign1 envelope (RFC 9052)" and carried
    // as opaque protobuf bytes; there is one wire form, so the tagged spelling
    // is not admitted — a second accepted spelling is a second encoding of one
    // statement.
    let sign1 = CoseSign1::from_slice(octets).map_err(|_| CryptoError::MalformedCose {
        kind,
        step: "not a COSE_Sign1 array",
    })?;
    let payload_octets = sign1.payload.as_deref().ok_or(CryptoError::MalformedCose {
        kind,
        step: "detached payload",
    })?;

    // (4) The payload's own encoding.
    let payload = dcbor::parse_canonical(payload_octets).map_err(|e| e.into_crypto_error(kind))?;

    // (5) `alg` must be in the PROTECTED header — an unprotected `alg` is not
    // covered by the signature, so an attacker could rewrite it. It must also
    // match the key the caller supplied, so a statement cannot claim one
    // algorithm and be verified under another.
    let alg = protected_alg(&sign1).ok_or(CryptoError::MalformedCose {
        kind,
        step: "alg absent from protected header",
    })?;
    if alg != key.alg() {
        return Err(CryptoError::IdentityAlgUnsupported {
            algorithm: "protected alg does not match the supplied key",
        });
    }

    // (6) `tbs_data` rebuilds the Sig_structure from the ORIGINAL protected
    // octets (`ProtectedHeader::original_data`) and the received payload bstr,
    // which is what makes this a verification over received octets.
    let tbs = sign1.tbs_data(&[]);
    if !key.verify(&tbs, &sign1.signature) {
        return Err(CryptoError::SignatureInvalid { kind });
    }

    Ok(VerifiedStatement {
        kind,
        payload,
        key_id: protected_kid(&sign1),
        alg,
    })
}

fn protected_alg(sign1: &CoseSign1) -> Option<i64> {
    match &sign1.protected.header.alg {
        Some(coset::RegisteredLabelWithPrivate::Assigned(a)) => Some(*a as i64),
        Some(coset::RegisteredLabelWithPrivate::PrivateUse(v)) => Some(*v),
        // A text `alg` is not a registered algorithm; refusing it here is the
        // same rule as refusing an unregistered `reason_code`.
        _ => None,
    }
}

fn protected_kid(sign1: &CoseSign1) -> Option<Vec<u8>> {
    if sign1.protected.header.key_id.is_empty() {
        None
    } else {
        Some(sign1.protected.header.key_id.clone())
    }
}

/// Parses an OKP/X25519 COSE_Key and returns the 32-byte public value.
///
/// Separate from [`PublicVerifyingKey::from_cose_key`] **on purpose**: an
/// agreement key and a signing key are different kinds, and a single
/// "parse a COSE_Key" entry point is how one comes to be used as the other. The
/// signing parser refuses X25519 by name; this one refuses everything else.
///
/// # Errors
///
/// [`CryptoError::NonCanonicalCbor`], [`CryptoError::IdentityAlgUnsupported`]
/// for a key type or curve that is not OKP/X25519 or that carries a private
/// half, or [`CryptoError::KeyLength`] for a coordinate of the wrong width.
pub fn cose_key_x25519(bytes: &[u8], kind: StatementKind) -> Result<[u8; 32]> {
    let v = dcbor::parse_canonical(bytes).map_err(|e| e.into_crypto_error(kind))?;
    if map_get_label(&v, KEY_D).is_some() {
        return Err(CryptoError::IdentityAlgUnsupported {
            algorithm: "COSE_Key carrying a private half",
        });
    }
    let kty = map_get_label(&v, KEY_KTY).and_then(Value::as_uint);
    let crv = map_get_label(&v, KEY_CRV).and_then(Value::as_uint);
    if kty != Some(KTY_OKP) || crv != Some(CRV_X25519) {
        return Err(CryptoError::IdentityAlgUnsupported {
            algorithm: "tunnel key is not an OKP/X25519 COSE_Key",
        });
    }
    let x = map_get_label(&v, KEY_X).and_then(Value::as_bytes).ok_or(
        CryptoError::IdentityAlgUnsupported {
            algorithm: "OKP COSE_Key without x",
        },
    )?;
    x.try_into().map_err(|_| CryptoError::KeyLength {
        expected: 32,
        observed: x.len(),
    })
}

/// Looks up a COSE label, which may be a positive or negative integer.
///
/// [`dcbor::Value::Nint`] holds the *encoded* `n` for the value `-1 - n`, so a
/// label of `-1` is `Nint(0)`.
fn map_get_label(v: &Value, label: i64) -> Option<&Value> {
    let Value::Map(entries) = v else {
        return None;
    };
    let want = if label >= 0 {
        Value::Uint(u64::try_from(label).ok()?)
    } else {
        Value::Nint(u64::try_from(-(label + 1)).ok()?)
    };
    entries.iter().find(|(k, _)| *k == want).map(|(_, val)| val)
}

/// The COSE header label for `kid`, exported so a test or a caller can build a
/// header without re-deriving the number.
pub const COSE_HEADER_KID: i64 = HDR_KID;
/// The COSE header label for `alg`.
pub const COSE_HEADER_ALG: i64 = HDR_ALG;
/// COSE `alg` for ES256.
pub const COSE_ALG_ES256: i64 = ALG_ES256;
/// COSE `alg` for EdDSA.
pub const COSE_ALG_EDDSA: i64 = ALG_EDDSA;
/// COSE `kty` for OKP.
pub const COSE_KTY_OKP: u64 = KTY_OKP;
/// COSE `kty` for EC2.
pub const COSE_KTY_EC2: u64 = KTY_EC2;
/// COSE `crv` for P-256.
pub const COSE_CRV_P256: u64 = CRV_P256;
/// COSE `crv` for X25519.
pub const COSE_CRV_X25519: u64 = CRV_X25519;
/// COSE `crv` for Ed25519.
pub const COSE_CRV_ED25519: u64 = CRV_ED25519;
