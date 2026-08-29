//! `TunnelKeyBinding` — the check that must not be skippable.
//!
//! **Authority:** ADR-0001 §11 item 4 and K3, ADR-0007 N-4 and N-5,
//! `contracts/cddl/twinvpn/v1/signed_statements.cddl` §2,
//! `contracts/proto/twinvpn/v1/identity.proto`.
//!
//! # Why this module is shaped the way it is
//!
//! ADR-0001 §11 item 4:
//!
//! > "The two are cryptographically bound: `DeviceIdentityKey` signs a
//! > `TunnelKeyBinding` over the X25519 static public key, and **peers MUST
//! > verify that binding before trusting a static key**."
//!
//! ADR-0001 K3 says what a mistake here costs:
//!
//! > "A binding-verification bug would be critical; it must be a **mandatory,
//! > non-skippable check**."
//!
//! And the CDDL says it a third time, in capitals: "**A SKIPPED CHECK IS A FULL
//! AUTHENTICATION BYPASS**: it is the only thing tying the software-held tunnel
//! key to the element-held identity that authorizes it."
//!
//! Three documents saying "must not be skippable" is a strong hint that a
//! comment is not the mechanism. So the mechanism here is a type:
//!
//! - [`VerifiedTunnelKey`] has **no public constructor**. The only way to obtain
//!   one is [`verify_tunnel_key_binding`], which requires the signed statement
//!   and the identity key that signed it.
//! - Every API in this crate that consumes a **peer's** X25519 static takes a
//!   `&VerifiedTunnelKey`, never a `[u8; 32]`. [`crate::noise`]'s
//!   `HandshakeConfig::remote_static` is the one that matters: a caller holding
//!   only raw bytes cannot start a handshake at all.
//!
//! There is deliberately no `VerifiedTunnelKey::from_bytes`, no `unchecked`
//! constructor, no feature flag, and no configuration switch. Adding one is the
//! change a reviewer should refuse.

use crate::cose::{cose_key_x25519, VerifiedStatement};
use crate::emit::{Item, StatementToSign};
use crate::error::StatementKind;
use crate::{CryptoError, Result};

/// The `tunnel-key-binding` CDDL map labels.
mod label {
    pub const DEVICE_ID: u64 = 1;
    pub const IDENTITY_ID: u64 = 2;
    pub const TK_PUB: u64 = 3;
    pub const TK_GENERATION: u64 = 4;
    pub const NOT_AFTER_MS: u64 = 5;
    pub const CRIT: u64 = 6;

    /// Every label the CDDL defines. A key outside this set is an unknown field
    /// in a signed statement, which encoding rule 5 refuses.
    pub const ALL: &[u64] = &[
        DEVICE_ID,
        IDENTITY_ID,
        TK_PUB,
        TK_GENERATION,
        NOT_AFTER_MS,
        CRIT,
    ];
}

/// Field names this build understands in a `TunnelKeyBinding`'s `crit` set.
const UNDERSTOOD_CRIT: &[&str] = &[
    "device_id",
    "identity_id",
    "tk_pub",
    "tk_generation",
    "not_after_ms",
];

/// The `crit` members the CDDL requires: "MUST include `"tk_generation"`".
const REQUIRED_CRIT: &[&str] = &["tk_generation"];

/// The maximum age of a `TunnelKeyBinding`, from ADR-0007's rotation rule.
///
/// The CDDL: `tk_generation` "MUST rotate at least every 180 days — this bounds
/// an extracted tunnel key, and it replaced certificate expiry in that role."
/// The value is exported so `twinvpn-trust` and the diagnostics agree on what
/// "overdue" means rather than each carrying a number.
pub const TK_ROTATION_MAX_DAYS: u64 = 180;

/// The overlap window during which a peer's previous `TK` is still accepted.
///
/// The CDDL: `T_TK_OVERLAP = 14 d`.
pub const TK_OVERLAP_DAYS: u64 = 14;

/// An X25519 static public key whose `TunnelKeyBinding` has been verified.
///
/// **No public constructor.** See the module documentation for why that is the
/// whole design.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTunnelKey {
    tk_pub: [u8; 32],
    device_id: [u8; 32],
    identity_id: [u8; 32],
    tk_generation: u64,
    not_after_ms: u64,
}

impl VerifiedTunnelKey {
    /// The X25519 static public key, for the Noise handshake.
    #[must_use]
    pub const fn tk_pub(&self) -> &[u8; 32] {
        &self.tk_pub
    }

    /// The `device_id` the binding names.
    #[must_use]
    pub const fn device_id(&self) -> &[u8; 32] {
        &self.device_id
    }

    /// The `identity_id` of the generation whose key signed the binding.
    #[must_use]
    pub const fn identity_id(&self) -> &[u8; 32] {
        &self.identity_id
    }

    /// The binding's `tk_generation`, tracked per peer as
    /// `highest_tk_generation_seen` and monotone (ADR-0007 N-22).
    #[must_use]
    pub const fn tk_generation(&self) -> u64 {
        self.tk_generation
    }

    /// The binding's expiry, in UTC milliseconds.
    #[must_use]
    pub const fn not_after_ms(&self) -> u64 {
        self.not_after_ms
    }
}

/// Verifies a `TunnelKeyBinding` and, only on success, yields the tunnel key.
///
/// `statement` must already have been verified as a COSE_Sign1 under the
/// **identity key of the device the binding claims** — which is what makes this
/// a binding rather than a self-assertion. The caller supplies
/// `expected_device_id` and `expected_identity_id` from the `DeviceIdentity`
/// record it is evaluating; a mismatch is refused, because a binding that
/// verifies under one identity while naming another is a binding for a different
/// device presented as if it were this one.
///
/// # What is checked
///
/// 1. the statement is a `TunnelKeyBinding` (the caller's `kind`, and the
///    payload shape);
/// 2. no unknown field (encoding rule 5);
/// 3. the `crit` set is understood and contains `tk_generation`;
/// 4. `device_id` and `identity_id` match what the caller is evaluating;
/// 5. `tk_pub` is a well-formed OKP/X25519 COSE_Key.
///
/// **Expiry is deliberately not checked here.** Evaluating `not_after_ms`
/// requires a [`twinvpn_env::ValidityClock`], and this crate takes no `Env`;
/// more importantly, ADR-0007 N-27's freshness ladder decides what an expired
/// binding *means*, and that decision is `twinvpn-trust`'s. The value is
/// returned so the caller cannot proceed without seeing it.
///
/// # Errors
///
/// [`CryptoError::BindingInvalid`] for every structural failure, so a caller
/// mapping this to a diagnostic reaches `AUTH.BINDING_INVALID` — the code whose
/// registry entry says "A skipped check would be a FULL AUTHENTICATION BYPASS".
pub fn verify_tunnel_key_binding(
    statement: &VerifiedStatement,
    expected_device_id: &[u8; 32],
    expected_identity_id: &[u8; 32],
) -> Result<VerifiedTunnelKey> {
    if statement.kind() != StatementKind::TunnelKeyBinding {
        return Err(CryptoError::BindingInvalid {
            step: "statement is not a TunnelKeyBinding",
        });
    }
    statement
        .check_no_unknown_fields(label::ALL)
        .map_err(|_| CryptoError::BindingInvalid {
            step: "unknown field in TunnelKeyBinding",
        })?;
    // A `crit` failure keeps its own code: an unrecognised critical field is a
    // version problem, not an authentication problem, and conflating them would
    // tell a user to re-pair when they need to update.
    statement.check_crit(label::CRIT, UNDERSTOOD_CRIT, REQUIRED_CRIT)?;

    let p = statement.payload();
    let device_id = fixed32(p.map_get(label::DEVICE_ID), "device_id")?;
    let identity_id = fixed32(p.map_get(label::IDENTITY_ID), "identity_id")?;
    let tk_generation = p
        .map_get(label::TK_GENERATION)
        .and_then(crate::dcbor::Value::as_uint)
        .ok_or(CryptoError::BindingInvalid {
            step: "tk_generation absent or not a uint",
        })?;
    let not_after_ms = p
        .map_get(label::NOT_AFTER_MS)
        .and_then(crate::dcbor::Value::as_uint)
        .ok_or(CryptoError::BindingInvalid {
            step: "not_after_ms absent or not a uint",
        })?;

    // The binding must be *for* the identity being evaluated. Without this the
    // check degrades into "some device signed some binding", which is not a
    // binding at all.
    if &device_id != expected_device_id {
        return Err(CryptoError::BindingInvalid {
            step: "binding names a different device_id",
        });
    }
    if &identity_id != expected_identity_id {
        return Err(CryptoError::BindingInvalid {
            step: "binding names a different identity_id",
        });
    }

    let tk_cose = p
        .map_get(label::TK_PUB)
        .and_then(crate::dcbor::Value::as_bytes)
        .ok_or(CryptoError::BindingInvalid {
            step: "tk_pub absent or not a byte string",
        })?;
    let tk_pub = cose_key_x25519(tk_cose, StatementKind::TunnelKeyBinding).map_err(|_| {
        CryptoError::BindingInvalid {
            step: "tk_pub is not an OKP/X25519 COSE_Key",
        }
    })?;
    // An all-zero X25519 public key is the low-order point that makes every
    // agreement produce zero. `x25519-dalek` returns a zero shared secret rather
    // than failing, so it is refused here — a peer offering it is either broken
    // or attacking, and neither should reach a handshake.
    if tk_pub == [0u8; 32] {
        return Err(CryptoError::BindingInvalid {
            step: "tk_pub is the all-zero point",
        });
    }

    Ok(VerifiedTunnelKey {
        tk_pub,
        device_id,
        identity_id,
        tk_generation,
        not_after_ms,
    })
}

fn fixed32(v: Option<&crate::dcbor::Value>, what: &'static str) -> Result<[u8; 32]> {
    let b = v
        .and_then(crate::dcbor::Value::as_bytes)
        .ok_or(CryptoError::BindingInvalid { step: what })?;
    // Rejected, never truncated and never padded — `identifiers.md` §5.
    b.try_into().map_err(|_| CryptoError::BindingInvalid {
        step: "identifier width",
    })
}

/// Builds this device's own `TunnelKeyBinding`, ready for `identity_sign`.
///
/// The counterpart to [`verify_tunnel_key_binding`], and the reason this module
/// stopped being verify-only. ADR-0007 **N-4** requires the statement in
/// production — a peer must verify one before writing TK into `TrustedPeer` —
/// and until now every construction of one in the workspace was a testkit
/// fixture, so the tree could check a binding it could not author. That is
/// `docs/implementation/ownership.md` §11.2 **G-14 (c)**.
///
/// # The signature is not here, and cannot be
///
/// CB-5 row 1 keeps IK inside the platform element, so this returns a
/// [`StatementToSign`] rather than a signed statement. The caller hands
/// [`StatementToSign::to_be_signed`] to `IdentityCustody::identity_sign` and
/// puts the answer back with [`StatementToSign::assemble`]. No signing key is
/// named in this crate and there is nowhere to put one (CD-I4).
///
/// # Why the emitter re-checks what the verifier checks
///
/// `tk_pub` is refused if it is the all-zero point, exactly as
/// [`verify_tunnel_key_binding`] refuses it. Emitting one would produce a
/// binding that every conforming peer rejects, and the failure would surface at
/// the far end of a pairing ceremony as `AUTH.BINDING_INVALID` against the
/// *joining* device — a diagnosis pointing at the wrong machine. Refusing at the
/// source costs one comparison.
///
/// The `crit` set is `["tk_generation"]`, which the CDDL states as a MUST and
/// which [`verify_tunnel_key_binding`] enforces on the way back in. It is a
/// `const` here rather than a parameter for the reason encoding rule 5 gives:
/// the field set of a signed statement is fixed by the contract, so a caller
/// that could vary it could author a statement no peer understands.
///
/// # Parameters
///
/// `tk_generation` is separately monotone from the identity `generation`
/// (N-22), and the CDDL requires it to advance at least every
/// [`TK_ROTATION_MAX_DAYS`] days. `not_after_ms` is mandatory on every statement
/// (encoding rule 6); choosing it is the caller's, because this crate takes no
/// clock — see [`verify_tunnel_key_binding`]'s note on why expiry is evaluated
/// in `twinvpn-trust`.
///
/// # Errors
///
/// [`CryptoError::BindingInvalid`] if `tk_pub` is the all-zero point, or as
/// [`crate::emit::encode`] for a duplicate map key — unreachable here, since
/// every label is a `const` in [`label`].
pub fn emit_tunnel_key_binding(
    device_id: &[u8; 32],
    identity_id: &[u8; 32],
    tk_pub: &[u8; 32],
    tk_generation: u64,
    not_after_ms: u64,
) -> Result<StatementToSign> {
    if tk_pub == &[0u8; 32] {
        return Err(CryptoError::BindingInvalid {
            step: "refusing to bind the all-zero point",
        });
    }
    // Field 3 is `cose-key`, not a raw 32-byte string: signed_statements.cddl §2
    // carries `tk_pub` as a COSE_Key and `verify_tunnel_key_binding` parses it
    // with `cose_key_x25519`. `pairing_offer.cddl` field 3 carries the SAME key
    // as a bare `bstr .size 32` and says so as a finding rather than a choice —
    // ownership.md §11 G-9. This is the signed-statement side, so it is the
    // COSE_Key form.
    let payload = Item::Map(vec![
        (
            Item::Uint(label::DEVICE_ID),
            Item::Bytes(device_id.to_vec()),
        ),
        (
            Item::Uint(label::IDENTITY_ID),
            Item::Bytes(identity_id.to_vec()),
        ),
        (
            Item::Uint(label::TK_PUB),
            Item::Bytes(crate::cose::x25519_cose_key(tk_pub)),
        ),
        (Item::Uint(label::TK_GENERATION), Item::Uint(tk_generation)),
        (Item::Uint(label::NOT_AFTER_MS), Item::Uint(not_after_ms)),
        (
            Item::Uint(label::CRIT),
            Item::Array(
                REQUIRED_CRIT
                    .iter()
                    .map(|f| Item::Text((*f).to_owned()))
                    .collect(),
            ),
        ),
    ]);
    // ES256, and no `kid`. ADR-0007 N-1 fixes ES256 for every IK, and the
    // verifier resolves the key from the `DeviceIdentityRecord` or the
    // `PairingOffer` it is already holding rather than from a hint in the
    // envelope — `verify_tunnel_key_binding` never reads `kid`. An identifier
    // that no verifier consults is bytes in a QR code.
    StatementToSign::new(&payload, crate::cose::COSE_ALG_ES256, None)
}

#[cfg(test)]
mod emit_tests {
    use super::*;
    use crate::error::StatementKind;

    /// The round trip the emitter exists for: what this device authors is what
    /// a peer's verifier accepts. `testkit::verified_tunnel_key` already drives
    /// the same path, so this is the direct statement of the property rather
    /// than an inference from a fixture.
    #[test]
    fn what_the_emitter_writes_is_what_the_verifier_accepts() {
        let issuer = crate::testkit::FixtureIdentity::from_seed(b"emit-roundtrip");
        let device_id = [7u8; 32];
        let identity_id = [9u8; 32];
        let tk_pub = [3u8; 32];

        let unsigned =
            emit_tunnel_key_binding(&device_id, &identity_id, &tk_pub, 4, 1_700_000_000_000)
                .expect("emits");
        let octets = issuer.sign_prepared(&unsigned);

        let statement = crate::verify_cose_sign1(
            &octets,
            StatementKind::TunnelKeyBinding,
            &issuer.verifying_key(),
        )
        .expect("the emitted envelope verifies");
        let verified = verify_tunnel_key_binding(&statement, &device_id, &identity_id)
            .expect("the emitted binding verifies");

        assert_eq!(verified.tk_pub(), &tk_pub);
        assert_eq!(verified.tk_generation(), 4);
        assert_eq!(verified.not_after_ms(), 1_700_000_000_000);
    }

    /// The emitter refuses the point the verifier refuses, so the failure lands
    /// on the device that made the mistake rather than on its peer.
    #[test]
    fn the_all_zero_point_is_refused_at_the_source() {
        let err = emit_tunnel_key_binding(&[1u8; 32], &[2u8; 32], &[0u8; 32], 1, 1)
            .expect_err("must refuse");
        assert!(matches!(err, CryptoError::BindingInvalid { .. }));
    }

    /// A binding authored for one device does not verify as another's. The
    /// negative control for the round trip above.
    #[test]
    fn a_binding_naming_another_device_is_refused() {
        let issuer = crate::testkit::FixtureIdentity::from_seed(b"emit-wrong-device");
        let unsigned =
            emit_tunnel_key_binding(&[7u8; 32], &[9u8; 32], &[3u8; 32], 1, 1).expect("emits");
        let octets = issuer.sign_prepared(&unsigned);
        let statement = crate::verify_cose_sign1(
            &octets,
            StatementKind::TunnelKeyBinding,
            &issuer.verifying_key(),
        )
        .expect("verifies as an envelope");
        assert!(verify_tunnel_key_binding(&statement, &[8u8; 32], &[9u8; 32]).is_err());
    }
}
