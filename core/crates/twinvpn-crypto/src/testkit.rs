//! Deterministic signing fixtures, behind `test-support`.
//!
//! # Why this is in `twinvpn-crypto` and not in each crate's own tests
//!
//! CD-I2 is a check over **declared dependencies**, and `cargo metadata` reports
//! dev-dependencies alongside normal ones. So a `p256` dev-dependency in
//! `twinvpn-trust` would fail `cargo run -p xtask -- lint` exactly as a real one
//! would — correctly, because it is the same fact: that crate would be naming a
//! cryptographic implementation.
//!
//! A test that needs a signature therefore takes it from here, where the
//! dependency is already permitted. That is a small inconvenience and the right
//! one: the alternative is a per-crate exemption, and CD-I2's value is that
//! there is exactly one crate to audit.
//!
//! Never enabled in a shipped build.

// Test scaffolding panics on a defect in its own fixtures rather than
// returning a `Result` nobody would handle; a `# Panics` section on each would
// say the same thing five times.
#![allow(clippy::missing_panics_doc)]
// Test scaffolding panics on a defect in its own fixtures rather than
// returning a `Result` nobody would handle; a `# Panics` section on each would
// say the same thing five times.
#![allow(clippy::missing_panics_doc)]
// Test scaffolding panics on a defect in its own fixtures rather than
// returning a `Result` nobody would handle; a `# Panics` section on each would
// say the same thing five times.
#![allow(clippy::missing_panics_doc)]
// Test scaffolding panics on a defect in its own fixtures rather than
// returning a `Result` nobody would handle; a `# Panics` section on each would
// say the same thing five times.
#![allow(clippy::missing_panics_doc)]

use p256::ecdsa::signature::Signer;

use crate::emit::{encode, int_item, Item, StatementToSign};
use crate::{PublicVerifyingKey, StatementKind};

/// A deterministic ES256 key pair.
pub struct FixtureIdentity {
    signing: p256::ecdsa::SigningKey,
}

impl FixtureIdentity {
    /// Derives a key pair from a seed.
    ///
    /// No RNG: CD-3 bans reaching for the platform CSPRNG outside
    /// `twinvpn-env`'s binding, and a fixture must be reproducible anyway. The
    /// top byte is cleared so any seed yields a scalar below the group order
    /// without rejection sampling.
    #[must_use]
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut bytes = crate::sha256(seed);
        bytes[0] = 0x01;
        Self {
            signing: p256::ecdsa::SigningKey::from_bytes(&bytes.into()).expect("valid scalar"),
        }
    }

    /// The COSE_Key octets for the public half.
    ///
    /// Delegates to [`crate::cose::es256_cose_key_from_verifying_key`] rather
    /// than re-encoding, for the reason [`x25519_cose_key`] already gives one
    /// curve over: a fixture that encoded the key its own way would let the
    /// production encoder drift away from the fixtures that exist to catch
    /// exactly that. This was the third copy of an encoding RZ-8 single-homed.
    #[must_use]
    pub fn cose_key(&self) -> Vec<u8> {
        crate::cose::es256_cose_key_from_verifying_key(self.signing.verifying_key())
    }

    /// The public half as a **SubjectPublicKeyInfo**, DER.
    ///
    /// This is the encoding RFC 7250 puts on the wire when a peer presents a
    /// raw public key instead of a certificate, and it is what
    /// `twinvpn-service-common`'s TLS layer hands to
    /// `AlwaysResolvesClientRawPublicKeys` — so a lab client that wants to
    /// attach to a control plane needs exactly this and nothing else.
    ///
    /// It lives here rather than in the caller because CD-I2 puts every key
    /// encoding in this crate: a lab crate assembling its own DER around a
    /// P-256 point would be the second key-handling path CD-I2 forbids, and the
    /// failure mode of getting it subtly wrong is a TLS handshake that fails
    /// with no diagnosis on either side.
    #[must_use]
    pub fn spki_der(&self) -> Vec<u8> {
        use p256::pkcs8::EncodePublicKey;
        self.signing
            .verifying_key()
            .to_public_key_der()
            .expect("p256 encodes its own public key")
            .as_bytes()
            .to_vec()
    }

    /// The private half as **PKCS#8**, DER.
    ///
    /// The counterpart to [`Self::spki_der`]: what a TLS stack loads as the
    /// signing key behind a raw public key. Never shipped — this whole module
    /// is behind `test-support` (CD-5), and a fixture private key is not a
    /// credential anyone should be able to link into a product build.
    #[must_use]
    pub fn pkcs8_der(&self) -> Vec<u8> {
        use p256::pkcs8::EncodePrivateKey;
        self.signing
            .to_pkcs8_der()
            .expect("p256 encodes its own private key")
            .as_bytes()
            .to_vec()
    }

    /// The public verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> PublicVerifyingKey {
        PublicVerifyingKey::from_cose_key(&self.cose_key(), StatementKind::DeviceIdentityRecord)
            .expect("parse")
    }

    /// Signs a payload into COSE_Sign1 wire octets.
    #[must_use]
    pub fn sign(&self, payload: &Item) -> Vec<u8> {
        let unsigned = StatementToSign::new(payload, -7, Some(b"k")).expect("build");
        self.sign_prepared(&unsigned)
    }

    /// Signs a [`StatementToSign`] a production emitter already built.
    ///
    /// The fixture's stand-in for `IdentityCustody::identity_sign`: it is the
    /// one operation CB-5 puts inside the element, and a test needs a local
    /// substitute for it to exercise an emitter at all.
    #[must_use]
    pub fn sign_prepared(&self, unsigned: &StatementToSign) -> Vec<u8> {
        let sig: p256::ecdsa::Signature = self.signing.sign(unsigned.to_be_signed());
        unsigned.assemble(&sig.to_bytes()).expect("assemble")
    }
}

/// A deterministic **Ed25519** key pair, for the relay-credential issuer.
///
/// Separate from [`FixtureIdentity`] because the two are not interchangeable and
/// the difference is normative: ADR-0007 N-1 fixes **ES256** for the
/// `DeviceIdentityKey`, and ADR-0005 §11.3 fixes **Ed25519** for the
/// `RelayCapabilityToken` issuer. A relay's issuer key set refuses anything but
/// Ed25519, so a test that signed a token with the ES256 fixture would be
/// testing a token no relay will ever accept.
pub struct FixtureIssuer {
    signing: ed25519_dalek::SigningKey,
}

impl FixtureIssuer {
    /// Derives a key pair from a seed.
    ///
    /// No RNG: CD-3 bans reaching for the platform CSPRNG outside
    /// `twinvpn-env`'s binding, and a fixture must be reproducible anyway.
    #[must_use]
    pub fn from_seed(seed: &[u8]) -> Self {
        Self {
            signing: ed25519_dalek::SigningKey::from_bytes(&crate::sha256(seed)),
        }
    }

    /// The OKP/Ed25519 COSE_Key octets for the public half.
    #[must_use]
    pub fn cose_key(&self) -> Vec<u8> {
        encode(&Item::Map(vec![
            (Item::Uint(1), Item::Uint(1)),
            (int_item(-1), Item::Uint(6)),
            (
                int_item(-2),
                Item::Bytes(self.signing.verifying_key().to_bytes().to_vec()),
            ),
        ]))
        .expect("encode okp key")
    }

    /// Signs a payload into COSE_Sign1 wire octets under `alg = -8` (EdDSA).
    #[must_use]
    pub fn sign(&self, payload: &Item) -> Vec<u8> {
        use ed25519_dalek::Signer as _;
        let unsigned = StatementToSign::new(payload, -8, Some(b"k")).expect("build");
        let sig = self.signing.sign(unsigned.to_be_signed());
        unsigned.assemble(&sig.to_bytes()).expect("assemble")
    }
}

/// The `device_id` every [`verified_tunnel_key`] binding names.
pub const TK_BINDING_DEVICE_ID: [u8; 32] = [0x02; 32];
/// The `identity_id` every [`verified_tunnel_key`] binding names.
pub const TK_BINDING_IDENTITY_ID: [u8; 32] = [0x12; 32];

/// Builds a [`crate::VerifiedTunnelKey`] the only way one can be built.
///
/// There is no constructor for that type, by design: ADR-0001 §11.4 K3 says
/// "peers MUST verify the `TunnelKeyBinding` before trusting a static key", and
/// [`crate::binding::VerifiedTunnelKey`] is that rule expressed as a type. So
/// this fixture does the whole thing — signs a `TunnelKeyBinding`, verifies the
/// COSE_Sign1 over its octets, then verifies the binding — rather than
/// short-circuiting it. A shortcut here would make every test that depends on
/// the gate test something weaker than production does.
///
/// The identity is derived from a fixed label, so two calls yield bindings under
/// the same issuer and the `device_id` / `identity_id` a caller must pass to
/// [`crate::verify_tunnel_key_binding`] are the two constants above.
#[must_use]
pub fn verified_tunnel_key(tk_pub: &[u8; 32]) -> crate::VerifiedTunnelKey {
    let issuer = FixtureIdentity::from_seed(b"twinvpn/testkit/tunnel-key-binding");
    // Built by the PRODUCTION emitter, not by a hand-assembled map. The fixture
    // used to spell the payload out itself, which meant the gate every test
    // relies on was exercised against an encoding no shipping code produced.
    let unsigned = crate::binding::emit_tunnel_key_binding(
        &TK_BINDING_DEVICE_ID,
        &TK_BINDING_IDENTITY_ID,
        tk_pub,
        1,
        2_000_000_000_000,
    )
    .expect("fixture binding is well formed");
    let sig: p256::ecdsa::Signature = issuer.signing.sign(unsigned.to_be_signed());
    let octets = unsigned
        .assemble(&sig.to_bytes())
        .expect("fixture binding assembles");
    let verified = crate::verify_cose_sign1(
        &octets,
        StatementKind::TunnelKeyBinding,
        &issuer.verifying_key(),
    )
    .expect("fixture TunnelKeyBinding verifies");
    crate::verify_tunnel_key_binding(&verified, &TK_BINDING_DEVICE_ID, &TK_BINDING_IDENTITY_ID)
        .expect("fixture binding is well formed")
}

/// A COSE_Key for an X25519 public value, as `tk_pub` and a `cnf` claim are
/// carried.
///
/// Delegates to [`crate::cose::x25519_cose_key`] rather than re-encoding: a
/// fixture that encoded the key its own way would let a production encoder drift
/// away from the fixtures that are supposed to catch exactly that.
#[must_use]
pub fn x25519_cose_key(pubkey: &[u8; 32]) -> Vec<u8> {
    crate::cose::x25519_cose_key(pubkey)
}
