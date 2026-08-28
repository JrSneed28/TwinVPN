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
    #[must_use]
    pub fn cose_key(&self) -> Vec<u8> {
        let point = self.signing.verifying_key().to_sec1_point(false);
        let sec1 = point.as_ref();
        encode(&Item::Map(vec![
            (Item::Uint(1), Item::Uint(2)),
            (int_item(-1), Item::Uint(1)),
            (int_item(-2), Item::Bytes(sec1[1..33].to_vec())),
            (int_item(-3), Item::Bytes(sec1[33..65].to_vec())),
        ]))
        .expect("encode cose key")
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
        let sig: p256::ecdsa::Signature = self.signing.sign(unsigned.to_be_signed());
        unsigned.assemble(&sig.to_bytes()).expect("assemble")
    }
}

/// A COSE_Key for an X25519 public value, as `tk_pub` is carried.
#[must_use]
pub fn x25519_cose_key(pubkey: &[u8; 32]) -> Vec<u8> {
    encode(&Item::Map(vec![
        (Item::Uint(1), Item::Uint(1)),
        (int_item(-1), Item::Uint(4)),
        (int_item(-2), Item::Bytes(pubkey.to_vec())),
    ]))
    .expect("encode okp key")
}
