//! Test fixtures: deterministic keys and a statement builder.
//!
//! Every key here is derived from a fixed byte string, never from an RNG. That
//! is not only for reproducibility: ADR-0018 CD-3 bans the platform CSPRNG
//! outside `twinvpn-env`'s binding, and a test that reached for one would be a
//! lint violation as well as a flaky test.

use p256::ecdsa::signature::Signer;
use twinvpn_crypto::emit::{encode, int_item, Item, StatementToSign};
use twinvpn_crypto::StatementKind;

/// A deterministic ES256 key pair.
pub struct TestIdentity {
    signing: p256::ecdsa::SigningKey,
}

impl TestIdentity {
    /// Derives a key pair from a seed. The seed is reduced into the scalar
    /// field by SHA-256 so any 32 bytes produce a valid key.
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut bytes = twinvpn_crypto::sha256(seed);
        // Clear the top byte so the scalar is comfortably below the group order
        // without needing rejection sampling in a fixture.
        bytes[0] = 0x01;
        let signing = p256::ecdsa::SigningKey::from_bytes(&bytes.into()).expect("valid scalar");
        Self { signing }
    }

    /// The COSE_Key octets for the public half.
    pub fn cose_key(&self) -> Vec<u8> {
        let point = self.signing.verifying_key().to_sec1_point(false);
        let sec1 = point.as_ref();
        assert_eq!(sec1.len(), 65, "an uncompressed SEC1 point is 65 bytes");
        assert_eq!(sec1[0], 0x04);
        encode(&Item::Map(vec![
            (Item::Uint(1), Item::Uint(2)),                     // kty = EC2
            (int_item(-1), Item::Uint(1)),                      // crv = P-256
            (int_item(-2), Item::Bytes(sec1[1..33].to_vec())),  // x
            (int_item(-3), Item::Bytes(sec1[33..65].to_vec())), // y
        ]))
        .expect("encode cose key")
    }

    /// The public verifying key, as the crate models it.
    pub fn verifying_key(&self) -> twinvpn_crypto::PublicVerifyingKey {
        twinvpn_crypto::PublicVerifyingKey::from_cose_key(
            &self.cose_key(),
            StatementKind::DeviceIdentityRecord,
        )
        .expect("parse own cose key")
    }

    /// Signs a payload and returns the COSE_Sign1 wire octets.
    pub fn sign_statement(&self, payload: &Item) -> Vec<u8> {
        let unsigned = StatementToSign::new(payload, -7, Some(b"k")).expect("build");
        let sig: p256::ecdsa::Signature = self.signing.sign(unsigned.to_be_signed());
        unsigned.assemble(&sig.to_bytes()).expect("assemble")
    }
}

/// A COSE_Key for an X25519 public value, as `tk_pub` is carried.
pub fn x25519_cose_key(pubkey: &[u8; 32]) -> Vec<u8> {
    encode(&Item::Map(vec![
        (Item::Uint(1), Item::Uint(1)),               // kty = OKP
        (int_item(-1), Item::Uint(4)),                // crv = X25519
        (int_item(-2), Item::Bytes(pubkey.to_vec())), // x
    ]))
    .expect("encode okp key")
}

/// The canonical `crit` set as an [`Item`].
pub fn crit(names: &[&str]) -> Item {
    Item::Array(names.iter().map(|n| Item::Text((*n).to_owned())).collect())
}
