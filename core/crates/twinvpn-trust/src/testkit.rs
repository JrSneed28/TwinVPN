//! Test fixtures that build a `VerifiedTunnelKey` **the only way one can be
//! built**.
//!
//! There is no shortcut constructor for [`twinvpn_crypto::VerifiedTunnelKey`],
//! by design (ADR-0007 N-4). So even a fixture has to sign a real
//! `TunnelKeyBinding`, verify the COSE_Sign1 over its octets, and verify the
//! binding — which makes these helpers a working demonstration that the gate
//! cannot be walked around, as well as scaffolding.
//!
//! The signing itself comes from `twinvpn_crypto::testkit`: CD-I2 covers
//! dev-dependencies too, so this crate may not name `p256` even in a test.
//!
//! Behind `test-support`, never enabled in a shipped build.

use twinvpn_crypto::emit::Item;
use twinvpn_crypto::testkit::{x25519_cose_key, FixtureIdentity};
use twinvpn_crypto::{verify_cose_sign1, StatementKind, VerifiedTunnelKey};

/// The `device_id` the default fixture binds to.
pub const FIXTURE_DEVICE: [u8; 32] = [0x02; 32];
/// The `identity_id` the default fixture binds to.
pub const FIXTURE_IDENTITY: [u8; 32] = [0x12; 32];

/// A `VerifiedTunnelKey` for the default fixture device.
#[must_use]
pub fn verified_tunnel_key(tk_pub: &[u8; 32], tk_generation: u64) -> VerifiedTunnelKey {
    verified_tunnel_key_inner(tk_pub, &FIXTURE_DEVICE, &FIXTURE_IDENTITY, tk_generation)
}

/// A `VerifiedTunnelKey` for an arbitrary device.
#[must_use]
pub fn verified_tunnel_key_for(
    tk_pub: &[u8; 32],
    device_id: &[u8; 32],
    tk_generation: u64,
) -> VerifiedTunnelKey {
    verified_tunnel_key_inner(tk_pub, device_id, &FIXTURE_IDENTITY, tk_generation)
}

fn verified_tunnel_key_inner(
    tk_pub: &[u8; 32],
    device_id: &[u8; 32],
    identity_id: &[u8; 32],
    tk_generation: u64,
) -> VerifiedTunnelKey {
    let ik = FixtureIdentity::from_seed(b"fixture-ik");
    let payload = Item::Map(vec![
        (Item::Uint(1), Item::Bytes(device_id.to_vec())),
        (Item::Uint(2), Item::Bytes(identity_id.to_vec())),
        (Item::Uint(3), Item::Bytes(x25519_cose_key(tk_pub))),
        (Item::Uint(4), Item::Uint(tk_generation)),
        (Item::Uint(5), Item::Uint(2_000_000_000_000)),
        (
            Item::Uint(6),
            Item::Array(vec![Item::Text("tk_generation".to_owned())]),
        ),
    ]);
    let octets = ik.sign(&payload);
    let verified = verify_cose_sign1(
        &octets,
        StatementKind::TunnelKeyBinding,
        &ik.verifying_key(),
    )
    .expect("verify");
    twinvpn_crypto::verify_tunnel_key_binding(&verified, device_id, identity_id).expect("binding")
}
