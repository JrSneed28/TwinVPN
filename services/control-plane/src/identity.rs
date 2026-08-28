//! Which device is on this connection.
//!
//! **Authority:** ADR-0001 §7.2 and ADR-0007 **N-32** (the `DeviceIdentityKey`
//! *is* the RFC 7250 raw public key an mTLS peer presents; "no separate
//! transport credential exists"), `contracts/docs/identifiers.md` §2 (the
//! derivation), ADR-0007 §11 and N-21 (rotation moves `identity_id` and leaves
//! `device_id` alone), `README.md` §7.
//!
//! # The two steps, and why they are two
//!
//! ```text
//!   presented SPKI ──derive──▶ identity_id ──look up──▶ device_id
//!        (this module, sync, no I/O)      (the device table, async)
//! ```
//!
//! Step one is pure: it converts the peer's `SubjectPublicKeyInfo` to the dCBOR
//! COSE_Key the derivation is defined over and hashes it, through
//! [`spki_to_es256_cose_key`](twinvpn_service_common::binding::spki_to_es256_cose_key)
//! and [`derive_device_id_for`](twinvpn_service_common::binding::derive_device_id_for)
//! — the single home for that conversion in this workspace, because "two copies
//! that disagree both produce canonical CBOR, of two different keys".
//!
//! Step two is the part only **this** service can do. `service-common`'s
//! [`DerivedPreferred`] binding says so plainly: closing the rotation gap "needs
//! the succession chain", which the rendezvous and presence may not fetch on a
//! reconnect path (**I5**). This service *is* the chain — `RotateDeviceCredential`
//! is one of its own commands and it re-indexes `device.identity_id` onto the
//! successor the signed `IdentitySuccession` names — so it resolves the derived
//! identity through a record it wrote itself rather than pinning a first claim.
//! [`crate::serve`] does that lookup, because it is I/O and this trait is not.
//!
//! # What a miss means
//!
//! An identity with no row resolves to **itself**: the derived value, which for
//! a generation-0 key *is* the `device_id` (`identifiers.md` §2). That is not a
//! grant. It is the only value that key can speak for, and every handler still
//! refuses it with `AUTH.PEER_UNTRUSTED` until a `RegisterDevice` — carrying an
//! `Owner`-signed enrolment proof — admits it. A device enrols as itself or not
//! at all, which is what [`crate::domain::device::register`]'s binding check
//! makes structural.
//!
//! [`DerivedPreferred`]: twinvpn_service_common::binding::DerivedPreferred

use quinn::rustls::pki_types::CertificateDer;
use twinvpn_service_common::binding as spki;
use twinvpn_service_common::{ChannelIdentity, ServiceError};

use crate::codes;
use crate::quic::PeerIdentityVerifier;

/// What a completed handshake established about the peer.
///
/// Both fields are **proved**, not claimed: TLS 1.3's `CertificateVerify` is a
/// signature over the handshake transcript, so the peer holds the private half
/// of the key these were computed from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelPeer {
    /// The presented key, in the COSE_Key encoding every signature check and
    /// every derivation in this system is defined over.
    pub identity_cose_key: Vec<u8>,
    /// `SHA-256("TwinVPN/DeviceIdentity/v1" || 0x00 || dCBOR(COSE_Key))`.
    pub identity_id: [u8; 32],
}

/// Derives the identity a presented raw public key speaks for.
///
/// Holds no state and does no I/O — which is what lets it run inside the
/// handshake path without putting a database call there.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChannelDerivedIdentity;

impl ChannelDerivedIdentity {
    /// Converts one presented certificate chain into a [`ChannelPeer`].
    ///
    /// # Errors
    ///
    /// `CONTROL.HANDSHAKE_REJECTED` for anything that is not a single RFC 7250
    /// P-256 `SubjectPublicKeyInfo` this build can derive an ES256 identity
    /// from. A general PKI chain, a compressed point, an Ed25519 key and a
    /// coordinate pair that is not on the curve all land here, and all land
    /// here **identically**: the refusal carries no bytes of what was presented.
    pub fn peer_of(
        &self,
        presented: &[CertificateDer<'static>],
    ) -> Result<ChannelPeer, ServiceError> {
        // Exactly one. RFC 7250 carries the SubjectPublicKeyInfo alone, so a
        // "chain" here is a client speaking a profile this service does not.
        let [spki] = presented else {
            return Err(codes::bare(
                twinvpn_types::codes::CONTROL_HANDSHAKE_REJECTED,
            ));
        };
        let channel = ChannelIdentity::new(spki.as_ref());
        let cose = spki::spki_to_es256_cose_key(channel.as_bytes())
            .map_err(|_| codes::bare(twinvpn_types::codes::CONTROL_HANDSHAKE_REJECTED))?;
        let identity_id = spki::derive_device_id_for(&channel)
            .map_err(|_| codes::bare(twinvpn_types::codes::CONTROL_HANDSHAKE_REJECTED))?;
        Ok(ChannelPeer {
            identity_cose_key: cose,
            identity_id: identity_id.to_array(),
        })
    }
}

impl PeerIdentityVerifier for ChannelDerivedIdentity {
    /// The **derived** value: the `device_id` for a generation-0 key, and the
    /// `identity_id` to resolve for any other. [`crate::serve`] performs that
    /// resolution; this returns what the key itself says and nothing more.
    fn identify(&self, peer_key: &[CertificateDer<'static>]) -> Result<[u8; 32], ServiceError> {
        self.peer_of(peer_key).map(|p| p.identity_id)
    }
}

#[cfg(test)]
mod tests {
    use super::{ChannelDerivedIdentity, ChannelPeer};
    use crate::quic::PeerIdentityVerifier;
    use quinn::rustls::pki_types::CertificateDer;

    /// A COSE_Key for the P-256 generator, assembled from the published point.
    ///
    /// The same fixture `twinvpn-crypto`'s own `deviceid` tests use, so this
    /// module's conversion is checked against a point anyone can rebuild from
    /// SP 800-186 rather than against one this code produced.
    const GX: [u8; 32] = [
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40,
        0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98,
        0xC2, 0x96,
    ];
    const GY: [u8; 32] = [
        0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E,
        0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF,
        0x51, 0xF5,
    ];

    fn generator_spki() -> CertificateDer<'static> {
        let mut der = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
            0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        ];
        der.extend_from_slice(&GX);
        der.extend_from_slice(&GY);
        CertificateDer::from(der)
    }

    #[test]
    fn a_presented_p256_key_derives_the_identity_the_device_derived() {
        let peer: ChannelPeer = ChannelDerivedIdentity
            .peer_of(&[generator_spki()])
            .expect("a real P-256 point");
        // The COSE_Key this module built must be the one `twinvpn-crypto`'s own
        // derivation is defined over — asserted by deriving through the crypto
        // crate directly and comparing, so the two paths agree by test rather
        // than by construction.
        let expected = twinvpn_crypto::derive_device_id_checked(&peer.identity_cose_key)
            .expect("a canonical ES256 COSE_Key");
        assert_eq!(peer.identity_id, expected.to_array());
        assert_eq!(
            ChannelDerivedIdentity
                .identify(&[generator_spki()])
                .expect("identifies"),
            peer.identity_id
        );
    }

    #[test]
    fn nothing_but_one_raw_p256_key_is_identified() {
        // A chain, an empty presentation, a truncated SPKI and a key whose
        // coordinates are not a point: one answer, and it names no bytes.
        let short = CertificateDer::from(vec![0x30, 0x59]);
        let mut off_curve = generator_spki().as_ref().to_vec();
        off_curve[30] ^= 0x01;
        let cases: Vec<Vec<CertificateDer<'static>>> = vec![
            Vec::new(),
            vec![generator_spki(), generator_spki()],
            vec![short],
            vec![CertificateDer::from(off_curve)],
        ];
        for presented in cases {
            let err = ChannelDerivedIdentity
                .identify(&presented)
                .expect_err("refused");
            assert_eq!(err.code().as_str(), "CONTROL.HANDSHAKE_REJECTED");
        }
    }

    #[test]
    fn a_generation_zero_identity_is_its_own_device_id() {
        // identifiers.md §2: "The generation-0 `identity_id` IS the
        // `device_id`." This is the property that makes a miss in the device
        // table safe to answer with the derived value: the key can speak for
        // that name and for no other.
        let peer = ChannelDerivedIdentity
            .peer_of(&[generator_spki()])
            .expect("derives");
        let identity =
            twinvpn_crypto::derive_identity_id_checked(&peer.identity_cose_key).expect("derives");
        let device =
            twinvpn_crypto::derive_device_id_checked(&peer.identity_cose_key).expect("derives");
        assert_eq!(identity.to_array(), device.to_array());
    }
}
