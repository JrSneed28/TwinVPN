//! The Noise handshake prologue — ADR-0001 §7.3.1, normative and owned by that
//! ADR alone.
//!
//! **Authority:** ADR-0001 §7.3.1 P-1..P-4, ADR-0001 §7.3 D1..D6, ADR-0007 N-20,
//! ADR-0014 N-6.
//!
//! # The field, quoted
//!
//! ```text
//! identity_binding_hash = SHA-256( "TWINVPN-IDBIND-v1"
//!                                || twinnet_id(16)
//!                                || device_id_init(32) || device_id_resp(32)
//!                                || trust_epoch(u64 BE) || psk_epoch(u64 BE)
//!                                || anchor_version(u32 BE)
//!                                || delegation_set_digest(32) )
//!
//! negotiation_hash      = SHA-256( "TWINVPN-NEG-v1"
//!                                || H_initiator || H_responder
//!                                || det_CBOR(Selection) )
//!
//! prologue              = "TWINVPN-PROLOGUE-v1"
//!                                || identity_binding_hash
//!                                || negotiation_hash          # 19 + 32 + 32 = 83 bytes
//! ```
//!
//! **P-1**: "The `prologue` MUST be exactly the 83-byte concatenation above. No
//! other document may define, extend, or reorder it." So [`Prologue`] is a
//! `[u8; 83]` newtype with exactly one constructor, and the two halves are
//! separate types that cannot be swapped for one another.
//!
//! **P-2**: the S-37 monotone floor is a *negotiation* input carried inside
//! `Selection`, under `negotiation_hash`. It has no field in
//! [`IdentityBinding`], and there is nowhere to put one.
//!
//! **P-3**: the prologue is never transmitted. A mismatch is observationally a
//! handshake failure like any other. Nothing a peer must *observe* may ride on
//! it — `trust_epoch` gossip and unexpected-delegation detection use the
//! in-session `TrustEpochAssert`, not this.
//!
//! # `twinnet_id(16)` — a contract tension, resolved and reported
//!
//! §7.3.1 writes `twinnet_id(16)`, a sixteen-byte field. `contracts/` declares
//! `twinnet_id` as a **`tstr .size (1..64)`** (`signed_statements.cddl`) and as
//! a `string` in every `.proto`. Sixty-four bytes of text does not fit sixteen.
//!
//! This module resolves it the only way that is both deterministic and
//! length-safe: [`TwinnetTag`] is `SHA-256(twinnet_id_utf8)[0..16]`, a
//! **contraction of the frozen identifier**, never a truncation of its text —
//! truncating text would let two `TwinNet`s sharing a 16-byte prefix collide,
//! which is exactly the identifier-truncation defect `identifiers.md` §5
//! forbids. The choice is documented as a decision taken here and reported to
//! the integration lead as an ADR-0001 §7.3.1 / contract-set inconsistency, not
//! presented as a reading of the ADR.

use crate::kdf::{sha256, sha256_parts};

/// `identity_binding_hash`'s domain label, verbatim from §7.3.1.
pub const IDBIND_LABEL: &[u8] = b"TWINVPN-IDBIND-v1";
/// `negotiation_hash`'s domain label, verbatim from §7.3.1.
pub const NEG_LABEL: &[u8] = b"TWINVPN-NEG-v1";
/// The prologue's own label, verbatim from §7.3.1. Nineteen bytes.
pub const PROLOGUE_LABEL: &[u8] = b"TWINVPN-PROLOGUE-v1";

/// The prologue's exact length: `19 + 32 + 32`.
pub const PROLOGUE_LEN: usize = 83;

/// The sixteen-byte `twinnet_id` contraction §7.3.1's field width requires.
///
/// See the module documentation: this is `SHA-256(twinnet_id)[0..16]`, not the
/// first sixteen bytes of the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TwinnetTag([u8; 16]);

impl TwinnetTag {
    /// Contracts a `twinnet_id` to the sixteen bytes §7.3.1 mixes in.
    #[must_use]
    pub fn from_twinnet_id(twinnet_id: &str) -> Self {
        let d = sha256(twinnet_id.as_bytes());
        let mut out = [0u8; 16];
        out.copy_from_slice(&d[..16]);
        Self(out)
    }

    /// The sixteen bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// The inputs ADR-0007 N-20 contributes to the prologue.
///
/// Every field is required, and there is no `Default`: a prologue assembled with
/// a forgotten `trust_epoch` would agree with a peer that also forgot it, which
/// is a downgrade that succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityBinding {
    /// `twinnet_id(16)`.
    pub twinnet: TwinnetTag,
    /// `device_id_init(32)` — the **initiator's**, whichever end is computing.
    pub device_id_init: [u8; 32],
    /// `device_id_resp(32)` — the **responder's**.
    pub device_id_resp: [u8; 32],
    /// `trust_epoch(u64 BE)` — S-03's totally ordered revocation epoch.
    pub trust_epoch: u64,
    /// `psk_epoch(u64 BE)` — the epoch of the `TwinNetPSK` in the `psk2` slot.
    pub psk_epoch: u64,
    /// `anchor_version(u32 BE)` — the pinned `OwnerTrustAnchor`'s version.
    pub anchor_version: u32,
    /// `delegation_set_digest(32)` — a digest over the pinned delegation set.
    pub delegation_set_digest: [u8; 32],
}

impl IdentityBinding {
    /// `identity_binding_hash`, exactly as §7.3.1 writes it.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        sha256_parts(&[
            IDBIND_LABEL,
            self.twinnet.as_bytes(),
            &self.device_id_init,
            &self.device_id_resp,
            &self.trust_epoch.to_be_bytes(),
            &self.psk_epoch.to_be_bytes(),
            &self.anchor_version.to_be_bytes(),
            &self.delegation_set_digest,
        ])
    }
}

/// The inputs ADR-0014 N-6 contributes to the prologue.
///
/// `selection_dcbor` is `det_CBOR(Selection)`. This crate does not model
/// `Selection` — ADR-0014 owns it, and `twinvpn-tunnel` drives the negotiation —
/// so the bytes arrive already deterministically encoded. What this crate owns
/// is that they are *bound*, and [`crate::dcbor::require_canonical`] is
/// available to a caller that wants to assert the encoding before mixing it in.
///
/// **P-2**: the S-37 floor rides inside `Selection`, here, and not in
/// [`IdentityBinding`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationBinding {
    /// `H_initiator` — the initiator's advertisement digest.
    pub h_initiator: [u8; 32],
    /// `H_responder` — the responder's advertisement digest.
    pub h_responder: [u8; 32],
    /// `det_CBOR(Selection)`.
    pub selection_dcbor: Vec<u8>,
}

impl NegotiationBinding {
    /// `negotiation_hash`, exactly as §7.3.1 writes it.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        sha256_parts(&[
            NEG_LABEL,
            &self.h_initiator,
            &self.h_responder,
            &self.selection_dcbor,
        ])
    }
}

/// The 83-byte prologue.
///
/// The single constructor takes both halves, so there is no way to build a
/// prologue that binds identity without binding negotiation, or the reverse —
/// which is P-1 made structural rather than documented.
#[derive(Clone, PartialEq, Eq)]
pub struct Prologue([u8; PROLOGUE_LEN]);

impl Prologue {
    /// Assembles the prologue from its two contributed digests.
    #[must_use]
    pub fn new(identity: &IdentityBinding, negotiation: &NegotiationBinding) -> Self {
        let mut out = [0u8; PROLOGUE_LEN];
        out[..19].copy_from_slice(PROLOGUE_LABEL);
        out[19..51].copy_from_slice(&identity.hash());
        out[51..83].copy_from_slice(&negotiation.hash());
        Self(out)
    }

    /// The bytes, for `snow`'s `Builder::prologue`.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PROLOGUE_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for Prologue {
    /// The prologue is not secret — P-3 says it is never transmitted, not that
    /// it is confidential — but it is 83 bytes of hash and rendering it in a log
    /// is noise. The length is the useful fact.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Prologue(<{PROLOGUE_LEN} B>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident() -> IdentityBinding {
        IdentityBinding {
            twinnet: TwinnetTag::from_twinnet_id("tn-example"),
            device_id_init: [0x01; 32],
            device_id_resp: [0x02; 32],
            trust_epoch: 4,
            psk_epoch: 9,
            anchor_version: 3,
            delegation_set_digest: [0x03; 32],
        }
    }

    fn nego() -> NegotiationBinding {
        NegotiationBinding {
            h_initiator: [0x04; 32],
            h_responder: [0x05; 32],
            selection_dcbor: vec![0xa0],
        }
    }

    /// P-1: exactly 83 bytes, with the label first and the two digests in the
    /// declared order.
    #[test]
    fn the_prologue_is_exactly_the_83_byte_concatenation() {
        let i = ident();
        let n = nego();
        let p = Prologue::new(&i, &n);
        let b = p.as_bytes();
        assert_eq!(b.len(), 83);
        assert_eq!(&b[..19], PROLOGUE_LABEL);
        assert_eq!(&b[19..51], &i.hash());
        assert_eq!(&b[51..83], &n.hash());
        assert_eq!(PROLOGUE_LABEL.len(), 19);
    }

    /// The two halves are not interchangeable: swapping them changes the
    /// prologue, so an implementation that reordered them would not interoperate
    /// rather than silently agreeing.
    #[test]
    fn the_two_digests_are_not_reorderable() {
        let i = ident();
        let n = nego();
        let p = Prologue::new(&i, &n);
        let mut swapped = [0u8; PROLOGUE_LEN];
        swapped[..19].copy_from_slice(PROLOGUE_LABEL);
        swapped[19..51].copy_from_slice(&n.hash());
        swapped[51..83].copy_from_slice(&i.hash());
        assert_ne!(p.as_bytes(), &swapped);
    }

    /// **Attack test.** An on-path adversary that could suppress the
    /// `trust_epoch` contribution would let a device at a stale epoch complete a
    /// handshake with one that has advanced. Every identity field must move the
    /// hash.
    #[test]
    fn every_identity_field_changes_the_binding_hash() {
        let base = ident().hash();
        let mut v = ident();
        v.trust_epoch += 1;
        assert_ne!(v.hash(), base, "trust_epoch is not bound");
        let mut v = ident();
        v.psk_epoch += 1;
        assert_ne!(v.hash(), base, "psk_epoch is not bound");
        let mut v = ident();
        v.anchor_version += 1;
        assert_ne!(v.hash(), base, "anchor_version is not bound");
        let mut v = ident();
        v.delegation_set_digest[0] ^= 1;
        assert_ne!(v.hash(), base, "delegation_set_digest is not bound");
        let mut v = ident();
        v.twinnet = TwinnetTag::from_twinnet_id("tn-other");
        assert_ne!(v.hash(), base, "twinnet_id is not bound");
        let mut v = ident();
        v.device_id_init[0] ^= 1;
        assert_ne!(v.hash(), base, "device_id_init is not bound");
        let mut v = ident();
        v.device_id_resp[0] ^= 1;
        assert_ne!(v.hash(), base, "device_id_resp is not bound");
    }

    /// **Attack test.** Reflecting the initiator's role onto the responder must
    /// not produce the same binding: the two `device_id` slots are positional,
    /// and an implementation that sorted them would let a reflection attack
    /// agree on the prologue.
    #[test]
    fn the_initiator_and_responder_slots_are_positional_not_sorted() {
        let a = ident();
        let mut b = ident();
        core::mem::swap(&mut b.device_id_init, &mut b.device_id_resp);
        assert_ne!(a.hash(), b.hash());
    }

    /// **Attack test.** D2's transcript: changing the selected negotiation
    /// result must change the prologue, so a tampered `Selection` fails the
    /// handshake rather than being confirmed.
    #[test]
    fn a_tampered_selection_changes_the_negotiation_hash() {
        let base = nego().hash();
        let mut v = nego();
        v.selection_dcbor = vec![0xa1, 0x01, 0x02];
        assert_ne!(v.hash(), base);
        let mut v = nego();
        v.h_initiator[0] ^= 1;
        assert_ne!(v.hash(), base);
        let mut v = nego();
        v.h_responder[0] ^= 1;
        assert_ne!(v.hash(), base);
    }

    /// The `twinnet_id` contraction must not be a text truncation: two ids
    /// sharing a long prefix must contract differently.
    #[test]
    fn the_twinnet_tag_contracts_rather_than_truncates() {
        let long_a = "a".repeat(40) + "one";
        let long_b = "a".repeat(40) + "two";
        assert_ne!(
            TwinnetTag::from_twinnet_id(&long_a),
            TwinnetTag::from_twinnet_id(&long_b),
            "a text truncation would have collided these"
        );
        // And it is the digest prefix, not the text prefix.
        let tag = TwinnetTag::from_twinnet_id("tn-example");
        assert_ne!(&tag.as_bytes()[..2], b"tn");
    }

    #[test]
    fn debug_does_not_dump_83_bytes_of_hash() {
        let p = Prologue::new(&ident(), &nego());
        assert_eq!(format!("{p:?}"), "Prologue(<83 B>)");
    }
}
