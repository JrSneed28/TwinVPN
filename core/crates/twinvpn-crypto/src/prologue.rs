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
//!
//! ## The contraction belongs here and **only** here
//!
//! There are two places in the corpus where a `twinnet_id` is mixed into a
//! cryptographic input, and they need opposite treatment:
//!
//! | Use | Shape | Contract? |
//! |---|---|---|
//! | §7.3.1's `identity_binding_hash` — **this module** | one field in a SHA-256 preimage of **concatenated fixed-width fields**, declared `twinnet_id(16)` | **Yes.** A variable-length value here would make the preimage's field boundaries ambiguous, and the ADR fixes the width at sixteen |
//! | ADR-0007 §7.7's `TwinNetPSK` salt — [`crate::psk::psk_salt`] | `salt = twinnet_id \|\| e (u64 BE)`, and HKDF's salt is **variable-length by construction** (RFC 5869 §2.2) | **No.** The raw UTF-8 bytes go in. Contracting would be a deviation from a fully specified derivation |
//!
//! The same identifier, two encodings, because the two contexts impose
//! different constraints. Applying this module's answer to the PSK salt would
//! break interoperability with a conforming implementation; applying the PSK
//! salt's answer here would break the prologue's field alignment.

use crate::kdf::{sha256, sha256_parts};
use crate::{CryptoError, Result};

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

    /// Adopts 83 bytes that were assembled elsewhere as the **same** normative
    /// field.
    ///
    /// # Why this exists
    ///
    /// P-1: "The `prologue` MUST be exactly the 83-byte concatenation above. **No
    /// other document may define, extend, or reorder it.**" One normative field,
    /// therefore one value — but until now there were two Rust *types* over it,
    /// `twinvpn_crypto::prologue::Prologue` and `twinvpn_tunnel::crypto::Prologue`,
    /// and **neither could be made from the other**: this one had no byte
    /// constructor, that one has no binding constructor. `twinvpn_tunnel::bind`
    /// bridged the gap by holding both and comparing them byte-for-byte on every
    /// trait call.
    ///
    /// That cross-check is sound and should stay — two independent constructions
    /// of the same 83 bytes agreeing is a real check, not a redundancy. What was
    /// wrong is that the two constructions were *independent* at all: two
    /// implementations of one normative field is the duplication P-1's last
    /// sentence forbids, and it is only a matter of time before one of them
    /// changes. With this constructor the tunnel-side value can be **derived**
    /// from this one (or the reverse), and a future integration can collapse the
    /// two types into one without touching a byte of the wire — because there is
    /// no wire: P-3 says the prologue "is never transmitted".
    ///
    /// # What is checked, and why that is all
    ///
    /// The 19-byte label, and nothing else. The remaining 64 bytes are two
    /// SHA-256 digests, and a digest is indistinguishable from any other 32
    /// bytes — there is no check to perform that would not amount to recomputing
    /// them, which is what [`Self::new`] is for. The label is the one part of the
    /// field whose absence is *detectable*, so it is detected: it catches a
    /// caller that swapped the two digest halves into the wrong offsets, or
    /// handed over 83 bytes that were never a prologue at all.
    ///
    /// [`Self::new`] remains the way a prologue is **built**. This is the way one
    /// already built is carried across a type boundary; it does not compute a
    /// prologue and cannot be used to skip the two bindings.
    ///
    /// # Errors
    ///
    /// [`CryptoError::HandshakeRejected`] if the bytes do not begin with
    /// [`PROLOGUE_LABEL`]. Handshake-shaped rather than a distinct code because
    /// P-3 wants a prologue disagreement to be "observationally
    /// indistinguishable from any other handshake failure".
    pub fn from_bytes(bytes: [u8; PROLOGUE_LEN]) -> Result<Self> {
        if &bytes[..PROLOGUE_LABEL.len()] != PROLOGUE_LABEL {
            return Err(CryptoError::HandshakeRejected {
                step: "prologue does not carry the §7.3.1 label",
            });
        }
        Ok(Self(bytes))
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

    /// The `twinnet_id` gets **two** encodings, and mixing them up breaks
    /// interoperability in one direction or field alignment in the other.
    ///
    /// The prologue needs the sixteen-byte contraction, because §7.3.1's
    /// preimage is a concatenation of fixed-width fields. ADR-0007 §7.7's PSK
    /// salt needs the raw bytes, because HKDF's salt is variable-length. This
    /// test pins the distinction so neither answer migrates to the other site.
    #[test]
    fn the_twinnet_contraction_is_for_the_prologue_and_not_for_the_psk_salt() {
        let id = "tn-example";
        // The prologue: exactly sixteen bytes, whatever the id's length.
        assert_eq!(TwinnetTag::from_twinnet_id(id).as_bytes().len(), 16);
        assert_eq!(
            TwinnetTag::from_twinnet_id(&"a".repeat(64))
                .as_bytes()
                .len(),
            16
        );
        // The PSK salt: the raw id, then the epoch. Not contracted.
        let salt = crate::psk::psk_salt(id, 7);
        assert_eq!(&salt[..id.len()], id.as_bytes());
        assert_eq!(salt.len(), id.len() + 8);
        // And the two are genuinely different values, so a call site that used
        // one where the other belongs would produce different key material
        // rather than accidentally agreeing.
        assert_ne!(&salt[..16], TwinnetTag::from_twinnet_id(id).as_bytes());
    }

    /// A prologue survives the round trip through its bytes unchanged, which is
    /// what makes "derive one type from the other" possible at all.
    #[test]
    fn a_prologue_round_trips_through_its_own_bytes() {
        let p = Prologue::new(&ident(), &nego());
        let q = Prologue::from_bytes(*p.as_bytes()).expect("round trip");
        assert_eq!(p, q);
        assert_eq!(p.as_bytes(), q.as_bytes());
    }

    /// **The R-31 point.** `twinvpn_tunnel::crypto::Prologue::new` assembles the
    /// same field from the two digests directly — `LABEL || h_id || h_neg` — and
    /// that is reproduced here byte for byte. [`Prologue::from_bytes`] must
    /// accept it and produce a value equal to the one this crate builds from the
    /// bindings themselves, because P-1 says there is only one such field.
    ///
    /// If this ever fails, the two types have diverged over a field no document
    /// is allowed to redefine — which is the whole reason the constructor
    /// exists.
    #[test]
    fn the_tunnel_sides_assembly_of_the_same_field_is_the_same_field() {
        let i = ident();
        let n = nego();

        // Exactly what `twinvpn_tunnel::crypto::Prologue::new` does, given the
        // two digests this crate computes.
        let mut assembled = [0u8; PROLOGUE_LEN];
        assembled[..19].copy_from_slice(PROLOGUE_LABEL);
        assembled[19..51].copy_from_slice(&i.hash());
        assembled[51..83].copy_from_slice(&n.hash());

        let derived = Prologue::from_bytes(assembled).expect("the tunnel side's bytes");
        assert_eq!(derived, Prologue::new(&i, &n));
    }

    /// Eighty-three bytes that never were a prologue are refused, so the
    /// constructor cannot become a way to bind nothing. The two digest halves
    /// cannot be checked — they are digests — but a caller that swapped them
    /// into the label's offsets is caught.
    #[test]
    fn eighty_three_bytes_without_the_label_are_not_a_prologue() {
        let err = Prologue::from_bytes([0u8; PROLOGUE_LEN]).expect_err("no label");
        assert!(matches!(err, CryptoError::HandshakeRejected { .. }));
        assert_eq!(err.reason_code().as_str(), "CRYPTO.HANDSHAKE_REJECTED");

        // One flipped bit in the label is still not the label.
        let p = Prologue::new(&ident(), &nego());
        let mut mangled = *p.as_bytes();
        mangled[0] ^= 1;
        assert!(Prologue::from_bytes(mangled).is_err());

        // And the label is checked at its own offsets, not searched for: the
        // digest halves rotated into the front are refused.
        let mut rotated = [0u8; PROLOGUE_LEN];
        rotated[..64].copy_from_slice(&p.as_bytes()[19..]);
        rotated[64..].copy_from_slice(&p.as_bytes()[..19]);
        assert!(Prologue::from_bytes(rotated).is_err());
    }

    #[test]
    fn debug_does_not_dump_83_bytes_of_hash() {
        let p = Prologue::new(&ident(), &nego());
        assert_eq!(format!("{p:?}"), "Prologue(<83 B>)");
    }
}
