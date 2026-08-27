//! `TwinNetPSK(A, B, epoch)` — the `psk2` slot, and the one TwinVPN-designed
//! derivation.
//!
//! **Authority:** ADR-0001 §7.5 and §11 item 7, ADR-0007 §7.7 (which *corrects*
//! an earlier form of §7.5's paragraph and is therefore the operative text for
//! the inputs), `docs/architecture.md` S-33.
//!
//! # The derivation, and why each half is there
//!
//! ADR-0001 §7.5, as corrected by ADR-0007 §7.7:
//!
//! > `TwinNetPSK(A,B,epoch) = HKDF-SHA-256( ikm = PairSecret(A,B) ||
//! > EpochSeed(epoch), … )` — derived from the **pairwise** `PairSecret` plus an
//! > `Owner`-generated, per-device-HPKE-sealed `EpochSeed`.
//!
//! The ADR then states, in the same paragraph, exactly why the shape is not
//! negotiable:
//!
//! > "The distinction is load-bearing: derived from a *`TwinNet`-wide* secret the
//! > PSK epoch would **not** be a revocation lever, because a revoked device
//! > would know that secret and could derive every later epoch's PSK. Derived
//! > pairwise, plus a seed it is not sealed a copy of, it is — the revoked device
//! > is simply not a recipient of `EpochSeed(epoch+1)`."
//!
//! So the type here takes **both** halves and there is no constructor taking one:
//! a `TwinNetPsk` that could be derived from a `TwinNet`-wide value alone would
//! be a PSK whose epoch is not a revocation lever, which is R13 silently lost.
//!
//! # What this module does *not* fix, and says so
//!
//! ADR-0001 §7.5 writes the derivation with an ellipsis — `HKDF-SHA-256( ikm =
//! …, ... )` — and neither ADR fixes the `salt` or the `info`. This module
//! chooses them, documents the choice as a *decision made here*, and pins it with
//! a vector so it cannot drift silently. It is reported to the integration lead
//! as an under-specification in ADR-0001 §7.5 rather than being presented as a
//! reading of text that does not exist. See [`PSK_INFO_PREFIX`].

use crate::kdf::hkdf_sha256;
use crate::locked::LockedBytes;
use crate::{CryptoError, Result};

/// The `psk2` slot's width, fixed by Noise (`PSKLEN`).
pub const PSK_LEN: usize = 32;

/// The domain-separation label for the `TwinNetPSK` derivation.
///
/// **A decision taken in this module, not a quotation.** ADR-0001 §7.5 writes
/// the `info` as an ellipsis. The value is chosen to be versioned (`/v1`), to
/// name the derivation rather than the protocol, and to be unmistakable in a
/// hexdump; the *epoch* and the two `device_id`s are appended to it by
/// [`TwinNetPsk::derive`] so that a PSK is bound to the ordered pair and the
/// epoch it claims to be for, not merely derived from inputs that happen to
/// include them.
pub const PSK_INFO_PREFIX: &[u8] = b"TWINVPN-TWINNETPSK-v1";

/// The salt for the `TwinNetPSK` extraction.
///
/// Also a decision taken here. A `TwinNet`-scoped salt would be tempting, but
/// `twinnet_id` is a `tstr` of unbounded shape and putting a variable-width
/// value in the salt while fixed-width values sit in the `info` is how two
/// implementations of the same spec disagree. The salt is the RFC 5869 §2.2
/// "not provided" case; every distinguishing input is in the `info`, where it is
/// length-disciplined.
const PSK_SALT: Option<&[u8]> = None;

/// A `TwinNetPSK` for one ordered peer pair at one epoch.
///
/// Held in [`LockedBytes`]: it is a symmetric secret that, combined with an
/// extracted static, completes a handshake. It is not one of CB-5's two
/// core-held *key* rows — it is derived material with the same lifetime as the
/// session state around it — but it gets the same custody, because there is no
/// reason for it to be weaker than the `TK` it sits beside.
pub struct TwinNetPsk {
    bytes: LockedBytes,
    epoch: u64,
}

impl TwinNetPsk {
    /// Derives `TwinNetPSK(local, remote, epoch)`.
    ///
    /// `pair_secret` is the pairwise `PairSecret` established by the pairing
    /// ceremony (ADR-0007 N-19: it "MUST NOT be transmitted, backed up, or
    /// replicated"). `epoch_seed` is the plaintext `EpochSeed` for `epoch`,
    /// which reaches the device only as an HPKE seal addressed to it (S-33) and
    /// which this crate therefore receives already opened by the caller.
    ///
    /// # The pair is ordered, and ordered canonically
    ///
    /// Both peers must derive the same PSK, so the two `device_id`s are folded
    /// in **sorted**, not in local-then-remote order. Getting this wrong
    /// produces two devices that each derive a different PSK and a handshake
    /// failure that looks like a key problem and is a byte-order problem; it is
    /// asserted by [`tests::both_peers_derive_the_same_psk`].
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyLength`] if `pair_secret` or `epoch_seed` is empty —
    /// an empty half is the shape a caller that forgot to open the seal would
    /// produce, and deriving from it would silently yield a PSK that is a pure
    /// function of the other half.
    pub fn derive(
        pair_secret: &[u8],
        epoch_seed: &[u8],
        epoch: u64,
        device_a: &[u8; 32],
        device_b: &[u8; 32],
    ) -> Result<Self> {
        if pair_secret.is_empty() {
            return Err(CryptoError::KeyLength {
                expected: 1,
                observed: 0,
            });
        }
        if epoch_seed.is_empty() {
            return Err(CryptoError::KeyLength {
                expected: 1,
                observed: 0,
            });
        }

        // ikm = PairSecret(A,B) || EpochSeed(epoch), exactly as ADR-0007 §7.7
        // writes it. Both halves are fixed-purpose and the concatenation is
        // unambiguous because `info` carries the epoch that selects the seed.
        let mut ikm = Vec::with_capacity(pair_secret.len() + epoch_seed.len());
        ikm.extend_from_slice(pair_secret);
        ikm.extend_from_slice(epoch_seed);

        let (lo, hi) = if device_a <= device_b {
            (device_a, device_b)
        } else {
            (device_b, device_a)
        };
        let mut info = Vec::with_capacity(PSK_INFO_PREFIX.len() + 8 + 64);
        info.extend_from_slice(PSK_INFO_PREFIX);
        info.extend_from_slice(&epoch.to_be_bytes());
        info.extend_from_slice(lo);
        info.extend_from_slice(hi);

        let mut derived = [0u8; PSK_LEN];
        let outcome = hkdf_sha256(PSK_SALT, &ikm, &info, &mut derived);
        // The intermediate `ikm` held the pairwise secret; erase it before any
        // early return can skip the erase.
        zeroize::Zeroize::zeroize(&mut ikm);
        outcome?;

        let bytes = LockedBytes::new_with(PSK_LEN, |dst| dst.copy_from_slice(&derived));
        zeroize::Zeroize::zeroize(&mut derived);
        Ok(Self {
            bytes: bytes?,
            epoch,
        })
    }

    /// The epoch this PSK belongs to.
    ///
    /// Not secret, and load-bearing: a peer refuses a handshake whose PSK epoch
    /// is below its `min_acceptable_epoch`, which is the second revocation lever
    /// (ADR-0001 §7.5 item 2).
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The 32 bytes, for the `psk2` slot.
    ///
    /// Named for its one destination. `snow`'s `Builder::psk` takes a
    /// `&[u8; 32]`, and [`Self::as_psk_array`] is what feeds it.
    #[must_use]
    pub fn as_psk_array(&self) -> [u8; PSK_LEN] {
        let mut out = [0u8; PSK_LEN];
        out.copy_from_slice(self.bytes.expose());
        out
    }
}

impl core::fmt::Debug for TwinNetPsk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TwinNetPsk")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 32] = [0x11; 32];
    const B: [u8; 32] = [0x22; 32];

    fn hex_of(bytes: &[u8; 32]) -> String {
        use core::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    fn derive(pair: &[u8], seed: &[u8], epoch: u64, x: &[u8; 32], y: &[u8; 32]) -> [u8; 32] {
        TwinNetPsk::derive(pair, seed, epoch, x, y)
            .expect("derive")
            .as_psk_array()
    }

    /// Both ends of the pair must derive the same PSK regardless of which of
    /// them is calling. A mismatch here is a handshake failure that looks like a
    /// key problem.
    #[test]
    fn both_peers_derive_the_same_psk() {
        let ab = derive(b"pair-secret", b"epoch-seed", 7, &A, &B);
        let ba = derive(b"pair-secret", b"epoch-seed", 7, &B, &A);
        assert_eq!(ab, ba);
    }

    /// **The revocation lever, as an attack test.** A device that holds the
    /// `PairSecret` but was not sealed `EpochSeed(epoch+1)` must not be able to
    /// derive the next epoch's PSK. Concretely: changing only the seed changes
    /// the PSK, so knowledge of the pairwise half is not sufficient.
    #[test]
    fn a_revoked_device_holding_only_the_pair_secret_cannot_derive_the_next_epoch() {
        let current = derive(b"pair-secret", b"epoch-seed-7", 7, &A, &B);
        // The revoked device knows `PairSecret` and knows the epoch advanced. It
        // does not hold `EpochSeed(8)`, so the best it can do is guess.
        let guessed = derive(b"pair-secret", b"epoch-seed-7", 8, &A, &B);
        let real = derive(b"pair-secret", b"epoch-seed-8", 8, &A, &B);
        assert_ne!(
            guessed, real,
            "advancing the epoch alone must not derive the new PSK"
        );
        assert_ne!(current, real);
    }

    /// **The reason the derivation is pairwise, as an attack test.** If the PSK
    /// were a function of a `TwinNet`-wide secret, every pair in the TwinNet
    /// would share it and a revoked device would hold every other pair's key.
    /// Two different pairs at the same epoch with the same seed must differ.
    #[test]
    fn two_different_pairs_at_one_epoch_derive_different_psks() {
        let first_pair = derive(b"pair-secret-ab", b"seed", 3, &A, &B);
        let second_pair = derive(b"pair-secret-ac", b"seed", 3, &A, &[0x33; 32]);
        assert_ne!(first_pair, second_pair);
    }

    /// The epoch is bound into the derivation, not merely recorded beside it.
    #[test]
    fn the_epoch_is_an_input_to_the_derivation() {
        let e7 = derive(b"pair", b"seed", 7, &A, &B);
        let e8 = derive(b"pair", b"seed", 8, &A, &B);
        assert_ne!(e7, e8);
    }

    /// The identities are bound in, so a PSK derived for one pair cannot be
    /// replayed into a handshake with a third device.
    #[test]
    fn the_pair_identities_are_bound_into_the_derivation() {
        let ab = derive(b"pair", b"seed", 1, &A, &B);
        let ac = derive(b"pair", b"seed", 1, &A, &[0x33; 32]);
        assert_ne!(ab, ac);
    }

    /// An empty half is refused rather than silently producing a PSK that is a
    /// function of the other half alone — the shape a caller that forgot to open
    /// the HPKE seal would produce.
    #[test]
    fn an_empty_half_is_refused() {
        assert!(TwinNetPsk::derive(b"", b"seed", 1, &A, &B).is_err());
        assert!(TwinNetPsk::derive(b"pair", b"", 1, &A, &B).is_err());
    }

    #[test]
    fn the_derivation_is_pinned_so_it_cannot_drift_silently() {
        // ikm  = "pair-secret" || "epoch-seed"
        // info = "TWINVPN-TWINNETPSK-v1" || be64(7) || 0x11*32 || 0x22*32
        // salt = absent (RFC 5869 §2.2 all-zero)
        let psk = derive(b"pair-secret", b"epoch-seed", 7, &A, &B);
        let hex = hex_of(&psk);
        assert_eq!(
            hex, "9aaf4ae67d6b0ffe29ac96f94aa758af4afc0e19bad5de9b136a693f3adc0514",
            "the TwinNetPSK derivation moved; every paired device would have to \
             re-derive, which is a fleet-wide compatibility event"
        );
    }

    #[test]
    fn debug_never_renders_the_secret() {
        let psk = TwinNetPsk::derive(b"pair", b"seed", 5, &A, &B).expect("derive");
        let rendered = format!("{psk:?}");
        assert!(rendered.contains("epoch: 5"));
        let hex = hex_of(&psk.as_psk_array());
        assert!(!rendered.contains(&hex[..8]));
    }
}
