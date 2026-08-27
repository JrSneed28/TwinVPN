//! The `RelayEpochFloor` — Owner-signed, monotone, and learnable from a client.
//!
//! ADR-0005 §11.3, "Revocation and S-03":
//!
//! > The relay holds an Owner-signed, monotone `RelayEpochFloor` document. It is
//! > pushed by the control plane best-effort **and may be piggybacked by any
//! > connecting client** — because it is Owner-signed and monotone, a relay
//! > partitioned from the control plane still learns of revocations from its own
//! > users.
//!
//! Three properties this module enforces, in this order:
//!
//! 1. **Owner-signed.** An advance is applied only when the injected verifier
//!    accepts the signature under a held issuer key. With the fail-closed default
//!    provider, *no* advance is ever applied — which is safe, because failing to
//!    advance can only make the relay more permissive about *stale* tokens, and
//!    ADR-0005 §11.3 is explicit that "relay denial is defence in depth only":
//!    revocation is enforced at the peer, so a lagging floor leaks no access and
//!    no confidentiality.
//! 2. **Monotone.** A lower or equal epoch is refused. This is what makes it safe
//!    to accept the document from an untrusted courier (a connecting client): a
//!    client can only ever push the floor *up*.
//! 3. **A higher epoch always wins** (S-30 "on conflict"), and a token whose
//!    `epoch` is below the floor MUST NOT be used.
//!
//! S-30's replica column also says the *device* holds its token durably. The
//! relay holds only the floor, and even that "is re-obtainable from any
//! connecting client, so even that is not strictly durable" (§10).

use crate::crypto::RelayCrypto;
use crate::issuer::IssuerKeySet;

/// A signed epoch-floor advance, exactly as it arrived.
#[derive(Debug, Clone)]
pub struct SignedEpochFloor {
    /// The `iss` key id whose key must verify the document.
    pub issuer_key_id: String,
    /// The canonical bytes that were signed. Forwarded and verified verbatim —
    /// never decoded and re-encoded (W-4).
    pub signed_bytes: Vec<u8>,
    /// The detached signature.
    pub signature: Vec<u8>,
    /// The epoch the document asserts, read from the signed bytes by the caller
    /// that parsed them. Trusted only after [`EpochFloor::advance`] verifies.
    pub epoch: u64,
}

/// Why an advance was not applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvanceRejected {
    /// The named issuer is not in the held key set — including the empty set.
    IssuerUnknown,
    /// The signature did not verify under the held key.
    SignatureInvalid,
    /// The document's epoch is not strictly greater than the current floor.
    NotMonotone,
}

/// The relay's current trust-epoch floor.
#[derive(Debug, Clone, Copy, Default)]
pub struct EpochFloor {
    current: u64,
    advances_applied: u64,
    advances_refused: u64,
}

impl EpochFloor {
    /// A floor starting at `epoch`.
    #[must_use]
    pub const fn starting_at(epoch: u64) -> Self {
        Self {
            current: epoch,
            advances_applied: 0,
            advances_refused: 0,
        }
    }

    /// The current floor. A token with `epoch < current` MUST NOT be used.
    #[must_use]
    pub const fn current(&self) -> u64 {
        self.current
    }

    /// How many advances were applied, and how many refused. Counters only —
    /// there is no per-device or per-flow dimension here.
    #[must_use]
    pub const fn counters(&self) -> (u64, u64) {
        (self.advances_applied, self.advances_refused)
    }

    /// Applies a signed advance, if it verifies and is strictly higher.
    ///
    /// # Errors
    ///
    /// [`AdvanceRejected`] for an unknown issuer, a bad signature, or a
    /// non-increasing epoch.
    pub fn advance(
        &mut self,
        doc: &SignedEpochFloor,
        keys: &IssuerKeySet,
        crypto: &dyn RelayCrypto,
    ) -> Result<u64, AdvanceRejected> {
        // Monotonicity is checked FIRST, before any signature verification, so a
        // flood of stale documents from an unauthenticated source costs no
        // asymmetric operation (ADR-0005 §11.5's amplification discipline).
        if doc.epoch <= self.current {
            self.advances_refused = self.advances_refused.saturating_add(1);
            return Err(AdvanceRejected::NotMonotone);
        }
        let Some(key) = keys.find(&doc.issuer_key_id) else {
            self.advances_refused = self.advances_refused.saturating_add(1);
            return Err(AdvanceRejected::IssuerUnknown);
        };
        if !crypto.verify_signature(key, &doc.signed_bytes, &doc.signature) {
            self.advances_refused = self.advances_refused.saturating_add(1);
            return Err(AdvanceRejected::SignatureInvalid);
        }
        self.current = doc.epoch;
        self.advances_applied = self.advances_applied.saturating_add(1);
        Ok(self.current)
    }

    /// Whether a token's epoch clears the floor (ADR-0005 §11.3).
    #[must_use]
    pub const fn admits(&self, token_epoch: u64) -> bool {
        token_epoch >= self.current
    }

    /// Whether a token's epoch is **equal** to the floor — the proof that no
    /// revocation intervened, and rule 1 of relay-issued renewal (§11.3).
    #[must_use]
    pub const fn permits_relay_renewal(&self, token_epoch: u64) -> bool {
        token_epoch == self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{FailClosed, IssuerPublicKey, LegKey};

    struct AlwaysVerifies;
    impl RelayCrypto for AlwaysVerifies {
        fn verify_signature(&self, _: &IssuerPublicKey, _: &[u8], _: &[u8]) -> bool {
            true
        }
        fn verify_frame_mac(&self, _: &LegKey, _: &[u8], _: [u8; 8]) -> bool {
            true
        }
        fn frame_mac(&self, _: &LegKey, _: &[u8]) -> Option<[u8; 8]> {
            Some([0; 8])
        }
        fn digest16(&self, _: &[u8], _: &[u8]) -> Option<[u8; 16]> {
            Some([0; 16])
        }
    }

    fn keys(populated: bool) -> IssuerKeySet {
        let raw = if populated {
            r#"{"operator_group_id":"g","issuers":[{"key_id":"k1","alg":"Ed25519","public_key_hex":"00"}]}"#
        } else {
            r#"{"operator_group_id":"g","issuers":[]}"#
        };
        IssuerKeySet::parse(raw, "g", "x").expect("parses")
    }

    fn doc(epoch: u64) -> SignedEpochFloor {
        SignedEpochFloor {
            issuer_key_id: "k1".into(),
            signed_bytes: b"canonical".to_vec(),
            signature: b"sig".to_vec(),
            epoch,
        }
    }

    #[test]
    fn a_higher_epoch_wins() {
        let mut f = EpochFloor::starting_at(4);
        assert_eq!(f.advance(&doc(9), &keys(true), &AlwaysVerifies), Ok(9));
        assert_eq!(f.current(), 9);
    }

    #[test]
    fn a_lower_or_equal_epoch_is_refused_so_a_courier_cannot_roll_it_back() {
        let mut f = EpochFloor::starting_at(9);
        assert_eq!(
            f.advance(&doc(8), &keys(true), &AlwaysVerifies),
            Err(AdvanceRejected::NotMonotone)
        );
        assert_eq!(
            f.advance(&doc(9), &keys(true), &AlwaysVerifies),
            Err(AdvanceRejected::NotMonotone)
        );
        assert_eq!(f.current(), 9);
    }

    #[test]
    fn an_empty_issuer_set_applies_no_advance() {
        let mut f = EpochFloor::starting_at(1);
        assert_eq!(
            f.advance(&doc(5), &keys(false), &AlwaysVerifies),
            Err(AdvanceRejected::IssuerUnknown)
        );
        assert_eq!(f.current(), 1);
    }

    #[test]
    fn the_fail_closed_provider_applies_no_advance() {
        let mut f = EpochFloor::starting_at(1);
        assert_eq!(
            f.advance(&doc(5), &keys(true), &FailClosed),
            Err(AdvanceRejected::SignatureInvalid)
        );
        assert_eq!(f.current(), 1);
    }

    #[test]
    fn a_token_below_the_floor_is_not_admitted() {
        let f = EpochFloor::starting_at(7);
        assert!(!f.admits(6));
        assert!(f.admits(7));
        assert!(f.admits(8));
    }

    #[test]
    fn relay_renewal_needs_epoch_equality_not_merely_sufficiency() {
        let f = EpochFloor::starting_at(7);
        assert!(f.permits_relay_renewal(7));
        assert!(
            !f.permits_relay_renewal(8),
            "a higher epoch is not proof that no revocation intervened at 7"
        );
        assert!(!f.permits_relay_renewal(6));
    }

    #[test]
    fn a_stale_document_costs_no_signature_verification() {
        // The monotonicity check runs first: with a verifier that would accept
        // anything, a stale document is still refused as NotMonotone, which is
        // the ordering the amplification discipline needs.
        let mut f = EpochFloor::starting_at(9);
        assert_eq!(
            f.advance(&doc(1), &keys(true), &AlwaysVerifies),
            Err(AdvanceRejected::NotMonotone)
        );
        assert_eq!(f.counters(), (0, 1));
    }
}
