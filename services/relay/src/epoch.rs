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

use crate::crypto::{RelayCrypto, Statement};
use crate::issuer::IssuerKeySet;

/// A signed epoch-floor advance, exactly as it arrived.
///
/// Two fields and no more: the `iss` hint needed to select a key, and the
/// COSE_Sign1 envelope verbatim. **The asserted epoch is deliberately absent** —
/// an earlier revision carried it here so the monotonicity check could run before
/// the signature, and that meant deciding on an attacker-supplied number. The
/// epoch is now read from the verified payload, like every other claim
/// (`relay.proto`: "read the claims FROM THE VERIFIED PAYLOAD").
#[derive(Debug, Clone)]
pub struct SignedEpochFloor {
    /// The `iss` key id whose key must verify the document. A key-selection hint.
    pub issuer_key_id: String,
    /// The COSE_Sign1 envelope, exactly as received. Verified verbatim; never
    /// decoded and re-encoded (W-4).
    pub cose_sign1: Vec<u8>,
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
    /// The floor is signed for a different operator group.
    WrongOperatorGroup,
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
        operator_group_id: &str,
    ) -> Result<u64, AdvanceRejected> {
        // The key lookup first: a map lookup, not an asymmetric operation, and an
        // empty key set refuses here without ever reaching the verifier.
        let Some(key) = keys.find(&doc.issuer_key_id) else {
            self.advances_refused = self.advances_refused.saturating_add(1);
            return Err(AdvanceRejected::IssuerUnknown);
        };
        // Then the Owner signature, over the received octets. Only after it does
        // any number in this document become something to reason about.
        let Some(verified) =
            crypto.verify_statement(key, Statement::RelayEpochFloor, &doc.cose_sign1)
        else {
            self.advances_refused = self.advances_refused.saturating_add(1);
            return Err(AdvanceRejected::SignatureInvalid);
        };
        let Some(claims) = verified.as_epoch_floor() else {
            self.advances_refused = self.advances_refused.saturating_add(1);
            return Err(AdvanceRejected::SignatureInvalid);
        };
        // A floor signed for another operator group admits nothing here, however
        // validly it is signed: `aud` scoping is what keeps one fleet's
        // revocations out of another's (ADR-0005 §10).
        if claims.operator_group_id != operator_group_id {
            self.advances_refused = self.advances_refused.saturating_add(1);
            return Err(AdvanceRejected::WrongOperatorGroup);
        }
        // Monotone, on the VERIFIED epoch. This is what makes it safe to accept
        // the document from an untrusted courier: a client can only push it up.
        if claims.epoch_floor <= self.current {
            self.advances_refused = self.advances_refused.saturating_add(1);
            return Err(AdvanceRejected::NotMonotone);
        }
        self.current = claims.epoch_floor;
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
    use crate::claims::{EpochFloorClaims, VerifiedClaims};
    use crate::crypto::{FailClosed, IssuerPublicKey, LegKey};

    /// Verifies any envelope beginning with `GOOD`, yielding `epoch` for `group`.
    struct Signed {
        epoch: u64,
        group: &'static str,
    }

    impl RelayCrypto for Signed {
        fn verify_statement(
            &self,
            _: &IssuerPublicKey,
            kind: Statement,
            envelope: &[u8],
        ) -> Option<VerifiedClaims> {
            if kind != Statement::RelayEpochFloor || !envelope.starts_with(b"GOOD") {
                return None;
            }
            Some(VerifiedClaims::EpochFloor(EpochFloorClaims {
                twinnet_id: "t".into(),
                operator_group_id: self.group.to_owned(),
                epoch_floor: self.epoch,
                not_after_ms: u64::MAX,
            }))
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

    fn signed(epoch: u64) -> Signed {
        Signed { epoch, group: "g" }
    }

    fn keys(populated: bool) -> IssuerKeySet {
        let raw = if populated {
            r#"{"operator_group_id":"g","issuers":[{"key_id":"k1","alg":"Ed25519","cose_key_hex":"00"}]}"#
        } else {
            r#"{"operator_group_id":"g","issuers":[]}"#
        };
        IssuerKeySet::parse(raw, "g", "x").expect("parses")
    }

    fn doc() -> SignedEpochFloor {
        SignedEpochFloor {
            issuer_key_id: "k1".into(),
            cose_sign1: b"GOOD-cose-sign1".to_vec(),
        }
    }

    #[test]
    fn a_higher_epoch_wins() {
        let mut f = EpochFloor::starting_at(4);
        assert_eq!(f.advance(&doc(), &keys(true), &signed(9), "g"), Ok(9));
        assert_eq!(f.current(), 9);
    }

    #[test]
    fn a_lower_or_equal_epoch_is_refused_so_a_courier_cannot_roll_it_back() {
        let mut f = EpochFloor::starting_at(9);
        for epoch in [8, 9, 0] {
            assert_eq!(
                f.advance(&doc(), &keys(true), &signed(epoch), "g"),
                Err(AdvanceRejected::NotMonotone)
            );
        }
        assert_eq!(f.current(), 9);
    }

    #[test]
    fn the_monotonicity_check_reads_the_verified_epoch_not_a_claimed_one() {
        // The document carries no epoch a caller could read: the only number
        // considered comes out of `verify_statement`. A courier that wanted to
        // roll the floor back would have to forge an Owner signature, not edit a
        // field. An earlier revision carried the epoch on the wire type so the
        // monotonicity check could run first — that meant deciding on an
        // attacker-supplied number, which relay.proto forbids.
        let d = doc();
        let rendered = format!("{d:?}");
        assert!(!rendered.contains("epoch"));
        assert!(rendered.contains("cose_sign1"));
    }

    #[test]
    fn an_empty_issuer_set_applies_no_advance() {
        let mut f = EpochFloor::starting_at(1);
        assert_eq!(
            f.advance(&doc(), &keys(false), &signed(5), "g"),
            Err(AdvanceRejected::IssuerUnknown)
        );
        assert_eq!(f.current(), 1);
    }

    #[test]
    fn the_fail_closed_provider_applies_no_advance() {
        let mut f = EpochFloor::starting_at(1);
        assert_eq!(
            f.advance(&doc(), &keys(true), &FailClosed, "g"),
            Err(AdvanceRejected::SignatureInvalid)
        );
        assert_eq!(f.current(), 1);
    }

    #[test]
    fn a_floor_signed_for_another_operator_group_is_refused() {
        // However validly signed: `aud` scoping keeps one fleet's revocations out
        // of another's, and an epoch floor is a revocation instrument.
        let mut f = EpochFloor::starting_at(1);
        let other = Signed {
            epoch: 99,
            group: "someone-else",
        };
        assert_eq!(
            f.advance(&doc(), &keys(true), &other, "g"),
            Err(AdvanceRejected::WrongOperatorGroup)
        );
        assert_eq!(f.current(), 1);
    }

    #[test]
    fn a_malformed_envelope_applies_no_advance() {
        let mut f = EpochFloor::starting_at(1);
        let bad = SignedEpochFloor {
            issuer_key_id: "k1".into(),
            cose_sign1: b"BAD".to_vec(),
        };
        assert_eq!(
            f.advance(&bad, &keys(true), &signed(9), "g"),
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
    fn every_refusal_is_counted_and_none_moves_the_floor() {
        let mut f = EpochFloor::starting_at(9);
        let _ = f.advance(&doc(), &keys(true), &signed(1), "g");
        let _ = f.advance(&doc(), &keys(false), &signed(99), "g");
        let _ = f.advance(&doc(), &keys(true), &FailClosed, "g");
        assert_eq!(f.counters(), (0, 3));
        assert_eq!(f.current(), 9);
    }
}
