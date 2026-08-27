//! Downgrade resistance — the transcript confirmation and the monotonic floor.
//!
//! **Authority:** ADR-0001 §7.3 D1–D6, §7.3.1 P-2 and P-4, §11 item 6,
//! ADR-0014 N-19/N-20, state row S-37, `contracts/proto/twinvpn/v1/peer.proto`
//! (`NegotiationFloor`).
//!
//! # The division of labour
//!
//! ADR-0001 §11 item 6 places the *requirement* on ADR-0014 and leaves the
//! *mechanism* here:
//!
//! > "Negotiation happens only inside the authenticated tunnel, with transcript
//! > confirmation and a monotonic floor."
//!
//! `twinvpn-tunnel` drives it: it exchanges advertisements, computes a
//! `Selection`, and runs the confirmation exchange. What this module owns is the
//! two decisions that must not be gettable wrong:
//!
//! 1. [`confirm_transcript`] — a **constant-time** comparison of the two
//!    transcript hashes, returning `PROTO.TRANSCRIPT_MISMATCH` on disagreement.
//! 2. [`NegotiationFloor`] — a monotone floor that can rise and cannot fall.
//!
//! # Why the floor lives here and not in `twinvpn-store`
//!
//! The floor is *persisted* by the store (S-37 is a durable row) but the
//! **rule** is cryptographic policy, and ADR-0014 N-20 makes lowering it an
//! authenticated local Owner action:
//!
//! > "clearing or lowering a floor requires an authenticated LOCAL
//! > management-plane action by the Owner, MUST name the peer, the recorded
//! > floor and the offered value, and MUST NOT be triggerable by the control
//! > plane or by any peer. A floor that could be transmitted could be lowered
//! > remotely, which would delete the anti-rollback property entirely."
//!
//! So [`NegotiationFloor`] has [`NegotiationFloor::raise`] and no `lower`. The
//! only downward path is [`NegotiationFloor::clear_by_owner`], which takes an
//! [`OwnerClearance`] — a token that only the local management plane can mint —
//! and returns the evidence N-20 requires be named.
//!
//! # N-19 narrows D3, and the narrowing is implemented
//!
//! ADR-0001 D3 would ratchet "the `security_relevant` subset of the `Capability`
//! set". ADR-0014 N-19 narrows it and says why:
//!
//! > "a whole-set ratchet is unsound because capability sets are a PARTIAL order
//! > and a capability can legitimately vanish when an OS revokes a permission —
//! > ratcheting the whole set would permanently brick an honest device."
//!
//! [`NegotiationFloor`] therefore holds **only** registry-flagged
//! `security_relevant` tokens, and [`NegotiationFloor::check_offer`] reports a
//! lost non-security capability as *not* a violation.

use subtle::ConstantTimeEq;

use crate::{CryptoError, Result};

/// Compares two transcript hashes in constant time.
///
/// D2: "A transcript hash covering the full negotiation MUST be confirmed by
/// both peers; mismatch MUST tear down the `Session` with
/// `PROTO.TRANSCRIPT_MISMATCH`."
///
/// Constant time because the comparison runs on a value an attacker influences,
/// and a variable-time compare on a hash leaks a prefix-matching oracle. It is
/// cheap here and there is no reason to make the weaker choice.
///
/// # Errors
///
/// [`CryptoError::TranscriptMismatch`] naming `phase`.
pub fn confirm_transcript(local: &[u8], peer: &[u8], phase: &'static str) -> Result<()> {
    // Lengths are public and a length mismatch is not a timing signal worth
    // hiding — but comparing slices of different lengths in constant time is
    // not meaningful, so it is refused first.
    if local.len() != peer.len() || local.is_empty() {
        return Err(CryptoError::TranscriptMismatch { phase });
    }
    if local.ct_eq(peer).into() {
        Ok(())
    } else {
        Err(CryptoError::TranscriptMismatch { phase })
    }
}

/// An authenticated local management-plane action by the Owner.
///
/// A zero-sized capability token. It carries nothing, because what matters is
/// **who can construct it**: [`OwnerClearance::from_local_management_action`]
/// is the only constructor, it is named for the one thing that may call it, and
/// nothing on a wire can produce one. ADR-0014 N-20's "MUST NOT be triggerable
/// by the control plane or by any peer" is that fact.
#[derive(Debug, Clone, Copy)]
pub struct OwnerClearance(());

impl OwnerClearance {
    /// Mints a clearance for an authenticated local Owner action.
    ///
    /// Called by `twinvpn-mgmt` after it has authenticated the local Owner.
    /// There is no other legitimate caller, and there is no path from a decoded
    /// message to this function.
    #[must_use]
    pub const fn from_local_management_action() -> Self {
        Self(())
    }
}

/// What ADR-0014 N-20 requires be named when a floor is cleared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorClearedEvidence {
    /// The peer the floor was recorded against.
    pub peer_device_id: [u8; 32],
    /// The epoch that was recorded.
    pub recorded_floor: u32,
    /// The epoch that was offered and refused.
    pub offered_epoch: u32,
    /// The `security_relevant` tokens that were in the floor.
    pub recorded_security_capabilities: Vec<String>,
}

/// The per-`TrustedPeer` anti-downgrade floor (S-37).
///
/// `Clone` but deliberately not `Default`: a floor with no peer is not a floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationFloor {
    peer_device_id: [u8; 32],
    floor_epoch: u32,
    /// Sorted and deduplicated, so two floors holding the same set compare
    /// equal and the persisted form is canonical.
    security_capabilities: Vec<String>,
}

impl NegotiationFloor {
    /// A floor for a peer with nothing recorded yet.
    #[must_use]
    pub const fn new(peer_device_id: [u8; 32]) -> Self {
        Self {
            peer_device_id,
            floor_epoch: 0,
            security_capabilities: Vec::new(),
        }
    }

    /// Rebuilds a floor from persisted state.
    ///
    /// Used by `twinvpn-store` when loading S-37. `security_capabilities` is
    /// normalised on the way in so a persisted set that was written unsorted
    /// cannot change a comparison.
    #[must_use]
    pub fn from_parts(
        peer_device_id: [u8; 32],
        floor_epoch: u32,
        security_capabilities: Vec<String>,
    ) -> Self {
        let mut caps = security_capabilities;
        caps.sort();
        caps.dedup();
        Self {
            peer_device_id,
            floor_epoch,
            security_capabilities: caps,
        }
    }

    /// The peer this floor is about.
    #[must_use]
    pub const fn peer_device_id(&self) -> &[u8; 32] {
        &self.peer_device_id
    }

    /// The highest `ProtocolEpoch` ever confirmed with this peer.
    #[must_use]
    pub const fn floor_epoch(&self) -> u32 {
        self.floor_epoch
    }

    /// The recorded `security_relevant` tokens.
    #[must_use]
    pub fn security_capabilities(&self) -> &[String] {
        &self.security_capabilities
    }

    /// Checks an offer against the floor.
    ///
    /// `offered_epoch` is the epoch the peer offers. `offered_security_caps` is
    /// the **`security_relevant` subset** of what the peer offers — the caller
    /// filters by the registry's `security_relevant` flag, because N-19's whole
    /// point is that the floor covers that subset and nothing else.
    ///
    /// # Errors
    ///
    /// [`CryptoError::DowngradeRefused`] if the epoch is strictly below the
    /// floor, or if a recorded `security_relevant` token is absent from the
    /// offer.
    pub fn check_offer(&self, offered_epoch: u32, offered_security_caps: &[String]) -> Result<()> {
        if offered_epoch < self.floor_epoch {
            return Err(CryptoError::DowngradeRefused {
                offered_epoch,
                recorded_floor: self.floor_epoch,
            });
        }
        for recorded in &self.security_capabilities {
            if !offered_security_caps.contains(recorded) {
                // The same code, because it is the same refusal: a peer that
                // has quietly lost a security-relevant capability is offering a
                // weaker session than one already established.
                return Err(CryptoError::DowngradeRefused {
                    offered_epoch,
                    recorded_floor: self.floor_epoch,
                });
            }
        }
        Ok(())
    }

    /// Raises the floor after an **in-session confirmed** negotiation.
    ///
    /// P-4: "A version epoch that is not yet confirmed in-session MUST NOT be
    /// written to the S-37 floor." The `_confirmed` parameter is the caller's
    /// assertion that D1's confirmation has happened; it is a named argument
    /// rather than a comment so that a call site which has not confirmed has to
    /// write `false` and see itself do it.
    ///
    /// A lower epoch is **ignored**, never applied. `security_capabilities` is
    /// unioned, never replaced, so a single session that happened to advertise
    /// fewer tokens cannot narrow the floor.
    pub fn raise(&mut self, confirmed: bool, epoch: u32, security_caps: &[String]) {
        if !confirmed {
            return;
        }
        if epoch > self.floor_epoch {
            self.floor_epoch = epoch;
        }
        for c in security_caps {
            if !self.security_capabilities.contains(c) {
                self.security_capabilities.push(c.clone());
            }
        }
        self.security_capabilities.sort();
        self.security_capabilities.dedup();
    }

    /// Clears the floor, by an authenticated local Owner action only.
    ///
    /// Returns the evidence ADR-0014 N-20 requires be named: the peer, the
    /// recorded floor, and the offered value.
    #[must_use]
    pub fn clear_by_owner(
        &mut self,
        _clearance: OwnerClearance,
        offered_epoch: u32,
    ) -> FloorClearedEvidence {
        let evidence = FloorClearedEvidence {
            peer_device_id: self.peer_device_id,
            recorded_floor: self.floor_epoch,
            offered_epoch,
            recorded_security_capabilities: self.security_capabilities.clone(),
        };
        self.floor_epoch = 0;
        self.security_capabilities.clear();
        evidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: [u8; 32] = [0x77; 32];

    fn caps(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn matching_transcripts_confirm() {
        assert!(confirm_transcript(&[1, 2, 3], &[1, 2, 3], "phase-1").is_ok());
    }

    /// **Attack test.** D2: a tampered negotiation must tear the session down.
    #[test]
    fn a_differing_transcript_is_refused() {
        let err = confirm_transcript(&[1, 2, 3], &[1, 2, 4], "phase-1").expect_err("mismatch");
        assert!(matches!(
            err,
            CryptoError::TranscriptMismatch { phase: "phase-1" }
        ));
        assert_eq!(err.reason_code().as_str(), "PROTO.TRANSCRIPT_MISMATCH");
    }

    /// An empty or truncated transcript must not confirm — a zero-length
    /// "hash" comparing equal to another zero-length one would make the
    /// confirmation vacuous.
    #[test]
    fn an_empty_or_short_transcript_is_refused() {
        assert!(confirm_transcript(&[], &[], "p").is_err());
        assert!(confirm_transcript(&[1, 2, 3], &[1, 2], "p").is_err());
    }

    /// **Attack test.** D3/S-37: an offer below the recorded floor is refused,
    /// which is the anti-rollback property.
    #[test]
    fn an_epoch_below_the_floor_is_refused() {
        let mut f = NegotiationFloor::new(PEER);
        f.raise(true, 5, &caps(&["strict_binding"]));
        let err = f
            .check_offer(4, &caps(&["strict_binding"]))
            .expect_err("downgrade");
        assert!(matches!(
            err,
            CryptoError::DowngradeRefused {
                offered_epoch: 4,
                recorded_floor: 5
            }
        ));
        assert_eq!(err.reason_code().as_str(), "PROTO.DOWNGRADE_REFUSED");
        // Equal and higher are both fine.
        assert!(f.check_offer(5, &caps(&["strict_binding"])).is_ok());
        assert!(f.check_offer(6, &caps(&["strict_binding"])).is_ok());
    }

    /// **Attack test.** Silently dropping a `security_relevant` capability is a
    /// downgrade even at an acceptable epoch.
    #[test]
    fn losing_a_security_relevant_capability_is_refused() {
        let mut f = NegotiationFloor::new(PEER);
        f.raise(true, 3, &caps(&["strict_binding", "psk_epoch_gate"]));
        assert!(
            f.check_offer(3, &caps(&["strict_binding"])).is_err(),
            "a dropped security capability must be refused"
        );
    }

    /// N-19's narrowing: a *non*-security capability may legitimately vanish,
    /// and the floor must not brick the device over it. The floor only ever
    /// holds the security-relevant subset, so a caller that filters correctly
    /// sees no violation.
    #[test]
    fn losing_a_non_security_capability_is_not_a_downgrade() {
        let mut f = NegotiationFloor::new(PEER);
        // Only the security-relevant subset is ever recorded.
        f.raise(true, 3, &caps(&["strict_binding"]));
        // The peer still offers the security-relevant token and has lost an
        // ordinary one, which never reaches this check.
        assert!(f.check_offer(3, &caps(&["strict_binding"])).is_ok());
    }

    /// **Attack test.** P-4: an unconfirmed negotiation must not write the
    /// floor, or an on-path adversary could raise a peer's floor with an offer
    /// that was never confirmed and permanently refuse honest sessions.
    #[test]
    fn an_unconfirmed_negotiation_does_not_write_the_floor() {
        let mut f = NegotiationFloor::new(PEER);
        f.raise(false, 9, &caps(&["strict_binding"]));
        assert_eq!(f.floor_epoch(), 0);
        assert!(f.security_capabilities().is_empty());
    }

    /// The floor rises and never falls, and a session advertising fewer tokens
    /// cannot narrow it.
    #[test]
    fn the_floor_is_monotone_and_the_capability_set_is_a_union() {
        let mut f = NegotiationFloor::new(PEER);
        f.raise(true, 5, &caps(&["a"]));
        f.raise(true, 3, &caps(&["b"]));
        assert_eq!(f.floor_epoch(), 5, "a lower epoch must not lower the floor");
        assert_eq!(f.security_capabilities(), caps(&["a", "b"]).as_slice());
        f.raise(true, 7, &[]);
        assert_eq!(f.floor_epoch(), 7);
        assert_eq!(
            f.security_capabilities(),
            caps(&["a", "b"]).as_slice(),
            "an empty offer must not clear the recorded set"
        );
    }

    /// N-20: clearing is possible only with an Owner clearance, and it produces
    /// the evidence the ADR requires be named.
    #[test]
    fn clearing_requires_an_owner_clearance_and_names_the_evidence() {
        let mut f = NegotiationFloor::new(PEER);
        f.raise(true, 5, &caps(&["strict_binding"]));
        let ev = f.clear_by_owner(OwnerClearance::from_local_management_action(), 2);
        assert_eq!(ev.peer_device_id, PEER);
        assert_eq!(ev.recorded_floor, 5);
        assert_eq!(ev.offered_epoch, 2);
        assert_eq!(ev.recorded_security_capabilities, caps(&["strict_binding"]));
        assert_eq!(f.floor_epoch(), 0);
        // And the previously refused offer now passes, which is the point.
        assert!(f.check_offer(2, &[]).is_ok());
    }

    /// Persisted floors normalise, so a store round trip cannot change a
    /// comparison by reordering.
    #[test]
    fn a_persisted_floor_normalises_its_capability_set() {
        let a = NegotiationFloor::from_parts(PEER, 4, caps(&["b", "a", "a"]));
        let b = NegotiationFloor::from_parts(PEER, 4, caps(&["a", "b"]));
        assert_eq!(a, b);
    }
}
