//! Revocation — the deliberate exception to I5.
//!
//! **Authority:** `docs/architecture.md` §4.5, ADR-0009 §11.2 E-1 and §11.5,
//! ADR-0007 N-25, `contracts/proto/twinvpn/v1/control_commands.proto`
//! (`RevokeDeviceRequest.revocation_statement`),
//! `contracts/docs/idempotency.md` §5.
//!
//! # Two effects, two authorities — and that split is the mechanism
//!
//! ADR-0007 N-25, restated in `control_commands.proto`:
//!
//! 1. **Peer refusal is LOCAL** and takes effect the instant a device verifies
//!    an Owner-signed `RevocationStatement`, **whatever its provenance**,
//!    requiring no epoch number and no control-plane reachability. This is the
//!    effect that survives a partition — and it is why a revocation carried
//!    peer-to-peer (protocol.md §16 row 37) works at all.
//! 2. **The `trust_epoch` advance is totally ordered.** The Owner *authorizes*
//!    by signing; the shard writer *assigns* the number under its fenced lease.
//!    A statement not yet admitted is **fully effective for (1)** and **PENDING
//!    for (2)**, and MUST NOT be assigned an epoch locally.
//!
//! > *"The split is what makes a forked history structurally impossible rather
//! > than merely detectable."*
//!
//! # Why this is not an I5 violation
//!
//! `architecture.md` §4.5(2): existing tunnels to a revoked peer are torn down
//! immediately on learning of revocation, and that is not an I5 violation
//! because **I5 protects tunnels against control-plane *unavailability*, not
//! against an authoritative instruction that trust has ended.** [`CpError`]'s
//! [`crate::CpError::permits_offline_reconnect`] draws the same line.

use crate::error::CpError;

/// The device's durable trust-generation high-water mark.
///
/// ADR-0009 R-6: `trust_epoch` MUST NOT decrease **under any circumstance, in
/// any document type**. Every document type therefore acts as a freshness beacon
/// for the trust generation, and this type is where that is enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustEpoch {
    high_water: u64,
}

impl TrustEpoch {
    /// A device that has never seen an admitted revocation.
    pub const GENESIS: TrustEpoch = TrustEpoch { high_water: 0 };

    /// Restores from the durable store.
    #[must_use]
    pub const fn restored(high_water: u64) -> Self {
        Self { high_water }
    }

    /// The current mark.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.high_water
    }

    /// Admits an offered epoch, or refuses it as a rollback.
    ///
    /// **The highest epoch wins and any lower epoch is refused rather than
    /// applied.** This is `AUTH.TRUST_EPOCH_ROLLBACK` and it is a *security
    /// control*, not hygiene: revocation is "a monotone epoch plus a
    /// never-shrinking set … never a mutable `revoked: true/false`", because a
    /// mutable boolean is precisely the shape that permits **un-revocation by
    /// replaying an older record**.
    ///
    /// Equal is accepted as an idempotent no-op (ADR-0009 R-3), which is what
    /// makes at-least-once C2 delivery safe.
    ///
    /// # Errors
    ///
    /// [`CpError::TrustEpochRollback`] on any lower value.
    pub const fn admit(self, offered: u64) -> Result<EpochAdmission, CpError> {
        if offered < self.high_water {
            return Err(CpError::TrustEpochRollback {
                offered_epoch: offered,
                high_water_epoch: self.high_water,
            });
        }
        if offered == self.high_water {
            return Ok(EpochAdmission::NoOp);
        }
        Ok(EpochAdmission::Advance { to: offered })
    }

    /// Moves the mark, **after** the durable write succeeded (ADR-0009 R-9).
    pub const fn commit(&mut self, epoch: u64) {
        if epoch > self.high_water {
            self.high_water = epoch;
        }
    }
}

/// What admitting an epoch produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochAdmission {
    /// A genuine advance.
    Advance {
        /// The new mark.
        to: u64,
    },
    /// The same epoch again — a duplicate delivery, applied as a no-op.
    NoOp,
}

/// What a verified revocation statement obliges the device to do.
///
/// The two effects are separate fields because they have separate authorities
/// and separate reachability requirements. Collapsing them into one `bool` is
/// how a partitioned device ends up either ignoring a revocation it *can*
/// enforce, or minting an epoch number it has no authority to assign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationEffect {
    /// Effect (1). Local, immediate, needs no epoch and no reachability.
    ///
    /// Always `true` for a statement whose Owner signature verified: refusal is
    /// not conditional on the control plane having ordered it.
    pub refuse_peer_now: bool,
    /// Effect (2). `Some` only when the control plane has **admitted** the
    /// statement and assigned it a number.
    pub admitted_epoch: Option<u64>,
}

impl RevocationEffect {
    /// A statement verified but not yet admitted: fully effective for refusal,
    /// **pending** for the epoch advance.
    ///
    /// This is the shape a peer-carried `RevocationTransfer` (protocol.md §16
    /// row 37) produces, and the shape a device sees during a total
    /// control-plane outage. The sender is a courier, never a publisher.
    #[must_use]
    pub const fn verified_but_unadmitted() -> Self {
        Self {
            refuse_peer_now: true,
            admitted_epoch: None,
        }
    }

    /// A statement the control plane admitted and numbered.
    #[must_use]
    pub const fn admitted(epoch: u64) -> Self {
        Self {
            refuse_peer_now: true,
            admitted_epoch: Some(epoch),
        }
    }

    /// Whether the device may advance its own `trust_epoch` from this.
    ///
    /// `false` for an unadmitted statement: ADR-0007 N-25 says a statement not
    /// yet admitted "MUST NOT be assigned an epoch locally", and that
    /// prohibition is what makes a forked history impossible rather than merely
    /// detectable.
    #[must_use]
    pub const fn may_advance_epoch(self) -> bool {
        self.admitted_epoch.is_some()
    }
}

/// The high-water marks a peer keeps per `device_id` for key rotation.
///
/// ADR-0007 N-22: peers hold **two** marks — `highest_generation_seen` and
/// `highest_tk_generation_seen` — and MUST reject any statement at or below the
/// corresponding mark. Two, because a TK rotation does not change
/// `DeviceIdentity`, so one counter would either block legitimate TK rotations
/// or admit an IK downgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RotationMarks {
    /// `highest_generation_seen` — the IK generation.
    pub generation: u32,
    /// `highest_tk_generation_seen` — the tunnel-key generation.
    pub tk_generation: u32,
}

impl RotationMarks {
    /// Admits an identity succession at `generation`.
    ///
    /// # Errors
    ///
    /// [`CpError::TrustEpochRollback`] at or below the mark — a key rollback.
    pub const fn admit_identity(self, generation: u32) -> Result<(), CpError> {
        if generation <= self.generation {
            return Err(CpError::TrustEpochRollback {
                offered_epoch: generation as u64,
                high_water_epoch: self.generation as u64,
            });
        }
        Ok(())
    }

    /// Admits a tunnel-key binding at `tk_generation`.
    ///
    /// # Errors
    ///
    /// [`CpError::TrustEpochRollback`] at or below the mark.
    pub const fn admit_tunnel_key(self, tk_generation: u32) -> Result<(), CpError> {
        if tk_generation <= self.tk_generation {
            return Err(CpError::TrustEpochRollback {
                offered_epoch: tk_generation as u64,
                high_water_epoch: self.tk_generation as u64,
            });
        }
        Ok(())
    }
}

/// A monotone counter with a durable floor, for the versions that are not epochs.
///
/// `contracts/docs/idempotency.md` §5 lists twelve; this crate holds
/// `policy_version`, `advertisement_epoch`, `offer_epoch`, `map_version`,
/// `epoch_floor` and `contract_seq` through this one type, because they all obey
/// the same three rules (ADR-0009 R-2/R-3/R-4/R-5) and writing six copies is how
/// one of them ends up missing the fork check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonotoneVersion {
    version: u64,
    content_digest: [u8; 32],
}

impl MonotoneVersion {
    /// Restores a stored mark.
    #[must_use]
    pub const fn restored(version: u64, content_digest: [u8; 32]) -> Self {
        Self {
            version,
            content_digest,
        }
    }

    /// The stored version.
    #[must_use]
    pub const fn version(self) -> u64 {
        self.version
    }

    /// Applies ADR-0009's four-way admission rule.
    ///
    /// # Errors
    ///
    /// [`CpError::TrustEpochRollback`] (R-5) below the mark, and
    /// [`CpError::TrustHistoryForked`] (R-4) at the same version with different
    /// content — the client-side detector for E-1(c).
    pub fn admit(self, offered: u64, digest: [u8; 32]) -> Result<VersionAdmission, CpError> {
        if offered < self.version {
            return Err(CpError::TrustEpochRollback {
                offered_epoch: offered,
                high_water_epoch: self.version,
            });
        }
        if offered == self.version {
            return if digest == self.content_digest {
                Ok(VersionAdmission::NoOp)
            } else {
                Err(CpError::TrustHistoryForked { epoch: offered })
            };
        }
        Ok(VersionAdmission::Accept)
    }
}

/// What admitting a versioned document produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionAdmission {
    /// R-2: a strictly higher version. Accept.
    Accept,
    /// R-3: the same version with the same content. Idempotent no-op.
    NoOp,
}

#[cfg(test)]
mod tests {
    use super::{EpochAdmission, MonotoneVersion, RevocationEffect, RotationMarks, TrustEpoch};

    #[test]
    fn the_highest_epoch_wins_and_a_lower_one_is_a_rollback() {
        let epoch = TrustEpoch::restored(12);
        assert_eq!(
            epoch.admit(13).expect("forward"),
            EpochAdmission::Advance { to: 13 }
        );
        assert_eq!(epoch.admit(12).expect("same"), EpochAdmission::NoOp);
        let err = epoch.admit(11).expect_err("rollback");
        assert_eq!(err.reason_code().as_str(), "AUTH.TRUST_EPOCH_ROLLBACK");
        assert!(err.reason_code().terminal());
        assert!(err.is_security_event());
    }

    #[test]
    fn un_revocation_by_replaying_an_older_record_is_not_expressible() {
        // idempotency.md §5: revocation is a monotone epoch plus a
        // never-shrinking set, never a mutable boolean.
        let mut epoch = TrustEpoch::GENESIS;
        epoch.commit(5);
        assert!(epoch.admit(0).is_err(), "epoch 0 would un-revoke");
        // And a commit cannot pull it back either.
        epoch.commit(1);
        assert_eq!(epoch.get(), 5);
    }

    #[test]
    fn refusal_survives_a_partition_but_the_epoch_advance_does_not() {
        let offline = RevocationEffect::verified_but_unadmitted();
        assert!(
            offline.refuse_peer_now,
            "effect (1) needs no control-plane reachability"
        );
        assert!(
            !offline.may_advance_epoch(),
            "ADR-0007 N-25: an unadmitted statement MUST NOT be numbered locally"
        );

        let admitted = RevocationEffect::admitted(9);
        assert!(admitted.refuse_peer_now);
        assert!(admitted.may_advance_epoch());
        assert_eq!(admitted.admitted_epoch, Some(9));
    }

    #[test]
    fn the_two_rotation_marks_are_independent() {
        let marks = RotationMarks {
            generation: 3,
            tk_generation: 11,
        };
        assert!(marks.admit_identity(4).is_ok());
        assert!(marks.admit_identity(3).is_err(), "at the mark is a replay");
        assert!(marks.admit_identity(2).is_err());
        // A TK rotation at a generation below the IK mark is perfectly normal:
        // TK rotation does not change DeviceIdentity.
        assert!(marks.admit_tunnel_key(12).is_ok());
        assert!(marks.admit_tunnel_key(11).is_err());
    }

    #[test]
    fn a_policy_rollback_is_refused_and_a_fork_is_detected() {
        let stored = MonotoneVersion::restored(40, [7u8; 32]);
        assert!(stored.admit(41, [8u8; 32]).is_ok());
        assert!(stored.admit(40, [7u8; 32]).is_ok(), "R-3 idempotent no-op");

        let rollback = stored.admit(39, [7u8; 32]).expect_err("R-5");
        assert_eq!(rollback.reason_code().as_str(), "AUTH.TRUST_EPOCH_ROLLBACK");

        let fork = stored.admit(40, [9u8; 32]).expect_err("R-4");
        assert_eq!(fork.reason_code().as_str(), "AUTH.TRUST_HISTORY_FORKED");
        assert!(fork.is_security_event());
    }

    #[test]
    fn a_rollback_does_not_permit_an_offline_reconnect() {
        // architecture.md §4.5(2): a revocation is an authoritative instruction
        // that trust has ended, not unavailability. I5 does not protect against
        // it, and an attempted rollback is the one thing this client will not
        // keep running through.
        let epoch = TrustEpoch::restored(4);
        let err = epoch.admit(1).expect_err("rollback");
        assert!(!err.permits_offline_reconnect());
        // Contrast: a plain outage does.
        assert!(crate::CpError::Unreachable.permits_offline_reconnect());
    }
}
