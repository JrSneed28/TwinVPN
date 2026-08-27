//! Revocation — N-25's two separable effects, and the resurrection attack.
//!
//! **Authority:** ADR-0007 N-25, N-26, N-28; `docs/architecture.md` §4.5 (the
//! plane-separation exception); ADR-0008 N-7; `signed_statements.cddl` §5 and
//! §6.
//!
//! # N-25, quoted, because both halves are load-bearing
//!
//! > 1. **Peer refusal** … is **local** (S-05) and takes effect the instant a
//! >    device verifies an `Owner`-signed `RevocationRecord`, **whatever its
//! >    provenance** — control plane, peer relay, or manual import. It requires
//! >    **no** epoch number and **no** control-plane reachability. This is the
//! >    effect that must survive a partition, and it does.
//! > 2. **`trust_epoch` advance** … is a **totally ordered** operation. The
//! >    `Owner` **authorizes** it by signing; the control-plane shard writer
//! >    **assigns** the epoch number at admission … An `Owner`-signed
//! >    `RevocationRecord` that has not yet been admitted is fully effective for
//! >    (1) and is **pending** for (2), and **MUST NOT be assigned an epoch
//! >    locally**.
//!
//! [`RevocationState`] therefore has two independent surfaces:
//! [`RevocationState::refuse_on_statement`], which needs only a verified inner
//! statement and no epoch at all, and [`RevocationState::admit_entry`], which
//! takes the writer's assigned epoch. There is **no** method that assigns an
//! epoch from a statement, because N-25(2) says a device must not.
//!
//! # The plane-separation exception
//!
//! `architecture.md` §4.5 makes revocation the deliberate exception to plane
//! separation: a data-plane peer relays a `RevocationTransfer` inside an
//! established tunnel, and a device acts on it. That is why
//! `refuse_on_statement` takes no provenance argument — accepting one would
//! invite a caller to weight "from the control plane" above "from a peer", and
//! N-25(1) says the two are equal.
//!
//! # Why there is no `un_revoke`
//!
//! ADR-0008 N-7 and the CDDL: "revocation is a MONOTONE EPOCH PLUS A
//! NEVER-SHRINKING SET. **A mutable boolean is exactly the shape that permits
//! UN-REVOCATION by replaying an older record.**" [`RevocationState`] holds a
//! `BTreeSet` that only ever grows and a `u64` that only ever rises. There is no
//! removal method, and adding one is the change a reviewer should refuse.

use std::collections::{BTreeMap, BTreeSet};

use twinvpn_crypto::sha256;
use twinvpn_crypto::statements::{RevocationEntry, RevocationStatement};

use crate::error::{Result, TrustError};

/// The device-local revocation state.
///
/// `Clone` for snapshotting into a diagnostic; there is no interior mutability
/// and no way to shrink it.
#[derive(Debug, Clone, Default)]
pub struct RevocationState {
    /// The never-shrinking revoked set, keyed by `device_id`.
    ///
    /// A `None` value means "every generation" (the CDDL's
    /// `identity-id / null`); a `Some` set names specific generations.
    revoked: BTreeMap<[u8; 32], Option<BTreeSet<[u8; 32]>>>,
    /// The monotone `trust_epoch` (N-26).
    trust_epoch: u64,
    /// The lowest `psk2` epoch this device will accept.
    min_acceptable_epoch: u64,
    /// The last admitted entry's hash, for N-26's chain check.
    last_entry_hash: [u8; 32],
    /// The last admitted `net_seq`.
    last_net_seq: u64,
}

/// What acting on a revocation produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefusalOutcome {
    /// Whether this statement added something the device did not already know.
    pub newly_revoked: bool,
    /// Whether the revocation is **pending** for effect (2): it refuses the
    /// peer now, and has no epoch until a writer admits it.
    pub epoch_pending: bool,
}

impl RevocationState {
    /// An empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The current `trust_epoch`.
    #[must_use]
    pub const fn trust_epoch(&self) -> u64 {
        self.trust_epoch
    }

    /// The lowest `psk2` epoch this device accepts.
    #[must_use]
    pub const fn min_acceptable_epoch(&self) -> u64 {
        self.min_acceptable_epoch
    }

    /// Whether a device is revoked, at any generation or at `identity_id`.
    ///
    /// The `None` entry — "every generation" — matches regardless of the
    /// generation asked about, because it is the *broader* reading and a
    /// narrower one would admit a device the Owner revoked wholesale.
    #[must_use]
    pub fn is_revoked(&self, device_id: &[u8; 32], identity_id: Option<&[u8; 32]>) -> bool {
        match self.revoked.get(device_id) {
            None => false,
            Some(None) => true,
            Some(Some(gens)) => identity_id.is_some_and(|i| gens.contains(i)),
        }
    }

    /// **Effect (1): peer refusal.** Applies a verified `RevocationStatement`.
    ///
    /// Takes **no** epoch and **no** provenance. The caller has verified the
    /// COSE_Sign1 under an Owner authority carrying the `REVOKE` power; from
    /// there this is unconditional and immediate.
    ///
    /// Adding a device that is already revoked at "every generation" does not
    /// narrow it — the set never shrinks, in either direction.
    pub fn refuse_on_statement(&mut self, s: &RevocationStatement) -> RefusalOutcome {
        let entry = self.revoked.entry(s.target_device_id);
        let newly_revoked = match (entry, s.target_identity_id) {
            (std::collections::btree_map::Entry::Vacant(v), None) => {
                v.insert(None);
                true
            }
            (std::collections::btree_map::Entry::Vacant(v), Some(id)) => {
                v.insert(Some(BTreeSet::from([id])));
                true
            }
            (std::collections::btree_map::Entry::Occupied(mut o), None) => {
                // Widening to "every generation" is always allowed.
                let was_all = o.get().is_none();
                o.insert(None);
                !was_all
            }
            (std::collections::btree_map::Entry::Occupied(mut o), Some(id)) => {
                match o.get_mut() {
                    // Already revoked wholesale: a narrower statement must not
                    // narrow it. This is the never-shrinking rule at its most
                    // subtle — accepting `Some(id)` over `None` would un-revoke
                    // every other generation.
                    None => false,
                    Some(gens) => gens.insert(id),
                }
            }
        };
        RefusalOutcome {
            newly_revoked,
            // N-25(2): a statement carries no epoch, and a device MUST NOT
            // assign one locally. It is pending until a writer admits it.
            epoch_pending: true,
        }
    }

    /// **Effect (2): the ordered epoch advance.** Applies an admitted
    /// `RevocationEntry`.
    ///
    /// `inner` is the entry's inner statement **after** the caller verified it
    /// under the Owner authority. The CDDL: "A `RevocationEntry` whose INNER
    /// statement signature does not verify MUST BE REJECTED OUTRIGHT: **A
    /// WELL-FORMED WRAPPER AUTHORIZES NOTHING.**" The signature is the caller's
    /// to check, and this method takes the *decoded, verified* statement rather
    /// than the octets so a caller cannot pass an unverified one by accident.
    ///
    /// `expect_chain` selects whether the `prev_entry_hash` chain is checked.
    /// N-26 makes the chain **detection, not prevention**, so a break raises
    /// `AUTH.TRUST_HISTORY_FORKED` **after** the refusal has already been
    /// applied — the peer stays refused whatever the chain says.
    ///
    /// # Errors
    ///
    /// [`TrustError::TrustEpochRollback`] for a lower epoch, refused not
    /// applied (N-26). [`TrustError::TrustHistoryForked`] for a broken chain,
    /// **after** the refusal has landed.
    pub fn admit_entry(
        &mut self,
        entry: &RevocationEntry,
        inner: &RevocationStatement,
        expect_chain: bool,
    ) -> Result<RefusalOutcome> {
        // N-26: a lower epoch is refused, not applied.
        if entry.trust_epoch < self.trust_epoch {
            return Err(TrustError::TrustEpochRollback {
                offered: entry.trust_epoch,
                high_water: self.trust_epoch,
            });
        }

        // Effect (1) first and unconditionally. It does not depend on the
        // chain, on ordering, or on anything the writer supplies — which is
        // exactly what makes it survive a partition.
        let mut outcome = self.refuse_on_statement(inner);
        outcome.epoch_pending = false;

        // Effect (2).
        self.trust_epoch = self.trust_epoch.max(entry.trust_epoch);
        self.min_acceptable_epoch = self.min_acceptable_epoch.max(entry.trust_epoch);
        self.last_net_seq = self.last_net_seq.max(entry.net_seq);

        if expect_chain && entry.prev_entry_hash != self.last_entry_hash {
            // Detection only. The refusal above has already landed, and the
            // epoch has already advanced, because a forked or withheld chain
            // must not be able to un-revoke a device at a peer that has seen
            // the statement.
            self.last_entry_hash = entry_hash(entry);
            return Err(TrustError::TrustHistoryForked {
                epoch: entry.trust_epoch,
            });
        }
        self.last_entry_hash = entry_hash(entry);
        Ok(outcome)
    }

    /// Advances `min_acceptable_epoch` from a verified `TrustEpochBundle`.
    ///
    /// N-28's second lever: without it "a lagging peer can refuse the revoked
    /// device but cannot advance `min_acceptable_epoch` or derive `psk2` at the
    /// new epoch."
    ///
    /// # Errors
    ///
    /// [`TrustError::TrustEpochRollback`]: "a lower value is
    /// `AUTH.TRUST_EPOCH_ROLLBACK`, refused rather than applied."
    pub fn advance_epoch(&mut self, trust_epoch: u64) -> Result<()> {
        if trust_epoch < self.trust_epoch {
            return Err(TrustError::TrustEpochRollback {
                offered: trust_epoch,
                high_water: self.trust_epoch,
            });
        }
        self.trust_epoch = trust_epoch;
        self.min_acceptable_epoch = self.min_acceptable_epoch.max(trust_epoch);
        Ok(())
    }

    /// Whether a handshake at `psk_epoch` may be accepted.
    ///
    /// N-25: "A device MUST NOT accept a handshake below its
    /// `min_acceptable_epoch`. It MUST retain the two preceding epochs' seeds."
    /// The retention is why the comparison is `>=` against
    /// `min_acceptable_epoch` and the caller keeps three seeds; a stricter
    /// equality would exclude legitimate peers mid-rotation, which is K8.
    #[must_use]
    pub const fn accepts_psk_epoch(&self, psk_epoch: u64) -> bool {
        psk_epoch >= self.min_acceptable_epoch
    }

    /// How many devices are revoked. For diagnostics only.
    #[must_use]
    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
    }
}

/// The hash of an admitted entry, for the next entry's `prev_entry_hash`.
#[must_use]
pub fn entry_hash(e: &RevocationEntry) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"TwinVPN/revocation/entry/v1");
    buf.extend_from_slice(
        &u32::try_from(e.inner_cose_sign1.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    buf.extend_from_slice(&e.inner_cose_sign1);
    buf.extend_from_slice(&e.trust_epoch.to_be_bytes());
    buf.extend_from_slice(&e.net_seq.to_be_bytes());
    buf.extend_from_slice(&e.prev_entry_hash);
    sha256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 32] = [0xaa; 32];
    const B: [u8; 32] = [0xbb; 32];
    const GEN0: [u8; 32] = [0x00; 32];
    const GEN1: [u8; 32] = [0x01; 32];

    fn statement(device: [u8; 32], identity: Option<[u8; 32]>) -> RevocationStatement {
        RevocationStatement {
            twinnet_id: "tn-1".to_owned(),
            target_device_id: device,
            target_identity_id: identity,
            effective_from_ms: 1_700_000_000_000,
            reason_code: "AUTH.DEVICE_REVOKED".to_owned(),
            issuer_osk_id: "osk-1".to_owned(),
        }
    }

    fn entry(epoch: u64, net_seq: u64, prev: [u8; 32]) -> RevocationEntry {
        RevocationEntry {
            inner_cose_sign1: vec![1, 2, 3],
            trust_epoch: epoch,
            net_seq,
            prev_entry_hash: prev,
        }
    }

    /// **N-25(1).** A verified statement refuses the peer immediately, with no
    /// epoch and no control-plane reachability. This is the effect that survives
    /// a partition.
    #[test]
    fn a_verified_statement_refuses_the_peer_with_no_epoch() {
        let mut s = RevocationState::new();
        let outcome = s.refuse_on_statement(&statement(A, None));
        assert!(outcome.newly_revoked);
        assert!(
            outcome.epoch_pending,
            "a statement carries no epoch and a device must not assign one"
        );
        assert!(s.is_revoked(&A, None));
        assert_eq!(
            s.trust_epoch(),
            0,
            "no epoch may be assigned locally (N-25(2))"
        );
    }

    /// **Attack test — trust resurrection.** A lower `trust_epoch` is refused,
    /// not applied.
    #[test]
    fn a_lower_trust_epoch_is_refused_and_the_peer_stays_revoked() {
        let mut s = RevocationState::new();
        s.admit_entry(&entry(9, 100, [0u8; 32]), &statement(A, None), false)
            .expect("admit");
        assert_eq!(s.trust_epoch(), 9);

        let err = s
            .admit_entry(&entry(4, 101, [0u8; 32]), &statement(B, None), false)
            .expect_err("rollback");
        assert!(matches!(
            err,
            TrustError::TrustEpochRollback {
                offered: 4,
                high_water: 9
            }
        ));
        assert_eq!(err.reason_code().as_str(), "AUTH.TRUST_EPOCH_ROLLBACK");
        assert_eq!(s.trust_epoch(), 9, "the epoch must not move");
        assert!(s.is_revoked(&A, None), "and A must stay revoked");
    }

    /// **Attack test — the never-shrinking set.** Once a device is revoked at
    /// **every** generation, a narrower statement must not un-revoke the others.
    #[test]
    fn a_narrower_statement_cannot_shrink_a_wholesale_revocation() {
        let mut s = RevocationState::new();
        s.refuse_on_statement(&statement(A, None));
        assert!(s.is_revoked(&A, Some(&GEN0)));
        assert!(s.is_revoked(&A, Some(&GEN1)));

        // The attacker replays an older, narrower record.
        let outcome = s.refuse_on_statement(&statement(A, Some(GEN0)));
        assert!(!outcome.newly_revoked);
        assert!(
            s.is_revoked(&A, Some(&GEN1)),
            "generation 1 must still be revoked"
        );
        assert!(s.is_revoked(&A, None));
    }

    /// The set widens freely: a per-generation revocation followed by a
    /// wholesale one covers everything.
    #[test]
    fn a_wholesale_revocation_widens_a_per_generation_one() {
        let mut s = RevocationState::new();
        s.refuse_on_statement(&statement(A, Some(GEN0)));
        assert!(!s.is_revoked(&A, Some(&GEN1)));
        assert!(s.refuse_on_statement(&statement(A, None)).newly_revoked);
        assert!(s.is_revoked(&A, Some(&GEN1)));
    }

    /// **N-26, and the reason it is only detection.** A broken chain raises the
    /// fork code — **after** the refusal has landed and the epoch has advanced,
    /// so a forked or withheld chain cannot un-revoke a device.
    #[test]
    fn a_broken_chain_is_detected_but_does_not_undo_the_refusal() {
        let mut s = RevocationState::new();
        let first = entry(1, 1, [0u8; 32]);
        s.admit_entry(&first, &statement(A, None), true)
            .expect("first");

        // The next entry claims a `prev_entry_hash` that does not follow.
        let forked = entry(2, 2, [0x99; 32]);
        let err = s
            .admit_entry(&forked, &statement(B, None), true)
            .expect_err("fork detected");
        assert!(matches!(err, TrustError::TrustHistoryForked { epoch: 2 }));
        assert!(
            s.is_revoked(&B, None),
            "the refusal must have landed despite the fork"
        );
        assert_eq!(s.trust_epoch(), 2, "and the epoch must have advanced");
    }

    /// A well-formed chain does not raise the fork code.
    #[test]
    fn a_well_formed_chain_is_accepted() {
        let mut s = RevocationState::new();
        let first = entry(1, 1, [0u8; 32]);
        s.admit_entry(&first, &statement(A, None), true)
            .expect("first");
        let second = entry(2, 2, entry_hash(&first));
        s.admit_entry(&second, &statement(B, None), true)
            .expect("second");
        assert_eq!(s.trust_epoch(), 2);
    }

    /// **Attack test — the psk2 lever.** A handshake below
    /// `min_acceptable_epoch` is refused, which is what makes revocation
    /// cryptographic rather than advisory.
    #[test]
    fn a_handshake_below_the_minimum_epoch_is_refused() {
        let mut s = RevocationState::new();
        s.advance_epoch(7).expect("advance");
        assert!(!s.accepts_psk_epoch(6));
        assert!(s.accepts_psk_epoch(7));
        assert!(s.accepts_psk_epoch(8));
    }

    /// **Attack test.** `advance_epoch` refuses a lower value too — the
    /// `TrustEpochBundle` path must not be a way around N-26.
    #[test]
    fn the_epoch_bundle_path_also_refuses_a_rollback() {
        let mut s = RevocationState::new();
        s.advance_epoch(7).expect("advance");
        assert!(s.advance_epoch(6).is_err());
        assert_eq!(s.min_acceptable_epoch(), 7);
    }

    /// There is no `un_revoke`. This test states the property; a future removal
    /// method would have to delete it.
    #[test]
    fn the_revoked_set_only_grows() {
        let mut s = RevocationState::new();
        for d in [A, B] {
            s.refuse_on_statement(&statement(d, None));
        }
        assert_eq!(s.revoked_count(), 2);
        // Replaying every statement, in any order, cannot reduce the count.
        for d in [B, A, B] {
            s.refuse_on_statement(&statement(d, None));
        }
        assert_eq!(s.revoked_count(), 2);
        assert!(s.is_revoked(&A, None) && s.is_revoked(&B, None));
    }
}
