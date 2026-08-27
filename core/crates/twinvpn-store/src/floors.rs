//! The floor set — the facts that must never decrease.
//!
//! **Authority:** ADR-0020 §11.7 (the floor-set enumeration), ST-23 step 2,
//! ST-15 rule 5, ADR-0007 N-26, ADR-0009 R-5/R-7, ADR-0003 NC-3, ADR-0014 S-37.
//!
//! # §11.7's list, in full
//!
//! > "`trust_epoch` / `min_acceptable_epoch` and `anchor_version` (ADR-0007
//! > N-26, §7.7); per-peer `generation` and `tk_generation` (N-22);
//! > `doc_version` high-water per `doc_type` (ADR-0009 R-5, R-7);
//! > `contract_seq` (ADR-0003 NC-3); the S-37 negotiation-floor digest
//! > (ADR-0014); and `store_seq`, this ADR's own vault commit counter."
//!
//! # Why a floor is a type and not a `u64` in a struct
//!
//! N-26: "A lower value MUST be refused with `AUTH.TRUST_EPOCH_ROLLBACK`, **not
//! applied**." The failure mode is not "somebody wrote a comparison backwards";
//! it is "somebody wrote `floors.trust_epoch = new` on a path that had already
//! decided the value was fine, and a later refactor moved the decision". So
//! [`FloorSet`] has **no field assignment and no `set`**: the only mutation is
//! [`FloorSet::propose`], which returns the refusal rather than performing the
//! write, and [`FloorSet::apply`], which takes the proposal's own accepted
//! result.
//!
//! ST-15 rule 5 is the same rule for migrations: "A migration MUST NOT advance a
//! monotone floor and MUST NOT be capable of lowering one." There is no
//! migration-specific setter here, so a migration has the same API a commit
//! does and inherits the same refusal.

use std::collections::BTreeMap;

use crate::error::{Result, StoreError};

/// A floor's identity.
///
/// Two shapes: the fixed floors §11.7 names by name, and the two families that
/// are per-peer or per-document-type. Modelled as an enum so a typo cannot
/// invent a floor that then holds no value and silently permits everything.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FloorId {
    /// S-03's totally ordered revocation epoch (N-26).
    TrustEpoch,
    /// The lowest `psk2` epoch this device will accept (§7.7, N-25(2)).
    MinAcceptableEpoch,
    /// The pinned `OwnerTrustAnchor`'s version (N-26, S-32).
    AnchorVersion,
    /// `highest_generation_seen` for one peer (N-22).
    PeerGeneration(Vec<u8>),
    /// `highest_tk_generation_seen` for one peer (N-22).
    PeerTkGeneration(Vec<u8>),
    /// The high-water mark for one signed document type (ADR-0009 R-5, R-7).
    DocVersion(&'static str),
    /// `contract_seq` (ADR-0003 NC-3).
    ContractSeq,
    /// The S-37 negotiation-floor digest, carried as a `u64` truncation used
    /// only for change detection — the floor itself is
    /// [`twinvpn_crypto::transcript::NegotiationFloor`], and this entry exists so
    /// that a change to it participates in the ST-23 commit ordering.
    NegotiationFloorDigest,
    /// The vault commit counter (ST-21).
    StoreSeq,
}

impl FloorId {
    /// A stable, bounded name for a diagnostic.
    ///
    /// Per-peer floors render the peer's `device_id` as hex, which is
    /// `SENSITIVE`; callers that put this in a Tier-2 export must pseudonymize
    /// it. It is exposed as an explicit method rather than a `Display` so that
    /// obligation is visible at the call site.
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            FloorId::TrustEpoch => "trust_epoch".to_owned(),
            FloorId::MinAcceptableEpoch => "min_acceptable_epoch".to_owned(),
            FloorId::AnchorVersion => "anchor_version".to_owned(),
            FloorId::PeerGeneration(d) => format!("generation:{}", hex(d)),
            FloorId::PeerTkGeneration(d) => format!("tk_generation:{}", hex(d)),
            FloorId::DocVersion(t) => format!("doc_version:{t}"),
            FloorId::ContractSeq => "contract_seq".to_owned(),
            FloorId::NegotiationFloorDigest => "negotiation_floor_digest".to_owned(),
            FloorId::StoreSeq => "store_seq".to_owned(),
        }
    }

    /// A `&'static str` category for the `floor` field of a refusal, which must
    /// not carry a `device_id`.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            FloorId::TrustEpoch => "trust_epoch",
            FloorId::MinAcceptableEpoch => "min_acceptable_epoch",
            FloorId::AnchorVersion => "anchor_version",
            FloorId::PeerGeneration(_) => "generation",
            FloorId::PeerTkGeneration(_) => "tk_generation",
            FloorId::DocVersion(_) => "doc_version",
            FloorId::ContractSeq => "contract_seq",
            FloorId::NegotiationFloorDigest => "negotiation_floor_digest",
            FloorId::StoreSeq => "store_seq",
        }
    }
}

fn hex(b: &[u8]) -> String {
    use core::fmt::Write as _;
    b.iter().fold(String::new(), |mut out, x| {
        let _ = write!(out, "{x:02x}");
        out
    })
}

/// The monotone floor set.
///
/// An absent floor is **zero**, not "unconstrained": a floor nobody has written
/// admits any value at or above zero, which is every value, and that is the
/// correct reading of "this device has never seen a `trust_epoch`". Modelling it
/// as `Option` and treating `None` as "accept anything" is the same behaviour
/// with a place for a bug to hide.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FloorSet {
    values: BTreeMap<FloorId, u64>,
}

/// A proposal that has been checked and may be applied.
///
/// Produced only by [`FloorSet::propose`]. There is no constructor, so an
/// unchecked value cannot reach [`FloorSet::apply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorProposal {
    accepted: Vec<(FloorId, u64)>,
}

impl FloorProposal {
    /// Which floors this proposal actually advances.
    ///
    /// ST-25's hardware-counter cadence branches on this: the TPM NV counter is
    /// incremented "**only** when a trust floor advances", never per commit.
    #[must_use]
    pub fn advances(&self) -> &[(FloorId, u64)] {
        &self.accepted
    }

    /// Whether any **trust** floor advances (ST-25's list).
    #[must_use]
    pub fn advances_a_trust_floor(&self) -> bool {
        self.accepted.iter().any(|(id, _)| {
            matches!(
                id,
                FloorId::TrustEpoch
                    | FloorId::AnchorVersion
                    | FloorId::MinAcceptableEpoch
                    | FloorId::DocVersion("TRUST_LIST" | "MEMBERSHIP" | "POLICY_BUNDLE")
            )
        })
    }

    /// Whether this proposal changes anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty()
    }
}

impl FloorSet {
    /// An empty floor set — every floor at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuilds a floor set from the Tier-1 anchor or from persisted state.
    #[must_use]
    pub fn from_pairs(pairs: impl IntoIterator<Item = (FloorId, u64)>) -> Self {
        Self {
            values: pairs.into_iter().collect(),
        }
    }

    /// The value held for `id`. Absent is zero.
    #[must_use]
    pub fn get(&self, id: &FloorId) -> u64 {
        self.values.get(id).copied().unwrap_or(0)
    }

    /// Every floor held, for the anchor.
    pub fn pairs(&self) -> impl Iterator<Item = (&FloorId, u64)> {
        self.values.iter().map(|(k, v)| (k, *v))
    }

    /// Whether any floor is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// ST-23 step 2 — checks a set of proposed floor values.
    ///
    /// > "compute new floor set; **if any floor would decrease → REFUSE**"
    ///
    /// A value equal to the held floor is accepted and is **not** an advance: it
    /// is a re-assertion, which happens on every reconnect and must not
    /// increment a hardware counter.
    ///
    /// The check is **all or nothing**: one decreasing floor refuses the whole
    /// proposal, because ST-12b's multi-key rule means the caller intends these
    /// to commit together, and applying the acceptable half would produce
    /// exactly the split state that rule exists to prevent.
    ///
    /// # Errors
    ///
    /// [`StoreError::FloorWouldDecrease`] naming the first floor that would go
    /// backwards.
    pub fn propose(&self, proposed: &[(FloorId, u64)]) -> Result<FloorProposal> {
        let mut accepted = Vec::new();
        for (id, value) in proposed {
            let held = self.get(id);
            if *value < held {
                return Err(StoreError::FloorWouldDecrease {
                    floor: id.category(),
                    offered: *value,
                    held,
                });
            }
            if *value > held {
                accepted.push((id.clone(), *value));
            }
        }
        Ok(FloorProposal { accepted })
    }

    /// Applies a checked proposal.
    ///
    /// Takes a [`FloorProposal`], which only [`Self::propose`] can produce — so
    /// there is no path that writes a floor without having compared it.
    pub fn apply(&mut self, proposal: &FloorProposal) {
        for (id, value) in &proposal.accepted {
            // Defence in depth: even here the write is a max, so a proposal
            // applied twice against a set that moved in between cannot lower it.
            let slot = self.values.entry(id.clone()).or_insert(0);
            *slot = (*slot).max(*value);
        }
    }

    /// The element-wise maximum of two floor sets.
    ///
    /// ST-24 row 4: when the anchor lost an update, "floors := `max(anchor,
    /// vault)`". The direction is not arbitrary — taking the *minimum* would
    /// silently lower a floor, which is the rollback the anchor exists to
    /// prevent.
    #[must_use]
    pub fn merge_max(&self, other: &Self) -> Self {
        let mut out = self.values.clone();
        for (id, v) in &other.values {
            let slot = out.entry(id.clone()).or_insert(0);
            *slot = (*slot).max(*v);
        }
        Self { values: out }
    }

    /// Whether `self` is at or above `other` for every floor `other` holds.
    ///
    /// The predicate ST-24 rows 2 and 5 use to decide which documents must be
    /// re-pulled.
    #[must_use]
    pub fn dominates(&self, other: &Self) -> bool {
        other.values.iter().all(|(id, v)| self.get(id) >= *v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_floor_reads_as_zero_and_admits_anything() {
        let f = FloorSet::new();
        assert_eq!(f.get(&FloorId::TrustEpoch), 0);
        assert!(f.propose(&[(FloorId::TrustEpoch, 0)]).is_ok());
        assert!(f.propose(&[(FloorId::TrustEpoch, 9)]).is_ok());
    }

    /// **Attack test — the anti-rollback control.** A lower `trust_epoch` is
    /// refused, not applied. This is the mechanism that stops trust
    /// resurrection.
    #[test]
    fn a_lower_floor_is_refused_and_the_set_is_unchanged() {
        let mut f = FloorSet::new();
        let p = f.propose(&[(FloorId::TrustEpoch, 5)]).expect("advance");
        f.apply(&p);
        assert_eq!(f.get(&FloorId::TrustEpoch), 5);

        let err = f
            .propose(&[(FloorId::TrustEpoch, 4)])
            .expect_err("must refuse");
        assert!(matches!(
            err,
            StoreError::FloorWouldDecrease {
                floor: "trust_epoch",
                offered: 4,
                held: 5
            }
        ));
        assert_eq!(
            err.reason_code().as_str(),
            "AUTH.TRUST_EPOCH_ROLLBACK",
            "the refusal must carry the registered rollback code"
        );
        assert_eq!(f.get(&FloorId::TrustEpoch), 5, "the set must be untouched");
    }

    /// **Attack test.** ST-12b: a multi-key commit is all or nothing. A proposal
    /// mixing one legitimate advance with one rollback must refuse **both**, or
    /// the attacker gets the half they wanted.
    #[test]
    fn one_decreasing_floor_refuses_the_whole_proposal() {
        let mut f = FloorSet::new();
        let p = f
            .propose(&[(FloorId::TrustEpoch, 5), (FloorId::AnchorVersion, 3)])
            .expect("initial");
        f.apply(&p);

        assert!(f
            .propose(&[
                (FloorId::TrustEpoch, 6),    // legitimate
                (FloorId::AnchorVersion, 2), // a rollback
            ])
            .is_err());
        assert_eq!(f.get(&FloorId::TrustEpoch), 5, "no partial application");
        assert_eq!(f.get(&FloorId::AnchorVersion), 3);
    }

    /// Re-asserting the same value is not an advance. ST-25: the hardware
    /// counter is incremented "only when a trust floor advances", and a
    /// reconnect re-asserts every floor it holds.
    #[test]
    fn re_asserting_a_floor_is_not_an_advance() {
        let mut f = FloorSet::new();
        let p = f.propose(&[(FloorId::TrustEpoch, 5)]).expect("advance");
        f.apply(&p);
        let again = f.propose(&[(FloorId::TrustEpoch, 5)]).expect("re-assert");
        assert!(again.is_empty());
        assert!(!again.advances_a_trust_floor());
    }

    /// ST-25's cadence rule needs to distinguish a trust floor from any other.
    #[test]
    fn only_the_named_trust_floors_signal_a_hardware_counter_increment() {
        let f = FloorSet::new();
        assert!(f
            .propose(&[(FloorId::TrustEpoch, 1)])
            .expect("p")
            .advances_a_trust_floor());
        assert!(f
            .propose(&[(FloorId::DocVersion("POLICY_BUNDLE"), 1)])
            .expect("p")
            .advances_a_trust_floor());
        assert!(!f
            .propose(&[(FloorId::StoreSeq, 1)])
            .expect("p")
            .advances_a_trust_floor());
        assert!(!f
            .propose(&[(FloorId::DocVersion("RELAY_MAP"), 1)])
            .expect("p")
            .advances_a_trust_floor());
    }

    /// Per-peer floors are independent: advancing one peer's `generation` must
    /// not touch another's, or one peer's rotation would let another peer's
    /// stale statement through.
    #[test]
    fn per_peer_floors_are_independent() {
        let mut f = FloorSet::new();
        let a = FloorId::PeerGeneration(vec![0xaa; 32]);
        let b = FloorId::PeerGeneration(vec![0xbb; 32]);
        let p = f.propose(&[(a.clone(), 3)]).expect("a");
        f.apply(&p);
        assert_eq!(f.get(&a), 3);
        assert_eq!(f.get(&b), 0);
        assert!(f.propose(&[(a.clone(), 2)]).is_err());
        assert!(f.propose(&[(b, 2)]).is_ok());
    }

    /// ST-24 row 4: `max(anchor, vault)`, never the minimum.
    #[test]
    fn merging_two_floor_sets_takes_the_maximum() {
        let anchor = FloorSet::from_pairs([(FloorId::TrustEpoch, 7), (FloorId::AnchorVersion, 2)]);
        let vault = FloorSet::from_pairs([(FloorId::TrustEpoch, 5), (FloorId::ContractSeq, 11)]);
        let m = anchor.merge_max(&vault);
        assert_eq!(m.get(&FloorId::TrustEpoch), 7);
        assert_eq!(m.get(&FloorId::AnchorVersion), 2);
        assert_eq!(m.get(&FloorId::ContractSeq), 11);
    }

    #[test]
    fn domination_is_the_predicate_for_which_documents_must_be_repulled() {
        let high = FloorSet::from_pairs([(FloorId::TrustEpoch, 7)]);
        let low = FloorSet::from_pairs([(FloorId::TrustEpoch, 5)]);
        assert!(high.dominates(&low));
        assert!(!low.dominates(&high));
    }

    /// The refusal names a *category*, never a `device_id`: a per-peer floor's
    /// full name is `SENSITIVE`, and an error rendered into a Tier-2 export must
    /// not carry it.
    #[test]
    fn a_refusal_names_a_category_and_not_a_peer_identifier() {
        let mut f = FloorSet::new();
        let id = FloorId::PeerGeneration(vec![0xde; 32]);
        let p = f.propose(&[(id.clone(), 4)]).expect("advance");
        f.apply(&p);
        let err = f.propose(&[(id.clone(), 1)]).expect_err("refuse");
        let rendered = format!("{err}");
        assert!(rendered.contains("generation"));
        assert!(!rendered.contains("dede"), "the peer id leaked: {rendered}");
        // The full name is available, but only through an explicitly named
        // method a reviewer can grep for.
        assert!(id.name().contains("dede"));
    }
}
