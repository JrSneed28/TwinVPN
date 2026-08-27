//! Rendezvous hashing (HRW): how two cold peers converge on the same relay with
//! no coordination and no control plane.
//!
//! **Authority:** ADR-0006 §11.5 (the cold case), §11.7 rule 1 (redistribution);
//! `docs/reliability.md` §2.1; ADR-0018 CD-4 (`Env::rng_for("relay/hrw")`).
//!
//! # HRW, not "lowest `relay_id`"
//!
//! §11.5: HRW "is chosen over 'lowest `relay_id`' because it spreads pairs
//! across the fleet **proportionally to `capacity_weight`** with no coordination
//! — the same property §11.7 needs for region redistribution."
//!
//! §11.7 rule 1 adds the reason it decides *redistribution* while score decides
//! *ordinary selection*: "**Independent score-optimising choice — every device
//! picking 'the best surviving relay' — is precisely what creates the hot
//! spot.**"
//!
//! # The hash is `twinvpn-crypto`'s
//!
//! `w(r) = BLAKE2s(relay_id ‖ pair_id)` as a `u64`, scaled by
//! `capacity_weight`. BLAKE2s is a cryptographic primitive and CD-I2 restricts
//! those to `twinvpn-crypto`, so [`HrwHash`] is a trait.
//!
//! **Integration item.** `twinvpn-crypto` supplies
//! `blake2s(relay_id ‖ pair_id) -> [u8; 32]`, of which this module reads the
//! leading eight bytes as a little-endian `u64`.

use twinvpn_types::RelayId;

use crate::map::Relay;

/// The weight hash, supplied by `twinvpn-crypto`.
pub trait HrwHash: Send + Sync {
    /// `BLAKE2s(relay_id ‖ pair_id)`.
    fn weight_digest(&self, relay: RelayId, pair_id: &[u8; 16]) -> [u8; 32];
}

/// §11.5's `k`: both devices `BIND` all three highest-weight relays in parallel.
///
/// "ADR-0005 makes the marginal cost one `BIND` frame on an existing leg."
pub const K: usize = 3;

/// One relay's HRW weight for one pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Weight {
    /// The relay.
    pub relay: RelayId,
    /// The scaled weight. Higher wins.
    pub weight: u64,
}

/// Computes the weight of one relay for one pair.
///
/// The scaling is multiplicative in `capacity_weight`, which is what makes the
/// spread proportional to capacity: a relay with twice the weight wins twice as
/// many pairs, in expectation, with no coordination.
#[must_use]
pub fn weight(hash: &dyn HrwHash, relay: &Relay, pair_id: &[u8; 16]) -> Weight {
    let digest = hash.weight_digest(relay.id, pair_id);
    let raw = u64::from_le_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    // Scale into the top bits so `capacity_weight` dominates the ordering while
    // the hash still decides between equal-capacity relays. A capacity of zero
    // means "take no new pairs", and a zero weight expresses that exactly.
    let scaled = (raw >> 16).saturating_mul(u64::from(relay.capacity_weight));
    Weight {
        relay: relay.id,
        weight: scaled,
    }
}

/// The `k` highest-weight relays among the admissible set.
///
/// Both devices compute this from their **own cached maps**, with no message
/// exchanged. "Convergence fails only if the two maps disagree in the pair's top
/// 3, and the failure is **self-announcing**: the pending slot expires in 30 s
/// with `RELAY.PAIR_UNMATCHED`, after which the device advances to HRW ranks
/// 4–6."
#[must_use]
pub fn top_k(
    hash: &dyn HrwHash,
    admissible: &[&Relay],
    pair_id: &[u8; 16],
    k: usize,
) -> Vec<Weight> {
    let mut weights: Vec<Weight> = admissible
        .iter()
        .map(|r| weight(hash, r, pair_id))
        .collect();
    // Descending weight, then ascending relay_id, so two devices with identical
    // maps produce identical lists even when two weights collide.
    weights.sort_by(|a, b| {
        b.weight
            .cmp(&a.weight)
            .then_with(|| a.relay.to_array().cmp(&b.relay.to_array()))
    });
    weights.truncate(k);
    weights
}

/// The next rank band to try after a `RELAY.PAIR_UNMATCHED`.
///
/// §11.5: "the device advances to HRW ranks **4–6** under the infrastructure
/// backoff regime".
#[must_use]
pub fn next_band(
    hash: &dyn HrwHash,
    admissible: &[&Relay],
    pair_id: &[u8; 16],
    band: usize,
) -> Vec<Weight> {
    let mut weights: Vec<Weight> = admissible
        .iter()
        .map(|r| weight(hash, r, pair_id))
        .collect();
    weights.sort_by(|a, b| {
        b.weight
            .cmp(&a.weight)
            .then_with(|| a.relay.to_array().cmp(&b.relay.to_array()))
    });
    weights
        .into_iter()
        .skip(band.saturating_mul(K))
        .take(K)
        .collect()
}

/// Whether two devices' top-`k` lists converge.
///
/// Convergence is *any* shared member, not identical lists: both sides bind all
/// `k`, so one relay in common is enough for the pair to meet.
#[must_use]
pub fn converges(ours: &[Weight], theirs: &[Weight]) -> bool {
    ours.iter()
        .any(|a| theirs.iter().any(|b| a.relay == b.relay))
}
