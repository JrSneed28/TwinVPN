//! `peer_label` — the only form in which a device identifier may leave this
//! process.
//!
//! `CONTROL.PEER_NOT_ATTACHED` and `CONTROL.CALL_UNDELIVERABLE` each declare one
//! evidence field, `peer_label`. The obvious implementation — render the
//! `device_id` — would put a stable, global, cross-service identifier into every
//! log line the rendezvous emits, and an operator holding those logs could
//! reconstruct which devices tried to reach which, and when.
//!
//! `contracts/docs/trust-boundaries.md` §5 shows the shape the corpus already
//! chose for exactly this problem: the relay's `sub` is "a per-operator, per-day
//! pseudonym, never `device_id`", and `pair_tag` is "scoped to one relay and one
//! 10-minute bucket" so that "a tag observed at one relay is useless at
//! another". CF-7/A11 removed `peer_key_id` from the relay binding for the same
//! reason.
//!
//! # The construction, and why it is a counter rather than a hash
//!
//! A keyed hash of the `device_id` would still be a *function of* the
//! `device_id`: anyone who learns the key can invert it over the population, and
//! the key has to come from somewhere.
//!
//! A **sequential label assigned on first sight** is a function of arrival
//! order and nothing else. It carries no information about the identifier at
//! all, it is not comparable across processes or restarts, and there is no key
//! to leak. Two log lines for one device correlate *within one process
//! lifetime*, which is the whole and only property an operator needs to follow
//! one incident — the same trade `trust-boundaries.md` §7 makes for `SENSITIVE`
//! fields in a diagnostic bundle.
//!
//! The table is bounded and evicted oldest-first, so an attacker cycling
//! fabricated targets cannot grow it and, having cycled it, has cost themselves
//! only the correlation an operator would have had.

use std::collections::{BTreeMap, HashMap};

use crate::frame::DeviceId;

/// A per-process, per-lifetime pseudonym for a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerLabel(u64);

impl std::fmt::Display for PeerLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "peer-{}", self.0)
    }
}

/// A bounded `device_id → PeerLabel` table.
#[derive(Debug)]
pub struct Labeller {
    capacity: usize,
    by_device: HashMap<DeviceId, u64>,
    by_seq: BTreeMap<u64, DeviceId>,
    next: u64,
}

impl Labeller {
    /// A table holding at most `capacity` mappings.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            by_device: HashMap::new(),
            by_seq: BTreeMap::new(),
            next: 1,
        }
    }

    /// The label for `device_id`, assigning one on first sight.
    pub fn label(&mut self, device_id: DeviceId) -> PeerLabel {
        if let Some(&n) = self.by_device.get(&device_id) {
            return PeerLabel(n);
        }
        if self.by_device.len() >= self.capacity {
            if let Some((&oldest, &victim)) = self.by_seq.iter().next() {
                self.by_seq.remove(&oldest);
                self.by_device.remove(&victim);
            }
        }
        let n = self.next;
        self.next += 1;
        self.by_device.insert(device_id, n);
        self.by_seq.insert(n, device_id);
        PeerLabel(n)
    }

    /// How many mappings are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_device.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_device.is_empty()
    }
}

impl Default for Labeller {
    fn default() -> Self {
        Self::new(16_384)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_label_is_stable_within_one_process_lifetime() {
        let mut l = Labeller::default();
        assert_eq!(l.label([1u8; 32]), l.label([1u8; 32]));
        assert_ne!(l.label([1u8; 32]), l.label([2u8; 32]));
    }

    #[test]
    fn a_label_carries_nothing_about_the_identifier() {
        // Two processes see the same devices in different orders and produce
        // different labels: the mapping is arrival order, not identity.
        let mut a = Labeller::default();
        let mut b = Labeller::default();
        let _ = a.label([1u8; 32]);
        let first_in_a = a.label([2u8; 32]);
        let first_in_b = b.label([2u8; 32]);
        assert_ne!(first_in_a, first_in_b);
    }

    #[test]
    fn the_table_is_bounded_against_fabricated_targets() {
        let mut l = Labeller::new(8);
        for i in 0..10_000u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            let _ = l.label(id);
        }
        assert!(l.len() <= 8);
    }

    #[test]
    fn a_rendered_label_contains_no_device_bytes() {
        let mut l = Labeller::default();
        let rendered = l.label([0xabu8; 32]).to_string();
        assert!(!rendered.contains("ab"), "{rendered}");
        assert_eq!(rendered, "peer-1");
    }
}
