//! The Tier-0 local ledger: a bounded ring that drops oldest-first and **says
//! so**.
//!
//! **Authority:** [ADR-0015](../../../../docs/adr/ADR-0015-observability-and-diagnostics.md)
//! §11.1 (Tier 0 is "always on, cannot be disabled, never leaves the device"),
//! §11.6 (the anti-silence mechanism),
//! `contracts/proto/twinvpn/v1/diagnostics.proto` (`INTERNAL.BUFFER_OVERFLOW`:
//! "the drop is **itself reported** rather than silently swallowed").
//!
//! # Why it is bounded, and why the bound is a caller's decision
//!
//! ADR-0015 §9 budgets the router class at well under a megabyte, and a ledger
//! that grew without bound would be the first thing to break there. The capacity
//! is a constructor argument rather than a constant because the same source
//! builds a desktop daemon and a 128 MB router (ADR-0018 §11.9), and a constant
//! would mean one of the two is wrong.
//!
//! # The drop is not a log line
//!
//! An overflow increments a counter that [`Ledger::overflow_diagnostic`] turns
//! into a registered `INTERNAL.BUFFER_OVERFLOW` with its declared `dropped`
//! evidence. `docs/reliability.md` §10's rule is that nothing fails silently;
//! a ring that quietly forgot its oldest entries would be exactly that.

use std::collections::VecDeque;

use twinvpn_env::MonotonicInstant;
use twinvpn_types::{codes, Component, Diagnostic, EvidenceValue, SessionId};

use crate::tier::Tier;

/// The smallest capacity a ledger may be built with.
///
/// A one-entry ring is indistinguishable from no ledger at all, and ADR-0015
/// makes Tier 0 undisableable; refusing a degenerate capacity keeps "always on"
/// from being satisfiable by a technicality.
pub const MIN_CAPACITY: usize = 16;

/// The router-class default (ADR-0015 §9's `< 512 KB` observability budget, and
/// ADR-0017's 16 KiB / 64-event router watermark).
pub const ROUTER_CAPACITY: usize = 512;

/// The desktop and server default.
pub const DEFAULT_CAPACITY: usize = 8_192;

/// One entry in the local ledger.
#[derive(Debug, Clone, PartialEq)]
pub struct LedgerEntry {
    /// Strictly increasing, never reused, and **not reset by a drop** — a gap in
    /// this sequence is what makes a compaction visible to a reader.
    pub seq: u64,
    /// When it was observed, on the injected monotonic clock (CD-1: never a
    /// wall clock, which is not comparable across a suspend).
    pub observed_at: MonotonicInstant,
    /// The `Session` it belongs to, where it has one.
    pub session_id: Option<SessionId>,
    /// What was recorded.
    pub record: Record,
}

/// What a ledger entry carries.
///
/// Deliberately a closed enum rather than a string: a ledger of formatted
/// sentences cannot be redacted mechanically, and ADR-0015 O-14 rules out
/// scrub-before-send.
#[derive(Debug, Clone, PartialEq)]
pub enum Record {
    /// A `Diagnostic` was raised.
    Diagnostic(Box<Diagnostic>),
    /// A state-machine transition, already encoded in its frozen form.
    Transition(Box<twinvpn_schema::v1::TransitionEvent>),
    /// A local, device-authoritative session or path observation
    /// (`contracts/docs/contract-matrix.md` §4.4).
    SessionEvent(Box<twinvpn_schema::v1::SessionEvent>),
}

/// The Tier-0 ring.
#[derive(Debug)]
pub struct Ledger {
    entries: VecDeque<LedgerEntry>,
    capacity: usize,
    next_seq: u64,
    dropped: u64,
    /// The sequence number of the newest entry a drop consumed, so a reader can
    /// say *where* the gap is rather than only that one exists.
    dropped_through: Option<u64>,
}

impl Ledger {
    /// A ledger holding at most `capacity` entries.
    ///
    /// `capacity` is clamped up to [`MIN_CAPACITY`] rather than rejected: Tier 0
    /// "cannot be disabled", so a caller that asks for a useless ledger gets a
    /// small one, never none.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(MIN_CAPACITY);
        Self {
            entries: VecDeque::with_capacity(capacity),
            capacity,
            next_seq: 1,
            dropped: 0,
            dropped_through: None,
        }
    }

    /// Records one entry, evicting the oldest if the ring is full.
    ///
    /// Returns the sequence number assigned.
    pub fn push(
        &mut self,
        observed_at: MonotonicInstant,
        session_id: Option<SessionId>,
        record: Record,
    ) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        if self.entries.len() == self.capacity {
            if let Some(evicted) = self.entries.pop_front() {
                self.dropped += 1;
                self.dropped_through = Some(evicted.seq);
            }
        }
        self.entries.push_back(LedgerEntry {
            seq,
            observed_at,
            session_id,
            record,
        });
        seq
    }

    /// Every entry, oldest first.
    pub fn entries(&self) -> impl Iterator<Item = &LedgerEntry> {
        self.entries.iter()
    }

    /// Entries at or after `seq` — `diag.log.tail{since}`'s backing read.
    pub fn since(&self, seq: u64) -> impl Iterator<Item = &LedgerEntry> {
        self.entries.iter().filter(move |e| e.seq >= seq)
    }

    /// Entries observed within `[from, to]` — the bounded window a Tier-1 bundle
    /// is built over (ADR-0015 §11.9 step 2).
    pub fn window(
        &self,
        from: MonotonicInstant,
        to: MonotonicInstant,
    ) -> impl Iterator<Item = &LedgerEntry> {
        self.entries
            .iter()
            .filter(move |e| e.observed_at >= from && e.observed_at <= to)
    }

    /// How many entries are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the ledger is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The ring's capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many entries have been dropped over this ledger's life.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The newest sequence number a drop consumed.
    #[must_use]
    pub const fn dropped_through(&self) -> Option<u64> {
        self.dropped_through
    }

    /// The registered diagnostic for the drops so far, or `None` if none.
    ///
    /// `INTERNAL.BUFFER_OVERFLOW` with its declared `dropped` evidence. This is
    /// what makes the ring's loss a *reported* fact: a caller emits it into its
    /// own event stream, and a bundle carries it, so "12 entries not shown" is
    /// sayable instead of a silent gap.
    #[must_use]
    pub fn overflow_diagnostic(&self) -> Option<Diagnostic> {
        if self.dropped == 0 {
            return None;
        }
        Some(
            Diagnostic::builder(codes::INTERNAL_BUFFER_OVERFLOW, Component::Diagnostics)
                .evidence("dropped", EvidenceValue::Uint(self.dropped))
                .build(),
        )
    }

    /// The tier this ledger is. Fixed: a ledger is Tier 0 by definition.
    #[must_use]
    pub const fn tier(&self) -> Tier {
        Tier::LocalLedger
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_types::codes;

    fn diag() -> Record {
        Record::Diagnostic(Box::new(
            Diagnostic::builder(codes::NET_NO_ROUTE, Component::RoutingEngine).build(),
        ))
    }

    fn at(us: u64) -> MonotonicInstant {
        MonotonicInstant::from_micros(us)
    }

    #[test]
    fn a_full_ring_drops_oldest_first_and_counts_it() {
        let mut l = Ledger::new(MIN_CAPACITY);
        for i in 0..(MIN_CAPACITY as u64 + 5) {
            l.push(at(i), None, diag());
        }
        assert_eq!(l.len(), MIN_CAPACITY);
        assert_eq!(l.dropped(), 5);
        assert_eq!(l.entries().next().expect("first").seq, 6);
    }

    #[test]
    fn sequence_numbers_are_never_reused_after_a_drop() {
        let mut l = Ledger::new(MIN_CAPACITY);
        for i in 0..40u64 {
            l.push(at(i), None, diag());
        }
        let seqs: Vec<u64> = l.entries().map(|e| e.seq).collect();
        let mut sorted = seqs.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(seqs, sorted, "sequence is strictly increasing and unique");
    }

    #[test]
    fn a_drop_is_reported_not_swallowed() {
        let mut l = Ledger::new(MIN_CAPACITY);
        assert!(l.overflow_diagnostic().is_none());
        for i in 0..=(MIN_CAPACITY as u64) {
            l.push(at(i), None, diag());
        }
        let d = l.overflow_diagnostic().expect("a drop must be reportable");
        assert_eq!(d.code().as_str(), "INTERNAL.BUFFER_OVERFLOW");
        assert_eq!(l.dropped_through(), Some(1));
    }

    #[test]
    fn tier_zero_cannot_be_configured_to_nothing() {
        assert_eq!(Ledger::new(0).capacity(), MIN_CAPACITY);
        assert_eq!(Ledger::new(1).capacity(), MIN_CAPACITY);
    }

    #[test]
    fn window_is_inclusive_at_both_ends() {
        let mut l = Ledger::new(64);
        for i in 0..10u64 {
            l.push(at(i * 10), None, diag());
        }
        assert_eq!(l.window(at(20), at(40)).count(), 3);
    }

    #[test]
    fn since_skips_entries_below_the_cursor() {
        let mut l = Ledger::new(64);
        for i in 0..10u64 {
            l.push(at(i), None, diag());
        }
        assert_eq!(l.since(5).count(), 6);
    }
}
