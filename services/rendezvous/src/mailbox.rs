//! The bounded, TTL'd `CALL` jitter buffer — and nothing else.
//!
//! ADR-0002 §11.5 path \[3\] and **N-9**:
//!
//! > Rendezvous `CALL` and candidate-exchange payloads MUST NOT be written to
//! > the durable log, MUST NOT be replayed from a cursor, and MUST NOT survive
//! > their TTL. The rendezvous mailbox is a bounded, TTL'd jitter buffer and is
//! > **not durability**.
//!
//! # Why there is no durable variant, not even a disabled one
//!
//! `contracts/docs/contract-matrix.md` §1 category 4: treating an ephemeral
//! message as durable is a **cost, privacy and denial-of-freshness** failure.
//! `docs/protocol.md` §6.1 names the specific harm for candidates — a replayed
//! set probes "NAT mappings that expired and IP addresses now belonging to
//! someone else", producing connection storms and probe traffic to an
//! uninvolved third party, and *"reliable delivery makes this worse, because
//! the stale data is guaranteed to arrive."*
//!
//! So this type takes no store, no path, no connection string and no `persist`
//! flag. The durable option does not exist rather than defaulting off, which is
//! the difference between a property and a configuration.
//!
//! # The four ceilings
//!
//! An unauthenticated attacker must not be able to make this process allocate.
//! Four bounds hold simultaneously. The per-payload bound is exercised at the
//! socket by `tests/hostile_input.rs`; the other three, and the TTL, by this
//! module's own tests and by `tests/connectivity_behavior.rs`, which drives them
//! through a real listener:
//!
//! | Bound | Default | Authority |
//! |---|---|---|
//! | per-payload bytes | 1200 | `limits.json envelope.c4_max_bytes`, applied by [`Verbatim`] before this module sees it |
//! | per-target depth | 8, drop-oldest | ADR-0002 §11.5 |
//! | distinct targets | 8192 | this service's own ceiling; see `README.md` §5 |
//! | total retained bytes | 32 MiB | as above |
//!
//! The TTL is the fifth and is what makes the other four survivable: at 30 s and
//! 32 MiB the buffer cannot become a store even if every other bound were
//! misconfigured.
//!
//! [`Verbatim`]: twinvpn_service_common::Verbatim

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use twinvpn_service_common::Verbatim;

use crate::frame::DeviceId;

/// One queued `CALL`, held as the octets that arrived.
#[derive(Debug)]
struct Entry {
    seq: u64,
    payload: Verbatim,
    expires_at: Instant,
}

/// The ceilings, all of them, in one place so a reviewer can read the whole
/// resource envelope without reading the code.
#[derive(Debug, Clone, Copy)]
pub struct MailboxLimits {
    /// ADR-0002 §11.5: capacity 8 per target, drop-oldest.
    pub capacity_per_target: usize,
    /// How many distinct targets may hold a mailbox at once.
    pub max_targets: usize,
    /// The process-wide ceiling on retained payload bytes.
    pub max_total_bytes: usize,
    /// ADR-0002 §11.5: TTL 30 s. The buffer is sized to the decay window.
    pub ttl: Duration,
}

impl Default for MailboxLimits {
    fn default() -> Self {
        Self {
            capacity_per_target: 8,
            max_targets: 8192,
            max_total_bytes: 32 * 1024 * 1024,
            ttl: Duration::from_millis(30_000),
        }
    }
}

/// What happened to a pushed `CALL`. Every variant maps to a registered code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Push {
    /// Queued with room to spare.
    Queued,
    /// Queued, and something older was dropped to make room — ADR-0002 §11.5's
    /// drop-oldest, reported as `CONTROL.MAILBOX_OVERFLOW`.
    QueuedAfterDrop,
    /// Refused. `CONTROL.CALL_UNDELIVERABLE`: "no live channel, no push token,
    /// mailbox expired or full".
    Refused,
}

/// In-memory only, bounded, TTL'd. There is no other kind.
#[derive(Debug)]
pub struct MailboxStore {
    limits: MailboxLimits,
    boxes: HashMap<DeviceId, VecDeque<Entry>>,
    /// `seq -> target`, so the globally oldest entry can be evicted in
    /// logarithmic time without scanning every mailbox.
    order: BTreeMap<u64, DeviceId>,
    next_seq: u64,
    total_bytes: usize,
    dropped: u64,
    expired: u64,
}

impl MailboxStore {
    /// A store bounded by `limits`.
    #[must_use]
    pub fn new(limits: MailboxLimits) -> Self {
        Self {
            limits,
            boxes: HashMap::new(),
            order: BTreeMap::new(),
            next_seq: 0,
            total_bytes: 0,
            dropped: 0,
            expired: 0,
        }
    }

    /// Queues `payload` for `target`.
    ///
    /// `now` is a parameter rather than a clock read so a decision is
    /// reproducible from its inputs (`architecture.md` §5.2 R-DET-1) and the TTL
    /// boundary is testable without sleeping.
    pub fn push(&mut self, target: DeviceId, payload: Verbatim, now: Instant) -> Push {
        self.sweep(now);

        let size = payload.len();
        // A payload that cannot fit the whole ceiling can never be queued, and
        // saying so is what gives CONTROL.CALL_UNDELIVERABLE a real path rather
        // than a theoretical one.
        if size > self.limits.max_total_bytes || self.limits.capacity_per_target == 0 {
            return Push::Refused;
        }

        let mut dropped_something = false;

        // 1. Per-target depth, drop-oldest (ADR-0002 §11.5).
        if let Some(q) = self.boxes.get(&target) {
            if q.len() >= self.limits.capacity_per_target {
                self.pop_front_of(target);
                dropped_something = true;
            }
        } else if self.boxes.len() >= self.limits.max_targets {
            // 2. Distinct-target ceiling. Evicting the globally oldest entry is
            //    the same drop-oldest rule applied one level up: a new target
            //    must never be able to refuse service to itself, and an
            //    attacker fabricating targets must not be able to refuse
            //    service to anyone else for longer than the TTL.
            if !self.evict_globally_oldest() {
                return Push::Refused;
            }
            dropped_something = true;
        }

        // 3. Total-bytes ceiling.
        while self.total_bytes + size > self.limits.max_total_bytes {
            if !self.evict_globally_oldest() {
                return Push::Refused;
            }
            dropped_something = true;
        }

        let seq = self.next_seq;
        self.next_seq += 1;
        self.total_bytes += size;
        self.order.insert(seq, target);
        self.boxes.entry(target).or_default().push_back(Entry {
            seq,
            payload,
            expires_at: now + self.limits.ttl,
        });

        if dropped_something {
            Push::QueuedAfterDrop
        } else {
            Push::Queued
        }
    }

    /// Drains `target`'s mailbox, discarding anything already expired.
    ///
    /// Draining is destructive by design: a `CALL` is delivered at most once and
    /// is **never replayed from a cursor** (N-9).
    pub fn take(&mut self, target: DeviceId, now: Instant) -> Vec<Verbatim> {
        self.sweep(now);
        let Some(q) = self.boxes.remove(&target) else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(q.len());
        for e in q {
            self.order.remove(&e.seq);
            self.total_bytes -= e.payload.len();
            out.push(e.payload);
        }
        out
    }

    /// Discards every entry past its TTL. Idempotent; safe to call on any path.
    pub fn sweep(&mut self, now: Instant) {
        let mut empty: Vec<DeviceId> = Vec::new();
        for (target, q) in &mut self.boxes {
            while q.front().is_some_and(|e| e.expires_at <= now) {
                let Some(e) = q.pop_front() else { break };
                self.order.remove(&e.seq);
                self.total_bytes -= e.payload.len();
                self.expired += 1;
            }
            if q.is_empty() {
                empty.push(*target);
            }
        }
        for t in empty {
            self.boxes.remove(&t);
        }
    }

    fn pop_front_of(&mut self, target: DeviceId) -> bool {
        let Some(q) = self.boxes.get_mut(&target) else {
            return false;
        };
        let Some(e) = q.pop_front() else {
            return false;
        };
        self.order.remove(&e.seq);
        self.total_bytes -= e.payload.len();
        self.dropped += 1;
        if q.is_empty() {
            self.boxes.remove(&target);
        }
        true
    }

    fn evict_globally_oldest(&mut self) -> bool {
        let Some((&seq, &target)) = self.order.iter().next() else {
            return false;
        };
        // Per-target order is FIFO by construction, so the globally oldest entry
        // is that target's front. Asserted rather than assumed.
        debug_assert_eq!(
            self.boxes
                .get(&target)
                .and_then(|q| q.front())
                .map(|e| e.seq),
            Some(seq)
        );
        self.pop_front_of(target)
    }

    /// Retained payload bytes across every mailbox.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Distinct targets currently holding a mailbox.
    #[must_use]
    pub fn target_count(&self) -> usize {
        self.boxes.len()
    }

    /// Entries dropped by an overflow rule since start.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Entries discarded by the TTL since start.
    #[must_use]
    pub const fn expired(&self) -> u64 {
        self.expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_schema::Channel;

    fn payload(n: usize) -> Verbatim {
        Verbatim::from_received(crate::testkit::payload(n), Channel::PeerDatagram).unwrap()
    }

    fn store(limits: MailboxLimits) -> (MailboxStore, Instant) {
        (MailboxStore::new(limits), Instant::now())
    }

    #[test]
    fn the_ninth_call_drops_the_oldest_and_says_so() {
        let (mut s, t0) = store(MailboxLimits::default());
        for _ in 0..8 {
            assert_eq!(s.push([1u8; 32], payload(16), t0), Push::Queued);
        }
        assert_eq!(s.push([1u8; 32], payload(16), t0), Push::QueuedAfterDrop);
        assert_eq!(
            s.take([1u8; 32], t0).len(),
            8,
            "capacity is a ceiling, not a hint"
        );
        assert_eq!(s.dropped(), 1);
    }

    #[test]
    fn nothing_survives_the_ttl() {
        let (mut s, t0) = store(MailboxLimits::default());
        s.push([2u8; 32], payload(64), t0);
        let after = t0 + Duration::from_millis(30_001);
        assert!(s.take([2u8; 32], after).is_empty());
        assert_eq!(s.total_bytes(), 0, "an expired entry must not hold memory");
        assert_eq!(s.expired(), 1);
    }

    #[test]
    fn a_call_is_delivered_at_most_once_and_never_replayed() {
        let (mut s, t0) = store(MailboxLimits::default());
        s.push([3u8; 32], payload(8), t0);
        assert_eq!(s.take([3u8; 32], t0).len(), 1);
        assert!(s.take([3u8; 32], t0).is_empty(), "N-9: never replayed");
    }

    #[test]
    fn fabricated_targets_cannot_grow_the_process_without_bound() {
        let limits = MailboxLimits {
            max_targets: 4,
            ..MailboxLimits::default()
        };
        let (mut s, t0) = store(limits);
        for i in 0..1000u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            s.push(id, payload(1200), t0);
        }
        assert!(s.target_count() <= 4);
        assert!(s.total_bytes() <= 4 * 8 * 1200);
    }

    #[test]
    fn the_total_byte_ceiling_holds_even_with_room_in_every_mailbox() {
        let limits = MailboxLimits {
            max_total_bytes: 4_000,
            ..MailboxLimits::default()
        };
        let (mut s, t0) = store(limits);
        for i in 0..100u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            s.push(id, payload(1200), t0);
        }
        assert!(s.total_bytes() <= 4_000, "observed {}", s.total_bytes());
    }

    #[test]
    fn a_payload_larger_than_the_whole_ceiling_is_refused_not_queued() {
        let limits = MailboxLimits {
            max_total_bytes: 100,
            ..MailboxLimits::default()
        };
        let (mut s, t0) = store(limits);
        assert_eq!(s.push([4u8; 32], payload(200), t0), Push::Refused);
        assert_eq!(s.total_bytes(), 0);
    }
}
