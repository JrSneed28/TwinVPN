//! **ADR-0017 §11.10's backpressure ladder**, declared once for every carriage.
//!
//! **Authority:** [ADR-0017](../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.10 (ordering, the ladder, the watermarks), MI-9, MI-9a, MI-16, MI-18,
//! MI-19, MI-I5-2, MI-20; ADR-0018 F-5, CB-2; `ownership.md` §9.6 **X-4** and
//! §10.8 **M-1**.
//!
//! # Why this is here and not in a shell
//!
//! X-4 found the MI *envelope* declared three times and moved it into this
//! crate. The ladder that carries it was declared **once**, in
//! `shells/linux/twinvpnd`, and the consequence was not drift but **absence**:
//! `shells/windows` and `shells/macos` never drained the core's event stream at
//! all. Both build a core, both link this crate, both serve the management
//! interface — and neither ever popped the one totally ordered stream F-5 puts
//! every state change on. The Windows service said so at its own
//! `event.resync`, which returned `MGMT.STREAM_COMPACTED` unconditionally
//! because *"this build has no subscribed-topic snapshot to take"*.
//!
//! So a client on two of three desktop platforms learned that state had changed
//! by asking again, the bounded ring filled behind an absent consumer and
//! dropped oldest-first, and `INTERNAL.BUFFER_OVERFLOW` — the code whose whole
//! purpose is that a drop is **reported** rather than silent — had nobody to
//! report it to.
//!
//! The fix is X-4's applied one level out: the ladder is a property of the
//! management interface, so it belongs above the composition root with the
//! vocabulary it carries, not inside whichever shell happened to implement it
//! first.
//!
//! # What is here, and what deliberately is not
//!
//! Here: the **decisions** — which frame a subscriber gets next, when a gap is
//! recorded, when a marker is emitted, when a subscriber is evicted, what the
//! MI-9 snapshot contains, and which submission an outcome settles. All of it
//! is `std` only, synchronous, and takes no lock of its own.
//!
//! Not here: the **wakes**. A `Notify`, a condvar or a channel is a property of
//! the carriage's runtime, and this crate has no runtime and wants none —
//! putting `tokio` in the dependency graph of the crate every shell links would
//! be a much larger cost than the twenty lines of wrapper each shell keeps.
//! [`Ledger`] is therefore `&mut self` throughout: the shell owns the lock, the
//! wake, and nothing else.
//!
//! # CB-2: none of this is a domain decision
//!
//! > A shell may translate, marshal, schedule and render. It must not contain a
//! > branch whose condition is a TwinVPN domain fact.
//!
//! No branch below reads a `ConnectionState`, a `reason_code` class, a policy
//! verdict, a candidate priority or a timer. The conditions are queue depth, a
//! counter, a topic string and a sequence number — transport facts about one
//! connection. That is why the ladder is safely shared rather than being a
//! second place a network decision is made.

use std::collections::{HashMap, VecDeque};

use crate::envelope::{Compacted, Event};

/// ADR-0017 §11.10's desktop watermark: 256 events per subscriber.
///
/// The same number `twinvpn_core::events::DEFAULT_CAPACITY` uses for the core's
/// own queue, and for the same reason: it is §11.10's.
pub const SUBSCRIBER_WATERMARK: usize = 256;

/// §11.10's router-profile watermark: 64 events.
///
/// Named so the `H-EMB` profile has a constant to bind rather than a literal to
/// invent. No desktop build selects it.
pub const ROUTER_WATERMARK: usize = 64;

/// How far past its watermark a subscriber may fall before it is evicted rather
/// than compacted.
///
/// §11.10's ladder ends in eviction; this is where the third rung sits. Four
/// watermarks of accumulated gap means the client has not read a thousand
/// events on a desktop profile, at which point a resync is strictly cheaper for
/// both sides than continuing to count.
pub const EVICTION_MULTIPLE: u64 = 4;

/// The floor on a watermark, so a caller cannot configure a queue too small to
/// hold a marker and the event that follows it.
const MIN_WATERMARK: usize = 8;

/// One frame a subscriber will receive.
///
/// Two shapes and no third: an event, or MI-19's ordered gap marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// An event, with the sequence number it had on the core's stream.
    Event {
        /// The core's `seq`. Contiguity proves nothing was lost (MI-16).
        seq: u64,
        /// The body.
        event: Event,
    },
    /// MI-19's marker, emitted **before** any further event.
    Compacted(Compacted),
}

/// One subscriber's bounded queue, watermark and gap bookkeeping.
#[derive(Debug)]
pub struct Subscriber {
    watermark: usize,
    queue: VecDeque<Frame>,
    /// Set while a gap is outstanding, so the marker is emitted before any
    /// further event rather than beside one.
    pending_gap: Option<(u64, HashMap<String, u64>)>,
    /// Total events dropped for this subscriber, for the eviction rung.
    dropped_total: u64,
    evicted: bool,
}

impl Subscriber {
    /// A subscriber with `watermark` slots.
    #[must_use]
    pub fn new(watermark: usize) -> Self {
        Self {
            watermark: watermark.max(MIN_WATERMARK),
            queue: VecDeque::new(),
            pending_gap: None,
            dropped_total: 0,
            evicted: false,
        }
    }

    /// **MI-I5-2's non-blocking offer.** Never waits; returns `false` once the
    /// subscriber has been evicted.
    ///
    /// > non-blocking offer only — **no blocking send primitive may exist**
    ///
    /// A blocking offer would let one slow client stall the drain and therefore
    /// every other client, which is the inversion §11.10's whole ladder exists
    /// to prevent.
    pub fn offer(&mut self, seq: u64, event: Event) -> bool {
        if self.evicted {
            return false;
        }
        if self.queue.len() >= self.watermark {
            self.compact_oldest();
            if self.dropped_total > EVICTION_MULTIPLE * self.watermark as u64 {
                // Rung 3. The connection is closed by the caller; the queue is
                // released here so an evicted subscriber costs nothing.
                self.evicted = true;
                self.queue.clear();
                return false;
            }
        }
        self.queue.push_back(Frame::Event { seq, event });
        true
    }

    /// Rung 1: evict the **oldest**, and count it under its own topic.
    fn compact_oldest(&mut self) {
        let Some(evicted) = self.queue.pop_front() else {
            return;
        };
        let (seq, topic) = match evicted {
            Frame::Event { seq, ref event } => (seq, event.topic.clone()),
            // A marker is never evicted: it is the record of an earlier
            // eviction, and dropping it would turn a recorded gap back into a
            // silence, which is exactly MI-19's prohibition. It is pushed back
            // and the event after it goes instead.
            Frame::Compacted(_) => {
                self.queue.push_front(evicted);
                if let Some(Frame::Event { seq, event }) = self.queue.remove(1) {
                    self.record_gap(seq, &event.topic);
                }
                return;
            }
        };
        self.record_gap(seq, &topic);
    }

    fn record_gap(&mut self, seq: u64, topic: &str) {
        self.dropped_total += 1;
        let (up_to, counts) = self
            .pending_gap
            .take()
            .unwrap_or_else(|| (0, HashMap::new()));
        let mut counts = counts;
        *counts.entry(topic.to_owned()).or_insert(0) += 1;
        self.pending_gap = Some((up_to.max(seq), counts));
    }

    /// Records a gap this subscriber did not cause — the **core's** ring
    /// overflowed upstream of the fan-out.
    ///
    /// MI-19 does not distinguish where a drop happened, only that it is
    /// announced in order, so an upstream gap joins the same pending marker as a
    /// local one rather than racing it.
    pub fn record_upstream_gap(&mut self, up_to_seq: u64, dropped_by_topic: &[(String, u64)]) {
        let (up_to, mut counts) = self
            .pending_gap
            .take()
            .unwrap_or_else(|| (0, HashMap::new()));
        for (topic, count) in dropped_by_topic {
            *counts.entry(topic.clone()).or_insert(0) += *count;
            self.dropped_total += *count;
        }
        self.pending_gap = Some((up_to.max(up_to_seq), counts));
    }

    /// The next frame, or `None` when the queue is empty.
    ///
    /// **Rung 2.** A pending gap is returned first, always, and is cleared by
    /// being returned — so the marker appears exactly once and strictly before
    /// the events that follow it. A consumer that sees the marker knows to
    /// resync; a consumer that sees none knows it has missed nothing, and MI-9a
    /// requires those two to stay distinguishable.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Frame> {
        if let Some((up_to_seq, counts)) = self.pending_gap.take() {
            let mut dropped_by_topic: Vec<(String, u64)> = counts.into_iter().collect();
            // Sorted so the marker is byte-stable: a `HashMap`'s order is not,
            // and a client diffing two markers would see spurious changes.
            dropped_by_topic.sort_by(|a, b| a.0.cmp(&b.0));
            return Some(Frame::Compacted(Compacted {
                up_to_seq,
                dropped_by_topic,
            }));
        }
        self.queue.pop_front()
    }

    /// Whether §11.10's third rung has fired for this subscriber.
    #[must_use]
    pub const fn is_evicted(&self) -> bool {
        self.evicted
    }

    /// How many events this subscriber has missed.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped_total
    }

    /// How many frames are queued.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Discharges any outstanding gap and clears the queue, for a resync.
    ///
    /// The snapshot **is** the recovery the marker asked for, so replaying the
    /// marker afterwards would send the client round the loop again.
    pub fn discharge(&mut self) {
        self.pending_gap = None;
        self.queue.clear();
    }
}

/// The **MI-9 snapshot**: the latest event on each topic, and the cursor.
///
/// > The snapshot MUST be taken under the agent's state lock with the cursor
/// > assigned **inside** it.
///
/// [`Ledger::resync`] copies the per-topic latest and reads the cursor in one
/// `&mut self` call, so a shell holding the ledger behind one lock gets exactly
/// that. A cursor read outside the lock would be a cursor for a *different*
/// snapshot, which is the bug MI-9's wording is written to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// The stream position this snapshot is current as of.
    pub cursor: u64,
    /// The most recent event on each topic that has one, in
    /// [`crate::fanout::TOPICS`] order.
    pub rows: Vec<(String, Event)>,
}

/// The five topics ADR-0017 §11.10 names.
///
/// Duplicated from `twinvpn_core::events::topics` **by value and on purpose**:
/// this crate is below the core in the graph and cannot name it, and a snapshot
/// needs a stable iteration order. `the_topic_list_matches_the_cores` in
/// `twinvpn-core` is the assertion that the two never drift.
pub const TOPICS: [&str; 5] = [
    "transition",
    "session",
    "diagnostic",
    "command.completed",
    "command.rejected",
];

/// The topic a `command.completed` event carries.
pub const TOPIC_COMMAND_COMPLETED: &str = "command.completed";

/// The topic a `command.rejected` event carries.
pub const TOPIC_COMMAND_REJECTED: &str = "command.rejected";

/// Where a settled submission's result is delivered.
///
/// A `oneshot::Sender`, a channel, a condvar — the ledger does not care and
/// must not, because that choice is the carriage's runtime and this crate has
/// none. `settle` consumes the sink, so a registration is answered exactly once
/// on every path.
pub trait CompletionSink: Send {
    /// Delivers the outcome. An empty body is a truthful answer for the two
    /// cases that are not a completion: a gap consumed the event, and shutdown
    /// closed the stream.
    fn settle(self: Box<Self>, result: Vec<u8>);
}

/// One submission waiting for the outcome the core published for it.
struct Pending {
    id: u64,
    op: &'static str,
    since: u64,
    sink: Box<dyn CompletionSink>,
}

impl core::fmt::Debug for Pending {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pending")
            .field("id", &self.id)
            .field("op", &self.op)
            .field("since", &self.since)
            .finish_non_exhaustive()
    }
}

/// N subscribers, the resync snapshot, and the pending-completion registry.
///
/// Synchronous and lock-free by construction: the shell holds this behind
/// whatever lock its runtime wants and does the waking itself.
#[derive(Debug, Default)]
pub struct Ledger {
    subscribers: HashMap<u64, Subscriber>,
    latest: HashMap<String, Event>,
    cursor: u64,
    next_id: u64,
    closed: bool,
    pending: Vec<Pending>,
}

impl Ledger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a subscriber and returns its handle.
    pub fn subscribe(&mut self, watermark: usize) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.subscribers.insert(id, Subscriber::new(watermark));
        id
    }

    /// Removes a subscriber. Idempotent — a connection that ends twice is a
    /// normal race, not an error.
    pub fn unsubscribe(&mut self, id: u64) {
        self.subscribers.remove(&id);
    }

    /// Publishes one event to every subscriber and to the snapshot.
    ///
    /// Returns the ids §11.10's third rung has just evicted, so the caller can
    /// close their connections rather than leaving them attached to a stream
    /// they are no longer on.
    ///
    /// **The settle is inside this call, under the caller's lock, on purpose.**
    /// The dispatcher that submitted this operation is waiting for exactly this
    /// event while holding the F-6 submission lock; resolving here — in the
    /// same call that assigns the cursor — is what makes `Response.result` a
    /// fact rather than a race.
    pub fn publish(&mut self, seq: u64, event: &Event) -> Vec<u64> {
        self.cursor = self.cursor.max(seq + 1);
        self.latest.insert(event.topic.clone(), event.clone());

        match event.topic.as_str() {
            TOPIC_COMMAND_COMPLETED => {
                if let Some(op) = event.op.as_deref() {
                    self.settle(seq, op, &event.payload);
                }
            }
            // A rejection settles it too, with an empty body: the diagnostic
            // travels on the response's own `diagnostic` field, and leaving the
            // dispatcher waiting would hang the connection.
            TOPIC_COMMAND_REJECTED => {
                if let Some(op) = event.op.as_deref() {
                    self.settle(seq, op, &[]);
                }
            }
            _ => {}
        }

        let mut evicted = Vec::new();
        for (id, subscriber) in &mut self.subscribers {
            if !subscriber.offer(seq, event.clone()) && subscriber.is_evicted() {
                evicted.push(*id);
            }
        }
        for id in &evicted {
            self.subscribers.remove(id);
        }
        evicted
    }

    /// Publishes MI-19's gap marker: the **core's** ring dropped events before
    /// the fan-out ever saw them.
    ///
    /// Every outstanding registration is settled empty rather than left waiting
    /// for a body that has been dropped.
    pub fn publish_gap(&mut self, up_to_seq: u64, dropped_by_topic: &[(String, u64)]) {
        self.cursor = self.cursor.max(up_to_seq + 1);
        for subscriber in self.subscribers.values_mut() {
            subscriber.record_upstream_gap(up_to_seq, dropped_by_topic);
        }
        self.settle_all_empty();
    }

    /// Registers a submission and returns its id.
    ///
    /// # Why a registration and not a peek at the queue
    ///
    /// `Core::submit` publishes the operation's result as a `command.completed`
    /// event **synchronously, before returning `Ok(())`** — so the result is not
    /// returned, it is published, and the only reader of the core's stream is
    /// the drain. A dispatcher that peeked at the queue would either race the
    /// drain (sometimes finding the event, sometimes not — non-determinism in a
    /// client's `Response.result`, which is worse than an honest empty) or steal
    /// it from the drain and break the one ordered stream.
    ///
    /// So the dispatcher **registers before submitting** and the drain resolves
    /// it as the event passes. Two facts make the match exact:
    ///
    /// 1. The **F-6 submission lock** is held by the registering dispatcher, so
    ///    no other submission is in flight.
    /// 2. `since` is the cursor read **before** the submission, so an event from
    ///    an earlier submission still queued is below it and is skipped by
    ///    sequence number rather than by hope.
    pub fn expect_completion(
        &mut self,
        op: &'static str,
        since: u64,
        sink: Box<dyn CompletionSink>,
    ) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.pending.push(Pending {
            id,
            op,
            since,
            sink,
        });
        id
    }

    /// Withdraws a registration whose submission was rejected before it could
    /// publish a completion.
    ///
    /// Without this, a rejected submission would leave an entry the drain would
    /// match against some later, unrelated call of the same operation.
    pub fn cancel_completion(&mut self, id: u64) {
        self.pending.retain(|p| p.id != id);
    }

    /// Resolves every registration this event settles.
    fn settle(&mut self, seq: u64, op: &str, result: &[u8]) {
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].op == op && seq >= self.pending[i].since {
                let pending = self.pending.remove(i);
                pending.sink.settle(result.to_vec());
            } else {
                i += 1;
            }
        }
    }

    /// Resolves every registration with an empty body.
    fn settle_all_empty(&mut self) {
        for pending in self.pending.drain(..) {
            pending.sink.settle(Vec::new());
        }
    }

    /// The next frame for one subscriber, or `None`.
    pub fn next_for(&mut self, id: u64) -> Option<Frame> {
        self.subscribers.get_mut(&id)?.next()
    }

    /// **MI-9's snapshot.**
    ///
    /// An empty `rows` is a truthful answer and is distinguishable from a
    /// refusal: it means the agent has published nothing on any subscribed topic
    /// since it started, which is current truth on a freshly-started agent.
    /// What MI-9a forbids is an empty snapshot that hides a **gap**, and the
    /// cursor beside it is what tells a client whether one occurred.
    pub fn resync(&mut self, id: u64) -> Snapshot {
        if let Some(subscriber) = self.subscribers.get_mut(&id) {
            subscriber.discharge();
        }
        let rows = TOPICS
            .iter()
            .filter_map(|topic| {
                self.latest
                    .get(*topic)
                    .map(|event| ((*topic).to_owned(), event.clone()))
            })
            .collect();
        Snapshot {
            cursor: self.cursor,
            rows,
        }
    }

    /// The stream position, for `HelloAck.event_cursor`.
    #[must_use]
    pub const fn cursor(&self) -> u64 {
        self.cursor
    }

    /// How many subscribers are attached.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// Closes the ledger during shutdown. Idempotent.
    ///
    /// **CB-6 is not touched by this.** Closing the event stream tells a drain
    /// thread to unblock; it does not remove the installed ruleset, which stays
    /// in the OS's custody so that the core going away cannot drop protection.
    pub fn close(&mut self) {
        self.closed = true;
        self.subscribers.clear();
        // Nothing more will be published, so anything still waiting for a body
        // is waiting forever.
        self.settle_all_empty();
    }

    /// Whether [`Ledger::close`] has been called.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(topic: &str) -> Event {
        Event {
            topic: topic.to_owned(),
            payload: Vec::new(),
            actor_principal: None,
            op: None,
        }
    }

    fn completion(op: &str, result: &[u8]) -> Event {
        Event {
            topic: TOPIC_COMMAND_COMPLETED.to_owned(),
            payload: result.to_vec(),
            actor_principal: None,
            op: Some(op.to_owned()),
        }
    }

    /// A sink that records into a shared cell, so a test can assert what a
    /// dispatcher would have received without a runtime.
    struct Cell(std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>);
    impl CompletionSink for Cell {
        fn settle(self: Box<Self>, result: Vec<u8>) {
            *self.0.lock().unwrap() = Some(result);
        }
    }
    /// What a settled registration left behind, shared with the test.
    type Settled = std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>;

    fn cell() -> (Settled, Box<dyn CompletionSink>) {
        let shared: Settled = std::sync::Arc::new(std::sync::Mutex::new(None));
        (shared.clone(), Box::new(Cell(shared)))
    }

    #[test]
    fn an_event_reaches_every_subscriber_in_order() {
        let mut ledger = Ledger::new();
        let a = ledger.subscribe(SUBSCRIBER_WATERMARK);
        let b = ledger.subscribe(SUBSCRIBER_WATERMARK);
        for seq in 0..3 {
            ledger.publish(seq, &event("transition"));
        }
        for id in [a, b] {
            for seq in 0..3 {
                assert!(
                    matches!(ledger.next_for(id), Some(Frame::Event { seq: s, .. }) if s == seq)
                );
            }
            assert!(ledger.next_for(id).is_none());
        }
    }

    #[test]
    fn a_slow_subscriber_is_compacted_and_the_marker_precedes_the_events() {
        // Rungs 1 and 2. The whole of MI-19: a drop is never a silence, and the
        // record of it arrives BEFORE the events that survived, never beside
        // one and never after.
        let mut ledger = Ledger::new();
        let id = ledger.subscribe(MIN_WATERMARK);
        for seq in 0..(MIN_WATERMARK as u64 + 3) {
            ledger.publish(seq, &event("transition"));
        }
        let Some(Frame::Compacted(marker)) = ledger.next_for(id) else {
            panic!("the marker comes first");
        };
        assert_eq!(marker.dropped_by_topic, vec![("transition".to_owned(), 3)]);
        assert_eq!(marker.up_to_seq, 2, "the highest seq the gap consumed");
        // And then events, with no second marker.
        let mut seen = 0;
        while let Some(frame) = ledger.next_for(id) {
            assert!(matches!(frame, Frame::Event { .. }), "exactly one marker");
            seen += 1;
        }
        assert_eq!(seen, MIN_WATERMARK);
    }

    #[test]
    fn the_marker_is_byte_stable_across_runs() {
        // A `HashMap`'s iteration order is not stable, and a client diffing two
        // markers would see changes that did not happen.
        let mut previous: Option<Vec<(String, u64)>> = None;
        for _ in 0..8 {
            let mut ledger = Ledger::new();
            let id = ledger.subscribe(MIN_WATERMARK);
            for (seq, topic) in TOPICS.iter().cycle().take(MIN_WATERMARK + 4).enumerate() {
                ledger.publish(seq as u64, &event(topic));
            }
            let Some(Frame::Compacted(marker)) = ledger.next_for(id) else {
                panic!("a marker")
            };
            if let Some(first) = &previous {
                assert_eq!(first, &marker.dropped_by_topic);
            }
            previous = Some(marker.dropped_by_topic);
        }
    }

    #[test]
    fn a_subscriber_four_watermarks_behind_is_evicted() {
        // Rung 3.
        let mut ledger = Ledger::new();
        let id = ledger.subscribe(MIN_WATERMARK);
        let mut evicted = Vec::new();
        for seq in 0..(MIN_WATERMARK as u64 * (EVICTION_MULTIPLE + 2)) {
            evicted.extend(ledger.publish(seq, &event("transition")));
        }
        assert_eq!(evicted, vec![id], "the ladder ends in eviction");
        assert_eq!(ledger.subscriber_count(), 0, "and the queue is released");
    }

    #[test]
    fn a_completion_settles_the_registration_that_preceded_it() {
        let mut ledger = Ledger::new();
        let (slot, sink) = cell();
        let since = ledger.cursor();
        ledger.expect_completion("tunnel.up", since, sink);
        ledger.publish(0, &completion("tunnel.up", b"body"));
        assert_eq!(slot.lock().unwrap().as_deref(), Some(&b"body"[..]));
    }

    #[test]
    fn an_earlier_events_completion_does_not_settle_a_later_registration() {
        // The `since` rule. Without it a queued completion from an EARLIER call
        // of the same operation would answer this one, and a client would get
        // another call's body.
        let mut ledger = Ledger::new();
        ledger.publish(0, &completion("tunnel.up", b"stale"));
        let (slot, sink) = cell();
        let since = ledger.cursor();
        ledger.expect_completion("tunnel.up", since, sink);
        // A completion at a sequence BELOW the registration is not ours.
        ledger.publish(0, &completion("tunnel.up", b"also stale"));
        assert!(slot.lock().unwrap().is_none());
        ledger.publish(since, &completion("tunnel.up", b"ours"));
        assert_eq!(slot.lock().unwrap().as_deref(), Some(&b"ours"[..]));
    }

    #[test]
    fn a_rejection_settles_empty_rather_than_hanging_the_connection() {
        let mut ledger = Ledger::new();
        let (slot, sink) = cell();
        ledger.expect_completion("tunnel.up", 0, sink);
        ledger.publish(
            0,
            &Event {
                topic: TOPIC_COMMAND_REJECTED.to_owned(),
                payload: b"the diagnostic travels on the response".to_vec(),
                actor_principal: None,
                op: Some("tunnel.up".to_owned()),
            },
        );
        assert_eq!(
            slot.lock().unwrap().as_deref(),
            Some(&[][..]),
            "settled, and settled EMPTY"
        );
    }

    #[test]
    fn a_gap_and_a_close_both_settle_rather_than_abandon() {
        // The two paths that are not a completion. Neither may leave a
        // dispatcher waiting on a body that will never arrive.
        for close_it in [false, true] {
            let mut ledger = Ledger::new();
            let (slot, sink) = cell();
            ledger.expect_completion("tunnel.up", 0, sink);
            if close_it {
                ledger.close();
            } else {
                ledger.publish_gap(9, &[("transition".to_owned(), 4)]);
            }
            assert_eq!(slot.lock().unwrap().as_deref(), Some(&[][..]));
        }
    }

    #[test]
    fn a_cancelled_registration_is_not_matched_by_a_later_call() {
        let mut ledger = Ledger::new();
        let (slot, sink) = cell();
        let id = ledger.expect_completion("tunnel.up", 0, sink);
        ledger.cancel_completion(id);
        ledger.publish(1, &completion("tunnel.up", b"someone else's"));
        assert!(slot.lock().unwrap().is_none());
    }

    #[test]
    fn an_upstream_gap_joins_the_pending_marker_rather_than_racing_it() {
        let mut ledger = Ledger::new();
        let id = ledger.subscribe(SUBSCRIBER_WATERMARK);
        ledger.publish_gap(5, &[("session".to_owned(), 2)]);
        ledger.publish_gap(9, &[("session".to_owned(), 1)]);
        let Some(Frame::Compacted(marker)) = ledger.next_for(id) else {
            panic!("one marker, not two")
        };
        assert_eq!(marker.up_to_seq, 9, "the later gap wins the high-water");
        assert_eq!(marker.dropped_by_topic, vec![("session".to_owned(), 3)]);
        assert!(ledger.next_for(id).is_none());
    }

    #[test]
    fn a_resync_discharges_the_marker_it_answers() {
        // The snapshot IS the recovery the marker asked for; replaying it would
        // send the client round the loop again.
        let mut ledger = Ledger::new();
        let id = ledger.subscribe(MIN_WATERMARK);
        for seq in 0..(MIN_WATERMARK as u64 + 3) {
            ledger.publish(seq, &event("transition"));
        }
        let snapshot = ledger.resync(id);
        assert_eq!(snapshot.cursor, MIN_WATERMARK as u64 + 3);
        assert_eq!(snapshot.rows.len(), 1);
        assert!(ledger.next_for(id).is_none(), "no marker survives a resync");
    }

    #[test]
    fn a_snapshot_holds_the_latest_of_each_topic_in_a_fixed_order() {
        let mut ledger = Ledger::new();
        let id = ledger.subscribe(SUBSCRIBER_WATERMARK);
        for (seq, topic) in TOPICS.iter().rev().enumerate() {
            ledger.publish(seq as u64, &event(topic));
        }
        let snapshot = ledger.resync(id);
        let order: Vec<&str> = snapshot.rows.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(order, TOPICS.to_vec(), "TOPICS order, not insertion order");
    }

    #[test]
    fn an_empty_snapshot_is_a_truthful_answer_and_not_a_refusal() {
        let mut ledger = Ledger::new();
        let id = ledger.subscribe(SUBSCRIBER_WATERMARK);
        let snapshot = ledger.resync(id);
        assert_eq!(snapshot.cursor, 0);
        assert!(snapshot.rows.is_empty(), "nothing published is not a gap");
    }

    #[test]
    fn a_watermark_below_the_floor_is_raised_to_it() {
        // A queue too small to hold a marker and the event after it could not
        // keep MI-19's ordering rule at all.
        let mut s = Subscriber::new(0);
        for seq in 0..=(MIN_WATERMARK as u64) {
            s.offer(seq, event("transition"));
        }
        assert!(matches!(s.next(), Some(Frame::Compacted(_))));
        assert!(matches!(s.next(), Some(Frame::Event { .. })));
    }
}
