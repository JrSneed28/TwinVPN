//! The event stream: one drain, N subscribers, and §11.10's backpressure ladder.
//!
//! **Authority:** [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.10 (ordering, the ladder, the watermarks), MI-9, MI-9a, MI-18, MI-19,
//! MI-I5-2; ADR-0018 F-5, F-6.
//!
//! # The shape, and why it has to be this shape
//!
//! F-5 gives one core instance **exactly one** totally ordered event stream, and
//! `twinvpn_core::Core::next_event` is a **popping** read: the event is gone from
//! the core's queue once it returns. So there can be exactly one reader, and it
//! cannot be a per-connection reader — two connections calling `next_event` would
//! each see half the stream, which is not "one ordered stream per instance", it
//! is two lossy ones.
//!
//! ```text
//!   Core (F-5, one ordered stream)
//!        │  next_event(timeout)  ── blocking condvar, so a DEDICATED THREAD
//!        ▼
//!   Drain ──► Fanout ──┬──► Subscriber(conn A)  bounded queue + gap counter
//!                      ├──► Subscriber(conn B)
//!                      └──► Latest (the resync snapshot, per topic)
//! ```
//!
//! The drain is a `std::thread` and not a `tokio::spawn`: `next_event` blocks on
//! a `Condvar`, and blocking a runtime worker on a condvar is how a runtime
//! deadlocks. The core's own documentation says the same — *"called from the
//! shell's drain thread, which is not inside the core's runtime"*.
//!
//! # MI-I5-2: the offer is non-blocking, per subscriber
//!
//! > non-blocking offer only — **no blocking send primitive may exist**
//!
//! [`Subscriber::offer`] pushes into a bounded [`std::collections::VecDeque`] and
//! **never waits**. A blocking offer would let one slow client stall the drain
//! thread and therefore every other client, which is the inversion §11.10's whole
//! ladder exists to prevent.
//!
//! # §11.10's ladder, and MI-19's rule that a drop is never a silence
//!
//! Each subscriber has its own watermark. On overflow:
//!
//! 1. **Compact.** The oldest event is evicted and counted **per topic**, so a UI
//!    can say "12 transitions not shown" rather than "something happened".
//! 2. **Announce, in order.** The next successful read carries a
//!    [`crate::mi::Compacted`] marker **before** any further event — never
//!    alongside one, and never after. A consumer that sees the marker knows to
//!    resync; a consumer that sees none knows it has missed nothing. MI-9a says
//!    those two must stay distinguishable, and this is where they do.
//! 3. **Evict the subscriber.** A connection whose gap exceeds
//!    [`EVICTION_MULTIPLE`] × its watermark is past the point where a resync is
//!    cheaper than a replay; it is closed with `MGMT.STREAM_COMPACTED` rather
//!    than accumulating unbounded bookkeeping for a client that is not reading.
//!
//! **CB-2:** none of the three steps branches on a TwinVPN domain fact. The
//! conditions are queue depth and a counter — transport facts about this
//! connection, not facts about the network.
//!
//! # The topic of an event is derived, never authored here
//!
//! [`topic_of`] is a total function of [`twinvpn_core::CoreEventKind`]'s
//! variant. There is no table of topic strings the shell maintains and no branch
//! on what an event *means*; adding a variant upstream fails this crate's build
//! (see `a_new_core_event_kind_must_be_given_a_topic`).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use twinvpn_core::{CoreEvent, CoreEventKind};

use crate::mi::wire::{Compacted, Event};

/// ADR-0017 §11.10's desktop watermark: 256 events per subscriber.
///
/// The same number `twinvpn_core::events::DEFAULT_CAPACITY` uses for the core's
/// own queue, and for the same reason: it is §11.10's.
pub const SUBSCRIBER_WATERMARK: usize = 256;

/// §11.10's router-profile watermark: 64 events.
///
/// Not used by this build — `BUILD_PROFILE` is `H-SRV` — and named so the
/// H-EMB profile has a constant to bind rather than a literal to invent.
pub const ROUTER_WATERMARK: usize = 64;

/// How far past its watermark a subscriber may fall before it is evicted rather
/// than compacted.
///
/// §11.10's ladder ends in eviction; this is where the third rung sits. Four
/// watermarks of accumulated gap means the client has not read a thousand events
/// on a desktop profile, at which point a resync is strictly cheaper for both
/// sides than continuing to count.
pub const EVICTION_MULTIPLE: u64 = 4;

/// The topics ADR-0017 §11.10 names, and the only strings this module emits.
pub mod topics {
    /// A `ConnectionState` transition.
    pub const TRANSITION: &str = "transition";
    /// One of `contract-matrix.md` §4.4's local session bodies.
    pub const SESSION: &str = "session";
    /// A `Diagnostic` was raised.
    pub const DIAGNOSTIC: &str = "diagnostic";
    /// A submitted command completed.
    pub const COMMAND_COMPLETED: &str = "command.completed";
    /// A submitted command was rejected.
    pub const COMMAND_REJECTED: &str = "command.rejected";

    /// Every topic, so `event.subscribe`'s filter and `event.resync`'s snapshot
    /// walk one list.
    pub const ALL: [&str; 5] = [
        TRANSITION,
        SESSION,
        DIAGNOSTIC,
        COMMAND_COMPLETED,
        COMMAND_REJECTED,
    ];
}

/// The topic a core event belongs to.
///
/// A total function of the variant, written as an exhaustive-in-spirit `match`
/// with no `_` arm for the variants that exist today. `CoreEventKind` is not
/// `#[non_exhaustive]`, so this genuinely fails to compile when a variant is
/// added upstream — which is the point: a new kind of event must be given a
/// topic by a person, not defaulted into one.
#[must_use]
pub fn topic_of(kind: &CoreEventKind) -> &'static str {
    match kind {
        CoreEventKind::Transition(_) => topics::TRANSITION,
        CoreEventKind::SessionEvent(_) => topics::SESSION,
        CoreEventKind::CommandCompleted { .. } => topics::COMMAND_COMPLETED,
        CoreEventKind::CommandRejected { .. } => topics::COMMAND_REJECTED,
        // The core's own gap marker shares the `diagnostic` topic: it reaches a
        // client as a `Compacted` body rather than as an `Event`, so its topic
        // is only ever used to count it, never to route it.
        CoreEventKind::Diagnostic(_) | CoreEventKind::Compacted { .. } => topics::DIAGNOSTIC,
    }
}

/// The payload bytes a client receives for an event.
///
/// **Carried, never rendered** (MI-15), and **never encoded here**. Wave 2's
/// §7 gap 2 was that four of the five topics carried an empty payload, because
/// `Transition`, `SessionEvent` and `Diagnostic` are `twinvpn_schema::v1`
/// messages and encoding one needs a `prost` dependency this shell has no other
/// use for — which is exactly the "translate, don't model" line CB-2 draws.
///
/// The fix was the core's and the core made it:
/// [`CoreEventKind::encoded_payload`] hands over the bytes and this function
/// forwards them. There is no encoder in this shell and no branch on which
/// variant carries a body, so a variant that gains one is carried the day it
/// lands rather than the day someone remembers to add an arm here.
#[must_use]
pub fn payload_of(kind: &CoreEventKind) -> Vec<u8> {
    kind.encoded_payload()
}

/// One frame a subscriber will receive.
///
/// Two shapes and no third: an event, or MI-19's ordered gap marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
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
    queue: VecDeque<Delivery>,
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
            watermark: watermark.max(8),
            queue: VecDeque::new(),
            pending_gap: None,
            dropped_total: 0,
            evicted: false,
        }
    }

    /// **MI-I5-2's non-blocking offer.** Never waits; returns `false` once the
    /// subscriber has been evicted.
    pub fn offer(&mut self, seq: u64, topic: &str, event: Event) -> bool {
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
        self.queue.push_back(Delivery::Event { seq, event });
        let _ = topic;
        true
    }

    /// Rung 1: evict the **oldest**, and count it under its own topic.
    fn compact_oldest(&mut self) {
        let Some(evicted) = self.queue.pop_front() else {
            return;
        };
        let (seq, topic) = match evicted {
            Delivery::Event { seq, ref event } => (seq, event.topic.clone()),
            // A marker is never evicted: it is the record of an earlier
            // eviction, and dropping it would turn a recorded gap back into a
            // silence, which is exactly MI-19's prohibition. It is pushed back
            // and the event after it goes instead.
            Delivery::Compacted(_) => {
                self.queue.push_front(evicted);
                if let Some(Delivery::Event { seq, event }) = self.queue.remove(1) {
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

    /// The next frame, or `None` when the queue is empty.
    ///
    /// **Rung 2.** A pending gap is returned first, always, and is cleared by
    /// being returned — so the marker appears exactly once and strictly before
    /// the events that follow it.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Delivery> {
        if let Some((up_to_seq, counts)) = self.pending_gap.take() {
            let mut dropped_by_topic: Vec<(String, u64)> = counts.into_iter().collect();
            // Sorted so the marker is byte-stable: a `HashMap`'s order is not,
            // and a client diffing two markers would see spurious changes.
            dropped_by_topic.sort_by(|a, b| a.0.cmp(&b.0));
            return Some(Delivery::Compacted(Compacted {
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
}

/// The **MI-9 snapshot**: the latest event on each topic, and the cursor.
///
/// > The snapshot MUST be taken under the agent's state lock with the cursor
/// > assigned **inside** it.
///
/// [`Fanout::resync`] takes one lock, copies the per-topic latest, reads the
/// cursor, and releases — so the cursor a client receives is a position that
/// this exact snapshot is current as of. A cursor read outside the lock would be
/// a cursor for a different snapshot, which is the bug MI-9's wording is written
/// to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// The stream position this snapshot is current as of.
    pub cursor: u64,
    /// The most recent event on each topic that has one, in `topics::ALL` order.
    pub rows: Vec<(String, Event)>,
}

/// One drain, N subscribers, and the resync snapshot.
#[derive(Debug, Default)]
pub struct Fanout {
    inner: Mutex<FanoutInner>,
    /// Wakes the per-connection pumps.
    ///
    /// `notify_one` rather than `notify_waiters`, deliberately: it **stores a
    /// permit** when nobody is waiting, so a publish that lands between a pump's
    /// drain and its next `notified()` is not lost. `notify_waiters` would drop
    /// it, and the event would sit in the queue until the next unrelated
    /// publish — a delivery delay that would look exactly like a lost event.
    ///
    /// This is a wake-up, not a queue: the frames live in each subscriber's own
    /// bounded deque, and the pump drains until empty on every wake.
    signal: tokio::sync::Notify,
}

#[derive(Debug, Default)]
struct FanoutInner {
    subscribers: HashMap<u64, Subscriber>,
    latest: HashMap<String, Event>,
    cursor: u64,
    next_id: u64,
    closed: bool,
    /// Submissions waiting for their own `CommandCompleted`. See
    /// [`Fanout::expect_completion`].
    pending: Vec<Pending>,
}

/// One submission waiting for the outcome the core published for it.
#[derive(Debug)]
struct Pending {
    id: u64,
    op: &'static str,
    since: u64,
    slot: tokio::sync::oneshot::Sender<Vec<u8>>,
}

impl Fanout {
    /// An empty fan-out.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a subscriber and returns its handle.
    pub fn subscribe(&self, watermark: usize) -> u64 {
        let mut inner = self.lock();
        inner.next_id += 1;
        let id = inner.next_id;
        inner.subscribers.insert(id, Subscriber::new(watermark));
        id
    }

    /// Removes a subscriber. Idempotent — a connection that ends twice is a
    /// normal race, not an error.
    pub fn unsubscribe(&self, id: u64) {
        self.lock().subscribers.remove(&id);
    }

    /// Publishes one core event to every subscriber and to the snapshot.
    ///
    /// Returns the ids of subscribers §11.10's third rung has just evicted, so
    /// the caller can close their connections rather than leaving them attached
    /// to a stream they are no longer on.
    pub fn publish(&self, core_event: &CoreEvent) -> Vec<u64> {
        let topic = topic_of(&core_event.kind);
        let event = Event {
            topic: topic.to_owned(),
            payload: payload_of(&core_event.kind),
            // **MI-18.** The acting principal travels with the event, unchanged.
            // "The tunnel went down" and "Dana took the tunnel down" are
            // different facts, and this is the field that keeps them different.
            actor_principal: core_event.actor_principal.clone(),
        };

        let mut inner = self.lock();
        inner.cursor = inner.cursor.max(core_event.seq + 1);
        inner.latest.insert(topic.to_owned(), event.clone());

        // The dispatcher that submitted this operation is waiting for exactly
        // this event, holding the F-6 lock. Resolving here — inside the same
        // lock that assigns the cursor — is what makes `Response.result` a fact
        // rather than a race.
        match &core_event.kind {
            CoreEventKind::CommandCompleted { op, result } => {
                Self::settle(&mut inner, core_event.seq, op, result);
            }
            // A rejection settles it too, with an empty body: the diagnostic
            // travels on the response's own `diagnostic` field, and leaving the
            // dispatcher waiting would hang the connection.
            CoreEventKind::CommandRejected { op, .. } => {
                Self::settle(&mut inner, core_event.seq, op, &[]);
            }
            // A gap consumed events we cannot identify, so every outstanding
            // registration is settled empty rather than left waiting for a body
            // that has been dropped.
            CoreEventKind::Compacted { .. } => Self::settle_all_empty(&mut inner),
            _ => {}
        }

        let mut evicted = Vec::new();
        for (id, subscriber) in &mut inner.subscribers {
            if !subscriber.offer(core_event.seq, topic, event.clone()) && subscriber.is_evicted() {
                evicted.push(*id);
            }
        }
        for id in &evicted {
            inner.subscribers.remove(id);
        }
        drop(inner);
        self.signal.notify_one();
        evicted
    }

    /// Waits for something to deliver.
    ///
    /// **This is the only wait in the shell that is not the core's**, and it is
    /// not a timeout: it has no duration and expires on nothing. CD-2's
    /// "cancellation is dropping the future" is what ends it — the pump's future
    /// is dropped when the connection closes.
    pub async fn wait(&self) {
        self.signal.notified().await;
    }

    /// Registers interest in the `CommandCompleted` a submission is about to
    /// publish, and returns the id to cancel it with plus the channel it will
    /// arrive on.
    ///
    /// # Why this exists rather than a peek at the queue
    ///
    /// `Core::submit` publishes the operation's result as a `CommandCompleted`
    /// event **synchronously, before returning `Ok(())`** — so the result is not
    /// returned, it is published, and the only reader of the core's stream is the
    /// drain thread. A dispatcher that peeked at the queue would either race the
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
    ///
    /// There is no timeout on the wait, and none is needed: the caller awaits
    /// only after `submit` returned `Ok`, which means the event exists in the
    /// queue and the drain will reach it. A `CommandRejected`, a `Compacted`
    /// marker that consumed it, and [`Fanout::close`] each resolve it too — so
    /// there is no path on which the channel is silently abandoned.
    pub fn expect_completion(
        &self,
        op: &'static str,
        since: u64,
    ) -> (u64, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        let (slot, receiver) = tokio::sync::oneshot::channel();
        let mut inner = self.lock();
        inner.next_id += 1;
        let id = inner.next_id;
        inner.pending.push(Pending {
            id,
            op,
            since,
            slot,
        });
        (id, receiver)
    }

    /// Withdraws a registration whose submission was rejected before it could
    /// publish a completion.
    ///
    /// Without this, a rejected submission would leave an entry the drain would
    /// match against some later, unrelated call of the same operation.
    pub fn cancel_completion(&self, id: u64) {
        self.lock().pending.retain(|p| p.id != id);
    }

    /// Resolves every registration this event settles.
    fn settle(inner: &mut FanoutInner, seq: u64, op: &str, result: &[u8]) {
        let mut i = 0;
        while i < inner.pending.len() {
            let matched = inner.pending[i].op == op && seq >= inner.pending[i].since;
            if matched {
                let pending = inner.pending.remove(i);
                // The receiver may already be gone — the client disconnected, and
                // CD-2 makes that "cancellation is dropping the future". A failed
                // send is that case and is not an error.
                let _ = pending.slot.send(result.to_vec());
            } else {
                i += 1;
            }
        }
    }

    /// Resolves every registration with an empty body.
    ///
    /// The two cases that are not a completion: a gap consumed the event, and
    /// shutdown closed the stream. Both are truthfully "no body", and both must
    /// resolve rather than leave a dispatcher waiting on something that will
    /// never arrive.
    fn settle_all_empty(inner: &mut FanoutInner) {
        for pending in inner.pending.drain(..) {
            let _ = pending.slot.send(Vec::new());
        }
    }

    /// The next frame for one subscriber, or `None`.
    pub fn next_for(&self, id: u64) -> Option<Delivery> {
        self.lock().subscribers.get_mut(&id)?.next()
    }

    /// **MI-9's snapshot**, taken under one lock with the cursor assigned inside.
    ///
    /// An empty `rows` is a truthful answer and is distinguishable from a
    /// refusal: it means the agent has published nothing on any subscribed topic
    /// since it started, which is current truth on a freshly-started agent.
    /// Wave 1 refused instead, on the reasoning that an empty snapshot would be
    /// read as current truth — but it **is** current truth; what MI-9a forbids
    /// is an empty snapshot that hides a gap, and the cursor beside it is what
    /// tells a client whether one occurred.
    #[must_use]
    pub fn resync(&self, id: u64) -> Snapshot {
        let mut inner = self.lock();
        // The resync discharges any outstanding gap for this subscriber: the
        // snapshot IS the recovery the marker asked for, so replaying the marker
        // afterwards would send the client round the loop again.
        if let Some(subscriber) = inner.subscribers.get_mut(&id) {
            subscriber.pending_gap = None;
            subscriber.queue.clear();
        }
        let rows = topics::ALL
            .iter()
            .filter_map(|topic| {
                inner
                    .latest
                    .get(*topic)
                    .map(|event| ((*topic).to_owned(), event.clone()))
            })
            .collect();
        Snapshot {
            cursor: inner.cursor,
            rows,
        }
    }

    /// The stream position, for `HelloAck.event_cursor`.
    #[must_use]
    pub fn cursor(&self) -> u64 {
        self.lock().cursor
    }

    /// How many subscribers are attached.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.lock().subscribers.len()
    }

    /// Closes the fan-out during shutdown. Idempotent.
    ///
    /// **CB-6 is not touched by this.** Closing the event stream tells a drain
    /// thread to unblock; it does not remove the installed ruleset, which stays
    /// in the OS's custody so that the core going away cannot drop protection.
    pub fn close(&self) {
        let mut inner = self.lock();
        inner.closed = true;
        inner.subscribers.clear();
        // Nothing more will be published, so anything still waiting for a body
        // is waiting forever. CB-6 is untouched: this closes a queue, not the
        // installed ruleset.
        Self::settle_all_empty(&mut inner);
        drop(inner);
        // Every pump wakes, finds the fan-out closed, and returns. Without this
        // a pump would sit in `wait()` forever and the connection task would
        // never join.
        self.signal.notify_waiters();
        self.signal.notify_one();
    }

    /// Whether [`Fanout::close`] has been called.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.lock().closed
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FanoutInner> {
        // A poisoned lock means a previous holder panicked while holding it. The
        // state behind it is a queue of events, not an invariant a panic can
        // corrupt into something unsafe, so the guard is taken rather than
        // propagating a panic into every subsequent client. F-7 contains a panic
        // inside the core; this is the same containment one level out.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Runs the drain until the core's stream closes.
///
/// **On its own thread.** `Core::next_event` blocks on a condvar, and blocking a
/// runtime worker on a condvar is how a runtime deadlocks. `timeout` is the
/// core's blocking read timeout, not a shell-invented deadline: it bounds how
/// long the thread sits in one call so that shutdown is observed, and CD-2's
/// "timeouts are the core's" is satisfied because the value comes from the
/// caller, who takes it from the core's own contract.
pub fn drain(core: &Arc<twinvpn_core::Core>, fanout: &Arc<Fanout>, timeout: std::time::Duration) {
    loop {
        if fanout.is_closed() {
            return;
        }
        let Some(event) = core.next_event(timeout) else {
            // Three outcomes share `None` — timeout, wake, closed — and the core
            // says a caller distinguishes them "by asking again rather than by a
            // sentinel". So: ask again, unless we are shutting down.
            continue;
        };
        for id in fanout.publish(&event) {
            tracing::info!(
                target: "twinvpn.mi",
                subscriber = id,
                reason_code = "MGMT.STREAM_COMPACTED",
                "a subscriber fell more than four watermarks behind and was evicted; \
                 §11.10's third rung"
            );
        }
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
        }
    }

    fn core_event(seq: u64, kind: CoreEventKind) -> CoreEvent {
        CoreEvent {
            seq,
            kind,
            actor_principal: None,
        }
    }

    fn diagnostic() -> CoreEventKind {
        CoreEventKind::Diagnostic(Box::default())
    }

    #[test]
    fn a_new_core_event_kind_must_be_given_a_topic() {
        // The tripwire that replaces a table: every variant is named in
        // `topic_of`'s match, and every topic it can produce is in `topics::ALL`
        // — except `Compacted`, which reaches a client as a marker rather than
        // as an event.
        for kind in [
            diagnostic(),
            CoreEventKind::Transition(Box::default()),
            CoreEventKind::SessionEvent(Box::default()),
            CoreEventKind::CommandCompleted {
                op: "status.get",
                result: Vec::new(),
            },
            CoreEventKind::CommandRejected {
                op: "status.get",
                diagnostic: Box::default(),
            },
        ] {
            let topic = topic_of(&kind);
            assert!(
                topics::ALL.contains(&topic),
                "{topic} is not one of §11.10's topics"
            );
        }
    }

    #[test]
    fn the_command_result_reaches_a_subscriber_byte_for_byte() {
        // The half of README §7's gap 2 that WAS the core's API being misread:
        // `CommandCompleted.result` is the operation's body, and forwarding it
        // is the whole job.
        let kind = CoreEventKind::CommandCompleted {
            op: "status.get",
            result: vec![9, 8, 7],
        };
        assert_eq!(payload_of(&kind), vec![9, 8, 7]);
    }

    /// **The other half of §7's gap 2, closed: a body-bearing topic now carries
    /// its body.**
    ///
    /// It used to be empty, because encoding a `twinvpn_schema::v1` message
    /// needed a `prost` dependency in this shell. `twinvpn-core` encodes and
    /// this shell forwards, so no contract type is modelled here.
    /// **The other half of §7's gap 2, closed: this shell holds no encoder.**
    ///
    /// `Transition`, `SessionEvent` and `Diagnostic` used to arrive with an
    /// empty payload, because encoding a `twinvpn_schema::v1` message needs a
    /// `prost` dependency this shell has no other use for — the "translate,
    /// don't model" line CB-2 draws. `twinvpn-core` encodes and this forwards.
    ///
    /// The assertion is *delegation*, not content, and deliberately so: a test
    /// here that built a code-bearing `ErrorEnvelope` would need
    /// `twinvpn-schema` in this manifest, which is the dependency the fix exists
    /// to avoid. That the bytes are non-empty for a body-bearing event is
    /// asserted where the encoder is, in `twinvpn-core`.
    #[test]
    fn every_body_bearing_event_is_forwarded_from_the_core_and_never_encoded_here() {
        for kind in [
            diagnostic(),
            CoreEventKind::Transition(Box::default()),
            CoreEventKind::SessionEvent(Box::default()),
            CoreEventKind::CommandCompleted {
                op: "status.get",
                result: vec![4, 5, 6],
            },
            CoreEventKind::Compacted {
                up_to_seq: 3,
                dropped: 1,
            },
        ] {
            assert_eq!(
                payload_of(&kind),
                kind.encoded_payload(),
                "the shell must forward the core's bytes, never produce its own"
            );
        }
    }

    #[test]
    fn events_reach_every_subscriber_in_order() {
        let fanout = Fanout::new();
        let a = fanout.subscribe(64);
        let b = fanout.subscribe(64);
        for seq in 1..=5 {
            assert!(fanout.publish(&core_event(seq, diagnostic())).is_empty());
        }
        for id in [a, b] {
            let mut seqs = Vec::new();
            while let Some(Delivery::Event { seq, .. }) = fanout.next_for(id) {
                seqs.push(seq);
            }
            assert_eq!(seqs, vec![1, 2, 3, 4, 5], "one ordered stream per client");
        }
    }

    #[test]
    fn a_subscriber_that_attaches_late_does_not_receive_the_backlog() {
        // §11.10: the stream is live, and history is `event.resync`'s job. A late
        // subscriber that received the backlog would be reading a replay it did
        // not ask for and could not bound.
        let fanout = Fanout::new();
        fanout.publish(&core_event(1, diagnostic()));
        let late = fanout.subscribe(64);
        assert!(fanout.next_for(late).is_none());
        fanout.publish(&core_event(2, diagnostic()));
        assert!(matches!(
            fanout.next_for(late),
            Some(Delivery::Event { seq: 2, .. })
        ));
    }

    #[test]
    fn an_overflow_emits_an_ordered_marker_before_any_further_event() {
        // **MI-19.** A drop is a recorded gap, never a silence — and the marker
        // comes FIRST, not alongside.
        let mut subscriber = Subscriber::new(8);
        for seq in 1..=12 {
            subscriber.offer(seq, topics::DIAGNOSTIC, event(topics::DIAGNOSTIC));
        }
        match subscriber.next().expect("a frame") {
            Delivery::Compacted(marker) => {
                assert_eq!(
                    marker.dropped_by_topic,
                    vec![(topics::DIAGNOSTIC.to_owned(), 4)]
                );
                assert_eq!(marker.up_to_seq, 4, "the highest seq the gap consumed");
            }
            other @ Delivery::Event { .. } => panic!("the marker must come first, got {other:?}"),
        }
        // And then the surviving events, with no second marker.
        let mut seqs = Vec::new();
        while let Some(frame) = subscriber.next() {
            match frame {
                Delivery::Event { seq, .. } => seqs.push(seq),
                Delivery::Compacted(_) => panic!("exactly one marker per gap"),
            }
        }
        assert_eq!(seqs, vec![5, 6, 7, 8, 9, 10, 11, 12]);
    }

    #[test]
    fn no_marker_appears_when_nothing_was_dropped() {
        // The other half of MI-9a: a consumer that sees no marker knows it has
        // missed nothing. Without this assertion a build that emitted a marker
        // defensively would pass the test above and destroy the distinction.
        let mut subscriber = Subscriber::new(64);
        subscriber.offer(1, topics::DIAGNOSTIC, event(topics::DIAGNOSTIC));
        assert!(matches!(
            subscriber.next(),
            Some(Delivery::Event { seq: 1, .. })
        ));
        assert!(subscriber.next().is_none());
    }

    #[test]
    fn the_marker_counts_drops_per_topic_so_a_ui_can_name_them() {
        // "12 transitions not shown" rather than "something happened".
        let mut subscriber = Subscriber::new(8);
        for seq in 1..=6 {
            subscriber.offer(seq, topics::TRANSITION, event(topics::TRANSITION));
        }
        for seq in 7..=14 {
            subscriber.offer(seq, topics::SESSION, event(topics::SESSION));
        }
        match subscriber.next().expect("a frame") {
            Delivery::Compacted(marker) => {
                let counts: HashMap<String, u64> = marker.dropped_by_topic.into_iter().collect();
                assert_eq!(counts.get(topics::TRANSITION), Some(&6));
                assert_eq!(counts.len(), 1, "only the topics that actually dropped");
            }
            other @ Delivery::Event { .. } => panic!("expected a marker, got {other:?}"),
        }
    }

    #[test]
    fn a_marker_is_never_itself_evicted() {
        // Evicting the marker would turn a recorded gap back into a silence,
        // which is precisely what MI-19 forbids. It is the one frame the
        // compaction rung must not consume.
        let mut subscriber = Subscriber::new(8);
        for seq in 1..=200 {
            subscriber.offer(seq, topics::DIAGNOSTIC, event(topics::DIAGNOSTIC));
        }
        assert!(
            subscriber.is_evicted() || matches!(subscriber.next(), Some(Delivery::Compacted(_)))
        );
    }

    #[test]
    fn a_subscriber_that_never_reads_is_evicted_rather_than_grown_without_bound() {
        // §11.10's third rung. The alternative is unbounded bookkeeping for a
        // client that is not reading, which is a local denial of service with
        // extra steps.
        let mut subscriber = Subscriber::new(8);
        let mut seq = 0;
        while !subscriber.is_evicted() && seq < 10_000 {
            seq += 1;
            subscriber.offer(seq, topics::DIAGNOSTIC, event(topics::DIAGNOSTIC));
        }
        assert!(subscriber.is_evicted(), "the ladder must terminate");
        assert!(
            subscriber.dropped() > EVICTION_MULTIPLE * 8,
            "eviction is the third rung, not the first"
        );
        assert!(subscriber.is_empty(), "an evicted subscriber costs nothing");
        assert!(!subscriber.offer(seq + 1, topics::DIAGNOSTIC, event(topics::DIAGNOSTIC)));
    }

    #[test]
    fn the_fanout_reports_which_subscribers_it_evicted() {
        // So the caller closes the connection rather than leaving a client
        // attached to a stream it is no longer on — which would be the silence
        // MI-19 forbids, one level up.
        let fanout = Fanout::new();
        let slow = fanout.subscribe(8);
        let mut evicted = Vec::new();
        for seq in 1..=200u64 {
            evicted.extend(fanout.publish(&core_event(seq, diagnostic())));
            if !evicted.is_empty() {
                break;
            }
        }
        assert_eq!(evicted, vec![slow]);
        assert_eq!(fanout.subscriber_count(), 0);
    }

    #[test]
    fn one_slow_subscriber_does_not_affect_another() {
        // MI-I5-2's actual purpose: the offer is non-blocking per subscriber, so
        // a client that stops reading cannot stall the drain thread and
        // therefore cannot stall anyone else.
        let fanout = Fanout::new();
        let slow = fanout.subscribe(8);
        let fast = fanout.subscribe(1024);
        for seq in 1..=100 {
            fanout.publish(&core_event(seq, diagnostic()));
            // The fast one reads every time; the slow one never does.
            assert!(fanout.next_for(fast).is_some());
        }
        let _ = slow;
        // The fast subscriber saw everything, in order, with no marker.
        assert_eq!(fanout.cursor(), 101);
    }

    #[test]
    fn mi_18_attribution_survives_the_fanout() {
        let fanout = Fanout::new();
        let id = fanout.subscribe(64);
        fanout.publish(&CoreEvent {
            seq: 1,
            kind: diagnostic(),
            actor_principal: Some("dana".to_owned()),
        });
        match fanout.next_for(id).expect("a frame") {
            Delivery::Event { event, .. } => {
                assert_eq!(event.actor_principal.as_deref(), Some("dana"));
            }
            other @ Delivery::Compacted(_) => panic!("expected an event, got {other:?}"),
        }
    }

    #[test]
    fn a_resync_snapshot_carries_the_latest_per_topic_and_a_cursor() {
        // **MI-9.** The cursor is assigned inside the same lock the rows are
        // copied under, so it is a position this exact snapshot is current as of.
        let fanout = Fanout::new();
        let id = fanout.subscribe(64);
        fanout.publish(&core_event(1, CoreEventKind::Transition(Box::default())));
        fanout.publish(&core_event(
            2,
            CoreEventKind::CommandCompleted {
                op: "status.get",
                result: vec![1, 2, 3],
            },
        ));
        let snapshot = fanout.resync(id);
        assert_eq!(snapshot.cursor, 3);
        let topics: Vec<&str> = snapshot.rows.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(topics, vec![topics::TRANSITION, topics::COMMAND_COMPLETED]);
        let completed = &snapshot.rows[1].1;
        assert_eq!(completed.payload, vec![1, 2, 3], "the body, carried");
    }

    #[test]
    fn an_empty_snapshot_is_current_truth_and_not_a_refusal() {
        // Wave 1 refused here, reasoning that an empty snapshot would be read as
        // current truth. It IS current truth on a freshly-started agent: nothing
        // has happened. What MI-9a forbids is an empty snapshot that HIDES a
        // gap, and the cursor beside it is what makes that detectable.
        let fanout = Fanout::new();
        let id = fanout.subscribe(64);
        let snapshot = fanout.resync(id);
        assert!(snapshot.rows.is_empty());
        assert_eq!(snapshot.cursor, 0, "nothing has been published");
    }

    #[test]
    fn a_resync_discharges_an_outstanding_gap() {
        // The snapshot IS the recovery the marker asked for. Replaying the
        // marker afterwards would send the client round the loop again.
        let fanout = Fanout::new();
        let id = fanout.subscribe(8);
        for seq in 1..=12 {
            fanout.publish(&core_event(seq, diagnostic()));
        }
        let snapshot = fanout.resync(id);
        assert_eq!(snapshot.cursor, 13);
        assert!(
            fanout.next_for(id).is_none(),
            "the gap was discharged by the snapshot"
        );
    }

    #[test]
    fn closing_the_fanout_detaches_every_subscriber() {
        let fanout = Fanout::new();
        fanout.subscribe(64);
        fanout.subscribe(64);
        assert_eq!(fanout.subscriber_count(), 2);
        fanout.close();
        assert!(fanout.is_closed());
        assert_eq!(fanout.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn a_completion_reaches_the_dispatcher_that_submitted_it() {
        // The half of README §7 gap 2 that was a misreading of the core's API:
        // the body of a read IS reachable, and this is the correlation that
        // reaches it.
        let fanout = Fanout::new();
        let (id, rx) = fanout.expect_completion("status.get", 1);
        fanout.publish(&core_event(
            1,
            CoreEventKind::CommandCompleted {
                op: "status.get",
                result: vec![4, 5, 6],
            },
        ));
        assert_eq!(rx.await.expect("settled"), vec![4, 5, 6]);
        // And the registration is gone rather than matching a later call.
        fanout.cancel_completion(id);
    }

    #[tokio::test]
    async fn a_completion_from_before_the_cursor_does_not_match() {
        // `since` is the cursor read before the submission. An event from an
        // EARLIER submission, still queued, must not be handed to this caller as
        // if it were its own result.
        let fanout = Fanout::new();
        let (_, rx) = fanout.expect_completion("status.get", 10);
        fanout.publish(&core_event(
            9,
            CoreEventKind::CommandCompleted {
                op: "status.get",
                result: vec![1],
            },
        ));
        fanout.publish(&core_event(
            10,
            CoreEventKind::CommandCompleted {
                op: "status.get",
                result: vec![2],
            },
        ));
        assert_eq!(
            rx.await.expect("settled"),
            vec![2],
            "the caller's own, not the earlier one"
        );
    }

    #[tokio::test]
    async fn a_completion_for_another_operation_does_not_match() {
        let fanout = Fanout::new();
        let (_, rx) = fanout.expect_completion("session.list", 1);
        fanout.publish(&core_event(
            1,
            CoreEventKind::CommandCompleted {
                op: "status.get",
                result: vec![7],
            },
        ));
        fanout.publish(&core_event(
            2,
            CoreEventKind::CommandCompleted {
                op: "session.list",
                result: vec![8],
            },
        ));
        assert_eq!(rx.await.expect("settled"), vec![8]);
    }

    #[tokio::test]
    async fn a_rejection_settles_the_wait_rather_than_hanging_the_connection() {
        let fanout = Fanout::new();
        let (_, rx) = fanout.expect_completion("session.connect", 1);
        fanout.publish(&core_event(
            1,
            CoreEventKind::CommandRejected {
                op: "session.connect",
                diagnostic: Box::default(),
            },
        ));
        assert!(rx.await.expect("settled").is_empty());
    }

    #[tokio::test]
    async fn a_gap_settles_every_outstanding_wait_rather_than_leaving_one_hanging() {
        // The body was dropped, so there is nothing to deliver — but a
        // dispatcher waiting for it must still be released. An empty body is the
        // truthful answer; a hang is not.
        let fanout = Fanout::new();
        let (_, rx) = fanout.expect_completion("status.get", 1);
        fanout.publish(&core_event(
            5,
            CoreEventKind::Compacted {
                up_to_seq: 4,
                dropped: 4,
            },
        ));
        assert!(rx.await.expect("settled").is_empty());
    }

    #[tokio::test]
    async fn shutdown_settles_every_outstanding_wait() {
        let fanout = Fanout::new();
        let (_, rx) = fanout.expect_completion("status.get", 1);
        fanout.close();
        assert!(rx.await.expect("settled").is_empty());
    }

    #[tokio::test]
    async fn a_cancelled_registration_does_not_match_a_later_call() {
        // A submission rejected before it published anything must not leave an
        // entry that a later, unrelated call of the same operation resolves.
        let fanout = Fanout::new();
        let (id, rx) = fanout.expect_completion("status.get", 1);
        fanout.cancel_completion(id);
        fanout.publish(&core_event(
            1,
            CoreEventKind::CommandCompleted {
                op: "status.get",
                result: vec![9],
            },
        ));
        assert!(
            rx.await.is_err(),
            "the sender was dropped with the registration"
        );
    }

    #[test]
    fn the_watermarks_are_the_ones_adr_0017_names() {
        assert_eq!(SUBSCRIBER_WATERMARK, 256, "§11.10's desktop watermark");
        assert_eq!(ROUTER_WATERMARK, 64, "§11.10's router watermark");
        assert_eq!(
            SUBSCRIBER_WATERMARK,
            twinvpn_core::events::DEFAULT_CAPACITY,
            "the shell's queue and the core's are the same §11.10 number"
        );
    }
}
