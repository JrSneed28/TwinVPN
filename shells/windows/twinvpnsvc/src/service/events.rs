//! The event stream: one drain, N subscribers, and §11.10's ladder.
//!
//! **Authority:** [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.10, MI-9, MI-9a, MI-16, MI-18, MI-19, MI-I5-2; ADR-0018 F-5, F-6;
//! `ownership.md` §10.8 **M-1**.
//!
//! # What was missing, and it was not a detail
//!
//! This service built a [`twinvpn_core::Core`], linked `twinvpn-mgmt`, and
//! served the management interface — and **never called `next_event` once**.
//! `next_event` appeared nowhere in this crate. So:
//!
//! - No client could be told that anything had changed. `event.resync`
//!   returned `MGMT.STREAM_COMPACTED` unconditionally, with a comment saying
//!   *"this build has no subscribed-topic snapshot to take"*, which was true.
//! - Every `Response.result` was `Vec::new()`. `Core::submit` publishes an
//!   operation's outcome as a `command.completed` event **before returning
//!   `Ok(())`**, so a service that never drained the stream threw every result
//!   away and answered `ok: true` with an empty body.
//! - The core's bounded ring filled behind an absent consumer and dropped
//!   oldest-first, and `INTERNAL.BUFFER_OVERFLOW` — the code whose whole
//!   purpose is that a drop is *reported* rather than silent — had nobody to
//!   report it to.
//!
//! `runtime::Service::shutdown` already documented the drain thread in its
//! ordering (*"the event stream closes so a drain thread unblocks"*). The
//! thread it described did not exist.
//!
//! # Where the ladder lives
//!
//! Not here. [`twinvpn_mgmt::fanout`] holds every decision — the watermarks,
//! the eviction rungs, the gap bookkeeping, MI-19's marker ordering, the MI-9
//! snapshot and the pending-completion registry — because they are properties
//! of the management interface and not of this carriage. `shells/linux` reads
//! the same ones. What is in this file is the **wake**: a `Mutex`, a `Notify`
//! and a thread, which are properties of this shell's runtime.
//!
//! ```text
//!   Core (F-5, one ordered stream)
//!        │  next_event(timeout)  ── blocking condvar, so a DEDICATED THREAD
//!        ▼
//!   Drain ──► Fanout ──┬──► pipe connection A   bounded queue + gap counter
//!                      ├──► pipe connection B
//!                      └──► Latest (the resync snapshot, per topic)
//! ```

use std::sync::{Arc, Mutex};

use twinvpn_core::{CoreEvent, CoreEventKind};

use crate::mi::wire::Event;

pub use twinvpn_mgmt::Frame as Delivery;
pub use twinvpn_mgmt::{Ledger, Snapshot, Subscriber, SUBSCRIBER_WATERMARK};

/// A `oneshot` sender, as the ledger's runtime-free sink.
///
/// `twinvpn-mgmt` settles a registration without knowing what a `oneshot` is —
/// it has no runtime and must not acquire one — so the channel that carries the
/// answer is supplied here, by the carriage that owns the runtime.
struct OneshotSink(tokio::sync::oneshot::Sender<Vec<u8>>);

impl twinvpn_mgmt::CompletionSink for OneshotSink {
    fn settle(self: Box<Self>, result: Vec<u8>) {
        // The receiver may already be gone — the client disconnected, and CD-2
        // makes that "cancellation is dropping the future". A failed send is
        // that case and is not an error.
        let _ = self.0.send(result);
    }
}

/// One drain, N subscribers, and the resync snapshot.
#[derive(Debug, Default)]
pub struct Fanout {
    inner: Mutex<Ledger>,
    /// Wakes the per-connection pumps.
    ///
    /// `notify_one` rather than `notify_waiters`, deliberately: it **stores a
    /// permit** when nobody is waiting, so a publish that lands between a
    /// pump's drain and its next `notified()` is not lost. `notify_waiters`
    /// would drop it, and the event would sit in the queue until the next
    /// unrelated publish — a delivery delay that looks exactly like a lost
    /// event.
    signal: tokio::sync::Notify,
}

impl Fanout {
    /// An empty fan-out.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a subscriber and returns its handle.
    pub fn subscribe(&self, watermark: usize) -> u64 {
        self.lock().subscribe(watermark)
    }

    /// Removes a subscriber. Idempotent.
    pub fn unsubscribe(&self, id: u64) {
        self.lock().unsubscribe(id);
    }

    /// Publishes one core event to every subscriber and to the snapshot.
    ///
    /// Returns the ids §11.10's third rung has just evicted.
    pub fn publish(&self, core_event: &CoreEvent) -> Vec<u64> {
        // MI-19's marker is not an event and does not take the event path: it
        // announces a gap the CORE's ring opened, upstream of this fan-out.
        if let CoreEventKind::Compacted { up_to_seq, dropped } = &core_event.kind {
            self.lock().publish_gap(
                *up_to_seq,
                &[(core_event.kind.topic().to_owned(), *dropped)],
            );
            self.signal.notify_one();
            return Vec::new();
        }

        let event = Event {
            topic: core_event.kind.topic().to_owned(),
            // **Forwarded, never encoded here.** `twinvpn-core` produces the
            // frozen contract bytes; a shell that encoded one would be the
            // second modeller MI-20 forbids, and would need `prost` in this
            // manifest to do it.
            payload: core_event.kind.encoded_payload(),
            // **MI-18.** "The tunnel went down" and "Dana took the tunnel down"
            // are different facts, and this is the field that keeps them
            // different.
            actor_principal: core_event.actor_principal.clone(),
            op: core_event.kind.op().map(str::to_owned),
        };

        let evicted = self.lock().publish(core_event.seq, &event);
        self.signal.notify_one();
        evicted
    }

    /// Registers a submission and returns its id and the channel its outcome
    /// will arrive on.
    ///
    /// There is no timeout on the wait, and none is needed: the caller awaits
    /// only after `submit` returned `Ok`, which means the event exists in the
    /// queue and the drain will reach it. A rejection, a gap that consumed it,
    /// and [`Fanout::close`] each resolve it too.
    pub fn expect_completion(
        &self,
        op: &'static str,
        since: u64,
    ) -> (u64, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        let (slot, receiver) = tokio::sync::oneshot::channel();
        let id = self
            .lock()
            .expect_completion(op, since, Box::new(OneshotSink(slot)));
        (id, receiver)
    }

    /// Withdraws a registration whose submission was rejected before it could
    /// publish a completion.
    pub fn cancel_completion(&self, id: u64) {
        self.lock().cancel_completion(id);
    }

    /// The next frame for one subscriber, or `None`.
    pub fn next_for(&self, id: u64) -> Option<Delivery> {
        self.lock().next_for(id)
    }

    /// **MI-9's snapshot**, taken under one lock with the cursor read inside it.
    #[must_use]
    pub fn resync(&self, id: u64) -> Snapshot {
        self.lock().resync(id)
    }

    /// The stream position, for `HelloAck.event_cursor`.
    #[must_use]
    pub fn cursor(&self) -> u64 {
        self.lock().cursor()
    }

    /// How many subscribers are attached.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.lock().subscriber_count()
    }

    /// Waits for the next wake.
    pub async fn wait(&self) {
        self.signal.notified().await;
    }

    /// Closes the fan-out during shutdown. Idempotent.
    ///
    /// **CB-6 is not touched by this.** ADR-0022 §11.4's Windows row: *"Shutdown
    /// MUST NOT remove enforcement — persistent WFP filters stay."* This closes
    /// a queue, not the installed rule set.
    pub fn close(&self) {
        self.lock().close();
        // Every pump wakes, finds the fan-out closed, and returns. Without this
        // a pump would sit in `wait()` forever and the connection task would
        // never join.
        self.signal.notify_waiters();
        self.signal.notify_one();
    }

    /// Whether [`Fanout::close`] has been called.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.lock().is_closed()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Ledger> {
        // A poisoned lock means a previous holder panicked while holding it. The
        // state behind it is a queue of events, not an invariant a panic can
        // corrupt into something unsafe, so the guard is taken rather than
        // propagating a panic into every subsequent client.
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
/// long the thread sits in one call so that shutdown is observed, and CD-3's
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
                specified_code = "MGMT.STREAM_COMPACTED",
                "a subscriber fell more than four watermarks behind and was evicted; \
                 §11.10's third rung"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn every_body_bearing_event_is_forwarded_from_the_core_and_never_encoded_here() {
        // CB-2's "translate, don't model": this shell holds no encoder, so the
        // assertion is DELEGATION rather than content. A test here that built a
        // code-bearing `ErrorEnvelope` would need `twinvpn-schema` in this
        // manifest, which is the dependency the design exists to avoid.
        let fanout = Fanout::new();
        let id = fanout.subscribe(64);
        for (seq, kind) in [
            diagnostic(),
            CoreEventKind::Transition(Box::default()),
            CoreEventKind::SessionEvent(Box::default()),
            CoreEventKind::CommandCompleted {
                op: "status.get",
                result: vec![4, 5, 6],
            },
        ]
        .into_iter()
        .enumerate()
        {
            let expected = kind.encoded_payload();
            fanout.publish(&core_event(seq as u64, kind));
            let Some(Delivery::Event { event, .. }) = fanout.next_for(id) else {
                panic!("an event")
            };
            assert_eq!(event.payload, expected);
        }
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
        let Some(Delivery::Event { event, .. }) = fanout.next_for(id) else {
            panic!("an event")
        };
        assert_eq!(event.actor_principal.as_deref(), Some("dana"));
    }

    #[test]
    fn a_core_gap_becomes_an_ordered_marker_and_not_a_diagnostic() {
        // MI-19. The core's ring overflowed upstream of this fan-out; a client
        // must be able to tell that from an ordinary diagnostic, and must get
        // the `up_to_seq` that makes the gap resyncable.
        let fanout = Fanout::new();
        let id = fanout.subscribe(64);
        fanout.publish(&core_event(
            9,
            CoreEventKind::Compacted {
                up_to_seq: 8,
                dropped: 3,
            },
        ));
        let Some(Delivery::Compacted(marker)) = fanout.next_for(id) else {
            panic!("a marker, not a diagnostic")
        };
        assert_eq!(marker.up_to_seq, 8);
        assert_eq!(marker.dropped_by_topic, vec![("diagnostic".to_owned(), 3)]);
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

    #[test]
    fn a_late_subscriber_does_not_receive_the_backlog() {
        // §11.10: the stream is live, and history is `event.resync`'s job.
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
    fn the_snapshot_carries_the_latest_per_topic_and_a_cursor() {
        let fanout = Fanout::new();
        let id = fanout.subscribe(64);
        fanout.publish(&core_event(1, diagnostic()));
        fanout.publish(&core_event(2, CoreEventKind::Transition(Box::default())));
        let snapshot = fanout.resync(id);
        assert_eq!(snapshot.cursor, 3);
        let topics: Vec<&str> = snapshot.rows.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(topics, vec!["transition", "diagnostic"], "TOPICS order");
    }
}
