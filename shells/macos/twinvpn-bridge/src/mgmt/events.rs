//! The event stream: one drain, N subscribers, and §11.10's ladder.
//!
//! **Authority:** [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.10, MI-9, MI-9a, MI-16, MI-18, MI-19, MI-I5-2, MI-20; ADR-0018 F-5;
//! ADR-0016 **PS-22**; `ownership.md` §10.8 **M-1**.
//!
//! # What was missing
//!
//! This bridge built a [`twinvpn_core::Core`], wrapped it in a `CommandSink`
//! that exposes exactly one method — `submit` — and **dropped the handle**. The
//! core's event stream was therefore unreachable by construction: `next_event`
//! appears nowhere in this crate, no client could be told that anything had
//! changed, and every `Response.result` was `Vec::new()` because `Core::submit`
//! publishes an operation's outcome as an *event* before it returns `Ok(())`.
//!
//! # PS-22 is why the drain is not in the mgmt server
//!
//! > The management-interface server … MUST be a module with **no dependency
//! > edge** onto the tunnel engine, packet-routing, or enforcement modules.
//!
//! So nothing in `mgmt/` names `twinvpn_core`, and that stays true: this module
//! takes `(seq, Event)` — the management vocabulary — and knows nothing about
//! where they came from. [`crate::host`] already names the core and owns the
//! conversion and the thread.
//!
//! # Why the completion wait is synchronous, and bounded
//!
//! Both carriages here are synchronous at the point a command is answered. The
//! socket carriage is `async`, but the **XPC** carriage is not: Swift owns the
//! listener and hands this crate one message at a time through the C ABI, so
//! `server::handle` is a plain function and cannot `await`.
//!
//! A registration therefore resolves through a [`std::sync::mpsc::sync_channel`]
//! read with a deadline supplied by the caller. It is not a protocol timeout and
//! CD-3 is untouched: it bounds how long **this carriage** waits before
//! answering with an empty body, and an empty body is exactly what this code
//! returned unconditionally before. The worst case is therefore the old
//! behaviour, reached only when the drain is starved.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use twinvpn_mi::wire::Event;

pub use twinvpn_mgmt::Frame as Delivery;
pub use twinvpn_mgmt::{Ledger, Snapshot, SUBSCRIBER_WATERMARK};

/// How long a carriage waits for the outcome the core published for it.
///
/// **Not a protocol deadline.** See the module header: exceeding it yields the
/// empty body this code used to return always.
pub const COMPLETION_WAIT: Duration = Duration::from_millis(250);

/// A bounded channel, as the ledger's runtime-free sink.
struct ChannelSink(std::sync::mpsc::SyncSender<Vec<u8>>);

impl twinvpn_mgmt::CompletionSink for ChannelSink {
    fn settle(self: Box<Self>, result: Vec<u8>) {
        // The receiver may already be gone — the client disconnected, or the
        // wait timed out. Neither is an error, and neither may block the drain.
        let _ = self.0.try_send(result);
    }
}

/// One drain, N subscribers, and the resync snapshot.
#[derive(Debug, Default)]
pub struct Fanout {
    inner: Mutex<Ledger>,
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

    /// Publishes one event. Returns the ids §11.10's third rung evicted.
    pub fn publish(&self, seq: u64, event: &Event) -> Vec<u64> {
        let evicted = self.lock().publish(seq, event);
        self.signal.notify_one();
        evicted
    }

    /// Publishes MI-19's gap marker for a gap the **core's** ring opened.
    pub fn publish_gap(&self, up_to_seq: u64, dropped_by_topic: &[(String, u64)]) {
        self.lock().publish_gap(up_to_seq, dropped_by_topic);
        self.signal.notify_one();
    }

    /// Registers a submission, runs it, and waits for the outcome the core
    /// published — bounded, and honest when the bound is reached.
    ///
    /// `run` is the submission itself, called **after** the registration and
    /// under the caller's own serialisation, so a completion still queued from
    /// an earlier call of the same operation is below the recorded cursor and
    /// is skipped by sequence number rather than by hope.
    pub fn submit_and_wait<E>(
        &self,
        op: &'static str,
        wait: Duration,
        run: impl FnOnce() -> Result<(), E>,
    ) -> Result<Vec<u8>, E> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let (id, since) = {
            let mut ledger = self.lock();
            let since = ledger.cursor();
            (
                ledger.expect_completion(op, since, Box::new(ChannelSink(sender))),
                since,
            )
        };
        let _ = since;
        match run() {
            Ok(()) => Ok(receiver.recv_timeout(wait).unwrap_or_default()),
            Err(error) => {
                // Rejected before it could publish anything, so the
                // registration would otherwise match some later, unrelated call
                // of the same operation.
                self.lock().cancel_completion(id);
                Err(error)
            }
        }
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
    /// **CB-6 is not touched by this.** Closing the event stream unblocks a
    /// drain; the installed pf anchor stays in the OS's custody so that the core
    /// going away cannot drop protection.
    pub fn close(&self) {
        self.lock().close();
        self.signal.notify_waiters();
        self.signal.notify_one();
    }

    /// Whether [`Fanout::close`] has been called.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.lock().is_closed()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Ledger> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A handle the drain publishes through, so [`crate::host`] can own the core and
/// this module can stay free of it (PS-22).
pub type Sink = Arc<Fanout>;

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
            topic: "command.completed".to_owned(),
            payload: result.to_vec(),
            actor_principal: None,
            op: Some(op.to_owned()),
        }
    }

    #[test]
    fn events_reach_every_subscriber_in_order() {
        let fanout = Fanout::new();
        let a = fanout.subscribe(64);
        let b = fanout.subscribe(64);
        for seq in 1..=4 {
            fanout.publish(seq, &event("transition"));
        }
        for id in [a, b] {
            let mut seqs = Vec::new();
            while let Some(Delivery::Event { seq, .. }) = fanout.next_for(id) {
                seqs.push(seq);
            }
            assert_eq!(seqs, vec![1, 2, 3, 4]);
        }
    }

    #[test]
    fn a_submission_receives_the_body_the_drain_publishes_for_it() {
        let fanout = Arc::new(Fanout::new());
        let publisher = Arc::clone(&fanout);
        let result = fanout.submit_and_wait::<()>("tunnel.up", COMPLETION_WAIT, || {
            // Stands in for the drain: `Core::submit` publishes the outcome
            // synchronously before returning, and the drain forwards it.
            publisher.publish(0, &completion("tunnel.up", b"body"));
            Ok(())
        });
        assert_eq!(result, Ok(b"body".to_vec()));
    }

    #[test]
    fn a_submission_nothing_answers_yields_an_empty_body_rather_than_hanging() {
        // The bound, and the reason it is safe: an empty body is exactly what
        // this code returned unconditionally before the drain existed.
        let fanout = Fanout::new();
        let result =
            fanout.submit_and_wait::<()>("tunnel.up", Duration::from_millis(20), || Ok(()));
        assert_eq!(result, Ok(Vec::new()));
    }

    #[test]
    fn a_rejected_submission_cancels_its_registration() {
        let fanout = Arc::new(Fanout::new());
        let outcome =
            fanout.submit_and_wait::<&str>("tunnel.up", Duration::from_millis(20), || Err("no"));
        assert_eq!(outcome, Err("no"));
        // A later, unrelated call of the same operation must not be answered by
        // the abandoned registration.
        let publisher = Arc::clone(&fanout);
        let second = fanout.submit_and_wait::<()>("tunnel.up", COMPLETION_WAIT, || {
            publisher.publish(1, &completion("tunnel.up", b"mine"));
            Ok(())
        });
        assert_eq!(second, Ok(b"mine".to_vec()));
    }

    #[test]
    fn a_core_gap_is_an_ordered_marker_that_keeps_its_up_to_seq() {
        let fanout = Fanout::new();
        let id = fanout.subscribe(64);
        fanout.publish_gap(8, &[("diagnostic".to_owned(), 3)]);
        let Some(Delivery::Compacted(marker)) = fanout.next_for(id) else {
            panic!("a marker, not a diagnostic")
        };
        assert_eq!(marker.up_to_seq, 8);
        assert_eq!(marker.dropped_by_topic, vec![("diagnostic".to_owned(), 3)]);
    }

    #[test]
    fn the_snapshot_carries_the_latest_per_topic_and_a_cursor() {
        let fanout = Fanout::new();
        let id = fanout.subscribe(64);
        fanout.publish(0, &event("diagnostic"));
        fanout.publish(1, &event("transition"));
        let snapshot = fanout.resync(id);
        assert_eq!(snapshot.cursor, 2);
        let topics: Vec<&str> = snapshot.rows.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(topics, vec!["transition", "diagnostic"], "TOPICS order");
    }

    #[test]
    fn closing_detaches_every_subscriber_and_settles_every_wait() {
        let fanout = Fanout::new();
        fanout.subscribe(64);
        assert_eq!(fanout.subscriber_count(), 1);
        fanout.close();
        assert!(fanout.is_closed());
        assert_eq!(fanout.subscriber_count(), 0);
    }
}
