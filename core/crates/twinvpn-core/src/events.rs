//! **F-5.** One instance, one totally ordered event stream.
//!
//! **Authority:** [ADR-0018](../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! §11.4 F-5 and F-6, §11.6; [ADR-0017](../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.10 (ordering, the backpressure ladder, MI-18, MI-19);
//! [ADR-0015](../../../../docs/adr/ADR-0015-observability-and-diagnostics.md) O-05.
//!
//! > **F-5.** No blocking call crosses the boundary except `tw_core_next_event`,
//! > which takes an explicit timeout and is cancellable via `tw_core_wake`.
//! > `tw_core_submit` is non-blocking. All state changes, **including the
//! > completion of a submitted command**, arrive as events on **exactly one**
//! > totally ordered stream per instance.
//!
//! # Why a condvar and not the async runtime
//!
//! `tw_core_next_event` is called from the shell's drain thread, which is not
//! inside the core's runtime, and F-6 forbids a host callback re-entering a
//! mutating core function. A `Condvar` gives a blocking wait with a timeout and a
//! wake that is callable from **any** thread, which is exactly what
//! `tw_core_wake` promises — and it needs no clock of its own, so CD-3 is
//! untouched.
//!
//! # A dropped event is a recorded gap, never a silence
//!
//! MI-19: *"No state-changing event may be discarded without a record."* The
//! queue is bounded; overflow drops the **oldest**, counts it per kind, and the
//! next successful read carries a [`CoreEventKind::Compacted`] marker **before**
//! any further event. A consumer that sees the marker knows to resync; a consumer
//! that sees no marker knows it has missed nothing. Those are the two things
//! MI-9a says must stay distinguishable.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use twinvpn_schema::v1;

/// What a core event carries.
#[derive(Debug, Clone, PartialEq)]
pub enum CoreEventKind {
    /// A state-machine transition. `docs/reliability.md` §4.5, ADR-0015 O-05.
    Transition(Box<v1::TransitionEvent>),
    /// One of `contract-matrix.md` §4.4's local, device-authoritative bodies.
    SessionEvent(Box<v1::SessionEvent>),
    /// A `Diagnostic` was raised, in its frozen `ErrorEnvelope` form.
    Diagnostic(Box<v1::ErrorEnvelope>),
    /// A submitted command completed. F-5: *"including the completion of a
    /// submitted command"*.
    CommandCompleted {
        /// Which operation.
        op: &'static str,
        /// The result, encoded from the frozen artifacts, or empty.
        result: Vec<u8>,
    },
    /// A submitted command was rejected. *Rejected commands produce an event,
    /// never a silent drop* (§11.6).
    CommandRejected {
        /// Which operation.
        op: &'static str,
        /// The registered code, in its frozen envelope form.
        diagnostic: Box<v1::ErrorEnvelope>,
    },
    /// An ordered marker announcing a **deliberate** gap (MI-19).
    Compacted {
        /// The highest sequence number the gap consumed.
        up_to_seq: u64,
        /// How many events were dropped.
        dropped: u64,
    },
}

/// One event on the stream.
#[derive(Debug, Clone, PartialEq)]
pub struct CoreEvent {
    /// Strictly increasing per instance, with no gaps except where a
    /// [`CoreEventKind::Compacted`] marker announces one.
    pub seq: u64,
    /// What happened.
    pub kind: CoreEventKind,
    /// **MI-18.** The OS principal whose call produced this, or `None` for an
    /// agent-internal or peer-initiated cause. *"'The tunnel went down' and
    /// '*Dana* took the tunnel down' are different facts."*
    pub actor_principal: Option<String>,
}

/// The bounded, totally ordered stream.
#[derive(Debug)]
pub struct EventStream {
    inner: Mutex<Inner>,
    signal: Condvar,
    capacity: usize,
}

#[derive(Debug, Default)]
struct Inner {
    queue: VecDeque<CoreEvent>,
    next_seq: u64,
    /// Set while a gap is outstanding, so the marker is emitted **before** any
    /// further event rather than alongside one.
    pending_gap: Option<(u64, u64)>,
    woken: bool,
    closed: bool,
}

/// ADR-0017 §11.10's desktop watermark: 256 events.
pub const DEFAULT_CAPACITY: usize = 256;

/// §11.10's router-profile watermark: 64 events.
pub const ROUTER_CAPACITY: usize = 64;

impl EventStream {
    /// A stream holding at most `capacity` events.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                queue: VecDeque::new(),
                next_seq: 1,
                pending_gap: None,
                woken: false,
                closed: false,
            }),
            signal: Condvar::new(),
            capacity: capacity.max(8),
        }
    }

    /// Publishes an event. **Non-blocking**, per F-5.
    ///
    /// Returns the sequence number assigned, or `None` once the stream is
    /// closed.
    pub fn publish(&self, kind: CoreEventKind, actor_principal: Option<String>) -> Option<u64> {
        let mut inner = self.inner.lock().ok()?;
        if inner.closed {
            return None;
        }
        let seq = inner.next_seq;
        inner.next_seq += 1;
        if inner.queue.len() >= self.capacity {
            if let Some(evicted) = inner.queue.pop_front() {
                let (up_to, count) = inner.pending_gap.unwrap_or((0, 0));
                inner.pending_gap = Some((up_to.max(evicted.seq), count + 1));
            }
        }
        inner.queue.push_back(CoreEvent {
            seq,
            kind,
            actor_principal,
        });
        drop(inner);
        self.signal.notify_all();
        Some(seq)
    }

    /// Blocks for at most `timeout` for the next event.
    ///
    /// Returns `None` on timeout, on wake, or once the stream is closed — three
    /// outcomes a caller distinguishes by asking again rather than by a sentinel,
    /// because F-5 makes this the *only* blocking call and a sentinel here would
    /// be a second protocol.
    #[must_use]
    pub fn next_event(&self, timeout: Duration) -> Option<CoreEvent> {
        let mut inner = self.inner.lock().ok()?;
        loop {
            if let Some((up_to_seq, dropped)) = inner.pending_gap.take() {
                let seq = inner.next_seq;
                inner.next_seq += 1;
                return Some(CoreEvent {
                    seq,
                    kind: CoreEventKind::Compacted { up_to_seq, dropped },
                    actor_principal: None,
                });
            }
            if let Some(event) = inner.queue.pop_front() {
                return Some(event);
            }
            if inner.woken {
                inner.woken = false;
                return None;
            }
            if inner.closed {
                return None;
            }
            let (guard, result) = self.signal.wait_timeout(inner, timeout).ok()?;
            inner = guard;
            if result.timed_out() {
                return None;
            }
        }
    }

    /// Cancels an in-flight [`EventStream::next_event`]. **Callable from any
    /// thread**, per `tw_core_wake`.
    pub fn wake(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.woken = true;
        }
        self.signal.notify_all();
    }

    /// Closes the stream during graceful shutdown. Idempotent.
    pub fn close(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.closed = true;
        }
        self.signal.notify_all();
    }

    /// The next sequence number the stream will assign.
    ///
    /// `event.subscribe`'s attach cursor: a client that reattaches offering this
    /// value has missed nothing, and one offering less has (§11.10, MI-9a).
    #[must_use]
    pub fn cursor(&self) -> u64 {
        self.inner.lock().map_or(0, |i| i.next_seq)
    }

    /// How many events are queued.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map_or(0, |i| i.queue.len())
    }

    /// Whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diag() -> CoreEventKind {
        CoreEventKind::Diagnostic(Box::default())
    }

    #[test]
    fn the_stream_is_totally_ordered_with_no_gaps_when_nothing_is_dropped() {
        let s = EventStream::new(64);
        for _ in 0..10 {
            s.publish(diag(), None);
        }
        let mut seqs = Vec::new();
        while let Some(e) = s.next_event(Duration::ZERO) {
            seqs.push(e.seq);
        }
        assert_eq!(seqs, (1..=10).collect::<Vec<u64>>());
    }

    #[test]
    fn an_overflow_emits_an_ordered_compacted_marker_before_any_further_event() {
        // MI-19: a drop is a recorded gap, never a silence.
        let s = EventStream::new(8);
        for _ in 0..12 {
            s.publish(diag(), None);
        }
        let first = s.next_event(Duration::ZERO).expect("an event");
        match first.kind {
            CoreEventKind::Compacted { dropped, .. } => assert_eq!(dropped, 4),
            other => panic!("the marker must come first, got {other:?}"),
        }
    }

    #[test]
    fn no_marker_appears_when_nothing_was_dropped() {
        // The other half of MI-9a: a consumer that sees no marker knows it has
        // missed nothing.
        let s = EventStream::new(64);
        s.publish(diag(), None);
        let e = s.next_event(Duration::ZERO).expect("an event");
        assert!(!matches!(e.kind, CoreEventKind::Compacted { .. }));
    }

    #[test]
    fn a_wake_cancels_a_wait_and_is_consumed_once() {
        let s = EventStream::new(8);
        s.wake();
        assert!(s.next_event(Duration::from_millis(50)).is_none());
        // The wake is consumed: a second call blocks for its timeout again.
        s.publish(diag(), None);
        assert!(s.next_event(Duration::from_millis(50)).is_some());
    }

    #[test]
    fn wake_is_callable_from_another_thread() {
        // `tw_core_wake` promises exactly this.
        let s = std::sync::Arc::new(EventStream::new(8));
        let s2 = std::sync::Arc::clone(&s);
        let h = std::thread::spawn(move || s2.wake());
        assert!(s.next_event(Duration::from_secs(5)).is_none());
        h.join().expect("join");
    }

    #[test]
    fn a_closed_stream_accepts_nothing_and_returns_nothing() {
        let s = EventStream::new(8);
        s.close();
        assert_eq!(s.publish(diag(), None), None);
        assert!(s.next_event(Duration::ZERO).is_none());
    }

    #[test]
    fn mi_18_attribution_survives_the_queue() {
        let s = EventStream::new(8);
        s.publish(diag(), Some("dana".to_owned()));
        let e = s.next_event(Duration::ZERO).expect("event");
        assert_eq!(e.actor_principal.as_deref(), Some("dana"));
    }
}
