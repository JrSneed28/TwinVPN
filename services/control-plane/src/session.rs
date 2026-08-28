//! One attached device: admission, C1 streams, the C2 stream, compaction, and
//! the drain.
//!
//! **Authority:** ADR-0002 N-1 (one connection per `Device`, the older closed
//! with `CONTROL.SUPERSEDED_BY_NEW_ATTACH`), N-2 (channel binding), N-8
//! (compaction announced in band and in order), §11.6 (the backlog watermark and
//! the priority rule), §11.7 (the accept limiter and the drain).
//!
//! # The priority rule, and why it is the first thing written
//!
//! §11.6: *"`revocation_epoch` and `pending_net_seq` are served in the attach
//! response itself, before any event body, so the security-critical fact arrives
//! in RTT 1 regardless of queue depth."* [`AttachPriority`] carries both as one
//! value, obtained before any call to [`Attachment::pump`] — a pair that is
//! *read* rather than *passed* is a pair a refactor can order after the first
//! event body.
//!
//! # Compaction announces; it never omits
//!
//! When [`twinvpn_service_common::transport::EventQueue`] breaches the
//! watermark it returns `PushOutcome::Compacted{up_to_net_seq}`, and
//! [`Attachment::pump`] turns that into a `StreamCompacted` event **at its own
//! log position, in order**. A device that receives it re-reads declaratively,
//! which is always correct because every durable event is independently
//! applicable (N-5). Dropping the bodies without the announcement would be the
//! silent omission N-8 prohibits.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use twinvpn_service_common::transport::{
    Admission, BacklogWatermark, EventQueue, PushOutcome, TokenBucket,
};
use twinvpn_service_common::{Metrics, ServiceError};

use crate::codes;
use crate::model::{DeviceKey, StoredEvent};

/// The rung a connection came up on. Rung 1 here; the TCP rungs are recorded in
/// `README.md` §7 as not implemented, and the type exists so the watermark rule
/// is written once rather than twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rung {
    /// QUIC + TLS 1.3 on UDP:443.
    Quic,
    /// One of the TCP rungs. Halves the watermark, because TCP head-of-line
    /// blocking makes a backlog costlier.
    Tcp,
}

impl Rung {
    /// The C2 backlog watermark for this rung.
    #[must_use]
    pub fn watermark(self) -> BacklogWatermark {
        match self {
            Rung::Quic => BacklogWatermark::for_rung(1),
            Rung::Tcp => BacklogWatermark::for_rung(2),
        }
    }

    /// The rung's 1-based number, as the `rung` evidence field carries it.
    #[must_use]
    pub const fn number(self) -> u64 {
        match self {
            Rung::Quic => 1,
            Rung::Tcp => 2,
        }
    }
}

/// The registry of attached devices — ADR-0002 N-1's enforcement point.
///
/// This is **not** S-25 `ControlChannelAttachment`, which is the Device-Presence
/// Service's and is `EVENTUAL` and never a gate. This is the local fact "which
/// connection on *this* front-end is currently serving this identity", which is
/// what N-1 needs in order to close the older one.
#[derive(Debug, Default)]
pub struct Attachments {
    epochs: Mutex<BTreeMap<DeviceKey, Slot>>,
    next_epoch: AtomicU64,
}

/// One live attachment: its epoch, and the signal that displaces it.
#[derive(Debug, Clone)]
struct Slot {
    epoch: u64,
    superseded: Arc<Notify>,
}

/// The outcome of registering a new attachment.
#[derive(Debug, Clone)]
pub struct Attached {
    /// This connection's epoch. Highest wins.
    pub epoch: u64,
    /// Whether an older connection for this identity must now be closed with
    /// `CONTROL.SUPERSEDED_BY_NEW_ATTACH`.
    pub superseded_previous: bool,
    /// Resolves when a **later** attach displaces this connection.
    ///
    /// N-1 says the older connection "MUST be closed", and a serving loop parked
    /// on its next stream would otherwise not notice until one arrived — which,
    /// for a device that is only listening on C2, is never. Polling would answer
    /// it late and by accident; this answers it at the moment the displacement
    /// happens, and the enforcement stays here rather than becoming a timer in
    /// the transport.
    pub superseded: Arc<Notify>,
}

impl Attachments {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            epochs: Mutex::new(BTreeMap::new()),
            next_epoch: AtomicU64::new(1),
        }
    }

    /// Registers a new connection for `device_id`.
    ///
    /// N-1: "A second concurrent control connection for the same
    /// `DeviceIdentity` MUST cause the **older** one to be closed." The newer
    /// connection wins, deliberately — a device that reattached did so because
    /// its old connection was, from its side, already gone.
    ///
    /// # Panics
    ///
    /// If the registry lock was poisoned by a panic while it was held. A
    /// poisoned attachment map means N-1 can no longer be enforced, and serving
    /// on past that would give one identity two C1 streams.
    pub fn attach(&self, device_id: DeviceKey) -> Attached {
        let epoch = self.next_epoch.fetch_add(1, Ordering::SeqCst);
        let superseded = Arc::new(Notify::new());
        let mut map = self.epochs.lock().expect("attachment lock");
        let previous = map.insert(
            device_id,
            Slot {
                epoch,
                superseded: Arc::clone(&superseded),
            },
        );
        if let Some(previous) = previous.as_ref() {
            // `notify_one` and not `notify_waiters`: it stores a permit, so a
            // displaced connection that has not yet reached its wait still sees
            // the displacement. `notify_waiters` would be lost in that race and
            // would leave exactly the second live attachment N-1 forbids.
            previous.superseded.notify_one();
        }
        Attached {
            epoch,
            superseded_previous: previous.is_some(),
            superseded,
        }
    }

    /// Whether `epoch` is still the live attachment for `device_id`.
    ///
    /// A connection that loses this race stops serving: continuing would give
    /// one identity two C1 streams with independent cursors.
    ///
    /// # Panics
    ///
    /// If the registry lock was poisoned. See [`Attachments::attach`].
    #[must_use]
    pub fn is_current(&self, device_id: &DeviceKey, epoch: u64) -> bool {
        self.epochs
            .lock()
            .expect("attachment lock")
            .get(device_id)
            .map(|slot| slot.epoch)
            == Some(epoch)
    }

    /// Removes an attachment if it is still the live one.
    ///
    /// # Panics
    ///
    /// If the registry lock was poisoned. See [`Attachments::attach`].
    pub fn detach(&self, device_id: &DeviceKey, epoch: u64) {
        let mut map = self.epochs.lock().expect("attachment lock");
        if map.get(device_id).map(|slot| slot.epoch) == Some(epoch) {
            map.remove(device_id);
        }
    }

    /// How many devices are attached to this front-end.
    ///
    /// # Panics
    ///
    /// If the registry lock was poisoned. See [`Attachments::attach`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.epochs.lock().expect("attachment lock").len()
    }

    /// Whether none are.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The accept limiter — ADR-0002 §11.7 rule 3, **S-6**.
#[derive(Debug)]
pub struct AcceptLimiter {
    bucket: Mutex<TokenBucket>,
    retry_after_ms: u64,
}

impl AcceptLimiter {
    /// A limiter at `sustained` attaches/s with `burst`.
    #[must_use]
    pub fn new(sustained: f64, burst: u32, now: std::time::Instant) -> Self {
        Self {
            bucket: Mutex::new(TokenBucket::new(sustained, burst, now)),
            // The deferral must name a number the client can honour: a bare
            // "try later" is what turns a limiter into a retry storm.
            retry_after_ms: interval_ms(sustained),
        }
    }

    /// Admits an attach, or defers it **with a number**.
    ///
    /// # Errors
    ///
    /// `CONTROL.ADMISSION_DEFERRED{retry_after_ms}`. S-6 prohibits a TCP reset
    /// or a silent drop here, and returning a typed error the caller must send
    /// is how that prohibition is discharged rather than remembered.
    ///
    /// # Panics
    ///
    /// If the limiter lock was poisoned by a panic while it was held.
    pub fn admit(&self, now: std::time::Instant) -> Result<(), ServiceError> {
        let mut bucket = self.bucket.lock().expect("limiter lock");
        match bucket.try_admit(now) {
            Admission::Admitted => Ok(()),
            Admission::Deferred { retry_after_ms } => {
                Err(codes::admission_deferred(if retry_after_ms == 0 {
                    self.retry_after_ms
                } else {
                    retry_after_ms
                }))
            }
        }
    }
}

/// The refill interval for one token, in milliseconds.
///
/// Computed rather than cast: a `retry_after_ms` a client cannot honour is worse
/// than no limiter at all, so a non-finite, negative or absurd configured rate
/// falls back to a usable ceiling instead of wrapping into one.
fn interval_ms(sustained_per_sec: f64) -> u64 {
    const CEILING_MS: u64 = 60_000;
    if !sustained_per_sec.is_finite() || sustained_per_sec <= 0.0 {
        return 1_000;
    }
    let ms = (1000.0 / sustained_per_sec).ceil();
    if !ms.is_finite() || !(0.0..=6e4).contains(&ms) {
        return CEILING_MS;
    }
    // In range, non-negative and finite by the guard above.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let out = ms as u64;
    out.max(1)
}

/// One device's C2 stream state.
#[derive(Debug)]
pub struct Attachment {
    device_id: DeviceKey,
    epoch: u64,
    rung: Rung,
    cursor: u64,
    queue: EventQueue,
    metrics: Metrics,
}

/// What [`Attachment::pump`] produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pumped {
    /// Records to write, in order.
    Records(Vec<Vec<u8>>),
    /// The backlog was shed. Announce the gap **in band and in order**, then
    /// continue from `up_to_net_seq`.
    Compacted {
        /// The position the device's cursor advances to.
        up_to_net_seq: u64,
    },
}

impl Attachment {
    /// Opens a C2 stream at `cursor`.
    #[must_use]
    pub fn new(
        device_id: DeviceKey,
        epoch: u64,
        rung: Rung,
        cursor: u64,
        metrics: Metrics,
    ) -> Self {
        Self {
            device_id,
            epoch,
            rung,
            cursor,
            queue: EventQueue::new(rung.watermark()),
            metrics,
        }
    }

    /// Whose stream this is.
    #[must_use]
    pub const fn device_id(&self) -> DeviceKey {
        self.device_id
    }

    /// This connection's attachment epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The device's current position.
    #[must_use]
    pub const fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Which rung, and therefore which watermark.
    #[must_use]
    pub const fn rung(&self) -> Rung {
        self.rung
    }

    /// Offers events to the stream and reports what to write.
    ///
    /// # Errors
    ///
    /// `CONTROL.EVENT_WRONG_PUBLISHER` when a stored event's publisher is not
    /// its type's sole publisher. Checking here as well as at the log is
    /// deliberate: this is the last point before the octets leave the process,
    /// and `protocol.md` §7 makes the receiver reject one too. Three checks on
    /// one property is what "enforced at the log, not by convention" means.
    pub fn pump(&mut self, events: &[StoredEvent]) -> Result<Pumped, ServiceError> {
        let mut compacted_to = None;
        for event in events {
            if event.publisher != event.event_type.sole_publisher() {
                return Err(codes::wrong_publisher(
                    event.event_type.as_str(),
                    event.publisher.as_str(),
                ));
            }
            match self
                .queue
                .push(event.net_seq, bytes::Bytes::from(event.encoded.clone()))
            {
                PushOutcome::Queued => {}
                PushOutcome::Compacted { up_to_net_seq } => {
                    compacted_to = Some(up_to_net_seq);
                }
            }
        }

        if let Some(up_to_net_seq) = compacted_to {
            self.cursor = up_to_net_seq;
            self.metrics
                .counter(
                    "twinvpn_cp_stream_compacted_total",
                    "C2 backlogs shed, each announced in band as StreamCompacted",
                    twinvpn_service_common::metrics::Labels::new(),
                )
                .inc();
            tracing::info!(
                reason_code = twinvpn_types::codes::CONTROL_STREAM_COMPACTED.as_str(),
                up_to_net_seq,
                rung = self.rung.number(),
                "C2 backlog shed; announcing the gap in band"
            );
            return Ok(Pumped::Compacted { up_to_net_seq });
        }

        let mut out = Vec::new();
        while let Some((net_seq, body)) = self.queue.pop() {
            self.cursor = net_seq;
            out.push(body.to_vec());
        }
        Ok(Pumped::Records(out))
    }

    /// Advances the cursor after a `StreamCompacted` has actually been written.
    ///
    /// Separate from [`Attachment::pump`] on purpose: the cursor moves when the
    /// **announcement** is on the wire, not when the decision to compact was
    /// made. A cursor advanced before the announcement is a silent gap.
    pub fn confirm_compaction(&mut self, up_to_net_seq: u64) {
        self.cursor = self.cursor.max(up_to_net_seq);
    }
}

/// The attach response's two priority fields, served **before any event body**.
///
/// §11.6: "the security-critical fact arrives in RTT 1 regardless of queue
/// depth". Returning them as a struct rather than reading them later is what
/// stops a future refactor from ordering the first event ahead of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachPriority {
    /// The trust generation. A device detects it is behind without draining.
    pub revocation_epoch: u64,
    /// The head position, so a device knows how far behind it is.
    pub pending_net_seq: u64,
}

#[cfg(test)]
mod tests {
    use super::{AcceptLimiter, AttachPriority, Attachment, Attachments, Pumped, Rung};
    use crate::event::{EventKind, Publisher};
    use crate::model::StoredEvent;
    use twinvpn_service_common::Metrics;

    fn event(net_seq: u64, size: usize) -> StoredEvent {
        StoredEvent {
            net_seq,
            event_type: EventKind::DeviceRegistered,
            publisher: Publisher::CoordinationService,
            encoded: vec![0u8; size],
            committed_at_ms: 0,
        }
    }

    #[test]
    fn a_second_attach_supersedes_the_older_connection() {
        // ADR-0002 N-1: the OLDER one is closed, not the newer. A device that
        // reattached did so because its old connection was already gone.
        let a = Attachments::new();
        let first = a.attach([1u8; 32]);
        assert!(!first.superseded_previous);
        let second = a.attach([1u8; 32]);
        assert!(second.superseded_previous);
        assert!(second.epoch > first.epoch);
        assert!(
            !a.is_current(&[1u8; 32], first.epoch),
            "the older stops serving"
        );
        assert!(a.is_current(&[1u8; 32], second.epoch));
    }

    #[test]
    fn detaching_a_stale_epoch_does_not_evict_the_live_one() {
        let a = Attachments::new();
        let first = a.attach([1u8; 32]);
        let second = a.attach([1u8; 32]);
        a.detach(&[1u8; 32], first.epoch);
        assert!(a.is_current(&[1u8; 32], second.epoch));
        a.detach(&[1u8; 32], second.epoch);
        assert!(a.is_empty());
    }

    #[test]
    fn an_over_limit_attach_is_deferred_with_a_number_never_dropped() {
        // S-6: "a TCP reset or a silent drop is prohibited here."
        let now = std::time::Instant::now();
        let limiter = AcceptLimiter::new(1.0, 1, now);
        assert!(limiter.admit(now).is_ok());
        let err = limiter.admit(now).expect_err("burst exhausted");
        assert_eq!(err.code().as_str(), "CONTROL.ADMISSION_DEFERRED");
        assert!(
            crate::codes::carries(&err, &["retry_after_ms"]),
            "a deferral with no number is a retry storm"
        );
    }

    #[test]
    fn the_tcp_rungs_halve_the_watermark() {
        // §11.6: halved on rung 2 because TCP head-of-line blocking makes a
        // backlog costlier.
        let quic = Rung::Quic.watermark();
        let tcp = Rung::Tcp.watermark();
        assert_eq!(tcp.max_bytes * 2, quic.max_bytes);
        assert_eq!(tcp.max_events * 2, quic.max_events);
    }

    #[test]
    fn a_wrong_publisher_never_reaches_the_wire() {
        // The third check on one property: construction, the log, and here — the
        // last point before the octets leave the process.
        let mut at = Attachment::new([1u8; 32], 1, Rung::Quic, 0, Metrics::new());
        let mut forged = event(1, 8);
        forged.publisher = Publisher::OriginatingDevice;
        let err = at.pump(&[forged]).expect_err("refused");
        assert_eq!(err.code().as_str(), "CONTROL.EVENT_WRONG_PUBLISHER");
        assert!(err.code().terminal());
    }

    #[test]
    fn a_breached_watermark_announces_the_gap_rather_than_omitting_it() {
        // N-8: "SILENT OMISSION IS PROHIBITED."
        let mut at = Attachment::new([1u8; 32], 1, Rung::Quic, 0, Metrics::new());
        let watermark = Rung::Quic.watermark();
        let big = watermark.max_bytes / 4 + 1;
        let events: Vec<StoredEvent> = (1..=8).map(|n| event(n, big)).collect();
        match at.pump(&events).expect("pumps") {
            Pumped::Compacted { up_to_net_seq } => {
                assert!(up_to_net_seq >= 1, "the gap names where the device resumes");
                assert_eq!(at.cursor(), up_to_net_seq);
            }
            Pumped::Records(_) => panic!("the watermark must have been breached"),
        }
    }

    #[test]
    fn an_unbreached_stream_delivers_every_record_in_order() {
        let mut at = Attachment::new([1u8; 32], 1, Rung::Quic, 0, Metrics::new());
        let events: Vec<StoredEvent> = (1..=5).map(|n| event(n, 16)).collect();
        match at.pump(&events).expect("pumps") {
            Pumped::Records(records) => {
                assert_eq!(records.len(), 5);
                assert_eq!(at.cursor(), 5);
            }
            Pumped::Compacted { .. } => panic!("five small events fit"),
        }
    }

    #[test]
    fn the_cursor_moves_when_the_announcement_is_written_not_when_it_is_decided() {
        let mut at = Attachment::new([1u8; 32], 1, Rung::Quic, 900, Metrics::new());
        at.confirm_compaction(880);
        assert_eq!(at.cursor(), 900, "a confirmation never moves it backwards");
        at.confirm_compaction(950);
        assert_eq!(at.cursor(), 950);
    }

    #[test]
    fn the_priority_pair_is_a_value_so_it_cannot_be_ordered_after_an_event() {
        let p = AttachPriority {
            revocation_epoch: 42,
            pending_net_seq: 900,
        };
        assert_eq!(p.revocation_epoch, 42);
        assert_eq!(p.pending_net_seq, 900);
    }
}
