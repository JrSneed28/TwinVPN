//! The live-delivery registry — ADR-0002 §11.5 path [1], S-25.
//!
//! `ControlChannelAttachment` is `{device_id → {front-end node, connection
//! epoch, expires_at}}`, `EVENTUAL`, **non-durable, TTL 90 s**, "highest
//! connection epoch wins", and — the line that governs this whole module —
//! **"never a gate: a missing attachment MUST NOT suppress a `CALL` attempt or a
//! connection attempt."**
//!
//! So a lookup miss here is not an error. It is the ordinary case that falls
//! through to the mailbox, and the caller may not treat it as a refusal.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use twinvpn_service_common::Verbatim;

use crate::frame::DeviceId;

/// What this process can hand to an attached device.
#[derive(Debug, Clone)]
pub enum Egress {
    /// A `CALL` body, forwarded **verbatim** (finding W-4). The octets that
    /// arrived, with no sender field added: the blob is Rule-B signed and names
    /// its own signer.
    Deliver(Verbatim),
    /// An answer. The body is an encoded `twinvpn.v1.ErrorEnvelope`, or empty
    /// for an unqualified success. `ServiceError` has no message field, so no
    /// internal error text can reach this path.
    Ack(bytes::Bytes),
    /// The source address this service observed, as an encoded
    /// `twinvpn.v1.Endpoint` (networking.md A6(a)).
    Reflexive(bytes::Bytes),
    /// This attachment was superseded by a newer one for the same device.
    /// ADR-0002 N-1's `CONTROL.SUPERSEDED_BY_NEW_ATTACH`, answered rather than
    /// reset: S-6 forbids a bare drop.
    Superseded,
}

/// A live delivery path.
#[derive(Debug)]
struct Attachment {
    epoch: u64,
    sink: tokio::sync::mpsc::Sender<Egress>,
    expires_at: Instant,
}

/// Bounds on how much identity this process will hold at once.
#[derive(Debug, Clone, Copy)]
pub struct AttachLimits {
    /// S-25: TTL 90 s. An attachment that stops being refreshed disappears.
    pub ttl: Duration,
    /// The ceiling on concurrently attached devices. Reaching it is
    /// `RESOURCE.PEER_LIMIT_REACHED`, a *policy* refusal with a named ceiling —
    /// never a silent drop.
    pub max_attachments: usize,
}

impl Default for AttachLimits {
    fn default() -> Self {
        Self {
            ttl: Duration::from_millis(90_000),
            max_attachments: 8192,
        }
    }
}

/// The outcome of an attach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attached {
    /// Bound, with this connection epoch.
    Bound {
        /// The epoch assigned to this attachment.
        epoch: u64,
    },
    /// The ceiling is reached; `RESOURCE.PEER_LIMIT_REACHED`.
    AtCapacity,
}

/// `device_id → live delivery path`. Bounded, TTL'd, never durable.
#[derive(Debug)]
pub struct AttachRegistry {
    limits: AttachLimits,
    live: HashMap<DeviceId, Attachment>,
    next_epoch: u64,
}

impl AttachRegistry {
    /// A registry bounded by `limits`.
    #[must_use]
    pub fn new(limits: AttachLimits) -> Self {
        Self {
            limits,
            live: HashMap::new(),
            next_epoch: 1,
        }
    }

    /// Binds `device_id` to `sink`, superseding any older attachment.
    ///
    /// Returns the superseded sink, if any, so the caller can answer it with
    /// `CONTROL.SUPERSEDED_BY_NEW_ATTACH` before dropping it.
    pub fn attach(
        &mut self,
        device_id: DeviceId,
        sink: tokio::sync::mpsc::Sender<Egress>,
        now: Instant,
    ) -> (Attached, Option<tokio::sync::mpsc::Sender<Egress>>) {
        self.sweep(now);
        if !self.live.contains_key(&device_id) && self.live.len() >= self.limits.max_attachments {
            return (Attached::AtCapacity, None);
        }
        let epoch = self.next_epoch;
        self.next_epoch += 1;
        let previous = self.live.insert(
            device_id,
            Attachment {
                epoch,
                sink,
                expires_at: now + self.limits.ttl,
            },
        );
        (Attached::Bound { epoch }, previous.map(|a| a.sink))
    }

    /// Releases `device_id` if `epoch` is still the current one.
    ///
    /// Epoch-guarded so a connection closing *after* it was superseded cannot
    /// unbind the connection that superseded it — the reordering bug this shape
    /// exists to make impossible.
    pub fn detach(&mut self, device_id: DeviceId, epoch: u64) {
        if self.live.get(&device_id).is_some_and(|a| a.epoch == epoch) {
            self.live.remove(&device_id);
        }
    }

    /// Refreshes an attachment's TTL, if it is still the current one.
    pub fn refresh(&mut self, device_id: DeviceId, epoch: u64, now: Instant) {
        if let Some(a) = self.live.get_mut(&device_id) {
            if a.epoch == epoch {
                a.expires_at = now + self.limits.ttl;
            }
        }
    }

    /// The live sink for `device_id`, if there is one.
    ///
    /// `None` is **not** an error and **not** a gate (S-11, S-25): it means the
    /// caller falls through to the mailbox.
    pub fn sink(
        &mut self,
        device_id: DeviceId,
        now: Instant,
    ) -> Option<tokio::sync::mpsc::Sender<Egress>> {
        self.sweep(now);
        self.live.get(&device_id).map(|a| a.sink.clone())
    }

    /// Drops attachments past their TTL.
    pub fn sweep(&mut self, now: Instant) {
        self.live.retain(|_, a| a.expires_at > now);
    }

    /// How many devices are attached.
    #[must_use]
    pub fn len(&self) -> usize {
        self.live.len()
    }

    /// Whether nothing is attached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sink() -> tokio::sync::mpsc::Sender<Egress> {
        tokio::sync::mpsc::channel(4).0
    }

    #[test]
    fn a_missing_attachment_is_a_miss_not_a_refusal() {
        let mut r = AttachRegistry::new(AttachLimits::default());
        assert!(r.sink([9u8; 32], Instant::now()).is_none());
    }

    #[test]
    fn the_highest_connection_epoch_wins_and_the_loser_is_told() {
        let mut r = AttachRegistry::new(AttachLimits::default());
        let now = Instant::now();
        let (first, superseded) = r.attach([1u8; 32], sink(), now);
        assert!(matches!(first, Attached::Bound { .. }));
        assert!(superseded.is_none());
        let (second, superseded) = r.attach([1u8; 32], sink(), now);
        assert!(matches!(second, Attached::Bound { .. }));
        assert!(
            superseded.is_some(),
            "S-6: answer the old attachment, never drop it silently"
        );
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn a_late_close_cannot_unbind_the_connection_that_superseded_it() {
        let mut r = AttachRegistry::new(AttachLimits::default());
        let now = Instant::now();
        let (Attached::Bound { epoch: old }, _) = r.attach([1u8; 32], sink(), now) else {
            panic!()
        };
        let _ = r.attach([1u8; 32], sink(), now);
        r.detach([1u8; 32], old);
        assert_eq!(
            r.len(),
            1,
            "the newer attachment must survive the older's close"
        );
    }

    #[test]
    fn an_attachment_expires_at_the_s25_ttl() {
        let mut r = AttachRegistry::new(AttachLimits::default());
        let t0 = Instant::now();
        r.attach([2u8; 32], sink(), t0);
        assert!(r
            .sink([2u8; 32], t0 + Duration::from_millis(89_999))
            .is_some());
        assert!(r
            .sink([2u8; 32], t0 + Duration::from_millis(90_001))
            .is_none());
    }

    #[test]
    fn the_attachment_ceiling_is_named_not_silent() {
        let mut r = AttachRegistry::new(AttachLimits {
            max_attachments: 2,
            ..AttachLimits::default()
        });
        let now = Instant::now();
        for i in 0..2u8 {
            let (a, _) = r.attach([i; 32], sink(), now);
            assert!(matches!(a, Attached::Bound { .. }));
        }
        let (a, _) = r.attach([9u8; 32], sink(), now);
        assert_eq!(a, Attached::AtCapacity);
    }
}
