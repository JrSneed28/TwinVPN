//! The `CALL` delivery ladder, as a decision this process can be held to.
//!
//! ADR-0002 §11.5, reproduced because it *is* this module:
//!
//! ```text
//!   rendezvous ingress
//!         ├─[1] target has a live control channel?  ──yes──▶ deliver on it
//!         ├─[2] target has a valid push token?      ──yes──▶ C3 wake hint
//!         ├─[3] mailbox: TTL 30 s, capacity 8/target, drop-oldest
//!         │                                            ▶ CONTROL.MAILBOX_OVERFLOW
//!         └─[4] none of the above                     ▶ CONTROL.CALL_UNDELIVERABLE
//! ```
//!
//! **Rung [2] is not implemented in this wave.** A push gateway is an untrusted
//! third party (`trust-boundaries.md` §1) and no push credential store exists
//! yet; a device with no live channel therefore falls straight to [3]. That is a
//! latency reduction that is missing, not a correctness hole — §11.5 says the
//! initiator never blocks on delivery, and a `CALL` that never lands costs a
//! fall back to `RELAYED`. It is recorded in `README.md` §9 rather than implied.
//!
//! # The existence oracle, closed structurally
//!
//! `trust-boundaries.md` §2 warns that answering a malformed input "would
//! confirm the target exists". The same concern applies one level up: if an
//! unknown `device_id` produced a different answer from a known-but-detached
//! one, this service would be a device-enumeration oracle for anyone with a
//! socket.
//!
//! It cannot be, and not because of a check. This process **holds no device
//! registry at all** — it never asks the control plane whether a `device_id` is
//! real, because doing so per `CALL` would put the control plane in the
//! connection path and break **I5**. A fabricated target and a real detached
//! target take the identical path and produce the identical answer, because
//! there is no information here with which to distinguish them.

use std::time::Instant;

use twinvpn_service_common::{codes, ServiceError, Verbatim};
use twinvpn_types::EvidenceValue;

use crate::attach::{AttachRegistry, Egress};
use crate::frame::DeviceId;
use crate::label::{Labeller, PeerLabel};
use crate::mailbox::{MailboxStore, Push};

/// Where a `CALL` went.
#[derive(Debug)]
pub enum Disposition {
    /// Rung [1]: handed to the target's live channel.
    Delivered(tokio::sync::mpsc::Sender<Egress>, Verbatim),
    /// Rung [3]: queued in the jitter buffer. `overflowed` reports that
    /// drop-oldest fired, which is `CONTROL.MAILBOX_OVERFLOW`.
    Mailboxed {
        /// Whether an older entry was discarded to make room.
        overflowed: bool,
        /// The pseudonym for the target, for the informational answer.
        label: PeerLabel,
    },
    /// Rung [4]: `CONTROL.CALL_UNDELIVERABLE`.
    Undeliverable(PeerLabel),
}

/// Everything a `CALL` decision touches. One struct so the whole mutable state
/// of the service is nameable in a sentence: three bounded, TTL'd tables.
#[derive(Debug)]
pub struct Router {
    /// Live delivery paths (S-25).
    pub attachments: AttachRegistry,
    /// The jitter buffer (ADR-0002 N-9).
    pub mailboxes: MailboxStore,
    /// `device_id → peer_label` (see [`crate::label`]).
    pub labels: Labeller,
}

impl Router {
    /// Routes one already-validated `CALL`.
    ///
    /// `payload` arrives as [`Verbatim`] and leaves as [`Verbatim`]: this
    /// function never decodes it, so finding W-4's "forward the received octets"
    /// is a property of the signature and not of the body.
    pub fn route_call(&mut self, target: DeviceId, payload: Verbatim, now: Instant) -> Disposition {
        if let Some(sink) = self.attachments.sink(target, now) {
            return Disposition::Delivered(sink, payload);
        }
        let label = self.labels.label(target);
        match self.mailboxes.push(target, payload, now) {
            Push::Queued => Disposition::Mailboxed {
                overflowed: false,
                label,
            },
            Push::QueuedAfterDrop => Disposition::Mailboxed {
                overflowed: true,
                label,
            },
            Push::Refused => Disposition::Undeliverable(label),
        }
    }

    /// Discards everything past its TTL. Called on a timer by the server.
    pub fn sweep(&mut self, now: Instant) {
        self.attachments.sweep(now);
        self.mailboxes.sweep(now);
    }
}

/// The informational answer for a `CALL` that did not reach a live channel.
///
/// `CONTROL.PEER_NOT_ATTACHED` is `TRANSIENT`/`INFO`, non-terminal, and the
/// registry's own condition text ends **"INFORMATIONAL - NEVER A GATE"**. The
/// initiator "MUST NOT block on it" (ADR-0002 §11.5) — relay-first
/// establishment already started at `t=0`.
#[must_use]
pub fn peer_not_attached(label: PeerLabel) -> ServiceError {
    ServiceError::new(codes::CONTROL_PEER_NOT_ATTACHED, crate::COMPONENT)
        .evidence("peer_label", EvidenceValue::Text(label.to_string()))
        .build()
}

/// `CONTROL.CALL_UNDELIVERABLE` — "no live channel, no push token, mailbox
/// expired or full". Also `TRANSIENT`/`INFO`, also never a gate.
#[must_use]
pub fn call_undeliverable(label: PeerLabel) -> ServiceError {
    ServiceError::new(codes::CONTROL_CALL_UNDELIVERABLE, crate::COMPONENT)
        .evidence("peer_label", EvidenceValue::Text(label.to_string()))
        .build()
}

/// `CONTROL.MAILBOX_OVERFLOW` — "rendezvous mailbox drop-oldest fired for this
/// target". The registry declares **no** evidence fields for this code, and an
/// undeclared key is an unclassified key, which cannot be redacted correctly and
/// is therefore dropped (`trust-boundaries.md` §8). So none is attached.
#[must_use]
pub fn mailbox_overflow() -> ServiceError {
    ServiceError::new(codes::CONTROL_MAILBOX_OVERFLOW, crate::COMPONENT).build()
}

/// `RESOURCE.PEER_LIMIT_REACHED` for an attach past the ceiling, naming the
/// ceiling as the registry requires.
#[must_use]
pub fn peer_limit_reached(max_peers: u64) -> ServiceError {
    ServiceError::new(codes::RESOURCE_PEER_LIMIT_REACHED, crate::COMPONENT)
        .evidence("max_peers", EvidenceValue::Uint(max_peers))
        .build()
}

/// `CONTROL.ADMISSION_DEFERRED{retry_after_ms}` — S-6's answer, never a reset.
#[must_use]
pub fn admission_deferred(retry_after_ms: u64) -> ServiceError {
    ServiceError::new(codes::CONTROL_ADMISSION_DEFERRED, crate::COMPONENT)
        .evidence("retry_after_ms", EvidenceValue::DurationMs(retry_after_ms))
        .build()
}

/// `CONTROL.CHANNEL_BINDING_MISMATCH` — the claimed `device_id` is not
/// answerable to the authenticated channel identity.
///
/// FATAL, CRITICAL, and `trust-boundaries.md` §4's words for this code are
/// "**a security event, never a parse error**". The registry declares no
/// evidence fields for it, and none is attached: naming the contested
/// `device_id` in an answer would turn the refusal into an oracle for which
/// devices are attached.
#[must_use]
pub fn channel_binding_mismatch() -> ServiceError {
    ServiceError::new(codes::CONTROL_CHANNEL_BINDING_MISMATCH, crate::COMPONENT).build()
}

/// `CONTROL.SUPERSEDED_BY_NEW_ATTACH` (ADR-0002 N-1).
#[must_use]
pub fn superseded() -> ServiceError {
    ServiceError::new(codes::CONTROL_SUPERSEDED_BY_NEW_ATTACH, crate::COMPONENT).build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_schema::Channel;

    use crate::attach::AttachLimits;
    use crate::mailbox::MailboxLimits;

    fn router() -> Router {
        Router {
            attachments: AttachRegistry::new(AttachLimits::default()),
            mailboxes: MailboxStore::new(MailboxLimits::default()),
            labels: Labeller::default(),
        }
    }

    fn payload(n: usize) -> Verbatim {
        Verbatim::from_received(crate::testkit::payload(n), Channel::PeerDatagram).unwrap()
    }

    #[test]
    fn an_attached_target_takes_rung_one() {
        let mut r = router();
        let now = Instant::now();
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        r.attachments.attach([1u8; 32], tx, now);
        assert!(matches!(
            r.route_call([1u8; 32], payload(32), now),
            Disposition::Delivered(..)
        ));
    }

    #[test]
    fn a_detached_target_falls_through_to_the_mailbox_and_is_never_gated() {
        let mut r = router();
        let now = Instant::now();
        let d = r.route_call([2u8; 32], payload(32), now);
        let Disposition::Mailboxed { overflowed, label } = d else {
            panic!("a missing attachment must not refuse the CALL")
        };
        assert!(!overflowed);
        let e = peer_not_attached(label);
        assert_eq!(e.code().as_str(), "CONTROL.PEER_NOT_ATTACHED");
        assert_eq!(e.code().severity(), twinvpn_types::ErrorSeverity::Info);
        assert!(!e.code().terminal(), "never a gate");
    }

    #[test]
    fn a_fabricated_target_is_indistinguishable_from_a_detached_real_one() {
        let mut r = router();
        let now = Instant::now();
        let real = r.route_call([3u8; 32], payload(32), now);
        let fabricated = r.route_call([0xffu8; 32], payload(32), now);
        assert!(matches!(
            real,
            Disposition::Mailboxed {
                overflowed: false,
                ..
            }
        ));
        assert!(matches!(
            fabricated,
            Disposition::Mailboxed {
                overflowed: false,
                ..
            }
        ));
    }

    #[test]
    fn a_full_mailbox_reports_overflow_and_still_queues_the_new_call() {
        let mut r = router();
        let now = Instant::now();
        for _ in 0..8 {
            let _ = r.route_call([4u8; 32], payload(16), now);
        }
        assert!(matches!(
            r.route_call([4u8; 32], payload(16), now),
            Disposition::Mailboxed {
                overflowed: true,
                ..
            }
        ));
        assert_eq!(
            mailbox_overflow().code().as_str(),
            "CONTROL.MAILBOX_OVERFLOW"
        );
    }

    #[test]
    fn an_unqueueable_call_is_undeliverable_not_a_panic() {
        let mut r = Router {
            attachments: AttachRegistry::new(AttachLimits::default()),
            mailboxes: MailboxStore::new(MailboxLimits {
                max_total_bytes: 8,
                ..MailboxLimits::default()
            }),
            labels: Labeller::default(),
        };
        let now = Instant::now();
        let Disposition::Undeliverable(label) = r.route_call([5u8; 32], payload(64), now) else {
            panic!("expected rung [4]")
        };
        assert_eq!(
            call_undeliverable(label).code().as_str(),
            "CONTROL.CALL_UNDELIVERABLE"
        );
    }
}
