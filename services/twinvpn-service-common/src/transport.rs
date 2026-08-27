//! Server-side transport helpers: bounded framing, C2 backpressure, admission
//! control.
//!
//! **Authority:** ADR-0002 §11.6 (backpressure, flow control, fan-out), §11.7
//! (connection storms and reconnect discipline, **S-6**), §11.12 (delivery
//! semantics per hop), ADR-0003 §11 and `contracts/registry/limits.json`
//! (envelope caps), `docs/implementation/ownership.md` §6 rules 9 and 10.
//!
//! # Everything here is a pure function of its inputs
//!
//! [`TokenBucket`] and [`WriteBudget`] take `now` as a parameter rather than
//! reading a clock. `docs/architecture.md` §5.2 R-DET-1 wants a decision to be
//! reproducible from its inputs; a rate limiter that reads `Instant::now()`
//! internally is untestable at the boundaries that matter (exactly at the
//! refill, one tick before it) and is the classic source of "flaky in CI".
//!
//! # Delivery semantics this supports
//!
//! ADR-0002 §11.12: **no hop claims exactly-once delivery.** Device→control
//! plane C1 is at-least-once with exactly-once *effect* via `idempotency_key` +
//! `if_version`; control plane→device C2 is at-least-once, cursor-resumable and
//! **compaction-permitted**. [`EventQueue`] implements the compaction half:
//! on watermark breach it discards queued event *bodies* and yields an ordered
//! `StreamCompacted{up_to_net_seq}`, because a device re-reads declaratively
//! (§11.4) and a body it can re-derive is not worth a stall.

use std::time::Instant;

use bytes::Bytes;
use twinvpn_schema::{Channel, Reject};
use twinvpn_types::{codes, ReasonCode};

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

/// The width of a frame's length prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthPrefix {
    /// Two bytes, big-endian. ADR-0005 §11.4's `R-TLS` carriage: "TLS 1.3,
    /// 2-byte length-prefixed frames".
    U16,
    /// Four bytes, big-endian. The control channels.
    U32,
}

impl LengthPrefix {
    /// How many bytes the prefix occupies.
    #[must_use]
    pub const fn width(self) -> usize {
        match self {
            LengthPrefix::U16 => 2,
            LengthPrefix::U32 => 4,
        }
    }

    /// Reads a declared length from `prefix`.
    ///
    /// # Errors
    ///
    /// [`Reject::Unparseable`] if `prefix` is short.
    pub fn decode(self, prefix: &[u8], channel: Channel) -> Result<usize, Reject> {
        if prefix.len() < self.width() {
            return Err(Reject::Unparseable {
                parser_id: channel.parser_id(),
            });
        }
        Ok(match self {
            LengthPrefix::U16 => usize::from(u16::from_be_bytes([prefix[0], prefix[1]])),
            LengthPrefix::U32 => {
                u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize
            }
        })
    }
}

/// Checks a declared length against its channel's cap **before** anything is
/// allocated for it.
///
/// This is the single most load-bearing helper in the module and the reason it
/// exists at all: `ownership.md` §6 rule 9 requires validation "*before* any
/// allocation proportional to a declared length", and the natural way to write a
/// frame reader — `let mut buf = vec![0; declared_len]` — violates it in the
/// first line. Call this, then allocate.
///
/// # Errors
///
/// [`Reject::SizeExceeded`] naming the channel and both numbers.
pub fn check_declared_length(declared: usize, channel: Channel) -> Result<usize, Reject> {
    let limit = channel.max_bytes();
    if declared > limit {
        return Err(Reject::SizeExceeded {
            parser_id: channel.parser_id(),
            observed: declared,
            limit,
        });
    }
    Ok(declared)
}

/// Reads one length-prefixed frame, refusing an over-long declaration before
/// allocating.
///
/// # Errors
///
/// [`Reject::SizeExceeded`] for an over-long declaration, [`Reject::Unparseable`]
/// for a short or truncated frame.
pub async fn read_frame<R>(
    reader: &mut R,
    prefix: LengthPrefix,
    channel: Channel,
) -> Result<Bytes, Reject>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;

    let mut hdr = [0u8; 4];
    let w = prefix.width();
    reader
        .read_exact(&mut hdr[..w])
        .await
        .map_err(|_| Reject::Unparseable {
            parser_id: channel.parser_id(),
        })?;

    let declared = prefix.decode(&hdr[..w], channel)?;
    // The cap is checked here. Only after this line does an allocation happen.
    let bounded = check_declared_length(declared, channel)?;

    let mut buf = vec![0u8; bounded];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|_| Reject::Unparseable {
            parser_id: channel.parser_id(),
        })?;
    Ok(Bytes::from(buf))
}

// ---------------------------------------------------------------------------
// C2 backpressure
// ---------------------------------------------------------------------------

/// The C2 backlog watermark of ADR-0002 §11.6.
///
/// > 256 KiB **or** 512 pending events per device, whichever first. **Halved on
/// > rung 2** (128 KiB / 256 events) because TCP head-of-line blocking makes a
/// > backlog costlier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BacklogWatermark {
    /// Byte watermark.
    pub max_bytes: usize,
    /// Event-count watermark.
    pub max_events: usize,
}

impl BacklogWatermark {
    /// Rung 1 (QUIC): `limits.json control_plane.c2_backlog_watermark_*`.
    #[must_use]
    pub const fn rung1() -> Self {
        Self {
            max_bytes: 262_144,
            max_events: 512,
        }
    }

    /// Rung 2 and below (TCP): halved, per §11.6.
    #[must_use]
    pub const fn rung2() -> Self {
        Self {
            max_bytes: 131_072,
            max_events: 256,
        }
    }

    /// The watermark for a transport rung, 1..=4.
    #[must_use]
    pub const fn for_rung(rung: u8) -> Self {
        if rung <= 1 {
            Self::rung1()
        } else {
            Self::rung2()
        }
    }
}

/// What happened to a pushed event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// Queued normally.
    Queued,
    /// The watermark was breached: every queued **body** was discarded and the
    /// device's cursor advances to `up_to_net_seq`. The caller emits an ordered
    /// `StreamCompacted{up_to_net_seq}` and `CONTROL.STREAM_COMPACTED`.
    Compacted {
        /// The position the cursor advances to.
        up_to_net_seq: u64,
    },
}

/// A per-device C2 backlog with ADR-0002 §11.6's compaction relief valve.
///
/// Compaction, not blocking, is the answer: N-8 and §11.4 make every event
/// independently applicable and let a device re-read declaratively, so a slow
/// device costs it a re-read rather than costing the fan-out a stall.
#[derive(Debug)]
pub struct EventQueue {
    watermark: BacklogWatermark,
    queued: std::collections::VecDeque<(u64, Bytes)>,
    bytes: usize,
    highest_net_seq: u64,
    compactions: u64,
}

impl EventQueue {
    /// A queue under `watermark`.
    #[must_use]
    pub fn new(watermark: BacklogWatermark) -> Self {
        Self {
            watermark,
            queued: std::collections::VecDeque::new(),
            bytes: 0,
            highest_net_seq: 0,
            compactions: 0,
        }
    }

    /// Queues one durable event body at `net_seq`.
    ///
    /// `net_seq` is ADR-0002 N-3's per-`TwinNet` monotone counter, allocated
    /// inside the mutating transaction. It is the resume cursor, so it is what
    /// compaction reports.
    pub fn push(&mut self, net_seq: u64, body: Bytes) -> PushOutcome {
        self.highest_net_seq = self.highest_net_seq.max(net_seq);
        self.bytes += body.len();
        self.queued.push_back((net_seq, body));

        if self.bytes > self.watermark.max_bytes || self.queued.len() > self.watermark.max_events {
            let up_to = self.highest_net_seq;
            self.queued.clear();
            self.bytes = 0;
            self.compactions += 1;
            return PushOutcome::Compacted {
                up_to_net_seq: up_to,
            };
        }
        PushOutcome::Queued
    }

    /// Takes the next queued event.
    pub fn pop(&mut self) -> Option<(u64, Bytes)> {
        let item = self.queued.pop_front();
        if let Some((_, b)) = &item {
            self.bytes -= b.len();
        }
        item
    }

    /// Queued event count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queued.len()
    }

    /// Whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queued.is_empty()
    }

    /// Queued bytes.
    #[must_use]
    pub const fn queued_bytes(&self) -> usize {
        self.bytes
    }

    /// How many compactions have happened.
    #[must_use]
    pub const fn compactions(&self) -> u64 {
        self.compactions
    }

    /// The code to emit alongside a compaction.
    #[must_use]
    pub const fn compaction_reason_code() -> ReasonCode {
        codes::CONTROL_STREAM_COMPACTED
    }
}

// ---------------------------------------------------------------------------
// Admission control
// ---------------------------------------------------------------------------

/// A token bucket with an explicit clock.
///
/// ADR-0002 §11.7 rule 3: "Each front-end admits at a token-bucket rate (default
/// 200 attaches/s sustained, burst 1000). Over-limit attaches receive an
/// application-level `CONTROL.ADMISSION_DEFERRED{retry_after_ms}` and MUST honour
/// `retry_after_ms`. **A TCP reset or a silent drop is prohibited here (S-6).**"
///
/// [`TokenBucket::try_admit`] returns the `retry_after_ms` rather than a bare
/// `false`, so the S-6 obligation is discharged by using the return value at all.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    sustained_per_sec: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

/// The outcome of an admission decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Admitted.
    Admitted,
    /// Refused, with the value the caller MUST put in
    /// `CONTROL.ADMISSION_DEFERRED{retry_after_ms}`.
    Deferred {
        /// Milliseconds until a token will be available.
        retry_after_ms: u64,
    },
}

impl Admission {
    /// The code accompanying a deferral.
    #[must_use]
    pub const fn reason_code() -> ReasonCode {
        codes::CONTROL_ADMISSION_DEFERRED
    }
}

impl TokenBucket {
    /// A bucket starting full.
    #[must_use]
    pub fn new(sustained_per_sec: f64, burst: u32, now: Instant) -> Self {
        Self {
            sustained_per_sec: sustained_per_sec.max(0.0),
            burst: f64::from(burst),
            tokens: f64::from(burst),
            last: now,
        }
    }

    /// ADR-0002 §11.7 rule 3's defaults, matching
    /// `TWINVPN_CP_ATTACH_RATE_SUSTAINED` / `_BURST`.
    #[must_use]
    pub fn attach_default(now: Instant) -> Self {
        Self::new(200.0, 1000, now)
    }

    /// Attempts to admit one unit of work.
    pub fn try_admit(&mut self, now: Instant) -> Admission {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            return Admission::Admitted;
        }
        let deficit = 1.0 - self.tokens;
        let seconds = if self.sustained_per_sec > 0.0 {
            deficit / self.sustained_per_sec
        } else {
            // A zero sustained rate never refills; report a bounded retry rather
            // than an infinite one, because "never" is not a value a client can
            // schedule against.
            3600.0
        };
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let retry_after_ms = (seconds * 1000.0).ceil().max(1.0) as u64;
        Admission::Deferred { retry_after_ms }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.sustained_per_sec).min(self.burst);
            self.last = now;
        }
    }

    /// Tokens currently available.
    #[must_use]
    pub const fn available(&self) -> f64 {
        self.tokens
    }
}

/// The per-`TwinNet` durable write budget of ADR-0002 §11.6.
///
/// > ≤ 1 durable event/s sustained, burst 20. Over budget ⇒
/// > `CONTROL.EVENT_RATE_EXCEEDED`, write refused. Bounds log-flooding
/// > denial-of-freshness.
///
/// Refused, never queued: a queued over-budget write is the flood, delayed.
#[derive(Debug, Clone)]
pub struct WriteBudget {
    bucket: TokenBucket,
}

impl WriteBudget {
    /// `limits.json control_plane.durable_events_per_second_sustained` = 1,
    /// `durable_events_burst` = 20.
    #[must_use]
    pub fn frozen_default(now: Instant) -> Self {
        Self {
            bucket: TokenBucket::new(1.0, 20, now),
        }
    }

    /// A budget with explicit parameters, for a deployment that narrows the
    /// frozen values. Widening one is a contract change, not a configuration
    /// change (`infra/README.md` §4.1 rule 3).
    #[must_use]
    pub fn new(sustained_per_sec: f64, burst: u32, now: Instant) -> Self {
        Self {
            bucket: TokenBucket::new(sustained_per_sec, burst, now),
        }
    }

    /// Whether one durable event may be written now.
    ///
    /// # Errors
    ///
    /// [`codes::CONTROL_EVENT_RATE_EXCEEDED`] when over budget.
    pub fn try_write(&mut self, now: Instant) -> Result<(), ReasonCode> {
        match self.bucket.try_admit(now) {
            Admission::Admitted => Ok(()),
            Admission::Deferred { .. } => Err(codes::CONTROL_EVENT_RATE_EXCEEDED),
        }
    }
}
