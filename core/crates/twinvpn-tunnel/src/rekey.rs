//! Rekey scheduling: ADR-0001 §7.2's five constants, on the monotonic clock.
//!
//! **Authority:** ADR-0001 §7.2 (the constants), §8 ("Rekey has no traffic
//! gap"); `docs/reliability.md` §5.3.1 (clock classes); ADR-0018 CD-1.
//!
//! # The 60-second overlap is the reliability property
//!
//! §8: "WireGuard's initiator begins a new handshake at 120 s while the old keys
//! remain valid until 180 s, giving a **60 s overlap**. A handshake failure is
//! therefore visible for a full minute before it becomes a data outage, which is
//! exactly the window `docs/reliability.md` needs to enter `DEGRADED` and attempt
//! recovery before entering `RECONNECTING`."
//!
//! # Every timer here reads the monotonic clock
//!
//! These are liveness constants, not authority deadlines, so §5.3.1 puts them on
//! `MonotonicClock`: "with an advancing clock, resuming from an eight-hour sleep
//! fires every short-horizon timer's accrued backlog at once."
//!
//! The one place the **elapsed** clock is read is `docs/reliability.md` §11.3's
//! wake comparison — "if the `ElapsedClock` delta exceeds the rekey window, a
//! full handshake is forced" — and that comparison belongs to the wake ladder,
//! which hands the answer here as [`KeyState::force_full_handshake`].

use core::time::Duration;

use twinvpn_env::MonotonicInstant;

/// The initiator begins a new handshake at this age.
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
/// Or at this many messages, whichever comes first.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
/// Keys are unusable and are **zeroed** at this age.
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
/// The counter ceiling: `2^64 − 2^13 − 1`.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13) - 1;
/// How long a broken handshake is retried before the `Session` reports failure.
///
/// §8: this "bounds how long a broken handshake is retried before the `Session`
/// reports failure, which turns 'it just hangs' into a bounded, reportable event
/// with a reason code (I6)".
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);

/// The overlap §8 relies on.
pub const REKEY_OVERLAP: Duration = Duration::from_secs(60);

/// What the scheduler wants done now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Nothing. The keys are fresh.
    Continue,
    /// Begin a new handshake **in place**. The `Tunnel` identity is unchanged —
    /// "a rekey does **not** create a new `Tunnel`".
    BeginRekey,
    /// The keys are past `REJECT_AFTER_*`: zero them and stop using them.
    ZeroizeKeys,
    /// `REKEY_ATTEMPT_TIME` elapsed with no completed handshake. The `Session`
    /// reports failure with `CRYPTO.REKEY_FAILED`.
    AttemptExhausted,
}

/// One key generation's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyState {
    established_at: MonotonicInstant,
    messages_sent: u64,
    /// When the current rekey attempt began, if one is in flight.
    rekey_started_at: Option<MonotonicInstant>,
    /// Monotone count of in-place rekeys. Bounds the data under one key without
    /// creating a new `Tunnel`.
    generation: u64,
}

impl KeyState {
    /// A freshly established generation.
    #[must_use]
    pub const fn new(at: MonotonicInstant) -> Self {
        Self {
            established_at: at,
            messages_sent: 0,
            rekey_started_at: None,
            generation: 0,
        }
    }

    /// The key generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// How many messages this generation has sent.
    #[must_use]
    pub const fn messages_sent(&self) -> u64 {
        self.messages_sent
    }

    /// Records one sent message.
    pub fn observe_send(&mut self) {
        self.messages_sent = self.messages_sent.saturating_add(1);
    }

    /// What to do at `now`.
    ///
    /// The order matters: exhaustion is checked before the reject bound, and the
    /// reject bound before the rekey bound, so a stalled rekey never masks an
    /// expired key.
    #[must_use]
    pub fn evaluate(&self, now: MonotonicInstant) -> Action {
        if let Some(started) = self.rekey_started_at {
            if now.duration_since(started) >= REKEY_ATTEMPT_TIME {
                return Action::AttemptExhausted;
            }
        }
        let age = now.duration_since(self.established_at);
        if age >= REJECT_AFTER_TIME || self.messages_sent >= REJECT_AFTER_MESSAGES {
            return Action::ZeroizeKeys;
        }
        if self.rekey_started_at.is_none()
            && (age >= REKEY_AFTER_TIME || self.messages_sent >= REKEY_AFTER_MESSAGES)
        {
            return Action::BeginRekey;
        }
        Action::Continue
    }

    /// Records that a rekey handshake started.
    pub fn begin_rekey(&mut self, now: MonotonicInstant) {
        self.rekey_started_at = Some(now);
    }

    /// Records that the rekey completed, **in place**.
    ///
    /// `docs/architecture.md` §3.4: "Survives rekey? **Yes, same `Tunnel`, new
    /// key generation**." So this advances the generation and does not mint a new
    /// `TunnelId`.
    pub fn complete_rekey(&mut self, now: MonotonicInstant) {
        self.established_at = now;
        self.messages_sent = 0;
        self.rekey_started_at = None;
        self.generation = self.generation.saturating_add(1);
    }

    /// Whether the keys are still usable at `now`.
    #[must_use]
    pub fn keys_usable(&self, now: MonotonicInstant) -> bool {
        now.duration_since(self.established_at) < REJECT_AFTER_TIME
            && self.messages_sent < REJECT_AFTER_MESSAGES
    }

    /// `docs/reliability.md` §11.3 and T35: a suspend longer than the rekey
    /// window forces a **full** handshake, because the transport keys are gone.
    ///
    /// The gap is measured on the **elapsed** clock by the wake ladder and handed
    /// in — a monotonic clock does not advance across suspend and would answer
    /// "no gap" for an eight-hour sleep.
    #[must_use]
    pub fn force_full_handshake(elapsed_gap: Duration) -> bool {
        elapsed_gap >= REJECT_AFTER_TIME
    }

    /// The window in which a handshake failure is visible before it becomes a
    /// data outage.
    #[must_use]
    pub const fn overlap_window() -> Duration {
        REKEY_OVERLAP
    }
}

/// §7.2's keepalive policy.
///
/// Two distinct keepalives, and conflating them is what `docs/reliability.md`
/// §6.6 spends a section separating:
///
/// - **passive**: 10 s after receiving data with nothing to send;
/// - **persistent**: 25 s, and **only** when the peer is behind NAT or the path
///   is `RELAYED` (R11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepalivePolicy {
    /// Whether the peer is behind NAT.
    pub peer_behind_nat: bool,
    /// Whether the path is relayed.
    pub relayed: bool,
}

/// The passive keepalive delay.
pub const PASSIVE_KEEPALIVE: Duration = Duration::from_secs(10);
/// The persistent keepalive interval.
pub const PERSISTENT_KEEPALIVE: Duration = Duration::from_secs(25);

impl KeepalivePolicy {
    /// Whether the persistent keepalive runs at all.
    ///
    /// R11 makes it conditional, not unconditional: a direct path to a peer with
    /// no NAT in front of it pays nothing.
    #[must_use]
    pub const fn persistent_runs(self) -> bool {
        self.peer_behind_nat || self.relayed
    }

    /// The interval to use, or `None` when no keepalive is needed.
    #[must_use]
    pub const fn interval(self, data_received_nothing_to_send: bool) -> Option<Duration> {
        if self.persistent_runs() {
            Some(PERSISTENT_KEEPALIVE)
        } else if data_received_nothing_to_send {
            Some(PASSIVE_KEEPALIVE)
        } else {
            None
        }
    }
}
