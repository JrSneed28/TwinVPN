//! §6.1's two backoff regimes, drawn from `Env::rng_for("reliability/backoff-jitter")`.
//!
//! **Authority:** `docs/reliability.md` §6.1, §6.3 (the floor rate in
//! `BLOCKED`), §8.2 (which regime a region failover takes), ADR-0018 CD-4.
//!
//! # Two regimes, and why neither is "exponential with full jitter"
//!
//! - **Infrastructure**, decorrelated jitter: `sleep = min(cap, uniform(base, sleep × 3))`.
//!   Each client's next delay depends on *its own previous delay* rather than on
//!   the attempt number, so a fleet knocked off a relay region simultaneously
//!   does not re-synchronise at every step.
//! - **Interactive**, equal jitter: `sleep = d/2 + uniform(0, d/2)` with
//!   `d = min(cap, base × 2ⁿ)`. Guarantees at least half the nominal delay has
//!   elapsed, which bounds how long a user is told "reconnecting" while the
//!   client is asleep. Full jitter can draw near-zero repeatedly and burn the
//!   retry budget in a fraction of a second.
//!
//! Both reset on success, and both are capped in **total attempts** by the retry
//! budget (§6.3), not only by the delay cap.

use core::time::Duration;

use twinvpn_env::{consumers, Env, EnvError};

/// §6.1's two regimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Regime {
    /// Control-plane requests, relay allocation, relay-map fetch, credential
    /// renewal — anything whose failure is **correlated across clients**.
    Infrastructure,
    /// Peer re-handshake, path re-validation, local interface/route
    /// re-assertion — retries that target a peer or the local OS.
    Interactive,
}

impl Regime {
    /// `base`.
    #[must_use]
    pub const fn base(self) -> Duration {
        match self {
            Regime::Infrastructure => Duration::from_millis(500),
            Regime::Interactive => Duration::from_millis(250),
        }
    }

    /// `cap`.
    #[must_use]
    pub const fn cap(self) -> Duration {
        match self {
            Regime::Infrastructure => Duration::from_secs(30),
            Regime::Interactive => Duration::from_secs(15),
        }
    }
}

/// The floor rate `BLOCKED` retries at, forever (§4.6, §6.1).
///
/// `BLOCKED` "retries internally forever, at the floor backoff rate, because
/// giving up on a blocked device would leave a user permanently offline with no
/// path back".
pub const BLOCKED_FLOOR: Duration = Duration::from_secs(30);

/// A backoff state machine for one target.
#[derive(Debug, Clone)]
pub struct Backoff {
    regime: Regime,
    /// Decorrelated jitter's carried state; the interactive regime ignores it.
    last: Duration,
    attempt: u32,
}

impl Backoff {
    /// A fresh backoff in `regime`.
    #[must_use]
    pub fn new(regime: Regime) -> Self {
        Self {
            regime,
            last: regime.base(),
            attempt: 0,
        }
    }

    /// The regime.
    #[must_use]
    pub const fn regime(&self) -> Regime {
        self.regime
    }

    /// How many delays have been drawn since the last success.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    /// §6.1: "Both regimes reset their state on a success."
    pub fn reset(&mut self) {
        self.last = self.regime.base();
        self.attempt = 0;
    }

    /// Draws the next delay.
    ///
    /// # Errors
    ///
    /// Propagates an entropy or derivation failure from `Env::rng_for` rather
    /// than substituting an unjittered delay — an unjittered fleet is the
    /// thundering herd this function exists to prevent.
    pub fn next_delay(&mut self, env: &Env) -> Result<Duration, EnvError> {
        let mut rng = env.rng_for(consumers::BACKOFF_JITTER)?;
        self.attempt = self.attempt.saturating_add(1);
        let cap = self.regime.cap();
        let base = self.regime.base();
        let delay = match self.regime {
            Regime::Infrastructure => {
                // uniform(base, last × 3), clamped to cap.
                let high = self.last.saturating_mul(3).min(cap).max(base);
                let span = high.saturating_sub(base);
                let drawn = base.saturating_add(rng.uniform_duration(span));
                self.last = drawn.min(cap);
                self.last
            }
            Regime::Interactive => {
                let shift = self.attempt.saturating_sub(1).min(20);
                let nominal = base
                    .saturating_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX))
                    .min(cap);
                let half = nominal / 2;
                half.saturating_add(rng.uniform_duration(half))
            }
        };
        Ok(delay)
    }

    /// §3.1's `retry-after` mapping: "backoff floor is
    /// `max(regime delay, retry_after_ms)`".
    #[must_use]
    pub fn with_retry_after(delay: Duration, retry_after: Option<Duration>) -> Duration {
        match retry_after {
            Some(r) => delay.max(r),
            None => delay,
        }
    }
}
