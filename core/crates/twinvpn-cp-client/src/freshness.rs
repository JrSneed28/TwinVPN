//! The `LogHead` freshness tracker, and the backoff regime for reattach.
//!
//! **Authority:** ADR-0002 §S-3 (the three defences and the stated limitation),
//! §11.7 (connection storms and reconnect discipline), `docs/reliability.md`
//! §6.1 (the **infrastructure** backoff regime), `contracts/proto/twinvpn/v1/control_events.proto`
//! (`LogHead`).
//!
//! # `LogHead` is a liveness proof, not trust
//!
//! > *"the `LogHead` signing key is an **online** control-plane key, so a
//! > **compromised** control plane **can forge freshness**. It cannot forge
//! > trust — that requires the Owner authority — but it can lie about there being
//! > nothing to fetch."*
//!
//! [`FreshnessTracker`] therefore produces exactly two things: a `WARN`-class
//! `CONTROL.FRESHNESS_PROOF_MISSING` after three missed intervals, and a flag
//! that says cached documents are **approaching expiry**. It grants nothing,
//! admits nothing, and no other module may take a trust decision from it. The
//! type carries no `is_trusted`, no `verified_recently` and no accessor a caller
//! could mistake for one.

use core::time::Duration;

use twinvpn_env::{Env, MonotonicInstant, Rng};

use crate::error::CpError;
use crate::idempotency::BACKOFF_JITTER_STREAM;

/// The `LogHead` emission interval ADR-0002 §S-3 fixes.
pub const LOG_HEAD_INTERVAL: Duration = Duration::from_secs(60);

/// How many intervals may pass before `CONTROL.FRESHNESS_PROOF_MISSING`.
pub const LOG_HEAD_MISSED_INTERVALS: u64 = 3;

/// Tracks whether a valid, unexpired `LogHead` is arriving.
///
/// Runs on [`twinvpn_env::MonotonicClock`] — the suspend-**exclusive** clock —
/// because this is a protocol timeout, and `common.proto` permits only the
/// monotonic clock for those.
#[derive(Debug, Clone, Copy)]
pub struct FreshnessTracker {
    last_valid: Option<MonotonicInstant>,
    interval: Duration,
    missed_threshold: u64,
}

impl FreshnessTracker {
    /// A tracker that has not yet seen a proof.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last_valid: None,
            interval: LOG_HEAD_INTERVAL,
            missed_threshold: LOG_HEAD_MISSED_INTERVALS,
        }
    }

    /// Records a `LogHead` whose signature verified **and** whose own
    /// `not_after_ms` has not passed.
    ///
    /// An unverified or expired proof must **not** reach here — recording one
    /// would let a control plane extend its own freshness window by replaying an
    /// old statement, which is the one thing `not_after_ms` on the statement
    /// exists to stop.
    pub const fn record_valid(&mut self, at: MonotonicInstant) {
        self.last_valid = Some(at);
    }

    /// How many intervals have passed since the last valid proof.
    #[must_use]
    pub fn intervals_missed(&self, now: MonotonicInstant) -> u64 {
        let Some(last) = self.last_valid else {
            return 0;
        };
        let elapsed = now.duration_since(last).as_micros();
        let interval = self.interval.as_micros().max(1);
        u64::try_from(elapsed / interval).unwrap_or(u64::MAX)
    }

    /// The diagnostic, once three intervals have passed.
    ///
    /// Returns `None` before the threshold and before the first proof: a device
    /// that has just attached has not "missed" anything.
    #[must_use]
    pub fn overdue(&self, now: MonotonicInstant) -> Option<CpError> {
        let missed = self.intervals_missed(now);
        (missed >= self.missed_threshold).then_some(CpError::FreshnessProofMissing {
            intervals_missed: missed,
        })
    }

    /// Whether cached documents should now be treated as **approaching expiry**.
    ///
    /// This is the whole behavioural consequence. It does not expire anything, it
    /// does not suspend anything, and it never withdraws baseline reachability.
    #[must_use]
    pub fn treat_documents_as_approaching_expiry(&self, now: MonotonicInstant) -> bool {
        self.overdue(now).is_some()
    }
}

impl Default for FreshnessTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// The `reliability.md` §6.1 **infrastructure** backoff regime: decorrelated
/// jitter, base 500 ms, cap 30 s.
///
/// ADR-0002 R-b: *"Reuse, do not redefine, the retry policy … This ADR sets no
/// timer values that reliability.md already owns."* So the two constants below
/// are `reliability.md`'s, cited, not chosen here — and the regime is the right
/// tool because **control-plane failure is correlated across the fleet**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InfrastructureBackoff {
    /// 500 ms.
    pub base: Duration,
    /// 30 s.
    pub cap: Duration,
    previous: Duration,
}

impl InfrastructureBackoff {
    /// `reliability.md` §6.1's values.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            base: Duration::from_millis(500),
            cap: Duration::from_secs(30),
            previous: Duration::from_millis(500),
        }
    }

    /// The next delay, decorrelated-jitter style: uniform in
    /// `[base, min(cap, previous * 3)]`.
    ///
    /// Every draw comes from `Env::rng_for(BACKOFF_JITTER)`, so a seeded scenario
    /// reproduces the whole reconnect schedule exactly.
    pub fn next(&mut self, rng: &mut dyn Rng) -> Duration {
        let ceiling = self.previous.saturating_mul(3).min(self.cap).max(self.base);
        let span = ceiling.saturating_sub(self.base);
        let delay = self.base.saturating_add(rng.uniform_duration(span));
        self.previous = delay;
        delay
    }

    /// Resets after a successful attach, so the next outage starts at `base`.
    pub const fn reset(&mut self) {
        self.previous = self.base;
    }
}

impl Default for InfrastructureBackoff {
    fn default() -> Self {
        Self::new()
    }
}

/// A drain: HTTP/3 `GOAWAY` carrying a deadline.
///
/// ADR-0002 §11.7 rule 1: each client picks its reattach instant **uniformly
/// from `[0, drain_deadline_ms)`** — the same herd-safe pattern
/// `reliability.md` T37 uses for relay drain. Picking `deadline` itself, or
/// reconnecting immediately, is how a planned restart becomes a thundering herd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Drain {
    /// The advertised deadline. ADR-0002's default is 120 s.
    pub deadline: Duration,
}

impl Drain {
    /// ADR-0002 §11.7 rule 1's default.
    pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(120);

    /// Builds from the server's advertised value, clamping an absurd one.
    #[must_use]
    pub fn from_millis(deadline_ms: u64) -> Self {
        let deadline = Duration::from_millis(deadline_ms);
        Self {
            deadline: if deadline.is_zero() {
                Self::DEFAULT_DEADLINE
            } else {
                deadline.min(Duration::from_secs(600))
            },
        }
    }

    /// This client's reattach instant, uniform in `[0, deadline)`.
    pub fn reattach_after(self, rng: &mut dyn Rng) -> Duration {
        rng.uniform_duration(self.deadline)
    }
}

/// Draws one backoff delay from the injected environment.
///
/// # Errors
///
/// [`CpError::Env`] if the stream cannot be opened. No fallback: a
/// non-random backoff is a synchronized fleet.
pub fn next_backoff(env: &Env, backoff: &mut InfrastructureBackoff) -> Result<Duration, CpError> {
    let mut rng = env.rng_for(BACKOFF_JITTER_STREAM)?;
    Ok(backoff.next(rng.as_mut()))
}

#[cfg(test)]
mod tests {
    use super::{Drain, FreshnessTracker, InfrastructureBackoff, LOG_HEAD_INTERVAL};
    use core::time::Duration;
    use twinvpn_env::MonotonicInstant;

    #[test]
    fn three_missed_intervals_produce_the_registered_code() {
        let mut t = FreshnessTracker::new();
        let start = MonotonicInstant::from_micros(0);
        t.record_valid(start);

        let two = start.saturating_add(LOG_HEAD_INTERVAL * 2);
        assert!(t.overdue(two).is_none(), "two intervals is not yet overdue");
        assert!(!t.treat_documents_as_approaching_expiry(two));

        let three = start.saturating_add(LOG_HEAD_INTERVAL * 3);
        let err = three_err(&t, three);
        assert_eq!(
            err.reason_code().as_str(),
            "CONTROL.FRESHNESS_PROOF_MISSING"
        );
        assert!(t.treat_documents_as_approaching_expiry(three));
        // It never becomes terminal and never withdraws reachability.
        assert!(!err.reason_code().terminal());
        assert!(err.permits_offline_reconnect());
    }

    fn three_err(t: &FreshnessTracker, at: MonotonicInstant) -> crate::CpError {
        t.overdue(at).expect("three intervals missed")
    }

    #[test]
    fn a_tracker_that_has_seen_nothing_is_not_yet_overdue() {
        let t = FreshnessTracker::new();
        let late = MonotonicInstant::from_micros(9_999_999_999);
        assert!(t.overdue(late).is_none());
    }

    #[test]
    fn backoff_stays_inside_the_reliability_md_regime() {
        let env = crate::testing::test_env();
        let mut backoff = InfrastructureBackoff::new();
        assert_eq!(backoff.base, Duration::from_millis(500));
        assert_eq!(backoff.cap, Duration::from_secs(30));
        let mut rng = env.rng_for(super::BACKOFF_JITTER_STREAM).expect("stream");
        for _ in 0..64 {
            let delay = backoff.next(rng.as_mut());
            assert!(delay >= backoff.base, "never below base");
            assert!(delay <= backoff.cap, "never above cap");
        }
        backoff.reset();
        let after_reset = backoff.next(rng.as_mut());
        assert!(after_reset <= Duration::from_millis(1_500));
    }

    #[test]
    fn a_drain_spreads_reattach_across_the_whole_window() {
        let env = crate::testing::test_env();
        let drain = Drain::from_millis(120_000);
        assert_eq!(drain.deadline, Duration::from_secs(120));
        let mut rng = env.rng_for(super::BACKOFF_JITTER_STREAM).expect("stream");
        let mut saw_early = false;
        let mut saw_late = false;
        for _ in 0..256 {
            let at = drain.reattach_after(rng.as_mut());
            assert!(at < drain.deadline, "uniform in [0, deadline)");
            if at < Duration::from_secs(30) {
                saw_early = true;
            }
            if at > Duration::from_secs(90) {
                saw_late = true;
            }
        }
        assert!(saw_early && saw_late, "the herd must actually be spread");
    }

    #[test]
    fn a_zero_or_absurd_drain_deadline_falls_back_to_the_default() {
        assert_eq!(Drain::from_millis(0).deadline, Drain::DEFAULT_DEADLINE);
        assert_eq!(
            Drain::from_millis(u64::MAX).deadline,
            Duration::from_secs(600)
        );
    }
}
