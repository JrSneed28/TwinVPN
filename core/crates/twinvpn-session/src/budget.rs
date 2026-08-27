//! §6.3's retry budgets, circuit breakers, and the global brake.
//!
//! **Authority:** `docs/reliability.md` §6.3, §8.2 (the brake during a region
//! failover), ADR-0006 §11.3 rule 3 (the −400 penalty).
//!
//! # Selection is a total ordering, never a filter
//!
//! §6.3 withdraws the earlier "skipped entirely by selection" wording:
//!
//! > an empty candidate set is not a legal output of selection while the map is
//! > non-empty, and a relay whose breaker is open is still better than no relay
//! > at all.
//!
//! So [`Breaker`] exposes [`Breaker::score_penalty`] — a number selection
//! **adds** — and offers no "is this candidate admissible" predicate at all.
//! There is nothing here to filter with.

use core::time::Duration;

use twinvpn_env::MonotonicInstant;
use twinvpn_types::{DeviceId, RegionId, RelayId};

/// The target class a budget is kept per (§6.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetClass {
    /// The control plane as a whole.
    ControlPlane,
    /// One relay.
    Relay(RelayId),
    /// One region.
    Region(RegionId),
    /// One peer.
    Peer(DeviceId),
}

/// ADR-0006 §11.3 rule 3's score penalty for an open breaker.
pub const OPEN_BREAKER_PENALTY: i32 = -400;

/// Floor refill: 3 tokens per minute, so "a target which is failing 100 % still
/// gets probed often enough to notice recovery".
pub const REFILL_FLOOR_PER_MIN: f64 = 3.0;
/// Burst.
pub const BURST: f64 = 10.0;
/// Refill is 20 % of the observed success rate for the class.
pub const REFILL_SUCCESS_FRACTION: f64 = 0.20;
/// Consecutive failures that open the breaker.
pub const OPEN_AFTER_FAILURES: u32 = 5;
/// Consecutive successes that close it.
pub const CLOSE_AFTER_SUCCESSES: u32 = 2;
/// §6.3's global brake: with breakers open on more than half the reachable relay
/// set, relay retries stop for this long.
pub const GLOBAL_BRAKE: Duration = Duration::from_secs(60);

/// A token bucket for one target class.
///
/// "A retry costs one token; a **first attempt costs none**" — which is what
/// keeps the fleet explorable when every breaker is open.
#[derive(Debug, Clone)]
pub struct RetryBudget {
    tokens: f64,
    /// Observed successes per minute for this class, feeding the refill rate.
    success_rate_per_min: f64,
    last_refill: MonotonicInstant,
}

impl RetryBudget {
    /// A full bucket at `now`.
    #[must_use]
    pub const fn new(now: MonotonicInstant) -> Self {
        Self {
            tokens: BURST,
            success_rate_per_min: 0.0,
            last_refill: now,
        }
    }

    /// Records an observed success, which both refills faster and closes a
    /// breaker.
    pub fn observe_success(&mut self) {
        self.success_rate_per_min = (self.success_rate_per_min * 0.8) + (60.0 * 0.2);
    }

    /// Records an observed failure.
    pub fn observe_failure(&mut self) {
        self.success_rate_per_min *= 0.8;
    }

    /// The current refill rate: 20 % of the observed success rate, floored at 3
    /// per minute.
    #[must_use]
    pub fn refill_per_min(&self) -> f64 {
        (self.success_rate_per_min * REFILL_SUCCESS_FRACTION).max(REFILL_FLOOR_PER_MIN)
    }

    /// Advances the bucket to `now`.
    pub fn refill(&mut self, now: MonotonicInstant) {
        let elapsed = now.duration_since(self.last_refill);
        if elapsed.is_zero() {
            return;
        }
        let minutes = elapsed.as_secs_f64() / 60.0;
        self.tokens = (self.tokens + self.refill_per_min() * minutes).min(BURST);
        self.last_refill = now;
    }

    /// Whether a **retry** may proceed. A first attempt does not ask.
    #[must_use]
    pub fn has_token(&self) -> bool {
        self.tokens >= 1.0
    }

    /// Spends a token for a retry. Returns `false` when the bucket is empty, at
    /// which point `EV_RETRY_BUDGET_EXHAUSTED` fires.
    pub fn spend(&mut self, now: MonotonicInstant) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Tokens remaining, for evidence.
    #[must_use]
    pub fn tokens(&self) -> f64 {
        self.tokens
    }
}

/// A circuit-breaker state (§6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BreakerState {
    /// Normal.
    Closed,
    /// Penalised in selection; one probe is admitted after a decorrelated delay.
    Open,
    /// Exactly one probe in flight.
    HalfOpen,
}

/// How a breaker opens, which decides how it closes again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenReason {
    /// A `TRANSIENT` failure run, or budget exhaustion. Reopens on a delay.
    Transient,
    /// A `PERSISTENT` code: "opens the breaker **for its named
    /// `retry_precondition`** rather than for a duration".
    UntilPrecondition,
    /// A `FATAL` code: "opens it permanently — retrying an `EV_AUTH_REJECTED` on
    /// a timer is pure waste".
    Permanent,
}

/// One target's breaker.
#[derive(Debug, Clone)]
pub struct Breaker {
    state: BreakerState,
    consecutive_failures: u32,
    consecutive_successes: u32,
    open_reason: Option<OpenReason>,
}

impl Default for Breaker {
    fn default() -> Self {
        Self::new()
    }
}

impl Breaker {
    /// A closed breaker.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: BreakerState::Closed,
            consecutive_failures: 0,
            consecutive_successes: 0,
            open_reason: None,
        }
    }

    /// The state.
    #[must_use]
    pub const fn state(&self) -> BreakerState {
        self.state
    }

    /// Why it is open, where it is.
    #[must_use]
    pub const fn open_reason(&self) -> Option<OpenReason> {
        self.open_reason
    }

    /// The score delta selection adds. **Never a filter** (§6.3, §7.4).
    #[must_use]
    pub const fn score_penalty(&self) -> i32 {
        match self.state {
            BreakerState::Closed => 0,
            BreakerState::Open | BreakerState::HalfOpen => OPEN_BREAKER_PENALTY,
        }
    }

    /// Records a failure, keyed on the code's `class` rather than on an error
    /// type (§3.1: "the retry policy, the backoff regime, and the circuit
    /// breaker are all driven by `class`, never guessed").
    pub fn observe_failure(&mut self, class: twinvpn_types::ErrorClass) {
        use twinvpn_types::ErrorClass as C;
        self.consecutive_successes = 0;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        match class {
            // §6.3: "A `POLICY` code does not open a breaker at all: it routes to
            // `BLOCKED` via T29, where the re-establishment loop keeps running."
            C::Policy => {}
            C::Fatal => {
                self.state = BreakerState::Open;
                self.open_reason = Some(OpenReason::Permanent);
            }
            C::Persistent => {
                self.state = BreakerState::Open;
                self.open_reason = Some(OpenReason::UntilPrecondition);
            }
            C::Transient => {
                if self.consecutive_failures >= OPEN_AFTER_FAILURES {
                    self.state = BreakerState::Open;
                    self.open_reason = Some(OpenReason::Transient);
                }
            }
        }
    }

    /// Records budget exhaustion, which opens the breaker like a failure run.
    pub fn observe_budget_exhausted(&mut self) {
        self.state = BreakerState::Open;
        self.open_reason = Some(OpenReason::Transient);
    }

    /// Admits exactly one probe after one decorrelated-jitter delay.
    ///
    /// Refuses for a `Permanent` open: a `FATAL` condition is revived by T33's
    /// precondition, never by a timer.
    pub fn try_half_open(&mut self) -> bool {
        if self.state == BreakerState::Open && self.open_reason == Some(OpenReason::Transient) {
            self.state = BreakerState::HalfOpen;
            true
        } else {
            false
        }
    }

    /// The named precondition was satisfied, or the user re-authorised.
    pub fn precondition_met(&mut self) {
        if matches!(
            self.open_reason,
            Some(OpenReason::UntilPrecondition | OpenReason::Permanent)
        ) {
            self.state = BreakerState::HalfOpen;
        }
    }

    /// Records a success. Two in a row close the breaker.
    pub fn observe_success(&mut self) {
        self.consecutive_failures = 0;
        self.consecutive_successes = self.consecutive_successes.saturating_add(1);
        if self.consecutive_successes >= CLOSE_AFTER_SUCCESSES {
            self.state = BreakerState::Closed;
            self.open_reason = None;
        }
    }
}

/// §6.3's global brake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalBrake {
    engaged_until: Option<MonotonicInstant>,
}

impl Default for GlobalBrake {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalBrake {
    /// Disengaged.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            engaged_until: None,
        }
    }

    /// Engages the brake when more than half the reachable relay set has an open
    /// breaker.
    ///
    /// Returns whether it engaged, so the caller can emit the accompanying
    /// `RELAY.*` condition exactly once.
    pub fn evaluate(&mut self, open: usize, reachable: usize, now: MonotonicInstant) -> bool {
        if reachable > 0 && open * 2 > reachable {
            let until = now.saturating_add(GLOBAL_BRAKE);
            let newly = self.engaged_until.is_none();
            self.engaged_until = Some(until);
            newly
        } else {
            false
        }
    }

    /// Whether relay retries are braked at `now`.
    #[must_use]
    pub fn is_engaged(&mut self, now: MonotonicInstant) -> bool {
        match self.engaged_until {
            Some(until) if now.reached(until) => {
                self.engaged_until = None;
                false
            }
            Some(_) => true,
            None => false,
        }
    }
}
