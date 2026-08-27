//! `networking.md` §4.1's scoring formula and §4.3's guards, with
//! `docs/reliability.md` §7.4's admissibility rules over them.
//!
//! **Authority:** `docs/networking.md` §4.1, §4.2, §4.3, §4.4;
//! `docs/reliability.md` §7.4 (which inputs are admissible, and what may never
//! be one), §7.5 (`T_MIGRATE_COOLDOWN`), §5.3's `T_UPGRADE_*` family.
//!
//! # No `EVENTUAL` fact may gate a connection attempt
//!
//! §7.4: "Relay `HealthState` (S-10), peer presence (S-11), relay-set age (S-09)
//! … score delta **only**; MUST NOT suppress an attempt. … **Only a `Path`
//! proves reachability**; everything else is a hint, and a device's own
//! measurement always outranks a reported one."
//!
//! So [`Inputs`] carries `health_delta` as an `i32` the score **adds**, and there
//! is no admissibility predicate anywhere in this module. The circuit breaker is
//! the same shape for the same reason: "a large penalty — **never a filter**".

use core::time::Duration;

use crate::candidate::Kind;

/// The measured and reported inputs a score is computed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Inputs {
    /// EWMA RTT in milliseconds, α = 1/8.
    pub ewma_rtt_ms: u32,
    /// Loss as a percentage, over a sliding 30 s window.
    pub loss_pct: u32,
    /// EWMA jitter in milliseconds.
    pub ewma_jitter_ms: u32,
    /// Seconds since the last validation failure.
    pub uptime_s: u32,
    /// The circuit breaker's penalty, from `twinvpn-session`'s
    /// `Breaker::score_penalty`. **A delta, never a filter.**
    pub breaker_penalty: i32,
    /// The relay `HealthState` / presence / relay-set-age delta. **A hint.**
    pub health_delta: i32,
}

/// `networking.md` §4.1's formula, verbatim.
///
/// ```text
/// score(path) = base(candidate_type)
///             − rtt_penalty(ewma_rtt_ms)        # 1 point per ms, capped at 60
///             − loss_penalty(loss_pct * 8)
///             − jitter_penalty(ewma_jitter_ms / 2)
///             + family_bonus(IPv6 ? 5 : 0)
///             + stability_bonus(min(uptime_s / 60, 20))
/// ```
#[must_use]
pub fn score(kind: Kind, family: twinvpn_types::AddressFamily, inputs: Inputs) -> i32 {
    let base = i32::try_from(kind.priority()).unwrap_or(i32::MAX);
    let rtt = i32::try_from(inputs.ewma_rtt_ms.min(60)).unwrap_or(60);
    let loss = i32::try_from(inputs.loss_pct.saturating_mul(8)).unwrap_or(i32::MAX);
    let jitter = i32::try_from(inputs.ewma_jitter_ms / 2).unwrap_or(i32::MAX);
    let family_bonus = i32::from(family == twinvpn_types::AddressFamily::V6) * 5;
    let stability = i32::try_from((inputs.uptime_s / 60).min(20)).unwrap_or(20);
    base.saturating_sub(rtt)
        .saturating_sub(loss)
        .saturating_sub(jitter)
        .saturating_add(family_bonus)
        .saturating_add(stability)
        .saturating_add(inputs.breaker_penalty)
        .saturating_add(inputs.health_delta)
}

/// `PATH_BETTER`: "candidate score exceeds the active path's by **≥ 15 points and
/// ≥ 10 ms** RTT improvement."
///
/// Both, not either. The conjunction is what makes §4.1's stability bonus and the
/// hysteresis rule "deliberately conservative: flapping between two near-equal
/// paths is worse for the user than sitting on the slightly worse one".
pub const BETTER_SCORE_MARGIN: i32 = 15;
/// The RTT half of `PATH_BETTER`.
pub const BETTER_RTT_MARGIN_MS: u32 = 10;
/// `PATH_STABLE`: `PATH_BETTER` held for ≥ 3 probe intervals.
pub const STABLE_INTERVALS: u32 = 3;
/// The default probe interval those three are counted at.
pub const STABLE_WINDOW: Duration = Duration::from_secs(15);

/// Whether `candidate` beats `active` by both margins.
#[must_use]
pub const fn path_better(
    candidate_score: i32,
    active_score: i32,
    candidate_rtt_ms: u32,
    active_rtt_ms: u32,
) -> bool {
    let score_ok = candidate_score >= active_score + BETTER_SCORE_MARGIN;
    let rtt_ok = active_rtt_ms >= candidate_rtt_ms + BETTER_RTT_MARGIN_MS;
    score_ok && rtt_ok
}

/// `PATH_FAILING`: "3 consecutive missed keepalives, or loss > 15 % over 10 s, or
/// a data-plane send error."
///
/// §7.4 reconciles this with `T_SUSPECT` (2 missed) and `T_DEAD` (5 missed): it
/// is "the **middle rung** and not a synonym for path death", and it authorises
/// demoting a *promoted* path back to an already-validated one — nothing more.
#[must_use]
pub const fn path_failing(missed_keepalives: u32, loss_pct_10s: u32, send_error: bool) -> bool {
    missed_keepalives >= 3 || loss_pct_10s > 15 || send_error
}

/// The anti-flap state for one `(peer, network fingerprint)` pair.
///
/// §7.4's one exception is the load-bearing part: "A **hard** failure signal is
/// never suppressed by dwell, by flap suppression, or by cooldown — **anti-flap
/// must never trap a `Session` on a dead path**."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AntiFlap {
    /// When the last promotion happened, for `T_UPGRADE_DWELL`.
    promoted_at: Option<twinvpn_env::MonotonicInstant>,
    /// Oscillations counted inside `T_UPGRADE_FLAP_WINDOW`.
    oscillations: u32,
    /// When the counting window opened.
    window_started: Option<twinvpn_env::MonotonicInstant>,
    /// When suppression ends, if it is in force.
    suppressed_until: Option<twinvpn_env::MonotonicInstant>,
}

/// After a `RELAYED → WAN_DIRECT` promotion, a **quality-only** reverse
/// migration is refused for this long.
pub const T_UPGRADE_DWELL: Duration = Duration::from_secs(120);
/// The oscillation observation window.
pub const T_UPGRADE_FLAP_WINDOW: Duration = Duration::from_secs(600);
/// Oscillations that trip suppression.
pub const N_UPGRADE_FLAP: u32 = 3;
/// How long the direct candidate is suppressed, **on that network fingerprint
/// only**.
pub const T_UPGRADE_FLAP_SUPPRESS: Duration = Duration::from_secs(1800);

impl AntiFlap {
    /// No promotions yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            promoted_at: None,
            oscillations: 0,
            window_started: None,
            suppressed_until: None,
        }
    }

    /// Records a promotion, which opens the dwell window.
    pub fn observe_promotion(&mut self, now: twinvpn_env::MonotonicInstant) {
        self.promoted_at = Some(now);
        match self.window_started {
            Some(start) if now.duration_since(start) <= T_UPGRADE_FLAP_WINDOW => {
                self.oscillations = self.oscillations.saturating_add(1);
            }
            _ => {
                self.window_started = Some(now);
                self.oscillations = 1;
            }
        }
        if self.oscillations >= N_UPGRADE_FLAP {
            self.suppressed_until = Some(now.saturating_add(T_UPGRADE_FLAP_SUPPRESS));
        }
    }

    /// Whether a **quality-only** demotion is admissible at `now`.
    #[must_use]
    pub fn quality_demotion_admissible(&self, now: twinvpn_env::MonotonicInstant) -> bool {
        match self.promoted_at {
            Some(at) => now.duration_since(at) >= T_UPGRADE_DWELL,
            None => true,
        }
    }

    /// Whether a **hard** demotion is admissible.
    ///
    /// Always. §7.4: never suppressed by dwell, flap suppression, or cooldown.
    #[must_use]
    pub const fn hard_demotion_admissible(&self) -> bool {
        true
    }

    /// Whether the direct candidate is flap-suppressed at `now`.
    #[must_use]
    pub fn is_suppressed(&self, now: twinvpn_env::MonotonicInstant) -> bool {
        self.suppressed_until
            .is_some_and(|until| !now.reached(until))
    }

    /// A network change clears suppression: "any network change clears it", and
    /// §7.5 adds that a cooldown "does not survive a network-change event: a new
    /// network is new evidence".
    pub fn on_network_change(&mut self) {
        self.suppressed_until = None;
        self.oscillations = 0;
        self.window_started = None;
    }
}

/// `N_UPGRADE_GIVEUP`: consecutive failed upgrade attempts on one network
/// fingerprint after which timer-driven probing suspends.
///
/// **Probing never stops permanently** (R-12): it becomes *event-driven*.
pub const N_UPGRADE_GIVEUP: u32 = 20;

/// Whether the upgrade prober should still run on a timer.
#[must_use]
pub const fn timer_driven_probing(consecutive_failures: u32) -> bool {
    consecutive_failures < N_UPGRADE_GIVEUP
}
