//! ADR-0006 §11.2's score, and §11.3's "selection is a reordering, never a
//! filter".
//!
//! **Authority:** ADR-0006 §11.2 (normative, base 1000), §11.3 rules 1–4;
//! `docs/reliability.md` §6.3, §7.4; ADR-0005 §10.
//!
//! # The composition rule is the whole design
//!
//! §11.2: "the server's total contribution is capped at **+100** while the
//! measurement terms are worth up to −410. Therefore **any relay with a ≥ 100 ms
//! measured RTT advantage outranks any server preference, unconditionally**, and
//! a relay the device has actually failed to bind outranks nothing."
//!
//! [`score`] is the arithmetic form of "the client's own measurement overrides a
//! stale ranking", and [`Selection::order`] returns a **total order over the
//! whole admissible set** — never a subset, and never empty while the map is
//! non-empty.

use twinvpn_types::RelayId;

use crate::map::HealthState;

use crate::map::{AdminState, Relay};

/// The base score. One point ≡ one millisecond of RTT.
pub const BASE: i32 = 1000;

/// Everything measured or reported about one relay.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Observations {
    /// EWMA RTT in milliseconds, α = 1/8. Contributes −1 each, floored at −250.
    pub ewma_rtt_ms: u32,
    /// Loss percentage over the 30 s window. −8 each, floored at −120.
    pub loss_pct: u32,
    /// EWMA jitter in milliseconds. −0.5 each, floored at −40.
    pub ewma_jitter_ms: u32,
    /// The map's age in hours, for the server-rank freshness decay.
    pub map_age_hours: u32,
    /// The reported `HealthState`.
    pub health: HealthState,
    /// Region locality: 0 same, −`added_rtt_ms_p50` adjacent, −200 other.
    /// **Replaced by measurement once measured**, which the caller does by
    /// passing 0 here and a real `ewma_rtt_ms`.
    pub region_locality_penalty: i32,
    /// S-31's EWMA bind-success rate for this relay **on this network
    /// fingerprint**, 0.0–1.0. Contributes up to +60.
    pub bind_success_rate: f32,
    /// The circuit breaker's penalty, from `twinvpn-session`. −400 when open.
    /// **A delta, never a filter.**
    pub breaker_penalty: i32,
}

/// §11.2's table, term by term.
#[must_use]
pub fn score(relay: &Relay, obs: Observations) -> i32 {
    let rtt = -i32::try_from(obs.ewma_rtt_ms).unwrap_or(i32::MAX).max(-250);
    let loss = -(i32::try_from(obs.loss_pct.saturating_mul(8)).unwrap_or(i32::MAX)).max(-120);
    let jitter = -i32::try_from(obs.ewma_jitter_ms / 2).unwrap_or(i32::MAX).max(-40);

    // Server rank × freshness: 1.0 at age <= 1 h, decaying linearly to 0.0 at
    // 24 h. Capped at +100, which is what makes a 100 ms measured advantage win
    // unconditionally.
    let freshness = if obs.map_age_hours <= 1 {
        1.0f32
    } else if obs.map_age_hours >= 24 {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        let age = f32::from(u16::try_from(obs.map_age_hours - 1).unwrap_or(u16::MAX));
        1.0 - (age / 23.0)
    };
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    let rank = ((relay.server_rank.min(100) as f32) * freshness) as i32;
    debug_assert!(rank <= MAX_SERVER_CONTRIBUTION);

    let load = match relay.load_class {
        0 => 0,
        1 => -20,
        2 => -60,
        _ => -120,
    };

    #[allow(clippy::cast_possible_truncation)]
    let bind_history = (obs.bind_success_rate.clamp(0.0, 1.0) * 60.0) as i32;

    // +120 only when a self-hosted relay can actually signal drain and honour
    // caps: ADR-0005 §10's "SHOULD rank below hosted" is satisfied by the ABSENT
    // bonus, not by a penalty.
    let self_hosted = i32::from(relay.self_hosted && relay.supports_drain && relay.supports_caps)
        * 120;

    let draining = i32::from(relay.admin_state == AdminState::Draining) * -300;

    BASE + rtt
        + loss
        + jitter
        + rank
        + obs.health.delta()
        + load
        + obs.region_locality_penalty
        + bind_history
        + self_hosted
        + draining
        + obs.breaker_penalty
}

/// The server's maximum possible contribution (§11.2's composition rule).
pub const MAX_SERVER_CONTRIBUTION: i32 = 100;
/// The measurement terms' maximum possible contribution.
pub const MAX_MEASUREMENT_PENALTY: i32 = -410;

/// One scored candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scored {
    /// Which relay.
    pub id: RelayId,
    /// Its score.
    pub score: i32,
    /// Whether its breaker is open, so the half-open rule can be applied.
    pub breaker_open: bool,
}

/// The outcome of one selection run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// The **whole** admissible set, best first. Never a subset.
    pub order: Vec<Scored>,
    /// Set when every candidate's breaker is open, in which case the
    /// highest-scoring one is returned as the half-open probe rather than the
    /// set being empty.
    pub all_breakers_open: bool,
}

impl Selection {
    /// Orders the admissible set. **A total order, never a filter.**
    ///
    /// §11.3 rule 3: "if every candidate's breaker is open, selection MUST
    /// return the highest-scoring candidate as the half-open probe rather than
    /// returning empty. **An empty candidate set is never a legal output of
    /// selection while the map is non-empty.**"
    #[must_use]
    pub fn order(mut scored: Vec<Scored>) -> Self {
        let all_breakers_open = !scored.is_empty() && scored.iter().all(|s| s.breaker_open);
        // Descending score, then ascending relay_id so the order is reproducible
        // rather than dependent on input order.
        scored.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| a.id.to_array().cmp(&b.id.to_array()))
        });
        Self {
            order: scored,
            all_breakers_open,
        }
    }

    /// The relay to try first.
    #[must_use]
    pub fn best(&self) -> Option<Scored> {
        self.order.first().copied()
    }

    /// Whether selection returned everything it was given.
    ///
    /// Asserted rather than assumed, because "selection is a **total ordering**,
    /// never a filter" is the property the `HealthState`-must-not-gate rule
    /// depends on.
    #[must_use]
    pub fn is_total_over(&self, admissible_count: usize) -> bool {
        self.order.len() == admissible_count
    }
}

/// §11.6's standby rule: "the highest-scoring candidate whose `failure_domain`
/// **differs** from the primary's".
///
/// A standby that fails with its primary is not a standby.
#[must_use]
pub fn standby_for<'a>(
    order: &Selection,
    relays: &'a [&'a Relay],
    primary: RelayId,
) -> Option<&'a Relay> {
    let primary_domain = relays
        .iter()
        .find(|r| r.id == primary)
        .map(|r| r.failure_domain.clone())?;
    order.order.iter().find_map(|s| {
        relays
            .iter()
            .find(|r| r.id == s.id && r.id != primary && r.failure_domain != primary_domain)
            .copied()
    })
}
