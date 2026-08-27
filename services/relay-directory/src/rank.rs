//! The advisory score (ADR-0006 §11.2) and the HRW spread (§11.5, §11.7).
//!
//! # The composition rule is the whole design
//!
//! §11.2, verbatim:
//!
//! > **The composition rule that discharges RQ3 and the S-09/S-10 "on conflict"
//! > column:** the server's total contribution is capped at **+100** while the
//! > measurement terms are worth up to **−410**. Therefore **any relay with a
//! > ≥100 ms measured RTT advantage outranks any server preference,
//! > unconditionally**, and a relay the device has actually failed to bind
//! > outranks nothing.
//!
//! That is why this module's server-side output is called [`ServerAdvice`] and
//! why [`score`] takes the client's own [`Measured`] as a *separate* argument
//! that is not defaulted: the arithmetic guarantee only exists if the two inputs
//! stay distinguishable, and `measurement_always_beats_server_preference` pins it.
//!
//! The service computes this locally for its **own** diagnostics — "why would a
//! device pick this relay" — and publishes only `server_rank`, `load_class`,
//! `capacity_weight` and `admin_state`. **The score itself is never published**;
//! publishing a computed ranking is exactly the frozen central view ADR-0006 §12
//! rejects.
//!
//! # HRW decides *redistribution*, score decides *ordinary selection*
//!
//! §11.7: "Independent score-optimising choice — every device picking 'the best
//! surviving relay' — is precisely what creates the hot spot, and is why HRW
//! rather than score decides *redistribution* while score decides *ordinary
//! selection*."

use crate::fleet::{AdminState, RelayRecord};

/// Base score. One point ≡ one millisecond of RTT (ADR-0006 §11.2).
pub const BASE: i32 = 1_000;

/// The maximum the server side may ever contribute, in total.
pub const SERVER_CAP: i32 = 100;

/// The maximum the client's own measurements may subtract, in total.
pub const MEASUREMENT_FLOOR: i32 = -410;

/// S-10's `HealthState`, as a score delta. **Never a gate.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Health {
    /// 0.
    Healthy,
    /// −40.
    Degraded,
    /// −150. Still a candidate: §11.3 rule 1.
    Unhealthy,
    /// 0 — the health service being down must cost nothing.
    #[default]
    Unknown,
}

impl Health {
    /// The delta.
    #[must_use]
    pub const fn delta(self) -> i32 {
        match self {
            Health::Healthy | Health::Unknown => 0,
            Health::Degraded => -40,
            Health::Unhealthy => -150,
        }
    }
}

/// Where a relay sits relative to the device's own region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locality {
    /// Same region: 0.
    Same,
    /// Adjacent: −`added_rtt_ms_p50`.
    Adjacent(u32),
    /// Elsewhere: −200.
    Other,
}

/// What this service knows and may contribute. **Capped at [`SERVER_CAP`].**
#[derive(Debug, Clone, Copy)]
pub struct ServerAdvice {
    /// `server_rank`, 0–100.
    pub server_rank: u8,
    /// Age of the ranking, in milliseconds. Freshness decays it linearly from
    /// 1.0 at ≤ 1 h to 0.0 at 24 h.
    pub rank_age_ms: u64,
    /// S-10's aggregate, which is advisory and may be `Unknown`.
    pub health: Health,
    /// 0–3.
    pub load_class: u8,
    /// Where the relay sits, until the device measures.
    pub locality: Locality,
    /// `self_hosted ∧ supports_drain ∧ supports_caps` ⇒ +120.
    pub self_hosted_bonus: bool,
    /// `admin_state = DRAINING` ⇒ −300.
    pub draining: bool,
}

impl ServerAdvice {
    /// The `server_rank` term, decayed by freshness and capped at +100.
    #[must_use]
    pub fn ranked_contribution(&self) -> i32 {
        let hour = 3_600_000_u64;
        let day = 24 * hour;
        let freshness_num = if self.rank_age_ms <= hour {
            day - hour
        } else {
            day.saturating_sub(self.rank_age_ms)
        };
        let denom = i64::try_from(day - hour).unwrap_or(1);
        let rank = i64::from(self.server_rank);
        let num = i64::try_from(freshness_num).unwrap_or(0);
        let scaled = i32::try_from(rank * num / denom).unwrap_or(SERVER_CAP);
        scaled.clamp(0, SERVER_CAP)
    }
}

/// The device's own observations. **Unbounded in influence, by design.**
#[derive(Debug, Clone, Copy, Default)]
pub struct Measured {
    /// EWMA RTT, milliseconds. −1× per ms, floored at −250.
    pub rtt_ms: Option<u32>,
    /// Loss percentage over the 30 s window. −8× per point, floored at −120.
    pub loss_percent: Option<f32>,
    /// EWMA jitter, milliseconds. −0.5× per ms, floored at −40.
    pub jitter_ms: Option<u32>,
    /// S-31 bind-success EWMA on this network fingerprint, 0.0–1.0. +60× it.
    pub bind_success_rate: Option<f32>,
    /// reliability §6.3's breaker, opened only on the device's own evidence.
    pub breaker_open: bool,
}

impl Measured {
    /// The measurement terms' total contribution.
    #[must_use]
    pub fn contribution(&self) -> i32 {
        let mut total = 0_i32;
        if let Some(rtt) = self.rtt_ms {
            total += -i32::try_from(rtt).unwrap_or(250).min(250);
        }
        if let Some(loss) = self.loss_percent {
            #[allow(clippy::cast_possible_truncation)]
            let d = (loss * -8.0).max(-120.0) as i32;
            total += d;
        }
        if let Some(jitter) = self.jitter_ms {
            #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
            let d = ((f64::from(jitter)) * -0.5).max(-40.0) as i32;
            total += d;
        }
        if let Some(rate) = self.bind_success_rate {
            #[allow(clippy::cast_possible_truncation)]
            let d = (rate.clamp(0.0, 1.0) * 60.0) as i32;
            total += d;
        }
        if self.breaker_open {
            total += -400;
        }
        total
    }
}

/// One relay's score. Higher is better.
#[must_use]
pub fn score(advice: &ServerAdvice, measured: &Measured) -> i32 {
    let mut s = BASE;
    s += advice.ranked_contribution();
    s += advice.health.delta();
    s += match advice.load_class {
        0 => 0,
        1 => -20,
        2 => -60,
        _ => -120,
    };
    // "replaced by measurement once measured" — the locality term is a stand-in
    // for an RTT the device has not taken yet, so it disappears the moment it has.
    if measured.rtt_ms.is_none() {
        s += match advice.locality {
            Locality::Same => 0,
            Locality::Adjacent(added) => -i32::try_from(added).unwrap_or(200).min(200),
            Locality::Other => -200,
        };
    }
    if advice.self_hosted_bonus {
        s += 120;
    }
    if advice.draining {
        s += -300;
    }
    s + measured.contribution()
}

/// Builds the advisory terms from a registry record and an S-10 health state.
#[must_use]
pub fn advice_for(record: &RelayRecord, health: Health, rank_age_ms: u64) -> ServerAdvice {
    ServerAdvice {
        server_rank: record.server_rank,
        rank_age_ms,
        health,
        load_class: record.load_class,
        locality: Locality::Same,
        self_hosted_bonus: record.self_hosted && record.supports_drain && record.supports_caps,
        draining: record.admin_state == AdminState::Draining,
    }
}

// ===========================================================================
// HRW — deterministic, coordination-free redistribution (§11.5, §11.7)
// ===========================================================================

/// The 64-bit hash HRW needs.
///
/// ADR-0006 §11.5 specifies `BLAKE2s(relay_id ‖ pair_id)`. BLAKE2s is a
/// cryptographic primitive and CD-I2 keeps those in `twinvpn-crypto`, so it is
/// injected here for the same reason as `relay::crypto::RelayCrypto` — see
/// `README.md` §7. Injection also satisfies testing-strategy A-14, which requires
/// the HRW hash to be **seedable** for a deterministic region-failure test.
pub trait Hrw64: Send + Sync {
    /// `BLAKE2s(relay_id ‖ pair_id)` interpreted as a `u64`.
    fn weight(&self, relay_id: &[u8], pair_id: &[u8]) -> u64;
}

/// The k highest-weighted relays for a pair, weighted by `capacity_weight`.
///
/// §11.5: "Both devices `BIND` all `k = 3` in parallel." §11.7: redistribution
/// uses this rather than the score, because "independent score-optimising choice
/// … is precisely what creates the hot spot".
#[must_use]
pub fn hrw_top_k<'a>(
    candidates: &'a [RelayRecord],
    pair_id: &[u8],
    k: usize,
    hash: &dyn Hrw64,
) -> Vec<&'a RelayRecord> {
    let mut scored: Vec<(u128, &RelayRecord)> = candidates
        .iter()
        .filter(|r| r.admin_state == AdminState::Active)
        .map(|r| {
            let w = u128::from(hash.weight(&r.relay_id, pair_id));
            // Scaling by capacity_weight is what makes the spread proportional to
            // published capacity, which is how an operator rebalances a fleet
            // "by publishing weights, not by touching clients" (§10).
            (w * u128::from(r.capacity_weight.max(1)), r)
        })
        .collect();
    // Ties break on relay_id so two devices with the same map agree exactly —
    // convergence with no coordination is the entire point of HRW here.
    scored.sort_unstable_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.relay_id.cmp(&b.1.relay_id)));
    scored.into_iter().take(k).map(|(_, r)| r).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::sample;

    /// A deterministic, seedable stand-in with a real avalanche.
    ///
    /// **Not a substitute for BLAKE2s in production** — it exists so the spread
    /// property is testable without a cryptographic dependency. FNV alone is not
    /// enough here: its high bits barely move with the last few input bytes, and
    /// HRW compares full 64-bit values, so an FNV-only double makes every pair
    /// pick the same relay and would make this test pass for the wrong reason.
    struct Mixed;
    impl Hrw64 for Mixed {
        fn weight(&self, relay_id: &[u8], pair_id: &[u8]) -> u64 {
            let mut h = 0xcbf2_9ce4_8422_2325_u64;
            for b in relay_id.iter().chain(pair_id.iter()) {
                h ^= u64::from(*b);
                h = h.wrapping_mul(0x0000_0100_0000_01B3);
            }
            // splitmix64 finalizer.
            h ^= h >> 30;
            h = h.wrapping_mul(0xbf58_476d_1ce4_e5b9);
            h ^= h >> 27;
            h = h.wrapping_mul(0x94d0_49bb_1331_11eb);
            h ^ (h >> 31)
        }
    }

    #[test]
    fn measurement_always_beats_server_preference() {
        // THE arithmetic guarantee, stated exactly as §11.2 states it: "any relay
        // with a >=100 ms measured RTT advantage outranks any SERVER PREFERENCE,
        // unconditionally". The server preference is the `server_rank` term,
        // whose whole 0..=100 range is narrower than 100 ms of measured RTT.
        //
        // The self-hosted +120 is NOT part of that cap and must not be included
        // here — §11.2's own self-hosted paragraph says so: "+120 points ~ 120 ms
        // of tolerated extra RTT: an Owner's own relay wins whenever it is not
        // dramatically worse, which is the intent". It is an Owner policy
        // preference, deliberately worth more than the server's ranking hint.
        let favoured = ServerAdvice {
            server_rank: 100,
            rank_age_ms: 0,
            health: Health::Healthy,
            load_class: 0,
            locality: Locality::Same,
            self_hosted_bonus: false,
            draining: false,
        };
        let disfavoured = ServerAdvice {
            server_rank: 0,
            ..favoured
        };

        for slow_rtt in [100_u32, 110, 150, 200, 250] {
            let a = score(
                &favoured,
                &Measured {
                    rtt_ms: Some(slow_rtt),
                    ..Measured::default()
                },
            );
            let b = score(
                &disfavoured,
                &Measured {
                    rtt_ms: Some(slow_rtt - 100),
                    ..Measured::default()
                },
            );
            assert!(
                b >= a,
                "a 100 ms measured advantage lost to a server_rank preference \
                 (slow={slow_rtt}, favoured={a}, measured={b})"
            );
        }
        // And strictly, at any advantage above 100 ms.
        let a = score(
            &favoured,
            &Measured {
                rtt_ms: Some(200),
                ..Measured::default()
            },
        );
        let b = score(
            &disfavoured,
            &Measured {
                rtt_ms: Some(99),
                ..Measured::default()
            },
        );
        assert!(b > a);
    }

    #[test]
    fn the_negative_server_terms_do_not_break_the_cap_because_they_only_subtract() {
        // `health` and `load_class` are server-supplied but can only LOWER a
        // score, so they cannot let a stale central view out-rank a measurement.
        // The direction is what makes the cap argument hold with more terms than
        // the +100 one.
        let base = ServerAdvice {
            server_rank: 0,
            rank_age_ms: 0,
            health: Health::Healthy,
            load_class: 0,
            locality: Locality::Same,
            self_hosted_bonus: false,
            draining: false,
        };
        let plain = score(&base, &Measured::default());
        for worse in [
            ServerAdvice {
                health: Health::Degraded,
                ..base
            },
            ServerAdvice {
                health: Health::Unhealthy,
                ..base
            },
            ServerAdvice {
                load_class: 3,
                ..base
            },
            ServerAdvice {
                draining: true,
                ..base
            },
        ] {
            assert!(score(&worse, &Measured::default()) <= plain);
        }
    }

    #[test]
    fn the_measurement_terms_reach_the_stated_floor() {
        // -410 is the sum of the bounded measurement terms in §11.2's table:
        // RTT -250, loss -120, jitter -40. The breaker's -400 is separate.
        let worst = Measured {
            rtt_ms: Some(10_000),
            loss_percent: Some(100.0),
            jitter_ms: Some(10_000),
            bind_success_rate: None,
            breaker_open: false,
        };
        assert_eq!(worst.contribution(), MEASUREMENT_FLOOR);
    }

    #[test]
    fn the_server_contribution_is_capped_at_one_hundred() {
        let a = ServerAdvice {
            server_rank: 100,
            rank_age_ms: 0,
            health: Health::Healthy,
            load_class: 0,
            locality: Locality::Same,
            self_hosted_bonus: false,
            draining: false,
        };
        assert_eq!(a.ranked_contribution(), SERVER_CAP);
    }

    #[test]
    fn a_stale_ranking_decays_to_zero_influence_without_removing_a_candidate() {
        // §11.2: "A stale server ranking decays to zero influence over 24 h
        // without ever removing a candidate."
        let mut a = ServerAdvice {
            server_rank: 100,
            rank_age_ms: 0,
            health: Health::Unknown,
            load_class: 0,
            locality: Locality::Same,
            self_hosted_bonus: false,
            draining: false,
        };
        assert_eq!(a.ranked_contribution(), 100);
        a.rank_age_ms = 3_600_000; // 1 h
        assert_eq!(a.ranked_contribution(), 100);
        a.rank_age_ms = 12 * 3_600_000;
        assert!((45..=60).contains(&a.ranked_contribution()));
        a.rank_age_ms = 24 * 3_600_000;
        assert_eq!(a.ranked_contribution(), 0);
        a.rank_age_ms = 365 * 24 * 3_600_000;
        assert_eq!(a.ranked_contribution(), 0);
        // And the relay is still a candidate: score() returns a number, never None.
        assert!(score(&a, &Measured::default()) > 0);
    }

    #[test]
    fn health_being_unknown_costs_nothing_at_all() {
        // The relay-health service being down must degrade ranking QUALITY and
        // nothing else (S-10).
        let base = ServerAdvice {
            server_rank: 50,
            rank_age_ms: 0,
            health: Health::Healthy,
            load_class: 0,
            locality: Locality::Same,
            self_hosted_bonus: false,
            draining: false,
        };
        let unknown = ServerAdvice {
            health: Health::Unknown,
            ..base
        };
        assert_eq!(
            score(&base, &Measured::default()),
            score(&unknown, &Measured::default())
        );
    }

    #[test]
    fn a_clients_own_probe_failure_outranks_a_healthy_report() {
        // S-10, exactly: "a client's own probe failure always outranks a
        // 'healthy' report".
        let healthy_report = ServerAdvice {
            server_rank: 100,
            rank_age_ms: 0,
            health: Health::Healthy,
            load_class: 0,
            locality: Locality::Same,
            self_hosted_bonus: true,
            draining: false,
        };
        let with_open_breaker = score(
            &healthy_report,
            &Measured {
                breaker_open: true,
                ..Measured::default()
            },
        );
        let plain = score(&healthy_report, &Measured::default());
        assert!(with_open_breaker < plain - 300);
    }

    #[test]
    fn a_measured_rtt_replaces_the_published_locality_term() {
        // §11.2: region locality is "replaced by measurement once measured".
        let far = ServerAdvice {
            server_rank: 0,
            rank_age_ms: 0,
            health: Health::Unknown,
            load_class: 0,
            locality: Locality::Other,
            self_hosted_bonus: false,
            draining: false,
        };
        let unmeasured = score(&far, &Measured::default());
        let measured = score(
            &far,
            &Measured {
                rtt_ms: Some(10),
                ..Measured::default()
            },
        );
        assert_eq!(unmeasured, BASE - 200);
        assert_eq!(measured, BASE - 10, "the -200 guess is gone once measured");
    }

    #[test]
    fn draining_lowers_the_score_by_three_hundred_and_does_not_remove() {
        let a = ServerAdvice {
            server_rank: 0,
            rank_age_ms: 0,
            health: Health::Unknown,
            load_class: 0,
            locality: Locality::Same,
            self_hosted_bonus: false,
            draining: true,
        };
        assert_eq!(score(&a, &Measured::default()), BASE - 300);
    }

    #[test]
    fn hrw_spreads_pairs_across_the_fleet_rather_than_piling_onto_the_best() {
        let fleet: Vec<RelayRecord> = (1..=6_u8)
            .map(|n| sample(n, "eu-west", if n % 2 == 0 { "fd-b" } else { "fd-a" }))
            .collect();
        let mut chosen = std::collections::BTreeMap::<u8, usize>::new();
        for pair in 0..600_u32 {
            let pair_id = pair.to_be_bytes();
            let top = hrw_top_k(&fleet, &pair_id, 1, &Mixed);
            *chosen.entry(top[0].relay_id[0]).or_default() += 1;
        }
        assert_eq!(chosen.len(), 6, "some relay received no share at all");
        for (id, n) in &chosen {
            assert!(
                *n > 40 && *n < 200,
                "relay {id} received {n} of 600 pairs: the spread is not proportional"
            );
        }
    }

    #[test]
    fn hrw_is_deterministic_so_two_devices_converge_with_no_coordination() {
        let fleet: Vec<RelayRecord> = (1..=5_u8).map(|n| sample(n, "eu-west", "fd-a")).collect();
        for pair in 0..50_u32 {
            let a = hrw_top_k(&fleet, &pair.to_be_bytes(), 3, &Mixed);
            let b = hrw_top_k(&fleet, &pair.to_be_bytes(), 3, &Mixed);
            let ids_a: Vec<_> = a.iter().map(|r| r.relay_id).collect();
            let ids_b: Vec<_> = b.iter().map(|r| r.relay_id).collect();
            assert_eq!(ids_a, ids_b);
            assert_eq!(ids_a.len(), 3, "k = 3 parallel binds (§11.5)");
        }
    }

    #[test]
    fn hrw_redistribution_ignores_retired_and_draining_relays() {
        let mut fleet: Vec<RelayRecord> =
            (1..=4_u8).map(|n| sample(n, "eu-west", "fd-a")).collect();
        fleet[0].admin_state = AdminState::Retired;
        fleet[1].admin_state = AdminState::Draining;
        for pair in 0..30_u32 {
            for r in hrw_top_k(&fleet, &pair.to_be_bytes(), 4, &Mixed) {
                assert_eq!(r.admin_state, AdminState::Active);
            }
        }
    }

    #[test]
    fn capacity_weight_shifts_the_share() {
        let mut fleet: Vec<RelayRecord> =
            (1..=4_u8).map(|n| sample(n, "eu-west", "fd-a")).collect();
        fleet[0].capacity_weight = 1_000;
        let mut big = 0_usize;
        for pair in 0..400_u32 {
            if hrw_top_k(&fleet, &pair.to_be_bytes(), 1, &Mixed)[0].relay_id[0] == 1 {
                big += 1;
            }
        }
        assert!(
            big > 200,
            "a 10x capacity weight took only {big} of 400 pairs; an operator \
             rebalances by publishing weights, not by touching clients"
        );
    }
}
