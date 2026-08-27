//! ADR-0005 §11.5 — resource control, quotas, and amplification safety.
//!
//! | Limit | Default | Enforcement | Condition |
//! |---|---|---|---|
//! | concurrent half-flows per `relay_sub` | 64 | `BIND` refused | `FlowLimitReached` |
//! | bitrate per `relay_sub` | 20 Mbit/s, 2 s burst | token bucket, **throttle not drop** | `RateLimited` |
//! | bitrate per half-flow | 10 Mbit/s | token bucket | `RateLimited` |
//! | bytes/hour per `relay_sub` | 20 GiB | leaky counter | `QuotaExceeded` |
//! | `BIND`/min per `relay_sub` | 30 | token bucket | `BindRateLimited` |
//! | handshakes/s per source /24 or /48 | 20 before cookie | stateless cookie | pre-auth; silent |
//!
//! Quota values come **from the token**, so a relay enforces the issuer's policy
//! with no lookup. The configured values are the ceiling a token may not exceed.
//!
//! # Amplification factor is exactly 1.0 by construction
//!
//! §11.5: "the relay emits at most one frame per received frame, of equal payload
//! length; it never fans out, retransmits, or pads; and it emits **zero bytes**
//! in response to any unauthenticated or unbound frame." [`CookieGate`] is the
//! pre-authentication half: above the threshold from a source /24 or /48 the
//! relay issues a stateless cookie challenge *first*, so it performs no
//! asymmetric operation for an unvalidated source address.
//!
//! Every decision here takes `now` as a parameter (architecture §5.2 R-DET-1), so
//! a boundary case is testable without sleeping.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use twinvpn_service_common::transport::{Admission, TokenBucket};

use crate::condition::Condition;
use crate::subject::RelaySub;
use crate::token::Quota;

/// The configured ceilings a token's quota may not exceed.
#[derive(Debug, Clone, Copy)]
pub struct Ceilings {
    /// `TWINVPN_RELAY_MAX_FLOWS_PER_SUBJECT`.
    pub max_flows_per_subject: u32,
    /// `TWINVPN_RELAY_RATE_PER_SUBJECT_MBPS`.
    pub rate_per_subject_mbps: u32,
    /// `TWINVPN_RELAY_RATE_PER_FLOW_MBPS`.
    pub rate_per_flow_mbps: u32,
    /// `TWINVPN_RELAY_QUOTA_BYTES_PER_HOUR`.
    pub quota_bytes_per_hour: u64,
    /// `TWINVPN_RELAY_BIND_PER_MINUTE_PER_SUBJECT`.
    pub bind_per_minute_per_subject: u32,
}

impl Ceilings {
    /// The effective quota: the **lesser** of the token's claim and the relay's
    /// configured ceiling, field by field.
    ///
    /// A token is issuer policy, not device policy — but an operator must still
    /// be able to cap what their own hardware will carry, and a token claiming
    /// `u32::MAX` flows must not be able to raise the relay's ceiling.
    #[must_use]
    pub fn clamp(&self, token: Quota) -> Quota {
        Quota {
            max_concurrent_flows: token.max_concurrent_flows.min(self.max_flows_per_subject),
            max_bitrate_kbps: token
                .max_bitrate_kbps
                .min(self.rate_per_subject_mbps.saturating_mul(1_000)),
            max_bytes_per_hour: token.max_bytes_per_hour.min(self.quota_bytes_per_hour),
            max_binds_per_min: token
                .max_binds_per_min
                .min(self.bind_per_minute_per_subject),
        }
    }
}

/// Per-subject accounting. Created on first use, dropped when idle.
#[derive(Debug)]
struct SubjectState {
    quota: Quota,
    flows: u32,
    binds: TokenBucket,
    bitrate: TokenBucket,
    hour_window_start_ms: u64,
    bytes_this_hour: u64,
}

/// The relay's per-`relay_sub` and per-half-flow limiter.
#[derive(Debug)]
pub struct Limiter {
    ceilings: Ceilings,
    subjects: HashMap<[u8; 16], SubjectState>,
    max_subjects: usize,
}

impl Limiter {
    /// A limiter with `ceilings`, tracking at most `max_subjects` subjects.
    ///
    /// The subject-count bound matters for the same reason the total flow ceiling
    /// does: the per-subject limits bound one attacker, not the number of them.
    #[must_use]
    pub fn new(ceilings: Ceilings, max_subjects: usize) -> Self {
        Self {
            ceilings,
            subjects: HashMap::new(),
            max_subjects: max_subjects.max(1),
        }
    }

    /// How many subjects are tracked.
    #[must_use]
    pub fn subject_count(&self) -> usize {
        self.subjects.len()
    }

    /// Whether a `BIND` is permitted for `subject` right now.
    ///
    /// # Errors
    ///
    /// [`Condition::FlowLimitReached`], [`Condition::BindRateLimited`], or
    /// [`Condition::Overloaded`] when the relay is tracking its maximum number of
    /// distinct subjects.
    pub fn admit_bind(
        &mut self,
        subject: RelaySub,
        token_quota: Quota,
        now: Instant,
    ) -> Result<(), Condition> {
        let quota = self.ceilings.clamp(token_quota);
        let key = *subject.as_quota_key();
        if !self.subjects.contains_key(&key) && self.subjects.len() >= self.max_subjects {
            return Err(Condition::Overloaded);
        }
        let ceilings = self.ceilings;
        let state = self.subjects.entry(key).or_insert_with(|| SubjectState {
            quota,
            flows: 0,
            binds: TokenBucket::new(
                f64::from(quota.max_binds_per_min) / 60.0,
                quota.max_binds_per_min,
                now,
            ),
            bitrate: TokenBucket::new(
                f64::from(quota.max_bitrate_kbps) * 125.0,
                ceilings
                    .rate_per_subject_mbps
                    .saturating_mul(125_000)
                    .saturating_mul(2),
                now,
            ),
            hour_window_start_ms: 0,
            bytes_this_hour: 0,
        });

        if state.flows >= state.quota.max_concurrent_flows {
            return Err(Condition::FlowLimitReached);
        }
        match state.binds.try_admit(now) {
            Admission::Admitted => {
                state.flows = state.flows.saturating_add(1);
                Ok(())
            }
            Admission::Deferred { .. } => Err(Condition::BindRateLimited),
        }
    }

    /// Releases one half-flow's accounting.
    pub fn release_flow(&mut self, subject: RelaySub) {
        let key = *subject.as_quota_key();
        if let Some(s) = self.subjects.get_mut(&key) {
            s.flows = s.flows.saturating_sub(1);
            if s.flows == 0 {
                self.subjects.remove(&key);
            }
        }
    }

    /// Charges `bytes` to `subject`'s hourly quota.
    ///
    /// # Errors
    ///
    /// [`Condition::QuotaExceeded`] once the hour's budget is spent. A leaky
    /// counter, not a token bucket: the ADR calls for exactly that.
    pub fn charge_bytes(
        &mut self,
        subject: RelaySub,
        bytes: u64,
        now_ms: u64,
    ) -> Result<(), Condition> {
        let key = *subject.as_quota_key();
        let Some(s) = self.subjects.get_mut(&key) else {
            return Ok(());
        };
        if now_ms.saturating_sub(s.hour_window_start_ms) >= 3_600_000 {
            s.hour_window_start_ms = now_ms;
            s.bytes_this_hour = 0;
        }
        let next = s.bytes_this_hour.saturating_add(bytes);
        if next > s.quota.max_bytes_per_hour {
            return Err(Condition::QuotaExceeded);
        }
        s.bytes_this_hour = next;
        Ok(())
    }

    /// Whether `bytes` may be forwarded for `subject` now.
    ///
    /// ADR-0005 §11.5 says **throttle, not drop**, so this returns the delay a
    /// caller should apply rather than a verdict to discard. A `Deferred` result
    /// is a queueing instruction; the tail-drop only happens once the per-flow
    /// bounded queue is full ([`FlowQueue`]).
    pub fn admit_bytes(&mut self, subject: RelaySub, now: Instant) -> Admission {
        let key = *subject.as_quota_key();
        self.subjects
            .get_mut(&key)
            .map_or(Admission::Admitted, |s| s.bitrate.try_admit(now))
    }
}

/// A per-half-flow send queue with the ADR-0005 §8 bound and tail-drop.
///
/// > The relay bounds each half-flow's `R-TLS` send queue to
/// > `min(64 KiB, 250 ms × flow rate)` and **tail-drops** on overflow rather than
/// > letting the kernel buffer without limit. This converts TCP's unbounded
/// > latency growth into datagram-shaped loss, which the inner protocol already
/// > handles correctly.
#[derive(Debug)]
pub struct FlowQueue {
    cap_bytes: usize,
    queued_bytes: usize,
    dropped: u64,
}

impl FlowQueue {
    /// `min(configured, 250 ms × rate)`, per ADR-0005 §8.
    #[must_use]
    pub fn new(configured_max_bytes: usize, flow_rate_mbps: u32) -> Self {
        let quarter_second = (usize::try_from(flow_rate_mbps).unwrap_or(0)).saturating_mul(31_250);
        Self {
            cap_bytes: configured_max_bytes.min(quarter_second.max(1)),
            queued_bytes: 0,
            dropped: 0,
        }
    }

    /// The effective cap.
    #[must_use]
    pub const fn cap_bytes(&self) -> usize {
        self.cap_bytes
    }

    /// How many bytes are queued.
    #[must_use]
    pub const fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// How many frames were tail-dropped.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Offers `bytes`. `false` means tail-dropped.
    pub fn offer(&mut self, bytes: usize) -> bool {
        if self.queued_bytes + bytes > self.cap_bytes {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        self.queued_bytes += bytes;
        true
    }

    /// Records that `bytes` left the queue.
    pub fn drained(&mut self, bytes: usize) {
        self.queued_bytes = self.queued_bytes.saturating_sub(bytes);
    }
}

/// The pre-authentication cookie gate (ADR-0005 §11.5).
///
/// Above `threshold` handshakes per second from one source **/24 (v4) or /48
/// (v6)**, a stateless cookie challenge is issued before any asymmetric
/// operation. The aggregation prefix is the ADR's, not the full address: rate
/// limiting per-address is trivially defeated by an attacker with a /64.
#[derive(Debug)]
pub struct CookieGate {
    threshold_per_s: u32,
    buckets: HashMap<[u8; 16], TokenBucket>,
    max_tracked: usize,
}

impl CookieGate {
    /// A gate at `threshold_per_s`, tracking at most `max_tracked` prefixes.
    #[must_use]
    pub fn new(threshold_per_s: u32, max_tracked: usize) -> Self {
        Self {
            threshold_per_s,
            buckets: HashMap::new(),
            max_tracked: max_tracked.max(1),
        }
    }

    /// The ADR-0005 aggregation prefix: /24 for v4, /48 for v6.
    #[must_use]
    pub fn prefix_key(addr: IpAddr) -> [u8; 16] {
        let mut key = [0_u8; 16];
        match addr {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                key[0..3].copy_from_slice(&o[0..3]);
                key[15] = 4;
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();
                key[0..6].copy_from_slice(&o[0..6]);
                key[15] = 6;
            }
        }
        key
    }

    /// Whether a handshake from `addr` may proceed without a cookie challenge.
    ///
    /// When this returns `false` the relay answers with a stateless cookie —
    /// which is one frame of bounded size, so the amplification factor stays
    /// ≤ 1.0 (§11.5). It never performs an asymmetric operation first.
    pub fn allows_handshake(&mut self, addr: IpAddr, now: Instant) -> bool {
        let key = Self::prefix_key(addr);
        if !self.buckets.contains_key(&key) && self.buckets.len() >= self.max_tracked {
            // At capacity, challenge rather than admit. The gate itself must not
            // become the memory-exhaustion primitive it exists to prevent.
            return false;
        }
        let threshold = self.threshold_per_s;
        let bucket = self
            .buckets
            .entry(key)
            .or_insert_with(|| TokenBucket::new(f64::from(threshold), threshold, now));
        matches!(bucket.try_admit(now), Admission::Admitted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ceilings() -> Ceilings {
        Ceilings {
            max_flows_per_subject: 64,
            rate_per_subject_mbps: 20,
            rate_per_flow_mbps: 10,
            quota_bytes_per_hour: 20 * 1024 * 1024 * 1024,
            bind_per_minute_per_subject: 30,
        }
    }

    fn sub(n: u8) -> RelaySub {
        RelaySub::from_verified_claim([n; 16])
    }

    #[test]
    fn a_token_cannot_raise_the_relays_own_ceiling() {
        let greedy = Quota {
            max_concurrent_flows: u32::MAX,
            max_bitrate_kbps: u32::MAX,
            max_bytes_per_hour: u64::MAX,
            max_binds_per_min: u32::MAX,
        };
        let c = ceilings().clamp(greedy);
        assert_eq!(c.max_concurrent_flows, 64);
        assert_eq!(c.max_binds_per_min, 30);
        assert_eq!(c.max_bytes_per_hour, 20 * 1024 * 1024 * 1024);
    }

    #[test]
    fn a_token_may_ask_for_less_than_the_ceiling() {
        let modest = Quota {
            max_concurrent_flows: 4,
            max_binds_per_min: 2,
            ..Quota::default()
        };
        let c = ceilings().clamp(modest);
        assert_eq!(c.max_concurrent_flows, 4);
        assert_eq!(c.max_binds_per_min, 2);
    }

    #[test]
    fn slot_exhaustion_degrades_predictably() {
        let now = Instant::now();
        let mut l = Limiter::new(ceilings(), 1_000);
        let q = Quota {
            max_concurrent_flows: 3,
            max_binds_per_min: 1_000,
            ..Quota::default()
        };
        for _ in 0..3 {
            l.admit_bind(sub(1), q, now).expect("under the limit");
        }
        // The 4th is a NAMED refusal, not a drop, not a hang, not a panic.
        assert_eq!(
            l.admit_bind(sub(1), q, now).unwrap_err(),
            Condition::FlowLimitReached
        );
        // Releasing one makes room again — the degradation is reversible.
        l.release_flow(sub(1));
        l.admit_bind(sub(1), q, now).expect("room again");
    }

    #[test]
    fn one_subject_cannot_exhaust_the_relay_for_another() {
        let now = Instant::now();
        let mut l = Limiter::new(ceilings(), 1_000);
        let q = Quota {
            max_concurrent_flows: 1,
            ..Quota::default()
        };
        l.admit_bind(sub(1), q, now).expect("first");
        assert!(l.admit_bind(sub(1), q, now).is_err());
        // A different subject is unaffected — I7.
        l.admit_bind(sub(2), q, now).expect("a different subject");
    }

    #[test]
    fn the_subject_table_itself_is_bounded() {
        let now = Instant::now();
        let mut l = Limiter::new(ceilings(), 2);
        l.admit_bind(sub(1), Quota::default(), now).expect("1");
        l.admit_bind(sub(2), Quota::default(), now).expect("2");
        assert_eq!(
            l.admit_bind(sub(3), Quota::default(), now).unwrap_err(),
            Condition::Overloaded
        );
        assert_eq!(l.subject_count(), 2);
    }

    #[test]
    fn the_bind_rate_limit_refuses_by_name_and_recovers_with_time() {
        let now = Instant::now();
        let mut l = Limiter::new(ceilings(), 1_000);
        let q = Quota {
            max_binds_per_min: 2,
            max_concurrent_flows: 1_000,
            ..Quota::default()
        };
        l.admit_bind(sub(1), q, now).expect("1");
        l.admit_bind(sub(1), q, now).expect("2");
        assert_eq!(
            l.admit_bind(sub(1), q, now).unwrap_err(),
            Condition::BindRateLimited
        );
        // 2/min = one token every 30 s.
        l.admit_bind(sub(1), q, now + Duration::from_secs(31))
            .expect("refilled");
    }

    #[test]
    fn the_hourly_quota_is_a_leaky_counter_that_resets() {
        let now = Instant::now();
        let mut l = Limiter::new(ceilings(), 1_000);
        let q = Quota {
            max_bytes_per_hour: 1_000,
            ..Quota::default()
        };
        l.admit_bind(sub(1), q, now).expect("bind");
        l.charge_bytes(sub(1), 900, 0).expect("under");
        assert_eq!(
            l.charge_bytes(sub(1), 200, 0).unwrap_err(),
            Condition::QuotaExceeded
        );
        l.charge_bytes(sub(1), 200, 3_600_000).expect("new hour");
    }

    #[test]
    fn the_flow_queue_takes_the_lesser_of_the_configured_cap_and_the_rate() {
        // 10 Mbit/s × 250 ms = 312 500 B, so 64 KiB wins.
        assert_eq!(FlowQueue::new(65_536, 10).cap_bytes(), 65_536);
        // 1 Mbit/s × 250 ms = 31 250 B, so the rate wins.
        assert_eq!(FlowQueue::new(65_536, 1).cap_bytes(), 31_250);
    }

    #[test]
    fn the_flow_queue_tail_drops_rather_than_growing() {
        let mut q = FlowQueue::new(1_000, 1_000);
        assert!(q.offer(600));
        assert!(q.offer(400));
        assert!(!q.offer(1), "the 1001st byte is tail-dropped");
        assert_eq!(q.dropped(), 1);
        assert_eq!(q.queued_bytes(), 1_000);
        q.drained(500);
        assert!(q.offer(500));
    }

    #[test]
    fn the_cookie_gate_aggregates_by_slash_24_and_slash_48() {
        let a: IpAddr = "192.0.2.1".parse().expect("v4");
        let b: IpAddr = "192.0.2.254".parse().expect("v4");
        let c: IpAddr = "192.0.3.1".parse().expect("v4");
        assert_eq!(CookieGate::prefix_key(a), CookieGate::prefix_key(b));
        assert_ne!(CookieGate::prefix_key(a), CookieGate::prefix_key(c));

        let d: IpAddr = "2001:db8:1::1".parse().expect("v6");
        let e: IpAddr = "2001:db8:1:ffff::9".parse().expect("v6");
        let f: IpAddr = "2001:db8:2::1".parse().expect("v6");
        assert_eq!(CookieGate::prefix_key(d), CookieGate::prefix_key(e));
        assert_ne!(CookieGate::prefix_key(d), CookieGate::prefix_key(f));
        assert_ne!(CookieGate::prefix_key(a), CookieGate::prefix_key(d));
    }

    #[test]
    fn above_the_threshold_a_cookie_challenge_comes_first() {
        let now = Instant::now();
        let mut g = CookieGate::new(2, 1_000);
        let addr: IpAddr = "2001:db8::1".parse().expect("v6");
        assert!(g.allows_handshake(addr, now));
        assert!(g.allows_handshake(addr, now));
        assert!(
            !g.allows_handshake(addr, now),
            "no asymmetric operation for an unvalidated source above the threshold"
        );
        // A different /48 is unaffected.
        assert!(g.allows_handshake("2001:db9::1".parse().expect("v6"), now));
    }

    #[test]
    fn the_cookie_gate_challenges_rather_than_admits_when_its_own_table_is_full() {
        let now = Instant::now();
        let mut g = CookieGate::new(100, 1);
        assert!(g.allows_handshake("192.0.2.1".parse().expect("v4"), now));
        assert!(!g.allows_handshake("198.51.100.1".parse().expect("v4"), now));
    }
}
