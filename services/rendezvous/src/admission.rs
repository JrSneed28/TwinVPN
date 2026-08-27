//! Per-source admission control on a pre-authentication surface.
//!
//! ADR-0002 §11.7 rule 3 and **S-6**: an over-limit caller receives an
//! application-level `CONTROL.ADMISSION_DEFERRED{retry_after_ms}` and **never** a
//! TCP reset or a silent drop, "because a reset is indistinguishable from
//! network failure and drives clients into the aggressive *interactive* backoff
//! regime, amplifying the very flood it was meant to shed."
//!
//! [`twinvpn_service_common::transport::TokenBucket`] is that limiter; this
//! module is only the bounded, privacy-conscious *keying* of it.
//!
//! # What keying by source address costs, stated
//!
//! To rate-limit a pre-authentication surface at all, this process must hold
//! source addresses in memory for as long as the buckets live. That is a real
//! observation about users (`README.md` §7 says so plainly). Three things bound
//! it: the key is the **address only, never the port**, so it identifies a host
//! and not a flow; the table is capped and evicted oldest-first; and an address
//! is never rendered — not in a log line, not in evidence, not in a metric
//! label, which `metrics::Label`'s five-value allowlist makes structural.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::Instant;

use twinvpn_service_common::transport::{Admission, TokenBucket};

/// The limiter's shape.
#[derive(Debug, Clone, Copy)]
pub struct AdmissionLimits {
    /// Sustained `CALL`s per second from one source address.
    pub sustained_per_sec: f64,
    /// Burst depth.
    pub burst: u32,
    /// How many source addresses may hold a bucket at once.
    pub max_sources: usize,
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        // A device negotiating a connection sends an offer, an answer and a
        // handful of trickle candidate sets: single-digit frames per second,
        // per peer. 20/s sustained with a burst of 40 leaves a legitimate NAT
        // or CGNAT full of devices ample room while making a flood cost the
        // attacker a bucket entry rather than a mailbox.
        Self {
            sustained_per_sec: 20.0,
            burst: 40,
            max_sources: 65_536,
        }
    }
}

/// A bounded set of per-source token buckets.
#[derive(Debug)]
pub struct SourceLimiter {
    limits: AdmissionLimits,
    buckets: HashMap<IpAddr, (TokenBucket, u64)>,
    order: BTreeMap<u64, IpAddr>,
    next_seq: u64,
    deferred: u64,
}

impl SourceLimiter {
    /// A limiter bounded by `limits`.
    #[must_use]
    pub fn new(limits: AdmissionLimits) -> Self {
        Self {
            limits,
            buckets: HashMap::new(),
            order: BTreeMap::new(),
            next_seq: 0,
            deferred: 0,
        }
    }

    /// Admits or defers one request from `source`.
    ///
    /// The address is used and dropped; nothing here retains it beyond the
    /// bucket, and the bucket holds no history.
    pub fn admit(&mut self, source: IpAddr, now: Instant) -> Admission {
        if let Some((bucket, seq)) = self.buckets.get_mut(&source) {
            let outcome = bucket.try_admit(now);
            // Touch: move this source to the back of the eviction order, so a
            // quiet legitimate source is evicted before a busy one and an
            // attacker cannot flush the table to reset their own bucket.
            let previous_position = *seq;
            let fresh_position = self.next_seq;
            self.next_seq += 1;
            *seq = fresh_position;
            self.order.remove(&previous_position);
            self.order.insert(fresh_position, source);
            if matches!(outcome, Admission::Deferred { .. }) {
                self.deferred += 1;
            }
            return outcome;
        }

        if self.buckets.len() >= self.limits.max_sources {
            if let Some((&oldest, &victim)) = self.order.iter().next() {
                self.order.remove(&oldest);
                self.buckets.remove(&victim);
            }
        }
        let mut bucket = TokenBucket::new(self.limits.sustained_per_sec, self.limits.burst, now);
        let outcome = bucket.try_admit(now);
        let seq = self.next_seq;
        self.next_seq += 1;
        self.buckets.insert(source, (bucket, seq));
        self.order.insert(seq, source);
        if matches!(outcome, Admission::Deferred { .. }) {
            self.deferred += 1;
        }
        outcome
    }

    /// How many requests have been deferred since start.
    #[must_use]
    pub const fn deferred(&self) -> u64 {
        self.deferred
    }

    /// How many source addresses currently hold a bucket.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }
}

impl Default for SourceLimiter {
    fn default() -> Self {
        Self::new(AdmissionLimits::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn a_flood_is_deferred_with_a_retry_hint_never_dropped() {
        let mut l = SourceLimiter::new(AdmissionLimits {
            sustained_per_sec: 1.0,
            burst: 2,
            max_sources: 16,
        });
        let src = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let now = Instant::now();
        assert!(matches!(l.admit(src, now), Admission::Admitted));
        assert!(matches!(l.admit(src, now), Admission::Admitted));
        match l.admit(src, now) {
            Admission::Deferred { retry_after_ms } => assert!(retry_after_ms > 0),
            Admission::Admitted => panic!("S-6: over-limit must defer, not admit"),
        }
        assert_eq!(l.deferred(), 1);
    }

    #[test]
    fn v4_and_v6_sources_are_limited_independently() {
        let mut l = SourceLimiter::new(AdmissionLimits {
            sustained_per_sec: 1.0,
            burst: 1,
            max_sources: 16,
        });
        let now = Instant::now();
        assert!(matches!(
            l.admit(IpAddr::V4(Ipv4Addr::LOCALHOST), now),
            Admission::Admitted
        ));
        assert!(
            matches!(
                l.admit(IpAddr::V6(Ipv6Addr::LOCALHOST), now),
                Admission::Admitted
            ),
            "an IPv6 source must not inherit an IPv4 source's budget"
        );
    }

    #[test]
    fn the_bucket_table_is_bounded_against_a_spoofed_source_flood() {
        let mut l = SourceLimiter::new(AdmissionLimits {
            sustained_per_sec: 1.0,
            burst: 1,
            max_sources: 32,
        });
        let now = Instant::now();
        for i in 0..100_000u32 {
            let _ = l.admit(IpAddr::V6(Ipv6Addr::from(u128::from(i))), now);
        }
        assert!(l.tracked() <= 32);
    }
}
