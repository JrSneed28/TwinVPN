//! The bounded `jti` replay cache.
//!
//! ADR-0005 §11.3 ends the verification chain with "`jti` unseen", against a
//! **bounded** replay cache. Bounded is the operative word: `jti` is a 16-byte
//! attacker-chosen value, so an unbounded set is a remote memory-exhaustion
//! primitive on a directly attacker-reachable service (`ownership.md` §6 rule 10).
//!
//! Two bounds, both enforced:
//!
//! 1. **Capacity.** A fixed maximum number of entries. At capacity the oldest
//!    entry is evicted, never the newest refused — refusing the newest would let
//!    an attacker who fills the cache lock every legitimate device out.
//! 2. **Time.** An entry older than the token lifetime plus the skew window
//!    cannot be replayed anyway, because `exp` will have passed, so it is dropped.
//!
//! Eviction under capacity pressure is a **stated, bounded weakening**: an
//! attacker who can push `capacity` distinct `jti`s between two presentations of
//! one token can replay it. The residual is small — a replayed token still needs
//! the bound `RLK` to complete the leg (§7.6, `cnf` proof of possession), so the
//! replay cache is defence in depth over a proof-of-possession binding, not the
//! only control.

use std::collections::HashSet;
use std::collections::VecDeque;

/// The `jti` claim: 16 random bytes (ADR-0005 §11.3).
pub type Jti = [u8; 16];

/// A capacity- and time-bounded set of recently seen `jti` values.
#[derive(Debug)]
pub struct ReplayCache {
    capacity: usize,
    ttl_ms: u64,
    seen: HashSet<Jti>,
    order: VecDeque<(u64, Jti)>,
}

/// What [`ReplayCache::admit`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayVerdict {
    /// Not seen inside the window. The `jti` is now recorded.
    Fresh,
    /// Already seen. The token is a replay.
    Replayed,
}

impl ReplayCache {
    /// A cache holding at most `capacity` entries for `ttl_ms` each.
    ///
    /// `capacity` of zero is coerced to one so that a misconfiguration cannot
    /// silently disable replay detection.
    #[must_use]
    pub fn new(capacity: usize, ttl_ms: u64) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            ttl_ms,
            seen: HashSet::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
        }
    }

    /// The default: 64 Ki entries over the token lifetime plus the skew window.
    ///
    /// 64 Ki × (16 B key + bookkeeping) is a few megabytes — an amount a relay
    /// can hold, unlike an unbounded set.
    #[must_use]
    pub fn frozen_default() -> Self {
        let ttl = twinvpn_schema::limits::RELAY_TOKEN_LIFETIME_MS as u64
            + twinvpn_schema::limits::RELAY_TOKEN_CLOCK_SKEW_MS as u64;
        Self::new(65_536, ttl)
    }

    /// Records `jti` if unseen, and says which it was.
    ///
    /// `now_ms` is a parameter rather than a clock read, so a decision is
    /// reproducible from its inputs (architecture §5.2 R-DET-1).
    pub fn admit(&mut self, jti: Jti, now_ms: u64) -> ReplayVerdict {
        self.expire(now_ms);
        if self.seen.contains(&jti) {
            return ReplayVerdict::Replayed;
        }
        while self.order.len() >= self.capacity {
            if let Some((_, oldest)) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        self.seen.insert(jti);
        self.order.push_back((now_ms, jti));
        ReplayVerdict::Fresh
    }

    /// How many entries are held. Never exceeds the configured capacity.
    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    fn expire(&mut self, now_ms: u64) {
        while let Some(&(inserted, jti)) = self.order.front() {
            if now_ms.saturating_sub(inserted) >= self.ttl_ms {
                self.order.pop_front();
                self.seen.remove(&jti);
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jti(n: u8) -> Jti {
        [n; 16]
    }

    #[test]
    fn a_fresh_jti_is_admitted_once_and_refused_after() {
        let mut c = ReplayCache::new(8, 1_000);
        assert_eq!(c.admit(jti(1), 0), ReplayVerdict::Fresh);
        assert_eq!(c.admit(jti(1), 1), ReplayVerdict::Replayed);
    }

    #[test]
    fn the_cache_never_grows_past_its_capacity() {
        let mut c = ReplayCache::new(4, 1_000_000);
        for n in 0..200_u8 {
            let _ = c.admit(jti(n), u64::from(n));
        }
        assert_eq!(
            c.len(),
            4,
            "an unbounded jti set is a memory-exhaustion primitive"
        );
    }

    #[test]
    fn a_zero_capacity_configuration_cannot_disable_replay_detection() {
        let mut c = ReplayCache::new(0, 1_000);
        assert_eq!(c.admit(jti(1), 0), ReplayVerdict::Fresh);
        assert_eq!(c.admit(jti(1), 0), ReplayVerdict::Replayed);
    }

    #[test]
    fn an_entry_past_the_token_lifetime_is_dropped() {
        let mut c = ReplayCache::new(64, 1_000);
        assert_eq!(c.admit(jti(1), 0), ReplayVerdict::Fresh);
        // Past the TTL the token itself has expired, so re-admitting the jti
        // costs nothing: token::verify will refuse on `exp` first.
        assert_eq!(c.admit(jti(1), 1_001), ReplayVerdict::Fresh);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn the_frozen_default_uses_the_registry_lifetime() {
        let c = ReplayCache::frozen_default();
        assert!(c.is_empty());
        assert_eq!(c.capacity, 65_536);
        assert_eq!(c.ttl_ms, 86_400_000 + 300_000);
    }
}
