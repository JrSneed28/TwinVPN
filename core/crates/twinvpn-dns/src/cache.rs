//! DN-1's four independent caches, and DN-22's "never persisted".
//!
//! **Authority:** ADR-0011 DN-1, DN-22, §11.1's cache column; ADR-0012 KS-16.
//!
//! # There is no cross-scope lookup, by construction
//!
//! [`ScopedCaches::get`] takes a [`Scope`] and consults exactly that scope's
//! map. There is no "search all scopes" method, no fallback, and no shared
//! negative cache — so KS-16's "a portal-supplied answer that persisted into
//! protected resolution would convert a 300 s hole into a durable redirection"
//! has no code path to travel.

use core::time::Duration;
use std::collections::HashMap;

use twinvpn_env::MonotonicInstant;

use crate::scope::Scope;

/// One cached answer. The record bytes are opaque here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The answer's wire bytes.
    pub records: Vec<u8>,
    /// When it stops being usable, on the **monotonic** clock (CD-1: a wall
    /// clock jump must not resurrect an expired answer or expire a live one).
    pub expires_at: MonotonicInstant,
}

/// Four caches that never see each other.
///
/// Memory-resident and discarded on process exit (DN-22): "A persisted DNS cache
/// is both a stale-answer channel across a policy change and a durable record of
/// the user's browsing; neither is acceptable."
#[derive(Debug, Default)]
pub struct ScopedCaches {
    twinnet: HashMap<Vec<u8>, Entry>,
    protected: HashMap<Vec<u8>, Entry>,
    portal: HashMap<Vec<u8>, Entry>,
    bootstrap: HashMap<Vec<u8>, Entry>,
}

impl ScopedCaches {
    /// Empty caches.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn map(&self, scope: Scope) -> &HashMap<Vec<u8>, Entry> {
        match scope {
            Scope::Twinnet => &self.twinnet,
            Scope::Protected => &self.protected,
            Scope::Portal => &self.portal,
            Scope::Bootstrap => &self.bootstrap,
        }
    }

    fn map_mut(&mut self, scope: Scope) -> &mut HashMap<Vec<u8>, Entry> {
        match scope {
            Scope::Twinnet => &mut self.twinnet,
            Scope::Protected => &mut self.protected,
            Scope::Portal => &mut self.portal,
            Scope::Bootstrap => &mut self.bootstrap,
        }
    }

    /// Looks a key up **in one scope only**.
    #[must_use]
    pub fn get(&self, scope: Scope, key: &[u8], now: MonotonicInstant) -> Option<&Entry> {
        self.map(scope)
            .get(key)
            .filter(|e| !now.reached(e.expires_at))
    }

    /// Inserts into one scope, clamping the TTL to that scope's ceiling.
    ///
    /// `grant_remaining` is `Some` only for [`Scope::Portal`], whose cache is
    /// "TTL-clamped to the remaining grant, flushed at expiry".
    pub fn insert(
        &mut self,
        scope: Scope,
        key: Vec<u8>,
        records: Vec<u8>,
        ttl: Duration,
        grant_remaining: Option<Duration>,
        now: MonotonicInstant,
    ) {
        let mut effective = ttl;
        if let Some(ceiling) = scope.ttl_ceiling() {
            effective = effective.min(ceiling);
        }
        if scope == Scope::Portal {
            // A portal answer never outlives the grant that permitted it.
            effective = effective.min(grant_remaining.unwrap_or(Duration::ZERO));
        }
        if effective.is_zero() {
            return;
        }
        self.map_mut(scope).insert(
            key,
            Entry {
                records,
                expires_at: now.saturating_add(effective),
            },
        );
    }

    /// Drops every entry in one scope. Called when a portal grant expires and
    /// whenever a policy version advances.
    pub fn flush(&mut self, scope: Scope) {
        self.map_mut(scope).clear();
    }

    /// Drops every entry in every scope.
    pub fn flush_all(&mut self) {
        for s in Scope::ALL {
            self.flush(s);
        }
    }

    /// How many live entries a scope holds, for diagnostics.
    #[must_use]
    pub fn len(&self, scope: Scope) -> usize {
        self.map(scope).len()
    }

    /// Whether a scope holds nothing.
    #[must_use]
    pub fn is_empty(&self, scope: Scope) -> bool {
        self.map(scope).is_empty()
    }
}

/// DN-22, stated as a function so it is greppable: the protected cache is
/// **never** persisted.
#[must_use]
pub const fn may_persist(_scope: Scope) -> bool {
    false
}
