//! [`ChannelPinned`] — first claim wins, and wins exclusively.
//!
//! Split out of `binding/mod.rs` to keep both files under the 500-line limit in
//! `CLAUDE.md`. `binding` re-exports it.
//!
//! This is the binding a service uses when it cannot derive the subject from the
//! presented key. [`super::DerivedPreferred`] wraps the same table with the
//! derivation check in front, and is what a service binding a `device_id`
//! should reach for.

use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

use crate::tls::ChannelIdentity;

use super::{Binding, BindingCardinality, BindingLimits, Claim, Refusal, Subject};

struct Entry {
    channel: ChannelIdentity,
    expires_at: Instant,
    /// Live connections currently holding this binding. A binding with a live
    /// holder is **never** evicted for capacity: evicting it would hand an
    /// attacker the very thing the binding exists to protect.
    holders: u32,
    arrival: u64,
}

/// The shipped [`Binding`]: first claim wins, and wins exclusively.
pub struct ChannelPinned<S: Subject> {
    limits: BindingLimits,
    by_subject: HashMap<S, Entry>,
    /// `arrival → subject`, so the oldest unheld binding is evictable without a
    /// scan.
    order: BTreeMap<u64, S>,
    next_arrival: u64,
    refusals: u64,
}

impl<S: Subject> std::fmt::Debug for ChannelPinned<S> {
    /// Counts only.
    ///
    /// A derived `Debug` would render every bound subject, which is exactly the
    /// per-device identifier O-13 forbids infrastructure from retaining and the
    /// collector's forbidden-key filter drops whole records for.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelPinned")
            .field("bound", &self.by_subject.len())
            .field("refusals", &self.refusals)
            .field("cardinality", &self.limits.cardinality)
            .finish_non_exhaustive()
    }
}

impl<S: Subject> ChannelPinned<S> {
    /// A table bounded by `limits`.
    #[must_use]
    pub fn new(limits: BindingLimits) -> Self {
        Self {
            limits,
            by_subject: HashMap::new(),
            order: BTreeMap::new(),
            next_arrival: 0,
            refusals: 0,
        }
    }

    /// How many claims have been refused since start.
    #[must_use]
    pub const fn refusals(&self) -> u64 {
        self.refusals
    }

    /// The limits in force.
    #[must_use]
    pub const fn limits(&self) -> BindingLimits {
        self.limits
    }

    /// The channel currently holding `subject`, if any.
    ///
    /// For [`super::DerivedPreferred`], which needs to know *who* holds a
    /// subject before deciding whether a proven claim may take it. Returns the
    /// channel identity, never the subject, and is not a lookup a service should
    /// need — the claim decision is [`Binding::claim`]'s.
    #[must_use]
    pub fn holder_of(&self, subject: &S) -> Option<ChannelIdentity> {
        self.by_subject.get(subject).map(|e| e.channel.clone())
    }

    /// Moves `subject`'s binding to `channel`, displacing whoever held it.
    ///
    /// **The only way to take a binding from a live holder**, and it exists for
    /// exactly one caller: [`super::DerivedPreferred`], where the new claimant
    /// has *derived* the subject from the key it proved possession of and the
    /// incumbent merely got there first. `pub(super)` so nothing else can reach
    /// it: an unqualified "take this binding" is the operation the whole module
    /// exists to prevent.
    ///
    /// The displaced connection is left holding nothing. Its later
    /// [`Binding::release`] finds a channel mismatch and returns without
    /// touching the entry, so the displacement does not corrupt the holder
    /// count.
    pub(super) fn force_rebind(
        &mut self,
        subject: &S,
        channel: &ChannelIdentity,
        now: Instant,
    ) -> bool {
        let ttl = self.limits.ttl;
        match self.by_subject.get_mut(subject) {
            Some(entry) => {
                entry.channel = channel.clone();
                entry.expires_at = now + ttl;
                entry.holders = 1;
                true
            }
            None => false,
        }
    }

    /// Evicts the oldest binding that no live connection holds.
    fn evict_oldest_unheld(&mut self) -> bool {
        let victim = self
            .order
            .iter()
            .find(|(_, s)| self.by_subject.get(*s).is_some_and(|e| e.holders == 0))
            .map(|(seq, s)| (*seq, s.clone()));
        match victim {
            Some((seq, subject)) => {
                self.order.remove(&seq);
                self.by_subject.remove(&subject);
                true
            }
            None => false,
        }
    }
}

impl<S: Subject> Default for ChannelPinned<S> {
    fn default() -> Self {
        Self::new(BindingLimits::default())
    }
}

impl<S: Subject> Binding<S> for ChannelPinned<S> {
    fn claim(&mut self, channel: &ChannelIdentity, subject: S, now: Instant) -> Claim {
        self.sweep(now);

        // Does this channel already speak for someone else? Checked first,
        // because it is the cheaper half of the invariant and because a channel
        // that changes its mind is a stronger signal than a contested subject.
        if self.limits.cardinality == BindingCardinality::OneSubjectPerChannel {
            if let Some((held, _)) = self
                .by_subject
                .iter()
                .find(|(_, e)| e.channel == *channel && e.holders > 0)
            {
                if *held != subject {
                    self.refusals += 1;
                    return Claim::Refused(Refusal::ChannelSpeaksForAnotherSubject);
                }
            }
        }

        match self.by_subject.get_mut(&subject) {
            Some(entry) if entry.channel == *channel => {
                entry.expires_at = now + self.limits.ttl;
                entry.holders = entry.holders.saturating_add(1);
                Claim::Accepted
            }
            Some(_) => {
                // The impersonation half. Refused under EVERY cardinality.
                self.refusals += 1;
                Claim::Refused(Refusal::SubjectHeldByAnotherChannel)
            }
            None => {
                if self.by_subject.len() >= self.limits.max_bindings && !self.evict_oldest_unheld()
                {
                    // Every binding is held by a live connection. Refusing is
                    // the safe direction: admitting would mean forgetting a
                    // binding that is actively protecting a subject.
                    self.refusals += 1;
                    return Claim::Refused(Refusal::TableAtCapacity);
                }
                let arrival = self.next_arrival;
                self.next_arrival += 1;
                self.order.insert(arrival, subject.clone());
                self.by_subject.insert(
                    subject,
                    Entry {
                        channel: channel.clone(),
                        expires_at: now + self.limits.ttl,
                        holders: 1,
                        arrival,
                    },
                );
                Claim::Accepted
            }
        }
    }

    fn release(&mut self, channel: &ChannelIdentity, subject: &S, now: Instant) {
        let Some(entry) = self.by_subject.get_mut(subject) else {
            return;
        };
        if entry.channel != *channel {
            // Not this connection's binding to release.
            return;
        }
        entry.holders = entry.holders.saturating_sub(1);
        if entry.holders == 0 {
            // The binding OUTLIVES the connection. This is the whole point: a
            // device that drops and reconnects finds its own binding, and an
            // attacker racing that reconnect finds it taken.
            entry.expires_at = now + self.limits.ttl;
        }
    }

    fn sweep(&mut self, now: Instant) {
        let gone: Vec<S> = self
            .by_subject
            .iter()
            .filter(|(_, e)| e.holders == 0 && e.expires_at <= now)
            .map(|(s, _)| s.clone())
            .collect();
        for s in gone {
            if let Some(e) = self.by_subject.remove(&s) {
                self.order.remove(&e.arrival);
            }
        }
    }

    fn len(&self) -> usize {
        self.by_subject.len()
    }
}
