//! [`DerivedPreferred`] — a proven claim beats a pinned one, and a rotated
//! device still binds.
//!
//! **Authority:** `contracts/docs/identifiers.md` §2 (the derivation),
//! **ADR-0007 §11** (IK rotation and what `device_id` pins), `trust-boundaries.md`
//! §4 (a binding mismatch is a security event), I5.
//!
//! # The rule
//!
//! | This claim | Current holder | Outcome |
//! |---|---|---|
//! | **proven** | none | accepted, proven |
//! | **proven** | pinned, another channel | **accepted — the pinned holder is displaced** |
//! | **proven** | proven, another channel | refused (unreachable: two channels cannot derive to one id) |
//! | pinned | none | accepted, pinned — this is [`super::ChannelPinned`]'s behaviour |
//! | pinned | pinned, another channel | refused |
//! | pinned | **proven**, another channel | refused — a proven holder is never displaced |
//!
//! A claim is **proven** when the `device_id` derived from the key the peer
//! presented on TLS *is* the `device_id` it claims. Nothing else proves
//! anything: the derivation is over the peer's own public key, and the peer
//! proved possession of the private half in the handshake.
//!
//! # Why not simply *require* the derivation
//!
//! This is the question the next reader will ask, and the answer is not obvious.
//! Requiring it would close first-contact impersonation completely — and would
//! **lock out every device that has ever rotated its identity key**, for ever.
//!
//! ADR-0007 §11:
//!
//! > `device_id` pins the **generation-0** public key. IK rotation creates a new
//! > `DeviceIdentity` … but **`device_id` does not change** … After a rotation,
//! > `device_id` is self-certifying *transitively*: a verifier checks the
//! > succession chain from generation 0 to the presented generation.
//!
//! So a rotated device presents a **generation-N** key on TLS. That key derives
//! to a value that is *not* its `device_id` — correctly, because its `device_id`
//! is the hash of its generation-**0** key, which it no longer holds and never
//! presents. Closing the gap properly needs the succession chain, and neither the
//! rendezvous nor presence holds an `IdentitySuccession`, nor may either fetch
//! one per connection: that is a control-plane call on the reconnect path, which
//! is **I5**.
//!
//! Derived-only would therefore trade a bounded, first-contact-only window for an
//! unbounded lockout of a growing fraction of the fleet — and a lockout is the
//! fleet-wide-irreversible kind of wrong. Derived-**preferred** takes the whole
//! win for every generation-0 device (all of them until they rotate) and costs a
//! rotated device only the binding it already had.
//!
//! `rendezvous-connectivity` reached this and refused the integration lead's
//! ruling to go derived-only; the ruling was reversed. The reasoning is recorded
//! here rather than in a service so that the next service to bind a `device_id`
//! inherits it.
//!
//! # What is still open
//!
//! First-contact impersonation of a **rotated** device. An attacker who claims a
//! rotated device's `device_id` before it reconnects holds a pinned binding until
//! the TTL lapses — the rotated device cannot prove its way past it, because it
//! cannot derive. The close is an `IdentitySuccession` check, which needs a chain
//! this layer may not fetch. Stated, not hidden.

use std::time::Instant;

use twinvpn_types::DeviceId;

use crate::tls::ChannelIdentity;

use super::spki::derive_device_id_for;
use super::{Binding, BindingLimits, ChannelPinned, Claim, Refusal, Subject};

/// A subject that a presented identity key can be checked *against*.
///
/// Implemented for the two spellings of a `device_id` in this workspace — the
/// `twinvpn-types` newtype and the raw `[u8; 32]` the service framing layers
/// use — so a service adopts [`DerivedPreferred`] without changing the type it
/// already threads through its parser.
pub trait DerivableSubject: Subject {
    /// Whether this subject **is** `device_id`.
    fn is(&self, device_id: &DeviceId) -> bool;
}

impl DerivableSubject for DeviceId {
    fn is(&self, device_id: &DeviceId) -> bool {
        self == device_id
    }
}

impl DerivableSubject for [u8; 32] {
    fn is(&self, device_id: &DeviceId) -> bool {
        use twinvpn_types::Identifier as _;
        device_id.as_bytes() == self
    }
}

/// How a holder came by its binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// The presented key derives to the claimed `device_id`. Cryptographic, and
    /// not displaceable by a pinned claim.
    Proven,
    /// First claim wins. What every claim was before this module, and what a
    /// rotated device still gets.
    Pinned,
}

/// [`super::ChannelPinned`] with the derivation check in front.
///
/// The table, the TTL, the capacity rules and the release discipline are
/// `ChannelPinned`'s, unchanged — this type adds provenance and the displacement
/// rule and delegates everything else, so there is one binding table and not two
/// that drift.
pub struct DerivedPreferred<S: DerivableSubject> {
    inner: ChannelPinned<S>,
    /// Subjects whose current holder proved itself. A proven holder is never
    /// displaced by a pinned claim, and the set is the only extra state.
    proven: std::collections::HashSet<S>,
    displacements: u64,
    unprovable_keys: u64,
}

impl<S: DerivableSubject> std::fmt::Debug for DerivedPreferred<S> {
    /// Counts only — never a subject. See [`super::ChannelPinned`]'s `Debug`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedPreferred")
            .field("bound", &self.inner.len())
            .field("proven", &self.proven.len())
            .field("displacements", &self.displacements)
            .field("unprovable_keys", &self.unprovable_keys)
            .finish_non_exhaustive()
    }
}

impl<S: DerivableSubject> DerivedPreferred<S> {
    /// A table bounded by `limits`.
    #[must_use]
    pub fn new(limits: BindingLimits) -> Self {
        Self {
            inner: ChannelPinned::new(limits),
            proven: std::collections::HashSet::new(),
            displacements: 0,
            unprovable_keys: 0,
        }
    }

    /// How many pinned holders a proven claim has displaced.
    ///
    /// Every one of these is an impersonation attempt that got as far as a
    /// binding, or a device that reconnected after an impostor took its name.
    /// Worth an alert; **not** worth a `reason_code`, because nothing was
    /// refused.
    #[must_use]
    pub const fn displacements(&self) -> u64 {
        self.displacements
    }

    /// How many claims arrived on a key this build cannot derive from.
    ///
    /// A rotated device is the expected cause. A sustained rise with no rotation
    /// campaign means something is presenting keys of a shape
    /// `super::spki` does not convert — a silent downgrade to pinning, and the
    /// counter is how it stops being silent.
    #[must_use]
    pub const fn unprovable_keys(&self) -> u64 {
        self.unprovable_keys
    }

    /// How many claims have been refused since start.
    #[must_use]
    pub const fn refusals(&self) -> u64 {
        self.inner.refusals()
    }

    /// Whether `subject`'s current holder proved itself.
    #[must_use]
    pub fn provenance_of(&self, subject: &S) -> Option<Provenance> {
        self.inner.holder_of(subject)?;
        Some(if self.proven.contains(subject) {
            Provenance::Proven
        } else {
            Provenance::Pinned
        })
    }

    /// The limits in force.
    #[must_use]
    pub const fn limits(&self) -> BindingLimits {
        self.inner.limits()
    }
}

impl<S: DerivableSubject> Default for DerivedPreferred<S> {
    fn default() -> Self {
        Self::new(BindingLimits::default())
    }
}

impl<S: DerivableSubject> Binding<S> for DerivedPreferred<S> {
    fn claim(&mut self, channel: &ChannelIdentity, subject: S, now: Instant) -> Claim {
        // Is this claim proven? Derive from the key the peer actually presented
        // and compare it to what the peer claims to be.
        let proven = if let Ok(derived) = derive_device_id_for(channel) {
            subject.is(&derived)
        } else {
            // A rotated device (a generation-N key), or a key shape this build
            // does not convert. Neither is a refusal; both fall back to pinning.
            // Counted, so the fallback is visible rather than silent.
            self.unprovable_keys = self.unprovable_keys.saturating_add(1);
            false
        };

        // The FULL sweep, not the inner one: it prunes lapsed bindings AND their
        // provenance together. Pruning only the table would leave a proof behind
        // for a subject the table has forgotten, and the next claimant would
        // inherit it.
        self.sweep(now);

        let prior = self.inner.holder_of(&subject);

        // A proven claim takes the subject from a MERELY PINNED holder on a
        // different channel. This is the whole point of the module: the party
        // that can prove the name outranks the party that got there first.
        if proven {
            if let Some(held_by) = &prior {
                if *held_by != *channel && !self.proven.contains(&subject) {
                    self.inner.force_rebind(&subject, channel, now);
                    self.proven.insert(subject);
                    self.displacements = self.displacements.saturating_add(1);
                    return Claim::Accepted;
                }
            }
        }

        // Everything else is the pinned table's decision, unchanged — which is
        // what refuses a pinned claim against a proven holder, refuses a pinned
        // claim against a pinned holder, and accepts a channel re-claiming its
        // own subject.
        let outcome = self.inner.claim(channel, subject.clone(), now);
        if outcome == Claim::Accepted {
            let same_channel_reclaim = prior.is_some_and(|h| h == *channel);
            if proven {
                self.proven.insert(subject);
            } else if !same_channel_reclaim {
                // A FRESH binding on a key that cannot prove starts out pinned.
                // A channel re-claiming its own subject is not a downgrade:
                // provenance is a property of the key, and the key has not
                // changed.
                self.proven.remove(&subject);
            }
        }
        outcome
    }

    fn release(&mut self, channel: &ChannelIdentity, subject: &S, now: Instant) {
        self.inner.release(channel, subject, now);
    }

    fn sweep(&mut self, now: Instant) {
        self.inner.sweep(now);
        // A subject the table has forgotten has no provenance either, or the set
        // grows without bound and a later pinned claim inherits a proof that
        // belonged to a binding that lapsed.
        self.proven.retain(|s| self.inner.holder_of(s).is_some());
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}

/// The refusal a pinned claim gets against a proven holder.
///
/// Named here so a service reads the same code for both halves of the invariant:
/// it is still `CONTROL.CHANNEL_BINDING_MISMATCH`, still FATAL/CRITICAL, and
/// still names no device.
#[must_use]
pub const fn refusal_against_proven_holder() -> Refusal {
    Refusal::SubjectHeldByAnotherChannel
}
