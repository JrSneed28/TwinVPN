//! Binding a claimed subject to the authenticated channel identity.
//!
//! # The hole this closes
//!
//! Before TLS, a claim like `ATTACH(D)` or `BIND(D)` was an unauthenticated
//! **assertion**: anyone who could open a socket could say "I am `device_id` D"
//! and receive D's `CALL`s, or publish presence for D. [`crate::tls`] now proves
//! that the peer holds the private half of the key it presented. This module is
//! the other half: it makes the claimed subject answerable to that key.
//!
//! # The invariant, stated exactly
//!
//! **A subject belongs to at most one channel identity, and a channel identity
//! speaks for at most one subject, for the life of the binding.**
//!
//! - the first claim of `S` on a channel holding key `K` records `K ↔ S`;
//! - a claim of `S' ≠ S` on that same channel is **refused**;
//! - a claim of `S` from any channel holding `K' ≠ K` is **refused** while
//!   `K ↔ S` is live.
//!
//! Refusal is `CONTROL.CHANNEL_BINDING_MISMATCH` — FATAL, CRITICAL, and
//! `trust-boundaries.md` §4's words for it are "**a security event, never a
//! parse error**". That is the right classification for the same reason it is
//! there: a mismatch is a message being lifted onto a channel that is not
//! entitled to it.
//!
//! # Provenance and generalisation
//!
//! `rendezvous-connectivity` wrote this and then wrote it again, verbatim, in
//! `services/presence`. It moves here rather than becoming a third copy in the
//! relay. One axis is generalised — **what a subject is**. Rendezvous and
//! presence bind a `device_id`; a relay binds a `relay_sub` and has `pair_tag`s.
//! [`Subject`] is therefore any hashable, comparable value, and
//! [`BindingCardinality`] names the one place the four services genuinely differ.
//!
//! **Only the non-safety half of the invariant is a cardinality question.** A
//! subject held by another channel is refused under *every* cardinality: that is
//! the anti-impersonation half, and it does not relax. What
//! [`BindingCardinality::ManySubjectsPerChannel`] relaxes is the converse — one
//! authenticated channel speaking for several subjects, which a relay carrying
//! several flows legitimately does and a device attaching legitimately does not.
//!
//! # What this is, and what it is not — stated plainly
//!
//! This is **channel-pinned** binding. It is not a derivation. It closes
//! impersonation of a subject that is bound, or that has been bound within
//! [`BindingLimits::ttl`], which is every device in normal operation. It does
//! **not** close first-contact impersonation: an attacker who claims `S` *before*
//! the real holder ever does keeps the binding until it lapses.
//!
//! Closing that needs the server to derive the subject from the presented key,
//! and `identifiers.md` §2 fixes exactly how:
//!
//! ```text
//! identity_id = SHA-256("TwinVPN/DeviceIdentity/v1" || 0x00 || dCBOR(COSE_Key(IK_pub)))
//! device_id   = identity_id of generation 0
//! ```
//!
//! **That derivation is not ours to re-implement** — W-23's finding, "a specified
//! derivation is not ours to improve" — and a wrong `device_id` derivation names
//! the wrong device, which is worse than the gap. `core-security` is moving it
//! into `twinvpn-crypto`, which the services workspace may depend on. So this
//! layer takes a subject that has **already been derived** and never derives one:
//! [`Binding`] is a trait, [`ChannelPinned`] is what ships, and a
//! derivation-checking implementor is a new type beside it rather than an edit
//! through it.

mod derived;
mod pinned;
mod spki;

pub use derived::{refusal_against_proven_holder, DerivableSubject, DerivedPreferred, Provenance};
pub use pinned::ChannelPinned;
pub use spki::{
    derive_device_id_for, spki_to_es256_cose_key, DerivationError, SpkiError, P256_SPKI_LEN,
};

use std::hash::Hash;
use std::time::{Duration, Instant};

use twinvpn_types::{codes, Component, ReasonCode};

use crate::errors::ServiceError;
use crate::tls::ChannelIdentity;

/// Anything a channel can be made answerable for.
///
/// A `device_id` for the rendezvous and presence; a `relay_sub` for a relay.
/// Deliberately **not** `Debug`: a subject is a stable per-device identifier and
/// `twinvpn.device_id` is on the collector's forbidden-key list, so a blanket
/// `Debug` bound here would be an invitation to render one. Nothing in this
/// module prints a subject.
pub trait Subject: Clone + Eq + Hash + Send + Sync + 'static {}

impl<T: Clone + Eq + Hash + Send + Sync + 'static> Subject for T {}

/// Why a claim was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// This channel already speaks for a different subject.
    ChannelSpeaksForAnotherSubject,
    /// Another live channel already speaks for this subject.
    SubjectHeldByAnotherChannel,
    /// The table is full of bindings that live connections are holding.
    ///
    /// A distinct variant, and a **different reason code**, because it is a
    /// different fact: the subject is not contested, the server is. Answering
    /// `SubjectHeldByAnotherChannel` here would tell a caller its subject was
    /// taken when it was not — an oracle, and a wrong one.
    ///
    /// The split has a second consequence a service should keep: a capacity
    /// refusal must **not** be counted as a binding mismatch. `rendezvous`
    /// excludes it from `binding_mismatches_total` for exactly that reason —
    /// counting a full table as a security event would make the metric lie
    /// during a capacity incident, which is when an operator most needs it to be
    /// telling the truth.
    TableAtCapacity,
}

impl Refusal {
    /// The registered code this refusal is reported as.
    ///
    /// A binding mismatch is `CONTROL.CHANNEL_BINDING_MISMATCH`: FATAL,
    /// CRITICAL, "a security event, never a parse error". Capacity is
    /// `CONTROL.ADMISSION_DEFERRED`, the ADR-0002 §11.7 rule 3 shape for "not
    /// now, come back" — and **S-6** makes answering mandatory there: "a TCP
    /// reset or a silent drop is prohibited".
    #[must_use]
    pub const fn reason_code(self) -> ReasonCode {
        match self {
            Refusal::ChannelSpeaksForAnotherSubject | Refusal::SubjectHeldByAnotherChannel => {
                codes::CONTROL_CHANNEL_BINDING_MISMATCH
            }
            Refusal::TableAtCapacity => codes::CONTROL_ADMISSION_DEFERRED,
        }
    }

    /// The refusal as a [`ServiceError`], ready to encode.
    ///
    /// **Names no subject, structurally.** `CONTROL.CHANNEL_BINDING_MISMATCH`
    /// declares *no* evidence fields in the frozen registry, and
    /// `twinvpn-types`' builder drops an undeclared key — so there is no call
    /// that could attach the contested subject to this error even by mistake. A
    /// refusal that echoed it would be an oracle for which subjects are bound.
    #[must_use]
    pub fn to_error(self, component: Component) -> ServiceError {
        ServiceError::new(self.reason_code(), component).build()
    }
}

/// The outcome of checking a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// The claim is consistent with the channel identity.
    Accepted,
    /// Refused.
    Refused(Refusal),
}

impl Claim {
    /// Whether the claim was accepted.
    #[must_use]
    pub const fn is_accepted(self) -> bool {
        matches!(self, Claim::Accepted)
    }

    /// The refusal, if there was one.
    #[must_use]
    pub const fn refusal(self) -> Option<Refusal> {
        match self {
            Claim::Accepted => None,
            Claim::Refused(r) => Some(r),
        }
    }
}

/// How many subjects one authenticated channel may speak for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BindingCardinality {
    /// **One.** A device attaching or binding speaks for itself and nothing
    /// else. The rendezvous and presence shape, and the default.
    #[default]
    OneSubjectPerChannel,
    /// **Many.** One authenticated channel legitimately carries several
    /// subjects — a relay holding several flows for one `relay_sub`.
    ///
    /// Relaxes only the converse half of the invariant. A subject held by
    /// another channel is still refused, because that is the impersonation half
    /// and it never relaxes.
    ///
    /// **This is a per-service safety decision, not a tuning knob.** It belongs
    /// in a service's source, chosen once and not configurable, because the
    /// right answer follows from what a subject *is* in that service and not
    /// from load. `rendezvous` sets [`BindingCardinality::OneSubjectPerChannel`]
    /// explicitly and refuses to expose it, and its reasoning generalises: there,
    /// `ManySubjectsPerChannel` would let one key hold **every mailbox it could
    /// name**. A relay reaches the opposite answer for the same kind of reason —
    /// one `relay_sub` genuinely carries many flows. Neither is a default worth
    /// overriding from the environment.
    ManySubjectsPerChannel,
}

/// How a claimed subject is made answerable to a channel identity.
///
/// One method for the decision, so an implementation cannot answer differently
/// in two places.
pub trait Binding<S: Subject>: Send + Sync {
    /// Decides whether `channel` may speak for `subject`, recording the binding
    /// when it may.
    fn claim(&mut self, channel: &ChannelIdentity, subject: S, now: Instant) -> Claim;

    /// Releases the hold a connection took on `subject` when it closes.
    ///
    /// **Takes the subject the caller actually claimed**, and only decrements an
    /// entry whose channel matches. Both halves matter:
    ///
    /// * A connection that was *refused* took no hold, has no subject, and
    ///   therefore has nothing to call this with. An earlier shape took only the
    ///   channel and decremented every entry it matched, so a refused connection
    ///   sharing a key with a live one released **that** connection's hold —
    ///   letting one channel go on to speak for a second subject, which is the
    ///   exact invariant this module exists to enforce. Found by porting
    ///   `rendezvous`'s own refusal tests; see `README.md` §12.
    /// * Naming the channel as well means a caller cannot release a binding it
    ///   does not hold by guessing a subject.
    fn release(&mut self, channel: &ChannelIdentity, subject: &S, now: Instant);

    /// Drops bindings past their TTL.
    fn sweep(&mut self, now: Instant);

    /// How many bindings are held. For metrics and tests.
    fn len(&self) -> usize;

    /// Whether none are held.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Bounds on the binding table.
#[derive(Debug, Clone, Copy)]
pub struct BindingLimits {
    /// How long a binding outlives its connection.
    ///
    /// Longer than the attachment TTL on purpose: a device that drops and
    /// reconnects must find its own binding still there, and an attacker racing
    /// that reconnect must find it **taken**. Shorter than for ever, because a
    /// device that legitimately rotates its identity key must eventually be able
    /// to bind — and because an unbounded table is an unbounded table.
    pub ttl: Duration,
    /// The ceiling on concurrently held bindings.
    pub max_bindings: usize,
    /// How many subjects one channel may speak for.
    pub cardinality: BindingCardinality,
}

impl Default for BindingLimits {
    fn default() -> Self {
        Self {
            // Ten minutes: comfortably past a mobile radio transition and a
            // process restart, well short of a key-rotation window.
            ttl: Duration::from_millis(600_000),
            max_bindings: 16_384,
            cardinality: BindingCardinality::OneSubjectPerChannel,
        }
    }
}
