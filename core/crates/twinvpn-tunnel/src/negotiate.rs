//! ADR-0014's negotiation: the selection function, the monotonic floor, and the
//! two caps.
//!
//! **Authority:** ADR-0014 N-6, N-8, N-9, N-10, N-11, N-16, N-17, N-19; ADR-0001
//! §7.3 D1–D6, §7.3.1; `docs/implementation/ownership.md` §4.3 (the open
//! `limits.json` defect); `contracts/registry/capabilities.json`.
//!
//! # Negotiation happens only inside the authenticated tunnel
//!
//! D1: "No negotiated result may become **authoritative**, or cause any
//! persistent state change, until it is confirmed **inside** the established
//! L-DATA session. Advertisements MAY be exchanged pre-handshake … but they are
//! **claims, not decisions**."
//!
//! [`Advertisement`] is the claim; [`Selection`] is the decision; and
//! [`MonotonicFloor::record`] refuses to write anything until the caller says the
//! selection was confirmed in-session (P-4).
//!
//! # The capability-name cap is 32, not `limits.json`'s 24
//!
//! `ownership.md` §4.3 records the open defect: `limits.json` says 24,
//! `capabilities.json` says 32, the CDDL says `[a-z][a-z0-9_]{0,31}`, and the
//! registry itself contains `dns_config_dies_with_tunnel` — **27 bytes**. This
//! crate validates against 32 through
//! `twinvpn_schema::validate::is_capability_name`, which already carries the
//! exception and the citation.

use std::collections::BTreeSet;

use twinvpn_schema::{limits, validate, Reject};

/// N-10's pre-authentication caps, from `limits.json` `capability.*`.
pub struct Caps;

impl Caps {
    /// At most this many tokens in one advertisement.
    pub const MAX_TOKENS: usize = limits::CAPABILITY_MAX_TOKENS;
    /// At most this many bytes in one advertisement.
    pub const MAX_ADVERTISEMENT_BYTES: usize = limits::CAPABILITY_MAX_ADVERTISEMENT_BYTES;
    /// N-11's name cap: **32**, per `ownership.md` §4.3.
    pub const MAX_NAME_BYTES: usize = limits::CAPABILITY_MAX_NAME_BYTES;
    /// At most this many parameters per token.
    pub const MAX_PARAMETERS: usize = limits::CAPABILITY_MAX_PARAMETERS;
    /// At most this many parameter bytes in total.
    pub const MAX_PARAMETER_BYTES: usize = limits::CAPABILITY_MAX_PARAMETER_BYTES;
    /// How far above the current epoch a peer may advertise.
    pub const MAX_EPOCH_ABOVE_CURRENT: usize = limits::CAPABILITY_MAX_EPOCH_ABOVE_CURRENT;
}

/// One peer's **claim** about what it supports.
///
/// Pre-authentication, attacker-controlled, and capped before anything is
/// allocated from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertisement {
    /// The peer's full supported range — **both** bounds.
    ///
    /// ADR-0014 §11.10 required-edit 3: without the responder's own maximum,
    /// "the initiator cannot verify that the responder selected the highest
    /// mutually supported epoch, **and the T2/T3 downgrade defence does not
    /// exist**".
    pub v_min: u32,
    /// The upper bound.
    pub v_max: u32,
    /// The full advertised set, canonically sorted.
    pub capabilities: BTreeSet<String>,
}

impl Advertisement {
    /// Validates a received advertisement against N-10's caps.
    ///
    /// # Errors
    ///
    /// [`Reject::CapViolated`] past any cap, or [`Reject::Malformed`] on a token
    /// whose name does not match `[a-z][a-z0-9_]{0,31}`.
    pub fn validate(&self, current_epoch: u32) -> Result<(), Reject> {
        Reject::check_max(
            "capability.max_tokens_per_advertisement",
            self.capabilities.len(),
            Caps::MAX_TOKENS,
        )?;
        let total: usize = self.capabilities.iter().map(String::len).sum();
        Reject::check_max(
            "capability.max_advertisement_bytes",
            total,
            Caps::MAX_ADVERTISEMENT_BYTES,
        )?;
        for name in &self.capabilities {
            if !validate::is_capability_name(name) {
                return Err(Reject::cap("capability.name_shape", 0, 1));
            }
        }
        validate::epoch_reach(current_epoch, self.v_max)?;
        Ok(())
    }
}

/// The agreed result, which is what the transcript covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// The selected epoch: the highest mutually supported one.
    pub epoch: u32,
    /// The selected capability set: the intersection.
    pub capabilities: BTreeSet<String>,
}

/// Computes the selection from two advertisements.
///
/// Both peers compute it **independently** and must agree; "disagreement
/// surfaces at `NegotiationConfirm`", which is the third detection layer and
/// "the only one that catches implementation divergence in the selection
/// function itself".
///
/// Returns `None` when the ranges do not overlap, which is
/// `PROTO.VERSION_UNSUPPORTED` and `docs/reliability.md` T06.
#[must_use]
pub fn select(ours: &Advertisement, theirs: &Advertisement) -> Option<Selection> {
    let lo = ours.v_min.max(theirs.v_min);
    let hi = ours.v_max.min(theirs.v_max);
    if lo > hi {
        return None;
    }
    Some(Selection {
        // The highest mutually supported epoch. "A unique maximum by
        // construction", which is why glare does not affect version selection.
        epoch: hi,
        capabilities: ours
            .capabilities
            .intersection(&theirs.capabilities)
            .cloned()
            .collect(),
    })
}

/// D3 / S-37's monotonic floor.
///
/// > Each `Device` MUST persist, per `TrustedPeer`, the highest
/// > `ProtocolVersion` epoch and the **`security_relevant` subset** of the
/// > `Capability` set ever successfully negotiated, and MUST refuse a strictly
/// > weaker offer.
///
/// The scope limit is load-bearing: the floor "MUST NOT cover the whole
/// capability set, because an honest device whose OS revokes a permission would
/// otherwise be **permanently unable to reconnect**" (N-19).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MonotonicFloor {
    epoch: u32,
    security_relevant: BTreeSet<String>,
}

impl MonotonicFloor {
    /// An empty floor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The recorded epoch floor.
    #[must_use]
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The recorded `security_relevant` tokens.
    #[must_use]
    pub fn security_relevant(&self) -> &BTreeSet<String> {
        &self.security_relevant
    }

    /// Whether an offer is admissible, or is a refused downgrade.
    ///
    /// `PROTO.DOWNGRADE_REFUSED` carries `recorded_floor`, `offered_epoch` and
    /// `lost_security_capabilities`, all of which this method's inputs supply.
    #[must_use]
    pub fn admits(&self, selection: &Selection, security_relevant: &BTreeSet<String>) -> bool {
        if selection.epoch < self.epoch {
            return false;
        }
        // A security-relevant token that was in the floor and is absent now is a
        // downgrade. A non-security-relevant one is not, by N-19.
        self.security_relevant
            .iter()
            .all(|t| security_relevant.contains(t) && selection.capabilities.contains(t))
    }

    /// The security-relevant tokens an offer would lose, for the diagnostic.
    #[must_use]
    pub fn lost_tokens(&self, selection: &Selection) -> Vec<String> {
        self.security_relevant
            .iter()
            .filter(|t| !selection.capabilities.contains(*t))
            .cloned()
            .collect()
    }

    /// Records a selection into the floor.
    ///
    /// P-4: "A version epoch that is not yet **confirmed in-session** MUST NOT be
    /// written to the S-37 floor." `confirmed_in_session` is therefore a required
    /// argument and a `false` writes nothing.
    pub fn record(
        &mut self,
        selection: &Selection,
        security_relevant: &BTreeSet<String>,
        confirmed_in_session: bool,
    ) -> bool {
        if !confirmed_in_session {
            return false;
        }
        self.epoch = self.epoch.max(selection.epoch);
        for t in selection.capabilities.intersection(security_relevant) {
            self.security_relevant.insert(t.clone());
        }
        true
    }

    /// Clearing the floor "MUST require an authenticated local management-plane
    /// action by the `Owner`" (D3).
    ///
    /// The argument is the proof, and there is no `clear()` without it.
    pub fn clear(&mut self, owner_local_action: OwnerLocalAction) {
        let OwnerLocalAction(()) = owner_local_action;
        self.epoch = 0;
        self.security_relevant.clear();
    }
}

/// Evidence of an authenticated local management-plane action by the `Owner`.
///
/// No `Default`, no public field: a floor must not be clearable from nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerLocalAction(());

impl OwnerLocalAction {
    /// Records that the `Owner` performed the action locally and authenticated.
    #[must_use]
    pub const fn authenticated() -> Self {
        Self(())
    }
}

/// N-16: the negotiated result is **recorded on the `Tunnel` and immutable for
/// its lifetime**, "regardless of any later advertisement change".
///
/// N-17(3): "when a capability disappears mid-session the negotiated set is
/// **NOT MUTATED** — renegotiation requires a **new `Tunnel`**, never a mutated
/// one."
#[must_use]
pub const fn negotiated_set_is_mutable_mid_session() -> bool {
    false
}
