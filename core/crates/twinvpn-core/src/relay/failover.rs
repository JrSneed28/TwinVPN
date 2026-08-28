//! The primary and its warm standby, and what happens when the primary dies.
//!
//! **Authority:** ADR-0006 §11.4 (failure attribution), §11.5 (the failover
//! mechanism and the cold-relay case), §11.6 (the standby condition table),
//! §11.7 (stampede control), §11.8 (total unavailability);
//! `docs/reliability.md` §4.4, §5.3's `T_STANDBY_WARM`, §8.1, §8.2, §11.1,
//! §11.2, and T19/T20/T37.
//!
//! # Attribution comes first, and it decides everything after it
//!
//! ADR-0006 §11.4: *"'Is the relay reachable' and 'is the peer talking' are two
//! separate observations, not one."* A silent half-flow on a **live** leg is
//! peer loss and MUST NOT cause failover — a working relay is not the problem,
//! and moving costs a migration that cannot help. [`RelayPair::on_observation`]
//! therefore calls `twinvpn_relay_client::failover::attribute` on the real
//! observation and branches on its verdict, rather than on "did something look
//! wrong".
//!
//! # What the standby is for, stated as the thing it buys
//!
//! `docs/reliability.md` §5.3 sets `T_FAILOVER_TARGET` at 300 ms. A leg
//! handshake plus `BIND` plus validation is ~2 s, so a failover that begins
//! with a fresh selection cannot meet that target and ADR-0006 §11.5 rule 1
//! routes it through `RECONNECTING` instead — *"a legal transition and a
//! **truthful** one: for the ~2 s … there is genuinely no carrying path, and
//! reporting `MIGRATING` would assert a make-before-break that is not
//! happening."*
//!
//! So the standby is what makes T19 reachable, and this type exists to make
//! "did we actually use it" answerable. [`Failover::PromotedStandby`] promotes
//! a leg that is **already bound** — no selection, no handshake, no `BIND`, and
//! measurably no datagram to the relay, which is what
//! `failover_to_a_warm_standby_needs_no_fresh_selection` asserts.
//!
//! # A standby whose keepalive is stopped is not warm
//!
//! `twinvpn_relay_client::standby::Posture::is_warm` answers `false` for
//! `Released`, and this module never reports otherwise. §11.2: *"the failover
//! posture on parked mobile is **genuinely weaker**, and saying so is the
//! point."*

use twinvpn_relay_client::failover::{attribute, Attribution, Observation};
use twinvpn_relay_client::standby::{self, Conditions, Posture};
use twinvpn_types::{codes as reg, ReasonCode, RelayId};

use super::leg::RelayLeg;

/// What this device did, or must do, about a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Failover {
    /// Nothing is wrong, or the fault is not the relay's.
    ///
    /// Carries the attribution rather than swallowing it, because "the peer is
    /// gone" and "the local link died" want completely different work and
    /// neither wants a relay move.
    NoMove {
        /// §11.4's verdict.
        attribution: Attribution,
    },
    /// The warm standby was promoted. **Make-before-break**: T19's guard held.
    PromotedStandby {
        /// The relay that failed.
        from: RelayId,
        /// The relay now carrying the flow.
        to: RelayId,
        /// §11.4's verdict, so the move and its cause travel together.
        attribution: Attribution,
    },
    /// A move is required and there is no standby to move to.
    ///
    /// T20, not T19: the `Session` passes through `RECONNECTING` while a fresh
    /// selection, leg handshake and `BIND` happen. Reporting `MIGRATING` here
    /// would assert a make-before-break that is not happening.
    NeedsSelection {
        /// The relay that failed.
        from: RelayId,
        /// §11.4's verdict.
        attribution: Attribution,
    },
}

impl Failover {
    /// The registered `reason_code` this outcome is reported as.
    ///
    /// A promotion is `RELAY.FAILOVER_VALIDATED` — the registry's code for a
    /// completed, validated move, with both relay ids as declared evidence. The
    /// absence of a standby is `RELAY.FAILOVER.NO_STANDBY`, which is what makes
    /// the weaker posture visible **at** the failure; §11.6's suppression codes
    /// make it visible *before* one.
    #[must_use]
    pub const fn reason_code(self) -> Option<ReasonCode> {
        match self {
            Failover::NoMove { .. } => None,
            Failover::PromotedStandby { .. } => Some(reg::RELAY_FAILOVER_VALIDATED),
            Failover::NeedsSelection { .. } => Some(reg::RELAY_FAILOVER_NO_STANDBY),
        }
    }

    /// Whether the transition may be reported as `MIGRATING`.
    ///
    /// Delegated to `failover::failover_is_make_before_break` so the rule has
    /// one definition: a promotion is make-before-break, everything else is not.
    #[must_use]
    pub const fn is_make_before_break(self) -> bool {
        twinvpn_relay_client::failover::failover_is_make_before_break(matches!(
            self,
            Failover::PromotedStandby { .. }
        ))
    }
}

/// One relay leg and, when policy says to hold one, its warm alternate.
pub struct RelayPair {
    primary: RelayLeg,
    standby: Option<RelayLeg>,
    posture: Posture,
}

impl RelayPair {
    /// A pair with no standby yet.
    ///
    /// §11.6's first row: fewer than two admissible relays means there is
    /// nothing to be a standby, and a brief relay use should not pay for a
    /// second relay. So `None` is a legitimate steady state, not a gap.
    #[must_use]
    pub const fn new(primary: RelayLeg) -> Self {
        Self {
            primary,
            standby: None,
            posture: Posture::None,
        }
    }

    /// The leg carrying traffic.
    #[must_use]
    pub const fn primary(&self) -> &RelayLeg {
        &self.primary
    }

    /// The leg carrying traffic, mutably — for sending on it.
    pub fn primary_mut(&mut self) -> &mut RelayLeg {
        &mut self.primary
    }

    /// The warm alternate, when one is held.
    #[must_use]
    pub const fn standby(&self) -> Option<&RelayLeg> {
        self.standby.as_ref()
    }

    /// The alternate, mutably — for the keepalive that is what makes it warm.
    pub fn standby_mut(&mut self) -> Option<&mut RelayLeg> {
        self.standby.as_mut()
    }

    /// The posture §11.6's table produces for `conditions`.
    #[must_use]
    pub const fn posture(&self) -> Posture {
        self.posture
    }

    /// Adopts a second leg as the standby, and records the posture that goes
    /// with it.
    ///
    /// The leg must already be **bound**: `Posture::is_warm` is `true` only for
    /// `Bound`, and a leg-only or released alternate cannot be promoted without
    /// the `BIND` round trip this whole mechanism exists to avoid. A leg that
    /// is not bound is refused rather than adopted and quietly reported as
    /// warm — which is §11.2's "saying so is the point", enforced.
    ///
    /// # Errors
    ///
    /// The unbound leg is handed back, so the caller still owns it and can
    /// finish binding it.
    pub fn adopt_standby(
        &mut self,
        leg: RelayLeg,
        conditions: Conditions,
    ) -> Result<(), Box<RelayLeg>> {
        if !leg.is_bound() {
            return Err(Box::new(leg));
        }
        self.posture = standby::posture(conditions);
        self.standby = Some(leg);
        Ok(())
    }

    /// Records the §11.6 posture without adopting a leg.
    ///
    /// The suppression rows produce a posture with **no bound standby**, and
    /// the accompanying code — `RELAY.STANDBY.SUPPRESSED_METERED`,
    /// `RELAY.STANDBY.SUPPRESSED_POWER`, `RELAY.STANDBY_UNAVAILABLE` — is what
    /// makes the weaker failover posture visible *before* the failure rather
    /// than at it. [`standby::suppression_reason`] names it.
    pub fn set_posture(&mut self, conditions: Conditions) -> Posture {
        self.posture = standby::posture(conditions);
        self.posture
    }

    /// Applies §11.4's attribution to a real observation and acts on it.
    ///
    /// **No selection runs here, ever.** Either the standby is promoted — one
    /// move of an already-bound leg, no datagram to any relay — or the caller
    /// is told that a fresh selection is required. Selection is
    /// `twinvpn_relay_client::select`'s and it is a total ordering over the
    /// verified map, which is a different decision from this one and belongs to
    /// whoever holds the map.
    pub fn on_observation(&mut self, observation: Observation) -> Failover {
        let attribution = attribute(observation);
        if !attribution.triggers_failover() {
            return Failover::NoMove { attribution };
        }
        let from = self.primary.relay();
        // A standby is only ever adopted bound, so this is a promotion and not
        // a bind. The `take` is what makes it a move rather than a copy: after
        // it, there is exactly one carrying leg and no stale second reference
        // to a relay this device has left.
        match self.standby.take() {
            Some(next) => {
                let to = next.relay();
                self.primary = next;
                self.posture = Posture::None;
                Failover::PromotedStandby {
                    from,
                    to,
                    attribution,
                }
            }
            None => Failover::NeedsSelection { from, attribution },
        }
    }
}

impl core::fmt::Debug for RelayPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RelayPair")
            .field("primary", &self.primary.relay())
            .field("standby", &self.standby.as_ref().map(RelayLeg::relay))
            .field("posture", &self.posture)
            .finish()
    }
}
