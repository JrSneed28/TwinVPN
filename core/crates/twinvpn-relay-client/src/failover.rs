//! Failover, drain, and multi-region redistribution — **with zero
//! control-plane messages anywhere**.
//!
//! **Authority:** ADR-0006 §11.4 (attribution), §11.5 (the mechanism), §11.7
//! (stampede control), §11.8 (total unavailability); `docs/reliability.md` §8.1,
//! §8.2, §8.3, §8.4; ADR-0018 CD-4.
//!
//! # Attribution comes first, and it decides everything after it
//!
//! §11.4: "'Is the relay reachable' and 'is the peer talking' are two separate
//! observations, not one." A silent half-flow on a **live** leg is peer loss and
//! **MUST NOT** cause failover — "a working relay is not the problem, and moving
//! costs a migration that cannot help".

use core::time::Duration;

use twinvpn_env::{consumers, Env, EnvError, MonotonicInstant};
use twinvpn_types::{DeviceId, RelayId};

/// What was observed, at the level §11.4 attributes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Seven booleans and a count, one per row of §11.4's attribution table. They are
// deliberately separate observations rather than one status: "'is the relay
// reachable' and 'is the peer talking' are TWO SEPARATE OBSERVATIONS, not one",
// and a packed type would make the discriminator that whole section rests on
// impossible to express.
#[allow(clippy::struct_excessive_bools)]
pub struct Observation {
    /// Consecutive missed leg `PING`/`PONG`. Three is `T_LEG_DEAD`.
    pub missed_leg_pings: u32,
    /// A hard leg signal: TCP RST, QUIC `CONNECTION_CLOSE`, socket error, ICMP
    /// unreachable.
    pub leg_hard_signal: bool,
    /// The relay's drain deadline has been reached.
    pub drain_deadline_reached: bool,
    /// Whether the half-flow is silent in both directions.
    pub half_flow_silent: bool,
    /// Whether quality is over `docs/reliability.md` §5.4's thresholds.
    pub quality_violated: bool,
    /// Whether every leg on this interface died at once, or `EV_LINK_DOWN` fired.
    pub all_legs_on_interface_dead: bool,
    /// Whether a `RELAY_STATUS` reported capacity rather than fault.
    pub capacity_rejected: bool,
    /// The correlated detector's verdict.
    pub region_failed: bool,
}

/// §11.4's attribution table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attribution {
    /// The relay is down. Fail over.
    RelayFailure,
    /// The peer is gone, or the peer's own leg failed. **Do not fail over.**
    PeerLoss,
    /// Quality degradation; migrate only if an alternate is `PATH_BETTER`.
    PathDegradation,
    /// The local link failed. Not a relay event at all.
    LocalLinkFailure,
    /// A whole region is down.
    RegionFailure,
    /// Capacity, not fault. Honour `retry_after_ms`.
    Capacity,
    /// Nothing is wrong.
    Healthy,
}

impl Attribution {
    /// Whether this attribution justifies moving relay.
    #[must_use]
    pub const fn triggers_failover(self) -> bool {
        matches!(
            self,
            Attribution::RelayFailure | Attribution::RegionFailure | Attribution::Capacity
        )
    }
}

/// `T_LEG_DEAD` — three missed leg `PING`/`PONG`. A **count**, and a deliberately
/// different constant from `T_DEAD`.
pub const N_LEG_DEAD_MISSED: u32 = 3;

/// Applies §11.4, in the table's order.
#[must_use]
pub fn attribute(o: Observation) -> Attribution {
    // The local link is checked first: a dead interface is not a relay event,
    // and treating it as one would fail over on every Wi-Fi drop.
    if o.all_legs_on_interface_dead {
        return Attribution::LocalLinkFailure;
    }
    if o.region_failed {
        return Attribution::RegionFailure;
    }
    if o.capacity_rejected {
        return Attribution::Capacity;
    }
    let leg_dead =
        o.missed_leg_pings >= N_LEG_DEAD_MISSED || o.leg_hard_signal || o.drain_deadline_reached;
    if leg_dead {
        return Attribution::RelayFailure;
    }
    // The leg is ALIVE from here on.
    if o.half_flow_silent {
        // Peer loss, or the peer's own relay leg failed. Moving a working relay
        // cannot help.
        return Attribution::PeerLoss;
    }
    if o.quality_violated {
        return Attribution::PathDegradation;
    }
    Attribution::Healthy
}

/// §11.5's simultaneous-offer rule.
///
/// > `path_epoch` is monotone; on an **equal** epoch the offer from the device
/// > with the lexicographically **lower `device_id`** wins and the other is
/// > ignored with `RELAY.FAILOVER.EPOCH_CONFLICT`. Both peers can evaluate this
/// > rule with no coordination, because `device_id` is self-certifying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferOutcome {
    /// Ours wins.
    Ours,
    /// Theirs wins; ignore ours.
    Theirs,
}

/// Resolves two competing `PathOffer`s.
#[must_use]
pub fn resolve_offers(
    our_epoch: u64,
    our_device: DeviceId,
    their_epoch: u64,
    their_device: DeviceId,
) -> OfferOutcome {
    match our_epoch.cmp(&their_epoch) {
        core::cmp::Ordering::Greater => OfferOutcome::Ours,
        core::cmp::Ordering::Less => OfferOutcome::Theirs,
        core::cmp::Ordering::Equal => {
            if our_device.to_array() <= their_device.to_array() {
                OfferOutcome::Ours
            } else {
                OfferOutcome::Theirs
            }
        }
    }
}

/// §11.5 rule 3: the `PathOffer` travels over the **standby flow**, not the dead
/// one.
///
/// "This is the reason a standby is worth its cost twice over: it is both the
/// destination **and** the signalling channel."
#[must_use]
pub const fn offer_carrier(standby: Option<RelayId>) -> Option<RelayId> {
    standby
}

/// Whether the transition may be `MIGRATING`, or must pass through
/// `RECONNECTING`.
///
/// §11.5 rule 1's cold-relay case, stated rather than glossed: a relay "never
/// probed and never connected" does **not** satisfy T19's guard, so T20 applies
/// and the `Session` passes through `RECONNECTING`. "That is a legal transition
/// and a **truthful** one: for the ~2 s of leg handshake + `BIND` + validation
/// there is genuinely no carrying path, and reporting `MIGRATING` would assert a
/// make-before-break that is not happening."
#[must_use]
pub const fn failover_is_make_before_break(standby_bound_or_leg_only: bool) -> bool {
    standby_bound_or_leg_only
}

/// `docs/reliability.md` §8.3's herd-safe drain.
///
/// > On `EV_RELAY_DRAINING{deadline}`, T37 schedules the migration at a time
/// > drawn uniformly from `[0, deadline − 60 s]`, so a fleet leaving a draining
/// > relay spreads itself across the drain window instead of arriving at its
/// > replacement together. **The 60 s reserve exists so that a device whose
/// > migration fails still has a full `T_MIGRATE` budget and one retry before
/// > the deadline.**
///
/// # Errors
///
/// Propagates an entropy or derivation failure from `Env::rng_for` rather than
/// substituting a fixed offset — every device drawing the same offset is exactly
/// the herd this function exists to prevent.
pub fn drain_offset(env: &Env, deadline: Duration) -> Result<Duration, EnvError> {
    let span = deadline.saturating_sub(DRAIN_RESERVE);
    if span.is_zero() {
        // The deadline is already inside the reserve: move now rather than
        // scheduling a migration that cannot finish.
        return Ok(Duration::ZERO);
    }
    let mut rng = env.rng_for(consumers::RELAY_REGION_SPREAD)?;
    Ok(rng.uniform_duration(span))
}

/// The 60 s reserve §8.3 keeps at the end of the drain window.
pub const DRAIN_RESERVE: Duration = Duration::from_secs(60);

/// §11.7 rule 2's split jittered start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionMoveTiming {
    /// The device holds a **bound** standby: move **immediately**. "Their
    /// capacity was already accounted at bind time, so their move requests
    /// nothing new. Delaying them serves nobody."
    Immediate,
    /// The device must **acquire** new capacity: draw from
    /// `uniform(0, T_REGION_SPREAD)` and emit `RELAY.REGION.SHED_DEFERRED` "so
    /// the deferral is visible rather than looking like a hang".
    Deferred(Duration),
}

/// `T_REGION_SPREAD`.
pub const T_REGION_SPREAD: Duration = Duration::from_secs(20);

/// Decides when this device moves during a region failover.
///
/// # Errors
///
/// Propagates an entropy or derivation failure.
pub fn region_move_timing(
    env: &Env,
    holds_bound_standby: bool,
) -> Result<RegionMoveTiming, EnvError> {
    if holds_bound_standby {
        return Ok(RegionMoveTiming::Immediate);
    }
    let mut rng = env.rng_for(consumers::RELAY_REGION_SPREAD)?;
    Ok(RegionMoveTiming::Deferred(
        rng.uniform_duration(T_REGION_SPREAD),
    ))
}

/// §11.7 rule 3: destination-side shedding with a usable answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShedResponse {
    /// How long to wait. **MUST** be honoured.
    pub retry_after: Duration,
    /// Suggested alternatives. A **hint**: the device re-ranks against its own
    /// map, and "**MUST ignore any suggestion absent from the verified map**".
    pub suggested: Vec<RelayId>,
}

impl ShedResponse {
    /// The suggestions that survive verification against the map.
    #[must_use]
    pub fn admissible_suggestions(&self, verified: &[RelayId]) -> Vec<RelayId> {
        self.suggested
            .iter()
            .copied()
            .filter(|s| verified.contains(s))
            .collect()
    }

    /// §11.7 rule 3: "MUST try a suggested alternative **before** retrying the
    /// same relay".
    #[must_use]
    pub fn must_try_alternative_first(&self, verified: &[RelayId]) -> bool {
        !self.admissible_suggestions(verified).is_empty()
    }
}

/// §11.8's outcome when nothing at all is reachable.
///
/// `DEGRADED` **MUST NOT** be used: "reliability §4.4 defines `DEGRADED` as
/// traffic continuing to flow, and here nothing flows."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetExhausted {
    /// A direct path is carrying traffic: **no state change**, and
    /// `RELAY.STANDBY_UNAVAILABLE` informational.
    NoStateChange,
    /// No path, fail-closed: `BLOCKED`, which retries forever at the floor rate.
    Blocked,
    /// No path, permissive: `RECONNECTING` until `T_RECONNECT_MAX`, then
    /// `FAILED`.
    ReconnectingThenFailed,
}

/// §11.8's table.
#[must_use]
pub const fn fleet_exhausted(direct_path_carrying: bool, fail_closed: bool) -> FleetExhausted {
    if direct_path_carrying {
        FleetExhausted::NoStateChange
    } else if fail_closed {
        FleetExhausted::Blocked
    } else {
        FleetExhausted::ReconnectingThenFailed
    }
}

/// The moment failover began, for `onset_to_traffic_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailoverTiming {
    /// When the failure was detected.
    pub onset: MonotonicInstant,
    /// When traffic resumed.
    pub traffic_resumed: Option<MonotonicInstant>,
}

impl FailoverTiming {
    /// How long the cutover took, once it has.
    #[must_use]
    pub fn onset_to_traffic(&self) -> Option<Duration> {
        self.traffic_resumed.map(|t| t.duration_since(self.onset))
    }

    /// Whether the 300 ms design target was met.
    #[must_use]
    pub fn met_target(&self) -> bool {
        self.onset_to_traffic()
            .is_some_and(|d| d <= crate::standby::T_FAILOVER_TARGET)
    }
}
