//! ADR-0006 §11.6's warm-standby policy: **when**, and **which**.
//!
//! **Authority:** ADR-0006 §11.6 (the condition table), §11.4 (failure
//! attribution); `docs/reliability.md` §4.4, §5.3's `T_STANDBY_WARM`, §8.1,
//! §11.1, §11.2.
//!
//! # A standby whose keepalive is stopped is not warm
//!
//! §11.6 and `docs/reliability.md` §8.1 both say it, and §11.2 says why it
//! matters: "The failover posture on parked mobile is **genuinely weaker**, and
//! saying so is the point."
//!
//! [`Posture::is_warm`] therefore answers `false` for [`Posture::Released`], and
//! there is no way to report a released standby as warm.

use core::time::Duration;

use twinvpn_types::PathClass;

/// `T_STANDBY_WARM`, from `docs/reliability.md` §5.3.
pub const T_STANDBY_WARM: Duration = Duration::from_secs(30);
/// `T_FAILOVER_TARGET` — the design target a leg-only standby must meet.
pub const T_FAILOVER_TARGET: Duration = Duration::from_millis(300);

/// The device's role, which decides whether dwell applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// An ordinary peer.
    Peer,
    /// A `LANGateway`, `ExitNode`, or user-marked "always reachable" device.
    ///
    /// `docs/reliability.md` §6.6's exception class: these keep a maintained
    /// path, "held by the **relay** rather than by a raw NAT binding, because a
    /// relay session can be kept alive through OS-sanctioned mechanisms far more
    /// cheaply than a UDP mapping can".
    AlwaysReachable,
}

/// The power and link facts §11.6's last two rows read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerPosture {
    /// Whether the link is metered.
    pub metered: bool,
    /// Battery percentage, where the platform reports one.
    pub battery_pct: Option<u8>,
    /// Whether the device is parked (backgrounded, no inbound requirement).
    pub parked: bool,
}

impl PowerPosture {
    /// Whether §11.6's suppression rows apply.
    #[must_use]
    pub fn suppressed(self) -> bool {
        self.metered || self.battery_pct.is_some_and(|b| b < 20)
    }
}

/// What posture the standby is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Posture {
    /// A second relay is **bound**: the designed failover path.
    Bound,
    /// The leg is established but no `BIND` has been made — one `BIND` RTT from
    /// bound, which satisfies `WAN_DIRECT`'s "warm **or re-establishable within
    /// `T_FAILOVER_TARGET`**" invariant.
    LegOnly,
    /// No standby. Brief relay use should not pay for a second relay.
    None,
    /// Released on a parked device, and **re-established on wake before traffic
    /// resumes**.
    Released,
}

impl Posture {
    /// Whether this posture may be **reported** as warm.
    #[must_use]
    pub const fn is_warm(self) -> bool {
        matches!(self, Posture::Bound)
    }

    /// Whether `docs/reliability.md` T19's guard `RELAY_FAILOVER_TARGET_READY`
    /// is satisfied — "a standby is bound, **or** a leg-only standby is
    /// reachable within `T_FAILOVER_TARGET`".
    ///
    /// This is "the guard that separates T19 from T20 on relay death, and its
    /// absence is exactly the cold-relay case ADR-0006 §11.5 rule 1 routes
    /// through `RECONNECTING`".
    #[must_use]
    pub const fn failover_target_ready(self) -> bool {
        matches!(self, Posture::Bound | Posture::LegOnly)
    }
}

/// Everything §11.6's table reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Conditions {
    /// The carrier class the `Session` is on.
    pub carrier: PathClass,
    /// How long it has been on it.
    pub carrier_duration: Duration,
    /// The device's role.
    pub role: Role,
    /// The power and link facts.
    pub power: PowerPosture,
    /// How many relays are admissible.
    pub admissible_relays: usize,
    /// Whether the device is on mains power or an unmetered link.
    pub mains_or_unmetered: bool,
}

/// §11.6's table, row by row and in its order.
#[must_use]
pub fn posture(c: Conditions) -> Posture {
    // Fewer than 2 admissible relays: there is nothing to be a standby.
    if c.admissible_relays < 2 {
        return Posture::None;
    }
    // Parked: released, and re-established on wake.
    if c.power.parked {
        return Posture::Released;
    }
    // Gateway, exit node or always-reachable: BOUND immediately, no dwell.
    if c.role == Role::AlwaysReachable {
        return Posture::Bound;
    }
    // Metered or low battery: LEG-ONLY, and the weaker posture is ANNOUNCED
    // "before the failure", not discovered at it.
    if c.power.suppressed() {
        return Posture::LegOnly;
    }
    match c.carrier {
        PathClass::Relayed => {
            if c.carrier_duration >= T_STANDBY_WARM {
                Posture::Bound
            } else {
                Posture::None
            }
        }
        PathClass::WanDirect => {
            if c.mains_or_unmetered {
                Posture::LegOnly
            } else {
                Posture::None
            }
        }
        // A LAN path needs no relay standby to satisfy an invariant: §4.4's
        // alternate requirement is WAN_DIRECT's, not LOCAL_DIRECT's.
        PathClass::LocalDirect => Posture::None,
    }
}

/// Whether a suppression code must accompany the posture, so the weaker failover
/// posture is visible **before** the failure rather than at it.
#[must_use]
pub fn suppression_reason(c: Conditions, p: Posture) -> Option<&'static str> {
    if p == Posture::LegOnly && c.power.metered {
        return Some("RELAY.STANDBY.SUPPRESSED_METERED");
    }
    if p == Posture::LegOnly && c.power.battery_pct.is_some_and(|b| b < 20) {
        return Some("RELAY.STANDBY.SUPPRESSED_POWER");
    }
    if p == Posture::None && c.admissible_relays < 2 {
        return Some("RELAY.STANDBY_UNAVAILABLE");
    }
    None
}

/// §11.6's region preference for the standby.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegionPreference {
    /// Same region as the primary, when it can supply a **different failure
    /// domain** — preserves the latency budget on cutover.
    SameRegionDifferentDomain,
    /// An adjacent region, ordered by published `added_rtt_ms_p50`.
    AdjacentRegion,
    /// Anywhere admissible.
    Any,
}

impl RegionPreference {
    /// The order to try.
    pub const ORDER: [RegionPreference; 3] = [
        RegionPreference::SameRegionDifferentDomain,
        RegionPreference::AdjacentRegion,
        RegionPreference::Any,
    ];
}
