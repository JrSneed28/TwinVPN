//! `docs/reliability.md` §5's constants, each with the clock class §5.3.1
//! requires it to declare.
//!
//! **Authority:** §5.1, §5.2, §5.3, §5.3.1 (R-CLK-1 … R-CLK-3), §5.4, §11.1.
//!
//! # R-CLK-3 is why every constant here is a struct and not a `Duration`
//!
//! > **Rule R-CLK-3.** A constant registered in §5.2 or §5.3 without a declared
//! > clock class is a **defect in this document**, not a detail left to the
//! > implementer.
//!
//! [`TimerConstant`] therefore has no default clock: declaring one is part of
//! declaring the constant. `clock_classes_are_declared_for_every_constant`
//! asserts the whole table, and
//! `authority_bounding_constants_read_the_elapsed_clock` asserts R-CLK-1 — the
//! rule whose violation "voided R-24 on a suspended device".

use core::time::Duration;

/// Which of `twinvpn-env`'s three clocks a constant reads (§5.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClockClass {
    /// Does **not** advance across suspend. Every liveness, establishment,
    /// migration, dwell and backoff constant.
    Monotonic,
    /// Advances across suspend. Long-horizon deadlines that **bound a granted
    /// authority**, and the suspend-gap measurement of §11.3.
    Elapsed,
    /// Evidence only. Never a timer input.
    Wall,
}

/// One registered constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerConstant {
    /// The `T_*` or `N_*` name §5 registers.
    pub name: &'static str,
    /// The default value. Every one is a tunable with a documented safe range.
    pub default: Duration,
    /// R-CLK-3: declared, never inferred.
    pub clock: ClockClass,
    /// Whether this constant exists to **bound a granted authority** (R-CLK-1).
    pub bounds_authority: bool,
}

const fn mono(name: &'static str, d: Duration) -> TimerConstant {
    TimerConstant {
        name,
        default: d,
        clock: ClockClass::Monotonic,
        bounds_authority: false,
    }
}

const fn authority(name: &'static str, d: Duration) -> TimerConstant {
    TimerConstant {
        name,
        default: d,
        clock: ClockClass::Elapsed,
        bounds_authority: true,
    }
}

// -- §5.1 establishment ------------------------------------------------------

/// 1.5 s — emit the first usable candidate early.
pub const T_DISCOVER_SOFT: TimerConstant = mono("T_DISCOVER_SOFT", Duration::from_millis(1_500));
/// 5 s — upper bound on gathering.
pub const T_DISCOVER: TimerConstant = mono("T_DISCOVER", Duration::from_secs(5));
/// 5 s — one rendezvous round trip plus slack.
pub const T_NEGOTIATE: TimerConstant = mono("T_NEGOTIATE", Duration::from_secs(5));
/// 10 s — ~6 hole-punch attempts plus a relay fallback.
pub const T_CONNECT: TimerConstant = mono("T_CONNECT", Duration::from_secs(10));
/// 250 ms — the **settled** Happy Eyeballs v2 bias. §5.1 is emphatic that any
/// ladder derived against 150 ms must be re-derived against this.
pub const T_HE_BIAS: TimerConstant = mono("T_HE_BIAS", Duration::from_millis(250));
/// 300 ms target — a warm relay carries traffic this fast.
pub const T_RELAY_FIRST_TRAFFIC: TimerConstant =
    mono("T_RELAY_FIRST_TRAFFIC", Duration::from_millis(300));

// -- §5.2 liveness -----------------------------------------------------------

/// 3 s — foreground-active heartbeat.
pub const T_HEARTBEAT_ACTIVE: TimerConstant = mono("T_HEARTBEAT_ACTIVE", Duration::from_secs(3));
/// 15 s — after 60 s with no user traffic.
pub const T_HEARTBEAT_IDLE: TimerConstant = mono("T_HEARTBEAT_IDLE", Duration::from_secs(15));
/// 6 s (2 missed) — **end-to-end `Path` only**.
pub const T_SUSPECT: TimerConstant = mono("T_SUSPECT", Duration::from_secs(6));
/// 15 s (5 missed) — **end-to-end `Path` only**.
pub const T_DEAD: TimerConstant = mono("T_DEAD", Duration::from_secs(15));
/// 30 s — an authenticated `PEER_RESTARTING` suppresses failure handling.
pub const T_PEER_RESTART_GRACE: TimerConstant =
    mono("T_PEER_RESTART_GRACE", Duration::from_secs(30));
/// 25 s — the **initial** NAT keepalive rung. The ladder is [`NAT_LADDER`].
pub const T_NAT_KEEPALIVE: TimerConstant = mono("T_NAT_KEEPALIVE", Duration::from_secs(25));

/// `T_LEG_DEAD` — **3 missed** leg `PING`/`PONG`, a count rather than a
/// duration.
///
/// §5.2 is emphatic that this is "a distinct constant from `T_DEAD`,
/// deliberately": `T_DEAD` measures the end-to-end `Path` and means *the peer is
/// unreachable this way*; `T_LEG_DEAD` measures the device↔relay leg and means
/// *this relay is down*. A silent half-flow on a **live** leg is peer loss and
/// MUST NOT cause relay failover.
pub const N_LEG_DEAD_MISSED: u32 = 3;

/// The `T_NAT_KEEPALIVE` ladder, in seconds (§5.2, §6.6).
///
/// Additive while bindings survive; on an observed mapping expiry it reverts to
/// the **last known-good rung**, never to half the current one — "the last rung
/// that worked is a measurement and half of the current rung is not".
pub const NAT_LADDER: [u64; 6] = [25, 35, 50, 70, 100, 120];

// -- §5.3 recovery and dwell -------------------------------------------------

/// 20 s — the boundary between `RECONNECTING` and `BLOCKED`.
pub const T_RECONNECT_GRACE: TimerConstant = mono("T_RECONNECT_GRACE", Duration::from_secs(20));
/// 10 min — only under `PERMISSIVE_ANNOUNCED`. `BLOCKED` has no equivalent bound.
pub const T_RECONNECT_MAX: TimerConstant = mono("T_RECONNECT_MAX", Duration::from_secs(600));
/// 3 s — the **settled** total budget for one migration attempt.
pub const T_MIGRATE: TimerConstant = mono("T_MIGRATE", Duration::from_secs(3));
/// 100 ms — the bounded make-before-break queue, used only when the old path is
/// already gone.
pub const T_MIGRATE_QUEUE: TimerConstant = mono("T_MIGRATE_QUEUE", Duration::from_millis(100));
/// 64 packets — the other half of `T_MIGRATE_QUEUE`. Drop-oldest on overflow.
pub const N_MIGRATE_QUEUE_PACKETS: usize = 64;
/// 60 s — per-candidate cooldown after a **failed** migration.
pub const T_MIGRATE_COOLDOWN: TimerConstant = mono("T_MIGRATE_COOLDOWN", Duration::from_secs(60));
/// 10 s — a violation must persist before it becomes `DEGRADED`.
pub const T_QOS_CONFIRM: TimerConstant = mono("T_QOS_CONFIRM", Duration::from_secs(10));
/// 30 s — asymmetric with confirm on purpose.
pub const T_QOS_CLEAR: TimerConstant = mono("T_QOS_CLEAR", Duration::from_secs(30));
/// 10 min — R5: no unbounded degradation.
pub const T_DEGRADED_MAX: TimerConstant = mono("T_DEGRADED_MAX", Duration::from_secs(600));
/// 30 s — how long `RELAYED` must persist before a standby is opened.
pub const T_STANDBY_WARM: TimerConstant = mono("T_STANDBY_WARM", Duration::from_secs(30));
/// 300 ms — design target for relay-to-relay failover with a warm standby.
pub const T_FAILOVER_TARGET: TimerConstant =
    mono("T_FAILOVER_TARGET", Duration::from_millis(300));

// -- §5.3 constants registered on behalf of other ADRs -----------------------

/// 120 s — quality-only reverse migration is refused for this long after an
/// upgrade. A **hard** failure is never suppressed by it.
pub const T_UPGRADE_DWELL: TimerConstant = mono("T_UPGRADE_DWELL", Duration::from_secs(120));
/// 10 min — the oscillation observation window.
pub const T_UPGRADE_FLAP_WINDOW: TimerConstant =
    mono("T_UPGRADE_FLAP_WINDOW", Duration::from_secs(600));
/// 3 — oscillations within the window that trip suppression.
pub const N_UPGRADE_FLAP: u32 = 3;
/// 30 min — suppression, **on that network fingerprint only**.
pub const T_UPGRADE_FLAP_SUPPRESS: TimerConstant =
    mono("T_UPGRADE_FLAP_SUPPRESS", Duration::from_secs(1_800));
/// 300 s — the mobile-background floor for the direct-upgrade prober.
pub const T_UPGRADE_PROBE_BG: TimerConstant = mono("T_UPGRADE_PROBE_BG", Duration::from_secs(300));
/// 20 — consecutive failed upgrades after which probing becomes event-driven.
/// Probing never stops permanently (R-12).
pub const N_UPGRADE_GIVEUP: u32 = 20;
/// 20 s — the width of the `uniform(0, T_REGION_SPREAD)` draw.
pub const T_REGION_SPREAD: TimerConstant = mono("T_REGION_SPREAD", Duration::from_secs(20));

/// 6 h — routine trust-state refresh floor. **Bounds an authority** (R-CLK-1).
pub const T_TRUST_REFRESH: TimerConstant = authority("T_TRUST_REFRESH", Duration::from_secs(21_600));
/// 24 h — trust state is stale. Persistent `Diagnostic`, **no state change**.
pub const T_TRUST_STALE: TimerConstant = authority("T_TRUST_STALE", Duration::from_secs(86_400));
/// 30 d — granted authority suspends; baseline connectivity continues.
pub const T_TRUST_HARD: TimerConstant =
    authority("T_TRUST_HARD", Duration::from_secs(30 * 86_400));
/// 30 d — identity-key rotation overlap.
pub const T_IK_OVERLAP: TimerConstant = authority("T_IK_OVERLAP", Duration::from_secs(30 * 86_400));
/// 14 d — tunnel-key rotation overlap. Rotation never tears down a `Session`.
pub const T_TK_OVERLAP: TimerConstant = authority("T_TK_OVERLAP", Duration::from_secs(14 * 86_400));

/// Every constant §5.2 and §5.3 register, so R-CLK-3 is checkable.
pub const REGISTERED: &[TimerConstant] = &[
    T_DISCOVER_SOFT,
    T_DISCOVER,
    T_NEGOTIATE,
    T_CONNECT,
    T_HE_BIAS,
    T_RELAY_FIRST_TRAFFIC,
    T_HEARTBEAT_ACTIVE,
    T_HEARTBEAT_IDLE,
    T_SUSPECT,
    T_DEAD,
    T_PEER_RESTART_GRACE,
    T_NAT_KEEPALIVE,
    T_RECONNECT_GRACE,
    T_RECONNECT_MAX,
    T_MIGRATE,
    T_MIGRATE_QUEUE,
    T_MIGRATE_COOLDOWN,
    T_QOS_CONFIRM,
    T_QOS_CLEAR,
    T_DEGRADED_MAX,
    T_STANDBY_WARM,
    T_FAILOVER_TARGET,
    T_UPGRADE_DWELL,
    T_UPGRADE_FLAP_WINDOW,
    T_UPGRADE_FLAP_SUPPRESS,
    T_UPGRADE_PROBE_BG,
    T_REGION_SPREAD,
    T_TRUST_REFRESH,
    T_TRUST_STALE,
    T_TRUST_HARD,
    T_IK_OVERLAP,
    T_TK_OVERLAP,
];

// -- §5.4 quality thresholds -------------------------------------------------

/// Loss above 2 % sustained over `T_QOS_CONFIRM`, in parts per million.
pub const QOS_LOSS_PPM: u32 = 20_000;
/// RTT above 3× the path's established baseline.
pub const QOS_RTT_BASELINE_MULTIPLE: u32 = 3;
/// RTT above 250 ms absolute **on a relay path**. §5.4: "**250 ms is the settled
/// value**", and `networking.md` §4.3's 150 ms must be brought to it.
pub const QOS_RTT_RELAY_ABSOLUTE_MS: u64 = 250;
/// Jitter above 30 ms standard deviation.
pub const QOS_JITTER_MS: u64 = 30;
/// Throughput below 25 % of the measured baseline, **under offered load only**.
pub const QOS_THROUGHPUT_FRACTION_PERCENT: u32 = 25;
/// Effective inner MTU below the IPv6 minimum.
pub const QOS_MIN_EFFECTIVE_MTU: u32 = 1280;

// -- §11.1 the background timer profile -------------------------------------

/// Which §11.1 profile the timers run under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerProfile {
    /// Foreground.
    Foreground,
    /// Backgrounded, but some peer declared an inbound reachability requirement.
    Background,
    /// Backgrounded with no inbound requirement — §11.2's park.
    Parked,
}

impl TimerProfile {
    /// The liveness heartbeat cadence, or `None` when parked.
    #[must_use]
    pub const fn heartbeat(self, idle: bool) -> Option<Duration> {
        match self {
            TimerProfile::Foreground => Some(if idle {
                T_HEARTBEAT_IDLE.default
            } else {
                T_HEARTBEAT_ACTIVE.default
            }),
            TimerProfile::Background => Some(Duration::from_secs(60)),
            TimerProfile::Parked => None,
        }
    }

    /// Whether the NAT binding keepalive runs.
    ///
    /// §11.1: parked means "**stopped** — the binding is allowed to expire".
    #[must_use]
    pub const fn nat_keepalive_runs(self) -> bool {
        !matches!(self, TimerProfile::Parked)
    }

    /// The direct-upgrade prober's cadence floor.
    #[must_use]
    pub const fn upgrade_probe_floor(self) -> Option<Duration> {
        match self {
            TimerProfile::Foreground => Some(Duration::from_secs(1)),
            TimerProfile::Background => Some(T_UPGRADE_PROBE_BG.default),
            TimerProfile::Parked => None,
        }
    }

    /// Whether a standby relay may be reported **warm**.
    ///
    /// §8.1 and §11.2: "A standby whose keepalive has been stopped is **not warm
    /// and MUST NOT be reported as one**." The failover posture on parked mobile
    /// is genuinely weaker, and saying so is the point.
    #[must_use]
    pub const fn standby_may_be_warm(self) -> bool {
        !matches!(self, TimerProfile::Parked)
    }
}
