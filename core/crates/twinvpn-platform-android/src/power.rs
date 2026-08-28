//! Doze, App Standby, battery saver, thermal — and the keepalive plan, which is
//! the place the objective's second prohibition is made structural.
//!
//! **Authority:** `docs/networking.md` §5.4's Android Doze row; ADR-0022
//! **LC-31**, **LC-32**, **LC-33**, and §11.4's Doze row;
//! `docs/implementation/ownership.md` §10.2's two prohibitions;
//! `docs/reliability.md` §6.6 and §11.2 (which own the cadence — this module
//! does not re-decide it).
//!
//! # The prohibition, made unsayable
//!
//! `ownership.md` §10.2(2):
//!
//! > Keepalives ride the tunnel socket's own kernel-side timer where the
//! > platform offers one, **never an app-side alarm cadence chosen to defeat
//! > Doze**.
//!
//! [`KeepalivePlan`] has exactly two variants and neither is an alarm. There is
//! no `AlarmManager` in this crate, no `setExactAndAllowWhileIdle`, and no
//! wake-lock anything — §10.2(1) forbids the latter outright. When
//! `SocketKeepalive` cannot serve the interval the core asked for, the answer is
//! [`KeepalivePlan::Unavailable`] carrying a **registered** reason code, so the
//! core learns the platform cannot do it and decides what to do. It is never an
//! invitation for the adapter to substitute a mechanism.
//!
//! That is the same shape as `SocketProvider::bind_udp`'s rule — an unsupported
//! family is *a fact about the host*, reported so the core can decide, and
//! substituting is how a v6-only network silently becomes v4-only.
//!
//! # Why the thermal and low-power signals are facts, not throttles
//!
//! LC-31 lists the application-layer responses to `low_power`, `metered` and
//! thermal pressure — every one of them a *core* decision (timer profile,
//! standby suppression, probe cadence). LC-32 then closes the list: no pressure
//! of any kind may disarm the kill switch, skip a rekey, or silently reduce
//! protection scope. So this module converts OS signals into
//! [`twinvpn_platform::NetworkChange::LinkPostureChanged`] and a declared
//! [`PowerSnapshot`], and applies nothing.

use core::time::Duration;

use twinvpn_types::{codes, ReasonCode};

/// `PowerManager.getCurrentThermalStatus()` (API 29+).
///
/// The raw ladder, kept whole. LC-31 acts at "serious or worse", and collapsing
/// the ladder to a boolean here would put that threshold in the adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[non_exhaustive]
pub enum ThermalStatus {
    /// `THERMAL_STATUS_NONE`, or an API level that does not report one.
    #[default]
    None,
    /// `THERMAL_STATUS_LIGHT`.
    Light,
    /// `THERMAL_STATUS_MODERATE`.
    Moderate,
    /// `THERMAL_STATUS_SEVERE`.
    Severe,
    /// `THERMAL_STATUS_CRITICAL`.
    Critical,
    /// `THERMAL_STATUS_EMERGENCY`.
    Emergency,
    /// `THERMAL_STATUS_SHUTDOWN`.
    Shutdown,
}

impl ThermalStatus {
    /// Decodes the platform integer.
    ///
    /// An unrecognised value maps to [`ThermalStatus::None`] rather than to a
    /// guessed severity: a future OEM value read as `Critical` would throttle a
    /// healthy device, and read as `None` it merely fails to throttle a hot one
    /// that the OS is already managing.
    #[must_use]
    pub const fn from_platform(value: i32) -> Self {
        match value {
            1 => ThermalStatus::Light,
            2 => ThermalStatus::Moderate,
            3 => ThermalStatus::Severe,
            4 => ThermalStatus::Critical,
            5 => ThermalStatus::Emergency,
            6 => ThermalStatus::Shutdown,
            _ => ThermalStatus::None,
        }
    }

    /// Whether LC-31's "serious or worse" threshold is met.
    ///
    /// Named for the row rather than for the value, so a reader can find the
    /// rule this predicate exists to serve.
    #[must_use]
    pub fn is_serious_or_worse(self) -> bool {
        self >= ThermalStatus::Severe
    }
}

/// What the OS says about power, as facts.
///
/// Every field is something a `PowerManager` or `ConnectivityManager` callback
/// reported. None of them is a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PowerSnapshot {
    /// `PowerManager.isDeviceIdleMode()` — Doze.
    pub device_idle: bool,
    /// `PowerManager.isPowerSaveMode()` — battery saver.
    pub power_save: bool,
    /// Whether the current default link is metered.
    pub metered: bool,
    /// The thermal ladder.
    pub thermal: ThermalStatus,
    /// The App Standby bucket, as `UsageStatsManager` reports it, or `None`
    /// below API 28.
    pub standby_bucket: Option<StandbyBucket>,
}

impl PowerSnapshot {
    /// The `low_power` fact [`twinvpn_platform::LinkFacts`] carries.
    ///
    /// Doze **or** battery saver. Both freeze or defer timers, and
    /// `docs/reliability.md` §11.1's background profile is the response to
    /// either; carrying them as one boolean at the seam is what
    /// [`twinvpn_platform::LinkFacts::low_power`] asks for, and both halves stay
    /// separately readable here for the diagnostic bundle.
    #[must_use]
    pub const fn low_power(&self) -> bool {
        self.device_idle || self.power_save
    }

    /// Whether this snapshot is one the OS considers deprioritised.
    ///
    /// ADR-0022 LC-1's `BACKGROUND` row names "Android App Standby bucket below
    /// `working_set`". Reported so the shell need not compute it; the core
    /// decides what `BACKGROUND` means.
    #[must_use]
    pub fn is_deprioritised(&self) -> bool {
        self.standby_bucket
            .is_some_and(|b| b < StandbyBucket::WorkingSet)
    }
}

/// `UsageStatsManager.getAppStandbyBucket()`.
///
/// Ordered from most to least active so `<` reads as "below", which is the
/// direction LC-1's row is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum StandbyBucket {
    /// `STANDBY_BUCKET_RESTRICTED` (45).
    Restricted,
    /// `STANDBY_BUCKET_RARE` (40).
    Rare,
    /// `STANDBY_BUCKET_FREQUENT` (30).
    Frequent,
    /// `STANDBY_BUCKET_WORKING_SET` (20).
    WorkingSet,
    /// `STANDBY_BUCKET_ACTIVE` (10).
    Active,
}

impl StandbyBucket {
    /// Decodes the platform integer, or `None` where it is not one of the five.
    #[must_use]
    pub const fn from_platform(value: i32) -> Option<Self> {
        match value {
            10 => Some(StandbyBucket::Active),
            20 => Some(StandbyBucket::WorkingSet),
            30 => Some(StandbyBucket::Frequent),
            40 => Some(StandbyBucket::Rare),
            45 => Some(StandbyBucket::Restricted),
            _ => None,
        }
    }
}

/// `SocketKeepalive`'s documented interval bounds, in seconds.
///
/// `ConnectivityManager.createSocketKeepalive` refuses anything outside
/// `[10, 3600]`. They are constants here so the refusal is a value this module
/// returns rather than an exception a device throws.
pub const KEEPALIVE_MIN_SECS: u32 = 10;
/// The upper bound. See [`KEEPALIVE_MIN_SECS`].
pub const KEEPALIVE_MAX_SECS: u32 = 3600;

/// How this device will keep a NAT binding alive.
///
/// **Two variants, and neither is an alarm.** See the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepalivePlan {
    /// `ConnectivityManager.createSocketKeepalive` on the tunnel socket itself.
    ///
    /// The kernel sends the packet; the app is not scheduled, so Doze cannot
    /// defer it and no wake lock is involved. This is `docs/networking.md`
    /// §5.4's "the tunnel socket's own kernel-side timer".
    KernelSocketKeepalive {
        /// The interval, within [`KEEPALIVE_MIN_SECS`]..=[`KEEPALIVE_MAX_SECS`].
        interval_secs: u32,
    },
    /// The platform cannot serve this request, with the reason as a registered
    /// code.
    ///
    /// **Not a fallback and not a licence to build one.** The core reads this and
    /// decides — it may shorten the session's idle horizon, prefer a relay, or
    /// accept the binding loss. What it must not be given is a mechanism the
    /// adapter invented.
    Unavailable {
        /// Why. A registered code, so it reaches the bundle as a code.
        reason: ReasonCode,
    },
}

impl KeepalivePlan {
    /// Whether this plan actually keeps anything alive.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, KeepalivePlan::KernelSocketKeepalive { .. })
    }
}

/// Plans a keepalive for `interval`, on a device that does or does not offer
/// `SocketKeepalive`.
///
/// `supported` is a **declared platform fact** the shell supplies from the API
/// level and the transport (`SocketKeepalive` is offered on cellular and Wi-Fi,
/// and not on every OEM build). It is a parameter rather than something this
/// function probes, because CD-2 forbids ambient discovery and because a probe
/// would be a device call inside a function that must run on this host.
///
/// The interval is **refused, never clamped**. A clamped keepalive is a NAT
/// binding that expires at a time nobody chose, and the failure it produces —
/// a silently dead path — is the one `docs/reliability.md` §6.4's bidirectional
/// detection exists to catch rather than to cause.
#[must_use]
pub fn keepalive_plan(supported: bool, interval: Duration) -> KeepalivePlan {
    if !supported {
        return KeepalivePlan::Unavailable {
            // The platform does not offer the mechanism at this API level or on
            // this transport. `PLATFORM.OS_UNSUPPORTED` is the registered code
            // for exactly that, and its `os_version` evidence field is the one
            // a support case needs.
            reason: codes::PLATFORM_OS_UNSUPPORTED,
        };
    }
    let secs = interval.as_secs();
    let Ok(secs) = u32::try_from(secs) else {
        return KeepalivePlan::Unavailable {
            reason: codes::PLATFORM_OS_UNSUPPORTED,
        };
    };
    if !(KEEPALIVE_MIN_SECS..=KEEPALIVE_MAX_SECS).contains(&secs) {
        return KeepalivePlan::Unavailable {
            reason: codes::PLATFORM_OS_UNSUPPORTED,
        };
    }
    KeepalivePlan::KernelSocketKeepalive {
        interval_secs: secs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §10.2(2), asserted structurally. If an `Alarm*` variant is ever added
    /// this match stops compiling.
    #[test]
    fn no_keepalive_plan_can_express_an_app_side_alarm() {
        for plan in [
            keepalive_plan(true, Duration::from_secs(25)),
            keepalive_plan(false, Duration::from_secs(25)),
        ] {
            match plan {
                KeepalivePlan::KernelSocketKeepalive { .. } | KeepalivePlan::Unavailable { .. } => {
                }
            }
        }
    }

    #[test]
    fn a_supported_interval_rides_the_kernel_timer() {
        assert_eq!(
            keepalive_plan(true, Duration::from_secs(25)),
            KeepalivePlan::KernelSocketKeepalive { interval_secs: 25 }
        );
        assert!(keepalive_plan(true, Duration::from_secs(25)).is_active());
    }

    #[test]
    fn an_out_of_range_interval_is_refused_and_never_clamped() {
        for interval in [
            Duration::from_secs(u64::from(KEEPALIVE_MIN_SECS) - 1),
            Duration::from_secs(u64::from(KEEPALIVE_MAX_SECS) + 1),
            Duration::from_secs(u64::from(u32::MAX) + 1),
            Duration::ZERO,
        ] {
            let plan = keepalive_plan(true, interval);
            assert!(
                matches!(plan, KeepalivePlan::Unavailable { .. }),
                "clamping {interval:?} would expire the binding at a time nobody chose"
            );
        }
        // The boundaries themselves ARE served.
        assert!(
            keepalive_plan(true, Duration::from_secs(u64::from(KEEPALIVE_MIN_SECS))).is_active()
        );
        assert!(
            keepalive_plan(true, Duration::from_secs(u64::from(KEEPALIVE_MAX_SECS))).is_active()
        );
    }

    #[test]
    fn an_unsupported_platform_reports_a_registered_code_not_a_substitute() {
        let plan = keepalive_plan(false, Duration::from_secs(25));
        let KeepalivePlan::Unavailable { reason } = plan else {
            panic!("must be unavailable");
        };
        assert!(twinvpn_types::ReasonCode::lookup(reason.as_str()).is_some());
        assert_eq!(reason.as_str(), "PLATFORM.OS_UNSUPPORTED");
    }

    #[test]
    fn doze_and_battery_saver_both_read_as_low_power_and_stay_separable() {
        let doze = PowerSnapshot {
            device_idle: true,
            ..PowerSnapshot::default()
        };
        let saver = PowerSnapshot {
            power_save: true,
            ..PowerSnapshot::default()
        };
        assert!(doze.low_power() && saver.low_power());
        assert!(!PowerSnapshot::default().low_power());
        // Separable, because "the device is dozing" and "the user turned battery
        // saver on" have different remediations.
        assert!(doze.device_idle && !doze.power_save);
        assert!(saver.power_save && !saver.device_idle);
    }

    #[test]
    fn the_thermal_ladder_is_kept_whole_and_lc31s_threshold_is_named() {
        assert_eq!(ThermalStatus::from_platform(3), ThermalStatus::Severe);
        assert!(ThermalStatus::Severe.is_serious_or_worse());
        assert!(ThermalStatus::Emergency.is_serious_or_worse());
        assert!(!ThermalStatus::Moderate.is_serious_or_worse());
        // An unknown OEM value fails SAFE: it does not throttle a healthy device.
        assert_eq!(ThermalStatus::from_platform(99), ThermalStatus::None);
        assert_eq!(ThermalStatus::from_platform(-1), ThermalStatus::None);
    }

    #[test]
    fn a_bucket_below_working_set_is_the_deprioritised_fact_lc1_names() {
        for (bucket, expected) in [
            (StandbyBucket::Active, false),
            (StandbyBucket::WorkingSet, false),
            (StandbyBucket::Frequent, true),
            (StandbyBucket::Rare, true),
            (StandbyBucket::Restricted, true),
        ] {
            let snapshot = PowerSnapshot {
                standby_bucket: Some(bucket),
                ..PowerSnapshot::default()
            };
            assert_eq!(snapshot.is_deprioritised(), expected, "{bucket:?}");
        }
        // Below API 28 there is no bucket, and "we do not know" is not
        // "deprioritised".
        assert!(!PowerSnapshot::default().is_deprioritised());
    }

    #[test]
    fn the_standby_bucket_decodes_the_five_platform_values_and_nothing_else() {
        assert_eq!(
            StandbyBucket::from_platform(10),
            Some(StandbyBucket::Active)
        );
        assert_eq!(
            StandbyBucket::from_platform(45),
            Some(StandbyBucket::Restricted)
        );
        assert_eq!(StandbyBucket::from_platform(0), None);
        assert_eq!(StandbyBucket::from_platform(50), None);
    }
}
