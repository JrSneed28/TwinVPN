//! Lifecycle **facts** the OS hands the provider: stop reasons, sleep/wake gaps,
//! the memory-shed ladder, thermal posture, and the app-liveness lease.
//!
//! **Authority:** ADR-0022 §11.1, LC-4, LC-8, LC-14, LC-15, LC-17, LC-18,
//! LC-23a, LC-23b, LC-24, LC-31, LC-32; ADR-0018 PB-6 and §11.9 row 1;
//! ADR-0016 §11.2's iOS process table; ADR-0018 CB-2.
//!
//! # What is here and what is deliberately not
//!
//! ADR-0022 LC-18 is exact: "OS termination produces no `ConnectionState`
//! transition — it produces a journal fact → `reason_code` on next start." So
//! this module produces **facts**. There is no `ConnectionState`, no
//! `HostLifecycleState`, no `absence_cause` and no timer profile in this file:
//! those are the core's, and CB-2 keeps them there.
//!
//! What the adapter *can* say is what the OS said and what the arithmetic over it
//! yields — the stop reason and whether the OS classifies it as user-initiated,
//! the measured suspension gap on the suspend-**inclusive** clock, whether RSS
//! has crossed a published threshold, and whether the app-liveness lease has
//! expired. Each is a mechanism; the response to each is a decision the core
//! makes.
//!
//! # A registry gap this module runs into, reported rather than patched
//!
//! ADR-0022 names a `PLATFORM.LIFECYCLE.*` family throughout — `REHYDRATED`,
//! `MEMORY_BUDGET_EXCEEDED`, `KEY_UNAVAILABLE_PRE_UNLOCK`, `ONDEMAND_RULES_ABSENT`,
//! `REHYDRATE_INCOMPLETE`, `REHYDRATE_TIMEOUT`, `LOW_POWER_PROFILE`,
//! `HIBERNATE_RESUMED`, `CRASH_REPORT_SUPPRESSED` — and
//! **not one of them exists in `contracts/registry/reason_codes.json`**. The ten
//! registered `PLATFORM.*` codes carry no `LIFECYCLE` subdomain at all. Nothing
//! here invents one. Where a registered code genuinely owns the condition it is
//! used ([`crate::posture`] maps them); where none does, the fact is reported as
//! a declared posture value and the gap is in the crate README and the domain's
//! final report.

/// ADR-0018 §11.9 row 1 and PB-6: the core's own RSS share, in bytes.
pub const CORE_RSS_SHARE_BYTES: u64 = 9 * 1024 * 1024;
/// ADR-0022 LC-17 and LC-31: shed bounded caches at this provider-wide RSS.
pub const PROVIDER_SHED_THRESHOLD_BYTES: u64 = 10 * 1024 * 1024;
/// ADR-0022 LC-17: the provider-wide engineering budget.
pub const PROVIDER_BUDGET_BYTES: u64 = 12 * 1024 * 1024;
/// ADR-0022 §9: the observed, unguaranteed platform ceiling. The design "MUST
/// NOT assume" it exceeds this.
pub const PROVIDER_CEILING_BYTES: u64 = 15 * 1024 * 1024;
/// ADR-0018 §14 condition 2: the core's revisit trigger, at p95.
pub const CORE_REVISIT_TRIGGER_BYTES: u64 = 8 * 1024 * 1024;
/// ADR-0018 §11.9 row 1: the stripped `staticlib` ceiling, on disk.
pub const STATICLIB_CEILING_BYTES: u64 = 12 * 1024 * 1024;

// The ladder's ordering is a compile-time fact, not a runtime one: a build in
// which the shed threshold sat above the budget, or the core's share above the
// provider's, would be a build whose memory policy contradicts ADR-0022 LC-17
// and ADR-0018 PB-6 — and it must not link, let alone run.
const _: () = assert!(CORE_REVISIT_TRIGGER_BYTES < CORE_RSS_SHARE_BYTES);
const _: () = assert!(CORE_RSS_SHARE_BYTES < PROVIDER_SHED_THRESHOLD_BYTES);
const _: () = assert!(PROVIDER_SHED_THRESHOLD_BYTES < PROVIDER_BUDGET_BYTES);
const _: () = assert!(PROVIDER_BUDGET_BYTES < PROVIDER_CEILING_BYTES);
// PB-6: "The 3 MB that remains at 9 MB is deliberate and is the shell's to spend."
const _: () = assert!(PROVIDER_BUDGET_BYTES - CORE_RSS_SHARE_BYTES == 3 * 1024 * 1024);

/// `NEProviderStopReason`, as the OS delivers it to `stopTunnelWithReason:`.
///
/// A translation of the platform enum and nothing more. ADR-0022 §11.4's iOS row
/// says to "map stop reason onto `absence_cause`" and to "set `clean_shutdown`
/// only for user/policy reasons" — the mapping's *destination* is a domain enum
/// the seam does not carry, so this type reports the reason and the OS's own
/// classification of it, and the core does the mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProviderStopReason {
    /// `NEProviderStopReasonNone`.
    None,
    /// `NEProviderStopReasonUserInitiated`.
    UserInitiated,
    /// `NEProviderStopReasonProviderFailed`.
    ProviderFailed,
    /// `NEProviderStopReasonNoNetworkAvailable`.
    NoNetworkAvailable,
    /// `NEProviderStopReasonUnrecoverableNetworkChange`.
    UnrecoverableNetworkChange,
    /// `NEProviderStopReasonProviderDisabled`.
    ProviderDisabled,
    /// `NEProviderStopReasonAuthenticationCanceled`.
    AuthenticationCanceled,
    /// `NEProviderStopReasonConfigurationFailed`.
    ConfigurationFailed,
    /// `NEProviderStopReasonIdleTimeout`.
    IdleTimeout,
    /// `NEProviderStopReasonConfigurationDisabled`.
    ConfigurationDisabled,
    /// `NEProviderStopReasonConfigurationRemoved`.
    ConfigurationRemoved,
    /// `NEProviderStopReasonSuperceded`.
    Superseded,
    /// `NEProviderStopReasonUserLogout`.
    UserLogout,
    /// `NEProviderStopReasonUserSwitch`.
    UserSwitch,
    /// `NEProviderStopReasonConnectionFailed`.
    ConnectionFailed,
    /// `NEProviderStopReasonSleep`.
    Sleep,
    /// `NEProviderStopReasonAppUpdate`.
    AppUpdate,
    /// A raw value this build does not know.
    ///
    /// Carried rather than coerced: a future SDK value mapped onto `None` would
    /// make an unknown stop indistinguishable from an orderly one, and
    /// `clean_shutdown` would be set for a reason nobody understood.
    Unknown(i32),
}

impl ProviderStopReason {
    /// Decodes the raw `NEProviderStopReason`.
    #[must_use]
    pub const fn from_raw(raw: i32) -> Self {
        match raw {
            0 => ProviderStopReason::None,
            1 => ProviderStopReason::UserInitiated,
            2 => ProviderStopReason::ProviderFailed,
            3 => ProviderStopReason::NoNetworkAvailable,
            4 => ProviderStopReason::UnrecoverableNetworkChange,
            5 => ProviderStopReason::ProviderDisabled,
            6 => ProviderStopReason::AuthenticationCanceled,
            7 => ProviderStopReason::ConfigurationFailed,
            8 => ProviderStopReason::IdleTimeout,
            9 => ProviderStopReason::ConfigurationDisabled,
            10 => ProviderStopReason::ConfigurationRemoved,
            11 => ProviderStopReason::Superseded,
            12 => ProviderStopReason::UserLogout,
            13 => ProviderStopReason::UserSwitch,
            14 => ProviderStopReason::ConnectionFailed,
            15 => ProviderStopReason::Sleep,
            16 => ProviderStopReason::AppUpdate,
            other => ProviderStopReason::Unknown(other),
        }
    }

    /// Whether the OS attributes this stop to the user or to policy.
    ///
    /// This is a property of Apple's enum, not a TwinVPN judgement: the cases
    /// below are the ones whose *names* attribute the stop to a person or to a
    /// configuration change. ADR-0022 §11.4 conditions `clean_shutdown` on it,
    /// and that conditioning is the **core's**.
    ///
    /// [`ProviderStopReason::Unknown`] is **not** in the set. A stop this build
    /// cannot name is not evidence of an orderly one.
    #[must_use]
    pub const fn os_attributes_to_user_or_policy(self) -> bool {
        matches!(
            self,
            ProviderStopReason::UserInitiated
                | ProviderStopReason::ProviderDisabled
                | ProviderStopReason::ConfigurationDisabled
                | ProviderStopReason::ConfigurationRemoved
                | ProviderStopReason::UserLogout
                | ProviderStopReason::UserSwitch
                | ProviderStopReason::AppUpdate
                | ProviderStopReason::Superseded
        )
    }

    /// Whether this stop means the VPN profile is gone or switched off.
    ///
    /// ADR-0012's durability table gives iOS `✘` for "uninstall/update — profile
    /// removal removes enforcement", and ADR-0019's permission lifecycle needs to
    /// distinguish "the user turned it off" from "the tunnel failed".
    #[must_use]
    pub const fn is_profile_withdrawn(self) -> bool {
        matches!(
            self,
            ProviderStopReason::ConfigurationRemoved
                | ProviderStopReason::ConfigurationDisabled
                | ProviderStopReason::ProviderDisabled
        )
    }

    /// A stable, non-localised tag for a diagnostic.
    ///
    /// Never user-facing text: CB-4 keeps every rendered string out of the core,
    /// so this is a name a support case greps for.
    #[must_use]
    pub fn as_tag(self) -> String {
        match self {
            ProviderStopReason::None => "none".to_owned(),
            ProviderStopReason::UserInitiated => "user_initiated".to_owned(),
            ProviderStopReason::ProviderFailed => "provider_failed".to_owned(),
            ProviderStopReason::NoNetworkAvailable => "no_network_available".to_owned(),
            ProviderStopReason::UnrecoverableNetworkChange => {
                "unrecoverable_network_change".to_owned()
            }
            ProviderStopReason::ProviderDisabled => "provider_disabled".to_owned(),
            ProviderStopReason::AuthenticationCanceled => "authentication_canceled".to_owned(),
            ProviderStopReason::ConfigurationFailed => "configuration_failed".to_owned(),
            ProviderStopReason::IdleTimeout => "idle_timeout".to_owned(),
            ProviderStopReason::ConfigurationDisabled => "configuration_disabled".to_owned(),
            ProviderStopReason::ConfigurationRemoved => "configuration_removed".to_owned(),
            ProviderStopReason::Superseded => "superseded".to_owned(),
            ProviderStopReason::UserLogout => "user_logout".to_owned(),
            ProviderStopReason::UserSwitch => "user_switch".to_owned(),
            ProviderStopReason::ConnectionFailed => "connection_failed".to_owned(),
            ProviderStopReason::Sleep => "sleep".to_owned(),
            ProviderStopReason::AppUpdate => "app_update".to_owned(),
            ProviderStopReason::Unknown(raw) => format!("unknown_{raw}"),
        }
    }
}

/// What the memory ladder says about one RSS reading.
///
/// ADR-0022 LC-31 and LC-17, and ADR-0018 PB-6's table. The thresholds are the
/// ADRs'; the comparison is arithmetic; the response — shedding a cache,
/// emitting a code — is the core's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryPosture {
    /// The provider-wide RSS observed, in bytes.
    pub provider_rss_bytes: u64,
    /// Whether bounded caches should be shed (≥ 10 MB).
    pub shed_indicated: bool,
    /// Whether the provider-wide engineering budget is exceeded (> 12 MB).
    pub over_budget: bool,
    /// Whether the observed platform ceiling is exceeded (> 15 MB).
    ///
    /// Past this, jetsam is expected and arrives with **no notice** — ADR-0022
    /// §11.4's iOS row: "none (`SIGKILL`)". LC-7's write-ahead journal is what
    /// makes the next start a resume rather than a mystery.
    pub over_ceiling: bool,
}

impl MemoryPosture {
    /// Classifies one reading.
    #[must_use]
    pub const fn observe(provider_rss_bytes: u64) -> Self {
        Self {
            provider_rss_bytes,
            shed_indicated: provider_rss_bytes >= PROVIDER_SHED_THRESHOLD_BYTES,
            over_budget: provider_rss_bytes > PROVIDER_BUDGET_BYTES,
            over_ceiling: provider_rss_bytes > PROVIDER_CEILING_BYTES,
        }
    }
}

/// `ProcessInfo.thermalState`.
///
/// ADR-0022 LC-31 names it as a signal alongside `low_power` and `metered` from
/// `query_link_facts()`. It is a **process** signal, kept separate from
/// `NWPath.isConstrained`, which is a **path** signal: collapsing them would make
/// "the network is rationed" and "the device is hot" the same fact with the same
/// response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ThermalState {
    /// `NSProcessInfoThermalStateNominal`.
    Nominal,
    /// `NSProcessInfoThermalStateFair`.
    Fair,
    /// `NSProcessInfoThermalStateSerious`.
    Serious,
    /// `NSProcessInfoThermalStateCritical`.
    Critical,
}

impl ThermalState {
    /// Decodes the raw value. An unknown value decodes to the **most severe**
    /// state, not the least: a future case this build does not know is not
    /// evidence that the device is cool.
    #[must_use]
    pub const fn from_raw(raw: i32) -> Self {
        match raw {
            0 => ThermalState::Nominal,
            1 => ThermalState::Fair,
            2 => ThermalState::Serious,
            _ => ThermalState::Critical,
        }
    }

    /// Whether the OS is reporting thermal pressure at all.
    #[must_use]
    pub const fn is_pressured(self) -> bool {
        !matches!(self, ThermalState::Nominal)
    }
}

/// The app-liveness lease of ADR-0022 **LC-23b**.
///
/// > "foreground state alone is not observable there without the app" … "the
/// > authority runs **background profile by default**, enters foreground profile
/// > only while holding an unexpired `foreground_lease`".
///
/// The lease is what makes a dead app safe: it expires, the provider falls back
/// to the background profile, and — LC-23b again — "this is the battery-optimal
/// default, not degraded". Nothing correctness-bearing rides on it; LC-23b
/// classifies foreground state as *optimization-bearing* precisely so that
/// losing it costs nothing but battery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForegroundLease {
    /// When the app last renewed it, on the suspend-inclusive clock, in
    /// microseconds.
    pub renewed_us: u64,
    /// How long a renewal is good for, in milliseconds.
    pub ttl_ms: u64,
}

impl ForegroundLease {
    /// Whether the lease is still held at `now_us`.
    ///
    /// A reading that runs backwards — which a suspend across a boundary can
    /// produce if the wrong clock is read — reports **expired**. That is the
    /// safe direction: it falls back to the background profile, which LC-23b
    /// says is the default anyway.
    #[must_use]
    pub const fn is_held(self, now_us: u64) -> bool {
        if now_us < self.renewed_us {
            return false;
        }
        (now_us - self.renewed_us) / 1_000 < self.ttl_ms
    }
}

/// How a start relates to the previous one.
///
/// ADR-0022 LC-24 step 1: "classify: `boot_id` changed ⇒ **NOT** a resume, run
/// LC-4 as `COLD_START`; `boot_id` same, gap > 0 ⇒ suspend/hibernate resume; gap
/// from suspend-inclusive monotonic clock (LC-8)."
///
/// Deriving this is arithmetic over two boot identities and two clock readings.
/// What the core *does* with it — LC-4's eleven ordered steps, the ladder handed
/// to `docs/reliability.md` §11.3 — is the core's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartClassification {
    /// The device rebooted. This is not a resume at any gap.
    ColdStart,
    /// The same boot, with a measured gap.
    Resume {
        /// The gap, in milliseconds, on the suspend-inclusive clock.
        gap_ms: u64,
    },
}

/// Classifies a start from two boot identities and two elapsed readings.
///
/// The readings **must** come from [`crate::clock::ContinuousElapsedClock`].
/// ADR-0022 LC-8 records that "Darwin's `CLOCK_MONOTONIC` is suspend-inclusive,
/// **reverse of Linux's**" — so a developer transplanting the Linux reasoning
/// gets it backwards here, and a suspend-exclusive reading would measure every
/// suspension as zero. That is LC-8's "invisible on CI" failure exactly.
#[must_use]
pub fn classify_start(
    previous_boot_id: Option<[u8; 16]>,
    current_boot_id: [u8; 16],
    previous_us: u64,
    now_us: u64,
) -> StartClassification {
    match previous_boot_id {
        Some(previous) if previous == current_boot_id => StartClassification::Resume {
            gap_ms: now_us.saturating_sub(previous_us) / 1_000,
        },
        // No previous boot id recorded is a cold start, not a zero-gap resume: a
        // resume asserts continuity we have no evidence for.
        _ => StartClassification::ColdStart,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_stop_reason_is_carried_and_never_coerced_to_orderly() {
        let unknown = ProviderStopReason::from_raw(9_999);
        assert_eq!(unknown, ProviderStopReason::Unknown(9_999));
        assert!(
            !unknown.os_attributes_to_user_or_policy(),
            "a stop this build cannot name is not evidence of an orderly one, \
             and clean_shutdown must not be set for it"
        );
        assert_eq!(unknown.as_tag(), "unknown_9999");
        assert_ne!(unknown, ProviderStopReason::None);
    }

    #[test]
    fn a_user_or_policy_stop_is_distinguished_from_a_failure() {
        for reason in [
            ProviderStopReason::UserInitiated,
            ProviderStopReason::ConfigurationRemoved,
            ProviderStopReason::UserLogout,
            ProviderStopReason::AppUpdate,
        ] {
            assert!(reason.os_attributes_to_user_or_policy(), "{reason:?}");
        }
        for reason in [
            ProviderStopReason::ProviderFailed,
            ProviderStopReason::ConnectionFailed,
            ProviderStopReason::NoNetworkAvailable,
            ProviderStopReason::UnrecoverableNetworkChange,
            ProviderStopReason::ConfigurationFailed,
            ProviderStopReason::None,
        ] {
            assert!(!reason.os_attributes_to_user_or_policy(), "{reason:?}");
        }
    }

    #[test]
    fn profile_withdrawal_is_its_own_fact() {
        // ADR-0012's durability table: iOS gets ✘ for uninstall — "profile
        // removal removes enforcement". ADR-0019 renders that differently from a
        // tunnel failure, so the two must be distinguishable here.
        assert!(ProviderStopReason::ConfigurationRemoved.is_profile_withdrawn());
        assert!(ProviderStopReason::ConfigurationDisabled.is_profile_withdrawn());
        assert!(!ProviderStopReason::UserInitiated.is_profile_withdrawn());
        assert!(!ProviderStopReason::ProviderFailed.is_profile_withdrawn());
    }

    #[test]
    fn every_raw_stop_reason_round_trips_to_a_distinct_tag() {
        let mut tags = std::collections::BTreeSet::new();
        for raw in 0..=16 {
            assert!(tags.insert(ProviderStopReason::from_raw(raw).as_tag()));
        }
        assert_eq!(tags.len(), 17);
    }

    #[test]
    fn the_memory_ladder_matches_the_published_thresholds() {
        // ADR-0022 LC-17/LC-31 and ADR-0018 PB-6.
        let quiet = MemoryPosture::observe(6 * 1024 * 1024);
        assert!(!quiet.shed_indicated && !quiet.over_budget && !quiet.over_ceiling);

        let shed = MemoryPosture::observe(PROVIDER_SHED_THRESHOLD_BYTES);
        assert!(shed.shed_indicated, "shedding starts AT 10 MB, not past it");
        assert!(!shed.over_budget);

        let over = MemoryPosture::observe(PROVIDER_BUDGET_BYTES + 1);
        assert!(over.shed_indicated && over.over_budget && !over.over_ceiling);

        let doomed = MemoryPosture::observe(PROVIDER_CEILING_BYTES + 1);
        assert!(doomed.over_ceiling);
    }

    #[test]
    fn the_core_share_leaves_the_shell_the_three_megabytes_it_is_owed() {
        // ADR-0018 PB-6: "The 3 MB that remains at 9 MB is deliberate and is the
        // shell's to spend." The ladder's ordering is pinned at compile time by
        // the `const _: () = assert!(…)` block above this module's constants; this
        // test pins the two absolute figures §11.9 row 1 states.
        assert_eq!(CORE_RSS_SHARE_BYTES, 9 * 1024 * 1024);
        assert_eq!(STATICLIB_CEILING_BYTES, 12 * 1024 * 1024);
    }

    #[test]
    fn an_unknown_thermal_state_is_read_as_critical_and_not_as_nominal() {
        assert_eq!(ThermalState::from_raw(0), ThermalState::Nominal);
        assert_eq!(ThermalState::from_raw(3), ThermalState::Critical);
        // A future case this build does not know is not evidence the device is
        // cool. Rounding the other way would suppress LC-31's response exactly
        // when the OS is asking for it.
        assert_eq!(ThermalState::from_raw(99), ThermalState::Critical);
        assert!(!ThermalState::Nominal.is_pressured());
        assert!(ThermalState::Fair.is_pressured());
    }

    #[test]
    fn a_dead_app_loses_the_foreground_lease_and_that_is_the_default() {
        // LC-23b: the provider runs the background profile by default and enters
        // the foreground profile only under an unexpired lease. Losing the app
        // is the battery-optimal default, not a degradation.
        let lease = ForegroundLease {
            renewed_us: 10_000_000,
            ttl_ms: 5_000,
        };
        assert!(lease.is_held(10_000_000));
        assert!(lease.is_held(14_999_000));
        assert!(!lease.is_held(15_000_000));
        assert!(!lease.is_held(60_000_000), "a dead app renews nothing");
    }

    #[test]
    fn a_backwards_clock_reading_expires_the_lease_rather_than_extending_it() {
        let lease = ForegroundLease {
            renewed_us: 10_000_000,
            ttl_ms: 5_000,
        };
        assert!(!lease.is_held(1_000_000));
    }

    #[test]
    fn a_reboot_is_never_a_resume_at_any_gap() {
        // LC-24 step 1. A resume asserts continuity; a reboot destroyed it.
        let a = [1u8; 16];
        let b = [2u8; 16];
        assert_eq!(
            classify_start(Some(a), b, 0, 5_000_000),
            StartClassification::ColdStart
        );
        assert_eq!(
            classify_start(Some(a), a, 1_000_000, 5_000_000),
            StartClassification::Resume { gap_ms: 4_000 }
        );
        // No previous boot id is a cold start, not a zero-gap resume.
        assert_eq!(
            classify_start(None, a, 0, 5_000_000),
            StartClassification::ColdStart
        );
    }

    #[test]
    fn a_resume_gap_is_measured_and_a_backwards_pair_does_not_underflow() {
        let a = [7u8; 16];
        assert_eq!(
            classify_start(Some(a), a, 9_000_000, 1_000_000),
            StartClassification::Resume { gap_ms: 0 }
        );
    }
}
