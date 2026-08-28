//! Sleep and wake: the service power events, turned into facts the core consumes.
//!
//! **Authority:** ADR-0022 LC-8 (the clock table and its finding F2), LC-23a
//! (the Windows `EV_SUSPEND`/`EV_RESUME` row), LC-24 (the resume sequence),
//! LC-25 (pre-sleep is a flush, never a teardown); ADR-0018 CB-2.
//!
//! # The rule this module exists to hold
//!
//! > A resume must not render a confident, stale green.
//!
//! `shells/windows` reported this from the opposite side to `desktop-macos`:
//! `SERVICE_CONTROL_POWEREVENT` carries `PBT_APMSUSPEND` and
//! `PBT_APMRESUMESUSPEND`, and the seam had nowhere to put the fact. It does now
//! ([`twinvpn_platform::NetworkChange::SystemResumed`]), and filling it is the
//! adapter's job rather than the service's: **the gap is a domain fact and CB-2
//! keeps the shell out of it.** The service's own `classify_power_event` decides
//! which *lifecycle signal* to raise, which is a different question; this decides
//! nothing at all.
//!
//! # The clock, and the trap LC-8 names
//!
//! The gap **must** be measured on `QueryInterruptTimePrecise` — the *biased*
//! interrupt time, which includes sleep. `QueryUnbiasedInterruptTimePrecise` is
//! the suspend-**exclusive** clock: "unbiased" means sleep is *excluded*, so it
//! reports an eight-hour sleep as zero. ADR-0022 LC-8 records that an earlier
//! draft of its own rule had these backwards, and that ADR-0017 MI-16(3) still
//! does. This module takes an [`ElapsedInstant`], which
//! [`crate::clock`] sources from the biased clock, and never reads one itself
//! (CD-2).
//!
//! # Modern Standby
//!
//! LC-23a is explicit: on Modern Standby neither `PBT_APMSUSPEND` nor its resume
//! fires, the process keeps running, and `EV_SUSPEND` **MUST NOT** be
//! synthesized there. Nothing here synthesizes one: a resume is reported only
//! when the OS delivered a resume message, and [`SuspendJournal::observe`]
//! ignores every code it does not know rather than guessing.

use twinvpn_env::{BootId, ElapsedInstant};
use twinvpn_platform::{NetworkChange, ResumeFacts};

/// `WM_POWERBROADCAST` / `SERVICE_CONTROL_POWEREVENT` event codes.
///
/// Written out rather than taken from `windows-sys`: these four numbers are the
/// whole of the surface that matters, and this module is compiled and tested on
/// a Linux host where the crate's `cfg(windows)` block does not resolve.
pub mod pbt {
    /// `PBT_APMSUSPEND` — the system is suspending. **S3/S4 only.**
    pub const APM_SUSPEND: u32 = 0x0004;
    /// `PBT_APMRESUMESUSPEND` — resumed from suspend, a user is present.
    pub const APM_RESUME_SUSPEND: u32 = 0x0007;
    /// `PBT_APMRESUMEAUTOMATIC` — resumed with no user present (a timer wake).
    pub const APM_RESUME_AUTOMATIC: u32 = 0x0012;
    /// `PBT_POWERSETTINGCHANGE` — a registered power setting changed. Not a
    /// suspend boundary, and deliberately not treated as one.
    pub const POWER_SETTING_CHANGE: u32 = 0x8013;
}

/// One power event, named.
///
/// A closed enum rather than a raw `u32`, so a caller cannot invent a transition
/// the OS never reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PowerEvent {
    /// `PBT_APMSUSPEND`.
    Suspend,
    /// `PBT_APMRESUMESUSPEND` — a user is present.
    ResumeWithUser,
    /// `PBT_APMRESUMEAUTOMATIC` — no user is present.
    ResumeAutomatic,
}

impl PowerEvent {
    /// The event a raw code names, or `None` for one this adapter does not react
    /// to.
    ///
    /// `PBT_POWERSETTINGCHANGE` is `None` on purpose: a display-off or a
    /// user-presence change is not a suspend, and LC-23a forbids synthesizing
    /// one from it.
    #[must_use]
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            pbt::APM_SUSPEND => Some(PowerEvent::Suspend),
            pbt::APM_RESUME_SUSPEND => Some(PowerEvent::ResumeWithUser),
            pbt::APM_RESUME_AUTOMATIC => Some(PowerEvent::ResumeAutomatic),
            _ => None,
        }
    }

    /// Whether this event ends a suspend.
    #[must_use]
    pub const fn is_resume(self) -> bool {
        matches!(
            self,
            PowerEvent::ResumeWithUser | PowerEvent::ResumeAutomatic
        )
    }
}

/// The suspend-boundary journal.
///
/// Holds the reading taken at `PBT_APMSUSPEND` so the resume can subtract it,
/// and a counter per boundary for the diagnostic bundle.
#[derive(Debug, Clone, Copy, Default)]
pub struct SuspendJournal {
    suspended_at: Option<ElapsedInstant>,
    suspends: u64,
    resumes: u64,
}

impl SuspendJournal {
    /// A journal that has seen nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            suspended_at: None,
            suspends: 0,
            resumes: 0,
        }
    }

    /// How many suspends this process has seen.
    #[must_use]
    pub const fn suspends(&self) -> u64 {
        self.suspends
    }

    /// How many resumes.
    #[must_use]
    pub const fn resumes(&self) -> u64 {
        self.resumes
    }

    /// The reading taken when the suspend was announced, if any.
    #[must_use]
    pub const fn suspended_at(&self) -> Option<ElapsedInstant> {
        self.suspended_at
    }

    /// Observes one event and reports the changes the core must see.
    ///
    /// | Event | Reported | Why |
    /// |---|---|---|
    /// | `Suspend` | `LinkPostureChanged { low_power: true }` | the one true fact before the stack stops. **No teardown** — LC-25: pre-sleep is a flush, and CB-6 puts the WFP filters in BFE's custody so a sleep cannot drop protection |
    /// | either resume | `EventsLost`, then `SystemResumed`, then `LinkPostureChanged { low_power: false }` | the change subscriptions were not drained while suspended, *and* wall time passed that no unbiased clock saw. Two facts |
    ///
    /// **`EventsLost` comes first and `SystemResumed` second, both before the
    /// posture.** A core that processed the posture change first would have a
    /// moment in which it believed a fresh, low-power-cleared, otherwise
    /// unchanged picture — the stale green.
    ///
    /// `now` must be the **biased** interrupt time. See the module docs.
    pub fn observe(
        &mut self,
        event: PowerEvent,
        now: Option<ElapsedInstant>,
        boot_id: Option<BootId>,
    ) -> Vec<NetworkChange> {
        match event {
            PowerEvent::Suspend => {
                self.suspends = self.suspends.saturating_add(1);
                self.suspended_at = now;
                vec![NetworkChange::LinkPostureChanged {
                    metered: false,
                    low_power: true,
                }]
            }
            PowerEvent::ResumeWithUser | PowerEvent::ResumeAutomatic => {
                self.resumes = self.resumes.saturating_add(1);
                let suspended_for = match (self.suspended_at.take(), now) {
                    (Some(went), Some(back)) => Some(back.duration_since(went)),
                    // A resume with no announced suspend behind it, or a caller
                    // with no clock. `None` means "we do not know how long",
                    // which is a different answer from `Some(ZERO)`.
                    _ => None,
                };
                vec![
                    // `NotifyIpInterfaceChange` and friends deliver into a
                    // callback that was not running; the count is not recoverable
                    // and a fabricated one would be worse than an honest absence.
                    NetworkChange::EventsLost { count: None },
                    NetworkChange::SystemResumed(ResumeFacts {
                        suspended_for,
                        boot_id,
                        // The SCM told us. Not inferred from a clock divergence.
                        announced_by_os: true,
                        // `PBT_APMRESUMESUSPEND` and `PBT_APMRESUMEAUTOMATIC`
                        // distinguish USER PRESENCE, not S3 from S4 — LC-23a's
                        // Windows row says exactly that — and nothing else the
                        // service receives names hibernation. So LC-24 step 5's
                        // `PLATFORM.LIFECYCLE.HIBERNATE_RESUMED` is not
                        // answerable here, and `None` says so rather than
                        // guessing `false`.
                        hibernated: None,
                    }),
                    NetworkChange::LinkPostureChanged {
                        metered: false,
                        low_power: false,
                    },
                ]
            }
        }
    }

    /// The same, from a raw `SERVICE_CONTROL_POWEREVENT` code.
    ///
    /// An unrecognised code reports **nothing**: LC-23a forbids synthesizing
    /// `EV_SUSPEND` on Modern Standby, where the process keeps running and
    /// parking it would be a lie.
    pub fn observe_code(
        &mut self,
        code: u32,
        now: Option<ElapsedInstant>,
        boot_id: Option<BootId>,
    ) -> Vec<NetworkChange> {
        match PowerEvent::from_code(code) {
            Some(event) => self.observe(event, now, boot_id),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;

    #[test]
    fn the_pbt_codes_are_the_documented_values() {
        // Written out rather than depended on, so a typo is visible in one place.
        assert_eq!(pbt::APM_SUSPEND, 4);
        assert_eq!(pbt::APM_RESUME_SUSPEND, 7);
        assert_eq!(pbt::APM_RESUME_AUTOMATIC, 0x12);
    }

    #[test]
    fn a_power_setting_change_is_not_a_suspend_boundary() {
        // LC-23a: on Modern Standby neither PBT_APMSUSPEND nor its resume fires,
        // and `EV_SUSPEND` MUST NOT be synthesized there — the process keeps
        // running, so parking it would be a lie.
        assert_eq!(PowerEvent::from_code(pbt::POWER_SETTING_CHANGE), None);
        let mut journal = SuspendJournal::new();
        assert!(journal
            .observe_code(pbt::POWER_SETTING_CHANGE, None, None)
            .is_empty());
        assert_eq!(journal.suspends(), 0);
        assert_eq!(journal.resumes(), 0);
    }

    #[test]
    fn a_resume_reports_the_hole_then_the_gap_then_the_posture() {
        let mut journal = SuspendJournal::new();
        let asleep_at = ElapsedInstant::from_micros(2_000_000);
        let awake_at = asleep_at.saturating_add(Duration::from_secs(9 * 3600));

        let down = journal.observe_code(pbt::APM_SUSPEND, Some(asleep_at), None);
        assert_eq!(
            down,
            vec![NetworkChange::LinkPostureChanged {
                metered: false,
                low_power: true,
            }],
            "a suspend tears nothing down: BFE holds the filters"
        );

        let boot = BootId::from_array([3u8; 16]);
        let up = journal.observe_code(pbt::APM_RESUME_SUSPEND, Some(awake_at), Some(boot));
        assert_eq!(up[0], NetworkChange::EventsLost { count: None });
        let NetworkChange::SystemResumed(facts) = up[1] else {
            panic!("a resume reports the gap");
        };
        assert_eq!(facts.suspended_for, Some(Duration::from_secs(9 * 3600)));
        assert_eq!(facts.boot_id, Some(boot));
        assert!(facts.announced_by_os);
        assert_eq!(
            facts.hibernated, None,
            "the resume codes distinguish user presence, not S3 from S4"
        );
        assert_eq!(
            up[2],
            NetworkChange::LinkPostureChanged {
                metered: false,
                low_power: false,
            }
        );
    }

    #[test]
    fn both_resume_codes_report_the_same_gap() {
        // `PBT_APMRESUMEAUTOMATIC` and `PBT_APMRESUMESUSPEND` differ in whether a
        // user is present, which is a lifecycle question and not a clock one.
        for code in [pbt::APM_RESUME_AUTOMATIC, pbt::APM_RESUME_SUSPEND] {
            let mut journal = SuspendJournal::new();
            let at = ElapsedInstant::from_micros(1);
            journal.observe_code(pbt::APM_SUSPEND, Some(at), None);
            let up = journal.observe_code(
                code,
                Some(at.saturating_add(Duration::from_secs(120))),
                None,
            );
            let NetworkChange::SystemResumed(facts) = up[1] else {
                panic!("resume");
            };
            assert_eq!(facts.suspended_for, Some(Duration::from_secs(120)));
        }
    }

    #[test]
    fn an_unmeasurable_gap_is_none_and_never_zero() {
        // A service that started while the machine was already suspending has no
        // reading to subtract. Reporting zero would tell the core no time had
        // passed, which is the confident stale green.
        let mut journal = SuspendJournal::new();
        let up = journal.observe_code(
            pbt::APM_RESUME_AUTOMATIC,
            Some(ElapsedInstant::from_micros(9_000_000)),
            None,
        );
        let NetworkChange::SystemResumed(facts) = up[1] else {
            panic!("resume");
        };
        assert_eq!(facts.suspended_for, None);
        assert_ne!(facts.suspended_for, Some(Duration::ZERO));
    }

    #[test]
    fn the_measurement_is_consumed_by_the_resume_that_reports_it() {
        let mut journal = SuspendJournal::new();
        let at = ElapsedInstant::from_micros(1_000);
        journal.observe_code(pbt::APM_SUSPEND, Some(at), None);
        journal.observe_code(
            pbt::APM_RESUME_SUSPEND,
            Some(at.saturating_add(Duration::from_secs(60))),
            None,
        );
        let again = journal.observe_code(
            pbt::APM_RESUME_SUSPEND,
            Some(at.saturating_add(Duration::from_secs(600))),
            None,
        );
        let NetworkChange::SystemResumed(facts) = again[1] else {
            panic!("resume");
        };
        assert_eq!(facts.suspended_for, None);
        assert_eq!(journal.suspends(), 1);
        assert_eq!(journal.resumes(), 2);
    }
}
