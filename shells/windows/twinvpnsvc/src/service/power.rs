//! Sleep, wake, and the rule that a resume may not paint a confident green.
//!
//! **Authority:** [ADR-0022](../../../../../docs/adr/ADR-0022-application-lifecycle-and-background-execution.md)
//! §11.6's Windows row, LC-8 (the three clocks), LC-16, LC-18, LC-22, LC-23a,
//! LC-23b, LC-24 (the resume sequence), LC-32; ADR-0015 O-17 and O-18;
//! ADR-0012 K12.
//!
//! # §11.6's Windows row, and the two suspends that are not the same
//!
//! > service `SERVICE_CONTROL_POWEREVENT` with `PBT_APMSUSPEND` (S3/S4 only);
//! > on **Modern Standby** there is no suspend event at all —
//! > `PowerSettingRegisterNotification` for `GUID_CONSOLE_DISPLAY_STATE`,
//! > `GUID_SESSION_USER_PRESENCE`, `GUID_ACDC_POWER_SOURCE`,
//! > `GUID_BATTERY_PERCENTAGE_REMAINING`, `GUID_LIDSWITCH_STATE_CHANGE` is the
//! > only signal.
//!
//! LC-23a states the consequence as a rule: on Modern Standby `EV_SUSPEND`
//! **MUST NOT be synthesized**, "the process keeps running so parking it would
//! be a lie". [`classify_power_event`] therefore maps display-off plus no user
//! presence to [`LifecycleSignal::Background`] and never to a suspend, and
//! `a_modern_standby_display_off_is_never_reported_as_a_suspend` is the
//! assertion.
//!
//! # LC-24's ordering, and why step 2 precedes step 3
//!
//! ```text
//! resume ─► 1. classify: boot_id changed ⇒ NOT a resume, run LC-4 as COLD_START
//!                        same boot_id, gap > 0 ⇒ resume, gap from the
//!                        SUSPEND-INCLUSIVE clock (LC-8), not the wall clock
//!        ─► 2. query the enforcement layer for BOTH families and verify;
//!              re-assert RULESET_BLOCKED on any mismatch
//!              ───── no packet may be emitted before this line ─────
//!        ─► 3. re-acquire OS objects that do not survive: sockets, interface
//!              handles, change subscriptions, power registrations
//!        ─► 4. hand off to the wake ladder
//!        ─► 5. emit PLATFORM.RESUMED with the measured gap
//! ```
//!
//! The ADR restates step 2's position because "on desktop platforms the resume
//! path is written by the shell and the temptation to re-open sockets first is
//! strong". [`ResumeSequence`] is that ordering as a value, and
//! [`ResumeSequence::may_emit_a_packet`] is where the line lives.
//!
//! # LC-22: no confident stale green
//!
//! > the daemon restarted while the UI was away, the UI reconnects and paints
//! > its cached "Connected" for the 200 ms before the first event arrives, and
//! > the user acts on a screen that was true two minutes ago.
//!
//! [`ProtectionIndicator::resumed`] takes `self` **by value** and returns
//! [`ProtectionIndicator::Unknown`]. There is no path from a remembered
//! assertion to a post-resume one, because the remembered value is consumed and
//! dropped. That is O-18's "assertions expire ⇒ `UNKNOWN`, never `PROTECTED`"
//! made structural rather than disciplinary.
//!
//! # CB-2
//!
//! Nothing here decides what a resume *means*. This module classifies an OS
//! event into an OS fact, orders the steps the ADR orders, and hands the core a
//! gap and a fresh assertion. Whether a gap crosses a rekey window, whether the
//! session survives, whether to re-probe a path — all of that is the core's.

/// A power event as the SCM delivers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerEvent {
    /// `PBT_APMSUSPEND`. **S3/S4 only.**
    Suspend,
    /// `PBT_APMRESUMEAUTOMATIC` — the machine woke with no user present.
    ResumeAutomatic,
    /// `PBT_APMRESUMESUSPEND` — the machine woke and a user is present.
    ResumeSuspend,
    /// `GUID_CONSOLE_DISPLAY_STATE` went to off.
    DisplayOff,
    /// `GUID_CONSOLE_DISPLAY_STATE` went to on.
    DisplayOn,
    /// `GUID_SESSION_USER_PRESENCE` reports a user present.
    UserPresent,
    /// `GUID_SESSION_USER_PRESENCE` reports a user absent.
    UserAbsent,
    /// `GUID_ACDC_POWER_SOURCE` changed.
    PowerSourceChanged,
    /// `GUID_LIDSWITCH_STATE_CHANGE` changed.
    LidStateChanged,
}

/// What the host's display and user-presence signals currently say.
///
/// Carried as a value because LC-23a's synthesis needs **both**: display-off
/// alone is a screen saver, and no-user-presence alone is a locked but lit
/// screen. Only the conjunction is the Modern Standby background state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PresencePosture {
    /// Whether the console display is on.
    pub display_on: bool,
    /// Whether a user is present.
    pub user_present: bool,
}

/// The lifecycle signal an event produces, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleSignal {
    /// `EV_SUSPEND`. **Only from `PBT_APMSUSPEND`.**
    Suspend,
    /// `EV_RESUME`, and whether a user was present at the wake.
    Resume {
        /// `true` for `PBT_APMRESUMESUSPEND`.
        user_present: bool,
    },
    /// `EV_BACKGROUND`, synthesised per LC-23a.
    Background,
    /// `EV_FOREGROUND`, synthesised per LC-23a.
    Foreground,
    /// A signal the core reads for the power profile and nothing else.
    PostureChanged,
}

/// Maps an OS event and the current presence posture onto a lifecycle signal.
///
/// # Errors in the other direction are the ones that matter
///
/// A missed suspend costs a stale timer. A **fabricated** suspend parks a live
/// session on a machine that never slept, which LC-23a calls "a lie". So this
/// function synthesises `Background` freely and `Suspend` never.
#[must_use]
pub fn classify_power_event(event: PowerEvent, posture: PresencePosture) -> LifecycleSignal {
    match event {
        // The only source of a suspend. S3/S4 only; on Modern Standby it never
        // arrives, and nothing below manufactures one.
        PowerEvent::Suspend => LifecycleSignal::Suspend,
        PowerEvent::ResumeAutomatic => LifecycleSignal::Resume {
            user_present: false,
        },
        PowerEvent::ResumeSuspend => LifecycleSignal::Resume { user_present: true },
        // LC-23a's synthesis: display-off AND no user presence, together.
        PowerEvent::DisplayOff | PowerEvent::UserAbsent => {
            if posture.display_on || posture.user_present {
                LifecycleSignal::PostureChanged
            } else {
                LifecycleSignal::Background
            }
        }
        PowerEvent::DisplayOn | PowerEvent::UserPresent => LifecycleSignal::Foreground,
        // LC-31: metering and power source are signals the core consumes for
        // the profile. They are not lifecycle transitions.
        PowerEvent::PowerSourceChanged | PowerEvent::LidStateChanged => {
            LifecycleSignal::PostureChanged
        }
    }
}

/// Applies an event to the presence posture.
///
/// Separated from [`classify_power_event`] so the classification reads the
/// posture **as it was before** the event: LC-23a's conjunction is about the
/// state the host is entering, and folding the update into the classification
/// would make a display-off event that arrives while a user is present
/// indistinguishable from one that arrives while they are absent.
#[must_use]
pub const fn apply(posture: PresencePosture, event: PowerEvent) -> PresencePosture {
    match event {
        PowerEvent::DisplayOff => PresencePosture {
            display_on: false,
            ..posture
        },
        PowerEvent::DisplayOn => PresencePosture {
            display_on: true,
            ..posture
        },
        PowerEvent::UserPresent => PresencePosture {
            user_present: true,
            ..posture
        },
        PowerEvent::UserAbsent => PresencePosture {
            user_present: false,
            ..posture
        },
        _ => posture,
    }
}

/// LC-24 step 1: is this a resume, or is it a different boot?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeClassification {
    /// The boot identity changed. **Not a resume**: run LC-4 as a cold start.
    ///
    /// LC-24 puts this first because no clock can answer it — a monotonic gap
    /// and a reboot look identical, and the boot identity is the third
    /// discriminator that separates them.
    ColdStart,
    /// The same boot, with a measured gap.
    Resume {
        /// The gap, in microseconds, **on the suspend-inclusive clock**.
        ///
        /// LC-8: `ElapsedClock`, never `MonotonicClock` — the monotonic one is
        /// paused across the suspend and would measure the gap as zero, which is
        /// the defect that is invisible on a machine that never sleeps.
        gap_micros: u64,
    },
}

/// Classifies a wake.
///
/// Takes the two readings rather than a clock, so the classification is a pure
/// function and CD-2's injection happens one level up.
#[must_use]
pub fn classify_wake(
    boot_id_before: [u8; 16],
    boot_id_now: [u8; 16],
    elapsed_before_micros: u64,
    elapsed_now_micros: u64,
) -> WakeClassification {
    if boot_id_before != boot_id_now {
        return WakeClassification::ColdStart;
    }
    WakeClassification::Resume {
        // Saturating rather than wrapping: a clock that went backwards within
        // one boot is a platform fault, and a gap of zero is the reading that
        // expires nothing early. `ElapsedInstant`'s own arithmetic saturates for
        // the same reason.
        gap_micros: elapsed_now_micros.saturating_sub(elapsed_before_micros),
    }
}

/// LC-24's five steps, as a value.
// Four booleans, and each is a distinct step LC-24 orders. Collapsing them into
// a bitflags type would make "how far did the resume get" a number a reader has
// to decode, and `may_emit_a_packet`'s line — which falls between steps 2 and 3
// — is exactly the distinction that would be lost.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResumeSequence {
    /// (1) The wake was classified.
    pub classified: bool,
    /// (2) The enforcement layer was queried for **both** families and
    /// re-asserted where it disagreed.
    pub enforcement_verified: bool,
    /// (3) The OS objects that do not survive a suspend were re-acquired.
    pub objects_reacquired: bool,
    /// (4) The wake ladder was handed the resume.
    pub ladder_handed_off: bool,
}

impl ResumeSequence {
    /// Whether a packet may be emitted yet.
    ///
    /// LC-24 draws the line immediately after step 2. Step 3 re-opens sockets,
    /// which is why the ADR restates the ordering: a socket re-opened before the
    /// filters were verified could carry a packet on a host whose enforcement
    /// state nobody has checked since before the suspend.
    #[must_use]
    pub const fn may_emit_a_packet(&self) -> bool {
        self.classified && self.enforcement_verified
    }

    /// Whether the sequence completed.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.classified
            && self.enforcement_verified
            && self.objects_reacquired
            && self.ladder_handed_off
    }

    /// The next step to perform, by name.
    #[must_use]
    pub const fn next_step(&self) -> Option<&'static str> {
        if !self.classified {
            Some("classify the wake")
        } else if !self.enforcement_verified {
            Some("query and re-assert enforcement, both families")
        } else if !self.objects_reacquired {
            Some("re-acquire sockets, interface handles and subscriptions")
        } else if !self.ladder_handed_off {
            Some("hand off to the wake ladder")
        } else {
            None
        }
    }
}

/// What the service publishes as the protection indicator.
///
/// **LC-22 and O-18, made structural.** There is no constructor that turns a
/// remembered value into a current one, and [`Self::resumed`] consumes whatever
/// it was handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionIndicator {
    /// No fresh assertion. The only state a resume can produce.
    Unknown,
    /// A fresh assertion, with the reading it was taken at.
    Asserted {
        /// Whether the engine holds a fail-closed posture in both families.
        fail_closed: bool,
        /// Whether it holds `PROTECTED` in both families and matching intent.
        protected: bool,
        /// When it was taken, on the **suspend-inclusive** clock.
        ///
        /// MI-16 stamps `as_of_ms` from the same clock, and for the same reason:
        /// a value computed before an eight-hour suspend must not read as
        /// zero milliseconds old.
        at_elapsed_micros: u64,
    },
}

impl ProtectionIndicator {
    /// The state after a resume. **Always [`Self::Unknown`].**
    ///
    /// Consuming `self` is the mechanism: there is no way to write a resume
    /// path that carries the old value forward, because the old value is gone.
    #[must_use]
    pub const fn resumed(self) -> Self {
        Self::Unknown
    }

    /// The state after a fresh query.
    ///
    /// The only constructor for [`Self::Asserted`], and it takes the reading —
    /// so an assertion always carries the time it was taken and can always be
    /// aged.
    #[must_use]
    pub const fn renew(fail_closed: bool, protected: bool, at_elapsed_micros: u64) -> Self {
        Self::Asserted {
            fail_closed,
            protected,
            at_elapsed_micros,
        }
    }

    /// Whether this may be rendered as protecting the host.
    ///
    /// `false` for [`Self::Unknown`], which is O-18's whole point.
    #[must_use]
    pub const fn is_protected(&self) -> bool {
        matches!(self, Self::Asserted { protected: true, .. })
    }

    /// Whether the assertion has aged out of its freshness window.
    ///
    /// O-18: "assertions expire; staleness → `UNKNOWN`, never `PROTECTED`". The
    /// window itself is the core's — a shell that chose one would be setting a
    /// deadline outside CD-1's reach — so it arrives as a parameter.
    #[must_use]
    pub const fn is_stale(&self, now_elapsed_micros: u64, window_micros: u64) -> bool {
        match self {
            Self::Unknown => true,
            Self::Asserted {
                at_elapsed_micros, ..
            } => now_elapsed_micros.saturating_sub(*at_elapsed_micros) > window_micros,
        }
    }

    /// The indicator as it should be rendered, given the time.
    ///
    /// A stale assertion becomes [`Self::Unknown`] rather than staying green.
    #[must_use]
    pub const fn aged(self, now_elapsed_micros: u64, window_micros: u64) -> Self {
        if self.is_stale(now_elapsed_micros, window_micros) {
            Self::Unknown
        } else {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ASLEEP: PresencePosture = PresencePosture {
        display_on: false,
        user_present: false,
    };
    const AWAKE: PresencePosture = PresencePosture {
        display_on: true,
        user_present: true,
    };

    #[test]
    fn a_modern_standby_display_off_is_never_reported_as_a_suspend() {
        // LC-23a: on Modern Standby neither PBT_APMSUSPEND nor its resume
        // fires, and "EV_SUSPEND MUST NOT be synthesized there — the process
        // keeps running so parking it would be a lie".
        let posture = apply(AWAKE, PowerEvent::UserAbsent);
        let signal = classify_power_event(PowerEvent::DisplayOff, posture);
        assert_ne!(signal, LifecycleSignal::Suspend);
    }

    #[test]
    fn display_off_with_no_user_present_is_the_background_state() {
        // Both halves, together. Display-off alone is a screen saver;
        // no-presence alone is a locked but lit screen.
        let dark = PresencePosture {
            display_on: false,
            user_present: false,
        };
        assert_eq!(
            classify_power_event(PowerEvent::DisplayOff, dark),
            LifecycleSignal::Background
        );
        // Display off while a user is present is not background.
        let present = PresencePosture {
            display_on: false,
            user_present: true,
        };
        assert_eq!(
            classify_power_event(PowerEvent::DisplayOff, present),
            LifecycleSignal::PostureChanged
        );
    }

    #[test]
    fn only_pbt_apmsuspend_produces_a_suspend() {
        // The one event that means the machine actually stopped.
        for event in [
            PowerEvent::DisplayOff,
            PowerEvent::UserAbsent,
            PowerEvent::PowerSourceChanged,
            PowerEvent::LidStateChanged,
            PowerEvent::DisplayOn,
            PowerEvent::UserPresent,
            PowerEvent::ResumeAutomatic,
            PowerEvent::ResumeSuspend,
        ] {
            assert_ne!(
                classify_power_event(event, ASLEEP),
                LifecycleSignal::Suspend,
                "{event:?} must not synthesise a suspend"
            );
        }
        assert_eq!(
            classify_power_event(PowerEvent::Suspend, AWAKE),
            LifecycleSignal::Suspend
        );
    }

    #[test]
    fn the_two_resume_events_are_distinguished_by_user_presence() {
        assert_eq!(
            classify_power_event(PowerEvent::ResumeAutomatic, ASLEEP),
            LifecycleSignal::Resume {
                user_present: false
            }
        );
        assert_eq!(
            classify_power_event(PowerEvent::ResumeSuspend, AWAKE),
            LifecycleSignal::Resume { user_present: true }
        );
    }

    #[test]
    fn the_posture_is_folded_after_the_classification_and_not_before() {
        // Folding it in first would make a display-off arriving while a user is
        // present indistinguishable from one arriving while they are absent.
        let posture = AWAKE;
        assert_eq!(
            classify_power_event(PowerEvent::DisplayOff, posture),
            LifecycleSignal::PostureChanged
        );
        let after = apply(posture, PowerEvent::DisplayOff);
        assert!(!after.display_on);
        assert!(after.user_present);
    }

    #[test]
    fn a_changed_boot_identity_is_a_cold_start_and_never_a_resume() {
        // LC-24 step 1, and the reason it is first: no clock can answer it.
        assert_eq!(
            classify_wake([1; 16], [2; 16], 0, 5_000_000),
            WakeClassification::ColdStart
        );
    }

    #[test]
    fn the_gap_is_measured_on_the_suspend_inclusive_clock() {
        // LC-8: the monotonic clock is paused across a suspend and would report
        // zero, which is the failure that is invisible on a machine that never
        // sleeps.
        assert_eq!(
            classify_wake([7; 16], [7; 16], 1_000_000, 28_801_000_000),
            WakeClassification::Resume {
                gap_micros: 28_800_000_000
            }
        );
    }

    #[test]
    fn a_clock_that_went_backwards_reports_a_zero_gap_rather_than_wrapping() {
        // A wrapped gap is an enormous one, which would expire every long-
        // horizon deadline at once. Zero expires nothing early.
        assert_eq!(
            classify_wake([7; 16], [7; 16], 5_000_000, 1_000_000),
            WakeClassification::Resume { gap_micros: 0 }
        );
    }

    #[test]
    fn no_packet_may_be_emitted_before_the_enforcement_query() {
        // LC-24's line, and the reason the ADR restates its position: "the
        // temptation to re-open sockets first is strong".
        let mut sequence = ResumeSequence::default();
        assert!(!sequence.may_emit_a_packet());
        sequence.classified = true;
        assert!(!sequence.may_emit_a_packet(), "step 2 has not run");
        sequence.enforcement_verified = true;
        assert!(sequence.may_emit_a_packet());
        assert!(!sequence.complete(), "steps 3 and 4 are still outstanding");
    }

    #[test]
    fn the_resume_steps_are_named_in_lc24s_order() {
        let mut sequence = ResumeSequence::default();
        assert_eq!(sequence.next_step(), Some("classify the wake"));
        sequence.classified = true;
        assert_eq!(
            sequence.next_step(),
            Some("query and re-assert enforcement, both families")
        );
        sequence.enforcement_verified = true;
        assert_eq!(
            sequence.next_step(),
            Some("re-acquire sockets, interface handles and subscriptions")
        );
        sequence.objects_reacquired = true;
        assert_eq!(sequence.next_step(), Some("hand off to the wake ladder"));
        sequence.ladder_handed_off = true;
        assert_eq!(sequence.next_step(), None);
        assert!(sequence.complete());
    }

    #[test]
    fn lc22_a_resume_cannot_carry_a_remembered_green_forward() {
        // The mechanism is that `resumed` CONSUMES the indicator. There is no
        // expression in this crate that produces a post-resume `Asserted` from
        // a pre-suspend one, because the pre-suspend value is moved and dropped.
        let before = ProtectionIndicator::renew(true, true, 1_000_000);
        assert!(before.is_protected());
        let after = before.resumed();
        assert_eq!(after, ProtectionIndicator::Unknown);
        assert!(!after.is_protected());
    }

    #[test]
    fn only_a_fresh_query_can_make_the_indicator_green_again() {
        let after = ProtectionIndicator::renew(true, true, 1_000).resumed();
        assert!(!after.is_protected());
        let renewed = ProtectionIndicator::renew(true, true, 28_800_000_000);
        assert!(renewed.is_protected());
    }

    #[test]
    fn o18_a_stale_assertion_ages_to_unknown_rather_than_staying_green() {
        let window = 30_000_000; // thirty seconds, supplied by the caller.
        let assertion = ProtectionIndicator::renew(true, true, 1_000_000);
        assert!(!assertion.is_stale(20_000_000, window));
        assert_eq!(assertion.aged(20_000_000, window), assertion);

        assert!(assertion.is_stale(40_000_000, window));
        assert_eq!(
            assertion.aged(40_000_000, window),
            ProtectionIndicator::Unknown
        );
    }

    #[test]
    fn unknown_is_always_stale_and_never_protected() {
        // The safe absorbing state: nothing ages an unknown into a known.
        let unknown = ProtectionIndicator::Unknown;
        assert!(unknown.is_stale(0, u64::MAX));
        assert!(!unknown.is_protected());
        assert_eq!(unknown.aged(0, u64::MAX), ProtectionIndicator::Unknown);
    }

    #[test]
    fn a_fail_closed_but_unprotected_assertion_is_not_rendered_as_protected() {
        // BLOCKED is fail-closed and is not "connected". Rendering DEGRADED or
        // BLOCKED as connected is the defect ADR-0015 §11.6 names.
        let blocked = ProtectionIndicator::renew(true, false, 1_000);
        assert!(!blocked.is_protected());
        assert!(matches!(
            blocked,
            ProtectionIndicator::Asserted {
                fail_closed: true,
                ..
            }
        ));
    }
}
