//! The Service Control Manager: the status machine, and the recovery ladder.
//!
//! **Authority:** [ADR-0016](../../../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
//! §11.2's Windows row, §11.6's supervision table, PS-9, PS-10, PS-11;
//! [ADR-0022](../../../../../docs/adr/ADR-0022-application-lifecycle-and-background-execution.md)
//! §11.4 (the Windows termination row), LC-12, LC-13, LC-27, LC-28, LC-37.
//!
//! # The transition function is a value, and that is the point
//!
//! `SetServiceStatus` is a Windows call this host cannot make. [`on_control`] is
//! not: it takes the state and the control code and returns the next state and
//! the actions to perform, and it is a `const`-shaped pure function whose whole
//! behaviour is exercised by the tests below. The `#[cfg(windows)]` part is one
//! function that turns a [`ServiceState`] into a `SERVICE_STATUS` and hands it
//! to the SCM.
//!
//! A state machine written directly against `SetServiceStatus` would be one this
//! domain could only assert about.
//!
//! # LC-12: `SERVICE_AUTO_START`, and not delayed
//!
//! > The choice is Automatic versus Automatic (Delayed Start), and **Automatic
//! > wins**: delayed start defers the service by ~2 minutes after boot, which
//! > lengthens exactly the window in which the host is fail-closed-and-offline…
//! > `SERVICE_BOOT_START` is not available to a user-mode service. The residual
//! > — the interval between BFE applying the persistent filters and our service
//! > reaching step 4 of LC-4 — is an availability gap in the correct direction
//! > and is what `T_REHYDRATE` bounds.
//!
//! Note that this **contradicts ADR-0016 §11.6's own supervision table**, which
//! says "delayed start". LC-12 states the reasoning and overrides it; the
//! contradiction is reported rather than resolved here.
//!
//! # PS-9: quarantine keeps protection and keeps a way out
//!
//! On entering quarantine the enforcement rule set stays installed and
//! unmodified — quarantine "MUST NOT disarm, MUST NOT clear the M2 latch, MUST
//! NOT swap `RULESET_BLOCKED`" — the offline unblock command stays functional,
//! and leaving requires an `ADMINISTER` action or a reboot. **It MUST NOT
//! self-clear on a timer**, which is why [`FailureActions::RESET_PERIOD_SECS`]
//! governs the SCM's *failure count* and nothing in this module governs the
//! quarantine's own duration.

/// A control code the SCM delivers.
///
/// Only the ones this service accepts. A control it did not accept is never
/// delivered, so there is no variant for one — which makes the exhaustive match
/// in [`on_control`] a genuine enumeration rather than one with a fallback arm
/// nobody reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// `SERVICE_CONTROL_STOP`.
    Stop,
    /// `SERVICE_CONTROL_PRESHUTDOWN`.
    ///
    /// Accepted rather than `SERVICE_CONTROL_SHUTDOWN` because ADR-0022 §11.4
    /// asks for a bounded flush before the machine goes: preshutdown is
    /// delivered earlier and with a longer timeout, and `SHUTDOWN`'s own budget
    /// is too short for a durable write.
    PreShutdown,
    /// `SERVICE_CONTROL_INTERROGATE`.
    Interrogate,
    /// `SERVICE_CONTROL_POWEREVENT`, with its `dwEventType`.
    PowerEvent(super::power::PowerEvent),
    /// `SERVICE_CONTROL_SESSIONCHANGE`.
    ///
    /// Carried so PS-14's console-seat rule has a signal, and for LC-23a's
    /// synthesised background state.
    SessionChange,
}

/// Where the service is, as the SCM sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// `SERVICE_START_PENDING`, with the checkpoint that has to keep rising.
    StartPending {
        /// `dwCheckPoint`. The SCM's own liveness signal: a start that stops
        /// advancing it is a hung start, and LC-37 makes that the equivalent of
        /// a watchdog on a platform whose SCM provides none.
        checkpoint: u32,
    },
    /// `SERVICE_RUNNING`.
    Running,
    /// `SERVICE_STOP_PENDING`.
    StopPending {
        /// `dwCheckPoint`.
        checkpoint: u32,
    },
    /// `SERVICE_STOPPED`.
    Stopped {
        /// `dwWin32ExitCode`. [`NO_ERROR`] for a clean stop, and
        /// [`ERROR_SERVICE_SPECIFIC_ERROR`] when the service refused to start
        /// for a reason of its own.
        exit_code: u32,
        /// `dwServiceSpecificExitCode`, which `sc query` reports as
        /// `SERVICE_EXIT_CODE` and reads **only** when `exit_code` is
        /// [`ERROR_SERVICE_SPECIFIC_ERROR`].
        ///
        /// Carried as its own field because the two are one Win32 contract, and
        /// because the alternative — mapping a [`super::StartupRefusal`] onto
        /// whichever `WIN32_ERROR` is numerically nearest its sysexits code —
        /// would put a wrong and confidently-rendered error name in front of an
        /// operator. 71 is `EX_OSERR` here and `ERROR_REQ_NOT_ACCEP` there.
        service_specific: u32,
    },
}

/// What the service must do as a consequence of a transition.
///
/// Returned as data rather than performed, so [`on_control`] stays pure and a
/// test can assert the **whole** consequence of a control rather than its
/// visible half.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Report the new status to the SCM.
    ReportStatus,
    /// Begin the graceful shutdown sequence.
    ///
    /// **Never "tear down enforcement".** ADR-0022 §11.4's Windows row:
    /// "Shutdown MUST NOT remove enforcement — persistent WFP filters stay."
    BeginShutdown,
    /// Flush the write-behind journal before the process goes.
    FlushDurableState,
    /// Hand a power event to [`super::power`].
    HandlePower(super::power::PowerEvent),
    /// Re-derive the console-seat facts PS-14 needs.
    RefreshSessionFacts,
}

/// The stop budget ADR-0022 §11.4 fixes.
///
/// > keep the stop path under `T_LIFECYCLE_STOP = 2s` (fits inside the 5s
/// > `WaitToKillServiceTimeout`)
///
/// A `u32` of milliseconds because that is what `dwWaitHint` takes. It is
/// reported to the SCM and **not enforced here**: the deadline is the core's,
/// composed from `twinvpn_env::Timer`, and a shell that imposed one would put it
/// outside CD-1's reach.
pub const STOP_WAIT_HINT_MS: u32 = 2_000;

/// The start budget reported in `dwWaitHint` while `START_PENDING`.
///
/// **A decision recorded as one.** No value is pinned in the corpus. LC-4's
/// sequence includes opening a durable store and querying the filtering engine,
/// neither of which is instant on a cold boot; thirty seconds is long enough
/// that a healthy start never trips the SCM and short enough that a wedged one
/// is noticed within a boot.
pub const START_WAIT_HINT_MS: u32 = 30_000;

/// `NO_ERROR`.
pub const NO_ERROR: u32 = 0;

/// `ERROR_SERVICE_SPECIFIC_ERROR`.
///
/// The `dwWin32ExitCode` a service reports when it failed for a reason of its
/// own rather than for one the Win32 error table already names, and the only
/// value that makes the SCM read `dwServiceSpecificExitCode` at all.
/// [`super::supervisor::stopped_for`] is the one place that produces it.
///
/// Declared here rather than taken from `windows-sys` so the mapping is a value
/// this Linux host can test; `supervisor`'s `#[cfg(windows)]` cross-check
/// asserts it against the real constant.
pub const ERROR_SERVICE_SPECIFIC_ERROR: u32 = 1_066;

/// The `SERVICE_FAILURE_ACTIONS` ladder, as a value the installer consumes.
///
/// ADR-0016 §11.6's Windows supervision row: "SCM recovery: restart at 1s,
/// restart at 5s, then *run a command* (the quarantine action);
/// `ResetPeriod=86400`. Third failure inside the reset period ⇒ quarantine."
///
/// Exported rather than written into the WiX, because a ladder that lived only
/// in packaging would be a second declaration of a policy this ADR states —
/// MI-20's principle applied to an installer.
pub struct FailureActions;

impl FailureActions {
    /// The first restart delay, in milliseconds.
    pub const FIRST_RESTART_MS: u32 = 1_000;
    /// The second restart delay, in milliseconds.
    pub const SECOND_RESTART_MS: u32 = 5_000;
    /// After how long a clean run resets the failure count, in seconds.
    pub const RESET_PERIOD_SECS: u32 = 86_400;
    /// How many failures inside the reset period reach the quarantine action.
    ///
    /// PS-10: detection (`PLATFORM.CRASH_LOOP`) and containment
    /// (`PLATFORM.SERVICE.QUARANTINED`) are **different codes**, and both are
    /// emitted; neither replaces the other. This constant is the boundary
    /// between them.
    pub const FAILURES_BEFORE_QUARANTINE: u32 = 3;

    /// The ladder as `(delay_ms, kind)` triples, in the order the SCM applies
    /// them.
    ///
    /// LC-13: the restart must be **conditional** on an unsuccessful exit and
    /// never a bare "always restart", because a bare one defeats crash-loop
    /// containment. `SERVICE_FAILURE_ACTIONS_FLAG` left unset is what makes it
    /// conditional, and [`Self::restart_on_clean_exit`] states it.
    #[must_use]
    pub const fn ladder() -> [(u32, RecoveryAction); 3] {
        [
            (Self::FIRST_RESTART_MS, RecoveryAction::Restart),
            (Self::SECOND_RESTART_MS, RecoveryAction::Restart),
            (0, RecoveryAction::RunQuarantineCommand),
        ]
    }

    /// Whether the SCM should restart after a **clean** exit.
    ///
    /// `false`, and LC-13 is why: "restart policy … must be **conditional** on
    /// crash/unsuccessful exit, never a bare 'always restart'". A service that
    /// restarted after a clean stop could never be stopped by an administrator,
    /// and a crash loop would be indistinguishable from an operator's
    /// intervention.
    #[must_use]
    pub const fn restart_on_clean_exit() -> bool {
        false
    }
}

/// One rung of the ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    /// `SC_ACTION_RESTART`.
    Restart,
    /// `SC_ACTION_RUN_COMMAND` — the quarantine action (PS-9).
    RunQuarantineCommand,
}

/// The transition, as a pure function.
///
/// # CB-2
///
/// Every branch here is on an **SCM** fact — which control arrived, and which
/// state the service was in. None is on a `ConnectionState`, a `reason_code`
/// class, a policy verdict or a timer expiry. The power event is *handed on*
/// rather than interpreted: [`super::power`] classifies it into facts, and the
/// core decides what they mean.
#[must_use]
// The `Stop` and `PreShutdown` arms are written out separately rather than
// merged. They do the same thing today and they are different questions — one is
// an administrator stopping a service, the other is the machine going down — and
// ADR-0022 §11.4 gives them different SCM budgets. Merging them would hide the
// day one of them gains a step.
#[allow(clippy::match_same_arms)]
pub fn on_control(state: ServiceState, control: Control) -> (ServiceState, Vec<Action>) {
    match (state, control) {
        // A stop while starting is honoured: the SCM may cancel a start, and a
        // service that ignored it would hang the boot.
        (ServiceState::StartPending { .. } | ServiceState::Running, Control::Stop) => (
            ServiceState::StopPending { checkpoint: 1 },
            vec![
                Action::ReportStatus,
                Action::FlushDurableState,
                Action::BeginShutdown,
            ],
        ),
        // Preshutdown is a stop with a durable flush and the same refusal to
        // touch enforcement.
        (ServiceState::StartPending { .. } | ServiceState::Running, Control::PreShutdown) => (
            ServiceState::StopPending { checkpoint: 1 },
            vec![
                Action::ReportStatus,
                Action::FlushDurableState,
                Action::BeginShutdown,
            ],
        ),
        // Interrogate is a status report and nothing else, in every state.
        (state, Control::Interrogate) => (state, vec![Action::ReportStatus]),
        // A power event never changes the SCM state: the service stays
        // `RUNNING` across a suspend, and ADR-0022 LC-16 is explicit that an OS
        // suspension "is not a `ConnectionState`" either.
        (state, Control::PowerEvent(event)) => (state, vec![Action::HandlePower(event)]),
        (state, Control::SessionChange) => (state, vec![Action::RefreshSessionFacts]),
        // A stop delivered twice: the second is idempotent. The SCM does this
        // when a stop is slow, and a service that started a second shutdown
        // would flush twice and race itself.
        (state @ ServiceState::StopPending { .. }, Control::Stop | Control::PreShutdown) => {
            (state, vec![Action::ReportStatus])
        }
        (state @ ServiceState::Stopped { .. }, Control::Stop | Control::PreShutdown) => {
            (state, Vec::new())
        }
    }
}

/// The next `START_PENDING` checkpoint.
///
/// The SCM treats a checkpoint that stops advancing as a hung start. Advancing
/// it is therefore the service's liveness signal during LC-4's sequence, and
/// LC-37 names it as the Windows equivalent of a watchdog: "On Windows, where
/// the SCM provides no watchdog, the equivalent is an in-process supervisor
/// thread plus the health check ADR-0023 specifies."
#[must_use]
pub const fn advance(state: ServiceState) -> ServiceState {
    match state {
        ServiceState::StartPending { checkpoint } => ServiceState::StartPending {
            checkpoint: checkpoint.saturating_add(1),
        },
        ServiceState::StopPending { checkpoint } => ServiceState::StopPending {
            checkpoint: checkpoint.saturating_add(1),
        },
        other => other,
    }
}

/// The `dwWaitHint` for a state.
#[must_use]
pub const fn wait_hint_ms(state: ServiceState) -> u32 {
    match state {
        ServiceState::StartPending { .. } => START_WAIT_HINT_MS,
        ServiceState::StopPending { .. } => STOP_WAIT_HINT_MS,
        ServiceState::Running | ServiceState::Stopped { .. } => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::power::PowerEvent;

    #[test]
    fn a_stop_flushes_before_it_shuts_down_and_never_touches_enforcement() {
        // ADR-0022 §11.4's Windows row: "Shutdown MUST NOT remove enforcement —
        // persistent WFP filters stay." The mechanism is that there is no
        // `Action` for it, in this enum, in any state.
        let (state, actions) = on_control(ServiceState::Running, Control::Stop);
        assert_eq!(state, ServiceState::StopPending { checkpoint: 1 });
        assert_eq!(
            actions,
            vec![
                Action::ReportStatus,
                Action::FlushDurableState,
                Action::BeginShutdown
            ]
        );
        // The flush comes BEFORE the shutdown: a flush scheduled onto a runtime
        // that has stopped accepting work never runs.
        let flush = actions
            .iter()
            .position(|a| *a == Action::FlushDurableState)
            .expect("flushes");
        let shutdown = actions
            .iter()
            .position(|a| *a == Action::BeginShutdown)
            .expect("shuts down");
        assert!(flush < shutdown);
    }

    #[test]
    fn preshutdown_is_handled_exactly_as_a_stop_is() {
        // The difference is the SCM's timeout, not ours: preshutdown is
        // delivered earlier and with a longer budget, and the sequence it runs
        // is the same one.
        assert_eq!(
            on_control(ServiceState::Running, Control::PreShutdown),
            on_control(ServiceState::Running, Control::Stop)
        );
    }

    #[test]
    fn a_stop_during_start_is_honoured_rather_than_ignored() {
        // The SCM may cancel a start. A service that ignored it would hang the
        // boot, which is a worse outcome than an incomplete start.
        let (state, actions) =
            on_control(ServiceState::StartPending { checkpoint: 3 }, Control::Stop);
        assert_eq!(state, ServiceState::StopPending { checkpoint: 1 });
        assert!(actions.contains(&Action::BeginShutdown));
    }

    #[test]
    fn a_second_stop_is_idempotent_and_does_not_flush_twice() {
        // The SCM re-delivers a stop when one is slow. A second shutdown would
        // flush twice and race itself.
        let (state, actions) =
            on_control(ServiceState::StopPending { checkpoint: 2 }, Control::Stop);
        assert_eq!(state, ServiceState::StopPending { checkpoint: 2 });
        assert_eq!(actions, vec![Action::ReportStatus]);
        assert!(!actions.contains(&Action::FlushDurableState));
    }

    #[test]
    fn a_stop_after_stopped_does_nothing_at_all() {
        let (state, actions) = on_control(
            ServiceState::Stopped {
                exit_code: NO_ERROR,
                service_specific: 0,
            },
            Control::Stop,
        );
        assert_eq!(
            state,
            ServiceState::Stopped {
                exit_code: NO_ERROR,
                service_specific: 0,
            }
        );
        assert!(actions.is_empty());
    }

    #[test]
    fn interrogate_reports_and_changes_nothing_in_every_state() {
        for state in [
            ServiceState::StartPending { checkpoint: 1 },
            ServiceState::Running,
            ServiceState::StopPending { checkpoint: 1 },
            ServiceState::Stopped {
                exit_code: NO_ERROR,
                service_specific: 0,
            },
        ] {
            let (after, actions) = on_control(state, Control::Interrogate);
            assert_eq!(after, state, "interrogate changed {state:?}");
            assert_eq!(actions, vec![Action::ReportStatus]);
        }
    }

    #[test]
    fn a_power_event_never_changes_the_scm_state() {
        // ADR-0022 LC-16 and LC-18: an OS suspension produces a journal fact,
        // not a transition. The service stays RUNNING across a suspend.
        for event in [
            PowerEvent::Suspend,
            PowerEvent::ResumeAutomatic,
            PowerEvent::ResumeSuspend,
            PowerEvent::DisplayOff,
            PowerEvent::UserPresent,
        ] {
            let (state, actions) = on_control(ServiceState::Running, Control::PowerEvent(event));
            assert_eq!(state, ServiceState::Running);
            assert_eq!(actions, vec![Action::HandlePower(event)]);
        }
    }

    #[test]
    fn the_power_event_is_handed_on_and_never_interpreted_here() {
        // CB-2: the SCM module translates a control code into an action. What a
        // suspend *means* is `power`'s and ultimately the core's.
        let (_, actions) = on_control(
            ServiceState::Running,
            Control::PowerEvent(PowerEvent::Suspend),
        );
        assert!(matches!(actions.as_slice(), [Action::HandlePower(_)]));
    }

    #[test]
    fn the_start_checkpoint_advances_so_the_scm_can_see_a_hung_start() {
        // LC-37: the SCM provides no watchdog, and a checkpoint that stops
        // advancing is the signal that stands in for one.
        let mut state = ServiceState::StartPending { checkpoint: 0 };
        for expected in 1..=5 {
            state = advance(state);
            assert_eq!(
                state,
                ServiceState::StartPending {
                    checkpoint: expected
                }
            );
        }
        // A running service has no checkpoint to advance.
        assert_eq!(advance(ServiceState::Running), ServiceState::Running);
    }

    #[test]
    fn the_checkpoint_saturates_rather_than_wrapping() {
        // A wrapped checkpoint reads to the SCM as a start that went backwards,
        // which is indistinguishable from a hung one.
        let state = advance(ServiceState::StartPending {
            checkpoint: u32::MAX,
        });
        assert_eq!(
            state,
            ServiceState::StartPending {
                checkpoint: u32::MAX
            }
        );
    }

    #[test]
    fn the_stop_budget_fits_inside_the_scms_own_kill_timeout() {
        // ADR-0022 §11.4: T_LIFECYCLE_STOP = 2s, inside the 5s default
        // WaitToKillServiceTimeout. A hint longer than the kill timeout is a
        // promise Windows will not keep.
        // The SCM's own default. Named as a value so the comparison below is a
        // comparison and not a constant the compiler folds away.
        let wait_to_kill_service_timeout_ms: u32 = 5_000;
        assert_eq!(STOP_WAIT_HINT_MS, 2_000);
        assert!(
            wait_hint_ms(ServiceState::StopPending { checkpoint: 1 })
                < wait_to_kill_service_timeout_ms,
            "a hint longer than the kill timeout is a promise Windows will not keep"
        );
        assert_eq!(
            wait_hint_ms(ServiceState::StopPending { checkpoint: 1 }),
            STOP_WAIT_HINT_MS
        );
        assert_eq!(wait_hint_ms(ServiceState::Running), 0);
    }

    #[test]
    fn the_recovery_ladder_is_adr_0016_11_6s_and_ends_in_quarantine() {
        let ladder = FailureActions::ladder();
        assert_eq!(ladder[0], (1_000, RecoveryAction::Restart));
        assert_eq!(ladder[1], (5_000, RecoveryAction::Restart));
        assert_eq!(ladder[2].1, RecoveryAction::RunQuarantineCommand);
        assert_eq!(FailureActions::RESET_PERIOD_SECS, 86_400);
        assert_eq!(FailureActions::FAILURES_BEFORE_QUARANTINE, 3);
        assert_eq!(
            u32::try_from(ladder.len()).expect("three rungs"),
            FailureActions::FAILURES_BEFORE_QUARANTINE,
            "the third failure is the one that reaches the quarantine rung"
        );
    }

    #[test]
    fn lc13_a_clean_exit_is_never_restarted() {
        // "restart policy … must be conditional on crash/unsuccessful exit,
        // never a bare 'always restart'" — a bare one defeats crash-loop
        // containment and makes an administrator's `sc stop` unactionable.
        assert!(!FailureActions::restart_on_clean_exit());
    }
}
