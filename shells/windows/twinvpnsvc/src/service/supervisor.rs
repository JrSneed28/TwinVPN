//! The SCM handshake: the control handler, and the status this service reports
//! at each step of §11.6.
//!
//! **Authority:** [ADR-0016](../../../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
//! §11.6 (the start ordering; steps 7 and 8 are bind then accept), PS-11, PS-18;
//! [ADR-0022](../../../../../docs/adr/ADR-0022-application-lifecycle-and-background-execution.md)
//! §11.4 (the Windows termination row and its 2 s stop budget), LC-24, LC-4,
//! LC-37; ADR-0018 CB-6.
//!
//! # 1053, and what it actually was
//!
//! The hosted kill-switch lane registered the shipped binary, ran `sc.exe start
//! TwinVPNService`, and got `ERROR_SERVICE_REQUEST_TIMEOUT` (1053) with the
//! process already gone. Nothing was wrong with the start sequence: the binary
//! never called `StartServiceCtrlDispatcherW` at all, so from the SCM's side a
//! process it had launched simply never reported in, and after 30 s it is
//! killed. A service that does not perform this handshake earns 1053 whatever
//! else it does correctly.
//!
//! # The split, which is this crate's usual one
//!
//! | Here | Next door |
//! |---|---|
//! | [`classify_control`] — a `dwControl` and its `dwEventType` become a [`Control`] | [`crate::win32::scm::register_handler`] |
//! | [`stopped_for`] and [`process_exit_code`] — a refusal becomes two exit codes | [`crate::win32::scm::report`] |
//! | [`FIRST_CHECKPOINT`] — LC-37's liveness signal starts at one | [`crate::win32::scm::dispatch`] |
//! | [`super::scm::on_control`] — the transition itself | `SetServiceStatus` |
//!
//! Every row on the left runs on this Linux host and is tested below. The
//! [`Supervisor`] that performs the right-hand column is `#[cfg(windows)]` and
//! has never executed; the guest lane is its only proof.
//!
//! # The control codes are declared, not imported
//!
//! `windows-sys` is a `cfg(windows)` dependency of this crate, so a mapping
//! written against `SERVICE_CONTROL_STOP` would be a mapping no test on this
//! host could run — which is the defect the whole `service`/`win32` split
//! exists to prevent. The values below are therefore written out, and
//! `the_declared_control_codes_are_the_scms_own` asserts each against the real
//! constant when this module is compiled for Windows.
//!
//! The `PBT_*` values get no such cross-check and the reason is worth stating:
//! they live in `Win32_UI_WindowsAndMessaging`, which this crate does not
//! enable — `Cargo.toml` names `Win32_System_Power` for them and that feature
//! does not carry them. They are quoted from `windows-sys` 0.61.2's own table.

use super::power::PowerEvent;
use super::scm::{Control, ServiceState, ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR};
use super::StartupRefusal;

/// `SERVICE_CONTROL_STOP`.
pub const SERVICE_CONTROL_STOP: u32 = 1;
/// `SERVICE_CONTROL_INTERROGATE`.
pub const SERVICE_CONTROL_INTERROGATE: u32 = 4;
/// `SERVICE_CONTROL_SHUTDOWN`.
///
/// Named so it can be **refused** by name. This service accepts
/// `SERVICE_ACCEPT_PRESHUTDOWN` instead (ADR-0022 §11.4: `SHUTDOWN`'s budget is
/// too short for a durable flush), so the SCM never delivers this one — and if
/// it did, answering `NO_ERROR` would claim a shutdown path that does not run.
pub const SERVICE_CONTROL_SHUTDOWN: u32 = 5;
/// `SERVICE_CONTROL_POWEREVENT`.
pub const SERVICE_CONTROL_POWEREVENT: u32 = 13;
/// `SERVICE_CONTROL_SESSIONCHANGE`.
pub const SERVICE_CONTROL_SESSIONCHANGE: u32 = 14;
/// `SERVICE_CONTROL_PRESHUTDOWN`.
pub const SERVICE_CONTROL_PRESHUTDOWN: u32 = 15;

/// `PBT_APMSUSPEND`. **S3/S4 only** — see [`super::power`].
pub const PBT_APMSUSPEND: u32 = 4;
/// `PBT_APMRESUMESUSPEND`.
pub const PBT_APMRESUMESUSPEND: u32 = 7;
/// `PBT_APMRESUMEAUTOMATIC`.
pub const PBT_APMRESUMEAUTOMATIC: u32 = 18;

/// `ERROR_CALL_NOT_IMPLEMENTED`, the reply for a control this service does not
/// implement.
pub const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;

/// The first `dwCheckPoint` reported while `START_PENDING`.
///
/// One and not zero: LC-37 makes the checkpoint the Windows stand-in for a
/// watchdog, and the SCM reads it as "has this start moved since I last
/// looked". A start that opened at zero would have spent its first report
/// saying nothing had happened yet.
pub const FIRST_CHECKPOINT: u32 = 1;

/// What a `dwControl` turned out to be.
///
/// Three cases and not two, because "this service has nothing to do for that"
/// and "this service does not implement that" are different answers to the SCM
/// and it acts on the difference. Collapsing them would have an unrecognised
/// `dwEventType` retract `SERVICE_ACCEPT_POWEREVENT`, which
/// [`crate::win32::scm::ACCEPTED`] has already advertised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classified {
    /// A control the state machine runs. Answered with `NO_ERROR`.
    Run(Control),
    /// A control this service accepts and has nothing to do for. Answered with
    /// `NO_ERROR`, because the control *was* handled — by deciding it needed
    /// nothing.
    Ignored,
    /// A control this service does not implement. Answered with
    /// [`ERROR_CALL_NOT_IMPLEMENTED`].
    Unimplemented,
}

/// Maps the two words the SCM's handler is called with onto a [`Control`].
///
/// # CB-2
///
/// The only facts consulted are the SCM's own two integers. What a suspend
/// *means* is [`super::power`]'s and ultimately the core's; this is a decoding.
#[must_use]
pub fn classify_control(control: u32, event_type: u32) -> Classified {
    match control {
        SERVICE_CONTROL_STOP => Classified::Run(Control::Stop),
        SERVICE_CONTROL_PRESHUTDOWN => Classified::Run(Control::PreShutdown),
        SERVICE_CONTROL_INTERROGATE => Classified::Run(Control::Interrogate),
        SERVICE_CONTROL_SESSIONCHANGE => Classified::Run(Control::SessionChange),
        SERVICE_CONTROL_POWEREVENT => match event_type {
            PBT_APMSUSPEND => Classified::Run(Control::PowerEvent(PowerEvent::Suspend)),
            PBT_APMRESUMEAUTOMATIC => {
                Classified::Run(Control::PowerEvent(PowerEvent::ResumeAutomatic))
            }
            PBT_APMRESUMESUSPEND => Classified::Run(Control::PowerEvent(PowerEvent::ResumeSuspend)),
            // Every other `dwEventType` — the query/cancel pairs, the battery
            // and power-source notifications, and `PBT_POWERSETTINGCHANGE`,
            // which only arrives for a `PowerSettingRegisterNotification` this
            // build has not made. LC-23a's Modern Standby half is the follow-up
            // named in `Supervisor::run_action`.
            _ => Classified::Ignored,
        },
        _ => Classified::Unimplemented,
    }
}

/// The reply the control handler returns to the SCM.
#[must_use]
pub const fn reply_for(classified: Classified) -> u32 {
    match classified {
        Classified::Run(_) | Classified::Ignored => NO_ERROR,
        Classified::Unimplemented => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

/// The terminal status for a start that finished, refused or not.
///
/// PS-18's other half: a service that refused to start must **say so to the
/// SCM**, not merely to its log. A `Stopped` reported with `NO_ERROR` after a
/// [`StartupRefusal`] leaves `sc query` showing a clean stop and the SCM's
/// recovery ladder — ADR-0016 §11.6's restart-at-1s, restart-at-5s, quarantine
/// — never engaging, because LC-13 makes it conditional on an *unsuccessful*
/// exit.
#[must_use]
pub fn stopped_for(refusal: Option<&StartupRefusal>) -> ServiceState {
    match refusal {
        None => ServiceState::Stopped {
            exit_code: NO_ERROR,
            service_specific: 0,
        },
        Some(refusal) => ServiceState::Stopped {
            exit_code: ERROR_SERVICE_SPECIFIC_ERROR,
            service_specific: u32::from(refusal.exit),
        },
    }
}

/// The **process** exit code, which is a different number from the SCM's.
///
/// [`StartupRefusal::exit`]'s own documentation: 70 (`EX_SOFTWARE`) and 71
/// (`EX_OSERR`) are "the *process* exit codes of a service that never reached
/// the SCM dispatcher". They keep that meaning on the supervised path — the
/// process still exits with one — while [`stopped_for`] carries the same value
/// into `dwServiceSpecificExitCode`, so the two surfaces agree.
#[must_use]
pub fn process_exit_code(refusal: Option<&StartupRefusal>) -> u8 {
    refusal.map_or(0, |refusal| refusal.exit)
}

/// The live SCM connection: the status handle, the state it last reported, and
/// the two shutdown seams a control has to reach.
///
/// One per process, handed to `RegisterServiceCtrlHandlerExW` as the handler's
/// `lpContext` and therefore leaked — see [`Self::install`].
#[cfg(windows)]
pub struct Supervisor {
    /// The `SERVICE_STATUS_HANDLE`, as a `usize`.
    ///
    /// An integer and not the pointer, for two reasons that happen to coincide.
    /// It keeps this type `Sync` without an `unsafe impl` — the handle is
    /// opaque, never dereferenced here, and only handed back to
    /// `SetServiceStatus`. And zero is a usable "not registered yet": the SCM
    /// may call the handler from the moment
    /// `RegisterServiceCtrlHandlerExW` returns, which is before this field can
    /// possibly be stored, and a report in that window has nowhere to go.
    handle: std::sync::atomic::AtomicUsize,
    /// The state last reported, which the next transition is computed from.
    state: std::sync::Mutex<ServiceState>,
    /// The stop signal `serve` observes. Flips at most once.
    stop: tokio::sync::watch::Sender<bool>,
    /// The adapter, once §11.6 step 4 has built one.
    ///
    /// `None` until then, and that is a real state rather than an
    /// initialisation gap: a stop that arrives during steps 1–3 has no adapter
    /// to latch because there is none to have work in flight on.
    adapter: std::sync::Mutex<Option<std::sync::Arc<dyn twinvpn_platform::PlatformAdapter>>>,
}

#[cfg(windows)]
impl Supervisor {
    /// Registers the control handler and returns the leaked supervisor.
    ///
    /// # Errors
    ///
    /// [`crate::win32::Failure`] when the SCM refuses the registration, which
    /// is fatal: a service with no handler cannot be stopped and would hang
    /// every shutdown.
    pub fn install(
        stop: tokio::sync::watch::Sender<bool>,
    ) -> Result<&'static Self, crate::win32::Failure> {
        // Leaked on purpose. `register_handler`'s safety contract is that the
        // context outlives the service, and the service outlives every scope
        // this could be held in — `run` is called *after* this and returns
        // before the process does. One leak, once, for the life of the process.
        let supervisor: &'static Self = std::boxed::Box::leak(std::boxed::Box::new(Self {
            handle: std::sync::atomic::AtomicUsize::new(0),
            state: std::sync::Mutex::new(ServiceState::StartPending {
                checkpoint: FIRST_CHECKPOINT,
            }),
            stop,
            adapter: std::sync::Mutex::new(None),
        }));
        let context = std::ptr::from_ref(supervisor)
            .cast::<core::ffi::c_void>()
            .cast_mut();
        // SAFETY: `context` points at the `Box::leak`ed `Supervisor` above, so
        // it outlives the service exactly as `register_handler` requires, and
        // the SCM hands it back unchanged to `control_handler`.
        let handle = unsafe {
            crate::win32::scm::register_handler(crate::SERVICE_NAME, Some(control_handler), context)
        }?;
        supervisor
            .handle
            .store(handle as usize, std::sync::atomic::Ordering::Release);
        Ok(supervisor)
    }

    /// Records a state and reports it to the SCM.
    ///
    /// Both halves, because an `INTERROGATE` answers from the recorded state: a
    /// report that did not record would have the service tell the SCM one thing
    /// and then answer a question with another.
    pub fn report(&self, state: ServiceState) {
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = state;
        self.report_now(state);
    }

    /// Hands the adapter over, once §11.6 step 4 has built one.
    pub fn attach_adapter(&self, adapter: std::sync::Arc<dyn twinvpn_platform::PlatformAdapter>) {
        *self
            .adapter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(adapter);
    }

    /// Runs one control through [`super::scm::on_control`] and performs what it
    /// returns.
    ///
    /// The state lock is held across the whole of it. The SCM does not promise
    /// to serialise control delivery, and two handlers interleaving their
    /// `SetServiceStatus` calls would report a checkpoint that went backwards —
    /// which reads to the SCM exactly like the hung start LC-37 uses it to
    /// detect.
    fn on_control(&self, control: Control) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (next, actions) = super::scm::on_control(*state, control);
        *state = next;
        for action in actions {
            self.run_action(action, next);
        }
    }

    fn run_action(&self, action: super::scm::Action, next: ServiceState) {
        match action {
            super::scm::Action::ReportStatus => self.report_now(next),
            super::scm::Action::BeginShutdown => self.begin_shutdown(),
            // The three below are named follow-ups, and each is logged rather
            // than silently dropped so a guest run says which one it reached.
            super::scm::Action::FlushDurableState => tracing::warn!(
                target: "twinvpn.service",
                reason_code = "PLATFORM.LIFECYCLE.STATE_UNWRITABLE",
                "ADR-0022 §11.4's bounded durable flush is NOT performed on this path: \
                 `Core::flush` is `async` and the core is owned by `serve`, which this \
                 handler cannot reach, and blocking an SCM control handler on it would \
                 spend the 2 s stop budget inside the handler. The write-behind journal's \
                 own durability is what covers the gap, and the next start rehydrates \
                 from it (LC-4)"
            ),
            super::scm::Action::HandlePower(event) => tracing::info!(
                target: "twinvpn.service",
                event = ?event,
                "a power event was decoded and NOT yet handed to the core: LC-24's resume \
                 sequence needs a lifecycle sink on `Core` that this build does not have. \
                 `service::power::classify_power_event` is written and tested; nothing \
                 calls it"
            ),
            super::scm::Action::RefreshSessionFacts => tracing::info!(
                target: "twinvpn.service",
                "a session change was decoded and NOT yet acted on: PS-14's console-seat \
                 facts are re-derived per connection in `service::peer`, so the cached \
                 facts this would refresh do not exist yet"
            ),
        }
    }

    /// ADR-0022 §11.4's stop path, which touches no enforcement.
    fn begin_shutdown(&self) {
        // The listener's half. `serve`'s contract is that it returns `Ok(())`
        // within `STOP_WAIT_HINT_MS` of this flipping.
        self.stop.send_replace(true);
        // The adapter's half, and it is what makes the 2 s budget reachable
        // rather than merely declared: an adapter call already in flight — a
        // WFP query, an interface enumeration — would otherwise spend the whole
        // of it, and the latch has every one of them return
        // `PlatformError::ShuttingDown` at once instead of hanging or silently
        // succeeding.
        //
        // CB-6 and §11.4's Windows row: this removes **no** enforcement. The
        // latch sets a flag and does nothing else, and the persistent WFP
        // filters stay in the Base Filtering Engine's custody.
        if let Some(adapter) = self
            .adapter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            twinvpn_platform::PlatformAdapter::begin_shutdown(adapter.as_ref());
        }
    }

    /// Reports without recording, for the transition that already recorded.
    fn report_now(&self, state: ServiceState) {
        let handle = self.handle.load(std::sync::atomic::Ordering::Acquire);
        if handle == 0 {
            // See `Self::handle`: the SCM may call the handler before the
            // registration's return value has been stored. Dropping the report
            // is the only option; the next one carries the same state.
            return;
        }
        // SAFETY: `handle` is the non-null `SERVICE_STATUS_HANDLE`
        // `register_handler` returned for this service — the zero case is the
        // "not stored yet" sentinel and returned above — and the service has
        // not stopped, because reporting `Stopped` is the last thing done with
        // it.
        unsafe {
            crate::win32::scm::report(
                handle as windows_sys::Win32::System::Services::SERVICE_STATUS_HANDLE,
                state,
            );
        }
    }
}

/// The SCM's `LPHANDLER_FUNCTION_EX`.
#[cfg(windows)]
unsafe extern "system" fn control_handler(
    control: u32,
    event_type: u32,
    _event_data: *mut core::ffi::c_void,
    context: *mut core::ffi::c_void,
) -> u32 {
    let classified = classify_control(control, event_type);
    if let Classified::Run(control) = classified {
        // SAFETY: `context` is the pointer `Supervisor::install` handed to
        // `RegisterServiceCtrlHandlerExW`. It points at a `Box::leak`ed
        // `Supervisor` that lives for the whole process, the SCM passes it back
        // unchanged on every control, and `Supervisor` is `Sync` — so the
        // shared reference is sound on whichever thread the SCM calls from.
        let supervisor = unsafe { &*context.cast::<Supervisor>() };
        supervisor.on_control(control);
    }
    reply_for(classified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::scm::{on_control, Action};

    #[test]
    fn every_accepted_control_is_decoded_and_run() {
        // `crate::win32::scm::ACCEPTED` advertises exactly these four plus the
        // power event. A control this service told the SCM it accepts and then
        // answered ERROR_CALL_NOT_IMPLEMENTED to would be a service that lied
        // in its `dwControlsAccepted`.
        for (code, expected) in [
            (SERVICE_CONTROL_STOP, Control::Stop),
            (SERVICE_CONTROL_PRESHUTDOWN, Control::PreShutdown),
            (SERVICE_CONTROL_INTERROGATE, Control::Interrogate),
            (SERVICE_CONTROL_SESSIONCHANGE, Control::SessionChange),
        ] {
            let classified = classify_control(code, 0);
            assert_eq!(classified, Classified::Run(expected), "control {code}");
            assert_eq!(reply_for(classified), NO_ERROR);
        }
    }

    #[test]
    fn the_three_s3_s4_power_events_are_decoded_and_nothing_else_is_invented() {
        // ADR-0022 §11.6's Windows row and LC-23a: `PBT_APMSUSPEND` is the only
        // source of a suspend, and on Modern Standby it never arrives. Nothing
        // here manufactures one from another event type.
        for (event_type, expected) in [
            (PBT_APMSUSPEND, PowerEvent::Suspend),
            (PBT_APMRESUMEAUTOMATIC, PowerEvent::ResumeAutomatic),
            (PBT_APMRESUMESUSPEND, PowerEvent::ResumeSuspend),
        ] {
            assert_eq!(
                classify_control(SERVICE_CONTROL_POWEREVENT, event_type),
                Classified::Run(Control::PowerEvent(expected)),
                "dwEventType {event_type}"
            );
        }
    }

    #[test]
    fn an_unrecognised_power_event_is_ignored_and_never_reported_unimplemented() {
        // `PBT_POWERSETTINGCHANGE` and the query/cancel pairs. Answering
        // ERROR_CALL_NOT_IMPLEMENTED here would retract
        // SERVICE_ACCEPT_POWEREVENT, which `ACCEPTED` has already advertised —
        // and the control *was* handled, by deciding it needed nothing.
        for event_type in [0_u32, 1, 6, 10, 32_787] {
            let classified = classify_control(SERVICE_CONTROL_POWEREVENT, event_type);
            assert_eq!(classified, Classified::Ignored, "dwEventType {event_type}");
            assert_eq!(reply_for(classified), NO_ERROR);
        }
    }

    #[test]
    fn shutdown_is_refused_by_name_because_preshutdown_is_what_this_service_accepts() {
        // ADR-0022 §11.4: `SHUTDOWN`'s budget is too short for a durable flush,
        // so `SERVICE_ACCEPT_PRESHUTDOWN` is what `ACCEPTED` carries. Claiming
        // NO_ERROR for a SHUTDOWN would promise a path that does not run.
        let classified = classify_control(SERVICE_CONTROL_SHUTDOWN, 0);
        assert_eq!(classified, Classified::Unimplemented);
        assert_eq!(reply_for(classified), ERROR_CALL_NOT_IMPLEMENTED);
    }

    #[test]
    fn an_unknown_control_is_unimplemented_rather_than_silently_accepted() {
        for code in [2_u32, 3, 6, 7, 16, 32, 200] {
            assert_eq!(
                classify_control(code, 0),
                Classified::Unimplemented,
                "control {code}"
            );
        }
    }

    #[test]
    fn a_clean_stop_reports_no_error_and_a_zero_process_code() {
        assert_eq!(
            stopped_for(None),
            ServiceState::Stopped {
                exit_code: NO_ERROR,
                service_specific: 0,
            }
        );
        assert_eq!(process_exit_code(None), 0);
    }

    #[test]
    fn a_refused_start_reports_a_non_zero_exit_the_scm_acts_on() {
        // PS-18 and LC-13 together: the SCM's recovery ladder is conditional on
        // an *unsuccessful* exit, so a refusal reported as NO_ERROR would leave
        // `sc query` showing a clean stop and no restart, no crash-loop count
        // and no quarantine.
        let refusal = StartupRefusal::platform(
            "POLICY.KILLSWITCH.ARM_FAILED",
            "POLICY.KILLSWITCH.ARM_FAILED",
            "the engine reports a posture that covers one family".to_owned(),
        );
        assert_eq!(refusal.exit, 71, "a platform refusal is EX_OSERR");
        assert_eq!(
            stopped_for(Some(&refusal)),
            ServiceState::Stopped {
                exit_code: ERROR_SERVICE_SPECIFIC_ERROR,
                service_specific: 71,
            }
        );
        assert_eq!(process_exit_code(Some(&refusal)), 71);
    }

    #[test]
    fn the_two_exit_surfaces_carry_the_same_number() {
        // The process's own exit code and `dwServiceSpecificExitCode` are read
        // by different tools and must not disagree about which failure it was.
        for refusal in [
            StartupRefusal::internal("the start sequence did not complete".to_owned()),
            StartupRefusal::platform(
                "PLATFORM.OS_UNSUPPORTED",
                "PLATFORM.OS_UNSUPPORTED",
                "no SCM here".to_owned(),
            ),
        ] {
            let ServiceState::Stopped {
                exit_code,
                service_specific,
            } = stopped_for(Some(&refusal))
            else {
                panic!("a refusal stops the service");
            };
            assert_eq!(exit_code, ERROR_SERVICE_SPECIFIC_ERROR);
            assert_eq!(
                service_specific,
                u32::from(process_exit_code(Some(&refusal)))
            );
            assert_ne!(service_specific, 0, "a refusal is never a clean stop");
        }
    }

    #[test]
    fn the_first_checkpoint_is_one_so_the_scm_sees_the_start_move() {
        // LC-37: the checkpoint is the Windows stand-in for a watchdog, read as
        // "has this start advanced". Opening at zero spends the first report
        // saying nothing has happened.
        assert_eq!(FIRST_CHECKPOINT, 1);
        assert_ne!(FIRST_CHECKPOINT, 0);
    }

    #[test]
    fn a_stop_decoded_here_produces_the_shutdown_the_state_machine_asks_for() {
        // The composition the control handler performs, minus the syscall: the
        // wire control code, through the decoder, through the transition.
        let Classified::Run(control) = classify_control(SERVICE_CONTROL_STOP, 0) else {
            panic!("a stop is run");
        };
        let (next, actions) = on_control(ServiceState::Running, control);
        assert_eq!(next, ServiceState::StopPending { checkpoint: 1 });
        assert!(actions.contains(&Action::BeginShutdown));
    }

    #[test]
    fn a_power_event_decoded_here_never_moves_the_reported_state() {
        // ADR-0022 LC-16: the service stays RUNNING across a suspend.
        let Classified::Run(control) = classify_control(SERVICE_CONTROL_POWEREVENT, PBT_APMSUSPEND)
        else {
            panic!("a suspend is run");
        };
        let (next, actions) = on_control(ServiceState::Running, control);
        assert_eq!(next, ServiceState::Running);
        assert_eq!(
            actions,
            vec![Action::HandlePower(PowerEvent::Suspend)],
            "the event is handed on, not interpreted here"
        );
    }

    /// The declared constants against the SCM's own, when there is one.
    #[cfg(windows)]
    #[test]
    fn the_declared_control_codes_are_the_scms_own() {
        use windows_sys::Win32::System::Services as svc;

        assert_eq!(SERVICE_CONTROL_STOP, svc::SERVICE_CONTROL_STOP);
        assert_eq!(
            SERVICE_CONTROL_INTERROGATE,
            svc::SERVICE_CONTROL_INTERROGATE
        );
        assert_eq!(SERVICE_CONTROL_SHUTDOWN, svc::SERVICE_CONTROL_SHUTDOWN);
        assert_eq!(SERVICE_CONTROL_POWEREVENT, svc::SERVICE_CONTROL_POWEREVENT);
        assert_eq!(
            SERVICE_CONTROL_SESSIONCHANGE,
            svc::SERVICE_CONTROL_SESSIONCHANGE
        );
        assert_eq!(
            SERVICE_CONTROL_PRESHUTDOWN,
            svc::SERVICE_CONTROL_PRESHUTDOWN
        );
        assert_eq!(
            ERROR_CALL_NOT_IMPLEMENTED,
            windows_sys::Win32::Foundation::ERROR_CALL_NOT_IMPLEMENTED
        );
        assert_eq!(NO_ERROR, windows_sys::Win32::Foundation::NO_ERROR);
        assert_eq!(
            ERROR_SERVICE_SPECIFIC_ERROR,
            windows_sys::Win32::Foundation::ERROR_SERVICE_SPECIFIC_ERROR
        );
    }
}
