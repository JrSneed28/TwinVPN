//! The Service Control Manager, as thinly as it can be wrapped.
//!
//! **Authority:** ADR-0016 §11.2's Windows row, §11.6's supervision table,
//! PS-11; ADR-0022 §11.4 (the Windows termination row), LC-12.
//!
//! # Everything that decides is next door
//!
//! [`crate::service::scm::on_control`] is the state machine, and it is a pure
//! function this host runs. What is here is the SCM's own vocabulary: the
//! dispatcher, the control handler, and the one call that reports a status.

use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    LPHANDLER_FUNCTION_EX, LPSERVICE_MAIN_FUNCTIONW, SERVICE_ACCEPT_POWEREVENT,
    SERVICE_ACCEPT_PRESHUTDOWN, SERVICE_ACCEPT_SESSIONCHANGE, SERVICE_ACCEPT_STOP, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED,
    SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

use crate::service::scm::{wait_hint_ms, ServiceState};

use super::{wide, Failure};

/// Whether the SCM started this process (PS-11).
///
/// An unsupervised authority "MUST NOT claim guarantees it does not have", and
/// R-25's restart guarantee is a property of the SCM rather than of this binary.
///
/// The signal is that [`StartServiceCtrlDispatcherW`] succeeds: a process the
/// SCM did not start fails it with `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`.
/// That is more honest than probing the parent process, which a container or a
/// debugger can imitate — and it is the Windows analogue of `shells/linux`'s
/// `INVOCATION_ID` check.
///
/// This function reports what the dispatcher attempt found; it does not attempt
/// one of its own, because a second attempt would consume the connection.
#[must_use]
pub fn started_by_scm() -> bool {
    DISPATCHED.load(std::sync::atomic::Ordering::Acquire)
}

static DISPATCHED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The controls this service accepts.
///
/// `PRESHUTDOWN` rather than `SHUTDOWN`: ADR-0022 §11.4 asks for a bounded
/// durable flush before the machine goes, and `SHUTDOWN`'s budget is too short
/// for one. `POWEREVENT` is LC-24's only S3/S4 signal, and `SESSIONCHANGE` is
/// what keeps PS-14's console-seat facts current.
pub const ACCEPTED: u32 = SERVICE_ACCEPT_STOP
    | SERVICE_ACCEPT_PRESHUTDOWN
    | SERVICE_ACCEPT_POWEREVENT
    | SERVICE_ACCEPT_SESSIONCHANGE;

/// Hands this process to the SCM.
///
/// Blocks until the service ends. Returns `false` when the SCM did not start
/// this process, which the caller turns into PS-11's warning and a foreground
/// run rather than a failure.
///
/// # Panics
///
/// Never: a null service name is refused by the SCM and reported as `false`.
#[must_use]
pub fn dispatch(service_name: &str, entry: LPSERVICE_MAIN_FUNCTIONW) -> bool {
    let mut name = wide(service_name);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: entry,
        },
        // The table is NUL-terminated by an all-zero entry, which is the
        // documented sentinel.
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: `table` is a live, correctly-terminated array that outlives the
    // call, and `name` outlives `table` because both are locals of this frame
    // and `name` is declared first.
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    let dispatched = ok != 0;
    DISPATCHED.store(dispatched, std::sync::atomic::Ordering::Release);
    dispatched
}

/// Registers the control handler.
///
/// # Safety
///
/// `context` is handed to the SCM and passed back to `handler` on every control
/// for the life of the service, so it must point at something that outlives the
/// service — a leaked `Box`, not a stack local.
///
/// # Errors
///
/// [`Failure`] when the SCM refuses, which is fatal: a service with no handler
/// cannot be stopped and would hang every shutdown.
pub unsafe fn register_handler(
    service_name: &str,
    handler: LPHANDLER_FUNCTION_EX,
    context: *mut core::ffi::c_void,
) -> Result<SERVICE_STATUS_HANDLE, Failure> {
    let name = wide(service_name);
    // SAFETY: `name` is a live NUL-terminated buffer for the duration of the
    // call. `context` is the caller's and must outlive the service, which the
    // caller guarantees by leaking it — see `main.rs`.
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), handler, context) };
    if handle.is_null() {
        Err(Failure::of("RegisterServiceCtrlHandlerExW"))
    } else {
        Ok(handle)
    }
}

/// Reports a state to the SCM.
///
/// The `SERVICE_STATUS` is built from the [`ServiceState`] the pure transition
/// function produced, so the two cannot disagree about what a state means.
///
/// # Safety
///
/// `handle` must be the value [`register_handler`] returned for this service,
/// and must not have been invalidated by the service having stopped.
pub unsafe fn report(handle: SERVICE_STATUS_HANDLE, state: ServiceState) {
    let (current, checkpoint, exit_code) = match state {
        ServiceState::StartPending { checkpoint } => (SERVICE_START_PENDING, checkpoint, 0),
        ServiceState::Running => (SERVICE_RUNNING, 0, 0),
        ServiceState::StopPending { checkpoint } => (SERVICE_STOP_PENDING, checkpoint, 0),
        ServiceState::Stopped { exit_code } => (SERVICE_STOPPED, 0, exit_code),
    };
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: current,
        // A pending or stopped service accepts nothing: the SCM must not deliver
        // a control to a service that cannot answer it.
        dwControlsAccepted: if matches!(state, ServiceState::Running) {
            ACCEPTED
        } else {
            0
        },
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: checkpoint,
        dwWaitHint: wait_hint_ms(state),
    };
    // SAFETY: `status` is a live, fully-initialised `SERVICE_STATUS` and
    // `handle` came from `register_handler`, which refused a null one.
    unsafe {
        SetServiceStatus(handle, &raw const status);
    }
}
