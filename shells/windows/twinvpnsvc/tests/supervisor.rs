//! The SCM handshake, driven through the public seam on this host.
//!
//! **Authority:** ADR-0016 §11.6 (the start ordering), PS-11, PS-18; ADR-0022
//! §11.4 (the Windows termination row and its 2 s stop budget), LC-13, LC-37.
//!
//! # What these tests are, and what they are not
//!
//! **This host is Linux.** `StartServiceCtrlDispatcherW` cannot be called here,
//! so the one fact that actually produced the lane's 1053 — that the binary now
//! attempts the dispatcher connection before anything else — is proven by the
//! guest lane and by nothing below.
//!
//! What is proven here is the whole of the decision layer that connection feeds:
//! a `dwControl` and its `dwEventType` become a `Control`, the transition
//! decides the next status and the actions, and a [`StartupRefusal`] becomes the
//! two exit codes the SCM and the process report. Every one of those was
//! unreachable before this change, because nothing called the state machine.

#![cfg(feature = "service")]

use twinvpnsvc::service::scm::{
    on_control, Action, ServiceState, ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR, STOP_WAIT_HINT_MS,
};
use twinvpnsvc::service::supervisor::{
    classify_control, process_exit_code, reply_for, stopped_for, Classified,
    ERROR_CALL_NOT_IMPLEMENTED, FIRST_CHECKPOINT, PBT_APMSUSPEND, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_POWEREVENT, SERVICE_CONTROL_PRESHUTDOWN, SERVICE_CONTROL_SESSIONCHANGE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
};
use twinvpnsvc::service::StartupRefusal;

/// The control handler's own composition, minus `SetServiceStatus`.
///
/// Returns what the handler would return to the SCM, and the states it would
/// have reported on the way — which is the pair a real handler decides and the
/// pair no test could reach before this change.
fn deliver(state: ServiceState, control: u32, event_type: u32) -> (u32, ServiceState, Vec<Action>) {
    let classified = classify_control(control, event_type);
    let reply = reply_for(classified);
    match classified {
        Classified::Run(control) => {
            let (next, actions) = on_control(state, control);
            (reply, next, actions)
        }
        Classified::Ignored | Classified::Unimplemented => (reply, state, Vec::new()),
    }
}

#[test]
fn a_stop_is_accepted_answered_and_turned_into_a_shutdown() {
    // The path the lane exercises after `sc.exe stop`. Before this change the
    // service had no handler at all, so the SCM's stop had nowhere to go.
    let (reply, next, actions) = deliver(ServiceState::Running, SERVICE_CONTROL_STOP, 0);

    assert_eq!(reply, NO_ERROR, "a stop is handled, so it is acknowledged");
    assert_eq!(next, ServiceState::StopPending { checkpoint: 1 });
    assert_eq!(
        actions,
        vec![
            Action::ReportStatus,
            Action::FlushDurableState,
            Action::BeginShutdown
        ]
    );
}

#[test]
fn preshutdown_takes_the_same_path_because_that_is_the_control_this_service_accepts() {
    // ADR-0022 §11.4: `SERVICE_ACCEPT_PRESHUTDOWN`, because `SHUTDOWN`'s budget
    // is too short for a durable flush.
    assert_eq!(
        deliver(ServiceState::Running, SERVICE_CONTROL_PRESHUTDOWN, 0),
        deliver(ServiceState::Running, SERVICE_CONTROL_STOP, 0)
    );
}

#[test]
fn shutdown_is_refused_rather_than_acknowledged_with_a_path_that_does_not_run() {
    let (reply, next, actions) = deliver(ServiceState::Running, SERVICE_CONTROL_SHUTDOWN, 0);

    assert_eq!(reply, ERROR_CALL_NOT_IMPLEMENTED);
    assert_eq!(
        next,
        ServiceState::Running,
        "a refused control changes nothing"
    );
    assert!(actions.is_empty());
}

#[test]
fn an_interrogate_is_answered_from_the_recorded_state_in_every_state() {
    // The SCM asks this at any time. A service that answered from a state it
    // had not reported would contradict its own last `SetServiceStatus`.
    for state in [
        ServiceState::StartPending {
            checkpoint: FIRST_CHECKPOINT,
        },
        ServiceState::Running,
        ServiceState::StopPending { checkpoint: 1 },
    ] {
        let (reply, next, actions) = deliver(state, SERVICE_CONTROL_INTERROGATE, 0);
        assert_eq!(reply, NO_ERROR);
        assert_eq!(next, state, "interrogate moved {state:?}");
        assert_eq!(actions, vec![Action::ReportStatus]);
    }
}

#[test]
fn a_suspend_is_acknowledged_without_the_service_leaving_running() {
    // ADR-0022 LC-16: an OS suspension is not a state transition. The service
    // stays RUNNING across it, and the event is handed on rather than read.
    let (reply, next, actions) = deliver(
        ServiceState::Running,
        SERVICE_CONTROL_POWEREVENT,
        PBT_APMSUSPEND,
    );

    assert_eq!(reply, NO_ERROR);
    assert_eq!(next, ServiceState::Running);
    assert!(matches!(actions.as_slice(), [Action::HandlePower(_)]));
}

#[test]
fn an_unhandled_power_sub_event_is_acknowledged_and_not_disowned() {
    // `ACCEPTED` advertises `SERVICE_ACCEPT_POWEREVENT`. Answering
    // ERROR_CALL_NOT_IMPLEMENTED to a sub-event we chose not to act on would
    // retract that advertisement one event at a time.
    let (reply, next, actions) = deliver(
        ServiceState::Running,
        SERVICE_CONTROL_POWEREVENT,
        32_787, // PBT_POWERSETTINGCHANGE, which needs a registration this build has not made
    );

    assert_eq!(reply, NO_ERROR);
    assert_eq!(next, ServiceState::Running);
    assert!(actions.is_empty());
}

#[test]
fn a_session_change_is_accepted_because_ps_14_needs_the_signal() {
    let (reply, _, actions) = deliver(ServiceState::Running, SERVICE_CONTROL_SESSIONCHANGE, 0);
    assert_eq!(reply, NO_ERROR);
    assert_eq!(actions, vec![Action::RefreshSessionFacts]);
}

#[test]
fn the_stop_path_declares_a_budget_that_fits_inside_the_scms_kill_timeout() {
    // ADR-0022 §11.4: T_LIFECYCLE_STOP = 2 s, inside the 5 s default
    // `WaitToKillServiceTimeout`. The hint the STOP_PENDING report carries is
    // the promise; a longer one is a promise Windows does not keep.
    let (_, next, _) = deliver(ServiceState::Running, SERVICE_CONTROL_STOP, 0);
    assert!(matches!(next, ServiceState::StopPending { .. }));
    assert_eq!(STOP_WAIT_HINT_MS, 2_000);
    // Named as a value so this is a comparison rather than a constant the
    // compiler folds away, exactly as `service::scm`'s own test does it.
    let wait_to_kill_service_timeout_ms: u32 = 5_000;
    assert!(
        STOP_WAIT_HINT_MS < wait_to_kill_service_timeout_ms,
        "a hint longer than the kill timeout is a promise Windows will not keep"
    );
}

#[test]
fn a_refused_start_stops_the_service_with_an_exit_the_scm_can_act_on() {
    // PS-18 and LC-13. The recovery ladder is conditional on an *unsuccessful*
    // exit, so a refusal reported as NO_ERROR would show a clean stop in
    // `sc query`, and neither the restart rungs nor the quarantine rung would
    // ever engage.
    let refusal = StartupRefusal::platform(
        "MGMT.UNAVAILABLE",
        "MGMT.UNAVAILABLE",
        "the named-pipe listener refused to bind".to_owned(),
    );

    let stopped = stopped_for(Some(&refusal));
    assert_eq!(
        stopped,
        ServiceState::Stopped {
            exit_code: ERROR_SERVICE_SPECIFIC_ERROR,
            service_specific: 71,
        }
    );
    assert_ne!(
        stopped,
        ServiceState::Stopped {
            exit_code: NO_ERROR,
            service_specific: 0,
        },
        "a refusal is never reported as a clean stop"
    );
    assert_eq!(process_exit_code(Some(&refusal)), 71);
}

#[test]
fn a_clean_run_stops_with_no_error_so_lc13_does_not_restart_it() {
    // The other half of LC-13: an administrator's `sc stop` must not be
    // undone by the SCM restarting the service it just stopped.
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
fn a_stop_delivered_during_the_start_sequence_is_honoured() {
    // The SCM may cancel a start, and the start sequence is long: §11.6 opens a
    // WFP engine, queries the boot artifact and reclaims the ruleset. A service
    // that ignored a stop there would hang the boot.
    let (reply, next, actions) = deliver(
        ServiceState::StartPending {
            checkpoint: FIRST_CHECKPOINT,
        },
        SERVICE_CONTROL_STOP,
        0,
    );

    assert_eq!(reply, NO_ERROR);
    assert_eq!(next, ServiceState::StopPending { checkpoint: 1 });
    assert!(actions.contains(&Action::BeginShutdown));
}

#[test]
fn a_stop_re_delivered_during_a_slow_stop_does_not_flush_twice() {
    // The SCM re-delivers a stop when one is slow. A second `BeginShutdown`
    // would flip the watch a second time and flush a second time.
    let (reply, next, actions) = deliver(
        ServiceState::StopPending { checkpoint: 1 },
        SERVICE_CONTROL_STOP,
        0,
    );

    assert_eq!(reply, NO_ERROR);
    assert_eq!(next, ServiceState::StopPending { checkpoint: 1 });
    assert_eq!(actions, vec![Action::ReportStatus]);
    assert!(!actions.contains(&Action::BeginShutdown));
}
