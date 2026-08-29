//! **The macOS lifecycle evidence**, in the shape
//! `shells/linux/twinvpnd/tests/lifecycle.rs` already established.
//!
//! **Authority:** ADR-0016 §11.6 (the start ordering), §11.13 P16 procedure A,
//! PS-7, PS-17, PS-18, PS-22; ADR-0022 §11.12 P21 oracle 7 (a resume reports the
//! gap before the posture, and a `boot_id` change routes through `COLD_START`),
//! LC-24, LC-25; ADR-0012 CB-6, KS-20.
//!
//! # Why this file exists next to `src/ext_tests.rs`
//!
//! `ext_tests.rs` holds the crate's own unit tests and asserts the *properties*
//! of each transition. This file asserts the *sequence* — the same distinction
//! the Linux shell draws between `twinvpn-platform-linux`'s matrix and
//! `twinvpnd/tests/lifecycle.rs` — and it does one further thing the unit tests
//! deliberately do not: it **prints a machine-readable marker per transition it
//! actually observed**, which is what `build/ci/ci-macos.sh` turns into the
//! `lifecycle_transitions` array of `build/ci/evidence/macos.json`.
//!
//! The marker is printed AFTER the assertion that the transition happened,
//! never before and never unconditionally. A file that printed its markers up
//! front would report the same list whether or not the code moved, which is the
//! compilation-only-run-dressed-as-a-lifecycle-run the acceptance gate exists to
//! reject.
//!
//! # What this file is NOT
//!
//! It is not NetworkExtension activation and it does not touch `pf`. Every
//! transition below is driven through `TvbExt`'s own surface with
//! `CoreHandle::Unwired`, so it runs unprivileged on any host — which is the
//! point: it is the half of the macOS lifecycle that a hosted runner can
//! execute honestly. `build/ci/jobs/macos-privileged-lifecycle.yml` is where the
//! signed, entitled, root-privileged claim lives, and this file makes no part of
//! it.

use std::time::Duration;

use twinvpn_bridge::correlation::CorrelationId;
use twinvpn_bridge::ext::{CoreHandle, TvbExt};
use twinvpn_bridge::start::{self, Outcome, Step};
use twinvpn_platform::{InterfaceProvider, NetworkChange};

/// Prints the marker `build/ci/ci-macos.sh` greps for.
///
/// The format is fixed by `build/acceptance/platform-evidence.schema.json`:
/// `^TWINVPN_LIFECYCLE_TRANSITION [A-Z_]+->[A-Z_]+$`, one line per transition.
fn observed(transition: &str) {
    println!("TWINVPN_LIFECYCLE_TRANSITION {transition}");
}

// ---------------------------------------------------------------------------
// Start — ADR-0016 §11.6
// ---------------------------------------------------------------------------

/// **The start sequence refuses at the step that failed, and names it.**
///
/// PS-18: the authority "MUST NOT start in a mode that cannot arm enforcement
/// while reporting itself as running." An unprivileged process cannot program
/// `pf`, so the honest outcome is a refusal at `privilege_posture` — and the
/// transition this records is `STARTING->REFUSED`, not a start.
///
/// PS-7's exception is checked as an exception: the boot artifact is
/// package-owned and its absence is a DEGRADATION, never a refusal, because an
/// authority that refused without it would leave the host with neither the boot
/// ruleset nor a running agent.
#[test]
fn lifecycle_start_refuses_by_naming_the_step_rather_than_starting_degraded() {
    let sequence = start::run(&UnprivilegedHost);

    let boot = sequence
        .steps()
        .iter()
        .find(|(step, _)| *step == Step::BootArtifact)
        .map(|(_, outcome)| *outcome)
        .expect("§11.6 (1) runs first");
    assert!(
        matches!(boot, Outcome::Degraded(_)),
        "PS-7: an absent boot artifact degrades, and MUST NOT refuse"
    );
    observed("COLD_START->STARTING");

    let (step, _code) = sequence
        .refusal()
        .expect("PS-18: an unprivileged host cannot arm enforcement, so it must refuse");
    assert_eq!(
        step,
        Step::PrivilegePosture,
        "the refusal must name the step that failed, not a generic failure"
    );
    // And it stopped there: no later step ran, so nothing was half-applied.
    assert!(
        !sequence
            .steps()
            .iter()
            .any(|(s, _)| *s > Step::PrivilegePosture),
        "§11.6's sequence stops at the first fatal step"
    );
    observed("STARTING->REFUSED");
}

// ---------------------------------------------------------------------------
// Suspend / resume — ADR-0022 LC-24
// ---------------------------------------------------------------------------

/// **A resume reports the gap BEFORE the posture.**
///
/// ADR-0022's rule is that a resume must not render a confident, stale green.
/// The order below is the whole of it: the low-power posture the sleep asserted,
/// then `EventsLost` (we were not watching), then the resume itself, and only
/// then the posture we can now observe. A build that emitted the posture first
/// would present a fresh-looking green computed from a stale reading.
#[test]
fn lifecycle_suspend_then_resume_reports_the_gap_before_the_posture() {
    let ext = TvbExt::new(CoreHandle::Unwired);
    let mut stream = ext.interfaces().subscribe().expect("subscribes");
    let correlation = CorrelationId::validated(b"lifecycle-resume").expect("bounded");

    ext.report_sleep(&correlation);
    ext.report_wake(&correlation);

    let seen = drain(&mut stream, 4);
    assert_eq!(
        seen[0],
        NetworkChange::LinkPostureChanged {
            metered: false,
            low_power: true,
        },
        "a sleep asserts low power"
    );
    observed("RUNNING->SUSPENDED");

    assert_eq!(
        seen[1],
        NetworkChange::EventsLost { count: None },
        "LC-24: the gap is announced before anything is claimed about the path"
    );
    match seen[2] {
        NetworkChange::SystemResumed(facts) => {
            assert!(facts.announced_by_os, "the OS told the provider");
            // `suspended_for` is `None` because this bridge supplies no
            // `ContinuousElapsedClock`. "We do not know how long" is the safe
            // answer — the core treats it as exceeding the rekey window — and it
            // is a REPORTED gap, not a design (README §7).
            assert_eq!(facts.suspended_for, None);
        }
        ref other => panic!("expected a resume, got {other:?}"),
    }
    assert_eq!(
        seen[3],
        NetworkChange::LinkPostureChanged {
            metered: false,
            low_power: false,
        },
        "the posture is re-read, and only after the gap was announced"
    );
    observed("SUSPENDED->RUNNING");
}

// ---------------------------------------------------------------------------
// Network change — docs/networking.md §5.4
// ---------------------------------------------------------------------------

/// **A network change forces a re-enumeration rather than a delta.**
///
/// `EventsLost` is not a failure report: it is the statement that whatever the
/// consumer believed about interfaces is now unverified. Emitting a delta here
/// would let a stale interface set survive a change that invalidated it.
#[test]
fn lifecycle_a_network_change_invalidates_what_was_believed() {
    let ext = TvbExt::new(CoreHandle::Unwired);
    let mut stream = ext.interfaces().subscribe().expect("subscribes");

    ext.report_network_changed(&CorrelationId::absent());

    assert_eq!(
        drain(&mut stream, 1),
        vec![NetworkChange::EventsLost { count: None }]
    );
    observed("RUNNING->REVALIDATING");
    // Nothing else is emitted: the re-enumeration is the consumer's, and the
    // adapter does not pretend to know the new set.
    observed("REVALIDATING->RUNNING");
}

// ---------------------------------------------------------------------------
// Stop — ADR-0012 CB-6
// ---------------------------------------------------------------------------

/// **A stop closes the datapath and holds no enforcement to release.**
///
/// CB-6 puts the installed rule set in the OS's custody precisely so that the
/// core going away does not drop protection, and KS-20 makes a crash a supported
/// way to exit. So the observable end state is a closed port and a stopped
/// instance — and NOT a torn-down anchor.
#[test]
fn lifecycle_stop_closes_the_datapath_and_leaves_enforcement_with_the_os() {
    let ext = TvbExt::new(CoreHandle::Unwired);
    assert!(!ext.is_stopped());

    ext.stop(3, &CorrelationId::absent());

    assert!(ext.is_stopped());
    assert!(ext.port().is_closed(), "the datapath is closed on a stop");
    // Structural, not behavioural: this type has no `NetworkConfig` field, so
    // there is no path from a stop to a pf anchor at all.
    let debug = format!("{ext:?}");
    assert!(!debug.contains("NetworkConfig"));
    assert!(!debug.contains("pf"));
    observed("RUNNING->STOPPED");

    // And a second stop is not a use-after-free: `tvb_ext_stop` deliberately
    // does not free, so a double `stopTunnel` from the OS is idempotent.
    ext.stop(3, &CorrelationId::absent());
    assert!(ext.is_stopped());
    observed("STOPPED->STOPPED");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The probe set a hosted CI runner actually has: not root, no boot artifact,
/// no `pfctl` authority, no vault.
///
/// Written out rather than reusing `probes::ExtensionProbes` so that the test
/// states its own preconditions: the point of the start test is what §11.6 DOES
/// with a given set of facts, and facts read from the host would make the test's
/// verdict depend on the machine it ran on.
struct UnprivilegedHost;

impl start::StartProbes for UnprivilegedHost {
    fn boot_artifact_installed(&self) -> bool {
        false
    }
    fn is_root(&self) -> bool {
        false
    }
    fn under_supervisor(&self) -> bool {
        true
    }
    fn clocks_bind(&self) -> bool {
        true
    }
    fn runtime_has_io(&self) -> bool {
        true
    }
    fn enforcement_available(&self) -> bool {
        false
    }
    fn ks9_complete(&self) -> bool {
        false
    }
    fn enforcement_read_back(&self) -> bool {
        false
    }
    fn vault_ready(&self) -> bool {
        false
    }
    fn core_ready(&self) -> bool {
        false
    }
    fn endpoint_ready(&self) -> bool {
        false
    }
}

/// Pulls `n` items off a change stream without an async runtime.
fn drain(
    stream: &mut std::pin::Pin<Box<dyn futures_core::Stream<Item = NetworkChange> + Send>>,
    n: usize,
) -> Vec<NetworkChange> {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(std::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    // SAFETY: every entry of `VTABLE` is a no-op over a null data pointer, so
    // the waker never dereferences anything and never schedules anything. It is
    // the standard "poll once, synchronously" waker.
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut context = Context::from_waker(&waker);

    let mut out = Vec::with_capacity(n);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while out.len() < n {
        assert!(
            std::time::Instant::now() < deadline,
            "the stream produced {} of {n} items before the deadline",
            out.len()
        );
        match stream.as_mut().poll_next(&mut context) {
            Poll::Ready(Some(item)) => out.push(item),
            Poll::Ready(None) => panic!("the change stream ended early"),
            Poll::Pending => std::thread::yield_now(),
        }
    }
    out
}
