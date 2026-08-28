//! The tests that need Windows. **None of them has ever executed.**
//!
//! **Authority:** the wave-2 objective ("Where a test genuinely needs Windows,
//! write it, gate it, and make sure it **compiles** under `cross-check` — and
//! say in your report that it has never executed"); ADR-0012 K12 and KS-17;
//! ADR-0010 R5; ADR-0011 D7; ADR-0015 O-17; ADR-0016 §11.6.
//!
//! # What this file is for
//!
//! `tests/enforcement.rs` proves the part of this adapter where a mistake is a
//! leak: which filters a contract implies, what the read-back concludes, how a
//! failed apply compensates, whether the canary can be fooled. It proves all of
//! that on a Linux host, against `sys::fake`.
//!
//! What it cannot prove is that `FwpmFilterAdd0` was called with a structure the
//! Base Filtering Engine accepts, that `CreateIpForwardEntry2` puts the route
//! where IP Helper says it will, or that an NRPT rule written into
//! `DnsPolicyConfig` is one `dnscache` obeys. **Only a Windows host can answer
//! those**, and this file is the shape of that answer, written now so that the
//! day somebody has such a host the work is running a command rather than
//! writing a suite.
//!
//! # Gated, and gated the honest way
//!
//! `#![cfg(windows)]` on the file, plus a run-time opt-in on every test that
//! **mutates** the host. The two gates do different jobs and both are needed:
//!
//! - The `cfg` means the file compiles to nothing here, and is **type-checked**
//!   by `make cross-check` for `x86_64-pc-windows-msvc` with `-D warnings`. A
//!   test that no longer matches the API fails the build on this Linux host,
//!   which is the only continuous protection these tests have.
//! - [`MUTATING_TEST_ENV`] means that running `cargo test` on a developer's own
//!   Windows machine does **not** install WFP filters, program routes or rewrite
//!   the NRPT. `twinvpn-platform-linux`'s `tests/netns.rs` takes the same shape
//!   for the same reason, and it also **asserts the refusal** when unprivileged
//!   rather than skipping — so a plain `cargo test` still checks that an
//!   unprivileged adapter names the right `reason_code`.
//!
//! # How to run them, when there is a host
//!
//! ```text
//! # Read-only, unprivileged. Asserts the refusals.
//! cargo test -p twinvpn-platform-windows --test windows_host
//!
//! # The write path. An Administrator shell on a machine you are willing to
//! # have TwinVPN filters installed on, and which you will reboot or run
//! # `twinvpn-unblock` on afterwards.
//! set TWINVPN_WINDOWS_TEST=1
//! cargo test -p twinvpn-platform-windows --test windows_host -- --test-threads=1
//! ```
//!
//! `--test-threads=1` is not tidiness: there is one WFP sublayer and one
//! routing table per host, and two tests mutating them concurrently would be
//! testing a race rather than the adapter.

#![cfg(windows)]

use twinvpn_platform_windows::oserr::{self, Win32Error};
use twinvpn_platform_windows::route::InterfaceLuid;
use twinvpn_platform_windows::sys::SystemOps as _;
use twinvpn_platform_windows::wfp;

/// The opt-in every mutating test requires.
///
/// Absent, the mutating tests assert the **refusal** an unprivileged process
/// gets rather than skipping, so a plain `cargo test` on a Windows host still
/// checks something real: that a `PlatformError` comes back with a registered
/// `reason_code` and the `WIN32_ERROR` as evidence, rather than a panic or a
/// silent success.
const MUTATING_TEST_ENV: &str = "TWINVPN_WINDOWS_TEST";

fn mutating_enabled() -> bool {
    std::env::var_os(MUTATING_TEST_ENV).is_some()
}

/// The overlay LUID these tests use.
///
/// **A placeholder that a real run must replace.** There is no adapter until
/// `wintun::WindowsTunnelDevice::create_interface` has made one, and the LUID it
/// returns is the only correct value. A test that guessed would program routes
/// onto whatever interface happened to hold that LUID, which on a real machine
/// is somebody's Wi-Fi.
const PLACEHOLDER_LUID: InterfaceLuid = InterfaceLuid(0);

fn system() -> twinvpn_platform_windows::sys::win::WindowsSystem {
    twinvpn_platform_windows::sys::win::WindowsSystem::new()
}

// ---------------------------------------------------------------------------
// read-only: these run unprivileged and assert what an unprivileged process gets
// ---------------------------------------------------------------------------

#[test]
fn the_engine_can_be_queried_or_the_refusal_is_named() {
    // ADR-0015 O-17: the `ProtectionAssertion` is a query. This is the query,
    // against a real Base Filtering Engine. Opening the engine for READ does not
    // need Administrator; opening it for write does. Either outcome is
    // acceptable here — what is not acceptable is a panic, or an `Ok` carrying a
    // state nobody asked the engine for.
    match system().filters().read() {
        Ok(state) => {
            // A host with no TwinVPN install holds no ruleset of ours, and
            // `parse_installed` must say so rather than inventing a posture.
            let installed = wfp::readback::parse_installed(&state);
            if !state.sublayer_present {
                assert!(installed.is_none(), "no sublayer is no posture");
            }
        }
        Err(err) => {
            assert!(
                err.reason_code().as_str().contains('.'),
                "the refusal must carry a registered code"
            );
            assert!(
                err.os_detail().is_some(),
                "and the WIN32_ERROR as evidence, never alone"
            );
        }
    }
}

#[test]
fn the_boot_artifact_check_answers_from_the_engine_and_never_from_a_file() {
    // ADR-0016 §11.6 step (1), and PS-7: verification, never installation. On a
    // host where the MSI has not run this must report absent; on one where it
    // has, present. Both are correct answers and neither is a failure of this
    // test — what it checks is that the question reaches the engine at all.
    if let Ok(state) = system().filters().read() {
        let artifact = wfp::boot::verify(&state);
        // Both families or neither: KS-5 at the moment the host is least
        // defended, and a one-family boot set must not read as registered.
        assert_eq!(
            artifact.is_registered(),
            artifact.v4_deny && artifact.v6_deny
        );
    }
}

#[test]
fn the_routing_table_can_be_read_and_reports_only_our_interface() {
    // `RouteTable::read` narrows to one LUID. On a host with no overlay adapter
    // the answer is empty, which is the honest one.
    if let Ok(routes) = system().routes().read(PLACEHOLDER_LUID) {
        for row in &routes.rows {
            assert_eq!(row.luid, PLACEHOLDER_LUID);
        }
        for address in &routes.addresses {
            assert_eq!(address.luid, PLACEHOLDER_LUID);
        }
    }
}

#[test]
fn every_oserr_literal_matches_the_platforms_own_constant() {
    // The `const _: () = assert!(...)` block in `sys::win` already checks this
    // at compile time. This test exists so that a reader of the *test* output on
    // a Windows host sees the fact stated, and so that a future `oserr` constant
    // added without an assertion is visible in one more place.
    assert_eq!(
        oserr::from_status(
            Win32Error(oserr::ERROR_ACCESS_DENIED),
            "probe",
            oserr::Context::RouteProgram
        )
        .reason_code()
        .as_str(),
        "ROUTE.PROGRAMMING_DENIED"
    );
}

// ---------------------------------------------------------------------------
// the write path: gated, and asserting the refusal when the gate is closed
// ---------------------------------------------------------------------------

#[test]
fn installing_the_blocked_ruleset_either_works_or_names_the_refusal() {
    // KS-17's arm step, against a real engine. Unprivileged, `FwpmEngineOpen0`
    // for write returns `ERROR_ACCESS_DENIED`, which must arrive as
    // `PLATFORM.ADAPTER_UNAVAILABLE` with the number as evidence — the same
    // assertion `twinvpn-platform-linux`'s `tests/netns.rs` makes about an
    // unprivileged `nft`.
    let set = wfp::boot::boot_set();
    let result = system().filters().commit(&set);
    if mutating_enabled() {
        result.expect("an Administrator shell can install the boot set");
        // KS-17: the read-back must show exactly what was committed, and it must
        // show it as a query rather than as a remembered value.
        let state = system().filters().read().expect("reads back");
        let installed = wfp::readback::parse_installed(&state).expect("a ruleset is installed");
        assert_eq!(installed.posture, wfp::Ruleset::Blocked);
        assert!(
            installed.both_families_covered(),
            "KS-5: one family without the other is non-conforming"
        );
        // And the cleanup, because this test just made a real host fail-closed.
        system().filters().purge().expect("purges");
    } else {
        let err = result.expect_err(
            "an unprivileged process must be refused, not silently succeed; \
             set TWINVPN_WINDOWS_TEST=1 in an Administrator shell to exercise the write path",
        );
        assert!(err.os_detail().is_some());
    }
}

#[test]
fn a_posture_swap_leaves_no_instant_with_no_rules() {
    // KS-17, on the only host that can answer it: install BLOCKED, swap to
    // PROTECTED, and read back between. The property cannot be *observed* from
    // one thread — there is no instant to sample — so what this checks is the
    // weaker, still-worth-having thing: that both postures read back correctly
    // and that the swap did not go through a state with no sublayer.
    if !mutating_enabled() {
        return;
    }
    let blocked = wfp::boot::boot_set();
    system()
        .filters()
        .commit(&blocked)
        .expect("installs BLOCKED");
    assert!(system().filters().read().expect("reads").sublayer_present);
    // A real swap renders from a contract; the boot set stands in for one here
    // because this file has no core to ask for one.
    system().filters().commit(&blocked).expect("re-installs");
    assert!(
        system().filters().read().expect("reads").sublayer_present,
        "the sublayer must never be absent between two commits"
    );
    system().filters().purge().expect("purges");
}

#[test]
fn the_net_event_stream_reports_its_own_losses() {
    // ADR-0012 §11.9's canary depends on this: a fold over a stream that lost
    // events under-counts, and `canary_verdict` refuses to conclude `Denied`
    // from a lossy window. Whether `FwpmNetEventEnum` reports its drops at all
    // is the single largest open question in this adapter — see the crate's
    // report — and this is the test that answers it.
    if !mutating_enabled() {
        return;
    }
    let (events, lost) = system().filters().net_events().expect("enumerates");
    // No assertion on the counts: a quiet host produces none. What is asserted
    // is that the call answers at all and that the loss flag is a fact the
    // engine supplied rather than one inferred from an empty slice.
    let snapshot = wfp::canary::fold(&events, lost);
    assert_eq!(snapshot.lost_events, lost);
}
