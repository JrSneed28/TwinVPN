//! The environment attestation for `WINDOWS-WFP-KILLSWITCH`.
//!
//! **Owner:** `platform-windows`. Runs only on Windows, and only inside the
//! disposable nested guest — never on the CI controller.
//!
//! # Why this file exists separately from `windows_host.rs`
//!
//! `windows_host.rs` tests the adapter. This tests the MACHINE, and the
//! difference is the whole point of the wave-1 correction: a kill-switch run on
//! a host whose Base Filtering Engine was stopped, or whose caller was not
//! actually elevated, produces perfectly well-formed evidence with every
//! boolean true and proves nothing. `build/acceptance/report.py` refuses a PASS
//! for `WINDOWS-WFP-KILLSWITCH` unless the four facts below were MEASURED and
//! recorded in the evidence's `environment` map, so the criterion cannot go
//! green on a machine that was never capable of it.
//!
//! # The output contract
//!
//! Each fact is printed as one line
//!
//! ```text
//! TWINVPN_PRECONDITION <key>=<value>
//! ```
//!
//! and `build/ci/ci-windows.sh` scrapes those lines into the evidence's
//! `environment`. The keys are read by `report.py`; renaming one here without
//! renaming it there turns the row NOT-EXECUTED, which is the failure direction
//! a rename should take.
//!
//! # Two modes, and they must not be run together
//!
//! * default — the preconditions, including a REAL add/remove probe that
//!   installs a filter set, reads it back and purges it. Requires
//!   `TWINVPN_WINDOWS_TEST=1`, the same opt-in `windows_host.rs` uses.
//! * `TWINVPN_EXPECT_FILTERS=1` — asserts that TwinVPN's OWN filters are
//!   installed at this instant. Run AFTER the product armed them, never before:
//!   the probe above purges, and a purge is exactly what this must not observe.
#![cfg(windows)]

use std::process::Command;

use twinvpn_platform_windows::sys::SystemOps as _;
use twinvpn_platform_windows::wfp;

fn fact(key: &str, value: impl std::fmt::Display) {
    println!("TWINVPN_PRECONDITION {key}={value}");
}

fn enabled(var: &str) -> bool {
    std::env::var(var).map(|v| v == "1").unwrap_or(false)
}

fn system() -> twinvpn_platform_windows::sys::win::WindowsSystem {
    twinvpn_platform_windows::sys::win::WindowsSystem::new()
}

/// The caller must be elevated, and "elevated" is a measured fact rather than an
/// assumption about how the job was launched.
///
/// The integrity level is the honest question. Membership of the Administrators
/// group is NOT: a filtered token in a UAC-split session carries that membership
/// while every privileged call is denied, so a group check reports `true` on
/// exactly the host where the run would fail.
#[test]
fn the_caller_is_genuinely_privileged() {
    let out = Command::new("whoami")
        .arg("/groups")
        .output()
        .expect("whoami is present on every Windows host");
    let text = String::from_utf8_lossy(&out.stdout);
    // S-1-16-12288 is High Mandatory Level; S-1-16-16384 is System.
    let high = text.contains("S-1-16-12288") || text.contains("S-1-16-16384");
    fact("privileged", high);
    assert!(
        high,
        "the caller's integrity level is not High or System, so no WFP write can \
         succeed and no kill-switch evidence produced here would mean anything. \
         whoami /groups said:\n{text}"
    );
}

/// WFP is the Base Filtering Engine. A stopped BFE makes every filter
/// disappear, which would make the armed window silent for a reason that has
/// nothing to do with TwinVPN.
#[test]
fn the_base_filtering_engine_is_running() {
    let out = Command::new("sc")
        .args(["query", "BFE"])
        .output()
        .expect("sc.exe is present on every Windows host");
    let text = String::from_utf8_lossy(&out.stdout);
    let running = text.contains("RUNNING");
    fact("bfe_running", running);
    assert!(
        running,
        "the Base Filtering Engine is not running; WFP filters cannot exist on \
         this host. sc query BFE said:\n{text}"
    );
}

/// A REAL add/remove against the real engine, before anything is claimed about
/// the product.
///
/// This is the probe that separates "the machine can hold filters" from "the
/// product installed filters". It uses the product's own commit/read/purge path
/// rather than a bespoke FFI call, because a bespoke call could succeed on a
/// host where the product's path is refused — and it is the product's path the
/// criterion is about.
///
/// It PURGES what it added. A precondition that leaves state behind would make
/// the run that follows it measure this test.
#[test]
fn a_real_wfp_add_and_remove_succeeds() {
    if !enabled("TWINVPN_WINDOWS_TEST") {
        // Deliberately NOT a skip that prints a fact. An absent
        // `wfp_write_probe` key is what report.py reads as "this was never
        // measured", and that must not be reachable by forgetting the opt-in.
        panic!(
            "TWINVPN_WINDOWS_TEST=1 is required: this probe writes to the real \
             engine, and a run without it would record no attestation at all"
        );
    }

    let set = wfp::boot::boot_set();
    let engine = system();
    engine
        .filters()
        .commit(&set)
        .expect("an elevated caller can install a filter set");

    let state = engine.filters().read().expect("the engine reads back");
    let installed = wfp::readback::parse_installed(&state)
        .expect("what was just committed must read back as an installed ruleset");
    assert!(
        installed.both_families_covered(),
        "KS-5: a probe that covered one family and not the other would not prove \
         the engine accepts what the product installs"
    );

    // The remove half. `purge` is `twinvpn-unblock`'s path (KS-20a), so the
    // probe's teardown and the product's sanctioned removal are the same code.
    engine
        .filters()
        .purge()
        .expect("an elevated caller can remove what it installed");
    let after = engine.filters().read().expect("the engine reads back");
    assert!(
        wfp::readback::parse_installed(&after).is_none(),
        "the probe's own filters must be gone; a probe that cannot remove its \
         filters has left the host in a state the run after it would measure"
    );

    fact("wfp_write_probe", true);
    fact("wfp_probe_filters", set.filters.len());
}

/// TwinVPN's OWN filters, right now.
///
/// Gated on `TWINVPN_EXPECT_FILTERS=1` and run at ONE moment: after the product
/// armed, before the tunnel is terminated. Running it at any other time asserts
/// something the product never promised.
#[test]
fn twinvpns_own_filters_are_installed_right_now() {
    if !enabled("TWINVPN_EXPECT_FILTERS") {
        return;
    }
    let engine = system();
    let state = engine.filters().read().expect("the engine reads back");
    let installed = wfp::readback::parse_installed(&state).expect(
        "TwinVPN's filters are not installed. The kill-switch sequence armed \
         nothing, so the silence it is about to measure would be the silence of \
         a host that was never protected",
    );
    assert!(
        installed.both_families_covered(),
        "KS-5: IPv4 without IPv6 (or the reverse) is a non-conforming posture, \
         and the family that is uncovered is the family that leaks"
    );
    fact("twinvpn_filters_installed", true);
    fact("twinvpn_owned_filters", installed.owned_filters);
    fact("twinvpn_posture", format!("{:?}", installed.posture));
}

/// The RUNTIME set — what the service commits at start step 5 — is accepted by
/// the engine, filter by filter, inside a transaction that is then aborted.
///
/// The boot-set probe above proves the engine takes writes; it says nothing
/// about the runtime set, whose class-7 bootstrap exemption carries an
/// `ALE_APP_ID` blob and an `ALE_USER_ID` security descriptor the boot set
/// does not. Run 33718660524 found that out inside the service:
/// `FwpmFilterAdd0` 1338 (`ERROR_INVALID_SECURITY_DESCR`), surfaced as
/// `POLICY.KILLSWITCH.ARM_FAILED`. This is the same set, rendered with this
/// process's own app id and a well-known SID, validated by the engine and
/// never committed.
#[test]
fn the_runtime_ruleset_is_accepted_by_the_engine_without_being_committed() {
    if !enabled("TWINVPN_WINDOWS_TEST") {
        panic!("TWINVPN_WINDOWS_TEST=1 is required: this probe opens the real engine");
    }
    let exe = std::env::current_exe().expect("this test has a path");
    let app_id = twinvpn_platform_windows::sys::win::wfp::app_id_for(&exe)
        .expect("the engine resolves this binary's app id");
    let config = wfp::EnforcementConfig {
        overlay_luid: 0,
        service_app_id: Box::leak(app_id.into_boxed_str()),
        // LocalSystem, resolvable on every host without a lookup. The dry run
        // validates the descriptor's shape, not who it names.
        service_sid: "S-1-5-18",
        local_network_access: true,
        on_link_prefixes: Vec::new(),
        updater_app_id: None,
        update_origins: Vec::new(),
        portal_grant: Vec::new(),
        doh_endpoints: Vec::new(),
    };
    let set = wfp::filters::render(
        &twinvpn_platform_windows::netcfg::prearming_contract(),
        wfp::Ruleset::Blocked,
        &config,
    );
    let engine = system();
    engine
        .filters()
        .dry_run(&set)
        .expect("the engine must accept every filter of the runtime Blocked set");
    fact("wfp_runtime_set_accepted", true);
    fact("wfp_runtime_set_filters", set.filters.len());
}
