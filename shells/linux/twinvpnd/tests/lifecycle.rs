//! **The test matrix**, process half: startup, shutdown, and UI/service
//! separation.
//!
//! **Authority:** ADR-0016 §11.6 (the start ordering), PS-1, PS-3, PS-7, PS-18,
//! PS-22; ADR-0017 §10.3, MI-20; ADR-0018 CB-2, CB-6; ADR-0023 EM-69, EM-70,
//! EM-71, EM-72; `ownership.md` §6 rule 7.
//!
//! Ten of the twelve required scenarios need a kernel and live in
//! `core/crates/twinvpn-platform-linux/tests/matrix.rs`. The three here are
//! **process** properties — what the agent does at start, what it does and does
//! not do on the way out, and what separates the privileged half from the
//! unprivileged one — and none of them needs `CAP_NET_ADMIN`, so they all run
//! under a plain `cargo test`.

use std::sync::Arc;

use twinvpnd::agent::{authority, events, health, StartSequence};

// ---------------------------------------------------------------------------
// 11. startup
// ---------------------------------------------------------------------------

/// **Startup**, as ADR-0016 §11.6's ordering rather than as a log to read.
///
/// The sequence is a value the diagnostic bundle can carry, so "which steps has
/// this build completed" is checkable rather than inferred — and PS-7's one
/// exception is checked *as* an exception, because it is the step most likely to
/// be quietly promoted into a prerequisite by someone tidying the code.
#[test]
fn matrix_startup_reaches_ready_only_after_every_step_except_the_boot_artifact() {
    let mut sequence = StartSequence::default();
    assert!(!sequence.ready(), "nothing done, nothing ready");

    // Each of the four preconditions, one at a time. A build that dropped one
    // would still pass a single all-true assertion.
    sequence.ruleset_reclaimed = true;
    assert!(!sequence.ready());
    sequence.privilege_verified = true;
    assert!(!sequence.ready());
    sequence.state_rehydrated = true;
    assert!(!sequence.ready());
    sequence.capabilities_probed = true;
    assert!(
        sequence.ready(),
        "§11.6: only then does it accept connections"
    );

    // PS-7's exception, and it is an exception in the SAFE direction: the boot
    // artifact is package-owned and "MUST NOT be a prerequisite for [the
    // authority] to apply". An agent that refused without it would leave the
    // host with neither the boot ruleset nor a running agent — the worse of the
    // two states, and a packaging problem turned into an outage.
    assert!(!sequence.boot_artifact_present);
    assert!(sequence.ready());
}

/// **Startup, PS-1's step.** The lock is taken before the first privileged
/// mutation, and a second authority is refused by name.
///
/// The whole point of the step wave 1 did not have: two agents programming one
/// host's `table inet twinvpn` and one host's routing table 52.
#[test]
fn matrix_startup_admits_exactly_one_authority_per_host() {
    let dir = std::env::temp_dir().join(format!("twinvpn-lifecycle-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("creates");

    let first = authority::take(&dir).expect("the first agent is the authority");
    let second = authority::take(&dir).expect_err("PS-1: exactly one per host");
    assert_eq!(
        second.reason_code(),
        "INTERNAL.INVARIANT_VIOLATED",
        "PS-1 names this condition itself, and the code IS registered"
    );

    // And the successor starts with no cleanup step, because a crash is a
    // supported way to exit (ADR-0012 KS-20).
    drop(first);
    let successor = authority::take(&dir).expect("no cleanup stands in the way");
    drop(successor);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 12. shutdown
// ---------------------------------------------------------------------------

/// **Shutdown — CB-6, which is the one that matters.**
///
/// > `begin_shutdown` must **not** tear down enforcement.
///
/// The rule exists because the tempting implementation is the wrong one: an
/// agent that "cleaned up after itself" on the way out would drop the host's
/// protection every time it restarted, and the window would be exactly as long
/// as the restart. ADR-0012 KS-20 states the same thing from the other side —
/// "a crash must leave the host blocked, never open".
///
/// The custody claim is the adapter's and is a property of nftables rather than
/// of our code: the table is kernel-resident, so it outlives the process.
#[test]
fn matrix_shutdown_leaves_enforcement_in_the_operating_systems_custody() {
    let adapter = adapter();
    let before = twinvpn_platform::NetworkConfig::enforcement_custody(adapter.network());
    assert!(
        before.survives_core_exit(),
        "CB-6: enforcement is in the OS's custody so the core going away cannot \
         drop protection"
    );

    twinvpn_platform::PlatformAdapter::begin_shutdown(&adapter);

    let after = twinvpn_platform::NetworkConfig::enforcement_custody(adapter.network());
    assert_eq!(
        before.survives_core_exit(),
        after.survives_core_exit(),
        "shutdown must not change the custody of the installed ruleset"
    );
    assert!(
        adapter.is_shutting_down(),
        "the shutdown latch is set, so new work is refused"
    );

    // And the swap is atomic in both directions, which is what makes a restart
    // safe: KS-23 requires an update to "replace the rule set by atomic swap,
    // never remove-then-add".
    assert!(after.swap_is_atomic);
}

/// **Shutdown — the event stream closes, and nothing is left waiting.**
///
/// `ownership.md` §6 rule 7: "the runtime stops accepting work, the event stream
/// closes so a drain thread unblocks, and the adapter is told last". A pump left
/// waiting on a closed stream is a connection task that never joins, and a
/// dispatcher left waiting for a command body is a client that hangs on the way
/// out — which §10.3 says is strictly worse than an error.
#[tokio::test]
async fn matrix_shutdown_closes_the_stream_and_settles_everything_waiting_on_it() {
    let fanout = Arc::new(events::Fanout::new());
    let subscriber = fanout.subscribe(events::SUBSCRIBER_WATERMARK);
    let (_id, waiting) = fanout.expect_completion("status.get", 1);
    assert_eq!(fanout.subscriber_count(), 1);

    fanout.close();

    assert!(fanout.is_closed());
    assert_eq!(
        fanout.subscriber_count(),
        0,
        "every subscriber is detached, so no pump waits on a stream that will \
         never publish again"
    );
    assert!(
        waiting.await.expect("settled, not abandoned").is_empty(),
        "a dispatcher waiting for a command body must be released on shutdown, \
         with the truthful empty answer rather than a hang"
    );
    // And a detached subscriber's reads are answered rather than blocking.
    assert!(fanout.next_for(subscriber).is_none());
}

/// **Shutdown — EM-69's health file says the agent is gone.**
///
/// > Escalation is **pull-first with three local push sinks**, and **no
/// > escalation path may be a TwinVPN-operated network service**.
///
/// A monitoring system that reads a stale "healthy" line after the agent has
/// exited has been told a falsehood by a file, which is the failure mode a
/// health file exists to prevent.
#[test]
fn matrix_shutdown_retracts_the_health_file_rather_than_leaving_it_stale() {
    let dir = std::env::temp_dir().join(format!("twinvpn-health-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("creates");

    let report = health::Report {
        state: "BLOCKED",
        worst_reason_code: "POLICY.KILLSWITCH.ENGAGED",
        as_of_ms: 1234,
        protection_asserted: true,
    };
    health::write(&dir, &report).expect("writes");
    let line = std::fs::read_to_string(dir.join(health::HEALTH_FILE)).expect("reads");
    assert!(line.contains("BLOCKED"), "{line}");
    assert!(line.contains("POLICY.KILLSWITCH.ENGAGED"), "{line}");

    health::retract(&dir);
    assert!(
        !dir.join(health::HEALTH_FILE).exists(),
        "a stale 'healthy' line outliving the agent is a monitoring system told \
         a falsehood by a file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 13. UI / service separation
// ---------------------------------------------------------------------------

/// **UI/service separation — PS-3.**
///
/// > Loss of the last management client MUST NOT change `session_intent`,
/// > enforcement mode, the installed rule set, or any `ConnectionState`.
///
/// This is the rule that separates a *client* from a *controller*. A build in
/// which closing the CLI disconnected the tunnel would be one in which the
/// service is a subordinate of its UI, and on a headless host (ADR-0023 EM-1's
/// H-SRV, which this is) there is no UI at all — so a dependency on one is a
/// dependency on something that never exists.
#[test]
fn matrix_ui_service_separation_the_agent_holds_no_state_a_client_can_take_away() {
    let fanout = events::Fanout::new();
    let a = fanout.subscribe(events::SUBSCRIBER_WATERMARK);
    let b = fanout.subscribe(events::SUBSCRIBER_WATERMARK);
    assert_eq!(fanout.subscriber_count(), 2);

    // Every client detaches. The agent's own state is untouched: the fan-out is
    // still open, still accepts publications, and still assigns cursors.
    fanout.unsubscribe(a);
    fanout.unsubscribe(b);
    assert_eq!(fanout.subscriber_count(), 0);
    assert!(
        !fanout.is_closed(),
        "PS-3: the last client leaving is not a shutdown signal"
    );

    // A new client attaching sees a live stream at the position the agent kept
    // while nobody was watching.
    let cursor = fanout.cursor();
    let late = fanout.subscribe(events::SUBSCRIBER_WATERMARK);
    assert_eq!(
        fanout.cursor(),
        cursor,
        "the cursor is the agent's, not a client's"
    );
    fanout.unsubscribe(late);
}

/// **UI/service separation — the unprivileged half links none of the privileged
/// one.**
///
/// ADR-0016 §11.2 puts the CLI and the authority in different processes with
/// different privileges, and ADR-0018 §11.16 (b) requires "one contract, two
/// carriages, **never two contracts**". `twinvpnctl` therefore depends on this
/// crate with `default-features = false`, which excludes the whole `agent`
/// feature — so the unprivileged binary links no tun, no nftables, no netlink
/// and no core-hosting code.
///
/// The assertion is on the **manifest**, because that is where the property
/// actually lives: a test that merely failed to call privileged code would pass
/// on a build that linked it anyway.
#[test]
fn matrix_ui_service_separation_the_cli_links_no_privileged_code() {
    let manifest = include_str!("../../twinvpnctl/Cargo.toml");
    assert!(
        manifest.contains("default-features = false"),
        "twinvpnctl must exclude the `agent` feature, or the unprivileged binary \
         links tun, nftables and netlink code it must never contain"
    );
    // And it does not reach the platform adapter or the core by another route.
    for forbidden in [
        "twinvpn-platform-linux",
        "twinvpn-core",
        "twinvpn-platform ",
        "libc",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "twinvpnctl's manifest names {forbidden}: the privilege split is a \
             property of what the process CAN do, not of what it chooses to call"
        );
    }

    // The one contract, in the one place. `mi` is compiled into both binaries
    // from this crate; a copy of the framing in each would be the second
    // contract MI-20 forbids.
    let agent_manifest = include_str!("../Cargo.toml");
    assert!(
        agent_manifest.contains("[lib]"),
        "this crate is a library as well as a binary precisely so the MI \
         envelope is declared once (MI-20)"
    );
}

/// **UI/service separation — PS-22, the server has no edge onto the datapath.**
///
/// > The management-interface server … MUST be a module with **no dependency
/// > edge** onto the tunnel engine, packet-routing, or enforcement modules: it
/// > reaches them only through the same typed operation vocabulary PS-4 defines.
///
/// Asserted on the source rather than on behaviour, because the rule is about
/// what the module *can* reach and not about what a particular call did.
#[test]
fn matrix_ui_service_separation_the_server_reaches_the_datapath_only_by_vocabulary() {
    let source = include_str!("../src/agent/server.rs");
    for forbidden in [
        "twinvpn_platform_linux::nft",
        "twinvpn_platform_linux::tun",
        "twinvpn_platform_linux::route",
        "twinvpn_platform_linux::netcfg",
    ] {
        // The rule is about what the module CAN reach, so the check is on CODE.
        // `server.rs`'s own documentation names these four deliberately, in
        // order to say it does not use them — and a check that fired on the
        // prose would make the honest comment the thing that fails the build.
        for (n, line) in source.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            assert!(
                !code.contains(forbidden),
                "PS-22: line {} of the MI server names {forbidden} in code; it \
                 must reach the datapath only through the typed operation \
                 vocabulary",
                n + 1
            );
        }
    }
    // The vocabulary it DOES use.
    assert!(source.contains("twinvpn_mgmt::"));
    assert!(source.contains("twinvpn_core::Core"));
}

// ---------------------------------------------------------------------------

fn adapter() -> twinvpn_platform_linux::LinuxPlatformAdapter {
    let dir = std::env::temp_dir().join(format!("twinvpn-lifecycle-a-{}", std::process::id()));
    twinvpn_platform_linux::LinuxPlatformAdapter::new(twinvpn_platform_linux::LinuxAdapterParts {
        enforcement: twinvpn_platform_linux::EnforcementConfig {
            overlay_interface: "twin0".to_owned(),
            firewall_mark: twinvpn_platform_linux::DEFAULT_FWMARK,
            cgroup_path: None,
            local_network_access: true,
            on_link_prefixes: Vec::new(),
        },
        store_root: dir.clone(),
        resolver_restore_point: dir.join("resolver.restore"),
        identity_element: Arc::new(twinvpn_platform_linux::AbsentElement),
    })
}
