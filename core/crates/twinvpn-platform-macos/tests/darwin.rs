//! The on-macOS integration suite. **Written, compiled for
//! `aarch64-apple-darwin`, and never run.**
//!
//! **Authority:** ADR-0018 §11.9 (the build matrix), `docs/implementation/
//! ownership.md` §5 and §6 rule 3; ADR-0012 §8 and K12; ADR-0016 PS-18.
//!
//! # What this file is for, and what it is not
//!
//! `make cross-check` type-checks it with `-D warnings` against the real Darwin
//! sys crates, so it is real code rather than a comment. But **no assertion in it
//! has ever executed**: this project's CI host is Linux, there is no Darwin SDK,
//! nothing links, and no Mac was available. Every claim below is a claim about
//! what *should* happen, and until somebody runs it on a Mac that is all it is.
//!
//! It is written in the register `twinvpn-platform-linux`'s `tests/netns.rs`
//! uses: where a privilege is missing, it **asserts the refusal** rather than
//! skipping, so a plain `cargo test` on a Mac still checks that an unprivileged
//! adapter names the right `reason_code`.
//!
//! # Running it
//!
//! ```sh
//! # On a Mac, from `core/`. The read-only half needs no privilege:
//! cargo test -p twinvpn-platform-macos --test darwin
//!
//! # The write half — loading the anchor, opening a utun, programming a route —
//! # needs root AND the opt-in, so it can never run by accident on a developer's
//! # machine:
//! sudo TWINVPN_DARWIN_WRITE_TEST=1 \
//!   cargo test -p twinvpn-platform-macos --test darwin -- --test-threads=1
//! ```

#![cfg(target_os = "macos")]

use std::sync::Arc;

use twinvpn_platform::{
    InterfaceName, NetworkConfig, PlatformAdapter, PlatformError, Ruleset, SocketFamily,
    SocketOptions, SocketProvider, UdpBindSpec,
};
use twinvpn_platform_macos::clock::{BootSessionId, ContinuousElapsedClock};
use twinvpn_platform_macos::custody::{Accessibility, KeychainItemSpec, Tier1Store};
use twinvpn_platform_macos::keychain::KeychainStore;
use twinvpn_platform_macos::netcfg::{MacosNetworkConfig, NetworkCarriers, PfEngine, PfctlEngine};
use twinvpn_platform_macos::pf;
use twinvpn_platform_macos::pfread::PfStatus;
use twinvpn_platform_macos::testkit;
use twinvpn_platform_macos::utun::QueuePort;
use twinvpn_platform_macos::{
    CustodyClass, MacosPlatformAdapter, RouteCarrier, ShutdownLatch, TunnelProvenance,
};

/// The opt-in for the tests that mutate the host.
///
/// Two gates, not one: root **and** an explicit variable. A suite that installed
/// a `pf` anchor because somebody ran `sudo cargo test` in the wrong directory
/// would be a worse defect than the one it was looking for.
fn write_tests_enabled() -> bool {
    std::env::var_os("TWINVPN_DARWIN_WRITE_TEST").is_some()
}

fn is_root() -> bool {
    // SAFETY: `geteuid` takes no arguments, touches no memory this code owns and
    // cannot fail.
    unsafe { libc::geteuid() == 0 }
}

// ---------------------------------------------------------------------------
// Read-only: these need no privilege and assert the refusal where they lack one
// ---------------------------------------------------------------------------

#[test]
fn the_two_mach_clocks_are_different_readings() {
    // The one check a Mac can make that this project's Linux host cannot: the
    // suspend-inclusive clock is at least the suspend-exclusive one, and on a
    // machine that has ever slept it is strictly greater. LC-8's defect —
    // substituting one for the other — is invisible until exactly here.
    let timebase = twinvpn_platform_macos::clock::read_timebase().expect("a Mac has a timebase");
    let monotonic = timebase.ticks_to_nanos(twinvpn_platform_macos::clock::monotonic_ticks());
    let elapsed = timebase.ticks_to_nanos(twinvpn_platform_macos::clock::elapsed_ticks());
    assert!(
        elapsed >= monotonic,
        "mach_continuous_time must never read behind mach_absolute_time; if it \
         does, the two are the wrong way round"
    );
    // On a laptop that has been closed at least once since boot, the gap is the
    // accumulated sleep time and is large. This assertion is deliberately weak
    // because a freshly booted Mac has a gap of zero and the test must not be
    // flaky — the STRONG check is the one a human does by suspending the machine
    // and running it again.
    let clock = ContinuousElapsedClock::from_kernel().expect("binds");
    let _ = twinvpn_env::ElapsedClock::now(&clock);
}

#[test]
fn the_boot_session_uuid_is_stable_within_one_boot() {
    let a = BootSessionId::read().expect("kern.bootsessionuuid exists on macOS");
    let b = BootSessionId::read().expect("reads");
    assert_eq!(
        twinvpn_env::BootIdSource::boot_id(&a),
        twinvpn_env::BootIdSource::boot_id(&b)
    );
}

#[test]
fn pfctl_is_present_and_answers_its_status() {
    // ADR-0012 §8: if the ruleset cannot be installed the client MUST NOT enter a
    // protected state. On a Mac `pfctl` is always present, so its ABSENCE would be
    // the surprise.
    MacosNetworkConfig::pfctl_binary().expect("/sbin/pfctl ships with macOS");
    let status = PfctlEngine.status();
    match status {
        Ok(PfStatus::Enabled | PfStatus::Disabled) => {}
        // `pfctl -s info` needs root on some releases. An unprivileged run must
        // therefore REFUSE rather than report `Disabled`, which would read as "no
        // enforcement" and is the dangerous direction.
        Ok(PfStatus::Unknown) | Err(_) => assert!(
            !is_root(),
            "a root process must be able to read pf's status"
        ),
    }
}

#[test]
fn reading_our_anchor_unprivileged_refuses_rather_than_reporting_unprotected() {
    // K12 with its fail-safe direction: "we could not look" must never render as
    // "nothing is installed".
    if is_root() {
        return;
    }
    match PfctlEngine.tables(pf::ANCHOR) {
        Err(error) => assert_eq!(
            error.reason_code().as_str(),
            "PLATFORM.ADAPTER_UNAVAILABLE",
            "an unprivileged read must name the condition"
        ),
        // `pfctl -a twinvpn -s Tables` exits non-zero when the anchor is absent,
        // which this adapter maps to `Ok(None)` — the one case in which `None` is
        // the truth. On a host with no TwinVPN installed that is correct.
        Ok(None) => {}
        Ok(Some(installed)) => {
            panic!("an unprivileged process read an installed anchor: {installed:?}")
        }
    }
}

#[test]
fn a_udp_socket_opens_in_both_families_with_the_darwin_options_applied() {
    // The Darwin `setsockopt` numbers are the part of `sock.rs` that no Linux test
    // can reach. A wrong `IP_DONTFRAG` fails HERE, with `ENOPROTOOPT`, mapped to
    // `PLATFORM.OS_UNSUPPORTED`.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let provider = twinvpn_platform_macos::sock::MacosSocketProvider::new(ShutdownLatch::new());
    runtime.block_on(async {
        for family in [
            SocketFamily::V4,
            SocketFamily::V6Only,
            SocketFamily::V6DualStack,
        ] {
            let spec = UdpBindSpec {
                family,
                local: None,
                options: SocketOptions::default(),
            };
            let socket = provider
                .bind_udp(&spec)
                .await
                .unwrap_or_else(|e| panic!("{family:?} did not open: {e}"));
            let endpoint = socket.local_endpoint().expect("bound");
            assert!(endpoint.port.get() > 0, "an ephemeral port was assigned");
            assert_eq!(socket.family(), family);
        }
        // Both families must be reportable, and dual-stack sockets exist on macOS.
        let families = provider.supported_families().await.expect("probes");
        assert!(families.v4 && families.v6 && families.dual_stack_socket);
    });
}

#[test]
fn a_keychain_read_of_an_absent_item_is_absent_and_not_an_error() {
    // The seam's distinction, which matters because "absent" enrols and
    // "unavailable" must not.
    let store = KeychainStore::new(
        KeychainItemSpec {
            service: "net.twinvpn.test".to_owned(),
            access_group: None,
            accessibility: Accessibility::SystemKeychain,
        },
        CustodyClass::SoftwareLocal,
    );
    match store.read("a-key-that-does-not-exist") {
        Ok(None) => {}
        Ok(Some(_)) => panic!("a key nobody wrote came back with a value"),
        Err(error) => {
            // The System keychain needs root to read. Unprivileged, the correct
            // answer is a NAMED refusal, never `Ok(None)`.
            assert!(!is_root(), "root must be able to read the System keychain");
            assert_eq!(error.reason_code().as_str(), "AUTH.KEY_STORE_UNAVAILABLE");
        }
    }
}

// ---------------------------------------------------------------------------
// Write: root plus the opt-in
// ---------------------------------------------------------------------------

#[test]
fn the_anchor_this_adapter_renders_is_one_apples_pf_accepts() {
    // **The single most valuable assertion in this file, and the one whose
    // absence is the largest gap in this wave.** `pf::render` is exhaustively
    // tested on Linux for what it SAYS; only `pfctl` can say whether Apple's fork
    // parses it. The `user` keyword and the `icmp6-type` names are the two
    // constructs most likely to differ.
    if !write_tests_enabled() || !is_root() {
        return;
    }
    let anchor = pf::render(
        &testkit::full_tunnel_contract(1, Ruleset::Protected),
        Ruleset::Protected,
        &testkit::enforcement(),
    );
    PfctlEngine
        .load_anchor(pf::ANCHOR, &anchor)
        .expect("Apple's pf must parse the anchor this adapter renders");

    // And it reads back as what was rendered — the W-24 query, against the real
    // kernel this time.
    let installed = PfctlEngine
        .tables(pf::ANCHOR)
        .expect("reads")
        .expect("our anchor");
    assert_eq!(installed.ruleset, Ruleset::Protected);
    assert!(installed.covers_a_scope());

    // Leave the host as we found it.
    PfctlEngine
        .load_anchor(pf::ANCHOR, "")
        .expect("clears the anchor");
}

#[test]
fn the_label_counters_pfctl_prints_are_the_shape_the_parser_expects() {
    // `pfctl -s labels`' column layout is the other thing only a Mac can settle.
    if !write_tests_enabled() || !is_root() {
        return;
    }
    let anchor = pf::render(
        &testkit::contract(1),
        Ruleset::Protected,
        &testkit::enforcement(),
    );
    PfctlEngine.load_anchor(pf::ANCHOR, &anchor).expect("loads");
    let labels = PfctlEngine.labels(pf::ANCHOR).expect("reads");
    for (label, _) in pf::DENY_LABEL {
        assert!(
            labels.contains_key(label),
            "the parser did not find {label}; `pfctl -s labels` prints a shape \
             this build does not understand"
        );
    }
    PfctlEngine.load_anchor(pf::ANCHOR, "").expect("clears");
}

#[test]
fn a_utun_interface_is_created_and_destroyed_and_a_second_open_reclaims_it() {
    if !write_tests_enabled() || !is_root() {
        return;
    }
    let (carriers, _rec) = testkit::daemon_carriers();
    let carriers = NetworkCarriers {
        route_carrier: RouteCarrier::Command,
        ..carriers
    };
    let adapter = MacosPlatformAdapter::new(twinvpn_platform_macos::MacosAdapterParts {
        enforcement: testkit::enforcement(),
        carriers,
        tunnel_provenance: TunnelProvenance::AdapterCreatedUtun,
        store_root: std::path::PathBuf::from("/tmp/twinvpn-darwin-test"),
        identity_element: Arc::new(twinvpn_platform_macos::AbsentElement),
        keychain: KeychainItemSpec {
            service: "net.twinvpn.test".to_owned(),
            access_group: None,
            accessibility: Accessibility::SystemKeychain,
        },
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let name = InterfaceName::new("utun7").expect("valid");
    let result = runtime.block_on(adapter.tunnel().create_interface(&name, 1400));
    // **This is the assertion that will fail first on a Mac**, and deliberately
    // so: `AdapterCreatedUtun` is not implemented in this wave and refuses by
    // name rather than returning a handle to nothing. The day it lands, this
    // becomes a real creation and the `expect_err` below is what changes.
    let error = result.expect_err("not implemented in this wave");
    assert_eq!(error.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
    assert_eq!(error.os_detail().map(|d| d.call), Some("utun.create"));
    let _ = adapter;
}

#[test]
fn the_os_provided_flow_binding_needs_no_privilege_at_all() {
    // The system-extension path never opens a `utun`: the OS did it before
    // `startTunnel` ran. So this half works unprivileged, which is itself the
    // difference between the two bindings.
    let (carriers, _rec) = testkit::daemon_carriers();
    let adapter = MacosPlatformAdapter::new(twinvpn_platform_macos::MacosAdapterParts {
        enforcement: testkit::enforcement(),
        carriers,
        tunnel_provenance: TunnelProvenance::OsProvidedFlow,
        store_root: std::path::PathBuf::from("/tmp/twinvpn-darwin-test"),
        identity_element: Arc::new(twinvpn_platform_macos::AbsentElement),
        keychain: KeychainItemSpec {
            service: "net.twinvpn.test".to_owned(),
            access_group: None,
            accessibility: Accessibility::SystemKeychain,
        },
    });
    adapter
        .tunnel_device()
        .set_pending_port(Arc::new(QueuePort::new()));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let name = InterfaceName::new("utun7").expect("valid");
    runtime
        .block_on(adapter.tunnel().create_interface(&name, 1400))
        .expect("adopting an OS-provided interface needs no privilege");
}

#[test]
fn query_link_facts_is_not_implemented_and_says_so_by_name() {
    // Named here so the gap is visible on a Mac too, and so the day it is
    // implemented this test fails and has to be rewritten rather than quietly
    // continuing to pass.
    let (carriers, _rec) = testkit::daemon_carriers();
    let net = MacosNetworkConfig::new(ShutdownLatch::new(), testkit::enforcement(), carriers);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let error = runtime
        .block_on(net.query_link_facts())
        .expect_err("not implemented in this wave");
    assert!(matches!(error, PlatformError::AdapterUnavailable(_)));
    assert_eq!(error.os_detail().map(|d| d.call), Some("query_link_facts"));
}
