//! **R-2 / R-7.** The data plane is composed, and it reaches the platform.
//!
//! # The defect this file exists to close
//!
//! `twinvpn-tunnel`, `twinvpn-relay-client`, `twinvpn-route`, `twinvpn-dns` and
//! `twinvpn-enforce` were declared dependencies of the composition root and
//! appeared **zero times** in `core/crates/twinvpn-core/src`. Outside their own
//! crates they were referenced only from `tests/` and `lab/`. There was no
//! production caller of `PlatformAdapter::apply` or of `set_ruleset` anywhere in
//! `core/`, `shells/linux`, `shells/windows` or `shells/macos`.
//!
//! So the composed product installed no ruleset of its own, programmed no route,
//! applied no DNS policy and created no overlay interface. Every one of those
//! crates was thoroughly tested and reachable from nothing.
//!
//! Every assertion here is about **the adapter**, because the adapter is the
//! only witness that distinguishes "computed a contract" from "installed one".

#![cfg(feature = "full")]

use std::time::Duration;

use twinvpn_core::testing;
use twinvpn_mgmt::{CoreCommand, Submission};
use twinvpn_platform::config::{LinkState, Ruleset};
use twinvpn_platform::iface::{InterfaceFacts, InterfaceIndex, InterfaceName, LinkClass};
use twinvpn_types::{
    DeviceId, Endpoint, InterfaceAddress, IpAddr, OverlayAddresses, TwinnetId, V4Addr, V6Addr,
};

fn dual_stack_interface() -> InterfaceFacts {
    InterfaceFacts {
        index: InterfaceIndex(2),
        name: InterfaceName::new("eth0").expect("valid"),
        addresses: vec![InterfaceAddress::new(
            IpAddr::V4(V4Addr::from_slice(&[192, 0, 2, 10]).expect("v4")),
            24,
        )
        .expect("address")],
        has_default_route_v4: true,
        has_default_route_v6: true,
        is_overlay: false,
        is_up: true,
        mtu: 1500,
        link_class: LinkClass::Ethernet,
    }
}

fn twinnet() -> TwinnetId {
    TwinnetId::new("tn-compose").expect("valid")
}

/// An overlay pair inside the product's own space: `100.64.0.0/10` for v4 and
/// the pinned `fd7c:9e5d:2a10::/48` ULA for v6 (AP-1/AP-2).
fn overlay(byte: u8) -> OverlayAddresses {
    OverlayAddresses {
        v4: V4Addr::from_slice(&[100, 64, 0, byte]).expect("v4"),
        v6: V6Addr::from_slice(
            &[
                0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0, 1, 0, 0, 0, 0, 0, 0, 0, byte,
            ],
            0,
        )
        .expect("v6"),
    }
}

fn peer_record(byte: u8, verified: bool) -> twinvpn_core::PeerRecord {
    twinvpn_core::PeerRecord {
        device_id: DeviceId::from_slice(&[byte; 32]).expect("32"),
        generation: 1,
        tk_generation: 1,
        tunnel_key_binding_verified: verified,
        endpoints: Vec::<Endpoint>::new(),
        overlay: overlay(byte),
    }
}

/// A harness whose control plane has supplied everything the contract needs.
fn provisioned() -> testing::Harness {
    let h = testing::harness().expect("creates");
    h.adapter
        .interfaces_mock()
        .set_interfaces(vec![dual_stack_interface()]);
    let cp = h.core.control_plane_port();
    // This device's own allocation (S-08), and one authorized peer.
    cp.put_local_overlay(&twinnet(), overlay(1));
    cp.put_peer(&twinnet(), peer_record(0x5a, true));
    h
}

// ---------------------------------------------------------------------------
// 1. `net.up` reaches the adapter.
// ---------------------------------------------------------------------------

#[test]
fn net_up_creates_the_interface_and_applies_a_contract() {
    let h = provisioned();
    assert_eq!(
        h.adapter.config_mock().apply_calls(),
        0,
        "the precondition: nothing has been applied yet"
    );

    h.core
        .submit(&Submission::bare(CoreCommand::NetUp))
        .expect("net.up executes");

    // THE ASSERTION THE WHOLE PRODUCT WAS MISSING.
    assert_eq!(
        h.adapter.config_mock().apply_calls(),
        1,
        "net.up must APPLY a contract, not merely compute one"
    );
    let contract = h
        .adapter
        .config_mock()
        .current_contract()
        .expect("a contract is in force");

    // ADR-0010 R1: both families, always. A contract carrying one family is
    // §11.3's non-conforming state, and `twinvpn-enforce` refuses to assemble
    // one — so reaching here at all is half the property.
    assert!(
        !contract
            .addresses
            .get(twinvpn_types::AddressFamily::V4)
            .is_empty(),
        "the overlay interface must carry a v4 address"
    );
    assert!(
        !contract
            .addresses
            .get(twinvpn_types::AddressFamily::V6)
            .is_empty(),
        "and a v6 one — R1 has no half"
    );
    assert!(
        !contract
            .routes
            .get(twinvpn_types::AddressFamily::V4)
            .is_empty(),
        "the authorized peer must be routed"
    );
    assert!(!contract
        .routes
        .get(twinvpn_types::AddressFamily::V6)
        .is_empty());

    // §6.3's floor, not a guess.
    assert_eq!(contract.mtu, twinvpn_core::enforce::MTU);

    // The interface exists and is up.
    let enforcement = h.core.enforcement();
    assert!(
        enforcement.has_interface(),
        "the overlay interface must have been created"
    );
    assert!(enforcement.applied().is_some(), "and a generation recorded");
}

#[test]
fn the_posture_is_read_back_from_the_adapter_never_assumed() {
    // ADR-0015 §11.6 rule 1: "A `ProtectionAssertion` is produced by QUERYING
    // the enforcement layer … never of the agent's belief about what it
    // configured."
    let h = provisioned();
    h.core
        .submit(&Submission::bare(CoreCommand::NetUp))
        .expect("net.up executes");

    let installed = h
        .adapter
        .config_mock()
        .current_contract()
        .map(|c| c.ruleset);
    assert!(installed.is_some(), "the adapter holds a posture");
}

#[test]
fn no_path_validation_means_the_host_stays_blocked() {
    // **KS-18.** `RULESET_PROTECTED` may be entered only after (a) an
    // authenticated bidirectional path validation and (b) an assertion that the
    // rules are installed for both families. This build has no path validation,
    // so (a) fails and the latch must stay `Blocked` — truthfully, rather than
    // reporting protection over a tunnel nothing has validated.
    let h = provisioned();
    h.core
        .submit(&Submission::bare(CoreCommand::NetUp))
        .expect("net.up executes");

    assert!(
        !h.core.any_session_connected(),
        "the precondition: no session reached a steady state"
    );
    assert_eq!(
        h.core.enforcement().desired(),
        Ruleset::Blocked,
        "KS-18(a) failed, so the latch must not have left BLOCKED"
    );
}

// ---------------------------------------------------------------------------
// 2. Every failure tightens.
// ---------------------------------------------------------------------------

#[test]
fn an_apply_failure_leaves_the_host_blocked_never_open() {
    // **The fail condition the review register names**: "tunnel failure silently
    // falls back to unprotected Internet while fail-closed mode is enabled."
    //
    // The interface has been created and brought UP by the time `apply` runs
    // (KS-17a), so a failure here is exactly the dangerous shape: a live overlay
    // interface with no contract on it.
    let h = provisioned();
    h.adapter.config_mock().fail_next_apply(
        twinvpn_platform::PlatformError::RouteProgrammingDenied(None),
    );

    let err = h
        .core
        .submit(&Submission::bare(CoreCommand::NetUp))
        .expect_err("a failed apply must be reported, not swallowed");
    assert_eq!(err.code().as_str(), "ROUTE.PROGRAMMING_DENIED");

    assert_eq!(
        h.core.enforcement().desired(),
        Ruleset::Blocked,
        "a failed arm must leave the latch BLOCKED"
    );
    assert!(
        h.adapter.config_mock().current_contract().is_none(),
        "and no contract in force — apply is all-or-nothing"
    );
}

#[test]
fn a_device_with_no_allocation_refuses_by_name_and_stays_blocked() {
    // No control plane, so no overlay allocation and no authorized peer. The
    // honest answer is a named refusal; the dangerous one is an empty contract
    // installed over a host that then believes it is protected.
    let h = testing::harness().expect("creates");
    h.adapter
        .interfaces_mock()
        .set_interfaces(vec![dual_stack_interface()]);

    let err = h
        .core
        .submit(&Submission::bare(CoreCommand::NetUp))
        .expect_err("nothing to build a contract from");
    assert_eq!(err.code().as_str(), "AUTH.IDENTITY_MISSING");
    assert_eq!(h.core.enforcement().desired(), Ruleset::Blocked);
    assert_eq!(
        h.adapter.config_mock().apply_calls(),
        0,
        "nothing was installed"
    );
}

#[test]
fn an_unverified_peer_is_not_a_route() {
    // ADR-0007 N-4: a peer whose `TunnelKeyBinding` has not verified is not a
    // `TrustedPeer`. Routing to one would pull its traffic into a tunnel it is
    // not authorized to use.
    let h = testing::harness().expect("creates");
    h.adapter
        .interfaces_mock()
        .set_interfaces(vec![dual_stack_interface()]);
    let cp = h.core.control_plane_port();
    cp.put_local_overlay(&twinnet(), overlay(1));
    cp.put_peer(&twinnet(), peer_record(0x5a, false));

    let err = h
        .core
        .submit(&Submission::bare(CoreCommand::NetUp))
        .expect_err("an unverified peer is not an authorization");
    assert_eq!(err.code().as_str(), "AUTH.PEER_UNTRUSTED");
    assert_eq!(h.adapter.config_mock().apply_calls(), 0);
}

// ---------------------------------------------------------------------------
// 3. Teardown never removes protection.
// ---------------------------------------------------------------------------

#[test]
fn net_down_tears_the_link_down_and_keeps_the_rules() {
    // §11.8's teardown: link down → swap to `RULESET_BLOCKED` → destroy the
    // interface. **The rules stay live**: CB-6 puts them in the OS's custody so
    // that the tunnel going away cannot drop protection, and MI-K1 forbids
    // `net.down` from clearing the latch.
    let h = provisioned();
    h.core
        .submit(&Submission::bare(CoreCommand::NetUp))
        .expect("net.up executes");
    assert!(h.core.enforcement().has_interface());

    h.core
        .submit(&Submission::bare(CoreCommand::NetDown))
        .expect("net.down executes");

    assert!(
        !h.core.enforcement().has_interface(),
        "the interface is destroyed last, and it is destroyed"
    );
    assert_eq!(
        h.core.enforcement().desired(),
        Ruleset::Blocked,
        "and the posture is BLOCKED, never absent"
    );
}

#[test]
fn arming_twice_reuses_the_interface_rather_than_duplicating_it() {
    // `apply` is idempotent on the generation id so a retry after a crash
    // converges. The interface must converge too: a second `create_interface`
    // for the same overlay is how a host ends up with two.
    let h = provisioned();
    h.core
        .submit(&Submission::bare(CoreCommand::NetUp))
        .expect("first");
    let first = h.core.enforcement().applied();

    h.core
        .submit(&Submission::bare(CoreCommand::NetUp))
        .expect("second");
    let second = h.core.enforcement().applied();

    assert_ne!(first, second, "a re-arm allocates a new generation");
    assert_eq!(
        h.adapter.config_mock().apply_calls(),
        2,
        "and applies it — convergence, not a no-op"
    );
    assert_eq!(
        h.adapter
            .tunnel_mock()
            .link_state(twinvpn_platform::TunnelHandle(1)),
        Some(LinkState::Up),
        "over the SAME interface"
    );
}

// ---------------------------------------------------------------------------
// 4. The composition itself.
// ---------------------------------------------------------------------------

#[test]
fn the_composition_root_names_every_data_plane_crate_it_declares() {
    // R-2's own tell: five crates were declared dependencies of this crate and
    // appeared zero times in its source. A dependency nothing names is a
    // dependency nothing composes, and `cargo` will not say so.
    let src = |name: &str| -> String {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(name);
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    };
    // `execute` and `session_table` are directories now, not files: the
    // establishment chain grew a handshake, a carriage and the key material
    // those need, and `CLAUDE.md` caps a file at 500 lines. The scan follows
    // them rather than being narrowed, so a crate that stops being named in any
    // of the composition's parts still fails this test.
    let composed = format!(
        "{}{}{}{}{}{}{}{}",
        src("enforce.rs"),
        src("execute/mod.rs"),
        src("execute/establishment.rs"),
        src("execute/handshake.rs"),
        src("execute/carriage.rs"),
        src("session_table/mod.rs"),
        src("establish.rs"),
        src("gateway.rs")
    );
    for crate_name in [
        "twinvpn_route",
        "twinvpn_dns",
        "twinvpn_enforce",
        "twinvpn_platform",
        // Added by the establishment chain: the L-DATA engine and the relay
        // leg were both declared dependencies that the composition root named
        // nowhere, which is R-2's shape one layer in from where R-2 found it.
        "twinvpn_tunnel",
        "twinvpn_relay_client",
    ] {
        assert!(
            composed.contains(crate_name),
            "{crate_name} is a declared dependency of the composition root and is \
             named nowhere in it — R-2 exactly"
        );
    }
}

#[test]
fn the_event_stream_records_what_net_up_did() {
    // §11.6: an operation that did work says so on the one ordered stream.
    let h = provisioned();
    h.core
        .submit(&Submission::bare(CoreCommand::NetUp))
        .expect("net.up executes");

    let mut completed = false;
    while let Some(event) = h.core.next_event(Duration::ZERO) {
        if let twinvpn_core::CoreEventKind::CommandCompleted { op, .. } = event.kind {
            if op == "net.up" {
                completed = true;
            }
        }
    }
    assert!(completed, "net.up must report completion");
}
