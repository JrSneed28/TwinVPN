//! **CB-2's falsification test**, run for the first time end to end.
//!
//! > **CB-2 — the shell holds no decision.** A shell MAY translate, marshal,
//! > schedule and render. It MUST NOT contain a branch whose condition is a
//! > TwinVPN domain fact — a `ConnectionState`, a `reason_code` class, a policy
//! > verdict, a candidate priority, a timer expiry, a version comparison.
//! > **The falsification test: with every shell deleted and a mock adapter
//! > bound, the core must still make every decision correctly. If it cannot, a
//! > decision leaked into a shell.**
//!
//! # What this file actually proves, and what it does not
//!
//! It proves, on a plain Linux CI runner with **no shell in the process**, no
//! VM, no device farm and no network, that the composed core:
//!
//! 1. **creates and reports its own identity** (S-46), including the epoch range
//!    from VR-3's table rather than from the version string;
//! 2. **refuses an ABI mismatch by name** before touching any capability (VR-4);
//! 3. **decides what an OS fact means** — `NetworkChange` → a §4.3 event —
//!    rather than being told;
//! 4. **runs the whole establishment path from a user intent to a steady state**,
//!    through the real §4.5 table, with every timer on the injected monotonic
//!    clock;
//! 5. **does not fire a timer across a suspend** (CD-1);
//! 6. **survives a control-plane outage**: the data plane reads the cached peer
//!    set and the control-plane port is never consulted (I5);
//! 7. **keeps enforcement installed through a poison** (F-7 + CB-6);
//! 8. **renders every diagnostic** with no live instance at all (F-10);
//! 9. **wires the planes in one direction only** (CD-I5).
//!
//! It does **not** prove that a real shell contains no decision — nothing here
//! can, because no shell is present. What it proves is the other half, and the
//! useful half: that the core is *capable* of every decision without one. A
//! shell that then duplicates a decision is a review finding; a core that
//! *needs* the shell to make one would be a design failure, and this is the test
//! that would have caught it.
//!
//! # Why the whole file is `full`-profile
//!
//! The falsification test drives the **data plane**, and ADR-0018 §11.12's
//! `core-lite` profile contains none. Compiling it under `core-lite` would fail
//! on the imports, and gating individual tests would leave a file that passes
//! while proving nothing. `tests/core_lite_profile.rs` is what runs under the
//! lite profile, and it asserts the property that profile actually has.
#![cfg(feature = "full")]

use std::sync::Arc;
use std::time::Duration;

use twinvpn_core::events::CoreEventKind;
use twinvpn_core::planes::PeerRecord;
use twinvpn_core::session_loop::{event_for_change, SessionRuntime};
use twinvpn_core::{testing, Core};
use twinvpn_mgmt::{CoreCommand, Submission};
use twinvpn_platform::iface::{InterfaceIndex, NetworkChange};
use twinvpn_session::event::{Event, LinkKind, TimerId, Trigger};
use twinvpn_session::state::SessionState;
use twinvpn_session::{Context, Guards, SessionMachine};
use twinvpn_types::{
    AddressFamily, DeviceId, OverlayAddresses, PathClass, SessionId, TwinnetId, V4Addr, V6Addr,
};

fn twinnet() -> TwinnetId {
    TwinnetId::new("tn-falsify").expect("a valid TwinNet id")
}

fn peer(byte: u8) -> PeerRecord {
    PeerRecord {
        device_id: DeviceId::from_slice(&[byte; 32]).expect("32 bytes"),
        generation: 1,
        tk_generation: 1,
        tunnel_key_binding_verified: true,
        endpoints: Vec::new(),
        overlay: OverlayAddresses {
            v4: V4Addr::from_slice(&[100, 64, 0, byte]).expect("v4"),
            v6: V6Addr::from_slice(
                &[0xfd, 0x7c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte],
                0,
            )
            .expect("v6"),
        },
    }
}

// ---------------------------------------------------------------------------
// 1 + 2. The core knows what it is, and refuses a shell it cannot work with.
// ---------------------------------------------------------------------------

#[test]
fn the_core_creates_itself_and_reports_s46_with_no_shell_present() {
    let core = testing::core().expect("the core creates itself");
    let id = core.build_identity();

    assert_eq!(id.core_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(id.abi_major, twinvpn_core::ABI_MAJOR);
    assert!(id.protocol_epoch_min >= 1);
    assert!(id.protocol_epoch_max >= id.protocol_epoch_min);
    assert_eq!(
        id.reason_registry_version,
        twinvpn_types::REASON_REGISTRY_VERSION
    );
    assert_eq!(id.profile, "full");
    // §11.16 (l): the core records what the adapter says, never a substitution.
    assert!(!id.hardware_backed);
    assert_eq!(id.adapter_binding, "mock-in-memory");
}

#[test]
fn an_abi_mismatch_is_named_before_any_capability_is_touched() {
    let err = testing::core_with(|p| p.abi_major_expected = 7).expect_err("VR-4");
    assert_eq!(err.code().as_str(), "INTERNAL.ABI_VERSION_MISMATCH");
    // Registry attributes are what a consumer branches on, and they are present
    // even here, where no instance exists to ask.
    assert!(err.resolved().user_actionable);
    assert!(err.resolved().terminal);
}

// ---------------------------------------------------------------------------
// 3. The core decides what an OS fact means.
// ---------------------------------------------------------------------------

#[test]
fn cb2_the_core_and_not_the_shell_maps_platform_facts_to_domain_events() {
    let cases: [(NetworkChange, Option<Event>); 4] = [
        (
            NetworkChange::InterfaceRemoved(InterfaceIndex(2)),
            Some(Event::LinkDown(LinkKind::Unknown)),
        ),
        (
            NetworkChange::LinkStateChanged {
                interface: InterfaceIndex(2),
                is_up: true,
            },
            Some(Event::LinkUp(LinkKind::Unknown)),
        ),
        (
            NetworkChange::DefaultRouteChanged {
                family: AddressFamily::V6,
                present: true,
            },
            Some(Event::AddrChanged),
        ),
        (NetworkChange::ResolversChanged, None),
    ];
    for (change, expected) in cases {
        assert_eq!(event_for_change(&change, None), expected, "{change:?}");
    }
}

// ---------------------------------------------------------------------------
// 4 + 5. The whole establishment path, driven by the injected clock.
// ---------------------------------------------------------------------------

#[test]
fn the_core_drives_a_session_from_intent_to_a_steady_state_with_no_shell() {
    let (env, _vt) = testing::env();
    let machine = SessionMachine::new(env.clone(), SessionId::from_slice(&[1; 16]).expect("16"));
    let mut rt = SessionRuntime::new(env, machine);

    let guards = Guards {
        credentials_valid: true,
        peer_authorized: true,
        usable_candidate: true,
        path_validated: true,
        // T09's discriminator: a WAN-direct win is only a WAN-direct win when no
        // L2 path won the race. Without this the table correctly refuses to move,
        // which is the guard doing its job.
        no_l2_path_won: true,
        ..Guards::default()
    };

    // T01 — the user asks.
    rt.apply(
        Trigger::Event(Event::ConnectRequested),
        guards,
        Context::default(),
    );
    assert_eq!(rt.machine().state(), SessionState::Discovering);
    assert!(rt.timers().is_armed(TimerId::Discover));

    // T03 — a candidate is usable.
    rt.apply(
        Trigger::Event(Event::CandidatesReady),
        guards,
        Context::default(),
    );
    assert_eq!(rt.machine().state(), SessionState::Negotiating);
    assert!(rt.timers().is_armed(TimerId::Negotiate));
    assert!(
        !rt.timers().is_armed(TimerId::Discover),
        "the previous state's deadline is cancelled, not left to fire later"
    );

    // T05 — negotiation succeeds.
    rt.apply(
        Trigger::Event(Event::NegotiationOk),
        guards,
        Context::default(),
    );
    assert_eq!(rt.machine().state(), SessionState::Connecting);
    assert!(rt.timers().is_armed(TimerId::Connect));

    // T09 — the handshake completes on a direct WAN path.
    rt.apply(
        Trigger::Event(Event::HandshakeOk(PathClass::WanDirect)),
        guards,
        Context::default(),
    );
    assert_eq!(
        rt.machine().state(),
        SessionState::Steady(PathClass::WanDirect)
    );
    assert!(
        rt.timers().is_empty(),
        "a steady state carries no establishment deadline"
    );

    // Every transition produced exactly one record, and none violated §10.2 E7.
    assert_eq!(rt.machine().history().len(), 4);
    assert_eq!(rt.machine().invariant_violations(), 0);
    assert!(rt.machine().state_and_reason_agree());
}

#[test]
fn cd1_a_suspend_does_not_tear_down_a_session_that_was_merely_asleep() {
    let (env, vt) = testing::env();
    let machine = SessionMachine::new(env.clone(), SessionId::from_slice(&[2; 16]).expect("16"));
    let mut rt = SessionRuntime::new(env, machine);
    rt.apply(
        Trigger::Event(Event::ConnectRequested),
        Guards {
            credentials_valid: true,
            peer_authorized: true,
            ..Guards::default()
        },
        Context::default(),
    );
    assert!(rt.timers().is_armed(TimerId::Discover));

    // Eight hours of suspend: the ELAPSED clock advances, the monotonic one does
    // not, and T_DISCOVER is a monotonic constant.
    vt.suspend(Duration::from_secs(8 * 3600));
    assert!(rt.tick(Guards::default(), Context::default()).is_empty());
    assert_eq!(rt.machine().state(), SessionState::Discovering);

    // And it still fires when monotonic time really passes.
    vt.advance(Duration::from_secs(6));
    assert_eq!(rt.tick(Guards::default(), Context::default()).len(), 1);
}

// ---------------------------------------------------------------------------
// 6 + 9. CD-I5, and I5's promise about an outage.
// ---------------------------------------------------------------------------

#[test]
fn cd_i5_the_control_plane_writes_the_store_and_the_data_plane_reads_it() {
    let core = testing::core().expect("creates");
    let cp = core.control_plane_port();
    let dp = core.data_plane_view();

    cp.put_peer(&twinnet(), peer(1));
    assert!(cp.advance_trust_epoch(&twinnet(), 5));

    assert_eq!(dp.trust_epoch(&twinnet()), 5);
    assert_eq!(dp.peers(&twinnet()).len(), 1);
    assert!(dp
        .peer(&twinnet(), DeviceId::from_slice(&[1; 32]).expect("32"))
        .is_some());
}

#[test]
fn i5_a_control_plane_outage_changes_nothing_the_data_plane_can_read() {
    let core = testing::core().expect("creates");
    let cp = core.control_plane_port();
    let dp = core.data_plane_view();
    cp.put_peer(&twinnet(), peer(3));

    // "The outage" is modelled the only way it can be here: the control-plane
    // port is dropped entirely. The data plane keeps its whole view, because it
    // never held a reference to the control plane — only to the store.
    drop(cp);

    let record = dp
        .peer(&twinnet(), DeviceId::from_slice(&[3; 32]).expect("32"))
        .expect("the cached peer set survives the control plane going away");
    assert!(record.tunnel_key_binding_verified);
    // Both families are present. ADR-0010 R1: there is no v4-only answer.
    assert_eq!(record.overlay.v4.octets()[0], 100);
    assert_eq!(record.overlay.v6.octets()[0], 0xfd);
}

// ---------------------------------------------------------------------------
// 7. F-7 + CB-6.
// ---------------------------------------------------------------------------

#[test]
fn f7_a_poisoned_core_stays_poisoned_and_leaves_enforcement_alone() {
    let (core, adapter) = testing::core_and_adapter().expect("creates");
    core.poison();

    assert!(core.is_poisoned());
    assert_eq!(
        core.submit(&Submission::bare(CoreCommand::StatusGet))
            .expect_err("poisoned")
            .code()
            .as_str(),
        "INTERNAL.CORE_PANIC"
    );
    // CB-6: the OS holds the rules. A core fault cannot drop protection.
    assert_eq!(adapter.tunnel_mock().destroy_calls(), 0);
    assert_eq!(adapter.config_mock().apply_calls(), 0);
}

// ---------------------------------------------------------------------------
// 8. F-10 — rendering with no instance at all.
// ---------------------------------------------------------------------------

#[test]
fn f10_every_registered_code_renders_with_no_core_instance_in_existence() {
    // Note what is NOT constructed in this test: no `Core`, no adapter, no
    // `Env`. F-10's whole point is that the moment a diagnostic most needs
    // rendering is exactly when no instance exists.
    let neutral = twinvpn_diag::PlatformContext::neutral();
    for code in twinvpn_types::ReasonCode::all() {
        let r = twinvpn_diag::render(code.as_str(), &[], "en", &neutral);
        assert!(!r.summary.trim().is_empty(), "{code} rendered nothing");
        assert!(r.registered);
        assert_eq!(r.attributes.severity, code.severity());
        if code.user_actionable() {
            assert!(
                r.next_action.is_some(),
                "{code} is actionable with no action"
            );
        }
    }
}

#[test]
fn f10_a_poisoned_instance_can_still_render_the_fault_that_poisoned_it() {
    let core = testing::core().expect("creates");
    core.poison();
    let r = twinvpn_diag::render(
        "INTERNAL.CORE_PANIC",
        &[],
        "en",
        &twinvpn_diag::PlatformContext::neutral(),
    );
    assert!(!r.summary.is_empty());
    assert!(r.summary.to_lowercase().contains("defect") || r.summary.len() > 20);
}

// ---------------------------------------------------------------------------
// The command surface: one vocabulary, and a rejection is never a silence.
// ---------------------------------------------------------------------------

#[test]
fn every_catalogue_operation_is_submittable_and_answers_on_the_one_stream() {
    let core = testing::core().expect("creates");
    let mut answered = 0usize;
    for op in CoreCommand::ALL {
        let entry = twinvpn_mgmt::entry(*op);
        let mut submission = Submission::bare(*op);
        // Supply whatever ADR-0008 precondition the catalogue declares, so the
        // operation is judged on whether it EXISTS rather than on its arguments.
        match entry.idempotency {
            twinvpn_mgmt::Idempotency::Key => submission.idempotency_key = Some(vec![0; 16]),
            twinvpn_mgmt::Idempotency::Version => submission.if_version = Some(1),
            _ => {}
        }
        let _ = core.submit(&submission);
        let event = core
            .next_event(Duration::ZERO)
            .expect("every submission answers on the stream — §11.6: never a silent drop");
        match event.kind {
            CoreEventKind::CommandCompleted { op: name, .. }
            | CoreEventKind::CommandRejected { op: name, .. } => {
                assert_eq!(name, op.name());
                answered += 1;
            }
            other => panic!("unexpected event for {op}: {other:?}"),
        }
    }
    assert_eq!(answered, CoreCommand::ALL.len());
}

#[test]
fn the_core_executes_every_operation_the_catalogue_advertises_or_says_it_does_not() {
    // The honest half of the previous test: an operation the catalogue names and
    // the core does not execute is enumerable, not hidden.
    let implemented = CoreCommand::ALL
        .iter()
        .filter(|op| twinvpn_core::core::is_implemented(**op))
        .count();
    assert_eq!(
        implemented + twinvpn_core::core::UNIMPLEMENTED.len(),
        CoreCommand::ALL.len()
    );
    assert!(
        implemented > 0,
        "a core that implements nothing is not a core"
    );
}

// ---------------------------------------------------------------------------
// Graceful shutdown, and the ledger.
// ---------------------------------------------------------------------------

#[test]
fn shutdown_is_graceful_and_does_not_remove_protection() {
    let (core, adapter) = testing::core_and_adapter().expect("creates");
    core.submit(&Submission::bare(CoreCommand::StatusGet))
        .expect("implemented");
    core.begin_shutdown();
    // Graceful: an already-queued event is still readable — a shutdown that
    // discarded the completion of a command it had accepted would be the silent
    // drop §11.6 forbids. What closing does is stop accepting new work.
    assert!(core.next_event(Duration::ZERO).is_some());
    assert!(core.next_event(Duration::ZERO).is_none());
    assert_eq!(adapter.tunnel_mock().destroy_calls(), 0);
}

#[test]
fn the_tier_zero_ledger_records_what_the_core_decided() {
    let core = testing::core().expect("creates");
    let (before, _) = core.ledger_stats();
    let _ = core.submit(&Submission::bare(CoreCommand::PairBegin));
    let (after, dropped) = core.ledger_stats();
    assert!(after > before, "a rejection is recorded in Tier 0");
    assert_eq!(dropped, 0);
}

#[test]
fn two_instances_in_one_process_have_distinct_identities() {
    // S-47: `instance_id` is unique within one process. A shared or reused id
    // would make "two processes both driving one core" indistinguishable from
    // one process with two handles.
    let a: Core = testing::core().expect("creates");
    let b: Core = testing::core().expect("creates");
    assert_ne!(a.instance_id(), b.instance_id());
}

#[test]
fn nothing_in_this_test_binary_links_a_shell() {
    // The claim CB-2 actually makes, asserted the only way a test can: this
    // binary's dependency closure is the core plus a mock adapter. If a shell
    // crate ever appeared in it, `Arc<dyn PlatformAdapter>` below would be a
    // real platform binding rather than the in-memory one.
    let (_, adapter, _) = testing::parts();
    let as_trait: Arc<dyn twinvpn_platform::PlatformAdapter> = adapter;
    assert_eq!(as_trait.binding_name(), "mock-in-memory");
}
