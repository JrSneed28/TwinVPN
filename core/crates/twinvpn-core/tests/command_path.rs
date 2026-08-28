//! **The test the earlier revision did not have.**
//!
//! `Core::submit` used to perform the admission checks and return `Ok` having
//! called no component. Thirty-three of the forty-seven catalogue operations
//! reported success and executed nothing, and no test noticed, because every
//! test asserted only that the submission was *accepted*.
//!
//! Every assertion in this file is about **work**, not acceptance:
//!
//! 1. every catalogue operation either performs an observable effect **or** is
//!    refused by a registered name — there is no third outcome;
//! 2. `session.connect` reaches the platform, opens a socket per family, drives
//!    the real §4.5 table, and — with a peer endpoint known — **moves a packet**;
//! 3. a refusal names *why*, and the reason is a registered code;
//! 4. the derived registers agree with the dispatcher.

#![cfg(feature = "full")]

use std::time::Duration;

use twinvpn_core::core::{executes, unimplemented};
use twinvpn_core::dispatch::{disposition, Disposition, Lifecycle};
use twinvpn_core::events::CoreEventKind;
use twinvpn_core::{testing, VaultState};
use twinvpn_mgmt::{CoreCommand, Idempotency, Submission};
use twinvpn_platform::iface::{InterfaceFacts, InterfaceIndex, InterfaceName, LinkClass};
use twinvpn_types::{InterfaceAddress, IpAddr, V4Addr, V6Addr};

const PEER: [u8; 32] = [0x5a; 32];

fn dual_stack_interface() -> InterfaceFacts {
    InterfaceFacts {
        index: InterfaceIndex(2),
        name: InterfaceName::new("eth0").expect("valid"),
        // A /24 and a /64 with host bits set — the ordinary shape of an
        // interface address, and the shape the seam could not carry until
        // `InterfaceFacts.addresses` became a `Vec<InterfaceAddress>`.
        addresses: vec![
            InterfaceAddress::new(
                IpAddr::V4(V4Addr::from_slice(&[192, 0, 2, 10]).expect("v4")),
                24,
            )
            .expect("address"),
            InterfaceAddress::new(
                IpAddr::V6(
                    V6Addr::from_slice(
                        &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10],
                        0,
                    )
                    .expect("v6"),
                ),
                64,
            )
            .expect("address"),
        ],
        has_default_route_v4: true,
        has_default_route_v6: true,
        is_overlay: false,
        is_up: true,
        mtu: 1500,
        link_class: LinkClass::Ethernet,
    }
}

/// The `DeviceId` every session operation in this file names.
fn peer_id() -> twinvpn_types::DeviceId {
    twinvpn_types::DeviceId::from_slice(&PEER).expect("32")
}

/// Establishes what `session.connect`'s T01 guards now READ.
///
/// `execute::connect` used to supply `credentials_valid: true` and
/// `peer_authorized: true` as literals — so this file's assertions about "work"
/// held for a peer nobody had authorized, and the strongest test suite in the
/// tree could not tell an authorized connect from an unauthorized one. Both
/// guards are read from state now, and a test that wants the work to happen has
/// to say what the state is.
///
/// The refusal is asserted separately, in
/// [`an_unauthorized_peer_is_refused_rather_than_connected`].
fn authorize(
    core: &twinvpn_core::Core,
    adapter: &std::sync::Arc<twinvpn_platform::mock::MockAdapter>,
) {
    testing::authorize_peer(core, adapter, peer_id()).expect("the vault opens and the peer caches");
}

/// A submission carrying whatever its catalogue row requires.
fn well_formed(op: CoreCommand) -> Submission {
    let mut s = Submission::bare(op);
    match twinvpn_mgmt::entry(op).idempotency {
        Idempotency::Key => s.idempotency_key = Some(vec![0; 16]),
        Idempotency::Version => s.if_version = Some(1),
        Idempotency::ReadOnly | Idempotency::Natural => {}
    }
    s.params = match op {
        CoreCommand::SessionConnect
        | CoreCommand::SessionGet
        | CoreCommand::SessionReconnect
        | CoreCommand::SessionDisconnect => PEER.to_vec(),
        CoreCommand::HostLifecycle => vec![Lifecycle::Foreground.to_params()],
        _ => Vec::new(),
    };
    s
}

// ---------------------------------------------------------------------------
// 1. No operation reports success having done nothing.
// ---------------------------------------------------------------------------

#[test]
fn every_operation_either_works_or_is_refused_by_name() {
    let (core, adapter) = testing::core_and_adapter().expect("creates");
    adapter
        .interfaces_mock()
        .set_interfaces(vec![dual_stack_interface()]);
    authorize(&core, &adapter);

    let mut executed = 0usize;
    let mut refused = 0usize;

    for op in CoreCommand::ALL {
        let outcome = core.submit(&well_formed(*op));

        // The outcome arrives on the ONE ordered stream, after whatever the
        // operation itself published — a transition legitimately precedes its
        // own command's completion. The stream is scanned rather than peeked,
        // which is what F-5's total order actually promises.
        let mut answered = false;
        while let Some(event) = core.next_event(Duration::ZERO) {
            match (&outcome, &event.kind) {
                (Ok(()), CoreEventKind::CommandCompleted { op: name, .. }) => {
                    assert_eq!(*name, op.name());
                    assert!(
                        executes(*op),
                        "{op} succeeded but the dispatcher says it does not execute"
                    );
                    executed += 1;
                    answered = true;
                }
                (Err(diagnostic), CoreEventKind::CommandRejected { op: name, .. }) => {
                    assert_eq!(*name, op.name());
                    // F-4: a failure carries a NAME, never a bare code.
                    assert!(
                        twinvpn_types::ReasonCode::lookup(diagnostic.code().as_str()).is_some(),
                        "{op} refused with an unregistered code"
                    );
                    refused += 1;
                    answered = true;
                }
                _ => {}
            }
        }
        assert!(
            answered,
            "§11.6: {op} produced no outcome event — a silent drop"
        );
    }

    assert_eq!(executed + refused, CoreCommand::ALL.len());
    assert!(executed > 0, "a core that executes nothing is not a core");
}

#[test]
fn the_derived_registers_agree_with_the_dispatcher() {
    let refused: Vec<CoreCommand> = unimplemented().into_iter().map(|(op, _, _)| op).collect();
    for op in CoreCommand::ALL {
        assert_eq!(
            executes(*op),
            !refused.contains(op),
            "{op} is described two ways"
        );
    }
    assert_eq!(
        refused.len() + CoreCommand::ALL.iter().filter(|o| executes(**o)).count(),
        CoreCommand::ALL.len()
    );
}

#[test]
fn the_non_exhaustive_arm_is_unreachable() {
    // `disposition` needs a wildcard because `CoreCommand` is
    // `#[non_exhaustive]`. This asserts no declared variant reaches it, so the
    // wildcard cannot become a silent default for a real operation.
    for op in CoreCommand::ALL {
        if let Disposition::NotWired { why, .. } = disposition(*op) {
            assert!(
                !why.contains("does not know"),
                "{op} fell through to the non-exhaustive arm"
            );
        }
    }
}

#[test]
fn every_refusal_states_why() {
    for (op, code, why) in unimplemented() {
        assert!(!why.trim().is_empty(), "{op} refuses with no stated reason");
        assert!(twinvpn_types::ReasonCode::lookup(code.as_str()).is_some());
    }
}

// ---------------------------------------------------------------------------
// 2. session.connect does the work.
// ---------------------------------------------------------------------------

#[test]
fn session_connect_reaches_the_platform_and_opens_both_families() {
    let (core, adapter) = testing::core_and_adapter().expect("creates");
    adapter
        .interfaces_mock()
        .set_interfaces(vec![dual_stack_interface()]);
    authorize(&core, &adapter);

    assert_eq!(adapter.sockets_mock().opened(), 0, "nothing yet");
    core.submit(&well_formed(CoreCommand::SessionConnect))
        .expect("session.connect executes");

    // ADR-0010 R1 at the mechanism level: one socket per family, both attempted.
    assert_eq!(
        adapter.sockets_mock().opened(),
        2,
        "gathering must open a v4 socket AND a v6 socket"
    );
}

#[test]
fn session_connect_drives_the_real_transition_table() {
    let (core, adapter) = testing::core_and_adapter().expect("creates");
    adapter
        .interfaces_mock()
        .set_interfaces(vec![dual_stack_interface()]);
    authorize(&core, &adapter);
    core.submit(&well_formed(CoreCommand::SessionConnect))
        .expect("executes");

    // T01 (DISCONNECTED -> DISCOVERING) and T03 (-> NEGOTIATING) both fired, and
    // each produced exactly one TransitionEvent on the one ordered stream.
    let mut transitions = Vec::new();
    while let Some(event) = core.next_event(Duration::ZERO) {
        if let CoreEventKind::Transition(t) = event.kind {
            transitions.push(*t);
        }
    }
    assert!(
        transitions.len() >= 2,
        "expected T01 and T03, saw {}",
        transitions.len()
    );
    let triggers: Vec<&str> = transitions.iter().map(|t| t.trigger.as_str()).collect();
    assert!(triggers.contains(&"EV_CONNECT_REQUESTED"), "{triggers:?}");
    assert!(triggers.contains(&"EV_CANDIDATES_READY"), "{triggers:?}");
    // §10.2: `session_id` is NEVER EMPTY — it is what lets an outage be
    // reconstructed across a crash.
    assert!(transitions.iter().all(|t| !t.session_id.is_empty()));
}

#[test]
fn session_connect_is_naturally_idempotent() {
    // ADR-0017 §11.9 marks it `nat`. Connecting twice must reach one `Session`,
    // and T01's own rule absorbs the second request.
    let (core, adapter) = testing::core_and_adapter().expect("creates");
    adapter
        .interfaces_mock()
        .set_interfaces(vec![dual_stack_interface()]);
    authorize(&core, &adapter);
    core.submit(&well_formed(CoreCommand::SessionConnect))
        .expect("first");
    core.submit(&well_formed(CoreCommand::SessionConnect))
        .expect("second");

    // One Session, not two: `status.get`'s per-session rows say how many.
    let sample = status(&core);
    assert_eq!(
        sample.per_session.len(),
        1,
        "two connects made two Sessions"
    );
}

#[test]
fn session_connect_moves_a_packet_once_a_peer_endpoint_is_known() {
    // THE ASSERTION NO EXISTING TEST MAKES.
    //
    // The probe needs somewhere to go. With no ControlTransport in the workspace
    // (W-12) nothing supplies a peer endpoint on its own, so the test binds a
    // second socket on the same mock fabric and hands the core its endpoint —
    // which is exactly what rendezvous will do when it exists.
    let h = testing::harness().expect("creates");
    h.adapter
        .interfaces_mock()
        .set_interfaces(vec![dual_stack_interface()]);
    authorize(&h.core, &h.adapter);

    // The peer's socket must OUTLIVE the probe: dropping it closes the inbox and
    // the datagram would be counted as dropped rather than delivered.
    let (_peer_socket, peer_endpoint) =
        testing::bind_peer(&h.adapter).expect("a peer socket on the same fabric");
    h.core.set_peer_endpoint(
        twinvpn_types::DeviceId::from_slice(&PEER).expect("32"),
        peer_endpoint,
    );

    let (delivered_before, _) = h.net.counters();
    h.core
        .submit(&well_formed(CoreCommand::SessionConnect))
        .expect("executes");

    // §4.4 races the families staggered by the Happy-Eyeballs bias, so the v4
    // half of the race is not due at t=0. A daemon ticks; so does this test.
    h.time.advance(Duration::from_millis(500));
    let (_transitions, probes) = h.core.tick();

    let (delivered_after, dropped) = h.net.counters();
    assert!(probes > 0, "the tick must probe the now-due candidate");
    assert!(
        delivered_after > delivered_before,
        "session.connect must move a packet: delivered {delivered_before} -> \
         {delivered_after}, dropped {dropped}"
    );
}

#[test]
fn a_session_operation_without_a_peer_is_refused_not_guessed() {
    let core = testing::core().expect("creates");
    let err = core
        .submit(&Submission::bare(CoreCommand::SessionConnect))
        .expect_err("a connect with no peer names nobody");
    assert_eq!(err.code().as_str(), "PROTO.MALFORMED_MESSAGE");
}

#[test]
fn disconnect_clears_session_intent() {
    let (core, adapter) = testing::core_and_adapter().expect("creates");
    adapter
        .interfaces_mock()
        .set_interfaces(vec![dual_stack_interface()]);
    authorize(&core, &adapter);
    core.submit(&well_formed(CoreCommand::SessionConnect))
        .expect("connect");
    while core.next_event(Duration::ZERO).is_some() {}

    core.submit(&well_formed(CoreCommand::SessionDisconnect))
        .expect("disconnect");
    let mut sawtransition = false;
    while let Some(event) = core.next_event(Duration::ZERO) {
        if let CoreEventKind::Transition(t) = event.kind {
            if t.trigger == "EV_DISCONNECT_REQUESTED" {
                sawtransition = true;
            }
        }
    }
    assert!(sawtransition, "disconnect must produce a transition");
}

// ---------------------------------------------------------------------------
// 3. The reads answer with something.
// ---------------------------------------------------------------------------

fn status(core: &twinvpn_core::Core) -> twinvpn_schema::v1::HealthSample {
    core.submit(&well_formed(CoreCommand::StatusGet))
        .expect("status.get executes");
    loop {
        let event = core.next_event(Duration::ZERO).expect("an answer");
        if let CoreEventKind::CommandCompleted {
            op: "status.get",
            result,
        } = event.kind
        {
            return <twinvpn_schema::v1::HealthSample as prost::Message>::decode(&result[..])
                .expect("status.get returns a HealthSample");
        }
    }
}

#[test]
fn status_get_returns_a_body_rather_than_an_empty_result() {
    // The specific shape of the old defect: every operation returned
    // `result: Vec::new()`.
    let core = testing::core().expect("creates");
    let sample = status(&core);
    assert!(
        !sample.agent_version.is_empty(),
        "status.get answered nothing"
    );
}

#[test]
fn version_get_returns_the_s46_table() {
    let core = testing::core().expect("creates");
    core.submit(&well_formed(CoreCommand::VersionGet))
        .expect("executes");
    let event = core.next_event(Duration::ZERO).expect("an answer");
    let CoreEventKind::CommandCompleted { result, .. } = event.kind else {
        panic!("version.get must complete");
    };
    let id = <twinvpn_schema::v1::CoreBuildIdentity as prost::Message>::decode(&result[..])
        .expect("version.get returns CoreBuildIdentity");
    assert_eq!(id.core_version, env!("CARGO_PKG_VERSION"));
    assert!(id.protocol_epoch_max >= id.protocol_epoch_min);
}

#[test]
fn status_get_carries_a_reason_code_whenever_the_state_requires_one() {
    // §14's teeth: a sample reporting DEGRADED or FAILED with an EMPTY
    // reason_codes[] is a MALFORMED MESSAGE.
    let (core, adapter) = testing::core_and_adapter().expect("creates");
    adapter
        .interfaces_mock()
        .set_interfaces(vec![dual_stack_interface()]);
    authorize(&core, &adapter);
    core.submit(&well_formed(CoreCommand::SessionConnect))
        .expect("connect");
    while core.next_event(Duration::ZERO).is_some() {}

    let sample = status(&core);
    // §14's teeth, read off the enum rather than guessed at: the four
    // reason-bearing states are DEGRADED, BLOCKED, RECONNECTING and FAILED.
    let requires_reason = [
        twinvpn_types::ConnectionState::Degraded,
        twinvpn_types::ConnectionState::Blocked,
        twinvpn_types::ConnectionState::Reconnecting,
        twinvpn_types::ConnectionState::Failed,
    ]
    .iter()
    .any(|s| s.to_wire() == sample.connection_state);
    if requires_reason {
        assert!(
            !sample.reason_codes.is_empty(),
            "state {} requires a reason code; an empty list is a MALFORMED MESSAGE",
            sample.connection_state
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Lifecycle and the vault.
// ---------------------------------------------------------------------------

#[test]
fn host_lifecycle_moves_the_core_and_refuses_an_unknown_phase() {
    let core = testing::core().expect("creates");
    let mut suspend = Submission::bare(CoreCommand::HostLifecycle);
    suspend.params = vec![Lifecycle::Suspend.to_params()];
    core.submit(&suspend).expect("executes");
    assert_eq!(core.lifecycle(), Lifecycle::Suspend);

    let mut nonsense = Submission::bare(CoreCommand::HostLifecycle);
    nonsense.params = vec![99];
    let err = core.submit(&nonsense).expect_err("never defaulted");
    assert_eq!(err.code().as_str(), "PROTO.MALFORMED_MESSAGE");
    assert_eq!(
        core.lifecycle(),
        Lifecycle::Suspend,
        "a refused phase must not move the core"
    );
}

#[test]
fn a_core_with_no_vault_refuses_durable_operations() {
    // D4: until `open_store` runs, a durable answer would be a memory answer.
    let core = testing::core().expect("creates");
    assert_eq!(core.vault_state(), VaultState::Absent);
    let err = core
        .submit(&well_formed(CoreCommand::SettingsGet))
        .expect_err("refused");
    assert_eq!(err.code().as_str(), "STORE.CUSTODY_DEGRADED");
}

// ---------------------------------------------------------------------------
// 5. An unauthorized peer is refused. (`ownership.md` §8 wave-1 review, item 2.)
// ---------------------------------------------------------------------------

#[test]
fn an_unauthorized_peer_is_refused_rather_than_connected() {
    // The defect: `execute::connect` supplied `credentials_valid: true` and
    // `peer_authorized: true` as LITERALS, with a comment saying so. Any 32
    // bytes a caller passed as a peer therefore drove the state machine to
    // CONNECTED — no credential check, no authorization check, no handshake —
    // and every test in this file passed, because none of them authorized
    // anything either.
    //
    // Two refusals, and they are different facts.
    let (core, adapter) = testing::core_and_adapter().expect("creates");
    adapter
        .interfaces_mock()
        .set_interfaces(vec![dual_stack_interface()]);

    // (a) No identity: `identity_public` refuses, which is §11.16 (l)'s
    //     specified behaviour on a host with no secure element — and the core
    //     "MUST NOT substitute a file-backed signer silently".
    //     AUTH.KEY_UNAVAILABLE.
    adapter.identity_mock().set_unavailable(true);
    let err = core
        .submit(&well_formed(CoreCommand::SessionConnect))
        .expect_err("a core with no credentials must not connect");
    assert_eq!(err.code().as_str(), "AUTH.KEY_UNAVAILABLE");
    adapter.identity_mock().set_unavailable(false);

    // (b) Vault open, peer not cached: ADR-0007 N-4's `TrustedPeer` does not
    //     exist, so the peer is not authorized. AUTH.PEER_UNTRUSTED — a
    //     DIFFERENT code, because "we have no credentials" and "we have them and
    //     you are not on the list" are different answers to the operator.
    let stranger = twinvpn_types::DeviceId::from_slice(&[0x5b; 32]).expect("32");
    testing::authorize_peer(&core, &adapter, peer_id()).expect("authorizes the OTHER peer");
    let mut connect = Submission::bare(CoreCommand::SessionConnect);
    connect.params = vec![0x5b; 32];
    let _ = stranger;
    let err = core
        .submit(&connect)
        .expect_err("a peer nobody authorized must not connect");
    assert_eq!(err.code().as_str(), "AUTH.PEER_UNTRUSTED");

    // And the refusal is an EVENT, never a silent drop (§11.6).
    let mut rejected = 0usize;
    while let Some(event) = core.next_event(Duration::ZERO) {
        if let CoreEventKind::CommandRejected { op, .. } = event.kind {
            assert_eq!(op, "session.connect");
            rejected += 1;
        }
    }
    assert!(rejected >= 2, "each refusal produces its own event");

    // The authorized peer still connects: the check is a gate, not a lockout.
    core.submit(&well_formed(CoreCommand::SessionConnect))
        .expect("the authorized peer connects");
}
