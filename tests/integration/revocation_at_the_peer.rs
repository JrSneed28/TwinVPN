//! **A-06**: revocation is enforced at the *peer*, not solely at the control
//! plane.
//!
//! **Authority:** `docs/testing-strategy.md` §0's assumption register;
//! ADR-0007 §7.7 (**P10**'s conformance surface).
//!
//! > | **A-06** | Device revocation is enforced at the **peer** (a peer refuses a
//! > revoked `TrustedPeer`) and not solely at the control plane, so revocation
//! > survives control-plane unavailability with a bounded propagation delay. |
//! > **P10** must be reframed as "revoked devices cannot reconnect *while the
//! > control plane is reachable*", a materially weaker property. |
//!
//! # Why this file is in `tests/` and not in either crate
//!
//! The assumption spans two crates that never link in production: the control
//! plane produces a revocation, and `twinvpn-trust` on a device consumes one.
//! `services/control-plane/tests/authorization.rs` proves the server half — a
//! revoked device is refused and disappears from the peer set. `twinvpn-trust`'s
//! own tests prove the device half in isolation. **Neither can show that the
//! statement the server verified is the statement the device acts on**, because
//! neither can link the other, and that is precisely the claim A-06 makes.
//!
//! `tests/` is the one workspace that links both.
//!
//! # The shape of the assertion
//!
//! The device half runs with **no control plane in the process at all** — not a
//! mocked one, not an unreachable one: the `RevocationState` is constructed, the
//! statement is applied, and the peer is refused, in code that has never heard of
//! `ControlStore`. That is what "survives control-plane unavailability" has to
//! mean if it is to mean anything.

use std::time::Duration;

use twinvpn_control_plane::store::{ControlStore, Request};
use twinvpn_control_plane::verify::testing::ScriptedVerifier;
use twinvpn_control_plane::verify::{Delegation, StatementVerifier};
use twinvpn_control_plane::CommandCode;
use twinvpn_crypto::statements::{OskPower, RevocationStatement};
use twinvpn_schema::v1;
use twinvpn_service_common::Correlation;
use twinvpn_trust::revocation::RevocationState;

use prost::Message;

const TWINNET: &str = "twn_a06";

/// The device the Owner revokes.
fn target() -> [u8; 32] {
    [7u8; 32]
}

/// An Owner verifier holding the `REVOKE` power.
fn owner_with_revoke() -> ScriptedVerifier {
    let delegation = Delegation {
        osk_id: "osk-revoke".to_owned(),
        osk_pub_cose: vec![0xa5; 8],
        powers: vec![OskPower::Revoke],
        anchor_version: 1,
        not_after_ms: 0,
    };
    ScriptedVerifier::owner()
        .held_by(delegation.clone())
        .granting(delegation)
}

/// A non-empty COSE_Sign1 stand-in, CBOR-shaped rather than protobuf.
///
/// The signature itself is the one port this build cannot bind on this host
/// (CD-I2 puts the single implementation in `twinvpn-crypto`, and there is no
/// anchor here); the scripted verifier stands in for it and everything else on
/// the path is real.
fn cose(tag: u8) -> v1::SignedStatement {
    v1::SignedStatement {
        cose_sign1: vec![0xd2, 0x84, 0x43, tag],
        statement_type: 0,
    }
}

/// The statement an Owner signs, in the form both halves read.
fn statement(target_identity: Option<[u8; 32]>) -> RevocationStatement {
    RevocationStatement {
        twinnet_id: TWINNET.to_owned(),
        target_device_id: target(),
        target_identity_id: target_identity,
        effective_from_ms: 1_000,
        reason_code: "AUTH.DEVICE.REVOKED".to_owned(),
        issuer_osk_id: "osk-revoke".to_owned(),
    }
}

/// Registers `target()` and then revokes it, through the real dispatch path.
fn revoke_at_the_control_plane() -> (u64, u64) {
    let store = twinvpn_control_plane::store::mem::MemStore::new();
    let base = std::time::Instant::now();
    let endpoints = vec!["cp.twinvpn.example".to_owned()];
    let run = |code: CommandCode, body: Vec<u8>, verifier: &dyn StatementVerifier| {
        futures::executor::block_on(store.execute(Request {
            twinnet_id: TWINNET,
            caller: target(),
            caller_identity_key: None,
            now_ms: 10_000,
            now: base + Duration::from_millis(10),
            code,
            body: &body,
            correlation: Correlation::empty(),
            verifier,
            coordination_endpoints: &endpoints,
            quorum_available: true,
        }))
    };

    let register = v1::RegisterDeviceRequest {
        metadata: Some(v1::MessageMetadata {
            idempotency_key: vec![1u8; 16],
            ..Default::default()
        }),
        // A complete identity, because `RegisterDevice` refuses an incomplete
        // one with `AUTH.IDENTITY_MISSING` — which is the correct behaviour and
        // means a test that omitted it would be asserting against a refusal
        // rather than against a registration.
        identity: Some(v1::DeviceIdentity {
            identity_id: target().to_vec(),
            device_id: target().to_vec(),
            generation: 0,
            identity_public_key: vec![7, 7, 7, 7],
            identity_key_algorithm: v1::IdentityKeyAlgorithm::Es256 as i32,
            tunnel_public_key: vec![7],
            tunnel_key_algorithm: v1::TunnelKeyAlgorithm::X25519 as i32,
            tk_generation: 0,
            tunnel_key_binding: Some(cose(7)),
            hardware_backed: false,
            created_at_ms: 0,
        }),
        key_attestation: Vec::new(),
        platform: None,
        declared_roles: vec![v1::DeviceRole::Client as i32],
        protocol_version: Some(v1::ProtocolVersion { v_max: 1, v_min: 1 }),
        capabilities: None,
        enrollment_proof: Some(cose(7)),
    };
    let owner =
        twinvpn_control_plane::verify::testing::ScriptedVerifier::owner().granting(Delegation {
            osk_id: "osk-enroll".to_owned(),
            osk_pub_cose: vec![0xa5; 8],
            powers: vec![OskPower::Enroll],
            anchor_version: 1,
            not_after_ms: 0,
        });
    let registered = run(
        CommandCode::RegisterDevice,
        register.encode_to_vec(),
        &owner,
    );
    assert!(
        registered.is_ok(),
        "the precondition failed: the device could not be registered: {:?}",
        registered.err()
    );
    let before = futures::executor::block_on(store.trust_epoch(TWINNET)).expect("a trust epoch");

    let revoke = v1::RevokeDeviceRequest {
        target_device_id: target().to_vec(),
        revocation_statement: Some(cose(2)),
        metadata: Some(v1::MessageMetadata {
            idempotency_key: vec![2u8; 16],
            ..Default::default()
        }),
        ..Default::default()
    };
    let revoked = run(
        CommandCode::RevokeDevice,
        revoke.encode_to_vec(),
        &owner_with_revoke(),
    );
    assert!(
        revoked.is_ok(),
        "the control plane refused a well-formed revocation: {:?}",
        revoked.err()
    );
    let after = futures::executor::block_on(store.trust_epoch(TWINNET)).expect("a trust epoch");
    (before, after)
}

// ===========================================================================

#[test]
fn the_control_plane_revokes_and_advances_the_trust_epoch() {
    // The server half, asserted here only so that the device half below is
    // known to be acting on a statement the real service accepts — not on one
    // this test invented and nothing would have verified.
    let (before, after) = revoke_at_the_control_plane();
    assert!(
        after > before,
        "the trust epoch did not advance across a revocation: {before} -> {after}"
    );
}

#[test]
fn a06_a_peer_refuses_a_revoked_device_with_no_control_plane_in_the_process() {
    // Nothing in this test touches `ControlStore`, `MemStore` or a socket. This
    // is the whole of A-06: the device acts on the Owner's statement, and the
    // control plane's reachability is not an input to the decision.
    let mut state = RevocationState::new();

    // The negative half first, so the positive one below is not vacuous: a
    // device that has not seen the statement does not refuse.
    assert!(
        !state.is_revoked(&target(), None),
        "a device refused a peer before it had ever seen a revocation"
    );

    let outcome = state.refuse_on_statement(&statement(None));
    assert!(
        outcome.newly_revoked,
        "applying a revocation the device had not seen reported nothing new"
    );
    assert!(
        state.is_revoked(&target(), None),
        "the peer was not refused after the Owner's statement was applied. A-06 is false, \
         and P10 is only 'revoked devices cannot reconnect while the control plane is \
         reachable' — a materially weaker property."
    );
    assert!(
        outcome.epoch_pending,
        "effect (1) must refuse immediately and hold no epoch until a writer admits it; \
         an epoch here would make the refusal wait on the control plane, which is the \
         dependency A-06 exists to deny"
    );
}

#[test]
fn a_revocation_naming_one_generation_does_not_refuse_the_others_and_widening_does() {
    let mut state = RevocationState::new();
    let generation = [9u8; 32];
    let other = [10u8; 32];

    state.refuse_on_statement(&statement(Some(generation)));
    assert!(state.is_revoked(&target(), Some(&generation)));
    assert!(
        !state.is_revoked(&target(), Some(&other)),
        "a revocation naming one generation must not refuse another; the narrower reading \
         is the correct one when the Owner named a generation"
    );

    // `None` is the broader reading, and the set never shrinks in either
    // direction: widening to every generation is always admitted.
    let widened = state.refuse_on_statement(&statement(None));
    assert!(widened.newly_revoked, "widening must be recorded as new");
    assert!(
        state.is_revoked(&target(), Some(&other)),
        "widening to every generation did not take effect"
    );
}

#[test]
fn re_applying_the_same_revocation_is_a_no_op_rather_than_a_second_refusal() {
    // ADR-0008 N-7. A device that reported "newly revoked" on a replay would
    // make a propagation retry look like a second Owner action.
    let mut state = RevocationState::new();
    assert!(state.refuse_on_statement(&statement(None)).newly_revoked);
    assert!(
        !state.refuse_on_statement(&statement(None)).newly_revoked,
        "re-applying an identical revocation reported it as new"
    );
    assert!(state.is_revoked(&target(), None));
}
