//! Two peers of one `Session`, on one virtual clock.
//!
//! Shared by `tests/resume.rs` (the wire flow and the attacks against it) and
//! `tests/resume_lifecycle.rs` (freshness, revocation, reconnect and restart),
//! so both halves talk about the same fixture rather than two that drifted.

use twinvpn_core::resume::PeerTrustFacts;
use twinvpn_core::session_loop::SessionRuntime;
use twinvpn_core::testing;
use twinvpn_crypto::noise::Role;
use twinvpn_env::virtual_time::VirtualTime;
use twinvpn_env::Env;
use twinvpn_session::event::{Event, Trigger};
use twinvpn_session::state::SessionState;
use twinvpn_session::{Context, Guards, SessionMachine};
use twinvpn_types::{SessionId, SessionNonce};

/// The `handshake_secret` both peers derive from. A fixture, not a key: the
/// derivation under test is `HKDF-Expand-Label`, and a constant input makes the
/// whole suite reproducible byte for byte.
pub const HANDSHAKE_SECRET: [u8; 32] = [0x5a; 32];

/// The `path_epoch` the `Session` was established at.
pub const ESTABLISHED_EPOCH: u64 = 7;

/// The `session_nonce` both peers are bound to.
pub fn nonce() -> SessionNonce {
    SessionNonce::from_slice(&[0x11; 16]).expect("16 bytes")
}

/// A peer this device has no revocation for, at epoch 3.
pub fn trusting() -> PeerTrustFacts {
    PeerTrustFacts {
        revocation_epoch: 3,
        peer_revoked: false,
    }
}

/// One `Session` on `env`, resting in `DISCONNECTED`.
pub fn runtime(env: &Env, tag: u8) -> SessionRuntime {
    let machine = SessionMachine::new(
        env.clone(),
        SessionId::from_slice(&[tag; 16]).expect("16 bytes"),
    );
    SessionRuntime::new(env.clone(), machine)
}

/// Two peers of one `Session`, armed from the same completed handshake.
///
/// `a` was the handshake initiator and `b` the responder, which is what fixes
/// the direction label each side MACs under.
pub fn armed_pair() -> (SessionRuntime, SessionRuntime, VirtualTime) {
    let (env, vt) = testing::env();
    let mut a = runtime(&env, 1);
    let mut b = runtime(&env, 2);
    a.arm_resumption(
        &HANDSHAKE_SECRET,
        Role::Initiator,
        nonce(),
        ESTABLISHED_EPOCH,
    )
    .expect("initiator arms");
    b.arm_resumption(
        &HANDSHAKE_SECRET,
        Role::Responder,
        nonce(),
        ESTABLISHED_EPOCH,
    )
    .expect("responder arms");
    (a, b, vt)
}

/// Parks `rt` in `RECONNECTING{parked}` — §4.5 T34 — which is the state a
/// resume arrives in.
pub fn park(rt: &mut SessionRuntime) {
    rt.apply(
        Trigger::Event(Event::Suspend),
        Guards::default(),
        Context::default(),
    );
    assert_eq!(
        rt.machine().state(),
        SessionState::Reconnecting { parked: true },
        "T34 must park the session before a resume can be tested"
    );
}

/// A wire `Endpoint`, for the `new_endpoint_hint` a roaming peer carries.
pub fn hint(last_octet: u8, port: u32) -> twinvpn_schema::v1::Endpoint {
    twinvpn_schema::v1::Endpoint {
        address: Some(twinvpn_schema::v1::IpAddress {
            address: Some(twinvpn_schema::v1::ip_address::Address::V4(
                twinvpn_schema::v1::IPv4Address {
                    octets: vec![198, 51, 100, last_octet],
                },
            )),
        }),
        port,
    }
}
