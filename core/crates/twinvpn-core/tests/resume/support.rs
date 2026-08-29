//! Two peers of one `Session`, on one virtual clock.
//!
//! Shared by `tests/resume.rs` (the wire flow and the attacks against it) and
//! `tests/resume_lifecycle.rs` (freshness, revocation, reconnect and restart),
//! so both halves talk about the same fixture rather than two that drifted.

use twinvpn_core::resume::PeerTrustFacts;
use twinvpn_core::session_loop::SessionRuntime;
use twinvpn_core::testing;
use twinvpn_env::virtual_time::VirtualTime;
use twinvpn_env::Env;
use twinvpn_session::event::{Event, Trigger};
use twinvpn_session::state::SessionState;
use twinvpn_session::{Context, Guards, SessionMachine};
use twinvpn_types::{SessionId, SessionNonce};

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

/// Two peers of one `Session`, armed from **one real `Noise_IKpsk2`
/// handshake**.
///
/// `a` was the handshake initiator and `b` the responder, and that is not this
/// fixture's choice: `twinvpn_crypto::testkit::established_pair` runs the whole
/// handshake and each half's role is the one its own `Handshake` was built with.
/// There is no way to hand both peers the same role, here or anywhere — see
/// `SessionRuntime::arm_resumption`, whose `&[u8]` secret and caller-supplied
/// `Role` this replaced.
///
/// The material is therefore no longer a constant. That is a real loss of
/// byte-for-byte reproducibility across runs and it is the right trade: a
/// fixture that could express the bug the API now forbids is not testing the
/// API. Determinism where it matters is preserved anyway — the entropy behind
/// `testing::env()` is seeded, so a run is reproducible.
pub fn armed_pair() -> (SessionRuntime, SessionRuntime, VirtualTime) {
    let (env, vt) = testing::env();
    let (initiator, responder) = twinvpn_crypto::testkit::established_pair(&env);
    let mut a = runtime(&env, 1);
    let mut b = runtime(&env, 2);
    a.arm_resumption(&initiator, nonce(), ESTABLISHED_EPOCH)
        .expect("initiator arms");
    b.arm_resumption(&responder, nonce(), ESTABLISHED_EPOCH)
        .expect("responder arms");
    (a, b, vt)
}

/// One `SessionRuntime` armed from a fresh handshake of its own, under `nonce`.
///
/// For the tests that need a **second, unrelated** `Session`: a resume from it
/// must not authenticate here, and the reason it must not is that neither the
/// `session_nonce` nor the resumption material is shared.
///
/// `allow(dead_code)` because this file is `#[path]`-included by two test
/// targets and only `resume.rs` needs it — the same reason `datapath/support.rs`
/// is shared without every consumer using every helper.
#[allow(dead_code, reason = "one harness, two test targets")]
pub fn armed_elsewhere(env: &Env, tag: u8, session_nonce: SessionNonce) -> SessionRuntime {
    let (initiator, _responder) = twinvpn_crypto::testkit::established_pair(env);
    let mut rt = runtime(env, tag);
    rt.arm_resumption(&initiator, session_nonce, ESTABLISHED_EPOCH)
        .expect("a second session arms");
    rt
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
