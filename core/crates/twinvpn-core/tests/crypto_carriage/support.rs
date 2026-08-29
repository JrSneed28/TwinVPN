//! Two production pumps facing each other over a **real `Noise_IKpsk2`
//! handshake**, and the helpers `crypto_carriage.rs` drives them with.
//!
//! # The gap this closes
//!
//! `tests/datapath/support.rs` says so itself, in its own module docs:
//!
//! > "The production `TransportKeys` is `twinvpn_tunnel::bind::SessionKeys`,
//! > over a real `Noise_IKpsk2` handshake … Reaching it from *this* crate needs
//! > a `VerifiedTunnelKey`, which needs a signed `TunnelKeyBinding`, which needs
//! > `twinvpn-crypto`'s `test-support` fixtures — a dev-dependency feature
//! > `twinvpn-core`'s manifest does not enable."
//!
//! The manifest **does** enable it (`[dev-dependencies] twinvpn-crypto = {
//! features = ["test-support"] }`), so that report is stale and the stub is no
//! longer necessary. Everything below runs the production key path end to end:
//!
//! ```text
//! Pump::step_outbound  ->  Tunnel::seal
//!   ->  twinvpn_tunnel::bind::SessionKeys::seal      (the production impl)
//!     ->  twinvpn_crypto::noise::TransportSession::seal
//!       ->  snow ChaCha20-Poly1305, under keys a real handshake derived
//! ```
//!
//! Nothing here is a stub, a mask or an XOR. A test that passes against
//! `datapath/support.rs`'s `StubKeys` and fails here has found something real.
//!
//! # What is reused rather than rebuilt
//!
//! The fabric, the mock network, the pumps and the wire helpers are
//! `datapath/support.rs`'s — this file swaps out **only** the keys, which is
//! the one thing under test. Building a second fabric would let the two drift
//! and would make a difference in behaviour ambiguous between "the keys" and
//! "the harness".

use std::sync::Arc;

use twinvpn_core::datapath::{Cancel, Pump, PumpParts};
use twinvpn_core::testing;
use twinvpn_crypto::locked::LockedBytes;
use twinvpn_crypto::noise::{static_public_key, HandshakeConfig, Role};
use twinvpn_crypto::psk::TwinNetPsk;
use twinvpn_crypto::{
    EstablishedHandshake, IdentityBinding, NegotiationBinding, Prologue, TwinnetTag,
};
use twinvpn_env::Env;
use twinvpn_platform::mock::{MockAdapter, MockNetwork, MockOptions};
use twinvpn_platform::PlatformAdapter;
use twinvpn_tunnel::bind::NoiseBinding;
use twinvpn_tunnel::crypto::{NoiseHandshake as _, Prologue as TunnelPrologue, TransportKeys};

use super::dp;

/// One completed handshake, from both ends.
pub struct Handshaked {
    /// The initiator's transport keys — the production `SessionKeys`.
    pub initiator_keys: Box<dyn TransportKeys>,
    /// The responder's.
    pub responder_keys: Box<dyn TransportKeys>,
    /// The initiator's authenticated handshake result.
    pub initiator_established: EstablishedHandshake,
    /// The responder's.
    pub responder_established: EstablishedHandshake,
    /// The initiator's X25519 static public half.
    pub initiator_static: [u8; 32],
    /// The responder's.
    pub responder_static: [u8; 32],
}

/// Runs one real `Noise_IKpsk2` handshake through the **production** binding.
///
/// Every gate the product imposes is imposed here: both ends are constructed
/// against a [`twinvpn_crypto::VerifiedTunnelKey`] (there is no other kind), the
/// `psk2` slot carries a real `TwinNetPSK`, and the 83-byte §7.3.1 prologue is
/// built twice — once as `twinvpn-crypto`'s type and once as
/// `twinvpn-tunnel`'s — so `NoiseBinding`'s own P-1 cross-check runs for real
/// rather than being satisfied by handing it the same object twice.
///
/// # Panics
///
/// If the handshake does not complete. It is a fixture.
#[must_use]
pub fn handshake(env: &Env) -> Handshaked {
    let initiator_static = local_static(0x21);
    let responder_static = local_static(0x42);
    let initiator_pub = static_public_key(&initiator_static).expect("initiator public");
    let responder_pub = static_public_key(&responder_static).expect("responder public");
    let initiator_key = twinvpn_crypto::testkit::verified_tunnel_key(&initiator_pub);
    let responder_key = twinvpn_crypto::testkit::verified_tunnel_key(&responder_pub);

    let psk = TwinNetPsk::derive(b"twinvpn/tests/pair-secret", &[0x33; 32], "tn-1", 1)
        .expect("fixture psk");
    let identity = IdentityBinding {
        twinnet: TwinnetTag::from_twinnet_id("tn-1"),
        device_id_init: [0x01; 32],
        device_id_resp: [0x02; 32],
        trust_epoch: 1,
        psk_epoch: 1,
        anchor_version: 1,
        delegation_set_digest: [0x03; 32],
    };
    let negotiation = NegotiationBinding {
        h_initiator: [0x04; 32],
        h_responder: [0x05; 32],
        selection_dcbor: vec![0xf6],
    };
    let crypto_prologue = Prologue::new(&identity, &negotiation);
    // Independently constructed from the same two digests, which is what makes
    // `NoiseBinding`'s comparison a check rather than a tautology.
    let tunnel_prologue = TunnelPrologue::new(identity.hash(), negotiation.hash());

    let mut initiator = NoiseBinding::new(
        env,
        Role::Initiator,
        &HandshakeConfig {
            local_static: &initiator_static,
            remote_static: Some(&responder_key),
            psk: &psk,
            prologue: &crypto_prologue,
        },
        &responder_key,
    )
    .expect("the initiator binding builds");
    let mut responder = NoiseBinding::new(
        env,
        Role::Responder,
        &HandshakeConfig {
            local_static: &responder_static,
            // `IK` learns the initiator's static from message 1; `NoiseBinding`
            // refuses any that is not `expected_peer`.
            remote_static: None,
            psk: &psk,
            prologue: &crypto_prologue,
        },
        &initiator_key,
    )
    .expect("the responder binding builds");

    let mut message_one = Vec::new();
    initiator
        .write_initiation(&tunnel_prologue, &mut message_one)
        .expect("message 1");
    let mut message_two = Vec::new();
    let responder_keys = responder
        .read_initiation_write_response(&tunnel_prologue, &message_one, &mut message_two)
        .expect("the responder authenticates message 1");
    let initiator_keys = initiator
        .read_response(&message_two)
        .expect("the initiator authenticates message 2");

    Handshaked {
        initiator_keys,
        responder_keys,
        initiator_established: initiator
            .take_established()
            .expect("a completed binding holds the resumption half"),
        responder_established: responder
            .take_established()
            .expect("a completed binding holds the resumption half"),
        initiator_static: initiator_pub,
        responder_static: responder_pub,
    }
}

/// A [`dp::Fabric`] whose two ends are keyed by one real handshake.
///
/// `left` is the handshake **initiator** and `right` the **responder**, so the
/// two directions are keyed by Noise's two distinct `Split()` outputs — which
/// is the property `producer_and_consumer_direction_keys_are_separated` and the
/// reflection test both rest on.
#[must_use]
pub fn fabric() -> (dp::Fabric, Env, Handshaked) {
    let (env, _time) = testing::env();
    let handshaked = handshake(&env);
    let net = MockNetwork::new();
    let left_adapter = Arc::new(MockAdapter::on_network(&net, &MockOptions::default()));
    let right_adapter = Arc::new(MockAdapter::on_network(&net, &MockOptions::default()));
    let observer_adapter = Arc::new(MockAdapter::on_network(&net, &MockOptions::default()));

    let (left_socket, left_endpoint) = dp::bind(&left_adapter);
    let (right_socket, right_endpoint) = dp::bind(&right_adapter);
    let (observer, observer_endpoint) = dp::bind(&observer_adapter);

    let left_handle = dp::interface(&left_adapter);
    let right_handle = dp::interface(&right_adapter);

    // Fresh keys for the fabric; `handshaked` keeps a second, independent pair
    // for the tests that need to seal and open outside a pump.
    let wired = handshake(&env);
    let left_tunnel = dp::tunnel(0x11, wired.initiator_keys, right_endpoint, &env);
    let right_tunnel = dp::tunnel(0x22, wired.responder_keys, left_endpoint, &env);

    let left_cancel = Cancel::new();
    let right_cancel = Cancel::new();

    let left_pump = Pump::new(PumpParts {
        env: env.clone(),
        adapter: Arc::clone(&left_adapter) as Arc<dyn PlatformAdapter>,
        handle: left_handle,
        socket: Arc::clone(&left_socket),
        tunnel: Arc::clone(&left_tunnel),
        local_receiver: dp::LEFT_INDEX,
        peer_receiver: dp::RIGHT_INDEX,
        overlay_mtu: dp::MTU,
        cancel: left_cancel.clone(),
    })
    .expect("a Userspace adapter at the floor MTU");
    let right_pump = Pump::new(PumpParts {
        env: env.clone(),
        adapter: Arc::clone(&right_adapter) as Arc<dyn PlatformAdapter>,
        handle: right_handle,
        socket: Arc::clone(&right_socket),
        tunnel: Arc::clone(&right_tunnel),
        local_receiver: dp::RIGHT_INDEX,
        peer_receiver: dp::LEFT_INDEX,
        overlay_mtu: dp::MTU,
        cancel: right_cancel.clone(),
    })
    .expect("a Userspace adapter at the floor MTU");

    let fabric = dp::Fabric {
        left: dp::End {
            adapter: left_adapter,
            endpoint: left_endpoint,
            tunnel: left_tunnel,
            pump: left_pump,
            cancel: left_cancel,
        },
        right: dp::End {
            adapter: right_adapter,
            endpoint: right_endpoint,
            tunnel: right_tunnel,
            pump: right_pump,
            cancel: right_cancel,
        },
        observer,
        observer_endpoint,
    };
    (fabric, env, handshaked)
}

/// One X25519 static in the locked allocator, from a fixed byte.
///
/// Deterministic on purpose: ADR-0018 CD-3 bans the platform CSPRNG outside
/// `twinvpn-env`'s binding, and the handshake's *correctness* does not depend on
/// the statics being unpredictable. The ephemerals still come from `Env`.
fn local_static(seed: u8) -> LockedBytes {
    LockedBytes::new_with(32, |dst| {
        dst.fill(seed);
        // The implementation clamps; a fixed pattern is a valid scalar.
        dst[0] = seed | 0x01;
    })
    .expect("locked static")
}

/// A datagram this device would put on the wire for `counter`, built by sealing
/// `plaintext` under `keys` and prefixing the production 16-octet header.
///
/// Uses [`twinvpn_core::datapath::DataHeader`] rather than assembling the
/// header by hand, so a change to the framing moves one place and this harness
/// cannot drift away from what the pump emits.
///
/// # Panics
///
/// If the seal is refused. The counters are handed out in order by the caller.
#[must_use]
pub fn seal_datagram(
    keys: &dyn TransportKeys,
    receiver: twinvpn_core::datapath::ReceiverIndex,
    counter: u64,
    plaintext: &[u8],
) -> Vec<u8> {
    let mut record = Vec::new();
    keys.seal(counter, plaintext, &mut record)
        .expect("the session seals under its own next counter");
    let mut datagram = Vec::new();
    twinvpn_core::datapath::DataHeader { receiver, counter }.write(&mut datagram);
    datagram.extend_from_slice(&record);
    datagram
}

/// Splits a wire datagram into its header and the sealed record.
///
/// # Panics
///
/// If it is not a well-formed transport-data frame.
#[must_use]
pub fn split(datagram: &[u8]) -> (twinvpn_core::datapath::DataHeader, Vec<u8>) {
    let (header, record) =
        twinvpn_core::datapath::DataHeader::parse(datagram).expect("a transport-data frame");
    (header, record.to_vec())
}
