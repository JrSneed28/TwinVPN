//! The harness `datapath.rs` runs its assertions against: a poll driver, a
//! deliberately non-cryptographic key pair, and two pumps facing each other on
//! one mock fabric with an attacker beside them.
//!
//! Split out of `tests/datapath.rs` only to keep both files under `CLAUDE.md`'s
//! 500-line rule. It is reached through `#[path]` from that file and is not a
//! test target of its own — nothing in `tests/<dir>/` is.
//!
//! # About the transport keys used here
//!
//! [`StubKeys`] is **not cryptography** and says so at every opportunity. The
//! production `TransportKeys` is `twinvpn_tunnel::bind::SessionKeys`, over a
//! real `Noise_IKpsk2` handshake, and it is exercised against real vectors in
//! `twinvpn-tunnel`'s own `tests/l_data_binding.rs`. Reaching it from *this*
//! crate needs a `VerifiedTunnelKey`, which needs a signed `TunnelKeyBinding`,
//! which needs `twinvpn-crypto`'s `test-support` fixtures — a dev-dependency
//! feature `twinvpn-core`'s manifest does not enable and this domain does not
//! own. It is reported as an integration item rather than worked around, and
//! the stub is faithful to the two properties the pump actually depends on: a
//! modified frame fails to open, and the counter is bound into the record.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::sync::{Arc, Mutex};

use twinvpn_core::datapath::{
    Cancel, Pump, PumpParts, ReceiverIndex, Step, OVERLAY_MTU_FLOOR, TAG_BYTES,
};
use twinvpn_core::testing;
use twinvpn_env::Env;
use twinvpn_platform::config::TunnelHandle;
use twinvpn_platform::iface::InterfaceName;
use twinvpn_platform::mock::{MockAdapter, MockNetwork, MockOptions};
use twinvpn_platform::socket::{SocketFamily, SocketOptions, UdpBindSpec, UdpSocket};
use twinvpn_platform::PlatformAdapter;
use twinvpn_tunnel::crypto::{CryptoUnavailable, TransportKeys};
use twinvpn_tunnel::{establish_tunnel, Tunnel, TunnelState};
use twinvpn_types::{Endpoint, SessionId, TunnelId};

// ---------------------------------------------------------------------------
// A driver, so a test needs no runtime
// ---------------------------------------------------------------------------

/// Drives a future that must be ready on its first poll.
///
/// Every mock capability a step touches is ready immediately once its input is
/// queued, so a step that stalls here is a defect and not a slow test —
/// asserting that is more useful than quietly spinning.
pub fn ready<F: Future>(future: F) -> F::Output {
    match poll(future) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the mock seam stalled; every capability here is ready inline"),
    }
}

/// Polls once and reports what happened. The cancellation test needs the
/// `Pending`.
pub fn poll<F: Future>(future: F) -> Poll<F::Output> {
    let mut future = Box::pin(future);
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    future.as_mut().poll(&mut cx)
}

/// A future held across several polls, so cancellation can be observed
/// *arriving* rather than only being true beforehand.
pub fn parked<'a, T>(
    future: impl Future<Output = T> + 'a,
) -> Pin<Box<dyn Future<Output = T> + 'a>> {
    Box::pin(future)
}

pub fn poll_parked<T>(future: &mut Pin<Box<dyn Future<Output = T> + '_>>) -> Poll<T> {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    future.as_mut().poll(&mut cx)
}

// ---------------------------------------------------------------------------
// Transport keys that are deliberately not cryptography
// ---------------------------------------------------------------------------

/// A **non-cryptographic** stand-in for `twinvpn_tunnel::bind::SessionKeys`.
///
/// It exists so this file can build two facing tunnels without a Noise
/// handshake, and it is faithful to exactly the two properties the pump relies
/// on: a record that has been modified does not open, and the counter is mixed
/// into both the keystream and the tag so a record cannot be lifted from one
/// counter to another. It is not confidential, not authenticated in any
/// meaningful sense, and never compiled into anything shipped.
pub struct StubKeys {
    send: [u8; 32],
    recv: [u8; 32],
}

pub fn mask(key: &[u8; 32], counter: u64, index: usize) -> u8 {
    let counter = counter.to_le_bytes();
    key[index % 32] ^ counter[index % 8] ^ counter[(index / 8) % 8]
}

pub fn stub_tag(key: &[u8; 32], counter: u64, plaintext: &[u8]) -> [u8; TAG_BYTES] {
    let counter = counter.to_le_bytes();
    let mut tag = [0u8; TAG_BYTES];
    for (index, slot) in tag.iter_mut().enumerate() {
        *slot = key[index] ^ key[index + 16] ^ counter[index % 8];
    }
    for (index, byte) in plaintext.iter().enumerate() {
        let slot = index % TAG_BYTES;
        tag[slot] =
            tag[slot].wrapping_add(*byte).rotate_left(3).wrapping_mul(3) ^ key[(index + 1) % 32];
    }
    tag
}

impl TransportKeys for StubKeys {
    fn seal(
        &self,
        counter: u64,
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoUnavailable> {
        out.clear();
        out.extend(
            plaintext
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask(&self.send, counter, index)),
        );
        out.extend_from_slice(&stub_tag(&self.send, counter, plaintext));
        Ok(())
    }

    fn open(
        &self,
        counter: u64,
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoUnavailable> {
        if ciphertext.len() < TAG_BYTES {
            return Err(CryptoUnavailable);
        }
        let (body, tag) = ciphertext.split_at(ciphertext.len() - TAG_BYTES);
        let plaintext: Vec<u8> = body
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask(&self.recv, counter, index))
            .collect();
        if stub_tag(&self.recv, counter, &plaintext).as_slice() != tag {
            // A failed open produces nothing. The pump must see a refusal, not a
            // partially written buffer.
            return Err(CryptoUnavailable);
        }
        out.clear();
        out.extend_from_slice(&plaintext);
        Ok(())
    }

    fn zeroize(&mut self) {
        self.send = [0u8; 32];
        self.recv = [0u8; 32];
    }
}

/// One key pair, wired so each end's send key is the other's receive key.
pub fn paired() -> (Box<dyn TransportKeys>, Box<dyn TransportKeys>) {
    let left = [0x11u8; 32];
    let right = [0x22u8; 32];
    (
        Box::new(StubKeys {
            send: left,
            recv: right,
        }),
        Box::new(StubKeys {
            send: right,
            recv: left,
        }),
    )
}

// ---------------------------------------------------------------------------
// The fabric
// ---------------------------------------------------------------------------

pub const MTU: u32 = OVERLAY_MTU_FLOOR;
pub const LEFT_INDEX: ReceiverIndex = ReceiverIndex(0x0000_1111);
pub const RIGHT_INDEX: ReceiverIndex = ReceiverIndex(0x0000_2222);

pub fn bind(adapter: &Arc<MockAdapter>) -> (Arc<dyn UdpSocket>, Endpoint) {
    let spec = UdpBindSpec {
        family: SocketFamily::V4,
        local: None,
        options: SocketOptions::default(),
    };
    let socket = ready(adapter.sockets().bind_udp(&spec)).expect("the mock binds");
    let endpoint = socket.local_endpoint().expect("bound");
    (Arc::from(socket), endpoint)
}

pub fn interface(adapter: &Arc<MockAdapter>) -> TunnelHandle {
    let name = InterfaceName::new("tvpn0").expect("valid name");
    ready(adapter.tunnel().create_interface(&name, MTU)).expect("the mock creates it")
}

/// An established tunnel aimed at `peer`.
///
/// It goes through `Confirming` and out the other side, because ADR-0014 N-8
/// makes `NegotiationConfirm` the first in-session message and
/// `TunnelState::carries_traffic` answers `false` until it has matched — so a
/// tunnel that skipped it would refuse to seal, and this file would be testing
/// the wrong refusal.
pub fn tunnel(
    tag: u8,
    keys: Box<dyn TransportKeys>,
    peer: Endpoint,
    env: &Env,
) -> Arc<Mutex<Tunnel>> {
    let mut tunnel = establish_tunnel(
        TunnelId::from_slice(&[tag; 16]).expect("16 bytes"),
        SessionId::from_slice(&[tag; 16]).expect("16 bytes"),
        keys,
        peer,
        1,
        env.now_monotonic(),
    );
    let transcript = [0x5a; 32];
    tunnel
        .confirm_negotiation(&transcript, &transcript)
        .expect("matching transcripts");
    assert_eq!(tunnel.state(), TunnelState::Established);
    Arc::new(Mutex::new(tunnel))
}

/// One end of the tunnel, with its pump.
pub struct End {
    pub adapter: Arc<MockAdapter>,
    pub endpoint: Endpoint,
    pub tunnel: Arc<Mutex<Tunnel>>,
    pub pump: Pump,
    pub cancel: Cancel,
}

impl End {
    pub fn written(&self) -> Vec<Vec<u8>> {
        self.adapter.tunnel_mock().written()
    }

    pub fn carries_traffic(&self) -> bool {
        self.tunnel
            .lock()
            .expect("not poisoned")
            .state()
            .carries_traffic()
    }
}

/// Two ends and an observer, all on one fabric.
pub struct Fabric {
    pub left: End,
    pub right: End,
    /// A third socket on the same network, used both as an on-path capture
    /// point and as the injector for every hostile-datagram test.
    pub observer: Arc<dyn UdpSocket>,
    pub observer_endpoint: Endpoint,
}

pub fn fabric() -> Fabric {
    let (env, _time) = testing::env();
    let net = MockNetwork::new();
    let left_adapter = Arc::new(MockAdapter::on_network(&net, &MockOptions::default()));
    let right_adapter = Arc::new(MockAdapter::on_network(&net, &MockOptions::default()));
    let observer_adapter = Arc::new(MockAdapter::on_network(&net, &MockOptions::default()));

    let (left_socket, left_endpoint) = bind(&left_adapter);
    let (right_socket, right_endpoint) = bind(&right_adapter);
    let (observer, observer_endpoint) = bind(&observer_adapter);

    let left_handle = interface(&left_adapter);
    let right_handle = interface(&right_adapter);

    let (left_keys, right_keys) = paired();
    let left_tunnel = tunnel(0x11, left_keys, right_endpoint, &env);
    let right_tunnel = tunnel(0x22, right_keys, left_endpoint, &env);

    let left_cancel = Cancel::new();
    let right_cancel = Cancel::new();

    let left_pump = Pump::new(PumpParts {
        env: env.clone(),
        adapter: Arc::clone(&left_adapter) as Arc<dyn PlatformAdapter>,
        handle: left_handle,
        socket: Arc::clone(&left_socket),
        tunnel: Arc::clone(&left_tunnel),
        local_receiver: LEFT_INDEX,
        peer_receiver: RIGHT_INDEX,
        overlay_mtu: MTU,
        cancel: left_cancel.clone(),
    })
    .expect("a Userspace adapter at the floor MTU");
    let right_pump = Pump::new(PumpParts {
        env,
        adapter: Arc::clone(&right_adapter) as Arc<dyn PlatformAdapter>,
        handle: right_handle,
        socket: Arc::clone(&right_socket),
        tunnel: Arc::clone(&right_tunnel),
        local_receiver: RIGHT_INDEX,
        peer_receiver: LEFT_INDEX,
        overlay_mtu: MTU,
        cancel: right_cancel.clone(),
    })
    .expect("a Userspace adapter at the floor MTU");

    Fabric {
        left: End {
            adapter: left_adapter,
            endpoint: left_endpoint,
            tunnel: left_tunnel,
            pump: left_pump,
            cancel: left_cancel,
        },
        right: End {
            adapter: right_adapter,
            endpoint: right_endpoint,
            tunnel: right_tunnel,
            pump: right_pump,
            cancel: right_cancel,
        },
        observer,
        observer_endpoint,
    }
}

/// A recognisable plaintext IP packet. Its contents are arbitrary; what matters
/// is that the *same bytes* come out the far side.
pub fn packet(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index % 251).expect("modulo 251"))
        .collect()
}

/// Captures the datagram the left pump puts on the wire, by aiming its
/// authoritative endpoint at the observer for one packet.
///
/// An on-path capture, which is exactly the adversary ADR-0001 §7.6 discusses
/// and exactly what a replay needs.
pub fn capture(fabric: &Fabric, plaintext: &[u8]) -> Vec<u8> {
    fabric
        .left
        .adapter
        .tunnel_mock()
        .push_inbound(plaintext.to_vec());
    {
        let mut tunnel = fabric.left.tunnel.lock().expect("not poisoned");
        tunnel.offer_endpoint(fabric.observer_endpoint);
        assert!(tunnel.commit_endpoint(true), "the observer is now the peer");
    }
    let mut buffers = fabric.left.pump.buffers();
    assert_eq!(
        ready(fabric.left.pump.step_outbound(&mut buffers)),
        Step::Moved(plaintext.len())
    );
    // Restore the real peer so the fabric is usable afterwards.
    {
        let mut tunnel = fabric.left.tunnel.lock().expect("not poisoned");
        tunnel.offer_endpoint(fabric.right.endpoint);
        assert!(tunnel.commit_endpoint(true));
    }

    let mut wire = vec![0u8; fabric.left.pump.budget().datagram_capacity()];
    let received = ready(fabric.observer.recv_from(&mut wire)).expect("the observer receives");
    assert!(!received.truncated);
    wire.truncate(received.len);
    wire
}

/// Puts `datagram` on the wire aimed at `to`, as an off-path injector would.
pub fn inject(fabric: &Fabric, datagram: &[u8], to: Endpoint) {
    let sent = ready(fabric.observer.send_to(datagram, &to)).expect("the mock delivers");
    assert_eq!(sent, datagram.len());
}
