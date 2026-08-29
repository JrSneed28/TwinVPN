//! Two composed endpoints, an on-path observer between them, and a real
//! `Noise_IKpsk2` session carrying packets across.
//!
//! **Owner:** `test-engineering`. Never shipped.
//!
//! **Authority:** ADR-0018 §11.2 row 2.3 (*"elsewhere the core **is** the
//! datapath"*), CB-1, CB-2, CD-2, CD-5; ADR-0001 §7.2, §7.6, §11 items 1 and 2;
//! ADR-0010 **R1**; ADR-0014 N-8/N-9.
//!
//! # What a [`Crossing`] composes
//!
//! Three [`MockAdapter`]s on one [`MockNetwork`]: a left endpoint, a right
//! endpoint, and an **observer** sitting between them. Each endpoint owns a real
//! `twinvpn_platform` TUN device, a real UDP socket, a real
//! `twinvpn_tunnel::Tunnel` holding production
//! `twinvpn_tunnel::bind::SessionKeys` from a real handshake, and a real
//! [`Pump`]. Nothing between the two TUN devices is a stand-in for a primitive.
//!
//! # Why the observer is on the path rather than beside it
//!
//! Both tunnels' authoritative endpoint is the observer's, so **every** datagram
//! is delivered by hand: the test sees the exact octets that cross and chooses
//! whether to forward them, forward them twice, or forward them altered. That is
//! the ADR-0001 §7.6 on-path adversary, and it is the only position from which a
//! replay or a tamper can be injected as the *same* bytes the sender produced.
//!
//! `Pump::step_inbound` deliberately does not check the source endpoint — a
//! frame that authenticates is ours wherever it arrived from, or roaming breaks
//! — so an on-path relay of this shape is exactly as visible to the receiver as
//! the direct path would be. `Tunnel::authoritative_endpoint` is read per packet
//! by the outbound step, so pointing it at the observer is a routing choice and
//! not a change to any code under test.
//!
//! # Both families through one code path (ADR-0010 R1)
//!
//! [`Crossing::open`] takes an [`AddressFamily`] and there is no v4 branch and
//! no v6 branch below it: the family reaches the socket as one
//! `SocketFamily` and reaches the tunnel as the family of its endpoint. A rig
//! that could only be built for IPv4 would make "there is no v6 later"
//! untestable, which is the asymmetry R1 exists to forbid.

use std::sync::{Arc, Mutex};

use twinvpn_core::datapath::{
    Budget, Cancel, Pump, PumpParts, ReceiverIndex, Step, HEADER_BYTES, OVERLAY_MTU_FLOOR,
};
use twinvpn_env::Env;
use twinvpn_platform::config::TunnelHandle;
use twinvpn_platform::iface::InterfaceName;
use twinvpn_platform::mock::{MockAdapter, MockNetwork, MockOptions};
use twinvpn_platform::socket::{SocketFamily, SocketOptions, UdpBindSpec, UdpSocket};
use twinvpn_platform::PlatformAdapter;
use twinvpn_tunnel::crypto::CryptoUnavailable;
use twinvpn_tunnel::{establish_tunnel, Tunnel, TunnelState};
use twinvpn_types::{AddressFamily, Endpoint, IpAddr, Port, SessionId, TunnelId, V4Addr, V6Addr};

use crate::block_on;
use crate::noise::{bound, crypto_env, handshake, peer, transcript, Peer};

/// The overlay MTU every endpoint programs. ADR-0005 §9.2's floor.
pub const MTU: u32 = OVERLAY_MTU_FLOOR;

/// The index the left endpoint expects on frames addressed to it.
pub const LEFT_INDEX: ReceiverIndex = ReceiverIndex(0x0000_1111);
/// The index the right endpoint expects on frames addressed to it.
pub const RIGHT_INDEX: ReceiverIndex = ReceiverIndex(0x0000_2222);

/// The `EpochSeed` both peers hold when they are recipients of the same
/// `TwinNetPSK` seal.
pub const SHARED_EPOCH_SEED: [u8; 32] = [0x5d; 32];

/// An address in the documentation range for `family`, distinguished by `last`.
#[must_use]
pub fn endpoint(family: AddressFamily, last: u8, port: u16) -> Endpoint {
    let address = match family {
        AddressFamily::V4 => IpAddr::V4(V4Addr::from_octets([203, 0, 113, last])),
        AddressFamily::V6 => IpAddr::V6(
            V6Addr::new(
                [
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last,
                ],
                None,
            )
            .expect("a documentation-range v6 address, neither mapped nor link-local"),
        ),
    };
    Endpoint::new(address, Port::new(port).expect("a non-zero port"))
}

fn socket_at(adapter: &Arc<MockAdapter>, at: Endpoint) -> Arc<dyn UdpSocket> {
    let spec = UdpBindSpec {
        family: match at.address.family() {
            AddressFamily::V4 => SocketFamily::V4,
            AddressFamily::V6 => SocketFamily::V6Only,
        },
        local: Some(at),
        options: SocketOptions::default(),
    };
    Arc::from(
        block_on(adapter.sockets().bind_udp(&spec)).expect("the mock binds a socket it was given"),
    )
}

fn interface(adapter: &Arc<MockAdapter>) -> TunnelHandle {
    let name = InterfaceName::new("tvpn0").expect("a valid interface name");
    block_on(adapter.tunnel().create_interface(&name, MTU)).expect("the mock creates an interface")
}

/// One composed endpoint: an adapter, a TUN, a socket, a tunnel and a pump.
pub struct End {
    /// The platform seam every packet reaches the OS through (CB-1).
    pub adapter: Arc<MockAdapter>,
    /// Where this endpoint's socket is bound.
    pub endpoint: Endpoint,
    /// The live tunnel, holding production `SessionKeys`.
    pub tunnel: Arc<Mutex<Tunnel>>,
    /// The packet pump — the code that carries an IP packet either way.
    pub pump: Pump,
    /// The shutdown request, held so a test can trip it.
    pub cancel: Cancel,
}

impl End {
    /// Every plaintext packet this endpoint has written to its TUN device.
    #[must_use]
    pub fn written(&self) -> Vec<Vec<u8>> {
        self.adapter.tunnel_mock().written()
    }

    /// Queues a plaintext packet for the pump to read off the TUN device.
    pub fn offer(&self, packet: &[u8]) {
        self.adapter.tunnel_mock().push_inbound(packet.to_vec());
    }

    /// Whether the tunnel is in a state that carries traffic (N-8/N-9).
    #[must_use]
    pub fn carries_traffic(&self) -> bool {
        self.tunnel
            .lock()
            .expect("not poisoned")
            .state()
            .carries_traffic()
    }
}

/// Two composed endpoints and the observer between them.
pub struct Crossing {
    /// The endpoint that initiated the handshake.
    pub left: End,
    /// The endpoint that responded to it.
    pub right: End,
    /// The on-path socket every datagram passes through.
    pub observer: Arc<dyn UdpSocket>,
    /// Where the observer is bound — and both tunnels' authoritative endpoint.
    pub observer_endpoint: Endpoint,
    /// The family this crossing runs on.
    pub family: AddressFamily,
}

/// Which direction a datagram is travelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Left endpoint to right endpoint.
    LeftToRight,
    /// Right endpoint to left endpoint.
    RightToLeft,
}

impl Crossing {
    /// Composes a crossing over a real handshake between two agreeing peers.
    ///
    /// # Panics
    ///
    /// If the handshake between two agreeing peers does not complete — which is
    /// a defect in the binding, not a case a caller distinguishes.
    #[must_use]
    pub fn open(family: AddressFamily) -> Self {
        Self::attempt(family, &SHARED_EPOCH_SEED, &SHARED_EPOCH_SEED)
            .expect("two agreeing peers complete Noise_IKpsk2")
    }

    /// Composes a crossing, or reports that the handshake refused.
    ///
    /// The two `EpochSeed`s are separate parameters so a caller can build the
    /// wrong-PSK case (ADR-0001 §7.5 item 2) through the **same** path that
    /// builds the working one — the only difference between the two being the
    /// key material, which is what makes the refusal attributable.
    ///
    /// # Errors
    ///
    /// [`CryptoUnavailable`] if the handshake does not complete.
    pub fn attempt(
        family: AddressFamily,
        left_epoch_seed: &[u8; 32],
        right_epoch_seed: &[u8; 32],
    ) -> Result<Self, CryptoUnavailable> {
        let left_env = crypto_env(0x41);
        let right_env = crypto_env(0x42);
        let left_peer: Peer = peer(0x41, 0x11, 1, left_epoch_seed);
        let right_peer: Peer = peer(0x42, 0x22, 1, right_epoch_seed);
        let prologue = bound(1, 1);

        let (left_keys, right_keys) = handshake(
            left_env.env(),
            right_env.env(),
            &left_peer,
            &right_peer,
            &prologue,
        )?;

        let net = MockNetwork::new();
        let left_adapter = Arc::new(MockAdapter::on_network(&net, &MockOptions::default()));
        let right_adapter = Arc::new(MockAdapter::on_network(&net, &MockOptions::default()));
        let observer_adapter = Arc::new(MockAdapter::on_network(&net, &MockOptions::default()));

        let left_endpoint = endpoint(family, 11, 51_820);
        let right_endpoint = endpoint(family, 22, 51_821);
        let observer_endpoint = endpoint(family, 99, 51_899);

        // ADR-0010 R1, made non-vacuous. A family loop that quietly ran the v4
        // arm twice would satisfy every assertion above it, so the rig asserts
        // that the family it was asked for is the family it built — the same
        // reason `tests/README.md` §3 insists a family-shaped assertion fails
        // if either arm is missing.
        for at in [left_endpoint, right_endpoint, observer_endpoint] {
            assert_eq!(
                at.address.family(),
                family,
                "the crossing was asked for {family:?} and bound an endpoint of another family"
            );
        }

        let left_socket = socket_at(&left_adapter, left_endpoint);
        let right_socket = socket_at(&right_adapter, right_endpoint);
        let observer = socket_at(&observer_adapter, observer_endpoint);

        let left_handle = interface(&left_adapter);
        let right_handle = interface(&right_adapter);

        // Both tunnels aim at the observer: every datagram is delivered by hand.
        let left_tunnel = live_tunnel(0x11, left_keys, observer_endpoint, left_env.env());
        let right_tunnel = live_tunnel(0x22, right_keys, observer_endpoint, right_env.env());

        let left_cancel = Cancel::new();
        let right_cancel = Cancel::new();

        let left_pump = Pump::new(PumpParts {
            env: left_env.env_owned(),
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
            env: right_env.env_owned(),
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

        Ok(Self {
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
            family,
        })
    }

    /// The sending end for `direction`.
    #[must_use]
    pub const fn sender(&self, direction: Direction) -> &End {
        match direction {
            Direction::LeftToRight => &self.left,
            Direction::RightToLeft => &self.right,
        }
    }

    /// The receiving end for `direction`.
    #[must_use]
    pub const fn receiver(&self, direction: Direction) -> &End {
        match direction {
            Direction::LeftToRight => &self.right,
            Direction::RightToLeft => &self.left,
        }
    }

    /// Puts one plaintext packet through the sender's pump and returns the
    /// octets the observer saw.
    ///
    /// # Panics
    ///
    /// If the outbound step did not move exactly `plaintext.len()` bytes, or if
    /// the observer received nothing — either is a broken rig rather than a
    /// property under test.
    #[must_use]
    pub fn emit(&self, direction: Direction, plaintext: &[u8]) -> Vec<u8> {
        let sender = self.sender(direction);
        sender.offer(plaintext);
        let mut buffers = sender.pump.buffers();
        assert_eq!(
            block_on(sender.pump.step_outbound(&mut buffers)),
            Step::Moved(plaintext.len()),
            "the outbound step must carry the whole packet or the rig is broken"
        );

        let capacity = Budget::new(MTU)
            .expect("the floor MTU bounds a budget")
            .datagram_capacity();
        let mut wire = vec![0_u8; capacity];
        let received = block_on(self.observer.recv_from(&mut wire)).expect("the observer receives");
        assert!(
            !received.truncated,
            "the observer's buffer is the MTU bound"
        );
        wire.truncate(received.len);
        wire
    }

    /// Hands `datagram` to the receiving end and returns what its pump made of
    /// it.
    ///
    /// # Panics
    ///
    /// If the mock refuses to deliver — a broken rig.
    pub fn deliver(&self, direction: Direction, datagram: &[u8]) -> Step {
        let receiver = self.receiver(direction);
        let sent = block_on(self.observer.send_to(datagram, &receiver.endpoint))
            .expect("the mock network delivers");
        assert_eq!(
            sent,
            datagram.len(),
            "the whole datagram was put on the wire"
        );
        let mut buffers = receiver.pump.buffers();
        block_on(receiver.pump.step_inbound(&mut buffers))
    }

    /// The whole crossing for one packet: emit, inspect, deliver.
    ///
    /// Returns the octets that were on the wire, so a caller can assert about
    /// them; the delivered outcome is asserted here because a helper that
    /// swallowed it would let a caller believe a packet crossed when it did not.
    ///
    /// # Panics
    ///
    /// If the receiving pump did not move the packet.
    pub fn cross(&self, direction: Direction, plaintext: &[u8]) -> Vec<u8> {
        let wire = self.emit(direction, plaintext);
        assert_eq!(
            self.deliver(direction, &wire),
            Step::Moved(plaintext.len()),
            "the inbound step must write the whole packet to the peer's TUN"
        );
        wire
    }
}

/// An established tunnel aimed at `peer_endpoint`.
///
/// It goes through `Confirming` and out the other side: ADR-0014 N-8 makes
/// `NegotiationConfirm` the first in-session message and
/// `TunnelState::carries_traffic` answers `false` until the transcript has
/// matched, so a tunnel that skipped it would refuse to seal and every test
/// above would be measuring the wrong refusal.
fn live_tunnel(
    tag: u8,
    keys: Box<dyn twinvpn_tunnel::crypto::TransportKeys>,
    peer_endpoint: Endpoint,
    env: &Env,
) -> Arc<Mutex<Tunnel>> {
    let mut tunnel = establish_tunnel(
        TunnelId::from_slice(&[tag; 16]).expect("16 bytes"),
        SessionId::from_slice(&[tag; 16]).expect("16 bytes"),
        keys,
        peer_endpoint,
        1,
        env.now_monotonic(),
    );
    assert_eq!(
        tunnel.state(),
        TunnelState::Confirming,
        "N-9: keys exist and nothing carries traffic yet"
    );
    let ours = transcript();
    tunnel
        .confirm_negotiation(&ours, &ours)
        .expect("both ends computed the same negotiation hash");
    assert_eq!(tunnel.state(), TunnelState::Established);
    Arc::new(Mutex::new(tunnel))
}

/// A recognisable plaintext payload of `len` bytes.
///
/// A repeating byte pattern rather than a real IP header: what is under test is
/// that the **same octets** come out the far side, and the pump is deliberately
/// payload-agnostic — it counts packets and bytes and never inspects one
/// (`ownership.md` §6 rule 11).
#[must_use]
pub fn payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index % 251).expect("modulo 251 fits a byte"))
        .collect()
}

/// Whether `needle` appears anywhere in `haystack`.
///
/// Used to assert that a plaintext is **not** on the wire. It is a substring
/// search rather than an equality check on purpose: a header, a tag or a
/// framing change must not be able to make a leak invisible by shifting it.
#[must_use]
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

/// A datagram carrying `plaintext` in the clear, framed the way a real one is.
///
/// This is the **positive control** for every "the plaintext is not on the wire"
/// assertion: an injected condition that *is* the leak, run through the same
/// detector on the same rig. `docs/testing-strategy.md` §6.5 blocker B-7 — a
/// leak test that only ever reports "no leak" is indistinguishable from a leak
/// test that is not looking.
#[must_use]
pub fn unsealed_datagram(plaintext: &[u8]) -> Vec<u8> {
    let mut wire = vec![0_u8; HEADER_BYTES];
    wire.extend_from_slice(plaintext);
    wire
}
