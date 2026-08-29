//! A relay stand-in assembled from the **real relay service's own code**.
//!
//! Split out of `tests/e2e/real_crypto_relay_leg.rs` only to keep both files
//! under `CLAUDE.md`'s 500-line rule. It is reached through `#[path]` from that
//! file and is not a test target of its own.
//!
//! # Why this is not another hand-written relay
//!
//! `core/crates/twinvpn-core/tests/relay.rs` already drives the device leg
//! against a stand-in that encodes the relay's side **by hand**, transcribed
//! from `services/relay/src/{control,status,frame}.rs`. That was the only option
//! available to it: `core/` and `services/` are separate cargo workspaces and
//! neither can link the other.
//!
//! `tests/` can link both — that is the whole reason the integration lead added
//! the server artifacts to this workspace (`tests/Cargo.toml` §"THE SERVER AND
//! SHELL ARTIFACTS", `tests/README.md` §8). So every octet the relay side of
//! this file produces or checks comes from the shipped relay:
//!
//! | What | Whose code |
//! |---|---|
//! | the `Noise_IK` leg responder and the cookie jar | `twinvpn_relay::leg::{LegHandshake, CookieJar}` |
//! | the frame MAC | `twinvpn_relay::provider::CryptoProvider` — the production binding |
//! | parsing the device's frames | `twinvpn_relay::frame::RelayFrame::parse` |
//! | counter reconstruction and the replay window | `twinvpn_relay::frame::CounterWindow` |
//! | the `BOUND` body and every control frame's octets | `twinvpn_relay::control` |
//! | rewriting `flow_id`/`counter_low` for the egress half-flow | `twinvpn_relay::frame::RelayFrame::reframe` |
//!
//! Nothing below re-declares a wire layout. `tests/README.md` §3's rule —
//! *read a shared artifact by value, never another crate's source* — applied to
//! a relay.
//!
//! # What it deliberately is not
//!
//! It is not `twinvpn_relay::engine`. There is no admission policy, no token
//! verification, no quota, no DRR and no drain: those are `relay-plane`'s and
//! are tested in `services/relay`'s own suite. This composes the **datagram
//! path** — handshake, bind, forward — because that is the only part a device
//! can be run against, and running a device against it is the point.

use std::sync::Arc;

use bytes::Bytes;
use twinvpn_crypto::relay_leg::{static_public_key, Entropy, STATIC_KEY_LEN};
use twinvpn_platform::socket::UdpSocket;
use twinvpn_relay::control::{self, BindBody, BoundBody, BoundState};
use twinvpn_relay::crypto::{LegKey, RelayCrypto};
use twinvpn_relay::frame::{
    CounterWindow, FrameType, RelayFrame, HEADER_LEN, MAX_DATA_PAYLOAD_BYTES,
};
use twinvpn_relay::leg::{CookieJar, LegHandshake};
use twinvpn_relay::provider::CryptoProvider;
use twinvpn_system_tests::block_on;
use twinvpn_types::Endpoint;

/// One device's half-flow, as the relay knows it.
struct Half {
    /// Where the device is.
    peer: Endpoint,
    /// The only per-leg key the relay ever holds (ADR-0005 §7.1).
    k_leg: LegKey,
    /// The `flow_id` this relay named for the half-flow.
    flow_id: u32,
    /// The `pair_tag` the device bound, once it has sent a `BIND`.
    pair_tag: Option<[u8; 16]>,
    /// The device's counters, reconstructed the way §9.1 requires.
    ingress: CounterWindow,
    /// The next counter this relay will stamp on a frame to the device.
    egress: u64,
}

/// The relay, as far as a device can tell.
pub struct RelayStandIn {
    socket: Arc<dyn UdpSocket>,
    /// The relay's static X25519 private key — one of the two items in its
    /// complete key inventory.
    static_private: [u8; STATIC_KEY_LEN],
    entropy: Arc<dyn Entropy>,
    cookies: CookieJar,
    crypto: CryptoProvider,
    halves: Vec<Half>,
    /// Every `DATA` payload this relay has carried — its entire view of the
    /// traffic. ADR-0005 §7.1's oracle needs the captures as well as the keys.
    pub observed: Vec<Vec<u8>>,
    /// Every token presentation recovered from an encrypted handshake payload.
    pub tokens_seen: Vec<Vec<u8>>,
    /// How many `DATA` frames were forwarded to a partner half-flow.
    pub forwarded: usize,
    /// How many datagrams were dropped because their MAC did not verify.
    pub mac_failures: usize,
}

impl RelayStandIn {
    /// A relay listening on `socket`.
    ///
    /// # Panics
    ///
    /// If the injected entropy cannot produce a cookie secret — a broken rig.
    #[must_use]
    pub fn new(socket: Arc<dyn UdpSocket>, entropy: Arc<dyn Entropy>) -> Self {
        let cookies = CookieJar::new(&entropy).expect("a cookie secret");
        Self {
            socket,
            static_private: [0x07; STATIC_KEY_LEN],
            entropy,
            cookies,
            crypto: CryptoProvider,
            halves: Vec::new(),
            observed: Vec::new(),
            tokens_seen: Vec::new(),
            forwarded: 0,
            mac_failures: 0,
        }
    }

    /// The static public key a device must have from a **verified** map before
    /// it may bind this relay (ADR-0006 §11.2).
    ///
    /// # Panics
    ///
    /// If the fixture static has no public half — a broken rig.
    #[must_use]
    pub fn public(&self) -> [u8; STATIC_KEY_LEN] {
        static_public_key(&self.static_private).expect("a static public half")
    }

    /// Where this relay is bound.
    ///
    /// # Panics
    ///
    /// If the socket is not bound — a broken rig.
    #[must_use]
    pub fn endpoint(&self) -> Endpoint {
        self.socket.local_endpoint().expect("bound")
    }

    /// The relay's **complete** key inventory, as ADR-0005 §7.1 enumerates it.
    ///
    /// Two items for a one-leg relay: the static private key and each `K_leg`.
    /// The issuer public-key set is the third and is public, so it is not a
    /// candidate decryption key. Returning it rather than describing it is what
    /// lets a test feed the whole set to a decryptor instead of asserting from
    /// prose.
    #[must_use]
    pub fn key_inventory(&self) -> Vec<[u8; 32]> {
        let mut keys = vec![self.static_private];
        for half in &self.halves {
            keys.push(*half.k_leg.expose());
        }
        keys
    }

    /// One synchronous turn: take a datagram if one is queued, and answer it.
    ///
    /// Returns whether anything was processed, so a caller can drive until the
    /// relay is idle without guessing a turn count.
    ///
    /// # Panics
    ///
    /// If the fabric delivers a truncated datagram — the buffer is the wire
    /// maximum, so that would be a broken rig.
    pub fn step(&mut self) -> bool {
        let mut buf = vec![0_u8; HEADER_LEN + MAX_DATA_PAYLOAD_BYTES];
        let Some(meta) = poll_once(self.socket.recv_from(&mut buf)) else {
            return false;
        };
        let meta = meta.expect("the fabric delivered");
        assert!(!meta.truncated, "the stand-in's buffer is the wire maximum");
        buf.truncate(meta.len);
        let from = meta.source;

        // The shipped parser. A device frame this refuses is a device frame the
        // real relay would refuse.
        let Ok(frame) = RelayFrame::parse(Bytes::from(buf.clone())) else {
            return true;
        };
        assert!(
            frame.kind().device_may_send(),
            "W-32: a device sent a relay-to-device frame type"
        );

        match frame.kind() {
            FrameType::HandshakeInit => self.on_handshake(&frame, &buf, from),
            FrameType::Bind => self.on_bind(&frame, from),
            FrameType::Data => self.on_data(&frame, from),
            _ => {}
        }
        true
    }

    /// Runs turns until nothing is queued. Bounded, so a loop cannot hang a
    /// test.
    ///
    /// # Panics
    ///
    /// If the relay is still busy after 64 turns — a rig that does not settle.
    pub fn settle(&mut self) {
        for _ in 0..64 {
            if !self.step() {
                return;
            }
        }
        panic!("the relay did not go idle in 64 turns");
    }

    fn on_handshake(&mut self, frame: &RelayFrame, datagram: &[u8], from: Endpoint) {
        // ADR-0005 §11.5's cookie gate: flag bit 0 says whether one rode along,
        // and it is stripped exactly as `admit.rs` strips it.
        let body = &datagram[HEADER_LEN..];
        let noise = if frame.flags() & 0x01 == 0 {
            body
        } else {
            &body[16..]
        };

        let handshake = LegHandshake {
            static_private: &self.static_private,
            entropy: &self.entropy,
            cookies: &self.cookies,
            crypto: &self.crypto,
        };
        let peer = std::net::SocketAddr::from(([192, 0, 2, 1], 1));
        let Ok((message_2, mut completed)) = handshake.step(peer, noise) else {
            return;
        };
        self.tokens_seen.push(completed.take_payload());

        let flow_id = 0x0A00_0000 | u32::try_from(self.halves.len() + 1).expect("few halves");
        self.halves.push(Half {
            peer: from,
            k_leg: LegKey::new(*completed.k_leg()),
            flow_id,
            pair_tag: None,
            ingress: CounterWindow::new(),
            egress: 0,
        });

        // A leg-setup frame carries no MAC and no flow: there is no `K_leg` yet.
        let reply = control::encode_frame(FrameType::HandshakeResp, 0, 0, [0; 8], &message_2);
        self.send(&reply, from);
    }

    fn on_bind(&mut self, frame: &RelayFrame, from: Endpoint) {
        let Some(index) = self.index_of(from) else {
            return;
        };
        if !self.verify(index, frame) {
            return;
        }
        let Ok(body) = BindBody::decode(frame.payload().as_bytes()) else {
            return;
        };
        self.halves[index].pair_tag = Some(body.pair_tag);

        // §11.1(4): the first BIND on a tag opens a pending slot, the second
        // binds it. `partner_of` is what decides which this is.
        let state = if self.partner_of(index).is_some() {
            BoundState::Bound
        } else {
            BoundState::Pending
        };
        let out = BoundBody {
            state,
            pending_ttl_ms: 30_000,
        }
        .encode();
        let flow_id = self.halves[index].flow_id;
        let tag = self.mac(
            index,
            &control::mac_input(FrameType::Bound, flow_id, 0, &out),
        );
        let reply = control::encode_frame(FrameType::Bound, flow_id, 0, tag, &out);
        self.send(&reply, from);
    }

    fn on_data(&mut self, frame: &RelayFrame, from: Endpoint) {
        let Some(index) = self.index_of(from) else {
            return;
        };
        if !self.verify(index, frame) {
            return;
        }
        // The relay's entire view of the traffic: a length and some octets it
        // has no key for.
        self.observed.push(frame.payload().as_bytes().to_vec());

        let Some(partner) = self.partner_of(index) else {
            return;
        };
        // §11.1(5): `flow_id` and `counter_low` are rewritten for the outgoing
        // half-flow; nothing else is touched. `reframe` is the shipped relay's
        // own function for that, and it copies the payload byte for byte.
        let counter = self.halves[partner].egress;
        let flow_id = self.halves[partner].flow_id;
        let tag = self.mac(partner, &frame.egress_mac_input(flow_id, counter));
        let counter_low = u16::try_from(counter & 0xFFFF).expect("masked");
        let out = frame.reframe(flow_id, counter_low, tag);
        self.halves[partner].egress += 1;
        self.forwarded += 1;
        let to = self.halves[partner].peer;
        self.send(&out, to);
    }

    fn index_of(&self, peer: Endpoint) -> Option<usize> {
        self.halves.iter().position(|half| half.peer == peer)
    }

    fn partner_of(&self, index: usize) -> Option<usize> {
        let tag = self.halves[index].pair_tag?;
        self.halves
            .iter()
            .position(|half| half.pair_tag == Some(tag) && half.peer != self.halves[index].peer)
    }

    /// Reconstructs the counter, verifies the MAC over the **full** value, and
    /// only then admits the counter — the order `services/relay/src/pump.rs`
    /// fixes, because admitting first would let a forged frame advance the
    /// window.
    fn verify(&mut self, index: usize, frame: &RelayFrame) -> bool {
        let counter = self.halves[index].ingress.reconstruct(frame.counter_low());
        let ok = self.crypto.verify_frame_mac(
            &self.halves[index].k_leg,
            &frame.mac_input(counter),
            frame.auth_tag(),
        );
        if !ok {
            self.mac_failures += 1;
            return false;
        }
        self.halves[index].ingress.accept(counter)
    }

    fn mac(&self, index: usize, input: &[u8]) -> [u8; 8] {
        self.crypto
            .frame_mac(&self.halves[index].k_leg, input)
            .expect("the production provider binds a frame MAC")
    }

    fn send(&self, datagram: &[u8], to: Endpoint) {
        let sent = block_on(self.socket.send_to(datagram, &to)).expect("the mock delivers");
        assert_eq!(sent, datagram.len());
    }
}

/// Polls once and reports whether anything was ready.
///
/// The mock socket answers `Pending` when its queue is empty, which is how a
/// caller knows the relay has nothing to do without a timer.
fn poll_once<F: core::future::Future>(future: F) -> Option<F::Output> {
    let mut future = Box::pin(future);
    let waker = core::task::Waker::noop();
    match future
        .as_mut()
        .poll(&mut core::task::Context::from_waker(waker))
    {
        core::task::Poll::Ready(value) => Some(value),
        core::task::Poll::Pending => None,
    }
}

/// Drives one device-side future, letting the relay answer whenever it stalls.
///
/// That interleaving *is* the deployment: a device sends, a relay answers, a
/// device reads. Doing it explicitly keeps the ordering reproducible.
///
/// # Panics
///
/// If the exchange has not settled after 32 turns.
pub fn drive<T>(future: impl core::future::Future<Output = T>, relay: &mut RelayStandIn) -> T {
    let mut future = Box::pin(future);
    let waker = core::task::Waker::noop();
    for _ in 0..32 {
        if let core::task::Poll::Ready(value) = future
            .as_mut()
            .poll(&mut core::task::Context::from_waker(waker))
        {
            return value;
        }
        relay.step();
    }
    panic!("the exchange did not settle in 32 turns");
}
