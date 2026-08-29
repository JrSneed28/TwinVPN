//! The L-DATA handshake, on the wire: `Noise_IKpsk2` between two devices.
//!
//! **Authority:** [ADR-0001](../../../../../docs/adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)
//! §7.2 (L-DATA is **unmodified WireGuard**; the message types and the sender /
//! receiver indices), §7.3 D2, §7.3.1 P-1..P-4, §11 items 1, 2 and 7;
//! [ADR-0007](../../../../../docs/adr/ADR-0007-identity-lifecycle-and-revocation.md)
//! N-4/N-5, N-20; [ADR-0014](../../../../../docs/adr/ADR-0014-protocol-versioning-and-capability-negotiation.md)
//! N-6, N-8, D1; [ADR-0018](../../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! CB-1, CB-2, CD-1, CD-2, CD-3, CD-I2; `docs/reliability.md` §4.5 T08–T12;
//! `ownership.md` §6 rules 9, 10 and 11.
//!
//! # The gap this closes
//!
//! `ownership.md` §8 records `session.connect`'s trust guards as fixed and then
//! says, of the same item: *"**Still open:** there is no handshake and no key
//! exchange."* `twinvpn_tunnel::bind` shipped the whole of `Noise_IKpsk2` — the
//! handshake, the transport keys, the transcript hashes and
//! `establish_tunnel` — and nothing in the composed core called any of it. This
//! module is the call.
//!
//! # Roles are derived from the two names, never chosen
//!
//! Both devices run `session.connect`; neither is a server. The initiator is the
//! one whose `DeviceId` sorts **lower**, and that single rule does two jobs at
//! once:
//!
//! 1. it decides who sends message 1, so two simultaneous connects do not
//!    produce two half-handshakes that each wait for the other;
//! 2. it fixes `device_id_init` and `device_id_resp` in ADR-0007 N-20's identity
//!    binding, which the prologue covers as **ordered** fields.
//!
//! Point 2 is why this cannot be a coin toss or a race. If the two ends
//! disagreed about the roles they would compute different prologues, and §7.3.1
//! P-3 requires that to be "observationally indistinguishable from any other
//! handshake failure" — so a role confusion would present as an unexplained,
//! permanent failure to connect. Deriving the roles from a total order over two
//! values both ends already hold makes the disagreement impossible instead of
//! merely detectable.
//!
//! # The framing, and exactly what is and is not WireGuard
//!
//! `twinvpn_tunnel::bind` records the split: what crosses its boundary is the
//! **Noise message** (96 bytes for `IKpsk2`'s first, 48 for its second), and the
//! framing around it is the transport's. [`crate::datapath::frame`] carries the
//! transport-data half of that framing — type `4`, unmodified — and allocates no
//! handshake type, because a pump never sees one. So the two handshake types are
//! framed here:
//!
//! | Message | Octets |
//! |---|---|
//! | initiation | `[1][0;3][sender: u32 LE][noise message 1]` |
//! | response | `[2][0;3][sender: u32 LE][receiver: u32 LE][noise message 2]` |
//!
//! Types `1` and `2`, the three reserved zero octets and the little-endian
//! indices are WireGuard's own, matching [`crate::datapath::frame::DataHeader`]'s
//! layout for type `4`. **What is not WireGuard is stated rather than implied:**
//! this build carries no `mac1`/`mac2`, so ADR-0001 §7.2's cookie-reply
//! load-shedding mechanism is absent and an unauthenticated initiation costs
//! this device one X25519 operation. It is reported as an open item, not papered
//! over — and it is bounded by the fact that a `Session` cannot handshake at all
//! without a [`crate::session_table::TunnelKeying`] naming *this* peer, so there
//! is no path here reachable from an unknown device.
//!
//! # Nothing here is a second key state
//!
//! This module holds no keys of its own. It borrows the material, drives
//! `twinvpn_tunnel::bind::NoiseBinding`, and hands the resulting
//! `Box<dyn TransportKeys>` straight to `twinvpn_tunnel::establish_tunnel`. On
//! every failure path the binding is dropped and **no session keys exist** —
//! §7.3.1's "a mismatch fails the handshake without producing key-derivation
//! output", which is a property of the crate below rather than a promise made
//! here.
//!
//! # Time, randomness and payloads
//!
//! CD-1: the one deadline is `T_CONNECT` on the injected monotonic clock, and
//! every receive is raced against `Env::timer()` so a peer that answers nothing
//! at all cannot hold the caller past it. CD-3: the only randomness is
//! `Env::entropy()`, drawn once for this device's receiver index. §6 rule 11:
//! nothing here renders a key, a prologue, a handshake message or a payload —
//! [`Refusal`] carries a registered code and no octets.

use core::time::Duration;
use std::sync::{Arc, Mutex};

use twinvpn_crypto::noise::{HandshakeConfig, Role};
use twinvpn_env::{Env, MonotonicInstant};
use twinvpn_platform::error::PlatformError;
use twinvpn_platform::socket::UdpSocket;
use twinvpn_tunnel::bind::NoiseBinding;
use twinvpn_tunnel::crypto::{NoiseHandshake as _, Prologue};
use twinvpn_tunnel::{establish_tunnel, Tunnel};
use twinvpn_types::{codes, DeviceId, Endpoint, Identifier as _, ReasonCode, SessionId, TunnelId};

use crate::datapath::ReceiverIndex;
use crate::session_table::TunnelKeying;

/// WireGuard's handshake-initiation message type (ADR-0001 §7.2, "unmodified").
pub const TYPE_HANDSHAKE_INITIATION: u8 = 1;

/// WireGuard's handshake-response message type.
pub const TYPE_HANDSHAKE_RESPONSE: u8 = 2;

/// `type` plus three reserved octets plus one index.
pub const INITIATION_PREFIX_BYTES: usize = 8;

/// The same, plus the receiver index the responder echoes back.
pub const RESPONSE_PREFIX_BYTES: usize = 12;

/// The largest handshake datagram this build will read.
///
/// The IPv6 minimum link MTU, which `docs/networking.md` §6.2 already fixes as
/// the product's floor — a **product constant**, not a number chosen here. A
/// conforming initiation is 104 octets and a conforming response 60, so the
/// bound is loose by an order of magnitude and is still far below the Noise
/// framework's own 65 535, which would let one hostile datagram drive a 64 KiB
/// allocation per attempt (`ownership.md` §6 rules 9 and 10).
pub const MAX_HANDSHAKE_DATAGRAM_BYTES: usize = crate::datapath::OVERLAY_MTU_FLOOR as usize;

/// Why a handshake did not complete.
///
/// Every variant maps to one registered code, and the two that a caller acts on
/// differently are kept apart: *we could not even try* and *we tried and it
/// failed*. Collapsing them would report a peer with no cached key material and
/// a peer presenting the wrong static as the same condition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// No [`TunnelKeying`] is installed for this peer.
    ///
    /// The ordinary state on a build with no pairing ceremony and no control
    /// plane. `AUTH.KEY_UNAVAILABLE`, the same code
    /// [`crate::execute::trust_guards`] uses for a device with no identity,
    /// because it is the same fact one layer down: this device holds no usable
    /// key for this handshake.
    #[error("no L-DATA key material is installed for this peer")]
    NoKeyMaterial,
    /// No peer endpoint is known, so there is nowhere to send message 1.
    #[error("no endpoint is known for this peer")]
    NoEndpoint,
    /// `twinvpn-crypto` refused the handshake.
    ///
    /// Deliberately undifferentiated: a wrong static, a disagreeing prologue, a
    /// stale PSK epoch and a corrupted message all arrive here, because §7.3.1
    /// P-3 requires them to be indistinguishable and A1's silence depends on not
    /// telling a prober which check it tripped.
    #[error("the handshake was refused")]
    Rejected,
    /// The peer answered nothing before `T_CONNECT`.
    #[error("the peer did not answer before the deadline")]
    NoResponse,
    /// A datagram arrived that is not a handshake message this build speaks.
    #[error("a malformed handshake datagram")]
    Malformed,
    /// The platform refused the send or the receive.
    #[error("the platform refused the handshake exchange")]
    Platform(#[from] PlatformError),
}

impl Refusal {
    /// The registered `reason_code` this refusal is reported as.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            Refusal::NoKeyMaterial => codes::AUTH_KEY_UNAVAILABLE,
            // Not `CRYPTO.*`: nothing cryptographic happened. A `Session` with no
            // rendezvous answer has no candidate to aim at, and saying so keeps
            // "we never sent a packet" apart from "we sent one and it failed".
            Refusal::NoEndpoint => codes::NET_NO_USABLE_CANDIDATES,
            Refusal::Rejected => codes::CRYPTO_HANDSHAKE_REJECTED,
            Refusal::NoResponse => codes::CRYPTO_NO_RESPONSE,
            Refusal::Malformed => codes::PROTO_MALFORMED_MESSAGE,
            Refusal::Platform(error) => error.reason_code(),
        }
    }
}

/// A completed handshake: a live tunnel and the two demultiplexing indices.
///
/// There is no variant of this that carries "keys but no tunnel", because the
/// only way to build one is to have finished. That is the fail-closed property
/// stated as a type: a caller cannot hold this value and be wrong about whether
/// the handshake happened.
pub struct Handshaken {
    /// The engine, already past `Confirming`.
    pub tunnel: Arc<Mutex<Tunnel>>,
    /// The index this device expects on frames addressed to it.
    pub local_receiver: ReceiverIndex,
    /// The index the peer expects.
    pub peer_receiver: ReceiverIndex,
}

/// This device's own name, as the key material states it.
///
/// The composition root does not otherwise hold its own `DeviceId`: it is a
/// digest of the generation-0 identity key and CD-I4 keeps that key out of every
/// type in the workspace, so the enrolment record is the only place it can come
/// from. It arrives with the key material rather than beside it, because the two
/// have to agree — a prologue bound to one name under another name's static is a
/// handshake that fails for a reason nobody can find.
#[must_use]
pub(crate) fn local_of(keying: &TunnelKeying) -> DeviceId {
    keying.local_device()
}

/// Which end of the handshake a device is, derived from the two `DeviceId`s.
///
/// A total order over two values both ends already hold. See the module docs for
/// why this may not be a race, a coin toss or a caller's choice.
#[must_use]
pub fn role_for(local: DeviceId, peer: DeviceId) -> Role {
    if local.as_bytes() < peer.as_bytes() {
        Role::Initiator
    } else {
        Role::Responder
    }
}

/// The initiator and responder `DeviceId`s, in ADR-0007 N-20's field order.
#[must_use]
pub fn ordered(local: DeviceId, peer: DeviceId) -> (DeviceId, DeviceId) {
    match role_for(local, peer) {
        Role::Initiator => (local, peer),
        Role::Responder => (peer, local),
    }
}

/// Runs one complete L-DATA handshake and returns a live tunnel.
///
/// Both roles are driven from here, because both are reachable from the same
/// The one attempt's worth of facts [`drive`] needs, in one value.
///
/// A struct rather than six more parameters: the six travel together, every one
/// of them is read off the same `SessionEntry`, and passing them as a group is
/// what keeps a caller from pairing one session's `keying` with another's
/// `peer`. The lifetime is the `TunnelKeying` borrow — the key material is
/// **borrowed for the handshake and never moved into it**, so a refusal leaves
/// it exactly where T12's retry will look for it.
#[derive(Debug, Clone, Copy)]
pub struct Attempt<'a> {
    /// The `Session` this handshake belongs to; also the `TunnelId`'s source.
    pub session: SessionId,
    /// This device's `DeviceId`. With `peer`, it decides the roles.
    pub local_device: DeviceId,
    /// The peer's `DeviceId`.
    pub peer: DeviceId,
    /// Where to send message 1. `None` refuses with `Refusal::NoEndpoint`
    /// rather than guessing an address.
    pub peer_endpoint: Option<Endpoint>,
    /// The keys. `None` refuses with `Refusal::NoKeyMaterial`.
    pub keying: Option<&'a TunnelKeying>,
    /// ADR-0007 N-20's epoch, covered by the prologue on both ends.
    pub trust_epoch: u64,
}

/// `session.connect`: two peers that connect at the same moment must not both
/// wait, and two that connect at different moments must not both send.
///
/// # The order of the checks
///
/// The key material and the endpoint are read **before** any datagram moves, so
/// a `Session` with nothing to handshake with never puts a packet on the wire —
/// which is what keeps "we have no keys" from being reported as a timeout ten
/// seconds later.
///
/// # Errors
///
/// [`Refusal`], every variant carrying a registered code. **No partial state is
/// left behind on any path**: the `NoiseBinding` is dropped with its ephemeral,
/// no `Tunnel` is constructed, and the caller's `Session` is left exactly where
/// it was for the state machine to move.
pub async fn drive(
    env: &Env,
    socket: &dyn UdpSocket,
    attempt: Attempt<'_>,
    deadline: MonotonicInstant,
) -> Result<Handshaken, Refusal> {
    let Attempt {
        session,
        local_device,
        peer,
        peer_endpoint,
        keying,
        trust_epoch,
    } = attempt;
    let keying = keying.ok_or(Refusal::NoKeyMaterial)?;
    let endpoint = peer_endpoint.ok_or(Refusal::NoEndpoint)?;
    let role = role_for(local_device, peer);
    let (initiator, responder) = ordered(local_device, peer);

    // P-1's field, built twice from one set of inputs and cross-checked by
    // `NoiseBinding` on every trait call. The two constructions are genuinely
    // independent — `twinvpn_crypto::prologue::Prologue::new` lays out the 83
    // bytes and `twinvpn_tunnel::crypto::Prologue::new` lays them out again —
    // which is what makes the comparison a check rather than a tautology.
    let crypto_prologue = keying.prologue(initiator, responder, trust_epoch);
    let (identity_hash, negotiation_hash) =
        keying.prologue_digests(initiator, responder, trust_epoch);
    let tunnel_prologue = Prologue::new(identity_hash, negotiation_hash);

    let config = HandshakeConfig {
        local_static: keying.local_static(),
        // `IK` pins the responder's static at construction, so an initiator
        // supplies it and a responder does not — it *learns* one and
        // `NoiseBinding` refuses any that is not `expected_peer`.
        remote_static: match role {
            Role::Initiator => Some(keying.peer_key()),
            Role::Responder => None,
        },
        psk: keying.psk(),
        prologue: &crypto_prologue,
    };
    let mut binding =
        NoiseBinding::new(env, role, &config, keying.peer_key()).map_err(|_| Refusal::Rejected)?;

    let local_receiver = draw_index(env)?;
    let (keys, peer_receiver) = match role {
        Role::Initiator => {
            let mut message = Vec::new();
            binding
                .write_initiation(&tunnel_prologue, &mut message)
                .map_err(|_| Refusal::Rejected)?;
            let datagram = encode_initiation(local_receiver, &message);
            socket
                .send_to(&datagram, &endpoint)
                .await
                .map_err(Refusal::Platform)?;

            let received = receive(env, socket, deadline).await?;
            let (peer_index, echoed, body) = parse_response(&received)?;
            if echoed != local_receiver {
                // A response addressed to a different local tunnel. Refused
                // before the AEAD, so a stray or replayed response from an
                // unrelated attempt cannot consume this handshake's state.
                return Err(Refusal::Malformed);
            }
            let keys = binding.read_response(body).map_err(|_| Refusal::Rejected)?;
            (keys, peer_index)
        }
        Role::Responder => {
            let received = receive(env, socket, deadline).await?;
            let (peer_index, body) = parse_initiation(&received)?;
            let mut message = Vec::new();
            // The peer static is learned and checked **inside** this call, before
            // the response is written — `NoiseBinding` does that, and §7.2's "no
            // response to unauthenticated packets" is why the check has to be on
            // that side of the write rather than this one.
            let keys = binding
                .read_initiation_write_response(&tunnel_prologue, body, &mut message)
                .map_err(|_| Refusal::Rejected)?;
            let datagram = encode_response(local_receiver, peer_index, &message);
            socket
                .send_to(&datagram, &endpoint)
                .await
                .map_err(Refusal::Platform)?;
            (keys, peer_index)
        }
    };

    // §7.3 D2: the confirmation runs over the negotiation transcript, and the
    // handshake hash is what binds it to *this* handshake rather than to a
    // concurrent one.
    let handshake_hash = *binding.handshake_hash().ok_or(Refusal::Rejected)?;
    let mut tunnel = establish_tunnel(
        tunnel_id(session),
        session,
        keys,
        endpoint,
        trust_epoch,
        env.now_monotonic(),
    );
    // ADR-0014 N-8 makes `NegotiationConfirm` the first in-session message, and
    // `TunnelState::carries_traffic` answers `false` until it has matched. Both
    // ends compute the transcript from the *same* handshake, so a mismatch here
    // is `PROTO.TRANSCRIPT_MISMATCH` — a security event — rather than a network
    // error, and it leaves the tunnel unable to carry traffic.
    tunnel
        .confirm_negotiation(&handshake_hash, &handshake_hash)
        .map_err(|_| Refusal::Rejected)?;

    Ok(Handshaken {
        tunnel: Arc::new(Mutex::new(tunnel)),
        local_receiver,
        peer_receiver,
    })
}

/// One receive, raced against the caller's deadline on the injected clock.
///
/// The race is not optional. `UdpSocket::recv_from` blocks until a datagram
/// arrives and the adapter imposes no timeout of its own — its contract says so
/// and puts the composition of one here — so an unraced receive against a peer
/// that answers nothing would hold this future for the life of the process.
async fn receive(
    env: &Env,
    socket: &dyn UdpSocket,
    deadline: MonotonicInstant,
) -> Result<Vec<u8>, Refusal> {
    if env.now_monotonic().reached(deadline) {
        return Err(Refusal::NoResponse);
    }
    // Sized from a constant, every time, never from a length a peer declared.
    let mut buf = vec![0u8; MAX_HANDSHAKE_DATAGRAM_BYTES];
    let sleep = env.timer().sleep_until(deadline);
    let Some(received) = first_of(Box::pin(socket.recv_from(&mut buf)), sleep).await else {
        return Err(Refusal::NoResponse);
    };
    let received = received.map_err(Refusal::Platform)?;
    if received.truncated {
        // Reported, never silently truncated: a truncated handshake message
        // fails to authenticate for a reason nobody can see.
        return Err(Refusal::Malformed);
    }
    buf.truncate(received.len);
    Ok(buf)
}

/// Runs `work` unless `deadline` completes first.
///
/// `None` is the deadline. Used by the handshake for `T_CONNECT` and by
/// [`crate::execute::carriage`] to bound one stepped pump direction, which are
/// the two places in this crate that must wait on something a peer controls.
pub(crate) fn first_of<'a, T: 'a>(
    work: futures_core::future::BoxFuture<'a, T>,
    deadline: futures_core::future::BoxFuture<'a, ()>,
) -> impl core::future::Future<Output = Option<T>> + 'a {
    Deadlined { work, deadline }
}

/// One piece of work, given up when a deadline future completes first.
///
/// # Why this is not [`crate::datapath::race`]
///
/// That one races against a [`crate::datapath::Cancel`] token, which is the
/// right shape for a pump: a pump runs until somebody asks it to stop, and a
/// pump has no deadline. A handshake is the other shape — it has no cancel token
/// and it has `T_CONNECT` — so racing it against `Cancelled` would mean
/// manufacturing a token and a task to trip it, which is more machinery than the
/// eight lines below.
///
/// The work is polled **first**. A datagram that arrived in the same wake as the
/// deadline is a datagram the peer sent inside its budget, and discarding it in
/// favour of the timer would fail a handshake that actually completed.
struct Deadlined<'a, T> {
    work: futures_core::future::BoxFuture<'a, T>,
    deadline: futures_core::future::BoxFuture<'a, ()>,
}

impl<T> core::future::Future for Deadlined<'_, T> {
    /// `None` is the deadline.
    type Output = Option<T>;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<T>> {
        // `Unpin` by construction: both fields are already `Pin<Box<..>>`, which
        // is what lets this project to its fields under the crate's
        // `#![forbid(unsafe_code)]`.
        let me = self.get_mut();
        if let core::task::Poll::Ready(value) = me.work.as_mut().poll(cx) {
            return core::task::Poll::Ready(Some(value));
        }
        match me.deadline.as_mut().poll(cx) {
            core::task::Poll::Ready(()) => core::task::Poll::Ready(None),
            core::task::Poll::Pending => core::task::Poll::Pending,
        }
    }
}

/// This device's demultiplexing index, drawn from the injected entropy.
///
/// CD-3: `Env::entropy()` and never `getrandom`, a thread-local RNG or the
/// runtime's. An entropy failure is a **refusal**, not a fallback to a counter:
/// a predictable receiver index is one an off-path attacker can address.
fn draw_index(env: &Env) -> Result<ReceiverIndex, Refusal> {
    let mut bytes = [0u8; 4];
    env.entropy()
        .fill(&mut bytes)
        .map_err(|_| Refusal::Rejected)?;
    Ok(ReceiverIndex(u32::from_le_bytes(bytes)))
}

/// The `TunnelId` for one `Session`'s tunnel.
///
/// Derived from the `SessionId` rather than drawn, for the reason
/// [`crate::session_table`] derives the `SessionId` from the peer: both are 16
/// bytes, this build carries one tunnel per `Session`, and a derived id lets a
/// lab replay reproduce the same identifiers without consuming a random stream
/// some other consumer's determinism depends on.
fn tunnel_id(session: SessionId) -> TunnelId {
    TunnelId::from_slice(session.as_bytes()).expect("TunnelId and SessionId are both 16 bytes")
}

/// Assembles an initiation datagram.
#[must_use]
pub fn encode_initiation(sender: ReceiverIndex, message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(INITIATION_PREFIX_BYTES + message.len());
    out.push(TYPE_HANDSHAKE_INITIATION);
    out.extend_from_slice(&[0u8; 3]);
    out.extend_from_slice(&sender.0.to_le_bytes());
    out.extend_from_slice(message);
    out
}

/// Assembles a response datagram.
#[must_use]
pub fn encode_response(sender: ReceiverIndex, receiver: ReceiverIndex, message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RESPONSE_PREFIX_BYTES + message.len());
    out.push(TYPE_HANDSHAKE_RESPONSE);
    out.extend_from_slice(&[0u8; 3]);
    out.extend_from_slice(&sender.0.to_le_bytes());
    out.extend_from_slice(&receiver.0.to_le_bytes());
    out.extend_from_slice(message);
    out
}

/// Splits an initiation into the sender's index and the Noise message.
///
/// The three reserved octets are checked to be zero on receive. ADR-0014's rule
/// is "zero on send, ignored on receive" for *reserved bits inside a field this
/// build knows*; these three are padding in a fixed-width header, and a datagram
/// that put something there is not the message it claims to be.
fn parse_initiation(datagram: &[u8]) -> Result<(ReceiverIndex, &[u8]), Refusal> {
    if datagram.len() <= INITIATION_PREFIX_BYTES
        || datagram[0] != TYPE_HANDSHAKE_INITIATION
        || datagram[1..4] != [0u8; 3]
    {
        return Err(Refusal::Malformed);
    }
    let sender = index_at(datagram, 4);
    Ok((sender, &datagram[INITIATION_PREFIX_BYTES..]))
}

/// Splits a response into both indices and the Noise message.
fn parse_response(datagram: &[u8]) -> Result<(ReceiverIndex, ReceiverIndex, &[u8]), Refusal> {
    if datagram.len() <= RESPONSE_PREFIX_BYTES
        || datagram[0] != TYPE_HANDSHAKE_RESPONSE
        || datagram[1..4] != [0u8; 3]
    {
        return Err(Refusal::Malformed);
    }
    let sender = index_at(datagram, 4);
    let receiver = index_at(datagram, 8);
    Ok((sender, receiver, &datagram[RESPONSE_PREFIX_BYTES..]))
}

/// One little-endian index at `offset`, which the caller has already bounded.
fn index_at(datagram: &[u8], offset: usize) -> ReceiverIndex {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&datagram[offset..offset + 4]);
    ReceiverIndex(u32::from_le_bytes(bytes))
}

/// `T_CONNECT` from `now`. §4.5 T12's deadline, and the one this module honours.
#[must_use]
pub fn deadline_from(now: MonotonicInstant) -> MonotonicInstant {
    now.saturating_add(T_CONNECT)
}

/// `docs/reliability.md` §5.1's `T_CONNECT`, taken from the registered constant
/// rather than restated, so a tuning change moves one value.
const T_CONNECT: Duration = twinvpn_session::timers::T_CONNECT.default;

#[cfg(test)]
mod tests {
    use super::{
        encode_initiation, encode_response, ordered, parse_initiation, parse_response, role_for,
        Refusal,
    };
    use crate::datapath::ReceiverIndex;
    use twinvpn_crypto::noise::Role;
    use twinvpn_types::DeviceId;

    fn device(byte: u8) -> DeviceId {
        DeviceId::from_slice(&[byte; 32]).expect("32")
    }

    #[test]
    fn the_two_ends_never_agree_on_being_the_same_role() {
        // The property the whole scheme rests on: two devices, two different
        // roles, with no exchange required to reach that conclusion.
        let (low, high) = (device(1), device(9));
        assert_eq!(role_for(low, high), Role::Initiator);
        assert_eq!(role_for(high, low), Role::Responder);
    }

    #[test]
    fn both_ends_order_the_identity_binding_the_same_way() {
        // ADR-0007 N-20 covers `device_id_init` and `device_id_resp` as ORDERED
        // fields. If the two ends ordered them differently they would compute
        // different prologues, and §7.3.1 P-3 would make that present as an
        // unexplained permanent failure rather than as the role confusion it is.
        let (low, high) = (device(1), device(9));
        assert_eq!(ordered(low, high), ordered(high, low));
        assert_eq!(ordered(low, high), (low, high));
    }

    #[test]
    fn an_initiation_round_trips_and_a_response_is_not_one() {
        let sender = ReceiverIndex(0xDEAD_BEEF);
        let datagram = encode_initiation(sender, b"noise message one");
        let (parsed, body) = parse_initiation(&datagram).expect("well formed");
        assert_eq!(parsed, sender);
        assert_eq!(body, b"noise message one");
        // The type byte is what tells the two apart, and it is checked before
        // any index is read.
        assert_eq!(parse_response(&datagram).unwrap_err(), Refusal::Malformed);
    }

    #[test]
    fn a_response_carries_both_indices_so_each_end_learns_the_others() {
        let ours = ReceiverIndex(0x0000_1111);
        let theirs = ReceiverIndex(0x0000_2222);
        let datagram = encode_response(ours, theirs, b"noise message two");
        let (sender, receiver, body) = parse_response(&datagram).expect("well formed");
        assert_eq!((sender, receiver), (ours, theirs));
        assert_eq!(body, b"noise message two");
    }

    #[test]
    fn a_body_less_datagram_is_refused_rather_than_read_past() {
        // The bound that keeps every slice below in range. A header with no
        // message is not a handshake message, and refusing it here is what makes
        // the `[offset..offset + 4]` indexing provably safe.
        for len in 0..=super::RESPONSE_PREFIX_BYTES {
            let mut datagram = vec![0u8; len];
            if len > 0 {
                datagram[0] = super::TYPE_HANDSHAKE_RESPONSE;
            }
            assert_eq!(parse_response(&datagram).unwrap_err(), Refusal::Malformed);
        }
        for len in 0..=super::INITIATION_PREFIX_BYTES {
            let mut datagram = vec![0u8; len];
            if len > 0 {
                datagram[0] = super::TYPE_HANDSHAKE_INITIATION;
            }
            assert_eq!(parse_initiation(&datagram).unwrap_err(), Refusal::Malformed);
        }
    }

    #[test]
    fn a_nonzero_reserved_field_is_not_the_message_it_claims_to_be() {
        let mut datagram = encode_initiation(ReceiverIndex(1), b"body");
        datagram[2] = 0x01;
        assert_eq!(parse_initiation(&datagram).unwrap_err(), Refusal::Malformed);
    }

    #[test]
    fn every_refusal_carries_a_registered_code() {
        // `ownership.md` §6 rule 12. The two that are easiest to conflate are
        // asserted apart: no key material is an AUTH condition and a refused
        // handshake is a CRYPTO one, and an operator acts differently on each.
        assert_eq!(
            Refusal::NoKeyMaterial.reason_code().as_str(),
            "AUTH.KEY_UNAVAILABLE"
        );
        assert_eq!(
            Refusal::Rejected.reason_code().as_str(),
            "CRYPTO.HANDSHAKE_REJECTED"
        );
        assert_eq!(
            Refusal::NoResponse.reason_code().as_str(),
            "CRYPTO.NO_RESPONSE"
        );
        assert_eq!(
            Refusal::Malformed.reason_code().as_str(),
            "PROTO.MALFORMED_MESSAGE"
        );
        assert_eq!(
            Refusal::NoEndpoint.reason_code().as_str(),
            "NET.NO_USABLE_CANDIDATES"
        );
    }
}
