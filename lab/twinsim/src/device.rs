//! One simulated device's relay leg: `Noise_IK`, the cookie ladder, `BIND`, `DATA`.
//!
//! **Authority:** ADR-0005 §11.1(2) (the leg is `Noise_IK` over X25519 /
//! ChaCha20-Poly1305 / BLAKE2s), §11.1(3) (the `pair_tag` rendezvous and its
//! bucket), §11.3 (offline token verification), §11.5 (the stateless cookie
//! challenge above 20 handshakes/s per source /24 or /48), §9.1 (the header).
//!
//! # Nothing here is a cryptographic stand-in
//!
//! | Piece | What runs |
//! |---|---|
//! | the token | a real COSE_Sign1, signed by [`crate::issuer::DevIssuer`] |
//! | the leg | a real `Noise_IK` handshake against the relay's real static key |
//! | `K_leg` | derived here and at the relay independently; nothing is copied |
//! | every frame MAC | real keyed BLAKE2s under the derived `K_leg` |
//! | the transport | a real `tokio::net::UdpSocket`, IPv4 **or** IPv6 |
//!
//! The one thing that is deliberately *not* real is the L-DATA payload. The
//! relay must forward bytes it cannot interpret (I1), so this simulator sends
//! byte patterns chosen to be hostile to a forwarder that peeks — including
//! octets that would decode as protobuf with an unknown field.
//!
//! # The ephemeral is not reproducible, and that is not an oversight
//!
//! `docs/testing-strategy.md` §3.5 makes seeding a lab obligation and CD-4
//! binds the stream — but the `Noise_IK` **ephemeral** is drawn from the OS
//! CSPRNG, never from the scenario seed. A reproducible ephemeral is not
//! forward-secret, so a simulator that seeded it would be exercising a
//! different protocol from the one that ships. What *is* seeded is everything
//! above the handshake: the `RLK`, the subject, the `jti`, the payload
//! schedule.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use twinvpn_crypto::relay_leg::{Entropy, LegInitiator};
use twinvpn_schema::limits::PAIR_TAG_BYTES;

use crate::control::{BindBody, BoundBody, BoundState, Carriage, Family, TokenPresentation};
use crate::issuer::{DevIssuer, TokenSpec};
use crate::wire::{
    self, FrameType, COOKIE_BYTES, FLAG_CARRIES_COOKIE, HEADER_LEN, MAX_DATA_PAYLOAD_BYTES,
};

/// How long a device waits for one reply before calling the relay silent.
///
/// ADR-0005 §11.5 makes a malformed or unauthorised frame a **silent drop**, so
/// "no reply" is a legitimate protocol outcome and must be a timeout rather than
/// a hang. Long enough to survive the impairment profiles TwinLab applies
/// (`impair.rs` tops out well below this), short enough that a scenario fails in
/// seconds rather than being killed by CI.
pub const REPLY_TIMEOUT: Duration = Duration::from_millis(2_000);

/// What a leg attempt ended as.
///
/// `Refused` and `Silent` are separate values on purpose: the first is the relay
/// answering, the second is the relay declining to answer, and collapsing them
/// would make an impairment profile that drops packets indistinguishable from a
/// relay that rejects the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegOutcome {
    /// `HANDSHAKE_RESP` arrived and `K_leg` is derived.
    Established,
    /// A cookie challenge arrived, was answered, and the retry established.
    EstablishedAfterCookie,
    /// The relay answered with something that is not a completion.
    Refused,
    /// Nothing came back inside [`REPLY_TIMEOUT`].
    Silent,
}

impl LegOutcome {
    /// Whether a leg exists. A cookie challenge on the way is not a failure —
    /// above §11.5's threshold it is the *only* path that works.
    #[must_use]
    pub const fn is_established(self) -> bool {
        matches!(self, Self::Established | Self::EstablishedAfterCookie)
    }

    /// A metric label.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Established => "established",
            Self::EstablishedAfterCookie => "established_after_cookie",
            Self::Refused => "refused",
            Self::Silent => "silent",
        }
    }
}

/// What a `BIND` ended as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindOutcome {
    /// A pending slot exists; the partner has `ttl_ms` to arrive.
    Pending {
        /// The relay's own pending-slot lifetime, so the re-`BIND` is scheduled
        /// from the relay's number rather than a compiled-in copy of it.
        ttl_ms: u32,
    },
    /// Both half-flows are present.
    Bound,
    /// The relay answered `RELAY_STATUS` — overload, shedding or drain.
    Status,
    /// Nothing came back.
    Silent,
    /// A reply arrived whose MAC did not verify under this device's `K_leg`.
    ///
    /// A distinct value, never folded into `Silent`: an unauthenticated reply
    /// is an injection attempt or a broken relay, and a simulator that treated
    /// it as loss would report a network fault for a security event.
    Unauthenticated,
}

/// A simulated device.
pub struct SimDevice {
    /// The relay-leg static private key. Distinct from any L-DATA static by
    /// construction — this simulator holds no L-DATA key at all, because the
    /// relay is not a party to that handshake (ADR-0005 §7.3).
    rlk_private: [u8; 32],
    /// Its public half, which the token's `cnf` binds to.
    rlk_public: [u8; 32],
    /// `K_leg`, once the handshake completes.
    k_leg: Option<[u8; 32]>,
    /// The relay-assigned handle, once bound.
    flow_id: Option<u32>,
    /// This device's send counter on the leg.
    counter: u64,
    entropy: Arc<dyn Entropy>,
}

impl SimDevice {
    /// A device whose `RLK` is derived from `seed`.
    ///
    /// # Errors
    ///
    /// A CSPRNG that cannot be opened, or a seed the curve refuses.
    pub fn new(seed: &[u8]) -> anyhow::Result<Self> {
        let rlk_private = twinvpn_crypto::sha256(seed);
        let rlk_public = twinvpn_crypto::relay_leg::static_public_key(&rlk_private)
            .map_err(|e| anyhow::anyhow!("deriving RLK_pub: {e}"))?;
        Ok(Self {
            rlk_private,
            rlk_public,
            k_leg: None,
            flow_id: None,
            counter: 0,
            entropy: Arc::new(Urandom::open()?),
        })
    }

    /// The public half the token's `cnf` must carry.
    #[must_use]
    pub const fn rlk_public(&self) -> &[u8; 32] {
        &self.rlk_public
    }

    /// The relay-assigned handle, once bound.
    #[must_use]
    pub const fn flow_id(&self) -> Option<u32> {
        self.flow_id
    }

    /// Whether a leg exists.
    #[must_use]
    pub const fn has_leg(&self) -> bool {
        self.k_leg.is_some()
    }

    /// Mints this device a token and establishes a leg, answering a cookie
    /// challenge if one comes back.
    ///
    /// Answering **once** and no more: a second challenge would mean the relay
    /// is not honouring its own cookie, and a loop here would hide that behind
    /// eventual success.
    ///
    /// # Errors
    ///
    /// A socket or handshake failure. A *refusal* is an `Ok(LegOutcome)`, not an
    /// error — the relay declining a token is a result the scenario wants.
    pub async fn establish(
        &mut self,
        socket: &UdpSocket,
        relay: SocketAddr,
        relay_static_public: &[u8; 32],
        issuer: &DevIssuer,
        spec: &TokenSpec,
    ) -> anyhow::Result<LegOutcome> {
        let token = issuer.mint(spec);
        let presentation = TokenPresentation {
            issuer_key_id: issuer.key_id().to_owned(),
            cose_sign1: token,
        }
        .encode();

        let Some(reply) = self
            .handshake(socket, relay, relay_static_public, &presentation, None)
            .await?
        else {
            return Ok(LegOutcome::Silent);
        };
        match reply.first().copied().and_then(FrameType::from_wire) {
            Some(FrameType::HandshakeResp) => Ok(LegOutcome::Established),
            Some(FrameType::CookieChallenge) => {
                let cookie = wire::body(&reply).to_vec();
                if cookie.len() != COOKIE_BYTES {
                    return Ok(LegOutcome::Refused);
                }
                let Some(reply) = self
                    .handshake(
                        socket,
                        relay,
                        relay_static_public,
                        &presentation,
                        Some(&cookie),
                    )
                    .await?
                else {
                    return Ok(LegOutcome::Silent);
                };
                if reply.first().copied() == Some(FrameType::HandshakeResp.to_wire()) {
                    Ok(LegOutcome::EstablishedAfterCookie)
                } else {
                    Ok(LegOutcome::Refused)
                }
            }
            _ => Ok(LegOutcome::Refused),
        }
    }

    /// One `HANDSHAKE_INIT` exchange. Returns the raw reply, or `None` on
    /// timeout, so a caller can tell a challenge from a completion.
    async fn handshake(
        &mut self,
        socket: &UdpSocket,
        relay: SocketAddr,
        relay_static_public: &[u8; 32],
        presentation: &[u8],
        cookie: Option<&[u8]>,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let mut initiator =
            LegInitiator::new(&self.entropy, &self.rlk_private, relay_static_public)
                .map_err(|e| anyhow::anyhow!("relay leg initiator: {e}"))?;
        let msg1 = initiator
            .initiate(presentation)
            .map_err(|e| anyhow::anyhow!("relay leg message 1: {e}"))?;

        let mut flags = 0_u8;
        let mut body = Vec::new();
        if let Some(c) = cookie {
            flags |= FLAG_CARRIES_COOKIE;
            body.extend_from_slice(c);
        }
        body.extend_from_slice(&msg1);

        // The handshake frame carries no MAC: `K_leg` does not exist yet, which
        // is exactly why §11.5's cookie gate is in front of it.
        let datagram = wire::encode_frame(FrameType::HandshakeInit, flags, 0, 0, [0_u8; 8], &body);
        socket.send_to(&datagram, relay).await?;

        let Some(reply) = recv(socket).await? else {
            return Ok(None);
        };
        if reply.first().copied() == Some(FrameType::HandshakeResp.to_wire()) {
            let completed = initiator
                .complete(wire::body(&reply))
                .map_err(|e| anyhow::anyhow!("relay leg message 2: {e}"))?;
            self.k_leg = Some(*completed.k_leg());
        }
        Ok(Some(reply))
    }

    /// Sends a `BIND` for `pair_tag` and interprets the reply.
    ///
    /// # Errors
    ///
    /// A socket failure, or a `BIND` attempted with no leg — which is a caller
    /// bug rather than a protocol outcome, because a device with no `K_leg`
    /// cannot MAC the frame and must not send it at all.
    pub async fn bind(
        &mut self,
        socket: &UdpSocket,
        relay: SocketAddr,
        pair_tag: [u8; PAIR_TAG_BYTES],
        bucket: u64,
    ) -> anyhow::Result<BindOutcome> {
        let local = socket.local_addr()?;
        let body = BindBody {
            pair_tag,
            bucket,
            carriage: Carriage::Udp,
            family: Family::of(local),
        }
        .encode();

        let Some(reply) = self
            .send_control(socket, relay, FrameType::Bind, 0, &body)
            .await?
        else {
            return Ok(BindOutcome::Silent);
        };
        let Some(header) = wire::parse_header(&reply) else {
            return Ok(BindOutcome::Silent);
        };
        if !self.verify(&reply, header.counter_low.into()) {
            return Ok(BindOutcome::Unauthenticated);
        }
        match header.kind {
            Some(FrameType::Bound) => {
                self.flow_id = Some(header.flow_id);
                match BoundBody::decode(wire::body(&reply)) {
                    Some(BoundBody {
                        state: BoundState::Bound,
                        ..
                    }) => Ok(BindOutcome::Bound),
                    Some(BoundBody { pending_ttl_ms, .. }) => Ok(BindOutcome::Pending {
                        ttl_ms: pending_ttl_ms,
                    }),
                    None => Ok(BindOutcome::Silent),
                }
            }
            Some(FrameType::RelayStatus) => Ok(BindOutcome::Status),
            _ => Ok(BindOutcome::Silent),
        }
    }

    /// Sends one `DATA` frame. No reply is awaited — it goes to the *peer*.
    ///
    /// # Errors
    ///
    /// A socket failure, no leg, no flow, or a payload above the B4 ceiling.
    /// The ceiling is enforced here rather than left to the relay: a device that
    /// oversends gets a silent drop, and a simulator that could not tell that
    /// from loss would mis-attribute every over-MTU test.
    pub async fn send_data(
        &mut self,
        socket: &UdpSocket,
        relay: SocketAddr,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            payload.len() <= MAX_DATA_PAYLOAD_BYTES,
            "a DATA payload is at most {MAX_DATA_PAYLOAD_BYTES} bytes (ADR-0005 §9.1); \
             {} would be dropped by the relay, not rejected",
            payload.len()
        );
        let flow = self.flow_id.ok_or_else(|| anyhow::anyhow!("not bound"))?;
        let datagram = self.encode(FrameType::Data, flow, payload)?;
        socket.send_to(&datagram, relay).await?;
        Ok(())
    }

    /// Waits for one datagram and returns it with its header, verifying the MAC.
    ///
    /// # Errors
    ///
    /// A socket failure.
    pub async fn recv_verified(
        &self,
        socket: &UdpSocket,
    ) -> anyhow::Result<Option<(FrameType, Vec<u8>)>> {
        let Some(datagram) = recv(socket).await? else {
            return Ok(None);
        };
        let Some(header) = wire::parse_header(&datagram) else {
            return Ok(None);
        };
        if !self.verify(&datagram, header.counter_low.into()) {
            return Ok(None);
        }
        Ok(header.kind.map(|k| (k, wire::body(&datagram).to_vec())))
    }

    /// Sends one MACed control frame and waits briefly for a reply.
    async fn send_control(
        &mut self,
        socket: &UdpSocket,
        relay: SocketAddr,
        kind: FrameType,
        flow_id: u32,
        body: &[u8],
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let datagram = self.encode(kind, flow_id, body)?;
        socket.send_to(&datagram, relay).await?;
        recv(socket).await
    }

    /// Assembles and MACs one frame under this device's `K_leg`.
    fn encode(&mut self, kind: FrameType, flow_id: u32, body: &[u8]) -> anyhow::Result<Vec<u8>> {
        let k = self
            .k_leg
            .ok_or_else(|| anyhow::anyhow!("no leg: a device with no K_leg must not send"))?;
        self.counter += 1;
        let counter = self.counter;
        let mac_input = wire::mac_input(kind, 0, flow_id, counter, body);
        let tag = twinvpn_crypto::frame_mac(&k, &mac_input);
        Ok(wire::encode_frame(
            kind,
            0,
            flow_id,
            u16::try_from(counter & 0xFFFF).expect("masked"),
            tag,
            body,
        ))
    }

    /// Whether an inbound frame's MAC verifies under this device's `K_leg`.
    ///
    /// The device checks the relay's frames too. An unauthenticated `DRAIN` or
    /// `RELAY_STATUS` would be an injection primitive for anyone who can spoof a
    /// source address, and a simulator that skipped this would not notice a
    /// relay that stopped signing.
    #[must_use]
    pub fn verify(&self, datagram: &[u8], counter_full: u64) -> bool {
        let Some(k) = self.k_leg else { return false };
        let Some(header) = wire::parse_header(datagram) else {
            return false;
        };
        let Some(kind) = header.kind else {
            return false;
        };
        let mac_input = wire::mac_input(
            kind,
            header.flags,
            header.flow_id,
            counter_full,
            &datagram[HEADER_LEN..],
        );
        twinvpn_crypto::verify_frame_mac(&k, &mac_input, &header.tag)
    }
}

/// One datagram, or `None` if the relay stayed silent for [`REPLY_TIMEOUT`].
async fn recv(socket: &UdpSocket) -> anyhow::Result<Option<Vec<u8>>> {
    let mut buf = vec![0_u8; HEADER_LEN + MAX_DATA_PAYLOAD_BYTES + 256];
    match tokio::time::timeout(REPLY_TIMEOUT, socket.recv(&mut buf)).await {
        Err(_) => Ok(None),
        Ok(Ok(n)) => {
            buf.truncate(n);
            Ok(Some(buf))
        }
        Ok(Err(e)) => Err(e.into()),
    }
}

/// The OS CSPRNG, read directly.
///
/// `Entropy::fill` **never falls back to a weaker source**, and neither does
/// this: a short read is an error, not a partial fill, because a partially
/// filled ephemeral is a key with known bytes in it.
struct Urandom(std::fs::File);

impl Urandom {
    fn open() -> anyhow::Result<Self> {
        Ok(Self(std::fs::File::open("/dev/urandom")?))
    }
}

impl Entropy for Urandom {
    fn fill(&self, dst: &mut [u8]) -> Result<(), twinvpn_crypto::relay_leg::EntropyError> {
        use std::io::Read;
        let mut f = &self.0;
        f.read_exact(dst)
            .map_err(|_| twinvpn_crypto::relay_leg::EntropyError::EntropyUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_derives_a_public_half_and_two_seeds_differ() {
        let a = SimDevice::new(b"device-a").expect("device");
        let b = SimDevice::new(b"device-b").expect("device");
        assert_ne!(a.rlk_public(), b.rlk_public());
        // Deterministic in the seed: a scenario replays with the same RLK.
        let a2 = SimDevice::new(b"device-a").expect("device");
        assert_eq!(a.rlk_public(), a2.rlk_public());
    }

    #[test]
    fn a_device_with_no_leg_refuses_to_send_rather_than_sending_an_unmaced_frame() {
        let mut d = SimDevice::new(b"no-leg").expect("device");
        let err = d.encode(FrameType::Bind, 0, b"body").expect_err("refused");
        assert!(err.to_string().contains("no leg"));
    }

    #[test]
    fn a_device_with_no_leg_verifies_nothing() {
        let d = SimDevice::new(b"no-leg").expect("device");
        // Not "returns true because there is nothing to check against".
        assert!(!d.verify(&[0_u8; HEADER_LEN], 0));
    }

    #[test]
    fn a_cookie_challenge_is_not_counted_as_a_failure() {
        assert!(LegOutcome::EstablishedAfterCookie.is_established());
        assert!(LegOutcome::Established.is_established());
        assert!(!LegOutcome::Refused.is_established());
        assert!(!LegOutcome::Silent.is_established());
    }

    #[test]
    fn the_entropy_source_fills_and_does_not_repeat() {
        let e = Urandom::open().expect("/dev/urandom");
        let (mut a, mut b) = ([0_u8; 32], [0_u8; 32]);
        e.fill(&mut a).expect("fill");
        e.fill(&mut b).expect("fill");
        assert_ne!(a, b);
        assert_ne!(a, [0_u8; 32]);
    }
}
