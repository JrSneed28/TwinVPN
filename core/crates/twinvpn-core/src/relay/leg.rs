//! One relay leg: the handshake that creates it, and the frames it carries.
//!
//! **Authority:** ADR-0005 §9.1 (the frame and its MAC), §11.1(2) (the
//! `Noise_IK` leg handshake), §11.1(3)/(4) (`BIND`/`BOUND` keyed by
//! `pair_tag`), §11.1(5) (a relay forwards byte for byte and never fragments),
//! §11.3 (the token is verified once, at leg setup), §11.5 (the cookie gate,
//! and zero bytes in reply to anything unauthenticated), §8 (`DRAIN`);
//! ADR-0006 §11.15(c) (leg liveness is a **separate** observation from the
//! end-to-end heartbeat); ADR-0010 R1; ADR-0018 CD-1, CD-2, CD-3.
//!
//! # The token rides inside the handshake, and that is the whole of admission
//!
//! ADR-0005 §11.3's order is: cookie gate, then the one asymmetric operation,
//! then the token, then `cnf` against the static the device just proved
//! possession of. [`PendingLeg`] is the device's half of exactly that sequence.
//! The `RelayCapabilityToken` travels in the `Noise_IK` message-1 payload — so
//! leg setup is one round trip, and a bearer credential is never on the wire in
//! the clear even before a leg exists.
//!
//! After that, `BIND` needs no second token check: its frame MAC verifies under
//! `K_leg`, and `K_leg` exists **only** because that token verified. Re-proving
//! it per `BIND` would put an asymmetric operation on the path a *listening*
//! device uses at ADR-0006 §11.5's cadence.
//!
//! # A cookie challenge restarts the handshake, it does not resume it
//!
//! `snow` will not write message 1 twice from one state, and it should not: the
//! WireGuard MAC2 / QUIC Retry pattern is a fresh initiation carrying proof of
//! a round trip, not a continuation. So [`LegStep::Challenged`] hands back a
//! **new** [`PendingLeg`] rather than mutating the old one, and the old state
//! is dropped with its ephemeral.
//!
//! # Two counter windows, because the relay uses two counter disciplines
//!
//! `services/relay/src/forward.rs` increments a per-half-flow `tx_counter` for
//! every forwarded `DATA` frame, and `services/relay/src/admit.rs`'s `signed()`
//! sends **every control frame at counter zero**. Running both through one
//! RFC 9147 window would accept the first control frame and reject every one
//! after it as a replay, which is a dead leg that looks like a network fault.
//!
//! So `DATA` is admitted to the leg's real window — that is where replay
//! protection of the carried ciphertext actually lives — and a control frame is
//! authenticated by its MAC over `counter_full = 0` and not admitted to it. The
//! cost is stated plainly: a control frame is replayable by anyone who can
//! capture and resend one, and **no client-side check can close that** while
//! the counter is a constant, because a replay is byte-identical to the
//! original and the MAC covers the same zero. Recorded as an integration item
//! for `relay-plane`; the fix is a per-leg egress counter on the relay's
//! control path, not a heuristic here.

use core::time::Duration;
use std::sync::Arc;

use twinvpn_crypto::relay_leg::{LegInitiator, STATIC_KEY_LEN};
use twinvpn_env::Env;
use twinvpn_relay_client::frame::{
    CounterWindow, FrameError, FrameType, InboundFrame, LegKey, LegSendCounter, OutboundFrame,
    LEG_KEY_LEN,
};
use twinvpn_relay_client::map::Carriage;
use twinvpn_types::{AddressFamily, Endpoint, PairTag, RelayId};

use super::codec::{BindBody, BoundBody, BoundState, CapsBody, DrainBody, StatusBody};
use super::drain::DrainNotice;
use super::legsetup::{
    encode_leg_setup, parse_leg_setup, LegSetupType, TokenPresentation, COOKIE_BYTES,
    FLAG_CARRIES_COOKIE,
};
use super::outcome::{BindOutcome, Inbound, Refusal, RelayReject};
use super::sealed::Sealed;

/// Everything one leg needs that this module cannot derive for itself.
///
/// Taken as parameters rather than reached for, so the unit is testable against
/// the mock adapter with no live session — and so wiring it into a `Session`
/// stays one integration-owned edit.
pub struct LegParams<'a> {
    /// Which relay, from the verified map.
    pub relay: RelayId,
    /// Where it is. The family this leg runs on is **this endpoint's**, not a
    /// separate choice: ADR-0010 R1 forbids a v4 story and a v6 story, and one
    /// derived field is how that stays true.
    pub endpoint: Endpoint,
    /// Which carriage the leg uses.
    pub carriage: Carriage,
    /// The relay's static Noise public key, **from a verified map**.
    ///
    /// ADR-0006 §11.2: a device MUST NOT bind a relay whose `relay_id` and
    /// static key are absent from a verified map. This module cannot check
    /// that, so the field is named for the obligation, exactly as
    /// `LegInitiator::new`'s parameter is.
    pub relay_static_public_from_verified_map: &'a [u8; STATIC_KEY_LEN],
    /// The device's relay-leg static private key (`RLK`), whose public half the
    /// token's `cnf` claim names.
    pub rlk_private: &'a [u8],
    /// The `RelayCapabilityToken`, presented exactly as it was issued.
    pub token: &'a TokenPresentation,
}

/// A leg that has sent `HANDSHAKE_INIT` and is waiting for an answer.
pub struct PendingLeg<'a> {
    params: LegParams<'a>,
    entropy: Arc<dyn twinvpn_crypto::relay_leg::Entropy>,
    initiator: LegInitiator,
}

/// What arrived while a leg was pending.
pub enum LegStep<'a> {
    /// The relay demanded a round trip first (ADR-0005 §11.5's cookie gate).
    ///
    /// The datagram is a **fresh** `HANDSHAKE_INIT` carrying the cookie; the
    /// pending leg it comes with is a new one, because a Noise initiator cannot
    /// write message 1 twice.
    Challenged {
        /// The re-initiated leg.
        ///
        /// Boxed because a `snow` handshake state is by far the largest thing
        /// either variant carries, and an unboxed one would make every
        /// `LegStep` — including the far commoner `Established` — pay for it.
        pending: Box<PendingLeg<'a>>,
        /// The datagram to send.
        datagram: Vec<u8>,
    },
    /// The leg is up and `K_leg` is derived.
    Established(RelayLeg),
}

impl<'a> PendingLeg<'a> {
    /// Begins a leg, returning the `HANDSHAKE_INIT` datagram to send.
    ///
    /// **CD-2/CD-3.** The randomness is `env.entropy()` — the injected
    /// capability — and never `snow`'s `DefaultResolver`, which reaches for the
    /// platform CSPRNG itself.
    ///
    /// # Errors
    ///
    /// [`RelayReject::HandshakeRefused`] for any refusal from the handshake,
    /// with no detail: a prober must not learn which check refused it.
    pub fn begin(env: &Env, params: LegParams<'a>) -> Result<(Self, Vec<u8>), RelayReject> {
        let entropy: Arc<dyn twinvpn_crypto::relay_leg::Entropy> = Arc::clone(env.entropy());
        Self::initiate(entropy, params, None)
    }

    fn initiate(
        entropy: Arc<dyn twinvpn_crypto::relay_leg::Entropy>,
        params: LegParams<'a>,
        cookie: Option<&[u8]>,
    ) -> Result<(Self, Vec<u8>), RelayReject> {
        let mut initiator = LegInitiator::new(
            &entropy,
            params.rlk_private,
            params.relay_static_public_from_verified_map,
        )
        .map_err(|_| RelayReject::HandshakeRefused)?;
        let message_1 = initiator
            .initiate(&params.token.encode())
            .map_err(|_| RelayReject::HandshakeRefused)?;

        let (flags, body) = match cookie {
            Some(c) => {
                let mut body = Vec::with_capacity(c.len() + message_1.len());
                body.extend_from_slice(c);
                body.extend_from_slice(&message_1);
                (FLAG_CARRIES_COOKIE, body)
            }
            None => (0, message_1),
        };
        let datagram = encode_leg_setup(LegSetupType::HandshakeInit, flags, &body);
        Ok((
            Self {
                params,
                entropy,
                initiator,
            },
            datagram,
        ))
    }

    /// Feeds one datagram to a pending leg.
    ///
    /// # Errors
    ///
    /// [`RelayReject::Malformed`] for anything that is not a leg-setup frame —
    /// a `DATA` or control frame cannot arrive before `K_leg` exists, so one
    /// that does is not a frame this leg can act on;
    /// [`RelayReject::WrongDirection`] for a `HANDSHAKE_INIT` from a relay; and
    /// [`RelayReject::HandshakeRefused`] for a message 2 that does not complete.
    pub fn on_datagram(self, datagram: &[u8]) -> Result<LegStep<'a>, RelayReject> {
        let frame = parse_leg_setup(datagram)?;
        match frame.kind {
            LegSetupType::CookieChallenge => {
                if frame.body.len() != COOKIE_BYTES {
                    return Err(RelayReject::Malformed);
                }
                let Self {
                    params, entropy, ..
                } = self;
                let (pending, datagram) = Self::initiate(entropy, params, Some(&frame.body))?;
                Ok(LegStep::Challenged {
                    pending: Box::new(pending),
                    datagram,
                })
            }
            LegSetupType::HandshakeResp => {
                let completed = self
                    .initiator
                    .complete(&frame.body)
                    .map_err(|_| RelayReject::HandshakeRefused)?;
                let mut key_bytes = [0_u8; LEG_KEY_LEN];
                key_bytes.copy_from_slice(completed.k_leg());
                Ok(LegStep::Established(RelayLeg::new(
                    &self.params,
                    LegKey::from_array(key_bytes),
                )))
            }
            // `parse_leg_setup` already refuses this, and matching it again
            // rather than reaching for a wildcard is what keeps the refusal
            // true if a fourth leg-setup type is ever allocated.
            LegSetupType::HandshakeInit => Err(RelayReject::WrongDirection),
        }
    }
}

impl core::fmt::Debug for PendingLeg<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingLeg")
            .field("relay", &self.params.relay)
            .finish_non_exhaustive()
    }
}

/// An established leg: `K_leg` derived, frames MACable in both directions.
pub struct RelayLeg {
    relay: RelayId,
    endpoint: Endpoint,
    carriage: Carriage,
    family: AddressFamily,
    key: LegKey,
    send_counter: LegSendCounter,
    data_window: CounterWindow,
    flow_id: u32,
    state: Option<BoundState>,
}

impl RelayLeg {
    fn new(params: &LegParams<'_>, key: LegKey) -> Self {
        Self {
            relay: params.relay,
            endpoint: params.endpoint,
            carriage: params.carriage,
            // Derived from the endpoint, never chosen separately (ADR-0010 R1).
            family: params.endpoint.address.family(),
            key,
            send_counter: LegSendCounter::new(),
            data_window: CounterWindow::new(),
            // Zero until the relay assigns one in `BOUND`. A device does not
            // name a flow; it is told one.
            flow_id: 0,
            state: None,
        }
    }

    /// Which relay this leg is to.
    #[must_use]
    pub const fn relay(&self) -> RelayId {
        self.relay
    }

    /// Where.
    #[must_use]
    pub const fn endpoint(&self) -> Endpoint {
        self.endpoint
    }

    /// Which family this half-flow runs on.
    #[must_use]
    pub const fn family(&self) -> AddressFamily {
        self.family
    }

    /// Which carriage.
    #[must_use]
    pub const fn carriage(&self) -> Carriage {
        self.carriage
    }

    /// The relay-assigned handle, once `BOUND` has named one.
    #[must_use]
    pub const fn flow_id(&self) -> u32 {
        self.flow_id
    }

    /// Whether both half-flows are present.
    ///
    /// `Some(Pending)` and `None` are different facts — "the relay holds a slot
    /// and the partner has not arrived" versus "nothing has been asked yet" —
    /// so this answers the narrow question and the state is available whole.
    #[must_use]
    pub fn is_bound(&self) -> bool {
        self.state == Some(BoundState::Bound)
    }

    /// Whether a `BIND` has been answered at all.
    #[must_use]
    pub const fn bind_state(&self) -> Option<BoundState> {
        self.state
    }

    /// The `BIND` datagram for `pair_tag` in `bucket`.
    ///
    /// The tag is the **only** thing that identifies the pair, and there is no
    /// peer identifier of any kind in the body — see
    /// [`super::codec::BindBody`].
    #[must_use]
    pub fn bind_datagram(&mut self, pair_tag: PairTag, bucket: u64) -> Vec<u8> {
        let body = BindBody {
            pair_tag: pair_tag.to_array(),
            bucket,
            carriage: self.carriage,
            family: self.family,
        }
        .encode();
        self.signed(FrameType::Bind, &body)
            .unwrap_or_else(|_| unreachable!("a fixed-width BIND body is inside every bound"))
    }

    /// The `DATA` datagram carrying one sealed payload.
    ///
    /// §11.1(5): a relay forwards byte for byte and never fragments, so neither
    /// does this — an oversized payload is refused, never split.
    ///
    /// # Errors
    ///
    /// [`RelayReject::PayloadTooLarge`] past ADR-0005 §9.2's ceiling.
    pub fn data_datagram(&mut self, sealed: &Sealed) -> Result<Vec<u8>, RelayReject> {
        self.signed(FrameType::Data, sealed.as_wire())
    }

    /// A leg `PING`.
    ///
    /// ADR-0006 §11.15(c): observable **independently** of any half-flow. The
    /// whole of §11.4's failure attribution — "is the relay reachable" versus
    /// "is the peer talking" — rests on this being a different observation from
    /// the end-to-end `Path` heartbeat.
    #[must_use]
    pub fn ping_datagram(&mut self) -> Vec<u8> {
        self.signed(FrameType::Ping, &[])
            .unwrap_or_else(|_| unreachable!("an empty PING body is inside every bound"))
    }

    /// This build's `CAPS` offer (ADR-0005 §10).
    #[must_use]
    pub fn caps_datagram(&mut self) -> Vec<u8> {
        self.signed(FrameType::Caps, &CapsBody::of_this_build().encode())
            .unwrap_or_else(|_| unreachable!("a fixed-width CAPS body is inside every bound"))
    }

    /// Assembles, bounds and MACs one outgoing frame.
    ///
    /// The bound is applied by `OutboundFrame::new` **before** the body is
    /// retained, and the direction check by `FrameType::device_may_send` — so a
    /// frame only a relay sends cannot leave this device even by mistake.
    fn signed(&mut self, kind: FrameType, body: &[u8]) -> Result<Vec<u8>, RelayReject> {
        // `twinvpn_relay_client::frame`'s public API is expressed in
        // `bytes::Bytes`, and `twinvpn-core`'s manifest carries no `bytes`
        // dependency — a manifest this domain does not extend on its own
        // (`ownership.md` §1). The conversion is therefore an inferred `.into()`
        // through `impl From<Vec<u8>> for Bytes`, which needs no `use`.
        // Recorded as an integration item: the right fix is a `bytes`
        // re-export from `twinvpn-relay-client`, or one line in this crate's
        // manifest, and both are somebody else's edit.
        let frame =
            OutboundFrame::new(kind, 0, self.flow_id, body.to_vec().into()).map_err(reject_of)?;
        let counter = self.send_counter.take_next();
        Ok(frame.encode(&self.key, counter).to_vec())
    }

    /// Feeds one received datagram to the leg.
    ///
    /// The order is the one `InboundFrame::verify` fixes and this module must
    /// not reorder: reconstruct the counter, verify the MAC over the **full**
    /// value, check direction, and only then admit the counter. Admitting first
    /// would let a forged or wrong-direction frame advance the window and lock
    /// out the genuine relay.
    ///
    /// # Errors
    ///
    /// [`RelayReject`] for every refusal, and **every one is a silent drop** on
    /// the wire: ADR-0005 §11.5 gives a relay zero bytes in reply to anything
    /// unauthenticated, and a device that replied would make itself an
    /// amplifier.
    pub fn on_datagram(&mut self, datagram: &[u8]) -> Result<Inbound, RelayReject> {
        let owned = datagram.to_vec().into();
        let parsed = InboundFrame::parse(&owned).map_err(reject_of)?;

        // See the module note: `DATA` is admitted to the leg's window, a
        // control frame is authenticated and not admitted, because the relay
        // sends every control frame at counter zero.
        let verified = if parsed.kind() == FrameType::Data {
            parsed.verify(&self.key, &mut self.data_window)
        } else {
            let mut control = CounterWindow::new();
            parsed.verify(&self.key, &mut control)
        }
        .map_err(reject_of)?;

        match verified.kind() {
            FrameType::Data => Ok(Inbound::Data(Sealed::from_tunnel(
                verified.payload().as_bytes().to_vec(),
            )?)),
            FrameType::Bound => {
                let body = BoundBody::decode(verified.payload().as_bytes())?;
                // The relay names the flow; the device records it.
                self.flow_id = verified.flow_id();
                self.state = Some(body.state);
                Ok(Inbound::Bound(match body.state {
                    BoundState::Pending => BindOutcome::Pending {
                        flow_id: verified.flow_id(),
                        pending_ttl: Duration::from_millis(u64::from(body.pending_ttl_ms)),
                    },
                    BoundState::Bound => BindOutcome::Bound {
                        flow_id: verified.flow_id(),
                    },
                }))
            }
            FrameType::RelayStatus => {
                let body = StatusBody::decode(verified.payload().as_bytes())?;
                let refusal = Refusal::from_wire(
                    &body.reason_code,
                    Duration::from_millis(u64::from(body.retry_after_ms)),
                    Duration::ZERO,
                )?;
                Ok(Inbound::Status(refusal))
            }
            FrameType::Drain => {
                let body = DrainBody::decode(verified.payload().as_bytes())?;
                Ok(Inbound::Drain(DrainNotice {
                    relay: self.relay,
                    deadline: Duration::from_millis(body.drain_deadline_ms),
                    suggested: body.suggested_relay_ids,
                }))
            }
            FrameType::Ping => Ok(Inbound::Ping),
            FrameType::Pong => Ok(Inbound::Pong),
            FrameType::Caps => Ok(Inbound::Caps(CapsBody::decode(
                verified.payload().as_bytes(),
            )?)),
            // `BIND` and `REBIND` are refused inside `verify` by
            // `device_may_receive`, so this arm is unreachable — and it is
            // written as a refusal rather than a panic because "unreachable"
            // is a claim about another crate's code, not this one's.
            FrameType::Bind | FrameType::Rebind => Err(RelayReject::WrongDirection),
        }
    }
}

impl core::fmt::Debug for RelayLeg {
    /// Never the key, never a counter's contents, never a payload.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RelayLeg")
            .field("relay", &self.relay)
            .field("family", &self.family)
            .field("carriage", &self.carriage)
            .field("flow_id", &self.flow_id)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Maps the device frame codec's refusal onto this module's.
///
/// One mapping, so a condition cannot surface as two different codes depending
/// on which layer noticed it.
fn reject_of(e: FrameError) -> RelayReject {
    match e {
        FrameError::UnsupportedVersion => RelayReject::VersionUnsupported,
        FrameError::PayloadTooLarge { observed, limit } => {
            RelayReject::PayloadTooLarge { observed, limit }
        }
        FrameError::AuthenticationFailed | FrameError::ReplayedCounter => {
            RelayReject::AuthenticationFailed
        }
        FrameError::WrongDirection => RelayReject::WrongDirection,
        // `FrameError` is `#[non_exhaustive]`, and `TooShort` / `UnknownType`
        // are both "this is not a frame this build can read".
        _ => RelayReject::Malformed,
    }
}
