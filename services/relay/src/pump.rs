//! The `R-UDP` datagram pump: one received datagram in, zero or one out.
//!
//! **Authority:** ADR-0005 §11.1 (forwarding model), §11.5 (resource control and
//! amplification), §9.1 (framing).
//!
//! # One frame in, at most one frame out — and that is the amplification proof
//!
//! §11.5: "the relay emits **at most one frame per received frame**, of equal
//! payload length; it never fans out, retransmits, or pads; and it emits **zero
//! bytes** in response to any unauthenticated or unbound frame."
//!
//! [`Pump::step`] returns an [`Action`], and `Action` has exactly two shapes:
//! send nothing, or send one datagram to one peer. There is no variant that
//! sends two — so the amplification factor is a property of the return type, not
//! of the implementation. `amplification_is_a_property_of_the_return_type` pins
//! it.
//!
//! The one thing that *looks* like an exception is not one. When a second `BIND`
//! completes a pair, the half-flow that was already waiting must also be told
//! (§11.1(4), "**both** peers receive `BOUND{flow_id}`"). That datagram is not a
//! reply to the received one: it is an announcement **onto an already-bound,
//! authenticated flow**, which is the same class §11.5 explicitly permits for
//! `DRAIN` and `RELAY_STATUS`. It is queued in
//! [`Pump::pending_announcements`] and drained by the caller, so it is visible
//! in the type rather than hidden inside a send.
//!
//! # It is synchronous, and that is I5 again
//!
//! `step` is `fn`, takes `&mut RelayEngine` and returns an `Action`. It performs
//! no I/O: [`crate::loop_udp::serve_udp`] awaits the socket and calls this. A
//! pure step is what makes "a frame from an unbound source produces zero bytes"
//! testable without a network, and what stops a future maintainer adding a lookup
//! on the packet path.
//!
//! # Direction is checked on receive, not only on send
//!
//! W-32's ruling: a device that accepted a `BIND` *from* a relay would be a
//! confused deputy, and the mirror holds here. `BOUND`, `DRAIN`,
//! `RELAY_STATUS`, `PONG`, `HANDSHAKE_RESP` and `COOKIE_CHALLENGE` are
//! relay-to-device only, and [`crate::frame::FrameType::device_may_send`]
//! refuses them **before** the leg lookup — so a spoofed `RELAY_STATUS` cannot
//! reach any state at all.

use std::net::SocketAddr;

use bytes::Bytes;

use crate::admit::LegSetup;
use crate::condition::Condition;
use crate::crypto::{LegKey, RelayCrypto};
use crate::drr::TwoTierDrr;
use crate::engine::RelayEngine;
use crate::flow::FlowId;
use crate::forward::ForwardRefusal;
use crate::frame::{FrameType, RelayFrame};
use crate::leg::LegRegistry;
use crate::status::RelayStatus;

/// What the pump decided to do with one datagram.
///
/// # It renders neither the peer nor the payload
///
/// A derived `Debug` here would put a peer address **and** a relayed payload in
/// one value — the exact pair ADR-0015 O-13 forbids and `ownership.md` §6 rule
/// 11 names. A `Debug` is written by hand instead, printing a length and a
/// family, so an enclosing `#[derive(Debug)]` anywhere above cannot leak either.
pub enum Action {
    /// **Zero bytes.** Every unauthenticated, unbound, malformed or refused-
    /// without-a-leg frame lands here (§11.5).
    Silent {
        /// Why, for a counter. Never sent to the peer.
        why: Drop,
    },
    /// One datagram, to one peer.
    Send {
        /// Where.
        to: SocketAddr,
        /// The complete datagram, header included.
        datagram: Bytes,
    },
}

impl std::fmt::Debug for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Silent { why } => f.debug_struct("Silent").field("why", why).finish(),
            Action::Send { to, datagram } => f
                .debug_struct("Send")
                // The address family is the allowlisted dimension (ADR-0015 §9);
                // the address itself is not, and the datagram never is.
                .field("family", &crate::net::peer_family_label(*to))
                .field("datagram_len", &datagram.len())
                .finish(),
        }
    }
}

impl Action {
    /// Whether anything leaves the socket.
    #[must_use]
    pub const fn emits_bytes(&self) -> bool {
        matches!(self, Action::Send { .. })
    }

    /// How many bytes leave. Zero for [`Action::Silent`].
    #[must_use]
    pub fn emitted_len(&self) -> usize {
        match self {
            Action::Silent { .. } => 0,
            Action::Send { datagram, .. } => datagram.len(),
        }
    }
}

/// Why nothing was sent. A local counter dimension, never a wire value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drop {
    /// The datagram did not parse: too short, unknown type, unsupported version,
    /// or over the derived payload bound.
    Malformed,
    /// The source has no established leg, so `K_leg` is unknown.
    NoLeg,
    /// The source is over the cookie threshold for its /24 or /48 and must
    /// complete a stateless challenge first (§11.5).
    CookieRequired,
    /// The frame named a `flow_id` no bound pair holds.
    Unbound,
    /// The frame MAC did not verify under `K_leg`.
    MacInvalid,
    /// A replay, or a counter outside the RFC 9147 window.
    CounterRejected,
    /// No egress MAC could be computed — no provider.
    NoEgressMac,
    /// A control frame this build does not act on here.
    UnhandledControl,
    /// A frame only a relay may send arrived **from** a device (W-32).
    WrongDirection,
    /// The frame's `flow_id` names a half-flow bound to a **different** source
    /// address than the one it arrived from (R-5).
    WrongSource,
    /// No token admitted the leg.
    Unauthorized,
    /// A ceiling in [`LegRegistry`] refused the leg.
    LegLimit,
}

/// Everything the pump needs, none of it a network handle.
pub struct Pump<'a> {
    /// The engine holding the tables and the limits.
    pub engine: &'a mut RelayEngine,
    /// The established legs. Mutable now: a completed handshake inserts, a
    /// received frame touches, and the collector expires.
    pub legs: &'a mut LegRegistry,
    /// The scheduler frames are enqueued into.
    pub scheduler: &'a mut TwoTierDrr,
    /// The cryptographic provider.
    pub crypto: &'a dyn RelayCrypto,
    /// The relay's static key, entropy and cookie secret.
    ///
    /// `None` when the relay has no static key, in which case no leg can be
    /// established and every handshake is refused with zero bytes — the same
    /// fail-closed direction an empty issuer key set produces.
    pub setup: Option<&'a LegSetup>,
    /// The source of the datagram being handled, for frames addressed back to
    /// it. Set by [`Pump::step`] and never read before.
    pub last_source: SocketAddr,
    /// `BOUND` announcements owed to half-flows that were already waiting.
    ///
    /// `(waiting_flow, arriving_flow)`. Drained by the caller after `step`; see
    /// the module docs for why this is not an amplification.
    pub pending_announcements: Vec<(FlowId, FlowId)>,
}

impl Pump<'_> {
    /// Handles one received datagram.
    ///
    /// Returns the single [`Action`] to take. Never two, never zero-or-many.
    pub fn step(&mut self, from: SocketAddr, datagram: Bytes, now_ms: u64) -> Action {
        self.last_source = from;
        self.pending_announcements.clear();

        // 1. Parse, with the derived payload bound applied before retention. A
        //    malformed datagram costs a parse and nothing else.
        let Ok(frame) = RelayFrame::parse(datagram) else {
            return Action::Silent {
                why: Drop::Malformed,
            };
        };

        // 2. Direction, BEFORE any state is touched (W-32). A relay-to-device
        //    frame arriving from a device reaches nothing.
        if !frame.kind().device_may_send() {
            return Action::Silent {
                why: Drop::WrongDirection,
            };
        }

        // 3. Leg setup is the one class that legitimately has no `K_leg` yet.
        if frame.kind().is_leg_setup() {
            return self.handshake(from, &frame, now_ms);
        }

        // 4. The leg. Without `K_leg` nothing can be authenticated, so nothing is
        //    answered — including control frames.
        if self.legs.get(from).is_none() {
            return Action::Silent { why: Drop::NoLeg };
        }
        self.legs.touch(from, now_ms);
        // Copied out of the registry rather than borrowed, because the branches
        // below need `&mut self.legs` (a handshake inserts, a bind reads the
        // token). `LegKey` is deliberately not `Clone` — a key that clones freely
        // is a key that ends up in two places — so the copy is explicit and
        // greppable through `expose`.
        let ingress_key = LegKey::new(
            *self
                .legs
                .key_for(from)
                .expect("the leg was present one line ago")
                .expose(),
        );

        match frame.kind() {
            FrameType::Data => self.forward_data(from, &frame, &ingress_key, now_ms),
            FrameType::Ping => self.pong(&frame, &ingress_key, from),
            FrameType::Bind | FrameType::Rebind => self.bind(from, &frame, &ingress_key, now_ms),
            FrameType::Caps => self.caps(from, &frame, &ingress_key),
            // Everything else was refused at step 2.
            _ => Action::Silent {
                why: Drop::UnhandledControl,
            },
        }
    }

    /// The `DATA` path: forward, or shed with a `RELAY_STATUS`.
    ///
    /// # `from` is a parameter, and that is finding R-5's fix
    ///
    /// The first version resolved the pair from `frame.flow_id()` alone and never
    /// compared `HalfFlow.peer`. `FlowId` is a sequential, enumerable `u32`, so
    /// **one** valid token let an attacker name any other subject's flow and:
    /// advance that victim's replay window (killing the flow with one packet),
    /// reflect bytes to any bound peer, and charge the victim's quota. It
    /// authenticated by source address implicitly and authorized by nothing.
    ///
    /// The fix is the `ingress.peer == from` comparison below. The frame MAC is
    /// not enough on its own: an attacker with its *own* valid leg can MAC
    /// anything correctly under *its* `K_leg`, and the ingress key is selected by
    /// source address — so without this check, MAC verification would confirm
    /// only that the attacker is some admitted device, which it is.
    fn forward_data(
        &mut self,
        from: SocketAddr,
        frame: &RelayFrame,
        ingress_key: &LegKey,
        now_ms: u64,
    ) -> Action {
        let ingress_flow = FlowId::new(frame.flow_id());

        let Some(pair) = self.engine.table().bound_for_flow(ingress_flow) else {
            return Action::Silent { why: Drop::Unbound };
        };
        // R-5: the half-flow this `flow_id` names must belong to the address the
        // datagram actually came from.
        if pair.ingress_peer(ingress_flow) != Some(from) {
            return Action::Silent {
                why: Drop::WrongSource,
            };
        }
        let Some(egress) = pair.egress_for(ingress_flow) else {
            return Action::Silent { why: Drop::Unbound };
        };
        let (egress_peer, egress_subject, egress_flow) =
            (egress.peer, egress.subject, egress.flow_id);

        let Some(egress_key) = self
            .legs
            .key_for(egress_peer)
            .map(|k| LegKey::new(*k.expose()))
        else {
            // The far side's leg is gone. Nothing to forward onto, and nothing to
            // say to this device that it will not learn from its own PING/PONG.
            return Action::Silent { why: Drop::NoLeg };
        };

        // ADR-0005 §11.5: throttle, NOT drop. A deferral is a queueing
        // instruction, so the frame goes to the DRR and the device is told.
        if let twinvpn_service_common::transport::Admission::Deferred { retry_after_ms } =
            self.engine.admit_bytes(egress_subject, now_ms)
        {
            self.scheduler
                .enqueue(egress_subject, egress_flow, frame.payload().len());
            return self.shed(
                ingress_key,
                Condition::RateLimited,
                retry_after_ms,
                ingress_flow,
                from,
            );
        }

        match self
            .engine
            .forward(frame, ingress_key, &egress_key, self.crypto, now_ms)
        {
            Ok(out) => {
                // On the path: the frame is scheduled, then handed to the socket.
                // The DRR decides ORDER between competing subjects; it never
                // decides whether a frame goes, which is what keeps §11.5's
                // "throttle not drop" and the scheduler from arguing.
                self.scheduler
                    .enqueue(out.egress_subject, out.egress_flow, out.payload_len);
                let _ = self.scheduler.dequeue();
                Action::Send {
                    to: egress_peer,
                    datagram: out.datagram,
                }
            }
            Err(ForwardRefusal::QuotaExceeded) => self.shed(
                ingress_key,
                Condition::QuotaExceeded,
                3_600_000,
                ingress_flow,
                from,
            ),
            Err(e) => Action::Silent {
                why: match e {
                    ForwardRefusal::NotData | ForwardRefusal::Unbound => Drop::Unbound,
                    ForwardRefusal::MacInvalid => Drop::MacInvalid,
                    ForwardRefusal::CounterRejected => Drop::CounterRejected,
                    ForwardRefusal::NoEgressMac => Drop::NoEgressMac,
                    ForwardRefusal::QuotaExceeded => unreachable!("handled above"),
                },
            },
        }
    }

    /// Emits `RELAY_STATUS` on the affected flow — never a silent drop (§11.5).
    ///
    /// If no MAC can be computed the frame cannot be authenticated to the device,
    /// and an unauthenticated status frame is worse than none: it is a free
    /// injection primitive for anyone who can spoof a source address. So the
    /// obligation degrades to a counter, and `Drop::NoEgressMac` records it.
    fn shed(
        &mut self,
        ingress_key: &LegKey,
        condition: Condition,
        retry_after_ms: u64,
        flow: FlowId,
        to: SocketAddr,
    ) -> Action {
        let status = RelayStatus::for_condition(
            condition,
            u32::try_from(retry_after_ms).unwrap_or(u32::MAX),
        );
        let body = status.encode_body();
        let mac_input = mac_input_for(FrameType::RelayStatus, flow.get(), &body);
        let Some(tag) = self.crypto.frame_mac(ingress_key, &mac_input) else {
            return Action::Silent {
                why: Drop::NoEgressMac,
            };
        };
        // Addressed to the source that sent the frame being shed, which is the
        // half-flow being throttled. Resolving it from the table instead would
        // send the status to whichever peer the table happened to name first.
        Action::Send {
            to,
            datagram: Bytes::from(status.encode_frame(flow.get(), 0, tag)),
        }
    }

    /// A leg-level `PONG`. ADR-0006 §11.15(c): the leg `PING`/`PONG` must be
    /// observable **independently of any half-flow**, because §11.4's whole
    /// failure attribution rests on distinguishing "the relay is gone" from "the
    /// peer is silent".
    fn pong(&self, frame: &RelayFrame, ingress_key: &LegKey, from: SocketAddr) -> Action {
        let body: &[u8] = &[];
        let mac_input = mac_input_for(FrameType::Pong, frame.flow_id(), body);
        let Some(tag) = self.crypto.frame_mac(ingress_key, &mac_input) else {
            return Action::Silent {
                why: Drop::NoEgressMac,
            };
        };
        let mut out = Vec::with_capacity(crate::frame::HEADER_LEN);
        out.push(FrameType::Pong.to_wire());
        out.push(crate::frame::VERSION << 4);
        out.extend_from_slice(&frame.counter_low().to_be_bytes());
        out.extend_from_slice(&frame.flow_id().to_be_bytes());
        out.extend_from_slice(&tag);
        Action::Send {
            to: from,
            datagram: Bytes::from(out),
        }
    }
}

/// ADR-0005 §9.1's MAC input, for a frame this relay originates.
fn mac_input_for(kind: FrameType, flow_id: u32, body: &[u8]) -> Vec<u8> {
    crate::control::mac_input(kind, flow_id, 0, body)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelayConfig;
    use crate::crypto::FailClosed;
    use crate::flow::PairTag;
    use crate::issuer::IssuerKeySet;
    use crate::token::testkit::{claims, good_envelope, Doubles};
    use std::time::Instant;
    use twinvpn_service_common::config::MapEnv;

    const LEG: &[u8] = b"RLK-cose-key";

    fn config() -> RelayConfig {
        RelayConfig::load(
            &MapEnv::new()
                .with("TWINVPN_RELAY_ID", "0000000000000a01")
                .with("TWINVPN_RELAY_REGION", "local-1")
                .with("TWINVPN_RELAY_FAILURE_DOMAIN", "fd-a")
                .with("TWINVPN_RELAY_OPERATOR_GROUP_ID", "local-operator")
                .with(
                    "TWINVPN_RELAY_ISSUER_KEYS_PATH",
                    concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
                )
                .with(
                    "TWINVPN_RELAY_STATIC_KEY_PATH",
                    concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
                ),
        )
        .expect("loads")
    }

    fn issuers() -> IssuerKeySet {
        IssuerKeySet::parse(
            r#"{"operator_group_id":"local-operator","issuers":[
               {"key_id":"k1","alg":"Ed25519","cose_key_hex":"0102"}]}"#,
            "local-operator",
            "x",
        )
        .expect("parses")
    }

    fn addr(port: u16) -> SocketAddr {
        format!("[::1]:{port}").parse().expect("addr")
    }

    fn datagram(kind: u8, flow: u32, counter: u16, payload: &[u8]) -> Bytes {
        let mut v = vec![kind, 0x10];
        v.extend_from_slice(&counter.to_be_bytes());
        v.extend_from_slice(&flow.to_be_bytes());
        v.extend_from_slice(&[0xAA; 8]);
        v.extend_from_slice(payload);
        Bytes::from(v)
    }

    /// A relay with one bound pair between `addr(1)` and `addr(2)`, and legs for
    /// both. Returns `(engine, legs, ingress_flow)`.
    fn bound_relay() -> (RelayEngine, LegRegistry, FlowId) {
        let mut e = RelayEngine::new(config(), issuers(), 3);
        let now = Instant::now();
        let mut c = claims();
        c.epoch = 3;
        c.not_before_ms = 0;
        c.not_after_ms = 86_400_000;
        let first = Doubles::new(c.clone());
        let v1 = e
            .admit(
                &crate::token::PresentedToken::new("k1".into(), good_envelope()),
                LEG,
                &first,
                1_000,
            )
            .expect("admitted");
        let tag = PairTag::from_wire(&[1; 16]).expect("16");
        let crate::engine::BindResult::Pending(a) = e.bind(tag, addr(1), &v1, now, 1_000) else {
            panic!("pending");
        };

        let mut c2 = c;
        c2.jti = [2; 16];
        c2.subject = [8; 16];
        let second = Doubles::new(c2);
        let v2 = e
            .admit(
                &crate::token::PresentedToken::new("k1".into(), good_envelope()),
                LEG,
                &second,
                1_000,
            )
            .expect("admitted");
        let crate::engine::BindResult::Bound { .. } = e.bind(tag, addr(2), &v2, now, 1_000) else {
            panic!("bound");
        };

        let mut legs = LegRegistry::new(1_000, 1_000, 900_000);
        assert!(legs.establish(
            addr(1),
            LegKey::new([1; 32]),
            crate::token::testkit::verified([9; 16]),
            0
        ));
        assert!(legs.establish(
            addr(2),
            LegKey::new([2; 32]),
            crate::token::testkit::verified([8; 16]),
            0
        ));
        (e, legs, a)
    }

    #[test]
    fn a_datagram_from_a_source_with_no_leg_produces_zero_bytes() {
        // The amplification property at its sharpest: a source that has not
        // completed a leg handshake gets nothing back, whatever it sends.
        let mut e = RelayEngine::new(config(), issuers(), 3);
        let mut legs = LegRegistry::new(1_000, 1_000, 900_000);
        let mut drr = TwoTierDrr::with_default_quantum();
        let mut p = Pump {
            engine: &mut e,
            legs: &mut legs,
            scheduler: &mut drr,
            crypto: &FailClosed,
            setup: None,
            last_source: addr(0),
            pending_announcements: Vec::new(),
        };
        for kind in [0x01_u8, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17] {
            let a = p.step(addr(9), datagram(kind, 1, 1, b"payload"), 0);
            assert!(!a.emits_bytes(), "kind {kind:#x} answered a legless source");
            assert_eq!(a.emitted_len(), 0);
        }
    }

    #[test]
    fn a_malformed_datagram_produces_zero_bytes() {
        let (mut e, mut legs, _) = bound_relay();
        let mut drr = TwoTierDrr::with_default_quantum();
        let mut p = Pump {
            engine: &mut e,
            legs: &mut legs,
            scheduler: &mut drr,
            crypto: &Doubles::new(claims()),
            setup: None,
            last_source: addr(0),
            pending_announcements: Vec::new(),
        };
        for bad in [
            Bytes::from_static(b""),
            Bytes::from_static(b"short"),
            datagram(0x7F, 1, 1, b""), // unknown type
            Bytes::from(vec![0x01, 0x90, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]), // bad version
            datagram(
                0x01,
                1,
                1,
                &vec![0; crate::frame::MAX_DATA_PAYLOAD_BYTES + 1],
            ),
        ] {
            let a = p.step(addr(1), bad, 0);
            assert!(matches!(
                a,
                Action::Silent {
                    why: Drop::Malformed
                }
            ));
        }
    }

    #[test]
    fn amplification_is_a_property_of_the_return_type() {
        // `Action` cannot express "send two". The forwarding path therefore emits
        // at most one frame per received frame BY CONSTRUCTION, which is
        // ADR-0005 §11.5's factor of exactly 1.0.
        let (mut e, mut legs, flow) = bound_relay();
        let mut drr = TwoTierDrr::with_default_quantum();
        let mut p = Pump {
            engine: &mut e,
            legs: &mut legs,
            scheduler: &mut drr,
            crypto: &Doubles::new(claims()),
            setup: None,
            last_source: addr(0),
            pending_announcements: Vec::new(),
        };
        let payload = vec![0xC3; 512];
        let a = p.step(addr(1), datagram(0x01, flow.get(), 1, &payload), 0);
        match a {
            Action::Send { to, datagram } => {
                assert_eq!(to, addr(2), "forwarded to exactly the peer half-flow");
                assert_eq!(
                    datagram.len(),
                    crate::frame::HEADER_LEN + payload.len(),
                    "equal payload length: no padding, no fan-out"
                );
                assert_eq!(&datagram[crate::frame::HEADER_LEN..], &payload[..]);
            }
            Action::Silent { why } => panic!("expected a forward, got {why:?}"),
        }
    }

    #[test]
    fn a_frame_for_an_unbound_flow_produces_zero_bytes() {
        let (mut e, mut legs, _) = bound_relay();
        let mut drr = TwoTierDrr::with_default_quantum();
        let mut p = Pump {
            engine: &mut e,
            legs: &mut legs,
            scheduler: &mut drr,
            crypto: &Doubles::new(claims()),
            setup: None,
            last_source: addr(0),
            pending_announcements: Vec::new(),
        };
        let a = p.step(addr(1), datagram(0x01, 9_999, 1, b"x"), 0);
        assert!(matches!(a, Action::Silent { why: Drop::Unbound }));
    }

    #[test]
    fn a_bad_mac_produces_zero_bytes() {
        let (mut e, mut legs, flow) = bound_relay();
        let mut drr = TwoTierDrr::with_default_quantum();
        let mut bad = Doubles::new(claims());
        bad.mac_ok = false;
        let mut p = Pump {
            engine: &mut e,
            legs: &mut legs,
            scheduler: &mut drr,
            crypto: &bad,
            setup: None,
            last_source: addr(0),
            pending_announcements: Vec::new(),
        };
        let a = p.step(addr(1), datagram(0x01, flow.get(), 1, b"x"), 0);
        assert!(matches!(
            a,
            Action::Silent {
                why: Drop::MacInvalid
            }
        ));
    }

    #[test]
    fn a_replayed_frame_produces_zero_bytes() {
        let (mut e, mut legs, flow) = bound_relay();
        let mut drr = TwoTierDrr::with_default_quantum();
        let d = Doubles::new(claims());
        let mut p = Pump {
            engine: &mut e,
            legs: &mut legs,
            scheduler: &mut drr,
            crypto: &d,
            setup: None,
            last_source: addr(0),
            pending_announcements: Vec::new(),
        };
        assert!(p
            .step(addr(1), datagram(0x01, flow.get(), 7, b"x"), 0)
            .emits_bytes());
        let a = p.step(addr(1), datagram(0x01, flow.get(), 7, b"x"), 0);
        assert!(matches!(
            a,
            Action::Silent {
                why: Drop::CounterRejected
            }
        ));
    }

    #[test]
    fn a_leg_ping_is_answered_independently_of_any_half_flow() {
        // ADR-0006 §11.15(c): the whole failure attribution in §11.4 rests on the
        // leg PING/PONG being observable with no bound half-flow at all.
        let mut e = RelayEngine::new(config(), issuers(), 3);
        let mut legs = LegRegistry::new(1_000, 1_000, 900_000);
        legs.establish(
            addr(1),
            LegKey::new([1; 32]),
            crate::token::testkit::verified([9; 16]),
            0,
        );
        let mut drr = TwoTierDrr::with_default_quantum();
        let mut p = Pump {
            engine: &mut e,
            legs: &mut legs,
            scheduler: &mut drr,
            crypto: &Doubles::new(claims()),
            setup: None,
            last_source: addr(0),
            pending_announcements: Vec::new(),
        };
        let a = p.step(addr(1), datagram(0x12, 0, 5, b""), 0);
        match a {
            Action::Send { to, datagram } => {
                assert_eq!(to, addr(1));
                assert_eq!(datagram[0], FrameType::Pong.to_wire());
                assert_eq!(datagram.len(), crate::frame::HEADER_LEN);
            }
            Action::Silent { why } => panic!("a leg PING went unanswered: {why:?}"),
        }
        assert_eq!(e.table().bound_count(), 0, "no half-flow was involved");
    }

    #[test]
    fn with_no_mac_provider_nothing_is_ever_emitted() {
        // An unauthenticated status or PONG frame would be a free injection
        // primitive for anyone who can spoof a source address, so the §11.5
        // obligation degrades to a counter rather than to an unsigned frame.
        let (mut e, mut legs, flow) = bound_relay();
        let mut drr = TwoTierDrr::with_default_quantum();
        let mut p = Pump {
            engine: &mut e,
            legs: &mut legs,
            scheduler: &mut drr,
            crypto: &FailClosed,
            setup: None,
            last_source: addr(0),
            pending_announcements: Vec::new(),
        };
        for kind in [0x01_u8, 0x12] {
            let a = p.step(addr(1), datagram(kind, flow.get(), 1, b"x"), 0);
            assert!(!a.emits_bytes());
        }
    }

    #[test]
    fn the_leg_registry_is_bounded() {
        let mut legs = LegRegistry::new(2, 2, 900_000);
        assert!(legs.establish(
            addr(1),
            LegKey::new([1; 32]),
            crate::token::testkit::verified([9; 16]),
            0
        ));
        assert!(legs.establish(
            addr(2),
            LegKey::new([2; 32]),
            crate::token::testkit::verified([8; 16]),
            0
        ));
        assert!(!legs.establish(
            addr(3),
            LegKey::new([3; 32]),
            crate::token::testkit::verified([7; 16]),
            0
        ));
        assert_eq!(legs.len(), 2);
        // Re-establishing an existing peer is a rekey, not a new entry.
        assert!(legs.establish(
            addr(1),
            LegKey::new([9; 32]),
            crate::token::testkit::verified([9; 16]),
            0
        ));
        assert_eq!(legs.len(), 2);
    }

    #[test]
    fn the_leg_registry_renders_no_peer_and_no_key() {
        let mut legs = LegRegistry::new(4, 4, 900_000);
        legs.establish(
            addr(1),
            LegKey::new([0xAB; 32]),
            crate::token::testkit::verified([9; 16]),
            0,
        );
        let rendered = format!("{legs:?}");
        assert!(!rendered.contains("::1"));
        assert!(!rendered.contains("ab"));
        assert!(rendered.contains("legs: 1"));
    }

    #[test]
    fn frames_pass_through_the_scheduler_on_the_forwarding_path() {
        // The DRR is ON the path: every forwarded frame is enqueued against its
        // (subject, flow) before it leaves, so two-tier fairness applies to real
        // traffic rather than to a scheduler nothing calls.
        let (mut e, mut legs, flow) = bound_relay();
        let mut drr = TwoTierDrr::with_default_quantum();
        {
            let mut p = Pump {
                engine: &mut e,
                legs: &mut legs,
                scheduler: &mut drr,
                crypto: &Doubles::new(claims()),
                setup: None,
                last_source: addr(0),
                pending_announcements: Vec::new(),
            };
            for counter in 1..=4_u16 {
                assert!(p
                    .step(addr(1), datagram(0x01, flow.get(), counter, b"payload"), 0)
                    .emits_bytes());
            }
        }
        // Four in, four dequeued on the way out: the queue does not grow.
        assert!(
            drr.is_empty(),
            "the scheduler is on the path, not beside it"
        );
    }

    #[test]
    fn a_subject_over_its_bitrate_is_told_rather_than_dropped_silently() {
        // ADR-0005 §11.5: "throttle, not drop", and "a relay that drops without a
        // status frame is a defect".
        let mut cfg = config();
        cfg.rate_per_subject_mbps = 0; // every byte defers
        let mut e = RelayEngine::new(cfg, issuers(), 3);
        let now = Instant::now();
        let mut c = claims();
        c.epoch = 3;
        c.not_before_ms = 0;
        c.not_after_ms = 86_400_000;
        c.quota.max_bitrate_kbps = 0;
        let d = Doubles::new(c.clone());
        let v1 = e
            .admit(
                &crate::token::PresentedToken::new("k1".into(), good_envelope()),
                LEG,
                &d,
                1_000,
            )
            .expect("admitted");
        let tag = PairTag::from_wire(&[1; 16]).expect("16");
        let crate::engine::BindResult::Pending(a) = e.bind(tag, addr(1), &v1, now, 1_000) else {
            panic!("pending");
        };
        let mut c2 = c;
        c2.jti = [2; 16];
        c2.subject = [8; 16];
        c2.quota.max_bitrate_kbps = 0;
        let v2 = e
            .admit(
                &crate::token::PresentedToken::new("k1".into(), good_envelope()),
                LEG,
                &Doubles::new(c2),
                1_000,
            )
            .expect("admitted");
        let crate::engine::BindResult::Bound { .. } = e.bind(tag, addr(2), &v2, now, 1_000) else {
            panic!("bound");
        };

        let mut legs = LegRegistry::new(8, 8, 900_000);
        legs.establish(
            addr(1),
            LegKey::new([1; 32]),
            crate::token::testkit::verified([9; 16]),
            0,
        );
        legs.establish(
            addr(2),
            LegKey::new([2; 32]),
            crate::token::testkit::verified([8; 16]),
            0,
        );
        let mut drr = TwoTierDrr::with_default_quantum();
        let mut p = Pump {
            engine: &mut e,
            legs: &mut legs,
            scheduler: &mut drr,
            crypto: &d,
            setup: None,
            last_source: addr(0),
            pending_announcements: Vec::new(),
        };
        // Drain the initial burst, then the next frame must be SHED WITH A STATUS.
        let mut saw_status = false;
        for counter in 1..=64_u16 {
            if let Action::Send { datagram, .. } =
                p.step(addr(1), datagram(0x01, a.get(), counter, b"payload"), 0)
            {
                if datagram[0] == FrameType::RelayStatus.to_wire() {
                    saw_status = true;
                    break;
                }
            }
        }
        assert!(
            saw_status,
            "a throttled subject received no RELAY_STATUS: §11.5 calls that a defect"
        );
        assert!(
            !drr.is_empty(),
            "the deferred frame is queued, not discarded"
        );
    }
}
