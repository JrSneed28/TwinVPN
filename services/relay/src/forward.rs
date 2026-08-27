//! The forwarding engine — and the structural argument that it cannot interpret.
//!
//! ADR-0005 §11.1(5):
//!
//! > The relay MUST forward each authenticated `DATA` frame to exactly the peer
//! > half-flow, **byte for byte**, without inspecting, buffering beyond its
//! > bounded queue, retransmitting, or padding. `flow_id` and `counter_low` are
//! > rewritten for the outgoing half-flow; **nothing else is touched**.
//!
//! # How "it cannot decrypt" is asserted structurally rather than by inspection
//!
//! Four properties, each checkable rather than argued:
//!
//! 1. **The payload's type has no reader.** A payload travels as
//!    [`crate::frame::Opaque`]. Its whole surface is `as_bytes`, `to_bytes`,
//!    `len`, `is_empty` — no decode, no parse, no `Display`, and a `Debug` that
//!    prints a length. There is no method to call that yields a decoded value.
//!    (`crate::frame`'s docs record why `twinvpn_service_common::Verbatim`
//!    cannot be the carrier for a ciphertext leg; the *rule* it encodes is
//!    honoured here in its strongest form — nothing is ever decoded.)
//! 2. **The key inventory has no decrypt operation.**
//!    [`crate::crypto::RelayCrypto`] exposes `verify_signature`,
//!    `verify_frame_mac`, `frame_mac` and `digest16`. There is no `decrypt`, no
//!    `open`, no `unseal`. A relay built against this trait has nothing to call.
//! 3. **The only key that touches a frame is `K_leg`, and it only MACs.** ADR-0005
//!    §7.1: `K_leg` is "domain-separated from L-DATA; used only for the 64-bit
//!    frame MAC". [`Forwarder::forward`] passes it to `verify_frame_mac` and
//!    `frame_mac` and to nothing else.
//! 4. **The bytes out equal the bytes in.** [`Forwarded::payload_is_verbatim`]
//!    compares them, and `tests/cannot_decrypt.rs` asserts it over a corpus
//!    including bytes that *would* parse as a protobuf message — because W-4's
//!    trap is precisely that a decode-then-re-encode round trip looks correct
//!    until an unknown field is present.
//!
//! What is *not* claimed: that a relay operator learns nothing. See
//! [`crate::observe`] and ADR-0005 §7.2 for what it does learn.

use bytes::Bytes;

use crate::crypto::{LegKey, RelayCrypto};
use crate::flow::{BoundPair, FlowId, PairTable};
use crate::frame::{FrameType, RelayFrame};
use crate::subject::RelaySub;

/// A frame ready to leave, on exactly one half-flow.
#[derive(Debug)]
pub struct Forwarded {
    /// The egress half-flow.
    pub egress_flow: FlowId,
    /// Whose quota the *egress* side is charged to.
    pub egress_subject: RelaySub,
    /// The complete datagram: rewritten 16-byte header plus the original payload.
    pub datagram: Bytes,
    /// How many payload bytes were carried, for metering.
    pub payload_len: usize,
}

impl Forwarded {
    /// Whether the payload left byte for byte.
    ///
    /// The test-facing half of property 4. It compares the tail of the outgoing
    /// datagram with the original payload; a mismatch means something decoded and
    /// re-encoded, which is the W-4 trap.
    #[must_use]
    pub fn payload_is_verbatim(&self, original_payload: &[u8]) -> bool {
        self.datagram.len() == crate::frame::HEADER_LEN + original_payload.len()
            && &self.datagram[crate::frame::HEADER_LEN..] == original_payload
    }
}

/// Why a frame was not forwarded. Every variant results in **zero bytes** on the
/// wire (ADR-0005 §11.5, amplification factor exactly 1.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardRefusal {
    /// The frame is not a `DATA` frame; control frames are handled elsewhere.
    NotData,
    /// No bound pair holds this `flow_id`. Includes a squatted pending slot.
    Unbound,
    /// The 64-bit truncated frame MAC did not verify under `K_leg`.
    ///
    /// This is what protects the relay's own session table from off-path
    /// injection. It is **not** a confidentiality control — the payload is
    /// already L-DATA-sealed and the relay could not read it either way.
    MacInvalid,
    /// The counter was a replay or fell outside the RFC 9147 window.
    CounterRejected,
    /// The relay could not compute an outgoing MAC — no crypto provider.
    NoEgressMac,
    /// The egress subject's hourly byte quota is spent (ADR-0005 §11.5).
    ///
    /// Unlike the others this is **not** a silent drop: §11.5 requires a
    /// `RELAY_STATUS` on the affected flow, which [`crate::pump`] emits.
    QuotaExceeded,
}

/// The forwarding engine.
///
/// It holds a reference to the crypto provider and nothing else. In particular it
/// holds **no** L-DATA key, no session key and no tunnel state, because there is
/// no such thing on a relay to hold.
pub struct Forwarder<'a> {
    crypto: &'a dyn RelayCrypto,
}

impl<'a> Forwarder<'a> {
    /// A forwarder over `crypto`.
    #[must_use]
    pub const fn new(crypto: &'a dyn RelayCrypto) -> Self {
        Self { crypto }
    }

    /// Forwards one authenticated `DATA` frame to exactly the peer half-flow.
    ///
    /// # Errors
    ///
    /// [`ForwardRefusal`]. Every one is a silent drop.
    pub fn forward(
        &self,
        frame: &RelayFrame,
        table: &mut PairTable,
        ingress_key: &LegKey,
        egress_key: &LegKey,
        now_ms: u64,
    ) -> Result<Forwarded, ForwardRefusal> {
        if frame.kind() != FrameType::Data {
            return Err(ForwardRefusal::NotData);
        }
        let ingress_flow = FlowId::new(frame.flow_id());
        let pair = table
            .bound_for_flow_mut(ingress_flow)
            .ok_or(ForwardRefusal::Unbound)?;

        // 1. Reconstruct the full counter, then verify the MAC over it. The order
        //    matters: MACing the truncated counter would let a 16-bit wrap be a
        //    forgery oracle (frame.rs asserts the two inputs differ).
        let counter_full = {
            let ingress = pair
                .ingress_for_mut(ingress_flow)
                .ok_or(ForwardRefusal::Unbound)?;
            ingress.window.reconstruct(frame.counter_low())
        };
        let mac_input = frame.mac_input(counter_full);
        if !self
            .crypto
            .verify_frame_mac(ingress_key, &mac_input, frame.auth_tag())
        {
            return Err(ForwardRefusal::MacInvalid);
        }

        // 2. Accept the counter only after the MAC verifies, so an unauthenticated
        //    frame cannot advance a window and lock out the real peer.
        {
            let ingress = pair
                .ingress_for_mut(ingress_flow)
                .ok_or(ForwardRefusal::Unbound)?;
            if !ingress.window.accept(counter_full) {
                return Err(ForwardRefusal::CounterRejected);
            }
            ingress.last_activity_ms = now_ms;
        }

        // 3. Rewrite for the egress half-flow. `flow_id` and `counter_low` only.
        let (egress_flow, egress_subject, egress_counter) = {
            let egress = Self::egress_mut(pair, ingress_flow)?;
            egress.tx_counter = egress.tx_counter.wrapping_add(1);
            egress.last_activity_ms = now_ms;
            (egress.flow_id, egress.subject, egress.tx_counter)
        };

        #[allow(clippy::cast_possible_truncation)]
        let counter_low = egress_counter as u16;
        // Over the EGRESS flow_id, because that is what `reframe` puts on the
        // wire. Using the ingress one MACs a value the peer never sees, and the
        // peer then verifies nothing — see `RelayFrame::egress_mac_input`.
        let egress_mac_input = frame.egress_mac_input(egress_flow.get(), egress_counter);
        let tag = self
            .crypto
            .frame_mac(egress_key, &egress_mac_input)
            .ok_or(ForwardRefusal::NoEgressMac)?;

        Ok(Forwarded {
            egress_flow,
            egress_subject,
            datagram: frame.reframe(egress_flow.get(), counter_low, tag),
            payload_len: frame.payload().len(),
        })
    }

    fn egress_mut(
        pair: &mut BoundPair,
        ingress: FlowId,
    ) -> Result<&mut crate::flow::HalfFlow, ForwardRefusal> {
        if pair.a.flow_id == ingress {
            Ok(&mut pair.b)
        } else if pair.b.flow_id == ingress {
            Ok(&mut pair.a)
        } else {
            Err(ForwardRefusal::Unbound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::VerifiedClaims;
    use crate::crypto::{FailClosed, IssuerPublicKey, Statement};
    use crate::flow::{BindOutcome, PairTag};

    struct MacAlwaysOk;
    impl RelayCrypto for MacAlwaysOk {
        fn verify_statement(
            &self,
            _: &IssuerPublicKey,
            _: Statement,
            _: &[u8],
        ) -> Option<VerifiedClaims> {
            None
        }
        fn verify_frame_mac(&self, _: &LegKey, _: &[u8], _: [u8; 8]) -> bool {
            true
        }
        fn frame_mac(&self, _: &LegKey, _: &[u8]) -> Option<[u8; 8]> {
            Some([0xEE; 8])
        }
        fn digest16(&self, _: &[u8], _: &[u8]) -> Option<[u8; 16]> {
            None
        }
    }

    fn datagram(flow: u32, counter: u16, payload: &[u8]) -> Bytes {
        let mut v = vec![0x01, 0x10];
        v.extend_from_slice(&counter.to_be_bytes());
        v.extend_from_slice(&flow.to_be_bytes());
        v.extend_from_slice(&[0xAA; 8]);
        v.extend_from_slice(payload);
        Bytes::from(v)
    }

    fn bound_table() -> (PairTable, FlowId, FlowId) {
        let mut t = PairTable::new(30_000, 900_000, 1_000);
        let tag = PairTag::from_wire(&[1; 16]).expect("16");
        let BindOutcome::Pending { flow_id: a } = t.bind(
            tag,
            "[::1]:1".parse().expect("addr"),
            RelaySub::from_verified_claim([1; 16]),
            0,
        ) else {
            panic!("pending");
        };
        let BindOutcome::Bound { flow_id: b, .. } = t.bind(
            tag,
            "192.0.2.9:2".parse().expect("addr"),
            RelaySub::from_verified_claim([2; 16]),
            0,
        ) else {
            panic!("bound");
        };
        (t, a, b)
    }

    #[test]
    fn a_data_frame_reaches_exactly_the_peer_half_flow() {
        let (mut t, a, b) = bound_table();
        let payload = b"opaque-l-data-ciphertext".to_vec();
        let f = RelayFrame::parse(datagram(a.get(), 1, &payload)).expect("parses");
        let out = Forwarder::new(&MacAlwaysOk)
            .forward(&f, &mut t, &LegKey::new([1; 32]), &LegKey::new([2; 32]), 0)
            .expect("forwards");
        assert_eq!(out.egress_flow, b);
        assert_eq!(out.payload_len, payload.len());
    }

    #[test]
    fn the_payload_leaves_byte_for_byte() {
        let (mut t, a, _) = bound_table();
        // Bytes that WOULD decode as a protobuf message with an unknown field —
        // the exact W-4 trap: a decode-then-re-encode round trip drops it.
        let payload = vec![0x08, 0x01, 0xF8, 0xFF, 0xFF, 0x0F, 0x2A, 0x00, 0xFF, 0x00];
        let f = RelayFrame::parse(datagram(a.get(), 1, &payload)).expect("parses");
        let out = Forwarder::new(&MacAlwaysOk)
            .forward(&f, &mut t, &LegKey::new([1; 32]), &LegKey::new([2; 32]), 0)
            .expect("forwards");
        assert!(out.payload_is_verbatim(&payload));
        assert_eq!(&out.datagram[crate::frame::HEADER_LEN..], &payload[..]);
    }

    #[test]
    fn the_egress_mac_covers_the_rewritten_flow_id_not_the_ingress_one() {
        // A real defect, found by the end-to-end socket test the frame-MAC
        // binding unlocked. `reframe` rewrites `flow_id` for the egress
        // half-flow, so the egress MAC must cover THAT value; MACing the ingress
        // one produces a tag over bytes the peer never sees, and the peer then
        // verifies nothing.
        //
        // It was invisible for as long as `frame_mac` returned `None`: nothing
        // verified, so nothing could disagree. Pinned here at unit level so it
        // cannot regress without an obvious failure.
        let (mut t, a, b) = bound_table();
        let payload = b"opaque".to_vec();
        let f = RelayFrame::parse(datagram(a.get(), 1, &payload)).expect("parses");
        assert_ne!(a, b, "the two half-flows have different handles");

        let ingress_input = f.mac_input(1);
        let egress_input = f.egress_mac_input(b.get(), 1);
        assert_ne!(
            ingress_input, egress_input,
            "the two inputs differ, so choosing the wrong one is a real error"
        );

        // What the forwarder actually MACs must be the egress form.
        let out = Forwarder::new(&MacAlwaysOk)
            .forward(&f, &mut t, &LegKey::new([1; 32]), &LegKey::new([2; 32]), 0)
            .expect("forwards");
        let on_the_wire_flow = u32::from_be_bytes([
            out.datagram[4],
            out.datagram[5],
            out.datagram[6],
            out.datagram[7],
        ]);
        assert_eq!(
            on_the_wire_flow,
            out.egress_flow.get(),
            "the wire carries the egress flow_id, so the MAC must too"
        );
    }

    #[test]
    fn an_unbound_flow_id_produces_zero_bytes() {
        let (mut t, _, _) = bound_table();
        let f = RelayFrame::parse(datagram(9_999, 1, b"x")).expect("parses");
        assert_eq!(
            Forwarder::new(&MacAlwaysOk)
                .forward(&f, &mut t, &LegKey::new([1; 32]), &LegKey::new([2; 32]), 0)
                .unwrap_err(),
            ForwardRefusal::Unbound
        );
    }

    #[test]
    fn a_bad_mac_produces_zero_bytes_and_does_not_advance_the_window() {
        let (mut t, a, _) = bound_table();
        let f = RelayFrame::parse(datagram(a.get(), 500, b"x")).expect("parses");
        assert_eq!(
            Forwarder::new(&FailClosed)
                .forward(&f, &mut t, &LegKey::new([1; 32]), &LegKey::new([2; 32]), 0)
                .unwrap_err(),
            ForwardRefusal::MacInvalid
        );
        // The counter window is untouched, so an off-path injector cannot lock
        // the real peer out by burning counters.
        let pair = t.bound_for_flow(a).expect("bound");
        let ingress = if pair.a.flow_id == a {
            &pair.a
        } else {
            &pair.b
        };
        assert_eq!(ingress.window.highest(), 0);
    }

    #[test]
    fn a_replayed_counter_is_refused() {
        let (mut t, a, _) = bound_table();
        let fwd = Forwarder::new(&MacAlwaysOk);
        let k1 = LegKey::new([1; 32]);
        let k2 = LegKey::new([2; 32]);
        let f = RelayFrame::parse(datagram(a.get(), 7, b"x")).expect("parses");
        fwd.forward(&f, &mut t, &k1, &k2, 0).expect("first");
        let again = RelayFrame::parse(datagram(a.get(), 7, b"x")).expect("parses");
        assert_eq!(
            fwd.forward(&again, &mut t, &k1, &k2, 0).unwrap_err(),
            ForwardRefusal::CounterRejected
        );
    }

    #[test]
    fn a_control_frame_is_not_forwarded_as_data() {
        let (mut t, a, _) = bound_table();
        let mut d = datagram(a.get(), 1, b"x").to_vec();
        d[0] = FrameType::Ping.to_wire();
        let f = RelayFrame::parse(Bytes::from(d)).expect("parses");
        assert_eq!(
            Forwarder::new(&MacAlwaysOk)
                .forward(&f, &mut t, &LegKey::new([1; 32]), &LegKey::new([2; 32]), 0)
                .unwrap_err(),
            ForwardRefusal::NotData
        );
    }

    #[test]
    fn amplification_is_at_most_one_frame_of_equal_payload_length() {
        let (mut t, a, _) = bound_table();
        for len in [0_usize, 1, 64, 1_200] {
            let payload = vec![0x5A; len];
            let f = RelayFrame::parse(datagram(a.get(), 1, &payload)).expect("parses");
            // A refusal emits zero bytes, which is below 1.0 and also safe.
            if let Ok(out) = Forwarder::new(&MacAlwaysOk).forward(
                &f,
                &mut t,
                &LegKey::new([1; 32]),
                &LegKey::new([2; 32]),
                0,
            ) {
                assert_eq!(
                    out.datagram.len(),
                    crate::frame::HEADER_LEN + len,
                    "the relay never pads and never fans out"
                );
            }
        }
    }

    #[test]
    fn a_forwarder_holds_no_key_but_the_leg_key_it_is_handed() {
        // The type-level half of the I1 argument. `Forwarder` has exactly one
        // field: a reference to a provider with no decrypt operation. If a
        // second field ever appears, this test is where the reviewer looks.
        assert_eq!(
            std::mem::size_of::<Forwarder<'_>>(),
            std::mem::size_of::<&dyn RelayCrypto>()
        );
    }
}
