//! The 16-byte `RelayFrame` header, and RFC 9147 §4.2.2 counter reconstruction.
//!
//! ADR-0005 §9.1, identical across all four carriages:
//!
//! ```text
//! +---------------+-------+-------+-------------------------------+
//! |     type      |  ver  | flags |      counter_low (16 bit)     |   4 B
//! +---------------+-------+-------+-------------------------------+
//! |                       flow_id (32 bit)                        |   4 B
//! +---------------------------------------------------------------+
//! |                    auth_tag (64 bit, truncated)               |   8 B
//! +---------------------------------------------------------------+
//!                             = 16 B, then the opaque L-DATA datagram
//! ```
//!
//! # The payload is never a value this crate can read
//!
//! [`RelayFrame::payload`] returns [`Opaque`], whose whole surface is
//! `as_bytes`, `to_bytes`, `len` and `is_empty` — there is no decode, no parse,
//! no `Display`, and a `Debug` that prints a length, never octets. That is one
//! half of the I1 structural argument; the other half is
//! [`crate::crypto::RelayCrypto`] having no decrypt operation at all.
//!
//! # Why not `twinvpn_service_common::Verbatim` — a finding, not a preference
//!
//! W-4 directs every forwarder at `Forwarded`/`Verbatim`, and the *rule* it
//! encodes — forward the received octets verbatim, never decode-then-re-encode —
//! is honoured here in its strongest possible form: the relay never decodes at
//! all. But `Verbatim::from_received` cannot carry a relay `DATA` payload,
//! because it calls `twinvpn_schema::depth::check`, a **protobuf** record scan
//! that returns `Reject::Unparseable` when "the bytes are not a well-formed
//! record sequence at the top level".
//!
//! A relay `DATA` payload is an unmodified WireGuard L-DATA datagram (ADR-0001
//! §11, ADR-0005 C2) — AEAD ciphertext, not protobuf. Wrapping it in `Verbatim`
//! rejects essentially all real traffic. Measured, not assumed:
//! `the_service_common_verbatim_primitive_cannot_carry_l_data` below.
//!
//! `Verbatim` is right for the rendezvous' opaque `CALL` *envelope*, which is
//! protobuf; it is wrong for a ciphertext leg. That is a `twinvpn-service-common`
//! gap for this consumer and is reported to the integration lead rather than
//! worked around silently. [`Opaque`] keeps every property `Verbatim` provides —
//! the size bound, the absent decoder, the non-rendering `Debug` — and drops only
//! the protobuf structural assumption.
//!
//! # Bounds before allocation
//!
//! `parse` refuses anything shorter than the header before it indexes, and
//! bounds the payload through `twinvpn_service_common::transport::check_declared_length`
//! against `Channel::PeerDatagram`'s cap — `ownership.md` §6 rules 9 and 10, on a
//! directly attacker-reachable surface.

use bytes::Bytes;
use twinvpn_schema::{Channel, Reject};
use twinvpn_service_common::transport::check_declared_length;

/// A payload this process is not entitled to interpret.
///
/// Modelled on `twinvpn_service_common::Verbatim` and deliberately no larger:
/// bytes out, a length, and a `Debug` that says only how many. There is no
/// `decode`, no `Display`, no `Serialize` and no `AsRef<[u8]>` — an implicit
/// conversion is exactly what a reviewer does not see.
#[derive(Clone)]
pub struct Opaque(Bytes);

impl Opaque {
    /// Bounds and retains `bytes` against `channel`'s byte cap.
    ///
    /// The **only** check applied is the size cap. No structural scan runs,
    /// because there is no structure: the relay is forwarding ciphertext it must
    /// not interpret, and a parser that "understands" it would be the I1
    /// violation.
    ///
    /// # Errors
    ///
    /// [`Reject::SizeExceeded`], carrying the `limits.json` bound it violated.
    /// Never a truncation, never a pad.
    pub fn from_received(bytes: Bytes, channel: Channel) -> Result<Self, Reject> {
        let limit = channel.max_bytes();
        if bytes.len() > limit {
            return Err(Reject::SizeExceeded {
                parser_id: channel.parser_id(),
                observed: bytes.len(),
                limit,
            });
        }
        Ok(Self(bytes))
    }

    /// The octets, unchanged.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The octets, cheaply cloned for the next hop.
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        self.0.clone()
    }

    /// How many octets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Opaque {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Opaque({} bytes)", self.0.len())
    }
}

/// The wire header length. ADR-0005 §9.1.
pub const HEADER_LEN: usize = 16;

/// The protocol version this build speaks, in the `ver` nibble.
pub const VERSION: u8 = 1;

/// ADR-0005 §9.1 frame types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// `0x01` — an opaque L-DATA datagram to forward.
    Data,
    /// `0x10` — a device asking to join a `pair_tag`.
    Bind,
    /// `0x11` — the relay confirming a bound flow.
    Bound,
    /// `0x12` — leg liveness, observable independently of any half-flow
    /// (ADR-0006 §11.15(c) — the whole failure attribution rests on this).
    Ping,
    /// `0x13`.
    Pong,
    /// `0x14` — the relay asking a device to leave, with a deadline.
    Drain,
    /// `0x15` — overload, shedding or drain, never silent loss (§11.5, I6).
    RelayStatus,
    /// `0x16` — version and capability negotiation at leg setup.
    Caps,
    /// `0x17`.
    Rebind,
}

impl FrameType {
    const fn from_wire(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(FrameType::Data),
            0x10 => Some(FrameType::Bind),
            0x11 => Some(FrameType::Bound),
            0x12 => Some(FrameType::Ping),
            0x13 => Some(FrameType::Pong),
            0x14 => Some(FrameType::Drain),
            0x15 => Some(FrameType::RelayStatus),
            0x16 => Some(FrameType::Caps),
            0x17 => Some(FrameType::Rebind),
            _ => None,
        }
    }

    /// The wire byte.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            FrameType::Data => 0x01,
            FrameType::Bind => 0x10,
            FrameType::Bound => 0x11,
            FrameType::Ping => 0x12,
            FrameType::Pong => 0x13,
            FrameType::Drain => 0x14,
            FrameType::RelayStatus => 0x15,
            FrameType::Caps => 0x16,
            FrameType::Rebind => 0x17,
        }
    }
}

/// A parsed frame. The payload is opaque and stays that way.
#[derive(Debug)]
pub struct RelayFrame {
    kind: FrameType,
    version: u8,
    flags: u8,
    counter_low: u16,
    flow_id: u32,
    auth_tag: [u8; 8],
    payload: Opaque,
}

/// Why a frame was not parsed. Distinguished from [`Reject`] because a relay
/// drops a malformed frame silently — it emits **zero bytes** in response to any
/// unauthenticated or unbound frame (ADR-0005 §11.5, amplification factor 1.0).
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Fewer than [`HEADER_LEN`] bytes arrived.
    #[error("frame shorter than the {HEADER_LEN}-byte header")]
    TooShort,
    /// The `type` byte is not one this build knows.
    #[error("unknown frame type")]
    UnknownType,
    /// The `ver` nibble names an unsupported version.
    #[error("unsupported frame version")]
    UnsupportedVersion,
    /// Reserved bits were non-zero on receive.
    ///
    /// ADR-0014 forward compatibility says reserved bits MUST be zero on send
    /// and **ignored on receive**, so this variant exists for the *send* side's
    /// self-check only and is never produced by [`RelayFrame::parse`].
    #[error("reserved bits set")]
    ReservedBitsSet,
    /// The payload violated the channel's byte cap.
    #[error(transparent)]
    Bounds(#[from] Reject),
}

impl RelayFrame {
    /// Parses a datagram, bounding the payload before retaining it.
    ///
    /// # Errors
    ///
    /// [`FrameError`]. Every variant results in a silent drop on the wire.
    pub fn parse(datagram: Bytes) -> Result<Self, FrameError> {
        if datagram.len() < HEADER_LEN {
            return Err(FrameError::TooShort);
        }
        let kind = FrameType::from_wire(datagram[0]).ok_or(FrameError::UnknownType)?;
        let verflags = datagram[1];
        let version = verflags >> 4;
        // Reserved bits: zero on send, IGNORED on receive (ADR-0014).
        let flags = verflags & 0x0F;
        if version != VERSION {
            return Err(FrameError::UnsupportedVersion);
        }
        let counter_low = u16::from_be_bytes([datagram[2], datagram[3]]);
        let flow_id = u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]);
        let mut auth_tag = [0_u8; 8];
        auth_tag.copy_from_slice(&datagram[8..16]);

        // The bound check happens BEFORE the payload is retained.
        let payload_len = datagram.len() - HEADER_LEN;
        check_declared_length(payload_len, Channel::PeerDatagram)?;
        let payload = Opaque::from_received(datagram.slice(HEADER_LEN..), Channel::PeerDatagram)?;

        Ok(Self {
            kind,
            version,
            flags,
            counter_low,
            flow_id,
            auth_tag,
            payload,
        })
    }

    /// The frame type.
    #[must_use]
    pub const fn kind(&self) -> FrameType {
        self.kind
    }

    /// The `ver` nibble as parsed.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// The `flags` nibble.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// The low 16 bits of the per-half-flow counter.
    #[must_use]
    pub const fn counter_low(&self) -> u16 {
        self.counter_low
    }

    /// The relay-assigned flow handle.
    #[must_use]
    pub const fn flow_id(&self) -> u32 {
        self.flow_id
    }

    /// The 64-bit truncated MAC.
    #[must_use]
    pub const fn auth_tag(&self) -> [u8; 8] {
        self.auth_tag
    }

    /// The opaque payload.
    ///
    /// **There is no method on the returned type that yields a decoded value.**
    #[must_use]
    pub const fn payload(&self) -> &Opaque {
        &self.payload
    }

    /// The MAC input ADR-0005 §9.1 specifies:
    /// `(type‖ver‖flags‖counter_full‖flow_id‖payload)`.
    ///
    /// Note `counter_full`, not `counter_low`: the receiver reconstructs the
    /// 64-bit counter with [`CounterWindow`] and MACs over the full value, which
    /// is what stops a 16-bit wrap from being a forgery oracle.
    #[must_use]
    pub fn mac_input(&self, counter_full: u64) -> Vec<u8> {
        let payload = self.payload.as_bytes();
        let mut out = Vec::with_capacity(2 + 8 + 4 + payload.len());
        out.push(self.kind.to_wire());
        out.push((self.version << 4) | self.flags);
        out.extend_from_slice(&counter_full.to_be_bytes());
        out.extend_from_slice(&self.flow_id.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Serialises a header for the **outgoing** half-flow.
    ///
    /// ADR-0005 §11.1(5): "`flow_id` and `counter_low` are rewritten for the
    /// outgoing half-flow; nothing else is touched." This function is the only
    /// place either is rewritten, and it copies the payload byte for byte.
    #[must_use]
    pub fn reframe(&self, flow_id: u32, counter_low: u16, auth_tag: [u8; 8]) -> Bytes {
        let payload = self.payload.as_bytes();
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.push(self.kind.to_wire());
        out.push((self.version << 4) | self.flags);
        out.extend_from_slice(&counter_low.to_be_bytes());
        out.extend_from_slice(&flow_id.to_be_bytes());
        out.extend_from_slice(&auth_tag);
        out.extend_from_slice(payload);
        Bytes::from(out)
    }
}

/// RFC 9147 (DTLS 1.3) §4.2.2 sequence-number reconstruction and replay window.
///
/// ADR-0005 §9.1 names this exactly — "reconstructed by the receiver with a
/// sliding window exactly as RFC 9147 §4.2.2 specifies. No new construction (C1)."
#[derive(Debug, Clone, Copy)]
pub struct CounterWindow {
    highest: u64,
    bitmap: u64,
    seen_any: bool,
}

impl Default for CounterWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl CounterWindow {
    /// The window width, in frames.
    pub const WIDTH: u64 = 64;

    /// A fresh window.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
            seen_any: false,
        }
    }

    /// Reconstructs the full 64-bit counter from the 16-bit wire value.
    ///
    /// Picks the candidate nearest the highest counter seen, which is RFC 9147's
    /// rule and is what makes a wrap unambiguous inside the window.
    #[must_use]
    pub const fn reconstruct(&self, counter_low: u16) -> u64 {
        if !self.seen_any {
            return counter_low as u64;
        }
        let window = 1_u64 << 16;
        let base = self.highest & !(window - 1);
        let candidate = base | (counter_low as u64);
        let half = window / 2;
        if candidate + half < self.highest {
            candidate + window
        } else if candidate > self.highest + half {
            candidate.saturating_sub(window)
        } else {
            candidate
        }
    }

    /// Accepts `counter` if it is new and inside the window, and records it.
    ///
    /// Returns `false` for a replay or a counter too old to judge — the relay
    /// then drops the frame with no reply (amplification factor 1.0).
    pub fn accept(&mut self, counter: u64) -> bool {
        if !self.seen_any {
            self.seen_any = true;
            self.highest = counter;
            self.bitmap = 1;
            return true;
        }
        if counter > self.highest {
            let shift = counter - self.highest;
            if shift >= Self::WIDTH {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.highest = counter;
            return true;
        }
        let back = self.highest - counter;
        if back >= Self::WIDTH {
            return false;
        }
        let mask = 1_u64 << back;
        if self.bitmap & mask != 0 {
            return false;
        }
        self.bitmap |= mask;
        true
    }

    /// The highest counter accepted so far.
    #[must_use]
    pub const fn highest(&self) -> u64 {
        self.highest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datagram(kind: u8, ver_flags: u8, counter: u16, flow: u32, payload: &[u8]) -> Bytes {
        let mut v = Vec::new();
        v.push(kind);
        v.push(ver_flags);
        v.extend_from_slice(&counter.to_be_bytes());
        v.extend_from_slice(&flow.to_be_bytes());
        v.extend_from_slice(&[0xAA; 8]);
        v.extend_from_slice(payload);
        Bytes::from(v)
    }

    #[test]
    fn the_service_common_verbatim_primitive_cannot_carry_l_data() {
        // The evidence for the finding in this module's docs, measured rather
        // than argued. A WireGuard L-DATA datagram begins with a 4-byte type
        // field, a 4-byte receiver index, an 8-byte counter and then AEAD
        // ciphertext (ADR-0001 §11). None of that is a protobuf record sequence,
        // and `Verbatim::from_received` runs `twinvpn_schema::depth::check`.
        let mut l_data = vec![4_u8, 0, 0, 0]; // WireGuard message type 4 = DATA
        l_data.extend_from_slice(&0x1234_5678_u32.to_le_bytes()); // receiver index
        l_data.extend_from_slice(&7_u64.to_le_bytes()); // counter
        l_data.extend_from_slice(&[0xC3; 64]); // ciphertext + tag

        let via_verbatim = twinvpn_service_common::Verbatim::from_received(
            Bytes::from(l_data.clone()),
            Channel::PeerDatagram,
        );
        assert!(
            via_verbatim.is_err(),
            "if this ever passes, service-common's Verbatim gained a non-protobuf \
             mode and the relay should go back to using it"
        );

        // `Opaque` carries the same bytes, with the same size bound and the same
        // absence of a decoder.
        let via_opaque = Opaque::from_received(Bytes::from(l_data.clone()), Channel::PeerDatagram)
            .expect("ciphertext is carriable");
        assert_eq!(via_opaque.as_bytes(), &l_data[..]);
    }

    #[test]
    fn an_oversized_payload_is_refused_against_the_frozen_cap() {
        let cap = Channel::PeerDatagram.max_bytes();
        let e = Opaque::from_received(Bytes::from(vec![0_u8; cap + 1]), Channel::PeerDatagram)
            .unwrap_err();
        assert!(matches!(e, Reject::SizeExceeded { limit, .. } if limit == cap));
        // And exactly at the cap it is accepted — never a truncation, never a pad.
        assert!(Opaque::from_received(Bytes::from(vec![0_u8; cap]), Channel::PeerDatagram).is_ok());
    }

    #[test]
    fn the_header_is_sixteen_bytes() {
        assert_eq!(
            HEADER_LEN, 16,
            "ADR-0005 §9.1 and §9.3's MTU table depend on it"
        );
    }

    #[test]
    fn a_data_frame_parses_and_its_payload_stays_opaque() {
        let f = RelayFrame::parse(datagram(0x01, 0x10, 7, 42, b"ciphertext")).expect("parses");
        assert_eq!(f.kind(), FrameType::Data);
        assert_eq!(f.counter_low(), 7);
        assert_eq!(f.flow_id(), 42);
        assert_eq!(f.payload().len(), 10);
        // The Debug of the payload prints a length and a channel, never octets.
        let rendered = format!("{:?}", f.payload());
        assert!(!rendered.contains("ciphertext"));
    }

    #[test]
    fn a_short_datagram_is_refused_before_it_is_indexed() {
        for len in 0..HEADER_LEN {
            let e = RelayFrame::parse(Bytes::from(vec![0x01; len])).unwrap_err();
            assert!(matches!(e, FrameError::TooShort));
        }
    }

    #[test]
    fn an_unknown_type_or_version_is_refused() {
        assert!(matches!(
            RelayFrame::parse(datagram(0x7F, 0x10, 0, 0, b"")).unwrap_err(),
            FrameError::UnknownType
        ));
        assert!(matches!(
            RelayFrame::parse(datagram(0x01, 0x90, 0, 0, b"")).unwrap_err(),
            FrameError::UnsupportedVersion
        ));
    }

    #[test]
    fn reserved_flag_bits_are_ignored_on_receive() {
        // ADR-0014 forward compatibility: an unknown flag must not make an
        // otherwise-valid frame unparseable.
        let f = RelayFrame::parse(datagram(0x01, 0x1F, 0, 0, b"x")).expect("parses");
        assert_eq!(f.flags(), 0x0F);
    }

    #[test]
    fn reframing_rewrites_only_the_flow_id_the_counter_and_the_tag() {
        let original = datagram(0x01, 0x10, 7, 42, b"opaque-ciphertext-bytes");
        let f = RelayFrame::parse(original.clone()).expect("parses");
        let out = f.reframe(99, 8, [0xBB; 8]);

        assert_eq!(out[0], original[0], "type unchanged");
        assert_eq!(out[1], original[1], "ver/flags unchanged");
        assert_eq!(&out[2..4], &8_u16.to_be_bytes(), "counter rewritten");
        assert_eq!(&out[4..8], &99_u32.to_be_bytes(), "flow_id rewritten");
        assert_eq!(&out[8..16], &[0xBB; 8], "tag recomputed for the new leg");
        assert_eq!(
            &out[HEADER_LEN..],
            &original[HEADER_LEN..],
            "the payload is forwarded BYTE FOR BYTE (ADR-0005 §11.1(5), W-4)"
        );
    }

    #[test]
    fn the_mac_covers_the_full_counter_not_the_truncated_one() {
        let f = RelayFrame::parse(datagram(0x01, 0x10, 7, 42, b"p")).expect("parses");
        let a = f.mac_input(7);
        let b = f.mac_input(65_543); // same low 16 bits, different full counter
        assert_ne!(
            a, b,
            "a 16-bit wrap must not produce an identical MAC input"
        );
    }

    #[test]
    fn the_counter_window_reconstructs_across_a_wrap() {
        let mut w = CounterWindow::new();
        assert!(w.accept(w.reconstruct(65_530)));
        let full = w.reconstruct(3);
        assert_eq!(full, 65_539, "3 after 65530 is the next wrap, not a rewind");
        assert!(w.accept(full));
    }

    #[test]
    fn the_counter_window_refuses_a_replay() {
        let mut w = CounterWindow::new();
        assert!(w.accept(100));
        assert!(w.accept(101));
        assert!(!w.accept(101), "an exact replay is refused");
        assert!(w.accept(99), "an in-window reorder is accepted once");
        assert!(!w.accept(99));
    }

    #[test]
    fn the_counter_window_refuses_anything_older_than_the_window() {
        let mut w = CounterWindow::new();
        assert!(w.accept(1_000));
        assert!(!w.accept(1_000 - CounterWindow::WIDTH));
        assert!(!w.accept(0));
    }

    #[test]
    fn a_large_jump_forward_resets_the_bitmap_without_panicking() {
        let mut w = CounterWindow::new();
        assert!(w.accept(1));
        assert!(w.accept(1_000_000));
        assert_eq!(w.highest(), 1_000_000);
        assert!(
            !w.accept(1),
            "the old counter is now far outside the window"
        );
    }
}
