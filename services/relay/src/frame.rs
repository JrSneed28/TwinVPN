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
//! [`RelayFrame::payload`] returns [`twinvpn_service_common::Verbatim`] built
//! through **[`Verbatim::from_opaque`]** — `Framing::Opaque`, size cap only. Its
//! whole surface is `as_bytes`, `to_bytes`, `into_bytes`, `len`, `is_empty`:
//! there is no decode, no parse, no `Display`, and a `Debug` that prints a
//! length, a channel and the framing token, never octets. That is one half of the
//! I1 structural argument; the other half is [`crate::crypto::RelayCrypto`]
//! having no decrypt operation at all.
//!
//! # Why `from_opaque` and not `from_received`
//!
//! `from_received` is `Framing::ProtobufRecords`: it runs
//! `twinvpn_schema::depth::check`, a protobuf record scan that returns
//! `Reject::Unparseable` for bytes that are not a well-formed record sequence. A
//! relay `DATA` payload is an unmodified WireGuard L-DATA datagram (ADR-0001
//! §11, ADR-0005 C2) — AEAD ciphertext, not protobuf — so `from_received`
//! refuses essentially all real relay traffic.
//!
//! The deeper reason `from_opaque` exists is ADR-0003 **R7**: "B4 MUST have
//! **zero** serialization framework in the packet path", and
//! `contracts/README.md`'s note that B4's schema artifact is *absent by design*
//! so "the highest-rate path is immune to serialization bugs by construction".
//! A parser on this path removes that immunity. The pair is asserted below by
//! `the_two_framings_disagree_which_is_the_whole_finding`: protobuf mode refuses
//! an L-DATA datagram, opaque mode carries it.
//!
//! # Bounds before allocation — and where the bound comes from
//!
//! See [`MAX_DATA_PAYLOAD_BYTES`]. `parse` refuses anything shorter than the
//! header before it indexes, and bounds the payload against that derived B4
//! ceiling *before* retaining it — `ownership.md` §6 rules 9 and 10, on a
//! directly attacker-reachable surface.

use bytes::Bytes;
use twinvpn_schema::{Channel, Reject};
use twinvpn_service_common::Verbatim;

/// The wire header length. ADR-0005 §9.1.
pub const HEADER_LEN: usize = 16;

/// The protocol version this build speaks, in the `ver` nibble.
pub const VERSION: u8 = 1;

/// The largest `DATA` payload a relay leg can legitimately carry: **1456 bytes**.
///
/// # This is derived, not borrowed — and the number it replaced was wrong
///
/// The first version of this crate bounded the payload against
/// `Channel::PeerDatagram` (1200 B, `limits.json`'s `envelope.c4_max_bytes`).
/// That is the **C4 rendezvous datagram** cap: a pre-authentication,
/// attacker-reachable *signalling* channel, deliberately given "the smallest safe
/// parser". A relay leg is B4, and it is bounded by **path MTU**, not by C4.
///
/// It was not merely the nearest available number, it was **too small to be
/// legal**. `docs/networking.md` §6.2 and ADR-0005 C7 fix an overlay MTU floor of
/// **1280**, and ADR-0005 §9.2 adds 32 B of L-DATA overhead beneath it, so the
/// smallest payload a conforming relay must be able to carry is
/// `1280 + 32 = 1312` — above 1200. A 1200-byte cap would have made the 1280
/// floor unachievable on every carriage, which is exactly the condition §9.2
/// requires `RELAY.MTU_FLOOR_VIOLATED` for.
///
/// # The derivation
///
/// `limits.json` has **no B4 entry to look this up in**, and that absence is
/// consistent rather than accidental: `contracts/README.md` records that B4's
/// schema artifact is *absent by design*. So the bound has to be argued from
/// ADR-0005 §9.2's overhead table.
///
/// A relay receives a datagram and forwards it byte for byte; it never fragments
/// and never reassembles (§11.1(5)). The payload it carries is therefore one
/// L-DATA datagram, and the largest one any carriage can deliver on the underlay
/// §9.2 analyses is the row with the **least framing beneath `RelayFrame`** —
/// `R-UDP` over IPv4:
///
/// ```text
///   1500   Ethernet underlay MTU (§9.2's stated basis)
///   -  20  IPv4 header
///   -   8  UDP header
///   -  16  RelayFrame (§9.1)
///   ------
///   = 1456 bytes of L-DATA datagram
/// ```
///
/// Which is §9.2's own arithmetic read the other way: that row gives an overlay
/// MTU of 1424, and `1424 + 32` (L-DATA overhead) `= 1456`. Every other row —
/// `R-UDP` v6 (1436), `R-QUIC` (1408 / 1388), `R-TLS` (1400 / 1380) — is
/// **smaller**, because each adds framing beneath `RelayFrame`. So the v4 `R-UDP`
/// row is the binding maximum across all four carriages and both families.
///
/// # Why this is the right conservative choice at the top end too
///
/// A link with an MTU above 1500 could in principle deliver more. Nothing in
/// Phase 1 contemplates one: §9.2 states 1500 as its basis and lists only
/// *lower* underlays (464XLAT 1480, PPPoE 1492) as variations, `docs/networking.md`
/// §6.2 sets a floor and no ceiling above 1500, and DPLPMTUD searches downward
/// from the interface MTU. Admitting jumbo frames here would widen an
/// attacker-driven allocation on the highest-rate path in the system for traffic
/// no ADR describes, so the ceiling stays where the ADR's own table puts it.
///
/// The margin is comfortable in the direction that matters: 1456 clears the 1312
/// the 1280 floor requires by **144 bytes**, and
/// `the_bound_clears_the_1280_overlay_floor` pins that.
///
/// # What a violation is
///
/// A silent drop, not a reply. ADR-0005 §11.5: the relay emits **zero bytes** in
/// response to any unauthenticated or unbound frame, so an oversized datagram
/// costs an attacker a packet and earns nothing — amplification stays at 1.0.
pub const MAX_DATA_PAYLOAD_BYTES: usize = 1_456;

/// The L-DATA per-datagram overhead ADR-0005 §9.2 accounts for.
pub const L_DATA_OVERHEAD_BYTES: usize = 32;

/// The overlay MTU floor `docs/networking.md` §6.2 and ADR-0005 C7 fix.
pub const OVERLAY_MTU_FLOOR: usize = 1_280;

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
    /// `0x18` — `Noise_IK` message 1, carrying the `RelayCapabilityToken`.
    ///
    /// **Allocated by this domain inside the space ADR-0005 §9.1 reserves.**
    /// §9.1 assigns `0x10..0x1F` to control and names eight of the sixteen; the
    /// leg handshake of §11.1(2) has to arrive in *some* datagram on the same
    /// socket, and the alternatives were worse. Multiplexing it onto `CAPS`
    /// would make one type mean two things at different points in a leg's life,
    /// and a separate UDP port would be a fifth carriage nothing in ADR-0006's
    /// map can describe. Recorded as a proposal for ADR-0005's owner, exactly as
    /// [`crate::status`] records the `RELAY_STATUS` body.
    HandshakeInit,
    /// `0x19` — `Noise_IK` message 2. See [`FrameType::HandshakeInit`].
    HandshakeResp,
    /// `0x1A` — the stateless cookie challenge of ADR-0005 §11.5.
    ///
    /// "Above 20 handshakes/s from a source /24 (v4) or /48 (v6) it issues a
    /// stateless cookie challenge first (the WireGuard MAC2 / QUIC Retry
    /// pattern)." This is that frame.
    CookieChallenge,
}

impl FrameType {
    /// Decodes a wire byte. `None` for a type this build does not know, which is
    /// a silent drop (ADR-0014: an unknown *type* is not a forward-compatible
    /// extension point the way a reserved *bit* is).
    #[must_use]
    pub const fn from_wire(v: u8) -> Option<Self> {
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
            0x18 => Some(FrameType::HandshakeInit),
            0x19 => Some(FrameType::HandshakeResp),
            0x1A => Some(FrameType::CookieChallenge),
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
            FrameType::HandshakeInit => 0x18,
            FrameType::HandshakeResp => 0x19,
            FrameType::CookieChallenge => 0x1A,
        }
    }

    /// Whether this frame is part of leg establishment and therefore **cannot**
    /// carry a `K_leg` MAC, because no `K_leg` exists yet.
    ///
    /// The pump branches on this before it looks a leg up, so the one datagram
    /// class that legitimately has no leg is not confused with the far larger
    /// class that has none because it is unauthenticated.
    #[must_use]
    pub const fn is_leg_setup(self) -> bool {
        matches!(
            self,
            FrameType::HandshakeInit | FrameType::HandshakeResp | FrameType::CookieChallenge
        )
    }

    /// Whether a **device** may legitimately send this type to a relay.
    ///
    /// The mirror of `twinvpn_relay_client::FrameType::device_may_send`, and the
    /// receive-side half of W-32's ruling: direction belongs on both sides.
    /// `BOUND`, `DRAIN`, `RELAY_STATUS`, `PONG`, `HANDSHAKE_RESP` and
    /// `COOKIE_CHALLENGE` are relay-to-device only; a device sending one is
    /// either confused or probing, and either way the relay must not act on it.
    #[must_use]
    pub const fn device_may_send(self) -> bool {
        matches!(
            self,
            FrameType::Data
                | FrameType::Bind
                | FrameType::Ping
                | FrameType::Caps
                | FrameType::Rebind
                | FrameType::HandshakeInit
        )
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
    payload: Verbatim,
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

        // The bound check happens BEFORE the payload is retained, and it is the
        // DERIVED B4 ceiling of `MAX_DATA_PAYLOAD_BYTES`, not a borrowed C4 cap.
        let payload_len = datagram.len() - HEADER_LEN;
        if payload_len > MAX_DATA_PAYLOAD_BYTES {
            return Err(FrameError::Bounds(Reject::CapViolated {
                cap_violated: "relay.data_payload_max_bytes",
                observed: payload_len as u64,
                limit: MAX_DATA_PAYLOAD_BYTES as u64,
            }));
        }
        // `Framing::Opaque` -- size cap only, no record scan (ADR-0003 R7).
        //
        // The `Channel` argument is service-common's OUTER backstop cap family,
        // not the operative bound: `limits.json` has no B4 entry, so `Channel`
        // cannot express 1456 and the two variants available are 1200 (C4, too
        // small to be legal here -- see MAX_DATA_PAYLOAD_BYTES) and 64 KiB. The
        // larger is passed deliberately, because the real bound was already
        // enforced two lines up and a backstop must never be tighter than the
        // rule it backs. Reported as a limits.json gap.
        //
        // ONE MISLEADING CONSEQUENCE, NAMED HERE SO IT DOES NOT MISLEAD: this
        // payload's `Verbatim` renders as `on c1_c2_c7` in a `Debug` line. It is
        // NOT a control-channel value — it is a B4 relay payload whose operative
        // bound is MAX_DATA_PAYLOAD_BYTES. The channel token is an artefact of
        // `limits.json` having no B4 cap family to name.
        let payload =
            Verbatim::from_opaque(datagram.slice(HEADER_LEN..), Channel::ControlAndTelemetry)?;

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
    pub const fn payload(&self) -> &Verbatim {
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

    /// The MAC input for the **outgoing** frame, over the rewritten `flow_id`.
    ///
    /// # Why this exists, and the bug it fixes
    ///
    /// [`RelayFrame::reframe`] rewrites `flow_id` and `counter_low` for the
    /// egress half-flow, so the egress MAC must cover **those** values. Using
    /// [`RelayFrame::mac_input`] for the outgoing tag computes it over the
    /// *ingress* `flow_id` while the wire carries the egress one, and the peer
    /// then cannot verify a single frame.
    ///
    /// That was a real defect here, and it was invisible for as long as
    /// `frame_mac` returned `None`: nothing verified, so nothing disagreed. It
    /// was caught the moment a real MAC met a real socket, by
    /// `loop_udp::tests::a_real_frame_traverses_a_real_relay_between_two_real_sockets`
    /// — which is the argument for having written that test rather than trusting
    /// the unit-level one.
    #[must_use]
    pub fn egress_mac_input(&self, flow_id: u32, counter_full: u64) -> Vec<u8> {
        let payload = self.payload.as_bytes();
        let mut out = Vec::with_capacity(2 + 8 + 4 + payload.len());
        out.push(self.kind.to_wire());
        out.push((self.version << 4) | self.flags);
        out.extend_from_slice(&counter_full.to_be_bytes());
        out.extend_from_slice(&flow_id.to_be_bytes());
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

    /// A WireGuard L-DATA datagram: 4-byte type, 4-byte receiver index, 8-byte
    /// counter, then AEAD ciphertext and tag (ADR-0001 §11).
    fn l_data_datagram(cipher_len: usize) -> Vec<u8> {
        let mut v = vec![4_u8, 0, 0, 0]; // WireGuard message type 4 = DATA
        v.extend_from_slice(&0x1234_5678_u32.to_le_bytes()); // receiver index
        v.extend_from_slice(&7_u64.to_le_bytes()); // counter
        v.extend_from_slice(&vec![0xC3; cipher_len]); // ciphertext + tag
        v
    }

    #[test]
    fn the_two_framings_disagree_which_is_the_whole_finding() {
        // The pair, asserted together, because the pair IS the finding: protobuf
        // framing refuses a ciphertext leg, opaque framing carries it. Keeping
        // both halves in one test means neither can drift out from under the
        // other, and it records WHY `from_opaque` had to exist.
        let l_data = l_data_datagram(64);

        // ProtobufRecords: `depth::check` is a record scan, and ciphertext is not
        // a record sequence. Correct behaviour, wrong framing for this consumer.
        let as_protobuf =
            Verbatim::from_received(Bytes::from(l_data.clone()), Channel::PeerDatagram);
        assert!(
            as_protobuf.is_err(),
            "if protobuf framing ever accepts ciphertext, a parser is on the B4 \
             packet path and ADR-0003 R7 is being violated silently"
        );

        // Opaque: size cap only. No record scan, no depth check, no framework.
        let as_opaque = Verbatim::from_opaque(Bytes::from(l_data.clone()), Channel::PeerDatagram)
            .expect("ciphertext is carriable under Framing::Opaque");
        assert_eq!(as_opaque.as_bytes(), &l_data[..]);
        assert_eq!(
            as_opaque.framing(),
            twinvpn_service_common::forward::Framing::Opaque
        );
        assert!(!as_opaque.framing().checks_depth());
    }

    #[test]
    fn the_payload_bound_is_derived_from_adr_0005_9_2_not_borrowed_from_c4() {
        // 1500 (Ethernet) - 20 (IPv4) - 8 (UDP) - 16 (RelayFrame) = 1456, which
        // is §9.2's R-UDP/v4 row read the other way: 1424 overlay MTU + 32 L-DATA.
        assert_eq!(MAX_DATA_PAYLOAD_BYTES, 1500 - 20 - 8 - HEADER_LEN);
        assert_eq!(MAX_DATA_PAYLOAD_BYTES, 1424 + L_DATA_OVERHEAD_BYTES);

        // Every other §9.2 row is smaller, so the v4 R-UDP row binds. Overlay
        // MTUs from §9.2's table, plus the 32 B L-DATA overhead.
        for (carriage, overlay_mtu) in [
            ("R-UDP v6", 1404_usize),
            ("R-QUIC v4", 1396),
            ("R-QUIC v6", 1376),
            ("R-TLS v4", 1388),
            ("R-TLS v6", 1368),
        ] {
            assert!(
                overlay_mtu + L_DATA_OVERHEAD_BYTES <= MAX_DATA_PAYLOAD_BYTES,
                "{carriage} needs more than the derived ceiling"
            );
        }

        // And the number it replaced was not merely loose, it was ILLEGAL.
        assert!(
            Channel::PeerDatagram.max_bytes() < OVERLAY_MTU_FLOOR + L_DATA_OVERHEAD_BYTES,
            "C4's 1200 B cap cannot carry the 1280 overlay floor ADR-0005 C7 fixes"
        );
    }

    #[test]
    fn the_bound_clears_the_1280_overlay_floor() {
        // ADR-0005 C7 / networking §6.2: the 1280 floor always holds. The
        // smallest payload a conforming relay must carry is 1280 + 32 = 1312.
        let required = OVERLAY_MTU_FLOOR + L_DATA_OVERHEAD_BYTES;
        assert_eq!(required, 1_312);
        assert!(MAX_DATA_PAYLOAD_BYTES >= required);
        assert_eq!(MAX_DATA_PAYLOAD_BYTES - required, 144, "margin, in bytes");

        // Behaviourally: a datagram carrying a floor-sized overlay packet parses.
        let f = RelayFrame::parse(datagram(0x01, 0x10, 1, 42, &l_data_datagram(required - 16)))
            .expect("a 1280-byte overlay packet must traverse the relay");
        assert_eq!(f.payload().len(), required);
    }

    #[test]
    fn an_oversized_payload_is_refused_against_the_derived_bound() {
        let over = vec![0_u8; MAX_DATA_PAYLOAD_BYTES + 1];
        let e = RelayFrame::parse(datagram(0x01, 0x10, 1, 42, &over)).unwrap_err();
        match e {
            FrameError::Bounds(Reject::CapViolated {
                cap_violated,
                observed,
                limit,
            }) => {
                assert_eq!(cap_violated, "relay.data_payload_max_bytes");
                assert_eq!(observed as usize, MAX_DATA_PAYLOAD_BYTES + 1);
                assert_eq!(limit as usize, MAX_DATA_PAYLOAD_BYTES);
            }
            other => panic!("expected a typed cap violation, got {other:?}"),
        }

        // Exactly at the bound it is accepted -- never a truncation, never a pad.
        let at = vec![0_u8; MAX_DATA_PAYLOAD_BYTES];
        assert!(RelayFrame::parse(datagram(0x01, 0x10, 1, 42, &at)).is_ok());
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
