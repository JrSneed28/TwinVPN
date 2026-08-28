//! The C6 relay wire encodings, derived **independently** of the relay server.
//!
//! **Authority:** ADR-0005 §9.1 (the 16-byte header and the `0x10..0x1F`
//! control range), §11.1 (the `pair_tag` rendezvous and the bucket),
//! §11.3 (the `RelayCapabilityToken` presentation), §11.5 (the cookie
//! challenge); `contracts/proto/twinvpn/v1/relay.proto` for every *meaning*;
//! `contracts/registry/limits.json` for every *width*.
//!
//! # This module is a second implementation on purpose, and only here
//!
//! `services/relay/src/control.rs` records its body encodings as **proposed,
//! not frozen** — ADR-0005 assigns the control type bytes and specifies no
//! body, and ADR-0003 R7 keeps B4 free of a serialization framework, so there
//! is no schema artifact to generate from. The relay's own integration harness
//! then re-derives the wire from the relay's public constants and says what
//! that costs: it "assert\[s\] *self-consistency*, not interoperability".
//!
//! So this module reads the same two authorities and encodes them again. The
//! duplication is the instrument: when `twinsim` binds a real relay, the fact
//! that two independently written encoders agree is evidence about the wire.
//! Importing `twinvpn_relay::control` here would delete that evidence and leave
//! the code looking identical.
//!
//! **The exception is cryptography.** ADR-0018 CD-I2 forbids a second
//! implementation and means it: `Noise_IK`, the keyed-BLAKE2s frame MAC, HKDF
//! and COSE all come from `twinvpn-crypto`. Nothing in this file computes a
//! cryptographic value; it only lays out octets around one.

/// The wire header length. ADR-0005 §9.1.
pub const HEADER_LEN: usize = 16;

/// The protocol version this build speaks, in the `ver` nibble.
pub const VERSION: u8 = 1;

/// `flags` bit 0 — this `HANDSHAKE_INIT` carries a cookie in front of the
/// Noise message. ADR-0005 §11.5.
pub const FLAG_CARRIES_COOKIE: u8 = 0x01;

/// The stateless cookie's exact width, ADR-0005 §11.5.
pub const COOKIE_BYTES: usize = 16;

/// The `RelayCapabilityToken` presentation envelope version.
pub const PRESENTATION_VERSION: u8 = 1;

/// The presentation's fixed prefix: version, id length, two reserved octets.
pub const PRESENTATION_PREFIX_BYTES: usize = 1 + 1 + 2;

/// The longest issuer key id a presentation may carry.
pub const MAX_ISSUER_KEY_ID_BYTES: usize = 64;

/// The largest `DATA` payload a leg carries. ADR-0005 §9.1, derived from the
/// path MTU rather than from the C4 signalling cap — see the relay's
/// `MAX_DATA_PAYLOAD_BYTES`, which this must equal.
pub const MAX_DATA_PAYLOAD_BYTES: usize = 1_456;

/// The `pair_tag` rotation bucket, ADR-0005 §11.1(3).
pub const BUCKET_SECONDS: u64 = 600;

// ===========================================================================
// frame types
// ===========================================================================

/// The frame types a device sends or receives. ADR-0005 §9.1.
///
/// The three handshake types (`0x18`, `0x19`, `0x1A`) are the relay domain's
/// allocation inside §9.1's reserved control range, recorded there as a
/// proposal to ADR-0005's owner. They are reproduced rather than re-decided:
/// disagreeing with the running relay about a type byte would be a lab that
/// cannot connect, not a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// `0x01` — an opaque L-DATA datagram to forward.
    Data = 0x01,
    /// `0x10` — a device asking to join a `pair_tag`.
    Bind = 0x10,
    /// `0x11` — the relay confirming a bound flow.
    Bound = 0x11,
    /// `0x12` — leg liveness.
    Ping = 0x12,
    /// `0x13`.
    Pong = 0x13,
    /// `0x14` — the relay asking a device to leave, with a deadline.
    Drain = 0x14,
    /// `0x15` — overload, shedding or drain, never silent loss.
    RelayStatus = 0x15,
    /// `0x16` — version and capability negotiation at leg setup.
    Caps = 0x16,
    /// `0x17`.
    Rebind = 0x17,
    /// `0x18` — `Noise_IK` message 1, carrying the `RelayCapabilityToken`.
    HandshakeInit = 0x18,
    /// `0x19` — `Noise_IK` message 2.
    HandshakeResp = 0x19,
    /// `0x1A` — the stateless cookie challenge.
    CookieChallenge = 0x1A,
}

impl FrameType {
    /// The wire byte.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        self as u8
    }

    /// Decodes a wire byte. `None` is a silent drop, never an error frame:
    /// ADR-0014 makes an unknown *type* a drop, not a forward-compatible
    /// extension point the way a reserved *bit* is.
    #[must_use]
    pub const fn from_wire(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Data),
            0x10 => Some(Self::Bind),
            0x11 => Some(Self::Bound),
            0x12 => Some(Self::Ping),
            0x13 => Some(Self::Pong),
            0x14 => Some(Self::Drain),
            0x15 => Some(Self::RelayStatus),
            0x16 => Some(Self::Caps),
            0x17 => Some(Self::Rebind),
            0x18 => Some(Self::HandshakeInit),
            0x19 => Some(Self::HandshakeResp),
            0x1A => Some(Self::CookieChallenge),
            _ => None,
        }
    }

    /// A readable name for a log line and a metric label.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Data => "DATA",
            Self::Bind => "BIND",
            Self::Bound => "BOUND",
            Self::Ping => "PING",
            Self::Pong => "PONG",
            Self::Drain => "DRAIN",
            Self::RelayStatus => "RELAY_STATUS",
            Self::Caps => "CAPS",
            Self::Rebind => "REBIND",
            Self::HandshakeInit => "HANDSHAKE_INIT",
            Self::HandshakeResp => "HANDSHAKE_RESP",
            Self::CookieChallenge => "COOKIE_CHALLENGE",
        }
    }
}

// ===========================================================================
// framing
// ===========================================================================

/// The MAC input, in ADR-0005 §9.1's field order:
/// `type ‖ ver|flags ‖ counter_full ‖ flow_id ‖ payload`.
///
/// `counter_full` and not `counter_low`: the wire carries 16 bits and the MAC
/// covers all 64 (RFC 9147 §4.2.2 reconstruction), which is what stops a
/// wrapped counter from replaying.
#[must_use]
pub fn mac_input(
    kind: FrameType,
    flags: u8,
    flow_id: u32,
    counter_full: u64,
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 8 + 4 + body.len());
    out.push(kind.to_wire());
    out.push((VERSION << 4) | flags);
    out.extend_from_slice(&counter_full.to_be_bytes());
    out.extend_from_slice(&flow_id.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Assembles a complete datagram.
///
/// `tag` is a parameter because only the caller holds `K_leg`, and a caller
/// with no MAC must not send at all.
#[must_use]
pub fn encode_frame(
    kind: FrameType,
    flags: u8,
    flow_id: u32,
    counter_low: u16,
    tag: [u8; 8],
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.push(kind.to_wire());
    out.push((VERSION << 4) | flags);
    out.extend_from_slice(&counter_low.to_be_bytes());
    out.extend_from_slice(&flow_id.to_be_bytes());
    out.extend_from_slice(&tag);
    out.extend_from_slice(body);
    out
}

/// A parsed header. Nothing here is trusted: the MAC has not been checked yet,
/// and `payload` is returned as a slice so no copy is made for a frame that is
/// about to be dropped.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    /// The frame type, `None` for a type this build does not know.
    pub kind: Option<FrameType>,
    /// The `flags` nibble.
    pub flags: u8,
    /// The version nibble.
    pub version: u8,
    /// The low 16 bits of the sender's counter.
    pub counter_low: u16,
    /// The relay-assigned flow handle.
    pub flow_id: u32,
    /// The truncated MAC.
    pub tag: [u8; 8],
}

/// Parses a datagram's header.
///
/// Refuses anything shorter than the header **before** it indexes —
/// `ownership.md` §6 rule 9, on a surface any source address can reach.
#[must_use]
pub fn parse_header(datagram: &[u8]) -> Option<Header> {
    if datagram.len() < HEADER_LEN {
        return None;
    }
    let mut tag = [0_u8; 8];
    tag.copy_from_slice(&datagram[8..16]);
    Some(Header {
        kind: FrameType::from_wire(datagram[0]),
        version: datagram[1] >> 4,
        flags: datagram[1] & 0x0F,
        counter_low: u16::from_be_bytes([datagram[2], datagram[3]]),
        flow_id: u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]),
        tag,
    })
}

/// The body of a datagram whose header parsed.
#[must_use]
pub fn body(datagram: &[u8]) -> &[u8] {
    if datagram.len() < HEADER_LEN {
        &[]
    } else {
        &datagram[HEADER_LEN..]
    }
}

/// The 10-minute bucket a wall-clock second falls in. ADR-0005 §11.1(3).
#[must_use]
pub const fn bucket_for(seconds_since_epoch: u64) -> u64 {
    seconds_since_epoch / BUCKET_SECONDS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_is_sixteen_octets_and_the_body_starts_after_it() {
        let d = encode_frame(FrameType::Bind, 0, 7, 3, [0xAA; 8], b"body");
        assert_eq!(d.len(), HEADER_LEN + 4);
        assert_eq!(d[0], 0x10);
        assert_eq!(d[1], VERSION << 4);
        assert_eq!(&d[2..4], &3_u16.to_be_bytes());
        assert_eq!(&d[4..8], &7_u32.to_be_bytes());
        assert_eq!(body(&d), b"body");
    }

    #[test]
    fn a_short_datagram_is_refused_before_it_is_indexed() {
        for len in 0..HEADER_LEN {
            assert!(parse_header(&vec![0_u8; len]).is_none(), "len {len}");
        }
        assert!(parse_header(&[0_u8; HEADER_LEN]).is_some());
    }

    #[test]
    fn the_mac_covers_the_full_counter_not_the_wire_one() {
        // The whole point of RFC 9147 reconstruction: two frames whose
        // `counter_low` collide must not have the same MAC input.
        let a = mac_input(FrameType::Data, 0, 1, 1, b"x");
        let b = mac_input(FrameType::Data, 0, 1, 1 + (1 << 16), b"x");
        assert_ne!(a, b);
    }

    #[test]
    fn every_frame_type_round_trips_its_wire_byte() {
        for t in [
            FrameType::Data,
            FrameType::Bind,
            FrameType::Bound,
            FrameType::Ping,
            FrameType::Pong,
            FrameType::Drain,
            FrameType::RelayStatus,
            FrameType::Caps,
            FrameType::Rebind,
            FrameType::HandshakeInit,
            FrameType::HandshakeResp,
            FrameType::CookieChallenge,
        ] {
            assert_eq!(FrameType::from_wire(t.to_wire()), Some(t), "{}", t.name());
        }
        // 0x00 and 0x1F are inside no assignment; both are drops.
        assert!(FrameType::from_wire(0x00).is_none());
        assert!(FrameType::from_wire(0x1F).is_none());
    }
}
