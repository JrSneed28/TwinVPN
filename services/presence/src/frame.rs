//! The C1 framing for presence.
//!
//! Presence travels on **C1**, not C4 (`docs/protocol.md` §16 row 13), so the
//! caps that apply are `envelope.c1_c2_c7_max_bytes` (65536) and
//! `c1_c2_c7_max_depth` (8). They are still applied *before* any allocation
//! proportional to a declared length, and a violation is still a typed reject
//! with a `PROTO.*` code (`ownership.md` §6 rule 9).
//!
//! The framing is deliberately the same shape as the rendezvous's, with a wider
//! length field for the wider channel, so an operator reading two tcpdumps is
//! not reading two protocols.

use bytes::Bytes;
use twinvpn_schema::{Channel, Reject};

/// The presence framing's magic.
pub const MAGIC: [u8; 4] = *b"TVP1";

/// The one wire version this build speaks.
pub const WIRE_VERSION: u8 = 1;

/// `magic(4) ‖ version(1) ‖ opcode(1) ‖ body_len(4, big-endian)`.
pub const HEADER_LEN: usize = 10;

/// `limits.json identifiers.device_id_bytes`.
pub const DEVICE_ID_LEN: usize = twinvpn_schema::limits::DEVICE_ID_BYTES;

/// A `device_id`.
pub type DeviceId = [u8; DEVICE_ID_LEN];

/// What a frame asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    /// Client → service. Body: `device_id(32)`. Declares which device this
    /// connection speaks for. S-11's "only for itself" is checked against it.
    Bind = 0x01,
    /// Client → service. Body: a `twinvpn.v1.PublishPresenceRequest`.
    Publish = 0x02,
    /// Client → service. Body: empty. Stream `PresenceUpdated` events.
    Subscribe = 0x03,
    /// Service → client. Body: a `twinvpn.v1.PublishPresenceResponse`.
    Ack = 0x81,
    /// Service → client. Body: a `twinvpn.v1.ControlEvent` carrying
    /// `PresenceUpdated`, `durability = EPHEMERAL`, `net_seq = 0`.
    Event = 0x82,
}

impl Opcode {
    /// Decodes a wire opcode.
    ///
    /// # Errors
    ///
    /// [`Reject::CapViolated`] for any value this build does not define.
    pub const fn from_wire(v: u8) -> Result<Self, Reject> {
        match v {
            0x01 => Ok(Opcode::Bind),
            0x02 => Ok(Opcode::Publish),
            0x03 => Ok(Opcode::Subscribe),
            0x81 => Ok(Opcode::Ack),
            0x82 => Ok(Opcode::Event),
            other => Err(Reject::cap("presence.frame.opcode", other as usize, 0x82)),
        }
    }

    /// The wire byte.
    #[must_use]
    pub const fn as_wire(self) -> u8 {
        self as u8
    }
}

/// A parsed ingress frame.
#[derive(Debug, Clone)]
pub enum Frame {
    /// Declare this connection's device.
    Bind {
        /// The device this connection speaks for.
        device_id: DeviceId,
    },
    /// A heartbeat.
    Publish {
        /// The decoded request. Presence is **consumed**, not forwarded, so
        /// decoding is correct here — the forward-verbatim rule (W-4) applies to
        /// a message a hop carries onward, and this hop carries nothing onward
        /// but its own re-derived `PresenceUpdated`.
        request: Box<twinvpn_schema::v1::PublishPresenceRequest>,
    },
    /// Subscribe to updates.
    Subscribe,
}

/// Reads a header, proving the declared length is within the C1 cap.
///
/// # Errors
///
/// [`Reject::Unparseable`] for a short or mis-magicked header,
/// [`Reject::CapViolated`] for an unknown opcode, [`Reject::SizeExceeded`] for
/// an over-long declaration.
pub fn parse_header(header: &[u8]) -> Result<(Opcode, usize), Reject> {
    let unparseable = || Reject::Unparseable {
        parser_id: Channel::ControlAndTelemetry.parser_id(),
    };
    if header.len() < HEADER_LEN {
        return Err(unparseable());
    }
    if header[0..4] != MAGIC || header[4] != WIRE_VERSION {
        return Err(unparseable());
    }
    let opcode = Opcode::from_wire(header[5])?;
    let declared = u32::from_be_bytes([header[6], header[7], header[8], header[9]]) as usize;
    // The cap check precedes every allocation.
    twinvpn_service_common::transport::check_declared_length(
        declared,
        Channel::ControlAndTelemetry,
    )?;
    Ok((opcode, declared))
}

impl Frame {
    /// Parses one complete ingress frame.
    ///
    /// # Errors
    ///
    /// A typed [`Reject`].
    pub fn parse(bytes: &[u8]) -> Result<Self, Reject> {
        let (opcode, declared) = parse_header(bytes)?;
        if bytes.len() != HEADER_LEN + declared {
            return Err(Reject::Unparseable {
                parser_id: Channel::ControlAndTelemetry.parser_id(),
            });
        }
        Self::parse_body(opcode, &Bytes::copy_from_slice(&bytes[HEADER_LEN..]))
    }

    /// Parses a body whose opcode and length were already validated.
    ///
    /// # Errors
    ///
    /// A typed [`Reject`]. The depth guard runs over the raw octets **before**
    /// `prost` sees them, because depth is a stack-exhaustion vector `prost`
    /// does not bound.
    pub fn parse_body(opcode: Opcode, body: &Bytes) -> Result<Self, Reject> {
        match opcode {
            Opcode::Bind => {
                Reject::check_exact("identifiers.device_id_bytes", body.len(), DEVICE_ID_LEN)?;
                let mut device_id = [0u8; DEVICE_ID_LEN];
                device_id.copy_from_slice(body);
                Ok(Frame::Bind { device_id })
            }
            Opcode::Publish => {
                let request: twinvpn_schema::v1::PublishPresenceRequest =
                    twinvpn_schema::validate::decode(body, Channel::ControlAndTelemetry)?;
                Ok(Frame::Publish {
                    request: Box::new(request),
                })
            }
            Opcode::Subscribe => {
                Reject::check_exact("presence.subscribe.empty_body", body.len(), 0)?;
                Ok(Frame::Subscribe)
            }
            Opcode::Ack | Opcode::Event => Err(Reject::cap(
                "presence.frame.ingress_opcode",
                opcode.as_wire() as usize,
                Opcode::Subscribe.as_wire() as usize,
            )),
        }
    }
}

/// Renders an egress frame.
///
/// # Panics
///
/// If `body` exceeds the C1 envelope cap, which only a defect in this process
/// can produce.
#[must_use]
pub fn encode(opcode: Opcode, body: &[u8]) -> Vec<u8> {
    assert!(
        body.len() <= twinvpn_schema::limits::C1_C2_C7_MAX_BYTES,
        "egress body exceeds the C1 envelope cap"
    );
    let len = u32::try_from(body.len()).expect("checked above");
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&MAGIC);
    out.push(WIRE_VERSION);
    out.push(opcode.as_wire());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_declaration_past_the_c1_cap_is_refused_before_the_body_is_read() {
        let mut header = Vec::from(MAGIC);
        header.push(WIRE_VERSION);
        header.push(Opcode::Publish.as_wire());
        header.extend_from_slice(&u32::MAX.to_be_bytes());
        let err = parse_header(&header).unwrap_err();
        assert_eq!(err.reason_code().as_str(), "PROTO.SIZE_EXCEEDED");
    }

    #[test]
    fn a_bind_of_the_wrong_width_is_never_padded_or_truncated() {
        for len in [0usize, 31, 33] {
            let err = Frame::parse(&encode(Opcode::Bind, &vec![1u8; len])).unwrap_err();
            assert_eq!(err.reason_code().as_str(), "PROTO.MALFORMED_MESSAGE");
        }
    }

    #[test]
    fn an_egress_opcode_is_not_routable_ingress() {
        let err = Frame::parse(&encode(Opcode::Event, &[])).unwrap_err();
        assert_eq!(err.reason_code().as_str(), "PROTO.MALFORMED_MESSAGE");
    }

    #[test]
    fn a_publish_nested_past_the_c1_depth_cap_is_refused() {
        let deep = crate::testkit::nested(twinvpn_schema::limits::C1_C2_C7_MAX_DEPTH + 1);
        let err = Frame::parse(&encode(Opcode::Publish, &deep)).unwrap_err();
        assert_eq!(err.reason_code().as_str(), "PROTO.DEPTH_EXCEEDED");
    }
}
