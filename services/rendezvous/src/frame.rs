//! The B3 wire framing, and the only parser an unauthenticated attacker reaches.
//!
//! **This is the deliverable.** `contracts/docs/trust-boundaries.md` §2:
//! pre-authentication, forwarded blind, reachable by anyone who can send a
//! datagram — *"this is where a parser bug is a remote memory-safety bug."*
//!
//! # The decode-outcome contract (ADR-0003 §11.7 PA-1)
//!
//! Exactly three outcomes exist, and this module produces only these:
//!
//! 1. **Accept**, with the received octets retained unchanged.
//! 2. **Reject**, with a specific `PROTO.*` code — a [`Reject`], never a bare
//!    `bool`, never an untyped error.
//! 3. **Reject-and-no-effect** — [`Frame::parse`] is a pure function of a byte
//!    slice and holds no state to change.
//!
//! There is no fourth outcome. A panic, a hang, or an allocation proportional to
//! a declared length is a P1 defect *regardless of perceived exploitability*.
//! `tests/hostile_input.rs` and `tests/frame_proptest.rs` assert both halves.
//!
//! # Why a fixed-layout header rather than a protobuf envelope
//!
//! No message in the frozen `contracts/` expresses the rendezvous `CALL`
//! envelope. ADR-0002 §11.5 and S-5 require a `CALL` to name its target *by
//! `DeviceId`* — "never to a caller-supplied address", which is the whole
//! anti-reflection control — but `ConnectOffer`, `ConnectAnswer` and
//! `CandidateSet` carry no recipient, and `MessageMetadata` has `sender_id` and
//! no counterpart. That gap is reported to the integration lead
//! (`README.md` §8). Until it is dispositioned, the target is carried in a
//! **fixed-layout binary header**, which is also the shape ADR-0003 §11 B4
//! prefers on a hostile path: no serialization library sits between the socket
//! and the cap check, so the caps are enforced by arithmetic on a slice.
//!
//! The `CALL` **payload** is never parsed here. It is handed to
//! [`twinvpn_service_common::Verbatim`], which applies the C4 byte and depth
//! caps and retains the octets for verbatim forwarding (finding W-4).

use bytes::Bytes;
use twinvpn_schema::{Channel, Reject};
use twinvpn_service_common::Verbatim;

/// Every frame starts with these four bytes. A stream that does not is not
/// this protocol and is refused on its first frame rather than resynchronised —
/// resynchronisation on a hostile stream is a scan primitive.
pub const MAGIC: [u8; 4] = *b"TVR1";

/// The one wire version this build speaks.
pub const WIRE_VERSION: u8 = 1;

/// `magic(4) ‖ version(1) ‖ opcode(1) ‖ body_len(2, big-endian)`.
pub const HEADER_LEN: usize = 8;

/// `limits.json identifiers.device_id_bytes`, taken from the registry this
/// build compiled in rather than restated as a literal.
pub const DEVICE_ID_LEN: usize = twinvpn_schema::limits::DEVICE_ID_BYTES;

/// The largest body any opcode may declare: a `CALL`'s target plus a full C4
/// envelope. Checked **before** the body is read, so an over-long declaration
/// costs one comparison and never an allocation.
pub const MAX_BODY_LEN: usize = DEVICE_ID_LEN + twinvpn_schema::limits::C4_MAX_BYTES;

/// A `device_id`, held as bytes because this service never interprets one.
pub type DeviceId = [u8; DEVICE_ID_LEN];

/// What a frame asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    /// Client → service. Body: `device_id(32)`. Binds this connection as the
    /// target's live delivery path (ADR-0002 §11.5 path \[1\], S-25).
    Attach = 0x01,
    /// Client → service. Body: `target device_id(32) ‖ opaque C4 payload`.
    Call = 0x02,
    /// Service → client. Body: an encoded `twinvpn.v1.ErrorEnvelope`, or empty
    /// for an unqualified success.
    Ack = 0x81,
    /// Service → client. Body: the `CALL` payload, **byte for byte as it
    /// arrived**. No sender field: the blob is Rule-B signed and names its own
    /// signer, so adding one would tell this courier a pairing it does not need.
    Deliver = 0x82,
    /// Service → client. Body: an encoded `twinvpn.v1.Endpoint` — the source
    /// address this service observed (networking.md A6(a), ADR-0004 §7's
    /// reflexive refresh).
    Reflexive = 0x83,
}

impl Opcode {
    /// Decodes a wire opcode.
    ///
    /// # Errors
    ///
    /// [`Reject::CapViolated`] on any value this build does not define. An
    /// unknown opcode is refused rather than skipped: skipping would let an
    /// attacker probe for opcodes a future build might add.
    pub const fn from_wire(v: u8) -> Result<Self, Reject> {
        match v {
            0x01 => Ok(Opcode::Attach),
            0x02 => Ok(Opcode::Call),
            0x81 => Ok(Opcode::Ack),
            0x82 => Ok(Opcode::Deliver),
            0x83 => Ok(Opcode::Reflexive),
            other => Err(Reject::cap("rendezvous.frame.opcode", other as usize, 0x83)),
        }
    }

    /// The wire byte.
    #[must_use]
    pub const fn as_wire(self) -> u8 {
        self as u8
    }
}

/// A parsed ingress frame. The `CALL` variant owns validated, unmodified octets.
#[derive(Debug, Clone)]
pub enum Frame {
    /// Bind this connection to a `device_id`.
    Attach {
        /// The device this connection claims to be.
        device_id: DeviceId,
    },
    /// Forward `payload` to `target`.
    Call {
        /// Who to hand it to. A `DeviceId`, never an address (ADR-0002 S-5).
        target: DeviceId,
        /// The opaque, Rule-B-signed C4 body. Capped and depth-checked; never
        /// decoded by this process.
        payload: Verbatim,
    },
}

/// How many body bytes a header declares, having proved the declaration is
/// within the cap.
///
/// Split out from [`Frame::parse`] so a streaming reader can check the cap
/// **before** it reads or allocates the body — the ordering `ownership.md` §6
/// rule 9 requires and the one a hand-rolled reader gets wrong in its first
/// line.
///
/// # Errors
///
/// [`Reject::Unparseable`] for a short or mis-magicked header or an unknown wire
/// version, [`Reject::CapViolated`] for an unknown opcode,
/// [`Reject::SizeExceeded`] for an over-long declaration.
pub fn parse_header(header: &[u8]) -> Result<(Opcode, usize), Reject> {
    let unparseable = || Reject::Unparseable {
        parser_id: Channel::PeerDatagram.parser_id(),
    };
    if header.len() < HEADER_LEN {
        return Err(unparseable());
    }
    if header[0..4] != MAGIC {
        return Err(unparseable());
    }
    if header[4] != WIRE_VERSION {
        return Err(unparseable());
    }
    let opcode = Opcode::from_wire(header[5])?;
    let declared = usize::from(u16::from_be_bytes([header[6], header[7]]));
    // The cap check precedes every allocation. Note the bound is the *frame*
    // bound; the C4 envelope bound is applied again, separately, to the payload
    // by `Verbatim::from_received`, because the two are different limits and
    // collapsing them would silently widen one of them.
    if declared > MAX_BODY_LEN {
        return Err(Reject::SizeExceeded {
            parser_id: Channel::PeerDatagram.parser_id(),
            observed: declared,
            limit: MAX_BODY_LEN,
        });
    }
    Ok((opcode, declared))
}

impl Frame {
    /// Parses one complete ingress frame from `bytes`.
    ///
    /// Pure: it reads a slice, allocates nothing proportional to a declared
    /// length, and changes no state. A caller that already read a header with
    /// [`parse_header`] may call [`Frame::parse_body`] instead.
    ///
    /// # Errors
    ///
    /// A typed [`Reject`] carrying the `limits.json` key it violated. Never a
    /// truncation, never a pad, never a silent accept.
    pub fn parse(bytes: &[u8]) -> Result<Self, Reject> {
        let (opcode, declared) = parse_header(bytes)?;
        let body = bytes
            .get(HEADER_LEN..HEADER_LEN + declared)
            .ok_or(Reject::Unparseable {
                parser_id: Channel::PeerDatagram.parser_id(),
            })?;
        // Trailing octets are a framing error, not something to ignore: a
        // tolerated tail is a place to smuggle bytes past a length check.
        if bytes.len() != HEADER_LEN + declared {
            return Err(Reject::Unparseable {
                parser_id: Channel::PeerDatagram.parser_id(),
            });
        }
        Self::parse_body(opcode, &Bytes::copy_from_slice(body))
    }

    /// Parses a body whose opcode and length were already validated.
    ///
    /// # Errors
    ///
    /// A typed [`Reject`]; see [`Frame::parse`].
    pub fn parse_body(opcode: Opcode, body: &Bytes) -> Result<Self, Reject> {
        match opcode {
            Opcode::Attach => {
                // Exact length. `trust-boundaries.md` §8: "Identifiers — exact
                // length. A mismatch is PROTO.MALFORMED_MESSAGE — never a
                // truncation, never a pad."
                Reject::check_exact("identifiers.device_id_bytes", body.len(), DEVICE_ID_LEN)?;
                let mut device_id = [0u8; DEVICE_ID_LEN];
                device_id.copy_from_slice(body);
                Ok(Frame::Attach { device_id })
            }
            Opcode::Call => {
                if body.len() <= DEVICE_ID_LEN {
                    // A target with no payload is not a shorter CALL, it is a
                    // malformed one. Forwarding an empty body would make this
                    // service a free per-target wakeup primitive.
                    return Err(Reject::cap(
                        "rendezvous.call.payload_present",
                        body.len(),
                        DEVICE_ID_LEN + 1,
                    ));
                }
                let mut target = [0u8; DEVICE_ID_LEN];
                target.copy_from_slice(&body[..DEVICE_ID_LEN]);
                // `from_received` applies `envelope.c4_max_bytes` (1200) and
                // `envelope.c4_max_depth` (4) to the payload, and retains the
                // octets unchanged. This is the only place a payload is touched,
                // and it is not a decode.
                let payload =
                    Verbatim::from_received(body.slice(DEVICE_ID_LEN..), Channel::PeerDatagram)?;
                Ok(Frame::Call { target, payload })
            }
            // Egress opcodes on an ingress frame are a protocol confusion, not a
            // message to route.
            Opcode::Ack | Opcode::Deliver | Opcode::Reflexive => Err(Reject::cap(
                "rendezvous.frame.ingress_opcode",
                opcode.as_wire() as usize,
                Opcode::Call.as_wire() as usize,
            )),
        }
    }
}

/// Renders an egress frame, declaring the body's true length.
///
/// It does **not** clamp: a body past the cap is a bug in this process, and a
/// silent truncation here would be the "never a truncation" rule broken on the
/// side nobody thinks to test. The length is declared honestly and the caller's
/// own cap check is what keeps it in range.
///
/// # Panics
///
/// If `body` is longer than [`MAX_BODY_LEN`], which only a defect in this
/// process can produce — every ingress path is capped long before here.
#[must_use]
pub fn encode(opcode: Opcode, body: &[u8]) -> Vec<u8> {
    assert!(
        body.len() <= MAX_BODY_LEN,
        "egress body exceeds the frame cap"
    );
    let len = u16::try_from(body.len()).expect("checked against MAX_BODY_LEN above");
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

    use crate::testkit;

    fn call_bytes(target: [u8; 32], payload: &[u8]) -> Vec<u8> {
        testkit::call_frame(target, payload)
    }

    #[test]
    fn a_well_formed_call_round_trips_verbatim() {
        // A one-field protobuf message with a field number this build does not
        // know: exactly the shape W-4 says must survive the hop.
        // field 31, varint 42 — a field number this build has no name for.
        let payload = [0xf8u8, 0x01, 0x2a];
        let bytes = call_bytes([7u8; 32], &payload);
        let Frame::Call { target, payload: v } = Frame::parse(&bytes).unwrap() else {
            panic!("expected a CALL");
        };
        assert_eq!(target, [7u8; 32]);
        assert_eq!(v.as_bytes(), &payload, "the octets must survive unchanged");
    }

    #[test]
    fn an_oversized_declaration_is_refused_before_the_body_is_read() {
        let mut header = Vec::from(MAGIC);
        header.push(WIRE_VERSION);
        header.push(Opcode::Call.as_wire());
        header.extend_from_slice(&u16::MAX.to_be_bytes());
        let err = parse_header(&header).unwrap_err();
        assert!(matches!(err, Reject::SizeExceeded { observed, limit, .. }
            if observed == usize::from(u16::MAX) && limit == MAX_BODY_LEN));
        assert_eq!(err.reason_code().as_str(), "PROTO.SIZE_EXCEEDED");
    }

    #[test]
    fn a_payload_one_byte_past_the_c4_cap_is_refused() {
        // Declared honestly, so the frame cap admits it and the C4 cap is the
        // one that fires — which is the bound this test is about.
        let over = testkit::payload(twinvpn_schema::limits::C4_MAX_BYTES + 1);
        let mut body = [1u8; 32].to_vec();
        body.extend_from_slice(&over);
        let declared = u16::try_from(body.len()).unwrap();
        let bytes = testkit::declared_length_frame(Opcode::Call, declared, &body);
        let err = Frame::parse(&bytes).unwrap_err();
        assert!(matches!(err, Reject::SizeExceeded { .. }), "{err:?}");
        assert_eq!(err.reason_code().as_str(), "PROTO.SIZE_EXCEEDED");
    }

    #[test]
    fn a_payload_past_the_c4_depth_cap_is_refused() {
        let deep = testkit::nested(twinvpn_schema::limits::C4_MAX_DEPTH + 1);
        let err = Frame::parse(&call_bytes([1u8; 32], &deep)).unwrap_err();
        assert_eq!(
            err.reason_code().as_str(),
            "PROTO.DEPTH_EXCEEDED",
            "{err:?}"
        );
    }

    #[test]
    fn an_attach_of_the_wrong_width_is_never_padded_or_truncated() {
        for len in [0usize, 1, 31, 33, 64] {
            let err = Frame::parse(&encode(Opcode::Attach, &vec![7u8; len])).unwrap_err();
            assert_eq!(
                err.reason_code().as_str(),
                "PROTO.MALFORMED_MESSAGE",
                "len {len}"
            );
        }
    }

    #[test]
    fn an_egress_opcode_is_not_routable_ingress() {
        let err = Frame::parse(&encode(Opcode::Deliver, &[7u8; 8])).unwrap_err();
        assert_eq!(err.reason_code().as_str(), "PROTO.MALFORMED_MESSAGE");
    }

    #[test]
    fn a_trailing_octet_is_a_framing_error_not_something_to_ignore() {
        let mut bytes = call_bytes([1u8; 32], &testkit::payload(4));
        bytes.push(0x00);
        assert!(matches!(
            Frame::parse(&bytes),
            Err(Reject::Unparseable { .. })
        ));
    }
}
