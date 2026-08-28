//! The control-frame bodies: `BIND`, `BOUND`, `CAPS`, `REBIND`, `DRAIN`.
//!
//! **Authority:** ADR-0005 §9.1 (the header and the control type range), §11.1
//! (the `pair_tag` rendezvous), §10 ("version skew is handled by the `ver`
//! nibble plus a `CAPS` control frame exchanged at leg setup"), ADR-0006 §11.9;
//! `contracts/proto/twinvpn/v1/relay.proto` for every *meaning* below.
//!
//! # These encodings are proposed, not frozen — and that is recorded, not hidden
//!
//! ADR-0005 §9.1 assigns the control **type bytes** and specifies **no body**
//! for any of them, and ADR-0003 R7 keeps B4 free of a serialization framework
//! by design, so there is no schema artifact to generate from.
//! [`crate::status`] already contributes the smallest encoding satisfying §11.5
//! for `RELAY_STATUS` and records it as a proposal; this module does the same for
//! the other five, under the same rule: **the body is versioned by the frame's
//! `ver` nibble, so changing one is an ADR-0014 event.**
//!
//! Every field here exists in `relay.proto` already. Nothing is invented but the
//! octet layout — §6 rule 2 forbids redeclaring a frozen message, and this is a
//! wire encoding for one, not a second definition of it.
//!
//! # Fixed width, and bounded before allocation
//!
//! Each body is a fixed-width prefix plus at most a bounded, length-counted
//! tail. A decoder refuses a short buffer *before* it indexes and refuses a
//! declared count above its ceiling *before* it allocates — `ownership.md` §6
//! rules 9 and 10, on a surface an unauthenticated source can reach on the
//! `BIND` path.

use twinvpn_schema::limits::{PAIR_TAG_BYTES, RELAY_ID_BYTES};

use crate::config::Carriage;
use crate::frame::{FrameType, VERSION};

/// The relay-side wire byte for an address family, matching
/// `common.proto AddressFamily`'s ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

impl Family {
    /// The wire byte.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Family::V4 => 1,
            Family::V6 => 2,
        }
    }

    /// Decodes a wire byte.
    #[must_use]
    pub const fn from_wire(v: u8) -> Option<Self> {
        match v {
            1 => Some(Family::V4),
            2 => Some(Family::V6),
            _ => None,
        }
    }

    /// The family a socket address is actually on.
    ///
    /// The relay uses **this**, not the device's claim, wherever the answer
    /// matters: a device may be wrong about its own family behind NAT64, and the
    /// socket cannot be.
    #[must_use]
    pub const fn of(addr: std::net::SocketAddr) -> Self {
        match addr {
            std::net::SocketAddr::V4(_) => Family::V4,
            std::net::SocketAddr::V6(_) => Family::V6,
        }
    }
}

/// Why a control body did not decode. Every variant is a **silent drop**: a
/// malformed control frame gets zero bytes, like every other unauthenticated
/// input (ADR-0005 §11.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BodyError {
    /// Fewer octets than the fixed-width prefix.
    #[error("control body shorter than its fixed prefix")]
    TooShort,
    /// A declared count exceeded its ceiling, or a field held a reserved value.
    #[error("control body field out of range")]
    OutOfRange,
}

// ===========================================================================
// BIND / REBIND
// ===========================================================================

/// `BIND` body — **the whole of what a device tells a relay about its pair**.
///
/// `relay.proto`: "`BindRequest` therefore carries `pair_tag` and no peer
/// identifier of any kind — not a `device_id`, not a key id, not a fingerprint."
/// The field list below *is* that property, and
/// `tests/privacy_and_persistence.rs` asserts nothing else ever joins it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindBody {
    /// The blinded join key: `HKDF-Expand(RelayPairKey, "tag" ‖ relay_id ‖
    /// bucket, 16)`. One-way, scoped to this relay and this bucket.
    pub pair_tag: [u8; PAIR_TAG_BYTES],
    /// The 10-minute bucket the tag was derived for. The relay accepts
    /// `bucket`, `bucket−1` and `bucket+1` (ADR-0005 §11.1(3)).
    pub bucket: u64,
    /// Which carriage the leg runs on.
    pub carriage: Carriage,
    /// Which family the device believes it is on. Advisory — see [`Family::of`].
    pub family: Family,
}

/// The fixed width of a `BIND`/`REBIND` body.
pub const BIND_BODY_BYTES: usize = PAIR_TAG_BYTES + 8 + 1 + 1 + 2;

impl BindBody {
    /// The body octets.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BIND_BODY_BYTES);
        out.extend_from_slice(&self.pair_tag);
        out.extend_from_slice(&self.bucket.to_be_bytes());
        out.push(carriage_to_wire(self.carriage));
        out.push(self.family.to_wire());
        out.extend_from_slice(&0_u16.to_be_bytes()); // reserved: zero on send
        out
    }

    /// Decodes a body.
    ///
    /// # Errors
    ///
    /// [`BodyError`]. The reserved octets are **ignored on receive**, per
    /// ADR-0014 forward compatibility — refusing them would make a later,
    /// compatible sender undiagnosable.
    pub fn decode(body: &[u8]) -> Result<Self, BodyError> {
        if body.len() < BIND_BODY_BYTES {
            return Err(BodyError::TooShort);
        }
        let mut pair_tag = [0_u8; PAIR_TAG_BYTES];
        pair_tag.copy_from_slice(&body[..PAIR_TAG_BYTES]);
        let mut bucket_bytes = [0_u8; 8];
        bucket_bytes.copy_from_slice(&body[PAIR_TAG_BYTES..PAIR_TAG_BYTES + 8]);
        let carriage = carriage_from_wire(body[PAIR_TAG_BYTES + 8]).ok_or(BodyError::OutOfRange)?;
        let family = Family::from_wire(body[PAIR_TAG_BYTES + 9]).ok_or(BodyError::OutOfRange)?;
        Ok(Self {
            pair_tag,
            bucket: u64::from_be_bytes(bucket_bytes),
            carriage,
            family,
        })
    }
}

/// Whether a received bucket is inside the accepted skew.
///
/// Written as two comparisons rather than a subtraction because the bucket is a
/// `u64` and an underflow would silently accept everything — the same reasoning,
/// and the same shape, as `twinvpn_relay_client::bind::bucket_accepted`.
#[must_use]
pub fn bucket_accepted(current: u64, received: u64, skew: u64) -> bool {
    received >= current.saturating_sub(skew) && received <= current.saturating_add(skew)
}

// ===========================================================================
// BOUND
// ===========================================================================

/// What the relay answers a `BIND` with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundState {
    /// A pending slot exists; the partner has 30 s to arrive.
    Pending,
    /// Both half-flows are present and the flow is usable.
    Bound,
}

/// `BOUND` body. The `flow_id` is in the **header**, where every other frame on
/// this flow carries it, so it is not repeated here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundBody {
    /// Pending or bound.
    pub state: BoundState,
    /// The pending-slot lifetime, so a device schedules its re-`BIND` from the
    /// relay's number rather than from a compiled-in copy of it.
    pub pending_ttl_ms: u32,
}

/// The fixed width of a `BOUND` body.
pub const BOUND_BODY_BYTES: usize = 1 + 3 + 4;

impl BoundBody {
    /// The body octets.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BOUND_BODY_BYTES);
        out.push(match self.state {
            BoundState::Pending => 0,
            BoundState::Bound => 1,
        });
        out.extend_from_slice(&[0_u8; 3]); // reserved: zero on send
        out.extend_from_slice(&self.pending_ttl_ms.to_be_bytes());
        out
    }

    /// Decodes a body.
    ///
    /// # Errors
    ///
    /// [`BodyError`].
    pub fn decode(body: &[u8]) -> Result<Self, BodyError> {
        if body.len() < BOUND_BODY_BYTES {
            return Err(BodyError::TooShort);
        }
        let state = match body[0] {
            0 => BoundState::Pending,
            1 => BoundState::Bound,
            _ => return Err(BodyError::OutOfRange),
        };
        let mut ttl = [0_u8; 4];
        ttl.copy_from_slice(&body[4..8]);
        Ok(Self {
            state,
            pending_ttl_ms: u32::from_be_bytes(ttl),
        })
    }
}

// ===========================================================================
// CAPS
// ===========================================================================

/// `relay_standby` — ADR-0014's capability name for holding a warm second leg.
pub const CAP_STANDBY: u16 = 1 << 0;
/// The relay implements `DRAIN`. ADR-0005 §10 requires it of a self-hosted
/// relay and ADR-0006 ranks a relay without it lower.
pub const CAP_DRAIN: u16 = 1 << 1;
/// The relay implements `CAPS` itself. Present so the bitmap is self-describing.
pub const CAP_CAPS: u16 = 1 << 2;
/// The relay implements `REBIND`.
pub const CAP_REBIND: u16 = 1 << 3;

/// `CAPS` body — the version and capability exchange of ADR-0005 §10.
///
/// It is carried **inside the leg handshake payload** as well as in a frame:
/// `Noise_IK` message 2 encrypts it, so a device learns the relay's version and
/// capability set without that set being observable to anyone on path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapsBody {
    /// The lowest `ver` nibble this relay speaks.
    pub version_min: u8,
    /// The highest.
    pub version_max: u8,
    /// The [`CAP_STANDBY`]-family bitmap.
    pub capabilities: u16,
    /// The largest `DATA` payload this relay will forward, so a device sizes its
    /// L-DATA datagram from the relay's number rather than assuming.
    pub max_data_payload_bytes: u16,
}

/// The fixed width of a `CAPS` body.
pub const CAPS_BODY_BYTES: usize = 1 + 1 + 2 + 2 + 2;

impl CapsBody {
    /// What this build offers.
    #[must_use]
    pub const fn of_this_build() -> Self {
        Self {
            version_min: VERSION,
            version_max: VERSION,
            capabilities: CAP_STANDBY | CAP_DRAIN | CAP_CAPS | CAP_REBIND,
            max_data_payload_bytes: crate::frame::MAX_DATA_PAYLOAD_BYTES as u16,
        }
    }

    /// Whether `version` is inside the offered window.
    #[must_use]
    pub const fn speaks(&self, version: u8) -> bool {
        version >= self.version_min && version <= self.version_max
    }

    /// The body octets.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CAPS_BODY_BYTES);
        out.push(self.version_min);
        out.push(self.version_max);
        out.extend_from_slice(&self.capabilities.to_be_bytes());
        out.extend_from_slice(&self.max_data_payload_bytes.to_be_bytes());
        out.extend_from_slice(&0_u16.to_be_bytes()); // reserved: zero on send
        out
    }

    /// Decodes a body.
    ///
    /// # Errors
    ///
    /// [`BodyError`]. An unknown capability **bit** is not an error: ADR-0014
    /// requires unknown capabilities to be ignored, not refused, or a relay
    /// could never gain one without breaking every deployed device.
    pub fn decode(body: &[u8]) -> Result<Self, BodyError> {
        if body.len() < CAPS_BODY_BYTES {
            return Err(BodyError::TooShort);
        }
        if body[0] > body[1] {
            return Err(BodyError::OutOfRange);
        }
        Ok(Self {
            version_min: body[0],
            version_max: body[1],
            capabilities: u16::from_be_bytes([body[2], body[3]]),
            max_data_payload_bytes: u16::from_be_bytes([body[4], body[5]]),
        })
    }
}

// ===========================================================================
// DRAIN
// ===========================================================================

/// The most alternates a `DRAIN` suggests. Three, matching
/// [`crate::status::MAX_SUGGESTED_ALTERNATIVES`], because a device re-ranks
/// against its own verified map anyway and a longer list is a larger
/// unauthenticated-at-parse-time allocation for no gain.
pub const MAX_SUGGESTED_RELAYS: usize = 3;

/// `DRAIN` body — `relay.proto RelayDrain`, minus the two fields the frame
/// already carries (`relay_id` is implied by who sent it, `flow_id` is the
/// header's).
///
/// **A relay can ask a device to leave; it can never redirect a session.**
/// `relay.proto` states that plainly, and the shape here obeys it: the
/// suggestions are relay *ids*, which the device must find in its own verified
/// map before it may bind one. A relay cannot name an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainBody {
    /// How long the flow may persist, in milliseconds from now. Each device
    /// draws its migration instant uniformly in `[0, deadline − 60 s]`.
    pub drain_deadline_ms: u64,
    /// Suggested alternates. A hint, never an instruction.
    pub suggested_relay_ids: Vec<[u8; RELAY_ID_BYTES]>,
}

/// The fixed prefix of a `DRAIN` body, before the suggestion list.
pub const DRAIN_PREFIX_BYTES: usize = 8 + 1 + 3;

impl DrainBody {
    /// The body octets.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let alts =
            &self.suggested_relay_ids[..self.suggested_relay_ids.len().min(MAX_SUGGESTED_RELAYS)];
        let mut out = Vec::with_capacity(DRAIN_PREFIX_BYTES + alts.len() * RELAY_ID_BYTES);
        out.extend_from_slice(&self.drain_deadline_ms.to_be_bytes());
        out.push(u8::try_from(alts.len()).unwrap_or(0));
        out.extend_from_slice(&[0_u8; 3]); // reserved: zero on send
        for id in alts {
            out.extend_from_slice(id);
        }
        out
    }

    /// Decodes a body.
    ///
    /// # Errors
    ///
    /// [`BodyError`]. The declared count is checked against
    /// [`MAX_SUGGESTED_RELAYS`] **and** against the octets actually present
    /// before anything is allocated.
    pub fn decode(body: &[u8]) -> Result<Self, BodyError> {
        if body.len() < DRAIN_PREFIX_BYTES {
            return Err(BodyError::TooShort);
        }
        let mut deadline = [0_u8; 8];
        deadline.copy_from_slice(&body[..8]);
        let count = usize::from(body[8]);
        if count > MAX_SUGGESTED_RELAYS {
            return Err(BodyError::OutOfRange);
        }
        let needed = DRAIN_PREFIX_BYTES + count * RELAY_ID_BYTES;
        if body.len() < needed {
            return Err(BodyError::TooShort);
        }
        let mut ids = Vec::with_capacity(count);
        for i in 0..count {
            let at = DRAIN_PREFIX_BYTES + i * RELAY_ID_BYTES;
            let mut id = [0_u8; RELAY_ID_BYTES];
            id.copy_from_slice(&body[at..at + RELAY_ID_BYTES]);
            ids.push(id);
        }
        Ok(Self {
            drain_deadline_ms: u64::from_be_bytes(deadline),
            suggested_relay_ids: ids,
        })
    }
}

// ===========================================================================
// framing
// ===========================================================================

/// Assembles a complete outgoing control datagram.
///
/// `auth_tag` comes from the caller because only the caller holds `K_leg` — and
/// a caller with no MAC must not send at all, which is [`crate::pump`]'s rule.
#[must_use]
pub fn encode_frame(
    kind: FrameType,
    flow_id: u32,
    counter_low: u16,
    tag: [u8; 8],
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(crate::frame::HEADER_LEN + body.len());
    out.push(kind.to_wire());
    out.push(VERSION << 4);
    out.extend_from_slice(&counter_low.to_be_bytes());
    out.extend_from_slice(&flow_id.to_be_bytes());
    out.extend_from_slice(&tag);
    out.extend_from_slice(body);
    out
}

/// The MAC input for an outgoing control frame, in ADR-0005 §9.1's field order.
///
/// Identical in shape to [`crate::frame::RelayFrame::mac_input`] and deliberately
/// not a second definition of the layout: both assemble
/// `type ‖ ver|flags ‖ counter_full ‖ flow_id ‖ payload`, and
/// `the_control_mac_input_agrees_with_the_frame_one` holds them together.
#[must_use]
pub fn mac_input(kind: FrameType, flow_id: u32, counter_full: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 8 + 4 + body.len());
    out.push(kind.to_wire());
    out.push(VERSION << 4);
    out.extend_from_slice(&counter_full.to_be_bytes());
    out.extend_from_slice(&flow_id.to_be_bytes());
    out.extend_from_slice(body);
    out
}

const fn carriage_to_wire(c: Carriage) -> u8 {
    match c {
        Carriage::Udp => 1,
        Carriage::Quic => 2,
        Carriage::Tls => 3,
    }
}

const fn carriage_from_wire(v: u8) -> Option<Carriage> {
    match v {
        1 => Some(Carriage::Udp),
        2 => Some(Carriage::Quic),
        3 => Some(Carriage::Tls),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bind_body_round_trips_and_carries_no_peer_identifier() {
        let b = BindBody {
            pair_tag: [0xAB; PAIR_TAG_BYTES],
            bucket: 12_345,
            carriage: Carriage::Udp,
            family: Family::V6,
        };
        assert_eq!(BindBody::decode(&b.encode()).expect("decodes"), b);
        // The field set IS the privacy property (A11, protocol.md §16 row 21).
        let rendered = format!("{b:?}");
        for forbidden in ["device_id", "peer_key_id", "identity", "fingerprint"] {
            assert!(!rendered.contains(forbidden));
        }
        assert_eq!(b.encode().len(), BIND_BODY_BYTES);
    }

    #[test]
    fn a_short_or_out_of_range_body_is_refused_before_indexing() {
        for len in 0..BIND_BODY_BYTES {
            assert_eq!(
                BindBody::decode(&vec![0_u8; len]),
                Err(BodyError::TooShort),
                "a {len}-octet BIND body must be refused, not indexed"
            );
        }
        // A reserved carriage byte.
        let mut body = vec![0_u8; BIND_BODY_BYTES];
        body[PAIR_TAG_BYTES + 8] = 9;
        assert_eq!(BindBody::decode(&body), Err(BodyError::OutOfRange));
    }

    #[test]
    fn a_drain_body_bounds_its_suggestion_count_before_allocating() {
        // A declared count above the ceiling is refused without allocating for it.
        let mut body = vec![0_u8; DRAIN_PREFIX_BYTES];
        body[8] = 255;
        assert_eq!(DrainBody::decode(&body), Err(BodyError::OutOfRange));

        // A count inside the ceiling but not backed by octets is TooShort, not a
        // panic and not a partial read.
        let mut body = vec![0_u8; DRAIN_PREFIX_BYTES];
        body[8] = 3;
        assert_eq!(DrainBody::decode(&body), Err(BodyError::TooShort));

        let d = DrainBody {
            drain_deadline_ms: 120_000,
            suggested_relay_ids: vec![[1; RELAY_ID_BYTES], [2; RELAY_ID_BYTES]],
        };
        assert_eq!(DrainBody::decode(&d.encode()).expect("decodes"), d);
    }

    #[test]
    fn a_drain_encodes_at_most_three_suggestions() {
        let d = DrainBody {
            drain_deadline_ms: 1,
            suggested_relay_ids: vec![[0; RELAY_ID_BYTES]; 10],
        };
        let decoded = DrainBody::decode(&d.encode()).expect("decodes");
        assert_eq!(decoded.suggested_relay_ids.len(), MAX_SUGGESTED_RELAYS);
    }

    #[test]
    fn caps_round_trips_and_an_unknown_capability_bit_is_ignored_not_refused() {
        let c = CapsBody::of_this_build();
        assert_eq!(CapsBody::decode(&c.encode()).expect("decodes"), c);
        assert!(c.speaks(VERSION));
        assert!(!c.speaks(VERSION + 1));

        // ADR-0014: unknown capabilities are ignored, never refused.
        let mut body = c.encode();
        body[2] = 0xFF;
        body[3] = 0xFF;
        assert!(CapsBody::decode(&body).is_ok());

        // But an inverted version window is a defect on the sender's side.
        let mut body = c.encode();
        body[0] = 9;
        body[1] = 1;
        assert_eq!(CapsBody::decode(&body), Err(BodyError::OutOfRange));
    }

    #[test]
    fn a_bound_body_round_trips_both_states() {
        for state in [BoundState::Pending, BoundState::Bound] {
            let b = BoundBody {
                state,
                pending_ttl_ms: 30_000,
            };
            assert_eq!(BoundBody::decode(&b.encode()).expect("decodes"), b);
        }
        assert_eq!(
            BoundBody::decode(&[2, 0, 0, 0, 0, 0, 0, 0]),
            Err(BodyError::OutOfRange)
        );
    }

    #[test]
    fn the_control_mac_input_agrees_with_the_frame_one() {
        // Two assemblers of one layout is exactly the shape that drifts, so they
        // are compared byte for byte rather than trusted to match.
        let body = b"body octets";
        let mine = mac_input(FrameType::Bound, 0x0A0B_0C0D, 0x1122_3344_5566_7788, body);
        let datagram = encode_frame(FrameType::Bound, 0x0A0B_0C0D, 0x7788, [0; 8], body);
        let parsed = crate::frame::RelayFrame::parse(bytes::Bytes::from(datagram)).expect("parses");
        assert_eq!(mine, parsed.mac_input(0x1122_3344_5566_7788));
    }

    #[test]
    fn the_bucket_skew_window_cannot_underflow() {
        // bucket 0 with skew 1 must not accept every possible bucket.
        assert!(bucket_accepted(0, 0, 1));
        assert!(bucket_accepted(0, 1, 1));
        assert!(!bucket_accepted(0, 2, 1));
        assert!(!bucket_accepted(0, u64::MAX, 1));
        assert!(bucket_accepted(10, 9, 1));
        assert!(!bucket_accepted(10, 8, 1));
    }

    #[test]
    fn the_family_of_a_socket_overrides_the_claim() {
        let v4: std::net::SocketAddr = "192.0.2.1:1".parse().expect("v4");
        let v6: std::net::SocketAddr = "[2001:db8::1]:1".parse().expect("v6");
        assert_eq!(Family::of(v4), Family::V4);
        assert_eq!(Family::of(v6), Family::V6);
    }
}
