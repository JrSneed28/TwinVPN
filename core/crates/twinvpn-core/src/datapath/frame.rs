//! The L-DATA datagram: its 16-byte header, and the buffer budget the MTU
//! fixes.
//!
//! **Authority:** ADR-0001 §7.2 and §11 (L-DATA is **unmodified WireGuard**;
//! the transport-data message carries a type, a receiver index and the 64-bit
//! counter that is the AEAD nonce); `docs/networking.md` §6.1, whose MTU
//! accounting is stated as *"the WireGuard-shaped **32 bytes** (16 B data
//! header + 16 B AEAD tag)"*, and §6.2 (the 1280 floor);
//! `docs/implementation/ownership.md` §6 rules 9 and 10.
//!
//! # The header is the framing the MTU table already assumed
//!
//! `twinvpn-tunnel` deliberately owns no framing: `Tunnel::seal` returns the
//! counter and `Tunnel::open` demands one, because ADR-0001 §7.2's composition
//! rule forbids L-DATA to depend on how it is carried, and
//! `twinvpn_tunnel::bind` records that split explicitly. Something still has to
//! put the counter on the wire, and this is that something — the smallest
//! possible amount of it, sized to the 16 bytes `networking.md` §6.1 already
//! charges every packet.
//!
//! # Every bound comes from the interface, not from the peer
//!
//! [`Budget`] is derived from the **overlay MTU** — a number the core chose and
//! programmed onto the interface — and the fixed overhead. A peer's declared
//! length is never an input to an allocation; it is only ever compared against
//! a capacity that already exists. That is §6 rule 10 expressed as a type: the
//! only constructor takes an MTU, and it can refuse.

use crate::datapath::outcome::{Refused, Reject};

/// The WireGuard transport-data message type (ADR-0001 §7.2, "unmodified").
pub const TYPE_TRANSPORT_DATA: u8 = 4;

/// The L-DATA data header, in bytes: type, three reserved, receiver index,
/// counter.
pub const HEADER_BYTES: usize = 16;

/// The ChaCha20-Poly1305 tag width.
pub const TAG_BYTES: usize = 16;

/// Per-packet L-DATA overhead: `networking.md` §6.1's 32 bytes.
pub const OVERHEAD_BYTES: usize = HEADER_BYTES + TAG_BYTES;

/// The overlay MTU floor: RFC 8200's IPv6 minimum link MTU, which
/// `networking.md` §6.2 adopts as the bring-up value and the floor DPLPMTUD
/// raises from.
pub const OVERLAY_MTU_FLOOR: u32 = 1280;

/// The largest payload a UDP datagram can carry over IPv4: 65535 − 20 − 8.
///
/// The ceiling every buffer here is bounded by, so a wrong or hostile MTU
/// cannot become an arbitrary allocation.
pub const DATAGRAM_CEILING: usize = 65_507;

/// A tunnel's demultiplexing index.
///
/// WireGuard's `receiver_index`: the value a peer stamps on frames addressed to
/// us. It is the transport's, not L-DATA's — `twinvpn_tunnel::engine::Tunnel`
/// carries no such field, and `twinvpn_tunnel::bind` says so — so the pump is
/// told both halves at construction rather than inventing them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReceiverIndex(pub u32);

/// How large every buffer in one pump may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    overlay_mtu: u32,
    plaintext: usize,
}

impl Budget {
    /// Derives a budget from the overlay interface MTU.
    ///
    /// # Errors
    ///
    /// [`Refused::MtuBelowFloor`] below 1280 and [`Refused::MtuAboveCeiling`]
    /// where the MTU plus the 32-byte overhead would not fit in a UDP datagram.
    /// Both are refusals to start, not conditions to clamp: silently clamping
    /// an MTU means the interface and the pump disagree about how large a
    /// packet may be, and the packets in between are lost with no explanation.
    pub const fn new(overlay_mtu: u32) -> Result<Self, Refused> {
        if overlay_mtu < OVERLAY_MTU_FLOOR {
            return Err(Refused::MtuBelowFloor { mtu: overlay_mtu });
        }
        let plaintext = overlay_mtu as usize;
        if plaintext + OVERHEAD_BYTES > DATAGRAM_CEILING {
            return Err(Refused::MtuAboveCeiling { mtu: overlay_mtu });
        }
        Ok(Self {
            overlay_mtu,
            plaintext,
        })
    }

    /// The overlay MTU this budget was derived from.
    #[must_use]
    pub const fn overlay_mtu(self) -> u32 {
        self.overlay_mtu
    }

    /// The largest plaintext IP packet the tunnel carries: the overlay MTU.
    #[must_use]
    pub const fn plaintext_capacity(self) -> usize {
        self.plaintext
    }

    /// The largest sealed record: plaintext plus the AEAD tag.
    #[must_use]
    pub const fn record_capacity(self) -> usize {
        self.plaintext + TAG_BYTES
    }

    /// The largest datagram on the wire: header, record and tag.
    #[must_use]
    pub const fn datagram_capacity(self) -> usize {
        self.plaintext + OVERHEAD_BYTES
    }
}

/// One transport-data frame's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataHeader {
    /// Whose tunnel the frame is addressed to.
    pub receiver: ReceiverIndex,
    /// The counter, which is the AEAD nonce.
    pub counter: u64,
}

impl DataHeader {
    /// Appends the header to `out`.
    ///
    /// Little-endian, because WireGuard is and ADR-0001 §11 says "unmodified".
    pub fn write(self, out: &mut Vec<u8>) {
        out.push(TYPE_TRANSPORT_DATA);
        out.extend_from_slice(&[0u8; 3]);
        out.extend_from_slice(&self.receiver.0.to_le_bytes());
        out.extend_from_slice(&self.counter.to_le_bytes());
    }

    /// Splits a received datagram into its header and its sealed record.
    ///
    /// Every check here runs **before** the AEAD and before any allocation, on
    /// a slice whose length is already bounded by the receive buffer. Nothing
    /// is read from the datagram to size anything.
    ///
    /// # Errors
    ///
    /// [`Reject::Malformed`] if the datagram is too short to hold a header and
    /// a tag, is not a transport-data frame, or has non-zero reserved bytes.
    pub fn parse(datagram: &[u8]) -> Result<(Self, &[u8]), Reject> {
        // A frame must have room for a header AND a tag: a "record" shorter
        // than the tag cannot be one, and checking it here is what stops the
        // arithmetic below from underflowing on attacker-chosen input.
        if datagram.len() < HEADER_BYTES + TAG_BYTES {
            return Err(Reject::Malformed);
        }
        if datagram[0] != TYPE_TRANSPORT_DATA {
            // Not ours. ADR-0001 §7.2 permits a disco message type on the same
            // socket, so this is an ordinary event, not a failure.
            return Err(Reject::Malformed);
        }
        if datagram[1..4] != [0u8; 3] {
            // Reserved means reserved. Accepting non-zero here would make a
            // future use of those bytes unnegotiable.
            return Err(Reject::Malformed);
        }
        let receiver = u32::from_le_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]);
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&datagram[8..HEADER_BYTES]);
        Ok((
            Self {
                receiver: ReceiverIndex(receiver),
                counter: u64::from_le_bytes(counter_bytes),
            },
            &datagram[HEADER_BYTES..],
        ))
    }
}

/// The buffers one pump direction owns.
///
/// Allocated once, from the [`Budget`], and never grown: a step resizes them
/// back to their capacity rather than reallocating, so the steady state does no
/// allocation at all and no untrusted length can drive one.
#[derive(Debug)]
pub struct Buffers {
    /// The plaintext IP packet: read from the TUN, or written to it.
    pub(super) packet: Vec<u8>,
    /// The sealed record. `TransportKeys::seal` and `open` own this buffer —
    /// both clear it — which is why the datagram is assembled separately.
    pub(super) record: Vec<u8>,
    /// The datagram on the wire: header followed by the record.
    pub(super) wire: Vec<u8>,
    budget: Budget,
}

impl Buffers {
    /// Allocates one direction's buffers at their bounds.
    #[must_use]
    pub fn new(budget: Budget) -> Self {
        Self {
            packet: vec![0u8; budget.plaintext_capacity()],
            record: Vec::with_capacity(budget.record_capacity()),
            wire: vec![0u8; budget.datagram_capacity()],
            budget,
        }
    }

    /// The budget these buffers were sized from.
    #[must_use]
    pub const fn budget(&self) -> Budget {
        self.budget
    }

    /// The wire buffer's allocated capacity.
    ///
    /// Exposed so a test can assert that an oversized datagram did **not**
    /// cause a reallocation — "rejected without allocating to its declared
    /// size" is otherwise an unobservable claim.
    #[must_use]
    pub fn wire_capacity(&self) -> usize {
        self.wire.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Budget, DataHeader, ReceiverIndex, DATAGRAM_CEILING, HEADER_BYTES, OVERHEAD_BYTES,
        OVERLAY_MTU_FLOOR, TAG_BYTES, TYPE_TRANSPORT_DATA,
    };
    use crate::datapath::outcome::{Refused, Reject};

    #[test]
    fn the_overhead_is_the_networking_md_accounting() {
        // `networking.md` §6.1: "the WireGuard-shaped 32 bytes (16 B data
        // header + 16 B AEAD tag)". A change here silently invalidates the
        // overlay-MTU table in that document.
        assert_eq!(HEADER_BYTES, 16);
        assert_eq!(TAG_BYTES, 16);
        assert_eq!(OVERHEAD_BYTES, 32);
        // §6.1's IPv6-direct row: 1500 underlay − 40 IP − 8 UDP − 32 = 1420.
        assert_eq!(Budget::new(1420).expect("v6 row").datagram_capacity(), 1452);
    }

    #[test]
    fn a_budget_refuses_below_the_floor_and_above_the_ceiling() {
        assert_eq!(
            Budget::new(OVERLAY_MTU_FLOOR - 1),
            Err(Refused::MtuBelowFloor {
                mtu: OVERLAY_MTU_FLOOR - 1
            })
        );
        assert!(Budget::new(OVERLAY_MTU_FLOOR).is_ok());
        let over = u32::MAX;
        assert_eq!(
            Budget::new(over),
            Err(Refused::MtuAboveCeiling { mtu: over })
        );
        // The boundary itself fits, and one more does not.
        let largest = u32::try_from(DATAGRAM_CEILING - OVERHEAD_BYTES).expect("fits in u32");
        assert!(Budget::new(largest).is_ok());
        assert!(Budget::new(largest + 1).is_err());
    }

    #[test]
    fn a_header_round_trips() {
        let header = DataHeader {
            receiver: ReceiverIndex(0xdead_beef),
            counter: 0x0102_0304_0506_0708,
        };
        let mut out = vec![0xaa; 0];
        header.write(&mut out);
        out.extend_from_slice(&[0u8; TAG_BYTES]);
        let (parsed, record) = DataHeader::parse(&out).expect("parses");
        assert_eq!(parsed, header);
        assert_eq!(record.len(), TAG_BYTES);
        assert_eq!(out[0], TYPE_TRANSPORT_DATA);
    }

    #[test]
    fn a_short_or_foreign_datagram_is_malformed_rather_than_a_panic() {
        // Every one of these is attacker-chosen input; none may index past the
        // end, underflow a length, or reach the AEAD.
        for len in 0..HEADER_BYTES + TAG_BYTES {
            let mut datagram = vec![0u8; len];
            if !datagram.is_empty() {
                datagram[0] = TYPE_TRANSPORT_DATA;
            }
            assert_eq!(
                DataHeader::parse(&datagram),
                Err(Reject::Malformed),
                "{len}"
            );
        }
        let mut wrong_type = vec![0u8; HEADER_BYTES + TAG_BYTES];
        wrong_type[0] = 1;
        assert_eq!(DataHeader::parse(&wrong_type), Err(Reject::Malformed));
        let mut reserved_set = vec![0u8; HEADER_BYTES + TAG_BYTES];
        reserved_set[0] = TYPE_TRANSPORT_DATA;
        reserved_set[2] = 1;
        assert_eq!(DataHeader::parse(&reserved_set), Err(Reject::Malformed));
    }
}
