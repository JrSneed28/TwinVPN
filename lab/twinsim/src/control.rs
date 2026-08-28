//! The relay control-frame bodies: the token presentation, `BIND` and `BOUND`.
//!
//! **Authority:** ADR-0005 §11.1 (the `pair_tag` rendezvous and its bucket),
//! §11.3 (the `RelayCapabilityToken` presentation);
//! `contracts/proto/twinvpn/v1/relay.proto` for every *meaning*;
//! `contracts/registry/limits.json` for `PAIR_TAG_BYTES`.
//!
//! Written independently of `twinvpn_relay::{control, admit}` — see
//! [`crate::wire`] for why that duplication is the instrument rather than an
//! oversight. Every width here is a fixed-width prefix, and every decoder
//! refuses a short buffer *before* it indexes.
//!
//! Not to be confused with [`crate::lcontrol`], which is L-CONTROL: the
//! device-to-control-plane channel. This module is the relay leg's C6 control
//! frames and shares nothing with it but the word.

use twinvpn_schema::limits::PAIR_TAG_BYTES;

use crate::wire::{MAX_ISSUER_KEY_ID_BYTES, PRESENTATION_PREFIX_BYTES, PRESENTATION_VERSION};

/// The fixed width of a `BIND`/`REBIND` body.
pub const BIND_BODY_BYTES: usize = PAIR_TAG_BYTES + 8 + 1 + 1 + 2;

/// The fixed width of a `BOUND` body.
pub const BOUND_BODY_BYTES: usize = 1 + 3 + 4;

/// Which carriage a leg runs on. ADR-0005 §9.1's four carriages, of which this
/// simulator drives one — `R-UDP`. The other three are the same frames over a
/// different transport, and a simulator that claimed to exercise them without
/// terminating QUIC or TLS would be the "flag inside the product" that
/// `docs/testing-strategy.md` §3.1 forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carriage {
    /// `R-UDP`.
    Udp,
    /// `R-QUIC`.
    Quic,
    /// `R-TLS`.
    Tls,
}

impl Carriage {
    /// The wire byte.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Udp => 1,
            Self::Quic => 2,
            Self::Tls => 3,
        }
    }
}

/// Which address family a half-flow believes it is on.
///
/// **Advisory.** ADR-0005: the relay uses the socket's own family wherever the
/// answer matters, because a device behind NAT64 can be wrong about its own and
/// the socket cannot. A simulator that "fixed" a disagreement here would be
/// hiding exactly the NAT64 case the lab exists to produce.
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
            Self::V4 => 1,
            Self::V6 => 2,
        }
    }

    /// The family a socket address is actually on.
    #[must_use]
    pub const fn of(addr: std::net::SocketAddr) -> Self {
        match addr {
            std::net::SocketAddr::V4(_) => Self::V4,
            std::net::SocketAddr::V6(_) => Self::V6,
        }
    }
}

// ===========================================================================
// the token presentation
// ===========================================================================

/// A `RelayCapabilityToken` as it travels inside `Noise_IK` message 1.
///
/// `issuer_key_id` is a **key-selection hint and nothing else**: naming the
/// wrong key can only cause a refusal, because the signature is then checked
/// under the key that was named (ADR-0005 §11.3).
#[derive(Debug, Clone)]
pub struct TokenPresentation {
    /// The `iss` the bearer claims.
    pub issuer_key_id: String,
    /// The COSE_Sign1 envelope, verbatim.
    pub cose_sign1: Vec<u8>,
}

impl TokenPresentation {
    /// The payload octets.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let id = self.issuer_key_id.as_bytes();
        let id_len = id.len().min(MAX_ISSUER_KEY_ID_BYTES);
        let mut out =
            Vec::with_capacity(PRESENTATION_PREFIX_BYTES + id_len + self.cose_sign1.len());
        out.push(PRESENTATION_VERSION);
        out.push(u8::try_from(id_len).unwrap_or(0));
        out.extend_from_slice(&0_u16.to_be_bytes()); // reserved: zero on send
        out.extend_from_slice(&id[..id_len]);
        out.extend_from_slice(&self.cose_sign1);
        out
    }
}

// ===========================================================================
// BIND / BOUND
// ===========================================================================

/// The `BIND` body. Four fields, and the absence of a peer identifier is the
/// security property, not an omission: the relay "never learns which two
/// devices are talking beyond what forwarding requires".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindBody {
    /// The blinded join key. Scoped to one relay and one bucket, and useless
    /// at another relay or in another bucket.
    pub pair_tag: [u8; PAIR_TAG_BYTES],
    /// The 10-minute bucket the tag was derived for.
    pub bucket: u64,
    /// Which carriage the leg runs on.
    pub carriage: Carriage,
    /// Which family this half-flow believes it is on.
    pub family: Family,
}

impl BindBody {
    /// The body octets.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BIND_BODY_BYTES);
        out.extend_from_slice(&self.pair_tag);
        out.extend_from_slice(&self.bucket.to_be_bytes());
        out.push(self.carriage.to_wire());
        out.push(self.family.to_wire());
        out.extend_from_slice(&0_u16.to_be_bytes()); // reserved: zero on send
        out
    }
}

/// What a `BOUND` answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundState {
    /// A pending slot exists; the partner has `pending_ttl_ms` to arrive.
    Pending,
    /// Both half-flows are present and the flow is usable.
    Bound,
}

/// A decoded `BOUND` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundBody {
    /// Pending or bound.
    pub state: BoundState,
    /// The pending-slot lifetime **the relay reports**, so a re-`BIND` is
    /// scheduled from the relay's number rather than a compiled-in copy.
    pub pending_ttl_ms: u32,
}

impl BoundBody {
    /// Decodes a body.
    ///
    /// Reserved octets are **ignored on receive** (ADR-0014 forward
    /// compatibility): refusing them would make a later, compatible relay
    /// undiagnosable from the device side.
    #[must_use]
    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() < BOUND_BODY_BYTES {
            return None;
        }
        let state = match body[0] {
            0 => BoundState::Pending,
            1 => BoundState::Bound,
            _ => return None,
        };
        let mut ttl = [0_u8; 4];
        ttl.copy_from_slice(&body[4..8]);
        Some(Self {
            state,
            pending_ttl_ms: u32::from_be_bytes(ttl),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bind_body_is_fixed_width_and_carries_no_peer_identifier() {
        let encoded = BindBody {
            pair_tag: [0xAB; PAIR_TAG_BYTES],
            bucket: 12_345,
            carriage: Carriage::Udp,
            family: Family::V6,
        }
        .encode();
        assert_eq!(encoded.len(), BIND_BODY_BYTES);
        assert_eq!(&encoded[..PAIR_TAG_BYTES], &[0xAB; PAIR_TAG_BYTES]);
        assert_eq!(encoded[PAIR_TAG_BYTES + 8], 1); // R-UDP
        assert_eq!(encoded[PAIR_TAG_BYTES + 9], 2); // v6
        assert_eq!(&encoded[PAIR_TAG_BYTES + 10..], &[0, 0]); // reserved, zero on send
    }

    #[test]
    fn a_bound_body_round_trips_the_relays_own_ttl() {
        let mut raw = vec![1_u8, 0, 0, 0];
        raw.extend_from_slice(&30_000_u32.to_be_bytes());
        let b = BoundBody::decode(&raw).expect("decodes");
        assert_eq!(b.state, BoundState::Bound);
        assert_eq!(b.pending_ttl_ms, 30_000);
        // Short bodies are refused rather than zero-filled.
        assert!(BoundBody::decode(&raw[..BOUND_BODY_BYTES - 1]).is_none());
    }

    #[test]
    fn a_presentation_declares_its_own_id_length() {
        let p = TokenPresentation {
            issuer_key_id: "dev-issuer".into(),
            cose_sign1: vec![0xD2, 0x84],
        };
        let e = p.encode();
        assert_eq!(e[0], PRESENTATION_VERSION);
        assert_eq!(usize::from(e[1]), "dev-issuer".len());
        assert_eq!(&e[2..4], &[0, 0]);
        assert_eq!(
            &e[PRESENTATION_PREFIX_BYTES..PRESENTATION_PREFIX_BYTES + 10],
            b"dev-issuer"
        );
    }

    #[test]
    fn an_over_long_issuer_key_id_is_truncated_rather_than_overflowing_its_length_byte() {
        // The length is ONE octet. An id longer than the cap must be clamped
        // before it is written, or the declared length wraps and the decoder
        // reads the signature as part of the id.
        let p = TokenPresentation {
            issuer_key_id: "x".repeat(MAX_ISSUER_KEY_ID_BYTES + 40),
            cose_sign1: vec![0xD2],
        };
        let e = p.encode();
        assert_eq!(usize::from(e[1]), MAX_ISSUER_KEY_ID_BYTES);
        assert_eq!(
            e.len(),
            PRESENTATION_PREFIX_BYTES + MAX_ISSUER_KEY_ID_BYTES + 1
        );
    }
}
