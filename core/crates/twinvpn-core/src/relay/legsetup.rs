//! The three leg-setup frames, and the token presentation one of them carries.
//!
//! **Authority:** ADR-0005 §9.1 (the `0x10..0x1F` control range), §11.1(2) (the
//! `Noise_IK` leg handshake), §11.3 (the token is verified once, at leg setup),
//! §11.5 (the stateless cookie challenge, and zero bytes in reply to anything
//! unauthenticated); ADR-0014 (reserved bits zero on send, ignored on receive);
//! `services/relay/src/{frame,admit,leg}.rs`, which are the authority for every
//! octet below.
//!
//! # These three are held apart from the rest of the vocabulary on purpose
//!
//! `services/relay/src/frame.rs` allocated `HANDSHAKE_INIT` (`0x18`),
//! `HANDSHAKE_RESP` (`0x19`) and `COOKIE_CHALLENGE` (`0x1A`) inside the control
//! space ADR-0005 §9.1 reserves, and records the allocation as a proposal for
//! that ADR's owner. `twinvpn_relay_client::frame::FrameType` has no variant for
//! any of them.
//!
//! Adding them to that type would be wrong even if this domain owned it. These
//! are the one class of datagram on this socket that legitimately carries **no
//! MAC** — no `K_leg` exists yet — and `FrameType`'s whole contract is "verify
//! before you act". Mixing the two is how an unauthenticated frame comes to be
//! treated as an authenticated one. The relay makes the same separation from
//! the other side, in `FrameType::is_leg_setup`: it branches on this *before* it
//! looks a leg up, so the one datagram class that legitimately has no leg is
//! never confused with the far larger class that has none because it is
//! unauthenticated.
//!
//! # Direction is the only check there is here
//!
//! [`LegSetupType::relay_may_send`] refuses an inbound `HANDSHAKE_INIT`. A relay
//! sending one is asking the device to act as a **relay's admission surface** —
//! the same confused-deputy shape W-32 rules on for `BIND` — and unlike `BIND`
//! there is not even a MAC to fall back on.

use twinvpn_relay_client::frame::{HEADER_LEN, MAX_DATA_PAYLOAD_BYTES, TAG_LEN, VERSION};

use super::outcome::RelayReject;

/// The stateless cookie width — `services/relay/src/leg.rs` `COOKIE_BYTES`.
pub const COOKIE_BYTES: usize = 16;

/// The `flags` bit a `HANDSHAKE_INIT` sets when it carries a cookie.
pub const FLAG_CARRIES_COOKIE: u8 = 0x01;

/// The handshake-payload envelope version.
pub const PRESENTATION_VERSION: u8 = 1;
/// The fixed prefix of a token presentation.
pub const PRESENTATION_PREFIX_BYTES: usize = 1 + 1 + 2;
/// The largest issuer key id a presentation may name.
pub const MAX_ISSUER_KEY_ID_BYTES: usize = 64;

/// The three frame types leg setup uses, which the device crate has no
/// `FrameType` variant for.
///
/// `services/relay/src/frame.rs` allocated them inside the `0x10..0x1F` control
/// space ADR-0005 §9.1 reserves, and records the allocation as a proposal for
/// that ADR's owner. They are held apart from
/// [`twinvpn_relay_client::frame::FrameType`] because they are the one class of
/// datagram on this socket that legitimately carries **no MAC** — no `K_leg`
/// exists yet — and mixing them into a type whose whole contract is "verify
/// before you act" is how an unauthenticated frame comes to be treated as an
/// authenticated one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegSetupType {
    /// `0x18` — `Noise_IK` message 1, carrying the `RelayCapabilityToken`.
    HandshakeInit,
    /// `0x19` — `Noise_IK` message 2.
    HandshakeResp,
    /// `0x1A` — ADR-0005 §11.5's stateless cookie challenge.
    CookieChallenge,
}

impl LegSetupType {
    /// The wire byte.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            LegSetupType::HandshakeInit => 0x18,
            LegSetupType::HandshakeResp => 0x19,
            LegSetupType::CookieChallenge => 0x1A,
        }
    }

    /// Decodes a wire byte.
    #[must_use]
    pub const fn from_wire(v: u8) -> Option<Self> {
        match v {
            0x18 => Some(LegSetupType::HandshakeInit),
            0x19 => Some(LegSetupType::HandshakeResp),
            0x1A => Some(LegSetupType::CookieChallenge),
            _ => None,
        }
    }

    /// Whether a **relay** may send this type to a device.
    ///
    /// `HANDSHAKE_INIT` is a device's to send; a relay sending one is asking
    /// the device to act as an admission surface, which is the same
    /// confused-deputy shape W-32 rules on for `BIND` — and here there is not
    /// even a MAC to fall back on, so the direction check is the only check
    /// there is.
    #[must_use]
    pub const fn relay_may_send(self) -> bool {
        matches!(
            self,
            LegSetupType::HandshakeResp | LegSetupType::CookieChallenge
        )
    }
}

/// One parsed leg-setup datagram: a header this module read and a body it has
/// **not** authenticated, because at leg setup there is nothing to authenticate
/// it with.
#[derive(Debug)]
pub struct LegSetupFrame {
    /// Which of the three.
    pub kind: LegSetupType,
    /// The `flags` nibble.
    pub flags: u8,
    /// The body: a Noise message, or a cookie.
    pub body: Vec<u8>,
}

/// Assembles a leg-setup datagram.
///
/// `counter_low`, `flow_id` and `auth_tag` are all zero, matching
/// `services/relay/src/admit.rs`, which sends every leg-setup frame that way:
/// there is no `K_leg` to MAC with and no flow to name.
#[must_use]
pub fn encode_leg_setup(kind: LegSetupType, flags: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.push(kind.to_wire());
    out.push((VERSION << 4) | (flags & 0x0F));
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&0_u32.to_be_bytes());
    out.extend_from_slice(&[0_u8; TAG_LEN]);
    out.extend_from_slice(body);
    out
}

/// Parses a leg-setup datagram, bounding the body **before** it is retained.
///
/// # Errors
///
/// [`RelayReject::Malformed`] for anything shorter than the header or not one
/// of the three types, [`RelayReject::VersionUnsupported`] for a `ver` nibble
/// this build does not speak, [`RelayReject::WrongDirection`] for a
/// `HANDSHAKE_INIT` from a relay, and [`RelayReject::PayloadTooLarge`] past the
/// leg's ceiling.
pub fn parse_leg_setup(datagram: &[u8]) -> Result<LegSetupFrame, RelayReject> {
    if datagram.len() < HEADER_LEN {
        return Err(RelayReject::Malformed);
    }
    let kind = LegSetupType::from_wire(datagram[0]).ok_or(RelayReject::Malformed)?;
    if datagram[1] >> 4 != VERSION {
        return Err(RelayReject::VersionUnsupported);
    }
    if !kind.relay_may_send() {
        return Err(RelayReject::WrongDirection);
    }
    let body_len = datagram.len() - HEADER_LEN;
    if body_len > MAX_DATA_PAYLOAD_BYTES {
        return Err(RelayReject::PayloadTooLarge {
            observed: body_len,
            limit: MAX_DATA_PAYLOAD_BYTES,
        });
    }
    Ok(LegSetupFrame {
        kind,
        // Reserved bits ignored on receive (ADR-0014).
        flags: datagram[1] & 0x0F,
        body: datagram[HEADER_LEN..].to_vec(),
    })
}

/// Whether a datagram's type byte is one of the three leg-setup types.
///
/// Read **before** a leg is looked up, exactly as `services/relay/src/frame.rs`'s
/// `is_leg_setup` is, so the one datagram class that legitimately has no leg is
/// never confused with the far larger class that has none because it is
/// unauthenticated.
#[must_use]
pub fn is_leg_setup(datagram: &[u8]) -> bool {
    !datagram.is_empty() && LegSetupType::from_wire(datagram[0]).is_some()
}

/// What a device puts in the `Noise_IK` message-1 payload.
///
/// `[version:u8][key_id_len:u8][reserved:u16][issuer_key_id][cose_sign1 …]` —
/// `services/relay/src/admit.rs`'s `TokenPresentation`, whose doc explains the
/// choice: the token rides *inside* the handshake, so leg setup is one round
/// trip and a bearer credential is never on the wire in the clear even before a
/// leg exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenPresentation {
    /// Which held issuer key the token claims to be signed by. A lookup hint;
    /// the signature decides.
    pub issuer_key_id: String,
    /// The COSE_Sign1 envelope, presented **exactly** as it was issued —
    /// `Auth.signed_payload` verifies over the received octets, so re-encoding
    /// it would invalidate a valid token.
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
