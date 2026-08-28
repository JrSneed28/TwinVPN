//! The device side of ADR-0005 §9.1's 16-byte `RelayFrame`.
//!
//! **Authority:** ADR-0005 §9.1 (the header, identical across all four
//! carriages), §9.2 (the overhead table the payload bound is derived from),
//! §11.1(5) (a relay forwards byte for byte and never fragments), §11.5 (zero
//! bytes in reply to anything unauthenticated); ADR-0001 §11 (the payload is an
//! unmodified WireGuard L-DATA datagram); ADR-0003 R7 (no serialization
//! framework in the packet path); RFC 9147 §4.2.2 (counter reconstruction).
//!
//! # This is the other half of a wire format that already ships
//!
//! `services/relay/src/frame.rs` implements the relay side and
//! `services/relay/README.md` §12 records it as exercised end to end over real
//! sockets. Until this module existed the device could select, bind and fail
//! over between relays and **could not put a byte on the wire to one**. Every
//! constant here is the relay's, and an agreement test is expected to hold the
//! two together — so where a value is derived rather than quoted, the derivation
//! is repeated rather than the number copied.
//!
//! # The payload is never a value this crate can read
//!
//! [`Payload`] carries opaque bytes. It has no decode, no parse, no `Display`,
//! and a `Debug` that prints a length and nothing else — `ownership.md` §6 rule
//! 11 forbids observability capturing a tunnel payload, and a derived `Debug`
//! anywhere above it would do exactly that.
//!
//! ADR-0003 R7 is the second reason there is no parser here: "B4 MUST have
//! **zero** serialization framework in the packet path". The relay side records
//! the same finding — a protobuf record scan refuses an L-DATA datagram
//! outright, because AEAD ciphertext is not a record sequence.
//!
//! # No cryptography is implemented here
//!
//! CD-I2. The MAC is `twinvpn_crypto::frame_mac` and the verify is
//! `twinvpn_crypto::verify_frame_mac`, which is constant-time — a variable-time
//! comparison on an attacker-supplied tag is a prefix-matching oracle.

use bytes::Bytes;
use twinvpn_crypto::{frame_mac, verify_frame_mac};

/// The wire header length. ADR-0005 §9.1.
pub const HEADER_LEN: usize = 16;

/// The protocol version this build speaks, in the `ver` nibble.
pub const VERSION: u8 = 1;

/// The per-leg MAC key length, from `twinvpn-crypto`.
pub const LEG_KEY_LEN: usize = 32;

/// The truncated MAC length. ADR-0005 §9.1's 64-bit `auth_tag`.
pub const TAG_LEN: usize = 8;

/// The L-DATA per-datagram overhead ADR-0005 §9.2 accounts for.
pub const L_DATA_OVERHEAD_BYTES: usize = 32;

/// The overlay MTU floor `docs/networking.md` §6.2 and ADR-0005 C7 fix.
pub const OVERLAY_MTU_FLOOR: usize = 1_280;

/// The largest `DATA` payload a relay leg can carry: **1456 bytes**.
///
/// Derived, not borrowed. `limits.json` has no B4 entry — `contracts/README.md`
/// records that B4's schema artifact is absent by design — so the bound comes
/// from ADR-0005 §9.2's overhead table, at the row with the least framing
/// beneath `RelayFrame` (`R-UDP` over IPv4):
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
/// Every other carriage and family is smaller, so this is the binding maximum.
/// It clears the `OVERLAY_MTU_FLOOR + L_DATA_OVERHEAD_BYTES` = 1312 that a
/// conforming relay must carry, by 144 bytes.
///
/// **Not** C4's 1200: that is the pre-authentication rendezvous datagram cap,
/// and it is too small to be legal here — a 1200-byte bound would make the 1280
/// overlay floor unachievable on every carriage.
pub const MAX_DATA_PAYLOAD_BYTES: usize = 1_456;

/// ADR-0005 §9.1's frame types, with the relay's wire bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameType {
    /// `0x01` — an opaque L-DATA datagram to forward.
    Data,
    /// `0x10` — this device asking to join a `pair_tag`.
    Bind,
    /// `0x11` — the relay confirming a bound flow.
    Bound,
    /// `0x12` — leg liveness, observable independently of any half-flow.
    ///
    /// ADR-0006 §11.15(c): the whole of §11.4's failure attribution rests on
    /// this being separate from the end-to-end `Path` heartbeat.
    Ping,
    /// `0x13`.
    Pong,
    /// `0x14` — the relay asking this device to leave, with a deadline.
    Drain,
    /// `0x15` — overload, shedding or drain. Never silent loss (I6).
    RelayStatus,
    /// `0x16` — version and capability negotiation at leg setup.
    Caps,
    /// `0x17`.
    Rebind,
}

impl FrameType {
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

    /// Decodes a wire byte.
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
            _ => None,
        }
    }

    /// Whether a device legitimately **sends** this type.
    ///
    /// `BOUND`, `DRAIN` and `RELAY_STATUS` are the relay's to send; a device
    /// emitting one would be impersonating its own relay to itself.
    #[must_use]
    pub const fn device_may_send(self) -> bool {
        matches!(
            self,
            FrameType::Data
                | FrameType::Bind
                | FrameType::Ping
                | FrameType::Pong
                | FrameType::Caps
                | FrameType::Rebind
        )
    }
}

/// An opaque relay payload.
///
/// The only surface is [`Payload::as_bytes`] and [`Payload::len`]. There is no
/// decode and no `Display`, and the `Debug` prints a length — never octets.
#[derive(Clone, PartialEq, Eq)]
pub struct Payload(Bytes);

impl Payload {
    /// Wraps bytes, bounding them **before** they are retained.
    ///
    /// # Errors
    ///
    /// [`FrameError::PayloadTooLarge`] past [`MAX_DATA_PAYLOAD_BYTES`].
    pub fn new(bytes: Bytes) -> Result<Self, FrameError> {
        if bytes.len() > MAX_DATA_PAYLOAD_BYTES {
            return Err(FrameError::PayloadTooLarge {
                observed: bytes.len(),
                limit: MAX_DATA_PAYLOAD_BYTES,
            });
        }
        Ok(Self(bytes))
    }

    /// The bytes. Deliberately the only way to reach them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The length.
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

impl core::fmt::Debug for Payload {
    /// A length and nothing else. This carries tunnel ciphertext, and
    /// `ownership.md` §6 rule 11 forbids observability capturing it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Payload(<{} B opaque>)", self.0.len())
    }
}

/// The per-leg MAC key.
///
/// Redacted `Debug` for the same reason every key type in the workspace has one:
/// a derive on some enclosing struct must not be able to print it.
#[derive(Clone, PartialEq, Eq)]
pub struct LegKey([u8; LEG_KEY_LEN]);

impl LegKey {
    /// Wraps the derived leg key.
    #[must_use]
    pub const fn from_array(bytes: [u8; LEG_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The key bytes, for `twinvpn-crypto` only.
    #[must_use]
    pub const fn as_array(&self) -> &[u8; LEG_KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for LegKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LegKey(<32 B redacted>)")
    }
}

/// Why a frame was rejected.
///
/// Every variant is a **silent drop** on the wire. ADR-0005 §11.5 gives the
/// relay zero bytes in reply to anything unauthenticated, and a device owes its
/// relay the same courtesy: replying would make the device an amplifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
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
    /// The payload exceeded the derived B4 ceiling.
    #[error("payload {observed} B exceeds the {limit} B relay-leg ceiling")]
    PayloadTooLarge {
        /// What arrived.
        observed: usize,
        /// The ceiling.
        limit: usize,
    },
    /// The MAC did not verify under this leg's key.
    #[error("frame authentication failed")]
    AuthenticationFailed,
    /// The counter was a replay, or too old to judge.
    #[error("frame counter replayed or outside the window")]
    ReplayedCounter,
    /// A frame type only the relay may send arrived from a device, or the
    /// reverse.
    #[error("frame type is not one this direction may carry")]
    WrongDirection,
}

/// A frame this device is about to send.
#[derive(Debug, Clone)]
pub struct OutboundFrame {
    kind: FrameType,
    flags: u8,
    flow_id: u32,
    payload: Payload,
}

impl OutboundFrame {
    /// Builds a frame.
    ///
    /// # Errors
    ///
    /// [`FrameError::WrongDirection`] for a type only the relay sends, and
    /// whatever [`Payload::new`] rejects.
    pub fn new(
        kind: FrameType,
        flags: u8,
        flow_id: u32,
        payload: Bytes,
    ) -> Result<Self, FrameError> {
        if !kind.device_may_send() {
            return Err(FrameError::WrongDirection);
        }
        Ok(Self {
            kind,
            flags: flags & 0x0F,
            flow_id,
            payload: Payload::new(payload)?,
        })
    }

    /// The MAC input ADR-0005 §9.1 specifies:
    /// `(type‖ver‖flags‖counter_full‖flow_id‖payload)`.
    ///
    /// `counter_full`, not `counter_low`: the receiver reconstructs the 64-bit
    /// counter and MACs over the full value, which is what stops a 16-bit wrap
    /// from becoming a forgery oracle.
    #[must_use]
    pub fn mac_input(&self, counter_full: u64) -> Vec<u8> {
        mac_input_of(
            self.kind,
            self.flags,
            counter_full,
            self.flow_id,
            self.payload.as_bytes(),
        )
    }

    /// Serialises the frame with a real MAC under `key`.
    ///
    /// The 16-bit `counter_low` on the wire is the low half of `counter_full`;
    /// the MAC covers the full 64 bits.
    #[must_use]
    pub fn encode(&self, key: &LegKey, counter_full: u64) -> Bytes {
        let tag = frame_mac(key.as_array(), &self.mac_input(counter_full));
        let payload = self.payload.as_bytes();
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.push(self.kind.to_wire());
        out.push((VERSION << 4) | self.flags);
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(counter_full as u16).to_be_bytes());
        out.extend_from_slice(&self.flow_id.to_be_bytes());
        out.extend_from_slice(&tag);
        out.extend_from_slice(payload);
        Bytes::from(out)
    }
}

/// A frame received from the relay, parsed but **not yet authenticated**.
///
/// Nothing here may be acted on until [`InboundFrame::verify`] has returned a
/// [`VerifiedFrame`]: the type exists so "parsed" and "authentic" cannot be
/// confused at a call site.
#[derive(Debug)]
pub struct InboundFrame {
    kind: FrameType,
    flags: u8,
    counter_low: u16,
    flow_id: u32,
    auth_tag: [u8; TAG_LEN],
    payload: Payload,
}

impl InboundFrame {
    /// Parses a datagram, bounding the payload **before** retaining it.
    ///
    /// # Errors
    ///
    /// [`FrameError::TooShort`], [`FrameError::UnknownType`],
    /// [`FrameError::UnsupportedVersion`] or [`FrameError::PayloadTooLarge`].
    /// Every one is a silent drop.
    pub fn parse(datagram: &Bytes) -> Result<Self, FrameError> {
        if datagram.len() < HEADER_LEN {
            return Err(FrameError::TooShort);
        }
        let kind = FrameType::from_wire(datagram[0]).ok_or(FrameError::UnknownType)?;
        let verflags = datagram[1];
        let version = verflags >> 4;
        // Reserved bits: zero on send, IGNORED on receive (ADR-0014 forward
        // compatibility). Masking rather than rejecting is the whole point.
        let flags = verflags & 0x0F;
        if version != VERSION {
            return Err(FrameError::UnsupportedVersion);
        }
        let counter_low = u16::from_be_bytes([datagram[2], datagram[3]]);
        let flow_id = u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]);
        let mut auth_tag = [0u8; TAG_LEN];
        auth_tag.copy_from_slice(&datagram[8..16]);

        // Bounded BEFORE the slice is retained (`ownership.md` §6 rules 9, 10).
        let payload_len = datagram.len() - HEADER_LEN;
        if payload_len > MAX_DATA_PAYLOAD_BYTES {
            return Err(FrameError::PayloadTooLarge {
                observed: payload_len,
                limit: MAX_DATA_PAYLOAD_BYTES,
            });
        }
        let payload = Payload::new(datagram.slice(HEADER_LEN..))?;

        Ok(Self {
            kind,
            flags,
            counter_low,
            flow_id,
            auth_tag,
            payload,
        })
    }

    /// The frame type, before authentication. Safe to read for routing a drop.
    #[must_use]
    pub const fn kind(&self) -> FrameType {
        self.kind
    }

    /// The relay-assigned flow handle, before authentication.
    #[must_use]
    pub const fn flow_id(&self) -> u32 {
        self.flow_id
    }

    /// The low 16 bits of the counter, before authentication.
    #[must_use]
    pub const fn counter_low(&self) -> u16 {
        self.counter_low
    }

    /// Authenticates the frame and admits its counter.
    ///
    /// The order is: reconstruct the full counter (RFC 9147 §4.2.2), verify the
    /// MAC **over that full value**, and only then admit it to the window.
    /// Admitting first would let a forged counter advance the window and lock
    /// out the genuine peer.
    ///
    /// # Errors
    ///
    /// [`FrameError::AuthenticationFailed`] or [`FrameError::ReplayedCounter`].
    pub fn verify(
        self,
        key: &LegKey,
        window: &mut CounterWindow,
    ) -> Result<VerifiedFrame, FrameError> {
        let counter_full = window.reconstruct(self.counter_low);
        let input = mac_input_of(
            self.kind,
            self.flags,
            counter_full,
            self.flow_id,
            self.payload.as_bytes(),
        );
        if !verify_frame_mac(key.as_array(), &input, &self.auth_tag) {
            return Err(FrameError::AuthenticationFailed);
        }
        if !window.accept(counter_full) {
            return Err(FrameError::ReplayedCounter);
        }
        Ok(VerifiedFrame {
            kind: self.kind,
            flags: self.flags,
            counter: counter_full,
            flow_id: self.flow_id,
            payload: self.payload,
        })
    }
}

/// A frame whose MAC verified and whose counter was admitted.
#[derive(Debug)]
pub struct VerifiedFrame {
    kind: FrameType,
    flags: u8,
    counter: u64,
    flow_id: u32,
    payload: Payload,
}

impl VerifiedFrame {
    /// The frame type.
    #[must_use]
    pub const fn kind(&self) -> FrameType {
        self.kind
    }

    /// The `flags` nibble.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// The reconstructed 64-bit counter.
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// The relay-assigned flow handle.
    #[must_use]
    pub const fn flow_id(&self) -> u32 {
        self.flow_id
    }

    /// The opaque payload. **There is no method on it that yields a decoded
    /// value.**
    #[must_use]
    pub const fn payload(&self) -> &Payload {
        &self.payload
    }
}

/// ADR-0005 §9.1's MAC input, in one place so the two directions cannot drift.
fn mac_input_of(
    kind: FrameType,
    flags: u8,
    counter_full: u64,
    flow_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 8 + 4 + payload.len());
    out.push(kind.to_wire());
    out.push((VERSION << 4) | flags);
    out.extend_from_slice(&counter_full.to_be_bytes());
    out.extend_from_slice(&flow_id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// The device's send counter for one leg.
///
/// 64 bits internally, low 16 on the wire. Distinct from
/// `twinvpn-tunnel`'s L-DATA counter: this one authenticates the **leg** and is
/// reset when the leg is re-established, while the L-DATA counter belongs to the
/// `Session` and survives a transport change (ADR-0001 §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LegSendCounter(u64);

impl LegSendCounter {
    /// A fresh counter, starting at 0.
    #[must_use]
    pub const fn new() -> Self {
        Self(0)
    }

    /// The next counter.
    #[must_use]
    pub fn take_next(&mut self) -> u64 {
        let v = self.0;
        self.0 = self.0.wrapping_add(1);
        v
    }

    /// How many have been issued.
    #[must_use]
    pub const fn issued(self) -> u64 {
        self.0
    }
}

/// RFC 9147 (DTLS 1.3) §4.2.2 sequence-number reconstruction and replay window.
///
/// ADR-0005 §9.1 names it exactly: "reconstructed by the receiver with a sliding
/// window exactly as RFC 9147 §4.2.2 specifies. **No new construction (C1).**"
///
/// This mirrors `services/relay/src/frame.rs`'s `CounterWindow` so the two ends
/// of a leg agree; an agreement test is the right place to hold them together.
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

    /// A fresh window. Nothing has been received.
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
    /// rule and what makes a wrap unambiguous inside the window.
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
    /// `false` for a replay or a counter too old to judge — the caller then
    /// drops the frame with no reply.
    ///
    /// Like `twinvpn-tunnel`'s L-DATA window, `seen_any` is what distinguishes
    /// "nothing received" from "counter 0 received"; conflating them is the
    /// defect that made the first L-DATA record of every tunnel a replay.
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
        let behind = self.highest - counter;
        if behind >= Self::WIDTH {
            return false;
        }
        let mask = 1_u64 << behind;
        if self.bitmap & mask != 0 {
            return false;
        }
        self.bitmap |= mask;
        true
    }

    /// The highest counter accepted.
    #[must_use]
    pub const fn highest(&self) -> u64 {
        self.highest
    }

    /// Whether anything has been accepted.
    #[must_use]
    pub const fn has_accepted_any(&self) -> bool {
        self.seen_any
    }
}

/// §11.1(5): a relay forwards byte for byte and **never fragments or
/// reassembles**, so neither does a device leg.
///
/// A function rather than a comment so the property is greppable and a change to
/// it fails a test.
#[must_use]
pub const fn leg_may_fragment() -> bool {
    false
}
