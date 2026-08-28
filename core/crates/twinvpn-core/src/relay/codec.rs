//! The device half of the control-frame bodies: `BIND`, `BOUND`, `CAPS`,
//! `DRAIN`, `RELAY_STATUS`.
//!
//! **Authority:** ADR-0005 §9.1 (the 16-byte `RelayFrame` header and the
//! `0x10..0x1F` control range), §11.1(3) (the `pair_tag` rendezvous), §11.5
//! (`RELAY_STATUS`, and zero bytes in reply to anything unauthenticated), §8
//! (`DRAIN`), §10 (`CAPS`); ADR-0014 (reserved bits are zero on send and
//! **ignored** on receive); ADR-0003 R7 (no serialization framework in the
//! packet path); `ownership.md` §6 rules 9 and 10.
//!
//! The three leg-setup frames are in [`super::legsetup`], and the module note
//! there says why they are not here.
//!
//! # Every octet here is the relay's, not this module's
//!
//! `services/relay/src/control.rs` and `services/relay/src/status.rs` are the
//! authority for these layouts — both record them as *proposed, not frozen*,
//! versioned by the frame's own `ver` nibble — and this file is the decoder for
//! what that encoder emits and the encoder for what its decoder accepts. Where
//! the relay derives a constant rather than quoting one, the derivation is
//! repeated here rather than the number copied, so the two cannot silently
//! drift; `the_wire_constants_match_the_relay` in `tests/relay.rs` holds them
//! together.
//!
//! # Why the bodies are not in `twinvpn-relay-client`
//!
//! They should be. `twinvpn_relay_client::frame` implements ADR-0005 §9.1's
//! **header** and stops there: it has no `BIND`/`BOUND`/`CAPS`/`DRAIN`/
//! `RELAY_STATUS` body codec at all. That crate belongs to `core-dataplane` and
//! this domain does not write into it (`ownership.md` §2), so the bodies live
//! here and their eventual home is an integration item.
//!
//! # Bounded before allocation, every time
//!
//! Each decoder refuses a short buffer **before** it indexes and a declared
//! count above its ceiling **before** it sizes anything — §6 rules 9 and 10, on
//! a surface a relay can drive. The ceiling check comes first and is
//! independent of how many octets actually arrived, so a body that declares 255
//! suggestions is refused whether or not it carries the 2 040 octets to back
//! the claim.

use twinvpn_relay_client::frame::{FrameType, MAX_DATA_PAYLOAD_BYTES, VERSION};
use twinvpn_relay_client::map::Carriage;
use twinvpn_types::{AddressFamily, RelayId};

use super::outcome::RelayReject;

/// `limits.json` `identifiers.pair_tag_bytes`.
pub const PAIR_TAG_BYTES: usize = twinvpn_types::PairTag::WIDTH;
/// `limits.json` `identifiers.relay_id_bytes`.
pub const RELAY_ID_BYTES: usize = twinvpn_types::RelayId::WIDTH;

/// The fixed width of a `BIND`/`REBIND` body — `services/relay/src/control.rs`
/// `BIND_BODY_BYTES`, derived the same way rather than copied.
pub const BIND_BODY_BYTES: usize = PAIR_TAG_BYTES + 8 + 1 + 1 + 2;
/// The fixed width of a `BOUND` body.
pub const BOUND_BODY_BYTES: usize = 1 + 3 + 4;
/// The fixed width of a `CAPS` body.
pub const CAPS_BODY_BYTES: usize = 1 + 1 + 2 + 2 + 2;
/// The fixed prefix of a `DRAIN` body, before its suggestion list.
pub const DRAIN_PREFIX_BYTES: usize = 8 + 1 + 3;
/// The fixed prefix of a `RELAY_STATUS` body, before its code and its list.
pub const STATUS_PREFIX_BYTES: usize = 1 + 1 + 2 + 4;

/// The most alternates either a `DRAIN` or a `RELAY_STATUS` may suggest.
///
/// Three, matching `services/relay/src/control.rs`'s `MAX_SUGGESTED_RELAYS` and
/// `status.rs`'s `MAX_SUGGESTED_ALTERNATIVES`: ADR-0006 §11.5 has a device
/// `BIND` `k = 3` in parallel, so three is what it can act on, and bounding it
/// at all is §6 rule 10.
pub const MAX_SUGGESTED_RELAYS: usize = 3;

/// A `reason_code` is ≤ 64 bytes by ADR-0015 §11.2's own format rule.
pub const MAX_REASON_CODE_BYTES: usize = 64;

/// The relay-side wire byte for an address family, matching
/// `common.proto AddressFamily`'s ordering.
///
/// **Both families, one code path** (ADR-0010 R1). There is no v4 branch and no
/// v6 branch anywhere below this function: the family is one octet of one body,
/// and everything else about a leg is identical.
#[must_use]
pub const fn family_to_wire(family: AddressFamily) -> u8 {
    match family {
        AddressFamily::V4 => 1,
        AddressFamily::V6 => 2,
    }
}

/// Decodes a family octet.
#[must_use]
pub const fn family_from_wire(v: u8) -> Option<AddressFamily> {
    match v {
        1 => Some(AddressFamily::V4),
        2 => Some(AddressFamily::V6),
        _ => None,
    }
}

/// A carriage's wire byte (`services/relay/src/control.rs`).
#[must_use]
pub const fn carriage_to_wire(c: Carriage) -> u8 {
    match c {
        Carriage::Udp => 1,
        Carriage::Quic => 2,
        Carriage::Tls => 3,
    }
}

/// The `BIND` body: **the whole of what a device tells a relay about its pair**.
///
/// There is no peer identifier of any kind, which is the security property, not
/// an omission — `identifiers.md` and `protocol.md` §16 row 21 record
/// `peer_key_id`'s withdrawal, because a `pair_tag` is *"one-way, scoped to one
/// `relay_id` and one ten-minute bucket … A tag observed at one relay is
/// useless at another, **which is what a `peer_key_id` field would have
/// destroyed**."*
///
/// This is a wire encoding for `twinvpn_relay_client::BindRequest`, not a
/// second definition of it: the field set is that struct's, and
/// `the_bind_body_carries_no_peer_identifier` asserts the encoded width admits
/// nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindBody {
    /// The blinded join key.
    pub pair_tag: [u8; PAIR_TAG_BYTES],
    /// The ten-minute bucket the tag was derived for.
    pub bucket: u64,
    /// Which carriage the leg runs on.
    pub carriage: Carriage,
    /// Which family this half-flow is on. The two halves of one `pair_tag` MAY
    /// differ — an IPv6-only peer and an IPv4-only peer meeting at the relay is
    /// a large part of why the relay exists.
    pub family: AddressFamily,
}

impl BindBody {
    /// The body octets.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BIND_BODY_BYTES);
        out.extend_from_slice(&self.pair_tag);
        out.extend_from_slice(&self.bucket.to_be_bytes());
        out.push(carriage_to_wire(self.carriage));
        out.push(family_to_wire(self.family));
        out.extend_from_slice(&0_u16.to_be_bytes()); // reserved: zero on send
        out
    }
}

/// Whether a `BIND` has been answered, or is still waiting for the partner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundState {
    /// A pending slot exists; the partner has the announced TTL to arrive.
    Pending,
    /// Both half-flows are present.
    Bound,
}

/// The `BOUND` body. `flow_id` is in the **header**, where every other frame on
/// this flow carries it, so it is not repeated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundBody {
    /// Pending or bound.
    pub state: BoundState,
    /// The pending-slot lifetime, so the re-`BIND` cadence comes from the
    /// relay's number rather than a compiled-in copy of it.
    pub pending_ttl_ms: u32,
}

impl BoundBody {
    /// Decodes a body.
    ///
    /// # Errors
    ///
    /// [`RelayReject::Malformed`] for a short buffer or a reserved state octet.
    pub fn decode(body: &[u8]) -> Result<Self, RelayReject> {
        if body.len() < BOUND_BODY_BYTES {
            return Err(RelayReject::Malformed);
        }
        let state = match body[0] {
            0 => BoundState::Pending,
            1 => BoundState::Bound,
            _ => return Err(RelayReject::Malformed),
        };
        // Octets 1..4 are reserved and IGNORED on receive (ADR-0014).
        let mut ttl = [0_u8; 4];
        ttl.copy_from_slice(&body[4..8]);
        Ok(Self {
            state,
            pending_ttl_ms: u32::from_be_bytes(ttl),
        })
    }
}

/// `relay_standby` — ADR-0014's capability name for holding a warm second leg.
pub const CAP_STANDBY: u16 = 1 << 0;
/// The relay implements `DRAIN`.
pub const CAP_DRAIN: u16 = 1 << 1;
/// The relay implements `CAPS`.
pub const CAP_CAPS: u16 = 1 << 2;
/// The relay implements `REBIND`.
pub const CAP_REBIND: u16 = 1 << 3;

/// The `CAPS` body — ADR-0005 §10's version and capability exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapsBody {
    /// The lowest `ver` nibble the sender speaks.
    pub version_min: u8,
    /// The highest.
    pub version_max: u8,
    /// The [`CAP_STANDBY`]-family bitmap.
    pub capabilities: u16,
    /// The largest `DATA` payload the relay will forward, so the device sizes
    /// its L-DATA datagram from the relay's number rather than assuming.
    pub max_data_payload_bytes: u16,
}

impl CapsBody {
    /// What this build offers.
    #[must_use]
    pub const fn of_this_build() -> Self {
        Self {
            version_min: VERSION,
            version_max: VERSION,
            capabilities: CAP_STANDBY | CAP_DRAIN | CAP_CAPS | CAP_REBIND,
            #[allow(clippy::cast_possible_truncation)]
            max_data_payload_bytes: MAX_DATA_PAYLOAD_BYTES as u16,
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
    /// [`RelayReject::Malformed`] for a short buffer or an inverted version
    /// window. An unknown capability **bit** is not an error: ADR-0014 requires
    /// unknown capabilities to be ignored, or a relay could never gain one
    /// without breaking every deployed device.
    pub fn decode(body: &[u8]) -> Result<Self, RelayReject> {
        if body.len() < CAPS_BODY_BYTES {
            return Err(RelayReject::Malformed);
        }
        if body[0] > body[1] {
            return Err(RelayReject::Malformed);
        }
        Ok(Self {
            version_min: body[0],
            version_max: body[1],
            capabilities: u16::from_be_bytes([body[2], body[3]]),
            max_data_payload_bytes: u16::from_be_bytes([body[4], body[5]]),
        })
    }
}

/// The `DRAIN` body — `relay.proto RelayDrain`, minus the two fields the frame
/// header already carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainBody {
    /// How long the flow may persist, in milliseconds from now.
    pub drain_deadline_ms: u64,
    /// Suggested alternates. A **hint**, never an instruction: `relay.proto`
    /// says a relay *"can ASK a device to leave but can NEVER REDIRECT A
    /// SESSION BY ITSELF"*, so these are ids the device re-checks against its
    /// own verified map, and a relay cannot name an endpoint at all.
    pub suggested_relay_ids: Vec<RelayId>,
}

impl DrainBody {
    /// Decodes a body.
    ///
    /// # Errors
    ///
    /// [`RelayReject::Malformed`] for a short buffer, and
    /// [`RelayReject::DeclaredCountTooLarge`] for a declared count above
    /// [`MAX_SUGGESTED_RELAYS`]. The ceiling is checked **first** and without
    /// reference to how many octets arrived, so a body claiming 255 ids is
    /// refused before anything is sized from that 255 — whether or not it
    /// carried the octets to back the claim.
    pub fn decode(body: &[u8]) -> Result<Self, RelayReject> {
        if body.len() < DRAIN_PREFIX_BYTES {
            return Err(RelayReject::Malformed);
        }
        let count = usize::from(body[8]);
        if count > MAX_SUGGESTED_RELAYS {
            return Err(RelayReject::DeclaredCountTooLarge {
                declared: count,
                ceiling: MAX_SUGGESTED_RELAYS,
            });
        }
        let needed = DRAIN_PREFIX_BYTES + count * RELAY_ID_BYTES;
        if body.len() < needed {
            return Err(RelayReject::Malformed);
        }
        let mut deadline = [0_u8; 8];
        deadline.copy_from_slice(&body[..8]);
        // Only now, with `count` proven to be at most three AND backed by
        // octets that are present, is anything allocated.
        let mut ids = Vec::with_capacity(count);
        for i in 0..count {
            let at = DRAIN_PREFIX_BYTES + i * RELAY_ID_BYTES;
            ids.push(
                RelayId::from_slice(&body[at..at + RELAY_ID_BYTES]).map_err(|_| {
                    // Unreachable while `RELAY_ID_BYTES` is the type's own width,
                    // and refused rather than unwrapped anyway: a width the
                    // registry moved is a wire event, not a panic.
                    RelayReject::Malformed
                })?,
            );
        }
        Ok(Self {
            drain_deadline_ms: u64::from_be_bytes(deadline),
            suggested_relay_ids: ids,
        })
    }
}

/// A `RELAY_STATUS` body: ADR-0005 §11.5's *"overload is never silent"*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusBody {
    /// The registered code, **as a string, never an enum** —
    /// `reason_codes.json` says so in as many words
    /// (`carried_on_wire_as: "string, never an enum"`), because stability rule
    /// 5 requires a receiver to degrade on an unknown code rather than fail,
    /// which an enum makes impossible.
    pub reason_code: String,
    /// How long to wait before retrying **this** relay.
    pub retry_after_ms: u32,
    /// Relay ids to try instead. A hint; see [`DrainBody::suggested_relay_ids`].
    pub suggested_relay_ids: Vec<RelayId>,
}

impl StatusBody {
    /// Decodes a body.
    ///
    /// # Errors
    ///
    /// [`RelayReject::Malformed`] for a short buffer or a code that is not
    /// UTF-8, and [`RelayReject::DeclaredCountTooLarge`] for a declared code
    /// length above [`MAX_REASON_CODE_BYTES`] or a declared suggestion count
    /// above [`MAX_SUGGESTED_RELAYS`]. Both ceilings are checked before either
    /// declared value is used to size or slice anything.
    pub fn decode(body: &[u8]) -> Result<Self, RelayReject> {
        if body.len() < STATUS_PREFIX_BYTES {
            return Err(RelayReject::Malformed);
        }
        let code_len = usize::from(body[0]);
        if code_len > MAX_REASON_CODE_BYTES {
            return Err(RelayReject::DeclaredCountTooLarge {
                declared: code_len,
                ceiling: MAX_REASON_CODE_BYTES,
            });
        }
        let count = usize::from(body[1]);
        if count > MAX_SUGGESTED_RELAYS {
            return Err(RelayReject::DeclaredCountTooLarge {
                declared: count,
                ceiling: MAX_SUGGESTED_RELAYS,
            });
        }
        let mut retry = [0_u8; 4];
        retry.copy_from_slice(&body[4..8]);
        let code_end = STATUS_PREFIX_BYTES + code_len;
        let needed = code_end + count * RELAY_ID_BYTES;
        if body.len() < needed {
            return Err(RelayReject::Malformed);
        }
        let reason_code = core::str::from_utf8(&body[STATUS_PREFIX_BYTES..code_end])
            .map_err(|_| RelayReject::Malformed)?
            .to_owned();
        let mut ids = Vec::with_capacity(count);
        for i in 0..count {
            let at = code_end + i * RELAY_ID_BYTES;
            ids.push(
                RelayId::from_slice(&body[at..at + RELAY_ID_BYTES])
                    .map_err(|_| RelayReject::Malformed)?,
            );
        }
        Ok(Self {
            reason_code,
            retry_after_ms: u32::from_be_bytes(retry),
            suggested_relay_ids: ids,
        })
    }
}

/// Which frame types this module knows how to act on once verified.
///
/// A thin wrapper over [`FrameType`] so the match in
/// [`super::leg::RelayLeg::on_datagram`] is exhaustive over the device's own
/// vocabulary rather than over the relay's.
#[must_use]
pub const fn is_relay_originated(kind: FrameType) -> bool {
    matches!(
        kind,
        FrameType::Drain | FrameType::RelayStatus | FrameType::Bound
    )
}
