//! The C1/C2 framing, and the bound that is applied **before** any allocation
//! proportional to a declared length.
//!
//! **Authority:** `ownership.md` §6 rules 9 and 10, `contracts/registry/limits.json`
//! (`envelope.c1_c2_c7_max_bytes = 65536`, `max_depth = 8`), ADR-0002 §11.1 N-1,
//! `twinvpn_service_common::transport::check_declared_length`.
//!
//! # Why a framing exists at all, and the contract gap it closes
//!
//! `control_commands.proto` defines seventeen request messages and no
//! discriminated union over them, and `MessageMetadata` carries no method name.
//! The client's seam is byte-oriented — `twinvpn-cp-client`'s
//! `ControlConnection::request(&[u8]) -> ReceivedOctets` — so **nothing in the
//! frozen contracts tells a receiver which of the seventeen a body is.** An
//! HTTP/3 binding would carry it in `:path`; this crate carries C1 directly over
//! QUIC bidirectional streams (see `quic`), so it carries it in a two-byte
//! header.
//!
//! That is a transport-level detail, not a schema: the header is outside the
//! protobuf body, adds no field to any frozen message, and an HTTP/3 front-end
//! can strip it and put the same value in `:path` without either side changing.
//! It is **reported as a contract gap**, not patched into `contracts/`.
//!
//! ```text
//!   C1 request  :  u16 command_code | u32 body_len | body
//!   C1 response :  u16 command_code | u32 body_len | body
//!   C2 record   :                     u32 body_len | ControlEvent
//! ```
//!
//! `body_len` is checked against the channel cap **before** the body buffer is
//! allocated, so a declared length of `0xFFFF_FFFF` costs six bytes of reading
//! and a typed reject, never four gigabytes of `Vec::with_capacity`.

use twinvpn_service_common::transport::check_declared_length;
use twinvpn_service_common::{Channel, Reject};

use crate::command::Command;

/// The two-byte discriminant.
///
/// Values are assigned once and never reused: a code is a wire identity, and
/// re-pointing one at a different command would make an old client's
/// `RevokeDevice` arrive as something else. The gaps are deliberate — each
/// decade is one group from `control_commands.proto`'s own section headings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CommandCode {
    /// `RegisterDevice`.
    RegisterDevice = 10,
    /// `UpdateDeviceMetadata`.
    UpdateDeviceMetadata = 11,
    /// `RevokeDevice`.
    RevokeDevice = 12,
    /// `RotateDeviceCredential`.
    RotateDeviceCredential = 13,
    /// `BeginPairing`.
    BeginPairing = 20,
    /// `CompletePairing`.
    CompletePairing = 21,
    /// `CancelPairing`.
    CancelPairing = 22,
    /// `RevokePairing`.
    RevokePairing = 23,
    /// `DiscoverPeers`.
    DiscoverPeers = 30,
    /// `PublishPresence`.
    PublishPresence = 31,
    /// `PutRouteAdvertisement`.
    PutRouteAdvertisement = 40,
    /// `WithdrawRouteAdvertisement`.
    WithdrawRouteAdvertisement = 41,
    /// `PutExitNodeOffer`.
    PutExitNodeOffer = 42,
    /// `WithdrawExitNodeOffer`.
    WithdrawExitNodeOffer = 43,
    /// `PutPolicy`.
    PutPolicy = 50,
    /// `SubscribeEvents`.
    SubscribeEvents = 60,
    /// `GetStateDocument`.
    GetStateDocument = 61,
}

impl CommandCode {
    /// The command this code names.
    #[must_use]
    pub const fn command(self) -> Command {
        match self {
            CommandCode::RegisterDevice => Command::RegisterDevice,
            CommandCode::UpdateDeviceMetadata => Command::UpdateDeviceMetadata,
            CommandCode::RevokeDevice => Command::RevokeDevice,
            CommandCode::RotateDeviceCredential => Command::RotateDeviceCredential,
            CommandCode::BeginPairing => Command::BeginPairing,
            CommandCode::CompletePairing => Command::CompletePairing,
            CommandCode::CancelPairing => Command::CancelPairing,
            CommandCode::RevokePairing => Command::RevokePairing,
            CommandCode::DiscoverPeers => Command::DiscoverPeers,
            CommandCode::PublishPresence => Command::PublishPresence,
            CommandCode::PutRouteAdvertisement => Command::PutRouteAdvertisement,
            CommandCode::WithdrawRouteAdvertisement => Command::WithdrawRouteAdvertisement,
            CommandCode::PutExitNodeOffer => Command::PutExitNodeOffer,
            CommandCode::WithdrawExitNodeOffer => Command::WithdrawExitNodeOffer,
            CommandCode::PutPolicy => Command::PutPolicy,
            CommandCode::SubscribeEvents => Command::SubscribeEvents,
            CommandCode::GetStateDocument => Command::GetStateDocument,
        }
    }

    /// The code for a command.
    #[must_use]
    pub const fn of(command: Command) -> Self {
        match command {
            Command::RegisterDevice => CommandCode::RegisterDevice,
            Command::UpdateDeviceMetadata => CommandCode::UpdateDeviceMetadata,
            Command::RevokeDevice => CommandCode::RevokeDevice,
            Command::RotateDeviceCredential => CommandCode::RotateDeviceCredential,
            Command::BeginPairing => CommandCode::BeginPairing,
            Command::CompletePairing => CommandCode::CompletePairing,
            Command::CancelPairing => CommandCode::CancelPairing,
            Command::RevokePairing => CommandCode::RevokePairing,
            Command::DiscoverPeers => CommandCode::DiscoverPeers,
            Command::PublishPresence => CommandCode::PublishPresence,
            Command::PutRouteAdvertisement => CommandCode::PutRouteAdvertisement,
            Command::WithdrawRouteAdvertisement => CommandCode::WithdrawRouteAdvertisement,
            Command::PutExitNodeOffer => CommandCode::PutExitNodeOffer,
            Command::WithdrawExitNodeOffer => CommandCode::WithdrawExitNodeOffer,
            Command::PutPolicy => CommandCode::PutPolicy,
            Command::SubscribeEvents => CommandCode::SubscribeEvents,
            Command::GetStateDocument => CommandCode::GetStateDocument,
        }
    }

    /// Decodes a wire value.
    ///
    /// An unassigned value is **not** a command. There is no default arm: a code
    /// this build does not know is a rejected frame, never a guessed one.
    #[must_use]
    pub const fn from_wire(value: u16) -> Option<Self> {
        match value {
            10 => Some(CommandCode::RegisterDevice),
            11 => Some(CommandCode::UpdateDeviceMetadata),
            12 => Some(CommandCode::RevokeDevice),
            13 => Some(CommandCode::RotateDeviceCredential),
            20 => Some(CommandCode::BeginPairing),
            21 => Some(CommandCode::CompletePairing),
            22 => Some(CommandCode::CancelPairing),
            23 => Some(CommandCode::RevokePairing),
            30 => Some(CommandCode::DiscoverPeers),
            31 => Some(CommandCode::PublishPresence),
            40 => Some(CommandCode::PutRouteAdvertisement),
            41 => Some(CommandCode::WithdrawRouteAdvertisement),
            42 => Some(CommandCode::PutExitNodeOffer),
            43 => Some(CommandCode::WithdrawExitNodeOffer),
            50 => Some(CommandCode::PutPolicy),
            60 => Some(CommandCode::SubscribeEvents),
            61 => Some(CommandCode::GetStateDocument),
            _ => None,
        }
    }

    /// The wire value.
    #[must_use]
    pub const fn to_wire(self) -> u16 {
        self as u16
    }
}

/// The fixed part of a C1 frame: two bytes of command, four of length.
pub const HEADER_BYTES: usize = 6;

/// The fixed part of a C2 record: four bytes of length.
pub const C2_HEADER_BYTES: usize = 4;

/// A decoded C1 frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct C1Frame {
    /// Which command.
    pub code: CommandCode,
    /// The body length, already checked against the channel cap.
    pub body_len: usize,
}

impl C1Frame {
    /// Parses the six-byte header and validates the declared length **before**
    /// the caller allocates a body buffer.
    ///
    /// # Errors
    ///
    /// [`Reject::Unparseable`] for a short header or an unassigned command code,
    /// and [`Reject::SizeExceeded`] carrying `limits.json`'s bound for a body
    /// larger than the C1 cap. Never a truncation, never a pad.
    pub fn parse_header(header: &[u8]) -> Result<Self, Reject> {
        if header.len() < HEADER_BYTES {
            return Err(Reject::Unparseable {
                parser_id: Channel::ControlAndTelemetry.parser_id(),
            });
        }
        let code = u16::from_be_bytes([header[0], header[1]]);
        let code = CommandCode::from_wire(code).ok_or(Reject::Unparseable {
            parser_id: Channel::ControlAndTelemetry.parser_id(),
        })?;
        let declared = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
        let body_len = check_declared_length(declared, Channel::ControlAndTelemetry)?;
        Ok(Self { code, body_len })
    }

    /// The header for a frame of `body_len` bytes.
    ///
    /// # Errors
    ///
    /// [`Reject::SizeExceeded`] if this process would emit a frame above the
    /// cap. The bound is applied on the way out as well as on the way in: a
    /// service that can *emit* an over-cap frame has a peer that must either
    /// reject it or raise its own cap, and both are worse than failing here.
    pub fn header_bytes(code: CommandCode, body_len: usize) -> Result<[u8; 6], Reject> {
        let checked = check_declared_length(body_len, Channel::ControlAndTelemetry)?;
        let len = u32::try_from(checked).map_err(|_| Reject::SizeExceeded {
            parser_id: Channel::ControlAndTelemetry.parser_id(),
            observed: body_len,
            limit: Channel::ControlAndTelemetry.max_bytes(),
        })?;
        let c = code.to_wire().to_be_bytes();
        let l = len.to_be_bytes();
        Ok([c[0], c[1], l[0], l[1], l[2], l[3]])
    }
}

/// Parses a C2 record header, applying the same cap.
///
/// # Errors
///
/// As [`C1Frame::parse_header`].
pub fn parse_c2_length(header: &[u8]) -> Result<usize, Reject> {
    if header.len() < C2_HEADER_BYTES {
        return Err(Reject::Unparseable {
            parser_id: Channel::ControlAndTelemetry.parser_id(),
        });
    }
    let declared = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    check_declared_length(declared, Channel::ControlAndTelemetry)
}

/// The header for a C2 record.
///
/// # Errors
///
/// [`Reject::SizeExceeded`] above the C1/C2 cap.
pub fn c2_header_bytes(body_len: usize) -> Result<[u8; 4], Reject> {
    let checked = check_declared_length(body_len, Channel::ControlAndTelemetry)?;
    let len = u32::try_from(checked).map_err(|_| Reject::SizeExceeded {
        parser_id: Channel::ControlAndTelemetry.parser_id(),
        observed: body_len,
        limit: Channel::ControlAndTelemetry.max_bytes(),
    })?;
    Ok(len.to_be_bytes())
}

/// `limits.json` `envelope.c2_inline_document_max_bytes`.
///
/// Restated because `twinvpn-schema` exposes the cap only as the
/// [`twinvpn_schema::validate::check_c2_inline_document`] predicate;
/// `the_inline_document_cap_is_the_frozen_sixteen_kib` fails if the frozen value
/// ever moves.
pub const INLINE_DOCUMENT_MAX_BYTES: usize = 16_384;

/// Whether a state document is pushed inline or announced by reference.
///
/// ADR-0002 §11.4: `≤ 16 KiB` inline; above it a `StateDocumentAvailable`
/// reference the device pulls with `GetStateDocument`. The cap is lower than the
/// envelope cap "on purpose, so a single policy bundle cannot monopolise a
/// stream", and the decision is delegated to the frozen validator rather than to
/// a local comparison so the two cannot drift.
#[must_use]
pub fn fits_inline(document: &[u8]) -> bool {
    twinvpn_schema::validate::check_c2_inline_document(document).is_ok()
}

#[cfg(test)]
mod tests {
    use super::{
        c2_header_bytes, fits_inline, parse_c2_length, C1Frame, CommandCode,
        INLINE_DOCUMENT_MAX_BYTES,
    };
    use crate::command::Command;
    use twinvpn_service_common::Channel;

    #[test]
    fn every_command_has_exactly_one_code_and_it_round_trips() {
        let mut seen = std::collections::BTreeSet::new();
        for c in Command::ALL {
            let code = CommandCode::of(c);
            assert!(seen.insert(code.to_wire()), "duplicate code for {c:?}");
            assert_eq!(code.command(), c);
            assert_eq!(CommandCode::from_wire(code.to_wire()), Some(code));
        }
        assert_eq!(seen.len(), Command::ALL.len());
    }

    #[test]
    fn an_unassigned_code_is_rejected_rather_than_guessed() {
        assert!(CommandCode::from_wire(0).is_none());
        assert!(CommandCode::from_wire(9).is_none());
        assert!(CommandCode::from_wire(u16::MAX).is_none());
        let header = [0x00, 0x63, 0, 0, 0, 4]; // 99 is not a command
        let err = C1Frame::parse_header(&header).expect_err("unassigned");
        assert_eq!(err.reason_code().as_str(), "PROTO.UNPARSEABLE_ENVELOPE");
    }

    #[test]
    fn a_hostile_declared_length_is_refused_before_any_allocation() {
        // ownership.md §6 rule 9: the check precedes the allocation. Six bytes
        // of input must not be able to ask for four gigabytes of buffer.
        let header = [0x00, 0x0c, 0xff, 0xff, 0xff, 0xff];
        let err = C1Frame::parse_header(&header).expect_err("over cap");
        assert_eq!(err.reason_code().as_str(), "PROTO.SIZE_EXCEEDED");
        // And exactly at the cap is fine.
        let cap = u32::try_from(Channel::ControlAndTelemetry.max_bytes()).expect("cap fits");
        let c = cap.to_be_bytes();
        let ok = [0x00, 0x0c, c[0], c[1], c[2], c[3]];
        assert_eq!(
            C1Frame::parse_header(&ok).expect("at cap").body_len,
            Channel::ControlAndTelemetry.max_bytes()
        );
    }

    #[test]
    fn a_short_header_is_a_reject_not_a_panic() {
        for n in 0..6 {
            assert!(C1Frame::parse_header(&vec![0u8; n]).is_err());
        }
        for n in 0..4 {
            assert!(parse_c2_length(&vec![0u8; n]).is_err());
        }
    }

    #[test]
    fn the_bound_is_applied_on_the_way_out_too() {
        assert!(C1Frame::header_bytes(CommandCode::PutPolicy, 10).is_ok());
        assert!(C1Frame::header_bytes(CommandCode::PutPolicy, 65_537).is_err());
        assert!(c2_header_bytes(65_537).is_err());
    }

    #[test]
    fn headers_round_trip() {
        let h = C1Frame::header_bytes(CommandCode::RevokeDevice, 1234).expect("encodes");
        let f = C1Frame::parse_header(&h).expect("decodes");
        assert_eq!(f.code, CommandCode::RevokeDevice);
        assert_eq!(f.body_len, 1234);
        let h2 = c2_header_bytes(77).expect("encodes");
        assert_eq!(parse_c2_length(&h2).expect("decodes"), 77);
    }

    #[test]
    fn the_inline_document_cap_is_the_frozen_sixteen_kib() {
        assert_eq!(INLINE_DOCUMENT_MAX_BYTES, 16_384);
        assert!(fits_inline(&vec![0u8; 16_384]));
        assert!(!fits_inline(&vec![0u8; 16_385]));
        assert!(
            twinvpn_schema::limits::LIMITS_JSON.contains("\"c2_inline_document_max_bytes\": 16384"),
            "the frozen inline cap moved"
        );
    }
}
