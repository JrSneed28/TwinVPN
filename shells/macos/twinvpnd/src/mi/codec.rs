//! The transport: reading and writing frames on an `AF_UNIX` stream.
//!
//! **Authority:** ADR-0017 §11.2 (the `SOCK_STREAM` fallback), §11.3 (the 1 MiB
//! cap, "enforced before parse"); `docs/implementation/ownership.md` §6 rules 9
//! and 10, §9.6 **X-4**.
//!
//! # The framing moved; the transport did not
//!
//! This file used to hold the whole codec — the cap, the prefix, the error type
//! and its `reason_code` — and so did `shells/linux` and `shells/windows`, in
//! two other dialects. X-4 assigned the envelope to `twinvpn-mgmt` and it now
//! lives there once: [`twinvpn_mgmt::envelope::declared_length`],
//! [`twinvpn_mgmt::envelope::encode_frame`],
//! [`twinvpn_mgmt::envelope::decode_frame`] and
//! [`twinvpn_mgmt::envelope::FrameError`].
//!
//! **Two of this shell's readings won and are now every carriage's:** a
//! zero-length frame is [`FrameError::Empty`] — a desynchronised stream, not a
//! keepalive and not a body that failed to parse — and `reason_code` returns a
//! typed [`twinvpn_types::ReasonCode`] resolved through
//! `twinvpn_mgmt::codes::substituted`, rather than a hard-coded string literal
//! beside the substitution table.
//!
//! # What is still this file's
//!
//! [`read_frame`], and one decision inside it: **a clean close between frames is
//! `Ok(None)` and not an error.** `shells/linux` answers `Err(Closed)` for the
//! same event. Both are defensible; neither is a judgement about bytes, which is
//! why the shared codec has no variant for it and each transport keeps its own
//! answer.
//!
//! The cap is still applied to the prefix **before the body buffer exists** — a
//! caller that read the body first and checked afterwards would have already
//! allocated whatever a hostile client declared. It is `twinvpn-mgmt`'s check
//! now, so all three carriages enforce it the same way.

pub use twinvpn_mgmt::envelope::{decode_frame, encode_frame, FrameError, MAX_ENVELOPE_BYTES};

use crate::mi::wire::{MgmtEnvelope, LENGTH_PREFIX_BYTES};

/// The declared length in a prefix, refusing an over-cap or zero one.
///
/// Kept under this name because it is what this shell's callers and tests say;
/// the body is `twinvpn-mgmt`'s.
///
/// # Errors
///
/// [`FrameError::TooLarge`] or [`FrameError::Empty`].
pub fn frame_length(prefix: [u8; LENGTH_PREFIX_BYTES]) -> Result<usize, FrameError> {
    twinvpn_mgmt::envelope::declared_length(prefix)
}

/// Reads one frame from an async stream.
///
/// **The cap is applied to the prefix before the body buffer exists.** A caller
/// that read the body first and checked afterwards would have already allocated
/// whatever a hostile client declared.
///
/// # Errors
///
/// [`FrameError`] on a protocol fault; `Ok(None)` when the peer closed cleanly
/// **between** frames, which is not a fault.
pub async fn read_frame<R>(reader: &mut R) -> Result<Option<MgmtEnvelope>, FrameError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    #![allow(clippy::items_after_statements)]
    use tokio::io::AsyncReadExt as _;

    let mut prefix = [0u8; LENGTH_PREFIX_BYTES];
    match reader.read_exact(&mut prefix).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(_) => return Err(FrameError::Truncated),
    }
    let declared = frame_length(prefix)?;
    let mut body = vec![0u8; declared];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|_| FrameError::Truncated)?;
    twinvpn_mgmt::envelope::decode_body(&body).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mi::wire::{Body, Hello, MI_VERSION, MI_VERSION_MIN};

    fn envelope() -> MgmtEnvelope {
        MgmtEnvelope {
            mi_version: MI_VERSION,
            request_id: vec![7],
            correlation_id: Vec::new(),
            seq: 0,
            idempotency_key: Vec::new(),
            as_of_ms: 0,
            body: Body::Hello(Hello {
                mi_version_min: MI_VERSION_MIN,
                mi_version_max: MI_VERSION,
                client_kind: "cli".to_owned(),
                client_version: "0.1.0".to_owned(),
                requested_scopes: Vec::new(),
                subscribe_topics: Vec::new(),
            }),
        }
    }

    #[test]
    fn a_frame_round_trips() {
        let bytes = encode_frame(&envelope()).expect("encodes");
        assert_eq!(decode_frame(&bytes).expect("decodes"), envelope());
    }

    #[test]
    fn an_over_cap_length_is_refused_from_the_prefix_alone() {
        // The whole point: no body is supplied, and the refusal still happens. A
        // decoder that allocated first would have taken a gigabyte to find out.
        let prefix = u32::try_from(MAX_ENVELOPE_BYTES + 1)
            .expect("fits")
            .to_be_bytes();
        assert_eq!(
            frame_length(prefix),
            Err(FrameError::TooLarge {
                declared: MAX_ENVELOPE_BYTES + 1
            })
        );
        assert_eq!(
            frame_length(u32::MAX.to_be_bytes()),
            Err(FrameError::TooLarge {
                declared: u32::MAX as usize
            })
        );
        // And it names ADR-0017 §11.3's own code. Before `registry_version` 2
        // this was PROTO.SIZE_EXCEEDED, forced by W-18: a MANAGEMENT framing
        // refusal degraded on an older client to "the peer protocol is wrong",
        // which is a different diagnosis with a different next action.
        assert_eq!(
            FrameError::TooLarge { declared: 0 }.reason_code(),
            twinvpn_mgmt::codes::substituted("MGMT.PAYLOAD_TOO_LARGE").expect("registered")
        );
        assert_eq!(
            FrameError::TooLarge { declared: 0 }.reason_code().as_str(),
            "MGMT.PAYLOAD_TOO_LARGE"
        );
    }

    #[test]
    fn the_largest_legal_length_is_accepted() {
        let prefix = u32::try_from(MAX_ENVELOPE_BYTES)
            .expect("fits")
            .to_be_bytes();
        assert_eq!(frame_length(prefix), Ok(MAX_ENVELOPE_BYTES));
    }

    #[test]
    fn a_zero_length_frame_is_a_desynchronised_stream_and_not_a_keepalive() {
        assert_eq!(frame_length([0, 0, 0, 0]), Err(FrameError::Empty));
    }

    #[test]
    fn a_body_shorter_than_its_prefix_is_truncated_and_never_parsed_from_what_arrived() {
        let mut bytes = encode_frame(&envelope()).expect("encodes");
        bytes.truncate(bytes.len() - 1);
        assert_eq!(decode_frame(&bytes), Err(FrameError::Truncated));
        assert_eq!(decode_frame(&[]), Err(FrameError::Truncated));
        assert_eq!(decode_frame(&[0, 0]), Err(FrameError::Truncated));
    }

    #[test]
    fn a_body_that_is_not_an_envelope_is_malformed_and_not_a_panic() {
        let mut bytes = vec![0, 0, 0, 4];
        bytes.extend_from_slice(b"junk");
        assert_eq!(decode_frame(&bytes), Err(FrameError::Malformed));
    }

    #[tokio::test]
    async fn the_async_reader_refuses_an_over_cap_prefix_before_it_reads_a_body() {
        // The hostile case: four bytes claiming four gigabytes, and nothing after
        // them. A reader that trusted the prefix would block forever holding a
        // 4 GiB buffer.
        let mut stream = std::io::Cursor::new(u32::MAX.to_be_bytes().to_vec());
        assert_eq!(
            read_frame(&mut stream).await,
            Err(FrameError::TooLarge {
                declared: u32::MAX as usize
            })
        );
    }

    #[tokio::test]
    async fn a_clean_close_between_frames_is_none_and_not_an_error() {
        let mut stream = std::io::Cursor::new(Vec::new());
        assert_eq!(read_frame(&mut stream).await, Ok(None));
    }

    #[tokio::test]
    async fn a_close_inside_a_frame_is_an_error() {
        let mut bytes = encode_frame(&envelope()).expect("encodes");
        bytes.truncate(6);
        let mut stream = std::io::Cursor::new(bytes);
        assert_eq!(read_frame(&mut stream).await, Err(FrameError::Truncated));
    }

    #[tokio::test]
    async fn several_frames_read_back_in_order() {
        let mut bytes = encode_frame(&envelope()).expect("encodes");
        bytes.extend(encode_frame(&envelope()).expect("encodes"));
        let mut stream = std::io::Cursor::new(bytes);
        assert_eq!(read_frame(&mut stream).await, Ok(Some(envelope())));
        assert_eq!(read_frame(&mut stream).await, Ok(Some(envelope())));
        assert_eq!(read_frame(&mut stream).await, Ok(None));
    }
}
