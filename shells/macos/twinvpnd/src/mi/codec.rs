//! The framing: a 4-byte big-endian length prefix, and the cap enforced
//! **before** the allocation.
//!
//! **Authority:** ADR-0017 §11.2 (the `SOCK_STREAM` fallback), §11.3 (the 1 MiB
//! cap, "enforced before parse"); `docs/implementation/ownership.md` §6 rules 9
//! and 10.
//!
//! # Why the cap is checked twice and the allocation once
//!
//! §6 rule 9 is exact: validate "*before* any allocation proportional to a
//! declared length. A violation is a typed reject with a `PROTO.*` code — never a
//! truncation, never a pad, never a silent accept." A local socket is not an
//! untrusted network, but the rule does not say it is, and the failure mode is the
//! same: a four-byte prefix from a client this agent has not yet authenticated is
//! a declared length, and `Vec::with_capacity` on it is a remote OOM.
//!
//! So [`decode_frame`] reads the prefix, compares it, and only then touches a
//! buffer — and [`encode_frame`] refuses to *emit* an over-cap envelope too,
//! because an agent that sent one would produce a frame no conforming client
//! could accept and would have no way to say why.

use crate::mi::wire::{MgmtEnvelope, LENGTH_PREFIX_BYTES, MAX_ENVELOPE_BYTES};

/// Why a frame could not be read or written.
///
/// Every variant maps to a registered `reason_code`; none of them is a bare
/// number or a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// The declared length exceeds §11.3's cap. **Rejected before allocation.**
    #[error("the envelope exceeds the 1 MiB cap")]
    TooLarge,
    /// A zero-length frame. Not a message, and not a keepalive: this protocol has
    /// none, so a zero prefix is a desynchronised stream.
    #[error("a zero-length frame")]
    Empty,
    /// The bytes did not parse.
    #[error("the envelope did not parse")]
    Malformed,
    /// The peer closed mid-frame.
    #[error("the stream ended inside a frame")]
    Truncated,
}

impl FrameError {
    /// The registered code.
    #[must_use]
    pub fn reason_code(self) -> twinvpn_types::ReasonCode {
        match self {
            // ADR-0017 §11.3 names `MGMT.PAYLOAD_TOO_LARGE`, which the frozen
            // registry does not contain — `ownership.md` §8 **W-18** measures 38
            // `MGMT` codes named across the corpus against 4 registered. The
            // substitution and ITS COST are already recorded once, in
            // `twinvpn_mgmt::codes::SUBSTITUTIONS`, and this build takes it from
            // there rather than choosing a second replacement for the same
            // condition: two shells substituting differently for one ADR spelling
            // would be worse than the substitution itself.
            FrameError::TooLarge => twinvpn_mgmt::codes::substituted("MGMT.PAYLOAD_TOO_LARGE")
                .unwrap_or(twinvpn_types::codes::PROTO_SIZE_EXCEEDED),
            FrameError::Empty | FrameError::Malformed => {
                twinvpn_types::codes::PROTO_UNPARSEABLE_ENVELOPE
            }
            FrameError::Truncated => twinvpn_types::codes::PROTO_MALFORMED_MESSAGE,
        }
    }
}

/// Encodes one envelope.
///
/// # Errors
///
/// [`FrameError::TooLarge`] if the encoded form exceeds the cap — refused rather
/// than sent, because a frame no conforming client can accept is worse than an
/// error the agent can name.
pub fn encode_frame(envelope: &MgmtEnvelope) -> Result<Vec<u8>, FrameError> {
    let body = serde_json::to_vec(envelope).map_err(|_| FrameError::Malformed)?;
    if body.len() > MAX_ENVELOPE_BYTES {
        return Err(FrameError::TooLarge);
    }
    let length = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge)?;
    let mut out = Vec::with_capacity(LENGTH_PREFIX_BYTES + body.len());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Reads the declared length out of a prefix, refusing an over-cap one.
///
/// Separated from the read so a test can see the refusal **without** supplying a
/// megabyte of bytes to go with it — which is the whole point of checking first.
///
/// # Errors
///
/// [`FrameError::TooLarge`] or [`FrameError::Empty`].
pub fn frame_length(prefix: [u8; LENGTH_PREFIX_BYTES]) -> Result<usize, FrameError> {
    let declared = u32::from_be_bytes(prefix) as usize;
    if declared == 0 {
        return Err(FrameError::Empty);
    }
    if declared > MAX_ENVELOPE_BYTES {
        return Err(FrameError::TooLarge);
    }
    Ok(declared)
}

/// Decodes one complete frame — prefix and body.
///
/// # Errors
///
/// [`FrameError`]. A frame whose body is shorter than its prefix declares is
/// [`FrameError::Truncated`] rather than being parsed from what arrived.
pub fn decode_frame(bytes: &[u8]) -> Result<MgmtEnvelope, FrameError> {
    let prefix: [u8; LENGTH_PREFIX_BYTES] = bytes
        .get(..LENGTH_PREFIX_BYTES)
        .and_then(|s| s.try_into().ok())
        .ok_or(FrameError::Truncated)?;
    let declared = frame_length(prefix)?;
    let body = bytes
        .get(LENGTH_PREFIX_BYTES..LENGTH_PREFIX_BYTES + declared)
        .ok_or(FrameError::Truncated)?;
    serde_json::from_slice(body).map_err(|_| FrameError::Malformed)
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
    serde_json::from_slice(&body).map_err(|_| FrameError::Malformed)
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
        assert_eq!(frame_length(prefix), Err(FrameError::TooLarge));
        assert_eq!(
            frame_length(u32::MAX.to_be_bytes()),
            Err(FrameError::TooLarge)
        );
        // And it names the code W-18 forces in place of ADR-0017 §11.3's
        // `MGMT.PAYLOAD_TOO_LARGE`, from the one place that substitution is
        // recorded.
        assert_eq!(
            FrameError::TooLarge.reason_code(),
            twinvpn_mgmt::codes::substituted("MGMT.PAYLOAD_TOO_LARGE").expect("recorded")
        );
        assert_eq!(
            FrameError::TooLarge.reason_code().as_str(),
            "PROTO.SIZE_EXCEEDED"
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
        assert_eq!(read_frame(&mut stream).await, Err(FrameError::TooLarge));
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
