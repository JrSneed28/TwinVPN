//! Reading and writing length-prefixed frames on a named pipe.
//!
//! **Authority:** [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.3 (the 1 MiB cap, enforced **before parse**), §11.2 (the Windows
//! message-mode row), MI-I5-2.
//!
//! # The cap is checked before the buffer exists
//!
//! [`read_frame`] reads four bytes, asks [`wire::declared_length`] whether the
//! value is admissible, and **only then** allocates. `ownership.md` §6 rule 9
//! and rule 10 are the same requirement stated twice: validate a declared length
//! before any allocation proportional to it, and bound every allocation an
//! untrusted input can drive. A local socket is still an untrusted input — MI's
//! own threat table has "a local attacker can deny *management*", and an
//! unbounded read here is how they would.
//!
//! # MI-I5-2: there is no blocking send primitive
//!
//! > non-blocking offer only — **no blocking send primitive may exist**
//!
//! [`write_frame`] writes to a pipe and is used only for a *response* on the
//! connection that asked for it. The **event** path never calls it directly: it
//! goes through the server's bounded per-connection queue, whose `try_send` is
//! the offer MI-I5-2 requires. A blocking send on an event would let one slow
//! client stall the agent, which is the inversion ADR-0017 §11.10's whole
//! backpressure ladder exists to prevent.

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::wire::{self, FrameError, MgmtEnvelope, LENGTH_PREFIX_BYTES};

/// Reads one frame.
///
/// # Errors
///
/// [`FrameError::Closed`] on a clean EOF, [`FrameError::TooLarge`] on an
/// over-cap declared length — **before** the body is read — and
/// [`FrameError::Malformed`] on bytes that do not decode.
pub async fn read_frame<R>(reader: &mut R) -> Result<MgmtEnvelope, FrameError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut prefix = [0u8; LENGTH_PREFIX_BYTES];
    match reader.read_exact(&mut prefix).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(FrameError::Closed),
        Err(e) => return Err(FrameError::Transport(e)),
    }
    // The check that makes the allocation below bounded. It happens here, on
    // four bytes, and not after a read.
    let declared = wire::declared_length(prefix)?;
    let mut body = vec![0u8; declared];
    match reader.read_exact(&mut body).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(FrameError::Closed),
        Err(e) => return Err(FrameError::Transport(e)),
    }
    wire::decode_body(&body)
}

/// Writes one frame.
///
/// # Errors
///
/// [`FrameError::TooLarge`] if this side would emit a frame it would itself
/// refuse, or the transport's error.
pub async fn write_frame<W>(writer: &mut W, envelope: &MgmtEnvelope) -> Result<(), FrameError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let frame = wire::encode_frame(envelope)?;
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mi::wire::{Body, Request, MI_VERSION};

    fn envelope() -> MgmtEnvelope {
        MgmtEnvelope {
            mi_version: MI_VERSION,
            request_id: vec![9; 16],
            correlation_id: Vec::new(),
            seq: 0,
            idempotency_key: Vec::new(),
            as_of_ms: 1,
            body: Body::Request(Request {
                operation: "status.get".to_owned(),
                params: Vec::new(),
                if_version: None,
            }),
        }
    }

    #[tokio::test]
    async fn a_frame_round_trips_over_a_stream() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &envelope()).await.expect("writes");
        let mut cursor = std::io::Cursor::new(buffer);
        let read = read_frame(&mut cursor).await.expect("reads");
        assert_eq!(read, envelope());
    }

    #[tokio::test]
    async fn two_frames_do_not_desynchronize_the_stream() {
        // The cost §11.2 names for taking the SOCK_STREAM fallback: message
        // boundaries are ours to keep. This is the test that keeps them.
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &envelope()).await.expect("writes");
        write_frame(&mut buffer, &envelope()).await.expect("writes");
        let mut cursor = std::io::Cursor::new(buffer);
        assert_eq!(read_frame(&mut cursor).await.expect("first"), envelope());
        assert_eq!(read_frame(&mut cursor).await.expect("second"), envelope());
        assert!(matches!(
            read_frame(&mut cursor).await.expect_err("eof"),
            FrameError::Closed
        ));
    }

    #[tokio::test]
    async fn an_over_cap_declared_length_is_refused_before_the_body_is_read() {
        // A hostile peer that declares 4 GiB and sends nothing must not cause a
        // 4 GiB allocation, and must not cause a wait either.
        let huge = u32::MAX.to_be_bytes();
        let mut cursor = std::io::Cursor::new(huge.to_vec());
        let err = read_frame(&mut cursor).await.expect_err("refused");
        match err {
            FrameError::TooLarge { declared } => {
                assert_eq!(declared, u32::MAX as usize);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_truncated_body_is_a_clean_close_not_a_hang() {
        // §11.7: "Never a parse error, never a hang, never a generic failure."
        let mut frame = Vec::new();
        write_frame(&mut frame, &envelope()).await.expect("writes");
        frame.truncate(frame.len() - 3);
        let mut cursor = std::io::Cursor::new(frame);
        assert!(matches!(
            read_frame(&mut cursor).await.expect_err("truncated"),
            FrameError::Closed
        ));
    }

    #[tokio::test]
    async fn a_zero_length_frame_decodes_to_a_typed_reject() {
        let mut cursor = std::io::Cursor::new(0u32.to_be_bytes().to_vec());
        assert!(matches!(
            read_frame(&mut cursor).await.expect_err("empty body"),
            FrameError::Malformed
        ));
    }
}
