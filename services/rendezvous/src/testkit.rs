//! Byte builders shared by the unit tests, the integration tests and the
//! `hostile` smoke client.
//!
//! It lives in the library rather than in one test file because
//! `tests/hostile_input.rs` drives the same bytes down a **real socket** that
//! `src/frame.rs`'s unit tests drive through the parser directly, and two
//! divergent builders would let those two agree with each other and disagree
//! with the wire.
//!
//! Nothing here is used by the service at runtime.

use bytes::Bytes;

use crate::frame::{Opcode, HEADER_LEN, MAGIC, WIRE_VERSION};

/// A well-formed C4 payload of exactly `len` bytes.
///
/// The bytes are a repeated `field 1: varint` record sequence, so
/// `twinvpn_schema::depth::check` sees a legal depth-1 message. That matters:
/// the C4 cap check is a *shape* check over raw octets, and a payload of zeros
/// is not a protobuf record sequence at all, so it would be refused for the
/// wrong reason and a size test would silently stop testing size.
///
/// # Panics
///
/// On `len == 1` or `len == 2` with an odd request that cannot be expressed;
/// `len` must be 0, 2, or ≥ 3.
#[must_use]
pub fn payload(len: usize) -> Bytes {
    assert!(len != 1, "a 1-byte protobuf record sequence does not exist");
    let mut out = Vec::with_capacity(len);
    if len % 2 == 1 {
        // field 1, varint 128 — three bytes, so an odd total is reachable.
        out.extend_from_slice(&[0x08, 0x80, 0x01]);
    }
    while out.len() < len {
        // field 1, varint 1.
        out.extend_from_slice(&[0x08, 0x01]);
    }
    out.truncate(len);
    Bytes::from(out)
}

/// A payload nested `depth` levels deep, for the depth-cap tests.
///
/// Each level is `field 1, wire type 2` wrapping the level below, which is
/// exactly the shape the guard counts.
///
/// # Panics
///
/// If a level's body exceeds 127 bytes, which the single-byte length prefix
/// below cannot express. Callers use small depths.
#[must_use]
pub fn nested(depth: usize) -> Bytes {
    let mut body = vec![0x08, 0x01];
    for _ in 1..depth {
        assert!(body.len() < 128, "testkit::nested only builds short bodies");
        let mut wrapped = Vec::with_capacity(body.len() + 2);
        wrapped.push(0x0a); // field 1, wire type 2
        wrapped.push(u8::try_from(body.len()).expect("checked above"));
        wrapped.extend_from_slice(&body);
        body = wrapped;
    }
    Bytes::from(body)
}

/// A complete `CALL` frame for `target` carrying `payload`.
#[must_use]
pub fn call_frame(target: [u8; 32], payload: &[u8]) -> Vec<u8> {
    let mut body = target.to_vec();
    body.extend_from_slice(payload);
    crate::frame::encode(Opcode::Call, &body)
}

/// A frame whose header **declares** `declared` body bytes while carrying
/// `body`, so a test can present a hostile length that the honest encoder would
/// never produce.
#[must_use]
pub fn raw_frame(opcode_byte: u8, version: u8, declared: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&MAGIC);
    out.push(version);
    out.push(opcode_byte);
    out.extend_from_slice(&declared.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// A frame with the honest wire version and a hostile declared length.
#[must_use]
pub fn declared_length_frame(opcode: Opcode, declared: u16, body: &[u8]) -> Vec<u8> {
    raw_frame(opcode.as_wire(), WIRE_VERSION, declared, body)
}
