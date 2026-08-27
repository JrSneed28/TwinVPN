//! Byte builders shared by the unit tests and the integration tests.
//!
//! Nothing here is used by the service at runtime.

use bytes::Bytes;
use prost::Message as _;
use twinvpn_schema::v1;

use crate::frame::{Opcode, HEADER_LEN, MAGIC, WIRE_VERSION};

/// A payload nested `depth` levels deep, for the depth-cap tests.
///
/// # Panics
///
/// If a level's body exceeds 127 bytes.
#[must_use]
pub fn nested(depth: usize) -> Bytes {
    let mut body = vec![0x08, 0x01];
    for _ in 1..depth {
        assert!(body.len() < 128, "testkit::nested only builds short bodies");
        let mut wrapped = Vec::with_capacity(body.len() + 2);
        wrapped.push(0x0a);
        wrapped.push(u8::try_from(body.len()).expect("checked above"));
        wrapped.extend_from_slice(&body);
        body = wrapped;
    }
    Bytes::from(body)
}

/// A `PublishPresenceRequest` asserting `state` for `device_id` until
/// `expires_at_ms`.
#[must_use]
pub fn heartbeat(
    device_id: [u8; 32],
    state: v1::PresenceState,
    expires_at_ms: u64,
) -> v1::PublishPresenceRequest {
    v1::PublishPresenceRequest {
        metadata: Some(v1::MessageMetadata::default()),
        heartbeat: Some(v1::Heartbeat {
            presence: Some(v1::Presence {
                device_id: device_id.to_vec(),
                state: state as i32,
                reachability: Some(v1::Reachability {
                    has_v4: true,
                    has_v6: true,
                    nat64_present: false,
                    network_class: v1::NetworkClass::Wifi as i32,
                }),
                expires_at_ms,
            }),
            ttl_ms: 60_000,
        }),
    }
}

/// A complete `PUBLISH` frame.
///
/// # Panics
///
/// Never: encoding into a `Vec` cannot fail.
#[must_use]
pub fn publish_frame(request: &v1::PublishPresenceRequest) -> Vec<u8> {
    let mut buf = Vec::with_capacity(request.encoded_len());
    request.encode(&mut buf).expect("a Vec never fails to grow");
    crate::frame::encode(Opcode::Publish, &buf)
}

/// A frame whose header declares `declared` body bytes while carrying `body`.
#[must_use]
pub fn raw_frame(opcode_byte: u8, version: u8, declared: u32, body: &[u8]) -> Vec<u8> {
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
pub fn declared_length_frame(opcode: Opcode, declared: u32, body: &[u8]) -> Vec<u8> {
    raw_frame(opcode.as_wire(), WIRE_VERSION, declared, body)
}
