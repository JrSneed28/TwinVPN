//! Wire encodings this service produces.
//!
//! Split out of [`crate::server`] so the connection loop reads as a sequence of
//! decisions rather than a mixture of decisions and serialisation — and so the
//! one place a `ServiceError` becomes bytes is a place a reviewer can find.

use std::net::{IpAddr, SocketAddr};

use bytes::Bytes;
use twinvpn_schema::v1;
use twinvpn_service_common::ServiceError;

/// Encodes a `ServiceError` as `twinvpn.v1.ErrorEnvelope`.
///
/// `ServiceError` has no message field and its envelope carries only the
/// registered code plus **this build's** registry attributes, so there is no
/// path by which an internal error string reaches the wire.
///
/// # Panics
///
/// Never: encoding into a `Vec` cannot fail.
#[must_use]
pub fn encode_error(e: &ServiceError) -> Vec<u8> {
    use prost::Message as _;
    let env: v1::ErrorEnvelope = e.envelope();
    let mut buf = Vec::with_capacity(env.encoded_len());
    env.encode(&mut buf).expect("a Vec never fails to grow");
    buf
}

/// Encodes an observed source address as `twinvpn.v1.Endpoint`.
///
/// Both families are first-class here: `Endpoint`'s `IPAddress` is a `oneof`, so
/// "we have a v4 story and a v6 story" is not sayable — ADR-0010 R1 expressed in
/// the schema rather than in a runtime branch.
///
/// # Panics
///
/// Never: the only fallible step is encoding into a `Vec`, which cannot fail.
#[must_use]
pub fn encode_endpoint(peer: SocketAddr) -> Bytes {
    use prost::Message as _;
    let address = match peer.ip() {
        IpAddr::V4(v4) => v1::ip_address::Address::V4(v1::IPv4Address {
            octets: v4.octets().to_vec(),
        }),
        IpAddr::V6(v6) => v1::ip_address::Address::V6(v1::IPv6Address {
            octets: v6.octets().to_vec(),
            // A rendezvous connection never arrives on a link-local source, and
            // an invented zone index would be a lie a peer might act on.
            zone_index: 0,
        }),
    };
    let ep = v1::Endpoint {
        address: Some(v1::IpAddress {
            address: Some(address),
        }),
        port: u32::from(peer.port()),
    };
    let mut buf = Vec::with_capacity(ep.encoded_len());
    ep.encode(&mut buf).expect("a Vec never fails to grow");
    Bytes::from(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn an_endpoint_carries_the_family_it_arrived_on() {
        for (addr, is_v6) in [
            (IpAddr::V4(Ipv4Addr::LOCALHOST), false),
            (IpAddr::V6(Ipv6Addr::LOCALHOST), true),
        ] {
            let bytes = encode_endpoint(SocketAddr::new(addr, 443));
            let ep = v1::Endpoint::decode(&bytes[..]).unwrap();
            let parsed = twinvpn_schema::validate::endpoint(&ep).unwrap();
            assert_eq!(parsed.family() == twinvpn_types::AddressFamily::V6, is_v6);
        }
    }

    #[test]
    fn an_error_envelope_carries_the_code_and_no_message() {
        let e = crate::ingress::channel_binding_mismatch();
        let bytes = encode_error(&e);
        let env = v1::ErrorEnvelope::decode(&bytes[..]).unwrap();
        assert_eq!(env.reason_code, "CONTROL.CHANNEL_BINDING_MISMATCH");
        assert_eq!(env.domain, "CONTROL");
    }
}
