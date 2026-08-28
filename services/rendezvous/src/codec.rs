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

/// Encodes an observed source address as `twinvpn.v1.Endpoint`, or `None` when
/// the address this connection arrived on has no canonical wire form.
///
/// Both families are first-class here: `Endpoint`'s `IPAddress` is a `oneof`, so
/// "we have a v4 story and a v6 story" is not sayable — ADR-0010 R1 expressed in
/// the schema rather than in a runtime branch.
///
/// # Why an IPv4-mapped source is unmapped, and why that is not "normalizing"
///
/// A listener bound to `[::]` is dual-stack on every platform this service runs
/// on, so an **IPv4** peer arrives with `peer.ip()` reading `::ffff:a.b.c.d`.
/// That is an artifact of the sockets API describing a v4 peer, not a v6 peer:
/// the packets carried an IPv4 header and the reflexive address the far side
/// needs is the v4 one. `twinvpn-types` rejects the mapped form outright
/// (`V6Addr::new` → `TypeError::Ipv4MappedIpv6`), so emitting it produced an
/// `Endpoint` that **every conformant client must refuse** — which silently
/// costs a dual-stack deployment its whole server-reflexive rung (ADR-0004 §5),
/// the one candidate class this service is the source of.
///
/// This is emission of *our own observation*, not normalization of peer input.
/// `validate::ip_prefix`'s "rejected, never normalized" rule is about attacker
/// bytes reaching a policy check; there are no peer bytes here at all — the
/// address came from the kernel, and unmapping recovers the family the peer
/// actually used.
///
/// # Why `None` rather than a best effort
///
/// The remaining unrepresentable case is a link-local source (`fe80::/10`),
/// which RFC 4007 makes unusable without a zone index — and this process cannot
/// know the peer's zone, only its own. `docs/protocol.md` §10.4 requires a
/// link-local candidate to carry `zone_index`, so there are exactly two honest
/// options: invent a zone (a lie a peer would act on) or say nothing. It says
/// nothing, and the caller sends no `REFLEXIVE` frame.
///
/// The check is the **frozen validator itself** rather than a re-derivation of
/// its rules, so "this service never emits an `Endpoint` a peer must reject" is
/// proved against the contract rather than asserted against a copy of it.
///
/// # Panics
///
/// Never: the only fallible step is encoding into a `Vec`, which cannot fail.
#[must_use]
pub fn encode_endpoint(peer: SocketAddr) -> Option<Bytes> {
    use prost::Message as _;
    // A v4 peer on a dual-stack listener is a v4 peer.
    let ip = match peer.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    };
    let address = match ip {
        IpAddr::V4(v4) => v1::ip_address::Address::V4(v1::IPv4Address {
            octets: v4.octets().to_vec(),
        }),
        IpAddr::V6(v6) => v1::ip_address::Address::V6(v1::IPv6Address {
            octets: v6.octets().to_vec(),
            // A zone index this process could supply would be its own, not the
            // peer's, and an invented one is a lie a peer might act on. A
            // link-local source therefore fails the check below and is answered
            // with silence rather than with a candidate that cannot be used.
            zone_index: 0,
        }),
    };
    let ep = v1::Endpoint {
        address: Some(v1::IpAddress {
            address: Some(address),
        }),
        port: u32::from(peer.port()),
    };
    // The contract's own validator, not a restatement of it.
    twinvpn_schema::validate::endpoint(&ep).ok()?;
    let mut buf = Vec::with_capacity(ep.encoded_len());
    ep.encode(&mut buf).expect("a Vec never fails to grow");
    Some(Bytes::from(buf))
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
            let bytes = encode_endpoint(SocketAddr::new(addr, 443)).expect("a canonical address");
            let ep = v1::Endpoint::decode(&bytes[..]).unwrap();
            let parsed = twinvpn_schema::validate::endpoint(&ep).unwrap();
            assert_eq!(parsed.family() == twinvpn_types::AddressFamily::V6, is_v6);
        }
    }

    #[test]
    fn a_v4_peer_on_a_dual_stack_listener_is_reported_as_v4() {
        // What the kernel hands a `[::]` listener when an IPv4 client connects.
        // Reported as `::ffff:198.51.100.7` this endpoint is one every conformant
        // client MUST reject, and a dual-stack deployment loses its whole
        // server-reflexive rung without a single error anywhere.
        let mapped = IpAddr::V6(Ipv4Addr::new(198, 51, 100, 7).to_ipv6_mapped());
        let bytes =
            encode_endpoint(SocketAddr::new(mapped, 51_820)).expect("unmapped, not dropped");
        let ep = v1::Endpoint::decode(&bytes[..]).unwrap();
        let parsed = twinvpn_schema::validate::endpoint(&ep).expect("the contract accepts it");
        assert_eq!(parsed.family(), twinvpn_types::AddressFamily::V4);
        let twinvpn_types::IpAddr::V4(v4) = parsed.address else {
            panic!("a mapped v4 source must be reported as v4");
        };
        assert_eq!(v4.octets(), [198, 51, 100, 7]);
        assert_eq!(parsed.port.get(), 51_820);
    }

    #[test]
    fn a_link_local_source_is_answered_with_silence_not_with_an_unusable_candidate() {
        // RFC 4007: unusable without a zone, and the zone this process holds is
        // its own, not the peer's. `protocol.md` §10.4 requires the zone on a
        // link-local candidate, so the only honest answers are a lie or nothing.
        let ll = IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap());
        assert!(encode_endpoint(SocketAddr::new(ll, 443)).is_none());
    }

    #[test]
    fn nothing_this_service_emits_is_refused_by_the_frozen_validator() {
        // The property, over every shape a real accept() can produce — including
        // the CGNAT range a carrier-NAT'd peer arrives from and the NAT64
        // well-known prefix a v6-only access network translates through, both of
        // which `networking.md` §3.8 and §7.5 make first-class rather than edge
        // cases. Either a canonical `Endpoint` comes back, or nothing does.
        let cases = [
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            IpAddr::V6("64:ff9b::c633:6407".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V6(Ipv4Addr::new(100, 64, 0, 1).to_ipv6_mapped()),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        ];
        for addr in cases {
            let Some(bytes) = encode_endpoint(SocketAddr::new(addr, 443)) else {
                continue;
            };
            let ep = v1::Endpoint::decode(&bytes[..]).unwrap();
            twinvpn_schema::validate::endpoint(&ep).unwrap_or_else(|e| {
                panic!("emitted an endpoint for {addr} the contract rejects: {e:?}")
            });
        }
    }

    #[test]
    fn an_error_envelope_carries_the_code_and_no_message() {
        let e = twinvpn_service_common::binding::Refusal::SubjectHeldByAnotherChannel
            .to_error(crate::COMPONENT);
        let bytes = encode_error(&e);
        let env = v1::ErrorEnvelope::decode(&bytes[..]).unwrap();
        assert_eq!(env.reason_code, "CONTROL.CHANNEL_BINDING_MISMATCH");
        assert_eq!(env.domain, "CONTROL");
    }
}
