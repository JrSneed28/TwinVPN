//! `sockaddr` ↔ [`Endpoint`] conversion, and the v4-mapped un-mapping the seam
//! requires. Pure, and tested on this host.
//!
//! **Authority:** [`twinvpn_platform::socket`] (*"Never a v4-mapped v6 address:
//! the adapter un-maps before this crosses the seam"*), `common.proto` (which
//! forbids a v4-mapped address in any canonical position), ADR-0010 R1.
//!
//! # Why the un-mapping is here and not at the syscall
//!
//! A `V6DualStack` socket receives IPv4 traffic with a source address of
//! `::ffff:a.b.c.d`. [`twinvpn_types::V6Addr::new`] **rejects** that shape
//! outright, so a naive conversion cannot even build the value — it would have
//! to `expect` and panic on ordinary IPv4 traffic. Doing the un-mapping in one
//! pure function, over plain octets, means the rule is a test rather than a
//! comment, and the syscall layer above it never has to know about it.

use twinvpn_types::{Endpoint, IpAddr, Port, TypeError, V4Addr, V6Addr, ZoneIndex};

/// The `::ffff:0:0/96` prefix an IPv4-mapped IPv6 address carries.
const V4_MAPPED_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

/// Whether `octets` is an IPv4-mapped IPv6 address.
#[must_use]
pub fn is_v4_mapped(octets: &[u8; 16]) -> bool {
    octets[..12] == V4_MAPPED_PREFIX
}

/// Whether `octets` is inside `fe80::/10`, the range RFC 4007 scopes.
#[must_use]
pub fn is_link_local(octets: &[u8; 16]) -> bool {
    octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
}

/// Builds an [`IpAddr`] from sixteen IPv6 octets and the interface index the
/// **kernel** supplied alongside them, un-mapping a v4-mapped address.
///
/// `ifindex` is metadata, not part of the address: it arrives on every
/// `sockaddr_in6` and every `in6_pktinfo` whether or not the address is scoped,
/// and several stacks set it on unscoped addresses. RFC 4007 makes the zone part
/// of the address **only** for a scoped one, and [`V6Addr::new`] enforces
/// exactly that — so the zone is attached for `fe80::/10` and dropped otherwise.
///
/// The half that matters is preserved and is a hard error: a **link-local
/// address with no interface index is refused**, because it is unusable on a
/// multi-homed host and `docs/protocol.md` §10.4 requires the zone.
///
/// # Errors
///
/// [`TypeError`] on a link-local address with `ifindex == 0`.
pub fn v6_from_kernel(octets: [u8; 16], ifindex: u32) -> Result<IpAddr, TypeError> {
    if is_v4_mapped(&octets) {
        let mut v4 = [0u8; 4];
        v4.copy_from_slice(&octets[12..16]);
        return Ok(IpAddr::V4(V4Addr::from_octets(v4)));
    }
    let zone = if is_link_local(&octets) {
        Some(ZoneIndex::new(ifindex).ok_or(TypeError::Ipv6ZoneIndex)?)
    } else {
        None
    };
    Ok(IpAddr::V6(V6Addr::new(octets, zone)?))
}

/// A v4 address from four octets. Infallible; present so callers never reach for
/// `V4Addr` directly and the two families read the same way at every call site.
#[must_use]
pub fn v4_address(octets: [u8; 4]) -> IpAddr {
    IpAddr::V4(V4Addr::from_octets(octets))
}

/// Builds an [`Endpoint`] from four IPv4 octets and a port.
///
/// # Errors
///
/// [`TypeError`] if the port is zero. A zero port is not a peer.
pub fn v4_endpoint(octets: [u8; 4], port: u16) -> Result<Endpoint, TypeError> {
    Ok(Endpoint::new(v4_address(octets), Port::new(port)?))
}

/// Builds an [`Endpoint`] from sixteen IPv6 octets, the kernel's interface
/// index, and a port, un-mapping a v4-mapped source.
///
/// # Errors
///
/// [`TypeError`] on a zero port, or on a link-local address with no interface.
pub fn v6_endpoint(octets: [u8; 16], ifindex: u32, port: u16) -> Result<Endpoint, TypeError> {
    Ok(Endpoint::new(
        v6_from_kernel(octets, ifindex)?,
        Port::new(port)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_types::AddressFamily;

    fn mapped(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        let mut octets = [0u8; 16];
        octets[..12].copy_from_slice(&V4_MAPPED_PREFIX);
        octets[12..].copy_from_slice(&[a, b, c, d]);
        octets
    }

    /// The rule the seam states: a v4-mapped address never crosses.
    #[test]
    fn a_v4_mapped_source_is_unmapped_at_the_seam_not_carried_across_it() {
        let addr = v6_from_kernel(mapped(192, 0, 2, 10), 0).expect("unmaps");
        assert_eq!(addr.family(), AddressFamily::V4);
        assert_eq!(addr.octets(), vec![192, 0, 2, 10]);

        let endpoint = v6_endpoint(mapped(198, 51, 100, 7), 0, 51820).expect("endpoint");
        assert_eq!(endpoint.family(), AddressFamily::V4);
        assert_eq!(endpoint.port.get(), 51820);
    }

    #[test]
    fn a_genuine_v6_address_is_left_alone() {
        let mut octets = [0u8; 16];
        octets[0] = 0x20;
        octets[1] = 0x01;
        octets[15] = 1;
        let addr = v6_from_kernel(octets, 0).expect("v6");
        assert_eq!(addr.family(), AddressFamily::V6);
        assert_eq!(addr.octets(), octets.to_vec());
    }

    /// A link-local source without its arrival interface is unusable on a
    /// multi-homed host, so it is refused rather than silently zoneless.
    #[test]
    fn a_link_local_source_needs_its_arrival_interface() {
        let mut octets = [0u8; 16];
        octets[0] = 0xfe;
        octets[1] = 0x80;
        octets[15] = 2;
        assert!(v6_from_kernel(octets, 0).is_err(), "no interface index");
        let addr = v6_from_kernel(octets, 7).expect("zoned");
        let IpAddr::V6(v6) = addr else { panic!("v6") };
        assert_eq!(v6.zone().map(ZoneIndex::get), Some(7));
    }

    /// The kernel sets `sin6_scope_id` / `ipi6_ifindex` on every datagram,
    /// scoped or not. RFC 4007 makes the zone part of the address only for a
    /// scoped one, so an unscoped address drops it rather than being refused —
    /// refusing here would reject ordinary global IPv6 traffic.
    #[test]
    fn a_global_address_drops_the_kernels_interface_index() {
        let mut octets = [0u8; 16];
        octets[0] = 0x20;
        octets[1] = 0x01;
        let addr = v6_from_kernel(octets, 7).expect("global, unscoped");
        let IpAddr::V6(v6) = addr else { panic!("v6") };
        assert_eq!(v6.zone(), None);
    }

    #[test]
    fn the_link_local_test_matches_the_whole_of_fe80_slash_10() {
        let mut octets = [0u8; 16];
        for (second, expected) in [(0x80u8, true), (0xbf, true), (0xc0, false), (0x7f, false)] {
            octets[0] = 0xfe;
            octets[1] = second;
            assert_eq!(is_link_local(&octets), expected, "fe{second:02x}");
        }
        octets[0] = 0xfd;
        octets[1] = 0x80;
        assert!(!is_link_local(&octets), "a ULA is not link-local");
    }

    #[test]
    fn a_zero_port_is_not_a_peer() {
        assert!(v4_endpoint([192, 0, 2, 1], 0).is_err());
        assert!(v6_endpoint([0u8; 16], 0, 0).is_err());
        assert!(v4_endpoint([192, 0, 2, 1], 1).is_ok());
        assert!(v4_endpoint([192, 0, 2, 1], 65535).is_ok());
    }

    #[test]
    fn the_mapped_prefix_test_is_exact() {
        assert!(is_v4_mapped(&mapped(0, 0, 0, 0)));
        let mut nearly = mapped(1, 2, 3, 4);
        nearly[10] = 0xfe;
        assert!(!is_v4_mapped(&nearly));
        // `::` is not v4-mapped, and neither is a v4-COMPATIBLE address
        // (`::a.b.c.d`), which is a different and deprecated shape.
        assert!(!is_v4_mapped(&[0u8; 16]));
        let mut compat = [0u8; 16];
        compat[12..].copy_from_slice(&[192, 0, 2, 1]);
        assert!(!is_v4_mapped(&compat));
    }
}
