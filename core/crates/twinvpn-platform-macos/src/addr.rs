//! Conversions between `twinvpn-types`' canonical addresses and the OS's, and
//! the Darwin address-family numbers.
//!
//! **Authority:** `contracts/proto/twinvpn/v1/common.proto` (canonical forms are
//! **enforced, never normalized**), ADR-0010 R1,
//! [`twinvpn_platform::socket`]'s rule that "the adapter un-maps before this
//! crosses the seam".
//!
//! # The one place a v4-mapped address is allowed to exist
//!
//! `V6Addr::new` **rejects** `::ffff:0:0/96`, because accepting
//! `::ffff:10.0.0.1` would let one logical address arrive under two encodings and
//! defeat every set-membership and prefix-match check that depends on a canonical
//! form. A `V6DualStack` socket receives exactly that form from the kernel, so
//! the un-mapping happens **here, at the seam**, in [`from_std`].
//!
//! # Why Darwin's `AF_INET6` is written out rather than taken from `libc`
//!
//! `AF_INET6` is **10 on Linux and 30 on Darwin**. This crate is compiled for
//! Darwin by `make cross-check` and *run* on Linux by `cargo test`, and the
//! byte-level decoders in [`crate::rtmsg`] and [`crate::utun`] parse **Darwin's**
//! bytes in both cases. Naming `libc::AF_INET6` there would produce a decoder
//! that is correct when compiled and wrong when tested — the worst of the two.
//! So the Darwin numbers live here, as constants, with their source named.

use std::net::{IpAddr as StdIpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use twinvpn_platform::PlatformError;
use twinvpn_types::{AddressFamily, Endpoint, IpAddr, IpPrefix, Port, V4Addr, V6Addr, ZoneIndex};

use crate::oserr;

/// Darwin's `AF_INET`, from `<sys/socket.h>`. The same as Linux's, and written
/// out anyway so the pair reads as one decision.
pub const DARWIN_AF_INET: u8 = 2;

/// Darwin's `AF_INET6`, from `<sys/socket.h>`. **30, not Linux's 10.**
pub const DARWIN_AF_INET6: u8 = 30;

/// Darwin's `AF_LINK`, from `<sys/socket.h>` — the `sockaddr_dl` family that
/// carries an interface's name and index in a `PF_ROUTE` message.
pub const DARWIN_AF_LINK: u8 = 18;

/// The Darwin address-family number for a canonical family.
#[must_use]
pub const fn darwin_af(family: AddressFamily) -> u8 {
    match family {
        AddressFamily::V4 => DARWIN_AF_INET,
        AddressFamily::V6 => DARWIN_AF_INET6,
    }
}

/// The canonical family for a Darwin address-family number, if it is one we
/// carry.
#[must_use]
pub const fn family_of_darwin_af(af: u8) -> Option<AddressFamily> {
    match af {
        DARWIN_AF_INET => Some(AddressFamily::V4),
        DARWIN_AF_INET6 => Some(AddressFamily::V6),
        _ => None,
    }
}

/// An OS-supplied address that could not be put in canonical form.
///
/// Never a `TypeError` at the seam: a malformed address from the kernel is an
/// adapter malfunction, and [`PlatformError::AdapterUnavailable`] is the
/// registered condition for one.
fn malformed(call: &'static str) -> PlatformError {
    oserr::unavailable(call, libc::EINVAL)
}

/// Converts a canonical address to the OS's.
#[must_use]
pub fn to_std(addr: IpAddr) -> StdIpAddr {
    match addr {
        IpAddr::V4(a) => StdIpAddr::V4(Ipv4Addr::from(a.octets())),
        IpAddr::V6(a) => StdIpAddr::V6(Ipv6Addr::from(a.octets())),
    }
}

/// Converts a canonical endpoint to the OS's.
#[must_use]
pub fn endpoint_to_std(ep: Endpoint) -> SocketAddr {
    match ep.address {
        IpAddr::V4(a) => SocketAddr::new(StdIpAddr::V4(Ipv4Addr::from(a.octets())), ep.port.get()),
        IpAddr::V6(a) => SocketAddr::V6(std::net::SocketAddrV6::new(
            Ipv6Addr::from(a.octets()),
            ep.port.get(),
            0,
            a.zone().map_or(0, ZoneIndex::get),
        )),
    }
}

/// Converts an OS address to canonical form, **un-mapping** a v4-mapped v6
/// address on the way.
///
/// # Errors
///
/// [`PlatformError::AdapterUnavailable`] if the address cannot be put in
/// canonical form — a link-local v6 address with no scope, principally. A
/// link-local address whose interface is unknown is not usable, and inventing a
/// zone for it would make it match the wrong segment.
pub fn from_std(
    addr: StdIpAddr,
    scope_id: u32,
    call: &'static str,
) -> Result<IpAddr, PlatformError> {
    match addr {
        StdIpAddr::V4(a) => Ok(IpAddr::V4(V4Addr::from_octets(a.octets()))),
        StdIpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return Ok(IpAddr::V4(V4Addr::from_octets(v4.octets())));
            }
            V6Addr::new(a.octets(), ZoneIndex::new(scope_id))
                .map(IpAddr::V6)
                .map_err(|_| malformed(call))
        }
    }
}

/// Converts an OS endpoint to canonical form.
///
/// # Errors
///
/// [`PlatformError::AdapterUnavailable`] on a malformed address or on port zero,
/// which [`Port`] refuses because it is not a reachable endpoint.
pub fn endpoint_from_std(addr: SocketAddr, call: &'static str) -> Result<Endpoint, PlatformError> {
    let scope = match addr {
        SocketAddr::V6(v6) => v6.scope_id(),
        SocketAddr::V4(_) => 0,
    };
    let address = from_std(addr.ip(), scope, call)?;
    let port = Port::new(addr.port()).map_err(|_| malformed(call))?;
    Ok(Endpoint::new(address, port))
}

/// Renders a prefix as `route(8)` / `pf` text: `10.0.0.0/8`, `fd00::/8`.
///
/// One function, so every place that writes a prefix into a kernel-bound or
/// `pfctl`-bound string writes the same one. Canonicality is already guaranteed
/// by [`IpPrefix`]'s constructor, so this cannot emit `10.0.0.1/8`.
#[must_use]
pub fn prefix_text(prefix: IpPrefix) -> String {
    format!("{}/{}", addr_text(prefix.address()), prefix.prefix_len())
}

/// Renders an address as text, without a zone suffix.
///
/// The zone is carried separately everywhere it matters (`IPV6_BOUND_IF`, a
/// multicast join's interface, a `sockaddr_in6`'s `sin6_scope_id`), so appending
/// `%en0` here would produce a second encoding of one value — the thing
/// `common.proto` forbids.
#[must_use]
pub fn addr_text(addr: IpAddr) -> String {
    to_std(addr).to_string()
}

/// The dotted-quad netmask for an IPv4 prefix length.
///
/// `NEIPv4Settings` and `NEIPv4Route` take a **mask**, not a length, so the
/// conversion happens once, here, rather than in Swift where it would be a
/// shell-side computation over a domain value.
///
/// # Errors
///
/// [`PlatformError::AdapterUnavailable`] on a length above 32 — which
/// [`IpPrefix`] already refuses, so reaching it means an adapter defect.
pub fn v4_netmask_text(prefix_len: u32) -> Result<String, PlatformError> {
    if prefix_len > 32 {
        return Err(malformed("v4_netmask"));
    }
    let bits: u32 = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ok(Ipv4Addr::from(bits.to_be_bytes()).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_darwin_family_numbers_are_darwins_and_not_this_hosts() {
        // The whole point: on Linux `libc::AF_INET6` is 10. A decoder of Darwin
        // bytes that used it would be correct when cross-compiled and wrong when
        // tested here, which is the failure this constant exists to prevent.
        assert_eq!(DARWIN_AF_INET6, 30);
        assert_eq!(DARWIN_AF_INET, 2);
        assert_eq!(DARWIN_AF_LINK, 18);
        assert_eq!(darwin_af(AddressFamily::V6), 30);
        assert_eq!(family_of_darwin_af(30), Some(AddressFamily::V6));
        assert_eq!(family_of_darwin_af(10), None, "10 is Linux's AF_INET6");
        assert_eq!(family_of_darwin_af(DARWIN_AF_LINK), None);
    }

    #[test]
    fn a_v4_mapped_address_is_unmapped_at_the_seam_and_never_reaches_the_core() {
        let mapped = StdIpAddr::V6("::ffff:192.0.2.1".parse::<Ipv6Addr>().expect("literal"));
        let canonical = from_std(mapped, 0, "test").expect("un-maps");
        assert_eq!(canonical.family(), AddressFamily::V4);
        assert_eq!(canonical.octets(), vec![192, 0, 2, 1]);
    }

    #[test]
    fn a_link_local_address_without_a_scope_is_refused_not_given_one() {
        let ll = StdIpAddr::V6("fe80::1".parse::<Ipv6Addr>().expect("literal"));
        assert!(from_std(ll, 0, "test").is_err());
        assert!(from_std(ll, 7, "test").is_ok());
    }

    #[test]
    fn endpoints_round_trip_in_both_families() {
        for text in ["192.0.2.1:1234", "[2001:db8::1]:5678"] {
            let std: SocketAddr = text.parse().expect("literal");
            let ep = endpoint_from_std(std, "test").expect("canonical");
            assert_eq!(endpoint_to_std(ep), std);
        }
    }

    #[test]
    fn port_zero_is_malformed_and_is_reported_by_name() {
        let std: SocketAddr = "192.0.2.1:0".parse().expect("literal");
        let err = endpoint_from_std(std, "recvmsg").expect_err("port 0 is malformed");
        assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
        assert_eq!(err.os_detail().map(|d| d.call), Some("recvmsg"));
    }

    #[test]
    fn prefix_text_is_written_once_and_for_both_families() {
        let v4 = IpPrefix::new(IpAddr::V4(V4Addr::from_octets([10, 0, 0, 0])), 8).expect("valid");
        assert_eq!(prefix_text(v4), "10.0.0.0/8");
        let mut ula = [0u8; 16];
        ula[0] = 0xfd;
        let v6 =
            IpPrefix::new(IpAddr::V6(V6Addr::new(ula, None).expect("valid")), 8).expect("valid");
        assert_eq!(prefix_text(v6), "fd00::/8");
    }

    #[test]
    fn the_v4_netmask_is_computed_here_and_never_in_swift() {
        assert_eq!(v4_netmask_text(0).expect("valid"), "0.0.0.0");
        assert_eq!(v4_netmask_text(1).expect("valid"), "128.0.0.0");
        assert_eq!(v4_netmask_text(10).expect("valid"), "255.192.0.0");
        assert_eq!(v4_netmask_text(24).expect("valid"), "255.255.255.0");
        assert_eq!(v4_netmask_text(32).expect("valid"), "255.255.255.255");
        assert!(v4_netmask_text(33).is_err());
    }
}
