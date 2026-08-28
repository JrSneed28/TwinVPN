//! Conversions between `twinvpn-types`' canonical addresses and the OS's.
//!
//! **Authority:** `contracts/proto/twinvpn/v1/common.proto` (canonical forms are
//! **enforced, never normalized**), ADR-0010 R1, `twinvpn_platform::socket`'s
//! rule that "the adapter un-maps before this crosses the seam".
//!
//! # The one place a v4-mapped address is allowed to exist
//!
//! `V6Addr::new` **rejects** `::ffff:0:0/96`, because "accepting `::ffff:10.0.0.1`
//! would let one logical address arrive under two encodings and defeat every
//! set-membership and prefix-match check that depends on a canonical form".
//!
//! But a `V6DualStack` socket receives exactly that form from the kernel. So the
//! un-mapping happens **here, at the seam**, in [`from_std`] — never in the core,
//! and never by widening the type's constructor.
//!
//! # Link-local zones
//!
//! `V6Addr` requires a zone index on `fe80::/10` and forbids one elsewhere.
//! `std::net::SocketAddrV6` carries a `scope_id` that is zero when absent, so the
//! two representations line up exactly, and a link-local address arriving with a
//! zero scope is **rejected** rather than given a zone of convenience: a
//! link-local address whose interface is unknown is not usable, and inventing one
//! would make it match the wrong segment.

use std::net::{IpAddr as StdIpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use twinvpn_platform::PlatformError;
use twinvpn_types::{Endpoint, IpAddr, IpPrefix, Port, V4Addr, V6Addr, ZoneIndex};

use crate::oserr;

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
/// canonical form — a link-local v6 address with no scope, principally.
pub fn from_std(
    addr: StdIpAddr,
    scope_id: u32,
    call: &'static str,
) -> Result<IpAddr, PlatformError> {
    match addr {
        StdIpAddr::V4(a) => Ok(IpAddr::V4(V4Addr::from_octets(a.octets()))),
        StdIpAddr::V6(a) => {
            // The un-mapping the seam owes the core. A `V6DualStack` socket is
            // the only way this shape arrives, and it must not reach the core.
            if let Some(v4) = a.to_ipv4_mapped() {
                return Ok(IpAddr::V4(V4Addr::from_octets(v4.octets())));
            }
            let octets = a.octets();
            let zone = ZoneIndex::new(scope_id);
            V6Addr::new(octets, zone)
                .map(IpAddr::V6)
                .map_err(|_| malformed(call))
        }
    }
}

/// Converts an OS socket address to a canonical endpoint, un-mapping as above.
///
/// # Errors
///
/// [`PlatformError::AdapterUnavailable`] on port zero — which `common.proto`
/// calls malformed — or on a non-canonical address.
pub fn endpoint_from_std(addr: SocketAddr, call: &'static str) -> Result<Endpoint, PlatformError> {
    let scope = match addr {
        SocketAddr::V6(v6) => v6.scope_id(),
        SocketAddr::V4(_) => 0,
    };
    let address = from_std(addr.ip(), scope, call)?;
    let port = Port::new(addr.port()).map_err(|_| malformed(call))?;
    Ok(Endpoint::new(address, port))
}

/// Renders a prefix as `iproute2`/`nftables` text: `10.0.0.0/8`, `fd00::/8`.
///
/// One function, so every place that writes a prefix into a kernel-bound string
/// writes the same one. Canonicality is already guaranteed by [`IpPrefix`]'s
/// constructor, so this cannot emit `10.0.0.1/8`.
#[must_use]
pub fn prefix_text(prefix: IpPrefix) -> String {
    format!("{}/{}", addr_text(prefix.address()), prefix.prefix_len())
}

/// Renders an address as text, without a zone suffix.
///
/// The zone is carried separately everywhere it matters (`SO_BINDTODEVICE`, a
/// netlink `oif`, a multicast join's interface), so appending `%eth0` here would
/// produce a second encoding of one value — the thing `common.proto` forbids.
#[must_use]
pub fn addr_text(addr: IpAddr) -> String {
    to_std(addr).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_types::AddressFamily;

    #[test]
    fn a_v4_mapped_address_is_unmapped_at_the_seam_and_never_reaches_the_core() {
        // ::ffff:192.0.2.1 — what a V6DualStack socket receives for a v4 peer.
        let mapped = StdIpAddr::V6("::ffff:192.0.2.1".parse::<Ipv6Addr>().expect("literal"));
        let canonical = from_std(mapped, 0, "test").expect("un-maps");
        assert_eq!(canonical.family(), AddressFamily::V4);
        assert_eq!(canonical.octets(), vec![192, 0, 2, 1]);
    }

    #[test]
    fn a_link_local_address_without_a_scope_is_refused_not_given_one() {
        let ll = StdIpAddr::V6("fe80::1".parse::<Ipv6Addr>().expect("literal"));
        assert!(
            from_std(ll, 0, "test").is_err(),
            "a link-local address whose interface is unknown must not be \
             invented a zone: it would match the wrong segment"
        );
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
}
