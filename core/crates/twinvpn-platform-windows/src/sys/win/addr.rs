//! `SOCKADDR_INET` and the WFP address-and-mask forms, both ways.
//!
//! **Authority:** ADR-0010 R1 (both families, always); `contracts/proto/twinvpn/v1/common.proto`
//! (canonical forms are **enforced, never normalized**);
//! `twinvpn-platform-linux`'s `addr.rs`, which is the register this module
//! follows.
//!
//! # This file has never been executed
//!
//! Nothing in `sys/win/` has been linked, loaded or run. `make cross-check`
//! type-checks it against the real `windows-sys` for `x86_64-pc-windows-msvc`
//! with `-D warnings`, and that is the only claim anybody may make about it.
//!
//! # The byte-order trap, stated once
//!
//! Windows is inconsistent about IPv4 byte order across these two APIs, and
//! getting it backwards produces a filter that matches the wrong `/8`:
//!
//! | Field | Order |
//! |---|---|
//! | `SOCKADDR_IN.sin_addr.S_addr` (IP Helper) | **network** — the bytes as they appear on the wire |
//! | `FWP_V4_ADDR_AND_MASK.addr` (WFP) | **host** — `192.0.2.1` is `0xC0000201` as a `u32` |
//!
//! So [`v4_network_order`] and [`v4_host_order`] are two functions with two
//! names rather than one function and a comment, because a caller that reached
//! for the wrong one would produce something that compiles, installs, and
//! silently protects a different network. IPv6 has no such split: it is a byte
//! array in both.
//!
//! **This is a documented Microsoft quirk that this build has not observed.**
//! It is recorded as an uncertainty in this domain's report.

use twinvpn_types::{AddressFamily, IpAddr, IpPrefix, V4Addr, V6Addr};
use windows_sys::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
};

/// An IPv4 address as IP Helper wants it: **network** byte order.
#[must_use]
pub const fn v4_network_order(addr: V4Addr) -> u32 {
    u32::from_ne_bytes(addr.octets())
}

/// An IPv4 address as WFP wants it: **host** byte order.
#[must_use]
pub const fn v4_host_order(addr: V4Addr) -> u32 {
    u32::from_be_bytes(addr.octets())
}

/// The mask a prefix length implies, in host byte order.
///
/// A `/0` is `0` and a `/32` is `u32::MAX`; the shift is written out rather than
/// `!0 << (32 - len)` because that expression is undefined behaviour at
/// `len == 0` and the compiler will not save a reviewer from it.
#[must_use]
pub const fn v4_mask(prefix_len: u32) -> u32 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

/// A canonical address as a `SOCKADDR_INET`.
///
/// The port is always zero: every use in this crate is a route destination, a
/// next hop or an interface address, none of which has one.
#[must_use]
pub fn to_sockaddr(address: IpAddr) -> SOCKADDR_INET {
    match address {
        IpAddr::V4(a) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                #[allow(clippy::cast_possible_truncation)]
                sin_family: AF_INET as ADDRESS_FAMILY,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: v4_network_order(a),
                    },
                },
                sin_zero: [0; 8],
            },
        },
        IpAddr::V6(a) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                #[allow(clippy::cast_possible_truncation)]
                sin6_family: AF_INET6 as ADDRESS_FAMILY,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: a.octets() },
                },
                // The zone travels here rather than being dropped: `V6Addr`
                // requires one on `fe80::/10`, and a link-local next hop with no
                // zone points at whichever interface the stack guesses.
                Anonymous: SOCKADDR_IN6_0 {
                    sin6_scope_id: a.zone_index_wire(),
                },
            },
        },
    }
}

/// A `SOCKADDR_INET` back to a canonical address.
///
/// Returns `None` for a family this crate does not carry, and for a v6 value
/// `V6Addr` refuses — a v4-mapped address, or a link-local one with no zone.
/// **Refusing is the point**: `common.proto` forbids a v4-mapped address in any
/// canonical position, and a link-local address whose interface is unknown is
/// not usable, so inventing a zone would make it match the wrong segment.
///
/// # Safety
///
/// The caller must guarantee `sa` is a `SOCKADDR_INET` the OS filled in, so that
/// reading the union member selected by `si_family` is reading an initialised
/// field.
#[must_use]
pub unsafe fn from_sockaddr(sa: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: `si_family` overlaps the first field of both arms of the union and
    // is initialised in either case, which is the whole reason `SOCKADDR_INET`
    // has it; the caller's guarantee is that the value came from the OS.
    let family = unsafe { sa.si_family };
    #[allow(clippy::cast_possible_truncation)]
    if family == AF_INET as ADDRESS_FAMILY {
        // SAFETY: `si_family` says this is the `Ipv4` arm.
        let raw = unsafe { sa.Ipv4.sin_addr.S_un.S_addr };
        Some(IpAddr::V4(V4Addr::from_octets(raw.to_ne_bytes())))
    } else if family == AF_INET6 as ADDRESS_FAMILY {
        // SAFETY: `si_family` says this is the `Ipv6` arm.
        let (octets, zone) = unsafe {
            (
                sa.Ipv6.sin6_addr.u.Byte,
                sa.Ipv6.Anonymous.sin6_scope_id,
            )
        };
        V6Addr::from_slice(&octets, zone).ok().map(IpAddr::V6)
    } else {
        None
    }
}

/// The address family a `SOCKADDR_INET` carries, where this crate carries it.
///
/// # Safety
///
/// As [`from_sockaddr`].
#[must_use]
pub unsafe fn family_of(sa: &SOCKADDR_INET) -> Option<AddressFamily> {
    // SAFETY: as above — `si_family` is initialised in either arm.
    let family = unsafe { sa.si_family };
    #[allow(clippy::cast_possible_truncation)]
    if family == AF_INET as ADDRESS_FAMILY {
        Some(AddressFamily::V4)
    } else if family == AF_INET6 as ADDRESS_FAMILY {
        Some(AddressFamily::V6)
    } else {
        None
    }
}

/// A prefix and its length, as IP Helper's `IP_ADDRESS_PREFIX` wants them.
#[must_use]
pub fn to_prefix(prefix: IpPrefix) -> (SOCKADDR_INET, u8) {
    #[allow(clippy::cast_possible_truncation)]
    (to_sockaddr(prefix.address()), prefix.prefix_len() as u8)
}

/// The `ADDRESS_FAMILY` value for one of ours.
#[must_use]
pub const fn address_family(family: AddressFamily) -> ADDRESS_FAMILY {
    #[allow(clippy::cast_possible_truncation)]
    match family {
        AddressFamily::V4 => AF_INET as ADDRESS_FAMILY,
        AddressFamily::V6 => AF_INET6 as ADDRESS_FAMILY,
    }
}
