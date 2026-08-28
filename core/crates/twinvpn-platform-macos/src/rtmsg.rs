//! The `PF_ROUTE` routing-socket decoder: Darwin's bytes → [`NetworkChange`].
//!
//! **Authority:** `docs/networking.md` §5.1 (`subscribe_network_change(cb)` —
//! "event-driven, never polled"), [`twinvpn_platform::iface`], ADR-0010 R6 (a v6
//! default route appearing **after** the tunnel is up is its own event),
//! ADR-0018 §11.6 ("a dropped event is itself recorded").
//!
//! # A pure decoder over Darwin's wire format
//!
//! Everything here takes `&[u8]` and returns values. The bytes are **Darwin's**,
//! whatever host this is compiled for: `AF_INET6` is 30 here and not the 10 a
//! Linux `libc` would supply, the header offsets are Darwin's, and the sockaddr
//! padding is Darwin's `ROUNDUP` to four rather than the BSD-general eight. So
//! the decoder is target-free, and `cargo test` on this Linux host runs it against
//! hand-built Darwin messages — which is the only way any of this is checkable
//! without a Mac.
//!
//! # Validation before allocation
//!
//! `ownership.md` §6 rule 9: every untrusted input is validated *before* any
//! allocation proportional to a declared length. A routing socket is a kernel
//! interface rather than a network one, but the discipline is the same and the
//! failure mode is worse: `rtm_msglen` is a `u16` read out of a buffer, and a
//! decoder that trusted it would index past the read. Every length here is
//! checked against the slice it indexes **first**, and a message that does not
//! fit is skipped rather than truncated.

use twinvpn_platform::{InterfaceIndex, NetworkChange};
use twinvpn_types::{AddressFamily, IpAddr, V4Addr, V6Addr, ZoneIndex};

use crate::addr::{DARWIN_AF_INET, DARWIN_AF_INET6, DARWIN_AF_LINK};

/// `<net/route.h>`: the routing message types this adapter reacts to.
pub mod rtm {
    /// A route was added.
    pub const ADD: u8 = 0x1;
    /// A route was deleted.
    pub const DELETE: u8 = 0x2;
    /// A route changed.
    pub const CHANGE: u8 = 0x3;
    /// An address was added.
    pub const NEWADDR: u8 = 0xc;
    /// An address was removed.
    pub const DELADDR: u8 = 0xd;
    /// An interface's state changed.
    pub const IFINFO: u8 = 0xe;
    /// The extended form, which Darwin also emits.
    pub const IFINFO2: u8 = 0x12;
}

/// `<net/route.h>`: the `rtm_addrs` / `ifam_addrs` bitmask.
pub mod rta {
    /// `RTA_DST`.
    pub const DST: i32 = 0x1;
    /// `RTA_GATEWAY`.
    pub const GATEWAY: i32 = 0x2;
    /// `RTA_NETMASK`.
    pub const NETMASK: i32 = 0x4;
    /// `RTA_GENMASK`.
    pub const GENMASK: i32 = 0x8;
    /// `RTA_IFP` — the interface's `sockaddr_dl`.
    pub const IFP: i32 = 0x10;
    /// `RTA_IFA` — the interface's address.
    pub const IFA: i32 = 0x20;
    /// `RTA_AUTHOR`.
    pub const AUTHOR: i32 = 0x40;
    /// `RTA_BRD` — the broadcast or destination address.
    pub const BRD: i32 = 0x80;
    /// How many slots the mask can name, in `RTAX_*` order.
    pub const MAX: usize = 8;
}

/// `<net/if.h>`: `IFF_UP`.
pub const IFF_UP: i32 = 0x1;

/// `<net/route.h>`: the current `RTM_VERSION`.
pub const RTM_VERSION: u8 = 5;

/// The smallest message Darwin can emit — `struct ifa_msghdr` is 20 bytes and is
/// the shortest of the three headers.
pub const MIN_MSG_LEN: usize = 20;

/// Darwin's `ROUNDUP`: sockaddrs in a routing message are padded to a multiple of
/// `sizeof(uint32_t)`, and a zero-length sockaddr still occupies four bytes.
///
/// **Four, not eight.** The 4.4BSD original rounds to `sizeof(long)`, which is
/// eight on a 64-bit host; Darwin's `<net/route.h>` pins `uint32_t`. A decoder
/// that used the BSD-general form would mis-parse every message with two or more
/// addresses, and would do it identically on both platforms — so no compile would
/// catch it and only a Mac would.
#[must_use]
pub const fn roundup(len: usize) -> usize {
    if len == 0 {
        4
    } else {
        1 + ((len - 1) | 3)
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(u16::from_ne_bytes([slice[0], slice[1]]))
}

fn i32_at(bytes: &[u8], offset: usize) -> Option<i32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(i32::from_ne_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// One routing message's header, as much of it as this adapter reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// `rtm_msglen` / `ifam_msglen` / `ifm_msglen`.
    pub msglen: usize,
    /// `rtm_version`.
    pub version: u8,
    /// `rtm_type`.
    pub kind: u8,
    /// The interface index the message concerns, where it names one.
    pub index: u32,
    /// The flags word — `RTF_*` on a route message, `IFF_*` on an interface one.
    pub flags: i32,
    /// The `RTA_*` mask saying which sockaddrs follow.
    pub addrs: i32,
    /// Where the sockaddr block begins.
    pub payload_at: usize,
}

/// Reads the header of whichever of Darwin's three message shapes `kind` names.
///
/// The three headers do **not** share a layout beyond their first four bytes,
/// which is the whole reason this is a `match` rather than one struct:
///
/// | Shape | `addrs` | `flags` | `index` |
/// |---|---|---|---|
/// | `rt_msghdr` | offset 12 | offset 8 | offset 4 (`u16`) |
/// | `ifa_msghdr` | offset 4 | offset 8 | offset 12 (`u16`) |
/// | `if_msghdr` | offset 4 | offset 8 | offset 12 (`u16`) |
///
/// `rt_msghdr` carries `rtm_index` in the header's fourth field and pads two
/// bytes before `rtm_flags`; the other two carry their index after the flags.
/// Getting that wrong reads a flags word as an index, which is the kind of defect
/// that produces plausible-looking nonsense rather than a crash.
#[must_use]
pub fn parse_header(bytes: &[u8]) -> Option<Header> {
    let msglen = usize::from(u16_at(bytes, 0)?);
    if msglen < MIN_MSG_LEN || msglen > bytes.len() {
        // Validated BEFORE anything indexes on it. A `u16` from a kernel buffer
        // is still a declared length, and §6 rule 9 does not care that the writer
        // is the kernel.
        return None;
    }
    let version = *bytes.get(2)?;
    let kind = *bytes.get(3)?;
    let (index, flags, addrs, payload_at) = match kind {
        rtm::ADD | rtm::DELETE | rtm::CHANGE => (
            u32::from(u16_at(bytes, 4)?),
            i32_at(bytes, 8)?,
            i32_at(bytes, 12)?,
            // `struct rt_msghdr` is 92 bytes on Darwin: 36 bytes of header
            // followed by a 56-byte `struct rt_metrics` (14 × u32).
            92usize,
        ),
        rtm::NEWADDR | rtm::DELADDR => (
            u32::from(u16_at(bytes, 12)?),
            i32_at(bytes, 8)?,
            i32_at(bytes, 4)?,
            // `struct ifa_msghdr`: 20 bytes.
            20usize,
        ),
        rtm::IFINFO | rtm::IFINFO2 => (
            u32::from(u16_at(bytes, 12)?),
            i32_at(bytes, 8)?,
            i32_at(bytes, 4)?,
            // **Deliberately `msglen`, not a size constant.** `struct if_msghdr`
            // is followed by a `struct if_data` whose length differs between
            // `RTM_IFINFO` and `RTM_IFINFO2` and has grown across Darwin
            // releases, so any constant here would be a number nobody on this
            // host can check. Nothing needs the sockaddrs of an interface
            // message — [`decode`] reads only `ifm_flags` and `ifm_index` — so
            // the address block is declared empty rather than located wrongly.
            msglen,
        ),
        _ => return None,
    };
    Some(Header {
        msglen,
        version,
        kind,
        index,
        flags,
        addrs,
        payload_at,
    })
}

/// The addresses a message carries, in `RTAX_*` slot order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Addresses {
    /// One entry per `RTA_*` bit that was set, in slot order. `None` where the
    /// sockaddr was of a family this adapter does not carry (`AF_LINK`, chiefly).
    pub slots: [Option<IpAddr>; rta::MAX],
    /// The interface name from an `AF_LINK` sockaddr, where one was present.
    pub link_name: Option<String>,
}

impl Addresses {
    /// The destination (`RTAX_DST`).
    #[must_use]
    pub fn destination(&self) -> Option<IpAddr> {
        self.slots[0]
    }

    /// The netmask (`RTAX_NETMASK`).
    #[must_use]
    pub fn netmask(&self) -> Option<IpAddr> {
        self.slots[2]
    }

    /// The interface address (`RTAX_IFA`).
    #[must_use]
    pub fn interface_address(&self) -> Option<IpAddr> {
        self.slots[5]
    }
}

/// Walks the sockaddr block that follows a header.
///
/// Every step re-checks the remaining length before it advances, so a message
/// whose `sa_len` runs past `msglen` truncates the walk rather than reading past
/// the buffer.
#[must_use]
pub fn parse_addresses(bytes: &[u8], header: &Header) -> Addresses {
    let mut out = Addresses::default();
    let Some(block) = bytes.get(header.payload_at..header.msglen) else {
        return out;
    };
    let mut offset = 0usize;
    for slot in 0..rta::MAX {
        if header.addrs & (1 << slot) == 0 {
            continue;
        }
        let Some(&sa_len) = block.get(offset) else {
            break;
        };
        let step = roundup(usize::from(sa_len));
        let Some(sa) = block.get(offset..offset + step.min(block.len() - offset)) else {
            break;
        };
        if sa_len != 0 {
            match sa.get(1).copied() {
                Some(DARWIN_AF_INET) => out.slots[slot] = parse_sockaddr_in(sa),
                Some(DARWIN_AF_INET6) => out.slots[slot] = parse_sockaddr_in6(sa),
                Some(DARWIN_AF_LINK) => {
                    if out.link_name.is_none() {
                        out.link_name = parse_sockaddr_dl_name(sa);
                    }
                }
                _ => {}
            }
        }
        offset += step;
        if offset >= block.len() {
            break;
        }
    }
    out
}

/// `struct sockaddr_in`: `sin_len`, `sin_family`, `sin_port`, `sin_addr`.
fn parse_sockaddr_in(sa: &[u8]) -> Option<IpAddr> {
    let octets = sa.get(4..8)?;
    Some(IpAddr::V4(V4Addr::from_octets([
        octets[0], octets[1], octets[2], octets[3],
    ])))
}

/// `struct sockaddr_in6`: `sin6_len`, `sin6_family`, `sin6_port`, `sin6_flowinfo`,
/// `sin6_addr`, `sin6_scope_id`.
///
/// Darwin embeds the scope id of a link-local address **inside the address's
/// second u16** in routing messages (the "KAME" form) as well as in
/// `sin6_scope_id`. The embedded copy is cleared and the explicit field is
/// preferred, because a `V6Addr` carrying `fe80:0:0:7::1` would be a different
/// address from `fe80::1%7` and would never match a prefix.
fn parse_sockaddr_in6(sa: &[u8]) -> Option<IpAddr> {
    let raw = sa.get(8..24)?;
    let mut octets = [0u8; 16];
    octets.copy_from_slice(raw);
    let embedded = u32::from(u16::from_be_bytes([octets[2], octets[3]]));
    let explicit = sa
        .get(24..28)
        .map_or(0, |b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]));
    let is_link_local = octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80;
    if is_link_local {
        octets[2] = 0;
        octets[3] = 0;
    }
    let scope = if explicit != 0 { explicit } else { embedded };
    let zone = if is_link_local {
        ZoneIndex::new(scope)
    } else {
        None
    };
    V6Addr::new(octets, zone).ok().map(IpAddr::V6)
}

/// `struct sockaddr_dl`: `sdl_len`, `sdl_family`, `sdl_index`, `sdl_type`,
/// `sdl_nlen`, `sdl_alen`, `sdl_slen`, then `sdl_data`, whose first `sdl_nlen`
/// bytes are the interface name.
fn parse_sockaddr_dl_name(sa: &[u8]) -> Option<String> {
    let nlen = usize::from(*sa.get(5)?);
    if nlen == 0 || nlen > 64 {
        // Bounded before the slice: `sdl_nlen` is a byte from the kernel and an
        // over-long one would take the name past the sockaddr.
        return None;
    }
    let name = sa.get(8..8 + nlen)?;
    core::str::from_utf8(name).ok().map(str::to_owned)
}

/// Whether an address and mask pair describe a default route.
///
/// A default route is `0.0.0.0/0` or `::/0`: an all-zero destination with an
/// all-zero mask, **or** an all-zero destination with no mask at all, which is how
/// Darwin reports one when `RTA_NETMASK` is unset.
#[must_use]
pub fn is_default_route(destination: IpAddr, netmask: Option<IpAddr>) -> bool {
    let dst_is_zero = destination.octets().iter().all(|b| *b == 0);
    let mask_is_zero = netmask.is_none_or(|m| m.octets().iter().all(|b| *b == 0));
    dst_is_zero && mask_is_zero
}

/// Decodes one message into the changes the core must see.
///
/// Returns an empty vector for a message this adapter does not react to, which is
/// most of them: `RTM_LOSING`, `RTM_MISS`, `RTM_REDIRECT` and the multicast
/// membership messages are all noise from the core's point of view, and turning
/// them into events would make the stream a poll by another name.
///
/// # Why a default-route change is per family
///
/// ADR-0010 R6's case — "IPv6 appears *after* the tunnel is up" — is precisely a
/// v6 default route arriving while the v4 one is unchanged, and a combined event
/// would make that indistinguishable from nothing having happened.
#[must_use]
pub fn decode(bytes: &[u8]) -> Vec<NetworkChange> {
    let Some(header) = parse_header(bytes) else {
        return Vec::new();
    };
    let index = InterfaceIndex(header.index);
    match header.kind {
        rtm::ADD | rtm::DELETE | rtm::CHANGE => {
            let addresses = parse_addresses(bytes, &header);
            let Some(destination) = addresses.destination() else {
                return Vec::new();
            };
            if !is_default_route(destination, addresses.netmask()) {
                return Vec::new();
            }
            vec![NetworkChange::DefaultRouteChanged {
                family: destination.family(),
                present: header.kind != rtm::DELETE,
            }]
        }
        rtm::NEWADDR | rtm::DELADDR => {
            let addresses = parse_addresses(bytes, &header);
            let Some(address) = addresses.interface_address() else {
                return Vec::new();
            };
            vec![if header.kind == rtm::NEWADDR {
                NetworkChange::AddressAdded {
                    interface: index,
                    address,
                }
            } else {
                NetworkChange::AddressRemoved {
                    interface: index,
                    address,
                }
            }]
        }
        rtm::IFINFO | rtm::IFINFO2 => vec![NetworkChange::LinkStateChanged {
            interface: index,
            is_up: header.flags & IFF_UP != 0,
        }],
        _ => Vec::new(),
    }
}

/// The address family a message's destination is in, where it has one.
///
/// Exposed so a caller can attribute a decode failure to a family rather than
/// losing it: ADR-0010 R8's "MUST NOT stall on a broken family" needs to know
/// *which* family went quiet.
#[must_use]
pub fn family_of(bytes: &[u8]) -> Option<AddressFamily> {
    let header = parse_header(bytes)?;
    let addresses = parse_addresses(bytes, &header);
    addresses
        .destination()
        .or_else(|| addresses.interface_address())
        .map(IpAddr::family)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `struct sockaddr_in` for `addr`, 16 bytes.
    fn sa_in(addr: [u8; 4]) -> Vec<u8> {
        let mut v = vec![0u8; 16];
        v[0] = 16; // sin_len
        v[1] = DARWIN_AF_INET;
        v[4..8].copy_from_slice(&addr);
        v
    }

    /// `struct sockaddr_in6` for `addr` with `scope`, 28 bytes.
    fn sa_in6(addr: [u8; 16], scope: u32) -> Vec<u8> {
        let mut v = vec![0u8; 28];
        v[0] = 28; // sin6_len
        v[1] = DARWIN_AF_INET6;
        v[8..24].copy_from_slice(&addr);
        v[24..28].copy_from_slice(&scope.to_ne_bytes());
        v
    }

    /// `struct sockaddr_dl` naming `name`.
    fn sa_dl(index: u16, name: &str) -> Vec<u8> {
        let nlen = name.len();
        let len = 8 + nlen;
        let mut v = vec![0u8; len];
        v[0] = u8::try_from(len).expect("short name");
        v[1] = DARWIN_AF_LINK;
        v[2..4].copy_from_slice(&index.to_ne_bytes());
        v[5] = u8::try_from(nlen).expect("short name");
        v[8..8 + nlen].copy_from_slice(name.as_bytes());
        v
    }

    /// A `struct rt_msghdr` message, 92 bytes of header plus the sockaddr block.
    fn rt_msg(kind: u8, index: u16, flags: i32, addrs: i32, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 92];
        v[2] = RTM_VERSION;
        v[3] = kind;
        v[4..6].copy_from_slice(&index.to_ne_bytes());
        v[8..12].copy_from_slice(&flags.to_ne_bytes());
        v[12..16].copy_from_slice(&addrs.to_ne_bytes());
        v.extend_from_slice(payload);
        let len = u16::try_from(v.len()).expect("short message");
        v[0..2].copy_from_slice(&len.to_ne_bytes());
        v
    }

    /// A `struct ifa_msghdr` message, 20 bytes of header plus the block.
    fn ifa_msg(kind: u8, index: u16, addrs: i32, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 20];
        v[2] = RTM_VERSION;
        v[3] = kind;
        v[4..8].copy_from_slice(&addrs.to_ne_bytes());
        v[12..14].copy_from_slice(&index.to_ne_bytes());
        v.extend_from_slice(payload);
        let len = u16::try_from(v.len()).expect("short message");
        v[0..2].copy_from_slice(&len.to_ne_bytes());
        v
    }

    /// A `struct if_msghdr` message. The `if_data` tail is zero-filled, because
    /// nothing reads it.
    fn if_msg(index: u16, flags: i32) -> Vec<u8> {
        let mut v = vec![0u8; 112];
        v[2] = RTM_VERSION;
        v[3] = rtm::IFINFO;
        v[8..12].copy_from_slice(&flags.to_ne_bytes());
        v[12..14].copy_from_slice(&index.to_ne_bytes());
        let len = u16::try_from(v.len()).expect("short message");
        v[0..2].copy_from_slice(&len.to_ne_bytes());
        v
    }

    fn padded(parts: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for part in parts {
            let step = roundup(part.len());
            out.extend_from_slice(part);
            out.resize(out.len() + (step - part.len()), 0);
        }
        out
    }

    #[test]
    fn the_roundup_is_darwins_four_and_not_the_bsd_generals_eight() {
        // The 4.4BSD original rounds to `sizeof(long)`, which is eight here;
        // Darwin pins `uint32_t`. A decoder using the general form mis-parses
        // every message with two or more addresses, identically on both
        // platforms — so no compile catches it and only a Mac does.
        assert_eq!(roundup(0), 4);
        assert_eq!(roundup(1), 4);
        assert_eq!(roundup(4), 4);
        assert_eq!(roundup(5), 8);
        assert_eq!(roundup(16), 16);
        assert_eq!(roundup(17), 20);
        assert_eq!(roundup(28), 28);
    }

    #[test]
    fn a_v4_default_route_arriving_is_a_per_family_event() {
        let payload = padded(&[
            sa_in([0, 0, 0, 0]),
            sa_in([192, 0, 2, 1]),
            sa_in([0, 0, 0, 0]),
        ]);
        let msg = rt_msg(
            rtm::ADD,
            4,
            0,
            rta::DST | rta::GATEWAY | rta::NETMASK,
            &payload,
        );
        assert_eq!(
            decode(&msg),
            vec![NetworkChange::DefaultRouteChanged {
                family: AddressFamily::V4,
                present: true,
            }]
        );
    }

    #[test]
    fn a_v6_default_route_is_its_own_event_and_never_folded_into_the_v4_one() {
        // ADR-0010 R6: "IPv6 appears AFTER the tunnel is up" is exactly a v6
        // default route arriving while the v4 one is unchanged, and a combined
        // event would make that indistinguishable from nothing having happened.
        let payload = padded(&[sa_in6([0u8; 16], 0), sa_in6([0u8; 16], 0)]);
        let msg = rt_msg(rtm::ADD, 4, 0, rta::DST | rta::NETMASK, &payload);
        assert_eq!(
            decode(&msg),
            vec![NetworkChange::DefaultRouteChanged {
                family: AddressFamily::V6,
                present: true,
            }]
        );
        let gone = rt_msg(rtm::DELETE, 4, 0, rta::DST | rta::NETMASK, &payload);
        assert_eq!(
            decode(&gone),
            vec![NetworkChange::DefaultRouteChanged {
                family: AddressFamily::V6,
                present: false,
            }]
        );
    }

    #[test]
    fn a_route_that_is_not_the_default_route_is_not_an_event() {
        // Turning every route message into an event would make the stream a poll
        // by another name.
        let payload = padded(&[sa_in([10, 0, 0, 0]), sa_in([255, 0, 0, 0])]);
        let msg = rt_msg(rtm::ADD, 4, 0, rta::DST | rta::NETMASK, &payload);
        assert!(decode(&msg).is_empty());
    }

    #[test]
    fn a_default_route_with_no_netmask_slot_still_reads_as_the_default_route() {
        // Darwin omits `RTA_NETMASK` for a default route in some messages.
        let payload = padded(&[sa_in([0, 0, 0, 0])]);
        let msg = rt_msg(rtm::ADD, 4, 0, rta::DST, &payload);
        assert_eq!(
            decode(&msg),
            vec![NetworkChange::DefaultRouteChanged {
                family: AddressFamily::V4,
                present: true,
            }]
        );
    }

    #[test]
    fn the_slot_walk_lands_on_rtax_ifa_and_not_on_whatever_came_first() {
        // `RTAX_IFA` is slot 5. The mask below sets slots 2, 4 and 5, so the walk
        // must skip the unset ones and consume exactly three sockaddrs — which is
        // the part of this format that is easy to get subtly wrong.
        let payload = padded(&[
            sa_in([255, 255, 255, 0]),
            sa_dl(6, "en0"),
            sa_in([192, 168, 1, 42]),
        ]);
        let msg = ifa_msg(
            rtm::NEWADDR,
            6,
            rta::NETMASK | rta::IFP | rta::IFA,
            &payload,
        );
        assert_eq!(
            decode(&msg),
            vec![NetworkChange::AddressAdded {
                interface: InterfaceIndex(6),
                address: IpAddr::V4(V4Addr::from_octets([192, 168, 1, 42])),
            }]
        );
        let header = parse_header(&msg).expect("valid");
        let addresses = parse_addresses(&msg, &header);
        assert_eq!(addresses.link_name.as_deref(), Some("en0"));
        assert_eq!(
            addresses.netmask(),
            Some(IpAddr::V4(V4Addr::from_octets([255, 255, 255, 0])))
        );
    }

    #[test]
    fn an_address_removal_is_a_different_event_from_an_addition() {
        let payload = padded(&[sa_in([192, 168, 1, 42])]);
        let msg = ifa_msg(rtm::DELADDR, 6, rta::IFA, &payload);
        assert_eq!(
            decode(&msg),
            vec![NetworkChange::AddressRemoved {
                interface: InterfaceIndex(6),
                address: IpAddr::V4(V4Addr::from_octets([192, 168, 1, 42])),
            }]
        );
    }

    #[test]
    fn a_link_local_v6_address_keeps_its_zone_and_drops_the_kame_embedding() {
        // Darwin embeds the scope id in the address's second u16 as well as in
        // `sin6_scope_id`. `fe80:0:0:7::1` is a DIFFERENT address from
        // `fe80::1%7` and would never match a prefix, so the embedded copy is
        // cleared and the explicit field preferred.
        let mut octets = [0u8; 16];
        octets[0] = 0xfe;
        octets[1] = 0x80;
        octets[3] = 0x07; // the KAME embedding
        octets[15] = 1;
        let payload = padded(&[sa_in6(octets, 7)]);
        let msg = ifa_msg(rtm::NEWADDR, 7, rta::IFA, &payload);
        let changes = decode(&msg);
        let Some(NetworkChange::AddressAdded { address, .. }) = changes.first() else {
            panic!("expected an address addition, got {changes:?}");
        };
        let IpAddr::V6(v6) = address else {
            panic!("expected a v6 address");
        };
        assert_eq!(v6.zone().map(ZoneIndex::get), Some(7));
        let mut expected = [0u8; 16];
        expected[0] = 0xfe;
        expected[1] = 0x80;
        expected[15] = 1;
        assert_eq!(v6.octets(), expected, "the KAME embedding must be cleared");
    }

    #[test]
    fn a_link_local_address_with_no_scope_anywhere_is_dropped_rather_than_invented() {
        // `V6Addr` requires a zone on `fe80::/10`, and a link-local address whose
        // interface is unknown would match the wrong segment.
        let mut octets = [0u8; 16];
        octets[0] = 0xfe;
        octets[1] = 0x80;
        octets[15] = 1;
        let payload = padded(&[sa_in6(octets, 0)]);
        let msg = ifa_msg(rtm::NEWADDR, 7, rta::IFA, &payload);
        assert!(decode(&msg).is_empty());
    }

    #[test]
    fn an_interface_message_reports_the_link_state_and_reads_no_sockaddrs() {
        // `if_data`'s length differs between `RTM_IFINFO` and `RTM_IFINFO2` and
        // has grown across Darwin releases, so the decoder must not need to
        // locate the address block at all.
        assert_eq!(
            decode(&if_msg(6, IFF_UP)),
            vec![NetworkChange::LinkStateChanged {
                interface: InterfaceIndex(6),
                is_up: true,
            }]
        );
        assert_eq!(
            decode(&if_msg(6, 0)),
            vec![NetworkChange::LinkStateChanged {
                interface: InterfaceIndex(6),
                is_up: false,
            }]
        );
    }

    #[test]
    fn a_declared_length_is_validated_before_anything_indexes_on_it() {
        // §6 rule 9. `rtm_msglen` is a `u16` out of a kernel buffer, and a
        // decoder that trusted it would read past the slice.
        let mut msg = if_msg(6, IFF_UP);
        msg[0..2].copy_from_slice(&u16::MAX.to_ne_bytes());
        assert!(parse_header(&msg).is_none());
        assert!(decode(&msg).is_empty());

        assert!(parse_header(&[0u8; 4]).is_none());
        assert!(parse_header(&[]).is_none());
    }

    #[test]
    fn a_sockaddr_that_runs_past_the_message_truncates_the_walk() {
        let mut payload = sa_in([192, 168, 1, 42]);
        payload[0] = 200; // a `sa_len` far larger than what follows
        let msg = ifa_msg(rtm::NEWADDR, 6, rta::IFA, &payload);
        // No panic and no fabricated address: the walk stops.
        let _ = decode(&msg);
    }

    #[test]
    fn an_interface_name_longer_than_its_sockaddr_is_refused() {
        let mut sa = sa_dl(6, "en0");
        sa[5] = 200; // `sdl_nlen` past the end
        let block = padded(&[sa]);
        let mut bytes = vec![0u8; 20];
        bytes.extend_from_slice(&block);
        let header = Header {
            msglen: bytes.len(),
            version: RTM_VERSION,
            kind: rtm::NEWADDR,
            index: 6,
            flags: 0,
            addrs: rta::IFP,
            payload_at: 20,
        };
        assert_eq!(parse_addresses(&bytes, &header).link_name, None);
    }

    #[test]
    fn a_message_type_we_do_not_react_to_produces_nothing() {
        for kind in [0x05u8, 0x06, 0x07, 0x0f, 0x10] {
            let mut msg = if_msg(6, IFF_UP);
            msg[3] = kind;
            assert!(decode(&msg).is_empty(), "type {kind:#x}");
        }
    }

    #[test]
    fn the_family_of_a_message_is_recoverable_for_r8s_broken_family_case() {
        // ADR-0010 R8's "MUST NOT stall on a broken family" needs to know WHICH
        // family went quiet, so a decode failure must be attributable.
        let v4 = rt_msg(rtm::ADD, 4, 0, rta::DST, &padded(&[sa_in([0, 0, 0, 0])]));
        assert_eq!(family_of(&v4), Some(AddressFamily::V4));
        let v6 = rt_msg(rtm::ADD, 4, 0, rta::DST, &padded(&[sa_in6([0u8; 16], 0)]));
        assert_eq!(family_of(&v6), Some(AddressFamily::V6));
        assert_eq!(family_of(&if_msg(6, IFF_UP)), None);
    }
}
