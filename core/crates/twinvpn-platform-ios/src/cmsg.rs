//! The Darwin control-message parser — **target-free**, so it is tested here.
//!
//! **Authority:** `docs/networking.md` §3.4 (the disco probe's reflexive
//! candidate) and §8 (LAN discovery); [`twinvpn_platform::Datagram`];
//! `docs/implementation/ownership.md` §10.3's design rule.
//!
//! # Why a parser rather than the `CMSG_*` macros
//!
//! `SocketOptions::receive_packet_info` exists because "without it a socket bound
//! to the wildcard cannot tell which of its addresses a probe arrived on, which
//! the disco probe of §3.4 needs to attribute a reflexive candidate correctly".
//! Getting that address means a `recvmsg` with a control buffer, and walking the
//! buffer means `CMSG_FIRSTHDR`/`CMSG_NXTHDR`/`CMSG_DATA` — C macros with no Rust
//! equivalent, whose Darwin definitions differ from Linux's in the one way that
//! matters.
//!
//! The **syscall** must be `#[cfg]`-gated. The **walk** need not be: it is
//! arithmetic over a byte buffer. So the walk lives here, over `&[u8]`, and its
//! tests build synthetic Darwin control buffers and run on the Linux build host.
//! That is `ownership.md` §10.3's rule applied to the layer that is otherwise
//! guaranteed to be untested until a device farm exists.
//!
//! # The alignment difference, which is the whole trap
//!
//! Linux aligns each control message to `sizeof(size_t)` — **8** bytes on a
//! 64-bit host. Darwin's `<sys/socket.h>` aligns to `sizeof(uint32_t)` — **4**:
//!
//! ```text
//! #define __DARWIN_ALIGN32(p)  (((uintptr_t)(p) + 3) & ~3)
//! #define CMSG_DATA(cmsg)      ((unsigned char *)(cmsg) + __DARWIN_ALIGN32(sizeof(struct cmsghdr)))
//! #define CMSG_SPACE(l)        (__DARWIN_ALIGN32(sizeof(struct cmsghdr)) + __DARWIN_ALIGN32(l))
//! #define CMSG_LEN(l)          (__DARWIN_ALIGN32(sizeof(struct cmsghdr)) + (l))
//! ```
//!
//! A walk written against Linux's alignment reads the second control message at
//! the wrong offset on Darwin whenever the first one's payload is not a multiple
//! of 8 — which `in_pktinfo` (12 bytes) is not. The failure is a *misparsed
//! address*, not a crash, so it would surface as a reflexive candidate pointing
//! somewhere plausible and wrong.
//!
//! # The constants are transcribed and marked as such
//!
//! Every value below comes from Apple's `<netinet/in.h>` and `<netinet6/in6.h>`.
//! They are not imported, because that would make this module reachable only on a
//! Darwin builder and would put its tests in `ownership.md` §9.2's
//! *written, not executed* row. A Darwin builder should verify them once; until
//! then they are marked here rather than presented as derived.

use twinvpn_types::{IpAddr, V4Addr, V6Addr};

use twinvpn_platform::InterfaceIndex;

/// `IPPROTO_IP`.
pub const IPPROTO_IP: i32 = 0;
/// `IPPROTO_IPV6`.
pub const IPPROTO_IPV6: i32 = 41;
/// `IP_PKTINFO` — the Darwin cmsg type carrying `struct in_pktinfo`.
pub const IP_PKTINFO: i32 = 26;
/// `IP_RECVDSTADDR` — the older Darwin cmsg carrying just `struct in_addr`.
///
/// Still delivered by some paths, so both are accepted. A socket that set
/// `IP_RECVPKTINFO` and received an `IP_RECVDSTADDR` message must not report "no
/// destination": that would silently disable reflexive-candidate attribution.
pub const IP_RECVDSTADDR: i32 = 7;
/// `IP_RECVIF` — Darwin's arrival-interface cmsg, carrying a `sockaddr_dl`.
pub const IP_RECVIF: i32 = 20;
/// `IPV6_PKTINFO` — the cmsg type carrying `struct in6_pktinfo`.
pub const IPV6_PKTINFO: i32 = 46;

/// `sizeof(struct cmsghdr)` on 64-bit Darwin: `socklen_t` + two `int`.
pub const CMSG_HEADER_BYTES: usize = 12;

/// Darwin's `__DARWIN_ALIGN32`.
///
/// **Four**, not eight. See the module header for why this single number is the
/// whole trap.
pub const CMSG_ALIGN_BYTES: usize = 4;

/// Aligns to Darwin's control-message boundary.
#[must_use]
pub const fn cmsg_align(len: usize) -> usize {
    (len + CMSG_ALIGN_BYTES - 1) & !(CMSG_ALIGN_BYTES - 1)
}

/// Darwin's `CMSG_SPACE`.
#[must_use]
pub const fn cmsg_space(payload: usize) -> usize {
    cmsg_align(CMSG_HEADER_BYTES) + cmsg_align(payload)
}

/// Darwin's `CMSG_LEN`.
#[must_use]
pub const fn cmsg_len(payload: usize) -> usize {
    cmsg_align(CMSG_HEADER_BYTES) + payload
}

/// A control buffer large enough for both families' packet-info messages.
///
/// Sized rather than guessed: v4 may deliver `IP_PKTINFO` *and* `IP_RECVIF`, and
/// v6 delivers `IPV6_PKTINFO`. An undersized buffer makes the kernel set
/// `MSG_CTRUNC` and drop the very field the option was set to obtain.
pub const CONTROL_BUFFER_BYTES: usize = cmsg_space(12) + cmsg_space(20) + cmsg_space(20);

/// What a control buffer said about where a datagram arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ArrivalInfo {
    /// Which of our addresses it arrived on.
    pub destination: Option<IpAddr>,
    /// Which interface it arrived on.
    pub interface: Option<InterfaceIndex>,
}

/// Walks a Darwin control buffer.
///
/// Malformed input yields whatever was parsed before the malformation, never a
/// panic and never a partial read past the end: every field is bounds-checked
/// against the buffer *and* against the message's own declared length before it
/// is read. A kernel is trusted; a fuzzer reaching this through a test is not,
/// and the two must be indistinguishable to the code.
#[must_use]
#[allow(clippy::missing_panics_doc)]
pub fn parse(buffer: &[u8]) -> ArrivalInfo {
    let mut out = ArrivalInfo::default();
    let mut offset = 0usize;

    while offset + CMSG_HEADER_BYTES <= buffer.len() {
        let len = u32::from_ne_bytes(
            buffer[offset..offset + 4]
                .try_into()
                .expect("four bytes, bounds-checked above"),
        ) as usize;
        let level = i32::from_ne_bytes(
            buffer[offset + 4..offset + 8]
                .try_into()
                .expect("four bytes"),
        );
        let kind = i32::from_ne_bytes(
            buffer[offset + 8..offset + 12]
                .try_into()
                .expect("four bytes"),
        );

        // A message shorter than its own header, or longer than the buffer, ends
        // the walk. Continuing would read the next header out of payload bytes.
        if len < CMSG_HEADER_BYTES || offset + len > buffer.len() {
            break;
        }
        let data = &buffer[offset + cmsg_align(CMSG_HEADER_BYTES)..offset + len];

        match (level, kind) {
            // struct in_pktinfo { u32 ipi_ifindex; in_addr ipi_spec_dst; in_addr ipi_addr; }
            (IPPROTO_IP, IP_PKTINFO) if data.len() >= 12 => {
                let index = u32::from_ne_bytes(data[0..4].try_into().expect("four bytes"));
                if index != 0 {
                    out.interface = Some(InterfaceIndex(index));
                }
                // `ipi_addr` — the address the datagram was actually sent to —
                // is the last field, and it is the one §3.4 needs. `ipi_spec_dst`
                // is the local source the route chose, which is a different
                // question with a frequently different answer.
                out.destination = Some(IpAddr::V4(V4Addr::from_octets(
                    data[8..12].try_into().expect("four bytes"),
                )));
            }
            (IPPROTO_IP, IP_RECVDSTADDR) if data.len() >= 4 => {
                out.destination = Some(IpAddr::V4(V4Addr::from_octets(
                    data[0..4].try_into().expect("four bytes"),
                )));
            }
            // struct sockaddr_dl { u8 sdl_len; u8 sdl_family; u16 sdl_index; ... }
            (IPPROTO_IP, IP_RECVIF) if data.len() >= 4 => {
                let index = u32::from(u16::from_ne_bytes(
                    data[2..4].try_into().expect("two bytes"),
                ));
                if index != 0 {
                    out.interface = Some(InterfaceIndex(index));
                }
            }
            // struct in6_pktinfo { in6_addr ipi6_addr; u32 ipi6_ifindex; }
            (IPPROTO_IPV6, IPV6_PKTINFO) if data.len() >= 20 => {
                let index = u32::from_ne_bytes(data[16..20].try_into().expect("four bytes"));
                if index != 0 {
                    out.interface = Some(InterfaceIndex(index));
                }
                let octets: [u8; 16] = data[0..16].try_into().expect("sixteen bytes");
                // A zone is required on `fe80::/10` and refused elsewhere, so it
                // is supplied from the arrival interface — which is exactly the
                // zone the address has. Where the interface is unknown the
                // address is dropped rather than spelled without its scope: a
                // link-local without a zone names no interface at all.
                if let Ok(addr) = V6Addr::from_slice(&octets, index) {
                    out.destination = Some(IpAddr::V6(addr));
                }
            }
            _ => {}
        }

        // Darwin's CMSG_NXTHDR: advance by the ALIGNED length. Advancing by the
        // unaligned one is the Linux-alignment bug in its most direct form.
        let step = cmsg_align(len);
        if step == 0 {
            break;
        }
        offset += step;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds one Darwin control message.
    fn message(level: i32, kind: i32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let len = cmsg_len(payload.len());
        out.extend_from_slice(
            &u32::try_from(len)
                .expect("a control message fits in u32")
                .to_ne_bytes(),
        );
        out.extend_from_slice(&level.to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(payload);
        out.resize(cmsg_space(payload.len()), 0);
        out
    }

    fn in_pktinfo(ifindex: u32, spec_dst: [u8; 4], addr: [u8; 4]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&ifindex.to_ne_bytes());
        payload.extend_from_slice(&spec_dst);
        payload.extend_from_slice(&addr);
        payload
    }

    fn in6_pktinfo(addr: [u8; 16], ifindex: u32) -> Vec<u8> {
        let mut payload = addr.to_vec();
        payload.extend_from_slice(&ifindex.to_ne_bytes());
        payload
    }

    #[test]
    fn darwin_aligns_control_messages_to_four_bytes_and_not_to_eight() {
        // The whole trap, pinned. `in_pktinfo` is 12 bytes: under Darwin's
        // 4-byte alignment the next message starts at 12 + 12 = 24; under
        // Linux's 8-byte alignment it would start at 16 + 16 = 32, and the walk
        // would read the second message's header out of nothing.
        assert_eq!(CMSG_ALIGN_BYTES, 4);
        assert_eq!(cmsg_align(12), 12);
        assert_eq!(cmsg_align(13), 16);
        assert_eq!(cmsg_len(12), 24);
        assert_eq!(cmsg_space(12), 24);
        // And the two alignments genuinely disagree for a real payload size.
        let linux_align = |len: usize| (len + 7) & !7;
        assert_ne!(cmsg_space(20), linux_align(12) + linux_align(20));
    }

    #[test]
    fn a_v4_arrival_address_is_ipi_addr_and_not_ipi_spec_dst() {
        // `ipi_spec_dst` is the local source the route chose; `ipi_addr` is the
        // address the datagram was actually sent to. §3.4's reflexive candidate
        // needs the second, and the two frequently differ on a multi-homed host.
        let buffer = message(
            IPPROTO_IP,
            IP_PKTINFO,
            &in_pktinfo(7, [10, 0, 0, 1], [192, 0, 2, 55]),
        );
        let info = parse(&buffer);
        assert_eq!(
            info.destination,
            Some(IpAddr::V4(V4Addr::from_octets([192, 0, 2, 55])))
        );
        assert_eq!(info.interface, Some(InterfaceIndex(7)));
    }

    #[test]
    fn the_older_recvdstaddr_message_is_accepted_too() {
        // A socket that set IP_RECVPKTINFO and received IP_RECVDSTADDR must not
        // report "no destination" — that silently disables the attribution the
        // option was set to enable.
        let buffer = message(IPPROTO_IP, IP_RECVDSTADDR, &[198, 51, 100, 9]);
        assert_eq!(
            parse(&buffer).destination,
            Some(IpAddr::V4(V4Addr::from_octets([198, 51, 100, 9])))
        );
    }

    #[test]
    fn a_v6_arrival_carries_its_zone_from_the_arrival_interface() {
        // V6Addr requires a zone on fe80::/10, and the zone IS the arrival
        // interface. Spelling a link-local without one names no interface at all.
        let mut link_local = [0u8; 16];
        link_local[0] = 0xfe;
        link_local[1] = 0x80;
        link_local[15] = 0x01;
        let buffer = message(IPPROTO_IPV6, IPV6_PKTINFO, &in6_pktinfo(link_local, 4));
        let info = parse(&buffer);
        assert_eq!(info.interface, Some(InterfaceIndex(4)));
        match info.destination {
            Some(IpAddr::V6(addr)) => {
                assert!(addr.is_link_local());
                assert_eq!(addr.zone_index_wire(), 4);
            }
            other => panic!("expected a zoned v6 address, got {other:?}"),
        }
    }

    #[test]
    fn a_link_local_with_no_interface_is_dropped_rather_than_spelled_unscoped() {
        let mut link_local = [0u8; 16];
        link_local[0] = 0xfe;
        link_local[1] = 0x80;
        let buffer = message(IPPROTO_IPV6, IPV6_PKTINFO, &in6_pktinfo(link_local, 0));
        let info = parse(&buffer);
        assert_eq!(info.interface, None);
        assert_eq!(info.destination, None);
    }

    #[test]
    fn two_messages_are_both_read_at_darwins_alignment() {
        // This is the test the Linux-alignment bug fails: the second message
        // starts at 24, not at 32.
        let mut buffer = message(
            IPPROTO_IP,
            IP_PKTINFO,
            &in_pktinfo(0, [0, 0, 0, 0], [203, 0, 113, 1]),
        );
        let mut sdl = vec![0u8; 20];
        sdl[0] = 20;
        sdl[2..4].copy_from_slice(&12u16.to_ne_bytes());
        buffer.extend_from_slice(&message(IPPROTO_IP, IP_RECVIF, &sdl));

        let info = parse(&buffer);
        assert_eq!(
            info.destination,
            Some(IpAddr::V4(V4Addr::from_octets([203, 0, 113, 1])))
        );
        assert_eq!(
            info.interface,
            Some(InterfaceIndex(12)),
            "the second message was read; a Linux-aligned walk would miss it"
        );
    }

    #[test]
    fn a_malformed_buffer_yields_what_was_parsed_and_never_panics() {
        // Every field is bounds-checked against the buffer AND against the
        // message's own declared length. A kernel is trusted; this code must not
        // depend on that.
        assert_eq!(parse(&[]), ArrivalInfo::default());
        assert_eq!(parse(&[0u8; 5]), ArrivalInfo::default());
        // A length smaller than the header.
        let mut runt = vec![0u8; 12];
        runt[0] = 4;
        assert_eq!(parse(&runt), ArrivalInfo::default());
        // A length longer than the buffer.
        let mut over = vec![0u8; 12];
        over[0..4].copy_from_slice(&999u32.to_ne_bytes());
        assert_eq!(parse(&over), ArrivalInfo::default());
        // A well-formed first message followed by garbage: the first survives.
        let mut mixed = message(IPPROTO_IP, IP_RECVDSTADDR, &[1, 2, 3, 4]);
        mixed.extend_from_slice(&[0xff; 7]);
        assert_eq!(
            parse(&mixed).destination,
            Some(IpAddr::V4(V4Addr::from_octets([1, 2, 3, 4])))
        );
    }

    #[test]
    fn a_message_shorter_than_its_declared_payload_is_not_read_past() {
        let mut short = Vec::new();
        short.extend_from_slice(&u32::try_from(cmsg_len(12)).expect("fits").to_ne_bytes());
        short.extend_from_slice(&IPPROTO_IP.to_ne_bytes());
        short.extend_from_slice(&IP_PKTINFO.to_ne_bytes());
        short.extend_from_slice(&[0u8; 4]); // only four of the twelve payload bytes
        assert_eq!(parse(&short), ArrivalInfo::default());
    }

    #[test]
    fn an_unknown_level_or_type_is_skipped_without_ending_the_walk() {
        let mut buffer = message(99, 99, &[0u8; 8]);
        buffer.extend_from_slice(&message(IPPROTO_IP, IP_RECVDSTADDR, &[9, 9, 9, 9]));
        assert_eq!(
            parse(&buffer).destination,
            Some(IpAddr::V4(V4Addr::from_octets([9, 9, 9, 9])))
        );
    }

    #[test]
    fn the_control_buffer_is_large_enough_for_everything_both_families_deliver() {
        // An undersized buffer makes the kernel set MSG_CTRUNC and drop the very
        // field the option was set to obtain.
        assert!(CONTROL_BUFFER_BYTES >= cmsg_space(12) + cmsg_space(20));
        assert!(CONTROL_BUFFER_BYTES >= cmsg_space(20));
    }
}
