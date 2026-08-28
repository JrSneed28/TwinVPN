//! Translating a packet in place, and paying the checksums that costs.
//!
//! A NAT that rewrote an address and left the checksum alone would produce a
//! condition no real middlebox produces: the receiver would drop the packet, the
//! scenario would report "no traversal", and the conclusion would be about the
//! laboratory rather than about TwinVPN. So every rewrite here recomputes every
//! checksum the change invalidates, from scratch rather than incrementally.
//!
//! **Full recomputation is deliberate.** RFC 1624's incremental update is faster
//! and is the standard source of one-off arithmetic errors; at this laboratory's
//! packet rates the difference is unmeasurable and the correctness argument is
//! "sum the bytes", which a reviewer can check.

use std::net::IpAddr;

use crate::ip::{proto, Parsed};

/// The upper-layer length the checksum covers, taken from the IP header rather
/// than from the frame, because Ethernet pads a short frame and the padding is
/// not part of any checksum.
#[must_use]
pub fn l4_len(p: &Parsed) -> usize {
    match p.src {
        IpAddr::V4(_) => p.ip_payload_len,
        IpAddr::V6(_) => p
            .ip_payload_len
            .saturating_sub(p.l4_off.saturating_sub(p.l3_off + 40)),
    }
}

/// The Internet checksum of a sequence of byte runs, plus a scalar addend.
///
/// Exposed because [`crate::nat::xlat`] builds a *new* packet rather than
/// editing one, so it cannot use the in-place helpers below — and a second
/// implementation of the one arithmetic operation every header in this crate
/// depends on is the last thing a laboratory needs.
#[must_use]
pub fn internet_checksum(runs: &[&[u8]], addend: u32) -> u16 {
    let mut sum = addend;
    for run in runs {
        accumulate(&mut sum, run);
    }
    fold(sum)
}

fn accumulate(sum: &mut u32, bytes: &[u8]) {
    let mut i = 0;
    while i + 1 < bytes.len() {
        *sum += u32::from(u16::from_be_bytes([bytes[i], bytes[i + 1]]));
        i += 2;
    }
    if i < bytes.len() {
        *sum += u32::from(u16::from_be_bytes([bytes[i], 0]));
    }
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Recomputes the IPv4 header checksum. A no-op for IPv6, which has none.
pub fn fix_ip_checksum(frame: &mut [u8], p: &Parsed) {
    if !matches!(p.src, IpAddr::V4(_)) {
        return;
    }
    let ihl = usize::from(frame[p.l3_off] & 0x0f) * 4;
    let Some(hdr) = frame.get_mut(p.l3_off..p.l3_off + ihl) else {
        return;
    };
    hdr[10] = 0;
    hdr[11] = 0;
    let mut sum = 0u32;
    accumulate(&mut sum, hdr);
    let c = fold(sum).to_be_bytes();
    hdr[10] = c[0];
    hdr[11] = c[1];
}

/// Recomputes the transport checksum, with the pseudo-header the family
/// requires.
///
/// An IPv4 UDP datagram that arrived with a zero checksum keeps one: RFC 768
/// makes it optional there, and a NAT that manufactured one would be
/// distinguishable from a NAT that did not.
pub fn fix_l4_checksum(frame: &mut [u8], p: &Parsed) {
    let len = l4_len(p);
    if len == 0 || p.l4_off + len > frame.len() {
        return;
    }
    let csum_off = match p.proto {
        proto::UDP => p.l4_off + 6,
        proto::TCP => p.l4_off + 16,
        proto::ICMPV6 => p.l4_off + 2,
        // An IPv4 ICMP checksum covers only the ICMP message, so an address
        // rewrite does not disturb it — but an echo-identifier rewrite does.
        proto::ICMP => {
            let Some(msg) = frame.get_mut(p.l4_off..p.l4_off + len) else {
                return;
            };
            msg[2] = 0;
            msg[3] = 0;
            let mut sum = 0u32;
            accumulate(&mut sum, msg);
            let c = fold(sum).to_be_bytes();
            msg[2] = c[0];
            msg[3] = c[1];
            return;
        }
        _ => return,
    };
    if p.proto == proto::UDP
        && frame[csum_off] == 0
        && frame[csum_off + 1] == 0
        && matches!(p.src, IpAddr::V4(_))
    {
        return;
    }
    frame[csum_off] = 0;
    frame[csum_off + 1] = 0;

    let mut sum = 0u32;
    match (p.src, p.dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            accumulate(&mut sum, &s.octets());
            accumulate(&mut sum, &d.octets());
            sum += u32::from(p.proto);
            sum += len as u32;
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            accumulate(&mut sum, &s.octets());
            accumulate(&mut sum, &d.octets());
            sum += len as u32;
            sum += u32::from(p.proto);
        }
        _ => return,
    }
    accumulate(&mut sum, &frame[p.l4_off..p.l4_off + len]);
    let mut c = fold(sum);
    // RFC 768: a computed zero is transmitted as all ones, so that zero keeps
    // meaning "no checksum".
    if c == 0 && p.proto == proto::UDP {
        c = 0xffff;
    }
    let c = c.to_be_bytes();
    frame[csum_off] = c[0];
    frame[csum_off + 1] = c[1];
}

/// Replaces the source address, and repairs every checksum that covered it.
///
/// The `Parsed` is updated so a caller can chain rewrites without re-parsing,
/// which is what makes a NAT translation one pass over the frame.
pub fn set_src(frame: &mut [u8], p: &mut Parsed, addr: IpAddr) {
    write_addr(frame, p, addr, true);
    p.src = addr;
    fix_ip_checksum(frame, p);
    fix_l4_checksum(frame, p);
}

/// Replaces the destination address, and repairs every checksum.
pub fn set_dst(frame: &mut [u8], p: &mut Parsed, addr: IpAddr) {
    write_addr(frame, p, addr, false);
    p.dst = addr;
    fix_ip_checksum(frame, p);
    fix_l4_checksum(frame, p);
}

fn write_addr(frame: &mut [u8], p: &Parsed, addr: IpAddr, source: bool) {
    match (p.src, addr) {
        (IpAddr::V4(_), IpAddr::V4(a)) => {
            let off = p.l3_off + if source { 12 } else { 16 };
            if off + 4 <= frame.len() {
                frame[off..off + 4].copy_from_slice(&a.octets());
            }
        }
        (IpAddr::V6(_), IpAddr::V6(a)) => {
            let off = p.l3_off + if source { 8 } else { 24 };
            if off + 16 <= frame.len() {
                frame[off..off + 16].copy_from_slice(&a.octets());
            }
        }
        // A family change is NAT64's job and is a whole new packet, not a
        // rewrite. `natbox` builds that one rather than calling this.
        _ => {}
    }
}

/// Replaces the source port, or an ICMP echo identifier.
pub fn set_src_port(frame: &mut [u8], p: &mut Parsed, port: u16) {
    write_port(frame, p, port, true);
    p.src_port = Some(port);
    fix_l4_checksum(frame, p);
}

/// Replaces the destination port, or an ICMP echo identifier.
pub fn set_dst_port(frame: &mut [u8], p: &mut Parsed, port: u16) {
    write_port(frame, p, port, false);
    p.dst_port = Some(port);
    fix_l4_checksum(frame, p);
}

fn write_port(frame: &mut [u8], p: &Parsed, port: u16, source: bool) {
    let bytes = port.to_be_bytes();
    match p.proto {
        proto::UDP | proto::TCP => {
            let off = p.l4_off + if source { 0 } else { 2 };
            if off + 2 <= frame.len() {
                frame[off..off + 2].copy_from_slice(&bytes);
            }
        }
        proto::ICMP | proto::ICMPV6 => {
            // One identifier serves as both ports; writing it twice would be a
            // second write of the same two octets.
            let off = p.l4_off + 4;
            if off + 2 <= frame.len() {
                frame[off..off + 2].copy_from_slice(&bytes);
            }
        }
        _ => {}
    }
}

/// Rewrites the Ethernet header for the next hop.
///
/// A middlebox that forwarded a frame with its ingress MAC addresses intact
/// would be relying on the egress segment being promiscuous, which is a property
/// of the laboratory and not of a network.
pub fn set_ethernet(frame: &mut [u8], dst: [u8; 6], src: [u8; 6]) {
    if frame.len() < 12 {
        return;
    }
    frame[0..6].copy_from_slice(&dst);
    frame[6..12].copy_from_slice(&src);
}

/// Decrements the IPv4 TTL or the IPv6 hop limit, returning `false` when the
/// packet has expired.
///
/// A NAT is a router. A router that did not decrement would make a forwarding
/// loop invisible, and a loop is exactly what a misconfigured scenario builds.
#[must_use]
pub fn decrement_hop_limit(frame: &mut [u8], p: &Parsed) -> bool {
    let off = match p.src {
        IpAddr::V4(_) => p.l3_off + 8,
        IpAddr::V6(_) => p.l3_off + 7,
    };
    let Some(byte) = frame.get_mut(off) else {
        return false;
    };
    if *byte <= 1 {
        return false;
    }
    *byte -= 1;
    if matches!(p.src, IpAddr::V4(_)) {
        fix_ip_checksum(frame, p);
    }
    true
}
