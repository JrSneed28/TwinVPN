//! Reading an Ethernet frame down to its five-tuple, in safe Rust.
//!
//! **Why the laboratory parses packets itself.** `tcpdump` is not installed on
//! every runner this suite has to work on, and a capture piped through a text
//! parser turns a wire oracle into a string-matching exercise. Rule PT-2 wants
//! an *independent* observation of the wire; a parser that this crate owns, and
//! that the system under test shares no code with, is exactly that.
//!
//! # Scope, stated so a reader does not assume more
//!
//! This parses what a leak oracle and a NAT need: Ethernet, one optional VLAN
//! tag, IPv4 with options, IPv6 with the hop-by-hop, routing, destination and
//! fragment extension headers, UDP, TCP, ICMP and ICMPv6 echo, and enough of a
//! DNS message to recover the QNAME and QTYPE. It does **not** reassemble
//! fragments: a fragmented packet is reported as a fragment, and
//! [`crate::observer`] treats an unreassembled fragment carrying protected
//! addressing as a leak rather than as an unparseable frame.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Ethernet header length, with no VLAN tag.
pub const ETH_HDR: usize = 14;
/// IPv4's ethertype.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// IPv6's ethertype.
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
/// ARP's ethertype. Never translated, and never a leak — but it is *seen*, and
/// an observer that silently dropped it would report a quiet wire.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// 802.1Q.
pub const ETHERTYPE_VLAN: u16 = 0x8100;

/// IP protocol numbers this crate knows by name.
pub mod proto {
    /// ICMP for IPv4.
    pub const ICMP: u8 = 1;
    /// TCP.
    pub const TCP: u8 = 6;
    /// UDP.
    pub const UDP: u8 = 17;
    /// ICMPv6.
    pub const ICMPV6: u8 = 58;
    /// IPv6 hop-by-hop options.
    pub const HOPOPTS: u8 = 0;
    /// IPv6 routing header.
    pub const ROUTING: u8 = 43;
    /// IPv6 fragment header.
    pub const FRAGMENT: u8 = 44;
    /// IPv6 destination options.
    pub const DSTOPTS: u8 = 60;
    /// IPv6 "no next header".
    pub const NONXT: u8 = 59;
}

/// What a parsed frame turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// Destination MAC.
    pub eth_dst: [u8; 6],
    /// Source MAC.
    pub eth_src: [u8; 6],
    /// The ethertype after any VLAN tag.
    pub ethertype: u16,
    /// Offset of the IP header.
    pub l3_off: usize,
    /// Source address.
    pub src: IpAddr,
    /// Destination address.
    pub dst: IpAddr,
    /// The upper-layer protocol number, after any IPv6 extension headers.
    pub proto: u8,
    /// Offset of the upper-layer header.
    pub l4_off: usize,
    /// Source port, or an ICMP echo identifier.
    pub src_port: Option<u16>,
    /// Destination port, or an ICMP echo identifier.
    pub dst_port: Option<u16>,
    /// Offset of the upper-layer payload.
    pub payload_off: usize,
    /// Whether this is a non-initial or fragmented IP packet.
    pub fragmented: bool,
    /// The IP payload length as the header declares it.
    pub ip_payload_len: usize,
}

impl Parsed {
    /// Whether both endpoints are IPv6.
    #[must_use]
    pub const fn is_v6(&self) -> bool {
        matches!(self.src, IpAddr::V6(_))
    }

    /// The five-tuple as a NAT keys on it.
    #[must_use]
    pub fn tuple(&self) -> (IpAddr, u16, IpAddr, u16, u8) {
        (
            self.src,
            self.src_port.unwrap_or(0),
            self.dst,
            self.dst_port.unwrap_or(0),
            self.proto,
        )
    }
}

/// Parses an Ethernet frame. Returns `None` when the frame is truncated or is
/// not IP — an ARP frame parses to `None` here and is classified by
/// [`ethertype_of`], which the observer uses so that a non-IP frame is still
/// counted rather than discarded.
#[must_use]
pub fn parse(frame: &[u8]) -> Option<Parsed> {
    if frame.len() < ETH_HDR {
        return None;
    }
    let mut eth_dst = [0u8; 6];
    let mut eth_src = [0u8; 6];
    eth_dst.copy_from_slice(&frame[0..6]);
    eth_src.copy_from_slice(&frame[6..12]);
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut l3_off = ETH_HDR;
    if ethertype == ETHERTYPE_VLAN {
        if frame.len() < ETH_HDR + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[16], frame[17]]);
        l3_off = ETH_HDR + 4;
    }
    match ethertype {
        ETHERTYPE_IPV4 => parse_v4(frame, l3_off, eth_dst, eth_src, ethertype),
        ETHERTYPE_IPV6 => parse_v6(frame, l3_off, eth_dst, eth_src, ethertype),
        _ => None,
    }
}

/// The ethertype of a frame, whether or not it carries IP.
#[must_use]
pub fn ethertype_of(frame: &[u8]) -> Option<u16> {
    if frame.len() < ETH_HDR {
        return None;
    }
    let t = u16::from_be_bytes([frame[12], frame[13]]);
    if t == ETHERTYPE_VLAN && frame.len() >= ETH_HDR + 4 {
        return Some(u16::from_be_bytes([frame[16], frame[17]]));
    }
    Some(t)
}

fn parse_v4(
    frame: &[u8],
    l3_off: usize,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    ethertype: u16,
) -> Option<Parsed> {
    let ip = frame.get(l3_off..)?;
    if ip.len() < 20 || (ip[0] >> 4) != 4 {
        return None;
    }
    let ihl = usize::from(ip[0] & 0x0f) * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    let frag = u16::from_be_bytes([ip[6], ip[7]]);
    let more_fragments = frag & 0x2000 != 0;
    let frag_offset = frag & 0x1fff;
    let fragmented = more_fragments || frag_offset != 0;
    let proto = ip[9];
    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let l4_off = l3_off + ihl;
    let (src_port, dst_port, payload_off) = if frag_offset == 0 {
        ports(frame, l4_off, proto)
    } else {
        (None, None, l4_off)
    };
    Some(Parsed {
        eth_dst,
        eth_src,
        ethertype,
        l3_off,
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        proto,
        l4_off,
        src_port,
        dst_port,
        payload_off,
        fragmented,
        ip_payload_len: total_len.saturating_sub(ihl),
    })
}

fn parse_v6(
    frame: &[u8],
    l3_off: usize,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    ethertype: u16,
) -> Option<Parsed> {
    let ip = frame.get(l3_off..)?;
    if ip.len() < 40 || (ip[0] >> 4) != 6 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([ip[4], ip[5]]));
    let mut next = ip[6];
    let mut off = l3_off + 40;
    let mut fragmented = false;
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&ip[8..24]);
    dst.copy_from_slice(&ip[24..40]);

    // Walk the extension headers. Bounded by a fixed count rather than by
    // "until we find an upper layer": a crafted chain must terminate the parser,
    // and this parser reads bytes a peer wrote.
    for _ in 0..8 {
        match next {
            proto::HOPOPTS | proto::ROUTING | proto::DSTOPTS => {
                let hdr = frame.get(off..off + 2)?;
                let len = (usize::from(hdr[1]) + 1) * 8;
                next = hdr[0];
                off += len;
            }
            proto::FRAGMENT => {
                let hdr = frame.get(off..off + 8)?;
                fragmented = true;
                next = hdr[0];
                off += 8;
            }
            _ => break,
        }
    }
    let (src_port, dst_port, payload_off) = if fragmented {
        (None, None, off)
    } else {
        ports(frame, off, next)
    };
    Some(Parsed {
        eth_dst,
        eth_src,
        ethertype,
        l3_off,
        src: IpAddr::V6(Ipv6Addr::from(src)),
        dst: IpAddr::V6(Ipv6Addr::from(dst)),
        proto: next,
        l4_off: off,
        src_port,
        dst_port,
        payload_off,
        fragmented,
        ip_payload_len: payload_len,
    })
}

/// Source and destination "ports", where an ICMP echo identifier counts as
/// both.
///
/// Treating the echo identifier as a port is what makes `ping` traverse
/// [`crate::natbox`]. RFC 5508 says the same thing for a real NAT, so this is
/// the middlebox behaviour rather than a convenience for the test.
fn ports(frame: &[u8], l4_off: usize, proto: u8) -> (Option<u16>, Option<u16>, usize) {
    match proto {
        proto::UDP => match frame.get(l4_off..l4_off + 8) {
            Some(h) => (
                Some(u16::from_be_bytes([h[0], h[1]])),
                Some(u16::from_be_bytes([h[2], h[3]])),
                l4_off + 8,
            ),
            None => (None, None, l4_off),
        },
        proto::TCP => match frame.get(l4_off..l4_off + 20) {
            Some(h) => {
                let data_off = usize::from(h[12] >> 4) * 4;
                (
                    Some(u16::from_be_bytes([h[0], h[1]])),
                    Some(u16::from_be_bytes([h[2], h[3]])),
                    l4_off + data_off.max(20),
                )
            }
            None => (None, None, l4_off),
        },
        proto::ICMP | proto::ICMPV6 => match frame.get(l4_off..l4_off + 8) {
            Some(h) if is_echo(proto, h[0]) => {
                let id = u16::from_be_bytes([h[4], h[5]]);
                (Some(id), Some(id), l4_off + 8)
            }
            Some(_) => (None, None, l4_off + 8),
            None => (None, None, l4_off),
        },
        _ => (None, None, l4_off),
    }
}

/// Whether an ICMP type is an echo request or reply, in either family.
#[must_use]
pub const fn is_echo(proto: u8, icmp_type: u8) -> bool {
    match proto {
        proto::ICMP => icmp_type == 0 || icmp_type == 8,
        proto::ICMPV6 => icmp_type == 128 || icmp_type == 129,
        _ => false,
    }
}

/// The QNAME and QTYPE of the first question in a DNS message.
///
/// Returns `None` for anything that is not a well-formed query section, which
/// includes a DNS-over-TLS record and a QUIC packet on 443 — both of which the
/// observer counts as encrypted rather than as a plaintext DNS leak.
#[must_use]
pub fn dns_question(payload: &[u8]) -> Option<(String, u16)> {
    if payload.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut off = 12;
    let mut name = String::new();
    loop {
        let len = *payload.get(off)? as usize;
        off += 1;
        if len == 0 {
            break;
        }
        // A compression pointer in a question section is malformed; refusing it
        // keeps this parser from following an offset a peer chose.
        if len & 0xc0 != 0 {
            return None;
        }
        let label = payload.get(off..off + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label));
        off += len;
        if name.len() > 255 {
            return None;
        }
    }
    let qtype = payload.get(off..off + 2)?;
    Some((name, u16::from_be_bytes([qtype[0], qtype[1]])))
}
