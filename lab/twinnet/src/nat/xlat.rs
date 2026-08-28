//! IPv4/IPv6 translation: RFC 6052 addressing and RFC 7915 header translation.
//!
//! **Authority:** `docs/testing-strategy.md` §3.3's `N-NAT64` row; ADR-0010;
//! `docs/networking.md` §3.8.
//!
//! > | `N-NAT64` | v6-only access + NAT64 | n/a | 464XLAT / mobile | `jool`-class
//! > stateful NAT64 in the transit namespace, `pref64` advertised **both** ways:
//! > RFC 8781 PREF64 in RAs and RFC 7050 `ipv4only.arpa`, independently
//! > switchable so the "PREF64 absent, must fall back to RFC 7050" case is a
//! > distinct scenario. |
//!
//! `jool` is not installed on every host this laboratory has to run on, and the
//! consequence was that `N-NAT64` reported `UNAVAILABLE` for ever — which is the
//! honest answer to "can this host run jool" and a useless one to "does TwinVPN
//! work on a mobile network". §3.1 constrains the observable semantics, so this
//! module is a second realization of the same ones.
//!
//! # What is translated, and what is not
//!
//! | Translated | Not translated |
//! |---|---|
//! | UDP, TCP, and ICMP/ICMPv6 **echo** | every other ICMP type, including the error messages that carry an embedded packet (RFC 7915 §5.2) |
//! | a `/96` translation prefix (RFC 6052 §2.2's last row, and the well-known `64:ff9b::/96`) | the `/32`…`/64` forms, whose u-octet handling is a different function |
//! | the fixed IPv6 header, plus a hop-by-hop / routing / destination-options chain that is skipped | fragment headers — a fragmented packet is refused rather than mistranslated |
//!
//! Each of those is a **refusal**, never a silent pass-through. A NAT64 that
//! forwarded what it could not translate would put an untranslated address on
//! the far side of itself, which is the one thing this module exists to prevent.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ip::{self, proto, Parsed, ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETH_HDR};
use crate::rewrite::{internet_checksum, l4_len};

/// An RFC 6052 translation prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Pref64 {
    /// The prefix.
    pub prefix: Ipv6Addr,
    /// Its length. Only `96` is supported; see the module note.
    pub len: u8,
}

impl Default for Pref64 {
    /// RFC 6052 §2.1's well-known prefix, `64:ff9b::/96`.
    fn default() -> Self {
        Pref64 {
            prefix: Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0),
            len: 96,
        }
    }
}

impl Pref64 {
    /// Embeds an IPv4 address in the prefix.
    #[must_use]
    pub fn embed(self, v4: Ipv4Addr) -> Ipv6Addr {
        let mut octets = self.prefix.octets();
        octets[12..16].copy_from_slice(&v4.octets());
        Ipv6Addr::from(octets)
    }

    /// Whether an address falls inside the prefix.
    #[must_use]
    pub fn contains(self, v6: Ipv6Addr) -> bool {
        v6.octets()[..12] == self.prefix.octets()[..12]
    }

    /// Recovers the embedded IPv4 address, or `None` if the address is not in
    /// the prefix.
    #[must_use]
    pub fn extract(self, v6: Ipv6Addr) -> Option<Ipv4Addr> {
        if !self.contains(v6) {
            return None;
        }
        let o = v6.octets();
        Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]))
    }
}

/// Why a packet could not be translated.
///
/// Every variant is a **drop**. A NAT64 that passed through what it could not
/// translate would emit an IPv6 address onto an IPv4 network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A fragment. RFC 7915 allows translating these; this module does not, and
    /// refusing is the safe half of that choice.
    Fragmented,
    /// An upper-layer protocol this module does not translate.
    Protocol(u8),
    /// An ICMP type that is not an echo request or reply.
    IcmpType(u8),
    /// The frame was shorter than its own headers claimed.
    Truncated,
}

/// Translates an IPv6 packet into an IPv4 one.
///
/// The caller supplies the translated addresses and, for a stateful translator,
/// the allocated source port. The Ethernet header is left zeroed; the caller
/// fills it, because only the caller knows the next hop.
///
/// # Errors
///
/// A [`Refusal`] naming why. Never a partially translated packet.
pub fn v6_to_v4(
    frame: &[u8],
    p: &Parsed,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: Option<u16>,
) -> Result<Vec<u8>, Refusal> {
    if p.fragmented {
        return Err(Refusal::Fragmented);
    }
    let v4_proto = match p.proto {
        proto::UDP => proto::UDP,
        proto::TCP => proto::TCP,
        proto::ICMPV6 => proto::ICMP,
        other => return Err(Refusal::Protocol(other)),
    };
    let len = l4_len(p);
    let body = frame
        .get(p.l4_off..p.l4_off + len)
        .ok_or(Refusal::Truncated)?;

    let mut out = vec![0u8; ETH_HDR + 20 + len];
    out[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    let ip = ETH_HDR;
    let hop_limit = frame.get(p.l3_off + 7).copied().unwrap_or(0);
    if hop_limit <= 1 {
        return Err(Refusal::Truncated);
    }
    out[ip] = 0x45;
    // RFC 7915 §5.1: the IPv4 TOS comes from the IPv6 traffic class.
    out[ip + 1] = ((frame[p.l3_off] << 4) & 0xf0) | (frame[p.l3_off + 1] >> 4);
    out[ip + 2..ip + 4].copy_from_slice(&((20 + len) as u16).to_be_bytes());
    // Identification zero and DF clear: this translator does not fragment, and
    // an identification a receiver could reassemble against would be a promise
    // it cannot keep.
    out[ip + 8] = hop_limit - 1;
    out[ip + 9] = v4_proto;
    out[ip + 12..ip + 16].copy_from_slice(&src.octets());
    out[ip + 16..ip + 20].copy_from_slice(&dst.octets());
    let header_sum = internet_checksum(&[&out[ip..ip + 20]], 0);
    out[ip + 10..ip + 12].copy_from_slice(&header_sum.to_be_bytes());

    let l4 = ip + 20;
    out[l4..l4 + len].copy_from_slice(body);
    if let Some(port) = sport {
        write_source(&mut out[l4..l4 + len], v4_proto, port);
    }
    // ICMPv6 echo becomes ICMP echo, which is a different type number as well
    // as a different checksum: 128 -> 8 and 129 -> 0.
    if v4_proto == proto::ICMP {
        out[l4] = match out[l4] {
            128 => 8,
            129 => 0,
            other => return Err(Refusal::IcmpType(other)),
        };
    }
    write_checksum_v4(&mut out, l4, len, v4_proto, src, dst);
    Ok(out)
}

/// Translates an IPv4 packet into an IPv6 one.
///
/// # Errors
///
/// A [`Refusal`] naming why.
pub fn v4_to_v6(
    frame: &[u8],
    p: &Parsed,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    dport: Option<u16>,
) -> Result<Vec<u8>, Refusal> {
    if p.fragmented {
        return Err(Refusal::Fragmented);
    }
    let v6_proto = match p.proto {
        proto::UDP => proto::UDP,
        proto::TCP => proto::TCP,
        proto::ICMP => proto::ICMPV6,
        other => return Err(Refusal::Protocol(other)),
    };
    let len = l4_len(p);
    let body = frame
        .get(p.l4_off..p.l4_off + len)
        .ok_or(Refusal::Truncated)?;

    let ttl = frame.get(p.l3_off + 8).copied().unwrap_or(0);
    if ttl <= 1 {
        return Err(Refusal::Truncated);
    }
    let mut out = vec![0u8; ETH_HDR + 40 + len];
    out[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
    let ip = ETH_HDR;
    let tos = frame[p.l3_off + 1];
    out[ip] = 0x60 | (tos >> 4);
    out[ip + 1] = (tos << 4) & 0xf0;
    out[ip + 4..ip + 6].copy_from_slice(&(len as u16).to_be_bytes());
    out[ip + 6] = v6_proto;
    out[ip + 7] = ttl - 1;
    out[ip + 8..ip + 24].copy_from_slice(&src.octets());
    out[ip + 24..ip + 40].copy_from_slice(&dst.octets());

    let l4 = ip + 40;
    out[l4..l4 + len].copy_from_slice(body);
    if let Some(port) = dport {
        write_destination(&mut out[l4..l4 + len], v6_proto, port);
    }
    if v6_proto == proto::ICMPV6 {
        out[l4] = match out[l4] {
            8 => 128,
            0 => 129,
            other => return Err(Refusal::IcmpType(other)),
        };
    }
    write_checksum_v6(&mut out, l4, len, v6_proto, src, dst);
    Ok(out)
}

fn write_source(l4: &mut [u8], protocol: u8, port: u16) {
    let bytes = port.to_be_bytes();
    match protocol {
        proto::UDP | proto::TCP if l4.len() >= 2 => l4[0..2].copy_from_slice(&bytes),
        proto::ICMP | proto::ICMPV6 if l4.len() >= 6 => l4[4..6].copy_from_slice(&bytes),
        _ => {}
    }
}

fn write_destination(l4: &mut [u8], protocol: u8, port: u16) {
    let bytes = port.to_be_bytes();
    match protocol {
        proto::UDP | proto::TCP if l4.len() >= 4 => l4[2..4].copy_from_slice(&bytes),
        proto::ICMP | proto::ICMPV6 if l4.len() >= 6 => l4[4..6].copy_from_slice(&bytes),
        _ => {}
    }
}

fn write_checksum_v4(
    out: &mut [u8],
    l4: usize,
    len: usize,
    protocol: u8,
    src: Ipv4Addr,
    dst: Ipv4Addr,
) {
    let Some(offset) = checksum_offset(protocol) else {
        return;
    };
    out[l4 + offset] = 0;
    out[l4 + offset + 1] = 0;
    let sum = if protocol == proto::ICMP {
        // An IPv4 ICMP checksum covers the message alone: no pseudo-header.
        internet_checksum(&[&out[l4..l4 + len]], 0)
    } else {
        internet_checksum(
            &[&src.octets(), &dst.octets(), &out[l4..l4 + len]],
            u32::from(protocol) + len as u32,
        )
    };
    let sum = if sum == 0 && protocol == proto::UDP {
        0xffff
    } else {
        sum
    };
    out[l4 + offset..l4 + offset + 2].copy_from_slice(&sum.to_be_bytes());
}

fn write_checksum_v6(
    out: &mut [u8],
    l4: usize,
    len: usize,
    protocol: u8,
    src: Ipv6Addr,
    dst: Ipv6Addr,
) {
    let Some(offset) = checksum_offset(protocol) else {
        return;
    };
    out[l4 + offset] = 0;
    out[l4 + offset + 1] = 0;
    // Every IPv6 transport checksum covers the pseudo-header, ICMPv6 included —
    // which is precisely why an ICMP echo cannot simply be copied across.
    let sum = internet_checksum(
        &[&src.octets(), &dst.octets(), &out[l4..l4 + len]],
        u32::from(protocol) + len as u32,
    );
    let sum = if sum == 0 && protocol == proto::UDP {
        0xffff
    } else {
        sum
    };
    out[l4 + offset..l4 + offset + 2].copy_from_slice(&sum.to_be_bytes());
}

const fn checksum_offset(protocol: u8) -> Option<usize> {
    match protocol {
        proto::UDP => Some(6),
        proto::TCP => Some(16),
        proto::ICMP | proto::ICMPV6 => Some(2),
        _ => None,
    }
}

/// The five-tuple a translated packet will have, for a mapping-table lookup,
/// without building the packet.
#[must_use]
pub fn translated_destination(pref64: Pref64, p: &Parsed) -> Option<Ipv4Addr> {
    match p.dst {
        IpAddr::V6(v6) => pref64.extract(v6),
        IpAddr::V4(_) => None,
    }
}

/// Parses a frame this module produced, so a caller can check its own work.
#[must_use]
pub fn reparse(frame: &[u8]) -> Option<Parsed> {
    ip::parse(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pref() -> Pref64 {
        Pref64::default()
    }

    #[test]
    fn the_well_known_prefix_embeds_and_recovers_an_address() {
        let v4 = Ipv4Addr::new(203, 0, 113, 10);
        let v6 = pref().embed(v4);
        assert_eq!(v6.to_string(), "64:ff9b::cb00:710a");
        assert_eq!(pref().extract(v6), Some(v4));
    }

    #[test]
    fn an_address_outside_the_prefix_yields_nothing_rather_than_a_wrong_answer() {
        let outside: Ipv6Addr = "2001:db8::1".parse().expect("a literal");
        assert!(!pref().contains(outside));
        assert_eq!(pref().extract(outside), None);
    }

    /// Builds a minimal IPv6 UDP frame, for the round-trip below.
    fn v6_udp(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let len = 8 + payload.len();
        let mut f = vec![0u8; ETH_HDR + 40 + len];
        f[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        let ip = ETH_HDR;
        f[ip] = 0x60;
        f[ip + 4..ip + 6].copy_from_slice(&(len as u16).to_be_bytes());
        f[ip + 6] = proto::UDP;
        f[ip + 7] = 64;
        f[ip + 8..ip + 24].copy_from_slice(&src.octets());
        f[ip + 24..ip + 40].copy_from_slice(&dst.octets());
        let l4 = ip + 40;
        f[l4..l4 + 2].copy_from_slice(&sport.to_be_bytes());
        f[l4 + 2..l4 + 4].copy_from_slice(&dport.to_be_bytes());
        f[l4 + 4..l4 + 6].copy_from_slice(&(len as u16).to_be_bytes());
        f[l4 + 8..l4 + 8 + payload.len()].copy_from_slice(payload);
        f
    }

    #[test]
    fn a_v6_datagram_becomes_a_v4_one_this_crates_own_parser_reads_back() {
        let client: Ipv6Addr = "2001:db8:64::2".parse().expect("a literal");
        let server = Ipv4Addr::new(203, 0, 113, 10);
        let frame = v6_udp(client, pref().embed(server), 5000, 9, b"hello");
        let p = ip::parse(&frame).expect("the fixture parses");
        assert_eq!(super::translated_destination(pref(), &p), Some(server));

        let out = v6_to_v4(
            &frame,
            &p,
            Ipv4Addr::new(198, 51, 100, 7),
            server,
            Some(40_001),
        )
        .expect("a UDP datagram is translatable");
        let q = ip::parse(&out).expect("the translated frame parses");
        assert_eq!(q.src, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
        assert_eq!(q.dst, IpAddr::V4(server));
        assert_eq!(q.src_port, Some(40_001));
        assert_eq!(q.dst_port, Some(9));
        assert_eq!(q.proto, proto::UDP);
        assert_eq!(&out[q.payload_off..], b"hello");
    }

    #[test]
    fn the_translated_headers_carry_a_checksum_that_verifies() {
        let client: Ipv6Addr = "2001:db8:64::2".parse().expect("a literal");
        let server = Ipv4Addr::new(203, 0, 113, 10);
        let frame = v6_udp(client, pref().embed(server), 5000, 9, b"hello");
        let p = ip::parse(&frame).expect("the fixture parses");
        let out = v6_to_v4(
            &frame,
            &p,
            Ipv4Addr::new(198, 51, 100, 7),
            server,
            Some(40_001),
        )
        .expect("translatable");
        let q = ip::parse(&out).expect("parses");
        // Summing a correct header including its own checksum yields zero.
        assert_eq!(
            internet_checksum(&[&out[q.l3_off..q.l3_off + 20]], 0),
            0,
            "the translated IPv4 header checksum does not verify"
        );
        let len = l4_len(&q);
        assert_eq!(
            internet_checksum(
                &[
                    &Ipv4Addr::new(198, 51, 100, 7).octets(),
                    &server.octets(),
                    &out[q.l4_off..q.l4_off + len],
                ],
                u32::from(proto::UDP) + len as u32,
            ),
            0,
            "the translated UDP checksum does not verify"
        );
    }

    #[test]
    fn a_fragment_and_an_untranslatable_protocol_are_refused_rather_than_forwarded() {
        let client: Ipv6Addr = "2001:db8:64::2".parse().expect("a literal");
        let server = Ipv4Addr::new(203, 0, 113, 10);
        let mut frame = v6_udp(client, pref().embed(server), 5000, 9, b"x");
        let mut p = ip::parse(&frame).expect("parses");
        p.fragmented = true;
        assert_eq!(
            v6_to_v4(&frame, &p, Ipv4Addr::new(1, 1, 1, 1), server, None),
            Err(Refusal::Fragmented)
        );

        frame[ETH_HDR + 6] = 132; // SCTP
        let p = ip::parse(&frame).expect("parses");
        assert_eq!(
            v6_to_v4(&frame, &p, Ipv4Addr::new(1, 1, 1, 1), server, None),
            Err(Refusal::Protocol(132))
        );
    }
}
