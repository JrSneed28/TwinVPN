//! The message a router sends when a packet will not fit, and the black hole
//! that swallows it.
//!
//! **Authority:** `docs/testing-strategy.md` §3.4's PMTU black hole row, §3.4.2's
//! conformance row for it.
//!
//! > A 1500-byte DF probe is dropped and **no** ICMP fragmentation-needed is
//! > observed at the sender.
//!
//! # Why the middlebox has to be able to send one
//!
//! A black hole is defined by an **absence**, and an absence is only a condition
//! if the thing could have been present. A middlebox that forwards in userspace
//! generates no ICMP at all, so switching a "drop the ICMP" flag on it changes
//! nothing: the sender learns nothing either way, and a test asserting "no ICMP
//! arrived" would pass against a middlebox that had never been capable of
//! sending one.
//!
//! So this module is the control. With the black hole off, an oversize packet is
//! dropped **and reported** — an ordinary MTU mismatch, which Path MTU discovery
//! resolves. With it on, the same packet is dropped and nothing is said. The two
//! are then distinguishable, which is the whole point.

use std::net::IpAddr;

use crate::ip::{proto, Parsed, ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETH_HDR};
use crate::rewrite::internet_checksum;

/// How much of the offending packet the report quotes back.
///
/// RFC 1191 wants the IP header plus 8 octets; RFC 4443 wants as much as fits in
/// 1280. This quotes 28 octets, which covers an IPv4 header and the first 8 of
/// its payload — enough for the sender to match the report to the socket that
/// caused it, which is the only thing the quote is for.
const QUOTE: usize = 28;

/// Builds the ICMP message reporting that a packet was too big.
///
/// The Ethernet header is filled for the return path: back to whoever sent the
/// packet, from the middlebox's own inside address.
///
/// Returns `None` for a packet this module does not report on — anything that is
/// not IPv4 or IPv6, and anything too short to quote.
#[must_use]
pub fn too_big(frame: &[u8], p: &Parsed, mtu: u32, from_mac: [u8; 6]) -> Option<Vec<u8>> {
    let quote_from = p.l3_off;
    let quote = frame.get(quote_from..)?;
    let quote = &quote[..QUOTE.min(quote.len())];

    match (p.src, p.dst) {
        (IpAddr::V4(src), IpAddr::V4(_)) => {
            // ICMPv4 type 3 code 4: "fragmentation needed and DF set", with the
            // next-hop MTU in the last two octets of the unused word (RFC 1191).
            let mut icmp = vec![3u8, 4, 0, 0, 0, 0];
            icmp.extend_from_slice(&(mtu as u16).to_be_bytes());
            icmp.extend_from_slice(quote);
            let sum = internet_checksum(&[&icmp], 0);
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());

            let total = 20 + icmp.len();
            let mut out = vec![0u8; ETH_HDR + total];
            out[0..6].copy_from_slice(&p.eth_src);
            out[6..12].copy_from_slice(&from_mac);
            out[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
            let ip = ETH_HDR;
            out[ip] = 0x45;
            out[ip + 2..ip + 4].copy_from_slice(&(total as u16).to_be_bytes());
            out[ip + 8] = 64;
            out[ip + 9] = proto::ICMP;
            // Sourced from the destination the sender was trying to reach: a
            // router quotes its own address, and this middlebox does not have
            // one on the path, so the destination is the honest choice — the
            // sender matches the report by the quoted packet, not the source.
            out[ip + 12..ip + 16].copy_from_slice(&match p.dst {
                IpAddr::V4(d) => d.octets(),
                IpAddr::V6(_) => return None,
            });
            out[ip + 16..ip + 20].copy_from_slice(&src.octets());
            let header_sum = internet_checksum(&[&out[ip..ip + 20]], 0);
            out[ip + 10..ip + 12].copy_from_slice(&header_sum.to_be_bytes());
            out[ip + 20..].copy_from_slice(&icmp);
            Some(out)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            // ICMPv6 type 2: "packet too big", with the MTU in the next word.
            let mut icmp = vec![2u8, 0, 0, 0];
            icmp.extend_from_slice(&mtu.to_be_bytes());
            icmp.extend_from_slice(quote);
            let len = icmp.len();
            let sum = internet_checksum(
                &[&dst.octets(), &src.octets(), &icmp],
                u32::from(proto::ICMPV6) + len as u32,
            );
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());

            let mut out = vec![0u8; ETH_HDR + 40 + len];
            out[0..6].copy_from_slice(&p.eth_src);
            out[6..12].copy_from_slice(&from_mac);
            out[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
            let ip = ETH_HDR;
            out[ip] = 0x60;
            out[ip + 4..ip + 6].copy_from_slice(&(len as u16).to_be_bytes());
            out[ip + 6] = proto::ICMPV6;
            out[ip + 7] = 64;
            out[ip + 8..ip + 24].copy_from_slice(&dst.octets());
            out[ip + 24..ip + 40].copy_from_slice(&src.octets());
            out[ip + 40..].copy_from_slice(&icmp);
            Some(out)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip;

    /// A 1500-byte IPv4 UDP packet, which is what a DF probe looks like.
    fn oversize() -> Vec<u8> {
        let payload = 1500 - 20 - 8;
        let mut f = vec![0u8; ETH_HDR + 20 + 8 + payload];
        f[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        f[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
        f[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let ip = ETH_HDR;
        f[ip] = 0x45;
        f[ip + 2..ip + 4].copy_from_slice(&1500u16.to_be_bytes());
        f[ip + 6] = 0x40; // DF
        f[ip + 8] = 64;
        f[ip + 9] = proto::UDP;
        f[ip + 12..ip + 16].copy_from_slice(&[10, 0, 1, 2]);
        f[ip + 16..ip + 20].copy_from_slice(&[203, 0, 113, 10]);
        f
    }

    #[test]
    fn the_report_is_addressed_back_to_the_sender_and_names_the_mtu() {
        let frame = oversize();
        let p = ip::parse(&frame).expect("the fixture parses");
        let report = too_big(&frame, &p, 1280, [0x02, 0, 0, 0, 0, 9]).expect("reportable");
        let q = ip::parse(&report).expect("the report parses");
        assert_eq!(q.dst.to_string(), "10.0.1.2", "back to the sender");
        assert_eq!(q.proto, proto::ICMP);
        let body = &report[q.l4_off..];
        assert_eq!((body[0], body[1]), (3, 4), "fragmentation needed, DF set");
        assert_eq!(
            u16::from_be_bytes([body[6], body[7]]),
            1280,
            "RFC 1191 puts the next-hop MTU here, and a sender that read a zero would \
             fall back to 576 rather than to the real path MTU"
        );
    }

    #[test]
    fn its_checksums_verify() {
        let frame = oversize();
        let p = ip::parse(&frame).expect("parses");
        let report = too_big(&frame, &p, 1280, [0x02, 0, 0, 0, 0, 9]).expect("reportable");
        let q = ip::parse(&report).expect("parses");
        assert_eq!(
            internet_checksum(&[&report[q.l3_off..q.l3_off + 20]], 0),
            0,
            "the IPv4 header checksum does not verify"
        );
        assert_eq!(
            internet_checksum(&[&report[q.l4_off..]], 0),
            0,
            "the ICMP checksum does not verify, so every sender drops the report"
        );
    }

    #[test]
    fn the_report_quotes_enough_of_the_packet_for_the_sender_to_match_it() {
        let frame = oversize();
        let p = ip::parse(&frame).expect("parses");
        let report = too_big(&frame, &p, 1280, [0x02, 0, 0, 0, 0, 9]).expect("reportable");
        let q = ip::parse(&report).expect("parses");
        let quoted = &report[q.l4_off + 8..];
        assert_eq!(
            quoted.len(),
            QUOTE,
            "RFC 1191 wants the IP header plus 8 octets; a shorter quote leaves the sender \
             unable to attribute the report to a socket"
        );
        assert_eq!(
            &quoted[..20],
            &frame[p.l3_off..p.l3_off + 20],
            "the quote is not the offending packet's own header"
        );
    }
}
