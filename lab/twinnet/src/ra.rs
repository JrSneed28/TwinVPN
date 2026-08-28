//! Router Advertisements, and RFC 8781's PREF64 option.
//!
//! **Authority:** `docs/testing-strategy.md` §3.3's `N-NAT64` row;
//! `docs/networking.md` §3.8.
//!
//! > `pref64` advertised **both** ways: RFC 8781 PREF64 in RAs (the path
//! > `docs/networking.md` §3.8 **prefers**) and RFC 7050 `ipv4only.arpa`,
//! > independently switchable so the "PREF64 absent, must fall back to RFC 7050"
//! > case is a distinct scenario.
//!
//! This module is the half that was missing. Until it existed, the laboratory
//! realized the two DNS paths and reported the RA path as not covered — which
//! was honest and also meant the path §3.8 *prefers* was the one never
//! exercised, and "PREF64 absent" could only ever mean "the DNS64 stopped
//! synthesizing".
//!
//! # What is real here
//!
//! A real ICMPv6 Router Advertisement: type 134, hop limit 255, sent to
//! `ff02::1` from a link-local source derived from the interface's own MAC the
//! way the kernel derives it, carrying RFC 8781's option 38 with the prefix in
//! its top 96 bits. A client reads it off the wire with a raw socket and takes
//! the prefix out of the option. Neither end shares a line of code with the DNS
//! paths, which is what makes "independently switchable" mean something.
//!
//! # What is not
//!
//! This is not `radvd`. It advertises one PREF64 option and nothing else: no
//! prefix information, no RDNSS, no route information, and it never answers a
//! Router Solicitation — it advertises unsolicited, on an interval. A scenario
//! that needed SLAAC from these RAs would not get it, and no scenario asks.

use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use crate::afpacket::PacketSocket;
use crate::error::{NetError, Result};
use crate::ip::{self, proto, ETHERTYPE_IPV6, ETH_HDR};
use crate::nat::xlat::Pref64;
use crate::rewrite::internet_checksum;

/// ICMPv6 Router Advertisement.
pub const ROUTER_ADVERTISEMENT: u8 = 134;
/// RFC 8781 §4: the PREF64 option type.
pub const OPTION_PREF64: u8 = 38;
/// RFC 8781 §4: `/96` is Prefix Length Code 0.
const PLC_96: u16 = 0;
/// `ff02::1`, all-nodes.
const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
/// The Ethernet address `ff02::1` maps to.
const ALL_NODES_MAC: [u8; 6] = [0x33, 0x33, 0x00, 0x00, 0x00, 0x01];

/// The link-local address a MAC produces, by RFC 4291's modified EUI-64.
///
/// Derived rather than configured so that a scenario does not have to state an
/// address the kernel is about to pick anyway — and so that a mismatch between
/// what this module sends from and what the interface actually is cannot happen.
#[must_use]
pub fn link_local_of(mac: [u8; 6]) -> Ipv6Addr {
    let mut o = [0u8; 16];
    o[0] = 0xfe;
    o[1] = 0x80;
    o[8] = mac[0] ^ 0x02;
    o[9] = mac[1];
    o[10] = mac[2];
    o[11] = 0xff;
    o[12] = 0xfe;
    o[13] = mac[3];
    o[14] = mac[4];
    o[15] = mac[5];
    Ipv6Addr::from(o)
}

/// Reads an interface's MAC out of `sysfs`.
///
/// # Errors
///
/// [`NetError::Os`] if the interface has no `address` file, which means it does
/// not exist in this namespace.
pub fn mac_of(iface: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{iface}/address");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| NetError::os(format!("reading the MAC of `{iface}` from {path}"), e))?;
    let mut mac = [0u8; 6];
    for (slot, part) in mac.iter_mut().zip(text.trim().split(':')) {
        *slot = u8::from_str_radix(part, 16).unwrap_or(0);
    }
    Ok(mac)
}

/// Builds one Router Advertisement carrying a PREF64 option.
///
/// `lifetime_s` is RFC 8781's scaled lifetime: it is carried in the top 13 bits
/// of a 16-bit field in units of 8 seconds, so the value is rounded down to a
/// multiple of 8 and capped at 65 528.
#[must_use]
pub fn advertisement(src_mac: [u8; 6], pref64: Pref64, lifetime_s: u16) -> Vec<u8> {
    let src = link_local_of(src_mac);
    // RA body: cur hop limit, flags, router lifetime, reachable time, retrans
    // timer — then the options.
    let mut icmp = vec![
        ROUTER_ADVERTISEMENT,
        0, // code
        0,
        0,  // checksum, filled below
        64, // cur hop limit
        0,  // flags: no managed, no other
        0,
        0, // router lifetime: this is not a default router, only a PREF64 source
        0,
        0,
        0,
        0, // reachable time
        0,
        0,
        0,
        0, // retrans timer
    ];
    // RFC 8781 §4. Length 2 means 16 octets, which is the whole option.
    let scaled = (lifetime_s / 8).min(0x1fff);
    let lifetime_and_plc = (scaled << 3) | PLC_96;
    icmp.push(OPTION_PREF64);
    icmp.push(2);
    icmp.extend_from_slice(&lifetime_and_plc.to_be_bytes());
    icmp.extend_from_slice(&pref64.prefix.octets()[..12]);

    let len = icmp.len();
    let sum = internet_checksum(
        &[&src.octets(), &ALL_NODES.octets(), &icmp],
        u32::from(proto::ICMPV6) + len as u32,
    );
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());

    let mut frame = Vec::with_capacity(ETH_HDR + 40 + len);
    frame.extend_from_slice(&ALL_NODES_MAC);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
    frame.push(0x60);
    frame.extend_from_slice(&[0, 0, 0]);
    frame.extend_from_slice(&(len as u16).to_be_bytes());
    frame.push(proto::ICMPV6);
    // RFC 4861 §6.1.2: a receiver MUST discard an RA whose hop limit is not 255.
    // Getting this wrong would make every advertisement silently ignored, and
    // the symptom would be indistinguishable from not advertising at all.
    frame.push(255);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&ALL_NODES.octets());
    frame.extend_from_slice(&icmp);
    frame
}

/// Advertises `pref64` on `iface` every `interval`, for `duration`.
///
/// # Errors
///
/// [`NetError::Unavailable`] if the raw socket is refused;
/// [`NetError::Os`] if the interface has no MAC.
pub fn advertise(
    iface: &str,
    pref64: Pref64,
    lifetime_s: u16,
    interval: Duration,
    duration: Duration,
) -> Result<()> {
    let sock = PacketSocket::open(iface)?;
    let mac = mac_of(iface)?;
    let frame = advertisement(mac, pref64, lifetime_s);
    let started = Instant::now();
    while started.elapsed() < duration {
        let _ = sock.send(&frame);
        std::thread::sleep(interval);
    }
    Ok(())
}

/// The PREF64 option inside a Router Advertisement, if there is one.
///
/// Returns `None` for anything that is not an RA, for an RA with no PREF64
/// option, and for an option whose length field does not match RFC 8781's — a
/// parser that read a prefix out of a 3-octet option would be one a malformed
/// advertisement could walk off the end of.
#[must_use]
pub fn pref64_in(frame: &[u8]) -> Option<Pref64> {
    let p = ip::parse(frame)?;
    if p.proto != proto::ICMPV6 {
        return None;
    }
    let icmp = frame.get(p.l4_off..)?;
    if *icmp.first()? != ROUTER_ADVERTISEMENT {
        return None;
    }
    // RFC 4861 §6.1.2 again, on the receive side.
    if frame.get(p.l3_off + 7).copied()? != 255 {
        return None;
    }
    let mut off = 16; // past the fixed RA body
    while off + 2 <= icmp.len() {
        let kind = icmp[off];
        let units = usize::from(icmp[off + 1]);
        if units == 0 {
            // RFC 4861: a zero length is malformed and the packet is discarded,
            // rather than looped on.
            return None;
        }
        let end = off + units * 8;
        if end > icmp.len() {
            return None;
        }
        if kind == OPTION_PREF64 && units == 2 {
            let plc = u16::from_be_bytes([icmp[off + 2], icmp[off + 3]]) & 0x7;
            if plc != PLC_96 {
                // A prefix length this laboratory does not implement. Refused
                // rather than read as a /96, which would silently translate
                // through the wrong prefix.
                return None;
            }
            let mut octets = [0u8; 16];
            octets[..12].copy_from_slice(&icmp[off + 4..off + 16]);
            return Some(Pref64 {
                prefix: Ipv6Addr::from(octets),
                len: 96,
            });
        }
        off = end;
    }
    None
}

/// Listens on `iface` for a Router Advertisement carrying a PREF64 option.
///
/// # Errors
///
/// [`NetError::Unavailable`] if the raw socket is refused.
pub fn listen(iface: &str, wait: Duration) -> Result<Option<Pref64>> {
    let sock = PacketSocket::open(iface)?;
    sock.set_promiscuous()?;
    sock.set_read_timeout(Duration::from_millis(100))?;
    let deadline = Instant::now() + wait;
    let mut buf = vec![0u8; 2048];
    while Instant::now() < deadline {
        let Some(n) = sock.recv(&mut buf)? else {
            continue;
        };
        if let Some(pref64) = pref64_in(&buf[..n]) {
            return Ok(Some(pref64));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac() -> [u8; 6] {
        [0x02, 0x00, 0x38, 0x73, 0xb9, 0x37]
    }

    #[test]
    fn the_link_local_address_is_the_one_the_kernel_would_derive() {
        // RFC 4291: the universal/local bit is flipped and `fffe` is inserted,
        // so `02:00:38:73:b9:37` becomes `00:00:38 ff:fe 73:b9:37`. This is the
        // same derivation the kernel performed for the interface whose stray
        // router solicitation the NAT64's wire oracle caught — `02:00:8c:28:9c:d9`
        // appeared on the wire as `fe80::8cff:fe28:9cd9`.
        assert_eq!(link_local_of(mac()).to_string(), "fe80::38ff:fe73:b937");
        assert_eq!(
            link_local_of([0x02, 0x00, 0x8c, 0x28, 0x9c, 0xd9]).to_string(),
            "fe80::8cff:fe28:9cd9"
        );
    }

    #[test]
    fn an_advertisement_this_module_builds_is_one_it_reads_back() {
        let pref64 = Pref64::default();
        let frame = advertisement(mac(), pref64, 600);
        assert_eq!(pref64_in(&frame), Some(pref64));
    }

    #[test]
    fn the_advertisement_carries_the_hop_limit_a_receiver_requires() {
        let frame = advertisement(mac(), Pref64::default(), 600);
        let p = ip::parse(&frame).expect("the advertisement parses");
        assert_eq!(
            frame[p.l3_off + 7],
            255,
            "RFC 4861 §6.1.2: a receiver MUST discard an RA whose hop limit is not 255, \
             so an advertisement sent with any other value is silently ignored and looks \
             exactly like not advertising at all"
        );
    }

    #[test]
    fn its_checksum_verifies() {
        let frame = advertisement(mac(), Pref64::default(), 600);
        let p = ip::parse(&frame).expect("parses");
        let len = frame.len() - p.l4_off;
        let (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) = (p.src, p.dst) else {
            panic!("a Router Advertisement is IPv6 by construction")
        };
        assert_eq!(
            internet_checksum(
                &[&src.octets(), &dst.octets(), &frame[p.l4_off..]],
                u32::from(proto::ICMPV6) + len as u32,
            ),
            0,
            "the ICMPv6 checksum does not verify, so every receiver drops it"
        );
    }

    #[test]
    fn a_frame_that_is_not_a_router_advertisement_yields_nothing() {
        let mut frame = advertisement(mac(), Pref64::default(), 600);
        let p = ip::parse(&frame).expect("parses");
        frame[p.l4_off] = 133; // a Router Solicitation
        assert_eq!(pref64_in(&frame), None);
    }

    #[test]
    fn a_zero_length_option_is_refused_rather_than_looped_on() {
        let mut frame = advertisement(mac(), Pref64::default(), 600);
        let p = ip::parse(&frame).expect("parses");
        // The option header starts 16 octets into the ICMPv6 message.
        frame[p.l4_off + 17] = 0;
        assert_eq!(
            pref64_in(&frame),
            None,
            "a zero-length option must terminate the walk; RFC 4861 discards the packet"
        );
    }

    #[test]
    fn a_prefix_length_this_module_does_not_implement_is_refused_not_guessed() {
        let mut frame = advertisement(mac(), Pref64::default(), 600);
        let p = ip::parse(&frame).expect("parses");
        // PLC 1 is /64, which this module does not implement.
        frame[p.l4_off + 19] = (frame[p.l4_off + 19] & !0x7) | 1;
        assert_eq!(
            pref64_in(&frame),
            None,
            "reading a /64 option as a /96 would translate through the wrong prefix"
        );
    }
}
