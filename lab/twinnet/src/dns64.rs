//! DNS64, RFC 7050 discovery, and the client that uses them.
//!
//! **Authority:** `docs/testing-strategy.md` §3.3's `N-NAT64` row and §3.4.2's
//! NAT64 conformance row; ADR-0011; `docs/networking.md` §3.8.
//!
//! > | NAT64 | A v4-literal destination is reachable from a v6-only client via
//! > the synthesized prefix, and `PREF64`-off forces the RFC 7050 path |
//!
//! # The two discovery paths, and the one that is honestly missing
//!
//! §3.3 wants `pref64` advertised **both** ways and independently switchable:
//!
//! | Path | Realized here |
//! |---|---|
//! | RFC 7050 — resolve `ipv4only.arpa` and read the prefix out of the synthesized AAAA | **yes**, and it is a distinct scenario with the synthesis switched off |
//! | DNS64 synthesis of a AAAA for an ordinary name | **yes** |
//! | RFC 8781 PREF64 in Router Advertisements | **no.** It needs an RA daemon in the transit namespace, and there is none. Reported as unavailable rather than approximated by the DNS path, because "the client found the prefix" and "the client found the prefix *the way §3.8 prefers*" are different claims |
//!
//! # This is a laboratory resolver, not a resolver
//!
//! It answers from a table, does not recurse, does not cache, ignores EDNS, and
//! serves one question per message. Its whole job is to make a v6-only client's
//! name lookup produce a synthesized address so that the NAT64 in the path has
//! something to translate.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::error::{NetError, Result};
use crate::nat::xlat::Pref64;

/// RFC 7050's well-known name.
pub const IPV4ONLY_ARPA: &str = "ipv4only.arpa";
/// The two addresses RFC 7050 fixes for it.
pub const IPV4ONLY_ADDRS: [Ipv4Addr; 2] =
    [Ipv4Addr::new(192, 0, 0, 170), Ipv4Addr::new(192, 0, 0, 171)];

/// DNS record types this module knows.
mod rtype {
    /// An IPv4 address.
    pub const A: u16 = 1;
    /// An IPv6 address.
    pub const AAAA: u16 = 28;
}

/// One question, and where it ends.
struct Question {
    name: String,
    qtype: u16,
    end: usize,
}

/// Parses the single question a laboratory message carries.
fn question(msg: &[u8]) -> Option<Question> {
    if msg.len() < 12 || u16::from_be_bytes([msg[4], msg[5]]) == 0 {
        return None;
    }
    let mut off = 12;
    let mut name = String::new();
    loop {
        let len = *msg.get(off)? as usize;
        off += 1;
        if len == 0 {
            break;
        }
        // A compression pointer in a question is malformed; refusing it keeps
        // this parser from following an offset a peer chose.
        if len & 0xc0 != 0 || name.len() > 255 {
            return None;
        }
        let label = msg.get(off..off + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label));
        off += len;
    }
    let qtype = u16::from_be_bytes([*msg.get(off)?, *msg.get(off + 1)?]);
    Some(Question {
        name,
        qtype,
        end: off + 4,
    })
}

/// What a laboratory resolver will answer.
#[derive(Debug, Clone)]
pub struct Zone {
    /// Name to IPv4 address.
    pub a: BTreeMap<String, Ipv4Addr>,
    /// The translation prefix used to synthesize AAAA records.
    pub pref64: Pref64,
    /// Whether a AAAA query for an ordinary name is synthesized.
    ///
    /// Off is the "PREF64 absent" half of §3.3's switchable pair: the client
    /// gets no AAAA for the destination and must discover the prefix itself.
    pub synthesize: bool,
    /// Whether `ipv4only.arpa` is answered at all — RFC 7050's discovery path,
    /// switchable independently of [`Zone::synthesize`].
    pub rfc7050: bool,
}

impl Zone {
    /// Builds the answer records for one question, or `None` for a name this
    /// zone does not serve.
    #[must_use]
    fn answers(&self, name: &str, qtype: u16) -> Vec<IpAddr> {
        let lower = name.to_ascii_lowercase();
        if lower == IPV4ONLY_ARPA {
            if !self.rfc7050 {
                return Vec::new();
            }
            return match qtype {
                rtype::A => IPV4ONLY_ADDRS.iter().copied().map(IpAddr::V4).collect(),
                // This is the RFC 7050 mechanism itself: the DNS64 synthesizes
                // AAAA records for `ipv4only.arpa`, and the client reads the
                // prefix out of the first 96 bits of what comes back.
                rtype::AAAA => IPV4ONLY_ADDRS
                    .iter()
                    .map(|v4| IpAddr::V6(self.pref64.embed(*v4)))
                    .collect(),
                _ => Vec::new(),
            };
        }
        let Some(v4) = self.a.get(&lower).copied() else {
            return Vec::new();
        };
        match qtype {
            rtype::A => vec![IpAddr::V4(v4)],
            rtype::AAAA if self.synthesize => vec![IpAddr::V6(self.pref64.embed(v4))],
            _ => Vec::new(),
        }
    }
}

/// Serves [`Zone`] on `bind` until `duration` elapses.
///
/// # Errors
///
/// [`NetError::Os`] if the socket cannot be bound.
pub fn serve(bind: SocketAddr, zone: &Zone, duration: Duration) -> Result<()> {
    let sock = UdpSocket::bind(bind)
        .map_err(|e| NetError::os(format!("binding the lab resolver to {bind}"), e))?;
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|e| NetError::os("setting the resolver read timeout", e))?;
    let started = Instant::now();
    let mut buf = [0u8; 1500];
    while started.elapsed() < duration {
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            continue;
        };
        let msg = &buf[..n];
        let Some(q) = question(msg) else {
            continue;
        };
        let answers = zone.answers(&q.name, q.qtype);
        let reply = respond(msg, &q, &answers);
        let _ = sock.send_to(&reply, from);
    }
    Ok(())
}

/// Builds a response carrying `answers`.
fn respond(request: &[u8], q: &Question, answers: &[IpAddr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(q.end + answers.len() * 32);
    out.extend_from_slice(&request[0..2]); // the transaction id, echoed
    out.extend_from_slice(&[0x81, 0x80]); // response, recursion desired + available
    out.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NSCOUNT, ARCOUNT
    out.extend_from_slice(&request[12..q.end]); // the question, verbatim
    for answer in answers {
        // A pointer to the question's name at offset 12.
        out.extend_from_slice(&[0xc0, 0x0c]);
        match answer {
            IpAddr::V4(v4) => {
                out.extend_from_slice(&rtype::A.to_be_bytes());
                out.extend_from_slice(&[0x00, 0x01]); // IN
                out.extend_from_slice(&60u32.to_be_bytes());
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.extend_from_slice(&rtype::AAAA.to_be_bytes());
                out.extend_from_slice(&[0x00, 0x01]);
                out.extend_from_slice(&60u32.to_be_bytes());
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&v6.octets());
            }
        }
    }
    out
}

/// Reads the addresses out of a response.
///
/// Skips each answer's NAME, which is either a compression pointer (two octets)
/// or a label sequence, and returns only records whose RDLENGTH matches their
/// type — a resolver that trusted a 3-byte A record would be one a malformed
/// answer could walk off the end of.
#[must_use]
pub fn parse_answers(msg: &[u8]) -> Vec<IpAddr> {
    let Some(q) = question(msg) else {
        return Vec::new();
    };
    let count = u16::from_be_bytes([msg[6], msg[7]]);
    let mut off = q.end;
    let mut out = Vec::new();
    for _ in 0..count {
        let Some(&first) = msg.get(off) else { break };
        off += if first & 0xc0 == 0xc0 {
            2
        } else {
            let mut n = off;
            loop {
                let Some(&len) = msg.get(n) else { return out };
                n += 1 + len as usize;
                if len == 0 {
                    break;
                }
            }
            n - off
        };
        let (Some(t), Some(rdlen)) = (
            msg.get(off..off + 2)
                .map(|b| u16::from_be_bytes([b[0], b[1]])),
            msg.get(off + 8..off + 10)
                .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]]))),
        ) else {
            break;
        };
        let rdata_at = off + 10;
        let Some(rdata) = msg.get(rdata_at..rdata_at + rdlen) else {
            break;
        };
        match (t, rdlen) {
            (rtype::A, 4) => out.push(IpAddr::V4(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            ))),
            (rtype::AAAA, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                out.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        off = rdata_at + rdlen;
    }
    out
}

/// What a v6-only client observed reaching a v4-only destination.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Nat64Report {
    /// The prefix the client ended up using, and how it learned it.
    pub pref64: Option<String>,
    /// How the prefix was discovered: `synthesized-aaaa` or `rfc7050`.
    pub discovery: String,
    /// The address the client actually sent to.
    pub target: Option<String>,
    /// Whether the v4-only destination answered.
    pub reachable: bool,
    /// Datagrams sent and received.
    pub sent: u32,
    /// Datagrams received.
    pub received: u32,
    /// Every step, in order, so a failure names where it stopped.
    pub evidence: Vec<String>,
}

/// How the client learns the translation prefix.
///
/// The three are **independently switchable**, which is what §3.3 asks for and
/// what makes "PREF64 absent, must fall back to RFC 7050" a distinct scenario
/// rather than a rewording of "the DNS64 stopped synthesizing".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discovery {
    /// The DNS64 synthesizes a AAAA for the destination itself.
    SynthesizedAaaa,
    /// RFC 7050: resolve `ipv4only.arpa` and read the prefix out of the answer.
    Rfc7050,
    /// RFC 8781: read the PREF64 option out of a Router Advertisement.
    ///
    /// The path `docs/networking.md` §3.8 **prefers**, and the only one of the
    /// three that touches no resolver at all — the client still needs the
    /// destination's A record, but the prefix comes off the wire.
    RouterAdvertisement {
        /// The interface to listen on.
        iface: &'static str,
    },
}

impl Discovery {
    /// The name a report carries.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Discovery::SynthesizedAaaa => "synthesized-aaaa",
            Discovery::Rfc7050 => "rfc7050",
            Discovery::RouterAdvertisement { .. } => "router-advertisement",
        }
    }
}

/// A v6-only client reaching a v4-only destination through a NAT64.
///
/// # Errors
///
/// [`NetError::Os`] if a socket cannot be bound. A destination that does not
/// answer is **not** an error: that is a scenario this laboratory deliberately
/// produces, and it reports `reachable: false`.
pub fn probe(
    resolver: SocketAddr,
    name: &str,
    port: u16,
    discovery: Discovery,
    wait: Duration,
) -> Result<Nat64Report> {
    let mut report = Nat64Report {
        pref64: None,
        discovery: discovery.name().to_owned(),
        target: None,
        reachable: false,
        sent: 0,
        received: 0,
        evidence: Vec::new(),
    };

    let target = if let Discovery::RouterAdvertisement { iface } = discovery {
        // RFC 8781. The prefix arrives on the wire in a Router Advertisement;
        // no resolver is involved in learning it, which is why this path still
        // works with both DNS mechanisms switched off.
        let Some(pref64) = crate::ra::listen(iface, wait * 4)? else {
            report.evidence.push(format!(
                "no Router Advertisement carrying a PREF64 option arrived on `{iface}` \
                 within {:?}",
                wait * 4
            ));
            return Ok(report);
        };
        report.pref64 = Some(format!("{}/96", pref64.prefix));
        report.evidence.push(format!(
            "RFC 8781: a Router Advertisement on `{iface}` carried PREF64 {}/96",
            pref64.prefix
        ));
        let v4 = query(resolver, name, rtype::A, wait, &mut report.evidence)?
            .into_iter()
            .find_map(|a| match a {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            });
        let Some(v4) = v4 else {
            report.evidence.push(format!(
                "`{name}` has no A record, so there is nothing to embed"
            ));
            return Ok(report);
        };
        report
            .evidence
            .push(format!("`{name}` A -> {v4}, embedded locally"));
        pref64.embed(v4)
    } else if discovery == Discovery::Rfc7050 {
        // The PREF64-absent path: no AAAA is synthesized for the destination,
        // so the client must discover the prefix from `ipv4only.arpa` and embed
        // the A record itself. This is the case §3.3 asks to be distinct.
        let discovered = query(
            resolver,
            IPV4ONLY_ARPA,
            rtype::AAAA,
            wait,
            &mut report.evidence,
        )?
        .into_iter()
        .find_map(|a| match a {
            IpAddr::V6(v6) => Some(v6),
            IpAddr::V4(_) => None,
        });
        let Some(synth) = discovered else {
            report
                .evidence
                .push("ipv4only.arpa returned no AAAA, so RFC 7050 discovery failed".to_owned());
            return Ok(report);
        };
        let mut octets = synth.octets();
        octets[12..16].fill(0);
        let pref64 = Pref64 {
            prefix: Ipv6Addr::from(octets),
            len: 96,
        };
        report.pref64 = Some(format!("{}/96", pref64.prefix));
        report.evidence.push(format!(
            "RFC 7050: ipv4only.arpa -> {synth}, prefix {}",
            pref64.prefix
        ));

        let v4 = query(resolver, name, rtype::A, wait, &mut report.evidence)?
            .into_iter()
            .find_map(|a| match a {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            });
        let Some(v4) = v4 else {
            report.evidence.push(format!(
                "`{name}` has no A record, so there is nothing to embed"
            ));
            return Ok(report);
        };
        report
            .evidence
            .push(format!("`{name}` A -> {v4}, embedded locally"));
        pref64.embed(v4)
    } else {
        let synthesized = query(resolver, name, rtype::AAAA, wait, &mut report.evidence)?
            .into_iter()
            .find_map(|a| match a {
                IpAddr::V6(v6) => Some(v6),
                IpAddr::V4(_) => None,
            });
        let Some(v6) = synthesized else {
            report
                .evidence
                .push(format!("`{name}` returned no synthesized AAAA"));
            return Ok(report);
        };
        let mut octets = v6.octets();
        octets[12..16].fill(0);
        report.pref64 = Some(format!("{}/96", Ipv6Addr::from(octets)));
        report
            .evidence
            .push(format!("DNS64: `{name}` AAAA -> {v6}"));
        v6
    };

    let dest = SocketAddr::new(IpAddr::V6(target), port);
    report.target = Some(dest.to_string());

    let sock =
        UdpSocket::bind("[::]:0").map_err(|e| NetError::os("binding the NAT64 probe socket", e))?;
    sock.set_read_timeout(Some(wait))
        .map_err(|e| NetError::os("setting the NAT64 probe timeout", e))?;
    let mut buf = [0u8; 1500];
    for _ in 0..4 {
        if sock.send_to(b"NAT64", dest).is_ok() {
            report.sent += 1;
        }
        if sock.recv_from(&mut buf).is_ok() {
            report.received += 1;
            report.reachable = true;
        }
    }
    report.evidence.push(format!(
        "sent {} to {dest}, {} came back",
        report.sent, report.received
    ));
    Ok(report)
}

fn query(
    resolver: SocketAddr,
    name: &str,
    qtype: u16,
    wait: Duration,
    evidence: &mut Vec<String>,
) -> Result<Vec<IpAddr>> {
    let bind: SocketAddr = if resolver.is_ipv4() {
        "0.0.0.0:0".parse().expect("a literal")
    } else {
        "[::]:0".parse().expect("a literal")
    };
    let sock = UdpSocket::bind(bind).map_err(|e| NetError::os("binding a query socket", e))?;
    sock.set_read_timeout(Some(wait))
        .map_err(|e| NetError::os("setting a query timeout", e))?;
    let mut msg = crate::traffic::encode_query(name);
    // `encode_query` writes QTYPE=A; the four trailing octets are QTYPE then
    // QCLASS, so this overwrites the type and leaves the class alone.
    let qtype_at = msg.len() - 4;
    msg[qtype_at..qtype_at + 2].copy_from_slice(&qtype.to_be_bytes());
    let mut buf = [0u8; 1500];
    // Retransmitted for the same reason every other exchange in this crate is:
    // a lost datagram is not a signal.
    for _ in 0..3 {
        if sock.send_to(&msg, resolver).is_err() {
            continue;
        }
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            let answers = parse_answers(&buf[..n]);
            evidence.push(format!(
                "{name} type {qtype} -> {}",
                if answers.is_empty() {
                    "no answer records".to_owned()
                } else {
                    answers
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ));
            return Ok(answers);
        }
    }
    evidence.push(format!("{name} type {qtype}: the resolver did not answer"));
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone() -> Zone {
        let mut a = BTreeMap::new();
        a.insert("v4only.example".to_owned(), Ipv4Addr::new(203, 0, 113, 10));
        Zone {
            a,
            pref64: Pref64::default(),
            synthesize: true,
            rfc7050: true,
        }
    }

    #[test]
    fn a_synthesized_aaaa_embeds_the_a_record_in_the_prefix() {
        let answers = zone().answers("v4only.example", rtype::AAAA);
        assert_eq!(
            answers,
            vec![IpAddr::V6("64:ff9b::cb00:710a".parse().expect("a literal"))]
        );
    }

    #[test]
    fn synthesis_off_returns_no_aaaa_and_still_returns_the_a() {
        let mut z = zone();
        z.synthesize = false;
        assert!(z.answers("v4only.example", rtype::AAAA).is_empty());
        assert_eq!(
            z.answers("v4only.example", rtype::A),
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]
        );
    }

    #[test]
    fn rfc7050_discovery_answers_ipv4only_arpa_and_can_be_switched_off_alone() {
        let answers = zone().answers(IPV4ONLY_ARPA, rtype::AAAA);
        assert_eq!(answers.len(), 2, "RFC 7050 fixes two addresses");
        let mut z = zone();
        z.rfc7050 = false;
        assert!(
            z.answers(IPV4ONLY_ARPA, rtype::AAAA).is_empty(),
            "the two discovery paths must be switchable independently (§3.3)"
        );
        assert!(
            !z.answers("v4only.example", rtype::AAAA).is_empty(),
            "switching off RFC 7050 must not switch off synthesis"
        );
    }

    #[test]
    fn a_response_this_module_builds_is_one_it_reads_back() {
        let mut request = crate::traffic::encode_query("v4only.example");
        let qtype_at = request.len() - 4;
        request[qtype_at..qtype_at + 2].copy_from_slice(&rtype::AAAA.to_be_bytes());
        let q = question(&request).expect("the request parses");
        let answers = zone().answers(&q.name, q.qtype);
        let reply = respond(&request, &q, &answers);
        assert_eq!(parse_answers(&reply), answers);
    }

    #[test]
    fn an_answer_whose_rdlength_disagrees_with_its_type_is_skipped_not_trusted() {
        let request = crate::traffic::encode_query("v4only.example");
        let q = question(&request).expect("parses");
        let mut reply = respond(&request, &q, &[IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
        // Claim a 3-byte A record.
        let rdlen_at = reply.len() - 6;
        reply[rdlen_at..rdlen_at + 2].copy_from_slice(&3u16.to_be_bytes());
        assert!(
            parse_answers(&reply).is_empty(),
            "a malformed record must be skipped rather than decoded from adjacent bytes"
        );
    }
}
