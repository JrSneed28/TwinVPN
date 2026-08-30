//! The DNS half of the data plane: enough of RFC 1035 to read a question and
//! answer it, and nothing else.
//!
//! # Why hand-rolled
//!
//! The oracle needs exactly two facts out of a DNS packet — the QNAME and the
//! peer address the kernel reported — and it needs to answer well enough that a
//! resolver does not retry forever. A full resolver library would bring a zone
//! store, a cache, DNSSEC and a recursion path, none of which participates in
//! the observation. What it would bring that matters is doubt: a reader of this
//! evidence has to be able to see what was recorded, and 150 lines is readable.
//!
//! # What arrives here, and from where
//!
//! Two shapes, and they are not the same evidence:
//!
//! * **Through the device's resolver** (the zone is delegated to this host).
//!   This is the shape that tests the DNS egress users leak through, because it
//!   is the path the OS actually takes. The peer address is then the RECURSIVE
//!   RESOLVER's, not the device's — which is why `lib.rs` keeps DNS out of the
//!   source sets.
//! * **Straight at this host's port 53.** The peer is the device, but the test
//!   is then really "UDP/53 egress", not "name resolution".
//!
//! Both count identically for presence/absence, which is the criterion.

use std::net::IpAddr;

use crate::PathKind;

/// A parsed question, reduced to what the oracle records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: u16,
    /// The QNAME, lowercased, dot-joined, without a trailing dot.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Byte length of the question section, so the reply can echo it verbatim.
    pub question_len: usize,
}

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;

/// Parse a query. Returns `None` for anything that is not a single-question
/// standard query, which is everything the oracle is willing to answer.
///
/// A malformed packet is NOT an error worth reporting: this socket is on the
/// public internet and will receive scans. It is dropped.
pub fn parse_query(buf: &[u8]) -> Option<Question> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    // QR must be 0 (a query) and OPCODE must be 0 (standard).
    if flags & 0x8000 != 0 || (flags >> 11) & 0x0f != 0 {
        return None;
    }
    if u16::from_be_bytes([buf[4], buf[5]]) != 1 {
        return None;
    }

    let mut labels: Vec<String> = Vec::new();
    let mut i = 12usize;
    loop {
        let len = *buf.get(i)? as usize;
        // NO COMPRESSION POINTER IS FOLLOWED. A pointer in a QNAME is not legal
        // in a query, and following one is how a parser this small becomes a
        // loop an attacker controls.
        if len & 0xc0 != 0 {
            return None;
        }
        i += 1;
        if len == 0 {
            break;
        }
        let end = i.checked_add(len)?;
        let label = buf.get(i..end)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        i = end;
        // A QNAME longer than the RFC's 255 octets is not a name we issued.
        if i > 12 + 255 {
            return None;
        }
    }
    let qtype = u16::from_be_bytes([*buf.get(i)?, *buf.get(i + 1)?]);
    let qclass = u16::from_be_bytes([*buf.get(i + 2)?, *buf.get(i + 3)?]);
    Some(Question {
        id,
        name: labels.join("."),
        qtype,
        qclass,
        question_len: (i + 4) - 12,
    })
}

/// Build a reply that echoes the question and answers with `answer`, or with no
/// records at all when `answer` is `None`.
///
/// A resolver that gets NODATA stops asking, which is all the oracle needs; the
/// observation was made the moment the query arrived. An address is returned
/// only when the probe asked for the matching type, so the beacon can also be
/// used as a reachability check by the probe itself.
pub fn build_reply(query: &[u8], q: &Question, answer: Option<IpAddr>) -> Vec<u8> {
    let qsec = &query[12..12 + q.question_len];
    let mut out = Vec::with_capacity(12 + qsec.len() + 32);
    out.extend_from_slice(&q.id.to_be_bytes());
    // QR=1, OPCODE=0, AA=1 (this host is authoritative for the beacon zone),
    // TC=0, RD copied from the query, RA=0, RCODE=0.
    let rd = query[2] & 0x01;
    out.push(0x84 | rd);
    out.push(0x00);
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    let (ancount, rdata): (u16, Option<Vec<u8>>) = match answer {
        Some(IpAddr::V4(a)) if q.qtype == TYPE_A => (1, Some(a.octets().to_vec())),
        Some(IpAddr::V6(a)) if q.qtype == TYPE_AAAA => (1, Some(a.octets().to_vec())),
        _ => (0, None),
    };
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(qsec);
    if let Some(rdata) = rdata {
        // A compression pointer back to the question's own QNAME at offset 12.
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&q.qtype.to_be_bytes());
        out.extend_from_slice(&q.qclass.to_be_bytes());
        // TTL 0. A cached beacon answer is a beacon that stops leaving the
        // device, which would make the next phase's silence meaningless.
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    out
}

/// Split `<seq>.<token>.<path_tag>.<zone>` into `(token, seq, path_tag)` when
/// `name` is inside `zone`. Returns `None` for anything else, which is how
/// internet scan noise is kept out of the observation record.
///
/// The `path_tag` label is OPTIONAL and is only ever the probe's INTENT — `p`
/// protected, `u` unprotected, `n` no claim, `s` a sentinel beacon. The last
/// two are consumed but name no path. A name whose last label is none of the
/// four still yields a `(token, seq)`, because the arrival itself is the
/// observation and dropping it would turn a mislabelled beacon into silence.
/// `evidence.rs` derives the path that actually resolved the query from the
/// address it arrived from and compares the two; the tag is never trusted on
/// its own.
pub fn beacon_labels(name: &str, zone: &str) -> Option<(String, String, Option<PathKind>)> {
    let zone = zone.trim_matches('.').to_ascii_lowercase();
    let name = name.trim_matches('.').to_ascii_lowercase();
    let head = name.strip_suffix(&zone)?.strip_suffix('.')?;
    let mut labels: Vec<&str> = head.split('.').collect();

    let tag = match labels.last().copied().and_then(PathKind::strip_tag) {
        Some(path) => {
            labels.pop();
            path
        }
        None => None,
    };

    let token = labels.pop()?.to_string();
    if token.is_empty() {
        return None;
    }
    Some((token, labels.join("."), tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wire-format round trip over a real query, because a hand-rolled parser
    /// that is wrong is worse than no parser: it would drop beacons and report
    /// silence.
    #[test]
    fn a_real_query_parses_and_the_reply_echoes_it() {
        // id=0xbeef, standard query, RD set, QDCOUNT=1, QNAME=7.tok.leak.test
        let mut q = vec![0xbe, 0xef, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in ["7", "tok", "leak", "test"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&TYPE_A.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());

        let parsed = parse_query(&q).expect("a well-formed query must parse");
        assert_eq!(parsed.name, "7.tok.leak.test");
        assert_eq!(parsed.qtype, TYPE_A);

        let reply = build_reply(&q, &parsed, Some("192.0.2.7".parse().unwrap()));
        assert_eq!(&reply[0..2], &[0xbe, 0xef], "the reply must echo the id");
        assert_eq!(reply[2] & 0x80, 0x80, "QR must be set");
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 1, "ANCOUNT");
        assert_eq!(&reply[reply.len() - 4..], &[192, 0, 2, 7]);

        assert_eq!(
            beacon_labels(&parsed.name, "leak.test"),
            Some(("tok".into(), "7".into(), None))
        );
        assert_eq!(beacon_labels("scanner.example.com", "leak.test"), None);

        // The tagged form the probe now emits: the tag is the LAST label before
        // the zone, so the token is the one before it and the sequence is
        // everything to the left.
        assert_eq!(
            beacon_labels("7.tok.u.leak.test", "leak.test"),
            Some(("tok".into(), "7".into(), Some(PathKind::Unprotected)))
        );
        assert_eq!(
            beacon_labels("7.tok.p.leak.test", "leak.test"),
            Some(("tok".into(), "7".into(), Some(PathKind::Protected)))
        );

        // `n` (the phase makes no path claim) and `s` (a sentinel beacon) are
        // real tag labels that name no path. They MUST be consumed: leave one
        // in place and it becomes the token, the beacon matches no session and
        // is dropped, and the family then reports zero arrivals — which is what
        // a working kill switch also reports. A sentinel silently parsed as
        // token "s" is a sentinel that appears never to have beaten at all.
        assert_eq!(
            beacon_labels("7.tok.n.leak.test", "leak.test"),
            Some(("tok".into(), "7".into(), None))
        );
        assert_eq!(
            beacon_labels("2.stok.s.leak.test", "leak.test"),
            Some(("stok".into(), "2".into(), None))
        );
    }

    /// A compression pointer in a QNAME is the loop a small parser is
    /// vulnerable to, and this socket is reachable from the internet.
    #[test]
    fn a_compression_pointer_in_the_question_is_refused_rather_than_followed() {
        let q = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c,
        ];
        assert_eq!(parse_query(&q), None);
    }

    /// Truncated garbage must be dropped, not panic. `parse_query` indexes with
    /// `get`, and this is the check that keeps it that way.
    #[test]
    fn truncated_packets_are_dropped_without_panicking() {
        for n in 0..14 {
            let q = vec![0u8; n];
            let _ = parse_query(&q);
        }
        let mut q = vec![0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        q.push(9); // a label longer than what follows
        q.extend_from_slice(b"ab");
        assert_eq!(parse_query(&q), None);
    }
}
