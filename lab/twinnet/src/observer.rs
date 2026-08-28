//! The wire oracle: what actually left the interface, decided by reading the
//! interface.
//!
//! **Authority:** `docs/testing-strategy.md` §4, rule **PT-2**:
//!
//! > For every test that asserts a *security* property (P07–P14), an independent
//! > wire-capture oracle MUST corroborate it, **because a system reporting on
//! > itself is not sufficient evidence for a security property**.
//!
//! A kill-switch deny counter read out of `twinvpn-enforce` is the system
//! reporting on itself. It is worth having and it is not sufficient: a packet
//! that never reached the enforcement hook is invisible to it by construction,
//! and that packet is exactly the leak. This module is the other oracle.
//!
//! # The rule this module exists to enforce
//!
//! > A test MUST fail if protected IPv4, IPv6 or DNS traffic escapes through an
//! > unauthorized path.
//!
//! [`LeakPolicy::audit`] returns one [`Escape`] per offending packet, and an
//! empty result is only meaningful next to a **positive control** — which is why
//! [`Capture::is_silent`] exists and why every rig in this laboratory asserts a
//! deliberate probe *was* seen before it asserts a leak was not. A capture that
//! recorded nothing because the socket was bound to the wrong interface would
//! otherwise be indistinguishable from a perfectly sealed tunnel, and would
//! report the same green line.

use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::afpacket::PacketSocket;
use crate::error::{NetError, Result};
use crate::ip::{self, proto};

/// One observed packet, reduced to what an oracle asks about.
///
/// Deliberately not the bytes. A capture that stored payloads would be a
/// capture that could leak key material into a CI artifact, and no oracle in
/// this laboratory reads a payload except the DNS question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Microseconds since the capture began. Evidence, never an assertion input
    /// in a `BIT` scenario (§3.5).
    pub at_us: u64,
    /// The interface the frame was seen on.
    pub iface: String,
    /// The ethertype, so a non-IP frame is counted rather than discarded.
    pub ethertype: u16,
    /// The link-layer source, as `02:00:…`.
    ///
    /// Carried because "something on this segment sent a frame it should not
    /// have" is only actionable if the finding names *which interface*. An IP
    /// source can be forged or absent; the MAC names the port it came out of.
    #[serde(default)]
    pub eth_src: String,
    /// The link-layer destination.
    #[serde(default)]
    pub eth_dst: String,
    /// Source address, absent for a non-IP frame.
    pub src: Option<String>,
    /// Destination address.
    pub dst: Option<String>,
    /// IP protocol number.
    pub proto: Option<u8>,
    /// Source port, or an ICMP echo identifier.
    pub sport: Option<u16>,
    /// Destination port.
    pub dport: Option<u16>,
    /// Frame length on the wire.
    pub len: usize,
    /// Whether the IP header said this was a fragment.
    pub fragmented: bool,
    /// The QNAME of the first question, when the payload is a plaintext DNS
    /// query. The one payload field this laboratory reads, because "which name
    /// leaked" is the whole content of a DNS-leak finding.
    pub dns_qname: Option<String>,
}

impl Record {
    /// The source address, parsed.
    #[must_use]
    pub fn src_ip(&self) -> Option<IpAddr> {
        self.src.as_ref().and_then(|s| s.parse().ok())
    }

    /// The destination address, parsed.
    #[must_use]
    pub fn dst_ip(&self) -> Option<IpAddr> {
        self.dst.as_ref().and_then(|s| s.parse().ok())
    }
}

/// A finished capture.
#[derive(Debug, Clone, Default)]
pub struct Capture {
    /// Every record, in the order observed.
    pub records: Vec<Record>,
}

impl Capture {
    /// Reads a capture written by [`run`].
    ///
    /// # Errors
    ///
    /// [`NetError::Os`] if the file cannot be read. A *missing* file is an
    /// error rather than an empty capture: "the observer never started" and
    /// "nothing leaked" must never produce the same value.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| NetError::os(format!("reading the capture at {}", path.display()), e))?;
        let mut records = Vec::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let r: Record = serde_json::from_str(line)
                .map_err(|e| NetError::Agent(format!("undecodable capture record: {e}")))?;
            records.push(r);
        }
        Ok(Capture { records })
    }

    /// Whether the capture saw nothing at all.
    ///
    /// **The positive control's question.** A rig asserts this is `false` — with
    /// a probe it deliberately sent — *before* it asserts that no leak is
    /// present. Rule V4, and the reason `tests/README.md` §3 says "a test that
    /// cannot fail is not a test".
    #[must_use]
    pub fn is_silent(&self) -> bool {
        self.records.is_empty()
    }

    /// Records matching a predicate.
    #[must_use]
    pub fn matching(&self, f: impl Fn(&Record) -> bool) -> Vec<&Record> {
        self.records.iter().filter(|r| f(r)).collect()
    }
}

/// An IP prefix, in the form a policy states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prefix {
    /// The network address.
    pub addr: IpAddr,
    /// The prefix length in bits.
    pub bits: u8,
}

impl Prefix {
    /// Parses `10.0.0.0/8` or `fd00::/8`.
    ///
    /// # Errors
    ///
    /// A message naming what was unparseable.
    pub fn parse(s: &str) -> std::result::Result<Self, String> {
        let (addr, bits) = s
            .split_once('/')
            .ok_or_else(|| format!("`{s}` is not a prefix; it has no `/`"))?;
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("`{addr}` is not an IP address"))?;
        let bits: u8 = bits
            .parse()
            .map_err(|_| format!("`{bits}` is not a prefix length"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return Err(format!("/{bits} is too long for {addr}"));
        }
        Ok(Prefix { addr, bits })
    }

    /// Whether `addr` falls inside this prefix.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.addr, addr) {
            (IpAddr::V4(net), IpAddr::V4(a)) => {
                let mask = if self.bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.bits))
                };
                u32::from(net) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(a)) => {
                let mask = if self.bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.bits))
                };
                u128::from(net) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

/// One endpoint traffic is allowed to reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allowed {
    /// The address.
    pub addr: IpAddr,
    /// The port, or `None` for every port at that address.
    pub port: Option<u16>,
    /// Why this endpoint is permitted, quoted into the failure message so a
    /// reader of a red test knows what the allowlist was for.
    pub because: String,
}

/// How strictly the oracle reads the interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Strictness {
    /// Only protected addressing and unauthorized DNS are escapes. The oracle
    /// for a split-tunnel scenario, where unprotected traffic on the underlay is
    /// the *correct* behaviour.
    ProtectedOnly,
    /// Everything not explicitly allowed is an escape. The oracle for a full
    /// tunnel and for the kill switch, where the guarantee is about the
    /// interface and not about a list of prefixes.
    FailClosed,
}

/// What the oracle considers a leak.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakPolicy {
    /// Prefixes that must never appear as a source or destination on the
    /// observed interface, in either family.
    pub protected: Vec<Prefix>,
    /// Endpoints traffic may reach: the relay, the rendezvous, the control
    /// plane, the peer's underlay address.
    pub allowed: Vec<Allowed>,
    /// The resolvers a DNS query may go to. Any other destination for a DNS
    /// query is a leak even if the destination is otherwise allowed.
    pub dns_authorities: Vec<IpAddr>,
    /// How strict to be.
    pub strictness: Strictness,
    /// Ethertypes that are never a leak: ARP and neighbour discovery are how a
    /// segment works, and counting them as escapes would make every scenario
    /// red for a reason that has nothing to do with the tunnel.
    pub benign_ethertypes: Vec<u16>,
}

impl LeakPolicy {
    /// A fail-closed policy with nothing allowed. The starting point for a kill
    /// switch scenario: a caller adds the endpoints the design says stay
    /// reachable, and every addition is visible in the test.
    #[must_use]
    pub fn sealed() -> Self {
        LeakPolicy {
            protected: Vec::new(),
            allowed: Vec::new(),
            dns_authorities: Vec::new(),
            strictness: Strictness::FailClosed,
            benign_ethertypes: vec![ip::ETHERTYPE_ARP],
        }
    }

    /// Adds a protected prefix.
    #[must_use]
    pub fn protecting(mut self, prefix: Prefix) -> Self {
        self.protected.push(prefix);
        self
    }

    /// Adds an allowed endpoint, with the reason it is allowed.
    #[must_use]
    pub fn allowing(mut self, addr: IpAddr, port: Option<u16>, because: &str) -> Self {
        self.allowed.push(Allowed {
            addr,
            port,
            because: because.to_owned(),
        });
        self
    }

    /// Names the resolver DNS may be sent to.
    #[must_use]
    pub fn resolver(mut self, addr: IpAddr) -> Self {
        self.dns_authorities.push(addr);
        self
    }

    /// Relaxes the oracle to protected addressing and DNS only.
    #[must_use]
    pub fn protected_only(mut self) -> Self {
        self.strictness = Strictness::ProtectedOnly;
        self
    }

    /// Every packet in `capture` that this policy forbids.
    ///
    /// The return value is a list rather than a boolean so a failure message can
    /// name the packets. "Traffic escaped" is not a finding a reader can act on;
    /// "packet 41: 100.64.3.2 → 8.8.8.8 udp/53 `telemetry.example.` " is.
    #[must_use]
    pub fn audit(&self, capture: &Capture) -> Vec<Escape> {
        let mut out = Vec::new();
        for (index, r) in capture.records.iter().enumerate() {
            if self.benign_ethertypes.contains(&r.ethertype) {
                continue;
            }
            if let Some(reason) = self.judge(r) {
                out.push(Escape {
                    index,
                    reason,
                    record: r.clone(),
                });
            }
        }
        out
    }

    fn judge(&self, r: &Record) -> Option<Reason> {
        let src = r.src_ip();
        let dst = r.dst_ip();
        let Some((src, dst)) = src.zip(dst) else {
            // A non-IP frame that is not on the benign list. It is not
            // *known* to be safe, so under a fail-closed oracle it is an
            // escape and under the relaxed one it is not.
            return match self.strictness {
                Strictness::FailClosed => Some(Reason::UnknownEthertype),
                Strictness::ProtectedOnly => None,
            };
        };

        for p in &self.protected {
            if p.contains(src) {
                return Some(Reason::ProtectedSource { prefix: *p });
            }
            if p.contains(dst) {
                return Some(Reason::ProtectedDestination { prefix: *p });
            }
        }

        if is_plaintext_dns(r) && !self.dns_authorities.contains(&dst) {
            return Some(Reason::UnauthorizedDns {
                qname: r.dns_qname.clone(),
            });
        }

        if self.strictness == Strictness::FailClosed && !self.permits(dst, r.dport) {
            // A reply to something we allowed is allowed: the peer is the
            // source, and the source is on the list.
            if self.permits(src, r.sport) {
                return None;
            }
            return Some(Reason::NotOnTheAllowlist);
        }
        None
    }

    fn permits(&self, addr: IpAddr, port: Option<u16>) -> bool {
        self.allowed
            .iter()
            .any(|a| a.addr == addr && (a.port.is_none() || port.is_none() || a.port == port))
    }
}

/// Whether a record is a plaintext DNS message.
///
/// Port 53 in either direction, plus mDNS on 5353 and LLMNR on 5355, because
/// ADR-0011's leak surface is "a name resolved off-tunnel" and the host stack
/// has three ways to do it. DNS-over-TLS on 853 and DNS-over-HTTPS on 443 are
/// deliberately **not** here: they are encrypted, they are a policy question
/// rather than a leak, and the endpoint allowlist is where they are judged.
#[must_use]
pub fn is_plaintext_dns(r: &Record) -> bool {
    const NAME_PORTS: [u16; 3] = [53, 5353, 5355];
    matches!(r.proto, Some(proto::UDP | proto::TCP))
        && (r.dport.is_some_and(|p| NAME_PORTS.contains(&p))
            || r.sport.is_some_and(|p| NAME_PORTS.contains(&p)))
}

/// Why a packet was judged an escape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// A protected prefix appeared as the source.
    ProtectedSource {
        /// The prefix it fell in.
        prefix: Prefix,
    },
    /// A protected prefix appeared as the destination.
    ProtectedDestination {
        /// The prefix it fell in.
        prefix: Prefix,
    },
    /// A plaintext name lookup went somewhere other than the authorized
    /// resolver.
    UnauthorizedDns {
        /// The name that leaked, when the question was parseable.
        qname: Option<String>,
    },
    /// A fail-closed oracle saw traffic to an endpoint nobody allowed.
    NotOnTheAllowlist,
    /// A fail-closed oracle saw a non-IP frame that is not on the benign list.
    UnknownEthertype,
}

/// One packet that should not have been on the wire.
#[derive(Debug, Clone)]
pub struct Escape {
    /// Its index in the capture, so a reader can find it.
    pub index: usize,
    /// Why it is an escape.
    pub reason: Reason,
    /// The record itself.
    pub record: Record,
}

impl std::fmt::Display for Escape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = &self.record;
        write!(
            f,
            "packet {} on {} at {}us: [{}] {} -> {} proto {} {}:{} ({} bytes)",
            self.index,
            r.iface,
            r.at_us,
            r.eth_src,
            r.src.as_deref().unwrap_or("?"),
            r.dst.as_deref().unwrap_or("?"),
            r.proto.map_or_else(|| "?".to_owned(), |p| p.to_string()),
            r.sport.map_or_else(|| "?".to_owned(), |p| p.to_string()),
            r.dport.map_or_else(|| "?".to_owned(), |p| p.to_string()),
            r.len
        )?;
        match &self.reason {
            Reason::ProtectedSource { prefix } => write!(
                f,
                " — PROTECTED SOURCE: {}/{} must never appear on this interface",
                prefix.addr, prefix.bits
            ),
            Reason::ProtectedDestination { prefix } => write!(
                f,
                " — PROTECTED DESTINATION: {}/{} must never appear on this interface",
                prefix.addr, prefix.bits
            ),
            Reason::UnauthorizedDns { qname } => write!(
                f,
                " — DNS LEAK: `{}` was resolved off-tunnel",
                qname.as_deref().unwrap_or("<unparsed question>")
            ),
            Reason::NotOnTheAllowlist => write!(f, " — FAIL-CLOSED: no rule permits this endpoint"),
            Reason::UnknownEthertype => write!(f, " — FAIL-CLOSED: unrecognised ethertype"),
        }
    }
}

/// Captures `iface` for `duration`, appending one JSON record per frame to
/// `out`.
///
/// Runs in the middlebox process rather than in the test, because a capture that
/// crossed a process boundary per packet would drop frames under load and a
/// dropped frame is a leak this oracle would not see.
///
/// # Errors
///
/// [`NetError::Unavailable`] if the raw socket cannot be opened.
pub fn run(iface: &str, out: &Path, duration: Duration) -> Result<()> {
    let sock = PacketSocket::open(iface)?;
    sock.set_promiscuous()?;
    sock.set_read_timeout(Duration::from_millis(100))?;
    let mut file = std::fs::File::create(out)
        .map_err(|e| NetError::os(format!("creating the capture at {}", out.display()), e))?;
    let started = Instant::now();
    let mut buf = vec![0u8; 65_536];
    while started.elapsed() < duration {
        let Some(n) = sock.recv(&mut buf)? else {
            continue;
        };
        let frame = &buf[..n];
        let record = summarize(iface, frame, started.elapsed().as_micros() as u64);
        use std::io::Write;
        let line = serde_json::to_string(&record).expect("Record is always encodable");
        writeln!(file, "{line}").map_err(|e| NetError::os("appending a capture record", e))?;
    }
    Ok(())
}

/// Reduces one frame to a [`Record`].
#[must_use]
pub fn summarize(iface: &str, frame: &[u8], at_us: u64) -> Record {
    let ethertype = ip::ethertype_of(frame).unwrap_or(0);
    let (eth_src, eth_dst) = link_layer(frame);
    let Some(p) = ip::parse(frame) else {
        return Record {
            at_us,
            iface: iface.to_owned(),
            ethertype,
            eth_src,
            eth_dst,
            src: None,
            dst: None,
            proto: None,
            sport: None,
            dport: None,
            len: frame.len(),
            fragmented: false,
            dns_qname: None,
        };
    };
    let dns_qname = if is_name_port(p.dst_port)
        .or_else(|| is_name_port(p.src_port))
        .is_some()
    {
        frame
            .get(p.payload_off..)
            .and_then(ip::dns_question)
            .map(|(name, _)| name)
    } else {
        None
    };
    Record {
        at_us,
        iface: iface.to_owned(),
        ethertype,
        eth_src,
        eth_dst,
        src: Some(p.src.to_string()),
        dst: Some(p.dst.to_string()),
        proto: Some(p.proto),
        sport: p.src_port,
        dport: p.dst_port,
        len: frame.len(),
        fragmented: p.fragmented,
        dns_qname,
    }
}

/// The two link-layer addresses, in the usual colon form.
fn link_layer(frame: &[u8]) -> (String, String) {
    let hex = |b: &[u8]| {
        b.iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    if frame.len() < 12 {
        return (String::new(), String::new());
    }
    (hex(&frame[6..12]), hex(&frame[0..6]))
}

fn is_name_port(port: Option<u16>) -> Option<u16> {
    port.filter(|p| matches!(p, 53 | 5353 | 5355))
}
