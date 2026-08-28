//! The traffic a scenario actually puts on the wire, and the reflector the
//! conformance prober measures a middlebox with.
//!
//! **Why a laboratory needs its own traffic sources.** A topology with a NAT in
//! it and nothing crossing it is a topology whose only test is that `ip` exited
//! zero. These are the smallest programs that make a middlebox do work and
//! report what happened, in a form an oracle can assert on.
//!
//! **Why the reflector is not a STUN server.** RFC 5780's behaviour tests need
//! a responder with two addresses and two ports that can be asked to answer from
//! a *different* one than it was addressed on. A real STUN server does that, and
//! importing one would put a third-party dependency in the trust path of the
//! conformance suite that decides whether TwinVPN's NAT results are admissible.
//! This is forty lines of UDP with a four-word text protocol, which a reviewer
//! can read in full — and, decisively for §3.4.2, it is **not TwinVPN code**.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::error::{NetError, Result};

/// The reflector's wire language.
///
/// Text because the whole protocol is four verbs and the debugging value of a
/// readable capture outweighs anything a binary encoding would buy at these
/// rates.
pub mod verbs {
    /// `PROBE` — answer from the socket this arrived on.
    pub const PROBE: &str = "PROBE";
    /// `PROBE-CHANGE-ADDR` — answer from the alternate address, same port.
    pub const PROBE_CHANGE_ADDR: &str = "PROBE-CHANGE-ADDR";
    /// `PROBE-CHANGE-PORT` — answer from the same address, alternate port.
    pub const PROBE_CHANGE_PORT: &str = "PROBE-CHANGE-PORT";
    /// `SENDTO <ip> <port>` — send one unsolicited datagram to that endpoint.
    /// The mechanism behind the mapping-lifetime and filtering measurements.
    pub const SENDTO: &str = "SENDTO";
    /// The answer: `MAPPED <ip> <port>`.
    pub const MAPPED: &str = "MAPPED";
}

/// Runs a reflector with two addresses and two ports.
///
/// # Errors
///
/// [`NetError::Os`] if any of the four sockets cannot be bound. All four are
/// required: a reflector that silently came up with three would answer the
/// filtering tests wrongly and the wrongness would look like a NAT property.
pub fn reflect(
    primary: IpAddr,
    alternate: IpAddr,
    port_a: u16,
    port_b: u16,
    duration: Duration,
) -> Result<()> {
    let bind = |addr: IpAddr, port: u16| -> Result<UdpSocket> {
        let s = UdpSocket::bind(SocketAddr::new(addr, port))
            .map_err(|e| NetError::os(format!("binding the reflector to {addr}:{port}"), e))?;
        s.set_read_timeout(Some(Duration::from_millis(50)))
            .map_err(|e| NetError::os("setting the reflector read timeout", e))?;
        Ok(s)
    };
    // The four sockets are laid out (primary,a) (primary,b) (alternate,a)
    // (alternate,b), so flipping bit 1 changes the address and flipping bit 0
    // changes the port. RFC 5780's filtering tests are exactly those two flips.
    let socks = [
        bind(primary, port_a)?,
        bind(primary, port_b)?,
        bind(alternate, port_a)?,
        bind(alternate, port_b)?,
    ];

    // One thread per socket, and it is worth saying why rather than leaving it
    // as a style choice. A single loop polling four sockets with a blocking
    // timeout answers in up to four times that timeout, and the prober's own
    // read timeout is the thing being compared against. The first version of
    // this file round-robined with 100 ms timeouts and produced a reflector that
    // answered one peer and appeared unreachable to another — which the
    // laboratory would have reported as a NAT class rather than as a slow
    // responder. A reflector must never be the slowest thing in a measurement of
    // something else.
    std::thread::scope(|scope| {
        let socks = &socks;
        for index in 0..socks.len() {
            scope.spawn(move || {
                let started = Instant::now();
                let mut buf = [0u8; 2048];
                while started.elapsed() < duration {
                    let Ok((n, from)) = socks[index].recv_from(&mut buf) else {
                        continue;
                    };
                    let text = String::from_utf8_lossy(&buf[..n]);
                    let mut parts = text.split_whitespace();
                    let verb = parts.next().unwrap_or("");
                    let responder = match verb {
                        verbs::PROBE_CHANGE_ADDR => index ^ 0b10,
                        verbs::PROBE_CHANGE_PORT => index ^ 0b01,
                        _ => index,
                    };
                    match verb {
                        verbs::PROBE | verbs::PROBE_CHANGE_ADDR | verbs::PROBE_CHANGE_PORT => {
                            let reply = format!("{} {} {}", verbs::MAPPED, from.ip(), from.port());
                            let _ = socks[responder].send_to(reply.as_bytes(), from);
                        }
                        verbs::SENDTO => {
                            let (Some(ip), Some(port)) = (parts.next(), parts.next()) else {
                                continue;
                            };
                            let (Ok(ip), Ok(port)) = (ip.parse::<IpAddr>(), port.parse::<u16>())
                            else {
                                continue;
                            };
                            let reply = format!("{} {} {}", verbs::MAPPED, ip, port);
                            let _ = socks[responder]
                                .send_to(reply.as_bytes(), SocketAddr::new(ip, port));
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    Ok(())
}

/// What one `udp-send` run observed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SendReport {
    /// How many datagrams were sent.
    pub sent: u32,
    /// How many replies came back.
    pub received: u32,
    /// The local port the sender bound, so a NAT's mapping can be attributed.
    pub local_port: u16,
    /// Each reply's payload, in arrival order. The reflector's `MAPPED` lines
    /// end up here, which is how the prober learns its external address.
    pub replies: Vec<String>,
    /// Round-trip times in microseconds. Evidence; never an assertion input in a
    /// `BIT` scenario (§3.5).
    pub rtt_us: Vec<u64>,
}

/// Sends `count` datagrams and collects whatever comes back.
///
/// # Errors
///
/// [`NetError::Os`] if the socket cannot be bound or the destination is
/// unreachable at bind time.
pub fn udp_send(
    bind_addr: SocketAddr,
    to: SocketAddr,
    payload: &str,
    count: u32,
    interval: Duration,
    wait: Duration,
) -> Result<SendReport> {
    let sock = UdpSocket::bind(bind_addr)
        .map_err(|e| NetError::os(format!("binding a sender to {bind_addr}"), e))?;
    sock.set_read_timeout(Some(wait))
        .map_err(|e| NetError::os("setting the sender read timeout", e))?;
    let local_port = sock
        .local_addr()
        .map_err(|e| NetError::os("reading the sender's local address", e))?
        .port();
    let mut report = SendReport {
        sent: 0,
        received: 0,
        local_port,
        replies: Vec::new(),
        rtt_us: Vec::new(),
    };
    let mut buf = [0u8; 2048];
    for i in 0..count {
        let at = Instant::now();
        if sock.send_to(payload.as_bytes(), to).is_ok() {
            report.sent += 1;
        }
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            report.received += 1;
            report.rtt_us.push(at.elapsed().as_micros() as u64);
            report
                .replies
                .push(String::from_utf8_lossy(&buf[..n]).into_owned());
        }
        if i + 1 < count {
            std::thread::sleep(interval);
        }
    }
    Ok(report)
}

/// Echoes every datagram back to its sender, for the duration.
///
/// The peer at the far side of a traversal scenario: if a datagram gets here and
/// the reply gets back, the path exists.
///
/// # Errors
///
/// [`NetError::Os`] if the socket cannot be bound.
pub fn udp_echo(bind_addr: SocketAddr, duration: Duration) -> Result<u64> {
    let sock = UdpSocket::bind(bind_addr)
        .map_err(|e| NetError::os(format!("binding an echo to {bind_addr}"), e))?;
    sock.set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|e| NetError::os("setting the echo read timeout", e))?;
    let started = Instant::now();
    let mut buf = [0u8; 2048];
    let mut seen = 0u64;
    while started.elapsed() < duration {
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            seen += 1;
            let _ = sock.send_to(&buf[..n], from);
        }
    }
    Ok(seen)
}

/// Sends one real DNS query and returns whether an answer came back.
///
/// **This exists to be caught.** It is the positive control for every DNS-leak
/// oracle: a rig that asserts "no plaintext DNS left this interface" must first
/// prove that a plaintext query *would* have been seen, or the assertion is
/// about the observer rather than about the tunnel.
///
/// # Errors
///
/// [`NetError::Os`] if the socket cannot be bound.
pub fn dns_query(server: SocketAddr, name: &str, wait: Duration) -> Result<bool> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().expect("a literal")
    } else {
        "[::]:0".parse().expect("a literal")
    };
    let sock =
        UdpSocket::bind(bind).map_err(|e| NetError::os("binding the DNS probe socket", e))?;
    sock.set_read_timeout(Some(wait))
        .map_err(|e| NetError::os("setting the DNS probe timeout", e))?;
    let query = encode_query(name);
    sock.send_to(&query, server)
        .map_err(|e| NetError::os(format!("sending a DNS query to {server}"), e))?;
    let mut buf = [0u8; 1500];
    Ok(sock.recv_from(&mut buf).is_ok())
}

/// A minimal DNS query: one question, type A, class IN, recursion desired.
#[must_use]
pub fn encode_query(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + name.len());
    // A fixed transaction id, because the laboratory's value is reproducibility
    // and nothing here defends against off-path spoofing.
    out.extend_from_slice(&[0x7a, 0x1d]);
    out.extend_from_slice(&[0x01, 0x00]); // RD
    out.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        out.push(bytes.len().min(63) as u8);
        out.extend_from_slice(&bytes[..bytes.len().min(63)]);
    }
    out.push(0);
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
    out
}

/// What one side of a hole-punch attempt observed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct P2pReport {
    /// The external endpoint the reflector saw for this peer.
    pub mapped: Option<String>,
    /// The peer's external endpoint, learned out of band.
    pub peer: Option<String>,
    /// Whether a datagram from the peer's external endpoint ever arrived.
    ///
    /// **This is the whole oracle.** §2.10 asserts an outcome *class*, and the
    /// class is decided by whether the two sides reached each other without a
    /// forwarder — not by whether either of them believes they did.
    pub direct: bool,
    /// How many hole-punch datagrams were sent.
    pub sent: u32,
    /// How many arrived from the peer.
    pub received: u32,
    /// The peer-reflexive endpoint, when the peer's packets arrived from an
    /// endpoint other than the one it published. Present exactly when the
    /// far-side middlebox allocated per destination.
    #[serde(default)]
    pub learned: Option<String>,
    /// Datagrams sent during the hold phase, after the path was established.
    #[serde(default)]
    pub held_sent: u32,
    /// Datagrams received during the hold phase.
    ///
    /// **This is the I5 oracle at the datagram level.** The hold phase touches
    /// no reflector, no signalling file and no third party: it is two sockets
    /// that already know each other. A scenario kills the rendezvous during the
    /// hold, and a non-zero count here is evidence that an established path
    /// needed nothing from it.
    #[serde(default)]
    pub held_received: u32,
}

/// One side of a simultaneous open across two middleboxes.
///
/// The out-of-band exchange is a file, and it stands in for the rendezvous
/// service: both peers learn each other's external endpoint through a channel
/// that is not the path under test. Using the real rendezvous here would make a
/// NAT-class result depend on a service, and §2.10's matrix is about middleboxes.
///
/// # Errors
///
/// [`NetError::Os`] if the socket cannot be bound or the exchange file cannot be
/// written. A peer that never appears is **not** an error: that is a scenario
/// this laboratory deliberately produces, and it reports `direct: false`.
pub fn p2p(
    reflector: SocketAddr,
    mine: &std::path::Path,
    theirs: &std::path::Path,
    rounds: u32,
    interval: Duration,
    wait: Duration,
    hold: Duration,
) -> Result<P2pReport> {
    let bind: SocketAddr = if reflector.is_ipv4() {
        "0.0.0.0:0".parse().expect("a literal")
    } else {
        "[::]:0".parse().expect("a literal")
    };
    let sock = UdpSocket::bind(bind).map_err(|e| NetError::os("binding the p2p socket", e))?;
    // Generous for the reflector exchange, which crosses the middlebox twice and
    // happens once; tightened below for the punch loop, which must not spend a
    // whole round waiting on a packet that a filter is never going to admit.
    sock.set_read_timeout(Some(Duration::from_millis(750)))
        .map_err(|e| NetError::os("setting the p2p read timeout", e))?;

    let mut report = P2pReport {
        mapped: None,
        peer: None,
        direct: false,
        sent: 0,
        received: 0,
        learned: None,
        held_sent: 0,
        held_received: 0,
    };

    // Learn the external endpoint the middlebox allocated. This is also what
    // opens the mapping, which is why it happens before the exchange.
    //
    // Retransmitted, because a lost datagram here is not a signal. RFC 5389
    // makes a STUN client retransmit for the same reason: on a loaded host or an
    // impaired link the first request can simply be dropped, and a peer that
    // gave up after one would report `mapped: null` — which reads identically to
    // "this middlebox blackholed us" and would attribute a scheduling hiccup to
    // the network under test.
    let mut buf = [0u8; 2048];
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(120));
        }
        let _ = sock.send_to(verbs::PROBE.as_bytes(), reflector);
        let Ok((n, _)) = sock.recv_from(&mut buf) else {
            continue;
        };
        let text = String::from_utf8_lossy(&buf[..n]).into_owned();
        let mut parts = text.split_whitespace();
        if parts.next() == Some(verbs::MAPPED) {
            if let (Some(ip), Some(port)) = (parts.next(), parts.next()) {
                // Composed through `SocketAddr`, not `format!("{ip}:{port}")`.
                // An IPv6 literal needs brackets before a port, and the naive
                // form produced `2001:db8:a::2:36781` — which the peer could not
                // parse, so every v6 pair reported "the peer never published"
                // and looked exactly like an unreachable network.
                if let (Ok(ip), Ok(port)) = (ip.parse::<IpAddr>(), port.parse::<u16>()) {
                    report.mapped = Some(SocketAddr::new(ip, port).to_string());
                    break;
                }
            }
        }
    }
    let Some(mapped) = report.mapped.clone() else {
        return Ok(report);
    };
    std::fs::write(mine, &mapped)
        .map_err(|e| NetError::os("publishing this peer's external endpoint", e))?;

    let deadline = Instant::now() + wait;
    let peer = loop {
        if let Ok(text) = std::fs::read_to_string(theirs) {
            if let Ok(addr) = text.trim().parse::<SocketAddr>() {
                break Some(addr);
            }
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let Some(peer) = peer else {
        return Ok(report);
    };
    report.peer = Some(peer.to_string());
    sock.set_read_timeout(Some(Duration::from_millis(40)))
        .map_err(|e| NetError::os("tightening the p2p read timeout", e))?;

    // The simultaneous open, with peer-reflexive learning.
    //
    // Both sides send and listen in the same loop, which is what gives an
    // address-dependent filter its opening: each side's outbound packet writes
    // the other's address into its own middlebox's filter before the other's
    // packet arrives.
    //
    // **Why a packet from an unexpected port is still the peer.** A middlebox
    // with address-and-port-dependent mapping allocates a *different* external
    // port for the peer than the one the reflector reported, so the endpoint
    // published out of band is not the endpoint the peer's packets actually
    // arrive from. A puncher that only ever spoke to the published endpoint
    // would call that pair unreachable — and it is not: the unrestricted side
    // learns the true endpoint the moment the first packet lands, which is
    // exactly ICE's peer-reflexive candidate. Refusing to learn it here would
    // make this laboratory report `RELAY_EXPECTED` for pairs `docs/networking.md`
    // §3.2 marks `D`, and the disagreement would be the puncher's, not TwinVPN's.
    let mut targets: Vec<SocketAddr> = vec![peer];
    for _ in 0..rounds {
        for target in targets.clone() {
            if sock.send_to(b"PUNCH", target).is_ok() {
                report.sent += 1;
            }
        }
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            if from.ip() == peer.ip() && &buf[..n] == b"PUNCH" {
                report.received += 1;
                report.direct = true;
                if !targets.contains(&from) {
                    report.learned = Some(from.to_string());
                    targets.push(from);
                }
            }
        }
        std::thread::sleep(interval);
    }
    // A final drain, so the last round's answer is not missed by the loop having
    // ended one send early.
    let drain = Instant::now() + interval * 4;
    while Instant::now() < drain {
        match sock.recv_from(&mut buf) {
            Ok((n, from)) if from.ip() == peer.ip() && &buf[..n] == b"PUNCH" => {
                report.received += 1;
                report.direct = true;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }

    // The hold phase: keep the established path alive, touching nothing but the
    // two sockets. A scenario removes the rendezvous, the relay or the control
    // plane while this runs; what happens to `held_received` is the answer.
    if !hold.is_zero() {
        let until = Instant::now() + hold;
        while Instant::now() < until {
            for target in targets.clone() {
                if sock.send_to(b"PUNCH", target).is_ok() {
                    report.held_sent += 1;
                }
            }
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                if from.ip() == peer.ip() && &buf[..n] == b"PUNCH" {
                    report.held_received += 1;
                }
            }
            std::thread::sleep(interval);
        }
    }
    Ok(report)
}

/// What one impairment measurement observed.
///
/// §3.4.2's conformance row for the loss / duplication / reorder shim asks for
/// the *measured rate over a population* to be within tolerance of the
/// configured rate. That is a statement about sequence numbers, not about
/// whether a datagram came back, so this report carries the population rather
/// than a verdict.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MeasureReport {
    /// Datagrams sent.
    pub sent: u32,
    /// Datagrams received, duplicates included.
    pub received: u32,
    /// Distinct sequence numbers seen.
    pub unique: u32,
    /// Receipts beyond the first for a sequence number.
    pub duplicates: u32,
    /// Arrivals whose sequence number was lower than one already seen.
    pub out_of_order: u32,
    /// The smallest round trip, in microseconds.
    pub min_rtt_us: u64,
    /// The largest.
    pub max_rtt_us: u64,
    /// The median, which is what a latency assertion should read: one scheduling
    /// hiccup moves a mean and does not move a median.
    pub median_rtt_us: u64,
}

/// Sends `count` sequenced datagrams to an echo and reports what came back.
///
/// Every datagram is sent before any reply is collected, and the collection
/// phase then drains for `wait`. Sending and waiting in lockstep would serialise
/// the population behind the round trip and turn a 5 % loss measurement over 200
/// packets into a two-minute test.
///
/// # Errors
///
/// [`NetError::Os`] if the socket cannot be bound.
pub fn measure(
    bind_addr: SocketAddr,
    to: SocketAddr,
    count: u32,
    interval: Duration,
    wait: Duration,
) -> Result<MeasureReport> {
    let sock = UdpSocket::bind(bind_addr)
        .map_err(|e| NetError::os(format!("binding the measurement socket to {bind_addr}"), e))?;
    // Non-blocking for the send phase, and this is load-bearing rather than a
    // micro-optimisation. The first version drained with a 20 ms read timeout
    // after every send, so a nominally back-to-back population went out at
    // about 50 datagrams a second — below the rate of the 64 kbit/s shaper it
    // was supposed to be measuring. The shaper was in the path, was working,
    // and the measurement reported "no shaper in the path". A measurement whose
    // own pacing is slower than the thing it measures cannot see it.
    sock.set_nonblocking(true)
        .map_err(|e| NetError::os("making the measurement socket non-blocking", e))?;

    let mut report = MeasureReport {
        sent: 0,
        received: 0,
        unique: 0,
        duplicates: 0,
        out_of_order: 0,
        min_rtt_us: 0,
        max_rtt_us: 0,
        median_rtt_us: 0,
    };
    let mut sent_at: Vec<Option<Instant>> = vec![None; count as usize];
    let mut seen: Vec<u32> = vec![0; count as usize];
    let mut rtts: Vec<u64> = Vec::new();
    let mut highest: i64 = -1;
    let mut buf = [0u8; 2048];

    let drain = |sock: &UdpSocket,
                 buf: &mut [u8; 2048],
                 report: &mut MeasureReport,
                 sent_at: &[Option<Instant>],
                 seen: &mut [u32],
                 rtts: &mut Vec<u64>,
                 highest: &mut i64| {
        while let Ok((n, _)) = sock.recv_from(buf) {
            let text = String::from_utf8_lossy(&buf[..n]);
            let Some(seq) = text
                .strip_prefix("SEQ ")
                .and_then(|s| s.trim().parse::<u32>().ok())
            else {
                continue;
            };
            let Some(slot) = seen.get_mut(seq as usize) else {
                continue;
            };
            report.received += 1;
            if *slot == 0 {
                report.unique += 1;
                if let Some(Some(at)) = sent_at.get(seq as usize) {
                    rtts.push(at.elapsed().as_micros() as u64);
                }
                if i64::from(seq) < *highest {
                    report.out_of_order += 1;
                } else {
                    *highest = i64::from(seq);
                }
            } else {
                report.duplicates += 1;
            }
            *slot += 1;
        }
    };

    for seq in 0..count {
        let payload = format!("SEQ {seq}");
        if sock.send_to(payload.as_bytes(), to).is_ok() {
            report.sent += 1;
            sent_at[seq as usize] = Some(Instant::now());
        }
        drain(
            &sock,
            &mut buf,
            &mut report,
            &sent_at,
            &mut seen,
            &mut rtts,
            &mut highest,
        );
        if !interval.is_zero() {
            std::thread::sleep(interval);
        }
    }
    // The drain phase blocks, so waiting for the tail of a shaped or delayed
    // population does not spin a core for the duration.
    sock.set_nonblocking(false)
        .map_err(|e| NetError::os("returning the measurement socket to blocking", e))?;
    sock.set_read_timeout(Some(Duration::from_millis(10)))
        .map_err(|e| NetError::os("setting the measurement drain timeout", e))?;
    let until = Instant::now() + wait;
    while Instant::now() < until {
        drain(
            &sock,
            &mut buf,
            &mut report,
            &sent_at,
            &mut seen,
            &mut rtts,
            &mut highest,
        );
    }
    if !rtts.is_empty() {
        rtts.sort_unstable();
        report.min_rtt_us = rtts[0];
        report.max_rtt_us = rtts[rtts.len() - 1];
        report.median_rtt_us = rtts[rtts.len() / 2];
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip;

    #[test]
    fn an_encoded_query_is_one_this_laboratorys_own_parser_reads_back() {
        let q = encode_query("vpn.example.internal");
        let (name, qtype) = ip::dns_question(&q).expect("the parser must read the encoder");
        assert_eq!(name, "vpn.example.internal");
        assert_eq!(qtype, 1, "type A");
    }

    #[test]
    fn a_trailing_dot_does_not_become_an_empty_label() {
        let q = encode_query("example.com.");
        let (name, _) = ip::dns_question(&q).expect("a rooted name is still a name");
        assert_eq!(name, "example.com");
    }
}
