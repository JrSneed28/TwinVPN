//! A forwarder, and a peer that can fail over between forwarders.
//!
//! **Why the laboratory has a relay of its own.** `docs/networking.md` §3.2
//! declares four cells **relay by design** — APDM↔APDM and CGNAT↔CGNAT over
//! IPv4 — and `docs/reliability.md` makes relay failover a first-class recovery
//! path. A laboratory that could produce those conditions and had nothing to
//! fall back *to* could assert that direct traversal failed and nothing about
//! what happened next.
//!
//! **What this is not.** It is not `twinvpn-relay`. It carries no
//! `RelayCapabilityToken`, verifies no COSE signature, derives no `K_leg` and
//! implements none of ADR-0005's framing. Its whole vocabulary is `BIND <tag>`
//! and "forward this to the other endpoint under that tag". Anything that needs
//! the real relay's admission, cryptography or wire belongs against the real
//! relay binary — `lab/twinsim` is that, and it says so.
//!
//! What this *is* is the topological fact a fallback scenario needs: a
//! forwarder on the public Internet that two peers behind symmetric NATs can
//! both reach, whose death is observable, and which has a standby.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::error::{NetError, Result};

/// The bind verb.
pub const BIND: &str = "BIND";
/// The acknowledgement.
pub const BOUND: &str = "BOUND";

/// Runs a forwarder until `duration` elapses.
///
/// # Errors
///
/// [`NetError::Os`] if the socket cannot be bound.
pub fn serve(bind: SocketAddr, duration: Duration) -> Result<()> {
    let sock = UdpSocket::bind(bind)
        .map_err(|e| NetError::os(format!("binding the relay to {bind}"), e))?;
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|e| NetError::os("setting the relay read timeout", e))?;
    // Two endpoints per tag. A third binder replaces the older of the two, which
    // is what makes a client restart under the same tag resume rather than be
    // refused — the behaviour a restart scenario needs, stated rather than
    // stumbled into.
    let mut legs: HashMap<String, Vec<SocketAddr>> = HashMap::new();
    let started = Instant::now();
    let mut buf = [0u8; 65_536];
    while started.elapsed() < duration {
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            continue;
        };
        let text = String::from_utf8_lossy(&buf[..n.min(64)]);
        if let Some(tag) = text.strip_prefix(&format!("{BIND} ")) {
            let tag = tag.split_whitespace().next().unwrap_or("").to_owned();
            let entry = legs.entry(tag).or_default();
            entry.retain(|a| *a != from);
            entry.push(from);
            if entry.len() > 2 {
                entry.remove(0);
            }
            let _ = sock.send_to(BOUND.as_bytes(), from);
            continue;
        }
        // A data frame: forward it to the other endpoint under whichever tag
        // this sender is bound to.
        if let Some(peer) = legs
            .values()
            .find(|v| v.contains(&from))
            .and_then(|v| v.iter().find(|a| **a != from))
        {
            let _ = sock.send_to(&buf[..n], *peer);
        }
    }
    Ok(())
}

/// What one relayed peer observed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayedReport {
    /// The relay this peer ended up bound to, if any.
    pub relay: Option<String>,
    /// How many relays were tried before one answered. The failover evidence.
    pub attempts: u32,
    /// Whether the bind was acknowledged.
    pub bound: bool,
    /// Datagrams sent through the relay.
    pub sent: u32,
    /// Datagrams received through it.
    pub received: u32,
}

/// Binds to the first relay that answers and exchanges traffic through it.
///
/// `relays` is tried in order. That ordering is the scenario's, not a policy:
/// ADR-0006's ranking is the product's job and re-deriving it here would make
/// a failover result a statement about this file.
///
/// # Errors
///
/// [`NetError::Os`] if the socket cannot be bound.
pub fn relayed(
    relays: &[SocketAddr],
    tag: &str,
    rounds: u32,
    interval: Duration,
    bind_wait: Duration,
) -> Result<RelayedReport> {
    let bind: SocketAddr = if relays.first().is_some_and(SocketAddr::is_ipv4) {
        "0.0.0.0:0".parse().expect("a literal")
    } else {
        "[::]:0".parse().expect("a literal")
    };
    let sock = UdpSocket::bind(bind).map_err(|e| NetError::os("binding a relayed peer", e))?;
    sock.set_read_timeout(Some(bind_wait))
        .map_err(|e| NetError::os("setting the relayed peer's read timeout", e))?;

    let mut report = RelayedReport {
        relay: None,
        attempts: 0,
        bound: false,
        sent: 0,
        received: 0,
    };
    let mut buf = [0u8; 65_536];
    let mut chosen = None;
    'relays: for relay in relays {
        report.attempts += 1;
        // Two attempts per relay. A relay that is merely slow must not be
        // mistaken for one that is down: the whole point of the failover
        // scenarios is that "this relay is gone" is a conclusion the client
        // reached, and a conclusion reached from one lost datagram is a flake
        // wearing a failover's clothes.
        for _ in 0..2 {
            let _ = sock.send_to(format!("{BIND} {tag}").as_bytes(), relay);
            if let Ok((n, from)) = sock.recv_from(&mut buf) {
                if from == *relay && &buf[..n] == BOUND.as_bytes() {
                    report.bound = true;
                    report.relay = Some(relay.to_string());
                    chosen = Some(*relay);
                    break 'relays;
                }
            }
        }
    }
    let Some(relay) = chosen else {
        return Ok(report);
    };
    sock.set_read_timeout(Some(Duration::from_millis(40)))
        .map_err(|e| NetError::os("tightening the relayed peer's read timeout", e))?;
    for _ in 0..rounds {
        if sock.send_to(b"PUNCH", relay).is_ok() {
            report.sent += 1;
        }
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            if from == relay && &buf[..n] == b"PUNCH" {
                report.received += 1;
            }
        }
        std::thread::sleep(interval);
    }
    let drain = Instant::now() + interval * 4;
    while Instant::now() < drain {
        match sock.recv_from(&mut buf) {
            Ok((n, from)) if from == relay && &buf[..n] == b"PUNCH" => report.received += 1,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    Ok(report)
}
