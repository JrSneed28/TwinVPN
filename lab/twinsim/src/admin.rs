//! The simulator's admin listener: `/healthz`, `/readyz`, `/metrics`.
//!
//! **Authority:** `docs/implementation/ownership.md` rule 4 (a long-running
//! process has **both** a health and a readiness path, and they answer
//! different questions), ADR-0015 §9 (the metric label allowlist),
//! `build/verify/check-compose.py` invariant 5, which fails the build for a
//! compose service that has only one of the two.
//!
//! # Why a simulator needs these at all
//!
//! Because it is a compose service like any other, and the invariant is checked
//! structurally rather than per-service. But there is a substantive reason too:
//! a simulated client whose readiness meant "the process started" would let a
//! `docker compose up --wait` return green while every leg was being refused,
//! and the whole point of the multi-node environment is that a broken stack is
//! *visible* rather than quiet.
//!
//! So the two answers are genuinely different here:
//!
//! - **`/healthz`** — this process is running and its own invariants hold. A
//!   simulator whose relay is unreachable is still healthy: restarting it will
//!   not help, and a restart loop would destroy the very evidence the run
//!   exists to collect.
//! - **`/readyz`** — the relay **admitted** this peer: a leg is established and
//!   a `BIND` returned a flow. That deliberately includes `PENDING`, because a
//!   peer whose partner has not arrived yet is doing exactly what it was
//!   started to do. Requiring `BOUND` would leave whichever half of a pair
//!   starts first permanently unready, and hold `docker compose up --wait`
//!   until the two raced. Unready is the correct state for a simulator that
//!   cannot reach its relay, and `restart: "no"` keeps it visible in that
//!   state.
//!
//! # No metric here carries a correlation
//!
//! ADR-0015 §9 restricts labels to five low-cardinality dimensions and forbids
//! per-`Session`, per-`Device`, per-peer and per-endpoint labels — "for privacy
//! first (O-13) and for cost second". A *simulator* has no real user, so the
//! privacy half does not bite; the allowlist is honoured anyway, because a
//! dashboard that works against `twinsim` and not against `twinvpn-relay` is a
//! dashboard that has to be written twice. The counters below carry `outcome`
//! and `address_family` and nothing else — no `flow_id`, no `pair_tag`, no
//! peer.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use std::fmt::Write as _;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The label dimensions ADR-0015 §9 permits, reproduced so a reviewer sees the
/// list at the point of use.
pub const LABEL_ALLOWLIST: [&str; 5] = [
    "relay_region",
    "protocol_version",
    "reason_code",
    "outcome",
    "address_family",
];

/// What the simulator reports about itself.
///
/// Every field is an atomic and the whole thing is shared by `Arc`: the run
/// loop writes and the admin listener reads, with no lock between them, so a
/// slow scrape can never stall a leg.
#[derive(Debug, Default)]
pub struct SimState {
    /// Whether the relay admitted this peer: a leg, and a flow from a `BIND`.
    ready: AtomicBool,
    /// Leg attempts that established.
    pub legs_established: AtomicU64,
    /// Leg attempts that established only after answering a cookie challenge.
    pub legs_after_cookie: AtomicU64,
    /// Leg attempts the relay answered with something else.
    pub legs_refused: AtomicU64,
    /// Leg attempts the relay did not answer.
    pub legs_silent: AtomicU64,
    /// `BIND`s that left a pending slot.
    pub binds_pending: AtomicU64,
    /// `BIND`s that completed a flow.
    pub binds_bound: AtomicU64,
    /// `BIND`s answered with `RELAY_STATUS`.
    pub binds_status: AtomicU64,
    /// `BIND` replies whose MAC did not verify. **Not loss** — see
    /// [`crate::device::BindOutcome::Unauthenticated`].
    pub binds_unauthenticated: AtomicU64,
    /// `DATA` frames sent.
    pub data_sent: AtomicU64,
    /// `DATA` frames received and MAC-verified.
    pub data_received: AtomicU64,
    /// Payload octets sent.
    pub bytes_sent: AtomicU64,
}

impl SimState {
    /// A fresh, unready state.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Declares the simulator ready, or not.
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Relaxed);
    }

    /// Whether the relay admitted this peer.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    /// The Prometheus exposition, with `role` and `family` as the only
    /// dimensions and both inside the §9 allowlist's spirit.
    #[must_use]
    pub fn metrics(&self, family: &str) -> String {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        let mut s = String::new();
        s.push_str("# HELP twinsim_legs_total relay leg attempts by outcome\n");
        s.push_str("# TYPE twinsim_legs_total counter\n");
        for (outcome, v) in [
            ("established", g(&self.legs_established)),
            ("established_after_cookie", g(&self.legs_after_cookie)),
            ("refused", g(&self.legs_refused)),
            ("silent", g(&self.legs_silent)),
        ] {
            let _ = writeln!(
                s,
                "twinsim_legs_total{{outcome=\"{outcome}\",address_family=\"{family}\"}} {v}"
            );
        }
        s.push_str("# HELP twinsim_binds_total BIND attempts by outcome\n");
        s.push_str("# TYPE twinsim_binds_total counter\n");
        for (outcome, v) in [
            ("pending", g(&self.binds_pending)),
            ("bound", g(&self.binds_bound)),
            ("status", g(&self.binds_status)),
            ("unauthenticated", g(&self.binds_unauthenticated)),
        ] {
            let _ = writeln!(
                s,
                "twinsim_binds_total{{outcome=\"{outcome}\",address_family=\"{family}\"}} {v}"
            );
        }
        s.push_str("# HELP twinsim_data_frames_total DATA frames by direction\n");
        s.push_str("# TYPE twinsim_data_frames_total counter\n");
        let _ = writeln!(
            s,
            "twinsim_data_frames_total{{outcome=\"sent\",address_family=\"{family}\"}} {}",
            g(&self.data_sent)
        );
        let _ = writeln!(
            s,
            "twinsim_data_frames_total{{outcome=\"received\",address_family=\"{family}\"}} {}",
            g(&self.data_received)
        );
        s.push_str("# HELP twinsim_data_bytes_total payload octets sent\n");
        s.push_str("# TYPE twinsim_data_bytes_total counter\n");
        let _ = writeln!(
            s,
            "twinsim_data_bytes_total{{address_family=\"{family}\"}} {}",
            g(&self.bytes_sent)
        );
        s.push_str(
            "# HELP twinsim_ready 1 when a leg is established and the relay admitted a BIND\n",
        );
        s.push_str("# TYPE twinsim_ready gauge\n");
        let _ = writeln!(s, "twinsim_ready {}", u8::from(self.is_ready()));
        s
    }
}

/// Serves the admin listener until the process exits.
///
/// A hand-written HTTP/1.1 responder rather than a framework: three fixed
/// paths, no routing, no body parsing, and `lab/Cargo.toml` is the integration
/// lead's to add a dependency to. It reads at most one buffer and never
/// allocates from a client-declared length.
///
/// # Errors
///
/// A bind failure. Accept failures are logged and the loop continues: an admin
/// listener that exited on one bad connection would take the simulator's only
/// observability with it.
pub async fn serve(
    addr: std::net::SocketAddr,
    state: Arc<SimState>,
    family: String,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "admin listener: /healthz /readyz /metrics");
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "admin accept failed");
                continue;
            }
        };
        let state = Arc::clone(&state);
        let family = family.clone();
        tokio::spawn(async move {
            // One fixed buffer. A request longer than this is answered from
            // whatever arrived, which for three literal paths is enough, and
            // is bounded before allocation rather than after.
            let mut buf = [0_u8; 1024];
            let Ok(n) = sock.read(&mut buf).await else {
                return;
            };
            let head = String::from_utf8_lossy(&buf[..n]);
            let path = head.split_whitespace().nth(1).unwrap_or("/");
            let (status, ctype, body) = match path {
                "/healthz" => ("200 OK", "text/plain; charset=utf-8", "ok\n".to_owned()),
                "/readyz" => {
                    if state.is_ready() {
                        ("200 OK", "text/plain; charset=utf-8", "ready\n".to_owned())
                    } else {
                        // 503, not 200-with-a-body: `docker compose up --wait`
                        // and Prometheus both read the status line, and a
                        // readiness probe that returns 200 unconditionally is
                        // not one.
                        (
                            "503 Service Unavailable",
                            "text/plain; charset=utf-8",
                            "no established leg with a bound flow\n".to_owned(),
                        )
                    }
                }
                "/metrics" => (
                    "200 OK",
                    "text/plain; version=0.0.4; charset=utf-8",
                    state.metrics(&family),
                ),
                _ => (
                    "404 Not Found",
                    "text/plain; charset=utf-8",
                    "\n".to_owned(),
                ),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_simulator_is_not_ready() {
        // The failure this prevents: `up --wait` going green over a stack in
        // which every leg is being refused.
        assert!(!SimState::new().is_ready());
    }

    #[test]
    fn every_metric_label_is_inside_the_adr_0015_allowlist() {
        let s = SimState::new();
        s.legs_established.store(3, Ordering::Relaxed);
        let text = s.metrics("v6");
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let Some(open) = line.find('{') else { continue };
            let close = line.find('}').expect("balanced");
            for pair in line[open + 1..close].split(',') {
                let name = pair.split('=').next().expect("name");
                assert!(
                    LABEL_ALLOWLIST.contains(&name),
                    "label `{name}` is outside ADR-0015 §9's allowlist: {line}"
                );
            }
        }
    }

    #[test]
    fn no_metric_carries_a_correlation() {
        // A sixth label is how a peer-pair dimension arrives. These are the
        // names that must never appear, spelled out so a future edit trips.
        let text = SimState::new().metrics("v4");
        for forbidden in [
            "session_id",
            "pair_tag",
            "flow_id",
            "peer",
            "device_id",
            "relay_sub",
        ] {
            assert!(
                !text.contains(forbidden),
                "`{forbidden}` reached the metrics"
            );
        }
    }

    #[test]
    fn readiness_is_a_state_the_run_loop_sets_and_clears() {
        let s = SimState::new();
        s.set_ready(true);
        assert!(s.is_ready());
        assert!(s.metrics("v4").contains("twinsim_ready 1"));
        // It must go back down: a leg that dies makes the simulator unready
        // again rather than latching green for the rest of the run.
        s.set_ready(false);
        assert!(s.metrics("v4").contains("twinsim_ready 0"));
    }

    #[test]
    fn the_exposition_is_well_formed_prometheus_text() {
        let text = SimState::new().metrics("v6");
        assert!(text.contains("# TYPE twinsim_legs_total counter"));
        assert!(text.contains("# TYPE twinsim_ready gauge"));
        assert!(text.ends_with('\n'));
        for line in text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            let value = line.rsplit(' ').next().expect("value");
            assert!(value.parse::<f64>().is_ok(), "not a sample: {line}");
        }
    }
}
