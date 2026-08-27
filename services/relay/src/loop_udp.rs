//! The `R-UDP` receive loop: the one place in this crate that `.await`s.
//!
//! **Authority:** ADR-0005 §11.1 (forwarding model), §11.5 (amplification).
//!
//! The loop holds **no policy**. It reads a datagram, calls the synchronous
//! [`Pump::step`], and writes at most one datagram. Every decision — parse, leg,
//! bind, MAC, counter, quota, shed — lives in that step, so all of it is testable
//! without a socket and none of it can acquire an `.await` by accident. That
//! split is the same I5 discipline `token::verify` and `RelayEngine` follow, at
//! the one boundary where I/O genuinely has to happen.
//!
//! `now_ms` comes from a caller-supplied `clock` rather than a clock read here
//! (`architecture.md` §5.2 R-DET-1), which is also what lets the loopback tests
//! drive timing deterministically.

#[cfg(test)]
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::net::UdpSocket;

use crate::crypto::RelayCrypto;
use crate::drr::TwoTierDrr;
use crate::engine::RelayEngine;
use crate::pump::{Action, LegRegistry, Pump};

/// The largest datagram the loop reads: header plus the derived payload ceiling.
///
/// A fixed buffer sized from [`crate::frame::MAX_DATA_PAYLOAD_BYTES`] is the
/// allocation bound on the highest-rate path (`ownership.md` §6 rule 10).
/// Anything larger is truncated by the kernel and then fails to parse — a silent
/// drop, which is what ADR-0005 §11.5 wants for a malformed frame anyway.
pub const RECV_BUFFER_BYTES: usize =
    crate::frame::HEADER_LEN + crate::frame::MAX_DATA_PAYLOAD_BYTES;

/// The mutable state one socket loop drives.
///
/// Shared behind a `Mutex` rather than a channel because every operation is a
/// short, non-blocking state transition: [`Pump::step`] does no I/O and never
/// `.await`s, so the lock is never held across a yield point.
pub struct RelayRuntime {
    /// The tables, limits and drain.
    pub engine: RelayEngine,
    /// The established legs. **Empty until a handshake exists** — see
    /// [`crate::pump`], which explains why and what that means operationally.
    pub legs: LegRegistry,
    /// The two-tier scheduler, on the forwarding path.
    pub scheduler: TwoTierDrr,
}

impl std::fmt::Debug for RelayRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayRuntime")
            .field("engine", &self.engine)
            .field("legs", &self.legs)
            .finish()
    }
}

/// Reads datagrams from `socket` and drives the pump until `shutdown` completes.
pub async fn serve_udp<F, S>(
    socket: Arc<UdpSocket>,
    runtime: Arc<Mutex<RelayRuntime>>,
    crypto: Arc<dyn RelayCrypto>,
    clock: F,
    shutdown: S,
) where
    F: Fn() -> u64 + Send + 'static,
    S: std::future::Future<Output = ()> + Send,
{
    let mut buf = vec![0_u8; RECV_BUFFER_BYTES];
    tokio::pin!(shutdown);
    loop {
        let received = tokio::select! {
            () = &mut shutdown => return,
            r = socket.recv_from(&mut buf) => r,
        };
        let Ok((len, from)) = received else {
            // A UDP read error is per-datagram (an ICMP error mapped back,
            // typically). It is not a reason to stop serving every other peer.
            continue;
        };

        let action = {
            let Ok(mut rt) = runtime.lock() else {
                return;
            };
            let RelayRuntime {
                engine,
                legs,
                scheduler,
            } = &mut *rt;
            let mut pump = Pump {
                engine,
                legs,
                scheduler,
                crypto: crypto.as_ref(),
            };
            pump.step(from, Bytes::copy_from_slice(&buf[..len]), clock())
        };

        // At most one datagram, to exactly one peer. `Action` cannot express more.
        if let Action::Send { to, datagram } = action {
            let _ = socket.send_to(&datagram, to).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelayConfig;
    use crate::crypto::FailClosed;
    use crate::issuer::IssuerKeySet;
    use twinvpn_service_common::config::MapEnv;

    fn relay_config() -> RelayConfig {
        RelayConfig::load(
            &MapEnv::new()
                .with("TWINVPN_RELAY_ID", "0000000000000a01")
                .with("TWINVPN_RELAY_REGION", "local-1")
                .with("TWINVPN_RELAY_FAILURE_DOMAIN", "fd-a")
                .with("TWINVPN_RELAY_OPERATOR_GROUP_ID", "local-operator")
                .with(
                    "TWINVPN_RELAY_ISSUER_KEYS_PATH",
                    concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
                )
                .with(
                    "TWINVPN_RELAY_STATIC_KEY_PATH",
                    concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
                ),
        )
        .expect("loads")
    }

    fn empty_issuers() -> IssuerKeySet {
        IssuerKeySet::parse(
            r#"{"operator_group_id":"local-operator","issuers":[]}"#,
            "local-operator",
            "x",
        )
        .expect("parses")
    }

    fn runtime() -> Arc<Mutex<RelayRuntime>> {
        Arc::new(Mutex::new(RelayRuntime {
            engine: RelayEngine::new(relay_config(), empty_issuers(), 0),
            legs: LegRegistry::new(1_024),
            scheduler: TwoTierDrr::with_default_quantum(),
        }))
    }

    type Started = (
        SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    );

    async fn start_on(bind: &str) -> Started {
        let socket = Arc::new(UdpSocket::bind(bind).await.expect("relay socket"));
        let addr = socket.local_addr().expect("addr");
        let (tx, rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(serve_udp(
            socket,
            runtime(),
            Arc::new(FailClosed),
            || 0,
            async move {
                let _ = rx.await;
            },
        ));
        (addr, tx, handle)
    }

    /// Sends `datagram` to a running relay and waits briefly for any reply.
    async fn probe(bind: &str, relay: SocketAddr, datagram: &[u8]) -> Option<Vec<u8>> {
        let client = UdpSocket::bind(bind).await.expect("client socket");
        client.send_to(datagram, relay).await.expect("send");
        let mut buf = vec![0_u8; RECV_BUFFER_BYTES];
        match tokio::time::timeout(
            std::time::Duration::from_millis(150),
            client.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
            _ => None,
        }
    }

    #[tokio::test]
    async fn a_real_relay_answers_unsolicited_input_with_zero_bytes() {
        // ADR-0005 §11.5's amplification claim, MEASURED over a real socket
        // rather than argued: the relay "emits ZERO BYTES in response to any
        // unauthenticated or unbound frame".
        let (addr, stop, handle) = start_on("[::1]:0").await;

        for datagram in [
            vec![],
            b"not a relay frame at all".to_vec(),
            // A well-formed DATA frame from a source with no leg.
            vec![
                0x01, 0x10, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0xC3, 0xC3,
            ],
            // A well-formed leg PING from a source with no leg.
            vec![0x12, 0x10, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            // A BIND.
            vec![0x10, 0x10, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            // Oversized: over the derived payload ceiling.
            vec![0xFF; 2_000],
        ] {
            let reply = probe("[::1]:0", addr, &datagram).await;
            assert!(
                reply.is_none(),
                "the relay answered {} bytes of unsolicited input with {:?} bytes",
                datagram.len(),
                reply.map(|r| r.len())
            );
        }

        let _ = stop.send(());
        let _ = handle.await;
    }

    #[tokio::test]
    async fn the_loop_survives_a_flood_and_still_stops_cleanly() {
        let (addr, stop, handle) = start_on("[::1]:0").await;
        let client = UdpSocket::bind("[::1]:0").await.expect("client");
        for n in 0..200_u16 {
            let mut junk = vec![0_u8; 64];
            junk[0] = u8::try_from(n % 251).unwrap_or(0);
            let _ = client.send_to(&junk, addr).await;
        }
        let mut buf = [0_u8; 64];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(150),
                client.recv_from(&mut buf)
            )
            .await
            .is_err(),
            "the relay answered a garbage flood"
        );

        let _ = stop.send(());
        tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("the loop stops on its shutdown future")
            .expect("no panic");
    }

    #[tokio::test]
    async fn the_loop_runs_on_ipv4_as_well_as_ipv6() {
        let (addr, stop, handle) = start_on("127.0.0.1:0").await;
        assert!(addr.is_ipv4());
        assert!(probe("127.0.0.1:0", addr, b"garbage").await.is_none());
        let _ = stop.send(());
        let _ = handle.await;
    }

    #[tokio::test]
    async fn the_receive_buffer_is_bounded_by_the_derived_payload_ceiling() {
        assert_eq!(
            RECV_BUFFER_BYTES,
            crate::frame::HEADER_LEN + crate::frame::MAX_DATA_PAYLOAD_BYTES
        );
        assert_eq!(RECV_BUFFER_BYTES, 1_472);
    }
}
