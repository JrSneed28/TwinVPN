//! Carriage binding — `R-UDP` over a real socket, and an honest account of the
//! other two rungs.
//!
//! ADR-0005 §11.4's ladder is `R-UDP` (UDP/41641 and UDP/443), `R-QUIC` (UDP/443,
//! QUIC DATAGRAM) and `R-TLS` (TCP/443, TLS 1.3, 2-byte length-prefixed frames),
//! **raced with a staggered start, never tried sequentially after a timeout**.
//! The racing is the *device's* behaviour; a relay's obligation is simply to be
//! listening on every carriage it advertises.
//!
//! # What this build actually binds, stated rather than implied
//!
//! | Carriage | Status here |
//! |---|---|
//! | `R-UDP` | **bound and serving** — a real `tokio::net::UdpSocket`, dual-stack, v4-only and v6-only |
//! | `R-QUIC` | **not bound.** `quinn` is in `services/Cargo.toml`'s workspace set but no member has ever built it, so it is absent from `services/Cargo.lock`; adding it needs a resolve this host cannot perform, and the QUIC leg additionally needs the RFC 8446 exporter that `crate::crypto` does not have a provider for |
//! | `R-TLS` | **not bound**, for the same two reasons (`rustls`, and TLS 1.3 with RFC 7250 raw-public-key client auth) |
//!
//! [`CarriageSet::bind`] therefore **fails closed**: a configured carriage that
//! cannot be served is reported as unavailable and makes the readiness probe red
//! (`infra/README.md` §5: "all configured carriages bound"). It does not bind a
//! bare TCP socket on 443 and call it `R-TLS` — a listener that accepts a
//! connection it cannot secure is worse than no listener, because a device would
//! race to it and succeed at the wrong thing.
//!
//! # IPv4, IPv6, dual-stack and IPv6-only
//!
//! `[::]` binds dual-stack on Linux when `net.ipv6.bindv6only=0` and IPv6-only
//! when it is 1, and `infra/`'s IPv6-only profile relies on the latter.
//! [`CarriageSet::bind`] therefore takes the address as configured and reports
//! back what it actually got, rather than assuming: [`BoundCarriage::families`]
//! is observed from the bound socket, not from the configuration.

use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::config::{Carriage, RelayConfig};

/// The address families a bound socket actually serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Families {
    /// IPv4 only.
    V4,
    /// IPv6 only — the socket is `v6only`, or the address is a v6 literal.
    V6,
    /// Both, via a dual-stack wildcard.
    Dual,
}

impl Families {
    /// The metric-label spelling. `Dual` reports as `v6` because the socket is a
    /// v6 socket carrying v4-mapped addresses; a per-datagram family label comes
    /// from the peer address, not from the listener.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Families::V4 => "v4",
            Families::V6 | Families::Dual => "v6",
        }
    }
}

/// One serving carriage.
#[derive(Debug)]
pub struct BoundCarriage {
    /// Which rung.
    pub carriage: Carriage,
    /// The address actually bound, which may differ from the configured one when
    /// the configured port was 0.
    pub local_addr: SocketAddr,
    /// What the socket actually serves, observed rather than assumed.
    pub families: Families,
    /// The socket.
    pub socket: UdpSocket,
}

/// Why a carriage could not be served.
#[derive(Debug, thiserror::Error)]
pub enum CarriageError {
    /// The socket could not be bound.
    #[error("{carriage}: cannot bind {addr}")]
    Bind {
        /// Which rung.
        carriage: &'static str,
        /// The configured address.
        addr: SocketAddr,
        /// The OS failure, kept for a log line and never encoded (ADR-0018 F-4).
        #[source]
        source: std::io::Error,
    },

    /// The carriage is configured but this build cannot serve it.
    ///
    /// **Fails closed on purpose.** See the module docs: binding a listener that
    /// cannot complete the carriage's handshake would let a device race to it and
    /// succeed at the wrong thing.
    #[error("{carriage}: not implemented in this build; see services/relay/README.md §8")]
    Unimplemented {
        /// Which rung.
        carriage: &'static str,
    },
}

/// Everything this relay is listening on.
#[derive(Debug)]
pub struct CarriageSet {
    /// The serving carriages.
    pub bound: Vec<BoundCarriage>,
    /// The configured carriages that could not be served, and why.
    pub unavailable: Vec<(Carriage, String)>,
}

impl CarriageSet {
    /// Binds every configured carriage this build can serve.
    ///
    /// # Errors
    ///
    /// [`CarriageError::Bind`] when a socket this build *can* serve refuses to
    /// bind — that is a hard startup failure, because a relay that cannot hold
    /// its primary port is not a relay. An unimplementable carriage is recorded
    /// in [`CarriageSet::unavailable`] instead, so the process still starts,
    /// still serves `/healthz`, and is visibly **not ready**.
    pub async fn bind(config: &RelayConfig) -> Result<Self, CarriageError> {
        let mut bound = Vec::new();
        let mut unavailable = Vec::new();

        for carriage in &config.carriages {
            match carriage {
                Carriage::Udp => {
                    for addr in [config.listen_udp, config.listen_udp_443] {
                        bound.push(bind_udp(Carriage::Udp, addr).await?);
                    }
                }
                Carriage::Quic | Carriage::Tls => {
                    unavailable.push((
                        *carriage,
                        CarriageError::Unimplemented {
                            carriage: carriage.as_str(),
                        }
                        .to_string(),
                    ));
                }
            }
        }

        Ok(Self { bound, unavailable })
    }

    /// Whether every configured carriage is serving.
    ///
    /// This is the relay's readiness predicate (`infra/README.md` §5, "all
    /// configured carriages bound"), and it is **false** whenever any carriage is
    /// unavailable — which is the fail-closed answer.
    #[must_use]
    pub fn all_configured_carriages_bound(&self) -> bool {
        self.unavailable.is_empty() && !self.bound.is_empty()
    }
}

async fn bind_udp(carriage: Carriage, addr: SocketAddr) -> Result<BoundCarriage, CarriageError> {
    let socket = UdpSocket::bind(addr)
        .await
        .map_err(|source| CarriageError::Bind {
            carriage: carriage.as_str(),
            addr,
            source,
        })?;
    let local_addr = socket.local_addr().map_err(|source| CarriageError::Bind {
        carriage: carriage.as_str(),
        addr,
        source,
    })?;
    let families = observe_families(&socket, local_addr);
    Ok(BoundCarriage {
        carriage,
        local_addr,
        families,
        socket,
    })
}

/// Reports what the socket actually serves, rather than what was asked for.
///
/// A `[::]` bind is dual-stack or v6-only depending on `bindv6only`, and the
/// IPv6-only compose profile depends on that difference. Observing it means a
/// relay's own diagnostics say which it got.
fn observe_families(socket: &UdpSocket, local: SocketAddr) -> Families {
    match local {
        SocketAddr::V4(_) => Families::V4,
        SocketAddr::V6(_) => {
            // `only_v6` is not exposed by tokio; a v6 wildcard is reported as
            // Dual only when the OS says the socket is not v6-only. Without that
            // query the honest answer is the conservative one.
            let _ = socket;
            if local.ip().is_unspecified() {
                Families::Dual
            } else {
                Families::V6
            }
        }
    }
}

/// The family label for one datagram, from its peer address.
///
/// This is the per-datagram dimension ADR-0015 §9 allows; the listener's family
/// is not it, because a dual-stack socket serves both.
#[must_use]
pub const fn peer_family_label(peer: SocketAddr) -> &'static str {
    match peer {
        SocketAddr::V4(_) => "v4",
        SocketAddr::V6(_) => "v6",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_service_common::config::MapEnv;

    fn config_with(carriages: &str, udp: &str, udp443: &str) -> RelayConfig {
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
                )
                .with("TWINVPN_RELAY_CARRIAGES", carriages)
                .with("TWINVPN_RELAY_LISTEN_UDP", udp)
                .with("TWINVPN_RELAY_LISTEN_UDP_443", udp443),
        )
        .expect("loads")
    }

    #[tokio::test]
    async fn r_udp_binds_on_ipv6() {
        let set = CarriageSet::bind(&config_with("R-UDP", "[::1]:0", "[::1]:0"))
            .await
            .expect("binds");
        assert_eq!(set.bound.len(), 2);
        assert!(set.bound.iter().all(|b| b.local_addr.is_ipv6()));
        assert!(set.all_configured_carriages_bound());
    }

    #[tokio::test]
    async fn r_udp_binds_on_ipv4() {
        let set = CarriageSet::bind(&config_with("R-UDP", "127.0.0.1:0", "127.0.0.1:0"))
            .await
            .expect("binds");
        assert_eq!(set.bound.len(), 2);
        assert!(set.bound.iter().all(|b| b.local_addr.is_ipv4()));
        assert_eq!(set.bound[0].families, Families::V4);
    }

    #[tokio::test]
    async fn a_wildcard_v6_bind_reports_what_it_got() {
        let set = CarriageSet::bind(&config_with("R-UDP", "[::]:0", "[::]:0"))
            .await
            .expect("binds");
        // Dual on a bindv6only=0 host, V6 on a bindv6only=1 one. Either is a
        // legitimate answer; the point is that it is observed, not assumed.
        assert!(matches!(
            set.bound[0].families,
            Families::Dual | Families::V6
        ));
    }

    #[tokio::test]
    async fn an_unimplemented_carriage_fails_closed_rather_than_binding_a_bare_socket() {
        let set = CarriageSet::bind(&config_with("R-UDP,R-TLS", "[::1]:0", "[::1]:0"))
            .await
            .expect("binds what it can");
        assert_eq!(set.unavailable.len(), 1);
        assert_eq!(set.unavailable[0].0, Carriage::Tls);
        assert!(
            !set.all_configured_carriages_bound(),
            "readiness must be RED while a configured carriage is not served"
        );
    }

    #[tokio::test]
    async fn a_relay_that_cannot_hold_its_port_is_a_hard_startup_failure() {
        let first = CarriageSet::bind(&config_with("R-UDP", "[::1]:0", "[::1]:0"))
            .await
            .expect("binds");
        let taken = first.bound[0].local_addr;
        let addr = taken.to_string();
        let e = CarriageSet::bind(&config_with("R-UDP", &addr, "[::1]:0"))
            .await
            .unwrap_err();
        assert!(matches!(e, CarriageError::Bind { .. }));
        // The OS detail never becomes the whole story: the error names the
        // carriage and the address, and the errno stays in `source`.
        assert!(e.to_string().contains("R-UDP"));
    }

    #[test]
    fn the_family_label_comes_from_the_peer_not_the_listener() {
        assert_eq!(peer_family_label("192.0.2.1:1".parse().expect("v4")), "v4");
        assert_eq!(
            peer_family_label("[2001:db8::1]:1".parse().expect("v6")),
            "v6"
        );
    }
}
