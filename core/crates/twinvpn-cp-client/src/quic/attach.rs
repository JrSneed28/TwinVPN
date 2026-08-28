//! Attaching: the rung-1 budget, Happy Eyeballs v2, and ADR-0002 N-1.
//!
//! **Authority:** ADR-0002 §11.2 (the per-rung budget: rung 1 is 3 s), **N-1**
//! (one connection per device carrying both C1 and C2), §11.7 (reconnect
//! discipline), `docs/protocol.md` §4.1 (Happy Eyeballs v2 with a 250 ms IPv6
//! bias), ADR-0010 **R1**, ADR-0001 **R8** (0-RTT prohibited).
//!
//! Split out of [`super`] so the configuration this transport is *built* with
//! and the race it *runs* are readable separately: the first is a security
//! surface — pins, identity, TLS versions, early data — and the second is a
//! timing one, and reviewing them together is how a detail in one gets read as
//! a detail in the other.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures_util::future::{select, Either};

use super::{candidates, connection, ControlEndpoint, Live, QuicConnection, QuicControlTransport};
use crate::transport::{AttachFamilies, EarlyData, Rung, TransportConfig, TransportError};

/// Handshake failures.
fn map_handshake_error(err: &quinn::ConnectionError) -> TransportError {
    match err {
        // A TLS alert reaches us as a close or a transport error: the server
        // refusing this identity, or us refusing its pin. Anything else is the
        // path. The mapped value deliberately says only "rejected" — a client
        // must not turn a server's refusal into a diagnosis.
        quinn::ConnectionError::ConnectionClosed(_) | quinn::ConnectionError::TransportError(_) => {
            TransportError::HandshakeRejected
        }
        _ => TransportError::RungFailed(Rung::Quic),
    }
}

impl QuicControlTransport {
    /// Attaches, returning the concrete connection.
    ///
    /// # Errors
    ///
    /// [`TransportError::RungFailed`] when no candidate came up inside rung 1's
    /// budget, and [`TransportError::HandshakeRejected`] when a candidate
    /// completed a handshake attempt and it was refused — an unknown device key
    /// on the server's side, or a **pin mismatch** on ours. The two are kept
    /// apart because an operator does different things about them.
    pub async fn attach_quic(
        &self,
        config: &TransportConfig,
    ) -> Result<QuicConnection, TransportError> {
        config
            .admissible()
            .map_err(|_| TransportError::RungFailed(config.rung))?;
        if config.rung != Rung::Quic {
            return Err(TransportError::RungFailed(config.rung));
        }
        // 0-RTT, control 1 of 3. Uninhabitable today by construction; it is
        // here so that adding a variant to `EarlyData` fails at this line.
        match config.early_data() {
            EarlyData::Prohibited => {}
        }

        let client = self.client_config(config.mobile_background);
        let budget = self.env.timer().sleep(Rung::Quic.budget());
        let ladder = Box::pin(self.walk_endpoints(config, &client));
        let attached = match select(ladder, budget).await {
            Either::Left((result, _)) => result?,
            // ADR-0002 §11.2's per-rung budget. Rung 1 is 3 s, and the ladder
            // above falls through to rung 2 — this is not a terminal failure.
            Either::Right(((), _)) => return Err(TransportError::RungFailed(Rung::Quic)),
        };

        let superseded = Arc::new(AtomicBool::new(false));
        self.supersede_previous(&attached.1, &superseded);
        tracing::debug!(
            rung = Rung::Quic.number(),
            peer_is_ipv6 = attached.1.remote_address().is_ipv6(),
            "L-CONTROL attached"
        );
        Ok(QuicConnection::new(attached.0, attached.1, superseded))
    }

    /// ADR-0002 N-1: **one** connection per device, carrying both C1 and C2.
    ///
    /// A second attach closes the first rather than running two, and the holder
    /// of the older handle is told `Superseded` rather than a generic close —
    /// the two need different responses, because a supersession needs no
    /// reattach.
    fn supersede_previous(&self, fresh: &quinn::Connection, flag: &Arc<AtomicBool>) {
        let previous = match self.live.lock() {
            Ok(mut guard) => guard.replace(Live {
                superseded: Arc::clone(flag),
                connection: fresh.clone(),
            }),
            // A poisoned lock means another thread panicked mid-attach. Not
            // superseding is the safe half: two connections cost the server a
            // duplicate attachment, which S-25 resolves by highest connection
            // epoch, whereas closing the wrong one drops a live channel.
            Err(_) => None,
        };
        if let Some(previous) = previous {
            previous.superseded.store(true, Ordering::Release);
            previous
                .connection
                .close(connection::SUPERSEDED_CODE.into(), b"superseded");
        }
    }

    /// Tries each configured coordination endpoint, in order.
    async fn walk_endpoints(
        &self,
        config: &TransportConfig,
        client: &quinn::ClientConfig,
    ) -> Result<(quinn::Endpoint, quinn::Connection), TransportError> {
        let mut worst = TransportError::RungFailed(Rung::Quic);
        for name in &config.coordination_endpoints {
            let Some(endpoint) = self.endpoints.iter().find(|e| e.server_name() == name) else {
                // A coordination name the composition root never resolved. It
                // is logged rather than merely skipped: the resulting failure
                // is `CONTROL.UNREACHABLE`, which reads as a network outage,
                // and a misconfigured endpoint list looks exactly like a
                // permanent one from the outside. The NAME is safe to log —
                // it is a public DNS label, not a credential.
                tracing::warn!(endpoint = %name, "no resolved address for this coordination name");
                continue;
            };
            let plan = candidates::plan(endpoint, config.families, self.nat64);
            if plan.is_empty() {
                // Resolved, but to nothing this host can reach: every address
                // is of a family the host does not have, and either there is no
                // NAT64 prefix or the host has no IPv6 to use it over. Same
                // reasoning as above — it is not the network.
                tracing::warn!(
                    endpoint = %name,
                    v4 = config.families.v4,
                    v6 = config.families.v6,
                    nat64 = config.families.nat64,
                    "no candidate of a usable address family"
                );
                continue;
            }
            match self.race(endpoint, plan, client).await {
                Ok(attached) => return Ok(attached),
                Err(err) => worst = keep_more_specific(worst, err),
            }
        }
        Err(worst)
    }

    /// Happy Eyeballs v2 over one endpoint's two family lists.
    ///
    /// `docs/protocol.md` §4.1: IPv6 starts first and IPv4 follows
    /// [`AttachFamilies::V6_BIAS`] later, rather than the two racing evenly —
    /// and then they *do* race, first success winning. ADR-0010 R1 is why this
    /// is one function over two lists instead of a v4 path and a v6 path.
    async fn race(
        &self,
        endpoint: &ControlEndpoint,
        plan: candidates::Plan,
        client: &quinn::ClientConfig,
    ) -> Result<(quinn::Endpoint, quinn::Connection), TransportError> {
        let name = endpoint.server_name();
        if plan.primary.is_empty() {
            return self.try_each(name, &plan.secondary, client).await;
        }
        let primary = Box::pin(self.try_each(name, &plan.primary, client));
        if plan.secondary.is_empty() {
            return primary.await;
        }
        let bias = self.env.timer().sleep(AttachFamilies::V6_BIAS);
        let primary = match select(primary, bias).await {
            Either::Left((result, _)) => return result,
            Either::Right(((), primary)) => primary,
        };
        let secondary = Box::pin(self.try_each(name, &plan.secondary, client));
        // Both branches carry the same future type — `try_each` is one `async
        // fn` — so the loser is awaited by one expression rather than two.
        let (first, loser) = match select(primary, secondary).await {
            Either::Left((result, loser)) | Either::Right((result, loser)) => (result, loser),
        };
        match first {
            Ok(attached) => Ok(attached),
            // The first family to settle **failed**, so the race is not over:
            // Happy Eyeballs v2 is first *success* wins, and abandoning the
            // other branch here would turn a single ICMP unreachable into a
            // rung-1 failure on a host that had a working second family.
            Err(err) => loser
                .await
                .map_err(|second| keep_more_specific(err, second)),
        }
    }

    /// Tries one family's addresses in resolver order.
    async fn try_each(
        &self,
        server_name: &str,
        addresses: &[std::net::SocketAddr],
        client: &quinn::ClientConfig,
    ) -> Result<(quinn::Endpoint, quinn::Connection), TransportError> {
        let mut worst = TransportError::RungFailed(Rung::Quic);
        for address in addresses {
            match connect_one(server_name, *address, client).await {
                Ok(attached) => return Ok(attached),
                Err(err) => worst = keep_more_specific(worst, err),
            }
        }
        Err(worst)
    }
}

/// One socket, one handshake.
///
/// A fresh endpoint per attempt: it owns the UDP socket, so a losing branch of
/// the race releases its socket when it is dropped and there is no shared
/// state between the two families. The local bind matches the target's family,
/// which is why nothing here sets `IPV6_V6ONLY` or maps a v4 address into v6 —
/// ADR-0010 R1 is satisfied by having no per-family branch **after** this
/// point, not by forcing both families through one socket.
async fn connect_one(
    server_name: &str,
    address: std::net::SocketAddr,
    client: &quinn::ClientConfig,
) -> Result<(quinn::Endpoint, quinn::Connection), TransportError> {
    let local: std::net::SocketAddr = if address.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let endpoint =
        quinn::Endpoint::client(local).map_err(|_| TransportError::RungFailed(Rung::Quic))?;
    let connecting = endpoint
        .connect_with(client.clone(), address, server_name)
        .map_err(|_| TransportError::RungFailed(Rung::Quic))?;
    // 0-RTT, control 3 of 3: `Connecting` offers `into_0rtt()` and this awaits
    // the future instead. Awaiting is the 1-RTT path, and there is no
    // configuration that turns it into the other one.
    let connection = connecting.await.map_err(|err| {
        tracing::debug!(error = %err, "rung 1 handshake did not complete");
        map_handshake_error(&err)
    })?;
    Ok((endpoint, connection))
}

/// Keeps the more diagnostic of two failures.
///
/// A refused handshake outranks a rung that never came up: "the control plane
/// declined this key, or its key is not one we pin" is actionable and "nothing
/// answered" is not, and losing the first inside the second is how a pin
/// mismatch gets misreported as a network outage for a week.
fn keep_more_specific(left: TransportError, right: TransportError) -> TransportError {
    match (&left, &right) {
        (TransportError::HandshakeRejected, _) => left,
        (_, TransportError::HandshakeRejected) | (TransportError::RungFailed(_), _) => right,
        _ => left,
    }
}

#[cfg(test)]
mod tests {
    use super::keep_more_specific;
    use crate::transport::{Rung, TransportError};

    #[test]
    fn a_refused_handshake_outranks_a_rung_that_never_came_up() {
        let refused = TransportError::HandshakeRejected;
        let silence = TransportError::RungFailed(Rung::Quic);
        assert_eq!(
            keep_more_specific(silence.clone(), refused.clone()),
            TransportError::HandshakeRejected
        );
        assert_eq!(
            keep_more_specific(refused, silence.clone()),
            TransportError::HandshakeRejected
        );
        assert_eq!(
            keep_more_specific(silence.clone(), silence.clone()),
            silence
        );
    }
}
