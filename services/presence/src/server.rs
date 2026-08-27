//! The listener, the per-connection loop, the fan-out, and the drain.
//!
//! This wave binds `TWINVPN_PRESENCE_LISTEN_TCP` and terminates **TLS 1.3 with
//! mutual RFC 7250 raw-public-key authentication** on it ([`crate::tls`]).
//! `TWINVPN_PRESENCE_LISTEN_QUIC` is parsed and not bound; `README.md` §9.
//!
//! A connection that presents no raw public key, or one it cannot prove
//! possession of, **never reaches the parser**. That is what makes S-11
//! enforceable: `BIND` is answerable to a key ([`crate::binding`]), so
//! "a device may assert presence only for itself" is a check against an
//! authenticated identity rather than against another unauthenticated claim.
//!
//! The fan-out is a broadcast channel with a bounded buffer. A subscriber that
//! falls behind **loses updates and is not disconnected**, which is correct
//! rather than merely convenient: presence is at-most-once, `EVENTUAL`, and
//! ADR-0008 N-9 says a heartbeat is "PERMITTED TO BE LOST". Blocking a publisher
//! to keep a slow reader current would make a lossy hint channel into a
//! back-pressure source on a device's heartbeat.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use twinvpn_schema::{v1, Channel, Reject};
use twinvpn_service_common::{Metrics, ServiceError, ShutdownHandle};

use crate::binding::{Binding, Claim};
use crate::config::PresenceConfig;
use crate::frame::{self, Frame, Opcode, HEADER_LEN};
use crate::ingress::{self, Labeller, Outcome};
use crate::store::Store;
use crate::tls::ChannelIdentity;

/// How many updates a slow subscriber may fall behind before it starts losing
/// them. Losing them is the designed behaviour; see the module docs.
const BROADCAST_DEPTH: usize = 256;

/// Everything a connection needs.
pub struct Shared {
    /// The presence table.
    pub store: Mutex<Store>,
    /// `device_id → pseudonym`, for evidence and logs.
    pub labels: Mutex<Labeller>,
    /// Fan-out to subscribers.
    pub updates: tokio::sync::broadcast::Sender<Bytes>,
    /// Configuration.
    pub config: PresenceConfig,
    /// Counters.
    pub metrics: Metrics,
    /// The connection ceiling.
    pub connections: Arc<Semaphore>,
    /// `device_id` ↔ authenticated channel identity.
    pub bindings: Mutex<Box<dyn Binding>>,
    /// The TLS acceptor.
    pub tls: tokio_rustls::TlsAcceptor,
}

impl std::fmt::Debug for Shared {
    /// Names the parts and renders none of them. A `Shared` holds every
    /// `device_id` and every channel identity this process knows.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("service", &"presence")
            .finish_non_exhaustive()
    }
}

impl Shared {
    /// Builds the shared state for `config`.
    ///
    /// # Errors
    ///
    /// [`crate::tls::TlsError`] if the private key cannot be read or parsed. A
    /// key that will not load is a startup failure, never a fallback to an
    /// unauthenticated listener.
    pub fn new(config: PresenceConfig, metrics: Metrics) -> Result<Self, crate::tls::TlsError> {
        let (updates, _) = tokio::sync::broadcast::channel(BROADCAST_DEPTH);
        let tls = tokio_rustls::TlsAcceptor::from(crate::tls::server_config(&config.tls_key_path)?);
        Ok(Self {
            store: Mutex::new(Store::new(config.store)),
            labels: Mutex::new(Labeller::new(65_536)),
            updates,
            connections: Arc::new(Semaphore::new(config.max_connections)),
            bindings: Mutex::new(Box::new(crate::binding::ChannelPinned::new(config.binding))),
            tls,
            config,
            metrics,
        })
    }
}

/// The counters this service exposes on `:9090/metrics`.
pub mod counters {
    /// Heartbeats accepted.
    pub const PUBLISHED: &str = "twinvpn_presence_heartbeats_published_total";
    /// Heartbeats ignored as superseded, expired or out of range.
    pub const IGNORED: &str = "twinvpn_presence_heartbeats_ignored_total";
    /// Frames refused by the parser.
    pub const REJECTED: &str = "twinvpn_presence_frames_rejected_total";
    /// Records currently held.
    pub const RECORDS: &str = "twinvpn_presence_records";
    /// TLS handshakes that did not complete.
    pub const HANDSHAKES_REFUSED: &str = "twinvpn_presence_tls_handshakes_refused_total";
    /// `BIND`s refused because the claimed device does not match the channel.
    pub const BINDING_MISMATCHES: &str = "twinvpn_presence_binding_mismatches_total";
}

/// Wall-clock milliseconds. Evidence only, never a timer input (ADR-0018 CD-1).
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Accepts connections until `handle` drains.
///
/// # Errors
///
/// Never today; the signature keeps the shape a TLS binding will need.
pub async fn serve(
    listener: TcpListener,
    shared: Arc<Shared>,
    handle: ShutdownHandle,
) -> std::io::Result<()> {
    loop {
        let accepted = tokio::select! {
            () = handle.draining() => return Ok(()),
            r = listener.accept() => r,
        };
        let Ok((stream, _peer)) = accepted else {
            continue;
        };
        let Ok(slot) = Arc::clone(&shared.connections).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let Some(guard) = handle.try_acquire() else {
            drop(stream);
            continue;
        };
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let _guard = guard;
            let _slot = slot;
            let _ = accept_one(stream, shared).await;
        });
    }
}

/// Completes the TLS handshake, then serves the connection behind it.
async fn accept_one(stream: TcpStream, shared: Arc<Shared>) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    let handshake =
        tokio::time::timeout(shared.config.frame_read_timeout, shared.tls.accept(stream)).await;
    let Ok(Ok(tls)) = handshake else {
        count(
            &shared,
            counters::HANDSHAKES_REFUSED,
            "TLS handshakes that did not complete",
        );
        return Ok(());
    };
    let Some(channel) = crate::tls::peer_identity(tls.get_ref().1) else {
        count(
            &shared,
            counters::HANDSHAKES_REFUSED,
            "TLS handshakes that did not complete",
        );
        return Ok(());
    };
    connection(tls, channel, shared).await
}

/// Reads one complete frame, applying the cap before the body buffer exists and
/// the stall deadline to every octet after the first.
async fn next_frame<R>(rd: &mut R, shared: &Arc<Shared>) -> Option<Frame>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; HEADER_LEN];
    // Idle is legitimate for a subscriber; a *started* frame is not.
    rd.read_exact(&mut header[..1]).await.ok()?;
    let rest = tokio::time::timeout(
        shared.config.frame_read_timeout,
        rd.read_exact(&mut header[1..]),
    )
    .await;
    if !matches!(rest, Ok(Ok(_))) {
        reject(shared, &unparseable());
        return None;
    }
    // The cap is checked HERE, before the body buffer exists.
    let (opcode, declared) = match frame::parse_header(&header) {
        Ok(v) => v,
        Err(r) => {
            reject(shared, &r);
            return None;
        }
    };
    let mut body = vec![0u8; declared];
    let completed =
        tokio::time::timeout(shared.config.frame_read_timeout, rd.read_exact(&mut body)).await;
    if !matches!(completed, Ok(Ok(_))) {
        reject(shared, &unparseable());
        return None;
    }
    match Frame::parse_body(opcode, &Bytes::from(body)) {
        Ok(f) => Some(f),
        Err(r) => {
            reject(shared, &r);
            None
        }
    }
}

async fn connection<S>(
    stream: S,
    channel: ChannelIdentity,
    shared: Arc<Shared>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    let writer = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if wr.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    let mut bound: Option<[u8; 32]> = None;
    let mut subscription: Option<tokio::sync::broadcast::Receiver<Bytes>> = None;

    loop {
        // Idle is legitimate for a subscriber, which may sit here for its whole
        // record TTL waiting for an update; a *started* frame is not.
        let parsed = if let Some(sub) = subscription.as_mut() {
            tokio::select! {
                f = next_frame(&mut rd, &shared) => f,
                m = sub.recv() => {
                    match m {
                        Ok(bytes) => {
                            if tx.send(frame::encode(Opcode::Event, &bytes)).await.is_err() {
                                break;
                            }
                            continue;
                        }
                        // Lagged: the subscriber fell behind and lost updates.
                        // Correct, and not a disconnect — presence is lossy by
                        // contract (ADR-0008 N-9).
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        } else {
            next_frame(&mut rd, &shared).await
        };
        let Some(parsed) = parsed else { break };

        match parsed {
            Frame::Bind { device_id } => {
                // The claim is checked against the AUTHENTICATED channel
                // identity. `CONTROL.CHANNEL_BINDING_MISMATCH` is FATAL/CRITICAL:
                // `trust-boundaries.md` §4 calls a binding mismatch "a security
                // event, never a parse error", and a device_id claimed on a
                // channel not entitled to it is exactly that.
                let claim = shared
                    .bindings
                    .lock()
                    .await
                    .claim(&channel, device_id, Instant::now());
                if let Claim::Refused(_) = claim {
                    let e = crate::ingress::channel_binding_mismatch();
                    e.emit(&shared.metrics, "binding_mismatch");
                    count(
                        &shared,
                        counters::BINDING_MISMATCHES,
                        "BINDs refused for a channel-binding mismatch",
                    );
                    let body = crate::ingress::refusal_response(&e);
                    let _ = tx.send(frame::encode(Opcode::Ack, &body)).await;
                    break;
                }
                bound = Some(device_id);
                let _ = tx.send(frame::encode(Opcode::Ack, &[])).await;
            }
            Frame::Subscribe => {
                subscription = Some(shared.updates.subscribe());
                let _ = tx.send(frame::encode(Opcode::Ack, &[])).await;
            }
            Frame::Publish { request } => {
                let answer = handle_publish(&shared, bound, &request).await;
                if tx.send(frame::encode(Opcode::Ack, &answer)).await.is_err() {
                    break;
                }
            }
        }
    }

    shared
        .bindings
        .lock()
        .await
        .release(&channel, Instant::now());
    drop(tx);
    let _ = writer.await;
    Ok(())
}

async fn handle_publish(
    shared: &Arc<Shared>,
    bound: Option<[u8; 32]>,
    request: &v1::PublishPresenceRequest,
) -> Vec<u8> {
    use prost::Message as _;

    let now = Instant::now();
    let wall = now_ms();
    let outcome = {
        let mut store = shared.store.lock().await;
        let mut labels = shared.labels.lock().await;
        ingress::publish(&mut store, &mut labels, bound, request, now, wall)
    };

    let response = match outcome {
        Outcome::Updated(presence) => {
            count(shared, counters::PUBLISHED, "heartbeats accepted");
            let twinnet_id = request
                .metadata
                .as_ref()
                .map(|m| m.twinnet_id.clone())
                .unwrap_or_default();
            let event = ingress::presence_updated(*presence, twinnet_id);
            let mut buf = Vec::with_capacity(event.encoded_len());
            event.encode(&mut buf).expect("a Vec never fails to grow");
            // `send` fails only when nobody is subscribed, which is not an error.
            let _ = shared.updates.send(Bytes::from(buf));
            v1::PublishPresenceResponse {
                ack: Some(ingress::heartbeat_ack(crate::config::millis(
                    shared.config.heartbeat_interval,
                ))),
                error: None,
            }
        }
        Outcome::Ignored => {
            count(shared, counters::IGNORED, "heartbeats ignored");
            // Ignored is still a success on the wire: the device asserted
            // something the aggregator already knows or has moved past, and
            // ADR-0008 N-9 permits the loss. An error here would teach a client
            // to retry a heartbeat, which is the one thing it must not do.
            v1::PublishPresenceResponse {
                ack: Some(ingress::heartbeat_ack(crate::config::millis(
                    shared.config.heartbeat_interval,
                ))),
                error: None,
            }
        }
        Outcome::Refused(e) => {
            e.emit(&shared.metrics, "refused");
            v1::PublishPresenceResponse {
                ack: None,
                error: Some(e.envelope()),
            }
        }
    };

    let mut buf = Vec::with_capacity(response.encoded_len());
    response
        .encode(&mut buf)
        .expect("a Vec never fails to grow");
    buf
}

fn unparseable() -> Reject {
    Reject::Unparseable {
        parser_id: Channel::ControlAndTelemetry.parser_id(),
    }
}

fn reject(shared: &Arc<Shared>, r: &Reject) {
    ServiceError::from_reject(r, crate::COMPONENT).emit(&shared.metrics, "rejected");
    count(shared, counters::REJECTED, "frames refused by the parser");
}

fn count(shared: &Arc<Shared>, name: &'static str, help: &'static str) {
    shared
        .metrics
        .counter(name, help, twinvpn_service_common::metrics::Labels::new())
        .inc();
}

/// Runs the TTL sweep until shutdown.
pub async fn sweeper(shared: Arc<Shared>, handle: ShutdownHandle, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        tokio::select! {
            () = handle.draining() => return,
            _ = ticker.tick() => {
                let mut store = shared.store.lock().await;
                store.sweep(Instant::now());
                shared
                    .metrics
                    .gauge(
                        counters::RECORDS,
                        "presence records held",
                        twinvpn_service_common::metrics::Labels::new(),
                    )
                    .set(i64::try_from(store.len()).unwrap_or(i64::MAX));
            }
        }
    }
}
