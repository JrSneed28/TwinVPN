//! The listener, the per-connection loop, the fan-out, and the drain.
//!
//! As in the rendezvous: this wave binds `TWINVPN_PRESENCE_LISTEN_TCP` and does
//! **not** terminate TLS or bind QUIC. `README.md` §9 says so plainly.
//!
//! The fan-out is a broadcast channel with a bounded buffer. A subscriber that
//! falls behind **loses updates and is not disconnected**, which is correct
//! rather than merely convenient: presence is at-most-once, `EVENTUAL`, and
//! ADR-0008 N-9 says a heartbeat is "PERMITTED TO BE LOST". Blocking a publisher
//! to keep a slow reader current would make a lossy hint channel into a
//! back-pressure source on a device's heartbeat.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use twinvpn_schema::{v1, Channel, Reject};
use twinvpn_service_common::{Metrics, ServiceError, ShutdownHandle};

use crate::config::PresenceConfig;
use crate::frame::{self, Frame, Opcode, HEADER_LEN};
use crate::ingress::{self, Labeller, Outcome};
use crate::store::Store;

/// How many updates a slow subscriber may fall behind before it starts losing
/// them. Losing them is the designed behaviour; see the module docs.
const BROADCAST_DEPTH: usize = 256;

/// Everything a connection needs.
#[derive(Debug)]
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
}

impl Shared {
    /// Builds the shared state for `config`.
    #[must_use]
    pub fn new(config: PresenceConfig, metrics: Metrics) -> Self {
        let (updates, _) = tokio::sync::broadcast::channel(BROADCAST_DEPTH);
        Self {
            store: Mutex::new(Store::new(config.store)),
            labels: Mutex::new(Labeller::new(65_536)),
            updates,
            connections: Arc::new(Semaphore::new(config.max_connections)),
            config,
            metrics,
        }
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
        let Ok((stream, peer)) = accepted else {
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
            let _ = connection(stream, peer, shared).await;
        });
    }
}

async fn connection(
    stream: TcpStream,
    _peer: SocketAddr,
    shared: Arc<Shared>,
) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    let (mut rd, mut wr) = stream.into_split();
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
        let mut header = [0u8; HEADER_LEN];
        // Idle is legitimate for a subscriber; a *started* frame is not.
        let first = if let Some(sub) = subscription.as_mut() {
            tokio::select! {
                r = rd.read_exact(&mut header[..1]) => r.map(|_| ()),
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
            rd.read_exact(&mut header[..1]).await.map(|_| ())
        };
        if first.is_err() {
            break;
        }
        let rest = tokio::time::timeout(
            shared.config.frame_read_timeout,
            rd.read_exact(&mut header[1..]),
        )
        .await;
        if !matches!(rest, Ok(Ok(_))) {
            reject(&shared, &unparseable());
            break;
        }

        // The cap is checked HERE, before the body buffer exists.
        let (opcode, declared) = match frame::parse_header(&header) {
            Ok(v) => v,
            Err(r) => {
                reject(&shared, &r);
                break;
            }
        };
        let mut body = vec![0u8; declared];
        let completed =
            tokio::time::timeout(shared.config.frame_read_timeout, rd.read_exact(&mut body)).await;
        if !matches!(completed, Ok(Ok(_))) {
            reject(&shared, &unparseable());
            break;
        }
        let parsed = match Frame::parse_body(opcode, &Bytes::from(body)) {
            Ok(f) => f,
            Err(r) => {
                reject(&shared, &r);
                break;
            }
        };

        match parsed {
            Frame::Bind { device_id } => {
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
