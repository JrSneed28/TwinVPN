//! The listener, the per-connection loop, and the shutdown drain.
//!
//! # What is bound, and what is not
//!
//! This wave binds **`TWINVPN_RZ_LISTEN_TCP`** and speaks the [`crate::frame`]
//! framing directly on it. `TWINVPN_RZ_LISTEN_QUIC` is parsed and validated but
//! **not bound**, and TLS is **not terminated**: `rustls` is a workspace
//! dependency but `tokio-rustls` is not, and adding one is the integration
//! lead's call, not this domain's. `README.md` §9 states this as a limitation
//! rather than letting a reader infer a mutually authenticated channel that does
//! not exist.
//!
//! What that costs is stated precisely there too. It does **not** change the
//! parser, the caps, the ladder, the ceilings or the forwarding rule, which are
//! the parts a transport cannot make safe.
//!
//! # The one rule the read loop must not get wrong
//!
//! A header is read, its declared length is checked against the cap, and *only
//! then* is a body buffer allocated. The natural spelling,
//! `vec![0; declared_len]`, violates `ownership.md` §6 rule 9 in its first line;
//! [`crate::frame::parse_header`] exists so the check cannot be skipped, and
//! `tests/hostile_input.rs` drives a declared 65535 down a real socket to prove
//! it.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use twinvpn_schema::{v1, Channel, Reject};
use twinvpn_service_common::transport::Admission;
use twinvpn_service_common::{Metrics, ServiceError, ShutdownHandle};

use tokio::sync::Semaphore;

use crate::admission::SourceLimiter;
use crate::attach::{Attached, Egress};
use crate::config::RendezvousConfig;
use crate::frame::{self, Frame, Opcode, HEADER_LEN};
use crate::ingress::{self, Disposition, Router};

/// Everything a connection needs. `Router` is behind one mutex because the whole
/// service state is three small tables and the work under the lock is a hash
/// lookup — a lock-free design here would buy nothing and cost reviewability.
#[derive(Debug)]
pub struct Shared {
    /// The routing tables.
    pub router: Mutex<Router>,
    /// Per-source admission.
    pub limiter: Mutex<SourceLimiter>,
    /// Configuration.
    pub config: RendezvousConfig,
    /// Counters.
    pub metrics: Metrics,
    /// The concurrently-served-connection ceiling. A pre-authentication surface
    /// with no connection bound is a file-descriptor exhaustion primitive; the
    /// semaphore makes the bound a resource rather than a hope.
    pub connections: Arc<Semaphore>,
}

/// How many egress frames may be queued for one attached device before this
/// service stops trying. Small on purpose: a device that is not reading is a
/// device whose `CALL`s have decayed anyway, and an unbounded queue here would
/// be the memory amplifier ADR-0002 S-5 forbids.
const EGRESS_QUEUE: usize = 16;

/// The counters this service exposes on `:9090/metrics`.
///
/// ADR-0015 O-13 forbids a per-session or peer-pair label on relay telemetry;
/// the same reasoning applies here, and `metrics::Label`'s five-value allowlist
/// makes it structural — there is no `device_id` label available to add.
pub mod counters {
    /// `CALL`s accepted at ingress.
    pub const CALLS_RECEIVED: &str = "twinvpn_rendezvous_calls_received_total";
    /// `CALL`s handed to a live attachment (ADR-0002 §11.5 rung [1]).
    pub const CALLS_DELIVERED: &str = "twinvpn_rendezvous_calls_delivered_total";
    /// `CALL`s queued in the jitter buffer (rung [3]).
    pub const CALLS_MAILBOXED: &str = "twinvpn_rendezvous_calls_mailboxed_total";
    /// Frames refused by the B3 parser.
    pub const FRAMES_REJECTED: &str = "twinvpn_rendezvous_frames_rejected_total";
    /// Retained mailbox bytes.
    pub const MAILBOX_BYTES: &str = "twinvpn_rendezvous_mailbox_bytes";
    /// Currently attached devices.
    pub const ATTACHED: &str = "twinvpn_rendezvous_attached_devices";
}

/// Accepts connections until `handle` drains.
///
/// # Errors
///
/// Never returns an error today; the signature keeps the shape a TLS or QUIC
/// binding will need.
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
        // A failed accept is a transient condition on a busy listener, not a
        // reason to stop serving everyone else.
        let Ok((stream, peer)) = accepted else {
            continue;
        };
        // Refuse rather than queue: an admitted connection this process cannot
        // serve is a descriptor held for nothing.
        let Ok(slot) = Arc::clone(&shared.connections).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let Some(guard) = handle.try_acquire() else {
            // Draining. S-6: close cleanly rather than resetting — a reset is
            // indistinguishable from network failure and drives clients into
            // the aggressive interactive backoff regime.
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

/// Serves one connection.
async fn connection(
    stream: TcpStream,
    peer: SocketAddr,
    shared: Arc<Shared>,
) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    let (mut rd, mut wr) = stream.into_split();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Egress>(EGRESS_QUEUE);

    // The egress task. Nothing here renders a payload: `Verbatim`'s `Debug`
    // prints a length and a channel, and this path writes octets without
    // looking at them.
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let bytes = match msg {
                // W-4: the ORIGINAL octets, byte for byte. No decode, no
                // re-encode, no normalisation.
                Egress::Deliver(v) => frame::encode(Opcode::Deliver, v.as_bytes()),
                Egress::Ack(b) => frame::encode(Opcode::Ack, &b),
                Egress::Reflexive(b) => frame::encode(Opcode::Reflexive, &b),
                Egress::Superseded => {
                    frame::encode(Opcode::Ack, &encode_error(&ingress::superseded()))
                }
            };
            if wr.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    // Tell the peer which source address this service observed for it —
    // networking.md A6(a), and the free reflexive refresh ADR-0004 §5 relies on.
    // Sent once, on connect. The address is used and dropped: nothing here
    // retains it, logs it, or puts it in a metric label.
    let _ = tx.try_send(Egress::Reflexive(encode_endpoint(peer)));

    let mut bound: Option<(frame::DeviceId, u64)> = None;
    let outcome = read_loop(&mut rd, peer.ip(), &shared, &tx, &mut bound).await;

    if let Some((device_id, epoch)) = bound {
        shared
            .router
            .lock()
            .await
            .attachments
            .detach(device_id, epoch);
    }
    drop(tx);
    let _ = writer.await;
    outcome
}

async fn read_loop(
    rd: &mut tokio::net::tcp::OwnedReadHalf,
    source: IpAddr,
    shared: &Arc<Shared>,
    tx: &tokio::sync::mpsc::Sender<Egress>,
    bound: &mut Option<(frame::DeviceId, u64)>,
) -> std::io::Result<()> {
    loop {
        let mut header = [0u8; HEADER_LEN];
        // An idle connection is legitimate: an attached peer waits here for a
        // CALL and may wait for its whole 90 s TTL. So the first octet has no
        // deadline...
        if rd.read_exact(&mut header[..1]).await.is_err() {
            return Ok(()); // clean close; done
        }
        // ...and every octet after it does. Once a frame has *started*, a caller
        // that stops sending is stalling, not idling, and a stalled frame holds
        // a socket and a buffer this process did not choose to commit.
        let rest = tokio::time::timeout(
            shared.config.frame_read_timeout,
            rd.read_exact(&mut header[1..]),
        )
        .await;
        if !matches!(rest, Ok(Ok(_))) {
            reject(
                shared,
                &Reject::Unparseable {
                    parser_id: Channel::PeerDatagram.parser_id(),
                },
            );
            return Ok(());
        }
        // The cap is checked HERE. Only the line after it allocates.
        let (opcode, declared) = match frame::parse_header(&header) {
            Ok(v) => v,
            Err(r) => {
                reject(shared, &r);
                return Ok(());
            }
        };
        let mut body = vec![0u8; declared];
        // The slowloris bound: once a header has committed this process to a
        // buffer, the body has a deadline. Without it a caller declares 1232
        // bytes, sends one, and owns a socket and its buffer for ever.
        let completed =
            tokio::time::timeout(shared.config.frame_read_timeout, rd.read_exact(&mut body)).await;
        if !matches!(completed, Ok(Ok(_))) {
            // A truncated or stalled body is Unparseable and — per
            // trust-boundaries.md §2 — draws no answer.
            reject(
                shared,
                &Reject::Unparseable {
                    parser_id: Channel::PeerDatagram.parser_id(),
                },
            );
            return Ok(());
        }
        let parsed = match Frame::parse_body(opcode, &Bytes::from(body)) {
            Ok(f) => f,
            Err(r) => {
                reject(shared, &r);
                return Ok(());
            }
        };

        let now = Instant::now();
        match parsed {
            Frame::Attach { device_id } => {
                if !handle_attach(shared, tx, bound, device_id, now).await {
                    return Ok(());
                }
            }
            Frame::Call { target, payload } => {
                match shared.limiter.lock().await.admit(source, now) {
                    Admission::Admitted => {}
                    Admission::Deferred { retry_after_ms } => {
                        // S-6: answer, never reset, never drop.
                        ack(tx, &ingress::admission_deferred(retry_after_ms));
                        continue;
                    }
                }
                count(
                    shared,
                    counters::CALLS_RECEIVED,
                    "CALLs accepted at ingress",
                );
                let disposition = shared.router.lock().await.route_call(target, payload, now);
                match disposition {
                    Disposition::Delivered(sink, v) => {
                        count(shared, counters::CALLS_DELIVERED, "CALLs delivered live");
                        // A full egress queue is a peer that is not reading; the
                        // CALL decays rather than blocking this connection.
                        let _ = sink.try_send(Egress::Deliver(v));
                        let _ = tx.try_send(Egress::Ack(Bytes::new()));
                    }
                    Disposition::Mailboxed { overflowed, label } => {
                        count(shared, counters::CALLS_MAILBOXED, "CALLs mailboxed");
                        if overflowed {
                            ingress::mailbox_overflow().emit(&shared.metrics, "overflow");
                        }
                        ack(tx, &ingress::peer_not_attached(label));
                    }
                    Disposition::Undeliverable(label) => {
                        ack(tx, &ingress::call_undeliverable(label));
                    }
                }
            }
        }
    }
}

/// Binds a connection, drains the jitter buffer onto it, and answers. Returns
/// `false` when the connection should close.
async fn handle_attach(
    shared: &Arc<Shared>,
    tx: &tokio::sync::mpsc::Sender<Egress>,
    bound: &mut Option<(frame::DeviceId, u64)>,
    device_id: frame::DeviceId,
    now: Instant,
) -> bool {
    let (result, superseded, queued) = {
        let mut router = shared.router.lock().await;
        let (result, superseded) = router.attachments.attach(device_id, tx.clone(), now);
        let queued = if matches!(result, Attached::Bound { .. }) {
            router.mailboxes.take(device_id, now)
        } else {
            Vec::new()
        };
        (result, superseded, queued)
    };
    match result {
        Attached::Bound { epoch } => {
            *bound = Some((device_id, epoch));
            if let Some(old) = superseded {
                let _ = old.try_send(Egress::Superseded);
            }
            // Rung [1] is now live for this device: hand it whatever the jitter
            // buffer holds. `take` is destructive, so nothing is replayed (N-9).
            for v in queued {
                if tx.send(Egress::Deliver(v)).await.is_err() {
                    return false;
                }
            }
            let _ = tx.try_send(Egress::Ack(Bytes::new()));
            true
        }
        Attached::AtCapacity => {
            let max = shared.config.attach.max_attachments as u64;
            ack(tx, &ingress::peer_limit_reached(max));
            false
        }
    }
}

/// Records a rejected frame and closes **without answering**.
///
/// `trust-boundaries.md` §2: "Violation ⇒ **drop, emit PROTO.MALFORMED_MESSAGE,
/// NO state change, NO answer.** Answering would confirm the target exists."
/// "Emit" is the local diagnostic and the metric; the sender learns nothing.
fn reject(shared: &Arc<Shared>, r: &Reject) {
    ServiceError::from_reject(r, crate::COMPONENT).emit(&shared.metrics, "rejected");
    count(
        shared,
        counters::FRAMES_REJECTED,
        "frames refused by the B3 parser",
    );
}

fn count(shared: &Arc<Shared>, name: &'static str, help: &'static str) {
    shared
        .metrics
        .counter(name, help, twinvpn_service_common::metrics::Labels::new())
        .inc();
}

fn ack(tx: &tokio::sync::mpsc::Sender<Egress>, e: &ServiceError) {
    let _ = tx.try_send(Egress::Ack(Bytes::from(encode_error(e))));
}

/// Encodes a `ServiceError` as `twinvpn.v1.ErrorEnvelope`.
///
/// `ServiceError` has no message field and its envelope carries only the
/// registered code plus **this build's** registry attributes, so there is no
/// path by which an internal error string reaches the wire.
fn encode_error(e: &ServiceError) -> Vec<u8> {
    use prost::Message as _;
    let env: v1::ErrorEnvelope = e.envelope();
    let mut buf = Vec::with_capacity(env.encoded_len());
    env.encode(&mut buf).expect("a Vec never fails to grow");
    buf
}

/// Encodes an observed source address as `twinvpn.v1.Endpoint`.
///
/// Both families are first-class here: `Endpoint`'s `IPAddress` is a `oneof`, so
/// "we have a v4 story and a v6 story" is not sayable — ADR-0010 R1 expressed in
/// the schema rather than in a runtime branch.
///
/// # Panics
///
/// Never: the only fallible step is encoding into a `Vec`, which cannot fail.
#[must_use]
pub fn encode_endpoint(peer: SocketAddr) -> Bytes {
    use prost::Message as _;
    let address = match peer.ip() {
        IpAddr::V4(v4) => v1::ip_address::Address::V4(v1::IPv4Address {
            octets: v4.octets().to_vec(),
        }),
        IpAddr::V6(v6) => v1::ip_address::Address::V6(v1::IPv6Address {
            octets: v6.octets().to_vec(),
            // A rendezvous connection never arrives on a link-local source, and
            // an invented zone index would be a lie a peer might act on.
            zone_index: 0,
        }),
    };
    let ep = v1::Endpoint {
        address: Some(v1::IpAddress {
            address: Some(address),
        }),
        port: u32::from(peer.port()),
    };
    let mut buf = Vec::with_capacity(ep.encoded_len());
    ep.encode(&mut buf).expect("a Vec never fails to grow");
    Bytes::from(buf)
}

/// Runs the TTL sweep until shutdown, so expired bytes are reclaimed on a timer
/// rather than only when a target is next touched.
pub async fn sweeper(shared: Arc<Shared>, handle: ShutdownHandle, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        tokio::select! {
            () = handle.draining() => return,
            _ = ticker.tick() => {
                let now = Instant::now();
                let mut router = shared.router.lock().await;
                router.sweep(now);
                let labels = twinvpn_service_common::metrics::Labels::new;
                shared
                    .metrics
                    .gauge(counters::MAILBOX_BYTES, "retained mailbox bytes", labels())
                    .set(i64::try_from(router.mailboxes.total_bytes()).unwrap_or(i64::MAX));
                shared
                    .metrics
                    .gauge(counters::ATTACHED, "attached devices", labels())
                    .set(i64::try_from(router.attachments.len()).unwrap_or(i64::MAX));
            }
        }
    }
}
