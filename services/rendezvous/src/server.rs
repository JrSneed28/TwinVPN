//! The listener, the per-connection loop, and the shutdown drain.
//!
//! # What is bound, and what is not
//!
//! This wave binds **`TWINVPN_RZ_LISTEN_TCP`** and terminates **TLS 1.3 with
//! mutual RFC 7250 raw-public-key authentication** on it
//! ([`twinvpn_service_common::tls`]).
//! `TWINVPN_RZ_LISTEN_QUIC` is parsed and validated but **not bound**:
//! ADR-0001's L-CONTROL is QUIC + TLS 1.3 and this is the TCP shape of the same
//! authentication, which ADR-0002 §11.2's rung 2 already contemplates. That gap
//! is `README.md` §9's, not a silent substitution.
//!
//! # The handshake happens before the framing
//!
//! A connection that presents no raw public key, or one it cannot prove
//! possession of, **never reaches the parser**: `client_auth_mandatory` is true
//! and rustls fails the handshake. So the B3 caps and the framing are now behind
//! an authenticated channel rather than in front of one — which does not make
//! them less load-bearing, because a device that authenticates is still a device
//! this service does not trust.
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

use crate::codec::{encode_endpoint, encode_error};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use twinvpn_schema::{Channel, Reject};
use twinvpn_service_common::binding::{Binding, Claim, Refusal};
use twinvpn_service_common::tls::{self, ChannelIdentity};
use twinvpn_service_common::transport::Admission;
use twinvpn_service_common::{Metrics, ServiceError, ShutdownHandle};

use tokio::sync::Semaphore;

use crate::admission::SourceLimiter;
use crate::attach::{Attached, Egress};

use crate::config::RendezvousConfig;
use crate::frame::{self, Frame, Opcode, HEADER_LEN};
use crate::ingress::{self, Disposition, Router};

/// Everything a connection needs. `Router` is behind one mutex because the whole
/// service state is four small tables and the work under the lock is a hash
/// lookup — a lock-free design here would buy nothing and cost reviewability.
pub struct Shared {
    /// The routing tables.
    pub router: Mutex<Router>,
    /// Per-source admission.
    pub limiter: Mutex<SourceLimiter>,
    /// `device_id` ↔ authenticated channel identity.
    pub bindings: Mutex<Box<dyn Binding<frame::DeviceId>>>,
    /// The TLS acceptor. Constructed at startup; a key that cannot be loaded is
    /// a startup failure, never a plaintext listener.
    pub tls: tokio_rustls::TlsAcceptor,
    /// Configuration.
    pub config: RendezvousConfig,
    /// Counters.
    pub metrics: Metrics,
    /// The concurrently-served-connection ceiling. A pre-authentication surface
    /// with no connection bound is a file-descriptor exhaustion primitive; the
    /// semaphore makes the bound a resource rather than a hope.
    pub connections: Arc<Semaphore>,
}

impl std::fmt::Debug for Shared {
    /// Names the parts and renders none of them. A `Shared` holds every
    /// `device_id`, every channel identity and every queued `CALL` this process
    /// knows; a derived `Debug` would be a rendering path for all three.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("service", &"rendezvous")
            .finish_non_exhaustive()
    }
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
    /// TLS handshakes that did not complete — no client key, an unprovable key,
    /// or a peer speaking something other than TLS 1.3.
    pub const HANDSHAKES_REFUSED: &str = "twinvpn_rendezvous_tls_handshakes_refused_total";
    /// `ATTACH`es refused because the claimed device does not match the channel.
    pub const BINDING_MISMATCHES: &str = "twinvpn_rendezvous_binding_mismatches_total";
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
            let _ = accept_one(stream, peer, shared).await;
        });
    }
}

/// Completes the TLS handshake, then serves the connection behind it.
///
/// The handshake is bounded by the same deadline a partial frame gets: a peer
/// that opens a socket and then stalls mid-handshake is the slowloris case one
/// layer down, and rustls will wait as long as the peer makes it.
async fn accept_one(
    stream: TcpStream,
    peer: SocketAddr,
    shared: Arc<Shared>,
) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    // No client key, an unprovable key, a TLS 1.2 hello, or plaintext. The peer
    // learns only that the handshake failed; nothing is answered and no state
    // exists to change. The shared helper carries the deadline and the
    // "a completed handshake always presented a key" assertion.
    let Ok((tls, channel)) =
        tls::accept_with_deadline(&shared.tls, stream, shared.config.frame_read_timeout).await
    else {
        count(
            &shared,
            counters::HANDSHAKES_REFUSED,
            "TLS handshakes that did not complete",
        );
        return Ok(());
    };

    connection(tls, channel, peer, shared).await
}

/// Serves one authenticated connection.
async fn connection<S>(
    stream: S,
    channel: ChannelIdentity,
    peer: SocketAddr,
    shared: Arc<Shared>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
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
    let outcome = read_loop(&mut rd, peer.ip(), &channel, &shared, &tx, &mut bound).await;

    // Release EXACTLY what this connection claimed, and only if it claimed
    // something.
    //
    // `bound` is `Some` only on an ACCEPTED claim, so a refused connection has
    // nothing to release. That is the whole of the defect the shared crate
    // found: an unconditional, channel-only release let a refused connection
    // drop a *live sibling's* hold on the same key, after which one channel
    // could speak for a second subject. This service previously did not release
    // at all, which leaked holder counts until the TTL swept them — a slower
    // path to the same table-at-capacity outcome, and equally wrong.
    if let Some((device_id, epoch)) = bound {
        shared
            .router
            .lock()
            .await
            .attachments
            .detach(device_id, epoch);
        // The binding OUTLIVES the connection: this drops the holder count
        // without dropping the claim, so a reconnect finds its own binding and
        // an attacker racing that reconnect finds it taken.
        shared
            .bindings
            .lock()
            .await
            .release(&channel, &device_id, Instant::now());
    }
    drop(tx);
    let _ = writer.await;
    outcome
}

async fn read_loop<R>(
    rd: &mut R,
    source: IpAddr,
    channel: &ChannelIdentity,
    shared: &Arc<Shared>,
    tx: &tokio::sync::mpsc::Sender<Egress>,
    bound: &mut Option<(frame::DeviceId, u64)>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
{
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
                if !handle_attach(shared, tx, channel, bound, device_id, now).await {
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
    channel: &ChannelIdentity,
    bound: &mut Option<(frame::DeviceId, u64)>,
    device_id: frame::DeviceId,
    now: Instant,
) -> bool {
    // The claim is checked against the AUTHENTICATED channel identity before
    // anything is bound, delivered or drained.
    //
    // The refusal carries its OWN reason code, and the two are different facts:
    // a binding mismatch is `CONTROL.CHANNEL_BINDING_MISMATCH`, FATAL/CRITICAL,
    // "a security event, never a parse error" (`trust-boundaries.md` §4);
    // a full table is `CONTROL.ADMISSION_DEFERRED`, because the subject is not
    // contested, the server is — and answering "held by another channel" there
    // would tell a caller its device_id was taken when it was not.
    let claim = shared.bindings.lock().await.claim(channel, device_id, now);
    if let Claim::Refused(refusal) = claim {
        let e = refusal.to_error(crate::COMPONENT);
        e.emit(&shared.metrics, "binding_refused");
        if refusal != Refusal::TableAtCapacity {
            count(
                shared,
                counters::BINDING_MISMATCHES,
                "ATTACHes refused for a channel-binding mismatch",
            );
        }
        ack(tx, &e);
        return false;
    }
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
