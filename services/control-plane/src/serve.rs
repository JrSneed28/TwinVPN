//! The accept loop: one endpoint, its connections, their C1 streams and their
//! C2 stream.
//!
//! **Authority:** ADR-0002 §11.2 rung 1, N-1 (one connection per `Device`), N-2
//! (channel binding), N-8 (compaction announced in band and in order), §11.6
//! (the priority rule and the backlog watermark), §11.7 (the accept limiter and
//! the drain), `README.md` §7 and §7.1 (the C1 framing).
//!
//! # What this module is
//!
//! Everything below it was already written and tested — [`crate::wire`] frames,
//! [`crate::dispatch`] executes, [`crate::store`] commits, [`crate::session`]
//! paces. This is the composition root that turns them into a listening service,
//! and it is deliberately thin: it owns **no** rule that any of them owns.
//!
//! # The order inside one request, and why it is that order
//!
//! ```text
//!   frame ──▶ envelope ──▶ channel binding ──▶ identity ──▶ store
//!   (§6 r9)   (bounded)      (N-2)            (N-32)     (the transaction)
//! ```
//!
//! 1. **Frame before body.** [`C1Frame::parse_header`] checks the declared
//!    length against the frozen cap before a body buffer is allocated, so a
//!    declared `0xFFFF_FFFF` costs six bytes of reading.
//! 2. **Channel binding before anything else the body says.** ADR-0002 N-2: the
//!    presented `Auth.channel_binding` must be *this connection's* RFC 9266
//!    exporter. A mismatch is a **security event** and is refused before the
//!    request is allowed to mean anything.
//! 3. **Identity from the connection, never from the body.** The caller is the
//!    key the peer proved possession of in the handshake, resolved through this
//!    service's own device table ([`crate::identity`]). A `device_id` in a body
//!    is a claim, and every handler treats it as one.
//! 4. **Then, and only then, the store.**
//!
//! # One thing this module does NOT do
//!
//! It never invents a response. A refusal is the command's own response message
//! with its `error` field set ([`error_response`]) — `README.md` §7.1's "there
//! is no separate error frame" — so a client decodes exactly one shape per
//! command code whatever happened.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use twinvpn_schema::v1;
use twinvpn_service_common::binding as spki;
use twinvpn_service_common::metrics::{Label, Labels};
use twinvpn_service_common::{ChannelIdentity, Correlation, Metrics, ServiceError, ShutdownHandle};

use crate::model::DeviceKey;
use crate::quic::PeerIdentityVerifier;
use crate::session::{AcceptLimiter, AttachPriority, Attachment, Attachments, Pumped, Rung};
use crate::store::{ControlStore, Request};
use crate::verify::StatementVerifier;
use crate::{codes, dispatch, event, quic, wire, C1Frame, CommandCode};

/// QUIC application close codes.
///
/// Distinct values, because "the connection closed" is three different facts to
/// an operator and a client retries differently for each. They are **not**
/// `reason_code`s: a QUIC close code is a transport-layer integer with no
/// registry, and the registered code travels in the response envelope where a
/// response could still be built.
mod close {
    /// The service is draining. Reconnect; another front-end will serve.
    pub const DRAINING: u32 = 1;
    /// ADR-0002 N-1: a newer connection for this identity superseded this one.
    pub const SUPERSEDED: u32 = 2;
    /// A frame that could not be answered at all — the framing itself was
    /// unparseable, so there is no command whose response could carry the error.
    pub const UNFRAMED: u32 = 3;
}

/// How many durable events one C2 pump takes from the log per turn.
///
/// A bound rather than "everything after the cursor": the watermark in
/// [`crate::session::Attachment`] sheds a backlog *after* it is in memory, and a
/// resume from position zero on a long-lived `TwinNet` would otherwise
/// materialise the whole log before the watermark ever saw it.
const C2_BATCH: usize = 256;

/// How often an idle C2 stream asks the log whether anything happened.
///
/// Polling, and not a broadcast bus, on purpose: the log is the only thing that
/// knows the committed order, and a bus would be a second ordering to keep in
/// step with it. ADR-0002 N-5 makes every durable event independently
/// applicable, so a device that learns of one 50 ms late applies it identically.
const C2_POLL: Duration = Duration::from_millis(50);

/// Everything one front-end needs to serve.
pub struct ControlPlane {
    store: Arc<dyn ControlStore>,
    verifier: Arc<dyn StatementVerifier>,
    identity: Arc<dyn PeerIdentityVerifier>,
    attachments: Arc<Attachments>,
    limiter: AcceptLimiter,
    metrics: Metrics,
    coordination_endpoints: Vec<String>,
    quorum_available: bool,
}

/// The half of a [`Peer`] the TLS handshake settles, before an attachment epoch
/// exists to complete it.
struct Established {
    identity_cose_key: Vec<u8>,
    binding: [u8; 32],
}

/// What one accepted connection established about its peer.
///
/// Every field is **proved**, not claimed. TLS 1.3's `CertificateVerify` is a
/// signature over the handshake transcript, so the peer holds the private half
/// of the key these were computed from, and the exporter is read from the live
/// connection rather than from any message on it.
struct Peer {
    /// The derived identity — the `device_id` for a generation-0 key, and the
    /// value [`ControlPlane::caller_for`] resolves for any other.
    derived: DeviceKey,
    /// The presented key as COSE_Key octets, for [`crate::domain::caller_key`].
    identity_cose_key: Vec<u8>,
    /// This connection's RFC 9266 `tls-exporter` value.
    binding: [u8; 32],
    /// The attachment epoch, for N-1's "the older one is closed".
    epoch: u64,
}

impl ControlPlane {
    /// Binds the pieces a front-end serves with.
    #[must_use]
    pub fn new(
        store: Arc<dyn ControlStore>,
        verifier: Arc<dyn StatementVerifier>,
        identity: Arc<dyn PeerIdentityVerifier>,
        metrics: Metrics,
        cfg: &crate::ControlPlaneConfig,
        coordination_endpoints: Vec<String>,
    ) -> Self {
        Self {
            store,
            verifier,
            identity,
            attachments: Arc::new(Attachments::new()),
            limiter: AcceptLimiter::new(
                cfg.attach_rate_sustained,
                cfg.attach_rate_burst,
                Instant::now(),
            ),
            metrics,
            coordination_endpoints,
            // ADR-0002 §11.3: an E-1-class write with quorum unreachable is
            // REFUSED, never committed locally. `TWINVPN_CP_QUORUM_REPLICAS`
            // records the operator's intent so a T1 deployment cannot silently
            // run as a T2 one; nothing here counts acknowledgements, because
            // nothing here replicates (`README.md` §10 item 3).
            quorum_available: !cfg.requires_quorum(),
        }
    }

    /// How many devices are attached to this front-end.
    #[must_use]
    pub fn attached(&self) -> usize {
        self.attachments.len()
    }

    /// Accepts until the drain begins, then closes the endpoint.
    ///
    /// Returns when every accepted connection has been closed. The drain itself
    /// is [`ShutdownHandle`]'s: this loop stops *admitting*, and each connection
    /// task closes with the draining application code so a client reconnects to another
    /// front-end rather than seeing a reset.
    pub async fn serve(self: Arc<Self>, endpoint: quinn::Endpoint, shutdown: ShutdownHandle) {
        tracing::info!(
            listen = ?endpoint.local_addr().ok(),
            alpn = %String::from_utf8_lossy(quic::ALPN),
            "C1/C2 listener accepting"
        );
        loop {
            let incoming = tokio::select! {
                () = shutdown.draining() => break,
                incoming = endpoint.accept() => match incoming {
                    Some(i) => i,
                    // The endpoint is closed; nothing further will arrive.
                    None => break,
                },
            };

            // §11.7 rule 3 (S-6): a deferral is a REFUSAL WITH A NUMBER, never a
            // silent drop. At the QUIC layer the number cannot be carried — no
            // stream exists yet — so the connection is refused and the retry
            // interval is logged with its registered code. A silently dropped
            // handshake is what turns a limiter into a retry storm.
            if let Err(err) = self.limiter.admit(Instant::now()) {
                err.emit(&self.metrics, "refused");
                incoming.refuse();
                continue;
            }
            let Some(guard) = shutdown.try_acquire() else {
                incoming.refuse();
                continue;
            };

            let this = Arc::clone(&self);
            let handle = shutdown.clone();
            tokio::spawn(async move {
                this.connection(incoming, handle).await;
                drop(guard);
            });
        }
        // Closes every live connection with the draining code, and stops the
        // socket. `wait_idle` is the caller's business: `Shutdown` already waits
        // for the in-flight guards these tasks hold.
        endpoint.close(close::DRAINING.into(), b"draining");
        tracing::info!("C1/C2 listener stopped accepting");
    }

    /// One connection: handshake, attach, and its C1 streams.
    async fn connection(self: Arc<Self>, incoming: quinn::Incoming, shutdown: ShutdownHandle) {
        // `quic::accept` awaits the `Connecting` future and never calls
        // `into_0rtt` — control 3 of 3 (ADR-0001 R8).
        let (connection, derived) = match quic::accept(incoming, &*self.identity).await {
            Ok(pair) => pair,
            Err(err) => {
                err.emit(&self.metrics, "handshake_rejected");
                return;
            }
        };

        let established = match Self::established(&connection) {
            Ok(established) => established,
            Err(err) => {
                err.emit(&self.metrics, "handshake_rejected");
                connection.close(close::UNFRAMED.into(), b"no channel binding");
                return;
            }
        };

        // N-1: the NEWER connection wins and the older is closed. A device that
        // reattached did so because its old connection was, from its side,
        // already gone. The epoch is taken from the attach that assigned it —
        // there is no path on which a `Peer` carries an epoch nobody issued.
        let attached = self.attachments.attach(derived);
        if attached.superseded_previous {
            self.metrics
                .counter(
                    "twinvpn_cp_attach_superseded_total",
                    "older control connections closed by a newer attach (ADR-0002 N-1)",
                    Labels::new(),
                )
                .inc();
        }
        let peer = Peer {
            derived,
            identity_cose_key: established.identity_cose_key,
            binding: established.binding,
            epoch: attached.epoch,
        };
        self.metrics
            .gauge(
                "twinvpn_cp_attached_devices",
                "devices attached to this front-end",
                Labels::new(),
            )
            .set(i64::try_from(self.attachments.len()).unwrap_or(i64::MAX));

        let c2_started = Arc::new(AtomicBool::new(false));
        loop {
            // Checked every turn rather than once: the supersede can happen at
            // any moment, and a connection that kept serving past it would give
            // one identity two C1 streams with independent cursors.
            if !self.attachments.is_current(&peer.derived, peer.epoch) {
                connection.close(close::SUPERSEDED.into(), b"superseded by new attach");
                break;
            }
            let stream = tokio::select! {
                () = shutdown.draining() => {
                    connection.close(close::DRAINING.into(), b"draining");
                    break;
                }
                // N-1, answered at the moment of displacement rather than at the
                // next stream. A device that is only listening on C2 opens no
                // further C1 stream, so a loop that noticed only there would
                // never close the older connection at all.
                () = attached.superseded.notified() => {
                    connection.close(close::SUPERSEDED.into(), b"superseded by new attach");
                    break;
                }
                stream = connection.accept_bi() => stream,
            };
            // The peer closed, or the connection failed. Either way there is
            // nothing left to serve on it.
            let Ok((send, recv)) = stream else { break };

            let this = Arc::clone(&self);
            let conn = connection.clone();
            let started = Arc::clone(&c2_started);
            let peer = Peer {
                derived: peer.derived,
                identity_cose_key: peer.identity_cose_key.clone(),
                binding: peer.binding,
                epoch: peer.epoch,
            };
            // `acquire_unconditionally`, not `try_acquire`: this request was
            // already accepted, and §11.7's drain is "finish what you took, stop
            // taking more". Refusing it here would drop a request the client has
            // every reason to believe is in flight — and a ceremony dropped
            // between its effect and its response is exactly what the
            // idempotency contract exists to make survivable, not something to
            // cause on purpose.
            let inflight = shutdown.acquire_unconditionally();
            tokio::spawn(async move {
                this.c1_stream(&conn, &peer, &started, send, recv).await;
                drop(inflight);
            });
        }

        self.attachments.detach(&peer.derived, peer.epoch);
        self.metrics
            .gauge(
                "twinvpn_cp_attached_devices",
                "devices attached to this front-end",
                Labels::new(),
            )
            .set(i64::try_from(self.attachments.len()).unwrap_or(i64::MAX));
    }

    /// Reads what the handshake established, without trusting anything on it.
    fn established(connection: &quinn::Connection) -> Result<Established, ServiceError> {
        let presented = quic::presented_key(connection)?;
        let [spki_der] = presented.as_slice() else {
            return Err(codes::bare(
                twinvpn_types::codes::CONTROL_HANDSHAKE_REJECTED,
            ));
        };
        let channel = ChannelIdentity::new(spki_der.as_ref());
        Ok(Established {
            identity_cose_key: spki::spki_to_es256_cose_key(channel.as_bytes())
                .map_err(|_| codes::bare(twinvpn_types::codes::CONTROL_HANDSHAKE_REJECTED))?,
            // Read from the live connection, not from a message on it. That is
            // what makes the binding a binding (ADR-0002 N-2).
            binding: quic::channel_binding(connection)?,
        })
    }

    /// One C1 bidirectional stream: one request, one response, then FIN.
    async fn c1_stream(
        &self,
        connection: &quinn::Connection,
        peer: &Peer,
        c2_started: &Arc<AtomicBool>,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) {
        let mut header = [0u8; wire::HEADER_BYTES];
        if recv.read_exact(&mut header).await.is_err() {
            return;
        }
        let frame = match C1Frame::parse_header(&header) {
            Ok(frame) => frame,
            Err(reject) => {
                // There is no command, so there is no response message whose
                // `error` field could carry this. §7.1: a response that could
                // not be built at all closes the stream with an application
                // error code.
                ServiceError::from_reject(&reject, crate::COMPONENT)
                    .emit(&self.metrics, "unframed");
                connection.close(close::UNFRAMED.into(), b"unparseable C1 frame");
                return;
            }
        };

        // Allocated only after the declared length passed the frozen cap.
        let mut body = vec![0u8; frame.body_len];
        if recv.read_exact(&mut body).await.is_err() {
            return;
        }

        let response = self
            .execute(peer, frame.code, &body, connection, c2_started)
            .await;

        // The bound is applied on the way OUT as well: a service that can emit
        // an over-cap frame has a peer that must either reject it or raise its
        // own cap, and both are worse than failing at the sender.
        let Ok(out) = C1Frame::header_bytes(frame.code, response.len()) else {
            connection.close(close::UNFRAMED.into(), b"response above the C1 cap");
            return;
        };
        if send.write_all(&out).await.is_ok() && send.write_all(&response).await.is_ok() {
            let _ = send.finish();
        }
    }

    /// Runs one command and returns the response octets, refusal included.
    async fn execute(
        &self,
        peer: &Peer,
        code: CommandCode,
        body: &[u8],
        connection: &quinn::Connection,
        c2_started: &Arc<AtomicBool>,
    ) -> Vec<u8> {
        match self
            .try_execute(peer, code, body, connection, c2_started)
            .await
        {
            Ok(response) => response,
            Err(err) => {
                err.emit(&self.metrics, "refused");
                error_response(code, &err)
            }
        }
    }

    /// The fallible half, so every refusal leaves by one door.
    async fn try_execute(
        &self,
        peer: &Peer,
        code: CommandCode,
        body: &[u8],
        connection: &quinn::Connection,
        c2_started: &Arc<AtomicBool>,
    ) -> Result<Vec<u8>, ServiceError> {
        let metadata = dispatch::envelope_of(code, body)?
            .ok_or_else(|| codes::bare(twinvpn_types::codes::PROTO_UNPARSEABLE_ENVELOPE))?;

        // N-2, before the body is allowed to mean anything. An absent binding
        // and a wrong one are the same answer: neither is this connection's
        // exporter, and reporting them differently would leak the shape of what
        // was expected.
        let presented = metadata
            .auth
            .as_ref()
            .map(|a| a.channel_binding.as_slice())
            .unwrap_or_default();
        quic::check_channel_binding(&peer.binding, presented)?;

        // Every message is `TwinNet`-scoped (common.proto `twinnet_id`); a
        // request that names none names no state to act on.
        if metadata.twinnet_id.is_empty() {
            return Err(codes::bare(twinvpn_types::codes::PROTO_MALFORMED_MESSAGE));
        }
        let twinnet_id = metadata.twinnet_id.clone();

        let correlation = Correlation::from_metadata(&metadata)
            .map_err(|r| ServiceError::from_reject(&r, crate::COMPONENT))?;
        correlation.record_on_current_span();

        let caller = self.caller_for(&twinnet_id, peer.derived).await?;

        let committed = self
            .store
            .execute(Request {
                twinnet_id: &twinnet_id,
                caller,
                caller_identity_key: Some(&peer.identity_cose_key),
                now_ms: now_ms(),
                now: Instant::now(),
                verifier: &*self.verifier,
                quorum_available: self.quorum_available,
                correlation,
                coordination_endpoints: &self.coordination_endpoints,
                code,
                body,
            })
            .await?;

        if committed.idempotent_replay {
            // ADR-0008 §10.2's observable. A retry that appended nothing is a
            // client behaving correctly, and it is counted as such rather than
            // being invisible.
            self.metrics
                .counter(
                    "twinvpn_cp_idempotent_replay_total",
                    "recorded ceremony outcomes served to a duplicate",
                    Labels::new().with(Label::Outcome, "replayed"),
                )
                .inc();
        }

        // The C2 stream starts on the request that asked for it, and only once
        // per connection: `SubscribeEvents` is idempotent as a *read*, and a
        // second pump would give one device two cursors on one connection.
        if code == CommandCode::SubscribeEvents && !c2_started.swap(true, Ordering::SeqCst) {
            // The cursor is the one the DEVICE asked to resume from, not the
            // head the response reports. A device that asks from zero is asking
            // to re-read the log declaratively — which is always correct (N-5)
            // and is the recovery path from every compaction and every rebuilt
            // cache — and starting it at the head instead would silently deliver
            // it nothing.
            let from_net_seq = <v1::SubscribeEventsRequest as prost::Message>::decode(body)
                .map(|req| req.from_net_seq)
                .unwrap_or_default();
            self.spawn_c2(
                connection,
                peer,
                &twinnet_id,
                from_net_seq,
                &committed.response,
            );
        }

        Ok(committed.response)
    }

    /// Resolves the derived identity to the `device_id` it currently names.
    ///
    /// A miss resolves to the derived value itself, which for a generation-0 key
    /// **is** the `device_id` (`identifiers.md` §2). That is not a grant: it is
    /// the only name that key can speak for, and every handler refuses it with
    /// `AUTH.PEER_UNTRUSTED` until a `RegisterDevice` carrying an `Owner`-signed
    /// enrolment proof admits it.
    ///
    /// Resolved per request rather than cached per connection, deliberately. The
    /// mapping changes under a rotation, and a device that rotates on a live
    /// connection *should* stop being served on the key it just superseded.
    async fn caller_for(
        &self,
        twinnet_id: &str,
        derived: DeviceKey,
    ) -> Result<DeviceKey, ServiceError> {
        Ok(self
            .store
            .device_for_identity(twinnet_id, derived)
            .await?
            .unwrap_or(derived))
    }

    /// Opens the C2 unidirectional stream and pumps it until the peer goes away.
    fn spawn_c2(
        &self,
        connection: &quinn::Connection,
        peer: &Peer,
        twinnet_id: &str,
        from_net_seq: u64,
        subscribe_response: &[u8],
    ) {
        // §11.6's priority rule: `revocation_epoch` and `pending_net_seq` are
        // served in the ATTACH RESPONSE itself, before any event body. They are
        // read out of the response that is already on its way back — not fetched
        // again here, which would be a second read that could disagree with the
        // one the device was told.
        let priority =
            match <v1::SubscribeEventsResponse as prost::Message>::decode(subscribe_response) {
                Ok(resp) => AttachPriority {
                    revocation_epoch: resp.revocation_epoch,
                    pending_net_seq: resp.current_net_seq,
                },
                // Unreachable: this is this service's own encoding of its own
                // response. Not serving a stream is the safe half of the branch.
                Err(_) => return,
            };
        tracing::debug!(
            revocation_epoch = priority.revocation_epoch,
            pending_net_seq = priority.pending_net_seq,
            "C2 attach: the security-critical fact went out in RTT 1"
        );

        let store = Arc::clone(&self.store);
        let attachments = Arc::clone(&self.attachments);
        let metrics = self.metrics.clone();
        let connection = connection.clone();
        let twinnet_id = twinnet_id.to_owned();
        let device_id = peer.derived;
        let epoch = peer.epoch;
        tokio::spawn(async move {
            let Ok(mut send) = connection.open_uni().await else {
                return;
            };
            let mut attachment =
                Attachment::new(device_id, epoch, Rung::Quic, from_net_seq, metrics.clone());
            loop {
                if !attachments.is_current(&device_id, epoch) {
                    return;
                }
                let events = match store
                    .events_from(&twinnet_id, attachment.cursor(), C2_BATCH)
                    .await
                {
                    Ok(events) => events,
                    Err(err) => {
                        // A cursor below the retention floor, or a store that
                        // went away. Both are terminal for this stream and the
                        // device re-snapshots declaratively, which is always
                        // correct (N-5).
                        err.emit(&metrics, "c2_stopped");
                        return;
                    }
                };
                if events.is_empty() {
                    tokio::time::sleep(C2_POLL).await;
                    continue;
                }

                let pumped = match attachment.pump(&events) {
                    Ok(pumped) => pumped,
                    Err(err) => {
                        // CONTROL.EVENT_WRONG_PUBLISHER: a security event, and
                        // the last point before the octets leave the process.
                        err.emit(&metrics, "c2_stopped");
                        return;
                    }
                };
                let records = match pumped {
                    Pumped::Records(records) => records,
                    // N-8: the gap is ANNOUNCED, in band and in order. The
                    // cursor moves only once the announcement is actually on the
                    // wire — a cursor advanced before it is a silent gap.
                    Pumped::Compacted { up_to_net_seq } => {
                        let Some(record) =
                            compaction_announcement(&twinnet_id, up_to_net_seq, now_ms())
                        else {
                            return;
                        };
                        if write_c2_record(&mut send, &record).await.is_err() {
                            return;
                        }
                        attachment.confirm_compaction(up_to_net_seq);
                        continue;
                    }
                };
                for record in records {
                    if write_c2_record(&mut send, &record).await.is_err() {
                        return;
                    }
                }
            }
        });
    }
}

/// Frames and writes one C2 record.
async fn write_c2_record(send: &mut quinn::SendStream, body: &[u8]) -> Result<(), ()> {
    let header = wire::c2_header_bytes(body.len()).map_err(|_| ())?;
    send.write_all(&header).await.map_err(|_| ())?;
    send.write_all(body).await.map_err(|_| ())
}

/// The `StreamCompacted` announcement, encoded as a C2 record.
///
/// Built through [`crate::event::DurableEvent`] rather than assembled here, so
/// its `durability` and `publisher` come from the one table
/// `tests/client_agreement.rs` pins against the client's own — an announcement
/// that disagreed with that table would be rejected by the device that needs it
/// most.
///
/// It is **not** appended to the durable log. A shed backlog is a fact about one
/// connection's queue, not about the `TwinNet`; logging it would give every other
/// device a position describing a queue it does not have.
fn compaction_announcement(twinnet_id: &str, up_to_net_seq: u64, now_ms: u64) -> Option<Vec<u8>> {
    let body = v1::control_event::Event::StreamCompacted(v1::StreamCompacted { up_to_net_seq });
    let announcement = event::DurableEvent::new(body).ok()?;
    let wire = announcement.to_wire(twinnet_id, up_to_net_seq, now_ms, &Correlation::empty());
    Some(prost::Message::encode_to_vec(&wire))
}

/// Wall-clock milliseconds.
///
/// Advisory, and never a guard: every window this service enforces is checked
/// against the value passed *into* the domain, so a decision is reproducible
/// from its inputs. A clock before the epoch yields zero rather than panicking.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The command's own response message, carrying the refusal.
///
/// One arm per command code and **no wildcard**: a new command that fell through
/// to a default would answer a refusal in the wrong message type, which a client
/// would decode as a differently-shaped success. `ErrorEnvelope` carries the
/// registered `reason_code` and its typed evidence and no message string (CF-4).
#[must_use]
pub fn error_response(code: CommandCode, err: &ServiceError) -> Vec<u8> {
    use prost::Message as _;
    let error = Some(err.envelope());
    match code {
        CommandCode::RegisterDevice => v1::RegisterDeviceResponse {
            error,
            ..Default::default()
        }
        .encode_to_vec(),
        CommandCode::UpdateDeviceMetadata => v1::UpdateDeviceMetadataResponse {
            error,
            ..Default::default()
        }
        .encode_to_vec(),
        CommandCode::RevokeDevice => v1::RevokeDeviceResponse {
            error,
            ..Default::default()
        }
        .encode_to_vec(),
        CommandCode::RotateDeviceCredential => v1::RotateDeviceCredentialResponse {
            error,
            ..Default::default()
        }
        .encode_to_vec(),
        CommandCode::BeginPairing => v1::BeginPairingResponse {
            error,
            ..Default::default()
        }
        .encode_to_vec(),
        CommandCode::CompletePairing => v1::CompletePairingResponse {
            error,
            ..Default::default()
        }
        .encode_to_vec(),
        CommandCode::CancelPairing => v1::CancelPairingResponse {
            error,
            ..Default::default()
        }
        .encode_to_vec(),
        CommandCode::RevokePairing => v1::RevokePairingResponse {
            error,
            ..Default::default()
        }
        .encode_to_vec(),
        CommandCode::DiscoverPeers => v1::DiscoverPeersResponse {
            error,
            ..Default::default()
        }
        .encode_to_vec(),
        CommandCode::PublishPresence => v1::PublishPresenceResponse {
            error,
            ..Default::default()
        }
        .encode_to_vec(),
        CommandCode::PutRouteAdvertisement => v1::PutRouteAdvertisementResponse {
            error,
            ..Default::default()
        }
        .encode_to_vec(),
        CommandCode::WithdrawRouteAdvertisement => v1::WithdrawRouteAdvertisementResponse {
            error,
            ..Default::default()
        }
        .encode_to_vec(),
        CommandCode::PutExitNodeOffer => v1::PutExitNodeOfferResponse {
            error,
            ..Default::default()
        }
        .encode_to_vec(),
        CommandCode::WithdrawExitNodeOffer => v1::WithdrawExitNodeOfferResponse {
            error,
            ..Default::default()
        }
        .encode_to_vec(),
        CommandCode::PutPolicy => v1::PutPolicyResponse {
            error,
            ..Default::default()
        }
        .encode_to_vec(),
        CommandCode::SubscribeEvents => v1::SubscribeEventsResponse {
            error,
            ..Default::default()
        }
        .encode_to_vec(),
        CommandCode::GetStateDocument => v1::GetStateDocumentResponse {
            error,
            ..Default::default()
        }
        .encode_to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::{compaction_announcement, error_response};
    use crate::{codes, Command, CommandCode};
    use prost::Message as _;
    use twinvpn_schema::v1;

    #[test]
    fn every_command_can_carry_a_refusal_in_its_own_response() {
        // §7.1: there is no separate error frame. If any command could not, its
        // refusal would have to invent a shape the client cannot decode.
        let err = codes::bare(twinvpn_types::codes::AUTH_PEER_UNTRUSTED);
        for command in Command::ALL {
            let code = CommandCode::of(command);
            let bytes = error_response(code, &err);
            assert!(!bytes.is_empty(), "{}", command.as_str());
        }
    }

    #[test]
    fn a_refusal_carries_the_registered_code_and_no_message() {
        // CF-4: `ErrorEnvelope` has no message field and never encodes one, so
        // there is nowhere for a driver's text — which can name a host, a user
        // and a constraint — to reach the wire.
        let err = codes::device_revoked(9);
        let bytes = error_response(CommandCode::RegisterDevice, &err);
        let decoded = v1::RegisterDeviceResponse::decode(bytes.as_slice()).expect("decodes");
        let envelope = decoded.error.expect("the refusal is in the response");
        assert_eq!(envelope.reason_code, "AUTH.DEVICE_REVOKED");
        assert!(decoded.device_id_echo.is_empty(), "no echo on a refusal");
    }

    #[test]
    fn the_compaction_announcement_is_the_events_own_publisher_and_durability() {
        // The device rejects an event whose publisher is not its type's sole
        // publisher (`Attachment::pump`, and the client does the same). An
        // announcement assembled by hand here could disagree with that table;
        // one built through `DurableEvent` cannot.
        let bytes = compaction_announcement("twinnet-1", 42, 1_000).expect("announces");
        let event = v1::ControlEvent::decode(bytes.as_slice()).expect("decodes");
        assert_eq!(
            event.publisher,
            crate::EventKind::StreamCompacted.sole_publisher().to_wire()
        );
        assert_eq!(
            event.durability,
            crate::EventKind::StreamCompacted.durability().to_wire()
        );
        let metadata = event.metadata.expect("metadata");
        assert_eq!(metadata.net_seq, 42, "the position the device lands on");
        assert_eq!(metadata.twinnet_id, "twinnet-1");
        match event.event {
            Some(v1::control_event::Event::StreamCompacted(c)) => {
                assert_eq!(c.up_to_net_seq, 42);
            }
            other => panic!("wrong body: {other:?}"),
        }
    }
}
