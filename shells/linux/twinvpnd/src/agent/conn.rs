//! One management connection: attach, negotiate, and the two directions.
//!
//! **Authority:** [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.7 (the negotiation and its mismatch table), §11.10 (the event stream),
//! MI-3, MI-A1, MI-A5, MI-S1, MI-I5-2; ADR-0016 PS-3.
//!
//! # Why the socket is split
//!
//! A connection carries traffic in **both** directions at once: the client's
//! requests, and the agent's unsolicited [`crate::mi::wire::Event`] frames. Wave 1 had only the
//! first, so one task owning the whole socket was enough.
//!
//! It is not enough now, and the reason is subtle enough to be worth stating:
//! [`crate::mi::codec::read_frame`] is **not cancel-safe**. It reads a four-byte
//! length prefix and then the body; a `select!` that dropped it between those two
//! reads would leave the body in the socket and desynchronise the stream — the
//! next read would take a body for a prefix, and MI-20's one contract would be
//! broken by the carriage rather than by the contract.
//!
//! So the socket is split. The reader is owned by one task and is never
//! cancelled mid-frame. The writer is shared behind a mutex, because two
//! producers — this task's responses and the pump's events — must not interleave
//! bytes inside one frame.
//!
//! ```text
//!   UnixStream
//!     ├── OwnedReadHalf  ─► request loop        (never cancelled mid-frame)
//!     └── OwnedWriteHalf ─► Mutex ─┬─ responses (this task)
//!                                  └─ events    (the pump task)
//! ```
//!
//! # PS-3, on the way out
//!
//! > Loss of the last management client MUST NOT change `session_intent`,
//! > enforcement mode, the installed rule set, or any `ConnectionState`.
//!
//! Nothing in this module touches any of them on the way out. The only teardown
//! is `Fanout::unsubscribe`, which removes a queue.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::mi::codec::TransportError;
use crate::mi::codec::{read_frame, write_frame};
use crate::mi::scope::Scopes;
use crate::mi::wire::{Body, Hello, HelloAck, Response, MI_VERSION, MI_VERSION_MIN};
use crate::{AGENT_VERSION, BUILD_PROFILE};

use super::events::{Delivery, SUBSCRIBER_WATERMARK};
use super::peer::Principal;
use super::server::{self, ServerContext};

/// Serves one connection to completion.
///
/// # Errors
///
/// The frame error that ended it. A clean [`TransportError::Closed`] is the normal
/// case.
pub async fn serve(
    context: Arc<ServerContext>,
    stream: tokio::net::UnixStream,
) -> Result<(), TransportError> {
    // MI-A1/MI-A5: the identity comes from the kernel, and an unverifiable one
    // is rejected and closed — never a default principal, never an anonymous
    // read-only tier. Read before the split, because `SO_PEERCRED` is a property
    // of the socket rather than of either half.
    let principal = match Principal::from_stream(&stream) {
        Ok(principal) => principal,
        Err(error) => {
            let (_, mut writer) = stream.into_split();
            let reject = server::envelope(
                context.as_of_ms(),
                Body::Reject(server::diagnostic(
                    error.reason_code(),
                    "PERSISTENT",
                    "ERROR",
                    true,
                )),
            );
            // Answered, THEN closed. §11.7: a silent close is indistinguishable
            // from "the agent is not running".
            write_frame(&mut writer, &reject).await?;
            return Ok(());
        }
    };

    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(tokio::sync::Mutex::new(writer));

    let held = principal.scopes(&context.groups);
    let Some((granted, wants_events)) = negotiate(&context, &mut reader, &writer, &held).await?
    else {
        return Ok(());
    };

    tracing::info!(
        target: "twinvpn.mi",
        principal = %principal.actor(),
        pid = principal.pid,
        scopes = ?granted.names(),
        "a management client attached"
    );

    // §11.10's stream, if the client asked for it and holds `mgmt.events`.
    // Registering the subscriber at attach rather than at the first published
    // event is what makes "attached and has missed nothing" a real state: a
    // subscriber registered later would silently start from a cursor the client
    // never saw.
    let subscription = (wants_events && granted.holds(twinvpn_mgmt::Scope::Events))
        .then(|| context.fanout.subscribe(SUBSCRIBER_WATERMARK));
    let pump = subscription.map(|id| {
        let fanout = Arc::clone(&context.fanout);
        let writer = Arc::clone(&writer);
        let as_of = Arc::clone(&context);
        tokio::spawn(async move { pump_events(&fanout, &writer, id, &as_of).await })
    });

    let outcome = request_loop(
        &context,
        &principal,
        &granted,
        subscription,
        &mut reader,
        &writer,
    )
    .await;

    // PS-3: the only teardown is a queue. No `session_intent`, no enforcement
    // mode, no installed rule set, no `ConnectionState`.
    if let Some(id) = subscription {
        context.fanout.unsubscribe(id);
    }
    if let Some(pump) = pump {
        // CD-2: "cancellation is dropping the future." The pump's write fails
        // once the peer is gone, so it ends on its own; the abort is the
        // belt-and-braces for a peer that is gone but whose socket buffer is not
        // yet full.
        pump.abort();
    }
    outcome
}

/// The client → agent direction.
async fn request_loop<R, W>(
    context: &Arc<ServerContext>,
    principal: &Principal,
    granted: &Scopes,
    subscription: Option<u64>,
    reader: &mut R,
    writer: &Arc<tokio::sync::Mutex<W>>,
) -> Result<(), TransportError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        // Never inside a `select!`: see this module's documentation.
        let request = match read_frame(reader).await {
            Ok(envelope) => envelope,
            Err(TransportError::Closed) => {
                // PS-3, made visible: the client going away is an INFO, and
                // nothing else happens.
                tracing::info!(
                    target: "twinvpn.mi",
                    principal = %principal.actor(),
                    "a management client detached; the agent continues unchanged"
                );
                return Ok(());
            }
            Err(error) => {
                let reject = server::envelope(
                    context.as_of_ms(),
                    Body::Reject(server::diagnostic(
                        error.reason_code().as_str(),
                        "PERSISTENT",
                        "ERROR",
                        false,
                    )),
                );
                let _ = write_frame(&mut *writer.lock().await, &reject).await;
                return Err(error);
            }
        };

        // MI-3: the agent never receives a response or an event. A client that
        // sends one has broken the protocol.
        if !request.body.is_client_originated() {
            let reject = server::envelope(
                context.as_of_ms(),
                Body::Reject(server::diagnostic(
                    "PROTO.UNPARSEABLE_ENVELOPE",
                    "PERSISTENT",
                    "ERROR",
                    false,
                )),
            );
            write_frame(&mut *writer.lock().await, &reject).await?;
            return Ok(());
        }

        let response = match request.body {
            // **The `idempotency_key` travels on the ENVELOPE, not on the
            // `Request`** (§11.3), so it has to be handed across here. It used
            // to be dropped — `dispatch` built its `Submission` with `None` —
            // which made every `CEREMONY`-class operation refuse
            // `MGMT.PRECONDITION_FAILED` no matter what the client sent.
            // `pair.begin` is one of them, so C-B was unreachable over MI even
            // once the core could perform it. MI-2 is why the value is the
            // envelope's rather than the request's: "a retry reuses
            // `idempotency_key`, never `request_id`", and only the envelope
            // carries both.
            Body::Request(ref call) => {
                server::dispatch(
                    context,
                    principal,
                    granted,
                    subscription,
                    call,
                    &request.idempotency_key,
                )
                .await
            }
            Body::Goodbye => return Ok(()),
            // A second `Hello` on one connection: §11.7 fixes the version "for
            // the life of the connection", so there is nothing to renegotiate.
            Body::Hello(_) => Response {
                ok: false,
                result: Vec::new(),
                diagnostic: Some(server::diagnostic(
                    "PROTO.UNPARSEABLE_ENVELOPE",
                    "PERSISTENT",
                    "ERROR",
                    false,
                )),
                committed_at_net_seq: None,
            },
            _ => unreachable!("is_client_originated already excluded these"),
        };

        let mut reply = server::envelope(context.as_of_ms(), Body::Response(response));
        reply.correlation_id = request.request_id;
        write_frame(&mut *writer.lock().await, &reply).await?;
    }
}

/// The agent → client direction: §11.10's ordered event stream.
///
/// Ends when a write fails — which is what a closed peer looks like — or when
/// the fan-out closes during shutdown.
async fn pump_events<W>(
    fanout: &Arc<super::events::Fanout>,
    writer: &Arc<tokio::sync::Mutex<W>>,
    id: u64,
    context: &Arc<ServerContext>,
) where
    W: AsyncWrite + Unpin,
{
    loop {
        // Drain everything queued before waiting again, so a burst costs one
        // wake rather than one wake per event.
        while let Some(delivery) = fanout.next_for(id) {
            let body = match delivery {
                Delivery::Event { seq, event } => {
                    let mut envelope = server::envelope(context.as_of_ms(), Body::Event(event));
                    // MI-16: the core's own sequence number, carried unchanged.
                    // A contiguous `seq` proves no event was lost.
                    envelope.seq = seq;
                    envelope
                }
                // MI-19's ordered gap marker, in the stream position the gap
                // occupied.
                Delivery::Compacted(marker) => {
                    server::envelope(context.as_of_ms(), Body::Compacted(marker))
                }
            };
            if write_frame(&mut *writer.lock().await, &body).await.is_err() {
                return;
            }
        }
        if fanout.is_closed() {
            return;
        }
        fanout.wait().await;
    }
}

/// §11.7's `Hello`/`HelloAck`, including its mismatch table.
///
/// Returns `None` when the connection was rejected and closed, and otherwise the
/// granted scopes plus whether the client asked for the event stream.
async fn negotiate<R, W>(
    context: &ServerContext,
    reader: &mut R,
    writer: &Arc<tokio::sync::Mutex<W>>,
    held: &Scopes,
) -> Result<Option<(Scopes, bool)>, TransportError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let hello = read_frame(reader).await?;
    let Body::Hello(Hello {
        mi_version_min,
        mi_version_max,
        requested_scopes,
        subscribe_topics,
        ..
    }) = hello.body
    else {
        // MI-3: the first message on a connection is a `Hello`. Anything else
        // is answered and closed, never silently dropped.
        let reject = server::envelope(
            context.as_of_ms(),
            Body::Reject(server::diagnostic(
                "PROTO.UNPARSEABLE_ENVELOPE",
                "PERSISTENT",
                "ERROR",
                false,
            )),
        );
        write_frame(&mut *writer.lock().await, &reject).await?;
        return Ok(None);
    };

    // §11.7's mismatch table. Both refusals name a REGISTERED code and are
    // written, then the connection closes — "A silent close is prohibited: it is
    // indistinguishable from 'the agent is not running', and it sends the user
    // to reinstall rather than to update."
    if mi_version_max < MI_VERSION_MIN || mi_version_min > MI_VERSION {
        let reject = server::envelope(
            context.as_of_ms(),
            // ADR-0017 spells these `MGMT.VERSION_TOO_OLD` / `TOO_NEW`, neither
            // of which the frozen registry carries. `PROTO.VERSION_UNSUPPORTED`
            // is the nearest registered code; the CLI maps it to exit 5.
            Body::Reject(server::diagnostic(
                "PROTO.VERSION_UNSUPPORTED",
                "PERSISTENT",
                "ERROR",
                true,
            )),
        );
        write_frame(&mut *writer.lock().await, &reject).await?;
        return Ok(None);
    }

    // §11.7: "Select `min(maxes)`; fixed for the connection."
    let selected = mi_version_max.min(MI_VERSION);
    // MI-S1: `policy(principal) ∩ requested`, with the difference NAMED.
    let (granted, withheld) = held.grant(&requested_scopes);

    let ack = HelloAck {
        mi_version: selected,
        agent_version: AGENT_VERSION.to_owned(),
        build_profile: BUILD_PROFILE.to_owned(),
        granted_scopes: granted.names(),
        withheld_scopes: withheld,
        // §11.7: "The catalogue, not the version, is the capability contract."
        // Taken from the core's own catalogue so it cannot disagree with what
        // this agent would actually serve.
        catalogue_digest: twinvpn_mgmt::catalogue_digest_text(),
        // The attach cursor: a client that reattaches offering this value has
        // missed nothing, and one offering less has (§11.10, MI-9a). Taken from
        // the fan-out rather than from the core, because the fan-out is what
        // this client will actually be reading.
        event_cursor: context.fanout.cursor(),
        protocol_epoch_range: epoch_range(),
        platform_ctx: context.platform_ctx.clone(),
    };
    let reply = server::envelope(context.as_of_ms(), Body::HelloAck(Box::new(ack)));
    write_frame(&mut *writer.lock().await, &reply).await?;
    Ok(Some((granted, !subscribe_topics.is_empty())))
}

/// VR-3's epoch **table**, read from the core rather than inferred.
///
/// ADR-0018 VR-3 forbids inferring the epoch from `core_version`, and
/// `twinvpn_core::EPOCH_TABLE` is the table it requires instead.
fn epoch_range() -> [u32; 2] {
    twinvpn_core::EPOCH_TABLE.first().map_or([1, 1], |row| {
        [row.protocol_epoch_min, row.protocol_epoch_max]
    })
}
