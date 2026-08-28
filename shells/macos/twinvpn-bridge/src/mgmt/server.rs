//! The MI server: one connection, one principal, one immutable scope set.
//!
//! **Authority:** ADR-0017 MI-1, MI-3, MI-5, MI-7, MI-14, MI-15, MI-16, MI-18,
//! MI-20, MI-21, MI-A1, MI-A5, MI-S1, MI-S2, §11.7 (the mismatch table);
//! ADR-0016 PS-3, PS-4, PS-13, PS-22.
//!
//! # PS-22 (§11.3): this module does not link the datapath
//!
//! > **Rule PS-22 — the management server does not link the datapath.** The
//! > management-interface server lives in the authority process (PS-1) but MUST
//! > be a module with **no dependency edge** onto the tunnel engine,
//! > packet-routing, or enforcement modules: it reaches them only through the
//! > same typed operation vocabulary PS-4 defines, and it MUST NOT be reachable
//! > *from* them.
//!
//! **This rule got harder to keep, and that is the point.** Before X-7 the MI
//! server was in a different *binary* from the datapath, so the assertion was a
//! crate-graph one and it held by accident. PS-22's §11.2 amendment moved the
//! authority into the system extension, and this module now lives in the same
//! crate as [`crate::ext`] and [`crate::port`] — which is exactly the shape
//! ADR-0017 A-12 predicted: *"MI-I5-1's assertion becomes a **module**-graph
//! rather than a **binary**-graph check. The check is unchanged in kind; only
//! its granularity moves."*
//!
//! So the check is now the only thing keeping it true. The edge is
//! [`CommandSink::submit`] and nothing else; there is no `use
//! twinvpn_platform_macos`, no `use crate::ext` and no `use crate::port` in this
//! file, and the test at the bottom asserts it over the source — so the day
//! somebody reaches for `pf::render` or for `BridgePort` from a request handler,
//! the build says so rather than a reviewer having to notice.
//!
//! **The edge is a trait rather than `twinvpn_core::Core` directly.** PS-22 asks
//! for "no dependency edge onto the tunnel, routing or enforcement modules …
//! only via PS-4's typed vocabulary", and a one-method trait over `Submission`
//! *is* that vocabulary. It also makes the authorization ladder testable on this
//! host with a recording sink, which is most of what this module is. (Until
//! wave 3 there was a third, accidental reason — `twinvpn-core` pulled `ring`,
//! whose C sources could not be cross-compiled to `aarch64-apple-darwin` here.
//! `core/Cargo.toml` now selects `snow`'s default resolver and that reason is
//! gone. The trait stays because the first two were the real ones.)
//!
//! # Two carriages, one server
//!
//! ADR-0017 §11.2's macOS row gives this platform an `AF_UNIX` socket **and** an
//! XPC Mach service. [`serve`] is the socket's loop; [`super::session::Session`]
//! is the XPC one. Everything either of them decides — the version window, the
//! grant, the catalogue lookup, the authorization ladder, the reply — is in this
//! file, called from both, so the two carriages cannot answer differently.
//!
//! # PS-4: no raw pass-through
//!
//! Every request names an operation from the **catalogue** and carries opaque
//! encoded params. There is no path by which a client supplies rule text, a route
//! spec, a resolver address, a filesystem path, a command line or a library path
//! — because [`twinvpn_mgmt::CoreCommand`] is a closed enum and an unrecognised
//! name is a typed rejection rather than a string that reaches anything.

use std::sync::Arc;

use twinvpn_mgmt::{CoreCommand, Submission};

use crate::mgmt::peer::{GroupPolicy, PeerCredentials};
use twinvpn_mi::codec::{self, FrameError};
use twinvpn_mi::wire::{
    Body, Diagnostic, Hello, HelloAck, MgmtEnvelope, PlatformCtx, Response, MI_VERSION,
    MI_VERSION_MIN,
};
use twinvpn_mi::Scopes;

/// Where a submitted command goes. **PS-4's typed vocabulary, as a trait.**
///
/// One method, taking a [`Submission`] — an operation from the closed
/// [`CoreCommand`] enum, opaque encoded params, and the acting principal. There
/// is no method here that takes rule text, a route spec, a resolver address, a
/// filesystem path, a command line or a library path, and there is no way to add
/// one without changing this trait.
pub trait CommandSink: Send + Sync {
    /// Submits one command.
    ///
    /// # Errors
    ///
    /// The core's own [`twinvpn_types::Diagnostic`], carrying a registered
    /// `reason_code`.
    fn submit(&self, submission: &Submission) -> Result<(), Box<twinvpn_types::Diagnostic>>;
}

/// What a connection needs that is not on the wire.
#[derive(Clone)]
pub struct ServerContext {
    /// The hosted core. The **only** edge out of this module (PS-22).
    pub core: Arc<dyn CommandSink>,
    /// The OS principals PS-12a's classes come from.
    pub policy: GroupPolicy,
    /// This host's OS version, for MI-C3's `platform_ctx`.
    pub os_version: String,
    /// The suspend-inclusive clock MI-16's `as_of_ms` is stamped on.
    ///
    /// Injected (CD-2). On this platform it is `mach_continuous_time`; a
    /// `SystemTime` here would make `as_of_ms` a wall-clock reading, which MI-16
    /// forbids because a wall clock can go backwards.
    pub elapsed: Arc<dyn twinvpn_env::ElapsedClock>,
    /// **§11.10's event stream.** One drain, N connections.
    ///
    /// Absent until `ownership.md` §10.8 **M-1**'s work: the core's handle was
    /// swallowed by a `CommandSink` that exposes only `submit`, so the event
    /// stream was unreachable by construction. `crate::host` owns the drain —
    /// PS-22 keeps `twinvpn_core` out of this module — and this is the seam it
    /// publishes through.
    pub fanout: Arc<super::events::Fanout>,
}

impl ServerContext {
    fn as_of_ms(&self) -> u64 {
        self.elapsed.now().as_micros() / 1_000
    }

    fn platform_ctx(&self) -> PlatformCtx {
        PlatformCtx {
            platform: twinvpn_mi::PLATFORM.to_owned(),
            os_version: self.os_version.clone(),
        }
    }
}

/// Why a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// The client said goodbye, or closed cleanly.
    Closed,
    /// The client's identity could not be established (**MI-A5**).
    PrincipalUnverifiable,
    /// The version window did not overlap (§11.7).
    VersionMismatch,
    /// The framing failed.
    Framing(FrameError),
    /// The client sent a body only the agent may send (**MI-3**).
    DirectionViolation,
}

/// Serves one connection to completion.
///
/// # The order is the security property
///
/// The peer's credentials are read **before the first byte is parsed**. A server
/// that read `Hello` first would have to decide what to do with a client whose
/// identity it then could not establish, and every answer to that is worse than
/// not having asked.
pub async fn serve(mut stream: tokio::net::UnixStream, context: &ServerContext) -> Ending {
    use std::os::fd::AsRawFd as _;

    // MI-A1 and MI-A5. `None` closes; there is no anonymous principal to fall
    // back to, and no branch here that could invent one.
    let Some(credentials) = PeerCredentials::read(stream.as_raw_fd()) else {
        let _ = send(
            &mut stream,
            context,
            Body::Reject(Diagnostic::of(
                twinvpn_types::codes::MGMT_PRINCIPAL_UNVERIFIABLE,
            )),
        )
        .await;
        return Ending::PrincipalUnverifiable;
    };
    if credentials.groups_possibly_truncated {
        tracing::warn!(
            target: "twinvpn.mi",
            uid = credentials.uid,
            "the kernel's group list for this peer was full and may be truncated; \
             the granted scope set may be narrower than intended"
        );
    }
    // **S-44: re-derived at every attach, never cached across attaches.** This
    // value is computed here, on this connection, from the kernel's answer a
    // moment ago — there is no map from uid to scopes anywhere in this process.
    let principal = crate::mgmt::peer::scopes_for(&credentials, context.policy);

    // The `Hello` must come first (§11.7).
    let hello = match codec::read_frame(&mut stream).await {
        Ok(Some(envelope)) => match envelope.body {
            Body::Hello(hello) => hello,
            body if body.is_client_originated() => return Ending::DirectionViolation,
            _ => return Ending::DirectionViolation,
        },
        Ok(None) => return Ending::Closed,
        Err(error) => return Ending::Framing(error),
    };

    // §11.7's version negotiation. **Never a silent close**: a rejection the
    // client can read is what separates "update me" from "reinstall me".
    if hello.mi_version_max < MI_VERSION_MIN || hello.mi_version_min > MI_VERSION {
        let code = if hello.mi_version_max < MI_VERSION_MIN {
            twinvpn_types::codes::PROTO_VERSION_UNSUPPORTED
        } else {
            twinvpn_types::codes::PROTO_VERSION_DEPRECATED
        };
        let _ = send(&mut stream, context, Body::Reject(Diagnostic::of(code))).await;
        return Ending::VersionMismatch;
    }

    // **MI-S1**, and **MI-S2**: computed once, here, and never widened.
    let (granted, withheld) = principal.grant(&hello.requested_scopes);
    let ack = hello_ack(&hello, &granted, withheld, context);
    if send(&mut stream, context, Body::HelloAck(Box::new(ack)))
        .await
        .is_err()
    {
        return Ending::Closed;
    }

    // §11.10's stream, if the client asked for it and holds `mgmt.events`.
    //
    // An EMPTY topic list is "no stream", not "every topic": §11.10 has no
    // wildcard, and a client that wants events names them. Registering the
    // subscriber at attach rather than at the first published event is what
    // makes "attached and has missed nothing" a real state.
    let subscription = (!hello.subscribe_topics.is_empty()
        && granted.holds(twinvpn_mgmt::Scope::Events))
    .then(|| context.fanout.subscribe(super::events::SUBSCRIBER_WATERMARK));

    let ending = request_loop(&mut stream, &granted, &credentials, subscription, context).await;

    // PS-3: the only teardown is a queue. No `session_intent`, no enforcement
    // mode, no installed rule set, no `ConnectionState`.
    if let Some(id) = subscription {
        context.fanout.unsubscribe(id);
    }
    ending
}

/// The request/response loop, with §11.10's stream interleaved.
///
/// **Generic over the transport, and that is not abstraction for its own sake.**
/// `PeerCredentials::read` returns `None` on any host that is not Darwin — MI-A5,
/// deliberately — so [`serve`] cannot complete an attach on the host this crate
/// is written on, and everything after the attach would be untestable if it were
/// written against `UnixStream`. Taking `AsyncRead + AsyncWrite` costs one type
/// parameter and buys the whole loop, the event pump and MI-3's direction rule
/// as **host-runnable tests** over `tokio::io::duplex`. `shells/windows` took
/// the same shape for the same reason and said so at its own server.
async fn request_loop<S>(
    stream: &mut S,
    granted: &Scopes,
    credentials: &PeerCredentials,
    subscription: Option<u64>,
    context: &ServerContext,
) -> Ending
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        // Anything queued for this subscriber goes out FIRST, in order, before
        // the next request is read. Two consequences, both wanted: an event
        // never overtakes a response to a request that preceded it, and a
        // client that is only listening still receives events, because the read
        // below is what yields to the runtime.
        if let Some(id) = subscription {
            while let Some(delivery) = context.fanout.next_for(id) {
                let mut framed = match delivery {
                    super::events::Delivery::Event { seq, event } => {
                        let mut framed = envelope(context, Body::Event(event));
                        // MI-16: the core's own sequence number, unchanged. A
                        // contiguous `seq` proves no event was lost.
                        framed.seq = seq;
                        framed
                    }
                    // MI-19's ordered gap marker, in the stream position the
                    // gap occupied.
                    super::events::Delivery::Compacted(marker) => {
                        envelope(context, Body::Compacted(marker))
                    }
                };
                framed.as_of_ms = context.as_of_ms();
                let bytes = codec::encode_frame(&framed).unwrap_or_default();
                if bytes.is_empty() || write_all(stream, &bytes).await.is_err() {
                    return Ending::Closed;
                }
            }
        }

        // A subscribed client may be silent for a long time while events are
        // published. Waiting only on the read would hold them until the client
        // happened to say something, so the wake races the read and whichever
        // fires first goes round again. An unsubscribed connection has no wake
        // to race and just reads.
        //
        // `read_frame` is cancel-safe here for one reason and it is worth
        // stating: `tokio::net::UnixStream` is not buffered by this codec — a
        // cancelled read has consumed nothing, because the codec reads the
        // length prefix and the body in one owned future that either completes
        // or leaves the socket untouched.
        let read = if subscription.is_some() {
            tokio::select! {
                frame = codec::read_frame(stream) => frame,
                () = context.fanout.wait() => continue,
            }
        } else {
            codec::read_frame(stream).await
        };

        let envelope_in = match read {
            Ok(Some(envelope)) => envelope,
            Ok(None) => return Ending::Closed,
            Err(error) => return Ending::Framing(error),
        };
        match envelope_in.body {
            Body::Goodbye => return Ending::Closed,
            Body::Request(request) => {
                let response = handle(&request, granted, credentials, subscription, context);
                if send(stream, context, Body::Response(response))
                    .await
                    .is_err()
                {
                    return Ending::Closed;
                }
            }
            // MI-3, enforced on the receiving side: a client may not send a
            // second `Hello`, a `Response`, an `Event` or a `Reject`.
            _ => return Ending::DirectionViolation,
        }
    }
}

/// Builds the `HelloAck` for a grant. **Both carriages, one answer.**
///
/// Separated from [`serve`] so the XPC session in [`super::session`] cannot
/// produce a different one: a client must not be able to tell which channel it
/// is on from the contents of its ack.
#[must_use]
pub fn hello_ack(
    hello: &Hello,
    granted: &Scopes,
    withheld: Vec<String>,
    context: &ServerContext,
) -> HelloAck {
    HelloAck {
        mi_version: MI_VERSION.min(hello.mi_version_max),
        agent_version: twinvpn_mi::AGENT_VERSION.to_owned(),
        build_profile: twinvpn_mi::build_profile().to_owned(),
        granted_scopes: granted.names(),
        withheld_scopes: withheld,
        // From the catalogue's own digest, so it cannot disagree with the
        // catalogue this agent would actually serve (§11.7). Rendered in hex
        // because the wire field is a string and JSON has no u64 that survives
        // every client's parser intact.
        catalogue_digest: twinvpn_mgmt::catalogue_digest_text(),
        event_cursor: 0,
        protocol_epoch_range: [1, 1],
        platform_ctx: context.platform_ctx(),
    }
}

/// The answer to a `Goodbye` on a message-oriented carriage.
///
/// The socket carriage just closes: the stream's own end-of-file is the
/// acknowledgement. XPC has no such signal at this layer — Swift closes the
/// connection after the reply — so the client is told the goodbye landed rather
/// than seeing a call that never returned, which §11.7's "never a silent close"
/// is the same rule as.
#[must_use]
pub fn goodbye_response() -> Response {
    Response {
        ok: true,
        result: Vec::new(),
        diagnostic: None,
        committed_at_net_seq: None,
    }
}

/// Encodes one body as a framed envelope.
///
/// **Always produces bytes.** A frame that cannot be encoded would otherwise
/// become a silent close, which §11.7 forbids by name, so the fallback is a
/// minimal `Reject` naming the condition. Only a failure to encode *that* — an
/// impossibility for a body with no variable-length content — yields nothing.
#[must_use]
pub fn frame(context: &ServerContext, body: Body) -> Vec<u8> {
    match codec::encode_frame(&envelope(context, body)) {
        Ok(bytes) => bytes,
        Err(_) => codec::encode_frame(&envelope(
            context,
            Body::Reject(Diagnostic::of(
                twinvpn_types::codes::INTERNAL_UNEXPECTED_STATE,
            )),
        ))
        .unwrap_or_default(),
    }
}

fn envelope(context: &ServerContext, body: Body) -> MgmtEnvelope {
    MgmtEnvelope {
        mi_version: MI_VERSION,
        request_id: Vec::new(),
        correlation_id: Vec::new(),
        seq: 0,
        idempotency_key: Vec::new(),
        // **MI-16**, on the injected suspend-inclusive clock.
        as_of_ms: context.as_of_ms(),
        body,
    }
}

/// Answers one request.
///
/// **Pure over the connection's state**, so the authorization ladder is testable
/// without a socket: the operation is resolved from the catalogue, the scope is
/// checked against the *granted* set, and only then does anything reach the core.
#[must_use]
pub fn handle(
    request: &twinvpn_mi::wire::Request,
    granted: &Scopes,
    credentials: &PeerCredentials,
    subscription: Option<u64>,
    context: &ServerContext,
) -> Response {
    // MI-21's four transport operations have no core counterpart and MUST NOT
    // acquire one. Two are answerable now; `Hello` and the MI half of
    // `version.get` ride in the `HelloAck` the client already has.
    if request.operation == "mi.catalogue.get" {
        return Response {
            ok: true,
            result: twinvpn_mgmt::catalogue_digest_text().into_bytes(),
            diagnostic: None,
            committed_at_net_seq: None,
        };
    }
    if request.operation == "event.resync" {
        return resync(granted, subscription, context);
    }

    let Some(operation) = CoreCommand::ALL
        .iter()
        .copied()
        .find(|op| op.name() == request.operation)
    else {
        // §11.7: "**Never** a parse error, never a hang, never a generic
        // failure." A typed rejection naming the condition — under the code W-18
        // forces in place of `MGMT.OP_UNKNOWN`.
        return refused(twinvpn_mgmt::codes::op_unknown());
    };

    // MI-S1's grant, applied. The scope requirement is the CATALOGUE's; this
    // module holds no operation-to-scope table.
    if !granted.authorises(operation) {
        // **Named directly, not substituted.** `registry_version` 2 registered
        // `PLATFORM.PRIV.CLIENT_UNAUTHORIZED` and emptied every substitution
        // table, so `codes::substituted` is now a plain lookup — and the
        // `unwrap_or` fallback this line used to carry pointed at
        // `PLATFORM.PRIV.HELPER_UNTRUSTED`, which is a **different diagnosis**
        // with a different next action: "this client may not do that" is not
        // "the installed authority binary is not the one we recorded". A dead
        // fallback to a wrong code is worse than no fallback.
        return refused(twinvpn_types::codes::PLATFORM_PRIV_CLIENT_UNAUTHORIZED);
    }

    // §11.14's ADMINISTER ceremony is not wired in this wave, so every operation
    // it gates is **refused** rather than performed on a scope alone — §11.5's
    // third consequence, and the safe direction.
    if twinvpn_mgmt::catalogue::entry(operation).administer {
        return refused(twinvpn_types::codes::MGMT_DISARM_REQUIRES_LOCAL_AUTH);
    }

    let submission = Submission {
        op: operation,
        params: request.params.clone(),
        idempotency_key: None,
        if_version: request.if_version,
        // **MI-18.** The principal travels with the command, so every event it
        // produces carries `actor_principal`: "the tunnel went down" and "Dana
        // took the tunnel down" are different facts.
        actor_principal: Some(format!("uid:{}", credentials.uid)),
    };
    // **The registration goes in before the submission.** `Core::submit`
    // publishes the operation's outcome as a `command.completed` event
    // *synchronously, before returning `Ok(())`* — the result is not returned,
    // it is published, and the drain is the only reader of that stream. Until
    // M-1's work this whole block answered `ok: true` with `Vec::new()`,
    // because nothing drained the stream the answer was published on.
    let outcome = context.fanout.submit_and_wait(
        operation.name(),
        super::events::COMPLETION_WAIT,
        || context.core.submit(&submission),
    );
    match outcome {
        Ok(result) => Response {
            ok: true,
            result,
            diagnostic: None,
            // **MI-6, and its honest absence.** The cursor is "a real, monotone
            // position in the same log" the C2 stream replays. A locally-mutating
            // operation reaches no C1 request and has no `net_seq`, and reporting
            // a per-process counter here would tell a client it had
            // read-your-writes when it had not.
            committed_at_net_seq: None,
        },
        Err(diagnostic) => Response {
            ok: false,
            result: Vec::new(),
            diagnostic: Some(from_core(&diagnostic)),
            committed_at_net_seq: None,
        },
    }
}

/// `event.resync`'s body: the cursor, and the latest event per topic.
///
/// The same shape `shells/linux` and `shells/windows` serve. MI-20's "one
/// contract, two carriages" does not stop at the envelope — a client that could
/// parse a resync on one platform and not another would have two contracts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResyncBody {
    /// The stream position this snapshot is current as of.
    pub cursor: u64,
    /// The latest event on each topic that has one, in `TOPICS` order.
    pub rows: Vec<twinvpn_mi::wire::Event>,
}

/// **MI-9's snapshot**, taken under one lock with the cursor read inside it.
fn resync(granted: &Scopes, subscription: Option<u64>, context: &ServerContext) -> Response {
    if !granted.holds(twinvpn_mgmt::Scope::Events) {
        return refused(twinvpn_types::codes::PLATFORM_PRIV_CLIENT_UNAUTHORIZED);
    }
    // A client on no stream has no gap to recover from, and answering with a
    // snapshot would invite it to believe it is on a stream it never joined.
    // `MGMT.RESYNC_REQUIRED` is what ADR-0017 spells here and, as of
    // `registry_version` 2, what this build emits — it used to collapse onto
    // `MGMT.STREAM_COMPACTED`, which made MI-9a's two conditions
    // indistinguishable at exactly the point a client must tell them apart.
    let Some(id) = subscription else {
        return refused(twinvpn_mgmt::codes::resync_required());
    };
    let snapshot = context.fanout.resync(id);
    let body = ResyncBody {
        cursor: snapshot.cursor,
        rows: snapshot.rows.into_iter().map(|(_, event)| event).collect(),
    };
    match serde_json::to_vec(&body) {
        Ok(result) => Response {
            ok: true,
            result,
            diagnostic: None,
            committed_at_net_seq: None,
        },
        Err(_) => refused(twinvpn_types::codes::INTERNAL_UNEXPECTED_STATE),
    }
}

fn refused(code: twinvpn_types::ReasonCode) -> Response {
    Response {
        ok: false,
        result: Vec::new(),
        diagnostic: Some(Diagnostic::of(code)),
        committed_at_net_seq: None,
    }
}

/// **MI-14**: the resolved attribute set travels with the code.
fn from_core(diagnostic: &twinvpn_types::Diagnostic) -> Diagnostic {
    Diagnostic::of(diagnostic.code())
}

async fn send<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    context: &ServerContext,
    body: Body,
) -> Result<(), FrameError> {
    // The same encoder the XPC carriage uses, so the two produce byte-identical
    // envelopes for the same body — §11.2's opening sentence.
    let bytes = frame(context, body);
    write_all(stream, &bytes).await
}

/// One whole frame onto the socket, flushed.
async fn write_all<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    bytes: &[u8],
) -> Result<(), FrameError> {
    use tokio::io::AsyncWriteExt as _;
    stream
        .write_all(bytes)
        .await
        .map_err(|_| FrameError::Truncated)?;
    stream.flush().await.map_err(|_| FrameError::Truncated)
}

/// A sink and a context for this crate's own tests.
///
/// `#[cfg(test)]`, so nothing here reaches a shipped binary. It lives beside the
/// server rather than inside `mod tests` because [`super::session`]'s tests need
/// the same context, and a second hand-built one there would be a second answer
/// to "what does a connection see".
#[cfg(test)]
pub mod testing {
    use super::{Arc, CommandSink, GroupPolicy, ServerContext, Submission};

    /// A sink that records what it was given and always succeeds.
    #[derive(Debug, Default)]
    pub struct RecordingSink {
        /// Every submission, in order.
        pub submitted: std::sync::Mutex<Vec<Submission>>,
    }

    impl CommandSink for RecordingSink {
        fn submit(&self, submission: &Submission) -> Result<(), Box<twinvpn_types::Diagnostic>> {
            self.submitted
                .lock()
                .expect("lock")
                .push(submission.clone());
            Ok(())
        }
    }

    /// The three gids the tests use, matching `peer`'s own fixtures.
    pub const POLICY: GroupPolicy = GroupPolicy {
        observe: 400,
        operate: 401,
        administer: 402,
    };

    /// A context over a fresh recording sink.
    #[must_use]
    pub fn context() -> ServerContext {
        with_sink(Arc::new(RecordingSink::default()))
    }

    /// A context over a caller's sink, so a test can inspect what arrived.
    #[must_use]
    pub fn with_sink(sink: Arc<RecordingSink>) -> ServerContext {
        ServerContext {
            core: sink,
            policy: POLICY,
            fanout: Arc::new(crate::mgmt::events::Fanout::new()),
            os_version: String::new(),
            // A fixed clock: MI-16 requires `as_of_ms` to come from the injected
            // suspend-inclusive clock, and a test that read a real one would be
            // asserting against the wall.
            elapsed: twinvpn_env::binding::system::ElapsedClockFn::shared(|| {
                twinvpn_env::ElapsedInstant::from_micros(0)
            }),
        }
    }
}

/// The non-comment, non-test source of a module, for the two structural tests
/// below.
///
/// Comments are stripped because both tests name the thing they forbid in their
/// own prose, and the test module is stripped because it names it in an
/// assertion — a source scan that matched its own description would be a test
/// that can only fail.
#[cfg(test)]
fn executable_source(source: &str) -> String {
    source
        .lines()
        .take_while(|line| !line.trim_start().starts_with("mod tests"))
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && !trimmed.starts_with("#[cfg(test)]")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
