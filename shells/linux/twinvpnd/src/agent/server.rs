//! The MI server: attach, authorize, dispatch, respond.
//!
//! **Authority:** [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.7 (the negotiation and its mismatch table), §11.5 (MI-S1/MI-S2),
//! §11.9 (the operation table), MI-1, MI-3, MI-15, MI-16, MI-18, MI-20, MI-21;
//! ADR-0016 PS-3, PS-13, PS-22; ADR-0018 CB-2, F-5.
//!
//! # CB-2: the three places a decision nearly leaked, and where each went
//!
//! A shell "may translate, marshal, schedule and render. It must not contain a
//! branch whose condition is a TwinVPN domain fact." Three branches here looked
//! like they wanted to be one, and each is resolved by asking the core:
//!
//! 1. **"Is this operation allowed for this principal?"** The *scope* comes from
//!    [`twinvpn_mgmt::catalogue::entry`] — the core's own table — and the
//!    *principal* comes from `SO_PEERCRED`. The shell compares a core-supplied
//!    requirement against an OS-supplied fact. It invents neither, and ADR-0016
//!    PS-12a assigns exactly this comparison to the daemon.
//! 2. **"Is this operation implemented?"** [`twinvpn_core::is_implemented`] and
//!    [`twinvpn_core::UNIMPLEMENTED`] answer it. The shell has no list.
//! 3. **"Did the command need an idempotency key?"** [`twinvpn_core::Core::submit`]
//!    checks it, once, and rejects — "checking it here, once, is what keeps the
//!    two carriages honest — the MI transport does not get to skip it". The
//!    server therefore **submits and reports**, and does not pre-validate.
//!
//! There is no branch in this file on a `ConnectionState`, a `reason_code`
//! class, a policy verdict, a candidate priority, a timer expiry or a version
//! comparison — except the `mi_version` overlap of §11.7, which is a property of
//! *this connection* and not of TwinVPN, and which the ADR requires the transport
//! to decide.
//!
//! # PS-22: no dependency edge onto the datapath
//!
//! > The management-interface server … MUST be a module with **no dependency
//! > edge** onto the tunnel engine, packet-routing, or enforcement modules: it
//! > reaches them only through the same typed operation vocabulary PS-4 defines.
//!
//! This module names [`twinvpn_core::Core`] and [`twinvpn_mgmt`] and nothing
//! else. It does not `use` `twinvpn_platform_linux::nft`, `::tun` or `::route`,
//! and `ps22_the_server_reaches_the_datapath_only_through_the_vocabulary` is the
//! assertion — clause B of ADR-0017's P17.

use std::sync::Arc;

use twinvpn_core::Core;
use twinvpn_env::Env;
use twinvpn_mgmt::{catalogue, CoreCommand, Submission, TransportOp};

use crate::mi::codec::{read_frame, write_frame};
use crate::mi::scope::Scopes;
use crate::mi::wire::{
    Body, Diagnostic, FrameError, Hello, HelloAck, MgmtEnvelope, PlatformCtx, Request, Response,
    MI_VERSION, MI_VERSION_MIN,
};
use crate::{AGENT_VERSION, BUILD_PROFILE};

use super::peer::{GroupSource, Principal};

/// Everything one connection needs.
pub struct ServerContext {
    /// The hosted core. **F-5**: every outcome, including a rejection, arrives
    /// as an event on the one ordered stream.
    pub core: Arc<Core>,
    /// The injected environment. Only [`Env::now_elapsed`] is used here, for
    /// MI-16's `as_of_ms`.
    pub env: Env,
    /// The group database, loaded once at start.
    pub groups: Arc<GroupSource>,
    /// **MI-C3.** Built once, by the agent, and handed to every client verbatim.
    pub platform_ctx: PlatformCtx,
}

impl ServerContext {
    /// **MI-16.** The agent's own reading, on the **boot-time monotonic** clock.
    ///
    /// > A contiguous `seq` proves **no event was lost**; it does not prove
    /// > **any event was recent**.
    ///
    /// [`Env::now_elapsed`] is `CLOCK_BOOTTIME` on Linux
    /// (`twinvpn_platform_linux::BootTimeElapsedClock`), which is what MI-16
    /// asks for by name — and is why the shell must supply the elapsed clock at
    /// all (W-7).
    #[must_use]
    pub fn as_of_ms(&self) -> u64 {
        self.env.now_elapsed().as_micros() / 1_000
    }
}

/// Serves one connection to completion.
///
/// # Errors
///
/// The frame error that ended it. A clean [`FrameError::Closed`] is the normal
/// case: **PS-3** — "Loss of the last management client MUST NOT change
/// `session_intent`, enforcement mode, the installed rule set, or any
/// `ConnectionState`." Nothing in this function touches any of them on the way
/// out.
pub async fn serve(
    context: Arc<ServerContext>,
    mut stream: tokio::net::UnixStream,
) -> Result<(), FrameError> {
    // MI-A1/MI-A5: the identity comes from the kernel, and an unverifiable one
    // is rejected and closed — never a default principal, never an anonymous
    // read-only tier.
    let principal = match Principal::from_stream(&stream) {
        Ok(principal) => principal,
        Err(error) => {
            let reject = envelope(
                context.as_of_ms(),
                Body::Reject(diagnostic(error.reason_code(), "PERSISTENT", "ERROR", true)),
            );
            // Answered, THEN closed. §11.7: a silent close is indistinguishable
            // from "the agent is not running".
            write_frame(&mut stream, &reject).await?;
            return Ok(());
        }
    };

    let held = principal.scopes(&context.groups);
    let Some(granted) = negotiate(&context, &mut stream, &held).await? else {
        return Ok(());
    };

    tracing::info!(
        target: "twinvpn.mi",
        principal = %principal.actor(),
        pid = principal.pid,
        scopes = ?granted.names(),
        "a management client attached"
    );

    loop {
        let request = match read_frame(&mut stream).await {
            Ok(envelope) => envelope,
            Err(FrameError::Closed) => {
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
                let reject = envelope(
                    context.as_of_ms(),
                    Body::Reject(diagnostic(
                        error.reason_code(),
                        "PERSISTENT",
                        "ERROR",
                        false,
                    )),
                );
                let _ = write_frame(&mut stream, &reject).await;
                return Err(error);
            }
        };

        // MI-3: the agent never receives a response or an event. A client that
        // sends one has broken the protocol.
        if !request.body.is_client_originated() {
            let reject = envelope(
                context.as_of_ms(),
                Body::Reject(diagnostic(
                    "PROTO.UNPARSEABLE_ENVELOPE",
                    "PERSISTENT",
                    "ERROR",
                    false,
                )),
            );
            write_frame(&mut stream, &reject).await?;
            return Ok(());
        }

        let response = match request.body {
            Body::Request(ref call) => dispatch(&context, &principal, &granted, call),
            Body::Goodbye => return Ok(()),
            // A second `Hello` on one connection: §11.7 fixes the version "for
            // the life of the connection", so there is nothing to renegotiate.
            Body::Hello(_) => Response {
                ok: false,
                result: Vec::new(),
                diagnostic: Some(diagnostic(
                    "PROTO.UNPARSEABLE_ENVELOPE",
                    "PERSISTENT",
                    "ERROR",
                    false,
                )),
                committed_at_net_seq: None,
            },
            _ => unreachable!("is_client_originated already excluded these"),
        };

        let mut reply = envelope(context.as_of_ms(), Body::Response(response));
        reply.correlation_id = request.request_id;
        write_frame(&mut stream, &reply).await?;
    }
}

/// §11.7's `Hello`/`HelloAck`, including its mismatch table.
///
/// Returns `None` when the connection was rejected and closed.
async fn negotiate(
    context: &ServerContext,
    stream: &mut tokio::net::UnixStream,
    held: &Scopes,
) -> Result<Option<Scopes>, FrameError> {
    let hello = read_frame(stream).await?;
    let Body::Hello(Hello {
        mi_version_min,
        mi_version_max,
        requested_scopes,
        ..
    }) = hello.body
    else {
        // MI-3: the first message on a connection is a `Hello`. Anything else
        // is answered and closed, never silently dropped.
        let reject = envelope(
            context.as_of_ms(),
            Body::Reject(diagnostic(
                "PROTO.UNPARSEABLE_ENVELOPE",
                "PERSISTENT",
                "ERROR",
                false,
            )),
        );
        write_frame(stream, &reject).await?;
        return Ok(None);
    };

    // §11.7's mismatch table. Both refusals name a REGISTERED code and are
    // written, then the connection closes — "A silent close is prohibited: it is
    // indistinguishable from 'the agent is not running', and it sends the user
    // to reinstall rather than to update."
    if mi_version_max < MI_VERSION_MIN || mi_version_min > MI_VERSION {
        let reject = envelope(
            context.as_of_ms(),
            // ADR-0017 spells these `MGMT.VERSION_TOO_OLD` / `TOO_NEW`, neither
            // of which the frozen registry carries. `PROTO.VERSION_UNSUPPORTED`
            // is the nearest registered code; the CLI maps it to exit 5.
            Body::Reject(diagnostic(
                "PROTO.VERSION_UNSUPPORTED",
                "PERSISTENT",
                "ERROR",
                true,
            )),
        );
        write_frame(stream, &reject).await?;
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
        catalogue_digest: format!("{:016x}", twinvpn_mgmt::catalogue_digest()),
        event_cursor: context.core.generation(),
        protocol_epoch_range: epoch_range(),
        platform_ctx: context.platform_ctx.clone(),
    };
    let reply = envelope(context.as_of_ms(), Body::HelloAck(Box::new(ack)));
    write_frame(stream, &reply).await?;
    Ok(Some(granted))
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

/// Answers one request.
///
/// **Translate, marshal, schedule and render — never decide.** Every branch here
/// is on a fact the core or the OS supplied.
fn dispatch(
    context: &ServerContext,
    principal: &Principal,
    granted: &Scopes,
    call: &Request,
) -> Response {
    // MI-21's four, which have no core counterpart because each is about THE
    // CONNECTION. They are answered here and never submitted.
    if let Some(response) = transport_op(granted, &call.operation) {
        return response;
    }

    // The one string-driven entry point. An unknown name is a TYPED rejection,
    // "never a parse error, never a hang, never a generic failure".
    let Some(op) = CoreCommand::from_name(&call.operation) else {
        return failure("PROTO.CAPABILITY_MISSING", "PERSISTENT", "ERROR", true);
    };

    // The scope the CORE's catalogue says this operation needs.
    let entry = catalogue::entry(op);
    if !granted.holds(entry.scope) {
        // ADR-0017 §11.12 gives `PLATFORM.PRIV.CLIENT_UNAUTHORIZED` its own exit
        // code (4). It is unregistered; the substitution and its cost are in
        // `super::privilege::SUBSTITUTIONS`.
        return failure("POLICY.POLICY_DENIED", "POLICY", "ERROR", true);
    }

    // ADR-0016 §11.7 and ADR-0017 §11.5's third consequence: holding
    // `mgmt.admin` is necessary and NOT sufficient. Every ADMINISTER operation
    // needs the §11.14 ceremony freshly, per call — and this build has no
    // ceremony, so it refuses rather than performing one on a scope alone.
    if entry.administer {
        return failure("MGMT.DISARM_REQUIRES_LOCAL_AUTH", "POLICY", "WARN", true);
    }

    // `twinvpn_core::UNIMPLEMENTED` is the core's own list. **Surfaced as
    // unimplemented, not as a failure**: a command the catalogue advertises and
    // the core does not execute is a lie a client cannot detect, so the set is
    // enumerable and this reports it by name.
    if !twinvpn_core::core::is_implemented(op) {
        return failure("PROTO.CAPABILITY_MISSING", "PERSISTENT", "ERROR", true);
    }

    let submission = Submission {
        op,
        params: call.params.clone(),
        idempotency_key: None,
        if_version: call.if_version,
        // **MI-18 / PS-13.** The acting principal travels with the command and
        // reaches every event it produces.
        actor_principal: Some(principal.actor()),
    };

    match context.core.submit(&submission) {
        Ok(()) => Response {
            ok: true,
            result: Vec::new(),
            diagnostic: None,
            // **MI-6.** S-47's generation is the cursor this agent can honestly
            // report for a mutating command; a client must observe an event at
            // or past it before telling a human the operation is complete.
            committed_at_net_seq: entry.mutating.then(|| context.core.generation()),
        },
        // The core's own diagnostic, carried verbatim. The shell does not
        // reclassify it and does not render it (MI-15).
        Err(rejected) => Response {
            ok: false,
            result: Vec::new(),
            diagnostic: Some(from_core(&rejected)),
            committed_at_net_seq: None,
        },
    }
}

/// MI-21's closed set of four.
///
/// `None` means "not one of the four", which is the only way a name reaches the
/// core command set below.
fn transport_op(granted: &Scopes, operation: &str) -> Option<Response> {
    // `version.get` is deliberately in BOTH sets: MI-21 splits that one
    // operation across the layers by name, and the client sees one operation.
    // So it is not answered here; it falls through to the core, and the MI half
    // rides in the `HelloAck` the client already has.
    let transport = TransportOp::ALL
        .into_iter()
        .find(|t| t.name() == operation && *t != TransportOp::VersionGetMiHalf)?;

    Some(match transport {
        TransportOp::CatalogueGet => {
            if granted.holds(twinvpn_mgmt::Scope::Status) {
                // The full table, DERIVED from the core's command set — there is
                // no catalogue authored in this shell.
                match serde_json::to_vec(&catalogue_rows()) {
                    Ok(result) => Response {
                        ok: true,
                        result,
                        diagnostic: None,
                        committed_at_net_seq: None,
                    },
                    Err(_) => failure("INTERNAL.UNEXPECTED_STATE", "FATAL", "CRITICAL", false),
                }
            } else {
                failure("POLICY.POLICY_DENIED", "POLICY", "ERROR", true)
            }
        }
        TransportOp::EventResync => {
            // MI-9 requires the snapshot to be taken under the agent's state
            // lock with the cursor assigned INSIDE it. This build has no
            // subscribed-topic snapshot to take, so it refuses rather than
            // returning an empty snapshot a client would treat as current
            // truth — which is MI-9a's whole point.
            failure("MGMT.STREAM_COMPACTED", "TRANSIENT", "INFO", true)
        }
        TransportOp::Hello => failure("PROTO.UNPARSEABLE_ENVELOPE", "PERSISTENT", "ERROR", false),
        TransportOp::VersionGetMiHalf => unreachable!("filtered above"),
    })
}

/// The catalogue, as rows a client can read.
///
/// Walks [`CoreCommand::ALL`], so the table's contents **and its order** both
/// come from the command set. There is no list here.
fn catalogue_rows() -> Vec<CatalogueRow> {
    catalogue::catalogue()
        .into_iter()
        .map(|entry| CatalogueRow {
            operation: entry.op.name().to_owned(),
            required_scope: entry.scope.name().to_owned(),
            mutating: entry.mutating,
            idempotency: format!("{:?}", entry.idempotency),
            delivery: format!("{:?}", entry.delivery),
            administer: entry.administer,
            // The honest half: which operations this BUILD executes. ADR-0017
            // §11.7's "the catalogue, not the version, is the capability
            // contract" is only true if the catalogue says so.
            implemented: twinvpn_core::core::is_implemented(entry.op),
        })
        .collect()
}

/// One `mi.catalogue.get` row.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CatalogueRow {
    /// The wire name.
    pub operation: String,
    /// The scope a principal must hold.
    pub required_scope: String,
    /// Whether it mutates.
    pub mutating: bool,
    /// Its idempotency requirement.
    pub idempotency: String,
    /// Unary or stream.
    pub delivery: String,
    /// Whether §11.14's ceremony gates it.
    pub administer: bool,
    /// Whether **this build** executes it.
    pub implemented: bool,
}

fn envelope(as_of_ms: u64, body: Body) -> MgmtEnvelope {
    MgmtEnvelope {
        mi_version: MI_VERSION,
        request_id: vec![0; 16],
        correlation_id: Vec::new(),
        seq: 0,
        idempotency_key: Vec::new(),
        as_of_ms,
        body,
    }
}

fn diagnostic(reason_code: &str, class: &str, severity: &str, user_actionable: bool) -> Diagnostic {
    // The registry is consulted for the class and the actionability where the
    // code is registered, so the caller's arguments are a fallback rather than
    // an assertion: MI-14 requires the resolved attributes to travel with the
    // code, resolved from the AGENT's own registry at emission.
    let resolved = twinvpn_types::ReasonCode::lookup(reason_code);
    Diagnostic {
        reason_code: reason_code.to_owned(),
        class: resolved.map_or_else(
            || class.to_owned(),
            |code| format!("{:?}", code.class()).to_uppercase(),
        ),
        severity: resolved.map_or_else(
            || severity.to_owned(),
            |code| format!("{:?}", code.severity()).to_uppercase(),
        ),
        user_actionable: resolved
            .map_or(user_actionable, twinvpn_types::ReasonCode::user_actionable),
        summary_key: resolved.map(|code| code.summary_key().to_owned()),
        next_action_key: None,
        evidence: Vec::new(),
    }
}

fn failure(reason_code: &str, class: &str, severity: &str, user_actionable: bool) -> Response {
    Response {
        ok: false,
        result: Vec::new(),
        diagnostic: Some(diagnostic(reason_code, class, severity, user_actionable)),
        committed_at_net_seq: None,
    }
}

/// Carries a core diagnostic onto the wire **without rendering it** (MI-15).
fn from_core(source: &twinvpn_types::Diagnostic) -> Diagnostic {
    let code = source.code();
    Diagnostic {
        reason_code: code.as_str().to_owned(),
        class: format!("{:?}", code.class()).to_uppercase(),
        severity: format!("{:?}", code.severity()).to_uppercase(),
        user_actionable: code.user_actionable(),
        summary_key: Some(code.summary_key().to_owned()),
        next_action_key: None,
        // Typed evidence only, and already restricted to the code's declared
        // fields by the core.
        evidence: source
            .evidence()
            .entries()
            .iter()
            .map(|e| (e.key().to_owned(), format!("{:?}", e.value())))
            .collect(),
    }
}
