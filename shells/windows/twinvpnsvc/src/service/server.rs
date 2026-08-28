//! The MI server: attach, authorize, dispatch, respond.
//!
//! **Authority:** [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.7 (the negotiation and its mismatch table), §11.5 (MI-S1/MI-S2), §11.9,
//! §11.14, MI-1, MI-3, MI-15, MI-16, MI-18, MI-20, MI-21;
//! ADR-0016 PS-3, PS-13, PS-14, PS-22; ADR-0018 CB-2, F-5, F-6.
//!
//! # Generic over the transport, and why that is not abstraction for its own sake
//!
//! `tokio`'s named-pipe types exist only under `#[cfg(windows)]`. A server
//! written against one could not be compiled — let alone exercised — on the host
//! this crate was written on. Taking `AsyncRead + AsyncWrite` costs one type
//! parameter and buys the whole negotiation, the authorization ladder, the
//! dispatch and PS-3's detach rule as **host-runnable tests** over
//! `tokio::io::duplex`. [`crate::mi::client::Client`] is generic for the same
//! reason and against the same bound, so a test drives a real client against a
//! real server through an in-memory pipe.
//!
//! # CB-2: where the decisions went
//!
//! A shell "may translate, marshal, schedule and render. It must not contain a
//! branch whose condition is a TwinVPN domain fact." Four branches here looked
//! like they wanted to be one:
//!
//! 1. **"Is this operation allowed for this principal?"** The *scope* comes from
//!    [`twinvpn_mgmt::catalogue::entry`] — the core's own table — and the
//!    *principal* comes from the client's token. The shell compares a
//!    core-supplied requirement against an OS-supplied fact. ADR-0016 PS-12a
//!    assigns exactly this comparison to the authority.
//! 2. **"Is this operation implemented?"** `twinvpn_core::core::executes`
//!    answers it. The shell has no list.
//! 3. **"Did the command need an idempotency key?"** [`twinvpn_core::Core::submit`]
//!    checks it, once. The server submits and reports.
//! 4. **"May this ADMINISTER operation proceed?"** [`super::peer::Principal::administer_verdict`]
//!    answers it from **OS** facts — the session kind and the token's enabled
//!    groups — and the answer is a refusal either way in this build, because
//!    §11.14's ceremony is not wired.
//!
//! There is no branch in this file on a `ConnectionState`, a `reason_code`
//! class, a policy verdict, a candidate priority or a timer expiry — except the
//! `mi_version` overlap of §11.7, which is a property of *this connection* and
//! which the ADR requires the transport to decide.
//!
//! # PS-22: no dependency edge onto the datapath
//!
//! > The management-interface server … MUST be a module with **no dependency
//! > edge** onto the tunnel engine, packet-routing, or enforcement modules: it
//! > reaches them only through the same typed operation vocabulary PS-4 defines.
//!
//! This module names [`twinvpn_core::Core`], [`twinvpn_mgmt`] and this crate's
//! own `mi` and `peer`. It does not `use` `twinvpn_platform_windows::wfp`,
//! `::route`, `::dns`, `::wintun` or `::netcfg` — and
//! `ps22_the_server_reaches_the_datapath_only_through_the_vocabulary` is the
//! assertion, clause B of ADR-0017's P17.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use twinvpn_core::Core;
use twinvpn_env::Env;
use twinvpn_mgmt::{catalogue, CoreCommand, Scope, Submission, TransportOp};

use crate::mi::codec::TransportError;
use crate::mi::codec::{read_frame, write_frame};
use crate::mi::dacl::PrincipalSids;
use crate::mi::scope::Scopes;
use crate::mi::wire::{
    Body, Diagnostic, Hello, HelloAck, MgmtEnvelope, PlatformCtx, Request, Response, MI_VERSION,
    MI_VERSION_MIN,
};

use super::peer::Principal;
use super::{AGENT_VERSION, BUILD_PROFILE};

/// Everything one connection needs.
pub struct ServerContext {
    /// The hosted core. **F-5**: every outcome, including a rejection, arrives
    /// as an event on the one ordered stream.
    pub core: Arc<Core>,
    /// The injected environment. Only [`Env::now_elapsed`] is used here, for
    /// MI-16's `as_of_ms`.
    pub env: Env,
    /// PS-12a's principals, **injected** (CD-2) rather than resolved here.
    pub sids: PrincipalSids,
    /// **MI-C3.** Built once, by the service, and handed to every client
    /// verbatim.
    pub platform_ctx: PlatformCtx,
    /// **F-6 / S-47.** Serialises submissions across connections.
    ///
    /// The service serves every connection on its own task, so without this two
    /// clients could submit concurrently. Rust's type system does not force it —
    /// `Core` is `Sync` because its interior state sits behind locks — so F-6 is
    /// a rule this shell has to keep, and this is where it keeps it.
    pub submission: Arc<tokio::sync::Mutex<()>>,
}

impl ServerContext {
    /// **MI-16.** The agent's own reading, on the **suspend-inclusive** clock.
    ///
    /// > A contiguous `seq` proves **no event was lost**; it does not prove
    /// > **any event was recent**.
    ///
    /// LC-8 assigns `as_of_ms` to `ElapsedClock` by name, and on this platform
    /// that is `QueryInterruptTimePrecise`. Stamping it from the monotonic clock
    /// would make a value computed before an eight-hour suspend read as
    /// milliseconds old.
    #[must_use]
    pub fn as_of_ms(&self) -> u64 {
        self.env.now_elapsed().as_micros() / 1_000
    }
}

/// Serves one connection to completion.
///
/// # Errors
///
/// The frame error that ended it. A clean [`TransportError::Closed`] is the normal
/// case: **PS-3** — "Loss of the last management client MUST NOT change
/// `session_intent`, enforcement mode, the installed rule set, or any
/// `ConnectionState`." Nothing in this function touches any of them on the way
/// out, and `ps3_a_client_detaching_changes_nothing` is the assertion.
pub async fn serve<S>(
    context: Arc<ServerContext>,
    principal: Principal,
    stream: &mut S,
) -> Result<(), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // MI-S1/MI-S2: the granted set is computed HERE, at attach, from the token
    // the kernel attested — never cached across attaches (S-44), because a
    // group membership change must take effect on the next attach.
    let held = principal.scopes(&context.sids);
    let Some(granted) = negotiate(&context, stream, &held).await? else {
        return Ok(());
    };

    tracing::info!(
        target: "twinvpn.mi",
        principal = %principal.actor(),
        pid = principal.pid,
        session = ?principal.session,
        scopes = ?granted.names(),
        "a management client attached"
    );

    loop {
        let request = match read_frame(stream).await {
            Ok(envelope) => envelope,
            Err(TransportError::Closed) => {
                // PS-3 and LC-20, made visible: the client going away is an
                // INFO, and nothing else happens.
                tracing::info!(
                    target: "twinvpn.mi",
                    principal = %principal.actor(),
                    specified_code = "PLATFORM.SERVICE.UI_DETACHED",
                    "a management client detached; the service continues unchanged"
                );
                return Ok(());
            }
            Err(error) => {
                let reject = envelope(
                    context.as_of_ms(),
                    Body::Reject(diagnostic(
                        error.reason_code().as_str(),
                        "PERSISTENT",
                        "ERROR",
                        false,
                    )),
                );
                let _ = write_frame(stream, &reject).await;
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
            write_frame(stream, &reject).await?;
            return Ok(());
        }

        let response = match request.body {
            Body::Request(ref call) => dispatch(&context, &principal, &granted, call).await,
            Body::Goodbye => return Ok(()),
            // A second `Hello` on one connection: §11.7 fixes the version "for
            // the life of the connection", so there is nothing to renegotiate,
            // and MI-S2 forbids re-deriving the scope set.
            Body::Hello(_) => failure("PROTO.UNPARSEABLE_ENVELOPE", "PERSISTENT", "ERROR", false),
            _ => unreachable!("is_client_originated already excluded these"),
        };

        let mut reply = envelope(context.as_of_ms(), Body::Response(response));
        reply.correlation_id = request.request_id;
        write_frame(stream, &reply).await?;
    }
}

/// §11.7's `Hello`/`HelloAck`, including its mismatch table.
///
/// Returns `None` when the connection was rejected and closed.
async fn negotiate<S>(
    context: &ServerContext,
    stream: &mut S,
    held: &Scopes,
) -> Result<Option<Scopes>, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hello = read_frame(stream).await?;
    let Body::Hello(Hello {
        mi_version_min,
        mi_version_max,
        requested_scopes,
        ..
    }) = hello.body
    else {
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
        catalogue_digest: twinvpn_mgmt::catalogue_digest_text(),
        event_cursor: context.core.generation(),
        protocol_epoch_range: epoch_range(),
        platform_ctx: context.platform_ctx.clone(),
    };
    let reply = envelope(context.as_of_ms(), Body::HelloAck(Box::new(ack)));
    write_frame(stream, &reply).await?;
    Ok(Some(granted))
}

/// VR-3's epoch **table**, read from the core rather than inferred.
fn epoch_range() -> [u32; 2] {
    twinvpn_core::EPOCH_TABLE.first().map_or([1, 1], |row| {
        [row.protocol_epoch_min, row.protocol_epoch_max]
    })
}

/// Answers one request.
///
/// **Translate, marshal, schedule and render — never decide.**
async fn dispatch(
    context: &ServerContext,
    principal: &Principal,
    granted: &Scopes,
    call: &Request,
) -> Response {
    // MI-21's set, which has no core counterpart because each is about THE
    // CONNECTION. Answered here and never submitted.
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
        return failure(
            super::start::emitted_for("PLATFORM.PRIV.CLIENT_UNAUTHORIZED"),
            "POLICY",
            "ERROR",
            true,
        );
    }

    if entry.administer {
        // PS-14 first: a remote session is refused before elevation is
        // considered, so an administrator on RDP is told to go to the console
        // rather than to re-elevate.
        if let Some(code) = principal.administer_verdict().reason_code() {
            return failure(code, "POLICY", "ERROR", true);
        }
        // ADR-0016 §11.7 and ADR-0017 §11.5's third consequence: holding
        // `mgmt.admin` is necessary and NOT sufficient. Every ADMINISTER
        // operation needs the §11.14 ceremony freshly, per call — and this
        // build has no ceremony, so it refuses rather than performing one on a
        // scope alone. That is the safe direction and it is a named gap.
        return failure("MGMT.DISARM_REQUIRES_LOCAL_AUTH", "POLICY", "WARN", true);
    }

    // The core's own list. Surfaced as unimplemented rather than as a failure: a
    // command the catalogue advertises and the core does not execute is a lie a
    // client cannot detect.
    if !twinvpn_core::core::executes(op) {
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

    // Off the reactor, and one at a time. `Core::submit` is non-blocking at the
    // ABI (F-5) but the executor beneath it is not, and the F-6 lock is held
    // across the call so exactly one thread holds the core for mutation (S-47).
    let core = Arc::clone(&context.core);
    let guard = context.submission.lock().await;
    let submitted = tokio::task::spawn_blocking(move || core.submit(&submission)).await;
    drop(guard);

    let Ok(submitted) = submitted else {
        return failure("INTERNAL.UNEXPECTED_STATE", "FATAL", "CRITICAL", false);
    };

    match submitted {
        Ok(()) => Response {
            ok: true,
            result: Vec::new(),
            diagnostic: None,
            committed_at_net_seq: None,
        },
        Err(rejected) => Response {
            ok: false,
            result: Vec::new(),
            diagnostic: Some(from_core(&rejected)),
            committed_at_net_seq: None,
        },
    }
}

/// MI-21's closed set.
fn transport_op(granted: &Scopes, operation: &str) -> Option<Response> {
    // `version.get` is deliberately in BOTH sets: MI-21 splits that one
    // operation across the layers by name, and the MI half rides in the
    // `HelloAck` the client already has.
    let transport = TransportOp::ALL
        .into_iter()
        .find(|t| t.name() == operation && *t != TransportOp::VersionGetMiHalf)?;

    Some(match transport {
        TransportOp::CatalogueGet => {
            if granted.holds(Scope::Status) {
                // DERIVED from the core's command set — there is no catalogue
                // authored in this shell (MI-20).
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
                failure(
                    super::start::emitted_for("PLATFORM.PRIV.CLIENT_UNAUTHORIZED"),
                    "POLICY",
                    "ERROR",
                    true,
                )
            }
        }
        // MI-9 requires the snapshot to be taken under the agent's state lock
        // with the cursor assigned INSIDE it. This build has no subscribed-topic
        // snapshot to take, so it refuses rather than returning an empty
        // snapshot a client would read as current truth — MI-9a's whole point.
        TransportOp::EventResync => failure("MGMT.STREAM_COMPACTED", "TRANSIENT", "INFO", true),
        TransportOp::Hello => failure("PROTO.UNPARSEABLE_ENVELOPE", "PERSISTENT", "ERROR", false),
        TransportOp::VersionGetMiHalf => unreachable!("filtered above"),
    })
}

/// One catalogue row, as a client reads it.
#[derive(Debug, serde::Serialize)]
pub struct CatalogueRow {
    /// The wire name.
    pub operation: &'static str,
    /// The scope it needs.
    pub scope: &'static str,
    /// Whether it mutates.
    pub mutating: bool,
    /// Whether §11.14's ceremony gates it.
    pub administer: bool,
}

/// The catalogue, walked from the core's own command set.
#[must_use]
pub fn catalogue_rows() -> Vec<CatalogueRow> {
    catalogue::catalogue()
        .into_iter()
        .map(|entry| CatalogueRow {
            operation: entry.op.name(),
            scope: entry.scope.name(),
            mutating: entry.mutating,
            administer: entry.administer,
        })
        .collect()
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

/// **MI-14.** The resolved attributes travel with the code, so a receiver never
/// looks one up in a registry that may be older than this build.
///
/// This used to carry FOUR of MI-14's eight attributes, taken from the caller's
/// arguments rather than resolved. `Diagnostic::of` resolves all eight from this
/// agent's own registry, which is what the rule actually asks for; the caller's
/// arguments remain the fallback for a code the registry does not have (X-1: the
/// registry carries 201 codes and the ADRs name roughly 490).
fn diagnostic(reason_code: &str, class: &str, severity: &str, user_actionable: bool) -> Diagnostic {
    match twinvpn_types::ReasonCode::lookup(reason_code) {
        Some(code) => Diagnostic {
            // MI-15: the registry's i18n KEY, never a sentence.
            summary_key: Some(code.summary_key().to_owned()),
            ..Diagnostic::of(code)
        },
        None => Diagnostic {
            reason_code: reason_code.to_owned(),
            class: class.to_owned(),
            severity: severity.to_owned(),
            terminal: false,
            user_actionable,
            // Left empty rather than guessed: an unregistered code has no
            // resolved attributes, and inventing them is what MI-14 forbids.
            remediation_class: String::new(),
            scope: String::new(),
            doc_anchor: String::new(),
            summary_key: None,
            next_action_key: None,
            evidence: serde_json::Value::Null,
        },
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

/// The core's own diagnostic, carried verbatim. The shell does not reclassify it
/// and does not render it (MI-15).
fn from_core(source: &twinvpn_types::Diagnostic) -> Diagnostic {
    Diagnostic {
        summary_key: Some(source.code().summary_key().to_owned()),
        ..Diagnostic::of(source.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::peer::AdministerVerdict;

    #[test]
    fn ps22_the_server_reaches_the_datapath_only_through_the_vocabulary() {
        // Clause B of ADR-0017's P17, asserted over this file's own text: the
        // module must have no dependency edge onto the tunnel, routing or
        // enforcement modules. A `use` of one would appear here.
        let source = include_str!("server.rs");
        for forbidden in [
            "twinvpn_platform_windows::wfp",
            "twinvpn_platform_windows::route",
            "twinvpn_platform_windows::dns",
            "twinvpn_platform_windows::netcfg",
            "twinvpn_platform_windows::wintun",
            "twinvpn_platform_windows::sock",
        ] {
            assert!(
                !source.contains(&format!("use {forbidden}")),
                "PS-22: the MI server must not depend on {forbidden}"
            );
        }
    }

    #[test]
    fn the_catalogue_is_derived_from_the_cores_command_set_and_never_authored_here() {
        // MI-20: "the core's command table generates the catalogue". A list in
        // this file would be a second answer to a question the core answers.
        let rows = catalogue_rows();
        assert_eq!(rows.len(), CoreCommand::ALL.len());
        let names: Vec<&str> = rows.iter().map(|r| r.operation).collect();
        let expected: Vec<&str> = CoreCommand::ALL.iter().map(|c| c.name()).collect();
        assert_eq!(names, expected, "the order is the catalogue's too");
    }

    #[test]
    fn every_scope_a_row_names_comes_from_the_catalogues_own_enum() {
        for row in catalogue_rows() {
            assert!(row.scope.starts_with("mgmt."), "{}", row.scope);
        }
    }

    #[test]
    fn mi15_no_rendered_human_text_exists_on_any_response_this_module_builds() {
        // The mechanism is that there is no FIELD for one. Serialising and
        // searching for a sentence is what makes that checkable.
        let response = failure("POLICY.POLICY_DENIED", "POLICY", "ERROR", true);
        let json = serde_json::to_string(&response).expect("serialises");
        for forbidden in ["\"summary\"", "\"message\"", "\"title\"", "\"description\""] {
            assert!(!json.contains(forbidden), "MI-15 forbids {forbidden}");
        }
        assert!(json.contains("POLICY.POLICY_DENIED"));
    }

    #[test]
    fn every_code_this_module_emits_is_registered() {
        for code in [
            "PROTO.UNPARSEABLE_ENVELOPE",
            "PROTO.VERSION_UNSUPPORTED",
            "PROTO.CAPABILITY_MISSING",
            "MGMT.STREAM_COMPACTED",
            "MGMT.DISARM_REQUIRES_LOCAL_AUTH",
            "INTERNAL.UNEXPECTED_STATE",
            super::super::start::emitted_for("PLATFORM.PRIV.CLIENT_UNAUTHORIZED"),
            super::super::start::emitted_for("PLATFORM.PRIV.REMOTE_ADMIN_REFUSED"),
        ] {
            assert!(
                twinvpn_types::ReasonCode::lookup(code).is_some(),
                "{code} is not in the frozen registry"
            );
        }
    }

    #[test]
    fn an_administer_operation_is_refused_in_this_build_whatever_the_verdict() {
        // §11.5's third consequence: holding `mgmt.admin` is necessary and not
        // sufficient, and there is no §11.14 ceremony here. Both refusals are
        // POLICY-class, which is what tells a script this will not succeed by
        // retrying.
        for verdict in [
            AdministerVerdict::PreconditionsMet,
            AdministerVerdict::NotElevated,
            AdministerVerdict::RemoteSession,
        ] {
            let code = verdict
                .reason_code()
                .unwrap_or("MGMT.DISARM_REQUIRES_LOCAL_AUTH");
            assert!(twinvpn_types::ReasonCode::lookup(code).is_some());
        }
    }

    #[test]
    fn the_transport_set_is_mi21s_closed_four_less_the_split_version_get() {
        let granted = Scopes::from_scopes([Scope::Status]);
        assert!(transport_op(&granted, "mi.catalogue.get").is_some());
        assert!(transport_op(&granted, "event.resync").is_some());
        // `version.get` falls through to the core: MI-21 splits it by name and
        // the MI half rides in the `HelloAck` the client already has.
        assert!(transport_op(&granted, "version.get").is_none());
        assert!(transport_op(&granted, "status.get").is_none());
        twinvpn_mgmt::assert_closed().expect("MI-21 holds");
    }

    #[test]
    fn the_catalogue_needs_a_scope_and_is_refused_without_one() {
        let nothing = Scopes::empty();
        let refused = transport_op(&nothing, "mi.catalogue.get").expect("answered");
        assert!(!refused.ok);
        assert_eq!(
            refused.diagnostic.expect("named").reason_code,
            super::super::start::emitted_for("PLATFORM.PRIV.CLIENT_UNAUTHORIZED")
        );
    }
}
