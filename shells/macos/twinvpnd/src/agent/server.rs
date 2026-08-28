//! The MI server: one connection, one principal, one immutable scope set.
//!
//! **Authority:** ADR-0017 MI-1, MI-3, MI-5, MI-7, MI-14, MI-15, MI-16, MI-18,
//! MI-20, MI-21, MI-A1, MI-A5, MI-S1, MI-S2, §11.7 (the mismatch table);
//! ADR-0016 PS-3, PS-4, PS-13, PS-22.
//!
//! # PS-22: this module does not link the datapath
//!
//! > The management server lives in the authority process but MUST be a module
//! > with no dependency edge onto the tunnel, routing or enforcement modules; it
//! > reaches them only via PS-4's typed vocabulary, and MUST NOT be reachable
//! > *from* them.
//!
//! The edge here is [`CommandSink::submit`] and nothing else. There is no
//! `use twinvpn_platform_macos` in this file, and the test at the bottom asserts
//! it over the source — so the day somebody reaches for `pf::render` from a
//! request handler, the build says so.
//!
//! **The edge is a trait rather than `twinvpn_core::Core` directly**, for two
//! reasons and one accident. PS-22 asks for "no dependency edge onto the tunnel,
//! routing or enforcement modules … only via PS-4's typed vocabulary", and a
//! one-method trait over `Submission` *is* that vocabulary. It also makes the
//! authorization ladder testable on this host with a recording sink, which is
//! most of what this module is. The accident is the third reason and is stated
//! rather than dressed up: `twinvpn-core` pulls `ring`, whose C sources cannot
//! be cross-compiled to `aarch64-apple-darwin` on the Linux CI host, so a direct
//! dependency here would make `make cross-check` fail on this whole workspace.
//! See `shells/macos/README.md` §7.
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

use crate::agent::peer::{GroupPolicy, PeerCredentials};
use crate::mi::codec::{self, FrameError};
use crate::mi::wire::{
    Body, Diagnostic, HelloAck, MgmtEnvelope, PlatformCtx, Response, MI_VERSION, MI_VERSION_MIN,
};
use crate::mi::Scopes;

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
}

impl ServerContext {
    fn as_of_ms(&self) -> u64 {
        self.elapsed.now().as_micros() / 1_000
    }

    fn platform_ctx(&self) -> PlatformCtx {
        PlatformCtx {
            platform: crate::PLATFORM.to_owned(),
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
    let principal = crate::agent::peer::scopes_for(&credentials, context.policy);

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
    let ack = HelloAck {
        mi_version: MI_VERSION.min(hello.mi_version_max),
        agent_version: crate::AGENT_VERSION.to_owned(),
        build_profile: crate::build_profile().to_owned(),
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
    };
    if send(&mut stream, context, Body::HelloAck(Box::new(ack)))
        .await
        .is_err()
    {
        return Ending::Closed;
    }

    loop {
        let envelope = match codec::read_frame(&mut stream).await {
            Ok(Some(envelope)) => envelope,
            Ok(None) => return Ending::Closed,
            Err(error) => return Ending::Framing(error),
        };
        match envelope.body {
            Body::Goodbye => return Ending::Closed,
            Body::Request(request) => {
                let response = handle(&request, &granted, &credentials, context);
                if send(&mut stream, context, Body::Response(response))
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

/// Answers one request.
///
/// **Pure over the connection's state**, so the authorization ladder is testable
/// without a socket: the operation is resolved from the catalogue, the scope is
/// checked against the *granted* set, and only then does anything reach the core.
#[must_use]
pub fn handle(
    request: &crate::mi::wire::Request,
    granted: &Scopes,
    credentials: &PeerCredentials,
    context: &ServerContext,
) -> Response {
    // MI-21's four transport operations have no core counterpart and MUST NOT
    // acquire one. Only one of them is answerable in this wave.
    if request.operation == "mi.catalogue.get" {
        return Response {
            ok: true,
            result: twinvpn_mgmt::catalogue_digest_text().into_bytes(),
            diagnostic: None,
            committed_at_net_seq: None,
        };
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
        return refused(
            twinvpn_mgmt::codes::substituted("PLATFORM.PRIV.CLIENT_UNAUTHORIZED")
                .unwrap_or(twinvpn_types::codes::PLATFORM_PRIV_HELPER_UNTRUSTED),
        );
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
    match context.core.submit(&submission) {
        Ok(()) => Response {
            ok: true,
            result: Vec::new(),
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

async fn send(
    stream: &mut tokio::net::UnixStream,
    context: &ServerContext,
    body: Body,
) -> Result<(), FrameError> {
    use tokio::io::AsyncWriteExt as _;
    let envelope = MgmtEnvelope {
        mi_version: MI_VERSION,
        request_id: Vec::new(),
        correlation_id: Vec::new(),
        seq: 0,
        idempotency_key: Vec::new(),
        // **MI-16**, on the injected suspend-inclusive clock.
        as_of_ms: context.as_of_ms(),
        body,
    };
    let bytes = codec::encode_frame(&envelope)?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| FrameError::Truncated)?;
    stream.flush().await.map_err(|_| FrameError::Truncated)
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
mod tests {
    use super::*;

    #[test]
    fn ps22_this_module_has_no_edge_onto_the_datapath() {
        // "a module with no dependency edge onto the tunnel, routing or
        // enforcement modules". Asserted over the source, so the day somebody
        // reaches for `pf::render` from a request handler the build says so
        // rather than a reviewer having to notice.
        let code = executable_source(include_str!("server.rs"));
        for forbidden in [
            "twinvpn_platform_macos",
            "twinvpn_platform::",
            "twinvpn_core",
            "pf::",
            "netcfg",
            "utun",
            "route::",
        ] {
            assert!(
                !code.contains(forbidden),
                "the MI server reached for {forbidden}, which PS-22 forbids"
            );
        }
        // The one edge that IS permitted, and it is a trait over PS-4's
        // vocabulary rather than a concrete type.
        assert!(code.contains("trait CommandSink"));
        assert!(code.contains("fn submit(&self, submission: &Submission)"));
    }

    /// A sink that records what it was given and answers as told.
    #[derive(Debug, Default)]
    struct RecordingSink {
        submitted: std::sync::Mutex<Vec<Submission>>,
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

    fn context(sink: Arc<RecordingSink>) -> ServerContext {
        ServerContext {
            core: sink,
            policy: GroupPolicy {
                observe: 400,
                operate: 401,
                administer: 402,
            },
            os_version: String::new(),
            elapsed: twinvpn_env::binding::system::ElapsedClockFn::shared(|| {
                twinvpn_env::ElapsedInstant::from_micros(0)
            }),
        }
    }

    fn request(operation: &str) -> crate::mi::wire::Request {
        crate::mi::wire::Request {
            operation: operation.to_owned(),
            params: Vec::new(),
            if_version: None,
        }
    }

    fn credentials(uid: u32) -> PeerCredentials {
        PeerCredentials {
            uid,
            groups: Vec::new(),
            groups_possibly_truncated: false,
        }
    }

    #[test]
    fn an_operation_the_catalogue_does_not_know_is_a_typed_rejection() {
        // §11.7: "**Never** a parse error, never a hang, never a generic
        // failure." And nothing reaches the sink.
        let sink = Arc::new(RecordingSink::default());
        let granted = Scopes::from_scopes(crate::mi::scope::GRANTABLE);
        let response = handle(
            &request("/bin/sh"),
            &granted,
            &credentials(501),
            &context(sink.clone()),
        );
        assert!(!response.ok);
        assert_eq!(
            response.diagnostic.expect("named").reason_code,
            twinvpn_mgmt::codes::op_unknown().as_str()
        );
        assert!(sink.submitted.lock().expect("lock").is_empty());
    }

    #[test]
    fn a_scope_the_connection_was_not_granted_refuses_before_the_core_sees_it() {
        // MI-S1's grant, applied. The requirement is the CATALOGUE's.
        let sink = Arc::new(RecordingSink::default());
        let status_only = Scopes::from_scopes([twinvpn_mgmt::Scope::Status]);
        let response = handle(
            &request("session.connect"),
            &status_only,
            &credentials(501),
            &context(sink.clone()),
        );
        assert!(!response.ok);
        assert!(
            sink.submitted.lock().expect("lock").is_empty(),
            "an unauthorised operation must not reach the core at all"
        );
    }

    #[test]
    fn an_administer_operation_is_refused_rather_than_performed_on_a_scope_alone() {
        // §11.5's third consequence, and the safe direction: holding
        // `mgmt.admin` is necessary and not sufficient, and the §11.14 ceremony
        // is not wired in this wave.
        let sink = Arc::new(RecordingSink::default());
        let everything = Scopes::from_scopes(crate::mi::scope::GRANTABLE);
        let administer: Vec<CoreCommand> = CoreCommand::ALL
            .iter()
            .copied()
            .filter(|op| twinvpn_mgmt::catalogue::entry(*op).administer)
            .collect();
        assert!(!administer.is_empty(), "the catalogue has ADMINISTER rows");
        for op in administer {
            let response = handle(
                &request(op.name()),
                &everything,
                &credentials(501),
                &context(sink.clone()),
            );
            assert!(!response.ok, "{} was performed", op.name());
        }
        assert!(sink.submitted.lock().expect("lock").is_empty());
    }

    #[test]
    fn an_authorised_operation_reaches_the_core_carrying_its_actor() {
        // **MI-18.** "The tunnel went down" and "Dana took the tunnel down" are
        // different facts, so the principal travels with the command.
        let sink = Arc::new(RecordingSink::default());
        let granted = Scopes::from_scopes([twinvpn_mgmt::Scope::Status]);
        let response = handle(
            &request("status.get"),
            &granted,
            &credentials(501),
            &context(sink.clone()),
        );
        assert!(response.ok);
        let submitted = sink.submitted.lock().expect("lock");
        assert_eq!(submitted.len(), 1);
        assert_eq!(submitted[0].op, CoreCommand::StatusGet);
        assert_eq!(submitted[0].actor_principal.as_deref(), Some("uid:501"));
    }

    #[test]
    fn mi6_a_locally_mutating_operation_reports_no_net_seq_rather_than_a_fake_one() {
        // The cursor is "a real, monotone position in the same log" the C2 stream
        // replays. A per-process counter here would tell a client it had
        // read-your-writes when it had not.
        let sink = Arc::new(RecordingSink::default());
        let granted = Scopes::from_scopes([twinvpn_mgmt::Scope::Status]);
        let response = handle(
            &request("status.get"),
            &granted,
            &credentials(501),
            &context(sink),
        );
        assert_eq!(response.committed_at_net_seq, None);
    }

    #[test]
    fn mi21_the_catalogue_operation_is_answered_without_reaching_the_core() {
        // One of the four transport-layer operations, which have no core
        // counterpart and MUST NOT acquire one.
        let sink = Arc::new(RecordingSink::default());
        let response = handle(
            &request("mi.catalogue.get"),
            &Scopes::empty(),
            &credentials(501),
            &context(sink.clone()),
        );
        assert!(response.ok);
        assert!(sink.submitted.lock().expect("lock").is_empty());
        assert_eq!(
            String::from_utf8(response.result).expect("utf8"),
            twinvpn_mgmt::catalogue_digest_text()
        );
    }

    #[test]
    fn ps4_no_operation_name_reaches_anything_that_is_not_a_catalogue_entry() {
        // The closed enum is the mechanism: an unrecognised name cannot become a
        // path, a command line or a rule, because there is nothing for it to
        // become.
        let unknown = crate::mi::wire::Request {
            operation: "/bin/sh".to_owned(),
            params: Vec::new(),
            if_version: None,
        };
        assert!(CoreCommand::ALL
            .iter()
            .all(|op| op.name() != unknown.operation));
    }

    #[test]
    fn every_core_command_has_a_name_and_no_two_share_one() {
        // MI-20's derivation is only safe if the wire names are unique, since the
        // wire carries a string.
        let mut names: Vec<&str> = CoreCommand::ALL.iter().map(|op| op.name()).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
    }

    #[test]
    fn the_catalogue_digest_is_the_catalogues_and_not_a_constant() {
        // §11.7: "the catalogue, not the version, is the capability contract."
        // Taking the digest from anywhere but the catalogue would let a `HelloAck`
        // advertise a contract the agent does not serve.
        assert_ne!(twinvpn_mgmt::catalogue_digest(), 0);
        assert_eq!(
            twinvpn_mgmt::catalogue_digest(),
            twinvpn_mgmt::catalogue_digest()
        );
    }
}
