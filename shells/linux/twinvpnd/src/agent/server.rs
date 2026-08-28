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
//! 2. **"Is this operation implemented?"** [`twinvpn_core::core::executes`] and
//!    `twinvpn_core::core::unimplemented()` answer it. The shell has no list.
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
//! A fourth nearly leaked and is worth naming because it *did* leak, and a review
//! caught it: **"does this operation need a `committed_at_net_seq`?"** The shell
//! answered it from `Entry::mutating`, which is a local fact, when MI-6's
//! predicate is *maps to a mutating **C1** request* — a control-plane fact the
//! ADR states and this shell must read rather than approximate. See
//! [`C1_MAPPING`].
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

use crate::mi::scope::Scopes;
use crate::mi::wire::{Body, Diagnostic, MgmtEnvelope, PlatformCtx, Request, Response, MI_VERSION};

use super::events::Fanout;
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
    /// **F-6 / S-47.** Serialises submissions across connections.
    ///
    /// > A `tw_core*` is Send but **NOT Sync** for mutating calls: exactly one
    /// > thread may hold it for mutation at a time (S-47).
    ///
    /// The agent serves every connection on its own task, so without this two
    /// clients could submit concurrently. Rust's type system does not force it —
    /// `Core` is `Sync` because its interior state sits behind locks — so F-6 is
    /// a rule this shell has to keep, and this is where it keeps it.
    pub submission: Arc<tokio::sync::Mutex<()>>,
    /// **§11.10's event stream**, one fan-out for the whole agent.
    ///
    /// F-5 gives the core exactly one ordered stream and `next_event` pops from
    /// it, so there is exactly one reader in the process — the drain thread —
    /// and every connection reads its own bounded copy from here. See
    /// [`super::events`].
    pub fanout: Arc<Fanout>,
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

/// Answers one request.
///
/// **Translate, marshal, schedule and render — never decide.** Every branch here
/// is on a fact the core or the OS supplied.
pub(super) async fn dispatch(
    context: &ServerContext,
    principal: &Principal,
    granted: &Scopes,
    subscription: Option<u64>,
    call: &Request,
) -> Response {
    // MI-21's four, which have no core counterpart because each is about THE
    // CONNECTION. They are answered here and never submitted.
    if let Some(response) = transport_op(context, granted, subscription, &call.operation) {
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
    // needs the §11.14 ceremony freshly, per call.
    if entry.administer {
        if let Err(refusal) = administer_ceremony(principal, granted) {
            return *refusal;
        }
    }

    // `twinvpn_core::core::unimplemented()` is the core's own list. **Surfaced as
    // unimplemented, not as a failure**: a command the catalogue advertises and
    // the core does not execute is a lie a client cannot detect, so the set is
    // enumerable and this reports it by name.
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

    // **Off the reactor, and one at a time.**
    //
    // `Core::submit` is non-blocking at the ABI (F-5), but the executor beneath
    // it is not: an operation like `session.connect` calls `block_on_adapter`,
    // which drives an adapter future to completion on the injected runtime.
    // Calling that from a runtime worker is tokio's "Cannot start a runtime from
    // within a runtime", which panics the connection the moment the command path
    // is wired. That is a real defect and not a test artifact — the daemon serves
    // every MI connection on a task of that same runtime.
    //
    // `spawn_blocking` moves it to a pool thread, and the F-6 lock is held across
    // it so exactly one thread holds the core for mutation at a time (S-47).
    let core = Arc::clone(&context.core);
    let guard = context.submission.lock().await;

    // **The body of a read, made reachable.** `Core::submit` returns `Ok(())`
    // and *publishes* the operation's result as a `CommandCompleted` event, so
    // the result never comes back through the return value. The registration is
    // taken BEFORE the submission and carries the cursor read before it, so the
    // drain thread can settle it with this call's own completion and with no
    // other. `Fanout::expect_completion` states why both facts are needed.
    let cursor_before = context.core.event_cursor();
    let (pending, completion) = context.fanout.expect_completion(op.name(), cursor_before);

    let submitted = tokio::task::spawn_blocking(move || core.submit(&submission)).await;
    drop(guard);

    // The blocking task was cancelled or panicked. F-7 contains a panic inside
    // the core and poisons the instance; a join failure here is the shell's own,
    // and is named rather than swallowed. The registration is withdrawn first,
    // or it would match a later call of the same operation.
    let Ok(submitted) = submitted else {
        context.fanout.cancel_completion(pending);
        return failure("INTERNAL.UNEXPECTED_STATE", "FATAL", "CRITICAL", false);
    };

    // Awaited only on the success path, because only that path publishes a
    // completion — and awaited without a timeout, because `submit` returning
    // `Ok` means the event is in the queue and the drain will reach it. CD-2:
    // timeouts are the core's, so a deadline invented here would be the shell
    // holding a decision it was not given.
    let body = if submitted.is_ok() {
        completion.await.unwrap_or_default()
    } else {
        context.fanout.cancel_completion(pending);
        Vec::new()
    };

    match submitted {
        Ok(()) => Response {
            ok: true,
            // **The body of a read.** `Core::submit` returns `Ok(())` and
            // publishes the operation's result as a `CommandCompleted` event on
            // the one ordered stream (F-5), so the result is not *returned* — it
            // is *published*. Wave 1 read that as "unreachable" and shipped an
            // empty `result`; it is reachable, and this is where it is reached.
            //
            // Two facts make the correlation exact rather than a guess: the F-6
            // lock means no other submission is in flight, and `cursor_before`
            // means no earlier completion can match. See `result_for`.
            result: body,
            diagnostic: None,
            // **MI-6**, and its predicate is `maps_to_mutating_c1` — NOT
            // `entry.mutating`. See that function: the cursor is a position in
            // the coordination service's C2 log, and a locally-mutating
            // operation that never reaches C1 has none.
            committed_at_net_seq: committed_cursor(op),
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

/// The operations that **map to a mutating C1 request**, which is MI-6's actual
/// predicate.
///
/// # The distinction, and why getting it wrong is worse than omitting the cursor
///
/// `docs/protocol.md` §5.1 and E-2 fix what `committed_at_net_seq` *is*: "a
/// **real, monotone position in the same log**" the C2 event stream replays —
/// the coordination service's. Its purpose is read-your-writes across the C1/C2
/// boundary: "a device pairs a peer, gets `200 OK`, and immediately tries to
/// connect — but its local `TrustedPeer` cache has not yet seen the pairing
/// event."
///
/// So MI-6's predicate is **not** `Entry::mutating`. `session.connect` mutates a
/// great deal — it gathers on the platform, drives the §4.5 table, admits into
/// the candidate ledger, schedules a race and persists to the journal — and
/// **sends no C1 request at all**. ADR-0017 §11.8's own table classifies it
/// "naturally idempotent … the state machine already absorbs a repeat", beside
/// `net.up` and `net.down`; §11.9 marks `committed_at_net_seq` on exactly the
/// ceremonies that reach the coordination service.
///
/// This shell previously computed the cursor as
/// `entry.mutating.then(|| core.generation())`, which was wrong twice: it
/// applied MI-6 to purely local operations, and it reported **S-47's
/// generation** — a per-process counter S-47 requires "**must not survive
/// process exit**" — as if it were a durable C2 log position. A client that
/// waited for an event "at or past" that number would believe it had discharged
/// E-2's read-your-writes when it had not. An absent cursor tells a client MI-6
/// does not apply; a fabricated one tells it a falsehood it cannot detect.
///
/// The update verbs are deliberately absent: ADR-0021 §11.18(f) puts them on the
/// **update service**, not the coordination service's C2 log, so they have no
/// `net_seq` either.
pub const C1_MAPPING: [CoreCommand; 5] = [
    // ADR-0017 MI-8: "Where an MI ceremony triggers a control-plane ceremony,
    // the agent MUST derive the C1 `idempotency_key` deterministically from the
    // MI key and the calling principal."
    CoreCommand::PairBegin,
    // §11.9: "Completion; carries `committed_at_net_seq` (MI-6)".
    CoreCommand::PairConfirm,
    CoreCommand::PairCancel,
    // §11.9: "Initiates the `Owner`-signed `RevocationRecord` ceremony; carries
    // `committed_at_net_seq`".
    CoreCommand::DeviceRevoke,
    // ADR-0007 succession is a control-plane fact.
    CoreCommand::KeyRotate,
];

/// Whether `op` maps to a mutating C1 request.
///
/// Membership in [`C1_MAPPING`] rather than an exhaustive `match`, because
/// `CoreCommand` is `#[non_exhaustive]` and a shell **cannot** match it
/// exhaustively — so the compile-time guarantee the core gets is unavailable
/// here. `a_new_core_command_must_be_classified_against_mi6` is the tripwire
/// that replaces it: it pins the catalogue's size, so a command added upstream
/// fails this crate's tests until someone states which side of MI-6 it falls on.
#[must_use]
pub fn maps_to_mutating_c1(op: CoreCommand) -> bool {
    C1_MAPPING.contains(&op)
}

/// The `committed_at_net_seq` this build can honestly report.
///
/// **Always `None`, and the reason is structural rather than an omission.** A
/// cursor exists only for an operation in [`C1_MAPPING`], and every one of those
/// needs a control-plane transport this build does not have (`ownership.md` §8
/// W-12: there is no `ControlTransport`). All five are therefore refused by
/// `twinvpn_core::core::executes` before they reach this point, so no response
/// that would need a cursor is ever produced.
///
/// Written as a function rather than a literal `None` so that the day a C2
/// transport lands there is one place to supply the cursor, with a test already
/// asserting which operations require it.
#[must_use]
fn committed_cursor(op: CoreCommand) -> Option<u64> {
    if !maps_to_mutating_c1(op) {
        return None;
    }
    // No C2 log exists in this build, so there is no position to report. An
    // operation reaching here would be a defect — a C1-mapping operation this
    // build claims to execute — and `None` is still the safe answer: a client
    // that receives no cursor knows it has no read-your-writes guarantee, which
    // is the truth.
    None
}

/// MI-21's closed set of four.
///
/// `None` means "not one of the four", which is the only way a name reaches the
/// core command set below.
fn transport_op(
    context: &ServerContext,
    granted: &Scopes,
    subscription: Option<u64>,
    operation: &str,
) -> Option<Response> {
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
        TransportOp::EventResync => resync(context, granted, subscription),
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
            implemented: twinvpn_core::core::executes(entry.op),
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

/// **MI-9's `event.resync`**, answered with a snapshot rather than a refusal.
///
/// > The snapshot MUST be taken under the agent's state lock with the cursor
/// > assigned **inside** it.
///
/// [`Fanout::resync`] is that one lock. What comes back is the latest event on
/// each subscribed topic plus the cursor the snapshot is current as of, encoded
/// as the response body.
///
/// # Why wave 1 refused, and why refusing was the wrong answer
///
/// The old code returned `MGMT.STREAM_COMPACTED` on the reasoning that "this
/// build has no subscribed-topic snapshot to take, so it refuses rather than
/// returning an empty snapshot a client would treat as current truth".
///
/// An empty snapshot **is** current truth on a freshly-started agent: nothing has
/// happened yet. What MI-9a actually forbids is an empty snapshot that *hides a
/// gap* — and the cursor beside it is exactly what makes a gap detectable, since
/// a client compares it against the cursor it last saw. Refusing left a client
/// with no way to recover from a `Compacted` marker at all, which turns MI-19's
/// recoverable gap into an unrecoverable one.
///
/// A client that has not subscribed gets the refusal, because for it there is no
/// stream position to be current as of and a cursor would be a number with no
/// referent.
fn resync(context: &ServerContext, granted: &Scopes, subscription: Option<u64>) -> Response {
    if !granted.holds(twinvpn_mgmt::Scope::Events) {
        return failure("POLICY.POLICY_DENIED", "POLICY", "ERROR", true);
    }
    let Some(id) = subscription else {
        // Not attached to the stream: `MGMT.RESYNC_REQUIRED` is what ADR-0017
        // spells here and `twinvpn_mgmt::SUBSTITUTIONS` records that the frozen
        // registry collapses it onto `MGMT.STREAM_COMPACTED` — "the worst of the
        // sixteen", because MI-9a needs the two distinguishable. Named rather
        // than glossed.
        return failure("MGMT.STREAM_COMPACTED", "TRANSIENT", "INFO", true);
    };
    let snapshot = context.fanout.resync(id);
    match serde_json::to_vec(&ResyncBody::from(snapshot)) {
        Ok(result) => Response {
            ok: true,
            result,
            diagnostic: None,
            committed_at_net_seq: None,
        },
        Err(_) => failure("INTERNAL.UNEXPECTED_STATE", "FATAL", "CRITICAL", false),
    }
}

/// `event.resync`'s body: the cursor, and the latest event per topic.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResyncBody {
    /// The stream position this snapshot is current as of.
    ///
    /// A client compares it against the cursor it last saw: equal means it has
    /// missed nothing, greater means it has, and that comparison is the whole
    /// reason the cursor is assigned inside the snapshot's lock.
    pub cursor: u64,
    /// The latest event on each topic that has one, in `topics::ALL` order.
    pub rows: Vec<crate::mi::wire::Event>,
}

impl From<super::events::Snapshot> for ResyncBody {
    fn from(snapshot: super::events::Snapshot) -> Self {
        Self {
            cursor: snapshot.cursor,
            rows: snapshot.rows.into_iter().map(|(_, event)| event).collect(),
        }
    }
}

/// The ADR-0016 §11.14 ceremony, as **ADR-0012 KS-21a defines it for HC-3**.
///
/// # Wave 1 refused every ADMINISTER operation. That was over-strict, and the
/// reason it was over-strict is a host-class rule this shell had not read.
///
/// KS-21 requires "a **local interactive action** on the device itself" and
/// "**OS-mediated authentication** of an `Owner`/administrator principal:
/// `polkit` on Linux…". Read alone, that needs a D-Bus client the workspace does
/// not have, so the shell refused and reported the gap.
///
/// **KS-21a is the host-class rule that resolves it**, and it is worth quoting
/// because it inverts the conclusion:
///
/// > On `HC-3` (headless servers, containers, routers) there is no interactive
/// > session, so read literally this clause makes disarm impossible — which
/// > contradicts **KS-20**'s "blocked must not mean bricked"… **A caller on the
/// > local management socket, authenticated by kernel-supplied peer credentials
/// > to an administrator principal, satisfies this clause on `HC-3`.**
///
/// This host is HC-3 (`BUILD_PROFILE == "H-SRV"`, ADR-0023 EM-1). So the
/// ceremony here is not a missing polkit call — `SO_PEERCRED` **is** the
/// OS-mediated authentication KS-21 clause 2 asks for, and ADR-0023 EM-39 says
/// so in as many words: *"The principal is established by the transport's
/// attested credentials, never self-asserted."*
///
/// # What the ceremony actually checks
///
/// 1. **The principal is kernel-attested.** [`Principal::from_stream`] read it
///    from `SO_PEERCRED` before this connection was negotiated; a client cannot
///    assert it. That is KS-21 clause 2 on this host class.
/// 2. **The principal holds the administrator class.** `mgmt.admin` comes from
///    `twinvpn-operators` membership via the core's catalogue, and PS-12a makes
///    that membership an install-time decision.
/// 3. **The transport is the local `AF_UNIX` socket.** Structurally true — there
///    is no other transport in this binary, and ADR-0017 §11.2 rejected loopback
///    TCP and abstract sockets precisely so this could be structural rather than
///    checked. **KS-21a's third limit** — "disarm MUST NOT be reachable over
///    `ubus`" — is therefore satisfied by there being no `ubus` at all.
///
/// # What it deliberately does NOT do, and why that is not a gap
///
/// KS-21 clause 3's confirmation-that-names-the-consequence and ADR-0023 EM-38's
/// `--confirm-unprotected` are the **client's**, not the agent's:
/// `twinvpnctl` exits 2 rather than prompting, which is EM-38's shape, and
/// `MI-17` requires the action to "fail at **request** rather than at commit" —
/// so an unauthorized caller is refused here, before any confirmation is
/// solicited anywhere.
///
/// # The disclosure is mandatory and is not optional on success
///
/// EM-39 clause 1: an `ADMINISTER` action from a remote administrative session
/// "**is** the headless realization of 'the `Owner`, present'… and is
/// **permitted and disclosed**, with `PLATFORM.PRIV.REMOTE_ADMIN_USED` recording
/// principal, session type, and source. **It is never silent.**" That code is
/// not in the frozen registry, so it is emitted as the `specified_code` of a
/// journal line rather than as a wire `Diagnostic` — the same shape this shell
/// already uses for `PLATFORM.SERVICE.SUPERVISOR_ABSENT`.
///
/// # Errors
///
/// The [`Response`] to send instead of performing the operation.
pub fn administer_ceremony(principal: &Principal, granted: &Scopes) -> Result<(), Box<Response>> {
    // Clause 2 on HC-3. Holding `mgmt.admin` is what "administrator principal"
    // means here, and it came from the core's catalogue plus PS-12a's group.
    if !granted.holds(twinvpn_mgmt::Scope::Admin) {
        // ADR-0012 names `POLICY.KILLSWITCH.DISARM_REFUSED_REMOTE` for a refused
        // disarm and says it is "always a security event". Unregistered; the
        // nearest registered code that keeps the class is used, and the ADR
        // spelling is carried in the log line below.
        tracing::warn!(
            target: "twinvpn.mi",
            specified_code = "POLICY.KILLSWITCH.DISARM_REFUSED_REMOTE",
            reason_code = "MGMT.DISARM_REQUIRES_LOCAL_AUTH",
            principal = %principal.actor(),
            pid = principal.pid,
            "an ADMINISTER operation was refused: the caller does not hold the \
             administrator class. ADR-0012 §11.10: a refused disarm is always a \
             security event"
        );
        return Err(Box::new(failure(
            "MGMT.DISARM_REQUIRES_LOCAL_AUTH",
            "POLICY",
            "WARN",
            true,
        )));
    }

    // Clause 1 and 3 hold structurally: the principal is `SO_PEERCRED`'s and the
    // transport is the local `AF_UNIX` endpoint. The ceremony is satisfied, and
    // EM-39 makes the disclosure part of satisfying it rather than a follow-up.
    tracing::warn!(
        target: "twinvpn.mi",
        specified_code = "PLATFORM.PRIV.REMOTE_ADMIN_USED",
        principal = %principal.actor(),
        pid = principal.pid,
        uid = principal.uid,
        session = "af_unix/so_peercred",
        host_class = "HC-3",
        "an ADMINISTER operation was authorized by ADR-0012 KS-21a's host-class \
         ceremony: a kernel-attested administrator principal on the local \
         management socket. This is never silent (ADR-0023 EM-39)"
    );
    Ok(())
}

pub(super) fn envelope(as_of_ms: u64, body: Body) -> MgmtEnvelope {
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

pub(super) fn diagnostic(
    reason_code: &str,
    class: &str,
    severity: &str,
    user_actionable: bool,
) -> Diagnostic {
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
        // **R-15.** Hardcoding `None` here made the next action unrecoverable for
        // every MI client that is not in this workspace: the key is the ONLY
        // thing on the wire a client can render from (MI-15 forbids the sentence
        // itself), so dropping it left a client with a diagnostic it could not
        // act on. Taken from the registry, like the summary key beside it.
        next_action_key: resolved
            .and_then(twinvpn_types::ReasonCode::next_action_key)
            .map(str::to_owned),
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
        // **R-15.** As above: the key is the only thing MI-15 lets travel, so
        // dropping it left a client unable to render a next action at all.
        next_action_key: code.next_action_key().map(str::to_owned),
        // Typed evidence only, and already restricted to the code's declared
        // fields by the core.
        evidence: source
            .evidence()
            .entries()
            .iter()
            .map(|e| (e.key().to_owned(), evidence_text(e.value())))
            .collect(),
    }
}

/// A canonical address, as text.
fn address_text(address: twinvpn_types::IpAddr) -> String {
    match address {
        twinvpn_types::IpAddr::V4(a) => std::net::Ipv4Addr::from(a.octets()).to_string(),
        twinvpn_types::IpAddr::V6(a) => std::net::Ipv6Addr::from(a.octets()).to_string(),
    }
}

/// One evidence value, as the text a renderer substitutes into a sentence.
///
/// `format!("{:?}")` was wrong for the same reason a summary key is: the
/// renderer substitutes this into `{placeholder}` slots, and `Uint(1280)` is not
/// what belongs in "the path MTU is {mtu}". Each variant is written out so the
/// substituted text is the value, not the value's Rust spelling.
fn evidence_text(value: &twinvpn_types::EvidenceValue) -> String {
    use twinvpn_types::EvidenceValue as V;
    match value {
        V::Text(text) => text.clone(),
        V::Int(n) => n.to_string(),
        V::Uint(n) | V::DurationMs(n) => n.to_string(),
        V::Bool(b) => b.to_string(),
        // An address is `SENSITIVE` under ADR-0015 §11.4 and is carried here in
        // full, deliberately: the MI is a local channel to a kernel-attested
        // principal who already holds `mgmt.status`, and it is THEIR OWN
        // address. Redacting it would make a local diagnostic unusable for the
        // one person entitled to read it. Tier-2 telemetry is a different
        // surface with a different rule.
        V::Address(address) => address_text(*address),
        V::Prefix(prefix) => format!("{}/{}", address_text(prefix.address()), prefix.prefix_len()),
        V::Family(family) => match family {
            twinvpn_types::AddressFamily::V4 => "IPv4".to_owned(),
            twinvpn_types::AddressFamily::V6 => "IPv6".to_owned(),
        },
    }
}
