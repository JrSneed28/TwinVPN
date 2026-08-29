//! What each executed operation actually does.
//!
//! **Authority:** ADR-0017 §11.9 (the operation table's stated `Returns`);
//! `docs/reliability.md` §4.3 (the event table), §4.7 (the aggregate);
//! ADR-0018 §11.4 F-8 (structured data crosses as encoded bytes), §11.16 (e).
//!
//! # About the response bodies
//!
//! The MI has **no response schema** — `contracts/docs/phase1-conflicts.md`
//! OQ-2 deliberately excluded one so the MI could not acquire a second
//! vocabulary — so every body here is an **existing frozen message** chosen for
//! fit, never a new one:
//!
//! | Operation | Body | Why that message |
//! |---|---|---|
//! | `status.get`, `session.list`, `path.list`, `metrics.get` | `twinvpn.v1.HealthSample` | it carries `connection_state`, `health_state`, `per_session` and the mandatory `reason_codes[]`, which is exactly §11.9's stated return, and ADR-0015 §11.7 calls the local status interface the place these are exposed |
//! | `session.get` | `twinvpn.v1.SessionEvent` | one `Session` plus its context |
//! | `version.get` | `twinvpn.v1.CoreBuildIdentity` | S-46 is the version table |
//! | `lifecycle.get` | one selector byte | S-61's phase; there is no frozen `HostLifecycleState` message |
//! | `gateway.get`, `gateway.peer.list`, `gateway.grant.list` | fixed-width big-endian fields | ADR-0017 §11.9's table has **no `gateway.*` row at all** — ADR-0023 EM-35 requires the noun and §11.9 does not enumerate it — so there is no frozen message to choose. The encodings are written out in [`crate::gateway`] and reported to the integration lead |
//!
//! Inventing a message would have been the second contract OQ-2 excluded.

pub(crate) mod carriage;
pub(crate) mod establishment;
pub(crate) mod handshake;

use twinvpn_diag::Tier;
use twinvpn_mgmt::{CoreCommand, Submission};
use twinvpn_schema::v1;
use twinvpn_session::aggregate::{aggregate, Contribution};
use twinvpn_session::event::{Event, Trigger};
use twinvpn_session::journal::{DurableSession, SessionJournal as _};
use twinvpn_session::{Context, Guards};
use twinvpn_types::{codes, Component, DeviceId, Diagnostic, Identifier as _, SessionId};

use crate::core::Core;
use crate::dispatch::{peer_from_params, Lifecycle, Outcome};
use crate::session_table::{session_id_for, SessionEntry};

/// Performs one admissible operation.
///
/// **Exhaustive, no wildcard.** A new [`CoreCommand`] fails to compile here as
/// well as in [`crate::dispatch::disposition`], so it cannot acquire an empty
/// implementation in either place.
///
/// # Errors
///
/// A [`Diagnostic`] carrying a registered code. The caller publishes it as a
/// `CommandRejected` event — §11.6: rejected commands produce an event, never a
/// silent drop.
// One arm per operation, and several arms share a body. Merging them would hide
// which operations are grouped for which reason, which is the whole content of
// this match.
#[allow(clippy::too_many_lines, clippy::match_same_arms)]
pub(crate) fn execute(core: &Core, submission: &Submission) -> Result<Outcome, Box<Diagnostic>> {
    use CoreCommand as C;
    match submission.op {
        C::SessionConnect => connect(core, submission),
        C::SessionReconnect => reconnect(core, submission),
        C::SessionDisconnect => disconnect(core, submission),
        C::NetUp => net_up(core, submission),
        C::NetDown => net_down(core, submission),
        C::SessionGet => session_get(core, submission),
        C::StatusGet | C::SessionList | C::PathList | C::MetricsGet => {
            Ok(Outcome::read(encode(&status_sample(core))))
        }
        C::VersionGet => Ok(Outcome::read(
            core.build_identity().encode(Tier::LocalLedger),
        )),
        C::LifecycleGet => Ok(Outcome::read(vec![core.lifecycle().to_params()])),
        C::HostLifecycle => host_lifecycle(core, submission),
        C::HostNetworkChanged => host_network_changed(core, submission),
        // F-5 gives one instance exactly one totally ordered event stream, so
        // subscription is a property of holding the handle rather than an
        // operation. The in-process caller is already subscribed; the MI
        // transport is where a *connection* subscribes, and that is MI-21's, not
        // the ABI's. Answering with the current cursor is the honest body.
        C::EventSubscribe | C::EventUnsubscribe => {
            Ok(Outcome::read(core.event_cursor().to_be_bytes().to_vec()))
        }

        // ADR-0023 EM-35's `gateway` noun. Every body is computed by
        // `crate::gateway`, which is a thin caller over `twinvpn-gateway` —
        // ADR-0013's decisions stay in that crate and none is restated here.
        C::GatewayGet => Ok(Outcome::read(crate::gateway::encode_status(
            &core.gateway(),
        ))),
        C::GatewayPeerList => Ok(Outcome::read(crate::gateway::encode_peers(&core.gateway()))),
        C::GatewayGrantList => Ok(Outcome::read(crate::gateway::encode_grants(
            &core.gateway(),
        ))),

        // Everything below is `NotWired` in `dispatch::disposition`, which
        // `Core::submit` consults BEFORE calling this function. Reaching one of
        // these arms means the two matches disagree, which is a defect in this
        // crate rather than a condition to report to a caller.
        C::PeerList
        | C::PeerGet
        | C::PolicyGet
        | C::CapabilityGet
        | C::KillswitchGet
        | C::KillswitchExemptGet
        | C::SettingsGet
        | C::SettingsSet
        | C::DiagReport
        | C::DiagBundleCreate
        | C::DiagLogTail
        | C::DiagCaptureSet
        | C::PairBegin
        | C::PairConfirm
        | C::PairCancel
        | C::PairStatus
        | C::DeviceRevoke
        | C::KeyRotate
        | C::KillswitchModeSet
        | C::KillswitchDisarmBegin
        | C::KillswitchDisarmCommit
        | C::DnsPreferenceSet
        | C::RouteAcceptSet
        | C::ExitnodeSelect
        | C::AutostartSet
        | C::UpdateStatus
        | C::UpdateCheck
        | C::UpdateStage
        | C::GatewaySet
        | C::UpdateApply
        | C::UpdateRollback => Err(Box::new(Diagnostic::invariant_violated(
            Component::ManagementInterface,
            "dispatch::disposition and execute disagree about this operation",
        ))),

        // `CoreCommand` is `#[non_exhaustive]`. An operation this build does not
        // know reaches `dispatch::disposition`'s own wildcard first and is
        // refused there, so arriving here is a defect in this crate rather than
        // a caller's error — and it is reported as one.
        _ => Err(Box::new(Diagnostic::invariant_violated(
            Component::ManagementInterface,
            "an operation reached execute() that dispatch::disposition does not know",
        ))),
    }
}

/// T01's `credentials_valid` and `peer_authorized`, as facts — or a refusal.
///
/// Both are `true` in the `Ok` case, and there is deliberately no way to get a
/// `false` out: a guard this build could not establish is a **refusal to
/// proceed**, not a `false` handed to the state machine, which would leave the
/// session in DISCONNECTED with no record of why.
///
/// # What each one reads
///
/// **`credentials_valid`** — this device holds an identity at all, asked of the
/// adapter through `identity_public`. That is CB-5's only way to ask: the
/// private half is not representable in any type this crate can name (CD-I4),
/// so "do we have credentials" is a question only the platform can answer.
///
/// On a host with no secure element the Linux adapter's `AbsentElement` refuses
/// it — §11.16 (l)'s *specified* behaviour, whose whole point is that the core
/// "MUST NOT substitute a file-backed signer silently" — and the connect is
/// refused rather than proceeding without credentials.
///
/// It is deliberately NOT the same as `!credentials_expired`. `Guards` keeps
/// the two apart because "not yet checked" must not read as "expired", and this
/// build cannot check a window: the device's own `DeviceIdentityRecord` carries
/// `not_before_ms`/`not_after_ms` and arrives over C2, which has no transport
/// (W-12). So `credentials_expired` stays `false` — the honest value for a
/// window nobody has read — and the missing check is a *refusal to proceed*
/// through `credentials_valid` rather than a claim about expiry.
///
/// The vault is deliberately **not** consulted here. R-10's memory-only vault
/// is a startup property and is refused at startup, in the shell's §11.6 step
/// (5b); folding it into a per-connect guard would report a durability failure
/// as an authentication one.
///
/// **`peer_authorized`** — [`crate::planes::DataPlaneView::peer_authorized`],
/// which is ADR-0007 N-4's rule: a cached peer record whose `TunnelKeyBinding`
/// verified. Not "we have heard of this device".
///
/// # Both fail closed, and that is visible
///
/// With no `ControlTransport` bound, nothing populates the peer cache, so
/// `peer_authorized` is `false` and `session.connect` is REFUSED by name. That
/// is the correct answer and it is meant to be noticed: the previous `true`
/// made an unauthenticated build look like a working one, which is how "the
/// composed product connects" came to be reported upward.
fn trust_guards(core: &Core, peer: DeviceId) -> Result<(bool, bool), Box<Diagnostic>> {
    let credentials_valid = core.block_on_adapter(|_env, adapter| {
        Box::pin(async move { adapter.identity().public_identity().await.is_ok() })
    });
    if !credentials_valid {
        return Err(Box::new(reject(codes::AUTH_KEY_UNAVAILABLE)));
    }
    // Refused BY NAME rather than by the state machine declining to move: T01's
    // guard failing leaves the session in DISCONNECTED with no transition
    // record, which a caller reads as "nothing happened" — the shape §11.6
    // forbids. The two codes are different facts, and an operator acts
    // differently on each.
    if !core.data_plane_view().peer_authorized(peer) {
        return Err(Box::new(reject(codes::AUTH_PEER_UNTRUSTED)));
    }
    Ok((true, true))
}

/// `session.connect` — the whole establishment chain.
///
/// Naturally idempotent (§11.9's `nat`), and the mechanism is the derived
/// `SessionId`: connecting twice to one peer reaches the same `Session`, and
/// T01's own rule absorbs a request while already connecting.
fn connect(core: &Core, submission: &Submission) -> Result<Outcome, Box<Diagnostic>> {
    let peer = peer_from_params(&submission.params)
        .ok_or_else(|| Box::new(reject(codes::PROTO_MALFORMED_MESSAGE)))?;
    let session_id = session_id_for(peer);
    let mut effects = 0u32;

    // 1. Gather, on the platform — **once per `Session`**. Real adapter calls:
    //    supported_families, enumerate, and one bind_udp per family the host
    //    offers.
    //
    //    A `Session` that already holds sockets keeps them. §11.9 marks this
    //    operation `nat`, and re-binding on an absorbed second request would
    //    hand the peer a *different source port* than the first attempt just
    //    advertised — discarding whatever NAT mapping that attempt created and
    //    making the second connect actively undo the first's work. It would
    //    also move the endpoint out from under a handshake already in flight.
    //    Idempotent has to mean "the second call changes nothing", not "the
    //    second call redoes everything".
    let previously_gathered = {
        let sessions = core.sessions();
        sessions
            .get(&session_id)
            .is_some_and(|entry| !entry.sockets.is_empty())
    };
    let gathered = if previously_gathered {
        None
    } else {
        let gathered = core.block_on_adapter(|env, adapter| {
            Box::pin(crate::establish::gather(env, adapter, session_id))
        });
        effects += 1;
        Some(gathered)
    };

    // Read the facts off `gathered` before its sockets move into the session
    // entry: the guards and T03/T04's selector both need them. On a re-entered
    // `Session` they come from the ledger instead — the same facts, recorded by
    // the gather that did run, rather than re-derived from a gather that did
    // not.
    let (usable_candidate, no_candidate_either_family) = if let Some(gathered) = gathered.as_ref() {
        (
            gathered.usable_candidate(),
            gathered.no_candidate_either_family(),
        )
    } else {
        let sessions = core.sessions();
        let rows = sessions
            .get(&session_id)
            .map_or(0, |entry| entry.ledger.rows().len());
        (rows > 0, rows == 0)
    };

    // 2. T01's two trust guards, READ rather than asserted.
    //
    //    These were literal `true`s, with a comment saying so — "THAT IS A REAL
    //    WEAKNESS". The consequence was that `session.connect` drove the state
    //    machine to CONNECTED for any 32 bytes a caller passed as a peer: no
    //    credential check, no authorization check, no handshake. An unauthorized
    //    peer was indistinguishable from an authorized one at every layer above.
    //
    //    Both are now facts the composed core can establish, and both FAIL
    //    CLOSED when it cannot. See `trust_guards`.
    let (credentials_valid, peer_authorized) = trust_guards(core, peer)?;
    let guards = Guards {
        credentials_valid,
        peer_authorized,
        usable_candidate,
        no_candidate_either_family,
        ..Guards::default()
    };

    let mut sessions = core.sessions();
    let entry = sessions
        .entry(session_id)
        .or_insert_with(|| SessionEntry::new(core.env().clone(), session_id, peer));

    let outcome = entry.runtime.apply(
        Trigger::Event(Event::ConnectRequested),
        guards,
        Context::default(),
    );
    if let Some(record) = outcome.record() {
        core.publish_transition(record.to_proto(), submission.actor_principal.clone());
        effects += 1;
    }

    // 3. Admit the candidates and schedule the race — `twinvpn-path`'s ledger
    //    and `Race`, driven here. Skipped where step 1 was: the ledger already
    //    holds these rows and re-recording them would double-count the
    //    connectivity report ADR-0015 §11.8 item 4 renders from it.
    let now = core.env().now_monotonic();
    if let Some(gathered) = gathered {
        entry.race = Some(crate::establish::admit(&mut entry.ledger, &gathered, now));
        entry.sockets = gathered.sockets;
        effects += 1;
    }

    // 4. `EV_CANDIDATES_READY` fires on the FIRST USABLE candidate (§4.3), or
    //    `EV_CANDIDATE_TIMEOUT`'s guard is what T04 reads. Both are real
    //    transitions, taken here rather than left to a timer that nothing winds.
    let next = if usable_candidate {
        Some(Event::CandidatesReady)
    } else if no_candidate_either_family {
        Some(Event::CandidateTimeout)
    } else {
        None
    };
    if let Some(event) = next {
        let outcome = entry
            .runtime
            .apply(Trigger::Event(event), guards, Context::default());
        if let Some(record) = outcome.record() {
            core.publish_transition(record.to_proto(), submission.actor_principal.clone());
            effects += 1;
        }
    }

    // 5. Probe. This is where a packet moves, when a peer endpoint is known.
    if let Some(race) = entry.race.as_ref() {
        let sockets = core.block_on_probe(
            &entry.sockets,
            race,
            &mut entry.ledger,
            entry.peer_endpoint,
            now,
        );
        effects += u32::try_from(sockets).unwrap_or(u32::MAX);
    }

    // 6. **The handshake.** NEGOTIATING → CONNECTING → a steady state, and only
    //    on a `Noise_IKpsk2` that actually completed.
    //
    //    Until this call existed, `session.connect` stopped at NEGOTIATING and
    //    `ownership.md` §8 recorded the consequence at the item it half-closed:
    //    "**Still open:** there is no handshake and no key exchange."
    //    `twinvpn_tunnel::bind` had shipped the whole of `Noise_IKpsk2` and
    //    nothing in the composed core called any of it.
    //
    //    The lock is released first. The handshake waits on a peer for up to
    //    `T_CONNECT`, and holding the session table across that would make one
    //    peer's silence every other `Session`'s stall.
    drop(sessions);
    effects = effects.saturating_add(establishment::carry(core, session_id, submission));

    // A `Session` closed under us while the handshake ran is a refusal, not a
    // silent success — and the lock taken to check that is released before
    // `recorded` takes it again.
    if !core.sessions().contains_key(&session_id) {
        return Err(Box::new(reject(codes::NET_SESSION_CLOSED_BY_USER)));
    }

    // 7 and 8, which are one concern — what this connect leaves behind — and
    //    are extracted so this function stays inside T1's length bound.
    effects = effects.saturating_add(recorded(core, session_id, peer, submission, now));

    Ok(Outcome::new(Vec::new(), effects))
}

/// Steps 7 and 8 of [`connect`]: the durable record, and the §4.4 local event.
///
/// Extracted whole rather than split at the `drop(sessions)`, because the two
/// share the one fact they both report — the state the machine actually reached
/// — and reading it twice would let the record and the event disagree about the
/// same connect. The session lock is taken here and released before the event is
/// published, exactly as it was inline.
fn recorded(
    core: &Core,
    session_id: SessionId,
    peer: twinvpn_types::DeviceId,
    submission: &Submission,
    now: twinvpn_env::MonotonicInstant,
) -> u32 {
    let mut effects = 0u32;
    let mut sessions = core.sessions();
    let Some(entry) = sessions.get_mut(&session_id) else {
        // The `Session` was closed under us while the handshake ran. There is
        // nothing to record and nothing to announce; `connect` has already
        // published everything it did.
        return effects;
    };

    // The durable half (S-12). Queued here; `Core::flush` makes it durable.
    let state = entry.runtime.machine().state();
    let record = DurableSession {
        session_id,
        peer,
        last_state: state,
        last_reason: entry.runtime.machine().reason(),
    };
    if core.journal().persist(&record).is_ok() {
        effects += 1;
    }

    // The §4.4 local event. `NAT.SINGLE_FAMILY_CANDIDATES` is what
    // `protocol.md` §4.1 requires to be flagged, and `single_family` is the
    // fact it turns on.
    let context = core.emitter().context(
        Some(session_id),
        None,
        Some(state.connection_state()),
        now,
        twinvpn_diag::Correlation::default(),
        &[],
        None,
    );
    let event = core.emitter().session_event(
        Some(session_id),
        context,
        v1::session_event::Event::ConnectionRequested(v1::ConnectionRequested {
            peer_device_id: peer.as_bytes().to_vec(),
            trigger: submission
                .actor_principal
                .as_deref()
                .map_or_else(|| "policy".to_owned(), |_| "user".to_owned()),
        }),
    );
    drop(sessions);
    core.publish_session_event(event, submission.actor_principal.clone());
    effects + 1
}

/// `session.reconnect` — forces re-establishment on an existing `Session`.
fn reconnect(core: &Core, submission: &Submission) -> Result<Outcome, Box<Diagnostic>> {
    let peer = peer_from_params(&submission.params)
        .ok_or_else(|| Box::new(reject(codes::PROTO_MALFORMED_MESSAGE)))?;
    let session_id = session_id_for(peer);
    if !core.sessions().contains_key(&session_id) {
        // §11.9 floors this at the §6.1 backoff floor so it cannot be a local
        // DoS. Refusing an unknown Session is the same rule at the front door.
        return Err(Box::new(reject(codes::NET_SESSION_CLOSED_BY_USER)));
    }
    connect(core, submission)
}

/// `session.disconnect` — injects `EV_DISCONNECT_REQUESTED`.
fn disconnect(core: &Core, submission: &Submission) -> Result<Outcome, Box<Diagnostic>> {
    let peer = peer_from_params(&submission.params)
        .ok_or_else(|| Box::new(reject(codes::PROTO_MALFORMED_MESSAGE)))?;
    Ok(Outcome::new(
        Vec::new(),
        close_one(core, session_id_for(peer), submission),
    ))
}

/// `net.up` — `TwinNet`-scope connect across every known `Session`.
// `net_up`, `net_down` and `host_network_changed` cannot fail today. Their
// signature is the DISPATCHER'S CONTRACT rather than a statement about the
// current body: every arm of `execute` returns the same type, and narrowing one
// of them would mean the next failure mode it acquires is a signature change
// across the match. Kept uniform on purpose.
#[allow(clippy::unnecessary_wraps)]
fn net_up(core: &Core, submission: &Submission) -> Result<Outcome, Box<Diagnostic>> {
    let peers: Vec<DeviceId> = core.sessions().values().map(|e| e.peer).collect();
    let mut effects = 0u32;
    let mut connected = 0usize;
    for peer in peers {
        let mut scoped = submission.clone();
        scoped.op = CoreCommand::SessionConnect;
        scoped.params = peer.as_bytes().to_vec();
        if let Ok(outcome) = connect(core, &scoped) {
            effects = effects.saturating_add(outcome.effects);
            connected += 1;
        }
    }

    // **R-2 / R-7.** The data plane is now composed and installed here.
    //
    // Until this call existed, `PlatformAdapter::apply` had no production caller
    // anywhere in the tree: the composed product installed no ruleset of its
    // own, programmed no route, applied no DNS policy and created no overlay
    // interface. On a Linux host the KS-19 boot table was the only enforcement
    // that ever existed and its scope is the overlay prefixes alone.
    //
    // `crate::enforce::arm` is fail-closed at every step, so a refusal here
    // leaves the host `Blocked` rather than open — which is why the refusal is
    // reported as the operation's outcome and not swallowed.
    let armed = crate::enforce::arm(core)?;
    effects = effects.saturating_add(1);

    // **The pump, now that there is an interface to pump into.**
    //
    // A `session.connect` that establishes before any arming has a live tunnel
    // and no `TunnelHandle` — ADR-0012 §11.8 computes the contract from the
    // peers that actually came up, so connecting first and arming second is the
    // order. This is the second half of `carriage::start`, and it is idempotent:
    // a `Session` whose pump is already running keeps it.
    let established: Vec<SessionId> = core
        .sessions()
        .iter()
        .filter(|(_, e)| e.established.is_some())
        .map(|(id, _)| *id)
        .collect();
    for id in established {
        if carriage::start(core, id) {
            effects = effects.saturating_add(1);
        }
    }
    tracing::info!(
        target: "twinvpn.core.enforce",
        generation = armed.generation.0,
        ruleset = ?armed.ruleset,
        sessions = connected,
        "net.up installed a contract generation and read the posture back"
    );
    Ok(Outcome::new(Vec::new(), effects.max(1)))
}

/// `net.down` — clears session intent.
///
/// **MI-K1: this MUST NOT clear the latch.** Nothing here touches
/// `twinvpn-enforce` or calls `set_ruleset`; the M2 latch is cleared
/// *exclusively* by §11.14's ceremony, and this is the single most likely place
/// for a local-control design to open a leak.
#[allow(clippy::unnecessary_wraps)]
fn net_down(core: &Core, submission: &Submission) -> Result<Outcome, Box<Diagnostic>> {
    let ids: Vec<SessionId> = core.sessions().keys().copied().collect();
    let mut effects = 0u32;
    for id in ids {
        effects = effects.saturating_add(close_one(core, id, submission));
    }

    // §11.8's teardown, in order: link down → swap to `RULESET_BLOCKED` →
    // destroy the interface. **The rules stay live** — CB-6 puts them in the
    // OS's custody so that the tunnel going away cannot drop protection.
    //
    // MI-K1 is untouched: this RAISES the posture and never clears the latch,
    // and only §11.14's authenticated ceremony can lower one. Leaving the
    // interface up with no contract on it — which is what this used to do,
    // because nothing here reached the adapter at all — is the state that
    // *would* have leaked.
    // Every carriage stops before the interface it wrote into is destroyed. A
    // pump still holding a `TunnelHandle` the adapter has torn down would write
    // into a handle that no longer names anything, and the adapter's refusal
    // would arrive as a `Fault` on a session the user simply turned off.
    carriage::stop_all(core);
    effects = effects.saturating_add(1);

    crate::enforce::teardown(core);
    effects = effects.saturating_add(1);
    Ok(Outcome::new(Vec::new(), effects.max(1)))
}

fn close_one(core: &Core, session_id: SessionId, submission: &Submission) -> u32 {
    let mut effects = 0u32;
    let mut sessions = core.sessions();
    let Some(entry) = sessions.get_mut(&session_id) else {
        return 0;
    };
    // **The pump stops here**, before the transition is published, so a caller
    // that observes DISCONNECTED cannot then observe a packet. The keys go with
    // it — §7.2's "keys are unusable and are zeroed" — and the order inside
    // `tear_down` is what keeps a live step from meeting a zeroed key.
    entry.tear_down();
    let outcome = entry.runtime.apply(
        Trigger::Event(Event::DisconnectRequested),
        Guards::default(),
        Context::default(),
    );
    if let Some(record) = outcome.record() {
        let proto = record.to_proto();
        drop(sessions);
        core.publish_transition(proto, submission.actor_principal.clone());
        effects += 1;
        // §6.5's one exception: a `Session` the user explicitly closed resumes
        // into DISCONNECTED, not RECONNECTING. Forgetting it is what makes that
        // true across a restart.
        if core.journal().forget(session_id).is_ok() {
            effects += 1;
        }
    }
    effects
}

/// `session.get` — one `Session` and its context.
fn session_get(core: &Core, submission: &Submission) -> Result<Outcome, Box<Diagnostic>> {
    let peer = peer_from_params(&submission.params)
        .ok_or_else(|| Box::new(reject(codes::PROTO_MALFORMED_MESSAGE)))?;
    let session_id = session_id_for(peer);
    let sessions = core.sessions();
    let entry = sessions
        .get(&session_id)
        .ok_or_else(|| Box::new(reject(codes::NET_SESSION_CLOSED_BY_USER)))?;
    let state = entry.runtime.machine().state();
    let context = core.emitter().context(
        Some(session_id),
        None,
        Some(state.connection_state()),
        core.env().now_monotonic(),
        twinvpn_diag::Correlation::default(),
        &[],
        None,
    );
    let event = core.emitter().session_event(
        Some(session_id),
        context,
        v1::session_event::Event::CandidateUpdated(v1::CandidateUpdated {
            candidates: None,
            // §4.1's flag, derived from the ledger's per-family counts —
            // both halves are always present, so "only one family produced
            // anything" is a fact rather than an inference from a missing key.
            single_family: {
                let counts = entry.ledger.report().per_family;
                (counts.v4 == 0) != (counts.v6 == 0)
            },
        }),
    );
    Ok(Outcome::read(encode(&event)))
}

/// `host.lifecycle` — ADR-0018 §11.16 (e)'s commands.
fn host_lifecycle(core: &Core, submission: &Submission) -> Result<Outcome, Box<Diagnostic>> {
    let phase = Lifecycle::from_params(&submission.params)
        .ok_or_else(|| Box::new(reject(codes::PROTO_MALFORMED_MESSAGE)))?;
    core.set_lifecycle(phase);
    let mut effects = 1u32;
    let ids: Vec<SessionId> = core.sessions().keys().copied().collect();
    for id in ids {
        let mut sessions = core.sessions();
        let Some(entry) = sessions.get_mut(&id) else {
            continue;
        };
        let outcome = entry.runtime.apply(
            Trigger::Event(phase.event()),
            Guards::default(),
            Context::default(),
        );
        if let Some(record) = outcome.record() {
            let proto = record.to_proto();
            drop(sessions);
            core.publish_transition(proto, submission.actor_principal.clone());
            effects += 1;
        }
    }
    Ok(Outcome::new(Vec::new(), effects))
}

/// `host.network_changed` — **F-9's inversion**, realized.
///
/// The shell subscribes with the OS and submits the change; the **core** decides
/// what it means (CB-2). Nothing here trusts the shell for a domain fact.
#[allow(clippy::unnecessary_wraps)]
fn host_network_changed(core: &Core, submission: &Submission) -> Result<Outcome, Box<Diagnostic>> {
    // The encoded change is not a frozen message — `NetworkChange` is a core
    // type, not a wire type. A submission with no body is the "re-enumerate"
    // case, which is what `InterfaceProvider::subscribe`'s own doc says a caller
    // must do after an `EventsLost`.
    let facts = core.block_on_adapter(|_, adapter| Box::pin(adapter.interfaces().enumerate()));
    let mut effects = 1u32;
    // A link event only reaches the machine when the CORE has decided the link
    // actually went away — CB-2's boundary. Here the fact is a re-enumeration,
    // so the decision is "is anything up".
    let event = match facts.as_ref() {
        Ok(f) if f.iter().any(|i| i.is_up && !i.is_overlay) => {
            Event::LinkUp(twinvpn_session::event::LinkKind::Unknown)
        }
        Ok(_) => Event::LinkDown(twinvpn_session::event::LinkKind::Unknown),
        // Enumeration was REFUSED. That is not "no interfaces": inventing a
        // link-down from a refused query would tear down a healthy session.
        Err(_) => return Ok(Outcome::new(Vec::new(), effects)),
    };

    let ids: Vec<SessionId> = core.sessions().keys().copied().collect();
    for id in ids {
        let mut sessions = core.sessions();
        let Some(entry) = sessions.get_mut(&id) else {
            continue;
        };
        let outcome =
            entry
                .runtime
                .apply(Trigger::Event(event), Guards::default(), Context::default());
        if let Some(record) = outcome.record() {
            let proto = record.to_proto();
            drop(sessions);
            core.publish_transition(proto, submission.actor_principal.clone());
            effects += 1;
        }
    }
    Ok(Outcome::new(Vec::new(), effects))
}

/// §4.7's aggregate, as a `HealthSample`.
fn status_sample(core: &Core) -> v1::HealthSample {
    let sessions = core.sessions();
    let contributions: Vec<Contribution> = sessions
        .values()
        .map(|e| {
            let state = e.runtime.machine().state();
            Contribution {
                state,
                reason_code: e.runtime.machine().reason(),
                in_protected_scope: true,
                has_usable_path: state.has_path(),
            }
        })
        .collect();
    // `fail_closed` with no enforcement mode bound reads as TRUE, which is
    // `Guards::fail_closed`'s rule: "we have not been told" is not a licence.
    let aggregate = aggregate(&contributions, true);

    let per_session: Vec<v1::ConnectionHealth> = sessions
        .iter()
        .map(|(id, e)| v1::ConnectionHealth {
            session_id: id.as_bytes().to_vec(),
            path_class: e
                .runtime
                .machine()
                .state()
                .carrier()
                .map_or(0, twinvpn_types::PathClass::to_wire),
            mtu: 0,
            ..Default::default()
        })
        .collect();

    // §14's teeth: a sample reporting DEGRADED or FAILED with an EMPTY
    // reason_codes[] is a MALFORMED MESSAGE. The aggregate's worst contributor
    // supplies it, and where there is none the list stays empty because the
    // state does not require one.
    // `protocol.md` §14: a sample reporting DEGRADED or FAILED with an EMPTY
    // reason_codes[] is a MALFORMED MESSAGE and MUST be rejected with
    // INTERNAL.MISSING_REASON. Emitting one would be this core failing its own
    // I6 teeth, so where the aggregate has no contributor reason the state's own
    // class-compatible default supplies one — the same rule
    // `twinvpn_session::machine::default_resume_reason` applies to a restored
    // Session, applied to the aggregate.
    let reason_codes = aggregate
        .reason_code
        .or_else(|| default_reason_for(aggregate.state))
        .map(|c| vec![c.as_str().to_owned()])
        .unwrap_or_default();

    v1::HealthSample {
        connection_state: aggregate.state.to_wire(),
        per_session,
        reason_codes,
        agent_version: core.build_identity().core_version.to_owned(),
        proto_version: core.build_identity().protocol_epoch_max,
        ..Default::default()
    }
}

/// The class-compatible reason a reason-bearing aggregate state carries when no
/// contributing `Session` supplied one.
///
/// `None` for a state that does not require one — a resting or steady aggregate
/// legitimately has no reason, and inventing one would be its own kind of lie.
fn default_reason_for(state: twinvpn_types::ConnectionState) -> Option<twinvpn_types::ReasonCode> {
    use twinvpn_types::ConnectionState as S;
    // §10.2's static rule: the code's REGISTERED CLASS must be admissible in the
    // state that carries it. Each answer below was chosen for its class first
    // and its wording second.
    match state {
        // POLICY, and the honest answer: fail-closed is holding traffic.
        S::Blocked => Some(codes::POLICY_KILLSWITCH_ENGAGED),
        // PERSISTENT: nothing is carrying traffic and we cannot say more.
        S::Failed => Some(codes::NET_NO_ROUTE),
        // TRANSIENT, the only class DEGRADED admits.
        S::Degraded => Some(codes::NET_QOS_DEGRADED_TIMEOUT),
        // TRANSIENT too — and deliberately NOT `NET.NO_ROUTE`, which is
        // PERSISTENT: a RECONNECTING Session is by definition still trying, and
        // labelling it with a persistent code would tell a surface to stop
        // waiting.
        S::Reconnecting => Some(codes::NET_NO_USABLE_CANDIDATES),
        _ => None,
    }
}

fn encode<M: prost::Message>(msg: &M) -> Vec<u8> {
    let mut buf = Vec::with_capacity(msg.encoded_len());
    msg.encode(&mut buf).expect("a Vec never fails to grow");
    buf
}

fn reject(code: twinvpn_types::ReasonCode) -> Diagnostic {
    Diagnostic::builder(code, Component::ManagementInterface).build()
}
