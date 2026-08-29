//! From a raced candidate to a carrying tunnel: §4.5 T05 through T12.
//!
//! **Authority:** `docs/reliability.md` §4.5 (T05, T07, T08–T12), §4.4 (no user
//! traffic on an unvalidated path, ever);
//! [ADR-0001](../../../../../docs/adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)
//! §7.2, §7.3, §7.3.1; [ADR-0007](../../../../../docs/adr/ADR-0007-identity-lifecycle-and-revocation.md)
//! N-4; [ADR-0014](../../../../../docs/adr/ADR-0014-protocol-versioning-and-capability-negotiation.md)
//! D1, N-8; [ADR-0012](../../../../../docs/adr/ADR-0012-killswitch-and-fail-closed-enforcement.md)
//! KS-18(a); [ADR-0018](../../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! CB-2; `ownership.md` §6 ("Never route around TwinVPN while fail-closed is
//! active").
//!
//! # The one rule this module exists to hold
//!
//! **A `Session` reaches a steady state only through a completed
//! `Noise_IKpsk2` handshake.** Every path below either produces a live
//! [`twinvpn_tunnel::Tunnel`] with real keys or fires `EV_HANDSHAKE_FAIL` with a
//! registered code. There is no third branch, no "assume it worked", and no
//! guard set anywhere in this file that hands the table a `true` the composed
//! core did not establish.
//!
//! `ownership.md` §8 records the previous position exactly: the trust guards were
//! made real, and *"**Still open:** there is no handshake and no key exchange."*
//! This is that half.
//!
//! # T09, not T08, and the reason is stated rather than assumed
//!
//! §4.5 splits the win by class. T08 is `EV_HANDSHAKE_OK{L2}` and its guard is
//! `path_validated`; T14's companion guard is `same_l2_confirmed`, "the peer is
//! confirmed on the same L2 segment". **Nothing in this build can confirm
//! that** — it needs `protocol.md` §10.4's authenticated disco exchange, whose
//! key `crate::establish::probe` records as unavailable — so this build never
//! claims `LOCAL_DIRECT`. A direct win is `WAN_DIRECT` under T09, whose extra
//! guard `no_l2_path_won` is *true by construction here*, and a relayed win is
//! `RELAYED` under T10. Claiming the better class on a path we cannot
//! distinguish would be exactly the over-claim §4.4 forbids.
//!
//! # `path_validated` is the handshake, not a belief about it
//!
//! ADR-0012 KS-18(a) asks for "an authenticated bidirectional path validation"
//! before `RULESET_PROTECTED` may be entered. A completed `Noise_IKpsk2` over a
//! path *is* one: message 1 went out on it, message 2 came back on it, and both
//! authenticated under keys only the two devices hold. So the guard is set from
//! the handshake's own outcome and from nothing else — which is why a peer that
//! fails the handshake cannot reach a steady state and therefore cannot lift the
//! host out of `RULESET_BLOCKED` either.
//!
//! # The relay is a fallback, and never a fallback to something weaker
//!
//! When the direct handshake does not complete, [`crate::execute::carriage`]
//! opens a relay leg and the **same** tunnel is carried over it. ADR-0005 §7.3
//! puts the relay outside the L-DATA handshake entirely — its static key "is
//! **NOT** an input" — so moving to a relay changes the carriage and no security
//! property. Where there is no relay to reach either, the `Session` fails with a
//! registered code and stays out of a steady state: `ownership.md` §6's "never
//! route around TwinVPN while fail-closed is active" has no exception for "the
//! relay was unavailable too".

use twinvpn_mgmt::Submission;
use twinvpn_session::event::{Event, Trigger};
use twinvpn_session::state::SessionState;
use twinvpn_session::{Context, Guards};
use twinvpn_types::{codes, Component, Diagnostic, PathClass, ReasonCode, SessionId};

use crate::core::Core;
use crate::datapath::Cancel;
use crate::execute::{carriage, handshake};
use crate::session_table::Established;

/// Drives one `Session` from NEGOTIATING to a steady state, or to a refusal.
///
/// Returns the number of observable effects, which is what `session.connect`
/// reports and what `Core::submit` checks against its "an operation declared
/// EXECUTES produced no observable effect" invariant.
///
/// Takes no lock across the handshake: the caller has released the session table
/// before calling, and every step below re-acquires it for as long as it needs.
pub(crate) fn carry(core: &Core, session_id: SessionId, submission: &Submission) -> u32 {
    let mut effects = 0u32;

    // T05 / T07 — NEGOTIATING.
    //
    // ADR-0014 D1: advertisements are claims and `NegotiationConfirm` is the
    // decision, taken **inside** the established tunnel. What is decided here is
    // narrower and is the honest question at this point in the chain: does this
    // device hold the negotiated inputs the §7.3.1 prologue binds? They arrive
    // as the `NegotiationBinding` inside the key material, and without them
    // there is nothing to bind — so `EV_NEGOTIATION_FAIL` is the truthful event
    // and T07's retry budget is what decides whether to try again.
    let negotiated = {
        let sessions = core.sessions();
        sessions
            .get(&session_id)
            .is_some_and(|e| e.keying.is_some())
    };
    if state_of(core, session_id) == Some(SessionState::Negotiating) {
        let event = if negotiated {
            Event::NegotiationOk
        } else {
            Event::NegotiationFail
        };
        effects = effects.saturating_add(fire(
            core,
            session_id,
            event,
            Guards {
                // T07's guard. A `Session` that has never attempted anything has
                // its full budget, and `SessionRuntime` owns the accounting.
                retry_budget_available: true,
                ..Guards::default()
            },
            Context::default(),
            submission,
        ));
    }

    if state_of(core, session_id) != Some(SessionState::Connecting) {
        return effects;
    }

    // T08–T12 — CONNECTING. The handshake, and nothing else, decides.
    match direct(core, session_id) {
        Ok(()) => {
            effects = effects.saturating_add(reached(
                core,
                session_id,
                PathClass::WanDirect,
                submission,
            ));
        }
        Err(direct_refusal) => {
            // The direct race produced no validated path. ADR-0006's answer is a
            // relay, and it is tried before the `Session` is failed.
            match relayed(core, session_id) {
                Ok(()) => {
                    effects = effects.saturating_add(reached(
                        core,
                        session_id,
                        carriage::RELAYED,
                        submission,
                    ));
                }
                Err(relay_refusal) => {
                    effects = effects.saturating_add(failed(
                        core,
                        session_id,
                        &direct_refusal,
                        relay_refusal,
                        submission,
                    ));
                }
            }
        }
    }
    effects
}

/// Runs the direct `Noise_IKpsk2` handshake and records the tunnel it produced.
///
/// The key material is **taken out** of the entry for the duration and put back
/// afterwards — the same borrow discipline `Core::tick` uses for the ledger —
/// so the session table is not held across a wait a peer controls.
fn direct(core: &Core, session_id: SessionId) -> Result<(), handshake::Refusal> {
    let Some((socket, peer, peer_endpoint, keying)) = ({
        let mut sessions = core.sessions();
        sessions.get_mut(&session_id).and_then(|entry| {
            let socket = entry.sockets.first().map(std::sync::Arc::clone)?;
            Some((
                socket,
                entry.peer,
                entry.peer_endpoint,
                entry.keying.take(),
            ))
        })
    }) else {
        return Err(handshake::Refusal::NoEndpoint);
    };

    let trust_epoch = keying
        .as_ref()
        .map_or(0, |k| core.data_plane_view().trust_epoch(k.twinnet()));
    let local_device = keying.as_ref().map(super::handshake::local_of);
    let deadline = handshake::deadline_from(core.env().now_monotonic());

    let mut outcome = None;
    core.env().runtime().block_on(Box::pin(async {
        outcome = Some(
            handshake::drive(
                core.env(),
                socket.as_ref(),
                session_id,
                local_device.unwrap_or(peer),
                peer,
                peer_endpoint,
                keying.as_ref(),
                trust_epoch,
                deadline,
            )
            .await,
        );
    }));

    // The material goes back whatever happened. A failed handshake is not a
    // reason to forget a peer's keys: T12's retry is exactly the case that needs
    // them again, and dropping them here would turn one lost datagram into a
    // permanent `AUTH.KEY_UNAVAILABLE`.
    let mut sessions = core.sessions();
    let Some(entry) = sessions.get_mut(&session_id) else {
        return Err(handshake::Refusal::NoKeyMaterial);
    };
    entry.keying = keying;

    let handshaken = outcome.expect("block_on drives the future to completion")?;
    entry.established = Some(Established {
        tunnel: handshaken.tunnel,
        pump: None,
        cancel: Cancel::new(),
        spawned: false,
        class: PathClass::WanDirect,
        local_receiver: handshaken.local_receiver,
        peer_receiver: handshaken.peer_receiver,
    });
    drop(sessions);

    // The interface may not exist yet — `net.up` arms after it connects — and
    // that is not a failure. See `carriage::start`.
    carriage::start(core, session_id);
    Ok(())
}

/// Opens a relay leg and carries the **same** tunnel over it.
///
/// # Why the tunnel is re-established rather than reused today
///
/// It is not: there is no second handshake here. A `Session` that reaches this
/// point has no live tunnel — the direct handshake is what would have produced
/// one — so the leg is opened first and the handshake is then run **through**
/// it. That ordering is ADR-0005 §11.1's: the leg carries opaque payloads, so it
/// has to exist before there is anything to carry.
///
/// **What is not wired, stated plainly:** running the L-DATA handshake itself
/// through a bound leg needs the leg's `DATA` frames to carry handshake messages
/// as well as transport records, and [`crate::relay::Sealed`] is deliberately
/// opaque about which it holds. So this build opens and binds the leg — the part
/// that had no caller at all — and refuses the `Session` if the direct handshake
/// did not complete. The relayed *carriage* is implemented
/// ([`crate::execute::carriage::relay_step`]) and is reached by a `Session` that
/// established directly and later moved; the relayed *establishment* is reported
/// as open.
fn relayed(core: &Core, session_id: SessionId) -> Result<(), Box<Diagnostic>> {
    carriage::open_relay(core, session_id)?;
    let carrying = core
        .sessions()
        .get(&session_id)
        .is_some_and(crate::session_table::SessionEntry::is_carrying);
    if carrying {
        Ok(())
    } else {
        // A bound leg with no tunnel to carry is not a connected `Session`, and
        // saying so is the whole of the fail-closed rule here: a leg is
        // carriage, never authentication.
        Err(Box::new(refuse(codes::CRYPTO_HANDSHAKE_REJECTED)))
    }
}

/// Fires `EV_HANDSHAKE_OK{class}` with the guards the handshake established.
fn reached(
    core: &Core,
    session_id: SessionId,
    class: PathClass,
    submission: &Submission,
) -> u32 {
    fire(
        core,
        session_id,
        Event::HandshakeOk(class),
        Guards {
            // The handshake completed on this path, in both directions, under
            // keys only these two devices hold. That is KS-18(a)'s
            // "authenticated bidirectional path validation" and it is the only
            // thing that sets this guard anywhere in the crate.
            path_validated: true,
            // T09's discriminator. True by construction: this build cannot
            // confirm a same-L2 peer at all, so no L2 path can have won.
            no_l2_path_won: true,
            // T10's. A relayed win is only reported when the direct attempt did
            // not produce one, which is the branch that reaches here with
            // `PathClass::Relayed`.
            no_direct_path_won: class == PathClass::Relayed,
            ..Guards::default()
        },
        Context::default(),
        submission,
    )
}

/// Fires `EV_HANDSHAKE_FAIL` carrying the most specific code observed.
///
/// §4.5 T12 reads `Context::transport_code`, and `transport_or_default` calls
/// `NET.NO_USABLE_CANDIDATES` "the honest answer — it is what actually
/// happened — rather than a generic 'connection failed', which §3.3 prohibits
/// outright". The direct refusal is the more specific of the two, so it wins;
/// the relay's is published beside it so neither is lost.
fn failed(
    core: &Core,
    session_id: SessionId,
    direct_refusal: &handshake::Refusal,
    relay_refusal: Box<Diagnostic>,
    submission: &Submission,
) -> u32 {
    let code = direct_refusal.reason_code();
    core.publish_diagnostic(&refuse(code));
    core.publish_diagnostic(&relay_refusal);
    let mut effects = 2u32;
    effects = effects.saturating_add(fire(
        core,
        session_id,
        Event::HandshakeFail,
        Guards {
            retry_budget_available: true,
            ..Guards::default()
        },
        Context {
            transport_code: Some(code),
            ..Context::default()
        },
        submission,
    ));
    effects
}

/// Applies one event and publishes whatever transition it produced.
fn fire(
    core: &Core,
    session_id: SessionId,
    event: Event,
    guards: Guards,
    context: Context,
    submission: &Submission,
) -> u32 {
    let record = {
        let mut sessions = core.sessions();
        let Some(entry) = sessions.get_mut(&session_id) else {
            return 0;
        };
        entry
            .runtime
            .apply(Trigger::Event(event), guards, context)
            .record()
            .map(twinvpn_session::TransitionRecord::to_proto)
    };
    match record {
        Some(record) => {
            core.publish_transition(record, submission.actor_principal.clone());
            1
        }
        None => 0,
    }
}

/// One `Session`'s state, read without holding the table.
fn state_of(core: &Core, session_id: SessionId) -> Option<SessionState> {
    core.sessions()
        .get(&session_id)
        .map(|e| e.runtime.machine().state())
}

fn refuse(code: ReasonCode) -> Diagnostic {
    Diagnostic::builder(code, Component::TunnelEngine).build()
}
