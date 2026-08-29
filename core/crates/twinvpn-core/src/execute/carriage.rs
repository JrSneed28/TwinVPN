//! Starting, stepping and stopping the thing that actually carries packets.
//!
//! **Authority:** [ADR-0018](../../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! §11.2 row 2.3 (on a userspace-datapath target the core **is** the datapath),
//! CB-1, CB-6, CD-1, CD-2; [ADR-0005](../../../../../docs/adr/ADR-0005-relay-architecture.md)
//! §11.1, §7.1/§7.3 and RQ1 (the relay never sees plaintext);
//! [ADR-0006](../../../../../docs/adr/ADR-0006-relay-discovery-and-failover.md)
//! §11.4 (attribution), §11.5; [ADR-0001](../../../../../docs/adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)
//! §7.2 and §7.6; `docs/reliability.md` §4.5 T08–T12, T19/T20;
//! `ownership.md` §6 rules 7, 10 and 11.
//!
//! # Two carriages, one tunnel
//!
//! A `Session` is carried either **directly** — [`crate::datapath::Pump`],
//! sealed L-DATA straight onto the underlay socket — or **through a relay leg**,
//! where the same sealed record travels as a [`crate::relay::Sealed`] inside an
//! ADR-0005 `DATA` frame. The L-DATA tunnel is identical in both: ADR-0001 §7.2
//! calls it "the single most important composition rule in this ADR" that the
//! transport mode is a property of the `Path` and switching it "MUST NOT re-run
//! the L-DATA handshake". So there is one [`twinvpn_tunnel::Tunnel`] here and two
//! ways to move its output, never two tunnels.
//!
//! # Why the relayed carriage is written here and not in [`crate::datapath`]
//!
//! `Pump` writes to `Tunnel::authoritative_endpoint()` and reads from the
//! socket, and that is right for a direct path and wrong for a relayed one: a
//! relayed datagram is a `DATA` frame keyed by `flow_id` and MAC'd under
//! `K_leg`, and the leg — not the tunnel — decides where it goes. Putting relay
//! framing inside `Pump` would give the direct path a branch it never takes and
//! would make `datapath` depend on `relay`. The two carriages share the one
//! thing they genuinely share — [`crate::datapath::frame::DataHeader`], the
//! 16 octets `networking.md` §6.1 already charges every packet — and nothing
//! else.
//!
//! # The relay cannot read what it carries, and that is structural here too
//!
//! The only thing this module hands a leg is a [`crate::relay::Sealed`], built
//! by [`crate::relay::Sealed::from_tunnel`] from bytes `Tunnel::seal` produced,
//! and the only thing it takes back is one it hands to
//! [`crate::relay::Sealed::into_tunnel`]. Between those two calls the payload is
//! opaque to every line below, which is ADR-0005 RQ1 held by the type rather
//! than by this paragraph.
//!
//! # Spawned, or stepped
//!
//! [`start`] asks `Env::runtime()` to spawn both directions. On the
//! **virtual-time** binding `spawn` is documented as running the future inline —
//! *"this runtime has one thread and no queue … a scenario that needs
//! concurrency composes futures explicitly"* — and a pump is an unbounded loop,
//! so spawning one there would never return. `RuntimeKind` is a **domain fact**
//! whose own documentation says reading it is not a CB-3 violation and that "a
//! component with a blocking section can refuse to run on `SingleThreaded`"; so
//! this module reads it, and on that binding the same `Pump`, the same `Cancel`
//! and the same step functions are driven a bounded number of steps per
//! [`crate::core::Core::tick`] instead. **No code path differs** — only who
//! calls the loop — which is what keeps CB-2's falsification test testing the
//! product rather than a test-only variant of it.

use core::time::Duration;
use std::sync::Arc;

use twinvpn_env::RuntimeKind;
use twinvpn_relay_client::failover::Observation;
use twinvpn_types::{codes, Component, Diagnostic, PathClass, SessionId};

use crate::core::Core;
use crate::datapath::{Buffers, DataHeader, Pump, PumpParts, Step};
use crate::relay::{Failover, Inbound, LegError, RelayPair, Sealed};
use crate::session_table::{Established, SessionEntry};

/// How long one stepped receive waits before giving the tick back.
///
/// Only reached on a runtime whose `spawn` is inline. Short enough that a tick
/// is not a stall, and measured on the injected monotonic clock (CD-1).
const STEP_BUDGET: Duration = Duration::from_millis(1);

/// Builds the pump for an established tunnel and starts it if it can be started.
///
/// Idempotent: a `Session` whose pump is already built keeps it, so a second
/// `session.connect` to the same peer — which ADR-0017 §11.9 marks `nat` — does
/// not produce a second pair of directions against one tunnel.
///
/// # The interface may not exist yet, and that is not a failure
///
/// The overlay interface is created by [`crate::enforce::arm`], which
/// `net.up` runs **after** it has connected every `Session` — the order
/// ADR-0012 §11.8 fixes, because a contract is computed from the peers that
/// actually came up. So a `session.connect` that establishes before any arming
/// legitimately has no [`twinvpn_platform::TunnelHandle`] to pump into. The
/// tunnel is live and recorded either way, and `net.up` calls this again once
/// the interface exists.
///
/// Returns whether a pump is now running.
pub(crate) fn start(core: &Core, session_id: SessionId) -> bool {
    let Some(handle) = core.enforcement().handle() else {
        return false;
    };
    let mut sessions = core.sessions();
    let Some(entry) = sessions.get_mut(&session_id) else {
        return false;
    };
    let Some(established) = entry.established.as_mut() else {
        return false;
    };
    if established.pump.is_some() {
        return established.spawned;
    }
    // The socket the handshake completed on, and no other. A second bind would
    // be a second source port, and the peer answers to the endpoint the tunnel
    // named — §7.6's authoritative endpoint, from the far side.
    let Some(socket) = entry.sockets.first().map(Arc::clone) else {
        return false;
    };

    let parts = PumpParts {
        env: core.env().clone(),
        adapter: Arc::clone(core.adapter()),
        handle,
        socket,
        tunnel: Arc::clone(&established.tunnel),
        local_receiver: established.local_receiver,
        peer_receiver: established.peer_receiver,
        overlay_mtu: crate::enforce::MTU,
        cancel: established.cancel.clone(),
    };
    let pump = match Pump::new(parts) {
        Ok(pump) => Arc::new(pump),
        Err(refused) => {
            // A refusal to start is reported with its registered code and is
            // **not** a reason to leave a tunnel that believes it is carrying:
            // `Refused::KernelOffload` means the kernel carries the packets and
            // this core must never touch one, and the two MTU refusals mean the
            // interface and the pump would disagree about how large a packet
            // may be. Neither is a condition to clamp past.
            core.publish_diagnostic(&refused.diagnostic());
            return false;
        }
    };
    established.pump = Some(Arc::clone(&pump));
    established.spawned = spawn_both(core, &pump);
    established.spawned
}

/// Spawns both directions, or reports that this runtime runs them inline.
///
/// One [`crate::datapath::Cancel`] is already shared by both, so a caller that
/// stops the session stops both halves with one act.
fn spawn_both(core: &Core, pump: &Arc<Pump>) -> bool {
    if core.env().runtime().kind() == RuntimeKind::VirtualTime {
        // See the module docs. Not a capability this build lacks — the same
        // pump is stepped from `Core::tick` — but a fact about the scheduler,
        // and recorded as one rather than discovered as a hang.
        return false;
    }
    let outbound = Arc::clone(pump);
    let inbound = Arc::clone(pump);
    let spawned_outbound = core
        .env()
        .runtime()
        .spawn(Box::pin(async move {
            let report = outbound.run_outbound().await;
            report_stop(&report);
        }))
        .is_ok();
    let spawned_inbound = core
        .env()
        .runtime()
        .spawn(Box::pin(async move {
            let report = inbound.run_inbound().await;
            report_stop(&report);
        }))
        .is_ok();
    if spawned_outbound != spawned_inbound {
        // One direction running without the other is a half-open tunnel that
        // still emits packets. Refusing a spawn is reported, never dropped, so
        // the token is tripped and both halves end.
        pump.cancel_handle().cancel();
        return false;
    }
    spawned_outbound && spawned_inbound
}

/// Records why a direction ended.
///
/// Counters and a stop reason — never a payload, never a key, never an endpoint
/// (`ownership.md` §6 rule 11).
fn report_stop(report: &crate::datapath::Report) {
    tracing::info!(
        target: "twinvpn.core.datapath",
        stop = ?report.stop,
        graceful = report.stop.is_graceful(),
        packets = report.counters.packets,
        bytes = report.counters.bytes,
        rejected = report.counters.rejected_total(),
        "a pump direction stopped"
    );
}

/// Drives one bounded step of each direction, for a runtime that runs spawned
/// work inline.
///
/// Called from [`crate::core::Core::tick`]. Returns how many packets moved.
///
/// A pump that `start` managed to spawn is **not** stepped here: it is already
/// running, and stepping it as well would put two readers on one socket.
pub(crate) fn step(core: &Core, session_id: SessionId) -> usize {
    let (pump, cancelled) = {
        let sessions = core.sessions();
        let Some(entry) = sessions.get(&session_id) else {
            return 0;
        };
        let Some(established) = entry.established.as_ref() else {
            return 0;
        };
        if established.spawned {
            return 0;
        }
        let Some(pump) = established.pump.as_ref().map(Arc::clone) else {
            return 0;
        };
        (pump, established.cancel.is_cancelled())
    };
    if cancelled {
        return 0;
    }

    let mut moved = 0usize;
    let mut buffers = pump.buffers();
    // Outbound first: the TUN answers immediately on an empty queue, so this
    // costs a poll and never a wait.
    if let Step::Moved(bytes) = block_on_step(core, &pump, &mut buffers, true) {
        moved += bytes;
    }
    // Inbound blocks until a datagram arrives, so it is bounded by the tick's
    // own budget rather than left to hold the tick open.
    if let Step::Moved(bytes) = block_on_step(core, &pump, &mut buffers, false) {
        moved += bytes;
    }
    moved
}

/// Runs one step to completion, or gives it up at the step budget.
fn block_on_step(core: &Core, pump: &Arc<Pump>, buffers: &mut Buffers, outbound: bool) -> Step {
    let mut result = Step::Idle;
    let deadline = core.env().timer().sleep(STEP_BUDGET);
    core.env().runtime().block_on(Box::pin(async {
        let work: futures_core::future::BoxFuture<'_, Step> = if outbound {
            Box::pin(pump.step_outbound(buffers))
        } else {
            Box::pin(pump.step_inbound(buffers))
        };
        if let Some(step) = super::handshake::first_of(work, deadline).await {
            result = step;
        }
    }));
    result
}

/// Stops every `Session`'s carriage. `ownership.md` §6 rule 7.
///
/// The tunnel's keys are erased with it — see
/// [`crate::session_table::SessionEntry::tear_down`] for why the order is the
/// security property.
pub(crate) fn stop_all(core: &Core) {
    for entry in core.sessions().values_mut() {
        entry.tear_down();
    }
}

// ---------------------------------------------------------------------------
// The relayed carriage
// ---------------------------------------------------------------------------

/// Opens and binds a relay leg for a `Session` the direct race could not carry.
///
/// **This is the fallback, and it is not a fallback to anything weaker.** The
/// L-DATA tunnel over a relay is the same tunnel with the same keys; what
/// changes is only which datagram carries the sealed record. ADR-0005 §7.3 is
/// explicit that the relay's own static key "is **NOT** an input to the L-DATA
/// `Noise_IKpsk2` handshake", so nothing about moving to a relay weakens the
/// end-to-end guarantee — which is what makes this a legal answer to a failed
/// direct race, where "route around TwinVPN" would not be.
///
/// # Errors
///
/// A [`Diagnostic`] carrying a registered code. `RELAY.NONE_REACHABLE` when no
/// [`crate::session_table::RelayAccess`] has been installed — the state of every
/// build today, and the reason a `Session` with no direct path stays out of a
/// steady state rather than quietly ending up on none.
pub(crate) fn open_relay(core: &Core, session_id: SessionId) -> Result<(), Box<Diagnostic>> {
    let deadline = core
        .env()
        .now_monotonic()
        .saturating_add(twinvpn_session::timers::T_CONNECT.default);
    let mut sessions = core.sessions();
    let Some(entry) = sessions.get_mut(&session_id) else {
        return Err(Box::new(refuse(codes::NET_SESSION_CLOSED_BY_USER)));
    };
    if entry.relay.is_some() {
        return Ok(());
    }
    let Some(access) = entry.relay_access.as_ref() else {
        // Nothing to reach for. Named rather than silent: ADR-0006 §11.8's
        // total-unavailability case reports `RELAY.NONE_REACHABLE`, and that is
        // exactly true here — this device knows of no relay at all, because
        // nothing has ever supplied it a verified map, an `RLK` or a token.
        return Err(Box::new(refuse(codes::RELAY_NONE_REACHABLE)));
    };
    let Some(socket) = entry.sockets.first().map(Arc::clone) else {
        return Err(Box::new(refuse(codes::NET_NO_USABLE_CANDIDATES)));
    };
    let pair_tag = access.pair_tag();

    let mut opened: Option<Result<crate::relay::RelayLeg, LegError>> = None;
    core.env().runtime().block_on(Box::pin(async {
        opened = Some(
            crate::relay::open_leg(core.env(), socket.as_ref(), access.params(), deadline).await,
        );
    }));
    let mut leg = match opened.expect("block_on drives the future to completion") {
        Ok(leg) => leg,
        Err(error) => return Err(Box::new(leg_refusal(&error))),
    };

    let mut bound = None;
    core.env().runtime().block_on(Box::pin(async {
        bound = Some(
            crate::relay::bind(
                core.env(),
                socket.as_ref(),
                &mut leg,
                pair_tag,
                // §8.3's bucket. `pair_tag_bucket` defers rather than inventing
                // one when the leg has heard no `DRAIN`, and zero is the
                // no-drain bucket both peers compute alike.
                0,
                deadline,
            )
            .await,
        );
    }));
    match bound.expect("block_on drives the future to completion") {
        Ok(crate::relay::BindOutcome::Bound { .. } | crate::relay::BindOutcome::Pending { .. }) => {
        }
        Ok(crate::relay::BindOutcome::Refused(refusal)) => {
            return Err(Box::new(refuse(
                refusal.reason_code().unwrap_or(codes::RELAY_NONE_REACHABLE),
            )));
        }
        Err(error) => return Err(Box::new(leg_refusal(&error))),
    }
    entry.relay = Some(RelayPair::new(leg));
    Ok(())
}

/// Carries one sealed record out through the leg, and one back in.
///
/// The two halves of [`crate::datapath::Pump`]'s job, with the relay's framing
/// in place of the socket's. Returns how many plaintext octets crossed.
pub(crate) fn relay_step(core: &Core, session_id: SessionId) -> usize {
    let Some(handle) = core.enforcement().handle() else {
        return 0;
    };
    let mut moved = 0usize;
    moved += relay_outbound(core, session_id, handle);
    moved += relay_inbound(core, session_id, handle);
    moved
}

/// TUN → seal → [`Sealed`] → `DATA` frame.
fn relay_outbound(
    core: &Core,
    session_id: SessionId,
    handle: twinvpn_platform::TunnelHandle,
) -> usize {
    let capacity = crate::enforce::MTU as usize;
    let mut packet = vec![0u8; capacity];
    let mut read = None;
    core.env().runtime().block_on(Box::pin(async {
        read = Some(
            core.adapter()
                .tunnel()
                .read_packet(handle, &mut packet[..capacity])
                .await,
        );
    }));
    // "Nothing queued" is the ordinary answer and is not an error to report.
    let Some(Ok(length)) = read else {
        return 0;
    };
    if length == 0 || length > capacity {
        return 0;
    }

    let mut sessions = core.sessions();
    let Some(entry) = sessions.get_mut(&session_id) else {
        return 0;
    };
    let Some(socket) = entry.sockets.first().map(Arc::clone) else {
        return 0;
    };
    let Some((established, pair)) = both(entry) else {
        return 0;
    };
    let mut record = Vec::new();
    let counter = {
        let Ok(mut tunnel) = established.tunnel.lock() else {
            return 0;
        };
        match tunnel.seal(&packet[..length], &mut record) {
            Ok(counter) => counter,
            Err(_) => return 0,
        }
    };
    let mut wire = Vec::with_capacity(crate::datapath::HEADER_BYTES + record.len());
    DataHeader {
        receiver: established.peer_receiver,
        counter,
    }
    .write(&mut wire);
    wire.extend_from_slice(&record);
    // The boundary. Past this line the payload is opaque to every line of
    // `crate::relay`, which holds no key that could open one.
    let Ok(sealed) = Sealed::from_tunnel(wire) else {
        return 0;
    };

    let mut sent = None;
    core.env().runtime().block_on(Box::pin(async {
        sent = Some(crate::relay::send_sealed(socket.as_ref(), pair.primary_mut(), &sealed).await);
    }));
    if let Some(Ok(())) = sent {
        return length;
    }
    // A send that the leg or the platform refused is a **real observation**
    // about the leg, and §11.4 is what decides whether it is the relay's
    // fault. It is fed to the attribution rather than counted as a drop.
    //
    // §11.4's inputs, as facts rather than as a verdict. A refused send is a
    // **hard leg signal** — a socket error, an ICMP unreachable — and it is
    // emphatically not `half_flow_silent`, which would attribute the peer's
    // silence to the relay and move a session that has nowhere better to go.
    observe(
        core,
        entry,
        Observation {
            missed_leg_pings: 0,
            leg_hard_signal: true,
            drain_deadline_reached: false,
            // Emphatically not set: attributing the peer's silence to the relay
            // is what §11.4 forbids, and `Observation` has no `Default`
            // precisely so that every field is a stated fact.
            half_flow_silent: false,
            quality_violated: false,
            all_legs_on_interface_dead: false,
            capacity_rejected: false,
            region_failed: false,
        },
    );
    0
}

/// `DATA` frame → [`Sealed`] → open → TUN.
fn relay_inbound(
    core: &Core,
    session_id: SessionId,
    handle: twinvpn_platform::TunnelHandle,
) -> usize {
    let deadline = core.env().now_monotonic().saturating_add(STEP_BUDGET);
    let socket = {
        let sessions = core.sessions();
        let Some(entry) = sessions.get(&session_id) else {
            return 0;
        };
        let Some(socket) = entry.sockets.first().map(Arc::clone) else {
            return 0;
        };
        socket
    };

    let mut sessions = core.sessions();
    let Some(entry) = sessions.get_mut(&session_id) else {
        return 0;
    };
    let Some((established, pair)) = both(entry) else {
        return 0;
    };

    let mut received = None;
    core.env().runtime().block_on(Box::pin(async {
        received = Some(
            crate::relay::receive(core.env(), socket.as_ref(), pair.primary_mut(), deadline).await,
        );
    }));
    let sealed = match received {
        Some(Ok(Inbound::Data(sealed))) => sealed,
        Some(Ok(Inbound::Drain(_))) => {
            // §8.3's herd-safe migration. The notice is a fact about the relay,
            // and it is an observation rather than an instruction: the leg is
            // still live and still carrying until the schedule says otherwise.
            return 0;
        }
        // A deadline is the ordinary answer on an idle leg. Anything else the
        // leg refused stays a refusal and is not an end-to-end observation.
        _ => return 0,
    };

    let wire = sealed.into_tunnel();
    let Ok((header, record)) = DataHeader::parse(&wire) else {
        return 0;
    };
    if header.receiver != established.local_receiver {
        return 0;
    }
    let mut packet = Vec::new();
    {
        let Ok(mut tunnel) = established.tunnel.lock() else {
            return 0;
        };
        if tunnel.open(header.counter, record, &mut packet).is_err() {
            // A record an untrusted peer could have produced. Dropped, never a
            // teardown — the same rule `Reject::tears_down` states for the
            // direct carriage.
            return 0;
        }
    }
    let length = packet.len();
    let mut written = None;
    core.env().runtime().block_on(Box::pin(async {
        written = Some(core.adapter().tunnel().write_packet(handle, &packet).await);
    }));
    if matches!(written, Some(Ok(_))) {
        length
    } else {
        0
    }
}

/// Both halves of a relayed carriage, or neither.
fn both(entry: &mut SessionEntry) -> Option<(&mut Established, &mut RelayPair)> {
    let established = entry.established.as_mut()?;
    let pair = entry.relay.as_mut()?;
    Some((established, pair))
}

/// Applies ADR-0006 §11.4's attribution to a real observation.
///
/// **No timer drives this and no heuristic decides it.** §11.4: *"'Is the relay
/// reachable' and 'is the peer talking' are two separate observations, not
/// one."* A silent half-flow on a live leg is peer loss and must not move relay,
/// and [`RelayPair::on_observation`] is where that verdict is reached.
fn observe(core: &Core, entry: &mut SessionEntry, observation: Observation) {
    let Some(pair) = entry.relay.as_mut() else {
        return;
    };
    let outcome = pair.on_observation(observation);
    if let Some(code) = outcome.reason_code() {
        core.publish_diagnostic(&Diagnostic::builder(code, Component::RelayClient).build());
    }
    match outcome {
        // T19: make-before-break — the `Session` stays on `Relayed` because the
        // promoted leg is already bound and already carrying — and `NoMove`,
        // where §11.4 attributed the observation to something a relay move
        // cannot fix. Two different reasons for the same action, which is
        // *nothing*: the leg in hand keeps carrying.
        Failover::PromotedStandby { .. } | Failover::NoMove { .. } => {}
        Failover::NeedsSelection { .. } => {
            // T20, not T19. There is no standby, so there is genuinely no
            // carrying path for as long as a fresh selection takes — and
            // reporting `MIGRATING` would assert a make-before-break that is
            // not happening. The leg is dropped so nothing sends on it.
            entry.relay = None;
        }
    }
}

/// The path class a relayed `Session` reaches.
pub(crate) const RELAYED: PathClass = PathClass::Relayed;

/// One leg refusal as a registered diagnostic.
///
/// A `LegError` that carries no code of its own — a platform refusal, or a
/// deadline — becomes `RELAY.NONE_REACHABLE`, which is the honest summary: this
/// device could not reach the relay it was told to use.
fn leg_refusal(error: &LegError) -> Diagnostic {
    refuse(error.reason_code().unwrap_or(codes::RELAY_NONE_REACHABLE))
}

fn refuse(code: twinvpn_types::ReasonCode) -> Diagnostic {
    Diagnostic::builder(code, Component::RelayClient).build()
}
