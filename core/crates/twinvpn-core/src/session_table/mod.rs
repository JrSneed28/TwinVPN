//! The `Session` state the composition root owns.
//!
//! **Authority:** `docs/architecture.md` §5 S-12 (`ConnectionSession` — the
//! owning device is the authoritative writer), `docs/reliability.md` §6.5,
//! ADR-0008 (idempotency).
//!
//! # Why the `SessionId` is derived from the peer
//!
//! ADR-0017 §11.9 marks `session.connect` **`nat`** — naturally idempotent —
//! and that has to be true of the *implementation*, not just of the table. A
//! `SessionId` minted per call would make two `connect`s to one peer produce two
//! `Session`s, which is the opposite of idempotent. Deriving it from the peer's
//! `device_id` makes "connect twice" reach the same `Session`, where §4.5 T01's
//! own rule absorbs the second request.
//!
//! The derivation is a **truncation, not a hash**: `SessionId` is 16 bytes and
//! `DeviceId` is 32, and `device_id` is already a collision-resistant digest of
//! the generation-0 identity key. Taking its first 16 bytes inherits that
//! resistance and needs no cryptographic dependency, which CD-I2 does not permit
//! this crate.
//!
//! **The consequence, stated:** a `Session` is per-peer and this build supports
//! exactly one concurrent `Session` per peer. `identifiers.md` scopes
//! `SessionId` as durable and never reassigned "on failover, roam, rekey or
//! re-handshake", which this satisfies; what it does not support is two
//! simultaneous `Session`s to one peer, and nothing in Phase 1 asks for that.

pub mod keying;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use twinvpn_env::Env;
use twinvpn_path::ledger::Ledger;
use twinvpn_path::race::Race;
use twinvpn_platform::socket::UdpSocket;
use twinvpn_session::SessionMachine;
use twinvpn_tunnel::Tunnel;
use twinvpn_types::{DeviceId, Endpoint, Identifier as _, PathClass, SessionId};

use crate::datapath::{Cancel, Pump, ReceiverIndex};
use crate::relay::RelayPair;
use crate::session_loop::SessionRuntime;

pub use keying::{RelayAccess, TunnelKeying, STATIC_KEY_LEN};

/// The core's `Session` table.
pub type SessionMap = BTreeMap<SessionId, SessionEntry>;

/// One `Session`, with everything the establishment path needs.
pub struct SessionEntry {
    /// The state machine, with its deadlines.
    pub runtime: SessionRuntime,
    /// The peer this `Session` is with.
    pub peer: DeviceId,
    /// The `ConnectionCandidate` ledger (S-14) — ADR-0015 §11.8 item 4's rows.
    pub ledger: Ledger,
    /// The race in flight, if one is.
    pub race: Option<Race>,
    /// The sockets gathering opened, held so a probe leaves from the same local
    /// endpoint its candidate names.
    ///
    /// `Arc` rather than `Box` because the pump outlives one `session.connect`:
    /// [`crate::datapath::PumpParts::socket`] is an `Arc<dyn UdpSocket>` and both
    /// directions run against the *same* socket the handshake completed on. A
    /// clone here would be a second socket at a second port, and the peer would
    /// answer to an endpoint the tunnel never named.
    pub sockets: Vec<Arc<dyn UdpSocket>>,
    /// The peer's endpoint, once something has supplied one.
    ///
    /// `None` until rendezvous answers — which, with no `ControlTransport` in
    /// the workspace (W-12), is always on this build. It is a field rather than
    /// an assumption so that the day a transport lands, the probe path already
    /// reads it.
    pub peer_endpoint: Option<Endpoint>,
    /// The L-DATA key material for this peer, once something has supplied it.
    ///
    /// `None` is the ordinary state on a build with no pairing ceremony and no
    /// control plane, and it is why `session.connect` **refuses** rather than
    /// reaching CONNECTED: there is no handshake to run without it, and a
    /// `Session` that reached a steady state without one would be asserting a
    /// tunnel that does not exist. See [`keying::TunnelKeying`].
    pub keying: Option<TunnelKeying>,
    /// The relay credentials, once something has supplied them.
    ///
    /// Same shape and same reason as `keying`: absent on every build today, and
    /// its absence is what makes the relay fallback refuse by name instead of
    /// silently leaving the `Session` on no path at all.
    pub relay_access: Option<RelayAccess>,
    /// The live tunnel and the pump carrying it, once the handshake completed.
    ///
    /// **This is the field that makes CONNECTED mean something.** It can only be
    /// set by [`crate::execute`]'s handshake step, so `Some` here and
    /// `SessionState::Steady` in the machine are two views of one fact rather
    /// than two beliefs that can disagree.
    pub established: Option<Established>,
    /// The relay leg carrying this `Session`, and its warm alternate.
    ///
    /// Set only when the direct race produced no validated path and a leg was
    /// opened and bound. [`crate::relay::RelayPair::on_observation`] is driven
    /// from here on real observations, never on a timer.
    pub relay: Option<RelayPair>,
}

/// One established tunnel and the pump carrying it.
///
/// **Authority:** ADR-0018 §11.2 row 2.3 (on a userspace-datapath target the
/// core *is* the datapath), CB-1; `ownership.md` §6 rule 7 (graceful shutdown).
///
/// # Why the tunnel and the pump are one field and not two
///
/// A tunnel with no pump carries nothing and a pump with no tunnel cannot exist.
/// Holding them separately would make "established" and "carrying" two
/// independent `Option`s with four states, two of which are defects — and the
/// two defects are exactly the ones that read as success: a `Session` in
/// `STEADY` whose pump was never started, and a pump still running against a
/// tunnel that was torn down.
pub struct Established {
    /// The L-DATA engine, shared with both pump directions.
    ///
    /// `Mutex` because `seal` and `open` both need `&mut` and the two directions
    /// are two tasks; [`crate::datapath`] documents that the lock is never held
    /// across an await.
    pub tunnel: Arc<Mutex<Tunnel>>,
    /// The pump, once the overlay interface exists to pump into.
    ///
    /// `None` between a handshake that completed and the `net.up` that creates
    /// the interface — ADR-0012 §11.8 computes the contract from the peers that
    /// actually came up, so establishing first and arming second is the order,
    /// not an oversight. The tunnel is live either way and
    /// [`crate::execute::carriage::start`] is called again once there is a
    /// handle.
    pub pump: Option<Arc<Pump>>,
    /// The one shutdown request **both** directions share.
    ///
    /// One token, not two: a pump whose inbound half stopped and whose outbound
    /// half did not is a half-open tunnel that still emits packets, and the
    /// single token is what makes "stop this session" one act.
    pub cancel: Cancel,
    /// Whether the two directions are running as spawned work.
    ///
    /// `false` on a runtime whose `spawn` is inline — see
    /// [`crate::core::Core::start_pump`] — where the pump is stepped from
    /// [`crate::core::Core::tick`] instead. Recorded rather than inferred so a
    /// caller can tell "the pump is running elsewhere" from "the pump is mine to
    /// step", which are different facts about the same object.
    pub spawned: bool,
    /// The class the winning path was validated at (§4.5 T08–T10).
    pub class: PathClass,
    /// The index this device stamps on frames it expects to receive.
    pub local_receiver: ReceiverIndex,
    /// The index the peer expects on frames addressed to it.
    pub peer_receiver: ReceiverIndex,
}

impl Established {
    /// Stops both directions. Idempotent.
    ///
    /// Tripping the token is the whole of it: `ownership.md` §6 rule 7 wants a
    /// *graceful* stop, and the pump's own contract is that a cancellation
    /// between `open` and `write_packet` never happens — the step in flight
    /// finishes and the loop then ends. Aborting the tasks instead would abandon
    /// a packet the OS already believes was accepted.
    pub fn stop(&self) {
        self.cancel.cancel();
    }
}

impl core::fmt::Debug for Established {
    /// The class and the liveness. **Not** the tunnel: `Tunnel` holds the
    /// transport keys, and a derived `Debug` that reached them would be the
    /// accident `ownership.md` §6 rule 11 exists to prevent.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Established")
            .field("class", &self.class)
            .field("spawned", &self.spawned)
            .field("stopped", &self.cancel.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl SessionEntry {
    /// A fresh `Session` resting in `DISCONNECTED`.
    #[must_use]
    pub fn new(env: Env, session_id: SessionId, peer: DeviceId) -> Self {
        Self {
            runtime: SessionRuntime::new(env.clone(), SessionMachine::new(env, session_id)),
            peer,
            ledger: Ledger::new(),
            race: None,
            sockets: Vec::new(),
            peer_endpoint: None,
            keying: None,
            relay_access: None,
            established: None,
            relay: None,
        }
    }

    /// A `Session` restored from the durable journal (§6.5, S-12).
    ///
    /// A restarted client "resumes into `RECONNECTING` for each known peer
    /// rather than starting from `DISCONNECTED` — which is what makes the
    /// diagnostic continuous across a crash".
    #[must_use]
    pub fn resumed(env: Env, record: &twinvpn_session::journal::DurableSession) -> Self {
        let machine = SessionMachine::resumed(
            env.clone(),
            record.session_id,
            record.resume_state(),
            record.last_reason,
        );
        Self {
            runtime: SessionRuntime::new(env, machine),
            peer: record.peer,
            ledger: Ledger::new(),
            race: None,
            sockets: Vec::new(),
            peer_endpoint: None,
            keying: None,
            relay_access: None,
            established: None,
            relay: None,
        }
    }

    /// Tears the carriage down: the pump stops and the tunnel's keys are erased.
    ///
    /// **Order is the security property.** The pump is stopped *first*, so no
    /// direction can be inside `seal` or `open` when the keys go away; only then
    /// is [`twinvpn_tunnel::Tunnel::zeroize`] called, which is ADR-0001 §7.2's
    /// "keys are unusable and are **zeroed**". Zeroing first would race a live
    /// step and turn a clean teardown into a `Fault::KeyStateUnusable` on a
    /// session the user simply closed.
    ///
    /// Idempotent, and safe on a `Session` that never established: it is exactly
    /// the no-op it looks like.
    pub fn tear_down(&mut self) {
        if let Some(established) = self.established.take() {
            established.stop();
            if let Ok(mut tunnel) = established.tunnel.lock() {
                tunnel.zeroize();
            }
        }
        // The leg goes with the tunnel it carried. Keeping a bound leg alive
        // across a teardown would leave this device holding a relay flow for a
        // `Session` that no longer exists — the stale second reference
        // `RelayPair::on_observation`'s `take` exists to avoid, in the other
        // direction.
        self.relay = None;
        self.race = None;
    }

    /// Whether a live tunnel is carrying this `Session`.
    ///
    /// Read from the carriage rather than from the state machine on purpose:
    /// this is the fact, and the machine's state is the *report* of it. Where
    /// the two disagree, this is the one that can be checked against an object
    /// that either exists or does not.
    #[must_use]
    pub fn is_carrying(&self) -> bool {
        self.established.as_ref().is_some_and(|e| {
            !e.cancel.is_cancelled()
                && e.tunnel
                    .lock()
                    .is_ok_and(|t| t.state().carries_traffic())
        })
    }
}

impl core::fmt::Debug for SessionEntry {
    /// Deliberately shallow. A derived `Debug` would walk the ledger, which
    /// holds endpoints — `SENSITIVE` under ADR-0015 §11.4 — and
    /// `ownership.md` §6 rule 11 makes a derive that reaches a sensitive value
    /// exactly the accident to prevent.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionEntry")
            .field("state", &self.runtime.machine().state())
            .field("candidates", &self.ledger.rows().len())
            .field("sockets", &self.sockets.len())
            .field("established", &self.established)
            .field("relay", &self.relay.is_some())
            .finish_non_exhaustive()
    }
}

/// The `SessionId` for a peer. See the module docs for why this is a derivation.
#[must_use]
pub fn session_id_for(peer: DeviceId) -> SessionId {
    let bytes = peer.as_bytes();
    SessionId::from_slice(&bytes[..16]).expect("SessionId is 16 bytes and DeviceId is 32")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(byte: u8) -> DeviceId {
        DeviceId::from_slice(&[byte; 32]).expect("32")
    }

    #[test]
    fn connecting_twice_to_one_peer_reaches_one_session() {
        // ADR-0017 §11.9 marks session.connect `nat`. This is the mechanism.
        assert_eq!(session_id_for(device(1)), session_id_for(device(1)));
    }

    #[test]
    fn two_peers_get_two_sessions() {
        assert_ne!(session_id_for(device(1)), session_id_for(device(2)));
    }

    #[test]
    fn a_resumed_session_comes_back_reconnecting_not_disconnected() {
        // §6.5: "a restarted client resumes into RECONNECTING for each known
        // peer rather than starting from DISCONNECTED — which is what makes the
        // diagnostic continuous across a crash."
        let (env, _vt) = crate::testing::env();
        let record = twinvpn_session::journal::DurableSession {
            session_id: session_id_for(device(3)),
            peer: device(3),
            last_state: twinvpn_session::state::SessionState::Steady(
                twinvpn_types::PathClass::WanDirect,
            ),
            last_reason: None,
        };
        let entry = SessionEntry::resumed(env, &record);
        assert_eq!(
            entry.runtime.machine().state(),
            twinvpn_session::state::SessionState::Reconnecting { parked: false }
        );
    }

    #[test]
    fn a_session_the_user_closed_stays_closed() {
        let (env, _vt) = crate::testing::env();
        let record = twinvpn_session::journal::DurableSession {
            session_id: session_id_for(device(4)),
            peer: device(4),
            last_state: twinvpn_session::state::SessionState::Disconnected,
            last_reason: None,
        };
        let entry = SessionEntry::resumed(env, &record);
        assert_eq!(
            entry.runtime.machine().state(),
            twinvpn_session::state::SessionState::Disconnected,
            "resuming a user-closed Session would reconnect something they turned off"
        );
    }

    #[test]
    fn the_debug_impl_does_not_walk_the_ledger() {
        let (env, _vt) = crate::testing::env();
        let entry = SessionEntry::new(env, session_id_for(device(5)), device(5));
        let rendered = format!("{entry:?}");
        assert!(rendered.contains("SessionEntry"));
        assert!(!rendered.contains("Endpoint"), "{rendered}");
    }
}
