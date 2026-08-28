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

use std::collections::BTreeMap;

use twinvpn_env::Env;
use twinvpn_path::ledger::Ledger;
use twinvpn_path::race::Race;
use twinvpn_platform::socket::UdpSocket;
use twinvpn_session::SessionMachine;
use twinvpn_types::{DeviceId, Endpoint, Identifier as _, SessionId};

use crate::session_loop::SessionRuntime;

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
    pub sockets: Vec<Box<dyn UdpSocket>>,
    /// The peer's endpoint, once something has supplied one.
    ///
    /// `None` until rendezvous answers — which, with no `ControlTransport` in
    /// the workspace (W-12), is always on this build. It is a field rather than
    /// an assumption so that the day a transport lands, the probe path already
    /// reads it.
    pub peer_endpoint: Option<Endpoint>,
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
        }
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
