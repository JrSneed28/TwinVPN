//! The durable half of a `Session` (S-12), behind the narrowest trait that
//! expresses it.
//!
//! **Authority:** `docs/reliability.md` §6.5 ("**What a process restart does
//! *not* lose is the `Session` itself**"), §10.2 E-rule 2, ADR-0020,
//! `contracts/proto/twinvpn/v1/connection.proto` `ConnectionSession`.
//!
//! # Why this trait is here and not in `twinvpn-store`
//!
//! `twinvpn-store` is `core-security`'s crate and is in flight in parallel with
//! this one. `docs/implementation/ownership.md` directs a domain that needs an
//! unavailable API to "define the narrowest trait you require **in your own
//! crate**, implement against it, and list it in your report as an integration
//! item". [`SessionJournal`] is that trait: three methods, no key material, no
//! namespace vocabulary, and nothing that presumes a record format.
//!
//! **Integration item:** `twinvpn-store` is expected to supply an implementation
//! over its `LOCAL`/durable namespace. Nothing else in this crate is coupled to
//! it.

use twinvpn_types::{DeviceId, ReasonCode, SessionId};

use crate::state::SessionState;

/// The durable record of one `Session`.
///
/// Deliberately small: §6.5's table says what survives a process restart is
/// *`Session` identity and the last `ConnectionState`* — not keys, not the
/// replay window, not the relay allocation, and not the candidate ledger, all of
/// which are `Lost`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableSession {
    /// Durable, and never reassigned on failover, roam, rekey or re-handshake.
    pub session_id: SessionId,
    /// The peer this `Session` is with.
    pub peer: DeviceId,
    /// The last state observed before the process went away.
    pub last_state: SessionState,
    /// The code that accompanied it, where it had one.
    pub last_reason: Option<ReasonCode>,
}

impl DurableSession {
    /// The state a restarted client resumes into.
    ///
    /// §6.5: "a restarted client resumes into `RECONNECTING` for each known peer
    /// rather than starting from `DISCONNECTED` — which is what makes the
    /// diagnostic continuous across a crash".
    ///
    /// The one exception is a `Session` the user had explicitly closed: resuming
    /// a `DISCONNECTED` peer into `RECONNECTING` would reconnect something the
    /// user turned off.
    #[must_use]
    pub const fn resume_state(&self) -> SessionState {
        match self.last_state {
            SessionState::Disconnected => SessionState::Disconnected,
            SessionState::Failed => SessionState::Failed,
            _ => SessionState::Reconnecting { parked: false },
        }
    }
}

/// Errors a journal can report.
///
/// Deliberately opaque about the storage layer: the caller maps these onto
/// `STORE.*` codes, which `twinvpn-store` owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JournalError {
    /// The store is not readable right now. Recoverable.
    #[error("session journal unavailable")]
    Unavailable,
    /// The stored record could not be interpreted.
    #[error("session journal record is corrupt")]
    Corrupt,
}

/// The durable-session seam.
///
/// **Exactly one writer** (S-12): the device that owns the `Session` is the sole
/// authority, which is what makes a control-plane outage change nothing about a
/// running `Tunnel`.
pub trait SessionJournal: Send + Sync {
    /// Every `Session` this device knows about.
    ///
    /// # Errors
    ///
    /// [`JournalError`] when the store cannot be read. A caller MUST NOT treat
    /// an error as "no sessions": that would silently drop every peer.
    fn load_all(&self) -> Result<Vec<DurableSession>, JournalError>;

    /// Records the current state of one `Session`.
    ///
    /// # Errors
    ///
    /// [`JournalError`] when the write cannot be made durable.
    fn persist(&self, record: &DurableSession) -> Result<(), JournalError>;

    /// Forgets a `Session` the user closed.
    ///
    /// # Errors
    ///
    /// [`JournalError`] when the removal cannot be made durable.
    fn forget(&self, session_id: SessionId) -> Result<(), JournalError>;
}

/// An in-memory journal, for tests and for a host with no durable store.
///
/// Deliberately **not** a silent fallback: a caller has to choose it by name, so
/// "we lost every session on restart" cannot be something that just happened.
#[derive(Debug, Default)]
pub struct EphemeralJournal {
    records: std::sync::Mutex<Vec<DurableSession>>,
}

impl EphemeralJournal {
    /// An empty journal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionJournal for EphemeralJournal {
    fn load_all(&self) -> Result<Vec<DurableSession>, JournalError> {
        self.records
            .lock()
            .map(|r| r.clone())
            .map_err(|_| JournalError::Unavailable)
    }

    fn persist(&self, record: &DurableSession) -> Result<(), JournalError> {
        let mut r = self.records.lock().map_err(|_| JournalError::Unavailable)?;
        if let Some(slot) = r.iter_mut().find(|x| x.session_id == record.session_id) {
            slot.clone_from(record);
        } else {
            r.push(record.clone());
        }
        Ok(())
    }

    fn forget(&self, session_id: SessionId) -> Result<(), JournalError> {
        let mut r = self.records.lock().map_err(|_| JournalError::Unavailable)?;
        r.retain(|x| x.session_id != session_id);
        Ok(())
    }
}
