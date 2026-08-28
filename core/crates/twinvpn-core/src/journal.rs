//! Binding `twinvpn_session::journal::SessionJournal` to `twinvpn-store` — the
//! second half of CD-I5.
//!
//! **Authority:** `twinvpn_session::journal`'s own module docs (*"**Integration
//! item:** `twinvpn-store` is expected to supply an implementation over its
//! `LOCAL`/durable namespace"*); `docs/reliability.md` §6.5 and S-12;
//! ADR-0018 CB-7.
//!
//! # Where the two crates disagreed, exactly
//!
//! `twinvpn-session` defined the seam and `twinvpn-store` shipped a different
//! shape. Both are reasonable; they do not compose without an adapter, and this
//! is it. The three disagreements, precisely:
//!
//! | | `SessionJournal` (session) | `Store` (store) |
//! |---|---|---|
//! | **Mutability** | `&self` | `commit(&mut self)` |
//! | **Sync/async** | synchronous | `async` |
//! | **Granularity** | one record per call | one multi-key `Transaction` (ST-12b) |
//!
//! A naive adapter would hold `Arc<Mutex<Store>>` and `block_on` the commit.
//! That is wrong twice: `Runtime::block_on`'s own doc says calling it from inside
//! a runtime deadlocks on the single-threaded binding (iOS, ADR-0018 §11.3), and
//! a per-record commit is exactly the split ST-12b names as a defect.
//!
//! **What this adapter does instead:** [`CoreSessionJournal::persist`] updates an
//! in-memory authoritative map synchronously and **queues** the durable write;
//! [`crate::bridge::StoreBridge::flush`] drains the queue into one transaction.
//! `load_all` reads the map, which is loaded from the store at construction.
//!
//! # The cost, stated
//!
//! `SessionJournal::persist`'s doc says it errors "when the write cannot be made
//! durable". After this adapter, a successful `persist` means **queued**, not
//! **durable**. §6.5's guarantee — a restarted client resumes into
//! `RECONNECTING` for each known peer — therefore depends on the composition root
//! calling `flush` before it can crash, which it does after every transition
//! ([`crate::session_loop`]) and at shutdown. A crash inside that window loses
//! the *most recent* transition, not the `Session`.
//!
//! That is a real weakening and it is reported as one. The alternative that
//! preserves the trait's wording — making `SessionJournal` async — is a change to
//! another domain's crate, which `ownership.md` §2 forbids this domain to make.

use core::fmt::Write as _;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use twinvpn_session::journal::{DurableSession, JournalError, SessionJournal};
use twinvpn_session::state::SessionState;
use twinvpn_types::{Identifier as _, PathClass, ReasonCode, SessionId};

use crate::planes::{PendingWrite, Shared};

/// The journal's own in-memory authority.
#[derive(Debug, Default)]
struct JournalState {
    records: BTreeMap<SessionId, DurableSession>,
}

/// `twinvpn-store`-backed `SessionJournal`.
#[derive(Debug, Clone)]
pub struct CoreSessionJournal {
    state: Arc<Mutex<JournalState>>,
    shared: Shared,
}

impl CoreSessionJournal {
    /// Builds a journal over the bridge's write queue, seeded with whatever the
    /// store already held.
    ///
    /// `restored` comes from the composition root, which reads the store before
    /// any `Session` exists. It is a parameter rather than a read performed here
    /// because this type is constructed on the hot path and CB-7 puts the vault
    /// I/O in exactly one place.
    #[must_use]
    pub fn new(shared: Shared, restored: Vec<DurableSession>) -> Self {
        let mut records = BTreeMap::new();
        for r in restored {
            records.insert(r.session_id, r);
        }
        Self {
            state: Arc::new(Mutex::new(JournalState { records })),
            shared,
        }
    }

    /// How many `Session`s the journal currently knows about.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().map_or(0, |s| s.records.len())
    }

    /// Whether the journal is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn enqueue(&self, key: String, value: Option<Vec<u8>>) -> Result<(), JournalError> {
        let mut shared = self.shared.lock().map_err(|_| JournalError::Unavailable)?;
        shared.push_session_write(PendingWrite::Session { key, value });
        Ok(())
    }
}

impl SessionJournal for CoreSessionJournal {
    fn load_all(&self) -> Result<Vec<DurableSession>, JournalError> {
        let state = self.state.lock().map_err(|_| JournalError::Unavailable)?;
        Ok(state.records.values().cloned().collect())
    }

    fn persist(&self, record: &DurableSession) -> Result<(), JournalError> {
        {
            let mut state = self.state.lock().map_err(|_| JournalError::Unavailable)?;
            state.records.insert(record.session_id, record.clone());
        }
        self.enqueue(key_for(record.session_id), Some(encode(record)))
    }

    fn forget(&self, session_id: SessionId) -> Result<(), JournalError> {
        {
            let mut state = self.state.lock().map_err(|_| JournalError::Unavailable)?;
            state.records.remove(&session_id);
        }
        self.enqueue(key_for(session_id), None)
    }
}

/// The vault key for one `Session`.
///
/// Hex of the `SessionId`, not a `DeviceId` fingerprint: a `SessionId` is
/// `OPERATIONAL` and opaque, and using the *peer's* identifier as the key would
/// put a `SENSITIVE` value in a record name where the redaction rules cannot
/// reach it.
fn key_for(session_id: SessionId) -> String {
    let mut out = String::with_capacity(32);
    for b in session_id.as_bytes() {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The vault encoding of one [`DurableSession`].
///
/// §6.5's table says what survives a restart is *`Session` identity and the last
/// `ConnectionState`* — not keys, not the replay window, not the relay
/// allocation. This encoding carries exactly that and nothing else, so there is
/// no field here that could accidentally persist something §6.5 marks `Lost`.
fn encode(record: &DurableSession) -> Vec<u8> {
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(record.session_id.as_bytes());
    out.extend_from_slice(record.peer.as_bytes());
    let (tag, param) = state_tag(record.last_state);
    out.push(tag);
    out.push(param);
    match record.last_reason {
        Some(code) => {
            let bytes = code.as_str().as_bytes();
            out.push(u8::try_from(bytes.len()).unwrap_or(0));
            out.extend_from_slice(bytes);
        }
        None => out.push(0),
    }
    out
}

/// Decodes what [`encode`] wrote.
///
/// A record that does not decode is a **corrupt journal entry**, reported as
/// [`JournalError::Corrupt`] rather than skipped: `SessionJournal::load_all`'s
/// own doc says a caller "MUST NOT treat an error as 'no sessions': that would
/// silently drop every peer".
///
/// # Errors
///
/// [`JournalError::Corrupt`] for any malformed record.
pub fn decode(bytes: &[u8]) -> Result<DurableSession, JournalError> {
    if bytes.len() < 16 + 32 + 3 {
        return Err(JournalError::Corrupt);
    }
    let session_id = SessionId::from_slice(&bytes[..16]).map_err(|_| JournalError::Corrupt)?;
    let peer =
        twinvpn_types::DeviceId::from_slice(&bytes[16..48]).map_err(|_| JournalError::Corrupt)?;
    let last_state = state_from_tag(bytes[48], bytes[49]).ok_or(JournalError::Corrupt)?;
    let reason_len = usize::from(bytes[50]);
    let last_reason = if reason_len == 0 {
        None
    } else {
        let end = 51 + reason_len;
        if end > bytes.len() {
            return Err(JournalError::Corrupt);
        }
        let text = core::str::from_utf8(&bytes[51..end]).map_err(|_| JournalError::Corrupt)?;
        // A code the registry no longer carries decodes to `None` rather than
        // failing the whole record: `resumed()` supplies a class-compatible
        // default, and losing one code is better than losing the `Session`.
        ReasonCode::lookup(text)
    };
    Ok(DurableSession {
        session_id,
        peer,
        last_state,
        last_reason,
    })
}

/// `SessionState` → two bytes. **Exhaustive, no wildcard:** a thirteenth state
/// would fail to compile here rather than silently persist as `DISCONNECTED`.
const fn state_tag(state: SessionState) -> (u8, u8) {
    match state {
        SessionState::Disconnected => (1, 0),
        SessionState::Discovering => (2, 0),
        SessionState::Negotiating => (3, 0),
        SessionState::Connecting => (4, 0),
        SessionState::Steady(class) => (5, class_tag(class)),
        SessionState::Migrating { from, to } => (6, class_tag(from) << 4 | class_tag(to)),
        SessionState::Degraded { carrier } => (7, class_tag(carrier)),
        SessionState::Reconnecting { parked } => (8, parked as u8),
        SessionState::Blocked => (9, 0),
        SessionState::Failed => (10, 0),
    }
}

const fn state_from_tag(tag: u8, param: u8) -> Option<SessionState> {
    match tag {
        1 => Some(SessionState::Disconnected),
        2 => Some(SessionState::Discovering),
        3 => Some(SessionState::Negotiating),
        4 => Some(SessionState::Connecting),
        5 => match class_from_tag(param) {
            Some(c) => Some(SessionState::Steady(c)),
            None => None,
        },
        6 => match (class_from_tag(param >> 4), class_from_tag(param & 0x0f)) {
            (Some(from), Some(to)) => Some(SessionState::Migrating { from, to }),
            _ => None,
        },
        7 => match class_from_tag(param) {
            Some(carrier) => Some(SessionState::Degraded { carrier }),
            None => None,
        },
        8 => Some(SessionState::Reconnecting { parked: param != 0 }),
        9 => Some(SessionState::Blocked),
        10 => Some(SessionState::Failed),
        _ => None,
    }
}

const fn class_tag(class: PathClass) -> u8 {
    match class {
        PathClass::LocalDirect => 1,
        PathClass::WanDirect => 2,
        PathClass::Relayed => 3,
    }
}

const fn class_from_tag(tag: u8) -> Option<PathClass> {
    match tag {
        1 => Some(PathClass::LocalDirect),
        2 => Some(PathClass::WanDirect),
        3 => Some(PathClass::Relayed),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_types::{codes, DeviceId};

    fn record(state: SessionState) -> DurableSession {
        DurableSession {
            session_id: SessionId::from_slice(&[3; 16]).expect("16"),
            peer: DeviceId::from_slice(&[4; 32]).expect("32"),
            last_state: state,
            last_reason: state
                .requires_reason_code()
                .then_some(codes::POLICY_KILLSWITCH_ENGAGED),
        }
    }

    #[test]
    fn every_state_round_trips_through_the_vault_encoding() {
        let states = [
            SessionState::Disconnected,
            SessionState::Discovering,
            SessionState::Negotiating,
            SessionState::Connecting,
            SessionState::Steady(PathClass::LocalDirect),
            SessionState::Steady(PathClass::WanDirect),
            SessionState::Steady(PathClass::Relayed),
            SessionState::Migrating {
                from: PathClass::Relayed,
                to: PathClass::WanDirect,
            },
            SessionState::Degraded {
                carrier: PathClass::Relayed,
            },
            SessionState::Reconnecting { parked: true },
            SessionState::Reconnecting { parked: false },
            SessionState::Blocked,
            SessionState::Failed,
        ];
        for state in states {
            let original = record(state);
            let back = decode(&encode(&original)).expect("decodes");
            assert_eq!(back.last_state, state, "{state:?} did not round-trip");
            assert_eq!(back.session_id, original.session_id);
            assert_eq!(back.peer, original.peer);
        }
    }

    #[test]
    fn a_truncated_record_is_corrupt_not_empty() {
        assert!(matches!(decode(&[]), Err(JournalError::Corrupt)));
        assert!(matches!(decode(&[0; 10]), Err(JournalError::Corrupt)));
    }

    #[test]
    fn persist_makes_the_record_loadable_and_queues_a_durable_write() {
        let shared = crate::planes::new_shared();
        let journal = CoreSessionJournal::new(Arc::clone(&shared), Vec::new());
        let r = record(SessionState::Blocked);
        journal.persist(&r).expect("persist");
        assert_eq!(journal.load_all().expect("load"), vec![r.clone()]);
        assert_eq!(shared.lock().expect("lock").pending_snapshot().len(), 1);
    }

    #[test]
    fn forget_removes_the_record_and_queues_the_delete() {
        let shared = crate::planes::new_shared();
        let journal = CoreSessionJournal::new(Arc::clone(&shared), Vec::new());
        let r = record(SessionState::Failed);
        journal.persist(&r).expect("persist");
        journal.forget(r.session_id).expect("forget");
        assert!(journal.load_all().expect("load").is_empty());
        let pending = shared.lock().expect("lock").pending_snapshot();
        assert_eq!(pending.len(), 2);
        assert!(matches!(
            pending[1],
            PendingWrite::Session { value: None, .. }
        ));
    }

    #[test]
    fn a_restored_journal_resumes_into_reconnecting_except_where_the_user_closed_it() {
        // §6.5's rule, asserted through the adapter rather than only in the
        // session crate: this is what makes a diagnostic continuous across a
        // crash.
        let restored = vec![
            record(SessionState::Steady(PathClass::WanDirect)),
            DurableSession {
                session_id: SessionId::from_slice(&[9; 16]).expect("16"),
                peer: DeviceId::from_slice(&[9; 32]).expect("32"),
                last_state: SessionState::Disconnected,
                last_reason: None,
            },
        ];
        let journal = CoreSessionJournal::new(crate::planes::new_shared(), restored);
        let loaded = journal.load_all().expect("load");
        assert_eq!(loaded.len(), 2);
        let resumed: Vec<SessionState> = loaded.iter().map(DurableSession::resume_state).collect();
        assert!(resumed.contains(&SessionState::Reconnecting { parked: false }));
        assert!(resumed.contains(&SessionState::Disconnected));
    }
}
