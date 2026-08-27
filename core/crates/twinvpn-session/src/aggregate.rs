//! §4.7's derived `TwinNet`-scope state: **worst wins**.
//!
//! **Authority:** `docs/reliability.md` §4.7.
//!
//! ```text
//! BLOCKED  >  FAILED (all sessions)  >  RECONNECTING (any)  >  DEGRADED (any)
//!          >  MIGRATING (any)  >  RELAYED (any established session on relay)
//!          >  WAN_DIRECT  >  LOCAL_DIRECT
//!          >  CONNECTING > NEGOTIATING > DISCOVERING  >  DISCONNECTED
//! ```
//!
//! Two rules make this honest rather than alarming, and both are implemented:
//! the fail-closed override, and carrying the worst contributor's code plus a
//! count of healthy `Session`s — "3 of 4 devices connected; laptop unreachable
//! because …" is the target sentence, not "Connected" or "Error".

use twinvpn_types::{ConnectionState, ReasonCode};

use crate::state::SessionState;

/// The aggregate a surface renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwinNetState {
    /// The aggregate state.
    pub state: ConnectionState,
    /// The reason code of the **worst contributing** `Session`.
    pub reason_code: Option<ReasonCode>,
    /// How many `Session`s are carrying traffic.
    pub healthy: usize,
    /// How many `Session`s there are in total.
    pub total: usize,
}

/// One `Session`'s contribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Contribution {
    /// Its state.
    pub state: SessionState,
    /// Its reason code, where it has one.
    pub reason_code: Option<ReasonCode>,
    /// Whether the peer is inside the protected scope, for rule 1.
    pub in_protected_scope: bool,
    /// Whether this `Session` currently has a usable path.
    pub has_usable_path: bool,
}

/// §4.7's priority. Lower is worse; the minimum wins.
fn rank(state: ConnectionState) -> u8 {
    match state {
        ConnectionState::Blocked => 0,
        ConnectionState::Failed => 1,
        ConnectionState::Reconnecting => 2,
        ConnectionState::Degraded => 3,
        ConnectionState::Migrating => 4,
        ConnectionState::Relayed => 5,
        ConnectionState::WanDirect => 6,
        ConnectionState::LocalDirect => 7,
        ConnectionState::Connecting => 8,
        ConnectionState::Negotiating => 9,
        ConnectionState::Discovering => 10,
        ConnectionState::Disconnected => 11,
        ConnectionState::Unspecified => 12,
    }
}

/// Aggregates per-`Session` states into the one a user is shown.
///
/// # The two honesty rules
///
/// 1. **Fail-closed override.** "If enforcement is `FAIL_CLOSED` and **no**
///    `Session` in the protected scope has a usable path, the aggregate is
///    `BLOCKED` regardless of the individual states." That is what makes
///    `FAILED` and `BLOCKED` coexist correctly: a `Session` can be `FAILED`
///    while the device as a whole is `BLOCKED`.
/// 2. **`FAILED` needs *all* sessions.** §4.7's ladder writes "FAILED (all
///    sessions)": one failed peer among four healthy ones must not make the
///    whole `TwinNet` read as failed.
#[must_use]
pub fn aggregate(sessions: &[Contribution], fail_closed: bool) -> TwinNetState {
    let total = sessions.len();
    let healthy = sessions
        .iter()
        .filter(|c| c.state.connection_state().carries_traffic())
        .count();

    if total == 0 {
        return TwinNetState {
            state: ConnectionState::Disconnected,
            reason_code: None,
            healthy: 0,
            total: 0,
        };
    }

    let protected: Vec<&Contribution> = sessions.iter().filter(|c| c.in_protected_scope).collect();
    let none_protected_usable =
        !protected.is_empty() && protected.iter().all(|c| !c.has_usable_path);

    // Rule 1.
    if fail_closed && none_protected_usable {
        let worst = worst_contributor(sessions);
        return TwinNetState {
            state: ConnectionState::Blocked,
            reason_code: worst.and_then(|c| c.reason_code),
            healthy,
            total,
        };
    }

    let all_failed = sessions
        .iter()
        .all(|c| c.state == SessionState::Failed);

    let worst = worst_contributor_excluding_partial_failed(sessions, all_failed);
    let state = worst.map_or(ConnectionState::Disconnected, |c| {
        c.state.connection_state()
    });

    TwinNetState {
        state,
        reason_code: worst.and_then(|c| c.reason_code),
        healthy,
        total,
    }
}

fn worst_contributor(sessions: &[Contribution]) -> Option<&Contribution> {
    sessions
        .iter()
        .min_by_key(|c| rank(c.state.connection_state()))
}

fn worst_contributor_excluding_partial_failed(
    sessions: &[Contribution],
    all_failed: bool,
) -> Option<&Contribution> {
    sessions
        .iter()
        .filter(|c| all_failed || c.state != SessionState::Failed)
        .min_by_key(|c| rank(c.state.connection_state()))
        .or_else(|| worst_contributor(sessions))
}
