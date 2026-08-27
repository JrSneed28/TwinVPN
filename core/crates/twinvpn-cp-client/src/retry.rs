//! Retry discipline, and what a control-plane `ErrorEnvelope` is allowed to mean.
//!
//! **Authority:** `contracts/docs/contract-matrix.md` §3 (the Retryable column),
//! `contracts/docs/idempotency.md` §4 (the response to a duplicate), ADR-0002
//! §11.7 rule 3 (honour `retry_after_ms`), `contract-matrix.md` §2's
//! `ErrorEnvelope` row: **received attributes are a claim, not a fact.**
//!
//! The one place a retry is wrong is after a precondition failure:
//!
//! > *"The client MUST re-read the current document before the next attempt, not
//! > blindly retry. A blind retry loops."*

use twinvpn_schema::v1;

use crate::commands::RETENTION_FLOOR_EVENTS;
use crate::error::CpError;
use crate::idempotency::Command;

/// Maps a control-plane `ErrorEnvelope` onto this crate's error type.
///
/// A received `reason_code` is **a claim, not a fact** (`contract-matrix.md` §2,
/// `ErrorEnvelope` row), so an unrecognised or unregistered code degrades to the
/// generic transport failure for its domain rather than being echoed onward as
/// though we had verified it.
#[must_use]
pub fn map_error_envelope(envelope: &v1::ErrorEnvelope) -> Option<CpError> {
    let code = twinvpn_types::ReasonCode::lookup(&envelope.reason_code)?;
    Some(match code.as_str() {
        "CONTROL.QUORUM_UNAVAILABLE" => CpError::QuorumUnavailable,
        "CONTROL.WRITE_LEADER_UNAVAILABLE" => CpError::WriteLeaderUnavailable,
        "CONTROL.EVENT_RATE_EXCEEDED" => CpError::EventRateExceeded,
        "CONTROL.CURSOR_TOO_OLD" => CpError::CursorTooOld {
            cursor: 0,
            retention_floor: RETENTION_FLOOR_EVENTS,
        },
        "CONTROL.READ_TOO_STALE" => CpError::ReadTooStale { retry_after_ms: 0 },
        "CONTROL.CONSISTENCY.REPLICA_BEHIND_CURSOR" => CpError::ReplicaBehindCursor {
            min_net_seq: 0,
            replica_net_seq: 0,
        },
        "CONTROL.ADMISSION_DEFERRED" => CpError::AdmissionDeferred { retry_after_ms: 0 },
        "AUTH.IDENTITY_MISMATCH" => CpError::IdentityMismatch,
        "AUTH.TRUST_EPOCH_ROLLBACK" => CpError::TrustEpochRollback {
            offered_epoch: 0,
            high_water_epoch: 0,
        },
        _ => return None,
    })
}

/// Whether a failed command may be retried with the **same** idempotency key.
///
/// Every row of `contract-matrix.md` §3 answers "yes" in its Retryable column;
/// what differs is the mechanism (`same key`, `if_version`, or nothing at all
/// because the operation is a state assertion). The one place a retry is wrong
/// is after a precondition failure: *"The client MUST re-read the current
/// document before the next attempt, not blindly retry. A blind retry loops."*
#[must_use]
pub const fn may_retry(command: Command, err: &CpError) -> Retry {
    match err {
        // A rollback or a fork is an authoritative refusal, not a transient
        // failure. Retrying re-offers a value the store has already refused.
        CpError::TrustEpochRollback { .. }
        | CpError::TrustHistoryForked { .. }
        | CpError::IdentityMismatch
        | CpError::ChannelBindingMismatch
        | CpError::EventWrongPublisher { .. } => Retry::Never,
        // Honour the server's number rather than choosing our own.
        CpError::AdmissionDeferred { retry_after_ms }
        | CpError::ReadTooStale { retry_after_ms } => Retry::After {
            millis: *retry_after_ms,
        },
        // The precondition, not the key, is what failed. Re-read first.
        CpError::Rejected(_) => Retry::RereadThenRetry,
        _ if command.class().requires_idempotency_key() => Retry::SameKey,
        _ => Retry::Backoff,
    }
}

/// How a failed command may be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    /// Retry with the **same** `idempotency_key`, under the infrastructure
    /// backoff regime. A fresh key would duplicate the ceremony.
    SameKey,
    /// Retry under backoff; the operation carries no key because its class does
    /// not need one.
    Backoff,
    /// Honour the server's `retry_after_ms` exactly.
    After {
        /// The server's number.
        millis: u64,
    },
    /// Re-read the current document, **then** retry. A blind retry loops.
    RereadThenRetry,
    /// Do not retry. The refusal is authoritative.
    Never,
}
