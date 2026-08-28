//! Where the state and its log live, and how one command becomes one
//! transaction.
//!
//! **Authority:** ADR-0002 §11.3 and B-3 (the durable event log is "a
//! per-`TwinNet` append-only `event` relation in the **same transactional
//! store** as control-plane state, with `net_seq` allocated **inside the
//! mutating transaction**"), N-4 (one writer per `TwinNet`, under a lease),
//! ADR-0009 §11.2 (shard ownership and fencing),
//! `infra/postgres/initdb/10-databases.sh`.
//!
//! # Two implementations, one set of rules
//!
//! [`mem::MemStore`] and [`pg::PgStore`] both do exactly this:
//!
//! ```text
//!   take the TwinNet's write lock ──▶ load the NetState ──▶ NetTx::open
//!        ──▶ dispatch::execute ──▶ apply the journal ──▶ commit
//! ```
//!
//! Every rule — monotone versions, the never-shrinking revoked set, the
//! sole-publisher check, the dedup log, `net_seq` allocation — lives in
//! [`crate::domain`] and [`crate::tx`], which both stores call. That is
//! deliberate: two stores with two copies of "may this epoch go backwards" is
//! two answers to one question, and only one of them gets tested.
//!
//! # What was and was not executed on this host
//!
//! `MemStore` is exercised by every test in this crate, including the crash
//! between the mutation and its event. `PgStore` **has never been run**: this
//! host has no PostgreSQL and no Docker (`infra/README.md` §9 records the same
//! absence). Its SQL is written against the migrations in `migrations/` and is
//! compiled, not executed. `README.md` §9 says so plainly rather than leaving it
//! to be discovered.

pub mod mem;
pub mod pg;

use futures::future::BoxFuture;
use twinvpn_service_common::{Correlation, ServiceError};

use crate::event::EphemeralEvent;
use crate::model::{DeviceKey, StoredEvent};
use crate::verify::StatementVerifier;
use crate::CommandCode;

/// One C1 request, with everything the domain needs that is not stored state.
pub struct Request<'a> {
    /// The `TwinNet` scope.
    pub twinnet_id: &'a str,
    /// The **authenticated** caller — the mTLS peer identity, not a body field.
    pub caller: DeviceKey,
    /// The COSE_Key form of the raw public key the caller presented on this
    /// connection. See [`crate::domain::Ctx::caller_identity_key`].
    pub caller_identity_key: Option<&'a [u8]>,
    /// Wall-clock milliseconds. Evidence, and the two contract-defined windows.
    pub now_ms: u64,
    /// The monotonic instant the rate limiters take. **Not** the wall clock:
    /// a budget driven by a wall clock that jumps is a budget an operator can
    /// widen by changing the time.
    pub now: std::time::Instant,
    /// The signature verifier. Fail-closed by default.
    pub verifier: &'a dyn StatementVerifier,
    /// Whether an E-1-class write may commit.
    pub quorum_available: bool,
    /// Preserved across the hop.
    pub correlation: Correlation,
    /// Returned by `RegisterDevice`.
    pub coordination_endpoints: &'a [String],
    /// Which command.
    pub code: CommandCode,
    /// The untrusted body. Bounded by [`crate::wire`] before it reaches here.
    pub body: &'a [u8],
}

/// What a committed transaction produced.
#[derive(Debug, Clone)]
pub struct Committed {
    /// The response octets for this caller.
    pub response: Vec<u8>,
    /// The position the effect committed at, `0` for a read.
    pub committed_at_net_seq: u64,
    /// Whether a recorded outcome was served rather than executed.
    pub idempotent_replay: bool,
    /// The durable events appended, for fan-out **after** the commit.
    pub appended: Vec<StoredEvent>,
    /// The ephemeral events queued. Never logged, never resumable.
    pub ephemeral: Vec<EphemeralEvent>,
}

/// The store interface the session layer talks to.
pub trait ControlStore: Send + Sync {
    /// Runs one command as one transaction.
    ///
    /// # Errors
    ///
    /// Any registered `reason_code` the domain or the store produces.
    fn execute<'a>(
        &'a self,
        request: Request<'a>,
    ) -> BoxFuture<'a, Result<Committed, ServiceError>>;

    /// Durable events strictly after `from_net_seq`, at most `max` of them.
    ///
    /// # Errors
    ///
    /// `CONTROL.CURSOR_TOO_OLD` when the cursor is below the retention floor.
    fn events_from<'a>(
        &'a self,
        twinnet_id: &'a str,
        from_net_seq: u64,
        max: usize,
    ) -> BoxFuture<'a, Result<Vec<StoredEvent>, ServiceError>>;

    /// The `device_id` the identity `identity_id` currently names, if any.
    ///
    /// **The rotation seam.** A `device_id` is the hash of a device's
    /// *generation-0* identity key (`identifiers.md` §2), so a device that has
    /// rotated presents a generation-N key on TLS whose derivation is **not**
    /// its `device_id` — and `service-common`'s [`DerivedPreferred`] binding
    /// documents that closing that gap needs the succession chain, which the
    /// rendezvous and presence may not fetch.
    ///
    /// This service **is** the chain: `RotateDeviceCredential` is one of its own
    /// commands, and `device.identity_id` is re-indexed to the successor the
    /// verified `IdentitySuccession` names. So the control plane can do the
    /// strict thing the other services cannot — resolve a presented key to a
    /// `device_id` through a record it wrote itself, rather than pinning a
    /// claim.
    ///
    /// A miss is `Ok(None)`, not an error: an unregistered generation-0 key is
    /// exactly what `RegisterDevice` arrives on.
    ///
    /// [`DerivedPreferred`]: twinvpn_service_common::binding::DerivedPreferred
    ///
    /// # Errors
    ///
    /// A store failure.
    fn device_for_identity<'a>(
        &'a self,
        twinnet_id: &'a str,
        identity_id: DeviceKey,
    ) -> BoxFuture<'a, Result<Option<DeviceKey>, ServiceError>>;

    /// The current head position, for `LogHead` and the attach response.
    ///
    /// # Errors
    ///
    /// A store failure.
    fn head<'a>(&'a self, twinnet_id: &'a str) -> BoxFuture<'a, Result<u64, ServiceError>>;

    /// The current trust epoch, served in the attach response **before any event
    /// body** so the security-critical fact arrives in RTT 1 (§11.6).
    ///
    /// # Errors
    ///
    /// A store failure.
    fn trust_epoch<'a>(&'a self, twinnet_id: &'a str) -> BoxFuture<'a, Result<u64, ServiceError>>;

    /// The readiness probe: is the datastore reachable **and** is the write
    /// lease obtainable or knowingly held elsewhere?
    ///
    /// `infra/README.md` §5 names both halves for this service. A store that
    /// answered on reachability alone would report ready while every mutation
    /// was refused with `CONTROL.WRITE_LEADER_UNAVAILABLE`.
    ///
    /// # Errors
    ///
    /// A store failure, which the caller turns into a not-ready answer.
    fn probe(&self) -> BoxFuture<'_, Result<StoreHealth, ServiceError>>;
}

/// What the readiness probe found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreHealth {
    /// The datastore answered.
    pub reachable: bool,
    /// This process holds, or can obtain, the per-`TwinNet` write lease.
    pub lease_held: bool,
}

impl StoreHealth {
    /// Whether the service can serve.
    ///
    /// A store that is reachable but whose lease is held elsewhere is **still
    /// ready**: reads and the C2 stream are served from the replica, and a
    /// mutation is refused with a named, retryable code. Reporting not-ready for
    /// a lease held by the current leader would take every follower out of
    /// service during a normal deployment.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        self.reachable
    }
}

#[cfg(test)]
mod tests {
    use super::StoreHealth;

    #[test]
    fn an_unreachable_datastore_is_not_ready() {
        assert!(!StoreHealth {
            reachable: false,
            lease_held: true
        }
        .is_ready());
    }

    #[test]
    fn a_follower_without_the_lease_is_still_ready() {
        // Mutations are refused with CONTROL.WRITE_LEADER_UNAVAILABLE, which is
        // TRANSIENT and retryable. Taking every follower out of service during a
        // normal leader handover would turn a handover into an outage.
        assert!(StoreHealth {
            reachable: true,
            lease_held: false
        }
        .is_ready());
    }
}
