//! The in-memory transactional store — the one that is actually executed here.
//!
//! **Authority:** the same rules as [`super::pg`]; the difference is only where
//! the bytes live. `ownership.md` §6 rule 3 wants component tests where a
//! component has a seam worth testing, and the seam worth testing in this
//! service is *the transaction*, not the SQL driver.
//!
//! # How the atomicity is real and not simulated
//!
//! [`MemStore::execute`] clones the `TwinNet`'s state, runs the whole command
//! against the clone, and **only then** swaps the clone in under the same lock
//! it took to read. A handler that returns an error, panics past this point, or
//! is dropped mid-way leaves the original untouched — including the appended
//! event, because the event was appended to the clone. That is the same
//! guarantee `BEGIN`/`COMMIT` gives, obtained the same way: nothing is visible
//! until everything is.
//!
//! It is not a *replacement* for testing the Postgres path. It is the part of
//! the property that can be executed on a host with no database, and
//! `README.md` §9 says which is which.

use std::collections::BTreeMap;
use std::sync::Mutex;

use futures::future::BoxFuture;
use twinvpn_service_common::transport::WriteBudget;
use twinvpn_service_common::ServiceError;

use crate::codes;
use crate::config::{EVENT_RATE_BURST, EVENT_RATE_SUSTAINED};
use crate::dispatch;
use crate::domain::Ctx;
use crate::model::{NetState, StoredEvent};
use crate::tx::{NetTx, WriteLease};

use super::{Committed, ControlStore, Request, StoreHealth};

/// A per-`TwinNet` slot: its state and its write budget.
struct Slot {
    state: NetState,
    budget: WriteBudget,
}

/// The in-memory store.
pub struct MemStore {
    nets: Mutex<BTreeMap<String, Slot>>,
    /// The fencing token this process presents. ADR-0009 §11.2: a write is
    /// admitted only if it presents the current `shard_epoch`.
    shard_epoch: u64,
    /// Whether this process believes it holds the lease. Settable so the
    /// readiness probe and the lease-less refusal can both be exercised.
    lease_held: bool,
}

impl std::fmt::Debug for MemStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemStore")
            .field("shard_epoch", &self.shard_epoch)
            .field("lease_held", &self.lease_held)
            .finish_non_exhaustive()
    }
}

impl MemStore {
    /// A store holding the lease at `shard_epoch` 1.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nets: Mutex::new(BTreeMap::new()),
            shard_epoch: 1,
            lease_held: true,
        }
    }

    /// A store fenced out by a newer writer — for the N-4 refusal test.
    #[must_use]
    pub fn fenced_out(current_shard_epoch: u64) -> Self {
        Self {
            nets: Mutex::new(BTreeMap::new()),
            shard_epoch: current_shard_epoch.saturating_sub(1),
            lease_held: false,
        }
    }

    /// Seeds a `TwinNet` whose recorded `shard_epoch` is `epoch`.
    ///
    /// # Panics
    ///
    /// If the store lock was poisoned by a panic while it was held.
    pub fn seed_shard_epoch(&self, twinnet_id: &str, epoch: u64) {
        let mut nets = self.nets.lock().expect("store lock");
        let slot = nets.entry(twinnet_id.to_owned()).or_insert_with(|| Slot {
            state: NetState::new(twinnet_id),
            budget: fresh_budget(),
        });
        slot.state.shard_epoch = epoch;
    }

    /// A snapshot of a `TwinNet`'s state, for assertions.
    ///
    /// # Panics
    ///
    /// If the store lock was poisoned.
    #[must_use]
    pub fn snapshot(&self, twinnet_id: &str) -> Option<NetState> {
        self.nets
            .lock()
            .expect("store lock")
            .get(twinnet_id)
            .map(|s| s.state.clone())
    }

    /// Replaces a `TwinNet`'s state wholesale, for building a fixture.
    ///
    /// # Panics
    ///
    /// If the store lock was poisoned.
    pub fn install(&self, state: NetState) {
        let mut nets = self.nets.lock().expect("store lock");
        nets.insert(
            state.twinnet_id.clone(),
            Slot {
                state,
                budget: fresh_budget(),
            },
        );
    }

    /// Compacts the retained window to start at `from`, announcing the gap.
    ///
    /// ADR-0002 N-8: a compaction is announced **in band and in order**. This
    /// only moves the retention floor; the announcement is the `StreamCompacted`
    /// event the session layer emits, and `tests/compaction.rs` asserts a cursor
    /// below the new floor is refused rather than silently skipped.
    ///
    /// # Panics
    ///
    /// If the store lock was poisoned.
    pub fn compact_below(&self, twinnet_id: &str, from: u64) {
        let mut nets = self.nets.lock().expect("store lock");
        if let Some(slot) = nets.get_mut(twinnet_id) {
            slot.state.retained_from = from;
            slot.state.events.retain(|e| e.net_seq >= from);
        }
    }
}

impl Default for MemStore {
    fn default() -> Self {
        Self::new()
    }
}

/// The frozen per-`TwinNet` durable write budget.
fn fresh_budget() -> WriteBudget {
    WriteBudget::new(
        EVENT_RATE_SUSTAINED,
        EVENT_RATE_BURST,
        std::time::Instant::now(),
    )
}

impl ControlStore for MemStore {
    fn execute<'a>(
        &'a self,
        request: Request<'a>,
    ) -> BoxFuture<'a, Result<Committed, ServiceError>> {
        Box::pin(async move {
            let mut nets = self.nets.lock().expect("store lock");
            let slot = nets
                .entry(request.twinnet_id.to_owned())
                .or_insert_with(|| Slot {
                    state: NetState::new(request.twinnet_id),
                    budget: fresh_budget(),
                });

            // The working copy. Nothing outside this function sees a byte of it
            // until the swap below.
            let working = slot.state.clone();
            let mut budget = slot.budget.clone();

            let mut tx = NetTx::open(
                working,
                WriteLease {
                    shard_epoch: self.shard_epoch,
                },
                request.now_ms,
            )?
            .caused_by(request.correlation);

            let ctx = Ctx {
                caller: request.caller,
                twinnet_id: request.twinnet_id,
                now_ms: request.now_ms,
                verifier: request.verifier,
                quorum_available: request.quorum_available,
                correlation: request.correlation,
                coordination_endpoints: request.coordination_endpoints,
            };

            let outcome = dispatch::execute(
                &mut tx,
                &ctx,
                request.code,
                request.body,
                &mut budget,
                request.now,
            )?;

            let (journal, new_state, ephemeral) = tx.into_journal();
            let appended: Vec<StoredEvent> = journal.appended().cloned().collect();

            // COMMIT. One assignment, under the lock that read the original.
            slot.state = new_state;
            slot.budget = budget;

            Ok(Committed {
                response: outcome.first,
                committed_at_net_seq: outcome.committed_at_net_seq,
                idempotent_replay: outcome.replayed,
                appended,
                ephemeral,
            })
        })
    }

    fn events_from<'a>(
        &'a self,
        twinnet_id: &'a str,
        from_net_seq: u64,
        max: usize,
    ) -> BoxFuture<'a, Result<Vec<StoredEvent>, ServiceError>> {
        Box::pin(async move {
            let nets = self.nets.lock().expect("store lock");
            let Some(slot) = nets.get(twinnet_id) else {
                return Ok(Vec::new());
            };
            // ADR-0002 §11.3: a cursor below the retained floor is answered with
            // CONTROL.CURSOR_TOO_OLD and the device re-snapshots declaratively.
            // Serving what happens to remain would hand it a silent gap.
            if from_net_seq != 0 && from_net_seq + 1 < slot.state.retained_from {
                return Err(codes::cursor_too_old(
                    from_net_seq,
                    slot.state.retained_from,
                ));
            }
            Ok(slot
                .state
                .events
                .iter()
                .filter(|e| e.net_seq > from_net_seq)
                .take(max)
                .cloned()
                .collect())
        })
    }

    fn head<'a>(&'a self, twinnet_id: &'a str) -> BoxFuture<'a, Result<u64, ServiceError>> {
        Box::pin(async move {
            let nets = self.nets.lock().expect("store lock");
            Ok(nets.get(twinnet_id).map_or(0, |s| s.state.head_net_seq()))
        })
    }

    fn trust_epoch<'a>(&'a self, twinnet_id: &'a str) -> BoxFuture<'a, Result<u64, ServiceError>> {
        Box::pin(async move {
            let nets = self.nets.lock().expect("store lock");
            Ok(nets.get(twinnet_id).map_or(0, |s| s.state.trust_epoch))
        })
    }

    fn probe(&self) -> BoxFuture<'_, Result<StoreHealth, ServiceError>> {
        Box::pin(async move {
            Ok(StoreHealth {
                reachable: true,
                lease_held: self.lease_held,
            })
        })
    }
}
