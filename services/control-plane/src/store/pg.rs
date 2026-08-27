//! The PostgreSQL store: the same transaction, in the store ADR-0002 B-3 names.
//!
//! **Authority:** ADR-0002 §11.3 and B-3, N-3, N-4; ADR-0009 §11.2;
//! `infra/postgres/initdb/10-databases.sh`; the migrations in `migrations/`.
//!
//! # NOT EXECUTED ON THIS HOST
//!
//! This host has no PostgreSQL server and no Docker — the same absence
//! `infra/README.md` §9 records for the `infrastructure` domain. Everything
//! below is **compiled, not run**. `README.md` §9 lists it as the largest
//! honest gap in this component, and the tests that *do* run exercise the same
//! [`crate::domain`] and [`crate::tx`] code through [`super::mem::MemStore`].
//!
//! # The shape, and why it is this shape
//!
//! ```text
//!   BEGIN
//!   SELECT … FROM twinnet WHERE twinnet_id = $1 FOR UPDATE   ← the serialisation point
//!   load the TwinNet slice into a NetState
//!   NetTx::open  ▸  dispatch::execute  ▸  apply the journal
//!   COMMIT
//! ```
//!
//! `FOR UPDATE` on the `twinnet` row is what makes ADR-0002 N-4's "exactly one
//! writer per `TwinNet` log at any instant" true **within** a process as well as
//! between processes, and it is what makes `net_seq` allocation dense: the
//! counter is read and written inside the same lock, so two concurrent commands
//! cannot both read the same `next_net_seq`.
//!
//! The event `INSERT` is in that transaction. There is no publish step, no
//! outbox and no notification that could be lost — which is the whole of
//! `contract-matrix.md` §5's "no dual write exists to be lost". `LISTEN/NOTIFY`
//! (`TWINVPN_CP_EVENT_BUS=postgres-notify`) carries only the watermark ADR-0002
//! N-6 permits, and is issued **after** the commit precisely because losing it
//! costs a fan-out latency and nothing else.
//!
//! # The known cost, stated
//!
//! [`PgStore::load`] materialises the whole `TwinNet` slice per command. That is
//! correct — one writer per `TwinNet`, everything under one lock — and it is
//! O(devices + pairings) per command, so it does not scale to a very large
//! `TwinNet`. It is the right first implementation for a design whose
//! single-box topology (T2/T3) is a first-class deployment, and it is recorded
//! in `README.md` §10 rather than left to be discovered under load.

use std::collections::{BTreeMap, BTreeSet};

use futures::future::BoxFuture;
use sqlx::{PgPool, Row};
use twinvpn_service_common::transport::WriteBudget;
use twinvpn_service_common::ServiceError;

use crate::codes;
use crate::config::{EVENT_RATE_BURST, EVENT_RATE_SUSTAINED};
use crate::dispatch;
use crate::domain::Ctx;
use crate::event::{EventKind, Publisher};
use crate::model::{
    DeviceKey, DeviceRecord, DocumentRecord, DocumentType, IdempotencyRecord, NetState, PairingKey,
    PairingRecord, PairingState, RelayTokenRecord, StoredEvent,
};
use crate::tx::{Change, NetTx, WriteLease};

use super::{Committed, ControlStore, Request, StoreHealth};

/// The PostgreSQL-backed store.
#[derive(Debug, Clone)]
pub struct PgStore {
    pool: PgPool,
    /// The fencing token this process presents (S-28).
    shard_epoch: u64,
    /// This process's lease identity, recorded in `twinnet.lease_holder`.
    holder: String,
}

impl PgStore {
    /// Binds a store to a pool.
    #[must_use]
    pub const fn new(pool: PgPool, shard_epoch: u64, holder: String) -> Self {
        Self {
            pool,
            shard_epoch,
            holder,
        }
    }

    /// Runs the migrations in `migrations/`.
    ///
    /// Forward-only and idempotent to re-run; `sqlx::migrate!` records what it
    /// applied and refuses a file whose checksum changed, which is the property
    /// that makes "the schema in the database is the schema in the repository" a
    /// fact rather than a hope.
    ///
    /// # Errors
    ///
    /// A migration failure, which is a startup failure: a service running
    /// against a schema it does not recognise is worse than one that will not
    /// start.
    pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::Error> {
        sqlx::migrate!("./migrations")
            .run(pool)
            .await
            .map_err(|e| sqlx::Error::Migrate(Box::new(e)))
    }

    /// Loads the whole `TwinNet` slice inside an open transaction.
    ///
    /// The `FOR UPDATE` on `twinnet` has already been taken by the caller, so
    /// every read below is consistent with it.
    ///
    /// One long linear function, deliberately: this is the exhaustive list of
    /// what one `TwinNet` owns, and a reader checking it against
    /// `architecture.md` §5 wants to see every row in one place. Split into six
    /// helpers, "which table is missing" stops being answerable by reading.
    #[allow(clippy::too_many_lines)]
    async fn load(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        twinnet_id: &str,
    ) -> Result<NetState, sqlx::Error> {
        let head = sqlx::query(
            "SELECT next_net_seq, trust_epoch, shard_epoch, policy_version, retained_from, \
             next_v4_offset FROM twinnet WHERE twinnet_id = $1",
        )
        .bind(twinnet_id)
        .fetch_one(&mut **tx)
        .await?;

        let mut state = NetState::new(twinnet_id);
        state.next_net_seq = u64_of(head.try_get::<i64, _>("next_net_seq")?);
        state.trust_epoch = u64_of(head.try_get::<i64, _>("trust_epoch")?);
        state.shard_epoch = u64_of(head.try_get::<i64, _>("shard_epoch")?);
        state.policy_version = u64_of(head.try_get::<i64, _>("policy_version")?);
        state.retained_from = u64_of(head.try_get::<i64, _>("retained_from")?);
        state.next_v4_offset =
            u32::try_from(head.try_get::<i64, _>("next_v4_offset")?).unwrap_or(u32::MAX);

        for row in sqlx::query(
            "SELECT device_id, identity_id, identity_public_key, generation, tk_generation, \
             label, version, membership_epoch, twinnet_addr_v4, twinnet_addr_v6, encoded, \
             revoked, net_seq, created_at_ms FROM device WHERE twinnet_id = $1",
        )
        .bind(twinnet_id)
        .fetch_all(&mut **tx)
        .await?
        {
            let device_id = key32(&row.try_get::<Vec<u8>, _>("device_id")?);
            let record = DeviceRecord {
                device_id,
                identity_id: key32(&row.try_get::<Vec<u8>, _>("identity_id")?),
                identity_public_key: row.try_get("identity_public_key")?,
                generation: u32::try_from(row.try_get::<i32, _>("generation")?).unwrap_or(0),
                tk_generation: u32::try_from(row.try_get::<i32, _>("tk_generation")?).unwrap_or(0),
                label: row.try_get("label")?,
                version: u64_of(row.try_get::<i64, _>("version")?),
                membership_epoch: u64_of(row.try_get::<i64, _>("membership_epoch")?),
                twinnet_addr_v4: fixed4(&row.try_get::<Vec<u8>, _>("twinnet_addr_v4")?),
                twinnet_addr_v6: fixed16(&row.try_get::<Vec<u8>, _>("twinnet_addr_v6")?),
                encoded: row.try_get("encoded")?,
                revoked: row.try_get("revoked")?,
                net_seq: u64_of(row.try_get::<i64, _>("net_seq")?),
                created_at_ms: u64_of(row.try_get::<i64, _>("created_at_ms")?),
            };
            state.devices.insert(device_id, record);
        }

        let mut revoked = BTreeSet::new();
        for row in sqlx::query("SELECT device_id FROM revocation WHERE twinnet_id = $1")
            .bind(twinnet_id)
            .fetch_all(&mut **tx)
            .await?
        {
            revoked.insert(key32(&row.try_get::<Vec<u8>, _>("device_id")?));
        }
        state.revoked = revoked;

        let mut pairings = BTreeMap::new();
        for row in sqlx::query(
            "SELECT pairing_id, state, version, expires_at_ms, initiator, outcome, \
             failed_attempts FROM pairing WHERE twinnet_id = $1",
        )
        .bind(twinnet_id)
        .fetch_all(&mut **tx)
        .await?
        {
            let pairing_id = key16(&row.try_get::<Vec<u8>, _>("pairing_id")?);
            pairings.insert(
                pairing_id,
                PairingRecord {
                    pairing_id,
                    state: pairing_state(&row.try_get::<String, _>("state")?),
                    version: u64_of(row.try_get::<i64, _>("version")?),
                    expires_at_ms: u64_of(row.try_get::<i64, _>("expires_at_ms")?),
                    initiator: key32(&row.try_get::<Vec<u8>, _>("initiator")?),
                    outcome: row.try_get("outcome")?,
                    failed_attempts: u32::try_from(row.try_get::<i32, _>("failed_attempts")?)
                        .unwrap_or(0),
                },
            );
        }
        state.pairings = pairings;

        for row in sqlx::query(
            "SELECT doc_type, version, content_digest, octets, net_seq, trust_epoch, \
             issued_at_ms FROM state_document WHERE twinnet_id = $1",
        )
        .bind(twinnet_id)
        .fetch_all(&mut **tx)
        .await?
        {
            let Some(doc_type) = DocumentType::from_wire(row.try_get::<i32, _>("doc_type")?) else {
                continue;
            };
            state.documents.insert(
                doc_type,
                DocumentRecord {
                    version: u64_of(row.try_get::<i64, _>("version")?),
                    content_digest: key32(&row.try_get::<Vec<u8>, _>("content_digest")?),
                    octets: row.try_get("octets")?,
                    net_seq: u64_of(row.try_get::<i64, _>("net_seq")?),
                    trust_epoch: u64_of(row.try_get::<i64, _>("trust_epoch")?),
                    issued_at_ms: u64_of(row.try_get::<i64, _>("issued_at_ms")?),
                },
            );
        }

        for row in
            sqlx::query("SELECT advertiser, epoch, octets FROM route_set WHERE twinnet_id = $1")
                .bind(twinnet_id)
                .fetch_all(&mut **tx)
                .await?
        {
            let who = key32(&row.try_get::<Vec<u8>, _>("advertiser")?);
            state
                .route_epochs
                .insert(who, u64_of(row.try_get::<i64, _>("epoch")?));
            state.route_sets.insert(who, row.try_get("octets")?);
        }

        for row in
            sqlx::query("SELECT offerer, epoch, octets FROM exit_offer WHERE twinnet_id = $1")
                .bind(twinnet_id)
                .fetch_all(&mut **tx)
                .await?
        {
            let who = key32(&row.try_get::<Vec<u8>, _>("offerer")?);
            state
                .offer_epochs
                .insert(who, u64_of(row.try_get::<i64, _>("epoch")?));
            state.offer_sets.insert(who, row.try_get("octets")?);
        }

        for row in sqlx::query(
            "SELECT device_id, epoch, octets, not_after_ms FROM relay_token WHERE twinnet_id = $1",
        )
        .bind(twinnet_id)
        .fetch_all(&mut **tx)
        .await?
        {
            let device_id = key32(&row.try_get::<Vec<u8>, _>("device_id")?);
            state.relay_tokens.insert(
                device_id,
                RelayTokenRecord {
                    device_id,
                    epoch: u64_of(row.try_get::<i64, _>("epoch")?),
                    octets: row.try_get("octets")?,
                    not_after_ms: u64_of(row.try_get::<i64, _>("not_after_ms")?),
                },
            );
        }

        // Only the caller's own dedup records are needed, and N-4 scopes the key
        // to the caller anyway — loading the whole TwinNet's dedup log would be
        // the one unbounded read in this function.
        Ok(state)
    }

    /// Loads the dedup records for one caller.
    async fn load_dedup(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        twinnet_id: &str,
        caller: DeviceKey,
        state: &mut NetState,
    ) -> Result<(), sqlx::Error> {
        for row in sqlx::query(
            "SELECT idempotency_key, command, response, committed_at_net_seq, stored_at_ms \
             FROM idempotency WHERE twinnet_id = $1 AND device_id = $2",
        )
        .bind(twinnet_id)
        .bind(caller.to_vec())
        .fetch_all(&mut **tx)
        .await?
        {
            let Some(command) = command_of(&row.try_get::<String, _>("command")?) else {
                continue;
            };
            state.idempotency.insert(
                (caller, row.try_get::<Vec<u8>, _>("idempotency_key")?),
                IdempotencyRecord {
                    command,
                    response: row.try_get("response")?,
                    committed_at_net_seq: u64_of(row.try_get::<i64, _>("committed_at_net_seq")?),
                    stored_at_ms: u64_of(row.try_get::<i64, _>("stored_at_ms")?),
                },
            );
        }
        Ok(())
    }

    /// Applies one journal. Every statement is in the caller's transaction.
    #[allow(clippy::too_many_lines)]
    async fn apply(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        twinnet_id: &str,
        changes: &[Change],
        next_net_seq: u64,
        next_v4_offset: u32,
    ) -> Result<(), sqlx::Error> {
        for change in changes {
            match change {
                Change::PutDevice(d) => {
                    sqlx::query(
                        "INSERT INTO device (twinnet_id, device_id, identity_id, \
                         identity_public_key, generation, tk_generation, label, version, \
                         membership_epoch, twinnet_addr_v4, twinnet_addr_v6, encoded, revoked, \
                         net_seq, created_at_ms) \
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) \
                         ON CONFLICT (twinnet_id, device_id) DO UPDATE SET \
                         identity_id = EXCLUDED.identity_id, generation = EXCLUDED.generation, \
                         tk_generation = EXCLUDED.tk_generation, label = EXCLUDED.label, \
                         version = EXCLUDED.version, encoded = EXCLUDED.encoded, \
                         revoked = EXCLUDED.revoked, net_seq = EXCLUDED.net_seq",
                    )
                    .bind(twinnet_id)
                    .bind(d.device_id.to_vec())
                    .bind(d.identity_id.to_vec())
                    .bind(d.identity_public_key.clone())
                    .bind(i32::try_from(d.generation).unwrap_or(i32::MAX))
                    .bind(i32::try_from(d.tk_generation).unwrap_or(i32::MAX))
                    .bind(d.label.clone())
                    .bind(i64_of(d.version))
                    .bind(i64_of(d.membership_epoch))
                    .bind(d.twinnet_addr_v4.to_vec())
                    .bind(d.twinnet_addr_v6.to_vec())
                    .bind(d.encoded.clone())
                    .bind(d.revoked)
                    .bind(i64_of(d.net_seq))
                    .bind(i64_of(d.created_at_ms))
                    .execute(&mut **tx)
                    .await?;
                }
                Change::Revoke {
                    device_id,
                    trust_epoch,
                } => {
                    // The revoked set is INSERT-only; the trigger in 0001 refuses
                    // an UPDATE or a DELETE outright, so there is no statement
                    // here that could shrink it.
                    sqlx::query(
                        "INSERT INTO revocation (twinnet_id, device_id, trust_epoch, net_seq, \
                         statement, admitted_at_ms) VALUES ($1,$2,$3,$4,$5,$6) \
                         ON CONFLICT DO NOTHING",
                    )
                    .bind(twinnet_id)
                    .bind(device_id.to_vec())
                    .bind(i64_of(*trust_epoch))
                    .bind(i64_of(next_net_seq))
                    .bind(Vec::<u8>::new())
                    .bind(0_i64)
                    .execute(&mut **tx)
                    .await?;
                    sqlx::query(
                        "UPDATE device SET revoked = TRUE, version = version + 1 \
                         WHERE twinnet_id = $1 AND device_id = $2",
                    )
                    .bind(twinnet_id)
                    .bind(device_id.to_vec())
                    .execute(&mut **tx)
                    .await?;
                }
                Change::PutPairing(p) => {
                    sqlx::query(
                        "INSERT INTO pairing (twinnet_id, pairing_id, state, version, \
                         expires_at_ms, initiator, outcome, failed_attempts) \
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) \
                         ON CONFLICT (twinnet_id, pairing_id) DO UPDATE SET \
                         state = EXCLUDED.state, version = EXCLUDED.version, \
                         outcome = COALESCE(pairing.outcome, EXCLUDED.outcome), \
                         failed_attempts = EXCLUDED.failed_attempts",
                    )
                    .bind(twinnet_id)
                    .bind(p.pairing_id.to_vec())
                    .bind(pairing_state_str(p.state))
                    .bind(i64_of(p.version))
                    .bind(i64_of(p.expires_at_ms))
                    .bind(p.initiator.to_vec())
                    .bind(p.outcome.clone())
                    .bind(i32::try_from(p.failed_attempts).unwrap_or(5))
                    .execute(&mut **tx)
                    .await?;
                }
                Change::PutDocument { doc_type, record } => {
                    sqlx::query(
                        "INSERT INTO state_document (twinnet_id, doc_type, version, \
                         content_digest, octets, net_seq, trust_epoch, issued_at_ms) \
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) \
                         ON CONFLICT (twinnet_id, doc_type) DO UPDATE SET \
                         version = EXCLUDED.version, content_digest = EXCLUDED.content_digest, \
                         octets = EXCLUDED.octets, net_seq = EXCLUDED.net_seq, \
                         trust_epoch = EXCLUDED.trust_epoch, issued_at_ms = EXCLUDED.issued_at_ms",
                    )
                    .bind(twinnet_id)
                    .bind(doc_type.to_wire())
                    .bind(i64_of(record.version))
                    .bind(record.content_digest.to_vec())
                    .bind(record.octets.clone())
                    .bind(i64_of(record.net_seq))
                    .bind(i64_of(record.trust_epoch))
                    .bind(i64_of(record.issued_at_ms))
                    .execute(&mut **tx)
                    .await?;
                }
                Change::PutRouteSet {
                    advertiser,
                    epoch,
                    octets,
                } => {
                    sqlx::query(
                        "INSERT INTO route_set (twinnet_id, advertiser, epoch, octets) \
                         VALUES ($1,$2,$3,$4) \
                         ON CONFLICT (twinnet_id, advertiser) DO UPDATE SET \
                         epoch = EXCLUDED.epoch, octets = EXCLUDED.octets",
                    )
                    .bind(twinnet_id)
                    .bind(advertiser.to_vec())
                    .bind(i64_of(*epoch))
                    .bind(octets.clone())
                    .execute(&mut **tx)
                    .await?;
                }
                Change::PutOffer {
                    offerer,
                    epoch,
                    octets,
                } => {
                    sqlx::query(
                        "INSERT INTO exit_offer (twinnet_id, offerer, epoch, octets) \
                         VALUES ($1,$2,$3,$4) \
                         ON CONFLICT (twinnet_id, offerer) DO UPDATE SET \
                         epoch = EXCLUDED.epoch, octets = EXCLUDED.octets",
                    )
                    .bind(twinnet_id)
                    .bind(offerer.to_vec())
                    .bind(i64_of(*epoch))
                    .bind(octets.clone())
                    .execute(&mut **tx)
                    .await?;
                }
                Change::PutRelayToken(t) => {
                    sqlx::query(
                        "INSERT INTO relay_token (twinnet_id, device_id, epoch, octets, \
                         not_after_ms) VALUES ($1,$2,$3,$4,$5) \
                         ON CONFLICT (twinnet_id, device_id) DO UPDATE SET \
                         epoch = EXCLUDED.epoch, octets = EXCLUDED.octets, \
                         not_after_ms = EXCLUDED.not_after_ms",
                    )
                    .bind(twinnet_id)
                    .bind(t.device_id.to_vec())
                    .bind(i64_of(t.epoch))
                    .bind(t.octets.clone())
                    .bind(i64_of(t.not_after_ms))
                    .execute(&mut **tx)
                    .await?;
                }
                Change::PutIdempotency {
                    device_id,
                    key,
                    record,
                } => {
                    // The dedup record is written in the SAME transaction as the
                    // effect it records. Written afterwards it would be a dual
                    // write, and the crash between the two loses exactly the
                    // record a retry needs.
                    sqlx::query(
                        "INSERT INTO idempotency (twinnet_id, device_id, idempotency_key, \
                         command, response, committed_at_net_seq, stored_at_ms) \
                         VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING",
                    )
                    .bind(twinnet_id)
                    .bind(device_id.to_vec())
                    .bind(key.clone())
                    .bind(record.command.as_str())
                    .bind(record.response.clone())
                    .bind(i64_of(record.committed_at_net_seq))
                    .bind(i64_of(record.stored_at_ms))
                    .execute(&mut **tx)
                    .await?;
                }
                Change::AppendEvent(e) => {
                    sqlx::query(
                        "INSERT INTO event (twinnet_id, net_seq, event_type, \
                         publisher_principal, encoded, committed_at_ms) \
                         VALUES ($1,$2,$3,$4,$5,$6)",
                    )
                    .bind(twinnet_id)
                    .bind(i64_of(e.net_seq))
                    .bind(e.event_type.as_str())
                    .bind(e.publisher.as_str())
                    .bind(e.encoded.clone())
                    .bind(i64_of(e.committed_at_ms))
                    .execute(&mut **tx)
                    .await?;
                }
                Change::AdvanceTrustEpoch(epoch) => {
                    sqlx::query("UPDATE twinnet SET trust_epoch = $2 WHERE twinnet_id = $1")
                        .bind(twinnet_id)
                        .bind(i64_of(*epoch))
                        .execute(&mut **tx)
                        .await?;
                }
                Change::AdvancePolicyVersion(version) => {
                    sqlx::query("UPDATE twinnet SET policy_version = $2 WHERE twinnet_id = $1")
                        .bind(twinnet_id)
                        .bind(i64_of(*version))
                        .execute(&mut **tx)
                        .await?;
                }
            }
        }

        // The counter, written in the same transaction that allocated from it.
        sqlx::query(
            "UPDATE twinnet SET next_net_seq = $2, next_v4_offset = $3 WHERE twinnet_id = $1",
        )
        .bind(twinnet_id)
        .bind(i64_of(next_net_seq))
        .bind(i64::from(next_v4_offset))
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
}

impl ControlStore for PgStore {
    fn execute<'a>(
        &'a self,
        request: Request<'a>,
    ) -> BoxFuture<'a, Result<Committed, ServiceError>> {
        Box::pin(async move {
            let mut db = self.pool.begin().await.map_err(store_error)?;

            // Create the TwinNet row on first contact, then take the write lock.
            // Both are inside the transaction, so two concurrent first contacts
            // resolve to one row rather than to a duplicate-key error the caller
            // would see as a protocol failure.
            sqlx::query(
                "INSERT INTO twinnet (twinnet_id, shard_epoch, lease_holder) VALUES ($1,$2,$3) \
                 ON CONFLICT (twinnet_id) DO NOTHING",
            )
            .bind(request.twinnet_id)
            .bind(i64_of(self.shard_epoch))
            .bind(self.holder.clone())
            .execute(&mut *db)
            .await
            .map_err(store_error)?;

            sqlx::query("SELECT twinnet_id FROM twinnet WHERE twinnet_id = $1 FOR UPDATE")
                .bind(request.twinnet_id)
                .fetch_one(&mut *db)
                .await
                .map_err(store_error)?;

            let mut state = Self::load(&mut db, request.twinnet_id)
                .await
                .map_err(store_error)?;
            Self::load_dedup(&mut db, request.twinnet_id, request.caller, &mut state)
                .await
                .map_err(store_error)?;

            let mut tx = NetTx::open(
                state,
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

            // The budget is per-TwinNet and per-process here. A multi-front-end
            // deployment needs it in the database; recorded in README.md §10.
            let mut budget = WriteBudget::new(EVENT_RATE_SUSTAINED, EVENT_RATE_BURST, request.now);

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

            Self::apply(
                &mut db,
                request.twinnet_id,
                journal.changes(),
                new_state.next_net_seq,
                new_state.next_v4_offset,
            )
            .await
            .map_err(store_error)?;

            db.commit().await.map_err(store_error)?;

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
            let floor: Option<i64> =
                sqlx::query_scalar("SELECT retained_from FROM twinnet WHERE twinnet_id = $1")
                    .bind(twinnet_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(store_error)?;
            let Some(floor) = floor else {
                return Ok(Vec::new());
            };
            let floor = u64_of(floor);
            if from_net_seq != 0 && from_net_seq + 1 < floor {
                return Err(codes::cursor_too_old(from_net_seq, floor));
            }
            let rows = sqlx::query(
                "SELECT net_seq, event_type, publisher_principal, encoded, committed_at_ms \
                 FROM event WHERE twinnet_id = $1 AND net_seq > $2 ORDER BY net_seq LIMIT $3",
            )
            .bind(twinnet_id)
            .bind(i64_of(from_net_seq))
            .bind(i64::try_from(max).unwrap_or(i64::MAX))
            .fetch_all(&self.pool)
            .await
            .map_err(store_error)?;

            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                let event_type = row
                    .try_get::<String, _>("event_type")
                    .map_err(store_error)?;
                let publisher = row
                    .try_get::<String, _>("publisher_principal")
                    .map_err(store_error)?;
                let Some(kind) = event_kind_of(&event_type) else {
                    // A row this build does not recognise. Skipping it silently
                    // would be the omission N-8 forbids, so it is an error.
                    return Err(codes::wrong_publisher("unknown", "unspecified"));
                };
                if publisher != Publisher::CoordinationService.as_str() {
                    return Err(codes::wrong_publisher(kind.as_str(), "originating_device"));
                }
                out.push(StoredEvent {
                    net_seq: u64_of(row.try_get::<i64, _>("net_seq").map_err(store_error)?),
                    event_type: kind,
                    publisher: Publisher::CoordinationService,
                    encoded: row.try_get("encoded").map_err(store_error)?,
                    committed_at_ms: u64_of(
                        row.try_get::<i64, _>("committed_at_ms")
                            .map_err(store_error)?,
                    ),
                });
            }
            Ok(out)
        })
    }

    fn head<'a>(&'a self, twinnet_id: &'a str) -> BoxFuture<'a, Result<u64, ServiceError>> {
        Box::pin(async move {
            let next: Option<i64> =
                sqlx::query_scalar("SELECT next_net_seq FROM twinnet WHERE twinnet_id = $1")
                    .bind(twinnet_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(store_error)?;
            Ok(next.map_or(0, |n| u64_of(n).saturating_sub(1)))
        })
    }

    fn trust_epoch<'a>(&'a self, twinnet_id: &'a str) -> BoxFuture<'a, Result<u64, ServiceError>> {
        Box::pin(async move {
            let epoch: Option<i64> =
                sqlx::query_scalar("SELECT trust_epoch FROM twinnet WHERE twinnet_id = $1")
                    .bind(twinnet_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(store_error)?;
            Ok(epoch.map_or(0, u64_of))
        })
    }

    fn probe(&self) -> BoxFuture<'_, Result<StoreHealth, ServiceError>> {
        Box::pin(async move {
            sqlx::query("SELECT 1")
                .fetch_one(&self.pool)
                .await
                .map_err(store_error)?;
            // The second half of infra/README.md §5's readiness for this
            // service: is the write lease obtainable, or knowingly held
            // elsewhere? A row whose lease_holder is another process at an equal
            // or higher shard_epoch is "knowingly held elsewhere" and is not an
            // error; one held by nobody is obtainable.
            let held: Option<String> = sqlx::query_scalar(
                "SELECT lease_holder FROM twinnet WHERE lease_holder IS NOT NULL \
                 AND shard_epoch >= $1 LIMIT 1",
            )
            .bind(i64_of(self.shard_epoch))
            .fetch_optional(&self.pool)
            .await
            .map_err(store_error)?;
            Ok(StoreHealth {
                reachable: true,
                lease_held: held.as_deref().is_none_or(|h| h == self.holder),
            })
        })
    }
}

/// Every store failure becomes a registered code. Never a raw driver error.
fn store_error(err: sqlx::Error) -> ServiceError {
    // The driver's message can name a column, a constraint and — for a
    // connection error — a host and a user. `ServiceError` has no message field
    // and never encodes one, so the detail stays in `source_detail()` for a log
    // line and nothing reaches the wire (CF-4).
    ServiceError::new(
        twinvpn_types::codes::CONTROL_WRITE_LEADER_UNAVAILABLE,
        crate::COMPONENT,
    )
    .source(err)
    .build()
}

fn u64_of(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn i64_of(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn key32(v: &[u8]) -> [u8; 32] {
    <[u8; 32]>::try_from(v).unwrap_or([0u8; 32])
}

fn key16(v: &[u8]) -> PairingKey {
    <[u8; 16]>::try_from(v).unwrap_or([0u8; 16])
}

fn fixed4(v: &[u8]) -> [u8; 4] {
    <[u8; 4]>::try_from(v).unwrap_or([0u8; 4])
}

fn fixed16(v: &[u8]) -> [u8; 16] {
    <[u8; 16]>::try_from(v).unwrap_or([0u8; 16])
}

fn pairing_state(s: &str) -> PairingState {
    match s {
        "completed" => PairingState::Completed,
        "rejected" => PairingState::Rejected,
        "cancelled" => PairingState::Cancelled,
        "expired" => PairingState::Expired,
        "revoked" => PairingState::Revoked,
        _ => PairingState::Pending,
    }
}

const fn pairing_state_str(s: PairingState) -> &'static str {
    match s {
        PairingState::Pending => "pending",
        PairingState::Completed => "completed",
        PairingState::Rejected => "rejected",
        PairingState::Cancelled => "cancelled",
        PairingState::Expired => "expired",
        PairingState::Revoked => "revoked",
    }
}

fn command_of(name: &str) -> Option<crate::Command> {
    crate::Command::ALL.into_iter().find(|c| c.as_str() == name)
}

fn event_kind_of(name: &str) -> Option<EventKind> {
    EventKind::ALL.into_iter().find(|k| k.as_str() == name)
}

#[cfg(test)]
mod tests {
    use super::{command_of, event_kind_of, pairing_state, pairing_state_str};
    use crate::model::PairingState;
    use crate::Command;

    #[test]
    fn every_command_and_event_name_round_trips_through_the_column() {
        // The text columns are the schema's vocabulary. A name that does not
        // round trip is a row this build writes and cannot read back.
        for c in Command::ALL {
            assert_eq!(command_of(c.as_str()), Some(c));
        }
        for k in crate::EventKind::ALL {
            assert_eq!(event_kind_of(k.as_str()), Some(k));
        }
        assert!(command_of("ResumeSession").is_none());
    }

    #[test]
    fn every_pairing_state_round_trips_and_matches_the_check_constraint() {
        for s in [
            PairingState::Pending,
            PairingState::Completed,
            PairingState::Rejected,
            PairingState::Cancelled,
            PairingState::Expired,
            PairingState::Revoked,
        ] {
            assert_eq!(pairing_state(pairing_state_str(s)), s);
        }
        // migrations/0003 CHECK (state IN (...)) lists exactly these six.
        let sql = include_str!("../../migrations/0003_ceremonies_documents_and_dedup.sql");
        for s in [
            "pending",
            "completed",
            "rejected",
            "cancelled",
            "expired",
            "revoked",
        ] {
            assert!(
                sql.contains(&format!("'{s}'")),
                "{s} missing from the CHECK"
            );
        }
    }

    #[test]
    fn the_durable_event_check_constraint_lists_exactly_the_durable_kinds() {
        // Layer 3 of sole-publisher/durability enforcement is only as good as
        // its list. If a durable event type is missing from the CHECK, the
        // database refuses a legitimate append; if an EPHEMERAL one is present,
        // presence could reach the log.
        let sql = include_str!("../../migrations/0002_event_log.sql");
        for k in crate::EventKind::ALL {
            let quoted = format!("'{}'", k.as_str());
            let listed = sql.contains(&quoted);
            let durable = k.durability() == crate::Durability::Durable;
            assert_eq!(
                listed,
                durable,
                "{} is {} in the CHECK but {} in the table",
                k.as_str(),
                if listed { "listed" } else { "absent" },
                if durable { "durable" } else { "ephemeral" }
            );
        }
    }
}
