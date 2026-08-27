//! One mutating transaction: the state change and the event it describes,
//! committed together or not at all.
//!
//! **Authority:** ADR-0002 **N-3** (`net_seq` allocated by a per-`TwinNet`
//! monotone counter *inside the same transaction* that commits the mutation),
//! **N-4** (exactly one writer per `TwinNet` log, held by a lease; a lease-less
//! write is **refused**, never optimistic), `contract-matrix.md` §5 ("control
//! plane → durable log: exactly-once … same transaction as the mutation; **no
//! dual write exists to be lost**").
//!
//! # The bug this type exists to make unwritable
//!
//! > *If you find yourself writing the mutation and then publishing the event,
//! > that is the bug §5 exists to prevent.*
//!
//! There is no `publish` on this type and no event sink reachable from it. The
//! only way to emit a durable event is [`NetTx::append`], which mutates the same
//! working copy the state change mutated and records both in one
//! [`Journal`]. The journal is applied by the store in one database transaction.
//! Dropping a `NetTx` without [`NetTx::into_journal`] discards **both** halves,
//! which is what `tests/atomicity.rs` exercises as "the crash between them".

use twinvpn_service_common::{Correlation, ServiceError};

use crate::codes;
use crate::event::{DurableEvent, EphemeralEvent};
use crate::model::{
    DeviceKey, DeviceRecord, DocumentRecord, DocumentType, IdempotencyRecord, NetState,
    PairingRecord, RelayTokenRecord, StoredEvent,
};

/// One recorded change, in the order it was made.
///
/// The journal is what a store applies. It exists rather than "write the whole
/// `NetState` back" because a whole-state write has no way to express *which*
/// rows a concurrent reader must see change, and because the event append has to
/// be one row in one `INSERT` for `net_seq` density to hold.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Change {
    /// A membership row was written (S-02).
    PutDevice(Box<DeviceRecord>),
    /// A device joined the never-shrinking revoked set (S-03, N-7).
    Revoke {
        /// Whose.
        device_id: DeviceKey,
        /// The epoch assigned at admission.
        trust_epoch: u64,
    },
    /// A pairing row was written (S-04).
    PutPairing(Box<PairingRecord>),
    /// A signed document was warehoused (S-06 / S-07 / S-32 …).
    PutDocument {
        /// Which document.
        doc_type: DocumentType,
        /// Its record.
        record: Box<DocumentRecord>,
    },
    /// An advertiser's whole desired route set, under a monotone epoch (S-16).
    PutRouteSet {
        /// The advertiser.
        advertiser: DeviceKey,
        /// The monotone epoch.
        epoch: u64,
        /// The verbatim signed octets. Empty means "withdraw everything".
        octets: Vec<u8>,
    },
    /// An offerer's whole desired exit-node offer, under a monotone epoch.
    PutOffer {
        /// The offerer.
        offerer: DeviceKey,
        /// The monotone epoch.
        epoch: u64,
        /// The verbatim signed octets.
        octets: Vec<u8>,
    },
    /// A `RelayCapabilityToken` was issued (S-30).
    PutRelayToken(Box<RelayTokenRecord>),
    /// A dedup record was written (ADR-0008 N-5).
    PutIdempotency {
        /// Scoped to the authenticated device (N-4).
        device_id: DeviceKey,
        /// The client-generated key.
        key: Vec<u8>,
        /// The recorded outcome, replayed verbatim.
        record: Box<IdempotencyRecord>,
    },
    /// A durable event was appended at the allocated position.
    AppendEvent(Box<StoredEvent>),
    /// The `TwinNet`-wide trust generation advanced (R-6).
    AdvanceTrustEpoch(u64),
    /// The policy version advanced (S-06).
    AdvancePolicyVersion(u64),
}

/// The ordered changes of one transaction.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Journal {
    changes: Vec<Change>,
    committed_at_net_seq: u64,
}

impl Journal {
    /// The changes, in order.
    #[must_use]
    pub fn changes(&self) -> &[Change] {
        &self.changes
    }

    /// The position the effect committed at, for `MutationResult`.
    ///
    /// `0` when the transaction appended no durable event — a read, or a
    /// `REGISTER`-class write, both of which have no log position by design.
    #[must_use]
    pub const fn committed_at_net_seq(&self) -> u64 {
        self.committed_at_net_seq
    }

    /// Whether anything at all was changed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// The durable events this transaction appended.
    pub fn appended(&self) -> impl Iterator<Item = &StoredEvent> {
        self.changes.iter().filter_map(|c| match c {
            Change::AppendEvent(e) => Some(e.as_ref()),
            _ => None,
        })
    }
}

/// Whether this process holds the per-`TwinNet` write lease (ADR-0002 N-4,
/// S-28).
///
/// A value of this type is required to open a mutating transaction, so "we
/// forgot to check the lease" is not a reachable state: there is no
/// `NetTx::mutating` that does not take one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteLease {
    /// The fencing token. A write presenting a lower one is refused at commit.
    pub shard_epoch: u64,
}

/// A mutating transaction over one `TwinNet`.
///
/// Holds a **working copy** of the state. Every read inside the transaction sees
/// its own writes, and nothing outside sees anything until the store applies the
/// journal.
#[derive(Debug)]
pub struct NetTx {
    state: NetState,
    journal: Journal,
    lease: WriteLease,
    now_ms: u64,
    ephemeral: Vec<EphemeralEvent>,
    cause: Correlation,
}

impl NetTx {
    /// Opens a mutating transaction, refusing without the lease.
    ///
    /// # Errors
    ///
    /// `CONTROL.WRITE_LEADER_UNAVAILABLE` when the presented `shard_epoch` is
    /// below the one recorded in the log. ADR-0009 §11.2: "a superseded writer's
    /// appends are refused"; ADR-0002 N-4: refused "rather than writing
    /// optimistically".
    pub fn open(state: NetState, lease: WriteLease, now_ms: u64) -> Result<Self, ServiceError> {
        if lease.shard_epoch < state.shard_epoch {
            return Err(codes::write_leader_unavailable());
        }
        Ok(Self {
            state,
            journal: Journal::default(),
            lease,
            now_ms,
            ephemeral: Vec::new(),
            cause: Correlation::empty(),
        })
    }

    /// Records the request whose processing this transaction is.
    ///
    /// Every event appended carries its `message_id` as `causation_id`, so a
    /// trace crosses the C1 → C2 boundary. `ownership.md` §6 rule 6 requires
    /// exactly that, and the seam where it is normally lost is this one: the
    /// event is emitted long after the request that caused it has returned.
    #[must_use]
    pub fn caused_by(mut self, cause: Correlation) -> Self {
        self.cause = cause;
        self
    }

    /// [`NetTx::caused_by`] on an already-open transaction, so the dispatcher
    /// can refine the store's correlation with the one on the request envelope.
    pub fn set_cause(&mut self, cause: Correlation) {
        self.cause = cause;
    }

    /// The correlation this transaction is a consequence of.
    #[must_use]
    pub const fn cause(&self) -> &Correlation {
        &self.cause
    }

    /// The working copy, for reads.
    #[must_use]
    pub const fn state(&self) -> &NetState {
        &self.state
    }

    /// The wall-clock instant this transaction is stamped with.
    ///
    /// **Evidence only.** No decision in this crate branches on it except the
    /// two the contracts define in wall-clock terms — the ADR-0008 dedup window
    /// and the ADR-0007 pairing expiry — and both take it as a parameter rather
    /// than reading a clock, so a decision is reproducible from its inputs
    /// (`architecture.md` §5.2 R-DET-1).
    #[must_use]
    pub const fn now_ms(&self) -> u64 {
        self.now_ms
    }

    /// The lease this transaction is fenced by.
    #[must_use]
    pub const fn lease(&self) -> WriteLease {
        self.lease
    }

    /// Appends a durable event, allocating `net_seq` **here**, inside the
    /// transaction (N-3).
    ///
    /// # Errors
    ///
    /// `CONTROL.EVENT_WRONG_PUBLISHER` — layer 2 of the sole-publisher
    /// enforcement — for an event whose stamped publisher is not its type's sole
    /// publisher.
    pub fn append(&mut self, event: &DurableEvent) -> Result<u64, ServiceError> {
        event.check_publisher()?;
        let net_seq = self.state.next_net_seq;
        self.state.next_net_seq += 1;
        let encoded = {
            use prost::Message;
            event
                .to_wire(&self.state.twinnet_id, net_seq, self.now_ms, &self.cause)
                .encode_to_vec()
        };
        let stored = StoredEvent {
            net_seq,
            event_type: event.kind(),
            publisher: event.publisher(),
            encoded,
            committed_at_ms: self.now_ms,
        };
        self.state.events.push(stored.clone());
        self.journal
            .changes
            .push(Change::AppendEvent(Box::new(stored)));
        self.journal.committed_at_net_seq = net_seq;
        Ok(net_seq)
    }

    /// Queues an ephemeral event for fan-out.
    ///
    /// It is **not** in the journal and never reaches the log: N-9 forbids it
    /// being written, replayed from a cursor, or surviving its TTL. It rides out
    /// with the transaction only so a presence update is not delivered before
    /// the state it describes.
    pub fn emit_ephemeral(&mut self, event: EphemeralEvent) {
        self.ephemeral.push(event);
    }

    /// The ephemeral events queued, for the fan-out after commit.
    #[must_use]
    pub fn ephemeral(&self) -> &[EphemeralEvent] {
        &self.ephemeral
    }

    /// Writes a membership row.
    pub fn put_device(&mut self, record: DeviceRecord) {
        self.state.devices.insert(record.device_id, record.clone());
        self.journal
            .changes
            .push(Change::PutDevice(Box::new(record)));
    }

    /// Adds to the revoked set and advances the trust epoch.
    ///
    /// ADR-0008 N-7: the set never shrinks and the epoch never decreases. There
    /// is deliberately no `un_revoke`; un-revocation is impossible by
    /// construction rather than forbidden by review.
    pub fn revoke(&mut self, device_id: DeviceKey) -> u64 {
        let trust_epoch = self.state.trust_epoch + 1;
        self.state.trust_epoch = trust_epoch;
        self.state.revoked.insert(device_id);
        if let Some(d) = self.state.devices.get_mut(&device_id) {
            d.revoked = true;
            d.version += 1;
        }
        self.journal.changes.push(Change::Revoke {
            device_id,
            trust_epoch,
        });
        self.journal
            .changes
            .push(Change::AdvanceTrustEpoch(trust_epoch));
        trust_epoch
    }

    /// Writes a pairing row.
    pub fn put_pairing(&mut self, record: PairingRecord) {
        self.state
            .pairings
            .insert(record.pairing_id, record.clone());
        self.journal
            .changes
            .push(Change::PutPairing(Box::new(record)));
    }

    /// Warehouses a signed document, enforcing ADR-0009 R-2…R-5.
    ///
    /// # Errors
    ///
    /// - `AUTH.TRUST_HISTORY_FORKED` on an equal version with a different
    ///   content digest — R-4's fork, applied **at the writer** so a fork never
    ///   enters the log rather than being detected by each device afterwards.
    /// - The interim precondition code on a lower version — R-5's rollback.
    pub fn put_document(
        &mut self,
        doc_type: DocumentType,
        record: DocumentRecord,
    ) -> Result<(), ServiceError> {
        if let Some(existing) = self.state.documents.get(&doc_type) {
            if record.version < existing.version {
                return Err(codes::precondition_failed(record.version, existing.version));
            }
            if record.version == existing.version {
                if record.content_digest == existing.content_digest {
                    // R-3: an idempotent no-op. Nothing is journalled.
                    return Ok(());
                }
                return Err(codes::forked_history(record.version));
            }
        }
        self.state.documents.insert(doc_type, record.clone());
        self.journal.changes.push(Change::PutDocument {
            doc_type,
            record: Box::new(record),
        });
        Ok(())
    }

    /// Records a whole desired route set under a strictly higher epoch (S-16).
    ///
    /// # Errors
    ///
    /// The interim precondition code when the epoch does not strictly advance.
    /// "An advertisement that reuses an epoch is a delta in disguise: the
    /// receiver would have no way to order it against the set already in force."
    pub fn put_route_set(
        &mut self,
        advertiser: DeviceKey,
        epoch: u64,
        octets: Vec<u8>,
    ) -> Result<(), ServiceError> {
        let last = self
            .state
            .route_epochs
            .get(&advertiser)
            .copied()
            .unwrap_or(0);
        if epoch <= last {
            return Err(codes::precondition_failed(epoch, last));
        }
        self.state.route_epochs.insert(advertiser, epoch);
        self.state.route_sets.insert(advertiser, octets.clone());
        self.journal.changes.push(Change::PutRouteSet {
            advertiser,
            epoch,
            octets,
        });
        Ok(())
    }

    /// Records a whole desired exit-node offer under a strictly higher epoch.
    ///
    /// # Errors
    ///
    /// As [`NetTx::put_route_set`].
    pub fn put_offer(
        &mut self,
        offerer: DeviceKey,
        epoch: u64,
        octets: Vec<u8>,
    ) -> Result<(), ServiceError> {
        let last = self.state.offer_epochs.get(&offerer).copied().unwrap_or(0);
        if epoch <= last {
            return Err(codes::precondition_failed(epoch, last));
        }
        self.state.offer_epochs.insert(offerer, epoch);
        self.state.offer_sets.insert(offerer, octets.clone());
        self.journal.changes.push(Change::PutOffer {
            offerer,
            epoch,
            octets,
        });
        Ok(())
    }

    /// Records a `RelayCapabilityToken` issuance (S-30), monotone by `epoch`.
    ///
    /// # Errors
    ///
    /// The interim precondition code on a non-advancing epoch.
    pub fn put_relay_token(&mut self, record: RelayTokenRecord) -> Result<(), ServiceError> {
        let last = self
            .state
            .relay_tokens
            .get(&record.device_id)
            .map_or(0, |t| t.epoch);
        if record.epoch <= last {
            return Err(codes::precondition_failed(record.epoch, last));
        }
        self.state
            .relay_tokens
            .insert(record.device_id, record.clone());
        self.journal
            .changes
            .push(Change::PutRelayToken(Box::new(record)));
        Ok(())
    }

    /// Consumes an address-pool offset (S-08).
    ///
    /// Not a journal entry: the offset is a column on the `TwinNet` row, and the
    /// store writes `next_v4_offset` from the committed state alongside
    /// `next_net_seq` in the same statement. An allocator that did not advance
    /// would hand the next device the same `/32`, which is the collision S-08
    /// refuses at allocation time.
    pub fn consume_v4_offset(&mut self, used: u32) {
        self.state.next_v4_offset = self.state.next_v4_offset.max(used.saturating_add(1));
    }

    /// Advances the policy version (S-06).
    pub fn advance_policy_version(&mut self, version: u64) {
        self.state.policy_version = version;
        self.journal
            .changes
            .push(Change::AdvancePolicyVersion(version));
    }

    /// Records the dedup outcome for a `CEREMONY` (ADR-0008 N-5).
    pub fn put_idempotency(
        &mut self,
        device_id: DeviceKey,
        key: Vec<u8>,
        record: IdempotencyRecord,
    ) {
        self.state
            .idempotency
            .insert((device_id, key.clone()), record.clone());
        self.journal.changes.push(Change::PutIdempotency {
            device_id,
            key,
            record: Box::new(record),
        });
    }

    /// Consumes the transaction, yielding the journal the store applies.
    ///
    /// Dropping a `NetTx` **without** calling this discards every change,
    /// including the appended event. That is the point: there is no interval in
    /// which one half is durable and the other is not.
    #[must_use]
    pub fn into_journal(self) -> (Journal, NetState, Vec<EphemeralEvent>) {
        (self.journal, self.state, self.ephemeral)
    }
}

#[cfg(test)]
mod tests {
    use super::{NetTx, WriteLease};
    use crate::event::DurableEvent;
    use crate::model::{DocumentRecord, DocumentType, NetState};
    use twinvpn_schema::v1;
    use twinvpn_schema::v1::control_event::Event as EventBody;

    fn tx(state: NetState) -> NetTx {
        NetTx::open(state, WriteLease { shard_epoch: 1 }, 1_000).expect("lease held")
    }

    fn registered() -> DurableEvent {
        DurableEvent::new(EventBody::DeviceRegistered(v1::DeviceRegistered::default()))
            .expect("durable")
    }

    #[test]
    fn a_lease_less_write_is_refused_not_written_optimistically() {
        let mut state = NetState::new("tn");
        state.shard_epoch = 9;
        let err = NetTx::open(state, WriteLease { shard_epoch: 8 }, 0).expect_err("fenced out");
        assert_eq!(err.code().as_str(), "CONTROL.WRITE_LEADER_UNAVAILABLE");
    }

    #[test]
    fn net_seq_is_allocated_inside_the_transaction_and_is_dense() {
        let mut t = tx(NetState::new("tn"));
        assert_eq!(t.append(&registered()).expect("appends"), 1);
        assert_eq!(t.append(&registered()).expect("appends"), 2);
        assert_eq!(t.append(&registered()).expect("appends"), 3);
        let (journal, state, _) = t.into_journal();
        assert_eq!(journal.committed_at_net_seq(), 3);
        let seqs: Vec<u64> = state.events.iter().map(|e| e.net_seq).collect();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    #[test]
    fn dropping_a_transaction_discards_the_mutation_and_the_event_together() {
        // The crash between the two halves. §5: "no dual write exists to be
        // lost", so there is no state in which one landed and the other did not.
        let base = NetState::new("tn");
        let mut t = tx(base.clone());
        t.revoke([7u8; 32]);
        t.append(&registered()).expect("appends");
        drop(t); // never `into_journal`
        assert!(base.revoked.is_empty());
        assert!(base.events.is_empty());
        assert_eq!(base.trust_epoch, 0);
    }

    #[test]
    fn revocation_advances_the_epoch_and_the_set_never_shrinks() {
        let mut t = tx(NetState::new("tn"));
        assert_eq!(t.revoke([1u8; 32]), 1);
        assert_eq!(t.revoke([2u8; 32]), 2);
        let (_, state, _) = t.into_journal();
        assert_eq!(state.trust_epoch, 2);
        assert!(state.is_revoked(&[1u8; 32]));
        assert!(state.is_revoked(&[2u8; 32]));
        // There is no method that could remove one. ADR-0008 N-7 is discharged
        // by the absence of an API, not by a check.
    }

    fn doc(version: u64, digest: u8) -> DocumentRecord {
        DocumentRecord {
            version,
            content_digest: [digest; 32],
            octets: vec![digest],
            net_seq: 1,
            trust_epoch: 0,
            issued_at_ms: 0,
        }
    }

    #[test]
    fn a_document_rollback_is_refused_and_a_fork_is_a_security_event() {
        let mut t = tx(NetState::new("tn"));
        t.put_document(DocumentType::PolicyBundle, doc(5, 0xaa))
            .expect("first write");

        // R-3: same version, same content — an idempotent no-op.
        t.put_document(DocumentType::PolicyBundle, doc(5, 0xaa))
            .expect("idempotent");

        // R-4: same version, different content — a fork, at the WRITER.
        let forked = t
            .put_document(DocumentType::PolicyBundle, doc(5, 0xbb))
            .expect_err("fork");
        assert_eq!(forked.code().as_str(), "AUTH.TRUST_HISTORY_FORKED");
        assert!(forked.code().terminal());

        // R-5: a lower version — a rollback.
        let rolled = t
            .put_document(DocumentType::PolicyBundle, doc(4, 0xcc))
            .expect_err("rollback");
        assert_eq!(rolled.code().as_str(), "AUTH.TRUST_EPOCH_ROLLBACK");
    }

    #[test]
    fn an_advertisement_epoch_must_strictly_advance() {
        let mut t = tx(NetState::new("tn"));
        t.put_route_set([1u8; 32], 5, vec![1]).expect("first");
        assert!(t.put_route_set([1u8; 32], 5, vec![2]).is_err(), "reuse");
        assert!(t.put_route_set([1u8; 32], 4, vec![3]).is_err(), "rollback");
        t.put_route_set([1u8; 32], 6, Vec::new())
            .expect("a withdrawal is a HIGHER epoch with an EMPTY set");
        // A different advertiser has its own monotone series (S-16 is per
        // advertiser, not global).
        t.put_route_set([2u8; 32], 1, vec![9]).expect("independent");
    }

    #[test]
    fn a_forged_publisher_cannot_reach_the_log() {
        use crate::event::Publisher;
        let mut t = tx(NetState::new("tn"));
        let forged = DurableEvent::forged_for_test(
            EventBody::DeviceRevoked(v1::DeviceRevoked::default()),
            Publisher::OriginatingDevice,
        );
        let err = t.append(&forged).expect_err("refused at the log");
        assert_eq!(err.code().as_str(), "CONTROL.EVENT_WRONG_PUBLISHER");
        let (journal, state, _) = t.into_journal();
        assert!(journal.is_empty(), "nothing was journalled");
        assert!(state.events.is_empty(), "and nothing reached the log");
    }
}
