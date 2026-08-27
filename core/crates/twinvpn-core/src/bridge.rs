//! [`StoreBridge`] — the single owner of `twinvpn_store::Store`, and the thing
//! that makes a queued write durable.
//!
//! **Authority:** [ADR-0018](../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! CB-7 and §11.7 CD-I5; [ADR-0009](../../../../docs/adr/ADR-0009-state-consistency.md)
//! R-9 (the high-water mark is durable **before** the document it admits is acted
//! on); `twinvpn_store`'s ST-12b multi-key commit and ST-23 commit order.
//!
//! # One owner, on purpose
//!
//! `twinvpn_store::Store::open` takes a single-opener lock and `commit` takes
//! `&mut self`. Both facts say the same thing: there is exactly one writer. This
//! type is it. Everything else in the core reaches the vault through
//! [`crate::planes`]'s two one-directional ports.
//!
//! # Flush is a checkpoint, not a background sweep
//!
//! [`StoreBridge::flush`] drains the pending queue into **one**
//! `twinvpn_store::Transaction` and commits it. One transaction, because ST-12b
//! is explicit about what a per-key write costs: *"if the `TrustedPeer` record
//! commits and the floor advance does not, the device admits a peer under an
//! epoch its floor does not reflect; reversed, it refuses a peer it should
//! accept."*
//!
//! The composition root calls it at the points R-9 names — after admitting a
//! verified document and **before** acting on it — rather than on a timer, so
//! "durable before acted on" is an ordering the caller can see rather than a race
//! against a sweeper.

use twinvpn_types::Identifier as _;

use twinvpn_store::{FloorId, Namespace, RecordKey, Store, StoreError, Transaction};

use crate::planes::{PendingWrite, Shared};

/// The single owner of the vault.
pub struct StoreBridge {
    store: Store,
    shared: Shared,
    /// Monotone per-record sequence, so ST-13's `rec_seq` advances rather than
    /// being invented per write.
    rec_seq: u64,
    flushes: u64,
}

impl StoreBridge {
    /// Takes ownership of an opened store.
    #[must_use]
    pub fn new(store: Store, shared: Shared) -> Self {
        let rec_seq = store.store_seq();
        Self {
            store,
            shared,
            rec_seq,
            flushes: 0,
        }
    }

    /// The opened store's ST-24 outcome, for `CoreBuildIdentity` and the bundle.
    #[must_use]
    pub fn outcome(&self) -> &twinvpn_store::OpenOutcome {
        self.store.outcome()
    }

    /// How many flushes have run. Observability, not decoration: a bridge that
    /// has never flushed is a core whose control-plane writes are all still in
    /// memory, and that is a fact worth being able to assert.
    #[must_use]
    pub const fn flushes(&self) -> u64 {
        self.flushes
    }

    /// Drains the pending queue into one durable transaction.
    ///
    /// Returns how many writes were committed. A refusal — the monotone floor
    /// declining an advance — is recorded on the shared state where the data
    /// plane can see it, because ADR-0008 §7.1 makes that refusal a **security
    /// control** rather than an error to retry around.
    ///
    /// # Errors
    ///
    /// [`StoreError`] from the underlying commit. On error the queue is **left
    /// intact**, so a transient store failure does not lose the writes; a caller
    /// that retries converges.
    pub async fn flush(&mut self) -> Result<usize, StoreError> {
        let pending: Vec<PendingWrite> = {
            let Ok(state) = self.shared.lock() else {
                return Err(StoreError::CryptoInvariant {
                    invariant: "the bridge state lock is not poisoned",
                });
            };
            state.pending_snapshot()
        };
        if pending.is_empty() {
            return Ok(0);
        }

        let mut tx = Transaction::new();
        let count = pending.len();
        for write in &pending {
            self.rec_seq += 1;
            tx = self.stage(tx, write)?;
        }

        match self.store.commit(tx).await {
            Ok(_proposal) => {
                if let Ok(mut state) = self.shared.lock() {
                    state.clear_pending(count);
                    state.set_refusal(None);
                }
                self.flushes += 1;
                Ok(count)
            }
            Err(e @ StoreError::FloorWouldDecrease { .. }) => {
                // Not a retry: a monotone floor refusing an advance is the
                // anti-rollback control working. The queue is dropped, because
                // re-offering the same refused value forever is a loop, and the
                // refusal is published so the data plane can act on it.
                if let Ok(mut state) = self.shared.lock() {
                    state.clear_pending(count);
                    state.set_refusal(Some(e.to_string()));
                }
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// Releases the single-opener lock. `ownership.md` §6 rule 7.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the lock file cannot be removed.
    pub fn close(&self) -> Result<(), StoreError> {
        self.store.close()
    }

    fn stage(&self, tx: Transaction, write: &PendingWrite) -> Result<Transaction, StoreError> {
        Ok(match write {
            PendingWrite::Cursor { twinnet, net_seq } => tx.write(
                RecordKey::new(Namespace::Doc, &format!("cursor.{}", twinnet.as_str()))?,
                net_seq.to_be_bytes().to_vec(),
                false,
                self.rec_seq,
            ),
            PendingWrite::TrustEpoch { twinnet, epoch } => {
                // The floor and the record advance in the SAME transaction.
                // ST-12b's worked failure is exactly this pair coming apart.
                tx.write(
                    RecordKey::new(Namespace::Trust, &format!("epoch.{}", twinnet.as_str()))?,
                    epoch.to_be_bytes().to_vec(),
                    false,
                    self.rec_seq,
                )
                .advance_floor(FloorId::TrustEpoch, *epoch)
            }
            PendingWrite::Document {
                twinnet,
                doc_type,
                version,
                payload,
                ..
            } => tx
                .advance_floor(FloorId::DocVersion(doc_type), *version)
                .write(
                    RecordKey::new(Namespace::Doc, &format!("{doc_type}.{}", twinnet.as_str()))?,
                    // `verbatim_signed = true`: ST-13's rule that the value is
                    // the RECEIVED OCTETS of a signed statement and must be
                    // stored unchanged. W-4 is the same rule on the wire.
                    payload.clone(),
                    true,
                    self.rec_seq,
                )
                .write(
                    RecordKey::new(
                        Namespace::Doc,
                        &format!("{doc_type}.{}.version", twinnet.as_str()),
                    )?,
                    version.to_be_bytes().to_vec(),
                    false,
                    self.rec_seq,
                ),
            PendingWrite::Peer {
                twinnet,
                device_id,
                record,
            } => tx.write(
                RecordKey::new(
                    Namespace::Peer,
                    &format!("{}.{}", twinnet.as_str(), device_id.fingerprint()),
                )?,
                encode_peer(record),
                false,
                self.rec_seq,
            ),
            PendingWrite::PeerRemoved {
                twinnet, device_id, ..
            } => tx.delete(RecordKey::new(
                Namespace::Peer,
                &format!("{}.{}", twinnet.as_str(), device_id.fingerprint()),
            )?),
            PendingWrite::Session { key, value } => {
                let record_key = RecordKey::new(Namespace::Session, key)?;
                match value {
                    Some(bytes) => tx.write(record_key, bytes.clone(), false, self.rec_seq),
                    None => tx.delete(record_key),
                }
            }
            PendingWrite::CausalityToken { twinnet, token } => tx.write(
                RecordKey::new(Namespace::Doc, &format!("causality.{}", twinnet.as_str()))?,
                token.clone(),
                false,
                self.rec_seq,
            ),
        })
    }
}

/// The vault encoding of a [`crate::planes::PeerRecord`].
///
/// Length-prefixed and **internal to the vault**: this never appears on any wire,
/// so it is not a contract and does not belong in `contracts/`. The frozen
/// `peer.proto` `TrustedPeer` is the *transmissible projection*; what is stored
/// here is the local cache, which `contract-matrix.md` §2 marks `LOCAL` with "no
/// remote replica".
fn encode_peer(record: &crate::planes::PeerRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(record.device_id.as_bytes());
    out.extend_from_slice(&record.generation.to_be_bytes());
    out.extend_from_slice(&record.tk_generation.to_be_bytes());
    out.push(u8::from(record.tunnel_key_binding_verified));
    out.extend_from_slice(&record.overlay.v4.octets());
    out.extend_from_slice(&record.overlay.v6.octets());
    out.extend_from_slice(
        &u32::try_from(record.endpoints.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    out
}

/// A store bridge is not `Sync`: it holds the single mutating handle, and S-47
/// makes "two writers to one core" a refused operation rather than a race.
impl core::fmt::Debug for StoreBridge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreBridge")
            .field("flushes", &self.flushes)
            .field("rec_seq", &self.rec_seq)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planes::{ControlPlanePort, PeerRecord};
    use std::sync::Arc;
    use twinvpn_types::TwinnetId;

    fn twinnet() -> TwinnetId {
        TwinnetId::new("tn-bridge").expect("valid")
    }

    #[test]
    fn a_peer_record_encodes_both_families() {
        let record = PeerRecord {
            device_id: twinvpn_types::DeviceId::from_slice(&[5; 32]).expect("32"),
            generation: 2,
            tk_generation: 3,
            tunnel_key_binding_verified: true,
            endpoints: Vec::new(),
            overlay: twinvpn_types::OverlayAddresses {
                v4: twinvpn_types::V4Addr::from_slice(&[100, 64, 0, 5]).expect("v4"),
                v6: twinvpn_types::V6Addr::from_slice(&[0xfd; 16], 0).expect("v6"),
            },
        };
        let bytes = encode_peer(&record);
        // 32 device_id + 4 + 4 + 1 + 4 (v4) + 16 (v6) + 4 (endpoint count)
        assert_eq!(bytes.len(), 65);
        assert!(
            bytes.windows(16).any(|w| w == [0xfd; 16]),
            "the v6 half must be stored, not dropped"
        );
    }

    #[test]
    fn the_queue_is_what_a_flush_would_drain() {
        // The bridge itself needs a real `Store`, which needs a platform
        // adapter; that path is exercised end to end in
        // `tests/falsification.rs`. What is asserted here is the piece that has
        // no dependency: every port write lands in the queue in order.
        let shared = crate::planes::new_shared();
        let cp = ControlPlanePort::new(Arc::clone(&shared));
        assert!(cp.advance_trust_epoch(&twinnet(), 3));
        assert!(cp.put_document(&twinnet(), "policy_bundle", 1, [0; 32], b"octets"));
        let pending = shared.lock().expect("lock").pending_snapshot();
        assert_eq!(pending.len(), 2);
        assert!(matches!(pending[0], PendingWrite::TrustEpoch { .. }));
        assert!(matches!(pending[1], PendingWrite::Document { .. }));
    }
}
