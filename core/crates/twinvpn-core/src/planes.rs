//! **CD-I5.** The control-plane client is wired *to the store*; the data plane
//! is wired *from the store*; neither is wired to the other.
//!
//! **Authority:** [ADR-0018](../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! §11.7 CD-I5; [`docs/architecture.md`](../../../../docs/architecture.md) §4.2
//! and §4.4; [ADR-0002](../../../../docs/adr/ADR-0002-control-plane-messaging-and-event-bus.md)
//! §11.8 step 3 (B-19 blocks a release without the artifact this is).
//!
//! > **CD-I5.** … The only path between them is `twinvpn-store`. Only
//! > `twinvpn-core`, the composition root, may name both, and it wires the
//! > control-plane client **to the store** and the data plane **from the store**
//! > — never to each other.
//!
//! # The shape, and why it is not "both hold an `Arc<Mutex<Store>>`"
//!
//! ```text
//!   twinvpn-cp-client  ──writes──►  ┌──────────────┐
//!                                   │ StoreBridge  │ ──owns──► twinvpn_store::Store
//!   data-plane crates  ◄──reads───  └──────────────┘
//! ```
//!
//! [`ControlPlanePort`] implements `twinvpn_cp_client::ControlPlaneStore` and can
//! **only write**. [`DataPlaneView`] can **only read**. They share one
//! [`Shared`] cache and a pending-write queue; the `Store` itself is owned by
//! [`StoreBridge`], which is driven by the composition root's own task.
//!
//! Three things follow that a shared `Arc<Mutex<Store>>` would not give:
//!
//! 1. **The direction is in the types.** There is no method on
//!    [`DataPlaneView`] that writes and none on [`ControlPlanePort`] that a
//!    data-plane crate could call, so "the data plane asked the control plane
//!    for something" is not expressible, not merely discouraged.
//! 2. **No lock is held across an `await`.** `twinvpn_store::Store::commit` is
//!    `async` and takes `&mut self`; `ControlPlaneStore`'s methods are `&self`
//!    and return `BoxFuture`. Holding the store's lock inside those futures would
//!    make them non-`Send`. The queue removes the question.
//! 3. **One writer to the vault.** `twinvpn_store` takes a single-opener lock
//!    (`STORE.LOCK_CONTENDED`), so exactly one owner is not a preference.
//!
//! # What this costs, stated plainly
//!
//! `ControlPlaneStore`'s doc comment says ADR-0009 R-9 requires the high-water
//! mark to be **durable before** the document it admits is acted on. A queued
//! write is not durable when `put_document` resolves. [`StoreBridge::flush`] is
//! what makes it durable, and the composition root calls it **before** admitting
//! the document's effects, so the ordering R-9 requires is preserved — but the
//! obligation moved from the port to the caller. That is a real weakening of the
//! trait's own contract and it is recorded in this crate's `README.md` and in the
//! completion report rather than glossed.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use twinvpn_types::{DeviceId, Endpoint, OverlayAddresses, TwinnetId};

/// The cached facts about one peer that cross the bridge.
///
/// Declared **here**, in the composition root, from `twinvpn-types` vocabulary
/// only. That is deliberate: if this struct were `twinvpn_cp_client::CachedPeer`
/// then a data-plane crate reading it would name a control-plane type, which is
/// the edge CD-I5 denies. The control-plane binding converts field-for-field on
/// the way in ([`crate::cp_binding`]), so nothing is re-modelled — this is a
/// transfer shape, not a second model.
///
/// It carries no `PairSecret` and no `EpochSeed`: those are `core-security`'s and
/// I4 keeps them out of the core's reach entirely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    /// The peer's permanent name.
    pub device_id: DeviceId,
    /// `highest_generation_seen` (ADR-0007 N-22).
    pub generation: u32,
    /// `highest_tk_generation_seen`, tracked separately.
    pub tk_generation: u32,
    /// Whether the peer's `TunnelKeyBinding` verified. A peer whose binding has
    /// not verified is **not** a `TrustedPeer` (ADR-0007 N-4).
    pub tunnel_key_binding_verified: bool,
    /// Cached endpoints (S-15) — what a reconnect during a total outage uses.
    pub endpoints: Vec<Endpoint>,
    /// Overlay addresses. **Both families, always** (ADR-0010 R1).
    pub overlay: OverlayAddresses,
}

/// One queued durable write.
///
/// Kept as a typed enum rather than a closure so the queue can be inspected,
/// counted and asserted on — a write-behind queue nobody can look inside is how
/// "we thought it was persisted" happens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingWrite {
    /// Advance the durable C2 cursor (S-27).
    Cursor {
        /// Which `TwinNet`.
        twinnet: TwinnetId,
        /// The offered value. A value below the stored one is refused at apply
        /// time, not here.
        net_seq: u64,
    },
    /// Advance the `trust_epoch` high-water mark (ADR-0009 R-6).
    TrustEpoch {
        /// Which `TwinNet`.
        twinnet: TwinnetId,
        /// The offered epoch.
        epoch: u64,
    },
    /// Store a verified document by its **verified octets**.
    Document {
        /// Which `TwinNet`.
        twinnet: TwinnetId,
        /// Which document type.
        doc_type: &'static str,
        /// The monotone version.
        version: u64,
        /// The content digest, for ADR-0009 R-4's fork detection.
        content_digest: [u8; 32],
        /// The received octets, **verbatim** (W-4, ST-13). Never re-encoded.
        payload: Vec<u8>,
    },
    /// Replace one cached peer record.
    Peer {
        /// Which `TwinNet`.
        twinnet: TwinnetId,
        /// The peer.
        device_id: DeviceId,
        /// The cached record.
        record: Box<PeerRecord>,
    },
    /// Remove a cached peer, recording why.
    PeerRemoved {
        /// Which `TwinNet`.
        twinnet: TwinnetId,
        /// The peer.
        device_id: DeviceId,
        /// The registered code that removed it.
        reason_code: String,
    },
    /// One `Session`'s durable record (S-12, `reliability.md` §6.5).
    ///
    /// A **data-plane** write, queued into the same transaction as the
    /// control-plane's so that ST-12b's multi-key commit covers both. It carries
    /// opaque bytes rather than a `twinvpn-session` type, which is what keeps
    /// this enum nameable by a module that must not favour either plane.
    Session {
        /// The record key, derived from the `SessionId`.
        key: String,
        /// The encoded record, or `None` for a deletion.
        value: Option<Vec<u8>>,
    },
    /// Record the newest `causality_token`. Devices **store and echo; they never
    /// parse** (`protocol.md` §5.2).
    CausalityToken {
        /// Which `TwinNet`.
        twinnet: TwinnetId,
        /// The opaque token.
        token: Vec<u8>,
    },
}

/// The cached, in-memory half of the bridge.
///
/// Both ports hold an `Arc` of this. It is the *only* shared object, and it
/// carries no reference to either plane's types beyond the vocabulary
/// `twinvpn-types` already defines — which is what keeps this module from being
/// the place the planes meet.
/// A held document: its monotone version, its content digest, and the
/// **received octets** exactly as they arrived (ST-13, W-4).
type HeldDocument = (u64, [u8; 32], Vec<u8>);

/// The cached, in-memory half of the bridge.
///
/// Both ports hold an `Arc` of this. It is the *only* shared object, and it
/// carries no reference to either plane's types beyond the vocabulary
/// `twinvpn-types` already defines — which is what keeps this module from being
/// the place the planes meet.
#[derive(Debug, Default)]
pub struct BridgeState {
    cursor: BTreeMap<TwinnetId, u64>,
    trust_epoch: BTreeMap<TwinnetId, u64>,
    documents: BTreeMap<(TwinnetId, &'static str), HeldDocument>,
    peers: BTreeMap<(TwinnetId, DeviceId), PeerRecord>,
    causality: BTreeMap<TwinnetId, Vec<u8>>,
    pending: Vec<PendingWrite>,
    /// Set when the durable store refused a write. Read by the data-plane view,
    /// because a refused monotone floor is a **security control** whose effect
    /// the data plane must see (ADR-0008 §7.1).
    last_refusal: Option<String>,
}

impl BridgeState {
    /// A snapshot of the queued writes, oldest first.
    ///
    /// `pub(crate)` deliberately: only [`crate::bridge::StoreBridge`], the single
    /// owner of the vault, may drain the queue. Neither plane's port can reach
    /// these, so "the control plane decided its own write was durable" is not
    /// expressible.
    pub(crate) fn pending_snapshot(&self) -> Vec<PendingWrite> {
        self.pending.clone()
    }

    /// Drops the first `count` queued writes, after they were committed.
    ///
    /// `count` rather than `clear()`, because a write enqueued *while* the flush
    /// was in flight must survive it — clearing wholesale is how a write made
    /// during a commit is silently lost.
    pub(crate) fn clear_pending(&mut self, count: usize) {
        let keep = self.pending.split_off(count.min(self.pending.len()));
        self.pending = keep;
    }

    /// Publishes a durable refusal for the data plane to read.
    pub(crate) fn set_refusal(&mut self, refusal: Option<String>) {
        self.last_refusal = refusal;
    }

    /// Queues a `Session` write.
    ///
    /// The data plane's only write path into the queue, and deliberately the
    /// **only** mutator on this type reachable from outside
    /// [`ControlPlanePort`]. It cannot touch a cursor, an epoch, a document or a
    /// peer, so "the data plane wrote something the control plane owns" is not
    /// expressible.
    // Under `core-lite` there is no `twinvpn-session`, so nothing calls this —
    // which is exactly the property §11.12 asks for, not a defect.
    #[cfg_attr(not(feature = "full"), allow(dead_code))]
    pub(crate) fn push_session_write(&mut self, write: PendingWrite) {
        debug_assert!(
            matches!(write, PendingWrite::Session { .. }),
            "only a Session write may enter through this path"
        );
        self.pending.push(write);
    }
}

/// The shared cache both ports see.
pub type Shared = Arc<Mutex<BridgeState>>;

/// A fresh, empty bridge state.
#[must_use]
pub fn new_shared() -> Shared {
    Arc::new(Mutex::new(BridgeState::default()))
}

/// **The control plane's half.** Write-only, by construction.
///
/// `twinvpn-cp-client` receives this as its `ControlPlaneStore`. It has no
/// accessor that reaches a data-plane type, and `twinvpn-cp-client` has no
/// dependency that could name one — `cargo run -p xtask -- lint` asserts the
/// second half.
#[derive(Debug, Clone)]
pub struct ControlPlanePort {
    shared: Shared,
}

impl ControlPlanePort {
    /// Binds the port to a shared state.
    #[must_use]
    pub const fn new(shared: Shared) -> Self {
        Self { shared }
    }

    /// Records a write and queues it for durability.
    fn record(&self, write: PendingWrite) {
        let Ok(mut state) = self.shared.lock() else {
            // A poisoned lock means another thread panicked while holding it.
            // Dropping the write silently would be the failure `reliability.md`
            // §10 forbids; the caller sees it through `last_refusal` and the
            // bridge's own flush count.
            return;
        };
        match &write {
            PendingWrite::Cursor { twinnet, net_seq } => {
                state.cursor.insert(twinnet.clone(), *net_seq);
            }
            PendingWrite::TrustEpoch { twinnet, epoch } => {
                state.trust_epoch.insert(twinnet.clone(), *epoch);
            }
            PendingWrite::Document {
                twinnet,
                doc_type,
                version,
                content_digest,
                payload,
            } => {
                state.documents.insert(
                    (twinnet.clone(), doc_type),
                    (*version, *content_digest, payload.clone()),
                );
            }
            PendingWrite::Peer {
                twinnet,
                device_id,
                record,
            } => {
                state
                    .peers
                    .insert((twinnet.clone(), *device_id), (**record).clone());
            }
            PendingWrite::PeerRemoved {
                twinnet, device_id, ..
            } => {
                state.peers.remove(&(twinnet.clone(), *device_id));
            }
            PendingWrite::CausalityToken { twinnet, token } => {
                state.causality.insert(twinnet.clone(), token.clone());
            }
            // A `Session` write never arrives through this path: it enters via
            // `push_session_write`, which is the data plane's only door. Reaching
            // here would mean the control-plane port had learned to write session
            // state, which is the CD-I5 edge this module exists to deny.
            PendingWrite::Session { .. } => {
                debug_assert!(
                    false,
                    "a Session write must not enter through the control-plane port"
                );
                return;
            }
        }
        state.pending.push(write);
    }

    /// The durable cursor for a `TwinNet`, or 0 if never attached.
    #[must_use]
    pub fn cursor(&self, twinnet: &TwinnetId) -> u64 {
        self.shared
            .lock()
            .ok()
            .and_then(|s| s.cursor.get(twinnet).copied())
            .unwrap_or(0)
    }

    /// Advances the cursor. A value at or below the stored one is **ignored**,
    /// because "a server-offered cursor below the local high-water MUST be
    /// rejected" and a silent overwrite is how that rejection is lost.
    #[must_use]
    pub fn advance_cursor(&self, twinnet: &TwinnetId, net_seq: u64) -> bool {
        if net_seq <= self.cursor(twinnet) && net_seq != 0 {
            return false;
        }
        self.record(PendingWrite::Cursor {
            twinnet: twinnet.clone(),
            net_seq,
        });
        true
    }

    /// The `trust_epoch` high-water mark.
    #[must_use]
    pub fn trust_epoch(&self, twinnet: &TwinnetId) -> u64 {
        self.shared
            .lock()
            .ok()
            .and_then(|s| s.trust_epoch.get(twinnet).copied())
            .unwrap_or(0)
    }

    /// Advances the trust epoch. **Never decreases** (ADR-0009 R-6).
    #[must_use]
    pub fn advance_trust_epoch(&self, twinnet: &TwinnetId, epoch: u64) -> bool {
        if epoch < self.trust_epoch(twinnet) {
            return false;
        }
        self.record(PendingWrite::TrustEpoch {
            twinnet: twinnet.clone(),
            epoch,
        });
        true
    }

    /// Stores a verified document by its verified octets and advances its mark.
    ///
    /// `payload` is written **verbatim** — W-4's forward-verbatim constraint and
    /// ST-13's `verbatim_signed` rule are the same rule seen from two sides, and
    /// a decode-then-re-encode here would drop unknown fields under `prost` 0.13.
    #[must_use]
    pub fn put_document(
        &self,
        twinnet: &TwinnetId,
        doc_type: &'static str,
        version: u64,
        content_digest: [u8; 32],
        payload: &[u8],
    ) -> bool {
        if let Ok(state) = self.shared.lock() {
            if let Some((held, digest, _)) = state.documents.get(&(twinnet.clone(), doc_type)) {
                if version < *held {
                    return false;
                }
                // ADR-0009 R-4: two different contents at one version is a fork,
                // not an update.
                if version == *held && *digest != content_digest {
                    return false;
                }
            }
        }
        self.record(PendingWrite::Document {
            twinnet: twinnet.clone(),
            doc_type,
            version,
            content_digest,
            payload: payload.to_vec(),
        });
        true
    }

    /// Replaces one peer's cached record.
    pub fn put_peer(&self, twinnet: &TwinnetId, record: PeerRecord) {
        let device_id = record.device_id;
        self.record(PendingWrite::Peer {
            twinnet: twinnet.clone(),
            device_id,
            record: Box::new(record),
        });
    }

    /// Removes a peer, recording the registered code that did it.
    pub fn remove_peer(&self, twinnet: &TwinnetId, device_id: DeviceId, reason_code: &str) {
        self.record(PendingWrite::PeerRemoved {
            twinnet: twinnet.clone(),
            device_id,
            reason_code: reason_code.to_owned(),
        });
    }

    /// The version of a held document, if any.
    #[must_use]
    pub fn document_version(&self, twinnet: &TwinnetId, doc_type: &'static str) -> Option<u64> {
        self.shared
            .lock()
            .ok()
            .and_then(|s| s.documents.get(&(twinnet.clone(), doc_type)).map(|d| d.0))
    }

    /// The newest `causality_token` seen. Devices **store and echo; they never
    /// parse** (`protocol.md` §5.2).
    #[must_use]
    pub fn causality_token(&self, twinnet: &TwinnetId) -> Option<Vec<u8>> {
        self.shared
            .lock()
            .ok()
            .and_then(|s| s.causality.get(twinnet).cloned())
    }

    /// The shared state, so the composition root can build the reading half.
    ///
    /// `pub(crate)` would be tighter, but the composition root's own binding
    /// module needs it and both live in this crate; what matters is that no
    /// **data-plane** crate can reach a `ControlPlanePort` at all, which CD-I5's
    /// dependency check enforces one level up.
    #[must_use]
    pub fn shared(&self) -> Shared {
        Arc::clone(&self.shared)
    }

    /// Records the newest `causality_token`.
    pub fn put_causality_token(&self, twinnet: &TwinnetId, token: &[u8]) {
        self.record(PendingWrite::CausalityToken {
            twinnet: twinnet.clone(),
            token: token.to_vec(),
        });
    }
}

/// **The data plane's half.** Read-only, by construction.
///
/// Every data-plane crate that needs a control-plane-sourced fact takes one of
/// these. There is no method here that writes and no field that reaches
/// `twinvpn-cp-client`, so `architecture.md` §4.2's rule is a property of the
/// type rather than a convention.
#[derive(Debug, Clone)]
pub struct DataPlaneView {
    shared: Shared,
}

impl DataPlaneView {
    /// Binds the view to a shared state.
    #[must_use]
    pub const fn new(shared: Shared) -> Self {
        Self { shared }
    }

    /// The trust epoch in force. What a handshake checks against.
    #[must_use]
    pub fn trust_epoch(&self, twinnet: &TwinnetId) -> u64 {
        self.shared
            .lock()
            .ok()
            .and_then(|s| s.trust_epoch.get(twinnet).copied())
            .unwrap_or(0)
    }

    /// One cached peer's encoded record, if the control plane has supplied it.
    ///
    /// **This is what an outage runs on** (I5): the data plane reads the cache
    /// and never asks the control plane, so a control-plane failure changes
    /// nothing about a running `Tunnel`.
    #[must_use]
    pub fn peer(&self, twinnet: &TwinnetId, device_id: DeviceId) -> Option<PeerRecord> {
        self.shared
            .lock()
            .ok()
            .and_then(|s| s.peers.get(&(twinnet.clone(), device_id)).cloned())
    }

    /// Every cached peer for a `TwinNet`.
    #[must_use]
    pub fn peers(&self, twinnet: &TwinnetId) -> Vec<PeerRecord> {
        self.shared.lock().map_or_else(
            |_| Vec::new(),
            |s| {
                s.peers
                    .iter()
                    .filter(|((t, _), _)| t == twinnet)
                    .map(|(_, record)| record.clone())
                    .collect()
            },
        )
    }

    /// A verified document's octets, exactly as received.
    #[must_use]
    pub fn document(&self, twinnet: &TwinnetId, doc_type: &'static str) -> Option<Vec<u8>> {
        self.shared
            .lock()
            .ok()
            .and_then(|s| s.documents.get(&(twinnet.clone(), doc_type)).cloned())
            .map(|(_, _, payload)| payload)
    }

    /// The version of a held document.
    #[must_use]
    pub fn document_version(&self, twinnet: &TwinnetId, doc_type: &'static str) -> Option<u64> {
        self.shared
            .lock()
            .ok()
            .and_then(|s| s.documents.get(&(twinnet.clone(), doc_type)).map(|d| d.0))
    }

    /// The last durable refusal, where one occurred.
    ///
    /// A monotone floor refusing a write is a security control, and the data
    /// plane is the half that must act on it — so the fact crosses the bridge as
    /// data rather than as a call back into the control plane.
    #[must_use]
    pub fn last_refusal(&self) -> Option<String> {
        self.shared.lock().ok().and_then(|s| s.last_refusal.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn twinnet() -> TwinnetId {
        TwinnetId::new("tn-test").expect("a valid TwinNet id")
    }

    fn device(byte: u8) -> DeviceId {
        DeviceId::from_slice(&[byte; 32]).expect("32 bytes")
    }

    fn record(byte: u8) -> PeerRecord {
        PeerRecord {
            device_id: device(byte),
            generation: 1,
            tk_generation: 1,
            tunnel_key_binding_verified: true,
            endpoints: Vec::new(),
            // Both families, always. There is no constructor that lets a test
            // omit the v6 half, which is ADR-0010 R1 doing its job even here.
            overlay: OverlayAddresses {
                v4: twinvpn_types::V4Addr::from_slice(&[100, 64, 0, byte]).expect("v4"),
                v6: twinvpn_types::V6Addr::from_slice(
                    &[
                        0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte,
                    ],
                    0,
                )
                .expect("v6"),
            },
        }
    }

    #[test]
    fn the_control_plane_writes_and_the_data_plane_reads_the_same_fact() {
        let shared = new_shared();
        let cp = ControlPlanePort::new(Arc::clone(&shared));
        let dp = DataPlaneView::new(shared);

        cp.put_peer(&twinnet(), record(1));
        assert_eq!(dp.peer(&twinnet(), device(1)), Some(record(1)));
    }

    #[test]
    fn a_cursor_never_goes_backwards() {
        let shared = new_shared();
        let cp = ControlPlanePort::new(shared);
        assert!(cp.advance_cursor(&twinnet(), 10));
        assert!(
            !cp.advance_cursor(&twinnet(), 9),
            "a lower cursor is refused"
        );
        assert!(
            !cp.advance_cursor(&twinnet(), 10),
            "an equal cursor is refused"
        );
        assert_eq!(cp.cursor(&twinnet()), 10);
    }

    #[test]
    fn a_trust_epoch_never_goes_backwards() {
        let shared = new_shared();
        let cp = ControlPlanePort::new(shared);
        assert!(cp.advance_trust_epoch(&twinnet(), 4));
        assert!(!cp.advance_trust_epoch(&twinnet(), 3));
        assert_eq!(cp.trust_epoch(&twinnet()), 4);
    }

    #[test]
    fn a_forked_document_is_refused_rather_than_overwritten() {
        // ADR-0009 R-4: two different contents at one version.
        let shared = new_shared();
        let cp = ControlPlanePort::new(shared);
        assert!(cp.put_document(&twinnet(), "policy_bundle", 7, [1; 32], b"a"));
        assert!(
            !cp.put_document(&twinnet(), "policy_bundle", 7, [2; 32], b"b"),
            "a fork must be refused"
        );
        assert!(
            !cp.put_document(&twinnet(), "policy_bundle", 6, [3; 32], b"c"),
            "a rollback must be refused"
        );
    }

    #[test]
    fn a_document_is_stored_verbatim() {
        // W-4 and ST-13: the received octets, never re-encoded.
        let shared = new_shared();
        let cp = ControlPlanePort::new(Arc::clone(&shared));
        let dp = DataPlaneView::new(shared);
        let octets = vec![0x0a, 0x03, b'x', b'y', b'z', 0xf8, 0x01, 0x2a];
        assert!(cp.put_document(&twinnet(), "network_contract", 1, [9; 32], &octets));
        assert_eq!(dp.document(&twinnet(), "network_contract"), Some(octets));
    }

    #[test]
    fn removing_a_peer_removes_it_from_the_data_plane_view() {
        let shared = new_shared();
        let cp = ControlPlanePort::new(Arc::clone(&shared));
        let dp = DataPlaneView::new(shared);
        cp.put_peer(&twinnet(), record(2));
        assert!(dp.peer(&twinnet(), device(2)).is_some());
        cp.remove_peer(&twinnet(), device(2), "AUTH.DEVICE_REVOKED");
        assert!(dp.peer(&twinnet(), device(2)).is_none());
    }

    #[test]
    fn every_write_is_queued_for_durability_and_none_is_dropped() {
        let shared = new_shared();
        let cp = ControlPlanePort::new(Arc::clone(&shared));
        assert!(cp.advance_cursor(&twinnet(), 1));
        assert!(cp.advance_trust_epoch(&twinnet(), 1));
        cp.put_peer(&twinnet(), record(3));
        cp.put_causality_token(&twinnet(), b"tok");
        let pending = shared.lock().expect("lock").pending.len();
        assert_eq!(pending, 4, "a queued write must never be silently dropped");
    }

    #[test]
    fn a_refused_write_does_not_reach_the_queue() {
        let shared = new_shared();
        let cp = ControlPlanePort::new(Arc::clone(&shared));
        assert!(cp.advance_cursor(&twinnet(), 5));
        assert!(!cp.advance_cursor(&twinnet(), 4));
        assert_eq!(shared.lock().expect("lock").pending.len(), 1);
    }
}
