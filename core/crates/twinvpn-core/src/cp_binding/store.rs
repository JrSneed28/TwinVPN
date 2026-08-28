//! `ControlPlaneStore` → the store. The **only** path CD-I5 permits between the
//! two planes, as a type.
//!
//! **Authority:** [ADR-0018](../../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! §11.7 CD-I5; [ADR-0009](../../../../../docs/adr/ADR-0009-consistency-and-state-convergence.md)
//! R-4, R-6, R-9; `contracts/docs/idempotency.md` §5; finding **W-4** (octets
//! are stored verbatim and never decoded here).
//!
//! [`ControlPlaneBinding`] holds a [`crate::planes::ControlPlanePort`] and
//! nothing else. The port is write-only and reaches no data-plane type, so
//! "the control plane asked the data plane for something" is not expressible
//! here rather than merely discouraged.
//!
//! The other two ports are bound beside this one — see [`super`] for the table
//! and for what W-12 resolved to.

use futures_core::future::BoxFuture;
use twinvpn_cp_client::ports::{ControlPlaneStore, StoreFailure};
use twinvpn_cp_client::state::{CachedPeer, DocumentType, StoredDocumentMark};
use twinvpn_cp_client::ReceivedOctets;
use twinvpn_types::{DeviceId, TwinnetId};

use crate::planes::{ControlPlanePort, PeerRecord};

/// The `ControlPlaneStore` implementation the client is constructed with.
///
/// It holds **only** a [`ControlPlanePort`], which is write-only and reaches no
/// data-plane type. That is CD-I5's "wired to the store" arrow, as a field.
#[derive(Debug, Clone)]
pub struct ControlPlaneBinding {
    port: ControlPlanePort,
}

impl ControlPlaneBinding {
    /// Binds the client to the store.
    #[must_use]
    pub const fn new(port: ControlPlanePort) -> Self {
        Self { port }
    }
}

/// `CachedPeer` → [`PeerRecord`], field for field.
///
/// A conversion, not a re-model: every field is copied and none is derived. The
/// two types exist because CD-I5 forbids a data-plane crate to name a
/// control-plane one, not because the facts differ.
fn to_record(peer: &CachedPeer) -> PeerRecord {
    PeerRecord {
        device_id: peer.device_id,
        generation: peer.generation,
        tk_generation: peer.tk_generation,
        tunnel_key_binding_verified: peer.tunnel_key_binding_verified,
        endpoints: peer.endpoints.clone(),
        overlay: peer.overlay,
    }
}

/// [`PeerRecord`] → `CachedPeer`, the reverse.
fn to_cached(record: &PeerRecord) -> CachedPeer {
    CachedPeer {
        device_id: record.device_id,
        generation: record.generation,
        tk_generation: record.tk_generation,
        tunnel_key_binding_verified: record.tunnel_key_binding_verified,
        endpoints: record.endpoints.clone(),
        overlay: record.overlay,
    }
}

/// A `'static` tag for a document type, so the bridge's key type stays
/// allocation-free.
const fn doc_tag(doc_type: DocumentType) -> &'static str {
    doc_type.as_str()
}

impl ControlPlaneStore for ControlPlaneBinding {
    fn cursor(&self, twinnet: &TwinnetId) -> BoxFuture<'_, Result<u64, StoreFailure>> {
        let value = self.port.cursor(twinnet);
        Box::pin(async move { Ok(value) })
    }

    fn advance_cursor<'a>(
        &'a self,
        twinnet: &'a TwinnetId,
        net_seq: u64,
    ) -> BoxFuture<'a, Result<(), StoreFailure>> {
        let floor = self.port.cursor(twinnet);
        let accepted = self.port.advance_cursor(twinnet, net_seq);
        Box::pin(async move {
            if accepted {
                Ok(())
            } else {
                // "A server-offered cursor below the local high-water MUST be
                // rejected." Reported as the typed refusal, never absorbed.
                Err(StoreFailure::RollbackRefused {
                    offered: net_seq,
                    floor,
                })
            }
        })
    }

    fn trust_epoch(&self, twinnet: &TwinnetId) -> BoxFuture<'_, Result<u64, StoreFailure>> {
        let value = self.port.trust_epoch(twinnet);
        Box::pin(async move { Ok(value) })
    }

    fn advance_trust_epoch<'a>(
        &'a self,
        twinnet: &'a TwinnetId,
        epoch: u64,
    ) -> BoxFuture<'a, Result<(), StoreFailure>> {
        let floor = self.port.trust_epoch(twinnet);
        let accepted = self.port.advance_trust_epoch(twinnet, epoch);
        Box::pin(async move {
            if accepted {
                Ok(())
            } else {
                Err(StoreFailure::RollbackRefused {
                    offered: epoch,
                    floor,
                })
            }
        })
    }

    fn document_version<'a>(
        &'a self,
        _twinnet: &'a TwinnetId,
        _doc_type: DocumentType,
    ) -> BoxFuture<'a, Result<Option<StoredDocumentMark>, StoreFailure>> {
        // INTEGRATION ITEM, reported rather than faked. `StoredDocumentMark`
        // carries `issued_at_ms`, `refresh_after_ms` and `not_after_ms` — three
        // facts that live inside the SIGNED PAYLOAD and that the bridge, which
        // stores octets verbatim and never decodes them (ST-13, W-4), does not
        // have. Returning a mark with invented band boundaries would make the
        // client's staleness ladder run on fiction, so this answers "not held"
        // until either the client supplies the bands with the document or a
        // decode step is added on the client's own side.
        Box::pin(async move { Ok(None) })
    }

    fn put_document<'a>(
        &'a self,
        twinnet: &'a TwinnetId,
        doc_type: DocumentType,
        version: u64,
        content_digest: [u8; 32],
        payload: &'a ReceivedOctets,
    ) -> BoxFuture<'a, Result<(), StoreFailure>> {
        let accepted = self.port.put_document(
            twinnet,
            doc_tag(doc_type),
            version,
            content_digest,
            payload.as_slice(),
        );
        let held = self.port.document_version(twinnet, doc_tag(doc_type));
        Box::pin(async move {
            if accepted {
                return Ok(());
            }
            // The port refuses two things for two different reasons, and they
            // must not be conflated: a lower version is a rollback (retry after
            // re-reading), an equal version with a different digest is
            // ADR-0009 R-4's fork (never retry — refetch and refuse).
            match held {
                Some(floor) if version < floor => Err(StoreFailure::RollbackRefused {
                    offered: version,
                    floor,
                }),
                _ => Err(StoreFailure::Forked { version }),
            }
        })
    }

    fn trusted_peers(
        &self,
        twinnet: &TwinnetId,
    ) -> BoxFuture<'_, Result<Vec<CachedPeer>, StoreFailure>> {
        // Read back through the same shared state the data plane reads. This is
        // the one place the client sees its own writes, and it sees them through
        // the store rather than from a private cache — which is what makes
        // "the store is the only path" true rather than decorative.
        let peers: Vec<CachedPeer> = crate::planes::DataPlaneView::new(self.port.shared())
            .peers(twinnet)
            .iter()
            .map(to_cached)
            .collect();
        Box::pin(async move { Ok(peers) })
    }

    fn put_trusted_peer<'a>(
        &'a self,
        twinnet: &'a TwinnetId,
        peer: &'a CachedPeer,
    ) -> BoxFuture<'a, Result<(), StoreFailure>> {
        self.port.put_peer(twinnet, to_record(peer));
        Box::pin(async move { Ok(()) })
    }

    fn remove_trusted_peer<'a>(
        &'a self,
        twinnet: &'a TwinnetId,
        peer: DeviceId,
        reason_code: &'a str,
    ) -> BoxFuture<'a, Result<(), StoreFailure>> {
        self.port.remove_peer(twinnet, peer, reason_code);
        Box::pin(async move { Ok(()) })
    }

    fn causality_token(
        &self,
        twinnet: &TwinnetId,
    ) -> BoxFuture<'_, Result<Option<Vec<u8>>, StoreFailure>> {
        let token = self.port.causality_token(twinnet);
        Box::pin(async move { Ok(token) })
    }

    fn put_causality_token<'a>(
        &'a self,
        twinnet: &'a TwinnetId,
        token: &'a [u8],
    ) -> BoxFuture<'a, Result<(), StoreFailure>> {
        self.port.put_causality_token(twinnet, token);
        Box::pin(async move { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planes::new_shared;
    use std::sync::Arc;
    use twinvpn_types::{OverlayAddresses, V4Addr, V6Addr};

    fn twinnet() -> TwinnetId {
        TwinnetId::new("tn-cp").expect("valid")
    }

    fn cached(byte: u8) -> CachedPeer {
        CachedPeer {
            device_id: DeviceId::from_slice(&[byte; 32]).expect("32"),
            generation: 3,
            tk_generation: 2,
            tunnel_key_binding_verified: true,
            endpoints: Vec::new(),
            overlay: OverlayAddresses {
                v4: V4Addr::from_slice(&[100, 64, 1, byte]).expect("v4"),
                v6: V6Addr::from_slice(
                    &[0xfd, 0x7c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte],
                    0,
                )
                .expect("v6"),
            },
        }
    }

    fn block<T>(f: BoxFuture<'_, T>) -> T {
        // A trivial executor: every future in this binding is ready on first
        // poll by construction (no `.await` inside any of them), so this needs
        // no runtime and asserts that property at the same time.
        use core::task::{Context, Poll, Waker};
        // A no-op waker from `std`, not a hand-rolled `RawWaker`: this crate is
        // `#![forbid(unsafe_code)]` and `Waker::from_raw` is unsafe.
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut f = f;
        match f.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("a ControlPlaneStore binding future must be ready on poll"),
        }
    }

    #[test]
    fn a_peer_written_through_the_client_is_readable_by_the_data_plane() {
        let shared = new_shared();
        let port = ControlPlanePort::new(Arc::clone(&shared));
        let binding = ControlPlaneBinding::new(port);
        let view = crate::planes::DataPlaneView::new(shared);

        block(binding.put_trusted_peer(&twinnet(), &cached(7))).expect("write");
        let record = view
            .peer(&twinnet(), DeviceId::from_slice(&[7; 32]).expect("32"))
            .expect("the data plane reads what the control plane wrote");
        assert_eq!(record.generation, 3);
        assert!(record.tunnel_key_binding_verified);
    }

    #[test]
    fn a_rolled_back_cursor_is_a_typed_refusal_not_a_silent_accept() {
        let shared = new_shared();
        let binding = ControlPlaneBinding::new(ControlPlanePort::new(shared));
        block(binding.advance_cursor(&twinnet(), 20)).expect("first advance");
        let err = block(binding.advance_cursor(&twinnet(), 19)).expect_err("must refuse");
        assert!(matches!(
            err,
            StoreFailure::RollbackRefused {
                offered: 19,
                floor: 20
            }
        ));
    }

    #[test]
    fn a_forked_document_is_refused() {
        let shared = new_shared();
        let binding = ControlPlaneBinding::new(ControlPlanePort::new(shared));
        block(binding.put_document(
            &twinnet(),
            DocumentType::PolicyBundle,
            4,
            [1; 32],
            &ReceivedOctets::from_wire(b"a"),
        ))
        .expect("first write");
        let err = block(binding.put_document(
            &twinnet(),
            DocumentType::PolicyBundle,
            4,
            [2; 32],
            &ReceivedOctets::from_wire(b"b"),
        ))
        .expect_err("a fork must be refused");
        assert!(matches!(err, StoreFailure::Forked { version: 4 }));
    }

    #[test]
    fn the_client_reads_its_own_writes_back_through_the_store() {
        let shared = new_shared();
        let binding = ControlPlaneBinding::new(ControlPlanePort::new(shared));
        block(binding.put_trusted_peer(&twinnet(), &cached(1))).expect("write");
        block(binding.put_trusted_peer(&twinnet(), &cached(2))).expect("write");
        let peers = block(binding.trusted_peers(&twinnet())).expect("read");
        assert_eq!(peers.len(), 2);
        assert!(peers.iter().all(|p| p.tunnel_key_binding_verified));
    }

    #[test]
    fn a_document_mark_is_absent_rather_than_invented() {
        let shared = new_shared();
        let binding = ControlPlaneBinding::new(ControlPlanePort::new(shared));
        let mark =
            block(binding.document_version(&twinnet(), DocumentType::PolicyBundle)).expect("query");
        assert!(
            mark.is_none(),
            "the bands live in the signed payload; a fabricated mark would make the \
             staleness ladder run on fiction"
        );
    }
}
