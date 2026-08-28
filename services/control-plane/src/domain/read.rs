//! The reads, the stream, and the one write that is permitted to be lost.
//!
//! **Authority:** `docs/protocol.md` §9.1 (`GetPeersReq`, snapshot + delta),
//! §9.2 (presence), ADR-0002 §11.4 (push and pull), §11.7 rule 4 (resume, do not
//! reload), `contract-matrix.md` §3.
//!
//! # Pull is always sufficient
//!
//! ADR-0002 §11.4: *"A device MUST be able to reach a correct state using pull
//! alone, with push serving only to reduce latency."* Everything in this module
//! is that pull half. It is what makes stream compaction safe, and it is why
//! [`get_state_document`] answers a version the caller never saw announced.
//!
//! # `PublishPresence` is here, and it is the odd one out
//!
//! `REGISTER` class: last-writer-wins, **no dedup log**, permitted to be lost,
//! and **never a gate**. [`publish_presence`] therefore writes nothing durable,
//! appends nothing to the log, and returns an ack even when it stored nothing.
//! Presence rows themselves live in `twinvpn_presence` — a different database,
//! owned by a different domain — because putting eventually-consistent hint rows
//! in the same transactional scope as revocation is the confusion ADR-0009
//! exists to prevent.

use prost::Message;
use twinvpn_schema::v1;
use twinvpn_service_common::ServiceError;

use crate::codes;
use crate::config::{PROTO_VERSION, RETENTION_FLOOR_EVENTS};
use crate::event::EphemeralEvent;
use crate::model::DocumentType;
use crate::NetTx;
use twinvpn_schema::v1::control_event::Event as EventBody;

use super::{Ctx, Outcome};

/// `DiscoverPeers` — read-only, `MONOTONIC`, snapshot plus delta.
///
/// `since_net_seq == 0` is a full snapshot; anything else is the delta from that
/// cursor. "The pairing is what makes a cold start bounded and a steady state
/// cheap **without a gap**, and it is the general pattern for every cached
/// collection in TwinVPN."
///
/// A revoked device is **excluded from the snapshot** and is separately carried
/// as a `PeerRemoved` event in the delta, so a device that re-snapshots after a
/// revocation cannot re-learn the peer it was told to forget.
///
/// # Errors
///
/// `AUTH.DEVICE_REVOKED` for a revoked caller.
pub fn discover_peers(
    tx: &NetTx,
    ctx: &Ctx<'_>,
    req: &v1::DiscoverPeersRequest,
) -> Result<Outcome, ServiceError> {
    if tx.state().is_revoked(&ctx.caller) {
        return Err(codes::device_revoked(tx.state().trust_epoch));
    }

    let state = tx.state();
    let peers: Vec<v1::TrustedPeer> = state
        .devices
        .values()
        .filter(|d| !d.revoked && d.device_id != ctx.caller)
        .filter(|d| req.since_net_seq == 0 || d.net_seq > req.since_net_seq)
        .map(|d| v1::TrustedPeer {
            peer_device_id: d.device_id.to_vec(),
            label: d.label.clone(),
            twinnet_address_v4: Some(v1::IPv4Address {
                octets: d.twinnet_addr_v4.to_vec(),
            }),
            twinnet_address_v6: Some(v1::IPv6Address {
                octets: d.twinnet_addr_v6.to_vec(),
                zone_index: 0,
            }),
            // MONOTONIC: the device keeps a high-water mark and rejects any
            // lower epoch as a rollback attempt.
            revocation_epoch: state.trust_epoch,
            ..Default::default()
        })
        .collect();

    let resp = v1::DiscoverPeersResponse {
        peers,
        revocation_epoch: state.trust_epoch,
        snapshot_net_seq: state.head_net_seq(),
        error: None,
    };
    Ok(Outcome::read_only(resp.encode_to_vec()))
}

/// `PublishPresence` — `REGISTER`. LWW, no dedup log, permitted to be lost.
///
/// The ack carries `pending_net_seq` so a mobile device learns it is behind
/// without draining the log — ADR-0002 §11.10's mechanism for a device whose
/// control channel is allowed to die in background.
///
/// # Errors
///
/// `AUTH.DEVICE_REVOKED`. Nothing else: presence "is never a gate", so a
/// malformed heartbeat is dropped rather than turned into a refusal that a
/// client might treat as a connectivity failure.
pub fn publish_presence(
    tx: &mut NetTx,
    ctx: &Ctx<'_>,
    req: &v1::PublishPresenceRequest,
) -> Result<Outcome, ServiceError> {
    if tx.state().is_revoked(&ctx.caller) {
        return Err(codes::device_revoked(tx.state().trust_epoch));
    }
    let pending = tx.state().head_net_seq();
    let revocation_epoch = tx.state().trust_epoch;

    // The aggregated fan-out. EPHEMERAL: net_seq == 0, not logged, not
    // resumable, not replayed. `EphemeralEvent::new` refuses anything else.
    if req.heartbeat.is_some() {
        tx.emit_ephemeral(EphemeralEvent::new(EventBody::PresenceUpdated(
            v1::PresenceUpdated { presence: None },
        ))?);
    }

    let resp = v1::PublishPresenceResponse {
        ack: Some(v1::HeartbeatAck {
            pending_net_seq: pending,
            revocation_epoch,
            ..Default::default()
        }),
        error: None,
    };
    Ok(Outcome::read_only(resp.encode_to_vec()))
}

/// `SubscribeEvents` — opens or resumes the C2 stream.
///
/// ADR-0002 §11.7 rule 4: *"A device whose cursor is still within the retention
/// floor MUST resume from it. Re-snapshotting on every reconnect is prohibited —
/// it converts a reconnect storm into a bandwidth storm."* So a cursor inside
/// the floor is accepted as given, and only a cursor **below** the floor is
/// refused.
///
/// # Errors
///
/// `CONTROL.CURSOR_TOO_OLD` carrying the cursor and the floor, so the device
/// knows to perform a full declarative re-snapshot — which is always correct,
/// because every durable event is independently applicable (N-5).
pub fn subscribe(
    tx: &NetTx,
    ctx: &Ctx<'_>,
    req: &v1::SubscribeEventsRequest,
) -> Result<Outcome, ServiceError> {
    if tx.state().is_revoked(&ctx.caller) {
        return Err(codes::device_revoked(tx.state().trust_epoch));
    }
    let state = tx.state();
    if req.from_net_seq != 0 && req.from_net_seq + 1 < state.retained_from {
        return Err(codes::cursor_too_old(req.from_net_seq, state.retained_from));
    }
    let resp = v1::SubscribeEventsResponse {
        current_net_seq: state.head_net_seq(),
        revocation_epoch: state.trust_epoch,
        error: None,
    };
    Ok(Outcome::read_only(resp.encode_to_vec()))
}

/// `GetStateDocument` — the declarative re-read. **Pull is always sufficient.**
///
/// `version == 0` means "the current version", so a device that lost its stream
/// entirely can still converge without ever having seen an announcement.
///
/// # Errors
///
/// `PROTO.MALFORMED_MESSAGE` for an unspecified `doc_type`;
/// `CONTROL.STALENESS.DOCUMENT_STALE` when the requested version is not the one
/// held — a device asking for a version this shard has not applied is exactly
/// the monotonic-read case, and serving an *older* document instead would be the
/// rollback ADR-0009 R-5 refuses.
pub fn get_state_document(
    tx: &NetTx,
    ctx: &Ctx<'_>,
    req: &v1::GetStateDocumentRequest,
) -> Result<Outcome, ServiceError> {
    if tx.state().is_revoked(&ctx.caller) {
        return Err(codes::device_revoked(tx.state().trust_epoch));
    }
    let doc_type = DocumentType::from_wire(req.doc_type)
        .ok_or_else(|| codes::bare(twinvpn_types::codes::PROTO_MALFORMED_MESSAGE))?;
    let held = tx
        .state()
        .documents
        .get(&doc_type)
        .ok_or_else(|| codes::bare(twinvpn_types::codes::CONTROL_STALENESS_DOCUMENT_STALE))?;
    if req.version != 0 && req.version != held.version {
        return Err(codes::bare(
            twinvpn_types::codes::CONTROL_STALENESS_DOCUMENT_STALE,
        ));
    }

    let resp = v1::GetStateDocumentResponse {
        reference: Some(v1::StateDocumentRef {
            doc_type: doc_type.to_wire(),
            version: held.version,
            digest: held.content_digest.to_vec(),
            size_bytes: held.octets.len() as u64,
        }),
        // The signed octets, forwarded VERBATIM. This service did not author
        // them and must not re-encode them (W-4).
        document: Some(v1::SignedStatement {
            cose_sign1: held.octets.clone(),
            statement_type: statement_type_of(doc_type),
        }),
        error: None,
    };
    Ok(Outcome::read_only(resp.encode_to_vec()))
}

/// The `SignedStatementType` a document type's payload claims to be.
#[must_use]
pub const fn statement_type_of(doc_type: DocumentType) -> i32 {
    match doc_type {
        DocumentType::PolicyBundle => v1::SignedStatementType::PolicyBundle as i32,
        DocumentType::OwnerTrustAnchor => v1::SignedStatementType::OwnerTrustAnchor as i32,
        DocumentType::TrustEpochBundle => v1::SignedStatementType::TrustEpochBundle as i32,
        DocumentType::RelayMap => v1::SignedStatementType::RelayMap as i32,
        DocumentType::RelayEpochFloor => v1::SignedStatementType::RelayEpochFloor as i32,
        DocumentType::NetworkContract => v1::SignedStatementType::NetworkContract as i32,
        DocumentType::Membership => v1::SignedStatementType::DeviceIdentityRecord as i32,
    }
}

/// The retention floor in events, restated from the frozen registry.
#[must_use]
pub const fn retention_floor_events() -> u64 {
    RETENTION_FLOOR_EVENTS
}

/// The control-plane API epoch a `MessageMetadata` this service emits carries.
#[must_use]
pub const fn proto_version() -> u32 {
    PROTO_VERSION
}

#[cfg(test)]
mod tests {
    use super::{proto_version, retention_floor_events, statement_type_of};
    use crate::model::DocumentType;

    #[test]
    fn every_document_type_names_a_declared_statement_type() {
        for t in DocumentType::ALL {
            assert!(statement_type_of(t) > 0, "{}", t.as_str());
        }
    }

    #[test]
    fn the_retention_floor_and_proto_epoch_are_the_frozen_ones() {
        assert_eq!(retention_floor_events(), 1_000_000);
        assert_eq!(proto_version(), 1);
    }
}
