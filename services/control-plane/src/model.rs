//! The per-`TwinNet` state this service is the single authoritative writer for,
//! and the monotone rules that hold over it.
//!
//! **Authority:** `docs/architecture.md` §5 rows **S-02** (membership),
//! **S-03** (revocation / trust epoch), **S-04** (the `Pairing` record),
//! **S-06**/**S-07** (the warehoused `Owner`-signed policy), **S-08** (address
//! allocation), **S-16** (route advertisements, per advertiser), **S-26** (the
//! log position), **S-28** (the write lease and `shard_epoch`), **S-30** (the
//! `RelayCapabilityToken` issuance record); ADR-0008 N-1/N-3/N-7; ADR-0009
//! §11.3 R-2…R-7.
//!
//! # What is NOT here, and why that is load-bearing
//!
//! - **S-09** — the relay fleet registry and its ranking. Finding **W-3** rules
//!   that §5 wins over `architecture.md` §2.8's prose, so registry *and* ranking
//!   are `relay-directory`'s. This service keeps only **S-30**, the issuance
//!   record, which a relay never reads: it verifies an `Owner`-rooted token
//!   offline, which is what makes relay admission survive a partition of any
//!   duration.
//! - **S-05** `TrustedPeer`, **S-12** `Session` state, **S-18** the kill switch,
//!   **S-27** the device cursor, **S-37** the negotiation floor. Every one is
//!   `LOCAL`. A control-plane row for any of them would be a remote authority
//!   over the device, which is the shape §7 of `protocol.md` warns about.
//! - **Presence.** `EVENTUAL`, TTL'd, and in `twinvpn_presence`, a different
//!   database. `initdb/10-databases.sh`: putting hint rows in the same
//!   transactional scope as revocation is the confusion ADR-0009 exists to
//!   prevent.

use std::collections::{BTreeMap, BTreeSet};

/// A 32-byte `device_id` (`limits.json identifiers.device_id_bytes`).
pub type DeviceKey = [u8; 32];
/// A 16-byte `pairing_id`.
pub type PairingKey = [u8; 16];

/// The document types this service warehouses.
///
/// The wire values are `policy.proto`'s `StateDocumentType` and are identical to
/// `twinvpn-cp-client`'s `state::DocumentType` — the same seven names in the same
/// order. `the_document_types_match_the_client` asserts the mapping, because a
/// server and a client that disagree about which number means `POLICY_BUNDLE`
/// would warehouse a policy under the relay map's high-water mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DocumentType {
    /// The `Owner`-signed `PolicyBundle` (S-06 / S-07).
    PolicyBundle,
    /// The pinned `OwnerTrustAnchor` (S-32).
    OwnerTrustAnchor,
    /// The `TrustEpochBundle` (S-33).
    TrustEpochBundle,
    /// The signed relay map. **S-09 is `relay-directory`'s** (finding W-3); this
    /// service only warehouses the document for distribution.
    RelayMap,
    /// The relay `epoch_floor`.
    RelayEpochFloor,
    /// The `NetworkContract`.
    NetworkContract,
    /// The membership document (S-02).
    Membership,
}

impl DocumentType {
    /// Every type, in wire order.
    pub const ALL: [DocumentType; 7] = [
        DocumentType::PolicyBundle,
        DocumentType::OwnerTrustAnchor,
        DocumentType::TrustEpochBundle,
        DocumentType::RelayMap,
        DocumentType::RelayEpochFloor,
        DocumentType::NetworkContract,
        DocumentType::Membership,
    ];

    /// The wire value.
    #[must_use]
    pub const fn to_wire(self) -> i32 {
        match self {
            DocumentType::PolicyBundle => 1,
            DocumentType::OwnerTrustAnchor => 2,
            DocumentType::TrustEpochBundle => 3,
            DocumentType::RelayMap => 4,
            DocumentType::RelayEpochFloor => 5,
            DocumentType::NetworkContract => 6,
            DocumentType::Membership => 7,
        }
    }

    /// Decodes a wire value.
    ///
    /// Proto3 cannot distinguish "absent" from "zero", so a zero is a missing
    /// required field rather than a default to fill in.
    #[must_use]
    pub const fn from_wire(value: i32) -> Option<Self> {
        match value {
            1 => Some(DocumentType::PolicyBundle),
            2 => Some(DocumentType::OwnerTrustAnchor),
            3 => Some(DocumentType::TrustEpochBundle),
            4 => Some(DocumentType::RelayMap),
            5 => Some(DocumentType::RelayEpochFloor),
            6 => Some(DocumentType::NetworkContract),
            7 => Some(DocumentType::Membership),
            _ => None,
        }
    }

    /// A stable tag, matching the client's.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            DocumentType::PolicyBundle => "policy_bundle",
            DocumentType::OwnerTrustAnchor => "owner_trust_anchor",
            DocumentType::TrustEpochBundle => "trust_epoch_bundle",
            DocumentType::RelayMap => "relay_map",
            DocumentType::RelayEpochFloor => "relay_epoch_floor",
            DocumentType::NetworkContract => "network_contract",
            DocumentType::Membership => "membership",
        }
    }
}

/// S-02: one member of the `TwinNet`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    /// The device's permanent name. **Derived on-device**, echoed here.
    pub device_id: DeviceKey,
    /// The current `identity_id`; changes on IK rotation, `device_id` does not.
    pub identity_id: DeviceKey,
    /// COSE_Key octets of the identity public key. The uniqueness key for
    /// linearizable admission on `(twinnet_id, device_pubkey)`.
    pub identity_public_key: Vec<u8>,
    /// ADR-0007 N-22: **monotone**. A statement at or below the stored value is
    /// refused.
    pub generation: u32,
    /// The tunnel-key rotation counter, also monotone.
    pub tk_generation: u32,
    /// The `Owner`-chosen label. Unique within the `TwinNet` because it becomes
    /// a DNS label (ADR-0011 §11.3).
    pub label: String,
    /// ADR-0008 N-1's object version.
    pub version: u64,
    /// S-02's membership epoch.
    pub membership_epoch: u64,
    /// S-08: allocated once, immutable for the device's life.
    pub twinnet_addr_v4: [u8; 4],
    /// S-08, the other half. **Both are required**, on any underlay.
    pub twinnet_addr_v6: [u8; 16],
    /// The whole `Device` record as protobuf octets, for `DiscoverPeers` and
    /// the `PeerAdded`/`PeerUpdated` bodies.
    pub encoded: Vec<u8>,
    /// `false → true` only. ADR-0008 N-7 forbids the reverse.
    pub revoked: bool,
    /// The position this record last changed at.
    pub net_seq: u64,
    /// Creation time, evidence only.
    pub created_at_ms: u64,
}

/// S-04: the registered half of a `Pairing`. Each device owns its own
/// `TrustedPeer` half, which is `LOCAL` and has no row here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingRecord {
    /// The single-use id.
    pub pairing_id: PairingKey,
    /// Its terminal or pending state.
    pub state: PairingState,
    /// ADR-0008 N-1/N-2: `CompletePairing` carries an `if_version`.
    pub version: u64,
    /// ADR-0007 N-17: 120 s, enforced independently by both devices and the
    /// rendezvous — and here.
    pub expires_at_ms: u64,
    /// Who proposed it.
    pub initiator: DeviceKey,
    /// The recorded `PairingResult` octets, once the ceremony has an outcome.
    /// **This is the value a replay returns**, and returning a *different* one
    /// is what produces asymmetric trust.
    pub outcome: Option<Vec<u8>>,
    /// `limits.json pairing.max_failed_runs`.
    pub failed_attempts: u32,
}

/// The state of one `Pairing`.
///
/// Every transition out of `Pending` is **terminal**: a `pairing_id` is
/// single-use, and a cancelled or completed one is never reissued because
/// reissuing it would reset the 5-attempt budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingState {
    /// In flight.
    Pending,
    /// Completed. The recorded outcome is authoritative for every replay.
    Completed,
    /// Rejected by the responder.
    Rejected,
    /// Cancelled by a participant. Burns the id.
    Cancelled,
    /// Expired at `expires_at_ms`.
    Expired,
    /// Withdrawn after completion. Distinct from device revocation.
    Revoked,
}

impl PairingState {
    /// Whether the ceremony has finished.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, PairingState::Pending)
    }
}

/// ADR-0009 §11.3's per-document high-water record, plus the signed octets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentRecord {
    /// Monotone per `(twinnet_id, doc_type)`.
    pub version: u64,
    /// SHA-256 of the content, as it arrived. R-4 compares this on an equal
    /// version and calls a difference a **fork**.
    pub content_digest: [u8; 32],
    /// The signed octets, **verbatim**. Never re-encoded (W-4).
    pub octets: Vec<u8>,
    /// The position the document committed at.
    pub net_seq: u64,
    /// The trust generation in force when it was issued.
    pub trust_epoch: u64,
    /// Evidence only.
    pub issued_at_ms: u64,
}

/// S-30: a `RelayCapabilityToken` issuance record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTokenRecord {
    /// Whose token.
    pub device_id: DeviceKey,
    /// **Monotone.** A token below the device's known floor must not be used.
    pub epoch: u64,
    /// The issued token's octets, verbatim.
    pub octets: Vec<u8>,
    /// `limits.json relay.token_lifetime_ms` from issuance.
    pub not_after_ms: u64,
}

/// ADR-0008 N-5's dedup record.
///
/// The response is stored as the **encoded response octets** so a replay
/// returns it *verbatim* rather than re-deriving something that might differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyRecord {
    /// Which command minted it. A key reused across commands is a client bug and
    /// is refused rather than served the other command's answer.
    pub command: crate::Command,
    /// The recorded response octets, replayed verbatim.
    pub response: Vec<u8>,
    /// The position the original effect committed at.
    pub committed_at_net_seq: u64,
    /// When the record was written; the window is measured from here.
    pub stored_at_ms: u64,
}

/// One appended durable event, as the log holds it.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredEvent {
    /// Dense and monotone per `twinnet_id`.
    pub net_seq: u64,
    /// The event type; the `CHECK` constraint's left-hand side.
    pub event_type: crate::EventKind,
    /// The sole publisher; the `CHECK` constraint's right-hand side.
    pub publisher: crate::Publisher,
    /// The encoded `ControlEvent`.
    pub encoded: Vec<u8>,
    /// Wall-clock commit time. **Evidence only, never a timer input.**
    pub committed_at_ms: u64,
}

/// Everything one `TwinNet` owns.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NetState {
    /// The `TwinNet` scope. There is no cross-`TwinNet` ordering (C-5).
    pub twinnet_id: String,
    /// S-26: the next position to allocate. Allocated **inside** the mutating
    /// transaction (N-3).
    pub next_net_seq: u64,
    /// S-03: the `TwinNet`-wide trust generation. **Never decreases** (R-6).
    pub trust_epoch: u64,
    /// S-28: the fencing token of the writer that holds the lease.
    pub shard_epoch: u64,
    /// S-06: the current policy version.
    pub policy_version: u64,
    /// S-02.
    pub devices: BTreeMap<DeviceKey, DeviceRecord>,
    /// S-03's **never-shrinking** revoked set (ADR-0008 N-7).
    pub revoked: BTreeSet<DeviceKey>,
    /// S-04.
    pub pairings: BTreeMap<PairingKey, PairingRecord>,
    /// S-16, per advertiser. Monotone `advertisement_epoch`.
    pub route_epochs: BTreeMap<DeviceKey, u64>,
    /// The current advertised set per advertiser, as verbatim signed octets.
    pub route_sets: BTreeMap<DeviceKey, Vec<u8>>,
    /// Monotone `offer_epoch`, per offerer.
    pub offer_epochs: BTreeMap<DeviceKey, u64>,
    /// The current exit-node offer per offerer, as verbatim signed octets.
    pub offer_sets: BTreeMap<DeviceKey, Vec<u8>>,
    /// The warehoused signed documents.
    pub documents: BTreeMap<DocumentType, DocumentRecord>,
    /// S-30.
    pub relay_tokens: BTreeMap<DeviceKey, RelayTokenRecord>,
    /// ADR-0008 N-5, keyed by `(device_id, idempotency_key)` — the scoping N-4
    /// requires, so one device cannot replay another's ceremony.
    pub idempotency: BTreeMap<(DeviceKey, Vec<u8>), IdempotencyRecord>,
    /// The append-only log. `net_seq` is dense within it.
    pub events: Vec<StoredEvent>,
    /// The lowest `net_seq` still retained. A cursor below it is
    /// `CONTROL.CURSOR_TOO_OLD`.
    pub retained_from: u64,
    /// The next free `/32` offset inside `100.64.0.0/10` (S-08).
    pub next_v4_offset: u32,
}

impl NetState {
    /// An empty `TwinNet`.
    ///
    /// `next_net_seq` starts at **1**: `net_seq == 0` means "no position", and a
    /// durable event carrying it is a defect the client refuses outright.
    #[must_use]
    pub fn new(twinnet_id: impl Into<String>) -> Self {
        Self {
            twinnet_id: twinnet_id.into(),
            next_net_seq: 1,
            shard_epoch: 1,
            retained_from: 1,
            next_v4_offset: 1,
            ..Self::default()
        }
    }

    /// The highest allocated position, or `0` before the first append.
    #[must_use]
    pub const fn head_net_seq(&self) -> u64 {
        self.next_net_seq - 1
    }

    /// Whether `device_id` is in the never-shrinking revoked set.
    #[must_use]
    pub fn is_revoked(&self, device_id: &DeviceKey) -> bool {
        self.revoked.contains(device_id)
    }

    /// The device already admitted for this identity public key, if any.
    ///
    /// This is the lookup that makes `RegisterDevice` linearizable on
    /// `(twinnet_id, device_pubkey)`: a duplicate enrol finds the same row and
    /// returns the same `device_id` rather than minting a second device.
    #[must_use]
    pub fn device_by_public_key(&self, key: &[u8]) -> Option<&DeviceRecord> {
        self.devices.values().find(|d| d.identity_public_key == key)
    }

    /// Whether a label is already taken by a different device.
    #[must_use]
    pub fn label_taken_by_other(&self, label: &str, by: &DeviceKey) -> bool {
        self.devices
            .values()
            .any(|d| d.label == label && &d.device_id != by && !d.revoked)
    }
}

#[cfg(test)]
mod tests {
    use super::{DocumentType, NetState, PairingState};

    #[test]
    fn a_fresh_net_starts_at_position_one() {
        // net_seq == 0 means "no position". A durable event carrying it is a
        // defect twinvpn-cp-client refuses outright, so the counter must never
        // hand one out.
        let n = NetState::new("tn");
        assert_eq!(n.next_net_seq, 1);
        assert_eq!(n.head_net_seq(), 0);
    }

    #[test]
    fn every_pairing_state_but_pending_is_terminal() {
        assert!(!PairingState::Pending.is_terminal());
        for s in [
            PairingState::Completed,
            PairingState::Rejected,
            PairingState::Cancelled,
            PairingState::Expired,
            PairingState::Revoked,
        ] {
            assert!(s.is_terminal(), "{s:?} must burn the pairing_id");
        }
    }

    #[test]
    fn the_document_types_match_the_client() {
        // `policy.proto`'s StateDocumentType, which is also
        // twinvpn-cp-client's `state::DocumentType`. A disagreement here
        // warehouses a policy under the relay map's high-water mark.
        assert_eq!(DocumentType::PolicyBundle.to_wire(), 1);
        assert_eq!(DocumentType::OwnerTrustAnchor.to_wire(), 2);
        assert_eq!(DocumentType::TrustEpochBundle.to_wire(), 3);
        assert_eq!(DocumentType::RelayMap.to_wire(), 4);
        assert_eq!(DocumentType::RelayEpochFloor.to_wire(), 5);
        assert_eq!(DocumentType::NetworkContract.to_wire(), 6);
        assert_eq!(DocumentType::Membership.to_wire(), 7);
        for wire in 1..=7 {
            let t = DocumentType::from_wire(wire).expect("declared");
            assert_eq!(t.to_wire(), wire);
        }
        assert!(DocumentType::from_wire(0).is_none());
        assert!(DocumentType::from_wire(99).is_none());
        assert_eq!(DocumentType::ALL.len(), 7);
    }
}
