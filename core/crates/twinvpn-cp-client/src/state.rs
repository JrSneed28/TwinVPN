//! The state this crate caches, and the vocabulary the store speaks.
//!
//! **Authority:** `contracts/proto/twinvpn/v1/policy.proto` (`StateDocumentType`,
//! `StateDocumentRef`), ADR-0009 §11.3 (the document header and its monotone
//! rules), `docs/architecture.md` §4.4.1 (the pre-materialization rule),
//! §5 rows S-02, S-05, S-06, S-15, S-27.
//!
//! These types are the *shape* of what crosses into
//! [`crate::ports::ControlPlaneStore`] — the only bridge between the planes
//! (CD-I5). They are deliberately separate from the traits in
//! [`crate::ports`]: when `core-security` lands the real `twinvpn-store`, the
//! traits are replaced and these types are what the adapter maps.

use twinvpn_types::{DeviceId, PolicyId};

/// A signed state document's stored identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredDocumentMark {
    /// The monotone version we hold.
    pub version: u64,
    /// The content digest at that version — the ADR-0009 R-4 fork detector.
    pub content_digest: [u8; 32],
    /// When it was issued, from the signed payload.
    pub issued_at_ms: u64,
    /// The `refresh_after` band boundary.
    pub refresh_after_ms: u64,
    /// The `not_after` band boundary.
    pub not_after_ms: u64,
}

/// The document types this crate pulls and stores. Mirrors
/// `policy.proto`'s `StateDocumentType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DocumentType {
    /// The Owner-signed `PolicyBundle`.
    PolicyBundle,
    /// The pinned `OwnerTrustAnchor` (S-32).
    OwnerTrustAnchor,
    /// The `TrustEpochBundle`.
    TrustEpochBundle,
    /// The signed relay map (S-09).
    RelayMap,
    /// The relay `epoch_floor`.
    RelayEpochFloor,
    /// The `NetworkContract`.
    NetworkContract,
    /// The membership document (S-02).
    Membership,
}

impl DocumentType {
    /// A stable tag for the `doc_type` evidence field.
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

    /// Decodes the wire enum, rejecting `UNSPECIFIED`.
    ///
    /// Proto3 cannot distinguish "absent" from "zero", so a zero here is a
    /// missing required field rather than a default to fill in.
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
}

/// The minimum a cached peer must carry for an offline reconnect to work.
///
/// `architecture.md` §4.4.1's pre-materialization rule enumerates the whole set;
/// the entries below are the ones the **control-plane client** is the source of.
/// `PairSecret` and the `EpochSeed` set are `core-security`'s and never appear in
/// this crate — I4 keeps them out of the core's reach entirely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedPeer {
    /// The peer's permanent name.
    pub device_id: DeviceId,
    /// The identity generation we last saw. `highest_generation_seen`; a
    /// statement at or below it is refused (ADR-0007 N-22).
    pub generation: u32,
    /// `highest_tk_generation_seen`, tracked separately because a TK rotation
    /// does not change `DeviceIdentity`.
    pub tk_generation: u32,
    /// Whether the peer's `TunnelKeyBinding` verified. A peer whose binding has
    /// not verified is **not** a `TrustedPeer`: skipping the check is a full
    /// authentication bypass (ADR-0007 N-4).
    pub tunnel_key_binding_verified: bool,
    /// Cached endpoints (S-15) — what a reconnect during a total outage uses.
    pub endpoints: Vec<twinvpn_types::Endpoint>,
    /// The peer's overlay addresses. **Both families, always** (ADR-0010 R1).
    pub overlay: twinvpn_types::OverlayAddresses,
}

impl CachedPeer {
    /// Whether this cached record alone is enough to re-establish a session with
    /// the control plane entirely down.
    ///
    /// `reliability.md` §9.1: a **new** `Session` to an existing `TrustedPeer`,
    /// from the durable `Endpoint` cache, "continues, indefinitely". This is the
    /// client-side half of that promise, and it deliberately does not consult
    /// any staleness band — §9.2's rule is grant/deny asymmetry, not a credential
    /// cliff, and baseline reachability is not a grant.
    #[must_use]
    pub fn supports_offline_reconnect(&self) -> bool {
        self.tunnel_key_binding_verified && !self.endpoints.is_empty()
    }
}

/// The Owner policy view the cache exposes to the rest of the core.
///
/// Deliberately **not** the decoded `PolicyBundle`: `policy.proto` is explicit
/// that the decoded fields are "a VIEW" and that enforcement must read the
/// verified payload. This struct carries only what the client itself must reason
/// about — the version, the lifetime, and the policy identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyMark {
    /// Monotone. A bundle at or below the stored version is a rollback attack.
    pub policy_version: u64,
    /// The document lineage, constant across versions.
    pub policy_id: PolicyId,
    /// The bundle's own upper bound.
    pub not_after_ms: u64,
    /// When it was issued.
    pub issued_at_ms: u64,
}
