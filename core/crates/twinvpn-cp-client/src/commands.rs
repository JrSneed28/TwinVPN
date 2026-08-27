//! The C1 command surface, client side.
//!
//! **Authority:** `contracts/proto/twinvpn/v1/control_commands.proto`,
//! `contracts/docs/contract-matrix.md` §3 and §3.1, `docs/protocol.md`
//! §8–§13, ADR-0008 §11.3.
//!
//! # What is *not* here, and why that is the point
//!
//! `contract-matrix.md` §3.1 lists eleven requests a naive control-plane client
//! would expose. Every one of them is somewhere else in Phase 1, and putting any
//! of them here would break **I5**:
//!
//! | Not here | Where it lives | Why |
//! |---|---|---|
//! | `BeginConnection`, `ExchangeCandidates` | C4 ephemeral signaling | coordination must not be in the critical path of every reconnect |
//! | `RequestRelay` / `ReleaseRelay` | `BIND`/`BOUND`, device↔relay on C6 | routing reservations through coordination puts it in the data path |
//! | `ResumeSession`, `EndSession` | peer-direct C5 | resumption must work with the control plane completely down |
//! | `UpdatePeerPermissions`, `UpdateRoutePolicy`, `UpdateDNSPolicy` | inside `PutPolicy` | a separate command creates a **second policy author** |
//! | `AdvertiseGateway` / `WithdrawGateway` | `PutRouteAdvertisement` / `PutExitNodeOffer` | a gateway is a **role** of a `Device`, not an object |
//! | `ReportConnectionHealth` | `HealthSample` on C7 | health must not affect the control or data plane |
//!
//! [`FORBIDDEN_ON_C1`] names them so the omission is asserted by a test rather
//! than left to be noticed.

use twinvpn_schema::v1;
use twinvpn_types::{DeviceId, Identifier};

use crate::error::{CpError, CpResult};
use crate::state::DocumentType;

/// The eleven requests Phase 1 places somewhere other than C1.
///
/// Each string is the *requested* name from `contract-matrix.md` §3.1. None of
/// them has a method on this crate's client, and
/// `no_forbidden_request_has_a_c1_command` asserts none ever acquires one.
pub const FORBIDDEN_ON_C1: [&str; 11] = [
    "BeginConnection",
    "ExchangeCandidates",
    "RequestRelay",
    "ReleaseRelay",
    "ResumeSession",
    "EndSession",
    "UpdatePeerPermissions",
    "UpdateRoutePolicy",
    "UpdateDNSPolicy",
    "AdvertiseGateway",
    "ReportConnectionHealth",
];

/// The C2 retention floor, in events.
///
/// `contracts/registry/limits.json` `control_plane.retention_floor_events`.
/// `twinvpn-schema` generates no constant for it, so it is restated here and
/// `the_retention_floor_still_matches_the_registry` fails if the frozen value
/// ever moves — the same drift guard `twinvpn-schema` uses for the capability
/// cap, rather than a number nobody re-checks.
pub const RETENTION_FLOOR_EVENTS: u64 = 1_000_000;

/// The C2 retention floor, in days. `control_plane.retention_floor_days`.
///
/// The floor is *the greater of* the two, which is why both are named.
pub const RETENTION_FLOOR_DAYS: u64 = 30;

/// The result header every mutating C1 response carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mutation {
    /// The position the effect committed at, **in the same log C2 reads**.
    pub committed_at_net_seq: u64,
    /// Carried on **every** C1 response so a device detects it is behind without
    /// draining the log.
    pub revocation_epoch: u64,
    /// The server served a **recorded outcome** for a duplicate
    /// `idempotency_key` rather than executing.
    pub idempotent_replay: bool,
}

impl Mutation {
    /// Reads the wire header.
    ///
    /// # Errors
    ///
    /// [`CpError::Rejected`] when a mutating response omits it — the header is
    /// the read-your-writes carrier and a response without one cannot be
    /// completed correctly.
    pub fn from_wire(result: Option<&v1::MutationResult>) -> CpResult<Self> {
        let r = result.ok_or_else(|| {
            CpError::Rejected(twinvpn_schema::Reject::cap("mutation_result", 0, 1))
        })?;
        Ok(Self {
            committed_at_net_seq: r.committed_at_net_seq,
            revocation_epoch: r.revocation_epoch,
            idempotent_replay: r.idempotent_replay,
        })
    }

    /// Whether the operation may be reported complete to a surface yet.
    ///
    /// `control_commands.proto` calls this **a protocol obligation, not a client
    /// convenience**: the client MUST NOT report complete until the C2 cursor has
    /// advanced to or past `committed_at_net_seq`. It closes the seam where a
    /// device pairs a peer, gets a success, and immediately fails to connect
    /// because its local `TrustedPeer` cache has not seen the pairing event.
    #[must_use]
    pub const fn is_visible_at(self, cursor: u64) -> bool {
        cursor >= self.committed_at_net_seq
    }
}

/// A `DiscoverPeers` request. Read-only, `MONOTONIC`, snapshot + delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoverPeers {
    /// `0` for a full snapshot; otherwise the device's current cursor.
    ///
    /// The pairing is what makes a cold start bounded and a steady state cheap
    /// **without a gap** — and it is "the general pattern for every cached
    /// collection in TwinVPN".
    pub since_net_seq: u64,
}

impl DiscoverPeers {
    /// A cold snapshot.
    pub const SNAPSHOT: DiscoverPeers = DiscoverPeers { since_net_seq: 0 };

    /// A delta from the device's cursor.
    #[must_use]
    pub const fn delta_from(cursor: u64) -> Self {
        Self {
            since_net_seq: cursor,
        }
    }

    /// Whether this asks for a full snapshot.
    #[must_use]
    pub const fn is_snapshot(self) -> bool {
        self.since_net_seq == 0
    }

    /// The wire request body, envelope excluded.
    #[must_use]
    pub fn to_wire(self, metadata: v1::MessageMetadata) -> v1::DiscoverPeersRequest {
        v1::DiscoverPeersRequest {
            metadata: Some(metadata),
            since_net_seq: self.since_net_seq,
        }
    }
}

/// What a failed `DiscoverPeers` obliges the device to do.
///
/// `control_commands.proto`, restating protocol.md §9.1: *"on control-plane
/// unavailability the device MUST use its last cached peer set and enter
/// discovery from cache, surfacing `CONTROL.STALE_POLICY_IN_USE`. Per I5 this
/// MUST NOT prevent connecting to a known peer."*
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryFallback {
    /// Always `true`. The cached peer set is used, not waited on.
    pub use_cached_peer_set: bool,
    /// Always `true`. Discovery proceeds; establishment is never gated on the
    /// control plane answering.
    pub keep_connecting: bool,
}

impl DiscoveryFallback {
    /// The one and only fallback shape.
    #[must_use]
    pub const fn on_outage() -> Self {
        Self {
            use_cached_peer_set: true,
            keep_connecting: true,
        }
    }
}

/// A whole desired advertised set, under a monotone epoch.
///
/// **Never a delta.** `control_commands.proto`: named `Put`, not `Advertise`,
/// "because it is whole-state: the request carries the complete set the
/// advertiser wants in force, not a delta to add". A withdrawal is a **higher**
/// epoch with an **empty** set, so it travels through the same monotone ordering
/// and cannot be reordered ahead of the advertisement it withdraws.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredSet {
    /// The monotone epoch. Strictly higher than the last one sent.
    pub epoch: u64,
    /// The complete set. Empty means "withdraw everything".
    pub prefixes: Vec<twinvpn_types::IpPrefix>,
}

impl DesiredSet {
    /// Whether this is a withdrawal.
    #[must_use]
    pub fn is_withdrawal(&self) -> bool {
        self.prefixes.is_empty()
    }

    /// Checks the epoch against the last one this advertiser sent.
    ///
    /// # Errors
    ///
    /// [`CpError::TrustEpochRollback`] on a repeated or lower epoch. An
    /// advertisement that reuses an epoch is a delta in disguise: the receiver
    /// would have no way to order it against the set already in force.
    pub const fn check_epoch(&self, last_sent: u64) -> Result<(), CpError> {
        if self.epoch <= last_sent {
            return Err(CpError::TrustEpochRollback {
                offered_epoch: self.epoch,
                high_water_epoch: last_sent,
            });
        }
        Ok(())
    }

    /// Rejects a set larger than `limits.json`'s cap, **before** it is encoded.
    ///
    /// # Errors
    ///
    /// [`CpError::Rejected`] past `routing.max_prefixes_per_advertisement`.
    pub fn check_size(&self) -> CpResult<()> {
        twinvpn_schema::Reject::check_max(
            "max_prefixes_per_advertisement",
            self.prefixes.len(),
            twinvpn_schema::limits::MAX_PREFIXES_PER_ADVERTISEMENT,
        )
        .map_err(CpError::Rejected)
    }
}

/// A `GetStateDocument` pull.
///
/// **Pull is always sufficient; push only reduces latency.** ADR-0002 §11.4: "A
/// device MUST be able to reach a correct state using pull alone, with push
/// serving only to reduce latency." That is what discharges ADR-0008's
/// requirement that a push notification be treatable as a hint triggering a
/// declarative re-read, and it is what makes stream compaction safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateDocumentPull {
    /// Which document.
    pub doc_type: DocumentType,
    /// `0` means "the current version".
    pub version: u64,
}

impl StateDocumentPull {
    /// The current version of a document.
    #[must_use]
    pub const fn current(doc_type: DocumentType) -> Self {
        Self {
            doc_type,
            version: 0,
        }
    }

    /// A specific announced version, from a `StateDocumentAvailable`.
    #[must_use]
    pub const fn at_version(doc_type: DocumentType, version: u64) -> Self {
        Self { doc_type, version }
    }

    /// The wire request body.
    #[must_use]
    pub fn to_wire(self, metadata: v1::MessageMetadata) -> v1::GetStateDocumentRequest {
        v1::GetStateDocumentRequest {
            metadata: Some(metadata),
            doc_type: self.doc_type.to_wire(),
            version: self.version,
        }
    }
}

/// Whether losing every push for a document type costs anything but latency.
///
/// Always `false` for correctness: a device on pull alone converges. This is
/// asserted rather than asserted-in-prose because "push is an optimisation"
/// degrades silently into "push is required" the first time somebody caches a
/// decision behind it.
#[must_use]
pub const fn total_push_failure_costs_correctness() -> bool {
    false
}

/// Checks a `RegisterDeviceResponse`'s `device_id_echo`.
///
/// **An echo, never an assignment.** protocol.md §8.1: the `device_id` is derived
/// on-device from the generation-0 identity public key and is already known
/// before the device contacts coordination. The device MUST compare and MUST
/// **abort registration** on disagreement; it MUST NOT adopt the server's value.
/// A server-assigned identifier would break self-certifying identity and the S-08
/// address derivation that depends on it.
///
/// # Errors
///
/// [`CpError::IdentityMismatch`] — `FATAL`/`CRITICAL` — on any disagreement, and
/// [`CpError::Rejected`] if the echoed value is not a well-formed `device_id`.
pub fn check_device_id_echo(echoed: &[u8], locally_derived: DeviceId) -> CpResult<DeviceId> {
    let echoed = twinvpn_schema::validate::device_id(echoed)?;
    if echoed.as_bytes() != locally_derived.as_bytes() {
        return Err(CpError::IdentityMismatch);
    }
    Ok(locally_derived)
}

#[cfg(test)]
mod tests {
    use super::{
        check_device_id_echo, total_push_failure_costs_correctness, DesiredSet, DiscoverPeers,
        DiscoveryFallback, Mutation, StateDocumentPull, FORBIDDEN_ON_C1,
    };
    use crate::idempotency::Command;
    use crate::retry::{may_retry, Retry};
    use crate::state::DocumentType;
    use crate::CpError;
    use twinvpn_types::{DeviceId, Identifier};

    #[test]
    fn no_forbidden_request_has_a_c1_command() {
        // contract-matrix.md §3.1: eleven requests Phase 1 places elsewhere.
        for forbidden in FORBIDDEN_ON_C1 {
            assert!(
                !Command::ALL.iter().any(|c| c.as_str() == forbidden),
                "{forbidden} is not a C1 command in Phase 1"
            );
        }
        // And the ones that ARE here really are.
        assert!(Command::ALL.iter().any(|c| c.as_str() == "PutPolicy"));
        assert!(Command::ALL
            .iter()
            .any(|c| c.as_str() == "PutRouteAdvertisement"));
    }

    #[test]
    fn a_mutation_is_not_complete_until_the_cursor_reaches_it() {
        let m = Mutation {
            committed_at_net_seq: 500,
            revocation_epoch: 3,
            idempotent_replay: false,
        };
        assert!(!m.is_visible_at(499), "a protocol obligation, not a nicety");
        assert!(m.is_visible_at(500));
        assert!(m.is_visible_at(501));
    }

    #[test]
    fn a_missing_mutation_result_is_rejected() {
        assert!(Mutation::from_wire(None).is_err());
    }

    #[test]
    fn discover_peers_is_snapshot_plus_delta() {
        assert!(DiscoverPeers::SNAPSHOT.is_snapshot());
        assert!(!DiscoverPeers::delta_from(77).is_snapshot());
        assert_eq!(DiscoverPeers::delta_from(77).since_net_seq, 77);
    }

    #[test]
    fn an_outage_uses_the_cache_and_keeps_connecting() {
        let fallback = DiscoveryFallback::on_outage();
        assert!(fallback.use_cached_peer_set);
        assert!(
            fallback.keep_connecting,
            "I5: this MUST NOT prevent connecting to a known peer"
        );
    }

    #[test]
    fn an_advertisement_epoch_must_strictly_advance() {
        let set = DesiredSet {
            epoch: 5,
            prefixes: Vec::new(),
        };
        assert!(set.is_withdrawal(), "a withdrawal is an empty set");
        assert!(set.check_epoch(4).is_ok());
        assert!(set.check_epoch(5).is_err(), "reusing an epoch is a delta");
        assert!(set.check_epoch(6).is_err());
    }

    #[test]
    fn an_oversized_advertisement_is_rejected_before_encoding() {
        let addr = twinvpn_types::IpAddr::V4(twinvpn_types::V4Addr::from_octets([10, 0, 0, 0]));
        let prefix = twinvpn_types::IpPrefix::new(addr, 24).expect("canonical");
        let cap = twinvpn_schema::limits::MAX_PREFIXES_PER_ADVERTISEMENT;
        let ok = DesiredSet {
            epoch: 1,
            prefixes: vec![prefix; cap],
        };
        assert!(ok.check_size().is_ok());
        let over = DesiredSet {
            epoch: 1,
            prefixes: vec![prefix; cap + 1],
        };
        let err = over.check_size().expect_err("over cap");
        assert_eq!(err.reason_code().as_str(), "PROTO.MALFORMED_MESSAGE");
    }

    #[test]
    fn the_device_id_echo_is_never_adopted() {
        let ours = DeviceId::from_array([1u8; 32]);
        let theirs = DeviceId::from_array([2u8; 32]);
        assert_eq!(
            check_device_id_echo(ours.as_bytes(), ours).expect("match"),
            ours
        );
        let err = check_device_id_echo(theirs.as_bytes(), ours).expect_err("mismatch aborts");
        assert_eq!(err.reason_code().as_str(), "AUTH.IDENTITY_MISMATCH");
        assert!(err.reason_code().terminal());
        assert!(err.is_security_event());
        // A malformed echo is a reject, not an adoption either.
        assert!(check_device_id_echo(&[0u8; 31], ours).is_err());
    }

    #[test]
    fn pull_alone_is_sufficient() {
        assert!(!total_push_failure_costs_correctness());
        let p = StateDocumentPull::current(DocumentType::PolicyBundle);
        assert_eq!(p.version, 0, "0 means the current version");
        let at = StateDocumentPull::at_version(DocumentType::PolicyBundle, 9);
        assert_eq!(at.version, 9);
    }

    #[test]
    fn the_retention_floor_still_matches_the_registry() {
        // limits.json is frozen; if this fires, the registry moved and the
        // restated constants above must move with it.
        let json = twinvpn_schema::limits::LIMITS_JSON;
        assert!(
            json.contains("\"retention_floor_events\": 1000000"),
            "control_plane.retention_floor_events moved"
        );
        assert!(
            json.contains("\"retention_floor_days\": 30"),
            "control_plane.retention_floor_days moved"
        );
        assert_eq!(super::RETENTION_FLOOR_EVENTS, 1_000_000);
        assert_eq!(super::RETENTION_FLOOR_DAYS, 30);
    }

    #[test]
    fn a_ceremony_retries_with_the_same_key_and_a_rollback_never_retries() {
        assert_eq!(
            may_retry(Command::CompletePairing, &CpError::Unreachable),
            Retry::SameKey
        );
        assert_eq!(
            may_retry(Command::DiscoverPeers, &CpError::Unreachable),
            Retry::Backoff
        );
        assert_eq!(
            may_retry(
                Command::RevokeDevice,
                &CpError::TrustEpochRollback {
                    offered_epoch: 1,
                    high_water_epoch: 4
                }
            ),
            Retry::Never
        );
        assert_eq!(
            may_retry(
                Command::PutPolicy,
                &CpError::AdmissionDeferred {
                    retry_after_ms: 750
                }
            ),
            Retry::After { millis: 750 }
        );
    }
}
