//! C2 events: what is durable, what is ephemeral, and who may publish each.
//!
//! **Authority:** `docs/protocol.md` §6 (the four-part test), §7 (single
//! publisher per event type), `contracts/docs/contract-matrix.md` §4,
//! `contracts/proto/twinvpn/v1/control_events.proto`, ADR-0002 N-5, N-6, N-8,
//! N-9 and S-4.
//!
//! # The producer half of `twinvpn-cp-client`'s `events::classify`
//!
//! The client classifies what it receives; this classifies what it emits. The
//! two tables are the same table, and
//! `tests/client_agreement.rs::every_event_kind_has_the_durability_the_client_expects`
//! reads the client's own table as text and fails if they ever disagree. That is
//! not a style check: a durable event delivered as ephemeral is the failure
//! `contract-matrix.md` §1 calls a **security** failure, and it is undetectable
//! from either side alone.
//!
//! # Making the wrong publisher structurally unable to append
//!
//! `protocol.md` §7 says sole-publisher is enforced *at the log*, not by
//! convention. Three layers do it here, and they fail independently:
//!
//! 1. **Construction.** [`DurableEvent::new`] takes an [`EventKind`] and a body
//!    and stamps `publisher = kind.sole_publisher()`. There is no `publisher`
//!    parameter and no setter, so ordinary code cannot express a wrong
//!    publisher. The only way to build one is
//!    [`DurableEvent::forged_for_test`], which is `#[cfg(any(test, feature = …))]`
//!    and exists so layer 2 has something to reject.
//! 2. **Append.** [`DurableEvent::check_publisher`] runs on every append and
//!    returns `CONTROL.EVENT_WRONG_PUBLISHER` — a `FATAL`/`CRITICAL` security
//!    event — on a mismatch.
//! 3. **Schema.** `migrations/0002_event_log.sql` carries a `CHECK` constraint
//!    mapping `event_type` to `publisher_principal`, so a write that reached the
//!    database by any other path is still refused by the database.

use twinvpn_schema::v1;
use twinvpn_schema::v1::control_event::Event as EventBody;
use twinvpn_service_common::{Correlation, ServiceError};

/// How an event is delivered and retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Durability {
    /// Written to the per-`TwinNet` log, assigned a `net_seq`, cursor-resumable,
    /// at-least-once, retained ≥ 30 days or 10^6 events.
    Durable,
    /// Delivered on C2 for latency only. **Not logged, not assigned a
    /// `net_seq`, not resumable, not replayed** (ADR-0002 N-9).
    Ephemeral,
}

impl Durability {
    /// The `EventDurability` wire value.
    #[must_use]
    pub const fn to_wire(self) -> i32 {
        match self {
            Durability::Durable => 1,
            Durability::Ephemeral => 2,
        }
    }
}

/// The sole publisher of an event type (protocol.md §7 / **I8**).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Publisher {
    /// The coordination service — this process.
    CoordinationService,
    /// The device that owns the fact. **No C2 event type has this publisher**;
    /// the variant exists because `control_events.proto` declares it and because
    /// a receiver must be able to name what it observed when refusing one.
    OriginatingDevice,
}

impl Publisher {
    /// The `EventPublisher` wire value.
    #[must_use]
    pub const fn to_wire(self) -> i32 {
        match self {
            Publisher::CoordinationService => 1,
            Publisher::OriginatingDevice => 2,
        }
    }

    /// A stable tag for the `observed_publisher` evidence field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Publisher::CoordinationService => "coordination_service",
            Publisher::OriginatingDevice => "originating_device",
        }
    }
}

/// One C2 event type.
///
/// A closed enum rather than a string, so the sole-publisher table and the
/// durability table are total matches and a new event in a future contract
/// revision is a compile error rather than an event that inherits a default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum EventKind {
    /// `DeviceRegistered`.
    DeviceRegistered,
    /// `DeviceMetadataUpdated`.
    DeviceMetadataUpdated,
    /// `DeviceRevoked` — carries an `Owner`-signed statement.
    DeviceRevoked,
    /// `DeviceCredentialRotated` — carries a device-signed statement.
    DeviceCredentialRotated,
    /// `PairingRequested`.
    PairingRequested,
    /// `PairingApproved` — carries a device-signed attestation.
    PairingApproved,
    /// `PairingRejected`.
    PairingRejected,
    /// `PairingExpired`.
    PairingExpired,
    /// `PairingRevoked`.
    PairingRevoked,
    /// `PeerAdded`.
    PeerAdded,
    /// `PeerUpdated`.
    PeerUpdated,
    /// `PeerRemoved`.
    PeerRemoved,
    /// `PolicyBundleUpdated` — carries an `Owner`-signed bundle.
    PolicyBundleUpdated,
    /// `RouteAdvertised` — carries the advertiser's signed statement.
    RouteAdvertised,
    /// `RouteWithdrawn`.
    RouteWithdrawn,
    /// `ExitNodeAdvertised`.
    ExitNodeAdvertised,
    /// `ExitNodeWithdrawn`.
    ExitNodeWithdrawn,
    /// `RelayRegionPolicyChanged`.
    RelayRegionPolicyChanged,
    /// `RelayEpochFloorAdvanced` — carries an `Owner`-signed floor.
    RelayEpochFloorAdvanced,
    /// `StreamCompacted` — **in band and in order**; silent omission is
    /// prohibited (N-8).
    StreamCompacted,
    /// `StateDocumentAvailable` — a document above the 16 KiB inline cap exists.
    StateDocumentAvailable,
    /// `LogHead` — a freshness proof signed by an **online** key with no trust
    /// power.
    LogHead,
    /// `PresenceUpdated`.
    PresenceUpdated,
    /// `RelayAssignmentHint`.
    RelayAssignmentHint,
}

impl EventKind {
    /// Every event type this service may publish.
    pub const ALL: [EventKind; 24] = [
        EventKind::DeviceRegistered,
        EventKind::DeviceMetadataUpdated,
        EventKind::DeviceRevoked,
        EventKind::DeviceCredentialRotated,
        EventKind::PairingRequested,
        EventKind::PairingApproved,
        EventKind::PairingRejected,
        EventKind::PairingExpired,
        EventKind::PairingRevoked,
        EventKind::PeerAdded,
        EventKind::PeerUpdated,
        EventKind::PeerRemoved,
        EventKind::PolicyBundleUpdated,
        EventKind::RouteAdvertised,
        EventKind::RouteWithdrawn,
        EventKind::ExitNodeAdvertised,
        EventKind::ExitNodeWithdrawn,
        EventKind::RelayRegionPolicyChanged,
        EventKind::RelayEpochFloorAdvanced,
        EventKind::StreamCompacted,
        EventKind::StateDocumentAvailable,
        EventKind::LogHead,
        EventKind::PresenceUpdated,
        EventKind::RelayAssignmentHint,
    ];

    /// What `protocol.md` §6's four-part test decided, per
    /// `contract-matrix.md` §4.
    #[must_use]
    pub const fn durability(self) -> Durability {
        match self {
            // §4.1 — each fails at least one of the four checks.
            EventKind::DeviceRegistered
            | EventKind::DeviceMetadataUpdated
            | EventKind::DeviceRevoked
            | EventKind::DeviceCredentialRotated
            | EventKind::PairingRequested
            | EventKind::PairingApproved
            | EventKind::PairingRejected
            | EventKind::PairingExpired
            | EventKind::PairingRevoked
            | EventKind::PeerAdded
            | EventKind::PeerUpdated
            | EventKind::PeerRemoved
            | EventKind::PolicyBundleUpdated
            | EventKind::RouteAdvertised
            | EventKind::RouteWithdrawn
            | EventKind::ExitNodeAdvertised
            | EventKind::ExitNodeWithdrawn
            | EventKind::RelayRegionPolicyChanged
            | EventKind::RelayEpochFloorAdvanced
            // §4.3 — a gap announcement that could be reordered or dropped is a
            // silent omission, which N-8 prohibits. So it occupies a position.
            | EventKind::StreamCompacted => Durability::Durable,
            // §4.2 and §4.3 — net_seq == 0, not logged, not resumable.
            EventKind::StateDocumentAvailable
            | EventKind::LogHead
            | EventKind::PresenceUpdated
            | EventKind::RelayAssignmentHint => Durability::Ephemeral,
        }
    }

    /// The sole publisher, from `protocol.md` §7.
    ///
    /// Every row is the coordination service, **including** the rows that
    /// transport a statement it cannot forge: `RouteAdvertised` is *published*
    /// by coordination and *authored* by the advertiser, and conflating the two
    /// is exactly the capability Rule B removes from the infrastructure.
    #[must_use]
    pub const fn sole_publisher(self) -> Publisher {
        Publisher::CoordinationService
    }

    /// Whether this event carries a statement this service did not author and
    /// must therefore forward **verbatim** (finding W-4).
    #[must_use]
    pub const fn carries_signed_statement(self) -> bool {
        matches!(
            self,
            EventKind::DeviceRevoked
                | EventKind::DeviceCredentialRotated
                | EventKind::PairingApproved
                | EventKind::PolicyBundleUpdated
                | EventKind::RouteAdvertised
                | EventKind::RouteWithdrawn
                | EventKind::ExitNodeAdvertised
                | EventKind::ExitNodeWithdrawn
                | EventKind::RelayEpochFloorAdvanced
                | EventKind::LogHead
        )
    }

    /// A stable tag, matching the client's `EventClass::event_type` exactly.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            EventKind::DeviceRegistered => "device_registered",
            EventKind::DeviceMetadataUpdated => "device_metadata_updated",
            EventKind::DeviceRevoked => "device_revoked",
            EventKind::DeviceCredentialRotated => "device_credential_rotated",
            EventKind::PairingRequested => "pairing_requested",
            EventKind::PairingApproved => "pairing_approved",
            EventKind::PairingRejected => "pairing_rejected",
            EventKind::PairingExpired => "pairing_expired",
            EventKind::PairingRevoked => "pairing_revoked",
            EventKind::PeerAdded => "peer_added",
            EventKind::PeerUpdated => "peer_updated",
            EventKind::PeerRemoved => "peer_removed",
            EventKind::PolicyBundleUpdated => "policy_bundle_updated",
            EventKind::RouteAdvertised => "route_advertised",
            EventKind::RouteWithdrawn => "route_withdrawn",
            EventKind::ExitNodeAdvertised => "exit_node_advertised",
            EventKind::ExitNodeWithdrawn => "exit_node_withdrawn",
            EventKind::RelayRegionPolicyChanged => "relay_region_policy_changed",
            EventKind::RelayEpochFloorAdvanced => "relay_epoch_floor_advanced",
            EventKind::StreamCompacted => "stream_compacted",
            EventKind::StateDocumentAvailable => "state_document_available",
            EventKind::LogHead => "log_head",
            EventKind::PresenceUpdated => "presence_updated",
            EventKind::RelayAssignmentHint => "relay_assignment_hint",
        }
    }

    /// The kind a decoded body is. A total match, so a new variant in a future
    /// contract revision breaks this build rather than defaulting.
    #[must_use]
    pub const fn of_body(body: &EventBody) -> Self {
        match body {
            EventBody::DeviceRegistered(_) => EventKind::DeviceRegistered,
            EventBody::DeviceMetadataUpdated(_) => EventKind::DeviceMetadataUpdated,
            EventBody::DeviceRevoked(_) => EventKind::DeviceRevoked,
            EventBody::DeviceCredentialRotated(_) => EventKind::DeviceCredentialRotated,
            EventBody::PairingRequested(_) => EventKind::PairingRequested,
            EventBody::PairingApproved(_) => EventKind::PairingApproved,
            EventBody::PairingRejected(_) => EventKind::PairingRejected,
            EventBody::PairingExpired(_) => EventKind::PairingExpired,
            EventBody::PairingRevoked(_) => EventKind::PairingRevoked,
            EventBody::PeerAdded(_) => EventKind::PeerAdded,
            EventBody::PeerUpdated(_) => EventKind::PeerUpdated,
            EventBody::PeerRemoved(_) => EventKind::PeerRemoved,
            EventBody::PolicyBundleUpdated(_) => EventKind::PolicyBundleUpdated,
            EventBody::RouteAdvertised(_) => EventKind::RouteAdvertised,
            EventBody::RouteWithdrawn(_) => EventKind::RouteWithdrawn,
            EventBody::ExitNodeAdvertised(_) => EventKind::ExitNodeAdvertised,
            EventBody::ExitNodeWithdrawn(_) => EventKind::ExitNodeWithdrawn,
            EventBody::RelayRegionPolicyChanged(_) => EventKind::RelayRegionPolicyChanged,
            EventBody::RelayEpochFloorAdvanced(_) => EventKind::RelayEpochFloorAdvanced,
            EventBody::StreamCompacted(_) => EventKind::StreamCompacted,
            EventBody::StateDocumentAvailable(_) => EventKind::StateDocumentAvailable,
            EventBody::LogHead(_) => EventKind::LogHead,
            EventBody::PresenceUpdated(_) => EventKind::PresenceUpdated,
            EventBody::RelayAssignmentHint(_) => EventKind::RelayAssignmentHint,
        }
    }
}

/// A durable event, ready to be appended inside a mutating transaction.
///
/// The `publisher` field is private and is set from `kind.sole_publisher()`.
/// There is no constructor that takes one.
#[derive(Debug, Clone, PartialEq)]
pub struct DurableEvent {
    kind: EventKind,
    publisher: Publisher,
    body: EventBody,
}

impl DurableEvent {
    /// Builds a durable event.
    ///
    /// # Errors
    ///
    /// [`ServiceError`] with `INTERNAL.INVARIANT_VIOLATED` if `body` classifies
    /// as ephemeral. Constructing a `DurableEvent` around `PresenceUpdated`
    /// would be the durable-presence antipattern, and it is refused here rather
    /// than at the database.
    pub fn new(body: EventBody) -> Result<Self, ServiceError> {
        let kind = EventKind::of_body(&body);
        if kind.durability() != Durability::Durable {
            return Err(ServiceError::from_diagnostic(
                twinvpn_types::Diagnostic::invariant_violated(
                    crate::COMPONENT,
                    "ephemeral_event_offered_as_durable",
                ),
            ));
        }
        Ok(Self {
            kind,
            publisher: kind.sole_publisher(),
            body,
        })
    }

    /// A wrong-publisher event, for the test that proves the log refuses one.
    ///
    /// Compiled only under `cfg(test)` and behind the `test-support` feature.
    /// Without it, layer 2 of the sole-publisher enforcement would have nothing
    /// to reject and the test would be vacuous.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn forged_for_test(body: EventBody, publisher: Publisher) -> Self {
        Self {
            kind: EventKind::of_body(&body),
            publisher,
            body,
        }
    }

    /// Its kind.
    #[must_use]
    pub const fn kind(&self) -> EventKind {
        self.kind
    }

    /// Its publisher, as stamped.
    #[must_use]
    pub const fn publisher(&self) -> Publisher {
        self.publisher
    }

    /// The body.
    #[must_use]
    pub const fn body(&self) -> &EventBody {
        &self.body
    }

    /// **Layer 2** of sole-publisher enforcement, run on every append.
    ///
    /// # Errors
    ///
    /// `CONTROL.EVENT_WRONG_PUBLISHER`, `FATAL`/`CRITICAL`, treated as a
    /// security event by both sides.
    pub fn check_publisher(&self) -> Result<(), ServiceError> {
        if self.publisher == self.kind.sole_publisher() {
            Ok(())
        } else {
            Err(crate::codes::wrong_publisher(
                self.kind.as_str(),
                self.publisher.as_str(),
            ))
        }
    }

    /// The wire event at `net_seq`, inside `twinnet_id`.
    ///
    /// `net_seq` is the position allocated **inside the mutating transaction**
    /// (N-3); this function does not allocate one, it records the one it was
    /// given.
    ///
    /// `cause` is the correlation of the request whose **processing** produced
    /// this event, and it is applied with
    /// [`Correlation::derive_consequence`] — `causation_id` set, `correlation_id`
    /// deliberately **absent**. That is `common.proto`'s own worked example: an
    /// event is not a *reply* to the request that caused it, and carrying a
    /// `correlation_id` would tell every other device in the `TwinNet` that this
    /// event answers a message they never sent.
    #[must_use]
    pub fn to_wire(
        &self,
        twinnet_id: &str,
        net_seq: u64,
        occurred_at_ms: u64,
        cause: &Correlation,
    ) -> v1::ControlEvent {
        let mut metadata = v1::MessageMetadata {
            proto_version: crate::config::PROTO_VERSION,
            net_seq,
            twinnet_id: twinnet_id.to_owned(),
            sender_time_ms: occurred_at_ms,
            ..Default::default()
        };
        cause.apply_to_metadata(&mut metadata);
        v1::ControlEvent {
            metadata: Some(metadata),
            durability: Durability::Durable.to_wire(),
            publisher: self.publisher.to_wire(),
            event: Some(self.body.clone()),
        }
    }
}

/// An ephemeral event: `net_seq == 0`, never logged, never replayed.
#[derive(Debug, Clone, PartialEq)]
pub struct EphemeralEvent {
    kind: EventKind,
    body: EventBody,
}

impl EphemeralEvent {
    /// Builds an ephemeral event.
    ///
    /// # Errors
    ///
    /// `INTERNAL.INVARIANT_VIOLATED` if `body` classifies as durable. **This is
    /// the direction that matters**: a `DeviceRevoked` sent as ephemeral is
    /// never replayed, so a device asleep during the revocation wakes still
    /// trusting a stolen laptop and nothing will ever correct it.
    pub fn new(body: EventBody) -> Result<Self, ServiceError> {
        let kind = EventKind::of_body(&body);
        if kind.durability() != Durability::Ephemeral {
            return Err(ServiceError::from_diagnostic(
                twinvpn_types::Diagnostic::invariant_violated(
                    crate::COMPONENT,
                    "durable_event_offered_as_ephemeral",
                ),
            ));
        }
        Ok(Self { kind, body })
    }

    /// Its kind.
    #[must_use]
    pub const fn kind(&self) -> EventKind {
        self.kind
    }

    /// The wire event. `net_seq` is `0` by construction.
    #[must_use]
    pub fn to_wire(
        &self,
        twinnet_id: &str,
        occurred_at_ms: u64,
        cause: &Correlation,
    ) -> v1::ControlEvent {
        let mut metadata = v1::MessageMetadata {
            proto_version: crate::config::PROTO_VERSION,
            net_seq: 0,
            twinnet_id: twinnet_id.to_owned(),
            sender_time_ms: occurred_at_ms,
            ..Default::default()
        };
        cause.apply_to_metadata(&mut metadata);
        v1::ControlEvent {
            metadata: Some(metadata),
            durability: Durability::Ephemeral.to_wire(),
            publisher: self.kind.sole_publisher().to_wire(),
            event: Some(self.body.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Durability, DurableEvent, EphemeralEvent, EventKind, Publisher};
    use twinvpn_schema::v1;
    use twinvpn_schema::v1::control_event::Event as EventBody;
    use twinvpn_service_common::Correlation;

    fn revoked() -> EventBody {
        EventBody::DeviceRevoked(v1::DeviceRevoked::default())
    }

    fn presence() -> EventBody {
        EventBody::PresenceUpdated(v1::PresenceUpdated::default())
    }

    #[test]
    fn a_durable_event_cannot_be_emitted_as_ephemeral() {
        // contract-matrix.md §1: the SECURITY direction.
        let err = EphemeralEvent::new(revoked()).expect_err("must refuse");
        assert_eq!(err.code().as_str(), "INTERNAL.INVARIANT_VIOLATED");
    }

    #[test]
    fn an_ephemeral_event_cannot_be_emitted_as_durable() {
        // The COST/PRIVACY direction: durable presence is a permanent movement
        // and IP history of the Owner.
        let err = DurableEvent::new(presence()).expect_err("must refuse");
        assert_eq!(err.code().as_str(), "INTERNAL.INVARIANT_VIOLATED");
    }

    #[test]
    fn a_durable_event_carries_its_position_and_an_ephemeral_one_carries_zero() {
        let d = DurableEvent::new(revoked()).expect("durable");
        let wire = d.to_wire("tn", 7, 1_000, &Correlation::empty());
        assert_eq!(wire.metadata.expect("metadata").net_seq, 7);
        assert_eq!(wire.durability, Durability::Durable.to_wire());

        let e = EphemeralEvent::new(presence()).expect("ephemeral");
        let wire = e.to_wire("tn", 1_000, &Correlation::empty());
        assert_eq!(
            wire.metadata.expect("metadata").net_seq,
            0,
            "ADR-0002 N-9: an ephemeral event has no log position"
        );
        assert_eq!(wire.durability, Durability::Ephemeral.to_wire());
    }

    #[test]
    fn the_wrong_publisher_is_refused_as_a_security_event() {
        let forged = DurableEvent::forged_for_test(revoked(), Publisher::OriginatingDevice);
        let err = forged.check_publisher().expect_err("must refuse");
        assert_eq!(err.code().as_str(), "CONTROL.EVENT_WRONG_PUBLISHER");
        assert!(err.code().terminal());
        // And the honestly-built one passes.
        assert!(DurableEvent::new(revoked())
            .expect("durable")
            .check_publisher()
            .is_ok());
    }

    #[test]
    fn every_kind_has_exactly_one_publisher_and_it_is_coordination() {
        for k in EventKind::ALL {
            assert_eq!(
                k.sole_publisher(),
                Publisher::CoordinationService,
                "{}",
                k.as_str()
            );
        }
    }

    #[test]
    fn the_four_ephemeral_kinds_are_exactly_the_matrix_rows() {
        let ephemeral: Vec<&str> = EventKind::ALL
            .iter()
            .filter(|k| k.durability() == Durability::Ephemeral)
            .map(|k| k.as_str())
            .collect();
        assert_eq!(
            ephemeral,
            vec![
                "state_document_available",
                "log_head",
                "presence_updated",
                "relay_assignment_hint"
            ]
        );
    }

    #[test]
    fn stream_compacted_occupies_a_position() {
        // ADR-0002 N-8: in band AND IN ORDER. An out-of-order gap announcement
        // is a silent omission with extra steps.
        assert_eq!(
            EventKind::StreamCompacted.durability(),
            Durability::Durable,
            "a gap announcement that can be dropped announces nothing"
        );
    }
}
