//! C2 event classification and admission.
//!
//! **Authority:** `docs/protocol.md` §6 (the four-part ephemeral/durable test),
//! §7 (single publisher per event type), `contracts/proto/twinvpn/v1/control_events.proto`,
//! `contracts/docs/contract-matrix.md` §4, ADR-0002 N-5, N-8, N-9, S-4.
//!
//! # Misclassification is the failure this module exists to make unwritable
//!
//! `contract-matrix.md` §1 states the two directions and they are not
//! symmetrical:
//!
//! > *"Treating a durable event as ephemeral is a **SECURITY** failure: a device
//! > asleep during a revocation broadcast wakes still trusting a stolen laptop,
//! > and nothing will ever correct it."*
//!
//! > *"Treating an ephemeral message as durable is a **COST, PRIVACY and
//! > DENIAL-OF-FRESHNESS** failure: durable presence is a permanent movement and
//! > IP history of the Owner, and draining it delays the one `DeviceRevoked` that
//! > matters."*
//!
//! So the classification is a `const fn` over the oneof variant — a **total
//! match**, which means adding a variant to `control_events.proto` breaks this
//! build rather than defaulting to a guess — and it is checked against **two
//! independent wire facts**: the explicit `EventDurability` enum and the
//! `net_seq != 0` rule. Agreement of all three is required. One field agreeing
//! with the table while the other does not is a defect, not a tie to break.

use twinvpn_schema::v1;
use twinvpn_schema::v1::control_event::Event as EventBody;

use crate::error::CpError;

/// How an event is delivered and retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Durability {
    /// Written to the per-`TwinNet` log, assigned a `net_seq`, resumable by
    /// cursor, at-least-once, retained ≥ 30 days or 10^6 events.
    Durable,
    /// Delivered on C2 for latency only. Not logged, not assigned a `net_seq`,
    /// not resumable, not replayed (ADR-0002 N-9).
    Ephemeral,
}

impl Durability {
    /// The wire value in `control_events.proto`'s `EventDurability`.
    #[must_use]
    pub const fn to_wire(self) -> i32 {
        match self {
            Durability::Durable => 1,
            Durability::Ephemeral => 2,
        }
    }

    /// Decodes the wire value. `UNSPECIFIED` is **not** a durability; it is a
    /// missing required field, and guessing one is exactly the misclassification
    /// this module forbids.
    #[must_use]
    pub const fn from_wire(value: i32) -> Option<Self> {
        match value {
            1 => Some(Durability::Durable),
            2 => Some(Durability::Ephemeral),
            _ => None,
        }
    }
}

/// The sole publisher of an event type (protocol.md §7 / I8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Publisher {
    /// The coordination service.
    CoordinationService,
    /// The device that owns the fact; coordination only transports it.
    OriginatingDevice,
}

impl Publisher {
    /// The wire value in `control_events.proto`'s `EventPublisher`.
    #[must_use]
    pub const fn to_wire(self) -> i32 {
        match self {
            Publisher::CoordinationService => 1,
            Publisher::OriginatingDevice => 2,
        }
    }

    /// Decodes the wire value; `UNSPECIFIED` is not a publisher.
    #[must_use]
    pub const fn from_wire(value: i32) -> Option<Self> {
        match value {
            1 => Some(Publisher::CoordinationService),
            2 => Some(Publisher::OriginatingDevice),
            _ => None,
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

/// The classification of one event type, from the frozen tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventClass {
    /// A stable tag for the `event_type` evidence field.
    pub event_type: &'static str,
    /// What §6's four-part test decided.
    pub durability: Durability,
    /// §7's sole publisher.
    pub publisher: Publisher,
}

/// The classification table.
///
/// Every arm cites the check that decided it. A `_ =>` arm is deliberately
/// absent: this match is total over `control_event::Event`, so a new event in a
/// future contract revision is a **compile error here** rather than an event
/// that silently inherits somebody's default.
#[must_use]
pub const fn classify(body: &EventBody) -> EventClass {
    use Durability::{Durable, Ephemeral};
    // `Publisher::OriginatingDevice` deliberately appears in no arm below.
    // protocol.md §7's table names the coordination service as the sole
    // publisher of every C2 event type, including the ones that transport a
    // device-signed statement: `RouteAdvertised` is published by coordination
    // and *authored* by the advertiser, and conflating the two is exactly the
    // capability Rule B removes from the infrastructure. The wire enum has the
    // variant; this table does not use it, and `admit` therefore rejects it.
    use Publisher::CoordinationService;

    macro_rules! class {
        ($name:literal, $d:expr, $p:expr) => {
            EventClass {
                event_type: $name,
                durability: $d,
                publisher: $p,
            }
        };
    }

    match body {
        // Device lifecycle. E1 fails (not re-derivable), E3 fails (device
        // invisible forever), E4 fails (harmful replay).
        EventBody::DeviceRegistered(_) => {
            class!("device_registered", Durable, CoordinationService)
        }
        EventBody::DeviceMetadataUpdated(_) => {
            class!("device_metadata_updated", Durable, CoordinationService)
        }
        // E3 fails catastrophically: a stolen device stays trusted. E4 is trust
        // resurrection. Coordination transports an Owner-signed statement.
        EventBody::DeviceRevoked(_) => class!("device_revoked", Durable, CoordinationService),
        EventBody::DeviceCredentialRotated(_) => {
            class!("device_credential_rotated", Durable, CoordinationService)
        }

        // Pairing. E3 fails as asymmetric trust; E4 is trust injection.
        EventBody::PairingRequested(_) => class!("pairing_requested", Durable, CoordinationService),
        EventBody::PairingApproved(_) => class!("pairing_approved", Durable, CoordinationService),
        EventBody::PairingRejected(_) => class!("pairing_rejected", Durable, CoordinationService),
        EventBody::PairingExpired(_) => class!("pairing_expired", Durable, CoordinationService),
        EventBody::PairingRevoked(_) => class!("pairing_revoked", Durable, CoordinationService),

        // Peer set.
        EventBody::PeerAdded(_) => class!("peer_added", Durable, CoordinationService),
        EventBody::PeerUpdated(_) => class!("peer_updated", Durable, CoordinationService),
        EventBody::PeerRemoved(_) => class!("peer_removed", Durable, CoordinationService),

        // Policy. E3 is a silent authorization hole; E4 is a policy rollback.
        EventBody::PolicyBundleUpdated(_) => {
            class!("policy_bundle_updated", Durable, CoordinationService)
        }

        // Advertisements: durable, TTL'd. Device-signed inside; coordination is
        // the publisher of the *event*, the advertiser is authoritative for the
        // *fact* (protocol.md §7's second load-bearing row).
        EventBody::RouteAdvertised(_) => class!("route_advertised", Durable, CoordinationService),
        EventBody::RouteWithdrawn(_) => class!("route_withdrawn", Durable, CoordinationService),
        EventBody::ExitNodeAdvertised(_) => {
            class!("exit_node_advertised", Durable, CoordinationService)
        }
        EventBody::ExitNodeWithdrawn(_) => {
            class!("exit_node_withdrawn", Durable, CoordinationService)
        }

        // Relay policy.
        EventBody::RelayRegionPolicyChanged(_) => {
            class!("relay_region_policy_changed", Durable, CoordinationService)
        }
        EventBody::RelayEpochFloorAdvanced(_) => {
            class!("relay_epoch_floor_advanced", Durable, CoordinationService)
        }

        // Stream control. `StreamCompacted` is in-band and IN ORDER, so it
        // carries a net_seq and is durable in the delivery sense that matters:
        // ADR-0002 N-8 forbids silent omission, and an out-of-order gap
        // announcement would be exactly that.
        EventBody::StreamCompacted(_) => class!("stream_compacted", Durable, CoordinationService),
        EventBody::StateDocumentAvailable(_) => {
            class!("state_document_available", Ephemeral, CoordinationService)
        }
        // Signed by an ONLINE key with no trust power. Ephemeral: it is a
        // liveness proof, and replaying an old one is what its own not_after_ms
        // exists to stop.
        EventBody::LogHead(_) => class!("log_head", Ephemeral, CoordinationService),

        // Ephemeral. Presence passes all four checks; durable presence is a
        // cost, privacy AND freshness defect simultaneously (§6.1).
        EventBody::PresenceUpdated(_) => {
            class!("presence_updated", Ephemeral, CoordinationService)
        }
        // Advisory. The device's OWN MEASURED RTT always overrides this hint.
        EventBody::RelayAssignmentHint(_) => {
            class!("relay_assignment_hint", Ephemeral, CoordinationService)
        }
    }
}

/// Events that carry a device-authored statement coordination cannot forge.
///
/// `contract-matrix.md` §4.1 marks each of these "(Owner-signed inside)" or
/// "(device-signed inside)". Verifying them is not optional and is not satisfied
/// by the transport being authenticated: B1 is *semi-trusted*, and these are the
/// rows where a forgery buys something.
#[must_use]
pub const fn carries_signed_statement(body: &EventBody) -> bool {
    matches!(
        body,
        EventBody::DeviceRevoked(_)
            | EventBody::DeviceCredentialRotated(_)
            | EventBody::PairingApproved(_)
            | EventBody::PolicyBundleUpdated(_)
            | EventBody::RouteAdvertised(_)
            | EventBody::RouteWithdrawn(_)
            | EventBody::ExitNodeAdvertised(_)
            | EventBody::ExitNodeWithdrawn(_)
            | EventBody::RelayEpochFloorAdvanced(_)
            | EventBody::LogHead(_)
    )
}

/// What admitting an event produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admitted {
    /// A durable event at this log position. The cursor advances to it **after**
    /// the effect is durably applied.
    Durable {
        /// The log position.
        net_seq: u64,
        /// Its classification.
        class: EventClass,
    },
    /// An ephemeral event. It carries no position and must never be persisted,
    /// replayed from a cursor, or allowed to survive its TTL.
    Ephemeral {
        /// Its classification.
        class: EventClass,
    },
}

impl Admitted {
    /// The log position, if this event has one.
    #[must_use]
    pub const fn net_seq(&self) -> Option<u64> {
        match self {
            Admitted::Durable { net_seq, .. } => Some(*net_seq),
            Admitted::Ephemeral { .. } => None,
        }
    }

    /// Its classification.
    #[must_use]
    pub const fn class(&self) -> EventClass {
        match self {
            Admitted::Durable { class, .. } | Admitted::Ephemeral { class } => *class,
        }
    }
}

/// Admits one decoded C2 event, or rejects it.
///
/// Order matters and is the order below:
///
/// 1. **Publisher first.** A wrong publisher is a security event, and a security
///    event must not be masked by a shape complaint about a message we were
///    never going to accept.
/// 2. **Durability agreement.** The wire enum, the `net_seq` rule and the frozen
///    table must all agree.
/// 3. **Position monotonicity** against the caller's cursor.
///
/// # Errors
///
/// [`CpError::EventWrongPublisher`] (a **security event**),
/// [`CpError::Rejected`] for a shape violation.
pub fn admit(event: &v1::ControlEvent, cursor: u64) -> Result<Admitted, CpError> {
    let body = event.event.as_ref().ok_or_else(|| {
        CpError::Rejected(twinvpn_schema::Reject::cap("control_event.event", 0, 1))
    })?;
    let class = classify(body);

    // 1. Sole publisher, enforced AT THE RECEIVER, not merely at the log.
    let observed = Publisher::from_wire(event.publisher);
    match observed {
        Some(p) if p == class.publisher => {}
        Some(p) => {
            return Err(CpError::EventWrongPublisher {
                event_type: class.event_type,
                observed_publisher: p.as_str(),
            })
        }
        None => {
            return Err(CpError::EventWrongPublisher {
                event_type: class.event_type,
                observed_publisher: "unspecified",
            })
        }
    }

    // 2. Durability, asserted against BOTH wire facts.
    let net_seq = event.metadata.as_ref().map_or(0, |m| m.net_seq);
    let declared = Durability::from_wire(event.durability).ok_or_else(|| {
        CpError::Rejected(twinvpn_schema::Reject::cap(
            "control_event.durability",
            0,
            2,
        ))
    })?;
    if declared != class.durability {
        return Err(CpError::Rejected(twinvpn_schema::Reject::CapViolated {
            cap_violated: "control_event.durability",
            observed: u64::from(declared.to_wire().unsigned_abs()),
            limit: u64::from(class.durability.to_wire().unsigned_abs()),
        }));
    }
    match class.durability {
        // "a DURABLE event arriving with net_seq == 0 … is a defect and MUST be
        // rejected rather than applied."
        Durability::Durable if net_seq == 0 => {
            return Err(CpError::Rejected(twinvpn_schema::Reject::cap(
                "control_event.net_seq",
                0,
                1,
            )))
        }
        // "… or an EPHEMERAL one arriving with net_seq != 0".
        Durability::Ephemeral if net_seq != 0 => {
            return Err(CpError::Rejected(twinvpn_schema::Reject::CapViolated {
                cap_violated: "control_event.net_seq",
                observed: net_seq,
                limit: 0,
            }))
        }
        _ => {}
    }

    // 3. Monotone position. A durable event at or below the cursor is a replay
    //    or a rebuilt log; either way it is refused rather than applied.
    if class.durability == Durability::Durable && net_seq <= cursor {
        return Err(CpError::TrustEpochRollback {
            offered_epoch: net_seq,
            high_water_epoch: cursor,
        });
    }

    Ok(match class.durability {
        Durability::Durable => Admitted::Durable { net_seq, class },
        Durability::Ephemeral => Admitted::Ephemeral { class },
    })
}

#[cfg(test)]
mod tests {
    use super::{admit, carries_signed_statement, classify, Durability, Publisher};
    use twinvpn_schema::v1;
    use twinvpn_schema::v1::control_event::Event as EventBody;

    fn event(body: EventBody, net_seq: u64) -> v1::ControlEvent {
        let class = classify(&body);
        v1::ControlEvent {
            metadata: Some(v1::MessageMetadata {
                net_seq,
                ..Default::default()
            }),
            durability: class.durability.to_wire(),
            publisher: class.publisher.to_wire(),
            event: Some(body),
        }
    }

    fn revoked() -> EventBody {
        EventBody::DeviceRevoked(v1::DeviceRevoked::default())
    }

    fn presence() -> EventBody {
        EventBody::PresenceUpdated(v1::PresenceUpdated::default())
    }

    #[test]
    fn revocation_is_durable_and_presence_is_ephemeral() {
        assert_eq!(classify(&revoked()).durability, Durability::Durable);
        assert_eq!(classify(&presence()).durability, Durability::Ephemeral);
    }

    #[test]
    fn a_durable_event_claiming_ephemeral_is_rejected() {
        // The security direction: a DeviceRevoked delivered as ephemeral would
        // never be replayed to a device that was asleep.
        let mut e = event(revoked(), 7);
        e.durability = Durability::Ephemeral.to_wire();
        assert!(admit(&e, 0).is_err());
    }

    #[test]
    fn a_durable_event_with_net_seq_zero_is_rejected() {
        let e = event(revoked(), 0);
        assert!(admit(&e, 0).is_err());
    }

    #[test]
    fn an_ephemeral_event_with_a_net_seq_is_rejected() {
        // The cost/privacy direction: presence that carries a log position has
        // been written to the log, which is the permanent movement history
        // §6.1 forbids.
        let e = event(presence(), 42);
        assert!(admit(&e, 0).is_err());
    }

    #[test]
    fn a_wrong_publisher_is_a_security_event() {
        let mut e = event(revoked(), 7);
        e.publisher = Publisher::OriginatingDevice.to_wire();
        let err = admit(&e, 0).expect_err("must reject");
        assert_eq!(
            err.reason_code().as_str(),
            "CONTROL.EVENT_WRONG_PUBLISHER",
            "receiver-side sole-publisher enforcement (ADR-0002 S-4)"
        );
        assert!(err.is_security_event());
        assert!(err.reason_code().terminal());
    }

    #[test]
    fn an_unspecified_publisher_is_also_a_security_event() {
        let mut e = event(revoked(), 7);
        e.publisher = 0;
        let err = admit(&e, 0).expect_err("must reject");
        assert_eq!(err.reason_code().as_str(), "CONTROL.EVENT_WRONG_PUBLISHER");
    }

    #[test]
    fn a_regressed_position_is_rejected() {
        let e = event(revoked(), 5);
        assert!(admit(&e, 9).is_err(), "net_seq 5 behind cursor 9");
        assert!(admit(&e, 5).is_err(), "net_seq 5 at cursor 5 is a replay");
        assert!(admit(&e, 4).is_ok());
    }

    #[test]
    fn ephemeral_events_are_admitted_regardless_of_the_cursor() {
        let e = event(presence(), 0);
        assert!(admit(&e, 1_000_000).is_ok());
        assert!(admit(&e, 1_000_000).expect("admitted").net_seq().is_none());
    }

    #[test]
    fn every_signed_carrier_is_named() {
        assert!(carries_signed_statement(&revoked()));
        assert!(carries_signed_statement(&EventBody::PolicyBundleUpdated(
            v1::PolicyBundleUpdated::default()
        )));
        assert!(carries_signed_statement(&EventBody::RouteAdvertised(
            v1::RouteAdvertised::default()
        )));
        assert!(!carries_signed_statement(&presence()));
        assert!(!carries_signed_statement(&EventBody::StreamCompacted(
            v1::StreamCompacted::default()
        )));
    }

    #[test]
    fn stream_compacted_is_in_band_and_in_order() {
        // ADR-0002 N-8: a compaction is announced IN BAND AND IN ORDER, so it
        // occupies a position. Silent omission is prohibited.
        let e = event(
            EventBody::StreamCompacted(v1::StreamCompacted { up_to_net_seq: 900 }),
            120,
        );
        let admitted = admit(&e, 100).expect("in-band gap announcement");
        assert_eq!(admitted.net_seq(), Some(120));
    }
}
