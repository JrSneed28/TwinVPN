//! Applying a heartbeat: S-11, the caps, and the one event shape.

use std::time::Instant;

use twinvpn_schema::{v1, Reject};
use twinvpn_service_common::{codes, ServiceError};
use twinvpn_types::EvidenceValue;

use crate::store::{Applied, DeviceId, Store};

/// A per-process pseudonym for a device, so an identifier never reaches a log
/// line or an evidence field.
///
/// Same construction and same reasoning as the rendezvous's: a sequential label
/// assigned on first sight is a function of arrival order and nothing else, so
/// there is no key to leak and no inversion over the population. See
/// `contracts/docs/trust-boundaries.md` §5 for the pattern the corpus already
/// applies to the relay's `sub` and `pair_tag`.
#[derive(Debug, Default)]
pub struct Labeller {
    by_device: std::collections::HashMap<DeviceId, u64>,
    order: std::collections::BTreeMap<u64, DeviceId>,
    next: u64,
    capacity: usize,
}

impl Labeller {
    /// A table holding at most `capacity` mappings.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            next: 1,
            ..Self::default()
        }
    }

    /// The label for `device_id`, assigning one on first sight.
    pub fn label(&mut self, device_id: DeviceId) -> String {
        if let Some(&n) = self.by_device.get(&device_id) {
            return format!("peer-{n}");
        }
        if self.by_device.len() >= self.capacity {
            if let Some((&oldest, &victim)) = self.order.iter().next() {
                self.order.remove(&oldest);
                self.by_device.remove(&victim);
            }
        }
        let n = self.next.max(1);
        self.next = n + 1;
        self.by_device.insert(device_id, n);
        self.order.insert(n, device_id);
        format!("peer-{n}")
    }
}

/// The result of one `PublishPresenceRequest`.
#[derive(Debug)]
pub enum Outcome {
    /// Applied; publish `PresenceUpdated` to subscribers.
    Updated(Box<v1::Presence>),
    /// Not applied, and that is fine: presence is `EVENTUAL` and ADR-0008 N-9
    /// says a heartbeat is **permitted to be lost**. The device is told and
    /// nothing else changes.
    Ignored,
    /// Refused, with a registered code and an answer.
    Refused(Box<ServiceError>),
}

/// Applies one heartbeat from the device this connection is bound to.
///
/// `bound` is the `device_id` the connection declared. S-11 and
/// `presence.proto`: "a device may assert presence **only for itself**. A
/// `Presence` naming another `device_id` is rejected."
pub fn publish(
    store: &mut Store,
    labels: &mut Labeller,
    bound: Option<DeviceId>,
    request: &v1::PublishPresenceRequest,
    now: Instant,
    now_ms: u64,
) -> Outcome {
    let Some(bound) = bound else {
        // A connection that has not said who it is cannot assert anything, and
        // there is no default identity to fall back on.
        return Outcome::Refused(Box::new(
            ServiceError::new(codes::CONTROL_HANDSHAKE_REJECTED, crate::COMPONENT).build(),
        ));
    };

    let Some(heartbeat) = request.heartbeat.as_ref() else {
        return Outcome::Refused(Box::new(malformed(&Reject::cap(
            "presence.heartbeat_present",
            0,
            1,
        ))));
    };
    let Some(presence) = heartbeat.presence.as_ref() else {
        return Outcome::Refused(Box::new(malformed(&Reject::cap(
            "presence.presence_present",
            0,
            1,
        ))));
    };

    // Exact length, before anything else touches the value.
    let device_id = match twinvpn_schema::validate::device_id(&presence.device_id) {
        Ok(_) => {
            let mut id = [0u8; 32];
            id.copy_from_slice(&presence.device_id);
            id
        }
        Err(r) => return Outcome::Refused(Box::new(malformed(&r))),
    };

    if device_id != bound {
        // S-11. `CONTROL.EVENT_WRONG_PUBLISHER` is FATAL/CRITICAL and a security
        // event, not a parse error: it is a device attempting to assert another
        // device's presence, which is the one thing presence authority forbids.
        // The evidence names the *pseudonym*, never the identifier.
        let label = labels.label(device_id);
        return Outcome::Refused(Box::new(
            ServiceError::new(codes::CONTROL_EVENT_WRONG_PUBLISHER, crate::COMPONENT)
                .evidence("event_type", EvidenceValue::Text("PresenceUpdated".into()))
                .evidence("observed_publisher", EvidenceValue::Text(label))
                .build(),
        ));
    }

    // `PRESENCE_STATE_UNSPECIFIED` is a missing required field, not a default to
    // fill in — proto3 cannot tell absent from zero, and guessing a state would
    // make an empty message an assertion.
    if presence.state == v1::PresenceState::Unspecified as i32
        || v1::PresenceState::try_from(presence.state).is_err()
    {
        return Outcome::Refused(Box::new(malformed(&Reject::cap(
            "presence.state",
            presence.state.unsigned_abs() as usize,
            v1::PresenceState::Offline as usize,
        ))));
    }

    match store.apply(
        device_id,
        presence.state,
        presence.reachability,
        presence.expires_at_ms,
        now,
        now_ms,
    ) {
        Applied::Stored => Outcome::Updated(Box::new(presence.clone())),
        Applied::Refused(_) => Outcome::Ignored,
    }
}

fn malformed(r: &Reject) -> ServiceError {
    ServiceError::from_reject(r, crate::COMPONENT)
}

/// The **one** event shape presence publishes.
///
/// `control_events.proto` on `PresenceUpdated`: *"Covers what an application
/// might call `PeerOnline` and `PeerOffline`: those are not separate event types,
/// they are values of `PresenceState`. Modelling them as distinct events would
/// imply an ordering guarantee that presence explicitly does not have, and a
/// reordered Online/Offline pair would leave the wrong terminal value."*
///
/// `durability` is `EPHEMERAL` and `net_seq` is 0, as ADR-0002 N-9 requires: this
/// is delivered on C2 for latency and is never written to the log, never
/// assigned a cursor position, never replayed.
///
/// `publisher` is `ORIGINATING_DEVICE`, not this service: the device owns the
/// fact (S-11) and this process only transports it.
#[must_use]
pub fn presence_updated(presence: v1::Presence, twinnet_id: String) -> v1::ControlEvent {
    v1::ControlEvent {
        metadata: Some(v1::MessageMetadata {
            twinnet_id,
            sender_id: "presence".to_owned(),
            net_seq: 0,
            ..v1::MessageMetadata::default()
        }),
        durability: v1::EventDurability::Ephemeral as i32,
        publisher: v1::EventPublisher::OriginatingDevice as i32,
        event: Some(v1::control_event::Event::PresenceUpdated(
            v1::PresenceUpdated {
                presence: Some(presence),
            },
        )),
    }
}

/// The `HeartbeatAck` this service can honestly produce.
///
/// `revocation_epoch` and `pending_net_seq` are the control plane's to answer
/// (ADR-0002 §11.4, `presence.proto`), and this service — which by I5 must never
/// call it on this path — does not know them. They are left at zero rather than
/// guessed, and `README.md` §9 records that a device wanting the battery lever
/// `pending_net_seq` provides must get it from the control plane's own C1
/// heartbeat, not from here.
#[must_use]
pub fn heartbeat_ack(suggested_interval_ms: u64) -> v1::HeartbeatAck {
    v1::HeartbeatAck {
        suggested_interval_ms,
        revocation_epoch: 0,
        pending_net_seq: 0,
    }
}
