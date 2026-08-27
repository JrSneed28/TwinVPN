//! The presence table: in memory, bounded, TTL'd, reordering-tolerant, and with
//! no history.
//!
//! # What is retained, exactly
//!
//! Per device: a [`PresenceState`], a [`Reachability`] (four booleans and a
//! coarse network class), and an absolute `expires_at_ms`. That is the whole
//! record.
//!
//! **No endpoint. No IP address. No coarse location. No previous value.**
//! `presence.proto` says why: *"`Reachability` says what families work, not
//! where the device is. Endpoints reach peers through the SIGNED `CandidateSet`
//! on C4, not through a presence record warehoused by infrastructure."*
//!
//! `docs/architecture.md` §2.13 describes this service as tracking "last-known
//! `Endpoint`s". The frozen contract removed that field, and the contract wins
//! (`ownership.md` §3). The divergence is reported in `README.md` §8 rather than
//! resolved by adding a field back.
//!
//! # Reordering, and the one refinement of the written rule
//!
//! `docs/protocol.md` §9.2 says "last-writer-wins **by arrival at the
//! aggregator**", and in the same row says there is **no ordering guarantee** and
//! that this is "why presence carries an absolute `expires_at_ms` rather than a
//! relative delta".
//!
//! Taken literally, arrival-order LWW would let a delayed `OFFLINE` overwrite a
//! newer `ONLINE` — the exact outcome the absolute instant exists to prevent, and
//! the reason `PresenceUpdated` is one event rather than two. So this store
//! resolves by **`expires_at_ms`, with arrival order as the tiebreak**: the
//! assertion the device made later has the later expiry, and an assertion that
//! is already expired on arrival is not stored at all. Arrival-order LWW is
//! recovered exactly when the two agree, which is the ordered case.
//!
//! Stated here and raised as a finding rather than silently chosen.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use twinvpn_schema::v1;

/// A `device_id`.
pub type DeviceId = [u8; twinvpn_schema::limits::DEVICE_ID_BYTES];

/// One device's current assertion about itself.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// `ONLINE` / `IDLE` / `SUSPENDING` / `OFFLINE`.
    pub state: i32,
    /// What families the device can currently reach. Not where it is.
    pub reachability: Option<v1::Reachability>,
    /// The emitter's absolute expiry, in wall-clock milliseconds. Carried
    /// verbatim so a consumer sees what the device asserted.
    pub expires_at_ms: u64,
    /// The local monotonic instant this record stops being served. Separate from
    /// `expires_at_ms` on purpose: a timer must never take a wall clock
    /// (ADR-0018 CD-1), because an NTP step would either resurrect or evict
    /// every record at once.
    pub expires_at: Instant,
    /// Arrival order, the tiebreak when two assertions claim the same expiry.
    pub arrival: u64,
}

/// Why an update was not applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejected {
    /// The assertion had already expired when it arrived. Not an error — a
    /// heartbeat that lost a race with its own TTL is exactly the loss this
    /// channel is allowed (ADR-0008 N-9: presence is "PERMITTED TO BE LOST").
    AlreadyExpired,
    /// A newer assertion is already held. Reordering, tolerated.
    Superseded,
    /// The claimed expiry is further out than the configured record TTL allows.
    /// Refused, never clamped: clamping would silently rewrite a device's own
    /// assertion, and accepting would let a device pin itself `ONLINE` for ever.
    ExpiryTooFar,
    /// The table is full.
    AtCapacity,
}

/// The outcome of applying one heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// Stored, and worth telling subscribers about.
    Stored,
    /// Not stored.
    Refused(Rejected),
}

/// Bounds on the table.
#[derive(Debug, Clone, Copy)]
pub struct StoreLimits {
    /// `TWINVPN_PRESENCE_RECORD_TTL_MS`, default 180 s. The ceiling on how far
    /// ahead a device may place its own expiry, and the ceiling on how long a
    /// record is served.
    pub record_ttl: Duration,
    /// How many devices may hold a record at once.
    pub max_devices: usize,
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            record_ttl: Duration::from_millis(180_000),
            max_devices: 65_536,
        }
    }
}

/// The presence table. In memory, and there is no other kind.
#[derive(Debug)]
pub struct Store {
    limits: StoreLimits,
    records: HashMap<DeviceId, Record>,
    /// `arrival → device`, so the oldest record can be evicted without a scan.
    order: BTreeMap<u64, DeviceId>,
    next_arrival: u64,
    expired: u64,
}

impl Store {
    /// A table bounded by `limits`.
    #[must_use]
    pub fn new(limits: StoreLimits) -> Self {
        Self {
            limits,
            records: HashMap::new(),
            order: BTreeMap::new(),
            next_arrival: 0,
            expired: 0,
        }
    }

    /// Applies one assertion.
    ///
    /// `now` is the monotonic instant and `now_ms` the wall clock, passed rather
    /// than read so a decision is reproducible from its inputs and the TTL
    /// boundary is testable without sleeping.
    pub fn apply(
        &mut self,
        device_id: DeviceId,
        state: i32,
        reachability: Option<v1::Reachability>,
        expires_at_ms: u64,
        now: Instant,
        now_ms: u64,
    ) -> Applied {
        self.sweep(now);

        if expires_at_ms <= now_ms {
            return Applied::Refused(Rejected::AlreadyExpired);
        }
        let ahead = expires_at_ms - now_ms;
        if ahead > crate::config::millis(self.limits.record_ttl) {
            return Applied::Refused(Rejected::ExpiryTooFar);
        }

        if let Some(existing) = self.records.get(&device_id) {
            // Reordering-tolerant LWW: the later assertion wins, and "later" is
            // the device's own absolute instant, not our arrival order.
            if existing.expires_at_ms > expires_at_ms {
                return Applied::Refused(Rejected::Superseded);
            }
        } else if self.records.len() >= self.limits.max_devices {
            // Evict the oldest arrival rather than refusing the newcomer: a
            // presence table that stops accepting is a table that reports a
            // stale answer for ever, and presence is allowed to be lossy.
            if let Some((&oldest, &victim)) = self.order.iter().next() {
                self.order.remove(&oldest);
                self.records.remove(&victim);
            } else {
                return Applied::Refused(Rejected::AtCapacity);
            }
        }

        let arrival = self.next_arrival;
        self.next_arrival += 1;
        if let Some(prev) = self.records.get(&device_id) {
            self.order.remove(&prev.arrival);
        }
        self.order.insert(arrival, device_id);
        self.records.insert(
            device_id,
            Record {
                state,
                reachability,
                expires_at_ms,
                expires_at: now + Duration::from_millis(ahead),
                arrival,
            },
        );
        Applied::Stored
    }

    /// The current record for `device_id`, if it has not expired.
    ///
    /// `None` means "nothing known", which is **not** "offline" and is **never**
    /// a reason to refuse anything (S-11, `architecture.md` §2.13).
    pub fn get(&mut self, device_id: DeviceId, now: Instant) -> Option<&Record> {
        self.sweep(now);
        self.records.get(&device_id)
    }

    /// Drops every expired record. Idempotent.
    pub fn sweep(&mut self, now: Instant) {
        let gone: Vec<DeviceId> = self
            .records
            .iter()
            .filter(|(_, r)| r.expires_at <= now)
            .map(|(d, _)| *d)
            .collect();
        for d in gone {
            if let Some(r) = self.records.remove(&d) {
                self.order.remove(&r.arrival);
                self.expired += 1;
            }
        }
    }

    /// How many records are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// How many records the TTL has discarded since start.
    #[must_use]
    pub const fn expired(&self) -> u64 {
        self.expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONLINE: i32 = v1::PresenceState::Online as i32;
    const OFFLINE: i32 = v1::PresenceState::Offline as i32;

    fn store() -> (Store, Instant, u64) {
        (
            Store::new(StoreLimits::default()),
            Instant::now(),
            1_000_000,
        )
    }

    #[test]
    fn a_reordered_offline_does_not_overwrite_a_newer_online() {
        let (mut s, t0, ms) = store();
        // The device asserted ONLINE at t+60 s ...
        assert_eq!(
            s.apply([1u8; 32], ONLINE, None, ms + 60_000, t0, ms),
            Applied::Stored
        );
        // ... and an OFFLINE it emitted EARLIER arrives late.
        assert_eq!(
            s.apply([1u8; 32], OFFLINE, None, ms + 30_000, t0, ms),
            Applied::Refused(Rejected::Superseded)
        );
        assert_eq!(s.get([1u8; 32], t0).unwrap().state, ONLINE);
    }

    #[test]
    fn an_ordered_offline_does_replace_an_online() {
        let (mut s, t0, ms) = store();
        s.apply([1u8; 32], ONLINE, None, ms + 30_000, t0, ms);
        assert_eq!(
            s.apply([1u8; 32], OFFLINE, None, ms + 60_000, t0, ms),
            Applied::Stored
        );
        assert_eq!(s.get([1u8; 32], t0).unwrap().state, OFFLINE);
    }

    #[test]
    fn nothing_known_is_not_offline() {
        let (mut s, t0, _) = store();
        assert!(
            s.get([9u8; 32], t0).is_none(),
            "absence must be absence, not a state a caller can act on"
        );
    }

    #[test]
    fn a_record_expires_and_leaves_nothing_behind() {
        let (mut s, t0, ms) = store();
        s.apply([2u8; 32], ONLINE, None, ms + 1_000, t0, ms);
        assert!(s
            .get([2u8; 32], t0 + Duration::from_millis(1_001))
            .is_none());
        assert_eq!(s.len(), 0);
        assert_eq!(s.expired(), 1);
    }

    #[test]
    fn a_device_cannot_pin_itself_online_for_ever() {
        let (mut s, t0, ms) = store();
        // One year out.
        assert_eq!(
            s.apply([3u8; 32], ONLINE, None, ms + 31_536_000_000, t0, ms),
            Applied::Refused(Rejected::ExpiryTooFar),
            "refused, never clamped: clamping rewrites a device's own assertion"
        );
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn an_already_expired_assertion_is_dropped_rather_than_stored() {
        let (mut s, t0, ms) = store();
        assert_eq!(
            s.apply([4u8; 32], ONLINE, None, ms - 1, t0, ms),
            Applied::Refused(Rejected::AlreadyExpired)
        );
    }

    #[test]
    fn the_table_is_bounded_against_fabricated_devices() {
        let mut s = Store::new(StoreLimits {
            max_devices: 4,
            ..StoreLimits::default()
        });
        let (t0, ms) = (Instant::now(), 1_000_000u64);
        for i in 0..1000u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            s.apply(id, ONLINE, None, ms + 60_000, t0, ms);
        }
        assert!(s.len() <= 4);
    }

    #[test]
    fn the_record_holds_no_endpoint_and_no_history() {
        let (mut s, t0, ms) = store();
        s.apply([5u8; 32], ONLINE, None, ms + 10_000, t0, ms);
        s.apply([5u8; 32], OFFLINE, None, ms + 20_000, t0, ms);
        let r = s.get([5u8; 32], t0).unwrap().clone();
        // The struct has five fields and none of them is an address or a
        // predecessor. Asserted by construction: `Record` is `PartialEq` and a
        // rebuilt copy of the current values equals it exactly.
        assert_eq!(
            r,
            Record {
                state: OFFLINE,
                reachability: None,
                expires_at_ms: ms + 20_000,
                expires_at: r.expires_at,
                arrival: r.arrival,
            }
        );
    }
}
