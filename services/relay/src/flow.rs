//! S-29 — the `pair_tag`-keyed pending-slot and half-flow table.
//!
//! `docs/architecture.md` §5 row **S-29**, contributed by ADR-0005 §11.8:
//!
//! | writer | replicas | class | durability | on conflict |
//! |---|---|---|---|---|
//! | the `Relay` instance, in memory | **None — MUST NOT be persisted or replicated** | `LOCAL` | **Non-durable by requirement** | impossible (single writer); loss ⇒ flow death ⇒ `MIGRATING` |
//!
//! **Loss is the design, not a gap.** A relay restart kills every in-flight
//! half-flow and persists nothing (RQ10); both peers see frame loss,
//! `PATH_FAILING` fires, and the `Session` takes `RELAYED → MIGRATING → RELAYED`
//! onto the pre-bound warm standby with keys, counters and addresses untouched.
//!
//! Two structural consequences are enforced here rather than documented:
//!
//! 1. **Nothing in this module derives `serde::Serialize` or `Deserialize`.**
//!    `tests/s29_is_not_persistable.rs` reads this file and asserts it, so
//!    "MUST NOT be persisted" is checked rather than remembered.
//! 2. **No type here holds two device identifiers.** The join key is the
//!    `pair_tag` — an HKDF output over the peers' own pairwise secret, scoped to
//!    one `relay_id` and one 10-minute bucket. `relay.proto` is explicit that
//!    `peer_key_id` "is WITHDRAWN precisely because that field would have told
//!    the relay which two devices are talking, defeating A11". A [`BoundPair`]
//!    holds two *transport* peers and one subject each — never an identity, and
//!    never a rendering path to either.

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::frame::CounterWindow;
use crate::subject::RelaySub;

/// The blinded 16-byte join key (ADR-0005 §11.1(3), `limits.json`
/// `identifiers.pair_tag_bytes`).
///
/// One-way, scoped to one `relay_id` and one bucket, and useless at another
/// relay or another bucket. It is a **map key**, not a value: no `Display`, and
/// a redacted `Debug`, because a `pair_tag` in a log is a join key in a log.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PairTag([u8; twinvpn_schema::limits::PAIR_TAG_BYTES]);

impl PairTag {
    /// Takes the tag from a `BIND` frame, after its width has been checked.
    ///
    /// # Errors
    ///
    /// A [`twinvpn_schema::Reject`] naming `identifiers.pair_tag_bytes` when the
    /// width is wrong — a typed reject before any allocation, never a truncation
    /// and never a pad (`ownership.md` §6 rule 9).
    pub fn from_wire(bytes: &[u8]) -> Result<Self, twinvpn_schema::Reject> {
        let want = twinvpn_schema::limits::PAIR_TAG_BYTES;
        if bytes.len() != want {
            return Err(twinvpn_schema::Reject::CapViolated {
                cap_violated: "identifiers.pair_tag_bytes",
                observed: bytes.len() as u64,
                limit: want as u64,
            });
        }
        let mut out = [0_u8; twinvpn_schema::limits::PAIR_TAG_BYTES];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }
}

impl std::fmt::Debug for PairTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A pair_tag is the join key. Rendering it would put the relay's own
        // rendezvous index in a log line.
        f.write_str("PairTag(<redacted>)")
    }
}

/// A relay-assigned handle for a bound half-flow. Local to this instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowId(u32);

impl FlowId {
    /// A handle. Allocated by [`PairTable`]; public so a scheduler or a test can
    /// name one without owning a table.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// The wire value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// One side of a bound pair: where to send, and whose quota to charge.
#[derive(Debug)]
pub struct HalfFlow {
    /// The relay-assigned handle for this direction.
    pub flow_id: FlowId,
    /// The transport peer. A relay must send frames somewhere; ADR-0005 §7.2
    /// lists this as unavoidably observable and identical to any on-path observer.
    pub peer: SocketAddr,
    /// Whose quota this half-flow is charged to.
    pub subject: RelaySub,
    /// The receive replay window for this direction.
    pub window: CounterWindow,
    /// The outgoing counter for this direction.
    pub tx_counter: u64,
    /// Monotonic-ish activity marker, in milliseconds, for the idle GC.
    pub last_activity_ms: u64,
}

/// Two joined half-flows.
#[derive(Debug)]
pub struct BoundPair {
    /// The half-flow the first `BIND` created.
    pub a: HalfFlow,
    /// The half-flow the second `BIND` created.
    pub b: HalfFlow,
}

impl BoundPair {
    /// The peer half-flow for a frame arriving on `flow_id`.
    #[must_use]
    pub fn egress_for(&self, flow_id: FlowId) -> Option<&HalfFlow> {
        if self.a.flow_id == flow_id {
            Some(&self.b)
        } else if self.b.flow_id == flow_id {
            Some(&self.a)
        } else {
            None
        }
    }

    /// The ingress half-flow for `flow_id`, mutably.
    pub fn ingress_for_mut(&mut self, flow_id: FlowId) -> Option<&mut HalfFlow> {
        if self.a.flow_id == flow_id {
            Some(&mut self.a)
        } else if self.b.flow_id == flow_id {
            Some(&mut self.b)
        } else {
            None
        }
    }
}

/// A first `BIND` waiting for its partner.
#[derive(Debug)]
pub struct PendingSlot {
    /// The half-flow already created for the first arrival.
    pub first: HalfFlow,
    /// When the slot was created, in milliseconds.
    pub created_ms: u64,
}

/// What a `BIND` did.
#[derive(Debug, PartialEq, Eq)]
pub enum BindOutcome {
    /// First `BIND` on this tag: a pending slot now exists, expiring in 30 s.
    Pending {
        /// The handle assigned to this half-flow.
        flow_id: FlowId,
    },
    /// Second `BIND`: both peers receive `BOUND{flow_id}`.
    Bound {
        /// The handle for the arriving half-flow.
        flow_id: FlowId,
        /// The handle for the half-flow that was already waiting.
        peer_flow_id: FlowId,
    },
    /// A third `BIND` on a bound tag (ADR-0005 §11.1(4)).
    ///
    /// "A squatter cannot in any case produce valid L-DATA traffic."
    Collision,
    /// The relay-wide flow ceiling is reached.
    RelayFull,
}

/// The relay's whole flow state. In memory, `LOCAL`, never written anywhere.
#[derive(Debug)]
pub struct PairTable {
    pending: HashMap<PairTag, PendingSlot>,
    bound: HashMap<PairTag, BoundPair>,
    by_flow: HashMap<FlowId, PairTag>,
    next_flow_id: u32,
    pending_ttl_ms: u64,
    idle_ttl_ms: u64,
    max_total_flows: usize,
}

impl PairTable {
    /// A table with the ADR-0005 §11.5 lifetimes and a relay-wide ceiling.
    ///
    /// `max_total_flows` is the ceiling the per-subject limit does *not* provide:
    /// per-subject limits bound one attacker, the total bounds all of them.
    #[must_use]
    pub fn new(pending_ttl_ms: u64, idle_ttl_ms: u64, max_total_flows: usize) -> Self {
        Self {
            pending: HashMap::new(),
            bound: HashMap::new(),
            by_flow: HashMap::new(),
            next_flow_id: 1,
            pending_ttl_ms,
            idle_ttl_ms,
            max_total_flows: max_total_flows.max(1),
        }
    }

    /// How many half-flows exist, pending and bound.
    #[must_use]
    pub fn half_flow_count(&self) -> usize {
        self.pending.len() + self.bound.len() * 2
    }

    /// How many tags have a pending slot.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// How many tags are bound.
    #[must_use]
    pub fn bound_count(&self) -> usize {
        self.bound.len()
    }

    /// Handles a `BIND` on `tag` from `peer`, charged to `subject`.
    pub fn bind(
        &mut self,
        tag: PairTag,
        peer: SocketAddr,
        subject: RelaySub,
        now_ms: u64,
    ) -> BindOutcome {
        if self.bound.contains_key(&tag) {
            return BindOutcome::Collision;
        }
        if self.half_flow_count() >= self.max_total_flows {
            return BindOutcome::RelayFull;
        }
        let flow_id = self.allocate_flow_id();
        let half = HalfFlow {
            flow_id,
            peer,
            subject,
            window: CounterWindow::new(),
            tx_counter: 0,
            last_activity_ms: now_ms,
        };

        match self.pending.remove(&tag) {
            None => {
                self.pending.insert(
                    tag,
                    PendingSlot {
                        first: half,
                        created_ms: now_ms,
                    },
                );
                self.by_flow.insert(flow_id, tag);
                BindOutcome::Pending { flow_id }
            }
            Some(slot) => {
                let peer_flow_id = slot.first.flow_id;
                self.bound.insert(
                    tag,
                    BoundPair {
                        a: slot.first,
                        b: half,
                    },
                );
                self.by_flow.insert(flow_id, tag);
                BindOutcome::Bound {
                    flow_id,
                    peer_flow_id,
                }
            }
        }
    }

    /// The bound pair a `flow_id` belongs to, mutably.
    pub fn bound_for_flow_mut(&mut self, flow_id: FlowId) -> Option<&mut BoundPair> {
        let tag = *self.by_flow.get(&flow_id)?;
        self.bound.get_mut(&tag)
    }

    /// The bound pair a `flow_id` belongs to.
    #[must_use]
    pub fn bound_for_flow(&self, flow_id: FlowId) -> Option<&BoundPair> {
        let tag = self.by_flow.get(&flow_id)?;
        self.bound.get(tag)
    }

    /// Every currently bound `flow_id`, for a drain sweep.
    #[must_use]
    pub fn bound_flow_ids(&self) -> Vec<FlowId> {
        let mut out: Vec<FlowId> = self
            .bound
            .values()
            .flat_map(|p| [p.a.flow_id, p.b.flow_id])
            .collect();
        out.sort_unstable();
        out
    }

    /// Expires pending slots past 30 s and bound pairs idle past 15 minutes.
    ///
    /// Returns `(pending_expired, bound_expired)` so the caller can emit
    /// `RELAY.PAIR_UNMATCHED` and `RELAY.FLOW_IDLE_TIMEOUT` as counters.
    pub fn collect(&mut self, now_ms: u64) -> (usize, usize) {
        let pending_ttl = self.pending_ttl_ms;
        let idle_ttl = self.idle_ttl_ms;

        let expired_pending: Vec<PairTag> = self
            .pending
            .iter()
            .filter(|(_, s)| now_ms.saturating_sub(s.created_ms) >= pending_ttl)
            .map(|(t, _)| *t)
            .collect();
        for tag in &expired_pending {
            if let Some(slot) = self.pending.remove(tag) {
                self.by_flow.remove(&slot.first.flow_id);
            }
        }

        let expired_bound: Vec<PairTag> = self
            .bound
            .iter()
            .filter(|(_, p)| {
                let newest = p.a.last_activity_ms.max(p.b.last_activity_ms);
                now_ms.saturating_sub(newest) >= idle_ttl
            })
            .map(|(t, _)| *t)
            .collect();
        for tag in &expired_bound {
            if let Some(pair) = self.bound.remove(tag) {
                self.by_flow.remove(&pair.a.flow_id);
                self.by_flow.remove(&pair.b.flow_id);
            }
        }

        (expired_pending.len(), expired_bound.len())
    }

    /// Drops every flow, as a restart does. Returns how many half-flows died.
    ///
    /// Exists so the restart property is testable in process: after this the
    /// table is empty and nothing was written anywhere.
    pub fn drop_everything(&mut self) -> usize {
        let n = self.half_flow_count();
        self.pending.clear();
        self.bound.clear();
        self.by_flow.clear();
        n
    }

    fn allocate_flow_id(&mut self) -> FlowId {
        loop {
            let id = FlowId(self.next_flow_id);
            self.next_flow_id = self.next_flow_id.wrapping_add(1);
            if self.next_flow_id == 0 {
                self.next_flow_id = 1;
            }
            if !self.by_flow.contains_key(&id) {
                return id;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(n: u8) -> PairTag {
        PairTag::from_wire(&[n; 16]).expect("16 bytes")
    }

    fn sub(n: u8) -> RelaySub {
        RelaySub::from_verified_claim([n; 16])
    }

    fn addr(port: u16) -> SocketAddr {
        format!("[::1]:{port}").parse().expect("addr")
    }

    fn table() -> PairTable {
        PairTable::new(30_000, 900_000, 1_000)
    }

    #[test]
    fn a_pair_tag_must_be_exactly_sixteen_bytes() {
        assert!(PairTag::from_wire(&[0; 15]).is_err());
        assert!(PairTag::from_wire(&[0; 17]).is_err());
        assert!(PairTag::from_wire(&[0; 16]).is_ok());
    }

    #[test]
    fn a_pair_tag_has_no_rendering_path() {
        assert_eq!(format!("{:?}", tag(1)), "PairTag(<redacted>)");
    }

    #[test]
    fn the_first_bind_pends_and_the_second_binds() {
        let mut t = table();
        let first = t.bind(tag(1), addr(1), sub(1), 0);
        assert!(matches!(first, BindOutcome::Pending { .. }));
        assert_eq!(t.pending_count(), 1);

        let second = t.bind(tag(1), addr(2), sub(2), 10);
        assert!(matches!(second, BindOutcome::Bound { .. }));
        assert_eq!(t.pending_count(), 0);
        assert_eq!(t.bound_count(), 1);
    }

    #[test]
    fn a_third_bind_on_a_bound_tag_collides() {
        let mut t = table();
        let _ = t.bind(tag(1), addr(1), sub(1), 0);
        let _ = t.bind(tag(1), addr(2), sub(2), 0);
        assert_eq!(t.bind(tag(1), addr(3), sub(3), 0), BindOutcome::Collision);
        assert_eq!(
            t.bound_count(),
            1,
            "a squatter does not displace a bound pair"
        );
    }

    #[test]
    fn a_pending_slot_expires_after_thirty_seconds() {
        let mut t = table();
        let _ = t.bind(tag(1), addr(1), sub(1), 0);
        assert_eq!(t.collect(29_999), (0, 0));
        assert_eq!(t.collect(30_000), (1, 0), "RELAY.PAIR_UNMATCHED");
        assert_eq!(t.pending_count(), 0);
    }

    #[test]
    fn a_bound_pair_expires_after_fifteen_idle_minutes() {
        let mut t = table();
        let _ = t.bind(tag(1), addr(1), sub(1), 0);
        let _ = t.bind(tag(1), addr(2), sub(2), 0);
        assert_eq!(t.collect(899_999), (0, 0));
        assert_eq!(t.collect(900_000), (0, 1), "RELAY.FLOW_IDLE_TIMEOUT");
        assert_eq!(t.bound_count(), 0);
    }

    #[test]
    fn the_relay_wide_ceiling_bounds_all_subjects_together() {
        // Per-subject limits bound ONE attacker. Without a total ceiling, N
        // subjects each under their own limit still exhaust the relay.
        let mut t = PairTable::new(30_000, 900_000, 4);
        for n in 0..4_u8 {
            assert!(matches!(
                t.bind(tag(n), addr(u16::from(n) + 1), sub(n), 0),
                BindOutcome::Pending { .. }
            ));
        }
        assert_eq!(
            t.bind(tag(200), addr(500), sub(200), 0),
            BindOutcome::RelayFull
        );
    }

    #[test]
    fn a_frame_is_forwarded_to_exactly_the_other_half_flow() {
        let mut t = table();
        let BindOutcome::Pending { flow_id: fa } = t.bind(tag(1), addr(1), sub(1), 0) else {
            panic!("pending");
        };
        let BindOutcome::Bound {
            flow_id: fb,
            peer_flow_id,
        } = t.bind(tag(1), addr(2), sub(2), 0)
        else {
            panic!("bound");
        };
        assert_eq!(peer_flow_id, fa);

        let pair = t.bound_for_flow(fa).expect("bound");
        assert_eq!(pair.egress_for(fa).expect("egress").flow_id, fb);
        assert_eq!(pair.egress_for(fb).expect("egress").flow_id, fa);
        assert!(pair.egress_for(FlowId(9_999)).is_none());
    }

    #[test]
    fn the_two_half_flows_may_be_different_address_families() {
        // ADR-0005 §11.1(6): the relay is the v4<->v6 bridge for a peer pair
        // with no common family. Nothing in the table couples the two.
        let mut t = table();
        let v4: SocketAddr = "192.0.2.10:41641".parse().expect("v4");
        let v6: SocketAddr = "[2001:db8::1]:41641".parse().expect("v6");
        let BindOutcome::Pending { flow_id: fa } = t.bind(tag(1), v4, sub(1), 0) else {
            panic!("pending");
        };
        let _ = t.bind(tag(1), v6, sub(2), 0);
        let pair = t.bound_for_flow(fa).expect("bound");
        assert!(pair.a.peer.is_ipv4());
        assert!(pair.b.peer.is_ipv6());
    }

    #[test]
    fn a_restart_kills_every_flow_and_persists_nothing() {
        let mut t = table();
        let _ = t.bind(tag(1), addr(1), sub(1), 0);
        let _ = t.bind(tag(1), addr(2), sub(2), 0);
        let _ = t.bind(tag(2), addr(3), sub(3), 0);
        assert_eq!(t.drop_everything(), 3);
        assert_eq!(t.half_flow_count(), 0);
        // S-29: "loss ⇒ flow death ⇒ MIGRATING". That is the design.
    }

    #[test]
    fn no_type_here_holds_two_device_identifiers() {
        // A BoundPair holds two TRANSPORT peers and two subjects. It holds no
        // device_id, no identity key and no peer_key_id — the field relay.proto
        // withdrew precisely so the relay cannot reconstruct the pairing.
        let mut t = table();
        let BindOutcome::Pending { flow_id } = t.bind(tag(1), addr(1), sub(1), 0) else {
            panic!("pending");
        };
        let _ = t.bind(tag(1), addr(2), sub(2), 0);
        let rendered = format!("{:?}", t.bound_for_flow(flow_id).expect("bound"));
        assert!(rendered.contains("RelaySub(<redacted>)"));
        assert!(!rendered.contains("device"));
    }
}
