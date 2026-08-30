//! ADR-0013 §11.4's per-peer accounting, quotas and fairness, and §11.5's scale
//! floor.
//!
//! **Authority:** ADR-0013 §11.4 (MG-10 … MG-13), §11.5 (MG-14), §11.11.
//!
//! # MG-10, the noisy-neighbour rule
//!
//! > A peer exceeding its share MUST degrade **itself**. … a peer MAY consume
//! > unused capacity, and MUST be **preempted back to its guaranteed floor
//! > within 100 ms** of another admitted peer becoming backlogged. Failure to
//! > meet the floor within that bound is `RESOURCE.FAIRNESS.FLOOR_NOT_MET` and
//! > **is a defect, not a condition**.
//!
//! # MG-12: capacity is reserved at admission, not at first packet
//!
//! "A gateway that cannot reserve **refuses admission** rather than admitting and
//! over-committing." [`Capacity::reserve`] therefore returns a `Result` and there
//! is no lazy path.

use core::time::Duration;

use twinvpn_types::{AddressFamily, PerFamily};

/// MG-14's normative floor: a conforming gateway supports at least this many
/// concurrent admitted peers "on **any** supported platform. A build that cannot
/// is non-conforming — this is the direct, testable negation of the R-16
/// defect."
pub const MIN_ADMITTED_PEERS: usize = 16;

/// The guaranteed per-peer floor's lower bound.
pub const FLOOR_MIN_BITS_PER_SEC: u64 = 256_000;

/// MG-10's preemption bound.
pub const PREEMPTION_BOUND: Duration = Duration::from_millis(100);

/// MG-11: `per_peer_conntrack_hard × max_admitted_peers` must be at most this
/// fraction of global conntrack capacity, "so that one peer can never make the
/// table unusable for the others".
pub const CONNTRACK_GLOBAL_HEADROOM_PERCENT: u64 = 80;

/// §11.5's fixed per-peer state, in bytes.
pub const FIXED_PER_PEER_BYTES: u64 = 5_632;
/// §11.5's per-conntrack-entry cost.
pub const CONNTRACK_ENTRY_BYTES: u64 = 320;

/// MG-10's guaranteed floor for one peer.
///
/// `floor(K) = max(256 kbit/s, configured_uplink / max_admitted_peers)`.
///
/// This is ADR-0013 §11.11's `gw_peer_floor_share_bps` — the ADR names that
/// gauge and this function is its value. The name is recorded here rather than
/// introduced as a second thing to keep in step.
#[must_use]
pub fn floor_bits_per_sec(configured_uplink_bps: u64, max_admitted_peers: usize) -> u64 {
    let share = if max_admitted_peers == 0 {
        0
    } else {
        configured_uplink_bps / (max_admitted_peers as u64)
    };
    share.max(FLOOR_MIN_BITS_PER_SEC)
}

/// ADR-0013 §11.11's `gw_peer_achieved_bps`, as arithmetic over an observation.
///
/// `docs/testing-strategy.md` §P06 designates the pair as the fairness oracle:
/// "the assertion is `gw_peer_achieved_bps(B) ≥ gw_peer_floor_share_bps(B)`
/// sustained, reached within 100 ms".
///
/// # What this is, and what it deliberately is not
///
/// ADR-0013 names the gauge in one table row — "`gw_peer_floor_share_bps` /
/// `gw_peer_achieved_bps` | gauge | peer | **The P06 fairness oracle**" — and
/// defines `achieved` nowhere: no unit, no window, no sampling interval. So what
/// is written here is only the part that is not a choice: bits per second is
/// bytes over an interval, and that conversion is the same on every platform.
///
/// The **measurement** is not here and cannot be. `lib.rs` states this crate's
/// shape — "This crate decides; it does not forward … none of them touches a
/// packet" — and ADR-0018 §11.7 puts it below the composition root, so a rate
/// window with a clock in it would live in `twinvpn-core` where the values live.
/// Picking a window length here would be inventing the part of the gauge the ADR
/// left open, in the crate least able to hold it.
///
/// Returns 0 for a zero-length interval rather than dividing by it: "no time has
/// passed" has no rate, and the conservative answer is the one that cannot
/// satisfy [`meets_floor`] by accident.
#[must_use]
pub fn achieved_bits_per_sec(bytes: u64, over: Duration) -> u64 {
    let nanos = over.as_nanos();
    if nanos == 0 {
        return 0;
    }
    let bits = u128::from(bytes)
        .saturating_mul(8)
        .saturating_mul(1_000_000_000);
    u64::try_from(bits / nanos).unwrap_or(u64::MAX)
}

/// MG-10's fairness predicate: a peer is at or above its guaranteed floor.
///
/// The comparison is `>=`, from `docs/testing-strategy.md` §P06's wording. MG-10
/// makes falling below it "a defect, not a condition", reported as
/// `RESOURCE.FAIRNESS.FLOOR_NOT_MET`.
#[must_use]
pub const fn meets_floor(achieved_bps: u64, floor_bps: u64) -> bool {
    achieved_bps >= floor_bps
}

/// One peer's quota allowance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerQuota {
    /// The guaranteed floor, each direction.
    pub floor_bps: u64,
    /// Optional ceiling. `None` means work-conserving with no cap, which MG-10
    /// permits: "a peer **MAY consume unused capacity**".
    pub ceiling_bps: Option<u64>,
    /// Per-class backlog byte cap; tail-drop above it.
    pub queue_bytes: u64,
    /// The soft conntrack cap: new-flow rate is throttled above it.
    pub conntrack_soft: u32,
    /// The hard cap: new flows are refused, **existing flows are untouched**.
    pub conntrack_hard: u32,
    /// New-flow token bucket, per second.
    pub new_flows_per_sec: u32,
    /// Handshake/rekey rate: 1/s sustained, burst 5.
    pub handshake_per_sec: u32,
    /// Handshake burst.
    pub handshake_burst: u32,
}

impl PeerQuota {
    /// The §11.4 defaults for a peer.
    #[must_use]
    pub fn new(configured_uplink_bps: u64, max_admitted_peers: usize) -> Self {
        Self {
            floor_bps: floor_bits_per_sec(configured_uplink_bps, max_admitted_peers),
            ceiling_bps: None,
            queue_bytes: 1 << 20,
            conntrack_soft: 2_048,
            conntrack_hard: 4_096,
            new_flows_per_sec: 100,
            handshake_per_sec: 1,
            handshake_burst: 5,
        }
    }

    /// The fixed and variable memory this peer reserves at admission.
    #[must_use]
    pub const fn reserved_bytes(&self) -> u64 {
        FIXED_PER_PEER_BYTES + (self.conntrack_hard as u64) * CONNTRACK_ENTRY_BYTES
    }
}

/// What a quota decision refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum QuotaRefusal {
    /// The peer is over its rate allowance.
    #[error("rate limited")]
    RateLimited,
    /// The peer's queue is full; tail-drop.
    #[error("queue overflow")]
    QueueOverflow,
    /// The peer is at its hard conntrack cap. **Existing flows are untouched.**
    #[error("per-peer conntrack exhausted")]
    ConntrackExhausted,
    /// The gateway's global conntrack is exhausted despite MG-11's sizing.
    /// `CRITICAL`, and **a sizing bug**.
    #[error("global conntrack exhausted despite per-peer sizing")]
    ConntrackGlobalExhausted,
    /// Handshake/rekey rate limited.
    #[error("handshake rate limited")]
    HandshakeRateLimited,
}

/// One peer's live usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerUsage {
    /// Live conntrack entries.
    pub conntrack: u32,
    /// Bytes currently queued.
    pub queued_bytes: u64,
    /// Byte and packet counters, **per family, separately counted**.
    pub bytes: PerFamily<u64>,
    /// Drops, per family.
    pub drops: PerFamily<u64>,
}

impl Default for PeerUsage {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerUsage {
    /// A zeroed record.
    #[must_use]
    pub fn new() -> Self {
        Self {
            conntrack: 0,
            queued_bytes: 0,
            bytes: PerFamily::new(0, 0),
            drops: PerFamily::new(0, 0),
        }
    }

    /// Records forwarded bytes for a family.
    pub fn observe_forward(&mut self, family: AddressFamily, bytes: u64) {
        *self.bytes.get_mut(family) = self.bytes.get(family).saturating_add(bytes);
    }

    /// Records a drop for a family.
    ///
    /// MG-4's refusal is "counted against K" — per family, so a v4-only counter
    /// could not hide a v6 spoofing campaign.
    pub fn observe_drop(&mut self, family: AddressFamily) {
        *self.drops.get_mut(family) = self.drops.get(family).saturating_add(1);
    }
}

/// Admits or refuses a new flow.
///
/// The hard cap refuses **new** flows only: "at hard cap, new flows are refused,
/// **existing flows are untouched**." Tearing down live flows to make room would
/// turn a quota into an outage.
///
/// # Errors
///
/// [`QuotaRefusal::ConntrackExhausted`] at the hard cap, and
/// [`QuotaRefusal::ConntrackGlobalExhausted`] when the gateway-wide table is
/// full despite MG-11's sizing.
pub fn admit_flow(
    quota: PeerQuota,
    usage: PeerUsage,
    global_conntrack_used: u32,
    global_conntrack_capacity: u32,
) -> Result<(), QuotaRefusal> {
    if usage.conntrack >= quota.conntrack_hard {
        return Err(QuotaRefusal::ConntrackExhausted);
    }
    if global_conntrack_used >= global_conntrack_capacity {
        return Err(QuotaRefusal::ConntrackGlobalExhausted);
    }
    Ok(())
}

/// Whether the new-flow rate should be throttled (the soft cap).
#[must_use]
pub const fn throttle_new_flows(quota: PeerQuota, usage: PeerUsage) -> bool {
    usage.conntrack >= quota.conntrack_soft
}

/// MG-11's sizing rule, as a check a gateway runs at configuration time.
///
/// "A gateway MUST size `per_peer_conntrack_hard × max_admitted_peers` to at
/// most 80 % of its global conntrack capacity."
#[must_use]
pub fn conntrack_sizing_is_conforming(
    per_peer_hard: u32,
    max_admitted_peers: usize,
    global_capacity: u32,
) -> bool {
    let demanded = u64::from(per_peer_hard) * (max_admitted_peers as u64);
    let allowed = u64::from(global_capacity) * CONNTRACK_GLOBAL_HEADROOM_PERCENT / 100;
    demanded <= allowed
}

/// The gateway's admission-time capacity reservation (MG-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capacity {
    total_bytes: u64,
    reserved_bytes: u64,
    max_peers: usize,
    admitted: usize,
}

impl Capacity {
    /// A gateway with `total_bytes` of reservable memory and a peer ceiling.
    ///
    /// The ceiling is clamped up to MG-14's floor, because "a build that cannot
    /// [support 16] is non-conforming".
    #[must_use]
    pub const fn new(total_bytes: u64, max_peers: usize) -> Self {
        Self {
            total_bytes,
            reserved_bytes: 0,
            max_peers: if max_peers < MIN_ADMITTED_PEERS {
                MIN_ADMITTED_PEERS
            } else {
                max_peers
            },
            admitted: 0,
        }
    }

    /// The peer ceiling.
    #[must_use]
    pub const fn max_peers(&self) -> usize {
        self.max_peers
    }

    /// How many peers are admitted.
    #[must_use]
    pub const fn admitted(&self) -> usize {
        self.admitted
    }

    /// Reserves capacity for one peer, or refuses.
    ///
    /// # Errors
    ///
    /// [`crate::peer_table::AdmitError::PeerLimitReached`] at the ceiling, and
    /// [`crate::peer_table::AdmitError::CapacityReservedUnavailable`] when the
    /// reservation does not fit — **never** an over-commit.
    pub fn reserve(&mut self, quota: PeerQuota) -> Result<(), crate::peer_table::AdmitError> {
        if self.admitted >= self.max_peers {
            return Err(crate::peer_table::AdmitError::PeerLimitReached);
        }
        let need = quota.reserved_bytes();
        if self.reserved_bytes.saturating_add(need) > self.total_bytes {
            return Err(crate::peer_table::AdmitError::CapacityReservedUnavailable);
        }
        self.reserved_bytes += need;
        self.admitted += 1;
        Ok(())
    }

    /// Releases a peer's reservation.
    pub fn release(&mut self, quota: PeerQuota) {
        self.reserved_bytes = self.reserved_bytes.saturating_sub(quota.reserved_bytes());
        self.admitted = self.admitted.saturating_sub(1);
    }
}

/// MG-13: a relayed path "changes latency, **not entitlement**".
///
/// Traffic over a relay is accounted against the same per-peer budget and the
/// same gateway uplink budget as direct traffic.
#[must_use]
pub const fn relayed_traffic_has_its_own_budget() -> bool {
    false
}
