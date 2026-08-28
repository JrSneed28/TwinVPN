//! Herd-safe drain — ADR-0005 §8, `docs/reliability.md` §8.3, transition T37.
//!
//! > On planned shutdown the relay emits `DRAIN{drain_deadline_ms,
//! > suggested_alternatives[]}` on every bound flow (default deadline 120 s) …
//! > devices move at a time drawn uniformly from `[0, deadline − 60 s]`.
//! > **Herd safety comes from the relay honouring the deadline it announced, not
//! > from client heuristics.**
//!
//! That sentence divides the work exactly:
//!
//! - The **relay's** obligation, [`DrainPlan`], is to announce one deadline, to
//!   every bound flow, once, and then to keep carrying traffic until it. A relay
//!   that announces 120 s and closes at 5 s has not drained; it has failed with a
//!   courtesy message, and the clients it stampedes were told to spread.
//! - The **client's** obligation, [`migration_instant_ms`], is to draw uniformly
//!   from `[0, deadline − 60 s]`. It lives here because ADR-0006 §11.7 fixes it
//!   and because a pure function of `(deadline, draw)` is the only form in which
//!   "a drain does not stampede" is testable rather than asserted.
//!
//! `relay.proto RelayDrain` is explicit about authority: "a relay can ASK a
//! device to leave but can NEVER REDIRECT A SESSION BY ITSELF — the peers decide,
//! via PathOffer/PathAck inside the existing encrypted Session." So
//! `suggested_relay_ids` is a **hint**, and [`DrainPlan::suggestions`] carries
//! only relay ids the device will re-check against its own verified map.

use crate::flow::FlowId;

/// The default deadline (ADR-0005 §8).
pub const DEFAULT_DRAIN_DEADLINE_MS: u64 = 120_000;

/// The reserved tail: no device is told to move inside the last minute, so the
/// relay always has 60 s of announced life left after the last scheduled move.
pub const RESERVED_TAIL_MS: u64 = 60_000;

/// One relay's announced drain.
#[derive(Debug, Clone)]
pub struct DrainPlan {
    deadline_ms: u64,
    announced_at_ms: u64,
    suggestions: Vec<[u8; twinvpn_schema::limits::RELAY_ID_BYTES]>,
    announced_to: Vec<FlowId>,
}

impl DrainPlan {
    /// Starts a drain announced at `now_ms` with `deadline_ms` of grace.
    ///
    /// A deadline shorter than [`RESERVED_TAIL_MS`] is raised to it: announcing
    /// a window inside which no client may legally move is worse than announcing
    /// a longer one, because every client would then move immediately.
    #[must_use]
    pub fn new(now_ms: u64, deadline_ms: u64) -> Self {
        Self {
            deadline_ms: deadline_ms.max(RESERVED_TAIL_MS),
            announced_at_ms: now_ms,
            suggestions: Vec::new(),
            announced_to: Vec::new(),
        }
    }

    /// The default 120 s plan.
    #[must_use]
    pub fn default_at(now_ms: u64) -> Self {
        Self::new(now_ms, DEFAULT_DRAIN_DEADLINE_MS)
    }

    /// Adds a suggested alternate. A hint only; the device re-ranks and MUST NOT
    /// bind a relay absent from its own verified map (`relay.proto`).
    #[must_use]
    pub fn suggesting(mut self, relay_id: [u8; twinvpn_schema::limits::RELAY_ID_BYTES]) -> Self {
        if !self.suggestions.contains(&relay_id) {
            self.suggestions.push(relay_id);
        }
        self
    }

    /// The announced deadline.
    #[must_use]
    pub const fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }

    /// The wall-clock instant the announced deadline expires.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.announced_at_ms + self.deadline_ms
    }

    /// The suggested alternates.
    #[must_use]
    pub fn suggestions(&self) -> &[[u8; twinvpn_schema::limits::RELAY_ID_BYTES]] {
        &self.suggestions
    }

    /// Records that `flow` has been told. Announcing twice is a defect: a device
    /// that receives two deadlines has been given two draws.
    pub fn announce_to(&mut self, flow: FlowId) -> bool {
        if self.announced_to.contains(&flow) {
            return false;
        }
        self.announced_to.push(flow);
        true
    }

    /// How many flows have been told.
    #[must_use]
    pub fn announced_count(&self) -> usize {
        self.announced_to.len()
    }

    /// Whether the relay may still carry traffic for this flow.
    ///
    /// **The relay's half of herd safety.** It stays `true` right up to the
    /// announced deadline, whatever else the process is doing.
    #[must_use]
    pub const fn still_carrying(&self, now_ms: u64) -> bool {
        now_ms < self.expires_at_ms()
    }
}

/// Where in `[0, deadline − 60 s]` a device moves — ADR-0006 §11.7, reliability T37.
///
/// `draw` is a uniform value in `[0, 1)` supplied by the caller's injected
/// randomness (testing-strategy A-14: "the `uniform(0, T_REGION_SPREAD)` draw and
/// the HRW hash must be seedable"). Returning a pure function of `(deadline,
/// draw)` is what makes the spread testable.
#[must_use]
pub fn migration_instant_ms(deadline_ms: u64, draw: f64) -> u64 {
    let span = deadline_ms.saturating_sub(RESERVED_TAIL_MS);
    if span == 0 {
        return 0;
    }
    let clamped = draw.clamp(0.0, 1.0);
    // `span` is a duration in milliseconds, well inside f64's exact range.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let scaled = (clamped * (span as f64)) as u64;
    scaled.min(span)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_deadline_is_the_adr_value() {
        assert_eq!(DrainPlan::default_at(0).deadline_ms(), 120_000);
    }

    #[test]
    fn a_drain_does_not_stampede() {
        // The property, measured: with the default 120 s deadline, migration
        // instants spread over the whole [0, 60 s] window and no bucket holds a
        // disproportionate share.
        let deadline = DEFAULT_DRAIN_DEADLINE_MS;
        let n = 10_000_u64;
        let mut buckets = [0_usize; 10];
        for i in 0..n {
            // A deterministic sweep of the draw space stands in for the client
            // population; the function under test is the mapping, not the RNG.
            #[allow(clippy::cast_precision_loss)]
            let draw = (i as f64) / (n as f64);
            let t = migration_instant_ms(deadline, draw);
            assert!(
                t <= deadline - RESERVED_TAIL_MS,
                "a client was told to move inside the reserved tail"
            );
            let idx = usize::try_from(t * 10 / (deadline - RESERVED_TAIL_MS))
                .unwrap_or(9)
                .min(9);
            buckets[idx] += 1;
        }
        let expected = usize::try_from(n).unwrap_or(0) / 10;
        for (i, count) in buckets.iter().enumerate() {
            assert!(
                *count > expected / 2 && *count < expected * 2,
                "bucket {i} holds {count}, expected about {expected}: the spread is not uniform"
            );
        }
        // And the sharpest form of the property: nothing lands at zero en masse.
        assert!(buckets[0] < usize::try_from(n).unwrap_or(0) / 5);
    }

    #[test]
    fn no_client_is_told_to_move_inside_the_last_minute() {
        for deadline in [60_000, 90_000, 120_000, 600_000] {
            for draw in [0.0, 0.5, 0.999_999, 1.0, 2.0, -1.0] {
                let t = migration_instant_ms(deadline, draw);
                assert!(
                    t + RESERVED_TAIL_MS <= deadline,
                    "deadline={deadline} draw={draw}"
                );
            }
        }
    }

    #[test]
    fn a_deadline_shorter_than_the_reserved_tail_is_raised_not_honoured() {
        // Announcing 5 s would leave no legal window, so every client would move
        // at once — the exact stampede the mechanism exists to prevent.
        assert_eq!(DrainPlan::new(0, 5_000).deadline_ms(), RESERVED_TAIL_MS);
    }

    #[test]
    fn the_relay_keeps_carrying_until_the_deadline_it_announced() {
        let p = DrainPlan::default_at(1_000);
        assert!(p.still_carrying(1_000));
        assert!(p.still_carrying(120_999));
        assert!(!p.still_carrying(121_000));
    }

    #[test]
    fn a_flow_is_announced_to_exactly_once() {
        let mut p = DrainPlan::default_at(0);
        assert!(p.announce_to(FlowId::new(1)));
        assert!(
            !p.announce_to(FlowId::new(1)),
            "two deadlines would be two draws"
        );
        assert!(p.announce_to(FlowId::new(2)));
        assert_eq!(p.announced_count(), 2);
    }

    #[test]
    fn suggestions_are_deduplicated_and_are_only_relay_ids() {
        let p = DrainPlan::default_at(0)
            .suggesting([1; 8])
            .suggesting([2; 8])
            .suggesting([1; 8]);
        assert_eq!(p.suggestions().len(), 2);
        // A suggestion is 8 bytes of relay_id and nothing else — no endpoint, no
        // token, no instruction. The peers decide, not the relay.
        assert_eq!(
            p.suggestions()[0].len(),
            twinvpn_schema::limits::RELAY_ID_BYTES
        );
    }
}
