//! Racing candidate pairs: concurrently, across both families, and across direct
//! and relay.
//!
//! **Authority:** `docs/reliability.md` §4.4 (`CONNECTING`), §5.1's `T_HE_BIAS`;
//! ADR-0004 §11 ("Probes are sent on **every** candidate pair simultaneously");
//! ADR-0010 §11.4; `docs/networking.md` §3.4; `candidate.proto`'s `PunchSync`.
//!
//! # The anti-amplification control is structural
//!
//! `candidate.proto` on `PunchSync.pairs`: "**INDICES, NOT ADDRESSES**: an index
//! cannot name an address that did not appear in a signed set, which is the
//! anti-amplification control expressed structurally rather than by a runtime
//! check."
//!
//! [`Pair`] therefore holds two indices, [`pairs_from_sync`] resolves them
//! against the two signed sets, and an out-of-range index is a **malformed
//! reference**, not a pair to skip — "skipping would let a peer silently change
//! which pair is raced".

use core::time::Duration;

use twinvpn_env::MonotonicInstant;
use twinvpn_schema::{v1, validate, Reject};
use twinvpn_types::AddressFamily;

use crate::candidate::Candidate;

/// The Happy Eyeballs v2 bias. **250 ms is the settled value**
/// (`docs/reliability.md` §5.1): "Any carriage or probe ladder whose rung offsets
/// were derived against 150 ms must re-derive them against 250 ms."
pub const T_HE_BIAS: Duration = Duration::from_millis(250);

/// `docs/protocol.md` §12.2's probe cadence, bounded by `T_MIGRATE`.
pub const PROBE_CADENCE: Duration = Duration::from_millis(500);

/// One raced pair, by index into the two signed candidate sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pair {
    /// Index into our own signed set.
    pub local: usize,
    /// Index into the peer's signed set.
    pub remote: usize,
}

/// When a pair's first probe is due.
///
/// ADR-0010 §11.4: "start the IPv6 attempt first, start the IPv4 attempt after a
/// **250 ms head-start delay**". The bias is a *stagger*, not a filter: the v4
/// attempt still starts, so a broken v6 path costs a quarter second rather than
/// the whole attempt.
#[must_use]
pub const fn start_offset(family: AddressFamily) -> Duration {
    match family {
        AddressFamily::V6 => Duration::ZERO,
        AddressFamily::V4 => T_HE_BIAS,
    }
}

/// The schedule for one race.
#[derive(Debug, Clone)]
pub struct Race {
    started_at: MonotonicInstant,
    entries: Vec<Entry>,
    winner: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    candidate: Candidate,
    first_probe_at: MonotonicInstant,
    cancelled: bool,
}

impl Race {
    /// Schedules every candidate at once, staggered only by the family bias.
    ///
    /// §4.4's `CONNECTING` invariant: "Candidate pairs are raced **concurrently**
    /// across v4 and v6 **and** across direct and relay." So there is no
    /// `next()` that returns one candidate at a time and no serial fallback —
    /// every entry gets a start instant up front.
    #[must_use]
    pub fn schedule(candidates: &[Candidate], now: MonotonicInstant) -> Self {
        let entries = candidates
            .iter()
            .map(|c| Entry {
                candidate: *c,
                first_probe_at: now.saturating_add(start_offset(c.family())),
                cancelled: false,
            })
            .collect();
        Self {
            started_at: now,
            entries,
            winner: None,
        }
    }

    /// When gathering started.
    #[must_use]
    pub const fn started_at(&self) -> MonotonicInstant {
        self.started_at
    }

    /// The candidates whose first probe is due at `now`.
    #[must_use]
    pub fn due(&self, now: MonotonicInstant) -> Vec<Candidate> {
        self.entries
            .iter()
            .filter(|e| !e.cancelled && now.reached(e.first_probe_at))
            .map(|e| e.candidate)
            .collect()
    }

    /// Whether both families are scheduled to start.
    ///
    /// A race that scheduled only one family has not raced "concurrently across
    /// v4 and v6", whatever the timings say.
    #[must_use]
    pub fn covers_both_families(&self) -> bool {
        let v4 = self
            .entries
            .iter()
            .any(|e| e.candidate.family() == AddressFamily::V4);
        let v6 = self
            .entries
            .iter()
            .any(|e| e.candidate.family() == AddressFamily::V6);
        v4 && v6
    }

    /// Records a winner and cancels every loser (T08's "cancel losing
    /// candidates").
    ///
    /// Returns the cancelled candidates so the caller can mark them in the
    /// ledger — a cancelled loser is still a ledger row, not a deletion.
    pub fn declare_winner(&mut self, id: twinvpn_types::CandidateId) -> Vec<Candidate> {
        let mut cancelled = Vec::new();
        for (i, e) in self.entries.iter_mut().enumerate() {
            if e.candidate.id == id {
                self.winner = Some(i);
            } else if !e.cancelled {
                e.cancelled = true;
                cancelled.push(e.candidate);
            }
        }
        cancelled
    }

    /// The winning candidate, once one is declared.
    #[must_use]
    pub fn winner(&self) -> Option<Candidate> {
        self.winner.map(|i| self.entries[i].candidate)
    }
}

/// Resolves a peer's `PunchSync` into raced pairs.
///
/// # Errors
///
/// [`Reject::CapViolated`] past `candidates.max_birthday_port_hints` (64) or on
/// **any** index outside the accompanying signed sets. An out-of-range index is
/// rejected, never skipped.
pub fn pairs_from_sync(
    sync: &v1::PunchSync,
    local_len: usize,
    remote_len: usize,
) -> Result<Vec<Pair>, Reject> {
    validate::punch_sync(sync, local_len, remote_len)?;
    Ok(sync
        .pairs
        .iter()
        .map(|p| Pair {
            local: p.local_candidate_index as usize,
            remote: p.remote_candidate_index as usize,
        })
        .collect())
}

/// `PunchSync.punch_at_ms_relative` is **relative to receipt**, and is measured
/// on the monotonic clock.
///
/// `candidate.proto`: "Relative because the two peers' wall clocks are advisory
/// and may differ by minutes; a relative offset needs only that both sides
/// measure duration, which the monotonic clock does correctly."
#[must_use]
pub fn punch_at(received_at: MonotonicInstant, sync: &v1::PunchSync) -> MonotonicInstant {
    received_at.saturating_add(Duration::from_millis(u64::from(sync.punch_at_ms_relative)))
}

/// `docs/networking.md` §3.4: the disco probe payload cap.
///
/// "Probe payloads are small (< 100 B) and rate-limited per peer to bound the
/// amplification and battery cost."
pub const MAX_PROBE_BYTES: usize = 100;

/// ADR-0004 §11: the direct-upgrade prober's decaying ladder, in seconds.
///
/// "1 s, 2 s, 4 s … capped at 60 s, reset on any network change event."
#[must_use]
pub fn upgrade_probe_interval(attempt: u32, background: bool) -> Duration {
    let base = Duration::from_secs(1u64 << attempt.min(6));
    let capped = base.min(Duration::from_secs(60));
    if background {
        // §11.1's floor: T_UPGRADE_PROBE_BG = 300 s, aligned to the wake window.
        capped.max(Duration::from_secs(300))
    } else {
        capped
    }
}
