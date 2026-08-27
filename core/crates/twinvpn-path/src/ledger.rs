//! The candidate ledger: every candidate, winners **and losers**, each with why
//! it is not carrying traffic.
//!
//! **Authority:** `docs/reliability.md` §7.2, ADR-0004 §11.6(a), ADR-0015 O-06
//! and O-07, S-14.
//!
//! # It must be producible with no network and with the control plane down
//!
//! O-07, restated by §7.2: the ledger "is `LOCAL`, in-memory state (S-14), is
//! the substrate for the connectivity report, and MUST be producible with **no
//! network** and with the control plane **down**."
//!
//! So [`Ledger::report`] takes nothing, calls nothing, and returns a value. It
//! cannot fail and cannot block, which is the strongest available reading of
//! "producible with no network".
//!
//! # Why a relay path stays warm behind a direct one
//!
//! §7.2: relay allocation begins at t = 0 "concurrently with direct probing —
//! never after a direct timeout". The consequence is that a `WAN_DIRECT` path
//! established through relay-assisted setup already has a warm relay behind it,
//! so `WAN_DIRECT → MIGRATING → RELAYED` on direct-path death is sub-second
//! rather than a fresh allocation.

use twinvpn_env::MonotonicInstant;
use twinvpn_types::{AddressFamily, CandidateId, ReasonCode};

use crate::candidate::{Candidate, Kind};

/// Why a candidate is not currently carrying traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// Gathered, not yet probed.
    Gathered,
    /// Probed, awaiting a second `PONG` inside the validation window.
    Probing,
    /// Passed authenticated path validation and is eligible.
    Validated,
    /// Carrying traffic.
    Carrying,
    /// Warm: validated and held as an alternate, keepalive running.
    Warm,
    /// Probed and failed, with the specific reason.
    Failed(ReasonCode),
    /// In `T_MIGRATE_COOLDOWN` after a failed migration. **Not deleted**:
    /// §7.5 keeps it "in the ledger with its failure reason", re-eligible after
    /// the cooldown.
    CoolingDown {
        /// When the cooldown ends.
        until: MonotonicInstant,
        /// Why the migration failed.
        reason: ReasonCode,
    },
    /// Cancelled because another pair won the race.
    CancelledLoser,
}

impl Standing {
    /// Whether this candidate may carry user traffic.
    ///
    /// **No user traffic on an unvalidated path, ever** (§4.4). `Gathered` and
    /// `Probing` therefore answer `false`, and there is no fourth state that
    /// answers `true` without validation.
    #[must_use]
    pub const fn may_carry_traffic(self) -> bool {
        matches!(
            self,
            Standing::Validated | Standing::Carrying | Standing::Warm
        )
    }

    /// Whether the candidate is re-eligible at `now`.
    #[must_use]
    pub fn is_eligible(self, now: MonotonicInstant) -> bool {
        match self {
            Standing::CoolingDown { until, .. } => now.reached(until),
            Standing::Failed(_) | Standing::CancelledLoser => false,
            _ => true,
        }
    }
}

/// One ledger row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row {
    /// The candidate.
    pub candidate: Candidate,
    /// Its current standing, and why.
    pub standing: Standing,
    /// The measured RTT, once one exists.
    pub rtt_micros: Option<u64>,
}

/// The per-`Session` ledger.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    rows: Vec<Row>,
    /// When the relay candidate's first gathering round began.
    relay_gathered_at: Option<MonotonicInstant>,
    /// When the first direct probe was sent.
    first_direct_probe_at: Option<MonotonicInstant>,
}

impl Ledger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a gathered candidate.
    ///
    /// A `Relay` candidate additionally stamps `relay_gathered_at` the first
    /// time one appears, which is the value P01 compares.
    pub fn record(&mut self, candidate: Candidate) {
        if candidate.kind == Kind::Relay && self.relay_gathered_at.is_none() {
            self.relay_gathered_at = Some(candidate.gathered_at);
        }
        self.rows.push(Row {
            candidate,
            standing: Standing::Gathered,
            rtt_micros: None,
        });
    }

    /// Records that the first direct probe went out.
    pub fn record_first_direct_probe(&mut self, at: MonotonicInstant) {
        if self.first_direct_probe_at.is_none() {
            self.first_direct_probe_at = Some(at);
        }
    }

    /// Updates one candidate's standing.
    ///
    /// Returns `false` when the id names nothing, which is a caller defect
    /// rather than something to swallow.
    pub fn set_standing(&mut self, id: CandidateId, standing: Standing) -> bool {
        match self.rows.iter_mut().find(|r| r.candidate.id == id) {
            Some(r) => {
                r.standing = standing;
                true
            }
            None => false,
        }
    }

    /// Records a measured RTT.
    pub fn set_rtt(&mut self, id: CandidateId, rtt_micros: u64) -> bool {
        match self.rows.iter_mut().find(|r| r.candidate.id == id) {
            Some(r) => {
                r.rtt_micros = Some(rtt_micros);
                true
            }
            None => false,
        }
    }

    /// Every row, winners and losers alike.
    #[must_use]
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// The rows eligible to be raced or migrated to at `now`.
    #[must_use]
    pub fn eligible(&self, now: MonotonicInstant) -> Vec<&Row> {
        self.rows
            .iter()
            .filter(|r| r.standing.is_eligible(now))
            .collect()
    }

    /// Whether a validated or warm alternate exists — T19's guard input.
    #[must_use]
    pub fn has_warm_alternate(&self, excluding: CandidateId) -> bool {
        self.rows.iter().any(|r| {
            r.candidate.id != excluding
                && matches!(r.standing, Standing::Validated | Standing::Warm)
        })
    }

    /// The connectivity report (O-06).
    ///
    /// Takes no arguments, performs no I/O, and cannot fail — O-07's "producible
    /// with no network and with the control plane down", read as strictly as it
    /// can be read.
    #[must_use]
    pub fn report(&self) -> Report {
        let mut per_family = twinvpn_types::PerFamily::new(0usize, 0usize);
        for r in &self.rows {
            *per_family.get_mut(r.candidate.family()) += 1;
        }
        Report {
            total: self.rows.len(),
            per_family,
            validated: self
                .rows
                .iter()
                .filter(|r| r.standing.may_carry_traffic())
                .count(),
            failed: self
                .rows
                .iter()
                .filter(|r| matches!(r.standing, Standing::Failed(_)))
                .count(),
            relay_gathered_at: self.relay_gathered_at,
            first_direct_probe_at: self.first_direct_probe_at,
        }
    }

    /// ADR-0004 §11.6(b) and (d): the relay was gathered from t = 0, not after
    /// direct failure.
    ///
    /// `None` when one of the two instants was never recorded, which is itself
    /// the answer P01 needs — a build that never gathered a relay cannot pass.
    #[must_use]
    pub fn relay_gathered_from_t_zero(&self) -> Option<bool> {
        match (self.relay_gathered_at, self.first_direct_probe_at) {
            (Some(relay), Some(direct)) => Some(relay <= direct),
            (Some(_), None) => Some(true),
            _ => None,
        }
    }

    /// §11.6(d)'s second mutant: gather timestamps must **overlap**, not be
    /// strictly ordered. Serialized racing shows up as a strict ordering.
    #[must_use]
    pub fn gathering_was_parallel(&self) -> bool {
        let v4: Vec<MonotonicInstant> = self
            .rows
            .iter()
            .filter(|r| r.candidate.family() == AddressFamily::V4)
            .map(|r| r.candidate.gathered_at)
            .collect();
        let v6: Vec<MonotonicInstant> = self
            .rows
            .iter()
            .filter(|r| r.candidate.family() == AddressFamily::V6)
            .map(|r| r.candidate.gathered_at)
            .collect();
        if v4.is_empty() || v6.is_empty() {
            return false;
        }
        let v4_min = v4.iter().min().copied().unwrap_or(MonotonicInstant::ORIGIN);
        let v4_max = v4.iter().max().copied().unwrap_or(MonotonicInstant::ORIGIN);
        let v6_min = v6.iter().min().copied().unwrap_or(MonotonicInstant::ORIGIN);
        let v6_max = v6.iter().max().copied().unwrap_or(MonotonicInstant::ORIGIN);
        // Overlapping intervals, rather than one strictly after the other.
        v4_min <= v6_max && v6_min <= v4_max
    }
}

/// The connectivity report's contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// How many candidates were gathered.
    pub total: usize,
    /// How many per family. Reported **side by side and always both** (O-09).
    pub per_family: twinvpn_types::PerFamily<usize>,
    /// How many validated.
    pub validated: usize,
    /// How many failed.
    pub failed: usize,
    /// When the relay was first gathered.
    pub relay_gathered_at: Option<MonotonicInstant>,
    /// When the first direct probe went out.
    pub first_direct_probe_at: Option<MonotonicInstant>,
}
