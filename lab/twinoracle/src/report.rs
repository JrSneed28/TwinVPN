//! The serialized answer — the exact shape `build/acceptance/report.py` fetches
//! from the control API and re-derives an acceptance row from.
//!
//! The field names here are a cross-process contract. They are flat, and they
//! are spelled out one per family rather than nested in a map, because the
//! consumer must be able to fail on a MISSING key. A map with a family absent
//! and a map with a family set to `false` are easy to conflate; three named
//! booleans are not.
//!
//! `*_identity_distinct` is deliberately `Option<bool>` and serializes to
//! `null` for a family the criterion makes no claim about. `null` is NOT
//! `true`, and a reader that treats it as one has silently re-introduced the
//! hole this whole file exists to close.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::evidence::SentinelBeat;
use crate::{Expectation, Family, Observation, Verdict};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseReport {
    pub name: String,
    pub expectation: Expectation,
    pub started_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub observations: BTreeMap<String, usize>,
    pub sources: Vec<String>,
    pub satisfied: bool,
    pub reasons: Vec<String>,
}

/// The machine-readable answer for one session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub session_id: String,
    pub commit: String,
    pub run_id: String,
    /// `GITHUB_RUN_ATTEMPT` the session was opened with. A re-run of the same
    /// run id is a different execution on a possibly different machine, and an
    /// oracle session from attempt 1 must not be able to discharge attempt 2.
    pub run_attempt: String,
    pub platform: String,
    pub criterion: String,
    pub opened_at_ms: u64,
    pub closed_at_ms: Option<u64>,
    pub phases: Vec<PhaseReport>,

    // --- Workstream 1: attempts, forbidden arrivals, sentinel ---
    /// What the DEVICE said it tried to send. Never evidence of silence.
    pub ipv4_attempts: u64,
    pub ipv6_attempts: u64,
    pub dns_attempts: u64,
    /// What the ORACLE saw arrive during a SILENCE phase. Any of these being
    /// non-zero is a leak and forces `FAIL`.
    pub ipv4_observed: u64,
    pub ipv6_observed: u64,
    pub dns_observed: u64,
    /// Whether an independent heartbeat covered every SILENCE phase for this
    /// family without a gap wider than the configured cadence. Absent sentinel
    /// evidence is `false`, never `true`.
    pub ipv4_sentinel_continuous: bool,
    pub ipv6_sentinel_continuous: bool,
    pub dns_sentinel_continuous: bool,
    /// Where the sentinel claimed to be running. Unverifiable by construction,
    /// and reported so a human can see whether the independence claim is
    /// plausible for the criterion at hand.
    pub sentinel_host: Option<String>,
    /// Every sentinel beat that arrived, so a reader can check the continuity
    /// arithmetic rather than believe the boolean above it.
    pub sentinel_beats: Vec<SentinelBeat>,

    // --- Workstream 2: path identity ---
    pub ipv4_identity_distinct: Option<bool>,
    pub ipv6_identity_distinct: Option<bool>,
    pub dns_identity_distinct: Option<bool>,
    /// True when any DNS arrival mapped to no known resolver, so the path that
    /// resolved it could not be derived.
    pub dns_resolver_identity_ambiguous: bool,

    /// Every observation that arrived during a SILENCE phase, in full. A leak
    /// is named, not counted.
    pub unauthorized_observations: Vec<Observation>,
    pub families_proven_live: Vec<Family>,
    pub failures: Vec<String>,
    pub inconclusive: Vec<String>,
    pub verdict: Verdict,
}
