//! The leak oracle's observation model and its verdict.
//!
//! **Owner:** `test-engineering`. Never shipped.
//!
//! # The one idea
//!
//! A platform kill-switch test cannot be graded by the platform. So the test
//! drives a sequence of *phases*, tells this process what each phase means, and
//! emits beacons throughout; this process records what actually arrived and
//! decides afterwards whether the sequence was satisfied.
//!
//! Two phase expectations, and the second one is the criterion:
//!
//! * [`Expectation::Observe`] — traffic MUST reach the oracle. This is the
//!   POSITIVE CONTROL, and without it the whole test is worthless: an oracle
//!   nobody can reach reports zero observations during the armed window and
//!   looks exactly like a working kill switch. So an `Observe` phase that
//!   observed nothing for a required family makes the session
//!   [`Verdict::Inconclusive`], never `Pass`.
//! * [`Expectation::Silence`] — traffic MUST NOT reach the oracle. One
//!   observation is one leak, and the record of it travels into the report.
//!
//! # What "unauthorized" means here, exactly
//!
//! It is not a property of a packet. It is a property of a packet *and the
//! phase it arrived in*: anything at all during a `Silence` phase, plus
//! anything that violates a phase's declared source constraint — traffic in the
//! tunnelled phase coming from the same address the unprotected baseline came
//! from is egress that never entered the tunnel, and traffic after restoration
//! coming from anywhere other than the tunnel's own address is egress that
//! resumed outside TwinVPN.
//!
//! # What this deliberately does not do
//!
//! It does not sign its reports. A signature would be produced by a key the
//! reporting side also holds, which proves nothing about a lying CI job. The
//! integrity property comes from somewhere else: the acceptance job fetches the
//! report FROM THIS PROCESS over the control API, keyed by a session id that
//! the platform evidence recorded, rather than believing a file the platform job
//! uploaded. See `build/acceptance/report.py`.

//! # What silence alone still does not prove
//!
//! A positive control establishes the oracle was reachable at ONE moment. It
//! does not establish that the listeners survived the armed window that
//! follows, nor that the protected and unprotected paths were ever
//! distinguishable. Those two gaps are closed in [`crate::evidence`], whose
//! results are folded into the verdict below.

pub mod evidence;
pub mod report;

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub mod model;

pub use evidence::{PathKind, ResolverEntry, SentinelBeat, SentinelEvidence};
pub use model::{Expectation, Family, Observation, Phase, Verdict};
pub use report::{PhaseReport, Report};

/// Everything one platform probe run told this process, and everything that
/// arrived because of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    /// The opaque label the probe puts in every beacon. Knowing it is how the
    /// oracle attributes an arrival to a session; it is not a secret that
    /// protects anything, because arriving at all is the observation.
    pub probe_token: String,
    pub commit: String,
    pub run_id: String,
    pub platform: String,
    /// The acceptance criterion this session is evidence for, e.g.
    /// `WINDOWS-WFP-KILLSWITCH`. Carried so the acceptance report can refuse a
    /// session opened for a different row.
    pub criterion: String,
    pub opened_at_ms: u64,
    pub closed_at_ms: Option<u64>,
    pub phases: Vec<Phase>,
    pub observations: Vec<Observation>,

    /// `GITHUB_RUN_ATTEMPT` the session was opened with. Carried so the
    /// acceptance report can refuse a session opened by an earlier attempt of
    /// the same run id.
    #[serde(default)]
    pub run_attempt: String,
    /// Sentinel liveness evidence. `None` — the key absent from the session
    /// entirely — is NOT "no gaps were seen"; it is "nothing was watching", and
    /// every family's continuity is then false. That asymmetry is the whole
    /// point: a report generator that forgets to wire the sentinel must produce
    /// an INCONCLUSIVE session, never a quiet PASS.
    #[serde(default)]
    pub sentinel: Option<evidence::SentinelEvidence>,
    /// DUT-self-reported probe attempts per family, whole session.
    #[serde(default)]
    pub attempts: BTreeMap<Family, u64>,
    /// The configured per-family attempt floor. An unconfigured family still
    /// has an effective floor of one.
    #[serde(default)]
    pub attempt_minimums: BTreeMap<Family, u64>,
    /// The families this criterion actually makes a claim about. Empty means
    /// all three, which is what every existing criterion uses; a criterion with
    /// no IPv6 leg names the two it has, and IPv6's identity then reports
    /// `null` rather than a boolean nobody established.
    #[serde(default)]
    pub required_families: Vec<Family>,
    /// Arriving resolver source address -> the identity the oracle derives for
    /// it. The ONLY way a DNS arrival acquires a path. The probe's own
    /// `path_tag` is compared against this map, never substituted for it.
    #[serde(default)]
    pub resolver_map: BTreeMap<IpAddr, ResolverEntry>,
}

impl Session {
    pub fn new(
        id: String,
        probe_token: String,
        commit: String,
        run_id: String,
        platform: String,
        criterion: String,
        now_ms: u64,
    ) -> Self {
        Self {
            id,
            probe_token,
            commit,
            run_id,
            platform,
            criterion,
            opened_at_ms: now_ms,
            closed_at_ms: None,
            phases: Vec::new(),
            observations: Vec::new(),
            run_attempt: String::new(),
            sentinel: None,
            attempts: BTreeMap::new(),
            attempt_minimums: BTreeMap::new(),
            required_families: Vec::new(),
            resolver_map: BTreeMap::new(),
        }
    }

    /// The families this session's verdict is allowed to be about. Empty
    /// `required_families` means all three, which is the behaviour every
    /// criterion had before the field existed.
    pub fn families_in_play(&self) -> Vec<Family> {
        if self.required_families.is_empty() {
            Family::ALL.to_vec()
        } else {
            self.required_families.clone()
        }
    }

    /// Open a phase, closing whichever one was open. Back-to-back by
    /// construction: there is no gap between phases for an observation to fall
    /// into and be excused.
    pub fn begin_phase(&mut self, phase: Phase) {
        let start = phase.started_at_ms;
        if let Some(prev) = self.phases.last_mut() {
            if prev.ended_at_ms.is_none() {
                prev.ended_at_ms = Some(start);
            }
        }
        self.phases.push(phase);
    }

    pub fn close(&mut self, now_ms: u64) {
        if let Some(prev) = self.phases.last_mut() {
            if prev.ended_at_ms.is_none() {
                prev.ended_at_ms = Some(now_ms);
            }
        }
        self.closed_at_ms.get_or_insert(now_ms);
    }

    pub fn record(&mut self, obs: Observation) {
        self.observations.push(obs);
    }

    pub(crate) fn observations_in(&self, phase: &Phase) -> Vec<&Observation> {
        let end = phase.ended_at_ms.unwrap_or(u64::MAX);
        self.observations
            .iter()
            .filter(|o| o.at_ms >= phase.started_at_ms && o.at_ms < end)
            .collect()
    }

    /// Compute the report. Pure: it reads the session and decides, so the same
    /// session always yields the same verdict and a test can drive it directly.
    pub fn report(&self) -> Report {
        let in_play = self.families_in_play();
        let mut phases = Vec::with_capacity(self.phases.len());
        let mut sources_by_phase: BTreeMap<String, BTreeSet<IpAddr>> = BTreeMap::new();
        let mut unauthorized: Vec<Observation> = Vec::new();
        let mut families_proven_live: BTreeSet<Family> = BTreeSet::new();
        let mut failures: Vec<String> = Vec::new();
        let mut inconclusive: Vec<String> = Vec::new();

        for phase in &self.phases {
            let obs = self.observations_in(phase);
            let mut counts: BTreeMap<Family, usize> = BTreeMap::new();
            let mut sources: BTreeSet<IpAddr> = BTreeSet::new();
            for o in &obs {
                *counts.entry(o.family).or_insert(0) += 1;
                // DNS IS DELIBERATELY EXCLUDED FROM THE SOURCE SET.
                //
                // A DNS beacon that goes through the device's own resolver — the
                // only shape that tests the egress path users actually leak
                // through — arrives here from the RECURSIVE RESOLVER, not from
                // the device. Its source address says nothing about whether the
                // device was inside the tunnel, so folding it in would make the
                // disjoint/subset constraints below compare the wrong hosts and
                // fail or pass for reasons unrelated to TwinVPN.
                //
                // The DNS observation still counts, everywhere it matters: the
                // per-family COUNTS above are what a SILENCE phase forbids and
                // what a positive control requires. Only the ADDRESS is unusable.
                if o.family != Family::Dns {
                    sources.insert(o.source);
                }
            }

            let mut reasons: Vec<String> = Vec::new();
            match phase.expectation {
                Expectation::Silence => {
                    if !obs.is_empty() {
                        for o in &obs {
                            unauthorized.push((*o).clone());
                        }
                        reasons.push(format!(
                            "{} unauthorized observation(s) during a SILENCE phase: {}",
                            obs.len(),
                            summarise(&counts),
                        ));
                    }
                }
                Expectation::Observe => {
                    // Intersected with the criterion's own scope: a phase
                    // cannot demand a positive control for a family the
                    // criterion makes no claim about, or a Windows-only
                    // IPv4/DNS row would be dragged to INCONCLUSIVE by an IPv6
                    // leg it was never asked to have.
                    for f in families_required(phase)
                        .iter()
                        .filter(|f| in_play.contains(f))
                    {
                        if counts.get(f).copied().unwrap_or(0) == 0 {
                            reasons.push(format!(
                                "no {} egress was observed, so this phase is not a positive \
                                 control and silence elsewhere proves nothing for {}",
                                f.as_str(),
                                f.as_str(),
                            ));
                        } else {
                            families_proven_live.insert(*f);
                        }
                    }
                    if let Some(other) = &phase.sources_disjoint_from {
                        if let Some(prev) = sources_by_phase.get(other) {
                            let overlap: Vec<String> =
                                sources.intersection(prev).map(|a| a.to_string()).collect();
                            if !overlap.is_empty() {
                                reasons.push(format!(
                                    "egress still came from the {} source address(es) {} — \
                                     traffic did not move into the tunnel",
                                    other,
                                    overlap.join(", "),
                                ));
                            }
                        } else {
                            reasons.push(format!(
                                "sources_disjoint_from names phase {other:?}, which this \
                                 session never ran"
                            ));
                        }
                    }
                    if let Some(other) = &phase.sources_subset_of {
                        if let Some(prev) = sources_by_phase.get(other) {
                            let stray: Vec<String> =
                                sources.difference(prev).map(|a| a.to_string()).collect();
                            if !stray.is_empty() {
                                reasons.push(format!(
                                    "egress resumed from {} which is not in the {} source \
                                     set — traffic did not resume through TwinVPN",
                                    stray.join(", "),
                                    other,
                                ));
                            }
                        } else {
                            reasons.push(format!(
                                "sources_subset_of names phase {other:?}, which this session \
                                 never ran"
                            ));
                        }
                    }
                }
            }

            let satisfied = reasons.is_empty();
            if !satisfied {
                match phase.expectation {
                    // A leak is a failure. A missing positive control is not a
                    // failure of the product; it is a failure of the test to
                    // establish anything, and it must not read as either a pass
                    // or a product defect.
                    Expectation::Silence => failures.extend(reasons.iter().cloned()),
                    Expectation::Observe => inconclusive.extend(reasons.iter().cloned()),
                }
            }

            sources_by_phase.insert(phase.name.clone(), sources.clone());
            phases.push(PhaseReport {
                name: phase.name.clone(),
                expectation: phase.expectation,
                started_at_ms: phase.started_at_ms,
                ended_at_ms: phase.ended_at_ms,
                observations: Family::ALL
                    .iter()
                    .map(|f| (f.as_str().to_string(), counts.get(f).copied().unwrap_or(0)))
                    .collect(),
                sources: sources.iter().map(|a| a.to_string()).collect(),
                satisfied,
                reasons,
            });
        }

        // Structural preconditions. A session with no silence phase never asked
        // the question; a session with no observe phase never proved it could
        // hear the answer; an unclosed session may still be receiving.
        if !self
            .phases
            .iter()
            .any(|p| p.expectation == Expectation::Silence)
        {
            inconclusive.push(
                "the session declared no SILENCE phase, so no kill-switch \
                               claim was tested"
                    .into(),
            );
        }
        if !self
            .phases
            .iter()
            .any(|p| p.expectation == Expectation::Observe)
        {
            inconclusive.push(
                "the session declared no OBSERVE phase, so the oracle was never \
                       proved reachable"
                    .into(),
            );
        }
        if self.closed_at_ms.is_none() {
            inconclusive
                .push("the session was never closed; observations may still be arriving".into());
        }
        // Every family that a SILENCE phase claims to have blocked must have
        // been proven live somewhere, or the silence is unexamined for it.
        for f in in_play.iter().copied() {
            if !families_proven_live.contains(&f) {
                inconclusive.push(format!(
                    "{} was never observed in any OBSERVE phase, so this session cannot \
                     support a claim about {} egress",
                    f.as_str(),
                    f.as_str(),
                ));
            }
        }

        // Sentinel liveness, attempt floors and path identity. These only ever
        // ADD reasons: nothing in `evidence` can clear a leak that was already
        // recorded above.
        let ev = evidence::evaluate(self);
        failures.extend(ev.failures.iter().cloned());
        inconclusive.extend(ev.inconclusive.iter().cloned());

        // PRECEDENCE, and it is not negotiable: a leak outranks a broken test.
        // A run that both leaked and lost its sentinel is a FAIL — "the
        // measurement was flawed" must never be able to launder an observed
        // packet into a softer verdict, because the packet arrived either way.
        let verdict = if !failures.is_empty() {
            Verdict::Fail
        } else if !inconclusive.is_empty() {
            Verdict::Inconclusive
        } else {
            Verdict::Pass
        };

        Report {
            schema_version: 2,
            session_id: self.id.clone(),
            commit: self.commit.clone(),
            run_id: self.run_id.clone(),
            run_attempt: self.run_attempt.clone(),
            platform: self.platform.clone(),
            criterion: self.criterion.clone(),
            opened_at_ms: self.opened_at_ms,
            closed_at_ms: self.closed_at_ms,
            phases,
            ipv4_attempts: ev.attempts_of(Family::Ipv4),
            ipv6_attempts: ev.attempts_of(Family::Ipv6),
            dns_attempts: ev.attempts_of(Family::Dns),
            ipv4_observed: ev.observed_of(Family::Ipv4),
            ipv6_observed: ev.observed_of(Family::Ipv6),
            dns_observed: ev.observed_of(Family::Dns),
            ipv4_sentinel_continuous: ev.continuous_of(Family::Ipv4),
            ipv6_sentinel_continuous: ev.continuous_of(Family::Ipv6),
            dns_sentinel_continuous: ev.continuous_of(Family::Dns),
            sentinel_host: self.sentinel.as_ref().and_then(|s| s.host.clone()),
            sentinel_beats: self
                .sentinel
                .as_ref()
                .map(|s| s.beats.clone())
                .unwrap_or_default(),
            ipv4_identity_distinct: ev.distinct_of(Family::Ipv4),
            ipv6_identity_distinct: ev.distinct_of(Family::Ipv6),
            dns_identity_distinct: ev.distinct_of(Family::Dns),
            dns_resolver_identity_ambiguous: ev.dns_resolver_identity_ambiguous,
            unauthorized_observations: unauthorized,
            families_proven_live: families_proven_live.into_iter().collect(),
            failures,
            inconclusive,
            verdict,
        }
    }
}

fn families_required(phase: &Phase) -> Vec<Family> {
    if phase.require_families.is_empty() {
        // "any one family will do" is expressed as "none is individually
        // required"; the session-level check below still insists that every
        // family be proven live somewhere.
        Vec::new()
    } else {
        phase.require_families.clone()
    }
}

fn summarise(counts: &BTreeMap<Family, usize>) -> String {
    Family::ALL
        .iter()
        .map(|f| format!("{}={}", f.as_str(), counts.get(f).copied().unwrap_or(0)))
        .collect::<Vec<_>>()
        .join(" ")
}
