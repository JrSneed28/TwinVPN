//! The two things a SILENCE phase's emptiness cannot establish on its own.
//!
//! # The hole this module closes
//!
//! `lib.rs` already refuses to call a session `PASS` unless some OBSERVE phase
//! proved each family could reach the oracle. That is a positive control at
//! ONE moment, before the armed window opens. It says nothing about whether the
//! listeners were still alive for the whole of the window that follows.
//!
//! The concrete failure: the oracle's IPv6 accept loop dies ten seconds into
//! SILENCE — the task panicked, the host ran out of file descriptors, an
//! operator restarted the process, the security group changed under it. The
//! session then records zero IPv6 observations during the armed window, which
//! is byte-for-byte what a perfect kill switch records. Under the old model
//! that was a `PASS`. It is now `INCONCLUSIVE`.
//!
//! Two facts are added, and neither is produced by the device under test:
//!
//! * the **sentinel** — an independent heartbeat source that is not the DUT and
//!   does not traverse the DUT's network. It beats at the same three data-plane
//!   listeners on a cadence, carrying its OWN token so that a heartbeat which
//!   proves the ears were open is never mistaken for a leak. Continuity across
//!   every SILENCE phase is the evidence; a gap wider than the configured
//!   cadence is the oracle dying, and zero beats is not continuity.
//! * the **path identity** — the protected and the unprotected egress paths
//!   must be two DISTINGUISHABLE things. If both leave from the same address,
//!   or both resolve through the same resolver, then "traffic moved into the
//!   tunnel" was never observable in the first place and a silent window says
//!   nothing about which path was silent.
//!
//! For DNS the identity is derived from the address the query ARRIVED from,
//! looked up in a configured resolver map. It is never taken from the probe's
//! own `path_tag` label, and never from an authoritative server claiming to
//! have seen an original client IP — both of those are the defendant testifying.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::{Expectation, Family, Session};

/// Which of the two egress paths something belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathKind {
    /// `p` is accepted as an alias so the single letter the DNS probe already
    /// puts in a query name is the same token the control API takes for a
    /// phase. One vocabulary, spelled two ways, rather than two vocabularies.
    #[serde(alias = "p")]
    Protected,
    #[serde(alias = "u")]
    Unprotected,
}

impl PathKind {
    /// A path letter, and only a path letter: `p` or `u`. Used where something
    /// MUST name a path — a `--resolver` map entry, say — and where `n` or `s`
    /// would be a configuration mistake rather than a legitimate abstention.
    pub fn from_tag(tag: &str) -> Option<PathKind> {
        match tag {
            "p" => Some(PathKind::Protected),
            "u" => Some(PathKind::Unprotected),
            _ => None,
        }
    }

    /// Both spellings the control API accepts for a path.
    pub fn from_wire(value: &str) -> Option<PathKind> {
        match value {
            "p" | "protected" => Some(PathKind::Protected),
            "u" | "unprotected" => Some(PathKind::Unprotected),
            _ => None,
        }
    }

    /// Read the `<path_tag>` label out of a beacon name.
    ///
    /// The outer `Option` answers "was that label a tag at all", the inner one
    /// "did it name a path". They are genuinely different questions, and
    /// collapsing them is a parsing bug with a nasty shape: an unrecognised
    /// label is left in place and becomes the TOKEN, so the beacon matches no
    /// session, is dropped, and the family reports zero arrivals — a beacon
    /// that never arrived and a beacon that was misparsed look identical in the
    /// evidence.
    ///
    /// Four letters are tags. `p` and `u` name a path. `n` is the probe stating
    /// that this phase makes NO path claim, which must not be read as either
    /// path. `s` marks a sentinel beacon; it carries no path because a sentinel
    /// has none, and it is the token index, not this letter, that decides
    /// whether an arrival is a beat or an observation.
    pub fn strip_tag(label: &str) -> Option<Option<PathKind>> {
        match label {
            "p" | "u" => Some(PathKind::from_tag(label)),
            "n" | "s" => Some(None),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PathKind::Protected => "protected",
            PathKind::Unprotected => "unprotected",
        }
    }
}

/// One heartbeat from the sentinel that actually arrived at a listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelBeat {
    pub family: Family,
    /// The peer address the kernel reported, kept for the same reason an
    /// observation keeps one: so a reader can tell a real sentinel beat from
    /// something else that happened to know the token.
    pub source: IpAddr,
    pub at_ms: u64,
}

/// The sentinel's configuration and everything it managed to deliver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelEvidence {
    /// Distinct from `Session::probe_token` BY CONSTRUCTION. If one token
    /// served both, every heartbeat proving the oracle was alive during the
    /// armed window would also be recorded as an unauthorized arrival — the
    /// liveness check would manufacture the leak it exists to rule out.
    pub token: String,
    /// The widest gap between consecutive beats that still counts as continuous.
    /// Set from the sentinel's cadence with slack; it is the resolution at which
    /// "the oracle was up" is being claimed.
    pub max_gap_ms: u64,
    /// Free-text identifier of the machine running the sentinel, as claimed by
    /// whoever started it. WHERE the sentinel ran is the whole independence
    /// claim, so it travels into the report to be read by a human — the oracle
    /// cannot verify it, and `is_dut_sourced` is the check that does not need
    /// to trust it.
    #[serde(default)]
    pub host: Option<String>,
    pub beats: Vec<SentinelBeat>,
}

/// What the oracle derives a DNS arrival's path from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolverEntry {
    /// A stable name for the resolver, e.g. `isp-recursive` or `twinvpn-dns`.
    pub id: String,
    pub path: PathKind,
}

/// The new report fields, plus the reasons they contribute to the verdict.
#[derive(Debug, Clone, Default)]
pub struct EvidenceOutcome {
    pub attempts: BTreeMap<Family, u64>,
    pub observed: BTreeMap<Family, u64>,
    pub sentinel_continuous: BTreeMap<Family, bool>,
    /// `None` for a family the criterion makes no claim about. `None` is not
    /// `true`: a reader that treats a null as a pass is reading it wrong, and
    /// `report.py` is required to reject that shape.
    pub identity_distinct: BTreeMap<Family, Option<bool>>,
    pub dns_resolver_identity_ambiguous: bool,
    pub failures: Vec<String>,
    pub inconclusive: Vec<String>,
}

impl EvidenceOutcome {
    pub fn attempts_of(&self, f: Family) -> u64 {
        self.attempts.get(&f).copied().unwrap_or(0)
    }

    pub fn observed_of(&self, f: Family) -> u64 {
        self.observed.get(&f).copied().unwrap_or(0)
    }

    /// Absent evidence reads as NOT continuous. There is no path through this
    /// accessor that turns a missing entry into `true`.
    pub fn continuous_of(&self, f: Family) -> bool {
        self.sentinel_continuous.get(&f).copied().unwrap_or(false)
    }

    pub fn distinct_of(&self, f: Family) -> Option<bool> {
        self.identity_distinct.get(&f).copied().flatten()
    }
}

/// Is `at_ms` inside any SILENCE phase? Phases are back-to-back by
/// construction, so this is exactly "was this arrival forbidden".
fn in_silence(session: &Session, at_ms: u64) -> bool {
    session.phases.iter().any(|p| {
        p.expectation == Expectation::Silence
            && at_ms >= p.started_at_ms
            && at_ms < p.ended_at_ms.unwrap_or(u64::MAX)
    })
}

/// Continuity for one family across every SILENCE phase.
///
/// Definition, and the edge cases are the point: over a phase `[t0, t1]` the
/// sequence `{t0} ∪ beats(F) ∪ {t1}` must have every consecutive gap `<=
/// max_gap_ms`. Anchoring at both ends is what catches an oracle that died at
/// the START of the window (beats begin late) or one that died and never came
/// back (beats stop early) — checking only the gaps BETWEEN beats would miss
/// both. A family with zero beats is not continuous no matter how short the
/// window was.
///
/// `dut_sources` are the addresses the DEVICE was observed egressing from.
/// Beats from those addresses do not count as continuity — see
/// [`non_independent_beats`].
fn sentinel_continuous(
    session: &Session,
    family: Family,
    dut_sources: &BTreeSet<IpAddr>,
) -> Result<(), String> {
    let Some(sentinel) = &session.sentinel else {
        return Err(format!(
            "the session carries no sentinel evidence at all, so nothing establishes that the \
             {} listener was still alive during the armed window; an oracle that died records \
             the same silence a kill switch does",
            family.as_str()
        ));
    };

    let silences: Vec<_> = session
        .phases
        .iter()
        .filter(|p| p.expectation == Expectation::Silence)
        .collect();
    if silences.is_empty() {
        return Err(format!(
            "there is no SILENCE phase for the {} sentinel to have covered",
            family.as_str()
        ));
    }

    for phase in silences {
        let t0 = phase.started_at_ms;
        let t1 = phase
            .ended_at_ms
            .or(session.closed_at_ms)
            .unwrap_or(phase.started_at_ms);
        let mut beats: Vec<u64> = sentinel
            .beats
            .iter()
            .filter(|b| b.family == family && b.at_ms >= t0 && b.at_ms <= t1)
            .filter(|b| !is_dut_sourced(b, dut_sources))
            .map(|b| b.at_ms)
            .collect();
        beats.sort_unstable();

        if beats.is_empty() {
            return Err(format!(
                "the {} sentinel delivered no beats at all during the {:?} phase \
                 [{t0}ms, {t1}ms], so the {} listener is not known to have been alive for any \
                 of it",
                family.as_str(),
                phase.name,
                family.as_str(),
            ));
        }

        let mut prev = t0;
        for at in beats.iter().copied().chain(std::iter::once(t1)) {
            let gap = at.saturating_sub(prev);
            if gap > sentinel.max_gap_ms {
                return Err(format!(
                    "the {} sentinel went quiet for {gap}ms during the {:?} phase (from {prev}ms \
                     to {at}ms), which is over the {}ms cadence — the oracle was not observably \
                     listening for that window, so its silence is not evidence",
                    family.as_str(),
                    phase.name,
                    sentinel.max_gap_ms,
                ));
            }
            prev = at;
        }
    }
    Ok(())
}

/// Did this "sentinel" beat actually come from the device under test?
///
/// The sentinel's whole claim is that it does not traverse the DUT's network,
/// and the sentinel token is deliberately never handed to the DUT. But a token
/// that leaks is a token that leaks, and the consequence would be severe: a
/// device that beat the sentinel token from its own address during the armed
/// window would be emitting a packet the kill switch was supposed to stop, and
/// that packet would be filed as PROOF THE ORACLE WAS ALIVE instead of as the
/// leak it is. The independence claim has to be checked, not assumed.
///
/// Only IPv4 and IPv6 are checked. A DNS beat arrives from a RESOLVER whether
/// the sentinel or the device sent it, so its source address cannot separate
/// the two — the same reason `lib.rs` keeps DNS out of the phase source sets.
//
// ponytail: address equality only. A DUT behind the same NAT as the sentinel
// would still pass; separate the two networks, or pin `sentinel_sources`, if a
// deployment ever needs more than this.
fn is_dut_sourced(beat: &SentinelBeat, dut_sources: &BTreeSet<IpAddr>) -> bool {
    beat.family != Family::Dns && dut_sources.contains(&beat.source)
}

/// A beat from the device's own address is not independent evidence, and it is
/// named rather than only silently dropped from the continuity arithmetic.
///
/// It is INCONCLUSIVE, not FAIL, and the reason is a topology the oracle cannot
/// see: a device behind the same NAT as the sentinel presents the same public
/// address as the sentinel does, so "this beat came from the device" and "this
/// beat came from a sentinel sharing the device's egress IP" are the same
/// observation. Calling that a leak would accuse the product of a defect on the
/// strength of a network layout. INCONCLUSIVE already blocks the gate exactly
/// as a failure does — `report.py` counts it the same way — so nothing ships on
/// the back of this, and nothing is accused on the back of a guess.
fn non_independent_beats(session: &Session, dut_sources: &BTreeSet<IpAddr>) -> Vec<String> {
    let Some(sentinel) = &session.sentinel else {
        return Vec::new();
    };
    sentinel
        .beats
        .iter()
        .filter(|b| is_dut_sourced(b, dut_sources) && in_silence(session, b.at_ms))
        .map(|b| {
            format!(
                "a {} sentinel beat arrived at {}ms from {}, which is an address the device \
                 itself was observed egressing from — either the device emitted it or the \
                 sentinel shares the device's egress path, and neither is the independent \
                 heartbeat this check needs, so it does not count as evidence that the oracle \
                 was listening",
                b.family.as_str(),
                b.at_ms,
                b.source,
            )
        })
        .collect()
}

/// Derive everything in this module from one session. Pure, like
/// [`Session::report`], so a test drives it directly.
pub fn evaluate(session: &Session) -> EvidenceOutcome {
    let in_play = session.families_in_play();
    let mut out = EvidenceOutcome::default();

    // The addresses the DEVICE was seen egressing from, used below to refuse a
    // "sentinel" that is really the device. DNS is excluded for the usual
    // reason: that address belongs to a resolver, not to the device.
    let dut_sources: BTreeSet<IpAddr> = session
        .observations
        .iter()
        .filter(|o| o.family != Family::Dns)
        .map(|o| o.source)
        .collect();
    out.inconclusive
        .extend(non_independent_beats(session, &dut_sources));

    // ---- forbidden arrivals, per family -----------------------------------
    // The FAIL itself is raised by `Session::report`, which names each leaking
    // packet. This is the counter the acceptance report reads.
    for o in &session.observations {
        if in_silence(session, o.at_ms) {
            *out.observed.entry(o.family).or_insert(0) += 1;
        }
    }

    // ---- DUT self-reported attempts ---------------------------------------
    // Self-reported because only the device can count what it TRIED to send.
    // It is used in exactly one direction: to catch a probe that barely ran. It
    // can never establish silence, because a lying device would just claim a
    // large number, and a large number is not what makes a session pass.
    for f in Family::ALL {
        out.attempts
            .insert(f, session.attempts.get(&f).copied().unwrap_or(0));
    }
    for f in &in_play {
        let got = out.attempts_of(*f);
        // An unconfigured minimum is still a minimum of one. A family the probe
        // never emitted on has not been shown to be blocked; it has been shown
        // to be unexercised, and those two must not share a verdict.
        let min = session.attempt_minimums.get(f).copied().unwrap_or(0).max(1);
        if got < min {
            out.inconclusive.push(format!(
                "the device reported {got} {} probe attempt(s), below the required minimum of \
                 {min}; a window nothing was sent into is silent for the wrong reason",
                f.as_str(),
            ));
        }
    }

    // ---- sentinel continuity ----------------------------------------------
    for f in Family::ALL {
        match sentinel_continuous(session, f, &dut_sources) {
            Ok(()) => {
                out.sentinel_continuous.insert(f, true);
            }
            Err(why) => {
                out.sentinel_continuous.insert(f, false);
                // Only a family the criterion claims something about can make
                // the session inconclusive; the flag is still reported false
                // for the others, because false is what the evidence says.
                if in_play.contains(&f) {
                    out.inconclusive.push(why);
                }
            }
        }
    }

    // ---- path identity ----------------------------------------------------
    let mut protected: BTreeMap<Family, BTreeSet<String>> = BTreeMap::new();
    let mut unprotected: BTreeMap<Family, BTreeSet<String>> = BTreeMap::new();

    // IPv4 and IPv6: the identity is the source address the kernel reported for
    // arrivals inside a phase the probe tagged as one path or the other. DNS is
    // excluded here for the same reason `lib.rs` keeps it out of the source
    // sets — the address belongs to a resolver, not to the device.
    for phase in &session.phases {
        let Some(kind) = phase.path else { continue };
        let side = match kind {
            PathKind::Protected => &mut protected,
            PathKind::Unprotected => &mut unprotected,
        };
        for o in session.observations_in(phase) {
            if o.family == Family::Dns {
                continue;
            }
            side.entry(o.family)
                .or_default()
                .insert(o.source.to_string());
        }
    }

    // DNS: derived from the ARRIVING resolver address only.
    for o in session
        .observations
        .iter()
        .filter(|o| o.family == Family::Dns)
    {
        let Some(entry) = session.resolver_map.get(&o.source) else {
            out.dns_resolver_identity_ambiguous = true;
            continue;
        };
        let side = match entry.path {
            PathKind::Protected => &mut protected,
            PathKind::Unprotected => &mut unprotected,
        };
        side.entry(Family::Dns)
            .or_default()
            .insert(entry.id.clone());

        // The probe's own label is evidence of INTENT, never of routing. Where
        // the two disagree the query did not take the path the test believed it
        // was testing, and during the armed window that is a leak through the
        // wrong resolver rather than a bookkeeping problem.
        if let Some(tag) = o.path_tag {
            if tag != entry.path {
                let msg = format!(
                    "a DNS query the probe labelled `{}` arrived from {}, which the resolver map \
                     places on the {} path as {:?} — the query did not resolve over the path the \
                     probe intended",
                    tag.as_str(),
                    o.source,
                    entry.path.as_str(),
                    entry.id,
                );
                if in_silence(session, o.at_ms) {
                    out.failures.push(msg);
                } else {
                    out.inconclusive.push(msg);
                }
            }
        }
    }

    if out.dns_resolver_identity_ambiguous {
        out.inconclusive.push(
            "at least one DNS query arrived from an address in no configured resolver map entry, \
             so which path resolved it cannot be derived; an unattributable resolver could be \
             either path, and guessing is how a leak through the wrong one is recorded as clean"
                .into(),
        );
    }

    for f in Family::ALL {
        if !in_play.contains(&f) {
            out.identity_distinct.insert(f, None);
            continue;
        }
        let p = protected.get(&f).cloned().unwrap_or_default();
        let u = unprotected.get(&f).cloned().unwrap_or_default();
        let distinct = !p.is_empty() && !u.is_empty() && p.is_disjoint(&u);
        out.identity_distinct.insert(f, Some(distinct));
        if !distinct {
            out.inconclusive.push(if p.is_empty() || u.is_empty() {
                format!(
                    "the session never established both a protected and an unprotected {} path \
                     identity (protected: [{}], unprotected: [{}]), so no arrival can be \
                     attributed to a path",
                    f.as_str(),
                    p.iter().cloned().collect::<Vec<_>>().join(", "),
                    u.iter().cloned().collect::<Vec<_>>().join(", "),
                )
            } else {
                format!(
                    "the protected and unprotected {} path identities overlap on [{}]; the two \
                     paths are indistinguishable, so a silent window does not say which of them \
                     was silent",
                    f.as_str(),
                    p.intersection(&u).cloned().collect::<Vec<_>>().join(", "),
                )
            });
        }
    }

    out
}
