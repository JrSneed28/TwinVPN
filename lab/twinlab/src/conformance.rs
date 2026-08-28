//! §3.4.2's simulator conformance suite — control **V10**, rule **L-1**.
//!
//! **Authority:** `docs/testing-strategy.md` §3.4.2, §6.5 blocker **B-15**.
//!
//! > **Rule L-1.** No traversal, leak, or relay test may run against a
//! > personality or impairment that has not passed its conformance suite **in
//! > the same lab instantiation, on the same day**.
//!
//! # Why the prober is deliberately not TwinVPN code
//!
//! §3.4.2 requires "an independent RFC 5780-style behaviour prober (**not
//! TwinVPN code**)". A personality checked by the same traversal logic that will
//! later be tested against it proves nothing: a shared misunderstanding of RFC
//! 4787 passes both. [`Prober`] is therefore a trait with **no implementation in
//! this crate**, and [`ConformanceSuite::run`] returns
//! [`crate::outcome::Verdict::Unavailable`] when none is bound.
//!
//! That is the honest state today: no independent prober is available on this
//! host, so no NAT personality has passed conformance, so **L-1 forbids running
//! a traversal test against one** — and the suite says so rather than skipping
//! quietly.

use crate::capability::Facility;
use crate::impair::Impairment;
use crate::nat::{Filtering, Mapping, Personality};
use crate::outcome::Verdict;
use crate::record::ConformanceResult;

/// What an independent prober reports about a middlebox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedBehaviour {
    /// The mapping behaviour it measured.
    pub mapping: Mapping,
    /// The filtering behaviour it measured.
    pub filtering: Filtering,
    /// The measured mapping lifetime, in seconds.
    pub lifetime_s: u32,
    /// Whether hairpinning worked.
    pub hairpin: bool,
    /// Which family it probed. §3.4.2 requires **both**.
    pub family_v6: bool,
}

/// An RFC 5780-style behaviour prober, external to TwinVPN.
///
/// Implemented by an external binary adapter, never by TwinVPN's own traversal
/// code — that independence is the whole value of the control.
pub trait Prober: Send + Sync {
    /// A short name for the run record, e.g. `"stuntman-client 1.2.16"`.
    fn name(&self) -> &str;

    /// Probes `middlebox` for `family_v6` and reports what it saw.
    ///
    /// # Errors
    ///
    /// A message describing why the probe could not be taken. An error is
    /// **not** a conformance pass.
    fn probe(&self, middlebox: &str, family_v6: bool) -> Result<ObservedBehaviour, String>;
}

/// The suite §3.4.2 tabulates.
pub struct ConformanceSuite<'a> {
    prober: Option<&'a dyn Prober>,
    results: Vec<ConformanceResult>,
}

impl<'a> ConformanceSuite<'a> {
    /// A suite with no prober bound. Every NAT row is `Unavailable`.
    #[must_use]
    pub fn without_prober() -> Self {
        Self {
            prober: None,
            results: Vec::new(),
        }
    }

    /// A suite driven by an external prober.
    #[must_use]
    pub fn with_prober(prober: &'a dyn Prober) -> Self {
        Self {
            prober: Some(prober),
            results: Vec::new(),
        }
    }

    /// The accumulated results, for the run record.
    #[must_use]
    pub fn results(&self) -> &[ConformanceResult] {
        &self.results
    }

    /// Runs §3.4.2's NAT-personality row for `middlebox`, **for both families**.
    ///
    /// A row that ran on one family only is recorded as failed, not as passed:
    /// L-5 makes both families a precondition, and a v4-only conformance result
    /// would silently license every v6 traversal claim.
    pub fn nat_personality(&mut self, middlebox: &str, declared: Personality) -> Verdict {
        let Some(prober) = self.prober else {
            return Verdict::Unavailable {
                missing: Facility::Nftables,
                needed_for: "§3.4.2 requires an independent RFC 5780-style prober, which is not \
                             TwinVPN code and is not bound on this host; L-1 therefore forbids \
                             running a traversal test against this personality",
            };
        };
        for family_v6 in [false, true] {
            let assertion = format!(
                "{} reports mapping={:?} filtering={:?} for {}",
                prober.name(),
                declared.mapping(),
                declared.filtering(),
                if family_v6 { "IPv6" } else { "IPv4" }
            );
            match prober.probe(middlebox, family_v6) {
                Ok(obs) => {
                    let ok = obs.mapping == declared.mapping()
                        && obs.filtering == declared.filtering()
                        && obs.family_v6 == family_v6;
                    self.results.push(ConformanceResult {
                        simulator: format!("{middlebox}:{}", declared.name()),
                        assertion: assertion.clone(),
                        passed: ok,
                    });
                    if !ok {
                        return Verdict::Void {
                            simulator: format!("{middlebox}:{}", declared.name()),
                            assertion: format!(
                                "{assertion}; observed mapping={:?} filtering={:?}",
                                obs.mapping, obs.filtering
                            ),
                        };
                    }
                }
                Err(why) => {
                    self.results.push(ConformanceResult {
                        simulator: format!("{middlebox}:{}", declared.name()),
                        assertion: assertion.clone(),
                        passed: false,
                    });
                    return Verdict::Void {
                        simulator: format!("{middlebox}:{}", declared.name()),
                        assertion: format!("{assertion}; the probe failed: {why}"),
                    };
                }
            }
        }
        Verdict::Pass
    }

    /// §3.4.2's loss-shim row: "two runs at one seed drop the **identical**
    /// packet indices", and the measured rate is within tolerance.
    ///
    /// This row **is** runnable without a prober, because the schedule is ours
    /// and its property is arithmetic rather than behavioural.
    pub fn loss_shim(
        &mut self,
        a: &crate::impair::LossSchedule,
        b: &crate::impair::LossSchedule,
        declared_pct: u32,
    ) -> Verdict {
        let identical = a.dropped_indices() == b.dropped_indices();
        self.results.push(ConformanceResult {
            simulator: "seeded-loss-schedule".to_owned(),
            assertion: "two runs at one seed drop the identical packet indices".to_owned(),
            passed: identical,
        });
        if !identical {
            return Verdict::Void {
                simulator: "seeded-loss-schedule".to_owned(),
                assertion: "two runs at one seed dropped different packet indices".to_owned(),
            };
        }
        let expected = (a.len() * declared_pct.min(100) as usize) / 100;
        let within = a.drop_count() == expected;
        self.results.push(ConformanceResult {
            simulator: "seeded-loss-schedule".to_owned(),
            assertion: format!("measured drop count equals the declared {declared_pct}%"),
            passed: within,
        });
        if within {
            Verdict::Pass
        } else {
            Verdict::Void {
                simulator: "seeded-loss-schedule".to_owned(),
                assertion: format!(
                    "declared {declared_pct}% over {} packets is {expected} drops; the schedule \
                     has {}",
                    a.len(),
                    a.drop_count()
                ),
            }
        }
    }

    /// Which §3.4.2 row an impairment needs before it may be used.
    #[must_use]
    pub fn row_for(impairment: &Impairment) -> &'static str {
        match impairment {
            Impairment::SeededLoss { .. }
            | Impairment::StatisticalLoss { .. }
            | Impairment::Duplication { .. }
            | Impairment::Reordering { .. } => "loss / duplication / reorder shim",
            Impairment::PmtuBlackHole { .. } => "PMTU black hole",
            Impairment::BlockedUdp { .. } | Impairment::EgressRestrictedTo443 { .. } => {
                "egress filter"
            }
            _ => "no conformance row",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::impair::LossSchedule;
    use crate::seed::{LabEnv, ScenarioSeed};

    struct HonestProber(Personality);

    impl Prober for HonestProber {
        fn name(&self) -> &'static str {
            "test-prober"
        }
        fn probe(&self, _m: &str, family_v6: bool) -> Result<ObservedBehaviour, String> {
            Ok(ObservedBehaviour {
                mapping: self.0.mapping(),
                filtering: self.0.filtering(),
                lifetime_s: 120,
                hairpin: false,
                family_v6,
            })
        }
    }

    struct DriftedProber;

    impl Prober for DriftedProber {
        fn name(&self) -> &'static str {
            "test-prober"
        }
        fn probe(&self, _m: &str, family_v6: bool) -> Result<ObservedBehaviour, String> {
            // The personality was declared EIF but behaves APDF: exactly the
            // drift §3.4.2 exists to catch, and the drift that would make every
            // DIRECT_EXPECTED result meaningless.
            Ok(ObservedBehaviour {
                mapping: Mapping::EndpointIndependent,
                filtering: Filtering::AddressPortDependent,
                lifetime_s: 120,
                hairpin: false,
                family_v6,
            })
        }
    }

    struct V4OnlyProber;

    impl Prober for V4OnlyProber {
        fn name(&self) -> &'static str {
            "test-prober"
        }
        fn probe(&self, _m: &str, _family_v6: bool) -> Result<ObservedBehaviour, String> {
            Ok(ObservedBehaviour {
                mapping: Mapping::EndpointIndependent,
                filtering: Filtering::EndpointIndependent,
                lifetime_s: 120,
                hairpin: false,
                family_v6: false, // always answers about v4
            })
        }
    }

    #[test]
    fn without_a_prober_no_personality_is_conformant_and_l_1_blocks_the_test() {
        let mut s = ConformanceSuite::without_prober();
        let v = s.nat_personality("nat-a", Personality::EimEif);
        assert!(matches!(v, Verdict::Unavailable { .. }), "{v:?}");
        assert!(!v.is_evidence_of_success());
    }

    #[test]
    fn a_drifted_personality_voids_the_run() {
        let p = DriftedProber;
        let mut s = ConformanceSuite::with_prober(&p);
        let v = s.nat_personality("nat-a", Personality::EimEif);
        assert!(v.is_blocking(), "{v:?}");
        assert!(matches!(v, Verdict::Void { .. }));
    }

    #[test]
    fn positive_control_an_honest_personality_passes_both_families() {
        let p = HonestProber(Personality::EimApdf);
        let mut s = ConformanceSuite::with_prober(&p);
        assert_eq!(
            s.nat_personality("nat-a", Personality::EimApdf),
            Verdict::Pass
        );
        assert_eq!(s.results().len(), 2, "one result per family");
    }

    #[test]
    fn a_prober_that_only_ever_answers_about_v4_does_not_certify_v6() {
        // L-5's teeth: a v4-only conformance result would license every IPv6
        // traversal claim in the matrix for free.
        let p = V4OnlyProber;
        let mut s = ConformanceSuite::with_prober(&p);
        let v = s.nat_personality("nat-a", Personality::EimEif);
        assert!(v.is_blocking(), "{v:?}");
    }

    #[test]
    fn the_loss_shim_row_passes_at_one_seed_and_voids_across_two() {
        let env = |n: u8| LabEnv::new(ScenarioSeed::from_bytes([n; 16]));
        let a = LossSchedule::derive(&env(1), 10_000, 2).unwrap();
        let a2 = LossSchedule::derive(&env(1), 10_000, 2).unwrap();
        let b = LossSchedule::derive(&env(2), 10_000, 2).unwrap();

        let mut ok = ConformanceSuite::without_prober();
        assert_eq!(ok.loss_shim(&a, &a2, 2), Verdict::Pass);

        let mut bad = ConformanceSuite::without_prober();
        assert!(bad.loss_shim(&a, &b, 2).is_blocking());
    }

    #[test]
    fn the_loss_shim_row_catches_a_rate_that_does_not_match_the_declaration() {
        let env = LabEnv::new(ScenarioSeed::from_bytes([9; 16]));
        let s = LossSchedule::derive(&env, 10_000, 2).unwrap();
        let mut suite = ConformanceSuite::without_prober();
        // Declared 5%, produced 2%: the emulator and the scenario disagree.
        assert!(suite.loss_shim(&s, &s, 5).is_blocking());
    }
}
