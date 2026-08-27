//! §2.10's expected outcome classes, and the verdict a run produces.
//!
//! **Authority:** `docs/testing-strategy.md` §2.10, §3.6, §6.5 blocker **B-6**.
//!
//! # The one design decision here
//!
//! A verdict has four values, not two. `Pass` and `Fail` are the ordinary pair;
//! [`Verdict::Unavailable`] says the rig could not produce the condition, and
//! [`Verdict::Void`] says a simulator failed its §3.4.2 conformance suite so the
//! result is not merely suspect but **void** (blocker **B-15**).
//!
//! Collapsing `Unavailable` into `Pass` is the single failure mode that would
//! make this whole laboratory worthless: it turns "we have no nftables" into
//! "symmetric NAT traversal works". [`Verdict::is_evidence_of_success`] is the
//! only accessor that answers "did it work", and it answers `false` for both
//! non-verdicts.

use crate::capability::Facility;

/// What §2.10 expects of a NAT class pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum OutcomeClass {
    /// The pair should reach `WAN_DIRECT`. Falling back to `RELAYED` is a
    /// **failure**, not a pass — the row that stops this level passing vacuously.
    DirectExpected,
    /// Direct is achievable but not guaranteed; a rate over N runs is asserted.
    DirectPossible {
        /// §3.6's run count for this pair class.
        runs: u32,
        /// §3.6's minimum direct-path success rate, in percent.
        min_success_pct: u32,
    },
    /// Direct is impossible for this pair. A `WAN_DIRECT` claim indicates a
    /// broken NAT emulator (**V10**) and fails the run.
    RelayExpected,
}

impl OutcomeClass {
    /// The §2.10 spelling, for a scenario document and a run record.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            OutcomeClass::DirectExpected => "DIRECT_EXPECTED",
            OutcomeClass::DirectPossible { .. } => "DIRECT_POSSIBLE",
            OutcomeClass::RelayExpected => "RELAY_EXPECTED",
        }
    }

    /// How many runs the class needs before a verdict exists.
    #[must_use]
    pub const fn runs(self) -> u32 {
        match self {
            OutcomeClass::DirectPossible { runs, .. } => runs,
            // §3.6's table gives 20 runs even to the unconditional classes; a
            // single run is never a rate.
            _ => 20,
        }
    }
}

/// What actually happened on a pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ObservedPath {
    /// The peers reached each other over the LAN.
    LocalDirect,
    /// The peers reached each other across the simulated Internet.
    WanDirect,
    /// The peers reached each other through a relay.
    Relayed,
    /// The peers did not reach each other.
    None,
}

/// A run's verdict.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Verdict {
    /// The oracle held.
    Pass,
    /// The oracle did not hold.
    Fail {
        /// What the oracle expected.
        expected: String,
        /// What was observed.
        observed: String,
    },
    /// The rig cannot produce the condition on this host.
    ///
    /// **Not a pass.** A caller that treats this as one is defeating §3.1.
    Unavailable {
        /// The facility the host lacks.
        missing: Facility,
        /// What the scenario needed it for.
        needed_for: &'static str,
    },
    /// A simulator failed its §3.4.2 conformance suite, so every result taken
    /// from it is void (**B-15**).
    Void {
        /// Which simulator drifted.
        simulator: String,
        /// The conformance assertion that failed.
        assertion: String,
    },
}

impl Verdict {
    /// The only accessor that means "it worked".
    ///
    /// `Unavailable` and `Void` both answer `false`, which is the whole point.
    #[must_use]
    pub const fn is_evidence_of_success(&self) -> bool {
        matches!(self, Verdict::Pass)
    }

    /// Whether this verdict blocks a merge or a release.
    ///
    /// `Unavailable` does **not** block — a host without `nftables` cannot be
    /// asked to prove a NAT class — but it is reported, counted, and can never
    /// be mistaken for evidence.
    #[must_use]
    pub const fn is_blocking(&self) -> bool {
        matches!(self, Verdict::Fail { .. } | Verdict::Void { .. })
    }

    /// Checks an observation against an expected class for a single run.
    ///
    /// `DirectPossible` has no single-run verdict — it is a rate — so this
    /// returns `Pass` for any direct outcome and `Pass` for a relayed fallback,
    /// leaving the rate assertion to [`DirectPossibleTally`].
    #[must_use]
    // Two arms below both yield `Pass` and clippy would merge them. They are
    // different rows of §2.10's table — a RELAY_EXPECTED pair reaching RELAYED,
    // and a DIRECT_POSSIBLE pair reaching anything at all — and merging them
    // would make the code unreadable against the document it transcribes.
    #[allow(clippy::match_same_arms)]
    pub fn for_single_run(expected: OutcomeClass, observed: ObservedPath) -> Self {
        match (expected, observed) {
            (OutcomeClass::DirectExpected, ObservedPath::WanDirect | ObservedPath::LocalDirect) => {
                Verdict::Pass
            }
            (OutcomeClass::DirectExpected, other) => Verdict::Fail {
                expected: "WAN_DIRECT (B-6: a DIRECT_EXPECTED pair falling back to RELAYED \
                           blocks the release)"
                    .to_owned(),
                observed: format!("{other:?}"),
            },
            (OutcomeClass::RelayExpected, ObservedPath::Relayed) => Verdict::Pass,
            (OutcomeClass::RelayExpected, ObservedPath::WanDirect | ObservedPath::LocalDirect) => {
                Verdict::Fail {
                    expected: "RELAYED (B-6: a RELAY_EXPECTED pair claiming WAN_DIRECT is a \
                               broken NAT emulator, V10)"
                        .to_owned(),
                    observed: format!("{observed:?}"),
                }
            }
            (OutcomeClass::RelayExpected, ObservedPath::None) => Verdict::Fail {
                expected: "RELAYED".to_owned(),
                observed: "no path established".to_owned(),
            },
            (OutcomeClass::DirectPossible { .. }, ObservedPath::None) => Verdict::Fail {
                expected: "a direct path or a RELAYED fallback (§2.10: every failure \
                           falls back to RELAYED)"
                    .to_owned(),
                observed: "no path established".to_owned(),
            },
            (OutcomeClass::DirectPossible { .. }, _) => Verdict::Pass,
        }
    }
}

/// The rate assertion a `DIRECT_POSSIBLE` pair actually carries (§3.6).
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectPossibleTally {
    /// Runs that reached a direct path.
    pub direct: u32,
    /// Runs that fell back to a relay.
    pub relayed: u32,
    /// Runs that established nothing. Any of these fails the class outright.
    pub none: u32,
}

impl DirectPossibleTally {
    /// Records one run.
    pub fn record(&mut self, observed: ObservedPath) {
        match observed {
            ObservedPath::LocalDirect | ObservedPath::WanDirect => self.direct += 1,
            ObservedPath::Relayed => self.relayed += 1,
            ObservedPath::None => self.none += 1,
        }
    }

    /// Total runs recorded.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.direct + self.relayed + self.none
    }

    /// The §3.6 verdict: the run count must be met and the rate must clear the
    /// budget. **A budget breach is a failure, not a re-run.**
    #[must_use]
    pub fn verdict(&self, class: OutcomeClass) -> Verdict {
        let OutcomeClass::DirectPossible {
            runs,
            min_success_pct,
        } = class
        else {
            return Verdict::Fail {
                expected: "a DIRECT_POSSIBLE class".to_owned(),
                observed: class.name().to_owned(),
            };
        };
        if self.total() < runs {
            return Verdict::Fail {
                expected: format!("{runs} runs (§3.6 fixes N per pair class)"),
                observed: format!("{} runs", self.total()),
            };
        }
        if self.none > 0 {
            return Verdict::Fail {
                expected: "every non-direct run falls back to RELAYED (§2.10)".to_owned(),
                observed: format!("{} run(s) established no path at all", self.none),
            };
        }
        // Integer arithmetic, so a 79.9% rate cannot round into an 80% budget.
        if u64::from(self.direct) * 100 < u64::from(min_success_pct) * u64::from(self.total()) {
            return Verdict::Fail {
                expected: format!("direct-path success ≥ {min_success_pct}%"),
                observed: format!(
                    "{}/{} direct ({}%)",
                    self.direct,
                    self.total(),
                    self.direct * 100 / self.total().max(1)
                ),
            };
        }
        Verdict::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_is_not_evidence_of_success() {
        let v = Verdict::Unavailable {
            missing: Facility::Nftables,
            needed_for: "the N-APDM-APDF personality",
        };
        assert!(
            !v.is_evidence_of_success(),
            "an unavailable facility must never read as a pass — this is the \
             assertion that keeps §3.1 honest"
        );
        assert!(
            !v.is_blocking(),
            "absence of a facility does not block a merge"
        );
    }

    #[test]
    fn void_is_neither_a_pass_nor_merely_suspect() {
        let v = Verdict::Void {
            simulator: "N-EIM-EIF".to_owned(),
            assertion: "RFC 5780 prober reported ADF filtering".to_owned(),
        };
        assert!(!v.is_evidence_of_success());
        assert!(v.is_blocking(), "B-15: the results are void, not suspect");
    }

    #[test]
    fn direct_expected_falling_back_to_relay_fails() {
        // B-6, the row that stops §2.10 passing vacuously.
        let v = Verdict::for_single_run(OutcomeClass::DirectExpected, ObservedPath::Relayed);
        assert!(v.is_blocking(), "{v:?}");
    }

    #[test]
    fn relay_expected_claiming_direct_fails() {
        // The V10 direction: a "success" that proves the emulator is broken.
        let v = Verdict::for_single_run(OutcomeClass::RelayExpected, ObservedPath::WanDirect);
        assert!(v.is_blocking(), "{v:?}");
    }

    #[test]
    fn positive_control_direct_expected_reaching_direct_passes() {
        assert_eq!(
            Verdict::for_single_run(OutcomeClass::DirectExpected, ObservedPath::WanDirect),
            Verdict::Pass
        );
        assert_eq!(
            Verdict::for_single_run(OutcomeClass::RelayExpected, ObservedPath::Relayed),
            Verdict::Pass
        );
    }

    #[test]
    fn a_rate_below_budget_is_a_failure_not_a_rerun() {
        let class = OutcomeClass::DirectPossible {
            runs: 50,
            min_success_pct: 80,
        };
        let mut t = DirectPossibleTally::default();
        for _ in 0..39 {
            t.record(ObservedPath::WanDirect);
        }
        for _ in 0..11 {
            t.record(ObservedPath::Relayed);
        }
        // 39/50 = 78% < 80%.
        assert!(t.verdict(class).is_blocking(), "{:?}", t.verdict(class));

        // Positive control at exactly the budget: 40/50 = 80% passes, so the
        // assertion above is about the rate and not about the tally being broken.
        let mut ok = DirectPossibleTally::default();
        for _ in 0..40 {
            ok.record(ObservedPath::WanDirect);
        }
        for _ in 0..10 {
            ok.record(ObservedPath::Relayed);
        }
        assert_eq!(ok.verdict(class), Verdict::Pass);
    }

    #[test]
    fn an_incomplete_run_count_is_not_a_pass() {
        let class = OutcomeClass::DirectPossible {
            runs: 50,
            min_success_pct: 60,
        };
        let mut t = DirectPossibleTally::default();
        t.record(ObservedPath::WanDirect);
        assert!(t.verdict(class).is_blocking());
    }

    #[test]
    fn a_run_that_established_nothing_fails_even_at_a_good_rate() {
        // §2.10: "every failure falls back to RELAYED". A total failure is not a
        // permitted member of the denominator.
        let class = OutcomeClass::DirectPossible {
            runs: 20,
            min_success_pct: 60,
        };
        let mut t = DirectPossibleTally::default();
        for _ in 0..19 {
            t.record(ObservedPath::WanDirect);
        }
        t.record(ObservedPath::None);
        assert!(t.verdict(class).is_blocking());
    }
}
