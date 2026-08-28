//! §3.5's three determinism classes, and rule **L-2** made mechanical.
//!
//! **Authority:** `docs/testing-strategy.md` §3.5, §6.1 rule **C-2**, §6.3 rule
//! **F-7**, §6.5 blocker **B-14**; ADR-0018 §11.8 **CD-6**.
//!
//! # CD-6's residual, stated rather than hidden
//!
//! Injected clocks give the core's event sequence `BIT` determinism. They do not
//! give it to a duration, because `conntrack` timers, `netem` and the kernel
//! scheduler run on real time and are outside any injected provider. §3.5 says
//! this in terms:
//!
//! > levels 1–2 achieve `BIT`; levels 6 and above achieve `BIT` only for their
//! > event *sequence*, not for their timing.
//!
//! [`Class::permits`] is that sentence as a function. A scenario that asserts an
//! exact duration while declaring `BIT` is refused at construction, which makes
//! §3.5's "review failure" a compile-time-adjacent failure instead of a habit.

use crate::error::LabError;

/// §3.5's classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Class {
    /// Two runs at the same seed produce the same ordered sequence of structured
    /// transition events and the same `reason_code` sequence.
    Bit,
    /// Reproducible in distribution over a declared run count.
    Statistical,
    /// Not reproducible. Fuzz, soak, discovery.
    Exploratory,
}

impl Class {
    /// The §3.5 spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Class::Bit => "BIT",
            Class::Statistical => "STATISTICAL",
            Class::Exploratory => "EXPLORATORY",
        }
    }

    /// Whether a test in this class may gate the given tier (rule **C-2**).
    #[must_use]
    pub const fn may_gate_tier(self, tier: Tier) -> bool {
        match self {
            // "An EXPLORATORY test MUST NOT gate T1 or T2."
            Class::Exploratory => matches!(tier, Tier::T3 | Tier::T4),
            _ => true,
        }
    }

    /// Whether an assertion of the given shape is valid for this class.
    #[must_use]
    pub const fn permits(self, shape: AssertionShape) -> bool {
        match self {
            Class::Bit => matches!(
                shape,
                AssertionShape::ExactEventSequence
                    | AssertionShape::ExactCounter
                    | AssertionShape::ExactStatePath
                    | AssertionShape::ReasonCodeSequence
                    | AssertionShape::Bound
                    | AssertionShape::Monotonicity
                    | AssertionShape::AbsenceOfCrash
            ),
            Class::Statistical => matches!(
                shape,
                AssertionShape::Rate
                    | AssertionShape::Percentile
                    | AssertionShape::Bound
                    | AssertionShape::Monotonicity
                    | AssertionShape::AbsenceOfCrash
            ),
            // "Crash/hang/sanitizer absence only. MUST NOT gate a release on a
            // numeric threshold."
            Class::Exploratory => matches!(shape, AssertionShape::AbsenceOfCrash),
        }
    }

    /// Refuses an assertion its class does not permit.
    ///
    /// # Errors
    ///
    /// [`LabError::DeterminismClass`] — §3.5 calls this "a review failure, not a
    /// flaky test", so it is raised at scenario construction rather than being
    /// discovered as flake three months later.
    pub fn check(self, shape: AssertionShape) -> Result<(), LabError> {
        if self.permits(shape) {
            Ok(())
        } else {
            Err(LabError::DeterminismClass {
                class: self.name(),
                assertion: shape.name().to_owned(),
            })
        }
    }
}

/// The kinds of assertion §3.5's table enumerates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum AssertionShape {
    /// "exactly this ordered list of transition events".
    ExactEventSequence,
    /// "exactly N retransmissions" — §3.5's own example of the invalid case.
    ExactCounter,
    /// "the machine visited exactly these states".
    ExactStatePath,
    /// "these `reason_code`s, in this order".
    ReasonCodeSequence,
    /// "≥ 80 % of runs reached a direct path".
    Rate,
    /// "p95 handshake time under X".
    Percentile,
    /// "no more than N", "within the budget" — valid in every reproducible class.
    Bound,
    /// "the backoff never decreased".
    Monotonicity,
    /// "no crash, no hang, no sanitizer report".
    AbsenceOfCrash,
    /// **An exact wall-clock duration.** Permitted by no class above level 2,
    /// which is CD-6's residual: real kernels, `conntrack`, `netem` and the
    /// scheduler are outside any injected provider.
    ExactDuration,
}

impl AssertionShape {
    /// A human name for an error message.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            AssertionShape::ExactEventSequence => "exact event sequence",
            AssertionShape::ExactCounter => "exact counter",
            AssertionShape::ExactStatePath => "exact state path",
            AssertionShape::ReasonCodeSequence => "reason_code sequence",
            AssertionShape::Rate => "rate",
            AssertionShape::Percentile => "percentile",
            AssertionShape::Bound => "bound",
            AssertionShape::Monotonicity => "monotonicity",
            AssertionShape::AbsenceOfCrash => "absence of crash/hang/sanitizer report",
            AssertionShape::ExactDuration => "exact wall-clock duration",
        }
    }
}

/// §6.1's tiers, so a scenario can declare where it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub enum Tier {
    /// Every push to a pull request. ≤ 15 min. Blocks merge.
    T1,
    /// Every merge into `main`. ≤ 60 min. Blocks `main` health.
    T2,
    /// Nightly and on every RC tag. ≤ 8 h.
    T3,
    /// Release candidate. ≤ 96 h. Blocks release.
    T4,
}

impl Tier {
    /// The tier's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Tier::T1 => "T1",
            Tier::T2 => "T2",
            Tier::T3 => "T3",
            Tier::T4 => "T4",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_refuses_an_exact_duration() {
        // CD-6's residual: this is the assertion a level-6 scenario is most
        // tempted to write and the one that makes it flaky.
        assert!(!Class::Bit.permits(AssertionShape::ExactDuration));
        assert!(Class::Bit.check(AssertionShape::ExactDuration).is_err());
    }

    #[test]
    fn no_class_permits_an_exact_duration() {
        for c in [Class::Bit, Class::Statistical, Class::Exploratory] {
            assert!(
                !c.permits(AssertionShape::ExactDuration),
                "{} must not permit an exact duration above level 2",
                c.name()
            );
        }
    }

    #[test]
    fn statistical_refuses_the_example_section_3_5_names() {
        // "An assertion of the form 'exactly 3 retransmissions' in a STATISTICAL
        // scenario is a review failure."
        assert!(!Class::Statistical.permits(AssertionShape::ExactCounter));
    }

    #[test]
    fn positive_control_each_class_permits_its_own_table_row() {
        assert!(Class::Bit.permits(AssertionShape::ExactEventSequence));
        assert!(Class::Bit.permits(AssertionShape::ExactCounter));
        assert!(Class::Statistical.permits(AssertionShape::Rate));
        assert!(Class::Exploratory.permits(AssertionShape::AbsenceOfCrash));
    }

    #[test]
    fn exploratory_may_not_gate_a_merge() {
        // Rule C-2.
        assert!(!Class::Exploratory.may_gate_tier(Tier::T1));
        assert!(!Class::Exploratory.may_gate_tier(Tier::T2));
        assert!(Class::Exploratory.may_gate_tier(Tier::T3));
        assert!(Class::Bit.may_gate_tier(Tier::T1));
    }
}
