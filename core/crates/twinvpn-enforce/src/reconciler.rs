//! The reconciler and the leak canary: the two mechanisms that make protection
//! **asserted** rather than assumed.
//!
//! **Authority:** ADR-0012 §11.9 (the T26/T29/T30/T32 guards and the canary),
//! §11.8 KS-20; ADR-0015 §11.6 rules 1, 2 and 4 (O-17, O-18);
//! `docs/reliability.md` §10.3's four mechanisms; `docs/testing-strategy.md` V4.
//!
//! # The indicator is a function of an observation, never of a belief
//!
//! ADR-0015 O-17: "The protection indicator is a pure function of a
//! `ProtectionAssertion` produced by **querying the enforcement layer** for both
//! families, never of the agent's belief about what it configured."
//!
//! O-18: "An unrenewed assertion makes the indicator `UNKNOWN`, never
//! `PROTECTED`." So [`Assertion::posture`] checks staleness **first**, and there
//! is no path from a stale assertion to [`Posture::Protected`].

use core::time::Duration;

use twinvpn_env::MonotonicInstant;
use twinvpn_platform::{ContractGeneration, Ruleset};
use twinvpn_types::{AddressFamily, PerFamily};

use crate::codes;

/// One observation of the enforcement layer, per family.
///
/// `PerFamily<bool>` rather than one flag, because KS-5 makes a one-family rule
/// set "**non-conforming**, not degraded" and a single boolean cannot say which
/// half is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assertion {
    /// The generation the rules were installed for.
    pub generation: ContractGeneration,
    /// The ruleset the OS actually reports, read back — never a cached value.
    pub installed: Option<Ruleset>,
    /// Whether rules are present for each family.
    pub present: PerFamily<bool>,
    /// When the assertion was taken, on the monotonic clock.
    pub asserted_at: MonotonicInstant,
    /// After this, the assertion is stale.
    pub freshness_window: Duration,
}

/// What a surface may render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    /// Rules present for both families, fresh, and matching the desired set.
    Protected,
    /// The assertion is stale. **Never `Protected`.**
    Unknown,
    /// An observation is negative.
    Unprotected(twinvpn_types::ReasonCode),
}

impl Assertion {
    /// The posture at `now`, given the ruleset the core desires.
    #[must_use]
    pub fn posture(&self, desired: Ruleset, now: MonotonicInstant) -> Posture {
        if now.duration_since(self.asserted_at) > self.freshness_window {
            return Posture::Unknown;
        }
        if self.missing_family().is_some() {
            return Posture::Unprotected(codes::ruleset_absent());
        }
        match self.installed {
            None => Posture::Unprotected(codes::ruleset_absent()),
            Some(r) if r != desired => Posture::Unprotected(codes::assertion_mismatch()),
            Some(_) => Posture::Protected,
        }
    }

    /// Which family's rules are missing, when one is.
    #[must_use]
    pub fn missing_family(&self) -> Option<AddressFamily> {
        [AddressFamily::V4, AddressFamily::V6]
            .into_iter()
            .find(|f| !*self.present.get(*f))
    }

    /// KS-5: an implementation that installs one family without the other is
    /// **non-conforming**. There is no partial-install success result, so this
    /// predicate exists to be asserted rather than handled.
    #[must_use]
    pub fn is_partial_install(&self) -> bool {
        *self.present.get(AddressFamily::V4) != *self.present.get(AddressFamily::V6)
    }
}

/// What the reconciler decided on one tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickOutcome {
    /// The installed rules match the desired ones. Nothing to do.
    Converged,
    /// The rules drifted and were re-asserted. Defense in depth: §11.3 row 3
    /// notes the 1 s re-assertion "is defense in depth, not the guarantee".
    Reasserted,
    /// The rules were tampered with or removed. Drives `EV_POLICY_VIOLATION`
    /// → `BLOCKED` (T29).
    PolicyViolation(twinvpn_types::ReasonCode),
    /// The assertion went stale. The indicator becomes `UNKNOWN`.
    AssertionStale,
}

impl TickOutcome {
    /// Whether this outcome drives T29.
    #[must_use]
    pub const fn drives_blocked(self) -> bool {
        matches!(self, TickOutcome::PolicyViolation(_))
    }
}

/// The reconciler.
///
/// Holds the desired generation and ruleset and compares them against what the
/// OS reports. It never installs anything: CB-6 puts installation in the adapter
/// and holding in the OS, and this is the "core computes" third.
#[derive(Debug, Clone, Copy)]
pub struct Reconciler {
    desired_generation: ContractGeneration,
    desired_ruleset: Ruleset,
    ticks: u64,
    violations: u64,
}

impl Reconciler {
    /// A reconciler holding `RULESET_BLOCKED` at generation zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            desired_generation: ContractGeneration(0),
            desired_ruleset: Ruleset::Blocked,
            ticks: 0,
            violations: 0,
        }
    }

    /// The ruleset the core currently wants installed.
    #[must_use]
    pub const fn desired_ruleset(&self) -> Ruleset {
        self.desired_ruleset
    }

    /// The generation the core currently wants installed.
    #[must_use]
    pub const fn desired_generation(&self) -> ContractGeneration {
        self.desired_generation
    }

    /// Advances the desired state. Generations are monotone, so a lower one is
    /// refused rather than applied.
    pub fn set_desired(&mut self, generation: ContractGeneration, ruleset: Ruleset) -> bool {
        if generation < self.desired_generation {
            return false;
        }
        self.desired_generation = generation;
        self.desired_ruleset = ruleset;
        true
    }

    /// One reconciler tick.
    ///
    /// §11.9's T29 guard: "raised by the enforcement reconciler or the leak
    /// canary on **assertion mismatch, ruleset tamper, or observed protected
    /// egress**."
    pub fn tick(&mut self, assertion: Assertion, now: MonotonicInstant) -> TickOutcome {
        self.ticks = self.ticks.saturating_add(1);
        match assertion.posture(self.desired_ruleset, now) {
            Posture::Unknown => TickOutcome::AssertionStale,
            Posture::Unprotected(code) => {
                self.violations = self.violations.saturating_add(1);
                TickOutcome::PolicyViolation(code)
            }
            Posture::Protected => {
                if assertion.generation == self.desired_generation {
                    TickOutcome::Converged
                } else {
                    TickOutcome::Reasserted
                }
            }
        }
    }

    /// How many ticks have run, and how many found a violation.
    #[must_use]
    pub const fn counters(&self) -> (u64, u64) {
        (self.ticks, self.violations)
    }
}

impl Default for Reconciler {
    fn default() -> Self {
        Self::new()
    }
}

/// The re-assertion cadence. §11.3 row 3: "The network-change subscription
/// additionally re-asserts policy within 1 s; that is defense in depth, not the
/// guarantee."
pub const REASSERT_WITHIN: Duration = Duration::from_secs(1);

/// KS-20: rule state is owner-tagged and reclaimable by a fresh process after an
/// unclean exit.
///
/// > A crash must leave the host **blocked, never open**; and a privileged local
/// > unblock command MUST exist so that "blocked" is not "bricked".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reclamation {
    /// The owner tag on the installed rules.
    pub owner_tag: String,
    /// The ruleset found in place.
    pub found: Option<Ruleset>,
}

impl Reclamation {
    /// What a fresh process should do with what it found.
    ///
    /// Finding nothing is the dangerous case and the answer is to install
    /// `Blocked` — never to assume the host was left protected.
    #[must_use]
    pub const fn action(&self) -> ReclamationAction {
        match self.found {
            None => ReclamationAction::InstallBlocked,
            Some(Ruleset::Blocked) => ReclamationAction::Adopt,
            // A previous process died holding PROTECTED with no live tunnel
            // behind it. Tightening is always safe; adopting would leave a hole.
            Some(Ruleset::Protected) => ReclamationAction::TightenToBlocked,
        }
    }
}

/// What reclamation does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclamationAction {
    /// Nothing was installed: install `RULESET_BLOCKED` before anything else.
    InstallBlocked,
    /// `RULESET_BLOCKED` was already in place; take ownership of it.
    Adopt,
    /// `RULESET_PROTECTED` was left behind with no tunnel; swap to blocked.
    TightenToBlocked,
}
