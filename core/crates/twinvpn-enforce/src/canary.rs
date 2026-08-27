//! The leak canary — active detection, per family.
//!
//! **Authority:** ADR-0012 §11.9 (the canary, K12), `docs/testing-strategy.md`
//! V4, `docs/reliability.md` §10.3 mechanism 4; ADR-0011 DN-28.
//!
//! # What it does, verbatim
//!
//! > **Per family**, at each existing network-change and keepalive wake point,
//! > the agent emits a uniquely marked datagram from a **non-exempt** socket to a
//! > destination in the protected scope and asserts that the enforcement layer's
//! > deny counter for that family incremented. A canary that does not increment
//! > is `POLICY.LEAK.EGRESS_OBSERVED` at `CRITICAL`.
//!
//! Three details are load-bearing and each is encoded:
//!
//! 1. **Per family.** [`Canary`] keeps a `PerFamily` of counters; a v4-only
//!    canary would prove nothing about the leak channel P07 exists to test.
//! 2. **From a non-exempt socket.** A probe sent on a `BOOTSTRAP`-registered
//!    socket would be permitted by design and would therefore always "leak",
//!    inverting the test.
//! 3. **The deny counter must increment.** Absence of an observed packet is not
//!    evidence; V4 requires that "the same rig demonstrably observes the leak in
//!    the unprotected control run".

use twinvpn_types::{AddressFamily, PerFamily, ReasonCode};

use crate::codes;

/// One canary probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// Which family this probe tests. There is one per family, always.
    pub family: AddressFamily,
    /// The unique mark, so the deny counter can be attributed to this probe and
    /// not to ordinary traffic.
    pub mark: u64,
    /// Whether the probe was emitted from a **non-exempt** socket.
    ///
    /// `false` invalidates the result: an exempt socket is permitted by design.
    pub from_non_exempt_socket: bool,
}

/// The result of one probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The deny counter incremented. Enforcement is working for this family.
    Denied,
    /// The counter did not increment: the packet was **not** dropped.
    /// `POLICY.LEAK.EGRESS_OBSERVED`, `CRITICAL`, and it drives `BLOCKED`.
    EgressObserved,
    /// The probe was invalid — sent from an exempt socket — so it proves
    /// nothing. Reported rather than counted as a pass.
    Invalid,
}

impl Verdict {
    /// Whether this verdict drives `EV_POLICY_VIOLATION` → `BLOCKED` (T29).
    #[must_use]
    pub const fn drives_blocked(self) -> bool {
        matches!(self, Verdict::EgressObserved)
    }

    /// The registered code, where there is one.
    #[must_use]
    pub fn reason_code(self) -> Option<ReasonCode> {
        match self {
            Verdict::Denied => None,
            Verdict::EgressObserved => Some(codes::egress_observed()),
            Verdict::Invalid => Some(codes::invariant_violated()),
        }
    }
}

/// The canary's bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Canary {
    /// The last deny-counter reading, per family.
    last_deny_counts: PerFamily<u64>,
    /// How many probes have run, per family.
    probes: PerFamily<u64>,
}

impl Default for Canary {
    fn default() -> Self {
        Self::new()
    }
}

impl Canary {
    /// A fresh canary.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_deny_counts: PerFamily::new(0, 0),
            probes: PerFamily::new(0, 0),
        }
    }

    /// Evaluates one probe against the enforcement layer's current deny counter
    /// for that family.
    pub fn observe(&mut self, probe: Probe, deny_count_now: u64) -> Verdict {
        if !probe.from_non_exempt_socket {
            return Verdict::Invalid;
        }
        *self.probes.get_mut(probe.family) += 1;
        let before = *self.last_deny_counts.get(probe.family);
        *self.last_deny_counts.get_mut(probe.family) = deny_count_now;
        if deny_count_now > before {
            Verdict::Denied
        } else {
            Verdict::EgressObserved
        }
    }

    /// How many probes have run for a family.
    #[must_use]
    pub fn probes(&self, family: AddressFamily) -> u64 {
        *self.probes.get(family)
    }

    /// Whether both families have been probed at least once.
    ///
    /// A canary that has only ever run for v4 has not tested the channel P07 is
    /// about, and reporting it as healthy would be the asymmetry ADR-0010 R1
    /// forbids.
    #[must_use]
    pub fn both_families_probed(&self) -> bool {
        self.probes(AddressFamily::V4) > 0 && self.probes(AddressFamily::V6) > 0
    }
}

/// The wake points the canary runs at.
///
/// "At each existing network-change and keepalive wake point" — deliberately
/// *existing* ones, so the canary costs no additional radio wake (§6.6's
/// coalescing rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WakePoint {
    /// An OS network-change notification arrived.
    NetworkChange,
    /// The coalesced keepalive window fired.
    KeepaliveWake,
}

/// DN-28: "the canary keeps running in the protected scope **during** a grant",
/// so a portal window cannot become a blind spot.
#[must_use]
pub const fn runs_during_portal_grant() -> bool {
    true
}
