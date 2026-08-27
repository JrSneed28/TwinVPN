//! The latch: KS-17's two rule sets, KS-18's entry preconditions, and KS-21's
//! disarm.
//!
//! **Authority:** ADR-0012 §11.8 (KS-17 … KS-20), §11.10 (KS-21, KS-21a),
//! §11.6's durability table; `docs/networking.md` §9.3;
//! `twinvpn_platform::Ruleset`.
//!
//! # KS-17: two rule sets, never zero
//!
//! > There are exactly two fail-closed rule sets: `RULESET_BLOCKED` and
//! > `RULESET_PROTECTED`. **Both are fail-closed.** Transitions between them are
//! > a single atomic swap. `leave_blocked()` means *swap to
//! > `RULESET_PROTECTED`*, never *remove rules*.
//!
//! `twinvpn_platform::Ruleset` has exactly two values and there is no
//! `remove_ruleset`, so "a moment with no ruleset" is unrepresentable at the
//! seam. This module never tries to express one either.

use twinvpn_platform::{EnforcementCustody, Ruleset};
use twinvpn_types::{AddressFamily, PerFamily};

/// §11's arming policy. M2 is the default; M1 and M4 are first-class settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArmingPolicy {
    /// M1 — always fail-closed, whether or not the user asked for a tunnel.
    Always,
    /// M2 — fail-closed while intended-up. **The default.**
    WhileIntendedUp,
    /// M4 — the announced opt-out. Traffic may flow untunneled, and says so.
    PermissiveAnnounced,
}

impl ArmingPolicy {
    /// Whether the latch should be up given the user's intent.
    #[must_use]
    pub const fn latch_up(self, intended_up: bool) -> bool {
        match self {
            ArmingPolicy::Always => true,
            ArmingPolicy::WhileIntendedUp => intended_up,
            ArmingPolicy::PermissiveAnnounced => false,
        }
    }
}

/// KS-18's two conditions for entering `RULESET_PROTECTED`.
///
/// > `RULESET_PROTECTED` may be entered only after **both** (a) an authenticated
/// > bidirectional path validation, and (b) a `ProtectionAssertion` confirming
/// > the intended rule set is installed **for both families**. Either check
/// > failing keeps `RULESET_BLOCKED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedPreconditions {
    /// (a) `EV_PATH_VALIDATED` — authenticated and bidirectional.
    pub path_validated: bool,
    /// (b) the assertion, per family. **Both**, or neither counts.
    pub ruleset_present: PerFamily<bool>,
}

impl ProtectedPreconditions {
    /// Whether the swap to `RULESET_PROTECTED` is permitted.
    #[must_use]
    pub fn satisfied(&self) -> bool {
        self.path_validated
            && *self.ruleset_present.get(AddressFamily::V4)
            && *self.ruleset_present.get(AddressFamily::V6)
    }

    /// Which family's rules are missing, when one is.
    #[must_use]
    pub fn missing_family(&self) -> Option<AddressFamily> {
        [AddressFamily::V4, AddressFamily::V6]
            .into_iter()
            .find(|f| !*self.ruleset_present.get(*f))
    }
}

/// The latch.
///
/// Deliberately holds no "off" state beyond the arming policy: the two rule sets
/// are both fail-closed, so `Down` means *`PermissiveAnnounced` is in force*,
/// not *no rules*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Latch {
    policy: ArmingPolicy,
    intended_up: bool,
    current: Ruleset,
    /// Whether an authenticated local disarm has been performed (KS-21).
    disarmed_by_owner: bool,
}

impl Latch {
    /// A latch under the default policy, holding `RULESET_BLOCKED`.
    ///
    /// Starting blocked is KS-19's direction: "the deny predates the first packet
    /// the host can emit".
    #[must_use]
    pub const fn new(policy: ArmingPolicy) -> Self {
        Self {
            policy,
            intended_up: false,
            current: Ruleset::Blocked,
            disarmed_by_owner: false,
        }
    }

    /// The ruleset currently desired.
    #[must_use]
    pub const fn desired(&self) -> Ruleset {
        self.current
    }

    /// Whether the latch is up, i.e. whether enforcement is fail-closed.
    #[must_use]
    pub const fn is_up(&self) -> bool {
        !self.disarmed_by_owner && self.policy.latch_up(self.intended_up)
    }

    /// Records the user's intent.
    pub fn set_intended_up(&mut self, intended: bool) {
        self.intended_up = intended;
        if !self.is_up() {
            // M4 or a disarm: the ruleset stays whatever it is. There is still no
            // "remove"; PermissiveAnnounced is a policy, not an absence.
        }
    }

    /// Swaps to `RULESET_PROTECTED`, but **only** when KS-18 is satisfied.
    ///
    /// Returns the ruleset now desired. A refused swap leaves `Blocked`, which is
    /// the whole point: "Either check failing keeps `RULESET_BLOCKED`."
    pub fn leave_blocked(&mut self, pre: ProtectedPreconditions) -> Ruleset {
        if pre.satisfied() {
            self.current = Ruleset::Protected;
        }
        self.current
    }

    /// Swaps back to `RULESET_BLOCKED`. Always permitted — tightening never
    /// needs a precondition.
    pub fn enter_blocked(&mut self) -> Ruleset {
        self.current = Ruleset::Blocked;
        self.current
    }

    /// KS-21: disarming requires a **local interactive action**, and KS-21a's
    /// host-class rule admits an administrator on the local management socket
    /// where no interactive session exists.
    ///
    /// Returns `false` — and changes nothing — when the authority is not local.
    /// "No network path, no remote management channel, and no control-plane
    /// document may initiate it."
    pub fn disarm(&mut self, authority: DisarmAuthority) -> bool {
        match authority {
            DisarmAuthority::LocalInteractive | DisarmAuthority::LocalAdminOnManagementSocket => {
                self.disarmed_by_owner = true;
                true
            }
            DisarmAuthority::Remote | DisarmAuthority::ControlPlaneDocument => false,
        }
    }

    /// Re-arms after a disarm.
    pub fn rearm(&mut self) {
        self.disarmed_by_owner = false;
    }

    /// Whether the owner has deliberately disengaged enforcement.
    #[must_use]
    pub const fn disarmed_by_owner(&self) -> bool {
        self.disarmed_by_owner
    }
}

/// Who is asking to disarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisarmAuthority {
    /// A local interactive action on the device itself.
    LocalInteractive,
    /// KS-21a: an administrator authenticated by kernel-supplied peer
    /// credentials on the local management socket, **only** where no interactive
    /// session exists (`HC-3`).
    ///
    /// Admissible because "a control plane **cannot produce an authenticated
    /// local shell**", and necessary because KS-20 says blocked must not mean
    /// bricked.
    LocalAdminOnManagementSocket,
    /// Anything arriving over a network path. Always refused — and always a
    /// security event.
    Remote,
    /// A control-plane document. Always refused. S-18: the control plane cannot
    /// disengage the kill switch.
    ControlPlaneDocument,
}

impl DisarmAuthority {
    /// Whether a refusal of this authority is a security event to report.
    #[must_use]
    pub const fn refusal_is_security_event(self) -> bool {
        matches!(
            self,
            DisarmAuthority::Remote | DisarmAuthority::ControlPlaneDocument
        )
    }
}

/// What §11.6's durability table guarantees on this target, as the adapter
/// declares it.
///
/// CB-6's third clause — "the OS holds it" — "is a property of the
/// *installation*, not of any type here, so it is stated as a declared per-target
/// fact rather than assumed."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurabilityPosture {
    /// What the adapter declares.
    pub custody: EnforcementCustody,
    /// Whether an OS-applied boot artifact covers KS-19's window.
    pub boot_enforcement_available: bool,
}

impl DurabilityPosture {
    /// Whether C-7 and S-18 hold on this target: a core crash cannot drop
    /// protection.
    #[must_use]
    pub const fn survives_core_exit(self) -> bool {
        self.custody.survives_core_exit
    }

    /// Whether KS-17's atomic swap is atomic here. `false` means there is a
    /// window with no rules, "which is KS-17's forbidden state — reported so it
    /// can be a known residual rather than an invisible one".
    #[must_use]
    pub const fn swap_is_atomic(self) -> bool {
        self.custody.swap_is_atomic
    }

    /// Whether the posture must be disclosed rather than silently accepted.
    #[must_use]
    pub const fn requires_disclosure(self) -> bool {
        !self.survives_core_exit() || !self.swap_is_atomic() || !self.boot_enforcement_available
    }
}
