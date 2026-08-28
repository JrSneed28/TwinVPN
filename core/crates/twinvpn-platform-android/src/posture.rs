//! The **three-valued** always-on/lockdown posture, and the enforcement
//! read-back that `installed_ruleset` answers from.
//!
//! **Authority:** `docs/networking.md` §5.4's Android always-on row;
//! ADR-0022 **LC-40**; ADR-0012 §11.6's Android rows (mechanism, durability and
//! limitation tables) and **KS-17**; ADR-0015 **O-17** and **O-18**;
//! `docs/implementation/ownership.md` §8 **W-24**.
//!
//! # The rule, and the probe that must not be built
//!
//! `docs/networking.md` §5.4, correcting itself in terms:
//!
//! > **Corrected: "the app detects whether it is enabled" cannot be built.** For
//! > a non-DPC app on Android 10+ there is no API exposing lockdown state, and
//! > the obvious in-app probe is **invalid by construction** — under lockdown
//! > *our own* sockets are the permitted ones, so a successful reachability test
//! > proves nothing.
//!
//! So there is no probe in this module and there is no place to put one: the
//! only constructor of a [`LockdownPosture`] takes a *report*, never a
//! measurement. [`LockdownPosture::Unverified`] is the default and
//! [`LockdownPosture::presents_as_protected`] is `false` for it — LC-40's
//! fail-closed direction, and O-18's "`UNKNOWN`, never green".
//!
//! # What `installed_ruleset` can honestly read back, on a platform with no
//! firewall
//!
//! ADR-0012 §11.6 lists **no firewall object** for Android. The enforcement
//! point *is* the `VpnService.Builder` route claim, and the two ADR-0012
//! postures are expressed as:
//!
//! | Posture | The claim | What the datapath does |
//! |---|---|---|
//! | `BLOCKED` | `0.0.0.0/0` **and** `::/0`, established | reads the tun and forwards nothing |
//! | `PROTECTED` | **identical** | reads the tun and forwards through the session |
//!
//! **The claim does not change between them, and that is the design.** KS-17
//! requires the transition to be an atomic swap with rules never absent; on
//! Android the only way to change a claim is `Builder.establish()` again, which
//! tears the interface down and rebuilds it — a window in which *nothing* is
//! claimed and every packet egresses. Holding the claim constant and swapping a
//! disposition flag makes the swap a single atomic store and makes the forbidden
//! state unreachable. [`EnforcementView::swap_is_atomic`] is `true` for that
//! reason, and it is a reason rather than an assertion.
//!
//! ## W-24, on Android, stated precisely
//!
//! ADR-0015 §11.6 rule 1 requires the `ProtectionAssertion` to be produced by
//! **querying the enforcement layer**, "never of the agent's belief". Half of
//! the Android answer is a genuine query and half is not:
//!
//! | Half | Read from | Is it the agent's belief? |
//! |---|---|---|
//! | is the claim in force | the tun descriptor's validity — the OS closes it on `onRevoke`, on always-on takeover, and on process death | **no**, it is the OS's answer |
//! | which disposition is in force | this process's own atomic | **yes** |
//!
//! There is no Android API that returns the second half, because there is no
//! object outside our process that holds it. So the read-back is honest about
//! its own shape: [`EnforcementView::from_claim`] takes the OS-observed fd
//! validity as a parameter and refuses to answer `Some(_)` without it. A dead
//! descriptor yields `None` — *rules genuinely absent* — which is the true and
//! the fail-safe answer, and the same direction `twinvpn-ffi` chose for W-24.
//!
//! **This does not discharge W-24.** It is reported again, in this domain's
//! words, in the completion report.

use twinvpn_platform::{EnforcementCustody, Ruleset};
use twinvpn_types::PerFamily;

/// What this device can truthfully say about always-on VPN with "Block
/// connections without VPN".
///
/// Three values, not a boolean. ADR-0022 LC-40 and `docs/networking.md` §5.4
/// both require exactly this, and ADR-0012 §11.6's limitation table "consumes
/// this three-valued posture, not a boolean".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum LockdownPosture {
    /// A DPC or a managed configuration reports lockdown is in force.
    ///
    /// The only value that may present as protected, and the only one that can
    /// be *reported* rather than guessed.
    Confirmed,
    /// Positively determined to be absent — a managed configuration that says so.
    Absent,
    /// Not observable. **The default, and it presents as unprotected.**
    #[default]
    Unverified,
}

impl LockdownPosture {
    /// Whether this posture may be presented to the user as protected-by-lockdown.
    ///
    /// LC-40: `LOCKDOWN_UNVERIFIED` **MUST** be presented as *not protected by
    /// lockdown*. `Absent` is likewise false, for the obvious reason. Only
    /// `Confirmed` is true, and only a report can produce `Confirmed`.
    #[must_use]
    pub const fn presents_as_protected(self) -> bool {
        matches!(self, LockdownPosture::Confirmed)
    }

    /// A stable, non-localised tag for the diagnostic bundle and for S-46.
    ///
    /// Not a sentence: CB-4 keeps every rendered string out of the core, and the
    /// shell renders `LOCKDOWN_UNVERIFIED` into whatever the user should read.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            LockdownPosture::Confirmed => "LOCKDOWN_CONFIRMED",
            LockdownPosture::Absent => "LOCKDOWN_ABSENT",
            LockdownPosture::Unverified => "LOCKDOWN_UNVERIFIED",
        }
    }

    /// The posture implied by a managed-configuration report.
    ///
    /// `None` — no DPC, no managed configuration, or a managed configuration
    /// that does not carry the key — is [`LockdownPosture::Unverified`], never
    /// `Absent`. The distinction is the whole rule: "nobody told us" and "we were
    /// told it is off" are different facts, and collapsing them would let a
    /// device with no management present as positively determined.
    #[must_use]
    pub const fn from_managed_report(reported: Option<bool>) -> Self {
        match reported {
            Some(true) => LockdownPosture::Confirmed,
            Some(false) => LockdownPosture::Absent,
            None => LockdownPosture::Unverified,
        }
    }
}

/// What the adapter can read back about enforcement, and where each half came
/// from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnforcementView {
    /// Whether the OS still holds our route claim.
    ///
    /// Observed from the tun descriptor, which the OS invalidates on `onRevoke`,
    /// on another app taking the VPN slot, and on process death.
    pub claim_in_force: bool,
    /// Which families the claim covers, as the rendered programme declared.
    pub claims_default: PerFamily<bool>,
    /// The disposition this process is applying to packets it reads.
    pub disposition: Ruleset,
    /// The always-on posture, three-valued.
    pub lockdown: LockdownPosture,
}

impl EnforcementView {
    /// Builds a view from the OS-observed claim and this process's disposition.
    #[must_use]
    pub const fn from_claim(
        claim_in_force: bool,
        claims_default: PerFamily<bool>,
        disposition: Ruleset,
        lockdown: LockdownPosture,
    ) -> Self {
        Self {
            claim_in_force,
            claims_default,
            disposition,
            lockdown,
        }
    }

    /// The answer to [`twinvpn_platform::NetworkConfig::installed_ruleset`].
    ///
    /// `None` means **rules genuinely absent**, and it is returned in exactly
    /// two situations, both of which are true absences rather than ignorance:
    ///
    /// 1. the descriptor is dead — `onRevoke`, another app took the slot, or the
    ///    interface was never established;
    /// 2. the claim covers one family and not the other, which on Android is not
    ///    a partial ruleset but an *absent* one for the unclaimed family, and
    ///    ADR-0010 R1 refuses to let the v4 half be reported as protection.
    ///
    /// `Ok(None)` reads as "no ruleset installed", and here that is the truth
    /// rather than the dangerous direction W-24 warns about — because on Android
    /// a dead claim really does mean traffic is egressing untunneled.
    #[must_use]
    pub const fn installed_ruleset(&self) -> Option<Ruleset> {
        if !self.claim_in_force {
            return None;
        }
        if !(self.claims_default.v4 && self.claims_default.v6) {
            // A one-family claim is reported as no ruleset rather than as the
            // ruleset we intended: ADR-0010 R1 forbids a v4 story with a weaker
            // v6 one, and reporting `Protected` here would be exactly that.
            //
            // A split-tunnel contract claims neither default and is likewise
            // reported as absent, which is correct: a claim that covers only
            // some prefixes is not the kill switch.
            return None;
        }
        Some(self.disposition)
    }

    /// The declared custody facts for this view (CB-6, CB-6a's shape).
    ///
    /// `survives_core_exit` is **dynamic on Android and honestly so**: the tun
    /// descriptor dies with the process, so a core crash drops the claim and
    /// everything egresses — *unless* the OS is holding always-on lockdown, in
    /// which case the platform blocks non-VPN traffic itself and the guarantee
    /// is real. Since the posture is not reliably observable, the default answer
    /// is `false`, and only a `Confirmed` report changes it.
    ///
    /// ADR-0012 §11.6's Android limitation row says the residual plainly:
    /// *"Everything, until the user enables lockdown."* This method is that
    /// sentence made machine-readable, so the core records it in the diagnostic
    /// bundle rather than inferring the CB-6 guarantee it does not have.
    #[must_use]
    pub const fn custody(&self) -> EnforcementCustody {
        EnforcementCustody {
            survives_core_exit: self.lockdown.presents_as_protected(),
            // See the module documentation: the claim is held constant across
            // the BLOCKED/PROTECTED swap precisely so the swap is a single
            // atomic store and KS-17's forbidden "rules absent" state is
            // unreachable. Re-establishing to swap would make this false.
            swap_is_atomic: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOTH: PerFamily<bool> = PerFamily::new(true, true);
    const V4_ONLY: PerFamily<bool> = PerFamily::new(true, false);

    #[test]
    fn unverified_is_the_default_and_presents_as_unprotected() {
        assert_eq!(LockdownPosture::default(), LockdownPosture::Unverified);
        assert!(!LockdownPosture::default().presents_as_protected());
        assert!(!LockdownPosture::Absent.presents_as_protected());
        assert!(LockdownPosture::Confirmed.presents_as_protected());
    }

    #[test]
    fn nobody_told_us_is_not_the_same_fact_as_we_were_told_it_is_off() {
        assert_eq!(
            LockdownPosture::from_managed_report(None),
            LockdownPosture::Unverified
        );
        assert_eq!(
            LockdownPosture::from_managed_report(Some(false)),
            LockdownPosture::Absent
        );
        assert_eq!(
            LockdownPosture::from_managed_report(Some(true)),
            LockdownPosture::Confirmed
        );
    }

    /// The tags are what a bundle carries; they are pinned so a rename is a
    /// deliberate act rather than a refactor.
    #[test]
    fn the_three_tags_are_the_ones_lc40_and_networking_md_name() {
        assert_eq!(LockdownPosture::Confirmed.tag(), "LOCKDOWN_CONFIRMED");
        assert_eq!(LockdownPosture::Absent.tag(), "LOCKDOWN_ABSENT");
        assert_eq!(LockdownPosture::Unverified.tag(), "LOCKDOWN_UNVERIFIED");
    }

    #[test]
    fn a_dead_descriptor_reports_no_ruleset_because_that_is_the_truth() {
        let view = EnforcementView::from_claim(
            false,
            BOTH,
            Ruleset::Protected,
            LockdownPosture::Unverified,
        );
        assert_eq!(view.installed_ruleset(), None);
    }

    #[test]
    fn a_live_claim_reports_the_disposition_this_process_is_applying() {
        for disposition in [Ruleset::Blocked, Ruleset::Protected] {
            let view =
                EnforcementView::from_claim(true, BOTH, disposition, LockdownPosture::Unverified);
            assert_eq!(view.installed_ruleset(), Some(disposition));
        }
    }

    /// ADR-0010 R1 at the read-back: a v4-only claim is not "protected with a
    /// v6 caveat", it is not protected.
    #[test]
    fn a_one_family_claim_is_never_reported_as_protection() {
        let view = EnforcementView::from_claim(
            true,
            V4_ONLY,
            Ruleset::Protected,
            LockdownPosture::Confirmed,
        );
        assert_eq!(view.installed_ruleset(), None);
    }

    /// ADR-0012 §11.6's Android limitation row, machine-readable.
    #[test]
    fn enforcement_survives_core_exit_only_where_lockdown_is_confirmed() {
        let unverified = EnforcementView::from_claim(
            true,
            BOTH,
            Ruleset::Protected,
            LockdownPosture::Unverified,
        );
        assert!(
            !unverified.custody().survives_core_exit,
            "the tun descriptor dies with the process; only OS lockdown outlives it"
        );

        let absent =
            EnforcementView::from_claim(true, BOTH, Ruleset::Protected, LockdownPosture::Absent);
        assert!(!absent.custody().survives_core_exit);

        let confirmed =
            EnforcementView::from_claim(true, BOTH, Ruleset::Protected, LockdownPosture::Confirmed);
        assert!(confirmed.custody().survives_core_exit);
    }

    /// KS-17: the swap is atomic because the claim is held constant across it.
    #[test]
    fn the_ruleset_swap_is_atomic_in_every_posture() {
        for lockdown in [
            LockdownPosture::Confirmed,
            LockdownPosture::Absent,
            LockdownPosture::Unverified,
        ] {
            let view = EnforcementView::from_claim(true, BOTH, Ruleset::Blocked, lockdown);
            assert!(view.custody().swap_is_atomic);
        }
    }

    /// The property that makes the swap safe, stated as a test: moving between
    /// the two postures changes nothing the OS holds.
    #[test]
    fn moving_between_blocked_and_protected_does_not_change_the_claim() {
        let blocked =
            EnforcementView::from_claim(true, BOTH, Ruleset::Blocked, LockdownPosture::Unverified);
        let protected = EnforcementView {
            disposition: Ruleset::Protected,
            ..blocked
        };
        assert_eq!(blocked.claims_default, protected.claims_default);
        assert_eq!(blocked.claim_in_force, protected.claim_in_force);
        assert_ne!(blocked.installed_ruleset(), protected.installed_ruleset());
    }
}
