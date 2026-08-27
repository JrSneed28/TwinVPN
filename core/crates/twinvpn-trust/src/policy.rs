//! `PolicyBundle` verification — the Owner authors, coordination cannot.
//!
//! **Authority:** `contracts/proto/twinvpn/v1/policy.proto`,
//! `signed_statements.cddl` §10, ADR-0008 N-3, ADR-0009 §11.4 and §11.5,
//! ADR-0012 §11.10, `docs/threat-model.md` §7, state rows S-06 and S-07.
//!
//! # The two rules that make a compromised coordination service harmless
//!
//! `policy.proto`:
//!
//! > "AUTHORED by the Owner authority via an OSK holding the POLICY power. The
//! > control plane **WAREHOUSES AND DISTRIBUTES; IT CANNOT AUTHOR** — otherwise
//! > a compromised coordination service could disable every kill switch in the
//! > fleet, which would make I1 and I3 jointly worthless."
//!
//! > "A device MUST reject any bundle with `policy_version` <= its high-water
//! > mark (ADR-0008 N-3). A bundle **not verifiable against the pinned
//! > `OwnerTrustAnchor` (S-32) MUST BE REJECTED OUTRIGHT, WHATEVER ITS
//! > VERSION.**"
//!
//! [`PolicyState::offer`] applies both, in that order: the signer is checked
//! before the version, because a bundle from the wrong signer is not a
//! candidate for the version comparison at all.
//!
//! # `MONOTONIC` reads are mandatory
//!
//! The contract matrix's phrase for the failure mode is "a silent authorization
//! hole": a device that quietly enforced a stale bundle would be enforcing an
//! Owner decision the Owner has since revoked. So the high-water mark is a floor
//! with no setter, and [`PolicyState::offer`] refuses `<=` rather than `<` —
//! re-delivery of the current version is a no-op, and anything lower is a
//! rollback attempt.
//!
//! # `killswitch_floor` is a floor
//!
//! > "THERE IS NO ENCODING OF THIS FIELD, OR OF ANY OTHER FIELD IN THIS BUNDLE,
//! > THAT LOWERS ENFORCEMENT BELOW THE DEVICE'S LOCAL SETTING, AND NO RECEIVER
//! > MAY IMPLEMENT ONE."
//!
//! [`effective_killswitch`] is `max(local, policy_required)` and takes both, so
//! there is no call shape that forgets the local half.
//!
//! # Expiry
//!
//! ADR-0009 §11.4's asymmetry: "on expiry, **GRANTS carried by the bundle
//! SUSPEND and DENIALS PERSIST**, so an expired bundle can only ever become MORE
//! RESTRICTIVE. An established `Session` is **NEVER TORN DOWN** by expiry (I5)."
//! [`PolicyState::disposition`] returns that, and there is no `on_expiry`
//! parameter anywhere — "Adding one would make the fail-closed behaviour
//! remotely selectable."

use twinvpn_crypto::statements::{OskPower, PolicyBundleHeader};

use crate::error::{Result, TrustError};
use crate::owner::{AnchorChain, Operation, VerifiedSigner};

/// What a device may do with the policy it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDisposition {
    /// Within its validity window: grants and denials both in force.
    Current,
    /// Past `not_after_ms`: **grants suspend, denials persist**. The session is
    /// not torn down.
    Expired,
    /// No bundle has ever verified. Denials are in force by default — an absent
    /// rule is a denial (`TM-A3`), so this is the *most* restrictive state, not
    /// the least.
    None,
}

impl PolicyDisposition {
    /// Whether grants carried by the bundle are in force.
    #[must_use]
    pub const fn grants_in_force(self) -> bool {
        matches!(self, PolicyDisposition::Current)
    }

    /// Whether denials are in force. **Always true**, in every state.
    ///
    /// A method rather than a constant so the asymmetry is legible at a call
    /// site: a reader who sees `grants_in_force()` next to `denials_in_force()`
    /// sees that one can be false and the other cannot.
    #[must_use]
    pub const fn denials_in_force(self) -> bool {
        true
    }

    /// Whether an established `Session` is torn down. **Never** (I5).
    #[must_use]
    pub const fn requires_teardown(self) -> bool {
        false
    }
}

/// The device's policy high-water mark and current bundle.
#[derive(Debug, Clone, Default)]
pub struct PolicyState {
    high_water: u64,
    current: Option<PolicyBundleHeader>,
}

impl PolicyState {
    /// An empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The high-water `policy_version`. This is a floor and has no setter.
    #[must_use]
    pub const fn high_water(&self) -> u64 {
        self.high_water
    }

    /// The bundle currently held, if any.
    #[must_use]
    pub const fn current(&self) -> Option<&PolicyBundleHeader> {
        self.current.as_ref()
    }

    /// Offers a verified `PolicyBundle`.
    ///
    /// `signers` are the signatures already verified against the keys they name.
    /// `chain` is the pinned anchor and delegation set. A signer with no
    /// `POLICY`-powered delegation is refused **whatever the version**.
    ///
    /// Returns `true` if the bundle was installed, `false` if it was a
    /// re-delivery of the version already held.
    ///
    /// # Errors
    ///
    /// [`TrustError::NotAuthorized`] for a wrong signer,
    /// [`TrustError::TrustEpochRollback`] for `policy_version` below the
    /// high-water mark.
    pub fn offer(
        &mut self,
        chain: &AnchorChain,
        signers: &[VerifiedSigner],
        bundle: PolicyBundleHeader,
    ) -> Result<bool> {
        // The signer first. "A bundle not verifiable against the pinned
        // OwnerTrustAnchor MUST BE REJECTED OUTRIGHT, WHATEVER ITS VERSION" —
        // so a wrong-signer bundle never reaches the version comparison and can
        // never advance the high-water mark.
        chain.authorize(Operation::Ordinary(OskPower::Policy), signers, &[])?;

        if bundle.policy_version < self.high_water {
            return Err(TrustError::TrustEpochRollback {
                offered: bundle.policy_version,
                high_water: self.high_water,
            });
        }
        if bundle.policy_version == self.high_water {
            // ADR-0008 N-3 says reject `<=`. A device that has never held a
            // bundle has a high-water of zero and a real bundle is at least 1,
            // so this branch is a genuine re-delivery. It is a no-op rather
            // than an error: re-delivery happens on every reconnect, and
            // erroring would make a normal event look like an attack.
            if self.current.is_some() {
                return Ok(false);
            }
        }
        self.high_water = bundle.policy_version;
        self.current = Some(bundle);
        Ok(true)
    }

    /// The current disposition, given the wall-clock evaluation of
    /// `not_after_ms`.
    ///
    /// `expired` is the caller's verdict from
    /// [`twinvpn_env::ValidityClock::evaluate`] — this crate takes no `Env`
    /// (CD-2), and on a device whose clock is `Unset` there is no verdict, which
    /// the caller expresses as `false`. That is the correct direction:
    /// `AUTH.CLOCK_IMPLAUSIBLE` "MUST NOT BE TERMINAL and MUST NOT GATE", so a
    /// clockless router keeps its grants rather than being silently degraded.
    #[must_use]
    pub fn disposition(&self, expired: bool) -> PolicyDisposition {
        match (&self.current, expired) {
            (None, _) => PolicyDisposition::None,
            (Some(_), true) => PolicyDisposition::Expired,
            (Some(_), false) => PolicyDisposition::Current,
        }
    }
}

/// `max(local_mode, policy_required_mode)` — the floor rule, as a function.
///
/// Both arguments are required, so there is no call that forgets the local
/// setting. The ordering is the mechanism: `KillSwitchFloor` is "ordered so that
/// 'higher value = stricter' and `max()` is a plain integer comparison — the
/// ordering **is** the mechanism, not a convention."
#[must_use]
pub const fn effective_killswitch(local_mode: u64, policy_required_mode: u64) -> u64 {
    if local_mode > policy_required_mode {
        local_mode
    } else {
        policy_required_mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_crypto::statements::{OwnerDelegation, OwnerTrustAnchor};

    fn chain_with(power: OskPower) -> AnchorChain {
        let mut c = AnchorChain::new();
        c.offer_anchor(OwnerTrustAnchor {
            twinnet_id: "tn-1".to_owned(),
            anchor_version: 1,
            ork_pub_cose: b"ork".to_vec(),
            not_after_ms: 2_000_000_000_000,
        })
        .expect("pin");
        c.install_delegation(OwnerDelegation {
            twinnet_id: "tn-1".to_owned(),
            osk_id: "osk-1".to_owned(),
            osk_pub_cose: b"key".to_vec(),
            powers: vec![power],
            anchor_version: 1,
            not_after_ms: 2_000_000_000_000,
        })
        .expect("install");
        c
    }

    fn bundle(version: u64, floor: u64) -> PolicyBundleHeader {
        PolicyBundleHeader {
            twinnet_id: "tn-1".to_owned(),
            policy_version: version,
            policy_id: "policy-main".to_owned(),
            access_rules: vec![0xa0],
            dns_policy: vec![0xa0],
            route_policy: vec![0xa0],
            exit_policy: vec![0xa0],
            relay_region_policy: vec![0xa0],
            killswitch_floor: floor,
            not_after_ms: 2_000_000_000_000,
        }
    }

    #[test]
    fn a_policy_powered_signer_installs_a_bundle() {
        let c = chain_with(OskPower::Policy);
        let mut p = PolicyState::new();
        assert!(p
            .offer(&c, &[VerifiedSigner::osk("osk-1")], bundle(4, 2))
            .expect("install"));
        assert_eq!(p.high_water(), 4);
    }

    /// **Attack test — "the control plane WAREHOUSES AND DISTRIBUTES; IT CANNOT
    /// AUTHOR".** A signer without the `POLICY` power is refused whatever the
    /// version, and the high-water mark does not move.
    #[test]
    fn a_signer_without_the_policy_power_is_refused_whatever_the_version() {
        let c = chain_with(OskPower::Enroll);
        let mut p = PolicyState::new();
        let err = p
            .offer(&c, &[VerifiedSigner::osk("osk-1")], bundle(9, 2))
            .expect_err("must refuse");
        assert!(matches!(err, TrustError::NotAuthorized { .. }));
        assert_eq!(
            p.high_water(),
            0,
            "a wrong signer must not advance the floor"
        );
        assert!(p.current().is_none());
    }

    /// **Attack test.** A signature from a key with no delegation at all —
    /// which is what a compromised coordination service could produce — is
    /// refused.
    #[test]
    fn an_undelegated_signer_cannot_author_policy() {
        let c = chain_with(OskPower::Policy);
        let mut p = PolicyState::new();
        assert!(p
            .offer(&c, &[VerifiedSigner::osk("osk-attacker")], bundle(1, 2))
            .is_err());
    }

    /// **Attack test — the policy rollback.** "Replaying an older bundle is a
    /// POLICY ROLLBACK ATTACK", and it is refused.
    #[test]
    fn an_older_bundle_is_refused_as_a_rollback() {
        let c = chain_with(OskPower::Policy);
        let mut p = PolicyState::new();
        p.offer(&c, &[VerifiedSigner::osk("osk-1")], bundle(7, 2))
            .expect("install");
        let err = p
            .offer(&c, &[VerifiedSigner::osk("osk-1")], bundle(6, 1))
            .expect_err("rollback");
        assert!(matches!(err, TrustError::TrustEpochRollback { .. }));
        assert_eq!(err.reason_code().as_str(), "AUTH.TRUST_EPOCH_ROLLBACK");
        assert_eq!(p.high_water(), 7);
        assert_eq!(
            p.current().expect("held").killswitch_floor,
            2,
            "the held bundle must be untouched"
        );
    }

    /// Re-delivery of the current version is a no-op, not an error: it happens
    /// on every reconnect.
    #[test]
    fn re_delivery_of_the_current_version_is_a_no_op() {
        let c = chain_with(OskPower::Policy);
        let mut p = PolicyState::new();
        p.offer(&c, &[VerifiedSigner::osk("osk-1")], bundle(3, 1))
            .expect("install");
        assert!(!p
            .offer(&c, &[VerifiedSigner::osk("osk-1")], bundle(3, 1))
            .expect("no-op"));
    }

    /// **The floor rule.** No bundle can lower enforcement below the local
    /// setting.
    #[test]
    fn the_killswitch_floor_can_only_raise_enforcement() {
        // A policy demanding fail-closed raises a permissive local setting.
        assert_eq!(effective_killswitch(1, 2), 2);
        // A policy demanding nothing cannot lower a strict local setting.
        assert_eq!(effective_killswitch(2, 1), 2);
        assert_eq!(effective_killswitch(2, 0), 2);
        // Equal is equal.
        assert_eq!(effective_killswitch(2, 2), 2);
    }

    /// **A fully compromised coordination service can make a device MORE
    /// blocked, NEVER LESS.** Exhaustively, over every pair in the enum's range.
    #[test]
    fn no_policy_value_lowers_a_local_setting() {
        for local in 0u64..=2 {
            for required in 0u64..=2 {
                assert!(
                    effective_killswitch(local, required) >= local,
                    "policy {required} lowered local {local}"
                );
            }
        }
    }

    /// ADR-0009 §11.4's asymmetry: on expiry, grants suspend and denials
    /// persist — and nothing is torn down.
    #[test]
    fn on_expiry_grants_suspend_and_denials_persist() {
        let c = chain_with(OskPower::Policy);
        let mut p = PolicyState::new();
        p.offer(&c, &[VerifiedSigner::osk("osk-1")], bundle(1, 2))
            .expect("install");

        let current = p.disposition(false);
        assert!(current.grants_in_force());
        assert!(current.denials_in_force());

        let expired = p.disposition(true);
        assert!(!expired.grants_in_force(), "grants must suspend");
        assert!(expired.denials_in_force(), "denials must persist");
        assert!(
            !expired.requires_teardown(),
            "I5: never torn down by expiry"
        );
    }

    /// No bundle at all is the *most* restrictive state, because an absent rule
    /// is a denial.
    #[test]
    fn no_bundle_denies_rather_than_permits() {
        let p = PolicyState::new();
        let d = p.disposition(false);
        assert_eq!(d, PolicyDisposition::None);
        assert!(!d.grants_in_force());
        assert!(d.denials_in_force());
    }

    /// A device with no usable clock keeps its grants: `AUTH.CLOCK_IMPLAUSIBLE`
    /// "MUST NOT BE TERMINAL and MUST NOT GATE", and gating "would brick the
    /// device" on an unattended RTC-less router.
    #[test]
    fn a_device_with_no_clock_verdict_keeps_its_grants() {
        let c = chain_with(OskPower::Policy);
        let mut p = PolicyState::new();
        p.offer(&c, &[VerifiedSigner::osk("osk-1")], bundle(1, 1))
            .expect("install");
        // The caller has no verdict and passes `false`.
        assert!(p.disposition(false).grants_in_force());
    }
}
