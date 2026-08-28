//! The Owner root of trust: anchors, delegations, epochs, and the N-11 quorum.
//!
//! **Authority:** ADR-0007 N-9..N-14, N-26; `docs/architecture.md` §2.22;
//! `signed_statements.cddl` §8 and §9; state row S-32.
//!
//! # Verification only
//!
//! ORK and OSK private material never reaches the core (CB-5 row 1). This module
//! **verifies** anchors and delegations and answers "is this signer authorized
//! for this power"; minting an OSK or publishing an anchor is a secure-element
//! ceremony performed elsewhere. There is no signing function here.
//!
//! # S-32, the fork detector
//!
//! > "higher `anchor_version` with a valid signature wins; **EQUAL VERSION WITH
//! > DIFFERENT CONTENT is `AUTH.TRUST_HISTORY_FORKED`** — the classic fork
//! > detector, and the reason `anchor_version` is not merely monotone but
//! > content-determining."
//!
//! [`AnchorChain::offer_anchor`] implements exactly that, and the equal-version
//! case is a separate branch rather than a `>=` comparison, because a `>=` is
//! how the fork case comes to be silently accepted.
//!
//! # N-11's quorum
//!
//! > "High-power operations (mint an OSK, revoke an `ENROLL`/`DELEGATE` device,
//! > publish an anchor) MUST carry either one ORK signature or
//! > `k = min(2, n_osk)` independent OSK signatures, **excluding any OSK
//! > belonging to the target**. Ordinary operations require one OSK signature
//! > bearing the matching power."
//!
//! The exclusion is the part that is easy to lose: without it, a compromised OSK
//! could sign its own retention.

use std::collections::BTreeMap;

use twinvpn_crypto::statements::{OskPower, OwnerDelegation, OwnerTrustAnchor};
use twinvpn_crypto::{sha256, PublicVerifyingKey, StatementKind};

use crate::error::{Result, TrustError};

/// Which operations N-11 classifies as high-power.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Mint an OSK.
    MintOsk,
    /// Revoke a device that itself holds `ENROLL` or `DELEGATE`.
    RevokePrivilegedDevice,
    /// Publish an `OwnerTrustAnchor`.
    PublishAnchor,
    /// Anything else: one OSK signature bearing the matching power.
    Ordinary(OskPower),
}

impl Operation {
    /// Whether N-11's quorum applies.
    #[must_use]
    pub const fn is_high_power(self) -> bool {
        matches!(
            self,
            Operation::MintOsk | Operation::RevokePrivilegedDevice | Operation::PublishAnchor
        )
    }

    /// The power an ordinary operation requires.
    #[must_use]
    pub const fn required_power(self) -> OskPower {
        match self {
            Operation::MintOsk | Operation::PublishAnchor => OskPower::Delegate,
            Operation::RevokePrivilegedDevice => OskPower::Revoke,
            Operation::Ordinary(p) => p,
        }
    }

    /// A stable name for the refusal's evidence.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Operation::MintOsk => "MINT_OSK",
            Operation::RevokePrivilegedDevice => "REVOKE_PRIVILEGED",
            Operation::PublishAnchor => "PUBLISH_ANCHOR",
            Operation::Ordinary(OskPower::Enroll) => "ENROLL",
            Operation::Ordinary(OskPower::Revoke) => "REVOKE",
            Operation::Ordinary(OskPower::Policy) => "POLICY",
            Operation::Ordinary(OskPower::Delegate) => "DELEGATE",
            Operation::Ordinary(OskPower::Administer) => "ADMINISTER",
        }
    }
}

/// One signature that has already been verified against a named key.
///
/// Constructed by the caller *after* [`twinvpn_crypto::verify_cose_sign1`]
/// succeeds. There is no constructor that takes an unverified signature, so a
/// quorum cannot be met with signatures nobody checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSigner {
    /// Which key signed, as its `osk_id`, or `None` for the ORK.
    pub osk_id: Option<String>,
}

impl VerifiedSigner {
    /// A verified ORK signature.
    #[must_use]
    pub const fn ork() -> Self {
        Self { osk_id: None }
    }

    /// A verified OSK signature.
    #[must_use]
    pub fn osk(osk_id: &str) -> Self {
        Self {
            osk_id: Some(osk_id.to_owned()),
        }
    }

    /// Whether this is the root key.
    #[must_use]
    pub const fn is_ork(&self) -> bool {
        self.osk_id.is_none()
    }
}

/// The pinned Owner root of trust and its delegation set.
#[derive(Debug, Clone, Default)]
pub struct AnchorChain {
    anchor: Option<OwnerTrustAnchor>,
    /// Digest of the anchor's content at its version, for S-32's fork check.
    anchor_content_digest: Option<[u8; 32]>,
    delegations: BTreeMap<String, OwnerDelegation>,
}

impl AnchorChain {
    /// An unpinned chain, before enrolment.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The pinned anchor, if one has been accepted.
    #[must_use]
    pub const fn anchor(&self) -> Option<&OwnerTrustAnchor> {
        self.anchor.as_ref()
    }

    /// The pinned `anchor_version`. Zero when unpinned.
    #[must_use]
    pub fn anchor_version(&self) -> u64 {
        self.anchor.as_ref().map_or(0, |a| a.anchor_version)
    }

    /// A digest over the current delegation set, for the ADR-0001 §7.3.1
    /// prologue's `delegation_set_digest`.
    ///
    /// Deterministic: the map is a `BTreeMap` and each entry is length-prefixed,
    /// so two devices holding the same delegations compute the same digest —
    /// which is what makes a prologue mismatch mean "our delegation sets differ"
    /// rather than "we serialized differently".
    #[must_use]
    pub fn delegation_set_digest(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"TwinVPN/owner/delegations/v1");
        for (id, d) in &self.delegations {
            buf.extend_from_slice(&u32::try_from(id.len()).unwrap_or(u32::MAX).to_be_bytes());
            buf.extend_from_slice(id.as_bytes());
            buf.extend_from_slice(
                &u32::try_from(d.osk_pub_cose.len())
                    .unwrap_or(u32::MAX)
                    .to_be_bytes(),
            );
            buf.extend_from_slice(&d.osk_pub_cose);
            for p in &d.powers {
                buf.push(power_byte(*p));
            }
            buf.push(0xff);
        }
        sha256(&buf)
    }

    /// Offers an `OwnerTrustAnchor`, already verified under the ORK it names.
    ///
    /// S-32's three cases:
    ///
    /// - **higher version** → accepted, and it replaces the pinned one;
    /// - **equal version, identical content** → accepted as a no-op;
    /// - **equal version, different content** → `AUTH.TRUST_HISTORY_FORKED`;
    /// - **lower version** → `AUTH.TRUST_EPOCH_ROLLBACK`, refused not applied
    ///   (N-26).
    ///
    /// # Errors
    ///
    /// [`TrustError::TrustHistoryForked`] or [`TrustError::TrustEpochRollback`].
    pub fn offer_anchor(&mut self, offered: OwnerTrustAnchor) -> Result<bool> {
        let digest = anchor_content_digest(&offered);
        match (&self.anchor, self.anchor_content_digest) {
            (None, _) => {
                self.anchor = Some(offered);
                self.anchor_content_digest = Some(digest);
                Ok(true)
            }
            (Some(held), Some(held_digest)) => {
                if offered.anchor_version > held.anchor_version {
                    // R-8 / ADR-0007 §7.5. The root moved, so every delegation
                    // the OLD root made goes with it.
                    //
                    // This used to replace the anchor and touch nothing else,
                    // which made phrase-compromise recovery fail at the step it
                    // exists for: an attacker who obtained an OSK delegated
                    // under the old anchor still authorised after the Owner
                    // rotated the root, because the delegation set was never
                    // consulted about the rotation. `install_delegation` already
                    // refuses a delegation bound BELOW the pinned version and
                    // says why in its own doc comment — this is the other half
                    // of that same invariant, applied when the pin moves
                    // instead of when a delegation arrives.
                    //
                    // A delegation bound at or above the NEW version survives:
                    // the Owner issued it under the root now in force.
                    self.retire_delegations_below(offered.anchor_version);
                    self.anchor = Some(offered);
                    self.anchor_content_digest = Some(digest);
                    Ok(true)
                } else if offered.anchor_version < held.anchor_version {
                    Err(TrustError::TrustEpochRollback {
                        offered: offered.anchor_version,
                        high_water: held.anchor_version,
                    })
                } else if digest == held_digest {
                    // Equal version, identical content: a re-delivery, which
                    // happens on every reconnect.
                    Ok(false)
                } else {
                    // Equal version, different content. This is the fork
                    // detector, and it is a distinct branch rather than a `>=`
                    // for exactly that reason.
                    Err(TrustError::TrustHistoryForked {
                        epoch: offered.anchor_version,
                    })
                }
            }
            (Some(_), None) => Err(TrustError::Invariant {
                invariant: "a pinned anchor always carries its content digest",
            }),
        }
    }

    /// Installs a delegation that has already been verified under the ORK or
    /// under a `DELEGATE`-powered OSK.
    ///
    /// A delegation bound to an anchor version below the pinned one is refused:
    /// a delegation issued under a superseded anchor is not automatically
    /// carried forward, or an Owner who rotated the root would find the old
    /// root's delegations still live.
    ///
    /// # Errors
    ///
    /// [`TrustError::TrustEpochRollback`] for a stale `anchor_version`.
    pub fn install_delegation(&mut self, d: OwnerDelegation) -> Result<()> {
        let pinned = self.anchor_version();
        if d.anchor_version < pinned {
            return Err(TrustError::TrustEpochRollback {
                offered: d.anchor_version,
                high_water: pinned,
            });
        }
        self.delegations.insert(d.osk_id.clone(), d);
        Ok(())
    }

    /// Removes a delegation, as a revocation of that OSK requires.
    pub fn remove_delegation(&mut self, osk_id: &str) {
        self.delegations.remove(osk_id);
    }

    /// Drops every delegation bound to an anchor below `pinned` (R-8).
    ///
    /// Called by [`AnchorChain::offer_anchor`] when the root advances. Written
    /// as a collect-then-remove rather than `BTreeMap::retain` so each removal
    /// goes through [`AnchorChain::remove_delegation`] — one place where a
    /// delegation leaves this set, whatever the reason.
    fn retire_delegations_below(&mut self, pinned: u64) {
        let superseded: Vec<String> = self
            .delegations
            .iter()
            .filter(|(_, d)| d.anchor_version < pinned)
            .map(|(id, _)| id.clone())
            .collect();
        for osk_id in superseded {
            self.remove_delegation(&osk_id);
        }
    }

    /// How many OSKs are currently delegated. N-13's warning input.
    #[must_use]
    pub fn osk_count(&self) -> usize {
        self.delegations.len()
    }

    /// The delegation for one `osk_id`.
    #[must_use]
    pub fn delegation(&self, osk_id: &str) -> Option<&OwnerDelegation> {
        self.delegations.get(osk_id)
    }

    /// The public key of a delegated OSK, for verification.
    ///
    /// # Errors
    ///
    /// [`TrustError::NotAuthorized`] if no such delegation exists, and
    /// [`TrustError::Crypto`] if its key does not parse.
    pub fn osk_key(&self, osk_id: &str) -> Result<PublicVerifyingKey> {
        let d = self
            .delegations
            .get(osk_id)
            .ok_or(TrustError::NotAuthorized {
                power: "UNKNOWN_OSK",
            })?;
        Ok(PublicVerifyingKey::from_cose_key(
            &d.osk_pub_cose,
            StatementKind::OwnerDelegation,
        )?)
    }

    /// The `OwnerRootKey`'s public half, for verifying an anchor or a
    /// high-power operation.
    ///
    /// # Errors
    ///
    /// [`TrustError::NotAuthorized`] if no anchor is pinned.
    pub fn ork_key(&self) -> Result<PublicVerifyingKey> {
        let a = self
            .anchor
            .as_ref()
            .ok_or(TrustError::NotAuthorized { power: "NO_ANCHOR" })?;
        Ok(PublicVerifyingKey::from_cose_key(
            &a.ork_pub_cose,
            StatementKind::OwnerTrustAnchor,
        )?)
    }

    /// N-11's authorization check.
    ///
    /// `signers` are signatures **already verified** against the keys they
    /// name — [`VerifiedSigner`] has no constructor that accepts an unchecked
    /// one. `target_osk_ids` are OSKs belonging to the *target* of the
    /// operation, which N-11 excludes from the quorum.
    ///
    /// # Errors
    ///
    /// [`TrustError::NotAuthorized`] naming the operation.
    pub fn authorize(
        &self,
        op: Operation,
        signers: &[VerifiedSigner],
        target_osk_ids: &[String],
    ) -> Result<()> {
        let refuse = TrustError::NotAuthorized { power: op.name() };

        // One ORK signature satisfies anything.
        if signers.iter().any(VerifiedSigner::is_ork) {
            return Ok(());
        }

        // Every OSK signature must come from a delegation that exists, carries
        // the required power, and is **not** the target's.
        let required = op.required_power();
        let mut qualified: Vec<&String> = Vec::new();
        for s in signers {
            let Some(id) = &s.osk_id else { continue };
            if target_osk_ids.contains(id) {
                // N-11's exclusion. Without it a compromised OSK signs its own
                // retention, or a device revokes the OSK that would revoke it.
                continue;
            }
            let Some(d) = self.delegations.get(id) else {
                continue;
            };
            if !d.has(required) {
                continue;
            }
            if !qualified.contains(&id) {
                qualified.push(id);
            }
        }

        if op.is_high_power() {
            // k = min(2, n_osk), over the delegations that could have signed —
            // which excludes the target's, or a TwinNet with two OSKs both
            // belonging to the target would have k = 2 and no eligible signer.
            let eligible = self
                .delegations
                .keys()
                .filter(|id| !target_osk_ids.contains(id))
                .count();
            let k = core::cmp::min(2, eligible);
            if k == 0 || qualified.len() < k {
                return Err(refuse);
            }
        } else if qualified.is_empty() {
            return Err(refuse);
        }
        Ok(())
    }
}

const fn power_byte(p: OskPower) -> u8 {
    match p {
        OskPower::Enroll => 1,
        OskPower::Revoke => 2,
        OskPower::Policy => 3,
        OskPower::Delegate => 4,
        OskPower::Administer => 5,
    }
}

/// The content digest S-32 compares at equal `anchor_version`.
///
/// Covers everything except the version itself: the version is the *label*, and
/// the question S-32 asks is whether two records carrying one label say the same
/// thing.
fn anchor_content_digest(a: &OwnerTrustAnchor) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"TwinVPN/owner/anchor-content/v1");
    buf.extend_from_slice(
        &u32::try_from(a.twinnet_id.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    buf.extend_from_slice(a.twinnet_id.as_bytes());
    buf.extend_from_slice(
        &u32::try_from(a.ork_pub_cose.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    buf.extend_from_slice(&a.ork_pub_cose);
    buf.extend_from_slice(&a.not_after_ms.to_be_bytes());
    sha256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(version: u64, ork: &[u8]) -> OwnerTrustAnchor {
        OwnerTrustAnchor {
            twinnet_id: "tn-1".to_owned(),
            anchor_version: version,
            ork_pub_cose: ork.to_vec(),
            not_after_ms: 2_000_000_000_000,
        }
    }

    fn delegation(id: &str, powers: Vec<OskPower>, anchor_version: u64) -> OwnerDelegation {
        OwnerDelegation {
            twinnet_id: "tn-1".to_owned(),
            osk_id: id.to_owned(),
            osk_pub_cose: format!("key-{id}").into_bytes(),
            powers,
            anchor_version,
            not_after_ms: 2_000_000_000_000,
        }
    }

    #[test]
    fn a_higher_anchor_version_replaces_the_pinned_one() {
        let mut c = AnchorChain::new();
        assert!(c.offer_anchor(anchor(1, b"ork-a")).expect("pin"));
        assert!(c.offer_anchor(anchor(2, b"ork-b")).expect("advance"));
        assert_eq!(c.anchor_version(), 2);
    }

    /// **Attack test — S-32's fork detector.** Two different anchors at one
    /// version is the classic split-brain, and it must be refused rather than
    /// resolved by arrival order.
    #[test]
    fn equal_version_with_different_content_is_a_fork() {
        let mut c = AnchorChain::new();
        c.offer_anchor(anchor(3, b"ork-a")).expect("pin");
        let err = c
            .offer_anchor(anchor(3, b"ork-b"))
            .expect_err("must detect a fork");
        assert!(matches!(err, TrustError::TrustHistoryForked { epoch: 3 }));
        assert_eq!(err.reason_code().as_str(), "AUTH.TRUST_HISTORY_FORKED");
        // The pinned anchor is unchanged: a fork must not install either side.
        assert_eq!(c.anchor().expect("pinned").ork_pub_cose, b"ork-a");
    }

    /// A re-delivery of the same anchor is a no-op, not a fork — this happens on
    /// every reconnect.
    #[test]
    fn equal_version_with_identical_content_is_a_no_op() {
        let mut c = AnchorChain::new();
        c.offer_anchor(anchor(3, b"ork-a")).expect("pin");
        assert!(!c.offer_anchor(anchor(3, b"ork-a")).expect("no-op"));
    }

    /// **Attack test — N-26.** A lower `anchor_version` is refused, not applied.
    #[test]
    fn a_lower_anchor_version_is_refused() {
        let mut c = AnchorChain::new();
        c.offer_anchor(anchor(5, b"ork-a")).expect("pin");
        let err = c.offer_anchor(anchor(4, b"ork-a")).expect_err("rollback");
        assert!(matches!(err, TrustError::TrustEpochRollback { .. }));
        assert_eq!(c.anchor_version(), 5);
    }

    /// **Attack test.** A delegation issued under a superseded anchor must not
    /// survive a root rotation, or rotating the root would achieve nothing.
    #[test]
    fn a_delegation_bound_to_a_stale_anchor_is_refused() {
        let mut c = AnchorChain::new();
        c.offer_anchor(anchor(4, b"ork")).expect("pin");
        assert!(c
            .install_delegation(delegation("osk-1", vec![OskPower::Enroll], 3))
            .is_err());
        assert!(c
            .install_delegation(delegation("osk-1", vec![OskPower::Enroll], 4))
            .is_ok());
    }

    /// An ordinary operation needs one OSK signature bearing the matching power.
    #[test]
    fn an_ordinary_operation_needs_one_matching_power() {
        let mut c = AnchorChain::new();
        c.offer_anchor(anchor(1, b"ork")).expect("pin");
        c.install_delegation(delegation("osk-1", vec![OskPower::Enroll], 1))
            .expect("install");
        assert!(c
            .authorize(
                Operation::Ordinary(OskPower::Enroll),
                &[VerifiedSigner::osk("osk-1")],
                &[]
            )
            .is_ok());
        // The same signer without the power is refused.
        assert!(c
            .authorize(
                Operation::Ordinary(OskPower::Policy),
                &[VerifiedSigner::osk("osk-1")],
                &[]
            )
            .is_err());
    }

    /// **Attack test.** A signature from a key with no delegation authorizes
    /// nothing, however well-formed it is.
    #[test]
    fn a_signature_from_an_undelegated_key_authorizes_nothing() {
        let mut c = AnchorChain::new();
        c.offer_anchor(anchor(1, b"ork")).expect("pin");
        assert!(c
            .authorize(
                Operation::Ordinary(OskPower::Enroll),
                &[VerifiedSigner::osk("osk-unknown")],
                &[]
            )
            .is_err());
    }

    /// N-11: one ORK signature satisfies a high-power operation on its own.
    #[test]
    fn one_ork_signature_satisfies_a_high_power_operation() {
        let mut c = AnchorChain::new();
        c.offer_anchor(anchor(1, b"ork")).expect("pin");
        assert!(c
            .authorize(Operation::PublishAnchor, &[VerifiedSigner::ork()], &[])
            .is_ok());
    }

    /// N-11: `k = min(2, n_osk)` independent OSK signatures.
    #[test]
    fn a_high_power_operation_needs_two_independent_osks() {
        let mut c = AnchorChain::new();
        c.offer_anchor(anchor(1, b"ork")).expect("pin");
        for id in ["osk-1", "osk-2", "osk-3"] {
            c.install_delegation(delegation(id, vec![OskPower::Delegate], 1))
                .expect("install");
        }
        assert!(
            c.authorize(Operation::MintOsk, &[VerifiedSigner::osk("osk-1")], &[])
                .is_err(),
            "one signature is not a quorum with three OSKs"
        );
        assert!(c
            .authorize(
                Operation::MintOsk,
                &[VerifiedSigner::osk("osk-1"), VerifiedSigner::osk("osk-2")],
                &[]
            )
            .is_ok());
    }

    /// **Attack test — the exclusion is the point.** N-11 excludes "any OSK
    /// belonging to the target". Without it, a compromised OSK could sign its
    /// own retention or block its own revocation.
    #[test]
    fn the_targets_own_osk_cannot_contribute_to_the_quorum() {
        let mut c = AnchorChain::new();
        c.offer_anchor(anchor(1, b"ork")).expect("pin");
        for id in ["osk-1", "osk-2", "osk-target"] {
            c.install_delegation(delegation(id, vec![OskPower::Revoke], 1))
                .expect("install");
        }
        let target = vec!["osk-target".to_owned()];
        // The target's own signature plus one other is not a quorum of two.
        assert!(c
            .authorize(
                Operation::RevokePrivilegedDevice,
                &[
                    VerifiedSigner::osk("osk-target"),
                    VerifiedSigner::osk("osk-1")
                ],
                &target
            )
            .is_err());
        // Two independent ones are.
        assert!(c
            .authorize(
                Operation::RevokePrivilegedDevice,
                &[VerifiedSigner::osk("osk-1"), VerifiedSigner::osk("osk-2")],
                &target
            )
            .is_ok());
    }

    /// **Attack test.** Two signatures from the *same* key are one signature.
    #[test]
    fn a_repeated_signature_from_one_key_is_not_a_quorum() {
        let mut c = AnchorChain::new();
        c.offer_anchor(anchor(1, b"ork")).expect("pin");
        for id in ["osk-1", "osk-2"] {
            c.install_delegation(delegation(id, vec![OskPower::Delegate], 1))
                .expect("install");
        }
        assert!(c
            .authorize(
                Operation::MintOsk,
                &[VerifiedSigner::osk("osk-1"), VerifiedSigner::osk("osk-1")],
                &[]
            )
            .is_err());
    }

    /// With a single OSK, `k = min(2, 1) = 1` — N-13's "recurring warning while
    /// `n_osk == 1`" exists precisely because this is weaker.
    #[test]
    fn with_one_osk_the_quorum_is_one_and_the_count_is_visible() {
        let mut c = AnchorChain::new();
        c.offer_anchor(anchor(1, b"ork")).expect("pin");
        c.install_delegation(delegation("osk-1", vec![OskPower::Delegate], 1))
            .expect("install");
        assert_eq!(c.osk_count(), 1, "N-13's warning input");
        assert!(c
            .authorize(Operation::MintOsk, &[VerifiedSigner::osk("osk-1")], &[])
            .is_ok());
    }

    /// **Attack test — R-8, ADR-0007 §7.5's phrase-compromise recovery.**
    ///
    /// The Owner's laptop is stolen with an `ADMINISTER`-powered OSK on it. The
    /// Owner recovers with the phrase and rotates the root — which is the whole
    /// point of §7.5. Before this fix `offer_anchor` replaced the anchor and
    /// touched nothing else, so the stolen OSK's delegation stayed in the set
    /// and kept authorising: the recovery ceremony achieved nothing against the
    /// key it exists to remove.
    #[test]
    fn a_root_rotation_retires_the_old_roots_delegations() {
        let mut c = AnchorChain::new();
        c.offer_anchor(anchor(1, b"ork-a")).expect("pin");
        c.install_delegation(delegation("stolen", vec![OskPower::Administer], 1))
            .expect("install");
        c.install_delegation(delegation("also-old", vec![OskPower::Enroll], 1))
            .expect("install");
        assert_eq!(c.osk_count(), 2);
        let before = c.delegation_set_digest();

        // The recovery: a new root at a higher anchor_version.
        assert!(c
            .offer_anchor(anchor(2, b"ork-recovered"))
            .expect("advance"));

        assert_eq!(c.osk_count(), 0, "the old root's delegations are retired");
        assert!(c.delegation("stolen").is_none());
        assert!(matches!(
            c.osk_key("stolen"),
            Err(TrustError::NotAuthorized { .. })
        ));
        assert_ne!(
            c.delegation_set_digest(),
            before,
            "and every peer sees the set changed, through the prologue"
        );
    }

    /// The other half: a rotation must not be a lockout.
    ///
    /// A delegation the Owner issued UNDER THE NEW ROOT survives the advance
    /// that installs it — otherwise an Owner who published the anchor and its
    /// delegations together would find the delegations discarded by their own
    /// anchor.
    #[test]
    fn a_root_rotation_keeps_delegations_bound_at_or_above_the_new_anchor() {
        let mut c = AnchorChain::new();
        c.offer_anchor(anchor(1, b"ork-a")).expect("pin");
        c.install_delegation(delegation("old", vec![OskPower::Enroll], 1))
            .expect("install");
        c.install_delegation(delegation("new", vec![OskPower::Enroll], 2))
            .expect("install");

        c.offer_anchor(anchor(2, b"ork-b")).expect("advance");

        assert!(c.delegation("old").is_none(), "issued under the old root");
        assert!(c.delegation("new").is_some(), "issued under the new one");
        assert_eq!(c.osk_count(), 1);
    }

    /// A no-op re-delivery and a refused rollback must not disturb the set.
    #[test]
    fn only_an_advance_retires_delegations() {
        let mut c = AnchorChain::new();
        c.offer_anchor(anchor(3, b"ork-a")).expect("pin");
        c.install_delegation(delegation("osk-1", vec![OskPower::Enroll], 3))
            .expect("install");

        assert!(!c.offer_anchor(anchor(3, b"ork-a")).expect("re-delivery"));
        assert_eq!(c.osk_count(), 1, "a reconnect must not retire anything");

        assert!(c.offer_anchor(anchor(2, b"ork-a")).is_err());
        assert_eq!(c.osk_count(), 1, "a refused rollback changes nothing");

        assert!(c.offer_anchor(anchor(3, b"ork-b")).is_err());
        assert_eq!(c.osk_count(), 1, "and neither does a detected fork");
    }

    /// The delegation-set digest is deterministic and changes with the set,
    /// which is what makes the prologue's `delegation_set_digest` meaningful.
    #[test]
    fn the_delegation_set_digest_tracks_the_set() {
        let mut a = AnchorChain::new();
        a.offer_anchor(anchor(1, b"ork")).expect("pin");
        let empty = a.delegation_set_digest();
        a.install_delegation(delegation("osk-1", vec![OskPower::Enroll], 1))
            .expect("install");
        let one = a.delegation_set_digest();
        assert_ne!(empty, one);

        // Insertion order must not matter: two devices that learned the same
        // delegations in different orders must agree.
        let mut b = AnchorChain::new();
        b.offer_anchor(anchor(1, b"ork")).expect("pin");
        b.install_delegation(delegation("osk-2", vec![OskPower::Policy], 1))
            .expect("install");
        b.install_delegation(delegation("osk-1", vec![OskPower::Enroll], 1))
            .expect("install");
        let mut c = AnchorChain::new();
        c.offer_anchor(anchor(1, b"ork")).expect("pin");
        c.install_delegation(delegation("osk-1", vec![OskPower::Enroll], 1))
            .expect("install");
        c.install_delegation(delegation("osk-2", vec![OskPower::Policy], 1))
            .expect("install");
        assert_eq!(b.delegation_set_digest(), c.delegation_set_digest());
    }

    /// Removing a delegation removes its authority immediately.
    #[test]
    fn removing_a_delegation_removes_its_authority() {
        let mut c = AnchorChain::new();
        c.offer_anchor(anchor(1, b"ork")).expect("pin");
        c.install_delegation(delegation("osk-1", vec![OskPower::Enroll], 1))
            .expect("install");
        assert!(c
            .authorize(
                Operation::Ordinary(OskPower::Enroll),
                &[VerifiedSigner::osk("osk-1")],
                &[]
            )
            .is_ok());
        c.remove_delegation("osk-1");
        assert!(c
            .authorize(
                Operation::Ordinary(OskPower::Enroll),
                &[VerifiedSigner::osk("osk-1")],
                &[]
            )
            .is_err());
    }
}
