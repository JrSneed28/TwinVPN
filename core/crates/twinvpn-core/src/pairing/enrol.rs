//! Building a [`PairingEnrolment`] from what a composition root can actually
//! hold — **finding F-2A**.
//!
//! **Authority:** ADR-0007 §7.4 (C-D's "always required" authorization), §7.5
//! (the `OwnerTrustAnchor` and its delegation set, "pinned by every device at
//! enrolment and verified offline thereafter"), N-2, N-11, N-25(1); ADR-0018
//! CB-1 (portable logic belongs in the core), CB-5, §11.16 (l);
//! `docs/implementation/ownership.md` §11.2 G-21.
//!
//! **Owner:** `core-composition`.
//!
//! # What was missing
//!
//! [`crate::Core::install_pairing_enrolment`] had **no production caller**.
//! Every shipped composition therefore reached `pair.begin` with no enrolment
//! record and refused, so the C-B ceremony `crate::pairing` implements could not
//! be performed by the product — only by a test that called the installer
//! directly. That is the whole of F-2A.
//!
//! The installer's five inputs are why nobody had called it: three of them are
//! `twinvpn-trust` and `twinvpn-crypto` types, and a shell may name neither
//! (CD-I2 puts every key encoding in `twinvpn-crypto`, and CB-2 forbids a shell
//! a branch on a TwinVPN domain fact). So this module is the join: it takes
//! **octets and strings** — [`OwnerMaterial`], which a shell can read off a
//! disk with no dependency beyond `std::fs` — and produces the typed record.
//!
//! CB-1 puts it here rather than in `shells/linux`: reading and verifying Owner
//! material is portable, POSIX-free, and identical on all ten targets. Only the
//! **path** is the shell's, and CB-7 makes that an injection.
//!
//! # The four checks, in order
//!
//! 1. **The pin.** `ork_pub_cose` is parsed as an ES256 `COSE_Key`. It is the
//!    out-of-band root §7.5 says is "pinned by every device at enrolment"; an
//!    unparseable pin is `AUTH.IDENTITY_MISSING` for the chain, not a warning.
//! 2. **The anchor**, verified as a COSE_Sign1 **under that pin** and then
//!    required to carry the same `ork_pub_cose`. A self-signed statement
//!    verified only under the key it carries proves nothing; the pin is what
//!    makes the verification mean something, and the equality check is what
//!    stops an anchor naming a *different* root from being pinned by a file
//!    swap.
//! 3. **Each delegation**, verified under the ORK and installed through
//!    [`twinvpn_trust::AnchorChain::install_delegation`], which enforces §7.5's
//!    rule that a delegation bound below the pinned `anchor_version` does not
//!    survive. A delegation that fails to verify is **dropped**, never admitted.
//! 4. **This device's own name**, under ADR-0007 N-2 — see below.
//!
//! # N-2, and why nothing here guesses an encoding
//!
//! `IdentityPublic::public_key` is documented as "the public key bytes, **in the
//! element's own encoding**", with no declared encoding to parse — the seam gap
//! `cp_binding::transport` records and `ownership.md` G-21 owns. This module
//! does **not** close that gap by choosing an encoding. It closes it by
//! *proving* one:
//!
//! > N-2 fixes `identity_id = SHA-256(dCBOR(COSE_Key(IK_pub)))`.
//!
//! So a candidate encoding is admissible **iff** its digest equals the
//! `identity_id` the element itself reports. [`ik_pub_cose_for`] tries the two
//! candidates that exist — the bytes as they arrived, in case the element
//! already vends a `COSE_Key`, and their SPKI reading, which is the encoding
//! `twinvpn_crypto::cose::es256_cose_key_from_spki` documents as the device's
//! own IK path — and returns the one N-2 accepts. **Neither is trusted; one is
//! checked.** A key that is not this device's key cannot be enrolled, and a
//! device that cannot prove its own name installs nothing.
//!
//! # What is deliberately absent, and stated rather than glossed
//!
//! **The approver set is standing, not per-ceremony.** ADR-0007 §7.4's C-D is
//! "an OSK device holding `ENROLL` power **approves**" — a signature over *this
//! enrolment*, which arrives over C1/C2 and has no transport in this build
//! (W-12). What this device can verify offline is the ORK's signature over a
//! delegation, so [`OwnerMaterial::into_enrolment`] names as approvers exactly
//! the OSKs whose ORK-signed delegation carries `ENROLL`. That is a real,
//! ORK-signed fact rather than a configured string — and it is **weaker than
//! §7.4**: it authorizes "an ENROLL-powered OSK exists in this TwinNet" where
//! §7.4 wants "one approved this ceremony". The residual is recorded here,
//! reported by the shell at startup, and — since it had reached neither —
//! entered in the register as `ownership.md` §11.2 **G-25**. It narrows when C1
//! has a transport, and **not before**: a C1 transport does not by itself make
//! the approval per-ceremony, it only makes one possible, so G-25 must be
//! re-measured rather than closed when W-12 lands. Note also that the divergence
//! is **invisible to the acceptance gate** — on a host with no C1, a standing
//! approval and a per-ceremony one are observationally identical.
//!
//! **The revocation set is empty** unless a caller supplies one, for the reason
//! `crate::pairing` already gives: it arrives over C2 (W-12). An empty set is
//! the honest value and *not* the permissive one — `ops::begin` still refuses a
//! revoked device, it simply has nothing to check against yet.

use twinvpn_crypto::statements::{self, OskPower};
use twinvpn_crypto::{PublicVerifyingKey, StatementKind};
use twinvpn_trust::owner::VerifiedSigner;
use twinvpn_trust::{derive_identity_id, AnchorChain, RevocationState};
use twinvpn_types::{codes, Diagnostic, Identifier as _};

use super::{refusal, PairingEnrolment};

/// The Owner material a composition root hands the core, as octets.
///
/// **Every field is bytes or a string**, so a shell can fill it from files with
/// no dependency on `twinvpn-trust`, `twinvpn-crypto` or any cryptographic
/// crate. That is the whole reason this type exists rather than the shell
/// building an [`AnchorChain`] itself.
///
/// An **empty** value is legal and means "no Owner has authorized this device to
/// enrol anyone". It produces a record whose chain authorizes nothing, so
/// `pair.begin` refuses `AUTH.PAIRING_NOT_AUTHORIZED` — which is a *different*
/// fact from `AUTH.IDENTITY_MISSING` and must stay different. See
/// [`PairingEnrolment::new`].
#[derive(Debug, Clone, Default)]
pub struct OwnerMaterial {
    /// The pinned `OwnerRootKey` public half, as ES256 `COSE_Key` octets.
    ///
    /// §7.5's pin, injected out of band. **Public**: it is a verifying key and
    /// carries no secret, which is why it may sit in a file at all.
    pub ork_pub_cose: Vec<u8>,
    /// The ORK-signed `OwnerTrustAnchor`, as COSE_Sign1 wire octets.
    pub anchor: Vec<u8>,
    /// The ORK-signed `OwnerDelegation` set, one COSE_Sign1 each.
    pub delegations: Vec<Vec<u8>>,
    /// The offer's field 6 (`pairing_offer.cddl`), bounded by
    /// `pairing.max_offer_hint_bytes`.
    pub rendezvous_hint: String,
}

/// What [`OwnerMaterial::into_enrolment`] could not use, so a shell can report
/// it rather than discover it at the first `pair.begin`.
///
/// **Counts, never content.** A rejected statement's octets are not carried:
/// this is the same rule `pairing_offer.cddl` puts on a decode failure, applied
/// to the statements beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MaterialReport {
    /// Whether the anchor verified under the pin and was pinned.
    pub anchor_pinned: bool,
    /// How many delegations verified and were installed.
    pub delegations_installed: usize,
    /// How many were offered and did not verify, or were bound below the pinned
    /// `anchor_version`.
    pub delegations_rejected: usize,
    /// How many installed delegations carry `ENROLL`, and are therefore
    /// approvers.
    pub approvers: usize,
}

impl OwnerMaterial {
    /// Builds the chain, the approver set and the record `pair.begin` reads.
    ///
    /// `ik_pub_cose` must already have been proved to be this device's key —
    /// [`ik_pub_cose_for`] is the only thing in this crate that can say so.
    ///
    /// # Errors
    ///
    /// Everything [`PairingEnrolment::new`] refuses: `AUTH.IDENTITY_MISSING` for
    /// an absent key, `PROTO.SIZE_EXCEEDED` for an over-long hint.
    pub fn into_enrolment(
        self,
        ik_pub_cose: Vec<u8>,
    ) -> Result<(PairingEnrolment, MaterialReport), Box<Diagnostic>> {
        let mut report = MaterialReport::default();
        let mut chain = AnchorChain::new();

        // 1 and 2. The pin, then the anchor under it. Both must hold or the
        // chain stays unpinned — and an unpinned chain has no `ork_key`, so
        // every delegation below is refused too. That cascade is deliberate:
        // installing delegations under no root is exactly the "verified by
        // nobody" state §7.5 exists to prevent.
        let ork =
            PublicVerifyingKey::from_cose_key(&self.ork_pub_cose, StatementKind::OwnerTrustAnchor)
                .ok();
        if let Some(ork) = ork.as_ref() {
            report.anchor_pinned = pin_anchor(&mut chain, &self.anchor, ork, &self.ork_pub_cose);
        }

        // 3. The delegations, each under the ORK the anchor just pinned.
        if report.anchor_pinned {
            if let Some(ork) = ork.as_ref() {
                for octets in &self.delegations {
                    if install_delegation(&mut chain, octets, ork) {
                        report.delegations_installed += 1;
                    } else {
                        report.delegations_rejected += 1;
                    }
                }
            }
        } else {
            report.delegations_rejected = self.delegations.len();
        }

        // The approvers: every installed delegation carrying ENROLL. See the
        // module documentation on why this is standing rather than per-ceremony,
        // and on what that costs.
        let approvers: Vec<VerifiedSigner> = self
            .delegations
            .iter()
            .filter_map(|octets| enrol_powered_osk_id(&chain, octets, ork.as_ref()?))
            .map(|id| VerifiedSigner::osk(&id))
            .collect();
        report.approvers = approvers.len();

        // The revocation set is empty: N-25(1)'s set arrives over C2 and the
        // control-plane client has no transport (W-12). `ops::begin` still runs
        // the check, against nothing, which keeps it present for the day it has
        // a source rather than removing it and rediscovering it later.
        let enrolment = PairingEnrolment::new(
            chain,
            approvers,
            RevocationState::new(),
            ik_pub_cose,
            self.rendezvous_hint,
        )?;
        Ok((enrolment, report))
    }
}

/// Verifies the anchor under the pinned ORK and pins it.
///
/// **Two checks, and the second is the one a reviewer should look for.** The
/// signature is verified under the *pin*, not under the key the anchor carries —
/// a self-signed statement verified only under its own key proves nothing. Then
/// the two are required to be the same key.
///
/// Without that equality the chain could end up in a state where
/// [`AnchorChain::ork_key`] — which reads the *pinned anchor's* `ork_pub_cose` —
/// returns a different key from the one every statement was verified under, so
/// the delegations installed here and the statements verified later would answer
/// to two different roots. It costs one comparison and removes the whole class.
fn pin_anchor(
    chain: &mut AnchorChain,
    octets: &[u8],
    ork: &PublicVerifyingKey,
    pin: &[u8],
) -> bool {
    let Ok(verified) =
        twinvpn_crypto::verify_cose_sign1(octets, StatementKind::OwnerTrustAnchor, ork)
    else {
        return false;
    };
    let Ok(anchor) = statements::decode_owner_trust_anchor(&verified) else {
        return false;
    };
    if anchor.ork_pub_cose != pin {
        return false;
    }
    chain.offer_anchor(anchor).is_ok()
}

/// Verifies one delegation under the ORK and installs it.
fn install_delegation(chain: &mut AnchorChain, octets: &[u8], ork: &PublicVerifyingKey) -> bool {
    let Ok(verified) =
        twinvpn_crypto::verify_cose_sign1(octets, StatementKind::OwnerDelegation, ork)
    else {
        return false;
    };
    let Ok(delegation) = statements::decode_owner_delegation(&verified) else {
        return false;
    };
    chain.install_delegation(delegation).is_ok()
}

/// The `osk_id` of a delegation that verified, was installed, and carries
/// `ENROLL`.
///
/// Re-verified rather than remembered from [`install_delegation`], so this
/// function cannot name an id whose signature nobody checked — and cross-checked
/// against `chain.delegation(id)`, so it cannot name one the chain retired under
/// §7.5's anchor-advance rule.
fn enrol_powered_osk_id(
    chain: &AnchorChain,
    octets: &[u8],
    ork: &PublicVerifyingKey,
) -> Option<String> {
    let verified =
        twinvpn_crypto::verify_cose_sign1(octets, StatementKind::OwnerDelegation, ork).ok()?;
    let delegation = statements::decode_owner_delegation(&verified).ok()?;
    let installed = chain.delegation(&delegation.osk_id)?;
    installed.has(OskPower::Enroll).then_some(delegation.osk_id)
}

/// The ES256 `COSE_Key` octets N-2 hashes, **proved** against the `identity_id`
/// the element reports.
///
/// See the module documentation: this does not choose an encoding, it checks
/// two candidates against the one definition that can settle the question.
/// `None` means "this device cannot prove its own name", which is
/// `AUTH.IDENTITY_MISSING` and not a smaller problem.
#[must_use]
pub fn ik_pub_cose_for(identity: &twinvpn_platform::custody::IdentityPublic) -> Option<Vec<u8>> {
    let names_this_device =
        |cose: &[u8]| derive_identity_id(cose).as_bytes() == identity.identity_id.as_bytes();

    // Candidate 1: the element already vends a dCBOR COSE_Key.
    if names_this_device(&identity.public_key) {
        return Some(identity.public_key.clone());
    }
    // Candidate 2: an SPKI, which is what `cose::es256_cose_key_from_verifying_key`
    // documents as the device's own IK path.
    let cose = twinvpn_crypto::cose::es256_cose_key_from_spki(&identity.public_key)?;
    names_this_device(&cose).then_some(cose)
}

/// Reads the element, proves the key, and installs the record.
///
/// **The one function a composition root calls.** `Core::enrol_for_pairing`
/// wraps it; nothing else in this crate does.
///
/// # Errors
///
/// `AUTH.KEY_UNAVAILABLE` where the element refuses to report a public identity
/// — §11.16 (l)'s specified answer on a host with no element, and the reason
/// nothing is installed on such a host. `AUTH.IDENTITY_MISSING` where it reports
/// one whose key cannot be proved under N-2. Then everything
/// [`OwnerMaterial::into_enrolment`] refuses.
pub(crate) fn enrol(
    core: &crate::Core,
    material: OwnerMaterial,
) -> Result<MaterialReport, Box<Diagnostic>> {
    let identity = core
        .block_on_adapter(|_, adapter| adapter.identity().public_identity())
        .map_err(|_| refusal(codes::AUTH_KEY_UNAVAILABLE))?;
    let Some(ik_pub_cose) = ik_pub_cose_for(&identity) else {
        return Err(refusal(codes::AUTH_IDENTITY_MISSING));
    };
    let (enrolment, report) = material.into_enrolment(ik_pub_cose)?;
    core.install_pairing_enrolment(enrolment);
    Ok(report)
}
