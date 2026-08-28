//! Who signed this, and were they allowed to?
//!
//! **Authority:** `contracts/proto/twinvpn/v1/identity.proto` (a
//! `SignedStatement` is opaque COSE_Sign1 and "the signature MUST be verified
//! over the RECEIVED OCTETS; an implementation MUST NOT re-serialize before
//! verifying"), `policy.proto` ("the control plane WAREHOUSES AND DISTRIBUTES;
//! IT CANNOT AUTHOR"), `protocol.md` §7, ADR-0007 N-25, finding **W-4**.
//!
//! # This module is where "authenticated but not trusted" is made mechanical
//!
//! [`StatementKind::required_authority`] is the exact table
//! `twinvpn-cp-client`'s `ports::StatementKind` carries, transcribed so the
//! server refuses what the client would refuse. A `PolicyBundle` that verified
//! against a *device* key is not a policy bundle; a `RouteAdvertisement` that
//! verified against the *`Owner`* chain is a coordination service minting
//! routes, which is the capability Rule B exists to remove.
//!
//! # The verifier is real, and it is still fail-closed
//!
//! [`CryptoVerifier`] verifies COSE_Sign1 **over the received octets** through
//! `twinvpn-crypto` — the audited provider, the one the client verifies with.
//! Using it rather than a second implementation is DP-8: two providers "double
//! the assurance surface" and must pass the identical golden-vector corpus, and
//! an agreement this service cannot test is not an agreement.
//!
//! Which key a statement must verify against is the caller's decision, not the
//! verifier's, and [`SignerKey`] makes it one:
//!
//! - [`SignerKey::Device`] — the calling device's own `DeviceIdentityKey`, which
//!   this service holds from registration. **Fully bound**: `PairingAttestation`,
//!   `IdentitySuccession`, `TunnelKeyBinding`, `RouteAdvertisement` and
//!   `ExitNodeOffer` are verified for real.
//! - [`SignerKey::OwnerAnchors`] — the pinned `OwnerTrustAnchor` set (S-32).
//!   With none configured, [`CryptoVerifier`] answers `AUTH.KEY_UNAVAILABLE` and
//!   **admits nothing**, so a `RevocationStatement` or a `PolicyBundle` is
//!   refused rather than admitted on trust. That is not an unfinished stub: a
//!   control plane that admitted an unverifiable revocation would be granting
//!   authority it does not have, and a design in which a compromised control
//!   plane could grant authority is a defect rather than a tradeoff.
//!
//! **What is still an integration item:** evaluating the `Owner` *delegation
//! chain* — whether the OSK that signed carries `ENROLL`, `POLICY` or `REVOKE`,
//! and whether its delegation is current for the anchor version. That is
//! `twinvpn-trust`'s (S-32), and this artifact does not link it. Configuring an
//! anchor key here therefore buys signature verification against a pinned key
//! set, not power scoping; `README.md` §7 says so rather than implying more.

use bytes::Bytes;
use twinvpn_service_common::forward::Verbatim;
use twinvpn_service_common::{Channel, Reject, ServiceError};

use crate::codes;

/// Bounds and retains a COSE_Sign1 statement, **with no structural assumption**.
///
/// [`Verbatim::from_opaque`] is the B4 constructor: the channel's byte cap and
/// nothing else. That is the correct one here and
/// [`Verbatim::from_received`] is not — `from_received` walks the *protobuf*
/// wire format, and `identity.proto` says a `SignedStatement` is "opaque
/// COSE_Sign1 octets", deterministic CBOR inside COSE. A protobuf record scan
/// over CBOR rejects it as `PROTO.UNPARSEABLE_ENVELOPE`, refusing exactly the
/// payloads ADR-0003 §11 B2 requires to be forwarded verbatim.
///
/// # Errors
///
/// [`Reject::SizeExceeded`] past the C1 envelope cap. The statement travels
/// inside a C1 message, so the envelope cap is its bound; a second per-statement
/// cap could disagree with the first.
pub fn opaque_statement(bytes: Bytes) -> Result<Verbatim, Reject> {
    Verbatim::from_opaque(bytes, Channel::ControlAndTelemetry)
}

/// Which CDDL statement type a verified payload turned out to be.
///
/// Narrowed to the ones this service sees on C1. Mirrors
/// `identity.proto`'s `SignedStatementType` and `twinvpn-cp-client`'s
/// `ports::StatementKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StatementKind {
    /// `RevocationStatement` — `Owner`-authority signed.
    RevocationStatement,
    /// `PolicyBundle` — `Owner`-authored. This service distributes; it cannot
    /// author.
    PolicyBundle,
    /// `PairingAttestation` — signed by a pairing device.
    PairingAttestation,
    /// `IdentitySuccession` — **dual-signed** by the old *and* the new IK.
    IdentitySuccession,
    /// `TunnelKeyBinding` — IK-signed.
    TunnelKeyBinding,
    /// `RouteAdvertisement` — signed by the advertiser.
    RouteAdvertisement,
    /// `ExitNodeOffer` — signed by the offerer.
    ExitNodeOffer,
    /// `RelayEpochFloor` — `Owner`-signed, monotone.
    RelayEpochFloor,
    /// `PairingRevocation` — **`Owner`-signed**. `pairing.proto`: "A device MUST
    /// NOT be able to revoke a pairing on its own authority any more than it can
    /// revoke a peer."
    PairingRevocation,
    /// `OwnerDelegation` — the enrolment proof an OSK with `ENROLL` signs.
    OwnerDelegation,
}

impl StatementKind {
    /// A stable, non-localised tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            StatementKind::RevocationStatement => "revocation_statement",
            StatementKind::PolicyBundle => "policy_bundle",
            StatementKind::PairingAttestation => "pairing_attestation",
            StatementKind::IdentitySuccession => "identity_succession",
            StatementKind::TunnelKeyBinding => "tunnel_key_binding",
            StatementKind::RouteAdvertisement => "route_advertisement",
            StatementKind::ExitNodeOffer => "exit_node_offer",
            StatementKind::RelayEpochFloor => "relay_epoch_floor",
            StatementKind::PairingRevocation => "pairing_revocation",
            StatementKind::OwnerDelegation => "owner_delegation",
        }
    }

    /// Which authority must have signed this for it to mean anything.
    #[must_use]
    pub const fn required_authority(self) -> SigningAuthority {
        match self {
            StatementKind::RevocationStatement
            | StatementKind::PolicyBundle
            | StatementKind::RelayEpochFloor
            | StatementKind::PairingRevocation
            | StatementKind::OwnerDelegation => SigningAuthority::Owner,
            StatementKind::PairingAttestation
            | StatementKind::IdentitySuccession
            | StatementKind::TunnelKeyBinding
            | StatementKind::RouteAdvertisement
            | StatementKind::ExitNodeOffer => SigningAuthority::Device,
        }
    }

    /// Which **OSK power** an `Owner`-authority signer must carry to author this.
    ///
    /// ADR-0007 O5 is a two-tier hierarchy: an offline, phrase-derived
    /// `OwnerRootKey` and a hardware-resident, ORK-delegated `OwnerSigningKey`
    /// per admin device, so that "routine operations (enroll, revoke, publish
    /// policy) use a hardware-resident OSK" and "the common path has no phrase
    /// and no ritual". **Every routine `Owner` operation is therefore OSK-signed,
    /// and each names the power it needs** — §11 rows for `RevocationStatement`
    /// ("`Owner` OSK with `REVOKE`"), policy ("one OSK signature with the
    /// matching power") and enrolment ("an OSK device holding `ENROLL` power
    /// approves").
    ///
    /// `None` for the device-authority kinds: an OSK power is not a thing a
    /// device statement can carry, and a `None` here is what keeps
    /// [`admit`]'s check total without inventing a power for them.
    #[must_use]
    pub const fn required_power(self) -> Option<twinvpn_crypto::statements::OskPower> {
        use twinvpn_crypto::statements::OskPower as P;
        match self {
            StatementKind::RevocationStatement | StatementKind::PairingRevocation => {
                Some(P::Revoke)
            }
            StatementKind::PolicyBundle => Some(P::Policy),
            // The enrolment proof. The power is checked on the delegation the
            // proof IS, not on whoever signed it — see [`admit`].
            StatementKind::OwnerDelegation => Some(P::Enroll),
            // ADR-0007 §11: the relay epoch floor is a TwinNet-wide
            // administrative act, not an enrolment, a revocation or a policy.
            StatementKind::RelayEpochFloor => Some(P::Administer),
            StatementKind::PairingAttestation
            | StatementKind::IdentitySuccession
            | StatementKind::TunnelKeyBinding
            | StatementKind::RouteAdvertisement
            | StatementKind::ExitNodeOffer => None,
        }
    }

    /// The same type, as `twinvpn-crypto` names it.
    ///
    /// A total match, so a statement type added here without a crypto
    /// counterpart is a compile error rather than a verification that silently
    /// checks the wrong CDDL shape.
    #[must_use]
    pub const fn as_crypto_kind(self) -> twinvpn_crypto::StatementKind {
        use twinvpn_crypto::StatementKind as K;
        match self {
            // `pairing.proto`'s PairingRevocation shares the CDDL shape:
            // both are Owner statements withdrawing something, and the CDDL
            // has one type for them. Listed separately so this match stays
            // total over the server's own enum.
            #[allow(clippy::match_same_arms)]
            StatementKind::RevocationStatement => K::RevocationStatement,
            StatementKind::PolicyBundle => K::PolicyBundle,
            StatementKind::PairingAttestation => K::PairingAttestation,
            StatementKind::IdentitySuccession => K::IdentitySuccession,
            StatementKind::TunnelKeyBinding => K::TunnelKeyBinding,
            StatementKind::RouteAdvertisement => K::RouteAdvertisement,
            StatementKind::ExitNodeOffer => K::ExitNodeOffer,
            StatementKind::RelayEpochFloor => K::RelayEpochFloor,
            // `pairing.proto`'s PairingRevocation is an Owner statement about
            // one relationship. The CDDL carries it as a RevocationStatement
            // shape; naming it here keeps the two tables total.
            StatementKind::PairingRevocation => K::RevocationStatement,
            StatementKind::OwnerDelegation => K::OwnerDelegation,
        }
    }

    /// Whether this statement requires **two** signatures.
    ///
    /// `IdentitySuccession` is dual-signed by the old *and* the new IK: "a
    /// single-signature rotation would let a stolen key rotate itself into
    /// permanence; an old-key-only signature would let a compromised old key
    /// install an attacker's new key."
    #[must_use]
    pub const fn is_dual_signed(self) -> bool {
        matches!(self, StatementKind::IdentitySuccession)
    }
}

/// Who a signature must chain to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningAuthority {
    /// The pinned `OwnerTrustAnchor` and its delegation chain (S-32).
    Owner,
    /// A `DeviceIdentityKey`, verified against the device's known identity.
    Device,
}

/// One `OwnerSigningKey` and what the `Owner` delegated to it.
///
/// Decoded from an ORK-signed `OwnerDelegation` by `twinvpn-crypto`, which owns
/// the CDDL, the closed [`OskPower`](twinvpn_crypto::statements::OskPower) enum
/// and the rule that "an unrecognised power is a **rejection**, not an ignored
/// entry". Nothing here re-derives any of that; this is the decoded result
/// carried where the authority check can reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    /// The key's identifier, and the `osk_id` evidence field
    /// `AUTH.UNEXPECTED_DELEGATION` declares.
    pub osk_id: String,
    /// COSE_Key octets for the OSK public half.
    pub osk_pub_cose: Vec<u8>,
    /// The powers, sorted and deduplicated by the decoder.
    pub powers: Vec<twinvpn_crypto::statements::OskPower>,
    /// Which anchor this delegation is bound to. "A delegation issued under an
    /// older anchor does not survive an anchor advance by default."
    pub anchor_version: u64,
    /// Expiry, checked at **use** time and not at load: this process outlives
    /// the delegations it loaded.
    pub not_after_ms: u64,
}

impl Delegation {
    /// Whether this delegation carries `power`.
    #[must_use]
    pub fn has(&self, power: twinvpn_crypto::statements::OskPower) -> bool {
        self.powers.contains(&power)
    }

    /// The powers, rendered for a log line. Public identifiers, never secrets.
    #[must_use]
    pub fn powers_str(&self) -> String {
        self.powers
            .iter()
            .map(|p| format!("{p:?}"))
            .collect::<Vec<_>>()
            .join("|")
    }
}

/// The successor identity an `IdentitySuccession` names.
///
/// Carried out of verification because it is the **only** place the successor is
/// available: `RotateDeviceCredentialRequest` has no field for a new public key,
/// so the sole statement of "which identity this device becomes" is inside the
/// signed payload. `domain::device::rotate_credential` re-indexes the device
/// record onto `new_identity_id`, which is what lets the rotated device's next
/// TLS connection still resolve to its own `device_id`
/// ([`crate::store::ControlStore::device_for_identity`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Succession {
    /// Unchanged across the rotation — ADR-0007 N-21, so S-08's immutable
    /// address allocation survives it.
    pub device_id: [u8; 32],
    /// The identity being replaced.
    pub old_identity_id: [u8; 32],
    /// The replacement, and the value the device table re-indexes onto.
    pub new_identity_id: [u8; 32],
    /// Exactly the old generation + 1.
    pub generation: u64,
}

/// What a verified `RevocationStatement` actually says, as **signed**.
///
/// R-4: `RevokeDeviceRequest.target_device_id` is an unsigned wire field, so
/// without this the service verified an Owner signature and then revoked
/// whatever the *caller* named. Replaying any Owner-signed revocation with a
/// different wire target revoked an arbitrary device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    /// The device the **Owner** signed for. The only authority on the target.
    pub target_device_id: [u8; 32],
    /// The generation, or `None` meaning every generation.
    pub target_identity_id: Option<[u8; 32]>,
    /// Which `TwinNet` the Owner signed about.
    pub twinnet_id: String,
    /// From the `AUTH` domain, for the audit row.
    pub reason_code: String,
}

/// What a verified `PolicyBundle` actually says, as **signed**.
///
/// R-4: `PolicyBundle.policy_version` on the wire is an unsigned hint, and the
/// floor was advanced from it. An old signed bundle re-wrapped with a higher
/// wire version is a **signed policy rollback**; `u64::MAX` permanently bricks
/// every future bundle. The number that orders policy has to come from inside
/// the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyClaims {
    /// Monotone. "A device MUST reject `<=` its high-water mark."
    pub policy_version: u64,
    /// The document lineage, constant across versions.
    pub policy_id: String,
    /// A floor, never a ceiling.
    pub killswitch_floor: u64,
}

/// A statement whose signature verified **over the received octets**.
#[derive(Debug, Clone)]
pub struct Verified {
    /// The type found *inside* the signed payload, not the wire's hint.
    pub kind: StatementKind,
    /// The authority the signature chained to.
    pub authority: SigningAuthority,
    /// Whoever signed, as a stable key id, for the audit row.
    pub signer_key_id: String,
    /// The exact octets that were verified, retained for forwarding.
    pub octets: Verbatim,
    /// `not_before_ms` from the signed payload.
    pub not_before_ms: u64,
    /// `not_after_ms` from the signed payload.
    pub not_after_ms: u64,
    /// The ceremony a `PairingAttestation` names, for that kind only.
    ///
    /// The attestation is the **only** thing that binds a completion to a
    /// ceremony: `PairingRequest` names no responder, so the control plane
    /// cannot know in advance which second device is entitled to complete one.
    /// What it can check is that the attestation the caller signed is an
    /// attestation *for this pairing* — see
    /// [`crate::domain::pairing::complete`].
    pub pairing_id: Option<[u8; 16]>,
    /// The delegation the **signer** holds, when an OSK signed rather than the
    /// ORK itself.
    ///
    /// `None` means the root signed: the ORK is unscoped by construction — it is
    /// the key every delegation chains to — so there is no power to check
    /// against it.
    pub signer_delegation: Option<Delegation>,
    /// The delegation this statement **is**, for `OwnerDelegation` only.
    ///
    /// The enrolment proof is itself an `OwnerDelegation`, so the power that
    /// matters for `RegisterDevice` is the one *inside* the proof, not the one
    /// its signer holds. Both are carried because both are checked, in different
    /// places, for different reasons.
    pub delegation: Option<Delegation>,
    /// The succession this statement declares, for `IdentitySuccession` only.
    ///
    /// `None` for every other kind, and `None` for a succession whose payload
    /// did not decode — a verifier reports what it read, and the handler decides
    /// what a missing successor means rather than being handed a default.
    pub succession: Option<Succession>,
    /// What a `RevocationStatement` or `PairingRevocation` **signed**, for
    /// those kinds only (R-4).
    ///
    /// The handler compares this against whatever the wire named. `None` for
    /// every other kind, and `None` for a payload that did not decode — the
    /// same "report what you read" rule [`Verified::succession`] follows, which
    /// is what lets the handler refuse rather than be handed a default target.
    pub revocation: Option<Revocation>,
    /// What a `PolicyBundle` **signed**, for that kind only (R-4).
    pub policy: Option<PolicyClaims>,
}

/// Why verification failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyFailure {
    /// The signature did not verify against the required authority.
    #[error("signature did not verify")]
    BadSignature,
    /// The payload's own type did not match what the caller dispatched on.
    #[error("statement type mismatch")]
    TypeMismatch,
    /// The signer is not permitted to author this statement type.
    #[error("wrong signing authority")]
    WrongAuthority,
    /// Non-canonical deterministic CBOR. **Rejected, never normalized** —
    /// normalizing attacker input before verification is a signature-bypass
    /// pattern.
    #[error("non-canonical CBOR")]
    NonCanonical,
    /// An unrecognized `crit` member. Ignoring one turns a future *tightening*
    /// into a silent no-op.
    #[error("unrecognized critical field")]
    UnknownCriticalField,
    /// The statement's own validity window has passed.
    #[error("statement expired")]
    Expired,
    /// The trust anchor needed to verify is not available.
    #[error("no trust anchor")]
    NoAnchor,
    /// Only one signature on a statement that requires two.
    #[error("missing the second signature")]
    MissingCosignature,
}

impl VerifyFailure {
    /// The registered `reason_code` for this failure.
    #[must_use]
    pub fn into_error(self) -> ServiceError {
        match self {
            VerifyFailure::BadSignature
            | VerifyFailure::TypeMismatch
            | VerifyFailure::MissingCosignature => codes::bare(codes::SIGNATURE_INVALID),
            VerifyFailure::WrongAuthority => codes::bare(codes::WRONG_SIGNING_AUTHORITY),
            VerifyFailure::NonCanonical => {
                codes::bare(twinvpn_types::codes::PROTO_NON_CANONICAL_CBOR)
            }
            VerifyFailure::UnknownCriticalField => {
                codes::bare(twinvpn_types::codes::PROTO_UNKNOWN_CRITICAL_FIELD)
            }
            VerifyFailure::Expired => codes::bare(twinvpn_types::codes::AUTH_STATEMENT_EXPIRED),
            VerifyFailure::NoAnchor => codes::bare(codes::NO_TRUST_ANCHOR),
        }
    }
}

/// Whose key a statement must verify against.
///
/// The **caller** chooses, not the verifier. A verifier that picked the key
/// would be choosing whether a statement is `Owner`-authority or
/// device-authority, which is exactly the decision
/// [`StatementKind::required_authority`] exists to fix in one table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerKey<'a> {
    /// The pinned `OwnerTrustAnchor` set (S-32), held by the verifier.
    OwnerAnchors,
    /// One device's `DeviceIdentityKey`, as COSE_Key octets — the value this
    /// service recorded at registration, never one the request supplied.
    Device(&'a [u8]),
}

impl SignerKey<'_> {
    /// The authority a signature against this key establishes.
    #[must_use]
    pub const fn authority(&self) -> SigningAuthority {
        match self {
            SignerKey::OwnerAnchors => SigningAuthority::Owner,
            SignerKey::Device(_) => SigningAuthority::Device,
        }
    }
}

/// Signature verification, as this service needs it.
///
/// An implementation MUST verify over the received octets, MUST NOT
/// re-serialize, MUST reject non-canonical CBOR rather than normalize it, MUST
/// reject an unrecognized `crit` member, and MUST return the type it found
/// *inside* the signed payload rather than the wire's hint.
pub trait StatementVerifier: Send + Sync {
    /// Verifies one COSE_Sign1 statement against `signer`.
    ///
    /// `expected` is the caller's dispatch expectation. An implementation MUST
    /// compare it against the type inside the verified payload and fail on a
    /// mismatch rather than trusting the caller or the wire.
    ///
    /// # Errors
    ///
    /// [`VerifyFailure`].
    fn verify(
        &self,
        octets: &Verbatim,
        expected: StatementKind,
        now_ms: u64,
        signer: SignerKey<'_>,
    ) -> Result<Verified, VerifyFailure>;
}

/// A verifier that admits nothing at all.
///
/// Not the shipped default any more — [`CryptoVerifier`] is — but kept as the
/// posture a deployment gets when it has neither an anchor nor a device key, and
/// as the thing `an_unbound_verifier_admits_nothing` pins so a future change
/// that makes refusal optional breaks a test whose name says what was lost.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefuseUnverifiable;

impl StatementVerifier for RefuseUnverifiable {
    fn verify(
        &self,
        _octets: &Verbatim,
        _expected: StatementKind,
        _now_ms: u64,
        _signer: SignerKey<'_>,
    ) -> Result<Verified, VerifyFailure> {
        Err(VerifyFailure::NoAnchor)
    }
}

/// COSE_Sign1 verification through `twinvpn-crypto`.
///
/// Holds the pinned `OwnerTrustAnchor` key set. An empty set is not an error at
/// construction and is a refusal at use: a deployment with no anchor still
/// enrols devices whose statements are device-signed, and cannot revoke or
/// author policy.
#[derive(Debug, Default)]
pub struct CryptoVerifier {
    owner: Vec<twinvpn_crypto::PublicVerifyingKey>,
    /// The ORK-signed `OwnerDelegation` set, verified at construction and held
    /// as `(the OSK's verifying key, what it may do)`.
    ///
    /// **Verified once, at load, against the pinned ORK** — which is what makes
    /// a delegation a delegation rather than a claim, and is why a delegation
    /// that does not verify is a startup failure rather than a refusal nobody
    /// sees until an operator tries to revoke a stolen laptop.
    delegated: Vec<(twinvpn_crypto::PublicVerifyingKey, Delegation)>,
}

impl CryptoVerifier {
    /// Binds a verifier to a pinned anchor key set.
    ///
    /// Each entry is COSE_Key octets for a public verifying key. A key carrying
    /// a private half is refused by `twinvpn-crypto` itself (CD-I4 held at the
    /// boundary), so a mis-provisioned secret cannot be loaded here by accident.
    ///
    /// # Errors
    ///
    /// `AUTH.ANCHOR_VERSION_UNSUPPORTED` when an entry is not a parsable
    /// COSE_Key of a supported algorithm. Startup fails rather than running with
    /// a partially-loaded anchor set, because a partially-loaded set silently
    /// refuses statements a correctly-configured one would admit.
    pub fn new(owner_anchor_cose_keys: &[Vec<u8>]) -> Result<Self, ServiceError> {
        Self::with_delegations(owner_anchor_cose_keys, &[], 0)
    }

    /// Binds a verifier to a pinned anchor key set **and its delegation chain**.
    ///
    /// Each entry in `delegations` is the COSE_Sign1 octets of an ORK-signed
    /// `OwnerDelegation`. Every one is verified against `owner_anchor_cose_keys`
    /// here, once, and decoded through `twinvpn-crypto` — so what this holds
    /// afterwards is a set of keys the `Owner` demonstrably delegated to, and
    /// the powers it gave each.
    ///
    /// `expected_anchor_version` is the operator's declared anchor generation.
    /// When non-zero, a delegation naming a different one is refused at startup:
    /// S-32 says "a delegation issued under an older anchor does not survive an
    /// anchor advance by default", and a mixed set silently means half an anchor
    /// rotation was applied. Zero disables the check, for a deployment that has
    /// never advanced its anchor.
    ///
    /// # Errors
    ///
    /// `AUTH.ANCHOR_VERSION_UNSUPPORTED` when an anchor entry is not a parsable
    /// COSE_Key of a supported algorithm, when a delegation names an unexpected
    /// anchor version, or when a delegation is offered with **no** anchor to
    /// verify it against. `AUTH.BINDING_INVALID` when a delegation does not
    /// verify against the pinned set, or is not a decodable `OwnerDelegation`.
    ///
    /// Every one of these is a **startup failure** rather than a per-request
    /// refusal, for the reason a malformed anchor line is: a partially-loaded
    /// authority set produces a service that refuses operations a correctly
    /// configured one would admit, which reads as an outage and is diagnosed as
    /// one.
    pub fn with_delegations(
        owner_anchor_cose_keys: &[Vec<u8>],
        delegations: &[Vec<u8>],
        expected_anchor_version: u64,
    ) -> Result<Self, ServiceError> {
        let mut owner = Vec::with_capacity(owner_anchor_cose_keys.len());
        for k in owner_anchor_cose_keys {
            owner.push(
                twinvpn_crypto::PublicVerifyingKey::from_cose_key(
                    k,
                    twinvpn_crypto::StatementKind::OwnerTrustAnchor,
                )
                .map_err(|_| codes::bare(twinvpn_types::codes::AUTH_ANCHOR_VERSION_UNSUPPORTED))?,
            );
        }
        if !delegations.is_empty() && owner.is_empty() {
            // A delegation with nothing to chain to is not a weaker
            // authorisation; it is none at all. Admitting it would make the
            // delegation file itself the trust root.
            return Err(codes::bare(
                twinvpn_types::codes::AUTH_ANCHOR_VERSION_UNSUPPORTED,
            ));
        }

        let mut delegated = Vec::with_capacity(delegations.len());
        for octets in delegations {
            let statement = owner
                .iter()
                .find_map(|anchor| {
                    twinvpn_crypto::verify_cose_sign1(
                        octets,
                        twinvpn_crypto::StatementKind::OwnerDelegation,
                        anchor,
                    )
                    .ok()
                })
                .ok_or_else(|| codes::bare(codes::SIGNATURE_INVALID))?;
            let decoded = twinvpn_crypto::statements::decode_owner_delegation(&statement)
                .map_err(|_| codes::bare(codes::SIGNATURE_INVALID))?;
            if expected_anchor_version != 0 && decoded.anchor_version != expected_anchor_version {
                return Err(codes::bare(
                    twinvpn_types::codes::AUTH_ANCHOR_VERSION_UNSUPPORTED,
                ));
            }
            let key = twinvpn_crypto::PublicVerifyingKey::from_cose_key(
                &decoded.osk_pub_cose,
                twinvpn_crypto::StatementKind::OwnerDelegation,
            )
            .map_err(|_| codes::bare(twinvpn_types::codes::AUTH_ANCHOR_VERSION_UNSUPPORTED))?;
            delegated.push((
                key,
                Delegation {
                    osk_id: decoded.osk_id,
                    osk_pub_cose: decoded.osk_pub_cose,
                    powers: decoded.powers,
                    anchor_version: decoded.anchor_version,
                    not_after_ms: decoded.not_after_ms,
                },
            ));
        }
        Ok(Self { owner, delegated })
    }

    /// The delegations this verifier admitted, for the startup posture line.
    #[must_use]
    pub fn delegations(&self) -> Vec<&Delegation> {
        self.delegated.iter().map(|(_, d)| d).collect()
    }

    /// Whether any `Owner`-authority statement can be admitted at all.
    #[must_use]
    pub fn has_owner_anchor(&self) -> bool {
        !self.owner.is_empty()
    }
}

impl StatementVerifier for CryptoVerifier {
    fn verify(
        &self,
        octets: &Verbatim,
        expected: StatementKind,
        _now_ms: u64,
        signer: SignerKey<'_>,
    ) -> Result<Verified, VerifyFailure> {
        let kind = expected.as_crypto_kind();

        // The candidate set. For a device it is exactly one key — the one this
        // service recorded — so "it verified" and "that device signed it" are
        // the same statement.
        let device_key;
        let candidates: &[twinvpn_crypto::PublicVerifyingKey] = match signer {
            SignerKey::OwnerAnchors => {
                if self.owner.is_empty() {
                    return Err(VerifyFailure::NoAnchor);
                }
                &self.owner
            }
            SignerKey::Device(cose) => {
                if cose.is_empty() {
                    return Err(VerifyFailure::NoAnchor);
                }
                device_key = twinvpn_crypto::PublicVerifyingKey::from_cose_key(cose, kind)
                    .map_err(|_| VerifyFailure::WrongAuthority)?;
                std::slice::from_ref(&device_key)
            }
        };

        let mut last = VerifyFailure::BadSignature;
        // The ORK first, then every key it delegated to. Order matters only for
        // reporting: a key cannot be both, because a delegation names an OSK and
        // the ORK signs the delegation.
        let delegated: Vec<(&twinvpn_crypto::PublicVerifyingKey, Option<&Delegation>)> =
            match signer {
                SignerKey::OwnerAnchors => candidates
                    .iter()
                    .map(|k| (k, None))
                    .chain(self.delegated.iter().map(|(k, d)| (k, Some(d))))
                    .collect(),
                // A device statement chains to nothing: the candidate set is
                // exactly the one key this service recorded for that device.
                SignerKey::Device(_) => candidates.iter().map(|k| (k, None)).collect(),
            };

        for (key, holder) in delegated {
            match twinvpn_crypto::verify_cose_sign1(octets.as_bytes(), kind, key) {
                Ok(statement) => {
                    return Ok(Verified {
                        kind: expected,
                        authority: signer.authority(),
                        signer_key_id: statement.key_id().map(hex_lower).unwrap_or_default(),
                        octets: octets.clone(),
                        not_before_ms: not_before_of(expected, &statement),
                        not_after_ms: not_after_of(expected, &statement),
                        pairing_id: pairing_id_of(expected, &statement),
                        signer_delegation: holder.cloned(),
                        delegation: delegation_of(expected, &statement),
                        succession: succession_of(expected, &statement),
                        revocation: revocation_of(expected, &statement),
                        policy: policy_of(expected, &statement),
                    });
                }
                // Only a signature mismatch is worth trying the next anchor:
                // a malformed or non-canonical envelope is malformed against
                // every key, and re-running the parse would just be slower.
                Err(twinvpn_crypto::CryptoError::SignatureInvalid { .. }) => {
                    last = VerifyFailure::BadSignature;
                }
                Err(other) => return Err(map_crypto_error(&other)),
            }
        }
        Err(last)
    }
}

/// Reads the statement's own `not_before_ms`, where its CDDL declares one.
///
/// # R-12
///
/// This used to be the literal `0`, on the line beside a decoded
/// `not_after_ms`. Every `admit` therefore passed `now_ms < claim.not_before_ms`
/// unconditionally, so the not-yet-valid gate did not exist in the shipped
/// object at all — the nbf tests exercise [`testing::ScriptedVerifier`], which
/// is `#[cfg(test)]`, so they were thorough against the wrong object.
///
/// The match has **no wildcard arm**, for the reason [`succession_of`] has none:
/// `signed_statements.cddl` declares `not_before_ms` on exactly two statements
/// (`device-identity-record` field 9 and `relay-capability-token` field 5), and
/// this service admits neither. That is a fact about the frozen contract, not a
/// decision this code gets to make silently — so each of the ten kinds names
/// itself here, and a statement that later gains an nbf fails to compile until
/// someone has decided whether to read it.
fn not_before_of(
    expected: StatementKind,
    statement: &twinvpn_crypto::cose::VerifiedStatement,
) -> u64 {
    let _ = statement;
    match expected {
        // None of the ten kinds this service admits declares `not_before_ms`.
        // Zero is "valid from the beginning of time", which is what a statement
        // with no lower bound means — not "the check is skipped".
        StatementKind::RevocationStatement
        | StatementKind::PolicyBundle
        | StatementKind::PairingAttestation
        | StatementKind::IdentitySuccession
        | StatementKind::TunnelKeyBinding
        | StatementKind::RouteAdvertisement
        | StatementKind::ExitNodeOffer
        | StatementKind::RelayEpochFloor
        | StatementKind::PairingRevocation
        | StatementKind::OwnerDelegation => 0,
    }
}

/// Reads the statement's own `not_after_ms`, where its CDDL declares one.
///
/// A `RevocationStatement` has none, and that is correct rather than an
/// omission: ADR-0009 §11.4 makes every denial permanent — "denials are monotone
/// accumulations, not leases" — so a revocation that expired would un-revoke a
/// stolen device by doing nothing.
fn not_after_of(
    expected: StatementKind,
    statement: &twinvpn_crypto::cose::VerifiedStatement,
) -> u64 {
    use twinvpn_crypto::statements as st;
    match expected {
        StatementKind::PairingAttestation => {
            st::decode_pairing_attestation(statement).map_or(0, |s| s.not_after_ms)
        }
        StatementKind::IdentitySuccession => {
            st::decode_identity_succession(statement).map_or(0, |s| s.not_after_ms)
        }
        StatementKind::PolicyBundle => {
            st::decode_policy_bundle(statement).map_or(0, |s| s.not_after_ms)
        }
        StatementKind::OwnerDelegation => {
            st::decode_owner_delegation(statement).map_or(0, |s| s.not_after_ms)
        }
        StatementKind::RouteAdvertisement => {
            st::decode_route_advertisement(statement).map_or(0, |s| s.not_after_ms)
        }
        StatementKind::ExitNodeOffer => {
            st::decode_exit_node_offer(statement).map_or(0, |s| s.not_after_ms)
        }
        StatementKind::RelayEpochFloor => {
            st::decode_relay_epoch_floor(statement).map_or(0, |s| s.not_after_ms)
        }
        // A revocation and a pairing revocation are permanent by design; a
        // TunnelKeyBinding's window is checked by the peer that pins the key.
        StatementKind::RevocationStatement
        | StatementKind::PairingRevocation
        | StatementKind::TunnelKeyBinding => 0,
    }
}

/// Reads the delegation an `OwnerDelegation` **is**, and nothing else.
///
/// No wildcard arm, for the reason [`succession_of`] has none.
fn delegation_of(
    expected: StatementKind,
    statement: &twinvpn_crypto::cose::VerifiedStatement,
) -> Option<Delegation> {
    match expected {
        StatementKind::OwnerDelegation => {
            twinvpn_crypto::statements::decode_owner_delegation(statement)
                .ok()
                .map(|d| Delegation {
                    osk_id: d.osk_id,
                    osk_pub_cose: d.osk_pub_cose,
                    powers: d.powers,
                    anchor_version: d.anchor_version,
                    not_after_ms: d.not_after_ms,
                })
        }
        StatementKind::PairingAttestation
        | StatementKind::IdentitySuccession
        | StatementKind::PolicyBundle
        | StatementKind::RouteAdvertisement
        | StatementKind::ExitNodeOffer
        | StatementKind::RelayEpochFloor
        | StatementKind::RevocationStatement
        | StatementKind::PairingRevocation
        | StatementKind::TunnelKeyBinding => None,
    }
}

/// Reads the ceremony a `PairingAttestation` names, and nothing else.
///
/// No wildcard arm, for the reason [`succession_of`] has none.
fn pairing_id_of(
    expected: StatementKind,
    statement: &twinvpn_crypto::cose::VerifiedStatement,
) -> Option<[u8; 16]> {
    match expected {
        StatementKind::PairingAttestation => {
            twinvpn_crypto::statements::decode_pairing_attestation(statement)
                .ok()
                .map(|a| a.pairing_id)
        }
        StatementKind::IdentitySuccession
        | StatementKind::PolicyBundle
        | StatementKind::OwnerDelegation
        | StatementKind::RouteAdvertisement
        | StatementKind::ExitNodeOffer
        | StatementKind::RelayEpochFloor
        | StatementKind::RevocationStatement
        | StatementKind::PairingRevocation
        | StatementKind::TunnelKeyBinding => None,
    }
}

/// Reads the target a revocation **signed**, and nothing else.
///
/// # R-4
///
/// `revoke` took its target from `RevokeDeviceRequest.target_device_id` — a
/// wire field no signature covers. The Owner statement was verified and then
/// never opened, so an attacker who obtained *any* Owner-signed revocation
/// (they are distributed to every device by design) could re-wrap it naming a
/// different device and the service would revoke that device instead.
///
/// The CDDL puts `target_device_id` at label 2 and requires it in the `crit`
/// set, so a revocation that does not commit to its target is already
/// unverifiable. This reads the committed value; the handler compares.
///
/// No wildcard arm, for the reason [`succession_of`] has none.
fn revocation_of(
    expected: StatementKind,
    statement: &twinvpn_crypto::cose::VerifiedStatement,
) -> Option<Revocation> {
    match expected {
        // Both share the CDDL shape — see `StatementKind::as_crypto_kind`.
        StatementKind::RevocationStatement | StatementKind::PairingRevocation => {
            twinvpn_crypto::statements::decode_revocation_statement(statement)
                .ok()
                .map(|r| Revocation {
                    target_device_id: r.target_device_id,
                    target_identity_id: r.target_identity_id,
                    twinnet_id: r.twinnet_id,
                    reason_code: r.reason_code,
                })
        }
        StatementKind::PolicyBundle
        | StatementKind::PairingAttestation
        | StatementKind::IdentitySuccession
        | StatementKind::TunnelKeyBinding
        | StatementKind::RouteAdvertisement
        | StatementKind::ExitNodeOffer
        | StatementKind::RelayEpochFloor
        | StatementKind::OwnerDelegation => None,
    }
}

/// Reads the version a `PolicyBundle` **signed**, and nothing else.
///
/// # R-4
///
/// `put_policy` advanced the monotone floor from `PutPolicyRequest.bundle
/// .policy_version`, which no signature covers. Re-wrapping last year's signed
/// bundle with a higher wire version was therefore a **signed policy
/// rollback**; wrapping any of them with `u64::MAX` advanced the floor past
/// every version the Owner could ever sign again.
///
/// The CDDL requires `policy_version` in the `crit` set, so the signed value
/// always exists for a bundle that verified at all.
///
/// No wildcard arm, for the reason [`succession_of`] has none.
fn policy_of(
    expected: StatementKind,
    statement: &twinvpn_crypto::cose::VerifiedStatement,
) -> Option<PolicyClaims> {
    match expected {
        StatementKind::PolicyBundle => twinvpn_crypto::statements::decode_policy_bundle(statement)
            .ok()
            .map(|b| PolicyClaims {
                policy_version: b.policy_version,
                policy_id: b.policy_id,
                killswitch_floor: b.killswitch_floor,
            }),
        StatementKind::RevocationStatement
        | StatementKind::PairingRevocation
        | StatementKind::PairingAttestation
        | StatementKind::IdentitySuccession
        | StatementKind::TunnelKeyBinding
        | StatementKind::RouteAdvertisement
        | StatementKind::ExitNodeOffer
        | StatementKind::RelayEpochFloor
        | StatementKind::OwnerDelegation => None,
    }
}

/// Reads the successor an `IdentitySuccession` names, and nothing else.
///
/// The match has no wildcard arm on purpose: a future statement kind that also
/// carried a successor would have to be considered here rather than silently
/// reported as carrying none.
fn succession_of(
    expected: StatementKind,
    statement: &twinvpn_crypto::cose::VerifiedStatement,
) -> Option<Succession> {
    match expected {
        StatementKind::IdentitySuccession => {
            twinvpn_crypto::statements::decode_identity_succession(statement)
                .ok()
                .map(|s| Succession {
                    device_id: s.device_id,
                    old_identity_id: s.old_identity_id,
                    new_identity_id: s.new_identity_id,
                    generation: s.generation,
                })
        }
        StatementKind::PairingAttestation
        | StatementKind::PolicyBundle
        | StatementKind::OwnerDelegation
        | StatementKind::RouteAdvertisement
        | StatementKind::ExitNodeOffer
        | StatementKind::RelayEpochFloor
        | StatementKind::RevocationStatement
        | StatementKind::PairingRevocation
        | StatementKind::TunnelKeyBinding => None,
    }
}

/// Maps `twinvpn-crypto`'s failures onto this service's registered codes.
fn map_crypto_error(err: &twinvpn_crypto::CryptoError) -> VerifyFailure {
    use twinvpn_crypto::CryptoError as E;
    match err {
        E::NonCanonicalCbor { .. } => VerifyFailure::NonCanonical,
        E::UnknownCriticalField { .. } | E::MissingCriticalField { .. } => {
            VerifyFailure::UnknownCriticalField
        }
        E::StatementExpired { .. } => VerifyFailure::Expired,
        E::SignatureInvalid { .. } | E::MalformedCose { .. } | E::BindingInvalid { .. } => {
            VerifyFailure::BadSignature
        }
        // Everything else — an unsupported algorithm, an unusable key — is "this
        // signer cannot have authored this", which is what WrongAuthority says.
        _ => VerifyFailure::WrongAuthority,
    }
}

/// Lowercase hex, for the `signer_key_id` audit field. Never a secret: a `kid`
/// is a public identifier by construction.
fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    out
}

/// Verifies, then re-checks the authority table and the validity window.
///
/// A verifier could in principle return a `Verified` whose `authority` does not
/// match the kind's `required_authority`. This wrapper is the second check, so
/// the table is enforced by this crate and not only by whoever binds the port.
///
/// # Errors
///
/// [`ServiceError`] with the registered code for the failure.
pub fn admit(
    verifier: &dyn StatementVerifier,
    octets: &Verbatim,
    expected: StatementKind,
    now_ms: u64,
    signer: SignerKey<'_>,
) -> Result<Verified, ServiceError> {
    // The caller must present the key the TYPE requires. A `PolicyBundle`
    // offered against a device key never reaches the verifier at all — this is
    // the table enforced before any signature arithmetic, so a verifier bug
    // cannot make an Owner-only statement device-signable.
    if signer.authority() != expected.required_authority() {
        return Err(VerifyFailure::WrongAuthority.into_error());
    }
    let claim = verifier
        .verify(octets, expected, now_ms, signer)
        .map_err(VerifyFailure::into_error)?;
    if claim.kind != expected {
        return Err(VerifyFailure::TypeMismatch.into_error());
    }
    if claim.authority != expected.required_authority() {
        return Err(VerifyFailure::WrongAuthority.into_error());
    }
    if claim.not_after_ms != 0 && now_ms > claim.not_after_ms {
        return Err(VerifyFailure::Expired.into_error());
    }
    if now_ms < claim.not_before_ms {
        return Err(VerifyFailure::Expired.into_error());
    }
    check_power(&claim, expected, now_ms)?;
    Ok(claim)
}

/// **The delegation-chain check** — S-32, and the difference between "the
/// `Owner` chain signed this" and "a key carrying `REVOKE` signed this".
///
/// ADR-0007 O5 puts the `OwnerRootKey` offline behind a recovery phrase and does
/// routine work with per-device `OwnerSigningKey`s, each delegated a subset of
/// {`ENROLL`, `REVOKE`, `POLICY`, `DELEGATE`, `ADMINISTER`}. Without this check
/// every OSK carries every power: an admin phone delegated only `ENROLL` could
/// revoke every device in the `TwinNet` and publish a policy bundle. The
/// delegation says what the `Owner` actually granted, and this is where that is
/// enforced.
///
/// Two checks, and they are about different documents:
///
/// 1. **The signer's** delegation must carry the power the statement kind needs.
///    Skipped when the ORK itself signed — the root is unscoped by construction,
///    because it is the key every delegation chains to.
/// 2. **The statement's own** delegation, for the `OwnerDelegation` that is an
///    enrolment proof, must carry `ENROLL`. `RegisterDevice` presents a
///    delegation as its authorisation; a delegation granting only `POLICY` is
///    not an approval to join, however impeccably it is signed.
///
/// # Errors
///
/// `AUTH.CRED_EXPIRED` for a delegation past its own `not_after_ms` — checked
/// here, at use, because this process outlives the file it loaded.
/// `AUTH.UNEXPECTED_DELEGATION` carrying `osk_id` when the power is absent.
fn check_power(claim: &Verified, expected: StatementKind, now_ms: u64) -> Result<(), ServiceError> {
    let Some(required) = expected.required_power() else {
        // A device-authority statement. There is no OSK power to check, and
        // inventing one would be a check that always passes.
        return Ok(());
    };

    // 1. Whoever signed. `None` is the ORK: unscoped, deliberately.
    if let Some(signer) = claim.signer_delegation.as_ref() {
        require_power(signer, required, now_ms)?;
    }

    // 2. The enrolment proof's own grant.
    if expected == StatementKind::OwnerDelegation {
        let proof = claim
            .delegation
            .as_ref()
            // Fail-closed: a proof whose grant cannot be read is not a proof.
            // `AUTH.BINDING_INVALID` and not a power failure, because what is
            // wrong is the document rather than its scope.
            .ok_or_else(|| codes::bare(codes::SIGNATURE_INVALID))?;
        require_power(proof, required, now_ms)?;
    }
    Ok(())
}

/// One delegation, one power.
fn require_power(
    delegation: &Delegation,
    required: twinvpn_crypto::statements::OskPower,
    now_ms: u64,
) -> Result<(), ServiceError> {
    if delegation.not_after_ms != 0 && now_ms > delegation.not_after_ms {
        return Err(codes::bare(twinvpn_types::codes::AUTH_CRED_EXPIRED));
    }
    if !delegation.has(required) {
        // `osk_id` is the evidence field the registry declares for this code,
        // and it is a public identifier: an operator needs to know WHICH admin
        // key was asked to do something it was not delegated.
        return Err(ServiceError::new(
            twinvpn_types::codes::AUTH_UNEXPECTED_DELEGATION,
            crate::COMPONENT,
        )
        .evidence(
            "osk_id",
            twinvpn_types::EvidenceValue::Text(delegation.osk_id.clone()),
        )
        .build());
    }
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub mod testing {
    //! A scripted verifier, for tests. **Never shipped**, exactly as
    //! `twinvpn-cp-client`'s `testing` and `twinvpn-env`'s `test-support` are
    //! never shipped.

    use super::{
        SignerKey, SigningAuthority, StatementKind, StatementVerifier, Verified, VerifyFailure,
    };
    use twinvpn_service_common::forward::Verbatim;

    /// A verifier that accepts anything, attributing it to a chosen authority.
    ///
    /// Its whole purpose is to let a test exercise the *server's* authority
    /// table without a cryptographic implementation: point it at
    /// [`SigningAuthority::Device`] and a `PolicyBundle` must still be refused,
    /// because refusing it is this crate's rule, not the verifier's.
    #[derive(Debug, Clone)]
    pub struct ScriptedVerifier {
        /// What every verification will claim to have chained to.
        pub authority: SigningAuthority,
        /// What every verification will claim the payload's type was.
        pub kind: Option<StatementKind>,
        /// The window every verified statement will carry.
        pub not_after_ms: u64,
        /// The ceremony a `PairingAttestation` will be reported as naming.
        pub pairing_id: Option<[u8; 16]>,
        /// The delegation the signer will be reported as holding. `None` is the
        /// ORK: unscoped, which is what an `owner()` double means by default.
        pub signer_delegation: Option<super::Delegation>,
        /// The delegation an `OwnerDelegation` will be reported as being.
        pub delegation: Option<super::Delegation>,
        /// The successor an `IdentitySuccession` will be reported as naming.
        pub succession: Option<super::Succession>,
        /// The target a revocation will be reported as having **signed** (R-4).
        /// `None` means "the payload did not decode", which every handler must
        /// refuse rather than fall back to the wire's target.
        pub revocation: Option<super::Revocation>,
        /// The version a `PolicyBundle` will be reported as having **signed**.
        pub policy: Option<super::PolicyClaims>,
    }

    impl ScriptedVerifier {
        /// A verifier that attributes everything to the `Owner`.
        #[must_use]
        pub const fn owner() -> Self {
            Self {
                authority: SigningAuthority::Owner,
                kind: None,
                not_after_ms: 0,
                pairing_id: None,
                signer_delegation: None,
                delegation: None,
                succession: None,
                revocation: None,
                policy: None,
            }
        }

        /// A verifier that attributes everything to a device.
        #[must_use]
        pub const fn device() -> Self {
            Self {
                authority: SigningAuthority::Device,
                kind: None,
                not_after_ms: 0,
                pairing_id: None,
                signer_delegation: None,
                delegation: None,
                succession: None,
                revocation: None,
                policy: None,
            }
        }

        /// Forces the payload type it reports, to exercise the mismatch path.
        #[must_use]
        pub const fn claiming(mut self, kind: StatementKind) -> Self {
            self.kind = Some(kind);
            self
        }

        /// Gives every statement a bounded lifetime.
        #[must_use]
        pub const fn expiring_at(mut self, not_after_ms: u64) -> Self {
            self.not_after_ms = not_after_ms;
            self
        }

        /// Reports the ceremony a `PairingAttestation` names.
        #[must_use]
        pub const fn attesting_to(mut self, pairing_id: [u8; 16]) -> Self {
            self.pairing_id = Some(pairing_id);
            self
        }

        /// Reports the delegation the signer holds — an OSK rather than the ORK.
        #[must_use]
        pub fn held_by(mut self, delegation: super::Delegation) -> Self {
            self.signer_delegation = Some(delegation);
            self
        }

        /// Reports the delegation an `OwnerDelegation` statement carries.
        #[must_use]
        pub fn granting(mut self, delegation: super::Delegation) -> Self {
            self.delegation = Some(delegation);
            self
        }

        /// Reports the succession an `IdentitySuccession` names.
        #[must_use]
        pub const fn succeeding_to(mut self, succession: super::Succession) -> Self {
            self.succession = Some(succession);
            self
        }

        /// Reports the target a revocation **signed** (R-4).
        #[must_use]
        pub fn revoking(mut self, revocation: super::Revocation) -> Self {
            self.revocation = Some(revocation);
            self
        }

        /// Reports the version a `PolicyBundle` **signed** (R-4).
        #[must_use]
        pub fn publishing(mut self, policy: super::PolicyClaims) -> Self {
            self.policy = Some(policy);
            self
        }
    }

    impl StatementVerifier for ScriptedVerifier {
        fn verify(
            &self,
            octets: &Verbatim,
            expected: StatementKind,
            _now_ms: u64,
            _signer: SignerKey<'_>,
        ) -> Result<Verified, VerifyFailure> {
            if octets.is_empty() {
                return Err(VerifyFailure::BadSignature);
            }
            Ok(Verified {
                kind: self.kind.unwrap_or(expected),
                // Deliberately the SCRIPTED authority and not the signer's: this
                // double is how a test drives `admit`'s own authority re-check,
                // which must hold even against a verifier that lies.
                authority: self.authority,
                signer_key_id: "scripted".to_owned(),
                octets: octets.clone(),
                not_before_ms: 0,
                not_after_ms: self.not_after_ms,
                pairing_id: self.pairing_id,
                signer_delegation: self.signer_delegation.clone(),
                delegation: self.delegation.clone(),
                succession: self.succession,
                revocation: self.revocation.clone(),
                policy: self.policy.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::ScriptedVerifier;
    use super::{
        admit, opaque_statement, CryptoVerifier, RefuseUnverifiable, SignerKey, SigningAuthority,
        StatementKind, StatementVerifier,
    };

    fn octets() -> twinvpn_service_common::forward::Verbatim {
        // Deliberately NOT protobuf. A real COSE_Sign1 is CBOR, and the whole
        // point of the opaque framing is that it accepts one.
        opaque_statement(bytes::Bytes::from_static(b"\xd2\x84\x43cose")).expect("within cap")
    }

    /// A deterministic ES256 device identity, from `twinvpn-crypto`'s own test
    /// kit. CD-I2 covers dev-dependencies, so a signature in a test comes from
    /// the audited crate rather than from a `p256` this crate names itself.
    fn fixture(seed: &[u8]) -> twinvpn_crypto::testkit::FixtureIdentity {
        twinvpn_crypto::testkit::FixtureIdentity::from_seed(seed)
    }

    /// A real COSE_Sign1 over a canonical payload, as wire octets.
    fn signed(
        id: &twinvpn_crypto::testkit::FixtureIdentity,
    ) -> twinvpn_service_common::forward::Verbatim {
        use twinvpn_crypto::emit::Item;
        let payload = Item::Map(vec![(Item::Uint(1), Item::Uint(7))]);
        opaque_statement(bytes::Bytes::from(id.sign(&payload))).expect("within cap")
    }

    /// A real ORK-signed `OwnerDelegation`, as wire octets.
    ///
    /// Built to `twinvpn-crypto`'s own `DELEGATION_SCHEMA`: labels 1..6 plus the
    /// `crit` array at 7, which must name `powers`. Signed by `root` so the
    /// chain this test exercises is the real one — an ORK signature over a
    /// delegation naming an OSK — and not a double.
    fn ork_signed_delegation(
        root: &twinvpn_crypto::testkit::FixtureIdentity,
        signing: &twinvpn_crypto::testkit::FixtureIdentity,
        osk_id: &str,
        powers: &[&str],
        anchor_version: u64,
        not_after_ms: u64,
    ) -> Vec<u8> {
        use twinvpn_crypto::emit::Item;
        let payload = Item::Map(vec![
            (Item::Uint(1), Item::Text("twn_test".to_owned())),
            (Item::Uint(2), Item::Text(osk_id.to_owned())),
            (Item::Uint(3), Item::Bytes(signing.cose_key())),
            (
                Item::Uint(4),
                Item::Array(powers.iter().map(|p| Item::Text((*p).to_owned())).collect()),
            ),
            (Item::Uint(5), Item::Uint(anchor_version)),
            (Item::Uint(6), Item::Uint(not_after_ms)),
            (
                Item::Uint(7),
                Item::Array(vec![Item::Text("powers".to_owned())]),
            ),
        ]);
        root.sign(&payload)
    }

    #[test]
    fn a_real_delegation_chain_scopes_a_real_signature() {
        // The whole point, with no doubles anywhere: an ORK signs a delegation
        // granting an OSK only REVOKE; the OSK then signs a statement. The
        // REVOKE-needing kind is admitted and the POLICY-needing kind is not,
        // and both answers come from the same loaded chain.
        let root = fixture(b"root");
        let signing = fixture(b"osk-revoke-only");
        let delegation = ork_signed_delegation(&root, &signing, "osk-revoke", &["REVOKE"], 1, 0);

        let verifier = CryptoVerifier::with_delegations(&[root.cose_key()], &[delegation], 1)
            .expect("the chain loads");
        assert_eq!(verifier.delegations().len(), 1);
        assert_eq!(verifier.delegations()[0].osk_id, "osk-revoke");

        let statement = signed(&signing);
        admit(
            &verifier,
            &statement,
            StatementKind::RevocationStatement,
            1_000,
            SignerKey::OwnerAnchors,
        )
        .expect("the OSK carries REVOKE");

        let err = admit(
            &verifier,
            &statement,
            StatementKind::PolicyBundle,
            1_000,
            SignerKey::OwnerAnchors,
        )
        .expect_err("it does not carry POLICY");
        assert_eq!(err.code().as_str(), "AUTH.UNEXPECTED_DELEGATION");
    }

    /// R-12: the validity window, exercised against the **shipped** verifier.
    ///
    /// Every existing nbf/exp test drives [`ScriptedVerifier`], which is
    /// `#[cfg(test)]` — so the window was tested thoroughly against an object
    /// that never ships. These two drive `CryptoVerifier` through a real ORK →
    /// OSK chain and real ES256 signatures.
    #[test]
    fn the_shipped_verifier_reads_the_signed_expiry_not_the_callers_word() {
        let root = fixture(b"root");
        let signing = fixture(b"osk-policy");
        // The DELEGATION expiry is the one the CDDL declares, at label 6.
        let delegation =
            ork_signed_delegation(&root, &signing, "osk-policy", &["POLICY"], 1, 5_000);
        let verifier = CryptoVerifier::with_delegations(&[root.cose_key()], &[delegation], 1)
            .expect("the chain loads");
        let statement = signed(&signing);

        assert!(
            admit(
                &verifier,
                &statement,
                StatementKind::PolicyBundle,
                4_999,
                SignerKey::OwnerAnchors,
            )
            .is_ok(),
            "inside the signed window"
        );
        let err = admit(
            &verifier,
            &statement,
            StatementKind::PolicyBundle,
            5_001,
            SignerKey::OwnerAnchors,
        )
        .expect_err("past the signed window");
        assert_eq!(err.code().as_str(), "AUTH.CRED_EXPIRED");
    }

    #[test]
    fn the_shipped_verifier_reports_a_not_before_for_every_kind_it_admits() {
        // `signed_statements.cddl` declares `not_before_ms` on exactly two
        // statements — `device-identity-record` (9) and
        // `relay-capability-token` (5) — and this service admits neither. So
        // the honest answer for all ten is 0, "valid from the beginning of
        // time", and `admit`'s `now_ms < not_before_ms` gate is live rather
        // than dead: at `now_ms == 0` it is evaluated and passes.
        //
        // `not_before_of`'s match carries no wildcard arm, so a kind that later
        // gains an nbf cannot reach this assertion without someone deciding to
        // read it.
        let root = fixture(b"root");
        let signing = fixture(b"osk-all");
        let delegation = ork_signed_delegation(
            &root,
            &signing,
            "osk-all",
            &["ENROLL", "REVOKE", "POLICY", "DELEGATE", "ADMINISTER"],
            1,
            0,
        );
        let verifier = CryptoVerifier::with_delegations(&[root.cose_key()], &[delegation], 1)
            .expect("the chain loads");
        let statement = signed(&signing);

        for kind in [
            StatementKind::RevocationStatement,
            StatementKind::PolicyBundle,
            StatementKind::RelayEpochFloor,
            StatementKind::PairingRevocation,
        ] {
            let claim = verifier
                .verify(&statement, kind, 0, SignerKey::OwnerAnchors)
                .expect("the OSK signed it");
            assert_eq!(
                claim.not_before_ms,
                0,
                "{} declares no not_before_ms in the frozen CDDL",
                kind.as_str()
            );
            assert!(
                admit(&verifier, &statement, kind, 0, SignerKey::OwnerAnchors).is_ok(),
                "{} must be admissible at t=0",
                kind.as_str()
            );
        }
    }

    #[test]
    fn an_undelegated_key_is_not_the_owner_however_well_it_signs() {
        // The property the whole file rests on: a signature is not an
        // authority. A key nobody delegated to verifies against nothing.
        let root = fixture(b"root");
        let stranger = fixture(b"not-delegated");
        let verifier = CryptoVerifier::with_delegations(&[root.cose_key()], &[], 0).expect("loads");
        let err = admit(
            &verifier,
            &signed(&stranger),
            StatementKind::RevocationStatement,
            1_000,
            SignerKey::OwnerAnchors,
        )
        .expect_err("refused");
        assert_eq!(err.code().as_str(), "AUTH.BINDING_INVALID");
    }

    #[test]
    fn a_delegation_the_anchor_did_not_sign_fails_startup() {
        // Loaded once, at startup, against the pinned root. An impostor
        // delegation must not become a per-request refusal nobody sees until an
        // operator tries to revoke a stolen laptop.
        let root = fixture(b"root");
        let impostor = fixture(b"impostor-root");
        let signing = fixture(b"signing");
        let forged = ork_signed_delegation(&impostor, &signing, "osk-forged", &["REVOKE"], 1, 0);
        let err = CryptoVerifier::with_delegations(&[root.cose_key()], &[forged], 0)
            .expect_err("the pinned root did not sign it");
        assert_eq!(err.code().as_str(), "AUTH.BINDING_INVALID");
    }

    #[test]
    fn a_delegation_from_a_superseded_anchor_fails_startup() {
        // S-32: "a delegation issued under an older anchor does not survive an
        // anchor advance by default." A mixed set means half a rotation landed.
        let root = fixture(b"root");
        let signing = fixture(b"signing");
        let stale = ork_signed_delegation(&root, &signing, "osk-stale", &["REVOKE"], 1, 0);
        let err = CryptoVerifier::with_delegations(&[root.cose_key()], &[stale], 2)
            .expect_err("anchor version 1 is not 2");
        assert_eq!(err.code().as_str(), "AUTH.ANCHOR_VERSION_UNSUPPORTED");
    }

    #[test]
    fn a_delegation_with_no_anchor_to_chain_to_is_refused() {
        // Otherwise the delegation file would itself be the trust root.
        let root = fixture(b"root");
        let signing = fixture(b"signing");
        let orphan = ork_signed_delegation(&root, &signing, "signing", &["REVOKE"], 1, 0);
        let err =
            CryptoVerifier::with_delegations(&[], &[orphan], 0).expect_err("nothing to chain to");
        assert_eq!(err.code().as_str(), "AUTH.ANCHOR_VERSION_UNSUPPORTED");
    }

    #[test]
    fn every_owner_statement_kind_names_the_power_it_needs() {
        // No Owner-authority kind may be power-less: one that was would be
        // admitted on the signature alone, which is the gap this table closes.
        use twinvpn_crypto::statements::OskPower as P;
        for (kind, expected) in [
            (StatementKind::RevocationStatement, Some(P::Revoke)),
            (StatementKind::PairingRevocation, Some(P::Revoke)),
            (StatementKind::PolicyBundle, Some(P::Policy)),
            (StatementKind::OwnerDelegation, Some(P::Enroll)),
            (StatementKind::RelayEpochFloor, Some(P::Administer)),
        ] {
            assert_eq!(kind.required_power(), expected, "{}", kind.as_str());
            assert_eq!(kind.required_authority(), SigningAuthority::Owner);
        }
        for kind in [
            StatementKind::PairingAttestation,
            StatementKind::IdentitySuccession,
            StatementKind::TunnelKeyBinding,
            StatementKind::RouteAdvertisement,
            StatementKind::ExitNodeOffer,
        ] {
            assert!(kind.required_power().is_none(), "{}", kind.as_str());
            assert_eq!(kind.required_authority(), SigningAuthority::Device);
        }
    }

    #[test]
    fn an_unbound_verifier_admits_nothing() {
        // Fail closed. If this test ever needs changing, read the module docs
        // first: a permissive default here is a control plane that can grant
        // authority.
        for kind in [
            StatementKind::RevocationStatement,
            StatementKind::PolicyBundle,
        ] {
            let err = admit(
                &RefuseUnverifiable,
                &octets(),
                kind,
                0,
                SignerKey::OwnerAnchors,
            )
            .expect_err("refuses");
            assert_eq!(err.code().as_str(), "AUTH.KEY_UNAVAILABLE");
        }
        let err = admit(
            &RefuseUnverifiable,
            &octets(),
            StatementKind::RouteAdvertisement,
            0,
            SignerKey::Device(b"key"),
        )
        .expect_err("refuses");
        assert_eq!(err.code().as_str(), "AUTH.KEY_UNAVAILABLE");
    }

    #[test]
    fn the_real_verifier_admits_no_owner_statement_without_an_anchor() {
        // The shipped posture: a deployment with no pinned OwnerTrustAnchor can
        // enrol and stream, and cannot revoke or author policy. Refusing is the
        // correct answer, not a gap to paper over.
        let v = CryptoVerifier::new(&[]).expect("an empty anchor set loads");
        assert!(!v.has_owner_anchor());
        for kind in [
            StatementKind::RevocationStatement,
            StatementKind::PolicyBundle,
            StatementKind::RelayEpochFloor,
            StatementKind::PairingRevocation,
        ] {
            let err = admit(&v, &octets(), kind, 0, SignerKey::OwnerAnchors)
                .expect_err("no anchor, no admission");
            assert_eq!(err.code().as_str(), "AUTH.KEY_UNAVAILABLE");
        }
    }

    #[test]
    fn the_real_verifier_refuses_a_statement_that_is_not_a_cose_sign1() {
        // Verification is over the RECEIVED OCTETS and nothing is normalised
        // first: `\xd2\x84\x43cose` is CBOR-shaped and is not a valid signed
        // statement, so it is refused rather than repaired.
        let v = CryptoVerifier::new(&[]).expect("loads");
        let err = admit(
            &v,
            &octets(),
            StatementKind::RouteAdvertisement,
            0,
            SignerKey::Device(&fixture(b"a").cose_key()),
        )
        .expect_err("not a statement");
        assert!(
            matches!(
                err.code().as_str(),
                "AUTH.BINDING_INVALID" | "PROTO.NON_CANONICAL_CBOR"
            ),
            "unexpected code {}",
            err.code().as_str()
        );
    }

    #[test]
    fn a_real_signature_verifies_and_the_wrong_device_key_does_not() {
        // End to end through `twinvpn-crypto`: a genuine COSE_Sign1 over the
        // received octets, verified against the key this service recorded for
        // the signer. This is the property every device-authority statement
        // rests on, and it is exercised rather than asserted.
        let v = CryptoVerifier::new(&[]).expect("loads");
        let alice = fixture(b"alice");
        let mallory = fixture(b"mallory");
        let statement = signed(&alice);

        let verified = admit(
            &v,
            &statement,
            StatementKind::RouteAdvertisement,
            0,
            SignerKey::Device(&alice.cose_key()),
        )
        .expect("alice signed it");
        assert_eq!(verified.authority, SigningAuthority::Device);
        assert_eq!(
            verified.octets.as_bytes(),
            statement.as_bytes(),
            "the verified octets are the RECEIVED octets, never a re-encoding"
        );

        // The same statement against a different device's key. This is the
        // check that stops one device advertising under another's name.
        let err = admit(
            &v,
            &statement,
            StatementKind::RouteAdvertisement,
            0,
            SignerKey::Device(&mallory.cose_key()),
        )
        .expect_err("mallory did not sign it");
        assert_eq!(err.code().as_str(), "AUTH.BINDING_INVALID");
    }

    #[test]
    fn a_flipped_byte_breaks_the_signature() {
        // Verification is over the octets as they arrived: change one and it
        // fails, which is what "MUST NOT re-serialize before verifying" buys.
        let v = CryptoVerifier::new(&[]).expect("loads");
        let alice = fixture(b"alice");
        let mut octets = alice.sign(&twinvpn_crypto::emit::Item::Map(vec![(
            twinvpn_crypto::emit::Item::Uint(1),
            twinvpn_crypto::emit::Item::Uint(7),
        )]));
        let last = octets.len() - 1;
        octets[last] ^= 0x01;
        let tampered = opaque_statement(bytes::Bytes::from(octets)).expect("within cap");
        let err = admit(
            &v,
            &tampered,
            StatementKind::RouteAdvertisement,
            0,
            SignerKey::Device(&alice.cose_key()),
        )
        .expect_err("tampered");
        assert_eq!(err.code().as_str(), "AUTH.BINDING_INVALID");
    }

    #[test]
    fn an_owner_signed_statement_verifies_against_the_pinned_anchor() {
        let owner_key = fixture(b"owner");
        let v = CryptoVerifier::new(&[owner_key.cose_key()]).expect("loads");
        assert!(v.has_owner_anchor());
        let statement = signed(&owner_key);
        let verified = admit(
            &v,
            &statement,
            StatementKind::RevocationStatement,
            0,
            SignerKey::OwnerAnchors,
        )
        .expect("the pinned anchor signed it");
        assert_eq!(verified.authority, SigningAuthority::Owner);

        // A statement signed by someone who is NOT the anchor is refused — this
        // is what stops a compromised control plane minting a revocation.
        let impostor = signed(&fixture(b"impostor"));
        let err = admit(
            &v,
            &impostor,
            StatementKind::RevocationStatement,
            0,
            SignerKey::OwnerAnchors,
        )
        .expect_err("not the Owner");
        assert_eq!(err.code().as_str(), "AUTH.BINDING_INVALID");
    }

    #[test]
    fn the_real_verifier_refuses_a_device_key_it_cannot_parse() {
        let v = CryptoVerifier::new(&[]).expect("loads");
        let err = admit(
            &v,
            &octets(),
            StatementKind::RouteAdvertisement,
            0,
            SignerKey::Device(b"not a COSE_Key"),
        )
        .expect_err("unusable key");
        assert_eq!(err.code().as_str(), "AUTH.UNEXPECTED_DELEGATION");
    }

    #[test]
    fn an_anchor_set_that_does_not_parse_fails_at_construction() {
        // Startup fails rather than running with a partially-loaded anchor set:
        // a partial set silently refuses statements a correct one would admit,
        // which reads as an outage rather than as a misconfiguration.
        let err = CryptoVerifier::new(&[b"not a COSE_Key".to_vec()]).expect_err("refuses");
        assert_eq!(err.code().as_str(), "AUTH.ANCHOR_VERSION_UNSUPPORTED");
    }

    #[test]
    fn coordination_cannot_author_policy_and_the_owner_cannot_mint_a_route() {
        // The two rows protocol.md §7 calls load-bearing, asserted at the SERVER.
        assert_eq!(
            StatementKind::PolicyBundle.required_authority(),
            SigningAuthority::Owner
        );
        assert_eq!(
            StatementKind::RouteAdvertisement.required_authority(),
            SigningAuthority::Device
        );
        assert_eq!(
            StatementKind::RevocationStatement.required_authority(),
            SigningAuthority::Owner
        );

        // A caller offering a POLICY BUNDLE against a device key never reaches
        // the verifier: `admit` checks the table first, so no verifier bug can
        // make an Owner-only statement device-signable.
        let err = admit(
            &ScriptedVerifier::device(),
            &octets(),
            StatementKind::PolicyBundle,
            0,
            SignerKey::Device(b"key"),
        )
        .expect_err("wrong authority at the caller");
        assert_eq!(err.code().as_str(), "AUTH.UNEXPECTED_DELEGATION");

        // And a verifier that LIES — presented with the device key the table
        // requires, but claiming the Owner chain signed — is caught afterwards.
        // That is what makes this crate's rule this crate's, not the binding's.
        let err = admit(
            &ScriptedVerifier::owner(),
            &octets(),
            StatementKind::RouteAdvertisement,
            0,
            SignerKey::Device(b"key"),
        )
        .expect_err("wrong authority at the verifier");
        assert_eq!(err.code().as_str(), "AUTH.UNEXPECTED_DELEGATION");
    }

    #[test]
    fn the_type_inside_the_payload_wins_over_the_callers_expectation() {
        // identity.proto: `statement_type` is "A HINT for dispatch only … An
        // attacker controls this value."
        let v = ScriptedVerifier::owner().claiming(StatementKind::RelayEpochFloor);
        let err = admit(
            &v,
            &octets(),
            StatementKind::RevocationStatement,
            0,
            SignerKey::OwnerAnchors,
        )
        .expect_err("type mismatch");
        assert_eq!(err.code().as_str(), "AUTH.BINDING_INVALID");
    }

    #[test]
    fn an_expired_statement_is_refused() {
        let v = ScriptedVerifier::owner().expiring_at(1_000);
        assert!(admit(
            &v,
            &octets(),
            StatementKind::RevocationStatement,
            999,
            SignerKey::OwnerAnchors
        )
        .is_ok());
        let err = admit(
            &v,
            &octets(),
            StatementKind::RevocationStatement,
            1_001,
            SignerKey::OwnerAnchors,
        )
        .expect_err("expired");
        assert_eq!(err.code().as_str(), "AUTH.STATEMENT_EXPIRED");
    }

    #[test]
    fn a_revocation_has_no_expiry_because_denials_are_permanent() {
        // ADR-0009 §11.4: "denials are monotone accumulations, not leases." A
        // revocation that expired would un-revoke a stolen device by doing
        // nothing at all, so the CDDL declares no `not_after_ms` and this
        // service reads none.
        for kind in [
            StatementKind::RevocationStatement,
            StatementKind::PairingRevocation,
        ] {
            let v = ScriptedVerifier::owner();
            assert!(
                admit(&v, &octets(), kind, u64::MAX, SignerKey::OwnerAnchors).is_ok(),
                "{} must not expire",
                kind.as_str()
            );
        }
    }

    #[test]
    fn every_statement_kind_maps_to_a_crypto_kind() {
        // A total match, so a statement type added here without a crypto
        // counterpart is a compile error rather than a verification that
        // silently checks the wrong CDDL shape.
        for kind in [
            StatementKind::RevocationStatement,
            StatementKind::PolicyBundle,
            StatementKind::PairingAttestation,
            StatementKind::IdentitySuccession,
            StatementKind::TunnelKeyBinding,
            StatementKind::RouteAdvertisement,
            StatementKind::ExitNodeOffer,
            StatementKind::RelayEpochFloor,
            StatementKind::PairingRevocation,
            StatementKind::OwnerDelegation,
        ] {
            let _ = kind.as_crypto_kind();
        }
        assert_eq!(
            StatementKind::PolicyBundle.as_crypto_kind(),
            twinvpn_crypto::StatementKind::PolicyBundle
        );
        assert_eq!(
            StatementKind::RouteAdvertisement.as_crypto_kind(),
            twinvpn_crypto::StatementKind::RouteAdvertisement
        );
    }

    #[test]
    fn the_signer_key_names_the_authority_it_establishes() {
        assert_eq!(SignerKey::OwnerAnchors.authority(), SigningAuthority::Owner);
        assert_eq!(
            SignerKey::Device(b"k").authority(),
            SigningAuthority::Device
        );
    }

    #[test]
    fn identity_succession_is_the_only_dual_signed_statement() {
        let dual: Vec<&str> = [
            StatementKind::RevocationStatement,
            StatementKind::PolicyBundle,
            StatementKind::PairingAttestation,
            StatementKind::IdentitySuccession,
            StatementKind::TunnelKeyBinding,
            StatementKind::RouteAdvertisement,
            StatementKind::ExitNodeOffer,
            StatementKind::RelayEpochFloor,
            StatementKind::PairingRevocation,
            StatementKind::OwnerDelegation,
        ]
        .into_iter()
        .filter(|k| k.is_dual_signed())
        .map(StatementKind::as_str)
        .collect();
        assert_eq!(dual, vec!["identity_succession"]);
    }
}
