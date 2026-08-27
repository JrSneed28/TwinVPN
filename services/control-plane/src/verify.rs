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
//! # Fail closed
//!
//! [`RefuseUnverifiable`] is the verifier this build ships. It admits **nothing**
//! and answers `AUTH.KEY_UNAVAILABLE`. That is deliberate and is not a stub with
//! a friendly default: a control plane that admitted an unverifiable
//! `RevocationStatement` would be granting authority it does not have, and a
//! design in which a compromised control plane could grant authority is a defect
//! rather than a tradeoff. Binding a real verifier is an integration item and is
//! stated as one in `README.md` §7.
//!
//! Note what the fail-closed default does **not** break: `RegisterDevice`,
//! `UpdateDeviceMetadata`, `DiscoverPeers`, `PublishPresence`, `SubscribeEvents`
//! and `GetStateDocument` carry no statement this service must verify, so a
//! deployment with no anchor still enrols, discovers and streams. It cannot
//! revoke, cannot author policy and cannot warehouse an advertisement — which is
//! the correct set of things to lose.

use bytes::Bytes;
use twinvpn_service_common::transport::check_declared_length;
use twinvpn_service_common::{Channel, Reject, ServiceError};

use crate::codes;

/// The exact octets of a COSE_Sign1 statement, as they arrived.
///
/// # Why this is not [`twinvpn_service_common::forward::Verbatim`]
///
/// `Verbatim::from_received` applies **`twinvpn_schema::depth::check`**, which
/// walks the *protobuf* wire format. That is right for a forwarded protobuf
/// message and wrong for a signed statement: `identity.proto` says a
/// `SignedStatement` is "opaque COSE_Sign1 octets" — deterministic CBOR inside
/// COSE — so a real statement is not protobuf and the depth scan rejects it as
/// `PROTO.UNPARSEABLE_ENVELOPE`. Wrapping COSE in `Verbatim` would refuse
/// exactly the payloads ADR-0003 §11 B2 requires to be forwarded verbatim.
///
/// So this type carries the same discipline — a byte cap applied before the
/// bytes are retained, no re-encode, no `Debug` that renders the content — over
/// a payload whose format this service is not entitled to interpret.
/// **Reported to `twinvpn-service-common`'s owner** as a gap in `forward`; see
/// `README.md` §8.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedOctets {
    bytes: Bytes,
}

impl SignedOctets {
    /// Validates the length and retains the octets.
    ///
    /// # Errors
    ///
    /// [`Reject::SizeExceeded`] past the C1 envelope cap. The statement travels
    /// inside a C1 message, so the envelope cap is its bound; a per-statement
    /// cap would be a second bound that could disagree with the first.
    pub fn from_received(bytes: Bytes) -> Result<Self, Reject> {
        check_declared_length(bytes.len(), Channel::ControlAndTelemetry)?;
        Ok(Self { bytes })
    }

    /// The octets, unchanged. **The only thing that may be forwarded.**
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the statement is empty, which is never a valid COSE_Sign1.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Debug for SignedOctets {
    /// A length only. A signed statement can carry an `EpochSeed` seal and a
    /// `PairingAttestation`; rendering it would be the capture ADR-0015 O-12
    /// forbids.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SignedOctets({} B, <not rendered>)", self.bytes.len())
    }
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
    pub octets: SignedOctets,
    /// `not_before_ms` from the signed payload.
    pub not_before_ms: u64,
    /// `not_after_ms` from the signed payload.
    pub not_after_ms: u64,
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

/// Signature verification, as this service needs it.
///
/// **This is an integration item.** ADR-0018 CD-I2 and finding W-12 put the
/// cryptographic implementation in `twinvpn-crypto`, which is a `core/` crate
/// this artifact does not link. An implementation MUST verify over the received
/// octets, MUST NOT re-serialize, MUST reject non-canonical CBOR rather than
/// normalize it, MUST reject an unrecognized `crit` member, and MUST return the
/// type it found *inside* the signed payload rather than the wire's hint.
pub trait StatementVerifier: Send + Sync {
    /// Verifies one COSE_Sign1 statement.
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
        octets: &SignedOctets,
        expected: StatementKind,
        now_ms: u64,
    ) -> Result<Verified, VerifyFailure>;
}

/// The verifier this build ships: it admits nothing.
///
/// See the module docs. This is fail-closed by design, not an unfinished stub —
/// `an_unbound_verifier_admits_nothing` asserts it, so a future change that
/// makes it permissive breaks a test whose name says what was lost.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefuseUnverifiable;

impl StatementVerifier for RefuseUnverifiable {
    fn verify(
        &self,
        _octets: &SignedOctets,
        _expected: StatementKind,
        _now_ms: u64,
    ) -> Result<Verified, VerifyFailure> {
        Err(VerifyFailure::NoAnchor)
    }
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
    octets: &SignedOctets,
    expected: StatementKind,
    now_ms: u64,
) -> Result<Verified, ServiceError> {
    let claim = verifier
        .verify(octets, expected, now_ms)
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
    Ok(claim)
}

#[cfg(any(test, feature = "test-support"))]
pub mod testing {
    //! A scripted verifier, for tests. **Never shipped**, exactly as
    //! `twinvpn-cp-client`'s `testing` and `twinvpn-env`'s `test-support` are
    //! never shipped.

    use super::{
        SignedOctets, SigningAuthority, StatementKind, StatementVerifier, Verified, VerifyFailure,
    };

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
    }

    impl ScriptedVerifier {
        /// A verifier that attributes everything to the `Owner`.
        #[must_use]
        pub const fn owner() -> Self {
            Self {
                authority: SigningAuthority::Owner,
                kind: None,
                not_after_ms: 0,
            }
        }

        /// A verifier that attributes everything to a device.
        #[must_use]
        pub const fn device() -> Self {
            Self {
                authority: SigningAuthority::Device,
                kind: None,
                not_after_ms: 0,
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
    }

    impl StatementVerifier for ScriptedVerifier {
        fn verify(
            &self,
            octets: &SignedOctets,
            expected: StatementKind,
            _now_ms: u64,
        ) -> Result<Verified, VerifyFailure> {
            if octets.is_empty() {
                return Err(VerifyFailure::BadSignature);
            }
            Ok(Verified {
                kind: self.kind.unwrap_or(expected),
                authority: self.authority,
                signer_key_id: "scripted".to_owned(),
                octets: octets.clone(),
                not_before_ms: 0,
                not_after_ms: self.not_after_ms,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::ScriptedVerifier;
    use super::{admit, RefuseUnverifiable, SignedOctets, SigningAuthority, StatementKind};

    fn octets() -> SignedOctets {
        // Deliberately NOT protobuf: a real COSE_Sign1 is CBOR, and the point of
        // SignedOctets is that it accepts one.
        SignedOctets::from_received(bytes::Bytes::from_static(b"\xd2\x84\x43cose"))
            .expect("within cap")
    }

    #[test]
    fn an_unbound_verifier_admits_nothing() {
        // Fail closed. If this test ever needs changing, read the module docs
        // first: a permissive default here is a control plane that can grant
        // authority.
        for kind in [
            StatementKind::RevocationStatement,
            StatementKind::PolicyBundle,
            StatementKind::RouteAdvertisement,
        ] {
            let err = admit(&RefuseUnverifiable, &octets(), kind, 0).expect_err("refuses");
            assert_eq!(err.code().as_str(), "AUTH.KEY_UNAVAILABLE");
        }
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

        // A policy bundle that verified against a DEVICE key is not a policy
        // bundle, however good the signature was.
        let err = admit(
            &ScriptedVerifier::device(),
            &octets(),
            StatementKind::PolicyBundle,
            0,
        )
        .expect_err("wrong authority");
        assert_eq!(err.code().as_str(), "AUTH.UNEXPECTED_DELEGATION");

        // And a route advertisement that verified against the OWNER chain is
        // this service minting routes.
        let err = admit(
            &ScriptedVerifier::owner(),
            &octets(),
            StatementKind::RouteAdvertisement,
            0,
        )
        .expect_err("wrong authority");
        assert_eq!(err.code().as_str(), "AUTH.UNEXPECTED_DELEGATION");
    }

    #[test]
    fn the_type_inside_the_payload_wins_over_the_callers_expectation() {
        // identity.proto: `statement_type` is "A HINT for dispatch only … An
        // attacker controls this value."
        let v = ScriptedVerifier::owner().claiming(StatementKind::RelayEpochFloor);
        let err =
            admit(&v, &octets(), StatementKind::RevocationStatement, 0).expect_err("type mismatch");
        assert_eq!(err.code().as_str(), "AUTH.BINDING_INVALID");
    }

    #[test]
    fn an_expired_statement_is_refused() {
        let v = ScriptedVerifier::owner().expiring_at(1_000);
        assert!(admit(&v, &octets(), StatementKind::RevocationStatement, 999).is_ok());
        let err =
            admit(&v, &octets(), StatementKind::RevocationStatement, 1_001).expect_err("expired");
        assert_eq!(err.code().as_str(), "AUTH.STATEMENT_EXPIRED");
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
