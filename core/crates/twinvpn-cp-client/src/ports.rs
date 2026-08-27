//! The narrowest traits this crate needs from `twinvpn-trust` and
//! `twinvpn-store`, declared here because those crates are still skeletons.
//!
//! **Authority:** `docs/implementation/ownership.md` §2 (`core-security` owns
//! `twinvpn-{crypto,store,trust}`; no domain writes into another's paths) and the
//! objective's instruction: *"If `twinvpn-store`/`twinvpn-trust` are not yet at
//! the API you need, define the narrowest trait you require in your own crate."*
//!
//! # These are integration items, not a second implementation
//!
//! Each trait below is a **request** to `core-security`, stated as a signature.
//! When the real crates land, the composition root binds an adapter, or these
//! traits are replaced by theirs. Nothing here implements cryptography — CD-I2
//! forbids this crate a cryptographic dependency, and `cargo run -p xtask -- lint`
//! enforces it including dev-dependencies.
//!
//! # Why the store is the only bridge
//!
//! CD-I5: `twinvpn-cp-client` must not reach a data-plane crate, and the reverse
//! edge is equally denied. The control plane's influence on the data plane is
//! *entirely* mediated by [`ControlPlaneStore`]: this crate writes verified,
//! monotone-checked state into it, and the data plane reads from it. That is
//! `architecture.md` §4.2's rule, and the reason this crate never learns whether
//! a `Session` exists.

use futures_core::future::BoxFuture;
use twinvpn_types::{DeviceId, TwinnetId};

use crate::octets::ReceivedOctets;
use crate::state::{CachedPeer, DocumentType, StoredDocumentMark};

/// Which CDDL statement type a verified payload turned out to be.
///
/// Mirrors `identity.proto`'s `SignedStatementType`, narrowed to the ones this
/// crate sees on C1/C2. The wire's `statement_type` field is **a hint for
/// dispatch only** — an attacker controls it — so a verifier returns the type it
/// found *inside* the signed payload and this crate compares the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StatementKind {
    /// `RevocationStatement` — Owner-authority signed.
    RevocationStatement,
    /// `RevocationEntry`, the writer's wrapper carrying the assigned ordering.
    RevocationEntry,
    /// `TrustEpochBundle` — each `EpochSeed` inside is HPKE-sealed to its
    /// recipient, so this crate forwards seals it cannot open.
    TrustEpochBundle,
    /// `PolicyBundle` — Owner-authored. Coordination distributes; it cannot author.
    PolicyBundle,
    /// `PairingAttestation` — signed by a pairing device.
    PairingAttestation,
    /// `IdentitySuccession` — **dual-signed** by the old *and* the new IK.
    IdentitySuccession,
    /// `TunnelKeyBinding` — IK-signed.
    TunnelKeyBinding,
    /// `RouteAdvertisement` — device-signed by the advertiser.
    RouteAdvertisement,
    /// `ExitNodeOffer` — device-signed by the offerer.
    ExitNodeOffer,
    /// `RelayEpochFloor` — Owner-signed, monotone.
    RelayEpochFloor,
    /// `LogHead` — signed by an **online** control-plane key that carries **no
    /// delegated trust power**. Proves liveness, never trust.
    LogHead,
    /// `OwnerTrustAnchor`.
    OwnerTrustAnchor,
    /// `NetworkContract`.
    NetworkContract,
}

impl StatementKind {
    /// A stable, non-localised tag for the `statement_type` evidence field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            StatementKind::RevocationStatement => "revocation_statement",
            StatementKind::RevocationEntry => "revocation_entry",
            StatementKind::TrustEpochBundle => "trust_epoch_bundle",
            StatementKind::PolicyBundle => "policy_bundle",
            StatementKind::PairingAttestation => "pairing_attestation",
            StatementKind::IdentitySuccession => "identity_succession",
            StatementKind::TunnelKeyBinding => "tunnel_key_binding",
            StatementKind::RouteAdvertisement => "route_advertisement",
            StatementKind::ExitNodeOffer => "exit_node_offer",
            StatementKind::RelayEpochFloor => "relay_epoch_floor",
            StatementKind::LogHead => "log_head",
            StatementKind::OwnerTrustAnchor => "owner_trust_anchor",
            StatementKind::NetworkContract => "network_contract",
        }
    }

    /// Which authority must have signed this statement for it to mean anything.
    ///
    /// This is the table that makes "the control plane is authenticated but not
    /// trusted" mechanical. A `PolicyBundle` that verified against a *device* key
    /// is not a policy bundle; a `RouteAdvertisement` that verified against the
    /// *Owner* chain is a coordination service minting routes, which is the
    /// capability Rule B exists to remove.
    #[must_use]
    pub const fn required_authority(self) -> SigningAuthority {
        match self {
            StatementKind::RevocationStatement
            | StatementKind::RevocationEntry
            | StatementKind::TrustEpochBundle
            | StatementKind::PolicyBundle
            | StatementKind::RelayEpochFloor
            | StatementKind::OwnerTrustAnchor
            | StatementKind::NetworkContract => SigningAuthority::Owner,
            StatementKind::PairingAttestation
            | StatementKind::IdentitySuccession
            | StatementKind::TunnelKeyBinding
            | StatementKind::RouteAdvertisement
            | StatementKind::ExitNodeOffer => SigningAuthority::Device,
            StatementKind::LogHead => SigningAuthority::OnlineControlPlane,
        }
    }
}

/// Who a signature must chain to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningAuthority {
    /// The pinned `OwnerTrustAnchor` and its delegation chain (S-32).
    Owner,
    /// A `DeviceIdentityKey`, verified against the peer's known identity.
    Device,
    /// The **online** `LogHead` key. Carries no trust power (ADR-0007 §7.9).
    OnlineControlPlane,
}

impl SigningAuthority {
    /// Whether a statement signed by this authority may change what the device
    /// trusts.
    ///
    /// `false` for [`SigningAuthority::OnlineControlPlane`], and that `false` is
    /// the whole of ADR-0002 §S-3's stated limitation: a compromised control
    /// plane can forge *freshness* and nothing else.
    #[must_use]
    pub const fn confers_trust(self) -> bool {
        !matches!(self, SigningAuthority::OnlineControlPlane)
    }
}

/// A statement whose signature verified **over the received octets**.
#[derive(Debug, Clone)]
pub struct VerifiedStatement {
    /// The type found *inside* the signed payload, not the wire's hint.
    pub kind: StatementKind,
    /// Which authority the signature chained to.
    pub authority: SigningAuthority,
    /// The exact octets that were verified, kept for forwarding.
    pub payload: ReceivedOctets,
    /// The statement's own bounded lifetime, from the signed payload.
    pub window: twinvpn_env::ValidityWindow,
}

/// Signature verification, as this crate needs it.
///
/// **Requested from `twinvpn-trust`.** An implementation MUST verify over the
/// received octets and MUST NOT re-serialize; MUST reject non-canonical CBOR
/// rather than normalize it (`PROTO.NON_CANONICAL_CBOR`); and MUST reject a
/// statement carrying an unrecognized `crit` member.
pub trait StatementVerifier: Send + Sync {
    /// Verifies a COSE_Sign1 statement.
    ///
    /// `expected` is the caller's dispatch expectation; an implementation MUST
    /// compare it against the type inside the verified payload and fail on a
    /// mismatch rather than trusting the caller or the wire.
    fn verify(
        &self,
        octets: &ReceivedOctets,
        expected: StatementKind,
    ) -> Result<VerifiedStatement, VerifyFailure>;
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
    /// Non-canonical deterministic CBOR. **Rejected, never normalized.**
    #[error("non-canonical CBOR")]
    NonCanonical,
    /// An unrecognized `crit` member. Rejecting is mandatory: ignoring one turns
    /// a future *tightening* into a silent no-op.
    #[error("unrecognized critical field")]
    UnknownCriticalField,
    /// The trust anchor needed to verify is not available.
    #[error("no trust anchor")]
    NoAnchor,
}

/// The durable high-water marks and cached state this crate reads and writes.
///
/// **Requested from `twinvpn-store`.** This is the **only** path between the
/// control plane and the data plane (CD-I5).
///
/// Every write is *conditional on monotonicity* and the store is where that is
/// enforced, so the floor holds "even against a compromised or hostile control
/// plane" (`contracts/docs/idempotency.md` §5). ADR-0009 R-9 requires the
/// high-water mark to be durable **before** the document it admits is acted on,
/// so a crash between the two cannot lose the floor — which is why these are
/// fallible async writes and not a cache update.
pub trait ControlPlaneStore: Send + Sync {
    /// The durable C2 cursor (S-27), or 0 if we have never attached.
    fn cursor(&self, twinnet: &TwinnetId) -> BoxFuture<'_, Result<u64, StoreFailure>>;

    /// Advances the durable cursor. MUST reject a value below the stored one:
    /// "a server-offered cursor below the local high-water MUST be rejected".
    fn advance_cursor<'a>(
        &'a self,
        twinnet: &'a TwinnetId,
        net_seq: u64,
    ) -> BoxFuture<'a, Result<(), StoreFailure>>;

    /// The `trust_epoch` high-water mark. **Never decreases** (ADR-0009 R-6).
    fn trust_epoch(&self, twinnet: &TwinnetId) -> BoxFuture<'_, Result<u64, StoreFailure>>;

    /// Advances the trust epoch. MUST refuse a lower value.
    fn advance_trust_epoch<'a>(
        &'a self,
        twinnet: &'a TwinnetId,
        epoch: u64,
    ) -> BoxFuture<'a, Result<(), StoreFailure>>;

    /// The monotone version high-water mark for one document type.
    fn document_version<'a>(
        &'a self,
        twinnet: &'a TwinnetId,
        doc_type: DocumentType,
    ) -> BoxFuture<'a, Result<Option<StoredDocumentMark>, StoreFailure>>;

    /// Stores a verified document, by its **verified octets**, and advances its
    /// high-water mark in the same durable step.
    fn put_document<'a>(
        &'a self,
        twinnet: &'a TwinnetId,
        doc_type: DocumentType,
        version: u64,
        content_digest: [u8; 32],
        payload: &'a ReceivedOctets,
    ) -> BoxFuture<'a, Result<(), StoreFailure>>;

    /// The cached `TrustedPeer` set. **This is what an outage runs on** — I5.
    fn trusted_peers(
        &self,
        twinnet: &TwinnetId,
    ) -> BoxFuture<'_, Result<Vec<CachedPeer>, StoreFailure>>;

    /// Replaces one peer's cached record.
    fn put_trusted_peer<'a>(
        &'a self,
        twinnet: &'a TwinnetId,
        peer: &'a CachedPeer,
    ) -> BoxFuture<'a, Result<(), StoreFailure>>;

    /// Removes a peer from the cached set, recording why.
    fn remove_trusted_peer<'a>(
        &'a self,
        twinnet: &'a TwinnetId,
        peer: DeviceId,
        reason_code: &'a str,
    ) -> BoxFuture<'a, Result<(), StoreFailure>>;

    /// The newest `causality_token` seen for this `TwinNet`, to echo on C1.
    /// Devices **store and echo; they never parse** (protocol.md §5.2).
    fn causality_token(
        &self,
        twinnet: &TwinnetId,
    ) -> BoxFuture<'_, Result<Option<Vec<u8>>, StoreFailure>>;

    /// Records the newest `causality_token`.
    fn put_causality_token<'a>(
        &'a self,
        twinnet: &'a TwinnetId,
        token: &'a [u8],
    ) -> BoxFuture<'a, Result<(), StoreFailure>>;
}

/// Why a store operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StoreFailure {
    /// A monotone floor refused the write. **This is a security control**, not
    /// an error to retry around (ADR-0008 §7.1).
    #[error("monotone floor refused: offered {offered}, floor {floor}")]
    RollbackRefused {
        /// What was offered.
        offered: u64,
        /// The durable floor.
        floor: u64,
    },
    /// Two different contents at one version (ADR-0009 R-4).
    #[error("forked history at version {version}")]
    Forked {
        /// The version at which the fork was seen.
        version: u64,
    },
    /// The vault is not available: a locked device, a corrupt record.
    #[error("the store is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::{SigningAuthority, StatementKind};

    #[test]
    fn only_the_online_log_head_key_carries_no_trust() {
        assert!(!SigningAuthority::OnlineControlPlane.confers_trust());
        assert!(SigningAuthority::Owner.confers_trust());
        assert!(SigningAuthority::Device.confers_trust());
        assert_eq!(
            StatementKind::LogHead.required_authority(),
            SigningAuthority::OnlineControlPlane
        );
    }

    #[test]
    fn coordination_cannot_author_policy_and_owner_cannot_mint_a_route() {
        // policy.proto: "AUTHORED by the Owner authority … the control plane
        // WAREHOUSES AND DISTRIBUTES; IT CANNOT AUTHOR".
        assert_eq!(
            StatementKind::PolicyBundle.required_authority(),
            SigningAuthority::Owner
        );
        // protocol.md §7: "A coordination service that could mint routes could
        // redirect an Owner's traffic for a subnet to an attacker-controlled
        // device." The advertiser signs.
        assert_eq!(
            StatementKind::RouteAdvertisement.required_authority(),
            SigningAuthority::Device
        );
        assert_eq!(
            StatementKind::ExitNodeOffer.required_authority(),
            SigningAuthority::Device
        );
        // The Owner authorizes a revocation by signing it.
        assert_eq!(
            StatementKind::RevocationStatement.required_authority(),
            SigningAuthority::Owner
        );
    }

    #[test]
    fn document_type_round_trips_and_rejects_unspecified() {
        for wire in 1..=7 {
            let t = super::DocumentType::from_wire(wire).expect("declared value");
            assert_eq!(t.to_wire(), wire);
        }
        assert!(super::DocumentType::from_wire(0).is_none());
        assert!(super::DocumentType::from_wire(99).is_none());
    }
}
