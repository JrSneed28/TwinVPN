//! `StatementVerifier` → `twinvpn_crypto::verify_cose_sign1` over the received
//! octets, against `twinvpn_trust::AnchorChain`.
//!
//! **Authority:** `contracts/proto/twinvpn/v1/identity.proto` (a
//! `SignedStatement` is opaque COSE_Sign1, and "the signature MUST be verified
//! over the RECEIVED OCTETS; an implementation MUST NOT re-serialize before
//! verifying"); `contracts/cddl/twinvpn/v1/signed_statements.cddl` encoding
//! rules 3 and 5; `policy.proto` ("the control plane WAREHOUSES AND
//! DISTRIBUTES; IT CANNOT AUTHOR"); `docs/protocol.md` §7 Rule B;
//! [ADR-0002](../../../../../docs/adr/ADR-0002-control-plane-messaging-and-event-bus.md)
//! **S-3** (a `LogHead` proves liveness and never trust);
//! [ADR-0007](../../../../../docs/adr/ADR-0007-identity-lifecycle-and-revocation.md)
//! N-11, N-27, S-32; [ADR-0009](../../../../../docs/adr/ADR-0009-consistency-and-state-convergence.md)
//! §11.4 (denials are monotone accumulations, not leases);
//! [ADR-0018](../../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! §11.7 CD-I2, DP-8.
//!
//! # Why this can be bound here when it could not be before
//!
//! Both halves have always existed — `twinvpn_crypto::verify_cose_sign1` and
//! `twinvpn_trust::AnchorChain` — and what was missing was said to be "the
//! mapping from `StatementKind` to the anchor a given statement must chain to".
//! That framing was wrong about where the table lives. `twinvpn-cp-client`
//! already publishes it: `StatementKind::required_authority` is the exact
//! Owner/Device/OnlineControlPlane table, `apply.rs` already re-checks the
//! verifier's answer against it, and this module **reads** that table rather
//! than deriving a second one. There is no authority table in this file. R-31's
//! defect class is avoided by consulting the existing table, not by declining to
//! bind.
//!
//! The second thing this module does not re-derive is *what a payload is*. The
//! ports contract requires that an implementation "compare `expected` against
//! the type inside the verified payload and fail on a mismatch rather than
//! trusting the caller or the wire", and the check for that is
//! `twinvpn_crypto::statements`' own decoder: each one applies its frozen
//! `Schema` — right kind, no unknown field, `crit` understood and complete —
//! before reading a byte. A payload that will not decode as the kind the caller
//! dispatched on **is** a type mismatch, judged against the CDDL rather than
//! against a table written here.
//!
//! # DP-8: one provider, not two
//!
//! Verification runs through `twinvpn-crypto`, the audited provider the rest of
//! the workspace verifies with, for the reason `services/control-plane` gives
//! for doing the same: two providers "double the assurance surface" and must
//! pass the identical golden-vector corpus, and an agreement nobody can test is
//! not an agreement. This crate declares no cryptographic dependency of its own
//! (CD-I2); it names `twinvpn_crypto`'s functions.
//!
//! # What this buys, and what it does **not**
//!
//! It buys: verification over the received octets, against a **pinned** key set,
//! with the payload's own type confirmed and the statement's own validity window
//! returned so a caller cannot proceed without seeing it. Deterministic-CBOR
//! violations are rejected and never normalized, and an unrecognized `crit`
//! member is refused — ignoring one turns a future *tightening* into a silent
//! no-op.
//!
//! It does **not** buy **power scoping**. ADR-0007 N-11 asks whether the OSK
//! that signed carries `POLICY`, `REVOKE` or `ENROLL`, and whether its
//! delegation is current for the pinned anchor version. `AnchorChain::authorize`
//! implements exactly that — and it is keyed on an `Operation`, which is *what
//! is being done*, while `StatementVerifier::verify` is handed *what kind of
//! statement arrived*. No frozen artifact maps one onto the other, so applying
//! the quorum here would mean inventing that mapping, which is the second
//! authority table this module exists to avoid. A verified Owner signature
//! therefore means "the Owner root, or a key the Owner root delegated to,
//! signed this" and not "a key bearing the matching power signed this".
//! `services/control-plane/src/verify.rs` records the identical limitation for
//! the identical reason. **This is open**, and closing it needs an
//! `Operation`-per-`StatementKind` decision from `core-security`, not a guess
//! here.
//!
//! # Fail closed, everywhere
//!
//! There is no configuration of this type that admits an unverifiable statement.
//! With no pinned anchor, every `Owner` statement is refused with
//! `VerifyFailure::NoAnchor`; with no device key set, every `Device` statement
//! is; with no `LogHead` key, every freshness proof is. Each of those is a
//! refusal, not a pass-through, because a control plane that could get an
//! unverified `RevocationStatement` or `PolicyBundle` admitted would be granting
//! authority it does not have — and a design in which a compromised control
//! plane can grant authority is a defect rather than a tradeoff.
//!
//! ## What the composition root still has to supply, and why it cannot be read
//! ## from the store today
//!
//! - **The delegated `osk_id`s**, because `AnchorChain` exposes no way to
//!   enumerate its own delegation set. See
//!   [`AnchorStatementVerifier::with_owner_delegations`].
//! - **The Owner chain.** [`AnchorStatementVerifier::new`] takes a
//!   `twinvpn_trust::AnchorChain`. The core holds no anchor of its own:
//!   `twinvpn-store` has a `Trust` namespace but no frozen record key under it
//!   that this crate may read, and `Core` has no `AnchorChain` field. The shell
//!   restores one and passes it in.
//! - **Peer `DeviceIdentityKey`s.** [`crate::planes::PeerRecord`] — CD-I5's
//!   transfer shape — carries `device_id`, generations, endpoints and overlay
//!   addresses, and **no public key**. That is not an oversight to patch here:
//!   `PeerRecord` is read by data-plane crates, and widening it is a change to
//!   the CD-I5 seam that belongs to the integration lead. Until it is widened or
//!   another path is supplied, every `Device`-authority statement —
//!   `RouteAdvertisement`, `ExitNodeOffer`, `IdentitySuccession`,
//!   `PairingAttestation`, `TunnelKeyBinding` — is **refused** unless the
//!   composition root supplies the key set explicitly through
//!   [`AnchorStatementVerifier::with_device_keys`].

use twinvpn_cp_client::ports::{
    SigningAuthority, StatementKind, StatementVerifier, VerifiedStatement, VerifyFailure,
};
use twinvpn_cp_client::ReceivedOctets;
use twinvpn_crypto::statements;
use twinvpn_crypto::{
    CryptoError, PublicVerifyingKey, StatementKind as CryptoKind,
    VerifiedStatement as CryptoVerified,
};
use twinvpn_env::ValidityWindow;
use twinvpn_trust::AnchorChain;

/// Verifies C1/C2 signed statements against the device's pinned trust state.
///
/// Holds only **public** keys and a pinned anchor. Nothing here can sign, and
/// `twinvpn-trust`'s `owner` module says why: ORK and OSK private material never
/// reaches the core (CB-5 row 1), so verification is the whole of what this side
/// of the seam does.
#[derive(Debug, Clone)]
pub struct AnchorStatementVerifier {
    anchors: AnchorChain,
    osk_ids: Vec<String>,
    device_keys: Vec<Vec<u8>>,
    log_head_keys: Vec<Vec<u8>>,
}

impl AnchorStatementVerifier {
    /// Binds the verifier to a pinned Owner chain.
    ///
    /// The device-key and `LogHead`-key sets start **empty**, which means every
    /// `Device` and every `OnlineControlPlane` statement is refused until one is
    /// supplied. Empty-means-refuse rather than empty-means-accept is the whole
    /// posture of this type.
    #[must_use]
    pub const fn new(anchors: AnchorChain) -> Self {
        Self {
            anchors,
            osk_ids: Vec::new(),
            device_keys: Vec::new(),
            log_head_keys: Vec::new(),
        }
    }

    /// The `DeviceIdentityKey` COSE_Key octets of every device whose statements
    /// this verifier will accept.
    ///
    /// A **set**, tried in order, because `StatementVerifier::verify` carries no
    /// `DeviceId` and cannot be told which peer to expect. That is a real
    /// weakening compared with the control plane's `SignerKey::Device`, which
    /// names exactly one key, and it is stated rather than glossed: here,
    /// "it verified" means *some enrolled device* signed it, and the caller must
    /// still bind the statement to the peer it claims to be about. ADR-0007's
    /// `TunnelKeyBinding` check is that binding, and `twinvpn-trust` performs it.
    #[must_use]
    pub fn with_device_keys(mut self, cose_keys: Vec<Vec<u8>>) -> Self {
        self.device_keys = cose_keys;
        self
    }

    /// The **online** control-plane `LogHead` keys.
    ///
    /// Separate from the Owner chain deliberately. ADR-0002 S-3: this key
    /// "carries no delegated trust power", so a compromised control plane "can
    /// forge *freshness* and nothing else". Folding it into the Owner set would
    /// hand it exactly the power S-3 says it does not have.
    #[must_use]
    pub fn with_log_head_keys(mut self, cose_keys: Vec<Vec<u8>>) -> Self {
        self.log_head_keys = cose_keys;
        self
    }

    /// Names the delegated OSKs whose signatures this verifier will try.
    ///
    /// **The keys still come from the pinned chain**, not from the caller:
    /// `AnchorChain::osk_key` resolves each id against the delegation set the
    /// Owner root signed, so naming an id here can only *narrow* what is tried
    /// and can never introduce a key the chain does not hold.
    ///
    /// # Why an id list is needed at all
    ///
    /// `AnchorChain`'s delegation map is private and it exposes no iterator —
    /// `osk_count()` counts, `delegation(id)` and `osk_key(id)` look up, and
    /// nothing enumerates. The alternative would be to read the COSE protected
    /// header's `kid` to choose a key, and that value is only reachable *after*
    /// verification, which is the wrong order. The composition root installed
    /// the delegations, so it already holds their ids.
    ///
    /// **Integration item for `core-security`:** an `AnchorChain::osk_ids()`
    /// would make this method unnecessary. Until it exists, an Owner statement
    /// signed by an OSK that was not named here is **refused**, not admitted —
    /// which is the safe half of the gap and the reason it is a limitation
    /// rather than a hole.
    #[must_use]
    pub fn with_owner_delegations(mut self, osk_ids: Vec<String>) -> Self {
        self.osk_ids = osk_ids;
        self
    }

    /// The candidate keys one authority admits, or the reason there are none.
    fn candidates(
        &self,
        authority: SigningAuthority,
    ) -> Result<Vec<PublicVerifyingKey>, VerifyFailure> {
        let keys = match authority {
            SigningAuthority::Owner => {
                // The ORK first, then every delegation named. A key cannot be
                // both, because a delegation names an OSK and the ORK signs the
                // delegation, so the order matters only for which failure is
                // reported last. A named id that the chain has retired — S-32's
                // anchor rotation drops delegations bound below the new version
                // — simply resolves to nothing and is skipped, which is the
                // rotation taking effect rather than an error.
                let mut keys = vec![self
                    .anchors
                    .ork_key()
                    .map_err(|_| VerifyFailure::NoAnchor)?];
                keys.extend(
                    self.osk_ids
                        .iter()
                        .filter_map(|id| self.anchors.osk_key(id).ok()),
                );
                keys
            }
            SigningAuthority::Device => {
                parse_all(&self.device_keys, CryptoKind::DeviceIdentityRecord)?
            }
            SigningAuthority::OnlineControlPlane => {
                parse_all(&self.log_head_keys, CryptoKind::LogHead)?
            }
        };
        if keys.is_empty() {
            return Err(VerifyFailure::NoAnchor);
        }
        Ok(keys)
    }
}

/// Parses a configured COSE_Key set, refusing an empty one.
///
/// A key that will not parse is dropped rather than failing the whole set: the
/// set is local configuration, and one malformed entry must not make every other
/// pinned key unusable. An empty *result* is still `NoAnchor`, so dropping every
/// entry refuses rather than admits.
fn parse_all(
    cose_keys: &[Vec<u8>],
    kind: CryptoKind,
) -> Result<Vec<PublicVerifyingKey>, VerifyFailure> {
    if cose_keys.is_empty() {
        return Err(VerifyFailure::NoAnchor);
    }
    Ok(cose_keys
        .iter()
        .filter_map(|k| PublicVerifyingKey::from_cose_key(k, kind).ok())
        .collect())
}

impl StatementVerifier for AnchorStatementVerifier {
    fn verify(
        &self,
        octets: &ReceivedOctets,
        expected: StatementKind,
    ) -> Result<VerifiedStatement, VerifyFailure> {
        // The table is read, never re-derived. See the module docs.
        let authority = expected.required_authority();
        let kind = crypto_kind(expected)?;
        let candidates = self.candidates(authority)?;

        let mut last = VerifyFailure::BadSignature;
        for key in &candidates {
            match twinvpn_crypto::verify_cose_sign1(octets.as_slice(), kind, key) {
                Ok(verified) => {
                    // The payload's own shape, checked against the frozen CDDL
                    // before the statement is handed back. This is the ports
                    // contract's "compare it against the type inside the
                    // verified payload".
                    let window = window_of(expected, &verified)?;
                    return Ok(VerifiedStatement {
                        kind: expected,
                        authority,
                        // The octets AS THEY ARRIVED. Never a re-encode: a
                        // re-serialized COSE_Sign1 stops verifying, and
                        // forwarding one would forward something nobody signed.
                        payload: octets.clone(),
                        window,
                    });
                }
                // Only a signature mismatch is worth trying the next key: a
                // malformed or non-canonical envelope is malformed against every
                // key, and re-running the parse would only be slower.
                Err(CryptoError::SignatureInvalid { .. }) => last = VerifyFailure::BadSignature,
                Err(other) => return Err(map_envelope_error(&other)),
            }
        }
        Err(last)
    }
}

/// `ports::StatementKind` → `twinvpn_crypto::StatementKind`.
///
/// A rename across a crate boundary, one for one. `ports::StatementKind` is
/// `#[non_exhaustive]`, so this match needs a wildcard arm it cannot avoid — and
/// that arm **refuses**. A variant added to the port after this binding was
/// written is a statement type this build does not understand, and admitting one
/// on the strength of a signature alone would verify bytes nobody has decided
/// the meaning of.
const fn crypto_kind(kind: StatementKind) -> Result<CryptoKind, VerifyFailure> {
    Ok(match kind {
        StatementKind::RevocationStatement => CryptoKind::RevocationStatement,
        StatementKind::RevocationEntry => CryptoKind::RevocationEntry,
        StatementKind::TrustEpochBundle => CryptoKind::TrustEpochBundle,
        StatementKind::PolicyBundle => CryptoKind::PolicyBundle,
        StatementKind::PairingAttestation => CryptoKind::PairingAttestation,
        StatementKind::IdentitySuccession => CryptoKind::IdentitySuccession,
        StatementKind::TunnelKeyBinding => CryptoKind::TunnelKeyBinding,
        StatementKind::RouteAdvertisement => CryptoKind::RouteAdvertisement,
        StatementKind::ExitNodeOffer => CryptoKind::ExitNodeOffer,
        StatementKind::RelayEpochFloor => CryptoKind::RelayEpochFloor,
        StatementKind::LogHead => CryptoKind::LogHead,
        StatementKind::OwnerTrustAnchor => CryptoKind::OwnerTrustAnchor,
        StatementKind::NetworkContract => CryptoKind::NetworkContract,
        _ => return Err(VerifyFailure::TypeMismatch),
    })
}

/// The statement's own bounded lifetime, read from the **signed payload**.
///
/// Decoding is the type check as well as the window read: each decoder runs its
/// frozen `Schema` first, so a payload that is not really this kind fails here
/// rather than being handed back as one.
///
/// # The two unbounded rows are correct, not skipped
///
/// `RevocationStatement` and `RevocationEntry` declare no `not_after_ms`, and
/// ADR-0009 §11.4 is why: every denial is permanent — "denials are monotone
/// accumulations, not leases" — so a revocation that expired would un-revoke a
/// stolen device by doing nothing. `None` here means "no upper bound in the
/// signed payload", which is what those statements say.
///
/// # `not_before_ms` is `None` for every row, and that is a fact about the CDDL
///
/// `signed_statements.cddl` declares `not_before_ms` on exactly two statements —
/// `device-identity-record` and `relay-capability-token` — and neither is a
/// `ports::StatementKind`. `None` is "valid from the beginning of time", which is
/// what a statement with no lower bound means, not "the check is skipped".
///
/// # `TunnelKeyBinding` is refused rather than given a window
///
/// `twinvpn_crypto::verify_tunnel_key_binding` requires the `expected_device_id`
/// and `expected_identity_id` of the identity being evaluated, and
/// `StatementVerifier::verify` carries neither. Without them the check degrades
/// into "some device signed some binding", which ADR-0007 N-4 says is not a
/// binding at all. `twinvpn-trust` verifies bindings against a known peer record
/// instead, and `apply.rs` never dispatches one here — so this arm refuses
/// rather than inventing an unbounded window that would disable the expiry gate
/// on a statement that has one.
fn window_of(
    expected: StatementKind,
    verified: &CryptoVerified,
) -> Result<ValidityWindow, VerifyFailure> {
    let not_after_ms = match expected {
        StatementKind::RevocationStatement => {
            statements::decode_revocation_statement(verified).map(|_| None)
        }
        StatementKind::RevocationEntry => {
            statements::decode_revocation_entry(verified).map(|_| None)
        }
        StatementKind::TrustEpochBundle => {
            statements::decode_trust_epoch_bundle(verified).map(|s| Some(s.not_after_ms))
        }
        StatementKind::PolicyBundle => {
            statements::decode_policy_bundle(verified).map(|s| Some(s.not_after_ms))
        }
        StatementKind::PairingAttestation => {
            statements::decode_pairing_attestation(verified).map(|s| Some(s.not_after_ms))
        }
        StatementKind::IdentitySuccession => {
            statements::decode_identity_succession(verified).map(|s| Some(s.not_after_ms))
        }
        StatementKind::RouteAdvertisement => {
            statements::decode_route_advertisement(verified).map(|s| Some(s.not_after_ms))
        }
        StatementKind::ExitNodeOffer => {
            statements::decode_exit_node_offer(verified).map(|s| Some(s.not_after_ms))
        }
        StatementKind::RelayEpochFloor => {
            statements::decode_relay_epoch_floor(verified).map(|s| Some(s.not_after_ms))
        }
        StatementKind::LogHead => {
            statements::decode_log_head(verified).map(|s| Some(s.not_after_ms))
        }
        StatementKind::OwnerTrustAnchor => {
            statements::decode_owner_trust_anchor(verified).map(|s| Some(s.not_after_ms))
        }
        StatementKind::NetworkContract => {
            statements::decode_network_contract(verified).map(|s| Some(s.not_after_ms))
        }
        // See the doc comment: the two identifiers this check needs are not in
        // `verify`'s signature, and "some device signed some binding" is not a
        // binding (ADR-0007 N-4). `NoAnchor` is the nearest true statement the
        // `#[non_exhaustive]` `VerifyFailure` can carry — the material needed to
        // verify is not available — and `apply.rs` maps it to
        // `AUTH.BINDING_INVALID` either way, which is the right outward answer.
        StatementKind::TunnelKeyBinding => return Err(VerifyFailure::NoAnchor),
        // A variant added to `ports::StatementKind` after this binding was
        // written. Refused for the reason `crypto_kind` refuses it.
        _ => return Err(VerifyFailure::TypeMismatch),
    };

    match not_after_ms {
        Ok(not_after_ms) => Ok(ValidityWindow {
            not_before_ms: None,
            not_after_ms,
        }),
        Err(
            CryptoError::UnknownCriticalField { .. } | CryptoError::MissingCriticalField { .. },
        ) => Err(VerifyFailure::UnknownCriticalField),
        // A signature that verified over a payload the CDDL does not admit as
        // this kind is a type mismatch, judged against the frozen schema.
        Err(_) => Err(VerifyFailure::TypeMismatch),
    }
}

/// A `verify_cose_sign1` failure that is not a signature mismatch.
///
/// `NonCanonical` keeps its own variant all the way up: `apply.rs` turns it into
/// a `PROTO.*` reject rather than an `AUTH.*` one, because "the peer sent
/// something unparseable" and "the peer sent something forged" are different
/// facts, and normalizing attacker input before verifying is a signature-bypass
/// pattern.
const fn map_envelope_error(err: &CryptoError) -> VerifyFailure {
    match err {
        CryptoError::NonCanonicalCbor { .. } => VerifyFailure::NonCanonical,
        CryptoError::UnknownCriticalField { .. } | CryptoError::MissingCriticalField { .. } => {
            VerifyFailure::UnknownCriticalField
        }
        CryptoError::IdentityAlgUnsupported { .. } => VerifyFailure::WrongAuthority,
        _ => VerifyFailure::BadSignature,
    }
}
