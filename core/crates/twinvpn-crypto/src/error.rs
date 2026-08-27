//! The one error type this crate exposes, and its mapping onto registered
//! `reason_code`s.
//!
//! **Authority:** `docs/implementation/ownership.md` §6 rule 12 ("expose
//! registered `reason_code`s, never raw internal errors"), ADR-0015 §11.2 (the
//! closed sixteen-domain taxonomy), ADR-0001 R14.
//!
//! # R14, structurally
//!
//! > "Every cryptographic failure MUST surface a stable machine-readable reason
//! > code and a human-actionable explanation, and MUST NOT leak key material
//! > through error detail."
//!
//! Two mechanisms carry that here. First, every variant maps to a constant from
//! [`twinvpn_types::codes`], so there is no way to construct an unregistered
//! code. Second, **no variant carries key material, plaintext, or a secret
//! length**: the variants carry a statement type, a counter, an epoch, or a
//! bounded `&'static str` naming a step — never bytes. A `Debug` on this type is
//! therefore safe to log, which is what makes rule 11 hold at the boundary
//! rather than at each call site.

use twinvpn_types::{codes, Component, Diagnostic, EvidenceValue, ReasonCode};

/// Which of the seventeen B2 statement types a failure concerned.
///
/// Carried as a stable non-localised tag so a diagnostic can say *which*
/// statement failed without the caller re-deriving it from context, and without
/// any part of the statement's contents entering the error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum StatementKind {
    DeviceIdentityRecord,
    TunnelKeyBinding,
    IdentitySuccession,
    PairingAttestation,
    RevocationStatement,
    RevocationEntry,
    TrustEpochBundle,
    OwnerTrustAnchor,
    OwnerDelegation,
    PolicyBundle,
    RouteAdvertisement,
    ExitNodeOffer,
    RelayCapabilityToken,
    RelayEpochFloor,
    RelayMap,
    LogHead,
    NetworkContract,
}

impl StatementKind {
    /// The stable tag used as `statement_type` evidence.
    ///
    /// Matches the CDDL section names in
    /// `contracts/cddl/twinvpn/v1/signed_statements.cddl` so a reader can go
    /// from a diagnostic straight to the schema.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            StatementKind::DeviceIdentityRecord => "device-identity-record",
            StatementKind::TunnelKeyBinding => "tunnel-key-binding",
            StatementKind::IdentitySuccession => "identity-succession",
            StatementKind::PairingAttestation => "pairing-attestation",
            StatementKind::RevocationStatement => "revocation-statement",
            StatementKind::RevocationEntry => "revocation-entry",
            StatementKind::TrustEpochBundle => "trust-epoch-bundle",
            StatementKind::OwnerTrustAnchor => "owner-trust-anchor",
            StatementKind::OwnerDelegation => "owner-delegation",
            StatementKind::PolicyBundle => "policy-bundle",
            StatementKind::RouteAdvertisement => "route-advertisement",
            StatementKind::ExitNodeOffer => "exit-node-offer",
            StatementKind::RelayCapabilityToken => "relay-capability-token",
            StatementKind::RelayEpochFloor => "relay-epoch-floor",
            StatementKind::RelayMap => "relay-map",
            StatementKind::LogHead => "log-head",
            StatementKind::NetworkContract => "network-contract",
        }
    }

    /// The `twinvpn.v1.SignedStatementType` wire value for this kind.
    ///
    /// The proto enum's numbering is *not* the CDDL's ordering, so this is a
    /// table rather than a cast.
    #[must_use]
    pub const fn to_wire(self) -> i32 {
        match self {
            StatementKind::PairingAttestation => 1,
            StatementKind::RevocationStatement => 2,
            StatementKind::DeviceIdentityRecord => 3,
            StatementKind::PolicyBundle => 4,
            StatementKind::RouteAdvertisement => 5,
            StatementKind::ExitNodeOffer => 6,
            StatementKind::IdentitySuccession => 7,
            StatementKind::TunnelKeyBinding => 8,
            StatementKind::OwnerTrustAnchor => 9,
            StatementKind::OwnerDelegation => 10,
            StatementKind::TrustEpochBundle => 11,
            StatementKind::RelayCapabilityToken => 12,
            StatementKind::RelayEpochFloor => 13,
            StatementKind::RelayMap => 14,
            StatementKind::LogHead => 15,
            StatementKind::NetworkContract => 16,
            // RevocationEntry is the writer's wrapper and has no proto enum
            // value: it never travels as a bare `SignedStatement`, it is the
            // admitted form inside the revocation log.
            StatementKind::RevocationEntry => 0,
        }
    }
}

/// Every way a cryptographic operation in this crate can fail.
///
/// Deliberately **not** `#[non_exhaustive]`: a caller in `twinvpn-trust` or
/// `twinvpn-tunnel` matching exhaustively should stop compiling when a new
/// failure mode appears, because each one needs a deliberate handling decision.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// The received octets are not valid CBOR, or not RFC 8949 §4.2.1 core
    /// deterministic encoding.
    ///
    /// **Never normalised.** The CDDL header is explicit: "Non-canonical input
    /// MUST BE REJECTED with `PROTO.NON_CANONICAL_CBOR`, NEVER NORMALIZED —
    /// normalizing attacker input before verifying is a signature-bypass
    /// pattern."
    #[error("statement {kind:?} is not deterministic CBOR: {step}")]
    NonCanonicalCbor {
        /// Which statement type the octets claimed to be.
        kind: StatementKind,
        /// A bounded, non-localised name for the failing check.
        step: &'static str,
    },

    /// A `crit` field the verifier does not understand.
    ///
    /// The CDDL header: "A VERIFIER ENCOUNTERING AN UNRECOGNIZED CRITICAL FIELD
    /// MUST REJECT THE STATEMENT" — without which a future *restriction* is
    /// silently ignored by an old device, "A SILENT AUTHORIZATION HOLE".
    #[error("statement {kind:?} carries unrecognized critical field")]
    UnknownCriticalField {
        /// Which statement type.
        kind: StatementKind,
        /// The offending field name, taken from the `crit` set. Bounded by the
        /// CDDL's `tstr` and by [`crate::cose::MAX_CRIT_ENTRY_BYTES`].
        field: String,
    },

    /// A required `crit` member is absent.
    ///
    /// Each statement's CDDL comment names the members its `crit` set MUST
    /// include. A statement that omits one is not merely unusual: it is a
    /// statement whose monotone field a verifier is being invited to ignore.
    #[error("statement {kind:?} omits required critical field {field}")]
    MissingCriticalField {
        /// Which statement type.
        kind: StatementKind,
        /// The member the CDDL requires.
        field: &'static str,
    },

    /// The COSE_Sign1 structure is malformed, or the payload is absent.
    #[error("statement {kind:?} is a malformed COSE_Sign1: {step}")]
    MalformedCose {
        /// Which statement type.
        kind: StatementKind,
        /// A bounded name for the failing structural check.
        step: &'static str,
    },

    /// The signature did not verify over the received octets.
    #[error("statement {kind:?} signature did not verify")]
    SignatureInvalid {
        /// Which statement type.
        kind: StatementKind,
    },

    /// A `TunnelKeyBinding` did not verify, or did not bind the key presented.
    ///
    /// `AUTH.BINDING_INVALID`: "A skipped check would be a FULL AUTHENTICATION
    /// BYPASS."
    #[error("TunnelKeyBinding did not verify: {step}")]
    BindingInvalid {
        /// Which structural check failed.
        step: &'static str,
    },

    /// A statement's validity window has passed, evaluated against local time
    /// with an explicit skew allowance.
    #[error("statement {kind:?} expired at {not_after_ms} ms")]
    StatementExpired {
        /// Which statement type.
        kind: StatementKind,
        /// The declared expiry.
        not_after_ms: u64,
        /// The skew allowance applied.
        skew_allowance_ms: u64,
    },

    /// The wall clock is too far off to evaluate a validity window at all.
    ///
    /// **Never terminal, never a gate.** The registry entry is explicit: "no
    /// security decision may depend on the device's clock. On an unattended
    /// RTC-less router there is no one present to perform a remediation, so
    /// gating would brick the device."
    #[error("wall clock unusable for validity evaluation")]
    ClockUnusable,

    /// A monotone counter went backwards. The lower value is **refused**, never
    /// applied.
    #[error("monotone rollback: offered {offered}, high-water {high_water}")]
    MonotoneRollback {
        /// The value that was offered.
        offered: u64,
        /// The value already held.
        high_water: u64,
    },

    /// The Noise handshake failed.
    #[error("noise handshake rejected: {step}")]
    HandshakeRejected {
        /// A bounded name for the failing step. Never carries `snow`'s own
        /// message, which can name key lengths and state.
        step: &'static str,
    },

    /// A transport frame was a replay, or fell outside the anti-replay window.
    #[error("replay detected at counter {counter}")]
    ReplayDetected {
        /// The rejected counter.
        counter: u64,
    },

    /// A rekey did not complete in place; a new `Tunnel` is required.
    #[error("rekey failed: {step}")]
    RekeyFailed {
        /// A bounded name for the failing step.
        step: &'static str,
    },

    /// The negotiation transcript did not match.
    #[error("transcript mismatch in phase {phase}")]
    TranscriptMismatch {
        /// Which confirmation phase, as a stable tag.
        phase: &'static str,
    },

    /// An offered `ProtocolEpoch` is strictly below the recorded monotonic
    /// floor (ADR-0001 D3, S-37).
    #[error("downgrade refused: offered {offered_epoch}, floor {recorded_floor}")]
    DowngradeRefused {
        /// The offered epoch.
        offered_epoch: u32,
        /// The recorded floor.
        recorded_floor: u32,
    },

    /// A key or secret had the wrong length for the algorithm.
    ///
    /// Carries the expected and observed *lengths*, which are not secret, and
    /// nothing else.
    #[error("key material length {observed}, expected {expected}")]
    KeyLength {
        /// The length the algorithm requires.
        expected: usize,
        /// The length supplied.
        observed: usize,
    },

    /// The identity key algorithm is outside this build's supported set.
    #[error("identity key algorithm {algorithm} unsupported")]
    IdentityAlgUnsupported {
        /// A stable tag for the algorithm, e.g. the COSE `alg` value rendered.
        algorithm: &'static str,
    },

    /// A derivation could not produce the requested output length.
    ///
    /// HKDF's `expand` fails only when `L > 255 * HashLen`, which is a caller
    /// defect rather than an input condition — so this maps to
    /// `INTERNAL.INVARIANT_VIOLATED`.
    #[error("derivation failed: {invariant}")]
    DerivationFailed {
        /// The invariant the caller broke.
        invariant: &'static str,
    },

    /// The locked allocator could not be given the memory protections this
    /// target declares.
    ///
    /// Surfaced rather than swallowed: CB-6a's whole point is that a weaker
    /// custody posture is a *declared fact*, not a silent degradation.
    #[error("locked allocation unavailable: {mechanism}")]
    LockedAllocationUnavailable {
        /// Which protection could not be applied.
        mechanism: &'static str,
    },
}

impl CryptoError {
    /// The registered `reason_code` for this condition.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            CryptoError::NonCanonicalCbor { .. } => codes::PROTO_NON_CANONICAL_CBOR,
            CryptoError::UnknownCriticalField { .. } | CryptoError::MissingCriticalField { .. } => {
                codes::PROTO_UNKNOWN_CRITICAL_FIELD
            }
            // A malformed COSE envelope is a malformed message, not a signature
            // failure: reporting it as `SignatureInvalid` would tell an attacker
            // that their structurally broken input got as far as a verification.
            CryptoError::MalformedCose { .. } => codes::PROTO_MALFORMED_MESSAGE,
            // A bad signature on any statement other than a binding is a
            // handshake-independent trust failure. `AUTH.PEER_UNTRUSTED` is the
            // registered code for "no TrustedPeer record for the presented
            // static"; a statement that does not verify is the same conclusion
            // reached a different way.
            CryptoError::SignatureInvalid { .. } => codes::AUTH_PEER_UNTRUSTED,
            CryptoError::BindingInvalid { .. } => codes::AUTH_BINDING_INVALID,
            CryptoError::StatementExpired { .. } => codes::AUTH_STATEMENT_EXPIRED,
            CryptoError::ClockUnusable => codes::AUTH_CLOCK_IMPLAUSIBLE,
            CryptoError::MonotoneRollback { .. } => codes::AUTH_TRUST_EPOCH_ROLLBACK,
            CryptoError::HandshakeRejected { .. } => codes::CRYPTO_HANDSHAKE_REJECTED,
            CryptoError::ReplayDetected { .. } => codes::CRYPTO_REPLAY_DETECTED,
            CryptoError::RekeyFailed { .. } => codes::CRYPTO_REKEY_FAILED,
            CryptoError::TranscriptMismatch { .. } => codes::PROTO_TRANSCRIPT_MISMATCH,
            CryptoError::DowngradeRefused { .. } => codes::PROTO_DOWNGRADE_REFUSED,
            CryptoError::KeyLength { .. } => codes::CRYPTO_PEER_KEY_UNKNOWN,
            CryptoError::IdentityAlgUnsupported { .. } => codes::AUTH_IDENTITY_ALG_UNSUPPORTED,
            CryptoError::DerivationFailed { .. }
            | CryptoError::LockedAllocationUnavailable { .. } => codes::INTERNAL_INVARIANT_VIOLATED,
        }
    }

    /// The typed [`Diagnostic`] for this condition, with its declared evidence.
    ///
    /// Only keys the frozen registry declares for the code are attached;
    /// [`twinvpn_types::Evidence::new`] refuses an undeclared key, so a drift
    /// between this mapping and `reason_codes.json` fails a test rather than
    /// emitting an unattributable field.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn diagnostic(&self, component: Component) -> Diagnostic {
        let code = self.reason_code();
        let mut b = Diagnostic::builder(code, component);
        match self {
            CryptoError::NonCanonicalCbor { kind, .. } => {
                b = b
                    .evidence("parser_id", EvidenceValue::Text("dcbor".to_owned()))
                    .evidence("statement_type", EvidenceValue::Text(kind.tag().to_owned()));
            }
            CryptoError::UnknownCriticalField { kind, field } => {
                b = b
                    .evidence("statement_type", EvidenceValue::Text(kind.tag().to_owned()))
                    .evidence("field", EvidenceValue::Text(field.clone()));
            }
            CryptoError::MissingCriticalField { kind, field } => {
                b = b
                    .evidence("statement_type", EvidenceValue::Text(kind.tag().to_owned()))
                    .evidence("field", EvidenceValue::Text((*field).to_owned()));
            }
            CryptoError::MalformedCose { step, .. } => {
                b = b.evidence("cap_violated", EvidenceValue::Text((*step).to_owned()));
            }
            CryptoError::StatementExpired {
                kind,
                not_after_ms,
                skew_allowance_ms,
            } => {
                b = b
                    .evidence("statement_type", EvidenceValue::Text(kind.tag().to_owned()))
                    .evidence("not_after_ms", EvidenceValue::Uint(*not_after_ms))
                    .evidence(
                        "skew_allowance_ms",
                        EvidenceValue::DurationMs(*skew_allowance_ms),
                    );
            }
            CryptoError::MonotoneRollback {
                offered,
                high_water,
            } => {
                b = b
                    .evidence("offered_epoch", EvidenceValue::Uint(*offered))
                    .evidence("high_water_epoch", EvidenceValue::Uint(*high_water));
            }
            CryptoError::TranscriptMismatch { phase } => {
                b = b.evidence("phase", EvidenceValue::Text((*phase).to_owned()));
            }
            CryptoError::DowngradeRefused {
                offered_epoch,
                recorded_floor,
            } => {
                b = b
                    .evidence(
                        "offered_epoch",
                        EvidenceValue::Uint(u64::from(*offered_epoch)),
                    )
                    .evidence(
                        "recorded_floor",
                        EvidenceValue::Uint(u64::from(*recorded_floor)),
                    );
            }
            CryptoError::IdentityAlgUnsupported { algorithm } => {
                b = b.evidence("algorithm", EvidenceValue::Text((*algorithm).to_owned()));
            }
            CryptoError::DerivationFailed { invariant } => {
                b = b.evidence("invariant", EvidenceValue::Text((*invariant).to_owned()));
            }
            CryptoError::LockedAllocationUnavailable { mechanism } => {
                b = b.evidence("invariant", EvidenceValue::Text((*mechanism).to_owned()));
            }
            // The remaining variants' registry entries declare no evidence
            // fields, or declare only `peer_label`, which this crate cannot
            // supply: a label is an Owner-chosen string held in `TrustedPeer`,
            // and `twinvpn-crypto` never sees one. `twinvpn-trust` attaches it.
            CryptoError::SignatureInvalid { .. }
            | CryptoError::BindingInvalid { .. }
            | CryptoError::ClockUnusable
            | CryptoError::HandshakeRejected { .. }
            | CryptoError::ReplayDetected { .. }
            | CryptoError::RekeyFailed { .. }
            | CryptoError::KeyLength { .. } => {}
        }
        b.build()
    }
}

/// The crate's result alias.
pub type Result<T> = core::result::Result<T, CryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant maps to a code the frozen registry contains.
    ///
    /// `ReasonCode` has no constructor from a string, so this cannot fail by
    /// naming an unregistered code — what it catches is a mapping changed to a
    /// code that means something else, which a reviewer reads here in one place.
    #[test]
    // A table, not logic: one line per variant is the point, and splitting it
    // would put half the mapping somewhere a reviewer has to go looking for.
    #[allow(clippy::too_many_lines)]
    fn every_variant_carries_a_registered_code() {
        let cases: Vec<(CryptoError, &str)> = vec![
            (
                CryptoError::NonCanonicalCbor {
                    kind: StatementKind::PolicyBundle,
                    step: "s",
                },
                "PROTO.NON_CANONICAL_CBOR",
            ),
            (
                CryptoError::UnknownCriticalField {
                    kind: StatementKind::PolicyBundle,
                    field: "f".to_owned(),
                },
                "PROTO.UNKNOWN_CRITICAL_FIELD",
            ),
            (
                CryptoError::MissingCriticalField {
                    kind: StatementKind::PolicyBundle,
                    field: "f",
                },
                "PROTO.UNKNOWN_CRITICAL_FIELD",
            ),
            (
                CryptoError::MalformedCose {
                    kind: StatementKind::LogHead,
                    step: "s",
                },
                "PROTO.MALFORMED_MESSAGE",
            ),
            (
                CryptoError::SignatureInvalid {
                    kind: StatementKind::LogHead,
                },
                "AUTH.PEER_UNTRUSTED",
            ),
            (
                CryptoError::BindingInvalid { step: "s" },
                "AUTH.BINDING_INVALID",
            ),
            (
                CryptoError::StatementExpired {
                    kind: StatementKind::LogHead,
                    not_after_ms: 1,
                    skew_allowance_ms: 2,
                },
                "AUTH.STATEMENT_EXPIRED",
            ),
            (CryptoError::ClockUnusable, "AUTH.CLOCK_IMPLAUSIBLE"),
            (
                CryptoError::MonotoneRollback {
                    offered: 1,
                    high_water: 2,
                },
                "AUTH.TRUST_EPOCH_ROLLBACK",
            ),
            (
                CryptoError::HandshakeRejected { step: "s" },
                "CRYPTO.HANDSHAKE_REJECTED",
            ),
            (
                CryptoError::ReplayDetected { counter: 1 },
                "CRYPTO.REPLAY_DETECTED",
            ),
            (
                CryptoError::RekeyFailed { step: "s" },
                "CRYPTO.REKEY_FAILED",
            ),
            (
                CryptoError::TranscriptMismatch { phase: "p" },
                "PROTO.TRANSCRIPT_MISMATCH",
            ),
            (
                CryptoError::DowngradeRefused {
                    offered_epoch: 1,
                    recorded_floor: 2,
                },
                "PROTO.DOWNGRADE_REFUSED",
            ),
            (
                CryptoError::KeyLength {
                    expected: 1,
                    observed: 2,
                },
                "CRYPTO.PEER_KEY_UNKNOWN",
            ),
            (
                CryptoError::IdentityAlgUnsupported { algorithm: "a" },
                "AUTH.IDENTITY_ALG_UNSUPPORTED",
            ),
            (
                CryptoError::DerivationFailed { invariant: "i" },
                "INTERNAL.INVARIANT_VIOLATED",
            ),
            (
                CryptoError::LockedAllocationUnavailable { mechanism: "m" },
                "INTERNAL.INVARIANT_VIOLATED",
            ),
        ];
        for (err, code) in cases {
            assert_eq!(err.reason_code().as_str(), code, "for {err:?}");
        }
    }

    /// The evidence a diagnostic carries is the evidence the registry declares.
    ///
    /// `DiagnosticBuilder::evidence` **silently drops** an undeclared key, so a
    /// mapping that named a key the registry does not have would produce an
    /// evidence-free diagnostic and no error anywhere. This asserts the fields
    /// actually arrive.
    #[test]
    fn the_declared_evidence_actually_reaches_the_diagnostic() {
        let d = CryptoError::MonotoneRollback {
            offered: 4,
            high_water: 9,
        }
        .diagnostic(Component::Store);
        assert!(d.evidence().get("offered_epoch").is_some());
        assert!(d.evidence().get("high_water_epoch").is_some());

        let d = CryptoError::NonCanonicalCbor {
            kind: StatementKind::PolicyBundle,
            step: "trailing bytes",
        }
        .diagnostic(Component::ControlPlaneClient);
        assert!(d.evidence().get("parser_id").is_some());
        assert!(d.evidence().get("statement_type").is_some());

        let d = CryptoError::UnknownCriticalField {
            kind: StatementKind::PolicyBundle,
            field: "future_restriction".to_owned(),
        }
        .diagnostic(Component::PolicyEngine);
        assert!(d.evidence().get("field").is_some());

        let d = CryptoError::DowngradeRefused {
            offered_epoch: 1,
            recorded_floor: 3,
        }
        .diagnostic(Component::TunnelEngine);
        assert!(d.evidence().get("offered_epoch").is_some());
        assert!(d.evidence().get("recorded_floor").is_some());
    }

    /// A `Debug` of any variant is safe to log: no variant carries key
    /// material, plaintext, or a secret length. Every field is a `&'static str`,
    /// a `StatementKind`, a counter, or the one bounded `crit` field name.
    #[test]
    fn no_variant_can_carry_content() {
        let rendered = format!(
            "{:?}",
            CryptoError::UnknownCriticalField {
                kind: StatementKind::PolicyBundle,
                field: "policy_version".to_owned(),
            }
        );
        assert!(rendered.contains("policy_version"));
        assert!(rendered.len() < 200);
    }
}
