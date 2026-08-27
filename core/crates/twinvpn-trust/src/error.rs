//! `TrustError` and its mapping onto the registered `AUTH.*` codes.
//!
//! **Authority:** ADR-0007 (which registers the `AUTH.*` family), ADR-0015
//! §11.2, `contracts/registry/reason_codes.json`,
//! `docs/implementation/ownership.md` §6 rule 12.
//!
//! Unlike `twinvpn-store`'s `STORE.*` family, the `AUTH.*` codes this crate
//! needs **are** all present in the frozen registry. Every variant below maps to
//! one that means exactly what the variant means.

use twinvpn_types::{codes, Component, Diagnostic, EvidenceValue, ReasonCode};

/// Every way a trust decision can fail.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    /// A cryptographic verification failed. Carries the underlying condition so
    /// the code is the crypto layer's, not a coarsened one.
    #[error("verification failed: {0}")]
    Crypto(#[from] twinvpn_crypto::CryptoError),

    /// No `TrustedPeer` record for the presented identity.
    #[error("peer is not trusted")]
    PeerUntrusted,

    /// An Owner-signed `RevocationStatement` for this peer has verified.
    ///
    /// **Terminal.** N-25(1): peer refusal "takes effect the instant a device
    /// verifies an Owner-signed `RevocationRecord`, whatever its provenance …
    /// It requires **no** epoch number and **no** control-plane reachability."
    #[error("peer is revoked")]
    DeviceRevoked,

    /// A monotone value went backwards. **Refused, not applied** (N-26).
    #[error("trust epoch rollback: offered {offered}, high-water {high_water}")]
    TrustEpochRollback {
        /// The value offered.
        offered: u64,
        /// The value held.
        high_water: u64,
    },

    /// Two different records at one epoch, or a broken `prev_entry_hash`.
    ///
    /// **Detection, not prevention** (N-26): peer refusal rests on the inner
    /// statement's OSK signature alone, so a forked chain cannot un-revoke a
    /// device at a peer that has already seen the statement.
    #[error("trust history forked at epoch {epoch}")]
    TrustHistoryForked {
        /// Where the fork was detected.
        epoch: u64,
    },

    /// A `TunnelKeyBinding` did not verify or did not bind the presented key.
    #[error("tunnel key binding invalid: {step}")]
    BindingInvalid {
        /// Which check failed.
        step: &'static str,
    },

    /// A signer had no delegation carrying the required power, or the quorum
    /// N-11 requires was not met.
    #[error("signer not authorized for {power}")]
    NotAuthorized {
        /// The power that was required.
        power: &'static str,
    },

    /// The ceremony ran out of attempts (N-17: at most five).
    #[error("pairing attempts exhausted")]
    PairingAttemptsExceeded,

    /// The ceremony exceeded its 120-second window (N-17).
    #[error("pairing expired")]
    PairingExpired,

    /// A SPAKE2 run failed: the code was wrong.
    #[error("pairing code mismatch, {attempts_remaining} attempts remain")]
    PairingCodeMismatch {
        /// How many runs remain before the id is burned.
        attempts_remaining: u32,
    },

    /// No OSK with the `ENROLL` power approved the join.
    #[error("pairing not authorized")]
    PairingNotAuthorized,

    /// A `pairing_id` was reused. **Never reissued, not even after expiry or
    /// cancellation**: reissuing would reset the five-attempt budget.
    #[error("pairing id is single-use and has been consumed")]
    PairingIdConsumed,

    /// The wall clock is too far off to evaluate a validity window.
    ///
    /// **Never terminal, never a gate.** The registry entry: "no security
    /// decision may depend on the device's clock. On an unattended RTC-less
    /// router there is no one present to perform a remediation, so gating would
    /// brick the device."
    #[error("wall clock unusable")]
    ClockUnusable,

    /// A peer's `hardware_backed` claim was downgraded (N-24).
    #[error("hardware backing lost")]
    HardwareBackingLost,

    /// A peer presents a key past its overlap window (N-23).
    #[error("peer key is past its overlap window")]
    KeyRotatedPeerStale,

    /// An identity operation could not be performed by the platform element.
    #[error("identity key unavailable")]
    KeyUnavailable,

    /// No identity is present. **A replacement MUST NOT be generated** (N-7).
    #[error("no identity present")]
    IdentityMissing,

    /// A derived `device_id` did not match the value echoed back.
    ///
    /// `device_id_echo` "is an **echo, never an assignment**: a device compares
    /// it against its own derivation and aborts … rather than adopt the server's
    /// value."
    #[error("identity mismatch")]
    IdentityMismatch,

    /// An internal invariant of this crate was broken.
    #[error("trust invariant: {invariant}")]
    Invariant {
        /// The invariant.
        invariant: &'static str,
    },
}

impl TrustError {
    /// The registered `reason_code`.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            TrustError::Crypto(e) => e.reason_code(),
            TrustError::PeerUntrusted => codes::AUTH_PEER_UNTRUSTED,
            TrustError::DeviceRevoked => codes::AUTH_DEVICE_REVOKED,
            TrustError::TrustEpochRollback { .. } => codes::AUTH_TRUST_EPOCH_ROLLBACK,
            TrustError::TrustHistoryForked { .. } => codes::AUTH_TRUST_HISTORY_FORKED,
            TrustError::BindingInvalid { .. } => codes::AUTH_BINDING_INVALID,
            // `NotAuthorized` and `PairingNotAuthorized` share a code because
            // they are the same fact — "no OSK bearing this power approved it" —
            // reached from the delegation check and from the pairing flow.
            TrustError::NotAuthorized { .. } | TrustError::PairingNotAuthorized => {
                codes::AUTH_PAIRING_NOT_AUTHORIZED
            }
            TrustError::PairingAttemptsExceeded => codes::AUTH_PAIRING_ATTEMPTS_EXCEEDED,
            TrustError::PairingExpired | TrustError::PairingIdConsumed => {
                codes::AUTH_PAIRING_EXPIRED
            }
            TrustError::PairingCodeMismatch { .. } => codes::AUTH_PAIRING_CODE_MISMATCH,
            TrustError::ClockUnusable => codes::AUTH_CLOCK_IMPLAUSIBLE,
            TrustError::HardwareBackingLost => codes::AUTH_HARDWARE_BACKING_LOST,
            TrustError::KeyRotatedPeerStale => codes::AUTH_KEY_ROTATED_PEER_STALE,
            TrustError::KeyUnavailable => codes::AUTH_KEY_UNAVAILABLE,
            TrustError::IdentityMissing => codes::AUTH_IDENTITY_MISSING,
            TrustError::IdentityMismatch => codes::AUTH_IDENTITY_MISMATCH,
            TrustError::Invariant { .. } => codes::INTERNAL_INVARIANT_VIOLATED,
        }
    }

    /// The typed diagnostic.
    ///
    /// `peer_label` is declared by several of these codes and is deliberately
    /// **not** attached here: a label is an Owner-chosen string held in the
    /// `TrustedPeer` record, and the caller that has one attaches it. Attaching
    /// a `device_id` in its place would put a `SENSITIVE` identifier where a
    /// human-readable name belongs and would defeat ADR-0014 N-27's requirement
    /// that a lost capability names the peer "BY ITS USER-VISIBLE LABEL".
    #[must_use]
    pub fn diagnostic(&self, component: Component) -> Diagnostic {
        if let TrustError::Crypto(e) = self {
            return e.diagnostic(component);
        }
        let mut b = Diagnostic::builder(self.reason_code(), component);
        match self {
            TrustError::TrustEpochRollback {
                offered,
                high_water,
            } => {
                b = b
                    .evidence("offered_epoch", EvidenceValue::Uint(*offered))
                    .evidence("high_water_epoch", EvidenceValue::Uint(*high_water));
            }
            TrustError::TrustHistoryForked { epoch } => {
                b = b.evidence("epoch", EvidenceValue::Uint(*epoch));
            }
            TrustError::PairingCodeMismatch { attempts_remaining } => {
                b = b.evidence(
                    "attempts_remaining",
                    EvidenceValue::Uint(u64::from(*attempts_remaining)),
                );
            }
            TrustError::Invariant { invariant } => {
                b = b.evidence("invariant", EvidenceValue::Text((*invariant).to_owned()));
            }
            _ => {}
        }
        b.build()
    }
}

impl From<twinvpn_platform::PlatformError> for TrustError {
    fn from(e: twinvpn_platform::PlatformError) -> Self {
        match e {
            twinvpn_platform::PlatformError::IdentityKeyUnavailable(_) => {
                TrustError::KeyUnavailable
            }
            _ => TrustError::KeyUnavailable,
        }
    }
}

impl From<twinvpn_store::StoreError> for TrustError {
    /// A store failure that reaches a trust decision becomes an invariant
    /// violation rather than being re-coded as a trust condition.
    ///
    /// The exception is the one that genuinely *is* a trust condition: a
    /// refused floor is `AUTH.TRUST_EPOCH_ROLLBACK` at both layers, and
    /// coarsening it would lose the fact that a rollback was attempted.
    fn from(e: twinvpn_store::StoreError) -> Self {
        match e {
            twinvpn_store::StoreError::FloorWouldDecrease { offered, held, .. } => {
                TrustError::TrustEpochRollback {
                    offered,
                    high_water: held,
                }
            }
            _ => TrustError::Invariant {
                invariant: "a durable trust write failed",
            },
        }
    }
}

/// The crate's result alias.
pub type Result<T> = core::result::Result<T, TrustError>;
