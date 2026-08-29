//! Why a resume was refused, and what an accepted one carries.
//!
//! **Authority:** `docs/protocol.md` §12.1 — the authorization row, and "each
//! fallback step MUST be visible: `NET.RESUME_OK`, `NET.RESUME_STALE`,
//! `NET.FULL_RENEGOTIATE`"; ADR-0001 §7.3.2 RS-4, RS-5, RS-6.

use twinvpn_types::{codes, Endpoint, ReasonCode};

/// Why a resume was refused, and therefore why a full handshake follows.
///
/// Typed rather than a bare code so that the *distinctions* survive: "we hold no
/// resumption material" and "the peer presented a forged MAC" both end in a full
/// handshake and are not the same sentence in a support case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResumeRefusal {
    /// No resumption material for this `Session`.
    ///
    /// **RS-1's ordinary case**: a process restart. Also the state of a
    /// `Session` restored from the journal, which is why journal hydration is
    /// not resumption.
    NotArmed,
    /// The datagram was not a well-formed, in-limits `ResumeSession`.
    Malformed {
        /// The `twinvpn-schema` rule that refused it.
        rule: &'static str,
        /// The registered code that rule maps to.
        code: ReasonCode,
    },
    /// The datagram named a different `Session`.
    WrongSession,
    /// The datagram named a `resumption_id` this device never derived.
    UnknownResumptionId,
    /// The MAC did not verify under the peer's direction label.
    Unauthenticated,
    /// **RS-4.** `path_epoch` was at or below the highest already seen.
    Replayed {
        /// What arrived.
        path_epoch: u64,
    },
    /// **RS-6.** The material is older than [`super::RESUMPTION_LIFETIME`].
    Expired,
    /// **RS-5.** The peer has been revoked since the handshake.
    PeerRevoked,
    /// The resumer's `revocation_epoch` is behind this device's.
    ///
    /// The contract's own words for field 5: "so a lagging peer can refuse
    /// rather than resume into a stale trust state".
    TrustEpochBehind {
        /// What the resumer claimed.
        offered: u64,
        /// What this device holds.
        local: u64,
    },
    /// A key derivation failed. Not reachable from any wire input.
    DerivationFailed,
}

impl ResumeRefusal {
    /// The registered code this refusal reports.
    ///
    /// §12.1: "Each fallback step MUST be visible: `NET.RESUME_OK`,
    /// `NET.RESUME_STALE`, `NET.FULL_RENEGOTIATE`." Stale *material* — nothing
    /// held, an unknown id, an expired secret — is `NET.RESUME_STALE`; a
    /// **security** refusal keeps its own `AUTH.*`/`PROTO.*`/`CRYPTO.*` code,
    /// because collapsing a forged MAC into "stale" would erase the only
    /// evidence that anyone tried.
    #[must_use]
    pub const fn reason_code(self) -> ReasonCode {
        match self {
            // Nothing to resume from: the next step is a full negotiation, and
            // that is the code that names it.
            ResumeRefusal::NotArmed | ResumeRefusal::DerivationFailed => {
                codes::NET_FULL_RENEGOTIATE
            }
            ResumeRefusal::Malformed { code, .. } => code,
            ResumeRefusal::UnknownResumptionId | ResumeRefusal::Expired => codes::NET_RESUME_STALE,
            ResumeRefusal::WrongSession | ResumeRefusal::Unauthenticated => {
                codes::AUTH_BINDING_INVALID
            }
            ResumeRefusal::Replayed { .. } => codes::CRYPTO_REPLAY_DETECTED,
            ResumeRefusal::PeerRevoked => codes::AUTH_DEVICE_REVOKED,
            ResumeRefusal::TrustEpochBehind { .. } => codes::AUTH_TRUST_EPOCH_ROLLBACK,
        }
    }

    /// Whether the refusal must be followed by a full handshake.
    ///
    /// Always `true`, and a function rather than a constant so that a future
    /// variant has to answer it rather than inherit an answer. §12.1: "On
    /// failure within its budget, fall back to a full negotiation from cache."
    /// A resume is an optimisation on top of a path the machine can always
    /// re-establish, so there is no refusal for which *doing less* is correct.
    #[must_use]
    pub const fn falls_back_to_full_handshake(self) -> bool {
        true
    }

    /// Whether the datagram is dropped without any answer to the peer.
    ///
    /// **RS-4** is explicit that a stale `path_epoch` "MUST be dropped
    /// silently", and the same is true of anything that failed to authenticate:
    /// answering an unauthenticated datagram turns this into an amplifier and
    /// an oracle. "Silently" is about the *wire*; the refusal is still reported
    /// locally under [`Self::reason_code`], which is what §12.1's visibility
    /// requirement asks for.
    #[must_use]
    pub const fn silent_on_the_wire(self) -> bool {
        matches!(
            self,
            ResumeRefusal::Replayed { .. }
                | ResumeRefusal::Unauthenticated
                | ResumeRefusal::WrongSession
                | ResumeRefusal::UnknownResumptionId
                | ResumeRefusal::Malformed { .. }
        )
    }
}

/// A resume that authenticated, was fresh, and was authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedResume {
    /// The epoch that was committed to the inbound window.
    pub path_epoch: u64,
    /// Where the peer says it is now, if it said.
    pub new_endpoint_hint: Option<Endpoint>,
    /// The `revocation_epoch` the resumer presented.
    pub revocation_epoch: u64,
}

impl AcceptedResume {
    /// `NET.RESUME_OK`. §12.1 requires the success step to be visible too.
    #[must_use]
    pub const fn reason_code(self) -> ReasonCode {
        codes::NET_RESUME_OK
    }
}
