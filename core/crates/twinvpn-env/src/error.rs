//! The environment's failure type, and its mapping into the registered
//! taxonomy.

use twinvpn_types::codes;
use twinvpn_types::evidence::EvidenceValue;
use twinvpn_types::{Component, Diagnostic, ReasonCode};

/// A failure of an injected capability.
///
/// Every variant maps onto a registered `reason_code` (`ownership.md` §6 rule
/// 12): a capability failure that reached a caller as a bare string would be the
/// "unexplained OS error" this product exists to remove.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EnvError {
    /// The platform CSPRNG could not be read.
    ///
    /// **Never** silently downgraded to a weaker source. A device that cannot
    /// produce unpredictable bytes cannot safely produce a nonce, a
    /// `session_nonce`, or an `idempotency_key`.
    #[error("platform entropy is unavailable")]
    EntropyUnavailable,

    /// The injected [`crate::StreamDerivation`] could not produce the requested
    /// length. A TwinLab configuration defect, not an operating state.
    #[error("CD-4 stream derivation failed for {consumer}")]
    StreamDerivationFailed {
        /// The consumer whose stream could not be derived.
        consumer: &'static str,
    },

    /// The runtime refused to accept work — during shutdown, or past a bound.
    #[error("the runtime refused to spawn: {reason}")]
    SpawnRefused {
        /// Why.
        reason: &'static str,
    },

    /// A capability was used after the environment began shutting down.
    ///
    /// Graceful shutdown is a state, not a race: a component that submits work
    /// after shutdown begins gets this rather than a task that never runs.
    #[error("the environment is shutting down")]
    ShuttingDown,
}

impl EnvError {
    /// The registered `reason_code` this failure is exposed as.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            // A CSPRNG that will not answer is a platform capability failure,
            // which is what PLATFORM.ADAPTER_UNAVAILABLE names. It is deliberately
            // not a CRYPTO.* code: nothing cryptographic went wrong, the platform
            // did not supply a capability.
            EnvError::EntropyUnavailable => codes::PLATFORM_ADAPTER_UNAVAILABLE,
            // A derivation or spawn failure is a defect in how the environment was
            // assembled, and INTERNAL is where "every occurrence is a bug" lives.
            EnvError::StreamDerivationFailed { .. } | EnvError::SpawnRefused { .. } => {
                codes::INTERNAL_INVARIANT_VIOLATED
            }
            EnvError::ShuttingDown => codes::INTERNAL_UNEXPECTED_STATE,
        }
    }

    /// The registered diagnostic for this failure.
    #[must_use]
    pub fn diagnostic(&self, component: Component) -> Diagnostic {
        let code = self.reason_code();
        let builder = Diagnostic::builder(code, component);
        match self {
            EnvError::StreamDerivationFailed { consumer } => builder.evidence(
                "invariant",
                EvidenceValue::Text(format!("CD-4 derivation failed for {consumer}")),
            ),
            EnvError::SpawnRefused { reason } => builder.evidence(
                "invariant",
                EvidenceValue::Text(format!("runtime refused to spawn: {reason}")),
            ),
            EnvError::ShuttingDown => builder
                .evidence("state", EvidenceValue::Text("shutting_down".to_owned()))
                .evidence("requested", EvidenceValue::Text("spawn".to_owned())),
            EnvError::EntropyUnavailable => builder,
        }
        .build()
    }
}
