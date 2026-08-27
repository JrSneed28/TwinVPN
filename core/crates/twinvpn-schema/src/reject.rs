//! The typed reject every validator returns.
//!
//! **Authority:** `docs/implementation/ownership.md` §6 rule 9 —
//!
//! > Validate every untrusted input against `contracts/registry/limits.json`
//! > *before* any allocation proportional to a declared length. A violation is a
//! > typed reject with a `PROTO.*` code — **never a truncation, never a pad,
//! > never a silent accept.**
//!
//! Three codes carry every violation, and each is the registry's own fit:
//!
//! | Violation | Code | Registry-declared evidence |
//! |---|---|---|
//! | Envelope byte cap | `PROTO.SIZE_EXCEEDED` | `{parser_id, observed, limit}` |
//! | Nesting depth | `PROTO.DEPTH_EXCEEDED` | `{parser_id, observed, limit}` |
//! | Everything else | `PROTO.MALFORMED_MESSAGE` | `{cap_violated, observed, limit}` |
//!
//! `PROTO.MALFORMED_MESSAGE` is the registry's cap-violation code — its declared
//! evidence is literally `cap_violated`, `observed`, `limit` — so a count cap, a
//! wrong identifier width, a non-canonical prefix and a zero port all land there
//! with the violated **registry key** named. A support case is then answerable
//! from the registry alone.

use twinvpn_types::evidence::EvidenceValue;
use twinvpn_types::{codes, Component, Diagnostic, ReasonCode, TypeError};

/// A rejected input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Reject {
    /// The message exceeded its channel's byte cap. Detected **before** decode,
    /// so no allocation was driven by the declared length.
    #[error("{parser_id}: {observed} bytes exceeds the {limit}-byte cap")]
    SizeExceeded {
        /// Which channel's cap.
        parser_id: &'static str,
        /// What arrived.
        observed: usize,
        /// The cap.
        limit: usize,
    },

    /// The message nested deeper than its channel's depth cap.
    #[error("{parser_id}: nesting depth exceeds {limit}")]
    DepthExceeded {
        /// Which channel's cap.
        parser_id: &'static str,
        /// The depth at which scanning stopped.
        observed: usize,
        /// The cap.
        limit: usize,
    },

    /// A count, width or shape cap was violated.
    #[error("{cap_violated}: observed {observed}, limit {limit}")]
    CapViolated {
        /// The `limits.json` key that was violated.
        cap_violated: &'static str,
        /// What arrived.
        observed: u64,
        /// The cap.
        limit: u64,
    },

    /// A value was malformed in a way that is not a cap: a non-canonical prefix,
    /// a zone-index rule violation, an `UNSPECIFIED` enum where a value is
    /// required.
    #[error("{cap_violated}: {source}")]
    Malformed {
        /// A stable name for the field or rule.
        cap_violated: &'static str,
        /// The underlying construction failure.
        source: TypeError,
    },

    /// The wire bytes were not decodable at all.
    #[error("{parser_id}: the envelope did not decode")]
    Unparseable {
        /// Which channel's parser.
        parser_id: &'static str,
    },
}

impl Reject {
    /// The registered `reason_code`.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            Reject::SizeExceeded { .. } => codes::PROTO_SIZE_EXCEEDED,
            Reject::DepthExceeded { .. } => codes::PROTO_DEPTH_EXCEEDED,
            Reject::CapViolated { .. } | Reject::Malformed { .. } => codes::PROTO_MALFORMED_MESSAGE,
            Reject::Unparseable { .. } => codes::PROTO_UNPARSEABLE_ENVELOPE,
        }
    }

    /// The registered diagnostic, with the code's declared evidence attached.
    #[must_use]
    pub fn diagnostic(&self, component: Component) -> Diagnostic {
        let code = self.reason_code();
        let b = Diagnostic::builder(code, component);
        match self {
            Reject::SizeExceeded {
                parser_id,
                observed,
                limit,
            }
            | Reject::DepthExceeded {
                parser_id,
                observed,
                limit,
            } => b
                .evidence("parser_id", EvidenceValue::Text((*parser_id).to_owned()))
                .evidence("observed", EvidenceValue::Uint(*observed as u64))
                .evidence("limit", EvidenceValue::Uint(*limit as u64)),
            Reject::CapViolated {
                cap_violated,
                observed,
                limit,
            } => b
                .evidence(
                    "cap_violated",
                    EvidenceValue::Text((*cap_violated).to_owned()),
                )
                .evidence("observed", EvidenceValue::Uint(*observed))
                .evidence("limit", EvidenceValue::Uint(*limit)),
            Reject::Malformed { cap_violated, .. } => b.evidence(
                "cap_violated",
                EvidenceValue::Text((*cap_violated).to_owned()),
            ),
            Reject::Unparseable { parser_id } => {
                b.evidence("parser_id", EvidenceValue::Text((*parser_id).to_owned()))
            }
        }
        .build()
    }

    /// A count-cap rejection.
    #[must_use]
    pub const fn cap(cap_violated: &'static str, observed: usize, limit: usize) -> Self {
        Reject::CapViolated {
            cap_violated,
            observed: observed as u64,
            limit: limit as u64,
        }
    }

    /// Rejects `observed` if it exceeds `limit`.
    ///
    /// The shape every count check takes, so a validator reads as a list of caps
    /// rather than a list of `if`s.
    pub const fn check_max(
        cap_violated: &'static str,
        observed: usize,
        limit: usize,
    ) -> Result<(), Self> {
        if observed > limit {
            Err(Reject::cap(cap_violated, observed, limit))
        } else {
            Ok(())
        }
    }

    /// Rejects `observed` unless it is exactly `expected`.
    pub const fn check_exact(
        cap_violated: &'static str,
        observed: usize,
        expected: usize,
    ) -> Result<(), Self> {
        if observed == expected {
            Ok(())
        } else {
            Err(Reject::cap(cap_violated, observed, expected))
        }
    }
}

impl Reject {
    /// Wraps a construction failure with the registry key it belongs to.
    #[must_use]
    pub const fn malformed(cap_violated: &'static str, source: TypeError) -> Self {
        Reject::Malformed {
            cap_violated,
            source,
        }
    }
}
