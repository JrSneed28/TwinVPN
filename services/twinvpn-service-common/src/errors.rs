//! The one place an internal error becomes a registered `reason_code`.
//!
//! **Authority:** ADR-0015 §11.2 (taxonomy, registry attributes, stability
//! rules), §11.3 (the `Diagnostic` record), ADR-0018 F-4 ("errors carry a name,
//! never an errno"), `contracts/proto/twinvpn/v1/errors.proto`,
//! `docs/implementation/ownership.md` §4.2 and §6 rule 12.
//!
//! # There is no parallel error model here
//!
//! `twinvpn-types` already owns `ReasonCode`, `Evidence`, `EvidenceSet` and
//! `Diagnostic`; `twinvpn-schema` already owns `envelope::encode`. This module
//! adds exactly one thing on top: a carrier that pairs a `Diagnostic` with an
//! **internal-only** source error, so that the platform detail is preserved for
//! diagnosis without ever becoming the user-facing answer.
//!
//! ```text
//!   io::Error / sqlx::Error / anything          ServiceError
//!            │                                   ├── diagnostic  → the wire, always
//!            └──────────── source ───────────────┘   (never rendered off-process)
//! ```
//!
//! # Why there is no message string
//!
//! `errors.proto` is normative and blunt:
//!
//! > NORMATIVE: every field here is machine-readable metadata … NO FIELD IS
//! > LOCALIZED AND NONE IS A SENTENCE. Adding a `summary`, `message`, or `title`
//! > field to this message is prohibited.
//!
//! `contracts/` is frozen, so the wire type physically has no such field, and
//! [`ServiceError::envelope`] builds only `v1::ErrorEnvelope` through
//! `twinvpn_schema::envelope::encode`. There is no local envelope type in this
//! crate that a text field could be added to. `no_text_beyond_the_registry`
//! asserts the property from the other direction: a `ServiceError` whose source
//! carries a distinctive string produces encoded bytes that do not contain it.
//!
//! # The `errno` rule
//!
//! The wave-1 objective's requirement — *never expose a raw unexplained OS error
//! as the complete user-facing error* — is satisfied structurally.
//! [`ServiceError::from_os_error`] takes the registered code the caller has
//! already chosen; the OS detail goes into `source` (diagnosable in a log at
//! `ERROR`, `OPERATIONAL` class) and into typed [`twinvpn_types::Evidence`]
//! **only when the registry declares a key for it**. An `errno` is never the
//! whole story and never the primary signal.

use std::fmt;

use twinvpn_schema::{envelope, v1, Reject};
use twinvpn_types::evidence::EvidenceValue;
use twinvpn_types::{
    codes, Component, Diagnostic, ErrorClass, ErrorSeverity, ReasonCode, RemediationClass,
};

use crate::metrics::{Label, Labels, Metrics};

/// A failure that is already a registered `reason_code`.
///
/// Construction always names a code, so there is no path from "something went
/// wrong" to a response without one.
pub struct ServiceError {
    diagnostic: Diagnostic,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl ServiceError {
    /// Starts a `ServiceError` for `code`, observed by `component`.
    ///
    /// Returns a builder rather than `Self` on purpose: a diagnostic is only
    /// complete once its registry-declared evidence is attached, and a `new`
    /// that returned a finished error would make the evidenceless form the
    /// convenient one.
    #[must_use]
    #[allow(clippy::new_ret_no_self)]
    pub fn new(code: ReasonCode, component: Component) -> ServiceErrorBuilder {
        ServiceErrorBuilder {
            builder: Diagnostic::builder(code, component),
            source: None,
        }
    }

    /// Wraps an already-built `Diagnostic`.
    #[must_use]
    pub const fn from_diagnostic(diagnostic: Diagnostic) -> Self {
        Self {
            diagnostic,
            source: None,
        }
    }

    /// The typed reject a validator produced, with its `limits.json` evidence
    /// already attached.
    #[must_use]
    pub fn from_reject(reject: &Reject, component: Component) -> Self {
        Self {
            diagnostic: reject.diagnostic(component),
            source: None,
        }
    }

    /// An OS-level failure, mapped to a code the caller has chosen.
    ///
    /// `code` is required and is not inferred from the `errno`: a mapping table
    /// from `errno` to `reason_code` would be a second taxonomy, and the caller
    /// is the only party that knows whether `ECONNREFUSED` on this socket means
    /// `CONTROL.UNREACHABLE` or `RELAY.NONE_REACHABLE`.
    ///
    /// The raw error is retained as [`ServiceError::source`] for logs and is
    /// **never** encoded into the envelope.
    #[must_use]
    pub fn from_os_error(code: ReasonCode, component: Component, error: std::io::Error) -> Self {
        let mut b = Diagnostic::builder(code, component);
        // `os_cause` is a real registry-declared evidence key on some codes (for
        // example PROTO.CAPABILITY_REVOKED_LOCAL). The builder drops an
        // undeclared key silently, which is exactly right on a failure path, so
        // this is an offer rather than an assumption.
        if let Some(raw) = error.raw_os_error() {
            b = b.evidence("os_cause", EvidenceValue::Int(i64::from(raw)));
        }
        Self {
            diagnostic: b.build(),
            source: Some(Box::new(error)),
        }
    }

    /// Attaches an internal source error. Diagnostic only; never encoded.
    #[must_use]
    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// The registered code.
    #[must_use]
    pub const fn code(&self) -> ReasonCode {
        self.diagnostic.code()
    }

    /// The diagnostic.
    #[must_use]
    pub const fn diagnostic(&self) -> &Diagnostic {
        &self.diagnostic
    }

    /// The internal source, for a log line and nothing else.
    #[must_use]
    pub fn source_detail(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
        self.source.as_deref()
    }

    /// The wire representation.
    ///
    /// Built by `twinvpn_schema::envelope::encode`, which fills `resolved` from
    /// **this build's** registry rather than from anything on the diagnostic, so
    /// the attribute block cannot disagree with the code it accompanies. That is
    /// what makes ADR-0015 §11.2 rule 5's attribute degradation work for a code
    /// the receiver has never seen.
    #[must_use]
    pub fn envelope(&self) -> v1::ErrorEnvelope {
        envelope::encode(&self.diagnostic)
    }

    /// The HTTP status a request-scoped surface should answer with.
    ///
    /// Derived from the registry attributes, never chosen per call site: the same
    /// code always produces the same status, which is what lets a client key on
    /// the code and treat the status as a transport nicety.
    #[must_use]
    pub fn http_status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        let code = self.diagnostic.code();
        match code.class() {
            // A deliberate refusal by policy. Retrying without changing the
            // policy "is not merely futile, it is wrong" (errors.proto).
            ErrorClass::Policy => StatusCode::FORBIDDEN,
            ErrorClass::Transient => {
                if code == codes::CONTROL_ADMISSION_DEFERRED
                    || code == codes::CONTROL_READ_TOO_STALE
                    || code == codes::CONTROL_WRITE_LEADER_UNAVAILABLE
                {
                    StatusCode::SERVICE_UNAVAILABLE
                } else if code.domain() == twinvpn_types::Domain::Proto {
                    // A malformed message is the caller's, even when the
                    // condition is transient.
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                }
            }
            ErrorClass::Persistent => {
                if code.domain() == twinvpn_types::Domain::Proto {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::CONFLICT
                }
            }
            // A security event or an invariant violation. Never retried
            // automatically, and never explained further than the code.
            ErrorClass::Fatal => {
                if code.domain() == twinvpn_types::Domain::Auth {
                    StatusCode::UNAUTHORIZED
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }
        }
    }

    /// Emits the error at the level ADR-0015 §11.5 assigns to its severity, with
    /// the registry attributes attached, and counts it.
    ///
    /// Every field named here is on the collector allowlist. The `source` is
    /// rendered into `error.type` **by type name only** — the message is never
    /// a field, because an OS or driver message can carry a path, an address or
    /// a buffer.
    pub fn emit(&self, metrics: &Metrics, outcome: &str) {
        let code = self.diagnostic.code();
        metrics
            .counter(
                crate::metrics::names::ERRORS,
                "errors mapped to a registered reason_code",
                Labels::new()
                    .with(Label::ReasonCode, code.as_str())
                    .with(Label::Outcome, outcome),
            )
            .inc();

        let error_type = self
            .source
            .as_ref()
            .map_or("none", |_| "internal_source_present");

        macro_rules! record {
            ($lvl:ident) => {
                tracing::$lvl!(
                    twinvpn.reason_code = code.as_str(),
                    twinvpn.reason_domain = code.domain().as_str(),
                    twinvpn.reason_class = class_name(code.class()),
                    twinvpn.severity = severity_name(code.severity()),
                    twinvpn.terminal = code.terminal(),
                    twinvpn.user_actionable = code.user_actionable(),
                    twinvpn.remediation_class = remediation_name(code.remediation_class()),
                    twinvpn.doc_anchor = code.doc_anchor(),
                    twinvpn.outcome = outcome,
                    error.type = error_type,
                    "a registered reason_code was raised"
                )
            };
        }
        match code.severity() {
            ErrorSeverity::Critical => record!(error),
            ErrorSeverity::Error => record!(error),
            ErrorSeverity::Warn => record!(warn),
            ErrorSeverity::Info => record!(info),
        }
    }
}

/// The `class` names ADR-0015 §11.2 registers.
#[must_use]
pub const fn class_name(c: ErrorClass) -> &'static str {
    match c {
        ErrorClass::Transient => "TRANSIENT",
        ErrorClass::Persistent => "PERSISTENT",
        ErrorClass::Policy => "POLICY",
        ErrorClass::Fatal => "FATAL",
    }
}

/// The `severity` names ADR-0015 §11.2 registers.
#[must_use]
pub const fn severity_name(s: ErrorSeverity) -> &'static str {
    match s {
        ErrorSeverity::Info => "INFO",
        ErrorSeverity::Warn => "WARN",
        ErrorSeverity::Error => "ERROR",
        ErrorSeverity::Critical => "CRITICAL",
    }
}

/// The `remediation_class` names ADR-0018 F-4 registers.
#[must_use]
pub const fn remediation_name(r: RemediationClass) -> &'static str {
    match r {
        RemediationClass::None => "NONE",
        RemediationClass::Wait => "WAIT",
        RemediationClass::LocalAction => "LOCAL_ACTION",
        RemediationClass::PeerAction => "PEER_ACTION",
        RemediationClass::PolicyChange => "POLICY_CHANGE",
        RemediationClass::UpdateRequired => "UPDATE_REQUIRED",
        RemediationClass::NetworkChange => "NETWORK_CHANGE",
        RemediationClass::PermissionGrant => "PERMISSION_GRANT",
        RemediationClass::ReportDefect => "REPORT_DEFECT",
    }
}

/// Builder for a [`ServiceError`].
pub struct ServiceErrorBuilder {
    builder: twinvpn_types::DiagnosticBuilder,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl ServiceErrorBuilder {
    /// Attaches registry-declared evidence. An undeclared key is dropped by
    /// `twinvpn-types` rather than turning a failure path into a second failure.
    #[must_use]
    pub fn evidence(mut self, key: &'static str, value: EvidenceValue) -> Self {
        self.builder = self.builder.evidence(key, value);
        self
    }

    /// Records the message this failure answers.
    #[must_use]
    pub fn correlated_to(mut self, message_id: twinvpn_types::MessageId) -> Self {
        self.builder = self.builder.correlated_to(message_id);
        self
    }

    /// Records the correlation from a [`crate::correlation::Correlation`].
    #[must_use]
    pub fn correlation(self, correlation: &crate::correlation::Correlation) -> Self {
        match correlation.message_id() {
            Some(m) => self.correlated_to(m),
            None => self,
        }
    }

    /// Appends a contributing code, most specific first
    /// (`docs/reliability.md` T12).
    #[must_use]
    pub fn contributing(mut self, code: ReasonCode) -> Self {
        self.builder = self.builder.contributing(code);
        self
    }

    /// Records when the condition was observed, on an advisory wall clock.
    #[must_use]
    pub fn occurred_at_ms(mut self, ms: Option<u64>) -> Self {
        self.builder = self.builder.occurred_at_ms(ms);
        self
    }

    /// Attaches an internal source error.
    #[must_use]
    pub fn source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// Finishes.
    #[must_use]
    pub fn build(self) -> ServiceError {
        ServiceError {
            diagnostic: self.builder.build(),
            source: self.source,
        }
    }
}

impl fmt::Debug for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The source is shown here because `Debug` on a `ServiceError` is a
        // developer-facing, in-process rendering — it is never a field on a
        // telemetry record, and `RedactingLayer` drops any field it appears in.
        f.debug_struct("ServiceError")
            .field("reason_code", &self.diagnostic.code().as_str())
            .field("component", &self.diagnostic.component())
            .field("source", &self.source)
            .finish()
    }
}

impl fmt::Display for ServiceError {
    /// The code, and only the code.
    ///
    /// ADR-0015 §11.2 rule 4: "the code is the contract; the human text is not".
    /// A `Display` that rendered a sentence would be the second text authority
    /// rule 5 forbids, arriving through the back door.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.diagnostic.code().as_str())
    }
}

impl std::error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|e| e as _)
    }
}

impl From<Reject> for ServiceError {
    /// A validator's reject, observed by the coordination service.
    ///
    /// A service that observes it elsewhere uses [`ServiceError::from_reject`]
    /// with its own `Component`.
    fn from(r: Reject) -> Self {
        Self::from_reject(&r, Component::CoordinationService)
    }
}
