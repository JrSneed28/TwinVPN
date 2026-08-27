//! [`Diagnostic`] — the one failure carrier every other crate maps into.
//!
//! **Authority:** `contracts/proto/twinvpn/v1/errors.proto` (`ErrorEnvelope`,
//! `ResolvedAttributes`), ADR-0015 §11.3, ADR-0018 F-4.
//!
//! `errors.proto` says it plainly: "There is deliberately no second error
//! shape." One envelope serves a non-success C1 response, a diagnostic attached
//! to a `DEGRADED`/`BLOCKED`/`FAILED` transition, an ABI failure return, and a
//! bundle entry. This is that shape, in domain terms; `twinvpn-schema` converts
//! it to and from the wire.
//!
//! # `ResolvedAttributes` is derived, never stored
//!
//! Nothing here holds a `class`, `severity` or `terminal` field. They are read
//! from the [`ReasonCode`]'s registry entry on demand ([`Diagnostic::resolved`]),
//! so a locally emitted diagnostic cannot disagree with the registry. ADR-0015
//! §11.2 rule 5 is the other half: on **receipt**, a consumer prefers its own
//! registry entry and falls back to the carried attributes only for a code it
//! does not know — which is why `twinvpn-schema`'s decode returns a carried
//! attribute block separately rather than folding it in here.

use crate::evidence::{Evidence, EvidenceSet};
use crate::id::{CorrelationId, MessageId};
use crate::reason::{
    codes, DiagnosticScope, ErrorClass, ErrorSeverity, ReasonCode, RemediationClass,
};
use crate::state::ConnectionState;
use crate::TypeError;

/// The component that **observed** the condition (ADR-0015 §11.3).
///
/// This is the observer, not the blamed party: "a relay failure observed by the
/// tunnel engine carries `COMPONENT_TUNNEL_ENGINE` and a `RELAY.*` reason_code."
/// Mirrors `twinvpn.v1.Component`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(missing_docs)]
pub enum Component {
    TunnelEngine = 1,
    RoutingEngine = 2,
    PlatformAdapter = 3,
    DeviceIdentity = 4,
    Pairing = 5,
    ControlPlaneClient = 6,
    RendezvousClient = 7,
    NatTraversal = 8,
    RelayClient = 9,
    RelaySelection = 10,
    Presence = 11,
    PolicyEngine = 12,
    Dns = 13,
    KillSwitch = 14,
    LanDiscovery = 15,
    ExitNode = 16,
    Diagnostics = 17,
    Store = 18,
    Update = 19,
    ManagementInterface = 20,
    CoordinationService = 21,
    RelayServer = 22,
}

impl Component {
    /// Decodes a wire value.
    pub const fn from_wire(value: i32) -> Result<Self, TypeError> {
        match value {
            1 => Ok(Component::TunnelEngine),
            2 => Ok(Component::RoutingEngine),
            3 => Ok(Component::PlatformAdapter),
            4 => Ok(Component::DeviceIdentity),
            5 => Ok(Component::Pairing),
            6 => Ok(Component::ControlPlaneClient),
            7 => Ok(Component::RendezvousClient),
            8 => Ok(Component::NatTraversal),
            9 => Ok(Component::RelayClient),
            10 => Ok(Component::RelaySelection),
            11 => Ok(Component::Presence),
            12 => Ok(Component::PolicyEngine),
            13 => Ok(Component::Dns),
            14 => Ok(Component::KillSwitch),
            15 => Ok(Component::LanDiscovery),
            16 => Ok(Component::ExitNode),
            17 => Ok(Component::Diagnostics),
            18 => Ok(Component::Store),
            19 => Ok(Component::Update),
            20 => Ok(Component::ManagementInterface),
            21 => Ok(Component::CoordinationService),
            22 => Ok(Component::RelayServer),
            0 => Err(TypeError::EnumUnspecified {
                enum_name: "twinvpn.v1.Component",
            }),
            observed => Err(TypeError::ConnectionStateUnknown { observed }),
        }
    }

    /// The wire value.
    #[must_use]
    pub const fn to_wire(self) -> i32 {
        self as i32
    }
}

/// The registry attributes for a code, as `ResolvedAttributes` carries them.
///
/// Every field is machine-readable metadata. **No field is localised and none is
/// a sentence**: `errors.proto` explicitly prohibits adding a `summary`,
/// `message` or `title`, because that would place a second text authority outside
/// the registry, breach ADR-0018 CB-4, and breach ADR-0017 MI-15.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedAttributes {
    /// How the condition behaves over time.
    pub class: ErrorClass,
    /// Its severity.
    pub severity: ErrorSeverity,
    /// Whether it ends the current attempt. Read with `scope`.
    pub terminal: bool,
    /// Whether an Owner can act. Implies `next_action_key.is_some()`.
    pub user_actionable: bool,
    /// The shape of the remediation.
    pub remediation_class: RemediationClass,
    /// What the condition applies to.
    pub scope: DiagnosticScope,
    /// Stable documentation anchor.
    pub doc_anchor: &'static str,
    /// Catalogue lookup key for the summary. Not text.
    pub summary_key: &'static str,
    /// Catalogue lookup key for the next action. Not text.
    pub next_action_key: Option<&'static str>,
}

/// A transition this diagnostic accompanied.
///
/// Both endpoints or neither: `errors.proto` gives `state_from`/`state_to` the
/// convention "zero means not a transition", and an `Option` of a pair says the
/// same thing without letting half of one be set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateTransition {
    /// The state left.
    pub from: ConnectionState,
    /// The state entered.
    pub to: ConnectionState,
}

/// The single canonical failure carrier.
///
/// Built through [`DiagnosticBuilder`], so that a diagnostic without a registered
/// code is not constructible.
#[derive(Debug, Clone, PartialEq)]
pub struct Diagnostic {
    code: ReasonCode,
    component: Component,
    evidence: EvidenceSet,
    correlation_id: Option<CorrelationId>,
    transition: Option<StateTransition>,
    contributing: Vec<ReasonCode>,
    occurred_at_ms: Option<u64>,
}

impl Diagnostic {
    /// Starts building a diagnostic.
    #[must_use]
    pub fn builder(code: ReasonCode, component: Component) -> DiagnosticBuilder {
        DiagnosticBuilder {
            diagnostic: Diagnostic {
                code,
                component,
                evidence: EvidenceSet::new(),
                correlation_id: None,
                transition: None,
                contributing: Vec::new(),
                occurred_at_ms: None,
            },
        }
    }

    /// The `INTERNAL.INVARIANT_VIOLATED` diagnostic, with its declared
    /// `invariant` evidence.
    ///
    /// ADR-0015: "A state-machine or ownership invariant did not hold. **Every
    /// occurrence is a defect.**" It is a constructor rather than a macro so
    /// that the call sites are greppable.
    #[must_use]
    pub fn invariant_violated(component: Component, invariant: &'static str) -> Self {
        let mut evidence = EvidenceSet::new();
        if let Ok(e) = Evidence::new(
            codes::INTERNAL_INVARIANT_VIOLATED,
            "invariant",
            crate::evidence::EvidenceValue::Text(invariant.to_owned()),
        ) {
            evidence.push(e);
        }
        Diagnostic {
            code: codes::INTERNAL_INVARIANT_VIOLATED,
            component,
            evidence,
            correlation_id: None,
            transition: None,
            contributing: Vec::new(),
            occurred_at_ms: None,
        }
    }

    /// The registered code.
    #[must_use]
    pub const fn code(&self) -> ReasonCode {
        self.code
    }

    /// The observing component.
    #[must_use]
    pub const fn component(&self) -> Component {
        self.component
    }

    /// The attached evidence.
    #[must_use]
    pub const fn evidence(&self) -> &EvidenceSet {
        &self.evidence
    }

    /// The `message_id` this failure answers, when there is one.
    #[must_use]
    pub const fn correlation_id(&self) -> Option<CorrelationId> {
        self.correlation_id
    }

    /// The transition this accompanied, when it accompanied one.
    #[must_use]
    pub const fn transition(&self) -> Option<StateTransition> {
        self.transition
    }

    /// Additional codes observed in the same failure, **most specific first**.
    ///
    /// `docs/reliability.md` T12 requires the most specific transport code
    /// observed, never a generic one; this list is what lets the specific code be
    /// primary while its contributing observations stay attached rather than
    /// being discarded.
    #[must_use]
    pub fn contributing(&self) -> &[ReasonCode] {
        &self.contributing
    }

    /// The emitter's wall clock at observation, if it had a usable one.
    ///
    /// `Option`, not a bare `u64`, because ADR-0018 CD-1a makes the wall clock a
    /// three-state value: a device with no RTC has no timestamp to give, and
    /// writing a zero would render as 1970.
    #[must_use]
    pub const fn occurred_at_ms(&self) -> Option<u64> {
        self.occurred_at_ms
    }

    /// The registry attributes, derived from the code.
    #[must_use]
    pub fn resolved(&self) -> ResolvedAttributes {
        ResolvedAttributes {
            class: self.code.class(),
            severity: self.code.severity(),
            terminal: self.code.terminal(),
            user_actionable: self.code.user_actionable(),
            remediation_class: self.code.remediation_class(),
            scope: self.code.scope(),
            doc_anchor: self.code.doc_anchor(),
            summary_key: self.code.summary_key(),
            next_action_key: self.code.next_action_key(),
        }
    }
}

impl From<TypeError> for Diagnostic {
    /// Maps a construction-time rejection onto its registered code, carrying the
    /// registry-declared `{cap_violated, observed, limit}` evidence where the
    /// variant has it.
    ///
    /// `ownership.md` §6 rule 12: "Expose registered `reason_code`s, never raw
    /// internal errors." This impl is what makes `?` do that automatically at a
    /// component boundary.
    fn from(err: TypeError) -> Self {
        use crate::evidence::EvidenceValue;

        let code = err.reason_code();
        let mut builder = Diagnostic::builder(code, Component::Diagnostics);
        if let Some(cap) = err.cap_violated() {
            builder = builder.evidence("cap_violated", EvidenceValue::Text(cap.to_owned()));
        }
        match &err {
            TypeError::IdentifierLength {
                expected, observed, ..
            } => {
                builder = builder
                    .evidence("observed", EvidenceValue::Uint(*observed as u64))
                    .evidence("limit", EvidenceValue::Uint(*expected as u64));
            }
            TypeError::IdentifierRange { max, observed, .. } => {
                builder = builder
                    .evidence("observed", EvidenceValue::Uint(*observed as u64))
                    .evidence("limit", EvidenceValue::Uint(*max as u64));
            }
            TypeError::TextIdentifierTooLong {
                limit, observed, ..
            } => {
                builder = builder
                    .evidence("observed", EvidenceValue::Uint(*observed as u64))
                    .evidence("limit", EvidenceValue::Uint(*limit as u64));
            }
            TypeError::PrefixLength { observed, limit } => {
                builder = builder
                    .evidence("observed", EvidenceValue::Uint(u64::from(*observed)))
                    .evidence("limit", EvidenceValue::Uint(u64::from(*limit)));
            }
            _ => {}
        }
        builder.build()
    }
}

/// Builds a [`Diagnostic`].
///
/// Evidence that the registry does not declare for the code is **dropped
/// silently by the builder** rather than failing the build. That is deliberate:
/// a diagnostic is often constructed on a failure path, and turning "this code
/// does not declare that key" into a second failure would lose the original
/// condition. The declared-key rule is still enforced — the entry simply does not
/// appear — and [`Evidence::new`] is available where a caller wants the error.
#[derive(Debug, Clone)]
pub struct DiagnosticBuilder {
    diagnostic: Diagnostic,
}

impl DiagnosticBuilder {
    /// Attaches evidence, if the registry declares the key for this code.
    #[must_use]
    pub fn evidence(mut self, key: &'static str, value: crate::evidence::EvidenceValue) -> Self {
        if let Ok(e) = Evidence::new(self.diagnostic.code, key, value) {
            self.diagnostic.evidence.push(e);
        }
        self
    }

    /// Attaches an already-built evidence entry.
    #[must_use]
    pub fn evidence_entry(mut self, evidence: Evidence) -> Self {
        self.diagnostic.evidence.push(evidence);
        self
    }

    /// Sets the `message_id` this failure answers.
    #[must_use]
    pub fn correlated_to(mut self, message_id: MessageId) -> Self {
        self.diagnostic.correlation_id =
            CorrelationId::from_slice(crate::id::Identifier::as_bytes(&message_id)).ok();
        self
    }

    /// Records the transition this diagnostic accompanied.
    #[must_use]
    pub fn transition(mut self, from: ConnectionState, to: ConnectionState) -> Self {
        self.diagnostic.transition = Some(StateTransition { from, to });
        self
    }

    /// Appends a contributing code. Callers add these **most specific first**.
    #[must_use]
    pub fn contributing(mut self, code: ReasonCode) -> Self {
        self.diagnostic.contributing.push(code);
        self
    }

    /// Records when the condition was observed, on the emitter's wall clock.
    ///
    /// The caller obtains this from `twinvpn_env::WallClock`, which returns a
    /// three-state value; `None` is the correct answer on a device whose clock is
    /// `Unset`.
    #[must_use]
    pub fn occurred_at_ms(mut self, ms: Option<u64>) -> Self {
        self.diagnostic.occurred_at_ms = ms;
        self
    }

    /// Finishes the diagnostic.
    #[must_use]
    pub fn build(self) -> Diagnostic {
        self.diagnostic
    }
}
