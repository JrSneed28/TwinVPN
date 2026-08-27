//! `ErrorEnvelope` conversion, in both directions.
//!
//! **Authority:** `contracts/proto/twinvpn/v1/errors.proto`, ADR-0015 §11.2
//! rule 5, ADR-0018 F-4.
//!
//! # Two rules the decode side exists to enforce
//!
//! 1. **`domain` must match `reason_code`'s prefix.** `errors.proto`: the field
//!    is carried redundantly "so a receiver can degrade without string-splitting
//!    attacker-supplied input. A receiver MUST verify it matches the prefix of
//!    `reason_code` and MUST reject the envelope on disagreement — a mismatched
//!    pair is **an attempt to make a condition render under the wrong domain**."
//! 2. **A received `resolved` block is a claim, not a fact.** ADR-0015 §11.2
//!    rule 5: prefer the local registry entry when the code is recognised, and
//!    fall back to the carried attributes only for a code this build does not
//!    know. [`DecodedEnvelope`] therefore keeps the two apart rather than merging
//!    them, so a caller cannot use a peer's claim about a code we already know.

use twinvpn_types::evidence::EvidenceValue;
use twinvpn_types::{
    AddressFamily, Component, ConnectionState, Diagnostic, DiagnosticScope, Domain, ErrorClass,
    ErrorSeverity, Evidence, EvidenceSet, FieldClassification, Identifier, ObservedReasonCode,
    ReasonCode, RemediationClass, ResolvedAttributes,
};

use crate::reject::Reject;
use crate::v1;
use crate::validate;

/// A received `ErrorEnvelope`, with the local and carried attributes separate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedEnvelope {
    /// The code, registered here or merely well-formed.
    pub code: ObservedReasonCode,
    /// The observing component, when it decoded.
    pub component: Option<Component>,
    /// The attributes the **emitter** claimed.
    ///
    /// Use these **only** when [`DecodedEnvelope::code`] is
    /// [`ObservedReasonCode::Unregistered`]. For a code this build knows, the
    /// local registry entry wins.
    pub carried: Option<ResolvedAttributesClaim>,
    /// Evidence, with every undeclared key already dropped.
    pub evidence: Vec<DecodedEvidence>,
    /// Contributing codes, most specific first.
    pub contributing: Vec<ObservedReasonCode>,
    /// The transition this accompanied, if any.
    pub transition: Option<(ConnectionState, ConnectionState)>,
    /// The emitter's wall clock at observation. Advisory.
    pub occurred_at_ms: Option<u64>,
}

impl DecodedEnvelope {
    /// The attributes to act on.
    ///
    /// Prefers this build's own registry entry, exactly as ADR-0015 §11.2 rule 5
    /// requires, and falls back to the carried claim only for a code this build
    /// does not know — which is the whole reason the claim is on the wire.
    #[must_use]
    pub fn effective_attributes(&self) -> Option<ResolvedAttributes> {
        match &self.code {
            ObservedReasonCode::Registered(code) => Some(local_attributes(*code)),
            ObservedReasonCode::Unregistered { .. } => None,
        }
    }

    /// The domain to degrade on when the code is unknown.
    #[must_use]
    pub fn degrade_domain(&self) -> Domain {
        self.code.domain()
    }
}

/// The emitter's claimed attributes, for an unknown code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedAttributesClaim {
    /// Claimed class.
    pub class: Option<ErrorClass>,
    /// Claimed severity.
    pub severity: Option<ErrorSeverity>,
    /// Claimed terminality.
    pub terminal: bool,
    /// Claimed actionability.
    pub user_actionable: bool,
    /// Claimed remediation shape.
    pub remediation_class: Option<RemediationClass>,
    /// Claimed scope.
    pub scope: Option<DiagnosticScope>,
}

/// One decoded evidence entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedEvidence {
    /// The key, bounded and shape-checked.
    pub key: String,
    /// The stricter of the carried classification and this build's own.
    pub classification: FieldClassification,
    /// The typed value.
    pub value: EvidenceValue,
}

/// Encodes a [`Diagnostic`] for the wire.
///
/// `resolved` is filled from **this build's** registry, never from a field on
/// the diagnostic, so the block cannot disagree with the code it accompanies. It
/// is present for every code — "that is its whole purpose: an unknown code still
/// arrives with its severity, terminality and actionability intact".
#[must_use]
pub fn encode(diagnostic: &Diagnostic) -> v1::ErrorEnvelope {
    let code = diagnostic.code();
    let mut evidence: Vec<v1::Evidence> = diagnostic
        .evidence()
        .entries()
        .iter()
        .map(encode_evidence)
        .collect();
    // The emitter appends the truncation marker, never the receiver.
    if let Some((key, value)) = diagnostic.evidence().truncation_marker() {
        evidence.push(v1::Evidence {
            key: key.to_owned(),
            classification: FieldClassification::Operational as i32,
            value: Some(encode_value(&value)),
        });
    }
    v1::ErrorEnvelope {
        reason_code: code.as_str().to_owned(),
        domain: code.domain().as_str().to_owned(),
        resolved: Some(encode_resolved(code)),
        component: diagnostic.component().to_wire(),
        evidence,
        occurred_at_ms: diagnostic.occurred_at_ms().unwrap_or(0),
        correlation_id: diagnostic
            .correlation_id()
            .map(|c| c.as_bytes().to_vec())
            .unwrap_or_default(),
        state_from: diagnostic
            .transition()
            .map_or(0, |t| t.from.to_wire().unsigned_abs()),
        state_to: diagnostic
            .transition()
            .map_or(0, |t| t.to.to_wire().unsigned_abs()),
        contributing_reason_codes: diagnostic
            .contributing()
            .iter()
            .map(|c| c.as_str().to_owned())
            .collect(),
    }
}

/// Decodes a received `ErrorEnvelope`.
///
/// # Errors
///
/// [`Reject::Malformed`] if `reason_code` is not well formed, if its `domain` is
/// outside the closed set, or if `domain` disagrees with the code's prefix;
/// [`Reject::CapViolated`] if the evidence exceeds its caps.
pub fn decode(msg: &v1::ErrorEnvelope) -> Result<DecodedEnvelope, Reject> {
    let code = ObservedReasonCode::parse(&msg.reason_code)
        .map_err(|e| Reject::malformed("reason_code", e))?;

    // Rule from errors.proto: a mismatched pair is an attempt to make a
    // condition render under the wrong domain. Rejected, never reconciled.
    if !msg.domain.is_empty() && msg.domain != code.domain().as_str() {
        return Err(Reject::cap("error_envelope.domain_matches_prefix", 0, 1));
    }

    validate::evidence_caps(msg.evidence.len(), evidence_bytes(&msg.evidence))?;

    let local = code.registered();
    let mut evidence = Vec::with_capacity(msg.evidence.len().min(32));
    for e in &msg.evidence {
        // An undeclared key is an unclassified key, and an unclassified key
        // cannot be redacted correctly — so it is DROPPED, exactly as ADR-0015
        // §11.3 requires, rather than rejecting the whole envelope.
        if let Some(decoded) = decode_evidence(e, local) {
            evidence.push(decoded);
        }
    }

    let contributing = msg
        .contributing_reason_codes
        .iter()
        .filter_map(|c| ObservedReasonCode::parse(c).ok())
        .collect();

    let transition = match (
        ConnectionState::from_wire(i32::try_from(msg.state_from).unwrap_or(-1)),
        ConnectionState::from_wire(i32::try_from(msg.state_to).unwrap_or(-1)),
    ) {
        (Ok(from), Ok(to))
            if from != ConnectionState::Unspecified && to != ConnectionState::Unspecified =>
        {
            Some((from, to))
        }
        _ => None,
    };

    Ok(DecodedEnvelope {
        code,
        component: Component::from_wire(msg.component).ok(),
        carried: msg.resolved.as_ref().map(decode_resolved),
        evidence,
        contributing,
        transition,
        // Zero is "no timestamp", not 1970: CD-1a's reason, on the receive side.
        occurred_at_ms: (msg.occurred_at_ms != 0).then_some(msg.occurred_at_ms),
    })
}

fn local_attributes(code: ReasonCode) -> ResolvedAttributes {
    ResolvedAttributes {
        class: code.class(),
        severity: code.severity(),
        terminal: code.terminal(),
        user_actionable: code.user_actionable(),
        remediation_class: code.remediation_class(),
        scope: code.scope(),
        doc_anchor: code.doc_anchor(),
        summary_key: code.summary_key(),
        next_action_key: code.next_action_key(),
    }
}

fn encode_resolved(code: ReasonCode) -> v1::ResolvedAttributes {
    v1::ResolvedAttributes {
        class: code.class() as i32,
        severity: code.severity() as i32,
        terminal: code.terminal(),
        user_actionable: code.user_actionable(),
        remediation_class: code.remediation_class() as i32,
        scope: code.scope() as i32,
        doc_anchor: code.doc_anchor().to_owned(),
        summary_key: code.summary_key().to_owned(),
        next_action_key: code.next_action_key().unwrap_or_default().to_owned(),
    }
}

fn decode_resolved(msg: &v1::ResolvedAttributes) -> ResolvedAttributesClaim {
    ResolvedAttributesClaim {
        class: match msg.class {
            1 => Some(ErrorClass::Transient),
            2 => Some(ErrorClass::Persistent),
            3 => Some(ErrorClass::Policy),
            4 => Some(ErrorClass::Fatal),
            _ => None,
        },
        severity: match msg.severity {
            1 => Some(ErrorSeverity::Info),
            2 => Some(ErrorSeverity::Warn),
            3 => Some(ErrorSeverity::Error),
            4 => Some(ErrorSeverity::Critical),
            _ => None,
        },
        terminal: msg.terminal,
        user_actionable: msg.user_actionable,
        remediation_class: match msg.remediation_class {
            1 => Some(RemediationClass::None),
            2 => Some(RemediationClass::Wait),
            3 => Some(RemediationClass::LocalAction),
            4 => Some(RemediationClass::PeerAction),
            5 => Some(RemediationClass::PolicyChange),
            6 => Some(RemediationClass::UpdateRequired),
            7 => Some(RemediationClass::NetworkChange),
            8 => Some(RemediationClass::PermissionGrant),
            9 => Some(RemediationClass::ReportDefect),
            _ => None,
        },
        scope: match msg.scope {
            1 => Some(DiagnosticScope::Session),
            2 => Some(DiagnosticScope::Twinnet),
            3 => Some(DiagnosticScope::Device),
            4 => Some(DiagnosticScope::Path),
            5 => Some(DiagnosticScope::Relay),
            _ => None,
        },
    }
}

fn encode_evidence(e: &Evidence) -> v1::Evidence {
    v1::Evidence {
        key: e.key().to_owned(),
        classification: e.classification() as i32,
        value: Some(encode_value(e.value())),
    }
}

fn encode_value(v: &EvidenceValue) -> v1::evidence::Value {
    use v1::evidence::Value;
    match v {
        EvidenceValue::Text(s) => Value::StringValue(s.clone()),
        EvidenceValue::Int(i) => Value::IntValue(*i),
        EvidenceValue::Uint(u) => Value::UintValue(*u),
        EvidenceValue::Bool(b) => Value::BoolValue(*b),
        EvidenceValue::Address(a) => Value::AddressValue(encode_address(*a)),
        EvidenceValue::Prefix(p) => Value::PrefixValue(v1::IpPrefix {
            address: Some(encode_address(p.address())),
            prefix_len: p.prefix_len(),
        }),
        EvidenceValue::Family(f) => Value::FamilyValue(*f as i32),
        EvidenceValue::DurationMs(d) => Value::DurationMsValue(*d),
    }
}

/// Encodes a domain address into the frozen wire form, zone index included.
#[must_use]
pub fn encode_address(addr: twinvpn_types::IpAddr) -> v1::IpAddress {
    use twinvpn_types::IpAddr;
    v1::IpAddress {
        address: Some(match addr {
            IpAddr::V4(a) => v1::ip_address::Address::V4(v1::IPv4Address {
                octets: a.octets().to_vec(),
            }),
            IpAddr::V6(a) => v1::ip_address::Address::V6(v1::IPv6Address {
                octets: a.octets().to_vec(),
                zone_index: a.zone_index_wire(),
            }),
        }),
    }
}

fn decode_evidence(e: &v1::Evidence, code: Option<ReasonCode>) -> Option<DecodedEvidence> {
    twinvpn_types::evidence::validate_key(&e.key).ok()?;
    // Drop, do not reject: ADR-0015 §11.3.
    if let Some(code) = code {
        if !code.declares_evidence(&e.key)
            && e.key != twinvpn_types::evidence::EVIDENCE_TRUNCATED_KEY
        {
            return None;
        }
    }
    let value = decode_value(e.value.as_ref()?)?;
    let carried = match e.classification {
        1 => FieldClassification::Public,
        2 => FieldClassification::Operational,
        // An unrecognised or absent classification is treated as SENSITIVE. The
        // safe direction: an unclassified field that renders as PUBLIC is a leak,
        // while one that renders as SENSITIVE is merely over-redacted.
        _ => FieldClassification::Sensitive,
    };
    Some(DecodedEvidence {
        classification: carried.stricter(value.intrinsic_classification()),
        key: e.key.clone(),
        value,
    })
}

fn decode_value(v: &v1::evidence::Value) -> Option<EvidenceValue> {
    use v1::evidence::Value;
    Some(match v {
        Value::StringValue(s) => EvidenceValue::Text(s.clone()),
        Value::IntValue(i) => EvidenceValue::Int(*i),
        Value::UintValue(u) => EvidenceValue::Uint(*u),
        Value::BoolValue(b) => EvidenceValue::Bool(*b),
        Value::AddressValue(a) => EvidenceValue::Address(validate::ip_address(a).ok()?),
        Value::PrefixValue(p) => EvidenceValue::Prefix(validate::ip_prefix(p).ok()?),
        Value::FamilyValue(f) => EvidenceValue::Family(match f {
            1 => AddressFamily::V4,
            2 => AddressFamily::V6,
            _ => return None,
        }),
        Value::DurationMsValue(d) => EvidenceValue::DurationMs(*d),
    })
}

fn evidence_bytes(entries: &[v1::Evidence]) -> usize {
    entries
        .iter()
        .map(|e| {
            e.key.len()
                + 4
                + match &e.value {
                    Some(v1::evidence::Value::StringValue(s)) => s.len(),
                    Some(_) => 24,
                    None => 0,
                }
        })
        .sum()
}

/// Rebuilds a [`Diagnostic`] from a decoded envelope, when the code is one this
/// build knows.
///
/// Returns `None` for an unregistered code: a `Diagnostic` can only carry a
/// registered code, and manufacturing one from a peer's claim would put an
/// unregistered string into this device's own diagnostics.
#[must_use]
pub fn to_diagnostic(decoded: &DecodedEnvelope) -> Option<Diagnostic> {
    let code = decoded.code.registered()?;
    let component = decoded.component.unwrap_or(Component::Diagnostics);
    let mut set = EvidenceSet::new();
    for e in &decoded.evidence {
        if let Some(key) = code
            .evidence_fields()
            .iter()
            .find(|k| **k == e.key.as_str())
        {
            if let Ok(entry) = Evidence::new(code, key, e.value.clone()) {
                set.push(entry.with_classification_floor(e.classification));
            }
        }
    }
    Some(rebuild(code, component, decoded, &set))
}

fn rebuild(
    code: ReasonCode,
    component: Component,
    decoded: &DecodedEnvelope,
    set: &EvidenceSet,
) -> Diagnostic {
    let mut builder = Diagnostic::builder(code, component).occurred_at_ms(decoded.occurred_at_ms);
    for entry in set.entries() {
        builder = builder.evidence_entry(entry.clone());
    }
    if let Some((from, to)) = decoded.transition {
        builder = builder.transition(from, to);
    }
    for c in &decoded.contributing {
        if let Some(registered) = c.registered() {
            builder = builder.contributing(registered);
        }
    }
    builder.build()
}
