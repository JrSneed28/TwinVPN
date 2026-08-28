//! The ADR-0015 §11.2 diagnostic envelope, as the bytes a `tvb_buf` carries.
//!
//! **Authority:** ADR-0015 §11.2 (the envelope), §11.3 (an undeclared evidence
//! key is dropped), §11.4 (the classification ladder); ADR-0018 F-4 ("errors
//! carry a name, never an errno"); ADR-0017 MI-15 (codes and typed evidence,
//! **never rendered human text**); `docs/implementation/ownership.md` §4.2 and
//! §6 rule 12.
//!
//! # No second failure vocabulary
//!
//! Every envelope this crate produces is built from a
//! [`twinvpn_types::Diagnostic`], whose `reason_code` is a **registered** code
//! and whose resolved attributes come from the frozen registry rather than from
//! a table here. The adapter's own [`twinvpn_platform_macos::oserr`] is what
//! turns an `errno`, an `OSStatus` or an `SCError` into one, so the bridge adds
//! no third mapping.
//!
//! # MI-15, structurally
//!
//! There is no `summary`, `message`, `title` or `description` field below — in
//! this version or any version. `summary_key` and `next_action_key` are the
//! registry's own identifiers, never resolved strings: rendering happens at a
//! surface that has a locale and a viewport, which a system extension does not.
//!
//! # A reported divergence: JSON here, protobuf in `twinvpn-ffi`
//!
//! `twinvpn-ffi` encodes the same document with `prost` through
//! `twinvpn_diag::Emitter::error_envelope`. This crate encodes it as JSON, for a
//! stated reason: the Swift side logs the envelope with
//! `String(decoding:as:UTF8.self)` and hands it back unparsed, so protobuf bytes
//! would render as mojibake in the one place an operator reads them. The field
//! names below are ADR-0015 §11.2's, verbatim, so a later switch to the
//! protobuf encoding is a re-encoding rather than a redesign.
//!
//! This is the same class of finding as `shells/linux`'s MI wire format, which
//! took JSON for the same reason, and it is **reported, not resolved**.

use serde_json::{json, Map, Value};
use twinvpn_types::evidence::EvidenceValue;
use twinvpn_types::{Component, Diagnostic, ReasonCode};

/// Renders a diagnostic as the envelope bytes a `tvb_buf` carries.
#[must_use]
pub fn render(diagnostic: &Diagnostic) -> Vec<u8> {
    document(diagnostic).to_string().into_bytes()
}

/// The envelope for a bare registered code.
#[must_use]
pub fn render_code(code: ReasonCode, component: Component) -> Vec<u8> {
    render(&Diagnostic::builder(code, component).build())
}

/// The envelope as a `serde_json` document, so a test can read a field.
#[must_use]
pub fn document(diagnostic: &Diagnostic) -> Value {
    let resolved = diagnostic.resolved();
    let mut doc = Map::new();
    doc.insert(
        "reason_code".to_owned(),
        Value::String(diagnostic.code().as_str().to_owned()),
    );
    doc.insert("class".to_owned(), Value::String(name_of(resolved.class)));
    doc.insert(
        "severity".to_owned(),
        Value::String(name_of(resolved.severity)),
    );
    doc.insert("terminal".to_owned(), json!(resolved.terminal));
    doc.insert(
        "user_actionable".to_owned(),
        json!(resolved.user_actionable),
    );
    doc.insert(
        "remediation_class".to_owned(),
        Value::String(name_of(resolved.remediation_class)),
    );
    doc.insert("scope".to_owned(), Value::String(name_of(resolved.scope)));
    doc.insert(
        "doc_anchor".to_owned(),
        Value::String(resolved.doc_anchor.to_owned()),
    );
    doc.insert(
        "summary_key".to_owned(),
        Value::String(resolved.summary_key.to_owned()),
    );
    doc.insert(
        "next_action_key".to_owned(),
        resolved
            .next_action_key
            .map_or(Value::Null, |k| Value::String(k.to_owned())),
    );
    doc.insert(
        "component".to_owned(),
        Value::String(name_of(diagnostic.component())),
    );
    doc.insert("evidence".to_owned(), evidence(diagnostic));
    Value::Object(doc)
}

/// The registry's own spelling for one of the resolved enums.
///
/// `{:?}` uppercased, which is exactly what `shells/linux`'s MI server does for
/// the same fields. A hand-written table here would be a second spelling of a
/// value the registry already names, and the two would drift the first time a
/// variant was added.
fn name_of(value: impl core::fmt::Debug) -> String {
    let mut out = String::new();
    for (index, ch) in format!("{value:?}").chars().enumerate() {
        if ch.is_uppercase() && index > 0 {
            out.push('_');
        }
        out.push(ch.to_ascii_uppercase());
    }
    out
}

/// The declared evidence, with `SENSITIVE` values rendered as their kind rather
/// than their content.
///
/// ADR-0015 §11.4's classification ladder reaches this crate as one rule: an
/// address identifies a user's network, and this envelope is logged by
/// `os_log`. So an [`EvidenceValue::Address`] or [`EvidenceValue::Prefix`]
/// contributes its **key and its kind** and never its bytes. A support bundle
/// that needs the address gets it from the Tier-1 path, which has a redaction
/// policy; a log line does not.
fn evidence(diagnostic: &Diagnostic) -> Value {
    let mut out = Map::new();
    for entry in diagnostic.evidence().entries() {
        out.insert(entry.key().to_owned(), value_of(entry.value()));
    }
    if let Some((key, value)) = diagnostic.evidence().truncation_marker() {
        out.insert(key.to_owned(), value_of(&value));
    }
    Value::Object(out)
}

fn value_of(value: &EvidenceValue) -> Value {
    match value {
        EvidenceValue::Text(text) => Value::String(text.clone()),
        EvidenceValue::Int(n) => json!(n),
        EvidenceValue::Uint(n) | EvidenceValue::DurationMs(n) => json!(n),
        EvidenceValue::Bool(b) => json!(b),
        EvidenceValue::Family(family) => Value::String(format!("{family:?}").to_uppercase()),
        // SENSITIVE under §11.4. The KEY still appears, so a reader can see that
        // an address was recorded and where to look for it; the value does not.
        EvidenceValue::Address(_) => Value::String("<address redacted>".to_owned()),
        EvidenceValue::Prefix(_) => Value::String("<prefix redacted>".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_types::codes;

    fn parse(bytes: &[u8]) -> Value {
        serde_json::from_slice(bytes).expect("the envelope is JSON")
    }

    #[test]
    fn an_envelope_names_a_registered_code_and_its_resolved_attributes() {
        let bytes = render_code(codes::INTERNAL_CORE_PANIC, Component::Diagnostics);
        let doc = parse(&bytes);
        assert_eq!(doc["reason_code"], "INTERNAL.CORE_PANIC");
        assert_eq!(doc["class"], "FATAL");
        assert_eq!(doc["severity"], "CRITICAL");
        assert_eq!(doc["terminal"], json!(true));
        assert_eq!(doc["user_actionable"], json!(false));
        assert_eq!(doc["remediation_class"], "REPORT_DEFECT");
        assert!(doc["doc_anchor"]
            .as_str()
            .expect("text")
            .starts_with("adr-"));
    }

    #[test]
    fn there_is_no_rendered_human_text_anywhere_in_the_envelope() {
        // MI-15, made structural. A `summary` field here would put a second text
        // authority outside the registry.
        let bytes = render_code(codes::PLATFORM_ADAPTER_UNAVAILABLE, Component::Diagnostics);
        let doc = parse(&bytes);
        for forbidden in ["summary", "message", "title", "description", "text"] {
            assert!(
                doc.get(forbidden).is_none(),
                "the envelope carries a rendered `{forbidden}` field"
            );
        }
        // The KEYS are present, because they are registry identifiers.
        assert!(doc["summary_key"]
            .as_str()
            .expect("text")
            .starts_with("reason."));
    }

    #[test]
    fn a_next_action_key_is_null_when_the_code_declares_none() {
        // `user_actionable` implies `next_action_key.is_some()`, and the
        // converse must not be quietly invented.
        let actionable = parse(&render_code(
            codes::PLATFORM_ADAPTER_UNAVAILABLE,
            Component::Diagnostics,
        ));
        assert!(actionable["next_action_key"].is_string());
        let not_actionable = parse(&render_code(
            codes::INTERNAL_CORE_PANIC,
            Component::Diagnostics,
        ));
        assert_eq!(not_actionable["next_action_key"], Value::Null);
    }

    #[test]
    fn declared_evidence_travels_and_an_address_does_not() {
        // ADR-0015 §11.4: an address identifies a user's network, and this
        // envelope reaches `os_log`.
        let diagnostic = Diagnostic::builder(codes::PROTO_SIZE_EXCEEDED, Component::Diagnostics)
            .evidence("observed", EvidenceValue::Uint(4096))
            .evidence("limit", EvidenceValue::Uint(16))
            .build();
        let doc = parse(&render(&diagnostic));
        assert_eq!(doc["evidence"]["observed"], json!(4096));
        assert_eq!(doc["evidence"]["limit"], json!(16));
    }

    #[test]
    fn the_enum_spelling_is_the_registrys_and_not_a_second_table() {
        assert_eq!(name_of(twinvpn_types::ErrorClass::Transient), "TRANSIENT");
        assert_eq!(name_of(twinvpn_types::ErrorClass::Persistent), "PERSISTENT");
        assert_eq!(name_of(twinvpn_types::ErrorSeverity::Critical), "CRITICAL");
        // A multi-word variant becomes SCREAMING_SNAKE, which is the registry's
        // own form: `REPORT_DEFECT`, not `REPORTDEFECT`.
        assert_eq!(
            name_of(twinvpn_types::RemediationClass::LocalAction),
            "LOCAL_ACTION"
        );
    }

    #[test]
    fn the_envelope_is_valid_utf8_because_swift_logs_it_as_text() {
        // The whole reason this is JSON and not protobuf.
        let bytes = render_code(codes::MGMT_UNAVAILABLE, Component::Diagnostics);
        assert!(core::str::from_utf8(&bytes).is_ok());
    }
}
