//! Component tests for the emit-time redaction layer.
//!
//! The forbidden-attribute case is the one that must never regress: a record
//! carrying a `filter/forbidden` key is dropped WHOLE, not sanitised.

use tracing_subscriber::prelude::*;
use twinvpn_service_common::metrics::Metrics;
use twinvpn_service_common::obs::layer::*;

fn with_layer<F: FnOnce()>(f: F) -> (Vec<String>, Metrics) {
    let sink = CapturingSink::new();
    let metrics = Metrics::new();
    let layer = RedactingLayer::new(LogFormat::Json, sink.clone(), metrics.clone());
    let sub = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(sub, f);
    (sink.records(), metrics)
}

#[test]
fn a_forbidden_field_drops_the_whole_record_and_counts_it() {
    let (records, metrics) = with_layer(|| {
        tracing::info!(
            twinvpn.reason_code = "NET.NO_ROUTE",
            twinvpn.session_id = "deadbeef",
            "a session failed"
        );
    });
    assert!(
        records.is_empty(),
        "the record must be dropped whole, not sanitised: {records:?}"
    );
    let rendered = metrics.render();
    assert!(
        rendered.contains(&format!(
            "{} 1",
            twinvpn_service_common::metrics::names::FORBIDDEN_ATTR_DROPPED
        )),
        "{rendered}"
    );
}

#[test]
fn a_non_allowlisted_field_is_deleted_but_the_record_survives() {
    let (records, metrics) = with_layer(|| {
        tracing::info!(twinvpn.outcome = "success", my_new_idea = 42, "attached");
    });
    assert_eq!(records.len(), 1);
    assert!(records[0].contains("twinvpn.outcome"));
    assert!(!records[0].contains("my_new_idea"), "{}", records[0]);
    assert!(metrics.render().contains(&format!(
        "{} 1",
        twinvpn_service_common::metrics::names::ATTR_NOT_ALLOWLISTED
    )));
}

#[test]
fn a_credential_shaped_value_on_an_allowlisted_key_is_replaced() {
    let secret = "A".repeat(64);
    let (records, metrics) = with_layer(|| {
        tracing::info!(twinvpn.outcome = tracing::field::display(&secret), "x");
    });
    assert_eq!(records.len(), 1);
    assert!(!records[0].contains(&secret), "{}", records[0]);
    assert!(records[0].contains("<redacted:blocked-value>"));
    assert!(metrics.render().contains(&format!(
        "{} 1",
        twinvpn_service_common::metrics::names::BLOCKED_VALUE_REDACTED
    )));
}

#[test]
fn span_fields_reach_every_event_inside_the_span() {
    let (records, _) = with_layer(|| {
        let span = tracing::info_span!(
            "request",
            twinvpn.correlation_id = "0f0f",
            twinvpn.causation_id = "1a1a"
        );
        let _g = span.enter();
        tracing::info!("inside");
    });
    assert_eq!(records.len(), 1);
    assert!(records[0].contains("0f0f"), "{}", records[0]);
    assert!(records[0].contains("1a1a"), "{}", records[0]);
}

#[test]
fn an_error_field_does_not_reach_the_record() {
    let (records, _) = with_layer(|| {
        let e = std::io::Error::other("connect to 203.0.113.7:5432 failed");
        tracing::error!(error = &e as &dyn std::error::Error, "db down");
    });
    assert_eq!(records.len(), 1);
    assert!(!records[0].contains("203.0.113.7"), "{}", records[0]);
}

#[test]
fn credential_detection_covers_the_collector_patterns() {
    assert!(looks_like_credential("Bearer abc.def.ghi"));
    assert!(looks_like_credential(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nx"
    ));
    assert!(looks_like_credential(&"a".repeat(40)));
    assert!(looks_like_credential(&"0123456789abcdef".repeat(4)));
    assert!(!looks_like_credential("NET.NO_ROUTE"));
    assert!(!looks_like_credential("v6"));
}

#[test]
fn a_long_value_is_bounded() {
    let (records, _) = with_layer(|| {
        let long = "x y ".repeat(1000);
        tracing::info!("{long}");
    });
    assert!(records[0].len() < 1200, "{}", records[0].len());
}
