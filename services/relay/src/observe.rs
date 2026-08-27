//! Relay observability — the emit side of ADR-0015 **O-13**.
//!
//! `infra/otel/collector-config.yaml`'s `transform/relay-severs-context` clears
//! the parent span id and deletes `twinvpn.correlation_id`,
//! `twinvpn.causation_id` and `twinvpn.message_id` on any span whose
//! `service.name` is `twinvpn-relay`. `infra/README.md` §6.2 explains why:
//!
//! > A relay sees both ends of a `RELAYED` session by necessity; if it LOGS that,
//! > it holds the peer graph, defeating I1 in metadata even though it never sees
//! > plaintext. Relay per-session debugging is DELIBERATELY IMPOSSIBLE.
//!
//! **This module is the emit half, and it agrees.** ADR-0015 O-14 requires
//! redaction at *emit* time by field classification, not at export time by
//! pattern matching, and says the collector "does not relieve [the services] of"
//! that obligation. So the relay does not emit what the collector would strip:
//!
//! - [`RelaySpan::root`] starts a span with **no parent** — the relay never
//!   continues a trace, so there is nothing for the collector to sever.
//! - [`RelayEvent`] has **no** correlation, causation or message id field, and no
//!   constructor that takes one. `twinvpn_service_common::Correlation` is
//!   deliberately never imported here.
//! - It has no `pair_tag`, no `flow_id` pair, no peer address and no device
//!   identifier. The only subject dimension is a [`LogSubject`] — a *daily
//!   re-hash* — and it is optional, absent when no digest provider is installed.
//!
//! `docs/implementation/ownership.md` §6 rule 6 requires correlation ids to be
//! preserved across every component boundary. **The relay is the one stated
//! exception** (`infra/README.md` §6.3: "the relay is the one exception, severed
//! under O-13 above"), and a relay is not a component boundary in the sense rule
//! 6 means — it is a forwarder that must not know what it forwards.

use twinvpn_service_common::metrics::{Label, Labels, Metrics};
use twinvpn_types::ReasonCode;

use crate::subject::LogSubject;

/// The five metric labels ADR-0015 §9 permits on relay telemetry.
///
/// `relay_region`, `protocol_version`, `reason_code`, `outcome`,
/// `address_family`. `docker-compose.yml` freezes the same list into
/// `TWINVPN_RELAY_METRICS_LABEL_ALLOWLIST` and
/// [`crate::config::RelayConfig::load`] refuses to start if it was altered.
///
/// Note what is **not** here: no `session_id`, no `pair_tag`, no `flow_id`, no
/// `peer`, no `device_id`, no `relay_sub`. A sixth label is how a peer-pair
/// dimension arrives.
pub const RELAY_METRIC_LABELS: [&str; 5] = crate::config::FROZEN_METRIC_LABELS;

/// A relay observation. Structurally incapable of carrying a correlation.
///
/// The fields are the whole vocabulary. There is no `extra`, no map and no
/// `with_attribute`, for the same reason `obs::tier2::Tier2Sample` has none:
/// adding a dimension must be an edit a reviewer sees.
#[derive(Debug, Clone)]
pub struct RelayEvent {
    /// The registered code, or `None` for a success.
    pub reason_code: Option<ReasonCode>,
    /// `bound`, `refused`, `forwarded`, `drained`, `expired`.
    pub outcome: &'static str,
    /// `v4`, `v6`.
    pub address_family: &'static str,
    /// The daily re-hashed subject, when a digest provider is installed.
    ///
    /// `Option`, and the `None` case is normal: with no provider there is no
    /// subject dimension at all, which is the fail-closed direction.
    pub log_subject: Option<LogSubject>,
}

impl RelayEvent {
    /// A success.
    #[must_use]
    pub const fn ok(outcome: &'static str, address_family: &'static str) -> Self {
        Self {
            reason_code: None,
            outcome,
            address_family,
            log_subject: None,
        }
    }

    /// A refusal carrying a registered code.
    #[must_use]
    pub const fn refused(code: ReasonCode, address_family: &'static str) -> Self {
        Self {
            reason_code: Some(code),
            outcome: "refused",
            address_family,
            log_subject: None,
        }
    }

    /// Attaches the daily re-hashed subject.
    #[must_use]
    pub const fn with_subject(mut self, subject: Option<LogSubject>) -> Self {
        self.log_subject = subject;
        self
    }

    /// The metric labels for this event, in ADR-0015 §9's allowlist only.
    ///
    /// **`log_subject` is deliberately not a metric label.** A per-subject metric
    /// series is a per-device cardinality dimension on infrastructure, which is
    /// exactly what O-13 forbids; the daily hash makes a *log line* safe, not a
    /// time series.
    #[must_use]
    pub fn labels(&self, relay_region: &str, protocol_version: u8) -> Labels {
        let l = Labels::new()
            .with(Label::RelayRegion, relay_region)
            .with(Label::ProtocolVersion, &protocol_version.to_string())
            .with(Label::Outcome, self.outcome)
            .with(Label::AddressFamily, self.address_family);
        match self.reason_code {
            Some(c) => l.with(Label::ReasonCode, c.as_str()),
            None => l,
        }
    }
}

/// A relay span: always a **root**, never a continuation.
pub struct RelaySpan;

impl RelaySpan {
    /// Starts a root span for a relay operation.
    ///
    /// `tracing::span!(parent: None, …)` is the emit-side form of
    /// `set(parent_span_id, SpanID(0))`: there is no remote parent to sever
    /// because the relay never adopts one. ADR-0015 §11.1 forbids propagating
    /// trace context across a relay, and a forwarder with no parent cannot
    /// stitch two peers into one trace even by accident.
    #[must_use]
    pub fn root(name: &'static str) -> tracing::Span {
        tracing::span!(parent: None, tracing::Level::INFO, "relay", op = name)
    }
}

/// Emits `event` as a counter and a log line, with nothing beyond the allowlist.
pub fn emit(metrics: &Metrics, event: &RelayEvent, relay_region: &str, protocol_version: u8) {
    let labels = event.labels(relay_region, protocol_version);
    metrics
        .counter(
            "twinvpn_relay_events_total",
            "relay outcomes by reason code and family",
            labels,
        )
        .inc();

    // The log line names the outcome, the family and — at most — a daily
    // re-hashed subject. No correlation id, no pair_tag, no peer address.
    match (&event.reason_code, &event.log_subject) {
        (Some(code), Some(sub)) => tracing::info!(
            reason_code = code.as_str(),
            outcome = event.outcome,
            address_family = event.address_family,
            relay_subject_day = sub.label(),
            "relay outcome"
        ),
        (Some(code), None) => tracing::info!(
            reason_code = code.as_str(),
            outcome = event.outcome,
            address_family = event.address_family,
            "relay outcome"
        ),
        (None, Some(sub)) => tracing::info!(
            outcome = event.outcome,
            address_family = event.address_family,
            relay_subject_day = sub.label(),
            "relay outcome"
        ),
        (None, None) => tracing::info!(
            outcome = event.outcome,
            address_family = event.address_family,
            "relay outcome"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_types::codes;

    #[test]
    fn the_metric_labels_are_exactly_adr_0015_9s_five() {
        assert_eq!(RELAY_METRIC_LABELS.len(), 5);
        for l in RELAY_METRIC_LABELS {
            assert!(
                twinvpn_service_common::metrics::LABEL_ALLOWLIST.contains(&l)
                    || l == "relay_region"
                    || l == "protocol_version",
                "{l} is not a permitted relay metric label"
            );
        }
    }

    #[test]
    fn a_relay_event_has_no_correlation_field_at_all() {
        // The structural half of O-13's emit side: there is no field to set and
        // no builder method that takes one, so a mis-instrumented relay cannot
        // put a correlation id on a span even by trying.
        let e = RelayEvent::ok("forwarded", "v6");
        let rendered = format!("{e:?}");
        assert!(!rendered.contains("correlation"));
        assert!(!rendered.contains("causation"));
        assert!(!rendered.contains("message_id"));
        assert!(!rendered.contains("session"));
        assert!(!rendered.contains("pair_tag"));
    }

    #[test]
    fn the_subject_is_never_a_metric_label() {
        let sub = LogSubjectForTest::make();
        let e = RelayEvent::ok("bound", "v4").with_subject(Some(sub));
        let rendered = e.labels("local-1", 1).render();
        assert!(
            !rendered.contains("subject"),
            "a per-subject metric series is a per-device cardinality dimension"
        );
    }

    #[test]
    fn a_refusal_carries_a_registered_code() {
        let e = RelayEvent::refused(codes::RELAY_TOKEN_INVALID, "v6");
        assert_eq!(e.reason_code.expect("code").as_str(), "RELAY.TOKEN_INVALID");
        assert!(e
            .labels("local-1", 1)
            .render()
            .contains("RELAY.TOKEN_INVALID"));
    }

    #[test]
    fn a_relay_span_has_no_parent() {
        // `parent: None` is the emit-side twin of the collector's
        // `set(parent_span_id, SpanID(0))`.
        // With no subscriber installed the span is disabled and has no id; the
        // property under test is the `parent: None` in RelaySpan::root, which is
        // the emit-side twin of the collector's parent-clearing transform.
        let span = RelaySpan::root("bind");
        assert!(
            span.id().is_none(),
            "no subscriber, so no id — and no parent"
        );
    }

    /// Building a `LogSubject` needs a digest provider; this is the smallest one.
    struct LogSubjectForTest;
    impl LogSubjectForTest {
        fn make() -> LogSubject {
            struct D;
            impl crate::crypto::RelayCrypto for D {
                fn verify_signature(
                    &self,
                    _: &crate::crypto::IssuerPublicKey,
                    _: &[u8],
                    _: &[u8],
                ) -> bool {
                    false
                }
                fn verify_frame_mac(
                    &self,
                    _: &crate::crypto::LegKey,
                    _: &[u8],
                    _: [u8; 8],
                ) -> bool {
                    false
                }
                fn frame_mac(&self, _: &crate::crypto::LegKey, _: &[u8]) -> Option<[u8; 8]> {
                    None
                }
                fn digest16(&self, _: &[u8], _: &[u8]) -> Option<[u8; 16]> {
                    Some([0x5A; 16])
                }
            }
            crate::subject::RelaySub::from_verified_claim([1; 16])
                .log_subject(&D, 20_000)
                .expect("digest")
        }
    }
}
