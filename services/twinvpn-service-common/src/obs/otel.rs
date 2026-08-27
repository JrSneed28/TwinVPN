//! OpenTelemetry wiring, with the attribute allowlist enforced on the export
//! path as well as the emit path.
//!
//! **Authority:** ADR-0015 §11.1 —
//!
//! > OpenTelemetry as an *internal, infrastructure-side* instrumentation library
//! > is permitted; OpenTelemetry as an *end-to-end client-to-backend pipeline* is
//! > rejected.
//!
//! Nothing here receives client telemetry, and nothing here is reachable from a
//! device. The exporter's only destination is the operator-owned collector named
//! by `OTEL_EXPORTER_OTLP_ENDPOINT`.
//!
//! # Two independent enforcement points, on purpose
//!
//! [`RedactingSpanProcessor`] filters `SpanData::attributes` on `on_end`, before
//! the batch processor sees them. That is the same two-step contract the
//! collector applies (`filter/forbidden` drops the record, the allowlist deletes
//! the field) and it holds even when the collector is misconfigured, absent, or
//! replaced. `infra/README.md` §9 records that the collector config "was **not**
//! loaded by a collector" on the host that wrote it; a service that relies on it
//! as its only control is relying on an unexercised file.

use std::time::Duration;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{SdkTracerProvider, SpanData, SpanProcessor};
use opentelemetry_sdk::Resource;

use super::attrs::{self, KeyVerdict};
use crate::metrics::{Labels, Metrics};

/// How the OTLP pipeline is configured.
#[derive(Debug, Clone)]
pub struct OtelConfig {
    /// `TWINVPN_OTEL_ENABLED`. When false nothing is exported and no exporter is
    /// constructed — ADR-0015 §8 requires that a stalled or absent export never
    /// affect the work, so "off" must be genuinely inert.
    pub enabled: bool,
    /// `OTEL_EXPORTER_OTLP_ENDPOINT`.
    pub endpoint: String,
    /// `OTEL_TRACES_SAMPLER_ARG`, in `[0.0, 1.0]`.
    pub sampler_ratio: f64,
    /// Export timeout. Bounded so a stalled collector cannot hold a task.
    pub export_timeout: Duration,
}

/// A `SpanProcessor` that applies the collector's attribute contract before any
/// span is queued for export.
///
/// A forbidden attribute drops the **whole span**, mirroring
/// `filter/forbidden`; an unknown attribute is deleted, mirroring
/// `redaction/allowlist`. Both increment the same counters the log layer uses,
/// so `TwinVPNObservabilityForbiddenAttributeObserved` has a service-side twin.
#[derive(Debug)]
pub struct RedactingSpanProcessor<P: SpanProcessor> {
    inner: P,
    metrics: Metrics,
}

impl<P: SpanProcessor> RedactingSpanProcessor<P> {
    /// Wraps `inner`.
    pub const fn new(inner: P, metrics: Metrics) -> Self {
        Self { inner, metrics }
    }

    fn count(&self, name: &'static str, help: &'static str, n: u64) {
        if n > 0 {
            self.metrics.counter(name, help, Labels::new()).add(n);
        }
    }
}

impl<P: SpanProcessor> SpanProcessor for RedactingSpanProcessor<P> {
    fn on_start(&self, span: &mut opentelemetry_sdk::trace::Span, cx: &opentelemetry::Context) {
        self.inner.on_start(span, cx);
    }

    fn on_end(&self, mut span: SpanData) {
        let mut dropped_unknown = 0u64;
        let mut forbidden = false;
        span.attributes
            .retain(|kv| match attrs::verdict(kv.key.as_str()) {
                KeyVerdict::Allowed => true,
                KeyVerdict::Unknown => {
                    dropped_unknown += 1;
                    false
                }
                KeyVerdict::Forbidden => {
                    forbidden = true;
                    false
                }
            });
        if forbidden {
            self.count(
                crate::metrics::names::FORBIDDEN_ATTR_DROPPED,
                "records dropped whole for carrying a forbidden telemetry attribute",
                1,
            );
            return;
        }
        self.count(
            crate::metrics::names::ATTR_NOT_ALLOWLISTED,
            "fields deleted for not being on the collector allowlist",
            dropped_unknown,
        );
        self.inner.on_end(span);
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

/// A live OTLP pipeline. Dropping it does **not** flush; call
/// [`OtelPipeline::shutdown`] from the shutdown sequence.
#[derive(Debug)]
pub struct OtelPipeline {
    provider: SdkTracerProvider,
}

impl OtelPipeline {
    /// The tracer `tracing-opentelemetry` should be wired to.
    #[must_use]
    pub fn tracer(&self, name: &'static str) -> opentelemetry_sdk::trace::SdkTracer {
        self.provider.tracer(name)
    }

    /// Flushes and shuts the exporter down.
    ///
    /// Called as the **last** ordered teardown step, after in-flight work has
    /// drained, so the spans describing the drain are themselves exported.
    ///
    /// # Errors
    ///
    /// The SDK's shutdown error. A failure here is logged and never propagated
    /// into an exit code: ADR-0015 §8 forbids observability from failing work,
    /// and that includes the work of stopping.
    pub fn shutdown(&self) -> OTelSdkResult {
        self.provider.shutdown()
    }
}

/// Builds the OTLP trace pipeline.
///
/// Returns `Ok(None)` when `enabled` is false — the caller then installs no
/// `tracing-opentelemetry` layer at all, so the cost is zero rather than small.
///
/// # Errors
///
/// [`opentelemetry_otlp::ExporterBuildError`] if the endpoint is unusable. A
/// service SHOULD treat this as non-fatal and continue without traces: an
/// unreachable collector must never keep a control plane down (ADR-0015 §8).
pub fn build_pipeline(
    cfg: &OtelConfig,
    resource: Resource,
    metrics: &Metrics,
) -> Result<Option<OtelPipeline>, opentelemetry_otlp::ExporterBuildError> {
    if !cfg.enabled {
        return Ok(None);
    }
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(cfg.endpoint.clone())
        .with_timeout(cfg.export_timeout)
        .build()?;

    let batch = opentelemetry_sdk::trace::BatchSpanProcessor::builder(exporter).build();
    let guarded = RedactingSpanProcessor::new(batch, metrics.clone());

    let sampler = opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(
        opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(cfg.sampler_ratio.clamp(0.0, 1.0)),
    ));

    let provider = SdkTracerProvider::builder()
        .with_span_processor(guarded)
        .with_sampler(sampler)
        .with_resource(resource)
        .build();

    Ok(Some(OtelPipeline { provider }))
}

/// Builds the OTel `Resource` from the service identity.
///
/// Only allowlisted provenance keys are set. `service.instance.id` is included
/// because the collector allowlists it and strips it on the Tier-2 pipeline
/// (`attributes/tier2-strip-abi`), which is exactly the split ADR-0018 VR-2
/// consequence 1 and 3 describe.
#[must_use]
pub fn resource_for(
    service_name: &str,
    service_version: &str,
    instance_id: &str,
    environment: &str,
    component: &str,
) -> Resource {
    Resource::builder()
        .with_service_name(service_name.to_owned())
        .with_attributes([
            KeyValue::new(attrs::SERVICE_VERSION.as_str(), service_version.to_owned()),
            KeyValue::new(attrs::SERVICE_INSTANCE_ID.as_str(), instance_id.to_owned()),
            KeyValue::new(
                attrs::DEPLOYMENT_ENVIRONMENT.as_str(),
                environment.to_owned(),
            ),
            KeyValue::new(attrs::COMPONENT.as_str(), component.to_owned()),
            // ADR-0015 §11.1: this process is infrastructure, never a device.
            KeyValue::new(attrs::OBSERVABILITY_TIER.as_str(), "infrastructure"),
            KeyValue::new(
                attrs::REASON_REGISTRY_VERSION.as_str(),
                i64::from(twinvpn_types::REASON_REGISTRY_VERSION),
            ),
        ])
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Default)]
    struct Recording(Arc<Mutex<Vec<SpanData>>>);

    impl SpanProcessor for Recording {
        fn on_start(&self, _s: &mut opentelemetry_sdk::trace::Span, _c: &opentelemetry::Context) {}
        fn on_end(&self, span: SpanData) {
            self.0.lock().expect("poisoned").push(span);
        }
        fn force_flush(&self) -> OTelSdkResult {
            Ok(())
        }
        fn shutdown_with_timeout(&self, _t: Duration) -> OTelSdkResult {
            Ok(())
        }
    }

    fn span_with(attrs_: Vec<KeyValue>) -> SpanData {
        use opentelemetry::trace::{SpanContext, SpanKind, Status};
        SpanData {
            span_context: SpanContext::empty_context(),
            parent_span_id: opentelemetry::trace::SpanId::INVALID,
            parent_span_is_remote: false,
            span_kind: SpanKind::Internal,
            name: "t".into(),
            start_time: std::time::SystemTime::UNIX_EPOCH,
            end_time: std::time::SystemTime::UNIX_EPOCH,
            attributes: attrs_,
            dropped_attributes_count: 0,
            events: opentelemetry_sdk::trace::SpanEvents::default(),
            links: opentelemetry_sdk::trace::SpanLinks::default(),
            status: Status::Unset,
            instrumentation_scope: opentelemetry::InstrumentationScope::builder("t").build(),
        }
    }

    #[test]
    fn a_forbidden_span_attribute_drops_the_whole_span() {
        let rec = Recording::default();
        let seen = rec.0.clone();
        let metrics = Metrics::new();
        let p = RedactingSpanProcessor::new(rec, metrics.clone());

        p.on_end(span_with(vec![
            KeyValue::new("twinvpn.reason_code", "NET.NO_ROUTE"),
            KeyValue::new("twinvpn.session_id", "deadbeef"),
        ]));

        assert!(seen.lock().unwrap().is_empty());
        assert!(metrics.render().contains(&format!(
            "{} 1",
            crate::metrics::names::FORBIDDEN_ATTR_DROPPED
        )));
    }

    #[test]
    fn an_unknown_span_attribute_is_deleted_and_the_span_survives() {
        let rec = Recording::default();
        let seen = rec.0.clone();
        let metrics = Metrics::new();
        let p = RedactingSpanProcessor::new(rec, metrics.clone());

        p.on_end(span_with(vec![
            KeyValue::new("twinvpn.correlation_id", "0f0f"),
            KeyValue::new("my.new.idea", "x"),
        ]));

        let got = seen.lock().unwrap();
        assert_eq!(got.len(), 1);
        let keys: Vec<_> = got[0]
            .attributes
            .iter()
            .map(|kv| kv.key.as_str().to_owned())
            .collect();
        assert_eq!(keys, vec!["twinvpn.correlation_id".to_owned()]);
    }

    #[test]
    fn a_disabled_pipeline_builds_nothing() {
        let cfg = OtelConfig {
            enabled: false,
            endpoint: "http://127.0.0.1:1".to_owned(),
            sampler_ratio: 1.0,
            export_timeout: Duration::from_secs(1),
        };
        let r = build_pipeline(&cfg, Resource::builder_empty().build(), &Metrics::new()).unwrap();
        assert!(r.is_none());
    }
}
