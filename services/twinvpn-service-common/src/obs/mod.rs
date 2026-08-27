//! Observability: structured logging, OpenTelemetry, the attribute vocabulary,
//! and the Tier-2 shape.
//!
//! **Authority:** ADR-0015 (whole), `infra/otel/collector-config.yaml`,
//! `infra/README.md` §6, `docs/implementation/ownership.md` §6 rules 5 and 11.
//!
//! # The four controls, in the order they run
//!
//! 1. **Typed keys.** [`attrs::AttrKey`] has no `From<&str>`; the ordinary way to
//!    name an attribute is a constant, and the only runtime constructor refuses
//!    forbidden and unknown names.
//! 2. **Emit-time filtering.** [`layer::RedactingLayer`] drops a record whole if
//!    it carries a `filter/forbidden` key and deletes any field the collector
//!    does not allowlist — the same two-step contract, applied before rendering.
//! 3. **Export-time filtering.** [`otel::RedactingSpanProcessor`] applies the
//!    same contract to span attributes before they are queued.
//! 4. **The collector**, which does it again, and the Prometheus
//!    `metric_relabel_configs`, which do it a fourth time for the direct scrape.
//!
//! None of these is the primary control on `SECRET` material. That one is
//! structural: `Secret`, `Sensitive` and the redacted `Debug` on the
//! `twinvpn-types` identifiers mean the code that would render key material,
//! a tunnel payload or a pairing secret **does not exist**, which is what
//! ADR-0015 §11.4 requires and what no filter can achieve.

pub mod attrs;
pub mod layer;
pub mod otel;
pub mod tier2;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::level_filters::LevelFilter;
use tracing::Metadata;
use tracing_subscriber::layer::{Context, Filter, SubscriberExt as _};
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::Layer as _;

use crate::metrics::Metrics;
use layer::{LogFormat, RecordSink, RedactingLayer, StdoutSink};

/// Everything the observability stack needs.
#[derive(Debug, Clone)]
pub struct ObservabilityConfig {
    /// `TWINVPN_SERVICE_NAME`.
    pub service_name: String,
    /// The crate version of the running artifact.
    pub service_version: String,
    /// A per-process instance id. Allowlisted, and stripped on Tier 2.
    pub instance_id: String,
    /// `TWINVPN_ENVIRONMENT`.
    pub environment: String,
    /// `twinvpn.component`, one of `errors.proto`'s `Component` names.
    pub component: String,
    /// `TWINVPN_LOG_LEVEL`.
    pub log_level: LevelFilter,
    /// `TWINVPN_LOG_FORMAT`.
    pub log_format: LogFormat,
    /// `TWINVPN_LOG_LEVEL_EXPIRY_MS` — the bound on how long `DEBUG`/`TRACE`
    /// may stay on (ADR-0015 §11.5: they "auto-revert after a bounded window so
    /// a user cannot leave a verbose, sensitive ledger accumulating
    /// indefinitely").
    pub log_level_expiry: Duration,
    /// OTLP settings.
    pub otel: otel::OtelConfig,
}

/// Why observability could not be initialised.
#[derive(Debug, thiserror::Error)]
pub enum ObsError {
    /// A global subscriber was already installed. Installing one is a
    /// process-global side effect; a service does it once, in `main`.
    #[error("a tracing subscriber is already installed for this process")]
    AlreadyInitialised,
    /// The OTLP exporter could not be built.
    #[error("OTLP exporter: {0}")]
    Exporter(#[from] opentelemetry_otlp::ExporterBuildError),
}

/// The live observability stack.
///
/// Held by `main` for the life of the process and shut down last, after the
/// drain, so that the records describing the drain are exported.
pub struct Observability {
    pipeline: Option<otel::OtelPipeline>,
    level: LogLevelControl,
    metrics: Metrics,
}

impl std::fmt::Debug for Observability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Observability")
            .field("otel", &self.pipeline.is_some())
            .finish_non_exhaustive()
    }
}

impl Observability {
    /// The dynamic log-level control (ADR-0015 §11.5's auto-expiring `DEBUG`).
    #[must_use]
    pub fn level(&self) -> &LogLevelControl {
        &self.level
    }

    /// The process metric registry.
    #[must_use]
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Flushes and stops the exporter. Never fails the caller.
    pub fn shutdown(&self) {
        if let Some(p) = &self.pipeline {
            if let Err(e) = p.shutdown() {
                // ADR-0015 §8: loss of diagnostics must itself be diagnosable,
                // and must never fail the work. `error.type` is allowlisted;
                // the SDK's message is not, so it is named by type only.
                tracing::warn!(
                    error.type = "otel_shutdown_failed",
                    twinvpn.outcome = "transient_failure",
                    "the OTLP exporter did not shut down cleanly"
                );
                let _ = e;
            }
        }
    }
}

/// Installs the process-global subscriber and builds the OTLP pipeline.
///
/// # Errors
///
/// [`ObsError::AlreadyInitialised`] if a subscriber is already installed.
/// An exporter failure is **not** an error here — ADR-0015 §8 forbids a stalled
/// or unreachable collector from affecting the work, so the pipeline is skipped
/// and a warning is logged instead.
pub fn init(cfg: &ObservabilityConfig, metrics: Metrics) -> Result<Observability, ObsError> {
    init_with_sink(cfg, metrics, StdoutSink)
}

/// [`init`] with an explicit sink, for tests and for a service that wants a
/// different transport for its stdout records.
///
/// # Errors
///
/// As [`init`].
pub fn init_with_sink<W: RecordSink>(
    cfg: &ObservabilityConfig,
    metrics: Metrics,
    sink: W,
) -> Result<Observability, ObsError> {
    let level = LogLevelControl::new(cfg.log_level, cfg.log_level_expiry);

    let log_layer =
        RedactingLayer::new(cfg.log_format, sink, metrics.clone()).with_filter(level.filter());

    let resource = otel::resource_for(
        &cfg.service_name,
        &cfg.service_version,
        &cfg.instance_id,
        &cfg.environment,
        &cfg.component,
    );

    let pipeline = match otel::build_pipeline(&cfg.otel, resource, &metrics) {
        Ok(p) => p,
        Err(e) => {
            // Deliberately not fatal. An unreachable collector must never keep a
            // control plane down.
            eprintln!("twinvpn: OTLP exporter unavailable, continuing without traces: {e}");
            None
        }
    };

    let registry = tracing_subscriber::registry().with(log_layer);
    let installed = match &pipeline {
        Some(p) => {
            let otel_layer = tracing_opentelemetry::layer()
                .with_tracer(p.tracer("twinvpn"))
                .with_filter(level.filter());
            registry.with(otel_layer).try_init()
        }
        None => registry.try_init(),
    };
    installed.map_err(|_| ObsError::AlreadyInitialised)?;

    Ok(Observability {
        pipeline,
        level,
        metrics,
    })
}

// ---------------------------------------------------------------------------
// Dynamic, auto-expiring log level (ADR-0015 §11.5)
// ---------------------------------------------------------------------------

fn level_to_u8(l: LevelFilter) -> u8 {
    match l {
        LevelFilter::OFF => 0,
        LevelFilter::ERROR => 1,
        LevelFilter::WARN => 2,
        LevelFilter::INFO => 3,
        LevelFilter::DEBUG => 4,
        LevelFilter::TRACE => 5,
    }
}

fn u8_to_level(v: u8) -> LevelFilter {
    match v {
        0 => LevelFilter::OFF,
        1 => LevelFilter::ERROR,
        2 => LevelFilter::WARN,
        3 => LevelFilter::INFO,
        4 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    }
}

/// The verbosity control, with ADR-0015 §11.5's mandatory auto-revert.
///
/// > `DEBUG` and `TRACE` auto-revert after a bounded window so a user cannot
/// > leave a verbose, sensitive ledger accumulating indefinitely.
///
/// The window is `TWINVPN_LOG_LEVEL_EXPIRY_MS`. `infra/README.md` §4.2 records
/// what raising it means: "a real privacy decision".
#[derive(Debug, Clone)]
pub struct LogLevelControl {
    current: Arc<AtomicU8>,
    baseline: u8,
    expiry: Duration,
    generation: Arc<AtomicU8>,
}

impl LogLevelControl {
    /// A control starting at `baseline`.
    #[must_use]
    pub fn new(baseline: LevelFilter, expiry: Duration) -> Self {
        // A configured baseline of DEBUG or TRACE still expires: §11.5 says the
        // levels are "off, user-enablable, auto-expiring", and a start-up value
        // is no more permanent than a runtime one.
        let b = level_to_u8(baseline);
        Self {
            current: Arc::new(AtomicU8::new(b)),
            baseline: if b >= level_to_u8(LevelFilter::DEBUG) {
                level_to_u8(LevelFilter::INFO)
            } else {
                b
            },
            expiry,
            generation: Arc::new(AtomicU8::new(0)),
        }
    }

    /// The current effective level.
    #[must_use]
    pub fn current(&self) -> LevelFilter {
        u8_to_level(self.current.load(Ordering::Relaxed))
    }

    /// The level the control reverts to.
    #[must_use]
    pub fn baseline(&self) -> LevelFilter {
        u8_to_level(self.baseline)
    }

    /// Whether the current level is one §11.5 requires to expire.
    #[must_use]
    pub fn is_verbose(&self) -> bool {
        self.current.load(Ordering::Relaxed) >= level_to_u8(LevelFilter::DEBUG)
    }

    /// Raises (or lowers) the level. A verbose level arms the expiry timer.
    ///
    /// Requires a tokio runtime when `level` is verbose; without one the level
    /// is refused rather than left on forever.
    ///
    /// # Errors
    ///
    /// [`LevelExpiryUnavailable`] when a verbose level is requested with no
    /// runtime to run the auto-revert timer on. Leaving `DEBUG` on with no way
    /// to turn it off is the accumulation ADR-0015 §11.5 forbids, so this is a
    /// refusal rather than a warning.
    pub fn set(&self, level: LevelFilter) -> Result<(), LevelExpiryUnavailable> {
        let v = level_to_u8(level);
        if v < level_to_u8(LevelFilter::DEBUG) {
            self.current.store(v, Ordering::Relaxed);
            return Ok(());
        }
        let gen = self
            .generation
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let handle = tokio::runtime::Handle::try_current().map_err(|_| LevelExpiryUnavailable)?;
        self.current.store(v, Ordering::Relaxed);
        let current = self.current.clone();
        let generation = self.generation.clone();
        let baseline = self.baseline;
        let expiry = self.expiry;
        handle.spawn(async move {
            tokio::time::sleep(expiry).await;
            if generation.load(Ordering::Relaxed) == gen {
                current.store(baseline, Ordering::Relaxed);
            }
        });
        Ok(())
    }

    /// Reverts to the baseline immediately.
    pub fn revert(&self) {
        self.generation.fetch_add(1, Ordering::Relaxed);
        self.current.store(self.baseline, Ordering::Relaxed);
    }

    /// A `tracing` filter reading this control.
    #[must_use]
    pub fn filter(&self) -> DynamicLevelFilter {
        DynamicLevelFilter {
            current: self.current.clone(),
        }
    }
}

/// Refused because no runtime is available to run the auto-revert timer.
///
/// Leaving `DEBUG` on with no way to turn it off is exactly the accumulation
/// §11.5 forbids, so this is a refusal rather than a warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a verbose log level needs a runtime for its auto-revert timer (ADR-0015 §11.5)")]
pub struct LevelExpiryUnavailable;

/// A `tracing` filter whose threshold can change at runtime.
#[derive(Debug, Clone)]
pub struct DynamicLevelFilter {
    current: Arc<AtomicU8>,
}

impl<S> Filter<S> for DynamicLevelFilter {
    fn enabled(&self, meta: &Metadata<'_>, _cx: &Context<'_, S>) -> bool {
        level_to_u8((*meta.level()).into()) <= self.current.load(Ordering::Relaxed)
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        // No static hint: the threshold moves, and a cached hint would pin the
        // callsite at whatever the level was when it was first seen.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lets every already-scheduled task run.
    ///
    /// `tokio::time::advance` fires a timer but does not guarantee the task
    /// waiting on it has been polled; a single `yield_now` is one poll of one
    /// task. Yielding a bounded number of times is deterministic and is not a
    /// sleep — nothing here waits on wall time.
    async fn settle() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    #[test]
    fn a_verbose_baseline_still_reverts_to_info() {
        let c = LogLevelControl::new(LevelFilter::DEBUG, Duration::from_millis(1));
        assert_eq!(c.current(), LevelFilter::DEBUG);
        assert_eq!(c.baseline(), LevelFilter::INFO);
        assert!(c.is_verbose());
        c.revert();
        assert_eq!(c.current(), LevelFilter::INFO);
    }

    #[test]
    fn a_non_verbose_baseline_is_its_own_baseline() {
        let c = LogLevelControl::new(LevelFilter::WARN, Duration::from_secs(1));
        assert_eq!(c.baseline(), LevelFilter::WARN);
        assert!(!c.is_verbose());
    }

    #[test]
    fn verbose_is_refused_without_a_runtime_rather_than_left_on() {
        let c = LogLevelControl::new(LevelFilter::INFO, Duration::from_millis(1));
        assert_eq!(c.set(LevelFilter::TRACE), Err(LevelExpiryUnavailable));
        assert_eq!(c.current(), LevelFilter::INFO);
    }

    #[tokio::test(start_paused = true)]
    async fn debug_auto_reverts_after_the_expiry_window() {
        let c = LogLevelControl::new(LevelFilter::INFO, Duration::from_millis(3_600_000));
        c.set(LevelFilter::DEBUG).expect("runtime present");
        assert_eq!(c.current(), LevelFilter::DEBUG);
        // Let the revert task register its deadline before the clock moves;
        // advancing past a timer that has not been armed yet arms it late.
        settle().await;
        tokio::time::advance(Duration::from_millis(3_600_001)).await;
        settle().await;
        assert_eq!(
            c.current(),
            LevelFilter::INFO,
            "ADR-0015 §11.5 requires DEBUG to auto-revert"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_enable_extends_rather_than_double_reverting() {
        let c = LogLevelControl::new(LevelFilter::INFO, Duration::from_millis(1000));
        c.set(LevelFilter::DEBUG).unwrap();
        settle().await;
        tokio::time::advance(Duration::from_millis(900)).await;
        c.set(LevelFilter::DEBUG).unwrap();
        settle().await;
        tokio::time::advance(Duration::from_millis(200)).await;
        settle().await;
        assert_eq!(
            c.current(),
            LevelFilter::DEBUG,
            "the first timer must not win"
        );
        tokio::time::advance(Duration::from_millis(1000)).await;
        settle().await;
        assert_eq!(c.current(), LevelFilter::INFO);
    }
}
