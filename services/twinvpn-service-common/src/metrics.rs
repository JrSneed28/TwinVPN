//! Prometheus metrics with the ADR-0015 §9 label allowlist enforced at the
//! point of construction.
//!
//! **Authority:** ADR-0015 §9 (cardinality discipline), §11.7 (infrastructure
//! metrics), O-13 (no per-session, per-device, per-peer or per-endpoint label),
//! `infra/prometheus/prometheus.yml` (which scrapes `:9090/metrics` directly and
//! applies a `labeldrop` backstop).
//!
//! # Why the crate carries its own tiny registry
//!
//! `/metrics` is scraped by Prometheus **directly**, not through the collector
//! (`infra/prometheus/prometheus.yml` job `twinvpn-services`), so the collector's
//! positive allowlist is not in that path. The `metric_relabel_configs` there are
//! a `labeldrop` over forbidden names — a denylist, and `infra/README.md` §6.2 is
//! explicit that a denylist "only catches what someone thought of". The positive
//! control therefore has to be here, at emit time, which is also what O-14
//! requires.
//!
//! [`Labels`] has no constructor that accepts an arbitrary name. The five §9
//! dimensions are the whole vocabulary, so `session_id` is not a label a service
//! can spell.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// The ADR-0015 §9 label allowlist, verbatim.
///
/// > Prometheus labels are restricted to a fixed allowlist of low-cardinality
/// > dimensions (`relay_region`, `protocol_version`, `reason_code`, `outcome`,
/// > `address_family`). Per-`Session`, per-`Device`, per-peer, and per-endpoint
/// > labels are forbidden — for privacy first (O-13) and for cost second.
///
/// `TWINVPN_RELAY_METRICS_LABEL_ALLOWLIST` in `infra/README.md` §4.6 is marked
/// `frozen` against exactly this list.
pub const LABEL_ALLOWLIST: [&str; 5] = [
    "relay_region",
    "protocol_version",
    "reason_code",
    "outcome",
    "address_family",
];

/// One of the five permitted label dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Label {
    /// ADR-0006 region identifier.
    RelayRegion,
    /// The negotiated protocol epoch, rendered.
    ProtocolVersion,
    /// A registered `reason_code`.
    ReasonCode,
    /// A coarse outcome token, e.g. `success`, `refused`, `timeout`.
    Outcome,
    /// `v4` or `v6`.
    AddressFamily,
}

impl Label {
    /// The Prometheus label name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Label::RelayRegion => "relay_region",
            Label::ProtocolVersion => "protocol_version",
            Label::ReasonCode => "reason_code",
            Label::Outcome => "outcome",
            Label::AddressFamily => "address_family",
        }
    }
}

/// A validated, ordered label set.
///
/// Ordering is deterministic (`BTreeMap`) so the same logical series always
/// renders the same text — `docs/architecture.md` §5.2 R-DET-1 applied to the
/// one place a map iteration order would otherwise leak into an artifact.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Labels(BTreeMap<&'static str, String>);

impl Labels {
    /// An empty label set.
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Adds a label. The value is sanitised: control characters, quotes,
    /// backslashes and newlines are replaced, and the value is bounded to 64
    /// bytes, so a label value cannot break the exposition format or grow a
    /// series without bound.
    #[must_use]
    pub fn with(mut self, label: Label, value: &str) -> Self {
        self.0.insert(label.as_str(), sanitise_label_value(value));
        self
    }

    /// Renders `{k="v",…}`, or the empty string when there are no labels.
    #[must_use]
    pub fn render(&self) -> String {
        if self.0.is_empty() {
            return String::new();
        }
        let mut s = String::from("{");
        for (i, (k, v)) in self.0.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(s, "{k}=\"{v}\"");
        }
        s.push('}');
        s
    }
}

fn sanitise_label_value(value: &str) -> String {
    value
        .chars()
        .take(64)
        .map(|c| {
            if c.is_control() || c == '"' || c == '\\' {
                '_'
            } else {
                c
            }
        })
        .collect()
}

/// A monotonically increasing counter.
#[derive(Debug, Clone, Default)]
pub struct Counter(Arc<AtomicU64>);

impl Counter {
    /// Adds one.
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    /// Adds `n`.
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }
    /// The current value.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A value that can go up and down.
#[derive(Debug, Clone, Default)]
pub struct Gauge(Arc<AtomicI64>);

impl Gauge {
    /// Sets the value.
    pub fn set(&self, v: i64) {
        self.0.store(v, Ordering::Relaxed);
    }
    /// The current value.
    #[must_use]
    pub fn get(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone)]
enum Series {
    Counter(Counter),
    Gauge(Gauge),
}

#[derive(Debug)]
struct Family {
    help: &'static str,
    kind: &'static str,
    series: BTreeMap<Labels, Series>,
}

/// The process's metric registry.
///
/// Cheap to clone; every clone shares one set of series.
#[derive(Debug, Clone, Default)]
pub struct Metrics {
    families: Arc<Mutex<BTreeMap<&'static str, Family>>>,
}

impl Metrics {
    /// A new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the counter for `(name, labels)`, registering it on first use.
    ///
    /// # Panics
    ///
    /// If `name` was already registered as a gauge. That is a programming error
    /// in the calling service and is caught at first use rather than producing a
    /// silently wrong exposition.
    #[must_use]
    pub fn counter(&self, name: &'static str, help: &'static str, labels: Labels) -> Counter {
        let mut g = self.families.lock().expect("metrics registry poisoned");
        let fam = g.entry(name).or_insert_with(|| Family {
            help,
            kind: "counter",
            series: BTreeMap::new(),
        });
        assert_eq!(
            fam.kind, "counter",
            "{name} is already registered as a gauge"
        );
        match fam
            .series
            .entry(labels)
            .or_insert_with(|| Series::Counter(Counter::default()))
        {
            Series::Counter(c) => c.clone(),
            Series::Gauge(_) => unreachable!("kind asserted above"),
        }
    }

    /// Returns the gauge for `(name, labels)`, registering it on first use.
    ///
    /// # Panics
    ///
    /// If `name` was already registered as a counter.
    #[must_use]
    pub fn gauge(&self, name: &'static str, help: &'static str, labels: Labels) -> Gauge {
        let mut g = self.families.lock().expect("metrics registry poisoned");
        let fam = g.entry(name).or_insert_with(|| Family {
            help,
            kind: "gauge",
            series: BTreeMap::new(),
        });
        assert_eq!(
            fam.kind, "gauge",
            "{name} is already registered as a counter"
        );
        match fam
            .series
            .entry(labels)
            .or_insert_with(|| Series::Gauge(Gauge::default()))
        {
            Series::Gauge(v) => v.clone(),
            Series::Counter(_) => unreachable!("kind asserted above"),
        }
    }

    /// Renders the Prometheus text exposition format (version 0.0.4).
    ///
    /// Deterministic: families and series are both ordered.
    ///
    /// # Panics
    ///
    /// If the registry mutex was poisoned by a panic in another thread. A
    /// scrape that returned a stale or empty exposition after a panic would
    /// hide the panic, which is the opposite of what `/metrics` is for.
    #[must_use]
    pub fn render(&self) -> String {
        let g = self.families.lock().expect("metrics registry poisoned");
        let mut out = String::new();
        for (name, fam) in g.iter() {
            let _ = writeln!(out, "# HELP {name} {}", fam.help);
            let _ = writeln!(out, "# TYPE {name} {}", fam.kind);
            for (labels, series) in &fam.series {
                let l = labels.render();
                match series {
                    Series::Counter(c) => {
                        let _ = writeln!(out, "{name}{l} {}", c.get());
                    }
                    Series::Gauge(v) => {
                        let _ = writeln!(out, "{name}{l} {}", v.get());
                    }
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// The metric names this crate owns.
// ---------------------------------------------------------------------------

/// Metric names emitted by `twinvpn-service-common` itself.
///
/// Named constants rather than string literals at each call site so the four
/// service domains share one set of series and a dashboard query written against
/// one service works against all four.
pub mod names {
    /// 1 while the process is running.
    pub const UP: &str = "twinvpn_service_up";
    /// 1 when `/readyz` would return 200.
    pub const READY: &str = "twinvpn_service_ready";
    /// 1 once a drain has begun.
    pub const DRAINING: &str = "twinvpn_service_draining";
    /// Readiness probe failures, labelled by `reason_code`.
    pub const READINESS_FAILURES: &str = "twinvpn_readiness_probe_failures_total";
    /// Duration of the most recent readiness evaluation.
    pub const READINESS_DURATION_MS: &str = "twinvpn_readiness_probe_duration_ms";
    /// Errors mapped through [`crate::errors`], labelled by `reason_code` and
    /// `outcome`.
    pub const ERRORS: &str = "twinvpn_errors_total";
    /// A log or span carrying a `filter/forbidden` attribute was dropped whole.
    /// **Non-zero is a security defect in this service** (`infra/README.md` §8).
    pub const FORBIDDEN_ATTR_DROPPED: &str =
        "twinvpn_observability_forbidden_attribute_dropped_total";
    /// A field was deleted because it is not on the collector allowlist.
    pub const ATTR_NOT_ALLOWLISTED: &str = "twinvpn_observability_attribute_not_allowlisted_total";
    /// A value on an allowlisted key looked like credential material and was
    /// replaced. The weakest of the controls, present as a backstop.
    pub const BLOCKED_VALUE_REDACTED: &str = "twinvpn_observability_blocked_value_redacted_total";
    /// ADR-0015 §8 `dropped_events`: telemetry lost rather than blocking work.
    pub const DROPPED_EVENTS: &str = "twinvpn_observability_dropped_events_total";
    /// The shutdown grace period expired with work still in flight.
    pub const SHUTDOWN_GRACE_EXPIRED: &str = "twinvpn_shutdown_grace_expired_total";
    /// In-flight operations still outstanding when the grace period expired.
    pub const SHUTDOWN_INFLIGHT_AT_DEADLINE: &str = "twinvpn_shutdown_inflight_at_deadline";
    /// `CONTROL.ADMISSION_DEFERRED` responses issued (ADR-0002 §11.7 rule 3).
    pub const ADMISSION_DEFERRED: &str = "twinvpn_admission_deferred_total";
    /// `CONTROL.STREAM_COMPACTED` emissions (ADR-0002 §11.6).
    pub const STREAM_COMPACTED: &str = "twinvpn_stream_compacted_total";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_label_vocabulary_is_exactly_the_five_section_9_dimensions() {
        let all = [
            Label::RelayRegion,
            Label::ProtocolVersion,
            Label::ReasonCode,
            Label::Outcome,
            Label::AddressFamily,
        ];
        assert_eq!(all.len(), LABEL_ALLOWLIST.len());
        for l in all {
            assert!(LABEL_ALLOWLIST.contains(&l.as_str()), "{}", l.as_str());
        }
    }

    #[test]
    fn a_label_value_cannot_break_the_exposition_format() {
        let l = Labels::new().with(Label::Outcome, "a\"b\\c\nd");
        assert_eq!(l.render(), r#"{outcome="a_b_c_d"}"#);
    }

    #[test]
    fn a_label_value_is_bounded() {
        let l = Labels::new().with(Label::ReasonCode, &"x".repeat(4096));
        assert_eq!(l.render().len(), "{reason_code=\"\"}".len() + 64);
    }

    #[test]
    fn rendering_is_deterministic_and_well_formed() {
        let m = Metrics::new();
        m.counter(
            names::ERRORS,
            "errors",
            Labels::new().with(Label::Outcome, "refused"),
        )
        .add(3);
        m.counter(
            names::ERRORS,
            "errors",
            Labels::new().with(Label::Outcome, "accepted"),
        )
        .inc();
        m.gauge(names::READY, "ready", Labels::new()).set(1);

        let a = m.render();
        let b = m.render();
        assert_eq!(a, b, "exposition must be deterministic");
        assert!(a.contains("# TYPE twinvpn_errors_total counter"));
        assert!(a.contains("twinvpn_errors_total{outcome=\"accepted\"} 1"));
        assert!(a.contains("twinvpn_errors_total{outcome=\"refused\"} 3"));
        assert!(a.contains("twinvpn_service_ready 1"));
        // "accepted" sorts before "refused": deterministic order, not map order.
        assert!(a.find("accepted").unwrap() < a.find("refused").unwrap());
    }

    #[test]
    fn a_shared_counter_is_one_series() {
        let m = Metrics::new();
        let a = m.counter(names::DROPPED_EVENTS, "dropped", Labels::new());
        let b = m.counter(names::DROPPED_EVENTS, "dropped", Labels::new());
        a.inc();
        b.inc();
        assert_eq!(a.get(), 2);
    }
}
