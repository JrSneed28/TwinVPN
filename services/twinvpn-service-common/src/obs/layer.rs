//! The emit-time redaction layer.
//!
//! **Authority:** ADR-0015 O-14 ("redaction at EMIT time by schema-level field
//! classification, NOT at export time by pattern matching over rendered text"),
//! O-12, §11.5 ("No level, in any build, may emit `SECRET`"),
//! `infra/otel/collector-config.yaml`.
//!
//! # What it does, and why it mirrors the collector rather than inventing rules
//!
//! The collector applies, in order: a forbidden-key filter that **drops the whole
//! record and increments a counter**, then a positive allowlist that **silently
//! deletes** anything unnamed. `infra/README.md` §6.2 explains the asymmetry: "a
//! silently sanitised leak is a leak nobody fixes".
//!
//! This layer applies the same two steps to every `tracing` event *before it is
//! rendered at all*, so the property holds for the stdout log (which Docker's
//! logging driver ships, bypassing the collector entirely) and not only for OTLP.
//! A service that starts emitting `twinvpn.session_id` is therefore loud in three
//! independent places rather than quietly sanitised in one.
//!
//! A third, deliberately weakest control follows: [`looks_like_credential`], the
//! non-regex twin of the collector's `blocked_values`. It is a backstop, exactly
//! as `infra/otel/collector-config.yaml` says pattern matching over rendered
//! values must be.

use std::fmt;
use std::io::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

use super::attrs::{self, KeyVerdict};
use crate::metrics::{Labels, Metrics};

/// How a record is rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// One JSON object per line. The production format
    /// (`TWINVPN_LOG_FORMAT=json`, the compose default).
    #[default]
    Json,
    /// Human-readable, for a terminal. Same redaction, different rendering.
    Text,
}

impl LogFormat {
    /// Parses `json` or `text`.
    ///
    /// # Errors
    ///
    /// Returns the unrecognised token so the caller can name the variable.
    pub fn parse(s: &str) -> Result<Self, &str> {
        match s.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "text" | "plain" | "pretty" => Ok(Self::Text),
            _ => Err(s),
        }
    }
}

/// A rendered field value, already bounded and sanitised.
#[derive(Debug, Clone, PartialEq)]
enum Value {
    Str(String),
    I64(i64),
    U64(u64),
    F64(f64),
    Bool(bool),
}

impl Value {
    fn to_json(&self) -> serde_json::Value {
        match self {
            Value::Str(s) => serde_json::Value::String(s.clone()),
            Value::I64(v) => serde_json::Value::from(*v),
            Value::U64(v) => serde_json::Value::from(*v),
            Value::F64(v) => serde_json::Number::from_f64(*v)
                .map_or(serde_json::Value::Null, serde_json::Value::Number),
            Value::Bool(v) => serde_json::Value::Bool(*v),
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Str(s) => f.write_str(s),
            Value::I64(v) => write!(f, "{v}"),
            Value::U64(v) => write!(f, "{v}"),
            Value::F64(v) => write!(f, "{v}"),
            Value::Bool(v) => write!(f, "{v}"),
        }
    }
}

/// The longest string value that is ever rendered.
///
/// ADR-0015 §9 budgets the observability subsystem; more directly, a log line is
/// an allocation an attacker-influenced value could otherwise drive
/// (`ownership.md` §6 rule 10).
const MAX_VALUE_BYTES: usize = 512;

fn bound(mut s: String) -> String {
    if s.len() > MAX_VALUE_BYTES {
        s.truncate(MAX_VALUE_BYTES);
        s.push_str("…<truncated>");
    }
    s
}

/// The non-regex twin of the collector's `blocked_values`.
///
/// Catches long base64, long hex, `Bearer`/`Basic` credentials and PEM blocks.
/// **Deliberately the weakest control in this module** — O-14 is explicit that
/// pattern matching over rendered values must not be the primary mechanism, and
/// it is not: the forbidden-key filter and the allowlist run first.
#[must_use]
pub fn looks_like_credential(s: &str) -> bool {
    if s.contains("-----BEGIN ") && s.contains("PRIVATE KEY") {
        return true;
    }
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("bearer ") || lower.starts_with("basic ") {
        return true;
    }
    let mut hex_run = 0usize;
    let mut b64_run = 0usize;
    for c in s.chars() {
        if c.is_ascii_hexdigit() {
            hex_run += 1;
            if hex_run >= 64 {
                return true;
            }
        } else {
            hex_run = 0;
        }
        if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' {
            b64_run += 1;
            if b64_run >= 40 {
                return true;
            }
        } else {
            b64_run = 0;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Visitor
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Collector {
    message: Option<String>,
    fields: Vec<(&'static str, Value)>,
    forbidden: Option<&'static str>,
    not_allowlisted: u64,
    blocked_values: u64,
}

impl Collector {
    fn put(&mut self, field: &Field, value: Value) {
        let name = field.name();
        if name == "message" {
            self.message = Some(bound(value.to_string()));
            return;
        }
        match attrs::verdict(name) {
            KeyVerdict::Forbidden => {
                // Record which key, from the STATIC list, never the caller's
                // string. The value itself is discarded here and never stored.
                if self.forbidden.is_none() {
                    self.forbidden = attrs::FORBIDDEN_KEYS.iter().find(|k| **k == name).copied();
                }
            }
            KeyVerdict::Unknown => self.not_allowlisted += 1,
            KeyVerdict::Allowed => {
                let value = match value {
                    Value::Str(s) if looks_like_credential(&s) => {
                        self.blocked_values += 1;
                        Value::Str("<redacted:blocked-value>".to_owned())
                    }
                    Value::Str(s) => Value::Str(bound(s)),
                    other => other,
                };
                self.fields.push((name, value));
            }
        }
    }
}

impl Visit for Collector {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, Value::Str(value.to_owned()));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, Value::I64(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, Value::U64(value));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, Value::Bool(value));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.put(field, Value::F64(value));
    }
    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        // An error's rendered chain can carry a path, an address or a driver
        // buffer. `error` is not on the allowlist, so this lands in the
        // not-allowlisted bucket and is dropped — which is the intent. Services
        // attach `error.type` (allowlisted) and the registered `reason_code`.
        self.put(field, Value::Str(format!("{value}")));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.put(field, Value::Str(format!("{value:?}")));
    }
}

// ---------------------------------------------------------------------------
// The layer
// ---------------------------------------------------------------------------

/// Where a rendered record goes.
pub trait RecordSink: Send + Sync + 'static {
    /// Writes one complete record. Implementations MUST NOT block a caller for
    /// long: ADR-0015 §8 makes it a hard rule that "a full buffer, a full disk,
    /// or a stalled export MUST never block, delay, or fail a packet-path or
    /// state-machine operation".
    fn write_record(&self, line: &str);
}

/// The default sink: one line on stdout, which is what the compose logging
/// driver collects.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdoutSink;

impl RecordSink for StdoutSink {
    fn write_record(&self, line: &str) {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(line.as_bytes());
        let _ = out.write_all(b"\n");
    }
}

/// An in-memory sink, for tests and for the readiness self-check.
#[derive(Debug, Clone, Default)]
pub struct CapturingSink(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl CapturingSink {
    /// A new, empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Every record written so far.
    ///
    /// # Panics
    ///
    /// If the sink mutex was poisoned. Test-only.
    #[must_use]
    pub fn records(&self) -> Vec<String> {
        self.0.lock().expect("sink poisoned").clone()
    }
}

impl RecordSink for CapturingSink {
    fn write_record(&self, line: &str) {
        self.0.lock().expect("sink poisoned").push(line.to_owned());
    }
}

/// A `tracing` layer that enforces the collector's attribute contract at emit
/// time.
pub struct RedactingLayer<W: RecordSink> {
    format: LogFormat,
    sink: W,
    metrics: Metrics,
}

impl<W: RecordSink> RedactingLayer<W> {
    /// Builds the layer.
    pub fn new(format: LogFormat, sink: W, metrics: Metrics) -> Self {
        // Register the families eagerly so a zero shows up in `/metrics` before
        // the first drop. A counter that only appears after the first incident
        // cannot be alerted on with `increase()`.
        for (name, help) in [
            (
                crate::metrics::names::FORBIDDEN_ATTR_DROPPED,
                "records dropped whole for carrying a forbidden telemetry attribute",
            ),
            (
                crate::metrics::names::ATTR_NOT_ALLOWLISTED,
                "fields deleted for not being on the collector allowlist",
            ),
            (
                crate::metrics::names::BLOCKED_VALUE_REDACTED,
                "values replaced for resembling credential material",
            ),
        ] {
            let _registered = metrics.counter(name, help, Labels::new());
        }
        Self {
            format,
            sink,
            metrics,
        }
    }

    fn emit(&self, level: tracing::Level, target: &str, c: &Collector) {
        let ts: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
            .unwrap_or(0);
        match self.format {
            LogFormat::Json => {
                let mut obj = serde_json::Map::new();
                obj.insert("ts_ms".into(), serde_json::Value::from(ts));
                obj.insert("level".into(), serde_json::Value::from(level.as_str()));
                obj.insert("target".into(), serde_json::Value::from(target));
                if let Some(m) = &c.message {
                    obj.insert("message".into(), serde_json::Value::from(m.clone()));
                }
                for (k, v) in &c.fields {
                    obj.insert((*k).to_owned(), v.to_json());
                }
                self.sink
                    .write_record(&serde_json::Value::Object(obj).to_string());
            }
            LogFormat::Text => {
                let mut line = format!(
                    "{ts} {:<5} {target}: {}",
                    level.as_str(),
                    c.message.as_deref().unwrap_or("")
                );
                for (k, v) in &c.fields {
                    use std::fmt::Write as _;
                    let _ = write!(line, " {k}={v}");
                }
                self.sink.write_record(&line);
            }
        }
    }
}

impl<S, W> Layer<S> for RedactingLayer<W>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: RecordSink,
{
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let mut c = Collector::default();

        // Ancestor span fields first, outermost to innermost, so an inner span
        // overrides an outer one and so `correlation_id` recorded on the request
        // span reaches every event inside it. This is the mechanism that makes
        // "a service cannot accidentally drop the correlation" true rather than
        // aspirational.
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                if let Some(fields) = span.extensions().get::<SpanFields>() {
                    for (k, v) in &fields.0 {
                        c.fields.push((k, v.clone()));
                    }
                }
            }
        }
        event.record(&mut c);

        if let Some(key) = c.forbidden {
            // Mirror the collector exactly: drop the WHOLE record, loudly.
            self.metrics
                .counter(
                    crate::metrics::names::FORBIDDEN_ATTR_DROPPED,
                    "records dropped whole for carrying a forbidden telemetry attribute",
                    Labels::new(),
                )
                .inc();
            // ADR-0015 O-12 says no code path may exist that renders `key`; the
            // counter is how the one that does becomes visible.
            let _ = key;
            return;
        }
        if c.not_allowlisted > 0 {
            self.metrics
                .counter(
                    crate::metrics::names::ATTR_NOT_ALLOWLISTED,
                    "fields deleted for not being on the collector allowlist",
                    Labels::new(),
                )
                .add(c.not_allowlisted);
        }
        if c.blocked_values > 0 {
            self.metrics
                .counter(
                    crate::metrics::names::BLOCKED_VALUE_REDACTED,
                    "values replaced for resembling credential material",
                    Labels::new(),
                )
                .add(c.blocked_values);
        }

        self.emit(*event.metadata().level(), event.metadata().target(), &c);
    }

    fn on_new_span(
        &self,
        attrs_: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        let mut c = Collector::default();
        attrs_.record(&mut c);
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanFields(c.fields));
        }
    }

    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: Context<'_, S>,
    ) {
        let mut c = Collector::default();
        values.record(&mut c);
        if let Some(span) = ctx.span(id) {
            let mut ext = span.extensions_mut();
            if let Some(existing) = ext.get_mut::<SpanFields>() {
                for (k, v) in c.fields {
                    existing.0.retain(|(ek, _)| *ek != k);
                    existing.0.push((k, v));
                }
            } else {
                ext.insert(SpanFields(c.fields));
            }
        }
    }
}

struct SpanFields(Vec<(&'static str, Value)>);
