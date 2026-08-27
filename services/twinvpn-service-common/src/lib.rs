//! `twinvpn-service-common` — the plumbing every TwinVPN server-side artifact
//! shares.
//!
//! **Owner:** `control-plane` (`docs/implementation/ownership.md` §2).
//! **Consumers:** `control-plane`, `rendezvous`, `presence`, `relay`,
//! `relay-directory`, `relay-health`.
//!
//! # Why this crate exists
//!
//! Six divergent implementations of health, shutdown, logging, tracing and error
//! mapping is the R-31 defect class ADR-0018 CB-2 exists to prevent.
//! `infra/README.md` §7 makes the same argument about the Dockerfile: "Six
//! near-identical Dockerfiles is the same R-31 divergence class
//! `twinvpn-service-common` exists to prevent." So the design rule here is not
//! "share code" but **"make the correct thing the easy thing for four consumers
//! with different needs"** — anything awkward gets worked around four different
//! ways, which is the divergence arriving through the back door.
//!
//! # The modules, and the one question each answers
//!
//! | Module | Question |
//! |---|---|
//! | [`config`] | what does the environment say, and what happens when it says nothing? |
//! | [`health`] | is this process alive, and can it serve — **including its dependencies**? |
//! | [`admin`] | how does an operator and a `HEALTHCHECK` ask? |
//! | [`metrics`] | what does Prometheus see, and which labels may it ever see? |
//! | [`obs`] | what reaches a log, a span or a backend — and what structurally cannot? |
//! | [`correlation`] | how do `correlation_id` and `causation_id` survive a hop? |
//! | [`shutdown`] | how does this process stop without dropping work? |
//! | [`errors`] | how does an internal error become a registered `reason_code`? |
//! | [`forward`] | how is a message forwarded without losing what this build does not understand? |
//! | [`transport`] | how is untrusted input bounded, and how does backpressure behave? |
//! | [`redact`] | which values have no rendering path at all? |
//!
//! # The five properties this crate is responsible for
//!
//! 1. **No secret has a default.** [`config::Loader::secret`] has no signature
//!    that takes one (`infra/README.md` §4.1 rule 1).
//! 2. **`/readyz` reflects real dependencies.** A registry with no probe reports
//!    not-ready, and a probe timeout is not-ready
//!    ([`health::HealthRegistry`]).
//! 3. **A forbidden telemetry attribute drops the record.** Three enforcement
//!    points before the collector sees anything ([`obs`]).
//! 4. **Shutdown drains.** The wait ends on the in-flight count, not on a timer;
//!    the timer is the bound ([`shutdown::Shutdown`]).
//! 5. **A forwarded message keeps its unknown fields.** `prost` 0.13 drops them,
//!    so nothing decodes-then-re-encodes ([`forward::Forwarded`]).
//!
//! # What this crate deliberately does not do
//!
//! - **It defines no error model.** `twinvpn-types` owns `ReasonCode`,
//!   `Evidence` and `Diagnostic`; `twinvpn-schema` owns the wire encoding.
//!   [`errors::ServiceError`] adds exactly one thing: an internal-only source
//!   error that never reaches the wire.
//! - **It reads no clock and no entropy source of its own** for anything a
//!   decision depends on. [`transport::TokenBucket`] and
//!   [`transport::WriteBudget`] take `now` as a parameter
//!   (`docs/architecture.md` §5.2 R-DET-1). The wall-clock reading in the log
//!   timestamp and the `Instant` in the readiness cache are the two exceptions,
//!   and neither is an input to a protocol decision.
//! - **It links no core crate but `twinvpn-schema` and `twinvpn-types`.**
//!   ADR-0018 §11.2 rows 2.8 and 2.11: the server side is a different artifact
//!   that *shares* the schema; it does not link the core.
//!
//! # Getting a service running
//!
//! See `README.md` in this directory for the full sequence, the environment
//! table and the debugging notes. In brief:
//!
//! ```no_run
//! # use twinvpn_service_common as svc;
//! # use std::time::Duration;
//! # async fn main_() -> Result<(), Box<dyn std::error::Error>> {
//! let cfg = svc::config::ServiceConfig::load(
//!     &svc::config::SystemEnv,
//!     "control-plane",
//!     env!("CARGO_PKG_VERSION"),
//!     "COMPONENT_COORDINATION_SERVICE",
//!     svc::config::RegistryCheck::Required,
//! )?;
//!
//! let metrics = svc::metrics::Metrics::new();
//! let obs = svc::obs::init(&cfg.observability_config("instance-1"), metrics.clone())?;
//!
//! let health = svc::health::HealthRegistry::builder(
//!     svc::health::ReadinessPolicy::AnyDependency,
//! )
//! .readiness(svc::health::FnProbe::new(
//!     "postgres",
//!     svc::health::ProbeKind::Datastore,
//!     || async { svc::health::ProbeOutcome::Ready },
//! ))?
//! .build();
//!
//! let shutdown = svc::shutdown::Shutdown::new(cfg.shutdown_config(), metrics.clone())
//!     .with_health(health.clone());
//!
//! health.set_state(svc::health::ServiceState::Serving);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// `doc_markdown` fires on IPv4, IPv6, TwinVPN, TwinNet, OpenTelemetry,
// Prometheus and Postgres in prose. Those are product and protocol nouns, and
// back-ticking them would make the ADR quotations this crate carries harder to
// read than the lint is worth. Same allowance `twinvpn-types` takes.
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]

pub mod admin;
pub mod config;
pub mod correlation;
pub mod errors;
pub mod forward;
pub mod health;
pub mod metrics;
pub mod obs;
pub mod redact;
pub mod shutdown;
pub mod transport;

pub use config::{ConfigError, ServiceConfig};
pub use correlation::Correlation;
pub use errors::ServiceError;
pub use forward::{Forwarded, Verbatim};
pub use health::{
    DependencyProbe, HealthRegistry, LivenessCheck, ProbeKind, ProbeOutcome, ReadinessPolicy,
    ReadinessStatus, ServiceState,
};
pub use metrics::Metrics;
pub use redact::{Secret, SecretString, Sensitive};
pub use shutdown::{InFlight, Shutdown, ShutdownHandle, ShutdownReport};

/// The channel vocabulary, re-exported so a consumer does not have to name
/// `twinvpn-schema` to bound an input.
pub use twinvpn_schema::{Channel, Reject};

/// The domain vocabulary, re-exported for the same reason.
pub use twinvpn_types::{codes, Component, Diagnostic, Evidence, ReasonCode};
