//! Typed, validated environment configuration.
//!
//! **Authority:** `infra/README.md` §4 (the variable table, its defaults, and
//! **what happens when each is absent**), `infra/env.example`,
//! `docker-compose.yml`'s `&service-env` anchor, `docs/implementation/ownership.md`
//! §6 rule 8.
//!
//! # The rule that shapes the API
//!
//! `infra/README.md` §4.1 rule 1: **no secret has a default.** The compose file
//! enforces it with `${VAR:?message}` and the infra CI lane asserts the guard
//! bites. This loader enforces the same rule in the type system:
//! [`Loader::secret`] takes **no default parameter**, so there is no signature in
//! which a secret acquires one. [`Loader::string`] and its siblings take a
//! default because a non-secret is allowed one.
//!
//! A secret that is still the placeholder from `infra/env.example` is refused as
//! well ([`ConfigError::PlaceholderSecret`]). The example file is written so that
//! copying it unedited fails at startup; this makes it fail the same way when the
//! variable reaches the process by some other route.
//!
//! # Variable names come from `infra/`, they are not invented here
//!
//! Every name below already appears in `infra/env.example` and in
//! `docker-compose.yml`. A parallel set would mean a service configured through
//! variables the compose file does not set, which is the divergence this crate
//! exists to prevent — and it would be invisible until deployment.

mod loader;

pub use loader::{ConfigError, EnvSource, Loader, MapEnv, SystemEnv};

use std::net::SocketAddr;
use std::time::Duration;

use tracing::level_filters::LevelFilter;

use crate::obs::layer::LogFormat;

/// Which address families this deployment uses (ADR-0010 R1).
///
/// `ipv4` exists because `infra/README.md` §3 keeps a v4-only override as **the
/// control run**, not a deployment mode: "absence of a signal is not evidence
/// unless the signal was provably possible". A service that only works there is
/// broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressFamilies {
    /// Both, the default.
    #[default]
    Dual,
    /// IPv4 only — the control run.
    V4Only,
    /// IPv6 only — the topology that finds v6 defects.
    V6Only,
}

impl AddressFamilies {
    fn parse(key: &'static str, s: &str) -> Result<Self, ConfigError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "dual" => Ok(Self::Dual),
            "ipv4" | "v4" => Ok(Self::V4Only),
            "ipv6" | "v6" => Ok(Self::V6Only),
            _ => Err(ConfigError::Invalid {
                key,
                expected: "dual | ipv4 | ipv6",
            }),
        }
    }

    /// Whether IPv4 is in use.
    #[must_use]
    pub const fn v4(self) -> bool {
        matches!(self, Self::Dual | Self::V4Only)
    }
    /// Whether IPv6 is in use.
    #[must_use]
    pub const fn v6(self) -> bool {
        matches!(self, Self::Dual | Self::V6Only)
    }
}

/// The configuration every server-side artifact shares.
///
/// Per-service configuration (`TWINVPN_CP_*`, `TWINVPN_RELAY_*`, …) belongs to
/// its own domain and is loaded with the same [`Loader`].
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceConfig {
    /// `TWINVPN_SERVICE_NAME`.
    pub service_name: String,
    /// The artifact's own version, supplied by the caller (`CARGO_PKG_VERSION`).
    pub service_version: String,
    /// `twinvpn.component` — one of `errors.proto`'s `Component` names.
    pub component: String,
    /// `TWINVPN_ENVIRONMENT`, default `local`.
    pub environment: String,
    /// `TWINVPN_LOG_LEVEL`, default `info`.
    pub log_level: LevelFilter,
    /// `TWINVPN_LOG_FORMAT`, default `json`.
    pub log_format: LogFormat,
    /// `TWINVPN_LOG_LEVEL_EXPIRY_MS`, default 1 h.
    pub log_level_expiry: Duration,
    /// `TWINVPN_ADMIN_ADDR`, default `[::]:9090`.
    pub admin_addr: SocketAddr,
    /// `TWINVPN_SHUTDOWN_GRACE_MS`, default 120 s.
    pub shutdown_grace: Duration,
    /// `TWINVPN_SHUTDOWN_DRAIN_DEADLINE_MS`, default 120 s.
    pub shutdown_drain_deadline: Duration,
    /// `TWINVPN_ADDRESS_FAMILIES`, default `dual`.
    pub address_families: AddressFamilies,
    /// `TWINVPN_HAPPY_EYEBALLS_V6_BIAS_MS`, default 250 ms (RFC 8305).
    pub happy_eyeballs_v6_bias: Duration,
    /// `TWINVPN_OTEL_ENABLED`, default true.
    pub otel_enabled: bool,
    /// `OTEL_EXPORTER_OTLP_ENDPOINT`.
    pub otel_endpoint: String,
    /// `OTEL_TRACES_SAMPLER_ARG`, default 1.0.
    pub otel_sampler_ratio: f64,
    /// `TWINVPN_LIMITS_PATH`.
    pub limits_path: std::path::PathBuf,
    /// `TWINVPN_REASON_CODES_PATH`.
    pub reason_codes_path: std::path::PathBuf,
}

/// Variable names, so a service names them once.
pub mod keys {
    /// `TWINVPN_SERVICE_NAME`.
    pub const SERVICE_NAME: &str = "TWINVPN_SERVICE_NAME";
    /// `TWINVPN_ENVIRONMENT`.
    pub const ENVIRONMENT: &str = "TWINVPN_ENVIRONMENT";
    /// `TWINVPN_LOG_LEVEL`.
    pub const LOG_LEVEL: &str = "TWINVPN_LOG_LEVEL";
    /// `TWINVPN_LOG_FORMAT`.
    pub const LOG_FORMAT: &str = "TWINVPN_LOG_FORMAT";
    /// `TWINVPN_LOG_LEVEL_EXPIRY_MS`.
    pub const LOG_LEVEL_EXPIRY_MS: &str = "TWINVPN_LOG_LEVEL_EXPIRY_MS";
    /// `TWINVPN_ADMIN_ADDR`.
    pub const ADMIN_ADDR: &str = "TWINVPN_ADMIN_ADDR";
    /// `TWINVPN_SHUTDOWN_GRACE_MS`.
    pub const SHUTDOWN_GRACE_MS: &str = "TWINVPN_SHUTDOWN_GRACE_MS";
    /// `TWINVPN_SHUTDOWN_DRAIN_DEADLINE_MS`.
    pub const SHUTDOWN_DRAIN_DEADLINE_MS: &str = "TWINVPN_SHUTDOWN_DRAIN_DEADLINE_MS";
    /// `TWINVPN_ADDRESS_FAMILIES`.
    pub const ADDRESS_FAMILIES: &str = "TWINVPN_ADDRESS_FAMILIES";
    /// `TWINVPN_HAPPY_EYEBALLS_V6_BIAS_MS`.
    pub const HAPPY_EYEBALLS_V6_BIAS_MS: &str = "TWINVPN_HAPPY_EYEBALLS_V6_BIAS_MS";
    /// `TWINVPN_OTEL_ENABLED`.
    pub const OTEL_ENABLED: &str = "TWINVPN_OTEL_ENABLED";
    /// `OTEL_EXPORTER_OTLP_ENDPOINT`.
    pub const OTEL_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
    /// `OTEL_TRACES_SAMPLER_ARG`.
    pub const OTEL_SAMPLER_ARG: &str = "OTEL_TRACES_SAMPLER_ARG";
    /// `TWINVPN_LIMITS_PATH`.
    pub const LIMITS_PATH: &str = "TWINVPN_LIMITS_PATH";
    /// `TWINVPN_REASON_CODES_PATH`.
    pub const REASON_CODES_PATH: &str = "TWINVPN_REASON_CODES_PATH";
}

/// How strictly the mounted registries are checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RegistryCheck {
    /// The files must exist and must match the compiled-in registry. The
    /// production setting: `docker-compose.yml` bind-mounts
    /// `contracts/registry` read-only into every service.
    #[default]
    Required,
    /// Skip the check. For a unit test or a host with no mount.
    Skip,
}

impl ServiceConfig {
    /// Loads the shared configuration.
    ///
    /// `component` is the `errors.proto` `Component` this artifact reports as;
    /// `service_version` is normally `env!("CARGO_PKG_VERSION")`. Neither comes
    /// from the environment, because both are properties of the build.
    ///
    /// # Errors
    ///
    /// The first [`ConfigError`] encountered. Loading stops there rather than
    /// accumulating: a service that starts with half its configuration is the
    /// failure this returns an error to prevent.
    pub fn load(
        env: &dyn EnvSource,
        default_service_name: &str,
        service_version: &str,
        component: &str,
        registries: RegistryCheck,
    ) -> Result<Self, ConfigError> {
        let l = Loader::new(env);

        let log_level = parse_level(keys::LOG_LEVEL, &l.string(keys::LOG_LEVEL, "info"))?;
        let log_format = LogFormat::parse(&l.string(keys::LOG_FORMAT, "json")).map_err(|_| {
            ConfigError::Invalid {
                key: keys::LOG_FORMAT,
                expected: "json | text",
            }
        })?;

        let (limits_path, reason_codes_path) = match registries {
            RegistryCheck::Skip => (
                std::path::PathBuf::from(
                    l.string(keys::LIMITS_PATH, "/contracts/registry/limits.json"),
                ),
                std::path::PathBuf::from(l.string(
                    keys::REASON_CODES_PATH,
                    "/contracts/registry/reason_codes.json",
                )),
            ),
            RegistryCheck::Required => {
                let limits =
                    l.readable_file(keys::LIMITS_PATH, "/contracts/registry/limits.json")?;
                check_matches_compiled(
                    keys::LIMITS_PATH,
                    &limits,
                    twinvpn_schema::limits::LIMITS_JSON,
                )?;
                let codes = l.readable_file(
                    keys::REASON_CODES_PATH,
                    "/contracts/registry/reason_codes.json",
                )?;
                check_registry_version(keys::REASON_CODES_PATH, &codes)?;
                (limits, codes)
            }
        };

        Ok(Self {
            service_name: l.string(keys::SERVICE_NAME, default_service_name),
            service_version: service_version.to_owned(),
            component: component.to_owned(),
            environment: l.string(keys::ENVIRONMENT, "local"),
            log_level,
            log_format,
            log_level_expiry: l
                .duration_ms(keys::LOG_LEVEL_EXPIRY_MS, Duration::from_millis(3_600_000))?,
            admin_addr: l.socket_addr(keys::ADMIN_ADDR, "[::]:9090")?,
            shutdown_grace: l
                .duration_ms(keys::SHUTDOWN_GRACE_MS, Duration::from_millis(120_000))?,
            shutdown_drain_deadline: l.duration_ms(
                keys::SHUTDOWN_DRAIN_DEADLINE_MS,
                Duration::from_millis(120_000),
            )?,
            address_families: AddressFamilies::parse(
                keys::ADDRESS_FAMILIES,
                &l.string(keys::ADDRESS_FAMILIES, "dual"),
            )?,
            happy_eyeballs_v6_bias: l
                .duration_ms(keys::HAPPY_EYEBALLS_V6_BIAS_MS, Duration::from_millis(250))?,
            otel_enabled: l.bool(keys::OTEL_ENABLED, true)?,
            otel_endpoint: l.string(keys::OTEL_ENDPOINT, "http://otel-collector:4317"),
            otel_sampler_ratio: l.f64(keys::OTEL_SAMPLER_ARG, 1.0)?,
            limits_path,
            reason_codes_path,
        })
    }

    /// The shutdown timings.
    #[must_use]
    pub fn shutdown_config(&self) -> crate::shutdown::ShutdownConfig {
        crate::shutdown::ShutdownConfig {
            grace: self.shutdown_grace,
            drain_deadline: self.shutdown_drain_deadline,
            ..crate::shutdown::ShutdownConfig::default()
        }
    }

    /// The observability configuration, with `instance_id` supplied by the
    /// caller (a hostname, a container id, a random value from the platform
    /// CSPRNG — this crate reads no clock and no entropy source).
    #[must_use]
    pub fn observability_config(&self, instance_id: &str) -> crate::obs::ObservabilityConfig {
        crate::obs::ObservabilityConfig {
            service_name: self.service_name.clone(),
            service_version: self.service_version.clone(),
            instance_id: instance_id.to_owned(),
            environment: self.environment.clone(),
            component: self.component.clone(),
            log_level: self.log_level,
            log_format: self.log_format,
            log_level_expiry: self.log_level_expiry,
            otel: crate::obs::otel::OtelConfig {
                enabled: self.otel_enabled,
                endpoint: self.otel_endpoint.clone(),
                sampler_ratio: self.otel_sampler_ratio,
                export_timeout: Duration::from_secs(10),
            },
        }
    }
}

fn parse_level(key: &'static str, s: &str) -> Result<LevelFilter, ConfigError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "off" => Ok(LevelFilter::OFF),
        // ADR-0015 §11.5 names the top level CRITICAL; `tracing` has no such
        // level and ERROR is its most severe. Accepting the ADR's spelling means
        // a value copied from the ADR configures the service.
        "critical" | "error" => Ok(LevelFilter::ERROR),
        "warn" | "warning" => Ok(LevelFilter::WARN),
        "info" => Ok(LevelFilter::INFO),
        "debug" => Ok(LevelFilter::DEBUG),
        "trace" => Ok(LevelFilter::TRACE),
        _ => Err(ConfigError::Invalid {
            key,
            expected: "off | critical | error | warn | info | debug | trace",
        }),
    }
}

fn check_matches_compiled(
    key: &'static str,
    path: &std::path::Path,
    compiled: &str,
) -> Result<(), ConfigError> {
    let on_disk = std::fs::read_to_string(path).map_err(|_| ConfigError::FileUnreadable { key })?;
    let a: serde_json::Value =
        serde_json::from_str(&on_disk).map_err(|_| ConfigError::Invalid {
            key,
            expected: "JSON registry",
        })?;
    let b: serde_json::Value =
        serde_json::from_str(compiled).map_err(|_| ConfigError::Invalid {
            key,
            expected: "JSON registry",
        })?;
    if a == b {
        Ok(())
    } else {
        Err(ConfigError::RegistryMismatch { key })
    }
}

fn check_registry_version(key: &'static str, path: &std::path::Path) -> Result<(), ConfigError> {
    let raw = std::fs::read_to_string(path).map_err(|_| ConfigError::FileUnreadable { key })?;
    let v: serde_json::Value = serde_json::from_str(&raw).map_err(|_| ConfigError::Invalid {
        key,
        expected: "JSON registry",
    })?;
    let on_disk = v
        .get("registry_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or(ConfigError::Invalid {
            key,
            expected: "JSON registry with a registry_version",
        })?;
    if on_disk == u64::from(twinvpn_types::REASON_REGISTRY_VERSION) {
        Ok(())
    } else {
        Err(ConfigError::RegistryMismatch { key })
    }
}
