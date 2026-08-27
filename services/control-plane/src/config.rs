//! `TWINVPN_CP_*` — every variable, its default, and what happens when it is
//! absent.
//!
//! **Authority:** `infra/README.md` §4.3 (which names every variable below and
//! is the source they come from — this module invents none),
//! `twinvpn_service_common::config::Loader` (which owns the "no secret has a
//! default" rule), ADR-0002 §11.2/§11.3/§11.6/§11.7, `limits.json`.
//!
//! # The three rules the loader enforces here
//!
//! 1. **No secret has a default.** `TWINVPN_CP_DATABASE_URL` is loaded with
//!    [`Loader::secret`], which has no signature taking one and which refuses a
//!    value still containing `CHANGE-ME`.
//! 2. **A boolean is validated, not coerced.** `TWINVPN_CP_QUIC_ZERO_RTT=flase`
//!    is a startup failure. 0-RTT is prohibited by ADR-0001 L-CONTROL, and a
//!    misspelling silently meaning "off" would be luck rather than safety —
//!    which is exactly why [`ControlPlaneConfig::load`] also **refuses to start
//!    at all** if the value parses as `true`.
//! 3. **A frozen bound is read from the registry, not from the environment.**
//!    `infra/README.md` marks the retention floor, the write budget, the C2
//!    watermarks and the dedup window "frozen". They are compiled in from
//!    `limits.json` and the environment cannot raise them; the variables are
//!    still *read*, and a value that disagrees with the registry is a startup
//!    failure rather than a silent override.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use twinvpn_service_common::config::{ConfigError, EnvSource, Loader};
use twinvpn_service_common::redact::SecretString;

/// The control-plane API epoch this build speaks.
///
/// ADR-0014 §11.1 V-3 / ADR-0002 §11.9: fixed for the life of a control
/// connection. A version change forces a reconnect; it is never an in-place
/// upgrade.
pub const PROTO_VERSION: u32 = 1;

/// `limits.json control_plane.retention_floor_days`.
pub const RETENTION_FLOOR_DAYS: u64 = 30;
/// `limits.json control_plane.retention_floor_events`.
pub const RETENTION_FLOOR_EVENTS: u64 = 1_000_000;
/// `limits.json control_plane.durable_events_per_second_sustained`.
pub const EVENT_RATE_SUSTAINED: f64 = 1.0;
/// `limits.json control_plane.durable_events_burst`.
pub const EVENT_RATE_BURST: u32 = 20;
/// `limits.json control_plane.idempotency_dedup_window_ms` — ADR-0008 N-5.
pub const IDEMPOTENCY_WINDOW_MS: u64 = 86_400_000;
/// `limits.json control_plane.c2_backlog_watermark_bytes`.
pub const C2_WATERMARK_BYTES: usize = 262_144;
/// `limits.json control_plane.c2_backlog_watermark_events`.
pub const C2_WATERMARK_EVENTS: usize = 512;

/// The control-plane's own configuration, on top of
/// [`twinvpn_service_common::ServiceConfig`].
#[derive(Debug, Clone)]
pub struct ControlPlaneConfig {
    /// `TWINVPN_CP_LISTEN_QUIC`, default `[::]:443`. ADR-0002 §11.2 rung 1.
    pub listen_quic: SocketAddr,
    /// `TWINVPN_CP_LISTEN_TCP`, default `[::]:443`. Rungs 2–4; see README §7.
    pub listen_tcp: SocketAddr,
    /// `TWINVPN_CP_TLS_CERT_PATH`.
    pub tls_cert_path: PathBuf,
    /// `TWINVPN_CP_TLS_KEY_PATH`.
    pub tls_key_path: PathBuf,
    /// `TWINVPN_CP_DATABASE_URL`. **No default, ever.**
    pub database_url: SecretString,
    /// `TWINVPN_CP_DATABASE_MAX_CONNECTIONS`, default 16.
    pub database_max_connections: u32,
    /// `TWINVPN_CP_EVENT_BUS`, default `postgres-notify`.
    pub event_bus: String,
    /// `TWINVPN_CP_WRITE_LEASE_TTL_MS`, default 15 000. ADR-0002 N-4.
    pub write_lease_ttl: Duration,
    /// `TWINVPN_CP_ATTACH_RATE_SUSTAINED`, default 200/s. §11.7 rule 3.
    pub attach_rate_sustained: f64,
    /// `TWINVPN_CP_ATTACH_RATE_BURST`, default 1000.
    pub attach_rate_burst: u32,
    /// `TWINVPN_CP_DRAIN_DEADLINE_MS`, default 120 000. §11.7 rule 1.
    pub drain_deadline: Duration,
    /// `TWINVPN_CP_READ_STALENESS_WAIT_MS`, default 250. §11.3.
    pub read_staleness_wait: Duration,
    /// `TWINVPN_CP_QUORUM_REPLICAS`, default 0.
    ///
    /// The number of replicas that must acknowledge before an E-1-class write
    /// returns. ADR-0009 §11.2 makes this a **deployment** choice: `0` is the
    /// single-box topology (T2/T3), `≥1` the hosted one (T1). It is named here
    /// so a T1 deployment cannot silently run as a T2 one.
    pub quorum_replicas: u32,
}

impl ControlPlaneConfig {
    /// Loads and validates.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the variable and the expectation — never the
    /// value, because a `ConfigError` holding a value would put a password in
    /// the first line of the container log.
    pub fn load(env: &dyn EnvSource) -> Result<Self, ConfigError> {
        let l = Loader::new(env);

        // ADR-0001 L-CONTROL, ownership.md §6, infra/README.md §4.3: "must stay
        // false. It is named as configuration so that enabling it is a visible,
        // reviewable act rather than a silent default." Enabling it is refused.
        if l.bool("TWINVPN_CP_QUIC_ZERO_RTT", false)? {
            return Err(ConfigError::Invalid {
                key: "TWINVPN_CP_QUIC_ZERO_RTT",
                expected: "false — TLS 1.3 early data is prohibited by ADR-0001 L-CONTROL; \
                           a replayed early-data C1 request is a replayed ceremony",
            });
        }

        let cfg = Self {
            listen_quic: l.socket_addr("TWINVPN_CP_LISTEN_QUIC", "[::]:443")?,
            listen_tcp: l.socket_addr("TWINVPN_CP_LISTEN_TCP", "[::]:443")?,
            tls_cert_path: PathBuf::from(l.string(
                "TWINVPN_CP_TLS_CERT_PATH",
                "/run/secrets/control-plane/tls.crt",
            )),
            tls_key_path: PathBuf::from(l.string(
                "TWINVPN_CP_TLS_KEY_PATH",
                "/run/secrets/control-plane/tls.key",
            )),
            database_url: l.secret("TWINVPN_CP_DATABASE_URL")?,
            database_max_connections: u32::try_from(
                l.u64("TWINVPN_CP_DATABASE_MAX_CONNECTIONS", 16)?,
            )
            .map_err(|_| ConfigError::Invalid {
                key: "TWINVPN_CP_DATABASE_MAX_CONNECTIONS",
                expected: "a u32",
            })?,
            event_bus: l.string("TWINVPN_CP_EVENT_BUS", "postgres-notify"),
            write_lease_ttl: l.duration_ms(
                "TWINVPN_CP_WRITE_LEASE_TTL_MS",
                Duration::from_millis(15_000),
            )?,
            attach_rate_sustained: l.f64("TWINVPN_CP_ATTACH_RATE_SUSTAINED", 200.0)?,
            attach_rate_burst: u32::try_from(l.u64("TWINVPN_CP_ATTACH_RATE_BURST", 1_000)?)
                .map_err(|_| ConfigError::Invalid {
                    key: "TWINVPN_CP_ATTACH_RATE_BURST",
                    expected: "a u32",
                })?,
            drain_deadline: l.duration_ms(
                "TWINVPN_CP_DRAIN_DEADLINE_MS",
                Duration::from_millis(120_000),
            )?,
            read_staleness_wait: l.duration_ms(
                "TWINVPN_CP_READ_STALENESS_WAIT_MS",
                Duration::from_millis(250),
            )?,
            quorum_replicas: u32::try_from(l.u64("TWINVPN_CP_QUORUM_REPLICAS", 0)?).map_err(
                |_| ConfigError::Invalid {
                    key: "TWINVPN_CP_QUORUM_REPLICAS",
                    expected: "a u32",
                },
            )?,
        };

        // The frozen bounds. Reading them and refusing a disagreement is not the
        // same as taking them from the environment: `limits.json` is the
        // enforced value either way, and a service that silently ignored a
        // deliberately-set variable would be worse than one that says no.
        check_frozen(&l, "TWINVPN_CP_RETENTION_FLOOR_DAYS", RETENTION_FLOOR_DAYS)?;
        check_frozen(
            &l,
            "TWINVPN_CP_RETENTION_FLOOR_EVENTS",
            RETENTION_FLOOR_EVENTS,
        )?;
        check_frozen(&l, "TWINVPN_CP_EVENT_RATE_SUSTAINED", 1)?;
        check_frozen(
            &l,
            "TWINVPN_CP_EVENT_RATE_BURST",
            u64::from(EVENT_RATE_BURST),
        )?;
        check_frozen(
            &l,
            "TWINVPN_CP_C2_WATERMARK_BYTES",
            C2_WATERMARK_BYTES as u64,
        )?;
        check_frozen(
            &l,
            "TWINVPN_CP_C2_WATERMARK_EVENTS",
            C2_WATERMARK_EVENTS as u64,
        )?;
        check_frozen(
            &l,
            "TWINVPN_CP_IDEMPOTENCY_WINDOW_MS",
            IDEMPOTENCY_WINDOW_MS,
        )?;

        Ok(cfg)
    }

    /// The drain deadline as the milliseconds a `GOAWAY` carries.
    #[must_use]
    pub fn drain_deadline_ms(&self) -> u64 {
        u64::try_from(self.drain_deadline.as_millis()).unwrap_or(u64::MAX)
    }

    /// Whether this deployment requires a quorum acknowledgement for E-1-class
    /// writes.
    #[must_use]
    pub const fn requires_quorum(&self) -> bool {
        self.quorum_replicas > 0
    }
}

/// Refuses a frozen bound set to anything other than its registry value.
fn check_frozen(l: &Loader<'_>, key: &'static str, frozen: u64) -> Result<(), ConfigError> {
    let observed = l.u64(key, frozen)?;
    if observed == frozen {
        Ok(())
    } else {
        Err(ConfigError::Invalid {
            key,
            expected: "the value frozen in contracts/registry/limits.json; \
                       this bound is not environment-tunable",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ControlPlaneConfig, C2_WATERMARK_BYTES, C2_WATERMARK_EVENTS, EVENT_RATE_BURST,
        IDEMPOTENCY_WINDOW_MS, RETENTION_FLOOR_DAYS, RETENTION_FLOOR_EVENTS,
    };
    use twinvpn_service_common::config::MapEnv;

    fn minimal() -> MapEnv {
        MapEnv::new().with(
            "TWINVPN_CP_DATABASE_URL",
            "postgres://u:p@db:5432/twinvpn_control",
        )
    }

    #[test]
    fn the_database_url_has_no_default() {
        let err = ControlPlaneConfig::load(&MapEnv::new()).expect_err("no default for a secret");
        assert!(format!("{err}").contains("TWINVPN_CP_DATABASE_URL"));
    }

    #[test]
    fn an_unedited_placeholder_secret_fails_at_startup() {
        let env = MapEnv::new().with(
            "TWINVPN_CP_DATABASE_URL",
            "postgres://twinvpn:CHANGE-ME-choose-a-real-value@postgres:5432/twinvpn_control",
        );
        assert!(ControlPlaneConfig::load(&env).is_err());
    }

    #[test]
    fn zero_rtt_cannot_be_enabled_and_a_typo_is_not_silently_off() {
        let on = minimal().with("TWINVPN_CP_QUIC_ZERO_RTT", "true");
        let err = ControlPlaneConfig::load(&on).expect_err("0-RTT is prohibited");
        assert!(format!("{err}").contains("TWINVPN_CP_QUIC_ZERO_RTT"));

        // The important half: a misspelling must NOT mean "off".
        let typo = minimal().with("TWINVPN_CP_QUIC_ZERO_RTT", "flase");
        assert!(ControlPlaneConfig::load(&typo).is_err());

        // And the only accepted value loads.
        let off = minimal().with("TWINVPN_CP_QUIC_ZERO_RTT", "false");
        assert!(ControlPlaneConfig::load(&off).is_ok());
    }

    #[test]
    fn a_frozen_bound_cannot_be_widened_from_the_environment() {
        for (key, wider) in [
            ("TWINVPN_CP_RETENTION_FLOOR_DAYS", "1"),
            ("TWINVPN_CP_RETENTION_FLOOR_EVENTS", "10"),
            ("TWINVPN_CP_EVENT_RATE_SUSTAINED", "1000"),
            ("TWINVPN_CP_EVENT_RATE_BURST", "100000"),
            ("TWINVPN_CP_C2_WATERMARK_BYTES", "999999999"),
            ("TWINVPN_CP_C2_WATERMARK_EVENTS", "999999"),
            ("TWINVPN_CP_IDEMPOTENCY_WINDOW_MS", "1"),
        ] {
            let env = minimal().with(key, wider);
            assert!(
                ControlPlaneConfig::load(&env).is_err(),
                "{key} must not be environment-tunable"
            );
        }
    }

    #[test]
    fn the_defaults_are_the_infra_readme_defaults() {
        let cfg = ControlPlaneConfig::load(&minimal()).expect("loads");
        assert_eq!(cfg.listen_quic.to_string(), "[::]:443");
        assert_eq!(cfg.listen_tcp.to_string(), "[::]:443");
        assert_eq!(cfg.write_lease_ttl.as_millis(), 15_000);
        assert!((cfg.attach_rate_sustained - 200.0).abs() < f64::EPSILON);
        assert_eq!(cfg.attach_rate_burst, 1_000);
        assert_eq!(cfg.drain_deadline_ms(), 120_000);
        assert_eq!(cfg.read_staleness_wait.as_millis(), 250);
        assert_eq!(cfg.event_bus, "postgres-notify");
        assert!(!cfg.requires_quorum(), "the single-box topology is T2/T3");
    }

    #[test]
    fn the_default_listeners_are_ipv6_wildcards_so_ipv6_only_works() {
        // ADR-0010 R1: there is no "v4 story and a v6 story". `[::]` accepts
        // both families on a dual-stack host AND is the only binding that works
        // at all under infrastructure's IPv6-only compose profile.
        let cfg = ControlPlaneConfig::load(&minimal()).expect("loads");
        assert!(cfg.listen_quic.is_ipv6());
        assert!(cfg.listen_tcp.is_ipv6());
    }

    #[test]
    fn the_compiled_bounds_still_match_the_frozen_registry() {
        let json = twinvpn_schema::limits::LIMITS_JSON;
        assert!(json.contains("\"retention_floor_days\": 30"));
        assert!(json.contains("\"retention_floor_events\": 1000000"));
        assert!(json.contains("\"durable_events_per_second_sustained\": 1"));
        assert!(json.contains("\"durable_events_burst\": 20"));
        assert!(json.contains("\"c2_backlog_watermark_bytes\": 262144"));
        assert!(json.contains("\"c2_backlog_watermark_events\": 512"));
        assert!(json.contains("\"idempotency_dedup_window_ms\": 86400000"));
        assert_eq!(RETENTION_FLOOR_DAYS, 30);
        assert_eq!(RETENTION_FLOOR_EVENTS, 1_000_000);
        assert_eq!(EVENT_RATE_BURST, 20);
        assert_eq!(C2_WATERMARK_BYTES, 262_144);
        assert_eq!(C2_WATERMARK_EVENTS, 512);
        assert_eq!(IDEMPOTENCY_WINDOW_MS, 86_400_000);
    }
}
