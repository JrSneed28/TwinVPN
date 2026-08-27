//! `TWINVPN_PRESENCE_*`, loaded through
//! [`twinvpn_service_common::config::Loader`].
//!
//! # `TWINVPN_DATABASE_URL` is validated and deliberately unused
//!
//! `docker-compose.yml` requires it with a `${VAR:?}` guard and
//! `infra/README.md` §5 lists this service's readiness as "Postgres reachable".
//! This service writes nothing to Postgres, because a durable presence record is
//! the privacy defect `docs/protocol.md` §6.1 names — *"a permanent movement and
//! IP-address history of the Owner"* — and `presence.proto` classifies presence
//! as ephemeral for that reason among others.
//!
//! The variable is still **loaded and validated** when present: a `.env` copied
//! from `infra/env.example` unedited still fails at startup rather than running
//! with `CHANGE-ME` as a password, which is the rule `infra/README.md` §4.1
//! states one layer out. It is then dropped. `README.md` §8 raises the
//! divergence.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use twinvpn_service_common::config::{ConfigError, EnvSource, Loader};

use crate::store::StoreLimits;

/// The presence-specific configuration.
#[derive(Debug, Clone)]
pub struct PresenceConfig {
    /// `TWINVPN_PRESENCE_LISTEN_TCP`.
    pub listen_tcp: SocketAddr,
    /// `TWINVPN_PRESENCE_LISTEN_QUIC`. Parsed, not yet bound — `README.md` §9.
    pub listen_quic: SocketAddr,
    /// `TWINVPN_PRESENCE_TLS_CERT_PATH`.
    pub tls_cert_path: PathBuf,
    /// `TWINVPN_PRESENCE_TLS_KEY_PATH`.
    pub tls_key_path: PathBuf,
    /// `TWINVPN_PRESENCE_CONTROL_PLANE_URL`. Never called on the publish path.
    pub control_plane_url: String,
    /// `TWINVPN_PRESENCE_HEARTBEAT_INTERVAL_MS`. Advisory; returned in
    /// `HeartbeatAck.suggested_interval_ms`, which the device "coalesces into its
    /// existing wake window rather than adding a wake" (ADR-0002 §11.10).
    pub heartbeat_interval: Duration,
    /// Table bounds, from `TWINVPN_PRESENCE_RECORD_TTL_MS`.
    pub store: StoreLimits,
    /// Whether a database URL was supplied. Recorded so startup can say plainly
    /// that it is not used.
    pub database_url_present: bool,
    /// How long a partially received frame may take to complete.
    pub frame_read_timeout: Duration,
    /// The concurrently-served-connection ceiling.
    pub max_connections: usize,
    /// How often the TTL sweep runs.
    pub sweep_interval: Duration,
}

/// Env keys.
pub mod keys {
    /// The C1 listener.
    pub const LISTEN_TCP: &str = "TWINVPN_PRESENCE_LISTEN_TCP";
    /// The QUIC listener (parsed, not yet bound).
    pub const LISTEN_QUIC: &str = "TWINVPN_PRESENCE_LISTEN_QUIC";
    /// TLS certificate path.
    pub const TLS_CERT: &str = "TWINVPN_PRESENCE_TLS_CERT_PATH";
    /// TLS private-key path.
    pub const TLS_KEY: &str = "TWINVPN_PRESENCE_TLS_KEY_PATH";
    /// Control-plane base URL.
    pub const CONTROL_PLANE_URL: &str = "TWINVPN_PRESENCE_CONTROL_PLANE_URL";
    /// Suggested heartbeat cadence.
    pub const HEARTBEAT_INTERVAL_MS: &str = "TWINVPN_PRESENCE_HEARTBEAT_INTERVAL_MS";
    /// Record TTL, and the ceiling on a device's own claimed expiry.
    pub const RECORD_TTL_MS: &str = "TWINVPN_PRESENCE_RECORD_TTL_MS";
    /// Validated, and deliberately unused. See the module docs.
    pub const DATABASE_URL: &str = "TWINVPN_DATABASE_URL";
    /// **(new)** device-record ceiling.
    pub const MAX_DEVICES: &str = "TWINVPN_PRESENCE_MAX_DEVICES";
    /// **(new)** how long a partially received frame may take to complete.
    pub const FRAME_READ_TIMEOUT_MS: &str = "TWINVPN_PRESENCE_FRAME_READ_TIMEOUT_MS";
    /// **(new)** concurrently served connection ceiling.
    pub const MAX_CONNECTIONS: &str = "TWINVPN_PRESENCE_MAX_CONNECTIONS";
}

/// Milliseconds of a `Duration`, saturating rather than truncating.
///
/// `Duration::as_millis` is a `u128`; a cast would silently wrap a configured
/// value, which is the class of silent rewrite this codebase refuses everywhere
/// else.
#[must_use]
pub fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

impl PresenceConfig {
    /// Loads and validates every `TWINVPN_PRESENCE_*` variable.
    ///
    /// # Errors
    ///
    /// [`ConfigError`], which never carries a value — only the key and the
    /// expectation.
    pub fn load(env: &dyn EnvSource) -> Result<Self, ConfigError> {
        let l = Loader::new(env);
        let defaults = StoreLimits::default();

        // Validated if present — including the CHANGE-ME refusal — and then
        // dropped. `SecretString` has no `Display` and no `Serialize`, so this
        // value has no rendering path even by accident.
        let database_url_present = match l.secret(keys::DATABASE_URL) {
            Ok(_) => true,
            Err(ConfigError::Missing { .. }) => false,
            Err(e) => return Err(e),
        };

        let ttl = l.duration_ms(keys::RECORD_TTL_MS, defaults.record_ttl)?;

        Ok(Self {
            listen_tcp: l.socket_addr(keys::LISTEN_TCP, "[::]:443")?,
            listen_quic: l.socket_addr(keys::LISTEN_QUIC, "[::]:443")?,
            tls_cert_path: l.readable_file(keys::TLS_CERT, "/run/secrets/presence/tls.crt")?,
            tls_key_path: l.readable_file(keys::TLS_KEY, "/run/secrets/presence/tls.key")?,
            control_plane_url: l.string(keys::CONTROL_PLANE_URL, "https://control-plane:443"),
            heartbeat_interval: l
                .duration_ms(keys::HEARTBEAT_INTERVAL_MS, Duration::from_millis(30_000))?,
            store: StoreLimits {
                record_ttl: ttl,
                max_devices: usize::try_from(
                    l.u64(keys::MAX_DEVICES, defaults.max_devices as u64)?,
                )
                .unwrap_or(defaults.max_devices),
            },
            database_url_present,
            frame_read_timeout: l
                .duration_ms(keys::FRAME_READ_TIMEOUT_MS, Duration::from_millis(5_000))?,
            max_connections: usize::try_from(l.u64(keys::MAX_CONNECTIONS, 16_384)?)
                .unwrap_or(16_384),
            sweep_interval: Duration::from_millis((millis(ttl) / 4).max(250)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_service_common::config::MapEnv;

    fn base() -> MapEnv {
        MapEnv::new()
            .with(keys::TLS_CERT, "Cargo.toml")
            .with(keys::TLS_KEY, "Cargo.toml")
    }

    #[test]
    fn the_defaults_are_the_compose_defaults() {
        let cfg = PresenceConfig::load(&base()).unwrap();
        assert_eq!(cfg.listen_tcp.port(), 443);
        assert!(cfg.listen_tcp.is_ipv6());
        assert_eq!(cfg.store.record_ttl, Duration::from_millis(180_000));
        assert_eq!(cfg.heartbeat_interval, Duration::from_millis(30_000));
        assert!(!cfg.database_url_present);
    }

    #[test]
    fn an_unedited_change_me_credential_fails_at_startup() {
        let env = base().with(
            keys::DATABASE_URL,
            "postgres://twinvpn:CHANGE-ME-choose-a-real-value@postgres:5432/twinvpn_presence",
        );
        assert!(
            PresenceConfig::load(&env).is_err(),
            "a .env copied from infra/env.example unedited must not start"
        );
    }

    #[test]
    fn a_real_database_url_is_accepted_and_recorded_as_unused() {
        let env = base().with(
            keys::DATABASE_URL,
            "postgres://u:p@postgres:5432/twinvpn_presence",
        );
        let cfg = PresenceConfig::load(&env).unwrap();
        assert!(
            cfg.database_url_present,
            "recorded, so startup can say it is unused"
        );
    }

    #[test]
    fn an_ipv4_only_listener_is_configurable() {
        let env = base().with(keys::LISTEN_TCP, "0.0.0.0:443");
        assert!(PresenceConfig::load(&env).unwrap().listen_tcp.is_ipv4());
    }
}
