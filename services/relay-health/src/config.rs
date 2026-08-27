//! `TWINVPN_RELAYHEALTH_*`, from `infra/README.md` §4.8.
//!
//! One value is marked `frozen` there: `TWINVPN_RELAYHEALTH_STATES` is
//! `HEALTHY,DEGRADED,UNHEALTHY,UNKNOWN`, testing-strategy A-03's four. Dropping
//! `UNKNOWN` would be the worst possible edit — it is the state that makes a
//! health-service outage cost nothing, so a fleet without it would have to call an
//! unobserved relay either healthy (a lie) or unhealthy (a fleet-wide penalty from
//! one service's failure).

use twinvpn_service_common::config::{ConfigError, EnvSource, Loader};
use twinvpn_service_common::SecretString;

use crate::aggregate::Thresholds;

/// The four states A-03 fixes, in the order compose declares them.
pub const FROZEN_STATES: [&str; 4] = ["HEALTHY", "DEGRADED", "UNHEALTHY", "UNKNOWN"];

/// A configuration that failed validation.
#[derive(Debug, thiserror::Error)]
pub enum HealthConfigError {
    /// A variable was absent, unparseable, or a file was unreadable.
    #[error(transparent)]
    Env(#[from] ConfigError),

    /// `TWINVPN_RELAYHEALTH_STATES` was altered.
    #[error(
        "TWINVPN_RELAYHEALTH_STATES is frozen to HEALTHY,DEGRADED,UNHEALTHY,UNKNOWN \
         (testing-strategy A-03). UNKNOWN in particular is what makes a \
         relay-health outage cost nothing"
    )]
    StatesAltered,

    /// A target was not `host:port`.
    #[error("TWINVPN_RELAYHEALTH_TARGETS: `{0}` is not host:port")]
    BadTarget(String),
}

/// One relay's admin listener.
///
/// **Not its data port.** `infra/README.md` §4.8: "a prober that opened a relay
/// flow would be indistinguishable from a peer and would consume the fleet's own
/// quota."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The relay's hostname or address, as configured.
    pub host: String,
    /// The **admin** port, `:9090` by default.
    pub port: u16,
}

/// The validated relay-health configuration.
#[derive(Debug)]
pub struct HealthConfig {
    /// `TWINVPN_DATABASE_URL`, fed from `TWINVPN_RELAYDIR_DATABASE_URL`.
    pub database_url: SecretString,
    /// `TWINVPN_RELAYHEALTH_TARGETS`. Empty means nothing is probed, which is a
    /// legitimate posture: every relay is `UNKNOWN`, which costs nothing.
    pub targets: Vec<Target>,
    /// `TWINVPN_RELAYHEALTH_PROBE_INTERVAL_MS`.
    pub probe_interval_ms: u64,
    /// `TWINVPN_RELAYHEALTH_PROBE_TIMEOUT_MS`.
    pub probe_timeout_ms: u64,
    /// Derived thresholds.
    pub thresholds: Thresholds,
}

impl HealthConfig {
    /// Loads and validates every `TWINVPN_RELAYHEALTH_*` variable.
    ///
    /// # Errors
    ///
    /// [`HealthConfigError`] for an absent secret, an unparseable value, an
    /// altered state set, or a malformed target.
    pub fn load(env: &dyn EnvSource) -> Result<Self, HealthConfigError> {
        let l = Loader::new(env);

        let states = l.string("TWINVPN_RELAYHEALTH_STATES", &FROZEN_STATES.join(","));
        let declared: Vec<&str> = states.split(',').map(str::trim).collect();
        if declared != FROZEN_STATES {
            return Err(HealthConfigError::StatesAltered);
        }

        let raw = l.string("TWINVPN_RELAYHEALTH_TARGETS", "");
        let mut targets = Vec::new();
        for t in raw.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            let (host, port) = t
                .rsplit_once(':')
                .ok_or_else(|| HealthConfigError::BadTarget(t.to_owned()))?;
            let port: u16 = port
                .parse()
                .map_err(|_| HealthConfigError::BadTarget(t.to_owned()))?;
            // `limits.json ports` is a validation bound (W-8), and this is the
            // validation it bounds.
            if host.is_empty() || port == 0 {
                return Err(HealthConfigError::BadTarget(t.to_owned()));
            }
            targets.push(Target {
                host: host.to_owned(),
                port,
            });
        }

        Ok(Self {
            database_url: l.secret("TWINVPN_DATABASE_URL")?,
            targets,
            probe_interval_ms: l.u64("TWINVPN_RELAYHEALTH_PROBE_INTERVAL_MS", 10_000)?,
            probe_timeout_ms: l.u64("TWINVPN_RELAYHEALTH_PROBE_TIMEOUT_MS", 3_000)?,
            thresholds: Thresholds {
                degraded_rtt_ms: u32::try_from(l.u64("TWINVPN_RELAYHEALTH_DEGRADED_RTT_MS", 250)?)
                    .unwrap_or(250),
                staleness_ms: l
                    .u64("TWINVPN_RELAYHEALTH_PROBE_INTERVAL_MS", 10_000)?
                    .saturating_mul(6),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_service_common::config::MapEnv;

    fn env() -> MapEnv {
        MapEnv::new().with("TWINVPN_DATABASE_URL", "postgres://u:p@postgres:5432/d")
    }

    #[test]
    fn the_compose_defaults_load() {
        let c = HealthConfig::load(
            &env().with("TWINVPN_RELAYHEALTH_TARGETS", "relay-a:9090,relay-b:9090"),
        )
        .expect("loads");
        assert_eq!(
            c.targets,
            vec![
                Target {
                    host: "relay-a".into(),
                    port: 9090
                },
                Target {
                    host: "relay-b".into(),
                    port: 9090
                },
            ]
        );
        assert_eq!(c.probe_interval_ms, 10_000);
        assert_eq!(c.probe_timeout_ms, 3_000);
        assert_eq!(c.thresholds.degraded_rtt_ms, 250);
    }

    #[test]
    fn no_targets_is_a_legitimate_posture_rather_than_an_error() {
        // Nothing probed means every relay is UNKNOWN, which costs nothing. A
        // health service that refused to start without targets would be a health
        // service that could take the fleet's ranking down with it.
        let c = HealthConfig::load(&env()).expect("loads");
        assert!(c.targets.is_empty());
    }

    #[test]
    fn altering_the_state_set_is_a_startup_failure() {
        assert!(matches!(
            HealthConfig::load(
                &env().with("TWINVPN_RELAYHEALTH_STATES", "HEALTHY,DEGRADED,UNHEALTHY")
            )
            .unwrap_err(),
            HealthConfigError::StatesAltered
        ));
    }

    #[test]
    fn a_malformed_target_is_refused_rather_than_skipped() {
        for bad in ["relay-a", "relay-a:0", ":9090", "relay-a:notaport"] {
            assert!(
                matches!(
                    HealthConfig::load(&env().with("TWINVPN_RELAYHEALTH_TARGETS", bad))
                        .unwrap_err(),
                    HealthConfigError::BadTarget(_)
                ),
                "{bad} was accepted"
            );
        }
    }

    #[test]
    fn an_ipv6_literal_target_parses() {
        let c = HealthConfig::load(&env().with("TWINVPN_RELAYHEALTH_TARGETS", "[::1]:9090"))
            .expect("loads");
        assert_eq!(c.targets[0].host, "[::1]");
        assert_eq!(c.targets[0].port, 9090);
    }

    #[test]
    fn the_database_url_has_no_default_and_no_rendering_path() {
        assert!(matches!(
            HealthConfig::load(&MapEnv::new()).unwrap_err(),
            HealthConfigError::Env(_)
        ));
        let c = HealthConfig::load(&env()).expect("loads");
        let rendered = format!("{c:?}");
        assert!(!rendered.contains("postgres://"));
        assert!(rendered.contains("Secret(<redacted>)"));
    }
}
