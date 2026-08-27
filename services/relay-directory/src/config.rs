//! `TWINVPN_RELAYDIR_*`, from `infra/README.md` §4.7 and `docker-compose.yml`.
//!
//! Two values are marked **"must stay false" / "frozen"** there, and this module
//! refuses to start if either is altered:
//!
//! - `TWINVPN_RELAYDIR_MAP_EXPIRY_ENFORCED` — ADR-0006 §11.1 rule 4: "the map is
//!   stale-but-usable without limit. No expiry, at any age, may reduce the
//!   candidate set or block an attempt." Turning it on would make a device with
//!   an old map worse off than a device with no map, which is the failure the rule
//!   exists to prevent.
//! - `TWINVPN_RELAYDIR_REQUIRE_LITERAL_ENDPOINTS` — §11.1 rule 1: "endpoints are
//!   literals, never hostnames. **Relay reachability MUST NOT depend on DNS.**"
//!   The type system already enforces it (`fleet::RelayRecord` uses `SocketAddr`),
//!   so the variable is a declaration; turning it off would be a declaration of
//!   something untrue.
//!
//! The two floor values are frozen at 2 apiece, because architecture §2.12's "a
//! cached set of size 1 is a design error" is not a tunable.

use std::net::SocketAddr;
use std::path::PathBuf;

use twinvpn_service_common::config::{ConfigError, EnvSource, Loader};
use twinvpn_service_common::SecretString;

use crate::map::PublicationFloor;

/// A configuration that failed validation. Startup aborts on any of these.
#[derive(Debug, thiserror::Error)]
pub enum DirectoryConfigError {
    /// A variable was absent, unparseable, or a file was unreadable.
    #[error(transparent)]
    Env(#[from] ConfigError),

    /// A bounded identifier exceeded its `limits.json` cap or was empty.
    #[error("{key} is empty or over {limit} bytes")]
    Identifier {
        /// The variable.
        key: &'static str,
        /// The cap.
        limit: usize,
    },

    /// `TWINVPN_RELAYDIR_MAP_EXPIRY_ENFORCED=true`.
    #[error(
        "TWINVPN_RELAYDIR_MAP_EXPIRY_ENFORCED=true: ADR-0006 §11.1 rule 4 makes the \
         relay map stale-but-usable WITHOUT LIMIT. No expiry, at any age, may \
         reduce the candidate set or block an attempt"
    )]
    ExpiryEnforcementRefused,

    /// `TWINVPN_RELAYDIR_REQUIRE_LITERAL_ENDPOINTS=false`.
    #[error(
        "TWINVPN_RELAYDIR_REQUIRE_LITERAL_ENDPOINTS=false: relay reachability MUST \
         NOT depend on DNS (ADR-0006 §11.1 rule 1), or recovering from BLOCKED \
         would need the resolver the relay is needed to reach"
    )]
    HostnameEndpointsRefused,

    /// A floor was set below ADR-0006 §11.1 rule 3's value.
    #[error("{key} is frozen at {expected}: a cached set of size 1 is a design error")]
    FloorLowered {
        /// The variable.
        key: &'static str,
        /// The frozen value.
        expected: usize,
    },
}

/// The validated relay-directory configuration.
#[derive(Debug)]
pub struct DirectoryConfig {
    /// `TWINVPN_RELAYDIR_LISTEN_TCP`.
    pub listen_tcp: SocketAddr,
    /// `TWINVPN_RELAYDIR_LISTEN_QUIC`.
    pub listen_quic: SocketAddr,
    /// `TWINVPN_RELAYDIR_TLS_CERT_PATH`.
    pub tls_cert_path: PathBuf,
    /// `TWINVPN_RELAYDIR_TLS_KEY_PATH`.
    pub tls_key_path: PathBuf,
    /// `TWINVPN_DATABASE_URL`, fed from `TWINVPN_RELAYDIR_DATABASE_URL` by compose.
    ///
    /// A secret, so it has no default and no rendering path.
    pub database_url: SecretString,
    /// `TWINVPN_RELAYDIR_MAP_SIGNING_KEY_PATH`.
    pub map_signing_key_path: PathBuf,
    /// `TWINVPN_RELAYDIR_OPERATOR_GROUP_ID`.
    pub operator_group_id: String,
    /// The publication floor, all three values frozen.
    pub floor: PublicationFloor,
    /// `TWINVPN_RELAYDIR_MAP_TTL_MS`. **Soft freshness only.**
    pub map_ttl_ms: u64,
    /// `TWINVPN_RELAYDIR_REGION_SPREAD_MS`, ADR-0006 §11.7 `T_REGION_SPREAD`.
    pub region_spread_ms: u64,
}

impl DirectoryConfig {
    /// Loads and validates every `TWINVPN_RELAYDIR_*` variable.
    ///
    /// # Errors
    ///
    /// [`DirectoryConfigError`] for an absent required value, an unparseable one,
    /// a bound violation, or any of the three frozen-value refusals.
    pub fn load(env: &dyn EnvSource) -> Result<Self, DirectoryConfigError> {
        let l = Loader::new(env);

        let operator_group_id = l.require("TWINVPN_RELAYDIR_OPERATOR_GROUP_ID")?;
        if operator_group_id.is_empty()
            || operator_group_id.len() > twinvpn_schema::limits::TWINNET_ID_MAX_BYTES
        {
            return Err(DirectoryConfigError::Identifier {
                key: "TWINVPN_RELAYDIR_OPERATOR_GROUP_ID",
                limit: twinvpn_schema::limits::TWINNET_ID_MAX_BYTES,
            });
        }

        if l.bool("TWINVPN_RELAYDIR_MAP_EXPIRY_ENFORCED", false)? {
            return Err(DirectoryConfigError::ExpiryEnforcementRefused);
        }
        if !l.bool("TWINVPN_RELAYDIR_REQUIRE_LITERAL_ENDPOINTS", true)? {
            return Err(DirectoryConfigError::HostnameEndpointsRefused);
        }

        let min_alternates = frozen_usize(&l, "TWINVPN_RELAYDIR_MIN_ALTERNATES_PER_REGION", 2)?;
        let min_domains = frozen_usize(&l, "TWINVPN_RELAYDIR_MIN_FAILURE_DOMAINS_PER_REGION", 2)?;

        Ok(Self {
            listen_tcp: l.socket_addr("TWINVPN_RELAYDIR_LISTEN_TCP", "[::]:443")?,
            listen_quic: l.socket_addr("TWINVPN_RELAYDIR_LISTEN_QUIC", "[::]:443")?,
            tls_cert_path: l.readable_file(
                "TWINVPN_RELAYDIR_TLS_CERT_PATH",
                "/run/secrets/relay-directory/tls.crt",
            )?,
            tls_key_path: l.readable_file(
                "TWINVPN_RELAYDIR_TLS_KEY_PATH",
                "/run/secrets/relay-directory/tls.key",
            )?,
            // No default, ever: a database URL embeds a password.
            database_url: l.secret("TWINVPN_DATABASE_URL")?,
            map_signing_key_path: l.readable_file(
                "TWINVPN_RELAYDIR_MAP_SIGNING_KEY_PATH",
                "/run/secrets/relay-directory/map-signing.key",
            )?,
            operator_group_id,
            floor: PublicationFloor {
                min_alternates_per_region: min_alternates,
                min_failure_domains_per_region: min_domains,
                require_both_families: l.bool("TWINVPN_RELAYDIR_REQUIRE_BOTH_FAMILIES", true)?,
            },
            map_ttl_ms: l.u64("TWINVPN_RELAYDIR_MAP_TTL_MS", 3_600_000)?,
            region_spread_ms: l.u64("TWINVPN_RELAYDIR_REGION_SPREAD_MS", 20_000)?,
        })
    }
}

fn frozen_usize(
    l: &Loader<'_>,
    key: &'static str,
    expected: usize,
) -> Result<usize, DirectoryConfigError> {
    let v = usize::try_from(l.u64(key, expected as u64)?).unwrap_or(expected);
    if v < expected {
        return Err(DirectoryConfigError::FloorLowered { key, expected });
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_service_common::config::MapEnv;

    fn env() -> MapEnv {
        let here = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
        MapEnv::new()
            .with("TWINVPN_RELAYDIR_OPERATOR_GROUP_ID", "local-operator")
            .with("TWINVPN_RELAYDIR_TLS_CERT_PATH", here)
            .with("TWINVPN_RELAYDIR_TLS_KEY_PATH", here)
            .with("TWINVPN_RELAYDIR_MAP_SIGNING_KEY_PATH", here)
            .with("TWINVPN_DATABASE_URL", "postgres://u:p@postgres:5432/d")
    }

    #[test]
    fn the_compose_defaults_load() {
        let c = DirectoryConfig::load(&env()).expect("loads");
        assert_eq!(c.operator_group_id, "local-operator");
        assert_eq!(c.floor.min_alternates_per_region, 2);
        assert_eq!(c.floor.min_failure_domains_per_region, 2);
        assert!(c.floor.require_both_families);
        assert_eq!(c.map_ttl_ms, 3_600_000);
        assert_eq!(c.region_spread_ms, 20_000);
    }

    #[test]
    fn enforcing_map_expiry_is_a_startup_failure() {
        assert!(matches!(
            DirectoryConfig::load(&env().with("TWINVPN_RELAYDIR_MAP_EXPIRY_ENFORCED", "true"))
                .unwrap_err(),
            DirectoryConfigError::ExpiryEnforcementRefused
        ));
    }

    #[test]
    fn allowing_hostname_endpoints_is_a_startup_failure() {
        assert!(matches!(
            DirectoryConfig::load(
                &env().with("TWINVPN_RELAYDIR_REQUIRE_LITERAL_ENDPOINTS", "false")
            )
            .unwrap_err(),
            DirectoryConfigError::HostnameEndpointsRefused
        ));
    }

    #[test]
    fn the_alternates_floor_cannot_be_lowered() {
        for key in [
            "TWINVPN_RELAYDIR_MIN_ALTERNATES_PER_REGION",
            "TWINVPN_RELAYDIR_MIN_FAILURE_DOMAINS_PER_REGION",
        ] {
            for v in ["0", "1"] {
                assert!(
                    matches!(
                        DirectoryConfig::load(&env().with(key, v)).unwrap_err(),
                        DirectoryConfigError::FloorLowered { .. }
                    ),
                    "{key}={v} was accepted"
                );
            }
        }
        // Raising it is an operator's prerogative.
        let c =
            DirectoryConfig::load(&env().with("TWINVPN_RELAYDIR_MIN_ALTERNATES_PER_REGION", "3"))
                .expect("loads");
        assert_eq!(c.floor.min_alternates_per_region, 3);
    }

    #[test]
    fn the_database_url_has_no_default_and_no_rendering_path() {
        let mut e = MapEnv::new()
            .with("TWINVPN_RELAYDIR_OPERATOR_GROUP_ID", "g")
            .with(
                "TWINVPN_RELAYDIR_TLS_CERT_PATH",
                concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            );
        e = e.with(
            "TWINVPN_RELAYDIR_TLS_KEY_PATH",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
        );
        e = e.with(
            "TWINVPN_RELAYDIR_MAP_SIGNING_KEY_PATH",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
        );
        // No TWINVPN_DATABASE_URL: startup fails rather than defaulting.
        assert!(matches!(
            DirectoryConfig::load(&e).unwrap_err(),
            DirectoryConfigError::Env(_)
        ));

        let c = DirectoryConfig::load(&env()).expect("loads");
        let rendered = format!("{c:?}");
        assert!(!rendered.contains("postgres://"));
        assert!(rendered.contains("Secret(<redacted>)"));
    }
}
