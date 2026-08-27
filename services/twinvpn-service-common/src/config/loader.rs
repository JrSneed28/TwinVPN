//! The environment source and the typed readers over it.
//!
//! Split out of `config/mod.rs` to keep both files under the 500-line limit
//! in `CLAUDE.md`. `config` re-exports every item.
//!
//! The rule this file exists to make structural is `infra/README.md` §4.1
//! rule 1: **no secret has a default.** [`Loader::secret`] takes no default
//! parameter, so there is no signature in which a secret acquires one.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use crate::redact::SecretString;

/// Where configuration is read from.
///
/// A trait rather than `std::env` directly so a test can supply a map. Reading
/// the process environment is a global; a component that takes its source at
/// construction is testable at every boundary, which is the same argument
/// ADR-0018 CD-2 makes about `Env`.
pub trait EnvSource {
    /// The value of `key`, if set and non-empty.
    fn get(&self, key: &str) -> Option<String>;
}

/// The process environment.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEnv;

impl EnvSource for SystemEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok().filter(|v| !v.trim().is_empty())
    }
}

/// A fixed map, for tests.
#[derive(Debug, Clone, Default)]
pub struct MapEnv(BTreeMap<String, String>);

impl MapEnv {
    /// An empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Sets `key`.
    #[must_use]
    pub fn with(mut self, key: &str, value: &str) -> Self {
        self.0.insert(key.to_owned(), value.to_owned());
        self
    }
}

impl EnvSource for MapEnv {
    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned().filter(|v| !v.trim().is_empty())
    }
}

/// Why configuration was refused.
///
/// No variant carries a **value**, only a key and an expectation. A
/// `ConfigError` is logged and printed at startup, and a variant carrying the
/// value would put `TWINVPN_CP_DATABASE_URL`'s password in the first line of the
/// container log.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// A required variable is unset or empty.
    #[error("{key} is required and is not set")]
    Missing {
        /// The variable.
        key: &'static str,
    },
    /// A variable is set but could not be parsed.
    #[error("{key} is not a valid {expected}")]
    Invalid {
        /// The variable.
        key: &'static str,
        /// What the loader wanted.
        expected: &'static str,
    },
    /// A secret is still the `infra/env.example` placeholder.
    #[error("{key} is still the infra/env.example placeholder; choose a real value")]
    PlaceholderSecret {
        /// The variable.
        key: &'static str,
    },
    /// A required file is missing or unreadable.
    #[error("{key} names a file that cannot be read")]
    FileUnreadable {
        /// The variable.
        key: &'static str,
    },
    /// The mounted registry disagrees with the one this build compiled in.
    ///
    /// A service validating against bounds different from the ones it was built
    /// with is worse than one with no file: it would pass its own tests and
    /// reject real traffic.
    #[error("{key} does not match the registry this build compiled in")]
    RegistryMismatch {
        /// The variable.
        key: &'static str,
    },
}

/// Reads typed values out of an [`EnvSource`].
pub struct Loader<'a> {
    env: &'a dyn EnvSource,
}

impl<'a> Loader<'a> {
    /// A loader over `env`.
    #[must_use]
    pub const fn new(env: &'a dyn EnvSource) -> Self {
        Self { env }
    }

    /// A string with a default.
    #[must_use]
    pub fn string(&self, key: &'static str, default: &str) -> String {
        self.env.get(key).unwrap_or_else(|| default.to_owned())
    }

    /// A required string.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Missing`].
    pub fn require(&self, key: &'static str) -> Result<String, ConfigError> {
        self.env.get(key).ok_or(ConfigError::Missing { key })
    }

    /// A **secret**. There is deliberately no `secret_or_default`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Missing`] when unset; [`ConfigError::PlaceholderSecret`]
    /// when it is still the example placeholder.
    pub fn secret(&self, key: &'static str) -> Result<SecretString, ConfigError> {
        let v = self.env.get(key).ok_or(ConfigError::Missing { key })?;
        if v.contains("CHANGE-ME") {
            return Err(ConfigError::PlaceholderSecret { key });
        }
        Ok(SecretString::new(v))
    }

    /// A `u64` with a default.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`].
    pub fn u64(&self, key: &'static str, default: u64) -> Result<u64, ConfigError> {
        match self.env.get(key) {
            None => Ok(default),
            Some(v) => v.trim().parse().map_err(|_| ConfigError::Invalid {
                key,
                expected: "unsigned integer",
            }),
        }
    }

    /// A duration in milliseconds, with a default.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`].
    pub fn duration_ms(
        &self,
        key: &'static str,
        default: Duration,
    ) -> Result<Duration, ConfigError> {
        match self.env.get(key) {
            None => Ok(default),
            Some(v) => v
                .trim()
                .parse::<u64>()
                .map(Duration::from_millis)
                .map_err(|_| ConfigError::Invalid {
                    key,
                    expected: "duration in milliseconds",
                }),
        }
    }

    /// An `f64` with a default.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`].
    pub fn f64(&self, key: &'static str, default: f64) -> Result<f64, ConfigError> {
        match self.env.get(key) {
            None => Ok(default),
            Some(v) => v.trim().parse().map_err(|_| ConfigError::Invalid {
                key,
                expected: "number",
            }),
        }
    }

    /// A boolean with a default. Accepts `true`/`false`, `1`/`0`, `yes`/`no`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] — a misspelled boolean is refused rather than
    /// read as `false`, because `TWINVPN_CP_QUIC_ZERO_RTT=flase` silently
    /// meaning "off" is luck, not safety.
    pub fn bool(&self, key: &'static str, default: bool) -> Result<bool, ConfigError> {
        match self.env.get(key) {
            None => Ok(default),
            Some(v) => match v.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" | "on" => Ok(true),
                "false" | "0" | "no" | "off" => Ok(false),
                _ => Err(ConfigError::Invalid {
                    key,
                    expected: "boolean",
                }),
            },
        }
    }

    /// A socket address with a default. Accepts `[::]:9090` and `0.0.0.0:9090`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`].
    pub fn socket_addr(&self, key: &'static str, default: &str) -> Result<SocketAddr, ConfigError> {
        let raw = self.string(key, default);
        raw.parse().map_err(|_| ConfigError::Invalid {
            key,
            expected: "socket address, e.g. [::]:9090",
        })
    }

    /// A path that must name a readable file.
    ///
    /// # Errors
    ///
    /// [`ConfigError::FileUnreadable`].
    pub fn readable_file(
        &self,
        key: &'static str,
        default: &str,
    ) -> Result<std::path::PathBuf, ConfigError> {
        let p = std::path::PathBuf::from(self.string(key, default));
        std::fs::metadata(&p)
            .ok()
            .filter(std::fs::Metadata::is_file)
            .ok_or(ConfigError::FileUnreadable { key })?;
        Ok(p)
    }
}
