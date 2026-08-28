//! `TWINVPN_RZ_*`, loaded through [`twinvpn_service_common::config::Loader`] so
//! the "no secret has a default" rule and the typed-error behaviour are the same
//! here as everywhere else.
//!
//! Every name below is `infra/env.example`'s and `docker-compose.yml`'s; this
//! crate invents only the four resource ceilings marked **(new)** in
//! `README.md` §3, which `infra/README.md` §4.3 does not list and which are
//! reported to the integration lead.
//!
//! # The frozen values are read, not hardcoded
//!
//! `infra/README.md` §4.3 marks `TWINVPN_RZ_MAILBOX_TTL_MS`,
//! `_CAPACITY_PER_TARGET`, `_OVERFLOW_POLICY`, `_C4_MAX_BYTES`, `_C4_MAX_DEPTH`,
//! `_MAX_CANDIDATES_PER_SET` and `_CANDIDATE_EXPIRY_MS` **frozen**. They are
//! read anyway and then *asserted* against the compiled-in registry, because a
//! compose file that quietly sets `TWINVPN_RZ_C4_MAX_BYTES: 65536` must fail at
//! startup rather than run with a widened hostile boundary. A frozen value that
//! is merely ignored is a frozen value nobody notices being wrong.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use twinvpn_service_common::config::{ConfigError, EnvSource, Loader};

use crate::admission::AdmissionLimits;
use crate::attach::AttachLimits;
use crate::mailbox::MailboxLimits;

/// The rendezvous-specific configuration.
#[derive(Debug, Clone)]
pub struct RendezvousConfig {
    /// `TWINVPN_RZ_LISTEN_TCP`. The C4 ingress listener.
    pub listen_tcp: SocketAddr,
    /// `TWINVPN_RZ_LISTEN_QUIC`. Parsed and validated; **not yet bound** — see
    /// `README.md` §9.
    pub listen_quic: SocketAddr,
    /// `TWINVPN_RZ_TLS_CERT_PATH`. Required to exist because `docker-compose.yml`
    /// mounts it; **not used**. In RFC 7250 mode the server's identity is its
    /// key, and a certificate is the naming system ADR-0001 §6 rejected.
    pub tls_cert_path: PathBuf,
    /// `TWINVPN_RZ_TLS_KEY_PATH`. **The server's whole identity.** Required to
    /// exist, be readable, and parse as a private key; anything else is a
    /// startup failure, never a plaintext listener.
    pub tls_key_path: PathBuf,
    /// `TWINVPN_RZ_CONTROL_PLANE_URL`. Recorded for authorization work that is
    /// **not** on the `CALL` path and **not** on the readiness path (I5).
    pub control_plane_url: String,
    /// `TWINVPN_RZ_CALL_DELIVERY_P50_BUDGET_MS`. ADR-0002 §9's budget, carried so
    /// the metric that measures it can name what it is measured against.
    pub call_delivery_p50_budget: Duration,
    /// Mailbox ceilings.
    pub mailbox: MailboxLimits,
    /// Attachment ceilings.
    pub attach: AttachLimits,
    /// `device_id` ↔ channel-identity binding ceilings.
    pub binding: twinvpn_service_common::binding::BindingLimits,
    /// Per-source admission.
    pub admission: AdmissionLimits,
    /// How often the TTL sweep runs.
    pub sweep_interval: Duration,
    /// How long a *partially received* frame may take to complete.
    ///
    /// This is the slowloris bound. Without it a caller can declare a body,
    /// send one octet of it, and hold a socket and its buffer open for ever —
    /// an allocation an unauthenticated attacker controls the lifetime of,
    /// which is `ownership.md` §6 rule 10 read as it is meant to be. It does
    /// **not** apply while a connection is idle between frames, because an
    /// attached peer waiting for a `CALL` is idle by design.
    pub frame_read_timeout: Duration,
    /// The ceiling on concurrently served connections.
    pub max_connections: usize,
}

/// Env keys, so a test and the loader cannot disagree about a spelling.
pub mod keys {
    /// The C4 ingress listener.
    pub const LISTEN_TCP: &str = "TWINVPN_RZ_LISTEN_TCP";
    /// The QUIC listener (parsed, not yet bound).
    pub const LISTEN_QUIC: &str = "TWINVPN_RZ_LISTEN_QUIC";
    /// TLS certificate path.
    pub const TLS_CERT: &str = "TWINVPN_RZ_TLS_CERT_PATH";
    /// TLS private-key path.
    pub const TLS_KEY: &str = "TWINVPN_RZ_TLS_KEY_PATH";
    /// Control-plane base URL (authorization only).
    pub const CONTROL_PLANE_URL: &str = "TWINVPN_RZ_CONTROL_PLANE_URL";
    /// ADR-0002 §11.5 mailbox TTL. Frozen at 30 s.
    pub const MAILBOX_TTL_MS: &str = "TWINVPN_RZ_MAILBOX_TTL_MS";
    /// ADR-0002 §11.5 per-target capacity. Frozen at 8.
    pub const MAILBOX_CAPACITY: &str = "TWINVPN_RZ_MAILBOX_CAPACITY_PER_TARGET";
    /// ADR-0002 §11.5 overflow policy. Frozen at `drop-oldest`.
    pub const MAILBOX_OVERFLOW_POLICY: &str = "TWINVPN_RZ_MAILBOX_OVERFLOW_POLICY";
    /// ADR-0002 §9's delivery budget.
    pub const CALL_P50_BUDGET_MS: &str = "TWINVPN_RZ_CALL_DELIVERY_P50_BUDGET_MS";
    /// `limits.json envelope.c4_max_bytes`. Frozen at 1200.
    pub const C4_MAX_BYTES: &str = "TWINVPN_RZ_C4_MAX_BYTES";
    /// `limits.json envelope.c4_max_depth`. Frozen at 4.
    pub const C4_MAX_DEPTH: &str = "TWINVPN_RZ_C4_MAX_DEPTH";
    /// `limits.json candidates.max_candidates_per_set`. Frozen at 32.
    pub const MAX_CANDIDATES: &str = "TWINVPN_RZ_MAX_CANDIDATES_PER_SET";
    /// `limits.json candidates.default_expiry_ms`. Frozen at 30000.
    pub const CANDIDATE_EXPIRY_MS: &str = "TWINVPN_RZ_CANDIDATE_EXPIRY_MS";
    /// **(new)** distinct-target ceiling on the mailbox store.
    pub const MAX_MAILBOX_TARGETS: &str = "TWINVPN_RZ_MAX_MAILBOX_TARGETS";
    /// **(new)** process-wide ceiling on retained mailbox bytes.
    pub const MAX_MAILBOX_BYTES: &str = "TWINVPN_RZ_MAX_MAILBOX_BYTES";
    /// **(new)** concurrently attached device ceiling.
    pub const MAX_ATTACHMENTS: &str = "TWINVPN_RZ_MAX_ATTACHMENTS";
    /// **(new)** sustained `CALL`s per second from one source address.
    pub const SOURCE_RATE_PER_SEC: &str = "TWINVPN_RZ_SOURCE_RATE_PER_SEC";
    /// **(new)** burst depth for the above.
    pub const SOURCE_BURST: &str = "TWINVPN_RZ_SOURCE_BURST";
    /// **(new)** how long a partially received frame may take to complete.
    pub const FRAME_READ_TIMEOUT_MS: &str = "TWINVPN_RZ_FRAME_READ_TIMEOUT_MS";
    /// **(new)** concurrently served connection ceiling.
    pub const MAX_CONNECTIONS: &str = "TWINVPN_RZ_MAX_CONNECTIONS";
    /// **(new)** how long a `device_id`↔channel binding outlives its connection.
    pub const BINDING_TTL_MS: &str = "TWINVPN_RZ_BINDING_TTL_MS";
    /// **(new)** concurrently held binding ceiling.
    pub const MAX_BINDINGS: &str = "TWINVPN_RZ_MAX_BINDINGS";
}

/// A frozen value arrived disagreeing with the compiled-in registry.
#[derive(Debug, thiserror::Error)]
#[error("{key}: {observed} disagrees with the frozen {expected}; refusing to widen a bound")]
pub struct FrozenMismatch {
    /// Which variable.
    pub key: &'static str,
    /// What the environment said.
    pub observed: u64,
    /// What `contracts/registry/limits.json` says.
    pub expected: u64,
}

/// Startup failed.
#[derive(Debug, thiserror::Error)]
pub enum RendezvousConfigError {
    /// A variable was absent, unparseable, or a secret still said `CHANGE-ME`.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// A frozen bound was overridden.
    #[error(transparent)]
    Frozen(#[from] FrozenMismatch),
}

impl RendezvousConfig {
    /// Loads and validates every `TWINVPN_RZ_*` variable.
    ///
    /// # Errors
    ///
    /// [`RendezvousConfigError`]. A `ConfigError` never carries the *value*,
    /// only the key and the expectation.
    pub fn load(env: &dyn EnvSource) -> Result<Self, RendezvousConfigError> {
        let l = Loader::new(env);

        let listen_tcp = l.socket_addr(keys::LISTEN_TCP, "[::]:443")?;
        let listen_quic = l.socket_addr(keys::LISTEN_QUIC, "[::]:443")?;
        let tls_cert_path = l.readable_file(keys::TLS_CERT, "/run/secrets/rendezvous/tls.crt")?;
        let tls_key_path = l.readable_file(keys::TLS_KEY, "/run/secrets/rendezvous/tls.key")?;
        let control_plane_url = l.string(keys::CONTROL_PLANE_URL, "https://control-plane:443");

        let (ttl_ms, capacity) = check_frozen(&l)?;

        // --- this service's own ceilings ------------------------------------
        let defaults = MailboxLimits::default();
        let mailbox = MailboxLimits {
            capacity_per_target: usize::try_from(capacity).unwrap_or(8),
            max_targets: usize::try_from(
                l.u64(keys::MAX_MAILBOX_TARGETS, defaults.max_targets as u64)?,
            )
            .unwrap_or(defaults.max_targets),
            max_total_bytes: usize::try_from(
                l.u64(keys::MAX_MAILBOX_BYTES, defaults.max_total_bytes as u64)?,
            )
            .unwrap_or(defaults.max_total_bytes),
            ttl: Duration::from_millis(ttl_ms),
        };
        let attach_defaults = AttachLimits::default();
        let attach = AttachLimits {
            max_attachments: usize::try_from(l.u64(
                keys::MAX_ATTACHMENTS,
                attach_defaults.max_attachments as u64,
            )?)
            .unwrap_or(attach_defaults.max_attachments),
            ..attach_defaults
        };
        let admission_defaults = AdmissionLimits::default();
        let admission = AdmissionLimits {
            sustained_per_sec: l.f64(
                keys::SOURCE_RATE_PER_SEC,
                admission_defaults.sustained_per_sec,
            )?,
            burst: u32::try_from(l.u64(keys::SOURCE_BURST, u64::from(admission_defaults.burst))?)
                .unwrap_or(admission_defaults.burst),
            ..admission_defaults
        };

        let binding_defaults = twinvpn_service_common::binding::BindingLimits::default();
        let binding = twinvpn_service_common::binding::BindingLimits {
            ttl: l.duration_ms(keys::BINDING_TTL_MS, binding_defaults.ttl)?,
            max_bindings: usize::try_from(
                l.u64(keys::MAX_BINDINGS, binding_defaults.max_bindings as u64)?,
            )
            .unwrap_or(binding_defaults.max_bindings),
            // A device attaching speaks for itself and nothing else. Not
            // configurable: `ManySubjectsPerChannel` is the relay's shape, and
            // it would let one key hold every mailbox it could name.
            cardinality: twinvpn_service_common::binding::BindingCardinality::OneSubjectPerChannel,
        };

        Ok(Self {
            listen_tcp,
            listen_quic,
            tls_cert_path,
            tls_key_path,
            control_plane_url,
            call_delivery_p50_budget: l
                .duration_ms(keys::CALL_P50_BUDGET_MS, Duration::from_millis(150))?,
            mailbox,
            attach,
            binding,
            admission,
            // A quarter of the shortest TTL: short enough that expired bytes do
            // not linger, long enough not to be a busy loop.
            sweep_interval: Duration::from_millis((ttl_ms / 4).max(250)),
            frame_read_timeout: l
                .duration_ms(keys::FRAME_READ_TIMEOUT_MS, Duration::from_millis(5_000))?,
            max_connections: usize::try_from(l.u64(keys::MAX_CONNECTIONS, 16_384)?)
                .unwrap_or(16_384),
        })
    }
}

/// Reads every value `infra/README.md` §4.3 marks **frozen** and asserts each
/// against the registry this build compiled in.
///
/// Reading them and then asserting — rather than ignoring them — is the point: a
/// compose file that quietly sets `TWINVPN_RZ_C4_MAX_BYTES: 65536` would
/// otherwise run with a widened hostile boundary and nothing would say so.
///
/// Returns the two values the rest of the configuration needs: the mailbox TTL
/// and its per-target capacity.
fn check_frozen(l: &Loader<'_>) -> Result<(u64, u64), RendezvousConfigError> {
    let ttl_ms = l.u64(keys::MAILBOX_TTL_MS, 30_000)?;
    frozen(keys::MAILBOX_TTL_MS, ttl_ms, 30_000)?;

    let capacity = l.u64(keys::MAILBOX_CAPACITY, 8)?;
    frozen(keys::MAILBOX_CAPACITY, capacity, 8)?;

    if l.string(keys::MAILBOX_OVERFLOW_POLICY, "drop-oldest") != "drop-oldest" {
        return Err(FrozenMismatch {
            key: keys::MAILBOX_OVERFLOW_POLICY,
            observed: 0,
            expected: 0,
        }
        .into());
    }

    for (key, expected) in [
        (keys::C4_MAX_BYTES, twinvpn_schema::limits::C4_MAX_BYTES),
        (keys::C4_MAX_DEPTH, twinvpn_schema::limits::C4_MAX_DEPTH),
        (
            keys::MAX_CANDIDATES,
            twinvpn_schema::limits::MAX_CANDIDATES_PER_SET,
        ),
        (
            keys::CANDIDATE_EXPIRY_MS,
            twinvpn_schema::limits::CANDIDATE_DEFAULT_EXPIRY_MS,
        ),
    ] {
        let expected = expected as u64;
        frozen(key, l.u64(key, expected)?, expected)?;
    }

    Ok((ttl_ms, capacity))
}

fn frozen(key: &'static str, observed: u64, expected: u64) -> Result<(), FrozenMismatch> {
    if observed == expected {
        Ok(())
    } else {
        Err(FrozenMismatch {
            key,
            observed,
            expected,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_service_common::config::MapEnv;

    fn base() -> MapEnv {
        // The TLS paths must exist; point them at files this repository has.
        MapEnv::new()
            .with(keys::TLS_CERT, "Cargo.toml")
            .with(keys::TLS_KEY, "Cargo.toml")
    }

    #[test]
    fn the_defaults_are_the_compose_defaults() {
        let cfg = RendezvousConfig::load(&base()).unwrap();
        assert_eq!(cfg.listen_tcp.port(), 443);
        assert!(
            cfg.listen_tcp.is_ipv6(),
            "the default listener is dual-stack [::]"
        );
        assert_eq!(cfg.mailbox.capacity_per_target, 8);
        assert_eq!(cfg.mailbox.ttl, Duration::from_millis(30_000));
    }

    #[test]
    fn widening_the_hostile_boundary_is_a_startup_failure() {
        let env = base().with(keys::C4_MAX_BYTES, "65536");
        let err = RendezvousConfig::load(&env).unwrap_err();
        assert!(matches!(err, RendezvousConfigError::Frozen(_)), "{err}");
    }

    #[test]
    fn deepening_the_parser_bound_is_a_startup_failure() {
        let env = base().with(keys::C4_MAX_DEPTH, "8");
        assert!(RendezvousConfig::load(&env).is_err());
    }

    #[test]
    fn an_unknown_overflow_policy_is_refused_rather_than_defaulted() {
        let env = base().with(keys::MAILBOX_OVERFLOW_POLICY, "drop-newest");
        assert!(RendezvousConfig::load(&env).is_err());
    }

    #[test]
    fn a_missing_tls_file_fails_at_startup() {
        let env = MapEnv::new()
            .with(keys::TLS_CERT, "/nonexistent/tls.crt")
            .with(keys::TLS_KEY, "/nonexistent/tls.key");
        assert!(RendezvousConfig::load(&env).is_err());
    }

    #[test]
    fn an_ipv4_only_listener_is_configurable() {
        let env = base().with(keys::LISTEN_TCP, "0.0.0.0:443");
        let cfg = RendezvousConfig::load(&env).unwrap();
        assert!(cfg.listen_tcp.is_ipv4());
    }
}
