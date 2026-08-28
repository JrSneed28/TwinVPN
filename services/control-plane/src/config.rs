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
    /// `TWINVPN_CP_OWNER_ANCHOR_PATH`.
    ///
    /// A file of newline-separated base16 COSE_Key entries for the pinned
    /// `OwnerTrustAnchor` set (S-32). **Optional, and its absence is a
    /// capability lost rather than a startup failure**: with no anchor this
    /// service still enrols, discovers and streams, and refuses every
    /// `Owner`-authority statement with `AUTH.KEY_UNAVAILABLE`. That is the
    /// correct set of things to lose, and it is announced at startup rather
    /// than discovered from a refusal.
    ///
    /// **New variable.** `infra/README.md` §4.3 does not list it yet; reported
    /// to the integration lead (README §11).
    pub owner_anchor_path: PathBuf,
    /// `TWINVPN_CP_TLS_CERT_PATH`.
    pub tls_cert_path: PathBuf,
    /// `TWINVPN_CP_TLS_KEY_PATH`.
    pub tls_key_path: PathBuf,
    /// `TWINVPN_CP_DATABASE_URL`. **No default, ever.**
    pub database_url: SecretString,
    /// `TWINVPN_CP_DATABASE_MAX_CONNECTIONS`, default 16.
    pub database_max_connections: u32,
    /// `TWINVPN_CP_EVENT_BUS`, default `postgres-notify`.
    /// Where devices reach this control plane, returned by `RegisterDevice`.
    ///
    /// **Names, not addresses** (ADR-0011 DN-0): GeoDNS is how a device reaches
    /// the nearest front-end, and a literal address baked into a registration
    /// response would pin every device that ever enrolled to one box. Resolved
    /// in the bootstrap DNS scope.
    ///
    /// Empty by default and empty is legal: a device that already knows how it
    /// got here does not need to be told again, and inventing a hostname would
    /// be worse than saying nothing.
    pub coordination_endpoints: Vec<String>,
    /// The ORK-signed `OwnerDelegation` set, one base16 COSE_Sign1 per line.
    ///
    /// **This is what makes `Owner` power scoped.** ADR-0007 O5 keeps the
    /// `OwnerRootKey` offline behind a recovery phrase and does routine work —
    /// enrol, revoke, publish policy — with per-admin-device `OwnerSigningKey`s,
    /// each delegated a subset of the powers. Without a delegation set this
    /// service can admit only statements the **root itself** signed, which means
    /// either the recovery phrase is reconstituted for every revocation, or an
    /// operator puts OSKs in the anchor file and every admin key silently
    /// carries every power.
    ///
    /// Absent is an **empty set**, not an error: a deployment that has not yet
    /// delegated anything is a deployment whose root signs, and that is a
    /// posture, not a misconfiguration. It is stated at startup rather than
    /// discovered from a refusal.
    pub owner_delegations_path: PathBuf,
    /// The anchor generation delegations must name, or `0` to not check.
    ///
    /// S-32: "a delegation issued under an older anchor does not survive an
    /// anchor advance by default." A mixed set means half an anchor rotation was
    /// applied, so a non-zero value here refuses one at startup. Operator-supplied
    /// for the same reason [`ControlPlaneConfig::shard_epoch`] is: a process that
    /// could infer its own would infer whichever value made the file it was given
    /// load.
    pub owner_anchor_version: u64,
    /// The fencing token this process presents on every write.
    ///
    /// ADR-0009 §11.2: a write is admitted only if it presents the current
    /// `shard_epoch`, and the epoch is **bumped by the operator on failover** —
    /// which is what stops a partitioned old leader, still believing it holds
    /// the lease, from writing behind the new one. It is configuration and not a
    /// value this process invents, because a process that could choose its own
    /// fencing token could choose one high enough to win.
    ///
    /// Defaults to 1: the single-writer deployment that has never failed over.
    pub shard_epoch: u64,
    /// Which event bus the deployment selected.
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

/// Splits a comma-separated endpoint list, dropping blanks.
///
/// Blank-tolerant on purpose: `A,,B` and a trailing comma are what a templated
/// compose file produces when one of its variables is unset, and a service that
/// answered `RegisterDevice` with an empty hostname would send devices to a name
/// that does not resolve.
fn split_endpoints(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
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
            owner_anchor_path: PathBuf::from(l.string(
                "TWINVPN_CP_OWNER_ANCHOR_PATH",
                "/run/secrets/control-plane/owner-anchors.hex",
            )),
            owner_delegations_path: PathBuf::from(l.string(
                "TWINVPN_CP_OWNER_DELEGATIONS_PATH",
                "/run/secrets/control-plane/owner-delegations.hex",
            )),
            owner_anchor_version: l.u64("TWINVPN_CP_OWNER_ANCHOR_VERSION", 0)?,
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
            coordination_endpoints: split_endpoints(
                &l.string("TWINVPN_CP_COORDINATION_ENDPOINTS", ""),
            ),
            shard_epoch: l.u64("TWINVPN_CP_SHARD_EPOCH", 1)?,
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

    /// Loads the pinned `OwnerTrustAnchor` COSE_Key set.
    ///
    /// One base16 key per line; blank lines and `#` comments are ignored. An
    /// absent file is an **empty set**, not an error — see
    /// [`ControlPlaneConfig::owner_anchor_path`].
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when a line is present but is not base16. A
    /// malformed anchor is a startup failure rather than a silently skipped
    /// key: skipping one produces a service that refuses statements a
    /// correctly-configured one would admit, which reads as an outage.
    pub fn load_owner_anchors(&self) -> Result<Vec<Vec<u8>>, ConfigError> {
        let Ok(text) = std::fs::read_to_string(&self.owner_anchor_path) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            out.push(from_hex(line).ok_or(ConfigError::Invalid {
                key: "TWINVPN_CP_OWNER_ANCHOR_PATH",
                expected: "one base16 COSE_Key per line",
            })?);
        }
        Ok(out)
    }

    /// Loads the ORK-signed `OwnerDelegation` set.
    ///
    /// One base16 COSE_Sign1 per line; blank lines and `#` comments ignored. An
    /// absent file is an **empty set**, exactly as an absent anchor file is: the
    /// posture "only the root may author", which is legal and is announced at
    /// startup.
    ///
    /// The octets are **not** verified here — [`crate::verify::CryptoVerifier`]
    /// does that against the pinned anchor, because verifying a delegation
    /// without the key it chains to would be reading a file, not establishing an
    /// authority.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when a line is present but is not base16, for
    /// the reason a malformed anchor line is a startup failure: a silently
    /// skipped delegation produces a service that refuses operations a correct
    /// one would admit.
    pub fn load_owner_delegations(&self) -> Result<Vec<Vec<u8>>, ConfigError> {
        let Ok(text) = std::fs::read_to_string(&self.owner_delegations_path) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            out.push(from_hex(line).ok_or(ConfigError::Invalid {
                key: "TWINVPN_CP_OWNER_DELEGATIONS_PATH",
                expected: "one base16 COSE_Sign1 OwnerDelegation per line",
            })?);
        }
        Ok(out)
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

/// Decodes lowercase or uppercase base16.
fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(u8::try_from(hi * 16 + lo).ok()?);
    }
    Some(out)
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
    fn an_absent_anchor_file_is_an_empty_set_and_not_a_startup_failure() {
        // Losing the anchor loses REVOCATION and POLICY AUTHORSHIP, which is a
        // capability, not a reason to refuse to serve reads and the C2 stream.
        let cfg = ControlPlaneConfig::load(
            &minimal().with("TWINVPN_CP_OWNER_ANCHOR_PATH", "/nonexistent/anchors.hex"),
        )
        .expect("loads");
        assert!(cfg.load_owner_anchors().expect("empty").is_empty());
    }

    #[test]
    fn a_malformed_anchor_line_fails_at_startup_rather_than_being_skipped() {
        // A silently skipped key produces a service that refuses statements a
        // correctly-configured one would admit — an outage wearing a
        // misconfiguration's clothes.
        let dir = std::env::temp_dir().join("twinvpn-cp-anchor-test");
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let path = dir.join("anchors.hex");
        std::fs::write(&path, "# a comment\n\nzznotbase16\n").expect("write");
        let cfg = ControlPlaneConfig::load(
            &minimal().with("TWINVPN_CP_OWNER_ANCHOR_PATH", &path.to_string_lossy()),
        )
        .expect("loads");
        let err = cfg.load_owner_anchors().expect_err("malformed");
        assert!(format!("{err}").contains("TWINVPN_CP_OWNER_ANCHOR_PATH"));

        std::fs::write(&path, "# a comment\n\nA1B2\nc3d4\n").expect("write");
        let keys = cfg.load_owner_anchors().expect("base16");
        assert_eq!(keys, vec![vec![0xa1, 0xb2], vec![0xc3, 0xd4]]);
        let _ = std::fs::remove_file(&path);
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
    fn coordination_endpoints_are_names_and_a_blank_is_never_one() {
        // ADR-0011 DN-0: NAMES, so GeoDNS reaches the nearest front-end. `A,,B`
        // and a trailing comma are what a templated compose file produces when
        // one of its variables is unset, and answering `RegisterDevice` with an
        // empty hostname would send a device to a name that does not resolve.
        let env = minimal().with(
            "TWINVPN_CP_COORDINATION_ENDPOINTS",
            " cp1.twinvpn.example , ,cp2.twinvpn.example,",
        );
        let cfg = ControlPlaneConfig::load(&env).expect("loads");
        assert_eq!(
            cfg.coordination_endpoints,
            vec![
                "cp1.twinvpn.example".to_owned(),
                "cp2.twinvpn.example".to_owned()
            ]
        );
        // Unset is an empty list, and an empty list is legal: a device that
        // already knows how it got here does not need to be told again.
        assert!(ControlPlaneConfig::load(&minimal())
            .expect("loads")
            .coordination_endpoints
            .is_empty());
    }

    #[test]
    fn the_shard_epoch_is_configuration_and_defaults_to_the_single_writer() {
        // ADR-0009 §11.2: the fencing token is bumped BY THE OPERATOR on
        // failover. A process that could choose its own could choose one high
        // enough to win against the leader that displaced it.
        assert_eq!(
            ControlPlaneConfig::load(&minimal())
                .expect("loads")
                .shard_epoch,
            1
        );
        let env = minimal().with("TWINVPN_CP_SHARD_EPOCH", "7");
        assert_eq!(
            ControlPlaneConfig::load(&env).expect("loads").shard_epoch,
            7
        );
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
