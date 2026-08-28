//! Every `TWINVPN_RELAY_*` variable, validated at startup.
//!
//! The names, defaults and "if absent" column are `infra/README.md` §4.6's and
//! `docker-compose.yml`'s; this module invents none of them. Loading goes through
//! [`twinvpn_service_common::config::Loader`] so the "no secret has a default"
//! rule and the typed-error behaviour are the same as every other service.
//!
//! # Three values this module refuses to let an operator get wrong
//!
//! 1. **`TWINVPN_RELAY_RETAIN_PEER_PAIR` must be `false`.** `infra/README.md`
//!    §4.6 marks it "must stay false" and explains why: a relay sees both ends of
//!    a `RELAYED` session by necessity, and retaining that correlation "would
//!    hold the peer graph and defeat I1 *in metadata* even though the relay never
//!    sees plaintext". A `true` here is a **startup failure**, not a warning —
//!    the whole point is that per-session relay debugging is deliberately
//!    impossible (ADR-0015 §13).
//! 2. **The metrics label allowlist is frozen** to ADR-0015 §9's five labels. A
//!    sixth label is how a peer-pair dimension arrives.
//! 3. **`pair_tag` bucketing is frozen** to `limits.json`'s 600 s and skew 1. A
//!    longer bucket is a longer linkage window.
//!
//! # There is no control-plane address here
//!
//! Deliberate, and it is I5 in configuration form: a relay that could be pointed
//! at a control plane would eventually be *required* to reach one. ADR-0005 RQ2
//! and architecture A-12 say admission is offline; `infra/README.md` §2.3 records
//! that the compose topology has no `depends_on` edge from a relay to the control
//! plane and that "that absence is load-bearing". It is load-bearing here too.

use std::net::SocketAddr;
use std::path::PathBuf;

use twinvpn_service_common::config::{ConfigError, EnvSource, Loader};

use crate::frame::VERSION;

/// The carriages ADR-0005 §11.4 defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Carriage {
    /// UDP/41641 and UDP/443, the primary. 16 B of added header.
    Udp,
    /// UDP/443, QUIC DATAGRAM (RFC 9221).
    Quic,
    /// TCP/443, TLS 1.3, 2-byte length-prefixed frames.
    Tls,
}

impl Carriage {
    /// The configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Carriage::Udp => "R-UDP",
            Carriage::Quic => "R-QUIC",
            Carriage::Tls => "R-TLS",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "R-UDP" => Some(Carriage::Udp),
            "R-QUIC" => Some(Carriage::Quic),
            "R-TLS" => Some(Carriage::Tls),
            _ => None,
        }
    }
}

/// `TWINVPN_RELAY_ADMIN_STATE`, mirroring `relay.proto RelayAdminState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminState {
    /// Serving.
    Active,
    /// Accepting no new binds; existing flows have until the drain deadline.
    Draining,
    /// Gone.
    Retired,
}

/// A relay configuration that failed validation. Startup aborts on any of these.
#[derive(Debug, thiserror::Error)]
pub enum RelayConfigError {
    /// A variable was absent, unparseable, or a file was unreadable.
    #[error(transparent)]
    Env(#[from] ConfigError),

    /// `TWINVPN_RELAY_ID` is not exactly 16 lowercase hex characters.
    #[error("TWINVPN_RELAY_ID must be {0} bytes as 16 lowercase hex characters")]
    RelayIdWidth(usize),

    /// A bounded identifier exceeded its `limits.json` cap.
    #[error("{key} exceeds {limit} bytes")]
    TooLong {
        /// The variable.
        key: &'static str,
        /// The `limits.json` cap.
        limit: usize,
    },

    /// A required identifier was empty.
    #[error("{0} must not be empty")]
    Empty(&'static str),

    /// `TWINVPN_RELAY_CARRIAGES` named something that is not a carriage.
    #[error("TWINVPN_RELAY_CARRIAGES: unknown carriage")]
    UnknownCarriage,

    /// `TWINVPN_RELAY_CARRIAGES` was empty — a relay with no carriage serves
    /// nothing, which is a configuration error rather than a quiet no-op.
    #[error("TWINVPN_RELAY_CARRIAGES: at least one carriage is required")]
    NoCarriage,

    /// `TWINVPN_RELAY_ADMIN_STATE` was not one of the three.
    #[error("TWINVPN_RELAY_ADMIN_STATE must be ACTIVE, DRAINING or RETIRED")]
    UnknownAdminState,

    /// `TWINVPN_RELAY_RETAIN_PEER_PAIR=true`. See the module docs.
    #[error(
        "TWINVPN_RELAY_RETAIN_PEER_PAIR=true would hold the peer graph (ADR-0015 O-13). \
         Per-session relay debugging is deliberately impossible; this flag cannot be turned on"
    )]
    PeerPairRetentionRefused,

    /// The metrics label allowlist is not ADR-0015 §9's five labels.
    #[error("TWINVPN_RELAY_METRICS_LABEL_ALLOWLIST is frozen to ADR-0015 §9's five labels")]
    MetricsAllowlistAltered,

    /// A frozen `limits.json` value was overridden.
    #[error("{key} is frozen at {expected} by contracts/registry/limits.json")]
    FrozenValueAltered {
        /// The variable.
        key: &'static str,
        /// The frozen value.
        expected: u64,
    },
}

/// The validated relay configuration.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// 8 bytes, from `limits.json identifiers.relay_id_bytes`.
    pub relay_id: [u8; twinvpn_schema::limits::RELAY_ID_BYTES],
    /// The hex spelling, for a log line and for `Evidence`.
    pub relay_id_hex: String,
    /// `TWINVPN_RELAY_REGION`.
    pub region_id: String,
    /// `TWINVPN_RELAY_FAILURE_DOMAIN`. ADR-0006 requires the standby to be in a
    /// different one; a relay that shares a domain with its standby has none.
    pub failure_domain: String,
    /// `TWINVPN_RELAY_OPERATOR_GROUP_ID` — must match a token's `aud`.
    pub operator_group_id: String,
    /// `TWINVPN_RELAY_ADMIN_STATE`.
    pub admin_state: AdminState,
    /// Whether this relay is the TwinNet Owner's own.
    pub self_hosted: bool,
    /// The configured carriages, deduplicated and ordered.
    pub carriages: Vec<Carriage>,
    /// `R-UDP` primary.
    pub listen_udp: SocketAddr,
    /// `R-UDP` on 443.
    pub listen_udp_443: SocketAddr,
    /// `R-QUIC`.
    pub listen_quic: SocketAddr,
    /// `R-TLS`.
    pub listen_tls: SocketAddr,
    /// The issuer public-key set. Empty means admit nothing.
    pub issuer_keys_path: PathBuf,
    /// The relay's static Noise key. **Never read into an `Evidence` or a log.**
    pub static_key_path: PathBuf,
    /// Frozen at `limits.json relay.token_lifetime_ms`.
    pub token_lifetime_ms: u64,
    /// Frozen at `limits.json relay.token_clock_skew_ms`.
    pub token_clock_skew_ms: u64,
    /// `T_RELAY_GRACE`, 6 h (ADR-0005 §11.3 relay-issued renewal).
    pub token_grace_ms: u64,
    /// Frozen at `limits.json relay.pair_tag_bucket_seconds`.
    pub pair_tag_bucket_seconds: u64,
    /// Frozen at `limits.json relay.accepted_bucket_skew`.
    pub pair_tag_accepted_skew: u64,
    /// ADR-0005 §11.5 per-`relay_sub` flow ceiling.
    pub max_flows_per_subject: u32,
    /// Per-`relay_sub` bitrate, Mbit/s.
    pub rate_per_subject_mbps: u32,
    /// Per-half-flow bitrate, Mbit/s.
    pub rate_per_flow_mbps: u32,
    /// Per-`relay_sub` bytes per hour.
    pub quota_bytes_per_hour: u64,
    /// Per-`relay_sub` binds per minute.
    pub bind_per_minute_per_subject: u32,
    /// Handshakes per second per source /24 or /48 before a cookie challenge.
    pub cookie_threshold_handshakes_per_s: u32,
    /// Pending-slot lifetime.
    pub pending_slot_ttl_ms: u64,
    /// Idle bound half-flow lifetime.
    pub idle_flow_timeout_ms: u64,
    /// Per-flow send queue bound, tail-drop above it.
    pub flow_queue_max_bytes: usize,
    /// The relay-wide half-flow ceiling. Not in `infra/README.md` §4.6; see
    /// [`RelayConfig::KEY_MAX_TOTAL_FLOWS`].
    pub max_total_flows: usize,
    /// The frame version this build speaks.
    pub protocol_version: u8,
}

/// ADR-0015 §9's five relay metric labels, in the order compose declares them.
pub const FROZEN_METRIC_LABELS: [&str; 5] = [
    "relay_region",
    "protocol_version",
    "reason_code",
    "outcome",
    "address_family",
];

impl RelayConfig {
    /// A relay-wide half-flow ceiling.
    ///
    /// **Not in `infra/README.md` §4.6, and stated as an addition rather than
    /// slipped in.** ADR-0005 §11.5's table bounds *per `relay_sub`*: 64 flows
    /// each. That bounds one attacker. It does not bound N subjects, and a relay
    /// admitting an unbounded number of subjects has no memory bound at all
    /// (`ownership.md` §6 rule 10). The default of 65 536 is 1 024 subjects at
    /// their full per-subject allowance.
    pub const KEY_MAX_TOTAL_FLOWS: &'static str = "TWINVPN_RELAY_MAX_TOTAL_FLOWS";

    /// Loads and validates every `TWINVPN_RELAY_*` variable.
    ///
    /// # Errors
    ///
    /// [`RelayConfigError`] for any absent required value, any unparseable value,
    /// any bound violation, and for the three refusals in the module docs.
    #[allow(clippy::too_many_lines)]
    pub fn load(env: &dyn EnvSource) -> Result<Self, RelayConfigError> {
        let l = Loader::new(env);

        let relay_id_hex = l.require("TWINVPN_RELAY_ID")?;
        let relay_id = parse_relay_id(&relay_id_hex)?;

        let region_id = bounded(
            l.require("TWINVPN_RELAY_REGION")?,
            "TWINVPN_RELAY_REGION",
            twinvpn_schema::limits::REGION_ID_MAX_BYTES,
        )?;
        let failure_domain = bounded(
            l.require("TWINVPN_RELAY_FAILURE_DOMAIN")?,
            "TWINVPN_RELAY_FAILURE_DOMAIN",
            twinvpn_schema::limits::REGION_ID_MAX_BYTES,
        )?;
        let operator_group_id = bounded(
            l.require("TWINVPN_RELAY_OPERATOR_GROUP_ID")?,
            "TWINVPN_RELAY_OPERATOR_GROUP_ID",
            twinvpn_schema::limits::TWINNET_ID_MAX_BYTES,
        )?;

        let admin_state = match l.string("TWINVPN_RELAY_ADMIN_STATE", "ACTIVE").as_str() {
            "ACTIVE" => AdminState::Active,
            "DRAINING" => AdminState::Draining,
            "RETIRED" => AdminState::Retired,
            _ => return Err(RelayConfigError::UnknownAdminState),
        };

        let carriages =
            parse_carriages(&l.string("TWINVPN_RELAY_CARRIAGES", "R-UDP,R-QUIC,R-TLS"))?;

        // --- O-13: the flag that cannot be turned on ------------------------
        if l.bool("TWINVPN_RELAY_RETAIN_PEER_PAIR", false)? {
            return Err(RelayConfigError::PeerPairRetentionRefused);
        }

        let labels = l.string(
            "TWINVPN_RELAY_METRICS_LABEL_ALLOWLIST",
            &FROZEN_METRIC_LABELS.join(","),
        );
        let declared: Vec<&str> = labels.split(',').map(str::trim).collect();
        if declared != FROZEN_METRIC_LABELS {
            return Err(RelayConfigError::MetricsAllowlistAltered);
        }

        // --- values frozen by limits.json -----------------------------------
        let token_lifetime_ms = frozen(
            &l,
            "TWINVPN_RELAY_TOKEN_LIFETIME_MS",
            twinvpn_schema::limits::RELAY_TOKEN_LIFETIME_MS as u64,
        )?;
        let token_clock_skew_ms = frozen(
            &l,
            "TWINVPN_RELAY_TOKEN_CLOCK_SKEW_MS",
            twinvpn_schema::limits::RELAY_TOKEN_CLOCK_SKEW_MS as u64,
        )?;
        let pair_tag_bucket_seconds = frozen(
            &l,
            "TWINVPN_RELAY_PAIR_TAG_BUCKET_SECONDS",
            twinvpn_schema::limits::RELAY_PAIR_TAG_BUCKET_SECONDS as u64,
        )?;
        let pair_tag_accepted_skew = frozen(
            &l,
            "TWINVPN_RELAY_PAIR_TAG_ACCEPTED_SKEW",
            twinvpn_schema::limits::RELAY_ACCEPTED_BUCKET_SKEW as u64,
        )?;

        Ok(Self {
            relay_id,
            relay_id_hex,
            region_id,
            failure_domain,
            operator_group_id,
            admin_state,
            self_hosted: l.bool("TWINVPN_RELAY_SELF_HOSTED", false)?,
            carriages,
            listen_udp: l.socket_addr("TWINVPN_RELAY_LISTEN_UDP", "[::]:41641")?,
            listen_udp_443: l.socket_addr("TWINVPN_RELAY_LISTEN_UDP_443", "[::]:443")?,
            listen_quic: l.socket_addr("TWINVPN_RELAY_LISTEN_QUIC", "[::]:443")?,
            listen_tls: l.socket_addr("TWINVPN_RELAY_LISTEN_TLS", "[::]:443")?,
            issuer_keys_path: l.readable_file(
                "TWINVPN_RELAY_ISSUER_KEYS_PATH",
                "/run/secrets/relay/issuer-keys.json",
            )?,
            static_key_path: l.readable_file(
                "TWINVPN_RELAY_STATIC_KEY_PATH",
                "/run/secrets/relay/static-noise.key",
            )?,
            token_lifetime_ms,
            token_clock_skew_ms,
            token_grace_ms: l.u64("TWINVPN_RELAY_TOKEN_GRACE_MS", 21_600_000)?,
            pair_tag_bucket_seconds,
            pair_tag_accepted_skew,
            max_flows_per_subject: u32::try_from(l.u64("TWINVPN_RELAY_MAX_FLOWS_PER_SUBJECT", 64)?)
                .unwrap_or(u32::MAX),
            rate_per_subject_mbps: u32::try_from(l.u64("TWINVPN_RELAY_RATE_PER_SUBJECT_MBPS", 20)?)
                .unwrap_or(u32::MAX),
            rate_per_flow_mbps: u32::try_from(l.u64("TWINVPN_RELAY_RATE_PER_FLOW_MBPS", 10)?)
                .unwrap_or(u32::MAX),
            quota_bytes_per_hour: l.u64("TWINVPN_RELAY_QUOTA_BYTES_PER_HOUR", 21_474_836_480)?,
            bind_per_minute_per_subject: u32::try_from(
                l.u64("TWINVPN_RELAY_BIND_PER_MINUTE_PER_SUBJECT", 30)?,
            )
            .unwrap_or(u32::MAX),
            cookie_threshold_handshakes_per_s: u32::try_from(
                l.u64("TWINVPN_RELAY_COOKIE_THRESHOLD_HANDSHAKES_PER_S", 20)?,
            )
            .unwrap_or(u32::MAX),
            pending_slot_ttl_ms: l.u64("TWINVPN_RELAY_PENDING_SLOT_TTL_MS", 30_000)?,
            idle_flow_timeout_ms: l.u64("TWINVPN_RELAY_IDLE_FLOW_TIMEOUT_MS", 900_000)?,
            flow_queue_max_bytes: usize::try_from(
                l.u64("TWINVPN_RELAY_FLOW_QUEUE_MAX_BYTES", 65_536)?,
            )
            .unwrap_or(65_536),
            max_total_flows: usize::try_from(l.u64(Self::KEY_MAX_TOTAL_FLOWS, 65_536)?)
                .unwrap_or(65_536),
            protocol_version: VERSION,
        })
    }
}

fn parse_relay_id(
    hex: &str,
) -> Result<[u8; twinvpn_schema::limits::RELAY_ID_BYTES], RelayConfigError> {
    const N: usize = twinvpn_schema::limits::RELAY_ID_BYTES;
    if hex.len() != N * 2 {
        return Err(RelayConfigError::RelayIdWidth(N));
    }
    let mut out = [0_u8; N];
    for (i, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = nibble(pair[0]).ok_or(RelayConfigError::RelayIdWidth(N))?;
        let lo = nibble(pair[1]).ok_or(RelayConfigError::RelayIdWidth(N))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

const fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn bounded(v: String, key: &'static str, limit: usize) -> Result<String, RelayConfigError> {
    if v.is_empty() {
        return Err(RelayConfigError::Empty(key));
    }
    if v.len() > limit {
        return Err(RelayConfigError::TooLong { key, limit });
    }
    Ok(v)
}

fn parse_carriages(s: &str) -> Result<Vec<Carriage>, RelayConfigError> {
    let mut out = Vec::new();
    for part in s.split(',').filter(|p| !p.trim().is_empty()) {
        let c = Carriage::parse(part).ok_or(RelayConfigError::UnknownCarriage)?;
        if !out.contains(&c) {
            out.push(c);
        }
    }
    if out.is_empty() {
        return Err(RelayConfigError::NoCarriage);
    }
    out.sort_unstable();
    Ok(out)
}

fn frozen(l: &Loader<'_>, key: &'static str, expected: u64) -> Result<u64, RelayConfigError> {
    let v = l.u64(key, expected)?;
    if v == expected {
        Ok(v)
    } else {
        Err(RelayConfigError::FrozenValueAltered { key, expected })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_service_common::config::MapEnv;

    fn env() -> MapEnv {
        MapEnv::new()
            .with("TWINVPN_RELAY_ID", "0000000000000a01")
            .with("TWINVPN_RELAY_REGION", "local-1")
            .with("TWINVPN_RELAY_FAILURE_DOMAIN", "fd-a")
            .with("TWINVPN_RELAY_OPERATOR_GROUP_ID", "local-operator")
            .with(
                "TWINVPN_RELAY_ISSUER_KEYS_PATH",
                concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            )
            .with(
                "TWINVPN_RELAY_STATIC_KEY_PATH",
                concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            )
    }

    #[test]
    fn the_compose_defaults_load() {
        let c = RelayConfig::load(&env()).expect("loads");
        assert_eq!(c.relay_id, [0, 0, 0, 0, 0, 0, 0x0a, 0x01]);
        assert_eq!(c.region_id, "local-1");
        assert_eq!(c.failure_domain, "fd-a");
        assert_eq!(c.admin_state, AdminState::Active);
        assert_eq!(
            c.carriages,
            vec![Carriage::Udp, Carriage::Quic, Carriage::Tls]
        );
        assert_eq!(c.max_flows_per_subject, 64);
        assert_eq!(c.pending_slot_ttl_ms, 30_000);
    }

    #[test]
    fn retaining_the_peer_pair_is_a_startup_failure() {
        let e =
            RelayConfig::load(&env().with("TWINVPN_RELAY_RETAIN_PEER_PAIR", "true")).unwrap_err();
        assert!(matches!(e, RelayConfigError::PeerPairRetentionRefused));
    }

    #[test]
    fn adding_a_sixth_metric_label_is_a_startup_failure() {
        let e = RelayConfig::load(&env().with(
            "TWINVPN_RELAY_METRICS_LABEL_ALLOWLIST",
            "relay_region,protocol_version,reason_code,outcome,address_family,pair_tag",
        ))
        .unwrap_err();
        assert!(matches!(e, RelayConfigError::MetricsAllowlistAltered));
    }

    #[test]
    fn a_frozen_limits_value_cannot_be_widened() {
        let e = RelayConfig::load(&env().with("TWINVPN_RELAY_PAIR_TAG_BUCKET_SECONDS", "86400"))
            .unwrap_err();
        assert!(matches!(
            e,
            RelayConfigError::FrozenValueAltered {
                key: "TWINVPN_RELAY_PAIR_TAG_BUCKET_SECONDS",
                expected: 600
            }
        ));
    }

    #[test]
    fn a_relay_id_of_the_wrong_width_is_refused() {
        for bad in [
            "0a01",
            "0000000000000a0",
            "0000000000000a0z",
            "0000000000000A01",
        ] {
            let e = RelayConfig::load(&env().with("TWINVPN_RELAY_ID", bad)).unwrap_err();
            assert!(matches!(e, RelayConfigError::RelayIdWidth(8)), "{bad}: {e}");
        }
        // An empty value is an unset value (service-common's rule), so it is a
        // missing-variable failure rather than a width one. Either way: refused.
        assert!(matches!(
            RelayConfig::load(&env().with("TWINVPN_RELAY_ID", "")).unwrap_err(),
            RelayConfigError::Env(_)
        ));
    }

    #[test]
    fn an_unknown_or_empty_carriage_list_is_refused() {
        assert!(matches!(
            RelayConfig::load(&env().with("TWINVPN_RELAY_CARRIAGES", "R-SCTP")).unwrap_err(),
            RelayConfigError::UnknownCarriage
        ));
        assert!(matches!(
            RelayConfig::load(&env().with("TWINVPN_RELAY_CARRIAGES", " , ")).unwrap_err(),
            RelayConfigError::NoCarriage
        ));
    }

    #[test]
    fn an_over_long_region_is_refused_against_limits_json() {
        let long = "r".repeat(twinvpn_schema::limits::REGION_ID_MAX_BYTES + 1);
        assert!(matches!(
            RelayConfig::load(&env().with("TWINVPN_RELAY_REGION", &long)).unwrap_err(),
            RelayConfigError::TooLong {
                key: "TWINVPN_RELAY_REGION",
                ..
            }
        ));
    }

    #[test]
    fn there_is_no_control_plane_variable_at_all() {
        // I5 in configuration form. If a control-plane address ever appears in
        // this struct, this test is the place the reviewer is sent.
        let c = RelayConfig::load(&env()).expect("loads");
        let rendered = format!("{c:?}").to_lowercase();
        assert!(!rendered.contains("control"));
        assert!(!rendered.contains("coordination"));
    }

    #[test]
    fn the_relay_wide_ceiling_defaults_and_is_overridable() {
        assert_eq!(
            RelayConfig::load(&env()).expect("loads").max_total_flows,
            65_536
        );
        let c =
            RelayConfig::load(&env().with(RelayConfig::KEY_MAX_TOTAL_FLOWS, "128")).expect("loads");
        assert_eq!(c.max_total_flows, 128);
    }
}
