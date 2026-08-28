//! S-09's registry half — what relays exist.
//!
//! One [`RelayRecord`] per relay instance, mirroring `relay.proto`'s `Relay`
//! message field for field. The proto is the contract; this is the server-side
//! record it is built from, and nothing here redeclares a type `contracts/`
//! already defines that could be used directly — `Relay` is a wire message with
//! `bytes`/`repeated` fields, and a registry needs validated, typed values.
//!
//! # Endpoints are literals, never hostnames
//!
//! ADR-0006 §11.1 rule 1, and `relay.proto` in capitals:
//!
//! > RELAY REACHABILITY MUST NOT DEPEND ON DNS — otherwise recovering from
//! > `BLOCKED` would require the resolver that the relay is needed to reach.
//!
//! [`RelayRecord::endpoints_v4`] and `endpoints_v6` are `SocketAddr`, a type that
//! **cannot hold a hostname**. That is the enforcement: there is no parse step to
//! forget, because a name has nowhere to go.

use std::net::SocketAddr;

/// `relay.proto RelayAdminState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminState {
    /// Serving, and eligible to be a candidate.
    Active,
    /// Accepting no new binds; still usable, and ranked lower (−300).
    Draining,
    /// No longer exists as a signed entity. The **only** admin state that may
    /// remove a relay from a candidate set (ADR-0006 §11.3 rule 2).
    Retired,
}

/// `relay.proto RelayCarriage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Carriage {
    /// `R-UDP`.
    Udp,
    /// `R-QUIC`.
    Quic,
    /// `R-TLS`.
    Tls,
}

/// One relay instance in the fleet registry.
#[derive(Debug, Clone)]
pub struct RelayRecord {
    /// 8 bytes (`limits.json identifiers.relay_id_bytes`). **Never reused after
    /// retirement** — `relay.proto`: a reused id would let a cached ranking or an
    /// S-31 quality record from a decommissioned instance apply to a new one.
    pub relay_id: [u8; twinvpn_schema::limits::RELAY_ID_BYTES],
    /// The unit of admission; must equal the token's `aud`.
    pub operator_group_id: String,
    /// ADR-0006 §11.1 `regions[]`.
    pub region_id: String,
    /// The relay's static Noise public key, as published.
    pub static_noise_public_key: Vec<u8>,
    /// Literal v4 endpoints. Never a hostname — see the module docs.
    pub endpoints_v4: Vec<SocketAddr>,
    /// Literal v6 endpoints.
    pub endpoints_v6: Vec<SocketAddr>,
    /// Supported carriages.
    pub carriages: Vec<Carriage>,
    /// The correlated-failure label. ADR-0005 §11.6's `RELAY_STANDBY_READY`
    /// requires a standby in a **different** one.
    pub failure_domain: String,
    /// 0–100, advisory. The device's own measurement always overrides.
    pub server_rank: u8,
    /// 0–3, coarse. A hint, never a gate.
    pub load_class: u8,
    /// Feeds the HRW weight, so redistribution is proportional to capacity.
    pub capacity_weight: u32,
    /// Lifecycle.
    pub admin_state: AdminState,
    /// Whether the TwinNet Owner operates it. **Trust is unchanged** — a
    /// self-hosted relay is untrusted (B3) and I1 applies identically.
    pub self_hosted: bool,
    /// Whether it implements `DRAIN`.
    pub supports_drain: bool,
    /// Whether it implements `CAPS`.
    pub supports_caps: bool,
}

/// Why a record was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// A bounded identifier exceeded a `limits.json` cap or was empty.
    #[error("{field}: empty or over {limit} bytes")]
    Identifier {
        /// Which field.
        field: &'static str,
        /// The cap.
        limit: usize,
    },
    /// `server_rank` outside 0–100 or `load_class` outside 0–3.
    #[error("{field} out of range")]
    OutOfRange {
        /// Which field.
        field: &'static str,
    },
    /// No endpoint in either family, or no carriage.
    #[error("a relay with no {0} is not reachable")]
    Unreachable(&'static str),
    /// The static Noise public key is absent or the wrong width.
    #[error("static_noise_public_key must be 32 bytes")]
    StaticKeyWidth,
}

impl RelayRecord {
    /// Validates the record against `limits.json` and ADR-0006 §11.1.
    ///
    /// # Errors
    ///
    /// [`RecordError`]. A registry that accepted an unreachable or unbounded
    /// record would publish it, and a published map is what a device trusts.
    pub fn validate(&self) -> Result<(), RecordError> {
        bounded(
            &self.operator_group_id,
            "operator_group_id",
            twinvpn_schema::limits::TWINNET_ID_MAX_BYTES,
        )?;
        bounded(
            &self.region_id,
            "region_id",
            twinvpn_schema::limits::REGION_ID_MAX_BYTES,
        )?;
        bounded(
            &self.failure_domain,
            "failure_domain",
            twinvpn_schema::limits::REGION_ID_MAX_BYTES,
        )?;
        if self.static_noise_public_key.len() != 32 {
            return Err(RecordError::StaticKeyWidth);
        }
        if self.server_rank > 100 {
            return Err(RecordError::OutOfRange {
                field: "server_rank",
            });
        }
        if self.load_class > 3 {
            return Err(RecordError::OutOfRange {
                field: "load_class",
            });
        }
        if self.endpoints_v4.is_empty() && self.endpoints_v6.is_empty() {
            return Err(RecordError::Unreachable("endpoint"));
        }
        if self.carriages.is_empty() {
            return Err(RecordError::Unreachable("carriage"));
        }
        Ok(())
    }

    /// The hex spelling of `relay_id`, for a log line and for `Evidence`.
    #[must_use]
    pub fn relay_id_hex(&self) -> String {
        twinvpn_service_common::redact::hex_lower(&self.relay_id)
    }

    /// Whether this relay may appear in a candidate set at all.
    ///
    /// **Only `RETIRED` removes it.** ADR-0006 §11.3 rule 1: an `UNHEALTHY`
    /// health state, a stale set or a "peer offline" record MUST NOT suppress a
    /// connection attempt — they contribute score deltas only.
    #[must_use]
    pub const fn is_candidate(&self) -> bool {
        !matches!(self.admin_state, AdminState::Retired)
    }
}

fn bounded(v: &str, field: &'static str, limit: usize) -> Result<(), RecordError> {
    if v.is_empty() || v.len() > limit {
        return Err(RecordError::Identifier { field, limit });
    }
    Ok(())
}

/// The registry (S-09's registry half).
///
/// A trait so the Postgres implementation can land without touching anything
/// above it. See `README.md` §8 for why the in-memory one is what ships now.
pub trait FleetStore: Send + Sync {
    /// Every relay in `operator_group_id`, retired ones included — a caller that
    /// needs candidates filters with [`RelayRecord::is_candidate`], so "what
    /// exists" and "what is a candidate" stay different questions.
    fn all(&self, operator_group_id: &str) -> Vec<RelayRecord>;

    /// The monotone version of the registry's current contents.
    fn version(&self) -> u64;
}

/// An in-memory registry.
#[derive(Debug, Default)]
pub struct InMemoryFleet {
    records: Vec<RelayRecord>,
    version: u64,
}

impl InMemoryFleet {
    /// An empty registry at version 0.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            version: 0,
        }
    }

    /// Adds a validated record and advances the version.
    ///
    /// # Errors
    ///
    /// [`RecordError`] from [`RelayRecord::validate`].
    pub fn insert(&mut self, record: RelayRecord) -> Result<(), RecordError> {
        record.validate()?;
        self.records.retain(|r| r.relay_id != record.relay_id);
        self.records.push(record);
        self.version += 1;
        Ok(())
    }

    /// How many records are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl FleetStore for InMemoryFleet {
    fn all(&self, operator_group_id: &str) -> Vec<RelayRecord> {
        self.records
            .iter()
            .filter(|r| r.operator_group_id == operator_group_id)
            .cloned()
            .collect()
    }

    fn version(&self) -> u64 {
        self.version
    }
}

#[cfg(test)]
pub(crate) fn sample(id: u8, region: &str, domain: &str) -> RelayRecord {
    RelayRecord {
        relay_id: [id; twinvpn_schema::limits::RELAY_ID_BYTES],
        operator_group_id: "local-operator".into(),
        region_id: region.into(),
        static_noise_public_key: vec![id; 32],
        endpoints_v4: vec!["192.0.2.1:41641".parse().expect("v4")],
        endpoints_v6: vec!["[2001:db8::1]:41641".parse().expect("v6")],
        carriages: vec![Carriage::Udp, Carriage::Quic, Carriage::Tls],
        failure_domain: domain.into(),
        server_rank: 50,
        load_class: 0,
        capacity_weight: 100,
        admin_state: AdminState::Active,
        self_hosted: false,
        supports_drain: true,
        supports_caps: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_endpoint_type_that_cannot_hold_a_hostname() {
        // ADR-0006 §11.1 rule 1 enforced by the type, not by a validator someone
        // has to remember to call: `SocketAddr` has no hostname variant.
        assert!("relay-a.example.com:41641".parse::<SocketAddr>().is_err());
        assert!("192.0.2.1:41641".parse::<SocketAddr>().is_ok());
        assert!("[2001:db8::1]:41641".parse::<SocketAddr>().is_ok());
    }

    #[test]
    fn a_valid_record_validates() {
        sample(1, "eu-west", "fd-a").validate().expect("valid");
    }

    #[test]
    fn a_relay_with_no_endpoint_or_no_carriage_is_refused() {
        let mut r = sample(1, "eu-west", "fd-a");
        r.endpoints_v4.clear();
        r.endpoints_v6.clear();
        assert_eq!(r.validate(), Err(RecordError::Unreachable("endpoint")));

        let mut r = sample(1, "eu-west", "fd-a");
        r.carriages.clear();
        assert_eq!(r.validate(), Err(RecordError::Unreachable("carriage")));
    }

    #[test]
    fn out_of_range_advisory_values_are_refused() {
        let mut r = sample(1, "eu-west", "fd-a");
        r.server_rank = 101;
        assert!(matches!(
            r.validate(),
            Err(RecordError::OutOfRange {
                field: "server_rank"
            })
        ));
        let mut r = sample(1, "eu-west", "fd-a");
        r.load_class = 4;
        assert!(matches!(
            r.validate(),
            Err(RecordError::OutOfRange {
                field: "load_class"
            })
        ));
    }

    #[test]
    fn only_retired_removes_a_relay_from_the_candidate_set() {
        // ADR-0006 §11.3 rule 1: selection is a REORDERING, never a filter.
        let mut r = sample(1, "eu-west", "fd-a");
        assert!(r.is_candidate());
        r.admin_state = AdminState::Draining;
        assert!(
            r.is_candidate(),
            "DRAINING lowers the score; it does not remove"
        );
        r.admin_state = AdminState::Retired;
        assert!(!r.is_candidate());
    }

    #[test]
    fn inserting_advances_the_version_and_replaces_by_id() {
        let mut f = InMemoryFleet::new();
        f.insert(sample(1, "eu-west", "fd-a")).expect("insert");
        assert_eq!(f.version(), 1);
        f.insert(sample(1, "eu-west", "fd-b")).expect("replace");
        assert_eq!(f.version(), 2);
        assert_eq!(f.len(), 1);
        assert_eq!(f.all("local-operator")[0].failure_domain, "fd-b");
    }

    #[test]
    fn the_registry_is_scoped_by_operator_group() {
        // ADR-0005 §10: `aud` scoping makes cross-TwinNet abuse structurally
        // impossible, and the registry keeps the same boundary.
        let mut f = InMemoryFleet::new();
        f.insert(sample(1, "eu-west", "fd-a")).expect("insert");
        assert_eq!(f.all("local-operator").len(), 1);
        assert!(f.all("someone-else").is_empty());
    }
}
