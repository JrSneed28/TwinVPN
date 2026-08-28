//! Relay-directory registration: the ADR-0006 §11.2 record this instance
//! publishes about itself.
//!
//! **Authority:** ADR-0006 §11.2 (the signed relay map's per-`Relay` fields),
//! §11.1 rule 3 (≥ 2 alternates per region across ≥ 2 failure domains),
//! ADR-0005 §10 ("relay endpoints published in the relay map are per-instance
//! and individually addressable; a `Relay` MUST NOT be a load-balanced VIP"),
//! ADR-0011 DN-0 (literal addresses, never hostnames);
//! `contracts/proto/twinvpn/v1/relay.proto` message `Relay`, which is what every
//! field here means.
//!
//! # This relay does not enrol itself, and that is the security decision
//!
//! The obvious reading of "relay directory registration" is a relay POSTing
//! itself into the directory's fleet. **That is not what this does, and it is
//! not an omission.**
//!
//! The relay map is *Owner-signed*, and ADR-0006 §11.2 makes it normative that a
//! device "MUST NOT bind a relay whose `relay_id` and static Noise public key
//! are not present in a VERIFIED map". The map is therefore the root of relay
//! trust for every device in a TwinNet. A relay that could write itself into it
//! could add a relay of its choosing — which is precisely the "compromised relay
//! steering traffic" attack `relay.proto` closes on the `DRAIN` path ("a relay
//! can ASK a device to leave but can NEVER REDIRECT A SESSION BY ITSELF"). It
//! would be inconsistent to close it there and open it here.
//!
//! Registration is therefore **operator-driven**: the operator enrols an
//! instance into `relay-directory`'s fleet, and this module's job is to make that
//! enrolment *exact* — it derives the record from the configuration the process
//! is actually running with, including the **public** half of the static Noise
//! key it will actually answer handshakes with, and emits it at startup.
//!
//! The failure this prevents is a real one and is otherwise silent: a map entry
//! whose `static_noise_public_key` does not match the key file the relay loaded
//! makes every device's `Noise_IK` initiation fail at the responder, with the
//! device blaming the network and the relay logging nothing, because a failed
//! handshake is deliberately indistinguishable from noise (`crate::leg`).
//!
//! # What is deliberately not in the record
//!
//! No flow count, no subject, no peer, no `pair_tag`, no session dimension of
//! any kind. `load_class` is 0–3 and coarse *because* `relay.proto` says
//! `RelayHealth` "carries no session_id, no pair_tag, and no device identifier"
//! (ADR-0015 O-13). The record describes an *instance*, never its traffic.

use serde::Serialize;

use crate::config::{AdminState, Carriage, RelayConfig};

/// The number of coarse load classes ADR-0006 §11.2 defines: 0–3.
pub const LOAD_CLASSES: u8 = 4;

/// One relay instance, as it must appear in the Owner-signed map.
///
/// Mirrors `relay.proto`'s `Relay` field for field. It is **not** a second
/// definition of that message (§6 rule 2 forbids one) — it is the operator-facing
/// rendering of the subset an instance can state about itself, and the fields it
/// cannot state (`server_rank`, `capacity_weight`) are the operator's to set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelayDescriptor {
    /// 8 bytes, lowercase hex. Never reused after retirement: a reused
    /// `relay_id` would let a cached ranking from a decommissioned instance be
    /// applied to a new one.
    pub relay_id: String,
    /// The unit of **admission** — a token's `aud` is this, never a `relay_id`,
    /// which is what makes ADR-0006's offline failover possible at all.
    pub operator_group_id: String,
    /// The region this instance serves. Opaque to a device.
    pub region_id: String,
    /// The correlated-failure label. ADR-0006 requires the standby to be in a
    /// **different** one; a standby that fails with its primary is not a standby.
    pub failure_domain: String,
    /// The static Noise **public** key, lowercase hex.
    ///
    /// Derived from the private key this process actually loaded, which is the
    /// whole point of the module. ADR-0005 §7.3: holding this key gives the relay
    /// no read access to L-DATA — it is not a party to that handshake.
    pub static_noise_public_key: String,
    /// The carriages this instance is configured for.
    pub carriages: Vec<&'static str>,
    /// The literal IPv4 endpoints, `addr:port`. **Never a hostname** (ADR-0011
    /// DN-0): relay reachability must not depend on the resolver a device needs
    /// the relay to reach.
    pub endpoints_v4: Vec<String>,
    /// The literal IPv6 endpoints. A device on IPv6-only cellular must be able
    /// to use a relay with no IPv4 path whatsoever.
    pub endpoints_v6: Vec<String>,
    /// `ACTIVE`, `DRAINING` or `RETIRED`.
    pub admin_state: &'static str,
    /// Whether the TwinNet's own Owner operates this instance. Affects ADR-0006
    /// ranking only; **trust is unchanged** — a self-hosted relay is untrusted
    /// exactly as a hosted one is (B3, I1).
    pub self_hosted: bool,
    /// This build implements `DRAIN` (ADR-0005 §10).
    pub supports_drain: bool,
    /// This build implements `CAPS`.
    pub supports_caps: bool,
}

/// Why a descriptor could not be built.
#[derive(Debug, thiserror::Error)]
pub enum DescriptorError {
    /// The static Noise key could not be read or was not 32 bytes.
    ///
    /// Fatal at startup: an instance that cannot state its own public key cannot
    /// be enrolled correctly, and enrolling it *incorrectly* is the silent
    /// failure this module exists to prevent.
    #[error("the relay static Noise key is unusable")]
    StaticKey,
    /// No endpoint of either family could be determined.
    #[error("no literal endpoint to publish")]
    NoEndpoint,
}

impl RelayDescriptor {
    /// Builds the record from the running configuration and the loaded key.
    ///
    /// `static_private` is borrowed and never retained — only its public half
    /// reaches the descriptor.
    ///
    /// # Errors
    ///
    /// [`DescriptorError`].
    pub fn build(cfg: &RelayConfig, static_private: &[u8]) -> Result<Self, DescriptorError> {
        let public = twinvpn_crypto::relay_leg::static_public_key(static_private)
            .map_err(|_| DescriptorError::StaticKey)?;

        // Both families, split by what the socket address actually is rather
        // than by what was configured: `[::]` is dual-stack or v6-only depending
        // on `bindv6only`, and the map must say which.
        let mut endpoints_v4 = Vec::new();
        let mut endpoints_v6 = Vec::new();
        for addr in cfg.published_endpoints() {
            match addr {
                std::net::SocketAddr::V4(_) => endpoints_v4.push(addr.to_string()),
                std::net::SocketAddr::V6(_) => endpoints_v6.push(addr.to_string()),
            }
        }
        if endpoints_v4.is_empty() && endpoints_v6.is_empty() {
            return Err(DescriptorError::NoEndpoint);
        }

        Ok(Self {
            relay_id: cfg.relay_id_hex.clone(),
            operator_group_id: cfg.operator_group_id.clone(),
            region_id: cfg.region_id.clone(),
            failure_domain: cfg.failure_domain.clone(),
            static_noise_public_key: hex(&public),
            carriages: cfg.carriages.iter().map(|c| c.as_str()).collect(),
            endpoints_v4,
            endpoints_v6,
            admin_state: admin_state_name(cfg.admin_state),
            self_hosted: cfg.self_hosted,
            supports_drain: true,
            supports_caps: true,
        })
    }

    /// The record as canonical JSON, for an operator to paste into the fleet.
    ///
    /// # Errors
    ///
    /// [`serde_json::Error`] — cannot occur for this shape, but is propagated
    /// rather than unwrapped so a future field cannot make it a panic.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Whether this instance would satisfy ADR-0006 §11.1 rule 3 **on its own**.
    ///
    /// It never can, and saying so is the point: the floor is "≥ 2 alternates
    /// per region across ≥ 2 failure domains", which is a property of a *fleet*.
    /// A one-relay deployment is a single point of failure and ADR-0005 §10
    /// requires it be surfaced as `RELAY.SELF_HOSTED_NO_ALTERNATE`, "never
    /// silently accepted".
    #[must_use]
    pub const fn satisfies_alternates_floor_alone(&self) -> bool {
        false
    }
}

/// Whether the descriptor names a family a device on that family could use.
///
/// ADR-0010 and `docs/protocol.md` §11.1: a relay MUST publish both families,
/// and a relay that publishes only one is only reachable by half the fleet.
/// Reported rather than refused, because an operator running an IPv6-only
/// profile deliberately (`infra/`'s does) is not making a mistake.
#[must_use]
pub fn dual_stack(d: &RelayDescriptor) -> bool {
    !d.endpoints_v4.is_empty() && !d.endpoints_v6.is_empty()
}

const fn admin_state_name(s: AdminState) -> &'static str {
    match s {
        AdminState::Active => "ACTIVE",
        AdminState::Draining => "DRAINING",
        AdminState::Retired => "RETIRED",
    }
}

/// Lowercase hex, because that is how `relay_id` is already spelled in
/// configuration and a map with two conventions is a map with a typo in it.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The carriages a `Carriage` list renders as, for a test to enumerate.
#[must_use]
pub fn carriage_names(carriages: &[Carriage]) -> Vec<&'static str> {
    carriages.iter().map(|c| c.as_str()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_service_common::config::MapEnv;

    fn config(extra: &[(&str, &str)]) -> RelayConfig {
        let mut env = MapEnv::new()
            .with("TWINVPN_RELAY_ID", "0000000000000a01")
            .with("TWINVPN_RELAY_REGION", "eu-west-1")
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
            // Routable literals, not the wildcard defaults: a wildcard is what
            // the socket listens on and never an address a device can dial, so
            // `published_endpoints` excludes it and a descriptor built from the
            // defaults alone is correctly refused.
            .with("TWINVPN_RELAY_LISTEN_UDP", "192.0.2.10:41641")
            .with("TWINVPN_RELAY_LISTEN_UDP_443", "[2001:db8::10]:443");
        for (k, v) in extra {
            env = env.with(k, v);
        }
        RelayConfig::load(&env).expect("loads")
    }

    #[test]
    fn a_wildcard_bind_is_never_published_as_an_endpoint() {
        // The defaults are `[::]` on every carriage. Publishing one would enrol
        // an unreachable relay that looks perfectly correct in the map.
        let cfg = RelayConfig::load(
            &MapEnv::new()
                .with("TWINVPN_RELAY_ID", "0000000000000a01")
                .with("TWINVPN_RELAY_REGION", "eu-west-1")
                .with("TWINVPN_RELAY_FAILURE_DOMAIN", "fd-a")
                .with("TWINVPN_RELAY_OPERATOR_GROUP_ID", "local-operator")
                .with(
                    "TWINVPN_RELAY_ISSUER_KEYS_PATH",
                    concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
                )
                .with(
                    "TWINVPN_RELAY_STATIC_KEY_PATH",
                    concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
                ),
        )
        .expect("loads");
        assert!(cfg.published_endpoints().is_empty());
        assert!(matches!(
            RelayDescriptor::build(&cfg, &[1_u8; 32]),
            Err(DescriptorError::NoEndpoint)
        ));
    }

    #[test]
    fn the_published_key_is_the_public_half_of_the_key_actually_loaded() {
        // The whole reason the module exists: a map entry that names a different
        // key than the process holds fails every handshake, silently.
        let cfg = config(&[]);
        let private = [7_u8; 32];
        let d = RelayDescriptor::build(&cfg, &private).expect("descriptor");
        let expected = twinvpn_crypto::relay_leg::static_public_key(&private).expect("public half");
        assert_eq!(d.static_noise_public_key, hex(&expected));
        assert_eq!(d.static_noise_public_key.len(), 64);
        // And it is not the private half, which is the mistake worth a test.
        assert_ne!(d.static_noise_public_key, hex(&private));
    }

    #[test]
    fn a_short_static_key_is_a_refusal_not_a_padded_guess() {
        let cfg = config(&[]);
        for len in [0_usize, 1, 31, 33, 64] {
            assert!(
                RelayDescriptor::build(&cfg, &vec![1_u8; len]).is_err(),
                "a {len}-byte static key must not produce a descriptor"
            );
        }
    }

    #[test]
    fn the_descriptor_names_literal_endpoints_and_never_a_hostname() {
        // ADR-0011 DN-0: relay reachability must not depend on DNS.
        let cfg = config(&[]);
        let d = RelayDescriptor::build(&cfg, &[3_u8; 32]).expect("descriptor");
        for e in d.endpoints_v4.iter().chain(d.endpoints_v6.iter()) {
            let host = e.rsplit_once(':').expect("host:port").0;
            assert!(
                host.parse::<std::net::IpAddr>().is_ok()
                    || host
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .parse::<std::net::IpAddr>()
                        .is_ok(),
                "{e} is not a literal address"
            );
        }
    }

    #[test]
    fn the_descriptor_carries_no_session_dimension() {
        let cfg = config(&[]);
        let d = RelayDescriptor::build(&cfg, &[5_u8; 32]).expect("descriptor");
        let json = d.to_json().expect("json");
        for forbidden in [
            "flow", "pair_tag", "session", "device", "subject", "peer", "token",
        ] {
            assert!(
                !json.contains(forbidden),
                "the fleet record must describe an INSTANCE, never its traffic \
                 (ADR-0015 O-13); it names `{forbidden}`"
            );
        }
    }

    #[test]
    fn the_admin_state_is_rendered_as_the_proto_spells_it() {
        for (value, expected) in [
            ("ACTIVE", "ACTIVE"),
            ("DRAINING", "DRAINING"),
            ("RETIRED", "RETIRED"),
        ] {
            let cfg = config(&[("TWINVPN_RELAY_ADMIN_STATE", value)]);
            let d = RelayDescriptor::build(&cfg, &[1_u8; 32]).expect("descriptor");
            assert_eq!(d.admin_state, expected);
        }
    }

    #[test]
    fn one_relay_never_satisfies_the_alternates_floor() {
        let cfg = config(&[]);
        let d = RelayDescriptor::build(&cfg, &[1_u8; 32]).expect("descriptor");
        assert!(
            !d.satisfies_alternates_floor_alone(),
            "ADR-0006 §11.1 rule 3 is a property of a FLEET; a relay that claimed \
             to satisfy it alone would let a directory serve a candidate set that \
             cannot survive one failure"
        );
    }

    #[test]
    fn this_build_advertises_the_two_capabilities_it_implements() {
        let cfg = config(&[]);
        let d = RelayDescriptor::build(&cfg, &[1_u8; 32]).expect("descriptor");
        // ADR-0005 §10: a self-hosted relay MUST implement DRAIN and CAPS, and
        // ADR-0006 SHOULD rank one that does not below hosted relays. Claiming
        // them without implementing them would be worse than not claiming them.
        assert!(d.supports_drain);
        assert!(d.supports_caps);
    }
}
