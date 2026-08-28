//! The verified relay map, and the **only four** reductions of the candidate set
//! ADR-0006 permits.
//!
//! **Authority:** ADR-0006 §11.2, §11.3 rule 2, §11.9; ADR-0005 §11.3;
//! `contracts/proto/twinvpn/v1/relay.proto` (frozen).
//!
//! # A stale map is used, never blocked on
//!
//! §11.9: the candidate set comes from the "cached signed `RelayMap`,
//! **stale-but-usable at any age** (S-09)", with no server contact. §9.1 of
//! `docs/reliability.md` says the same from the other side: relay-map staleness
//! has "**no enforcement effect whatsoever** — a stale map is used, never
//! blocked on."
//!
//! So [`RelayMap`] carries its version and age as *evidence* and there is no
//! `is_fresh()` gate anywhere in this crate.

use twinvpn_types::{Endpoint, PerFamily, RegionId, RelayId};

/// The derived, eventually-consistent opinion held about a relay (S-10).
///
/// **W-20's disposition, executed (R-14).** This crate used to hand-write a
/// FOUR-variant copy of `twinvpn.v1.HealthState` and re-encode ADR-0006 §11.2's
/// deltas as literals beside it. The frozen enum has FIVE variants, and the one
/// every copy omitted was `HEALTH_STATE_UNSPECIFIED` — the proto3 zero an unset
/// field decodes to. A four-variant model cannot represent "the sender did not
/// say", so it has to invent an answer, and the convenient invention is
/// `HEALTHY`.
///
/// The canonical enum now lives in `twinvpn-types` beside `ConnectionState`,
/// `PathClass` and `TrafficDisposition`, and this is a re-export of it. The
/// score delta has one definition; a second place to drift no longer exists.
pub use twinvpn_types::state::HealthState;

/// A relay's carriage, from `relay.proto`'s `RelayCarriage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Carriage {
    /// `relay_udp/1`.
    Udp,
    /// `relay_quic/1` — the UDP:443 rung.
    Quic,
    /// `relay_tls/1` — the last rung on UDP-blocked networks (R-18).
    Tls,
}

/// A relay's operator-declared lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdminState {
    /// Accepting binds.
    Active,
    /// Accepting no new binds; existing flows have until the drain deadline.
    Draining,
    /// The relay no longer exists as a signed entity.
    Retired,
}

/// One relay, as published in the Owner-signed map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    /// Opaque, 8 bytes, never reused after retirement.
    pub id: RelayId,
    /// The unit of admission. The token's `aud` is this, **never a single
    /// `relay_id`** — "one token works across the whole ranked set, which is what
    /// makes ADR-0006's offline failover possible at all".
    pub operator_group_id: String,
    /// Which region it is in.
    pub region: RegionId,
    /// Literal addresses, both families. **Never hostnames** — "relay
    /// reachability MUST NOT depend on DNS, otherwise recovering from `BLOCKED`
    /// would require the resolver that the relay is needed to reach".
    pub endpoints: PerFamily<Vec<Endpoint>>,
    /// Which carriages it offers.
    pub carriages: Vec<Carriage>,
    /// The correlated-failure label. A standby in the **same** domain is not a
    /// standby.
    pub failure_domain: String,
    /// The operator's static ranking hint, 0–100. **Advisory.**
    pub server_rank: u32,
    /// 0–3, coarse. A hint, never a gate.
    pub load_class: u32,
    /// Proportional weight for HRW redistribution.
    pub capacity_weight: u32,
    /// Lifecycle.
    pub admin_state: AdminState,
    /// Whether the TwinNet's own Owner operates it.
    pub self_hosted: bool,
    /// Whether it signals drain.
    pub supports_drain: bool,
    /// Whether it honours capability tokens.
    pub supports_caps: bool,
}

impl Relay {
    /// Whether this relay publishes an endpoint in `family`.
    #[must_use]
    pub fn reachable_in(&self, family: twinvpn_types::AddressFamily) -> bool {
        !self.endpoints.get(family).is_empty()
    }
}

/// The signed map, with the version that orders it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayMap {
    /// Monotone. A non-increasing version is refused.
    pub version: u64,
    /// The relays.
    pub relays: Vec<Relay>,
}

impl RelayMap {
    /// §11.9's peer-supplied map rule: "refuses any **non-increasing** version".
    ///
    /// The peer "is a courier of signed bytes", so this decides ordering only —
    /// the signature check is `twinvpn-trust`'s.
    #[must_use]
    pub const fn accepts_version(&self, offered: u64) -> bool {
        offered > self.version
    }
}

/// What the device can actually do, which is the other half of admissibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCapability {
    /// Families the device can reach right now.
    pub families: PerFamily<bool>,
    /// Whether a NAT64 prefix is available to synthesize a v6 route to a v4
    /// literal.
    pub nat64_available: bool,
    /// Carriages this build supports.
    pub carriages: Vec<Carriage>,
    /// The `aud` of the token this device holds.
    pub token_operator_group_id: String,
}

/// Why a relay was removed from the candidate set.
///
/// §11.3 rule 2 permits **exactly four**, "all of them local or structural facts
/// rather than `EVENTUAL` state". There is deliberately no variant for an
/// `UNHEALTHY` `HealthState`, a "peer offline" record, or a stale map — those
/// are score deltas and nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Excluded {
    /// `admin_state = RETIRED` in a verified map.
    Retired,
    /// No endpoint in a family the device can reach, and no NAT64 synthesis.
    NoCandidateForFamily,
    /// No `carriages[]` entry the device supports.
    NoCarriageSupported,
    /// `operator_group_id` does not match the held token's `aud` — the device
    /// cannot be admitted at all.
    NotInOperatorGroup,
}

/// Applies §11.3 rule 2, and nothing else.
///
/// Returns `None` when the relay is admissible.
#[must_use]
pub fn exclusion(relay: &Relay, device: &DeviceCapability) -> Option<Excluded> {
    if relay.admin_state == AdminState::Retired {
        return Some(Excluded::Retired);
    }
    if relay.operator_group_id != device.token_operator_group_id {
        return Some(Excluded::NotInOperatorGroup);
    }
    let reachable = [
        twinvpn_types::AddressFamily::V4,
        twinvpn_types::AddressFamily::V6,
    ]
    .into_iter()
    .any(|f| *device.families.get(f) && relay.reachable_in(f))
        || (device.nat64_available
            && *device.families.get(twinvpn_types::AddressFamily::V6)
            && relay.reachable_in(twinvpn_types::AddressFamily::V4));
    if !reachable {
        return Some(Excluded::NoCandidateForFamily);
    }
    if !relay.carriages.iter().any(|c| device.carriages.contains(c)) {
        return Some(Excluded::NoCarriageSupported);
    }
    None
}

/// The admissible subset of a map.
#[must_use]
pub fn admissible<'a>(map: &'a RelayMap, device: &DeviceCapability) -> Vec<&'a Relay> {
    map.relays
        .iter()
        .filter(|r| exclusion(r, device).is_none())
        .collect()
}
