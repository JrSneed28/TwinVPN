//! Candidate gathering: both families concurrently, the relay from t = 0, and
//! the C4 caps applied **before** anything is allocated.
//!
//! **Authority:** ADR-0004 §11 (the ordered ladder), `docs/networking.md` §3.3,
//! §3.8; `contracts/proto/twinvpn/v1/candidate.proto` (frozen);
//! `contracts/registry/limits.json` `candidates.*` and `envelope.c4_*`;
//! `docs/reliability.md` §4.4 (`DISCOVERING`).
//!
//! # `CandidateSet` is the most hostile parser surface this crate owns
//!
//! It is a **B3** input — pre-authentication, attacker-reachable — arriving on
//! C4, whose envelope cap is 1200 bytes at depth 4. [`validate_set`] applies the
//! count cap **first**, "so a set claiming ten thousand candidates is rejected
//! before ten thousand endpoints are validated", and every allocation below it
//! is sized from the registry rather than from the sender's claim.
//!
//! # Rule 1 of §3.3, which is the one that matters
//!
//! > A `RELAY` candidate is **always** gathered, in parallel, from the first
//! > millisecond. It is never gathered "after direct fails" — that ordering is
//! > exactly what produces the multi-second connect stalls in the defect list.
//!
//! [`GatherPlan::new`] therefore records `relay_gathered_at` at construction,
//! and ADR-0004 §11.6(b) makes the assertion structural: P01 checks
//! `relay_gathered_at_ms ≤ first_direct_probe_ms` from the ledger, "which is
//! decidable from the ledger alone and does not depend on the rig's clock
//! resolution".

use twinvpn_env::MonotonicInstant;
use twinvpn_schema::{limits, v1, validate, Reject};
use twinvpn_types::{AddressFamily, CandidateId, Endpoint, Nat64Prefix, V4Addr};

/// `candidate.proto`'s `CandidateKind`, with `networking.md` §3.3's priorities.
///
/// The ladder's order is ADR-0004 §11's: native IPv6 first, then LAN, then IPv4
/// reflexive, then explicit port mapping, then bounded prediction, then relay —
/// "**by design, not by failure**".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// A global IPv6 address on a local interface. The highest priority, because
    /// "if both ends have working IPv6, every cell is `D`".
    HostV6Global,
    /// An IPv6 link-local address. **Carries a zone index, always** (RFC 4007).
    HostV6LinkLocal,
    /// A private IPv4 address on a local interface.
    HostV4Private,
    /// The IPv6 reflexive address the rendezvous observed.
    SrflxV6,
    /// The IPv4 reflexive address the rendezvous observed.
    SrflxV4,
    /// A mapping created via PCP → NAT-PMP → UPnP-IGDv2.
    PortmapV4,
    /// A birthday-paradox prediction. Lowest confidence, tracked separately "so
    /// 'prediction worked' is measurable rather than assumed".
    PredictedV4,
    /// A relay-allocated address. **Always present.**
    Relay,
}

impl Kind {
    /// `networking.md` §3.3's priority column.
    #[must_use]
    pub const fn priority(self) -> u32 {
        match self {
            Kind::HostV6Global => 130,
            Kind::HostV6LinkLocal => 126,
            Kind::HostV4Private => 120,
            Kind::SrflxV6 => 110,
            Kind::SrflxV4 => 100,
            Kind::PortmapV4 => 95,
            Kind::PredictedV4 => 40,
            Kind::Relay => 10,
        }
    }

    /// The family this kind is by construction.
    #[must_use]
    pub const fn family(self) -> Option<AddressFamily> {
        match self {
            Kind::HostV6Global | Kind::HostV6LinkLocal | Kind::SrflxV6 => Some(AddressFamily::V6),
            Kind::HostV4Private
            | Kind::SrflxV4
            | Kind::PortmapV4
            | Kind::PredictedV4 => Some(AddressFamily::V4),
            // A relay publishes both families and a device on IPv6-only cellular
            // must be able to bind one with no IPv4 path whatsoever.
            Kind::Relay => None,
        }
    }

    /// The wire value of `twinvpn.v1.CandidateKind`.
    #[must_use]
    pub const fn to_wire(self) -> i32 {
        match self {
            Kind::HostV6Global | Kind::HostV6LinkLocal | Kind::HostV4Private => 1,
            Kind::SrflxV6 | Kind::SrflxV4 => 2,
            Kind::PortmapV4 => 5,
            Kind::PredictedV4 => 6,
            Kind::Relay => 4,
        }
    }

    /// The `candidate_type` string ADR-0004 §11.5 requires
    /// `NAT.DIRECT_ESTABLISHED` to carry.
    #[must_use]
    pub const fn evidence_name(self) -> &'static str {
        match self {
            Kind::HostV6Global => "HOST_V6_GLOBAL",
            Kind::HostV6LinkLocal => "HOST_V6_LINKLOCAL",
            Kind::HostV4Private => "HOST_V4_PRIVATE",
            Kind::SrflxV6 => "SRFLX_V6",
            Kind::SrflxV4 => "SRFLX_V4",
            Kind::PortmapV4 => "PORTMAP",
            Kind::PredictedV4 => "PREDICTED",
            Kind::Relay => "RELAY",
        }
    }
}

/// One gathered candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// Unique within one establishment attempt.
    pub id: CandidateId,
    /// How it was learned.
    pub kind: Kind,
    /// Where it points.
    pub endpoint: Endpoint,
    /// When it was gathered, for the ledger's ordering assertion.
    pub gathered_at: MonotonicInstant,
    /// A hint, never authoritative: PMTU is re-probed on migration.
    pub mtu_hint: u32,
}

impl Candidate {
    /// The candidate's family, taken from the endpoint rather than the kind —
    /// so a relay candidate reports the family it is actually reachable on.
    #[must_use]
    pub const fn family(&self) -> AddressFamily {
        self.endpoint.family()
    }

    /// Whether the candidate is well formed for its kind.
    ///
    /// The one structural rule: an IPv6 link-local host candidate **MUST** carry
    /// a non-zero zone index. `protocol.md` §10.4: "IPv6 link-local host
    /// candidates MUST carry `zone_index` or they are unusable on
    /// multi-interface hosts."
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        match (self.kind, self.endpoint.address) {
            (Kind::HostV6LinkLocal, twinvpn_types::IpAddr::V6(a)) => {
                a.is_link_local() && a.zone().is_some()
            }
            (Kind::HostV6LinkLocal, _) => false,
            _ => match self.kind.family() {
                Some(f) => f == self.family(),
                None => true,
            },
        }
    }
}

/// The plan for one gathering round.
///
/// Both families are gathered **concurrently** — `docs/reliability.md` §4.4's
/// `DISCOVERING` invariant says so explicitly — and the relay is gathered from
/// t = 0 alongside them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatherPlan {
    /// When gathering started.
    pub started_at: MonotonicInstant,
    /// When the relay candidate's **first** gathering round began.
    ///
    /// Recorded at gathering, not at use, which is what makes P01's assertion
    /// structural.
    pub relay_gathered_at: MonotonicInstant,
    /// Whether v4 gathering was started.
    pub v4_started: bool,
    /// Whether v6 gathering was started.
    pub v6_started: bool,
}

impl GatherPlan {
    /// Starts a round. Both families and the relay begin at the same instant.
    #[must_use]
    pub const fn new(now: MonotonicInstant) -> Self {
        Self {
            started_at: now,
            relay_gathered_at: now,
            v4_started: true,
            v6_started: true,
        }
    }

    /// Whether both families were gathered, as `DISCOVERING` requires.
    #[must_use]
    pub const fn both_families_gathered(&self) -> bool {
        self.v4_started && self.v6_started
    }

    /// P01's structural assertion: the relay was gathered no later than the
    /// first direct probe.
    #[must_use]
    pub fn relay_gathered_before(&self, first_direct_probe: MonotonicInstant) -> bool {
        self.relay_gathered_at <= first_direct_probe
    }
}

/// `networking.md` §3.3 rule 2: gathering has a hard deadline.
///
/// "Late candidates are still usable for an *upgrade* but never delay
/// first-packet delivery."
pub const GATHER_DEADLINE: core::time::Duration = core::time::Duration::from_secs(3);

/// Validates a received `CandidateSet` against the C4 caps, **before** decoding
/// its members.
///
/// # Errors
///
/// [`Reject::CapViolated`] past `candidates.max_candidates_per_set` (32) or any
/// per-member cap; [`Reject::Malformed`] on a bad identifier or endpoint.
///
/// The envelope caps — `envelope.c4_max_bytes` = 1200 and
/// `envelope.c4_max_depth` = 4 — are applied by
/// `twinvpn_schema::validate::decode` *before* this is reached; a caller that
/// decodes without going through it has skipped both.
pub fn validate_set(set: &v1::CandidateSet) -> Result<(), Reject> {
    validate::candidate_set(set)
}

/// The C4 caps this crate validates against, restated so a test can assert them
/// against the frozen registry.
pub struct C4Caps;

impl C4Caps {
    /// `envelope.c4_max_bytes`.
    pub const MAX_BYTES: usize = limits::C4_MAX_BYTES;
    /// `envelope.c4_max_depth`.
    pub const MAX_DEPTH: usize = limits::C4_MAX_DEPTH;
    /// `candidates.max_candidates_per_set`.
    pub const MAX_CANDIDATES: usize = limits::MAX_CANDIDATES_PER_SET;
    /// `candidates.max_birthday_port_hints`.
    pub const MAX_PORT_HINTS: usize = limits::MAX_BIRTHDAY_PORT_HINTS;
}

/// `docs/networking.md` §3.8: synthesizes an IPv6 candidate for an IPv4-literal
/// peer or relay on a NAT64 network.
///
/// **TwinVPN never relies on DNS64 to do this for it**, "because the overlay's
/// own resolver may be the one answering, and a resolver that both synthesizes
/// and is tunneled produces a circular dependency at bring-up". The prefix comes
/// from RFC 8781 PREF64 in a Router Advertisement (preferred) or RFC 7050
/// `ipv4only.arpa`, discovered once per network fingerprint and cached — never
/// from this stub's answers.
#[must_use]
pub fn synthesize_nat64(prefix: Nat64Prefix, v4: V4Addr) -> twinvpn_types::V6Addr {
    prefix.synthesize(v4)
}

/// A `CandidateSet` carrying only one family is flagged, never accepted quietly.
///
/// `candidate.proto`: "A set containing only one family MUST be flagged
/// `NAT.SINGLE_FAMILY_CANDIDATES` in diagnostics — it is the leading cause of
/// 'works at home, fails on cellular'."
#[must_use]
pub fn single_family(candidates: &[Candidate]) -> Option<AddressFamily> {
    let has_v4 = candidates
        .iter()
        .any(|c| c.family() == AddressFamily::V4);
    let has_v6 = candidates
        .iter()
        .any(|c| c.family() == AddressFamily::V6);
    match (has_v4, has_v6) {
        (true, false) => Some(AddressFamily::V4),
        (false, true) => Some(AddressFamily::V6),
        _ => None,
    }
}
