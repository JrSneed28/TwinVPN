//! The `NAT.*` codes ADR-0004 §11.5 registers, and the three the frozen registry
//! does not carry.
//!
//! **Authority:** ADR-0004 §11.5, §11.6(a); ADR-0015 §11.2;
//! `contracts/registry/reason_codes.json`.
//!
//! # The finding
//!
//! ADR-0004 §11.5 registers eleven `NAT.*` codes. The frozen registry carries
//! eight of them plus `NAT.SINGLE_FAMILY_CANDIDATES` (which `candidate.proto`
//! names and §11.5 does not). Three are missing: `NAT.PORTMAP_FAILED`,
//! `NAT.HAIRPIN_UNSUPPORTED` and `NAT.CLASS_OBSERVED`.
//!
//! `NAT.CLASS_OBSERVED` is the one that hurts: ADR-0004 §11.6(a) names it a
//! **guaranteed observable** that proof test P01 consumes for "P01's per-class
//! pass criteria". `networking.md` §3.7 additionally names
//! `NET.EGRESS_RESTRICTED`, `NET.PROXY_REQUIRED` and `NET.HAIRPIN_UNSUPPORTED`,
//! none of which is registered either.

use twinvpn_types::{codes as reg, AddressFamily, Component, Diagnostic, EvidenceValue, ReasonCode};

use crate::candidate::Kind;

/// One code a document names that the frozen registry does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Substitution {
    /// The spelling the document uses.
    pub specified: &'static str,
    /// Where it is named.
    pub cited_by: &'static str,
    /// The registered code this build emits instead.
    pub emitted: ReasonCode,
}

/// The six. A test asserts each is genuinely absent.
pub const UNREGISTERED: &[Substitution] = &[
    Substitution {
        specified: "NAT.PORTMAP_FAILED",
        cited_by: "ADR-0004 §11.5",
        emitted: reg::NAT_PUNCH_TIMEOUT,
    },
    Substitution {
        specified: "NAT.HAIRPIN_UNSUPPORTED",
        cited_by: "ADR-0004 §11.5",
        emitted: reg::NAT_PUNCH_TIMEOUT,
    },
    Substitution {
        specified: "NAT.CLASS_OBSERVED",
        cited_by: "ADR-0004 §11.5, §11.6(a) — a GUARANTEED OBSERVABLE for P01",
        emitted: reg::NAT_CGNAT_DETECTED,
    },
    Substitution {
        specified: "NET.EGRESS_RESTRICTED",
        cited_by: "networking.md §3.7",
        emitted: reg::NAT_UDP_BLOCKED,
    },
    Substitution {
        specified: "NET.PROXY_REQUIRED",
        cited_by: "networking.md §3.7",
        emitted: reg::NAT_UDP_BLOCKED,
    },
    Substitution {
        specified: "NET.HAIRPIN_UNSUPPORTED",
        cited_by: "networking.md §3.7",
        emitted: reg::NAT_PUNCH_TIMEOUT,
    },
];

/// `NAT.DIRECT_ESTABLISHED` — the direct-path **success** outcome.
///
/// §11.6 records why it exists: "the ladder previously emitted a code for every
/// way direct could *fail* and none for the way it succeeds, so success was
/// assertable only as the absence of failure."
///
/// Carries `family`, `candidate_type`, `elapsed_ms` from `EV_CONNECT_REQUESTED`
/// and `relay_gathered_at_ms` — all four declared by the registry.
#[must_use]
pub fn direct_established(
    family: AddressFamily,
    kind: Kind,
    elapsed_ms: u64,
    relay_gathered_at_ms: u64,
) -> Diagnostic {
    Diagnostic::builder(reg::NAT_DIRECT_ESTABLISHED, Component::NatTraversal)
        .evidence("family", EvidenceValue::Family(family))
        .evidence(
            "candidate_type",
            EvidenceValue::Text(kind.evidence_name().to_owned()),
        )
        .evidence("elapsed_ms", EvidenceValue::DurationMs(elapsed_ms))
        .evidence(
            "relay_gathered_at_ms",
            EvidenceValue::DurationMs(relay_gathered_at_ms),
        )
        .build()
}

/// `NAT.DIRECT_UPGRADED` — a `RELAYED` path became direct by background probing
/// (R-12).
#[must_use]
pub fn direct_upgraded(
    family: AddressFamily,
    kind: Kind,
    relayed_duration_ms: u64,
) -> Diagnostic {
    Diagnostic::builder(reg::NAT_DIRECT_UPGRADED, Component::NatTraversal)
        .evidence("family", EvidenceValue::Family(family))
        .evidence(
            "candidate_type",
            EvidenceValue::Text(kind.evidence_name().to_owned()),
        )
        .evidence(
            "relayed_duration_ms",
            EvidenceValue::DurationMs(relayed_duration_ms),
        )
        .build()
}

/// `NAT.SYMMETRIC_BOTH_ENDS` — relay by design, not an error path.
#[must_use]
pub fn symmetric_both_ends(family: AddressFamily) -> Diagnostic {
    Diagnostic::builder(reg::NAT_SYMMETRIC_BOTH_ENDS, Component::NatTraversal)
        .evidence("family", EvidenceValue::Family(family))
        .build()
}

/// `NAT.SINGLE_FAMILY_CANDIDATES` — "the leading cause of 'works at home, fails
/// on cellular'".
#[must_use]
pub fn single_family_candidates(present: AddressFamily) -> Diagnostic {
    Diagnostic::builder(reg::NAT_SINGLE_FAMILY_CANDIDATES, Component::NatTraversal)
        .evidence("family", EvidenceValue::Family(present))
        .build()
}

/// The most specific transport code observed, for `docs/reliability.md` T12's
/// "never a generic one".
#[must_use]
pub const fn udp_blocked() -> ReasonCode {
    reg::NAT_UDP_BLOCKED
}

/// `NAT.NO_SERVER_REFLEXIVE`.
#[must_use]
pub const fn no_server_reflexive() -> ReasonCode {
    reg::NAT_NO_SERVER_REFLEXIVE
}

/// `NAT.CGNAT_V4_NO_V6` — "the worst traversal case", and the one where telling
/// the user to enable IPv6 actually helps.
#[must_use]
pub const fn cgnat_v4_no_v6() -> ReasonCode {
    reg::NAT_CGNAT_V4_NO_V6
}
