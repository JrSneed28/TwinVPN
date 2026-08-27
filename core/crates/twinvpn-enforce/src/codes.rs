//! The `POLICY.*` codes this crate emits — and the seventeen ADR-0012 registers
//! that the frozen registry does not carry.
//!
//! **Authority:** ADR-0012 §11.9's code table, ADR-0015 §11.2,
//! `contracts/registry/reason_codes.json` (frozen), `ownership.md` §6 rule 12.
//!
//! # The finding
//!
//! ADR-0012 §11.9 contributes **twenty-one** `POLICY.*` codes. The frozen
//! registry carries **four** of them: `POLICY.KILLSWITCH.ENGAGED`,
//! `POLICY.KILLSWITCH.ARM_FAILED`, `POLICY.KILLSWITCH.UNPROTECTED_FALLBACK` and
//! `POLICY.LEAK.IPV6_UNPROTECTED`. The other seventeen are listed in
//! [`UNREGISTERED`], each with the registered code this build emits instead.
//!
//! Two of them are the ones that hurt: `POLICY.LEAK.EGRESS_OBSERVED` is the leak
//! canary's own verdict, and `POLICY.KILLSWITCH.TRAFFIC_RESTORED` is
//! `docs/reliability.md` T30's emit action. Neither can be spelled by a
//! `twinvpn_types::ReasonCode`, so both are substituted and both are reported.
//!
//! The registry also **classifies two of the four differently** from ADR-0012
//! §11.9: `POLICY.KILLSWITCH.ENGAGED` is `POLICY`/`WARN` in the registry and
//! `POLICY`/`ERROR` in the ADR; `POLICY.KILLSWITCH.ARM_FAILED` is
//! `FATAL`/`CRITICAL` in the registry and `PERSISTENT`/`CRITICAL` in the ADR.

use twinvpn_types::{codes as reg, Component, Diagnostic, EvidenceValue, ReasonCode};

/// One code ADR-0012 §11.9 registers that the frozen registry does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Substitution {
    /// The spelling ADR-0012 §11.9 uses.
    pub specified: &'static str,
    /// The registered code this build emits instead.
    pub emitted: ReasonCode,
}

/// The seventeen. A test asserts each `specified` spelling is genuinely absent,
/// so registering one fails the build and points at the line to delete.
pub const UNREGISTERED: &[Substitution] = &[
    Substitution {
        specified: "POLICY.KILLSWITCH.TRAFFIC_RESTORED",
        emitted: reg::NET_SESSION_RECOVERED,
    },
    Substitution {
        specified: "POLICY.KILLSWITCH.ASSERTION_MISMATCH",
        emitted: reg::ROUTE_DRIFT_DETECTED,
    },
    Substitution {
        specified: "POLICY.KILLSWITCH.RULESET_TAMPERED",
        emitted: reg::POLICY_KILLSWITCH_ARM_FAILED,
    },
    Substitution {
        specified: "POLICY.KILLSWITCH.BOOT_ENFORCEMENT_UNAVAILABLE",
        emitted: reg::PLATFORM_ADAPTER_UNAVAILABLE,
    },
    Substitution {
        specified: "POLICY.KILLSWITCH.DISARMED_BY_OWNER",
        emitted: reg::POLICY_KILLSWITCH_UNPROTECTED_FALLBACK,
    },
    Substitution {
        specified: "POLICY.KILLSWITCH.DISARM_REFUSED_REMOTE",
        emitted: reg::MGMT_DISARM_REQUIRES_LOCAL_AUTH,
    },
    Substitution {
        specified: "POLICY.LEAK.FAMILY_GRANT_MISSING",
        emitted: reg::POLICY_LEAK_IPV6_UNPROTECTED,
    },
    Substitution {
        specified: "POLICY.LEAK.EGRESS_OBSERVED",
        emitted: reg::POLICY_LEAK_DETECTED,
    },
    Substitution {
        specified: "POLICY.LEAK.DNS_UNPROTECTED",
        emitted: reg::DNS_RESOLUTION_BLOCKED_FAIL_CLOSED,
    },
    Substitution {
        specified: "POLICY.SCOPE.ROUTE_UNGRANTED",
        emitted: reg::POLICY_NOT_ADVERTISED,
    },
    Substitution {
        specified: "POLICY.EXEMPT.LOCAL_NETWORK_ALLOWED",
        emitted: reg::POLICY_KILLSWITCH_UNPROTECTED_FALLBACK,
    },
    Substitution {
        specified: "POLICY.EXEMPT.PLATFORM_MANDATED",
        emitted: reg::PLATFORM_THIRD_PARTY_FILTER_SUSPECTED,
    },
    Substitution {
        specified: "POLICY.EXEMPT.EGRESS_ANOMALY",
        emitted: reg::POLICY_LEAK_DETECTED,
    },
    Substitution {
        specified: "POLICY.PORTAL.EXEMPTION_ACTIVE",
        emitted: reg::NET_CAPTIVE_PORTAL,
    },
    Substitution {
        specified: "POLICY.PORTAL.EXEMPTION_EXPIRED",
        emitted: reg::NET_CAPTIVE_PORTAL,
    },
    Substitution {
        specified: "POLICY.COEXIST.SECOND_VPN_DEFAULT_ROUTE",
        emitted: reg::ROUTE_IFACE_CONFLICT,
    },
    Substitution {
        specified: "POLICY.COEXIST.FILTER_CONFLICT",
        emitted: reg::PLATFORM_THIRD_PARTY_FILTER_SUSPECTED,
    },
];

/// `POLICY.KILLSWITCH.ENGAGED` — protected traffic is blocked because no
/// authorized secure path exists. Registered.
#[must_use]
pub const fn killswitch_engaged() -> ReasonCode {
    reg::POLICY_KILLSWITCH_ENGAGED
}

/// `POLICY.KILLSWITCH.ARM_FAILED` — the rule set could not be installed, and the
/// client refuses to enter a protected state. Registered.
#[must_use]
pub const fn ruleset_absent() -> ReasonCode {
    reg::POLICY_KILLSWITCH_ARM_FAILED
}

/// `POLICY.KILLSWITCH.ASSERTION_MISMATCH` — installed rules differ from intended
/// policy (O-17). **Substituted**; see [`UNREGISTERED`].
#[must_use]
pub const fn assertion_mismatch() -> ReasonCode {
    reg::ROUTE_DRIFT_DETECTED
}

/// `POLICY.LEAK.EGRESS_OBSERVED` — the canary observed protected traffic on a
/// non-overlay interface. **Substituted**; see [`UNREGISTERED`].
#[must_use]
pub const fn egress_observed() -> ReasonCode {
    reg::POLICY_LEAK_DETECTED
}

/// `POLICY.LEAK.IPV6_UNPROTECTED` — the tunnel or exit grant is v4-only.
/// Registered.
#[must_use]
pub const fn ipv6_unprotected() -> ReasonCode {
    reg::POLICY_LEAK_IPV6_UNPROTECTED
}

/// `POLICY.KILLSWITCH.UNPROTECTED_FALLBACK` — enforcement is disabled and
/// traffic is flowing untunneled, persistently announced. Registered.
#[must_use]
pub const fn unprotected_fallback() -> ReasonCode {
    reg::POLICY_KILLSWITCH_UNPROTECTED_FALLBACK
}

/// `INTERNAL.INVARIANT_VIOLATED` — used where a canary probe is itself invalid.
#[must_use]
pub const fn invariant_violated() -> ReasonCode {
    reg::INTERNAL_INVARIANT_VIOLATED
}

/// A `KILL_SWITCH`-observed diagnostic, with the family named as evidence.
///
/// Address family is an **evidence field**, never a namespace
/// (`ownership.md` §4.2): "a per-family namespace makes 'we have a v4 story and
/// a v6 story' sayable — the exact asymmetry ADR-0010 R1 exists to forbid."
#[must_use]
pub fn diagnostic(code: ReasonCode, family: Option<twinvpn_types::AddressFamily>) -> Diagnostic {
    let mut b = Diagnostic::builder(code, Component::KillSwitch);
    if let Some(f) = family {
        b = b.evidence("family", EvidenceValue::Family(f));
    }
    b.build()
}
