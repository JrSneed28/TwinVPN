//! The `reason_code` each row of §4.5 emits — and the substitutions forced by a
//! contract defect.
//!
//! **Authority:** `docs/reliability.md` §3.4, §3.5, §4.5, §10.2 E3;
//! `contracts/registry/reason_codes.json` (frozen, 201 codes).
//!
//! # The defect, stated before it is worked around
//!
//! §3.5 lists fifteen codes this document *contributes* — "a contribution is a
//! request for registration, not an act of registration" — and the frozen
//! registry has not registered them. Four of them are named by **normative
//! transition rows**:
//!
//! | Named by | Spelling §4.5 uses | In the frozen registry? |
//! |---|---|---|
//! | T20 | `NET.PATH.DEAD_NO_ALTERNATE` | **no** |
//! | T27, §6.3, §8.4 | `RELAY.FLEET.UNREACHABLE` | **no** |
//! | T30 | `POLICY.KILLSWITCH.TRAFFIC_RESTORED` | **no** |
//! | T34 (mobile park) | `PLATFORM.BACKGROUND_SUSPENDED` | **no** |
//! | T29 (DNS leak) | `DNS.LEAK.QUERY_OBSERVED_OFF_TUNNEL` | **no** |
//! | §5.4 | `NET.QOS.THROUGHPUT_LOW` | **no** |
//!
//! `twinvpn_types::ReasonCode` cannot name an unregistered code — deliberately,
//! because that is what makes "expose registered reason codes, never raw
//! internal errors" a compile-time property. So this module maps each
//! spec-named code onto the **nearest registered** one, records the pair, and
//! [`SUBSTITUTIONS`] is asserted by a test that fails the moment a substitution
//! becomes unnecessary. Nothing is silently downgraded and nothing is invented.

use twinvpn_types::{codes, ReasonCode};

use crate::event::{LinkKind, PolicyViolationKind, QosMetric};

/// One forced substitution: what `docs/reliability.md` names, and what this
/// build actually emits because the registry does not carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Substitution {
    /// The spelling `docs/reliability.md` uses.
    pub specified: &'static str,
    /// The registered code emitted instead.
    pub emitted: ReasonCode,
    /// The section of `docs/reliability.md` that names the specified spelling.
    pub cited_by: &'static str,
}

/// Every substitution this build makes, for the integration lead to reconcile.
///
/// A test asserts each `specified` spelling is genuinely **absent** from the
/// frozen registry, so registering one turns this list into a build failure that
/// points at the line to delete.
pub const SUBSTITUTIONS: &[Substitution] = &[
    Substitution {
        specified: "NET.PATH.DEAD_NO_ALTERNATE",
        emitted: codes::NET_NO_ROUTE,
        cited_by: "reliability.md §3.5, §4.5 T20, §8.1",
    },
    Substitution {
        specified: "RELAY.FLEET.UNREACHABLE",
        emitted: codes::RELAY_FAILOVER_EXHAUSTED,
        cited_by: "reliability.md §3.4, §4.5 T27, §6.3, §8.2, §8.4",
    },
    Substitution {
        specified: "POLICY.KILLSWITCH.TRAFFIC_RESTORED",
        emitted: codes::NET_SESSION_RECOVERED,
        cited_by: "reliability.md §4.5 T30",
    },
    Substitution {
        specified: "PLATFORM.BACKGROUND_SUSPENDED",
        emitted: codes::PLATFORM_SUSPENDED,
        cited_by: "reliability.md §3.5, §4.5 T34, §11.1, §11.2",
    },
    Substitution {
        specified: "DNS.LEAK.QUERY_OBSERVED_OFF_TUNNEL",
        emitted: codes::POLICY_LEAK_DETECTED,
        cited_by: "reliability.md §3.2, §3.4, §4.5 T29",
    },
    Substitution {
        specified: "NET.QOS.THROUGHPUT_LOW",
        emitted: codes::NET_QOS_DEGRADED_TIMEOUT,
        cited_by: "reliability.md §3.5, §5.4",
    },
    Substitution {
        specified: "RELAY.REGION.DOWN",
        emitted: codes::RELAY_REGION_UNAVAILABLE,
        cited_by: "reliability.md §3.2, §3.4, §8.2",
    },
];

/// The registered code for a substituted spelling.
///
/// # Panics
///
/// Never: every call site passes a literal that appears in [`SUBSTITUTIONS`],
/// and a test asserts the table covers each of them.
#[must_use]
pub fn substituted(specified: &str) -> Option<ReasonCode> {
    SUBSTITUTIONS
        .iter()
        .find(|s| s.specified == specified)
        .map(|s| s.emitted)
}

/// T20's code: `NET.PATH.DEAD_NO_ALTERNATE`, substituted, with the specific
/// cause available as `caused_by` evidence.
#[must_use]
pub const fn path_dead_no_alternate() -> ReasonCode {
    codes::NET_NO_ROUTE
}

/// The specific cause T20 carries in `caused_by`.
///
/// §4.5 T20: "with the specific cause as the `caused_by` evidence field
/// (`NET.LINK.DOWN_WIFI`, `NET.LINK.DOWN_CELLULAR`, `NET.PATH.DIRECT_LOST`,
/// `RELAY.NONE_REACHABLE`, …)". All four of those **are** registered.
#[must_use]
pub const fn link_down_cause(kind: LinkKind) -> ReasonCode {
    match kind {
        LinkKind::WiFi => codes::NET_LINK_DOWN_WIFI,
        LinkKind::Cellular => codes::NET_LINK_DOWN_CELLULAR,
        LinkKind::Ethernet => codes::NET_LINK_CHANGED_ETHERNET,
        LinkKind::Unknown => codes::NET_PATH_DIRECT_LOST,
    }
}

/// The `NET.QOS.*` code for a metric (§5.4).
#[must_use]
pub const fn qos_code(metric: QosMetric) -> ReasonCode {
    match metric {
        QosMetric::Loss => codes::NET_QOS_LOSS_HIGH,
        QosMetric::Rtt => codes::NET_QOS_RTT_HIGH,
        QosMetric::Jitter => codes::NET_QOS_JITTER_HIGH,
        // `NET.QOS.THROUGHPUT_LOW` is unregistered; see SUBSTITUTIONS.
        QosMetric::Throughput => codes::NET_QOS_DEGRADED_TIMEOUT,
        QosMetric::EffectiveMtu => codes::NET_MTU_TOO_SMALL,
    }
}

/// The specific policy code T29 emits for a violation kind.
///
/// §4.5 T29: "emit the **specific** policy code
/// (`DNS.LEAK.QUERY_OBSERVED_OFF_TUNNEL`, `ROUTE.DRIFT_DETECTED`,
/// `ROUTE.IFACE_MISSING`, …)" — never a generic one.
#[must_use]
pub const fn policy_violation_code(kind: PolicyViolationKind) -> ReasonCode {
    match kind {
        // Unregistered spelling; see SUBSTITUTIONS.
        PolicyViolationKind::DnsQueryOffTunnel => codes::POLICY_LEAK_DETECTED,
        PolicyViolationKind::RouteDrift => codes::ROUTE_DRIFT_DETECTED,
        PolicyViolationKind::InterfaceMissing => codes::ROUTE_IFACE_MISSING,
        PolicyViolationKind::FamilyUncovered => codes::POLICY_LEAK_IPV6_UNPROTECTED,
        PolicyViolationKind::RulesetAbsent => codes::POLICY_KILLSWITCH_ARM_FAILED,
        PolicyViolationKind::GrantExpired => codes::POLICY_EXPIRY_BUNDLE_EXPIRED,
    }
}

/// Whether a code's `class` is compatible with the state it accompanies.
///
/// §10.2's static test states the mapping as "`POLICY` → `BLOCKED`;
/// `FATAL`/`PERSISTENT` → `FAILED`; `TRANSIENT`/`PERSISTENT` → `RECONNECTING`;
/// `TRANSIENT` → `DEGRADED`".
///
/// # Two widenings, each forced by the frozen registry
///
/// 1. **`BLOCKED` admits `FATAL` and `PERSISTENT`, not only `POLICY`.** §4.5 T29
///    names `ROUTE.DRIFT_DETECTED` and `ROUTE.IFACE_MISSING` as T29 codes; the
///    registry classifies both `PERSISTENT`. It classifies `POLICY.LEAK.DETECTED`
///    — the archetypal leak — `FATAL`. Under the literal rule, three codes the
///    normative table names for `BLOCKED` could not be emitted there.
/// 2. **`FAILED` admits `POLICY` and `TRANSIENT`.** T11 and T28 send
///    `AUTH.DEVICE_REVOKED` — registered `POLICY` — to `FAILED`. T27's own
///    fallback ladder names `NET.NO_USABLE_CANDIDATES`, registered `TRANSIENT`,
///    "where nothing more specific exists". Both are in the normative table, so
///    the table wins over §10.2's summary of it.
///
/// 3. **`DEGRADED` admits `PERSISTENT`.** §5.4's effective-MTU row is a
///    `DEGRADED` entry threshold and the nearest registered code,
///    `NET.MTU_TOO_SMALL`, is `PERSISTENT`. §5.4 assigns that row no code at
///    all, which is the underlying gap.
///
/// All four are reported to the integration lead as spec/registry divergences
/// rather than resolved locally.
#[must_use]
pub fn class_admissible(code: ReasonCode, state: crate::state::SessionState) -> bool {
    use crate::state::SessionState as S;
    use twinvpn_types::ErrorClass as C;
    match state {
        S::Blocked => matches!(code.class(), C::Policy | C::Fatal | C::Persistent),
        // RECONNECTING and DEGRADED admit the same two classes, for different
        // reasons: §10.2 gives RECONNECTING `TRANSIENT`/`PERSISTENT` outright,
        // and DEGRADED reaches `PERSISTENT` only through widening 3 above.
        S::Reconnecting { .. } | S::Degraded { .. } => {
            matches!(code.class(), C::Transient | C::Persistent)
        }
        // FAILED admits every class after widening 2, and a state that carries
        // no code at all constrains nothing — so both fall through here.
        _ => true,
    }
}
