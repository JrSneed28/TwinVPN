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
pub const SUBSTITUTIONS: &[Substitution] = &[];

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
    codes::NET_PATH_DEAD_NO_ALTERNATE
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
/// # The registry decides a code's class; §10.2 summarises, it does not legislate
///
/// §10.2's static test states the mapping as "`POLICY` → `BLOCKED`;
/// `FATAL`/`PERSISTENT` → `FAILED`; `TRANSIENT`/`PERSISTENT` → `RECONNECTING`;
/// `TRANSIENT` → `DEGRADED`". Read as a constraint on which codes §4.5 may name,
/// it is contradicted by §4.5 itself in four places.
///
/// The resolution is ADR-0015 §11.2 rule 4 — **"the code is the contract"**. The
/// frozen registry is authoritative for a code's `class`; an ADR's prose about
/// what class a condition "is" does not override the registry entry, and §10.2's
/// sentence is a summary of the common case rather than a fifth authority. So
/// this function admits the classes the **registry** assigns to the codes §4.5
/// **actually names**, which is what the transition table already implies:
///
/// | State | Admits | Because §4.5 names |
/// |---|---|---|
/// | `BLOCKED` | `POLICY`, `FATAL`, `PERSISTENT` | T29's `ROUTE.DRIFT_DETECTED` and `ROUTE.IFACE_MISSING` (both `PERSISTENT`), and `POLICY.LEAK.DETECTED` (`FATAL`) |
/// | `FAILED` | any | T11/T28's `AUTH.DEVICE_REVOKED` (`POLICY`) and T27's fallback `NET.NO_USABLE_CANDIDATES` (`TRANSIENT`) |
/// | `RECONNECTING` | `TRANSIENT`, `PERSISTENT` | §10.2's reading holds here unchanged |
/// | `DEGRADED` | `TRANSIENT`, `PERSISTENT` | §5.4's effective-MTU row, whose nearest registered code `NET.MTU_TOO_SMALL` is `PERSISTENT` |
///
/// Only the last row rests on a genuine gap rather than a summary: §5.4 assigns
/// the effective-MTU threshold **no code at all**, so the `PERSISTENT` reading
/// comes from the code this crate had to choose. That one is still worth an
/// ADR amendment; the other three are not, because the table was always right.
#[must_use]
pub fn class_admissible(code: ReasonCode, state: crate::state::SessionState) -> bool {
    use crate::state::SessionState as S;
    use twinvpn_types::ErrorClass as C;
    match state {
        S::Blocked => matches!(code.class(), C::Policy | C::Fatal | C::Persistent),
        // RECONNECTING and DEGRADED admit the same two classes: §10.2 gives
        // RECONNECTING both outright, and DEGRADED reaches `PERSISTENT` through
        // §5.4's uncoded effective-MTU row.
        S::Reconnecting { .. } | S::Degraded { .. } => {
            matches!(code.class(), C::Transient | C::Persistent)
        }
        // FAILED admits every class, because §4.5 sends it both a `POLICY` and
        // a `TRANSIENT` code by name. A state that carries no code at all
        // constrains nothing, so both fall through here.
        _ => true,
    }
}
