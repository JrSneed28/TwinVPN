//! ADR-0012 §11.1's two tiers, and KS-3a's scope qualifier.
//!
//! **Authority:** ADR-0012 §11.1 (normative), KS-1, KS-2, KS-3, KS-3a, KS-4;
//! ADR-0010 §11.5.
//!
//! # Tier 2 references no prefix, ever
//!
//! §11.1: "Tier 2 is interface-scoped and default-deny, is expressed as one
//! object covering both families, and **MUST NOT** reference any destination
//! prefix."
//!
//! That is why [`Tier2`] carries an interface index and nothing else. A
//! prefix-shaped Tier 2 is the design ADR-0010 §11.5(2) rejects: "a newly
//! learned IPv6 prefix cannot escape by being unknown to an allow-list, because
//! there is no allow-list of prefixes."

use twinvpn_platform::InterfaceIndex;
use twinvpn_types::{AddressFamily, IpAddr, IpPrefix};

use twinvpn_route::RoutingMode;

/// KS-4's setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalNetworkAccess {
    /// On-link prefixes of non-overlay interfaces are permitted.
    ///
    /// The permitted set is "**on-link prefixes only**, recomputed on every
    /// network-change event, and never includes a destination reachable only via
    /// a router".
    Allow,
    /// The iOS/macOS `excludeLocalNetworks` inverse.
    Deny,
}

impl LocalNetworkAccess {
    /// KS-4's defaults: `ALLOW` in TwinNet-only and split-tunnel, and `ALLOW` in
    /// full tunnel with a one-toggle `DENY`.
    #[must_use]
    pub const fn default_for(_mode: RoutingMode) -> Self {
        LocalNetworkAccess::Allow
    }
}

/// Tier 1: **which packets are in the protected scope**.
///
/// Full tunnel is deliberately the **complement** form: §11.1 says it "MUST NOT
/// be expressed as an enumeration of protected prefixes", and the P07 mutant is
/// exactly "a build whose Tier 1 is prefix-enumerated rather than
/// complement-form in full-tunnel mode".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tier1 {
    /// Destination ∈ the TwinNet prefixes.
    TwinnetOnly {
        /// The overlay prefixes, both families.
        overlay: Vec<IpPrefix>,
    },
    /// The above ∪ every **accepted** `Route` prefix, both families.
    SplitTunnel {
        /// The overlay prefixes.
        overlay: Vec<IpPrefix>,
        /// Accepted route prefixes.
        accepted: Vec<IpPrefix>,
    },
    /// **Every** packet except §11.2's exempt classes.
    FullTunnelComplement,
    /// The platform's app set.
    PerApp,
}

impl Tier1 {
    /// Builds the Tier-1 scope for a routing mode.
    #[must_use]
    pub fn for_mode(mode: RoutingMode, overlay: Vec<IpPrefix>, accepted: Vec<IpPrefix>) -> Self {
        match mode {
            RoutingMode::TwinnetOnly => Tier1::TwinnetOnly { overlay },
            RoutingMode::SplitTunnel => Tier1::SplitTunnel { overlay, accepted },
            RoutingMode::FullTunnel => Tier1::FullTunnelComplement,
            RoutingMode::PerApp => Tier1::PerApp,
        }
    }

    /// Whether a destination is inside the protected scope.
    ///
    /// KS-3a's qualifier is why this can answer `false`: the §11.2 table is
    /// "exhaustive **over the Tier-1 protected set**, which is mode-dependent;
    /// traffic outside that set is not governed by this table and is not dropped
    /// by it". Without that, a TwinNet-only device in `BLOCKED` would lose all
    /// name resolution and therefore all Internet.
    #[must_use]
    pub fn contains(&self, destination: IpAddr) -> bool {
        match self {
            Tier1::TwinnetOnly { overlay } => overlay.iter().any(|p| p.contains(destination)),
            Tier1::SplitTunnel { overlay, accepted } => overlay
                .iter()
                .chain(accepted.iter())
                .any(|p| p.contains(destination)),
            // The complement form: everything is in scope, and §11.2's exempt
            // classes are what carve pieces out. Per-app is the platform's app
            // set, which a destination check cannot narrow either — so both
            // answer "in scope" and let §11.2 do the carving.
            Tier1::FullTunnelComplement | Tier1::PerApp => true,
        }
    }

    /// Whether this scope is expressed as an enumeration of prefixes.
    ///
    /// Asserted by the P07 mutant test: full tunnel must answer `false`.
    #[must_use]
    pub const fn is_prefix_enumerated(&self) -> bool {
        matches!(self, Tier1::TwinnetOnly { .. } | Tier1::SplitTunnel { .. })
    }
}

/// Tier 2: **where a protected packet may egress**.
///
/// One value covering both families, because ADR-0010 §11.5(1) makes it one
/// object: "**There is no code path that installs IPv4 protection without IPv6
/// protection**, because there is no separate IPv6 object to forget. This is a
/// structural guarantee, not a discipline."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tier2 {
    /// The **only** interface protected traffic may leave by.
    pub overlay_interface: InterfaceIndex,
}

impl Tier2 {
    /// Whether a protected packet on `egress` is permitted.
    ///
    /// Default deny, scoped by interface, with **no** destination in the
    /// question — which is what makes "IPv6 enabled after the tunnel is up"
    /// denied by the pre-existing rule with no rule update required for
    /// correctness.
    #[must_use]
    pub fn permits(self, egress: InterfaceIndex) -> bool {
        egress == self.overlay_interface
    }

    /// Both families are covered by construction; this exists so the property
    /// can be asserted rather than assumed (KS-5).
    #[must_use]
    pub const fn covers(self, _family: AddressFamily) -> bool {
        true
    }
}

/// KS-2: forwarded traffic is protected by the same Tier-2 rule and is **never**
/// eligible for any §11.2 exemption.
#[must_use]
pub const fn forwarded_traffic_is_exemptible() -> bool {
    false
}

/// KS-1: a Tier-1 scope change is applied **atomically with the contract
/// generation that caused it**.
///
/// > A scope may never be *narrowed* and a rule set *widened* in two steps; the
/// > transition is one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeTransaction {
    /// The generation this scope belongs to.
    pub generation: twinvpn_platform::ContractGeneration,
    /// The scope.
    pub tier1: Tier1,
    /// The egress rule.
    pub tier2: Tier2,
    /// KS-4's setting, and the on-link prefixes it permits.
    pub local_network_access: LocalNetworkAccess,
    /// The on-link prefixes of non-overlay interfaces, recomputed on every
    /// network-change event.
    pub on_link: Vec<IpPrefix>,
}
