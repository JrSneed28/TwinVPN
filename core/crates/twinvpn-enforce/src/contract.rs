//! Assembling the one `NetworkContract` the adapter installs atomically.
//!
//! **Authority:** ADR-0018 CB-6, `docs/networking.md` §2.3 ("partial application
//! is the leak window") and §5.1, ADR-0010 §11.3, ADR-0008 N-8,
//! `twinvpn_platform::NetworkContract`.
//!
//! # CB-6, in three clauses
//!
//! > The core computes the desired rule-set generation; the adapter installs it;
//! > the OS holds it. A core crash therefore cannot drop protection (C-7, S-18).
//!
//! This module is the first clause and only the first. It returns a
//! `NetworkContract` and calls nothing — there is no `install`, no `apply`, and
//! no adapter handle in this crate's public API.

use twinvpn_dns::policy::Dnspolicy;
use twinvpn_platform::{ContractGeneration, DnsConfig, NetworkContract, Ruleset};
use twinvpn_route::RoutePlan;
use twinvpn_types::{AddressFamily, IpAddr, PerFamily};

use crate::latch::ProtectedPreconditions;

/// Everything the contract is assembled from.
#[derive(Debug, Clone)]
pub struct ContractInputs<'a> {
    /// `twinvpn-route`'s output: addresses, routes, MTU, blocked families.
    pub route_plan: &'a RoutePlan,
    /// `twinvpn-dns`'s validated policy.
    pub dns_policy: &'a Dnspolicy,
    /// The stub's listening addresses, which the host is pointed at.
    pub stub_addresses: PerFamily<Vec<IpAddr>>,
    /// The ruleset the latch currently wants.
    pub ruleset: Ruleset,
    /// The underlay remote the tunnel is currently riding, where there is one.
    ///
    /// `None` in `RULESET_BLOCKED`: no path is validated in that posture, so
    /// there is no remote. `twinvpn_platform::NetworkContract` needs it because
    /// `NEPacketTunnelNetworkSettings` is constructed with
    /// `init(tunnelRemoteAddress:)` and requires one; carrying it here rather
    /// than letting the macOS shell supply it is what keeps the two sides from
    /// holding different answers.
    pub tunnel_remote_address: Option<IpAddr>,
}

/// Assembles one generation.
///
/// The four halves — addresses, routes, resolvers and ruleset — arrive as **one**
/// `NetworkContract` because §2.3 says partial application is the leak window,
/// and `apply()` is "all-or-nothing per contract generation".
///
/// # Errors
///
/// [`ContractError::FamilyAsymmetry`] when the route plan carries one family and
/// neither blocks the other — ADR-0010 §11.3 makes that non-conforming, and
/// KS-5 makes it non-conforming for the rule set too. There is no partial-install
/// success result to return instead.
pub fn assemble(
    inputs: &ContractInputs<'_>,
    generation: ContractGeneration,
) -> Result<NetworkContract, ContractError> {
    if inputs.route_plan.is_family_asymmetric() {
        return Err(ContractError::FamilyAsymmetry);
    }

    // The host is pointed at the stub, per family, and never at a bare upstream:
    // ADR-0011 §11.2's four listeners are what `resolvers` names.
    let resolvers = inputs.stub_addresses.clone();

    let split_domains = inputs
        .dns_policy
        .split_rules
        .iter()
        .map(|r| {
            r.labels
                .iter()
                .map(|l| String::from_utf8_lossy(l).into_owned())
                .collect::<Vec<_>>()
                .join(".")
        })
        .collect();

    let dns = DnsConfig {
        resolvers,
        search_domains: inputs.dns_policy.search_domains.clone(),
        split_domains,
        // FULL mode makes the overlay resolver the system default for
        // everything; SPLIT and OFF do not.
        is_default_resolver: inputs.dns_policy.mode == twinvpn_dns::Mode::Full,
    };

    Ok(NetworkContract {
        generation,
        addresses: inputs.route_plan.addresses.clone(),
        routes: inputs.route_plan.routes.clone(),
        dns,
        ruleset: inputs.ruleset,
        mtu: inputs.route_plan.mtu,
        tunnel_remote_address: inputs.tunnel_remote_address,
    })
}

/// §11.8's arm sequence, as an explicit order.
///
/// ```text
/// arm: RULESET_BLOCKED live -> create iface (DOWN) -> assign addresses
///      -> link up -> program routes -> path validated + assertion OK
///      -> atomic swap -> PROTECTED
/// ```
///
/// The interface is created **DOWN** because "an interface that comes up before
/// its addresses, routes and rules are installed is the partial-application leak
/// window".
///
/// **ADR-0012 KS-17a** is why the link comes up in the middle rather than after
/// the whole contract: the superseded sequence read `create iface (DOWN) ->
/// apply(contract_gen) -> link up`, and that is not implementable. An address
/// *can* be added to a down interface; a route **cannot** — `RTM_NEWROUTE`
/// answers `ENETDOWN` — which `desktop-linux` found against a kernel rather than
/// by reading. No guarantee moves: `RULESET_BLOCKED` is live across the whole
/// interval either way, and it is the *routes* that carry traffic, so nothing is
/// carried before the contract is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArmStep {
    /// `RULESET_BLOCKED` is live before anything else exists.
    BlockedLive,
    /// Create the interface, **down**.
    CreateInterfaceDown,
    /// Apply the whole contract generation.
    ApplyContract,
    /// Bring the link up.
    LinkUp,
    /// KS-18's two conditions.
    PathValidatedAndAsserted,
    /// The atomic swap to `RULESET_PROTECTED`.
    SwapToProtected,
}

impl ArmStep {
    /// The arm order.
    pub const SEQUENCE: [ArmStep; 6] = [
        ArmStep::BlockedLive,
        ArmStep::CreateInterfaceDown,
        ArmStep::ApplyContract,
        ArmStep::LinkUp,
        ArmStep::PathValidatedAndAsserted,
        ArmStep::SwapToProtected,
    ];
}

/// §11.8's teardown sequence.
///
/// ```text
/// teardown: link down -> atomic swap -> RULESET_BLOCKED -> destroy iface
///           (rules stay live while the latch is UP)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TeardownStep {
    /// Bring the link down.
    LinkDown,
    /// Swap to `RULESET_BLOCKED`. Never *remove* rules.
    SwapToBlocked,
    /// Only now, destroy the interface.
    DestroyInterface,
}

impl TeardownStep {
    /// The teardown order.
    pub const SEQUENCE: [TeardownStep; 3] = [
        TeardownStep::LinkDown,
        TeardownStep::SwapToBlocked,
        TeardownStep::DestroyInterface,
    ];
}

/// The decision T30 reads: may traffic be restored?
///
/// §11.9's T30 guard: "KS-18's two conditions both hold." Nothing else is
/// consulted — not the tunnel's opinion of itself, not a cached belief about the
/// rules.
#[must_use]
pub fn may_restore_traffic(pre: ProtectedPreconditions) -> bool {
    pre.satisfied()
}

/// Why a contract could not be assembled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ContractError {
    /// One family would be carried and the other neither carried nor blocked.
    #[error("the route plan is family-asymmetric; §11.3 and KS-5 make that non-conforming")]
    FamilyAsymmetry,
}

impl ContractError {
    /// The registered code.
    #[must_use]
    pub const fn reason_code(self) -> twinvpn_types::ReasonCode {
        match self {
            ContractError::FamilyAsymmetry => twinvpn_types::codes::POLICY_LEAK_IPV6_UNPROTECTED,
        }
    }

    /// The family that would have been left uncovered, when it is knowable.
    #[must_use]
    pub const fn uncovered_family(self, plan_carries_v4: bool) -> AddressFamily {
        if plan_carries_v4 {
            AddressFamily::V6
        } else {
            AddressFamily::V4
        }
    }
}
