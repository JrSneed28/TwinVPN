//! The route programme: what a contract generation asks the routing table for,
//! as data.
//!
//! **Authority:** ADR-0010 R1 (there is no "a v4 story and a v6 story"), R5
//! (installation is "fully reversible, including after an unclean process exit"),
//! §11.3's macOS row; `docs/networking.md` §5.1 and §7.2 (a default route
//! installed "without destroying the host's default route"), §2.3 ("partial
//! application is the leak window"); ADR-0008 (idempotent on the generation id).
//!
//! # Why the programme is a value and not a sequence of calls
//!
//! The whole point of this module is that "which routes does generation 7 want,
//! and what exactly undoes it" is answerable **without a kernel**. [`programme`]
//! turns a [`NetworkContract`] into a list of [`RouteOp`], [`inverse`] turns an
//! applied list into the list that undoes it, and both are pure — so the
//! transactional property ADR-0010 R5 requires is a checked property on this Linux
//! host rather than an operational one on a Mac.
//!
//! # Two carriers, one programme (CB-3)
//!
//! macOS programmes routes in two entirely different ways, and **neither is an OS
//! branch**: it is a declared capability of the injected carrier.
//!
//! | Carrier | How routes reach the kernel | Where it runs |
//! |---|---|---|
//! | [`RouteCarrier::Command`] | `route(8)` add/delete over the `PF_ROUTE` socket | the `LaunchDaemon` |
//! | [`RouteCarrier::TunnelSettings`] | `NEPacketTunnelNetworkSettings.includedRoutes` | the NE system extension |
//!
//! Under the second, [`programme`] still computes the same list — it is the input
//! to [`crate::nesettings`] — and the *applied* programme is empty, because the
//! OS installs the routes when it accepts the settings object. A carrier that
//! reported an applied route it did not install would make [`inverse`] try to
//! delete a route the OS owns.
//!
//! # Known gap: macOS `route(8)` has no metric
//!
//! [`twinvpn_platform::RouteEntry::metric`] is `Option<u32>` "where the platform
//! has one". macOS has none: `route(8)` takes no metric, and route preference is
//! decided by prefix length and by the network service order, neither of which is
//! a per-route value. A `Some(metric)` is therefore **dropped**, and
//! [`RouteOp::metric_unrepresentable`] says so per op so the shell can report it
//! rather than the core assuming a preference it did not get.

use twinvpn_platform::{InterfaceIndex, NetworkContract, RouteEntry};
use twinvpn_types::{AddressFamily, IpAddr, IpPrefix};

use crate::addr::{addr_text, prefix_text};

/// How routes reach the kernel on this binding.
///
/// A **capability fact**, declared at construction (CD-2) and never inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteCarrier {
    /// `route(8)` / the `PF_ROUTE` socket. The `LaunchDaemon` path.
    Command,
    /// `NEPacketTunnelNetworkSettings`. The system-extension path: the OS
    /// installs the routes, so the adapter installs none.
    TunnelSettings,
}

/// Add or delete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteAction {
    /// Install the route.
    Add,
    /// Remove it.
    Delete,
}

impl RouteAction {
    /// The `route(8)` verb.
    #[must_use]
    pub const fn verb(self) -> &'static str {
        match self {
            RouteAction::Add => "add",
            RouteAction::Delete => "delete",
        }
    }

    /// The action that undoes this one.
    #[must_use]
    pub const fn inverse(self) -> Self {
        match self {
            RouteAction::Add => RouteAction::Delete,
            RouteAction::Delete => RouteAction::Add,
        }
    }
}

/// One route operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteOp {
    /// Add or delete.
    pub action: RouteAction,
    /// The destination prefix, canonical.
    pub destination: IpPrefix,
    /// The next hop, or `None` for an on-link route through the interface.
    pub via: Option<IpAddr>,
    /// The OS index of the interface it points through.
    pub interface: InterfaceIndex,
    /// That interface's name, which is what `route(8)` takes.
    pub interface_name: String,
    /// Whether the contract asked for a metric this platform cannot express.
    ///
    /// Never a silent drop: the shell turns a `true` here into a log line, so
    /// "the core asked for a preference and macOS has nowhere to put it" is a
    /// readable fact rather than an inference.
    pub metric_unrepresentable: bool,
}

impl RouteOp {
    /// The address family this operation is in.
    #[must_use]
    pub fn family(&self) -> AddressFamily {
        self.destination.family()
    }

    /// The operation that undoes this one.
    #[must_use]
    pub fn inverse(&self) -> Self {
        Self {
            action: self.action.inverse(),
            ..self.clone()
        }
    }

    /// The `route(8)` argument vector, without the binary.
    ///
    /// `-n` because a route program must never perform a name lookup: the
    /// resolver may be the one we are about to reprogram, and a DNS query on the
    /// route path is a bring-up that depends on the thing it is bringing up.
    #[must_use]
    pub fn argv(&self) -> Vec<String> {
        let af = match self.family() {
            AddressFamily::V4 => "-inet",
            AddressFamily::V6 => "-inet6",
        };
        let mut argv = vec![
            "-n".to_owned(),
            self.action.verb().to_owned(),
            af.to_owned(),
            prefix_text(self.destination),
        ];
        if let Some(gateway) = self.via {
            argv.push(addr_text(gateway));
        } else {
            argv.push("-interface".to_owned());
            argv.push(self.interface_name.clone());
        }
        argv
    }
}

/// Everything one generation asks the routing table for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteProgramme {
    /// The operations, **v4 then v6, in contract order within each family**.
    ///
    /// Deterministic, because two renders of one contract must produce identical
    /// programmes or a reconciler comparing them would see drift that is not
    /// there.
    pub ops: Vec<RouteOp>,
}

impl RouteProgramme {
    /// Whether the programme does nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// How many operations it holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// How many operations it holds in `family`.
    #[must_use]
    pub fn count(&self, family: AddressFamily) -> usize {
        self.ops.iter().filter(|op| op.family() == family).count()
    }

    /// The programme that undoes this one, **in reverse order**.
    ///
    /// Reverse because a later route may depend on an earlier one having been
    /// installed, and unwinding forwards would delete the dependency first.
    /// ADR-0010 R5's reversibility is this function.
    #[must_use]
    pub fn inverse(&self) -> Self {
        Self {
            ops: self.ops.iter().rev().map(RouteOp::inverse).collect(),
        }
    }

    /// The prefix of this programme that was applied before `failed_at` failed.
    ///
    /// `docs/networking.md` §2.3: "partial application is the leak window". A
    /// failed apply unwinds **exactly** what it managed to install, and nothing
    /// else — deleting an op that never went in would remove a route belonging to
    /// the previous generation or to the host.
    #[must_use]
    pub fn applied_prefix(&self, failed_at: usize) -> Self {
        Self {
            ops: self.ops.iter().take(failed_at).cloned().collect(),
        }
    }
}

/// The programme for one generation.
///
/// Both families, in one pass over one struct: [`NetworkContract::routes`] is a
/// `PerFamily`, so there is no code path here that can emit the v4 half without
/// the v6 half.
#[must_use]
pub fn programme(
    contract: &NetworkContract,
    overlay_name: &str,
    carrier: RouteCarrier,
) -> RouteProgramme {
    if matches!(carrier, RouteCarrier::TunnelSettings) {
        // The OS installs them from the settings object. Reporting them as
        // applied would make `inverse` try to delete routes we do not own.
        return RouteProgramme::default();
    }
    let mut ops = Vec::with_capacity(contract.routes.v4.len() + contract.routes.v6.len());
    for entry in contract.routes.v4.iter().chain(contract.routes.v6.iter()) {
        ops.push(op_for(entry, overlay_name, RouteAction::Add));
    }
    RouteProgramme { ops }
}

fn op_for(entry: &RouteEntry, overlay_name: &str, action: RouteAction) -> RouteOp {
    RouteOp {
        action,
        destination: entry.destination,
        via: entry.via,
        interface: entry.interface,
        interface_name: overlay_name.to_owned(),
        metric_unrepresentable: entry.metric.is_some(),
    }
}

/// The four `/1` destinations `docs/networking.md` §7.2 uses for a full tunnel.
///
/// Two per family, so the tunnel wins on longest-prefix without the host's own
/// default route being touched — which is what "without destroying the host's
/// default route" means in practice, and why an implementation must never
/// `route delete default`.
///
/// Present so a test can name them; the **core** decides whether a contract is
/// full-tunnel, and this adapter only ever renders the routes it was handed
/// (CB-2).
#[must_use]
pub fn full_tunnel_destinations() -> Vec<IpPrefix> {
    let mut out = Vec::new();
    for octets in [[0u8, 0, 0, 0], [128, 0, 0, 0]] {
        if let Ok(p) = IpPrefix::new(IpAddr::V4(twinvpn_types::V4Addr::from_octets(octets)), 1) {
            out.push(p);
        }
    }
    for first in [0u8, 0x80] {
        let mut octets = [0u8; 16];
        octets[0] = first;
        if let Ok(address) = twinvpn_types::V6Addr::new(octets, None) {
            if let Ok(p) = IpPrefix::new(IpAddr::V6(address), 1) {
                out.push(p);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{contract, v4, v6};

    #[test]
    fn a_generation_programmes_both_families_and_never_one() {
        // ADR-0010 R1: a v4 story and a v6 story is the defect.
        let p = programme(&contract(1), "utun7", RouteCarrier::Command);
        assert_eq!(p.count(AddressFamily::V4), 1);
        assert_eq!(p.count(AddressFamily::V6), 1);
        assert!(p.ops.iter().all(|op| op.action == RouteAction::Add));
    }

    #[test]
    fn the_settings_carrier_applies_nothing_because_the_os_owns_the_routes() {
        let p = programme(&contract(1), "utun7", RouteCarrier::TunnelSettings);
        assert!(
            p.is_empty(),
            "reporting an OS-installed route as applied would make the inverse \
             delete a route we do not own"
        );
    }

    #[test]
    fn the_inverse_undoes_exactly_what_was_applied_in_reverse_order() {
        let p = programme(&contract(3), "utun7", RouteCarrier::Command);
        let undo = p.inverse();
        assert_eq!(undo.len(), p.len());
        assert!(undo.ops.iter().all(|op| op.action == RouteAction::Delete));
        // Reverse: a later route may depend on an earlier one.
        assert_eq!(undo.ops[0].destination, p.ops[p.len() - 1].destination);
        // And the inverse of the inverse is the original programme.
        assert_eq!(undo.inverse(), p);
    }

    #[test]
    fn a_failed_apply_unwinds_exactly_what_went_in_and_nothing_else() {
        // §2.3: partial application is the leak window. Deleting an op that never
        // went in would remove a route belonging to the previous generation.
        let p = programme(&contract(4), "utun7", RouteCarrier::Command);
        let partial = p.applied_prefix(1);
        assert_eq!(partial.len(), 1);
        assert_eq!(partial.ops[0], p.ops[0]);
        assert!(p.applied_prefix(0).is_empty());
        assert_eq!(p.applied_prefix(99), p, "a full apply unwinds fully");
    }

    #[test]
    fn the_route_argv_never_performs_a_name_lookup() {
        // The resolver may be the thing we are about to reprogram. `-n` is not a
        // nicety.
        let p = programme(&contract(1), "utun7", RouteCarrier::Command);
        for op in &p.ops {
            assert_eq!(op.argv()[0], "-n");
        }
    }

    #[test]
    fn an_on_link_route_names_the_interface_and_a_via_route_names_the_gateway() {
        let on_link = RouteOp {
            action: RouteAction::Add,
            destination: v4([100, 64, 0, 0], 10),
            via: None,
            interface: InterfaceIndex(9),
            interface_name: "utun7".to_owned(),
            metric_unrepresentable: false,
        };
        assert_eq!(
            on_link.argv(),
            vec!["-n", "add", "-inet", "100.64.0.0/10", "-interface", "utun7"]
        );

        let via = RouteOp {
            via: Some(IpAddr::V4(twinvpn_types::V4Addr::from_octets([
                100, 64, 0, 1,
            ]))),
            ..on_link
        };
        assert_eq!(
            via.argv(),
            vec!["-n", "add", "-inet", "100.64.0.0/10", "100.64.0.1"]
        );
    }

    #[test]
    fn a_v6_route_is_rendered_with_inet6_and_not_with_inet() {
        let op = RouteOp {
            action: RouteAction::Delete,
            destination: v6(0xfd, 0x7c, 48),
            via: None,
            interface: InterfaceIndex(9),
            interface_name: "utun7".to_owned(),
            metric_unrepresentable: false,
        };
        assert_eq!(
            op.argv(),
            vec!["-n", "delete", "-inet6", "fd7c::/48", "-interface", "utun7"]
        );
    }

    #[test]
    fn a_metric_the_platform_cannot_express_is_reported_and_not_silently_dropped() {
        let mut c = contract(1);
        c.routes.v4[0].metric = Some(4242);
        let p = programme(&c, "utun7", RouteCarrier::Command);
        assert!(p.ops[0].metric_unrepresentable);
        assert!(!p.ops[1].metric_unrepresentable);
        // And it does not leak into the argv as a flag `route(8)` does not have:
        // the command is byte-for-byte the one the metric-free contract produces.
        let without = programme(&contract(1), "utun7", RouteCarrier::Command);
        assert_eq!(p.ops[0].argv(), without.ops[0].argv());
    }

    #[test]
    fn the_full_tunnel_form_is_four_slash_one_routes_and_never_a_default_delete() {
        let d = full_tunnel_destinations();
        assert_eq!(d.len(), 4);
        assert!(d.iter().all(|p| p.prefix_len() == 1));
        assert_eq!(
            d.iter().filter(|p| p.family() == AddressFamily::V4).count(),
            2
        );
        assert_eq!(
            d.iter().filter(|p| p.family() == AddressFamily::V6).count(),
            2
        );
    }
}
