//! The route and address programme: a contract in, a transactional plan out.
//!
//! **Authority:** ADR-0010 R1 (both families, always), R5 (atomic per generation
//! and fully reversible, "including after an unclean process exit"), R6, R7,
//! §11.3 (the Windows row: `CreateIpForwardEntry2` plus an explicit interface
//! metric, and the `0.0.0.0/1` + `128.0.0.0/1` + `::/1` + `8000::/1` default-route
//! form), §11.6 (route precedence); `docs/networking.md` §7.2;
//! [`twinvpn_platform::NetworkConfig`].
//!
//! # One transaction, both families
//!
//! ADR-0010 §11.3 is normative: "On every platform, IPv4 and IPv6 routes MUST be
//! installed in the same `apply()` transaction. An implementation that can
//! install one family's routes without the other's is non-conforming."
//!
//! [`plan`] produces **one** [`RoutePlan`] holding both families' rows, and
//! [`RoutePlan::families_touched`] reports what it covers. There is no
//! per-family entry point and no partial-success result, so a v4-only apply is
//! not a thing this module can express.
//!
//! # R5: reversible, and reversible after a crash
//!
//! Rollback is not "undo the last thing you did". [`plan`] is a **diff from a
//! stated previous state to a desired one**, and [`RoutePlan::inverse`] is the
//! diff the other way — so the same machinery that applies generation *n* also
//! restores generation *n − 1*, and a process that died mid-apply recovers by
//! reading the rows the OS actually holds and diffing from those.
//!
//! # The host's own default route is never touched
//!
//! §11.3's Windows row: "Host's own default route is **never deleted or
//! modified**. The two-`/1`-per-family form wins by longest-prefix match while
//! leaving the host default intact; teardown is a pure deletion."
//!
//! The structural guarantee here is narrower and stronger than a review of the
//! prefixes: **every row this module emits carries the overlay LUID**, and
//! [`RoutePlan::validate`] refuses a plan containing a row that does not. A
//! route on another interface is not something this adapter can accidentally
//! delete, because it is not something this adapter can name.
//!
//! # This module is target-free
//!
//! [`RouteRow`] and [`AddressRow`] are the fields of `MIB_IPFORWARD_ROW2` and
//! `MIB_UNICASTIPADDRESS_ROW` that this adapter sets, as plain Rust. The
//! conversion into those structs, and the `CreateIpForwardEntry2` /
//! `DeleteIpForwardEntry2` / `CreateUnicastIpAddressEntry` calls, are
//! [`crate::sys`]'s and are the only part that needs Windows.

use twinvpn_platform::{NetworkContract, RouteEntry};
use twinvpn_types::{AddressFamily, IpAddr, IpPrefix, PerFamily};

/// The interface LUID a row is programmed on.
///
/// A LUID rather than an index: ADR-0016 O1 creates the adapter through Wintun,
/// whose name a user can change in Network Connections and whose index Windows
/// reassigns when an adapter is removed and re-added. `NET_LUID` is stable for
/// the life of the adapter and is what both IP Helper and WFP key on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InterfaceLuid(pub u64);

/// The origin `MIB_IPFORWARD_ROW2.Protocol` carries.
///
/// `NetMgmt` is `MIB_IPPROTO_NETMGMT` — "a route added by a network-management
/// application". It is the owner tag on this platform's routing state: a fresh
/// process after an unclean exit reclaims by `(luid, protocol)` rather than by
/// remembering what it installed, which is R5's "including after an unclean
/// process exit".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RouteProtocol {
    /// `MIB_IPPROTO_NETMGMT` (3).
    NetMgmt,
    /// Anything else — a row somebody else owns. Never emitted, only observed.
    Other(u32),
}

impl RouteProtocol {
    /// The numeric value.
    #[must_use]
    pub const fn number(self) -> u32 {
        match self {
            RouteProtocol::NetMgmt => 3,
            RouteProtocol::Other(n) => n,
        }
    }

    /// Whether a row with this origin is one of ours.
    #[must_use]
    pub const fn is_ours(self) -> bool {
        matches!(self, RouteProtocol::NetMgmt)
    }
}

/// One `MIB_IPFORWARD_ROW2`, reduced to the fields this adapter sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteRow {
    /// The interface. Always the overlay's, and [`RoutePlan::validate`] enforces
    /// it.
    pub luid: InterfaceLuid,
    /// `DestinationPrefix`.
    pub destination: IpPrefix,
    /// `NextHop`, or `None` for an on-link route.
    ///
    /// On the wire to IP Helper an on-link route is the unspecified address in
    /// `NextHop`, which is why this is an `Option` here and not a sentinel: a
    /// sentinel is a value somebody eventually compares against the wrong
    /// constant.
    pub next_hop: Option<IpAddr>,
    /// `Metric`.
    ///
    /// Windows composes the **effective** metric as the interface metric plus
    /// this one, so a route metric alone does not decide precedence. §11.3's
    /// Windows row therefore names "an explicit interface metric" as part of the
    /// mechanism, and [`AddressPlan::interface_metric`] carries it.
    pub metric: u32,
    /// `Protocol`. Always [`RouteProtocol::NetMgmt`] on a row we emit.
    pub protocol: RouteProtocol,
}

/// One `MIB_UNICASTIPADDRESS_ROW`, reduced the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AddressRow {
    /// The interface.
    pub luid: InterfaceLuid,
    /// The address and its on-link prefix length.
    ///
    /// # Why an `IpPrefix` is sufficient here, unlike in `InterfaceFacts`
    ///
    /// [`twinvpn_platform::InterfaceFacts::addresses`] documents a known defect:
    /// `IpPrefix` requires every host bit to be zero, so it cannot express an
    /// interface's own `192.0.2.10/24`. That defect does **not** reach this
    /// struct, because ADR-0010 §11.1 assigns each device a `/32` and a `/128` —
    /// prefixes whose host part is empty by construction. A contract carrying a
    /// shorter overlay prefix would be expressing something ADR-0010 does not
    /// allocate, and [`AddressPlan::validate`] names it rather than programming
    /// a network address as an interface address.
    pub address: IpPrefix,
    /// Whether Windows should treat the prefix as on-link and add the
    /// corresponding subnet route.
    ///
    /// Always `false` for the overlay: ADR-0010 R3 forbids DHCP/SLAAC on the
    /// overlay and the routes are programmed explicitly, so letting the stack
    /// synthesise one would put a route in the table that no generation owns and
    /// that rollback would therefore not remove.
    pub skip_as_source: bool,
}

/// The addresses and the interface metric for one generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressPlan {
    /// Addresses to add.
    pub adds: Vec<AddressRow>,
    /// Addresses to delete.
    pub deletes: Vec<AddressRow>,
    /// The interface metric to set, per family.
    ///
    /// §11.3's Windows row names it explicitly. `None` leaves the stack's
    /// automatic metric in place, which is what a rollback restores.
    pub interface_metric: PerFamily<Option<u32>>,
}

/// One transaction's worth of routing change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePlan {
    /// Routes to add.
    pub adds: Vec<RouteRow>,
    /// Routes to delete.
    pub deletes: Vec<RouteRow>,
    /// The address half.
    pub addresses: AddressPlan,
}

/// What a plan cannot legally contain.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanDefect {
    /// A row names an interface that is not the overlay.
    #[error("a row names interface {found:?}, not the overlay {overlay:?}")]
    ForeignInterface {
        /// What the row named.
        found: InterfaceLuid,
        /// The overlay.
        overlay: InterfaceLuid,
    },
    /// A row would delete something this adapter does not own.
    #[error("a delete names a row with protocol {0:?}, which is not ours")]
    ForeignRoute(RouteProtocol),
    /// An overlay address is not a host address.
    ///
    /// ADR-0010 §11.1 allocates a `/32` and a `/128`. A shorter prefix in
    /// `NetworkContract::addresses` would be programmed as an interface address
    /// whose host bits are zero — a network address, which answers nothing and
    /// reads as a NAT fault when offered as a candidate.
    #[error("the overlay address {0:?}/{1} is not a host address")]
    OverlayAddressIsNotAHost(IpAddr, u32),
}

impl RoutePlan {
    /// An empty plan.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            adds: Vec::new(),
            deletes: Vec::new(),
            addresses: AddressPlan {
                adds: Vec::new(),
                deletes: Vec::new(),
                interface_metric: PerFamily::new(None, None),
            },
        }
    }

    /// Whether the plan changes nothing.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.adds.is_empty()
            && self.deletes.is_empty()
            && self.addresses.adds.is_empty()
            && self.addresses.deletes.is_empty()
    }

    /// Which families this plan touches.
    ///
    /// Reported so a caller can assert R1 over a *plan* rather than over the
    /// contract it came from: a contract with both families whose plan touches
    /// one is exactly the non-conforming case §11.3 names.
    #[must_use]
    pub fn families_touched(&self) -> PerFamily<bool> {
        let touched = |family: AddressFamily| {
            self.adds
                .iter()
                .chain(&self.deletes)
                .any(|r| r.destination.family() == family)
                || self
                    .addresses
                    .adds
                    .iter()
                    .chain(&self.addresses.deletes)
                    .any(|a| a.address.family() == family)
        };
        PerFamily::new(touched(AddressFamily::V4), touched(AddressFamily::V6))
    }

    /// The plan that undoes this one.
    ///
    /// Adds become deletes and deletes become adds. The interface metric is
    /// **not** inverted here, because a metric has no inverse: restoring it
    /// needs the previous value, which [`plan`] takes as an input and
    /// [`invert_with_metric`] threads through.
    #[must_use]
    pub fn inverse(&self) -> Self {
        Self {
            adds: self.deletes.clone(),
            deletes: self.adds.clone(),
            addresses: AddressPlan {
                adds: self.addresses.deletes.clone(),
                deletes: self.addresses.adds.clone(),
                interface_metric: PerFamily::new(None, None),
            },
        }
    }

    /// Refuses a plan that could touch something outside the overlay.
    pub fn validate(&self, overlay: InterfaceLuid) -> Result<(), PlanDefect> {
        for row in self.adds.iter().chain(&self.deletes) {
            if row.luid != overlay {
                return Err(PlanDefect::ForeignInterface {
                    found: row.luid,
                    overlay,
                });
            }
        }
        for row in &self.deletes {
            if !row.protocol.is_ours() {
                return Err(PlanDefect::ForeignRoute(row.protocol));
            }
        }
        for row in self.addresses.adds.iter().chain(&self.addresses.deletes) {
            if row.luid != overlay {
                return Err(PlanDefect::ForeignInterface {
                    found: row.luid,
                    overlay,
                });
            }
            let full = row.address.family().max_prefix_len();
            if row.address.prefix_len() != full {
                return Err(PlanDefect::OverlayAddressIsNotAHost(
                    row.address.address(),
                    row.address.prefix_len(),
                ));
            }
        }
        Ok(())
    }
}

/// The routing state a generation left behind.
///
/// Read back from the OS rather than remembered, which is what makes rollback
/// work after an unclean exit (R5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledRoutes {
    /// The rows the OS reports on the overlay interface, ours and not.
    pub rows: Vec<RouteRow>,
    /// The addresses the OS reports on it.
    pub addresses: Vec<AddressRow>,
    /// The interface metric currently in force, per family.
    pub interface_metric: PerFamily<Option<u32>>,
}

impl Default for InstalledRoutes {
    /// A host with nothing of ours on it.
    ///
    /// Hand-written because `PerFamily` has no `Default`, which is deliberate on
    /// its part: a family-keyed pair with a default is one a caller can forget to
    /// fill in for one family, and that is ADR-0010 R1's whole subject.
    fn default() -> Self {
        Self {
            rows: Vec::new(),
            addresses: Vec::new(),
            interface_metric: PerFamily::new(None, None),
        }
    }
}

impl InstalledRoutes {
    /// Only the rows this adapter owns.
    #[must_use]
    pub fn ours(&self) -> Vec<RouteRow> {
        let mut rows: Vec<RouteRow> = self
            .rows
            .iter()
            .copied()
            .filter(|r| r.protocol.is_ours())
            .collect();
        rows.sort_unstable();
        rows
    }
}

/// The metric a route with no stated metric gets.
///
/// **A decision recorded as one.** No value is pinned in the corpus.
/// `MIB_IPFORWARD_ROW2.Metric` composes with the interface metric, and Windows'
/// automatic interface metrics for physical adapters start at 5 and rise with
/// slower media; a route metric of `0` on the overlay therefore lets the
/// interface metric alone decide, which is what §11.3's "explicit interface
/// metric" mechanism wants. A non-zero default here would silently add to every
/// comparison the interface metric was supposed to settle.
pub const DEFAULT_ROUTE_METRIC: u32 = 0;

/// The overlay's interface metric.
///
/// **A decision recorded as one**, for the same reason. `1` is below every
/// automatic metric Windows assigns a physical adapter, so the four `/1` routes
/// win the longest-prefix comparison against a host default route without the
/// host default being touched — §11.3's Windows row, expressed as the one number
/// that makes it true.
pub const OVERLAY_INTERFACE_METRIC: u32 = 1;

/// Computes the transaction that moves the host from `previous` to `contract`.
///
/// A diff, not a script: applying the result to a host already in the desired
/// state produces an empty plan, which is `apply`'s idempotence-on-the-generation
/// (ADR-0008) obtained structurally rather than by remembering which generation
/// was last applied.
#[must_use]
pub fn plan(
    previous: &InstalledRoutes,
    contract: &NetworkContract,
    overlay: InterfaceLuid,
) -> RoutePlan {
    let desired_routes = desired_rows(contract, overlay);
    let existing = previous.ours();

    let adds = desired_routes
        .iter()
        .copied()
        .filter(|row| !existing.iter().any(|e| same_route(e, row)))
        .collect();
    let deletes = existing
        .iter()
        .copied()
        .filter(|row| !desired_routes.iter().any(|d| same_route(d, row)))
        .collect();

    let desired_addresses = desired_address_rows(contract, overlay);
    let existing_addresses = {
        let mut a: Vec<AddressRow> = previous
            .addresses
            .iter()
            .copied()
            .filter(|a| a.luid == overlay)
            .collect();
        a.sort_unstable();
        a
    };
    let address_adds = desired_addresses
        .iter()
        .copied()
        .filter(|row| !existing_addresses.iter().any(|e| e.address == row.address))
        .collect();
    let address_deletes = existing_addresses
        .iter()
        .copied()
        .filter(|row| !desired_addresses.iter().any(|d| d.address == row.address))
        .collect();

    RoutePlan {
        adds,
        deletes,
        addresses: AddressPlan {
            adds: address_adds,
            deletes: address_deletes,
            interface_metric: PerFamily::new(
                Some(OVERLAY_INTERFACE_METRIC),
                Some(OVERLAY_INTERFACE_METRIC),
            ),
        },
    }
}

/// The inverse of `plan`, with the interface metric restored to what `previous`
/// held.
///
/// Separate from [`RoutePlan::inverse`] because a metric's inverse is not a
/// property of the plan: it is a property of the state the plan started from,
/// and PS-6's "restore before mutate" is what makes that state available.
#[must_use]
pub fn invert_with_metric(forward: &RoutePlan, previous: &InstalledRoutes) -> RoutePlan {
    let mut inverse = forward.inverse();
    inverse.addresses.interface_metric = previous.interface_metric;
    inverse
}

/// The transaction that moves the host from what it holds **now** to a stated
/// earlier state.
///
/// This is what rollback actually needs, and it is not the same as inverting the
/// forward plan. Inverting assumes the host is still exactly where the forward
/// plan left it — true in the happy case and **false** after a crash, after a
/// third-party tool has touched the table, or after two generations have been
/// applied. R5 requires reversibility "including after an unclean process exit",
/// and the only state a fresh process can trust is the one it read back.
///
/// The interface metric comes from `desired`, because a metric is a value rather
/// than a difference and there is nothing to diff.
#[must_use]
pub fn plan_to_state(
    now: &InstalledRoutes,
    desired: &InstalledRoutes,
    overlay: InterfaceLuid,
) -> RoutePlan {
    let existing = now.ours();
    let target = desired.ours();
    let adds = target
        .iter()
        .copied()
        .filter(|row| !existing.iter().any(|e| same_route(e, row)))
        .collect();
    let deletes = existing
        .iter()
        .copied()
        .filter(|row| !target.iter().any(|d| same_route(d, row)))
        .collect();

    let mine = |rows: &[AddressRow]| {
        let mut a: Vec<AddressRow> = rows.iter().copied().filter(|a| a.luid == overlay).collect();
        a.sort_unstable();
        a
    };
    let existing_addresses = mine(&now.addresses);
    let target_addresses = mine(&desired.addresses);

    RoutePlan {
        adds,
        deletes,
        addresses: AddressPlan {
            adds: target_addresses
                .iter()
                .copied()
                .filter(|row| !existing_addresses.iter().any(|e| e.address == row.address))
                .collect(),
            deletes: existing_addresses
                .iter()
                .copied()
                .filter(|row| !target_addresses.iter().any(|d| d.address == row.address))
                .collect(),
            interface_metric: desired.interface_metric,
        },
    }
}

/// The rows a contract implies, both families, sorted.
#[must_use]
pub fn desired_rows(contract: &NetworkContract, overlay: InterfaceLuid) -> Vec<RouteRow> {
    let mut rows = Vec::new();
    // ADR-0010 R1 and §11.3: one loop over both families, so there is no place
    // to emit one family's routes without the other's.
    for family in [AddressFamily::V4, AddressFamily::V6] {
        for entry in contract.routes.get(family) {
            rows.push(row_for(entry, overlay));
        }
    }
    rows.sort_unstable();
    rows.dedup();
    rows
}

/// The address rows a contract implies.
#[must_use]
pub fn desired_address_rows(contract: &NetworkContract, overlay: InterfaceLuid) -> Vec<AddressRow> {
    let mut rows = Vec::new();
    for family in [AddressFamily::V4, AddressFamily::V6] {
        for prefix in contract.addresses.get(family) {
            rows.push(AddressRow {
                luid: overlay,
                address: *prefix,
                skip_as_source: false,
            });
        }
    }
    rows.sort_unstable();
    rows.dedup();
    rows
}

fn row_for(entry: &RouteEntry, overlay: InterfaceLuid) -> RouteRow {
    RouteRow {
        luid: overlay,
        destination: entry.destination,
        next_hop: entry.via,
        metric: entry.metric.unwrap_or(DEFAULT_ROUTE_METRIC),
        protocol: RouteProtocol::NetMgmt,
    }
}

/// Whether two rows are the same route.
///
/// Identity is `(luid, destination, next_hop)` — **not** the metric. IP Helper
/// keys a forward entry on exactly those three, so two rows differing only in
/// metric are one route whose metric changed, and treating them as two would
/// make every metric change a delete-and-add: a window in which the route is
/// absent, which on a default route is a leak.
fn same_route(a: &RouteRow, b: &RouteRow) -> bool {
    a.luid == b.luid && a.destination == b.destination && a.next_hop == b.next_hop
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_platform::{ContractGeneration, DnsConfig, InterfaceIndex, RouteEntry};
    use twinvpn_types::{V4Addr, V6Addr};

    const OVERLAY: InterfaceLuid = InterfaceLuid(0x0001_0000_0000_0006);

    fn v4(octets: [u8; 4], len: u32) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(V4Addr::from_octets(octets)), len).expect("prefix")
    }

    fn v6(first: u8, second: u8, len: u32) -> IpPrefix {
        let mut octets = [0u8; 16];
        octets[0] = first;
        octets[1] = second;
        IpPrefix::new(IpAddr::V6(V6Addr::prefix_base(octets).expect("base")), len).expect("prefix")
    }

    fn host_v4(octets: [u8; 4]) -> IpPrefix {
        v4(octets, 32)
    }

    fn host_v6(tail: u8) -> IpPrefix {
        let mut octets = [0u8; 16];
        octets[0] = 0xfd;
        octets[1] = 0x7c;
        octets[15] = tail;
        IpPrefix::new(IpAddr::V6(V6Addr::new(octets, None).expect("address")), 128).expect("prefix")
    }

    fn entry(destination: IpPrefix, metric: Option<u32>) -> RouteEntry {
        RouteEntry {
            destination,
            via: None,
            interface: InterfaceIndex(6),
            metric,
        }
    }

    fn contract(
        routes: PerFamily<Vec<RouteEntry>>,
        addresses: PerFamily<Vec<IpPrefix>>,
    ) -> NetworkContract {
        NetworkContract {
            generation: ContractGeneration(3),
            addresses,
            routes,
            dns: DnsConfig {
                resolvers: PerFamily::new(Vec::new(), Vec::new()),
                search_domains: Vec::new(),
                split_domains: Vec::new(),
                is_default_resolver: false,
            },
            ruleset: twinvpn_platform::Ruleset::Protected,
            mtu: 1420,
        }
    }

    /// §11.3's Windows default-route form, both families.
    fn full_tunnel() -> NetworkContract {
        contract(
            PerFamily::new(
                vec![
                    entry(v4([0, 0, 0, 0], 1), None),
                    entry(v4([128, 0, 0, 0], 1), None),
                ],
                vec![
                    entry(v6(0x00, 0x00, 1), None),
                    entry(v6(0x80, 0x00, 1), None),
                ],
            ),
            PerFamily::new(vec![host_v4([100, 64, 0, 5])], vec![host_v6(5)]),
        )
    }

    #[test]
    fn the_default_route_form_is_four_ones_and_never_a_zero_length_prefix() {
        // §11.3's Windows row: the host's own default route is never deleted or
        // modified, and the two-`/1`-per-family form is what wins by
        // longest-prefix match while leaving it intact.
        let plan = plan(&InstalledRoutes::default(), &full_tunnel(), OVERLAY);
        assert_eq!(plan.adds.len(), 4);
        for row in &plan.adds {
            assert_eq!(row.destination.prefix_len(), 1);
            assert_ne!(row.destination.prefix_len(), 0, "never a bare default");
        }
        let families = plan.families_touched();
        assert!(families.get(AddressFamily::V4));
        assert!(families.get(AddressFamily::V6));
    }

    #[test]
    fn r1_a_plan_from_a_dual_family_contract_touches_both_families() {
        let plan = plan(&InstalledRoutes::default(), &full_tunnel(), OVERLAY);
        let families = plan.families_touched();
        assert!(
            *families.get(AddressFamily::V4) && *families.get(AddressFamily::V6),
            "installing one family without the other is non-conforming"
        );
    }

    #[test]
    fn re_applying_a_generation_already_in_force_changes_nothing() {
        // ADR-0008 idempotence, obtained structurally: the plan is a diff, so a
        // host already in the desired state produces an empty one.
        let contract = full_tunnel();
        let first = plan(&InstalledRoutes::default(), &contract, OVERLAY);
        let installed = InstalledRoutes {
            rows: first.adds.clone(),
            addresses: first.addresses.adds.clone(),
            interface_metric: PerFamily::new(Some(1), Some(1)),
        };
        let second = plan(&installed, &contract, OVERLAY);
        assert!(second.is_noop(), "{second:?}");
    }

    #[test]
    fn rollback_restores_exactly_what_was_there_including_the_metric() {
        // R5: "fully reversible, including after an unclean process exit".
        let before = InstalledRoutes {
            rows: vec![RouteRow {
                luid: OVERLAY,
                destination: v4([10, 0, 0, 0], 8),
                next_hop: None,
                metric: 0,
                protocol: RouteProtocol::NetMgmt,
            }],
            addresses: vec![AddressRow {
                luid: OVERLAY,
                address: host_v4([100, 64, 0, 5]),
                skip_as_source: false,
            }],
            interface_metric: PerFamily::new(Some(25), Some(30)),
        };
        let forward = plan(&before, &full_tunnel(), OVERLAY);
        let back = invert_with_metric(&forward, &before);

        // Everything the forward plan added, the inverse deletes.
        assert_eq!(back.deletes, forward.adds);
        assert_eq!(back.adds, forward.deletes);
        assert_eq!(back.addresses.adds, forward.addresses.deletes);
        // ...and the metric goes back to the value the host actually had, which
        // no amount of inverting the plan alone could recover.
        assert_eq!(
            *back.addresses.interface_metric.get(AddressFamily::V4),
            Some(25)
        );
        assert_eq!(
            *back.addresses.interface_metric.get(AddressFamily::V6),
            Some(30)
        );
    }

    #[test]
    fn applying_the_inverse_returns_the_host_to_the_previous_state() {
        // The property rollback actually has to have, checked by simulating the
        // application rather than by comparing plans.
        let before = InstalledRoutes {
            rows: vec![RouteRow {
                luid: OVERLAY,
                destination: v4([10, 0, 0, 0], 8),
                next_hop: None,
                metric: 0,
                protocol: RouteProtocol::NetMgmt,
            }],
            addresses: Vec::new(),
            interface_metric: PerFamily::new(None, None),
        };
        let forward = plan(&before, &full_tunnel(), OVERLAY);

        let mut rows = before.ours();
        rows.retain(|r| !forward.deletes.iter().any(|d| same_route(d, r)));
        rows.extend(forward.adds.iter().copied());
        rows.sort_unstable();

        let after_forward = InstalledRoutes {
            rows: rows.clone(),
            addresses: forward.addresses.adds.clone(),
            interface_metric: PerFamily::new(Some(1), Some(1)),
        };
        let back = invert_with_metric(&forward, &before);
        let mut restored = after_forward.ours();
        restored.retain(|r| !back.deletes.iter().any(|d| same_route(d, r)));
        restored.extend(back.adds.iter().copied());
        restored.sort_unstable();

        assert_eq!(restored, before.ours());
    }

    #[test]
    fn a_rollback_diffs_from_what_the_os_holds_now_and_not_from_the_forward_plan() {
        // R5: reversible "including after an unclean process exit". Inverting
        // the forward plan assumes the host is still where that plan left it;
        // after a crash, or after a third-party tool has touched the table, it
        // is not.
        let before = InstalledRoutes {
            rows: vec![RouteRow {
                luid: OVERLAY,
                destination: v4([10, 0, 0, 0], 8),
                next_hop: None,
                metric: 0,
                protocol: RouteProtocol::NetMgmt,
            }],
            addresses: Vec::new(),
            interface_metric: PerFamily::new(Some(25), Some(30)),
        };

        // What the host actually holds now: neither the previous state nor what
        // the forward plan would have produced. One of our routes is gone (a
        // cleanup tool), and one nobody planned has appeared (a crashed retry).
        let now = InstalledRoutes {
            rows: vec![
                RouteRow {
                    luid: OVERLAY,
                    destination: v4([0, 0, 0, 0], 1),
                    next_hop: None,
                    metric: 0,
                    protocol: RouteProtocol::NetMgmt,
                },
                RouteRow {
                    luid: OVERLAY,
                    destination: v4([192, 0, 2, 0], 24),
                    next_hop: None,
                    metric: 0,
                    protocol: RouteProtocol::NetMgmt,
                },
            ],
            addresses: Vec::new(),
            interface_metric: PerFamily::new(Some(1), Some(1)),
        };

        let back = plan_to_state(&now, &before, OVERLAY);
        back.validate(OVERLAY).expect("valid");

        // Apply it and the host is exactly `before` — including the route the
        // forward plan never knew about.
        let mut rows = now.ours();
        rows.retain(|r| !back.deletes.iter().any(|d| same_route(d, r)));
        rows.extend(back.adds.iter().copied());
        rows.sort_unstable();
        assert_eq!(rows, before.ours());
        assert_eq!(
            *back.addresses.interface_metric.get(AddressFamily::V4),
            Some(25)
        );
    }

    #[test]
    fn a_rollback_never_touches_a_row_somebody_else_owns() {
        let foreign = RouteRow {
            luid: OVERLAY,
            destination: v4([172, 16, 0, 0], 12),
            next_hop: None,
            metric: 0,
            protocol: RouteProtocol::Other(2),
        };
        let now = InstalledRoutes {
            rows: vec![foreign],
            ..InstalledRoutes::default()
        };
        let back = plan_to_state(&now, &InstalledRoutes::default(), OVERLAY);
        assert!(back.is_noop(), "{back:?}");
        back.validate(OVERLAY).expect("valid");
    }

    #[test]
    fn rolling_back_to_the_state_the_host_is_already_in_changes_nothing() {
        let now = InstalledRoutes {
            rows: vec![RouteRow {
                luid: OVERLAY,
                destination: v4([10, 0, 0, 0], 8),
                next_hop: None,
                metric: 0,
                protocol: RouteProtocol::NetMgmt,
            }],
            addresses: Vec::new(),
            interface_metric: PerFamily::new(Some(1), Some(1)),
        };
        assert!(plan_to_state(&now, &now, OVERLAY).is_noop());
    }

    #[test]
    fn a_metric_change_is_not_a_delete_and_add() {
        // IP Helper keys a forward entry on (luid, destination, next hop). If a
        // metric change were treated as a different route, the default route
        // would be absent for the width of the transaction — which is a leak.
        let contract = contract(
            PerFamily::new(vec![entry(v4([10, 0, 0, 0], 8), Some(7))], Vec::new()),
            PerFamily::new(Vec::new(), Vec::new()),
        );
        let installed = InstalledRoutes {
            rows: vec![RouteRow {
                luid: OVERLAY,
                destination: v4([10, 0, 0, 0], 8),
                next_hop: None,
                metric: 3,
                protocol: RouteProtocol::NetMgmt,
            }],
            ..InstalledRoutes::default()
        };
        let plan = plan(&installed, &contract, OVERLAY);
        assert!(plan.adds.is_empty(), "the route already exists");
        assert!(plan.deletes.is_empty(), "and must not be removed");
    }

    #[test]
    fn rows_the_adapter_does_not_own_are_never_deleted() {
        // R7 and §11.3: the host's own routing is surfaced, never silently
        // resolved by overwriting.
        let installed = InstalledRoutes {
            rows: vec![RouteRow {
                luid: OVERLAY,
                destination: v4([172, 16, 0, 0], 12),
                next_hop: None,
                metric: 0,
                protocol: RouteProtocol::Other(2),
            }],
            ..InstalledRoutes::default()
        };
        let plan = plan(&installed, &full_tunnel(), OVERLAY);
        assert!(
            plan.deletes.is_empty(),
            "a row somebody else owns is not ours to remove"
        );
    }

    #[test]
    fn a_plan_naming_another_interface_is_refused_rather_than_applied() {
        let mut plan = plan(&InstalledRoutes::default(), &full_tunnel(), OVERLAY);
        plan.adds[0].luid = InterfaceLuid(99);
        assert!(matches!(
            plan.validate(OVERLAY).expect_err("refused"),
            PlanDefect::ForeignInterface { .. }
        ));
    }

    #[test]
    fn a_delete_of_a_foreign_row_is_refused_rather_than_applied() {
        let mut plan = RoutePlan::empty();
        plan.deletes.push(RouteRow {
            luid: OVERLAY,
            destination: v4([0, 0, 0, 0], 1),
            next_hop: None,
            metric: 0,
            protocol: RouteProtocol::Other(3_u32.wrapping_add(1)),
        });
        assert!(matches!(
            plan.validate(OVERLAY).expect_err("refused"),
            PlanDefect::ForeignRoute(_)
        ));
    }

    #[test]
    fn an_overlay_address_that_is_not_a_host_address_is_named_rather_than_programmed() {
        // ADR-0010 §11.1 allocates a /32 and a /128. Programming a shorter
        // prefix would put a network address on the interface, which answers
        // nothing and reads as a NAT fault when offered as a candidate.
        let contract = contract(
            PerFamily::new(Vec::new(), Vec::new()),
            PerFamily::new(vec![v4([100, 64, 0, 0], 24)], Vec::new()),
        );
        let plan = plan(&InstalledRoutes::default(), &contract, OVERLAY);
        assert!(matches!(
            plan.validate(OVERLAY).expect_err("refused"),
            PlanDefect::OverlayAddressIsNotAHost(_, 24)
        ));
    }

    #[test]
    fn a_valid_plan_passes_validation_in_both_directions() {
        let forward = plan(&InstalledRoutes::default(), &full_tunnel(), OVERLAY);
        forward.validate(OVERLAY).expect("forward");
        forward.inverse().validate(OVERLAY).expect("inverse");
    }

    #[test]
    fn the_plan_is_deterministic_whatever_order_the_contract_lists_routes_in() {
        let mut shuffled = full_tunnel();
        shuffled.routes.get_mut(AddressFamily::V4).reverse();
        let a = plan(&InstalledRoutes::default(), &full_tunnel(), OVERLAY);
        let b = plan(&InstalledRoutes::default(), &shuffled, OVERLAY);
        assert_eq!(a, b);
    }

    #[test]
    fn an_on_link_route_is_an_absent_next_hop_and_never_a_sentinel() {
        let contract = contract(
            PerFamily::new(vec![entry(v4([10, 0, 0, 0], 8), None)], Vec::new()),
            PerFamily::new(Vec::new(), Vec::new()),
        );
        let plan = plan(&InstalledRoutes::default(), &contract, OVERLAY);
        assert_eq!(plan.adds[0].next_hop, None);
    }

    #[test]
    fn every_emitted_row_carries_the_owner_tag() {
        // KS-20's Windows equivalent for routing state: a fresh process
        // reclaims by (luid, protocol) rather than by remembering.
        let plan = plan(&InstalledRoutes::default(), &full_tunnel(), OVERLAY);
        for row in &plan.adds {
            assert_eq!(row.protocol, RouteProtocol::NetMgmt);
            assert!(row.protocol.is_ours());
        }
        assert_eq!(RouteProtocol::NetMgmt.number(), 3);
        assert!(!RouteProtocol::Other(1).is_ours());
    }
}
