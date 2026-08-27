//! The desired-route generation: what the adapter installs, computed whole
//! before anything is mutated.
//!
//! **Authority:** ADR-0010 §11.3 (normative, per platform), §11.5, §11.6, R5,
//! R6; `docs/networking.md` §7.1, §7.2; ADR-0008 N-8;
//! `contracts/proto/twinvpn/v1/routing.proto` `RoutePolicy`.
//!
//! # One transaction, both families
//!
//! ADR-0010 §11.3, verbatim and normative:
//!
//! > **On every platform, IPv4 and IPv6 routes MUST be installed in the same
//! > `apply()` transaction. An implementation that can install one family's
//! > routes without the other's is non-conforming.**
//!
//! [`RoutePlan`] therefore holds a `PerFamily<Vec<RouteEntry>>` — one value with
//! two non-optional halves — and there is no per-family builder, no
//! `install_v4`, and no way to hand the adapter half a plan.
//!
//! # The host's default route is never touched
//!
//! Full tunnel installs **two `/1` routes per family** (`networking.md` §7.2),
//! which win by longest-prefix match while the host's real default stays
//! installed. "Teardown is trivial and complete — delete four routes … No
//! 'restore the default route' logic that can fail after a crash."

use twinvpn_platform::{ContractGeneration, InterfaceIndex, RouteEntry};
use twinvpn_types::{AddressFamily, IpAddr, IpPrefix, OverlayAddresses, PerFamily, V4Addr, V6Addr};

use crate::conflict::{self, Candidate, Resolution, Source};
use crate::error::RouteError;

/// The four modes of `networking.md` §7.1.
///
/// `PerApp` is carried because refusing it must be a **named** configuration
/// error rather than a silent downgrade: "requesting it there is a configuration
/// error with `NET.PERAPP_UNSUPPORTED`, not a silent downgrade."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoutingMode {
    /// Only the overlay prefixes. The default.
    TwinnetOnly,
    /// Overlay prefixes plus explicitly accepted advertised routes.
    SplitTunnel,
    /// Default routes for **both** families, via a chosen `ExitNode`.
    FullTunnel,
    /// Platform-scoped per-application routing.
    PerApp,
}

/// The inputs a plan is computed from.
///
/// Every field is a *fact* supplied by the caller. Nothing here reads the OS,
/// which is what lets the whole computation be exercised against
/// `twinvpn-platform`'s mock (CB-2, CD-5).
#[derive(Debug, Clone)]
pub struct PlanInputs {
    /// The mode in force.
    pub mode: RoutingMode,
    /// This device's overlay addresses. Both, always (R1).
    pub overlay: OverlayAddresses,
    /// The TwinNet's own prefixes, per family.
    pub twinnet_prefixes: PerFamily<Vec<IpPrefix>>,
    /// Routes accepted from peers, already filtered by `AccessPolicy` and by the
    /// user's per-route decision (`networking.md` §7.3: advertised ≠ installed).
    pub accepted: Vec<Candidate>,
    /// Prefixes the host already has on-link, so P2 can be applied.
    pub on_link: Vec<IpPrefix>,
    /// Prefixes explicitly kept off the tunnel.
    pub excluded: Vec<IpPrefix>,
    /// The overlay interface.
    pub interface: InterfaceIndex,
    /// The selected `ExitNode`, if any. P6 reads it.
    pub selected_exit_node: Option<twinvpn_types::DeviceId>,
    /// The effective overlay MTU, from `crate::mtu`.
    pub mtu: u32,
    /// Whether the exit node granted a default route for each family.
    ///
    /// **Two independent booleans, never one flag** (`routing.proto`): "if a
    /// client requests full-tunnel egress and the exit node grants only one
    /// family, THE CLIENT MUST BLOCK THE UNGRANTED FAMILY rather than letting it
    /// egress locally."
    pub exit_grant: PerFamily<bool>,
}

/// The desired system state for one generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePlan {
    /// The generation this describes. Monotone, allocated by the core.
    pub generation: ContractGeneration,
    /// The overlay interface's addresses, both families (R1).
    pub addresses: PerFamily<Vec<IpPrefix>>,
    /// Routes to install, both families, in **one** transaction (§11.3).
    pub routes: PerFamily<Vec<RouteEntry>>,
    /// The overlay MTU.
    pub mtu: u32,
    /// Families whose traffic must be **blocked** rather than allowed out.
    ///
    /// §11.5(3): an IPv4-only tunnel on an IPv6-capable host blocks IPv6 — it
    /// does not permit it and does not globally disable it. §13.3: a one-family
    /// exit grant blocks the other family.
    pub blocked_families: PerFamily<bool>,
    /// Every conflict found, for P5's mandatory diagnostic.
    pub conflicts: Vec<conflict::Conflict>,
}

impl RoutePlan {
    /// Whether this plan carries routes for `family`.
    #[must_use]
    pub fn carries(&self, family: AddressFamily) -> bool {
        !self.routes.get(family).is_empty()
    }

    /// `ROUTE.FAMILY_ASYMMETRY`'s condition: one family got routes and the other
    /// did not, without the missing one being deliberately blocked.
    ///
    /// ADR-0010 §11.3 makes that state non-conforming, so this predicate exists
    /// to be asserted rather than to be handled.
    #[must_use]
    pub fn is_family_asymmetric(&self) -> bool {
        let v4 = self.carries(AddressFamily::V4) || *self.blocked_families.get(AddressFamily::V4);
        let v6 = self.carries(AddressFamily::V6) || *self.blocked_families.get(AddressFamily::V6);
        v4 != v6
    }
}

/// The two `/1` halves of a default route, per family (`networking.md` §7.2).
///
/// # Errors
///
/// [`RouteError::Address`] if the constants fail to build, which they cannot.
pub fn default_route_halves(family: AddressFamily) -> Result<[IpPrefix; 2], RouteError> {
    let prefixes = match family {
        AddressFamily::V4 => [
            IpPrefix::new(IpAddr::V4(V4Addr::from_octets([0, 0, 0, 0])), 1),
            IpPrefix::new(IpAddr::V4(V4Addr::from_octets([128, 0, 0, 0])), 1),
        ],
        AddressFamily::V6 => {
            let zero = V6Addr::new([0u8; 16], None).map_err(RouteError::Address)?;
            let mut high = [0u8; 16];
            high[0] = 0x80;
            let high = V6Addr::new(high, None).map_err(RouteError::Address)?;
            [
                IpPrefix::new(IpAddr::V6(zero), 1),
                IpPrefix::new(IpAddr::V6(high), 1),
            ]
        }
    };
    let mut out = Vec::with_capacity(2);
    for p in prefixes {
        out.push(p.map_err(RouteError::Address)?);
    }
    Ok([out[0], out[1]])
}

/// Computes the whole desired state, refusing rather than half-applying.
///
/// ADR-0008 N-8: "local OS-state application MUST be a reconciliation of a
/// **fully-computed** desired state, conflict-checked against pre-existing
/// system state **before** any mutation, all-or-nothing, with verified
/// read-back."
///
/// # Errors
///
/// - [`RouteError::PerAppUnsupported`] for [`RoutingMode::PerApp`], which this
///   core cannot express portably — a **named** refusal, never a downgrade.
/// - [`RouteError::ScopeViolation`] when a non-`ExitNode` advertised a default
///   route (P6).
/// - [`RouteError::DefaultSingleFamily`] when full tunnel is requested and
///   exactly one family is granted **and** the other is not blocked — the leak
///   `routing.proto` and `protocol.md` §13.3 forbid.
/// - [`RouteError::Address`] from a prefix constructor.
// One function because ADR-0008 N-8 requires the desired state to be computed
// WHOLE before any mutation; splitting it into stages that each return a
// partial plan is the shape that rule exists to forbid.
#[allow(clippy::too_many_lines)]
pub fn compute(inputs: &PlanInputs, generation: ContractGeneration) -> Result<RoutePlan, RouteError> {
    if inputs.mode == RoutingMode::PerApp {
        return Err(RouteError::PerAppUnsupported);
    }

    // P6, checked before anything else so a scope violation is never partially
    // honoured.
    for c in &inputs.accepted {
        if !conflict::default_route_permitted(*c, inputs.selected_exit_node) {
            return Err(RouteError::ScopeViolation {
                prefix: c.prefix,
                advertiser: c.source.device(),
            });
        }
    }

    let mut candidates: Vec<Candidate> = Vec::new();

    // The overlay's own prefixes are always routed, in every mode.
    for family in [AddressFamily::V4, AddressFamily::V6] {
        for p in inputs.twinnet_prefixes.get(family) {
            candidates.push(Candidate {
                prefix: *p,
                source: Source::Overlay,
                measured_score: 0,
                metric: 0,
            });
        }
    }

    // On-link physical prefixes participate so P2 can beat an advertised route,
    // but they are never installed by us — they are already there.
    let on_link: Vec<Candidate> = inputs
        .on_link
        .iter()
        .map(|p| Candidate {
            prefix: *p,
            source: Source::OnLinkPhysical,
            measured_score: 0,
            metric: 0,
        })
        .collect();

    match inputs.mode {
        RoutingMode::TwinnetOnly => {}
        RoutingMode::SplitTunnel => candidates.extend(inputs.accepted.iter().copied()),
        RoutingMode::FullTunnel => {
            candidates.extend(inputs.accepted.iter().copied());
            for family in [AddressFamily::V4, AddressFamily::V6] {
                if *inputs.exit_grant.get(family) {
                    for half in default_route_halves(family)? {
                        candidates.push(Candidate {
                            prefix: half,
                            source: inputs
                                .selected_exit_node
                                .map_or(Source::Overlay, Source::ExitNode),
                            measured_score: 0,
                            metric: 0,
                        });
                    }
                }
            }
        }
        RoutingMode::PerApp => unreachable!("refused above"),
    }

    // Excluded prefixes are removed AFTER the candidate set is assembled, by
    // longest-prefix match, per ADR-0010 P1.
    candidates.retain(|c| !inputs.excluded.contains(&c.prefix));

    let mut with_on_link = on_link;
    with_on_link.extend(candidates.iter().copied());
    let Resolution {
        installed,
        conflicts,
    } = conflict::resolve(&with_on_link);

    let mut routes = PerFamily::new(Vec::new(), Vec::new());
    let mut addresses = PerFamily::new(Vec::new(), Vec::new());

    // R1: both overlay addresses are present at all times, whatever the underlay
    // offers. `OverlayAddresses` has two non-optional fields, so this cannot
    // populate one half.
    addresses.get_mut(AddressFamily::V4).push(
        IpPrefix::new(IpAddr::V4(inputs.overlay.v4), 32).map_err(RouteError::Address)?,
    );
    addresses.get_mut(AddressFamily::V6).push(
        IpPrefix::new(IpAddr::V6(inputs.overlay.v6), 128).map_err(RouteError::Address)?,
    );

    for c in installed {
        // An on-link physical prefix is the host's, not ours: it participates in
        // precedence and is never installed by TwinVPN.
        if c.source == Source::OnLinkPhysical {
            continue;
        }
        let family = c.prefix.family();
        routes.get_mut(family).push(RouteEntry {
            destination: c.prefix,
            via: None,
            interface: inputs.interface,
            metric: Some(c.metric),
        });
    }

    // §11.5(3) and protocol.md §13.3: a family we do not carry must be BLOCKED,
    // never left to egress locally.
    let mut blocked = PerFamily::new(false, false);
    if inputs.mode == RoutingMode::FullTunnel {
        for family in [AddressFamily::V4, AddressFamily::V6] {
            if !*inputs.exit_grant.get(family) {
                *blocked.get_mut(family) = true;
            }
        }
        let granted_v4 = *inputs.exit_grant.get(AddressFamily::V4);
        let granted_v6 = *inputs.exit_grant.get(AddressFamily::V6);
        if granted_v4 != granted_v6
            && !(*blocked.get(AddressFamily::V4) || *blocked.get(AddressFamily::V6))
        {
            return Err(RouteError::DefaultSingleFamily {
                granted: if granted_v4 {
                    AddressFamily::V4
                } else {
                    AddressFamily::V6
                },
            });
        }
    }

    Ok(RoutePlan {
        generation,
        addresses,
        routes,
        mtu: inputs.mtu.max(crate::plan::MTU_FLOOR),
        blocked_families: blocked,
        conflicts,
    })
}
