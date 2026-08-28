//! The renderer: a [`NetworkContract`] and a [`Ruleset`] in, one [`FilterSet`]
//! out.
//!
//! **Authority:** ADR-0012 §11.1 (Tier 1 selects, Tier 2 enforces), §11.2 (the
//! traffic-class table), §11.5 (KS-9…KS-12), §11.8 KS-17; ADR-0010 §11.5 clause
//! 1; ADR-0011 §11.9 (SMHNR); ADR-0018 CB-2.
//!
//! # A pure function
//!
//! No I/O, no clock, no ambient state — so the *contents* of the ruleset are a
//! unit-tested property on a host with no `fwpuclnt.dll` at all, which is the
//! whole point of keeping the layer that decides what to install separate from
//! the layer that installs it.
//!
//! # CB-2: nothing here is a decision
//!
//! The Tier-1 protected scope is taken **verbatim from the contract's route
//! destinations**. That is not this adapter choosing a scope: `twinvpn-route`
//! computes which destinations go through the overlay, and ADR-0012 §11.1's
//! three routing modes are already expressed in that set — full tunnel arrives
//! as the four `/1` routes of `docs/networking.md` §7.2, which *is* §11.1's
//! required complement form rather than an enumeration of protected prefixes.
//! This function translates; it does not decide.
//!
//! # The two postures differ by exactly one filter
//!
//! `RULESET_BLOCKED` and `RULESET_PROTECTED` are rendered from the same inputs
//! and differ in **one** object: the Tier-2 overlay permit
//! ([`TrafficClass::OverlayEgress`]). That is KS-17's atomic swap made as small
//! as it can be — the transaction that swaps postures adds or removes a single
//! filter and rewrites one marker, and every exemption, every deny and the whole
//! Tier-1 scope stay exactly where they were. A swap that re-rendered thirty
//! objects would be atomic on paper and a much larger thing to get wrong.
//!
//! # KS-9(2) on Windows: a residual, named
//!
//! KS-9(2) requires the bootstrap exemption to be scoped to a socket
//! **registered with the enforcement layer at bind time**. WFP's ALE conditions
//! identify a *process* (`ALE_APP_ID` plus `ALE_USER_ID`) and not a socket, and
//! the only mechanism that could distinguish two sockets in one process is a
//! kernel callout driver, which is not in this build. So on this platform the
//! `BOOTSTRAP`, `RESOLVER` and class-13 probe socket classes of KS-10's table
//! **collapse into one process-scoped permit**. See [`Ks9Residual`], which is a
//! value the shell reports and a diagnostic bundle carries rather than a comment
//! nobody reads.
//!
//! Two things bound the residual, and neither is this crate's doing:
//!
//! - **KS-10's structural argument still holds.** The agent exposes no proxy, no
//!   SOCKS/CONNECT listener, no port-forwarder and no packet-injection API, so
//!   there is no way for another party's bytes to reach one of these sockets.
//! - **KS-2 is satisfied by the layer itself.** `FWPM_LAYER_ALE_AUTH_CONNECT_*`
//!   classifies *locally originated* connections. Forwarded gateway traffic never
//!   reaches it, so it can never match an exemption here — which is the one place
//!   Windows makes a KS rule easier rather than harder.
//!
//! The `UPDATE` class of KS-10a does **not** collapse, because ADR-0016 §11.2
//! puts the updater in its own binary: a different `ALE_APP_ID`, plus KS-10a's
//! destination bound to the pinned origins.

use twinvpn_types::{AddressFamily, IpPrefix};

use super::{
    baseline_protected, Action, Condition, EnforcementConfig, FilterFlags, FilterSet, FilterSpec,
    Guid, IpProtocol, Layer, Ruleset, TrafficClass, FILTER_POSTURE_BLOCKED,
    FILTER_POSTURE_PROTECTED,
};
use twinvpn_platform::NetworkContract;

/// Which of ADR-0012 §11.1's three Tier-1 modes the contract expresses.
///
/// **Derived, never configured.** §11.1's full-tunnel mode is the complement
/// form, which reaches this adapter as `docs/networking.md` §7.2's four `/1`
/// routes; TwinNet-only and split arrive as ordinary prefixes. Reporting which
/// one was seen is what lets a diagnostic bundle say "this host was in full
/// tunnel" without the shell having been told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeMode {
    /// The scope is the overlay space and whatever routes were accepted.
    Bounded,
    /// The scope is everything: both families carry the complement form.
    Complement,
}

/// What KS-9(2) asks for and what this platform can actually express.
///
/// Reported as a value so ADR-0012 K10 ("where a platform cannot deliver a
/// guarantee, the residual exposure MUST be stated, measured, and surfaced —
/// never papered over") is discharged by data rather than by prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ks9Residual {
    /// Whether the exemption is scoped per socket, as KS-9(2) specifies.
    ///
    /// Always `false` in this build. A kernel callout driver is what would make
    /// it `true`, and ADR-0016 §10 puts driver lifecycle with the installer.
    pub per_socket: bool,
    /// Whether the exemption is scoped to a process (`ALE_APP_ID` **and**
    /// `ALE_USER_ID`), which is KS-9(1) in full.
    pub per_process: bool,
    /// Which of KS-10's socket classes share the one process-scoped permit.
    pub collapsed_classes: &'static [TrafficClass],
    /// Whether forwarded traffic can reach an exemption (KS-2).
    ///
    /// Always `false`, and structurally so: the ALE authorization-connect layers
    /// classify locally originated connections only.
    pub forwarded_traffic_exemptible: bool,
}

/// KS-10's classes that this platform cannot separate.
const COLLAPSED: &[TrafficClass] = &[
    TrafficClass::BootstrapExemption,
    TrafficClass::ResolverExemption,
    TrafficClass::PortalProbe,
];

impl Ks9Residual {
    /// The residual as configured.
    #[must_use]
    pub const fn of(config: &EnforcementConfig) -> Self {
        Self {
            per_socket: false,
            per_process: config.ks9_complete(),
            collapsed_classes: COLLAPSED,
            forwarded_traffic_exemptible: false,
        }
    }
}

/// A stable code per class, so a derived filter key is reviewable.
///
/// `pub` because [`super::readback::class_of`] decodes it: the key IS the
/// class tag, and a second table over there would be the drift this avoids.
#[must_use]
pub const fn code_of(class: TrafficClass) -> u8 {
    match class {
        TrafficClass::ProtectedScopeDeny => 1,
        TrafficClass::LocalNetwork => 2,
        TrafficClass::UnderlayConfiguration => 3,
        TrafficClass::DnsContainment => 4,
        TrafficClass::BootstrapExemption => 5,
        TrafficClass::ResolverExemption => 6,
        TrafficClass::UpdateExemption => 7,
        TrafficClass::Loopback => 8,
        TrafficClass::LinkLocal => 9,
        TrafficClass::PortalGrant => 10,
        TrafficClass::PortalProbe => 11,
        TrafficClass::OverlayEgress => 12,
        TrafficClass::Marker => 13,
    }
}

const fn layer_code(layer: Layer) -> u8 {
    match layer {
        Layer::AleAuthConnectV4 => 4,
        Layer::AleAuthConnectV6 => 6,
    }
}

/// The filter key for one rendered rule.
///
/// **Derived from `(class, layer, ordinal)` and nothing else**, so re-rendering
/// the same inputs produces the same keys and a reclaim after an unclean exit
/// converges rather than duplicating (KS-20, ADR-0008). It is deliberately not a
/// hash of the conditions: a key that changed when a prefix changed would make
/// every contract generation a full delete-and-add, which is what KS-23 forbids
/// on update and what KS-17 forbids at any time.
#[must_use]
pub const fn filter_key(class: TrafficClass, layer: Layer, ordinal: u16) -> Guid {
    let ord = ordinal.to_be_bytes();
    Guid::from_fields(
        0x7477_696e,
        0x7670,
        0x6e01,
        [
            b'F',
            code_of(class),
            layer_code(layer),
            ord[0],
            ord[1],
            0,
            0,
            0,
        ],
    )
}

/// Weights, highest first. Named rather than inlined so the evaluation order of
/// the whole set reads as one table.
mod weight {
    /// Class 8. Above everything: loopback never leaves the host, and a rule
    /// that could block it would break the stub's own listeners.
    pub const LOOPBACK: u64 = 10_000;
    /// Class 7 / KS-9.
    pub const BOOTSTRAP: u64 = 9_000;
    /// KS-10a.
    pub const UPDATE: u64 = 8_500;
    /// Class 5.
    pub const UNDERLAY: u64 = 8_000;
    /// Class 9.
    pub const LINK_LOCAL: u64 = 7_500;
    /// Class 4 / KS-4.
    pub const LOCAL_NETWORK: u64 = 7_000;
    /// Class 11.
    pub const PORTAL: u64 = 6_000;
    /// Class 6 / ADR-0011 §11.9.
    pub const DNS_CONTAINMENT: u64 = 1_000;
    /// Tier 2.
    pub const OVERLAY: u64 = 200;
    /// Tier 1.
    pub const SCOPE_DENY: u64 = 100;
    /// The marker. Lowest, and it can never match.
    pub const MARKER: u64 = 0;
}

/// A LUID that is never assigned to an interface.
///
/// The posture marker has to be a filter so that `FwpmFilterEnum0` reports it,
/// and a filter that can be reached is a rule. Conditioning it on LUID 0 makes
/// it unreachable: `NET_LUID` 0 is not a valid interface identifier, so the
/// condition can never be true. The action is nevertheless `Block`, because if
/// this reasoning is ever wrong the failure must be in the closed direction.
const UNREACHABLE_LUID: u64 = 0;

/// The DNS ports the containment rule covers.
///
/// ADR-0011 §11.9: "deny UDP/TCP 53, TCP 853, and known-DoH endpoints on every
/// non-overlay interface **regardless of which process opened the socket**".
/// The DoH endpoint list is a policy input this seam does not carry — see the
/// module's own gap note in [`crate::dns`] — so what is installed here is the
/// port half, which is the part that is a constant of the protocol.
const DNS_PORTS: [(IpProtocol, u16); 3] = [
    (IpProtocol::Udp, 53),
    (IpProtocol::Tcp, 53),
    (IpProtocol::Tcp, 853),
];

/// Renders the desired filter set.
///
/// The result is deterministic: prefixes are sorted and de-duplicated, and
/// filters are emitted in a fixed class order, so two calls with equal inputs
/// produce byte-identical sets and a digest over one is a meaningful comparison
/// (ADR-0012 §11.13's `ruleset_digest`).
#[must_use]
// One function per ADR-0012 §11.2 class, in weight order. Splitting it would
// scatter the traffic-class table across a call graph, and the table's whole
// value is that a reviewer can read it against the ADR top to bottom.
#[allow(clippy::too_many_lines)]
pub fn render(
    contract: &NetworkContract,
    ruleset: Ruleset,
    config: &EnforcementConfig,
) -> FilterSet {
    let mut filters = Vec::new();

    // ---- class 8: loopback ------------------------------------------------
    for (ordinal, layer) in Layer::BOTH.into_iter().enumerate() {
        filters.push(FilterSpec {
            key: filter_key(TrafficClass::Loopback, layer, 0),
            name: "twinvpn-loopback",
            layer,
            action: Action::Permit,
            weight: weight::LOOPBACK,
            conditions: vec![Condition::IsLoopback],
            class: TrafficClass::Loopback,
            flags: persistent(),
        });
        let _ = ordinal;
    }

    // ---- class 7: the KS-9 bootstrap exemption ----------------------------
    // One permit, process-scoped, destination-unbounded — which is what KS-10's
    // table specifies for the BOOTSTRAP class's first two payload types. See
    // `Ks9Residual` for what this platform cannot narrow.
    for layer in Layer::BOTH {
        filters.push(FilterSpec {
            key: filter_key(TrafficClass::BootstrapExemption, layer, 0),
            name: "twinvpn-bootstrap",
            layer,
            action: Action::Permit,
            weight: weight::BOOTSTRAP,
            conditions: vec![
                Condition::AppId(config.service_app_id),
                Condition::UserSid(config.service_sid),
            ],
            class: TrafficClass::BootstrapExemption,
            flags: persistent(),
        });
    }

    // ---- KS-10a: the UPDATE class ----------------------------------------
    // Installed only when BOTH halves of its predicate exist. KS-10a makes the
    // class destination-bounded, and a bound of "everywhere" is not a bound; an
    // updater with no origins, or origins with no updater, produces no filter.
    if let Some(updater) = config.updater_app_id {
        for (ordinal, origin) in sorted(&config.update_origins).into_iter().enumerate() {
            let layer = Layer::for_family(origin.family());
            filters.push(FilterSpec {
                key: filter_key(TrafficClass::UpdateExemption, layer, ordinal_of(ordinal)),
                name: "twinvpn-update",
                layer,
                action: Action::Permit,
                weight: weight::UPDATE,
                conditions: vec![Condition::AppId(updater), Condition::RemotePrefix(origin)],
                class: TrafficClass::UpdateExemption,
                flags: persistent(),
            });
        }
    }

    // ---- class 5: DHCP, DHCPv6, ND and RA on the underlay ------------------
    // Link-local scope only, per §11.2's own qualification on this class.
    filters.push(FilterSpec {
        key: filter_key(
            TrafficClass::UnderlayConfiguration,
            Layer::AleAuthConnectV4,
            0,
        ),
        name: "twinvpn-dhcp4",
        layer: Layer::AleAuthConnectV4,
        action: Action::Permit,
        weight: weight::UNDERLAY,
        conditions: vec![
            Condition::Protocol(IpProtocol::Udp),
            Condition::RemotePort(67),
        ],
        class: TrafficClass::UnderlayConfiguration,
        flags: persistent(),
    });
    filters.push(FilterSpec {
        key: filter_key(
            TrafficClass::UnderlayConfiguration,
            Layer::AleAuthConnectV6,
            0,
        ),
        name: "twinvpn-dhcp6",
        layer: Layer::AleAuthConnectV6,
        action: Action::Permit,
        weight: weight::UNDERLAY,
        conditions: vec![
            Condition::Protocol(IpProtocol::Udp),
            Condition::RemotePort(547),
            Condition::LinkLocalScope,
        ],
        class: TrafficClass::UnderlayConfiguration,
        flags: persistent(),
    });
    filters.push(FilterSpec {
        key: filter_key(
            TrafficClass::UnderlayConfiguration,
            Layer::AleAuthConnectV6,
            1,
        ),
        name: "twinvpn-nd-ra",
        layer: Layer::AleAuthConnectV6,
        action: Action::Permit,
        weight: weight::UNDERLAY,
        conditions: vec![
            Condition::Protocol(IpProtocol::IcmpV6),
            Condition::LinkLocalScope,
        ],
        class: TrafficClass::UnderlayConfiguration,
        flags: persistent(),
    });

    // ---- class 9: link-local unicast on non-overlay interfaces -------------
    for (ordinal, prefix) in link_local_prefixes().into_iter().enumerate() {
        let layer = Layer::for_family(prefix.family());
        filters.push(FilterSpec {
            key: filter_key(TrafficClass::LinkLocal, layer, ordinal_of(ordinal)),
            name: "twinvpn-link-local",
            layer,
            action: Action::Permit,
            weight: weight::LINK_LOCAL,
            conditions: vec![
                Condition::RemotePrefix(prefix),
                Condition::NotLocalInterface(config.overlay_luid),
            ],
            class: TrafficClass::LinkLocal,
            flags: persistent(),
        });
    }

    // ---- class 4: on-link local network access (KS-4) ----------------------
    // "on-link prefixes only … never a destination reachable only via a router".
    if config.local_network_access {
        for (ordinal, prefix) in sorted(&config.on_link_prefixes).into_iter().enumerate() {
            let layer = Layer::for_family(prefix.family());
            filters.push(FilterSpec {
                key: filter_key(TrafficClass::LocalNetwork, layer, ordinal_of(ordinal)),
                name: "twinvpn-local-network",
                layer,
                action: Action::Permit,
                weight: weight::LOCAL_NETWORK,
                conditions: vec![
                    Condition::RemotePrefix(prefix),
                    Condition::NotLocalInterface(config.overlay_luid),
                ],
                class: TrafficClass::LocalNetwork,
                flags: persistent(),
            });
        }
    }

    // ---- class 11: the time-boxed captive-portal grant ---------------------
    // Not our app-id: the grant exists so a *user's browser* can reach the
    // portal. The time box is the core's — an adapter that expired a grant on
    // its own clock would put a deadline outside CD-1's reach — so what arrives
    // here is a set that is either present or empty.
    for (ordinal, prefix) in sorted(&config.portal_grant).into_iter().enumerate() {
        let layer = Layer::for_family(prefix.family());
        filters.push(FilterSpec {
            key: filter_key(TrafficClass::PortalGrant, layer, ordinal_of(ordinal)),
            name: "twinvpn-portal-grant",
            layer,
            action: Action::Permit,
            weight: weight::PORTAL,
            conditions: vec![
                Condition::RemotePrefix(prefix),
                Condition::NotLocalInterface(config.overlay_luid),
            ],
            class: TrafficClass::PortalGrant,
            flags: persistent(),
        });
    }

    // ---- class 6: DNS containment (ADR-0011 §11.9's SMHNR answer) ----------
    // "regardless of which process opened the socket" — so no app-id condition,
    // and the bootstrap permit above it is what keeps the stub's own upstream
    // resolution working.
    for layer in Layer::BOTH {
        for (ordinal, (protocol, port)) in DNS_PORTS.into_iter().enumerate() {
            filters.push(FilterSpec {
                key: filter_key(TrafficClass::DnsContainment, layer, ordinal_of(ordinal)),
                name: "twinvpn-dns-containment",
                layer,
                action: Action::Block,
                weight: weight::DNS_CONTAINMENT,
                conditions: vec![
                    Condition::Protocol(protocol),
                    Condition::RemotePort(port),
                    Condition::NotLocalInterface(config.overlay_luid),
                ],
                class: TrafficClass::DnsContainment,
                flags: persistent(),
            });
        }
    }

    // ---- Tier 2: the overlay permit, and the ONLY difference between the two
    //      postures ---------------------------------------------------------
    if ruleset == Ruleset::Protected {
        for layer in Layer::BOTH {
            filters.push(FilterSpec {
                key: filter_key(TrafficClass::OverlayEgress, layer, 0),
                name: "twinvpn-overlay-egress",
                layer,
                action: Action::Permit,
                weight: weight::OVERLAY,
                // Interface-scoped, and references no destination. ADR-0012
                // §11.1's requirement on the enforcement tier, and
                // `FilterSet::validate` refuses a violation rather than
                // trusting this line.
                conditions: vec![Condition::LocalInterface(config.overlay_luid)],
                class: TrafficClass::OverlayEgress,
                flags: persistent(),
            });
        }
    }

    // ---- Tier 1: the scoped deny ------------------------------------------
    for (ordinal, prefix) in protected_scope(contract).into_iter().enumerate() {
        let layer = Layer::for_family(prefix.family());
        filters.push(FilterSpec {
            key: filter_key(TrafficClass::ProtectedScopeDeny, layer, ordinal_of(ordinal)),
            name: "twinvpn-scope-deny",
            layer,
            action: Action::Block,
            weight: weight::SCOPE_DENY,
            conditions: vec![Condition::RemotePrefix(prefix)],
            class: TrafficClass::ProtectedScopeDeny,
            flags: persistent(),
        });
    }

    // ---- the posture marker ------------------------------------------------
    filters.push(FilterSpec {
        key: match ruleset {
            Ruleset::Blocked => FILTER_POSTURE_BLOCKED,
            Ruleset::Protected => FILTER_POSTURE_PROTECTED,
        },
        name: "twinvpn-posture",
        layer: Layer::AleAuthConnectV4,
        action: Action::Block,
        weight: weight::MARKER,
        conditions: vec![Condition::LocalInterface(UNREACHABLE_LUID)],
        class: TrafficClass::Marker,
        flags: persistent(),
    });

    FilterSet {
        generation: contract.generation.0,
        posture: ruleset,
        filters,
    }
}

/// Which Tier-1 mode the contract expresses.
#[must_use]
pub fn scope_mode(contract: &NetworkContract) -> ScopeMode {
    let complement = |family: AddressFamily| {
        contract
            .routes
            .get(family)
            .iter()
            .any(|r| r.destination.prefix_len() <= 1)
    };
    if complement(AddressFamily::V4) && complement(AddressFamily::V6) {
        ScopeMode::Complement
    } else {
        ScopeMode::Bounded
    }
}

/// The Tier-1 protected scope: the contract's route destinations, both
/// families, with [`baseline_protected`] as a floor beneath them.
#[must_use]
pub fn protected_scope(contract: &NetworkContract) -> Vec<IpPrefix> {
    let mut prefixes = baseline_protected();
    for family in [AddressFamily::V4, AddressFamily::V6] {
        for route in contract.routes.get(family) {
            prefixes.push(route.destination);
        }
    }
    sorted(&prefixes)
}

/// `169.254.0.0/16` and `fe80::/10`, class 9's own two prefixes.
fn link_local_prefixes() -> Vec<IpPrefix> {
    let mut out = Vec::new();
    if let Ok(v4) = IpPrefix::new(
        twinvpn_types::IpAddr::V4(twinvpn_types::V4Addr::from_octets([169, 254, 0, 0])),
        16,
    ) {
        out.push(v4);
    }
    let mut fe80 = [0u8; 16];
    fe80[0] = 0xfe;
    fe80[1] = 0x80;
    // `V6Addr::prefix_base` is the constructor that accepts a link-local value
    // with no zone: a *prefix* has no interface, and `V6Addr::new` rejecting a
    // zoneless `fe80::` is a rule about addresses rather than about prefixes.
    if let Ok(address) = twinvpn_types::V6Addr::prefix_base(fe80) {
        if let Ok(v6) = IpPrefix::new(twinvpn_types::IpAddr::V6(address), 10) {
            out.push(v6);
        }
    }
    out
}

/// Sorted and de-duplicated, so a rendered set is deterministic.
fn sorted(prefixes: &[IpPrefix]) -> Vec<IpPrefix> {
    let mut keyed: Vec<(Vec<u8>, u32, IpPrefix)> = prefixes
        .iter()
        .map(|p| (p.address().octets(), p.prefix_len(), *p))
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    keyed.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    keyed.into_iter().map(|(_, _, p)| p).collect()
}

/// A usize ordinal narrowed for the key derivation.
///
/// `limits.json` bounds every list that reaches this renderer, so an ordinal
/// beyond `u16::MAX` cannot arise from a valid contract; the saturation is here
/// so that if one ever did, two filters would share a key and
/// [`FilterSet::validate`]'s duplicate check would refuse the set rather than
/// this function silently wrapping.
fn ordinal_of(index: usize) -> u16 {
    u16::try_from(index).unwrap_or(u16::MAX)
}

/// The flags every runtime filter carries.
///
/// `persistent` on every one, because ADR-0012 §11.6's Windows row makes the
/// full policy survive a reboot through BFE. `boot_time` on none: a BOOTTIME
/// filter cannot carry an ALE condition, so the runtime set — which is built
/// around exactly those conditions — could not be a boot set even if it wanted
/// to be. [`super::boot`] is the separate, coarser set that can.
const fn persistent() -> FilterFlags {
    FilterFlags {
        persistent: true,
        boot_time: false,
    }
}

/// Fixtures the sibling modules' tests share.
///
/// One definition, so `boot.rs`'s "the runtime set must not satisfy the boot
/// check" and this module's own tests are talking about the same contract.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    use twinvpn_platform::{ContractGeneration, DnsConfig, RouteEntry};
    use twinvpn_types::PerFamily;

    /// A representative enforcement configuration.
    pub(crate) fn config() -> EnforcementConfig {
        EnforcementConfig {
            overlay_luid: 0x0001_0000_0000_0006,
            service_app_id: r"\device\harddiskvolume3\program files\twinvpn\twinvpnsvc.exe",
            service_sid: "S-1-5-80-0",
            local_network_access: true,
            on_link_prefixes: Vec::new(),
            updater_app_id: None,
            update_origins: Vec::new(),
            portal_grant: Vec::new(),
        }
    }

    /// A contract with one route in each family.
    pub(crate) fn contract() -> NetworkContract {
        let v4 = IpPrefix::new(
            twinvpn_types::IpAddr::V4(twinvpn_types::V4Addr::from_octets([10, 0, 0, 0])),
            8,
        )
        .expect("prefix");
        let mut octets = [0u8; 16];
        octets[0] = 0x20;
        octets[1] = 0x01;
        let v6 = IpPrefix::new(
            twinvpn_types::IpAddr::V6(
                twinvpn_types::V6Addr::prefix_base(octets).expect("prefix base"),
            ),
            16,
        )
        .expect("prefix");
        let entry = |destination| RouteEntry {
            destination,
            via: None,
            interface: twinvpn_platform::InterfaceIndex(6),
            metric: None,
        };
        NetworkContract {
            generation: ContractGeneration(7),
            addresses: PerFamily::new(Vec::new(), Vec::new()),
            routes: PerFamily::new(vec![entry(v4)], vec![entry(v6)]),
            dns: DnsConfig {
                resolvers: PerFamily::new(Vec::new(), Vec::new()),
                search_domains: Vec::new(),
                split_domains: Vec::new(),
                is_default_resolver: false,
            },
            ruleset: Ruleset::Blocked,
            mtu: 1420,
            tunnel_remote_address: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wfp::SetDefect;
    use twinvpn_platform::{ContractGeneration, DnsConfig, RouteEntry};
    use twinvpn_types::PerFamily;

    fn prefix(v4: [u8; 4], len: u32) -> IpPrefix {
        IpPrefix::new(
            twinvpn_types::IpAddr::V4(twinvpn_types::V4Addr::from_octets(v4)),
            len,
        )
        .expect("prefix")
    }

    fn v6_prefix(first: u8, second: u8, len: u32) -> IpPrefix {
        let mut octets = [0u8; 16];
        octets[0] = first;
        octets[1] = second;
        IpPrefix::new(
            twinvpn_types::IpAddr::V6(
                twinvpn_types::V6Addr::prefix_base(octets).expect("prefix base"),
            ),
            len,
        )
        .expect("prefix")
    }

    fn config() -> EnforcementConfig {
        EnforcementConfig {
            overlay_luid: 0x0001_0000_0000_0006,
            service_app_id: r"\device\harddiskvolume3\program files\twinvpn\twinvpnsvc.exe",
            service_sid: "S-1-5-80-3454763047-1234567890-1111111111-2222222222-3333333333",
            local_network_access: true,
            on_link_prefixes: vec![prefix([192, 168, 1, 0], 24)],
            updater_app_id: None,
            update_origins: Vec::new(),
            portal_grant: Vec::new(),
        }
    }

    fn contract(routes: PerFamily<Vec<RouteEntry>>) -> NetworkContract {
        NetworkContract {
            generation: ContractGeneration(7),
            addresses: PerFamily::new(Vec::new(), Vec::new()),
            routes,
            dns: DnsConfig {
                resolvers: PerFamily::new(Vec::new(), Vec::new()),
                search_domains: Vec::new(),
                split_domains: Vec::new(),
                is_default_resolver: false,
            },
            ruleset: Ruleset::Blocked,
            mtu: 1420,
            tunnel_remote_address: None,
        }
    }

    fn route(destination: IpPrefix) -> RouteEntry {
        RouteEntry {
            destination,
            via: None,
            interface: twinvpn_platform::InterfaceIndex(6),
            metric: None,
        }
    }

    fn empty_contract() -> NetworkContract {
        contract(PerFamily::new(Vec::new(), Vec::new()))
    }

    fn full_tunnel_contract() -> NetworkContract {
        contract(PerFamily::new(
            vec![
                route(prefix([0, 0, 0, 0], 1)),
                route(prefix([128, 0, 0, 0], 1)),
            ],
            vec![
                route(v6_prefix(0x00, 0x00, 1)),
                route(v6_prefix(0x80, 0x00, 1)),
            ],
        ))
    }

    #[test]
    fn both_postures_render_a_valid_set_from_an_empty_contract() {
        // R-6, as a Windows test: `set_ruleset(_, Blocked)` on a contract with
        // no routes must still deny. The baseline is what makes an empty-scope
        // set unrepresentable.
        for posture in [Ruleset::Blocked, Ruleset::Protected] {
            let set = render(&empty_contract(), posture, &config());
            set.validate()
                .expect("a rendered set is always installable");
            assert_eq!(set.families_covered(), (true, true));
            assert_eq!(set.posture, posture);
            assert_eq!(set.generation, 7);
        }
    }

    #[test]
    fn ks5_no_rendered_set_covers_one_family_without_the_other() {
        // Every contract shape, including the ones a v4-only host produces.
        let shapes = [
            empty_contract(),
            full_tunnel_contract(),
            contract(PerFamily::new(
                vec![route(prefix([10, 0, 0, 0], 8))],
                Vec::new(),
            )),
            contract(PerFamily::new(
                Vec::new(),
                vec![route(v6_prefix(0x20, 0x01, 16))],
            )),
        ];
        for shape in shapes {
            for posture in [Ruleset::Blocked, Ruleset::Protected] {
                let set = render(&shape, posture, &config());
                assert_eq!(
                    set.families_covered(),
                    (true, true),
                    "a v4-only contract must still produce a v6 deny"
                );
                set.validate().expect("installable");
            }
        }
    }

    #[test]
    fn the_two_postures_differ_by_exactly_the_tier_2_permit_and_the_marker() {
        // KS-17's atomic swap, made as small as it can be. If this ever grows,
        // the swap is doing more than it claims.
        let blocked = render(&full_tunnel_contract(), Ruleset::Blocked, &config());
        let protected = render(&full_tunnel_contract(), Ruleset::Protected, &config());

        let only_in_protected: Vec<_> = protected
            .filters
            .iter()
            .filter(|f| !blocked.filters.iter().any(|b| b.key == f.key))
            .map(|f| f.class)
            .collect();
        let only_in_blocked: Vec<_> = blocked
            .filters
            .iter()
            .filter(|f| !protected.filters.iter().any(|p| p.key == f.key))
            .map(|f| f.class)
            .collect();

        assert_eq!(
            only_in_protected,
            vec![
                TrafficClass::OverlayEgress,
                TrafficClass::OverlayEgress,
                TrafficClass::Marker
            ],
            "one overlay permit per family, plus the posture marker"
        );
        assert_eq!(only_in_blocked, vec![TrafficClass::Marker]);
    }

    #[test]
    fn blocked_has_no_path_out_of_the_protected_scope() {
        // The leak test, asserted over the data: in BLOCKED there is no permit
        // whose predicate can carry protected traffic off the host, in either
        // family. Every permit is either loopback, a named exemption class, or
        // scoped to an interface that is not the overlay.
        let set = render(&full_tunnel_contract(), Ruleset::Blocked, &config());
        for filter in set.filters.iter().filter(|f| f.action == Action::Permit) {
            let acceptable = matches!(
                filter.class,
                TrafficClass::Loopback
                    | TrafficClass::BootstrapExemption
                    | TrafficClass::UpdateExemption
                    | TrafficClass::UnderlayConfiguration
                    | TrafficClass::LinkLocal
                    | TrafficClass::LocalNetwork
                    | TrafficClass::PortalGrant
                    | TrafficClass::PortalProbe
                    | TrafficClass::ResolverExemption
            );
            assert!(
                acceptable,
                "BLOCKED contains an unaccounted permit: {filter:?}"
            );
            assert!(
                filter.class != TrafficClass::OverlayEgress,
                "the overlay permit is the difference between the postures"
            );
        }
    }

    #[test]
    fn every_family_has_a_deny_in_both_postures_even_in_full_tunnel() {
        // ADR-0010 R1 and R6: IPv6 must not be able to bypass tunnel policy,
        // "including when IPv6 appears *after* the tunnel is up". The deny that
        // covers it is already installed, keyed on a destination prefix and not
        // on which interfaces exist, so a new adapter changes nothing.
        for posture in [Ruleset::Blocked, Ruleset::Protected] {
            let set = render(&full_tunnel_contract(), posture, &config());
            for layer in Layer::BOTH {
                assert!(
                    set.filters.iter().any(|f| f.layer == layer
                        && f.action == Action::Block
                        && f.class == TrafficClass::ProtectedScopeDeny),
                    "{layer:?} has no scope deny in {posture:?}"
                );
            }
        }
    }

    #[test]
    fn the_tier_2_permit_references_an_interface_and_never_a_destination() {
        let set = render(&full_tunnel_contract(), Ruleset::Protected, &config());
        let tier2: Vec<_> = set
            .filters
            .iter()
            .filter(|f| f.class == TrafficClass::OverlayEgress)
            .collect();
        assert_eq!(tier2.len(), 2, "one per family");
        for filter in tier2 {
            assert_eq!(
                filter.conditions,
                vec![Condition::LocalInterface(config().overlay_luid)]
            );
        }
        set.validate().expect("installable");
    }

    #[test]
    fn a_tier_2_filter_that_named_a_destination_is_refused_rather_than_installed() {
        let mut set = render(&full_tunnel_contract(), Ruleset::Protected, &config());
        for filter in &mut set.filters {
            if filter.class == TrafficClass::OverlayEgress {
                filter
                    .conditions
                    .push(Condition::RemotePrefix(prefix([10, 0, 0, 0], 8)));
                break;
            }
        }
        assert!(matches!(
            set.validate().expect_err("refused"),
            SetDefect::Tier2NamesADestination(_)
        ));
    }

    #[test]
    fn a_set_missing_one_familys_deny_is_refused_rather_than_installed() {
        let mut set = render(&empty_contract(), Ruleset::Blocked, &config());
        set.filters.retain(|f| {
            !(f.class == TrafficClass::ProtectedScopeDeny && f.layer == Layer::AleAuthConnectV6)
        });
        assert!(matches!(
            set.validate().expect_err("refused"),
            SetDefect::FamilyAsymmetry {
                v4: true,
                v6: false
            }
        ));
    }

    #[test]
    fn dns_containment_covers_both_families_and_all_three_ports() {
        // ADR-0011 §11.9: containment, not configuration, is the guarantee, and
        // it applies "regardless of which process opened the socket" — so no
        // app-id condition appears on any of these.
        let set = render(&empty_contract(), Ruleset::Protected, &config());
        let dns: Vec<_> = set
            .filters
            .iter()
            .filter(|f| f.class == TrafficClass::DnsContainment)
            .collect();
        assert_eq!(dns.len(), 6, "three ports times two families");
        for filter in dns {
            assert_eq!(filter.action, Action::Block);
            assert!(
                !filter
                    .conditions
                    .iter()
                    .any(|c| matches!(c, Condition::AppId(_) | Condition::UserSid(_))),
                "containment must not depend on which process asked"
            );
            assert!(filter
                .conditions
                .iter()
                .any(|c| matches!(c, Condition::NotLocalInterface(_))));
        }
    }

    #[test]
    fn the_scope_is_the_contracts_routes_with_the_baseline_beneath_them() {
        let c = contract(PerFamily::new(
            vec![route(prefix([10, 0, 0, 0], 8))],
            vec![route(v6_prefix(0x20, 0x01, 16))],
        ));
        let scope = protected_scope(&c);
        assert!(scope.contains(&prefix([10, 0, 0, 0], 8)));
        assert!(scope.contains(&v6_prefix(0x20, 0x01, 16)));
        for baseline in baseline_protected() {
            assert!(scope.contains(&baseline), "the floor is always beneath");
        }
    }

    #[test]
    fn the_render_is_deterministic_so_a_digest_over_it_means_something() {
        // ADR-0012 §11.13's `ruleset_digest` compares two renders of the same
        // inputs; that comparison is only meaningful if the ordering is fixed.
        let mut jumbled = config();
        jumbled.on_link_prefixes = vec![
            prefix([192, 168, 1, 0], 24),
            prefix([10, 1, 0, 0], 16),
            prefix([192, 168, 1, 0], 24),
        ];
        let a = render(&full_tunnel_contract(), Ruleset::Protected, &jumbled);
        jumbled.on_link_prefixes = vec![
            prefix([10, 1, 0, 0], 16),
            prefix([192, 168, 1, 0], 24),
            prefix([10, 1, 0, 0], 16),
        ];
        let b = render(&full_tunnel_contract(), Ruleset::Protected, &jumbled);
        assert_eq!(a, b, "order and duplicates in the input must not show");
    }

    #[test]
    fn denying_local_network_access_removes_the_class_rather_than_narrowing_it() {
        // KS-4's DENY is a whole class disappearing, not a permit with a smaller
        // set: a permit for "no prefixes" and no permit at all are the same
        // enforcement, and the second is the one a reader can verify.
        let mut denied = config();
        denied.local_network_access = false;
        let set = render(&empty_contract(), Ruleset::Protected, &denied);
        assert!(!set
            .filters
            .iter()
            .any(|f| f.class == TrafficClass::LocalNetwork));
    }

    #[test]
    fn the_update_class_needs_both_halves_of_ks10as_predicate() {
        let mut c = config();
        // Origins with no updater binary: nothing installed.
        c.update_origins = vec![prefix([203, 0, 113, 0], 24)];
        let set = render(&empty_contract(), Ruleset::Protected, &c);
        assert!(!set
            .filters
            .iter()
            .any(|f| f.class == TrafficClass::UpdateExemption));

        // An updater binary with no origins: still nothing, because "everywhere"
        // is not a destination bound.
        c.update_origins = Vec::new();
        c.updater_app_id = Some(r"\device\harddiskvolume3\program files\twinvpn\twinvpnup.exe");
        let set = render(&empty_contract(), Ruleset::Protected, &c);
        assert!(!set
            .filters
            .iter()
            .any(|f| f.class == TrafficClass::UpdateExemption));

        // Both: one bounded permit, under the updater's own app-id.
        c.update_origins = vec![prefix([203, 0, 113, 0], 24)];
        let set = render(&empty_contract(), Ruleset::Protected, &c);
        let update: Vec<_> = set
            .filters
            .iter()
            .filter(|f| f.class == TrafficClass::UpdateExemption)
            .collect();
        assert_eq!(update.len(), 1);
        assert!(update[0]
            .conditions
            .iter()
            .any(|cond| matches!(cond, Condition::RemotePrefix(_))));
        assert!(update[0]
            .conditions
            .iter()
            .any(|cond| matches!(cond, Condition::AppId(a) if a.ends_with("twinvpnup.exe"))));
    }

    #[test]
    fn the_scope_mode_is_derived_from_the_routes_and_needs_both_families() {
        assert_eq!(scope_mode(&full_tunnel_contract()), ScopeMode::Complement);
        assert_eq!(scope_mode(&empty_contract()), ScopeMode::Bounded);
        // A v4 complement with a bounded v6 set is NOT full tunnel: calling it
        // one would be exactly ADR-0010 R1's "a v4 story and a v6 story".
        let half = contract(PerFamily::new(
            vec![
                route(prefix([0, 0, 0, 0], 1)),
                route(prefix([128, 0, 0, 0], 1)),
            ],
            vec![route(v6_prefix(0x20, 0x01, 16))],
        ));
        assert_eq!(scope_mode(&half), ScopeMode::Bounded);
    }

    #[test]
    fn every_key_in_a_rendered_set_is_distinct() {
        // Two filters sharing a key means the second `FwpmFilterAdd0` replaces
        // the first, so a rule silently disappears at install time.
        let set = render(&full_tunnel_contract(), Ruleset::Protected, &config());
        let mut keys = set.keys();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len(), "a derived key collided");
    }

    #[test]
    fn the_ks9_residual_is_a_value_and_says_what_this_platform_cannot_do() {
        // ADR-0012 K10: "where a platform cannot deliver a guarantee, the
        // residual exposure MUST be stated, measured, and surfaced".
        let residual = Ks9Residual::of(&config());
        assert!(!residual.per_socket, "no callout driver in this build");
        assert!(residual.per_process, "KS-9(1) in full");
        assert!(!residual.forwarded_traffic_exemptible, "KS-2, structurally");
        assert!(residual
            .collapsed_classes
            .contains(&TrafficClass::ResolverExemption));
        // The UPDATE class is NOT collapsed: it has its own binary.
        assert!(!residual
            .collapsed_classes
            .contains(&TrafficClass::UpdateExemption));
    }

    #[test]
    fn the_posture_marker_can_never_match_and_fails_closed_if_that_is_wrong() {
        for posture in [Ruleset::Blocked, Ruleset::Protected] {
            let set = render(&empty_contract(), posture, &config());
            let marker = set
                .filters
                .iter()
                .find(|f| f.class == TrafficClass::Marker)
                .expect("exactly one");
            assert_eq!(marker.conditions, vec![Condition::LocalInterface(0)]);
            assert_eq!(
                marker.action,
                Action::Block,
                "if the unreachability reasoning is ever wrong, close rather than open"
            );
            assert_eq!(
                marker.key,
                match posture {
                    Ruleset::Blocked => FILTER_POSTURE_BLOCKED,
                    Ruleset::Protected => FILTER_POSTURE_PROTECTED,
                }
            );
        }
    }

    #[test]
    fn every_runtime_filter_is_persistent_and_none_is_boot_time() {
        // ADR-0012 §11.6's Windows row: the full policy survives a reboot
        // through BFE. A BOOTTIME filter cannot carry an ALE condition, so the
        // runtime set could not be a boot set even if it wanted to be.
        let set = render(&full_tunnel_contract(), Ruleset::Protected, &config());
        for filter in &set.filters {
            assert!(filter.flags.persistent, "{}", filter.name);
            assert!(!filter.flags.boot_time, "{}", filter.name);
        }
    }
}
