//! The transactional network-configuration contract, and the tunnel device.
//!
//! **Authority:** `docs/networking.md` §5.1 (the adapter contract, reproduced
//! below), ADR-0018 CB-6 and §11.6, ADR-0008 (idempotency), ADR-0012 KS-17,
//! ADR-0010 R5.
//!
//! ```text
//! create_interface(name, mtu)   -> Handle    # created DOWN
//! apply(contract_generation)    -> Result    # atomic: addrs + routes + dns + firewall
//! rollback(contract_generation)              # restores prior generation exactly
//! set_link(up|down)
//! set_ruleset(BLOCKED|PROTECTED)             # atomic swap; rules NEVER absent
//! subscribe_network_change(cb)               # event-driven, never polled
//! query_link_facts() -> { ... }
//! destroy_interface()                        # idempotent; safe after crash
//! ```
//!
//! # CB-6: the core computes, the adapter installs, the **OS holds**
//!
//! > "The core computes the desired rule-set generation; the adapter installs it;
//! > the OS holds it. A core crash therefore cannot drop protection (C-7, S-18)."
//!
//! That third clause is a property of the *installation*, not of any type here,
//! so it is stated as a declared per-target fact
//! ([`EnforcementCustody::survives_core_exit`]) rather than assumed. An adapter
//! whose ruleset dies with the process must say so, because on such a target the
//! kill switch is not fail-closed across a crash and that is a fact the
//! diagnostic bundle has to carry rather than one a reviewer has to infer.

use core::time::Duration;

use futures_core::future::BoxFuture;
use twinvpn_types::{InterfaceAddress, IpAddr, IpPrefix, PerFamily, UnderlayFamilies};

use crate::error::PlatformError;
use crate::iface::{InterfaceIndex, InterfaceName};

/// The generation identifier `apply` and `rollback` are idempotent on.
///
/// `docs/networking.md` §5.1: "`apply` is all-or-nothing per contract generation
/// and is idempotent on the generation id, so a retry after a crash converges
/// rather than duplicating routes." Monotone and allocated by the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContractGeneration(pub u64);

/// The link state of the tunnel interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkState {
    /// Carrying traffic.
    Up,
    /// Not carrying traffic. **Enforcement rules stay installed** — the two are
    /// separate facts, which is why they are separate calls.
    Down,
}

/// The two fail-closed rulesets.
///
/// ADR-0012 KS-17: "transitions are an **atomic swap** between the two; rules are
/// **never absent** while the latch is UP." There is deliberately no third value
/// and no `remove_ruleset`: a moment with no ruleset is the leak window the whole
/// mechanism exists to close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ruleset {
    /// Nothing leaves except the bootstrap exemptions.
    Blocked,
    /// The tunnel is up; protected scope goes through it.
    Protected,
}

/// What holds the host between power-on and the authority starting.
///
/// **Authority:** ADR-0012 KS-19 (*"the rule set that covers the interval
/// between the network stack coming up and the agent starting MUST be installed
/// by an artifact the **OS itself applies**, never by the agent. This is where
/// real products leak."*), §11.6's per-platform durability table; ADR-0016 PS-7
/// and PS-7a.
///
/// # Why this is a three-valued capability and not a `bool`
///
/// `twinvpn-enforce`'s `DurabilityPosture` carried this as
/// `boot_enforcement_available: bool`, which cannot tell the two facts wave 2
/// reported apart — and they were reported from opposite sides:
///
/// - `desktop-windows`: BOOTTIME + `FWPM_FILTER_FLAG_PERSISTENT` filters hold
///   the host **closed** with no process of ours running. ADR-0012 §11.6 records
///   the residual as *"an availability gap, not a leak. Deliberate: the boot
///   window fails closed"* — because a BOOTTIME filter cannot carry an ALE
///   app-id, so TwinVPN itself cannot reach the control plane until the service
///   starts.
/// - `desktop-macos`: ADR-0012 §11.6's own macOS residual — *"Recovery and safe
///   boot do not load the LaunchDaemon. Residual exposure: a device booted to
///   Recovery is unprotected."* That is a **hole**, not an availability gap, and
///   a `true` here would have claimed the Windows guarantee for it.
///
/// The honest `ProtectionAssertion` differs between those two, so the capability
/// has to be able to say which one a platform is in (CB-3: the core branches on
/// a declared capability, never on which OS it is).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BootEnforcement {
    /// The **OS itself** holds an enforcement artifact from power-on, in every
    /// boot mode, with no process of ours running.
    ///
    /// Windows: BOOTTIME plus `FWPM_FILTER_FLAG_PERSISTENT` WFP filters, applied
    /// by the Base Filtering Engine. The residual is availability, not exposure.
    OsHeldFromBoot,
    /// A **package-owned** boot artifact is loaded by the platform's supervisor
    /// on every boot mode it starts in, and there is no boot mode that skips it.
    ///
    /// Linux/OpenWrt: the KS-19 nftables artifact the unit loads before the
    /// authority runs.
    PackageArtifactLoadedAtBoot,
    /// A boot artifact exists, and there is at least one **named boot mode in
    /// which the platform does not load it**, leaving the host unprotected for
    /// the whole of that boot.
    ///
    /// macOS: Recovery and safe boot do not load the `LaunchDaemon`. This is a
    /// leak, and it must reach the diagnostic bundle as one rather than being
    /// folded into the two values above.
    ExemptBootModes,
    /// Nothing enforces until the authority installs the ruleset.
    ///
    /// KS-19's *"this is where real products leak"*, as a declared value.
    None,
}

impl BootEnforcement {
    /// Whether **something** the OS applies covers KS-19's window on every boot.
    ///
    /// The `bool` `twinvpn-enforce`'s `DurabilityPosture` used to take as a
    /// separate field, now derived from the richer value so the fact has one
    /// home. [`BootEnforcement::ExemptBootModes`] is deliberately `false`: a
    /// platform with a boot mode that loads nothing does not cover the window.
    #[must_use]
    pub const fn covers_the_boot_window(self) -> bool {
        matches!(
            self,
            BootEnforcement::OsHeldFromBoot | BootEnforcement::PackageArtifactLoadedAtBoot
        )
    }

    /// Whether the residual is **exposure** rather than availability.
    ///
    /// The distinction ADR-0012 §11.6 draws between the Windows row (closed, and
    /// TwinVPN itself is what cannot get out) and the macOS row (open).
    #[must_use]
    pub const fn leaves_the_host_open(self) -> bool {
        matches!(
            self,
            BootEnforcement::ExemptBootModes | BootEnforcement::None
        )
    }
}

/// Who holds the installed ruleset across a core exit, declared per target.
///
/// **This was a `bool` and could not say what two of five targets actually do**
/// (`ownership.md` §10.8 **M-6**, reported by `mobile-ios`). ADR-0012 §11.6's
/// durability table gives iOS `◐` for both agent crash and `SIGKILL`: the rules
/// do *not* outlive the provider, and the OS *does* re-arm them without any user
/// act. Against a boolean, `true` asserts CB-6's guarantee the platform does not
/// give and `false` understates the re-arm — so an adapter had to round, and
/// whichever way it rounded the reported posture was wrong.
///
/// [`BootEnforcement`] in this same file is the precedent: a per-target fact with
/// more than two honest values is an enum with a derived predicate, never a
/// boolean plus a comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesetCustody {
    /// The OS holds the rules and they outlive the core process.
    ///
    /// CB-6's normal case: nftables, WFP, `pf`. A core crash cannot drop
    /// protection because the core was never holding it.
    OsHeld,
    /// The rules die with the process, and nothing re-installs them.
    ///
    /// A core crash **does** drop protection. The core records this rather than
    /// assuming a guarantee it does not have.
    ProcessHeld,
    /// The rules die with the process and the **OS re-arms them itself**, with no
    /// user act.
    ///
    /// ADR-0012 §11.6's `◐`. iOS is the case: enforcement is the system's, via
    /// `includeAllNetworks` and on-demand rules, so a provider that is killed
    /// takes its rules with it and the OS brings both back. There **is** a
    /// window, it is not zero, and P09 *measures* it rather than assuming it —
    /// which is exactly why this is a third value and not a rounded boolean.
    OsReArmed,
}

impl RulesetCustody {
    /// Whether the installed ruleset outlives the core process **unconditionally**.
    ///
    /// Only [`Self::OsHeld`] is `true`. [`Self::OsReArmed`] is deliberately
    /// **not**: CB-6's guarantee is that a core crash *cannot* drop protection,
    /// and a re-arm means protection was dropped and restored. O-18's direction
    /// is to report the weaker fact, and the re-arm is reported separately by
    /// [`Self::os_rearms`] rather than by widening this predicate.
    #[must_use]
    pub const fn survives_core_exit(self) -> bool {
        matches!(self, Self::OsHeld)
    }

    /// Whether the OS restores enforcement itself after a core exit, with no user
    /// act.
    ///
    /// True for [`Self::OsHeld`] trivially — it never lapsed — and for
    /// [`Self::OsReArmed`]. This is the fact a `ProtectionAssertion` needs to
    /// distinguish "unprotected until the user intervenes" from "unprotected for
    /// a measured window".
    #[must_use]
    pub const fn os_rearms(self) -> bool {
        matches!(self, Self::OsHeld | Self::OsReArmed)
    }
}

/// Who holds the installed enforcement rules, declared per target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnforcementCustody {
    /// What happens to the installed ruleset when the core process exits.
    ///
    /// See [`RulesetCustody`]. Read it through
    /// [`EnforcementCustody::survives_core_exit`], which keeps CB-6's predicate
    /// in one place.
    pub ruleset_custody: RulesetCustody,
    /// Whether the swap between the two rulesets is atomic at the OS level.
    ///
    /// `false` means there is a window with no rules, which is KS-17's forbidden
    /// state — reported so it can be a known residual rather than an invisible one.
    pub swap_is_atomic: bool,
    /// What covers KS-19's window, between power-on and the authority starting.
    ///
    /// The two facts above are about a *running* system; this one is about the
    /// interval before there is one, which KS-19 calls *"where real products
    /// leak"*. It lives here, on the capability the adapter declares, so that
    /// `twinvpn-enforce`'s `DurabilityPosture` **derives** it rather than taking
    /// it as a second field — one fact, one home.
    pub boot_enforcement: BootEnforcement,
}

impl EnforcementCustody {
    /// Whether the installed ruleset outlives the core process unconditionally.
    ///
    /// Delegates to [`RulesetCustody::survives_core_exit`]. It is a method rather
    /// than the former `bool` field so that the three-valued fact has exactly one
    /// reading and a caller cannot re-derive CB-6's predicate its own way.
    #[must_use]
    pub const fn survives_core_exit(self) -> bool {
        self.ruleset_custody.survives_core_exit()
    }

    /// Whether the OS restores enforcement itself after a core exit.
    #[must_use]
    pub const fn os_rearms(self) -> bool {
        self.ruleset_custody.os_rearms()
    }
}

/// The desired system state for one generation.
///
/// Built by `twinvpn-route`, `twinvpn-dns` and `twinvpn-enforce`; installed here
/// **as one transaction**. `docs/networking.md` §2.3 is why it is one struct
/// rather than four calls: "partial application is the leak window".
#[derive(Debug, Clone, PartialEq, Eq)]
// NOT `#[non_exhaustive]`: BOTH sides of the seam construct this. The adapter
// implementations live in other crates (`twinvpn-platform-*`, the shells) and the
// core builds the values it hands across, so sealing construction would make the
// trait unimplementable outside this crate. Adding a field here SHOULD break every
// implementor — that is a seam change, and a silent default is how one side comes
// to believe a fact the other never supplied.
pub struct NetworkContract {
    /// The generation this describes.
    pub generation: ContractGeneration,
    /// The overlay interface's addresses.
    ///
    /// A `PerFamily` of lists, so the v6 half cannot be forgotten: ADR-0010 R1
    /// requires **both** families on the overlay interface at all times,
    /// regardless of what the underlay offers.
    ///
    /// [`InterfaceAddress`] and not [`IpPrefix`], for the same reason
    /// [`crate::iface::InterfaceFacts::addresses`] is: this is an interface's
    /// *own* address, whose host bits are the whole point. `IpPrefix` requires
    /// every host bit to be zero, so `100.64.0.2/24` could not be represented
    /// and arrived as `100.64.0.0/24` — and
    /// `NEIPv4Settings(addresses:subnetMasks:)` wants the host address, which is
    /// where `desktop-macos` hit this defect for the second time. Where a route
    /// is what is wanted, [`InterfaceAddress::network`] derives it.
    pub addresses: PerFamily<Vec<InterfaceAddress>>,
    /// Routes to install into the overlay.
    pub routes: PerFamily<Vec<RouteEntry>>,
    /// Resolver configuration.
    pub dns: DnsConfig,
    /// Which ruleset to hold for this generation.
    pub ruleset: Ruleset,
    /// The overlay interface's MTU.
    pub mtu: u32,
    /// The underlay remote this generation's tunnel rides, where there is one.
    ///
    /// # Why the seam has to carry it
    ///
    /// `NEPacketTunnelNetworkSettings` is constructed with
    /// `init(tunnelRemoteAddress:)` and **requires** it — so before this field
    /// existed, `twinvpn-platform-macos` could not build a settings document
    /// from the contract alone and took it as a separate parameter the shell
    /// supplied. A value the shell holds and the core does not is a fact the two
    /// sides can disagree about, which is the whole reason the contract is one
    /// struct (`docs/networking.md` §2.3).
    ///
    /// `None` is a real answer and not an absence to paper over: in
    /// [`Ruleset::Blocked`] no path is validated, so there is no remote the
    /// tunnel is riding, and an adapter that needs one must **refuse by name**
    /// rather than substitute a placeholder. `twinvpn-platform-linux` and
    /// `twinvpn-platform-windows` do not need it to program anything — their
    /// datapaths take the peer endpoint by another route — and record it for the
    /// diagnostic bundle instead of inventing a use for it.
    pub tunnel_remote_address: Option<IpAddr>,
}

/// RFC 6598 shared address space, `100.64.0.0/10`.
///
/// **It is two things at once, and that collision is `ownership.md` §9.6 X-9.**
/// ADR-0010 §11.1 / AP-1 carve TwinNet's overlay IPv4 space out of it, so every
/// adapter's Tier-1 baseline names it as *protected* — and RFC 6598 assigned it
/// for **carrier-grade NAT**, so a subscriber behind CGNAT holds an underlay
/// address in the very same `/10`.
///
/// Address alone therefore cannot tell an overlay peer from the host's own
/// upstream. The disambiguator is the **interface**: overlay traffic egresses
/// the overlay interface and underlay traffic does not, which is why Tier 2 is
/// interface-scoped in the first place.
pub const SHARED_ADDRESS_SPACE_V4: ([u8; 4], u32) = ([100, 64, 0, 0], 10);

/// Whether an on-link prefix is the host's **own underlay path** rather than a
/// local LAN — the X-9 case.
///
/// # What this is for
///
/// A renderer accepts on-link prefixes off the overlay interface under ADR-0012
/// **KS-4**, whose `local_network_access` setting the user may set to DENY. That
/// is right for a local physical LAN: refusing it costs the user their printer
/// and protects their traffic.
///
/// It is **wrong** for a prefix inside [`SHARED_ADDRESS_SPACE_V4`]. A host
/// behind CGNAT has an on-link prefix there, and it is not the user's LAN — it
/// is the path every packet leaves by. Denying it does not protect anything,
/// because the overlay's own traffic still egresses the overlay interface and is
/// unaffected; it only severs the underlay. ADR-0010 §11.5 clause 5 already
/// makes exactly this argument for DHCP — *"blocking them breaks the underlay
/// itself"* — and DHCP is accepted by port for that reason. This is the same
/// class of traffic reached by address instead of by port.
///
/// So a colliding on-link prefix is accepted off-overlay **unconditionally**,
/// and every other on-link prefix stays under KS-4's gate. KS-4 is not widened:
/// the set this exempts is bounded by what the OS reports as on-link on a
/// non-overlay interface, it is recomputed on every network-change event, and it
/// never includes a destination reachable only via a router.
///
/// # Why it is here and not in each adapter
///
/// X-9 was recorded as *"open, and deliberately not worked around by one
/// platform alone"* — Linux and macOS behave identically and each would
/// otherwise grow its own copy of the rule. This is the one definition both
/// read, beside the contract they render.
#[must_use]
pub fn on_link_is_underlay_path(prefix: IpPrefix) -> bool {
    let (octets, len) = SHARED_ADDRESS_SPACE_V4;
    let IpAddr::V4(address) = prefix.address() else {
        // The v6 half of the overlay is the product ULA `fd7c:9e5d:2a10::/48`,
        // which is ours alone: no carrier assigns out of it, so there is no
        // collision to resolve and no exemption to make.
        return false;
    };
    if prefix.prefix_len() < len {
        // A prefix WIDER than the shared space is not "an address inside it";
        // accepting it would exempt more than the collision costs.
        return false;
    }
    let host = u32::from_be_bytes(address.octets());
    let base = u32::from_be_bytes(octets);
    let mask = u32::MAX << (32 - len);
    host & mask == base & mask
}

impl NetworkContract {
    /// The address `NEPacketTunnelNetworkSettings(tunnelRemoteAddress:)` takes,
    /// **derived from this contract and from nothing else**.
    ///
    /// # Why this rule lives here and not in each Apple adapter
    ///
    /// `ownership.md` §10.8 **M-15**: the field above was added so a settings
    /// document could be built from the contract alone, and then *neither*
    /// Apple adapter read it — `twinvpn-platform-macos::nesettings::render` and
    /// `twinvpn-platform-ios::settings::render` both kept taking it as a
    /// separate parameter the shell supplied, which is the split the field
    /// exists to close. Two adapters needing the same derivation is exactly the
    /// shape X-4 found in the MI envelope, so it is written once, here, beside
    /// the data it derives from.
    ///
    /// # The three cases, and why only one of them is an error
    ///
    /// - **A remote, on any ruleset.** Rendered as given. This is the fact the
    ///   field exists to carry, and the reason the shell no longer holds a
    ///   second copy of it.
    /// - **No remote, in [`Ruleset::Blocked`].** `Ok`, as the family's
    ///   unspecified address. This is **not** the placeholder the field's
    ///   documentation forbids: a placeholder stands in for a fact nobody
    ///   knows, and here every side agrees there is no remote — no path is
    ///   validated in that posture, so `0.0.0.0` *states* that rather than
    ///   guessing at it. It matters that this is not an error: on iOS the
    ///   blocked posture is installed **through** a settings object, so
    ///   refusing to render one would leave the kill-switch uninstalled, which
    ///   is the one direction O-18 forbids.
    /// - **No remote, in [`Ruleset::Protected`].** `Err`. A protected
    ///   generation asserts a validated path, and a validated path has a
    ///   remote; a contract carrying both claims at once is a core defect and
    ///   is refused **by name** rather than rendered against a substitute.
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] for the third case above.
    pub fn tunnel_remote_for_settings(&self) -> Result<IpAddr, PlatformError> {
        match (self.tunnel_remote_address, self.ruleset) {
            (Some(address), _) => Ok(address),
            // Stating "there is no remote", not guessing at one.
            (None, Ruleset::Blocked) => Ok(IpAddr::V4(twinvpn_types::V4Addr::UNSPECIFIED)),
            (None, Ruleset::Protected) => Err(PlatformError::AdapterUnavailable(None)),
        }
    }
}

/// One route to install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    /// The destination prefix, in canonical form.
    pub destination: IpPrefix,
    /// The next hop, or `None` for an on-link route.
    pub via: Option<IpAddr>,
    /// Which interface it points through.
    pub interface: InterfaceIndex,
    /// The route metric, where the platform has one.
    ///
    /// `docs/networking.md` §7.2 installs a default route "without destroying the
    /// host's default route", which on several targets is a metric question.
    ///
    /// **Set this only when [`RouteCapabilities::metric`] is `true`.** Darwin has
    /// no route metric at all — preference comes from prefix length and network
    /// service order — so `twinvpn-platform-macos` can only refuse a metric it is
    /// handed. The capability exists so the core plans for what the platform
    /// *can* do instead of issuing an instruction that will be refused.
    pub metric: Option<u32>,
}

/// Which route attributes this platform can actually install.
///
/// **A declared capability (CB-3)**, not an OS branch. Two domains reported the
/// same shape from opposite sides and both refused rather than silently
/// dropping, which was right and left the core no way to know:
///
/// - `desktop-macos`: *"`RouteEntry::metric` is dropped. macOS `route(8)` has no
///   metric; preference comes from prefix length and network service order."*
///   Reported per operation as `RouteOp::metric_unrepresentable`.
/// - `desktop-windows`: `InterfaceMetric` / `RouteMetric` exist and are used, so
///   the same instruction is honoured there.
///
/// A refusal a caller cannot anticipate is indistinguishable from a fault. This
/// makes the refusal **expressible in advance**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteCapabilities {
    /// Whether [`RouteEntry::metric`] means anything on this platform.
    ///
    /// `false` means the platform has no metric concept at all, and a route's
    /// preference is decided some other way. A core that has read `false`
    /// expresses precedence through the prefixes it installs — §7.2's split
    /// default (`0.0.0.0/1` + `128.0.0.0/1`) is exactly that technique — rather
    /// than through a number the platform will discard.
    pub metric: bool,
}

/// Resolver configuration for one generation.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOT `#[non_exhaustive]`: BOTH sides of the seam construct this. The adapter
// implementations live in other crates (`twinvpn-platform-*`, the shells) and the
// core builds the values it hands across, so sealing construction would make the
// trait unimplementable outside this crate. Adding a field here SHOULD break every
// implementor — that is a seam change, and a silent default is how one side comes
// to believe a fact the other never supplied.
pub struct DnsConfig {
    /// Resolvers, per family and capped per family by `limits.json`.
    pub resolvers: PerFamily<Vec<IpAddr>>,
    /// Search domains.
    pub search_domains: Vec<String>,
    /// Domains routed to the overlay resolver (split DNS).
    pub split_domains: Vec<String>,
    /// Whether the overlay resolver is the system default for everything else.
    pub is_default_resolver: bool,
}

/// What the OS currently reports about the underlay.
///
/// `docs/networking.md` §5.1's `query_link_facts()`.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOT `#[non_exhaustive]`: BOTH sides of the seam construct this. The adapter
// implementations live in other crates (`twinvpn-platform-*`, the shells) and the
// core builds the values it hands across, so sealing construction would make the
// trait unimplementable outside this crate. Adding a field here SHOULD break every
// implementor — that is a seam change, and a silent default is how one side comes
// to believe a fact the other never supplied.
pub struct LinkFacts {
    /// The underlay's effective MTU.
    pub mtu: u32,
    /// Which families the underlay actually carries, and the NAT64 prefix when
    /// there is one (ADR-0010 §11.7).
    pub families: UnderlayFamilies,
    /// Whether a default route exists, per family.
    pub default_routes: PerFamily<bool>,
    /// The system resolvers, per family.
    pub resolvers: PerFamily<Vec<IpAddr>>,
    /// Whether the link is metered.
    pub metered: bool,
    /// Whether the host is in a low-power state.
    pub low_power: bool,
}

/// The transactional configuration surface.
pub trait NetworkConfig: Send + Sync {
    /// Installs a whole generation, atomically.
    ///
    /// **All-or-nothing**: on failure the system is exactly as it was before the
    /// call, with no partially applied address, route or resolver. **Idempotent
    /// on the generation id**: re-applying a generation already in force
    /// succeeds and changes nothing, so a retry after a crash converges rather
    /// than duplicating routes (ADR-0008).
    ///
    /// # Errors
    ///
    /// [`PlatformError::RouteProgrammingDenied`] and friends. A failure leaves
    /// the previous generation intact.
    fn apply<'a>(
        &'a self,
        contract: &'a NetworkContract,
    ) -> BoxFuture<'a, Result<(), PlatformError>>;

    /// Restores the generation before `generation`, exactly.
    ///
    /// ADR-0010 R5 requires installation to be "fully reversible, including after
    /// an unclean process exit", which is why this takes a generation id rather
    /// than meaning "undo the last thing you did".
    fn rollback(&self, generation: ContractGeneration) -> BoxFuture<'_, Result<(), PlatformError>>;

    /// The generation currently in force, if any.
    ///
    /// The recovery entry point: after a crash the core reads this and decides
    /// whether to converge or roll back.
    fn current_generation(
        &self,
    ) -> BoxFuture<'_, Result<Option<ContractGeneration>, PlatformError>>;

    /// Swaps the enforcement ruleset.
    ///
    /// KS-17: an **atomic swap**; rules are never absent while the latch is up.
    /// The core computes which ruleset is desired; this installs it; the OS holds
    /// it (CB-6).
    fn set_ruleset(
        &self,
        generation: ContractGeneration,
        ruleset: Ruleset,
    ) -> BoxFuture<'_, Result<(), PlatformError>>;

    /// The ruleset currently installed, read back from the OS.
    ///
    /// Read from the OS rather than from a cached value: the reconciler's job is
    /// to notice that something else changed the rules, and a cache cannot.
    fn installed_ruleset(&self) -> BoxFuture<'_, Result<Option<Ruleset>, PlatformError>>;

    /// Who holds the rules on this target.
    fn enforcement_custody(&self) -> EnforcementCustody;

    /// Which route attributes this platform can install.
    ///
    /// Read **before** a contract is assembled, so a route carries a metric only
    /// where a metric is a thing.
    fn route_capabilities(&self) -> RouteCapabilities;

    /// The underlay's current facts.
    fn query_link_facts(&self) -> BoxFuture<'_, Result<LinkFacts, PlatformError>>;
}

/// A created tunnel interface.
///
/// Opaque. The core never learns the OS handle behind it, which is what keeps
/// every OS-specific operation on the adapter's side of CB-1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TunnelHandle(pub u64);

/// Where the datapath actually runs on this target.
///
/// A **capability fact**, so `twinvpn-tunnel` branches on the datapath rather
/// than on the OS (CB-3). ADR-0018 §11.2 row 2.3 splits exactly here: "on
/// Linux/OpenWrt the core *programs* the kernel WireGuard module; elsewhere the
/// core *is* the datapath".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Datapath {
    /// The kernel carries packets; the core programs the module and never sees a
    /// packet. Zero crossings of `twinvpn.h` per packet (PB-1).
    KernelOffload,
    /// The core reads and writes packets itself, through
    /// [`TunnelDevice::read_packet`] and [`TunnelDevice::write_packet`].
    Userspace,
}

/// The tunnel device.
pub trait TunnelDevice: Send + Sync {
    /// Creates the interface. **Created DOWN**, per `docs/networking.md` §5.1.
    ///
    /// Down first is not a convention: an interface that comes up before its
    /// addresses, routes and rules are installed is the partial-application leak
    /// window §2.3 names.
    ///
    /// # Errors
    ///
    /// [`PlatformError::VpnPermissionDenied`] where the OS gates it behind a user
    /// grant, [`PlatformError::NotPermitted`] where it gates it behind privilege.
    fn create_interface<'a>(
        &'a self,
        name: &'a InterfaceName,
        mtu: u32,
    ) -> BoxFuture<'a, Result<TunnelHandle, PlatformError>>;

    /// Brings the interface up or down.
    fn set_link(
        &self,
        handle: TunnelHandle,
        state: LinkState,
    ) -> BoxFuture<'_, Result<(), PlatformError>>;

    /// Destroys the interface. **Idempotent; safe after a crash.**
    fn destroy_interface(&self, handle: TunnelHandle) -> BoxFuture<'_, Result<(), PlatformError>>;

    /// Where the datapath runs on this target.
    fn datapath(&self) -> Datapath;

    /// Reads one packet. `Userspace` datapath only.
    ///
    /// # Errors
    ///
    /// [`PlatformError::OsUnsupported`] on a `KernelOffload` target, where the
    /// core never sees a packet.
    fn read_packet<'a>(
        &'a self,
        handle: TunnelHandle,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<usize, PlatformError>>;

    /// Writes one packet. `Userspace` datapath only.
    fn write_packet<'a>(
        &'a self,
        handle: TunnelHandle,
        packet: &'a [u8],
    ) -> BoxFuture<'a, Result<usize, PlatformError>>;

    /// Changes the interface MTU after creation.
    ///
    /// DPLPMTUD raises and lowers this as it probes (`docs/networking.md` §6.2).
    fn set_mtu(&self, handle: TunnelHandle, mtu: u32) -> BoxFuture<'_, Result<(), PlatformError>>;
}

/// How long the adapter's own contract says a call may take.
///
/// §11.6: a core→shell call is "blocking, bounded by the adapter's own
/// contract". Declared so the core's watchdog has a figure to compare against;
/// the deadline itself is always the core's, on the injected monotonic clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyBudget(pub Duration);
#[cfg(test)]
mod x9_tests {
    //! `ownership.md` §9.6 **X-9**: RFC 6598 is both the overlay's address
    //! space and carrier-grade NAT space, so a CGNAT subscriber's own underlay
    //! prefix sits inside the range every adapter's Tier-1 baseline protects.

    use super::on_link_is_underlay_path;
    use twinvpn_types::{IpAddr, IpPrefix, V4Addr, V6Addr};

    fn v4(octets: [u8; 4], len: u32) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(V4Addr::from_octets(octets)), len).expect("prefix")
    }

    #[test]
    fn a_cgnat_subscribers_own_prefix_is_the_underlay_path() {
        // The case X-9 names. Without this the Tier-2 deny takes the host's
        // route to its own upstream whenever KS-4 is DENY.
        assert!(on_link_is_underlay_path(v4([100, 64, 0, 0], 24)));
        assert!(on_link_is_underlay_path(v4([100, 96, 0, 0], 12)));
        assert!(on_link_is_underlay_path(v4([100, 127, 255, 0], 24)));
    }

    #[test]
    fn an_ordinary_lan_is_not_and_stays_under_ks4() {
        // KS-4 is not widened. A printer on 192.168.1.0/24 is still the user's
        // to deny, which is the whole point of the setting.
        for prefix in [
            v4([192, 168, 1, 0], 24),
            v4([10, 0, 0, 0], 8),
            v4([172, 16, 0, 0], 12),
            v4([100, 63, 255, 0], 24),
            v4([100, 128, 0, 0], 24),
        ] {
            assert!(!on_link_is_underlay_path(prefix), "{prefix:?}");
        }
    }

    #[test]
    fn a_prefix_wider_than_the_shared_space_is_not_exempted() {
        // "An address inside the shared space" is the fact; a supernet of it is
        // not, and exempting one would pass more than the collision costs.
        assert!(!on_link_is_underlay_path(v4([0, 0, 0, 0], 0)));
        assert!(!on_link_is_underlay_path(v4([100, 0, 0, 0], 8)));
        // The boundary itself is the shared space and IS exempt.
        assert!(on_link_is_underlay_path(v4([100, 64, 0, 0], 10)));
    }

    #[test]
    fn the_v6_half_has_no_collision_to_resolve() {
        // The overlay's v6 space is the product ULA, which is ours alone: no
        // carrier assigns out of it, so there is no exemption to make and this
        // must not become a general "pass on-link v6" hole.
        let ula = IpPrefix::new(
            IpAddr::V6(
                V6Addr::prefix_base([
                    0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ])
                .expect("v6"),
            ),
            48,
        )
        .expect("prefix");
        assert!(!on_link_is_underlay_path(ula));
    }
}
