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
use twinvpn_types::{IpAddr, IpPrefix, PerFamily, UnderlayFamilies};

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

/// Who holds the installed enforcement rules, declared per target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnforcementCustody {
    /// Whether the installed ruleset outlives the core process.
    ///
    /// `true` on a target where the OS holds the rules (nftables, WFP, `pf`) —
    /// CB-6's normal case. `false` where the rules die with the process, on which
    /// a core crash **does** drop protection; the core must record that in the
    /// diagnostic bundle rather than assume the CB-6 guarantee it does not have.
    pub survives_core_exit: bool,
    /// Whether the swap between the two rulesets is atomic at the OS level.
    ///
    /// `false` means there is a window with no rules, which is KS-17's forbidden
    /// state — reported so it can be a known residual rather than an invisible one.
    pub swap_is_atomic: bool,
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
    pub addresses: PerFamily<Vec<IpPrefix>>,
    /// Routes to install into the overlay.
    pub routes: PerFamily<Vec<RouteEntry>>,
    /// Resolver configuration.
    pub dns: DnsConfig,
    /// Which ruleset to hold for this generation.
    pub ruleset: Ruleset,
    /// The overlay interface's MTU.
    pub mtu: u32,
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
    pub metric: Option<u32>,
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
