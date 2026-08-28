//! The Windows Filtering Platform enforcement layer: **the core computes, the
//! adapter installs, the OS holds** (CB-6).
//!
//! **Authority:** ADR-0012 §11.1 (the two-tier model), §11.2 (the traffic-class
//! table), §11.5 KS-9…KS-12 (the bootstrap exemption), §11.6 (the Windows row —
//! one owned sublayer, `FWPM_LAYER_ALE_AUTH_CONNECT_V4` **and** `_V6`, installed
//! in one transaction; `FWPM_FILTER_FLAG_BOOTTIME` + `FWPM_FILTER_FLAG_PERSISTENT`),
//! §11.8 KS-17/KS-18/KS-20, §11.9 (the leak canary); ADR-0010 §11.5 clause 1
//! (**one object, both families**); ADR-0011 §11.9 (SMHNR containment);
//! ADR-0015 §11.6 rule 1 (the `ProtectionAssertion`); ADR-0016 §11.5 and PS-8
//! (owner-tagged, reclaimed not recreated).
//!
//! # KS-5, made structural rather than disciplinary
//!
//! > An implementation that can install the Tier-2 rule set for one family
//! > without the other is **non-conforming**, not degraded. There is no partial-
//! > install success result.
//!
//! [`filters::render`] produces **one** [`FilterSet`], and every rule it emits is
//! emitted from a loop over both [`Layer::AleAuthConnectV4`] and
//! [`Layer::AleAuthConnectV6`]. There is no code path in this module that emits a
//! v4 filter without its v6 counterpart, because there is no separate v6 object
//! to forget — ADR-0010 §11.5's "structural guarantee, not a discipline".
//! [`FilterSet::families_covered`] reports it as a value, and
//! [`readback::Installed`] recovers the same fact from what the engine actually
//! holds, so a half-installed set is a state a caller can *see* rather than one
//! it has to trust did not happen.
//!
//! # KS-17: two rulesets, never zero
//!
//! [`Ruleset`] has two values and there is no third. A swap is one
//! `FwpmTransactionBegin0` / `FwpmTransactionCommit0` pair over the whole owned
//! object graph, which WFP applies atomically, so there is no instant at which
//! the host holds no TwinVPN filters. `FwpmFilterDeleteByKey0`-then-add across
//! two transactions would open exactly the window KS-17 exists to close, and is
//! also what KS-23 forbids on update.
//!
//! # W-24: the assertion here is a **query**, not a belief
//!
//! ADR-0015 §11.6 rule 1 requires the `ProtectionAssertion` to be produced by
//! *querying the enforcement layer*, "never of the agent's belief". This module
//! therefore has no cached posture. [`readback::parse_installed`] takes the rows
//! the engine enumerated and derives the posture, the generation and the family
//! coverage from **which objects exist**, and nothing else. If the query fails
//! the answer is an error, never a remembered value — `Ok(None)` would read as
//! "no ruleset installed", which is the dangerous direction.
//!
//! # Where the posture and the generation live
//!
//! Windows has no equivalent of an nftables named counter, so the two facts are
//! carried by objects instead:
//!
//! | Fact | Carrier | Why |
//! |---|---|---|
//! | posture (`BLOCKED` xor `PROTECTED`) | exactly one of two **marker filters** with fixed keys ([`FILTER_POSTURE_BLOCKED`], [`FILTER_POSTURE_PROTECTED`]) | structural: `FwpmFilterEnum0` reports objects, and a filter that is present or absent cannot be misread the way free text can |
//! | contract generation | the owned provider's `providerData` blob, 8 bytes big-endian | a blob this crate owns end to end; recovered by `FwpmProviderGetByKey0` |
//! | family coverage | whether a Tier-2 scope filter exists at **each** ALE layer | KS-5's question asked of the engine rather than of the installer's return code |
//!
//! Both survive a core crash, because they are Base Filtering Engine objects
//! (CB-6), and both are removed with the provider by an uninstall.
//!
//! # This module is target-free
//!
//! Nothing here calls Windows. [`FilterSet`] is data, [`filters::render`] is a
//! pure function of `(NetworkContract, Ruleset, EnforcementConfig)`, and
//! [`readback::parse_installed`] is a pure function of enumerated rows. The
//! syscall shim that hands those rows over lives in [`crate::sys`], behind
//! `#[cfg(windows)]`, and is the only part of the enforcement story that cannot
//! be exercised on a Linux host.

pub mod boot;
pub mod canary;
pub mod filters;
pub mod readback;

use twinvpn_platform::EnforcementCustody;
use twinvpn_types::{AddressFamily, IpPrefix};

pub use canary::{CounterSnapshot, NetEvent, NetEventKind};
pub use filters::{render, ScopeMode};
pub use readback::{parse_installed, Installed, InstalledFilter};

/// A Windows GUID, as the sixteen bytes WFP stores.
///
/// A newtype over the bytes rather than the `windows-sys` struct so that every
/// key in this crate is a compile-time constant that exists on a Linux host.
/// [`crate::sys::win`] converts to `GUID` at the one call site that needs one.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// Builds a GUID from its canonical five-field form.
    #[must_use]
    pub const fn from_fields(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Self {
        let a = d1.to_be_bytes();
        let b = d2.to_be_bytes();
        let c = d3.to_be_bytes();
        Self([
            a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4],
            d4[5], d4[6], d4[7],
        ])
    }

    /// The bytes, for the conversion in [`crate::sys`].
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl core::fmt::Debug for Guid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{{{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
             {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

/// The owned provider. **This is the owner tag** KS-20 and PS-8 turn on.
///
/// Every object this crate installs carries `provider_key = PROVIDER_KEY`, so
/// "which filters are ours" is a question the engine answers rather than one we
/// answer from a name we chose. A fresh process after an unclean exit reclaims by
/// this key; it never enumerates by display name, because a display name is free
/// text another product can also choose.
pub const PROVIDER_KEY: Guid = Guid::from_fields(
    0x7477_696e,
    0x7670,
    0x6e00,
    [0x54, 0x77, 0x69, 0x6e, 0x56, 0x50, 0x4e, 0x01],
);

/// The one owned sublayer. ADR-0012 §11.6's Windows row: "one owned WFP
/// sublayer containing `FWPM_LAYER_ALE_AUTH_CONNECT_V4` **and**
/// `FWPM_LAYER_ALE_AUTH_CONNECT_V6` filters, installed in one transaction".
pub const SUBLAYER_KEY: Guid = Guid::from_fields(
    0x7477_696e,
    0x7670,
    0x6e00,
    [0x54, 0x77, 0x69, 0x6e, 0x56, 0x50, 0x4e, 0x02],
);

/// The marker filter whose presence means `RULESET_BLOCKED` is installed.
pub const FILTER_POSTURE_BLOCKED: Guid = Guid::from_fields(
    0x7477_696e,
    0x7670,
    0x6e00,
    [0x50, 0x4f, 0x53, 0x54, 0x55, 0x52, 0x45, 0x00],
);

/// The marker filter whose presence means `RULESET_PROTECTED` is installed.
pub const FILTER_POSTURE_PROTECTED: Guid = Guid::from_fields(
    0x7477_696e,
    0x7670,
    0x6e00,
    [0x50, 0x4f, 0x53, 0x54, 0x55, 0x52, 0x45, 0x01],
);

/// The sublayer's weight.
///
/// **A decision recorded as one.** No weight is pinned anywhere in the Phase 1
/// corpus, and the choice is consequential: a sublayer's weight decides whether
/// our block survives another product's permit. `0xFF00` sits above the weights
/// the documented Microsoft sublayers use (`FWPM_SUBLAYER_UNIVERSAL` is 0) and
/// below `u16::MAX`, leaving room for a product that must be above us to be
/// there deliberately. K11 requires coexistence, not supremacy: we do not take
/// the top of the range.
pub const SUBLAYER_WEIGHT: u16 = 0xFF00;

/// The WFP layers this crate installs into.
///
/// Deliberately short. ADR-0012 §11.6 names the two ALE authorization-connect
/// layers and nothing else, and every additional layer is an additional place a
/// reviewer has to check for the v4/v6 pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Layer {
    /// `FWPM_LAYER_ALE_AUTH_CONNECT_V4`.
    AleAuthConnectV4,
    /// `FWPM_LAYER_ALE_AUTH_CONNECT_V6`.
    AleAuthConnectV6,
}

impl Layer {
    /// Both layers, in a fixed order. **The only way this crate enumerates
    /// layers** — a loop over this constant is what makes a v4-without-v6 filter
    /// unrepresentable.
    pub const BOTH: [Layer; 2] = [Layer::AleAuthConnectV4, Layer::AleAuthConnectV6];

    /// Which family this layer carries.
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        match self {
            Layer::AleAuthConnectV4 => AddressFamily::V4,
            Layer::AleAuthConnectV6 => AddressFamily::V6,
        }
    }

    /// The layer for a family.
    #[must_use]
    pub const fn for_family(family: AddressFamily) -> Self {
        match family {
            AddressFamily::V4 => Layer::AleAuthConnectV4,
            AddressFamily::V6 => Layer::AleAuthConnectV6,
        }
    }

    /// The stable, non-localised name a support case greps for.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Layer::AleAuthConnectV4 => "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
            Layer::AleAuthConnectV6 => "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
        }
    }
}

/// What a filter does when every condition matches.
///
/// There is no `Continue`: a filter that neither permits nor blocks is a filter
/// whose effect depends on what else is installed, which is precisely the
/// property ADR-0012 K12 forbids an implementation from relying on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// `FWP_ACTION_BLOCK`.
    Block,
    /// `FWP_ACTION_PERMIT`.
    Permit,
}

/// One WFP filter condition.
///
/// Only the conditions ADR-0012's traffic-class table actually needs. Each
/// variant names the `FWPM_CONDITION_*` it becomes, so [`crate::sys`]'s
/// translation is mechanical and this enum stays reviewable against §11.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// `FWPM_CONDITION_IP_LOCAL_INTERFACE` — an interface LUID.
    ///
    /// Tier 2's whole predicate. It references an interface and never a
    /// destination, which is ADR-0012 §11.1's requirement on the enforcement
    /// tier stated as a type.
    LocalInterface(u64),
    /// `FWPM_CONDITION_IP_LOCAL_INTERFACE` with `FWP_MATCH_NOT_EQUAL`.
    ///
    /// The DNS containment of ADR-0011 §11.9 needs "every non-overlay
    /// interface", and WFP's not-equal match is the only way to say that
    /// without enumerating interfaces — an enumeration that would be wrong the
    /// moment a new adapter appeared, which is precisely the SMHNR case.
    NotLocalInterface(u64),
    /// `FWPM_CONDITION_ALE_APP_ID` — the normalised path of the service binary.
    AppId(&'static str),
    /// `FWPM_CONDITION_ALE_USER_ID` — the service SID
    /// (`NT SERVICE\TwinVPNService`), in SDDL form.
    UserSid(&'static str),
    /// `FWPM_CONDITION_IP_REMOTE_ADDRESS` — a destination prefix. **Tier 1
    /// only.**
    RemotePrefix(IpPrefix),
    /// `FWPM_CONDITION_IP_REMOTE_PORT`.
    RemotePort(u16),
    /// `FWPM_CONDITION_IP_PROTOCOL`.
    Protocol(IpProtocol),
    /// `FWPM_CONDITION_FLAGS` with `FWP_CONDITION_FLAG_IS_LOOPBACK`.
    IsLoopback,
    /// `FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE` restricted to link-local.
    LinkLocalScope,
}

/// The transport protocols the class table names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IpProtocol {
    /// UDP (17).
    Udp,
    /// TCP (6).
    Tcp,
    /// ICMPv6 (58) — ND and RA, class 5.
    IcmpV6,
}

impl IpProtocol {
    /// The IANA number.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            IpProtocol::Tcp => 6,
            IpProtocol::Udp => 17,
            IpProtocol::IcmpV6 => 58,
        }
    }
}

/// Which of ADR-0012 §11.2's classes a filter realises.
///
/// Carried on the filter so that the read-back, the canary fold and a diagnostic
/// bundle can all say *why* a packet was permitted or denied in the ADR's own
/// vocabulary rather than in a GUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrafficClass {
    /// Class 1–3 and the complement form: the Tier-1 scoped deny.
    ProtectedScopeDeny,
    /// Class 4: on-link local network access (KS-4).
    LocalNetwork,
    /// Class 5: DHCP, DHCPv6, ND and RA on the underlay.
    UnderlayConfiguration,
    /// Class 6: DNS containment (ADR-0011 §11.9's SMHNR answer).
    DnsContainment,
    /// Class 7: the KS-9 bootstrap exemption, `BOOTSTRAP` socket class.
    BootstrapExemption,
    /// KS-10's `RESOLVER` socket class.
    ResolverExemption,
    /// KS-10a's `UPDATE` socket class.
    UpdateExemption,
    /// Class 8: loopback.
    Loopback,
    /// Class 9: link-local unicast on non-overlay interfaces.
    LinkLocal,
    /// Class 11: the time-boxed captive-portal grant.
    PortalGrant,
    /// Class 13: the captive-portal *detection* probe.
    PortalProbe,
    /// Tier 2: the interface-scoped permit that is the whole of the overlay's
    /// authorisation. References no destination.
    OverlayEgress,
    /// A marker filter carrying a fact rather than a decision.
    Marker,
}

impl TrafficClass {
    /// The stable, non-localised tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            TrafficClass::ProtectedScopeDeny => "protected_scope_deny",
            TrafficClass::LocalNetwork => "local_network",
            TrafficClass::UnderlayConfiguration => "underlay_configuration",
            TrafficClass::DnsContainment => "dns_containment",
            TrafficClass::BootstrapExemption => "bootstrap_exemption",
            TrafficClass::ResolverExemption => "resolver_exemption",
            TrafficClass::UpdateExemption => "update_exemption",
            TrafficClass::Loopback => "loopback",
            TrafficClass::LinkLocal => "link_local",
            TrafficClass::PortalGrant => "portal_grant",
            TrafficClass::PortalProbe => "portal_probe",
            TrafficClass::OverlayEgress => "overlay_egress",
            TrafficClass::Marker => "marker",
        }
    }

    /// Whether a packet permitted by this class is **exempt egress** for KS-11's
    /// accounting.
    ///
    /// The loopback and marker classes are not: loopback never leaves the host,
    /// and a marker matches nothing. Counting them would put a floor under the
    /// exempt byte count that has nothing to do with the bootstrap channel, and
    /// KS-11's divergence test is a comparison against the agent's own frame
    /// accounting.
    #[must_use]
    pub const fn is_exempt_egress(self) -> bool {
        matches!(
            self,
            TrafficClass::BootstrapExemption
                | TrafficClass::ResolverExemption
                | TrafficClass::UpdateExemption
                | TrafficClass::PortalGrant
                | TrafficClass::PortalProbe
                | TrafficClass::LocalNetwork
                | TrafficClass::LinkLocal
                | TrafficClass::UnderlayConfiguration
        )
    }
}

/// The flags one filter carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FilterFlags {
    /// `FWPM_FILTER_FLAG_PERSISTENT` — reinstated by the Base Filtering Engine
    /// across a reboot, with no process of ours running.
    pub persistent: bool,
    /// `FWPM_FILTER_FLAG_BOOTTIME` — applied by BFE before any service starts.
    ///
    /// **Cannot carry an ALE app-id or user-id condition.** ADR-0012 §11.6's
    /// Windows row states the consequence: the bootstrap exception is
    /// unavailable during the boot window, which is an availability gap and not
    /// a leak, and the boot window therefore fails closed. [`boot`] is where
    /// that set lives, and [`FilterSet::validate`] refuses a boot-time filter
    /// that names a principal.
    pub boot_time: bool,
}

/// One filter, as data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterSpec {
    /// The filter key. Fixed for the marker filters; derived for the rest, so a
    /// re-render of the same inputs produces the same keys and a reclaim after a
    /// crash converges rather than duplicating.
    pub key: Guid,
    /// A stable, non-localised name for `displayData`.
    pub name: &'static str,
    /// Which layer.
    pub layer: Layer,
    /// What it does.
    pub action: Action,
    /// Its weight within the sublayer. Higher is evaluated first.
    pub weight: u64,
    /// Its conditions, in a deterministic order.
    pub conditions: Vec<Condition>,
    /// Which ADR-0012 class it realises.
    pub class: TrafficClass,
    /// Its flags.
    pub flags: FilterFlags,
}

/// The whole owned object graph for one generation and one posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterSet {
    /// The generation the provider's `providerData` will carry.
    pub generation: u64,
    /// Which posture this set realises.
    pub posture: Ruleset,
    /// The filters, in a deterministic order.
    pub filters: Vec<FilterSpec>,
}

/// Re-exported so this module's signatures do not need the seam's path spelled
/// out at every use.
pub use twinvpn_platform::Ruleset;

impl FilterSet {
    /// Which families this set actually covers with a Tier-1 scope deny.
    ///
    /// **KS-5's question, answered from the data.** Both must be `true`; a set
    /// where one is not is non-conforming, and [`Self::validate`] refuses it
    /// rather than letting it reach the engine.
    #[must_use]
    pub fn families_covered(&self) -> (bool, bool) {
        let covers = |layer: Layer| {
            self.filters.iter().any(|f| {
                f.layer == layer
                    && f.action == Action::Block
                    && f.class == TrafficClass::ProtectedScopeDeny
            })
        };
        (
            covers(Layer::AleAuthConnectV4),
            covers(Layer::AleAuthConnectV6),
        )
    }

    /// Refuses a set that cannot be installed as specified.
    ///
    /// # Errors
    ///
    /// [`SetDefect`] naming the rule that was broken. Every one of these is a
    /// **defect in this crate**, not a condition a host can be in, which is why
    /// it is a distinct type from [`twinvpn_platform::PlatformError`]: the
    /// caller turns it into `INTERNAL.INVARIANT_VIOLATED` and does not retry.
    pub fn validate(&self) -> Result<(), SetDefect> {
        let (v4, v6) = self.families_covered();
        if !v4 || !v6 {
            return Err(SetDefect::FamilyAsymmetry { v4, v6 });
        }
        for filter in &self.filters {
            // ADR-0012 §11.6: a BOOTTIME filter cannot carry an ALE condition.
            // Asserting it here rather than discovering it at
            // `FwpmFilterAdd0` is what keeps the boot set installable by an
            // installer that has no way to report a rejection to a user.
            if filter.flags.boot_time
                && filter
                    .conditions
                    .iter()
                    .any(|c| matches!(c, Condition::AppId(_) | Condition::UserSid(_)))
            {
                return Err(SetDefect::BootTimeFilterNamesAPrincipal(filter.name));
            }
            // ADR-0012 §11.1: Tier 2 is interface-scoped and "MUST NOT reference
            // any destination prefix". The permit that authorises the overlay is
            // the Tier-2 object, so a destination on it would be a Tier-1
            // decision that had leaked into the enforcement tier.
            if filter.class == TrafficClass::OverlayEgress
                && filter
                    .conditions
                    .iter()
                    .any(|c| matches!(c, Condition::RemotePrefix(_)))
            {
                return Err(SetDefect::Tier2NamesADestination(filter.name));
            }
        }
        let markers = self
            .filters
            .iter()
            .filter(|f| f.class == TrafficClass::Marker)
            .count();
        if markers != 1 {
            return Err(SetDefect::PostureNotExactlyOnce(markers));
        }
        Ok(())
    }

    /// Every filter key, sorted — the reclaim set (KS-20).
    #[must_use]
    pub fn keys(&self) -> Vec<Guid> {
        let mut keys: Vec<Guid> = self.filters.iter().map(|f| f.key).collect();
        keys.sort_unstable();
        keys
    }
}

/// A rendered set that violates a rule this crate is supposed to hold.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SetDefect {
    /// KS-5: one family covered and not the other.
    #[error("the rendered set covers v4={v4} and v6={v6}; KS-5 requires both")]
    FamilyAsymmetry {
        /// Whether IPv4 has a Tier-1 scope deny.
        v4: bool,
        /// Whether IPv6 has one.
        v6: bool,
    },
    /// A boot-time filter names an ALE principal, which BFE cannot evaluate.
    #[error("the boot-time filter `{0}` names a principal, which BFE cannot evaluate")]
    BootTimeFilterNamesAPrincipal(&'static str),
    /// A Tier-2 object references a destination.
    #[error("the Tier-2 filter `{0}` references a destination prefix")]
    Tier2NamesADestination(&'static str),
    /// The posture marker is missing or duplicated.
    #[error("the set carries {0} posture markers; exactly one is required")]
    PostureNotExactlyOnce(usize),
}

/// What the adapter needs that the seam does not carry.
///
/// **Each field here is a reported gap, not a decision this adapter made up.**
/// [`twinvpn_platform::NetworkContract`] carries addresses, routes, DNS, the
/// ruleset selector and the MTU — and nothing that names the service binary, its
/// SID, the `local_network_access` setting of ADR-0012 KS-4, or the pinned update
/// origins KS-10a bounds the `UPDATE` class to. Those are facts the shell knows
/// about its own process and its own installation, so they are injected at
/// construction (CD-2) rather than discovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementConfig {
    /// The overlay interface's LUID. Tier 2 is **interface-scoped**, so this is
    /// the one identifier the whole permit turns on.
    ///
    /// A LUID rather than an index or a name: ADR-0016 O1 creates the adapter
    /// through Wintun, whose name a user can rename in Network Connections, and
    /// an index is reassigned when an adapter is removed and re-added. The LUID
    /// is what IP Helper and WFP both key on.
    pub overlay_luid: u64,
    /// The service binary's normalised path, for `FWPM_CONDITION_ALE_APP_ID`.
    ///
    /// KS-9(1)'s first half on this platform.
    pub service_app_id: &'static str,
    /// The service SID in SDDL form, for `FWPM_CONDITION_ALE_USER_ID`.
    ///
    /// KS-9(1)'s second half. ADR-0016 §11.2 fixes it as
    /// `NT SERVICE\TwinVPNService` under `SERVICE_SID_TYPE_UNRESTRICTED`.
    pub service_sid: &'static str,
    /// Whether ADR-0012 KS-4's `local_network_access` is `ALLOW` (its default in
    /// all three routing modes).
    pub local_network_access: bool,
    /// The on-link prefixes of the non-overlay interfaces.
    ///
    /// KS-4: "the permitted set is *on-link prefixes only*, recomputed on every
    /// network-change event, and never includes a destination reachable only via
    /// a router."
    pub on_link_prefixes: Vec<IpPrefix>,
    /// The privileged updater's own binary path, for KS-10a's `UPDATE` class.
    ///
    /// A **different** app-id from [`Self::service_app_id`], and that is what
    /// makes the class mean anything on this platform: WFP's ALE conditions are
    /// process-scoped, so two socket classes inside one process are
    /// indistinguishable to the engine, but two processes are not. See
    /// [`filters::Ks9Residual`].
    pub updater_app_id: Option<&'static str>,
    /// The pinned update origins KS-10a bounds the `UPDATE` class to.
    ///
    /// Empty means the class is **not installed at all**, which is the correct
    /// direction: KS-10a makes the class destination-bounded, and a bound of
    /// "everywhere" is not a bound.
    pub update_origins: Vec<IpPrefix>,
    /// A live captive-portal grant's permitted destinations (class 11), or empty.
    pub portal_grant: Vec<IpPrefix>,
}

impl EnforcementConfig {
    /// Whether KS-9(1)'s Windows predicate is satisfiable as configured.
    ///
    /// `false` means the bootstrap exemption rests on the app-id alone, which is
    /// a **weaker** predicate than KS-9 specifies — any process running as the
    /// same binary path would match — so the shell reports it rather than
    /// silently upgrading it to "close enough".
    #[must_use]
    pub const fn ks9_complete(&self) -> bool {
        !self.service_app_id.is_empty() && !self.service_sid.is_empty()
    }
}

/// The Tier-1 protected set that is true of **every** TwinVPN host, whatever
/// contract is in force: the overlay address space itself.
///
/// ADR-0010 §11.1 and AP-1 fix both — IPv4 `100.64.0.0/10` (RFC 6598) and the
/// pinned product ULA `fd7c:9e5d:2a10::/48`, "a pinned constant, identical in
/// every build". These are a **constant of the product**, not a policy this
/// adapter chose (CB-2).
///
/// # Why a baseline exists at all
///
/// `desktop-linux`'s review finding **R-6**: a `set_ruleset(_, Blocked)` that
/// renders from an empty route set emits zero deny filters and a "fail-closed"
/// swap opens the host. The baseline makes an empty-scope set unrepresentable:
/// every rendered set denies at least the overlay space, in both families, so
/// [`FilterSet::validate`] can never pass over nothing.
///
/// **A stated limit, referred rather than resolved.** KS-3a makes the Tier-1
/// protected set *mode-dependent*, and this baseline is only complete for
/// TwinNet-only mode. On a full-tunnel host the protected set is everything, and
/// a baseline of two prefixes under-covers it — which is why the baseline is a
/// **floor beneath a real contract's scope, never a substitute for it**, and why
/// [`filters::render`] re-derives scope from the applied contract rather than
/// from this. The same referral `desktop-linux` made as R-7's second half.
#[must_use]
pub fn baseline_protected() -> Vec<IpPrefix> {
    let mut out = Vec::new();
    if let Ok(v4) = IpPrefix::new(
        twinvpn_types::IpAddr::V4(twinvpn_types::V4Addr::from_octets([100, 64, 0, 0])),
        10,
    ) {
        out.push(v4);
    }
    let mut ula = [0u8; 16];
    ula[0] = 0xfd;
    ula[1] = 0x7c;
    ula[2] = 0x9e;
    ula[3] = 0x5d;
    ula[4] = 0x2a;
    ula[5] = 0x10;
    if let Ok(address) = twinvpn_types::V6Addr::new(ula, None) {
        if let Ok(v6) = IpPrefix::new(twinvpn_types::IpAddr::V6(address), 48) {
            out.push(v6);
        }
    }
    out
}

/// Who holds the rules on this target.
///
/// Both `true`, and both are facts about the Base Filtering Engine rather than
/// about this crate:
///
/// - `survives_core_exit`: ADR-0012 §11.6's Windows durability row is `✔` for
///   crash, `SIGKILL`-equivalent, update and reboot. A committed filter is a
///   kernel object owned by BFE, and `FWPM_FILTER_FLAG_PERSISTENT` reinstates it
///   across a boot with no process of ours running.
/// - `swap_is_atomic`: `FwpmTransactionBegin0` … `FwpmTransactionCommit0` is
///   applied by the engine as a unit, so there is no instant with no rules.
#[must_use]
pub const fn custody() -> EnforcementCustody {
    EnforcementCustody {
        survives_core_exit: true,
        swap_is_atomic: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_guid_renders_in_the_form_a_support_case_can_paste_into_a_tool() {
        assert_eq!(
            format!("{PROVIDER_KEY:?}"),
            "{7477696e-7670-6e00-5477-696e56504e01}"
        );
    }

    #[test]
    fn the_four_owned_keys_are_distinct() {
        // A collision would make the reclaim delete the posture marker, or make
        // the two postures indistinguishable — either of which reads back as a
        // ruleset that is not there.
        let keys = [
            PROVIDER_KEY,
            SUBLAYER_KEY,
            FILTER_POSTURE_BLOCKED,
            FILTER_POSTURE_PROTECTED,
        ];
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert_ne!(a, b, "{a:?} collides with {b:?}");
            }
        }
    }

    #[test]
    fn both_layers_are_enumerated_from_one_constant() {
        // The mechanism behind KS-5: there is no second place to add a layer,
        // so there is no place to forget one.
        assert_eq!(Layer::BOTH.len(), 2);
        assert_eq!(Layer::BOTH[0].family(), AddressFamily::V4);
        assert_eq!(Layer::BOTH[1].family(), AddressFamily::V6);
        for layer in Layer::BOTH {
            assert_eq!(Layer::for_family(layer.family()), layer);
        }
    }

    #[test]
    fn the_baseline_covers_both_families_and_is_the_products_own_constants() {
        let baseline = baseline_protected();
        assert_eq!(baseline.len(), 2, "one prefix per family, always");
        assert!(baseline.iter().any(|p| p.family() == AddressFamily::V4));
        assert!(baseline.iter().any(|p| p.family() == AddressFamily::V6));
        // ADR-0010 §11.1: the RFC 6598 block and the pinned ULA.
        let v4 = baseline
            .iter()
            .find(|p| p.family() == AddressFamily::V4)
            .expect("v4");
        assert_eq!(v4.prefix_len(), 10);
        let v6 = baseline
            .iter()
            .find(|p| p.family() == AddressFamily::V6)
            .expect("v6");
        assert_eq!(v6.prefix_len(), 48);
    }

    #[test]
    fn the_custody_declaration_is_about_bfe_and_not_about_this_process() {
        // CB-6's normal case, and ADR-0012 §11.6's Windows durability row.
        let custody = custody();
        assert!(custody.survives_core_exit);
        assert!(custody.swap_is_atomic);
    }

    #[test]
    fn loopback_and_markers_are_not_counted_as_exempt_egress() {
        // KS-11 compares exempt egress against the agent's own frame
        // accounting. Loopback never leaves the host and a marker matches
        // nothing, so counting either would put a floor under the comparison
        // that has nothing to do with the bootstrap channel.
        assert!(!TrafficClass::Loopback.is_exempt_egress());
        assert!(!TrafficClass::Marker.is_exempt_egress());
        assert!(!TrafficClass::OverlayEgress.is_exempt_egress());
        assert!(!TrafficClass::ProtectedScopeDeny.is_exempt_egress());
        assert!(TrafficClass::BootstrapExemption.is_exempt_egress());
        assert!(TrafficClass::ResolverExemption.is_exempt_egress());
        assert!(TrafficClass::UpdateExemption.is_exempt_egress());
    }

    #[test]
    fn ks9_is_incomplete_when_either_half_of_the_predicate_is_missing() {
        let mut config = EnforcementConfig {
            overlay_luid: 1,
            service_app_id: r"\device\harddiskvolume3\program files\twinvpn\twinvpnsvc.exe",
            service_sid: "S-1-5-80-0",
            local_network_access: true,
            on_link_prefixes: Vec::new(),
            updater_app_id: None,
            update_origins: Vec::new(),
            portal_grant: Vec::new(),
        };
        assert!(config.ks9_complete());
        config.service_sid = "";
        assert!(!config.ks9_complete(), "app-id alone is weaker than KS-9");
        config.service_sid = "S-1-5-80-0";
        config.service_app_id = "";
        assert!(!config.ks9_complete());
    }
}
