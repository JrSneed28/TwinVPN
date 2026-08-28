//! `ConnectivityManager.NetworkCallback` decoded into [`NetworkChange`], and the
//! snapshot diff that produces it. Target-free, and tested on this host.
//!
//! **Authority:** `docs/networking.md` §5.1 ("event-driven, never polled"),
//! §5.2's Android row (`ConnectivityManager.NetworkCallback`,
//! `PowerManager` idle callbacks), §5.4's roaming row; ADR-0010 **R6**;
//! ADR-0018 CB-2 and §11.6; [`twinvpn_platform::iface`].
//!
//! # The shape of Android's network model, and why a diff is needed
//!
//! `NetworkCallback` does not deliver "an address was added". It delivers
//! `onCapabilitiesChanged(Network, NetworkCapabilities)` and
//! `onLinkPropertiesChanged(Network, LinkProperties)` — **whole current
//! states**, repeatedly, for each `Network` the process is watching, plus
//! `onAvailable`/`onLost`. The seam's [`NetworkChange`] is a vocabulary of
//! *deltas*. Turning one into the other is a diff against the previously
//! observed snapshot, and it is exactly the layer §9.2's design rule says must
//! be target-free: an implementation that computed the delta in Kotlin would
//! move the roaming story from *executed* to *written, not compiled*.
//!
//! # Nothing here classifies
//!
//! `docs/networking.md` §5.4's roaming row: *"`MIGRATING`, not
//! `RECONNECTING`"* — and that is **the core's** call, not this module's.
//! [`NetworkChange`]'s own documentation says it: *"Every variant is a fact,
//! never an instruction: the adapter reports what happened and the core decides
//! what it means."* So a Wi-Fi→cellular handoff produces a sequence of facts
//! here and no verdict, and `tests/falsification.rs` drives the resulting facts
//! through the real `twinvpn-session` machine to show the verdict is made there.
//!
//! # R6, at the diff
//!
//! [`NetworkChange::DefaultRouteChanged`] is per family. ADR-0010 R6's case —
//! *"IPv6 appears **after** the tunnel is up"* — is a v6 default arriving while
//! the v4 one is unchanged, and a combined event would make that
//! indistinguishable from nothing having happened. The diff therefore compares
//! the two families **separately** and can emit one without the other.

use twinvpn_platform::iface::{InterfaceFacts, InterfaceIndex, InterfaceName, LinkClass};
use twinvpn_platform::{NetworkChange, PlatformError};
use twinvpn_types::{AddressFamily, InterfaceAddress, IpAddr, Nat64Prefix, PerFamily};

/// `NetworkCapabilities.TRANSPORT_*`, as a set.
///
/// A set rather than one value because Android genuinely reports more than one:
/// a VPN network carries `TRANSPORT_VPN` **and** the transport it runs over, and
/// a Wi-Fi-Aware or Ethernet-over-USB link can report two. Collapsing to a
/// single value at the JNI boundary would be a decision taken in the shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct TransportSet(u32);

impl TransportSet {
    /// `NetworkCapabilities.TRANSPORT_CELLULAR` (0).
    pub const CELLULAR: u32 = 1 << 0;
    /// `TRANSPORT_WIFI` (1).
    pub const WIFI: u32 = 1 << 1;
    /// `TRANSPORT_BLUETOOTH` (2).
    pub const BLUETOOTH: u32 = 1 << 2;
    /// `TRANSPORT_ETHERNET` (3).
    pub const ETHERNET: u32 = 1 << 3;
    /// `TRANSPORT_VPN` (4).
    pub const VPN: u32 = 1 << 4;
    /// `TRANSPORT_WIFI_AWARE` (5).
    pub const WIFI_AWARE: u32 = 1 << 5;
    /// `TRANSPORT_LOWPAN` (6).
    pub const LOWPAN: u32 = 1 << 6;

    /// Builds from the raw bitset the JNI shim assembles from
    /// `NetworkCapabilities.hasTransport(i)`.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// The raw bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether `transport` is present.
    #[must_use]
    pub const fn has(self, transport: u32) -> bool {
        self.0 & transport != 0
    }
}

/// The [`LinkClass`] a transport set reports.
///
/// **VPN wins.** A network carrying `TRANSPORT_VPN` is another product's tunnel
/// (or ours), and `docs/networking.md` §5.5 rule 4 requires a second
/// default-route-claiming interface to be *detected and named* rather than
/// treated as ordinary underlay. Reporting it as `Cellular` because it also
/// carries `TRANSPORT_CELLULAR` would hide exactly that.
///
/// `Unknown` is a legitimate answer and is preferred to a guess: it is what the
/// core reads when the OS does not say, and `docs/reliability.md`'s
/// `NET.LINK.DOWN_WIFI` / `NET.LINK.DOWN_CELLULAR` split degrades correctly on it.
#[must_use]
pub const fn link_class(transports: TransportSet) -> LinkClass {
    if transports.has(TransportSet::VPN) {
        LinkClass::Tunnel
    } else if transports.has(TransportSet::WIFI) || transports.has(TransportSet::WIFI_AWARE) {
        LinkClass::WiFi
    } else if transports.has(TransportSet::CELLULAR) {
        LinkClass::Cellular
    } else if transports.has(TransportSet::ETHERNET) {
        LinkClass::Ethernet
    } else {
        LinkClass::Unknown
    }
}

/// One `Network` as `ConnectivityManager` currently describes it.
///
/// Every field is a fact the OS reported. There is no field that is a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidNetwork {
    /// `Network.getNetworkHandle()`, the stable per-network identifier.
    ///
    /// Kept as the OS gives it and converted to an [`InterfaceIndex`] by
    /// [`AndroidNetwork::index`], because the seam compares interfaces by index
    /// and Android has no `if_index` on the Java side.
    pub handle: u64,
    /// `LinkProperties.getInterfaceName()`.
    pub name: InterfaceName,
    /// The transports this network carries.
    pub transports: TransportSet,
    /// The interface's own addresses, exactly as `LinkProperties` reported them.
    ///
    /// # The lossy conversion this used to carry, and the commit that closed it
    ///
    /// [`InterfaceFacts::addresses`] was `Vec<IpPrefix>`, which cannot
    /// represent a host address — `192.0.2.10/24` masked to `192.0.2.0/24` —
    /// and cannot represent a link-local address at all, because `V6Addr`
    /// demands a zone and `IpPrefix` rejects one (W-39). This crate recorded
    /// the defect and said the replacement was "queued as a coordinated
    /// cross-domain commit".
    ///
    /// **This is that commit.** `ownership.md` §9.6 **X-10** flipped the seam
    /// to [`InterfaceAddress`], which keeps the address and the prefix length
    /// as two facts instead of collapsing them into one. Nothing is masked
    /// away now, and `InterfaceAddress::network` derives the `IpPrefix` at the
    /// one place a route is what is wanted.
    pub addresses: Vec<InterfaceAddress>,
    /// Whether `LinkProperties.getRoutes()` holds a default route, per family.
    pub default_routes: PerFamily<bool>,
    /// `LinkProperties.getDnsServers()`.
    pub resolvers: Vec<IpAddr>,
    /// `LinkProperties.getMtu()`, or 0 where the OS does not say.
    pub mtu: u32,
    /// `!NetworkCapabilities.hasCapability(NET_CAPABILITY_NOT_METERED)`.
    pub metered: bool,
    /// `LinkProperties.getNat64Prefix()` (API 30+), or `None`.
    pub nat64: Option<Nat64Prefix>,
    /// `LinkProperties.isPrivateDnsActive()`.
    ///
    /// Carried because Android Private DNS takes precedence over a VPN's own
    /// resolvers, which ADR-0019's catalogue names as a user-actionable
    /// condition. It is reported, never worked around: §5.5 rule 2 forbids
    /// disabling a host resolver service.
    pub private_dns_active: bool,
    /// Whether the network is still usable (`onAvailable` seen, `onLost` not).
    pub is_up: bool,
}

impl AndroidNetwork {
    /// The seam's interface index for this network.
    ///
    /// Android's `networkHandle` is a 64-bit value whose low bits carry the
    /// netId; the seam's index is 32 bits. Truncating would collide, so the two
    /// halves are folded — the result is stable for a given handle within a
    /// boot, which is exactly what [`InterfaceIndex`]'s contract asks for
    /// ("opaque; compared only for equality").
    #[must_use]
    // The truncation IS the fold: both halves are combined and the result is
    // taken modulo 2^32 on purpose. `try_from` is not available in a `const fn`
    // and would have nothing to report here in any case.
    #[allow(clippy::cast_possible_truncation)]
    pub const fn index(&self) -> InterfaceIndex {
        InterfaceIndex((((self.handle >> 32) ^ self.handle) & 0xffff_ffff) as u32)
    }

    /// The seam's view of this network.
    #[must_use]
    pub fn facts(&self, is_overlay: bool) -> InterfaceFacts {
        InterfaceFacts {
            index: self.index(),
            name: self.name.clone(),
            addresses: self.addresses.clone(),
            has_default_route_v4: self.default_routes.v4,
            has_default_route_v6: self.default_routes.v6,
            is_overlay,
            is_up: self.is_up,
            mtu: self.mtu,
            link_class: link_class(self.transports),
        }
    }
}

/// Every network the process is currently watching, plus the power posture.
///
/// Ordered by handle so a diff is deterministic; [`Snapshot::ingest`] is the
/// only mutator and it maintains the order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    networks: Vec<AndroidNetwork>,
    metered: bool,
    low_power: bool,
}

/// The most networks one process will track.
///
/// `ConnectivityManager` will not hand an app an unbounded set, but the input
/// arrives across a JNI boundary and `ownership.md` §6 rule 10 requires the
/// allocation to be bounded by something other than the sender's honesty.
pub const MAX_TRACKED_NETWORKS: usize = 32;

impl Snapshot {
    /// An empty snapshot: nothing observed yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            networks: Vec::new(),
            metered: false,
            low_power: false,
        }
    }

    /// The networks, in handle order.
    #[must_use]
    pub fn networks(&self) -> &[AndroidNetwork] {
        &self.networks
    }

    /// Whether the current default link is metered.
    #[must_use]
    pub const fn metered(&self) -> bool {
        self.metered
    }

    /// Whether the host is in a low-power state (Doze, battery saver).
    #[must_use]
    pub const fn low_power(&self) -> bool {
        self.low_power
    }

    /// Sets the power posture. Returns whether it changed.
    pub fn set_power(&mut self, metered: bool, low_power: bool) -> bool {
        let changed = self.metered != metered || self.low_power != low_power;
        self.metered = metered;
        self.low_power = low_power;
        changed
    }

    /// Inserts or replaces one network.
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] once [`MAX_TRACKED_NETWORKS`] would
    /// be exceeded. Refused rather than evicted: silently dropping a network
    /// would make the *next* diff report it as removed, which is a link-down
    /// event that did not happen.
    pub fn ingest(&mut self, network: AndroidNetwork) -> Result<(), PlatformError> {
        match self
            .networks
            .binary_search_by_key(&network.handle, |n| n.handle)
        {
            Ok(at) => self.networks[at] = network,
            Err(at) => {
                if self.networks.len() >= MAX_TRACKED_NETWORKS {
                    return Err(crate::oserr::unavailable(
                        "ConnectivityManager.onAvailable",
                        libc::ENOSPC,
                    ));
                }
                self.networks.insert(at, network);
            }
        }
        Ok(())
    }

    /// Removes one network (`onLost`). Returns whether it was present.
    pub fn forget(&mut self, handle: u64) -> bool {
        match self.networks.binary_search_by_key(&handle, |n| n.handle) {
            Ok(at) => {
                self.networks.remove(at);
                true
            }
            Err(_) => false,
        }
    }

    /// Whether any tracked non-VPN network carries a default route for `family`.
    ///
    /// VPN networks are excluded because our own tunnel carries a default route
    /// by construction, and counting it would make "the underlay has a way out"
    /// permanently true — the precise question ADR-0010 R6 asks.
    #[must_use]
    pub fn underlay_has_default(&self, family: AddressFamily) -> bool {
        self.networks.iter().any(|n| {
            n.is_up && !n.transports.has(TransportSet::VPN) && *n.default_routes.get(family)
        })
    }
}

/// The deltas between two snapshots, in a deterministic order.
///
/// Order: removals, then additions, then per-network changes, then the two
/// aggregate facts (default routes per family, resolvers), then posture. It is
/// fixed so a test can assert on the sequence; the seam attaches no meaning to
/// the order beyond "these all happened".
#[must_use]
pub fn diff(old: &Snapshot, new: &Snapshot) -> Vec<NetworkChange> {
    let mut out = Vec::new();

    for gone in &old.networks {
        if !new.networks.iter().any(|n| n.handle == gone.handle) {
            out.push(NetworkChange::InterfaceRemoved(gone.index()));
        }
    }
    for fresh in &new.networks {
        if !old.networks.iter().any(|n| n.handle == fresh.handle) {
            out.push(NetworkChange::InterfaceAdded(fresh.index()));
        }
    }

    for now in &new.networks {
        let Some(before) = old.networks.iter().find(|n| n.handle == now.handle) else {
            // A network that has just appeared reports its addresses through
            // `InterfaceAdded` plus the caller's `enumerate()`, not as a burst
            // of `AddressAdded`. `InterfaceProvider::subscribe`'s contract is
            // explicit: replaying initial state as changes would make "we just
            // started" and "the network just changed" indistinguishable.
            continue;
        };
        if before.is_up != now.is_up {
            out.push(NetworkChange::LinkStateChanged {
                interface: now.index(),
                is_up: now.is_up,
            });
        }
        for was in &before.addresses {
            if !now.addresses.contains(was) {
                out.push(NetworkChange::AddressRemoved {
                    interface: now.index(),
                    address: was.address(),
                });
            }
        }
        for is in &now.addresses {
            if !before.addresses.contains(is) {
                out.push(NetworkChange::AddressAdded {
                    interface: now.index(),
                    address: is.address(),
                });
            }
        }
    }

    // R6: the two families are compared separately and either may be emitted
    // alone. A combined event would hide "IPv6 appeared after the tunnel is up".
    for family in [AddressFamily::V4, AddressFamily::V6] {
        let was = old.underlay_has_default(family);
        let is = new.underlay_has_default(family);
        if was != is {
            out.push(NetworkChange::DefaultRouteChanged {
                family,
                present: is,
            });
        }
    }

    if resolvers_of(old) != resolvers_of(new) {
        out.push(NetworkChange::ResolversChanged);
    }

    let old_nat64 = nat64_of(old);
    let new_nat64 = nat64_of(new);
    if old_nat64 != new_nat64 {
        out.push(NetworkChange::Nat64PrefixChanged(new_nat64));
    }

    if old.metered != new.metered || old.low_power != new.low_power {
        out.push(NetworkChange::LinkPostureChanged {
            metered: new.metered,
            low_power: new.low_power,
        });
    }

    out
}

/// Every resolver across every live non-VPN network, in observation order.
fn resolvers_of(snapshot: &Snapshot) -> Vec<IpAddr> {
    snapshot
        .networks
        .iter()
        .filter(|n| n.is_up && !n.transports.has(TransportSet::VPN))
        .flat_map(|n| n.resolvers.iter().copied())
        .collect()
}

/// The NAT64 prefix in force, if exactly one live underlay reports one.
///
/// Two networks reporting different prefixes is reported as **none**, not as
/// whichever came first: ADR-0010 §11.7 makes synthesis a pure function of the
/// prefix, and synthesising against the wrong one produces an address that
/// silently goes nowhere.
fn nat64_of(snapshot: &Snapshot) -> Option<Nat64Prefix> {
    let mut found: Option<Nat64Prefix> = None;
    for network in snapshot
        .networks
        .iter()
        .filter(|n| n.is_up && !n.transports.has(TransportSet::VPN))
    {
        match (found, network.nat64) {
            (_, None) => {}
            (None, Some(p)) => found = Some(p),
            (Some(a), Some(b)) if a == b => {}
            (Some(_), Some(_)) => return None,
        }
    }
    found
}

#[cfg(test)]
mod tests;
