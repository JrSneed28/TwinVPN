//! Interface enumeration and change **notification**, over IP Helper.
//!
//! **Authority:** [`twinvpn_platform::iface`], `docs/networking.md` §5.1
//! ("`subscribe_network_change(cb)` — event-driven, never polled"), ADR-0010 R6,
//! ADR-0018 §11.6, ADR-0022 LC-23b (correctness-bearing lifecycle events reach
//! the authority directly, never through the UI).
//!
//! # W-25 again: the other thing the C ABI cannot do
//!
//! `twinvpn.h`'s F-9 vtable has **no interface enumerator**, and it deliberately
//! omits `subscribe_network_change` because handing the OS a pointer into the
//! core would break F-6's reentrancy rule. A shell binding only the ABI must
//! therefore submit `host.network_changed` commands built from *some* source it
//! does not have. `shells/windows` binds this crate as a Rust crate, so the
//! stream is a real [`futures_core::Stream`] and the enumeration is a real
//! `GetAdaptersAddresses`.
//!
//! # A change is an event, and the reason is not efficiency
//!
//! > A poll interval is a window in which the host has moved networks and the
//! > core still believes it has not. Every roaming and failover deadline in
//! > `docs/reliability.md` §5 is measured from the moment the change is *known*,
//! > so a poll interval is added directly to `T_FAILOVER_TARGET`.
//!
//! The stream carries **changes and not the initial state**. That is why
//! [`NotificationType::Initial`] is dropped by [`decode_change`] rather than
//! reported as an add: the seam is explicit that "an adapter that replayed the
//! initial state as a burst of `Added` events would make 'we just started' and
//! 'the network just changed' indistinguishable". A caller that has just
//! subscribed also calls [`InterfaceProvider::enumerate`], which is where the
//! initial state comes from.
//!
//! # A dropped event is recorded, never silently coalesced
//!
//! The channel is bounded. When the core is not draining, the excess is reported
//! as [`NetworkChange::EventsLost`] with a count ([`DropLedger`]), because "an
//! adapter that silently coalesces leaves the core believing it has a complete
//! picture; an adapter that reports the gap lets the core re-enumerate and
//! recover".
//!
//! # What the three `Notify*` APIs do not tell us
//!
//! `NotifyIpInterfaceChange`, `NotifyRouteChange2` and
//! `NotifyUnicastIpAddressChange` are the whole of what this build subscribes
//! to, and three [`NetworkChange`] variants have no source in them:
//! `ResolversChanged`, `Nat64PrefixChanged` and `LinkPostureChanged`. They are
//! **not emitted by this build**. Each is a stated gap rather than a silence:
//! see this module's report. Nothing here fabricates one, because a fabricated
//! posture change is worse than an absent one.
//!
//! # This module is mostly target-free
//!
//! The classification, the notification decode, the facts assembly and the drop
//! accounting are plain functions over plain data, tested on the Linux host this
//! crate was written on. Only `imp` — `GetAdaptersAddresses` and the three
//! registrations — needs Windows, and **it has never executed**.

use std::pin::Pin;

use futures_core::future::BoxFuture;
use futures_core::Stream;
use twinvpn_platform::{
    InterfaceFacts, InterfaceIndex, InterfaceName, InterfaceProvider, LinkClass, NetworkChange,
    PlatformError,
};
use twinvpn_types::{AddressFamily, InterfaceAddress, IpAddr, IpPrefix, V4Addr, V6Addr};

use crate::oserr;
use crate::route::InterfaceLuid;
use crate::shutdown::ShutdownLatch;

/// How many changes are buffered before the adapter starts counting drops.
///
/// **A decision recorded as one.** Sized for a full dual-stack network
/// transition on a host with a handful of adapters — link down, addresses gone,
/// default routes gone, link up, addresses back, routes back — so an ordinary
/// roam never drops. Beyond that, dropping with a **count** is better than
/// growing without bound, which is `ownership.md` §6 rule 10 applied to an event
/// queue. The same figure `twinvpn-platform-linux` chose, deliberately: two
/// adapters that buffered differently would make a roaming test that passes on
/// one platform mean nothing on the other.
pub const CHANGE_QUEUE: usize = 256;

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// `IF_TYPE_ETHERNET_CSMACD`.
pub const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
/// `IF_TYPE_SOFTWARE_LOOPBACK`.
pub const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
/// `IF_TYPE_PROP_VIRTUAL`.
pub const IF_TYPE_PROP_VIRTUAL: u32 = 53;
/// `IF_TYPE_IEEE80211`.
pub const IF_TYPE_IEEE80211: u32 = 71;
/// `IF_TYPE_TUNNEL`.
pub const IF_TYPE_TUNNEL: u32 = 131;
/// `IF_TYPE_IEEE1394`.
pub const IF_TYPE_IEEE1394: u32 = 144;
/// `IF_TYPE_WWANPP` — GSM-family cellular.
pub const IF_TYPE_WWANPP: u32 = 243;
/// `IF_TYPE_WWANPP2` — CDMA-family cellular.
pub const IF_TYPE_WWANPP2: u32 = 244;

/// `IfOperStatusUp`.
pub const IF_OPER_STATUS_UP: u32 = 1;

/// The link class the OS reports.
///
/// A **domain fact**, not an OS branch: `docs/reliability.md` emits
/// `NET.LINK.DOWN_WIFI` and `NET.LINK.DOWN_CELLULAR` as distinct codes, so the
/// core needs the class and CB-3 is not violated by having it. Getting WiFi and
/// Cellular the wrong way round is therefore a user-visible defect and not
/// cosmetics: one of those two codes tells a user their Wi-Fi dropped and the
/// other tells them their mobile data did.
///
/// Windows answers this in one field, `IP_ADAPTER_ADDRESSES.IfType`, which is
/// more than Linux offers — and where it does not say, the answer is
/// [`LinkClass::Unknown`]. That is a fact, not a failure, and it is better than
/// a guess that turns a wired link into a metered one.
#[must_use]
pub const fn link_class(if_type: u32) -> LinkClass {
    match if_type {
        IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE1394 => LinkClass::Ethernet,
        IF_TYPE_IEEE80211 => LinkClass::WiFi,
        IF_TYPE_WWANPP | IF_TYPE_WWANPP2 => LinkClass::Cellular,
        IF_TYPE_SOFTWARE_LOOPBACK => LinkClass::Loopback,
        IF_TYPE_TUNNEL | IF_TYPE_PROP_VIRTUAL => LinkClass::Tunnel,
        _ => LinkClass::Unknown,
    }
}

/// Whether an adapter is one of **ours**.
///
/// Answered by the name this product chooses ([`crate::OVERLAY_PREFIX`]) and
/// **not** by the adapter being a Wintun device: a Wintun adapter another
/// product created is a third party's, and treating it as ours would make
/// ADR-0012's Tier-2 interface-scoped permit authorise somebody else's tunnel.
#[must_use]
pub fn is_overlay(name: &str) -> bool {
    name.starts_with(crate::OVERLAY_PREFIX)
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

/// One adapter, as `GetAdaptersAddresses` reports it, reduced to what the seam
/// carries.
///
/// Defined here rather than imported from `windows-sys` so that the assembly —
/// where a family flag or a default-route flag can be dropped — is testable on
/// this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterRow {
    /// `IfIndex`.
    pub index: u32,
    /// `Luid`. Carried because IP Helper and WFP both key on it and an index is
    /// reassigned when an adapter is removed and re-added.
    pub luid: InterfaceLuid,
    /// `FriendlyName`.
    pub name: String,
    /// `IfType`.
    pub if_type: u32,
    /// `OperStatus`.
    pub oper_status: u32,
    /// `Mtu`.
    pub mtu: u32,
    /// Every unicast address, with its `OnLinkPrefixLength`.
    pub addresses: Vec<(IpAddr, u32)>,
    /// Whether a v4 default route points through it.
    pub has_default_route_v4: bool,
    /// Whether a v6 default route points through it.
    pub has_default_route_v6: bool,
}

/// Assembles one interface's facts.
///
/// # Errors
///
/// [`PlatformError::AdapterUnavailable`] if the OS supplied a name the seam
/// refuses — empty, over `InterfaceName::MAX_BYTES`, or control-bearing. An
/// adapter that hands the core a 4 KiB adapter name is malfunctioning, and
/// truncating it would produce a name that matches the wrong interface.
pub fn facts_from(row: &AdapterRow) -> Result<InterfaceFacts, PlatformError> {
    let name = InterfaceName::new(&row.name)?;
    let mut addresses = Vec::with_capacity(row.addresses.len());
    for (address, prefix_len) in &row.addresses {
        // Kept exactly as the OS reported it. This used to mask down to an
        // `IpPrefix`, which normalised away the host bits an interface address
        // exists to carry, and stripped the scope zone from a link-local — the
        // half of finding X-10 this adapter was on: it reported `fe80::/10` with
        // no zone while `twinvpn-platform-linux` dropped it entirely, so the core
        // saw a different address set for one host depending on which adapter was
        // bound. Both now report the same thing, and both keep the zone.
        if let Ok(interface_address) = InterfaceAddress::new(*address, *prefix_len) {
            if !addresses.contains(&interface_address) {
                addresses.push(interface_address);
            }
        }
    }
    Ok(InterfaceFacts {
        index: InterfaceIndex(row.index),
        is_overlay: is_overlay(name.as_str()),
        name,
        addresses,
        has_default_route_v4: row.has_default_route_v4,
        // Separate from the v4 flag, never a family-keyed map: ADR-0010 R6 needs
        // "does v6 have a way out" as its own question, because its case is v6
        // appearing AFTER the tunnel is up.
        has_default_route_v6: row.has_default_route_v6,
        is_up: row.oper_status == IF_OPER_STATUS_UP,
        mtu: row.mtu,
        link_class: link_class(row.if_type),
    })
}

/// Masks an interface address down to the prefix it sits on.
///
/// [`IpPrefix`] enforces canonical form and **refuses** `10.0.0.1/24` rather
/// than normalizing it — normalizing attacker input before a policy check is how
/// a rule intended to match one network comes to match another. Masking here is
/// this adapter's own arithmetic on an OS-supplied value, not a normalization of
/// untrusted input.
///
/// Returns `None` for a prefix length the family cannot carry.
#[must_use]
pub fn mask_to_prefix(address: IpAddr, prefix_len: u32) -> Option<IpPrefix> {
    match address {
        IpAddr::V4(a) => {
            if prefix_len > 32 {
                return None;
            }
            let mut octets = a.octets();
            mask_bits(&mut octets, prefix_len);
            IpPrefix::new(IpAddr::V4(V4Addr::from_octets(octets)), prefix_len).ok()
        }
        IpAddr::V6(a) => {
            if prefix_len > 128 {
                return None;
            }
            let mut octets = a.octets();
            mask_bits(&mut octets, prefix_len);
            // `prefix_base` rather than `V6Addr::new`: a *prefix* has no
            // interface, and `V6Addr::new`'s insistence on a zone for `fe80::/10`
            // is a rule about addresses. Using it here is what lets this adapter
            // report a link-local prefix at all — see the module's report, where
            // the divergence from `twinvpn-platform-linux` is recorded, because
            // two adapters that show the core different address sets for the
            // same host is a difference somebody has to know about.
            let base = V6Addr::prefix_base(octets).ok()?;
            IpPrefix::new(IpAddr::V6(base), prefix_len).ok()
        }
    }
}

/// Clears every bit below `prefix_len`.
fn mask_bits(octets: &mut [u8], prefix_len: u32) {
    let bits = prefix_len as usize;
    for (index, byte) in octets.iter_mut().enumerate() {
        let high = index * 8;
        if high >= bits {
            *byte = 0;
        } else if high + 8 > bits {
            let keep = bits - high;
            *byte &= 0xFFu8 << (8 - keep);
        }
    }
}

// ---------------------------------------------------------------------------
// Notification
// ---------------------------------------------------------------------------

/// `MIB_NOTIFICATION_TYPE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotificationType {
    /// `MibParameterNotification` — an existing row's fields changed.
    Parameter,
    /// `MibAddInstance`.
    Add,
    /// `MibDeleteInstance`.
    Delete,
    /// `MibInitialNotification` — the one delivered at registration.
    Initial,
}

impl NotificationType {
    /// Decodes the enumeration IP Helper passes to the callback.
    ///
    /// `None` for a value Windows should not produce. Dropping it is the honest
    /// answer: a notification whose kind we cannot name is one whose meaning we
    /// cannot state, and guessing "add" would invent an interface.
    #[must_use]
    pub const fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(NotificationType::Parameter),
            1 => Some(NotificationType::Add),
            2 => Some(NotificationType::Delete),
            3 => Some(NotificationType::Initial),
            _ => None,
        }
    }
}

/// One row delivered to one of the three notification callbacks.
///
/// A plain value rather than the `windows-sys` structs, so [`decode_change`] is
/// a pure function this host can exercise over every combination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notification {
    /// `NotifyIpInterfaceChange` — a `MIB_IPINTERFACE_ROW`.
    Interface {
        /// `InterfaceIndex`.
        index: InterfaceIndex,
        /// `Connected`.
        connected: bool,
        /// Which kind of notification.
        kind: NotificationType,
    },
    /// `NotifyUnicastIpAddressChange` — a `MIB_UNICASTIPADDRESS_ROW`.
    Address {
        /// `InterfaceIndex`.
        index: InterfaceIndex,
        /// The address, already canonical.
        address: IpAddr,
        /// Which kind of notification.
        kind: NotificationType,
    },
    /// `NotifyRouteChange2` — a `MIB_IPFORWARD_ROW2`.
    Route {
        /// Which family the row is in.
        family: AddressFamily,
        /// `DestinationPrefix.PrefixLength`. A default route is zero.
        prefix_len: u8,
        /// Which kind of notification.
        kind: NotificationType,
    },
}

/// Turns one notification into the fact the core reacts to.
///
/// Returns `None` for a notification the seam has no variant for. Every such
/// case is deliberate and is named in the tests:
///
/// - **[`NotificationType::Initial`], always.** The stream carries changes and
///   not the initial state.
/// - **A parameter change on an address.** A lifetime or DAD-state change is not
///   an address appearing or disappearing, and there is no `AddressChanged`.
/// - **A non-default route change.** [`NetworkChange`] has
///   `DefaultRouteChanged` and no general route event, because ADR-0010 R6's
///   question is "does this family have a way out".
#[must_use]
pub fn decode_change(notification: &Notification) -> Option<NetworkChange> {
    match notification {
        // The initial notification is dropped for every kind, before anything
        // else is considered.
        Notification::Interface {
            kind: NotificationType::Initial,
            ..
        }
        | Notification::Address {
            kind: NotificationType::Initial,
            ..
        }
        | Notification::Route {
            kind: NotificationType::Initial,
            ..
        } => None,

        Notification::Interface { index, kind, .. } if *kind == NotificationType::Add => {
            Some(NetworkChange::InterfaceAdded(*index))
        }
        Notification::Interface { index, kind, .. } if *kind == NotificationType::Delete => {
            Some(NetworkChange::InterfaceRemoved(*index))
        }
        Notification::Interface {
            index, connected, ..
        } => Some(NetworkChange::LinkStateChanged {
            interface: *index,
            is_up: *connected,
        }),

        Notification::Address {
            index,
            address,
            kind,
        } => match kind {
            NotificationType::Add => Some(NetworkChange::AddressAdded {
                interface: *index,
                address: *address,
            }),
            NotificationType::Delete => Some(NetworkChange::AddressRemoved {
                interface: *index,
                address: *address,
            }),
            NotificationType::Parameter | NotificationType::Initial => None,
        },

        Notification::Route {
            family,
            prefix_len,
            kind,
        } => {
            if *prefix_len != 0 {
                return None;
            }
            match kind {
                // Per family, because ADR-0010 R6's case — "IPv6 appears *after*
                // the tunnel is up" — is precisely a v6 default route arriving
                // while the v4 one is unchanged, and a combined event would make
                // that indistinguishable from nothing having happened.
                NotificationType::Add => Some(NetworkChange::DefaultRouteChanged {
                    family: *family,
                    present: true,
                }),
                NotificationType::Delete => Some(NetworkChange::DefaultRouteChanged {
                    family: *family,
                    present: false,
                }),
                NotificationType::Parameter | NotificationType::Initial => None,
            }
        }
    }
}

/// Counts the changes a full channel dropped.
///
/// ADR-0018 §11.6: "a dropped event is itself recorded". The count is reported
/// the moment there is room, so the core can re-enumerate and recover rather
/// than trusting a picture that is missing an unknown number of facts.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DropLedger {
    lost: u64,
}

impl DropLedger {
    /// A ledger with nothing lost.
    #[must_use]
    pub const fn new() -> Self {
        Self { lost: 0 }
    }

    /// Records one change that could not be delivered.
    ///
    /// Saturating: a host that dropped `u64::MAX` events has a problem the exact
    /// number does not help with, and wrapping to zero would report "nothing was
    /// lost" at the moment that is least true.
    pub fn record(&mut self) {
        self.lost = self.lost.saturating_add(1);
    }

    /// How many are outstanding.
    #[must_use]
    pub const fn outstanding(&self) -> u64 {
        self.lost
    }

    /// The marker to send, if there is anything to report.
    ///
    /// The count is cleared only by [`Self::clear`], which the caller invokes
    /// once the marker has actually been accepted by the channel — so a marker
    /// that itself could not be delivered does not lose the count it carried.
    #[must_use]
    pub const fn marker(&self) -> Option<NetworkChange> {
        if self.lost == 0 {
            None
        } else {
            Some(NetworkChange::EventsLost {
                count: Some(self.lost),
            })
        }
    }

    /// Clears the count, after the marker has been delivered.
    pub fn clear(&mut self) {
        self.lost = 0;
    }
}

// ---------------------------------------------------------------------------
// The provider
// ---------------------------------------------------------------------------

/// Enumerates and watches Windows adapters.
pub struct WindowsInterfaceProvider {
    shutdown: ShutdownLatch,
}

impl WindowsInterfaceProvider {
    /// Binds the provider to the adapter's shutdown latch.
    #[must_use]
    pub const fn new(shutdown: ShutdownLatch) -> Self {
        Self { shutdown }
    }
}

impl InterfaceProvider for WindowsInterfaceProvider {
    fn enumerate(&self) -> BoxFuture<'_, Result<Vec<InterfaceFacts>, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            imp::enumerate()
        })
    }

    fn subscribe(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = NetworkChange> + Send>>, PlatformError> {
        self.shutdown.check()?;
        imp::subscribe(self.shutdown.clone())
    }
}

impl crate::sys::InterfaceTable for WindowsInterfaceProvider {
    fn enumerate(&self) -> Result<Vec<InterfaceFacts>, PlatformError> {
        self.shutdown.check()?;
        imp::enumerate()
    }

    fn subscribe(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = NetworkChange> + Send>>, PlatformError> {
        self.shutdown.check()?;
        imp::subscribe(self.shutdown.clone())
    }
}

/// The stream the subscription hands back.
pub struct ChangeStream {
    rx: tokio::sync::mpsc::Receiver<NetworkChange>,
}

impl ChangeStream {
    /// Wraps a receiver.
    #[must_use]
    pub const fn new(rx: tokio::sync::mpsc::Receiver<NetworkChange>) -> Self {
        Self { rx }
    }
}

impl Stream for ChangeStream {
    type Item = NetworkChange;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

#[cfg(windows)]
mod imp;

#[cfg(not(windows))]
mod imp {
    //! The non-Windows stand-in.
    //!
    //! This adapter enumerates no interface on a host that is not Windows, and
    //! says so by name rather than by returning an empty list — an empty list
    //! reads as "this host has no network", which is a claim about the host
    //! rather than about the adapter. It exists so the target-free layers above
    //! compile and run their tests on the Linux host this crate was written on.

    use std::pin::Pin;

    use futures_core::Stream;
    use twinvpn_platform::{InterfaceFacts, NetworkChange, PlatformError};

    use crate::shutdown::ShutdownLatch;

    fn unsupported(call: &'static str) -> PlatformError {
        crate::oserr::from_status(
            crate::oserr::Win32Error(crate::oserr::ERROR_NOT_SUPPORTED),
            call,
            crate::oserr::Context::InterfaceQuery,
        )
    }

    pub(super) fn enumerate() -> Result<Vec<InterfaceFacts>, PlatformError> {
        Err(unsupported("GetAdaptersAddresses"))
    }

    pub(super) fn subscribe(
        _shutdown: ShutdownLatch,
    ) -> Result<Pin<Box<dyn Stream<Item = NetworkChange> + Send>>, PlatformError> {
        Err(unsupported("NotifyIpInterfaceChange"))
    }
}

/// The `IF_TYPE_*` and `IfOperStatus` numbers this module hard-codes, checked
/// against `windows-sys`.
///
/// A drifted number turns a Wi-Fi link into an `Unknown` one, which changes
/// which of `NET.LINK.DOWN_WIFI` and `NET.LINK.DOWN_CELLULAR` a user sees.
#[cfg(windows)]
mod win_constants {
    use windows_sys::Win32::NetworkManagement::IpHelper as ip;

    const _: () = {
        assert!(super::IF_TYPE_ETHERNET_CSMACD == ip::IF_TYPE_ETHERNET_CSMACD);
        assert!(super::IF_TYPE_SOFTWARE_LOOPBACK == ip::IF_TYPE_SOFTWARE_LOOPBACK);
        assert!(super::IF_TYPE_PROP_VIRTUAL == ip::IF_TYPE_PROP_VIRTUAL);
        assert!(super::IF_TYPE_IEEE80211 == ip::IF_TYPE_IEEE80211);
        assert!(super::IF_TYPE_TUNNEL == ip::IF_TYPE_TUNNEL);
        assert!(super::IF_TYPE_IEEE1394 == ip::IF_TYPE_IEEE1394);
        assert!(super::IF_TYPE_WWANPP == ip::IF_TYPE_WWANPP);
        assert!(super::IF_TYPE_WWANPP2 == ip::IF_TYPE_WWANPP2);
    };
}

/// Keeps `oserr` reachable from the non-Windows build's error path.
const _: fn(&'static str) -> twinvpn_platform::PlatformError = oserr::unavailable;

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(V4Addr::from_octets(octets))
    }

    fn v6(text: &str) -> IpAddr {
        let octets = text
            .parse::<std::net::Ipv6Addr>()
            .expect("literal")
            .octets();
        IpAddr::V6(V6Addr::prefix_base(octets).expect("no zone"))
    }

    fn row() -> AdapterRow {
        AdapterRow {
            index: 12,
            luid: InterfaceLuid(0x0001_0000_0000_000c),
            name: "Ethernet".to_owned(),
            if_type: IF_TYPE_ETHERNET_CSMACD,
            oper_status: IF_OPER_STATUS_UP,
            mtu: 1500,
            addresses: vec![(v4([192, 0, 2, 10]), 24)],
            has_default_route_v4: true,
            has_default_route_v6: false,
        }
    }

    #[test]
    fn the_whole_if_type_table_classifies_and_an_unknown_type_says_unknown() {
        assert_eq!(link_class(IF_TYPE_ETHERNET_CSMACD), LinkClass::Ethernet);
        assert_eq!(link_class(IF_TYPE_IEEE1394), LinkClass::Ethernet);
        assert_eq!(link_class(IF_TYPE_IEEE80211), LinkClass::WiFi);
        assert_eq!(link_class(IF_TYPE_WWANPP), LinkClass::Cellular);
        assert_eq!(link_class(IF_TYPE_WWANPP2), LinkClass::Cellular);
        assert_eq!(link_class(IF_TYPE_SOFTWARE_LOOPBACK), LinkClass::Loopback);
        assert_eq!(link_class(IF_TYPE_TUNNEL), LinkClass::Tunnel);
        assert_eq!(link_class(IF_TYPE_PROP_VIRTUAL), LinkClass::Tunnel);
        // No guess: an unrecognised type is Unknown, never Ethernet.
        for unknown in [0u32, 1, 23, 100, 242, 245, u32::MAX] {
            assert_eq!(link_class(unknown), LinkClass::Unknown, "{unknown}");
        }
    }

    #[test]
    fn wifi_and_cellular_are_never_confused_because_the_codes_differ() {
        // `docs/reliability.md` emits NET.LINK.DOWN_WIFI and
        // NET.LINK.DOWN_CELLULAR as distinct codes: one tells a user their
        // Wi-Fi dropped and the other tells them their mobile data did.
        assert_ne!(
            link_class(IF_TYPE_IEEE80211),
            link_class(IF_TYPE_WWANPP),
            "a swapped table is a user-visible defect"
        );
    }

    #[test]
    fn ours_is_answered_by_the_name_and_never_by_the_driver() {
        // A Wintun adapter another product created is a third party's, and
        // treating it as ours would make ADR-0012's Tier-2 permit authorise
        // somebody else's tunnel.
        assert!(is_overlay("TwinVPN"));
        assert!(is_overlay("TwinVPN Tunnel"));
        assert!(!is_overlay("WireGuard Tunnel"));
        assert!(!is_overlay("Wintun Userspace Tunnel"));
        assert!(!is_overlay("twinvpn"), "the prefix is exact");
    }

    #[test]
    fn an_overlay_adapter_is_reported_as_ours_and_a_third_partys_is_not() {
        let mut ours = row();
        ours.name = "TwinVPN".to_owned();
        ours.if_type = IF_TYPE_PROP_VIRTUAL;
        assert!(facts_from(&ours).expect("facts").is_overlay);

        let mut theirs = row();
        theirs.name = "Wintun Userspace Tunnel".to_owned();
        theirs.if_type = IF_TYPE_PROP_VIRTUAL;
        let facts = facts_from(&theirs).expect("facts");
        assert!(!facts.is_overlay);
        assert_eq!(facts.link_class, LinkClass::Tunnel);
    }

    #[test]
    fn the_two_default_route_flags_are_separate_facts() {
        // ADR-0010 R6 needs "does v6 have a way out" as its own question,
        // because its case is v6 appearing AFTER the tunnel is up.
        let facts = facts_from(&row()).expect("facts");
        assert!(facts.has_default_route(AddressFamily::V4));
        assert!(!facts.has_default_route(AddressFamily::V6));
    }

    /// **The host bits survive the crossing.**
    ///
    /// This test used to assert the opposite — that `192.0.2.10/24` arrived as
    /// `192.0.2.0/24` — because `IpPrefix` refuses a set host bit and this
    /// adapter masked before handing the value over. The masked value named a
    /// network nothing answers on, which is what
    /// `twinvpn-core::establish::host_address` then had to refuse. The seam now
    /// carries `InterfaceAddress`, so there is nothing to mask.
    #[test]
    fn an_interface_address_crosses_with_its_host_bits() {
        let facts = facts_from(&row()).expect("facts");
        assert_eq!(facts.addresses.len(), 1);
        assert_eq!(facts.addresses[0].address(), v4([192, 0, 2, 10]));
        assert_eq!(facts.addresses[0].prefix_len(), 24);
        // And the network is still derivable, by name, when a route is wanted.
        assert_eq!(facts.addresses[0].network().address(), v4([192, 0, 2, 0]));
    }

    #[test]
    fn masking_is_correct_at_every_byte_boundary_and_inside_one() {
        for (address, len, expected) in [
            (v4([255, 255, 255, 255]), 0u32, v4([0, 0, 0, 0])),
            (v4([10, 1, 2, 3]), 8, v4([10, 0, 0, 0])),
            (v4([10, 1, 2, 3]), 12, v4([10, 0, 0, 0])),
            (v4([10, 17, 2, 3]), 12, v4([10, 16, 0, 0])),
            (v4([192, 0, 2, 10]), 31, v4([192, 0, 2, 10])),
            (v4([192, 0, 2, 11]), 31, v4([192, 0, 2, 10])),
            (v4([192, 0, 2, 10]), 32, v4([192, 0, 2, 10])),
        ] {
            let prefix = mask_to_prefix(address, len).expect("maskable");
            assert_eq!(prefix.address(), expected, "{address:?}/{len}");
            assert_eq!(prefix.prefix_len(), len);
        }
    }

    #[test]
    fn a_prefix_length_the_family_cannot_carry_is_refused_rather_than_clamped() {
        assert_eq!(mask_to_prefix(v4([10, 0, 0, 0]), 33), None);
        assert_eq!(mask_to_prefix(v6("2001:db8::"), 129), None);
    }

    #[test]
    fn a_v6_prefix_masks_and_a_link_local_one_is_representable_here() {
        let prefix = mask_to_prefix(v6("2001:db8:1:2:3:4:5:6"), 64).expect("maskable");
        assert_eq!(prefix.address(), v6("2001:db8:1:2::"));
        // `mask_to_prefix` is still used for the ROUTE side, where a prefix is
        // the right kind of value and `prefix_base`'s zone-stripping is correct.
        // The divergence it used to cause at the FACTS side — this adapter
        // reporting a zoneless `fe80::/10` while `twinvpn-platform-linux` dropped
        // it, finding X-10 — is gone: `InterfaceFacts.addresses` is a
        // `Vec<InterfaceAddress>` now, and both adapters report the address with
        // its zone.
        let link_local = mask_to_prefix(v6("fe80::1"), 64).expect("representable");
        assert_eq!(link_local.prefix_len(), 64);
    }

    #[test]
    fn an_os_supplied_name_the_seam_refuses_is_a_typed_reject_and_never_truncated() {
        // An adapter that hands the core a 4 KiB name is malfunctioning, and
        // truncating it would produce a name that matches the wrong interface.
        let mut long = row();
        long.name = "A".repeat(InterfaceName::MAX_BYTES + 1);
        let err = facts_from(&long).expect_err("refused");
        assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");

        let mut empty = row();
        empty.name = String::new();
        assert!(facts_from(&empty).is_err());

        let mut control = row();
        control.name = "Ether\u{0}net".to_owned();
        assert!(facts_from(&control).is_err());
    }

    /// **Two addresses on one subnet are two addresses, not one.**
    ///
    /// This test used to assert `2`, because `.10/24` and `.11/24` masked to the
    /// same `IpPrefix` and the second was silently dropped — a real address the
    /// core could then never bind or offer as a candidate. Only an exact
    /// duplicate is now de-duplicated.
    #[test]
    fn two_addresses_on_one_subnet_are_both_reported_and_an_exact_duplicate_is_not() {
        let mut dupes = row();
        dupes.addresses = vec![
            (v4([192, 0, 2, 10]), 24),
            (v4([192, 0, 2, 11]), 24),
            // The same address twice: the OS can list one address on two rows,
            // and reporting it twice would double-count a candidate.
            (v4([192, 0, 2, 10]), 24),
            (v6("2001:db8::1"), 64),
        ];
        let facts = facts_from(&dupes).expect("facts");
        assert_eq!(
            facts.addresses.len(),
            3,
            "two distinct v4 addresses on one subnet, plus the v6 — and the \
             repeated row counted once"
        );
    }

    #[test]
    fn an_interface_that_is_not_operationally_up_is_reported_down() {
        let mut down = row();
        down.oper_status = 2; // IfOperStatusDown
        assert!(!facts_from(&down).expect("facts").is_up);
        assert!(facts_from(&row()).expect("facts").is_up);
    }

    #[test]
    fn the_notification_type_decode_refuses_a_value_windows_should_not_produce() {
        assert_eq!(
            NotificationType::from_raw(0),
            Some(NotificationType::Parameter)
        );
        assert_eq!(NotificationType::from_raw(1), Some(NotificationType::Add));
        assert_eq!(
            NotificationType::from_raw(2),
            Some(NotificationType::Delete)
        );
        assert_eq!(
            NotificationType::from_raw(3),
            Some(NotificationType::Initial)
        );
        for bogus in [-1, 4, 99] {
            assert_eq!(NotificationType::from_raw(bogus), None, "{bogus}");
        }
    }

    #[test]
    fn the_initial_notification_is_dropped_for_every_kind() {
        // "An adapter that replayed the initial state as a burst of `Added`
        // events would make 'we just started' and 'the network just changed'
        // indistinguishable."
        let initial = [
            Notification::Interface {
                index: InterfaceIndex(1),
                connected: true,
                kind: NotificationType::Initial,
            },
            Notification::Address {
                index: InterfaceIndex(1),
                address: v4([10, 0, 0, 1]),
                kind: NotificationType::Initial,
            },
            Notification::Route {
                family: AddressFamily::V6,
                prefix_len: 0,
                kind: NotificationType::Initial,
            },
        ];
        for notification in initial {
            assert_eq!(decode_change(&notification), None, "{notification:?}");
        }
    }

    #[test]
    fn an_interface_appearing_disappearing_and_changing_state_each_decode() {
        assert_eq!(
            decode_change(&Notification::Interface {
                index: InterfaceIndex(4),
                connected: true,
                kind: NotificationType::Add,
            }),
            Some(NetworkChange::InterfaceAdded(InterfaceIndex(4)))
        );
        assert_eq!(
            decode_change(&Notification::Interface {
                index: InterfaceIndex(4),
                connected: false,
                kind: NotificationType::Delete,
            }),
            Some(NetworkChange::InterfaceRemoved(InterfaceIndex(4)))
        );
        for connected in [true, false] {
            assert_eq!(
                decode_change(&Notification::Interface {
                    index: InterfaceIndex(4),
                    connected,
                    kind: NotificationType::Parameter,
                }),
                Some(NetworkChange::LinkStateChanged {
                    interface: InterfaceIndex(4),
                    is_up: connected,
                })
            );
        }
    }

    #[test]
    fn an_address_appearing_and_disappearing_decode_and_a_parameter_change_does_not() {
        let address = v6("2001:db8::1");
        assert_eq!(
            decode_change(&Notification::Address {
                index: InterfaceIndex(9),
                address,
                kind: NotificationType::Add,
            }),
            Some(NetworkChange::AddressAdded {
                interface: InterfaceIndex(9),
                address,
            })
        );
        assert_eq!(
            decode_change(&Notification::Address {
                index: InterfaceIndex(9),
                address,
                kind: NotificationType::Delete,
            }),
            Some(NetworkChange::AddressRemoved {
                interface: InterfaceIndex(9),
                address,
            })
        );
        // A lifetime or DAD-state change is not an address appearing, and the
        // seam has no `AddressChanged`.
        assert_eq!(
            decode_change(&Notification::Address {
                index: InterfaceIndex(9),
                address,
                kind: NotificationType::Parameter,
            }),
            None
        );
    }

    #[test]
    fn a_default_route_change_is_reported_per_family_and_never_combined() {
        // ADR-0010 R6's case is precisely a v6 default route arriving while the
        // v4 one is unchanged; a combined event would make that
        // indistinguishable from nothing having happened.
        for family in [AddressFamily::V4, AddressFamily::V6] {
            assert_eq!(
                decode_change(&Notification::Route {
                    family,
                    prefix_len: 0,
                    kind: NotificationType::Add,
                }),
                Some(NetworkChange::DefaultRouteChanged {
                    family,
                    present: true,
                })
            );
            assert_eq!(
                decode_change(&Notification::Route {
                    family,
                    prefix_len: 0,
                    kind: NotificationType::Delete,
                }),
                Some(NetworkChange::DefaultRouteChanged {
                    family,
                    present: false,
                })
            );
        }
        // The two families produce different events for the same shape of row.
        assert_ne!(
            decode_change(&Notification::Route {
                family: AddressFamily::V4,
                prefix_len: 0,
                kind: NotificationType::Add,
            }),
            decode_change(&Notification::Route {
                family: AddressFamily::V6,
                prefix_len: 0,
                kind: NotificationType::Add,
            })
        );
    }

    #[test]
    fn a_route_that_is_not_a_default_route_produces_no_event() {
        // The seam has `DefaultRouteChanged` and no general route event: the
        // question ADR-0010 R6 asks is whether the family has a way out. Our own
        // two `/1` routes are not that, and reporting them would make every
        // apply look like a network change.
        for prefix_len in [1u8, 8, 24, 64, 128] {
            assert_eq!(
                decode_change(&Notification::Route {
                    family: AddressFamily::V4,
                    prefix_len,
                    kind: NotificationType::Add,
                }),
                None,
                "/{prefix_len}"
            );
        }
    }

    #[test]
    fn a_dropped_change_is_counted_and_reported_with_its_count() {
        // §11.6: "a dropped event is itself recorded."
        let mut ledger = DropLedger::new();
        assert_eq!(ledger.marker(), None, "nothing lost, nothing to say");
        ledger.record();
        ledger.record();
        ledger.record();
        assert_eq!(ledger.outstanding(), 3);
        assert_eq!(
            ledger.marker(),
            Some(NetworkChange::EventsLost { count: Some(3) })
        );
    }

    #[test]
    fn the_count_survives_a_marker_that_could_not_itself_be_delivered() {
        // The failure this guards: reporting "3 lost", failing to enqueue the
        // marker, and clearing anyway — after which the core believes it has a
        // complete picture and is missing three facts.
        let mut ledger = DropLedger::new();
        ledger.record();
        let _ = ledger.marker(); // the send failed; nothing was cleared
        assert_eq!(ledger.outstanding(), 1);
        ledger.record();
        assert_eq!(
            ledger.marker(),
            Some(NetworkChange::EventsLost { count: Some(2) })
        );
        ledger.clear();
        assert_eq!(ledger.outstanding(), 0);
        assert_eq!(ledger.marker(), None);
    }

    #[test]
    fn the_drop_count_saturates_rather_than_wrapping_to_zero() {
        // Wrapping would report "nothing was lost" at the moment that is least
        // true.
        let mut ledger = DropLedger { lost: u64::MAX };
        ledger.record();
        assert_eq!(ledger.outstanding(), u64::MAX);
    }

    #[test]
    fn a_shutting_down_provider_refuses_to_enumerate_or_subscribe() {
        let latch = ShutdownLatch::new();
        let provider = WindowsInterfaceProvider::new(latch.clone());
        latch.begin();
        // `Pin<Box<dyn Stream>>` has no `Debug`, so the result is matched on
        // rather than unwrapped: the assertion is about the refusal, not about
        // how a stream would have printed.
        match provider.subscribe() {
            Err(PlatformError::ShuttingDown) => {}
            Err(other) => panic!("expected a shutdown refusal, got {other:?}"),
            Ok(_) => panic!("a shutting-down provider must not hand out a stream"),
        }
    }
}
