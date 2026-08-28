//! Interface enumeration and change **notification**.
//!
//! **Authority:** `docs/networking.md` §5.1 (`subscribe_network_change(cb)` —
//! "event-driven, never polled"), ADR-0018 §11.6 and F-9, ADR-0015.
//!
//! # Changes are events the core reacts to, not state it polls
//!
//! `docs/networking.md` §5.1 is explicit, and the reason is not efficiency: a
//! poll interval is a window in which the host has moved networks and the core
//! still believes it has not. Every roaming and failover deadline in
//! `docs/reliability.md` §5 is measured from the moment the change is *known*, so
//! a poll interval is added directly to `T_FAILOVER_TARGET`.
//!
//! ADR-0018 §11.16 (h) records the refinement: at the C ABI the subscription is
//! satisfied by **an inbound command submission** rather than a literal outbound
//! function pointer (F-9, F-6's reentrancy guard). Inside the core, above the
//! ABI, it is a [`futures_core::Stream`] — the same fact in the shape a Rust
//! caller can select on.

use core::time::Duration;

use futures_core::future::BoxFuture;
use futures_core::Stream;
use std::pin::Pin;

use twinvpn_env::BootId;
use twinvpn_types::{AddressFamily, InterfaceAddress, IpAddr, Nat64Prefix};

use crate::error::PlatformError;

/// An OS interface index. Opaque; compared only for equality.
///
/// Deliberately not a name: names are not stable across a reconnect on several
/// targets, and a name comparison is how an interface change comes to look like
/// no change at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InterfaceIndex(pub u32);

/// An interface's name, bounded so an OS-supplied string cannot drive an
/// unbounded allocation.
///
/// `SENSITIVE` under ADR-0015 §11.4 — an interface name identifies a user's
/// network — so `Debug` is redacted.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct InterfaceName(String);

impl InterfaceName {
    /// The cap. `IFNAMSIZ` is 16 on Linux; Windows and Darwin are longer, and
    /// 255 covers every target with room to spare.
    pub const MAX_BYTES: usize = 255;

    /// Builds a name, rejecting an over-cap or control-bearing value.
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] — an adapter that hands the core a
    /// 4 KiB interface name is malfunctioning, and truncating it would produce a
    /// name that matches the wrong interface.
    pub fn new(name: &str) -> Result<Self, PlatformError> {
        if name.is_empty() || name.len() > Self::MAX_BYTES || name.chars().any(char::is_control) {
            return Err(PlatformError::AdapterUnavailable(None));
        }
        Ok(Self(name.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for InterfaceName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "InterfaceName(<{} B redacted>)", self.0.len())
    }
}

/// What the OS reports about one interface.
///
/// Mirrors `twinvpn.v1.NetworkInterface`, whose own comment scopes it:
/// **diagnostic and local-decision only**, never advertised to a peer.
// Five booleans, and each is a distinct fact the core reads on its own:
// ADR-0010 R6 needs the two default-route flags SEPARATELY, `is_overlay`
// answers "is this ours", and `is_up` answers "is the link alive". Collapsing
// them into a bitflags type would make the v4/v6 pair look like one fact, which
// is the asymmetry R1 exists to forbid.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
// NOT `#[non_exhaustive]`: BOTH sides of the seam construct this. The adapter
// implementations live in other crates (`twinvpn-platform-*`, the shells) and the
// core builds the values it hands across, so sealing construction would make the
// trait unimplementable outside this crate. Adding a field here SHOULD break every
// implementor — that is a seam change, and a silent default is how one side comes
// to believe a fact the other never supplied.
pub struct InterfaceFacts {
    /// The OS index.
    pub index: InterfaceIndex,
    /// The OS name.
    pub name: InterfaceName,
    /// Every address on it, exactly as the OS reported it, with its prefix
    /// length beside it.
    ///
    /// # This was a `Vec<IpPrefix>`, and that was the defect
    ///
    /// [`twinvpn_types::IpPrefix`] names a *range* and requires every host bit
    /// to be zero, so an adapter holding `10.0.0.7/24` had no representation for
    /// it and masked to `10.0.0.0/24`, losing the address the core actually
    /// needs — the one to bind and to offer as a host candidate. A network
    /// address offered as a candidate probes where nothing answers and reads as
    /// a NAT fault, which is why `twinvpn-core`'s `establish::host_address` once
    /// accepted only `/32` and `/128` and reported `AddressNotReportable`
    /// otherwise. The same conjunction dropped every link-local address:
    /// [`twinvpn_types::V6Addr`] requires a zone on `fe80::/10` and `IpPrefix`
    /// rejects any zone, so `twinvpn-platform-linux` dropped `fe80::/64` while
    /// `twinvpn-platform-windows` stripped the zone and kept it — **the core saw
    /// a different address set for one host depending on which adapter was
    /// bound** (`shells/windows/README.md` §7 gap 16).
    ///
    /// [`InterfaceAddress`] is the type for this kind of value: it keeps the
    /// host bits *and* the scope zone, and derives the on-link prefix with
    /// [`InterfaceAddress::network`] where a route is what is wanted. Three
    /// domains reported this defect independently; it is fixed here rather than
    /// worked around a fourth time.
    pub addresses: Vec<InterfaceAddress>,
    /// Whether a v4 default route points through it.
    pub has_default_route_v4: bool,
    /// Whether a v6 default route points through it.
    ///
    /// Separate from the v4 flag, not a family-keyed map: ADR-0010 R6 requires
    /// IPv6 not to be able to bypass tunnel policy "including when IPv6 appears
    /// **after** the tunnel is up", so "does v6 have a way out" is a question the
    /// core asks on its own.
    pub has_default_route_v6: bool,
    /// Whether this is one of our own overlay interfaces.
    pub is_overlay: bool,
    /// Whether the link is up.
    pub is_up: bool,
    /// The interface MTU.
    pub mtu: u32,
    /// The link's class, where the OS reports one.
    pub link_class: LinkClass,
}

impl InterfaceFacts {
    /// Whether this interface carries a default route for `family`.
    #[must_use]
    pub const fn has_default_route(&self, family: AddressFamily) -> bool {
        match family {
            AddressFamily::V4 => self.has_default_route_v4,
            AddressFamily::V6 => self.has_default_route_v6,
        }
    }
}

/// The class of underlay link, as the OS reports it.
///
/// A **domain fact**, not an OS branch: `docs/reliability.md` emits
/// `NET.LINK.DOWN_WIFI` and `NET.LINK.DOWN_CELLULAR` as distinct codes, so the
/// core needs the class and CB-3 is not violated by having it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LinkClass {
    /// Wired.
    Ethernet,
    /// Wi-Fi.
    WiFi,
    /// Cellular.
    Cellular,
    /// Loopback.
    Loopback,
    /// Another VPN or tunnel interface.
    Tunnel,
    /// The OS does not say.
    Unknown,
}

/// What an adapter can say about a suspend the host has just come back from.
///
/// **Authority:** ADR-0022 LC-8 (the clock table and its finding F2), LC-24
/// (the resume sequence); `docs/reliability.md` §11.3 (the rekey window).
///
/// # Why this is not derivable from anything already at the seam
///
/// [`NetworkChange::EventsLost`] is true and sufficient for the *stream* — the
/// routing socket genuinely drops while the machine is asleep — and it cannot
/// say *"the machine was off for nine hours"*. Nothing else can either:
/// `MonotonicClock` does not advance across a suspend, which is the entire
/// reason LC-8 makes it and `ElapsedClock` non-interchangeable types with no
/// conversion. So a core reading only monotonic time sees a resume as *no time
/// having passed* — and every long-horizon deadline LC-8's F2 moves onto the
/// elapsed clock (`T_TRUST_HARD`, `T_TRUST_STALE`, `T_IK_OVERLAP`, credential
/// expiry) and every NAT binding lifetime is measured across exactly this gap.
///
/// The rule this exists to preserve is ADR-0022's: **a resume must not render a
/// confident, stale green.** The adapter reports the gap; the core decides what
/// is still trustworthy. Nothing here is a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOT `#[non_exhaustive]`: BOTH sides of the seam construct this, for the same
// reason `InterfaceFacts` is not. Adding a field SHOULD break every implementor.
pub struct ResumeFacts {
    /// How long the host was away, measured on the **suspend-inclusive** clock
    /// (`CLOCK_BOOTTIME`, `mach_continuous_time`, the unbiased interrupt time).
    ///
    /// `None` where the platform cannot say. **Not zero** — "the machine was
    /// asleep for no measurable time" and "we do not know how long the machine
    /// was asleep" are different facts, and a core that read the second as the
    /// first would keep a nine-hour-old assertion green.
    pub suspended_for: Option<Duration>,
    /// The boot identity observed at resume, where the platform has one.
    ///
    /// LC-8's *third discriminator, which is not a clock*: after a reboot both
    /// monotonic clocks restart at zero, which is indistinguishable from "no
    /// time passed". Carried rather than compared, because comparing it against
    /// the identity the core is holding is the core's decision — a hibernate
    /// that actually became a cold boot is a different fact from a resume, and
    /// LC-24 step 1 reads it as a cold start.
    pub boot_id: Option<BootId>,
    /// Whether the OS announced the suspend, or the adapter inferred it.
    ///
    /// `true` on a platform that delivers a power notification —
    /// `SERVICE_CONTROL_POWEREVENT` / `PBT_APMRESUMESUSPEND` on Windows,
    /// `kIOMessageSystemHasPoweredOn` on Darwin. `false` where the adapter
    /// noticed after the fact that the suspend-inclusive clock had advanced and
    /// the monotonic one had not, which is Linux's only honest answer. A core
    /// treating an inferred resume as an announced one would attribute a
    /// container freeze or a live migration to a user closing a lid.
    pub announced_by_os: bool,
    /// Whether this was a resume from **hibernation** (S4), where the platform
    /// distinguishes it from a suspend (S3).
    ///
    /// LC-24 step 5 emits `PLATFORM.LIFECYCLE.HIBERNATE_RESUMED` *"where the
    /// platform distinguishes S4"* and `PLATFORM.RESUMED` otherwise, so which of
    /// the two is honest is exactly this fact. `None` is the platform that cannot
    /// tell them apart, and it is not the same answer as `Some(false)`.
    pub hibernated: Option<bool>,
}

/// A change the core must react to.
///
/// Every variant is a fact, never an instruction: the adapter reports what
/// happened and the core decides what it means. CB-2's falsification test is
/// what keeps that true.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkChange {
    /// An interface appeared.
    InterfaceAdded(InterfaceIndex),
    /// An interface disappeared.
    InterfaceRemoved(InterfaceIndex),
    /// An interface's link state changed.
    LinkStateChanged {
        /// Which interface.
        interface: InterfaceIndex,
        /// Whether it is now up.
        is_up: bool,
    },
    /// An address was added.
    AddressAdded {
        /// Which interface.
        interface: InterfaceIndex,
        /// The address.
        address: IpAddr,
    },
    /// An address was removed.
    AddressRemoved {
        /// Which interface.
        interface: InterfaceIndex,
        /// The address.
        address: IpAddr,
    },
    /// A default route appeared or disappeared **for one family**.
    ///
    /// Per family, because ADR-0010 R6's case — "IPv6 appears *after* the tunnel
    /// is up" — is precisely a v6 default route arriving while the v4 one is
    /// unchanged, and a combined event would make that indistinguishable from
    /// nothing having happened.
    DefaultRouteChanged {
        /// Which family.
        family: AddressFamily,
        /// Whether a default route now exists.
        present: bool,
    },
    /// The system resolver configuration changed.
    ResolversChanged,
    /// The discovered NAT64 prefix changed (ADR-0010 §11.7).
    Nat64PrefixChanged(Option<Nat64Prefix>),
    /// The link's metering or power posture changed.
    LinkPostureChanged {
        /// Whether the link is metered.
        metered: bool,
        /// Whether the host is in a low-power state.
        low_power: bool,
    },
    /// The host came back from a suspend, and this is what it can say about the
    /// gap.
    ///
    /// **Not derivable from [`NetworkChange::EventsLost`].** That variant is
    /// true and sufficient for the *stream* — the routing socket genuinely drops
    /// while the machine is asleep — and it cannot say how long the machine was
    /// away, which is what ADR-0022 LC-24 step 1 classifies the resume on and
    /// what LC-8's F2 measures every long-horizon policy deadline across. An
    /// adapter that emits both is correct and expected: they are different facts.
    ///
    /// It rides this stream rather than the `host.lifecycle` command because
    /// `host.lifecycle` carries a **one-byte phase selector** and has nowhere to
    /// put a duration; `EV_RESUME` still travels there, and this is the
    /// measurement beside it.
    SystemResumed(ResumeFacts),
    /// The stream dropped `count` events because the core was not draining.
    ///
    /// ADR-0018 §11.6: "a dropped event is itself recorded". An adapter that
    /// silently coalesces leaves the core believing it has a complete picture; an
    /// adapter that reports the gap lets the core re-enumerate and recover.
    EventsLost {
        /// How many were dropped, if the platform can say.
        count: Option<u64>,
    },
}

/// Enumerates interfaces and reports changes.
pub trait InterfaceProvider: Send + Sync {
    /// Every interface the OS currently reports.
    ///
    /// # Errors
    ///
    /// [`PlatformError`] if enumeration is refused or unavailable.
    fn enumerate(&self) -> BoxFuture<'_, Result<Vec<InterfaceFacts>, PlatformError>>;

    /// The change stream.
    ///
    /// Event-driven, never polled. A caller that has just subscribed should also
    /// [`InterfaceProvider::enumerate`], because the stream carries changes and
    /// not the initial state — and an adapter that replayed the initial state as
    /// a burst of `Added` events would make "we just started" and "the network
    /// just changed" indistinguishable.
    ///
    /// # Errors
    ///
    /// [`PlatformError`] if the platform's notification mechanism is unavailable.
    fn subscribe(&self)
        -> Result<Pin<Box<dyn Stream<Item = NetworkChange> + Send>>, PlatformError>;
}
