//! Interface enumeration and change **notification**.
//!
//! **Authority:** `docs/networking.md` §5.1 (`subscribe_network_change(cb)` —
//! "event-driven, never polled"), ADR-0018 §11.6 and F-9 ("a dropped event is
//! itself recorded"), ADR-0010 R6, ADR-0015.
//!
//! # Changes are published into the adapter, not polled out of it
//!
//! On Darwin there are two independent sources of network change and neither is a
//! file descriptor the core can select on: the `PF_ROUTE` socket, which the shell
//! reads on its own thread, and IOKit's power notifications, which arrive on a
//! `CFRunLoop`. So the provider owns a broadcast channel: the shell decodes with
//! [`crate::rtmsg`] and [`crate::power`] — both pure — and publishes the resulting
//! facts here, and the core selects on the [`Stream`].
//!
//! **That is translation, not decision.** Nothing the shell publishes is a
//! judgement: `rtmsg` turns bytes into `NetworkChange`, `power` turns an IOKit
//! message into `NetworkChange`, and both are in this crate and tested.
//!
//! # A dropped event is itself recorded
//!
//! A broadcast receiver that falls behind reports how many it missed, and that
//! becomes [`NetworkChange::EventsLost`] with a **count** — the one place on this
//! platform where the number is actually known. An adapter that silently coalesced
//! would leave the core believing it has a complete picture.
//!
//! # `is_overlay` is answered by ownership, never by the name
//!
//! Darwin names `utun` interfaces itself and a caller does not get to pick the
//! prefix, so `utun3` may be Tailscale's, `utun5` may be the corporate VPN's and
//! `utun7` may be ours. Treating any `utun` as ours would make ADR-0012's
//! interface-scoped Tier-2 rule permit somebody else's tunnel — the exact defect
//! the Linux adapter avoids by owning a `twin` prefix it *can* choose.
//! [`MacosInterfaceProvider::own_interface`] records the indexes this adapter
//! created or adopted, and nothing else is ever `is_overlay`.

use std::collections::BTreeSet;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};

use futures_core::future::BoxFuture;
use futures_core::Stream;
use tokio::sync::broadcast;
use twinvpn_platform::{
    InterfaceFacts, InterfaceIndex, InterfaceName, InterfaceProvider, LinkClass, NetworkChange,
    PlatformError,
};
use twinvpn_types::InterfaceAddress;

use crate::oserr;
use crate::shutdown::ShutdownLatch;

/// How many changes the channel holds before a slow subscriber starts losing
/// them.
///
/// Generous, because the cost of a lost event is a re-enumeration and the cost of
/// a large buffer is a few kilobytes. A resume storm on a Mac that has changed
/// networks while asleep is the burst this number is sized for.
pub const CHANGE_BUFFER: usize = 256;

/// `SCNetworkInterface` type strings, as `SCNetworkInterfaceGetInterfaceType`
/// returns them.
///
/// The **only** way to tell Wi-Fi from Ethernet on macOS: both are `enN`, and the
/// number tells you nothing — a Mac with a Thunderbolt dock has Ethernet on `en5`
/// and Wi-Fi on `en0`, and a Mac mini has Ethernet on `en0`. A classifier that
/// guessed from the name would emit `NET.LINK.DOWN_WIFI` for an unplugged cable.
pub mod sc_type {
    /// `kSCNetworkInterfaceTypeIEEE80211`.
    pub const WIFI: &str = "IEEE80211";
    /// `kSCNetworkInterfaceTypeEthernet`.
    pub const ETHERNET: &str = "Ethernet";
    /// `kSCNetworkInterfaceTypeWWAN`.
    pub const WWAN: &str = "WWAN";
    /// `kSCNetworkInterfaceTypeBridge`.
    pub const BRIDGE: &str = "Bridge";
    /// `kSCNetworkInterfaceTypeBond`.
    pub const BOND: &str = "Bond";
    /// `kSCNetworkInterfaceTypePPP`.
    pub const PPP: &str = "PPP";
}

/// Classifies a link.
///
/// `sc_type` is `SCNetworkInterfaceGetInterfaceType`'s answer where the shell
/// could get one, and `None` where it could not — which is the common case for a
/// tunnel interface, since a `utun` has no `SCNetworkInterface` until a service
/// is created for it.
///
/// The name is used only where it is genuinely decisive: `lo0` is loopback,
/// `utun`/`ipsec`/`ppp`/`gif`/`stf` are tunnels, `pdp_ip` is the cellular
/// interface on a Mac with a WWAN module, and `awdl`/`llw` are Apple Wireless
/// Direct Link, which is Wi-Fi hardware but never a route to anywhere.
#[must_use]
pub fn classify(name: &str, sc_type: Option<&str>) -> LinkClass {
    if name.starts_with("lo") {
        return LinkClass::Loopback;
    }
    if name.starts_with("utun")
        || name.starts_with("ipsec")
        || name.starts_with("ppp")
        || name.starts_with("gif")
        || name.starts_with("stf")
    {
        return LinkClass::Tunnel;
    }
    if name.starts_with("pdp_ip") {
        return LinkClass::Cellular;
    }
    if name.starts_with("awdl") || name.starts_with("llw") {
        // Apple Wireless Direct Link. Wi-Fi hardware, and never a path to a peer:
        // it carries AirDrop and Sidecar and has no default route. Classified as
        // Wi-Fi truthfully; the core's own gathering excludes it because it
        // carries no default route, which is a fact and not a name test.
        return LinkClass::WiFi;
    }
    match sc_type {
        Some(sc_type::WIFI) => LinkClass::WiFi,
        Some(sc_type::WWAN) => LinkClass::Cellular,
        Some(sc_type::PPP) => LinkClass::Tunnel,
        Some(sc_type::ETHERNET | sc_type::BRIDGE | sc_type::BOND) => LinkClass::Ethernet,
        // **`Unknown`, not `Ethernet`.** `enN` with no `SCNetworkInterface` type
        // is genuinely unknown, and guessing Ethernet would make a Wi-Fi drop
        // report `NET.LINK.DOWN_ETHERNET` — a code whose remediation is "check the
        // cable" on a machine that has none.
        _ => LinkClass::Unknown,
    }
}

/// One interface as the OS reports it, before this adapter's own facts are added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawInterface {
    /// The OS name.
    pub name: String,
    /// The OS index.
    pub index: u32,
    /// Addresses, exactly as `getifaddrs` reports them: the address with its
    /// host bits intact and its prefix length beside it.
    ///
    /// `InterfaceAddress` rather than `IpPrefix`, which normalised the host bits
    /// away — see [`twinvpn_platform::InterfaceFacts::addresses`]. It also means
    /// a link-local `fe80::/64` keeps its scope zone instead of being dropped.
    pub addresses: Vec<InterfaceAddress>,
    /// Whether the link is up (`IFF_UP` **and** `IFF_RUNNING`).
    pub is_up: bool,
    /// The MTU.
    pub mtu: u32,
    /// `SCNetworkInterfaceGetInterfaceType`, where the shell could read one.
    pub sc_type: Option<String>,
    /// Whether a v4 default route points through it.
    pub has_default_route_v4: bool,
    /// Whether a v6 default route points through it.
    pub has_default_route_v6: bool,
}

/// Where the raw interface list comes from. Injected, so enumeration is testable.
pub trait InterfaceSource: Send + Sync + std::fmt::Debug {
    /// Every interface the OS currently reports.
    fn snapshot(&self) -> Result<Vec<RawInterface>, PlatformError>;
}

/// A source on a host with no Darwin interface enumeration.
#[derive(Debug, Clone, Copy, Default)]
pub struct AbsentInterfaceSource;

impl InterfaceSource for AbsentInterfaceSource {
    fn snapshot(&self) -> Result<Vec<RawInterface>, PlatformError> {
        // Refused by name rather than reported as an empty list. An empty
        // enumeration is a **fact** — "this host has no interfaces" — and the core
        // would act on it; a refusal is what "we could not look" means.
        Err(oserr::unavailable("getifaddrs", libc::ENOSYS))
    }
}

/// Turns a raw interface into the seam's facts.
///
/// `owned` is the set of indexes this adapter created or adopted — the only
/// answer to `is_overlay` that cannot be fooled by another VPN's `utun`.
///
/// # Errors
///
/// [`PlatformError::AdapterUnavailable`] when the OS supplies a name the seam
/// refuses — over 255 bytes or carrying a control character. An adapter that
/// truncated it would produce a name that matches the wrong interface.
pub fn facts_from(
    raw: &RawInterface,
    owned: &BTreeSet<u32>,
) -> Result<InterfaceFacts, PlatformError> {
    Ok(InterfaceFacts {
        index: InterfaceIndex(raw.index),
        name: InterfaceName::new(&raw.name)?,
        addresses: raw.addresses.clone(),
        has_default_route_v4: raw.has_default_route_v4,
        has_default_route_v6: raw.has_default_route_v6,
        is_overlay: owned.contains(&raw.index),
        is_up: raw.is_up,
        mtu: raw.mtu,
        link_class: classify(&raw.name, raw.sc_type.as_deref()),
    })
}

/// macOS's interface provider.
#[derive(Debug)]
pub struct MacosInterfaceProvider {
    shutdown: ShutdownLatch,
    source: Arc<dyn InterfaceSource>,
    owned: Mutex<BTreeSet<u32>>,
    sender: broadcast::Sender<NetworkChange>,
}

impl MacosInterfaceProvider {
    /// Binds the provider with no enumeration source.
    #[must_use]
    pub fn new(shutdown: ShutdownLatch) -> Self {
        Self::with_source(shutdown, Arc::new(AbsentInterfaceSource))
    }

    /// Binds it with a source.
    #[must_use]
    pub fn with_source(shutdown: ShutdownLatch, source: Arc<dyn InterfaceSource>) -> Self {
        let (sender, _) = broadcast::channel(CHANGE_BUFFER);
        Self {
            shutdown,
            source,
            owned: Mutex::new(BTreeSet::new()),
            sender,
        }
    }

    /// Records an interface index as ours.
    ///
    /// Called by the shell after `create_interface`. The **only** thing that makes
    /// an interface `is_overlay`, because Darwin picks `utun` names and another
    /// product's tunnel is indistinguishable from ours by name.
    pub fn own_interface(&self, index: InterfaceIndex) {
        if let Ok(mut owned) = self.owned.lock() {
            owned.insert(index.0);
        }
    }

    /// Forgets an interface index. Called after `destroy_interface`.
    pub fn disown_interface(&self, index: InterfaceIndex) {
        if let Ok(mut owned) = self.owned.lock() {
            owned.remove(&index.0);
        }
    }

    /// Whether an index is one of ours.
    #[must_use]
    pub fn owns(&self, index: InterfaceIndex) -> bool {
        self.owned.lock().is_ok_and(|o| o.contains(&index.0))
    }

    /// Publishes a decoded change to every subscriber.
    ///
    /// Called by the shell's `PF_ROUTE` reader with [`crate::rtmsg::decode`]'s
    /// output and by its IOKit handler with [`crate::power::PowerJournal`]'s.
    /// Returns how many subscribers received it; zero is normal before the core
    /// has subscribed and is not an error.
    pub fn publish(&self, change: NetworkChange) -> usize {
        self.sender.send(change).unwrap_or(0)
    }

    /// Publishes several, in order.
    pub fn publish_all(&self, changes: impl IntoIterator<Item = NetworkChange>) {
        for change in changes {
            self.publish(change);
        }
    }

    /// How many subscribers are attached.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl InterfaceProvider for MacosInterfaceProvider {
    fn enumerate(&self) -> BoxFuture<'_, Result<Vec<InterfaceFacts>, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            let owned = self
                .owned
                .lock()
                .map_err(|_| oserr::unavailable("iface.lock", libc::EDEADLK))?
                .clone();
            let raw = self.source.snapshot()?;
            let mut out = Vec::with_capacity(raw.len());
            for interface in &raw {
                match facts_from(interface, &owned) {
                    Ok(facts) => out.push(facts),
                    // One malformed name must not lose the whole enumeration: the
                    // core needs the interfaces it *can* see, and the one it
                    // cannot is logged rather than fatal.
                    Err(error) => tracing::warn!(
                        target: "twinvpn.platform.macos.iface",
                        reason_code = error.reason_code().as_str(),
                        "an interface the OS reported could not be represented"
                    ),
                }
            }
            Ok(out)
        })
    }

    fn subscribe(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = NetworkChange> + Send>>, PlatformError> {
        self.shutdown.check()?;
        Ok(Box::pin(ChangeStream::new(self.sender.subscribe())))
    }
}

/// The change stream.
///
/// A hand-rolled [`Stream`] over a broadcast receiver rather than a combinator,
/// because the one behaviour that matters here is what happens when a subscriber
/// falls behind: the receiver reports **how many** it missed, and that number
/// becomes an [`NetworkChange::EventsLost`] the core can act on. A combinator that
/// mapped `Lagged` to "end of stream" would silently stop delivering network
/// changes to a running core.
pub struct ChangeStream {
    receiver: Option<broadcast::Receiver<NetworkChange>>,
    pending: Option<PendingRecv>,
}

/// One in-flight `recv()`, carrying the receiver through the borrow.
///
/// The receiver is moved **into** the future and handed back with the result,
/// because `broadcast::Receiver::recv` borrows `&mut self` and a `BoxFuture` that
/// borrowed the struct's own field could not be stored in that struct.
type PendingRecv = BoxFuture<
    'static,
    (
        broadcast::Receiver<NetworkChange>,
        Result<NetworkChange, broadcast::error::RecvError>,
    ),
>;

impl ChangeStream {
    fn new(receiver: broadcast::Receiver<NetworkChange>) -> Self {
        Self {
            receiver: Some(receiver),
            pending: None,
        }
    }
}

impl std::fmt::Debug for ChangeStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChangeStream")
    }
}

impl Stream for ChangeStream {
    type Item = NetworkChange;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.pending.is_none() {
            let Some(mut receiver) = this.receiver.take() else {
                return Poll::Ready(None);
            };
            this.pending = Some(Box::pin(async move {
                let result = receiver.recv().await;
                (receiver, result)
            }));
        }
        let Some(future) = this.pending.as_mut() else {
            return Poll::Ready(None);
        };
        match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((receiver, result)) => {
                this.pending = None;
                this.receiver = Some(receiver);
                match result {
                    Ok(change) => Poll::Ready(Some(change)),
                    // The one place on this platform where the dropped-event count
                    // is genuinely known. Reported as an item, and the receiver is
                    // put back: a lag is a gap in the stream, never its end.
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        Poll::Ready(Some(NetworkChange::EventsLost {
                            count: Some(missed),
                        }))
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        this.receiver = None;
                        Poll::Ready(None)
                    }
                }
            }
        }
    }
}
