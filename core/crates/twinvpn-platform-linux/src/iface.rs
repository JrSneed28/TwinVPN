//! Interface enumeration and change **notification**, over `rtnetlink`.
//!
//! **Authority:** [`twinvpn_platform::iface`], `docs/networking.md` §5.1
//! ("`subscribe_network_change(cb)` — event-driven, never polled") and §5.2's
//! Linux row, ADR-0010 R6, ADR-0018 §11.6.
//!
//! # W-25 again: this is the other thing the C ABI cannot do
//!
//! `twinvpn.h`'s F-9 vtable has **no interface enumerator**, and F-9 deliberately
//! omits `subscribe_network_change` because handing the OS a pointer into the
//! core would break F-6's reentrancy rule. A shell binding only the ABI must
//! therefore submit `host.network_changed` commands built from *some* source it
//! does not have. This crate is bound as a Rust crate, so the stream is a real
//! [`futures_core::Stream`] and the enumeration is a real netlink dump.
//!
//! # A change is an event, and the reason is not efficiency
//!
//! > A poll interval is a window in which the host has moved networks and the
//! > core still believes it has not. Every roaming and failover deadline in
//! > `docs/reliability.md` §5 is measured from the moment the change is *known*,
//! > so a poll interval is added directly to `T_FAILOVER_TARGET`.
//!
//! The stream carries **changes and not the initial state**: an adapter that
//! replayed the initial state as a burst of `Added` events would make "we just
//! started" and "the network just changed" indistinguishable. A caller that has
//! just subscribed also calls [`InterfaceProvider::enumerate`].
//!
//! # A dropped event is recorded, never silently coalesced
//!
//! The channel is bounded. When the core is not draining, the excess is reported
//! as [`NetworkChange::EventsLost`] with a count, because "an adapter that
//! silently coalesces leaves the core believing it has a complete picture; an
//! adapter that reports the gap lets the core re-enumerate and recover".

use std::collections::HashMap;
use std::fs;
use std::pin::Pin;
use std::sync::Arc;

use futures_core::future::BoxFuture;
use futures_core::Stream;
use twinvpn_platform::{
    InterfaceFacts, InterfaceIndex, InterfaceName, InterfaceProvider, LinkClass, NetworkChange,
    PlatformError,
};
use twinvpn_types::{
    AddressFamily, InterfaceAddress, IpAddr, V4Addr, V6Addr, ZoneIndex,
};

use crate::netlink::{self, NetlinkSocket, NlBuilder, AF_INET6_U8, AF_INET_U8};
use crate::oserr::{self, Context};
use crate::shutdown::ShutdownLatch;

/// `struct ifinfomsg` — family, pad, type, index, flags, change.
const IFINFOMSG_LEN: usize = 16;
/// `struct ifaddrmsg` — family, prefixlen, flags, scope, index.
const IFADDRMSG_LEN: usize = 8;
/// `struct rtmsg` — eight `u8` then `rtm_flags`.
const RTMSG_LEN: usize = 12;

/// How many changes are buffered before the adapter starts counting drops.
///
/// Sized for a full dual-stack network transition (link down, addresses gone,
/// default routes gone, link up, addresses back, routes back) on a host with a
/// handful of interfaces, so an ordinary roam never drops. Beyond that, dropping
/// with a **count** is better than growing without bound, which is the
/// `ownership.md` §6 rule 10 obligation applied to an event queue.
const CHANGE_QUEUE: usize = 256;

/// Enumerates and watches Linux interfaces.
pub struct LinuxInterfaceProvider {
    shutdown: ShutdownLatch,
}

impl LinuxInterfaceProvider {
    /// Binds the provider.
    #[must_use]
    pub const fn new(shutdown: ShutdownLatch) -> Self {
        Self { shutdown }
    }

    async fn dump() -> Result<Vec<InterfaceFacts>, PlatformError> {
        let sock = NetlinkSocket::open(0)
            .map_err(|e| oserr::from_errno(&e, "AF_NETLINK", Context::Netlink))?;

        let links = dump_links(&sock).await?;
        let addresses = dump_addresses(&sock).await?;
        let defaults = dump_default_routes(&sock).await?;

        let mut out = Vec::with_capacity(links.len());
        for link in links {
            let index = link.index;
            let (v4, v6) = defaults.get(&index).copied().unwrap_or((false, false));
            out.push(InterfaceFacts {
                index: InterfaceIndex(index),
                name: link.name,
                addresses: addresses.get(&index).cloned().unwrap_or_default(),
                has_default_route_v4: v4,
                // Separate from the v4 flag, never a family-keyed map: ADR-0010
                // R6 needs "does v6 have a way out" as its own question, because
                // its case is v6 appearing AFTER the tunnel is up.
                has_default_route_v6: v6,
                is_overlay: link.is_overlay,
                is_up: link.is_up,
                mtu: link.mtu,
                link_class: link.class,
            });
        }
        Ok(out)
    }
}

impl InterfaceProvider for LinuxInterfaceProvider {
    fn enumerate(&self) -> BoxFuture<'_, Result<Vec<InterfaceFacts>, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            Self::dump().await
        })
    }

    fn subscribe(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = NetworkChange> + Send>>, PlatformError> {
        self.shutdown.check()?;
        let sock = NetlinkSocket::open(netlink::change_groups())
            .map_err(|e| oserr::from_errno(&e, "AF_NETLINK(groups)", Context::Netlink))?;
        let (tx, rx) = tokio::sync::mpsc::channel(CHANGE_QUEUE);
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            let mut lost: u64 = 0;
            loop {
                if shutdown.is_shutting_down() {
                    break;
                }
                let Ok(messages) = sock.recv().await else {
                    // The socket is gone. Closing the stream is the honest
                    // answer: the core re-enumerates rather than believing a
                    // silent stream means a stable network.
                    break;
                };
                for message in messages {
                    for change in decode_change(&message) {
                        match tx.try_send(change) {
                            Ok(()) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                lost = lost.saturating_add(1);
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
                        }
                    }
                }
                if lost > 0 {
                    // §11.6: "a dropped event is itself recorded". Reported the
                    // moment there is room, with the count, so the core can
                    // re-enumerate and recover rather than trusting a picture
                    // that is missing an unknown number of facts.
                    if tx
                        .try_send(NetworkChange::EventsLost { count: Some(lost) })
                        .is_ok()
                    {
                        lost = 0;
                    }
                }
            }
        });

        Ok(Box::pin(ChangeStream { rx }))
    }
}

struct ChangeStream {
    rx: tokio::sync::mpsc::Receiver<NetworkChange>,
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

/// One link, as the dump reports it.
struct Link {
    index: u32,
    name: InterfaceName,
    mtu: u32,
    is_up: bool,
    is_overlay: bool,
    class: LinkClass,
}

async fn dump_links(sock: &NetlinkSocket) -> Result<Vec<Link>, PlatformError> {
    let mut b = NlBuilder::new(
        libc::RTM_GETLINK,
        u16::try_from(libc::NLM_F_REQUEST | libc::NLM_F_DUMP).unwrap_or(0x301),
        sock.next_seq(),
    );
    b.payload(&[0u8; IFINFOMSG_LEN]);
    let messages = sock
        .request(b.finish())
        .await
        .map_err(|e| oserr::from_errno(&e, "RTM_GETLINK", Context::Netlink))?;

    let mut out = Vec::new();
    for message in messages {
        if message.body.len() < IFINFOMSG_LEN {
            continue;
        }
        let index = u32::from_ne_bytes([
            message.body[4],
            message.body[5],
            message.body[6],
            message.body[7],
        ]);
        let flags = u32::from_ne_bytes([
            message.body[8],
            message.body[9],
            message.body[10],
            message.body[11],
        ]);
        let arphrd = u16::from_ne_bytes([message.body[2], message.body[3]]);

        let mut name = None;
        let mut mtu = 0u32;
        let mut kind: Option<String> = None;
        for (attr, value) in netlink::parse_attrs(&message.body, IFINFOMSG_LEN) {
            match attr {
                libc::IFLA_IFNAME => {
                    let text = String::from_utf8_lossy(value);
                    name = InterfaceName::new(text.trim_end_matches('\0')).ok();
                }
                libc::IFLA_MTU if value.len() == 4 => {
                    mtu = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                }
                libc::IFLA_LINKINFO => {
                    // IFLA_INFO_KIND inside the nested attribute: "tun",
                    // "wireguard", "veth". The kind is what distinguishes one of
                    // ours from a third party's tunnel.
                    for (nested, nvalue) in netlink::parse_attrs(value, 0) {
                        if nested == libc::IFLA_INFO_KIND {
                            kind = Some(
                                String::from_utf8_lossy(nvalue)
                                    .trim_end_matches('\0')
                                    .to_owned(),
                            );
                        }
                    }
                }
                _ => {}
            }
        }
        let Some(name) = name else { continue };
        let class = classify(name.as_str(), arphrd, kind.as_deref());
        out.push(Link {
            index,
            is_up: (flags & u32::try_from(libc::IFF_UP).unwrap_or(1)) != 0
                && (flags & u32::try_from(libc::IFF_RUNNING).unwrap_or(64)) != 0,
            // "Is this ours" is answered by the name we chose, not by the link
            // kind: a `wireguard` link created by `wg-quick` is a third party's,
            // and treating it as ours would make ADR-0012's Tier-2
            // interface-scoped deny permit somebody else's tunnel.
            is_overlay: name.as_str().starts_with(crate::OVERLAY_PREFIX),
            name,
            mtu,
            class,
        });
    }
    Ok(out)
}

/// The link class the OS reports.
///
/// A **domain fact**, not an OS branch: `docs/reliability.md` emits
/// `NET.LINK.DOWN_WIFI` and `NET.LINK.DOWN_CELLULAR` as distinct codes, so the
/// core needs the class.
///
/// Linux does not expose a single "link class" field, so this is assembled from
/// three sources in decreasing reliability: `ARPHRD_*`, the netlink link *kind*,
/// and `sysfs`. Where none of them says, the answer is [`LinkClass::Unknown`] —
/// which is a fact, not a failure, and is better than a guess that turns a wired
/// link into a metered one.
fn classify(name: &str, arphrd: u16, kind: Option<&str>) -> LinkClass {
    if arphrd == libc::ARPHRD_LOOPBACK {
        return LinkClass::Loopback;
    }
    if matches!(
        kind,
        Some("tun" | "tap" | "wireguard" | "ipip" | "gre" | "sit" | "vti" | "ppp" | "wgtun")
    ) {
        return LinkClass::Tunnel;
    }
    // `/sys/class/net/<name>/wireless` exists exactly on cfg80211 devices.
    if fs::metadata(format!("/sys/class/net/{name}/wireless")).is_ok() {
        return LinkClass::WiFi;
    }
    // A WWAN modem exposes its subsystem through the device uevent. Reading it
    // is cheap and is the only way Linux distinguishes cellular from ethernet.
    if let Ok(uevent) = fs::read_to_string(format!("/sys/class/net/{name}/device/uevent")) {
        if uevent.contains("wwan") || uevent.contains("cdc_mbim") || uevent.contains("qmi_wwan") {
            return LinkClass::Cellular;
        }
    }
    if arphrd == libc::ARPHRD_ETHER {
        return LinkClass::Ethernet;
    }
    LinkClass::Unknown
}

async fn dump_addresses(
    sock: &NetlinkSocket,
) -> Result<HashMap<u32, Vec<InterfaceAddress>>, PlatformError> {
    let mut b = NlBuilder::new(
        libc::RTM_GETADDR,
        u16::try_from(libc::NLM_F_REQUEST | libc::NLM_F_DUMP).unwrap_or(0x301),
        sock.next_seq(),
    );
    b.payload(&[0u8; IFADDRMSG_LEN]);
    let messages = sock
        .request(b.finish())
        .await
        .map_err(|e| oserr::from_errno(&e, "RTM_GETADDR", Context::Netlink))?;

    let mut out: HashMap<u32, Vec<InterfaceAddress>> = HashMap::new();
    for message in messages {
        if message.body.len() < IFADDRMSG_LEN {
            continue;
        }
        let family = message.body[0];
        let prefix_len = u32::from(message.body[1]);
        let index = u32::from_ne_bytes([
            message.body[4],
            message.body[5],
            message.body[6],
            message.body[7],
        ]);
        for (attr, value) in netlink::parse_attrs(&message.body, IFADDRMSG_LEN) {
            // IFA_LOCAL is the host's own address on a point-to-point link;
            // IFA_ADDRESS is the peer's there and the host's elsewhere. Taking
            // LOCAL where it exists is what keeps a PPP link from reporting the
            // far end as one of ours.
            if attr != libc::IFA_LOCAL && attr != libc::IFA_ADDRESS {
                continue;
            }
            let Some(address) = decode_address(family, value, index) else {
                continue;
            };
            // The address is kept EXACTLY as the kernel reported it, with its
            // prefix length beside it. This used to mask down to an `IpPrefix`,
            // which "enforces canonical form and REFUSES `10.0.0.1/24`" — right
            // for a range matched against untrusted input, and wrong for an
            // interface's own address, whose host bits are the whole point.
            //
            // Two defects close here. `10.0.0.7/24` is now representable, so the
            // core no longer has to reject everything that is not a `/32` or a
            // `/128`. And a link-local address keeps its zone, so `fe80::/64` is
            // no longer silently dropped from this list while
            // `twinvpn-platform-windows` reported it — the divergence recorded as
            // finding X-10, where "the core saw a different address set for one
            // host depending on which adapter was bound".
            if let Ok(interface_address) = InterfaceAddress::new(address, prefix_len) {
                let list = out.entry(index).or_default();
                if !list.contains(&interface_address) {
                    list.push(interface_address);
                }
            }
        }
    }
    Ok(out)
}

/// Per-interface `(v4_default, v6_default)`, from the main table.
async fn dump_default_routes(
    sock: &NetlinkSocket,
) -> Result<HashMap<u32, (bool, bool)>, PlatformError> {
    let mut b = NlBuilder::new(
        libc::RTM_GETROUTE,
        u16::try_from(libc::NLM_F_REQUEST | libc::NLM_F_DUMP).unwrap_or(0x301),
        sock.next_seq(),
    );
    b.payload(&[0u8; RTMSG_LEN]);
    let messages = sock
        .request(b.finish())
        .await
        .map_err(|e| oserr::from_errno(&e, "RTM_GETROUTE", Context::Netlink))?;

    let mut out: HashMap<u32, (bool, bool)> = HashMap::new();
    for message in messages {
        if message.body.len() < RTMSG_LEN {
            continue;
        }
        let family = message.body[0];
        let dst_len = message.body[1];
        let table = message.body[4];
        // A default route is `dst_len == 0` in the MAIN table. Our own table 52
        // is deliberately excluded: the question ADR-0010 R6 asks is whether the
        // HOST has a way out, and our own /1 routes are not that.
        if dst_len != 0 || table != libc::RT_TABLE_MAIN {
            continue;
        }
        for (attr, value) in netlink::parse_attrs(&message.body, RTMSG_LEN) {
            if attr == libc::RTA_OIF && value.len() == 4 {
                let oif = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                let entry = out.entry(oif).or_insert((false, false));
                if family == AF_INET_U8 {
                    entry.0 = true;
                } else if family == AF_INET6_U8 {
                    entry.1 = true;
                }
            }
        }
    }
    Ok(out)
}

fn decode_address(family: u8, value: &[u8], index: u32) -> Option<IpAddr> {
    if family == AF_INET_U8 && value.len() == 4 {
        let mut o = [0u8; 4];
        o.copy_from_slice(value);
        return Some(IpAddr::V4(V4Addr::from_octets(o)));
    }
    if family == AF_INET6_U8 && value.len() == 16 {
        let mut o = [0u8; 16];
        o.copy_from_slice(value);
        // A link-local address needs its zone, and the zone is the interface it
        // was reported on. Without it `V6Addr::new` refuses, which is correct:
        // a link-local address whose interface is unknown matches the wrong
        // segment.
        let is_link_local = o[0] == 0xfe && (o[1] & 0xc0) == 0x80;
        let zone = if is_link_local {
            ZoneIndex::new(index)
        } else {
            None
        };
        return V6Addr::new(o, zone).ok().map(IpAddr::V6);
    }
    None
}


/// Turns one netlink message into the changes it represents.
///
/// Every value is a **fact**, never an instruction: the adapter reports what
/// happened and the core decides what it means. CB-2's falsification test is
/// what keeps that true, and it is why nothing here inspects a
/// `ConnectionState` or decides whether a change is worth reacting to.
fn decode_change(message: &netlink::NlMessage) -> Vec<NetworkChange> {
    let mut out = Vec::new();
    match message.msg_type {
        libc::RTM_NEWLINK | libc::RTM_DELLINK => {
            if message.body.len() < IFINFOMSG_LEN {
                return out;
            }
            let index = InterfaceIndex(u32::from_ne_bytes([
                message.body[4],
                message.body[5],
                message.body[6],
                message.body[7],
            ]));
            let flags = u32::from_ne_bytes([
                message.body[8],
                message.body[9],
                message.body[10],
                message.body[11],
            ]);
            if message.msg_type == libc::RTM_DELLINK {
                out.push(NetworkChange::InterfaceRemoved(index));
            } else {
                let is_up = (flags & u32::try_from(libc::IFF_UP).unwrap_or(1)) != 0
                    && (flags & u32::try_from(libc::IFF_RUNNING).unwrap_or(64)) != 0;
                // Both facts are reported: the kernel sends RTM_NEWLINK for a
                // creation AND for a flag change, and the core is the one that
                // knows whether it already had this index.
                out.push(NetworkChange::InterfaceAdded(index));
                out.push(NetworkChange::LinkStateChanged {
                    interface: index,
                    is_up,
                });
            }
        }
        libc::RTM_NEWADDR | libc::RTM_DELADDR => {
            if message.body.len() < IFADDRMSG_LEN {
                return out;
            }
            let family = message.body[0];
            let index = u32::from_ne_bytes([
                message.body[4],
                message.body[5],
                message.body[6],
                message.body[7],
            ]);
            for (attr, value) in netlink::parse_attrs(&message.body, IFADDRMSG_LEN) {
                if attr != libc::IFA_LOCAL && attr != libc::IFA_ADDRESS {
                    continue;
                }
                let Some(address) = decode_address(family, value, index) else {
                    continue;
                };
                let interface = InterfaceIndex(index);
                out.push(if message.msg_type == libc::RTM_NEWADDR {
                    NetworkChange::AddressAdded { interface, address }
                } else {
                    NetworkChange::AddressRemoved { interface, address }
                });
                break;
            }
        }
        libc::RTM_NEWROUTE | libc::RTM_DELROUTE => {
            if message.body.len() < RTMSG_LEN {
                return out;
            }
            let family = message.body[0];
            let dst_len = message.body[1];
            let table = message.body[4];
            if dst_len != 0 || table != libc::RT_TABLE_MAIN {
                return out;
            }
            // Per family, because ADR-0010 R6's case — "IPv6 appears AFTER the
            // tunnel is up" — is a v6 default route arriving while the v4 one is
            // unchanged, and a combined event would make that indistinguishable
            // from nothing having happened.
            let family = if family == AF_INET_U8 {
                AddressFamily::V4
            } else if family == AF_INET6_U8 {
                AddressFamily::V6
            } else {
                return out;
            };
            out.push(NetworkChange::DefaultRouteChanged {
                family,
                present: message.msg_type == libc::RTM_NEWROUTE,
            });
        }
        _ => {}
    }
    out
}

/// The index of `name`, asked of **the kernel on this process's own netlink
/// socket**.
///
/// # Why not `sysfs`
///
/// An earlier version of this function read `/sys/class/net/<name>/ifindex`,
/// which needs no `unsafe` and is correct on an ordinary host. It is **wrong in
/// a network namespace**: `/sys` is not remounted when a process enters one, so
/// a freshly created interface is invisible under `/sys/class/net` and the
/// lookup returns `ENODEV` for an interface that plainly exists.
///
/// That was found by `tests/netns.rs` and not by any unit test, which is the
/// argument for running one. A netlink query is scoped to the caller's own
/// namespace by construction, which is the property this needs.
///
/// `RTM_GETLINK` **without** `NLM_F_DUMP` and with an `IFLA_IFNAME` filter, so
/// the kernel matches rather than this code walking a dump.
///
/// # Errors
///
/// [`PlatformError`] if netlink is unavailable; `Ok(None)` if the interface
/// simply does not exist, which is a different fact and is reported as one.
pub async fn index_of(name: &str) -> Result<Option<InterfaceIndex>, PlatformError> {
    let sock = NetlinkSocket::open(0)
        .map_err(|e| oserr::from_errno(&e, "AF_NETLINK", Context::Netlink))?;
    let mut b = NlBuilder::new(libc::RTM_GETLINK, netlink::REQUEST, sock.next_seq());
    b.payload(&[0u8; IFINFOMSG_LEN]);
    // NUL-terminated, as the kernel's own `IFLA_IFNAME` policy expects.
    let mut named = name.as_bytes().to_vec();
    named.push(0);
    b.attr(libc::IFLA_IFNAME, &named);

    match sock.request(b.finish()).await {
        Ok(messages) => Ok(messages.first().and_then(|message| {
            if message.body.len() < IFINFOMSG_LEN {
                return None;
            }
            let index = u32::from_ne_bytes([
                message.body[4],
                message.body[5],
                message.body[6],
                message.body[7],
            ]);
            Some(InterfaceIndex(index))
        })),
        // The interface does not exist. Distinct from "netlink is broken", and
        // reported as such rather than collapsed into one answer.
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENODEV | libc::ENOENT)) => Ok(None),
        Err(e) => Err(oserr::from_errno(
            &e,
            "RTM_GETLINK(IFLA_IFNAME)",
            Context::Netlink,
        )),
    }
}

/// The `sysfs` form, for a caller with no async runtime.
///
/// **Namespace-unsafe**, and named so: `/sys` is the host's inside a network
/// namespace. Used only by tests that run outside one; production code uses
/// [`index_of`].
#[must_use]
pub fn index_of_sysfs_unscoped(name: &str) -> Option<InterfaceIndex> {
    let text = fs::read_to_string(format!("/sys/class/net/{name}/ifindex")).ok()?;
    text.trim().parse::<u32>().ok().map(InterfaceIndex)
}

/// The provider, shareable.
#[must_use]
pub fn provider(shutdown: ShutdownLatch) -> Arc<LinuxInterfaceProvider> {
    Arc::new(LinuxInterfaceProvider::new(shutdown))
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_types::IpPrefix;

    /// **An interface address keeps its host bits, and derives the network on
    /// request.**
    ///
    /// This adapter used to mask every kernel-supplied address down to a
    /// canonical `IpPrefix` before it crossed the seam, because that was the
    /// only shape `InterfaceFacts.addresses` could carry — and `10.1.2.3/24`
    /// arrived at the core as `10.1.2.0/24`, which is a network nothing answers
    /// on. The masking helper is gone; `InterfaceAddress` carries both facts and
    /// `network()` is the explicit, named derivation when a route is what is
    /// wanted.
    #[test]
    fn an_address_crosses_the_seam_with_its_host_bits_and_derives_its_network() {
        let addr = IpAddr::V4(V4Addr::from_octets([10, 1, 2, 3]));
        let carried = InterfaceAddress::new(addr, 24).expect("valid");
        assert_eq!(carried.address(), addr, "the host address survives");
        assert_eq!(crate::addr::prefix_text(carried.network()), "10.1.2.0/24");

        // A /0 and a /32 both work, and the /32 is a host route.
        assert_eq!(
            crate::addr::prefix_text(
                InterfaceAddress::new(addr, 0).expect("valid").network()
            ),
            "0.0.0.0/0"
        );
        let host = InterfaceAddress::new(addr, 32).expect("valid");
        assert!(host.is_host_route());
        assert_eq!(crate::addr::prefix_text(host.network()), "10.1.2.3/32");

        // An over-long prefix for the family is refused, not clamped.
        assert!(InterfaceAddress::new(addr, 33).is_err());
    }

    #[test]
    fn a_link_local_v6_address_carries_the_interface_it_was_seen_on() {
        let mut o = [0u8; 16];
        o[0] = 0xfe;
        o[1] = 0x80;
        o[15] = 1;
        let addr = decode_address(AF_INET6_U8, &o, 7).expect("link-local decodes with its zone");
        match addr {
            IpAddr::V6(a) => assert_eq!(a.zone().map(ZoneIndex::get), Some(7)),
            IpAddr::V4(_) => panic!("v6 expected"),
        }
        // A global address must NOT acquire a zone.
        let mut g = [0u8; 16];
        g[0] = 0x20;
        g[1] = 0x01;
        let global = decode_address(AF_INET6_U8, &g, 7).expect("global decodes");
        match global {
            IpAddr::V6(a) => assert_eq!(a.zone(), None),
            IpAddr::V4(_) => panic!("v6 expected"),
        }
    }

    /// **The contract defect this used to pin is closed, and the test is kept
    /// inverted so the closure is asserted rather than assumed.**
    ///
    /// It used to read: `twinvpn-types` cannot represent a link-local IPv6
    /// *prefix* at all — `V6Addr::new` rejects a link-local address with no zone
    /// and `IpPrefix::new` rejects any address that *has* one — so every
    /// `fe80::/64` an interface actually carries was **dropped** from
    /// `InterfaceFacts.addresses`, while `twinvpn-platform-windows` stripped the
    /// zone and kept it. Finding X-10: "the core saw a different address set for
    /// the same host depending on which adapter was bound."
    ///
    /// `InterfaceFacts.addresses` is now a `Vec<InterfaceAddress>`, which is the
    /// right kind of value for an interface's own address and **permits a scope
    /// zone**, because a link-local interface address genuinely has one. Both
    /// halves of the old conjunction still hold for `IpPrefix` — they are right
    /// about a *range* — and neither reaches this list any more.
    #[test]
    fn a_link_local_address_reaches_the_seam_with_its_zone_intact() {
        let mut ll = [0u8; 16];
        ll[0] = 0xfe;
        ll[1] = 0x80;
        ll[15] = 1;
        let address = decode_address(AF_INET6_U8, &ll, 7).expect("link-local decodes");

        // It is now carriable as an INTERFACE ADDRESS, zone and all...
        let carried = InterfaceAddress::new(address, 64).expect("carried with its zone");
        assert_eq!(carried.prefix_len(), 64);
        match carried.address() {
            IpAddr::V6(a) => assert_eq!(a.zone().map(ZoneIndex::get), Some(7)),
            IpAddr::V4(_) => panic!("v6 expected"),
        }

        // ...while `IpPrefix` still refuses it in both directions, which is
        // correct for a range and is why the two are not the same type.
        assert!(V6Addr::new(ll, None).is_err(), "no zone: rejected");
        let zoned = V6Addr::new(ll, ZoneIndex::new(7)).expect("with zone");
        assert!(
            IpPrefix::new(IpAddr::V6(zoned), 64).is_err(),
            "with a zone: still not a prefix"
        );
    }

    #[test]
    fn loopback_is_classified_as_loopback_and_an_unknown_link_says_unknown() {
        assert_eq!(
            classify("lo", libc::ARPHRD_LOOPBACK, None),
            LinkClass::Loopback
        );
        assert_eq!(classify("wg0", 65534, Some("wireguard")), LinkClass::Tunnel);
        // No guess: an unrecognised ARPHRD is Unknown, not Ethernet.
        assert_eq!(classify("weird0", 65533, None), LinkClass::Unknown);
    }

    #[test]
    fn a_default_route_event_names_its_family_and_never_both_at_once() {
        let mut body = vec![0u8; RTMSG_LEN];
        body[0] = AF_INET6_U8;
        body[1] = 0; // dst_len 0 == default
        body[4] = libc::RT_TABLE_MAIN;
        let msg = netlink::NlMessage {
            msg_type: libc::RTM_NEWROUTE,
            flags: 0,
            body,
        };
        let changes = decode_change(&msg);
        assert_eq!(
            changes,
            vec![NetworkChange::DefaultRouteChanged {
                family: AddressFamily::V6,
                present: true
            }]
        );
    }

    #[test]
    fn a_route_in_our_own_table_is_not_reported_as_the_hosts_default() {
        // ADR-0010 R6 asks whether the HOST has a way out. Our own /1 routes in
        // table 52 are not that, and reporting them would make the core believe
        // the underlay still has a default route it does not have.
        let mut body = vec![0u8; RTMSG_LEN];
        body[0] = AF_INET_U8;
        body[4] = netlink::TABLE;
        let msg = netlink::NlMessage {
            msg_type: libc::RTM_NEWROUTE,
            flags: 0,
            body,
        };
        assert!(decode_change(&msg).is_empty());
    }

    #[tokio::test]
    async fn enumeration_finds_the_loopback_interface_with_both_families() {
        let p = LinuxInterfaceProvider::new(ShutdownLatch::new());
        let all = p.enumerate().await.expect("enumerates");
        let lo = all
            .iter()
            .find(|i| i.name.as_str() == "lo")
            .expect("every host has `lo`");
        assert!(lo.is_up);
        assert_eq!(lo.link_class, LinkClass::Loopback);
        assert!(!lo.is_overlay);
        assert!(lo.mtu >= 1280, "lo's MTU is 65536 on Linux");
        // ADR-0010 R1 is about the OVERLAY, but the enumerator still has to
        // report both families wherever the host has them: `lo` has 127.0.0.1
        // and ::1 on every Linux host.
        let families: Vec<AddressFamily> = lo.addresses.iter().map(|p| p.family()).collect();
        assert!(families.contains(&AddressFamily::V4));
        assert!(
            families.contains(&AddressFamily::V6),
            "::1 must be enumerated; a v4-only enumerator is the asymmetry R1 forbids"
        );
    }

    #[tokio::test]
    async fn the_change_stream_opens_and_carries_facts_not_the_initial_state() {
        let p = LinuxInterfaceProvider::new(ShutdownLatch::new());
        let stream = p.subscribe().expect("subscribes");
        // The contract: "the stream carries changes and not the initial state".
        // With nothing happening on the host, nothing must arrive — an adapter
        // that replayed the initial state as a burst of `Added` events would
        // make "we just started" and "the network just changed" the same fact.
        let mut stream = stream;
        let mut cx = std::task::Context::from_waker(futures_noop_waker());
        assert!(
            matches!(stream.as_mut().poll_next(&mut cx), std::task::Poll::Pending),
            "a fresh subscription must not replay state"
        );
    }

    /// A no-op waker, so a poll can be made without a runtime driving it.
    fn futures_noop_waker() -> &'static std::task::Waker {
        use std::sync::OnceLock;
        static WAKER: OnceLock<std::task::Waker> = OnceLock::new();
        WAKER.get_or_init(|| std::task::Waker::noop().clone())
    }

    #[tokio::test]
    async fn subscribing_after_shutdown_is_refused() {
        let latch = ShutdownLatch::new();
        let p = LinuxInterfaceProvider::new(latch.clone());
        latch.begin();
        match p.subscribe() {
            Err(PlatformError::ShuttingDown) => {}
            Err(other) => panic!("wrong refusal: {other:?}"),
            Ok(_) => panic!("a shutting-down adapter must refuse a subscription"),
        }
    }
}
