//! `NWPathMonitor` snapshot decoding: what the OS reported, turned into the
//! seam's facts — and **nothing more**.
//!
//! **Authority:** `docs/networking.md` §5.1 ("event-driven, never polled"),
//! §5.2's iOS change-events column (`NWPathMonitor`, `NEProvider.sleep/wake`),
//! §5.4's iOS and shared rows; ADR-0010 R6 and §11.7; ADR-0022 LC-23a, LC-23b,
//! LC-24; ADR-0018 CB-2.
//!
//! # The one sentence this module exists to obey
//!
//! `docs/networking.md` §5.4, shared row:
//!
//! > "Underlay change does not touch overlay addressing (N2); path re-validation
//! > + make-before-break migration (§4.4). **`MIGRATING`, not `RECONNECTING`.**"
//!
//! That is a *core* decision, and this module must not make it. Everything here
//! produces [`NetworkChange`] values — "an interface appeared", "a v6 default
//! route arrived", "the resolvers changed" — and there is deliberately no
//! function in this file that returns a `ConnectionState`, a migration verdict or
//! a path class. CB-2's falsification test is what keeps it that way: with this
//! shell deleted and the mock adapter bound, `twinvpn-path` still decides
//! `MIGRATING`, because the deciding was never here.
//!
//! # Every wake is a network-change event
//!
//! §5.4's iOS row: "on `wake`, immediately re-validate every path rather than
//! assuming continuity; **treat every wake as a network-change event**". The
//! provider was frozen; `NWPathMonitor` did not run; whatever changed while it
//! was asleep produced no callback. A diff of two snapshots across that gap is
//! therefore *not* a complete account of what happened, and reporting it as one
//! is exactly the "believes it has a complete picture" failure the seam's
//! [`NetworkChange::EventsLost`] variant exists to prevent.
//!
//! [`changes_across_wake`] therefore emits `EventsLost { count: None }` **first**,
//! unconditionally, and then the diff. `count: None` is honest: the platform
//! cannot say how many callbacks it did not deliver. The core re-enumerates and
//! re-validates; this module does not tell it to.
//!
//! # Target-free
//!
//! Swift serialises the `NWPath` it was handed into [`PathSnapshot`]'s canonical
//! JSON and pushes it through [`crate::bridge`]. Everything below runs, and is
//! tested, on the Linux build host.

use serde_json::Value;
use twinvpn_types::{
    AddressFamily, IpAddr, IpPrefix, Nat64Prefix, PerFamily, UnderlayFamilies, V4Addr, V6Addr,
};

use twinvpn_platform::{
    InterfaceFacts, InterfaceIndex, InterfaceName, LinkClass, LinkFacts, NetworkChange,
    PlatformError,
};

use crate::oserr;

/// `limits.json` `routing.max_prefixes_per_advertisement`, reused as the bound on
/// how many addresses one OS-supplied snapshot may carry.
///
/// The snapshot is adapter-supplied rather than peer-supplied, so this is
/// defence in depth rather than a protocol bound — but `ownership.md` §6 rule 10
/// says "bound every allocation an untrusted input can drive", and a snapshot
/// that has crossed a JSON boundary is exactly that.
pub const MAX_ADDRESSES_PER_SNAPSHOT: usize = 256;

/// The bound on interfaces in one snapshot.
///
/// A device with more than this many live interfaces is not a device this
/// product runs on; the value is refused rather than allocated for.
pub const MAX_INTERFACES_PER_SNAPSHOT: usize = 64;

/// One interface, exactly as `NWPathMonitor` described it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInterface {
    /// The OS index (`if_nametoindex`).
    pub index: u32,
    /// The BSD name (`en0`, `pdp_ip0`, `utun3`).
    pub name: String,
    /// `NWInterface.InterfaceType`, as a stable tag.
    pub interface_type: String,
    /// Addresses with their prefix lengths.
    pub addresses: Vec<(IpAddr, u32)>,
    /// Whether the link is up.
    pub is_up: bool,
    /// The interface MTU.
    pub mtu: u32,
}

/// What the monitor most recently reported.
// Five booleans, and each is a distinct fact the core reads on its own. The
// `supports_v4`/`supports_v6` pair in particular must stay separate: ADR-0010 R1
// exists to forbid a design in which "we have a v4 story and a v6 story" is
// sayable, and collapsing the pair into one flag is how that sentence becomes
// true. `metered` and `constrained` are likewise two different OS signals with
// two different responses under ADR-0022 LC-31.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSnapshot {
    /// Every interface in the path.
    pub interfaces: Vec<SnapshotInterface>,
    /// Whether the path is satisfied for IPv4.
    pub supports_v4: bool,
    /// Whether the path is satisfied for IPv6.
    pub supports_v6: bool,
    /// Whether the path is DNS-capable — `NWPath.supportsDNS`.
    pub supports_dns: bool,
    /// Whether the path is expensive (`NWPath.isExpensive`), which is what iOS
    /// means by metered.
    pub metered: bool,
    /// Whether the path is constrained (`NWPath.isConstrained` — Low Data Mode),
    /// which is what iOS means by low power at the *path* level.
    pub constrained: bool,
    /// The system resolvers, per family, when the shell could read them.
    pub resolvers: PerFamily<Vec<IpAddr>>,
    /// The discovered NAT64 prefix, from the RFC 8781 RA option.
    pub nat64_prefix: Option<Nat64Prefix>,
    /// Which prefix of ours the tunnel occupies, so `is_overlay` is answered by
    /// a name this build chose rather than by a link kind.
    pub overlay_name_prefix: String,
}

impl PathSnapshot {
    /// Parses the canonical JSON Swift produces.
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] on malformed bytes or a snapshot
    /// exceeding a declared bound. An adapter that hands the core a
    /// ten-thousand-interface snapshot is malfunctioning, and truncating it
    /// would produce a picture of the network that is confidently wrong.
    pub fn parse(json: &str) -> Result<Self, PlatformError> {
        let value: Value = serde_json::from_str(json)
            .map_err(|_| oserr::unavailable("NWPathMonitor.snapshot.decode", 0))?;
        let object = value
            .as_object()
            .ok_or_else(|| oserr::unavailable("NWPathMonitor.snapshot.shape", 0))?;

        let raw_interfaces = object
            .get("interfaces")
            .and_then(Value::as_array)
            .ok_or_else(|| oserr::unavailable("NWPathMonitor.snapshot.interfaces", 0))?;
        if raw_interfaces.len() > MAX_INTERFACES_PER_SNAPSHOT {
            return Err(oserr::unavailable(
                "limits.snapshot.max_interfaces",
                i32::try_from(raw_interfaces.len()).unwrap_or(i32::MAX),
            ));
        }

        let mut interfaces = Vec::with_capacity(raw_interfaces.len());
        for entry in raw_interfaces {
            interfaces.push(parse_interface(entry)?);
        }

        Ok(Self {
            interfaces,
            supports_v4: flag(object.get("supports_v4")),
            supports_v6: flag(object.get("supports_v6")),
            supports_dns: flag(object.get("supports_dns")),
            metered: flag(object.get("metered")),
            constrained: flag(object.get("constrained")),
            resolvers: PerFamily::new(
                parse_addresses(object.get("resolvers_v4"))?,
                parse_addresses(object.get("resolvers_v6"))?,
            ),
            nat64_prefix: parse_nat64(object.get("nat64_prefix"))?,
            overlay_name_prefix: object
                .get("overlay_name_prefix")
                .and_then(Value::as_str)
                .unwrap_or("utun")
                .to_owned(),
        })
    }

    /// The interfaces, as the seam's facts.
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] if a name is unusable.
    pub fn interface_facts(&self) -> Result<Vec<InterfaceFacts>, PlatformError> {
        self.interfaces
            .iter()
            .map(|iface| {
                let is_overlay = iface.name.starts_with(&self.overlay_name_prefix);
                Ok(InterfaceFacts {
                    index: InterfaceIndex(iface.index),
                    name: InterfaceName::new(&iface.name)?,
                    addresses: interface_prefixes(iface),
                    // `NWPath` reports reachability for the path as a whole, not
                    // a per-interface routing table — iOS exposes no route API to
                    // ask. So a non-overlay interface that is up on a path
                    // satisfied for a family is reported as carrying that
                    // family's default route, and the overlay never is: claiming
                    // our own tunnel has the host's default would make ADR-0010
                    // R6's "did v6 acquire a way out" unanswerable.
                    has_default_route_v4: !is_overlay && iface.is_up && self.supports_v4,
                    has_default_route_v6: !is_overlay && iface.is_up && self.supports_v6,
                    is_overlay,
                    is_up: iface.is_up,
                    mtu: iface.mtu,
                    link_class: link_class(&iface.interface_type),
                })
            })
            .collect()
    }

    /// The underlay facts `query_link_facts()` reports.
    ///
    /// `mtu` is the smallest non-overlay MTU on the path, or the IPv6 minimum
    /// when the path carries none: `docs/networking.md` §6.2 selects a 1280 floor,
    /// and reporting a larger figure we did not observe would start DPLPMTUD
    /// above the floor it is meant to probe up from.
    #[must_use]
    pub fn link_facts(&self) -> LinkFacts {
        const IPV6_MINIMUM_MTU: u32 = 1280;
        let mtu = self
            .interfaces
            .iter()
            .filter(|i| i.is_up && !i.name.starts_with(&self.overlay_name_prefix))
            .map(|i| i.mtu)
            .filter(|mtu| *mtu > 0)
            .min()
            .unwrap_or(IPV6_MINIMUM_MTU);

        LinkFacts {
            mtu,
            families: self.families(),
            default_routes: PerFamily::new(self.supports_v4, self.supports_v6),
            resolvers: self.resolvers.clone(),
            metered: self.metered,
            // `NWPath.isConstrained` is Low Data Mode, which is a *path* signal.
            // ADR-0022 LC-31 also takes `ProcessInfo.thermalState`, which is a
            // *process* signal and reaches the adapter through
            // `crate::lifecycle` rather than through the path monitor — two
            // sources, and collapsing them here would make "the network is
            // rationed" and "the device is hot" the same fact.
            low_power: self.constrained,
        }
    }

    /// Which families the underlay carries (ADR-0010 §11.7).
    #[must_use]
    pub fn families(&self) -> UnderlayFamilies {
        match (self.supports_v4, self.supports_v6) {
            (true, true) => UnderlayFamilies::DualStack,
            (false, true) => UnderlayFamilies::V6Only {
                nat64: self.nat64_prefix,
            },
            // A path with neither family satisfied is reported as v4-only rather
            // than invented into a fourth value the type does not have; the
            // `default_routes` pair in `LinkFacts` carries the truth, and
            // `supports_v4 == false` is what the core reads there.
            _ => {
                if self.nat64_prefix.is_some() {
                    // 464XLAT: ADR-0010 §11.7 treats it "as IPv4 with
                    // underlay=xlat", and it is deliberately NOT the same value
                    // as V4Only because the MTU and NAT-class consequences do not
                    // follow from plain IPv4.
                    UnderlayFamilies::Xlat464
                } else {
                    UnderlayFamilies::V4Only
                }
            }
        }
    }
}

/// The snapshot most recently delivered, shared between [`crate::iface`] and
/// [`crate::netcfg`].
///
/// # Why one cell and not two readers
///
/// [`InterfaceProvider::enumerate`] and [`twinvpn_platform::NetworkConfig::query_link_facts`]
/// are on **different traits**, and a first draft had each fetch its own snapshot
/// — the interface provider from what the bridge had pushed, the network config
/// from `NWPathMonitor.currentPath`. Its own matrix test caught the consequence:
/// the two describe **different instants**, so the core could enumerate one
/// network and read link facts for another, with no event between them saying so.
///
/// Both now read this cell, which the bridge writes once per `pathUpdateHandler`
/// callback. One observation, one instant, two views of it.
///
/// [`InterfaceProvider::enumerate`]: twinvpn_platform::InterfaceProvider::enumerate
#[derive(Debug, Clone, Default)]
pub struct ObservedPath(std::sync::Arc<std::sync::Mutex<Option<PathSnapshot>>>);

impl ObservedPath {
    /// The snapshot most recently observed, if any.
    #[must_use]
    pub fn get(&self) -> Option<PathSnapshot> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Records an observation, returning the one it replaced.
    pub fn replace(&self, snapshot: PathSnapshot) -> Option<PathSnapshot> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace(snapshot)
    }
}

/// The changes between two snapshots — facts only, never a verdict.
#[must_use]
pub fn diff(previous: &PathSnapshot, current: &PathSnapshot) -> Vec<NetworkChange> {
    let mut out = Vec::new();

    let before: std::collections::BTreeMap<u32, &SnapshotInterface> =
        previous.interfaces.iter().map(|i| (i.index, i)).collect();
    let after: std::collections::BTreeMap<u32, &SnapshotInterface> =
        current.interfaces.iter().map(|i| (i.index, i)).collect();

    for (index, iface) in &after {
        match before.get(index) {
            None => out.push(NetworkChange::InterfaceAdded(InterfaceIndex(*index))),
            Some(was) => {
                if was.is_up != iface.is_up {
                    out.push(NetworkChange::LinkStateChanged {
                        interface: InterfaceIndex(*index),
                        is_up: iface.is_up,
                    });
                }
                for (addr, _) in &iface.addresses {
                    if !was.addresses.iter().any(|(a, _)| a == addr) {
                        out.push(NetworkChange::AddressAdded {
                            interface: InterfaceIndex(*index),
                            address: *addr,
                        });
                    }
                }
                for (addr, _) in &was.addresses {
                    if !iface.addresses.iter().any(|(a, _)| a == addr) {
                        out.push(NetworkChange::AddressRemoved {
                            interface: InterfaceIndex(*index),
                            address: *addr,
                        });
                    }
                }
            }
        }
    }
    for index in before.keys() {
        if !after.contains_key(index) {
            out.push(NetworkChange::InterfaceRemoved(InterfaceIndex(*index)));
        }
    }

    // Per family, never combined. ADR-0010 R6's case is "IPv6 appears *after*
    // the tunnel is up" — a v6 default arriving while the v4 one is unchanged —
    // and a single merged event would make that indistinguishable from nothing
    // having happened.
    if previous.supports_v4 != current.supports_v4 {
        out.push(NetworkChange::DefaultRouteChanged {
            family: AddressFamily::V4,
            present: current.supports_v4,
        });
    }
    if previous.supports_v6 != current.supports_v6 {
        out.push(NetworkChange::DefaultRouteChanged {
            family: AddressFamily::V6,
            present: current.supports_v6,
        });
    }

    if previous.resolvers != current.resolvers {
        out.push(NetworkChange::ResolversChanged);
    }
    if previous.nat64_prefix != current.nat64_prefix {
        out.push(NetworkChange::Nat64PrefixChanged(current.nat64_prefix));
    }
    if previous.metered != current.metered || previous.constrained != current.constrained {
        out.push(NetworkChange::LinkPostureChanged {
            metered: current.metered,
            low_power: current.constrained,
        });
    }

    out
}

/// The changes to report after `NEProvider.wake()`.
///
/// `docs/networking.md` §5.4: "on `wake`, immediately re-validate every path
/// rather than assuming continuity; treat every wake as a network-change event."
///
/// The first element is **always** [`NetworkChange::EventsLost`] with
/// `count: None`, whether or not the snapshots differ. A wake is a statement
/// that the monitor was not running, so "the snapshots look the same" is not
/// evidence that nothing happened — and ADR-0018 §11.6's rule that "a dropped
/// event is itself recorded" is exactly the primitive for saying so. The core
/// re-enumerates on seeing it; this function does not instruct it to.
#[must_use]
pub fn changes_across_wake(previous: &PathSnapshot, current: &PathSnapshot) -> Vec<NetworkChange> {
    let mut out = vec![NetworkChange::EventsLost { count: None }];
    out.extend(diff(previous, current));
    out
}

/// Maps `NWInterface.InterfaceType` onto the seam's link class.
///
/// A **domain fact**, not an OS branch: `docs/reliability.md` emits
/// `NET.LINK.DOWN_WIFI` and `NET.LINK.DOWN_CELLULAR` as distinct codes, so the
/// core needs the class. An unknown tag maps to [`LinkClass::Unknown`] rather
/// than to a guess — "the OS does not say" is a value the enum has for exactly
/// this case, and inventing `WiFi` for an unrecognised type would make a
/// cellular-to-Wi-Fi migration report the wrong code.
#[must_use]
pub fn link_class(interface_type: &str) -> LinkClass {
    match interface_type {
        "wifi" => LinkClass::WiFi,
        "cellular" => LinkClass::Cellular,
        "wiredEthernet" | "ethernet" => LinkClass::Ethernet,
        "loopback" => LinkClass::Loopback,
        "other" => LinkClass::Tunnel,
        _ => LinkClass::Unknown,
    }
}

fn flag(value: Option<&Value>) -> bool {
    value.and_then(Value::as_bool).unwrap_or(false)
}

fn parse_interface(entry: &Value) -> Result<SnapshotInterface, PlatformError> {
    let object = entry
        .as_object()
        .ok_or_else(|| oserr::unavailable("NWPathMonitor.interface.shape", 0))?;
    let raw_addresses = object
        .get("addresses")
        .and_then(Value::as_array)
        .map_or(&[][..], |a| a.as_slice());
    if raw_addresses.len() > MAX_ADDRESSES_PER_SNAPSHOT {
        return Err(oserr::unavailable(
            "limits.snapshot.max_addresses",
            i32::try_from(raw_addresses.len()).unwrap_or(i32::MAX),
        ));
    }
    let mut addresses = Vec::with_capacity(raw_addresses.len());
    for raw in raw_addresses {
        let object = raw
            .as_object()
            .ok_or_else(|| oserr::unavailable("NWPathMonitor.address.shape", 0))?;
        let addr = parse_address(object.get("address"))?;
        let prefix_len = object
            .get("prefix_length")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or_else(|| addr.family().max_prefix_len());
        addresses.push((addr, prefix_len));
    }
    Ok(SnapshotInterface {
        index: object
            .get("index")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| oserr::unavailable("NWPathMonitor.interface.index", 0))?,
        name: object
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| oserr::unavailable("NWPathMonitor.interface.name", 0))?
            .to_owned(),
        interface_type: object
            .get("interface_type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned(),
        addresses,
        is_up: flag(object.get("is_up")),
        mtu: object
            .get("mtu")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(0),
    })
}

fn parse_addresses(value: Option<&Value>) -> Result<Vec<IpAddr>, PlatformError> {
    let Some(array) = value.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    if array.len() > MAX_ADDRESSES_PER_SNAPSHOT {
        return Err(oserr::unavailable(
            "limits.snapshot.max_addresses",
            i32::try_from(array.len()).unwrap_or(i32::MAX),
        ));
    }
    array.iter().map(|v| parse_address(Some(v))).collect()
}

/// Parses an address from its octets.
///
/// Octets rather than text: the shell already has the bytes from
/// `NWEndpoint`/`sockaddr`, and a text round-trip is a parser this adapter would
/// have to get exactly as right as the OS's own.
fn parse_address(value: Option<&Value>) -> Result<IpAddr, PlatformError> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| oserr::unavailable("NWPathMonitor.address.shape", 0))?;
    let octets: Vec<u8> = object
        .get("octets")
        .and_then(Value::as_array)
        .ok_or_else(|| oserr::unavailable("NWPathMonitor.address.octets", 0))?
        .iter()
        .map(|v| {
            v.as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or_else(|| oserr::unavailable("NWPathMonitor.address.octet", 0))
        })
        .collect::<Result<_, _>>()?;
    match octets.len() {
        4 => Ok(IpAddr::V4(V4Addr::from_slice(&octets).map_err(|_| {
            oserr::unavailable("NWPathMonitor.address.v4", 0)
        })?)),
        16 => {
            let zone = object
                .get("zone")
                .and_then(Value::as_u64)
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0);
            Ok(IpAddr::V6(V6Addr::from_slice(&octets, zone).map_err(
                |_| oserr::unavailable("NWPathMonitor.address.v6", 0),
            )?))
        }
        _ => Err(oserr::unavailable("NWPathMonitor.address.length", 0)),
    }
}

fn parse_nat64(value: Option<&Value>) -> Result<Option<Nat64Prefix>, PlatformError> {
    let Some(object) = value.and_then(Value::as_object) else {
        return Ok(None);
    };
    let IpAddr::V6(addr) = parse_address(object.get("address"))? else {
        return Err(oserr::unavailable("NWPathMonitor.nat64.family", 0));
    };
    let prefix_len = object
        .get("prefix_length")
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| oserr::unavailable("NWPathMonitor.nat64.prefix_length", 0))?;
    Ok(Some(Nat64Prefix::new(addr.octets(), prefix_len).map_err(
        |_| oserr::unavailable("NWPathMonitor.nat64.shape", 0),
    )?))
}

/// The addresses of one interface, as [`IpPrefix`] values.
///
/// # A known defect, inherited rather than introduced
///
/// [`InterfaceFacts::addresses`] is `Vec<IpPrefix>` and [`IpPrefix`] requires
/// every host bit to be zero, so an interface holding `192.0.2.10/24` has no
/// representation for the address the core actually needs — the one to bind and
/// to offer as a host candidate. The same conjunction drops every link-local v6
/// address, because [`V6Addr`] demands a zone on `fe80::/10` and [`IpPrefix`]
/// rejects any zone (W-39).
///
/// The seam's own comment records the replacement (`InterfaceAddress`) and says
/// the flip "lands as a coordinated commit across those domains rather than as a
/// red build from this one". So this function keeps the addresses it *can*
/// represent and drops the rest, rather than masking a host address to its
/// network — a network address offered as a candidate probes where nothing
/// answers and reads as a NAT fault.
fn interface_prefixes(iface: &SnapshotInterface) -> Vec<IpPrefix> {
    iface
        .addresses
        .iter()
        .filter_map(|(addr, len)| IpPrefix::new(*addr, *len).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use super::*;

    fn snapshot(json: &str) -> PathSnapshot {
        PathSnapshot::parse(json).expect("parses")
    }

    fn wifi_v4_only() -> PathSnapshot {
        snapshot(
            r#"{"interfaces":[{"index":1,"name":"en0","interface_type":"wifi","is_up":true,
                "mtu":1500,"addresses":[{"address":{"octets":[192,168,1,20]},"prefix_length":32}]}],
                "supports_v4":true,"supports_v6":false,"supports_dns":true,
                "metered":false,"constrained":false,"overlay_name_prefix":"utun"}"#,
        )
    }

    fn cellular_dual_stack() -> PathSnapshot {
        snapshot(
            r#"{"interfaces":[{"index":2,"name":"pdp_ip0","interface_type":"cellular",
                "is_up":true,"mtu":1428,
                "addresses":[{"address":{"octets":[100,80,0,5]},"prefix_length":32}]}],
                "supports_v4":true,"supports_v6":true,"supports_dns":true,
                "metered":true,"constrained":false,"overlay_name_prefix":"utun"}"#,
        )
    }

    #[test]
    fn a_wifi_to_cellular_roam_reports_facts_and_never_a_verdict() {
        // `networking.md` §5.4: the roam is `MIGRATING`, not `RECONNECTING` —
        // and that is the CORE's decision. This adapter reports what the OS
        // said; nothing here names a ConnectionState.
        let changes = diff(&wifi_v4_only(), &cellular_dual_stack());
        assert!(changes.contains(&NetworkChange::InterfaceAdded(InterfaceIndex(2))));
        assert!(changes.contains(&NetworkChange::InterfaceRemoved(InterfaceIndex(1))));
        assert!(changes.contains(&NetworkChange::DefaultRouteChanged {
            family: AddressFamily::V6,
            present: true
        }));
        assert!(changes.contains(&NetworkChange::LinkPostureChanged {
            metered: true,
            low_power: false
        }));
        // The v4 default did not change, so no v4 event is manufactured.
        assert!(!changes.contains(&NetworkChange::DefaultRouteChanged {
            family: AddressFamily::V4,
            present: true
        }));
    }

    #[test]
    fn ipv6_arriving_after_the_tunnel_is_up_is_its_own_event() {
        // ADR-0010 R6: IPv6 must not bypass tunnel policy "including when IPv6
        // appears AFTER the tunnel is up". A combined default-route event would
        // make that indistinguishable from nothing happening.
        let mut later = wifi_v4_only();
        later.supports_v6 = true;
        let changes = diff(&wifi_v4_only(), &later);
        assert_eq!(
            changes,
            vec![NetworkChange::DefaultRouteChanged {
                family: AddressFamily::V6,
                present: true
            }]
        );
    }

    #[test]
    fn every_wake_reports_lost_events_even_when_the_snapshots_are_identical() {
        // `networking.md` §5.4's iOS row: "treat every wake as a network-change
        // event" and "re-validate every path rather than assuming continuity".
        // A quiet diff across a suspension is not evidence that nothing changed
        // — the monitor was not running.
        let same = wifi_v4_only();
        let changes = changes_across_wake(&same, &same);
        assert_eq!(
            changes.first(),
            Some(&NetworkChange::EventsLost { count: None })
        );
        assert_eq!(changes.len(), 1, "and nothing is invented beyond it");

        // A plain diff of the same two snapshots says nothing at all, which is
        // exactly why the wake path cannot be a plain diff.
        assert!(diff(&same, &same).is_empty());
    }

    #[test]
    fn a_wake_that_did_change_reports_the_loss_first_and_then_the_diff() {
        let changes = changes_across_wake(&wifi_v4_only(), &cellular_dual_stack());
        assert_eq!(changes[0], NetworkChange::EventsLost { count: None });
        assert!(changes.len() > 1);
    }

    #[test]
    fn the_link_class_is_the_os_tag_and_an_unknown_one_is_not_guessed() {
        assert_eq!(link_class("wifi"), LinkClass::WiFi);
        assert_eq!(link_class("cellular"), LinkClass::Cellular);
        assert_eq!(link_class("wiredEthernet"), LinkClass::Ethernet);
        assert_eq!(link_class("loopback"), LinkClass::Loopback);
        assert_eq!(link_class("other"), LinkClass::Tunnel);
        // Guessing WiFi here would make a cellular roam emit NET.LINK.DOWN_WIFI.
        assert_eq!(link_class("nwInterfaceTypeFuture"), LinkClass::Unknown);
        assert_eq!(link_class(""), LinkClass::Unknown);
    }

    #[test]
    fn the_overlay_is_named_by_our_own_prefix_and_not_by_a_link_kind() {
        let path = snapshot(
            r#"{"interfaces":[
                {"index":1,"name":"en0","interface_type":"wifi","is_up":true,"mtu":1500},
                {"index":9,"name":"utun4","interface_type":"other","is_up":true,"mtu":1280}],
                "supports_v4":true,"supports_v6":true,"supports_dns":true,
                "metered":false,"constrained":false,"overlay_name_prefix":"utun"}"#,
        );
        let facts = path.interface_facts().expect("facts");
        let overlay = facts.iter().find(|f| f.is_overlay).expect("one overlay");
        assert_eq!(overlay.index, InterfaceIndex(9));
        // Our own tunnel must never be reported as carrying the host default
        // route, or ADR-0010 R6's "did v6 acquire a way out" is unanswerable.
        assert!(!overlay.has_default_route_v4);
        assert!(!overlay.has_default_route_v6);
        let underlay = facts.iter().find(|f| !f.is_overlay).expect("one underlay");
        assert!(underlay.has_default_route_v4 && underlay.has_default_route_v6);
    }

    #[test]
    fn an_ipv6_only_path_carries_its_nat64_prefix() {
        // ADR-0010 §11.7: IPv6-only-with-NAT64 and IPv6-only-without are two
        // distinct situations with two distinct behaviours.
        let with = snapshot(
            r#"{"interfaces":[],"supports_v4":false,"supports_v6":true,"supports_dns":true,
                "metered":false,"constrained":false,
                "nat64_prefix":{"address":{"octets":[0,100,255,155,0,0,0,0,0,0,0,0,0,0,0,0]},
                "prefix_length":96}}"#,
        );
        assert!(matches!(
            with.families(),
            UnderlayFamilies::V6Only { nat64: Some(_) }
        ));
        let without = snapshot(
            r#"{"interfaces":[],"supports_v4":false,"supports_v6":true,"supports_dns":true,
                "metered":false,"constrained":false}"#,
        );
        assert_eq!(without.families(), UnderlayFamilies::V6Only { nat64: None });
    }

    #[test]
    fn a_nat64_prefix_with_no_v6_path_is_464xlat_and_not_plain_v4() {
        // ADR-0010 §11.7: 464XLAT is "NOT the same value as V4Only, because
        // those two consequences" — reduced MTU and CGNAT-equivalent NAT class —
        // "do not follow from plain IPv4."
        let xlat = snapshot(
            r#"{"interfaces":[],"supports_v4":true,"supports_v6":false,"supports_dns":true,
                "metered":false,"constrained":false,
                "nat64_prefix":{"address":{"octets":[0,100,255,155,0,0,0,0,0,0,0,0,0,0,0,0]},
                "prefix_length":96}}"#,
        );
        assert_eq!(xlat.families(), UnderlayFamilies::Xlat464);
        assert_eq!(wifi_v4_only().families(), UnderlayFamilies::V4Only);
    }

    #[test]
    fn the_link_mtu_is_the_smallest_underlay_and_never_the_tunnels_own() {
        let path = snapshot(
            r#"{"interfaces":[
                {"index":1,"name":"en0","interface_type":"wifi","is_up":true,"mtu":1500},
                {"index":2,"name":"pdp_ip0","interface_type":"cellular","is_up":true,"mtu":1428},
                {"index":9,"name":"utun4","interface_type":"other","is_up":true,"mtu":1280}],
                "supports_v4":true,"supports_v6":true,"supports_dns":true,
                "metered":false,"constrained":false,"overlay_name_prefix":"utun"}"#,
        );
        assert_eq!(path.link_facts().mtu, 1428);
    }

    #[test]
    fn a_path_with_no_underlay_reports_the_ipv6_floor_and_not_a_larger_guess() {
        // §6.2 selects "1280 floor + DPLPMTUD". Reporting a figure we did not
        // observe would start the probe above the floor it probes up from.
        let path = snapshot(
            r#"{"interfaces":[],"supports_v4":false,"supports_v6":false,"supports_dns":false,
                "metered":false,"constrained":false}"#,
        );
        assert_eq!(path.link_facts().mtu, 1280);
    }

    #[test]
    fn metered_and_low_power_are_separate_path_facts() {
        let mut path = wifi_v4_only();
        path.metered = true;
        path.constrained = true;
        let facts = path.link_facts();
        assert!(facts.metered && facts.low_power);
        assert_eq!(facts.default_routes, PerFamily::new(true, false));
    }

    #[test]
    fn an_oversized_snapshot_is_refused_rather_than_allocated_for() {
        // `ownership.md` §6 rule 10: bound every allocation an untrusted input
        // can drive. A snapshot that has crossed a JSON boundary is one.
        let mut interfaces = String::from("[");
        for i in 0..=MAX_INTERFACES_PER_SNAPSHOT {
            if i > 0 {
                interfaces.push(',');
            }
            write!(
                interfaces,
                r#"{{"index":{i},"name":"en{i}","interface_type":"wifi","is_up":true,"mtu":1500}}"#
            )
            .expect("writing to a String cannot fail");
        }
        interfaces.push(']');
        let json = format!(
            r#"{{"interfaces":{interfaces},"supports_v4":true,"supports_v6":true,
                "supports_dns":true,"metered":false,"constrained":false}}"#
        );
        let err = PathSnapshot::parse(&json).expect_err("refuses");
        assert_eq!(
            err.os_detail().map(|d| d.call),
            Some("limits.snapshot.max_interfaces")
        );
    }

    #[test]
    fn malformed_bytes_are_a_named_condition_and_never_an_empty_path() {
        // An empty path would read as "the device is offline", which is a
        // different and far more consequential statement than "the shell sent
        // us something we could not read".
        for bad in ["", "null", "[]", r#"{"interfaces":3}"#] {
            let err = PathSnapshot::parse(bad).expect_err("refuses");
            assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
        }
    }

    #[test]
    fn a_link_local_v6_address_is_dropped_rather_than_mangled() {
        // W-39: V6Addr requires a zone on fe80::/10 and IpPrefix rejects any
        // zone. Both rules are individually right; their conjunction makes the
        // address unrepresentable. Dropping it is exact; masking it to a network
        // address would offer a candidate that probes where nothing answers.
        let path = snapshot(
            r#"{"interfaces":[{"index":1,"name":"en0","interface_type":"wifi","is_up":true,
                "mtu":1500,"addresses":[
                {"address":{"octets":[254,128,0,0,0,0,0,0,0,0,0,0,0,0,0,1],"zone":1},
                 "prefix_length":128},
                {"address":{"octets":[192,168,1,20]},"prefix_length":32}]}],
                "supports_v4":true,"supports_v6":true,"supports_dns":true,
                "metered":false,"constrained":false}"#,
        );
        let facts = path.interface_facts().expect("facts");
        assert_eq!(
            facts[0].addresses.len(),
            1,
            "the v4 host address survives; the zoned link-local cannot be spelled"
        );
    }

    #[test]
    fn a_resolver_change_is_its_own_event() {
        let mut later = wifi_v4_only();
        later.resolvers = PerFamily::new(
            vec![IpAddr::V4(V4Addr::from_octets([1, 1, 1, 1]))],
            Vec::new(),
        );
        assert!(diff(&wifi_v4_only(), &later).contains(&NetworkChange::ResolversChanged));
    }
}
