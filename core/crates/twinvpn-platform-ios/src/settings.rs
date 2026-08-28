//! The `NEPacketTunnelNetworkSettings` **programme**, rendered from a
//! [`NetworkContract`] — addresses, routes, DNS and MTU, both families, one
//! object.
//!
//! **Authority:** `docs/networking.md` §5.1 (the adapter contract) and §5.2's
//! iOS row — "`NEPacketTunnelNetworkSettings` only (no route API)";
//! ADR-0010 R1 and §11.3's iOS row; ADR-0011 §11.2, §11.7 and §11.9's iOS rows;
//! ADR-0018 CB-2; `contracts/registry/limits.json`.
//!
//! # Why this is Rust and not Swift
//!
//! On this platform `setTunnelNetworkSettings` is the *entire* mechanism for
//! address, route, resolver and MTU programming: §5.2's iOS row records that
//! there is **no route API**, and ADR-0016's O2 row says the same from the
//! privilege side. So the question "which routes, which resolvers, which match
//! domains, which MTU" is the whole of `apply()` here — and it is a decision.
//! CB-2 puts it in Rust; `ownership.md` §10.3 adds that a layer written in Swift
//! moves from *executed* to *written, not compiled*. This module is therefore
//! plain data over plain data, and its tests run on the Linux build host.
//!
//! Swift receives [`TunnelSettingsProgramme::to_json`] and builds the
//! `NEPacketTunnelNetworkSettings` from it field by field. It chooses nothing.
//!
//! # Both families, in one object, always
//!
//! ADR-0010 R1: "Every `Device` MUST have both an IPv4 and an IPv6 overlay
//! address, always, regardless of underlay family." §11.3 adds the normative
//! rule that "IPv4 and IPv6 routes MUST be installed in the same `apply()`
//! transaction. An implementation that can install one family's routes without
//! the other's is non-conforming." Here that is structural:
//! [`TunnelSettingsProgramme`] has a non-optional `ipv4` and a non-optional
//! `ipv6`, so there is no shape of this type that carries one family and not the
//! other, and a Swift side that forgot `IPv6Settings` would be reading a field
//! that is always present.
//!
//! # The default route is a marker, not a prefix
//!
//! ADR-0010 §11.3's iOS row gives the default-route form as
//! `NEIPv4Route.default()` + `NEIPv6Route.default()` — **not** the
//! `0.0.0.0/1` + `128.0.0.0/1` pair Linux installs. Linux splits the default so
//! it can add one "without destroying the host's default route"; on iOS the
//! settings object *is* the routing table for the tunnel and there is no host
//! default to preserve inside it. So a `0.0.0.0/0` or `::/0` entry renders as the
//! platform's own default marker, and [`RouteProgramme::Default`] is what carries
//! that across to Swift.

use core::fmt::Write as _;

use serde_json::{json, Map, Value};
use twinvpn_types::{AddressFamily, IpAddr, IpPrefix};

use crate::oserr;
use twinvpn_platform::{DnsConfig, NetworkContract, PlatformError, RouteEntry};

/// `limits.json` `dns.max_resolvers_per_family`.
pub const MAX_RESOLVERS_PER_FAMILY: usize = 8;
/// `limits.json` `dns.max_search_domains`.
pub const MAX_SEARCH_DOMAINS: usize = 32;
/// `limits.json` `dns.max_split_domain_rules`.
pub const MAX_SPLIT_DOMAIN_RULES: usize = 256;
/// `limits.json` `dns.max_domain_name_bytes`.
pub const MAX_DOMAIN_NAME_BYTES: usize = 253;

/// The domain `mDNSResponder` sends to multicast whatever we configure.
///
/// ADR-0011 N2: "On macOS and iOS `mDNSResponder` sends `.local` to multicast
/// regardless of what we configure", and §11.7's iOS row requires it excluded
/// from `matchDomains`. Claiming it would be a claim the OS does not honour, and
/// a resolver posture that lies is worse than one that discloses.
pub const MDNS_RESERVED_SUFFIX: &str = "local";

/// One route, in the form iOS accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteProgramme {
    /// `NEIPv4Route.default()` / `NEIPv6Route.default()`.
    Default,
    /// An explicit destination prefix.
    Prefix {
        /// The destination address, in canonical text.
        address: String,
        /// The subnet mask (v4) or prefix length (v6), as iOS takes it.
        mask_or_length: String,
    },
}

/// A residual this render could not carry, stated rather than dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsResidual {
    /// The core supplied a route metric and `NEIPv4Route`/`NEIPv6Route` have no
    /// metric field.
    ///
    /// `RouteEntry::metric` exists because `docs/networking.md` §7.2 installs a
    /// default route "without destroying the host's default route", which "on
    /// several targets is a metric question". iOS is not one of them — the
    /// settings object scopes the routes to the tunnel — so the value is
    /// *unrepresentable rather than ignored*, and this says so.
    RouteMetricUnrepresentable {
        /// How many entries carried one.
        count: usize,
    },
    /// A split domain was dropped because the OS will not honour a claim on it.
    MdnsDomainNotClaimable {
        /// The domain, as supplied.
        domain: String,
    },
    /// A route pointed through an interface index the settings object cannot
    /// name.
    ///
    /// `NEPacketTunnelNetworkSettings` scopes every route to the tunnel by
    /// construction; there is no per-route interface. An entry naming another
    /// interface therefore cannot be expressed, and is refused rather than
    /// silently re-pointed at the tunnel — which would send somebody else's
    /// traffic into ours.
    RouteInterfaceUnrepresentable {
        /// The index the entry named.
        interface: u32,
    },
}

/// The rendered programme, and everything it could not carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelSettingsProgramme {
    /// The tunnel remote address the settings object is constructed with.
    pub tunnel_remote_address: String,
    /// IPv4 addresses, subnet masks and routes. **Never absent** (R1).
    pub ipv4: FamilySettings,
    /// IPv6 addresses, prefix lengths and routes. **Never absent** (R1).
    pub ipv6: FamilySettings,
    /// The resolver programme.
    pub dns: DnsProgramme,
    /// The tunnel MTU.
    pub mtu: u32,
    /// What could not be expressed on this platform.
    pub residuals: Vec<SettingsResidual>,
}

/// One family's half of the settings object.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FamilySettings {
    /// Overlay addresses, in canonical text.
    pub addresses: Vec<String>,
    /// The mask (v4) or prefix length (v6) for each address, index-parallel.
    pub masks: Vec<String>,
    /// Routes to send through the tunnel.
    pub included_routes: Vec<RouteProgramme>,
    /// Routes to keep off the tunnel.
    pub excluded_routes: Vec<RouteProgramme>,
}

/// The `NEDNSSettings` half.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsProgramme {
    /// Resolver addresses, both families, in the order the core supplied.
    pub servers: Vec<String>,
    /// Search domains.
    pub search_domains: Vec<String>,
    /// `matchDomains`. An empty list is **not** the same as `[""]`: the empty
    /// list claims nothing, and `[""]` claims everything.
    pub match_domains: Vec<String>,
    /// Whether the resolver is the system default for everything else, which iOS
    /// expresses as `matchDomains = [""]`.
    pub is_default_resolver: bool,
}

/// Renders a contract into the programme Swift installs.
///
/// # Errors
///
/// A limit violation from `contracts/registry/limits.json` is a typed refusal,
/// never a truncation and never a pad (`ownership.md` §6 rule 9). The seam's
/// [`PlatformError`] has no variant for "the caller handed me more than a
/// declared limit permits" — every variant names an OS condition — so the
/// nearest registered condition is used and the **limit that was exceeded is
/// named in [`twinvpn_platform::OsDetail::call`]**, with the observed count as
/// the number. This is reported as a finding rather than papered over; see the
/// crate README.
pub fn render(
    contract: &NetworkContract,
    tunnel_remote_address: &str,
) -> Result<TunnelSettingsProgramme, PlatformError> {
    let mut residuals = Vec::new();
    let mut metric_count = 0usize;

    let mut ipv4 = FamilySettings::default();
    let mut ipv6 = FamilySettings::default();

    for family in [AddressFamily::V4, AddressFamily::V6] {
        let side = if family == AddressFamily::V4 {
            &mut ipv4
        } else {
            &mut ipv6
        };
        for prefix in contract.addresses.get(family) {
            side.addresses.push(address_text(prefix.address()));
            side.masks.push(mask_text(*prefix));
        }
        for route in contract.routes.get(family) {
            if route.metric.is_some() {
                metric_count += 1;
            }
            side.included_routes.push(route_programme(route));
        }
    }

    if metric_count > 0 {
        residuals.push(SettingsResidual::RouteMetricUnrepresentable {
            count: metric_count,
        });
    }

    let dns = render_dns(&contract.dns, &mut residuals)?;

    Ok(TunnelSettingsProgramme {
        tunnel_remote_address: tunnel_remote_address.to_owned(),
        ipv4,
        ipv6,
        dns,
        mtu: contract.mtu,
        residuals,
    })
}

fn limit_exceeded(limit: &'static str, observed: usize) -> PlatformError {
    PlatformError::RouteProgrammingDenied(Some(oserr::detail_from_code(
        i32::try_from(observed).unwrap_or(i32::MAX),
        limit,
    )))
}

/// Renders the resolver half, applying ADR-0011's iOS rules.
fn render_dns(
    dns: &DnsConfig,
    residuals: &mut Vec<SettingsResidual>,
) -> Result<DnsProgramme, PlatformError> {
    // Bound before any allocation proportional to a declared length
    // (`ownership.md` §6 rules 9 and 10), per family and not in aggregate —
    // `limits.json` states the bound per family, and checking the sum would let
    // nine v6 resolvers through on a contract with none for v4.
    for family in [AddressFamily::V4, AddressFamily::V6] {
        let count = dns.resolvers.get(family).len();
        if count > MAX_RESOLVERS_PER_FAMILY {
            return Err(limit_exceeded("limits.dns.max_resolvers_per_family", count));
        }
    }
    if dns.search_domains.len() > MAX_SEARCH_DOMAINS {
        return Err(limit_exceeded(
            "limits.dns.max_search_domains",
            dns.search_domains.len(),
        ));
    }
    if dns.split_domains.len() > MAX_SPLIT_DOMAIN_RULES {
        return Err(limit_exceeded(
            "limits.dns.max_split_domain_rules",
            dns.split_domains.len(),
        ));
    }
    for domain in dns.search_domains.iter().chain(dns.split_domains.iter()) {
        if domain.len() > MAX_DOMAIN_NAME_BYTES {
            return Err(limit_exceeded(
                "limits.dns.max_domain_name_bytes",
                domain.len(),
            ));
        }
    }

    // Both families' resolvers, v4 then v6, in the order the core supplied.
    // Order is the core's decision (ADR-0011 DN-17's family steering), so it is
    // preserved rather than sorted.
    let mut servers = Vec::new();
    for family in [AddressFamily::V4, AddressFamily::V6] {
        for addr in dns.resolvers.get(family) {
            servers.push(address_text(*addr));
        }
    }

    let mut match_domains = Vec::new();
    for domain in &dns.split_domains {
        if is_mdns_reserved(domain) {
            residuals.push(SettingsResidual::MdnsDomainNotClaimable {
                domain: domain.clone(),
            });
            continue;
        }
        match_domains.push(domain.clone());
    }

    Ok(DnsProgramme {
        servers,
        search_domains: dns.search_domains.clone(),
        match_domains,
        is_default_resolver: dns.is_default_resolver,
    })
}

/// Whether `domain` is `.local` or beneath it.
///
/// Compared case-insensitively and on label boundaries: `mylocal` is not
/// `.local`, and `Foo.LOCAL` is.
fn is_mdns_reserved(domain: &str) -> bool {
    let trimmed = domain.trim_end_matches('.').trim_start_matches('.');
    if trimmed.eq_ignore_ascii_case(MDNS_RESERVED_SUFFIX) {
        return true;
    }
    trimmed.len() > MDNS_RESERVED_SUFFIX.len()
        && trimmed
            .as_bytes()
            .get(trimmed.len() - MDNS_RESERVED_SUFFIX.len() - 1)
            == Some(&b'.')
        && trimmed[trimmed.len() - MDNS_RESERVED_SUFFIX.len()..]
            .eq_ignore_ascii_case(MDNS_RESERVED_SUFFIX)
}

fn route_programme(route: &RouteEntry) -> RouteProgramme {
    if route.destination.prefix_len() == 0 {
        return RouteProgramme::Default;
    }
    RouteProgramme::Prefix {
        address: address_text(route.destination.address()),
        mask_or_length: mask_text(route.destination),
    }
}

/// Canonical text for an address, un-zoned.
///
/// A v6 zone index is an interface scope; `NEIPv6Route` and `NEPacketTunnelNetworkSettings`
/// take no zone, because every route in the object is already scoped to the
/// tunnel. Dropping it here is exact rather than lossy.
#[must_use]
pub fn address_text(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
        }
        IpAddr::V6(v6) => v6_text(v6.octets()),
    }
}

/// RFC 5952 text for sixteen octets: lowercase hex, longest run of zero groups
/// compressed once, ties broken leftmost.
fn v6_text(octets: [u8; 16]) -> String {
    let groups: [u16; 8] =
        core::array::from_fn(|i| (u16::from(octets[i * 2]) << 8) | u16::from(octets[i * 2 + 1]));
    let (mut best_start, mut best_len) = (usize::MAX, 0usize);
    let (mut run_start, mut run_len) = (0usize, 0usize);
    for (i, group) in groups.iter().enumerate() {
        if *group == 0 {
            if run_len == 0 {
                run_start = i;
            }
            run_len += 1;
            if run_len > best_len {
                best_len = run_len;
                best_start = run_start;
            }
        } else {
            run_len = 0;
        }
    }
    // RFC 5952 §4.2.2: a single zero group is not compressed.
    if best_len < 2 {
        best_start = usize::MAX;
        best_len = 0;
    }
    let mut out = String::with_capacity(39);
    let mut i = 0;
    while i < 8 {
        if i == best_start {
            out.push_str("::");
            i += best_len;
            continue;
        }
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        write!(out, "{:x}", groups[i]).expect("writing to a String cannot fail");
        i += 1;
    }
    if out.is_empty() {
        out.push_str("::");
    }
    out
}

/// The mask (v4) or prefix length (v6) `NEIPv4Route`/`NEIPv6Route` take.
///
/// iOS is asymmetric here — `NEIPv4Route` takes a dotted-quad `subnetMask` and
/// `NEIPv6Route` takes an `NSNumber` prefix length — so the two are rendered
/// differently on purpose, and the difference is *here*, once, rather than in
/// Swift at every call site.
#[must_use]
pub fn mask_text(prefix: IpPrefix) -> String {
    match prefix.family() {
        AddressFamily::V4 => {
            let bits = prefix.prefix_len();
            let mask: u32 = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            let o = mask.to_be_bytes();
            format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
        }
        AddressFamily::V6 => prefix.prefix_len().to_string(),
    }
}

impl TunnelSettingsProgramme {
    /// The canonical JSON Swift decodes.
    ///
    /// # Why JSON and not the frozen protobuf
    ///
    /// This is not a contract message and must never become one. `contracts/` is
    /// the vocabulary two *independently versioned* parties share; this
    /// programme crosses `ownership.md` §10.4's internal bridge, where "both
    /// sides are compiled from one commit into one artifact" and there is
    /// nothing for it to be compatible with. Encoding it in a frozen schema
    /// would give an internal detail a compatibility obligation the ADR
    /// deliberately withholds.
    ///
    /// Keys are emitted through `serde_json`'s ordered map, so the bytes are a
    /// pure function of the value — which is what lets a test assert on them.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut root = Map::new();
        root.insert(
            "tunnel_remote_address".to_owned(),
            Value::String(self.tunnel_remote_address.clone()),
        );
        root.insert("ipv4".to_owned(), family_json(&self.ipv4, false));
        root.insert("ipv6".to_owned(), family_json(&self.ipv6, true));
        root.insert("dns".to_owned(), dns_json(&self.dns));
        root.insert("mtu".to_owned(), json!(self.mtu));
        Value::Object(root).to_string()
    }
}

fn family_json(settings: &FamilySettings, v6: bool) -> Value {
    let mask_key = if v6 { "prefix_lengths" } else { "subnet_masks" };
    let mut out = Map::new();
    out.insert("addresses".to_owned(), json!(settings.addresses));
    out.insert(mask_key.to_owned(), json!(settings.masks));
    out.insert(
        "included_routes".to_owned(),
        routes_json(&settings.included_routes, v6),
    );
    out.insert(
        "excluded_routes".to_owned(),
        routes_json(&settings.excluded_routes, v6),
    );
    Value::Object(out)
}

fn routes_json(routes: &[RouteProgramme], v6: bool) -> Value {
    let mask_key = if v6 { "prefix_length" } else { "subnet_mask" };
    Value::Array(
        routes
            .iter()
            .map(|route| match route {
                RouteProgramme::Default => json!({ "default": true }),
                RouteProgramme::Prefix {
                    address,
                    mask_or_length,
                } => {
                    let mut entry = Map::new();
                    entry.insert("default".to_owned(), Value::Bool(false));
                    entry.insert("address".to_owned(), Value::String(address.clone()));
                    entry.insert(mask_key.to_owned(), Value::String(mask_or_length.clone()));
                    Value::Object(entry)
                }
            })
            .collect(),
    )
}

fn dns_json(dns: &DnsProgramme) -> Value {
    let mut out = Map::new();
    out.insert("servers".to_owned(), json!(dns.servers));
    out.insert("search_domains".to_owned(), json!(dns.search_domains));
    // `matchDomains = [""]` is how iOS spells "this resolver is the default for
    // everything". It is a different value from an empty array, which claims
    // nothing at all, and conflating them is how a full-tunnel DNS posture
    // silently becomes a split one.
    let match_domains = if dns.is_default_resolver {
        vec![String::new()]
    } else {
        dns.match_domains.clone()
    };
    out.insert("match_domains".to_owned(), json!(match_domains));
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_platform::{ContractGeneration, InterfaceIndex, Ruleset};
    use twinvpn_types::{PerFamily, V4Addr, V6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8, len: u32) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(V4Addr::from_octets([a, b, c, d])), len).expect("prefix")
    }

    fn v6(octets: [u8; 16], len: u32) -> IpPrefix {
        IpPrefix::new(IpAddr::V6(V6Addr::prefix_base(octets).expect("v6")), len).expect("prefix")
    }

    fn route(destination: IpPrefix) -> RouteEntry {
        RouteEntry {
            destination,
            via: None,
            interface: InterfaceIndex(0),
            metric: None,
        }
    }

    fn contract(routes: PerFamily<Vec<RouteEntry>>, dns: DnsConfig) -> NetworkContract {
        NetworkContract {
            generation: ContractGeneration(1),
            addresses: PerFamily::new(
                vec![v4(100, 64, 0, 7, 32)],
                vec![v6(
                    [
                        0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                    128,
                )],
            ),
            routes,
            dns,
            ruleset: Ruleset::Protected,
            mtu: 1280,
        }
    }

    fn empty_dns() -> DnsConfig {
        DnsConfig {
            resolvers: PerFamily::new(Vec::new(), Vec::new()),
            search_domains: Vec::new(),
            split_domains: Vec::new(),
            is_default_resolver: false,
        }
    }

    #[test]
    fn both_families_are_present_in_one_object_and_neither_is_optional() {
        // ADR-0010 R1 and §11.3: "IPv4 and IPv6 routes MUST be installed in the
        // same apply() transaction. An implementation that can install one
        // family's routes without the other's is non-conforming." The type has
        // no shape that carries one and not the other; this asserts the render
        // fills both.
        let programme = render(
            &contract(
                PerFamily::new(vec![route(v4(0, 0, 0, 0, 0))], vec![route(v6([0; 16], 0))]),
                empty_dns(),
            ),
            "100.64.0.1",
        )
        .expect("renders");
        assert_eq!(
            programme.ipv4.included_routes,
            vec![RouteProgramme::Default]
        );
        assert_eq!(
            programme.ipv6.included_routes,
            vec![RouteProgramme::Default]
        );
        assert_eq!(programme.ipv4.addresses, vec!["100.64.0.7".to_owned()]);
        assert_eq!(
            programme.ipv6.addresses,
            vec!["fd7c:9e5d:2a10::".to_owned()]
        );
        let json = programme.to_json();
        assert!(json.contains("\"ipv4\""), "{json}");
        assert!(json.contains("\"ipv6\""), "{json}");
    }

    #[test]
    fn a_default_route_renders_as_the_platform_marker_not_as_two_halves() {
        // ADR-0010 §11.3: on iOS the form is `NEIPv4Route.default()`, NOT the
        // `0.0.0.0/1` + `128.0.0.0/1` split Linux installs to avoid destroying
        // the host default. Rendering the split here would install two routes
        // where the platform expects one marker.
        let programme = render(
            &contract(
                PerFamily::new(vec![route(v4(0, 0, 0, 0, 0))], Vec::new()),
                empty_dns(),
            ),
            "100.64.0.1",
        )
        .expect("renders");
        assert_eq!(programme.ipv4.included_routes.len(), 1);
        assert_eq!(programme.ipv4.included_routes[0], RouteProgramme::Default);
        let json = programme.to_json();
        assert!(!json.contains("128.0.0.0"), "the /1 split must not appear");
    }

    #[test]
    fn a_v4_prefix_becomes_a_dotted_mask_and_a_v6_prefix_becomes_a_length() {
        // NEIPv4Route takes a dotted-quad subnetMask; NEIPv6Route takes a
        // numeric prefix length. The asymmetry lives here, once.
        assert_eq!(mask_text(v4(10, 0, 0, 0, 8)), "255.0.0.0");
        assert_eq!(mask_text(v4(192, 168, 1, 0, 24)), "255.255.255.0");
        assert_eq!(mask_text(v4(100, 64, 0, 7, 32)), "255.255.255.255");
        assert_eq!(mask_text(v4(0, 0, 0, 0, 0)), "0.0.0.0");
        assert_eq!(mask_text(v6([0; 16], 0)), "0");
        assert_eq!(
            mask_text(v6(
                [0xfd, 0x7c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                16
            )),
            "16"
        );
    }

    #[test]
    fn v6_text_is_rfc_5952_so_two_renders_of_one_address_are_one_string() {
        assert_eq!(v6_text([0; 16]), "::");
        let mut loopback = [0u8; 16];
        loopback[15] = 1;
        assert_eq!(v6_text(loopback), "::1");
        assert_eq!(
            v6_text([0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0x53]),
            "fd7c:9e5d:2a10:ffff::53"
        );
        // A single zero group is NOT compressed (RFC 5952 §4.2.2).
        assert_eq!(
            v6_text([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5]),
            "2001:db8:0:1:2:3:4:5"
        );
    }

    #[test]
    fn the_overlay_anycast_resolvers_render_for_both_families() {
        // ADR-0011 §11.2: the overlay anycast addresses are "the only option on
        // iOS/Android" — a VPN there cannot point the system resolver at
        // loopback. Both families are carried, in the core's order.
        let dns = DnsConfig {
            resolvers: PerFamily::new(
                vec![IpAddr::V4(V4Addr::from_octets([100, 127, 255, 53]))],
                vec![IpAddr::V6(
                    V6Addr::prefix_base([
                        0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0x53,
                    ])
                    .expect("v6"),
                )],
            ),
            search_domains: vec!["twin.example".to_owned()],
            split_domains: Vec::new(),
            is_default_resolver: false,
        };
        let programme = render(
            &contract(PerFamily::new(Vec::new(), Vec::new()), dns),
            "100.64.0.1",
        )
        .expect("renders");
        assert_eq!(
            programme.dns.servers,
            vec![
                "100.127.255.53".to_owned(),
                "fd7c:9e5d:2a10:ffff::53".to_owned()
            ]
        );
    }

    #[test]
    fn a_default_resolver_claims_everything_and_an_empty_list_claims_nothing() {
        let mut dns = empty_dns();
        dns.is_default_resolver = true;
        let full = render(
            &contract(PerFamily::new(Vec::new(), Vec::new()), dns),
            "100.64.0.1",
        )
        .expect("renders");
        assert!(full.to_json().contains("\"match_domains\":[\"\"]"));

        let split = render(
            &contract(PerFamily::new(Vec::new(), Vec::new()), empty_dns()),
            "100.64.0.1",
        )
        .expect("renders");
        assert!(split.to_json().contains("\"match_domains\":[]"));
    }

    #[test]
    fn dot_local_is_never_claimed_because_the_os_will_not_honour_the_claim() {
        // ADR-0011 N2 and §11.7: mDNSResponder sends `.local` to multicast
        // regardless. Claiming it would make our resolver posture a statement
        // the OS contradicts.
        let mut dns = empty_dns();
        dns.split_domains = vec![
            "corp.example".to_owned(),
            "local".to_owned(),
            "printer.LOCAL".to_owned(),
            "mylocal".to_owned(),
        ];
        let programme = render(
            &contract(PerFamily::new(Vec::new(), Vec::new()), dns),
            "100.64.0.1",
        )
        .expect("renders");
        assert_eq!(
            programme.dns.match_domains,
            vec!["corp.example".to_owned(), "mylocal".to_owned()],
            "only the two genuinely claimable domains survive"
        );
        assert_eq!(
            programme
                .residuals
                .iter()
                .filter(|r| matches!(r, SettingsResidual::MdnsDomainNotClaimable { .. }))
                .count(),
            2,
            "and the drop is stated, not silent"
        );
    }

    #[test]
    fn every_limits_json_bound_is_a_typed_refusal_and_never_a_truncation() {
        // `ownership.md` §6 rule 9: "A violation is a typed reject ... never a
        // truncation, never a pad, never a silent accept."
        let mut dns = empty_dns();
        dns.resolvers = PerFamily::new(
            (0..=MAX_RESOLVERS_PER_FAMILY)
                .map(|i| IpAddr::V4(V4Addr::from_octets([10, 0, 0, u8::try_from(i).unwrap()])))
                .collect(),
            Vec::new(),
        );
        let err = render(
            &contract(PerFamily::new(Vec::new(), Vec::new()), dns),
            "100.64.0.1",
        )
        .expect_err("refuses");
        assert_eq!(err.reason_code().as_str(), "ROUTE.PROGRAMMING_DENIED");
        assert_eq!(
            err.os_detail().map(|d| d.call),
            Some("limits.dns.max_resolvers_per_family"),
            "the limit that was exceeded is named, and the count is the evidence"
        );
        assert_eq!(
            err.os_detail().map(|d| d.code),
            Some(i64::try_from(MAX_RESOLVERS_PER_FAMILY).unwrap() + 1)
        );

        for (mutate, limit) in [
            (
                Box::new(|d: &mut DnsConfig| {
                    d.search_domains = vec!["a.example".to_owned(); MAX_SEARCH_DOMAINS + 1];
                }) as Box<dyn Fn(&mut DnsConfig)>,
                "limits.dns.max_search_domains",
            ),
            (
                Box::new(|d: &mut DnsConfig| {
                    d.split_domains = vec!["a.example".to_owned(); MAX_SPLIT_DOMAIN_RULES + 1];
                }),
                "limits.dns.max_split_domain_rules",
            ),
            (
                Box::new(|d: &mut DnsConfig| {
                    d.search_domains = vec!["a".repeat(MAX_DOMAIN_NAME_BYTES + 1)];
                }),
                "limits.dns.max_domain_name_bytes",
            ),
        ] {
            let mut dns = empty_dns();
            mutate(&mut dns);
            let err = render(
                &contract(PerFamily::new(Vec::new(), Vec::new()), dns),
                "100.64.0.1",
            )
            .expect_err("refuses");
            assert_eq!(err.os_detail().map(|d| d.call), Some(limit));
        }
    }

    #[test]
    fn the_resolver_bound_is_per_family_and_not_an_aggregate() {
        // Eight per family is sixteen in total and is legal; nine in one family
        // is not. Checking the sum would let the second case through.
        let mut dns = empty_dns();
        dns.resolvers = PerFamily::new(
            (0..MAX_RESOLVERS_PER_FAMILY)
                .map(|i| IpAddr::V4(V4Addr::from_octets([10, 0, 0, u8::try_from(i).unwrap()])))
                .collect(),
            (0..MAX_RESOLVERS_PER_FAMILY)
                .map(|i| {
                    let mut o = [0u8; 16];
                    o[0] = 0xfd;
                    o[15] = u8::try_from(i).unwrap();
                    IpAddr::V6(V6Addr::prefix_base(o).expect("v6"))
                })
                .collect(),
        );
        assert!(render(
            &contract(PerFamily::new(Vec::new(), Vec::new()), dns),
            "100.64.0.1"
        )
        .is_ok());
    }

    #[test]
    fn a_route_metric_is_unrepresentable_and_says_so_rather_than_vanishing() {
        let mut entry = route(v4(10, 0, 0, 0, 8));
        entry.metric = Some(100);
        let programme = render(
            &contract(PerFamily::new(vec![entry], Vec::new()), empty_dns()),
            "100.64.0.1",
        )
        .expect("renders");
        assert_eq!(
            programme.residuals,
            vec![SettingsResidual::RouteMetricUnrepresentable { count: 1 }]
        );
    }

    #[test]
    fn the_rendered_bytes_are_a_pure_function_of_the_value() {
        let build = || {
            render(
                &contract(
                    PerFamily::new(vec![route(v4(10, 0, 0, 0, 8))], vec![route(v6([0; 16], 0))]),
                    empty_dns(),
                ),
                "100.64.0.1",
            )
            .expect("renders")
            .to_json()
        };
        assert_eq!(build(), build());
    }
}
