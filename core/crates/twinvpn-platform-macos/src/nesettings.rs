//! The `NEPacketTunnelNetworkSettings` document — **computed here, applied
//! verbatim in Swift**.
//!
//! **Authority:** ADR-0018 CB-2 ("the shell holds no decision"); ADR-0010 §11.3's
//! macOS row (`IPv4Settings.includedRoutes` / `IPv6Settings.includedRoutes`,
//! `NEIPv4Route.default()` + `NEIPv6Route.default()`) and §11.5 clause 1 ("one
//! `NEPacketTunnelNetworkSettings` carrying **both** `IPv4Settings` and
//! `IPv6Settings`"); ADR-0011 §11.6 and §11.9's macOS rows
//! (`dnsSettings` with `matchDomains`, **`.local` excluded**, "so mDNS keeps
//! working"); ADR-0012 §11.6's macOS enforcement row.
//!
//! # Why this is a Rust module and not Swift code
//!
//! CB-2's falsification test is the design target: with every shell deleted and a
//! mock adapter bound, the core must still make every decision correctly. A
//! `setTunnelNetworkSettings` call assembled in Swift would put at least four
//! decisions in the shell — which family to configure, whether the tunnel is the
//! default resolver, which domains to match, and what a netmask is for a prefix
//! length. All four live here, in a pure function, and the Swift side does one
//! thing: decode this document and copy each field into the NE object.
//!
//! So the whole of the macOS tunnel-settings surface is **executed** by
//! `cargo test` on this Linux host, and the unverified Swift is reduced to a
//! `Codable` struct and a sequence of assignments.
//!
//! # ADR-0010 R1 is structural here
//!
//! `ipv4` and `ipv6` are **both always present** in the document, even when a
//! family has no routes: [`render`] has no branch that can omit one, because
//! [`twinvpn_platform::NetworkContract`] carries a `PerFamily` and this function
//! walks both halves of it. "A v4 story and a v6 story" is not expressible.
//!
//! # Two reported gaps
//!
//! 1. **`tunnelRemoteAddress` has no seam field.** NE requires one on the
//!    settings object. [`NetworkContract`] carries addresses, routes, DNS, the
//!    posture and the MTU, and nothing that names the remote the tunnel is
//!    currently riding. It is therefore a parameter of [`render`], supplied by the
//!    shell from the value the **core** handed it at `startTunnel` — never
//!    invented by the shell and never discovered by this adapter.
//! 2. **An interface address's host bits are already lost.**
//!    `NetworkContract::addresses` is a `Vec<IpPrefix>` and `IpPrefix` requires
//!    every host bit to be zero, so `100.64.0.2/24` cannot be represented and
//!    arrives as `100.64.0.0/24`. `NEIPv4Settings(addresses:subnetMasks:)` wants
//!    the *host* address. This is the same defect
//!    [`twinvpn_platform::InterfaceFacts::addresses`] records against itself, with
//!    the same replacement ready (`twinvpn_types::InterfaceAddress`); until the
//!    seam takes it, a contract whose overlay address is not a `/32` or `/128`
//!    produces a settings object naming the network address. Recorded here rather
//!    than papered over with a guess at the host part.

use serde_json::{json, Map, Value};

use twinvpn_platform::{DnsConfig, NetworkContract, PlatformError};
use twinvpn_types::{AddressFamily, IpPrefix};

use crate::addr::{addr_text, v4_netmask_text};

/// The domain suffix ADR-0011 §11.9 requires `matchDomains` to exclude on macOS.
///
/// > "`matchDomains` covering the split set (or `[""]` in `FULL` mode), `.local`
/// > **excluded** so mDNS keeps working"
///
/// `mDNSResponder` always sends `.local` to multicast; claiming it would break
/// Bonjour on the host and would not gain the tunnel anything, because nothing in
/// the overlay answers a multicast name.
pub const MDNS_SUFFIX: &str = "local";

/// NE's "this resolver is the default for everything" spelling: a `matchDomains`
/// array containing the empty string.
pub const MATCH_ALL: &str = "";

/// Renders the settings document for one generation.
///
/// # Errors
///
/// [`PlatformError::AdapterUnavailable`] if a prefix length is out of range for
/// its family — which [`IpPrefix`] already refuses, so reaching it means an
/// adapter defect rather than a bad contract.
pub fn render(
    contract: &NetworkContract,
    tunnel_remote_address: &str,
) -> Result<Value, PlatformError> {
    let mut doc = Map::new();
    doc.insert(
        "tunnel_remote_address".to_owned(),
        Value::String(tunnel_remote_address.to_owned()),
    );
    doc.insert("mtu".to_owned(), json!(contract.mtu));
    doc.insert("ipv4".to_owned(), render_v4(contract)?);
    doc.insert("ipv6".to_owned(), render_v6(contract));
    doc.insert("dns".to_owned(), render_dns(&contract.dns));
    Ok(Value::Object(doc))
}

/// The same, serialised. What crosses the bridge.
///
/// # Errors
///
/// As [`render`].
pub fn render_json(
    contract: &NetworkContract,
    tunnel_remote_address: &str,
) -> Result<String, PlatformError> {
    Ok(render(contract, tunnel_remote_address)?.to_string())
}

fn render_v4(contract: &NetworkContract) -> Result<Value, PlatformError> {
    let mut addresses = Vec::new();
    let mut masks = Vec::new();
    for prefix in &contract.addresses.v4 {
        addresses.push(Value::String(addr_text(prefix.address())));
        masks.push(Value::String(v4_netmask_text(prefix.prefix_len())?));
    }
    let mut included = Vec::new();
    for route in &contract.routes.v4 {
        included.push(json!({
            "address": addr_text(route.destination.address()),
            "subnet_mask": v4_netmask_text(route.destination.prefix_len())?,
        }));
    }
    Ok(json!({
        "addresses": addresses,
        "subnet_masks": masks,
        "included_routes": included,
        // Deliberately empty and deliberately PRESENT. `excludedRoutes` is a
        // policy decision — which destinations bypass the tunnel — and nothing in
        // the seam carries one, so this adapter emits none rather than inventing
        // one. A shell that added an exclusion would be deciding scope, which is
        // ADR-0012 Tier 1 and CB-2 forbids it.
        "excluded_routes": Value::Array(Vec::new()),
    }))
}

fn render_v6(contract: &NetworkContract) -> Value {
    let mut addresses = Vec::new();
    let mut lengths = Vec::new();
    for prefix in &contract.addresses.v6 {
        addresses.push(Value::String(addr_text(prefix.address())));
        lengths.push(json!(prefix.prefix_len()));
    }
    let included: Vec<Value> = contract
        .routes
        .v6
        .iter()
        .map(|route| {
            json!({
                "address": addr_text(route.destination.address()),
                "network_prefix_length": route.destination.prefix_len(),
            })
        })
        .collect();
    json!({
        "addresses": addresses,
        "network_prefix_lengths": lengths,
        "included_routes": included,
        "excluded_routes": Value::Array(Vec::new()),
    })
}

/// The `dnsSettings` half, or `null` when the contract configures no resolver.
///
/// `null` rather than an empty object: NE treats "no `dnsSettings`" and "a
/// `dnsSettings` with no servers" differently — the first leaves the host's
/// resolvers alone, the second installs a resolver that answers nothing — and
/// collapsing them is how a tunnel comes up with name resolution silently dead.
fn render_dns(config: &DnsConfig) -> Value {
    let servers: Vec<Value> = config
        .resolvers
        .v4
        .iter()
        .chain(config.resolvers.v6.iter())
        .map(|a| Value::String(addr_text(*a)))
        .collect();
    if servers.is_empty() {
        return Value::Null;
    }
    json!({
        "servers": servers,
        "search_domains": config.search_domains.clone(),
        "match_domains": match_domains(config),
        // The core supplies `search_domains` explicitly, so `matchDomains` must
        // not silently become search domains as well: NE appends them otherwise,
        // and a search list the core did not compute is a name the core did not
        // decide to resolve. Recorded as this adapter's choice, since ADR-0011
        // does not pin the flag.
        "match_domains_no_search": true,
    })
}

/// `matchDomains`, per ADR-0011 §11.6's macOS row.
///
/// `[""]` in FULL mode — NE's spelling of "this resolver is the default for
/// everything" — otherwise the split set, with `.local` removed.
fn match_domains(config: &DnsConfig) -> Vec<String> {
    if config.is_default_resolver {
        return vec![MATCH_ALL.to_owned()];
    }
    config
        .split_domains
        .iter()
        .filter(|d| !is_mdns_domain(d))
        .cloned()
        .collect()
}

/// Whether a domain is `local` or a subdomain of it, case-insensitively.
///
/// A separate function because the comparison is subtler than it looks: `.local`
/// must be dropped, `alocal` must not, and DNS labels are case-insensitive so
/// `LOCAL` is the same name.
#[must_use]
pub fn is_mdns_domain(domain: &str) -> bool {
    let trimmed = domain.trim_end_matches('.').trim_start_matches('.');
    trimmed.eq_ignore_ascii_case(MDNS_SUFFIX)
        || trimmed
            .to_ascii_lowercase()
            .ends_with(&format!(".{MDNS_SUFFIX}"))
}

/// Whether every route in `contract` is covered by the rendered document, per
/// family.
///
/// Present so a test can assert the translation is total rather than sampling it:
/// a settings object that dropped one of eight routes would still look right.
#[must_use]
pub fn route_counts(doc: &Value) -> (usize, usize) {
    let count = |family: &str| {
        doc.get(family)
            .and_then(|f| f.get("included_routes"))
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    };
    (count("ipv4"), count("ipv6"))
}

/// The families a contract's routes actually name — for a test that a document
/// carrying both halves is not accidentally carrying one twice.
#[must_use]
pub fn families_in(contract: &NetworkContract) -> Vec<AddressFamily> {
    let mut out = Vec::new();
    if !contract.routes.v4.is_empty() {
        out.push(AddressFamily::V4);
    }
    if !contract.routes.v6.is_empty() {
        out.push(AddressFamily::V6);
    }
    out
}

/// The prefix an address entry in the document came from, for round-trip tests.
#[must_use]
pub fn prefix_families(prefixes: &[IpPrefix]) -> Vec<AddressFamily> {
    prefixes.iter().map(|p| p.family()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{contract, full_tunnel_contract, v4 as p4};
    use twinvpn_platform::Ruleset;
    use twinvpn_types::{IpAddr, PerFamily, V4Addr, V6Addr};

    fn resolver_v4(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(V4Addr::from_octets(octets))
    }

    fn resolver_v6() -> IpAddr {
        let mut o = [0u8; 16];
        o[0] = 0xfd;
        o[1] = 0x7c;
        o[15] = 1;
        IpAddr::V6(V6Addr::new(o, None).expect("valid"))
    }

    #[test]
    fn both_families_are_always_present_even_when_one_has_no_routes() {
        // ADR-0010 §11.5 clause 1: ONE settings object carrying BOTH. There is no
        // branch in `render` that can omit a family, which is R1 as a code shape.
        let mut c = contract(1);
        c.routes.v6.clear();
        c.addresses.v6.clear();
        let doc = render(&c, "203.0.113.7").expect("renders");
        assert!(doc.get("ipv4").is_some());
        assert!(
            doc.get("ipv6").is_some_and(serde_json::Value::is_object),
            "the v6 half must be present and empty, never absent"
        );
        assert_eq!(route_counts(&doc), (1, 0));
    }

    #[test]
    fn every_route_reaches_the_document_and_none_is_dropped() {
        let c = full_tunnel_contract(2, Ruleset::Protected);
        let doc = render(&c, "203.0.113.7").expect("renders");
        assert_eq!(route_counts(&doc), (2, 2));
        assert_eq!(families_in(&c).len(), 2);
    }

    #[test]
    fn the_netmask_is_computed_here_so_swift_never_computes_one() {
        let mut c = contract(1);
        c.addresses.v4 = vec![p4([100, 64, 0, 0], 10)];
        let doc = render(&c, "203.0.113.7").expect("renders");
        assert_eq!(doc["ipv4"]["subnet_masks"][0], "255.192.0.0");
        assert_eq!(doc["ipv4"]["included_routes"][0]["subnet_mask"], "255.192.0.0");
        // The v6 half carries a LENGTH, because that is what NEIPv6Route takes.
        assert_eq!(doc["ipv6"]["included_routes"][0]["network_prefix_length"], 48);
    }

    #[test]
    fn a_contract_with_no_resolvers_emits_null_and_not_an_empty_resolver() {
        // "No dnsSettings" leaves the host's resolvers alone; "a dnsSettings with
        // no servers" installs a resolver that answers nothing. Collapsing them is
        // how a tunnel comes up with name resolution silently dead.
        let doc = render(&contract(1), "203.0.113.7").expect("renders");
        assert_eq!(doc["dns"], Value::Null);
    }

    #[test]
    fn full_mode_matches_everything_with_nes_own_spelling() {
        let mut c = contract(1);
        c.dns = DnsConfig {
            resolvers: PerFamily::new(vec![resolver_v4([100, 64, 0, 1])], vec![resolver_v6()]),
            search_domains: vec!["twin.internal".to_owned()],
            split_domains: vec!["twin.internal".to_owned()],
            is_default_resolver: true,
        };
        let doc = render(&c, "203.0.113.7").expect("renders");
        assert_eq!(doc["dns"]["match_domains"], json!([""]));
        assert_eq!(doc["dns"]["servers"], json!(["100.64.0.1", "fd7c::1"]));
        assert_eq!(doc["dns"]["search_domains"], json!(["twin.internal"]));
        assert_eq!(doc["dns"]["match_domains_no_search"], json!(true));
    }

    #[test]
    fn split_mode_matches_the_split_set_and_never_claims_dot_local() {
        // ADR-0011 §11.9's macOS row, verbatim: ".local excluded so mDNS keeps
        // working". `mDNSResponder` always sends `.local` to multicast, and
        // claiming it would break Bonjour without gaining the tunnel anything.
        let mut c = contract(1);
        c.dns = DnsConfig {
            resolvers: PerFamily::new(vec![resolver_v4([100, 64, 0, 1])], Vec::new()),
            search_domains: Vec::new(),
            split_domains: vec![
                "twin.internal".to_owned(),
                "local".to_owned(),
                "printer.LOCAL".to_owned(),
                "notlocal".to_owned(),
            ],
            is_default_resolver: false,
        };
        let doc = render(&c, "203.0.113.7").expect("renders");
        assert_eq!(
            doc["dns"]["match_domains"],
            json!(["twin.internal", "notlocal"])
        );
    }

    #[test]
    fn the_mdns_test_is_a_suffix_test_and_not_a_substring_test() {
        assert!(is_mdns_domain("local"));
        assert!(is_mdns_domain(".local"));
        assert!(is_mdns_domain("local."));
        assert!(is_mdns_domain("LOCAL"));
        assert!(is_mdns_domain("printer.local"));
        assert!(is_mdns_domain("a.b.Local."));
        assert!(!is_mdns_domain("notlocal"));
        assert!(!is_mdns_domain("locale"));
        assert!(!is_mdns_domain("local.example.com"));
    }

    #[test]
    fn no_excluded_route_is_ever_invented() {
        // `excludedRoutes` is a scope decision (ADR-0012 Tier 1) and nothing in
        // the seam carries one. Emitting an empty array — present, not absent —
        // is how Swift is told "there are none" rather than "decide for
        // yourself".
        let doc = render(&full_tunnel_contract(3, Ruleset::Blocked), "203.0.113.7")
            .expect("renders");
        assert_eq!(doc["ipv4"]["excluded_routes"], json!([]));
        assert_eq!(doc["ipv6"]["excluded_routes"], json!([]));
    }

    #[test]
    fn the_document_is_deterministic_so_a_reconciler_sees_no_phantom_drift() {
        let c = full_tunnel_contract(4, Ruleset::Protected);
        let a = render_json(&c, "203.0.113.7").expect("renders");
        let b = render_json(&c, "203.0.113.7").expect("renders");
        assert_eq!(a, b);
        assert_eq!(
            prefix_families(&c.addresses.v4),
            vec![AddressFamily::V4]
        );
    }

    #[test]
    fn the_posture_never_reaches_the_settings_document() {
        // The kill switch is pf's (ADR-0012 §11.6), not the settings object's. A
        // posture field here would be a second, weaker enforcement point that a
        // reader could mistake for the real one.
        let blocked = render(&full_tunnel_contract(5, Ruleset::Blocked), "203.0.113.7")
            .expect("renders");
        let protected = render(
            &full_tunnel_contract(5, Ruleset::Protected),
            "203.0.113.7",
        )
        .expect("renders");
        assert_eq!(blocked, protected);
    }
}
