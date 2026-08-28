//! The resolver programme: a [`DnsConfig`] as `SCDynamicStore` keys, plus the
//! restore point that undoes it.
//!
//! **Authority:** ADR-0011 §11.6's macOS row and §11.9's macOS bypass row (the
//! steering mechanism, and `.local` **excluded**), DN-18 (restore point first),
//! DN-19 and ADR-0016 PS-21 step 3 (restore the resolver **before** the interface
//! goes), DN-20 (a failed restore leaves the device fail-closed rather than
//! regaining an upstream resolver in an unarmed window), PS-6 ("restore before
//! mutate"); `contracts/registry/limits.json` `dns.*`.
//!
//! # Two carriers, and only one of them is this module's
//!
//! | Carrier | Mechanism | Where |
//! |---|---|---|
//! | [`ResolverCarrier::TunnelSettings`] | `NEPacketTunnelNetworkSettings.dnsSettings` | the NE system extension — [`crate::nesettings`] |
//! | [`ResolverCarrier::DynamicStore`] | `State:/Network/Service/…/DNS` | the `LaunchDaemon` |
//!
//! ADR-0011 §11.6's macOS row says the settings object needs "None" in the way of
//! extra mechanism, which is why the extension path has no work here at all. The
//! daemon path has no settings object, so it programmes `configd` directly, and
//! this module is that programme — as **data**, so it is checkable without a Mac.
//!
//! # Containment is the guarantee, not the mechanism
//!
//! ADR-0011 §11.9's macOS row names `mDNSResponder`'s per-interface resolver
//! behaviour as the bypass channel, steers it with `matchDomains`, and contains it
//! with "a `pf` anchor `twinvpn`, both families, denying 53/853/known-DoH
//! off-overlay". The containment is [`crate::pf`]'s class-6 rule and it is
//! installed **whichever carrier is in force** — so a build that could not
//! programme `configd` at all would still not leak a query. That separation is
//! why this module may fail without the kill switch failing.

use std::collections::BTreeMap;

use twinvpn_platform::{DnsConfig, PlatformError};
use twinvpn_types::IpAddr;

use crate::addr::addr_text;
use crate::nesettings::is_mdns_domain;
use crate::oserr;

/// `contracts/registry/limits.json` `dns.max_search_domains`.
pub const MAX_SEARCH_DOMAINS: usize = 32;

/// `contracts/registry/limits.json` `dns.max_split_domain_rules`.
pub const MAX_SPLIT_DOMAINS: usize = 256;

/// `contracts/registry/limits.json` `dns.max_domain_name_bytes`.
pub const MAX_DOMAIN_BYTES: usize = 253;

/// `contracts/registry/limits.json` `dns.max_resolvers_per_family`.
pub const MAX_RESOLVERS_PER_FAMILY: usize = 8;

/// The `SCDynamicStore` key prefix for a service's live DNS configuration.
pub const STATE_PREFIX: &str = "State:/Network/Service/";

/// The suffix. `State:/Network/Service/<id>/DNS`.
pub const DNS_SUFFIX: &str = "/DNS";

/// Where the daemon writes its restore point.
///
/// Readable with the authority absent, which is what DN-20 and PS-6 need: the
/// offline unblock command and a boot-time restore both have to be able to put
/// the host's resolver back without us.
pub const RESTORE_POINT_PATH: &str = "/Library/Application Support/TwinVPN/resolver.restore";

/// Which mechanism carries the resolver configuration on this binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverCarrier {
    /// `NEPacketTunnelNetworkSettings.dnsSettings`. The OS installs it; this
    /// module has nothing to do.
    TunnelSettings,
    /// `SCDynamicStore`. The daemon writes the keys itself.
    DynamicStore,
}

/// A value in an `SCDynamicStore` dictionary.
///
/// Three shapes, because that is all the DNS dictionary uses. Not a general
/// property-list type: a general encoder here would be a second serialisation
/// format in the tree with no second reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScValue {
    /// A `CFString`.
    Text(String),
    /// A `CFArray` of `CFString`.
    Strings(Vec<String>),
    /// A `CFArray` of `CFNumber`.
    Numbers(Vec<i32>),
}

/// One `SCDynamicStore` key and the dictionary to set at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScEntry {
    /// The full key.
    pub key: String,
    /// The dictionary, sorted so two renders of one config produce identical
    /// output and a reconciler sees no drift that is not there.
    pub dictionary: BTreeMap<String, ScValue>,
}

/// What one generation asks `configd` for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolverPlan {
    /// Keys to set.
    pub sets: Vec<ScEntry>,
    /// Keys to remove.
    pub removes: Vec<String>,
}

impl ResolverPlan {
    /// Whether the plan does nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sets.is_empty() && self.removes.is_empty()
    }
}

/// The `State:` key for one network service's DNS dictionary.
#[must_use]
pub fn dns_key(service_id: &str) -> String {
    format!("{STATE_PREFIX}{service_id}{DNS_SUFFIX}")
}

/// Validates a domain against `limits.json` **before** it is put anywhere.
///
/// `ownership.md` §6 rule 9: a violation is a typed reject, "never a truncation,
/// never a pad, never a silent accept". A domain is not an untrusted network input
/// here — it comes from a verified contract — but the rule is not scoped to
/// network inputs and a 4 KiB search domain would be an unbounded write into
/// `configd` either way.
#[must_use]
pub fn is_safe_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= MAX_DOMAIN_BYTES
        && !domain.starts_with('.')
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
}

/// The programme for one [`DnsConfig`].
///
/// # Errors
///
/// [`PlatformError::AdapterUnavailable`] when a count exceeds `limits.json` or a
/// domain fails [`is_safe_domain`]. **Refused, not trimmed**: a silently trimmed
/// split-domain list is a set of names that resolve off-tunnel without anybody
/// having decided they should.
pub fn plan(config: &DnsConfig, service_id: &str) -> Result<ResolverPlan, PlatformError> {
    validate(config)?;
    let servers: Vec<String> = config
        .resolvers
        .v4
        .iter()
        .chain(config.resolvers.v6.iter())
        .map(|a| addr_text(*a))
        .collect();

    if servers.is_empty() {
        // No resolver to install. Removing the key rather than writing an empty
        // dictionary: an empty `ServerAddresses` is a resolver that answers
        // nothing, and the host's own resolvers are what should apply.
        return Ok(ResolverPlan {
            sets: Vec::new(),
            removes: vec![dns_key(service_id)],
        });
    }

    let mut dictionary = BTreeMap::new();
    dictionary.insert("ServerAddresses".to_owned(), ScValue::Strings(servers));
    if !config.search_domains.is_empty() {
        dictionary.insert(
            "SearchDomains".to_owned(),
            ScValue::Strings(config.search_domains.clone()),
        );
    }

    if config.is_default_resolver {
        // FULL mode. `configd` reads a service's DNS dictionary as the default
        // resolver when it carries no supplemental match domains; the ordering
        // among services is the network service order, which is why the daemon
        // path also raises the overlay service's rank. That rank is not a value
        // in this dictionary and is recorded as a gap rather than faked here.
        dictionary.insert(
            "SupplementalMatchDomains".to_owned(),
            ScValue::Strings(Vec::new()),
        );
    } else {
        // SPLIT mode. `.local` is excluded, per ADR-0011 §11.9's macOS row, "so
        // mDNS keeps working" — the same filter `nesettings` applies to
        // `matchDomains`, applied by the same function so the two carriers cannot
        // disagree about which names the tunnel claims.
        let matched: Vec<String> = config
            .split_domains
            .iter()
            .filter(|d| !is_mdns_domain(d))
            .cloned()
            .collect();
        let orders = vec![100i32; matched.len()];
        dictionary.insert(
            "SupplementalMatchDomains".to_owned(),
            ScValue::Strings(matched),
        );
        dictionary.insert(
            "SupplementalMatchOrders".to_owned(),
            ScValue::Numbers(orders),
        );
    }

    Ok(ResolverPlan {
        sets: vec![ScEntry {
            key: dns_key(service_id),
            dictionary,
        }],
        removes: Vec::new(),
    })
}

fn validate(config: &DnsConfig) -> Result<(), PlatformError> {
    let reject = || oserr::unavailable("dns.limits", libc::EINVAL);
    if config.resolvers.v4.len() > MAX_RESOLVERS_PER_FAMILY
        || config.resolvers.v6.len() > MAX_RESOLVERS_PER_FAMILY
    {
        return Err(reject());
    }
    if config.search_domains.len() > MAX_SEARCH_DOMAINS
        || config.split_domains.len() > MAX_SPLIT_DOMAINS
    {
        return Err(reject());
    }
    for domain in config.search_domains.iter().chain(config.split_domains.iter()) {
        if !is_safe_domain(domain) {
            return Err(reject());
        }
    }
    Ok(())
}

/// What the host's resolver looked like before we touched it.
///
/// **DN-18: captured first, written to disk first, mutated second.** PS-6's
/// "restore before mutate" is not satisfiable by remembering a value in a process
/// that may be `SIGKILL`ed; the restore point is a file so an offline unblock
/// command and a boot-time restore can put the host back with the authority
/// absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePoint {
    /// The service whose DNS dictionary we replaced.
    pub service_id: String,
    /// The prior `ServerAddresses`, if the key existed.
    pub servers: Vec<String>,
    /// The prior `SearchDomains`.
    pub search_domains: Vec<String>,
    /// Whether the key existed at all. A key that did not exist is restored by
    /// **removing** ours, not by writing an empty one.
    pub existed: bool,
}

impl RestorePoint {
    /// A restore point for a service that had no DNS dictionary.
    #[must_use]
    pub fn absent(service_id: &str) -> Self {
        Self {
            service_id: service_id.to_owned(),
            servers: Vec::new(),
            search_domains: Vec::new(),
            existed: false,
        }
    }

    /// The plan that puts the host back.
    #[must_use]
    pub fn plan(&self) -> ResolverPlan {
        let key = dns_key(&self.service_id);
        if !self.existed {
            return ResolverPlan {
                sets: Vec::new(),
                removes: vec![key],
            };
        }
        let mut dictionary = BTreeMap::new();
        if !self.servers.is_empty() {
            dictionary.insert(
                "ServerAddresses".to_owned(),
                ScValue::Strings(self.servers.clone()),
            );
        }
        if !self.search_domains.is_empty() {
            dictionary.insert(
                "SearchDomains".to_owned(),
                ScValue::Strings(self.search_domains.clone()),
            );
        }
        ResolverPlan {
            sets: vec![ScEntry { key, dictionary }],
            removes: Vec::new(),
        }
    }

    /// The on-disk form.
    ///
    /// A line-oriented text format rather than a property list: the readers are
    /// the authority, the offline unblock command and a human with `cat`, and the
    /// last of those matters most in the case this file exists for.
    #[must_use]
    pub fn encode(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        out.push_str("twinvpn-resolver-restore 1\n");
        let _ = writeln!(out, "service {}", self.service_id);
        let _ = writeln!(out, "existed {}", u8::from(self.existed));
        for server in &self.servers {
            let _ = writeln!(out, "server {server}");
        }
        for domain in &self.search_domains {
            let _ = writeln!(out, "search {domain}");
        }
        out
    }

    /// Reads the on-disk form back.
    ///
    /// Returns `None` on anything it does not recognise. **Never a partial
    /// restore point:** a half-read one would restore half the host's resolver
    /// configuration, which is worse than restoring none and saying so.
    #[must_use]
    pub fn decode(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        if lines.next()? != "twinvpn-resolver-restore 1" {
            return None;
        }
        let mut service_id = None;
        let mut existed = None;
        let mut servers = Vec::new();
        let mut search_domains = Vec::new();
        for line in lines {
            let (tag, rest) = line.split_once(' ')?;
            match tag {
                "service" => service_id = Some(rest.to_owned()),
                "existed" => existed = Some(rest == "1"),
                "server" => servers.push(rest.to_owned()),
                "search" => search_domains.push(rest.to_owned()),
                _ => return None,
            }
        }
        Some(Self {
            service_id: service_id?,
            servers,
            search_domains,
            existed: existed?,
        })
    }
}

/// The resolvers a [`LinkFacts`](twinvpn_platform::LinkFacts) report would carry,
/// split per family.
///
/// A helper rather than an inline loop, because "which of these is v6" is a
/// question two call sites ask and one of them getting it wrong would make a
/// v6 resolver invisible.
#[must_use]
pub fn split_by_family(resolvers: &[IpAddr]) -> (Vec<IpAddr>, Vec<IpAddr>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for address in resolvers {
        match address.family() {
            twinvpn_types::AddressFamily::V4 => v4.push(*address),
            twinvpn_types::AddressFamily::V6 => v6.push(*address),
        }
    }
    (v4, v6)
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_types::{PerFamily, V4Addr, V6Addr};

    fn v4(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(V4Addr::from_octets(octets))
    }

    fn v6() -> IpAddr {
        let mut o = [0u8; 16];
        o[0] = 0xfd;
        o[1] = 0x7c;
        o[15] = 1;
        IpAddr::V6(V6Addr::new(o, None).expect("valid"))
    }

    fn config(is_default: bool) -> DnsConfig {
        DnsConfig {
            resolvers: PerFamily::new(vec![v4([100, 64, 0, 1])], vec![v6()]),
            search_domains: vec!["twin.internal".to_owned()],
            split_domains: vec!["twin.internal".to_owned(), "printer.local".to_owned()],
            is_default_resolver: is_default,
        }
    }

    #[test]
    fn the_key_is_the_one_configd_reads() {
        assert_eq!(
            dns_key("A1B2C3D4-0000-0000-0000-00000000000F"),
            "State:/Network/Service/A1B2C3D4-0000-0000-0000-00000000000F/DNS"
        );
    }

    #[test]
    fn both_families_reach_the_server_list_in_one_key() {
        let plan = plan(&config(true), "svc").expect("plans");
        let entry = &plan.sets[0];
        assert_eq!(
            entry.dictionary["ServerAddresses"],
            ScValue::Strings(vec!["100.64.0.1".to_owned(), "fd7c::1".to_owned()])
        );
    }

    #[test]
    fn split_mode_never_claims_dot_local() {
        // ADR-0011 §11.9's macOS row. `mDNSResponder` always sends `.local` to
        // multicast, and the two carriers must not disagree about which names the
        // tunnel claims — which is why both call `nesettings::is_mdns_domain`.
        let plan = plan(&config(false), "svc").expect("plans");
        assert_eq!(
            plan.sets[0].dictionary["SupplementalMatchDomains"],
            ScValue::Strings(vec!["twin.internal".to_owned()])
        );
        assert_eq!(
            plan.sets[0].dictionary["SupplementalMatchOrders"],
            ScValue::Numbers(vec![100])
        );
    }

    #[test]
    fn full_mode_carries_an_empty_supplemental_list_and_not_a_wildcard() {
        let plan = plan(&config(true), "svc").expect("plans");
        assert_eq!(
            plan.sets[0].dictionary["SupplementalMatchDomains"],
            ScValue::Strings(Vec::new())
        );
        assert!(!plan.sets[0]
            .dictionary
            .contains_key("SupplementalMatchOrders"));
    }

    #[test]
    fn a_config_with_no_resolvers_removes_the_key_rather_than_writing_an_empty_one() {
        // An empty `ServerAddresses` is a resolver that answers nothing; the
        // host's own resolvers are what should apply.
        let empty = DnsConfig {
            resolvers: PerFamily::new(Vec::new(), Vec::new()),
            search_domains: Vec::new(),
            split_domains: Vec::new(),
            is_default_resolver: false,
        };
        let plan = plan(&empty, "svc").expect("plans");
        assert!(plan.sets.is_empty());
        assert_eq!(plan.removes, vec![dns_key("svc")]);
    }

    #[test]
    fn a_limit_violation_is_refused_and_never_trimmed() {
        // §6 rule 9: "never a truncation, never a pad, never a silent accept". A
        // trimmed split-domain list is a set of names that resolve off-tunnel
        // without anybody having decided they should.
        let mut too_many = config(false);
        too_many.split_domains = (0..=MAX_SPLIT_DOMAINS).map(|i| format!("d{i}.x")).collect();
        let err = plan(&too_many, "svc").expect_err("refused");
        assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");

        let mut too_many_servers = config(false);
        too_many_servers.resolvers = PerFamily::new(
            vec![v4([100, 64, 0, 1]); MAX_RESOLVERS_PER_FAMILY + 1],
            Vec::new(),
        );
        assert!(plan(&too_many_servers, "svc").is_err());

        let mut too_many_search = config(false);
        too_many_search.search_domains =
            (0..=MAX_SEARCH_DOMAINS).map(|i| format!("s{i}.x")).collect();
        assert!(plan(&too_many_search, "svc").is_err());
    }

    #[test]
    fn a_domain_that_could_drive_an_unbounded_write_is_refused() {
        assert!(is_safe_domain("twin.internal"));
        assert!(is_safe_domain("a-b_c.example"));
        assert!(!is_safe_domain(""));
        assert!(!is_safe_domain(".leading"));
        assert!(!is_safe_domain(&"a".repeat(MAX_DOMAIN_BYTES + 1)));
        assert!(is_safe_domain(&"a".repeat(MAX_DOMAIN_BYTES)));
        // The characters that would end a key or start a new one.
        assert!(!is_safe_domain("twin internal"));
        assert!(!is_safe_domain("twin/internal"));
        assert!(!is_safe_domain("twin\ninternal"));
        assert!(!is_safe_domain("State:/Network"));

        let mut bad = config(false);
        bad.split_domains = vec!["has space".to_owned()];
        assert!(plan(&bad, "svc").is_err());
    }

    #[test]
    fn a_restore_point_round_trips_through_the_form_a_human_can_read() {
        // The readers are the authority, the offline unblock command, and a
        // person with `cat` — and the last matters most in the case this file
        // exists for.
        let point = RestorePoint {
            service_id: "svc".to_owned(),
            servers: vec!["192.168.1.1".to_owned(), "fd00::1".to_owned()],
            search_domains: vec!["lan".to_owned()],
            existed: true,
        };
        let text = point.encode();
        assert!(text.starts_with("twinvpn-resolver-restore 1\n"));
        assert_eq!(RestorePoint::decode(&text), Some(point));
    }

    #[test]
    fn a_service_that_had_no_dns_key_is_restored_by_removing_ours() {
        // Writing an empty dictionary would leave the host with a resolver
        // configuration it never had.
        let point = RestorePoint::absent("svc");
        let plan = point.plan();
        assert!(plan.sets.is_empty());
        assert_eq!(plan.removes, vec![dns_key("svc")]);
        assert_eq!(RestorePoint::decode(&point.encode()), Some(point));
    }

    #[test]
    fn a_restore_point_restores_exactly_what_was_there() {
        let point = RestorePoint {
            service_id: "svc".to_owned(),
            servers: vec!["192.168.1.1".to_owned()],
            search_domains: Vec::new(),
            existed: true,
        };
        let plan = point.plan();
        assert!(plan.removes.is_empty());
        assert_eq!(
            plan.sets[0].dictionary["ServerAddresses"],
            ScValue::Strings(vec!["192.168.1.1".to_owned()])
        );
        assert!(!plan.sets[0].dictionary.contains_key("SearchDomains"));
    }

    #[test]
    fn a_half_read_restore_point_is_refused_rather_than_half_restored() {
        assert_eq!(RestorePoint::decode(""), None);
        assert_eq!(RestorePoint::decode("wrong-header 1\n"), None);
        assert_eq!(
            RestorePoint::decode("twinvpn-resolver-restore 1\nservice svc\n"),
            None,
            "no `existed` line is an incomplete point"
        );
        assert_eq!(
            RestorePoint::decode("twinvpn-resolver-restore 1\nexisted 1\n"),
            None,
            "no `service` line is an incomplete point"
        );
        assert_eq!(
            RestorePoint::decode("twinvpn-resolver-restore 1\nservice svc\nexisted 1\nwat x\n"),
            None,
            "an unrecognised tag is a format this build does not know"
        );
    }

    #[test]
    fn the_plan_is_deterministic_because_the_dictionary_is_sorted() {
        let a = plan(&config(false), "svc").expect("plans");
        let b = plan(&config(false), "svc").expect("plans");
        assert_eq!(a, b);
        let keys: Vec<&String> = a.sets[0].dictionary.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn resolvers_split_by_family_so_a_v6_one_cannot_go_missing() {
        let (v4s, v6s) = split_by_family(&[v4([1, 1, 1, 1]), v6(), v4([8, 8, 8, 8])]);
        assert_eq!(v4s.len(), 2);
        assert_eq!(v6s.len(), 1);
    }
}
