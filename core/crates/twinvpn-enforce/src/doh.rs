//! The known-encrypted-resolver registry: parsed once, consumed by every
//! enforcement layer.
//!
//! **Authority:** `contracts/registry/encrypted_resolvers.json` (frozen,
//! `registry_version` 2), ADR-0011 §11.9 and §11.13(b), ADR-0012 §11.2 class 6
//! and §11.6.
//!
//! # Why the list lives here and not in `twinvpn-dns`
//!
//! `twinvpn_dns::stub::resolver_socket_permitted` already states it:
//!
//! > The list itself is `twinvpn-enforce`'s and ships with the build (ADR-0011
//! > §11.9); this crate takes the membership answer rather than holding the
//! > list, because the same list is what the enforcement layer denies
//! > off-overlay.
//!
//! One list, two questions, one answer. ADR-0011 §11.9's containment row and
//! KS-10's `RESOLVER` socket bound are the *same* set of addresses read in
//! opposite directions — "deny 443 to these off-overlay" and "permit 443 to
//! these from a resolver socket" — and holding it in two places is how those
//! two readings drift apart. This crate already owns ADR-0012's desired rule
//! set and already depends on `twinvpn-dns`, so it is the one place from which
//! both readings are reachable without a new edge in the crate graph.
//!
//! # What this is not, in the registry's own words
//!
//! > NOT a guarantee, and no implementation may present it as one. […] A
//! > resolver absent from this list is not thereby permitted — it is merely not
//! > specifically denied, and the class-6 + Tier-2 default-deny is what actually
//! > contains it. Containment is the guarantee; this list is a detection aid
//! > that narrows a known bypass.
//!
//! Nothing in this module, and nothing that consumes it, may be documented as
//! leak prevention. The leak guarantee is Tier 2.
//!
//! # The consumer rule, which is normative
//!
//! > An enforcement layer MUST treat this list as ADDITIVE to the port-based
//! > denial, never as a substitute for it. An empty or unparseable list MUST NOT
//! > weaken the port rules, and MUST NOT be a reason to fail open.
//!
//! Both halves are structural here rather than remembered:
//!
//! 1. **Additive.** A [`KnownResolvers`] carries endpoints and *no ports*
//!    besides [`KnownResolvers::doh_port`], and every renderer that consumes it
//!    emits its port rule unconditionally, before consulting this type at all.
//!    There is no code path in which a value of this type is the reason a port
//!    rule was not written.
//! 2. **Never a reason to fail open.** An unparseable or empty registry does not
//!    produce a degraded [`KnownResolvers`]; it produces no `KnownResolvers` at
//!    all. The failure is a [`RegistryError`], loud and typed, and a caller that
//!    ignores it is left holding an *empty* endpoint list — which the renderers
//!    treat as "no additional endpoint rules", never as "skip the port rules".
//!
//! Because the registry is embedded with `include_str!`, a parse failure is a
//! **build** defect and not an operational one: this module's own
//! `embedded_parses_and_covers_both_families` test fails `cargo test` before
//! such a build can ship.

use twinvpn_types::{AddressFamily, IpAddr, IpPrefix, PerFamily, V4Addr, V6Addr};

/// The frozen registry, embedded verbatim.
///
/// The same technique `twinvpn_schema::limits::LIMITS_JSON` uses, and for the
/// same reason: the compiled copy cannot drift from `contracts/registry/` without
/// failing `cargo test`, and the crate reads no file at runtime — which is what
/// keeps this crate the pure-decision crate its module documentation claims.
pub const REGISTRY_JSON: &str =
    include_str!("../../../../contracts/registry/encrypted_resolvers.json");

/// Why a registry could not be turned into a usable endpoint set.
///
/// Every variant is a **hard** condition. None of them has a "carry on with what
/// we could read" form, because a partially parsed deny-list is the shape of
/// failure the consumer rule exists to forbid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// The document is not JSON, or not an object.
    #[error("the encrypted-resolver registry is not parseable JSON: {detail}")]
    Unparseable {
        /// The parser's own complaint.
        detail: String,
    },
    /// A required field is missing or has the wrong JSON type.
    #[error("the encrypted-resolver registry is malformed: {field} is missing or ill-typed")]
    Malformed {
        /// The field that could not be read.
        field: &'static str,
    },
    /// An endpoint literal is not an address of the family its key names.
    #[error("the encrypted-resolver registry carries `{literal}` under `{key}`, which is not a {key} address")]
    BadEndpoint {
        /// The key the literal appeared under, `v4` or `v6`.
        key: &'static str,
        /// The literal as it appeared.
        literal: String,
    },
    /// The registry parsed but names no endpoints in one or both families.
    ///
    /// Refused rather than accepted-as-empty. An empty list is legal in the
    /// sense that it must not weaken the port rules — and the renderers honour
    /// that — but it is never legal as the *shipped* artifact, and silently
    /// building the product around one would remove the half of §11.9 this
    /// registry exists to supply.
    #[error(
        "the encrypted-resolver registry names no {family:?} endpoints; \
             a shipped registry covers both families (ADR-0011 §11.9, KS-5)"
    )]
    Empty {
        /// The family with no endpoints.
        family: AddressFamily,
    },
}

/// The parsed registry: the known-DoH/DoT endpoints, per family.
///
/// Construction is fallible and the type has no other constructor, so a value of
/// this type is proof that the registry parsed and covers both families. That is
/// the fail-closed half of the consumer rule expressed as a type rather than as
/// a check a caller has to remember.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownResolvers {
    version: u32,
    doh_port: u16,
    dot_port: u16,
    v4: Vec<IpPrefix>,
    v6: Vec<IpPrefix>,
}

impl KnownResolvers {
    /// Parses the registry this build embedded.
    ///
    /// # Errors
    ///
    /// [`RegistryError`], for every reason a registry can be unusable. A caller
    /// that cannot proceed without the list MUST refuse to start rather than
    /// substitute an empty one of its own — but note that refusing is a choice
    /// about *this half* of §11.9 only: the port-based denial and Tier 2 do not
    /// depend on this type and are unaffected by its absence.
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(REGISTRY_JSON)
    }

    /// Parses an arbitrary registry document, for tests and for a build that
    /// ships a newer artifact than the one embedded here.
    ///
    /// # Errors
    ///
    /// [`RegistryError`].
    pub fn parse(json: &str) -> Result<Self, RegistryError> {
        let root: serde_json::Value =
            serde_json::from_str(json).map_err(|error| RegistryError::Unparseable {
                detail: error.to_string(),
            })?;
        let version = u32::try_from(
            root.get("registry_version")
                .and_then(serde_json::Value::as_u64)
                .ok_or(RegistryError::Malformed {
                    field: "registry_version",
                })?,
        )
        .map_err(|_| RegistryError::Malformed {
            field: "registry_version",
        })?;
        let ports = root
            .get("ports")
            .ok_or(RegistryError::Malformed { field: "ports" })?;
        let entries = root
            .get("endpoints")
            .and_then(serde_json::Value::as_array)
            .ok_or(RegistryError::Malformed { field: "endpoints" })?;

        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for entry in entries {
            read_family(entry, "v4", &mut v4)?;
            read_family(entry, "v6", &mut v6)?;
        }
        // Sorted and de-duplicated, so a renderer that walks the list produces
        // byte-identical output for one registry however the JSON was ordered.
        // Two renders of one input must be comparable, or a reconciler sees
        // drift that is not there.
        v4.sort_unstable();
        v4.dedup();
        v6.sort_unstable();
        v6.dedup();

        if v4.is_empty() {
            return Err(RegistryError::Empty {
                family: AddressFamily::V4,
            });
        }
        if v6.is_empty() {
            return Err(RegistryError::Empty {
                family: AddressFamily::V6,
            });
        }
        Ok(Self {
            version,
            doh_port: read_port(ports, "doh_tcp")?,
            dot_port: read_port(ports, "dot_tcp")?,
            v4,
            v6,
        })
    }

    /// The registry's own `registry_version`, for a diagnostic bundle.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// The port the DoH half of the containment rule denies — the registry's
    /// `ports.doh_tcp`, 443 in version 2.
    ///
    /// Read from the artifact rather than written here, so a registry that ever
    /// names a different port moves every enforcement layer at once.
    #[must_use]
    pub const fn doh_port(&self) -> u16 {
        self.doh_port
    }

    /// The registry's `ports.dot_tcp`, 853 in version 2.
    ///
    /// Present so a renderer can assert that the port it already denies
    /// unconditionally is the port the registry names, rather than assuming it.
    #[must_use]
    pub const fn dot_port(&self) -> u16 {
        self.dot_port
    }

    /// The endpoints, per family, as host prefixes (`/32` and `/128`).
    ///
    /// **Both families, always.** [`Self::parse`] refuses a registry that covers
    /// only one, so there is no value of this type from which a caller could
    /// render a v4 endpoint rule with no v6 counterpart — ADR-0010 §11.5's
    /// "structural guarantee, not a discipline", applied to this list.
    #[must_use]
    pub fn per_family(&self) -> PerFamily<Vec<IpPrefix>> {
        PerFamily::new(self.v4.clone(), self.v6.clone())
    }

    /// Every endpoint, both families, v4 first.
    ///
    /// The shape the platform adapters take: their `EnforcementConfig` carries
    /// one `Vec<IpPrefix>` and splits it per family itself, exactly as it
    /// already does for `on_link_prefixes`.
    #[must_use]
    pub fn endpoints(&self) -> Vec<IpPrefix> {
        let mut out = self.v4.clone();
        out.extend_from_slice(&self.v6);
        out
    }

    /// Whether `address` is a known encrypted-resolver endpoint.
    ///
    /// This is a **detection aid**, and a `false` here means only "not
    /// specifically listed". It is never evidence that a destination is safe,
    /// and no caller may treat it as one.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        let family = match address {
            IpAddr::V4(_) => &self.v4,
            IpAddr::V6(_) => &self.v6,
        };
        family.iter().any(|prefix| prefix.contains(address))
    }

    /// KS-10's `RESOLVER` socket rule, with the membership answer supplied.
    ///
    /// [`twinvpn_dns::stub::resolver_socket_permitted`] has held the rule since
    /// defect D-5 was closed, and has been unreachable in practice because
    /// nothing could answer its `destination_is_known_doh` argument. This is
    /// that answer, from the registry ADR-0011 §11.9 designates — which is the
    /// same list the containment rule denies off-overlay, so the socket bound
    /// and the firewall rule cannot disagree about which endpoints are "known".
    #[must_use]
    pub fn resolver_socket_permitted(&self, port: u16, destination: IpAddr) -> bool {
        twinvpn_dns::stub::resolver_socket_permitted(port, self.contains(destination))
    }
}

/// Reads one port field out of the registry's `ports` object.
fn read_port(ports: &serde_json::Value, field: &'static str) -> Result<u16, RegistryError> {
    ports
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(RegistryError::Malformed { field })
}

/// Reads one provider entry's `v4` or `v6` array into `out`.
///
/// A **missing** array is not an error: a future provider entry may carry only
/// one family, and the both-families guarantee is asserted over the whole
/// registry in [`KnownResolvers::parse`] rather than per entry. An array that is
/// present but holds something that is not an address of that family *is* an
/// error, because that is a corrupt artifact and not a sparse one.
fn read_family(
    entry: &serde_json::Value,
    key: &'static str,
    out: &mut Vec<IpPrefix>,
) -> Result<(), RegistryError> {
    let Some(list) = entry.get(key) else {
        return Ok(());
    };
    let list = list
        .as_array()
        .ok_or(RegistryError::Malformed { field: "endpoints" })?;
    for literal in list {
        let literal = literal
            .as_str()
            .ok_or(RegistryError::Malformed { field: "endpoints" })?;
        out.push(host_prefix(key, literal)?);
    }
    Ok(())
}

/// One address literal as a host prefix.
///
/// The registry names bare addresses, and the enforcement layers all match on
/// prefixes, so each endpoint becomes its own `/32` or `/128`. Parsing goes
/// through `std::net`, which is the standard library's address grammar and not a
/// second one written here — an IPv6 literal has enough corner cases
/// (compression, embedded IPv4, leading zeros) that a hand-rolled parser is a
/// defect waiting to be found by an endpoint we then fail to deny.
fn host_prefix(key: &'static str, literal: &str) -> Result<IpPrefix, RegistryError> {
    let bad = || RegistryError::BadEndpoint {
        key,
        literal: literal.to_owned(),
    };
    let (address, len) = if key == "v4" {
        let parsed: std::net::Ipv4Addr = literal.parse().map_err(|_| bad())?;
        (IpAddr::V4(V4Addr::from_octets(parsed.octets())), 32)
    } else {
        let parsed: std::net::Ipv6Addr = literal.parse().map_err(|_| bad())?;
        // `prefix_base` rather than `new`: a registry endpoint is a global
        // address with no zone, and `V6Addr::new` would demand one were a
        // link-local literal ever to appear here.
        (
            IpAddr::V6(V6Addr::prefix_base(parsed.octets()).map_err(|_| bad())?),
            128,
        )
    };
    IpPrefix::new(address, len).map_err(|_| bad())
}

#[cfg(test)]
mod tests {
    use super::{AddressFamily, IpAddr, KnownResolvers, RegistryError, V4Addr, V6Addr};

    fn v6(literal: &str) -> IpAddr {
        let parsed: std::net::Ipv6Addr = literal.parse().expect("test literal is well formed");
        IpAddr::V6(V6Addr::prefix_base(parsed.octets()).expect("no zone on a global address"))
    }

    /// The build defect that would otherwise be an operational one.
    ///
    /// `include_str!` makes a malformed registry a *compiled-in* fact, so this
    /// test is the loud, fail-closed condition the consumer rule asks for: a
    /// registry that does not parse, or that stops covering a family, fails
    /// `cargo test` and never reaches a host.
    #[test]
    fn embedded_parses_and_covers_both_families() {
        let registry = KnownResolvers::embedded().expect("the shipped registry parses");
        assert_eq!(registry.version(), 2);
        assert_eq!(registry.doh_port(), 443);
        assert_eq!(registry.dot_port(), 853);
        let per_family = registry.per_family();
        assert!(!per_family.v4.is_empty(), "KS-5: v4 endpoints are present");
        assert!(!per_family.v6.is_empty(), "KS-5: v6 endpoints are present");
        assert_eq!(
            registry.endpoints().len(),
            per_family.v4.len() + per_family.v6.len()
        );
    }

    #[test]
    fn the_named_providers_are_all_present_in_both_families() {
        let registry = KnownResolvers::embedded().expect("the shipped registry parses");
        // One v4 and one v6 endpoint per provider row of the registry, so a
        // provider silently dropped from the artifact fails here.
        for literal in [
            [1, 1, 1, 1],
            [1, 1, 1, 2],
            [8, 8, 8, 8],
            [9, 9, 9, 9],
            [208, 67, 222, 222],
            [94, 140, 14, 14],
            [194, 242, 2, 2],
            [45, 90, 28, 0],
        ] {
            assert!(
                registry.contains(IpAddr::V4(V4Addr::from_octets(literal))),
                "{literal:?} is a registry endpoint"
            );
        }
        for literal in [
            "2606:4700:4700::1111",
            "2606:4700:4700::1112",
            "2001:4860:4860::8888",
            "2620:fe::fe",
            "2620:119:35::35",
            "2a10:50c0::ad1:ff",
            "2a07:e340::2",
            "2a07:a8c0::",
        ] {
            assert!(
                registry.contains(v6(literal)),
                "{literal} is a registry endpoint"
            );
        }
    }

    /// The registry is a detection aid, so an address it does not name is
    /// simply not named — never "permitted".
    #[test]
    fn an_unlisted_address_is_not_a_known_endpoint() {
        let registry = KnownResolvers::embedded().expect("the shipped registry parses");
        assert!(!registry.contains(IpAddr::V4(V4Addr::from_octets([203, 0, 113, 1]))));
        assert!(!registry.contains(v6("2001:db8::1")));
    }

    /// KS-10, wired: 443 is authorised by DESTINATION and never by the port.
    #[test]
    fn ks10_authorises_443_only_to_a_registry_endpoint() {
        let registry = KnownResolvers::embedded().expect("the shipped registry parses");
        let known = IpAddr::V4(V4Addr::from_octets([1, 1, 1, 1]));
        let unknown = IpAddr::V4(V4Addr::from_octets([203, 0, 113, 1]));
        assert!(registry.resolver_socket_permitted(443, known));
        assert!(!registry.resolver_socket_permitted(443, unknown));
        // 53 and 853 are authorised by the port alone, to any destination.
        assert!(registry.resolver_socket_permitted(53, unknown));
        assert!(registry.resolver_socket_permitted(853, unknown));
        // And nothing else is authorised at all, to either.
        assert!(!registry.resolver_socket_permitted(80, known));
        assert!(!registry.resolver_socket_permitted(8080, known));
        // Both families, so a v6 endpoint is not a second implementation.
        assert!(registry.resolver_socket_permitted(443, v6("2606:4700:4700::1111")));
        assert!(!registry.resolver_socket_permitted(443, v6("2001:db8::1")));
    }

    #[test]
    fn an_unparseable_registry_is_an_error_and_not_an_empty_list() {
        let error = KnownResolvers::parse("{ not json").expect_err("refused");
        assert!(matches!(error, RegistryError::Unparseable { .. }));
    }

    #[test]
    fn a_registry_missing_a_family_is_refused_rather_than_half_installed() {
        let only_v4 = r#"{
            "registry_version": 2,
            "ports": { "doh_tcp": 443, "dot_tcp": 853 },
            "endpoints": [ { "provider": "x", "v4": ["1.1.1.1"], "v6": [] } ]
        }"#;
        assert_eq!(
            KnownResolvers::parse(only_v4).expect_err("refused"),
            RegistryError::Empty {
                family: AddressFamily::V6
            }
        );
    }

    #[test]
    fn a_corrupt_endpoint_literal_is_refused_rather_than_skipped() {
        let corrupt = r#"{
            "registry_version": 2,
            "ports": { "doh_tcp": 443, "dot_tcp": 853 },
            "endpoints": [ { "provider": "x", "v4": ["not-an-address"], "v6": ["::1"] } ]
        }"#;
        assert!(matches!(
            KnownResolvers::parse(corrupt).expect_err("refused"),
            RegistryError::BadEndpoint { key: "v4", .. }
        ));
    }

    #[test]
    fn parsing_is_deterministic_and_deduplicated() {
        let duplicated = r#"{
            "registry_version": 7,
            "ports": { "doh_tcp": 443, "dot_tcp": 853 },
            "endpoints": [
              { "provider": "b", "v4": ["8.8.8.8", "1.1.1.1"], "v6": ["2001:db8::2"] },
              { "provider": "a", "v4": ["1.1.1.1"], "v6": ["2001:db8::1", "2001:db8::2"] }
            ]
        }"#;
        let registry = KnownResolvers::parse(duplicated).expect("parses");
        assert_eq!(registry.version(), 7);
        let per_family = registry.per_family();
        assert_eq!(per_family.v4.len(), 2, "1.1.1.1 appears once");
        assert_eq!(per_family.v6.len(), 2, "2001:db8::2 appears once");
        assert_eq!(
            registry,
            KnownResolvers::parse(duplicated).expect("parses"),
            "two parses of one document are equal"
        );
    }
}
