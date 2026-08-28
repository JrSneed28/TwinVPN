//! The resolver programme: NRPT rules and interface DNS settings.
//!
//! **Authority:** ADR-0011 §11.7 (the Windows row — "NRPT rules
//! (`DnsPolicyConfig`) for the split domains, and `.` in `FULL` mode;
//! interface-scoped resolver on our adapter", and **"the highest-risk platform
//! for D7"**), §11.9 (SMHNR), DN-5, DN-8, DN-9, DN-10, DN-18, DN-19, DN-20,
//! DN-24; ADR-0016 PS-6 and PS-21 step 3; `ownership.md` §6 rule 9;
//! `contracts/registry/limits.json`.
//!
//! # D7 is why this module has a restore point and not just a programme
//!
//! ADR-0011 §11.7 names Windows the highest-risk platform for D7 for a specific
//! reason: NRPT configuration lives in the registry and **does not die with the
//! tunnel object**. A crashed, killed or uninstalled agent leaves the host
//! pointed at a stub that is not answering, and the host stays broken until
//! somebody edits the registry.
//!
//! So the ordering rule DN-19 states is not advice here, it is the whole design:
//!
//! ```text
//! apply:    stub bound & answering ─► RestorePoint persisted ─► NRPT + interface
//!                                    ─► reconciler confirms actual == intended
//! teardown: restore the RestorePoint ─► reconciler confirms ─► unbind the stub
//! crash:    boot ─► the KS-19 filters are live ─► the restore service runs ─►
//!           if an owner-tagged resolver config exists whose stub does not
//!           answer, restore the RestorePoint
//! ```
//!
//! [`RestorePoint`] is the value written **before** the mutation (DN-18, PS-6),
//! and it is deliberately serialisable to a plain file: DN-20 requires
//! restoration not to depend on the agent being healthy, so the artifact that
//! performs it is a separate package-owned service that can read this without
//! linking the core.
//!
//! # Containment, not configuration, is the guarantee
//!
//! ADR-0011 §11.9 names Smart Multi-Homed Name Resolution as the Windows bypass
//! channel: `dnscache` sends the same query out every adapter in parallel and
//! takes the first answer. NRPT makes a *matched* namespace non-parallel, which
//! is the steering half. The half that holds when steering fails is
//! [`crate::wfp::TrafficClass::DnsContainment`] — a WFP block on UDP/TCP 53 and
//! TCP 853 on every non-overlay interface, regardless of which process opened
//! the socket. This module does the steering; it does not pretend to be the
//! guarantee.
//!
//! # A gap this module reports rather than fills
//!
//! §11.9's containment names "known-DoH endpoints" alongside the three ports.
//! That list is a policy input: it changes as resolvers appear, and it is
//! carried by `DNSPolicy` rather than by a constant. **The seam does not carry
//! it** — [`twinvpn_platform::DnsConfig`] has `resolvers`, `search_domains`,
//! `split_domains` and `is_default_resolver`, and nothing that names an
//! encrypted-DNS endpoint. So the DoH half of §11.9's containment is **not
//! installed by this build**, and the residual is that a browser with a pinned
//! DoH endpoint on 443 resolves off-tunnel. Reported to the integration lead;
//! not resolved here, because `contracts/` is frozen and inventing a config
//! field would be the second contract MI-20 forbids in its own domain.
//!
//! # This module is target-free
//!
//! [`DnsProgramme`] is data. Writing it — `DnsPolicyConfig` registry values and
//! `SetInterfaceDnsSettings` — is [`crate::sys`]'s.

use twinvpn_platform::{DnsConfig, PlatformError};
use twinvpn_types::{AddressFamily, IpAddr, PerFamily};

use crate::route::InterfaceLuid;

/// The registry subkey NRPT rules live under.
///
/// Documented as a constant because ADR-0017 §10.1's reasoning applies to it
/// too: scripts and configuration-management tooling hard-code paths, and the
/// offline restore service reads this one with the agent absent.
pub const NRPT_ROOT: &str =
    r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";

/// The prefix every rule this adapter creates carries.
///
/// **The owner tag.** DN-18 requires the restore point to name "platform object
/// IDs", and on Windows the object ID of an NRPT rule is its subkey name. A rule
/// without this prefix is somebody else's — a domain policy, an enterprise MDM
/// profile — and is never modified, never counted and never removed.
pub const RULE_PREFIX: &str = "TwinVPN-";

/// `limits.json`'s `dns.max_split_domain_rules`.
pub const MAX_SPLIT_DOMAIN_RULES: usize = 256;
/// `limits.json`'s `dns.max_search_domains`.
pub const MAX_SEARCH_DOMAINS: usize = 32;
/// `limits.json`'s `dns.max_domain_name_bytes`.
pub const MAX_DOMAIN_NAME_BYTES: usize = 253;
/// `limits.json`'s `dns.max_resolvers_per_family`.
pub const MAX_RESOLVERS_PER_FAMILY: usize = 8;

/// One NRPT rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NrptRule {
    /// The subkey name, always prefixed with [`RULE_PREFIX`].
    pub id: String,
    /// The namespace, in NRPT's own form: a leading dot for a suffix match, or
    /// exactly `"."` for the whole namespace in `FULL` mode.
    pub namespace: String,
    /// The resolvers, in the order they should be tried.
    ///
    /// Both families in one list, because a rule is a namespace and not an
    /// address family: splitting them would let a v6 rule exist without its v4
    /// counterpart, which is ADR-0011 D4's "identical rigor" failing at the
    /// configuration layer.
    pub resolvers: Vec<IpAddr>,
    /// Whether the rule requires DNSSEC validation.
    ///
    /// `true` for the `protected` scope per DN-25.
    pub dnssec_validation: bool,
}

/// The interface-scoped resolver settings for one adapter.
///
/// `SetInterfaceDnsSettings`'s inputs, reduced to what this adapter sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceDns {
    /// Which adapter.
    pub luid: InterfaceLuid,
    /// The resolvers, per family.
    ///
    /// `SetInterfaceDnsSettings` takes one family per call, which is exactly the
    /// shape that lets a v6 configuration be forgotten; carrying a `PerFamily`
    /// here means the *programme* always names both, and
    /// [`DnsProgramme::validate`] refuses one that does not.
    pub resolvers: PerFamily<Vec<IpAddr>>,
    /// The search list.
    pub search_list: Vec<String>,
    /// Whether to register this adapter's addresses in DNS.
    ///
    /// Always `false`: registering the overlay address in the host's DNS would
    /// publish it outside the overlay, and ADR-0011 D6 keeps the TwinNet
    /// namespace to itself.
    pub register_adapter_name: bool,
}

/// Everything one generation asks of the host resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsProgramme {
    /// The NRPT rules to hold, sorted by id.
    pub rules: Vec<NrptRule>,
    /// The interface settings to hold.
    pub interface: InterfaceDns,
}

/// The verbatim prior configuration, written before anything is mutated.
///
/// **DN-18**: "Before writing host resolver config, agent MUST durably persist an
/// owner-tagged `RestorePoint` (verbatim prior config + platform object IDs +
/// `restore_token`), written and flushed **before** the mutation."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePoint {
    /// The NRPT rules that existed before, **including** rules that are not
    /// ours.
    ///
    /// Not ours to restore — the restore only re-creates what it removed — but
    /// recorded, because DN-8's rule-conflict diagnosis needs to know what else
    /// claimed a namespace and a support case cannot reconstruct that later.
    pub prior_rules: Vec<NrptRule>,
    /// The interface settings that existed before.
    pub prior_interface: InterfaceDns,
    /// The token that ties this restore point to the generation that wrote it.
    pub restore_token: u64,
}

/// The change from one programme to another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPlan {
    /// Rules to write.
    pub rule_writes: Vec<NrptRule>,
    /// Rule ids to delete. **Only ever ours** — see [`DnsPlan::validate`].
    pub rule_deletes: Vec<String>,
    /// The interface settings to install, or `None` to leave them alone.
    pub interface: Option<InterfaceDns>,
}

/// What a DNS programme cannot legally contain.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsDefect {
    /// A rule id without the owner tag would let this adapter modify somebody
    /// else's policy.
    #[error("the rule id `{0}` is not owner-tagged")]
    ForeignRule(String),
    /// DN-8: two rules claim the same namespace.
    #[error("two rules claim the namespace `{0}`")]
    RuleConflict(String),
    /// A namespace that is not a whole-label suffix (DN-9).
    #[error("the namespace `{0}` is not a whole-label suffix")]
    MalformedNamespace(String),
    /// One family has resolvers and the other does not, which is D4's
    /// "identical rigor" failing at the configuration layer.
    #[error("resolvers were programmed for one family and not the other (v4={v4}, v6={v6})")]
    FamilyAsymmetry {
        /// How many v4 resolvers.
        v4: usize,
        /// How many v6.
        v6: usize,
    },
}

/// The stub's four listening addresses, ADR-0011 §11.2's Windows row.
///
/// Two loopback and two overlay anycast, and the programme points the host at
/// all four rather than at one: a host whose only resolver is `127.0.0.53` has
/// no v6 path to the stub, and DN-12 forbids AAAA resolution from depending on
/// the underlay family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StubAddresses {
    /// `127.0.0.53` (or the first free address in `127.0.0.0/8`).
    pub loopback_v4: IpAddr,
    /// `[::1]`.
    pub loopback_v6: IpAddr,
    /// `100.127.255.53`, AP-2's reserved service block.
    pub anycast_v4: IpAddr,
    /// `fd7c:9e5d:2a10:ffff::53`.
    pub anycast_v6: IpAddr,
}

impl StubAddresses {
    /// The four addresses, in NRPT's preference order: loopback first, because
    /// it needs no route and answers during the window in which the overlay
    /// interface exists but carries nothing.
    #[must_use]
    pub fn ordered(&self) -> Vec<IpAddr> {
        vec![
            self.loopback_v4,
            self.loopback_v6,
            self.anycast_v4,
            self.anycast_v6,
        ]
    }

    /// The addresses of one family.
    #[must_use]
    pub fn of_family(&self, family: AddressFamily) -> Vec<IpAddr> {
        self.ordered()
            .into_iter()
            .filter(|a| a.family() == family)
            .collect()
    }
}

/// Renders the programme a `DnsConfig` implies.
///
/// # Errors
///
/// [`PlatformError`] when an input exceeds `limits.json`. **Validated before any
/// allocation proportional to a declared length** (`ownership.md` §6 rule 9):
/// the counts are checked against the caps first, and a violation is a typed
/// reject rather than a truncation.
pub fn render(
    config: &DnsConfig,
    overlay: InterfaceLuid,
    stub: &StubAddresses,
) -> Result<DnsProgramme, PlatformError> {
    // §6 rule 9: check the declared lengths BEFORE reserving anything.
    if config.split_domains.len() > MAX_SPLIT_DOMAIN_RULES
        || config.search_domains.len() > MAX_SEARCH_DOMAINS
        || config.resolvers.get(AddressFamily::V4).len() > MAX_RESOLVERS_PER_FAMILY
        || config.resolvers.get(AddressFamily::V6).len() > MAX_RESOLVERS_PER_FAMILY
    {
        return Err(crate::oserr::unavailable("DnsConfig exceeds limits.json"));
    }
    for name in config.split_domains.iter().chain(&config.search_domains) {
        if name.len() > MAX_DOMAIN_NAME_BYTES {
            return Err(crate::oserr::unavailable("domain name exceeds limits.json"));
        }
    }

    let mut rules = Vec::with_capacity(config.split_domains.len() + 1);
    for domain in &config.split_domains {
        let namespace = suffix_namespace(domain);
        rules.push(NrptRule {
            id: rule_id(&namespace),
            namespace,
            resolvers: stub.ordered(),
            dnssec_validation: true,
        });
    }
    // ADR-0011 §11.7's Windows row: `.` in `FULL` mode. One rule for the whole
    // namespace is what makes SMHNR's parallel resolution stop applying to it.
    if config.is_default_resolver {
        rules.push(NrptRule {
            id: rule_id("."),
            namespace: ".".to_owned(),
            resolvers: stub.ordered(),
            dnssec_validation: true,
        });
    }
    rules.sort();
    rules.dedup_by(|a, b| a.namespace == b.namespace);

    Ok(DnsProgramme {
        rules,
        interface: InterfaceDns {
            luid: overlay,
            resolvers: PerFamily::new(
                stub.of_family(AddressFamily::V4),
                stub.of_family(AddressFamily::V6),
            ),
            search_list: config.search_domains.clone(),
            register_adapter_name: false,
        },
    })
}

impl DnsProgramme {
    /// Refuses a programme that would touch somebody else's policy or leave a
    /// family unprogrammed.
    pub fn validate(&self) -> Result<(), DnsDefect> {
        let mut seen: Vec<&str> = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            if !rule.id.starts_with(RULE_PREFIX) {
                return Err(DnsDefect::ForeignRule(rule.id.clone()));
            }
            if !is_well_formed_namespace(&rule.namespace) {
                return Err(DnsDefect::MalformedNamespace(rule.namespace.clone()));
            }
            if seen.contains(&rule.namespace.as_str()) {
                return Err(DnsDefect::RuleConflict(rule.namespace.clone()));
            }
            seen.push(&rule.namespace);
        }
        let v4 = self.interface.resolvers.get(AddressFamily::V4).len();
        let v6 = self.interface.resolvers.get(AddressFamily::V6).len();
        if (v4 == 0) != (v6 == 0) {
            return Err(DnsDefect::FamilyAsymmetry { v4, v6 });
        }
        Ok(())
    }

    /// Every owner-tagged rule id this programme holds.
    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        self.rules.iter().map(|r| r.id.clone()).collect()
    }
}

/// The change from what the host holds to what the programme wants.
///
/// Only ever writes and deletes **our own** rules; a rule an enterprise policy
/// or another product installed is left exactly where it is (`ROUTE`'s R7
/// discipline, applied to the resolver).
#[must_use]
pub fn plan(previous: &[NrptRule], desired: &DnsProgramme) -> DnsPlan {
    let ours = |r: &NrptRule| r.id.starts_with(RULE_PREFIX);
    let writes = desired
        .rules
        .iter()
        .filter(|d| !previous.iter().any(|p| p == *d))
        .cloned()
        .collect();
    let deletes = previous
        .iter()
        .filter(|p| ours(p) && !desired.rules.iter().any(|d| d.id == p.id))
        .map(|p| p.id.clone())
        .collect();
    DnsPlan {
        rule_writes: writes,
        rule_deletes: deletes,
        interface: Some(desired.interface.clone()),
    }
}

/// The plan that restores a [`RestorePoint`].
///
/// DN-19's teardown step and PS-21 step 3. It removes every rule of ours that
/// the restore point did not record and re-writes the ones it did — so a rule an
/// enterprise policy added *while* we were configured survives, which is the
/// difference between restoring and reverting.
#[must_use]
pub fn restore_plan(point: &RestorePoint, currently_ours: &[String]) -> DnsPlan {
    let keep: Vec<&NrptRule> = point
        .prior_rules
        .iter()
        .filter(|r| r.id.starts_with(RULE_PREFIX))
        .collect();
    DnsPlan {
        rule_writes: keep.iter().map(|r| (*r).clone()).collect(),
        rule_deletes: currently_ours
            .iter()
            .filter(|id| !keep.iter().any(|r| &&r.id == id))
            .cloned()
            .collect(),
        interface: Some(point.prior_interface.clone()),
    }
}

impl DnsPlan {
    /// Refuses a plan that would delete a rule this adapter does not own.
    pub fn validate(&self) -> Result<(), DnsDefect> {
        for id in &self.rule_deletes {
            if !id.starts_with(RULE_PREFIX) {
                return Err(DnsDefect::ForeignRule(id.clone()));
            }
        }
        for rule in &self.rule_writes {
            if !rule.id.starts_with(RULE_PREFIX) {
                return Err(DnsDefect::ForeignRule(rule.id.clone()));
            }
        }
        Ok(())
    }
}

/// The subkey name for a namespace.
///
/// Deterministic, so re-rendering the same config addresses the same registry
/// values and a retry after a crash converges rather than accumulating rules.
#[must_use]
pub fn rule_id(namespace: &str) -> String {
    let mut id = String::with_capacity(RULE_PREFIX.len() + namespace.len());
    id.push_str(RULE_PREFIX);
    for byte in namespace.bytes() {
        // A registry subkey name may not contain a backslash; everything else in
        // a DNS name is already safe. Lower-cased because DN-9's matching is
        // case-insensitive and two ids differing only in case would be two rules
        // for one namespace.
        id.push(match byte {
            b'\\' => '_',
            b => (b as char).to_ascii_lowercase(),
        });
    }
    id
}

/// A domain in NRPT's suffix form.
///
/// DN-9: "suffix matching on whole labels, case-insensitive". NRPT expresses a
/// whole-label suffix with a leading dot, so `example.com` becomes
/// `.example.com` — and a namespace that already has one is not given a second.
#[must_use]
pub fn suffix_namespace(domain: &str) -> String {
    let trimmed = domain.trim_end_matches('.').to_ascii_lowercase();
    if trimmed.starts_with('.') {
        trimmed
    } else {
        format!(".{trimmed}")
    }
}

/// Whether a namespace is one NRPT can hold.
fn is_well_formed_namespace(namespace: &str) -> bool {
    if namespace == "." {
        return true;
    }
    if !namespace.starts_with('.') || namespace.len() < 2 {
        return false;
    }
    if namespace.len() > MAX_DOMAIN_NAME_BYTES {
        return false;
    }
    // Whole labels: no empty label, and nothing but the characters a DNS
    // presentation name may carry.
    namespace[1..].split('.').all(|label| {
        !label.is_empty()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_types::{V4Addr, V6Addr};

    const OVERLAY: InterfaceLuid = InterfaceLuid(6);

    fn stub() -> StubAddresses {
        let mut anycast6 = [0u8; 16];
        anycast6[0] = 0xfd;
        anycast6[1] = 0x7c;
        anycast6[2] = 0x9e;
        anycast6[3] = 0x5d;
        anycast6[4] = 0x2a;
        anycast6[5] = 0x10;
        anycast6[6] = 0xff;
        anycast6[7] = 0xff;
        anycast6[15] = 0x53;
        let mut loop6 = [0u8; 16];
        loop6[15] = 1;
        StubAddresses {
            loopback_v4: IpAddr::V4(V4Addr::from_octets([127, 0, 0, 53])),
            loopback_v6: IpAddr::V6(V6Addr::new(loop6, None).expect("::1")),
            anycast_v4: IpAddr::V4(V4Addr::from_octets([100, 127, 255, 53])),
            anycast_v6: IpAddr::V6(V6Addr::new(anycast6, None).expect("anycast")),
        }
    }

    fn config(split: &[&str], full: bool) -> DnsConfig {
        DnsConfig {
            resolvers: PerFamily::new(Vec::new(), Vec::new()),
            search_domains: vec!["tnet.twinvpn.net".to_owned()],
            split_domains: split.iter().map(|s| (*s).to_owned()).collect(),
            is_default_resolver: full,
        }
    }

    #[test]
    fn split_mode_programmes_one_rule_per_domain_and_no_dot_rule() {
        let programme = render(
            &config(&["tnet.twinvpn.net", "corp.example"], false),
            OVERLAY,
            &stub(),
        )
        .expect("renders");
        programme.validate().expect("valid");
        assert_eq!(programme.rules.len(), 2);
        assert!(programme.rules.iter().all(|r| r.namespace != "."));
        assert!(programme
            .rules
            .iter()
            .any(|r| r.namespace == ".tnet.twinvpn.net"));
    }

    #[test]
    fn full_mode_adds_the_dot_rule_which_is_what_stops_smhnr() {
        // ADR-0011 §11.7's Windows row and §11.9: NRPT makes a matched namespace
        // non-parallel, and in FULL mode the matched namespace is everything.
        let programme = render(&config(&["corp.example"], true), OVERLAY, &stub()).expect("renders");
        programme.validate().expect("valid");
        assert!(programme.rules.iter().any(|r| r.namespace == "."));
    }

    #[test]
    fn every_rule_points_at_all_four_stub_addresses() {
        // DN-12: a host whose only resolver is a v4 loopback has no v6 path to
        // the stub, and AAAA resolution must not depend on the underlay family.
        let programme = render(&config(&["corp.example"], true), OVERLAY, &stub()).expect("renders");
        for rule in &programme.rules {
            assert_eq!(rule.resolvers.len(), 4, "{}", rule.namespace);
            assert!(rule.resolvers.iter().any(|a| a.family() == AddressFamily::V4));
            assert!(rule.resolvers.iter().any(|a| a.family() == AddressFamily::V6));
        }
    }

    #[test]
    fn the_interface_settings_name_both_families() {
        // `SetInterfaceDnsSettings` takes one family per call, which is exactly
        // the shape that lets a v6 configuration be forgotten.
        let programme = render(&config(&[], true), OVERLAY, &stub()).expect("renders");
        assert!(!programme
            .interface
            .resolvers
            .get(AddressFamily::V4)
            .is_empty());
        assert!(!programme
            .interface
            .resolvers
            .get(AddressFamily::V6)
            .is_empty());
        programme.validate().expect("valid");
    }

    #[test]
    fn a_one_family_interface_configuration_is_refused() {
        let mut programme = render(&config(&[], true), OVERLAY, &stub()).expect("renders");
        programme.interface.resolvers.get_mut(AddressFamily::V6).clear();
        assert!(matches!(
            programme.validate().expect_err("refused"),
            DnsDefect::FamilyAsymmetry { v6: 0, .. }
        ));
    }

    #[test]
    fn dn9_suffix_matching_is_whole_label_and_case_insensitive() {
        assert_eq!(suffix_namespace("Corp.Example"), ".corp.example");
        assert_eq!(suffix_namespace(".corp.example"), ".corp.example");
        assert_eq!(suffix_namespace("corp.example."), ".corp.example");
        // Two spellings of one namespace must produce one rule id, or the host
        // ends up with two rules for one namespace and DN-8's conflict is
        // self-inflicted.
        assert_eq!(
            rule_id(&suffix_namespace("CORP.example")),
            rule_id(&suffix_namespace("corp.EXAMPLE"))
        );
    }

    #[test]
    fn two_spellings_of_one_domain_produce_one_rule() {
        let programme = render(
            &config(&["corp.example", "CORP.EXAMPLE", "corp.example."], false),
            OVERLAY,
            &stub(),
        )
        .expect("renders");
        assert_eq!(programme.rules.len(), 1);
        programme.validate().expect("no self-inflicted conflict");
    }

    #[test]
    fn a_malformed_namespace_is_refused_rather_than_written() {
        for bad in ["", ".", "..", ".a..b", ".a b", "corp.example"] {
            let programme = DnsProgramme {
                rules: vec![NrptRule {
                    id: format!("{RULE_PREFIX}x"),
                    namespace: bad.to_owned(),
                    resolvers: Vec::new(),
                    dnssec_validation: true,
                }],
                interface: InterfaceDns {
                    luid: OVERLAY,
                    resolvers: PerFamily::new(Vec::new(), Vec::new()),
                    search_list: Vec::new(),
                    register_adapter_name: false,
                },
            };
            let verdict = programme.validate();
            if bad == "." {
                assert!(verdict.is_ok(), "the FULL-mode rule is well formed");
            } else {
                assert!(matches!(
                    verdict.expect_err("refused"),
                    DnsDefect::MalformedNamespace(_)
                ));
            }
        }
    }

    #[test]
    fn a_third_partys_rule_is_never_written_and_never_deleted() {
        // A domain policy or an MDM profile owns rules we must leave alone.
        let foreign = NrptRule {
            id: "DomainPolicy-corp".to_owned(),
            namespace: ".corp.example".to_owned(),
            resolvers: Vec::new(),
            dnssec_validation: false,
        };
        let desired = render(&config(&["tnet.twinvpn.net"], false), OVERLAY, &stub())
            .expect("renders");
        let plan = plan(std::slice::from_ref(&foreign), &desired);
        plan.validate().expect("valid");
        assert!(plan.rule_deletes.is_empty(), "not ours to remove");
        assert!(!plan.rule_writes.iter().any(|r| r.id == foreign.id));
    }

    #[test]
    fn a_plan_that_would_delete_a_foreign_rule_is_refused() {
        let plan = DnsPlan {
            rule_writes: Vec::new(),
            rule_deletes: vec!["DomainPolicy-corp".to_owned()],
            interface: None,
        };
        assert!(matches!(
            plan.validate().expect_err("refused"),
            DnsDefect::ForeignRule(_)
        ));
    }

    #[test]
    fn re_applying_the_same_programme_writes_nothing() {
        let desired = render(&config(&["corp.example"], true), OVERLAY, &stub()).expect("renders");
        let plan = plan(&desired.rules, &desired);
        assert!(plan.rule_writes.is_empty());
        assert!(plan.rule_deletes.is_empty());
    }

    #[test]
    fn d7_the_restore_removes_our_rules_and_puts_back_exactly_what_was_there() {
        // The Windows-specific defect ADR-0011 §11.7 names: NRPT is
        // registry-persistent and does not die with the tunnel object.
        let prior_interface = InterfaceDns {
            luid: OVERLAY,
            resolvers: PerFamily::new(
                vec![IpAddr::V4(V4Addr::from_octets([192, 168, 1, 1]))],
                Vec::new(),
            ),
            search_list: vec!["lan".to_owned()],
            register_adapter_name: true,
        };
        let point = RestorePoint {
            prior_rules: vec![NrptRule {
                id: "DomainPolicy-corp".to_owned(),
                namespace: ".corp.example".to_owned(),
                resolvers: Vec::new(),
                dnssec_validation: false,
            }],
            prior_interface: prior_interface.clone(),
            restore_token: 42,
        };
        let desired = render(&config(&["tnet.twinvpn.net"], true), OVERLAY, &stub())
            .expect("renders");
        let restore = restore_plan(&point, &desired.ids());
        restore.validate().expect("valid");
        assert_eq!(restore.rule_deletes.len(), desired.rules.len());
        assert!(
            restore.rule_writes.is_empty(),
            "the only prior rule was somebody else's and was never removed"
        );
        assert_eq!(restore.interface.as_ref(), Some(&prior_interface));
    }

    #[test]
    fn a_rule_of_ours_that_predated_this_generation_is_restored_not_dropped() {
        let ours_before = NrptRule {
            id: rule_id(".legacy.example"),
            namespace: ".legacy.example".to_owned(),
            resolvers: Vec::new(),
            dnssec_validation: true,
        };
        let point = RestorePoint {
            prior_rules: vec![ours_before.clone()],
            prior_interface: InterfaceDns {
                luid: OVERLAY,
                resolvers: PerFamily::new(Vec::new(), Vec::new()),
                search_list: Vec::new(),
                register_adapter_name: false,
            },
            restore_token: 1,
        };
        let current = vec![rule_id(".corp.example"), ours_before.id.clone()];
        let restore = restore_plan(&point, &current);
        assert_eq!(restore.rule_writes, vec![ours_before.clone()]);
        assert_eq!(restore.rule_deletes, vec![rule_id(".corp.example")]);
    }

    #[test]
    fn an_over_cap_input_is_a_typed_reject_and_never_a_truncation() {
        // `ownership.md` §6 rule 9: validated against `limits.json` BEFORE any
        // allocation proportional to the declared length.
        let mut over = config(&[], false);
        over.split_domains = (0..=MAX_SPLIT_DOMAIN_RULES)
            .map(|i| format!("d{i}.example"))
            .collect();
        let err = render(&over, OVERLAY, &stub()).expect_err("refused");
        assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");

        let mut long = config(&[], false);
        long.split_domains = vec!["a".repeat(MAX_DOMAIN_NAME_BYTES + 1)];
        assert!(render(&long, OVERLAY, &stub()).is_err());

        let mut many = config(&[], false);
        many.search_domains = (0..=MAX_SEARCH_DOMAINS).map(|i| format!("s{i}")).collect();
        assert!(render(&many, OVERLAY, &stub()).is_err());

        // Exactly at the cap is accepted.
        let mut exact = config(&[], false);
        exact.split_domains = (0..MAX_SPLIT_DOMAIN_RULES)
            .map(|i| format!("d{i}.example"))
            .collect();
        assert!(render(&exact, OVERLAY, &stub()).is_ok());
    }

    #[test]
    fn the_overlay_adapter_never_registers_its_name_in_dns() {
        let programme = render(&config(&[], true), OVERLAY, &stub()).expect("renders");
        assert!(!programme.interface.register_adapter_name);
    }

    #[test]
    fn every_rule_id_carries_the_owner_tag() {
        let programme = render(&config(&["a.example", "b.example"], true), OVERLAY, &stub())
            .expect("renders");
        for id in programme.ids() {
            assert!(id.starts_with(RULE_PREFIX), "{id}");
            assert!(!id.contains('\\'), "a registry subkey may not contain one");
        }
    }
}
