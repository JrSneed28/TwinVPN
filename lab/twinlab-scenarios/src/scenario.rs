//! §3.6's scenario document, as a type.
//!
//! **Authority:** `docs/testing-strategy.md` §3.6 (the document and the ID
//! grammar), §3.5 rule **L-2**, §3.7 rule **L-5**, §6.1 rule **C-2**.

use twinlab::capability::{Facility, HostCapabilities};
use twinlab::determinism::{Class, Tier};
use twinlab::error::LabError;
use twinlab::impair::ImpairmentSet;
use twinlab::nat::{Personality, PortMap};
use twinlab::outcome::{OutcomeClass, Verdict};

/// §3.6's `FAMILY` component of the scenario ID grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScenarioFamily {
    /// NAT traversal (§2.10, §3.3).
    Nat,
    /// Networking: addressing, routing, MTU (§2.9).
    Net,
    /// DNS (ADR-0011).
    Dns,
    /// Kill switch and leak prevention (ADR-0012).
    Ks,
    /// Relay selection, health, failover (§2 level 11).
    Relay,
    /// Gateway and `ExitNode`.
    Gw,
    /// Pairing, trust, revocation.
    Auth,
    /// Wire-format and version negotiation.
    Proto,
    /// Control-plane availability and consistency.
    Cp,
    /// Pre-flight conflict detection (§2.9's `S-COLL-*`).
    Coll,
    /// Performance.
    Perf,
    /// Soak.
    Soak,
}

impl ScenarioFamily {
    /// The §3.6 spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            ScenarioFamily::Nat => "NAT",
            ScenarioFamily::Net => "NET",
            ScenarioFamily::Dns => "DNS",
            ScenarioFamily::Ks => "KS",
            ScenarioFamily::Relay => "RELAY",
            ScenarioFamily::Gw => "GW",
            ScenarioFamily::Auth => "AUTH",
            ScenarioFamily::Proto => "PROTO",
            ScenarioFamily::Cp => "CP",
            ScenarioFamily::Coll => "COLL",
            ScenarioFamily::Perf => "PERF",
            ScenarioFamily::Soak => "SOAK",
        }
    }

    /// Every family §3.6's grammar admits, so a new one cannot be introduced by
    /// a typo in an id.
    pub const ALL: [ScenarioFamily; 12] = [
        ScenarioFamily::Nat,
        ScenarioFamily::Net,
        ScenarioFamily::Dns,
        ScenarioFamily::Ks,
        ScenarioFamily::Relay,
        ScenarioFamily::Gw,
        ScenarioFamily::Auth,
        ScenarioFamily::Proto,
        ScenarioFamily::Cp,
        ScenarioFamily::Coll,
        ScenarioFamily::Perf,
        ScenarioFamily::Soak,
    ];
}

/// §3.6's `family` axis. **L-5 requires every family to be instantiated for all
/// of these**, so this is an enum rather than a flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    /// IPv4 only.
    V4Only,
    /// IPv6 only.
    V6Only,
    /// Dual stack.
    Dual,
    /// v6-only access with NAT64/DNS64.
    Nat64,
}

impl Family {
    /// The §3.6 spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Family::V4Only => "v4-only",
            Family::V6Only => "v6-only",
            Family::Dual => "dual",
            Family::Nat64 => "nat64",
        }
    }

    /// The three L-5 requires of every scenario family. NAT64 is separate
    /// because L-5 qualifies it with "where the personality supports it".
    pub const REQUIRED: [Family; 3] = [Family::V4Only, Family::V6Only, Family::Dual];

    /// The short id component, for §3.6's ID grammar.
    #[must_use]
    pub const fn id_component(self) -> &'static str {
        match self {
            Family::V4Only => "V4",
            Family::V6Only => "V6",
            Family::Dual => "DUAL",
            Family::Nat64 => "NAT64",
        }
    }
}

/// One site in §3.6's `[topology]` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Site {
    /// The site id (`"a"`, `"b"`).
    pub id: &'static str,
    /// The NAT personality.
    pub nat: Personality,
    /// The mapping lifetime, seconds.
    pub lifetime_s: u32,
    /// Whether hairpinning is on.
    pub hairpin: bool,
    /// Which port-mapping protocol the middlebox offers.
    pub portmap: PortMap,
}

/// A §3.6 scenario.
#[derive(Debug, Clone)]
pub struct Scenario {
    /// `S-<FAMILY>-<SUBJECT>-<VARIANT>-<NN>`. Permanent: a retired id is never
    /// reused.
    pub id: String,
    /// The family, for the id grammar check.
    pub family: ScenarioFamily,
    /// The declared determinism class.
    pub determinism: Class,
    /// The tiers this scenario runs in.
    pub tiers: Vec<Tier>,
    /// Assumption identifiers this scenario carries (§0).
    pub assumptions: Vec<&'static str>,
    /// Proof tests this scenario contributes to, e.g. `"P02"`.
    pub proves: Vec<&'static str>,
    /// The sites.
    pub sites: Vec<Site>,
    /// The address family axis.
    pub address_family: Family,
    /// The impairment set.
    pub impairment: ImpairmentSet,
    /// The expected outcome class, where the scenario is a traversal one.
    pub expect: Option<OutcomeClass>,
    /// One line saying what this scenario proves that no other one does.
    pub purpose: &'static str,
}

impl Scenario {
    /// Checks everything §3 makes checkable without a rig.
    ///
    /// # Errors
    ///
    /// [`LabError::Mechanism`] for an ID-grammar violation, and
    /// [`LabError::DeterminismClass`] where the declared class is stronger than
    /// the impairments or the tier permits (rules **L-2** and **C-2**).
    pub fn validate(&self) -> Result<(), LabError> {
        let parts: Vec<&str> = self.id.split('-').collect();
        if parts.len() < 4 || parts[0] != "S" {
            return Err(LabError::Mechanism {
                detail: format!(
                    "`{}` does not match §3.6's grammar S-<FAMILY>-<SUBJECT>-<VARIANT>-<NN>",
                    self.id
                ),
            });
        }
        if parts[1] != self.family.name() {
            return Err(LabError::Mechanism {
                detail: format!(
                    "`{}` declares family {} but its id says {}",
                    self.id,
                    self.family.name(),
                    parts[1]
                ),
            });
        }
        let last = parts.last().copied().unwrap_or_default();
        if last.len() != 2 || !last.chars().all(|c| c.is_ascii_digit()) {
            return Err(LabError::Mechanism {
                detail: format!("`{}` must end in a two-digit ordinal", self.id),
            });
        }
        if self.tiers.is_empty() {
            return Err(LabError::Mechanism {
                detail: format!("`{}` runs in no tier, so it gates nothing", self.id),
            });
        }
        for t in &self.tiers {
            if !self.determinism.may_gate_tier(*t) {
                return Err(LabError::DeterminismClass {
                    class: self.determinism.name(),
                    assertion: format!("gating {} (rule C-2)", t.name()),
                });
            }
        }
        self.impairment.check_class(self.determinism)?;
        if self.sites.len() > 2 {
            return Err(LabError::Mechanism {
                detail: format!(
                    "`{}` declares {} sites; §3.6's [topology] table is a pair",
                    self.id,
                    self.sites.len()
                ),
            });
        }
        Ok(())
    }

    /// Everything the host must provide before this scenario can run for real.
    #[must_use]
    pub fn required_facilities(&self) -> Vec<Facility> {
        let mut out = vec![Facility::NetworkNamespaces, Facility::Veth];
        for s in &self.sites {
            for f in s.nat.required_facilities() {
                if !out.contains(&f) {
                    out.push(f);
                }
            }
        }
        for f in self.impairment.required_facilities() {
            if !out.contains(&f) {
                out.push(f);
            }
        }
        if matches!(
            self.address_family,
            Family::V6Only | Family::Dual | Family::Nat64
        ) && !out.contains(&Facility::Ipv6)
        {
            out.push(Facility::Ipv6);
        }
        out
    }

    /// Whether `host` can run this scenario, and the verdict if it cannot.
    ///
    /// # Errors
    ///
    /// [`Verdict::Unavailable`] — an absence of evidence, never a pass and never
    /// a failure. It is an `Err` so a caller cannot ignore it, but it does not
    /// block; see [`Verdict::is_blocking`].
    pub fn runnable_on(&self, host: &HostCapabilities) -> Result<(), Verdict> {
        match host.missing(&self.required_facilities()) {
            None => Ok(()),
            Some(missing) => Err(Verdict::Unavailable {
                missing,
                needed_for: "this scenario's declared personality or impairment set",
            }),
        }
    }

    /// §3.6's document, rendered.
    ///
    /// Rendering rather than parsing is deliberate — see the crate docs. The
    /// output is the checked-in scenario document, so a change here changes what
    /// `lab/scenarios/` must contain.
    #[must_use]
    pub fn to_toml(&self) -> String {
        use core::fmt::Write as _;

        let quoted = |items: &[&str]| {
            items
                .iter()
                .map(|i| format!("{i:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        };

        // Every `write!` into a String is infallible; the results are discarded
        // rather than unwrapped so rendering a document can never panic.
        let mut s = String::new();
        let _ = writeln!(s, "# {}", self.purpose);
        let _ = writeln!(s, "id            = {:?}", self.id);
        let _ = writeln!(s, "determinism   = {:?}", self.determinism.name());
        s.push_str(
            "seed          = \"\"                          # generated and recorded per run\n",
        );
        let tiers: Vec<&str> = self.tiers.iter().map(|t| t.name()).collect();
        let _ = writeln!(s, "tier          = [{}]", quoted(&tiers));
        let _ = writeln!(s, "assumptions   = [{}]", quoted(&self.assumptions));
        let _ = writeln!(s, "proves        = [{}]\n", quoted(&self.proves));

        s.push_str("[topology]\n");
        s.push_str("sites   = [ ");
        s.push_str(
            &self
                .sites
                .iter()
                .map(|site| {
                    format!(
                        "{{ id = {:?}, nat = {:?}, lifetime_s = {}, hairpin = {}, portmap = {:?} }}",
                        site.id,
                        site.nat.name(),
                        site.lifetime_s,
                        site.hairpin,
                        portmap_name(site.portmap)
                    )
                })
                .collect::<Vec<_>>()
                .join(",\n            "),
        );
        s.push_str(" ]\n");
        let _ = writeln!(s, "family  = {:?}", self.address_family.name());
        s.push_str("relays  = { regions = 2, per_region = 2, domains_per_region = 2 }\n\n");

        s.push_str("[impairment]\n");
        for c in &self.impairment.conditions {
            let _ = writeln!(s, "# {c:?}");
        }
        s.push('\n');

        if let Some(e) = self.expect {
            s.push_str("[expect]\n");
            let _ = writeln!(s, "outcome_class = {:?}", e.name());
            if let OutcomeClass::DirectPossible {
                runs,
                min_success_pct,
            } = e
            {
                let _ = writeln!(s, "runs            = {runs}");
                let _ = writeln!(s, "min_success_pct = {min_success_pct}");
            }
        }
        s
    }
}

const fn portmap_name(p: PortMap) -> &'static str {
    match p {
        PortMap::None => "none",
        PortMap::Pcp => "pcp",
        PortMap::NatPmp => "natpmp",
        PortMap::UpnpIgd2 => "upnp-igdv2",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinlab::impair::Impairment;

    fn base() -> Scenario {
        Scenario {
            id: "S-NAT-EIM-EIM-V4-01".to_owned(),
            family: ScenarioFamily::Nat,
            determinism: Class::Statistical,
            tiers: vec![Tier::T2],
            assumptions: vec!["A-01"],
            proves: vec!["P02"],
            sites: vec![
                Site {
                    id: "a",
                    nat: Personality::EimEif,
                    lifetime_s: 120,
                    hairpin: false,
                    portmap: PortMap::None,
                },
                Site {
                    id: "b",
                    nat: Personality::EimApdf,
                    lifetime_s: 30,
                    hairpin: false,
                    portmap: PortMap::None,
                },
            ],
            address_family: Family::V4Only,
            impairment: ImpairmentSet::new(),
            expect: Some(OutcomeClass::DirectExpected),
            purpose: "test",
        }
    }

    #[test]
    fn a_well_formed_scenario_validates() {
        base().validate().expect("valid");
    }

    #[test]
    fn an_id_that_does_not_match_the_grammar_is_refused() {
        for bad in ["NAT-EIM-01", "S-NAT-EIM-1", "S-NAT-EIM-EIM-V4-ONE"] {
            let mut s = base();
            s.id = bad.to_owned();
            assert!(s.validate().is_err(), "`{bad}` must be refused");
        }
    }

    #[test]
    fn an_id_whose_family_disagrees_with_the_declaration_is_refused() {
        let mut s = base();
        s.id = "S-RELAY-EIM-EIM-V4-01".to_owned();
        assert!(s.validate().is_err());
    }

    #[test]
    fn an_exploratory_scenario_may_not_gate_a_merge() {
        let mut s = base();
        s.determinism = Class::Exploratory;
        s.tiers = vec![Tier::T1];
        assert!(s.validate().is_err(), "rule C-2");
        s.tiers = vec![Tier::T3];
        s.validate().expect("T3 is permitted");
    }

    #[test]
    fn a_bit_scenario_carrying_netem_is_refused() {
        let mut s = base();
        s.determinism = Class::Bit;
        s.impairment = ImpairmentSet::new().with(Impairment::Jitter {
            base_ms: 40,
            jitter_ms: 30,
        });
        let err = s.validate().expect_err("rule L-2");
        assert!(err.to_string().contains("STATISTICAL"), "{err}");
    }

    #[test]
    fn a_scenario_names_the_facilities_its_personalities_need() {
        let mut s = base();
        s.address_family = Family::Dual;
        let f = s.required_facilities();
        assert!(f.contains(&Facility::Nftables), "{f:?}");
        assert!(
            f.contains(&Facility::Conntrack),
            "N-EIM-EIF needs the helper"
        );
        assert!(f.contains(&Facility::Ipv6), "a dual scenario needs v6");
    }

    #[test]
    fn a_host_without_a_facility_yields_unavailable_and_not_a_pass() {
        let host = HostCapabilities::probe();
        let s = base();
        if let Err(v) = s.runnable_on(&host) {
            assert!(!v.is_evidence_of_success());
            assert!(!v.is_blocking());
        }
    }

    #[test]
    fn the_rendered_document_carries_the_fields_section_3_6_shows() {
        let t = base().to_toml();
        for needle in [
            "id            = \"S-NAT-EIM-EIM-V4-01\"",
            "determinism   = \"STATISTICAL\"",
            "tier          = [\"T2\"]",
            "family  = \"v4-only\"",
            "outcome_class = \"DIRECT_EXPECTED\"",
            "nat = \"N-EIM-EIF\"",
        ] {
            assert!(t.contains(needle), "missing `{needle}` in:\n{t}");
        }
    }
}
