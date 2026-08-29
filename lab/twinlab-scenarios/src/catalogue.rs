//! The named scenario family, and the NAT-class-pair matrix generated from
//! `docs/networking.md` §3.2.
//!
//! **Authority:** `docs/testing-strategy.md` §2.9 (`S-COLL-*`), §2.10, §3.3,
//! §3.6, §3.7 rule **L-5**.
//!
//! # Determinism, per family, with CD-6's residual stated
//!
//! | Family | Class | Why |
//! |---|---|---|
//! | `S-NAT-*` | `STATISTICAL` | `conntrack` allocation and mapping lifetimes are kernel timers outside every injected provider |
//! | `S-NET-*` | `STATISTICAL` | `netem` and PMTU discovery are kernel-timed |
//! | `S-KS-*` | `BIT` | the enforcement decision is entirely in the core against injected clocks and a mock adapter; only the leak *observation* touches the kernel, and that is a counter comparison, not a duration |
//! | `S-COLL-*` | `BIT` | pre-flight detection is a comparison of two captured host states |
//! | `S-RELAY-*` | `STATISTICAL` | failover timing is measured against a real socket |
//! | `S-CP-*` | `BIT` | the outage story is a guard change, and §9's three-way split is a `Guards` input |
//!
//! `BIT` here means what §3.5 says it means above level 2: **the ordered event
//! sequence and the `reason_code` sequence**, not the timing. No scenario in this
//! catalogue asserts a duration, and [`twinlab::determinism::Class::permits`]
//! refuses one.

use twinlab::determinism::{Class, Tier};
use twinlab::impair::{Impairment, ImpairmentSet};
use twinlab::nat::{expected_class, Personality, PortMap, Traversability, TRAVERSABILITY_MD};

use crate::scenario::{Family, Scenario, ScenarioFamily, Site};

/// Every scenario in the catalogue.
#[must_use]
pub fn all() -> Vec<Scenario> {
    let mut out = nat_class_pair_matrix();
    out.extend(networking_family());
    out.extend(kill_switch_family());
    out.extend(collision_family());
    out.extend(relay_family());
    out.extend(control_plane_family());
    out
}

/// A scenario by id.
#[must_use]
pub fn by_id(id: &str) -> Option<Scenario> {
    all().into_iter().find(|s| s.id == id)
}

/// The families present in the catalogue.
#[must_use]
pub fn families() -> Vec<ScenarioFamily> {
    let mut f: Vec<ScenarioFamily> = all().into_iter().map(|s| s.family).collect();
    f.sort_unstable();
    f.dedup();
    f
}

/// The personalities the class-pair matrix enumerates, in a stable order.
///
/// `N-NAT64` is excluded from the *pair* matrix and carried by its own scenario:
/// it is an access-network property rather than a middlebox pair, and pairing it
/// against itself would assert a cell §3.2 does not contain.
const MATRIX_PERSONALITIES: [Personality; 7] = [
    Personality::Routed,
    Personality::EimEif,
    Personality::EimAdf,
    Personality::EimApdf,
    Personality::ApdmApdfRand,
    Personality::ApdmApdfSeq,
    Personality::Cgnat,
];

/// §2.10's matrix: one scenario per ordered personality pair per address family.
///
/// Rule **L-5**: every pair is instantiated for `v4-only`, `v6-only` and `dual`.
/// The v6 instantiations are not decoration — §3.2's last row is unqualified, so
/// each of them carries a `DIRECT_EXPECTED` expectation with a 100 % budget, and
/// a v4-only regression fails there and nowhere else.
#[must_use]
pub fn nat_class_pair_matrix() -> Vec<Scenario> {
    let matrix = Traversability::parse(TRAVERSABILITY_MD);
    let mut out = Vec::new();
    let mut ordinal = 0u32;
    for local in MATRIX_PERSONALITIES {
        for remote in MATRIX_PERSONALITIES {
            for family in Family::REQUIRED {
                // On a v6-only or dual path both ends have working IPv6, which
                // §3.2's last row makes unconditionally direct — so the pair is
                // evaluated as N-ROUTED x N-ROUTED there. This is the mechanical
                // consequence of §3.2 and is exactly why a v6 regression is
                // visible: these scenarios stop being DIRECT_EXPECTED.
                let (l, r) = match family {
                    Family::V4Only => (local, remote),
                    _ => (Personality::Routed, Personality::Routed),
                };
                let Some(expect) = expected_class(&matrix, l, r, PortMap::None) else {
                    continue;
                };
                ordinal = ordinal % 99 + 1;
                out.push(Scenario {
                    id: format!(
                        "S-NAT-{}-{}-{}-{:02}",
                        short(local),
                        short(remote),
                        family.id_component(),
                        ordinal
                    ),
                    family: ScenarioFamily::Nat,
                    // conntrack allocation and mapping lifetime are kernel
                    // timers; CD-6's residual applies in full.
                    determinism: Class::Statistical,
                    tiers: match expect {
                        twinlab::OutcomeClass::DirectPossible { .. } => vec![Tier::T3],
                        // §6.2: T2 carries the DIRECT_EXPECTED and
                        // RELAY_EXPECTED classes at 5 runs each.
                        _ => vec![Tier::T2, Tier::T3],
                    },
                    assumptions: vec!["A-01", "A-02", "A-14", "A-17"],
                    // The proof test a cell contributes to is decided by its
                    // OUTCOME CLASS, not by the family it belongs to.
                    //
                    // This block used to tag every cell `P02`, which is the tag
                    // §3.6's worked example carries — but that example is
                    // `S-NAT-APDM-APDM-V4-01`, a RELAY_EXPECTED pair, and P02 is
                    // "relays are selected automatically WHEN REQUIRED". A
                    // DIRECT_EXPECTED cell is P01's evidence ("direct tunnels
                    // work when the network permits"), and tagging it P02 pointed
                    // the acceptance register at the wrong proof test for the
                    // large majority of the matrix. Found by the P01-P22 register
                    // cross-check in build/proof/.
                    proves: match expect {
                        twinlab::OutcomeClass::RelayExpected => vec!["P02"],
                        _ => vec!["P01"],
                    },
                    sites: vec![
                        Site {
                            id: "a",
                            nat: local,
                            lifetime_s: 120,
                            hairpin: false,
                            portmap: PortMap::None,
                        },
                        Site {
                            id: "b",
                            nat: remote,
                            lifetime_s: 30,
                            hairpin: false,
                            portmap: PortMap::None,
                        },
                    ],
                    address_family: family,
                    impairment: ImpairmentSet::new().with(Impairment::Latency { ms: 40 }),
                    expect: Some(expect),
                    purpose: "§2.10: the expected outcome CLASS for this ordered NAT pair, \
                              not merely that it connected",
                });
            }
        }
    }
    out
}

fn short(p: Personality) -> &'static str {
    match p {
        Personality::Routed => "ROUTED",
        Personality::EimEif => "EIF",
        Personality::EimAdf => "ADF",
        Personality::EimApdf => "APDF",
        Personality::ApdmApdfRand => "RAND",
        Personality::ApdmApdfSeq => "SEQ",
        Personality::Cgnat => "CGNAT",
        Personality::Nat64 => "NAT64",
    }
}

/// §2.9's networking level: MTU, PMTU black holes, and the interface change.
#[must_use]
pub fn networking_family() -> Vec<Scenario> {
    let sites = || {
        vec![
            Site {
                id: "a",
                nat: Personality::EimApdf,
                lifetime_s: 120,
                hairpin: false,
                portmap: PortMap::None,
            },
            Site {
                id: "b",
                nat: Personality::EimApdf,
                lifetime_s: 120,
                hairpin: false,
                portmap: PortMap::None,
            },
        ]
    };
    let mut out = Vec::new();
    for (n, family) in Family::REQUIRED.into_iter().enumerate() {
        out.push(Scenario {
            id: format!(
                "S-NET-PMTU-BLACKHOLE-{}-{:02}",
                family.id_component(),
                n + 1
            ),
            family: ScenarioFamily::Net,
            determinism: Class::Statistical,
            tiers: vec![Tier::T2, Tier::T3],
            assumptions: vec!["A-01", "A-14"],
            proves: vec![],
            sites: sites(),
            address_family: family,
            impairment: ImpairmentSet::new().with(Impairment::PmtuBlackHole { bytes: 1400 }),
            expect: None,
            purpose: "§2.9: DPLPMTUD converges with ICMP dropped, for BOTH families — a \
                      v4-only PMTU story fails the v6 instantiation",
        });
        out.push(Scenario {
            id: format!("S-NET-ROAM-{}-{:02}", family.id_component(), n + 1),
            family: ScenarioFamily::Net,
            determinism: Class::Statistical,
            tiers: vec![Tier::T3],
            assumptions: vec!["A-01", "A-02", "A-14"],
            proves: vec![],
            sites: sites(),
            address_family: family,
            impairment: ImpairmentSet::new().with(Impairment::InterfaceChange {
                cross_family: family == Family::Dual,
                make_before_break: true,
            }),
            expect: None,
            purpose: "§3.4: a genuine EV_LINK_DOWN/EV_ADDR_CHANGED produced by moving a \
                      veth leg, never by an injected event",
        });
    }
    out
}

/// ADR-0012's kill switch. The leak canary is the target.
#[must_use]
pub fn kill_switch_family() -> Vec<Scenario> {
    Family::REQUIRED
        .into_iter()
        .enumerate()
        .map(|(n, family)| Scenario {
            id: format!("S-KS-FAIL-CLOSED-{}-{:02}", family.id_component(), n + 1),
            family: ScenarioFamily::Ks,
            // The enforcement decision is entirely in the core, against injected
            // clocks and a mock adapter (CD-5). The observation is a deny-counter
            // comparison, not a duration.
            determinism: Class::Bit,
            tiers: vec![Tier::T2, Tier::T3],
            assumptions: vec!["A-02", "A-14"],
            proves: vec!["P09"],
            sites: vec![Site {
                id: "a",
                nat: Personality::EimApdf,
                lifetime_s: 120,
                hairpin: false,
                portmap: PortMap::None,
            }],
            address_family: family,
            impairment: ImpairmentSet::new(),
            expect: None,
            purpose: "ADR-0012: protected traffic never leaves untunneled while fail-closed \
                      is active, asserted per family with the canary's positive control \
                      green in the same session (B-7)",
        })
        .collect()
}

/// §2.9's `S-COLL-*` family — the one family permitted the overlay/underlay
/// collision, because reproducing it is its entire purpose.
#[must_use]
pub fn collision_family() -> Vec<Scenario> {
    [
        (
            "ADDR",
            "a foreign interface already holds an address inside the TwinNet prefix",
        ),
        (
            "IFACE",
            "another product holds an adapter with our naming/owner tag",
        ),
        (
            "RULE",
            "a pre-existing policy-routing rule sits at our priority",
        ),
    ]
    .into_iter()
    .enumerate()
    .flat_map(|(n, (subject, why))| {
        Family::REQUIRED.into_iter().map(move |family| Scenario {
            id: format!("S-COLL-{subject}-{}-{:02}", family.id_component(), n + 1),
            family: ScenarioFamily::Coll,
            // Rule COLL-1 compares two captured host states; nothing here is timed.
            determinism: Class::Bit,
            tiers: vec![Tier::T2, Tier::T3],
            assumptions: vec!["A-02"],
            proves: vec![],
            sites: vec![Site {
                id: "a",
                nat: Personality::EimApdf,
                lifetime_s: 120,
                hairpin: false,
                portmap: PortMap::None,
            }],
            address_family: family,
            impairment: ImpairmentSet::new(),
            expect: None,
            purpose: why,
        })
    })
    .collect()
}

/// Relay selection, failover and the whole-region case.
#[must_use]
pub fn relay_family() -> Vec<Scenario> {
    Family::REQUIRED
        .into_iter()
        .enumerate()
        .map(|(n, family)| Scenario {
            id: format!("S-RELAY-FAILOVER-{}-{:02}", family.id_component(), n + 1),
            family: ScenarioFamily::Relay,
            // The failover budget is a wall-clock measurement against a real
            // socket, so the timing half is STATISTICAL by construction.
            determinism: Class::Statistical,
            tiers: vec![Tier::T2, Tier::T3],
            assumptions: vec!["A-01", "A-02", "A-14"],
            // This family's own doc comment says "relay selection, failover and
            // the whole-region case", which is P02 and P03. It was tagged `P05`,
            // and P05 is path migration — a different proof test with a different
            // injection and a different oracle. The two are easy to confuse
            // because A-01 makes both of them transit `MIGRATING`, but §2.13 maps
            // "kill the in-use relay process" to P03 and nothing here roams a
            // path. Found by the P01-P22 register cross-check in build/proof/.
            proves: vec!["P02", "P03"],
            sites: vec![
                Site {
                    id: "a",
                    nat: Personality::Cgnat,
                    lifetime_s: 30,
                    hairpin: false,
                    portmap: PortMap::None,
                },
                Site {
                    id: "b",
                    nat: Personality::Cgnat,
                    lifetime_s: 30,
                    hairpin: false,
                    portmap: PortMap::None,
                },
            ],
            address_family: family,
            impairment: ImpairmentSet::new(),
            expect: Some(twinlab::OutcomeClass::RelayExpected),
            purpose: "§2 level 11: a relay loss migrates rather than dropping the Session, \
                      and no peer-pair record is retained",
        })
        .collect()
}

/// §9's control-plane outage — invariant **I5** and proof test **P15**.
#[must_use]
pub fn control_plane_family() -> Vec<Scenario> {
    Family::REQUIRED
        .into_iter()
        .enumerate()
        .map(|(n, family)| Scenario {
            id: format!("S-CP-OUTAGE-{}-{:02}", family.id_component(), n + 1),
            family: ScenarioFamily::Cp,
            // §9's three-way split is a Guards input; the machine's response is
            // an event sequence with every clock injected.
            determinism: Class::Bit,
            tiers: vec![Tier::T2, Tier::T3],
            assumptions: vec!["A-02", "A-14", "A-18"],
            proves: vec!["P15"],
            sites: vec![
                Site {
                    id: "a",
                    nat: Personality::EimApdf,
                    lifetime_s: 120,
                    hairpin: false,
                    portmap: PortMap::None,
                },
                Site {
                    id: "b",
                    nat: Personality::EimApdf,
                    lifetime_s: 120,
                    hairpin: false,
                    portmap: PortMap::None,
                },
            ],
            address_family: family,
            impairment: ImpairmentSet::new(),
            expect: None,
            purpose: "I5: a control-plane outage never prevents re-establishing a session \
                      with a known TrustedPeer; cp, rz and rs are blackholed independently \
                      and together",
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_scenario_in_the_catalogue_validates() {
        for s in all() {
            s.validate()
                .unwrap_or_else(|e| panic!("{} is invalid: {e}", s.id));
        }
    }

    #[test]
    fn every_scenario_id_is_unique_and_permanent() {
        // §3.6: "IDs are permanent: a retired scenario's ID is never reused."
        // A duplicate today is a collision that would silently merge two runs.
        let ids: Vec<String> = all().into_iter().map(|s| s.id).collect();
        let unique: BTreeSet<&String> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "duplicate scenario ids");
    }

    #[test]
    fn rule_l_5_every_family_is_instantiated_for_all_three_address_families() {
        let scenarios = all();
        for family in families() {
            for af in Family::REQUIRED {
                assert!(
                    scenarios
                        .iter()
                        .any(|s| s.family == family && s.address_family == af),
                    "family {} has no {} instantiation; L-5 fails such a family at \
                     review, and a v4-only story is exactly what ADR-0010 R1 forbids",
                    family.name(),
                    af.name()
                );
            }
        }
    }

    #[test]
    fn the_pair_matrix_covers_every_ordered_personality_pair() {
        let m = nat_class_pair_matrix();
        for a in MATRIX_PERSONALITIES {
            for b in MATRIX_PERSONALITIES {
                assert!(
                    m.iter().any(|s| s.sites.len() == 2
                        && s.sites[0].nat == a
                        && s.sites[1].nat == b
                        && s.address_family == Family::V4Only),
                    "no v4 scenario for {} x {}",
                    a.name(),
                    b.name()
                );
            }
        }
        // 7 x 7 ordered pairs x 3 address families.
        assert_eq!(m.len(), 7 * 7 * 3);
    }

    #[test]
    fn every_ipv6_instantiation_expects_a_direct_path() {
        // networking.md §3.2's last row is unqualified and §3.6 gives it a 100%
        // budget. This is the assertion a v4-only regression fails.
        for s in nat_class_pair_matrix()
            .iter()
            .filter(|s| s.address_family != Family::V4Only)
        {
            assert_eq!(
                s.expect,
                Some(twinlab::OutcomeClass::DirectExpected),
                "{} is not DIRECT_EXPECTED",
                s.id
            );
        }
    }

    #[test]
    fn the_relay_by_design_pairs_are_present_and_expect_a_relay() {
        let m = nat_class_pair_matrix();
        let hard = m.iter().filter(|s| {
            s.address_family == Family::V4Only
                && matches!(
                    (s.sites[0].nat, s.sites[1].nat),
                    (Personality::Cgnat, Personality::Cgnat)
                        | (Personality::ApdmApdfRand, Personality::ApdmApdfRand)
                )
        });
        let mut n = 0;
        for s in hard {
            assert_eq!(
                s.expect,
                Some(twinlab::OutcomeClass::RelayExpected),
                "{}",
                s.id
            );
            n += 1;
        }
        assert!(n >= 2, "the two hard cells must both be present");
    }

    #[test]
    fn no_scenario_declares_bit_while_carrying_a_kernel_prng_impairment() {
        // §3.5 rule L-2, over the whole catalogue rather than one scenario.
        for s in all() {
            if matches!(s.determinism, Class::Bit) {
                assert_eq!(
                    s.impairment.achievable_class(),
                    Class::Bit,
                    "{} declares BIT while carrying {:?}",
                    s.id,
                    s.impairment.conditions
                );
            }
        }
    }

    #[test]
    fn every_nat_scenario_carries_an_expected_outcome_class() {
        // §2.10's whole point: asserting "it connected" is what this level must
        // never do.
        for s in all().iter().filter(|s| s.family == ScenarioFamily::Nat) {
            assert!(s.expect.is_some(), "{} asserts no outcome class", s.id);
        }
    }

    #[test]
    fn the_collision_family_is_the_only_one_permitted_the_overlay_underlay_overlap() {
        // A structural assertion about the catalogue, paired with
        // twinlab::addressing's runtime one.
        let coll: Vec<_> = all()
            .into_iter()
            .filter(|s| s.family == ScenarioFamily::Coll)
            .collect();
        assert_eq!(coll.len(), 9, "three subjects x three address families");
        assert!(coll.iter().all(|s| s.id.starts_with("S-COLL-")));
    }

    #[test]
    fn every_scenario_renders_a_document_that_names_its_class_and_tier() {
        for s in all() {
            let t = s.to_toml();
            assert!(t.contains(s.determinism.name()), "{}", s.id);
            assert!(t.contains(&format!("id            = {:?}", s.id)));
            assert!(!s.tiers.is_empty());
        }
    }
}
