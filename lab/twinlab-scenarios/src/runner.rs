//! Executing a scenario, and refusing to pretend one was executed.
//!
//! **Authority:** `docs/testing-strategy.md` §3.1, §3.4.2 (rule **L-1**), §3.6.
//!
//! # Why there was no `run`, and what changed
//!
//! This crate's CLI deliberately had no `run` subcommand, and the reason was
//! correct: `ip netns add` needs `CAP_NET_ADMIN`, every §3.3 personality was
//! realized by `nftables`, this host has neither, and *a `run` that printed a
//! green line would be exactly the lie §3.1 exists to prevent*.
//!
//! Two of those three facts have changed, and one has not:
//!
//! - `twinnet::agent` unshares a user namespace and holds the full capability
//!   set inside it, so named namespaces exist without privilege.
//! - `twinnet::nat` is a second realization of every personality, so `nftables`
//!   is one way to have them rather than the only way.
//! - **Nothing has changed about what a host that cannot produce a condition
//!   must report.** [`Execution::Unavailable`] is that answer, and
//!   [`Execution::NotExecutable`] is the other one — a family this runner has no
//!   procedure for. Neither is a pass, and the CLI prints them differently from
//!   one, because "the laboratory declined" and "the product succeeded" must
//!   never be spelled the same way.
//!
//! # Rule L-1 is enforced here, not documented here
//!
//! > No traversal, leak, or relay test may run against a personality that has
//! > not passed its conformance suite **in the same lab instantiation, on the
//! > same day**.
//!
//! [`run`] runs [`conformance`] for both of a scenario's personalities *in the
//! rig it is about to use*, before it punches anything. A personality that fails
//! makes the run [`Execution::Void`] — not `Fail`, because a result taken from a
//! middlebox that is not what it claims is evidence of nothing.

use twinlab::nat::{Personality, Realization};
use twinlab::OutcomeClass;
use twinnet::nat::config::{Filtering, Mapping};
use twinnet::prober::{self, Behaviour, Report};
use twinnet::rigs;
use twinnet::NetError;

use crate::scenario::{Family, Scenario, ScenarioFamily};

/// What happened when a scenario was asked to run.
#[derive(Debug)]
pub enum Execution {
    /// The scenario ran and its oracle held.
    Pass {
        /// Everything observed, in order.
        evidence: Vec<String>,
    },
    /// The scenario ran and its oracle did not hold.
    Fail {
        /// What §3.2 expected.
        expected: String,
        /// What was observed.
        observed: String,
        /// Everything observed, in order.
        evidence: Vec<String>,
    },
    /// This host cannot produce the condition. **Never a pass.**
    Unavailable {
        /// What is missing, with the evidence of its absence.
        detail: String,
    },
    /// A middlebox failed its §3.4.2 conformance suite, so any result taken
    /// from it is evidence of nothing (**B-15**, rule **L-1**).
    Void {
        /// Which axis disagreed.
        disagreements: Vec<String>,
    },
    /// This runner has no procedure for the scenario's family.
    ///
    /// Distinct from [`Execution::Unavailable`], and the distinction is the
    /// point: "this host lacks nftables" and "nobody has written the DNS
    /// family's procedure yet" are different problems with different owners,
    /// and collapsing them would hide the second one behind the first for ever.
    NotExecutable {
        /// The family.
        family: &'static str,
        /// What would have to exist.
        needs: String,
    },
}

impl Execution {
    /// Whether this is evidence the scenario's oracle held. Only `Pass` is.
    #[must_use]
    pub const fn is_evidence_of_success(&self) -> bool {
        matches!(self, Execution::Pass { .. })
    }

    /// The one-word status a report prints.
    #[must_use]
    pub const fn status(&self) -> &'static str {
        match self {
            Execution::Pass { .. } => "PASS",
            Execution::Fail { .. } => "FAIL",
            Execution::Unavailable { .. } => "UNAVAILABLE",
            Execution::Void { .. } => "VOID",
            Execution::NotExecutable { .. } => "NOT-EXECUTABLE",
        }
    }
}

/// The `received` count out of a `udp-send` report.
///
/// One type at module level rather than a local `struct R` at each call site:
/// clippy is right that items after statements are confusing, and three copies
/// of a two-field struct were three places for the field name to drift from the
/// JSON `twinnet` actually emits.
#[derive(serde::Deserialize)]
struct Received {
    received: u32,
}

/// How many datagrams came back, or zero if the report was undecodable.
fn received(stdout: &str) -> u32 {
    serde_json::from_str::<Received>(stdout.trim()).map_or(0, |r| r.received)
}

/// Maps §3.3's personality onto the two independent axes the middlebox takes.
#[must_use]
pub fn axes(p: Personality) -> Option<(Mapping, Filtering)> {
    let mapping = match p.mapping() {
        twinlab::nat::Mapping::None => Mapping::None,
        twinlab::nat::Mapping::EndpointIndependent => Mapping::EndpointIndependent,
        twinlab::nat::Mapping::AddressPortDependentRandom => Mapping::AddressPortDependentRandom,
        twinlab::nat::Mapping::AddressPortDependentSequential => {
            Mapping::AddressPortDependentSequential
        }
    };
    let filtering = match p.filtering() {
        twinlab::nat::Filtering::None => Filtering::None,
        twinlab::nat::Filtering::EndpointIndependent => Filtering::EndpointIndependent,
        twinlab::nat::Filtering::AddressDependent => Filtering::AddressDependent,
        twinlab::nat::Filtering::AddressPortDependent => Filtering::AddressPortDependent,
    };
    // `N-NAT64` is a family translation, and the userspace middlebox does not
    // translate families. Refusing it here is what keeps a NAT64 scenario from
    // being silently run as a router.
    if p == Personality::Nat64 {
        return None;
    }
    Some((mapping, filtering))
}

/// What the prober should report for a personality, if the middlebox is what it
/// claims.
#[must_use]
fn expected_behaviour(p: Personality) -> (Behaviour, Behaviour) {
    let mapping = match p.mapping() {
        twinlab::nat::Mapping::None => Behaviour::None,
        twinlab::nat::Mapping::EndpointIndependent => Behaviour::EndpointIndependent,
        _ => Behaviour::AddressPortDependent,
    };
    let filtering = match p.filtering() {
        // A router filters nothing, which a prober observes as
        // endpoint-independent: every source reaches it.
        twinlab::nat::Filtering::None | twinlab::nat::Filtering::EndpointIndependent => {
            Behaviour::EndpointIndependent
        }
        twinlab::nat::Filtering::AddressDependent => Behaviour::AddressDependent,
        twinlab::nat::Filtering::AddressPortDependent => Behaviour::AddressPortDependent,
    };
    (mapping, filtering)
}

/// §3.4.2's NAT64 conformance row, which asks a different question from every
/// other personality's.
///
/// > | NAT64 | A v4-literal destination is reachable from a v6-only client via
/// > the synthesized prefix, and `PREF64`-off forces the RFC 7050 path |
///
/// RFC 5780's mapping and filtering probes do not apply: they measure a
/// translator within one address family, and this one is between two. So this
/// runs the two assertions the row actually names, and the negative control that
/// makes them mean something — with both discovery paths off, the client must
/// **not** get there.
///
/// # Errors
///
/// [`NetError::Unavailable`] when this host cannot build the rig.
pub fn nat64_conformance() -> Result<(bool, Vec<String>), NetError> {
    let mut evidence = Vec::new();
    let mut ok = true;

    // 1. The synthesized-AAAA path.
    let synthesized = nat64_probe("conformance-nat64-synth", true, true, false, "aaaa")?;
    evidence.push(format!(
        "synthesized AAAA: reachable={} target={} prefix={}",
        synthesized.reachable,
        synthesized.target.as_deref().unwrap_or("-"),
        synthesized.pref64.as_deref().unwrap_or("-")
    ));
    ok &= synthesized.reachable;

    // 2. PREF64 absent forces RFC 7050 — and, first, that PREF64 really is
    //    absent, or the fallback would be measuring the ordinary path.
    let without = nat64_probe("conformance-nat64-rfc7050", false, true, false, "aaaa")?;
    if without.reachable {
        ok = false;
        evidence.push(
            "PREF64-off: the destination was still reachable without RFC 7050, so the \
             synthesis was not actually switched off"
                .to_owned(),
        );
    } else {
        evidence.push("PREF64-off: the ordinary path correctly fails".to_owned());
    }
    let fallback = nat64_probe("conformance-nat64-rfc7050b", false, true, false, "rfc7050")?;
    evidence.push(format!(
        "RFC 7050 fallback: reachable={} prefix={}",
        fallback.reachable,
        fallback.pref64.as_deref().unwrap_or("-")
    ));
    ok &= fallback.reachable;

    // 3. The negative control.
    let neither = nat64_probe("conformance-nat64-neither", false, false, false, "rfc7050")?;
    if neither.reachable {
        ok = false;
        evidence.push(
            "negative control: with NEITHER discovery path the client still got there, so \
             the rig lets everything through and the two results above mean nothing"
                .to_owned(),
        );
    } else {
        evidence.push("negative control: with neither path, correctly unreachable".to_owned());
    }

    // 4. RFC 8781 PREF64 in Router Advertisements — the path
    //    `docs/networking.md` §3.8 PREFERS. Exercised with BOTH DNS mechanisms
    //    switched off, so a success can only have come off the wire.
    let ra = nat64_probe("conformance-nat64-ra", false, false, true, "ra")?;
    evidence.push(format!(
        "RFC 8781 (both DNS paths off): reachable={} prefix={}",
        ra.reachable,
        ra.pref64.as_deref().unwrap_or("-")
    ));
    ok &= ra.reachable;

    Ok((ok, evidence))
}

fn nat64_probe(
    label: &str,
    synthesize: bool,
    rfc7050_zone: bool,
    advertise_ra: bool,
    discover: &str,
) -> Result<twinnet::dns64::Nat64Report, NetError> {
    let mut rig = rigs::build_nat64_site(label, synthesize, rfc7050_zone, advertise_ra)?;
    let cfg = rigs::nat64_config(&rig);
    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    let started = fabric.start_nat(&mut rig.sb, "nat64", &cfg);
    rig.fabric = fabric;
    started?;
    rigs::settle();

    let agent = rig.sb.agent_path().display().to_string();
    let resolver = format!("[{}]:53", rigs::NAT64_RESOLVER_V6);
    let argv = vec![
        agent.as_str(),
        "nat64-probe",
        "--resolver",
        &resolver,
        "--name",
        rigs::NAT64_NAME,
        "--port",
        "9",
        "--wait-ms",
        "700",
        "--discover",
        discover,
        "--iface",
        "lan",
    ];
    let ran = rig.sb.run(Some("client6"), &argv)?;
    serde_json::from_str(ran.stdout.trim()).map_err(|e| {
        NetError::Agent(format!(
            "the NAT64 probe's report was undecodable ({e}): {}",
            ran.stdout
        ))
    })
}

/// §3.4.2's NAT-personality conformance suite, run against a real middlebox by
/// a prober that is not TwinVPN code.
///
/// # Errors
///
/// [`NetError::Unavailable`] when this host cannot build the rig at all.
pub fn conformance(p: Personality) -> Result<(Report, Vec<String>), NetError> {
    let Some((mapping, filtering)) = axes(p) else {
        return Err(NetError::Unavailable {
            facility: "nat64",
            detail: format!(
                "`{}` is not measured by an RFC 5780 mapping/filtering prober, which works \
                 within one address family; see `nat64_conformance` for the row §3.4.2 \
                 actually specifies for it",
                p.name()
            ),
        });
    };
    let label = format!("conformance-{}", p.name().to_lowercase());
    let mut rig = rigs::build_single_site(&label, false)?;
    let mut cfg = rigs::single_site_nat(
        &rig,
        &rigs::Personality {
            name: leak_name(p),
            mapping,
            filtering,
        },
    );
    p.name().clone_into(&mut cfg.personality);
    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    let started = fabric.start_nat(&mut rig.sb, "cpe", &cfg);
    rig.fabric = fabric;
    started?;
    rigs::settle();

    let agent = rig.sb.agent_path().display().to_string();
    let port_a = rigs::PORT_A.to_string();
    let port_b = rigs::PORT_B.to_string();
    let ran = rig.sb.run(
        Some("client"),
        &[
            &agent,
            "probe",
            "--primary",
            rigs::REFLECT_A,
            "--alternate",
            rigs::REFLECT_B,
            "--port-a",
            &port_a,
            "--port-b",
            &port_b,
            "--wait-ms",
            "700",
        ],
    )?;
    let report: Report = serde_json::from_str(ran.stdout.trim()).map_err(|e| {
        NetError::Agent(format!(
            "the prober's report was undecodable ({e}): {}",
            ran.stdout
        ))
    })?;
    let (want_mapping, want_filtering) = expected_behaviour(p);
    let disagreements = prober::disagreements(want_mapping, want_filtering, &report);
    Ok((report, disagreements))
}

/// A `'static` name for a personality, which the rig's `Personality` wants.
fn leak_name(p: Personality) -> &'static str {
    p.name()
}

/// Runs one scenario.
///
/// # Errors
///
/// Never: every failure mode is a variant of [`Execution`], because a runner
/// that returned `Err` for "this host cannot" would leave the caller to decide
/// whether that was a pass.
#[must_use]
pub fn run(scenario: &Scenario) -> Execution {
    match scenario.family {
        ScenarioFamily::Nat => run_nat(scenario),
        ScenarioFamily::Relay => run_relay(scenario),
        ScenarioFamily::Cp => run_cp(scenario),
        ScenarioFamily::Ks => run_ks(scenario),
        ScenarioFamily::Net => run_net(scenario),
        other => Execution::NotExecutable {
            family: other.name(),
            needs: missing_procedure(other),
        },
    }
}

/// What each unimplemented family would need, named specifically.
///
/// A single generic sentence would collapse four different problems into one,
/// and three of them are a missing *mechanism* while the fourth is a missing
/// *mapping*. Those have different owners and different costs, and a reader of a
/// `NOT-EXECUTABLE` line should be told which one they are looking at.
fn missing_procedure(family: ScenarioFamily) -> String {
    match family {
        ScenarioFamily::Coll => "nothing from this crate. `S-COLL-*` compares two captured \
             host states before a tunnel exists; it is in-process work against the real \
             pre-flight detector, not a network scenario, and belongs in tests/."
            .to_owned(),
        other => format!(
            "a procedure for the `{}` family; none is written, and no mechanism for it is \
             known to be missing either.",
            other.name()
        ),
    }
}

/// Installs a scenario's declared personalities on both sites of the two-site
/// rig, after checking rule L-1 on each.
///
/// # Errors
///
/// The [`Execution`] that should be reported instead of running.
fn prepare_two_site(
    scenario: &Scenario,
    label: &str,
) -> std::result::Result<(rigs::Rig, Vec<String>), Execution> {
    let (Some(a), Some(b)) = (scenario.sites.first(), scenario.sites.get(1)) else {
        return Err(Execution::NotExecutable {
            family: scenario.family.name(),
            needs: "two sites; this runner's rig is a pair".to_owned(),
        });
    };
    let (Some(axes_a), Some(axes_b)) = (axes(a.nat), axes(b.nat)) else {
        return Err(Execution::Unavailable {
            detail: format!(
                "`{}` x `{}`: a NAT64 tier is not one of the two personalities this rig \
                 installs",
                a.nat.name(),
                b.nat.name()
            ),
        });
    };

    let mut evidence = vec![format!(
        "realization: {}",
        Realization::UserspaceMiddlebox.name()
    )];
    for p in [a.nat, b.nat] {
        match conformance(p) {
            Ok((report, d)) if d.is_empty() => evidence.push(format!(
                "L-1: `{}` passed its §3.4.2 conformance suite (mapping {:?}, filtering {:?})",
                p.name(),
                report.mapping,
                report.filtering
            )),
            Ok((_, disagreements)) => return Err(Execution::Void { disagreements }),
            Err(e) if e.is_unavailable() => {
                return Err(Execution::Unavailable {
                    detail: e.to_string(),
                })
            }
            Err(e) => {
                return Err(Execution::Fail {
                    expected: "a conformance report".to_owned(),
                    observed: e.to_string(),
                    evidence,
                })
            }
        }
    }

    let mut rig = match rigs::build_two_site(label) {
        Ok(rig) => rig,
        Err(e) if e.is_unavailable() => {
            return Err(Execution::Unavailable {
                detail: e.to_string(),
            })
        }
        Err(e) => {
            return Err(Execution::Fail {
                expected: "a two-site rig".to_owned(),
                observed: e.to_string(),
                evidence,
            })
        }
    };
    let named = |p: Personality, ax: (Mapping, Filtering)| rigs::Personality {
        name: p.name(),
        mapping: ax.0,
        filtering: ax.1,
    };
    let cfg_a = rigs::site_nat(&rig, "a", &named(a.nat, axes_a));
    let cfg_b = rigs::site_nat(&rig, "b", &named(b.nat, axes_b));
    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    let started = fabric
        .start_nat(&mut rig.sb, "cpe-a", &cfg_a)
        .and_then(|_| fabric.start_nat(&mut rig.sb, "cpe-b", &cfg_b));
    rig.fabric = fabric;
    if let Err(e) = started {
        return Err(Execution::Fail {
            expected: "two middleboxes".to_owned(),
            observed: e.to_string(),
            evidence,
        });
    }
    rigs::settle();
    Ok((rig, evidence))
}

/// `S-RELAY-FAILOVER-*`: a relay loss migrates rather than dropping the session.
fn run_relay(scenario: &Scenario) -> Execution {
    let label = format!("run-{}", scenario.id.to_lowercase());
    let (mut rig, mut evidence) = match prepare_two_site(scenario, &label) {
        Ok(pair) => pair,
        Err(e) => return e,
    };
    let relays = format!(
        "{}:{},{}:{}",
        rigs::RELAY_EU,
        rigs::RELAY_PORT,
        rigs::RELAY_US,
        rigs::RELAY_PORT
    );

    // The precondition, asserted rather than assumed (V3): failover to a
    // standby means nothing unless the primary was in use first.
    let before = match relayed_pair(&mut rig, &relays, "before") {
        Ok(pair) => pair,
        Err(e) => {
            return Execution::Fail {
                expected: "both legs bound to the primary relay".to_owned(),
                observed: e.to_string(),
                evidence,
            }
        }
    };
    let primary = format!("{}:{}", rigs::RELAY_EU, rigs::RELAY_PORT);
    if before.0.relay.as_deref() != Some(primary.as_str()) {
        return Execution::Fail {
            expected: format!("the primary relay {primary} in use before the failure"),
            observed: format!("{:?}", before.0.relay),
            evidence,
        };
    }
    evidence.push(format!("precondition: both legs bound to {primary}"));

    let Some(handle) = rig.process("relay-eu") else {
        return Execution::Fail {
            expected: "a handle on the primary relay".to_owned(),
            observed: "the rig started none".to_owned(),
            evidence,
        };
    };
    match rig.sb.signal(handle, 9) {
        Ok(true) => evidence.push("the primary relay was terminated (SIGKILL)".to_owned()),
        Ok(false) => {
            return Execution::Fail {
                expected: "a live primary relay to terminate".to_owned(),
                observed: "it was already dead, so killing it proves nothing".to_owned(),
                evidence,
            }
        }
        Err(e) => {
            return Execution::Fail {
                expected: "the signal to be delivered".to_owned(),
                observed: e.to_string(),
                evidence,
            }
        }
    }
    rigs::settle();

    let after = match relayed_pair(&mut rig, &relays, "after") {
        Ok(pair) => pair,
        Err(e) => {
            return Execution::Fail {
                expected: "both legs on the standby".to_owned(),
                observed: e.to_string(),
                evidence,
            }
        }
    };
    let standby = format!("{}:{}", rigs::RELAY_US, rigs::RELAY_PORT);
    evidence.push(format!(
        "after: a bound {:?} attempts {} received {}; b bound {:?} received {}",
        after.0.relay, after.0.attempts, after.0.received, after.1.relay, after.1.received
    ));
    let migrated = after.0.relay.as_deref() == Some(standby.as_str())
        && after.1.relay.as_deref() == Some(standby.as_str())
        && after.0.received > 0
        && after.1.received > 0;
    if migrated {
        Execution::Pass { evidence }
    } else {
        Execution::Fail {
            expected: format!("both legs carried by the standby {standby} with no user action"),
            observed: format!(
                "a: {:?} ({} received), b: {:?} ({} received)",
                after.0.relay, after.0.received, after.1.relay, after.1.received
            ),
            evidence,
        }
    }
}

/// `S-CP-OUTAGE-*`: **I5** — an established session survives the control plane
/// going away.
fn run_cp(scenario: &Scenario) -> Execution {
    let label = format!("run-{}", scenario.id.to_lowercase());
    let (mut rig, mut evidence) = match prepare_two_site(scenario, &label) {
        Ok(pair) => pair,
        Err(e) => return e,
    };
    let reflector = match scenario.address_family {
        Family::V4Only => format!("{}:{}", rigs::REFLECT_A, rigs::PORT_A),
        Family::V6Only | Family::Dual => format!("[{}]:{}", rigs::REFLECT_A6, rigs::PORT_A),
        Family::Nat64 => {
            return Execution::Unavailable {
                detail: "a NAT64 access network is not one of this rig's underlays".to_owned(),
            }
        }
    };
    evidence.push(format!(
        "underlay: {} via {reflector}",
        scenario.address_family.name()
    ));

    // Establish a path, hold it, and destroy the rendezvous WHILE it is held.
    // Killing it during discovery would test something else entirely.
    let killed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (a, b) = match punch_and_hold(&mut rig, &reflector, 3_000, &killed) {
        Ok(pair) => pair,
        Err(e) => {
            return Execution::Fail {
                expected: "two hole-punch reports".to_owned(),
                observed: e.to_string(),
                evidence,
            }
        }
    };
    if !killed.load(std::sync::atomic::Ordering::Relaxed) {
        return Execution::Fail {
            expected: "the rendezvous to be terminated during the hold".to_owned(),
            observed: "it was already gone, so the outage proves nothing".to_owned(),
            evidence,
        };
    }
    evidence.push("the rendezvous was terminated while the path was held".to_owned());
    evidence.push(format!(
        "a: direct {} held {}/{} sent; b: direct {} held {}/{} sent",
        a.direct, a.held_received, a.held_sent, b.direct, b.held_received, b.held_sent
    ));

    if !(a.direct && b.direct) {
        return Execution::Fail {
            expected: "an established path before the outage".to_owned(),
            observed: "the path was never established, so its survival was not measured".to_owned(),
            evidence,
        };
    }
    if a.held_received > 0 && b.held_received > 0 {
        Execution::Pass { evidence }
    } else {
        Execution::Fail {
            expected: "I5: an established session carries traffic through the outage".to_owned(),
            observed: format!(
                "a received {} and b received {} datagrams after the rendezvous died",
                a.held_received, b.held_received
            ),
            evidence,
        }
    }
}

/// `S-NET-*`: §3.4's PMTU black hole and interface-change rows.
fn run_net(scenario: &Scenario) -> Execution {
    let label = format!("run-{}", scenario.id.to_lowercase());
    if scenario.id.contains("PMTU-BLACKHOLE") {
        return run_pmtu(scenario, &label);
    }
    if scenario.id.contains("ROAM") {
        return run_roam(&label);
    }
    Execution::NotExecutable {
        family: "NET",
        needs: format!(
            "a procedure for `{}`; this runner knows `PMTU-BLACKHOLE` and `ROAM`",
            scenario.id
        ),
    }
}

/// §3.4.2: "A 1500-byte DF probe is dropped and **no** ICMP fragmentation-needed
/// is observed at the sender."
fn run_pmtu(scenario: &Scenario, label: &str) -> Execution {
    let Some(site) = scenario.sites.first() else {
        return Execution::NotExecutable {
            family: "NET",
            needs: "at least one site".to_owned(),
        };
    };
    let Some((mapping, filtering)) = axes(site.nat) else {
        return Execution::Unavailable {
            detail: format!(
                "`{}` is not a personality this rig installs",
                site.nat.name()
            ),
        };
    };
    let personality = rigs::Personality {
        name: site.nat.name(),
        mapping,
        filtering,
    };
    let mut evidence = Vec::new();

    // The control, in its own rig: with the black hole OFF the same probe is
    // REPORTED. An absence is only a condition if the thing could have been
    // present, and a middlebox that cannot send the message would satisfy the
    // real assertion for the wrong reason.
    match pmtu_run(&format!("{label}-control"), &personality, false) {
        Ok(snapshot) if rigs::counter(&snapshot, "pmtu_reported") > 0 => {
            evidence.push(
                "control: with the black hole off, the oversize probe was reported".to_owned(),
            );
        }
        Ok(snapshot) => {
            return Execution::Fail {
                expected: "the control to report an oversize packet".to_owned(),
                observed: format!("it reported none: {snapshot:#}"),
                evidence,
            }
        }
        Err(e) if e.is_unavailable() => {
            return Execution::Unavailable {
                detail: e.to_string(),
            }
        }
        Err(e) => {
            return Execution::Fail {
                expected: "the control rig to run".to_owned(),
                observed: e.to_string(),
                evidence,
            }
        }
    }

    match pmtu_run(label, &personality, true) {
        Ok(snapshot) if rigs::counter(&snapshot, "pmtu_dropped") > 0 => {
            evidence.push(format!(
                "the black hole swallowed {} path-MTU messages and reported {}",
                rigs::counter(&snapshot, "pmtu_dropped"),
                rigs::counter(&snapshot, "pmtu_reported")
            ));
            if rigs::counter(&snapshot, "pmtu_reported") > 0 {
                return Execution::Fail {
                    expected: "no ICMP fragmentation-needed at the sender".to_owned(),
                    observed: "the black hole reported one anyway".to_owned(),
                    evidence,
                };
            }
            Execution::Pass { evidence }
        }
        Ok(snapshot) => Execution::Fail {
            expected: "an oversize probe to be dropped by the black hole".to_owned(),
            observed: format!("nothing was dropped, so no probe was oversize: {snapshot:#}"),
            evidence,
        },
        Err(e) if e.is_unavailable() => Execution::Unavailable {
            detail: e.to_string(),
        },
        Err(e) => Execution::Fail {
            expected: "the black hole rig to run".to_owned(),
            observed: e.to_string(),
            evidence,
        },
    }
}

fn pmtu_run(
    label: &str,
    personality: &rigs::Personality,
    black_hole: bool,
) -> Result<serde_json::Value, NetError> {
    let mut rig = rigs::build_single_site(label, false)?;
    let mut cfg = rigs::single_site_nat(&rig, personality);
    cfg.egress_mtu = Some(1_280);
    cfg.drop_pmtu_icmp = black_hole;
    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    let started = fabric.start_nat(&mut rig.sb, "cpe", &cfg);
    rig.fabric = fabric;
    let (_, stats) = started?;
    rigs::settle();
    let _ = rig.sb.run(
        Some("client"),
        &[
            "ping",
            "-c",
            "2",
            "-W",
            "1",
            "-M",
            "do",
            "-s",
            "1400",
            rigs::REFLECT_A,
        ],
    )?;
    let want = if black_hole {
        "pmtu_dropped"
    } else {
        "pmtu_reported"
    };
    rigs::await_snapshot(&stats, std::time::Duration::from_secs(3), |v| {
        rigs::counter(v, want) > 0
    })
}

/// §3.4's interface-change row: the session survives a move between access
/// networks, and the tunnel is not restarted to make it.
fn run_roam(label: &str) -> Execution {
    let mut rig = match rigs::build_roam_site(label) {
        Ok(rig) => rig,
        Err(e) if e.is_unavailable() => {
            return Execution::Unavailable {
                detail: e.to_string(),
            }
        }
        Err(e) => {
            return Execution::Fail {
                expected: "a roam rig".to_owned(),
                observed: e.to_string(),
                evidence: Vec::new(),
            }
        }
    };
    let mut evidence = Vec::new();
    let tunnel = match rigs::start_roam_tunnel(&mut rig) {
        Ok(t) => t,
        Err(e) => {
            return Execution::Fail {
                expected: "a tunnel over the first access network".to_owned(),
                observed: e.to_string(),
                evidence,
            }
        }
    };
    match roam_traffic(&mut rig) {
        Ok(n) if n > 0 => evidence.push(format!("{n} datagrams carried before the roam")),
        Ok(_) => {
            return Execution::Fail {
                expected: "traffic on the first access network".to_owned(),
                observed: "none, so the roam has nothing to preserve".to_owned(),
                evidence,
            }
        }
        Err(e) => {
            return Execution::Fail {
                expected: "the pre-roam probe to run".to_owned(),
                observed: e.to_string(),
                evidence,
            }
        }
    }

    if let Err(e) = rigs::roam_to_cell(&mut rig) {
        return Execution::Fail {
            expected: "the leg to move to the second access network".to_owned(),
            observed: e.to_string(),
            evidence,
        };
    }
    rigs::settle();
    evidence.push("the device moved to the second access network and re-addressed".to_owned());

    match rig.sb.wait(tunnel, 0) {
        Ok((true, _)) => {
            return Execution::Fail {
                expected: "the same tunnel process to survive the roam".to_owned(),
                observed: "it exited, so anything that resumes is a new session".to_owned(),
                evidence,
            }
        }
        Ok(_) => evidence.push("the tunnel process was not restarted".to_owned()),
        Err(e) => {
            return Execution::Fail {
                expected: "the tunnel handle to answer".to_owned(),
                observed: e.to_string(),
                evidence,
            }
        }
    }

    let mut carried = 0;
    for _ in 0..5 {
        match roam_traffic(&mut rig) {
            Ok(n) => carried = n,
            Err(e) => {
                return Execution::Fail {
                    expected: "the post-roam probe to run".to_owned(),
                    observed: e.to_string(),
                    evidence,
                }
            }
        }
        if carried > 0 {
            break;
        }
    }
    evidence.push(format!("{carried} datagrams carried after the roam"));
    if carried > 0 {
        Execution::Pass { evidence }
    } else {
        Execution::Fail {
            expected: "the session to survive the interface change".to_owned(),
            observed: "no traffic was carried after the roam".to_owned(),
            evidence,
        }
    }
}

fn roam_traffic(rig: &mut rigs::Rig) -> Result<u32, NetError> {
    let agent = rig.sb.agent_path().display().to_string();
    let overlay = format!("{}:9", rigs::EXIT_OVERLAY_V4);
    let ran = rig.sb.run(
        Some("device"),
        &[
            &agent,
            "udp-send",
            "--to",
            &overlay,
            "--count",
            "3",
            "--interval-ms",
            "30",
            "--wait-ms",
            "300",
        ],
    )?;
    Ok(received(&ran.stdout))
}

/// `S-KS-*`: protected traffic never leaves untunneled while fail-closed is
/// active, per family, with the canary's positive control green in the same
/// session (**B-7**).
fn run_ks(scenario: &Scenario) -> Execution {
    let Some(site) = scenario.sites.first() else {
        return Execution::NotExecutable {
            family: "KS",
            needs: "one site; every `S-KS-*` document declares one".to_owned(),
        };
    };
    let Some((mapping, filtering)) = axes(site.nat) else {
        return Execution::Unavailable {
            detail: format!(
                "`{}` is not a personality this rig installs in front of a device",
                site.nat.name()
            ),
        };
    };

    let mut evidence = vec![format!(
        "site a is behind `{}` ({})",
        site.nat.name(),
        Realization::UserspaceMiddlebox.name()
    )];
    match conformance(site.nat) {
        Ok((_, d)) if d.is_empty() => evidence.push(format!(
            "L-1: `{}` passed its §3.4.2 conformance suite",
            site.nat.name()
        )),
        Ok((_, disagreements)) => return Execution::Void { disagreements },
        Err(e) if e.is_unavailable() => {
            return Execution::Unavailable {
                detail: e.to_string(),
            }
        }
        Err(e) => {
            return Execution::Fail {
                expected: "a conformance report".to_owned(),
                observed: e.to_string(),
                evidence,
            }
        }
    }

    let label = format!("run-{}", scenario.id.to_lowercase());
    let personality = rigs::Personality {
        name: site.nat.name(),
        mapping,
        filtering,
    };
    let mut rig = match rigs::build_tunnel_site_with(&label, Some(&personality)) {
        Ok(rig) => rig,
        Err(e) if e.is_unavailable() => {
            return Execution::Unavailable {
                detail: e.to_string(),
            }
        }
        Err(e) => {
            return Execution::Fail {
                expected: "a tunnel site behind the declared middlebox".to_owned(),
                observed: e.to_string(),
                evidence,
            }
        }
    };
    let ends = match rigs::start_tunnel(&mut rig) {
        Ok(ends) => ends,
        Err(e) => {
            return Execution::Fail {
                expected: "a tunnel through the middlebox".to_owned(),
                observed: e.to_string(),
                evidence,
            }
        }
    };
    if let Err(e) = rigs::arm_kill_switch(&mut rig) {
        return Execution::Fail {
            expected: "an armed kill switch".to_owned(),
            observed: e.to_string(),
            evidence,
        };
    }
    evidence.push("the kill switch is armed as an OS-level blackhole per family".to_owned());

    match ks_procedure(&mut rig, scenario, ends, &mut evidence) {
        Ok(None) => Execution::Pass { evidence },
        Ok(Some((expected, observed))) => Execution::Fail {
            expected,
            observed,
            evidence,
        },
        Err(e) => Execution::Fail {
            expected: "the scenario to run".to_owned(),
            observed: e.to_string(),
            evidence,
        },
    }
}

/// The `S-KS-*` procedure. `Ok(None)` is a pass.
///
/// Long because the procedure is: a positive control, protected traffic per
/// family, the sealed assertion, the kill, the fail-closed assertion, and the
/// mutant — in that order, on one capture. Splitting it would put six steps of
/// one experiment in six functions and hide the ordering that makes them mean
/// anything.
#[allow(clippy::too_many_lines)]
fn ks_procedure(
    rig: &mut rigs::Rig,
    scenario: &Scenario,
    ends: rigs::TunnelEnds,
    evidence: &mut Vec<String>,
) -> Result<Option<(String, String)>, NetError> {
    use twinnet::observer::{Prefix, Reason};

    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    let started = fabric.start_capture(&mut rig.sb, "device", "wan", "ks", 20_000);
    rig.fabric = fabric;
    let (_, capture_path) = started?;
    rigs::settle();

    let policy = || {
        twinnet::LeakPolicy::sealed()
            .protecting(Prefix::parse(rigs::OVERLAY_V4).expect("the overlay v4 prefix"))
            .protecting(Prefix::parse(rigs::OVERLAY_V6).expect("the overlay v6 prefix"))
            .resolver(rigs::EXIT_OVERLAY_V4.parse().expect("a literal"))
    };
    let deliberate = ["ks-canary.twinvpn.invalid"];
    let escapes = |capture: &twinnet::Capture| -> Vec<String> {
        policy()
            .audit(capture)
            .into_iter()
            .filter(|e| match &e.reason {
                Reason::ProtectedSource { .. } | Reason::ProtectedDestination { .. } => true,
                Reason::UnauthorizedDns { qname } => {
                    !qname.as_deref().is_some_and(|q| deliberate.contains(&q))
                }
                _ => false,
            })
            .map(|e| e.to_string())
            .collect()
    };
    let load = |path: &std::path::Path| -> Result<twinnet::Capture, NetError> {
        std::thread::sleep(std::time::Duration::from_millis(700));
        twinnet::Capture::load(path)
    };

    // B-7: the canary's positive control, green in the same session.
    let agent = rig.sb.agent_path().display().to_string();
    let rogue = format!("{}:53", rigs::ROGUE_UNDERLAY);
    let _ = rig.sb.run(
        Some("device"),
        &[
            &agent,
            "dns-query",
            "--server",
            &rogue,
            "--name",
            deliberate[0],
            "--wait-ms",
            "250",
        ],
    )?;
    let control = load(&capture_path)?;
    if !policy().audit(&control).iter().any(|e| {
        matches!(&e.reason, Reason::UnauthorizedDns { qname }
            if qname.as_deref() == Some(deliberate[0]))
    }) {
        return Ok(Some((
            "the leak canary's positive control to be caught (B-7)".to_owned(),
            "it was not, so no silence in this capture means anything".to_owned(),
        )));
    }
    evidence.push("B-7: the positive control leaked and the oracle caught it".to_owned());

    // Protected traffic, per family, as §3.6 requires: a v4-only scenario
    // asserts v4, a v6-only one asserts v6, and `dual` asserts both. A rig that
    // always asserted both would make the v6 instantiation of a v4-only story
    // pass for a reason the document does not claim.
    let mut targets: Vec<String> = Vec::new();
    if scenario.address_family != Family::V6Only {
        targets.push(format!("{}:9", rigs::EXIT_OVERLAY_V4));
    }
    if scenario.address_family != Family::V4Only {
        targets.push(format!("[{}]:9", rigs::EXIT_OVERLAY_V6));
    }
    let mut carried = 0u32;
    for to in &targets {
        let bind = if to.starts_with('[') {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let ran = rig.sb.run(
            Some("device"),
            &[
                &agent,
                "udp-send",
                "--to",
                to,
                "--bind",
                bind,
                "--count",
                "3",
                "--interval-ms",
                "30",
                "--wait-ms",
                "200",
            ],
        )?;
        carried += received(&ran.stdout);
    }
    evidence.push(format!(
        "{carried} datagrams carried over {} protected target(s)",
        targets.len()
    ));
    if carried == 0 {
        return Ok(Some((
            "the tunnel to carry protected traffic".to_owned(),
            "it carried none, so `nothing leaked` is a statement about a dead tunnel".to_owned(),
        )));
    }
    let sealed = load(&capture_path)?;
    let found = escapes(&sealed);
    if !found.is_empty() {
        return Ok(Some((
            "no protected addressing on the underlay while the tunnel is up".to_owned(),
            found.join("; "),
        )));
    }
    evidence.push("no protected addressing on the underlay while the tunnel is up".to_owned());

    // Fail-closed: the tunnel dies and the blackhole is what is left.
    if !rig.sb.signal(ends.device, 9)? {
        return Ok(Some((
            "a live tunnel to terminate".to_owned(),
            "it was already dead, so killing it proves nothing".to_owned(),
        )));
    }
    rigs::settle();
    for to in &targets {
        let bind = if to.starts_with('[') {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let _ = rig.sb.run(
            Some("device"),
            &[
                &agent,
                "udp-send",
                "--to",
                to,
                "--bind",
                bind,
                "--count",
                "3",
                "--interval-ms",
                "30",
                "--wait-ms",
                "200",
            ],
        )?;
    }
    let after = load(&capture_path)?;
    let found = escapes(&after);
    if !found.is_empty() {
        return Ok(Some((
            "no protected addressing on the underlay after the tunnel died".to_owned(),
            found.join("; "),
        )));
    }
    evidence.push(
        "fail-closed: nothing protected reached the underlay after the tunnel died".to_owned(),
    );

    // The mutant (V2): disarm the kill switch and the same traffic must escape.
    // Without it, the silence above would be the topology's and not the switch's.
    rigs::disarm_kill_switch(rig)?;
    for to in &targets {
        let bind = if to.starts_with('[') {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let _ = rig.sb.run(
            Some("device"),
            &[
                &agent,
                "udp-send",
                "--to",
                to,
                "--bind",
                bind,
                "--count",
                "3",
                "--interval-ms",
                "30",
                "--wait-ms",
                "200",
            ],
        )?;
    }
    let mutant = load(&capture_path)?;
    if escapes(&mutant).is_empty() {
        return Ok(Some((
            "the mutant to leak: with the kill switch disarmed, protected traffic must \
             escape"
                .to_owned(),
            "it did not, so the fail-closed result above says nothing about the kill switch"
                .to_owned(),
        )));
    }
    evidence.push(
        "V2: with the kill switch disarmed the same traffic escaped and was caught".to_owned(),
    );
    Ok(None)
}

fn relayed_pair(
    rig: &mut rigs::Rig,
    relays: &str,
    tag: &str,
) -> Result<(twinnet::relay::RelayedReport, twinnet::relay::RelayedReport), NetError> {
    let agent = rig.sb.agent_path().display().to_string();
    let out = rig.scratch.join(format!("relayed-a-{tag}.json"));
    let _ = std::fs::remove_file(&out);
    let argv = |t: &str| {
        vec![
            "relayed".to_owned(),
            "--relays".to_owned(),
            relays.to_owned(),
            "--tag".to_owned(),
            t.to_owned(),
            "--rounds".to_owned(),
            "12".to_owned(),
            "--interval-ms".to_owned(),
            "50".to_owned(),
            "--bind-wait-ms".to_owned(),
            "400".to_owned(),
        ]
    };
    let mut full = vec![agent.clone()];
    full.extend(argv(tag));
    let refs: Vec<&str> = full.iter().map(String::as_str).collect();
    let handle = rig.sb.spawn(Some("peer-a"), &refs, Some(&out))?;
    let ran = rig.sb.run(Some("peer-b"), &refs)?;
    rig.sb.wait(handle, 15_000)?;
    let decode = |text: &str| -> Result<twinnet::relay::RelayedReport, NetError> {
        serde_json::from_str(text.trim())
            .map_err(|e| NetError::Agent(format!("undecodable relayed report ({e}): {text}")))
    };
    let a_text = std::fs::read_to_string(&out).unwrap_or_default();
    Ok((decode(&a_text)?, decode(&ran.stdout)?))
}

fn punch_and_hold(
    rig: &mut rigs::Rig,
    reflector: &str,
    hold_ms: u64,
    killed: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<(twinnet::traffic::P2pReport, twinnet::traffic::P2pReport), NetError> {
    let agent = rig.sb.agent_path().display().to_string();
    let a_ep = rig.scratch.join("hold-a.endpoint");
    let b_ep = rig.scratch.join("hold-b.endpoint");
    let a_out = rig.scratch.join("hold-a.json");
    let b_out = rig.scratch.join("hold-b.json");
    for f in [&a_ep, &b_ep, &a_out, &b_out] {
        let _ = std::fs::remove_file(f);
    }
    let hold = hold_ms.to_string();
    let (a_ep_s, b_ep_s) = (a_ep.display().to_string(), b_ep.display().to_string());
    let args = |mine: &str, theirs: &str| {
        vec![
            "p2p".to_owned(),
            "--reflector".to_owned(),
            reflector.to_owned(),
            "--mine".to_owned(),
            mine.to_owned(),
            "--theirs".to_owned(),
            theirs.to_owned(),
            "--rounds".to_owned(),
            "8".to_owned(),
            "--interval-ms".to_owned(),
            "50".to_owned(),
            "--wait-ms".to_owned(),
            "5000".to_owned(),
            "--hold-ms".to_owned(),
            hold.clone(),
        ]
    };
    let mut spawn = |node: &str, argv: Vec<String>, out: &std::path::Path| {
        let mut full = vec![agent.clone()];
        full.extend(argv);
        let refs: Vec<&str> = full.iter().map(String::as_str).collect();
        rig.sb.spawn(Some(node), &refs, Some(out))
    };
    let ha = spawn("peer-a", args(&a_ep_s, &b_ep_s), &a_out)?;
    let hb = spawn("peer-b", args(&b_ep_s, &a_ep_s), &b_out)?;

    std::thread::sleep(std::time::Duration::from_millis(1_500));
    if let Some(reflector) = rig.process("reflector") {
        if rig.sb.signal(reflector, 9)? {
            killed.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    rig.sb.wait(ha, 40_000)?;
    rig.sb.wait(hb, 40_000)?;
    let decode = |path: &std::path::Path| -> Result<twinnet::traffic::P2pReport, NetError> {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        serde_json::from_str(text.trim())
            .map_err(|e| NetError::Agent(format!("undecodable peer report ({e}): {text}")))
    };
    Ok((decode(&a_out)?, decode(&b_out)?))
}

#[allow(clippy::too_many_lines)]
fn run_nat(scenario: &Scenario) -> Execution {
    let Some(expect) = scenario.expect else {
        return Execution::NotExecutable {
            family: "NAT",
            needs: "an expected outcome class; this scenario declares none".to_owned(),
        };
    };
    let (Some(a), Some(b)) = (scenario.sites.first(), scenario.sites.get(1)) else {
        return Execution::NotExecutable {
            family: "NAT",
            needs: "two sites; §2.10's matrix is a pair".to_owned(),
        };
    };
    if let OutcomeClass::DirectPossible { .. } = expect {
        return Execution::NotExecutable {
            family: "NAT",
            needs: "a peer that implements port prediction or a port-mapping protocol. \
                    §3.2 defines `D*` as direct WITH prediction, and `twinnet`'s hole-puncher \
                    implements neither — a rate measured against it would be a number about \
                    the laboratory."
                .to_owned(),
        };
    }
    let (Some(axes_a), Some(axes_b)) = (axes(a.nat), axes(b.nat)) else {
        return Execution::Unavailable {
            detail: format!(
                "`{}` x `{}`: a NAT64 tier needs a family-translating middlebox, which this \
                 host has no realization of",
                a.nat.name(),
                b.nat.name()
            ),
        };
    };

    let mut evidence = vec![format!(
        "realization: {} (§3.3's nftables realization needs `nft` and `conntrack`)",
        Realization::UserspaceMiddlebox.name()
    )];

    // Rule L-1, enforced before anything is measured.
    for p in [a.nat, b.nat] {
        match conformance(p) {
            Ok((report, disagreements)) if disagreements.is_empty() => {
                evidence.push(format!(
                    "L-1: `{}` passed its §3.4.2 conformance suite (mapping {:?}, filtering {:?})",
                    p.name(),
                    report.mapping,
                    report.filtering
                ));
            }
            Ok((_, disagreements)) => return Execution::Void { disagreements },
            Err(e) if e.is_unavailable() => {
                return Execution::Unavailable {
                    detail: e.to_string(),
                }
            }
            Err(e) => {
                return Execution::Fail {
                    expected: "a conformance report".to_owned(),
                    observed: e.to_string(),
                    evidence,
                }
            }
        }
    }

    let rig = rigs::build_two_site(&format!("run-{}", scenario.id.to_lowercase()));
    let mut rig = match rig {
        Ok(rig) => rig,
        Err(e) if e.is_unavailable() => {
            return Execution::Unavailable {
                detail: e.to_string(),
            }
        }
        Err(e) => {
            return Execution::Fail {
                expected: "a two-site rig".to_owned(),
                observed: e.to_string(),
                evidence,
            }
        }
    };

    let named = |p: Personality, axes: (Mapping, Filtering)| rigs::Personality {
        name: leak_name(p),
        mapping: axes.0,
        filtering: axes.1,
    };
    let cfg_a = rigs::site_nat(&rig, "a", &named(a.nat, axes_a));
    let cfg_b = rigs::site_nat(&rig, "b", &named(b.nat, axes_b));
    let mut fabric = std::mem::replace(&mut rig.fabric, twinnet::fabric::Fabric::new(&rig.scratch));
    let started = fabric
        .start_nat(&mut rig.sb, "cpe-a", &cfg_a)
        .and_then(|_| fabric.start_nat(&mut rig.sb, "cpe-b", &cfg_b));
    rig.fabric = fabric;
    if let Err(e) = started {
        return Execution::Fail {
            expected: "two middleboxes".to_owned(),
            observed: e.to_string(),
            evidence,
        };
    }
    rigs::settle();

    // §3.2's last row: on a v6-only or dual path both ends have working IPv6, so
    // the pair is evaluated over the native v6 underlay.
    let reflector = match scenario.address_family {
        Family::V4Only => format!("{}:{}", rigs::REFLECT_A, rigs::PORT_A),
        Family::V6Only | Family::Dual => format!("[{}]:{}", rigs::REFLECT_A6, rigs::PORT_A),
        Family::Nat64 => {
            return Execution::Unavailable {
                detail: "a NAT64 access network needs a family-translating middlebox, which \
                         this host has no realization of"
                    .to_owned(),
            }
        }
    };
    evidence.push(format!(
        "underlay: {} via {reflector}",
        scenario.address_family.name()
    ));

    let (ra, rb) = match punch(&mut rig, &reflector) {
        Ok(pair) => pair,
        Err(e) => {
            return Execution::Fail {
                expected: "two hole-punch reports".to_owned(),
                observed: e.to_string(),
                evidence,
            }
        }
    };
    evidence.push(format!(
        "a: mapped {:?} peer {:?} direct {} received {}",
        ra.mapped, ra.peer, ra.direct, ra.received
    ));
    evidence.push(format!(
        "b: mapped {:?} peer {:?} direct {} received {}",
        rb.mapped, rb.peer, rb.direct, rb.received
    ));

    let direct = ra.direct && rb.direct;
    let held = match expect {
        OutcomeClass::DirectExpected => direct,
        OutcomeClass::RelayExpected => !direct,
        OutcomeClass::DirectPossible { .. } => unreachable!("filtered above"),
    };
    if held {
        Execution::Pass { evidence }
    } else {
        Execution::Fail {
            expected: expect.name().to_owned(),
            observed: if direct {
                "a direct path was established".to_owned()
            } else {
                "no direct path was established".to_owned()
            },
            evidence,
        }
    }
}

fn punch(
    rig: &mut rigs::Rig,
    reflector: &str,
) -> Result<(twinnet::traffic::P2pReport, twinnet::traffic::P2pReport), NetError> {
    let agent = rig.sb.agent_path().display().to_string();
    let a_ep = rig.scratch.join("a.endpoint");
    let b_ep = rig.scratch.join("b.endpoint");
    let a_out = rig.scratch.join("a.json");
    let b_out = rig.scratch.join("b.json");
    for f in [&a_ep, &b_ep, &a_out, &b_out] {
        let _ = std::fs::remove_file(f);
    }
    let (a_ep_s, b_ep_s) = (a_ep.display().to_string(), b_ep.display().to_string());
    let mut spawn = |node: &str, mine: &str, theirs: &str, out: &std::path::Path| {
        rig.sb.spawn(
            Some(node),
            &[
                &agent,
                "p2p",
                "--reflector",
                reflector,
                "--mine",
                mine,
                "--theirs",
                theirs,
                "--rounds",
                "10",
                "--interval-ms",
                "60",
                "--wait-ms",
                "5000",
            ],
            Some(out),
        )
    };
    let ha = spawn("peer-a", &a_ep_s, &b_ep_s, &a_out)?;
    let hb = spawn("peer-b", &b_ep_s, &a_ep_s, &b_out)?;
    rig.sb.wait(ha, 30_000)?;
    rig.sb.wait(hb, 30_000)?;
    let decode = |path: &std::path::Path| -> Result<twinnet::traffic::P2pReport, NetError> {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        serde_json::from_str(text.trim())
            .map_err(|e| NetError::Agent(format!("undecodable peer report ({e}): {text}")))
    };
    Ok((decode(&a_out)?, decode(&b_out)?))
}
