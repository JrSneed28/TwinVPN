//! `twinlab-scenarios` — the CLI over the scenario catalogue.
//!
//! **Owner:** `test-engineering`. Never shipped (ADR-0018 §11.12).
//!
//! ```text
//! twinlab-scenarios capabilities        what this host can actually realize
//! twinlab-scenarios list [--family NAT] every scenario, with its class and tiers
//! twinlab-scenarios matrix              the NAT class-pair matrix and expected outcomes
//! twinlab-scenarios show <ID>           §3.6's scenario document
//! twinlab-scenarios plan <ID>           what the scenario needs, and whether this host has it
//! twinlab-scenarios nat-ruleset <CLASS> the real `nft` ruleset for a NAT personality
//! twinlab-scenarios impair-argv <SPEC>  the real `tc` arguments for an impairment
//! ```
//!
//! `nat-ruleset` and `impair-argv` exist so the container-based test network in
//! `infra/compose/netlab.yml` can be driven by the SAME definitions the
//! namespace lab uses. `twinlab::nat::Personality::ruleset` and
//! `twinlab::impair::Impairment::tc_argv` are the mechanism; these subcommands
//! print it. A shell script that re-typed the rules would be the R-31
//! divergence class ADR-0018 CB-2 exists to prevent, and it would diverge in
//! exactly the direction that matters: a container "NAT" that is not the
//! personality its label claims produces a green traversal result for a class
//! that was never realized.
//!
//! `plan` is the honest half of `run`. There is no `run` subcommand, because on
//! a host that cannot create a named network namespace there is nothing to run,
//! and a `run` that printed a green line would be exactly the lie
//! `docs/testing-strategy.md` §3.1 exists to prevent.
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]

use clap::{Parser, Subcommand};
use twinlab::capability::HostCapabilities;
use twinlab::nat::{expected_class, Personality, PortMap, Traversability, TRAVERSABILITY_MD};
use twinlab_scenarios::{all, by_id, ScenarioFamily};

/// `println!`, minus the panic when the reader has walked away.
///
/// Every line this binary prints goes through here, because every subcommand
/// can be read by something that stops reading. `lab-t1` pipes `list` into
/// `head -1` and `capabilities` into `tee`: the first closes the pipe after one
/// line, and Rust ignores `SIGPIPE`, so the next write returns `EPIPE` and
/// `println!` unwraps it into "failed printing to stdout: Broken pipe". That is
/// how a command which had already produced the line its consumer wanted exited
/// 101 and failed the step (job 100262708050).
///
/// A closed stdout is the consumer saying it has enough, so the error is
/// dropped and the command finishes on its own terms. The exit code then still
/// means what it says — §3.1's three-way answer reaches the shell, instead of
/// being overwritten by a panic on the way out.
macro_rules! outln {
    () => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout().lock());
    }};
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout().lock(), $($arg)*);
    }};
}

/// `print!`, on the same terms as [`outln`].
macro_rules! out {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = write!(std::io::stdout().lock(), $($arg)*);
    }};
}

#[derive(Parser)]
#[command(
    name = "twinlab-scenarios",
    about = "the NAT-class matrix and the named scenario family of testing-strategy.md §3"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// What this host can actually realize, probed rather than assumed.
    Capabilities,
    /// Every scenario, with its determinism class and tiers.
    List {
        /// Restrict to one §3.6 family, e.g. `NAT`.
        #[arg(long)]
        family: Option<String>,
    },
    /// The class-pair matrix, generated from `docs/networking.md` §3.2.
    Matrix,
    /// §3.6's scenario document for one id.
    Show {
        /// The scenario id.
        id: String,
    },
    /// §3.4.2's NAT-personality conformance suite, run against a real
    /// middlebox by a prober that is not TwinVPN code.
    ///
    /// Rule **L-1**: no traversal, leak or relay test may run against a
    /// personality that has not passed this, in the same lab instantiation, on
    /// the same day.
    Conformance,
    /// Run a scenario for real, and report what happened.
    ///
    /// `PASS`, `FAIL`, `UNAVAILABLE`, `VOID` and `NOT-EXECUTABLE` are five
    /// different answers and are printed as five different words. Only `PASS`
    /// is evidence the oracle held.
    Run {
        /// The scenario id.
        id: String,
    },
    /// What a scenario needs, and whether this host provides it.
    Plan {
        /// The scenario id.
        id: String,
    },
    /// The real `nft` ruleset §3.3 specifies for one NAT personality.
    NatRuleset {
        /// `N-ROUTED`, `N-EIM-EIF`, `N-EIM-ADF`, `N-EIM-APDF`,
        /// `N-APDM-APDF-RAND`, `N-APDM-APDF-SEQ`, `N-CGNAT`, `N-NAT64`.
        class: String,
        /// The external address the translator maps to.
        #[arg(long, default_value = "203.0.113.1")]
        external: String,
        /// The internal prefix behind it.
        #[arg(long, default_value = "10.10.0.0/24")]
        internal: String,
    },
    /// The real `tc` argument vector for one impairment.
    ImpairArgv {
        /// `latency:<ms>`, `jitter:<base_ms>,<jitter_ms>`, `loss:<pct>`,
        /// `dup:<tenths>`, `reorder:<pct>,<corr_pct>`, `corrupt:<hundredths>`,
        /// `bw:<mbit>`.
        spec: String,
        /// The device to attach the qdisc to.
        #[arg(long, default_value = "eth0")]
        dev: String,
    },
}

/// Parses an impairment spec.
///
/// Returns `None` rather than a default for anything it does not recognise.
/// A misspelled spec that silently became "no impairment" would produce a
/// scenario that passed because nothing was ever applied — the exact class of
/// false pass `docs/testing-strategy.md` §3.1 exists to prevent.
fn parse_impairment(spec: &str) -> Option<twinlab::Impairment> {
    use twinlab::Impairment;
    let (kind, rest) = spec.split_once(':')?;
    let n = |s: &str| s.parse::<u32>().ok();
    let two = |s: &str| {
        let (a, b) = s.split_once(',')?;
        Some((n(a)?, n(b)?))
    };
    match kind {
        "latency" => Some(Impairment::Latency { ms: n(rest)? }),
        "jitter" => {
            let (base_ms, jitter_ms) = two(rest)?;
            Some(Impairment::Jitter { base_ms, jitter_ms })
        }
        "loss" => Some(Impairment::StatisticalLoss { pct: n(rest)? }),
        "dup" => Some(Impairment::Duplication {
            pct_tenths: n(rest)?,
        }),
        "reorder" => {
            let (pct, correlation_pct) = two(rest)?;
            Some(Impairment::Reordering {
                pct,
                correlation_pct,
            })
        }
        "corrupt" => Some(Impairment::Corruption {
            pct_hundredths: n(rest)?,
        }),
        "bw" => Some(Impairment::Bandwidth { mbit: n(rest)? }),
        _ => None,
    }
}

/// §3.4.2's conformance suite over every personality, and the L-1 gate.
fn conformance() -> std::process::ExitCode {
    let mut blocked = Vec::new();
    let mut passed = 0usize;
    for p in Personality::ALL {
        // NAT64's conformance row asks a different question, and asking it with
        // an RFC 5780 prober would answer about the wrong thing.
        if p == Personality::Nat64 {
            match twinlab_scenarios::runner::nat64_conformance() {
                Ok((true, evidence)) => {
                    passed += 1;
                    outln!("  {:<18} PASS         {}", p.name(), evidence.join("; "));
                }
                Ok((false, evidence)) => {
                    blocked.push(p.name());
                    outln!("  {:<18} FAIL         {}", p.name(), evidence.join("; "));
                }
                Err(e) if e.is_unavailable() => {
                    blocked.push(p.name());
                    outln!("  {:<18} UNAVAILABLE  {e}", p.name());
                }
                Err(e) => {
                    blocked.push(p.name());
                    outln!("  {:<18} ERROR        {e}", p.name());
                }
            }
            continue;
        }
        match twinlab_scenarios::runner::conformance(p) {
            Ok((report, disagreements)) if disagreements.is_empty() => {
                passed += 1;
                outln!(
                    "  {:<18} PASS         mapping {:?}, filtering {:?}, mapped {}",
                    p.name(),
                    report.mapping,
                    report.filtering,
                    report.mapped.as_deref().unwrap_or("-")
                );
            }
            Ok((_, disagreements)) => {
                blocked.push(p.name());
                outln!(
                    "  {:<18} FAIL         {}",
                    p.name(),
                    disagreements.join("; ")
                );
            }
            Err(e) if e.is_unavailable() => {
                blocked.push(p.name());
                outln!("  {:<18} UNAVAILABLE  {e}", p.name());
            }
            Err(e) => {
                blocked.push(p.name());
                outln!("  {:<18} ERROR        {e}", p.name());
            }
        }
    }
    outln!(
        "\n{passed} of {} personalities passed §3.4.2's conformance suite.",
        Personality::ALL.len()
    );
    if blocked.is_empty() {
        outln!("Rule L-1 permits a traversal, leak or relay test against any of them.");
        std::process::ExitCode::SUCCESS
    } else {
        outln!(
            "Rule L-1 FORBIDS a traversal, leak or relay test against: {}",
            blocked.join(", ")
        );
        // Exit 3, the same code `twinnet` uses for "this host cannot produce the
        // condition", so a CI job can tell a missing facility from a red test.
        std::process::ExitCode::from(3)
    }
}

/// Runs one scenario and prints the five-way answer.
fn run_scenario(id: &str) -> std::process::ExitCode {
    use twinlab_scenarios::runner::{run, Execution};
    let Some(scenario) = by_id(id) else {
        eprintln!("no scenario `{id}`; `twinlab-scenarios list` names every one");
        return std::process::ExitCode::FAILURE;
    };
    let outcome = run(&scenario);
    outln!("{}  {}", outcome.status(), scenario.id);
    match &outcome {
        Execution::Pass { evidence } => {
            for line in evidence {
                outln!("  {line}");
            }
            std::process::ExitCode::SUCCESS
        }
        Execution::Fail {
            expected,
            observed,
            evidence,
        } => {
            outln!("  expected: {expected}");
            outln!("  observed: {observed}");
            for line in evidence {
                outln!("  {line}");
            }
            std::process::ExitCode::FAILURE
        }
        Execution::Void { disagreements } => {
            outln!(
                "  a middlebox failed its §3.4.2 conformance suite, so this result is \
                 evidence of nothing (rule L-1, control V10):"
            );
            for d in disagreements {
                outln!("  {d}");
            }
            std::process::ExitCode::from(4)
        }
        Execution::Unavailable { detail } => {
            outln!("  {detail}");
            outln!("  This is NOT a pass. §3.1: a facility this host cannot provide yields");
            outln!("  Unavailable, never a green line.");
            std::process::ExitCode::from(3)
        }
        Execution::NotExecutable { family, needs } => {
            outln!("  the `{family}` family has no procedure in this runner yet.");
            outln!("  needs: {needs}");
            std::process::ExitCode::from(3)
        }
    }
}

/// Emits the real `nft` ruleset for one NAT personality.
fn nat_ruleset(class: &str, external: &str, internal: &str) -> std::process::ExitCode {
    let Some(p) = Personality::ALL
        .into_iter()
        .find(|p| p.name().eq_ignore_ascii_case(class))
    else {
        eprintln!(
            "no NAT personality `{class}`. §3.3 defines: {}",
            Personality::ALL.map(Personality::name).join(", ")
        );
        return std::process::ExitCode::FAILURE;
    };
    // The facilities are printed as comments, not checked here: this
    // command EMITS a ruleset, it does not apply one. Whether this host
    // can realize it is `plan`'s question, and answering it twice in
    // two places is how the two answers come to disagree.
    outln!("# personality: {}", p.name());
    for f in p.required_facilities() {
        outln!("# requires: {}", f.name());
    }
    out!("{}", p.ruleset(external, internal, None));
    std::process::ExitCode::SUCCESS
}

/// Emits the real `tc` argument vector for one impairment.
fn impair_argv(spec: &str, dev: &str) -> std::process::ExitCode {
    let Some(imp) = parse_impairment(spec) else {
        eprintln!(
            "cannot parse `{spec}`. Forms: latency:<ms> jitter:<ms>,<ms> loss:<pct> \
                     dup:<tenths> reorder:<pct>,<corr> corrupt:<hundredths> bw:<mbit>"
        );
        return std::process::ExitCode::FAILURE;
    };
    let Some(argv) = imp.tc_argv(dev) else {
        // `SeededLoss`, `Mtu`, `PmtuBlackHole`, `BlockedUdp` and
        // `EgressRestrictedTo443` are realized by `nft` or by `ip
        // link`, not by a qdisc. Saying so beats printing an empty
        // argument vector that a caller would run as a no-op.
        eprintln!(
            "`{spec}` is not realized by a qdisc: it needs `nft` or `ip link`, \
                     and twinlab applies it directly rather than through tc"
        );
        return std::process::ExitCode::FAILURE;
    };
    outln!("{}", argv.join(" "));
    std::process::ExitCode::SUCCESS
}

/// The NAT class-pair matrix, generated from `docs/networking.md` §3.2.
fn matrix() -> std::process::ExitCode {
    let m = Traversability::parse(TRAVERSABILITY_MD);
    out!("{:<18}", "local \\ remote");
    for p in Personality::ALL {
        out!("{:<20}", p.name());
    }
    outln!();
    for a in Personality::ALL {
        out!("{:<18}", a.name());
        for b in Personality::ALL {
            let c =
                expected_class(&m, a, b, PortMap::None).map_or("-", twinlab::OutcomeClass::name);
            out!("{c:<20}");
        }
        outln!();
    }
    outln!(
        "\ngenerated from docs/networking.md §3.2 — §3.3 requires exactly that, so a \
                 change to the matrix changes the lab"
    );
    std::process::ExitCode::SUCCESS
}

#[allow(clippy::too_many_lines)]
fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().command {
        Command::Capabilities => {
            out!("{}", HostCapabilities::probe().summary());
            // The sandbox's own probe, which is the one a run actually gets:
            // `twinlab` probes from this process, and this process cannot create
            // a named namespace or open a raw socket. `twinnet`'s agent can,
            // because it unshares first, and what it reports is what a scenario
            // will find. Printing only the first would understate the host;
            // printing only the second would hide the difference between them.
            outln!("\ninside the twinnet sandbox:");
            match twinnet::Sandbox::start() {
                Ok(sb) => {
                    for fact in sb.facts() {
                        outln!(
                            "  {:<20} {:<11} {}",
                            fact.facility,
                            if fact.available {
                                "AVAILABLE"
                            } else {
                                "unavailable"
                            },
                            fact.evidence
                        );
                    }
                }
                Err(e) => outln!("  the sandbox could not start: {e}"),
            }
            std::process::ExitCode::SUCCESS
        }
        Command::Conformance => conformance(),
        Command::Run { id } => run_scenario(&id),
        Command::List { family } => {
            let want = family.and_then(|f| {
                ScenarioFamily::ALL
                    .into_iter()
                    .find(|x| x.name().eq_ignore_ascii_case(&f))
            });
            for s in all() {
                if want.is_some_and(|w| w != s.family) {
                    continue;
                }
                outln!(
                    "{:<34} {:<12} {:<10} {}",
                    s.id,
                    s.determinism.name(),
                    s.tiers
                        .iter()
                        .map(|t| t.name())
                        .collect::<Vec<_>>()
                        .join(","),
                    s.expect.map_or("-", twinlab::OutcomeClass::name)
                );
            }
            std::process::ExitCode::SUCCESS
        }
        Command::Matrix => matrix(),
        Command::Show { id } => {
            if let Some(s) = by_id(&id) {
                out!("{}", s.to_toml());
                std::process::ExitCode::SUCCESS
            } else {
                eprintln!("no scenario `{id}`");
                std::process::ExitCode::FAILURE
            }
        }
        Command::NatRuleset {
            class,
            external,
            internal,
        } => nat_ruleset(&class, &external, &internal),
        Command::ImpairArgv { spec, dev } => impair_argv(&spec, &dev),
        Command::Plan { id } => {
            let Some(s) = by_id(&id) else {
                eprintln!("no scenario `{id}`");
                return std::process::ExitCode::FAILURE;
            };
            let host = HostCapabilities::probe();
            outln!("{} ({})", s.id, s.determinism.name());
            outln!("  purpose: {}", s.purpose);
            outln!("  needs:");
            for f in s.required_facilities() {
                outln!(
                    "    {:<20} {}",
                    f.name(),
                    if host.has(f) {
                        "available"
                    } else {
                        "UNAVAILABLE"
                    }
                );
            }
            match s.runnable_on(&host) {
                Ok(()) => outln!("  verdict: runnable on this host"),
                Err(v) => outln!(
                    "  verdict: {v:?}\n           this is an ABSENCE OF EVIDENCE, not a pass \
                     and not a failure"
                ),
            }
            std::process::ExitCode::SUCCESS
        }
    }
}
