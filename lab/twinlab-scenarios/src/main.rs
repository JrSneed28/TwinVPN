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
//! ```
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
    /// What a scenario needs, and whether this host provides it.
    Plan {
        /// The scenario id.
        id: String,
    },
}

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().command {
        Command::Capabilities => {
            print!("{}", HostCapabilities::probe().summary());
            std::process::ExitCode::SUCCESS
        }
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
                println!(
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
        Command::Matrix => {
            let m = Traversability::parse(TRAVERSABILITY_MD);
            print!("{:<18}", "local \\ remote");
            for p in Personality::ALL {
                print!("{:<20}", p.name());
            }
            println!();
            for a in Personality::ALL {
                print!("{:<18}", a.name());
                for b in Personality::ALL {
                    let c = expected_class(&m, a, b, PortMap::None)
                        .map_or("-", twinlab::OutcomeClass::name);
                    print!("{c:<20}");
                }
                println!();
            }
            println!(
                "\ngenerated from docs/networking.md §3.2 — §3.3 requires exactly that, so a \
                 change to the matrix changes the lab"
            );
            std::process::ExitCode::SUCCESS
        }
        Command::Show { id } => {
            if let Some(s) = by_id(&id) {
                print!("{}", s.to_toml());
                std::process::ExitCode::SUCCESS
            } else {
                eprintln!("no scenario `{id}`");
                std::process::ExitCode::FAILURE
            }
        }
        Command::Plan { id } => {
            let Some(s) = by_id(&id) else {
                eprintln!("no scenario `{id}`");
                return std::process::ExitCode::FAILURE;
            };
            let host = HostCapabilities::probe();
            println!("{} ({})", s.id, s.determinism.name());
            println!("  purpose: {}", s.purpose);
            println!("  needs:");
            for f in s.required_facilities() {
                println!(
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
                Ok(()) => println!("  verdict: runnable on this host"),
                Err(v) => println!(
                    "  verdict: {v:?}\n           this is an ABSENCE OF EVIDENCE, not a pass \
                     and not a failure"
                ),
            }
            std::process::ExitCode::SUCCESS
        }
    }
}
