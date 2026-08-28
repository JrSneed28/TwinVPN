//! `twinlab` — namespace/veth topology, NAT classes, netem impairment and the seeded scenario runtime.
//!
//! **Owner:** `test-engineering`. Never shipped (ADR-0018 §11.12).
//!
//! docs/testing-strategy.md §3.1's realization principle is the constraint that
//! makes this crate hard: a condition must be produced by a real mechanism, and
//! the system under test must not be able to detect the lab.
//!
//! # The shape of the crate, and the one rule behind it
//!
//! | Module | § | What it holds |
//! |---|---|---|
//! | [`capability`] | §3.1, §3.2 | what this host can actually realize, **probed** |
//! | [`exec`] | §3.1 | the only place a real `ip`/`tc`/`nft` process is spawned |
//! | [`addressing`] | §3.2 | the address plan, and the contradiction inside §3.2's realism rule |
//! | [`topology`] | §3.2 | namespaces, `veth`, bridges, and their lifecycle |
//! | [`nat`] | §3.3 | the personalities, their real `nft` mechanism, and the class-pair matrix **generated from** `docs/networking.md` §3.2 |
//! | [`impair`] | §3.4, §3.5 | the impairment matrix and the seeded drop schedule |
//! | [`determinism`] | §3.5 | the three classes, and rule L-2 made mechanical |
//! | [`seed`] | §3.5, CD-4 | the HKDF binding TwinLab owns (finding **W-1**) |
//! | [`conformance`] | §3.4.2 | control **V10**, and why nothing here is conformant yet |
//! | [`outcome`] | §2.10 | the expected classes, and a verdict with four values |
//! | [`record`] | §3.6 | the run record, and what it honestly does not carry |
//!
//! **The rule:** a facility this host does not provide yields
//! [`outcome::Verdict::Unavailable`], never a pass. Every type in this crate is
//! arranged so that "we could not produce the condition" and "the condition
//! held" cannot be confused, because that confusion is the only way a network
//! laboratory can be worse than no laboratory at all.
//!
//! # What this crate does not contain
//!
//! No simulated backend. No `lab_mode`. No switch inside TwinVPN that TwinLab
//! sets. §3.1 forbids all three, and the absence is the point: a `RELAY_EXPECTED`
//! outcome must come from a NAT that genuinely allocates that way.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// Product and protocol nouns — TwinVPN, TwinLab, TwinNet, IPv4, IPv6, NAT, CGNAT
// — appear throughout the specification quotations this crate carries, and
// back-ticking them would make those quotations harder to read.
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]
// Every fallible function here returns `LabError`, whose own documentation
// enumerates its variants; a per-function `# Errors` section would restate that
// table once per constructor.
#![allow(clippy::missing_errors_doc)]

pub mod addressing;
pub mod capability;
pub mod conformance;
pub mod determinism;
pub mod error;
pub mod exec;
pub mod impair;
pub mod nat;
pub mod outcome;
pub mod record;
pub mod seed;
pub mod topology;

pub use addressing::AddressPlan;
pub use capability::{Facility, HostCapabilities};
pub use determinism::{AssertionShape, Class, Tier};
pub use error::LabError;
pub use impair::{Impairment, ImpairmentSet, LossSchedule};
pub use nat::{Personality, PortMap, Traversability};
pub use outcome::{DirectPossibleTally, ObservedPath, OutcomeClass, Verdict};
pub use record::RunRecord;
pub use seed::{CountingEntropy, LabEnv, ScenarioSeed};
pub use topology::{LinuxNamespaceBackend, Node, NodeKind, Realization, Topology};
