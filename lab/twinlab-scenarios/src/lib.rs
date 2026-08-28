//! `twinlab-scenarios` — the named scenario family and the NAT-class-pair matrix.
//!
//! **Owner:** `test-engineering`. Never shipped (ADR-0018 §11.12).
//!
//! **Authority:** `docs/testing-strategy.md` §2.2, §2.9 (`S-COLL-*`), §2.10, §3,
//! §3.3, §3.6 (the scenario document and the ID grammar), §6 (tiers).
//!
//! # Scenarios are code that emits a document, not a document that is parsed
//!
//! §3.6 requires "a declarative document under version control" and that
//! "nothing about a run may live only in an operator's shell history". Both hold
//! here, in the direction that cannot drift: the **catalogue is the document**,
//! it is Rust, it is under version control, and [`Scenario::to_toml`] renders
//! §3.6's exact TOML form on demand (`twinlab-scenarios show <ID>`).
//!
//! There is deliberately no checked-in `lab/scenarios/*.toml` tree. Rendering
//! the whole catalogue to files that are generated from code creates a second
//! copy that can go stale, and §3.6's requirement is that the *specification*
//! be versioned — which it is, in `catalogue.rs`.
//!
//! Rendering rather than parsing is deliberate. A parser would let a scenario
//! exist that the class-pair matrix has never seen, and the matrix — generated
//! from `docs/networking.md` §3.2 by [`twinlab::nat`] — is the only thing
//! standing between §2.10 and a vacuous pass.
//!
//! # Determinism, stated per scenario (CD-6's residual)
//!
//! Every scenario declares one class. The **only** scenarios here that declare
//! `BIT` are the ones whose assertions are over the core's event sequence with
//! every clock injected. Everything that touches `conntrack`, `netem` or the
//! kernel scheduler declares `STATISTICAL`, because ADR-0018 CD-6's residual is
//! real: those are outside every injected provider. [`Scenario::validate`]
//! refuses a scenario whose impairments cannot support its declaration, so the
//! distinction is enforced rather than remembered.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]

pub mod catalogue;
pub mod runner;
pub mod scenario;

pub use catalogue::{all, by_id, families};
pub use scenario::{Family, Scenario, ScenarioFamily, Site};
