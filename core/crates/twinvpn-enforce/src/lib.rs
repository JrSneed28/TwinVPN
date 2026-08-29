//! `twinvpn-enforce` — the kill switch: the latch, the reconciler, the desired
//! rule set, and the `BLOCKED` decision.
//!
//! **Authority:** ADR-0012 (the whole ADR), ADR-0010 §11.5, ADR-0011 §11.10,
//! ADR-0015 §11.6, `docs/networking.md` §9, `docs/reliability.md` §4.4 and §10.3,
//! ADR-0018 CB-6.
//!
//! **Owner:** `core-dataplane`.
//!
//! # CB-6 is the shape of this crate
//!
//! > The core computes the desired rule-set generation; the adapter installs it;
//! > the OS holds it. **A core crash therefore cannot drop protection** (C-7,
//! > S-18).
//!
//! This crate is the first clause. It holds no adapter handle, opens no socket,
//! and installs nothing: [`contract::assemble`] returns a
//! `twinvpn_platform::NetworkContract` and [`reconciler::Reconciler::tick`]
//! compares an observation against a desire. Whether the OS really holds the
//! rules is a *declared per-target fact*
//! ([`latch::DurabilityPosture::survives_core_exit`]), not an assumption — an
//! adapter whose ruleset dies with the process has to say so, because on such a
//! target the kill switch is not fail-closed across a crash.
//!
//! # Two rule sets, never zero
//!
//! KS-17. `twinvpn_platform::Ruleset` has exactly two values, both fail-closed,
//! and there is no `remove_ruleset` at the seam. `leave_blocked` here is a
//! **swap**, and [`latch::Latch::leave_blocked`] refuses it unless KS-18's two
//! conditions hold — an authenticated bidirectional path validation *and* an
//! assertion that the rules are present **for both families**.
//!
//! # Never route around TwinVPN while fail-closed is active
//!
//! §11.2's exempt classes are the complete list, KS-3 makes an unmatched
//! in-scope packet dropped, and KS-12 makes a failed socket registration a
//! non-exemption rather than a blanket one. The only destination-unbounded
//! class is [`exempt::SocketClass::Bootstrap`], and KS-10 is what bounds it —
//! by what can enter the socket, not by where it may go.
//!
//! # What is here and what is not
//!
//! | Module | § | Holds |
//! |---|---|---|
//! | [`scope`] | §11.1 | Tier 1 and Tier 2, KS-1 … KS-4 |
//! | [`exempt`] | §11.2, §11.5 | the class table, KS-9's predicate, the socket registry, KS-11's accounting |
//! | [`latch`] | §11.8, §11.10 | KS-17's two rule sets, KS-18's preconditions, KS-21's disarm, the durability posture |
//! | [`reconciler`] | §11.9, ADR-0015 §11.6 | assertions, drift, KS-20's reclamation |
//! | [`canary`] | §11.9 | active leak detection, per family |
//! | [`portal`] | §11.7 | KS-14 … KS-16 |
//! | [`contract`] | CB-6 | the one `NetworkContract`, and the arm/teardown orders |
//! | [`codes`] | §11.9 | the registered codes, and the seventeen ADR-0012 names the frozen registry does not carry |
//! | [`doh`] | ADR-0011 §11.9 | the known-encrypted-resolver registry, parsed once for every platform |

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]

pub mod canary;
pub mod codes;
pub mod contract;
pub mod doh;
pub mod exempt;
pub mod latch;
pub mod portal;
pub mod reconciler;
pub mod scope;

pub use canary::{Canary, Verdict};
pub use contract::{ContractError, ContractInputs};
pub use doh::{KnownResolvers, RegistryError};
pub use exempt::{BootstrapPredicate, Class, SocketClass, SocketRegistry};
pub use latch::{ArmingPolicy, DisarmAuthority, Latch, ProtectedPreconditions};
pub use portal::{PortalGrant, PortalPolicy, UserAction};
pub use reconciler::{Assertion, Posture, Reconciler, TickOutcome};
pub use scope::{LocalNetworkAccess, Tier1, Tier2};
