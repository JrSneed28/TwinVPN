//! `twinvpn-route` — address plan, route computation, MTU, and conflict
//! resolution, **for both families equally**.
//!
//! **Authority:** ADR-0010 (the whole ADR; R1 above all),
//! `docs/networking.md` §2, §6, §7; ADR-0008 N-8; ADR-0018 CB-2, CB-3, §11.7.
//!
//! **Owner:** `core-dataplane`.
//!
//! # R1 is the shape of this crate, not a feature of it
//!
//! > Every `Device` MUST have both an IPv4 and an IPv6 overlay address, always,
//! > regardless of underlay family.
//!
//! There is no `v4` module and no `v6` module. [`plan::overlay_addresses`]
//! returns a `twinvpn_types::OverlayAddresses`, whose two fields are both
//! non-optional; [`program::RoutePlan`] holds `PerFamily<Vec<RouteEntry>>`;
//! [`mtu::Carriage::overlay_ceiling`] takes the family as a parameter rather
//! than having two functions. Forgetting the v6 half is a compile error in every
//! one of those places, which is what ADR-0010 §11.3 means by calling a
//! one-family install "non-conforming".
//!
//! # What this crate computes, and what installs it
//!
//! CB-6 splits it: **the core computes the desired generation, the adapter
//! installs it, the OS holds it.** So [`program::compute`] returns a
//! [`program::RoutePlan`] and never touches an interface. `twinvpn-enforce`
//! assembles the plan, the resolver configuration and the ruleset into the one
//! `twinvpn_platform::NetworkContract` that `apply()` installs atomically —
//! "partial application is the leak window" (`networking.md` §2.3).
//!
//! # No `#[cfg(target_os)]`
//!
//! CB-3. ADR-0010 §11.3's per-platform table is the *adapter's* concern; this
//! crate emits prefixes and interface indices and never asks which OS it is on.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]

pub mod conflict;
pub mod error;
pub mod mtu;
pub mod plan;
pub mod program;

pub use conflict::{Candidate, Conflict, Resolution, Source};
pub use error::RouteError;
pub use mtu::{Carriage, Dplpmtud, ProbeOutcome};
pub use plan::{PlanError, V6InterfaceIdSource, MTU_FLOOR};
pub use program::{PlanInputs, RoutePlan, RoutingMode};
