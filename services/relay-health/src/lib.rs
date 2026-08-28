//! `twinvpn-relay-health` — S-10, relay health aggregated from self-reports.
//!
//! **Owner:** `relay-plane`.
//!
//! # The one rule that shapes every type here
//!
//! `relay.proto`'s `RelayHealth` message:
//!
//! > CONSISTENCY: EVENTUAL. Freshest observation wins, and **A CLIENT'S OWN PROBE
//! > FAILURE ALWAYS OUTRANKS A "HEALTHY" REPORT.** Per `docs/reliability.md` §4.1
//! > this MUST NOT gate a connection attempt — it contributes a score delta to
//! > selection and nothing more.
//!
//! ADR-0006 §11.3 rule 1 says the same from the selection side: an `UNHEALTHY`
//! state "MUST NOT suppress a connection attempt".
//!
//! So this crate has **no API that returns a boolean, a filtered list, or an
//! admission decision**. [`aggregate::Aggregate::state_for`] returns a
//! [`aggregate::HealthState`], and the only thing that can be done with one is
//! [`aggregate::HealthState::score_delta`]. There is no `is_usable`, no
//! `is_healthy`, no `candidates()` and no `filter()` — because a gate that does
//! not exist cannot be added by accident, and `tests/never_a_gate.rs` asserts the
//! absence rather than trusting it.
//!
//! # `EVENTUAL`, non-durable, recomputed
//!
//! S-10's class. Nothing here is written to a datastore: the aggregate is rebuilt
//! from self-reports every interval, and losing it costs one interval of ranking
//! quality. **A relay-health outage must degrade ranking quality and nothing
//! else** — `Unknown` contributes a delta of exactly **0**, so a fleet whose
//! health service is down ranks by measurement alone, which is what a device
//! should be doing anyway.
//!
//! # No per-session or peer-pair label, ever
//!
//! `relay.proto`: "ADR-0015 O-13 forbids any per-session or peer-pair label on
//! relay telemetry, so this message carries no `session_id`, no `pair_tag`, and no
//! device identifier." [`aggregate::SelfReport`] carries a `relay_id`, a
//! `load_class`, an observation timestamp and reachability — and nothing else.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod aggregate;
pub mod config;

pub use aggregate::{Aggregate, HealthState, SelfReport};
pub use config::{HealthConfig, HealthConfigError};

/// The component every `ServiceError` from this crate is observed by.
pub const COMPONENT: twinvpn_types::Component = twinvpn_types::Component::RelaySelection;
