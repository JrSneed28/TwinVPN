//! `twinvpn-presence` — the device-presence aggregator.
//!
//! **Owner:** `rendezvous-connectivity` (`docs/implementation/ownership.md` §2).
//!
//! # A hint service, never an authority
//!
//! `docs/architecture.md` §2.13 states the whole of it: presence answers "is
//! peer X likely online" and it **"MUST NOT gate connection attempts —
//! 'presence says offline' MUST NOT prevent an attempt"**, because presence is
//! eventually consistent and can be wrong. Its unavailability "degrades
//! reconnect *latency*, not reconnect *capability*".
//!
//! That is not a caveat on the design; it *is* the design, and it is enforced
//! structurally rather than by care: nothing on the connection path depends on
//! this crate. `tests/never_a_gate.rs` asserts that by reading the rendezvous's
//! own manifest.
//!
//! # S-11: the device is authoritative for its own presence
//!
//! `presence.proto`: "a device may assert presence **only for itself**. A
//! `Presence` naming another `device_id` is rejected." [`ingress`] enforces it
//! and classifies a violation as `CONTROL.EVENT_WRONG_PUBLISHER` — FATAL,
//! CRITICAL, a security event, never a parse error.
//!
//! # Ephemeral, and why there is no durable variant
//!
//! `docs/protocol.md` §6.1 gives three independent reasons, and the third is the
//! one that shapes this crate's dependency list: *"a durable presence log is a
//! **permanent movement and IP-address history of the Owner**, held by
//! infrastructure. Infrastructure that cannot read your traffic but can
//! reconstruct where you were every hour for two years has not achieved zero
//! knowledge."*
//!
//! So [`store`] is a bounded in-memory table with an absolute expiry and no
//! history, this crate declares no database client, and `Cargo.toml` says why.
//!
//! # No ordering guarantee
//!
//! `docs/protocol.md` §9.2: **"NO ORDERING GUARANTEE — consumers MUST tolerate
//! reordering"**, which is exactly why `PeerOnline`/`PeerOffline` are values of
//! `PresenceState` inside one `PresenceUpdated` rather than two events. This
//! service publishes that one shape and no other; see [`store::Store::apply`]
//! for how a reordered pair still settles on the right answer.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]

pub mod config;
pub mod frame;
pub mod ingress;
pub mod server;
pub mod store;
pub mod testkit;

/// The `errors.proto` component this service reports itself as.
pub const COMPONENT: twinvpn_types::Component = twinvpn_types::Component::Presence;

/// The `errors.proto` enum name `ServiceConfig::load` wants.
pub const COMPONENT_NAME: &str = "COMPONENT_PRESENCE";

/// The default `TWINVPN_SERVICE_NAME`, matching `docker-compose.yml`.
pub const SERVICE_NAME: &str = "presence";
