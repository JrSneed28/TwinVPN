//! `twinvpn-core` — the composition root, and the **only** crate that may name
//! both planes (ADR-0018 CD-I5).
//!
//! **Authority:** [ADR-0018](../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! §11.4 (the ABI's command/event model), §11.6 (the seam), §11.7 (CD-I5, CD-I2,
//! CD-I4, CD-CB3), §11.8 (CD-1…CD-5), §11.12 (`core-lite`, the three version
//! numbers), §11.17 (S-46, S-47); `docs/architecture.md` §4.2 and §5;
//! `docs/reliability.md` §4 and §5.
//!
//! **Owner:** `core-composition`.
//!
//! # What this crate is
//!
//! Eight domains' worth of components exist as libraries that take their
//! capabilities and decide nothing about where those capabilities come from.
//! This crate is where they come from. Concretely:
//!
//! | Module | What it wires |
//! |---|---|
//! | [`planes`] | **CD-I5.** The control-plane client → the store → the data plane, in two one-directional ports |
//! | [`bridge`] | The single owner of `twinvpn_store::Store`, and the durable flush |
//! | [`cp_binding`] | `twinvpn-cp-client`'s `ControlPlaneStore`, bound to [`planes`] |
//! | [`journal`] | `twinvpn-session`'s `SessionJournal`, bound to the same store |
//! | [`session_loop`] | The `Env`-driven timers and the platform events that fire `twinvpn-session`'s transitions |
//! | [`events`] | **F-5.** One instance, one totally ordered event stream |
//! | [`core`] | The instance: create, submit, next_event, wake, poison (S-47) |
//! | [`build_identity`] | **S-46**, with VR-3's epoch *table* |
//! | [`lite`] | The `core-lite` profile's assertions (§11.12) |
//!
//! # CD-I5, in one sentence
//!
//! The control-plane client is wired **to the store** and the data plane **from
//! the store**, never to each other. [`planes::ControlPlanePort`] can only write;
//! [`planes::DataPlaneView`] can only read; `cargo run -p xtask -- lint` asserts
//! the crate graph beneath this one, and this crate's own tests assert the
//! direction above it.
//!
//! # CD-2, in one sentence
//!
//! Everything takes its `Env` at construction. There is no global, no
//! `OnceCell`, no ambient default, and no `Default` impl on any type that holds
//! a capability.
//!
//! # What is deliberately absent
//!
//! - **No `tracing` subscriber.** Installing one is a process-global side effect
//!   and there may be two cores in one process. The shell installs it.
//! - **No environment variable, no configuration file, no ambient locale.**
//!   CD-2. See this crate's `README.md`.
//! - **No datapath through the ABI.** PB-1: zero FFI crossings per packet. The
//!   core programs the kernel module or holds the fd; neither path passes a
//!   packet across `twinvpn.h`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod bridge;
pub mod build_identity;
pub mod core;
pub mod events;
pub mod lite;
pub mod planes;

#[cfg(feature = "full")]
pub mod dispatch;
#[cfg(feature = "full")]
pub mod establish;
#[cfg(feature = "full")]
pub(crate) mod execute;
#[cfg(feature = "full")]
pub mod session_table;

#[cfg(feature = "full")]
pub mod cp_binding;
#[cfg(feature = "full")]
pub mod journal;
#[cfg(feature = "full")]
pub mod session_loop;

#[cfg(any(test, feature = "test-support"))]
pub mod testing;

pub use build_identity::{CoreBuildIdentity, EpochRow, EPOCH_TABLE};
pub use core::{Core, CoreParts, VaultState};
pub use events::{CoreEvent, CoreEventKind, EventStream};
pub use planes::{ControlPlanePort, DataPlaneView, PeerRecord};

/// **V-B major.** The `twinvpn.h` ABI's major version.
///
/// Bumped on a removal or a semantic change (VR-1). It is declared here rather
/// than in `twinvpn-ffi` so that `CoreBuildIdentity` — which lives in this crate
/// — and the header cannot disagree about it; `twinvpn-ffi` re-exports this
/// value and `core/ffi/include/twinvpn.h` carries the same number, checked by
/// `twinvpn-ffi`'s header-drift test.
pub const ABI_MAJOR: u32 = 1;

/// **V-B minor.** Bumped on an addition (VR-1).
pub const ABI_MINOR: u32 = 0;
