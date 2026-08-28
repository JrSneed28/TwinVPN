//! `twinvpn-mgmt` — the local management interface's **vocabulary**, and the
//! catalogue derived from it.
//!
//! **Authority:** [ADR-0017](../../../docs/adr/ADR-0017-local-management-interface.md)
//! MI-1, MI-15, MI-20, MI-21, §11.5, §11.7, §11.9, §11.12;
//! [ADR-0018](../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! §11.4 F-5 and §11.16 (b) and (o); `contracts/docs/phase1-conflicts.md` OQ-2.
//!
//! **Owner:** `core-composition`.
//!
//! # One contract, two carriages
//!
//! ADR-0018 §11.16 (b) asks ADR-0017 for *"a transport for the command/event port
//! that carries **the same command set** the core exposes over the ABI — one
//! contract, two carriages, **never two contracts**"*. MI-20 grants it in terms:
//! the MI catalogue is **derived from the core's command/event set**, not
//! specified beside it.
//!
//! This crate is where that becomes structural:
//!
//! ```text
//!            twinvpn-mgmt::CoreCommand          <- the one vocabulary
//!                   |                    \
//!                   |                     \
//!   twinvpn-core dispatches it     twinvpn-mgmt::catalogue derives from it
//!                   |                      (exhaustive match, no wildcard)
//!            twinvpn-ffi carries it                     |
//!             over tw_core_submit               the CLI verb table (MI-C1)
//! ```
//!
//! There is **no second list of operations anywhere in this crate**. Adding a
//! core command without a catalogue row is a compile error, not a review finding.
//!
//! # What this crate deliberately does not contain
//!
//! - **No transport schema.** `contracts/docs/phase1-conflicts.md` OQ-2 excluded
//!   one from Phase 2 precisely so the MI could not acquire an independent
//!   vocabulary. None is created here: the catalogue is a runtime object over the
//!   command set, and framing belongs to whoever carries it.
//! - **No rendered human text (MI-15).** Nothing in this crate produces a
//!   sentence. Codes and typed evidence only; rendering is
//!   [`twinvpn_diag::render`]'s, on the consumer's own side of the boundary.
//! - **No fifth transport operation.** MI-21's set is closed at four and
//!   [`transport::assert_closed`] says so at runtime as well as in the type.
//!
//! # Environment configuration, local startup, debugging
//!
//! This crate reads no environment variable and no configuration file (CD-2).
//! See its `README.md`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod catalogue;
pub mod codes;
pub mod command;
pub mod transport;

pub use catalogue::{catalogue, catalogue_digest, entry, Delivery, Entry, Idempotency, Scope};
pub use codes::{substituted, Substitution, SUBSTITUTIONS};
pub use command::{CoreCommand, Submission};
pub use transport::{assert_closed, TransportOp};
