//! `twinvpn-diag` — the Tier-0 ring, event emission, redaction classification,
//! Tier-1 bundle assembly, and the ADR-0019 presentation resolver.
//!
//! **Authority:** [ADR-0015](../../../docs/adr/ADR-0015-observability-and-diagnostics.md)
//! in whole; [ADR-0018](../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! CB-4 (the core *resolves*; the shell *presents*) and §11.4 F-4/F-10;
//! [ADR-0019](../../../docs/adr/ADR-0019-application-state-model-and-ui-architecture.md)
//! §11.5 (LT-3, LT-4, LT-5); `contracts/proto/twinvpn/v1/diagnostics.proto`;
//! `contracts/docs/contract-matrix.md` §4.4.
//!
//! **Owner:** `core-composition`.
//!
//! # The four jobs
//!
//! | Module | Job | Authority |
//! |---|---|---|
//! | [`tier`] | which of the three tiers a record is for, and what that implies | §11.1, §11.4 |
//! | [`redact()`] | emitter-side classification and per-bundle pseudonymization | §11.4, O-14 |
//! | [`ring`] | the bounded, always-on Tier-0 ledger, whose drops are reported | §11.1, `INTERNAL.BUFFER_OVERFLOW` |
//! | [`event`] | the fourteen **local, device-authoritative** session events | contract-matrix §4.4 |
//! | [`resolve`] | code + evidence + locale + platform → sentences and attributes | CB-4, F-10, LT-3 |
//! | [`bundle`] | Tier-1 assembly and the R-23 connectivity report | §11.8, §11.9 |
//!
//! # What this crate will never do
//!
//! - **Capture a secret.** There is no `SECRET` classification to construct, no
//!   accessor that yields a key, and no path from a tunnel payload to a record.
//!   `twinvpn-crypto` and `twinvpn-trust` deliberately emit nothing and hand
//!   typed values across; nothing here asks them for more.
//! - **Reach the control plane.** The events in [`event`] are local and
//!   device-authoritative; this crate has no dependency on `twinvpn-cp-client`
//!   and ADR-0018 §11.7 places it above the composition root, so it cannot
//!   acquire one without failing `cargo run -p xtask -- lint`.
//! - **Install a `tracing` subscriber.** That is a process-global side effect and
//!   the shell's job (ADR-0018 §11.3, `core/README.md` §5).
//! - **Read an ambient locale, platform or clock.** [`resolve::render`] is pure
//!   and instance-free; every input is a parameter (CD-2, F-10).
//!
//! # Environment configuration, local startup, debugging
//!
//! This crate reads **no** environment variable and **no** configuration file.
//! Everything arrives as a parameter, which is CD-2. See this crate's
//! `README.md` for how to run it, what the catalogue is made of, and what is not
//! finished.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod bundle;
pub mod event;
pub mod redact;
pub mod resolve;
pub mod ring;
pub mod tier;

pub use bundle::{Bundle, ConnectivityReport};
pub use event::{Correlation, Emitter};
pub use redact::{redact, Pseudonymizer, RedactedEvidence, RedactedValue};
pub use resolve::{render, Binding, FallbackRung, PlatformContext, Resolved, ResolvedAttributes};
pub use ring::{Ledger, LedgerEntry, Record};
pub use tier::{disposition, Disposition, Tier};

/// The registry version this build compiled the reason-code table against.
///
/// ADR-0018 F-10 exports this over the ABI as `tw_reason_registry_version()` and
/// S-46 mirrors it, so a support case can answer "which registry" without a live
/// instance. It is re-exported rather than redeclared: one number, one source.
#[must_use]
pub const fn reason_registry_version() -> u32 {
    twinvpn_types::REASON_REGISTRY_VERSION
}
