//! `twinvpn-platform-windows` — the Windows implementation of the
//! `twinvpn-platform` trait. **This crate is the seam** (ADR-0018 §11.6).
//!
//! **Authority:** ADR-0018 §11.6 (the seam in both directions), §11.2 row 2.5,
//! CB-1, CB-2, CB-3, CB-5, CB-6, CB-6a, CB-7, CD-2, CD-3, DP-4;
//! `docs/application-architecture.md` §7's Windows row (HC-1, `TwinVPNService`
//! under LocalSystem with trimmed privileges, a WFP sublayer with persistent and
//! boot-time filters, a named pipe with an explicit DACL, MSI + Authenticode EV);
//! ADR-0010, ADR-0011, ADR-0012, ADR-0016, ADR-0020, ADR-0022 LC-8.
//!
//! **Owner:** `desktop-windows`.
//!
//! # The one thing to know before reading this crate
//!
//! **It was written on a Linux host and has never been linked or run.**
//! `make cross-check` type-checks it against the real `windows-sys` for
//! `x86_64-pc-windows-msvc` with `-D warnings`, which is a genuine compile proof
//! and is not a behaviour proof. The crate is therefore laid out so that the
//! largest possible share of its behaviour is **target-free and host-testable**,
//! and so that the part which genuinely cannot be is as small and as obvious as
//! possible.
//!
//! | Layer | Target-free | Where |
//! |---|---|---|
//! | what a Windows status *means* | yes | [`oserr`] |
//! | which filters a contract implies | yes | [`wfp::filters`] |
//! | what the engine's own answer says is installed | yes | [`wfp::readback`] |
//! | the leak canary's arithmetic | yes | [`wfp::canary`] |
//! | the KS-19 boot artifact, and its verification | yes | [`wfp::boot`] |
//! | which route rows a contract implies, and their rollback | yes | [`route`] |
//! | which NRPT rules and interface settings a `DnsConfig` implies | yes | [`dns`] |
//! | the DN-18 restore point, on disk and back | yes | [`restore`] |
//! | the transactional apply/rollback/reconcile state machine | yes | [`netcfg`] |
//! | socket options as a programme | yes | [`sock`] |
//! | interface-change decoding and `LinkClass` | yes | [`iface`] |
//! | custody classes and the store root's attributes | yes | [`custody`] |
//! | **the syscall shim** | **no** | [`sys`] |
//!
//! Every trait in [`sys`] has an in-memory implementation behind the
//! `test-support` feature, which is what lets the layers above it be exercised
//! end to end on this host. `WindowsPlatformAdapter::new` constructs the **real**
//! shim and there is no path by which a fake reaches a production build.
//!
//! # CB-3 and DP-4
//!
//! This crate is on the `unsafe` allowlist and is one of the few permitted
//! `#[cfg(target_os)]`. It uses both only inside [`sys::win`], and every `unsafe`
//! block there carries a `// SAFETY:` comment naming its invariant. Everything
//! else in the crate is safe, portable Rust.
//!
//! # CD-3, and W-36
//!
//! [`clock`] names `QueryUnbiasedInterruptTimePrecise`,
//! `QueryInterruptTimePrecise` and `BCryptGenRandom`. The first two are on
//! `core/xtask/src/checks.rs`'s `CD3_PLATFORM_PRIMITIVES` list, which
//! `cd3_crate_may_read_platform_primitives` permits in a `twinvpn-platform-*`
//! crate — the exemption W-36 established for exactly this. What stays denied
//! even here is `Instant::now`, `SystemTime::now`, `tokio::time` and `chrono`,
//! and none of them appears in this crate.

// DP-4 unsafe allowlist member: `unsafe` is permitted here and NOWHERE else
// outside the two sibling adapter crates. Every `unsafe` block MUST carry a
// `// SAFETY:` comment stating the invariant it relies on.
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// Product nouns in prose, and a single uniform error type across the crate.
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod clock;
pub mod custody;
pub mod dns;
pub mod iface;
pub mod netcfg;
pub mod oserr;
pub mod restore;
pub mod route;
pub mod shutdown;
pub mod sock;
pub mod sys;
pub mod wfp;
pub mod wintun;

pub use shutdown::ShutdownLatch;
pub use wfp::{EnforcementConfig, FilterSet, Ruleset};

/// The name prefix every TwinVPN overlay adapter carries.
///
/// `is_overlay` is answered by this prefix and not by the adapter's driver
/// identity: a Wintun adapter created by another product is a third party's, and
/// treating it as ours would make ADR-0012's Tier-2 interface-scoped permit
/// authorise somebody else's tunnel.
pub const OVERLAY_PREFIX: &str = "TwinVPN";

/// The binding name recorded in `CoreBuildIdentity` (S-46).
///
/// Stable and non-localised, so a support case can answer "which adapter was
/// loaded" from the bundle rather than from an inference.
pub const BINDING_NAME: &str = "windows-wfp";
