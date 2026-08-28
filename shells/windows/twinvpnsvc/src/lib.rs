//! `twinvpnsvc` — the library half: **the MI contract, declared once**.
//!
//! **Authority:** [ADR-0017](../../../../docs/adr/ADR-0017-local-management-interface.md)
//! MI-20 ("one contract, two carriages, **never two contracts**"), ADR-0018
//! §11.16 (b), ADR-0016 §11.2's Windows row.
//!
//! # Why the service is a library as well as a binary
//!
//! `twinvpnctl` depends on this crate with `default-features = false`, which
//! excludes the whole `service` feature — so the unprivileged CLI links no
//! Wintun, no WFP, no IP Helper and no core-hosting code, and both binaries
//! speak the MI from **one** definition. A copy of the framing in each binary
//! would be the second contract MI-20 forbids, and it would drift the first time
//! one side gained a field.
//!
//! # `unsafe` in this crate, and how it differs from `shells/linux`
//!
//! `shells/linux` carries `#![forbid(unsafe_code)]`, and it can: `tokio` gives
//! it `UnixListener` and `UnixStream::peer_cred()`, so every privileged
//! operation the Linux agent performs has a safe wrapper somebody else wrote.
//!
//! **There is no equivalent on this platform.** SCM registration
//! (`StartServiceCtrlDispatcherW`), the pipe's security descriptor
//! (`ConvertStringSecurityDescriptorToSecurityDescriptorW`), the client-token
//! check (`GetNamedPipeClientProcessId`, `ImpersonateNamedPipeClient`), the
//! console-seat rule (`WTSQuerySessionInformationW`) and the power events
//! (`SERVICE_CONTROL_POWEREVENT`) are all raw `windows-sys` calls, and every one
//! of them is `unsafe`.
//!
//! So this crate takes the adapter's discipline instead of the Linux shell's:
//! `unsafe` is confined to [`win32`], which is the only module that names
//! Windows, every block in it carries a `// SAFETY:` comment stating its
//! invariant, and `#![deny(unsafe_op_in_unsafe_fn)]` is on. **This is a
//! deviation from `shells/linux`'s posture and it is stated here rather than
//! discovered by a reader** — see this shell's `README.md` §7.
//!
//! Everything above [`win32`] — the MI envelope and its framing, the DACL as an
//! SDDL value, the scope arithmetic, the start sequence, the exit-code mapping —
//! is safe, portable Rust, and its tests run on a Linux host.
//!
//! # CB-2: this shell holds no decision
//!
//! A shell may translate, marshal, schedule and render. It must not contain a
//! branch whose condition is a TwinVPN domain fact — not a `ConnectionState`,
//! not a `reason_code` class, not a policy verdict, not a candidate priority,
//! not a timer expiry, not a version comparison. The falsification test is the
//! design target: with every shell deleted and a mock adapter bound, the core
//! must still decide everything.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// Product nouns in prose, and a single uniform error type across the crate.
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod mi;

#[cfg(feature = "service")]
pub mod service;

#[cfg(all(feature = "service", windows))]
pub mod win32;

/// The client kind this crate's own `Hello` announces.
///
/// Diagnostic only, per ADR-0017 §11.7 — it appears in the agent's log so a
/// support case can say which surface asked, and it grants nothing.
pub const AGENT_CLIENT_KIND: &str = "agent";

/// The service's name, as the SCM knows it.
///
/// ADR-0016 §11.2's Windows row fixes it: the service SID is
/// `NT SERVICE\TwinVPNService`, which the SCM derives from exactly this string,
/// so changing it changes the principal every ACL and every
/// `FWPM_CONDITION_ALE_USER_ID` names.
pub const SERVICE_NAME: &str = "TwinVPNService";

/// The display name the Services console shows.
pub const SERVICE_DISPLAY_NAME: &str = "TwinVPN";
