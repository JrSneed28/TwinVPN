//! TwinVPN T1 architectural lints.
//!
//! **Authority:** ADR-0018 §11.7 (CD-I2, CD-I5, CD-CB3) and §11.8 (CD-3).
//!
//! ADR-0018 CD-3 is explicit that the deny-list *is* the mechanism — "a
//! violation fails the merge" — so these checks belong in the build, not in a
//! review checklist. Nothing is implemented yet; `core-foundation` owns this
//! binary and supplies the four checks:
//!
//! - **CD-3** deny-list: `SystemTime::now`, `Instant::now`, `getrandom`,
//!   thread-local RNG constructors, the runtime's time module, `chrono` now-
//!   constructors and the platform time syscalls, everywhere except
//!   `twinvpn-env`'s implementations.
//! - **CD-I2**: only `twinvpn-crypto` may declare a cryptographic dependency.
//! - **CD-I5**: no data-plane crate may reach `twinvpn-cp-client`, directly or
//!   transitively, and the reverse edge is equally denied. Only `twinvpn-core`
//!   may name both.
//! - **CD-CB3**: `#[cfg(target_os = …)]` outside `twinvpn-platform-*`.
#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    eprintln!("xtask: no lint implemented yet (owner: core-foundation)");
    std::process::ExitCode::FAILURE
}
