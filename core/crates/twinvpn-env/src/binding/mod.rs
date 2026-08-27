//! Capability bindings.
//!
//! # This directory is the CD-3 exception, and it is the only one
//!
//! ADR-0018 CD-3 runs a deny-list — `SystemTime::now`, `Instant::now`,
//! `getrandom`, thread-local RNG constructors, the runtime's own time module,
//! `chrono` now-constructors and the platform time syscalls — over the whole
//! workspace "excluding `twinvpn-env`'s implementations". `cargo run -p xtask --
//! lint` implements that exclusion as **this path and no other**:
//! `core/crates/twinvpn-env/src/binding/**`. A deny-listed call anywhere else,
//! including elsewhere in this crate, fails the merge.
//!
//! Keeping the exception to one directory is what makes CD-3 answerable: the
//! reviewer's question "where does this build read the clock" has a directory as
//! its answer rather than a search.
//!
//! # What is here, and what is deliberately not
//!
//! | Capability | Binding | Why |
//! |---|---|---|
//! | [`MonotonicClock`](crate::MonotonicClock) | [`system::SystemMonotonicClock`] | `std::time::Instant` is suspend-exclusive on Linux and Darwin, which is exactly this clock's contract |
//! | [`WallClock`](crate::WallClock) | [`system::SystemWallClock`] | `SystemTime::now`, reported as `Trusted` or `Offset` per the platform's own synchronisation claim |
//! | [`ElapsedClock`](crate::ElapsedClock) | **none** — [`system::ElapsedClockFn`] adapts a platform-supplied reader | `std` has no suspend-inclusive clock; the primitive is `CLOCK_BOOTTIME` / `mach_continuous_time()` / `QueryInterruptTimePrecise`, which needs a syscall (`#![forbid(unsafe_code)]`) or an OS branch (CB-3) |
//! | [`Entropy`](crate::Entropy) | **none** | CD-3 bans `getrandom`; the shell supplies the CSPRNG |
//! | [`Runtime`](crate::Runtime), [`Timer`](crate::Timer) | [`tokio_rt`] | ADR-0018 §11.3's two bindings |
//! | virtual time | [`crate::virtual_time`] | behind the `test-support` feature |

pub mod system;

#[cfg(feature = "runtime-tokio")]
pub mod tokio_rt;
