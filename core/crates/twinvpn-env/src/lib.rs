//! `twinvpn-env` — the ONLY source of time, timers, randomness and the runtime.
//!
//! **Authority:** ADR-0018 §11.8 (CD-1, CD-1a, CD-2, CD-3, CD-4, CD-5, CD-6),
//! §11.3 (the runtime bindings), ADR-0022 LC-8 / I-03b (the three clocks and
//! their per-platform primitives), `docs/architecture.md` §5.2 (R-DET-1),
//! `docs/testing-strategy.md` §3.5 (seeded streams).
//!
//! **Owner:** `core-foundation`.
//!
//! # R-DET-1, in one sentence
//!
//! > Every component MUST take wall-clock time, monotonic time, elapsed time,
//! > **timers**, and randomness from a source **bound at construction**. No
//! > component may read a global, an ambient default, or a process-wide
//! > singleton for any of them.
//!
//! Four properties make that non-obvious, and each has a mechanism here:
//!
//! | R-DET-1 property | Mechanism |
//! |---|---|
//! | A timer is not a clock read | [`Timer`] is its own capability; CD-3 bans the runtime's time module outside `src/binding/` |
//! | "Injectable" is not "bound at construction" | [`Env`] has no `Default`, no global, and no partial constructor |
//! | The obligation is on the consumers | every component takes [`Env`], not just the two that implement clocks |
//! | "A clock" is three clocks | [`MonotonicClock`], [`ElapsedClock`], [`WallClock`] are distinct types with **no conversion** |
//!
//! # The one-paragraph version for a caller
//!
//! Take an [`Env`] at construction. Ask it for [`Env::now_monotonic`] to drive a
//! timer, [`Env::now_elapsed`] to measure across a suspend or to check a
//! long-horizon policy deadline, and [`Env::now_wall`] for evidence — which
//! returns a three-state value, and to evaluate a validity window you must first
//! turn it into a [`ValidityClock`], which cannot be built from `Unset`. Ask for
//! randomness with [`Env::rng_for`] and a `const` [`ConsumerId`].
//!
//! # Features
//!
//! | Feature | Default | Contents |
//! |---|---|---|
//! | `runtime-tokio` | **yes** | ADR-0018 §11.3's work-stealing and single-threaded [`Runtime`] bindings, and the [`Timer`] over them |
//! | `test-support` | no | [`virtual_time::VirtualTime`] — the virtual-clock driver TwinLab drives, including [`virtual_time::VirtualTime::suspend`], which advances the elapsed and wall clocks while leaving the monotonic clock exactly where it was |
//!
//! # What this crate deliberately does not provide
//!
//! - **A production [`ElapsedClock`].** `std` has no suspend-inclusive clock, and
//!   reaching `CLOCK_BOOTTIME` needs `unsafe` or a `#[cfg(target_os)]` branch —
//!   forbidden here by DP-4 and CB-3 respectively. The shell supplies it through
//!   [`binding::system::ElapsedClockFn`]. Substituting the monotonic clock
//!   compiles and is invisible on Linux CI, which is why there is no default.
//! - **A production [`Entropy`].** CD-3 bans `getrandom`; the shell supplies the
//!   platform CSPRNG.
//! - **An HKDF implementation.** CD-I2 restricts cryptographic dependencies to
//!   `twinvpn-crypto`, and §11.7's arrow already points from `twinvpn-crypto` to
//!   this crate, so an implementation here would be a cycle. CD-4's derivation is
//!   supplied by the binding through [`StreamDerivation`]; see [`rng`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// See `twinvpn-types`: these two fire on product nouns in prose and on a
// uniform error type respectively.
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod binding;
pub mod clock;
pub mod env;
pub mod error;
pub mod rng;
pub mod task;

#[cfg(feature = "test-support")]
pub mod virtual_time;

pub use clock::{
    BootId, BootIdSource, ElapsedClock, ElapsedInstant, MonotonicClock, MonotonicInstant,
    OffsetSource, ValidityClock, ValidityWindow, WallClock, WallClockConfidence, WallClockReading,
    WallMillis, WindowVerdict,
};
pub use env::{Env, EnvParts};
pub use error::EnvError;
pub use rng::{
    consumers, ConsumerId, Entropy, Rng, RngSource, SeededRngSource, StreamDerivation,
    SystemRngSource, CD4_INFO_PREFIX,
};
pub use task::{Abort, JoinHandle, Runtime, RuntimeKind, Timer};
