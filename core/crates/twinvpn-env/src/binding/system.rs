//! The `std`-only clock bindings, and the adapter for the one clock `std`
//! cannot provide.
//!
//! Every deny-listed call in the workspace lives in this file and its sibling.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::clock::{
    ElapsedClock, ElapsedInstant, MonotonicClock, MonotonicInstant, OffsetSource, WallClock,
    WallClockReading, WallMillis,
};

/// The suspend-**exclusive** monotonic clock, over `std::time::Instant`.
///
/// ADR-0018 §11.8 reason 2 is why this is the *only* correct use of `Instant`:
/// it is `CLOCK_MONOTONIC` on Linux and `mach_absolute_time()` on Darwin, both
/// suspend-exclusive — right for this clock, "silently wrong for anything needing
/// the gap".
///
/// Windows note, from LC-8: the primitive there is
/// `QueryUnbiasedInterruptTimePrecise`, where **"unbiased" means sleep is
/// excluded**. An earlier draft of LC-8 attributed it to the inclusive clock;
/// that was backwards. Rust's `Instant` on Windows uses `QueryPerformanceCounter`,
/// which does *not* exclude sleep, so a Windows shell **must** supply its own
/// `MonotonicClock` rather than take this one.
pub struct SystemMonotonicClock {
    origin: Instant,
}

impl SystemMonotonicClock {
    /// Fixes this clock's origin at the moment of construction.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemMonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn now(&self) -> MonotonicInstant {
        let micros = self.origin.elapsed().as_micros();
        MonotonicInstant::from_micros(u64::try_from(micros).unwrap_or(u64::MAX))
    }
}

/// The wall clock, over `std::time::SystemTime`.
///
/// # Why `Trusted` is not the default
///
/// CD-1a exists because most `GC-0` hardware has no RTC and boots to epoch 0 on
/// every power cycle. `SystemTime::now()` on such a device returns a time near
/// the epoch and says nothing about whether it is real, so this binding takes the
/// platform's synchronisation claim as a **constructor argument** rather than
/// assuming one. A shell that cannot answer "is this clock synchronised" passes
/// [`WallClockTrust::Unsynchronised`], and the reading is `Unset` below the
/// plausibility floor — which is the correct answer, not a degraded one.
pub struct SystemWallClock {
    trust: WallClockTrust,
}

/// What the platform claims about its own wall clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WallClockTrust {
    /// The platform reports the clock as synchronised (NTP, cellular, or an RTC
    /// the platform vouches for).
    Synchronised,
    /// The platform makes no such claim. A reading is reported as
    /// [`WallClockReading::Offset`] with the given source when it is plausible,
    /// and [`WallClockReading::Unset`] when it is not.
    Unsynchronised(OffsetSource),
}

/// The plausibility floor: 2020-01-01T00:00:00Z in UTC milliseconds.
///
/// Below this, the clock has not been set. The floor is a **constant**, not a
/// build timestamp: a build timestamp would make an old artifact reject a correct
/// clock, and it would make the artifact non-reproducible (§11.10).
pub const WALL_CLOCK_PLAUSIBILITY_FLOOR_MS: u64 = 1_577_836_800_000;

impl SystemWallClock {
    /// Binds a wall clock with the platform's synchronisation claim.
    #[must_use]
    pub const fn new(trust: WallClockTrust) -> Self {
        Self { trust }
    }
}

impl WallClock for SystemWallClock {
    fn now(&self) -> WallClockReading {
        let Ok(since) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            // Before the epoch. Not a plausible time; not a timestamp to report.
            return WallClockReading::Unset;
        };
        let millis = u64::try_from(since.as_millis()).unwrap_or(u64::MAX);
        if millis < WALL_CLOCK_PLAUSIBILITY_FLOOR_MS {
            return WallClockReading::Unset;
        }
        match self.trust {
            WallClockTrust::Synchronised => WallClockReading::Trusted {
                millis: WallMillis::from_millis(millis),
            },
            WallClockTrust::Unsynchronised(source) => WallClockReading::Offset {
                millis: WallMillis::from_millis(millis),
                source,
            },
        }
    }
}

/// Adapts a platform-supplied suspend-**inclusive** reader to [`ElapsedClock`].
///
/// # Why there is no `SystemElapsedClock`
///
/// `std` has no suspend-inclusive clock. The primitive is per-platform — Linux
/// and Android `CLOCK_BOOTTIME`, Darwin `mach_continuous_time()`, Windows
/// `QueryInterruptTimePrecise` — and reaching any of them from here would need
/// either `unsafe` (which `#![forbid(unsafe_code)]` rules out) or a
/// `#[cfg(target_os)]` branch (which CB-3 rules out above the adapter).
///
/// So the shell reads it and passes the reader in. This is not a workaround: it
/// is LC-8's per-platform table landing where CB-1 says platform-specific code
/// belongs.
///
/// **Getting this wrong is invisible on Linux CI.** Substituting the monotonic
/// clock here compiles, passes every test that does not suspend, and fails only
/// on a device that actually sleeps — which is why this crate ships no default
/// and forces the shell to supply one.
pub struct ElapsedClockFn<F> {
    read: F,
}

impl<F> ElapsedClockFn<F>
where
    F: Fn() -> ElapsedInstant + Send + Sync,
{
    /// Wraps a platform reader.
    pub const fn new(read: F) -> Self {
        Self { read }
    }

    /// Wraps a platform reader as a shared capability.
    pub fn shared(read: F) -> Arc<dyn ElapsedClock>
    where
        F: 'static,
    {
        Arc::new(Self::new(read))
    }
}

impl<F> ElapsedClock for ElapsedClockFn<F>
where
    F: Fn() -> ElapsedInstant + Send + Sync,
{
    fn now(&self) -> ElapsedInstant {
        (self.read)()
    }
}
