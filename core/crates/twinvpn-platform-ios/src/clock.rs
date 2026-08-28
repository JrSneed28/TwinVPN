//! W-7's three shell-supplied capabilities on Darwin: the suspend-**inclusive**
//! clock, the platform CSPRNG, and the boot identity.
//!
//! **Authority:** `docs/implementation/ownership.md` §8 **W-7**; ADR-0022 LC-8
//! and its per-platform primitive table, LC-24; ADR-0017 MI-16; ADR-0018 CD-1,
//! CD-3, CB-3, DP-4; [`twinvpn_env::ElapsedClock`].
//!
//! # LC-8's table for this target, and the trap in it
//!
//! | Capability | Darwin primitive | Suspend |
//! |---|---|---|
//! | `MonotonicClock` | `mach_absolute_time()` / `CLOCK_UPTIME_RAW`, via `twinvpn_env::binding::system::SystemMonotonicClock` | **excluded** |
//! | `ElapsedClock` | **`mach_continuous_time()`** | **included** |
//! | `WallClock` | `CLOCK_REALTIME`, via `SystemWallClock` | n/a |
//! | `boot_id` | `sysctl kern.boottime` | n/a |
//!
//! ADR-0022 LC-8 records the trap explicitly: **"Darwin's `CLOCK_MONOTONIC` is
//! suspend-inclusive, reverse of Linux's."** A developer carrying the Linux
//! reasoning across — where `CLOCK_MONOTONIC` excludes suspend and
//! `CLOCK_BOOTTIME` includes it — picks the wrong primitive, and the resulting
//! clock "compiles, passes every test that does not suspend, and fails only on a
//! device that actually sleeps". On a phone, that is every day.
//!
//! # Who else depends on this clock being the right one
//!
//! Not only rekey windows. ADR-0017 **MI-16** requires every management response
//! and event to carry `as_of_ms` "on a **boot-time monotonic** clock", and adds
//! that "on iOS and iPadOS the containing app and the provider are different
//! processes on one device and **share `mach_continuous_time()`**, so the
//! property holds across the subset channel too". Substituting the
//! suspend-*exclusive* clock would break the staleness stamp on every value the
//! UI renders, silently, in the direction of claiming data is fresher than it is.
//!
//! [`crate::enforce::AttachToArm`] and [`crate::lifecycle::classify_start`] read
//! it too, for the same reason: a network attach and a suspension can straddle
//! each other.
//!
//! # This build host has none of it
//!
//! [`crate::sys`] refuses on Linux, and these types propagate the refusal rather
//! than fabricating a reading. That is why the tests below assert *absence* on
//! the host: a stub that returned zero would make this file look tested and the
//! product wrong on a device.

use std::sync::Arc;

use twinvpn_env::{BootId, BootIdSource, ElapsedClock, ElapsedInstant, Entropy, EnvError};

use crate::sys;

/// The suspend-**inclusive** clock: Darwin `mach_continuous_time()`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ContinuousElapsedClock;

impl ContinuousElapsedClock {
    /// Binds the clock.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Binds it as a shared capability, ready for `twinvpn_env::EnvParts`.
    #[must_use]
    pub fn shared() -> Arc<dyn ElapsedClock> {
        Arc::new(Self)
    }

    /// The raw reading, or `None` where the primitive is unreachable.
    ///
    /// Separated from [`ElapsedClock::now`] so a test can see the failure that
    /// `now` has to absorb, and so a startup posture can report the absence.
    #[must_use]
    pub fn read_micros() -> Option<u64> {
        sys::continuous_micros()
    }

    /// Whether this build can read the clock at all.
    #[must_use]
    pub fn is_available() -> bool {
        sys::darwin_primitives_available()
    }
}

impl ElapsedClock for ContinuousElapsedClock {
    fn now(&self) -> ElapsedInstant {
        // The trait gives a clock read no error channel. `mach_continuous_time`
        // does not fail on a device; if the reading is absent we are not on one.
        // ORIGIN is wrong in the safe direction: every interval measures as
        // zero, so nothing expires early — a deadline that fires late is a
        // delay, and one that fires early is a rekey that did not happen.
        ElapsedInstant::from_micros(Self::read_micros().unwrap_or(0))
    }
}

/// The platform CSPRNG: Darwin `getentropy(2)`.
///
/// [`Entropy::fill`] **never** falls back to a weaker source — not to
/// `/dev/urandom`, not to the host's RNG on a cross build. `EntropyUnavailable`
/// is propagated, because a silent downgrade here is indistinguishable from
/// working and the value it produces is the one every nonce and key depends on.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEntropy;

impl SystemEntropy {
    /// Binds the platform CSPRNG.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Binds it as a shared capability.
    #[must_use]
    pub fn shared() -> Arc<dyn Entropy> {
        Arc::new(Self)
    }

    /// Draws once so a startup failure is loud rather than deferred to the first
    /// key derivation.
    ///
    /// # Errors
    ///
    /// [`EnvError::EntropyUnavailable`].
    pub fn probe(&self) -> Result<(), EnvError> {
        let mut probe = [0u8; 32];
        self.fill(&mut probe)
    }
}

impl Entropy for SystemEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
        sys::fill_entropy(dst)
    }
}

/// The boot identity, from `sysctl kern.boottime`.
///
/// W-7's third required shell interface, and LC-24 step 1's input: "`boot_id`
/// changed ⇒ **NOT** a resume".
///
/// # Why the raw bytes are the identity
///
/// The kernel's boot `timeval` is stable for the life of a boot and differs
/// across boots, which is exactly [`BootIdSource`]'s contract. Hashing it would
/// need a digest, and CD-I2 permits a cryptographic dependency only in
/// `twinvpn-crypto`; the value is not a secret and is not compared for anything
/// but equality, so the raw bytes serve. They are read **once, at construction**
/// and cached: the value cannot change while the process lives, and a per-call
/// read would make an equality comparison depend on `sysctl` still answering.
#[derive(Debug, Clone, Copy)]
pub struct KernBootTimeId {
    id: BootId,
}

impl KernBootTimeId {
    /// The sysctl name the reading comes from.
    ///
    /// A constant so a test can assert *which* name is read: this is the whole
    /// of the boot identity, and a silent change of source would make two boots
    /// compare equal.
    pub const SOURCE: &'static str = "kern.boottime";

    /// Reads the boot identity.
    ///
    /// # Errors
    ///
    /// [`EnvError::EntropyUnavailable`] where the sysctl is unreachable — the
    /// same failure shape the shell already handles for the CSPRNG. A fabricated
    /// boot id would make "we rebooted" and "we did not" the same fact, and
    /// LC-24 classifies a whole start sequence on that distinction.
    pub fn read() -> Result<Self, EnvError> {
        let raw = sys::boot_time_raw().ok_or(EnvError::EntropyUnavailable)?;
        Ok(Self {
            id: BootId::from_array(raw),
        })
    }
}

impl BootIdSource for KernBootTimeId {
    fn boot_id(&self) -> BootId {
        self.id
    }
}

/// What the three W-7 capabilities can do on this build, declared at startup.
///
/// ADR-0016 PS-17's principle applied to the adapter: "Silently running wider
/// than declared is the defect this rule retires." A shell reports these; none
/// of them is a decision this crate makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockPosture {
    /// Whether the suspend-inclusive clock is readable.
    pub elapsed_clock_available: bool,
    /// Whether the platform CSPRNG answered a probe.
    pub entropy_available: bool,
    /// Whether the boot identity is readable.
    pub boot_id_available: bool,
}

impl ClockPosture {
    /// Probes all three.
    #[must_use]
    pub fn probe() -> Self {
        Self {
            elapsed_clock_available: ContinuousElapsedClock::read_micros().is_some(),
            entropy_available: SystemEntropy::new().probe().is_ok(),
            boot_id_available: KernBootTimeId::read().is_ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The clock-distinctness check, and an honest statement of its limit.**
    ///
    /// `mach_continuous_time` differs from `mach_absolute_time` by exactly the
    /// accumulated suspend time. On a host that has never suspended the two read
    /// the same, so no test anywhere can *prove* the right one was chosen — that
    /// is LC-8's "invisible on CI" warning, and on this build host the situation
    /// is starker still: neither primitive exists.
    ///
    /// What is checkable here, and is checked: the reading is **absent** rather
    /// than fabricated. A build that silently substituted `std::time::Instant` —
    /// which is suspend-*exclusive* on both platforms, and which CD-3 denies to
    /// this crate for exactly that reason — would report a plausible number here
    /// and would under-measure every suspension on a device.
    #[test]
    fn the_elapsed_clock_is_absent_on_this_host_rather_than_substituted() {
        assert_eq!(
            ContinuousElapsedClock::is_available(),
            cfg!(target_os = "ios")
        );
        if !ContinuousElapsedClock::is_available() {
            assert_eq!(ContinuousElapsedClock::read_micros(), None);
            // And `now()` absorbs the absence at ORIGIN, which is wrong in the
            // safe direction: every interval measures zero, so nothing expires
            // early.
            assert_eq!(
                ContinuousElapsedClock::new().now(),
                ElapsedInstant::from_micros(0)
            );
        }
    }

    #[test]
    fn the_entropy_source_never_falls_back_to_a_weaker_one() {
        let entropy = SystemEntropy::new();
        let mut buf = [0u8; 32];
        let result = entropy.fill(&mut buf);
        if ContinuousElapsedClock::is_available() {
            assert!(result.is_ok());
        } else {
            assert_eq!(result, Err(EnvError::EntropyUnavailable));
            assert_eq!(
                buf, [0u8; 32],
                "a refused draw writes nothing; it does not half-fill"
            );
        }
        // A zero-length fill is a no-op on every target.
        assert!(entropy.fill(&mut []).is_ok());
    }

    #[test]
    fn a_boot_identity_is_never_fabricated() {
        let read = KernBootTimeId::read();
        if ContinuousElapsedClock::is_available() {
            let a = read.expect("reads");
            let b = KernBootTimeId::read().expect("reads");
            assert_eq!(a.boot_id(), b.boot_id(), "stable within one boot");
        } else {
            assert!(
                read.is_err(),
                "an invented boot id makes 'we rebooted' and 'we did not' the \
                 same fact, and LC-24 classifies a whole start sequence on it"
            );
        }
        assert_eq!(KernBootTimeId::SOURCE, "kern.boottime");
    }

    #[test]
    fn the_posture_is_declared_rather_than_discovered_by_a_user() {
        let posture = ClockPosture::probe();
        let expected = cfg!(target_os = "ios");
        assert_eq!(posture.elapsed_clock_available, expected);
        assert_eq!(posture.entropy_available, expected);
        assert_eq!(posture.boot_id_available, expected);
    }
}
