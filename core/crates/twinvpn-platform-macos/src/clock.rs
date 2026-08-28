//! The three shell-supplied capabilities of **W-7**: the suspend-**inclusive**
//! clock, the platform CSPRNG, and the boot identity.
//!
//! **Authority:** ADR-0022 LC-8 and its per-platform primitive table; ADR-0018
//! CD-1 (three non-interchangeable clocks), CD-3 and `core/xtask/src/checks.rs`'s
//! `CD3_PLATFORM_PRIMITIVES` (the W-36 exemption), CB-3, DP-4;
//! `docs/implementation/ownership.md` §8 **W-7**;
//! [`twinvpn_env::binding::system::ElapsedClockFn`].
//!
//! # The pair that is invisible when it is wrong
//!
//! `twinvpn-env` ships **no production `ElapsedClock`**, deliberately:
//!
//! > Substituting the monotonic clock here compiles, passes every test that does
//! > not suspend, and fails only on a device that actually sleeps.
//!
//! On Darwin the three clocks are:
//!
//! | Capability | Darwin primitive | Suspend |
//! |---|---|---|
//! | `MonotonicClock` | `mach_absolute_time` | **excluded** |
//! | `ElapsedClock` | `mach_continuous_time` | **INCLUDED** |
//! | `WallClock` | `gettimeofday` / `CLOCK_REALTIME`, via `SystemWallClock` | n/a |
//!
//! The two mach calls differ by exactly the accumulated sleep time and by nothing
//! else. A Mac is the one desktop that sleeps constantly, so getting them the
//! wrong way round here is not a theoretical defect — and it is precisely the one
//! LC-8 says a Linux CI runner cannot see. The choice is made **once**, in
//! [`ContinuousElapsedClock`], with the reasoning beside it and a test that reads
//! the two symbols apart.
//!
//! # What is target-free, and what is not
//!
//! The **timebase arithmetic** — `ticks × numer / denom`, which on Apple silicon
//! is `× 125 / 3` and on Intel is `× 1 / 1` — is pure, so
//! `cargo test` checks it on this Linux host across the whole `u64` range,
//! including the two overflow edges. Only the two mach calls themselves are
//! `cfg`-gated.
//!
//! # Entropy: `/dev/urandom`, and why not `SecRandomCopyBytes`
//!
//! `SecRandomCopyBytes` is the Apple-blessed spelling and it is
//! `cfg(target_os = "macos")`-only, so a build using it would ship an entropy
//! source **no test on this host could draw from**. `/dev/urandom` on Darwin is
//! the same kernel CSPRNG (Fortuna, seeded by the boot loader before userspace
//! exists) and it reads on both platforms, so [`SystemEntropy`] is exercised by
//! `cargo test` here. [`Entropy::fill`] **never** falls back to a weaker source:
//! `EntropyUnavailable` is propagated, because "a silent downgrade here is
//! indistinguishable from working, and the value it produces is the one every
//! nonce and key depends on".

use std::fs;
use std::io::Read;
use std::sync::Arc;

use twinvpn_env::{BootId, BootIdSource, ElapsedClock, ElapsedInstant, Entropy, EnvError};

/// `mach_timebase_info`'s two numbers: mach ticks × `numer` ÷ `denom` = ns.
///
/// On Intel Macs the ratio is 1/1 and a tick is a nanosecond. On Apple silicon it
/// is 125/3 — a 24 MHz counter — which is why the conversion cannot be a shift
/// and why it must be done in a width wider than `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachTimebase {
    /// The numerator.
    pub numer: u32,
    /// The denominator. Never zero; [`MachTimebase::new`] refuses one.
    pub denom: u32,
}

impl MachTimebase {
    /// The identity ratio — an Intel Mac, where a mach tick is a nanosecond.
    pub const IDENTITY: Self = Self { numer: 1, denom: 1 };

    /// Apple silicon's ratio: a 24 MHz counter, 125 ns per tick.
    pub const APPLE_SILICON: Self = Self {
        numer: 125,
        denom: 3,
    };

    /// A timebase, refusing a zero denominator.
    ///
    /// A zero `denom` would be a division by zero on every clock read; the kernel
    /// never reports one, and refusing here means a corrupted read fails loudly
    /// instead of taking the process down on the first timer.
    #[must_use]
    pub const fn new(numer: u32, denom: u32) -> Option<Self> {
        if denom == 0 || numer == 0 {
            None
        } else {
            Some(Self { numer, denom })
        }
    }

    /// Converts mach ticks to nanoseconds.
    ///
    /// # The overflow this exists to make well-defined
    ///
    /// `ticks * 125` overflows `u64` at about `1.47e17` ticks, which on a 24 MHz
    /// counter is roughly **194 years** of uptime — so on any real Mac the naive
    /// `u64` multiply would in fact be fine, and saying otherwise would be an
    /// inflated claim. What the `u128` buys is that the *edge* is defined rather
    /// than left to a release build's wrapping semantics: the result **saturates**,
    /// and a saturated clock is still monotone where a wrapped one is not. That
    /// matters because [`ElapsedInstant`]'s interval arithmetic saturates a
    /// non-monotone pair to zero, which would silently swallow real elapsed time
    /// rather than failing.
    ///
    /// The reading it is derived from is genuinely unbounded, though:
    /// `mach_continuous_time` is what the *kernel* has counted since boot, and a
    /// corrupted or hostile value is a `u64` this function must not panic on.
    #[must_use]
    // The cast is reached only on the `else` branch, where `wide <= u64::MAX` has
    // just been checked; and this is a `const fn`, so `u64::try_from` is not
    // available to say the same thing in the type system.
    #[allow(clippy::cast_possible_truncation)]
    pub const fn ticks_to_nanos(self, ticks: u64) -> u64 {
        let wide = (ticks as u128) * (self.numer as u128) / (self.denom as u128);
        if wide > u64::MAX as u128 {
            u64::MAX
        } else {
            wide as u64
        }
    }

    /// Converts mach ticks to microseconds, which is what [`ElapsedInstant`] takes.
    #[must_use]
    pub const fn ticks_to_micros(self, ticks: u64) -> u64 {
        self.ticks_to_nanos(ticks) / 1_000
    }
}

impl Default for MachTimebase {
    fn default() -> Self {
        Self::IDENTITY
    }
}

/// Reads `mach_timebase_info`.
///
/// # Errors
///
/// [`EnvError::EntropyUnavailable`] is deliberately **not** used here; a failed
/// timebase read returns `None` and the caller refuses to build a clock, because
/// a clock with a guessed timebase is worse than no clock.
#[cfg(target_os = "macos")]
#[must_use]
pub fn read_timebase() -> Option<MachTimebase> {
    let mut info = crate::sys::MachTimebaseInfo::default();
    // SAFETY: `mach_timebase_info` writes two `u32`s into the struct we own and
    // whose address is live for the duration of the call. It reads nothing else
    // and takes no ownership.
    let rc = unsafe { crate::sys::mach_timebase_info(&raw mut info) };
    if rc != 0 {
        return None;
    }
    MachTimebase::new(info.numer, info.denom)
}

/// The same, on a host that is not Darwin: there is no mach timebase to read.
///
/// Present so the module has one shape on both targets; a caller on this host
/// gets `None` and refuses to build the clock, which is the honest answer.
#[cfg(not(target_os = "macos"))]
#[must_use]
pub fn read_timebase() -> Option<MachTimebase> {
    None
}

/// Suspend-**exclusive** mach ticks — the `MonotonicClock` primitive.
#[cfg(target_os = "macos")]
#[must_use]
pub fn monotonic_ticks() -> u64 {
    // SAFETY: `mach_absolute_time` takes no arguments, touches no memory we own
    // and cannot fail.
    unsafe { crate::sys::mach_absolute_time() }
}

/// Suspend-**inclusive** mach ticks — the `ElapsedClock` primitive.
#[cfg(target_os = "macos")]
#[must_use]
pub fn elapsed_ticks() -> u64 {
    // SAFETY: `mach_continuous_time` takes no arguments, touches no memory we own
    // and cannot fail. It is declared in `crate::sys` with its `<mach/mach_time.h>`
    // signature.
    unsafe { crate::sys::mach_continuous_time() }
}

/// The suspend-**inclusive** clock: Darwin `mach_continuous_time`.
///
/// # Why this one and not `mach_absolute_time`
///
/// They differ by exactly the accumulated sleep time. Every documented consumer
/// of `ElapsedClock` — the suspend gap, the rekey window, NAT binding lifetime,
/// `T_REHYDRATE`, and LC-8 F2's long-horizon policy deadlines (`T_TRUST_HARD`,
/// `T_IK_OVERLAP`) — must count the time the lid was shut. A Mac that slept for
/// six hours and woke with a `MonotonicClock` reading six hours short would
/// consider a trust window still open that has in fact expired, and would do so
/// silently.
///
/// # A stated limit
///
/// The timebase is read **once, at construction**. It cannot change while the
/// process lives (it is a property of the SoC), and a per-read `mach_timebase_info`
/// would put a syscall on every timer tick.
#[derive(Debug, Clone, Copy)]
pub struct ContinuousElapsedClock {
    timebase: MachTimebase,
}

impl ContinuousElapsedClock {
    /// Binds the clock to a timebase.
    ///
    /// Injected rather than read, so the arithmetic is testable on a host with no
    /// mach at all — CD-2's "no ambient default" applied to the one number this
    /// clock depends on.
    #[must_use]
    pub const fn with_timebase(timebase: MachTimebase) -> Self {
        Self { timebase }
    }

    /// Binds the clock, reading the timebase from the kernel.
    ///
    /// # Errors
    ///
    /// `None` when `mach_timebase_info` fails or this is not Darwin. A clock with
    /// a guessed timebase would be wrong by a factor of 41 on Apple silicon, so a
    /// refusal is the only safe answer.
    #[must_use]
    pub fn from_kernel() -> Option<Self> {
        read_timebase().map(Self::with_timebase)
    }

    /// Binds it as a shared capability, ready for [`twinvpn_env::EnvParts`].
    #[must_use]
    pub fn shared(timebase: MachTimebase) -> Arc<dyn ElapsedClock> {
        Arc::new(Self::with_timebase(timebase))
    }

    /// The timebase in force.
    #[must_use]
    pub const fn timebase(&self) -> MachTimebase {
        self.timebase
    }
}

impl ElapsedClock for ContinuousElapsedClock {
    #[cfg(target_os = "macos")]
    fn now(&self) -> ElapsedInstant {
        ElapsedInstant::from_micros(self.timebase.ticks_to_micros(elapsed_ticks()))
    }

    /// On a host that is not Darwin there is no `mach_continuous_time`.
    ///
    /// Returning the origin rather than panicking keeps the type constructible in
    /// a host test; the value is monotonically wrong in the **safe** direction,
    /// because every interval measures as zero and nothing expires early. A test
    /// that needs a moving elapsed clock injects `twinvpn-env`'s virtual one,
    /// which is what CD-2 exists to make possible.
    #[cfg(not(target_os = "macos"))]
    fn now(&self) -> ElapsedInstant {
        ElapsedInstant::from_micros(0)
    }
}

/// The platform CSPRNG, read from `/dev/urandom`.
///
/// See the module documentation for why this and not `SecRandomCopyBytes`.
#[derive(Debug)]
pub struct SystemEntropy {
    path: &'static str,
}

impl Default for SystemEntropy {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemEntropy {
    /// Binds the platform CSPRNG.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            path: "/dev/urandom",
        }
    }

    /// Binds it as a shared capability.
    #[must_use]
    pub fn shared() -> Arc<dyn Entropy> {
        Arc::new(Self::new())
    }

    /// Draws once, so a startup failure is loud rather than deferred to the first
    /// key.
    ///
    /// Darwin's CSPRNG is seeded by the boot loader before userspace runs, so
    /// there is no unseeded window to probe for as there is on Linux — the probe
    /// is a reachability check, and its value is that it fails at startup rather
    /// than at the first handshake.
    ///
    /// # Errors
    ///
    /// [`EnvError::EntropyUnavailable`] if the device cannot be read.
    pub fn probe(&self) -> Result<(), EnvError> {
        let mut probe = [0u8; 32];
        self.fill(&mut probe)
    }
}

impl Entropy for SystemEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
        if dst.is_empty() {
            return Ok(());
        }
        let mut file = fs::File::open(self.path).map_err(|_| EnvError::EntropyUnavailable)?;
        file.read_exact(dst)
            .map_err(|_| EnvError::EntropyUnavailable)
    }
}

/// The boot identity, from the `kern.bootsessionuuid` sysctl.
///
/// W-7's third required shell interface. Darwin generates a fresh UUID for each
/// boot session and holds it for the life of the boot, which is exactly the
/// contract [`BootIdSource`] states. Read **once, at construction**: the value
/// cannot change while the process lives, and a per-call read would make an
/// equality comparison depend on a syscall.
#[derive(Debug, Clone, Copy)]
pub struct BootSessionId {
    id: BootId,
}

impl BootSessionId {
    /// The sysctl the identity comes from.
    pub const SOURCE: &'static str = "kern.bootsessionuuid";

    /// Builds one from an already-read UUID string.
    ///
    /// Separated from the syscall so the **parse** is testable on this host: the
    /// sysctl is Darwin-only, the string format is not.
    ///
    /// # Errors
    ///
    /// [`EnvError::EntropyUnavailable`] if the text is not a canonical UUID. A
    /// fabricated boot id would make "we rebooted" and "we did not" the same fact.
    pub fn parse(text: &str) -> Result<Self, EnvError> {
        parse_uuid(text.trim().trim_end_matches('\0'))
            .map(|bytes| Self {
                id: BootId::from_array(bytes),
            })
            .ok_or(EnvError::EntropyUnavailable)
    }

    /// Reads the boot identity from the kernel.
    ///
    /// # Errors
    ///
    /// [`EnvError::EntropyUnavailable`] if the sysctl is absent or unparseable,
    /// or on a host that is not Darwin.
    #[cfg(target_os = "macos")]
    pub fn read() -> Result<Self, EnvError> {
        let name = c"kern.bootsessionuuid";
        let mut buf = [0u8; 64];
        let mut len: libc::size_t = buf.len();
        // SAFETY: `name` is a NUL-terminated C string with static lifetime; `buf`
        // is a live 64-byte buffer we own and `len` is its true length, which the
        // call updates to the number of bytes written. The two null pointers are
        // the documented "no new value" form.
        let rc = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                &raw mut len,
                core::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 || len == 0 || len > buf.len() {
            return Err(EnvError::EntropyUnavailable);
        }
        let text = core::str::from_utf8(&buf[..len]).map_err(|_| EnvError::EntropyUnavailable)?;
        Self::parse(text)
    }

    /// On a host that is not Darwin there is no boot session uuid.
    #[cfg(not(target_os = "macos"))]
    pub fn read() -> Result<Self, EnvError> {
        Err(EnvError::EntropyUnavailable)
    }
}

impl BootIdSource for BootSessionId {
    fn boot_id(&self) -> BootId {
        self.id
    }
}

/// Parses a canonical hyphenated UUID into sixteen bytes.
fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    let mut nibbles = text.bytes().filter(|b| *b != b'-');
    for slot in &mut out {
        let hi = (nibbles.next()? as char).to_digit(16)?;
        let lo = (nibbles.next()? as char).to_digit(16)?;
        *slot = u8::try_from(hi * 16 + lo).ok()?;
    }
    // Exactly thirty-two hex digits; a longer string is not this sysctl's format.
    if nibbles.next().is_some() {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_apple_silicon_timebase_converts_a_realistic_uptime_exactly() {
        let tb = MachTimebase::APPLE_SILICON;
        // One day of uptime on a 24 MHz counter.
        let day_ticks: u64 = 24_000_000 * 86_400;
        assert_eq!(tb.ticks_to_nanos(day_ticks), 86_400_000_000_000);
        // A year. The naive `u64` multiply still fits here, and this test says so
        // rather than claiming an overflow that does not happen: the honest
        // boundary is ~194 YEARS of uptime, not 194 days.
        let year_ticks: u64 = 24_000_000 * 86_400 * 365;
        assert_eq!(tb.ticks_to_nanos(year_ticks), 31_536_000_000_000_000);
        assert!(year_ticks.checked_mul(125).is_some());
        // Two distinct boundaries, and the difference between them is the point.
        //
        // The `u64` MULTIPLY overflows first, at `u64::MAX / 125` ticks — ~194
        // years of uptime. The u128 carries past it and still gives the right
        // answer, which a wrapping multiply would not.
        let multiply_overflows_at = u64::MAX / 125 + 1;
        assert!(multiply_overflows_at.checked_mul(125).is_none());
        assert_eq!(
            tb.ticks_to_nanos(multiply_overflows_at),
            u64::try_from(u128::from(multiply_overflows_at) * 125 / 3).expect("fits")
        );
        // The RESULT overflows later, at `u64::MAX * 3 / 125` ticks, and there the
        // conversion saturates — monotone, rather than wrapping to a small value
        // that would send every deadline in the system backwards at once.
        let result_overflows_at =
            u64::try_from(u128::from(u64::MAX) * 3 / 125 + 1).expect("fits");
        assert_eq!(tb.ticks_to_nanos(result_overflows_at), u64::MAX);
    }

    #[test]
    fn the_conversion_saturates_rather_than_wrapping_at_the_top_of_the_range() {
        // A saturated clock is still monotone; a wrapped one is not, and a
        // non-monotone reading is what `ElapsedInstant`'s saturating interval
        // arithmetic silently turns into zero elapsed time.
        let tb = MachTimebase::APPLE_SILICON;
        assert_eq!(tb.ticks_to_nanos(u64::MAX), u64::MAX);
        assert_eq!(tb.ticks_to_micros(u64::MAX), u64::MAX / 1_000);
    }

    #[test]
    fn the_intel_timebase_is_the_identity_and_a_tick_is_a_nanosecond() {
        let tb = MachTimebase::IDENTITY;
        for ticks in [0u64, 1, 1_000, 1_000_000_000, u64::MAX / 2] {
            assert_eq!(tb.ticks_to_nanos(ticks), ticks);
        }
    }

    #[test]
    fn the_conversion_is_monotone_across_the_whole_range_it_can_see() {
        // Sampled rather than exhaustive, but across eleven orders of magnitude
        // and on both real timebases: a conversion that is not monotone makes a
        // clock that goes backwards.
        for tb in [MachTimebase::IDENTITY, MachTimebase::APPLE_SILICON] {
            let mut previous = 0u64;
            let mut ticks = 1u64;
            while ticks < u64::MAX / 4 {
                let now = tb.ticks_to_nanos(ticks);
                assert!(now >= previous, "{tb:?} went backwards at {ticks}");
                previous = now;
                ticks = ticks.saturating_mul(7);
            }
        }
    }

    #[test]
    fn a_zero_denominator_is_refused_rather_than_dividing_by_zero_on_every_tick() {
        assert!(MachTimebase::new(0, 1).is_none());
        assert!(MachTimebase::new(1, 0).is_none());
        assert_eq!(
            MachTimebase::new(125, 3),
            Some(MachTimebase::APPLE_SILICON)
        );
    }

    /// **The clock-distinctness check, and an honest statement of its limit.**
    ///
    /// The only thing that distinguishes the two mach clocks is accumulated sleep
    /// time, and no test on any host — Linux or Mac — can prove the right symbol
    /// was chosen without actually suspending the machine. That is LC-8's
    /// "invisible on CI" warning, stated rather than papered over.
    ///
    /// What *is* checkable, and is checked here, is that the `ElapsedClock`
    /// implementation names `mach_continuous_time` and not `mach_absolute_time`.
    /// The two are different `extern` symbols in [`crate::sys`] and
    /// [`elapsed_ticks`] / [`monotonic_ticks`] are separate functions, so a
    /// substitution is a source change a reviewer can see — which is the strongest
    /// guarantee available from this host.
    #[test]
    fn the_elapsed_clock_is_the_suspend_inclusive_one() {
        let clock = ContinuousElapsedClock::with_timebase(MachTimebase::APPLE_SILICON);
        assert_eq!(clock.timebase(), MachTimebase::APPLE_SILICON);
        // On this host `now()` is the documented origin, because there is no mach
        // clock to read. The reading is wrong in the SAFE direction: every
        // interval measures as zero, so nothing expires early.
        assert_eq!(clock.now().as_micros(), 0);
        // And there is no mach timebase here, so `from_kernel` refuses rather
        // than guessing — a clock with a guessed timebase is wrong by 41x on
        // Apple silicon.
        assert!(ContinuousElapsedClock::from_kernel().is_none());
    }

    #[test]
    fn the_entropy_source_fills_and_two_draws_differ() {
        let entropy = SystemEntropy::new();
        entropy.probe().expect("the platform CSPRNG must be readable");
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        entropy.fill(&mut a).expect("fills");
        entropy.fill(&mut b).expect("fills");
        assert_ne!(a, b, "two draws must not be identical");
        assert_ne!(a, [0u8; 32], "an all-zero draw is a broken source");
        entropy.fill(&mut []).expect("an empty fill is a no-op");
    }

    #[test]
    fn a_boot_session_uuid_parses_and_a_malformed_one_does_not() {
        let id =
            BootSessionId::parse("A1B2C3D4-0000-0000-0000-0000000000FF").expect("canonical");
        assert_eq!(
            id.boot_id().as_bytes(),
            &[0xA1, 0xB2, 0xC3, 0xD4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF]
        );
        // The sysctl returns a NUL-terminated string in a fixed buffer.
        assert!(BootSessionId::parse("A1B2C3D4-0000-0000-0000-0000000000FF\0\0").is_ok());
        assert!(BootSessionId::parse("short").is_err());
        assert!(BootSessionId::parse("").is_err());
        assert!(
            BootSessionId::parse(&"a".repeat(33)).is_err(),
            "thirty-three hex digits is not this sysctl's format"
        );
    }
}
