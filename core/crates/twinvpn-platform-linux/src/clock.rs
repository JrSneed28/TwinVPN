//! The three shell-supplied capabilities of **W-7**: the suspend-**inclusive**
//! clock, the platform CSPRNG, and the boot identity.
//!
//! **Authority:** ADR-0022 LC-8 and its per-platform primitive table; ADR-0018
//! CD-1 (three non-interchangeable clocks), CD-3 (the deny-list), CB-3, DP-4;
//! `docs/implementation/ownership.md` §8 **W-7**;
//! [`twinvpn_env::binding::system::ElapsedClockFn`].
//!
//! # W-7, discharged for the first time
//!
//! `twinvpn-env` ships **no production [`ElapsedClock`]**, deliberately:
//!
//! > Substituting the monotonic clock here compiles, passes every test that does
//! > not suspend, and fails only on a device that actually sleeps.
//!
//! On Linux the three clocks are:
//!
//! | Capability | Linux primitive | Suspend |
//! |---|---|---|
//! | `MonotonicClock` | `CLOCK_MONOTONIC`, via `std::time::Instant` — `twinvpn_env::binding::system::SystemMonotonicClock` | **excluded** |
//! | `ElapsedClock` | `CLOCK_BOOTTIME` | **included** |
//! | `WallClock` | `CLOCK_REALTIME`, via `SystemWallClock` | n/a |
//!
//! Getting the second one backwards is the failure LC-8 names, so this module
//! exists to make it right once, in one place, with a test that reads both.
//!
//! # `CLOCK_BOOTTIME` is read with `clock_gettime(2)`
//!
//! Wave 1 read it out of `/proc/uptime` instead, because two of our own lints
//! contradicted each other: CB-3 and DP-4 put platform-specific code and
//! `unsafe` in a `twinvpn-platform-*` crate — this one — while ADR-0018 CD-3's
//! deny-list denied the needle `clock_gettime` *everywhere* outside
//! `twinvpn-env`'s binding directory, including here. That conjunction was
//! unsatisfiable: no location in the tree could legally read a platform clock.
//! It is `ownership.md` §8 **W-36**, and the disposition was "one exemption in
//! `checks.rs` for `twinvpn-platform-*`".
//!
//! That exemption now exists — `core/xtask/src/checks.rs`'s
//! `CD3_PLATFORM_PRIMITIVES` and `cd3_crate_may_read_platform_primitives` —
//! so the workaround is **deleted** and the syscall is called directly. The
//! difference is not cosmetic: `/proc/uptime` quantises to 10 ms and costs an
//! `open`/`read`/`close` of a pseudo-file per reading, where `clock_gettime` is
//! a vDSO call with nanosecond resolution and no file descriptor at all. LC-8's
//! consumers are seconds-to-days quantities, so the *quantisation* was not a
//! functional defect; the syscall is still the primitive the ADR's own
//! per-platform table names, and reading a formatted pseudo-file to obtain it
//! was a workaround, not a design.
//!
//! The one property that must not be lost in the change is **suspend
//! inclusion**: `CLOCK_BOOTTIME` counts time spent suspended and
//! `CLOCK_MONOTONIC` does not, and substituting the second for the first
//! "compiles, passes every test that does not suspend, and fails only on a
//! device that actually sleeps". `the_clock_id_is_boottime_and_not_monotonic`
//! pins the constant, and `boottime_is_never_behind_monotonic` asserts the
//! ordering the two clocks must always satisfy on any host.

use std::fs;
use std::sync::Arc;

use twinvpn_env::{BootId, BootIdSource, ElapsedClock, ElapsedInstant, Entropy, EnvError};

/// The `clockid_t` this clock reads, named so a test can pin it.
///
/// The whole difference between this clock and the monotonic one is this
/// constant. `CLOCK_MONOTONIC` here would compile, pass every test on a host
/// that has never suspended, and be wrong on every device that sleeps — which
/// is LC-8's "invisible on CI" failure exactly.
pub const BOOTTIME_CLOCK_ID: libc::clockid_t = libc::CLOCK_BOOTTIME;

/// The suspend-**inclusive** clock: Linux `CLOCK_BOOTTIME`, read with
/// `clock_gettime(2)`.
#[derive(Debug, Clone, Copy, Default)]
pub struct BootTimeElapsedClock;

impl BootTimeElapsedClock {
    /// Binds the clock.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Binds it as a shared capability, ready for [`twinvpn_env::EnvParts`].
    #[must_use]
    pub fn shared() -> Arc<dyn ElapsedClock> {
        Arc::new(Self)
    }

    /// The raw reading in microseconds, or `None` if the kernel refused.
    ///
    /// Separated from [`ElapsedClock::now`] so a test can see the failure that
    /// `now` has to absorb, and so the `unsafe` block has exactly one caller.
    #[must_use]
    pub fn read_micros() -> Option<u64> {
        Self::read_micros_of(BOOTTIME_CLOCK_ID)
    }

    /// The same reading, for an arbitrary `clockid_t`.
    ///
    /// Present so `boottime_is_never_behind_monotonic` can read
    /// `CLOCK_MONOTONIC` through the identical code path: comparing the two
    /// clocks is only meaningful if the *only* difference between the readings
    /// is the clock id.
    #[must_use]
    pub fn read_micros_of(clock: libc::clockid_t) -> Option<u64> {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `timespec` is two integers with no invalid bit patterns, so
        // the zeroed local above is a valid initial value. `clock_gettime`
        // writes through the pointer and reads nothing else, and the pointee is
        // a local that outlives the call. The return code is checked before the
        // struct is read, so a failed call never produces a reading. This is the
        // syscall CB-3 and DP-4 place in this crate, and CD-3's W-36 exemption
        // (`cd3_crate_may_read_platform_primitives`) permits here.
        let rc = unsafe { libc::clock_gettime(clock, &raw mut ts) };
        if rc != 0 {
            return None;
        }
        micros_of(ts.tv_sec, ts.tv_nsec)
    }
}

/// Converts a `timespec` to microseconds.
///
/// A negative `tv_sec` is not a value `CLOCK_BOOTTIME` can produce; it is
/// refused rather than cast, because `as u64` on a negative would turn a
/// nonsense reading into an enormous one, and every interval computed from it
/// into an expiry far in the future.
fn micros_of(secs: libc::time_t, nanos: libc::c_long) -> Option<u64> {
    let secs = u64::try_from(secs).ok()?;
    let nanos = u64::try_from(nanos).ok()?;
    secs.checked_mul(1_000_000)?.checked_add(nanos / 1_000)
}

impl ElapsedClock for BootTimeElapsedClock {
    fn now(&self) -> ElapsedInstant {
        // A clock read has no error channel, by the trait's design.
        // `clock_gettime(CLOCK_BOOTTIME)` fails only with EINVAL on a kernel
        // that does not know the clock id, which is every Linux since 2.6.39 and
        // therefore none that TwinVPN supports. Returning ORIGIN rather than
        // panicking keeps a broken vDSO from being a crash vector, and the value
        // is wrong in the safe direction: every interval measures as zero, so
        // nothing expires early.
        ElapsedInstant::from_micros(Self::read_micros().unwrap_or(0))
    }
}

/// The platform CSPRNG, read with `getrandom(2)`.
///
/// # Why the syscall and not `/dev/urandom`
///
/// Wave 1 opened `/dev/urandom` for the same W-36 reason the clock read
/// `/proc/uptime`: CD-3 denied the needle `getrandom` here. The exemption now
/// exists, and the syscall is strictly better than the device in two ways that
/// matter for a key source:
///
/// 1. **It blocks until the pool is initialised.** `/dev/urandom` returns bytes
///    from an uninitialised pool very early in boot; `getrandom(2)` with no
///    flags does not. On an embedded or router target — ADR-0023's `H-EMB` and
///    `H-CTR` profiles — that window is real, and a nonce drawn inside it is
///    predictable.
/// 2. **It needs no file descriptor.** A `chroot` or a `seccomp` filter or an
///    exhausted fd table can make `open("/dev/urandom")` fail; there is nothing
///    between this call and the kernel.
///
/// [`Entropy::fill`] **never** falls back to a weaker source.
/// `EntropyUnavailable` is propagated, because "a silent downgrade here is
/// indistinguishable from working, and the value it produces is the one every
/// nonce and key depends on".
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEntropy;

impl SystemEntropy {
    /// The pool-initialisation flag. `1` once the CSPRNG is seeded.
    const READY_FLAG: &'static str = "/proc/sys/kernel/random/entropy_avail";

    /// The largest number of bytes one `getrandom(2)` call is guaranteed to
    /// return without a short read on Linux.
    ///
    /// The kernel documents 256 for the urandom source. Larger requests may be
    /// interrupted by a signal, so [`Entropy::fill`] loops rather than assuming
    /// one call fills the buffer — a short read that went unnoticed would leave
    /// the tail of a key buffer holding whatever was there before.
    const MAX_PER_CALL: usize = 256;

    /// Binds the platform CSPRNG.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Binds it as a shared capability.
    #[must_use]
    pub fn shared() -> Arc<dyn Entropy> {
        Arc::new(Self::new())
    }

    /// Draws once and asserts the pool is seeded, so a startup failure is loud.
    ///
    /// # Errors
    ///
    /// [`EnvError::EntropyUnavailable`] if the syscall is unavailable, or if the
    /// kernel reports an unseeded pool.
    pub fn probe(&self) -> Result<(), EnvError> {
        let mut probe = [0u8; 32];
        self.fill(&mut probe)?;
        // `entropy_avail` is advisory on a modern kernel — `getrandom(2)` would
        // have blocked rather than returned unseeded bytes — but a zero here on
        // an early-boot embedded target is still worth refusing. Absence of the
        // file is not a failure: it means a kernel or a container that does not
        // export it.
        if let Ok(text) = fs::read_to_string(Self::READY_FLAG) {
            if text.trim() == "0" {
                return Err(EnvError::EntropyUnavailable);
            }
        }
        Ok(())
    }
}

impl Entropy for SystemEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
        let mut filled = 0usize;
        while filled < dst.len() {
            let chunk = (dst.len() - filled).min(Self::MAX_PER_CALL);
            // SAFETY: the pointer is derived from a mutable slice this call
            // holds exclusively, and `chunk` is at most the remaining length, so
            // the kernel writes only within `dst`. `flags = 0` selects the
            // urandom source and blocks until it is initialised rather than
            // returning unseeded bytes. The return value is checked before any
            // byte is treated as written.
            let written = unsafe {
                libc::getrandom(
                    dst.as_mut_ptr().add(filled).cast::<libc::c_void>(),
                    chunk,
                    0,
                )
            };
            if written < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error();
                // EINTR is a signal, not a failure: retry rather than propagate,
                // because a caller that treated a signal as "no entropy" would
                // fail a handshake for a reason unrelated to entropy.
                if errno == Some(libc::EINTR) {
                    continue;
                }
                return Err(EnvError::EntropyUnavailable);
            }
            let written = usize::try_from(written).map_err(|_| EnvError::EntropyUnavailable)?;
            if written == 0 {
                // Never a spin: a zero-length return with a non-empty request is
                // a broken source, not a retry condition.
                return Err(EnvError::EntropyUnavailable);
            }
            filled += written;
        }
        Ok(())
    }
}

/// The boot identity, from `/proc/sys/kernel/random/boot_id`.
///
/// W-7's third required shell interface. The kernel generates a fresh random
/// UUID at each boot and holds it for the life of the boot, which is exactly the
/// contract [`BootIdSource`] states.
///
/// Read **once, at construction**, and cached: the value cannot change while the
/// process lives, and a per-call read would make an equality comparison depend
/// on `/proc` still being mounted.
#[derive(Debug, Clone, Copy)]
pub struct ProcBootId {
    id: BootId,
}

impl ProcBootId {
    /// Where the boot identity comes from.
    pub const SOURCE: &'static str = "/proc/sys/kernel/random/boot_id";

    /// Reads the boot identity.
    ///
    /// # Errors
    ///
    /// [`EnvError::EntropyUnavailable`] if the file is absent or unparseable —
    /// the same failure shape the shell already handles for the CSPRNG, and a
    /// fabricated boot id would make "we rebooted" and "we did not" the same
    /// fact.
    pub fn read() -> Result<Self, EnvError> {
        let text = fs::read_to_string(Self::SOURCE).map_err(|_| EnvError::EntropyUnavailable)?;
        let bytes = parse_uuid(text.trim()).ok_or(EnvError::EntropyUnavailable)?;
        Ok(Self {
            id: BootId::from_array(bytes),
        })
    }
}

impl BootIdSource for ProcBootId {
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
    // Exactly thirty-two hex digits; a longer string is not this file's format.
    if nibbles.next().is_some() {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_env::binding::system::SystemMonotonicClock;
    use twinvpn_env::MonotonicClock;

    #[test]
    fn a_timespec_converts_exactly_and_a_negative_one_is_refused() {
        assert_eq!(micros_of(12, 340_000_000), Some(12_340_000));
        assert_eq!(micros_of(0, 0), Some(0));
        assert_eq!(micros_of(59_750, 540_000_000), Some(59_750_540_000));
        // Sub-microsecond nanoseconds truncate rather than round: an interval
        // must never measure LONGER than it was.
        assert_eq!(micros_of(0, 999), Some(0));
        assert_eq!(micros_of(0, 1_999), Some(1));
        // A negative reading is not a value CLOCK_BOOTTIME can produce, and
        // casting it would produce an enormous positive one.
        assert_eq!(micros_of(-1, 0), None);
        assert_eq!(micros_of(0, -1), None);
    }

    #[test]
    fn the_clock_id_is_boottime_and_not_monotonic() {
        // The entire suspend-inclusion property is this one constant. A build
        // that changed it would pass every other test in this file on a host
        // that has never suspended, which is LC-8's stated failure mode.
        assert_eq!(BOOTTIME_CLOCK_ID, libc::CLOCK_BOOTTIME);
        assert_ne!(BOOTTIME_CLOCK_ID, libc::CLOCK_MONOTONIC);
        assert_ne!(BOOTTIME_CLOCK_ID, libc::CLOCK_REALTIME);
    }

    /// `CLOCK_BOOTTIME` is `CLOCK_MONOTONIC` plus accumulated suspend time, so
    /// the difference is `>= 0` always and `> 0` on a host that has slept. Both
    /// readings go through the same code path, so the only difference between
    /// them is the clock id — which is what makes the comparison meaningful.
    ///
    /// **The read order is load-bearing**, and getting it wrong is how this test
    /// first failed. On a host that has never suspended the two clocks are equal,
    /// so the microsecond that elapses *between* the two syscalls is the entire
    /// margin: reading boottime first made the later monotonic read one
    /// microsecond larger and the assertion fail on a correct implementation.
    /// Monotonic is therefore read **first**, so the elapsed read is separated
    /// from it by the suspend delta *plus* the read gap, both non-negative.
    #[test]
    fn boottime_is_never_behind_monotonic() {
        let mono = BootTimeElapsedClock::read_micros_of(libc::CLOCK_MONOTONIC).expect("monotonic");
        let boot = BootTimeElapsedClock::read_micros_of(libc::CLOCK_BOOTTIME).expect("boottime");
        assert!(
            boot >= mono,
            "CLOCK_BOOTTIME ({boot} us) must never read behind CLOCK_MONOTONIC \
             ({mono} us) read before it: the difference is accumulated suspend \
             time plus the gap between the two reads, and both are non-negative"
        );
    }

    #[test]
    fn an_unknown_clock_id_is_a_none_and_never_a_panic() {
        // The failure `ElapsedClock::now` has to absorb, made visible. A clock
        // read has no error channel, so this is the only place the refusal is
        // observable.
        assert_eq!(BootTimeElapsedClock::read_micros_of(-424_242), None);
    }

    #[test]
    fn the_elapsed_clock_reads_boottime_and_advances() {
        let clock = BootTimeElapsedClock::new();
        let a = clock.now();
        // Busy-spin rather than sleep: CD-3 bans the runtime's time module and
        // `std::thread::sleep` would make this test a timing dependency.
        // `clock_gettime` resolves to nanoseconds, so this terminates in a few
        // iterations rather than in a 10 ms `/proc/uptime` tick.
        let mut b = clock.now();
        for _ in 0..2_000_000u64 {
            b = clock.now();
            if b > a {
                break;
            }
        }
        assert!(b > a, "a nanosecond-resolution clock must advance");
        assert!(a.as_micros() > 0, "a booted host has non-zero boot time");
    }

    /// **The clock-distinctness check, and an honest statement of its limit.**
    ///
    /// `CLOCK_BOOTTIME` differs from `CLOCK_MONOTONIC` by exactly the accumulated
    /// suspend time. On a host that has never suspended the two read the same,
    /// so no test on such a host can *prove* the right one was chosen — that is
    /// LC-8's "invisible on CI" warning, stated as a test comment rather than
    /// papered over.
    ///
    /// What is checkable here, and is checked:
    ///
    /// 1. The two clocks have **different origins**. `SystemMonotonicClock`
    ///    zeroes at construction; this one is absolute since boot. A build that
    ///    substituted the monotonic clock would read near zero.
    /// 2. The clock id is pinned by
    ///    `the_clock_id_is_boottime_and_not_monotonic`, and the ordering by
    ///    `boottime_is_never_behind_monotonic`.
    #[test]
    fn the_elapsed_clock_is_not_the_monotonic_clock() {
        let monotonic = SystemMonotonicClock::new();
        let elapsed = BootTimeElapsedClock::new();
        let m = monotonic.now().as_micros();
        let e = elapsed.now().as_micros();
        assert!(
            m < 1_000_000,
            "SystemMonotonicClock zeroes at construction; it read {m} us"
        );
        assert!(
            e > 1_000_000,
            "the elapsed clock is absolute since boot; it read {e} us — a value \
             near zero means the monotonic clock was substituted, which is \
             exactly LC-8's invisible-on-CI failure"
        );
    }

    #[test]
    fn the_entropy_source_fills_and_is_seeded() {
        let entropy = SystemEntropy::new();
        entropy.probe().expect("the platform CSPRNG must be seeded");
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        entropy.fill(&mut a).expect("fills");
        entropy.fill(&mut b).expect("fills");
        assert_ne!(a, b, "two draws must not be identical");
        assert_ne!(a, [0u8; 32], "an all-zero draw is a broken source");
        // A zero-length fill is a no-op, not an error.
        entropy.fill(&mut []).expect("empty fill");

        // Larger than one `getrandom(2)` call: the loop must fill the WHOLE
        // buffer. A short read that went unnoticed would leave the tail holding
        // whatever was there before, which for a key buffer is zeros.
        let mut long = vec![0u8; 4096];
        entropy.fill(&mut long).expect("fills a long buffer");
        assert!(
            long[4000..].iter().any(|b| *b != 0),
            "the tail past the first getrandom(2) call was not filled"
        );
    }

    #[test]
    fn the_boot_id_is_stable_within_one_boot() {
        let a = ProcBootId::read().expect("reads");
        let b = ProcBootId::read().expect("reads");
        assert_eq!(a.boot_id(), b.boot_id());
        assert_ne!(a.boot_id().as_bytes(), &[0u8; 16]);
    }

    #[test]
    fn a_uuid_parses_and_a_malformed_one_does_not() {
        assert_eq!(
            parse_uuid("00000000-0000-0000-0000-0000000000ff"),
            Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff])
        );
        assert_eq!(parse_uuid("short"), None);
        assert_eq!(parse_uuid(""), None);
        // Thirty-three hex digits is not this file's format and is refused
        // rather than truncated.
        assert_eq!(parse_uuid(&"a".repeat(33)), None);
    }
}
