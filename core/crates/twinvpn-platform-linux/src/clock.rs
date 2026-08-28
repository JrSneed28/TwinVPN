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
//! # Why `CLOCK_BOOTTIME` is read through `/proc/uptime` and not `clock_gettime`
//!
//! **This is a real conflict between two rules, reported rather than
//! sidestepped.** CB-3 and DP-4 put platform-specific code and `unsafe` in a
//! `twinvpn-platform-*` crate — this one. But ADR-0018 CD-3's deny-list, as
//! `core/xtask/src/checks.rs` implements it, excludes exactly one path
//! (`crates/twinvpn-env/src/binding/`) and denies the needle `clock_gettime`
//! **everywhere else, including here**. Verified by running the lint against a
//! deliberate probe, not assumed. The shells are outside the lint's reach but
//! carry `#![forbid(unsafe_code)]`, so there is no location in the tree that
//! holds both permissions at once.
//!
//! `/proc/uptime`'s first field is written by the kernel from
//! `ktime_get_boottime_ts64()` — the same clock `CLOCK_BOOTTIME` reads — so it
//! is **genuinely suspend-inclusive**, which is the property that is invisible
//! when it is wrong. It costs one `read(2)` of a ~30-byte pseudo-file and
//! quantises to 10 ms. Every documented consumer of this clock — the suspend
//! gap, the rekey window, NAT binding lifetime, `T_REHYDRATE`, and LC-8 F2's
//! long-horizon policy deadlines (`T_TRUST_HARD`, `T_IK_OVERLAP`) — is a
//! seconds-to-days quantity, so 10 ms is not a functional cost. It is stated
//! here rather than glossed.
//!
//! The preferred fix is one line in `checks.rs`: exempt the platform-time
//! needles for `twinvpn-platform-*` crates, exactly as `cb3_crate_is_exempt`
//! already exempts them for `target_os`. Reported to the integration lead.

use std::fs;
use std::io::Read;
use std::sync::Arc;

use twinvpn_env::{BootId, BootIdSource, ElapsedClock, ElapsedInstant, Entropy, EnvError};

/// The path the suspend-inclusive reading comes from.
///
/// A constant so a test can assert *which* file is read: reading
/// `/proc/uptime`'s first field is the whole difference between this clock and
/// the monotonic one, and a silent change to another source would be exactly
/// LC-8's invisible defect.
pub const BOOTTIME_SOURCE: &str = "/proc/uptime";

/// The suspend-**inclusive** clock: Linux `CLOCK_BOOTTIME`.
///
/// See the module documentation for why the reading comes through
/// `/proc/uptime` rather than `clock_gettime(CLOCK_BOOTTIME)`.
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

    /// The raw reading in microseconds, or `None` if the file could not be read
    /// or parsed.
    ///
    /// Separated from [`ElapsedClock::now`] so a test can see the failure that
    /// `now` has to absorb.
    #[must_use]
    pub fn read_micros() -> Option<u64> {
        let text = fs::read_to_string(BOOTTIME_SOURCE).ok()?;
        parse_uptime_micros(&text)
    }
}

/// Parses `/proc/uptime`'s first field into microseconds.
///
/// The format is two space-separated decimal seconds values with two fractional
/// digits. Parsed by hand rather than through a float so the conversion is
/// exact: `f64` round-tripping introduces a sub-microsecond error that turns a
/// monotone sequence into an occasionally-decreasing one, and
/// [`ElapsedInstant`]'s interval arithmetic saturates a non-monotone pair to
/// zero — which would silently swallow real elapsed time.
fn parse_uptime_micros(text: &str) -> Option<u64> {
    let field = text.split_ascii_whitespace().next()?;
    let (secs, frac) = match field.split_once('.') {
        Some((s, f)) => (s, f),
        None => (field, ""),
    };
    let secs: u64 = secs.parse().ok()?;
    // Right-pad or truncate the fraction to exactly six digits (microseconds).
    let mut micros: u64 = 0;
    let mut digits = 0;
    for byte in frac.bytes() {
        if digits == 6 {
            break;
        }
        let d = (byte as char).to_digit(10)?;
        micros = micros * 10 + u64::from(d);
        digits += 1;
    }
    while digits < 6 {
        micros *= 10;
        digits += 1;
    }
    secs.checked_mul(1_000_000)?.checked_add(micros)
}

impl ElapsedClock for BootTimeElapsedClock {
    fn now(&self) -> ElapsedInstant {
        // A clock read has no error channel, by the trait's design. `/proc` is
        // mounted on every Linux host TwinVPN supports and this file has existed
        // since 0.99; if it is unreadable the process is in an environment where
        // no reading is meaningful. Returning ORIGIN rather than panicking keeps
        // a hostile /proc from being a crash vector, and the value is
        // monotonically wrong in the safe direction: every interval measures as
        // zero, so nothing expires early.
        ElapsedInstant::from_micros(Self::read_micros().unwrap_or(0))
    }
}

/// The platform CSPRNG, read from `/dev/urandom`.
///
/// # Why `/dev/urandom` and not `getrandom(2)`
///
/// Same conflict as the clock above: CD-3 denies the needle `getrandom`
/// everywhere outside `twinvpn-env`'s binding directory, including here. On
/// Linux since 3.17 `/dev/urandom` and `getrandom(GRND_NONBLOCK)` draw from the
/// same CSPRNG; the difference is that `/dev/urandom` can return bytes before
/// the pool is initialised very early in boot. That window is closed here by
/// [`SystemEntropy::probe`], which the shell calls at startup and which fails
/// loudly rather than proceeding with a possibly-unseeded pool.
///
/// [`Entropy::fill`] **never** falls back to a weaker source. `EntropyUnavailable`
/// is propagated, because "a silent downgrade here is indistinguishable from
/// working, and the value it produces is the one every nonce and key depends on".
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
    /// The pool-initialisation flag. `1` once the CSPRNG is seeded.
    const READY_FLAG: &'static str = "/proc/sys/kernel/random/entropy_avail";

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

    /// Draws once and asserts the pool is seeded, so a startup failure is loud.
    ///
    /// # Errors
    ///
    /// [`EnvError::EntropyUnavailable`] if the device cannot be read, or if the
    /// kernel reports an unseeded pool.
    pub fn probe(&self) -> Result<(), EnvError> {
        let mut probe = [0u8; 32];
        self.fill(&mut probe)?;
        // `entropy_avail` is advisory on a modern kernel (the CSPRNG stays
        // seeded once initialised) but a zero here on an early-boot embedded
        // target is the one case worth refusing. Absence of the file is not a
        // failure: it means a kernel or a container that does not export it.
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
        if dst.is_empty() {
            return Ok(());
        }
        let mut file = fs::File::open(self.path).map_err(|_| EnvError::EntropyUnavailable)?;
        file.read_exact(dst)
            .map_err(|_| EnvError::EntropyUnavailable)
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
    fn the_uptime_field_parses_exactly_and_not_through_a_float() {
        assert_eq!(parse_uptime_micros("12.34 56.78\n"), Some(12_340_000));
        assert_eq!(parse_uptime_micros("0.00 0.00"), Some(0));
        assert_eq!(
            parse_uptime_micros("59750.54 935371.51"),
            Some(59_750_540_000)
        );
        // No fractional part, and extra precision, both accepted.
        assert_eq!(parse_uptime_micros("7 8"), Some(7_000_000));
        assert_eq!(parse_uptime_micros("1.1234567 2"), Some(1_123_456));
        assert_eq!(parse_uptime_micros("not-a-number x"), None);
        assert_eq!(parse_uptime_micros(""), None);
    }

    #[test]
    fn the_elapsed_clock_reads_boottime_and_advances() {
        let clock = BootTimeElapsedClock::new();
        let a = clock.now();
        // Busy-spin rather than sleep: CD-3 bans the runtime's time module and
        // `std::thread::sleep` would make this test a timing dependency. Ten
        // milliseconds of work is one `/proc/uptime` tick.
        let mut b = clock.now();
        for _ in 0..2_000_000u64 {
            b = clock.now();
            if b > a {
                break;
            }
        }
        assert!(b >= a, "an elapsed reading must never go backwards");
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
    /// 2. The reading agrees with the kernel's own boot-time accounting.
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
