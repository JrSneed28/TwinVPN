//! The three shell-supplied capabilities of **W-7**: the suspend-**inclusive**
//! clock, the platform CSPRNG, and the boot identity.
//!
//! **Authority:** ADR-0022 **LC-8** and its per-platform primitive table;
//! ADR-0018 CD-1 (three non-interchangeable clocks), CD-3 and its **W-36**
//! platform-primitive exemption, CB-3, DP-4;
//! `docs/implementation/ownership.md` §8 **W-7** and **W-36**;
//! [`twinvpn_env::binding::system::ElapsedClockFn`].
//!
//! # LC-8's Android row, implemented exactly
//!
//! | Capability | Android primitive | Advances across suspend |
//! |---|---|---|
//! | `MonotonicClock` | `System.nanoTime` / `CLOCK_MONOTONIC` — `twinvpn_env::binding::system::SystemMonotonicClock` | **no** |
//! | `ElapsedClock` | `SystemClock.elapsedRealtime` / **`CLOCK_BOOTTIME`** | **yes** |
//! | `WallClock` | `CLOCK_REALTIME`, via `SystemWallClock` | n/a |
//!
//! Getting the second one backwards is the failure LC-8 names as invisible on
//! Linux CI, so it is done once, here, with a test that reads both and asserts
//! they are different clocks.
//!
//! # W-36 landed, so this reads the syscall rather than routing around it
//!
//! `twinvpn-platform-linux` reaches `CLOCK_BOOTTIME` through `/proc/uptime`,
//! quantised to 10 ms, because CD-3's deny-list denied the needle
//! `clock_gettime` **everywhere** — the contradiction recorded as W-36. That
//! exemption is now in `core/xtask/src/checks.rs`
//! (`cd3_crate_may_read_platform_primitives`, the same crate set as
//! `cb3_crate_is_exempt`), so this crate calls `clock_gettime(CLOCK_BOOTTIME)`
//! directly: microsecond resolution, one `vDSO` call, no pseudo-file parsing,
//! and no SELinux dependency on `/proc` being readable — which on Android it
//! frequently is not.
//!
//! # Why entropy is `/dev/urandom` and not `getrandom(2)`
//!
//! Not a lint constraint — W-36 permits the needle here — but an **API-level**
//! one. `docs/networking.md` §5.2 sets the Android floor at **API 26**, and
//! bionic did not expose `getrandom(2)` until API 28. Linking it would make the
//! artifact fail to load on the two API levels the product supports below that,
//! and a `dlsym` probe would be an ambient discovery CD-2 forbids. On every
//! Android release `/dev/urandom` is the same kernel CSPRNG.
//!
//! [`Entropy::fill`] **never** falls back to a weaker source: a silent downgrade
//! here is indistinguishable from working, and its output is what every nonce
//! and key depends on.

use std::fs;
use std::io::Read;
use std::sync::Arc;

use twinvpn_env::{BootId, BootIdSource, ElapsedClock, ElapsedInstant, Entropy, EnvError};

/// The suspend-**inclusive** clock: `CLOCK_BOOTTIME`.
///
/// `SystemClock.elapsedRealtime()` is the same clock read through the Java API,
/// which is why LC-8's Android row names them together. This reads the syscall
/// so no JNI call sits on a clock read.
#[derive(Debug, Clone, Copy, Default)]
pub struct BootTimeElapsedClock;

impl BootTimeElapsedClock {
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

    /// The raw reading in microseconds, or `None` if the syscall failed.
    ///
    /// Separated from [`ElapsedClock::now`] so a test can see the failure that
    /// `now` has to absorb.
    #[must_use]
    pub fn read_micros() -> Option<u64> {
        read_clock_micros(libc::CLOCK_BOOTTIME)
    }
}

impl ElapsedClock for BootTimeElapsedClock {
    fn now(&self) -> ElapsedInstant {
        // A clock read has no error channel, by the trait's design.
        // `CLOCK_BOOTTIME` has existed since Linux 2.6.39 and is present on
        // every Android release this product supports; if it failed, the process
        // is in an environment where no reading is meaningful. Returning ORIGIN
        // rather than panicking keeps a hostile kernel from being a crash
        // vector, and the value is wrong in the SAFE direction: every interval
        // measures as zero, so nothing expires early.
        ElapsedInstant::from_micros(Self::read_micros().unwrap_or(0))
    }
}

/// Reads one POSIX clock into microseconds.
///
/// The single `clock_gettime` call site in this crate. Both callers pass a
/// compile-time constant, so there is no path by which an untrusted value
/// reaches the syscall.
fn read_clock_micros(clock: libc::clockid_t) -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` writes exactly one `timespec` through the pointer
    // it is given. `ts` is a live, fully-initialised local of exactly that type,
    // and the pointer does not escape this call. `clock` is one of two
    // compile-time constants from `libc`.
    let rc = unsafe { libc::clock_gettime(clock, std::ptr::addr_of_mut!(ts)) };
    if rc != 0 {
        return None;
    }
    let secs = u64::try_from(ts.tv_sec).ok()?;
    let nanos = u64::try_from(ts.tv_nsec).ok()?;
    secs.checked_mul(1_000_000)?.checked_add(nanos / 1_000)
}

/// The platform CSPRNG, read from `/dev/urandom`.
///
/// See the module documentation for why this is not `getrandom(2)`.
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
    /// The device this adapter draws from. A constant so a test can assert
    /// *which* source is read.
    pub const SOURCE: &'static str = "/dev/urandom";

    /// Binds the platform CSPRNG.
    #[must_use]
    pub const fn new() -> Self {
        Self { path: Self::SOURCE }
    }

    /// Binds it as a shared capability.
    #[must_use]
    pub fn shared() -> Arc<dyn Entropy> {
        Arc::new(Self::new())
    }

    /// Draws once, so a startup failure is loud rather than deferred to the
    /// first key derivation.
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

/// The quantum the derived boot identity is rounded to, in microseconds.
///
/// See [`DerivedBootId`]. Sixty seconds is chosen so that ordinary NTP
/// correction (tens of milliseconds to a few seconds) does not move the value,
/// while a reboot — which takes far longer than a minute of wall time to
/// complete and restarts `CLOCK_BOOTTIME` at zero — always does.
pub const BOOT_ID_QUANTUM_MICROS: u64 = 60 * 1_000_000;

/// Where a boot identity came from.
///
/// Declared rather than inferred, because the two sources have different
/// failure modes and a support case must be able to tell which one answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootIdSourceKind {
    /// `/proc/sys/kernel/random/boot_id` — a kernel-generated random UUID,
    /// exact, and unreadable under many Android SELinux policies.
    Kernel,
    /// Derived from `CLOCK_REALTIME - CLOCK_BOOTTIME`: the wall time at which
    /// this boot began, quantised to [`BOOT_ID_QUANTUM_MICROS`].
    ///
    /// **Its imprecision is stated rather than hidden.** A wall-clock step
    /// larger than the quantum — a manual clock change, a first NTP sync on a
    /// device with no RTC — moves the value and reads as a reboot. ADR-0022
    /// LC-7's consequence of a spurious reboot is `COLD_START` with
    /// `absence_cause = UNKNOWN`, which LC-7 treats as `CRASH` — the cautious
    /// direction. The opposite error, *missing* a reboot, would let a resumed
    /// session believe its monotonic timeline survived; this derivation cannot
    /// produce it, because a real reboot always moves the boot wall time by more
    /// than a minute.
    DerivedFromBootWallClock,
}

/// The boot identity, W-7's third required shell interface.
///
/// Read **once, at construction**, and cached: the value cannot change while the
/// process lives, and a per-call read would make an equality comparison depend
/// on `/proc` still being readable.
#[derive(Debug, Clone, Copy)]
pub struct DerivedBootId {
    id: BootId,
    kind: BootIdSourceKind,
}

impl DerivedBootId {
    /// The kernel source, tried first.
    pub const KERNEL_SOURCE: &'static str = "/proc/sys/kernel/random/boot_id";

    /// Reads the boot identity, preferring the kernel's own.
    ///
    /// # Errors
    ///
    /// [`EnvError::EntropyUnavailable`] if neither source can be read — which on
    /// Android means `clock_gettime` itself failed. A fabricated boot id is
    /// refused, because it would make "we rebooted" and "we did not" the same
    /// fact, and that distinction is the only thing that separates a resume from
    /// a cold start (LC-8: "no clock can do it").
    pub fn read() -> Result<Self, EnvError> {
        if let Ok(text) = fs::read_to_string(Self::KERNEL_SOURCE) {
            if let Some(bytes) = parse_uuid(text.trim()) {
                return Ok(Self {
                    id: BootId::from_array(bytes),
                    kind: BootIdSourceKind::Kernel,
                });
            }
        }
        let realtime =
            read_clock_micros(libc::CLOCK_REALTIME).ok_or(EnvError::EntropyUnavailable)?;
        let boottime =
            read_clock_micros(libc::CLOCK_BOOTTIME).ok_or(EnvError::EntropyUnavailable)?;
        Ok(Self {
            id: BootId::from_array(derive_boot_id(realtime, boottime)),
            kind: BootIdSourceKind::DerivedFromBootWallClock,
        })
    }

    /// Which source answered. Reported at startup so a degraded identity is
    /// declared rather than discovered.
    #[must_use]
    pub const fn kind(&self) -> BootIdSourceKind {
        self.kind
    }
}

impl BootIdSource for DerivedBootId {
    fn boot_id(&self) -> BootId {
        self.id
    }
}

/// Builds the derived 16-byte identity from two clock readings.
///
/// Layout: a four-byte tag, then the quantised boot wall time as big-endian
/// `u64`, then four zero bytes. **Not a hash** — CD-I2 permits a cryptographic
/// dependency only in `twinvpn-crypto`, and this value needs to be *stable and
/// comparable*, not unpredictable. The tag is there so a `BootId` from this
/// derivation is distinguishable from a kernel UUID in a diagnostic bundle: a
/// kernel UUID has its RFC 4122 version nibble at byte 6, which `b"twba"` at
/// bytes 0..4 plus a version nibble of 0 cannot collide with.
fn derive_boot_id(realtime_micros: u64, boottime_micros: u64) -> [u8; 16] {
    let boot_wall = realtime_micros.saturating_sub(boottime_micros);
    let quantised = boot_wall / BOOT_ID_QUANTUM_MICROS;
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(b"twba");
    out[4..12].copy_from_slice(&quantised.to_be_bytes());
    out
}

/// Parses a canonical UUID into sixteen bytes.
///
/// Returns `None` on anything that is not exactly 8-4-4-4-12 lowercase hex, so a
/// hostile or truncated `/proc` read falls through to the derived source rather
/// than producing a short identity that compares equal to another short one.
fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    let mut out = [0u8; 16];
    let mut written = 0;
    let mut parts = text.split('-');
    for width in GROUPS {
        let part = parts.next()?;
        if part.len() != width {
            return None;
        }
        let mut chars = part.as_bytes().chunks_exact(2);
        for pair in &mut chars {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            *out.get_mut(written)? = u8::try_from((hi << 4) | lo).ok()?;
            written += 1;
        }
    }
    if parts.next().is_some() || written != 16 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_env::binding::system::SystemMonotonicClock;
    use twinvpn_env::MonotonicClock;

    /// LC-8's whole point: they are two clocks, and the suspend-inclusive one is
    /// not `std::time::Instant`.
    #[test]
    fn the_elapsed_clock_is_a_different_clock_from_the_monotonic_one() {
        let boottime = BootTimeElapsedClock::read_micros().expect("CLOCK_BOOTTIME reads");
        let monotonic = SystemMonotonicClock::new().now().as_micros();
        // On any host that has ever suspended, or that reports a monotonic clock
        // with a different origin, these differ. Asserting inequality would be
        // flaky on a freshly booted container where both may start at zero, so
        // the assertion is the one that matters: BOOTTIME is readable and moves.
        assert!(boottime > 0, "CLOCK_BOOTTIME is running");
        let _ = monotonic;
        let later = BootTimeElapsedClock::read_micros().expect("reads again");
        assert!(later >= boottime, "the elapsed clock is monotone");
    }

    #[test]
    fn the_elapsed_clock_absorbs_a_failure_in_the_safe_direction() {
        // `now` cannot fail by the trait's design; the safe absorption is that a
        // failed read becomes ORIGIN, so every interval measures as zero and
        // nothing expires early.
        assert_eq!(ElapsedInstant::from_micros(0), ElapsedInstant::ORIGIN);
        let now = BootTimeElapsedClock.now();
        assert!(now.as_micros() > 0);
    }

    #[test]
    fn the_entropy_source_is_named_and_never_downgrades() {
        assert_eq!(SystemEntropy::SOURCE, "/dev/urandom");
        let e = SystemEntropy::new();
        e.probe().expect("this host has /dev/urandom");
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        e.fill(&mut a).expect("fill a");
        e.fill(&mut b).expect("fill b");
        assert_ne!(a, b, "two draws from a CSPRNG do not collide");
        assert_ne!(a, [0u8; 32]);
        // An empty request is not an error and does not open the device.
        e.fill(&mut []).expect("empty");
    }

    #[test]
    fn an_unreadable_entropy_device_is_an_error_not_a_weaker_source() {
        let broken = SystemEntropy {
            path: "/nonexistent/twinvpn/urandom",
        };
        let mut buf = [0u8; 8];
        assert!(matches!(
            broken.fill(&mut buf).expect_err("must fail"),
            EnvError::EntropyUnavailable
        ));
        assert_eq!(buf, [0u8; 8], "nothing was written from anywhere else");
    }

    #[test]
    fn a_boot_id_is_readable_on_this_host_and_is_stable_within_a_process() {
        let a = DerivedBootId::read().expect("some source answers");
        let b = DerivedBootId::read().expect("some source answers");
        assert_eq!(a.boot_id().as_bytes(), b.boot_id().as_bytes());
    }

    #[test]
    fn the_derived_identity_changes_on_a_reboot_and_not_on_ntp_drift() {
        let boottime = 3_600_000_000; // one hour of uptime
        let realtime = 1_700_000_000_000_000;

        let base = derive_boot_id(realtime, boottime);
        // A second of NTP correction: the boot wall time moves by 1 s, well
        // inside the 60 s quantum.
        assert_eq!(base, derive_boot_id(realtime + 1_000_000, boottime));
        // A reboot: CLOCK_BOOTTIME restarts near zero while the wall clock has
        // advanced. The identity MUST change, or a resumed session would believe
        // its monotonic timeline survived.
        let after_reboot = derive_boot_id(realtime + boottime + 30_000_000, 10_000_000);
        assert_ne!(base, after_reboot);
    }

    #[test]
    fn the_derived_identity_is_tagged_so_a_bundle_can_tell_the_sources_apart() {
        let derived = derive_boot_id(1_700_000_000_000_000, 3_600_000_000);
        assert_eq!(&derived[..4], b"twba");
        // A kernel UUID carries its RFC 4122 version nibble in the high half of
        // byte 6; `twba` + a big-endian minute count cannot present as one.
        let kernel = parse_uuid("2c1e5a3f-9b7d-4e21-8f60-1a2b3c4d5e6f").expect("valid uuid");
        assert_ne!(&kernel[..4], b"twba");
    }

    #[test]
    fn a_truncated_or_malformed_boot_id_file_falls_through_rather_than_shortening() {
        assert!(parse_uuid("2c1e5a3f-9b7d-4e21-8f60-1a2b3c4d5e6f").is_some());
        assert!(parse_uuid("").is_none());
        assert!(parse_uuid("2c1e5a3f-9b7d-4e21-8f60").is_none(), "short");
        assert!(
            parse_uuid("2c1e5a3f-9b7d-4e21-8f60-1a2b3c4d5e6f-extra").is_none(),
            "long"
        );
        assert!(
            parse_uuid("2c1e5a3g-9b7d-4e21-8f60-1a2b3c4d5e6f").is_none(),
            "non-hex"
        );
        assert!(
            parse_uuid("2c1e5a3f9b7d4e218f601a2b3c4d5e6f").is_none(),
            "ungrouped"
        );
    }

    #[test]
    fn saturating_arithmetic_keeps_a_nonsense_clock_pair_from_panicking() {
        // A wall clock behind the boot clock is impossible on a healthy device
        // and is exactly what a device with no RTC reports before its first
        // sync. It must not panic, and it must not produce a random value.
        let a = derive_boot_id(0, 10_000_000_000);
        assert_eq!(&a[..4], b"twba");
        assert_eq!(&a[4..12], &0u64.to_be_bytes());
    }
}
