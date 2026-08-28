//! The three clocks, the platform CSPRNG, and the boot identity.
//!
//! **Authority:** ADR-0022 LC-8 and its per-platform primitive table, LC-24
//! step 1 (the reboot discriminator); ADR-0018 CD-1 (three non-interchangeable
//! clocks), CD-1a (the wall clock's three states), CD-2 (bound at construction),
//! CD-3 (the deny-list and its W-36 platform-primitive exemption), CB-3, DP-4;
//! `docs/implementation/ownership.md` §6 and §8 **W-7**;
//! [`twinvpn_env::binding::system::ElapsedClockFn`].
//!
//! # LC-8's Windows row, and the one thing that is invisible when it is wrong
//!
//! | Capability | Windows primitive | Suspend |
//! |---|---|---|
//! | [`MonotonicClock`] | `QueryUnbiasedInterruptTimePrecise` — **"unbiased" means sleep is EXCLUDED** | excluded |
//! | [`ElapsedClock`] | `QueryInterruptTimePrecise` — biased, so sleep is **included** | included |
//! | [`WallClock`] | `GetSystemTimeAsFileTime` | n/a |
//!
//! An earlier draft of LC-8 attributed `QueryUnbiasedInterruptTime` to the
//! *inclusive* clock; that was backwards, and the table above is the corrected
//! one. Getting it backwards compiles, passes every test that does not suspend,
//! and fails only on a machine that actually sleeps — which is why the two
//! readers below are separate named functions with separate synthetic values on
//! a non-Windows host, so that a crossed wire is a failing assertion here rather
//! than a field report later.
//!
//! # Why this crate supplies a `MonotonicClock` at all
//!
//! `twinvpn-env` ships `SystemMonotonicClock` over `std::time::Instant`, and its
//! own documentation rules it out here:
//!
//! > Rust's `Instant` on Windows uses `QueryPerformanceCounter`, which does
//! > *not* exclude sleep, so a Windows shell **must** supply its own
//! > `MonotonicClock` rather than take this one.
//!
//! So on this platform **all three** clocks are the adapter's, not just the
//! suspend-inclusive one W-7 names.
//!
//! # CD-3, and W-36
//!
//! `core/xtask/src/checks.rs` `CD3_PLATFORM_PRIMITIVES` permits
//! `QueryUnbiasedInterruptTime`, `QueryInterruptTime` and
//! `GetSystemTimeAsFileTime` inside a `twinvpn-platform-*` crate — the exemption
//! W-36 established after `desktop-linux` found the two lints unsatisfiable in
//! conjunction. The `…Precise` spellings contain those needles, so they are
//! permitted. `BCryptGenRandom` is not on the deny-list. What stays denied even
//! here is `Instant::now`, `SystemTime::now`, `std::time::Instant`,
//! `tokio::time` and `chrono`, and none of them appears in this file — including
//! in its tests.
//!
//! # This host is not Windows
//!
//! Every `#[cfg(windows)]` reader below has a `#[cfg(not(windows))]` sibling
//! returning a **fixed, obviously-synthetic value**. Those siblings exist so the
//! target-free layers — the unit conversion, the boot-identity mixing, the
//! `WallClockReading` construction — can be exercised on the Linux host this
//! crate was written on. **No code path binds these clocks on a non-Windows
//! host**: `WindowsPlatformAdapter` is constructed only by the Windows service,
//! and the values below would be nonsense anywhere else.

use std::sync::Arc;

use twinvpn_env::binding::system::WALL_CLOCK_PLAUSIBILITY_FLOOR_MS;
use twinvpn_env::{
    BootId, BootIdSource, ElapsedClock, ElapsedInstant, Entropy, EnvError, MonotonicClock,
    MonotonicInstant, OffsetSource, WallClock, WallClockReading, WallMillis,
};

/// 100-nanosecond ticks per microsecond.
///
/// Both interrupt-time APIs and `FILETIME` count in 100 ns units; every reading
/// this crate hands to `twinvpn-env` is in microseconds. One constant, so the
/// conversion cannot be spelled differently in two places.
const TICKS_PER_MICRO: u64 = 10;

/// 100-nanosecond ticks per millisecond.
const TICKS_PER_MILLI: u64 = 10_000;

/// 100-nanosecond ticks per second.
const TICKS_PER_SECOND: u64 = 10_000_000;

/// Ticks between the `FILETIME` epoch (1601-01-01Z) and the Unix epoch.
///
/// `11_644_473_600` seconds, in 100 ns units. A constant of the two calendars,
/// not a decision.
const FILETIME_TO_UNIX_TICKS: u64 = 116_444_736_000_000_000;

// ---------------------------------------------------------------------------
// the platform readers — the whole of this file's `#[cfg(windows)]`
// ---------------------------------------------------------------------------

/// The suspend-**exclusive** interrupt time, in 100 ns ticks.
#[cfg(windows)]
fn read_unbiased_ticks() -> u64 {
    let mut ticks: u64 = 0;
    // SAFETY: `QueryUnbiasedInterruptTimePrecise` writes one `u64` through the
    // pointer and reads nothing. `ticks` is a live, aligned, initialised local
    // of exactly that type, so the write is in bounds and well aligned. The
    // function cannot fail and returns no status.
    unsafe {
        windows_sys::Win32::System::WindowsProgramming::QueryUnbiasedInterruptTimePrecise(
            &raw mut ticks,
        );
    }
    ticks
}

/// The suspend-**inclusive** (biased) interrupt time, in 100 ns ticks.
#[cfg(windows)]
fn read_biased_ticks() -> u64 {
    let mut ticks: u64 = 0;
    // SAFETY: identical to `read_unbiased_ticks` — one `u64` written through a
    // pointer to a live, aligned local of that type.
    unsafe {
        windows_sys::Win32::System::WindowsProgramming::QueryInterruptTimePrecise(&raw mut ticks);
    }
    ticks
}

/// The system time, in 100 ns ticks since the `FILETIME` epoch.
#[cfg(windows)]
fn read_system_time_ticks() -> u64 {
    let mut filetime = windows_sys::Win32::Foundation::FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: `GetSystemTimeAsFileTime` writes one `FILETIME` through the
    // pointer. `filetime` is a live, aligned, fully initialised local of that
    // exact type. The call cannot fail and returns nothing.
    unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime(&raw mut filetime);
    }
    (u64::from(filetime.dwHighDateTime) << 32) | u64::from(filetime.dwLowDateTime)
}

/// Fills `dst` from the platform CSPRNG.
#[cfg(windows)]
fn fill_random(dst: &mut [u8]) -> Result<(), EnvError> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    let len = u32::try_from(dst.len()).map_err(|_| EnvError::EntropyUnavailable)?;
    // SAFETY: the buffer pointer and length describe `dst` exactly, so
    // `BCryptGenRandom` writes only within it. A null algorithm handle is the
    // documented form for `BCRYPT_USE_SYSTEM_PREFERRED_RNG`, which selects the
    // system default generator and needs no opened algorithm provider.
    let status = unsafe {
        BCryptGenRandom(
            core::ptr::null_mut(),
            dst.as_mut_ptr(),
            len,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    // `NTSTATUS` is a success when non-negative; `STATUS_SUCCESS` is zero. There
    // is deliberately no fallback branch: a silent downgrade here is
    // indistinguishable from working, and the value it produces is the one every
    // nonce and key depends on.
    if status >= 0 {
        Ok(())
    } else {
        Err(EnvError::EntropyUnavailable)
    }
}

/// The machine's stable identifier: `HKLM\SOFTWARE\Microsoft\Cryptography`
/// `MachineGuid`, as its raw UTF-16 bytes.
///
/// The same value ADR-0020 §11.12 names as the Windows half of
/// `StoreBindingToken`'s `host_id`, so a device that reports a foreign host in
/// one place reports it in the other.
#[cfg(windows)]
fn read_machine_id() -> Result<Vec<u8>, EnvError> {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};

    /// `SOFTWARE\Microsoft\Cryptography`, NUL-terminated UTF-16.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(core::iter::once(0)).collect()
    }

    let subkey = wide(r"SOFTWARE\Microsoft\Cryptography");
    let value = wide("MachineGuid");
    // A GUID in registry string form is 38 UTF-16 code units plus a NUL; 128
    // bytes is generous and bounded, which is `ownership.md` §6 rule 10 applied
    // to an OS-supplied length.
    let mut buffer = [0u8; 128];
    let mut len = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
    // SAFETY: `subkey` and `value` are NUL-terminated UTF-16 buffers that
    // outlive the call. `buffer` and `len` describe a live byte buffer of
    // exactly `len` bytes, which is the contract `RegGetValueW` writes under; it
    // reports the needed size in `len` and writes nothing on overflow.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            core::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &raw mut len,
        )
    };
    if status != windows_sys::Win32::Foundation::ERROR_SUCCESS {
        return Err(EnvError::EntropyUnavailable);
    }
    let taken = usize::try_from(len).unwrap_or(0).min(buffer.len());
    Ok(buffer[..taken].to_vec())
}

/// The synthetic suspend-exclusive reading on a host that is not Windows.
///
/// Deliberately distinct from [`SYNTHETIC_BIASED_TICKS`]: the gap between them
/// stands in for accumulated suspend, so a build that crossed the two readers
/// fails `the_elapsed_clock_is_not_the_monotonic_clock` on this host.
#[cfg(not(windows))]
pub const SYNTHETIC_UNBIASED_TICKS: u64 = 42_000_000_000;

/// The synthetic suspend-inclusive reading on a host that is not Windows.
#[cfg(not(windows))]
pub const SYNTHETIC_BIASED_TICKS: u64 = 99_000_000_000;

/// The synthetic `FILETIME` reading on a host that is not Windows.
///
/// 2024-01-01T00:00:00Z, which is above `twinvpn-env`'s plausibility floor, so
/// the target-free `WallClockReading` construction can be exercised in both
/// directions.
#[cfg(not(windows))]
pub const SYNTHETIC_SYSTEM_TICKS: u64 = FILETIME_TO_UNIX_TICKS + 1_704_067_200 * TICKS_PER_SECOND;

/// Synthetic stand-in. **Never bound by any code path on this host.**
#[cfg(not(windows))]
fn read_unbiased_ticks() -> u64 {
    SYNTHETIC_UNBIASED_TICKS
}

/// Synthetic stand-in. **Never bound by any code path on this host.**
#[cfg(not(windows))]
fn read_biased_ticks() -> u64 {
    SYNTHETIC_BIASED_TICKS
}

/// Synthetic stand-in. **Never bound by any code path on this host.**
#[cfg(not(windows))]
fn read_system_time_ticks() -> u64 {
    SYNTHETIC_SYSTEM_TICKS
}

/// **Refuses**, rather than producing synthetic bytes.
///
/// The other synthetic readers return a fixed value because a wrong clock on a
/// host that never runs this code costs nothing. A fixed *random* value would
/// cost everything: it is the one stand-in that, if it ever escaped into a real
/// build, would be indistinguishable from working while producing predictable
/// nonces and keys. So this one fails closed.
#[cfg(not(windows))]
fn fill_random(_dst: &mut [u8]) -> Result<(), EnvError> {
    Err(EnvError::EntropyUnavailable)
}

/// **Refuses**, for the same reason [`ProcBootId`]-style fabrication is refused
/// on Linux: an invented machine identifier would make "we rebooted" and "we did
/// not" the same fact.
#[cfg(not(windows))]
fn read_machine_id() -> Result<Vec<u8>, EnvError> {
    Err(EnvError::EntropyUnavailable)
}

// ---------------------------------------------------------------------------
// the clocks
// ---------------------------------------------------------------------------

/// The suspend-**exclusive** clock: `QueryUnbiasedInterruptTimePrecise`.
///
/// Every timer in `docs/reliability.md` §5 runs on this. The origin is fixed at
/// construction, matching `MonotonicInstant`'s contract that the origin is
/// "process-local and meaningless off-device".
#[derive(Debug, Clone, Copy)]
pub struct WindowsMonotonicClock {
    origin_ticks: u64,
}

impl Default for WindowsMonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsMonotonicClock {
    /// Fixes this clock's origin at the moment of construction.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin_ticks: read_unbiased_ticks(),
        }
    }

    /// Binds it as a shared capability, ready for [`twinvpn_env::EnvParts`].
    #[must_use]
    pub fn shared() -> Arc<dyn MonotonicClock> {
        Arc::new(Self::new())
    }
}

impl MonotonicClock for WindowsMonotonicClock {
    fn now(&self) -> MonotonicInstant {
        // Saturating rather than wrapping: the interrupt time is monotone by
        // contract, and a non-monotone pair would be a platform defect. Turning
        // it into a huge reading would turn that defect into a timer that never
        // fires; zero is the direction that fires early and is noticed.
        let ticks = read_unbiased_ticks().saturating_sub(self.origin_ticks);
        MonotonicInstant::from_micros(ticks / TICKS_PER_MICRO)
    }
}

/// The suspend-**inclusive** clock: `QueryInterruptTimePrecise`.
///
/// Absolute since boot rather than origin-relative, exactly as
/// `twinvpn-platform-linux`'s `CLOCK_BOOTTIME` reading is: LC-24 step 1 measures
/// a suspend gap across a *process* that may have restarted, so a per-process
/// origin would make the gap unmeasurable.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsElapsedClock;

impl WindowsElapsedClock {
    /// Binds the clock.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Binds it as a shared capability.
    #[must_use]
    pub fn shared() -> Arc<dyn ElapsedClock> {
        Arc::new(Self)
    }

    /// The raw reading in microseconds.
    ///
    /// Separated from [`ElapsedClock::now`] so a test can read the primitive
    /// this clock is *supposed* to read, which is the whole of LC-8's
    /// invisible failure.
    #[must_use]
    pub fn read_micros() -> u64 {
        read_biased_ticks() / TICKS_PER_MICRO
    }
}

impl ElapsedClock for WindowsElapsedClock {
    fn now(&self) -> ElapsedInstant {
        ElapsedInstant::from_micros(Self::read_micros())
    }
}

/// The wall clock: `GetSystemTimeAsFileTime`. **Evidence only.**
///
/// # Why the reading is `Offset`, not `Trusted`
///
/// CD-1a asks the binding to say what the platform *claims* about its own clock,
/// and Windows offers no cheap, dependable answer. A domain-joined host, an
/// NTP-synced workgroup host and a host whose CMOS battery is flat all return
/// the same thing from `GetSystemTimeAsFileTime`; the Windows Time service's
/// synchronisation state is a separate query whose answer is stale the moment it
/// is read. So the conservative variant is the honest one:
/// [`OffsetSource::PersistedLastKnown`], which is literally what a Windows clock
/// is at boot — the value the RTC persisted, adjusted afterwards by whatever
/// w32time managed.
///
/// A shell that *can* prove synchronisation constructs this with
/// [`WallClockTrust::Synchronised`]; the trust is a constructor argument (CD-2)
/// rather than something this type discovers, for the same reason
/// `twinvpn-env`'s own `SystemWallClock` takes one.
///
/// It reads the same primitive [`WindowsBootId`] derives from, deliberately: two
/// different wall-clock sources in one adapter would let the boot-identity
/// derivation and the evidence timestamps drift apart.
#[derive(Debug, Clone, Copy)]
pub struct WindowsWallClock {
    trust: WallClockTrust,
}

/// What the shell claims about the host's wall clock.
///
/// A local mirror of `twinvpn-env`'s own trust enum rather than a re-export:
/// that one is bound to `SystemWallClock`, which reads `SystemTime::now` and is
/// therefore not a thing this crate may call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WallClockTrust {
    /// The shell has proof the clock is synchronised.
    Synchronised,
    /// It has none. **The default**, and the honest answer on Windows.
    Unsynchronised,
}

impl Default for WindowsWallClock {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsWallClock {
    /// Binds the conservative wall clock.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            trust: WallClockTrust::Unsynchronised,
        }
    }

    /// Binds it with the shell's synchronisation claim.
    #[must_use]
    pub const fn with_trust(trust: WallClockTrust) -> Self {
        Self { trust }
    }

    /// Binds it as a shared capability.
    #[must_use]
    pub fn shared(trust: WallClockTrust) -> Arc<dyn WallClock> {
        Arc::new(Self::with_trust(trust))
    }
}

/// Converts a `FILETIME` tick count into a [`WallClockReading`].
///
/// Target-free, so the plausibility floor and the epoch shift are host-tested.
#[must_use]
pub fn reading_from_filetime(ticks: u64, trust: WallClockTrust) -> WallClockReading {
    let Some(unix_ticks) = ticks.checked_sub(FILETIME_TO_UNIX_TICKS) else {
        // Before 1970. Not a plausible time, and therefore not a timestamp to
        // report: CD-1a's `Unset` carries no number precisely so there is
        // nothing to misread as an epoch date.
        return WallClockReading::Unset;
    };
    let millis = unix_ticks / TICKS_PER_MILLI;
    if millis < WALL_CLOCK_PLAUSIBILITY_FLOOR_MS {
        return WallClockReading::Unset;
    }
    match trust {
        WallClockTrust::Synchronised => WallClockReading::Trusted {
            millis: WallMillis::from_millis(millis),
        },
        WallClockTrust::Unsynchronised => WallClockReading::Offset {
            millis: WallMillis::from_millis(millis),
            source: OffsetSource::PersistedLastKnown,
        },
    }
}

impl WallClock for WindowsWallClock {
    fn now(&self) -> WallClockReading {
        reading_from_filetime(read_system_time_ticks(), self.trust)
    }
}

// ---------------------------------------------------------------------------
// entropy
// ---------------------------------------------------------------------------

/// The platform CSPRNG: `BCryptGenRandom` with
/// `BCRYPT_USE_SYSTEM_PREFERRED_RNG`.
///
/// [`Entropy::fill`] **never** falls back to a weaker source. `EntropyUnavailable`
/// is propagated, because "a silent downgrade here is indistinguishable from
/// working, and the value it produces is the one every nonce and key depends on".
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsEntropy;

impl WindowsEntropy {
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

    /// Draws once, so a startup failure is loud rather than deferred to the
    /// first nonce.
    ///
    /// Windows has no equivalent of Linux's `entropy_avail`: the system
    /// preferred RNG is seeded by the kernel before user mode runs, so there is
    /// no unseeded window to test for. A successful draw is the whole probe, and
    /// saying so is more useful than inventing a second check that asserts
    /// nothing.
    ///
    /// # Errors
    ///
    /// [`EnvError::EntropyUnavailable`] if `BCryptGenRandom` refuses.
    pub fn probe(&self) -> Result<(), EnvError> {
        let mut probe = [0u8; 32];
        self.fill(&mut probe)
    }
}

impl Entropy for WindowsEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
        if dst.is_empty() {
            return Ok(());
        }
        fill_random(dst)
    }
}

// ---------------------------------------------------------------------------
// the boot identity
// ---------------------------------------------------------------------------

/// The coarse unit the derived boot instant is truncated to.
///
/// **A decision recorded as one.** The two readings that produce the boot
/// instant are taken at slightly different moments, so their difference jitters
/// by the width of the gap between them — sub-microsecond on a quiet host,
/// microseconds under load. One second is four to six orders of magnitude above
/// that, which makes the derived value stable across reads. See
/// [`WindowsBootId`]'s own documentation for the residual this does *not*
/// remove.
pub const BOOT_INSTANT_QUANTUM_TICKS: u64 = TICKS_PER_SECOND;

/// How many times the pair of clocks is sampled before the boot instant is
/// derived.
///
/// **A decision recorded as one.** The biased interrupt time is read *first* and
/// the system time second, so every sample under-estimates the boot instant by
/// the gap between the two reads; taking the **minimum** of the differences
/// therefore converges on the true value from below, and eight samples is enough
/// to catch one quiet interval on a loaded machine without turning construction
/// into a measurable cost.
pub const BOOT_INSTANT_SAMPLES: usize = 8;

/// The boot identity, derived rather than supplied.
///
/// # Windows has no `boot_id`, so this one is constructed
///
/// Linux hands out a fresh random UUID per boot and holds it for the life of the
/// boot. Windows has no equivalent, so the identity here is derived from the two
/// facts that together change at a reboot and at nothing else:
///
/// ```text
/// boot_instant = system_time - biased_interrupt_time     (truncated to a second)
/// boot_id      = mix(boot_instant, MachineGuid)
/// ```
///
/// The biased interrupt time includes suspend, so the difference is constant
/// across a sleep/resume cycle — which is exactly what LC-24 step 1 needs:
/// `boot_id` changed means "this is not a resume, run LC-4 as a cold start".
///
/// # Where this is weaker than Linux's, precisely
///
/// 1. **It is not random.** Two hosts with the same `MachineGuid` — a cloned VM
///    image — that booted in the same second derive the same identity. That
///    matters for nothing LC-24 does, because a boot identity is compared only
///    against this device's own previous value, but it means the value must
///    never be treated as a device secret or a device identifier.
/// 2. **A boot instant near a second boundary is ambiguous.** The truncation
///    makes the value stable against jitter *unless* the true boot instant lies
///    within the sampling error of a second boundary, in which case two
///    processes in the same boot can derive different identities. The
///    consequence is bounded and is in the safe direction: LC-24 step 1
///    classifies the resume as a cold start, and a cold start runs the whole of
///    LC-4 — including step 3's enforcement query and step 4's re-assertion —
///    rather than skipping it.
/// 3. **The mixing is not cryptographic.** `mix` is FNV-1a, chosen because it
///    is short enough to read in full and needs no dependency. It is a
///    diffusion function, not a hash: it makes two nearby boot instants produce
///    unrelated identities, and it makes no claim about preimages.
///
/// Read **once, at construction**, and cached: the value cannot change while the
/// process lives, and a per-call derivation would make an equality comparison
/// depend on the registry still being readable.
#[derive(Debug, Clone, Copy)]
pub struct WindowsBootId {
    id: BootId,
}

impl WindowsBootId {
    /// Derives the boot identity.
    ///
    /// # Errors
    ///
    /// [`EnvError::EntropyUnavailable`] if `MachineGuid` cannot be read — the
    /// same failure shape the shell already handles for the CSPRNG, and the same
    /// reasoning `twinvpn-platform-linux` gives for refusing to fabricate one: a
    /// fabricated boot identity would make "we rebooted" and "we did not" the
    /// same fact.
    pub fn read() -> Result<Self, EnvError> {
        let machine_id = read_machine_id()?;
        Ok(Self {
            id: boot_id_from(derive_boot_instant_ticks(), &machine_id),
        })
    }

    /// Derives it from readings a caller supplies, for a test or a diagnostic
    /// that wants to see the inputs.
    #[must_use]
    pub fn from_parts(boot_instant_ticks: u64, machine_id: &[u8]) -> Self {
        Self {
            id: boot_id_from(boot_instant_ticks, machine_id),
        }
    }
}

impl BootIdSource for WindowsBootId {
    fn boot_id(&self) -> BootId {
        self.id
    }
}

/// Samples the two clocks and returns the tightest boot instant observed.
///
/// See [`BOOT_INSTANT_SAMPLES`] for why the minimum is the right reduction.
#[must_use]
pub fn derive_boot_instant_ticks() -> u64 {
    let mut best = u64::MAX;
    for _ in 0..BOOT_INSTANT_SAMPLES {
        // Interrupt time first, system time second: the sample under-estimates
        // the boot instant by the gap, so the minimum converges from below.
        let interrupt = read_biased_ticks();
        let system = read_system_time_ticks();
        best = best.min(system.saturating_sub(interrupt));
    }
    best
}

/// The boot identity for a boot instant and a machine identifier.
///
/// **A pure function**, so the truncation and the mixing are host-tested in full.
#[must_use]
pub fn boot_id_from(boot_instant_ticks: u64, machine_id: &[u8]) -> BootId {
    let quantised = boot_instant_ticks / BOOT_INSTANT_QUANTUM_TICKS;
    let mut input = Vec::with_capacity(8 + machine_id.len());
    input.extend_from_slice(&quantised.to_be_bytes());
    input.extend_from_slice(machine_id);
    BootId::from_array(mix(&input))
}

/// FNV-1a, 128-bit, with a finalisation step.
///
/// Written out rather than depended on, and **not cryptographic**: it diffuses,
/// so two nearby inputs produce unrelated identities, and it offers no preimage
/// or collision resistance. Nothing here needs either — a boot identity is
/// compared for equality against this device's own previous value and is never a
/// secret, an identifier, or an authentication input.
///
/// # Why the finalisation is not optional
///
/// Plain FNV-1a barely diffuses the **last** byte it consumes: that byte is
/// xor-ed in and then passed through a single multiply, which carries a
/// low-order change only a little way up the word. `boot_id_from` puts the
/// machine identifier last, so without a finaliser two hosts whose `MachineGuid`
/// differed in its final character would derive nearly-identical identities.
/// That breaks nothing LC-24 does — the comparison is against this device's own
/// previous value — but "nearly identical" is not a property worth shipping when
/// two multiplies fix it, and
/// `the_mixing_diffuses_a_one_bit_change_across_the_whole_output` is what caught
/// it.
///
/// The finaliser is `splitmix64`'s, applied to each half with the other half fed
/// in, so a change anywhere in the state reaches every output byte.
fn mix(input: &[u8]) -> [u8; 16] {
    /// The FNV-1a 128-bit offset basis.
    const OFFSET_BASIS: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    /// The FNV-1a 128-bit prime, `2^88 + 2^8 + 0x3b`.
    const PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;

    let mut hash = OFFSET_BASIS;
    for byte in input {
        hash ^= u128::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }

    // Masked, so the narrowing is a value the compiler can prove fits rather
    // than a truncating cast a reader has to check.
    let low_mask = u128::from(u64::MAX);
    let mut lo = u64::try_from(hash & low_mask).unwrap_or(u64::MAX);
    let mut hi = u64::try_from((hash >> 64) & low_mask).unwrap_or(u64::MAX);
    lo = avalanche(lo ^ hi);
    hi = avalanche(hi ^ lo);

    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&hi.to_be_bytes());
    out[8..].copy_from_slice(&lo.to_be_bytes());
    out
}

/// `splitmix64`'s finaliser: three shift-xors around two odd multiplies.
///
/// A bijection on `u64` with good avalanche. Named separately so the two calls
/// above read as one step each rather than as six lines of constants.
const fn avalanche(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The clock-distinctness check — LC-8's invisible failure, made visible.**
    ///
    /// The two readers are separate named functions over separate primitives,
    /// and on this host they return deliberately different synthetic values. A
    /// build that wired `QueryInterruptTimePrecise` into the monotonic clock, or
    /// `QueryUnbiasedInterruptTimePrecise` into the elapsed one, fails here
    /// rather than on a laptop that was closed overnight.
    #[test]
    fn the_elapsed_clock_is_not_the_monotonic_clock() {
        let monotonic = WindowsMonotonicClock::new();
        let elapsed = WindowsElapsedClock::new();
        // The monotonic clock zeroes at construction; the elapsed clock is
        // absolute since boot. A build that substituted one for the other would
        // read them the same way, and the second assertion is what would fail.
        assert!(
            monotonic.now().as_micros() < 1_000_000,
            "the monotonic clock zeroes at construction"
        );
        assert!(
            elapsed.now().as_micros() > 1_000_000,
            "the elapsed clock is absolute since boot; a value near zero means \
             the monotonic clock was substituted, which is exactly LC-8's \
             invisible-on-CI failure"
        );
        // The biased reading includes suspend and the unbiased one excludes it,
        // so the first can never be the smaller of the two.
        //
        // On a Windows host that has never slept they are **equal**, which is
        // LC-8's warning restated: no test on such a host can prove the right
        // primitive was chosen. The inequality below is what is checkable
        // everywhere; the strict difference is only assertable on this host,
        // where the two synthetic values are deliberately distinct.
        assert!(read_biased_ticks() >= read_unbiased_ticks());
        #[cfg(not(windows))]
        assert_ne!(
            read_unbiased_ticks(),
            read_biased_ticks(),
            "the two primitives must not be the same reader"
        );
    }

    #[test]
    fn the_elapsed_clock_reads_the_biased_primitive_and_converts_to_microseconds() {
        // 100 ns ticks in, microseconds out. One conversion constant, asserted
        // against the reader it is applied to.
        assert_eq!(
            WindowsElapsedClock::read_micros(),
            read_biased_ticks() / TICKS_PER_MICRO
        );
        assert_eq!(TICKS_PER_MICRO, 10);
        assert_eq!(TICKS_PER_MILLI, 10_000);
        assert_eq!(TICKS_PER_SECOND, 10_000_000);
    }

    #[test]
    fn the_monotonic_clock_never_goes_backwards_across_repeated_reads() {
        let clock = WindowsMonotonicClock::new();
        let mut previous = clock.now();
        for _ in 0..1_000 {
            let now = clock.now();
            assert!(now >= previous, "a monotonic reading went backwards");
            previous = now;
        }
    }

    #[test]
    fn a_filetime_below_the_plausibility_floor_carries_no_timestamp_at_all() {
        // CD-1a: `Unset` has no number, precisely so there is none to misread as
        // 1970 — which would make every `nbf` check pass and every `exp` check
        // fail.
        assert_eq!(
            reading_from_filetime(0, WallClockTrust::Synchronised),
            WallClockReading::Unset
        );
        assert_eq!(
            reading_from_filetime(FILETIME_TO_UNIX_TICKS, WallClockTrust::Synchronised),
            WallClockReading::Unset,
            "the Unix epoch itself is below the floor"
        );
        // One tick below the floor, and exactly at it.
        let floor_ticks =
            FILETIME_TO_UNIX_TICKS + WALL_CLOCK_PLAUSIBILITY_FLOOR_MS * TICKS_PER_MILLI;
        assert_eq!(
            reading_from_filetime(floor_ticks - 1, WallClockTrust::Synchronised),
            WallClockReading::Unset
        );
        assert!(reading_from_filetime(floor_ticks, WallClockTrust::Synchronised).is_resolved());
    }

    #[test]
    fn an_unsynchronised_windows_clock_reports_offset_and_never_trusted() {
        // The conservative variant, and the honest one: a flat CMOS battery and
        // a domain-joined host are indistinguishable through this API.
        match WindowsWallClock::new().now() {
            WallClockReading::Offset { source, millis } => {
                assert_eq!(source, OffsetSource::PersistedLastKnown);
                assert!(millis.as_millis() >= WALL_CLOCK_PLAUSIBILITY_FLOOR_MS);
            }
            other => panic!("expected an Offset reading, got {other:?}"),
        }
        // ...and a shell that can prove synchronisation gets `Trusted`.
        assert!(matches!(
            WindowsWallClock::with_trust(WallClockTrust::Synchronised).now(),
            WallClockReading::Trusted { .. }
        ));
    }

    #[test]
    fn the_epoch_shift_is_the_calendars_and_not_a_rounding() {
        // 2024-01-01T00:00:00Z, exactly.
        let ticks = FILETIME_TO_UNIX_TICKS + 1_704_067_200 * TICKS_PER_SECOND;
        match reading_from_filetime(ticks, WallClockTrust::Synchronised) {
            WallClockReading::Trusted { millis } => {
                assert_eq!(millis.as_millis(), 1_704_067_200_000);
            }
            other => panic!("expected Trusted, got {other:?}"),
        }
    }

    #[test]
    fn the_boot_identity_survives_the_jitter_between_the_two_clock_reads() {
        // The property that makes LC-24 step 1 work: readings taken microseconds
        // apart within one boot must derive the same identity, or every resume
        // classifies as a cold start.
        let machine = b"{7f3b2a10-0000-4000-8000-000000000001}";
        let base = 1_700_000_000 * TICKS_PER_SECOND + 5_000_000;
        let reference = boot_id_from(base, machine);
        for jitter in [0u64, 1, 37, 1_000, 9_999, 1_000_000, 4_999_999] {
            assert_eq!(
                boot_id_from(base + jitter, machine).as_bytes(),
                reference.as_bytes(),
                "a jitter of {jitter} ticks changed the boot identity"
            );
            assert_eq!(
                boot_id_from(base - jitter, machine).as_bytes(),
                reference.as_bytes(),
                "a jitter of -{jitter} ticks changed the boot identity"
            );
        }
    }

    #[test]
    fn a_different_boot_derives_a_different_identity() {
        let machine = b"{7f3b2a10-0000-4000-8000-000000000001}";
        let first = 1_700_000_000 * TICKS_PER_SECOND;
        let reference = boot_id_from(first, machine);
        // One quantum apart is a different boot, and every larger gap is too.
        for gap_seconds in [1u64, 2, 60, 3_600, 86_400] {
            let other = boot_id_from(first + gap_seconds * TICKS_PER_SECOND, machine);
            assert_ne!(
                other.as_bytes(),
                reference.as_bytes(),
                "a reboot {gap_seconds} s later derived the same identity"
            );
        }
    }

    #[test]
    fn the_machine_identifier_is_mixed_in_and_not_ignored() {
        let instant = 1_700_000_000 * TICKS_PER_SECOND;
        let a = boot_id_from(instant, b"{aaaaaaaa-0000-4000-8000-000000000001}");
        let b = boot_id_from(instant, b"{bbbbbbbb-0000-4000-8000-000000000002}");
        assert_ne!(a.as_bytes(), b.as_bytes());
        // An empty machine identifier is still a defined input; it must not
        // collapse to the same value as a populated one.
        assert_ne!(boot_id_from(instant, b"").as_bytes(), a.as_bytes());
    }

    #[test]
    fn the_boot_identity_is_never_all_zero_and_is_stable_for_one_input() {
        let id = boot_id_from(0, b"m");
        assert_ne!(id.as_bytes(), &[0u8; 16]);
        assert_eq!(
            boot_id_from(0, b"m").as_bytes(),
            boot_id_from(0, b"m").as_bytes()
        );
        // `from_parts` and `boot_id_from` are the same derivation, so a
        // diagnostic that shows the inputs shows the ones actually used.
        assert_eq!(
            WindowsBootId::from_parts(0, b"m").boot_id().as_bytes(),
            id.as_bytes()
        );
    }

    #[test]
    fn the_mixing_diffuses_a_one_bit_change_across_the_whole_output() {
        // Not a cryptographic claim — an avalanche check strong enough to catch
        // a mixing function that was accidentally additive, which would make
        // two nearby boots produce nearly-equal identities.
        let a = mix(&[0u8; 8]);
        let mut input = [0u8; 8];
        input[7] = 1;
        let b = mix(&input);
        let differing = a.iter().zip(&b).filter(|(x, y)| x != y).count();
        assert!(
            differing >= 8,
            "a one-bit input change moved only {differing} of 16 output bytes"
        );
    }

    #[test]
    fn the_boot_instant_derivation_is_stable_enough_to_quantise() {
        // The property that has to hold on a real host: repeated derivations
        // land in the same quantum, so the boot identity does not change while
        // the process runs. Asserting the raw tick value would be a timing
        // dependency on Windows, where the two clocks genuinely advance between
        // reads; asserting the quantised value is the thing `boot_id_from`
        // actually consumes.
        let first = derive_boot_instant_ticks() / BOOT_INSTANT_QUANTUM_TICKS;
        for _ in 0..16 {
            assert_eq!(
                derive_boot_instant_ticks() / BOOT_INSTANT_QUANTUM_TICKS,
                first,
                "the derived boot instant crossed a quantum boundary within one \
                 process, which would make LC-24 step 1 read a resume as a cold \
                 start"
            );
        }
        assert_eq!(BOOT_INSTANT_SAMPLES, 8);
        assert_eq!(BOOT_INSTANT_QUANTUM_TICKS, TICKS_PER_SECOND);
    }

    #[test]
    #[cfg(not(windows))]
    fn the_boot_instant_derivation_is_the_difference_of_the_two_readings() {
        // On this host both readers are constant, so the reduction's result is
        // exactly the single difference — which is what pins that it is a pure
        // function of the readings and does not accumulate across samples.
        let expected = read_system_time_ticks().saturating_sub(read_biased_ticks());
        assert_eq!(derive_boot_instant_ticks(), expected);
        assert_eq!(
            derive_boot_instant_ticks(),
            expected,
            "and it is repeatable"
        );
    }

    /// **The one capability that refuses rather than substituting.**
    ///
    /// On this host `fill_random` has no `BCryptGenRandom` to call, and the
    /// synthetic stand-in the other readers use would be catastrophic here: a
    /// fixed "random" value is indistinguishable from working while producing
    /// predictable nonces and keys. So it fails closed, and this test pins that.
    ///
    /// The consequence is stated rather than hidden: **the `BCryptGenRandom`
    /// path has never executed.** It is compiled by `make cross-check` and
    /// nothing more.
    #[test]
    #[cfg(not(windows))]
    fn the_entropy_source_refuses_on_a_host_that_is_not_windows() {
        let entropy = WindowsEntropy::new();
        let mut buffer = [0u8; 32];
        assert!(matches!(
            entropy.fill(&mut buffer).expect_err("must refuse"),
            EnvError::EntropyUnavailable
        ));
        assert!(matches!(
            entropy.probe().expect_err("must refuse"),
            EnvError::EntropyUnavailable
        ));
        assert_eq!(buffer, [0u8; 32], "and it wrote nothing");
        // A zero-length fill is a no-op, not an error, on every host.
        entropy.fill(&mut []).expect("empty fill");
    }

    #[test]
    #[cfg(not(windows))]
    fn the_boot_identity_refuses_rather_than_fabricating_a_machine_identifier() {
        assert!(matches!(
            WindowsBootId::read().expect_err("must refuse"),
            EnvError::EntropyUnavailable
        ));
    }

    #[test]
    fn every_capability_is_shareable_as_the_env_trait_object() {
        // CD-2: `EnvParts` takes these as `Arc<dyn _>` at construction. A type
        // that was not `Send + Sync` would fail to compile here rather than at
        // the shell's assembly point.
        let _monotonic: Arc<dyn MonotonicClock> = WindowsMonotonicClock::shared();
        let _elapsed: Arc<dyn ElapsedClock> = WindowsElapsedClock::shared();
        let _wall: Arc<dyn WallClock> = WindowsWallClock::shared(WallClockTrust::Unsynchronised);
        let _entropy: Arc<dyn Entropy> = WindowsEntropy::shared();
    }
}
