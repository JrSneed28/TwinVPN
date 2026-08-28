//! The **thinnest** Darwin shim: four syscalls, and everything `#[cfg]`-gated in
//! this crate.
//!
//! **Authority:** ADR-0018 CB-3 and DP-4; ADR-0022 LC-8's per-platform primitive
//! table; ADR-0018 CD-3 as `core/xtask/src/checks.rs` implements it (a
//! `twinvpn-platform-*` crate may name the platform time and entropy primitives
//! and nothing else); `docs/implementation/ownership.md` §10.3's design rule.
//!
//! # Why this file is small on purpose
//!
//! `ownership.md` §10.3: "`#[cfg]` is confined to the thinnest syscall shim, and
//! everything a reviewer would want to see exercised runs its tests on this Linux
//! host." Every other module in this crate is target-free. This one is not, and
//! it holds **every** `#[cfg(target_os = "ios")]` and **every** `unsafe` block the
//! crate has:
//!
//! | Primitive | Why the core cannot make the call | Blocks |
//! |---|---|---|
//! | `mach_continuous_time` + `mach_timebase_info` | ADR-0022 LC-8's suspend-**inclusive** clock; `std` has no such reading (W-7) | 2 |
//! | `getentropy` | W-7's `Entropy`; `twinvpn-env` ships no production implementation | 1 |
//! | `sysctlbyname("kern.boottime")` | W-7's `BootIdSource`; LC-24 classifies a start from it | 1 |
//!
//! # Darwin's `CLOCK_MONOTONIC` is the reverse of Linux's
//!
//! ADR-0022 LC-8 states it in terms, and it is the single most transplantable
//! mistake on this target: on Linux `CLOCK_MONOTONIC` **excludes** suspend and
//! `CLOCK_BOOTTIME` includes it; on Darwin `CLOCK_MONOTONIC`/`mach_absolute_time`
//! exclude it and **`mach_continuous_time` includes it**. A developer carrying
//! the Linux reasoning across picks the wrong one, and the defect is invisible on
//! every host that never sleeps — which is every CI runner.
//!
//! # On a non-Darwin host
//!
//! Each function has a `#[cfg(not(target_os = "ios"))]` counterpart that refuses.
//! They exist so the crate compiles and clippies clean on the Linux build host,
//! which is what lets `make lint` and `make test` cover every other module. A
//! refusal is a named condition, never a fabricated reading: a boot identity
//! invented on a host that has none would make "we rebooted" and "we did not" the
//! same fact.

use twinvpn_env::EnvError;

/// Whether this build can reach the Darwin primitives at all.
///
/// `false` on the Linux build host. Reported so a startup posture says
/// "these readings are unavailable" rather than quietly returning zeros.
#[must_use]
pub const fn darwin_primitives_available() -> bool {
    cfg!(target_os = "ios")
}

#[cfg(target_os = "ios")]
mod imp {
    use core::ffi::{c_char, c_int, c_void};

    use twinvpn_env::EnvError;

    /// `mach_timebase_info_data_t`.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    struct MachTimebaseInfo {
        numer: u32,
        denom: u32,
    }

    extern "C" {
        fn mach_continuous_time() -> u64;
        fn mach_timebase_info(info: *mut MachTimebaseInfo) -> c_int;
        fn getentropy(buf: *mut c_void, len: usize) -> c_int;
        fn sysctlbyname(
            name: *const c_char,
            oldp: *mut c_void,
            oldlenp: *mut usize,
            newp: *mut c_void,
            newlen: usize,
        ) -> c_int;
    }

    /// The suspend-**inclusive** reading, in microseconds.
    pub fn continuous_micros() -> Option<u64> {
        // SAFETY: `mach_timebase_info` writes two `u32`s into the struct we
        // supply, which is a live, correctly-aligned `MachTimebaseInfo` on this
        // stack frame for the whole call. It takes no ownership and stores no
        // pointer.
        let mut timebase = MachTimebaseInfo::default();
        let rc = unsafe { mach_timebase_info(core::ptr::addr_of_mut!(timebase)) };
        if rc != 0 || timebase.denom == 0 {
            return None;
        }
        // SAFETY: no arguments, no pointers; the call reads a kernel counter and
        // returns it by value.
        let ticks = unsafe { mach_continuous_time() };
        // ticks * numer / denom yields nanoseconds. Done in u128 because the
        // product overflows u64 on a device that has been up for weeks with a
        // numer > 1, and a wrapped clock reading is a clock that goes backwards.
        let nanos = u128::from(ticks) * u128::from(timebase.numer) / u128::from(timebase.denom);
        u64::try_from(nanos / 1_000).ok()
    }

    /// Fills `dst` from the platform CSPRNG.
    pub fn fill_entropy(dst: &mut [u8]) -> Result<(), EnvError> {
        // `getentropy(2)` on Darwin accepts at most 256 bytes per call, and
        // returns EIO for more. Chunking is required, not an optimisation.
        for chunk in dst.chunks_mut(256) {
            // SAFETY: `chunk` is a live, uniquely-borrowed slice of exactly
            // `chunk.len()` bytes, and `chunk.len() <= 256` is the documented
            // maximum. The callee writes that many bytes and retains nothing.
            let rc = unsafe { getentropy(chunk.as_mut_ptr().cast::<c_void>(), chunk.len()) };
            if rc != 0 {
                // NEVER a fallback to a weaker source: "a silent downgrade here
                // is indistinguishable from working, and the value it produces
                // is the one every nonce and key depends on."
                return Err(EnvError::EntropyUnavailable);
            }
        }
        Ok(())
    }

    /// `kern.boottime`, as the sixteen bytes of a `struct timeval` pair.
    pub fn boot_time_raw() -> Option<[u8; 16]> {
        // `struct timeval` is `{ time_t tv_sec; suseconds_t tv_usec; }` — on
        // 64-bit Darwin that is 8 + 4 with 4 bytes of tail padding, so the
        // kernel writes 16 bytes. The buffer is sized from the kernel's own
        // answer rather than from that reasoning.
        let mut buffer = [0u8; 16];
        let mut len = buffer.len();
        let name = c"kern.boottime";
        // SAFETY: `name` is a NUL-terminated C string with static storage.
        // `buffer` is a live 16-byte array and `len` is its true length; the
        // callee writes at most `len` bytes and updates `len` to what it wrote.
        // `newp`/`newlen` are null/zero, which is the documented read-only form.
        let rc = unsafe {
            sysctlbyname(
                name.as_ptr(),
                buffer.as_mut_ptr().cast::<c_void>(),
                core::ptr::addr_of_mut!(len),
                core::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 || len == 0 || len > buffer.len() {
            return None;
        }
        Some(buffer)
    }
}

#[cfg(not(target_os = "ios"))]
mod imp {
    use twinvpn_env::EnvError;

    /// Refuses: there is no Darwin clock on this host.
    pub fn continuous_micros() -> Option<u64> {
        None
    }

    /// Refuses. **Never** substitutes a host CSPRNG: a build that silently drew
    /// from a different source than the one it declares is the failure this
    /// whole seam exists to prevent, and it would pass every test.
    pub fn fill_entropy(_dst: &mut [u8]) -> Result<(), EnvError> {
        Err(EnvError::EntropyUnavailable)
    }

    /// Refuses. A fabricated boot identity would make "we rebooted" and "we did
    /// not" the same fact, which is exactly what LC-24 classifies on.
    pub fn boot_time_raw() -> Option<[u8; 16]> {
        None
    }
}

/// The suspend-**inclusive** reading, in microseconds.
///
/// `None` when the primitive is unreachable — on the build host, always.
#[must_use]
pub fn continuous_micros() -> Option<u64> {
    imp::continuous_micros()
}

/// Fills `dst` from the platform CSPRNG.
///
/// # Errors
///
/// [`EnvError::EntropyUnavailable`], propagated and never softened.
pub fn fill_entropy(dst: &mut [u8]) -> Result<(), EnvError> {
    if dst.is_empty() {
        return Ok(());
    }
    imp::fill_entropy(dst)
}

/// The kernel's boot time, as sixteen raw bytes.
#[must_use]
pub fn boot_time_raw() -> Option<[u8; 16]> {
    imp::boot_time_raw()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_build_host_reports_the_primitives_as_unavailable_rather_than_faking_them() {
        // This assertion is the point of the module: on the Linux build host
        // every Darwin reading is ABSENT, and absence is what the callers see.
        // A stub that returned zero would make `crate::clock`'s tests pass here
        // and the product wrong on a device — LC-8's invisible-on-CI failure in
        // its purest form.
        assert_eq!(darwin_primitives_available(), cfg!(target_os = "ios"));
        if !darwin_primitives_available() {
            assert_eq!(continuous_micros(), None);
            assert_eq!(boot_time_raw(), None);
            let mut buf = [0u8; 32];
            assert!(fill_entropy(&mut buf).is_err());
            assert_eq!(buf, [0u8; 32], "a refused fill writes nothing");
        }
    }

    #[test]
    fn an_empty_entropy_fill_is_a_no_op_and_not_a_failure() {
        assert!(fill_entropy(&mut []).is_ok());
    }
}
