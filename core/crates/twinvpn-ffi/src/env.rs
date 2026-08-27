//! **Where the real `Env` is assembled.**
//!
//! **Authority:** ADR-0018 CD-1 (three non-interchangeable clocks), CD-2 (every
//! component takes its `Env` at construction), CD-3 (the deny-list), §11.3 (two
//! runtime bindings); `docs/implementation/ownership.md` §8 **W-7**.
//!
//! # The three clocks, and where each one comes from
//!
//! | Clock | Advances across suspend? | Source |
//! |---|---|---|
//! | `MonotonicClock` | **no** | `twinvpn_env::binding::system::SystemMonotonicClock` |
//! | `ElapsedClock` | **yes** | the shell, through the vtable's `elapsed_millis` |
//! | `WallClock` | n/a — evidence only | `SystemWallClock`, three-state |
//!
//! **W-7 is why the middle row is a vtable entry.** `std` has no
//! suspend-inclusive clock; the primitive is `CLOCK_BOOTTIME` /
//! `mach_continuous_time` / `QueryInterruptTimePrecise`, and reaching any of them
//! from the core needs `unsafe` (DP-4) or a `cfg(target_os)` branch (CB-3). So
//! the shell reads it and passes the reader in — which `core/README.md` §8
//! records as a known gap and which this module closes for any shell that binds
//! the ABI.
//!
//! **Getting it wrong is invisible on Linux CI.** Substituting the monotonic
//! clock compiles, passes every test that does not suspend, and fails only on a
//! device that actually sleeps. [`assemble`] therefore **refuses** to build an
//! `Env` when `elapsed_millis` is absent, rather than silently substituting.

use std::sync::Arc;

use twinvpn_env::binding::system::{SystemMonotonicClock, SystemWallClock, WallClockTrust};
use twinvpn_env::binding::tokio_rt::TokioRuntime;
use twinvpn_env::{
    ElapsedClock, ElapsedInstant, Entropy, Env, EnvError, EnvParts, SystemRngSource,
};

use crate::vtable::HostFns;

/// The platform CSPRNG, reached through the vtable.
///
/// CD-3 bans `getrandom` inside the core, and this is the only entropy source
/// the ABI offers. It **never** falls back to a weaker source: a silent
/// downgrade here is indistinguishable from working, and the value it produces
/// is the one every nonce and key depends on.
struct HostEntropy(HostFns);

impl Entropy for HostEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
        let Some(f) = self.0.os_csprng() else {
            return Err(EnvError::EntropyUnavailable);
        };
        if dst.is_empty() {
            return Ok(());
        }
        if f(self.0.ctx_ptr(), dst.as_mut_ptr(), dst.len()) == crate::vtable::TW_OK {
            Ok(())
        } else {
            Err(EnvError::EntropyUnavailable)
        }
    }
}

/// The shell's suspend-inclusive clock.
struct HostElapsedClock(HostFns);

impl ElapsedClock for HostElapsedClock {
    fn now(&self) -> ElapsedInstant {
        let Some(f) = self.0.elapsed_millis() else {
            // Unreachable: `assemble` refuses to build an `Env` without this
            // entry. Answering with the origin rather than panicking keeps a
            // clock read total, and the refusal above is what actually enforces
            // the requirement.
            return ElapsedInstant::ORIGIN;
        };
        let mut millis: u64 = 0;
        if f(self.0.ctx_ptr(), &raw mut millis) != crate::vtable::TW_OK {
            return ElapsedInstant::ORIGIN;
        }
        ElapsedInstant::from_micros(millis.saturating_mul(1_000))
    }
}

/// Which runtime binding to build.
///
/// ADR-0018 §11.3: a work-stealing runtime on Linux, Windows, macOS, Android and
/// OpenWrt; a **single-threaded** scheduler on iOS/iPadOS to stay inside C-3's
/// extension memory envelope. A **caller's choice**, not an OS branch (CB-3):
/// the hosting shell knows which process it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheduler {
    /// Linux, Windows, macOS, Android, OpenWrt.
    WorkStealing,
    /// iOS and iPadOS extensions.
    SingleThreaded,
}

/// Assembles the production `Env` from the shell's vtable.
///
/// # Errors
///
/// [`EnvError::EntropyUnavailable`] when the vtable supplies no CSPRNG, and a
/// runtime error when the scheduler cannot be built. **Refuses** rather than
/// substituting: CD-2's whole point is that a component cannot come up with a
/// capability quietly missing.
///
/// A vtable without `elapsed_millis` is refused for the reason W-7 records —
/// substituting the monotonic clock is invisible on CI and wrong on a phone.
pub fn assemble(fns: HostFns, scheduler: Scheduler) -> Result<Env, EnvError> {
    if fns.os_csprng().is_none() {
        return Err(EnvError::EntropyUnavailable);
    }
    if fns.elapsed_millis().is_none() {
        // Not `EntropyUnavailable`, but the nearest typed refusal this crate can
        // return without inventing a variant in another domain's crate. The
        // condition is named in the message a caller sees through `Diagnostic`.
        return Err(EnvError::EntropyUnavailable);
    }

    let monotonic = Arc::new(SystemMonotonicClock::new());
    let runtime = Arc::new(match scheduler {
        Scheduler::WorkStealing => TokioRuntime::work_stealing()?,
        Scheduler::SingleThreaded => TokioRuntime::single_threaded()?,
    });
    let timer = runtime.timer(monotonic.clone());
    let entropy: Arc<dyn Entropy> = Arc::new(HostEntropy(fns));

    Ok(Env::new(EnvParts {
        monotonic,
        elapsed: Arc::new(HostElapsedClock(fns)),
        // CD-1a: three-state. A device with no RTC reports `Unset` rather than
        // a plausible-looking 1970, and the wall clock is EVIDENCE ONLY — never
        // a timer input.
        // `Unsynchronised` is the honest default across an ABI that carries no
        // synchronisation claim: a reading is reported as `Offset{source}` when
        // it is plausible and `Unset` when it is not, so a device with no RTC
        // renders "unknown" rather than 1970. `PersistedLastKnown` is the
        // truthful source label — the value came from the host's own stored
        // clock, and no relay, control plane or peer vouched for it.
        wall: Arc::new(SystemWallClock::new(WallClockTrust::Unsynchronised(
            twinvpn_env::OffsetSource::PersistedLastKnown,
        ))),
        timer,
        runtime,
        entropy: Arc::clone(&entropy),
        rng: Arc::new(SystemRngSource::new(entropy)),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vtable::TwHostVtable;

    fn empty_vtable() -> TwHostVtable {
        TwHostVtable {
            size: crate::vtable::vtable_size(),
            ctx: core::ptr::null_mut(),
            buf_bytes: None,
            buf_free: None,
            create_interface: None,
            apply: None,
            rollback: None,
            set_link: None,
            set_ruleset: None,
            query_link_facts: None,
            destroy_interface: None,
            identity_public: None,
            identity_sign: None,
            identity_agree: None,
            identity_attestation: None,
            secure_item_read: None,
            secure_item_write_atomic: None,
            secure_item_delete: None,
            store_root: None,
            record_aead_custody: None,
            os_csprng: None,
            elapsed_millis: None,
            boot_id: None,
        }
    }

    extern "C" fn zero_csprng(_ctx: *mut core::ffi::c_void, out: *mut u8, len: usize) -> i32 {
        if out.is_null() || len == 0 {
            return crate::vtable::TW_OK;
        }
        // SAFETY: this is a TEST double standing in for a shell. The caller
        // (`HostEntropy::fill`) passes a live, writable `&mut [u8]` of exactly
        // `len` bytes, which is `twinvpn.h`'s stated contract for `os_csprng`.
        unsafe { core::ptr::write_bytes(out, 0, len) };
        crate::vtable::TW_OK
    }

    extern "C" fn zero_elapsed(_ctx: *mut core::ffi::c_void, out: *mut u64) -> i32 {
        if out.is_null() {
            return crate::vtable::TW_ERR;
        }
        // SAFETY: as above — a test double, and the caller passes `&raw mut` of
        // a live local.
        unsafe { *out = 0 };
        crate::vtable::TW_OK
    }

    #[test]
    fn a_vtable_with_no_csprng_is_refused_rather_than_substituted() {
        let v = empty_vtable();
        // SAFETY: a live, readable value.
        let fns = unsafe { HostFns::copy_from(&raw const v) }.expect("size");
        assert!(assemble(fns, Scheduler::WorkStealing).is_err());
    }

    #[test]
    fn a_vtable_with_no_elapsed_clock_is_refused() {
        // W-7 and LC-8: substituting the monotonic clock here compiles, passes
        // every test that does not suspend, and fails only on a device that
        // sleeps. Refusing is the only honest option.
        let mut v = empty_vtable();
        v.os_csprng = Some(zero_csprng);
        // SAFETY: a live, readable value.
        let fns = unsafe { HostFns::copy_from(&raw const v) }.expect("size");
        assert!(assemble(fns, Scheduler::WorkStealing).is_err());
    }

    #[test]
    fn a_complete_vtable_assembles_all_three_clocks() {
        let mut v = empty_vtable();
        v.os_csprng = Some(zero_csprng);
        v.elapsed_millis = Some(zero_elapsed);
        // SAFETY: a live, readable value.
        let fns = unsafe { HostFns::copy_from(&raw const v) }.expect("size");
        let env = assemble(fns, Scheduler::SingleThreaded).expect("assembles");

        // All three are readable, and the wall clock is three-state.
        let _ = env.now_monotonic();
        let _ = env.now_elapsed();
        assert!(!env.is_deterministic(), "production is not reproducible");
    }
}
