//! The locked, non-swappable, non-dumpable allocator for the two core-held keys.
//!
//! **Authority:** ADR-0018 CB-5 rows 2 and 3 (the L-DATA static X25519 key `TK`
//! and the store encryption key `SEK` are the *only* keys the core may hold),
//! CB-6a (a core-held key is a **declared per-target fact**), ADR-0001 §7.2
//! L-STORE, ADR-0007 N-5, `docs/threat-model.md` TM-14.
//!
//! # What this actually achieves, stated before what it is for
//!
//! TM-14 already records **TK extraction from process memory as undefended**,
//! and this module does not change that. What it does, on Linux without any
//! privilege:
//!
//! | Protection | Mechanism | Achieved unprivileged? |
//! |---|---|---|
//! | Not written to swap or a hibernation image | `mlock(2)` over exactly the pages | **Yes**, up to `RLIMIT_MEMLOCK` (commonly 8 MiB under systemd, 64 KiB on older hosts). A key is tens of bytes, so the limit binds only if a caller allocates pathologically |
//! | Excluded from a core dump | `madvise(MADV_DONTDUMP)` over exactly the pages | **Yes** on Linux. Silently unavailable elsewhere, and then *reported* as unavailable |
//! | Not inherited by a `fork(2)` child | `madvise(MADV_WIPEONFORK)` | **Yes** on Linux ≥ 4.14. Reported when it is not |
//! | Erased on drop | [`zeroize`] over the region before it is returned to the allocator | **Yes**, unconditionally, on every target |
//!
//! And what it does **not** achieve, which is the part that matters:
//!
//! - It does **not** stop `ptrace(2)`, `/proc/<pid>/mem`, or a debugger running
//!   as the same user or as root. Those are AD-12-at-agent-privilege, and TM-14
//!   records them as undefended.
//! - It does **not** stop the compiler from having left a copy in a register
//!   spill, in a stack temporary, or in a `Vec` that grew. Which is why the
//!   secret must be *constructed inside* a [`LockedBytes`] rather than copied
//!   into one — see [`LockedBytes::new_with`].
//! - It is **not** a substitute for a secure element. CB-5 row 1 keys never come
//!   near this module, and CD-I4 makes that structural: no type here can hold an
//!   identity private scalar because nothing constructs one.
//!
//! # Why `unsafe` is here, and only here
//!
//! `twinvpn-crypto` is the DP-4 unsafe allowlist member. Four `unsafe` blocks
//! live in this module and nowhere else in the crate: the page-aligned
//! allocation, the two `libc` advisory calls, and the deallocation. Each carries
//! a `// SAFETY:` comment naming the invariant it relies on. Everything else in
//! the crate is safe Rust.
//!
//! # Why `cfg(unix)` and not a capability
//!
//! CB-3 forbids `#[cfg(target_os = …)]` above the platform adapter, and this
//! module honours that: it branches on the POSIX *family*, never on an OS. The
//! per-target fact CB-6a asks for is not a compile-time branch at all — it is
//! [`LockedMemoryReport`], measured at runtime from what the kernel actually
//! accepted, and surfaced for `CoreBuildIdentity` (S-46) and the diagnostic
//! bundle. A build that *claims* `MADV_DONTDUMP` and a kernel that refused it
//! are distinguishable here, which a `cfg` could never be.

use zeroize::Zeroize;

/// What the running kernel actually granted for one locked region.
///
/// CB-6a: "a core-held key … MUST be recorded in `CoreBuildIdentity` (S-46) and
/// surfaced in the diagnostic bundle, so 'this device's vault key was
/// software-held' is a readable fact rather than an inference." This is the
/// readable fact, and every field is an *observation*, never an assumption.
// Four independent, individually meaningful observations. `clippy::pedantic`
// suggests an enum, but these are not mutually exclusive states: a kernel can
// grant `mlock` and refuse `MADV_WIPEONFORK`, and CB-6a wants each fact
// readable rather than collapsed into a summary. `tag()` is the summary.
#[allow(clippy::struct_excessive_bools)]
// Four independent, individually meaningful observations. `clippy::pedantic`
// suggests an enum, but these are not mutually exclusive states: a kernel can
// grant `mlock` and refuse `MADV_WIPEONFORK`, and CB-6a wants each fact
// readable rather than collapsed into a summary. `tag()` is the summary.
#[allow(clippy::struct_excessive_bools)]
// Four independent, individually meaningful observations. `clippy::pedantic`
// suggests an enum, but these are not mutually exclusive states: a kernel can
// grant `mlock` and refuse `MADV_WIPEONFORK`, and CB-6a wants each fact
// readable rather than collapsed into a summary. `tag()` is the summary.
#[allow(clippy::struct_excessive_bools)]
// Four independent, individually meaningful observations. `clippy::pedantic`
// suggests an enum, but these are not mutually exclusive states: a kernel can
// grant `mlock` and refuse `MADV_WIPEONFORK`, and CB-6a wants each fact
// readable rather than collapsed into a summary. `tag()` is the summary.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockedMemoryReport {
    /// `mlock(2)` succeeded: the pages will not reach swap or hibernation.
    pub swap_locked: bool,
    /// `madvise(MADV_DONTDUMP)` succeeded: the pages are excluded from a core
    /// dump.
    pub dump_excluded: bool,
    /// `madvise(MADV_WIPEONFORK)` succeeded: a `fork(2)` child sees zeroes.
    pub wipe_on_fork: bool,
    /// The region is erased before it returns to the allocator. Always true.
    pub zeroized_on_drop: bool,
}

impl LockedMemoryReport {
    /// The report for a target where no protection is available.
    ///
    /// Note `zeroized_on_drop` is still `true`: it is the one guarantee this
    /// module makes without kernel cooperation.
    pub const UNPROTECTED: Self = Self {
        swap_locked: false,
        dump_excluded: false,
        wipe_on_fork: false,
        zeroized_on_drop: true,
    };

    /// Whether every protection this module can request was granted.
    ///
    /// Deliberately **not** used as a gate anywhere: refusing to run because a
    /// kernel declined `MADV_WIPEONFORK` would brick an OpenWrt router to buy a
    /// property TM-14 already concedes. It is reported, not enforced.
    #[must_use]
    pub const fn fully_protected(self) -> bool {
        self.swap_locked && self.dump_excluded && self.wipe_on_fork
    }

    /// A stable, non-localised summary tag for `CoreBuildIdentity` and the
    /// diagnostic bundle.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match (self.swap_locked, self.dump_excluded, self.wipe_on_fork) {
            (true, true, true) => "locked+nodump+wipeonfork",
            (true, true, false) => "locked+nodump",
            (true, false, _) => "locked",
            (false, _, _) => "unprotected",
        }
    }
}

/// A heap region that is page-aligned, locked where the kernel allows it, and
/// erased before it is freed.
///
/// # Construction is by callback, deliberately
///
/// There is no `LockedBytes::from_vec`. A secret that arrives as a `Vec<u8>` has
/// already been in unlocked, swappable, dumpable memory, and moving it here
/// afterwards protects the copy while leaving the original wherever the
/// allocator put it. [`LockedBytes::new_with`] hands out a `&mut [u8]` inside
/// the locked region so the value is *produced* there.
///
/// [`LockedBytes::adopt`] exists for the one case where that is impossible — a
/// secret unsealed by the shell and handed across the platform seam — and is
/// named to make the compromise visible at the call site.
pub struct LockedBytes {
    ptr: *mut u8,
    len: usize,
    /// The allocation's true size: `len` rounded up to a page.
    alloc_len: usize,
    align: usize,
    report: LockedMemoryReport,
}

// SAFETY: `LockedBytes` owns a unique heap allocation and hands out references
// only through `&self` / `&mut self`, so the usual Rust aliasing rules apply.
// The raw pointer is an implementation detail of owning a page-aligned
// allocation; it is never shared, never copied out, and never freed twice.
unsafe impl Send for LockedBytes {}
// SAFETY: as above — `&LockedBytes` grants only `&[u8]`, which is `Sync`-safe
// for an immutable borrow of an owned allocation.
unsafe impl Sync for LockedBytes {}

impl LockedBytes {
    /// The largest region this type will allocate.
    ///
    /// A cap, not a budget: `mlock` draws on `RLIMIT_MEMLOCK`, which is a
    /// process-wide resource, and an unbounded locked allocation driven by a
    /// length an attacker controls is a denial-of-service against every *other*
    /// locked allocation in the process. 64 KiB is far above any key this crate
    /// holds (a `TK` is 32 bytes, an `SEK` is 32) and far below the smallest
    /// `RLIMIT_MEMLOCK` in the field.
    pub const MAX_BYTES: usize = 64 * 1024;

    /// Allocates a locked region of `len` bytes and lets `init` fill it.
    ///
    /// The region is zeroed before `init` sees it, so a short write leaves
    /// zeroes rather than allocator residue.
    ///
    /// # Errors
    ///
    /// [`crate::CryptoError::LockedAllocationUnavailable`] if `len` is zero or
    /// above [`Self::MAX_BYTES`]. A kernel that *declines* a protection is not
    /// an error — it is recorded in [`Self::report`], per CB-6a.
    pub fn new_with<F>(len: usize, init: F) -> crate::Result<Self>
    where
        F: FnOnce(&mut [u8]),
    {
        let mut this = Self::alloc(len)?;
        init(this.as_mut_slice());
        Ok(this)
    }

    /// Takes custody of a secret that already exists elsewhere in memory.
    ///
    /// **This is the compromised path and is named so.** The bytes have already
    /// been in unlocked memory — typically because the shell unsealed them
    /// across the platform seam (`twinvpn_platform::SecureItem`) — and this
    /// call protects the copy it makes, not the original. It zeroes `source`
    /// before returning, which is the most that can be done from here.
    ///
    /// # Errors
    ///
    /// As [`Self::new_with`].
    pub fn adopt(source: &mut [u8]) -> crate::Result<Self> {
        let this = Self::new_with(source.len(), |dst| dst.copy_from_slice(source))?;
        source.zeroize();
        Ok(this)
    }

    /// What the kernel granted for this region (CB-6a).
    #[must_use]
    pub const fn report(&self) -> LockedMemoryReport {
        self.report
    }

    /// The region's contents.
    ///
    /// Deliberately a named method rather than `Deref`: an implicit deref would
    /// let a secret flow into any `&[u8]` parameter without the call site
    /// showing it, and `grep -n 'expose()'` is how a reviewer audits this crate.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        // SAFETY: `ptr` is a live allocation of at least `len` bytes made by
        // `Self::alloc` and freed only in `Drop`, and `&self` borrows it, so no
        // `&mut` alias can exist for the lifetime of the returned slice.
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// The region's length, which is not secret.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the region is empty. Never true: `alloc` rejects a zero length.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as `expose`, and `&mut self` guarantees exclusivity.
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    fn alloc(len: usize) -> crate::Result<Self> {
        if len == 0 {
            return Err(crate::CryptoError::LockedAllocationUnavailable {
                mechanism: "zero-length locked allocation",
            });
        }
        if len > Self::MAX_BYTES {
            return Err(crate::CryptoError::LockedAllocationUnavailable {
                mechanism: "locked allocation above MAX_BYTES",
            });
        }
        let align = page_size();
        let alloc_len = len.div_ceil(align) * align;
        let layout = std::alloc::Layout::from_size_align(alloc_len, align).map_err(|_| {
            crate::CryptoError::LockedAllocationUnavailable {
                mechanism: "page-aligned layout",
            }
        })?;
        // SAFETY: `layout` has a non-zero size (`len >= 1` implies
        // `alloc_len >= align >= 1`) and a power-of-two alignment, which is
        // `alloc_zeroed`'s contract. A null return is the documented
        // out-of-memory signal and is handled below rather than dereferenced.
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(crate::CryptoError::LockedAllocationUnavailable {
                mechanism: "allocator returned null",
            });
        }
        let report = apply_protections(ptr, alloc_len);
        Ok(Self {
            ptr,
            len,
            alloc_len,
            align,
            report,
        })
    }
}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        // Erase first, unconditionally and before any protection is released,
        // so a failure in `munlock` cannot leave readable bytes behind.
        self.as_mut_slice().zeroize();
        release_protections(self.ptr, self.alloc_len);
        let Ok(layout) = std::alloc::Layout::from_size_align(self.alloc_len, self.align) else {
            // Unreachable: the same arguments built a layout in `alloc`. Leaking
            // is the only sound response to an impossible layout, and the region
            // has already been zeroed.
            return;
        };
        // SAFETY: `ptr` came from `alloc_zeroed` with exactly this layout in
        // `Self::alloc`, has not been freed (this is `Drop`, which runs once),
        // and is not aliased — `&mut self` is exclusive.
        unsafe { std::alloc::dealloc(self.ptr, layout) };
    }
}

impl core::fmt::Debug for LockedBytes {
    /// Never shows a byte. The length and the protection posture are not secret;
    /// the contents are the entire point of the type.
    ///
    /// `finish_non_exhaustive` rather than `finish`: the omitted fields are the
    /// pointer and the allocation's true size, and omitting them is the whole
    /// purpose of a hand-written `Debug` here.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LockedBytes")
            .field("len", &self.len)
            .field("protection", &self.report.tag())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// The POSIX half. See the module docs on why this is `cfg(unix)` and not a
// `target_os` branch.
// ---------------------------------------------------------------------------

/// `MADV_DONTDUMP`, Linux `<asm-generic/mman-common.h>`.
///
/// Spelled as a constant rather than taken from `libc` because the `libc`
/// crate exposes it only under a `target_os` gate, and CB-3 forbids this crate
/// an OS branch. A kernel that does not know the value returns `EINVAL`, which
/// `apply_protections` records as "not granted" — the same outcome as a `cfg`
/// would have produced, reached without the branch.
#[cfg(unix)]
const MADV_DONTDUMP: libc::c_int = 16;

/// `MADV_WIPEONFORK`, Linux ≥ 4.14. See [`MADV_DONTDUMP`] on the spelling.
#[cfg(unix)]
const MADV_WIPEONFORK: libc::c_int = 18;

#[cfg(unix)]
fn page_size() -> usize {
    // SAFETY: `sysconf` takes an `int` and returns a `long`; it has no
    // preconditions, touches no caller memory, and cannot fail in a way that
    // matters here — a negative return is handled below.
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if v > 0 {
        usize::try_from(v).unwrap_or(4096)
    } else {
        4096
    }
}

#[cfg(unix)]
fn apply_protections(ptr: *mut u8, len: usize) -> LockedMemoryReport {
    // SAFETY: `ptr` is a live, page-aligned allocation of exactly `len` bytes.
    // `mlock` and `madvise` read no caller memory and only change kernel-side
    // attributes of that range. Every return value is checked; none of these
    // calls can invalidate `ptr`.
    let swap_locked = unsafe { libc::mlock(ptr.cast(), len) } == 0;
    let dump_excluded = unsafe { libc::madvise(ptr.cast(), len, MADV_DONTDUMP) } == 0;
    let wipe_on_fork = unsafe { libc::madvise(ptr.cast(), len, MADV_WIPEONFORK) } == 0;
    LockedMemoryReport {
        swap_locked,
        dump_excluded,
        wipe_on_fork,
        zeroized_on_drop: true,
    }
}

#[cfg(unix)]
fn release_protections(ptr: *mut u8, len: usize) {
    // SAFETY: as `apply_protections`. A failure is ignored: the region has
    // already been zeroed, and `dealloc` must proceed regardless.
    unsafe { libc::munlock(ptr.cast(), len) };
}

#[cfg(not(unix))]
fn page_size() -> usize {
    4096
}

#[cfg(not(unix))]
fn apply_protections(_ptr: *mut u8, _len: usize) -> LockedMemoryReport {
    // No POSIX memory-advice API. The fact is *reported*, per CB-6a, rather
    // than the allocation being refused: refusing would make the core
    // unbuildable on a target the build matrix includes.
    LockedMemoryReport::UNPROTECTED
}

#[cfg(not(unix))]
fn release_protections(_ptr: *mut u8, _len: usize) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_locked_region_holds_what_was_written_into_it() {
        let b = LockedBytes::new_with(32, |dst| dst.fill(0xab)).expect("allocate");
        assert_eq!(b.len(), 32);
        assert_eq!(b.expose(), &[0xab; 32]);
    }

    #[test]
    fn a_locked_region_starts_zeroed_so_a_short_write_leaves_no_residue() {
        let b =
            LockedBytes::new_with(64, |dst| dst[..4].copy_from_slice(b"abcd")).expect("allocate");
        assert_eq!(&b.expose()[..4], b"abcd");
        assert!(b.expose()[4..].iter().all(|x| *x == 0));
    }

    #[test]
    fn adopt_erases_the_source_it_was_given() {
        let mut src = [7u8; 32];
        let b = LockedBytes::adopt(&mut src).expect("adopt");
        assert_eq!(b.expose(), &[7u8; 32]);
        assert_eq!(src, [0u8; 32], "adopt must erase the unlocked original");
    }

    #[test]
    fn a_zero_length_or_oversized_region_is_refused() {
        assert!(LockedBytes::new_with(0, |_| {}).is_err());
        assert!(LockedBytes::new_with(LockedBytes::MAX_BYTES + 1, |_| {}).is_err());
        // The cap itself is allowed, so the boundary is inclusive.
        assert!(LockedBytes::new_with(LockedBytes::MAX_BYTES, |_| {}).is_ok());
    }

    #[test]
    fn debug_never_renders_a_byte_of_the_region() {
        let b = LockedBytes::new_with(32, |dst| dst.fill(0xde)).expect("allocate");
        let rendered = format!("{b:?}");
        assert!(
            !rendered.contains("de"),
            "Debug leaked contents: {rendered}"
        );
        assert!(rendered.contains("len: 32"));
    }

    #[test]
    fn the_report_is_an_observation_and_the_tag_is_stable() {
        let b = LockedBytes::new_with(32, |_| {}).expect("allocate");
        let r = b.report();
        // Always true, on every target, with or without kernel cooperation.
        assert!(r.zeroized_on_drop);
        // The rest is whatever this kernel granted. Asserting `swap_locked` here
        // would make the test fail on a host with RLIMIT_MEMLOCK = 0, which is a
        // legitimate deployment and is exactly the fact the report exists to
        // carry. So the assertion is on the *shape*, not on the grant.
        assert!(matches!(
            r.tag(),
            "locked+nodump+wipeonfork" | "locked+nodump" | "locked" | "unprotected"
        ));
        assert_eq!(
            r.fully_protected(),
            r.swap_locked && r.dump_excluded && r.wipe_on_fork
        );
    }

    #[test]
    fn the_region_is_page_aligned_so_the_advice_covers_no_neighbour() {
        let b = LockedBytes::new_with(32, |_| {}).expect("allocate");
        let addr = b.expose().as_ptr() as usize;
        assert_eq!(addr % page_size(), 0, "region must own whole pages");
    }
}
