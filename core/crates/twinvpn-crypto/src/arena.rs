//! The `SecretArena` — ADR-0022 LC-30(1)'s one arena, and the `Secret` handle
//! whose only constructor allocates from it.
//!
//! **Authority:** ADR-0022 §11.7 rule LC-30(1) and §11.13 interface I-03(a);
//! `docs/vision.md` R-45; `docs/threat-model.md` §9; ADR-0018 DP-4 (this crate
//! is the unsafe allowlist member), CB-3, CB-6a.
//!
//! # The rule, quoted, because every decision here is downstream of it
//!
//! LC-30(1): *"All `SECRET`-classified material — static and ephemeral key
//! material, handshake state, `EpochSeed`s, `TwinNetPSK`, packet plaintext
//! buffers — is allocated exclusively from a `SecretArena`: a dedicated
//! allocator with guard pages, `mlock`/`VirtualLock`, zero-on-free, and the
//! platform's dump exclusion applied to the whole arena at creation
//! (`madvise(MADV_DONTDUMP)` on Linux/Android; …). The core's type system
//! enforces the 'exclusively' — a `Secret<T>` wrapper whose only constructor
//! allocates from the arena — and a CI test fails the build on any direct
//! allocation of a key-bearing type outside it."*
//!
//! R-45 names the same object as part of the reliability requirement: *"the
//! `SecretArena` with platform dump exclusion and a module-range crash-handler
//! filter"*.
//!
//! # What is here, and what is honestly not
//!
//! | LC-30(1) clause | State |
//! |---|---|
//! | one arena | **done** — [`SecretArena`] is a single mapping, carved into slots |
//! | guard pages | **done** on POSIX — a `PROT_NONE` page either side, so a linear overrun faults instead of walking into a neighbour |
//! | `mlock` / dump exclusion **applied to the whole arena at creation** | **done** on POSIX, and *reported* rather than assumed (CB-6a), exactly as [`crate::locked`] does |
//! | zero-on-free | **done** — [`Secret::drop`] erases the slot before returning it to the free list, so a reused slot never carries residue |
//! | a `Secret<T>` whose only constructor allocates from the arena | **partial** — [`Secret`] holds bytes, not an arbitrary `T`, and its only constructor is [`SecretArena::allocate`] |
//! | *"allocated **exclusively**"* | **NOT done.** Nothing in this workspace allocates from the arena yet |
//!
//! The last row is the one that matters, and it is stated here rather than left
//! to be discovered. The key-bearing types this rule is about — the Noise
//! handshake state, the transport keys, `TK`, the `SEK` — are constructed in
//! `noise.rs`, `established.rs` and `aead.rs`, and moving them is a separate
//! change with its own review. **Until that lands, this arena is the mechanism
//! and not yet the guarantee**, and ADR-0022 §11.12 oracle 6 — "the canary is
//! absent from every collected artifact" — cannot be run against it as evidence
//! about a real transport key. [`SecretArena::install_canary`] exists so the
//! oracle has the 32-byte value its preconditions call for the moment the rig
//! that can collect a crash artifact does.
//!
//! # Why this is a second allocator beside [`crate::locked::LockedBytes`]
//!
//! It is not a second *strategy*: the protections are the same three POSIX calls
//! and the same [`crate::locked::LockedMemoryReport`], so there is one answer to
//! "what did the kernel grant". It is a different *shape*, and it has to be:
//!
//! - `LockedBytes` allocates through [`std::alloc`], and you cannot `mprotect`
//!   the pages either side of an allocation you do not own — they belong to the
//!   global allocator and may hold something else. Guard pages therefore require
//!   the arena to map its own region, which is what `mmap` is for.
//! - LC-30(1) says dump exclusion is applied **to the whole arena at creation**,
//!   once. `LockedBytes` applies it per region, which is the right shape for two
//!   long-lived keys and the wrong one for "every secret in the process".
//!
//! # Why `cfg(unix)` and not a `target_os` branch
//!
//! The same reasoning as [`crate::locked`], and the same shape: this module
//! branches on the POSIX *family*, never on an OS, and reports what the kernel
//! actually granted rather than claiming what a `cfg` implies.

use core::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroize;

use crate::locked::LockedMemoryReport;

/// The width of one slot.
///
/// Every `SECRET` value in this workspace is small: a `TK` is 32 bytes, an `SEK`
/// is 32, an `EpochSeed` and a `TwinNetPSK` are 32. 256 leaves room for the
/// handshake state LC-30(1) also names without making the arena's own footprint
/// a consideration on the 128 MB router of ADR-0023.
///
/// Fixed-size slots rather than a bump pointer, deliberately: a bump allocator
/// cannot reuse the space a rekey frees, and ADR-0001's rekey schedule means
/// that space is freed on a timer for the life of the process.
pub const SLOT_BYTES: usize = 256;

/// How many slots one arena holds.
///
/// A cap, not a budget. `mlock` draws on the process-wide `RLIMIT_MEMLOCK`, and
/// an arena sized past it would fail to lock and silently become ordinary
/// swappable memory. 64 slots is 16 KiB, comfortably inside the 64 KiB floor
/// [`crate::locked::LockedBytes::MAX_BYTES`] documents for the field.
pub const SLOTS: usize = 64;

/// The canary's width, from ADR-0022 §11.12's P21 preconditions: "a 32-byte
/// **canary key** installed in the `SecretArena` in place of a transport key".
pub const CANARY_BYTES: usize = 32;

/// The arena: one mapping, guard-paged, locked, dump-excluded, slot-allocated.
///
/// Not `Clone` and not copyable. One process holds one, which is what the word
/// "arena" in LC-30(1) means.
pub struct SecretArena {
    /// The whole mapping, guard pages included.
    base: *mut u8,
    /// The whole mapping's length.
    mapping_len: usize,
    /// The usable span, one page in from `base`.
    usable: *mut u8,
    /// The usable span's length. Stored rather than recomputed at drop, so the
    /// erase and the unlock cannot disagree with the map about how much there
    /// is.
    usable_span: usize,
    /// Per-slot occupancy. `true` is taken.
    taken: [AtomicBool; SLOTS],
    /// What the kernel granted, measured (CB-6a).
    report: LockedMemoryReport,
    /// Whether guard pages were actually established.
    guarded: bool,
}

// SAFETY: the arena owns a unique mapping and hands out slots through
// `&self`, arbitrating with per-slot atomics, so two `Secret`s can never name
// the same slot. The raw pointers are an implementation detail of owning a
// mapping; they are never copied out and never freed twice.
unsafe impl Send for SecretArena {}
// SAFETY: as above. `&SecretArena` grants only `allocate`, which claims a slot
// atomically, and the report, which is `Copy` and not secret.
unsafe impl Sync for SecretArena {}

impl SecretArena {
    /// Maps and protects a new arena.
    ///
    /// Dump exclusion, `mlock` and `MADV_WIPEONFORK` are applied to the **whole
    /// usable span at creation**, which is LC-30(1)'s wording. A kernel that
    /// declines one is not an error — it is recorded in [`Self::report`], per
    /// CB-6a, for the same reason [`crate::locked`] records it: refusing to run
    /// because a kernel declined `MADV_WIPEONFORK` would brick an OpenWrt router
    /// to buy a property `docs/threat-model.md` TM-14 already concedes.
    ///
    /// # Errors
    ///
    /// [`crate::CryptoError::LockedAllocationUnavailable`] if the mapping itself
    /// could not be made.
    pub fn new() -> crate::Result<Self> {
        let page = page_size();
        let usable_len = SLOT_BYTES * SLOTS;
        // One guard page either side of a whole number of usable pages.
        let usable_span = usable_len.div_ceil(page) * page;
        let mapping_len = usable_span + 2 * page;

        let base = map_anonymous(mapping_len)?;
        // SAFETY: `base` is a live mapping of `mapping_len >= 3 * page` bytes, so
        // `base + page` is in bounds and page-aligned.
        let usable = unsafe { base.add(page) };

        let guarded = guard(base, page)
            && guard(
                // SAFETY: in bounds by the same arithmetic; this is the trailing
                // guard page, which starts one page past the usable span.
                unsafe { usable.add(usable_span) },
                page,
            );
        let report = crate::locked::apply_protections(usable, usable_span);

        Ok(Self {
            base,
            mapping_len,
            usable,
            usable_span,
            taken: [const { AtomicBool::new(false) }; SLOTS],
            report,
            guarded,
        })
    }

    /// What the kernel granted for the whole arena (CB-6a).
    #[must_use]
    pub const fn report(&self) -> LockedMemoryReport {
        self.report
    }

    /// Whether the guard pages were established.
    ///
    /// Reported rather than enforced, for the reason [`Self::new`] gives. A
    /// target with no `mprotect` still gets locking, dump exclusion and
    /// zero-on-free; it does not get the overrun trap, and says so.
    #[must_use]
    pub const fn is_guarded(&self) -> bool {
        self.guarded
    }

    /// How many slots are free.
    #[must_use]
    pub fn free_slots(&self) -> usize {
        self.taken
            .iter()
            .filter(|t| !t.load(Ordering::Acquire))
            .count()
    }

    /// Allocates a slot and lets `init` fill the first `len` bytes.
    ///
    /// **This is the only constructor of [`Secret`]**, which is how LC-30(1)'s
    /// "exclusively" is expressed in the type system: [`Secret`] has no public
    /// fields, no `From`, and no other associated function that produces one.
    ///
    /// The slot is zeroed before `init` sees it, so a short write leaves zeroes
    /// rather than a previous secret's residue.
    ///
    /// # Errors
    ///
    /// [`crate::CryptoError::LockedAllocationUnavailable`] if `len` is zero, if
    /// it exceeds [`SLOT_BYTES`], or if every slot is taken.
    pub fn allocate<F>(&self, len: usize, init: F) -> crate::Result<Secret<'_>>
    where
        F: FnOnce(&mut [u8]),
    {
        if len == 0 || len > SLOT_BYTES {
            return Err(crate::CryptoError::LockedAllocationUnavailable {
                mechanism: "secret larger than one arena slot",
            });
        }
        let index = self
            .claim_slot()
            .ok_or(crate::CryptoError::LockedAllocationUnavailable {
                mechanism: "arena exhausted",
            })?;

        let mut secret = Secret {
            arena: self,
            index,
            len,
        };
        secret.as_mut_slice().zeroize();
        init(secret.as_mut_slice());
        Ok(secret)
    }

    /// Installs ADR-0022 §11.12's 32-byte canary key **in place of a transport
    /// key**, and returns it.
    ///
    /// P21's preconditions (V3) call for exactly this: "a 32-byte **canary key**
    /// installed in the `SecretArena` in place of a transport key". Oracle 6
    /// then "greps every byte of every crash artifact for the canary value; one
    /// occurrence is a failure (I4)".
    ///
    /// The value is the caller's, not this module's: the rig picks a value it
    /// can search for, and a constant baked in here would be a value an
    /// unrelated build could also contain.
    ///
    /// # Errors
    ///
    /// As [`Self::allocate`].
    pub fn install_canary(&self, value: &[u8; CANARY_BYTES]) -> crate::Result<Secret<'_>> {
        self.allocate(CANARY_BYTES, |dst| dst.copy_from_slice(value))
    }

    /// Claims the lowest free slot, or `None` when the arena is full.
    fn claim_slot(&self) -> Option<usize> {
        self.taken.iter().position(|t| {
            t.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        })
    }

    /// The slot's start address.
    fn slot_ptr(&self, index: usize) -> *mut u8 {
        debug_assert!(index < SLOTS);
        // SAFETY: `index < SLOTS`, so the offset is within the usable span this
        // arena mapped and still owns.
        unsafe { self.usable.add(index * SLOT_BYTES) }
    }
}

impl Drop for SecretArena {
    fn drop(&mut self) {
        // Erase the whole usable span before any protection is released, so a
        // failure in `munlock` or `munmap` cannot leave readable bytes behind.
        // SAFETY: the usable span is live, owned, and no `Secret` can outlive
        // the arena — the lifetime on `Secret<'_>` is what guarantees it.
        unsafe { core::slice::from_raw_parts_mut(self.usable, self.usable_span) }.zeroize();
        crate::locked::release_protections(self.usable, self.usable_span);
        unmap(self.base, self.mapping_len);
    }
}

impl core::fmt::Debug for SecretArena {
    /// Never shows a byte, for the reason [`crate::locked::LockedBytes`]'s
    /// `Debug` does not: the contents are the entire point of the type.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecretArena")
            .field("slots", &SLOTS)
            .field("free", &self.free_slots())
            .field("guarded", &self.guarded)
            .field("protection", &self.report.tag())
            .finish_non_exhaustive()
    }
}

/// One `SECRET`-classified value, living in the arena.
///
/// I-03(a) asks for "a `Secret<T>` type whose only allocator is the
/// `SecretArena`". This is that type for **byte-shaped** secrets, which is what
/// every `SECRET` value in this workspace currently is — a `TK`, an `SEK`, an
/// `EpochSeed` and a `TwinNetPSK` are each 32 bytes. A generic `Secret<T>` with
/// in-arena placement of an arbitrary `T` is a larger change and is not claimed
/// here.
///
/// The borrow of the arena is load-bearing: it is what makes it impossible for a
/// secret to outlive the mapping it lives in, without a reference count and
/// without a runtime check.
pub struct Secret<'a> {
    arena: &'a SecretArena,
    index: usize,
    len: usize,
}

impl Secret<'_> {
    /// The secret's bytes.
    ///
    /// A named method rather than `Deref`, for the reason
    /// [`crate::locked::LockedBytes::expose`] gives: an implicit deref would let
    /// a secret flow into any `&[u8]` parameter without the call site showing
    /// it, and `grep -n 'expose()'` is how a reviewer audits this crate.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        // SAFETY: the slot is live for the arena's lifetime, which outlives
        // `self`; `&self` borrows it, so no `&mut` alias can exist.
        unsafe { core::slice::from_raw_parts(self.arena.slot_ptr(self.index), self.len) }
    }

    /// The secret's length, which is not secret.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether it is empty. Never true: `allocate` rejects a zero length.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as `expose`, and `&mut self` guarantees exclusivity. The slot
        // is this `Secret`'s alone until it drops — `claim_slot` hands each
        // index out once.
        unsafe { core::slice::from_raw_parts_mut(self.arena.slot_ptr(self.index), self.len) }
    }
}

impl Drop for Secret<'_> {
    /// LC-30(1)'s zero-on-free.
    ///
    /// The **whole slot** is erased, not the `len` bytes that were written: a
    /// shorter secret reusing a longer one's slot would otherwise inherit its
    /// tail, which is the residue this clause exists to prevent.
    fn drop(&mut self) {
        // SAFETY: the slot is live and exclusively this `Secret`'s.
        unsafe { core::slice::from_raw_parts_mut(self.arena.slot_ptr(self.index), SLOT_BYTES) }
            .zeroize();
        self.arena.taken[self.index].store(false, Ordering::Release);
    }
}

impl core::fmt::Debug for Secret<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Secret")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// The POSIX half. See the module docs on why this is `cfg(unix)`.
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn page_size() -> usize {
    // SAFETY: `sysconf` takes an `int` and returns a `long`; it has no
    // preconditions and touches no caller memory. A non-positive return is
    // handled.
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if v > 0 {
        usize::try_from(v).unwrap_or(4096)
    } else {
        4096
    }
}

#[cfg(unix)]
fn map_anonymous(len: usize) -> crate::Result<*mut u8> {
    // SAFETY: an anonymous private mapping with a null hint has no
    // preconditions and touches no caller memory. The return is checked against
    // MAP_FAILED before it is used.
    let p = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(crate::CryptoError::LockedAllocationUnavailable {
            mechanism: "arena mmap",
        });
    }
    Ok(p.cast::<u8>())
}

#[cfg(unix)]
fn guard(ptr: *mut u8, len: usize) -> bool {
    // SAFETY: `ptr` is page-aligned and inside a mapping this arena owns.
    // `mprotect` changes only that range's protection and touches no caller
    // memory. The return is checked.
    unsafe { libc::mprotect(ptr.cast(), len, libc::PROT_NONE) == 0 }
}

#[cfg(unix)]
fn unmap(ptr: *mut u8, len: usize) {
    // SAFETY: `ptr`/`len` are exactly what `map_anonymous` returned, and this
    // runs once, from `Drop`.
    unsafe { libc::munmap(ptr.cast(), len) };
}

#[cfg(not(unix))]
fn page_size() -> usize {
    4096
}

#[cfg(not(unix))]
fn map_anonymous(len: usize) -> crate::Result<*mut u8> {
    // No POSIX mapping API. The arena still gets zero-on-free and whatever
    // `apply_protections_for_arena` reports; it does not get guard pages, and
    // `is_guarded` says so rather than the allocation being refused — refusing
    // would make the core unbuildable on a target the build matrix includes.
    let layout = std::alloc::Layout::from_size_align(len, 4096).map_err(|_| {
        crate::CryptoError::LockedAllocationUnavailable {
            mechanism: "arena layout",
        }
    })?;
    // SAFETY: `layout` has a non-zero size and a power-of-two alignment. A null
    // return is the documented out-of-memory signal and is handled below.
    let p = unsafe { std::alloc::alloc_zeroed(layout) };
    if p.is_null() {
        return Err(crate::CryptoError::LockedAllocationUnavailable {
            mechanism: "arena allocation",
        });
    }
    Ok(p)
}

#[cfg(not(unix))]
fn guard(_ptr: *mut u8, _len: usize) -> bool {
    false
}

#[cfg(not(unix))]
fn unmap(ptr: *mut u8, len: usize) {
    let Ok(layout) = std::alloc::Layout::from_size_align(len, 4096) else {
        return;
    };
    // SAFETY: `ptr` came from `alloc_zeroed` with exactly this layout, and this
    // runs once, from `Drop`.
    unsafe { std::alloc::dealloc(ptr, layout) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_arena_applies_its_protections_to_the_whole_span_at_creation() {
        let a = SecretArena::new().expect("arena");
        let r = a.report();
        // Always true, on every target, with or without kernel cooperation.
        assert!(r.zeroized_on_drop);
        // The rest is whatever this kernel granted. Asserting `swap_locked` here
        // would fail on a host with RLIMIT_MEMLOCK = 0, which is a legitimate
        // deployment and is exactly the fact CB-6a wants carried rather than
        // assumed. So the assertion is on the SHAPE.
        assert!(matches!(
            r.tag(),
            "locked+nodump+wipeonfork" | "locked+nodump" | "locked" | "unprotected"
        ));

        // Guard pages are NOT in that category. `mprotect` on a range of the
        // arena's own anonymous mapping has no resource limit behind it and no
        // reason to be declined, so on POSIX this is an assertion rather than an
        // observation — and it has to be, or the clause could be silently inert
        // on every host and nothing would say so.
        #[cfg(unix)]
        assert!(
            a.is_guarded(),
            "LC-30(1) asks for guard pages and mprotect declined them"
        );
    }

    #[test]
    fn a_secret_holds_what_was_written_and_starts_from_zeroes() {
        let a = SecretArena::new().expect("arena");
        let s = a.allocate(32, |dst| dst.fill(0xab)).expect("allocate");
        assert_eq!(s.expose(), &[0xab; 32]);

        let short = a
            .allocate(64, |dst| dst[..4].copy_from_slice(b"abcd"))
            .expect("allocate");
        assert_eq!(&short.expose()[..4], b"abcd");
        assert!(
            short.expose()[4..].iter().all(|x| *x == 0),
            "a short write must leave zeroes, not residue"
        );
    }

    /// LC-30(1)'s zero-on-free, observed rather than asserted about itself.
    ///
    /// The freed slot is claimed again — `claim_slot` hands out the lowest free
    /// index, so the second allocation lands on the first one's bytes — and the
    /// tail beyond the new secret's length must be zeroes.
    #[test]
    fn a_freed_slot_carries_no_residue_into_the_next_secret() {
        let a = SecretArena::new().expect("arena");
        {
            let _first = a.allocate(SLOT_BYTES, |dst| dst.fill(0x5a)).expect("first");
        }
        assert_eq!(a.free_slots(), SLOTS, "the slot returned to the free list");

        let second = a
            .allocate(SLOT_BYTES, |dst| dst[..2].fill(0x01))
            .expect("second");
        assert_eq!(&second.expose()[..2], &[0x01, 0x01]);
        assert!(
            second.expose()[2..].iter().all(|x| *x == 0),
            "the previous secret's bytes survived the free"
        );
    }

    #[test]
    fn the_arena_hands_each_slot_to_one_secret_at_a_time() {
        let a = SecretArena::new().expect("arena");
        let mut held = Vec::new();
        for i in 0..SLOTS {
            held.push(
                a.allocate(8, |dst| dst.fill(u8::try_from(i).unwrap_or(0)))
                    .expect("allocate"),
            );
        }
        assert_eq!(a.free_slots(), 0);
        // Exhaustion is an error, never a silent overwrite of a live secret.
        assert!(a.allocate(8, |_| {}).is_err());

        // Every live secret still reads back its own value, so no two shared a
        // slot.
        for (i, s) in held.iter().enumerate() {
            assert_eq!(s.expose(), &[u8::try_from(i).unwrap_or(0); 8]);
        }
    }

    #[test]
    fn a_secret_larger_than_a_slot_is_refused_rather_than_truncated() {
        let a = SecretArena::new().expect("arena");
        assert!(a.allocate(0, |_| {}).is_err());
        assert!(a.allocate(SLOT_BYTES + 1, |_| {}).is_err());
        assert!(a.allocate(SLOT_BYTES, |_| {}).is_ok());
    }

    /// ADR-0022 §11.12's precondition: "a 32-byte **canary key** installed in
    /// the `SecretArena` in place of a transport key".
    #[test]
    fn the_p21_canary_is_thirty_two_bytes_and_lives_in_the_arena() {
        let a = SecretArena::new().expect("arena");
        let value = [0xc7u8; CANARY_BYTES];
        let canary = a.install_canary(&value).expect("canary");
        assert_eq!(canary.len(), CANARY_BYTES);
        assert_eq!(canary.expose(), &value);
        // It is inside the arena's dump-excluded span, which is the property
        // oracle 6 rests on. What the kernel granted is reported, not assumed.
        assert_eq!(a.free_slots(), SLOTS - 1);
    }

    #[test]
    fn debug_never_renders_a_byte_of_a_secret_or_of_the_arena() {
        let a = SecretArena::new().expect("arena");
        let s = a.allocate(32, |dst| dst.fill(0xde)).expect("allocate");
        let rendered = format!("{s:?}");
        assert!(
            !rendered.contains("de"),
            "Debug leaked contents: {rendered}"
        );
        assert!(rendered.contains("len: 32"));
        let arena = format!("{a:?}");
        assert!(arena.contains("slots"));
        assert!(!arena.contains("0xde"));
    }

    #[test]
    fn the_usable_span_is_page_aligned_so_the_guard_pages_cover_no_secret() {
        let a = SecretArena::new().expect("arena");
        let s = a.allocate(8, |_| {}).expect("allocate");
        let addr = s.expose().as_ptr() as usize;
        assert_eq!(
            addr % page_size(),
            0,
            "the first slot starts on a page boundary"
        );
    }
}
