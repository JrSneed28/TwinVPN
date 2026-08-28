//! The raw ABI primitives: the slice, the buffer, the out-parameters, and the
//! panic containment every entry point is wrapped in.
//!
//! **Authority:** ADR-0018 F-2 (no `malloc`/`free` pairing crosses the
//! boundary), F-3 (length-delimited, never NUL-reliant), F-7 (`catch_unwind`
//! containment at the boundary), DP-4 (`unsafe` is permitted here and carries a
//! `// SAFETY:` comment naming its invariant).
//!
//! # Three pointer rules, enforced rather than documented
//!
//! 1. **A `(NULL, 0)` slice is empty, not a fault.** Swift's
//!    `withUnsafeBufferPointer` yields a nil base address for an empty array, so
//!    that shape arrives on every call that passes an empty parameter — and
//!    `slice::from_raw_parts` on a null base is undefined behaviour even for a
//!    zero length. [`slice_of`] is the **only** place this crate turns a
//!    `TvbSlice` into a `&[u8]`, so the check exists once and cannot be skipped.
//! 2. **A NULL handle is a typed error, never a dereference.** [`ext_of`]
//!    returns an `Option`, so the null case has to be handled to compile.
//! 3. **A NULL out-parameter is tolerated.** [`write_out`] drops the value
//!    rather than writing through a null pointer; a caller that does not want a
//!    result is not a caller that deserves a crash.

use std::panic::{catch_unwind, AssertUnwindSafe};

/// `tvb_slice` — a borrowed, length-delimited byte range.
///
/// `#[repr(C)]` and field order fixed: this struct is passed **by value** across
/// the boundary, so its layout is the ABI.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TvbSlice {
    /// The bytes. May be null **only** when `len` is zero.
    pub ptr: *const u8,
    /// The length.
    pub len: usize,
}

impl TvbSlice {
    /// The empty slice, in the shape Swift produces for an empty array.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            ptr: core::ptr::null(),
            len: 0,
        }
    }

    /// A slice borrowing `bytes`, valid for as long as `bytes` is.
    #[must_use]
    pub const fn borrowing(bytes: &[u8]) -> Self {
        Self {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        }
    }
}

/// Turns a `TvbSlice` into a Rust slice, tolerating the empty shape.
///
/// Returns `None` for a **malformed** slice — a null pointer with a non-zero
/// length — which is a caller defect and becomes a typed error rather than a
/// dereference.
///
/// # Safety
///
/// If `slice.len` is non-zero, `slice.ptr` must point to `slice.len`
/// initialised bytes that stay valid and unaliased-for-write for the lifetime
/// `'a`. The ABI's own contract — "valid only for the duration of the call it is
/// passed to" — is what makes `'a` the call's body and nothing longer.
#[must_use]
pub unsafe fn slice_of<'a>(slice: TvbSlice) -> Option<&'a [u8]> {
    if slice.len == 0 {
        // The `(NULL, 0)` case, and the `(valid, 0)` case, are the same empty
        // slice. Neither may reach `from_raw_parts`: a null base is UB there
        // even at length zero.
        return Some(&[]);
    }
    if slice.ptr.is_null() {
        return None;
    }
    // SAFETY: `len` is non-zero and `ptr` is non-null, and by this function's
    // contract the caller guarantees `len` initialised bytes live at `ptr` for
    // `'a`. The result is a shared borrow, so no write aliasing is created.
    Some(unsafe { core::slice::from_raw_parts(slice.ptr, slice.len) })
}

/// The same, for the raw `(ptr, len)` pair `tvb_ext_inject_inbound` takes.
///
/// # Safety
///
/// As [`slice_of`].
#[must_use]
pub unsafe fn slice_of_raw<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    // SAFETY: delegated verbatim; the caller's obligation is unchanged.
    unsafe { slice_of(TvbSlice { ptr, len }) }
}

/// `tvb_buf` — a bridge-owned heap buffer.
///
/// The type is opaque to C. The only way to read it is `tvb_buf_bytes` and the
/// only way to release it is `tvb_buf_free`, which is F-2 as a shape rather than
/// as a rule to remember.
pub struct TvbBuf {
    bytes: Vec<u8>,
}

impl TvbBuf {
    /// Allocates a buffer and hands the caller a raw pointer it now owns.
    #[must_use]
    pub fn into_raw(bytes: Vec<u8>) -> *mut TvbBuf {
        Box::into_raw(Box::new(TvbBuf { bytes }))
    }

    /// The bytes, borrowed.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reclaims a buffer previously produced by [`TvbBuf::into_raw`].
    ///
    /// # Safety
    ///
    /// `ptr` is either null or a pointer previously returned by
    /// [`TvbBuf::into_raw`] and **not yet released**. Releasing twice, or
    /// releasing a pointer this crate did not produce, is undefined behaviour —
    /// which is exactly why F-2 forbids a `malloc`/`free` pairing from crossing
    /// the boundary in either direction.
    pub unsafe fn release(ptr: *mut TvbBuf) {
        if ptr.is_null() {
            return;
        }
        // SAFETY: non-null, and by this function's contract it came from
        // `Box::into_raw` in `into_raw` and has not been released. Reboxing
        // reclaims exactly that allocation and nothing else.
        drop(unsafe { Box::from_raw(ptr) });
    }
}

/// Writes an out-parameter, tolerating a null pointer.
///
/// # Safety
///
/// `out` is either null or a valid, aligned, writable `*mut T` the caller owns
/// for the duration of the call.
pub unsafe fn write_out<T>(out: *mut T, value: T) {
    if out.is_null() {
        // A caller that does not want the value gets no crash. `value` drops
        // here, which for a `*mut TvbBuf` would LEAK — so no call site passes a
        // raw buffer pointer through this without having checked `out` first.
        drop(value);
        return;
    }
    // SAFETY: non-null by the branch above, and valid and aligned by this
    // function's contract. `write` does not read or drop the old value, which is
    // correct for an out-parameter whose prior contents are indeterminate.
    unsafe { out.write(value) };
}

/// Borrows an opaque handle, tolerating a null pointer.
///
/// # Safety
///
/// `ptr` is either null or a pointer previously returned by the matching
/// `into_raw`, still live, and not aliased mutably. The returned borrow must not
/// outlive the call.
#[must_use]
pub unsafe fn ext_of<'a, T>(ptr: *const T) -> Option<&'a T> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: non-null by the branch above, and live and immutably aliasable by
    // this function's contract. `TvbExt` is `Send + Sync`, so a shared borrow
    // reachable from several threads at once is sound.
    Some(unsafe { &*ptr })
}

/// Runs `body`, containing any panic.
///
/// **F-7.** A panic unwinding across `extern "C"` into Swift is undefined
/// behaviour, and `panic = "unwind"` is in every shipped profile precisely so
/// this can catch it. A caught panic is **never swallowed**: the caller turns
/// `None` into `INTERNAL.CORE_PANIC` and logs it.
///
/// # Why `AssertUnwindSafe`
///
/// The state this crate observes after a panic is a `Mutex`-guarded queue, a
/// channel and a `PowerJournal`. A panic while one of those locks is held
/// **poisons** it, and every lock acquisition in this crate treats a poisoned
/// lock as a typed error rather than unwrapping — so the post-panic state is
/// observable without being trusted, which is what unwind safety actually asks
/// for. Asserting it here rather than requiring `UnwindSafe` on the closure is
/// what lets that judgement live in one place with its reasoning.
pub fn contained<T>(body: impl FnOnce() -> T) -> Option<T> {
    catch_unwind(AssertUnwindSafe(body)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_slice_with_a_null_base_is_empty_and_never_a_dereference() {
        // The shape Swift's `withUnsafeBufferPointer` produces for `[]`.
        // `from_raw_parts` on a null base is UB even at length zero, which is
        // why this case is handled before it and not inside it.
        // SAFETY: the slice is `(null, 0)`, which this function documents as
        // well-formed and does not dereference.
        let empty = unsafe { slice_of(TvbSlice::empty()) };
        assert_eq!(empty, Some(&[][..]));
    }

    #[test]
    fn a_null_base_with_a_non_zero_length_is_a_typed_error() {
        let malformed = TvbSlice {
            ptr: core::ptr::null(),
            len: 7,
        };
        // SAFETY: the pointer is null and the function checks that before any
        // dereference; `None` is the documented answer.
        assert!(unsafe { slice_of(malformed) }.is_none());
    }

    #[test]
    fn a_slice_borrows_exactly_the_bytes_it_was_given() {
        let bytes = b"twinvpn".to_vec();
        let slice = TvbSlice::borrowing(&bytes);
        // SAFETY: `bytes` outlives the borrow, and `slice` was built from it.
        let seen = unsafe { slice_of(slice) }.expect("well formed");
        assert_eq!(seen, b"twinvpn");
        // A zero-length slice over a VALID pointer is also empty.
        let zero = TvbSlice {
            ptr: bytes.as_ptr(),
            len: 0,
        };
        // SAFETY: length zero, so nothing is read.
        assert_eq!(unsafe { slice_of(zero) }, Some(&[][..]));
    }

    #[test]
    fn a_buffer_round_trips_and_is_freed_exactly_once() {
        let raw = TvbBuf::into_raw(b"envelope".to_vec());
        assert!(!raw.is_null());
        // SAFETY: `raw` came from `into_raw` and has not been released.
        let borrowed = unsafe { ext_of(raw.cast_const()) }.expect("non-null");
        assert_eq!(borrowed.bytes(), b"envelope");
        // SAFETY: `raw` came from `into_raw` and this is its only release.
        unsafe { TvbBuf::release(raw) };
        // And a null release is a no-op rather than a crash.
        // SAFETY: null is explicitly tolerated.
        unsafe { TvbBuf::release(core::ptr::null_mut()) };
    }

    #[test]
    fn an_empty_buffer_is_still_a_buffer() {
        // `tvb_buf_bytes` on it yields `(valid, 0)`, which the caller reads as
        // an empty result rather than as an absent one.
        let raw = TvbBuf::into_raw(Vec::new());
        // SAFETY: `raw` came from `into_raw`.
        assert!(unsafe { ext_of(raw.cast_const()) }
            .expect("non-null")
            .bytes()
            .is_empty());
        // SAFETY: only release.
        unsafe { TvbBuf::release(raw) };
    }

    #[test]
    fn a_null_handle_is_none_rather_than_a_dereference() {
        // SAFETY: null is explicitly tolerated and not dereferenced.
        assert!(unsafe { ext_of::<TvbBuf>(core::ptr::null()) }.is_none());
    }

    #[test]
    fn a_null_out_parameter_is_tolerated() {
        let mut slot: i32 = 0;
        // SAFETY: `slot` is a live, aligned, writable `i32`.
        unsafe { write_out(&raw mut slot, 42) };
        assert_eq!(slot, 42);
        // SAFETY: null is explicitly tolerated and the value is dropped.
        unsafe { write_out::<i32>(core::ptr::null_mut(), 7) };
    }

    #[test]
    fn a_panic_is_contained_and_reported_rather_than_unwinding_into_swift() {
        // F-7. The `None` is what the caller turns into INTERNAL.CORE_PANIC;
        // silently returning a success value here would be the failure mode the
        // rule exists to prevent.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let caught = contained(|| -> i32 { panic!("a deliberate defect") });
        std::panic::set_hook(previous);
        assert!(caught.is_none());
        assert_eq!(contained(|| 5), Some(5));
    }
}
