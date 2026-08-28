//! The ABI's two data shapes — `tw_slice` and `tw_buf` — and the **whole** of
//! this crate's raw-pointer handling.
//!
//! **Authority:** ADR-0018 §11.4 F-2 (ownership), F-3 (strings and buffers),
//! F-8 (only handles, slices and scalars cross); DP-4 (the `unsafe` allowlist).
//!
//! # Every `unsafe` in this crate is one of the helpers below, or a vtable call
//!
//! DP-4 puts this crate on the allowlist and requires every `unsafe` block to
//! carry a `// SAFETY:` comment naming its invariant. Concentrating the pointer
//! work here means the count is small, the invariants are stated once, and a
//! reviewer asking *"what does this crate do that could be unsound"* reads one
//! file rather than every entry point.
//!
//! # F-2, stated once
//!
//! > A buffer crossing the boundary is either borrowed for the duration of one
//! > call (`const uint8_t*, size_t`) or owned by the allocator that created it
//! > and released by that side's own free function. The core never frees a
//! > shell allocation; the shell never frees a core allocation. **No
//! > `malloc`/`free` pairing crosses the boundary.**
//!
//! [`TwSlice`] is the borrowed form. [`TwBuf`] is the core-owned form: it is a
//! `Box<Vec<u8>>` leaked into a raw pointer and reclaimed by
//! [`crate::tw_buf_free`], so the allocation is Rust's on both ends.

use core::ffi::c_void;

/// A borrowed, length-delimited byte range. Mirrors `tw_slice` in `twinvpn.h`.
///
/// `#[repr(C)]` and exactly two fields, in the header's order. The
/// header-drift test checks that shape against the header text.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TwSlice {
    /// The first byte, or null for an empty slice.
    pub ptr: *const u8,
    /// The length in bytes.
    pub len: usize,
}

impl TwSlice {
    /// The empty slice. What every fallible accessor returns rather than a
    /// null-pointer crash.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            ptr: core::ptr::null(),
            len: 0,
        }
    }

    /// Borrows a Rust slice for the duration of one call.
    #[must_use]
    pub const fn from_slice(bytes: &[u8]) -> Self {
        Self {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        }
    }

    /// Reads the slice the caller passed.
    ///
    /// Returns the empty slice for a null pointer or a zero length, which is
    /// F-3's rule applied to the degenerate case: an absent buffer is a
    /// **valid input meaning "nothing"**, not a crash. An empty `platform_ctx`
    /// is exactly that, and ADR-0019 LT-3b requires it to resolve.
    ///
    /// # Safety
    ///
    /// The caller guarantees that, when `ptr` is non-null and `len` is
    /// non-zero, `ptr` points to `len` initialised bytes that stay valid and
    /// unmutated for the lifetime `'a`. That is precisely `twinvpn.h`'s
    /// documented contract for a `tw_slice` argument.
    #[must_use]
    pub unsafe fn as_bytes<'a>(self) -> &'a [u8] {
        if self.ptr.is_null() || self.len == 0 {
            return &[];
        }
        // SAFETY: `ptr` is non-null and `len` is non-zero, and the caller's
        // contract (stated in this function's `# Safety` section and in
        // `twinvpn.h`) is that the range is initialised and stays valid for the
        // duration of the call. No aliasing `&mut` can exist, because the ABI
        // hands out only `const uint8_t *` for a slice.
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
}

// SAFETY-adjacent note, not an `unsafe impl`: `TwSlice` is deliberately NOT
// `Send`/`Sync`. It is a borrow valid for one call, and marking it shareable
// would invite exactly the cross-thread use F-6 forbids.

/// A core-allocated buffer. Mirrors the opaque `tw_buf` in `twinvpn.h`.
///
/// Opaque to C by construction: the header declares `typedef struct tw_buf
/// tw_buf;` with no definition, so a C caller can hold a pointer and nothing
/// else.
#[derive(Debug)]
pub struct TwBuf {
    bytes: Vec<u8>,
}

impl TwBuf {
    /// Allocates a buffer and hands the caller a raw pointer it now owns.
    ///
    /// The counterpart is [`TwBuf::release`], reached from C through
    /// `tw_buf_free`. Nothing else may free it (F-2).
    #[must_use]
    pub fn into_raw(bytes: Vec<u8>) -> *mut TwBuf {
        Box::into_raw(Box::new(TwBuf { bytes }))
    }

    /// The bytes, borrowed.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reclaims a buffer previously produced by [`TwBuf::into_raw`].
    ///
    /// # Safety
    ///
    /// `ptr` is either null or a pointer previously returned by
    /// [`TwBuf::into_raw`] and not yet released. Releasing twice, or releasing
    /// a pointer this crate did not produce, is undefined behaviour — which is
    /// exactly why F-2 forbids a `malloc`/`free` pairing from crossing the
    /// boundary in either direction.
    pub unsafe fn release(ptr: *mut TwBuf) {
        if ptr.is_null() {
            return;
        }
        // SAFETY: non-null, and by this function's contract it came from
        // `Box::into_raw` in `into_raw` and has not been released. Reboxing
        // reclaims exactly that allocation.
        drop(unsafe { Box::from_raw(ptr) });
    }
}

/// Writes an out-parameter, tolerating a null pointer.
///
/// A caller that does not want the value passes null, and dropping the value
/// rather than writing through null is the correct behaviour — the alternative
/// is a crash in the one code path that exists to *report* a failure.
///
/// # Safety
///
/// `out` is either null or a valid, writable `*mut *mut T` the caller owns for
/// the duration of the call.
pub unsafe fn write_out<T>(out: *mut *mut T, value: *mut T) {
    if out.is_null() {
        // The caller declined the value. Nothing is leaked: `value` is either
        // null or owned by this crate's caller-side free function, and a caller
        // that passes null for `err_out` has accepted that it cannot see the
        // name of what went wrong.
        return;
    }
    // SAFETY: `out` is non-null and, by this function's contract, points to a
    // writable slot the caller owns for the duration of the call.
    unsafe { *out = value };
}

/// Borrows an opaque instance pointer.
///
/// # Safety
///
/// `ptr` is either null or a pointer previously returned by
/// [`crate::tw_core_create`] and not yet destroyed. F-6 additionally requires
/// that at most one thread holds it for a **mutating** call at a time (S-47);
/// that is the caller's obligation and is not checkable here.
#[must_use]
pub unsafe fn as_ref_opt<'a, T>(ptr: *const T) -> Option<&'a T> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: non-null, and by this function's contract it is a live instance
    // pointer this crate produced. The returned reference is shared, so it
    // cannot alias a `&mut`; the ABI never hands out a `&mut` to an instance.
    Some(unsafe { &*ptr })
}

/// The `void *ctx` a vtable entry is called with.
///
/// A distinct type so a `ctx` cannot be confused with any other pointer this
/// crate handles, and so `Send`/`Sync` are asserted **once**, with the reason
/// written down, rather than implicitly at each use.
#[derive(Debug, Clone, Copy)]
pub struct HostCtx(pub *mut c_void);

// SAFETY: `ctx` is an opaque token the shell supplies and the core only ever
// passes back to that same shell's function pointers. The core never
// dereferences it, so no data race is possible on this side of the boundary.
// The shell's own contract (`twinvpn.h`, F-6) is that its vtable entries are
// callable from a core-owned thread; making `HostCtx` `Send`/`Sync` records
// that obligation in one place instead of scattering `unsafe impl`s.
unsafe impl Send for HostCtx {}
// SAFETY: as above.
unsafe impl Sync for HostCtx {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_slice_is_a_valid_input_not_a_crash() {
        // ADR-0019 LT-3b depends on this: an EMPTY platform_ctx must resolve to
        // the neutral variant, so the empty slice has to be readable.
        // SAFETY: the empty slice has a null pointer and zero length, which the
        // accessor handles without dereferencing.
        let bytes = unsafe { TwSlice::empty().as_bytes() };
        assert!(bytes.is_empty());
    }

    #[test]
    fn a_null_pointer_with_a_nonzero_length_still_yields_nothing() {
        let slice = TwSlice {
            ptr: core::ptr::null(),
            len: 32,
        };
        // SAFETY: the accessor checks for null before dereferencing, which is
        // the whole point of this test.
        let bytes = unsafe { slice.as_bytes() };
        assert!(bytes.is_empty());
    }

    #[test]
    fn a_borrowed_slice_round_trips() {
        let data = [1u8, 2, 3, 4];
        let slice = TwSlice::from_slice(&data);
        // SAFETY: `data` outlives `slice` in this scope.
        assert_eq!(unsafe { slice.as_bytes() }, &data);
    }

    #[test]
    fn a_buffer_round_trips_and_frees() {
        let raw = TwBuf::into_raw(vec![7u8; 5]);
        // SAFETY: `raw` was just produced by `into_raw` and is live.
        let borrowed = unsafe { as_ref_opt(raw.cast_const()) }.expect("live");
        assert_eq!(borrowed.bytes(), &[7u8; 5]);
        // SAFETY: `raw` came from `into_raw` and has not been released.
        unsafe { TwBuf::release(raw) };
    }

    #[test]
    fn freeing_null_is_a_no_op() {
        // SAFETY: the null case is checked before any dereference.
        unsafe { TwBuf::release(core::ptr::null_mut()) };
    }

    #[test]
    fn writing_through_a_null_out_parameter_is_a_no_op() {
        // SAFETY: the null case is checked before any dereference.
        unsafe { write_out::<TwBuf>(core::ptr::null_mut(), core::ptr::null_mut()) };
    }

    #[test]
    fn a_null_instance_pointer_is_none_rather_than_a_crash() {
        // SAFETY: null is checked before any dereference.
        let r: Option<&TwBuf> = unsafe { as_ref_opt(core::ptr::null()) };
        assert!(r.is_none());
    }
}
