//! Turning a failure into a return value, and resolving the two arguments every
//! entry point shares.
//!
//! **Authority:** ADR-0018 F-4 ("errors carry a name, never an errno"), F-7;
//! ADR-0015 §11.2; `docs/implementation/ownership.md` §6 rule 9.
//!
//! Split out of `lib.rs` so that file holds the `extern "C"` surface and nothing
//! else — which is also what lets `tests/header_matches_rust.rs` parse one file
//! and be sure it has seen every exported symbol.

use twinvpn_types::{codes, Component, Diagnostic};

use crate::abi::{ext_of, slice_of, write_out, TvbBuf, TvbSlice};
use crate::correlation::CorrelationId;
use crate::ext::TvbExt;
use crate::{envelope, log, TVB_ERR};

/// Writes an envelope into `err` and returns `TVB_ERR`.
///
/// The one place a failure becomes a return value, so "how does this crate
/// report an error" has one answer.
pub(crate) unsafe fn fail(
    call: &'static str,
    diagnostic: &Diagnostic,
    correlation: &CorrelationId,
    err: *mut *mut TvbBuf,
) -> i32 {
    log::refused(call, diagnostic.code().as_str(), correlation);
    let bytes = envelope::render(diagnostic);
    // SAFETY: `err` is either null or a caller-owned `*mut *mut TvbBuf`, and
    // `write_out` checks for null before writing. The buffer is leaked into the
    // caller's ownership, which is F-2's direction: the bridge allocated it and
    // `tvb_buf_free` releases it.
    unsafe { write_out(err, TvbBuf::into_raw(bytes)) };
    TVB_ERR
}

/// The failure for a bare registered code.
pub(crate) unsafe fn fail_code(
    call: &'static str,
    code: twinvpn_types::ReasonCode,
    correlation: &CorrelationId,
    err: *mut *mut TvbBuf,
) -> i32 {
    let diagnostic = Diagnostic::builder(code, Component::TunnelEngine).build();
    // SAFETY: delegated; `err`'s contract is unchanged.
    unsafe { fail(call, &diagnostic, correlation, err) }
}

/// The failure a caught panic produces (F-7).
pub(crate) unsafe fn fail_panic(call: &'static str, err: *mut *mut TvbBuf) -> i32 {
    let correlation = CorrelationId::absent();
    log::panicked(call, &correlation);
    // SAFETY: delegated; `err`'s contract is unchanged.
    unsafe { fail_code(call, codes::INTERNAL_CORE_PANIC, &correlation, err) }
}

/// Resolves a handle and a correlation slice, or reports why it could not.
///
/// # Safety
///
/// `ptr` and `cid` obey the ABI's own contract: a handle from `tvb_ext_start`
/// that is still live, and a slice valid for the duration of the call.
pub(crate) unsafe fn resolve<'a>(
    call: &'static str,
    ptr: *const TvbExt,
    cid: TvbSlice,
    err: *mut *mut TvbBuf,
) -> Result<(&'a TvbExt, CorrelationId), i32> {
    // SAFETY: `cid` obeys the ABI contract by this function's own contract, and
    // `slice_of` handles the `(NULL, 0)` shape without dereferencing.
    let Some(bytes) = (unsafe { slice_of(cid) }) else {
        // SAFETY: `err`'s contract is unchanged.
        return Err(unsafe {
            fail_code(
                call,
                codes::PROTO_MALFORMED_MESSAGE,
                &CorrelationId::absent(),
                err,
            )
        });
    };
    // Validated BEFORE the handle is resolved and before anything proportional
    // to its length is allocated (§6 rule 9).
    let correlation = match CorrelationId::validated(bytes) {
        Ok(correlation) => correlation,
        // SAFETY: `err`'s contract is unchanged.
        Err(diagnostic) => {
            return Err(unsafe { fail(call, &diagnostic, &CorrelationId::absent(), err) })
        }
    };
    // SAFETY: `ptr` obeys the ABI contract by this function's own contract, and
    // `ext_of` returns `None` for null rather than dereferencing.
    let Some(instance) = (unsafe { ext_of(ptr) }) else {
        // SAFETY: `err`'s contract is unchanged.
        return Err(unsafe {
            fail_code(call, codes::INTERNAL_UNEXPECTED_STATE, &correlation, err)
        });
    };
    log::entered(call, &correlation);
    Ok((instance, correlation))
}
