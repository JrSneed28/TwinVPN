//! The syscall shim: **the only module in this crate that names Windows, and
//! the only one that contains `unsafe`.**
//!
//! **Authority:** ADR-0018 DP-4 (`unsafe` is confined and every block carries a
//! `// SAFETY:` comment), CB-1; ADR-0016 §11.2's Windows row and §11.9;
//! ADR-0017 §11.4 MI-A1 … MI-A5.
//!
//! # Why this module exists at all, and why it is this small
//!
//! `shells/linux` carries `#![forbid(unsafe_code)]` and can: `tokio` gives it a
//! `UnixListener` and `UnixStream::peer_cred()`, so every privileged operation
//! the Linux agent performs has a safe wrapper somebody else wrote.
//!
//! There is no equivalent here. So this crate takes the **adapter's** discipline
//! instead: the decision is a pure function over a plain value in
//! [`crate::service`], and this module is the reader that produces the value.
//! Every function below returns plain data — a `Vec<String>` of SIDs, a
//! [`crate::service::privilege::TokenPrivileges`] — and never a handle, so
//! nothing above this line can hold a Windows resource open or be called while
//! impersonating.
//!
//! # It has never been compiled for Windows *and executed*
//!
//! `make cross-check` type-checks this module against the real `windows-sys` for
//! `x86_64-pc-windows-msvc` with `-D warnings`. That is a genuine proof that
//! every signature, every struct layout and every constant name is right. It is
//! **not** a proof that any of it does what it says: none of this has run.

// The endpoint and the accept loop are two modules and not one, and the split is
// a verification decision rather than a taste one: `ring`'s build script refuses
// a GNU compiler for `x86_64-pc-windows-msvc`, so anything linking the core
// cannot be type-checked for Windows on this host at all. `endpoint` names no
// core type, so `--features service` checks every `unsafe` block in it;
// `listener` does, and is first compiled on a Windows runner. See this crate's
// `Cargo.toml` and `shells/windows/README.md` §7.19.
pub mod endpoint;
pub mod instance;
#[cfg(feature = "core-host")]
pub mod listener;
pub mod pipe;
pub mod scm;
pub mod token;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::PSID;

/// A Windows call that refused, carrying the status it refused with.
///
/// A type rather than `()`, because the whole of `oserr`'s discipline is that a
/// number rides along with a name: a shim that lost the status would make the
/// decision layer above it unable to say *why* a token could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the call `{call}` failed with status {:#010x}", .status.get())]
pub struct Failure {
    /// Which call.
    pub call: &'static str,
    /// What it reported.
    pub status: twinvpn_platform_windows::oserr::Win32Error,
}

impl Failure {
    /// The failure of `call`, with this thread's last error.
    #[must_use]
    pub fn of(call: &'static str) -> Self {
        Self {
            call,
            status: last_error(),
        }
    }
}

/// A NUL-terminated UTF-16 buffer, for the `W` entry points.
///
/// Returned as an owned `Vec` rather than a pointer, so the buffer outlives the
/// call by construction: a `.as_ptr()` on a temporary is the classic
/// use-after-free at an FFI boundary, and the borrow checker cannot see it
/// through a raw pointer.
#[must_use]
pub fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The last error, as the adapter's own [`Win32Error`] so the whole product has
/// one mapping.
///
/// [`Win32Error`]: twinvpn_platform_windows::oserr::Win32Error
#[must_use]
pub fn last_error() -> twinvpn_platform_windows::oserr::Win32Error {
    // SAFETY: `GetLastError` reads this thread's own last-error slot. It takes
    // no arguments, dereferences nothing, and is safe to call at any time.
    twinvpn_platform_windows::oserr::Win32Error(unsafe { GetLastError() })
}

/// A SID in its `S-1-…` form.
///
/// The string form rather than the binary one, because that is what the DACL
/// ([`crate::mi::dacl`]) and the decision layer ([`crate::service::peer`]) both
/// speak — and because a [`PSID`] is a pointer into a buffer whose lifetime this
/// function cannot express.
///
/// # Recorded rather than left to be discovered
///
/// [`token`] carries a private twin of this function, written when reading a
/// token was the only place a SID had to be rendered. The two are the same three
/// calls and should be one; collapsing them is a deletion in `token.rs`, which
/// belongs to another change in flight at the time this landed.
///
/// # Safety
///
/// `sid` must be null or point at a valid `SID` structure that stays live for
/// the duration of the call.
#[must_use]
pub unsafe fn sid_to_string(sid: PSID) -> Option<String> {
    if sid.is_null() {
        return None;
    }
    let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: the caller guarantees `sid` points at a live `SID`; `raw` is a
    // live out-parameter this frame owns.
    let ok = unsafe { ConvertSidToStringSidW(sid, &raw mut raw) };
    if ok == 0 || raw.is_null() {
        return None;
    }
    let mut length = 0usize;
    // SAFETY: `raw` is a NUL-terminated buffer the OS allocated; the walk stops
    // at the terminator it guarantees.
    while unsafe { *raw.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: `length` units were just walked and found to be inside the buffer.
    let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(raw, length) });
    // SAFETY: `raw` was allocated by `ConvertSidToStringSidW`, which documents
    // `LocalFree` as its release, and nothing else holds it.
    unsafe {
        windows_sys::Win32::Foundation::LocalFree(raw.cast());
    }
    Some(text)
}

/// An owned handle that closes itself.
///
/// Every handle this module opens is wrapped, so a `?` on an error path cannot
/// leak one. `Drop` rather than an explicit close at each site: the impersonation
/// path in [`pipe`] has five early returns, and five hand-written closes is five
/// chances to miss one.
#[derive(Debug)]
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    /// Wraps a handle a Windows call produced.
    ///
    /// Returns `None` for the two values Windows uses for "no handle", so the
    /// caller cannot construct a wrapper around a sentinel and close it later.
    #[must_use]
    pub fn new(handle: HANDLE) -> Option<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Self(handle))
        }
    }

    /// The raw handle, for the duration of a call.
    #[must_use]
    pub const fn get(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from `OwnedHandle::new`, which refused both
        // sentinel values, and this type owns it — there is no `Clone` and no
        // constructor that borrows, so no other owner can close it first.
        unsafe {
            CloseHandle(self.0);
        }
    }
}
