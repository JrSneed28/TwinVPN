//! Reading a pipe client's identity — and reverting before anything else
//! happens.
//!
//! **Authority:** ADR-0017 §11.4 MI-A1 (the identity comes from the kernel),
//! MI-A2 (a pid gates nothing), **MI-A4** (impersonate to read, revert before
//! any work), MI-A5 (fail closed); ADR-0016 PS-14 (the console seat).
//!
//! # MI-A4, made structural
//!
//! > On Windows the server MAY call `ImpersonateNamedPipeClient` only to read
//! > the client's token, and MUST `RevertToSelf` **before** performing any work.
//! > Performing privileged work while impersonating a client is the classic
//! > named-pipe confused deputy…
//!
//! [`read_client_principal`] is the only function in this crate that
//! impersonates. It reverts through [`Impersonation`]'s `Drop`, which runs on
//! **every** path out including the early returns and a panic, and it returns a
//! [`Principal`] — a value with no handle in it. There is no way to be
//! impersonating and holding one, because the token handle is closed and the
//! impersonation reverted before the value exists.

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::{RevertToSelf, TOKEN_QUERY};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient};
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSActive, WTSConnectState, WTSFreeMemory, WTSGetActiveConsoleSessionId,
    WTSQuerySessionInformationW, WTS_CURRENT_SERVER_HANDLE,
};
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

use crate::service::peer::{Principal, SessionKind};

use super::{token, Failure, OwnedHandle};

/// An active impersonation, reverted on drop.
///
/// The whole of MI-A4's guarantee: a `?` inside the block, a panic, or an early
/// `return` all run this destructor, so there is no path on which the thread is
/// still impersonating when [`read_client_principal`] returns.
struct Impersonation;

impl Drop for Impersonation {
    fn drop(&mut self) {
        // SAFETY: `RevertToSelf` takes no arguments and undoes the
        // impersonation this thread performed. Calling it when no impersonation
        // is active is documented as harmless.
        unsafe {
            RevertToSelf();
        }
    }
}

/// The calling client's kernel-attested identity.
///
/// # Safety
///
/// `pipe` must be a live, **connected** named-pipe handle, and must stay live
/// for the duration of the call. An unconnected one makes
/// `ImpersonateNamedPipeClient` fail, which is handled; a dangling one is
/// undefined behaviour, which is what this contract exists to exclude.
///
/// # Errors
///
/// [`Failure`] when the token cannot be read, which the server turns into
/// `MGMT.PRINCIPAL_UNVERIFIABLE` and a close (MI-A5). There is no fallback
/// principal and no anonymous tier.
pub unsafe fn read_client_principal(pipe: HANDLE) -> Result<Principal, Failure> {
    // MI-A2: the pid is read for the log line and gates nothing.
    let mut pid: u32 = 0;
    // SAFETY: `pipe` is a live pipe handle the caller owns for the duration of
    // this call; `pid` is a live out-parameter.
    let ok = unsafe { GetNamedPipeClientProcessId(pipe, &raw mut pid) };
    if ok == 0 {
        return Err(Failure::of("GetNamedPipeClientProcessId"));
    }

    // SAFETY: `pipe` is a live, connected pipe handle. On success this thread is
    // impersonating until the guard below is dropped.
    let ok = unsafe { ImpersonateNamedPipeClient(pipe) };
    if ok == 0 {
        return Err(Failure::of("ImpersonateNamedPipeClient"));
    }
    let _revert = Impersonation;

    let mut token_handle: HANDLE = std::ptr::null_mut();
    // SAFETY: `GetCurrentThread` returns a pseudo-handle needing no close.
    // `openasself` is TRUE so the open is checked against the *service's* own
    // context rather than the client's — otherwise a client whose token cannot
    // open itself would make this fail for the wrong reason.
    let ok = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token_handle) };
    if ok == 0 {
        return Err(Failure::of("OpenThreadToken"));
    }
    let token_handle =
        OwnedHandle::new(token_handle).ok_or_else(|| Failure::of("OpenThreadToken"))?;

    // SAFETY: `token_handle` was opened with `TOKEN_QUERY` immediately above and
    // is live until it is dropped below.
    let user_sid = unsafe { token::user_sid(token_handle.get()) }?;
    // SAFETY: as above.
    let enabled_group_sids = unsafe { token::enabled_group_sids(token_handle.get()) }?;

    // Everything is read. The handle closes here and the impersonation reverts
    // at the end of the function, both before the value below is used for
    // anything — which is MI-A4's ordering.
    drop(token_handle);

    Ok(Principal {
        user_sid,
        enabled_group_sids,
        session: session_kind(pid),
        pid,
        // Resolving a SID to an account name needs `LookupAccountSidW` and a
        // domain round trip that can block. `Principal::actor` falls back to the
        // SID, so attribution is never absent (PS-13) — it is simply less
        // readable. Recorded as a gap rather than a blocking call on the attach
        // path.
        account: None,
    })
}

/// Which session the client is in (PS-14).
///
/// Two facts, and **both** are required for a console seat:
///
/// 1. the client's session is the one Windows currently calls the console
///    session (`WTSGetActiveConsoleSessionId`), and
/// 2. that session is `WTSActive` rather than disconnected or locked out.
///
/// Asking only the first would let a *disconnected* console session count;
/// asking only the second would let any live RDP session count, which is exactly
/// what PS-14 refuses. Session 0 is the service session and has no seat at all.
///
/// **Failing closed is the point**: a query that does not answer yields
/// [`SessionKind::Unknown`], and the decision layer treats that as remote.
fn session_kind(pid: u32) -> SessionKind {
    let mut session: u32 = 0;
    // SAFETY: `session` is a live out-parameter; `pid` is a plain integer.
    let ok = unsafe { ProcessIdToSessionId(pid, &raw mut session) };
    if ok == 0 {
        return SessionKind::Unknown;
    }
    if session == 0 {
        return SessionKind::Service;
    }

    // SAFETY: takes no arguments and reads a global the session manager owns.
    // `0xFFFF_FFFF` is its documented "no console session" answer.
    let console = unsafe { WTSGetActiveConsoleSessionId() };
    if console == u32::MAX || console != session {
        return SessionKind::Remote;
    }

    let mut buffer: windows_sys::core::PWSTR = std::ptr::null_mut();
    let mut returned: u32 = 0;
    // SAFETY: both out-parameters are live. `WTS_CURRENT_SERVER_HANDLE` is the
    // documented local-server constant.
    let ok = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session,
            WTSConnectState,
            &raw mut buffer,
            &raw mut returned,
        )
    };
    if ok == 0 || buffer.is_null() {
        return SessionKind::Unknown;
    }
    // `WTSConnectState` returns a `WTS_CONNECTSTATE_CLASS`, which is an `i32`.
    // The four bytes are **copied out** rather than read through a cast: WTS
    // hands back a `PWSTR`, whose alignment is two, and a `*const i32` read from
    // it would be an under-aligned load. A copy has no alignment requirement.
    let state = if returned as usize >= core::mem::size_of::<i32>() {
        let mut raw = [0u8; core::mem::size_of::<i32>()];
        // SAFETY: the call succeeded and reported at least four bytes at
        // `buffer`, and `raw` is exactly four bytes; the two do not overlap.
        unsafe {
            core::ptr::copy_nonoverlapping(buffer.cast::<u8>(), raw.as_mut_ptr(), raw.len());
        }
        i32::from_ne_bytes(raw)
    } else {
        // A short buffer is not a state. `-1` matches nothing below, so the
        // answer is `Remote` — the closed direction.
        -1
    };
    // SAFETY: `buffer` was allocated by `WTSQuerySessionInformationW`, whose
    // documented release is `WTSFreeMemory` — `LocalFree` is not correct here.
    unsafe {
        WTSFreeMemory(buffer.cast());
    }

    if state == WTSActive {
        SessionKind::Console
    } else {
        SessionKind::Remote
    }
}
