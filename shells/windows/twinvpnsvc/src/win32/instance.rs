//! The single-instance lock (LC-5), and PS-1's mechanism.
//!
//! **Authority:** [ADR-0022](../../../../../docs/adr/ADR-0022-application-lifecycle-and-background-execution.md)
//! LC-5 ("Windows = named kernel mutex in the `Global\` namespace, held by the
//! service SID. Failure is **fatal**"); ADR-0016 PS-1.
//!
//! # Why a kernel mutex and not a lock file
//!
//! PS-1 requires exactly one authority per host, and the failure it names is a
//! *second process* claiming the Wintun adapter, the WFP sublayer or the store.
//! A lock file survives the process that made it, so a crash leaves a lock
//! nobody holds and the next start has to decide whether to break it — which is
//! the decision `shells/linux/README.md` §7 item 7 records as unresolved there.
//!
//! A kernel mutex has no such problem: the handle is released when the process
//! ends, however it ends, so a crashed predecessor never blocks a restart and a
//! *live* one always does. That is the one place Windows makes PS-1 easier
//! rather than harder, and this shell takes it.
//!
//! # `Global\`, and what it costs
//!
//! LC-5 specifies the `Global\` namespace, which is per-machine rather than per
//! session — so a service in session 0 and a user's process in session 2 contend
//! for the same name, which is the point. Creating a `Global\` object needs
//! `SeCreateGlobalPrivilege`, which `LocalSystem` holds; an unprivileged
//! foreground run does not, and [`acquire`] reports that as a failure to acquire
//! rather than pretending it succeeded.

use windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS;
use windows_sys::Win32::System::Threading::CreateMutexW;

use super::{last_error, wide, OwnedHandle};

/// The mutex's name.
///
/// Documented as a constant for the same reason the pipe's name is: an
/// administrator diagnosing "the service will not start" needs to be able to
/// find the object, and `handle.exe` searches by name.
pub const MUTEX_NAME: &str = r"Global\TwinVPNService.Instance";

/// The acquired lock, released when the process ends however it ends.
///
/// Held by `main` for the life of the service. Dropping it is not part of the
/// shutdown path: LC-5's guarantee is that a *live* process holds it, and the
/// kernel releases it at exit whether that exit was clean or not.
#[derive(Debug)]
pub struct InstanceLock(#[allow(dead_code)] OwnedHandle);

/// Why the lock could not be taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LockError {
    /// Another authority already holds it. **PS-1's condition.**
    #[error("another TwinVPN authority is already running on this host")]
    AlreadyHeld,
    /// The mutex could not be created — most often `SeCreateGlobalPrivilege`
    /// absent, which is what an unprivileged foreground run hits.
    #[error("the single-instance mutex could not be created")]
    Unavailable,
}

/// Takes the lock.
///
/// # Errors
///
/// [`LockError::AlreadyHeld`] when a second authority is running, which LC-5
/// makes **fatal**: "MUST NOT proceed to step 3". [`LockError::Unavailable`]
/// when the object cannot be created at all.
pub fn acquire() -> Result<InstanceLock, LockError> {
    let name = wide(MUTEX_NAME);
    // SAFETY: `name` is a live NUL-terminated buffer for the duration of the
    // call. A null `SECURITY_ATTRIBUTES` takes the default descriptor, which for
    // a `LocalSystem` creator is `SYSTEM` and `Administrators` — the same
    // principals the store directory and the pipe grant, so a user process
    // cannot take the name first and lock the service out.
    let handle = unsafe { CreateMutexW(std::ptr::null(), 1, name.as_ptr()) };
    // `CreateMutexW` returns a handle to the EXISTING object when the name is
    // taken, and sets the last error — so the handle being non-null is not the
    // answer. Reading the error before wrapping is what distinguishes "we
    // created it" from "we opened somebody else's".
    let existed = last_error().get() == ERROR_ALREADY_EXISTS;
    let owned = OwnedHandle::new(handle).ok_or(LockError::Unavailable)?;
    if existed {
        // The handle is dropped here, which closes our reference and leaves the
        // holder's intact.
        return Err(LockError::AlreadyHeld);
    }
    Ok(InstanceLock(owned))
}
