//! Reading a token: privileges, group SIDs, and the user.
//!
//! **Authority:** ADR-0016 §11.9 (the privilege set), §11.7 (PS-12a's
//! principals); ADR-0017 MI-A1 (the identity comes from the kernel).
//!
//! Every function here returns **plain data**. Nothing returns a handle, so no
//! caller can hold a token open, and nothing above this module can be reached
//! while one is borrowed.

use windows_sys::Win32::Foundation::{HANDLE, LUID};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    CreateWellKnownSid, GetTokenInformation, LookupPrivilegeNameW, TokenGroups, TokenPrivileges,
    TokenUser, WinLocalSystemSid, PSID, SE_PRIVILEGE_ENABLED, SID_AND_ATTRIBUTES, TOKEN_GROUPS,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::service::privilege::{Privilege, TokenPrivilege, TokenPrivileges as Privileges};

use super::{wide, OwnedHandle};

/// `SE_GROUP_ENABLED`.
///
/// A literal rather than an import: `windows-sys` 0.61 exposes the
/// `SE_PRIVILEGE_*` attributes and not the `SE_GROUP_*` ones, and the value is
/// fixed by the ABI. **This is the bit the whole authorization model turns on** —
/// a filtered (non-elevated) administrator token carries `Administrators` as
/// deny-only, and reading "present" instead of "enabled" would grant `mgmt.admin`
/// to every administrator's ordinary shell.
pub const SE_GROUP_ENABLED: u32 = 0x0000_0004;

/// The privilege names §11.9 talks about, as static strings.
///
/// `LookupPrivilegeNameW` returns an owned `String`, and the decision layer
/// compares against `&'static str`. Rather than leak, the lookup is matched
/// against this table — which also means a privilege this build has no name for
/// is reported as unknown rather than silently dropped, and
/// [`crate::service::privilege::Posture::degradations`] then names it as a
/// token that was not trimmed.
const KNOWN: [&str; 6] = [
    "SeChangeNotifyPrivilege",
    "SeImpersonatePrivilege",
    "SeLoadDriverPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeDebugPrivilege",
    "SeTcbPrivilege",
];

/// The name this build recognises, or a stable placeholder.
///
/// The placeholder matters: an unrecognised privilege is still a privilege the
/// token holds, and dropping it would make an untrimmed token look trimmed.
fn known_name(name: &str) -> Privilege {
    KNOWN
        .iter()
        .find(|known| **known == name)
        .map_or(Privilege("SeUnrecognizedPrivilege"), |known| {
            Privilege(known)
        })
}

/// Opens this process's own token for reading.
fn own_token() -> Result<OwnedHandle, ()> {
    let mut handle: HANDLE = std::ptr::null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no close,
    // and `handle` is a live, correctly-typed out-parameter this frame owns.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut handle) };
    if ok == 0 {
        return Err(());
    }
    OwnedHandle::new(handle).ok_or(())
}

/// Queries one token-information class into a byte buffer.
///
/// Two calls, which is the documented protocol: the first fails with
/// `ERROR_INSUFFICIENT_BUFFER` and reports the size, the second fills it.
/// **The length is the OS's, not a guess**, so there is no fixed buffer here for
/// a token with an unusual number of groups to overrun.
fn query(token: HANDLE, class: i32) -> Result<Vec<u8>, ()> {
    let mut needed: u32 = 0;
    // SAFETY: a null buffer with a zero length is the documented size probe.
    // `needed` is a live out-parameter. The call is expected to fail.
    unsafe {
        GetTokenInformation(token, class, std::ptr::null_mut(), 0, &raw mut needed);
    }
    if needed == 0 {
        return Err(());
    }
    let mut buffer = vec![0u8; needed as usize];
    // SAFETY: `buffer` is `needed` bytes long, which is the length the OS just
    // asked for, and the pointer is valid for that whole length.
    let ok = unsafe {
        GetTokenInformation(
            token,
            class,
            buffer.as_mut_ptr().cast::<core::ffi::c_void>(),
            needed,
            &raw mut needed,
        )
    };
    if ok == 0 {
        return Err(());
    }
    Ok(buffer)
}

/// The privileges in a token.
///
/// # Errors
///
/// `()` when the token cannot be opened or queried, which
/// [`crate::service::privilege::Posture::read`] turns into
/// `PrivilegeError::Unverifiable` — refused, never assumed.
pub fn process_privileges() -> Result<Privileges, ()> {
    let token = own_token()?;
    privileges_of(token.get())
}

/// The privileges in an arbitrary token.
///
/// # Errors
///
/// `()` when the query fails.
pub fn privileges_of(token: HANDLE) -> Result<Privileges, ()> {
    let buffer = query(token, TokenPrivileges)?;
    if buffer.len() < core::mem::size_of::<TOKEN_PRIVILEGES>() {
        return Err(());
    }
    // SAFETY: the buffer was filled by `GetTokenInformation(TokenPrivileges)`,
    // which writes a `TOKEN_PRIVILEGES`, and its length was checked against that
    // struct's size immediately above.
    let header = unsafe { &*buffer.as_ptr().cast::<TOKEN_PRIVILEGES>() };
    let count = header.PrivilegeCount as usize;
    // The array is a trailing variable-length member declared as `[_; 1]`. Its
    // true extent is checked against the buffer the OS filled, so a count field
    // that disagreed with the length cannot drive a read past the end.
    let entries_offset = core::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
    let entry_size = core::mem::size_of::<windows_sys::Win32::Security::LUID_AND_ATTRIBUTES>();
    if entries_offset + count * entry_size > buffer.len() {
        return Err(());
    }

    let mut privileges = Vec::with_capacity(count);
    for index in 0..count {
        // SAFETY: `index < count`, and `count` entries were just proven to fit
        // inside the buffer the OS filled.
        let entry = unsafe { *header.Privileges.as_ptr().add(index) };
        let Some(name) = privilege_name(entry.Luid) else {
            continue;
        };
        privileges.push(TokenPrivilege {
            privilege: known_name(&name),
            enabled: entry.Attributes & SE_PRIVILEGE_ENABLED != 0,
        });
    }
    Ok(Privileges { privileges })
}

/// A privilege's name, from its LUID.
fn privilege_name(luid: LUID) -> Option<String> {
    let mut length: u32 = 0;
    // SAFETY: a null name buffer with a zero length is the documented size
    // probe; `luid` and `length` are live and correctly typed.
    unsafe {
        LookupPrivilegeNameW(
            std::ptr::null(),
            &raw const luid,
            std::ptr::null_mut(),
            &raw mut length,
        );
    }
    if length == 0 {
        return None;
    }
    // The OS reports the length in characters, excluding the terminator.
    let mut buffer = vec![0u16; length as usize + 1];
    let mut capacity = length + 1;
    // SAFETY: `buffer` holds `capacity` UTF-16 units and the pointer is valid
    // for all of them.
    let ok = unsafe {
        LookupPrivilegeNameW(
            std::ptr::null(),
            &raw const luid,
            buffer.as_mut_ptr(),
            &raw mut capacity,
        )
    };
    if ok == 0 {
        return None;
    }
    buffer.truncate(capacity as usize);
    Some(String::from_utf16_lossy(&buffer))
}

/// The **enabled** group SIDs in a token, as strings.
///
/// Enabled, not merely present — see [`SE_GROUP_ENABLED`].
///
/// # Errors
///
/// `()` when the query fails.
pub fn enabled_group_sids(token: HANDLE) -> Result<Vec<String>, ()> {
    let buffer = query(token, TokenGroups)?;
    if buffer.len() < core::mem::size_of::<TOKEN_GROUPS>() {
        return Err(());
    }
    // SAFETY: the buffer was filled by `GetTokenInformation(TokenGroups)`, which
    // writes a `TOKEN_GROUPS`, and its length was checked above.
    let header = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
    let count = header.GroupCount as usize;
    let entries_offset = core::mem::offset_of!(TOKEN_GROUPS, Groups);
    let entry_size = core::mem::size_of::<SID_AND_ATTRIBUTES>();
    if entries_offset + count * entry_size > buffer.len() {
        return Err(());
    }

    let mut sids = Vec::with_capacity(count);
    for index in 0..count {
        // SAFETY: `index < count`, and `count` entries were proven to fit.
        let entry = unsafe { *header.Groups.as_ptr().add(index) };
        if entry.Attributes & SE_GROUP_ENABLED == 0 {
            continue;
        }
        if let Some(text) = sid_to_string(entry.Sid) {
            sids.push(text);
        }
    }
    Ok(sids)
}

/// The user SID in a token, as a string.
///
/// # Errors
///
/// `()` when the query fails.
pub fn user_sid(token: HANDLE) -> Result<String, ()> {
    let buffer = query(token, TokenUser)?;
    if buffer.len() < core::mem::size_of::<TOKEN_USER>() {
        return Err(());
    }
    // SAFETY: filled by `GetTokenInformation(TokenUser)`, length checked above.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_to_string(user.User.Sid).ok_or(())
}

/// A SID in its `S-1-…` form.
///
/// The string form rather than the binary one, because that is what the DACL and
/// the decision layer both speak — and because a `PSID` is a pointer into a
/// buffer whose lifetime this function cannot express.
fn sid_to_string(sid: PSID) -> Option<String> {
    if sid.is_null() {
        return None;
    }
    let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: `sid` is non-null and points into a buffer the caller still owns
    // for the duration of this call; `raw` is a live out-parameter.
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

/// Whether this process is running as `LocalSystem`.
///
/// ADR-0016 §11.2 specifies it and rejects `LocalService` and `NetworkService`
/// by name, so this is a startup precondition rather than a curiosity.
///
/// # Errors
///
/// `()` when the token or the well-known SID cannot be obtained.
pub fn running_as_local_system() -> Result<bool, ()> {
    let token = own_token()?;
    let user = user_sid(token.get())?;
    Ok(user == local_system_sid()?)
}

/// `S-1-5-18`, from the OS rather than from a literal.
///
/// The value is fixed, and asking the OS for it is still better than writing it
/// down: `CreateWellKnownSid` is the same function every other component uses,
/// so a comparison here cannot disagree with one elsewhere over a formatting
/// difference.
fn local_system_sid() -> Result<String, ()> {
    let mut size: u32 = 0;
    // SAFETY: a null buffer with a zero size is the documented size probe.
    unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut size,
        );
    }
    if size == 0 {
        return Err(());
    }
    let mut buffer = vec![0u8; size as usize];
    // SAFETY: `buffer` is `size` bytes, which is what the probe asked for.
    let ok = unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast::<core::ffi::c_void>(),
            &raw mut size,
        )
    };
    if ok == 0 {
        return Err(());
    }
    sid_to_string(buffer.as_mut_ptr().cast::<core::ffi::c_void>()).ok_or(())
}

/// The service's own SID, for the pipe DACL.
///
/// # Errors
///
/// `()` when the name cannot be resolved.
pub fn service_sid(service_name: &str) -> Result<String, ()> {
    // `NT SERVICE\<name>` is resolvable by `LookupAccountNameW`, but the SID is
    // also derivable from the name by a documented hash — and neither is
    // available without more surface than this shim needs. The **injected** form
    // is what CD-2 asks for anyway: the installer knows the SID it created.
    let _ = wide(service_name);
    Err(())
}
