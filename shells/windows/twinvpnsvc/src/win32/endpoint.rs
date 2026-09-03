//! The management endpoint itself: PS-12a's principals, MI-A3's descriptor, and
//! the pipe instance that carries them.
//!
//! **Authority:** [ADR-0016](../../../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
//! §11.6 step (7), §11.9 (the pipe DACL), PS-12a;
//! [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.2's Windows transport row, MI-A3;
//! [ADR-0021](../../../../../docs/adr/ADR-0021-packaging-distribution-and-updates.md)
//! §11's Windows row ("the named pipe and its **explicit** DACL … resolved
//! against the group SID at creation"); ADR-0018 CD-2, DP-4.
//!
//! # What §11.2's Windows row asks for, and where each half is
//!
//! | Requirement | Here |
//! |---|---|
//! | `\\.\pipe\TwinVPN\mgmt` | [`crate::mi::pipe_name`] — the constant, never retyped |
//! | message mode | [`ServerOptions::pipe_mode`] |
//! | `PIPE_REJECT_REMOTE_CLIENTS` (**mandatory**: without it the pipe is on SMB) | [`ServerOptions::reject_remote_clients`] |
//! | `FILE_FLAG_FIRST_PIPE_INSTANCE` | [`ServerOptions::first_pipe_instance`], on the first instance only |
//! | the explicit DACL, written by **the agent** at every start (MI-A3) | [`crate::mi::dacl::pipe_sddl`] → `Descriptor` → `lpSecurityAttributes` |
//!
//! # Message mode does not make the length prefix redundant
//!
//! `crate::mi::wire` states the split and it is worth restating where the mode is
//! actually set: the kernel preserves the **boundary**, and `mio` — which owns
//! the overlapped reads under `tokio` — drains a message into its own buffer and
//! hands this crate a byte stream regardless. So the four-byte prefix is still
//! what bounds the allocation (`ownership.md` §6 rule 9), and message mode is the
//! property underneath it rather than a replacement for it.
//!
//! # Why this is a separate module from `super::listener`
//!
//! Nothing here names `twinvpn_core`, and that is load-bearing rather than tidy.
//! `ring`'s build script refuses a GNU compiler for `x86_64-pc-windows-msvc`, so
//! on the Linux host this shell is written on **nothing that links the core can
//! be type-checked for Windows at all** (see this crate's `Cargo.toml`).
//! Splitting the endpoint from the accept loop is what puts every `unsafe` block
//! below inside
//!
//! ```text
//! cargo clippy -p twinvpnsvc --no-default-features --features service \
//!     --all-targets --target x86_64-pc-windows-msvc -- -D warnings
//! ```
//!
//! which is the only compile proof this domain's Windows code has.

use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use windows_sys::Win32::Foundation::{LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    LookupAccountNameW, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SID_NAME_USE, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::mi::dacl::{BindRefusal, PrincipalSids};

use super::{last_error, sid_to_string, wide, Failure, OwnedHandle};

/// PS-12a's `OBSERVE` principal: the local group the MSI creates **empty**.
///
/// The name is ADR-0016 §11.7's and the SID is this host's, which is why one is
/// a constant here and the other is a lookup.
pub const OBSERVE_GROUP: &str = "TwinVPN Users";

/// PS-12a's `OPERATE` principal.
pub const OPERATE_GROUP: &str = "TwinVPN Operators";

/// `sizeof(SECURITY_ATTRIBUTES)`, which the structure carries in its own first
/// field so that Windows can tell versions apart.
#[allow(clippy::cast_possible_truncation)]
const ATTRIBUTES_LEN: u32 = core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;

/// PS-12a's three principals, resolved to the SIDs this host gave them.
///
/// **This is the reader, not the decision.** [`crate::mi::dacl::pipe_sddl`] takes
/// the value and holds no lookup, which is the split `super`'s own documentation
/// describes; ADR-0021 §11's Windows row assigns the resolution itself to the
/// daemon — the pipe's DACL is *"resolved against the group SID at creation"* —
/// because the package creates the groups and only this host knows their SIDs.
///
/// # Errors
///
/// [`BindRefusal::PrincipalUnknown`] when a group is absent, which on a machine
/// the MSI has not run on is the normal answer and is a refusal rather than a
/// widened descriptor (MI-A5's direction).
pub fn principals() -> Result<PrincipalSids, BindRefusal> {
    Ok(PrincipalSids {
        service: account_sid(&format!(r"NT SERVICE\{}", crate::SERVICE_NAME))?,
        observe: account_sid(OBSERVE_GROUP)?,
        operate: account_sid(OPERATE_GROUP)?,
    })
}

/// One account's SID, in its `S-1-…` form.
///
/// # Errors
///
/// [`BindRefusal`] carrying whatever `LookupAccountNameW` reported.
pub fn account_sid(name: &str) -> Result<String, BindRefusal> {
    let account = wide(name);
    let mut sid_bytes: u32 = 0;
    let mut domain_chars: u32 = 0;
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: null buffers with zero lengths are the documented size probe;
    // `account` is a live NUL-terminated buffer and the three out-parameters are
    // live for the call. The probe is expected to fail.
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            std::ptr::null_mut(),
            &raw mut sid_bytes,
            std::ptr::null_mut(),
            &raw mut domain_chars,
            &raw mut kind,
        );
    }
    if sid_bytes == 0 {
        return Err(BindRefusal::classify(last_error().get(), false));
    }

    // A `Vec<u32>` and not a `Vec<u8>`: a `SID` is a structure whose alignment is
    // four, and `Vec<u8>` guarantees one. The same reasoning `super::token`'s
    // `AlignedBuffer` records — a cast from an under-aligned pointer is
    // undefined behaviour whatever the allocator happened to return.
    let mut sid = vec![0u32; (sid_bytes as usize).div_ceil(core::mem::size_of::<u32>())];
    let mut domain = vec![0u16; domain_chars as usize + 1];
    // SAFETY: both buffers are at least the size the probe asked for, and their
    // pointers are valid for that whole length.
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast::<core::ffi::c_void>(),
            &raw mut sid_bytes,
            domain.as_mut_ptr(),
            &raw mut domain_chars,
            &raw mut kind,
        )
    };
    if ok == 0 {
        return Err(BindRefusal::classify(last_error().get(), false));
    }
    // SAFETY: `sid` holds the `SID` the OS just wrote and outlives the call.
    unsafe { sid_to_string(sid.as_mut_ptr().cast::<core::ffi::c_void>()) }
        .ok_or(BindRefusal::Refused)
}

/// This process's own user SID.
///
/// `super::listener::serve` reads it for its MI-A3 start line — *"which
/// identity wrote this DACL"* is the first question asked when a client is
/// refused, and a service running as the wrong account answers it in one field.
///
/// # Errors
///
/// [`Failure`] when the token cannot be opened or queried.
pub fn own_user_sid() -> Result<String, Failure> {
    let token = own_token()?;
    // SAFETY: `token` was opened with `TOKEN_QUERY` and is live until dropped.
    unsafe { super::token::user_sid(token.get()) }
}

/// The **enabled** groups in this process's own token.
///
/// Beside [`own_user_sid`] because it is the same three calls on the same token.
/// Its caller is `tests/mgmt_listener.rs`: the production principals are local
/// groups the MSI creates, which no CI runner has, so the Windows integration
/// test injects principals this host actually carries — which CD-2 already makes
/// the supported way to supply them.
///
/// # Errors
///
/// [`Failure`] when the token cannot be opened or queried.
pub fn own_group_sids() -> Result<Vec<String>, Failure> {
    let token = own_token()?;
    // SAFETY: as above.
    unsafe { super::token::enabled_group_sids(token.get()) }
}

/// This process's own token, opened for reading.
fn own_token() -> Result<OwnedHandle, Failure> {
    let mut handle: HANDLE = std::ptr::null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle needing no close, and
    // `handle` is a live, correctly-typed out-parameter this frame owns.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut handle) };
    if ok == 0 {
        return Err(Failure::of("OpenProcessToken"));
    }
    OwnedHandle::new(handle).ok_or_else(|| Failure::of("OpenProcessToken"))
}

/// A security descriptor converted from SDDL, released on drop.
///
/// Owned rather than borrowed for the same reason [`OwnedHandle`] is: every path
/// out of [`instance`] is a `?`, and a hand-written `LocalFree` at each of them
/// is one chance per path to miss one.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Descriptor {
    /// Converts [`crate::mi::dacl::pipe_sddl`]'s output.
    fn from_sddl(sddl: &str) -> Result<Self, BindRefusal> {
        let text = wide(sddl);
        let mut raw: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `text` is a live NUL-terminated buffer for the duration of the
        // call, `raw` is a live out-parameter, and a null size pointer is the
        // documented "do not report the size".
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &raw mut raw,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || raw.is_null() {
            return Err(BindRefusal::classify(last_error().get(), false));
        }
        Ok(Self(raw))
    }

    /// The `lpSecurityAttributes` `CreateNamedPipeW` takes.
    ///
    /// `bInheritHandle` is `FALSE`: an inheritable listening handle would let a
    /// child process this service spawns hold the endpoint open past its own
    /// exit, which is the squatter case one layer down.
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: ATTRIBUTES_LEN,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: `self.0` was allocated by
        // `ConvertStringSecurityDescriptorToSecurityDescriptorW`, whose
        // documented release is `LocalFree`. This type owns it — there is no
        // `Clone` and no constructor that borrows — so no other owner frees it.
        unsafe {
            LocalFree(self.0.cast());
        }
    }
}

/// One pipe instance, with MI-A3's DACL.
///
/// The descriptor is rendered per instance rather than held across the accept
/// loop, and that is not waste: `CreateNamedPipeW` copies the descriptor into the
/// object, so nothing outlives this function — which is what keeps the accept
/// loop's future free of a raw pointer and therefore `Send` without an
/// `unsafe impl`.
///
/// `pub` because it is also the seam `tests/mgmt_listener.rs` binds through: the
/// production principals are local groups the MSI creates, so a CI runner
/// exercises this exact function with a descriptor built from its own token.
///
/// # Errors
///
/// [`BindRefusal`] classified from the status Windows reported.
pub fn instance(name: &str, sddl: &str, first: bool) -> Result<NamedPipeServer, BindRefusal> {
    let descriptor = Descriptor::from_sddl(sddl)?;
    let mut attributes = descriptor.attributes();
    let mut options = ServerOptions::new();
    options
        // ADR-0017 §11.2: so a squatter fails loudly instead of this service
        // quietly becoming the second server on somebody else's pipe.
        .first_pipe_instance(first)
        // **Mandatory** — without it the pipe is reachable over SMB.
        .reject_remote_clients(true)
        // §11.2: "Message mode gives the same boundary property as
        // `SOCK_SEQPACKET`."
        .pipe_mode(PipeMode::Message);
    // SAFETY: `attributes` is a live, fully-initialised `SECURITY_ATTRIBUTES`
    // whose descriptor pointer is valid until `descriptor` is dropped at the end
    // of this function — after `CreateNamedPipeW` has returned and copied the
    // descriptor into the object.
    let created = unsafe {
        options.create_with_security_attributes_raw(
            name,
            std::ptr::from_mut(&mut attributes).cast::<core::ffi::c_void>(),
        )
    };
    created.map_err(|error| BindRefusal::classify(status_of(&error), first))
}

/// The raw status behind an `io::Error`, in the one number space
/// [`BindRefusal::classify`] reads.
fn status_of(error: &std::io::Error) -> u32 {
    error.raw_os_error().map_or(0, |code| {
        twinvpn_platform_windows::oserr::Win32Error::from_i32(code).get()
    })
}
