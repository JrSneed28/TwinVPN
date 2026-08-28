//! The Wintun and IP Helper syscall shim. **`#[cfg(windows)]`, and never
//! executed.**
//!
//! **Authority:** `docs/networking.md` §5.3's Windows row; ADR-0016 §10 (the
//! installer owns the driver, the service compares versions), §11.9
//! (`ProcessImageLoadPolicy{NoRemoteImages, PreferSystem32}`); ADR-0018 §11.15's
//! Windows row ("WinTun send/receive rings, called from
//! `twinvpn-platform-windows`; **0** ABI crossings per packet"), DP-4;
//! ADR-0010 R1.
//!
//! `make cross-check` type-checks this against the real `windows-sys` for
//! `x86_64-pc-windows-msvc` with `-D warnings`. That is a compile proof and is
//! **not** a behaviour proof: no line below has ever run.
//!
//! # Why the entry points are resolved by hand
//!
//! Wintun ships no import library this build can link, and ADR-0016 §10 wants a
//! *missing* DLL to be a named startup refusal rather than a loader dialog. So
//! [`WintunDriver::load`] opens the DLL with `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`
//! — the application directory and nothing else, which is
//! `ProcessImageLoadPolicy`'s intention at the call site — and resolves each
//! entry point with `GetProcAddress`. A DLL that loads but lacks an entry point
//! is `ERROR_PROC_NOT_FOUND`, which [`crate::oserr`] maps to
//! `PLATFORM.OS_UNSUPPORTED`: the remediation is "the shipped Wintun is the
//! wrong version", which is a different sentence from "it is missing".
//!
//! # The MTU is set on both families, in one call site
//!
//! Wintun has no MTU of its own; the interface MTU is IP Helper's
//! `MIB_IPINTERFACE_ROW.NlMtu`, and that row is **per family**. So
//! [`WintunDriver::set_mtu`] loops over `AF_INET` and `AF_INET6` from one array
//! and reports the first failure — ADR-0010 R1's "an implementation that can
//! install one family's … without the other's is non-conforming", applied to the
//! one setting where forgetting v6 is a silently truncated tunnel rather than a
//! visible one.

use core::ffi::c_void;

use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError, FARPROC, HANDLE, HMODULE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetIpInterfaceEntry, SetIpInterfaceEntry, MIB_IPINTERFACE_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
};

use twinvpn_platform::PlatformError;

use super::{TunnelDriver, ERROR_NO_MORE_ITEMS, TUNNEL_TYPE, WINTUN_DLL};
use crate::oserr::{self, Context, Win32Error};
use crate::route::InterfaceLuid;

/// The largest packet the receive path will accept from the ring.
///
/// **A bound recorded as one.** `ownership.md` §6 rule 10: the length comes from
/// the driver, so it is bounded before anything is done with it. Wintun's own
/// maximum is 0xFFFF and no overlay MTU approaches it; a larger value is a
/// malfunctioning driver rather than a jumbo frame.
const MAX_PACKET_BYTES: u32 = 0xFFFF;

/// The two families a `MIB_IPINTERFACE_ROW` can name. **One array, so there is
/// no place to forget one** (ADR-0010 R1).
const BOTH_FAMILIES: [ADDRESS_FAMILY; 2] = [AF_INET, AF_INET6];

// The Wintun C entry points, in `wintun.h`'s own shapes.
type CreateAdapterFn =
    unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> *mut c_void;
type OpenAdapterFn = unsafe extern "system" fn(*const u16) -> *mut c_void;
type CloseAdapterFn = unsafe extern "system" fn(*mut c_void);
type GetAdapterLuidFn = unsafe extern "system" fn(*mut c_void, *mut NET_LUID_LH);
type GetRunningDriverVersionFn = unsafe extern "system" fn() -> u32;
type StartSessionFn = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
type EndSessionFn = unsafe extern "system" fn(*mut c_void);
type ReceivePacketFn = unsafe extern "system" fn(*mut c_void, *mut u32) -> *mut u8;
type ReleaseReceivePacketFn = unsafe extern "system" fn(*mut c_void, *const u8);
type AllocateSendPacketFn = unsafe extern "system" fn(*mut c_void, u32) -> *mut u8;
type SendPacketFn = unsafe extern "system" fn(*mut c_void, *const u8);

/// The dynamically-loaded Wintun.
///
/// The `HMODULE` is held for the process's life and deliberately **not** freed
/// on drop: the resolved function pointers are borrowed from it, and a driver
/// that unloaded the DLL while a session was running would turn an in-flight
/// packet into a jump into unmapped memory. [`WintunDriver::unload`] exists for
/// the uninstall path, which is the only caller that knows nothing is running.
#[derive(Debug)]
pub struct WintunDriver {
    module: HMODULE,
    create_adapter: CreateAdapterFn,
    open_adapter: OpenAdapterFn,
    close_adapter: CloseAdapterFn,
    get_adapter_luid: GetAdapterLuidFn,
    get_running_driver_version: GetRunningDriverVersionFn,
    start_session: StartSessionFn,
    end_session: EndSessionFn,
    receive_packet: ReceivePacketFn,
    release_receive_packet: ReleaseReceivePacketFn,
    allocate_send_packet: AllocateSendPacketFn,
    send_packet: SendPacketFn,
}

// SAFETY: the fields are a module handle and eleven function pointers, all of
// which are immutable for the life of the value. Wintun's own documentation
// makes the session API thread-safe for one reader and one writer, which is how
// `TunnelDevice`'s `read_packet` and `write_packet` are used. Nothing here is
// interior-mutable.
unsafe impl Send for WintunDriver {}
// SAFETY: as above.
unsafe impl Sync for WintunDriver {}

/// The last `GetLastError`, as a named condition.
fn last_error(call: &'static str) -> PlatformError {
    // SAFETY: `GetLastError` reads this thread's own last-error value and takes
    // no pointer.
    let code = unsafe { GetLastError() };
    oserr::from_status(Win32Error(code), call, Context::TunnelDevice)
}

/// A NUL-terminated UTF-16 buffer for a `PCWSTR` parameter.
///
/// Returned owned so the caller keeps it alive across the call: handing
/// `as_ptr()` of a temporary to a `system` function is the classic
/// use-after-free in this FFI.
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Resolves one entry point, or names the one that is missing.
///
/// # Safety
///
/// `module` must be a loaded module handle, and `T` must be the exact
/// `extern "system"` signature `wintun.h` declares for `name`. A mismatch is
/// undefined behaviour at the first call, which is why every use below sits
/// beside the declaration it transcribes.
unsafe fn resolve<T: Copy>(module: HMODULE, name: &[u8]) -> Result<T, PlatformError> {
    debug_assert_eq!(core::mem::size_of::<T>(), core::mem::size_of::<FARPROC>());
    // SAFETY: `module` is the caller's loaded handle; `name` is a NUL-terminated
    // byte string this file supplies as a literal. `GetProcAddress` retains no
    // pointer into it.
    let symbol = unsafe { GetProcAddress(module, name.as_ptr()) };
    let Some(symbol) = symbol else {
        return Err(oserr::from_status(
            Win32Error(oserr::ERROR_PROC_NOT_FOUND),
            "GetProcAddress(wintun)",
            Context::TunnelDevice,
        ));
    };
    // SAFETY: the caller's contract — `T` is the declared signature, and a
    // `FARPROC` and a function pointer are the same width, asserted above.
    Ok(unsafe { core::mem::transmute_copy::<FARPROC, T>(&Some(symbol)) })
}

impl WintunDriver {
    /// Loads `wintun.dll` from the application directory and resolves every
    /// entry point.
    ///
    /// # Errors
    ///
    /// `PLATFORM.ADAPTER_UNAVAILABLE` where the DLL is absent
    /// (`ERROR_MOD_NOT_FOUND` — a packaging failure, not a user's problem), and
    /// `PLATFORM.OS_UNSUPPORTED` where it loads but is the wrong version
    /// (`ERROR_PROC_NOT_FOUND`, or `ERROR_BAD_EXE_FORMAT` for a 32-bit DLL
    /// beside a 64-bit service). The two have different remediations, which is
    /// why they are different codes.
    pub fn load() -> Result<Self, PlatformError> {
        let name = wide(WINTUN_DLL);
        // SAFETY: `name` is a live NUL-terminated UTF-16 buffer that outlives
        // the call; the file handle is the documented null; the flag restricts
        // the search to the application directory, so no DLL on the search path
        // can be loaded in its place.
        let module = unsafe {
            LoadLibraryExW(
                name.as_ptr(),
                core::ptr::null_mut::<c_void>() as HANDLE,
                LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
            )
        };
        if module.is_null() {
            return Err(last_error("LoadLibraryExW(wintun.dll)"));
        }
        // SAFETY: `module` is the handle just loaded, and each signature below
        // is transcribed from `wintun.h`'s declaration of that name.
        let driver = unsafe {
            Self {
                module,
                create_adapter: resolve(module, b"WintunCreateAdapter\0")?,
                open_adapter: resolve(module, b"WintunOpenAdapter\0")?,
                close_adapter: resolve(module, b"WintunCloseAdapter\0")?,
                get_adapter_luid: resolve(module, b"WintunGetAdapterLUID\0")?,
                get_running_driver_version: resolve(module, b"WintunGetRunningDriverVersion\0")?,
                start_session: resolve(module, b"WintunStartSession\0")?,
                end_session: resolve(module, b"WintunEndSession\0")?,
                receive_packet: resolve(module, b"WintunReceivePacket\0")?,
                release_receive_packet: resolve(module, b"WintunReleaseReceivePacket\0")?,
                allocate_send_packet: resolve(module, b"WintunAllocateSendPacket\0")?,
                send_packet: resolve(module, b"WintunSendPacket\0")?,
            }
        };
        Ok(driver)
    }

    /// Unloads the DLL.
    ///
    /// Consumes the driver, so no function pointer can outlive the module it
    /// came from. For the uninstall path only — ADR-0016 PS-21 step 6 — where
    /// the caller knows no session is running.
    pub fn unload(self) {
        // SAFETY: `self.module` is the handle `load` obtained and has not been
        // freed; consuming `self` guarantees no resolved pointer is used after.
        unsafe {
            FreeLibrary(self.module);
        }
    }
}

/// One `MIB_IPINTERFACE_ROW` read, modified and written back.
///
/// Read-modify-write rather than write-only: `SetIpInterfaceEntry` rejects a row
/// whose other fields are zero, and PS-6's "restore before mutate" wants the
/// prior value to have been seen rather than assumed.
fn set_family_mtu(
    luid: InterfaceLuid,
    family: ADDRESS_FAMILY,
    mtu: u32,
) -> Result<(), PlatformError> {
    let mut row = MIB_IPINTERFACE_ROW {
        Family: family,
        InterfaceLuid: NET_LUID_LH { Value: luid.0 },
        ..Default::default()
    };
    // SAFETY: `row` is a live, uniquely-borrowed, fully-initialised row of the
    // declared type; `GetIpInterfaceEntry` fills it in place and retains no
    // pointer.
    let rc = unsafe { GetIpInterfaceEntry(&raw mut row) };
    if rc != 0 {
        return Err(oserr::from_status(
            Win32Error(rc),
            "GetIpInterfaceEntry",
            Context::RouteProgram,
        ));
    }
    row.NlMtu = mtu;
    // `SitePrefixLength` must be cleared on a write or IP Helper rejects the
    // row: `GetIpInterfaceEntry` returns the read-only value it uses
    // internally, and the documented write form is zero. A quirk of the API,
    // recorded here because it is invisible at the call site.
    row.SitePrefixLength = 0;
    // SAFETY: as above — the same live row, now with one field changed.
    let rc = unsafe { SetIpInterfaceEntry(&raw mut row) };
    if rc != 0 {
        return Err(oserr::from_status(
            Win32Error(rc),
            "SetIpInterfaceEntry(NlMtu)",
            Context::RouteProgram,
        ));
    }
    Ok(())
}

impl TunnelDriver for WintunDriver {
    fn open_adapter(&self, name: &str) -> Result<Option<u64>, PlatformError> {
        let name = wide(name);
        // SAFETY: `name` is a live NUL-terminated UTF-16 buffer that outlives
        // the call; the entry point is the one `load` resolved for this
        // signature.
        let adapter = unsafe { (self.open_adapter)(name.as_ptr()) };
        if adapter.is_null() {
            // "No such adapter" is the ordinary first-start state and is
            // reported as `Ok(None)`, not as an error — the distinction the
            // reclaim path turns on. Any other status is a real failure.
            // SAFETY: reads this thread's last-error value only.
            let code = unsafe { GetLastError() };
            return if code == oserr::ERROR_FILE_NOT_FOUND || code == oserr::ERROR_NOT_FOUND {
                Ok(None)
            } else {
                Err(oserr::from_status(
                    Win32Error(code),
                    "WintunOpenAdapter",
                    Context::TunnelDevice,
                ))
            };
        }
        Ok(Some(adapter as u64))
    }

    fn create_adapter(&self, name: &str) -> Result<u64, PlatformError> {
        let name = wide(name);
        let kind = wide(TUNNEL_TYPE);
        // SAFETY: both buffers are live and NUL-terminated and outlive the call;
        // the requested-GUID pointer is the documented null, which lets Wintun
        // derive a deterministic GUID from the name — which is what
        // `docs/networking.md` §5.3's "named and GUID-stamped deterministically
        // per install" asks for.
        let adapter =
            unsafe { (self.create_adapter)(name.as_ptr(), kind.as_ptr(), core::ptr::null()) };
        if adapter.is_null() {
            // `ERROR_ACCESS_DENIED` here is `Context::TunnelDevice`, which
            // `oserr` maps to `PLATFORM.VPN_PERMISSION_DENIED`: the remediation
            // is "install the service", not "run it as Administrator by hand".
            return Err(last_error("WintunCreateAdapter"));
        }
        Ok(adapter as u64)
    }

    fn close_adapter(&self, adapter: u64) {
        // SAFETY: `adapter` is a handle this driver returned from
        // `open_adapter` or `create_adapter` and the caller owns; the device
        // above removes it from its table before calling, so it is closed once.
        unsafe { (self.close_adapter)(adapter as *mut c_void) }
    }

    fn adapter_luid(&self, adapter: u64) -> Result<InterfaceLuid, PlatformError> {
        let mut luid = NET_LUID_LH { Value: 0 };
        // SAFETY: `adapter` is a live adapter handle; `luid` is a live,
        // uniquely-borrowed out-parameter of the declared type. The call writes
        // eight bytes and retains no pointer.
        unsafe { (self.get_adapter_luid)(adapter as *mut c_void, &raw mut luid) };
        // SAFETY: `NET_LUID_LH` is a union of a `u64` and a bitfield of the same
        // width; reading the `Value` arm is reading the eight bytes the call
        // just wrote, in the union's own declared representation.
        let value = unsafe { luid.Value };
        if value == 0 {
            // LUID 0 is never assigned. Wintun reports failure by leaving the
            // out-parameter untouched, so this is the only way to notice.
            return Err(oserr::unavailable("WintunGetAdapterLUID"));
        }
        Ok(InterfaceLuid(value))
    }

    fn start_session(&self, adapter: u64, capacity: u32) -> Result<u64, PlatformError> {
        // SAFETY: `adapter` is a live adapter handle; `capacity` is the
        // power-of-two ring size `super::RING_CAPACITY` asserts is in Wintun's
        // declared range.
        let session = unsafe { (self.start_session)(adapter as *mut c_void, capacity) };
        if session.is_null() {
            return Err(last_error("WintunStartSession"));
        }
        Ok(session as u64)
    }

    fn end_session(&self, session: u64) {
        // SAFETY: `session` is a handle `start_session` returned and the device
        // above removes from its table before calling, so it is ended once.
        unsafe { (self.end_session)(session as *mut c_void) }
    }

    fn receive(&self, session: u64, buf: &mut [u8]) -> Result<Option<usize>, PlatformError> {
        let session = session as *mut c_void;
        let mut size: u32 = 0;
        // SAFETY: `session` is a live session handle; `size` is a live
        // out-parameter. The returned pointer, when non-null, is valid for
        // `size` bytes until `WintunReleaseReceivePacket` is called on it, which
        // happens on every path below.
        let packet = unsafe { (self.receive_packet)(session, &raw mut size) };
        if packet.is_null() {
            // SAFETY: reads this thread's last-error value only.
            let code = unsafe { GetLastError() };
            return if code == ERROR_NO_MORE_ITEMS {
                // An empty ring is not an error; it is the ordinary state
                // between packets, and reporting it as one would make an idle
                // tunnel look broken.
                Ok(None)
            } else {
                Err(oserr::from_status(
                    Win32Error(code),
                    "WintunReceivePacket",
                    Context::TunnelDevice,
                ))
            };
        }
        if size > MAX_PACKET_BYTES {
            // Release before refusing: a bound that leaked the ring slot it
            // refused would wedge the ring after 4 MiB of malformed packets.
            // SAFETY: `packet` is the pointer just returned and not yet
            // released.
            unsafe { (self.release_receive_packet)(session, packet) };
            return Err(oserr::unavailable("WintunReceivePacket.length"));
        }
        let length = size as usize;
        let copied = length.min(buf.len());
        // SAFETY: `packet` is valid for `size` bytes and `copied <= size`;
        // `buf` is a live, uniquely-borrowed slice and `copied <= buf.len()`.
        // The two regions cannot overlap: one is the driver's ring and the
        // other is the caller's buffer.
        unsafe { core::ptr::copy_nonoverlapping(packet, buf.as_mut_ptr(), copied) };
        // SAFETY: as above, and `packet` is not used after this.
        unsafe { (self.release_receive_packet)(session, packet) };
        // A short read is reported as what was copied. `Datagram::truncated`
        // is the seam's mechanism for saying so on a socket; `read_packet` has
        // no such field, so a caller must size `buf` at the MTU — which the
        // core does, because it is the one that set the MTU.
        Ok(Some(copied))
    }

    fn send(&self, session: u64, packet: &[u8]) -> Result<usize, PlatformError> {
        let session = session as *mut c_void;
        let length = u32::try_from(packet.len()).unwrap_or(u32::MAX);
        if length > MAX_PACKET_BYTES {
            return Err(oserr::unavailable("WintunAllocateSendPacket.length"));
        }
        // SAFETY: `session` is a live session handle. The returned pointer, when
        // non-null, is valid for `length` bytes until `WintunSendPacket` hands
        // it back.
        let slot = unsafe { (self.allocate_send_packet)(session, length) };
        if slot.is_null() {
            // A full ring reports `ERROR_BUFFER_OVERFLOW`, which `oserr` maps to
            // its default arm; the caller retries under the core's own backoff.
            return Err(last_error("WintunAllocateSendPacket"));
        }
        // SAFETY: `slot` is valid for exactly `packet.len()` bytes, `packet` is
        // a live slice of that length, and the two cannot overlap — one is the
        // driver's ring.
        unsafe { core::ptr::copy_nonoverlapping(packet.as_ptr(), slot, packet.len()) };
        // SAFETY: `slot` is the allocation just filled and is not used after.
        unsafe { (self.send_packet)(session, slot) };
        Ok(packet.len())
    }

    fn set_mtu(&self, luid: InterfaceLuid, mtu: u32) -> Result<(), PlatformError> {
        // One loop over both families. ADR-0010 R1: an MTU set on v4 alone is a
        // v6 path that black-holes at the first full-size packet, which is the
        // asymmetry the rule exists to forbid.
        for family in BOTH_FAMILIES {
            set_family_mtu(luid, family, mtu)?;
        }
        Ok(())
    }

    fn running_version(&self) -> u32 {
        // SAFETY: takes no argument and returns a plain integer; `0` is the
        // documented "no driver loaded".
        unsafe { (self.get_running_driver_version)() }
    }
}
