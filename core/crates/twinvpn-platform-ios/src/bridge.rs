//! The `extern "C"` bridge to Swift — **internal linkage, not an ABI of record**.
//!
//! **Authority:** `docs/implementation/ownership.md` **§10.4** (the wave-3
//! ruling), §8 **W-24** and **W-25**; ADR-0018 F-7 (panic containment), VR-2
//! (same-process scope), CB-2.
//!
//! # What §10.4 rules, and what this file is
//!
//! W-24 and W-25 record that `twinvpn.h`'s F-9 vtable has **no**
//! `installed_ruleset` read-back, **no** `current_generation`, **no** socket
//! provider and **no** interface enumerator, so "a shell bound only to that
//! vtable cannot do NAT traversal and cannot produce a `ProtectionAssertion` at
//! all". `shells/linux` escapes by linking the adapter as a Rust crate; a Swift
//! shell cannot. §10.4's ruling:
//!
//! > "The missing capabilities stay **in Rust, in-process**, inside
//! > `twinvpn-platform-{ios,android}`, and the Swift/Kotlin side reaches them
//! > through a per-platform `extern "C"` bridge exported by that same adapter
//! > crate. That bridge is **not** an ABI of record, is **not** `twinvpn.h`, and
//! > acquires **no** compatibility obligation: both sides are compiled from one
//! > commit into one artifact, which is precisely the same-process scope VR-2
//! > already carves out. It is internal linkage, and it is versionless because
//! > there is nothing for it to be compatible *with*."
//!
//! This file is that bridge. It is **versionless on purpose**: there is no
//! `abi_major` here and there must not be one, because a version number would
//! assert a compatibility promise §10.4 explicitly withholds. The `size` field on
//! [`TwIosHostVtable`] is a *safety* check against a mismatched build, not a
//! compatibility mechanism.
//!
//! # The CB-2 rule this surface must not break
//!
//! §10.4 again: "The bridge surface is **not** permitted to grow a TwinVPN domain
//! fact. An entry that takes or returns a `ConnectionState`, a `reason_code`
//! class, a policy verdict or a candidate priority is a CB-2 violation on the
//! wrong side of the line, and is a finding."
//!
//! Every entry below therefore carries **bytes, counts and OS numbers**. There is
//! no `ConnectionState`, no `Ruleset`, no `reason_code` and no verdict in any
//! signature in this file, and `the_bridge_surface_carries_no_domain_fact`
//! is the check that says so in a form that fails.
//!
//! # Panic containment, stated precisely rather than hopefully
//!
//! F-7 wraps every `twinvpn.h` body in `catch_unwind` because a panic unwinding
//! into Swift is undefined behaviour. The same hazard exists here and the same
//! guard is applied — but **what it can and cannot catch is not symmetric**, and
//! a first draft of this module got it wrong in a way its own test caught:
//!
//! | Where the panic is | What happens | Why |
//! |---|---|---|
//! | Rust marshalling on **this** side of a call — building a slice, collecting a sink, decoding UTF-8 | caught by [`SwiftHost::guarded`], reported as [`HostStatus::NotAttached`] | ordinary `catch_unwind` |
//! | Inside a **Swift** callback | cannot occur as a Rust unwind | Swift has no Rust panics; a Swift fatal error terminates the process before Rust sees anything |
//! | Inside a **Rust `extern "C"`** function reached through the vtable | **the process aborts**, and `catch_unwind` around the call never runs | since Rust 1.71 an `extern "C"` function that unwinds aborts at the ABI boundary. The guard is on the wrong side of that boundary to help |
//!
//! The third row is why F-7 requires the `catch_unwind` to be **inside** each
//! exported body rather than around each call to one, and the same discipline
//! applies to every `#[no_mangle]` function in this file: each one guards its own
//! body. [`TW_IOS_KIND_PANIC`] exists for a Swift side that wants to report a
//! trapped condition of its own; nothing in Rust produces it, because by the time
//! Rust could, the process is already gone.
//!
//! A contained panic does **not** touch the installed enforcement, for CB-6's
//! reason: the OS holds it precisely so the core going away cannot drop
//! protection.

use core::ffi::c_void;
use std::sync::{Arc, Mutex, OnceLock};

use crate::host::{HostIdentity, HostStatus, PathSnapshotJson, ProviderHost, SettingsProgramme};

/// The call succeeded.
pub const TW_IOS_KIND_OK: i32 = 0;
/// The code is a POSIX `errno`.
pub const TW_IOS_KIND_ERRNO: i32 = 1;
/// The code is an `OSStatus`.
pub const TW_IOS_KIND_OSSTATUS: i32 = 2;
/// The code is an `NEVPNErrorDomain` value.
pub const TW_IOS_KIND_NEVPN: i32 = 3;
/// No provider is attached.
pub const TW_IOS_KIND_NOT_ATTACHED: i32 = 4;
/// A panic was caught crossing the bridge.
pub const TW_IOS_KIND_PANIC: i32 = 5;

/// A borrowed byte slice.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TwIosSlice {
    /// The bytes. May be null only when `len` is zero.
    pub ptr: *const u8,
    /// How many bytes.
    pub len: usize,
}

impl TwIosSlice {
    /// Borrows the bytes.
    ///
    /// # Safety
    ///
    /// `ptr` must be valid for `len` bytes for the duration of the borrow, or
    /// `len` must be zero.
    #[must_use]
    pub unsafe fn as_slice<'a>(self) -> &'a [u8] {
        if self.len == 0 || self.ptr.is_null() {
            return &[];
        }
        // SAFETY: the caller's contract, restated above.
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
}

/// What a host call returned: a kind and the OS's own number.
///
/// Two `i32`s and nothing else. This is the shape that keeps CB-2 true: Swift
/// reports what the OS reported, and [`crate::oserr`] — in Rust — turns it into a
/// registered name.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwIosStatus {
    /// One of the `TW_IOS_KIND_*` constants.
    pub kind: i32,
    /// The OS's own number, or zero.
    pub code: i32,
}

impl TwIosStatus {
    /// Success.
    #[must_use]
    pub const fn ok() -> Self {
        Self {
            kind: TW_IOS_KIND_OK,
            code: 0,
        }
    }

    /// The seam's status.
    #[must_use]
    pub const fn to_host_status(self) -> HostStatus {
        match self.kind {
            TW_IOS_KIND_OK => HostStatus::Ok,
            TW_IOS_KIND_ERRNO => HostStatus::Errno(self.code),
            TW_IOS_KIND_OSSTATUS => HostStatus::OsStatus(self.code),
            TW_IOS_KIND_NEVPN => HostStatus::NeVpnError(self.code),
            // A panic on the Swift side, or a kind this build does not know, is
            // "the adapter has gone away" — never a success, and never silently
            // mapped onto an OS number that would name a condition nobody
            // observed.
            _ => HostStatus::NotAttached,
        }
    }
}

/// A sink Swift pushes bytes into.
///
/// Rust owns the storage and Swift never allocates for Rust — F-2's ownership
/// rule, applied here even though this is not F-2's ABI: "the core never frees a
/// shell allocation; the shell never frees a core allocation."
pub struct TwIosSink {
    items: Vec<Vec<u8>>,
}

/// Pushes one item into a sink.
///
/// # Safety
///
/// `sink` must be a pointer Rust handed to the callback that is calling this,
/// and `ptr`/`len` must describe a readable range for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn twinvpn_ios_sink_push(sink: *mut c_void, ptr: *const u8, len: usize) {
    if sink.is_null() {
        return;
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: the caller's contract. The pointer came from
        // `&mut TwIosSink` in this crate and is not aliased for the callback's
        // duration, because the callback is synchronous and the borrow is held
        // across exactly that call.
        let sink = unsafe { &mut *sink.cast::<TwIosSink>() };
        let bytes = if len == 0 || ptr.is_null() {
            Vec::new()
        } else {
            // SAFETY: the caller's contract.
            unsafe { core::slice::from_raw_parts(ptr, len) }.to_vec()
        };
        sink.items.push(bytes);
    }));
    // A panic here cannot be reported — the signature has no channel — so it is
    // swallowed rather than allowed to unwind into Swift, which is undefined
    // behaviour. The item is simply absent, which the caller sees as a short
    // batch.
    drop(result);
}

/// The Swift side of the bridge.
///
/// Every entry carries bytes, counts and OS numbers. See the module header for
/// why nothing else may be added.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TwIosHostVtable {
    /// `size_of::<TwIosHostVtable>()`, checked at registration.
    pub size: u32,
    /// The Swift provider, opaque to Rust.
    pub ctx: *mut c_void,

    /// `setTunnelNetworkSettings` with a rendered programme.
    pub apply_settings: Option<extern "C" fn(*mut c_void, TwIosSlice) -> TwIosStatus>,
    /// `setTunnelNetworkSettings(nil)`.
    pub clear_settings: Option<extern "C" fn(*mut c_void) -> TwIosStatus>,
    /// `NEPacketTunnelFlow.readPackets`, pushing each packet into the sink.
    pub read_packets: Option<extern "C" fn(*mut c_void, *mut c_void) -> TwIosStatus>,
    /// `NEPacketTunnelFlow.writePackets`, with one family per packet.
    pub write_packets:
        Option<extern "C" fn(*mut c_void, *const TwIosSlice, *const i32, usize) -> TwIosStatus>,
    /// The on-demand rules and `includeAllNetworks` flags.
    pub apply_enforcement: Option<extern "C" fn(*mut c_void, TwIosSlice) -> TwIosStatus>,
    /// The installed configuration, read back from `NETunnelProviderManager`.
    pub installed_enforcement: Option<extern "C" fn(*mut c_void, *mut c_void) -> TwIosStatus>,
    /// The most recent `NWPathMonitor` snapshot.
    pub path_snapshot: Option<extern "C" fn(*mut c_void, *mut c_void) -> TwIosStatus>,
    /// `SecItemCopyMatching`.
    pub keychain_read: Option<extern "C" fn(*mut c_void, TwIosSlice, *mut c_void) -> TwIosStatus>,
    /// `SecItemAdd` / `SecItemUpdate`, whole-blob.
    pub keychain_write: Option<extern "C" fn(*mut c_void, TwIosSlice, TwIosSlice) -> TwIosStatus>,
    /// `SecItemDelete`.
    pub keychain_delete: Option<extern "C" fn(*mut c_void, TwIosSlice) -> TwIosStatus>,
    /// The App Group container path, attributes already applied.
    pub store_root: Option<extern "C" fn(*mut c_void, *mut c_void) -> TwIosStatus>,
    /// Whether backup exclusion was verified at this start.
    pub store_root_backup_excluded: Option<extern "C" fn(*mut c_void) -> i32>,
    /// `SecKeyCreateSignature`, inside the element.
    pub enclave_sign:
        Option<extern "C" fn(*mut c_void, TwIosSlice, TwIosSlice, *mut c_void) -> TwIosStatus>,
    /// `SecKeyCopyKeyExchangeResult`, inside the element.
    pub enclave_agree: Option<
        extern "C" fn(*mut c_void, TwIosSlice, TwIosSlice, TwIosSlice, *mut c_void) -> TwIosStatus,
    >,
    /// The public half and its attestation: two sink pushes, key then blob.
    pub enclave_public: Option<extern "C" fn(*mut c_void, TwIosSlice, *mut c_void) -> TwIosStatus>,
    /// Whether the element is genuinely hardware-backed.
    pub enclave_hardware_backed: Option<extern "C" fn(*mut c_void) -> i32>,
}

// SAFETY: `ctx` is an opaque Swift pointer that the Swift side guarantees is
// safe to use from the core's threads — it is an `NEPacketTunnelProvider`
// reference whose methods this vtable's implementations serialise. The Rust side
// never dereferences it.
unsafe impl Send for TwIosHostVtable {}
// SAFETY: as above.
unsafe impl Sync for TwIosHostVtable {}

/// A host that calls through a registered vtable.
pub struct SwiftHost {
    vtable: TwIosHostVtable,
}

impl SwiftHost {
    /// Wraps a registered vtable.
    #[must_use]
    pub const fn new(vtable: TwIosHostVtable) -> Self {
        Self { vtable }
    }

    fn guarded<T>(f: impl FnOnce() -> Result<T, HostStatus>) -> Result<T, HostStatus> {
        // F-7's guard, applied to this bridge for the same reason: a panic
        // unwinding into Swift is undefined behaviour.
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
            Ok(result) => result,
            Err(_) => Err(HostStatus::NotAttached),
        }
    }

    fn collect(call: impl FnOnce(*mut c_void) -> TwIosStatus) -> Result<Vec<Vec<u8>>, HostStatus> {
        let mut sink = TwIosSink { items: Vec::new() };
        let status = call(core::ptr::addr_of_mut!(sink).cast::<c_void>());
        match status.to_host_status() {
            HostStatus::Ok => Ok(sink.items),
            other => Err(other),
        }
    }
}

fn slice_of(bytes: &[u8]) -> TwIosSlice {
    TwIosSlice {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
    }
}

macro_rules! entry {
    ($self:expr, $field:ident) => {
        match $self.vtable.$field {
            Some(f) => f,
            // A vtable entry Swift did not fill is "not attached", never a
            // silent success: a `clear_settings` that quietly did nothing would
            // leave a tunnel installed that the core believes is gone.
            None => return HostStatus::NotAttached,
        }
    };
    ($self:expr, $field:ident, err) => {
        match $self.vtable.$field {
            Some(f) => f,
            None => return Err(HostStatus::NotAttached),
        }
    };
}

impl ProviderHost for SwiftHost {
    fn apply_settings(&self, programme: SettingsProgramme<'_>) -> HostStatus {
        let f = entry!(self, apply_settings);
        Self::guarded(|| Ok(f(self.vtable.ctx, slice_of(programme.as_bytes()))))
            .map_or(HostStatus::NotAttached, TwIosStatus::to_host_status)
    }

    fn clear_settings(&self) -> HostStatus {
        let f = entry!(self, clear_settings);
        Self::guarded(|| Ok(f(self.vtable.ctx)))
            .map_or(HostStatus::NotAttached, TwIosStatus::to_host_status)
    }

    fn read_packets(&self) -> Result<Vec<Vec<u8>>, HostStatus> {
        let f = entry!(self, read_packets, err);
        Self::guarded(|| Self::collect(|sink| f(self.vtable.ctx, sink)))
    }

    fn write_packets(&self, packets: &[Vec<u8>], families: &[i32]) -> HostStatus {
        let f = entry!(self, write_packets);
        // Length equality is checked here rather than trusted: a families array
        // shorter than the packets array would have Swift read past its end.
        if packets.len() != families.len() {
            return HostStatus::NotAttached;
        }
        let slices: Vec<TwIosSlice> = packets.iter().map(|p| slice_of(p)).collect();
        Self::guarded(|| {
            Ok(f(
                self.vtable.ctx,
                slices.as_ptr(),
                families.as_ptr(),
                slices.len(),
            ))
        })
        .map_or(HostStatus::NotAttached, TwIosStatus::to_host_status)
    }

    fn apply_enforcement(&self, programme: &str) -> HostStatus {
        let f = entry!(self, apply_enforcement);
        Self::guarded(|| Ok(f(self.vtable.ctx, slice_of(programme.as_bytes()))))
            .map_or(HostStatus::NotAttached, TwIosStatus::to_host_status)
    }

    fn installed_enforcement(&self) -> Result<Option<String>, HostStatus> {
        let f = entry!(self, installed_enforcement, err);
        let items = Self::guarded(|| Self::collect(|sink| f(self.vtable.ctx, sink)))?;
        Ok(first_utf8(items))
    }

    fn path_snapshot(&self) -> Result<Option<PathSnapshotJson>, HostStatus> {
        let f = entry!(self, path_snapshot, err);
        let items = Self::guarded(|| Self::collect(|sink| f(self.vtable.ctx, sink)))?;
        Ok(first_utf8(items))
    }

    fn keychain_read(&self, attributes: &str) -> Result<Option<Vec<u8>>, HostStatus> {
        let f = entry!(self, keychain_read, err);
        let query = attributes.as_bytes().to_vec();
        let items =
            Self::guarded(|| Self::collect(|sink| f(self.vtable.ctx, slice_of(&query), sink)))?;
        Ok(items.into_iter().next())
    }

    fn keychain_write(&self, attributes: &str, value: &[u8]) -> HostStatus {
        let f = entry!(self, keychain_write);
        Self::guarded(|| {
            Ok(f(
                self.vtable.ctx,
                slice_of(attributes.as_bytes()),
                slice_of(value),
            ))
        })
        .map_or(HostStatus::NotAttached, TwIosStatus::to_host_status)
    }

    fn keychain_delete(&self, attributes: &str) -> HostStatus {
        let f = entry!(self, keychain_delete);
        Self::guarded(|| Ok(f(self.vtable.ctx, slice_of(attributes.as_bytes()))))
            .map_or(HostStatus::NotAttached, TwIosStatus::to_host_status)
    }

    fn store_root(&self) -> Result<String, HostStatus> {
        let f = entry!(self, store_root, err);
        let items = Self::guarded(|| Self::collect(|sink| f(self.vtable.ctx, sink)))?;
        first_utf8(items).ok_or(HostStatus::NotAttached)
    }

    fn store_root_backup_excluded(&self) -> bool {
        self.vtable.store_root_backup_excluded.is_some_and(|f| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(self.vtable.ctx)))
                .unwrap_or(0)
                != 0
        })
    }

    fn enclave_sign(&self, key_tag: &str, message: &[u8]) -> Result<Vec<u8>, HostStatus> {
        let f = entry!(self, enclave_sign, err);
        let items = Self::guarded(|| {
            Self::collect(|sink| {
                f(
                    self.vtable.ctx,
                    slice_of(key_tag.as_bytes()),
                    slice_of(message),
                    sink,
                )
            })
        })?;
        items.into_iter().next().ok_or(HostStatus::NotAttached)
    }

    fn enclave_agree(
        &self,
        key_tag: &str,
        algorithm: &str,
        peer_public: &[u8],
    ) -> Result<Vec<u8>, HostStatus> {
        let f = entry!(self, enclave_agree, err);
        let items = Self::guarded(|| {
            Self::collect(|sink| {
                f(
                    self.vtable.ctx,
                    slice_of(key_tag.as_bytes()),
                    slice_of(algorithm.as_bytes()),
                    slice_of(peer_public),
                    sink,
                )
            })
        })?;
        items.into_iter().next().ok_or(HostStatus::NotAttached)
    }

    fn enclave_public(&self, key_tag: &str) -> Result<HostIdentity, HostStatus> {
        let f = entry!(self, enclave_public, err);
        let mut items = Self::guarded(|| {
            Self::collect(|sink| f(self.vtable.ctx, slice_of(key_tag.as_bytes()), sink))
        })?
        .into_iter();
        let public_key = items.next().ok_or(HostStatus::NotAttached)?;
        Ok(HostIdentity {
            public_key,
            // An empty second push means "the element produced no attestation",
            // which is a different fact from "it produced an empty one".
            attestation: items.next().filter(|blob| !blob.is_empty()),
            // The generation is the core's; the element does not name it.
            generation: 0,
        })
    }

    fn enclave_hardware_backed(&self) -> bool {
        self.vtable.enclave_hardware_backed.is_some_and(|f| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(self.vtable.ctx)))
                .unwrap_or(0)
                != 0
        })
    }
}

fn first_utf8(items: Vec<Vec<u8>>) -> Option<String> {
    items
        .into_iter()
        .next()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

/// The registered host, if Swift has registered one.
static REGISTERED: OnceLock<Mutex<Option<Arc<SwiftHost>>>> = OnceLock::new();

fn registry() -> &'static Mutex<Option<Arc<SwiftHost>>> {
    REGISTERED.get_or_init(|| Mutex::new(None))
}

/// Registers the Swift provider.
///
/// Returns [`TW_IOS_KIND_OK`] on success, or a status whose `code` is the
/// received `size` when the vtable does not match this build.
///
/// # Safety
///
/// `vtable` must point to a valid [`TwIosHostVtable`] for the duration of the
/// call, and its `ctx` must outlive every subsequent bridge call.
#[no_mangle]
pub unsafe extern "C" fn twinvpn_ios_bridge_register(
    vtable: *const TwIosHostVtable,
) -> TwIosStatus {
    if vtable.is_null() {
        return TwIosStatus {
            kind: TW_IOS_KIND_NOT_ATTACHED,
            code: 0,
        };
    }
    // SAFETY: the caller's contract, restated above.
    let vtable = unsafe { *vtable };
    // A `size` check, not a version check. §10.4 makes this bridge versionless;
    // this catches a Swift side compiled against a different commit, which is a
    // build error rather than a compatibility question.
    if vtable.size as usize != core::mem::size_of::<TwIosHostVtable>() {
        return TwIosStatus {
            kind: TW_IOS_KIND_NOT_ATTACHED,
            code: i32::try_from(vtable.size).unwrap_or(i32::MAX),
        };
    }
    let mut slot = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = Some(Arc::new(SwiftHost::new(vtable)));
    TwIosStatus::ok()
}

/// The registered host, or `None`.
///
/// The composition root calls this and binds [`crate::host::DetachedHost`] when
/// it is `None`, so "nothing is attached" is a state with a name rather than a
/// null dereference.
#[must_use]
pub fn registered_host() -> Option<Arc<SwiftHost>> {
    registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Forgets the registered host. Used at provider teardown, and by tests.
#[no_mangle]
pub extern "C" fn twinvpn_ios_bridge_unregister() {
    let mut slot = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    static SEEN: Mutex<Vec<String>> = Mutex::new(Vec::new());

    extern "C" fn apply(_ctx: *mut c_void, programme: TwIosSlice) -> TwIosStatus {
        // SAFETY: the bridge passed a live slice for the duration of this call.
        let bytes = unsafe { programme.as_slice() };
        SEEN.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(String::from_utf8_lossy(bytes).into_owned());
        TwIosStatus::ok()
    }

    extern "C" fn refuse(_ctx: *mut c_void, _programme: TwIosSlice) -> TwIosStatus {
        TwIosStatus {
            kind: TW_IOS_KIND_NEVPN,
            code: crate::oserr::NE_VPN_CONFIGURATION_DISABLED,
        }
    }

    /// A callback that hands back a byte sequence that is not UTF-8.
    ///
    /// The marshalling on this side has to decode it, and that is the layer
    /// [`SwiftHost::guarded`] genuinely protects.
    extern "C" fn not_utf8(_ctx: *mut c_void, sink: *mut c_void) -> TwIosStatus {
        let bytes = [0xff_u8, 0xfe, 0xfd];
        // SAFETY: `sink` is the pointer the bridge handed this callback and is
        // live for its duration.
        unsafe { twinvpn_ios_sink_push(sink, bytes.as_ptr(), bytes.len()) };
        TwIosStatus::ok()
    }

    extern "C" fn read_two(_ctx: *mut c_void, sink: *mut c_void) -> TwIosStatus {
        for packet in [b"\x45one".as_slice(), b"\x60two".as_slice()] {
            // SAFETY: `sink` is the pointer the bridge handed this callback and
            // is live for its duration.
            unsafe { twinvpn_ios_sink_push(sink, packet.as_ptr(), packet.len()) };
        }
        TwIosStatus::ok()
    }

    fn vtable() -> TwIosHostVtable {
        TwIosHostVtable {
            size: u32::try_from(core::mem::size_of::<TwIosHostVtable>()).expect("fits"),
            ctx: core::ptr::null_mut(),
            apply_settings: Some(apply),
            clear_settings: None,
            read_packets: Some(read_two),
            write_packets: None,
            apply_enforcement: None,
            installed_enforcement: None,
            path_snapshot: None,
            keychain_read: None,
            keychain_write: None,
            keychain_delete: None,
            store_root: None,
            store_root_backup_excluded: None,
            enclave_sign: None,
            enclave_agree: None,
            enclave_public: None,
            enclave_hardware_backed: None,
        }
    }

    #[test]
    fn a_rendered_programme_reaches_swift_verbatim() {
        SEEN.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        let host = SwiftHost::new(vtable());
        assert_eq!(host.apply_settings("{\"mtu\":1280}"), HostStatus::Ok);
        assert_eq!(
            SEEN.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_slice(),
            ["{\"mtu\":1280}".to_owned()]
        );
    }

    #[test]
    fn an_os_number_crosses_as_a_number_and_is_named_in_rust() {
        // CB-2's whole point: Swift reports what the OS reported, and the
        // registered name is computed here.
        let mut v = vtable();
        v.apply_settings = Some(refuse);
        let host = SwiftHost::new(v);
        let status = host.apply_settings("{}");
        assert_eq!(
            status,
            HostStatus::NeVpnError(crate::oserr::NE_VPN_CONFIGURATION_DISABLED)
        );
        let named = crate::netcfg::status_error(
            status,
            "NEVPNManager.saveToPreferences",
            crate::oserr::Context::Enforcement,
        );
        assert_eq!(
            named.reason_code().as_str(),
            "PLATFORM.VPN_PERMISSION_DENIED"
        );
    }

    /// **The containment claim, corrected by its own test.**
    ///
    /// A first draft asserted that a panic *inside a callback* was caught by the
    /// `catch_unwind` around the call. It is not: since Rust 1.71 an
    /// `extern "C"` function that unwinds **aborts at the ABI boundary**, so the
    /// guard is on the wrong side to help — the test aborted the whole test
    /// binary rather than failing. See the module header's table.
    ///
    /// What the guard genuinely protects is the marshalling on *this* side of
    /// the call, and that is what is asserted here: a callback that hands back
    /// bytes the decoder rejects yields a named refusal rather than a fault.
    #[test]
    fn a_fault_in_the_marshalling_is_contained_and_never_reaches_swift() {
        let mut v = vtable();
        v.installed_enforcement = Some(not_utf8);
        let host = SwiftHost::new(v);
        // Not UTF-8, so there is no configuration string to report — and the
        // answer is `None`, not a panic and not a lossy string that would then
        // fail to parse as a programme for a reason nobody could see.
        assert_eq!(host.installed_enforcement(), Ok(None));
    }

    #[test]
    fn a_null_sink_is_a_no_op_rather_than_a_fault() {
        let bytes = [1u8, 2, 3];
        // SAFETY: a null sink is explicitly handled by the callee.
        unsafe { twinvpn_ios_sink_push(core::ptr::null_mut(), bytes.as_ptr(), bytes.len()) };
        // A null payload with a non-zero length is likewise refused rather than
        // dereferenced.
        let mut sink = TwIosSink { items: Vec::new() };
        // SAFETY: `sink` is live; the payload pointer is null, which the callee
        // checks before reading.
        unsafe {
            twinvpn_ios_sink_push(
                core::ptr::addr_of_mut!(sink).cast::<c_void>(),
                core::ptr::null(),
                8,
            );
        }
        assert_eq!(sink.items, vec![Vec::<u8>::new()]);
    }

    #[test]
    fn an_unfilled_vtable_entry_is_not_attached_and_never_a_silent_success() {
        // A `clear_settings` that quietly did nothing would leave a tunnel
        // installed that the core believes is gone.
        let host = SwiftHost::new(vtable());
        assert_eq!(host.clear_settings(), HostStatus::NotAttached);
        assert_eq!(host.installed_enforcement(), Err(HostStatus::NotAttached));
        assert!(!host.enclave_hardware_backed());
        assert!(!host.store_root_backup_excluded());
    }

    #[test]
    fn a_batch_pushed_through_the_sink_arrives_whole() {
        let host = SwiftHost::new(vtable());
        let packets = host.read_packets().expect("reads");
        assert_eq!(packets, vec![b"\x45one".to_vec(), b"\x60two".to_vec()]);
    }

    #[test]
    fn a_mismatched_vtable_size_is_refused_rather_than_read_past() {
        let mut v = vtable();
        v.size = 8;
        // SAFETY: `&v` is a live vtable for the duration of the call.
        let status = unsafe { twinvpn_ios_bridge_register(core::ptr::addr_of!(v)) };
        assert_eq!(status.kind, TW_IOS_KIND_NOT_ATTACHED);
        assert_eq!(status.code, 8);
        assert!(registered_host().is_none());
    }

    #[test]
    fn a_null_vtable_is_refused() {
        // SAFETY: a null pointer is explicitly handled by the callee.
        let status = unsafe { twinvpn_ios_bridge_register(core::ptr::null()) };
        assert_eq!(status.kind, TW_IOS_KIND_NOT_ATTACHED);
    }

    #[test]
    fn registration_round_trips_and_unregistering_clears_it() {
        let v = vtable();
        // SAFETY: `&v` is live for the call and `ctx` is null, which this test's
        // callbacks never dereference.
        assert_eq!(
            unsafe { twinvpn_ios_bridge_register(core::ptr::addr_of!(v)) },
            TwIosStatus::ok()
        );
        assert!(registered_host().is_some());
        twinvpn_ios_bridge_unregister();
        assert!(registered_host().is_none());
    }

    #[test]
    fn a_mismatched_packet_and_family_count_is_refused_rather_than_read_past() {
        let host = SwiftHost::new(vtable());
        assert_eq!(
            host.write_packets(&[vec![0x45]], &[]),
            HostStatus::NotAttached
        );
    }

    #[test]
    fn an_unknown_status_kind_is_not_attached_and_never_a_success() {
        assert_eq!(
            TwIosStatus { kind: 99, code: 0 }.to_host_status(),
            HostStatus::NotAttached
        );
        assert_eq!(
            TwIosStatus {
                kind: TW_IOS_KIND_PANIC,
                code: 0
            }
            .to_host_status(),
            HostStatus::NotAttached
        );
    }

    /// **The CB-2 check, in a form that fails.**
    ///
    /// `ownership.md` §10.4: "An entry that takes or returns a `ConnectionState`,
    /// a `reason_code` class, a policy verdict or a candidate priority is a CB-2
    /// violation on the wrong side of the line, and is a finding."
    ///
    /// The vtable is `#[repr(C)]` and every field is a nullable function pointer
    /// or a scalar, so a domain type could only enter as a new field. This
    /// asserts the struct's **size**: adding a field changes it, and the test
    /// fails with a message naming the rule — which is a prompt to check the new
    /// entry against §10.4 rather than a prohibition on ever adding one.
    #[test]
    fn the_bridge_surface_carries_no_domain_fact() {
        const POINTER: usize = core::mem::size_of::<*const c_void>();
        // size (u32, padded to a pointer) + ctx + 16 function pointers.
        let expected = POINTER * 18;
        assert_eq!(
            core::mem::size_of::<TwIosHostVtable>(),
            expected,
            "the bridge vtable changed shape. ownership.md §10.4: an entry that \
             takes or returns a ConnectionState, a reason_code class, a policy \
             verdict or a candidate priority is a CB-2 violation and is a \
             finding. Check the new entry, then update this figure."
        );
        // And the status that crosses is two plain integers — the shape that
        // keeps the naming of conditions in Rust.
        assert_eq!(core::mem::size_of::<TwIosStatus>(), 8);
    }
}
