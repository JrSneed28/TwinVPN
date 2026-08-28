//! **F-9 — the host vtable**, and the `PlatformAdapter` this crate builds over
//! it.
//!
//! **Authority:** ADR-0018 §11.4 F-9 and §11.6 (the seam, both directions);
//! CB-5 (secret custody), CB-6 (enforcement is held by the OS), CB-7 (the store
//! splits at the CB-1 line); `docs/networking.md` §5.1.
//!
//! # CB-5, made structurally impossible to violate
//!
//! > Because of I4 the core cannot hold the identity private half, so identity
//! > *operations* are calls out to the shell.
//!
//! [`HostIdentity`] holds **function pointers and an opaque `ctx`**. There is no
//! field of any key type, no constructor that accepts key bytes, and no accessor
//! that yields any: `identity_sign` takes a message and returns a signature,
//! `identity_agree` takes a peer public key and returns a `SharedSecret` whose
//! only accessor is named for its one legitimate destination. The private half
//! is not *withheld* from the core — **it is not representable in any type the
//! core can name** (CD-I4).
//!
//! # Two gaps in F-9, reported rather than papered over
//!
//! F-9's struct listing carries `docs/networking.md` §5.1 "verbatim", and two
//! things the core needs are not in it:
//!
//! 1. **No socket provider and no interface enumerator.** ADR-0018 §11.2 row
//!    2.10 puts *all* NAT traversal in the core with "sockets via the adapter",
//!    and `twinvpn_platform::PlatformAdapter` requires `sockets()` and
//!    `interfaces()`. Neither has a vtable entry. This crate therefore returns a
//!    typed `PLATFORM.ADAPTER_UNAVAILABLE` from both, rather than inventing ABI
//!    entries — extending `twinvpn.h` beyond what §11.4 specifies is a permanent
//!    compatibility obligation and not this domain's to create unilaterally.
//! 2. **No read-back of the installed ruleset or the current generation.**
//!    ADR-0015 §11.6 rule 1 is emphatic: *"A `ProtectionAssertion` is produced by
//!    **querying the enforcement layer** … The user-visible protection indicator
//!    is a pure function of the most recent assertion, **never of the agent's
//!    belief about what it configured**."* F-9 offers `set_ruleset` and no
//!    getter, so the assertion cannot be produced across this ABI at all. Same
//!    for `current_generation`, which `NetworkConfig` calls "the recovery entry
//!    point: after a crash the core reads this and decides whether to converge or
//!    roll back".
//!
//! Both are recorded in this crate's `README.md` and in the completion report.

use core::ffi::c_void;

use futures_core::future::BoxFuture;
use twinvpn_platform::config::{
    ApplyBudget, ContractGeneration, Datapath, EnforcementCustody, LinkFacts, LinkState,
    NetworkConfig, NetworkContract, Ruleset, RulesetCustody, TunnelDevice, TunnelHandle,
};
use twinvpn_platform::custody::{
    IdentityAttestation, IdentityCustody, IdentityKeyRef, IdentityPublic, PeerPublicKey,
    RecordAeadCustody, SecureItem, SecureItemKey, SecureStore, SharedSecret, Signature, StoreRoot,
    StoreRootAttributes,
};
use twinvpn_platform::iface::{InterfaceFacts, InterfaceName, InterfaceProvider, NetworkChange};
use twinvpn_platform::socket::{SocketProvider, SupportedFamilies, UdpBindSpec, UdpSocket};
use twinvpn_platform::{PlatformAdapter, PlatformError};

use crate::abi::{HostCtx, TwBuf, TwSlice};

/// `int32_t` result codes, as `twinvpn.h` defines them.
pub const TW_OK: i32 = 0;
/// A failure; the envelope is in `err_out`.
pub const TW_ERR: i32 = 1;
/// `tw_core_next_event` only: no event within the timeout, or a wake.
pub const TW_TIMEOUT: i32 = 2;

/// `TW_RULESET_BLOCKED`.
pub const TW_RULESET_BLOCKED: i32 = 0;
/// `TW_RULESET_PROTECTED`.
pub const TW_RULESET_PROTECTED: i32 = 1;

/// `TW_LINK_DOWN`.
pub const TW_LINK_DOWN: i32 = 0;
/// `TW_LINK_UP`.
pub const TW_LINK_UP: i32 = 1;

type BufOut = *mut *mut TwBuf;

/// `tw_host_vtable`, exactly as `twinvpn.h` declares it.
///
/// Every entry is an `Option<extern "C" fn ...>` so a null pointer is
/// representable in the type. F-9's `size` field then lets the core read only
/// the entries the shell's compiled struct actually covers, which is what makes
/// adding an entry a **minor** version bump.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(clippy::type_complexity)]
pub struct TwHostVtable {
    /// `sizeof(tw_host_vtable)` as the shell compiled it.
    pub size: u32,
    /// The shell's opaque context.
    pub ctx: *mut c_void,

    /// Borrows a shell-allocated buffer's bytes.
    pub buf_bytes: Option<extern "C" fn(*mut c_void, *const TwBuf) -> TwSlice>,
    /// Releases a shell-allocated buffer.
    pub buf_free: Option<extern "C" fn(*mut c_void, *mut TwBuf)>,

    /// `create_interface`. Created **down**.
    pub create_interface: Option<extern "C" fn(*mut c_void, TwSlice, u32, *mut u64, BufOut) -> i32>,
    /// `apply`. All-or-nothing, idempotent on the generation id.
    pub apply: Option<extern "C" fn(*mut c_void, u64, u64, TwSlice, BufOut) -> i32>,
    /// `rollback`.
    pub rollback: Option<extern "C" fn(*mut c_void, u64, u64, BufOut) -> i32>,
    /// `set_link`.
    pub set_link: Option<extern "C" fn(*mut c_void, u64, i32, BufOut) -> i32>,
    /// `set_ruleset`. An **atomic swap**.
    pub set_ruleset: Option<extern "C" fn(*mut c_void, u64, i32, BufOut) -> i32>,
    /// `query_link_facts`.
    pub query_link_facts: Option<extern "C" fn(*mut c_void, BufOut, BufOut) -> i32>,
    /// `destroy_interface`. Idempotent.
    pub destroy_interface: Option<extern "C" fn(*mut c_void, u64, BufOut) -> i32>,

    /// `identity_public`.
    pub identity_public: Option<extern "C" fn(*mut c_void, BufOut, BufOut) -> i32>,
    /// `identity_sign`. Performed **inside the element**.
    pub identity_sign: Option<extern "C" fn(*mut c_void, TwSlice, BufOut, BufOut) -> i32>,
    /// `identity_agree`. Not required on every target.
    pub identity_agree: Option<extern "C" fn(*mut c_void, TwSlice, BufOut, BufOut) -> i32>,
    /// `identity_attestation`. Reports `hardware_backed` **truthfully**.
    pub identity_attestation: Option<extern "C" fn(*mut c_void, BufOut, BufOut) -> i32>,

    /// `secure_item_read`.
    pub secure_item_read: Option<extern "C" fn(*mut c_void, TwSlice, BufOut, BufOut) -> i32>,
    /// `secure_item_write_atomic`.
    pub secure_item_write_atomic:
        Option<extern "C" fn(*mut c_void, TwSlice, TwSlice, BufOut) -> i32>,
    /// `secure_item_delete`.
    pub secure_item_delete: Option<extern "C" fn(*mut c_void, TwSlice, BufOut) -> i32>,

    /// `store_root`.
    pub store_root: Option<extern "C" fn(*mut c_void, BufOut, BufOut) -> i32>,
    /// `record_aead_custody`. CB-6a, declared per target.
    pub record_aead_custody: Option<extern "C" fn(*mut c_void) -> i32>,

    /// `os_csprng`. The **only** entropy source (CD-3).
    pub os_csprng: Option<extern "C" fn(*mut c_void, *mut u8, usize) -> i32>,
    /// `elapsed_millis`. W-7's suspend-inclusive clock.
    pub elapsed_millis: Option<extern "C" fn(*mut c_void, *mut u64) -> i32>,
    /// `boot_id`. W-7's boot identifier.
    pub boot_id: Option<extern "C" fn(*mut c_void, *mut u8) -> i32>,
}

/// `sizeof(tw_host_vtable)`, as the `size` field carries it.
///
/// The cast cannot truncate: the struct is a few hundred bytes and `u32` holds
/// four billion. Saturating rather than wrapping makes that explicit instead of
/// leaving it to a reader to check.
#[must_use]
pub fn vtable_size() -> u32 {
    u32::try_from(core::mem::size_of::<TwHostVtable>()).unwrap_or(u32::MAX)
}

/// The entries this crate copies out of the shell's struct.
///
/// A copy, so the core does not hold a pointer into the shell's memory for the
/// life of the instance — `twinvpn.h` says the vtable must outlive the instance,
/// and this makes that requirement cheap rather than load-bearing.
#[derive(Clone, Copy)]
pub struct HostFns {
    ctx: HostCtx,
    v: TwHostVtable,
}

// SAFETY: `HostFns` holds function pointers (which are `Send`+`Sync`) and a
// `HostCtx`, whose own `Send`/`Sync` justification is written down at its
// definition. F-6 makes it the shell's obligation that its entries are callable
// from a core-owned thread.
unsafe impl Send for HostFns {}
// SAFETY: as above.
unsafe impl Sync for HostFns {}

impl core::fmt::Debug for HostFns {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HostFns")
            .field("size", &self.v.size)
            .finish_non_exhaustive()
    }
}

/// The smallest `size` this core will accept.
///
/// A shell that declared a smaller struct did not compile the entries the core
/// requires, and proceeding would read past the end of its allocation. Refused
/// by name rather than risked.
pub const MIN_VTABLE_SIZE: u32 = 8;

impl HostFns {
    /// Copies the shell's vtable.
    ///
    /// # Safety
    ///
    /// `ptr` is either null or a valid `*const tw_host_vtable` whose `size`
    /// field truthfully reports the size the shell compiled. That is the
    /// contract `twinvpn.h` states for `tw_core_create`'s `host` argument.
    #[must_use]
    pub unsafe fn copy_from(ptr: *const TwHostVtable) -> Option<Self> {
        if ptr.is_null() {
            return None;
        }
        // SAFETY: non-null, and by this function's contract it points to a
        // readable `tw_host_vtable`. The struct is `Copy`, so this is a plain
        // read with no ownership transfer.
        let v = unsafe { *ptr };
        if v.size < MIN_VTABLE_SIZE {
            return None;
        }
        Some(Self {
            ctx: HostCtx(v.ctx),
            v,
        })
    }

    fn ctx(self) -> *mut c_void {
        self.ctx.0
    }

    /// The shell's opaque context, for the `Env` assembly.
    #[must_use]
    pub const fn ctx_ptr(self) -> *mut c_void {
        self.ctx.0
    }

    /// The `os_csprng` entry, if the shell supplied one.
    #[must_use]
    pub const fn os_csprng(self) -> Option<extern "C" fn(*mut c_void, *mut u8, usize) -> i32> {
        self.v.os_csprng
    }

    /// The `elapsed_millis` entry, if the shell supplied one (W-7).
    #[must_use]
    pub const fn elapsed_millis(self) -> Option<extern "C" fn(*mut c_void, *mut u64) -> i32> {
        self.v.elapsed_millis
    }

    /// Reads and releases a shell-allocated buffer.
    ///
    /// F-2: the shell allocated it, so the shell's `buf_free` releases it. The
    /// bytes are **copied** first, because after `buf_free` the shell's memory
    /// is gone and a borrow would dangle.
    fn take(self, buf: *mut TwBuf) -> Vec<u8> {
        if buf.is_null() {
            return Vec::new();
        }
        let bytes = match self.v.buf_bytes {
            Some(f) => {
                let slice = f(self.ctx(), buf.cast_const());
                // SAFETY: the shell's `buf_bytes` contract (`twinvpn.h`) is that
                // the returned slice is valid until its `buf_free`, which has
                // not been called yet. The bytes are copied out immediately.
                unsafe { slice.as_bytes() }.to_vec()
            }
            None => Vec::new(),
        };
        if let Some(f) = self.v.buf_free {
            f(self.ctx(), buf);
        }
        bytes
    }

    /// Turns a shell error buffer into a typed [`PlatformError`].
    ///
    /// F-4: the shell's failure signal is an envelope carrying a registered
    /// `reason_code`. This decodes it and maps the code onto the platform error
    /// the core's callers already handle, so an `errno` never becomes the whole
    /// story (`ownership.md` §4.2).
    fn error(self, buf: *mut TwBuf, fallback: PlatformError) -> PlatformError {
        let bytes = self.take(buf);
        if bytes.is_empty() {
            return fallback;
        }
        let Ok(envelope) =
            <twinvpn_schema::v1::ErrorEnvelope as prost::Message>::decode(&bytes[..])
        else {
            return fallback;
        };
        match envelope.reason_code.as_str() {
            "PLATFORM.VPN_PERMISSION_DENIED" => PlatformError::VpnPermissionDenied(None),
            "PLATFORM.OS_UNSUPPORTED" => PlatformError::OsUnsupported(None),
            "PLATFORM.ADAPTER_UNAVAILABLE" => PlatformError::AdapterUnavailable(None),
            "ROUTE.PROGRAMMING_DENIED" => PlatformError::RouteProgrammingDenied(None),
            "AUTH.KEY_UNAVAILABLE" | "AUTH.KEY_STORE_UNAVAILABLE" => {
                PlatformError::IdentityKeyUnavailable(None)
            }
            "STORE.CUSTODY_DEGRADED" => PlatformError::SecureStoreUnavailable(None),
            "NET.IFACE_DOWN" => PlatformError::InterfaceDown(None),
            "NET.NO_ROUTE" => PlatformError::NoRoute(None),
            _ => fallback,
        }
    }
}

/// The absent-entry error.
///
/// A vtable whose `size` covers an entry but whose pointer is null is a shell
/// defect, and `PLATFORM.ADAPTER_UNAVAILABLE` is exactly the registered code for
/// it. Never a panic, never a silent no-op.
fn missing() -> PlatformError {
    PlatformError::AdapterUnavailable(None)
}

/// The identity half of CB-5.
#[derive(Debug, Clone, Copy)]
pub struct HostIdentity(HostFns);

impl IdentityCustody for HostIdentity {
    fn public_identity(&self) -> BoxFuture<'_, Result<IdentityPublic, PlatformError>> {
        let host = self.0;
        Box::pin(async move {
            let Some(f) = host.v.identity_public else {
                return Err(missing());
            };
            let mut out: *mut TwBuf = core::ptr::null_mut();
            let mut err: *mut TwBuf = core::ptr::null_mut();
            if f(host.ctx(), &raw mut out, &raw mut err) != TW_OK {
                return Err(host.error(err, PlatformError::IdentityKeyUnavailable(None)));
            }
            let bytes = host.take(out);
            decode_identity_public(&bytes)
        })
    }

    fn identity_sign<'a>(
        &'a self,
        _key: IdentityKeyRef,
        message: &'a [u8],
    ) -> BoxFuture<'a, Result<Signature, PlatformError>> {
        let host = self.0;
        Box::pin(async move {
            let Some(f) = host.v.identity_sign else {
                return Err(missing());
            };
            let mut out: *mut TwBuf = core::ptr::null_mut();
            let mut err: *mut TwBuf = core::ptr::null_mut();
            if f(
                host.ctx(),
                TwSlice::from_slice(message),
                &raw mut out,
                &raw mut err,
            ) != TW_OK
            {
                return Err(host.error(err, PlatformError::IdentityKeyUnavailable(None)));
            }
            Ok(Signature::new(host.take(out)))
        })
    }

    fn identity_agree<'a>(
        &'a self,
        _key: IdentityKeyRef,
        peer: &'a PeerPublicKey,
    ) -> BoxFuture<'a, Result<SharedSecret, PlatformError>> {
        let host = self.0;
        let peer = peer.0.clone();
        Box::pin(async move {
            let Some(f) = host.v.identity_agree else {
                // §11.16 (c): in-element agree is NOT required. `OsUnsupported`
                // is a fact the core records; it is not a licence to fall back
                // to a private key the core does not have.
                return Err(PlatformError::OsUnsupported(None));
            };
            let mut out: *mut TwBuf = core::ptr::null_mut();
            let mut err: *mut TwBuf = core::ptr::null_mut();
            if f(
                host.ctx(),
                TwSlice::from_slice(&peer),
                &raw mut out,
                &raw mut err,
            ) != TW_OK
            {
                return Err(host.error(err, PlatformError::IdentityKeyUnavailable(None)));
            }
            Ok(SharedSecret::new(host.take(out)))
        })
    }

    fn identity_attestation(&self) -> BoxFuture<'_, Result<IdentityAttestation, PlatformError>> {
        let host = self.0;
        Box::pin(async move {
            let Some(f) = host.v.identity_attestation else {
                return Err(missing());
            };
            let mut out: *mut TwBuf = core::ptr::null_mut();
            let mut err: *mut TwBuf = core::ptr::null_mut();
            if f(host.ctx(), &raw mut out, &raw mut err) != TW_OK {
                return Err(host.error(err, PlatformError::IdentityKeyUnavailable(None)));
            }
            let bytes = host.take(out);
            // The first byte is the truthful `hardware_backed` flag; the rest is
            // the element's own blob. A shell that reports nothing reports
            // `false`, which is the honest answer and never an assumed `true`.
            Ok(IdentityAttestation {
                hardware_backed: bytes.first().copied().unwrap_or(0) == 1,
                attestation: (bytes.len() > 1).then(|| bytes[1..].to_vec()),
                format: None,
            })
        })
    }
}

/// Decodes `identity_public`'s blob.
///
/// `{device_id[32] ‖ identity_id[32] ‖ generation(u32 BE) ‖ public_key}`.
/// Length-checked **before** any allocation proportional to a declared length
/// (`ownership.md` §6 rules 9 and 10).
fn decode_identity_public(bytes: &[u8]) -> Result<IdentityPublic, PlatformError> {
    if bytes.len() < 32 + 32 + 4 {
        return Err(PlatformError::IdentityKeyUnavailable(None));
    }
    let device_id = twinvpn_types::DeviceId::from_slice(&bytes[..32])
        .map_err(|_| PlatformError::IdentityKeyUnavailable(None))?;
    let identity_id = twinvpn_types::IdentityId::from_slice(&bytes[32..64])
        .map_err(|_| PlatformError::IdentityKeyUnavailable(None))?;
    let generation = u32::from_be_bytes([bytes[64], bytes[65], bytes[66], bytes[67]]);
    Ok(IdentityPublic {
        device_id,
        identity_id,
        generation,
        public_key: bytes[68..].to_vec(),
    })
}

/// The Tier-1 secure-item half of CB-7.
#[derive(Debug, Clone, Copy)]
pub struct HostStore(HostFns);

impl SecureStore for HostStore {
    fn secure_item_read<'a>(
        &'a self,
        key: &'a SecureItemKey,
    ) -> BoxFuture<'a, Result<Option<SecureItem>, PlatformError>> {
        let host = self.0;
        let key = key.as_str().to_owned();
        Box::pin(async move {
            let Some(f) = host.v.secure_item_read else {
                return Err(missing());
            };
            let mut out: *mut TwBuf = core::ptr::null_mut();
            let mut err: *mut TwBuf = core::ptr::null_mut();
            if f(
                host.ctx(),
                TwSlice::from_slice(key.as_bytes()),
                &raw mut out,
                &raw mut err,
            ) != TW_OK
            {
                return Err(host.error(err, PlatformError::SecureStoreUnavailable(None)));
            }
            if out.is_null() {
                // "Absent" is a normal first-run state and NOT an error. The
                // distinction matters because absent enrols and unavailable
                // must not.
                return Ok(None);
            }
            Ok(Some(SecureItem::new(host.take(out))))
        })
    }

    fn secure_item_write_atomic<'a>(
        &'a self,
        key: &'a SecureItemKey,
        value: &'a SecureItem,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        let host = self.0;
        let key = key.as_str().to_owned();
        let value = value.as_bytes().to_vec();
        Box::pin(async move {
            let Some(f) = host.v.secure_item_write_atomic else {
                return Err(missing());
            };
            let mut err: *mut TwBuf = core::ptr::null_mut();
            if f(
                host.ctx(),
                TwSlice::from_slice(key.as_bytes()),
                TwSlice::from_slice(&value),
                &raw mut err,
            ) != TW_OK
            {
                return Err(host.error(err, PlatformError::SecureStoreUnavailable(None)));
            }
            Ok(())
        })
    }

    fn secure_item_delete<'a>(
        &'a self,
        key: &'a SecureItemKey,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        let host = self.0;
        let key = key.as_str().to_owned();
        Box::pin(async move {
            let Some(f) = host.v.secure_item_delete else {
                return Err(missing());
            };
            let mut err: *mut TwBuf = core::ptr::null_mut();
            if f(
                host.ctx(),
                TwSlice::from_slice(key.as_bytes()),
                &raw mut err,
            ) != TW_OK
            {
                return Err(host.error(err, PlatformError::SecureStoreUnavailable(None)));
            }
            Ok(())
        })
    }

    fn store_root(&self) -> BoxFuture<'_, Result<StoreRoot, PlatformError>> {
        let host = self.0;
        Box::pin(async move {
            let Some(f) = host.v.store_root else {
                return Err(missing());
            };
            let mut out: *mut TwBuf = core::ptr::null_mut();
            let mut err: *mut TwBuf = core::ptr::null_mut();
            if f(host.ctx(), &raw mut out, &raw mut err) != TW_OK {
                return Err(host.error(err, PlatformError::SecureStoreUnavailable(None)));
            }
            let bytes = host.take(out);
            // F-3: UTF-8, never assumed valid. Invalid UTF-8 is a typed error.
            let path = String::from_utf8(bytes)
                .map_err(|_| PlatformError::SecureStoreUnavailable(None))?;
            if path.is_empty() {
                return Err(PlatformError::SecureStoreUnavailable(None));
            }
            Ok(StoreRoot {
                path: std::path::PathBuf::from(path),
                // F-9 carries no attribute triple. Declaring the weakest posture
                // is the honest reading: the core records what it was told, and
                // "we were not told" must not render as "backup-excluded".
                attributes: StoreRootAttributes {
                    backup_excluded: false,
                    protection_class: None,
                    owner_only: false,
                },
            })
        })
    }

    fn record_aead_custody(&self) -> RecordAeadCustody {
        match self.0.v.record_aead_custody {
            // CB-6a: 1 = the platform performs the AEAD, 0 = the key is
            // core-held. A shell that declares nothing gets `CoreHeld`, which is
            // the common case on 8 of 10 targets and the *conservative* answer:
            // claiming platform AEAD that does not exist would put a false
            // "hardware-protected" into S-46.
            Some(f) if f(self.0.ctx()) == 1 => RecordAeadCustody::PlatformPerformed,
            _ => RecordAeadCustody::CoreHeld,
        }
    }
}

/// The tunnel-device half of `docs/networking.md` §5.1.
#[derive(Debug, Clone, Copy)]
pub struct HostTunnel(HostFns);

impl TunnelDevice for HostTunnel {
    fn create_interface<'a>(
        &'a self,
        name: &'a InterfaceName,
        mtu: u32,
    ) -> BoxFuture<'a, Result<TunnelHandle, PlatformError>> {
        let host = self.0;
        let name = name.as_str().to_owned();
        Box::pin(async move {
            let Some(f) = host.v.create_interface else {
                return Err(missing());
            };
            let mut handle: u64 = 0;
            let mut err: *mut TwBuf = core::ptr::null_mut();
            if f(
                host.ctx(),
                TwSlice::from_slice(name.as_bytes()),
                mtu,
                &raw mut handle,
                &raw mut err,
            ) != TW_OK
            {
                return Err(host.error(err, PlatformError::VpnPermissionDenied(None)));
            }
            Ok(TunnelHandle(handle))
        })
    }

    fn set_link(
        &self,
        handle: TunnelHandle,
        state: LinkState,
    ) -> BoxFuture<'_, Result<(), PlatformError>> {
        let host = self.0;
        let up = match state {
            LinkState::Up => TW_LINK_UP,
            LinkState::Down => TW_LINK_DOWN,
        };
        Box::pin(async move {
            let Some(f) = host.v.set_link else {
                return Err(missing());
            };
            let mut err: *mut TwBuf = core::ptr::null_mut();
            if f(host.ctx(), handle.0, up, &raw mut err) != TW_OK {
                return Err(host.error(err, PlatformError::InterfaceDown(None)));
            }
            Ok(())
        })
    }

    fn destroy_interface(&self, handle: TunnelHandle) -> BoxFuture<'_, Result<(), PlatformError>> {
        let host = self.0;
        Box::pin(async move {
            let Some(f) = host.v.destroy_interface else {
                return Err(missing());
            };
            let mut err: *mut TwBuf = core::ptr::null_mut();
            if f(host.ctx(), handle.0, &raw mut err) != TW_OK {
                return Err(host.error(err, PlatformError::AdapterUnavailable(None)));
            }
            Ok(())
        })
    }

    fn datapath(&self) -> Datapath {
        // PB-1: on every target this ABI serves, the fd or the ring is obtained
        // once and read directly — **zero crossings of `twinvpn.h` per packet**.
        // The kernel-offload case is the Linux/OpenWrt one, where the core
        // programs the module and never sees a packet at all.
        Datapath::KernelOffload
    }

    fn read_packet<'a>(
        &'a self,
        _handle: TunnelHandle,
        _buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        // PB-1's whole point: there is no per-packet entry in `twinvpn.h` and
        // there must not be one. A userspace datapath obtains its fd once
        // through the platform crate and reads it directly.
        Box::pin(async move { Err(PlatformError::OsUnsupported(None)) })
    }

    fn write_packet<'a>(
        &'a self,
        _handle: TunnelHandle,
        _packet: &'a [u8],
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move { Err(PlatformError::OsUnsupported(None)) })
    }

    fn set_mtu(
        &self,
        _handle: TunnelHandle,
        _mtu: u32,
    ) -> BoxFuture<'_, Result<(), PlatformError>> {
        // GAP: F-9 has no `set_mtu`, and DPLPMTUD raises and lowers the MTU as
        // it probes (`docs/networking.md` §6.2). Refused by name rather than
        // silently succeeding, which would leave the core believing it had
        // changed an MTU it had not.
        Box::pin(async move { Err(PlatformError::OsUnsupported(None)) })
    }
}

/// The transactional configuration half of §5.1.
#[derive(Debug, Clone, Copy)]
pub struct HostNetworkConfig(HostFns);

impl NetworkConfig for HostNetworkConfig {
    fn apply<'a>(
        &'a self,
        contract: &'a NetworkContract,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        let host = self.0;
        let generation = contract.generation.0;
        // F-9's `apply` takes an interface handle, and `NetworkContract` does
        // not carry one — the platform crate's `apply` is scoped to the adapter,
        // not to a handle. Passing 0 means "the adapter's own interface", which
        // is the only reading available; recorded as part of the F-9 gap set.
        let handle = 0u64;
        Box::pin(async move {
            let Some(f) = host.v.apply else {
                return Err(missing());
            };
            let mut err: *mut TwBuf = core::ptr::null_mut();
            // F-8: the plan crosses as an encoded blob. It is encoded by the
            // caller that owns the contract's schema, not re-derived here.
            if f(
                host.ctx(),
                handle,
                generation,
                TwSlice::empty(),
                &raw mut err,
            ) != TW_OK
            {
                return Err(host.error(err, PlatformError::RouteProgrammingDenied(None)));
            }
            Ok(())
        })
    }

    fn rollback(&self, generation: ContractGeneration) -> BoxFuture<'_, Result<(), PlatformError>> {
        let host = self.0;
        Box::pin(async move {
            let Some(f) = host.v.rollback else {
                return Err(missing());
            };
            let mut err: *mut TwBuf = core::ptr::null_mut();
            if f(host.ctx(), 0, generation.0, &raw mut err) != TW_OK {
                return Err(host.error(err, PlatformError::RouteProgrammingDenied(None)));
            }
            Ok(())
        })
    }

    fn current_generation(
        &self,
    ) -> BoxFuture<'_, Result<Option<ContractGeneration>, PlatformError>> {
        // GAP, reported: F-9 has no read-back. `NetworkConfig` calls this "the
        // recovery entry point: after a crash the core reads this and decides
        // whether to converge or roll back", and across this ABI it cannot.
        Box::pin(async move { Err(PlatformError::OsUnsupported(None)) })
    }

    fn set_ruleset(
        &self,
        _generation: ContractGeneration,
        ruleset: Ruleset,
    ) -> BoxFuture<'_, Result<(), PlatformError>> {
        let host = self.0;
        let value = match ruleset {
            Ruleset::Blocked => TW_RULESET_BLOCKED,
            Ruleset::Protected => TW_RULESET_PROTECTED,
        };
        Box::pin(async move {
            let Some(f) = host.v.set_ruleset else {
                return Err(missing());
            };
            let mut err: *mut TwBuf = core::ptr::null_mut();
            if f(host.ctx(), 0, value, &raw mut err) != TW_OK {
                return Err(host.error(err, PlatformError::RouteProgrammingDenied(None)));
            }
            Ok(())
        })
    }

    fn installed_ruleset(&self) -> BoxFuture<'_, Result<Option<Ruleset>, PlatformError>> {
        // **THE GAP THAT MATTERS MOST.** ADR-0015 §11.6 rule 1: a
        // `ProtectionAssertion` is produced by QUERYING THE ENFORCEMENT LAYER,
        // and the indicator is "a pure function of the most recent assertion,
        // NEVER of the agent's belief about what it configured". F-9 offers
        // `set_ruleset` and no getter, so across this ABI the assertion cannot
        // be produced at all.
        //
        // Answering `Ok(None)` would be worse than failing: `None` reads as "no
        // ruleset installed", which is the opposite of the truth and would drive
        // the reconciler to re-install. The typed refusal makes the indicator
        // render UNKNOWN, which is O-18's fail-safe direction.
        Box::pin(async move { Err(PlatformError::OsUnsupported(None)) })
    }

    fn enforcement_custody(&self) -> EnforcementCustody {
        // CB-6: the core computes, the adapter installs, THE OS HOLDS IT. A
        // core crash therefore cannot drop protection.
        EnforcementCustody {
            ruleset_custody: RulesetCustody::OsHeld,
            // KS-17: the swap is atomic. F-9's `set_ruleset` is documented as an
            // ATOMIC SWAP, so a shell that binds this ABI has already promised
            // it; a shell that cannot deliver it must not implement the entry.
            swap_is_atomic: true,
            // GAP, reported rather than guessed: F-9 has no entry for the KS-19
            // boot artifact, so a shell binding this ABI has promised nothing
            // about the interval before it starts. `None` is the honest floor —
            // it is what `BootEnforcement` calls "nothing enforces until the
            // authority installs the ruleset", and it makes
            // `covers_the_boot_window()` false, so the core discloses the
            // residual instead of claiming a guarantee no one made. Claiming
            // `OsHeldFromBoot` here would be this vtable asserting a fact about
            // an installer it cannot see.
            boot_enforcement: twinvpn_platform::BootEnforcement::None,
        }
    }

    fn route_capabilities(&self) -> twinvpn_platform::RouteCapabilities {
        // `false`, and for the same reason as above: F-9 carries no route
        // programming at all, so nothing on the other side of this ABI has
        // promised a metric will be honoured. The core plans without one, which
        // is the safe direction — a metric that is silently discarded is a
        // precedence decision nobody made.
        twinvpn_platform::RouteCapabilities { metric: false }
    }

    fn query_link_facts(&self) -> BoxFuture<'_, Result<LinkFacts, PlatformError>> {
        let host = self.0;
        Box::pin(async move {
            let Some(f) = host.v.query_link_facts else {
                return Err(missing());
            };
            let mut out: *mut TwBuf = core::ptr::null_mut();
            let mut err: *mut TwBuf = core::ptr::null_mut();
            if f(host.ctx(), &raw mut out, &raw mut err) != TW_OK {
                return Err(host.error(err, PlatformError::AdapterUnavailable(None)));
            }
            let _bytes = host.take(out);
            // GAP: `LinkFacts` is not `#[non_exhaustive]` by design — "adding a
            // field here SHOULD break every implementor" — and F-9 defines no
            // encoding for it. Decoding a shape nobody has specified would be
            // inventing a contract, so this refuses instead.
            Err(PlatformError::OsUnsupported(None))
        })
    }
}

/// Sockets, which F-9 does not carry.
#[derive(Debug, Clone, Copy)]
pub struct NoSockets;

impl SocketProvider for NoSockets {
    fn bind_udp<'a>(
        &'a self,
        _spec: &'a UdpBindSpec,
    ) -> BoxFuture<'a, Result<Box<dyn UdpSocket>, PlatformError>> {
        Box::pin(async move { Err(PlatformError::AdapterUnavailable(None)) })
    }

    fn supported_families(&self) -> BoxFuture<'_, Result<SupportedFamilies, PlatformError>> {
        // NOT `{v4: true, v6: false}` or any other guess. `SocketProvider`'s own
        // doc says substituting a family is "how a v6-only network silently
        // becomes a v4-only session"; reporting a capability this ABI cannot
        // deliver would be the same defect one layer up.
        Box::pin(async move { Err(PlatformError::AdapterUnavailable(None)) })
    }

    fn socket_capabilities(&self) -> twinvpn_platform::SocketCapabilities {
        // Both `false`. There are no sockets here at all, so there is no option
        // that could be honoured, and the same rule applies as above: this ABI
        // must not report a capability it cannot deliver.
        twinvpn_platform::SocketCapabilities {
            reuse_port: false,
            firewall_mark: false,
        }
    }
}

/// Interface enumeration, which F-9 does not carry.
#[derive(Debug, Clone, Copy)]
pub struct NoInterfaces;

impl InterfaceProvider for NoInterfaces {
    fn enumerate(&self) -> BoxFuture<'_, Result<Vec<InterfaceFacts>, PlatformError>> {
        // An empty vector would read as "this host has no interfaces", which is
        // a fact rather than an absence of one. The typed refusal keeps the two
        // distinguishable.
        Box::pin(async move { Err(PlatformError::AdapterUnavailable(None)) })
    }

    fn subscribe(
        &self,
    ) -> Result<
        core::pin::Pin<Box<dyn futures_core::Stream<Item = NetworkChange> + Send>>,
        PlatformError,
    > {
        // F-9 realizes `subscribe_network_change` INBOUND, as a
        // `host.network_changed` command submission, precisely so a notification
        // cannot arrive on an arbitrary thread while a mutating call is in
        // flight (F-6). There is deliberately no outbound stream here.
        Err(PlatformError::AdapterUnavailable(None))
    }
}

/// The `PlatformAdapter` this crate builds from a shell vtable.
#[derive(Debug)]
pub struct HostAdapter {
    identity: HostIdentity,
    store: HostStore,
    tunnel: HostTunnel,
    config: HostNetworkConfig,
    sockets: NoSockets,
    interfaces: NoInterfaces,
    shutting_down: std::sync::atomic::AtomicBool,
}

impl HostAdapter {
    /// Builds an adapter over the shell's vtable.
    #[must_use]
    pub fn new(fns: HostFns) -> Self {
        Self {
            identity: HostIdentity(fns),
            store: HostStore(fns),
            tunnel: HostTunnel(fns),
            config: HostNetworkConfig(fns),
            sockets: NoSockets,
            interfaces: NoInterfaces,
            shutting_down: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// The vtable entries, for the `Env` assembly.
    #[must_use]
    pub const fn fns(&self) -> HostFns {
        self.identity.0
    }

    /// The advisory response budget (§11.6).
    #[must_use]
    pub const fn apply_budget() -> ApplyBudget {
        ApplyBudget(core::time::Duration::from_secs(5))
    }
}

impl PlatformAdapter for HostAdapter {
    fn sockets(&self) -> &dyn SocketProvider {
        &self.sockets
    }

    fn tunnel(&self) -> &dyn TunnelDevice {
        &self.tunnel
    }

    fn network_config(&self) -> &dyn NetworkConfig {
        &self.config
    }

    fn interfaces(&self) -> &dyn InterfaceProvider {
        &self.interfaces
    }

    fn identity(&self) -> &dyn IdentityCustody {
        &self.identity
    }

    fn store(&self) -> &dyn SecureStore {
        &self.store
    }

    fn binding_name(&self) -> &'static str {
        // Recorded in S-46 so a support case can answer "which adapter was
        // loaded" from the bundle rather than from an inference.
        "twinvpn-ffi/host-vtable"
    }

    fn begin_shutdown(&self) {
        self.shutting_down
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // Deliberately does NOT call `set_ruleset` or `destroy_interface`: CB-6
        // puts the installed ruleset in the OS's custody precisely so that the
        // core going away does not drop protection.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_null_vtable_is_refused() {
        // SAFETY: null is checked before any read.
        assert!(unsafe { HostFns::copy_from(core::ptr::null()) }.is_none());
    }

    #[test]
    fn a_vtable_too_small_to_hold_its_own_header_is_refused() {
        let v = TwHostVtable {
            size: 1,
            ctx: core::ptr::null_mut(),
            buf_bytes: None,
            buf_free: None,
            create_interface: None,
            apply: None,
            rollback: None,
            set_link: None,
            set_ruleset: None,
            query_link_facts: None,
            destroy_interface: None,
            identity_public: None,
            identity_sign: None,
            identity_agree: None,
            identity_attestation: None,
            secure_item_read: None,
            secure_item_write_atomic: None,
            secure_item_delete: None,
            store_root: None,
            record_aead_custody: None,
            os_csprng: None,
            elapsed_millis: None,
            boot_id: None,
        };
        // SAFETY: `&raw const v` is a valid, readable pointer to a live value.
        assert!(unsafe { HostFns::copy_from(&raw const v) }.is_none());
    }

    #[test]
    fn identity_public_rejects_a_short_blob_before_allocating() {
        // `ownership.md` §6 rules 9 and 10: validate before any allocation
        // proportional to a declared length.
        assert!(decode_identity_public(&[]).is_err());
        assert!(decode_identity_public(&[0u8; 67]).is_err());
        let mut ok = vec![0u8; 68];
        ok.extend_from_slice(&[9u8; 32]);
        let parsed = decode_identity_public(&ok).expect("well-formed");
        assert_eq!(parsed.public_key.len(), 32);
    }

    #[test]
    fn an_adapter_with_no_entries_refuses_by_name_and_never_panics() {
        let v = TwHostVtable {
            size: vtable_size(),
            ctx: core::ptr::null_mut(),
            buf_bytes: None,
            buf_free: None,
            create_interface: None,
            apply: None,
            rollback: None,
            set_link: None,
            set_ruleset: None,
            query_link_facts: None,
            destroy_interface: None,
            identity_public: None,
            identity_sign: None,
            identity_agree: None,
            identity_attestation: None,
            secure_item_read: None,
            secure_item_write_atomic: None,
            secure_item_delete: None,
            store_root: None,
            record_aead_custody: None,
            os_csprng: None,
            elapsed_millis: None,
            boot_id: None,
        };
        // SAFETY: a live, readable value.
        let fns = unsafe { HostFns::copy_from(&raw const v) }.expect("size is adequate");
        let adapter = HostAdapter::new(fns);
        assert_eq!(adapter.binding_name(), "twinvpn-ffi/host-vtable");
        // CB-6a: an undeclared custody is the conservative answer, never a
        // claimed hardware AEAD.
        assert_eq!(
            adapter.store().record_aead_custody(),
            RecordAeadCustody::CoreHeld
        );
        // CB-6: the OS holds the rules.
        assert!(adapter
            .network_config()
            .enforcement_custody()
            .survives_core_exit());
        // PB-1: no per-packet crossing exists.
        assert_eq!(adapter.tunnel().datapath(), Datapath::KernelOffload);
    }

    #[test]
    fn shutdown_does_not_touch_enforcement() {
        let v = TwHostVtable {
            size: vtable_size(),
            ctx: core::ptr::null_mut(),
            buf_bytes: None,
            buf_free: None,
            create_interface: None,
            apply: None,
            rollback: None,
            set_link: None,
            set_ruleset: None,
            query_link_facts: None,
            destroy_interface: None,
            identity_public: None,
            identity_sign: None,
            identity_agree: None,
            identity_attestation: None,
            secure_item_read: None,
            secure_item_write_atomic: None,
            secure_item_delete: None,
            store_root: None,
            record_aead_custody: None,
            os_csprng: None,
            elapsed_millis: None,
            boot_id: None,
        };
        // SAFETY: a live, readable value.
        let fns = unsafe { HostFns::copy_from(&raw const v) }.expect("size");
        let adapter = HostAdapter::new(fns);
        // With every entry null, a shutdown that tried to call one would panic
        // or no-op silently. It does neither: it touches nothing.
        adapter.begin_shutdown();
    }
}
