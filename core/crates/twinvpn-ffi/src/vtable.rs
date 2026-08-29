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
//! # Two gaps in F-9 — one closed, one still open
//!
//! F-9's struct listing carries `docs/networking.md` §5.1 "verbatim", and two
//! things the core needs were not in it:
//!
//! 1. **W-25, STILL OPEN. No socket provider and no interface enumerator.**
//!    ADR-0018 §11.2 row 2.10 puts *all* NAT traversal in the core with "sockets
//!    via the adapter", and `twinvpn_platform::PlatformAdapter` requires
//!    `sockets()` and `interfaces()`. Neither has a vtable entry. This crate
//!    therefore returns a typed `PLATFORM.ADAPTER_UNAVAILABLE` from both.
//!
//!    **This one is deliberately NOT closed the way W-24 was, and the asymmetry
//!    is the point.** W-24 needed two scalar queries whose whole content is a
//!    posture and a `u64`. A socket provider is a *lifecycle*: bind, send,
//!    receive, close, readiness, per-datagram addressing — a per-packet surface
//!    against PB-1's budget, and an interface enumerator brings change events,
//!    which F-6 already forbids as an outbound callback. Guessing that shape
//!    unilaterally would spend F-1's "compatibility obligation forever" on a
//!    design nobody reviewed. §10.4 already rules that these stay **in Rust,
//!    in-process** for the mobile shells; W-25 still asks ADR-0018 §11.4 for the
//!    general answer.
//! 2. **W-24, CLOSED. No read-back of the installed ruleset or the current
//!    generation.** ADR-0015 §11.6 rule 1 is emphatic: *"A `ProtectionAssertion`
//!    is produced by **querying the enforcement layer** … The user-visible
//!    protection indicator is a pure function of the most recent assertion,
//!    **never of the agent's belief about what it configured**."* F-9 offered
//!    `set_ruleset` and no getter, so the assertion could not be produced across
//!    this ABI at all — and the same for `current_generation`, which
//!    `NetworkConfig` calls "the recovery entry point: after a crash the core
//!    reads this and decides whether to converge or roll back".
//!
//!    `twinvpn.h` now carries both, **appended** to `tw_host_vtable` at ABI
//!    minor `1 -> 2`. VR-1 makes an addition a minor bump and F-9's `size` field
//!    is what makes it one in fact: a shell compiled against minor 1 declares a
//!    shorter struct, [`HostFns::copy_from`] reads only the prefix that struct
//!    covers, and both entries stay `None` — the same state that shell already
//!    produced. Nothing was removed, no signature changed, no existing entry
//!    moved. Same mechanism and same justification as W-26's four additions.
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
/// What the core writes into `installed_ruleset`'s `ruleset_out` **before** the
/// call.
///
/// Not a posture, and deliberately not in `twinvpn.h`: it is never passed to a
/// shell as an input and never accepted from one as an output, so it is not part
/// of the ABI. It exists so that a shell returning `TW_OK` without writing the
/// parameter cannot leave a `0` behind to be read as `TW_RULESET_BLOCKED`.
const TW_RULESET_UNSET: i32 = -1;

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

    /// `installed_ruleset`. W-24's read-back: a **query of the OS**.
    ///
    /// Appended rather than placed beside `set_ruleset` because F-9's `size`
    /// field only makes an *append* compatible — moving an entry changes the
    /// prefix every older shell already compiled.
    pub installed_ruleset:
        Option<extern "C" fn(*mut c_void, u64, *mut i32, *mut i32, BufOut) -> i32>,
    /// `current_generation`. W-24's recovery entry point, likewise appended.
    pub current_generation:
        Option<extern "C" fn(*mut c_void, u64, *mut u64, *mut i32, BufOut) -> i32>,
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

/// The end offset of the vtable **header** — `size` and `ctx`.
///
/// Everything after it is a function-pointer entry, and every one of those is
/// pointer-sized and pointer-aligned. Both facts are asserted below, because
/// [`HostFns::copy_from`] relies on them to truncate a short vtable at a field
/// boundary rather than mid-pointer.
const HEADER_END: usize =
    core::mem::offset_of!(TwHostVtable, ctx) + core::mem::size_of::<*mut c_void>();

// The entry region begins where the header ends, and is pointer-aligned. If a
// future field breaks either property, `copy_from`'s truncation could land in
// the middle of one, so this fails the build instead.
const _: () = assert!(HEADER_END == core::mem::offset_of!(TwHostVtable, buf_bytes));
const _: () = assert!(HEADER_END.is_multiple_of(core::mem::align_of::<*mut c_void>()));
const _: () = assert!(
    core::mem::size_of::<TwHostVtable>().is_multiple_of(core::mem::align_of::<*mut c_void>())
);
const _: () = assert!(
    core::mem::size_of::<Option<extern "C" fn(*mut c_void) -> i32>>()
        == core::mem::size_of::<*mut c_void>()
);

/// The smallest `size` this core will accept.
///
/// A shell that declared a smaller struct did not compile the entries the core
/// requires, and proceeding would read past the end of its allocation. Refused
/// by name rather than risked.
///
/// This is the **header**: a `size` that cannot even cover `size` and `ctx` is
/// not a truncated vtable, it is a wrong pointer.
// The header is a `u32` and a pointer — tens of bytes on every target this
// product builds for. The cast cannot truncate, and saturating makes that
// explicit rather than leaving it to a reader.
pub const MIN_VTABLE_SIZE: u32 = {
    // `u32::try_from` is not yet const, so the bound is asserted and the cast
    // then cannot truncate. The header is a `u32` and a pointer — tens of bytes
    // on every target — so this holds by construction rather than by hope, and
    // a layout that broke it would fail the build here.
    assert!(HEADER_END <= u32::MAX as usize);
    #[allow(clippy::cast_possible_truncation)]
    {
        HEADER_END as u32
    }
};

impl TwHostVtable {
    /// A vtable with no `ctx` and no entries.
    ///
    /// The base [`HostFns::copy_from`] copies the shell's declared bytes onto.
    /// Written out field by field rather than zeroed through `MaybeUninit`,
    /// because DP-4 forbids `assume_init` anywhere in this tree — and because a
    /// field added to the struct then fails to compile here until someone has
    /// decided what its absent value is.
    pub const EMPTY: Self = Self {
        size: 0,
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
        installed_ruleset: None,
        current_generation: None,
    };
}

impl HostFns {
    /// Copies the shell's vtable, reading **only the bytes its `size` covers**.
    ///
    /// # R-3: `size` is honoured BEFORE the struct is dereferenced
    ///
    /// `twinvpn.h` promises the core "reads only the entries the declared size
    /// covers", and that promise is what makes adding an entry a *minor* bump.
    /// The previous implementation did `let v = *ptr` — materialising all 24
    /// fn-pointer fields — and only then compared `size`. A wave-2 shell built
    /// against an older, shorter header therefore had every byte past the end
    /// of its allocation read, and any non-zero word past it became `Some(fn)`
    /// **and was called**.
    ///
    /// This reads `size` on its own (it is the first field, so it is covered by
    /// any conforming allocation), clamps it to what this core compiled, rounds
    /// it **down to a whole entry** so a truncation can never land mid-pointer,
    /// and copies exactly that many bytes over [`TwHostVtable::EMPTY`]. Entries
    /// the shell did not declare are therefore `None` — the same value a shell
    /// that declared and left them null produces, which
    /// [`missing`] already reports as
    /// `PLATFORM.ADAPTER_UNAVAILABLE`.
    ///
    /// # Safety
    ///
    /// `ptr` is either null or a valid `*const tw_host_vtable` whose `size`
    /// field truthfully reports the size the shell compiled, and which is
    /// readable for that many bytes. That is the contract `twinvpn.h` states
    /// for `tw_core_create`'s `host` argument.
    #[must_use]
    pub unsafe fn copy_from(ptr: *const TwHostVtable) -> Option<Self> {
        if ptr.is_null() {
            return None;
        }
        // SAFETY: non-null and, by this function's contract, pointing at a
        // `tw_host_vtable` whose declared size is at least its own first field.
        // `size` is at offset 0, so this read is inside ANY conforming
        // allocation — including one shorter than `TwHostVtable`. Nothing else
        // is touched until the declared size has been checked.
        let declared = unsafe { core::ptr::addr_of!((*ptr).size).read() };
        if declared < MIN_VTABLE_SIZE {
            return None;
        }

        // Never read past the shell's allocation, and never past our own struct
        // (a NEWER shell may legitimately declare a larger one).
        let readable = core::cmp::min(declared as usize, core::mem::size_of::<TwHostVtable>());
        // Round down to a whole entry: a `size` landing mid-pointer would
        // otherwise leave a half-copied, non-null word that reads as `Some(fn)`.
        let align = core::mem::align_of::<*mut c_void>();
        let n = readable - (readable % align);

        // `n` is a multiple of the pointer alignment and so never splits an
        // entry: a copied one is exactly the shell's bit pattern, an uncopied
        // one keeps `EMPTY`'s `None`.
        let mut v = TwHostVtable::EMPTY;
        // SAFETY: `ptr` is readable for `declared` bytes by this function's
        // contract and `n <= declared`; `v` is a live, fully-initialised local
        // of `TwHostVtable`, so it is writable for `size_of` >= `n` bytes and
        // cannot overlap `ptr`, being a fresh stack local.
        unsafe {
            core::ptr::copy_nonoverlapping(
                ptr.cast::<u8>(),
                core::ptr::addr_of_mut!(v).cast::<u8>(),
                n,
            );
        }
        // Report what we actually honoured, not what the shell claimed, so
        // `Debug` and any future gate read the same number this copy used.
        v.size = u32::try_from(n).unwrap_or(u32::MAX);

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
        // **W-24, closed.** This was a typed refusal, because F-9 had no
        // read-back and `NetworkConfig` calls this "the recovery entry point:
        // after a crash the core reads this and decides whether to converge or
        // roll back". `twinvpn.h` now carries the entry — ABI minor 1 -> 2, an
        // append under VR-1 — so the recovery decision is answerable across this
        // ABI instead of being refused.
        //
        // A shell compiled against minor 1 declared a shorter struct, so
        // `copy_from` leaves this `None` and the refusal below is still what it
        // gets: the behaviour it was built against, unchanged.
        let host = self.0;
        Box::pin(async move {
            let Some(f) = host.v.current_generation else {
                return Err(PlatformError::OsUnsupported(None));
            };
            // Both out-parameters are initialized here, so a shell that returns
            // TW_OK without writing them yields "nothing in force" rather than a
            // stack value read as a generation id. `present` carries the absence
            // because a generation is a monotone u64 with no spare value to
            // reserve for it.
            let mut generation: u64 = 0;
            let mut present: i32 = 0;
            let mut err: *mut TwBuf = core::ptr::null_mut();
            if f(
                host.ctx(),
                0,
                &raw mut generation,
                &raw mut present,
                &raw mut err,
            ) != TW_OK
            {
                return Err(host.error(err, PlatformError::OsUnsupported(None)));
            }
            if present == 0 {
                return Ok(None);
            }
            Ok(Some(ContractGeneration(generation)))
        })
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
        // **W-24, the gap that mattered most, closed.** ADR-0015 §11.6 rule 1:
        // a `ProtectionAssertion` is produced by QUERYING THE ENFORCEMENT
        // LAYER, and the indicator is "a pure function of the most recent
        // assertion, NEVER of the agent's belief about what it configured".
        // F-9 offered `set_ruleset` and no getter, so across this ABI the
        // assertion could not be produced at all and this returned a typed
        // refusal — UNKNOWN, which is O-18's fail-safe direction but not the
        // required one. `twinvpn.h` now carries the getter.
        //
        // **Three outcomes, and each keeps a distinct fact distinct.** The
        // entry ABSENT — an older shell, or one that cannot query the OS — is
        // still the typed refusal, because an unreadable posture is not an
        // asserted one and `Ok(None)` would read as "nothing is installed",
        // the opposite of the truth. `present == 0` is `Ok(None)`, which is now
        // an ANSWER rather than a guess: the shell queried the OS and found no
        // rules of ours. A posture this core does not recognize is REFUSED
        // rather than rounded to one, because rounding it up asserts protection
        // nobody stated and rounding it down hides a shell defect behind a
        // plausible reading.
        let host = self.0;
        Box::pin(async move {
            let Some(f) = host.v.installed_ruleset else {
                return Err(PlatformError::OsUnsupported(None));
            };
            // Initialized to "absent, and no posture": a shell that returns
            // TW_OK without writing them yields `Ok(None)`, never a stack value
            // read as TW_RULESET_PROTECTED.
            let mut ruleset: i32 = TW_RULESET_UNSET;
            let mut present: i32 = 0;
            let mut err: *mut TwBuf = core::ptr::null_mut();
            if f(
                host.ctx(),
                0,
                &raw mut ruleset,
                &raw mut present,
                &raw mut err,
            ) != TW_OK
            {
                return Err(host.error(err, PlatformError::OsUnsupported(None)));
            }
            if present == 0 {
                return Ok(None);
            }
            match ruleset {
                TW_RULESET_BLOCKED => Ok(Some(Ruleset::Blocked)),
                TW_RULESET_PROTECTED => Ok(Some(Ruleset::Protected)),
                // A shell claiming a ruleset is present and naming a posture
                // this core has no value for. `PLATFORM.ADAPTER_UNAVAILABLE` is
                // the registered code for a vtable entry that does not honour
                // its own contract, and refusing renders the indicator UNKNOWN.
                _ => Err(missing()),
            }
        })
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

/// Sockets, which F-9 does not carry — and, per **G-11**, will not.
///
/// # This absence is a decision, not a hole waiting for an entry
///
/// A UDP socket is on the **datapath**, and PB-1's headline rule is *zero FFI
/// crossings per packet*: its table reads `0` for every target but the Apple
/// app-extension's `NEPacketTunnelFlow`, which is a Swift API and not this ABI.
/// PB-4 then prices the split at **0 ns/packet** on Linux, Windows, Android and
/// OpenWrt. A `udp_send`/`udp_recv` pair here would make both false *by
/// construction* — at PB-3's desktop userspace gate (≥ 60 % of ≥ 90 % of 1 GbE,
/// so ≈ 540 Mbit/s) a 1420-byte payload is ≈ 47 500 datagrams per second per
/// direction, and no per-datagram crossing costs 0 ns.
///
/// F-6 makes it worse than a call cost. A vtable callee MUST NOT re-enter a
/// mutating core function, so a datagram received inside `udp_recv` cannot be
/// handed to the core on the thread that received it: every datagram would owe
/// a hop to the single mutating thread S-47 allows. That hop is scheduler
/// latency, not nanoseconds, and it is per packet.
///
/// So the refusal below is the design. The capability lives in Rust, in the
/// shell's own process, over `twinvpn-platform-*` — which is what all five
/// shells already do (§10.4's ruling, generalised by X-7).
#[derive(Debug, Clone, Copy)]
pub struct NoSockets;

impl SocketProvider for NoSockets {
    fn bind_udp<'a>(
        &'a self,
        _spec: &'a UdpBindSpec,
    ) -> BoxFuture<'a, Result<Box<dyn UdpSocket>, PlatformError>> {
        // `OsUnsupported`, not `AdapterUnavailable`, and the difference is the
        // registry's: `PLATFORM.ADAPTER_UNAVAILABLE` is `LOCAL_ACTION` — it
        // sends the user to restart something — while
        // `PLATFORM.OS_UNSUPPORTED` is `UPDATE_REQUIRED`, which is the truth.
        // No local action gives a vtable-only binding sockets; only a shell
        // built with a platform adapter has them. `SocketProvider::bind_udp`'s
        // own contract already names `OsUnsupported` as the code for a socket
        // shape this host cannot open.
        Box::pin(async move { Err(PlatformError::OsUnsupported(None)) })
    }

    fn supported_families(&self) -> BoxFuture<'_, Result<SupportedFamilies, PlatformError>> {
        // NOT `{v4: true, v6: false}` or any other guess. `SocketProvider`'s own
        // doc says substituting a family is "how a v6-only network silently
        // becomes a v4-only session"; reporting a capability this ABI cannot
        // deliver would be the same defect one layer up.
        Box::pin(async move { Err(PlatformError::OsUnsupported(None)) })
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

/// Interface enumeration, which F-9 does not carry — and, per **G-11**, cannot
/// carry today for a different reason from [`NoSockets`]'.
///
/// # This half is control-rate and would be admissible; it has no encoding
///
/// `enumerate` is called on a gather and on a network change, not per packet,
/// so PB-1 and PB-4 have nothing to say about it. What blocks it is **F-8**:
/// structured data crosses as blobs generated from ADR-0003's contract
/// artifacts, and `contracts/` holds no message that can carry
/// [`InterfaceFacts`]. The only candidate, `twinvpn.v1.NetworkInterface`, is
/// lossy in three ways at once — it has no interface **index** (the identity
/// [`twinvpn_platform::InterfaceIndex`] exists to be, *"deliberately not a
/// name"*), no `link_class` (so `NET.LINK.DOWN_WIFI` and `NET.LINK.DOWN_CELLULAR`
/// become one code), and its `addresses` are `repeated IPPrefix` — the exact
/// shape [`InterfaceFacts::addresses`] records as the defect three domains
/// reported independently, which masks `10.0.0.7/24` to the network address and
/// which W-39 shows drops `fe80::/10` outright.
///
/// Encoding over it would reinstate a defect the corpus has already fixed once,
/// so this refuses instead — the same stop `query_link_facts` takes above, for
/// the same stated reason: decoding a shape nobody has specified is inventing a
/// contract. Closing it needs a `contracts/` amendment under §3, which is an ask
/// and not a patch.
#[derive(Debug, Clone, Copy)]
pub struct NoInterfaces;

impl InterfaceProvider for NoInterfaces {
    fn enumerate(&self) -> BoxFuture<'_, Result<Vec<InterfaceFacts>, PlatformError>> {
        // An empty vector would read as "this host has no interfaces", which is
        // a fact rather than an absence of one. The typed refusal keeps the two
        // distinguishable — and `host.network_changed` depends on exactly that,
        // returning early on a refusal rather than inventing a link-down that
        // would tear down a healthy session.
        //
        // `OsUnsupported` for the same reason as `NoSockets::bind_udp`: the
        // remediation is a shell that carries an adapter, which is
        // `UPDATE_REQUIRED`, not the `LOCAL_ACTION` that
        // `PLATFORM.ADAPTER_UNAVAILABLE` would send a user to attempt.
        Box::pin(async move { Err(PlatformError::OsUnsupported(None)) })
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
        Err(PlatformError::OsUnsupported(None))
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
            installed_ruleset: None,
            current_generation: None,
        };
        // SAFETY: `&raw const v` is a valid, readable pointer to a live value.
        assert!(unsafe { HostFns::copy_from(&raw const v) }.is_none());
    }

    extern "C" fn never_called_buf_free(_ctx: *mut c_void, _buf: *mut TwBuf) {
        unreachable!("an entry past the declared size must never be reached");
    }

    /// R-3, the regression the old test could not catch.
    ///
    /// The previous test built a FULL-SIZE Rust struct and set `size: 1`, so
    /// every field it "must not read" was in fact live, initialised memory —
    /// it passed whether or not `size` was honoured. This allocates a buffer
    /// that genuinely ENDS after the header plus two entries, fills the bytes
    /// past it with a non-zero pattern, and checks the core neither reads them
    /// nor turns them into callable entries.
    #[test]
    fn entries_past_the_declared_size_are_not_read_and_are_not_callable() {
        let entry = core::mem::size_of::<*mut c_void>();
        let declared = HEADER_END + 2 * entry; // size, ctx, buf_bytes, buf_free.

        // A *pointer-aligned* allocation of exactly `declared` bytes, followed
        // by a poison region standing in for "memory this shell never owned".
        //
        // `Vec<usize>` and not `Vec<u8>`: a `Vec<u8>`'s buffer is 1-aligned, so
        // reading a `TwHostVtable` out of it would be undefined regardless of
        // what this test is trying to prove. The element type IS the alignment.
        let words = (declared + 8 * entry).div_ceil(entry);
        let mut backing = vec![0usize; words];
        // SAFETY: `backing` owns `words * entry` initialised bytes and outlives
        // this borrow; `u8` has no alignment requirement and no invalid bit
        // pattern, so viewing the allocation as bytes is sound.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), words * entry)
        };
        bytes[declared..].fill(0xAA);
        bytes[..core::mem::size_of::<u32>()]
            .copy_from_slice(&u32::try_from(declared).expect("small").to_le_bytes());
        let free = never_called_buf_free as *const ();
        bytes[HEADER_END + entry..HEADER_END + 2 * entry]
            .copy_from_slice(&(free as usize).to_ne_bytes());

        // SAFETY: the buffer is `declared` bytes of initialised memory, aligned
        // for `TwHostVtable` because its element type is pointer-sized, and its
        // first field truthfully declares that size — exactly the `twinvpn.h`
        // contract for a shell compiled against a shorter header. If
        // `copy_from` reads past `declared` it reads the poison, which the
        // assertions below then catch.
        let fns = unsafe { HostFns::copy_from(backing.as_ptr().cast::<TwHostVtable>()) }
            .expect("the header is present");

        // Declared: honoured.
        assert!(fns.v.buf_free.is_some(), "a declared entry is kept");
        // Undeclared: absent, NOT the 0xAAAA.. poison reinterpreted as a fn.
        assert!(fns.v.apply.is_none(), "an entry past `size` must be None");
        assert!(fns.v.set_ruleset.is_none(), "R-3: never a poisoned pointer");
        assert!(fns.v.os_csprng.is_none());
        assert!(fns.v.boot_id.is_none());
        assert_eq!(
            fns.v.size,
            u32::try_from(declared).expect("small"),
            "the honoured size is reported, not the claim"
        );
    }

    /// A `size` that stops in the middle of an entry truncates to the entry
    /// BEFORE it, so no half-copied word can read as `Some(fn)`.
    #[test]
    fn a_size_landing_mid_entry_truncates_to_the_previous_entry() {
        let entry = core::mem::size_of::<*mut c_void>();
        let mut v = TwHostVtable::EMPTY;
        v.buf_free = Some(never_called_buf_free);
        v.size = u32::try_from(HEADER_END + 2 * entry - 1).expect("small");
        // SAFETY: `&raw const v` is a valid, readable, fully-initialised value,
        // and its declared size is smaller than the struct.
        let fns = unsafe { HostFns::copy_from(&raw const v) }.expect("the header is present");
        assert!(
            fns.v.buf_free.is_none(),
            "a partially covered entry is dropped, never half-read"
        );
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
            installed_ruleset: None,
            current_generation: None,
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
            installed_ruleset: None,
            current_generation: None,
        };
        // SAFETY: a live, readable value.
        let fns = unsafe { HostFns::copy_from(&raw const v) }.expect("size");
        let adapter = HostAdapter::new(fns);
        // With every entry null, a shutdown that tried to call one would panic
        // or no-op silently. It does neither: it touches nothing.
        adapter.begin_shutdown();
    }

    // -----------------------------------------------------------------------
    // W-24 — the enforcement read-back
    // -----------------------------------------------------------------------

    /// A tiny inline executor.
    ///
    /// Every future in this module is ready on first poll — a vtable entry is a
    /// synchronous C call — and asserting that keeps these tests free of an
    /// async runtime this crate does not depend on.
    fn ready<T>(mut future: BoxFuture<'_, T>) -> T {
        let waker = core::task::Waker::noop();
        let mut cx = core::task::Context::from_waker(waker);
        match core::future::Future::poll(future.as_mut(), &mut cx) {
            core::task::Poll::Ready(value) => value,
            core::task::Poll::Pending => unreachable!("a vtable call is ready on first poll"),
        }
    }

    /// A full-size host vtable with the entries this test supplies.
    fn host(build: impl FnOnce(&mut TwHostVtable)) -> HostFns {
        let mut v = TwHostVtable::EMPTY;
        build(&mut v);
        v.size = vtable_size();
        // SAFETY: `&raw const v` is a valid, readable, fully-initialised value
        // whose `size` field truthfully reports `size_of::<TwHostVtable>()`.
        unsafe { HostFns::copy_from(&raw const v) }.expect("size is adequate")
    }

    extern "C" fn reads_back_protected(
        _ctx: *mut c_void,
        _h: u64,
        ruleset: *mut i32,
        present: *mut i32,
        _err: BufOut,
    ) -> i32 {
        // SAFETY: `twinvpn.h`'s contract for this entry is that both
        // out-parameters are valid, writable pointers to a live `int32_t` for
        // the duration of the call. The caller here is `HostNetworkConfig`,
        // which passes two stack locals of its own.
        unsafe {
            *ruleset = TW_RULESET_PROTECTED;
            *present = 1;
        }
        TW_OK
    }

    extern "C" fn reads_back_blocked(
        _ctx: *mut c_void,
        _h: u64,
        ruleset: *mut i32,
        present: *mut i32,
        _err: BufOut,
    ) -> i32 {
        // SAFETY: as `reads_back_protected`.
        unsafe {
            *ruleset = TW_RULESET_BLOCKED;
            *present = 1;
        }
        TW_OK
    }

    extern "C" fn reads_back_nothing_installed(
        _ctx: *mut c_void,
        _h: u64,
        _ruleset: *mut i32,
        present: *mut i32,
        _err: BufOut,
    ) -> i32 {
        // SAFETY: as `reads_back_protected`. `ruleset` is deliberately left
        // unwritten, which is what the contract permits when nothing is
        // installed.
        unsafe {
            *present = 0;
        }
        TW_OK
    }

    extern "C" fn reads_back_an_unknown_posture(
        _ctx: *mut c_void,
        _h: u64,
        ruleset: *mut i32,
        present: *mut i32,
        _err: BufOut,
    ) -> i32 {
        // SAFETY: as `reads_back_protected`.
        unsafe {
            *ruleset = 7;
            *present = 1;
        }
        TW_OK
    }

    extern "C" fn returns_ok_and_writes_nothing(
        _ctx: *mut c_void,
        _h: u64,
        _ruleset: *mut i32,
        _present: *mut i32,
        _err: BufOut,
    ) -> i32 {
        TW_OK
    }

    extern "C" fn returns_ok_and_writes_no_generation(
        _ctx: *mut c_void,
        _h: u64,
        _generation: *mut u64,
        _present: *mut i32,
        _err: BufOut,
    ) -> i32 {
        TW_OK
    }

    extern "C" fn read_back_fails(
        _ctx: *mut c_void,
        _h: u64,
        _ruleset: *mut i32,
        _present: *mut i32,
        _err: BufOut,
    ) -> i32 {
        TW_ERR
    }

    extern "C" fn generation_in_force(
        _ctx: *mut c_void,
        _h: u64,
        generation: *mut u64,
        present: *mut i32,
        _err: BufOut,
    ) -> i32 {
        // SAFETY: `twinvpn.h`'s contract for this entry — both out-parameters
        // are valid, writable pointers to live storage for the call's duration.
        unsafe {
            *generation = 41 + 1;
            *present = 1;
        }
        TW_OK
    }

    extern "C" fn no_generation_in_force(
        _ctx: *mut c_void,
        _h: u64,
        _generation: *mut u64,
        present: *mut i32,
        _err: BufOut,
    ) -> i32 {
        // SAFETY: as `generation_in_force`.
        unsafe {
            *present = 0;
        }
        TW_OK
    }

    extern "C" fn accepts_any_ruleset(
        _ctx: *mut c_void,
        _h: u64,
        _ruleset: i32,
        _err: BufOut,
    ) -> i32 {
        TW_OK
    }

    /// The property W-24 exists for: the posture is the OS's answer, not ours.
    #[test]
    fn the_read_back_reports_the_posture_the_shell_queried() {
        let protected =
            HostNetworkConfig(host(|v| v.installed_ruleset = Some(reads_back_protected)));
        assert_eq!(
            ready(protected.installed_ruleset()).expect("a posture"),
            Some(Ruleset::Protected)
        );
        let blocked = HostNetworkConfig(host(|v| v.installed_ruleset = Some(reads_back_blocked)));
        assert_eq!(
            ready(blocked.installed_ruleset()).expect("a posture"),
            Some(Ruleset::Blocked)
        );
    }

    /// `None` is now an ANSWER, not the absence of one.
    ///
    /// Before W-24 closed there was no getter, so `Ok(None)` would have meant
    /// "we could not ask" while reading as "nothing is installed". With a shell
    /// that queried the OS and found no rules of ours, `None` is the truth.
    #[test]
    fn a_shell_that_queried_and_found_nothing_answers_none() {
        let config = HostNetworkConfig(host(|v| {
            v.installed_ruleset = Some(reads_back_nothing_installed);
        }));
        assert_eq!(ready(config.installed_ruleset()).expect("an answer"), None);
    }

    /// A posture this core has no value for is refused, never rounded.
    #[test]
    fn an_unrecognized_posture_is_refused_and_never_read_as_protected() {
        let config = HostNetworkConfig(host(|v| {
            v.installed_ruleset = Some(reads_back_an_unknown_posture);
        }));
        // Rounding it up would assert protection nobody stated; rounding it down
        // would hide a shell defect behind a plausible reading.
        assert!(matches!(
            ready(config.installed_ruleset()),
            Err(PlatformError::AdapterUnavailable(_))
        ));
    }

    /// The out-parameters are initialized core-side, so a shell that returns
    /// `TW_OK` and writes neither cannot leave a stack value behind that reads
    /// as `TW_RULESET_PROTECTED`.
    #[test]
    fn an_unwritten_out_parameter_is_never_read_as_a_posture() {
        let config = HostNetworkConfig(host(|v| {
            v.installed_ruleset = Some(returns_ok_and_writes_nothing);
        }));
        assert_eq!(ready(config.installed_ruleset()).expect("an answer"), None);

        let generation = HostNetworkConfig(host(|v| {
            v.current_generation = Some(returns_ok_and_writes_no_generation);
        }));
        assert_eq!(
            ready(generation.current_generation()).expect("an answer"),
            None
        );
    }

    /// A failing read-back is a typed refusal, so the indicator renders UNKNOWN.
    #[test]
    fn a_failing_read_back_refuses_rather_than_answering_none() {
        let config = HostNetworkConfig(host(|v| v.installed_ruleset = Some(read_back_fails)));
        assert!(matches!(
            ready(config.installed_ruleset()),
            Err(PlatformError::OsUnsupported(_))
        ));
    }

    /// The recovery entry point round-trips, and reports absence separately.
    #[test]
    fn current_generation_round_trips_and_reports_absence_separately() {
        let in_force =
            HostNetworkConfig(host(|v| v.current_generation = Some(generation_in_force)));
        assert_eq!(
            ready(in_force.current_generation()).expect("a generation"),
            Some(ContractGeneration(42))
        );
        let none = HostNetworkConfig(host(|v| {
            v.current_generation = Some(no_generation_in_force);
        }));
        assert_eq!(ready(none.current_generation()).expect("an answer"), None);
    }

    /// **R-3's clamping rule, applied to the two entries this change adds.**
    ///
    /// A shell compiled against ABI minor 1 declared a `tw_host_vtable` that
    /// ENDS at `boot_id`. This allocates exactly that struct — a buffer that
    /// genuinely stops there — fills the bytes past it with a non-zero pattern
    /// standing in for memory the shell never owned, and checks three things:
    ///
    /// 1. the core does not turn the poison into `Some(fn)` and call it;
    /// 2. the two new entries read as absent, so the older shell gets exactly
    ///    the typed refusal it was built against — which is what makes this a
    ///    MINOR bump under VR-1 rather than a break;
    /// 3. an entry the older shell DID declare still works, so the addition
    ///    cost it nothing.
    #[test]
    fn a_shell_predating_the_w24_entries_still_works_and_never_calls_poison() {
        let entry = core::mem::size_of::<*mut c_void>();
        // The struct as ABI minor 1 declared it: everything up to, and not
        // including, the first entry this change appended.
        let declared = core::mem::offset_of!(TwHostVtable, installed_ruleset);

        // `Vec<usize>` and not `Vec<u8>`: the element type IS the alignment, and
        // reading a `TwHostVtable` out of a 1-aligned buffer would be undefined
        // regardless of what this test is trying to prove.
        let words = (declared + 4 * entry).div_ceil(entry);
        let mut backing = vec![0usize; words];
        // SAFETY: `backing` owns `words * entry` initialised bytes and outlives
        // this borrow; `u8` has no alignment requirement and no invalid bit
        // pattern, so viewing the allocation as bytes is sound.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), words * entry)
        };
        bytes[declared..].fill(0xAA);
        bytes[..core::mem::size_of::<u32>()]
            .copy_from_slice(&u32::try_from(declared).expect("small").to_le_bytes());
        let set = accepts_any_ruleset as *const ();
        let at = core::mem::offset_of!(TwHostVtable, set_ruleset);
        bytes[at..at + entry].copy_from_slice(&(set as usize).to_ne_bytes());

        // SAFETY: the buffer holds `declared` bytes of initialised memory,
        // aligned for `TwHostVtable` because its element type is pointer-sized,
        // and its first field truthfully declares that size — exactly the
        // `twinvpn.h` contract for a shell compiled against a shorter header.
        let fns = unsafe { HostFns::copy_from(backing.as_ptr().cast::<TwHostVtable>()) }
            .expect("the header is present");

        assert!(
            fns.v.installed_ruleset.is_none(),
            "an entry past `size` must be None, never the 0xAA poison as a fn"
        );
        assert!(fns.v.current_generation.is_none());

        let config = HostNetworkConfig(fns);
        // (2) The refusal it was built against, unchanged — and reached without
        // ever calling through the poison.
        assert!(matches!(
            ready(config.installed_ruleset()),
            Err(PlatformError::OsUnsupported(_))
        ));
        assert!(matches!(
            ready(config.current_generation()),
            Err(PlatformError::OsUnsupported(_))
        ));
        // (3) What it did declare still works. This is the whole claim of a
        // minor bump: the older shell paid nothing for the addition.
        assert!(ready(config.set_ruleset(ContractGeneration(1), Ruleset::Blocked)).is_ok());
    }

    // -----------------------------------------------------------------------
    // W-25 / G-11 — sockets and interface enumeration, refused on purpose
    // -----------------------------------------------------------------------

    /// The refusal names the remediation that can actually work.
    ///
    /// `PLATFORM.ADAPTER_UNAVAILABLE` is `LOCAL_ACTION` in the registry, which
    /// tells a user to go and fix something locally. Nothing local gives a
    /// vtable-only binding a socket or an interface table: the remediation is a
    /// shell built with a `twinvpn-platform-*` adapter, and that is
    /// `PLATFORM.OS_UNSUPPORTED`'s `UPDATE_REQUIRED`. Pinned because the wrong
    /// one is not merely imprecise — it sends an operator to try something that
    /// cannot succeed, and it is the same class of defect W-24 named when it
    /// refused to let a shell echo its own belief back.
    #[test]
    fn the_absent_capabilities_refuse_as_unsupported_and_never_as_unavailable() {
        // `.err()` rather than `expect_err`: `Box<dyn UdpSocket>` and the
        // `NetworkChange` stream are not `Debug`, so the `Ok` side cannot be
        // formatted and `unwrap_err` does not compile.
        let refusals = [
            ready(NoSockets.bind_udp(&UdpBindSpec {
                family: twinvpn_platform::SocketFamily::V4,
                local: None,
                options: twinvpn_platform::SocketOptions::default(),
            }))
            .err(),
            ready(NoSockets.supported_families()).err(),
            ready(NoInterfaces.enumerate()).err(),
            NoInterfaces.subscribe().err(),
        ];
        for refusal in refusals {
            let err = refusal.expect("every one of the four refuses");
            assert!(
                matches!(err, PlatformError::OsUnsupported(_)),
                "a structurally absent capability is UPDATE_REQUIRED, not LOCAL_ACTION: {err:?}"
            );
        }
    }

    /// Absence is reported as absence, never as a fact about the host.
    ///
    /// This is the half that would be dangerous to get wrong in the other
    /// direction. `supported_families` answering `{v4: false, v6: false}` would
    /// say *"this host has no IP stack"*, and `enumerate` answering `[]` would
    /// say *"this host has no interfaces"* — both are findings the core would
    /// act on, and neither is true. `host.network_changed` reads exactly this
    /// distinction: on `Err` it returns early rather than deriving a link-down
    /// that would tear down a healthy session.
    #[test]
    fn an_absent_capability_is_a_refusal_and_never_a_fact_about_the_host() {
        assert!(ready(NoSockets.supported_families()).is_err());
        assert!(ready(NoInterfaces.enumerate()).is_err());
        // The one thing that IS answered rather than refused, because a
        // capability nobody can honour is honestly `false` in both fields —
        // there is no socket for the option to fail to apply to.
        let caps = NoSockets.socket_capabilities();
        assert!(!caps.reuse_port && !caps.firewall_mark);
    }

    /// **G-11's design claim, asserted rather than left in prose: no entry this
    /// ABI carries is on the datapath.**
    ///
    /// PB-1 budgets zero FFI crossings per packet and PB-4 prices the split at
    /// 0 ns/packet on four of six targets. The property that keeps both true is
    /// structural — `twinvpn.h` declares no entry that takes or returns a
    /// packet, so `HostAdapter` cannot be a datapath and says so by reporting
    /// `KernelOffload` and refusing the per-packet calls outright. A future
    /// `udp_send`/`udp_recv` pair would break this test, which is the point.
    #[test]
    fn no_vtable_entry_sits_on_the_datapath() {
        let adapter = HostAdapter::new(host(|_| {}));
        assert_eq!(adapter.tunnel().datapath(), Datapath::KernelOffload);
        assert!(matches!(
            ready(adapter.tunnel().read_packet(TunnelHandle(1), &mut [0u8; 4])),
            Err(PlatformError::OsUnsupported(_))
        ));
        assert!(matches!(
            ready(adapter.tunnel().write_packet(TunnelHandle(1), &[0u8; 4])),
            Err(PlatformError::OsUnsupported(_))
        ));
        // And the underlay half of the datapath is refused by the same rule:
        // a datagram socket carries packets at the same rate the tunnel does.
        assert!(matches!(
            ready(adapter.sockets().supported_families()),
            Err(PlatformError::OsUnsupported(_))
        ));
    }
}
