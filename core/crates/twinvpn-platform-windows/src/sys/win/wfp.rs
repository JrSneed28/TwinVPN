//! The Windows Filtering Platform, as [`FilterEngine`].
//!
//! **Authority:** ADR-0012 §11.6's Windows row (one owned sublayer,
//! `FWPM_LAYER_ALE_AUTH_CONNECT_V4` **and** `_V6`, installed in one
//! transaction), KS-17 (two rulesets, never zero), KS-20 (owner-tagged and
//! reclaimable), KS-23 (atomic swap, never remove-then-add), K11 (coexistence),
//! K12 (observable by query); ADR-0015 §11.6 O-17; ADR-0016 PS-8;
//! ADR-0018 CB-6, DP-4.
//!
//! # This file has never been executed
//!
//! Nothing in `sys/win/` has been linked, loaded or run. `make cross-check`
//! type-checks it against the real `windows-sys` for `x86_64-pc-windows-msvc`
//! with `-D warnings`; that is a compile proof and it is not a behaviour proof.
//! Every claim below about what the engine does is a claim about what the
//! documentation says it does.
//!
//! # The transaction cannot be left open
//!
//! KS-17 forbids an instant in which the host holds no TwinVPN filters, and the
//! mechanism is `FwpmTransactionBegin0` … `FwpmTransactionCommit0` with the
//! delete pass **inside** it. An early return that forgot to abort would leave
//! the engine holding a write transaction until the process exited, and every
//! later commit would fail with `FWP_E_TXN_IN_PROGRESS`.
//!
//! So the abort is not a discipline, it is [`Transaction`]'s `Drop`: the guard
//! aborts unless [`Transaction::commit`] consumed it. There is no path out of
//! the block — `?`, a panic, an early `return` — that does not run it.
//!
//! # Only owner-tagged objects are touched
//!
//! Every object added carries `providerKey = &PROVIDER_KEY`, and the delete pass
//! enumerates with an `FWPM_FILTER_ENUM_TEMPLATE0` whose `providerKey` is ours —
//! so a filter another product installed is never enumerated, never counted and
//! never deleted. ADR-0012 K11 requires exactly that, and on Windows it is the
//! ordinary case rather than the exotic one.

use std::sync::Mutex;

use twinvpn_platform::PlatformError;
use twinvpn_types::AddressFamily;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmEngineSetOption0, FwpmFilterAdd0,
    FwpmFilterCreateEnumHandle0, FwpmFilterDeleteByKey0, FwpmFilterDestroyEnumHandle0,
    FwpmFilterEnum0, FwpmFilterGetById0, FwpmFreeMemory0, FwpmNetEventCreateEnumHandle0,
    FwpmNetEventDestroyEnumHandle0, FwpmNetEventEnum2, FwpmProviderAdd0, FwpmProviderDeleteByKey0,
    FwpmProviderGetByKey0, FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmSubLayerGetByKey0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0,
    FWPM_ACTION0_0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_ALE_USER_ID, FWPM_CONDITION_FLAGS,
    FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_DISPLAY_DATA0, FWPM_ENGINE_COLLECT_NET_EVENTS, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER_FLAG_BOOTTIME, FWPM_FILTER_FLAG_PERSISTENT,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_NET_EVENT2,
    FWPM_NET_EVENT_ENUM_TEMPLATE0, FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW,
    FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, FWPM_PROVIDER0, FWPM_SUBLAYER0,
    FWPM_SUBLAYER_FLAG_PERSISTENT, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB,
    FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0,
    FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME, FWP_FILTER_ENUM_FULLY_CONTAINED, FWP_IP_VERSION_V4,
    FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ANY_SET, FWP_MATCH_NOT_EQUAL, FWP_UINT16, FWP_UINT32,
    FWP_UINT64, FWP_UINT8, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK,
    FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use crate::oserr::{self, Context, Win32Error};
use crate::wfp::canary::{NetEvent, NetEventKind};
use crate::wfp::readback::{EngineState, InstalledFilter};
use crate::wfp::{
    Action, Condition, FilterSet, FilterSpec, Guid, IpProtocol, Layer, PROVIDER_KEY, SUBLAYER_KEY,
    SUBLAYER_WEIGHT,
};

use super::wide;
use crate::sys::FilterEngine;

/// How many entries an enumeration asks for per call.
///
/// **A decision recorded as one.** No value is pinned in the corpus. The owned
/// set is a few dozen filters, so one call returns everything in practice; the
/// loop exists because an enumeration that assumed it would is a truncation
/// waiting for the day somebody adds a class.
const ENUM_BATCH: u32 = 512;

/// An engine handle that may be shared across threads.
///
/// `HANDLE` is a raw pointer and therefore neither `Send` nor `Sync` by default.
struct EngineHandle(HANDLE);

// SAFETY: an `FWPM` engine handle is a kernel object reference, not a pointer
// into this process's address space, and the filter-engine API is documented as
// callable from multiple threads on one handle. Nothing in this module derefs
// it; it is only ever passed back to `fwpuclnt.dll`.
unsafe impl Send for EngineHandle {}
// SAFETY: as above.
unsafe impl Sync for EngineHandle {}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was produced by a successful `FwpmEngineOpen0` and
        // has not been closed — `EngineHandle` owns it and is not `Clone`.
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}

/// The engine, opened once at construction (CD-2).
pub struct WfpEngine {
    engine: EngineHandle,
    /// Serialises transactions within this process.
    ///
    /// WFP allows one write transaction per session, so two threads committing
    /// concurrently would give one of them `FWP_E_TXN_IN_PROGRESS` — a failure
    /// that has nothing to do with the host and everything to do with us. The
    /// mutex makes the second wait instead.
    txn: Mutex<()>,
}

impl WfpEngine {
    /// Opens the filter engine.
    ///
    /// # Errors
    ///
    /// [`PlatformError::NotPermitted`] where the token cannot open the engine
    /// for write — ADR-0016 §11.2 rejects `LocalService` and `NetworkService`
    /// for exactly this reason, and PS-18 makes it a startup refusal rather than
    /// a degradation.
    pub fn open() -> Result<Self, PlatformError> {
        let mut handle: HANDLE = core::ptr::null_mut();
        // SAFETY: `servername` null selects the local engine; `authidentity` and
        // `session` null select the caller's own credentials and a
        // non-dynamic session, which is what makes the objects outlive this
        // process (CB-6). `handle` is a live out-parameter.
        let status = unsafe {
            FwpmEngineOpen0(
                core::ptr::null(),
                RPC_C_AUTHN_WINNT,
                core::ptr::null(),
                core::ptr::null(),
                &raw mut handle,
            )
        };
        if status != 0 {
            return Err(oserr::from_status(
                Win32Error(status),
                "FwpmEngineOpen0",
                Context::Enforcement,
            ));
        }
        let engine = EngineHandle(handle);

        // ADR-0012 §11.9's canary reads classify events, and the engine does not
        // collect them unless asked. Set once, at open, rather than per sample:
        // an option toggled per call is a window in which the counters are
        // silently zero.
        let value = FWP_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: FWP_VALUE0_0 { uint32: 1 },
        };
        // SAFETY: `engine.0` is live; `value` outlives the call.
        let status = unsafe {
            FwpmEngineSetOption0(engine.0, FWPM_ENGINE_COLLECT_NET_EVENTS, &raw const value)
        };
        if status != 0 {
            // Not fatal, and deliberately so: the canary degrades to
            // `Indeterminate`, which `canary_verdict` already refuses to read as
            // "the rule is live". Losing the counters must not stop the host
            // being protected.
            tracing::warn!(
                status = format!("{status:#x}"),
                "the engine refused FWPM_ENGINE_COLLECT_NET_EVENTS; the leak canary will report Indeterminate"
            );
        }

        Ok(Self {
            engine,
            txn: Mutex::new(()),
        })
    }

    fn handle(&self) -> HANDLE {
        self.engine.0
    }
}

/// The engine, opened on first use.
///
/// # Why this exists, stated once
///
/// [`WfpEngine::open`] can fail, and ADR-0016 PS-18 wants that failure at
/// startup. But [`crate::WindowsPlatformAdapter::new`] is infallible and is not
/// this domain's file, so the shim needs a constructor that cannot fail.
///
/// The refusal is not lost, only deferred by one call: every method here opens
/// the engine if it is not open and returns the **open error** if it cannot, and
/// the first call the service makes is the start sequence's read-back. So a host
/// where `FwpmEngineOpen0` is refused still fails to start, with the same
/// `reason_code`.
///
/// A failed open is **retried** on the next call rather than remembered. That is
/// deliberate: the Base Filtering Engine is a service, and "BFE was not up yet"
/// is a condition that resolves, whereas a cached failure would make it
/// permanent for the life of the process.
pub struct LazyEngine {
    inner: Mutex<Option<std::sync::Arc<WfpEngine>>>,
}

impl LazyEngine {
    /// An engine that will open on first use.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    /// An engine that is already open.
    #[must_use]
    pub fn opened(engine: WfpEngine) -> Self {
        Self {
            inner: Mutex::new(Some(std::sync::Arc::new(engine))),
        }
    }

    /// The engine, opening it if this is the first call.
    fn get(&self) -> Result<std::sync::Arc<WfpEngine>, PlatformError> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(engine) = guard.as_ref() {
            return Ok(engine.clone());
        }
        let engine = std::sync::Arc::new(WfpEngine::open()?);
        *guard = Some(engine.clone());
        Ok(engine)
    }
}

impl Default for LazyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterEngine for LazyEngine {
    fn commit(&self, set: &FilterSet) -> Result<(), PlatformError> {
        self.get()?.commit(set)
    }

    fn dry_run(&self, set: &FilterSet) -> Result<(), PlatformError> {
        self.get()?.dry_run(set)
    }

    fn read(&self) -> Result<EngineState, PlatformError> {
        self.get()?.read()
    }

    fn net_events(&self) -> Result<(Vec<NetEvent>, bool), PlatformError> {
        self.get()?.net_events()
    }

    fn purge(&self) -> Result<(), PlatformError> {
        self.get()?.purge()
    }
}

/// A write transaction that cannot be left open.
struct Transaction<'a> {
    engine: HANDLE,
    committed: bool,
    _lock: std::sync::MutexGuard<'a, ()>,
}

impl<'a> Transaction<'a> {
    fn begin(engine: &'a WfpEngine) -> Result<Self, PlatformError> {
        let lock = engine
            .txn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: the handle is live for the engine's lifetime; `0` is
        // `FWPM_TXN_READ_WRITE`.
        let status = unsafe { FwpmTransactionBegin0(engine.handle(), 0) };
        if status != 0 {
            return Err(oserr::from_status(
                Win32Error(status),
                "FwpmTransactionBegin0",
                Context::Enforcement,
            ));
        }
        Ok(Self {
            engine: engine.handle(),
            committed: false,
            _lock: lock,
        })
    }

    fn commit(mut self) -> Result<(), PlatformError> {
        // SAFETY: the transaction was begun on this handle and has not been
        // committed or aborted.
        let status = unsafe { FwpmTransactionCommit0(self.engine) };
        self.committed = true;
        if status == 0 {
            Ok(())
        } else {
            Err(oserr::from_status(
                Win32Error(status),
                "FwpmTransactionCommit0",
                Context::Enforcement,
            ))
        }
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // SAFETY: a transaction begun on this handle and not committed.
            unsafe {
                FwpmTransactionAbort0(self.engine);
            }
        }
    }
}

/// The GUID form of one of ours.
///
/// `Guid` holds the sixteen bytes in the order a GUID prints, and
/// `GUID::from_u128` splits a big-endian `u128` into exactly those fields — so
/// the round trip through `u128` is the identity and not a re-ordering.
const fn guid(g: Guid) -> GUID {
    GUID::from_u128(u128::from_be_bytes(g.0))
}

/// Our GUID form of one of Windows'.
const fn ours(g: GUID) -> Guid {
    let one = g.data1.to_be_bytes();
    let two = g.data2.to_be_bytes();
    let three = g.data3.to_be_bytes();
    let rest = g.data4;
    Guid([
        one[0], one[1], one[2], one[3], two[0], two[1], three[0], three[1], rest[0], rest[1],
        rest[2], rest[3], rest[4], rest[5], rest[6], rest[7],
    ])
}

/// Whether two GUIDs are the same value.
///
/// `windows_sys::core::GUID` derives neither `PartialEq` nor `Eq`, so this is
/// written out. Comparing through [`ours`] rather than field by field means the
/// crate has exactly one notion of GUID equality, and it is the one the filter
/// keys and the read-back already use.
fn guid_eq(a: GUID, b: GUID) -> bool {
    ours(a).0 == ours(b).0
}

const fn layer_guid(layer: Layer) -> GUID {
    match layer {
        Layer::AleAuthConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::AleAuthConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    }
}

/// Everything one `FWPM_FILTER0` borrows, kept alive beside it.
///
/// WFP structures are shallow: they hold pointers into the caller's memory and
/// the engine reads them during the call. So the conditions, the wide strings,
/// the address-and-mask values and the SID blob have to outlive the
/// `FwpmFilterAdd0` — which they do because this struct owns them and the
/// filter borrows from it.
struct FilterArena {
    conditions: Vec<FWPM_FILTER_CONDITION0>,
    name: Vec<u16>,
    app_ids: Vec<Vec<u16>>,
    /// Self-relative security descriptors, one per `Condition::UserSid`. NOT
    /// the SID string: `FWPM_CONDITION_ALE_USER_ID` is
    /// `FWP_SECURITY_DESCRIPTOR_TYPE`, and the engine answers a string with
    /// `ERROR_INVALID_SECURITY_DESCR` (1338) — measured, in the hosted
    /// kill-switch lane, as the service's `POLICY.KILLSWITCH.ARM_FAILED`.
    sids: Vec<Vec<u8>>,
    v4: Vec<FWP_V4_ADDR_AND_MASK>,
    v6: Vec<FWP_V6_ADDR_AND_MASK>,
    u64s: Vec<u64>,
}

impl FilterArena {
    fn new(spec: &FilterSpec) -> Self {
        Self {
            conditions: Vec::with_capacity(spec.conditions.len()),
            name: wide(spec.name),
            app_ids: Vec::new(),
            sids: Vec::new(),
            v4: Vec::new(),
            v6: Vec::new(),
            u64s: Vec::new(),
        }
    }
}

/// Builds the condition array for one filter.
///
/// The two-pass shape — fill the owned vectors, then take pointers — is not
/// stylistic: a `Vec` that grows reallocates, and a pointer taken before a push
/// would dangle. Every vector is sized before any pointer is taken.
#[allow(clippy::too_many_lines)]
fn build_conditions(spec: &FilterSpec, arena: &mut FilterArena) -> Result<(), PlatformError> {
    // Pass one: own every value the conditions will point at, with the vectors
    // sized up front so no later push can reallocate them.
    let app_ids = spec
        .conditions
        .iter()
        .filter(|c| matches!(c, Condition::AppId(_)))
        .count();
    let sids = spec
        .conditions
        .iter()
        .filter(|c| matches!(c, Condition::UserSid(_)))
        .count();
    let v4 = spec
        .conditions
        .iter()
        .filter(|c| matches!(c, Condition::RemotePrefix(p) if p.family() == AddressFamily::V4))
        .count();
    let v6 = spec
        .conditions
        .iter()
        .filter(|c| matches!(c, Condition::RemotePrefix(p) if p.family() == AddressFamily::V6))
        .count();
    let luids = spec
        .conditions
        .iter()
        .filter(|c| {
            matches!(
                c,
                Condition::LocalInterface(_) | Condition::NotLocalInterface(_)
            )
        })
        .count();
    arena.app_ids.reserve_exact(app_ids);
    arena.sids.reserve_exact(sids);
    arena.v4.reserve_exact(v4);
    arena.v6.reserve_exact(v6);
    arena.u64s.reserve_exact(luids);

    for condition in &spec.conditions {
        match condition {
            Condition::AppId(path) => arena.app_ids.push(wide(path)),
            Condition::UserSid(sid) => arena.sids.push(match_filter_descriptor(sid)?),
            Condition::LocalInterface(luid) | Condition::NotLocalInterface(luid) => {
                arena.u64s.push(*luid);
            }
            Condition::RemotePrefix(prefix) => match prefix.address() {
                twinvpn_types::IpAddr::V4(a) => arena.v4.push(FWP_V4_ADDR_AND_MASK {
                    addr: super::addr::v4_host_order(a),
                    mask: super::addr::v4_mask(prefix.prefix_len()),
                }),
                twinvpn_types::IpAddr::V6(a) => arena.v6.push(FWP_V6_ADDR_AND_MASK {
                    addr: a.octets(),
                    #[allow(clippy::cast_possible_truncation)]
                    prefixLength: prefix.prefix_len() as u8,
                }),
            },
            Condition::RemotePort(_)
            | Condition::Protocol(_)
            | Condition::IsLoopback
            | Condition::LinkLocalScope => {}
        }
    }

    // Pass two: the conditions themselves, pointing into the now-stable vectors.
    let mut app = 0usize;
    let mut sid = 0usize;
    let mut v4i = 0usize;
    let mut v6i = 0usize;
    let mut luid = 0usize;
    for condition in &spec.conditions {
        let built = match condition {
            Condition::LocalInterface(_) | Condition::NotLocalInterface(_) => {
                let value = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
                    matchType: if matches!(condition, Condition::LocalInterface(_)) {
                        FWP_MATCH_EQUAL
                    } else {
                        FWP_MATCH_NOT_EQUAL
                    },
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT64,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            uint64: arena.u64s.as_mut_ptr().wrapping_add(luid),
                        },
                    },
                };
                luid += 1;
                value
            }
            Condition::AppId(_) => {
                let value = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_ALE_APP_ID,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            byteBlob: core::ptr::null_mut(),
                        },
                    },
                };
                // The pointer is filled in by `link_blobs`, once the blob
                // arena exists: a `FWP_BYTE_BLOB` is itself a struct the engine
                // dereferences, so it needs storage the condition can point at
                // and that storage cannot exist until both arenas do. The
                // counter advances so the two passes stay in step.
                app += 1;
                let _ = app;
                value
            }
            Condition::UserSid(_) => {
                let value = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_ALE_USER_ID,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_SECURITY_DESCRIPTOR_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            sd: core::ptr::null_mut(),
                        },
                    },
                };
                // Same as the app-id arm: `link_blobs` fills the pointer in.
                sid += 1;
                let _ = sid;
                value
            }
            Condition::RemotePrefix(prefix) => {
                if prefix.family() == AddressFamily::V4 {
                    let value = FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        matchType: FWP_MATCH_EQUAL,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_V4_ADDR_MASK,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                v4AddrMask: arena.v4.as_mut_ptr().wrapping_add(v4i),
                            },
                        },
                    };
                    v4i += 1;
                    value
                } else {
                    let value = FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        matchType: FWP_MATCH_EQUAL,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_V6_ADDR_MASK,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                v6AddrMask: arena.v6.as_mut_ptr().wrapping_add(v6i),
                            },
                        },
                    };
                    v6i += 1;
                    value
                }
            }
            Condition::RemotePort(port) => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: *port },
                },
            },
            Condition::Protocol(protocol) => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint8: protocol_number(*protocol),
                    },
                },
            },
            Condition::IsLoopback => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_FLAGS,
                matchType: FWP_MATCH_FLAGS_ANY_SET,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT32,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                    },
                },
            },
            Condition::LinkLocalScope => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    // `NlatUnicast` is 1; the link-local narrowing WFP can
                    // express at this layer is the address *type*, not the
                    // scope. **A stated approximation**: this condition is
                    // weaker than the name `LinkLocalScope` implies, and the
                    // prefix conditions on the same filters are what actually
                    // bound class 5 and class 9 to link-local space.
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint8: 1 },
                },
            },
        };
        arena.conditions.push(built);
    }
    Ok(())
}

const fn protocol_number(protocol: IpProtocol) -> u8 {
    protocol.number()
}

/// The `FWP_BYTE_BLOB`s an app-id or SID condition points at.
///
/// Separate from [`FilterArena`] because a blob is a struct the engine
/// dereferences *through* the condition, so it needs its own stable storage and
/// its pointer has to be written into the condition after both exist.
struct BlobArena {
    blobs: Vec<FWP_BYTE_BLOB>,
}

impl BlobArena {
    fn new(count: usize) -> Self {
        Self {
            blobs: Vec::with_capacity(count),
        }
    }
}

/// The SDDL of a descriptor whose DACL grants `FWP_ACTRL_MATCH_FILTER` to
/// exactly one SID. `CC` is the SDDL spelling of access bit 0x1, which is what
/// `FWP_ACTRL_MATCH_FILTER` is; the engine evaluates the condition as "does this
/// DACL grant that right to the caller's token" (`Permitting and Blocking
/// Applications and Users`, Microsoft Learn).
#[must_use]
pub fn match_filter_sddl(sid: &str) -> String {
    format!("D:(A;;CC;;;{sid})")
}

/// The self-relative security descriptor `FWPM_CONDITION_ALE_USER_ID` takes,
/// for one SID.
///
/// # Errors
///
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW`'s refusal, which is
/// what an empty or malformed SID produces — reported here, before the engine,
/// so the failure names the SID rather than the filter.
pub fn match_filter_descriptor(sid: &str) -> Result<Vec<u8>, PlatformError> {
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{GetSecurityDescriptorLength, PSECURITY_DESCRIPTOR};

    if sid.is_empty() {
        return Err(oserr::unavailable(
            "match_filter_descriptor: the SID is empty",
        ));
    }
    let sddl = wide(&match_filter_sddl(sid));
    let mut descriptor: PSECURITY_DESCRIPTOR = core::ptr::null_mut();
    let mut size: u32 = 0;
    // SAFETY: `sddl` is a live NUL-terminated wide string; `descriptor` and
    // `size` are live out-parameters. On success `descriptor` is LocalAlloc'd
    // memory the caller owns and frees below.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            &raw mut size,
        )
    };
    if ok == 0 || descriptor.is_null() {
        // SAFETY: plain thread-local read.
        let status = unsafe { GetLastError() };
        return Err(oserr::from_status(
            Win32Error(status),
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            Context::Enforcement,
        ));
    }
    // SAFETY: `descriptor` is a valid self-relative descriptor of `length`
    // bytes, which is copied out before the buffer is freed exactly once.
    let bytes = unsafe {
        let length = GetSecurityDescriptorLength(descriptor) as usize;
        let length = if length == 0 { size as usize } else { length };
        let copy = core::slice::from_raw_parts(descriptor.cast::<u8>(), length).to_vec();
        LocalFree(descriptor);
        copy
    };
    Ok(bytes)
}

/// The `FWPM_CONDITION_ALE_APP_ID` value for an executable: its lower-case NT
/// device path (`\device\harddiskvolumeN\...`), from
/// `FwpmGetAppIdFromFileName0`. A Win32 path in that condition matches
/// nothing, and an empty one is refused; the service derives its own from
/// `current_exe` at start.
///
/// # Errors
///
/// The engine's refusal — the file must exist on this machine.
pub fn app_id_for(path: &std::path::Path) -> Result<String, PlatformError> {
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    };

    let name = wide(&path.to_string_lossy());
    let mut blob: *mut FWP_BYTE_BLOB = core::ptr::null_mut();
    // SAFETY: `name` is a live NUL-terminated wide string; `blob` is a live
    // out-parameter the engine fills with memory it owns until freed below.
    let status = unsafe { FwpmGetAppIdFromFileName0(name.as_ptr(), &raw mut blob) };
    if status != 0 || blob.is_null() {
        return Err(oserr::from_status(
            Win32Error(status),
            "FwpmGetAppIdFromFileName0",
            Context::Enforcement,
        ));
    }
    // SAFETY: the blob is a UTF-16 string of `size` bytes (NUL included) that
    // the engine allocated; it is read once and freed exactly once.
    let app_id = unsafe {
        // Byte-wise, then paired: the engine's buffer carries no alignment
        // promise a `*const u16` could rely on.
        let bytes = core::slice::from_raw_parts((*blob).data, (*blob).size as usize);
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let text = super::wide_from_utf16(&units);
        FwpmFreeMemory0((&raw mut blob).cast::<*mut core::ffi::c_void>());
        text
    };
    Ok(app_id)
}

/// Fills in the app-id and SID condition pointers, now that both arenas exist.
fn link_blobs(spec: &FilterSpec, arena: &mut FilterArena, blobs: &mut BlobArena) {
    let mut app = 0usize;
    let mut sid = 0usize;
    for (index, condition) in spec.conditions.iter().enumerate() {
        match condition {
            Condition::AppId(_) => {
                let bytes = &mut arena.app_ids[app];
                blobs.blobs.push(FWP_BYTE_BLOB {
                    #[allow(clippy::cast_possible_truncation)]
                    size: (bytes.len() * 2) as u32,
                    data: bytes.as_mut_ptr().cast::<u8>(),
                });
                let slot = blobs.blobs.len() - 1;
                arena.conditions[index].conditionValue.Anonymous.byteBlob =
                    blobs.blobs.as_mut_ptr().wrapping_add(slot);
                app += 1;
            }
            Condition::UserSid(_) => {
                let bytes = &mut arena.sids[sid];
                blobs.blobs.push(FWP_BYTE_BLOB {
                    #[allow(clippy::cast_possible_truncation)]
                    size: bytes.len() as u32,
                    data: bytes.as_mut_ptr(),
                });
                let slot = blobs.blobs.len() - 1;
                arena.conditions[index].conditionValue.Anonymous.sd =
                    blobs.blobs.as_mut_ptr().wrapping_add(slot);
                sid += 1;
            }
            _ => {}
        }
    }
}

impl WfpEngine {
    /// Adds one filter inside an open transaction.
    fn add_filter(&self, spec: &FilterSpec, provider: &mut GUID) -> Result<(), PlatformError> {
        let mut arena = FilterArena::new(spec);
        build_conditions(spec, &mut arena)?;
        let blob_count = spec
            .conditions
            .iter()
            .filter(|c| matches!(c, Condition::AppId(_) | Condition::UserSid(_)))
            .count();
        let mut blobs = BlobArena::new(blob_count);
        link_blobs(spec, &mut arena, &mut blobs);

        let mut flags = 0u32;
        if spec.flags.persistent {
            flags |= FWPM_FILTER_FLAG_PERSISTENT;
        }
        if spec.flags.boot_time {
            flags |= FWPM_FILTER_FLAG_BOOTTIME;
        }

        let filter = FWPM_FILTER0 {
            filterKey: guid(spec.key),
            displayData: FWPM_DISPLAY_DATA0 {
                name: arena.name.as_mut_ptr(),
                description: core::ptr::null_mut(),
            },
            flags,
            providerKey: &raw mut *provider,
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: core::ptr::null_mut(),
            },
            layerKey: layer_guid(spec.layer),
            subLayerKey: guid(SUBLAYER_KEY),
            weight: FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    // The engine reads the weight through the pointer, so it
                    // has to point at storage that outlives the call.
                    uint64: core::ptr::null_mut(),
                },
            },
            #[allow(clippy::cast_possible_truncation)]
            numFilterConditions: arena.conditions.len() as u32,
            filterCondition: arena.conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: match spec.action {
                    Action::Block => FWP_ACTION_BLOCK,
                    Action::Permit => FWP_ACTION_PERMIT,
                },
                Anonymous: FWPM_ACTION0_0 {
                    filterType: GUID::from_u128(0),
                },
            },
            Anonymous:
                windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER0_0 {
                    rawContext: 0,
                },
            reserved: core::ptr::null_mut(),
            filterId: 0,
            effectiveWeight: FWP_VALUE0 {
                r#type: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_EMPTY,
                Anonymous: FWP_VALUE0_0 { uint8: 0 },
            },
        };
        let mut weight = spec.weight;
        let mut filter = filter;
        // The engine reads the weight through this pointer during the call, so
        // `weight` has to outlive it — it does, being a local of this function.
        filter.weight.Anonymous.uint64 = &raw mut weight;

        let mut id: u64 = 0;
        // SAFETY: every pointer in `filter` points into `arena`, `blobs`,
        // `provider` or `weight`, all of which are live for this call; `sd` null
        // takes the engine's default security descriptor; `id` is a live
        // out-parameter.
        let status = unsafe {
            FwpmFilterAdd0(
                self.handle(),
                &raw const filter,
                core::ptr::null_mut(),
                &raw mut id,
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(oserr::from_status(
                Win32Error(status),
                "FwpmFilterAdd0",
                Context::Enforcement,
            ))
        }
    }

    /// Ensures the provider and sublayer exist, and writes the generation blob.
    fn ensure_objects(&self, generation: u64, provider: &mut GUID) -> Result<(), PlatformError> {
        let mut name = wide("TwinVPN");
        let mut blob = generation.to_be_bytes();
        let record = FWPM_PROVIDER0 {
            providerKey: *provider,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: core::ptr::null_mut(),
            },
            // Persistent, so the provider survives a reboot and the filters that
            // reference it are still owner-tagged when BFE reinstates them.
            flags: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_PROVIDER_FLAG_PERSISTENT,
            providerData: FWP_BYTE_BLOB {
                #[allow(clippy::cast_possible_truncation)]
                size: blob.len() as u32,
                data: blob.as_mut_ptr(),
            },
            serviceName: core::ptr::null_mut(),
        };
        // SAFETY: every pointer in `record` points at storage live for this
        // call; `sd` null takes the engine default. `FwpmProviderAdd0` is
        // idempotent in effect here because the delete pass removed the previous
        // provider inside the same transaction.
        let status =
            unsafe { FwpmProviderAdd0(self.handle(), &raw const record, core::ptr::null_mut()) };
        if status != 0 && Win32Error(status).get() != oserr::FWP_E_ALREADY_EXISTS {
            return Err(oserr::from_status(
                Win32Error(status),
                "FwpmProviderAdd0",
                Context::Enforcement,
            ));
        }

        let mut sub_name = wide("TwinVPN");
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: guid(SUBLAYER_KEY),
            displayData: FWPM_DISPLAY_DATA0 {
                name: sub_name.as_mut_ptr(),
                description: core::ptr::null_mut(),
            },
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: &raw mut *provider,
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: core::ptr::null_mut(),
            },
            weight: SUBLAYER_WEIGHT,
        };
        // SAFETY: as above.
        let status =
            unsafe { FwpmSubLayerAdd0(self.handle(), &raw const sublayer, core::ptr::null_mut()) };
        if status != 0 && Win32Error(status).get() != oserr::FWP_E_ALREADY_EXISTS {
            return Err(oserr::from_status(
                Win32Error(status),
                "FwpmSubLayerAdd0",
                Context::Enforcement,
            ));
        }
        Ok(())
    }

    /// Every filter key the engine holds under our provider.
    fn owned_keys(&self) -> Result<Vec<Guid>, PlatformError> {
        Ok(self
            .enumerate()?
            .into_iter()
            .filter(|f| f.provider_owned)
            .map(|f| f.key)
            .collect())
    }

    /// The filter rows, ours and not.
    ///
    /// Enumerates **without** a provider template so that a third party's
    /// filters are visible to the caller — `read()` reports them with
    /// `provider_owned: false`, which is what lets `readback` refuse to count
    /// them and what lets a diagnostic bundle say who else is filtering.
    fn enumerate(&self) -> Result<Vec<InstalledFilter>, PlatformError> {
        let mut out = Vec::new();
        for layer in Layer::BOTH {
            self.enumerate_layer(layer, &mut out)?;
        }
        Ok(out)
    }

    /// One layer's filter rows, appended to `out`.
    ///
    /// The template names the layer because the engine requires one: a null
    /// `layerKey` is `FWP_E_LAYER_NOT_FOUND`, not "every layer". It asks for
    /// boot-time filters explicitly because the engine omits them by default,
    /// and the KS-19 boot artifact is exactly what `read` must count and
    /// `purge` must remove.
    fn enumerate_layer(
        &self,
        layer: Layer,
        out: &mut Vec<InstalledFilter>,
    ) -> Result<(), PlatformError> {
        let mut enum_handle: HANDLE = core::ptr::null_mut();
        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            providerKey: core::ptr::null_mut(),
            layerKey: layer_guid(layer),
            enumType: FWP_FILTER_ENUM_FULLY_CONTAINED,
            flags: FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME,
            providerContextTemplate: core::ptr::null_mut(),
            numFilterConditions: 0,
            filterCondition: core::ptr::null_mut(),
            actionMask: u32::MAX,
            calloutKey: core::ptr::null_mut(),
        };
        // SAFETY: `template` is live for the call; `enum_handle` is a live
        // out-parameter.
        let status = unsafe {
            FwpmFilterCreateEnumHandle0(self.handle(), &raw const template, &raw mut enum_handle)
        };
        if status != 0 {
            return Err(oserr::from_status(
                Win32Error(status),
                "FwpmFilterCreateEnumHandle0",
                Context::Enforcement,
            ));
        }
        let guard = EnumGuard {
            engine: self.handle(),
            handle: enum_handle,
            kind: EnumKind::Filter,
        };

        let ours = guid(PROVIDER_KEY);
        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = core::ptr::null_mut();
            let mut returned: u32 = 0;
            // SAFETY: both out-parameters are live; the engine owns the returned
            // array until `FwpmFreeMemory0`.
            let status = unsafe {
                FwpmFilterEnum0(
                    self.handle(),
                    guard.handle,
                    ENUM_BATCH,
                    &raw mut entries,
                    &raw mut returned,
                )
            };
            if status != 0 {
                return Err(oserr::from_status(
                    Win32Error(status),
                    "FwpmFilterEnum0",
                    Context::Enforcement,
                ));
            }
            if returned == 0 {
                break;
            }
            for index in 0..returned as usize {
                // SAFETY: `entries` points at `returned` pointers, each to a
                // filter the engine filled in.
                let filter = unsafe { &**entries.add(index) };
                let provider_owned = !filter.providerKey.is_null()
                    // SAFETY: checked non-null immediately above.
                    && guid_eq(unsafe { *filter.providerKey }, ours);
                // The template already restricts the rows to `layer`; a row
                // from anywhere else is skipped rather than mapped, because
                // reporting it as ours would make the read-back lie.
                if !guid_eq(filter.layerKey, layer_guid(layer)) {
                    continue;
                }
                out.push(InstalledFilter {
                    key: ours_key(filter.filterKey),
                    layer,
                    action: if filter.action.r#type == FWP_ACTION_BLOCK {
                        Action::Block
                    } else {
                        Action::Permit
                    },
                    provider_owned,
                });
            }
            // SAFETY: `entries` was allocated by the engine and has not been
            // freed.
            unsafe {
                FwpmFreeMemory0((&raw mut entries).cast());
            }
            if returned < ENUM_BATCH {
                break;
            }
        }
        Ok(())
    }
}

const fn ours_key(g: GUID) -> Guid {
    ours(g)
}

/// Which enumeration a guard closes.
enum EnumKind {
    Filter,
    NetEvent,
}

/// Closes an enumeration handle however the block exits.
struct EnumGuard {
    engine: HANDLE,
    handle: HANDLE,
    kind: EnumKind,
}

impl Drop for EnumGuard {
    fn drop(&mut self) {
        // SAFETY: the handle came from the matching `Create*EnumHandle0` and has
        // not been destroyed.
        unsafe {
            match self.kind {
                EnumKind::Filter => {
                    FwpmFilterDestroyEnumHandle0(self.engine, self.handle);
                }
                EnumKind::NetEvent => {
                    FwpmNetEventDestroyEnumHandle0(self.engine, self.handle);
                }
            }
        }
    }
}

impl WfpEngine {
    /// Everything [`FilterEngine::commit`] does up to the commit itself: the
    /// transaction is returned open, and the caller commits it or drops it,
    /// which aborts. One body for the real swap and for the dry run, so the
    /// dry run cannot validate a different set of calls than the swap makes.
    fn stage(&self, set: &FilterSet) -> Result<Transaction<'_>, PlatformError> {
        // A set that fails its own validation never reaches the engine. The
        // caller checks this too; checking again here is what keeps the shim
        // honest if a second caller ever appears.
        set.validate().map_err(|defect| {
            tracing::error!(defect = %defect, "a filter set violated its own invariants");
            oserr::unavailable("FilterSet::validate")
        })?;

        let txn = Transaction::begin(self)?;
        let mut provider = guid(PROVIDER_KEY);

        // Delete every owner-tagged filter, then add the new set, then write the
        // generation — all inside the one transaction, so the host never holds
        // an intermediate state (KS-17) and the swap is a swap rather than a
        // remove-then-add (KS-23).
        for key in self.owned_keys()? {
            // The trait's one exception: the KS-19 boot artifact survives a
            // runtime commit. A boot key the incoming set also carries is
            // replaced inside this transaction instead, because
            // `FwpmFilterAdd0` refuses a duplicate key rather than overwriting.
            if crate::wfp::boot::is_boot_filter(key) && !set.filters.iter().any(|f| f.key == key) {
                continue;
            }
            let key = guid(key);
            // SAFETY: `key` is live for the call.
            let status = unsafe { FwpmFilterDeleteByKey0(self.handle(), &raw const key) };
            if status != 0 && Win32Error(status).get() != oserr::FWP_E_FILTER_NOT_FOUND {
                return Err(oserr::from_status(
                    Win32Error(status),
                    "FwpmFilterDeleteByKey0",
                    Context::Enforcement,
                ));
            }
        }
        self.ensure_objects(set.generation, &mut provider)?;
        for spec in &set.filters {
            self.add_filter(spec, &mut provider)?;
        }
        Ok(txn)
    }
}

impl FilterEngine for WfpEngine {
    fn commit(&self, set: &FilterSet) -> Result<(), PlatformError> {
        self.stage(set)?.commit()
    }

    fn dry_run(&self, set: &FilterSet) -> Result<(), PlatformError> {
        // Dropping the open transaction is the abort (see `Drop for
        // Transaction`); every `FwpmFilterAdd0` has already run its validation.
        self.stage(set).map(drop)
    }

    fn read(&self) -> Result<EngineState, PlatformError> {
        let filters = self.enumerate()?;

        let key = guid(SUBLAYER_KEY);
        let mut sublayer: *mut FWPM_SUBLAYER0 = core::ptr::null_mut();
        // SAFETY: `key` is live; `sublayer` is a live out-parameter the engine
        // fills with memory it owns.
        let status =
            unsafe { FwpmSubLayerGetByKey0(self.handle(), &raw const key, &raw mut sublayer) };
        let sublayer_present = match status {
            0 => {
                // SAFETY: the engine allocated it and we have not freed it.
                unsafe { FwpmFreeMemory0((&raw mut sublayer).cast()) };
                true
            }
            s if Win32Error(s).get() == oserr::FWP_E_SUBLAYER_NOT_FOUND => false,
            s => {
                return Err(oserr::from_status(
                    Win32Error(s),
                    "FwpmSubLayerGetByKey0",
                    Context::Enforcement,
                ))
            }
        };

        let pkey = guid(PROVIDER_KEY);
        let mut provider: *mut FWPM_PROVIDER0 = core::ptr::null_mut();
        // SAFETY: as above.
        let status =
            unsafe { FwpmProviderGetByKey0(self.handle(), &raw const pkey, &raw mut provider) };
        let provider_data = match status {
            0 => {
                // SAFETY: the call succeeded, so `provider` points at a record
                // the engine filled in.
                let record = unsafe { &*provider };
                let data = if record.providerData.data.is_null() {
                    None
                } else {
                    // SAFETY: `data` is non-null and `size` bytes long, as the
                    // engine reported them.
                    Some(
                        unsafe {
                            core::slice::from_raw_parts(
                                record.providerData.data,
                                record.providerData.size as usize,
                            )
                        }
                        .to_vec(),
                    )
                };
                // SAFETY: the engine allocated it and we have not freed it.
                unsafe { FwpmFreeMemory0((&raw mut provider).cast()) };
                data
            }
            s if Win32Error(s).get() == oserr::FWP_E_PROVIDER_NOT_FOUND => None,
            s => {
                return Err(oserr::from_status(
                    Win32Error(s),
                    "FwpmProviderGetByKey0",
                    Context::Enforcement,
                ))
            }
        };

        Ok(EngineState {
            sublayer_present,
            provider_data,
            filters,
        })
    }

    fn net_events(&self) -> Result<(Vec<NetEvent>, bool), PlatformError> {
        let template = FWPM_NET_EVENT_ENUM_TEMPLATE0 {
            startTime: windows_sys::Win32::Foundation::FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            },
            endTime: windows_sys::Win32::Foundation::FILETIME {
                dwLowDateTime: u32::MAX,
                dwHighDateTime: i32::MAX as u32,
            },
            numFilterConditions: 0,
            filterCondition: core::ptr::null_mut(),
        };
        let mut enum_handle: HANDLE = core::ptr::null_mut();
        // SAFETY: `template` is live; `enum_handle` is a live out-parameter.
        let status = unsafe {
            FwpmNetEventCreateEnumHandle0(self.handle(), &raw const template, &raw mut enum_handle)
        };
        if status != 0 {
            return Err(oserr::from_status(
                Win32Error(status),
                "FwpmNetEventCreateEnumHandle0",
                Context::Enforcement,
            ));
        }
        let guard = EnumGuard {
            engine: self.handle(),
            handle: enum_handle,
            kind: EnumKind::NetEvent,
        };

        let mut out = Vec::new();
        let mut truncated = false;
        loop {
            let mut entries: *mut *mut FWPM_NET_EVENT2 = core::ptr::null_mut();
            let mut returned: u32 = 0;
            // SAFETY: both out-parameters are live.
            let status = unsafe {
                FwpmNetEventEnum2(
                    self.handle(),
                    guard.handle,
                    ENUM_BATCH,
                    &raw mut entries,
                    &raw mut returned,
                )
            };
            if status != 0 {
                return Err(oserr::from_status(
                    Win32Error(status),
                    "FwpmNetEventEnum2",
                    Context::Enforcement,
                ));
            }
            if returned == 0 {
                break;
            }
            for index in 0..returned as usize {
                // SAFETY: `entries` points at `returned` pointers, each to an
                // event the engine filled in.
                let event = unsafe { &**entries.add(index) };
                let family = if event.header.ipVersion == FWP_IP_VERSION_V4 {
                    AddressFamily::V4
                } else {
                    AddressFamily::V6
                };
                let (kind, filter_id) = if event.r#type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
                    // SAFETY: the discriminant says this arm is the live one.
                    let drop = unsafe { event.Anonymous.classifyDrop };
                    if drop.is_null() {
                        continue;
                    }
                    // SAFETY: checked non-null.
                    (NetEventKind::ClassifyDrop, unsafe { (*drop).filterId })
                } else if event.r#type == FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW {
                    // SAFETY: the discriminant says this arm is the live one.
                    let allow = unsafe { event.Anonymous.classifyAllow };
                    if allow.is_null() {
                        continue;
                    }
                    // SAFETY: checked non-null.
                    (NetEventKind::ClassifyAllow, unsafe { (*allow).filterId })
                } else {
                    continue;
                };
                out.push(NetEvent {
                    kind,
                    family,
                    filter: self.key_of(filter_id),
                });
            }
            // SAFETY: engine-allocated and not yet freed.
            unsafe {
                FwpmFreeMemory0((&raw mut entries).cast());
            }
            if returned >= ENUM_BATCH {
                // The engine had at least a full batch waiting. That is not
                // proof it dropped anything, but it is the only signal this API
                // gives, and reporting it as loss is the safe direction:
                // `canary_verdict` answers `Indeterminate` rather than `Denied`.
                truncated = true;
            } else {
                break;
            }
        }
        Ok((out, truncated))
    }

    fn purge(&self) -> Result<(), PlatformError> {
        let txn = Transaction::begin(self)?;
        for key in self.owned_keys()? {
            let key = guid(key);
            // SAFETY: `key` is live for the call.
            let status = unsafe { FwpmFilterDeleteByKey0(self.handle(), &raw const key) };
            if status != 0 && Win32Error(status).get() != oserr::FWP_E_FILTER_NOT_FOUND {
                return Err(oserr::from_status(
                    Win32Error(status),
                    "FwpmFilterDeleteByKey0",
                    Context::Enforcement,
                ));
            }
        }
        let sub = guid(SUBLAYER_KEY);
        // SAFETY: `sub` is live for the call.
        let status = unsafe { FwpmSubLayerDeleteByKey0(self.handle(), &raw const sub) };
        if status != 0 && Win32Error(status).get() != oserr::FWP_E_SUBLAYER_NOT_FOUND {
            return Err(oserr::from_status(
                Win32Error(status),
                "FwpmSubLayerDeleteByKey0",
                Context::Enforcement,
            ));
        }
        let prov = guid(PROVIDER_KEY);
        // SAFETY: `prov` is live for the call.
        let status = unsafe { FwpmProviderDeleteByKey0(self.handle(), &raw const prov) };
        if status != 0 && Win32Error(status).get() != oserr::FWP_E_PROVIDER_NOT_FOUND {
            return Err(oserr::from_status(
                Win32Error(status),
                "FwpmProviderDeleteByKey0",
                Context::Enforcement,
            ));
        }
        txn.commit()
    }
}

impl WfpEngine {
    /// The filter key one runtime filter id names, or `None`.
    ///
    /// A **query**, not a cache: `FWPM_NET_EVENT_CLASSIFY_DROP2` carries a
    /// `filterId`, which is a runtime number the engine assigns, and the canary
    /// fold works on keys. Resolving it per event keeps K12's discipline — a
    /// cache built at commit time would go stale the moment BFE reinstated a
    /// persistent filter after a reboot with a new id.
    ///
    /// `None` for an id the engine does not know (a filter deleted since the
    /// event) or one belonging to another provider, which the fold counts as
    /// unattributed rather than charging to us.
    fn key_of(&self, filter_id: u64) -> Option<Guid> {
        let mut filter: *mut FWPM_FILTER0 = core::ptr::null_mut();
        // SAFETY: `filter` is a live out-parameter the engine fills with memory
        // it owns.
        let status = unsafe { FwpmFilterGetById0(self.handle(), filter_id, &raw mut filter) };
        if status != 0 {
            return None;
        }
        // SAFETY: the call succeeded, so `filter` points at a record.
        let key = unsafe { (*filter).filterKey };
        // SAFETY: engine-allocated and not yet freed.
        unsafe { FwpmFreeMemory0((&raw mut filter).cast()) };
        Some(ours(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_match_filter_sddl_grants_access_bit_one_to_the_sid_alone() {
        // 0x1 is FWP_ACTRL_MATCH_FILTER, spelled `CC` in SDDL.
        assert_eq!(match_filter_sddl("S-1-5-80-0"), "D:(A;;CC;;;S-1-5-80-0)");
    }

    #[test]
    fn a_real_sid_becomes_a_self_relative_descriptor_and_an_empty_one_is_refused() {
        // LocalSystem: a SID every Windows host resolves without a lookup.
        let bytes = match_filter_descriptor("S-1-5-18").expect("a well-known SID converts");
        // SECURITY_DESCRIPTOR_RELATIVE: revision 1, then Sbz1, then Control
        // with SE_SELF_RELATIVE (0x8000) set; the DACL follows the header.
        assert_eq!(bytes[0], 1, "revision");
        assert_ne!(
            u16::from_le_bytes([bytes[2], bytes[3]]) & 0x8000,
            0,
            "self-relative"
        );
        assert!(
            bytes.len() > 20,
            "a header plus a one-ACE DACL: {}",
            bytes.len()
        );
        assert!(
            match_filter_descriptor("").is_err(),
            "an empty SID must be refused, not sent"
        );
        assert!(match_filter_descriptor("not a sid").is_err());
    }

    #[test]
    fn the_app_id_of_this_test_binary_is_its_lower_case_device_path() {
        let exe = std::env::current_exe().expect("this test has a path");
        let app_id = app_id_for(&exe).expect("the engine resolves an existing file");
        assert!(app_id.starts_with("\\device\\"), "{app_id}");
        assert_eq!(app_id, app_id.to_lowercase(), "{app_id}");
        assert!(
            std::path::Path::new(&app_id)
                .extension()
                .is_some_and(|e| e == "exe"),
            "{app_id}"
        );
        assert!(app_id_for(std::path::Path::new(r"C:\no\such\file.exe")).is_err());
    }
}
