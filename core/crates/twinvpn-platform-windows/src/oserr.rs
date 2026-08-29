//! `WIN32_ERROR` → [`PlatformError`], and the one place this crate turns an OS
//! number into a name.
//!
//! **Authority:** ADR-0018 F-4 ("errors carry a name, never an errno"),
//! `docs/implementation/ownership.md` §4.2 and §6 rule 12, ADR-0020 ST-32a
//! ("every fallible store operation yields `{reason_code, evidence}`, never a
//! raw platform status"), [`twinvpn_platform::error`].
//!
//! # The rule, and why it is one function
//!
//! > Never expose a raw unexplained OS error as the complete user-facing error:
//! > map every internal error into a registered `reason_code`, carry the platform
//! > detail as typed `Evidence`, and never let an `errno` be the whole story.
//!
//! [`PlatformError`] already makes the second half structural — no variant can
//! carry only an integer. What is left is the *mapping*, and it lives here so
//! that a reviewer asking "what does this adapter do with `ERROR_ACCESS_DENIED`"
//! reads one `match` rather than searching for a `GetLastError` call.
//!
//! # Three number spaces, one type
//!
//! Windows returns failures in three shapes and this crate must not confuse them:
//!
//! | Space | Shape | Example |
//! |---|---|---|
//! | `WIN32_ERROR` | small unsigned | `ERROR_ACCESS_DENIED` = 5 |
//! | Winsock | 10000-range unsigned | `WSAEAFNOSUPPORT` = 10047 |
//! | `HRESULT` / `NTSTATUS` | `0x8032xxxx`, `0x8009xxxx` — **negative as `i32`** | `FWP_E_ALREADY_EXISTS` = `0x80320009` |
//!
//! [`Win32Error`] holds the **raw 32-bit pattern as `u32`**, and
//! [`Win32Error::as_evidence`] widens it into [`OsDetail::code`] unsigned. A
//! sign-extended `HRESULT` in a support bundle reads as `-2144206839`, which
//! nobody can look up; `2150629385` is at least a stable number whose hex form
//! is `0x80320009`. Stated here rather than left to the reader of a log.
//!
//! # This module is target-free, deliberately
//!
//! Every constant below is a literal, not a `windows-sys` import, so the whole
//! mapping **compiles and its tests run on a Linux host**. That is the discipline
//! `twinvpn-platform-linux`'s `nft.rs` establishes: the layer that decides what
//! an error *means* has no reason to need the OS that produced it. The literals
//! are asserted against `windows-sys`'s own constants in `sys::win`
//! under `#[cfg(windows)]`, so a drifted value fails `make cross-check` rather
//! than silently mapping the wrong condition.

use twinvpn_platform::{OsDetail, PlatformError};

/// A raw Windows status, in whichever of the three number spaces produced it.
///
/// A newtype rather than a bare `u32` so that "this is an OS status" is visible
/// at every call site, and so the widening in [`Self::as_evidence`] happens in
/// exactly one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Win32Error(pub u32);

impl Win32Error {
    /// Wraps the value an `i32`-returning API produced, preserving the bit
    /// pattern rather than the sign.
    #[must_use]
    // The cast is the whole point: an `HRESULT` is a bit pattern, and reading it
    // as a signed integer is what produces the unlookupable `-2144206839` this
    // type exists to avoid. `cast_sign_loss` is exactly the transformation being
    // asked for.
    #[allow(clippy::cast_sign_loss)]
    pub const fn from_i32(value: i32) -> Self {
        Self(value as u32)
    }

    /// The raw pattern.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Whether this is an `HRESULT`/`NTSTATUS` rather than a `WIN32_ERROR` —
    /// the severity bit is set.
    #[must_use]
    pub const fn is_hresult(self) -> bool {
        self.0 & 0x8000_0000 != 0
    }

    /// Whether this is a Windows Filtering Platform status (`FWP_E_*`), whose
    /// facility is `0x032`.
    #[must_use]
    pub const fn is_fwp(self) -> bool {
        self.0 & 0xFFFF_0000 == 0x8032_0000
    }

    /// The detail carried alongside the name, never instead of it.
    #[must_use]
    pub const fn as_evidence(self, call: &'static str) -> OsDetail {
        OsDetail {
            code: self.0 as i64,
            call,
        }
    }
}

/// What the caller was doing when Windows refused.
///
/// Not a severity and not a component: it is the disambiguator the status number
/// does not carry. `ERROR_ACCESS_DENIED` from `CreateIpForwardEntry2` is
/// `ROUTE.PROGRAMMING_DENIED`; the same number from `WintunCreateAdapter` is the
/// VPN grant, whose remediation is a different sentence entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Context {
    /// A Winsock call.
    Socket,
    /// The Wintun adapter or the tunnel session.
    TunnelDevice,
    /// IP Helper address, route or interface programming.
    RouteProgram,
    /// The WFP engine, a sublayer, a provider or a filter.
    Enforcement,
    /// NRPT policy or `SetInterfaceDnsSettings`.
    Resolver,
    /// Interface enumeration or a change subscription.
    InterfaceQuery,
    /// DPAPI-NG or the vault directory.
    SecureStore,
    /// A CNG key operation.
    Identity,
}

/// `ERROR_INVALID_FUNCTION`.
pub const ERROR_INVALID_FUNCTION: u32 = 1;
/// `ERROR_FILE_NOT_FOUND`.
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
/// `ERROR_PATH_NOT_FOUND`.
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
/// `ERROR_ACCESS_DENIED`.
pub const ERROR_ACCESS_DENIED: u32 = 5;
/// `ERROR_INVALID_HANDLE`.
pub const ERROR_INVALID_HANDLE: u32 = 6;
/// `ERROR_NOT_ENOUGH_MEMORY`.
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
/// `ERROR_OUTOFMEMORY`.
pub const ERROR_OUTOFMEMORY: u32 = 14;
/// `ERROR_NOT_READY`.
pub const ERROR_NOT_READY: u32 = 21;
/// `ERROR_SHARING_VIOLATION`.
pub const ERROR_SHARING_VIOLATION: u32 = 32;
/// `ERROR_NOT_SUPPORTED`.
pub const ERROR_NOT_SUPPORTED: u32 = 50;
/// `ERROR_DEV_NOT_EXIST`.
pub const ERROR_DEV_NOT_EXIST: u32 = 55;
/// `ERROR_ADAP_HDW_ERR`.
pub const ERROR_ADAP_HDW_ERR: u32 = 57;
/// `ERROR_NETWORK_ACCESS_DENIED`.
pub const ERROR_NETWORK_ACCESS_DENIED: u32 = 65;
/// `ERROR_INVALID_PARAMETER`.
pub const ERROR_INVALID_PARAMETER: u32 = 87;
/// `ERROR_SEM_TIMEOUT`.
pub const ERROR_SEM_TIMEOUT: u32 = 121;
/// `ERROR_INSUFFICIENT_BUFFER`.
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
/// `ERROR_MOD_NOT_FOUND` — `wintun.dll` is not beside the binary.
pub const ERROR_MOD_NOT_FOUND: u32 = 126;
/// `ERROR_PROC_NOT_FOUND` — the DLL loaded but is the wrong version.
pub const ERROR_PROC_NOT_FOUND: u32 = 127;
/// `ERROR_BUSY`.
pub const ERROR_BUSY: u32 = 170;
/// `ERROR_ALREADY_EXISTS`.
pub const ERROR_ALREADY_EXISTS: u32 = 183;
/// `ERROR_BAD_EXE_FORMAT` — a 32-bit Wintun beside a 64-bit service.
pub const ERROR_BAD_EXE_FORMAT: u32 = 193;
/// `ERROR_ELEVATION_REQUIRED`.
pub const ERROR_ELEVATION_REQUIRED: u32 = 740;
/// `ERROR_OPERATION_ABORTED`.
pub const ERROR_OPERATION_ABORTED: u32 = 995;
/// `ERROR_IO_PENDING`.
pub const ERROR_IO_PENDING: u32 = 997;
/// `ERROR_NOT_FOUND`.
pub const ERROR_NOT_FOUND: u32 = 1168;
/// `ERROR_NO_NETWORK`.
pub const ERROR_NO_NETWORK: u32 = 1222;
/// `ERROR_CANCELLED`.
pub const ERROR_CANCELLED: u32 = 1223;
/// `ERROR_NETWORK_UNREACHABLE`.
pub const ERROR_NETWORK_UNREACHABLE: u32 = 1231;
/// `ERROR_HOST_UNREACHABLE`.
pub const ERROR_HOST_UNREACHABLE: u32 = 1232;
/// `ERROR_NOT_ALL_ASSIGNED` — a privilege the token does not hold.
pub const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;
/// `ERROR_PRIVILEGE_NOT_HELD`.
pub const ERROR_PRIVILEGE_NOT_HELD: u32 = 1314;
/// `ERROR_NO_SYSTEM_RESOURCES`.
pub const ERROR_NO_SYSTEM_RESOURCES: u32 = 1450;
/// `ERROR_TIMEOUT`.
pub const ERROR_TIMEOUT: u32 = 1460;
/// `ERROR_OBJECT_ALREADY_EXISTS`.
pub const ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;

/// `WSAEINTR`.
pub const WSAEINTR: u32 = 10004;
/// `WSAEACCES`.
pub const WSAEACCES: u32 = 10013;
/// `WSAEINVAL`.
pub const WSAEINVAL: u32 = 10022;
/// `WSAEMFILE`.
pub const WSAEMFILE: u32 = 10024;
/// `WSAEWOULDBLOCK`.
pub const WSAEWOULDBLOCK: u32 = 10035;
/// `WSAEMSGSIZE`.
pub const WSAEMSGSIZE: u32 = 10040;
/// `WSAENOPROTOOPT`.
pub const WSAENOPROTOOPT: u32 = 10042;
/// `WSAEPROTONOSUPPORT`.
pub const WSAEPROTONOSUPPORT: u32 = 10043;
/// `WSAEOPNOTSUPP`.
pub const WSAEOPNOTSUPP: u32 = 10045;
/// `WSAEAFNOSUPPORT`.
pub const WSAEAFNOSUPPORT: u32 = 10047;
/// `WSAEADDRINUSE`.
pub const WSAEADDRINUSE: u32 = 10048;
/// `WSAEADDRNOTAVAIL`.
pub const WSAEADDRNOTAVAIL: u32 = 10049;
/// `WSAENETDOWN`.
pub const WSAENETDOWN: u32 = 10050;
/// `WSAENETUNREACH`.
pub const WSAENETUNREACH: u32 = 10051;
/// `WSAECONNRESET`.
pub const WSAECONNRESET: u32 = 10054;
/// `WSAENOBUFS`.
pub const WSAENOBUFS: u32 = 10055;
/// `WSAEHOSTUNREACH`.
pub const WSAEHOSTUNREACH: u32 = 10065;
/// `WSASYSNOTREADY`.
pub const WSASYSNOTREADY: u32 = 10091;

/// `FWP_E_FILTER_NOT_FOUND`.
pub const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0003;
/// `FWP_E_PROVIDER_NOT_FOUND`.
pub const FWP_E_PROVIDER_NOT_FOUND: u32 = 0x8032_0005;
/// `FWP_E_SUBLAYER_NOT_FOUND`.
pub const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x8032_0007;
/// `FWP_E_NOT_FOUND`.
pub const FWP_E_NOT_FOUND: u32 = 0x8032_0008;
/// `FWP_E_ALREADY_EXISTS`.
pub const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;
/// `FWP_E_IN_USE`.
pub const FWP_E_IN_USE: u32 = 0x8032_000A;
/// `FWP_E_TXN_IN_PROGRESS`.
pub const FWP_E_TXN_IN_PROGRESS: u32 = 0x8032_000E;
/// `FWP_E_TXN_ABORTED`.
pub const FWP_E_TXN_ABORTED: u32 = 0x8032_000F;
/// `FWP_E_SESSION_ABORTED`.
pub const FWP_E_SESSION_ABORTED: u32 = 0x8032_0010;
/// `FWP_E_TIMEOUT`.
pub const FWP_E_TIMEOUT: u32 = 0x8032_0012;

/// `NTE_NO_KEY`.
pub const NTE_NO_KEY: u32 = 0x8009_000D;
/// `NTE_PERM`.
pub const NTE_PERM: u32 = 0x8009_0010;
/// `NTE_BAD_KEYSET` — CNG has no key container of that name.
pub const NTE_BAD_KEYSET: u32 = 0x8009_0016;
/// `NTE_NOT_FOUND`.
pub const NTE_NOT_FOUND: u32 = 0x8009_002A;
/// `NTE_DEVICE_NOT_READY` — the TPM is present but not usable.
pub const NTE_DEVICE_NOT_READY: u32 = 0x8009_002D;

/// Maps one Windows status onto the seam's failure vocabulary.
///
/// # Why the mapping is coarse on purpose
///
/// ADR-0015 §11.2's admission rule refuses a new code for a condition an
/// existing one owns, and [`PlatformError`] is deliberately narrower than
/// Windows' status space. So several numbers land on one variant, and the number
/// itself rides along in [`OsDetail`] — which is exactly the split §4.2 asks
/// for: the *name* is TwinVPN's, the *number* is supporting evidence.
#[must_use]
// Several arms coincide, and each is written out rather than merged: a reviewer
// asking "what does this adapter do with ERROR_ACCESS_DENIED while opening the
// filter engine" must be able to find that arm, and merging two contexts that
// happen to share a mapping today would hide it when one of them changes.
#[allow(clippy::match_same_arms)]
#[allow(clippy::too_many_lines)]
pub fn from_status(status: Win32Error, call: &'static str, context: Context) -> PlatformError {
    let d = Some(status.as_evidence(call));
    match status.get() {
        // Retryable conditions. Reported as `Transient`, which since Amendment 2
        // names `PLATFORM.ADAPTER_BUSY` — TRANSIENT, non-terminal — and no
        // longer the PERSISTENT `ADAPTER_UNAVAILABLE` that W-40 recorded; the
        // tripwire below guards that. Under CB-2 the adapter still only reports
        // and the core still rules on the recovery, so what matters here is that
        // "try again" is not collapsed into "refused".
        ERROR_BUSY
        | ERROR_NOT_ENOUGH_MEMORY
        | ERROR_OUTOFMEMORY
        | ERROR_NO_SYSTEM_RESOURCES
        | ERROR_SEM_TIMEOUT
        | ERROR_TIMEOUT
        | ERROR_IO_PENDING
        | ERROR_SHARING_VIOLATION
        | WSAEINTR
        | WSAEWOULDBLOCK
        | WSAENOBUFS
        | WSAEMFILE
        | FWP_E_TXN_IN_PROGRESS
        | FWP_E_TIMEOUT => PlatformError::Transient(d),

        ERROR_OPERATION_ABORTED | ERROR_CANCELLED => PlatformError::Cancelled,

        // A privileged refusal. Which name it gets depends entirely on what the
        // caller was doing, because "Windows said no" is not a remediation.
        ERROR_ACCESS_DENIED
        | ERROR_NETWORK_ACCESS_DENIED
        | ERROR_PRIVILEGE_NOT_HELD
        | ERROR_NOT_ALL_ASSIGNED
        | ERROR_ELEVATION_REQUIRED
        | WSAEACCES
        | NTE_PERM => match context {
            Context::RouteProgram => PlatformError::RouteProgrammingDenied(d),
            Context::SecureStore => PlatformError::SecureStoreUnavailable(d),
            Context::Identity => PlatformError::IdentityKeyUnavailable(d),
            // Wintun refuses adapter creation to a token without
            // `SeLoadDriverPrivilege` (ADR-0016 §11.9's trimmed list keeps
            // exactly that one), which is the closest Windows has to the OS's
            // VPN grant: it is what a user sees when the service is not the one
            // the MSI installed, and its remediation is "reinstall the service",
            // not "run it as Administrator by hand".
            Context::TunnelDevice => PlatformError::VpnPermissionDenied(d),
            Context::Socket
            | Context::Enforcement
            | Context::Resolver
            | Context::InterfaceQuery => PlatformError::NotPermitted(d),
        },

        ERROR_NETWORK_UNREACHABLE | ERROR_HOST_UNREACHABLE | WSAENETUNREACH | WSAEHOSTUNREACH => {
            PlatformError::NoRoute(d)
        }

        ERROR_NO_NETWORK | ERROR_DEV_NOT_EXIST | ERROR_ADAP_HDW_ERR | ERROR_NOT_READY
        | WSAENETDOWN | WSASYSNOTREADY => PlatformError::InterfaceDown(d),

        ERROR_NOT_SUPPORTED
        | ERROR_INVALID_FUNCTION
        | ERROR_BAD_EXE_FORMAT
        | ERROR_PROC_NOT_FOUND
        | WSAEAFNOSUPPORT
        | WSAEPROTONOSUPPORT
        | WSAENOPROTOOPT
        | WSAEOPNOTSUPP => PlatformError::OsUnsupported(d),

        // Another product holding the same sublayer weight, the same filter key
        // or the same address is the condition that maps onto ADR-0018 §11.11's
        // coexistence story and ADR-0012 K11's requirement to coexist. On
        // Windows this is the ordinary case, not the exotic one: every consumer
        // VPN and every endpoint-protection product installs WFP filters.
        ERROR_ALREADY_EXISTS
        | ERROR_OBJECT_ALREADY_EXISTS
        | FWP_E_ALREADY_EXISTS
        | FWP_E_IN_USE
        | WSAEADDRINUSE => match context {
            Context::Enforcement | Context::TunnelDevice => {
                PlatformError::ThirdPartyFilterSuspected(d)
            }
            _ => PlatformError::Transient(d),
        },

        // `ERROR_MOD_NOT_FOUND` is Wintun's DLL missing beside the binary, which
        // is a packaging failure and not a user's problem to solve; it is
        // reported as the adapter being unavailable so PS-18 makes the service
        // refuse to start rather than run without a datapath.
        ERROR_MOD_NOT_FOUND
        | ERROR_FILE_NOT_FOUND
        | ERROR_PATH_NOT_FOUND
        | ERROR_NOT_FOUND
        | FWP_E_NOT_FOUND
        | FWP_E_FILTER_NOT_FOUND
        | FWP_E_SUBLAYER_NOT_FOUND
        | FWP_E_PROVIDER_NOT_FOUND => match context {
            Context::SecureStore => PlatformError::SecureStoreUnavailable(d),
            Context::RouteProgram => PlatformError::RouteProgrammingDenied(d),
            Context::Identity => PlatformError::IdentityKeyUnavailable(d),
            _ => PlatformError::AdapterUnavailable(d),
        },

        // A CNG status, and **the context decides which condition it is**.
        //
        // This arm used to be context-free, and `desktop-windows`'s custody work
        // caught what that cost: DPAPI-NG returns the same `NTE_*` values as a
        // key operation, so a Tier-1 *store* failure reported
        // `AUTH.KEY_UNAVAILABLE` — `PERSISTENT`/`ERROR` — where the registry has
        // `AUTH.KEY_STORE_UNAVAILABLE` at `TRANSIENT`/`WARN`. A momentarily
        // unavailable protector read to the core as a permanently missing
        // identity, which routes ADR-0020's recovery ladder to L4 (re-enrolment)
        // instead of a retry. Two codes, two classes, two remediations: the
        // disambiguator is the one `Context` already carries.
        NTE_BAD_KEYSET | NTE_NOT_FOUND | NTE_NO_KEY | NTE_DEVICE_NOT_READY => match context {
            Context::SecureStore => PlatformError::SecureStoreUnavailable(d),
            _ => PlatformError::IdentityKeyUnavailable(d),
        },

        // The WFP session went away underneath us. That is **not** "no rules" —
        // once committed, the filters belong to the Base Filtering Engine and
        // not to our session (ADR-0012 §11.6's Windows row), and CB-6 makes the
        // difference matter: the OS still holds the ruleset.
        FWP_E_TXN_ABORTED | FWP_E_SESSION_ABORTED => PlatformError::AdapterUnavailable(d),

        _ => match context {
            Context::RouteProgram => PlatformError::RouteProgrammingDenied(d),
            Context::SecureStore => PlatformError::SecureStoreUnavailable(d),
            Context::Identity => PlatformError::IdentityKeyUnavailable(d),
            _ => PlatformError::AdapterUnavailable(d),
        },
    }
}

/// The shorthand for "a call failed and there is no status to read" — a DLL
/// entry point that returned `NULL` with `GetLastError` reporting success, a
/// buffer that did not parse.
///
/// Still not a bare string: the caller supplies the mechanism's name, and the
/// number `0` is honest about there being none.
#[must_use]
pub const fn unavailable(call: &'static str) -> PlatformError {
    PlatformError::AdapterUnavailable(Some(OsDetail { code: 0, call }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_route_refusal_is_not_reported_as_a_generic_adapter_failure() {
        let e = from_status(
            Win32Error(ERROR_ACCESS_DENIED),
            "CreateIpForwardEntry2",
            Context::RouteProgram,
        );
        assert_eq!(e.reason_code().as_str(), "ROUTE.PROGRAMMING_DENIED");
    }

    #[test]
    fn wintun_being_refused_is_the_vpn_grant_and_not_run_as_administrator() {
        let e = from_status(
            Win32Error(ERROR_ACCESS_DENIED),
            "WintunCreateAdapter",
            Context::TunnelDevice,
        );
        assert_eq!(e.reason_code().as_str(), "PLATFORM.VPN_PERMISSION_DENIED");
    }

    #[test]
    fn a_wfp_object_collision_is_the_coexistence_condition_and_names_it() {
        // ADR-0012 K11 requires enforcement to coexist with host firewalls,
        // endpoint-security filters and other VPNs. On Windows a sublayer weight
        // or filter-key collision is the ordinary case, not the exotic one, and
        // it must not read as "our code is broken".
        for status in [FWP_E_ALREADY_EXISTS, FWP_E_IN_USE, ERROR_ALREADY_EXISTS] {
            let e = from_status(Win32Error(status), "FwpmSubLayerAdd0", Context::Enforcement);
            assert_eq!(
                e.reason_code().as_str(),
                "PLATFORM.THIRD_PARTY_FILTER_SUSPECTED",
                "{status:#x}"
            );
        }
    }

    #[test]
    fn every_mapped_status_keeps_the_number_as_evidence_and_never_as_the_story() {
        for status in [
            ERROR_ACCESS_DENIED,
            ERROR_NETWORK_UNREACHABLE,
            WSAEAFNOSUPPORT,
            FWP_E_ALREADY_EXISTS,
            0x1234_5678,
        ] {
            let e = from_status(Win32Error(status), "probe", Context::Socket);
            // The user-facing name is TwinVPN's...
            assert!(e.reason_code().as_str().contains('.'));
            // ...and the number is still reachable for a Tier-1 bundle.
            assert_eq!(e.os_detail().map(|d| d.code), Some(i64::from(status)));
            assert_eq!(e.os_detail().map(|d| d.call), Some("probe"));
        }
    }

    #[test]
    fn an_hresult_is_carried_unsigned_so_a_support_case_can_look_it_up() {
        // Sign-extended, `FWP_E_ALREADY_EXISTS` reads as -2144206839 in a
        // bundle, which matches nothing anybody can search for.
        let raw = Win32Error::from_i32(-2_144_206_839_i32);
        assert_eq!(raw.get(), FWP_E_ALREADY_EXISTS);
        assert!(raw.is_hresult());
        assert!(raw.is_fwp());
        assert_eq!(raw.as_evidence("FwpmFilterAdd0").code, 0x8032_0009);
        // A plain WIN32_ERROR is neither, and a CNG status is an HRESULT that is
        // not the filtering platform's.
        assert!(!Win32Error(ERROR_ACCESS_DENIED).is_hresult());
        assert!(Win32Error(NTE_BAD_KEYSET).is_hresult());
        assert!(!Win32Error(NTE_BAD_KEYSET).is_fwp());
    }

    #[test]
    fn an_unsupported_family_is_reported_as_a_host_fact_and_never_substituted() {
        // `SocketProvider::bind_udp`'s contract: `OsUnsupported` is a FACT about
        // the host, reported so the core can decide. Substituting another family
        // is how a v6-only network silently becomes a v4-only session.
        let e = from_status(Win32Error(WSAEAFNOSUPPORT), "socket", Context::Socket);
        assert_eq!(e.reason_code().as_str(), "PLATFORM.OS_UNSUPPORTED");
    }

    #[test]
    fn a_missing_wintun_dll_is_an_adapter_failure_and_not_a_permission_problem() {
        // The remediation is "reinstall the package", which is a different
        // sentence from "grant the service a privilege". Mapping both onto one
        // code would send a user down the wrong path.
        let e = from_status(
            Win32Error(ERROR_MOD_NOT_FOUND),
            "LoadLibraryExW(wintun.dll)",
            Context::TunnelDevice,
        );
        assert_eq!(e.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
    }

    #[test]
    fn a_cng_key_that_is_gone_is_an_identity_failure_in_every_context() {
        for status in [NTE_BAD_KEYSET, NTE_NO_KEY, NTE_DEVICE_NOT_READY] {
            let e = from_status(Win32Error(status), "NCryptOpenKey", Context::Identity);
            assert_eq!(
                e.reason_code().as_str(),
                "AUTH.KEY_UNAVAILABLE",
                "{status:#x}"
            );
        }
    }

    #[test]
    fn a_dpapi_ng_failure_is_a_store_condition_and_not_a_missing_identity() {
        // DPAPI-NG returns the same `NTE_*` values a key operation does, and the
        // two conditions have different classes and different remediations:
        // `AUTH.KEY_STORE_UNAVAILABLE` is TRANSIENT/WARN and the caller retries,
        // `AUTH.KEY_UNAVAILABLE` is PERSISTENT/ERROR and ADR-0020's ladder goes
        // to L4 — re-enrolment. Reporting the second for the first would make a
        // momentarily unavailable protector look like a lost device.
        for status in [
            NTE_BAD_KEYSET,
            NTE_NOT_FOUND,
            NTE_NO_KEY,
            NTE_DEVICE_NOT_READY,
        ] {
            assert_eq!(
                from_status(
                    Win32Error(status),
                    "NCryptUnprotectSecret",
                    Context::SecureStore
                )
                .reason_code()
                .as_str(),
                "AUTH.KEY_STORE_UNAVAILABLE",
                "{status:#x}"
            );
            assert_eq!(
                from_status(Win32Error(status), "NCryptSignHash", Context::Identity)
                    .reason_code()
                    .as_str(),
                "AUTH.KEY_UNAVAILABLE",
                "{status:#x}"
            );
        }
    }

    #[test]
    fn an_aborted_wfp_session_does_not_read_as_the_rules_being_gone() {
        // CB-6: once committed, the filters are BFE's. Losing the session means
        // this adapter cannot speak to the engine; it does not mean the host is
        // unprotected, and reporting it as a route or enforcement *failure*
        // would invite exactly the wrong recovery.
        let e = from_status(
            Win32Error(FWP_E_SESSION_ABORTED),
            "FwpmTransactionCommit0",
            Context::Enforcement,
        );
        assert_eq!(e.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
    }

    /// **W-40, closed — inverted, not deleted; full note in
    /// `twinvpn-platform-linux`. Authority:** `contracts/FROZEN` Amendment 2
    /// (`registry_version` 3), `ownership.md` §8 (W-40, and W-18's rule that a
    /// tripwire keeps guarding the fixed behaviour), `reliability.md` §3.1/§6.1.
    ///
    /// It first asserted `!transient.is_retryable()`; that is deleted, since
    /// §3.1 makes `class` the only retry authority — which left this mapping as
    /// the only one and made W-40 load-bearing. Amendment 2 registered
    /// `PLATFORM.ADAPTER_BUSY` and `PlatformError::Transient` names it, so the
    /// assertion inverts: a `WSAEWOULDBLOCK` reaches the core undecided per CB-2
    /// **and** names a `TRANSIENT`, non-terminal code — both, because a re-point
    /// fixing only the class would still tell the core the attempt had ended.
    #[test]
    fn a_retryable_status_reaches_the_core_as_transient_and_names_a_transient_code() {
        let transient = from_status(Win32Error(WSAEWOULDBLOCK), "WSARecvFrom", Context::Socket);
        // The adapter's half: the condition is reported, undecided, for the core.
        assert!(matches!(transient, PlatformError::Transient(_)));
        // The registry's half, which W-40 was.
        let code = transient.reason_code();
        assert_eq!(code.as_str(), "PLATFORM.ADAPTER_BUSY");
        assert_eq!(
            code.class(),
            twinvpn_types::ErrorClass::Transient,
            "a WSAEWOULDBLOCK must name a TRANSIENT-class code: §6.1's backoff \
             reads `class`, and it is the only retry authority left"
        );
        assert!(!code.terminal(), "may succeed if repeated");
        // `ADAPTER_UNAVAILABLE` keeps its own meaning — could not be *opened* —
        // which `a_missing_wintun_dll_is_an_adapter_failure…` above still pins.
    }

    #[test]
    fn a_status_with_no_number_is_still_a_named_condition() {
        let e = unavailable("WintunGetAdapterLUID");
        assert_eq!(e.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
        assert_eq!(e.os_detail().map(|d| d.call), Some("WintunGetAdapterLUID"));
    }
}
