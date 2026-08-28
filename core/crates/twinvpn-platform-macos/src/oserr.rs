//! `errno`, `OSStatus` and `SCError` → [`PlatformError`], and the one place this
//! crate turns an OS number into a name.
//!
//! **Authority:** ADR-0018 F-4 ("errors carry a name, never an errno"),
//! `docs/implementation/ownership.md` §4.2 and §6 rule 12,
//! [`twinvpn_platform::error`].
//!
//! # The rule, and why it is one module
//!
//! > Never expose a raw unexplained OS error as the complete user-facing error:
//! > map every internal error into a registered `reason_code`, carry the platform
//! > detail as typed `Evidence`, and never let an `errno` be the whole story.
//!
//! [`PlatformError`] already makes the second half structural — no variant can
//! carry only an integer. What is left is the *mapping*. macOS has **three**
//! numeric error vocabularies rather than one, so there are three entry points
//! and one `Context`, and a reviewer asking "what does this adapter do with
//! `errSecInteractionNotAllowed`" reads one `match`.
//!
//! # Target-free on purpose
//!
//! Every constant here is either a `libc` symbol (whose *value* differs between
//! Linux and Darwin but whose *meaning* does not, so a symbolic match is correct
//! on both) or a Darwin constant written out with its own value and a citation.
//! Nothing in this module is `cfg`-gated, so all of it executes under `cargo test`
//! on the Linux host.

use std::io;

use twinvpn_platform::{OsDetail, PlatformError};

/// The last `errno`, as an [`OsDetail`] tagged with the call that produced it.
///
/// `call` is a **stable, non-localised tag** — `"bind"`, `"RTM_NEWADDR"`,
/// `"SecItemCopyMatching"` — not user-visible text. CB-4 keeps every rendered
/// string out of the core, so this is a name a support case greps for.
#[must_use]
pub fn detail(err: &io::Error, call: &'static str) -> OsDetail {
    OsDetail {
        code: i64::from(err.raw_os_error().unwrap_or(0)),
        call,
    }
}

/// A detail from a bare numeric code.
#[must_use]
pub const fn detail_from_code(code: i64, call: &'static str) -> OsDetail {
    OsDetail { code, call }
}

/// What the caller was doing when the OS refused.
///
/// Not a severity and not a component: it is the disambiguator the number itself
/// does not carry. The same `EPERM` from `bind` is a privilege problem and from a
/// route program is `ROUTE.PROGRAMMING_DENIED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Context {
    /// A socket call.
    Socket,
    /// A `PF_ROUTE` socket read, or an interface enumeration.
    RouteSocket,
    /// `utun` creation, or the `NEPacketTunnelFlow` handed to the provider.
    TunnelDevice,
    /// Address or route programming.
    RouteProgram,
    /// The `pf` anchor.
    Enforcement,
    /// Resolver configuration — `SCDynamicStore` or the tunnel settings object.
    Resolver,
    /// Tier-1 secure storage (the Keychain).
    SecureStore,
    /// An identity operation inside the element.
    Identity,
    /// An IOKit power-management call.
    Power,
}

// ---------------------------------------------------------------------------
// Darwin numeric vocabularies
//
// Written out with their values rather than taken from a sys crate, for two
// reasons. They must be readable on the Linux host so the mapping is TESTED
// rather than merely compiled; and `security-framework-sys` /
// `system-configuration-sys` are `cfg(target_os = "macos")` dependencies of this
// crate, so naming them here would make the mapping itself Darwin-only.
// ---------------------------------------------------------------------------

/// `OSStatus` values from `Security/SecBase.h` that this adapter distinguishes.
///
/// A value not named here falls through to the context default, which is the
/// safe direction: an unrecognised Keychain failure is "the secure store is
/// unavailable", never "the item is absent".
pub mod sec {
    /// `errSecSuccess`.
    pub const SUCCESS: i64 = 0;
    /// `errSecUnimplemented`.
    pub const UNIMPLEMENTED: i64 = -4;
    /// `errSecIO`.
    pub const IO: i64 = -36;
    /// `errSecOpWr` — the file is already open with write permission.
    pub const OP_WR: i64 = -49;
    /// `errSecParam`.
    pub const PARAM: i64 = -50;
    /// `errSecAllocate`.
    pub const ALLOCATE: i64 = -108;
    /// `errSecUserCanceled`.
    pub const USER_CANCELED: i64 = -128;
    /// `errSecNotAvailable` — no keychain is available.
    pub const NOT_AVAILABLE: i64 = -25291;
    /// `errSecAuthFailed`.
    pub const AUTH_FAILED: i64 = -25293;
    /// `errSecDuplicateItem`.
    pub const DUPLICATE_ITEM: i64 = -25299;
    /// `errSecItemNotFound` — **absent, which is not an error** at the seam.
    pub const ITEM_NOT_FOUND: i64 = -25300;
    /// `errSecInteractionNotAllowed` — the device has not been unlocked since
    /// boot, or the item's accessibility class forbids access right now.
    pub const INTERACTION_NOT_ALLOWED: i64 = -25308;
    /// `errSecDecode`.
    pub const DECODE: i64 = -26275;
    /// `errSecMissingEntitlement`.
    pub const MISSING_ENTITLEMENT: i64 = -34018;
}

/// `SCError` values from `SystemConfiguration/SystemConfiguration.h`.
pub mod sc {
    /// `kSCStatusOK`.
    pub const OK: i64 = 0;
    /// `kSCStatusFailed`.
    pub const FAILED: i64 = 1001;
    /// `kSCStatusInvalidArgument`.
    pub const INVALID_ARGUMENT: i64 = 1002;
    /// `kSCStatusAccessError` — permission denied.
    pub const ACCESS_ERROR: i64 = 1003;
    /// `kSCStatusNoKey` — the key does not exist.
    pub const NO_KEY: i64 = 1004;
    /// `kSCStatusKeyExists`.
    pub const KEY_EXISTS: i64 = 1005;
    /// `kSCStatusLocked`.
    pub const LOCKED: i64 = 1006;
    /// `kSCStatusNeedLock`.
    pub const NEED_LOCK: i64 = 1007;
    /// `kSCStatusNoStoreSession` — the configuration daemon session is gone.
    pub const NO_STORE_SESSION: i64 = 1009;
    /// `kSCStatusNoStoreServer` — `configd` is not reachable.
    pub const NO_STORE_SERVER: i64 = 1010;
    /// `kSCStatusNotifierActive`.
    pub const NOTIFIER_ACTIVE: i64 = 1011;
    /// `kSCStatusNoLink`.
    pub const NO_LINK: i64 = 1015;
    /// `kSCStatusStale` — the configuration changed under us.
    pub const STALE: i64 = 1016;
    /// `kSCStatusReachabilityUnknown`.
    pub const REACHABILITY_UNKNOWN: i64 = 1018;
}

/// `NEVPNError` values from `NetworkExtension/NEVPNConnection.h`.
///
/// Reached only through the shell, which forwards the provider's `NSError` code;
/// mapped here so the shell has no failure vocabulary of its own.
pub mod ne {
    /// `NEVPNErrorConfigurationInvalid`.
    pub const CONFIGURATION_INVALID: i64 = 1;
    /// `NEVPNErrorConfigurationDisabled`.
    pub const CONFIGURATION_DISABLED: i64 = 2;
    /// `NEVPNErrorConnectionFailed`.
    pub const CONNECTION_FAILED: i64 = 3;
    /// `NEVPNErrorConfigurationStale`.
    pub const CONFIGURATION_STALE: i64 = 4;
    /// `NEVPNErrorConfigurationReadWriteFailed`.
    pub const CONFIGURATION_READ_WRITE_FAILED: i64 = 5;
    /// `NEVPNErrorConfigurationUnknown`.
    pub const CONFIGURATION_UNKNOWN: i64 = 6;
}

/// Maps one POSIX error onto the seam's failure vocabulary.
///
/// # Why the mapping is coarse on purpose
///
/// ADR-0015 §11.2's admission rule refuses a new code for a condition an existing
/// one owns, and [`PlatformError`] is deliberately narrower than `errno`. So
/// several numbers land on one variant and the number itself rides along in
/// [`OsDetail`] — the split §4.2 asks for: the *name* is TwinVPN's, the *number*
/// is supporting evidence.
#[must_use]
// Several arms coincide, and each is written out rather than merged: a reviewer
// asking "what does this adapter do with ENOENT while opening the utun control"
// must be able to find that arm, and merging two contexts that happen to share a
// mapping today would hide it when one of them changes.
#[allow(clippy::match_same_arms)]
pub fn from_errno(err: &io::Error, call: &'static str, context: Context) -> PlatformError {
    let d = Some(detail(err, call));
    let raw = err.raw_os_error().unwrap_or(0);
    match raw {
        // Interrupted and would-block are the caller's to retry; they are never a
        // fault of the platform and never a reason to give up on a path.
        libc::EINTR | libc::EAGAIN | libc::EBUSY | libc::ENOBUFS | libc::ENOMEM => {
            PlatformError::Transient(d)
        }
        libc::ECANCELED => PlatformError::Cancelled,
        libc::EPERM | libc::EACCES => match context {
            Context::RouteProgram => PlatformError::RouteProgrammingDenied(d),
            Context::SecureStore => PlatformError::SecureStoreUnavailable(d),
            Context::Identity => PlatformError::IdentityKeyUnavailable(d),
            // `PF_SYSTEM`/`SYSPROTO_CONTROL` refused, or `NEPacketTunnelProvider`
            // without its entitlement, is the closest macOS has to the OS's VPN
            // grant: its remediation is "approve the extension", not "run as
            // root". PS-18 makes the absence a startup failure either way.
            Context::TunnelDevice => PlatformError::VpnPermissionDenied(d),
            Context::Socket
            | Context::RouteSocket
            | Context::Enforcement
            | Context::Resolver
            | Context::Power => PlatformError::NotPermitted(d),
        },
        libc::ENETUNREACH | libc::EHOSTUNREACH => PlatformError::NoRoute(d),
        libc::ENETDOWN | libc::ENXIO | libc::ENODEV => PlatformError::InterfaceDown(d),
        libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::ENOPROTOOPT | libc::EOPNOTSUPP => {
            PlatformError::OsUnsupported(d)
        }
        libc::EEXIST | libc::EADDRINUSE => match context {
            // Another product holding the same anchor or the same utun unit is
            // the one condition Darwin reports that maps cleanly onto ADR-0012
            // §11.11's coexistence story.
            Context::Enforcement | Context::TunnelDevice => {
                PlatformError::ThirdPartyFilterSuspected(d)
            }
            _ => PlatformError::Transient(d),
        },
        libc::ENOENT => match context {
            Context::SecureStore => PlatformError::SecureStoreUnavailable(d),
            Context::RouteProgram => PlatformError::RouteProgrammingDenied(d),
            _ => PlatformError::AdapterUnavailable(d),
        },
        _ => match context {
            Context::RouteProgram => PlatformError::RouteProgrammingDenied(d),
            Context::SecureStore => PlatformError::SecureStoreUnavailable(d),
            Context::Identity => PlatformError::IdentityKeyUnavailable(d),
            _ => PlatformError::AdapterUnavailable(d),
        },
    }
}

/// Maps a Security.framework `OSStatus` onto the seam's failure vocabulary.
///
/// **`errSecItemNotFound` is deliberately not mapped here.** At the seam,
/// "absent" is `Ok(None)` and not an error: [`twinvpn_platform::SecureStore`]'s
/// contract says the distinction matters "because 'absent' enrols and
/// 'unavailable' must not". A caller checks for it before calling this.
#[must_use]
#[allow(clippy::match_same_arms)]
pub fn from_os_status(status: i64, call: &'static str, context: Context) -> PlatformError {
    let d = Some(detail_from_code(status, call));
    match status {
        sec::INTERACTION_NOT_ALLOWED | sec::AUTH_FAILED | sec::USER_CANCELED => match context {
            Context::Identity => PlatformError::IdentityKeyUnavailable(d),
            _ => PlatformError::SecureStoreUnavailable(d),
        },
        // No keychain at all, and a build whose entitlement the OS did not
        // honour. The second is PS-18's condition and the shell turns it into a
        // startup refusal rather than a degraded run.
        sec::NOT_AVAILABLE | sec::MISSING_ENTITLEMENT => match context {
            Context::Identity => PlatformError::IdentityKeyUnavailable(d),
            _ => PlatformError::SecureStoreUnavailable(d),
        },
        sec::UNIMPLEMENTED => PlatformError::OsUnsupported(d),
        sec::ALLOCATE => PlatformError::Transient(d),
        sec::DUPLICATE_ITEM | sec::OP_WR => PlatformError::Transient(d),
        // `errSecItemNotFound` reaching this function at all means a caller asked
        // for a mapping of a condition the seam expresses as `Ok(None)`. Reported
        // as store-unavailable rather than silently as success, because a silent
        // success here would make a missing SEK look like a first run.
        sec::ITEM_NOT_FOUND => PlatformError::SecureStoreUnavailable(d),
        sec::SUCCESS => PlatformError::AdapterUnavailable(d),
        _ => match context {
            Context::Identity => PlatformError::IdentityKeyUnavailable(d),
            _ => PlatformError::SecureStoreUnavailable(d),
        },
    }
}

/// Maps a `SystemConfiguration` `SCError` onto the seam's failure vocabulary.
#[must_use]
#[allow(clippy::match_same_arms)]
pub fn from_sc_error(status: i64, call: &'static str, context: Context) -> PlatformError {
    let d = Some(detail_from_code(status, call));
    match status {
        sc::ACCESS_ERROR => PlatformError::NotPermitted(d),
        // `configd` gone is transient by nature: it is restarted by `launchd`, and
        // the reconciler's retry is the right response.
        sc::NO_STORE_SESSION | sc::NO_STORE_SERVER | sc::STALE | sc::NEED_LOCK | sc::LOCKED => {
            PlatformError::Transient(d)
        }
        sc::NO_LINK => PlatformError::InterfaceDown(d),
        sc::REACHABILITY_UNKNOWN => PlatformError::Transient(d),
        // A key that does not exist is a fact about the store, not a failure of
        // the adapter — but at the DNS layer it means the service we were told to
        // program is gone, which is a resolver failure the core must see.
        sc::NO_KEY | sc::KEY_EXISTS => match context {
            Context::Resolver => PlatformError::AdapterUnavailable(d),
            _ => PlatformError::Transient(d),
        },
        sc::OK => PlatformError::AdapterUnavailable(d),
        sc::FAILED | sc::INVALID_ARGUMENT | sc::NOTIFIER_ACTIVE => {
            PlatformError::AdapterUnavailable(d)
        }
        _ => PlatformError::AdapterUnavailable(d),
    }
}

/// Maps a `NEVPNError` the shell forwarded from the provider.
///
/// The shell holds no failure vocabulary of its own (CB-2), so an `NSError` code
/// crossing the bridge lands here rather than being interpreted in Swift.
#[must_use]
pub fn from_ne_error(code: i64, call: &'static str) -> PlatformError {
    let d = Some(detail_from_code(code, call));
    match code {
        ne::CONFIGURATION_DISABLED | ne::CONFIGURATION_INVALID => {
            PlatformError::VpnPermissionDenied(d)
        }
        ne::CONFIGURATION_STALE | ne::CONNECTION_FAILED => PlatformError::Transient(d),
        ne::CONFIGURATION_READ_WRITE_FAILED | ne::CONFIGURATION_UNKNOWN => {
            PlatformError::AdapterUnavailable(d)
        }
        _ => PlatformError::AdapterUnavailable(d),
    }
}

/// A shorthand for "the OS refused and there is no `errno`" — a tool that exited
/// non-zero, output that did not parse.
///
/// Still not a bare string: the caller supplies the registered *condition* and
/// `call` names the mechanism for a support case.
#[must_use]
pub const fn unavailable(call: &'static str, code: i32) -> PlatformError {
    PlatformError::AdapterUnavailable(Some(detail_from_code(code as i64, call)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(code: i32) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    #[test]
    fn a_route_refusal_is_not_reported_as_a_generic_adapter_failure() {
        let e = from_errno(&err(libc::EPERM), "RTM_ADD", Context::RouteProgram);
        assert_eq!(e.reason_code().as_str(), "ROUTE.PROGRAMMING_DENIED");
    }

    #[test]
    fn the_utun_control_being_refused_is_the_vpn_grant_not_root() {
        // On macOS the entitlement, not the uid, is what the user grants. PS-18
        // makes its absence a startup failure either way.
        let e = from_errno(&err(libc::EPERM), "connect(utun)", Context::TunnelDevice);
        assert_eq!(e.reason_code().as_str(), "PLATFORM.VPN_PERMISSION_DENIED");
    }

    #[test]
    fn every_mapped_errno_keeps_the_number_as_evidence_and_never_as_the_story() {
        for code in [libc::EPERM, libc::ENETUNREACH, libc::EAFNOSUPPORT, 12345] {
            let e = from_errno(&err(code), "probe", Context::Socket);
            assert!(e.reason_code().as_str().contains('.'));
            assert_eq!(e.os_detail().map(|d| d.code), Some(i64::from(code)));
            assert_eq!(e.os_detail().map(|d| d.call), Some("probe"));
        }
    }

    #[test]
    fn a_locked_keychain_is_the_identity_key_being_unavailable_not_a_store_fault() {
        // ADR-0020's macOS system-extension row: the item is
        // `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, so a Mac rebooted
        // with no console login cannot open Tier 1 until someone unlocks it. That
        // is a NAMED condition, not a generic failure.
        let e = from_os_status(
            sec::INTERACTION_NOT_ALLOWED,
            "SecItemCopyMatching",
            Context::Identity,
        );
        assert_eq!(e.reason_code().as_str(), "AUTH.KEY_UNAVAILABLE");
        assert_eq!(e.os_detail().map(|d| d.code), Some(-25308));

        let store = from_os_status(
            sec::INTERACTION_NOT_ALLOWED,
            "SecItemCopyMatching",
            Context::SecureStore,
        );
        assert_eq!(store.reason_code().as_str(), "AUTH.KEY_STORE_UNAVAILABLE");
    }

    #[test]
    fn a_missing_entitlement_is_named_and_never_softened_into_a_retry() {
        let e = from_os_status(sec::MISSING_ENTITLEMENT, "SecItemAdd", Context::SecureStore);
        assert_eq!(e.reason_code().as_str(), "AUTH.KEY_STORE_UNAVAILABLE");
        // PS-18: the shell turns this into a startup refusal. It must never look
        // like something a backoff will fix.
        assert!(!matches!(e, PlatformError::Transient(_)));
    }

    #[test]
    fn configd_being_absent_is_transient_because_launchd_restarts_it() {
        for code in [sc::NO_STORE_SERVER, sc::NO_STORE_SESSION, sc::STALE] {
            let e = from_sc_error(code, "SCDynamicStoreCreate", Context::Resolver);
            assert!(
                matches!(e, PlatformError::Transient(_)),
                "SCError {code} should be transient"
            );
        }
    }

    #[test]
    fn an_sc_access_error_is_a_privilege_refusal_and_not_an_adapter_fault() {
        let e = from_sc_error(
            sc::ACCESS_ERROR,
            "SCDynamicStoreSetValue",
            Context::Resolver,
        );
        assert_eq!(e.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
        assert!(matches!(e, PlatformError::NotPermitted(_)));
    }

    #[test]
    fn a_disabled_ne_configuration_is_the_vpn_grant() {
        let e = from_ne_error(ne::CONFIGURATION_DISABLED, "startTunnel");
        assert_eq!(e.reason_code().as_str(), "PLATFORM.VPN_PERMISSION_DENIED");
    }

    #[test]
    fn an_unsupported_family_is_reported_as_a_host_fact_not_substituted() {
        // `SocketProvider::bind_udp`'s contract: `OsUnsupported` is a FACT about
        // the host. Substituting another family is how a v6-only network silently
        // becomes a v4-only session.
        let e = from_errno(&err(libc::EAFNOSUPPORT), "socket", Context::Socket);
        assert_eq!(e.reason_code().as_str(), "PLATFORM.OS_UNSUPPORTED");
    }

    /// **The same finding `twinvpn-platform-linux` pinned, re-checked here.**
    ///
    /// `PlatformError::is_retryable` asks the registry for the code's class, and
    /// every code a `PlatformError` can produce is `PERSISTENT` or `FATAL` under
    /// the frozen registry. So `EAGAIN` — the most retryable condition a socket
    /// has — reports `is_retryable() == false`. This adapter therefore never
    /// drives a backoff off `is_retryable()`; it returns the variant and lets the
    /// core decide, which is CB-2's direction anyway.
    #[test]
    fn no_platform_error_is_retryable_under_the_frozen_registry() {
        let transient = from_errno(&err(libc::EAGAIN), "recvmsg", Context::Socket);
        assert!(matches!(transient, PlatformError::Transient(_)));
        assert!(
            !transient.is_retryable(),
            "if this ever passes, a TRANSIENT PLATFORM code was registered and \
             this test and its finding should be deleted"
        );
    }
}
