//! OS error → [`PlatformError`], and the only place this crate interprets a
//! number the OS gave it.
//!
//! **Authority:** ADR-0018 F-4 ("errors carry a name, never an errno"),
//! `docs/implementation/ownership.md` §4.2 and §6 rule 12,
//! [`twinvpn_platform::error`], `twinvpn-platform-linux::oserr` (the precedent
//! this module follows deliberately).
//!
//! # The rule, and why it is one module
//!
//! > Never expose a raw unexplained OS error as the complete user-facing error:
//! > map every internal error into a registered `reason_code`, carry the platform
//! > detail as typed `Evidence`, and never let an `errno` be the whole story.
//!
//! [`PlatformError`] already makes the second half structural. What is left is
//! the *mapping*, and iOS has **three** number spaces rather than Linux's one:
//!
//! | Space | Where it comes from | Entry point |
//! |---|---|---|
//! | POSIX `errno` | BSD sockets, `getifaddrs`, file I/O beneath the vended store root | [`from_errno`] |
//! | `OSStatus` | `Security.framework` — every Keychain and Secure Enclave call | [`from_os_status`] |
//! | `NEVPNError` | `NetworkExtension` — profile install, provider start, settings apply | [`from_ne_vpn_error`] |
//!
//! All three are **target-free**: they are `match` statements over `i32`, so they
//! compile and their tests run on the Linux build host exactly as
//! `twinvpn-platform-linux`'s nftables renderer does. That is
//! `ownership.md` §10.3's design rule applied to the layer that most often gets
//! written in Swift by accident.
//!
//! # Why the constants are transcribed rather than imported
//!
//! `security-framework-sys` is an `[target.'cfg(target_os = "ios")']` dependency,
//! so importing `errSecItemNotFound` from it would make this module — and its
//! tests — reachable only on a Darwin builder. The values are transcribed from
//! Apple's `SecBase.h` and `NEVPNConnection.h` and are **stable public ABI**;
//! each is named at its definition so a reviewer can check it against the header
//! rather than against a comment. [`crate::sys`] asserts, on a Darwin build, that
//! the transcriptions still agree with the real headers — so a drift fails
//! `make cross-check` rather than mis-mapping a Keychain refusal on a device.

use std::io;

use twinvpn_platform::{OsDetail, PlatformError};

// ---------------------------------------------------------------------------
// OSStatus — Security.framework. Transcribed from `SecBase.h`.
// ---------------------------------------------------------------------------

/// `errSecSuccess` — the call succeeded.
pub const ERR_SEC_SUCCESS: i32 = 0;
/// `errSecUnimplemented` — the function is not implemented on this platform.
pub const ERR_SEC_UNIMPLEMENTED: i32 = -4;
/// `errSecDiskFull`.
pub const ERR_SEC_DISK_FULL: i32 = -34;
/// `errSecIO` — an I/O error on the keychain's backing store.
pub const ERR_SEC_IO: i32 = -36;
/// `errSecOpWr` — the file is already open with write permission.
pub const ERR_SEC_OP_WR: i32 = -49;
/// `errSecParam` — one or more parameters were not valid.
pub const ERR_SEC_PARAM: i32 = -50;
/// `errSecWrPerm` — write permission denied.
pub const ERR_SEC_WR_PERM: i32 = -61;
/// `errSecAllocate` — memory allocation failed.
pub const ERR_SEC_ALLOCATE: i32 = -108;
/// `errSecUserCanceled` — the user cancelled the operation.
pub const ERR_SEC_USER_CANCELED: i32 = -128;
/// `errSecNotAvailable` — no keychain is available (the device may be locked
/// before first unlock).
pub const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
/// `errSecReadOnly` — the keychain is read-only.
pub const ERR_SEC_READ_ONLY: i32 = -25292;
/// `errSecAuthFailed` — authentication or authorization failed.
pub const ERR_SEC_AUTH_FAILED: i32 = -25293;
/// `errSecDuplicateItem` — the item already exists.
pub const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
/// `errSecItemNotFound` — no such item. **Absent, not unavailable.**
pub const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
/// `errSecBufferTooSmall`.
pub const ERR_SEC_BUFFER_TOO_SMALL: i32 = -25301;
/// `errSecDataTooLarge` — the value exceeds what the item type accepts.
pub const ERR_SEC_DATA_TOO_LARGE: i32 = -25302;
/// `errSecInteractionNotAllowed` — **the locked-device state**. The item exists
/// and its protection class makes it unreadable right now.
pub const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
/// `errSecKeySizeNotAllowed`.
pub const ERR_SEC_KEY_SIZE_NOT_ALLOWED: i32 = -25311;
/// `errSecDecode` — the item could not be decoded.
pub const ERR_SEC_DECODE: i32 = -26275;
/// `errSecMissingEntitlement` — the app-group or keychain-sharing entitlement is
/// absent from the signed binary.
pub const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

// ---------------------------------------------------------------------------
// NEVPNError — NetworkExtension. Transcribed from `NEVPNConnection.h`.
// ---------------------------------------------------------------------------

/// `NEVPNErrorConfigurationInvalid`.
pub const NE_VPN_CONFIGURATION_INVALID: i32 = 1;
/// `NEVPNErrorConfigurationDisabled` — the profile exists and the user turned it
/// off, which is a **grant** condition and not an adapter failure.
pub const NE_VPN_CONFIGURATION_DISABLED: i32 = 2;
/// `NEVPNErrorConnectionFailed`.
pub const NE_VPN_CONNECTION_FAILED: i32 = 3;
/// `NEVPNErrorConfigurationStale` — the in-memory profile is behind the one in
/// preferences and must be reloaded before it is saved.
pub const NE_VPN_CONFIGURATION_STALE: i32 = 4;
/// `NEVPNErrorConfigurationReadWriteFailed` — commonly the user declining the
/// system consent sheet at profile install.
pub const NE_VPN_CONFIGURATION_READ_WRITE_FAILED: i32 = 5;
/// `NEVPNErrorConfigurationUnknown`.
pub const NE_VPN_CONFIGURATION_UNKNOWN: i32 = 6;

/// What the caller was doing when the OS refused.
///
/// Not a severity and not a component: it is the disambiguator the number itself
/// does not carry. The same `errSecInteractionNotAllowed` means "the vault is
/// locked" from the store and "IK cannot sign right now" from the element, and
/// those have different remediations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Context {
    /// A BSD socket call.
    Socket,
    /// `getifaddrs`, `if_nametoindex`, or an `NWPathMonitor` callback.
    Interfaces,
    /// `NEPacketTunnelProvider` lifecycle, or `NEPacketTunnelFlow` I/O.
    TunnelDevice,
    /// `setTunnelNetworkSettings` — the whole of route, address and DNS
    /// programming on this platform, because there is no route API.
    RouteProgram,
    /// On-demand rules and `includeAllNetworks`: everything ADR-0012 calls
    /// enforcement on a host with no packet filter.
    Enforcement,
    /// `dnsSettings` / `NEDNSSettingsManager`.
    Resolver,
    /// Keychain: a Tier-1 secure item, or the vended store root.
    SecureStore,
    /// The Secure Enclave: `identity_sign`, `identity_agree`, attestation.
    Identity,
    /// Installing, loading or saving the `NEVPNManager` profile.
    VpnProfile,
}

/// An [`OsDetail`] from an `io::Error`, tagged with the call that produced it.
#[must_use]
pub fn detail(err: &io::Error, call: &'static str) -> OsDetail {
    OsDetail {
        code: i64::from(err.raw_os_error().unwrap_or(0)),
        call,
    }
}

/// An [`OsDetail`] from a bare numeric code.
#[must_use]
pub const fn detail_from_code(code: i32, call: &'static str) -> OsDetail {
    OsDetail {
        code: code as i64,
        call,
    }
}

/// Maps a POSIX `errno` onto the seam's failure vocabulary.
///
/// The Darwin `errno` space is the BSD one, so the arms below are the same
/// conditions `twinvpn-platform-linux` maps, with two iOS-specific differences
/// spelled out at their arms.
#[must_use]
// Several arms coincide, and each is written out rather than merged: a reviewer
// asking "what does this adapter do with EPERM while binding a socket" must find
// that arm, and merging two contexts that share a mapping today would hide it
// when one of them changes.
#[allow(clippy::match_same_arms)]
pub fn from_errno(err: &io::Error, call: &'static str, context: Context) -> PlatformError {
    let d = Some(detail(err, call));
    match err.raw_os_error().unwrap_or(0) {
        libc::EINTR | libc::EAGAIN | libc::EBUSY | libc::ENOBUFS | libc::ENOMEM => {
            PlatformError::Transient(d)
        }
        libc::ECANCELED => PlatformError::Cancelled,
        libc::EPERM | libc::EACCES => match context {
            Context::RouteProgram | Context::Resolver => PlatformError::RouteProgrammingDenied(d),
            Context::SecureStore => PlatformError::SecureStoreUnavailable(d),
            Context::Identity => PlatformError::IdentityKeyUnavailable(d),
            // On iOS there is no `/dev/net/tun` and no privileged bring-up: the
            // provider either has the `packet-tunnel-provider` entitlement and a
            // user-approved profile, or it does not run at all. A refusal on the
            // tunnel or enforcement path is therefore the **grant**, whose
            // remediation is "the user approves the VPN profile" — never "run as
            // root", which iOS does not have.
            Context::TunnelDevice | Context::Enforcement | Context::VpnProfile => {
                PlatformError::VpnPermissionDenied(d)
            }
            Context::Socket | Context::Interfaces => PlatformError::NotPermitted(d),
        },
        libc::ENETUNREACH | libc::EHOSTUNREACH => PlatformError::NoRoute(d),
        libc::ENETDOWN | libc::ENXIO | libc::ENODEV => PlatformError::InterfaceDown(d),
        libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::ENOPROTOOPT | libc::EOPNOTSUPP => {
            PlatformError::OsUnsupported(d)
        }
        libc::EEXIST | libc::EADDRINUSE => match context {
            // §11.11: only one app can hold the platform always-on slot, so a
            // conflict here is another VPN product, not a bug of ours. Surfaced,
            // never resolved by clobbering (`networking.md` §5.5 rule 1).
            Context::Enforcement | Context::TunnelDevice | Context::VpnProfile => {
                PlatformError::ThirdPartyFilterSuspected(d)
            }
            _ => PlatformError::Transient(d),
        },
        libc::ENOENT => match context {
            Context::SecureStore => PlatformError::SecureStoreUnavailable(d),
            Context::RouteProgram | Context::Resolver => PlatformError::RouteProgrammingDenied(d),
            _ => PlatformError::AdapterUnavailable(d),
        },
        _ => match context {
            Context::RouteProgram | Context::Resolver => PlatformError::RouteProgrammingDenied(d),
            Context::SecureStore => PlatformError::SecureStoreUnavailable(d),
            Context::Identity => PlatformError::IdentityKeyUnavailable(d),
            _ => PlatformError::AdapterUnavailable(d),
        },
    }
}

/// What a Keychain or Secure Enclave call returned, before it becomes an error.
///
/// `errSecItemNotFound` is **not** a failure: [`SecureStore::secure_item_read`]'s
/// contract makes "absent" a normal first-run state, and the distinction matters
/// because *absent* enrols and *unavailable* must not.
///
/// [`SecureStore::secure_item_read`]: twinvpn_platform::SecureStore::secure_item_read
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecOutcome {
    /// The call succeeded.
    Ok,
    /// No such item. A state, not an error.
    Absent,
    /// A genuine failure.
    Failed(PlatformError),
}

/// Classifies an `OSStatus` from `Security.framework`.
///
/// # The locked-device state is designed, not surprising
///
/// `errSecInteractionNotAllowed` is what a Tier-1 item under
/// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` returns before the first
/// unlock of a boot, and what an
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` item returns whenever the
/// screen is locked. `ownership.md` §10.1 requires that state to be "a designed
/// state with a registered `reason_code`, not a surprise
/// `errSecInteractionNotAllowed`", so it maps to
/// [`PlatformError::SecureStoreUnavailable`] (`AUTH.KEY_STORE_UNAVAILABLE`) from
/// the store and to [`PlatformError::IdentityKeyUnavailable`]
/// (`AUTH.KEY_UNAVAILABLE`) from the element — two registered names, one OS
/// number, the number itself carried as evidence.
#[must_use]
#[allow(clippy::match_same_arms)]
pub fn from_os_status(status: i32, call: &'static str, context: Context) -> SecOutcome {
    if status == ERR_SEC_SUCCESS {
        return SecOutcome::Ok;
    }
    if status == ERR_SEC_ITEM_NOT_FOUND {
        return SecOutcome::Absent;
    }
    let d = Some(detail_from_code(status, call));
    let err = match status {
        ERR_SEC_INTERACTION_NOT_ALLOWED | ERR_SEC_NOT_AVAILABLE | ERR_SEC_AUTH_FAILED => {
            match context {
                Context::Identity => PlatformError::IdentityKeyUnavailable(d),
                _ => PlatformError::SecureStoreUnavailable(d),
            }
        }
        ERR_SEC_USER_CANCELED => PlatformError::Cancelled,
        // The entitlement is missing from the signed binary: the build is not
        // the one the OS will run this way. `UPDATE_REQUIRED` is the honest
        // remediation class, which is `PLATFORM.OS_UNSUPPORTED`'s.
        ERR_SEC_MISSING_ENTITLEMENT | ERR_SEC_UNIMPLEMENTED => PlatformError::OsUnsupported(d),
        ERR_SEC_ALLOCATE | ERR_SEC_DISK_FULL | ERR_SEC_IO | ERR_SEC_OP_WR => {
            PlatformError::Transient(d)
        }
        // Every remaining Security-framework status is a store or element
        // failure, split by which one the caller was touching. A parameter or
        // decode fault is ours, not the user's, but it still reaches the user as
        // a registered name with the number as evidence.
        _ => match context {
            Context::Identity => PlatformError::IdentityKeyUnavailable(d),
            _ => PlatformError::SecureStoreUnavailable(d),
        },
    };
    SecOutcome::Failed(err)
}

/// Maps an `NEVPNErrorDomain` code onto the seam's vocabulary.
///
/// The **permission lifecycle** lives here: profile install, user consent,
/// denial, later revocation and profile deletion all arrive as one of these six
/// numbers, and `ownership.md` §10.1 requires denial to be
/// `PLATFORM.VPN_PERMISSION_DENIED` rather than a generic adapter failure.
#[must_use]
// The two `AdapterUnavailable` arms below are written out rather than folded
// into the wildcard: a reviewer asking "what does this adapter do with
// NEVPNErrorConnectionFailed" must find that arm, and folding it hides the
// answer the day one of them changes.
#[allow(clippy::match_same_arms)]
pub fn from_ne_vpn_error(code: i32, call: &'static str) -> PlatformError {
    let d = Some(detail_from_code(code, call));
    match code {
        // The user declined the consent sheet, or later switched the profile off
        // in Settings, or deleted it. All three are the grant, not a fault, and
        // all three are recoverable by the user approving it again.
        NE_VPN_CONFIGURATION_DISABLED | NE_VPN_CONFIGURATION_READ_WRITE_FAILED => {
            PlatformError::VpnPermissionDenied(d)
        }
        // Stale means "reload and retry" — the profile in preferences moved
        // under us, which is exactly a transient condition.
        NE_VPN_CONFIGURATION_STALE => PlatformError::Transient(d),
        NE_VPN_CONNECTION_FAILED => PlatformError::AdapterUnavailable(d),
        NE_VPN_CONFIGURATION_INVALID | NE_VPN_CONFIGURATION_UNKNOWN => {
            PlatformError::AdapterUnavailable(d)
        }
        _ => PlatformError::AdapterUnavailable(d),
    }
}

/// The "a mechanism refused and there is no number" shape.
///
/// Still not a bare string: the caller supplies the registered *condition* by
/// choosing the context, and `call` names the mechanism for a support case.
#[must_use]
pub const fn unavailable(call: &'static str, code: i32) -> PlatformError {
    PlatformError::AdapterUnavailable(Some(detail_from_code(code, call)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(code: i32) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    fn failed(outcome: SecOutcome) -> PlatformError {
        match outcome {
            SecOutcome::Failed(e) => e,
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn a_locked_device_is_a_designed_state_with_a_registered_name() {
        // `ownership.md` §10.1: "an item that is unavailable while the device is
        // locked must be a designed state with a registered `reason_code`, not a
        // surprise `errSecInteractionNotAllowed`."
        let store = failed(from_os_status(
            ERR_SEC_INTERACTION_NOT_ALLOWED,
            "SecItemCopyMatching",
            Context::SecureStore,
        ));
        assert_eq!(store.reason_code().as_str(), "AUTH.KEY_STORE_UNAVAILABLE");
        let element = failed(from_os_status(
            ERR_SEC_INTERACTION_NOT_ALLOWED,
            "SecKeyCreateSignature",
            Context::Identity,
        ));
        assert_eq!(element.reason_code().as_str(), "AUTH.KEY_UNAVAILABLE");
        // One OS number, two registered names, and the number survives as
        // evidence in both.
        for e in [store, element] {
            assert_eq!(
                e.os_detail().map(|d| d.code),
                Some(i64::from(ERR_SEC_INTERACTION_NOT_ALLOWED))
            );
        }
    }

    #[test]
    fn an_absent_item_is_a_state_and_not_an_error() {
        // "absent" enrols; "unavailable" must not. Conflating them makes a
        // first run indistinguishable from a locked device.
        assert_eq!(
            from_os_status(
                ERR_SEC_ITEM_NOT_FOUND,
                "SecItemCopyMatching",
                Context::SecureStore
            ),
            SecOutcome::Absent
        );
        assert_eq!(
            from_os_status(ERR_SEC_SUCCESS, "SecItemAdd", Context::SecureStore),
            SecOutcome::Ok
        );
    }

    #[test]
    fn declining_the_consent_sheet_is_the_grant_and_not_an_adapter_fault() {
        for code in [
            NE_VPN_CONFIGURATION_DISABLED,
            NE_VPN_CONFIGURATION_READ_WRITE_FAILED,
        ] {
            let e = from_ne_vpn_error(code, "NEVPNManager.saveToPreferences");
            assert_eq!(e.reason_code().as_str(), "PLATFORM.VPN_PERMISSION_DENIED");
            assert_eq!(e.os_detail().map(|d| d.code), Some(i64::from(code)));
        }
    }

    #[test]
    fn a_stale_profile_is_reload_and_retry_not_a_denial() {
        let e = from_ne_vpn_error(NE_VPN_CONFIGURATION_STALE, "NEVPNManager.saveToPreferences");
        assert!(matches!(e, PlatformError::Transient(_)));
        assert_ne!(e.reason_code().as_str(), "PLATFORM.VPN_PERMISSION_DENIED");
    }

    #[test]
    fn there_is_no_root_on_ios_so_a_tunnel_refusal_is_the_grant() {
        let e = from_errno(&err(libc::EPERM), "startTunnel", Context::TunnelDevice);
        assert_eq!(e.reason_code().as_str(), "PLATFORM.VPN_PERMISSION_DENIED");
    }

    #[test]
    fn settings_apply_is_the_whole_of_route_programming_on_this_platform() {
        // There is no route API: `setTunnelNetworkSettings` carries addresses,
        // routes and DNS together, so a refusal there is ROUTE.PROGRAMMING_DENIED
        // and not a generic adapter failure.
        let e = from_errno(
            &err(libc::EINVAL),
            "setTunnelNetworkSettings",
            Context::RouteProgram,
        );
        assert_eq!(e.reason_code().as_str(), "ROUTE.PROGRAMMING_DENIED");
    }

    #[test]
    fn every_mapped_error_keeps_the_number_as_evidence_and_never_as_the_story() {
        for code in [libc::EPERM, libc::ENETUNREACH, libc::EAFNOSUPPORT, 12345] {
            let e = from_errno(&err(code), "probe", Context::Socket);
            assert!(e.reason_code().as_str().contains('.'));
            assert_eq!(e.os_detail().map(|d| d.code), Some(i64::from(code)));
            assert_eq!(e.os_detail().map(|d| d.call), Some("probe"));
        }
        for status in [
            ERR_SEC_PARAM,
            ERR_SEC_DECODE,
            ERR_SEC_DUPLICATE_ITEM,
            ERR_SEC_DATA_TOO_LARGE,
            ERR_SEC_BUFFER_TOO_SMALL,
            ERR_SEC_KEY_SIZE_NOT_ALLOWED,
            ERR_SEC_READ_ONLY,
            ERR_SEC_WR_PERM,
            -999_999,
        ] {
            let e = failed(from_os_status(status, "SecItemAdd", Context::SecureStore));
            assert!(e.reason_code().as_str().contains('.'));
            assert_eq!(e.os_detail().map(|d| d.code), Some(i64::from(status)));
        }
    }

    #[test]
    fn a_missing_entitlement_is_a_build_fact_not_a_user_action() {
        let e = failed(from_os_status(
            ERR_SEC_MISSING_ENTITLEMENT,
            "SecItemAdd",
            Context::SecureStore,
        ));
        assert_eq!(e.reason_code().as_str(), "PLATFORM.OS_UNSUPPORTED");
    }

    #[test]
    fn a_cancelled_operation_is_not_a_platform_fault() {
        let e = failed(from_os_status(
            ERR_SEC_USER_CANCELED,
            "LAContext.evaluatePolicy",
            Context::Identity,
        ));
        assert_eq!(e, PlatformError::Cancelled);
        assert!(e.os_detail().is_none());
    }

    /// **W-40, pinned as a test rather than reported only in prose.**
    ///
    /// No `PlatformError` variant is retryable under the frozen registry:
    /// `Transient` maps to `PLATFORM.ADAPTER_UNAVAILABLE`, which
    /// `contracts/registry/reason_codes.json` classes `PERSISTENT`. So an
    /// `EAGAIN` — the most retryable condition a socket has — reports
    /// `is_retryable() == false`. This adapter therefore never drives a backoff
    /// off `is_retryable()`; it returns the variant and the core decides, which
    /// is CB-2's direction anyway.
    #[test]
    fn no_platform_error_is_retryable_under_the_frozen_registry() {
        let transient = from_errno(&err(libc::EAGAIN), "recvfrom", Context::Socket);
        assert!(matches!(transient, PlatformError::Transient(_)));
        assert_eq!(
            transient.reason_code().as_str(),
            "PLATFORM.ADAPTER_UNAVAILABLE"
        );
        assert!(
            !transient.is_retryable(),
            "if this ever passes, a TRANSIENT PLATFORM code was registered and \
             this test and its finding should be deleted"
        );
    }

    #[test]
    fn an_unsupported_family_is_a_host_fact_and_is_never_substituted() {
        let e = from_errno(&err(libc::EAFNOSUPPORT), "socket", Context::Socket);
        assert_eq!(e.reason_code().as_str(), "PLATFORM.OS_UNSUPPORTED");
    }

    #[test]
    fn another_vpn_holding_the_slot_is_surfaced_and_not_clobbered() {
        // `networking.md` §5.5 rule 1 and ADR-0012 §11.11: only one app holds the
        // platform always-on slot, and the conflict is reported.
        let e = from_errno(&err(libc::EEXIST), "NEVPNManager.save", Context::VpnProfile);
        assert_eq!(
            e.reason_code().as_str(),
            "PLATFORM.THIRD_PARTY_FILTER_SUSPECTED"
        );
    }

    #[test]
    fn the_unavailable_shorthand_still_names_a_mechanism() {
        let e = unavailable("NEPacketTunnelFlow.readPackets", -1);
        assert_eq!(e.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
        assert_eq!(
            e.os_detail().map(|d| d.call),
            Some("NEPacketTunnelFlow.readPackets")
        );
    }
}
