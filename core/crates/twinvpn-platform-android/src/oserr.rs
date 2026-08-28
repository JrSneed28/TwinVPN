//! `errno` and Java exception names → [`PlatformError`], and the one place this
//! crate turns an OS failure into a name.
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
//! carry only an integer. What is left is the *mapping*, and it lives here so a
//! reviewer asking "what does this adapter do when `establish()` throws
//! `SecurityException`" reads one `match`.
//!
//! # Android has two failure vocabularies, not one
//!
//! `twinvpn-platform-linux` needs only [`from_errno`], because every Linux
//! refusal is an `errno`. Android's are split:
//!
//! | Surface | Failure shape | Mapped by |
//! |---|---|---|
//! | sockets, the tun fd, `/proc`, `/dev/urandom` | `errno` | [`from_errno`] |
//! | `VpnService`, `ConnectivityManager`, `KeyStore`, `PowerManager` | a **thrown Java exception** | [`from_java_exception`] |
//!
//! A Java exception carries a *class name*, not a number, and the class name is
//! the only stable machine-readable thing about it — the message is localised
//! and vendor-variable, so it is neither logged nor mapped. The class name
//! reaches this module from the JNI shim as a borrowed `&str`, and it is
//! **untrusted input** (`ownership.md` §6 rule 9): it is bounded before it is
//! matched and it never drives an allocation.
//!
//! Neither mapping ever produces a bare number as the story. The `errno` (or a
//! synthetic code for the Java path) rides in [`OsDetail`] as supporting
//! evidence a support case can use and a user never sees alone.

use std::io;

use twinvpn_platform::{OsDetail, PlatformError};

/// The longest Java class name this module will look at.
///
/// A fully-qualified JVM binary name is bounded by the class-file format at
/// 65535 *bytes of modified UTF-8*, which is not a bound worth honouring here:
/// every name this adapter can legitimately see is under 128 bytes, and a longer
/// one is a malfunctioning shim rather than an exception worth classifying.
/// `ownership.md` §6 rule 9 — bound the input before it is used, and never
/// truncate: an over-long name is refused into
/// [`PlatformError::AdapterUnavailable`], not shortened until it matches.
pub const MAX_EXCEPTION_NAME_BYTES: usize = 128;

/// The synthetic `OsDetail::code` used where the failure came from the JVM and
/// there is no `errno`.
///
/// Deliberately **not** zero: zero is what `io::Error::raw_os_error()` yields
/// when there was no OS error at all, and a support case must be able to tell
/// "the JVM threw" from "we had nothing to report".
pub const JVM_DETAIL_CODE: i64 = -1;

/// The last `errno`, as an [`OsDetail`] tagged with the call that produced it.
///
/// `call` is a **stable, non-localised tag** — `"bind"`, `"read(tun)"`,
/// `"VpnService.Builder.establish"` — not user-visible text. CB-4 keeps every
/// rendered string out of the core, so this is a name a support case greps for,
/// never a sentence.
#[must_use]
pub fn detail(err: &io::Error, call: &'static str) -> OsDetail {
    OsDetail {
        code: i64::from(err.raw_os_error().unwrap_or(0)),
        call,
    }
}

/// A detail from a bare `errno` value.
#[must_use]
pub const fn detail_from_code(code: i32, call: &'static str) -> OsDetail {
    OsDetail {
        code: code as i64,
        call,
    }
}

/// What the caller was doing when the platform refused.
///
/// Not a severity and not a component: it is the disambiguator neither an
/// `errno` nor a Java class name carries. The same `SecurityException` means
/// "the user has not granted the VPN consent" from `establish()` and "this
/// process may not read that Keystore entry" from `KeyStore.getEntry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Context {
    /// A socket call, including `VpnService.protect`.
    Socket,
    /// `ConnectivityManager`, `NetworkCallback`, `LinkProperties`.
    Connectivity,
    /// `VpnService.Builder`, `establish()`, the tun `ParcelFileDescriptor`.
    TunnelDevice,
    /// The `VpnService.Builder` route/address/DNS programme.
    RouteProgram,
    /// The route claim considered as enforcement (ADR-0012 §11.6 Android row).
    Enforcement,
    /// Resolver configuration, including Private DNS.
    Resolver,
    /// Tier-1 secure storage in the Android Keystore.
    SecureStore,
    /// An identity operation inside the Keystore element.
    Identity,
    /// `PowerManager`, `SocketKeepalive`, thermal status.
    Power,
}

/// Maps one OS error onto the seam's failure vocabulary.
///
/// # Why the mapping is coarse on purpose
///
/// ADR-0015 §11.2's admission rule refuses a new code for a condition an
/// existing one owns, and [`PlatformError`] is deliberately narrower than
/// `errno`. So several numbers land on one variant, and the number itself rides
/// along in [`OsDetail`] — which is exactly the split §4.2 asks for: the *name*
/// is TwinVPN's, the *number* is supporting evidence.
#[must_use]
// Several arms coincide, and each is written out rather than merged: a reviewer
// asking "what does this adapter do with ENOENT while touching the tun fd" must
// be able to find that arm, and merging two contexts that happen to share a
// mapping today would hide it when one of them changes.
#[allow(clippy::match_same_arms)]
pub fn from_errno(err: &io::Error, call: &'static str, context: Context) -> PlatformError {
    let d = Some(detail(err, call));
    match err.raw_os_error().unwrap_or(0) {
        // Interrupted and would-block are the caller's to retry; they are never
        // a fault of the platform and never a reason to give up on a path.
        libc::EINTR | libc::EAGAIN | libc::EBUSY | libc::ENOBUFS | libc::ENOMEM => {
            PlatformError::Transient(d)
        }
        libc::ECANCELED => PlatformError::Cancelled,
        libc::EPERM | libc::EACCES => match context {
            Context::RouteProgram => PlatformError::RouteProgrammingDenied(d),
            Context::SecureStore => PlatformError::SecureStoreUnavailable(d),
            Context::Identity => PlatformError::IdentityKeyUnavailable(d),
            // A refused tun fd on Android is the OS's VPN grant, not privilege:
            // the remediation is "approve the consent dialog", never "run as
            // root", and ADR-0019's platform table routes it to
            // `Settings.ACTION_VPN_SETTINGS`.
            Context::TunnelDevice => PlatformError::VpnPermissionDenied(d),
            Context::Socket
            | Context::Connectivity
            | Context::Enforcement
            | Context::Resolver
            | Context::Power => PlatformError::NotPermitted(d),
        },
        libc::ENETUNREACH | libc::EHOSTUNREACH => PlatformError::NoRoute(d),
        libc::ENETDOWN | libc::ENXIO | libc::ENODEV => PlatformError::InterfaceDown(d),
        libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::ENOPROTOOPT | libc::EOPNOTSUPP => {
            PlatformError::OsUnsupported(d)
        }
        // Another VPN holding the platform's single VPN slot is the one
        // condition Android reports that maps onto §5.5's coexistence story.
        libc::EEXIST | libc::EADDRINUSE => match context {
            Context::Enforcement | Context::TunnelDevice => {
                PlatformError::ThirdPartyFilterSuspected(d)
            }
            _ => PlatformError::Transient(d),
        },
        // The tun fd going stale under us is what `onRevoke()` looks like from
        // the read side: the descriptor is closed by the system and every
        // subsequent read fails. It is an interface fact, not an adapter fault.
        libc::EBADF => match context {
            Context::TunnelDevice => PlatformError::InterfaceDown(d),
            _ => PlatformError::AdapterUnavailable(d),
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

/// Maps a thrown Java exception onto the seam's failure vocabulary.
///
/// `class_name` is the JVM binary name as `Throwable.getClass().getName()`
/// returns it — `"android.security.keystore.KeyPermanentlyInvalidatedException"`.
/// **The exception's *message* is deliberately not a parameter**: it is
/// localised, vendor-variable, and on the Keystore path it can quote key
/// material aliases, so it is never mapped and never logged (§6 rule 11).
///
/// An unrecognised class name is not a failure of this function. It maps by
/// `context`, exactly as an unrecognised `errno` does, so a vendor-specific
/// subclass still produces a registered code rather than a panic.
#[must_use]
#[allow(clippy::match_same_arms)]
pub fn from_java_exception(
    class_name: &str,
    call: &'static str,
    context: Context,
) -> PlatformError {
    let d = Some(OsDetail {
        code: JVM_DETAIL_CODE,
        call,
    });

    // Untrusted input, bounded BEFORE it is matched. An over-long name is a
    // malfunctioning shim; refusing is the honest answer, and truncating until
    // it matched a known class would be a fabricated diagnosis.
    if class_name.is_empty() || class_name.len() > MAX_EXCEPTION_NAME_BYTES {
        return PlatformError::AdapterUnavailable(d);
    }

    match class_name {
        // ---- the Keystore element -----------------------------------------
        // ADR-0020 §11's Android row: the screen lock was removed or the
        // biometric enrolment changed, and the key is gone for good. The vault
        // is unopenable and unrecoverable; ADR-0020's ladder quarantines it and
        // rebuilds from ANCH. `STORE.KEY_INVALIDATED` is the code ADR-0020
        // names and the frozen registry does not carry it -- see `codes`.
        "android.security.keystore.KeyPermanentlyInvalidatedException"
        | "java.security.UnrecoverableKeyException"
        | "javax.crypto.AEADBadTagException"
        | "javax.crypto.BadPaddingException" => PlatformError::SecureStoreUnavailable(d),

        // Pre-first-unlock on a credential-encrypted store, or a key bound to
        // user authentication. ADR-0022 LC-15: the agent comes up fail-closed
        // and NAMED, and rehydration completes on the first unlock. This is an
        // availability gap, never a licence to weaken the key (I4).
        "android.security.keystore.UserNotAuthenticatedException" => {
            PlatformError::IdentityKeyUnavailable(d)
        }

        "java.security.KeyStoreException"
        | "java.security.NoSuchAlgorithmException"
        | "java.security.cert.CertificateException"
        | "android.security.KeyStoreException" => match context {
            Context::Identity => PlatformError::IdentityKeyUnavailable(d),
            _ => PlatformError::SecureStoreUnavailable(d),
        },

        // The device has no StrongBox. ADR-0020's ladder falls back to the TEE;
        // the FACT is reported, never silently substituted (§11.16 (l)).
        "android.security.keystore.StrongBoxUnavailableException" => {
            PlatformError::OsUnsupported(d)
        }

        // ---- VpnService and the platform's single VPN slot ----------------
        // `establish()` throws SecurityException when `prepare()` has not been
        // consented to, or when another app now holds the VPN slot. Both are
        // the user-facing grant ADR-0019's platform table routes to
        // `Settings.ACTION_VPN_SETTINGS`.
        "java.lang.SecurityException" => match context {
            Context::TunnelDevice | Context::Enforcement => PlatformError::VpnPermissionDenied(d),
            Context::SecureStore => PlatformError::SecureStoreUnavailable(d),
            Context::Identity => PlatformError::IdentityKeyUnavailable(d),
            _ => PlatformError::NotPermitted(d),
        },

        // The binder to the system server died -- system_server restart, or
        // the service being torn down under us.
        "android.os.DeadObjectException" | "android.os.DeadSystemException" => {
            PlatformError::AdapterUnavailable(d)
        }

        // `Builder.addRoute`/`addAddress` reject a malformed or unroutable
        // value. The programme this adapter renders cannot produce one, so
        // this arm firing at all is a defect in the renderer -- but it is
        // reported as a route refusal rather than swallowed.
        "java.lang.IllegalArgumentException" => match context {
            Context::RouteProgram | Context::TunnelDevice => {
                PlatformError::RouteProgrammingDenied(d)
            }
            _ => PlatformError::AdapterUnavailable(d),
        },

        "java.lang.IllegalStateException" | "java.lang.UnsupportedOperationException" => {
            PlatformError::OsUnsupported(d)
        }

        // Jetsam's cousin. ADR-0022 LC-16's Android low-memory row: no notice,
        // a foreground service is late in the LMK order but not exempt.
        "java.lang.OutOfMemoryError" => PlatformError::Transient(d),

        "java.io.IOException" | "android.system.ErrnoException" => match context {
            Context::SecureStore => PlatformError::SecureStoreUnavailable(d),
            Context::TunnelDevice => PlatformError::InterfaceDown(d),
            _ => PlatformError::Transient(d),
        },

        // Unrecognised: map by context exactly as an unrecognised errno does.
        // A vendor subclass must still produce a registered code.
        _ => match context {
            Context::RouteProgram => PlatformError::RouteProgrammingDenied(d),
            Context::SecureStore => PlatformError::SecureStoreUnavailable(d),
            Context::Identity => PlatformError::IdentityKeyUnavailable(d),
            Context::TunnelDevice => PlatformError::AdapterUnavailable(d),
            _ => PlatformError::AdapterUnavailable(d),
        },
    }
}

/// A shorthand for "the platform refused and there is no `errno`" — a JNI call
/// that returned null, a shim that produced an unparseable payload.
///
/// Still not a bare string: the caller supplies the registered *condition* by
/// choosing the variant, and `call` names the mechanism for a support case.
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

    #[test]
    fn a_refused_tun_fd_is_the_vpn_grant_not_root() {
        // ADR-0019's Android row: `VpnService.prepare()` ->
        // PLATFORM.VPN_PERMISSION_DENIED, remediated by the consent dialog.
        let e = from_errno(&err(libc::EACCES), "open(tun)", Context::TunnelDevice);
        assert_eq!(e.reason_code().as_str(), "PLATFORM.VPN_PERMISSION_DENIED");

        let j = from_java_exception(
            "java.lang.SecurityException",
            "VpnService.Builder.establish",
            Context::TunnelDevice,
        );
        assert_eq!(j.reason_code().as_str(), "PLATFORM.VPN_PERMISSION_DENIED");
    }

    #[test]
    fn a_route_refusal_is_not_reported_as_a_generic_adapter_failure() {
        let e = from_errno(&err(libc::EPERM), "Builder.addRoute", Context::RouteProgram);
        assert_eq!(e.reason_code().as_str(), "ROUTE.PROGRAMMING_DENIED");
    }

    #[test]
    fn every_mapped_error_keeps_the_number_as_evidence_and_never_as_the_story() {
        for code in [libc::EPERM, libc::ENETUNREACH, libc::EAFNOSUPPORT, 12345] {
            let e = from_errno(&err(code), "probe", Context::Socket);
            // The user-facing name is TwinVPN's...
            assert!(e.reason_code().as_str().contains('.'));
            // ...and the number is still reachable for a Tier-1 bundle.
            assert_eq!(e.os_detail().map(|d| d.code), Some(i64::from(code)));
            assert_eq!(e.os_detail().map(|d| d.call), Some("probe"));
        }
    }

    #[test]
    fn a_jvm_failure_is_distinguishable_from_having_nothing_to_report() {
        let e = from_java_exception(
            "android.os.DeadObjectException",
            "ConnectivityManager.registerNetworkCallback",
            Context::Connectivity,
        );
        assert_eq!(e.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
        // Not zero: zero means "no OS error at all", which is a different fact.
        assert_eq!(e.os_detail().map(|d| d.code), Some(JVM_DETAIL_CODE));
        assert_ne!(JVM_DETAIL_CODE, 0);
    }

    #[test]
    fn a_keystore_invalidation_and_a_locked_device_are_different_facts() {
        // The screen lock was removed: the SEK is gone for good, and ADR-0020's
        // ladder quarantines the vault.
        let dead = from_java_exception(
            "android.security.keystore.KeyPermanentlyInvalidatedException",
            "KeyStore.getEntry",
            Context::SecureStore,
        );
        assert_eq!(dead.reason_code().as_str(), "AUTH.KEY_STORE_UNAVAILABLE");

        // Pre-first-unlock: the key is fine, the device is locked, and LC-15
        // says come up fail-closed and named, then rehydrate on unlock.
        let locked = from_java_exception(
            "android.security.keystore.UserNotAuthenticatedException",
            "KeyStore.getEntry",
            Context::Identity,
        );
        assert_eq!(locked.reason_code().as_str(), "AUTH.KEY_UNAVAILABLE");
        assert_ne!(dead.reason_code(), locked.reason_code());
    }

    #[test]
    fn an_over_long_or_empty_exception_name_is_refused_never_truncated() {
        let long = "a".repeat(MAX_EXCEPTION_NAME_BYTES + 1);
        let e = from_java_exception(&long, "probe", Context::TunnelDevice);
        assert_eq!(e.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");

        // The prefix of the over-long name IS a class this module recognises,
        // so a truncating implementation would have classified it. This asserts
        // we do not: `ownership.md` §6 rule 9 -- never a truncation, never a pad.
        let mut padded = String::from("java.lang.SecurityException");
        padded.push_str(&"x".repeat(MAX_EXCEPTION_NAME_BYTES));
        let p = from_java_exception(&padded, "establish", Context::TunnelDevice);
        assert_eq!(p.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
        assert_eq!(
            from_java_exception("", "establish", Context::TunnelDevice)
                .reason_code()
                .as_str(),
            "PLATFORM.ADAPTER_UNAVAILABLE"
        );
    }

    #[test]
    fn an_unknown_vendor_subclass_still_produces_a_registered_code() {
        let e = from_java_exception(
            "com.example.oem.VendorVpnException",
            "VpnService.Builder.establish",
            Context::RouteProgram,
        );
        assert!(twinvpn_types::ReasonCode::lookup(e.reason_code().as_str()).is_some());
    }

    /// **A finding, pinned as a test rather than reported only in prose.**
    ///
    /// `PlatformError::is_retryable` asks the *registry* for the code's class,
    /// and `PlatformError::Transient` maps to `PLATFORM.ADAPTER_UNAVAILABLE`,
    /// which `contracts/registry/reason_codes.json` classes **`PERSISTENT`**.
    /// So `EAGAIN` — the most retryable condition a socket has — reports
    /// `is_retryable() == false`, and **no** `PlatformError` variant is
    /// retryable under the frozen registry.
    ///
    /// That is W-40 (a W-18 instance) landing on this adapter too, which is the
    /// point of re-asserting it here: it is not a Linux-specific accident.
    /// Neither `contracts/` nor `twinvpn-platform` is this domain's to change,
    /// so the behaviour is asserted as it is and this adapter never relies on
    /// `is_retryable()` — it returns the variant and lets the core decide, which
    /// is CB-2's direction anyway.
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
