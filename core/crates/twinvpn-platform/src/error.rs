//! The seam's failure type.
//!
//! **Authority:** ADR-0018 F-4 ("errors carry a name, never an errno"), §11.6
//! (the vtable returns "a typed `reason_code` in `err_out`"),
//! `docs/implementation/ownership.md` §4.2.
//!
//! # The rule this type exists to make structural
//!
//! > Never expose a raw unexplained OS error as the complete user-facing error:
//! > map every internal error into a registered `reason_code`, carry the
//! > platform detail as typed `Evidence`, and never let an `errno` be the whole
//! > story.
//!
//! So [`PlatformError`] has **no variant that carries only an integer**. Every
//! variant names a condition in TwinVPN's own vocabulary, and the OS's own number
//! rides along in [`PlatformError::os_detail`] as *supporting* evidence that a
//! support case can use and a user never sees alone.

use twinvpn_types::evidence::EvidenceValue;
use twinvpn_types::{codes, Component, Diagnostic, ReasonCode};

/// The platform's own error code, carried as evidence and never alone.
///
/// `errno` on POSIX, `GetLastError()` on Windows, an `NSError` code on Darwin.
/// It is deliberately not a variant of [`PlatformError`]: a value of this type
/// cannot be *the* error, only an attribute of one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OsDetail {
    /// The platform's numeric code.
    pub code: i64,
    /// A short, stable, **non-localised** tag for the call that produced it,
    /// e.g. `"bind"`, `"RTM_NEWROUTE"`, `"WinTun.Start"`.
    ///
    /// Not user-visible text: CB-4 keeps every rendered string out of the core.
    pub call: &'static str,
}

/// A failure of a platform capability.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlatformError {
    /// The adapter itself could not be opened or has gone away.
    #[error("the platform adapter is unavailable ({0:?})")]
    AdapterUnavailable(Option<OsDetail>),

    /// The OS refused VPN permission, or the entitlement is missing.
    ///
    /// Distinct from [`PlatformError::NotPermitted`]: this one is the user-facing
    /// grant that ADR-0015 classifies `PERMISSION_GRANT`, and its remediation is
    /// "the Owner approves it", not "run as root".
    #[error("VPN permission was denied by the OS")]
    VpnPermissionDenied(Option<OsDetail>),

    /// A privileged operation was refused.
    #[error("the operation was not permitted ({0:?})")]
    NotPermitted(Option<OsDetail>),

    /// The build target is outside the supported matrix, or a required OS
    /// feature is missing at the version present.
    #[error("this OS or target is unsupported")]
    OsUnsupported(Option<OsDetail>),

    /// Another product appears to be filtering or claiming the same resource.
    #[error("a third-party filter is suspected ({0:?})")]
    ThirdPartyFilterSuspected(Option<OsDetail>),

    /// No route to the destination for the requested family.
    #[error("no route for this address family ({0:?})")]
    NoRoute(Option<OsDetail>),

    /// The interface is down or has disappeared.
    #[error("the interface is down or missing ({0:?})")]
    InterfaceDown(Option<OsDetail>),

    /// Route or address programming was refused by the OS.
    #[error("route programming was denied ({0:?})")]
    RouteProgrammingDenied(Option<OsDetail>),

    /// A secure item could not be read or written.
    #[error("the secure store is unavailable ({0:?})")]
    SecureStoreUnavailable(Option<OsDetail>),

    /// The identity key is not available — locked device, revoked entitlement,
    /// or an element that has lost its backing.
    #[error("the identity key is unavailable ({0:?})")]
    IdentityKeyUnavailable(Option<OsDetail>),

    /// The operation was cancelled by the caller.
    ///
    /// Not a fault. Present so a binding can distinguish "you dropped the
    /// future" from "the OS refused", which are different facts with different
    /// remediations.
    #[error("the operation was cancelled")]
    Cancelled,

    /// The adapter is shutting down and will accept no new work.
    #[error("the adapter is shutting down")]
    ShuttingDown,

    /// A transient condition the caller may retry under the backoff regime.
    #[error("a transient platform condition ({0:?})")]
    Transient(Option<OsDetail>),
}

impl PlatformError {
    /// The registered `reason_code`.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            // A privileged refusal that is not the VPN grant, and a transient
            // condition, are both adapter-capability failures from the core's
            // point of view; the OS detail is what tells a support case which one.
            // They share a code deliberately, because ADR-0015 §11.2's admission
            // rule refuses a new code for a condition an existing one owns.
            PlatformError::AdapterUnavailable(_)
            | PlatformError::NotPermitted(_)
            | PlatformError::Transient(_) => codes::PLATFORM_ADAPTER_UNAVAILABLE,
            PlatformError::VpnPermissionDenied(_) => codes::PLATFORM_VPN_PERMISSION_DENIED,
            PlatformError::OsUnsupported(_) => codes::PLATFORM_OS_UNSUPPORTED,
            PlatformError::ThirdPartyFilterSuspected(_) => {
                codes::PLATFORM_THIRD_PARTY_FILTER_SUSPECTED
            }
            PlatformError::NoRoute(_) => codes::NET_NO_ROUTE,
            PlatformError::InterfaceDown(_) => codes::NET_IFACE_DOWN,
            PlatformError::RouteProgrammingDenied(_) => codes::ROUTE_PROGRAMMING_DENIED,
            PlatformError::SecureStoreUnavailable(_) => codes::AUTH_KEY_STORE_UNAVAILABLE,
            PlatformError::IdentityKeyUnavailable(_) => codes::AUTH_KEY_UNAVAILABLE,
            // A cancelled or shutting-down operation is a state the core asked
            // for, so it is INTERNAL rather than PLATFORM: nothing about the
            // platform went wrong.
            PlatformError::Cancelled | PlatformError::ShuttingDown => {
                codes::INTERNAL_UNEXPECTED_STATE
            }
        }
    }

    /// The OS's own code, when there is one.
    #[must_use]
    pub const fn os_detail(&self) -> Option<OsDetail> {
        match self {
            PlatformError::AdapterUnavailable(d)
            | PlatformError::VpnPermissionDenied(d)
            | PlatformError::NotPermitted(d)
            | PlatformError::OsUnsupported(d)
            | PlatformError::ThirdPartyFilterSuspected(d)
            | PlatformError::NoRoute(d)
            | PlatformError::InterfaceDown(d)
            | PlatformError::RouteProgrammingDenied(d)
            | PlatformError::SecureStoreUnavailable(d)
            | PlatformError::IdentityKeyUnavailable(d)
            | PlatformError::Transient(d) => *d,
            PlatformError::Cancelled | PlatformError::ShuttingDown => None,
        }
    }

    /// Whether a caller may retry under the `docs/reliability.md` backoff regime.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.reason_code().class(),
            twinvpn_types::ErrorClass::Transient
        )
    }

    /// The registered diagnostic.
    ///
    /// # A registry gap, reported rather than patched
    ///
    /// `ownership.md` §4.2 requires the platform detail to be carried "as typed
    /// `Evidence`", but **no `PLATFORM.*`, `NET.*`, `ROUTE.*` or `AUTH.KEY_*`
    /// code in `contracts/registry/reason_codes.json` declares an evidence key
    /// for an OS error number** — `PLATFORM.ADAPTER_UNAVAILABLE` declares none at
    /// all, and `PLATFORM.OS_UNSUPPORTED` declares only `os_version`. ADR-0015
    /// §11.3 requires an undeclared key to be dropped, so the attempts below are
    /// dropped for exactly those codes.
    ///
    /// The rule's *substance* still holds — the code is registered, the user
    /// never sees a bare number, and [`Self::os_detail`] carries the detail into
    /// a Tier-1 bundle — but the typed-evidence half cannot be satisfied until
    /// the registry declares a key. `contracts/` is frozen (`ownership.md` §3),
    /// so this is reported to the integration lead, not patched.
    ///
    /// The calls are written out rather than omitted so that the moment such a
    /// key is registered, the detail starts flowing with no code change here.
    #[must_use]
    pub fn diagnostic(&self, component: Component) -> Diagnostic {
        let code = self.reason_code();
        let mut builder = Diagnostic::builder(code, component);
        if let Some(detail) = self.os_detail() {
            builder = builder
                .evidence("errno", EvidenceValue::Int(detail.code))
                .evidence("syscall", EvidenceValue::Text(detail.call.to_owned()))
                .evidence("os_error", EvidenceValue::Int(detail.code));
        }
        builder.build()
    }
}
