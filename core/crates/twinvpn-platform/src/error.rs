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
///
/// # Why there is no `is_retryable`
///
/// **Authority:** `docs/reliability.md` §3.1 and §6.3, ADR-0018 CB-2,
/// `docs/implementation/ownership.md` §8 W-40.
///
/// This type used to carry `is_retryable(&self) -> bool`. It is **deliberately
/// gone**, and the deletion is the finding — not a tidy-up — so a reader who
/// reaches for it finds the reason here rather than re-adding it.
///
/// `reliability.md` §3.1 gives exactly one authority for the question:
///
/// > `class` … is the field §6 reads: the retry policy, the backoff regime, and
/// > the circuit breaker are all driven by `class`, **never guessed from an
/// > error type**.
///
/// A predicate on an error enum is a retry decision read off an error type,
/// which is the shape that sentence forbids, and it was wrong in both available
/// implementations:
///
/// - **Asking the registry**, as it did, was honest about the registry and a lie
///   about the variant. [`PlatformError::Transient`] then mapped to
///   `PLATFORM.ADAPTER_UNAVAILABLE`, which the registry classes `PERSISTENT`, so
///   the one variant whose whole purpose is "retry me" answered `false`. Five
///   adapters found that independently and every one routed around this function
///   rather than through it — a function that existed only to be avoided.
///   Amendment 2 has since fixed that mapping (see [`Self::reason_code`]), which
///   does **not** make the predicate right: it would still be a second retry
///   authority, and the next mis-mapped arm would go just as quiet.
/// - **Answering from the variant** would have fixed the name and broken the
///   architecture: it would stand beside §6's governor and *disagree* with it,
///   giving one system two answers to one question. §3.1 also records that an
///   earlier `Retryability` attribute with four values was considered and
///   **withdrawn**, replaced by `class`; reintroducing it here, keyed on a Rust
///   variant, re-litigates a closed decision inside a seam crate.
///
/// A `bool` could not carry the answer in any case. §6.3's breaker needs all
/// four classes kept apart: `PERSISTENT` opens it for a named
/// `retry_precondition`, `POLICY` opens none at all and routes to `BLOCKED` via
/// T29, `FATAL` opens it permanently. Collapsing those to one bit makes a policy
/// refusal and an invariant violation indistinguishable, which §6.3 says is
/// wrong in both directions.
///
/// **What to call instead:** `self.reason_code().class()`, which is one call,
/// already public, and is the field §6 is specified to read. And under CB-2 the
/// adapter should usually call nothing — it reports the variant and the core
/// decides, which is what all five adapters already do.
///
/// **What has changed since, and what it does not license.** `ownership.md` §8
/// W-40 — the *mapping* defect this note used to record as open — is **closed**:
/// Amendment 2 to the freeze registered `PLATFORM.ADAPTER_BUSY` and
/// [`Self::reason_code`] names it, so §6.1's ordinary backoff is now reachable
/// for an `EAGAIN`. It is reachable *through `class`*, which is where §3.1 puts
/// it. Nothing about that close argues for re-adding a predicate here; it
/// removes the last practical excuse for one. Each adapter still pins the
/// mapping with a test — now guarding the fixed behaviour rather than the
/// defect.
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

    /// Nothing is wrong; the call arrived at a bad moment. `EAGAIN`, `EBUSY`,
    /// `ENOBUFS`, `WSAEWOULDBLOCK` and their kin.
    ///
    /// Reporting the condition is the adapter's whole job here — the decision to
    /// retry is the core's, under `reliability.md` §6.1's interactive regime, and
    /// CB-2 keeps it there. See the note on [`PlatformError`] for why this type
    /// offers no predicate of its own, and [`Self::reason_code`] for the
    /// `TRANSIENT`-class code this variant names.
    #[error("a transient platform condition ({0:?})")]
    Transient(Option<OsDetail>),
}

impl PlatformError {
    /// The registered `reason_code`.
    ///
    /// # W-40, closed: a transient condition names a transient code
    ///
    /// **Authority:** `contracts/FROZEN` Amendment 2 (`registry_version` 3),
    /// `docs/implementation/ownership.md` §8 W-40, `docs/reliability.md` §6.1
    /// and §6.3, ADR-0015 §11.2.
    ///
    /// [`PlatformError::Transient`] names `PLATFORM.ADAPTER_BUSY`: class
    /// `TRANSIENT`, severity `WARN`, `terminal` false, `user_actionable` false,
    /// `remediation_class` `NONE`, and the registered condition *"the platform
    /// adapter could not complete the call now; the same call may succeed if
    /// repeated"* — which is what an `EAGAIN`, `EINTR` or `WSAEWOULDBLOCK`
    /// actually is.
    ///
    /// It used to name `PLATFORM.ADAPTER_UNAVAILABLE`, whose condition is *"the
    /// platform network adapter could not be opened"* and which the registry
    /// classes `PERSISTENT`, `terminal`, `user_actionable`, `LOCAL_ACTION`. A
    /// call that would succeed on the next poll therefore reached the core as a
    /// permanent, user-fixable failure to open the adapter — none of those four
    /// things — and §6.3's breaker, which keys on `class`, opened for a named
    /// precondition instead of taking §6.1's ordinary backoff. The deletion of
    /// `is_retryable` is what made that load-bearing rather than cosmetic: with
    /// the predicate gone, this mapping is the only retry authority left.
    ///
    /// **`ADAPTER_UNAVAILABLE` keeps its meaning and its other arms** — could
    /// not be *opened*, as against could not complete *now*. Those are two
    /// conditions, which is why ADR-0015 §11.2's admission rule *admits* the
    /// second code rather than refusing it: no existing code owned "not now".
    ///
    /// The name is a condition and not a policy. It is `ADAPTER_BUSY`, not
    /// `SYSCALL_RETRYABLE`, because "retryable" is the answer `class` carries,
    /// and a code whose name asserts the retry decision invites back the second
    /// retry authority `reliability.md` §3.1 forbids and whose Rust incarnation
    /// was just deleted. `contracts/FROZEN` records that reasoning.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            // A privileged refusal that is not the VPN grant is still a failure
            // to *open* the capability, and it is `PERSISTENT` and remediable by
            // a local action exactly as the registered condition says; the OS
            // detail is what tells a support case which refusal it was. These
            // two share a code deliberately, because ADR-0015 §11.2's admission
            // rule refuses a new code for a condition an existing one owns.
            PlatformError::AdapterUnavailable(_) | PlatformError::NotPermitted(_) => {
                codes::PLATFORM_ADAPTER_UNAVAILABLE
            }
            // `Transient` sat in that arm until Amendment 2 and does not belong
            // there: "could not open" and "could not complete now" are different
            // conditions with different classes, so the same rule that keeps the
            // two above together is what separates this one out.
            PlatformError::Transient(_) => codes::PLATFORM_ADAPTER_BUSY,
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

    /// The registered diagnostic.
    ///
    /// # Which of these keys actually land, and why one of them did not
    ///
    /// **Authority:** ADR-0015 §11.3 (an undeclared evidence key is dropped),
    /// `ownership.md` §4.2 ("carry the platform detail as typed `Evidence`").
    ///
    /// The three `PLATFORM.*` codes this type can name —
    /// `PLATFORM.ADAPTER_BUSY`, `PLATFORM.ADAPTER_UNAVAILABLE` and
    /// `PLATFORM.OS_UNSUPPORTED` — each declare `errno`, `syscall`,
    /// `os_error_code` and `platform`, so for those the detail flows. The
    /// `NET.*`, `ROUTE.*` and `AUTH.KEY_*` codes it also names declare **no**
    /// evidence keys at all, so for those every call below is dropped. That is
    /// the builder working as specified, not a failure: it will not turn a
    /// missing declaration into a second failure on a failure path. The rule's
    /// substance still holds there — the code is registered, the user never sees
    /// a bare number, and [`Self::os_detail`] carries the detail into a Tier-1
    /// bundle — and the calls are written out unconditionally so that the day
    /// such a key is registered the detail starts flowing with no change here.
    ///
    /// **`errno` and `os_error_code` both carry the same number on purpose.**
    /// The registry declares both, and this seam is cross-platform: the value is
    /// a `GetLastError()` or an `NSError` code as often as it is an `errno`, so
    /// a consumer that does not assume POSIX reads the neutral key. The second
    /// call was spelled `os_error` — a key no code declares, so §11.3 dropped it
    /// silently and the neutral key was absent from **every** diagnostic this
    /// type has produced. A dropped key is invisible by design, which is why a
    /// spelling slip here costs a support case and no test.
    ///
    /// `platform` is deliberately left unset: [`OsDetail`] does not carry it and
    /// this crate is the platform-neutral half of the seam (ADR-0018 CB-3). The
    /// adapter that knows the answer is the one that should add it.
    #[must_use]
    pub fn diagnostic(&self, component: Component) -> Diagnostic {
        let code = self.reason_code();
        let mut builder = Diagnostic::builder(code, component);
        if let Some(detail) = self.os_detail() {
            builder = builder
                .evidence("errno", EvidenceValue::Int(detail.code))
                .evidence("syscall", EvidenceValue::Text(detail.call.to_owned()))
                .evidence("os_error_code", EvidenceValue::Int(detail.code));
        }
        builder.build()
    }
}
