//! `errno` → [`PlatformError`], and the one place this crate reads `errno` at all.
//!
//! **Authority:** ADR-0018 F-4 ("errors carry a name, never an errno"),
//! `docs/implementation/ownership.md` §4.2 and §6 rule 12,
//! [`twinvpn_platform::error`].
//!
//! # The rule, and why it is one function
//!
//! > Never expose a raw unexplained OS error as the complete user-facing error:
//! > map every internal error into a registered `reason_code`, carry the platform
//! > detail as typed `Evidence`, and never let an `errno` be the whole story.
//!
//! [`PlatformError`] already makes the second half structural — no variant can
//! carry only an integer. What is left is the *mapping*, and it lives here, in
//! one function, so that a reviewer asking "what does this adapter do with
//! `EPERM`" reads one `match` rather than searching for `io::Error`.
//!
//! Every construction site in this crate calls [`from_errno`] or one of the
//! shorthands, so a bare `io::Error` never reaches the seam.

use std::io;

use twinvpn_platform::{OsDetail, PlatformError};

/// The last `errno`, as an [`OsDetail`] tagged with the call that produced it.
///
/// `call` is a **stable, non-localised tag** — `"bind"`, `"RTM_NEWROUTE"`,
/// `"nft -f"` — not user-visible text. CB-4 keeps every rendered string out of
/// the core, so this is a name a support case greps for, never a sentence.
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

/// Maps one OS error onto the seam's failure vocabulary.
///
/// # Why the mapping is coarse on purpose
///
/// ADR-0015 §11.2's admission rule refuses a new code for a condition an
/// existing one owns, and [`PlatformError`] is deliberately narrower than
/// `errno`. So several numbers land on one variant, and the number itself rides
/// along in [`OsDetail`] — which is exactly the split §4.2 asks for: the *name*
/// is TwinVPN's, the *number* is supporting evidence.
///
/// `context` says what the caller was doing, because the same `errno` means
/// different things in different places: `EPERM` from `bind` is a privilege
/// problem, `EPERM` from a route program is `ROUTE.PROGRAMMING_DENIED`.
#[must_use]
// Several arms coincide, and each is written out rather than merged: a reviewer
// asking "what does this adapter do with ENOENT while touching the tun device"
// must be able to find that arm, and merging two contexts that happen to share a
// mapping today would hide it when one of them changes.
#[allow(clippy::match_same_arms)]
pub fn from_errno(err: &io::Error, call: &'static str, context: Context) -> PlatformError {
    let d = Some(detail(err, call));
    let raw = err.raw_os_error().unwrap_or(0);
    match raw {
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
            // `/dev/net/tun` refused is the closest Linux has to the OS's VPN
            // grant: on a desktop it is what the user sees when the daemon is
            // not privileged, and its remediation is "grant it", not "run as
            // root". PS-18 makes the absence a startup failure either way.
            Context::TunnelDevice => PlatformError::VpnPermissionDenied(d),
            Context::Socket | Context::Netlink | Context::Enforcement | Context::Resolver => {
                PlatformError::NotPermitted(d)
            }
        },
        libc::ENETUNREACH | libc::EHOSTUNREACH => PlatformError::NoRoute(d),
        libc::ENETDOWN | libc::ENXIO | libc::ENODEV => PlatformError::InterfaceDown(d),
        libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::ENOPROTOOPT | libc::EOPNOTSUPP => {
            PlatformError::OsUnsupported(d)
        }
        libc::EEXIST | libc::EADDRINUSE => match context {
            // Another product holding the same address or the same table is the
            // one condition Linux reports that maps cleanly onto §11.11's
            // coexistence story.
            Context::Enforcement | Context::TunnelDevice => {
                PlatformError::ThirdPartyFilterSuspected(d)
            }
            _ => PlatformError::Transient(d),
        },
        libc::ENOENT => match context {
            Context::SecureStore => PlatformError::SecureStoreUnavailable(d),
            Context::TunnelDevice | Context::Enforcement => PlatformError::AdapterUnavailable(d),
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

/// What the caller was doing when the OS refused.
///
/// Not a severity and not a component: it is the disambiguator the `errno`
/// itself does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Context {
    /// A socket call.
    Socket,
    /// A netlink call.
    Netlink,
    /// `/dev/net/tun` or an interface-lifecycle call.
    TunnelDevice,
    /// Address, route or policy-rule programming.
    RouteProgram,
    /// The firewall ruleset.
    Enforcement,
    /// Resolver configuration.
    Resolver,
    /// Tier-1 secure storage.
    SecureStore,
    /// An identity operation.
    Identity,
}

/// A shorthand for the common "the OS refused and there is no `errno`" shape —
/// a tool that exited non-zero, a file whose contents did not parse.
///
/// Still not a bare string: the caller supplies the registered *condition*, and
/// `call` names the mechanism for a support case.
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
    fn a_route_refusal_is_not_reported_as_a_generic_adapter_failure() {
        let e = from_errno(&err(libc::EPERM), "RTM_NEWROUTE", Context::RouteProgram);
        assert_eq!(e.reason_code().as_str(), "ROUTE.PROGRAMMING_DENIED");
    }

    #[test]
    fn the_tun_device_being_refused_is_the_vpn_grant_not_root() {
        let e = from_errno(
            &err(libc::EACCES),
            "open(/dev/net/tun)",
            Context::TunnelDevice,
        );
        assert_eq!(e.reason_code().as_str(), "PLATFORM.VPN_PERMISSION_DENIED");
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

    /// **W-40, closed — this tripwire now guards the fixed behaviour.**
    ///
    /// **Authority:** `contracts/FROZEN` Amendment 2 (`registry_version` 3),
    /// `docs/implementation/ownership.md` §8 (W-40, and the W-18 rule that a
    /// tripwire is inverted rather than deleted), `docs/reliability.md` §3.1 and
    /// §6.1.
    ///
    /// The test has been through two shapes and neither is deleted, because the
    /// property is still worth a test after the defect is gone.
    ///
    /// 1. It first asserted `!transient.is_retryable()`. That function is now
    ///    **deleted**: §3.1 makes `class` the only retry authority and forbids
    ///    guessing one "from an error type", which is what a predicate on an
    ///    error enum is. The note on `PlatformError` carries the argument.
    /// 2. It then asserted the *mapping* defect — that `Transient` named
    ///    `PLATFORM.ADAPTER_UNAVAILABLE`, class `PERSISTENT`. Deleting the
    ///    predicate had made that the **only** retry authority left, so the
    ///    defect stopped being cosmetic.
    ///
    /// Amendment 2 registered `PLATFORM.ADAPTER_BUSY` — `TRANSIENT`,
    /// non-terminal, not `user_actionable` — and `PlatformError::Transient` now
    /// names it, so both halves are true at once: the adapter reports the
    /// condition undecided (CB-2's direction, and what this adapter relies on
    /// instead of a predicate), and the code it names carries the class §6.1's
    /// backoff reads.
    ///
    /// Asserting `class` **and** `terminal` is the point. `ADAPTER_UNAVAILABLE`
    /// was wrong on four counts at once — class, terminal, `user_actionable`,
    /// `remediation_class` — and a re-point to some other near neighbour could
    /// fix the class while leaving `terminal` true, which would still tell the
    /// core an `EAGAIN` ends the attempt.
    ///
    /// Prose once claimed "**no** `PlatformError` variant is retryable … every
    /// code the enum can produce is `PERSISTENT` or `FATAL`". It went stale
    /// unnoticed at `registry_version` 2 — which made `NET.IFACE_DOWN` and
    /// `AUTH.KEY_STORE_UNAVAILABLE` `TRANSIENT` — and is doubly false now. A
    /// sweeping claim no test checks is exactly what rots; this asserts the
    /// narrow property instead.
    #[test]
    fn a_retryable_errno_reaches_the_core_as_transient_and_names_a_transient_code() {
        let transient = from_errno(&err(libc::EAGAIN), "recvmsg", Context::Socket);
        // The adapter's half: the condition is reported, undecided, for the core.
        assert!(matches!(transient, PlatformError::Transient(_)));
        // A refusal must never be collapsed into it — the discrimination is the
        // whole value the core gets from this classification.
        assert!(matches!(
            from_errno(&err(libc::EPERM), "bind", Context::Socket),
            PlatformError::NotPermitted(_)
        ));
        // The registry's half, which W-40 was.
        let code = transient.reason_code();
        assert_eq!(code.as_str(), "PLATFORM.ADAPTER_BUSY");
        assert_eq!(
            code.class(),
            twinvpn_types::ErrorClass::Transient,
            "an EAGAIN must name a TRANSIENT-class code: §6.1's backoff reads \
             `class`, and since `is_retryable` was deleted this mapping is the \
             only retry authority left"
        );
        assert!(
            !code.terminal(),
            "a call that may succeed if repeated must not be terminal"
        );
        // And the code it left keeps its own, different, meaning: could not be
        // *opened*, as against could not complete *now*.
        let opened = from_errno(&err(libc::ENOENT), "open(tun)", Context::TunnelDevice);
        assert_eq!(
            opened.reason_code().as_str(),
            "PLATFORM.ADAPTER_UNAVAILABLE"
        );
    }

    #[test]
    fn an_unsupported_family_is_reported_as_a_host_fact_not_substituted() {
        // SocketProvider::bind_udp's contract: OsUnsupported is a FACT about the
        // host, reported so the core can decide. Substituting another family is
        // how a v6-only network silently becomes a v4-only session.
        let e = from_errno(&err(libc::EAFNOSUPPORT), "socket", Context::Socket);
        assert_eq!(e.reason_code().as_str(), "PLATFORM.OS_UNSUPPORTED");
    }
}
