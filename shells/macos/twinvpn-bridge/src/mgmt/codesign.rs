//! **ADR-0017 §11.2's macOS row: `SecCodeCheckValidity` against a Team-ID-pinned
//! code requirement.**
//!
//! **Authority:** ADR-0017 §11.2 (the macOS transport row), MI-A1, MI-A5;
//! ADR-0016 §11.14 (a); `ownership.md` §9.7 **X-13**.
//!
//! # The gap this closes, and the half of it that this host cannot close
//!
//! X-13: *"`SecCodeCheckValidity` against a Team-ID-pinned requirement is not
//! implemented — it needs `Security.framework`. Until it is, any local process
//! whose euid/egid land in a TwinVPN group can attach."* That is the check that
//! turns *"a process in the right group"* into *"our signed client"*, and
//! without it group membership is the whole of the authorization.
//!
//! This module is split so that the part which can be executed on the host this
//! crate is written on **is** executed:
//!
//! - **The decision** — what requirement string a pin produces, what a pin of
//!   `None` means, and which verdict admits a client — is target-free, is below,
//!   and is covered by this file's tests on Linux.
//! - **The call** — `SecStaticCodeCreateWithPath` / `SecCodeCopyGuestWithAttributes`,
//!   `SecRequirementCreateWithString`, `SecCodeCheckValidity` — is
//!   `#[cfg(target_os = "macos")]`, is type-checked for `aarch64-apple-darwin`
//!   by `make cross-check`, and **has never executed**. `ownership.md` §9.2's
//!   categories are what this distinction is for, and claiming otherwise would
//!   be the thing that section exists to prevent.
//!
//! # Why the requirement is built here rather than configured as a string
//!
//! A code requirement is a security predicate, and a misspelled one **fails
//! open in the direction that matters**: `anchor apple generic` alone admits
//! every Developer-ID-signed binary on the machine. So the string is assembled
//! from a pinned Team ID by [`requirement_for`], which cannot be given a
//! requirement that omits the identifier, and the assembly is asserted rather
//! than reviewed.

use crate::mgmt::audit::AuditToken;

/// The Team ID a client must be signed by, or `None` where no pin is
/// configured.
///
/// **`None` is not "allow anything".** It is the state a development build is
/// in, and [`Verdict::for_pin`] makes it produce [`Verdict::Unpinned`], which
/// the caller reports rather than treats as a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamIdPin(String);

impl TeamIdPin {
    /// Builds a pin, rejecting anything that is not a Team ID.
    ///
    /// Apple Team IDs are exactly ten alphanumeric characters. Validating that
    /// here is what keeps a mistyped value from reaching
    /// `SecRequirementCreateWithString` as a *syntactically valid* requirement
    /// naming an identifier nobody holds — which parses, evaluates, and denies
    /// every client, turning a typo into an outage rather than into an error.
    #[must_use]
    pub fn new(team_id: &str) -> Option<Self> {
        let ok = team_id.len() == 10 && team_id.bytes().all(|b| b.is_ascii_alphanumeric());
        ok.then(|| Self(team_id.to_owned()))
    }

    /// The Team ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The code requirement a pin produces.
///
/// Both clauses are load-bearing and neither is sufficient:
///
/// - `anchor apple generic` says the chain terminates at Apple's root, which
///   excludes an ad-hoc or self-signed binary.
/// - `certificate leaf[subject.OU] = "<team>"` says **which** developer, which
///   is the half that excludes every *other* Developer-ID-signed program on the
///   machine. Without it the requirement admits any notarized app.
#[must_use]
pub fn requirement_for(pin: &TeamIdPin) -> String {
    format!(
        "anchor apple generic and certificate leaf[subject.OU] = \"{}\"",
        pin.as_str()
    )
}

/// What the check concluded about one connecting process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The client's code satisfies the pinned requirement.
    Valid,
    /// The client's code does **not** satisfy it. Refuse the connection.
    Invalid,
    /// The check could not be performed — no `Security.framework` on this
    /// target, or the OS refused to produce a code object for the peer.
    ///
    /// **Refuse.** O-18's direction: an assertion that cannot be made fails
    /// toward `UNKNOWN`, never toward trusted, and a client this agent cannot
    /// identify is exactly the client MI-A5 closes the connection on.
    Unavailable,
    /// No Team ID is pinned in this build's configuration.
    ///
    /// **Admit, and report.** A development build has no Team ID and must
    /// remain usable; a shipped build that reaches this state has lost its pin,
    /// which is a packaging defect the operator has to be told about rather
    /// than a connection to drop. The caller logs it; it is not silent.
    Unpinned,
}

impl Verdict {
    /// Whether a connection carrying this verdict may proceed.
    #[must_use]
    pub const fn admits(self) -> bool {
        matches!(self, Verdict::Valid | Verdict::Unpinned)
    }

    /// The verdict for a build with no pin configured, without calling the OS.
    #[must_use]
    pub const fn for_pin(pin: Option<&TeamIdPin>) -> Option<Self> {
        match pin {
            None => Some(Verdict::Unpinned),
            Some(_) => None,
        }
    }
}

/// Checks the connecting process against the pinned requirement.
///
/// # What is checked, and against what
///
/// The peer is identified by its **audit token**, not by its pid: ADR-0016
/// §11.14 (a) takes the token precisely because a pid can be reused between the
/// moment it is read and the moment it is checked, and the token's `pidversion`
/// is what makes the identification stable. `SecCodeCopyGuestWithAttributes`
/// takes the token for the same reason.
#[must_use]
pub fn check(token: AuditToken, pin: Option<&TeamIdPin>) -> Verdict {
    let Some(pin) = pin else {
        return Verdict::Unpinned;
    };
    // SAFETY-FREE ON THIS HOST: there is no `Security.framework` off Darwin, so
    // the check cannot be performed and O-18 fixes which way that rounds.
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (token, pin);
        Verdict::Unavailable
    }
    #[cfg(target_os = "macos")]
    {
        darwin::check(token, pin)
    }
}

/// The `Security.framework` half. **Never executed on the host this crate is
/// written on**, type-checked for `aarch64-apple-darwin` by `make cross-check`.
#[cfg(target_os = "macos")]
mod darwin {
    use super::{requirement_for, AuditToken, TeamIdPin, Verdict};

    /// `Security.framework`'s opaque types, as pointers.
    ///
    /// Declared rather than pulled in as a dependency: three functions and two
    /// opaque handles is a smaller and more auditable surface than a crate, and
    /// ADR-0018 §11.11's supply-chain policy is a real cost to weigh. The same
    /// trade `TwinVPNXPCShim.h` makes for `xpc_connection_get_audit_token`.
    #[allow(non_camel_case_types)]
    type CFTypeRef = *const core::ffi::c_void;

    #[allow(non_upper_case_globals)]
    const errSecSuccess: i32 = 0;

    extern "C" {
        fn SecCodeCopyGuestWithAttributes(
            host: CFTypeRef,
            attributes: CFTypeRef,
            flags: u32,
            guest: *mut CFTypeRef,
        ) -> i32;
        fn SecRequirementCreateWithString(
            text: CFTypeRef,
            flags: u32,
            requirement: *mut CFTypeRef,
        ) -> i32;
        fn SecCodeCheckValidity(code: CFTypeRef, flags: u32, requirement: CFTypeRef) -> i32;
        fn CFRelease(cf: CFTypeRef);
        fn CFStringCreateWithBytes(
            allocator: CFTypeRef,
            bytes: *const u8,
            length: isize,
            encoding: u32,
            external: u8,
        ) -> CFTypeRef;
        fn CFDataCreate(allocator: CFTypeRef, bytes: *const u8, length: isize) -> CFTypeRef;
        fn CFDictionaryCreate(
            allocator: CFTypeRef,
            keys: *const CFTypeRef,
            values: *const CFTypeRef,
            count: isize,
            key_callbacks: CFTypeRef,
            value_callbacks: CFTypeRef,
        ) -> CFTypeRef;
        static kSecGuestAttributeAudit: CFTypeRef;
        static kCFTypeDictionaryKeyCallBacks: core::ffi::c_void;
        static kCFTypeDictionaryValueCallBacks: core::ffi::c_void;
    }

    /// UTF-8, for `CFStringCreateWithBytes`.
    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

    /// A CoreFoundation handle that releases itself.
    ///
    /// Every `Sec*Create*` and `CF*Create*` above follows the **Create Rule**:
    /// the caller owns the result and must `CFRelease` it. On a path with four
    /// creates and three early returns, doing that by hand is how a leak gets
    /// in — so ownership is a type here rather than a convention.
    struct Owned(CFTypeRef);

    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` came from a Create-Rule function in this
                // module and is released exactly once, here, because `Owned` is
                // not `Copy` and nothing else holds a reference to it.
                unsafe { CFRelease(self.0) };
            }
        }
    }

    pub(super) fn check(token: AuditToken, pin: &TeamIdPin) -> Verdict {
        let text = requirement_for(pin);

        // SAFETY: `text` outlives the call; the length is its true byte length;
        // the encoding constant is UTF-8 and `text` is a Rust `String`, so it is
        // valid UTF-8 by construction. A null return is checked below.
        let requirement_text = Owned(unsafe {
            CFStringCreateWithBytes(
                core::ptr::null(),
                text.as_ptr(),
                // The requirement is assembled from a ten-character Team ID by
                // `requirement_for`, so its length is a small constant plus ten
                // and cannot approach `isize::MAX`. `try_into` rather than `as`
                // so that stops being an argument and starts being a check.
                isize::try_from(text.len()).unwrap_or(0),
                K_CF_STRING_ENCODING_UTF8,
                0,
            )
        });
        if requirement_text.0.is_null() {
            return Verdict::Unavailable;
        }

        let bytes = token.as_bytes();
        // SAFETY: `bytes` is a live local array for the duration of the call and
        // its length is its true length.
        let audit = Owned(unsafe {
            CFDataCreate(
                core::ptr::null(),
                bytes.as_ptr(),
                // Exactly `AUDIT_TOKEN_BYTES`, which is 32.
                isize::try_from(bytes.len()).unwrap_or(0),
            )
        });
        if audit.0.is_null() {
            return Verdict::Unavailable;
        }

        // SAFETY: one key and one value, both live for the call, and the two
        // callback tables are the framework's own statics.
        let attributes = Owned(unsafe {
            let keys = [kSecGuestAttributeAudit];
            let values = [audit.0];
            CFDictionaryCreate(
                core::ptr::null(),
                keys.as_ptr(),
                values.as_ptr(),
                1,
                core::ptr::addr_of!(kCFTypeDictionaryKeyCallBacks).cast(),
                core::ptr::addr_of!(kCFTypeDictionaryValueCallBacks).cast(),
            )
        });
        if attributes.0.is_null() {
            return Verdict::Unavailable;
        }

        let mut guest: CFTypeRef = core::ptr::null();
        // SAFETY: `attributes` is live; `guest` is a live out-parameter this
        // frame owns. A null host asks about the system host, which is what
        // identifies a peer process by its audit token.
        let status = unsafe {
            SecCodeCopyGuestWithAttributes(
                core::ptr::null(),
                attributes.0,
                0,
                core::ptr::addr_of_mut!(guest),
            )
        };
        if status != errSecSuccess || guest.is_null() {
            // The OS would not identify the peer. O-18: refuse.
            return Verdict::Unavailable;
        }
        let guest = Owned(guest);

        let mut requirement: CFTypeRef = core::ptr::null();
        // SAFETY: `requirement_text` is live; `requirement` is a live
        // out-parameter this frame owns.
        let status = unsafe {
            SecRequirementCreateWithString(
                requirement_text.0,
                0,
                core::ptr::addr_of_mut!(requirement),
            )
        };
        if status != errSecSuccess || requirement.is_null() {
            // The requirement did not compile. That is a defect in THIS build,
            // not a fact about the client, and it must not read as one.
            return Verdict::Unavailable;
        }
        let requirement = Owned(requirement);

        // SAFETY: both handles are live and owned by this frame.
        let status = unsafe { SecCodeCheckValidity(guest.0, 0, requirement.0) };
        if status == errSecSuccess {
            Verdict::Valid
        } else {
            // The client IS identified and does NOT satisfy the requirement.
            // Distinct from `Unavailable`: this is an answer, and it is "no".
            Verdict::Invalid
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_requirement_names_the_anchor_and_the_team_and_both_are_needed() {
        // `anchor apple generic` alone admits every Developer-ID-signed binary
        // on the machine; the leaf OU is the half that says WHICH developer.
        let pin = TeamIdPin::new("ABCDE12345").expect("a valid team id");
        let requirement = requirement_for(&pin);
        assert!(requirement.contains("anchor apple generic"));
        assert!(requirement.contains("certificate leaf[subject.OU] = \"ABCDE12345\""));
    }

    #[test]
    fn a_team_id_that_is_not_one_is_refused_at_construction() {
        // A mistyped pin produces a requirement that COMPILES and denies every
        // client, so a typo would present as an outage rather than an error.
        for bad in ["", "SHORT", "ABCDE123456", "ABCDE-1234", "ABCDE 1234", "ábcde12345"] {
            assert!(TeamIdPin::new(bad).is_none(), "{bad:?} is not a Team ID");
        }
        assert!(TeamIdPin::new("ABCDE12345").is_some());
        assert!(TeamIdPin::new("0123456789").is_some());
    }

    #[test]
    fn an_unavailable_check_refuses_and_an_invalid_one_refuses() {
        // O-18's direction, at the one place it decides whether a stranger is
        // admitted. `Unavailable` must NOT be the permissive answer.
        assert!(!Verdict::Unavailable.admits());
        assert!(!Verdict::Invalid.admits());
        assert!(Verdict::Valid.admits());
    }

    #[test]
    fn an_unpinned_build_admits_and_says_so_rather_than_failing_shut() {
        // A development build has no Team ID and must stay usable; a shipped
        // build that reaches this has lost its pin, which the operator is told
        // about. Both are `Unpinned` — one verdict, two situations, and the
        // caller distinguishes them by whether it expected a pin.
        assert_eq!(Verdict::for_pin(None), Some(Verdict::Unpinned));
        assert!(Verdict::Unpinned.admits());
        // With a pin, no verdict is reachable without asking the OS.
        let pin = TeamIdPin::new("ABCDE12345").expect("valid");
        assert_eq!(Verdict::for_pin(Some(&pin)), None);
    }

    #[test]
    fn off_darwin_a_pinned_check_is_unavailable_and_therefore_refuses() {
        // The honest answer on this host, and the one `make cross-check` cannot
        // give: there is no `Security.framework`, so the assertion cannot be
        // made and it fails toward UNKNOWN.
        let pin = TeamIdPin::new("ABCDE12345").expect("valid");
        let token = AuditToken::from_bytes(&[0u8; crate::mgmt::audit::AUDIT_TOKEN_BYTES])
            .expect("a token");
        assert_eq!(check(token, Some(&pin)), Verdict::Unavailable);
        assert!(!check(token, Some(&pin)).admits());
    }

    #[test]
    fn an_unpinned_check_does_not_reach_the_os_at_all() {
        let token = AuditToken::from_bytes(&[0u8; crate::mgmt::audit::AUDIT_TOKEN_BYTES])
            .expect("a token");
        assert_eq!(check(token, None), Verdict::Unpinned);
    }
}
