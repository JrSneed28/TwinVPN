//! The `core-lite` profile (ADR-0018 §11.12), and the rule it must not break.
//!
//! **Authority:** [ADR-0018](../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! §11.12; [ADR-0016](../../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
//! PS-24; [`docs/networking.md`](../../../../docs/networking.md) §5.4.
//!
//! > **`core-lite`.** A feature profile of the *same* source containing
//! > `twinvpn-schema`, `twinvpn-crypto` (verification only), `twinvpn-store`,
//! > `twinvpn-trust` and `twinvpn-diag`, and **no** data-plane crate.
//!
//! # The rule that matters more than the crate list
//!
//! > **`core-lite` MUST NOT sit on a fetch path or on any recovery path.**
//!
//! §11.12 gives the deadlock shape in full: under `includeAllNetworks` the iOS
//! app process **has no network**, and it cannot match ADR-0012's
//! bootstrap-exemption class because KS-9(1)'s predicate names the *provider*,
//! not the app. An app-process fetch would therefore fail in exactly the state
//! where the contract is most needed, and would fail *silently from the
//! extension's point of view*.
//!
//! The general rule: **no component whose availability depends on the tunnel
//! being up may sit on the path that brings the tunnel up.**
//!
//! # How that rule is enforced here rather than remembered
//!
//! [`Capability`] enumerates what a profile may do, and [`capabilities`] returns
//! the set for the profile this artifact was built as. `core-lite`'s set contains
//! [`Capability::Parse`], [`Capability::Verify`] and [`Capability::Render`] and
//! **does not contain** [`Capability::Fetch`] or [`Capability::Recover`]. A
//! caller asks the set; there is no code path that fetches, because the
//! data-plane crates that would do it are not compiled in.

/// What a built profile is permitted to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// Decode a signed document. C-3 puts the memory pressure here.
    Parse,
    /// Verify a signature over the received octets.
    Verify,
    /// Resolve a `reason_code` into sentences (CB-4, F-10).
    Render,
    /// Assemble a Tier-1 diagnostic bundle.
    Bundle,
    /// Open a socket and **fetch** a document.
    ///
    /// **Never granted to `core-lite`.** §11.12's deadlock: the extension
    /// fetches — it holds the exempted socket — and hands raw bytes to the app
    /// process over ADR-0017.
    Fetch,
    /// Bring a tunnel up, or recover one.
    ///
    /// **Never granted to `core-lite`.** The same rule: the component that can
    /// recover must not be the component that lacks the network.
    Recover,
}

/// The capability set of the profile this artifact was built as.
#[must_use]
pub fn capabilities() -> &'static [Capability] {
    if cfg!(feature = "full") {
        &[
            Capability::Parse,
            Capability::Verify,
            Capability::Render,
            Capability::Bundle,
            Capability::Fetch,
            Capability::Recover,
        ]
    } else {
        // §11.12's list, and nothing else. `Fetch` and `Recover` are absent, and
        // the crates that would implement them are not compiled.
        &[
            Capability::Parse,
            Capability::Verify,
            Capability::Render,
            Capability::Bundle,
        ]
    }
}

/// Whether this build has `capability`.
#[must_use]
pub fn has(capability: Capability) -> bool {
    capabilities().contains(&capability)
}

/// The profile's name, as `CoreBuildIdentity.profile` reports it.
#[must_use]
pub const fn profile() -> &'static str {
    crate::build_identity::PROFILE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_lite_never_fetches_and_never_recovers() {
        // The assertion holds in BOTH profiles: under `full` these are granted,
        // under `core-lite` they are not, and the test says which it is looking
        // at rather than passing vacuously.
        if cfg!(feature = "full") {
            assert!(has(Capability::Fetch));
            assert!(has(Capability::Recover));
            assert_eq!(profile(), "full");
        } else {
            assert!(
                !has(Capability::Fetch),
                "ADR-0018 §11.12: core-lite MUST NOT sit on a fetch path"
            );
            assert!(
                !has(Capability::Recover),
                "ADR-0018 §11.12: core-lite MUST NOT sit on any recovery path"
            );
            assert_eq!(profile(), "core-lite");
        }
    }

    #[test]
    fn every_profile_can_parse_verify_and_render() {
        // §11.12's purpose: the app process "parses, verifies and renders". A
        // profile that could not render could not display the diagnostic that
        // poisoned the core (F-10), which is the one job it must always do.
        for c in [Capability::Parse, Capability::Verify, Capability::Render] {
            assert!(has(c), "{c:?} must be available in every profile");
        }
    }

    #[test]
    fn the_data_plane_is_absent_from_the_lite_profile() {
        // The structural half. Under `core-lite` the modules that name a
        // data-plane crate are not compiled at all, so this is a compile-time
        // fact asserted at runtime for the record.
        let has_dataplane_modules = cfg!(feature = "full");
        assert_eq!(has_dataplane_modules, has(Capability::Recover));
    }
}
