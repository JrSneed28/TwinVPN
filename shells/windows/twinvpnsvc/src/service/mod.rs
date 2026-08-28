//! The privileged half: the start sequence, the SCM, the power events, the MI
//! server and its authorization.
//!
//! **Authority:** [ADR-0016](../../../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
//! §11.2's Windows row, §11.6 (the start ordering, normatively), §11.9 (the
//! Windows hardening posture), PS-1 … PS-23;
//! [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.4, §11.5, §11.14;
//! [ADR-0022](../../../../../docs/adr/ADR-0022-application-lifecycle-and-background-execution.md)
//! LC-4, LC-5, LC-12, LC-19, LC-20, LC-22, LC-23a, LC-24, LC-37.
//!
//! Behind the `service` feature, so `twinvpnctl` links none of it.
//!
//! # Where the Windows-specific code is, and where it is not
//!
//! Every module here is split the same way the adapter is: the **decision** is a
//! pure function over a plain value, and the **syscall** is a thin reader in
//! [`crate::win32`]. That is not abstraction for its own sake — this crate was
//! written on a Linux host and cannot be linked there, so a decision that lived
//! inside an `unsafe` block would be a decision nobody could test.
//!
//! | Module | The decision, target-free | The syscall |
//! |---|---|---|
//! | [`start`] | which steps completed, and which are fatal | — |
//! | [`privilege`] | [`privilege::Posture::verify`] over a `TokenPrivileges` value | `OpenProcessToken` / `GetTokenInformation` |
//! | [`scm`] | [`scm::on_control`], a pure transition | `SetServiceStatus` |
//! | [`power`] | [`power::classify`] and [`power::ResumeSequence`] | `SERVICE_CONTROL_POWEREVENT` |
//! | [`peer`] | [`peer::Principal::scopes`] | `GetNamedPipeClientProcessId`, the token SIDs, WTS |
//! | [`server`] | the whole frame loop, over any `AsyncRead + AsyncWrite` | the pipe itself |
//! | [`logging`] | the level mapping | — |

pub mod events;
pub mod logging;
pub mod peer;
pub mod power;
pub mod privilege;
#[cfg(feature = "core-host")]
pub mod runtime;
pub mod scm;
#[cfg(feature = "core-host")]
pub mod server;
pub mod start;

pub use start::{StartSequence, StartupRefusal, Substitution, SUBSTITUTIONS};

/// This build's version, for `HelloAck.agent_version` and `version.get`.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The build profile this binary was compiled as (ADR-0023 EM-1).
///
/// §11.7: "**Build profile is not version.**" A host built with a reduced
/// feature profile answers the same `mi_version` and offers a different
/// catalogue, so a client that branched on version alone would be wrong.
///
/// `H-CLI` rather than `H-SRV`: ADR-0016 puts Windows in host class **HC-1**,
/// attended and separable, with a console seat — which is a different tier from
/// `shells/linux`'s headless `HC-3`. Recorded here because it is the one place
/// the two shells' profiles legitimately differ.
pub const BUILD_PROFILE: &str = "H-CLI";

#[cfg(test)]
mod tests {
    #[test]
    fn the_agent_version_is_the_packages_own() {
        assert_eq!(super::AGENT_VERSION, env!("CARGO_PKG_VERSION"));
        assert!(super::AGENT_VERSION.contains('.'));
    }

    #[test]
    fn the_build_profile_is_one_of_adr_0023s_four() {
        assert!(matches!(
            super::BUILD_PROFILE,
            "H-SRV" | "H-EMB" | "H-CTR" | "H-CLI"
        ));
    }
}
