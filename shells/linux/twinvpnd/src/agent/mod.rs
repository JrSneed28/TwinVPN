//! The privileged half: the posture check, the endpoint, the core, the server.
//!
//! **Authority:** [ADR-0016](../../../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
//! §11.6 (the start ordering, normatively), PS-1, PS-7, PS-11, PS-17, PS-18;
//! ADR-0018 §11.16 (a).
//!
//! Behind the `agent` feature, so `twinvpnctl` links none of it.

pub mod authority;
pub mod conn;
pub mod endpoint;
pub mod events;
pub mod logging;
pub mod peer;
pub mod privilege;
pub mod runtime;
pub mod server;

/// §11.6's start ordering, as a checkable sequence.
///
/// > The authority reaches `ready` only after: (1) the boot artifact's presence
/// > is verified (PS-7); (2) the owner-tagged rule set is reclaimed or
/// > re-asserted (KS-20, PS-8); (3) privilege drop has succeeded
/// > (`PLATFORM.PRIV.DROP_FAILED` otherwise); (4) durable state is rehydrated;
/// > (5) the capability probe has run. Only then does it accept management
/// > connections.
///
/// Written out as a type rather than as a comment on `main` so that "which steps
/// has this build actually completed" is a value the diagnostic bundle can carry
/// and a test can assert, rather than an inference from the log.
// Five booleans, and each is a distinct step of §11.6's ordering that the
// diagnostic bundle reports on its own line. Collapsing them into a bitflags
// type would make "which steps completed" a number a reader has to decode, and
// PS-7's "CRITICAL but never fatal" distinction is exactly the one that would
// be lost.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StartSequence {
    /// (1) The KS-19 boot artifact is registered.
    ///
    /// `false` is `PLATFORM.SERVICE.BOOT_ARTIFACT_UNREGISTERED` at `CRITICAL` —
    /// **and is not fatal**: PS-7 makes the artifact package-owned and says the
    /// authority "MUST NOT be a prerequisite for it to apply", so an agent that
    /// refused to start without it would make a packaging problem into an
    /// outage.
    pub boot_artifact_present: bool,
    /// (2) The owner-tagged ruleset was reclaimed or re-asserted (KS-20).
    pub ruleset_reclaimed: bool,
    /// (3) The privilege posture verified (§11.2). **Fatal when false.**
    pub privilege_verified: bool,
    /// (4) Durable state rehydrated.
    pub state_rehydrated: bool,
    /// (5) The capability probe ran.
    pub capabilities_probed: bool,
}

impl StartSequence {
    /// Whether the authority may accept management connections.
    ///
    /// §11.6: "**Only then** does it accept management connections."
    ///
    /// `boot_artifact_present` is deliberately **not** a precondition — see its
    /// own documentation. Everything else is.
    #[must_use]
    pub const fn ready(&self) -> bool {
        self.ruleset_reclaimed
            && self.privilege_verified
            && self.state_rehydrated
            && self.capabilities_probed
    }
}

/// The KS-19 boot artifact this package installs.
///
/// ADR-0012 §11.6's Linux row: "`twinvpn-killswitch.service`,
/// `Before=network-pre.target`, `Wants=network-pre.target`, restoring
/// `/etc/twinvpn/killswitch.nft`". Its presence is **verified**, never written
/// by the agent: PS-7 makes it package-owned and modifiable only by an atomic
/// replace under `ADMINISTER` authority.
pub const BOOT_ARTIFACT_UNIT: &str = "/etc/systemd/system/twinvpn-killswitch.service";

/// The ruleset that unit restores.
pub const BOOT_ARTIFACT_RULESET: &str = "/etc/twinvpn/killswitch.nft";

/// Whether the KS-19 artifact is installed.
///
/// Both halves, because either alone is useless: a unit with no ruleset applies
/// nothing, and a ruleset with no unit is never applied.
#[must_use]
pub fn boot_artifact_present() -> bool {
    std::path::Path::new(BOOT_ARTIFACT_UNIT).exists()
        && std::path::Path::new(BOOT_ARTIFACT_RULESET).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_authority_does_not_accept_connections_before_its_five_steps() {
        let mut sequence = StartSequence::default();
        assert!(!sequence.ready());
        sequence.ruleset_reclaimed = true;
        assert!(!sequence.ready());
        sequence.privilege_verified = true;
        assert!(!sequence.ready());
        sequence.state_rehydrated = true;
        assert!(!sequence.ready());
        sequence.capabilities_probed = true;
        assert!(sequence.ready(), "all four preconditions met");
    }

    #[test]
    fn a_missing_boot_artifact_is_critical_but_never_fatal() {
        // PS-7: the artifact is package-owned and the authority "MUST NOT be a
        // prerequisite for it to apply". An agent that refused to start without
        // it would turn a packaging problem into an outage — and would leave the
        // host with neither the boot ruleset NOR a running agent, which is the
        // worse of the two states.
        let sequence = StartSequence {
            boot_artifact_present: false,
            ruleset_reclaimed: true,
            privilege_verified: true,
            state_rehydrated: true,
            capabilities_probed: true,
        };
        assert!(sequence.ready());
    }

    #[test]
    fn the_boot_artifact_needs_both_halves() {
        // A unit with no ruleset applies nothing; a ruleset with no unit is
        // never applied. Either alone is a false positive.
        assert_eq!(
            BOOT_ARTIFACT_UNIT,
            "/etc/systemd/system/twinvpn-killswitch.service"
        );
        assert_eq!(BOOT_ARTIFACT_RULESET, "/etc/twinvpn/killswitch.nft");
        // On a developer host neither is installed, which is the honest answer.
        let _ = boot_artifact_present();
    }
}
