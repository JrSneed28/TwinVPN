//! ADR-0016 §11.6's start ordering, as a value the diagnostic bundle can carry.
//!
//! **Authority:** [ADR-0016](../../../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
//! §11.6 (the start ordering, normatively), PS-7, PS-8, PS-18;
//! [ADR-0022](../../../../../docs/adr/ADR-0022-application-lifecycle-and-background-execution.md)
//! LC-4 (the rehydration order **is** the safety property), LC-5;
//! ADR-0012 §8; `ownership.md` §8 W-18.
//!
//! # §11.6, verbatim
//!
//! > The authority reaches `ready` only after: (1) the boot artifact's presence
//! > is verified (PS-7); (2) the owner-tagged rule set is reclaimed or
//! > re-asserted (KS-20, PS-8); (3) privilege drop has succeeded; (4) durable
//! > state is rehydrated; (5) the capability probe has run. Only then does it
//! > accept management connections.
//!
//! This is written out as a **type** rather than as a comment on `main` so that
//! "which steps has this build actually completed" is a value a test can assert
//! and a bundle can carry, rather than an inference from the log. That is the
//! shape `shells/linux/twinvpnd/src/agent/mod.rs` established, and the reason it
//! matters is `desktop-linux`'s review finding R-7: step (2) there was once a
//! flag set to `true` with nothing behind it, and the host ran unprotected.
//!
//! # The one step that is CRITICAL and not fatal
//!
//! PS-7 makes the KS-19 boot artifact **package-owned** and says the authority
//! "MUST NOT be a prerequisite for it to apply". A service that refused to start
//! without it would turn a packaging problem into an outage, and would leave the
//! host with neither the boot filters *nor* a running authority — the worse of
//! the two states. So [`StartSequence::boot_artifact_present`] is reported and
//! [`StartSequence::ready`] does not consult it.
//!
//! # Everything else is fatal, and PS-18 is why
//!
//! > The authority MUST NOT start in a mode that cannot arm enforcement while
//! > reporting itself as running.
//!
//! A service that reached `SERVICE_RUNNING` without a WFP sublayer, without
//! `SeLoadDriverPrivilege`, or with a runtime that cannot open a socket, would
//! be reporting exactly that.

/// §11.6's ordering, as a checkable sequence.
///
/// Seven booleans, and each is a distinct step the diagnostic bundle reports on
/// its own line. Collapsing them into a bitflags type would make "which steps
/// completed" a number a reader has to decode, and PS-7's CRITICAL-but-never-
/// fatal distinction is exactly the one that would be lost.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StartSequence {
    /// (1) The KS-19 boot artifact is registered — a boot-time WFP deny for
    /// **both** families, written by the installer and applied by the Base
    /// Filtering Engine.
    ///
    /// `false` is `PLATFORM.SERVICE.BOOT_ARTIFACT_UNREGISTERED` at `CRITICAL`
    /// and **is not fatal**; see the module documentation.
    pub boot_artifact_present: bool,
    /// (2) The single-instance lock was acquired (LC-5). **Fatal when false.**
    ///
    /// PS-1: exactly one process per host is the network and policy authority.
    /// A second one claiming the Wintun adapter, the WFP sublayer or the store
    /// is `INTERNAL.INVARIANT_VIOLATED`, and LC-5 makes the lock the mechanism
    /// that stops it rather than a rule somebody has to keep.
    pub single_instance: bool,
    /// (3) The privilege posture verified against §11.9. **Fatal when false.**
    pub privilege_verified: bool,
    /// (4) The three clocks, the runtime and the CSPRNG are bound, and the
    /// CSPRNG has been **probed**. **Fatal when false.**
    pub env_bound: bool,
    /// (5) The capability probe ran: Wintun's DLL is loadable and the WFP engine
    /// opens. **Fatal when false** — ADR-0012 §8, arming must never fail open.
    pub capabilities_probed: bool,
    /// (6) The owner-tagged WFP state was reclaimed **and read back from the
    /// engine**. **Fatal when false.**
    ///
    /// This is the W-24 query, not the fact that an install returned `Ok`. A
    /// `true` here means `ProtectionAssertion::is_fail_closed()` held.
    pub ruleset_reclaimed: bool,
    /// (7) Durable state rehydrated (LC-4 steps 5–9). **Fatal when false.**
    pub state_rehydrated: bool,
}

impl StartSequence {
    /// Whether the authority may accept management connections.
    ///
    /// §11.6: "**Only then** does it accept management connections."
    ///
    /// [`Self::boot_artifact_present`] is deliberately **not** a precondition —
    /// see its own documentation. Everything else is, and the order in which
    /// they are listed is the order in which they must have happened: LC-4's
    /// line, "no packet may be emitted before this line", falls immediately
    /// after [`Self::ruleset_reclaimed`].
    #[must_use]
    pub const fn ready(&self) -> bool {
        self.single_instance
            && self.privilege_verified
            && self.env_bound
            && self.capabilities_probed
            && self.ruleset_reclaimed
            && self.state_rehydrated
    }

    /// Whether a packet may be emitted yet.
    ///
    /// LC-4 draws the line after the enforcement query and re-assertion, not
    /// after the whole sequence: rehydration reads the durable store, and the
    /// store is on this host rather than on the network. Separating the two
    /// makes the ordering rule checkable rather than implied.
    #[must_use]
    pub const fn may_emit_a_packet(&self) -> bool {
        self.single_instance && self.privilege_verified && self.ruleset_reclaimed
    }

    /// The first step that has not completed, for the log line and the bundle.
    ///
    /// Named rather than counted: "the capability probe did not run" and "the
    /// ruleset was not reclaimed" send an operator to different places.
    #[must_use]
    pub const fn first_incomplete(&self) -> Option<&'static str> {
        if !self.single_instance {
            Some("single-instance lock")
        } else if !self.privilege_verified {
            Some("privilege posture")
        } else if !self.env_bound {
            Some("clocks, runtime and CSPRNG")
        } else if !self.capabilities_probed {
            Some("capability probe")
        } else if !self.ruleset_reclaimed {
            Some("owner-tagged ruleset reclaim and read-back")
        } else if !self.state_rehydrated {
            Some("durable state rehydration")
        } else {
            None
        }
    }
}

/// A refusal to start, with the code that names it.
///
/// Never a bare message: the registered code is the contract, and the sentence
/// is for a human reading the Event Log.
#[derive(Debug, Clone)]
pub struct StartupRefusal {
    /// The **registered** code that is actually emitted.
    pub code: &'static str,
    /// The spelling ADR-0016 §11.12 uses, where it differs.
    pub specified: &'static str,
    /// What went wrong, for a human.
    pub detail: String,
    /// The process exit code.
    ///
    /// `70` (`EX_SOFTWARE`) for an internal failure and `71` (`EX_OSERR`) for a
    /// platform one, matching `shells/linux/twinvpnd`. These are the *process*
    /// exit codes of a service that never reached the SCM dispatcher; ADR-0017
    /// §11.12's 0–5 are the **CLI's** and do not apply here.
    pub exit: u8,
}

impl StartupRefusal {
    /// A platform refusal.
    #[must_use]
    pub fn platform(code: &'static str, specified: &'static str, detail: String) -> Self {
        Self {
            code,
            specified,
            detail,
            exit: 71,
        }
    }

    /// An internal refusal — a defect in this build rather than a condition the
    /// host is in.
    #[must_use]
    pub fn internal(detail: String) -> Self {
        Self {
            code: "INTERNAL.INVARIANT_VIOLATED",
            specified: "INTERNAL.INVARIANT_VIOLATED",
            detail,
            exit: 70,
        }
    }
}

/// One forced substitution, for the integration lead's W-18 amendment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Substitution {
    /// The spelling the ADR uses.
    pub specified: &'static str,
    /// The registered code emitted instead.
    pub emitted: &'static str,
    /// What the substitution costs, stated rather than glossed.
    pub cost: &'static str,
}

/// The codes this shell needs and the frozen registry does not carry.
///
/// The pattern is `shells/linux/twinvpnd/src/agent/privilege.rs`'s, adopted as
/// the wave standard by `ownership.md` §8 **W-18**: record the pair, state the
/// cost, and assert with a tripwire that the specified spelling is **still
/// absent** — so registering one fails the build and points at the row to
/// delete.
///
/// Seven of them, and the overlap with the Linux shell's five is not an
/// accident: `PLATFORM.PRIV.*` and `PLATFORM.SERVICE.*` are ADR-0016's
/// contribution to the registry and almost none of it landed. The two rows that
/// are new here are Windows-shaped — a service has a single-instance lock and a
/// remote-session rule that a `systemd` unit does not.
pub const SUBSTITUTIONS: &[Substitution] = &[
    Substitution {
        specified: "PLATFORM.SERVICE.BOOT_ARTIFACT_UNREGISTERED",
        emitted: "PLATFORM.ADAPTER_UNAVAILABLE",
        cost: "PS-7's CRITICAL becomes indistinguishable from any other adapter problem, so a \
               fleet query cannot count hosts whose boot window is unprotected — which is the \
               one number KS-19 exists to make countable",
    },
    Substitution {
        specified: "PLATFORM.LIFECYCLE.SINGLE_INSTANCE_CONFLICT",
        emitted: "INTERNAL.INVARIANT_VIOLATED",
        cost: "PS-1 names a second authority as INTERNAL.INVARIANT_VIOLATED anyway, so the \
               class and severity are right; what is lost is that the second process cannot \
               be distinguished from a genuine internal defect in the first",
    },
    Substitution {
        specified: "PLATFORM.PRIV.DROP_FAILED",
        emitted: "PLATFORM.ADAPTER_UNAVAILABLE",
        cost: "a fatal privilege-separation failure reads as a generic adapter problem. The \
               remediation differs completely: one is 'the service is installed with the \
               wrong RequiredPrivileges', the other is 'the platform is unavailable'",
    },
    Substitution {
        specified: "PLATFORM.PRIV.CAPABILITY_MISSING",
        emitted: "PLATFORM.ADAPTER_UNAVAILABLE",
        cost: "loses the named privilege, which PS-18 requires the code to carry so an \
               operator knows WHICH one to grant — SeLoadDriverPrivilege and \
               SeImpersonatePrivilege have different consequences and different fixes",
    },
    Substitution {
        specified: "PLATFORM.SERVICE.SUPERVISOR_ABSENT",
        emitted: "PLATFORM.ADAPTER_UNAVAILABLE",
        cost: "PS-11's WARN is emitted as a log line with the fact in it rather than as a \
               distinguishable code, so a fleet query cannot count services running outside \
               the SCM",
    },
    Substitution {
        specified: "PLATFORM.PRIV.CLIENT_UNAUTHORIZED",
        emitted: "POLICY.POLICY_DENIED",
        cost: "ADR-0017 §11.12 gives this its OWN exit code (4), 'distinct so a script can \
               tell re-run with privilege from this will never work'. Degrading onto POLICY \
               tells a correct script to give up",
    },
    Substitution {
        specified: "PLATFORM.PRIV.REMOTE_ADMIN_REFUSED",
        emitted: "POLICY.POLICY_DENIED",
        cost: "PS-14's console-seat rule becomes indistinguishable from an ordinary \
               authorization failure, so an administrator on RDP is told 'denied' rather \
               than 'denied BECAUSE this is a remote session' — which is the one sentence \
               that would send them to the console",
    },
];

/// The registered code emitted for a specified spelling.
///
/// One lookup rather than a `match` at every emission site, so a row added to
/// [`SUBSTITUTIONS`] takes effect everywhere and a row deleted stops compiling
/// nothing — the tripwire test is what catches that case.
#[must_use]
pub fn emitted_for(specified: &'static str) -> &'static str {
    SUBSTITUTIONS
        .iter()
        .find(|s| s.specified == specified)
        .map_or(specified, |s| s.emitted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_types::ReasonCode;

    fn complete() -> StartSequence {
        StartSequence {
            boot_artifact_present: true,
            single_instance: true,
            privilege_verified: true,
            env_bound: true,
            capabilities_probed: true,
            ruleset_reclaimed: true,
            state_rehydrated: true,
        }
    }

    #[test]
    fn the_authority_does_not_accept_connections_before_its_six_preconditions() {
        let mut sequence = StartSequence::default();
        assert!(!sequence.ready());
        for step in [
            "single_instance",
            "privilege_verified",
            "env_bound",
            "capabilities_probed",
            "ruleset_reclaimed",
            "state_rehydrated",
        ] {
            assert!(!sequence.ready(), "ready before {step}");
            match step {
                "single_instance" => sequence.single_instance = true,
                "privilege_verified" => sequence.privilege_verified = true,
                "env_bound" => sequence.env_bound = true,
                "capabilities_probed" => sequence.capabilities_probed = true,
                "ruleset_reclaimed" => sequence.ruleset_reclaimed = true,
                _ => sequence.state_rehydrated = true,
            }
        }
        assert!(sequence.ready(), "all six preconditions met");
    }

    #[test]
    fn a_missing_boot_artifact_is_critical_but_never_fatal() {
        // PS-7: the artifact is package-owned and the authority "MUST NOT be a
        // prerequisite for it to apply". Refusing would leave the host with
        // neither the boot ruleset NOR a running authority.
        let sequence = StartSequence {
            boot_artifact_present: false,
            ..complete()
        };
        assert!(sequence.ready());
        assert_eq!(sequence.first_incomplete(), None);
    }

    #[test]
    fn no_packet_may_be_emitted_before_the_enforcement_query() {
        // ADR-0022 LC-4's line falls after step 4, not after the whole
        // sequence: rehydration reads a local store and emits nothing.
        let mut sequence = StartSequence {
            single_instance: true,
            privilege_verified: true,
            ..StartSequence::default()
        };
        assert!(!sequence.may_emit_a_packet(), "the ruleset is not reclaimed");
        sequence.ruleset_reclaimed = true;
        assert!(sequence.may_emit_a_packet());
        // ...and that is still not `ready`: connections wait for everything.
        assert!(!sequence.ready());
    }

    #[test]
    fn every_incomplete_step_is_named_rather_than_counted() {
        // "the capability probe did not run" and "the ruleset was not
        // reclaimed" send an operator to different places.
        let mut sequence = StartSequence::default();
        assert_eq!(sequence.first_incomplete(), Some("single-instance lock"));
        sequence.single_instance = true;
        assert_eq!(sequence.first_incomplete(), Some("privilege posture"));
        sequence.privilege_verified = true;
        assert_eq!(
            sequence.first_incomplete(),
            Some("clocks, runtime and CSPRNG")
        );
        sequence.env_bound = true;
        assert_eq!(sequence.first_incomplete(), Some("capability probe"));
        sequence.capabilities_probed = true;
        assert_eq!(
            sequence.first_incomplete(),
            Some("owner-tagged ruleset reclaim and read-back")
        );
        sequence.ruleset_reclaimed = true;
        assert_eq!(
            sequence.first_incomplete(),
            Some("durable state rehydration")
        );
        sequence.state_rehydrated = true;
        assert_eq!(sequence.first_incomplete(), None);
    }

    #[test]
    fn a_refusal_carries_a_registered_code_and_a_separate_specified_spelling() {
        let refusal = StartupRefusal::platform(
            emitted_for("PLATFORM.PRIV.DROP_FAILED"),
            "PLATFORM.PRIV.DROP_FAILED",
            "the token holds SeDebugPrivilege".to_owned(),
        );
        assert_eq!(refusal.code, "PLATFORM.ADAPTER_UNAVAILABLE");
        assert_eq!(refusal.specified, "PLATFORM.PRIV.DROP_FAILED");
        assert_eq!(refusal.exit, 71);
        assert!(ReasonCode::lookup(refusal.code).is_some());
    }

    #[test]
    fn a_code_that_needs_no_substitution_passes_through_unchanged() {
        assert_eq!(
            emitted_for("POLICY.KILLSWITCH.ARM_FAILED"),
            "POLICY.KILLSWITCH.ARM_FAILED"
        );
        assert!(ReasonCode::lookup("POLICY.KILLSWITCH.ARM_FAILED").is_some());
    }

    #[test]
    fn an_internal_refusal_is_a_defect_and_not_a_host_condition() {
        // Different exit codes because they are different questions: 71 says
        // "this host cannot run it", 70 says "this build is wrong".
        let internal = StartupRefusal::internal("the sequence did not complete".to_owned());
        assert_eq!(internal.exit, 70);
        assert_eq!(internal.code, "INTERNAL.INVARIANT_VIOLATED");
    }

    /// **The W-18 tripwire.** Deleting a row is what a registry addition looks
    /// like, and this fails the build until the row is deleted.
    #[test]
    fn every_substituted_spelling_is_still_absent_from_the_frozen_registry() {
        for substitution in SUBSTITUTIONS {
            assert!(
                ReasonCode::lookup(substitution.specified).is_none(),
                "{} is now REGISTERED. Delete its row from SUBSTITUTIONS and emit it \
                 directly — the substitution's cost is recorded there.",
                substitution.specified
            );
            assert!(
                ReasonCode::lookup(substitution.emitted).is_some(),
                "{} must be a registered code",
                substitution.emitted
            );
        }
    }

    #[test]
    fn no_specified_spelling_is_listed_twice() {
        // A duplicate row is how two emission sites come to disagree about
        // which registered code stands in for one condition.
        for (i, a) in SUBSTITUTIONS.iter().enumerate() {
            for b in &SUBSTITUTIONS[i + 1..] {
                assert_ne!(a.specified, b.specified, "{} is listed twice", a.specified);
            }
        }
    }
}
