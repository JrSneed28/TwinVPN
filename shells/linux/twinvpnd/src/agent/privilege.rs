//! The privilege posture: verified from `/proc/self/status`, and **fatal** when
//! it is wrong.
//!
//! **Authority:** [ADR-0016](../../../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
//! §11.2's "Linux, normatively" paragraph, §11.9's directive table, PS-11,
//! PS-17, PS-18; ADR-0018 DP-4.
//!
//! # The drop is performed by the unit, and verified here
//!
//! §11.2 requires the authority to run "as the dedicated system user with an
//! ambient `CAP_NET_ADMIN`", to hold **no** `CAP_SYS_MODULE`, `CAP_SYS_ADMIN`,
//! `CAP_DAC_OVERRIDE` or `CAP_SYS_PTRACE`, and makes a failure to drop
//! `PLATFORM.PRIV.DROP_FAILED` and **fatal** — "the authority MUST NOT continue
//! as root 'just this once'".
//!
//! Performing that drop *in process* needs `capset(2)`, `setresuid(2)` and
//! `prctl(2)`, all of which need `unsafe`, and this crate carries
//! `#![forbid(unsafe_code)]`. So the drop is done by
//! `packaging/twinvpnd.service`'s `User=`, `AmbientCapabilities=` and
//! `CapabilityBoundingSet=` — **before `exec`**, which means this process never
//! runs as root at all rather than running as root briefly.
//!
//! That is not a workaround; it is the stronger arrangement, and it is exactly
//! what §11.9's directive table specifies. What it costs is that the guarantee
//! now lives in a unit file, which an operator can edit. So this module
//! **verifies the posture at start and refuses to continue when it is wrong** —
//! turning "the unit was edited" from an invisible widening into a startup
//! failure. PS-17's principle: "Silently running wider than declared is the
//! defect this rule retires."
//!
//! # PS-11: an unsupervised authority does not claim supervised guarantees
//!
//! [`Posture::supervised`] is `false` when the process was not started by a
//! recognised supervisor. R-25's restart guarantee "is a property of the
//! supervisor, not of the binary", so the shell emits
//! `PLATFORM.SERVICE.SUPERVISOR_ABSENT`'s condition at `WARN` rather than
//! reporting a posture it does not have.

use std::fs;

/// The capability the authority keeps. §11.2, verbatim.
pub const REQUIRED_CAPABILITY: &str = "CAP_NET_ADMIN";

/// `CAP_NET_ADMIN`'s bit.
pub const CAP_NET_ADMIN: u64 = 1 << 12;

/// The capabilities §11.2 forbids, with their bits.
///
/// A named list rather than a mask, because the log line has to say **which**
/// one is held: "run without `CAP_SYS_ADMIN`" and "run without
/// `CAP_DAC_OVERRIDE`" are different instructions to an operator.
pub const FORBIDDEN_CAPABILITIES: [(&str, u64); 4] = [
    ("CAP_SYS_MODULE", 1 << 16),
    ("CAP_SYS_ADMIN", 1 << 21),
    ("CAP_DAC_OVERRIDE", 1 << 1),
    ("CAP_SYS_PTRACE", 1 << 19),
];

/// What this process's privilege actually is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Posture {
    /// The effective uid.
    pub uid: u32,
    /// The effective capability set.
    pub effective: u64,
    /// The bounding set.
    pub bounding: u64,
    /// Whether `NoNewPrivileges` is set.
    pub no_new_privs: bool,
    /// Whether a recognised supervisor started this process (PS-11).
    pub supervised: bool,
}

/// Why the posture is not the one §11.2 requires.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrivilegeError {
    /// Still root. §11.2: **fatal**, and never "just this once".
    #[error("the authority is still running as root; the privilege drop did not happen")]
    StillRoot,
    /// A capability §11.2 forbids is held.
    #[error("the authority holds a capability it must not: {capability}")]
    ForbiddenCapability {
        /// Which one.
        capability: &'static str,
    },
    /// `CAP_NET_ADMIN` is absent, so the tun device and netlink are unreachable.
    ///
    /// **PS-18**: "The authority MUST NOT start in a mode that cannot arm
    /// enforcement while reporting itself as running."
    #[error("the authority lacks {REQUIRED_CAPABILITY} and cannot arm enforcement")]
    CapabilityMissing,
    /// `/proc/self/status` could not be read, so the posture is unknown.
    ///
    /// Refused rather than assumed: an unverifiable posture is the same failure
    /// direction as an unverifiable principal (MI-A5).
    #[error("the privilege posture could not be verified")]
    Unverifiable,
}

impl PrivilegeError {
    /// The `reason_code` this condition would carry.
    ///
    /// **Every one is a substitution.** ADR-0016 §11.12 contributes
    /// `PLATFORM.PRIV.DROP_FAILED` and `PLATFORM.PRIV.CAPABILITY_MISSING`, and
    /// `contracts/registry/reason_codes.json` registers **neither** — it carries
    /// two of the nineteen `PLATFORM.PRIV.*`/`PLATFORM.SERVICE.*` codes that ADR
    /// names (`ownership.md` §8 W-18). The nearest registered code is emitted
    /// and the specified spelling is recorded in [`SUBSTITUTIONS`].
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            // `PLATFORM.PRIV.DROP_FAILED` and `PLATFORM.PRIV.CAPABILITY_MISSING`
            // are both unregistered. `PLATFORM.ADAPTER_UNAVAILABLE` is the
            // nearest registered `PLATFORM.*` code and keeps the domain, which
            // is what ADR-0015 §11.2's prefix degradation actually needs.
            PrivilegeError::StillRoot
            | PrivilegeError::ForbiddenCapability { .. }
            | PrivilegeError::CapabilityMissing => "PLATFORM.ADAPTER_UNAVAILABLE",
            // Registered, so it is emitted DIRECTLY rather than substituted —
            // and the tripwire below is what caught that: the row this used to
            // have in `SUBSTITUTIONS` failed the build until it was deleted.
            PrivilegeError::Unverifiable => "PLATFORM.PRIV.SANDBOX_DEGRADED",
        }
    }

    /// The spelling ADR-0016 §11.12 uses, for the log line and the report.
    #[must_use]
    pub const fn specified_code(&self) -> &'static str {
        match self {
            PrivilegeError::StillRoot | PrivilegeError::ForbiddenCapability { .. } => {
                "PLATFORM.PRIV.DROP_FAILED"
            }
            PrivilegeError::CapabilityMissing => "PLATFORM.PRIV.CAPABILITY_MISSING",
            PrivilegeError::Unverifiable => "PLATFORM.PRIV.SANDBOX_DEGRADED",
        }
    }
}

/// One forced substitution, for the integration lead's W-18 amendment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Substitution {
    /// The spelling ADR-0016 §11.12 uses.
    pub specified: &'static str,
    /// The registered code emitted instead.
    pub emitted: &'static str,
    /// What the substitution costs, stated rather than glossed.
    pub cost: &'static str,
}

/// The `PLATFORM.PRIV.*` and `PLATFORM.SERVICE.*` codes this shell needs and the
/// frozen registry does not carry.
///
/// The pattern is `core-dataplane`'s, adopted as the wave standard by
/// `ownership.md` §8 W-18: record the pair, state the cost, and assert with a
/// tripwire that the specified spelling is **still absent** — so registering one
/// fails the build and points at the line to delete.
pub const SUBSTITUTIONS: &[Substitution] = &[
    Substitution {
        specified: "PLATFORM.PRIV.DROP_FAILED",
        emitted: "PLATFORM.ADAPTER_UNAVAILABLE",
        cost: "a fatal privilege-separation failure reads as a generic adapter problem. The \
               remediation differs completely: one is 'fix the unit file', the other is \
               'the platform is unavailable'",
    },
    Substitution {
        specified: "PLATFORM.PRIV.CAPABILITY_MISSING",
        emitted: "PLATFORM.ADAPTER_UNAVAILABLE",
        cost: "loses the named entitlement, which PS-18 requires the code to carry so the \
               operator knows WHICH capability to grant",
    },
    Substitution {
        specified: "PLATFORM.SERVICE.SUPERVISOR_ABSENT",
        emitted: "PLATFORM.ADAPTER_UNAVAILABLE",
        cost: "PS-11's WARN is emitted as a log line with the fact in it rather than as a \
               distinguishable code, so a fleet query cannot count unsupervised agents",
    },
    Substitution {
        specified: "PLATFORM.PRIV.CLIENT_UNAUTHORIZED",
        emitted: "POLICY.POLICY_DENIED",
        cost: "ADR-0017 §11.12 gives this its OWN exit code (4), 'distinct so a script can \
               tell re-run with privilege from this will never work'. Degrading on POLICY \
               tells a correct script to give up",
    },
    Substitution {
        specified: "PLATFORM.SERVICE.QUARANTINED",
        emitted: "MGMT.UNAVAILABLE",
        cost: "PS-9's quarantine stub must answer management with a code that says 'the rules \
               are still installed and this is contained'. MGMT.UNAVAILABLE says only 'not \
               now', which is the fact a UI most needs to distinguish",
    },
];

impl Posture {
    /// Reads this process's actual posture.
    ///
    /// # Errors
    ///
    /// [`PrivilegeError::Unverifiable`] when `/proc/self/status` cannot be read
    /// or parsed. An unverifiable posture is refused, never assumed.
    pub fn read() -> Result<Self, PrivilegeError> {
        let status =
            fs::read_to_string("/proc/self/status").map_err(|_| PrivilegeError::Unverifiable)?;
        Self::parse(&status)
    }

    /// Parses `/proc/self/status`. Separated so the whole check is testable
    /// without being the process it describes.
    ///
    /// # Errors
    ///
    /// [`PrivilegeError::Unverifiable`] on a status file missing `Uid:` or
    /// `CapEff:`.
    pub fn parse(status: &str) -> Result<Self, PrivilegeError> {
        let mut uid = None;
        let mut effective = None;
        let mut bounding = None;
        let mut no_new_privs = false;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                // real, effective, saved, filesystem — the EFFECTIVE one is
                // what matters, and it is the second.
                uid = rest.split_whitespace().nth(1).and_then(|v| v.parse().ok());
            } else if let Some(rest) = line.strip_prefix("CapEff:") {
                effective = u64::from_str_radix(rest.trim(), 16).ok();
            } else if let Some(rest) = line.strip_prefix("CapBnd:") {
                bounding = u64::from_str_radix(rest.trim(), 16).ok();
            } else if let Some(rest) = line.strip_prefix("NoNewPrivs:") {
                no_new_privs = rest.trim() == "1";
            }
        }
        Ok(Self {
            uid: uid.ok_or(PrivilegeError::Unverifiable)?,
            effective: effective.ok_or(PrivilegeError::Unverifiable)?,
            bounding: bounding.unwrap_or(u64::MAX),
            no_new_privs,
            supervised: supervisor_present(),
        })
    }

    /// Checks the posture against §11.2, in the order the ADR states it.
    ///
    /// # Fatal versus degraded, and why the line is where it is
    ///
    /// §11.2's "It MUST NOT **hold** `CAP_SYS_MODULE`" is about what the process
    /// *has*, which is the **effective** set — so holding one there is fatal.
    ///
    /// The **bounding** set is a different question: it bounds what a later
    /// `execve` could gain, and `CapabilityBoundingSet=CAP_NET_ADMIN` is a §11.9
    /// *hardening directive*. PS-17 says exactly what a directive that did not
    /// apply is worth: "the authority MUST emit `PLATFORM.PRIV.SANDBOX_DEGRADED`
    /// at `WARN` **naming the directive**" — a warning, not a refusal. So a wide
    /// bounding set is reported by [`Self::degradations`] and does not stop the
    /// start, which also keeps the agent runnable on a developer host where no
    /// unit narrowed it.
    ///
    /// # Errors
    ///
    /// The first violation. Each is **fatal** at startup: PS-18 forbids starting
    /// "in a mode that cannot arm enforcement while reporting itself as
    /// running", and §11.2 forbids continuing as root.
    pub fn verify(&self) -> Result<(), PrivilegeError> {
        if self.uid == 0 {
            return Err(PrivilegeError::StillRoot);
        }
        for (capability, bit) in FORBIDDEN_CAPABILITIES {
            if self.effective & bit != 0 {
                return Err(PrivilegeError::ForbiddenCapability { capability });
            }
        }
        if self.effective & CAP_NET_ADMIN == 0 {
            return Err(PrivilegeError::CapabilityMissing);
        }
        Ok(())
    }

    /// The §11.9 hardening directives that are **not** in force.
    ///
    /// PS-17: "If any directive in this table fails to apply … the authority
    /// MUST emit `PLATFORM.PRIV.SANDBOX_DEGRADED` at `WARN` **naming the
    /// directive**, and the diagnostic bundle MUST carry the effective posture.
    /// Silently running wider than declared is the defect this rule retires."
    ///
    /// Each entry is the directive's own name, so the log line tells an operator
    /// which line of the unit file to look at.
    #[must_use]
    pub fn degradations(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.no_new_privs {
            out.push("NoNewPrivileges=yes");
        }
        for (_, bit) in FORBIDDEN_CAPABILITIES {
            if self.bounding & bit != 0 {
                out.push("CapabilityBoundingSet=CAP_NET_ADMIN");
                break;
            }
        }
        out
    }
}

/// Whether a recognised supervisor started this process (PS-11).
///
/// `INVOCATION_ID` is set by `systemd` for every unit it starts and by nothing
/// else, which makes it a better answer than "is our parent pid 1" — a container
/// whose PID 1 does not restart us would pass that test and fail PS-11's actual
/// requirement.
fn supervisor_present() -> bool {
    std::env::var_os("INVOCATION_ID").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(uid: u32, eff: u64, bnd: u64) -> String {
        format!("Name:\ttwinvpnd\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nCapEff:\t{eff:016x}\nCapBnd:\t{bnd:016x}\nNoNewPrivs:\t1\n")
    }

    #[test]
    fn the_expected_posture_passes() {
        let posture = Posture::parse(&status(970, CAP_NET_ADMIN, CAP_NET_ADMIN)).expect("parses");
        assert_eq!(posture.uid, 970);
        assert!(posture.no_new_privs);
        posture.verify().expect("the §11.2 posture");
    }

    #[test]
    fn running_as_root_is_fatal_and_never_just_this_once() {
        // §11.2: "Failure to drop is PLATFORM.PRIV.DROP_FAILED and is fatal —
        // the authority MUST NOT continue as root 'just this once'."
        let posture = Posture::parse(&status(0, u64::MAX, u64::MAX)).expect("parses");
        let err = posture.verify().expect_err("root is refused");
        assert_eq!(err, PrivilegeError::StillRoot);
        assert_eq!(err.specified_code(), "PLATFORM.PRIV.DROP_FAILED");
    }

    #[test]
    fn every_capability_11_2_forbids_is_refused_by_name() {
        // "run without CAP_SYS_ADMIN" and "run without CAP_DAC_OVERRIDE" are
        // different instructions to an operator, so the check names which.
        for (capability, bit) in FORBIDDEN_CAPABILITIES {
            let posture = Posture::parse(&status(970, CAP_NET_ADMIN | bit, CAP_NET_ADMIN | bit))
                .expect("parses");
            assert_eq!(
                posture.verify().expect_err("refused"),
                PrivilegeError::ForbiddenCapability { capability }
            );
        }
    }

    #[test]
    fn a_wide_bounding_set_is_a_ps17_degradation_and_not_a_refusal() {
        // §11.2's "MUST NOT hold" is about the EFFECTIVE set. The bounding set
        // bounds what a later `execve` could gain and is a §11.9 hardening
        // directive, which PS-17 makes a WARN naming the directive.
        let (_, bit) = FORBIDDEN_CAPABILITIES[1];
        let posture =
            Posture::parse(&status(970, CAP_NET_ADMIN, CAP_NET_ADMIN | bit)).expect("parses");
        posture.verify().expect("not fatal");
        assert_eq!(
            posture.degradations(),
            vec!["CapabilityBoundingSet=CAP_NET_ADMIN"],
            "PS-17 requires the directive to be NAMED"
        );
    }

    #[test]
    fn a_missing_no_new_privileges_is_named_as_the_directive_it_is() {
        let text =
            status(970, CAP_NET_ADMIN, CAP_NET_ADMIN).replace("NoNewPrivs:\t1", "NoNewPrivs:\t0");
        let posture = Posture::parse(&text).expect("parses");
        posture.verify().expect("not fatal");
        assert!(posture.degradations().contains(&"NoNewPrivileges=yes"));
    }

    #[test]
    fn a_fully_hardened_posture_reports_no_degradations() {
        let posture = Posture::parse(&status(970, CAP_NET_ADMIN, CAP_NET_ADMIN)).expect("parses");
        assert!(posture.degradations().is_empty());
    }

    #[test]
    fn missing_cap_net_admin_is_a_startup_failure_not_a_degradation() {
        // PS-18: "The authority MUST NOT start in a mode that cannot arm
        // enforcement while reporting itself as running."
        let posture = Posture::parse(&status(970, 0, 0)).expect("parses");
        let err = posture.verify().expect_err("refused");
        assert_eq!(err, PrivilegeError::CapabilityMissing);
        assert_eq!(err.specified_code(), "PLATFORM.PRIV.CAPABILITY_MISSING");
    }

    #[test]
    fn an_unverifiable_posture_is_refused_rather_than_assumed() {
        assert_eq!(
            Posture::parse("Name:\ttwinvpnd\n").expect_err("no Uid"),
            PrivilegeError::Unverifiable
        );
        assert_eq!(
            Posture::parse("Uid:\t970\t970\t970\t970\n").expect_err("no CapEff"),
            PrivilegeError::Unverifiable
        );
    }

    #[test]
    fn this_test_process_can_read_its_own_posture() {
        // The parser is exercised against a real `/proc/self/status`, so a
        // format change fails here rather than at a customer's startup.
        let posture = Posture::read().expect("reads /proc/self/status");
        // The test runner is unprivileged, so `verify` refuses — which is
        // itself the assertion: the check is real and would have caught a
        // daemon started without its capability.
        assert!(posture.verify().is_err() || posture.effective & CAP_NET_ADMIN != 0);
    }

    /// **The W-18 tripwire.** Deleting a row is what a registry addition looks
    /// like, and this fails the build until the row is deleted.
    #[test]
    fn every_substituted_spelling_is_still_absent_from_the_frozen_registry() {
        for substitution in SUBSTITUTIONS {
            assert!(
                twinvpn_types::ReasonCode::lookup(substitution.specified).is_none(),
                "{} is now REGISTERED. Delete its row from SUBSTITUTIONS and emit it \
                 directly — the substitution's cost is recorded there.",
                substitution.specified
            );
            assert!(
                twinvpn_types::ReasonCode::lookup(substitution.emitted).is_some(),
                "{} must be a registered code",
                substitution.emitted
            );
        }
    }
}
