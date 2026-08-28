//! ADR-0016 §11.6's start sequence, as a **value the diagnostic bundle can
//! carry** rather than a sequence of `if`s in `main`.
//!
//! **Authority:** ADR-0016 §11.6 ("start ordering, normatively"), §11.2, §11.5's
//! macOS row, PS-7, PS-8, PS-11, PS-17, PS-18; ADR-0012 §8 and KS-20; ADR-0015
//! §11.6 rule 1; `docs/implementation/ownership.md` §8 **W-24** and **W-43**.
//!
//! # Why it is a value
//!
//! §11.6 says the authority "reaches `ready` only after" five things, and PS-18
//! forbids starting "in a mode that cannot arm enforcement while reporting itself
//! as running". Both are statements about a **sequence with outcomes**, and a
//! sequence with outcomes is exactly what a support case needs to see. So
//! [`run`] returns a [`StartSequence`] — every step, what it found, and whether
//! that was fatal — and `main` renders it and exits. The alternative, a chain of
//! early returns, produces a log line for the step that failed and no record of
//! the ones that passed.
//!
//! # Testable on a host with no macOS
//!
//! Every check goes through [`StartProbes`], which is injected. So the sequence's
//! *logic* — what is fatal, what warns, what order they run in, what the bundle
//! records — is exercised by `cargo test` on this Linux host, and only the
//! `DarwinProbes` implementation needs a Mac.

use twinvpn_types::ReasonCode;

/// One step of §11.6's sequence.
///
/// The order of this enum **is** the order of the sequence, and [`Step::ALL`]
/// walks it — so a step cannot be added without appearing in the sequence, and
/// cannot be reordered without the reorder being visible here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    /// §11.6 (1) — the KS-19 boot artifact's presence (PS-7).
    BootArtifact,
    /// §11.2 — the privilege posture (PS-17, PS-18).
    PrivilegePosture,
    /// The three clocks, the CSPRNG and the boot identity (ADR-0022 LC-8, W-7).
    Clocks,
    /// The injected runtime's I/O driver (**W-43**).
    RuntimeIoDriver,
    /// The adapter's capability probe (ADR-0012 §8, PS-18).
    CapabilityProbe,
    /// §11.6 (2) — reclaim the owner-tagged ruleset and **read it back**
    /// (KS-20, PS-8, W-24).
    EnforcementReclaim,
    /// §11.6 (4) — durable state (ADR-0020's vault directory).
    DurableState,
    /// §11.6 (5) — the core, ABI-checked first (VR-4).
    Core,
    /// §11.6 (6) — the MI endpoint (MI-A3).
    MgmtEndpoint,
    /// §11.6 (7) — accept connections. Only now.
    Accept,
}

impl Step {
    /// Every step, in order.
    pub const ALL: [Self; 10] = [
        Self::BootArtifact,
        Self::PrivilegePosture,
        Self::Clocks,
        Self::RuntimeIoDriver,
        Self::CapabilityProbe,
        Self::EnforcementReclaim,
        Self::DurableState,
        Self::Core,
        Self::MgmtEndpoint,
        Self::Accept,
    ];

    /// A stable, non-localised tag for the bundle.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Step::BootArtifact => "boot_artifact",
            Step::PrivilegePosture => "privilege_posture",
            Step::Clocks => "clocks",
            Step::RuntimeIoDriver => "runtime_io_driver",
            Step::CapabilityProbe => "capability_probe",
            Step::EnforcementReclaim => "enforcement_reclaim",
            Step::DurableState => "durable_state",
            Step::Core => "core",
            Step::MgmtEndpoint => "mgmt_endpoint",
            Step::Accept => "accept",
        }
    }
}

/// What a step found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The step passed.
    Passed,
    /// The step found a degradation the authority reports and continues past.
    ///
    /// PS-17: "a hardening directive that cannot be applied is reported, not
    /// skipped … silently running wider than declared is the defect this rule
    /// retires."
    Degraded(ReasonCode),
    /// The step failed and the authority must not start.
    ///
    /// PS-18: "MUST NOT start in a mode that cannot arm enforcement while
    /// reporting itself as running."
    Refused(ReasonCode),
}

impl Outcome {
    /// Whether this outcome stops the sequence.
    #[must_use]
    pub const fn is_fatal(self) -> bool {
        matches!(self, Outcome::Refused(_))
    }

    /// The code, where there is one.
    #[must_use]
    pub const fn reason_code(self) -> Option<ReasonCode> {
        match self {
            Outcome::Passed => None,
            Outcome::Degraded(code) | Outcome::Refused(code) => Some(code),
        }
    }
}

/// The whole sequence, as it ran.
#[derive(Debug, Clone, Default)]
pub struct StartSequence {
    steps: Vec<(Step, Outcome)>,
}

impl StartSequence {
    /// Every step that ran, in order, with what it found.
    #[must_use]
    pub fn steps(&self) -> &[(Step, Outcome)] {
        &self.steps
    }

    /// Whether the authority may reach `ready`.
    ///
    /// §11.6: "only after" every step. A sequence that stopped early has not.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.steps.len() == Step::ALL.len()
            && self.steps.iter().all(|(_, outcome)| !outcome.is_fatal())
    }

    /// The step that refused, if one did.
    #[must_use]
    pub fn refusal(&self) -> Option<(Step, ReasonCode)> {
        self.steps.iter().find_map(|(step, outcome)| match outcome {
            Outcome::Refused(code) => Some((*step, *code)),
            _ => None,
        })
    }

    /// Every degradation, in order. Each is a named warning an operator can see
    /// rather than infer.
    #[must_use]
    pub fn degradations(&self) -> Vec<(Step, ReasonCode)> {
        self.steps
            .iter()
            .filter_map(|(step, outcome)| match outcome {
                Outcome::Degraded(code) => Some((*step, *code)),
                _ => None,
            })
            .collect()
    }
}

/// What the sequence asks the host.
///
/// Injected (CD-2), so the sequence's logic is testable with no Mac. Each method
/// answers a **fact**; none of them decides what the fact means.
pub trait StartProbes {
    /// Whether the KS-19 boot artifact — the `com.twinvpn.ksd` `LaunchDaemon`
    /// and the `/etc/twinvpn/pf.anchor` it applies — is installed.
    fn boot_artifact_installed(&self) -> bool;

    /// Whether this process is root.
    ///
    /// **On macOS this is the whole privilege posture, and that is the gap.**
    /// ADR-0016 §11.2 says the authority "MUST NOT continue as root 'just this
    /// once'", and Linux discharges it by dropping to `CAP_NET_ADMIN` alone.
    /// macOS has **no spelling of "this capability and nothing else"**: `pf`,
    /// the route socket and `SCDynamicStore` all require root, and the
    /// equivalents of `systemd`'s hardening directives are set at *codesign*
    /// time (hardened runtime, library validation) rather than by the
    /// supervisor. So this returns the only fact there is, and
    /// [`run`] reports the unsatisfiable half as a **named degradation**
    /// rather than pretending it was applied.
    fn is_root(&self) -> bool;

    /// Whether a recognised supervisor started us (PS-11).
    fn under_supervisor(&self) -> bool;

    /// Whether the three clocks, the CSPRNG and the boot identity all bind.
    fn clocks_bind(&self) -> bool;

    /// Whether the injected runtime has an I/O driver (**W-43**).
    fn runtime_has_io(&self) -> bool;

    /// Whether the enforcement layer can be reached at all (ADR-0012 §8).
    fn enforcement_available(&self) -> bool;

    /// Whether KS-9(1)'s macOS predicate holds in full.
    fn ks9_complete(&self) -> bool;

    /// Whether the owner-tagged ruleset was reclaimed **and read back from the
    /// kernel** — the W-24 query, not the fact that a load returned `Ok`.
    fn enforcement_read_back(&self) -> bool;

    /// Whether the vault directory exists with ADR-0016 O8's `0700`.
    fn vault_ready(&self) -> bool;

    /// Whether the core constructed, ABI check included (VR-4).
    fn core_ready(&self) -> bool;

    /// Whether the MI endpoint bound, MI-A3's checks included.
    fn endpoint_ready(&self) -> bool;
}

/// Runs the sequence.
///
/// **Stops at the first refusal.** The steps that did not run are absent from
/// [`StartSequence::steps`] rather than recorded as passed, so a bundle shows how
/// far the authority got.
#[must_use]
pub fn run(probes: &dyn StartProbes) -> StartSequence {
    let mut sequence = StartSequence::default();
    for step in Step::ALL {
        let outcome = evaluate(step, probes);
        let fatal = outcome.is_fatal();
        sequence.steps.push((step, outcome));
        if fatal {
            break;
        }
    }
    sequence
}

fn evaluate(step: Step, probes: &dyn StartProbes) -> Outcome {
    use twinvpn_types::codes;
    match step {
        // **§11.6 (1) vs PS-7, and a divergence deliberately not created.**
        //
        // §11.6 step 1 reads as a refusal; PS-7 says the boot artifact "MUST NOT
        // be a prerequisite for [the authority] to apply". `desktop-linux` read
        // the pair as warn-and-continue, on the ground that refusing "would leave
        // the host with neither the boot ruleset *nor* an agent", and this shell
        // takes the SAME reading — not because it is obviously right, but because
        // two shells behaving differently on one rule is worse than either
        // reading. The ambiguity is reported to the integration lead.
        Step::BootArtifact => {
            if probes.boot_artifact_installed() {
                Outcome::Passed
            } else {
                Outcome::Degraded(codes::PLATFORM_ADAPTER_UNAVAILABLE)
            }
        }
        // Not root means pf cannot be programmed at all, which PS-18 makes a
        // startup failure. Root *with* no way to drop is the degradation above.
        Step::PrivilegePosture => {
            if !probes.is_root() {
                Outcome::Refused(codes::PLATFORM_VPN_PERMISSION_DENIED)
            } else if !probes.under_supervisor() {
                // PS-11: an unsupervised authority does not claim supervised
                // guarantees.
                Outcome::Degraded(codes::PLATFORM_PRIV_SANDBOX_DEGRADED)
            } else {
                // PS-17. The authority runs as root and cannot narrow itself,
                // and it says so on every start rather than letting a reader
                // assume a sandbox that is not there.
                Outcome::Degraded(codes::PLATFORM_PRIV_SANDBOX_DEGRADED)
            }
        }
        Step::Clocks => {
            if probes.clocks_bind() {
                Outcome::Passed
            } else {
                // A clock with a guessed timebase is wrong by 41x on Apple
                // silicon, and an unseeded CSPRNG is worse. Fatal.
                Outcome::Refused(codes::INTERNAL_UNEXPECTED_STATE)
            }
        }
        // **W-43.** `twinvpn-env`'s `TokioRuntime` once built with `enable_time()`
        // and not `enable_io()`, so no socket could be opened at all and the
        // agent panicked on the first command. It is fixed; the probe stays,
        // because PS-18's rule is to refuse at startup rather than report a
        // running agent that can do nothing.
        Step::RuntimeIoDriver => {
            if probes.runtime_has_io() {
                Outcome::Passed
            } else {
                Outcome::Refused(codes::INTERNAL_UNEXPECTED_STATE)
            }
        }
        // ADR-0012 §8: arming must never fail open. PS-18: MUST NOT start in a
        // mode that cannot arm enforcement while reporting itself as running.
        Step::CapabilityProbe => {
            if !probes.enforcement_available() {
                Outcome::Refused(codes::PLATFORM_ADAPTER_UNAVAILABLE)
            } else if probes.ks9_complete() {
                Outcome::Passed
            } else {
                // The bootstrap exemption rests on the uid alone, which is weaker
                // than KS-9(1) specifies. Named, never silently upgraded.
                Outcome::Degraded(codes::PLATFORM_PRIV_SANDBOX_DEGRADED)
            }
        }
        // §11.6 (2), and the half that matters: the ruleset is reclaimed **and
        // read back from the kernel**. A flag set to `true` after a successful
        // load is what W-24 exists to reject.
        Step::EnforcementReclaim => {
            if probes.enforcement_read_back() {
                Outcome::Passed
            } else {
                Outcome::Refused(codes::PLATFORM_ADAPTER_UNAVAILABLE)
            }
        }
        Step::DurableState => {
            if probes.vault_ready() {
                Outcome::Passed
            } else {
                Outcome::Refused(codes::AUTH_KEY_STORE_UNAVAILABLE)
            }
        }
        Step::Core => {
            if probes.core_ready() {
                Outcome::Passed
            } else {
                // VR-4: a mismatch is a packaging defect, not an operating state
                // — and it is still checked, because the alternative is
                // undefined behaviour.
                Outcome::Refused(codes::INTERNAL_ABI_VERSION_MISMATCH)
            }
        }
        Step::MgmtEndpoint => {
            if probes.endpoint_ready() {
                Outcome::Passed
            } else {
                Outcome::Refused(twinvpn_mgmt::codes::unavailable())
            }
        }
        // Reached only when every earlier step did.
        Step::Accept => Outcome::Passed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host on which everything is in order.
    struct Healthy;

    impl StartProbes for Healthy {
        fn boot_artifact_installed(&self) -> bool {
            true
        }
        fn is_root(&self) -> bool {
            true
        }
        fn under_supervisor(&self) -> bool {
            true
        }
        fn clocks_bind(&self) -> bool {
            true
        }
        fn runtime_has_io(&self) -> bool {
            true
        }
        fn enforcement_available(&self) -> bool {
            true
        }
        fn ks9_complete(&self) -> bool {
            true
        }
        fn enforcement_read_back(&self) -> bool {
            true
        }
        fn vault_ready(&self) -> bool {
            true
        }
        fn core_ready(&self) -> bool {
            true
        }
        fn endpoint_ready(&self) -> bool {
            true
        }
    }

    /// `Healthy`, with one probe forced.
    struct Broken {
        which: Step,
    }

    impl StartProbes for Broken {
        fn boot_artifact_installed(&self) -> bool {
            self.which != Step::BootArtifact
        }
        fn is_root(&self) -> bool {
            self.which != Step::PrivilegePosture
        }
        fn under_supervisor(&self) -> bool {
            true
        }
        fn clocks_bind(&self) -> bool {
            self.which != Step::Clocks
        }
        fn runtime_has_io(&self) -> bool {
            self.which != Step::RuntimeIoDriver
        }
        fn enforcement_available(&self) -> bool {
            self.which != Step::CapabilityProbe
        }
        fn ks9_complete(&self) -> bool {
            true
        }
        fn enforcement_read_back(&self) -> bool {
            self.which != Step::EnforcementReclaim
        }
        fn vault_ready(&self) -> bool {
            self.which != Step::DurableState
        }
        fn core_ready(&self) -> bool {
            self.which != Step::Core
        }
        fn endpoint_ready(&self) -> bool {
            self.which != Step::MgmtEndpoint
        }
    }

    #[test]
    fn a_healthy_host_reaches_ready_and_records_every_step() {
        let sequence = run(&Healthy);
        assert!(sequence.is_ready());
        assert_eq!(sequence.steps().len(), Step::ALL.len());
        assert_eq!(sequence.refusal(), None);
        // Even a healthy macOS host is degraded, and says so: there is no
        // spelling of "this capability and nothing else" on this platform.
        assert_eq!(sequence.degradations().len(), 1);
        assert_eq!(sequence.degradations()[0].0, Step::PrivilegePosture);
    }

    #[test]
    fn the_order_is_11_6s_and_the_enum_is_the_order() {
        let sequence = run(&Healthy);
        let ran: Vec<Step> = sequence.steps().iter().map(|(s, _)| *s).collect();
        assert_eq!(ran, Step::ALL.to_vec());
        // Accept is last, and §11.6 says "only then does it accept management
        // connections".
        assert_eq!(*Step::ALL.last().expect("non-empty"), Step::Accept);
        // Enforcement is reclaimed and read back BEFORE the MI endpoint binds: a
        // client that attached first could ask for a posture nobody had verified.
        let position = |step: Step| Step::ALL.iter().position(|s| *s == step);
        assert!(position(Step::EnforcementReclaim) < position(Step::MgmtEndpoint));
        assert!(position(Step::CapabilityProbe) < position(Step::EnforcementReclaim));
    }

    #[test]
    fn every_fatal_step_stops_the_sequence_where_it_failed() {
        // PS-18. A bundle must show how far the authority got, so the steps after
        // a refusal are ABSENT rather than recorded as passed.
        for which in [
            Step::PrivilegePosture,
            Step::Clocks,
            Step::RuntimeIoDriver,
            Step::CapabilityProbe,
            Step::EnforcementReclaim,
            Step::DurableState,
            Step::Core,
            Step::MgmtEndpoint,
        ] {
            let sequence = run(&Broken { which });
            assert!(!sequence.is_ready(), "{which:?} did not stop the start");
            let (step, code) = sequence.refusal().expect("a refusal");
            assert_eq!(step, which);
            assert!(code.as_str().contains('.'), "a registered code");
            let position = Step::ALL.iter().position(|s| *s == which).expect("a step");
            assert_eq!(
                sequence.steps().len(),
                position + 1,
                "steps after the refusal must not be recorded"
            );
        }
    }

    #[test]
    fn a_missing_boot_artifact_warns_and_the_agent_still_starts() {
        // The §11.6-vs-PS-7 reading, pinned as a test so a change to it is
        // visible rather than incidental. Matches `desktop-linux`.
        let sequence = run(&Broken {
            which: Step::BootArtifact,
        });
        assert!(sequence.is_ready());
        assert_eq!(sequence.refusal(), None);
        assert!(sequence
            .degradations()
            .iter()
            .any(|(step, _)| *step == Step::BootArtifact));
    }

    #[test]
    fn an_enforcement_layer_that_cannot_be_reached_is_fatal_and_never_a_warning() {
        // ADR-0012 §8: arming must never fail open. An agent that started here
        // would report itself running while unable to protect anything.
        let sequence = run(&Broken {
            which: Step::CapabilityProbe,
        });
        assert!(!sequence.is_ready());
        assert_eq!(
            sequence.refusal().map(|(_, c)| c.as_str()),
            Some("PLATFORM.ADAPTER_UNAVAILABLE")
        );
    }

    #[test]
    fn a_load_that_returned_ok_is_not_a_read_back() {
        // W-24's whole point: the assertion is a QUERY. `enforcement_available`
        // is true here — `pfctl` is present and the load worked — and the
        // read-back still refuses.
        struct LoadedButUnverified;
        impl StartProbes for LoadedButUnverified {
            fn boot_artifact_installed(&self) -> bool {
                true
            }
            fn is_root(&self) -> bool {
                true
            }
            fn under_supervisor(&self) -> bool {
                true
            }
            fn clocks_bind(&self) -> bool {
                true
            }
            fn runtime_has_io(&self) -> bool {
                true
            }
            fn enforcement_available(&self) -> bool {
                true
            }
            fn ks9_complete(&self) -> bool {
                true
            }
            fn enforcement_read_back(&self) -> bool {
                false
            }
            fn vault_ready(&self) -> bool {
                true
            }
            fn core_ready(&self) -> bool {
                true
            }
            fn endpoint_ready(&self) -> bool {
                true
            }
        }
        let sequence = run(&LoadedButUnverified);
        assert_eq!(
            sequence.refusal().map(|(s, _)| s),
            Some(Step::EnforcementReclaim)
        );
    }

    #[test]
    fn a_weaker_ks9_predicate_is_named_rather_than_upgraded() {
        struct UidOnly;
        impl StartProbes for UidOnly {
            fn boot_artifact_installed(&self) -> bool {
                true
            }
            fn is_root(&self) -> bool {
                true
            }
            fn under_supervisor(&self) -> bool {
                true
            }
            fn clocks_bind(&self) -> bool {
                true
            }
            fn runtime_has_io(&self) -> bool {
                true
            }
            fn enforcement_available(&self) -> bool {
                true
            }
            fn ks9_complete(&self) -> bool {
                false
            }
            fn enforcement_read_back(&self) -> bool {
                true
            }
            fn vault_ready(&self) -> bool {
                true
            }
            fn core_ready(&self) -> bool {
                true
            }
            fn endpoint_ready(&self) -> bool {
                true
            }
        }
        let sequence = run(&UidOnly);
        assert!(sequence.is_ready(), "weaker is not unusable");
        assert!(sequence
            .degradations()
            .iter()
            .any(|(step, _)| *step == Step::CapabilityProbe));
    }

    #[test]
    fn every_step_has_a_stable_tag_and_no_two_share_one() {
        let mut tags: Vec<&str> = Step::ALL.iter().map(|s| s.tag()).collect();
        let count = tags.len();
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), count);
        assert!(tags.iter().all(|t| !t.is_empty()));
    }
}
