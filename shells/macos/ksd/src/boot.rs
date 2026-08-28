//! The boot sequence, as a **value the log line can carry** rather than a chain
//! of `if`s in `main`.
//!
//! **Authority:** ADR-0016 §11.2's macOS row and amendment **PS-22**, §11.5's
//! macOS durability row, §11.6 (start ordering), PS-7, PS-8, PS-18; ADR-0012
//! KS-19, KS-20, §11.6's macOS row; `ownership.md` §8 **W-24**.
//!
//! # What survived the move, and what did not
//!
//! `twinvpnd`'s start sequence had ten steps. Eight of them belonged to the
//! authority and moved into the system extension with it: the clocks, the
//! runtime's I/O driver, the capability probe's KS-9 half, the durable vault,
//! the core, the MI endpoint, the privilege *drop* argument, and `accept`.
//!
//! Four remain, and each is here because `ksd` is the component that does it:
//!
//! | Step | Why it is `ksd`'s |
//! |---|---|
//! | [`Step::Privilege`] | `pfctl` needs uid 0, and there is no macOS spelling of "this capability and nothing else" |
//! | [`Step::AnchorBody`] | PS-7: the package owns `/etc/twinvpn/pf.anchor`; `ksd` reads it and **never writes it** |
//! | [`Step::Apply`] | KS-19: the rule set that covers the interval between the network stack coming up and the authority starting |
//! | [`Step::ReadBack`] | **W-24.** The assertion is what `pfctl` says is loaded, never the fact that a load returned `Ok` |
//!
//! **The read-back did not become optional by getting smaller.** It is the one
//! step whose absence would let this daemon report a protected host that is not
//! protected, which is precisely the defect W-24 exists to name.
//!
//! # Testable on a host with no macOS
//!
//! Every check goes through [`BootProbes`], which is injected. The sequence's
//! *logic* — what is fatal, in what order, and what it records — is exercised by
//! `cargo test` on the Linux host; only the `Pfctl` implementation needs a Mac.

use twinvpn_types::{codes, ReasonCode};

/// One step of the boot sequence.
///
/// The order of this enum **is** the order of the sequence, and [`Step::ALL`]
/// walks it — so a step cannot be added without appearing in the sequence, and
/// cannot be reordered without the reorder being visible here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    /// Root, because `pfctl` needs it.
    Privilege,
    /// The package-owned anchor body (PS-7).
    AnchorBody,
    /// One `pfctl -a twinvpn -f -`, as a single transaction.
    Apply,
    /// **W-24.** What the kernel says is loaded.
    ReadBack,
}

impl Step {
    /// Every step, in order.
    pub const ALL: [Self; 4] = [
        Self::Privilege,
        Self::AnchorBody,
        Self::Apply,
        Self::ReadBack,
    ];

    /// A stable, non-localised tag for a log line.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Step::Privilege => "privilege",
            Step::AnchorBody => "anchor_body",
            Step::Apply => "apply",
            Step::ReadBack => "read_back",
        }
    }
}

/// What a step found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The step passed.
    Passed,
    /// The step failed and the boot anchor is not in force.
    Refused(ReasonCode),
}

impl Outcome {
    /// Whether this outcome stops the sequence.
    #[must_use]
    pub const fn is_fatal(self) -> bool {
        matches!(self, Outcome::Refused(_))
    }
}

/// The whole sequence, as it ran.
#[derive(Debug, Clone, Default)]
pub struct BootSequence {
    steps: Vec<(Step, Outcome)>,
}

impl BootSequence {
    /// Every step that ran, in order, with what it found.
    #[must_use]
    pub fn steps(&self) -> &[(Step, Outcome)] {
        &self.steps
    }

    /// Whether the boot anchor is loaded **and confirmed loaded**.
    #[must_use]
    pub fn is_applied(&self) -> bool {
        self.steps.len() == Step::ALL.len()
            && self.steps.iter().all(|(_, outcome)| !outcome.is_fatal())
    }

    /// The step that refused, if one did.
    #[must_use]
    pub fn refusal(&self) -> Option<(Step, ReasonCode)> {
        self.steps.iter().find_map(|(step, outcome)| match outcome {
            Outcome::Refused(code) => Some((*step, *code)),
            Outcome::Passed => None,
        })
    }
}

/// What the sequence asks the host.
///
/// Injected, so the logic is testable with no Mac. Each method answers a
/// **fact**; none of them decides what the fact means.
pub trait BootProbes {
    /// Whether this process is root.
    fn is_root(&self) -> bool;

    /// The package-owned anchor body, or `None` if it is not installed.
    ///
    /// **Read, never written.** PS-7: "installed by the package, modified only
    /// by atomic replace under ADMINISTER; the authority MUST NOT rewrite it as
    /// a runtime action". There is no method on this trait that writes it, which
    /// is the mechanism rather than a comment about one.
    fn anchor_body(&self) -> Option<String>;

    /// Loads `body` into the anchor, as **one** transaction.
    ///
    /// One invocation, because `pf` applies a load atomically. A
    /// flush-then-load in two calls would open exactly the window KS-17 exists
    /// to close.
    fn apply(&self, body: &str) -> bool;

    /// **The W-24 query.** Whether the kernel now reports our anchor loaded into
    /// an enabled filter — not whether [`BootProbes::apply`] returned success.
    fn read_back(&self) -> bool;
}

/// Runs the sequence.
///
/// **Stops at the first refusal.** The steps that did not run are absent from
/// [`BootSequence::steps`] rather than recorded as passed, so a log line shows
/// how far it got.
#[must_use]
pub fn run(probes: &dyn BootProbes) -> BootSequence {
    let mut sequence = BootSequence::default();

    if !probes.is_root() {
        sequence.steps.push((
            Step::Privilege,
            Outcome::Refused(codes::PLATFORM_VPN_PERMISSION_DENIED),
        ));
        return sequence;
    }
    sequence.steps.push((Step::Privilege, Outcome::Passed));

    let Some(body) = probes.anchor_body() else {
        // ADR-0012 §11.6 and KS-19: without the artifact there is no boot-time
        // enforcement at all. `PLATFORM.SERVICE.BOOT_ARTIFACT_UNREGISTERED` is
        // the registry's own name for that condition, and it is a REFUSAL here
        // rather than the degradation the authority records — because applying
        // the boot anchor is the entire job of this process, and a job with
        // nothing to do that exits 0 is a job nobody notices has stopped
        // working.
        sequence.steps.push((
            Step::AnchorBody,
            Outcome::Refused(codes::PLATFORM_SERVICE_BOOT_ARTIFACT_UNREGISTERED),
        ));
        return sequence;
    };
    sequence.steps.push((Step::AnchorBody, Outcome::Passed));

    if !probes.apply(&body) {
        sequence.steps.push((
            Step::Apply,
            Outcome::Refused(codes::POLICY_KILLSWITCH_ARM_FAILED),
        ));
        return sequence;
    }
    sequence.steps.push((Step::Apply, Outcome::Passed));

    if probes.read_back() {
        sequence.steps.push((Step::ReadBack, Outcome::Passed));
    } else {
        // **W-24, and the only code that fits.** The load reported success and
        // the kernel does not agree. `POLICY.KILLSWITCH.ASSERTION_MISMATCH` is
        // the registry's "installed rules differ from intended policy" (O-17),
        // which is exactly this and is not `ARM_FAILED`: arming did not fail,
        // it lied.
        sequence.steps.push((
            Step::ReadBack,
            Outcome::Refused(codes::POLICY_KILLSWITCH_ASSERTION_MISMATCH),
        ));
    }
    sequence
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host on which everything is in order.
    struct Healthy;

    impl BootProbes for Healthy {
        fn is_root(&self) -> bool {
            true
        }
        fn anchor_body(&self) -> Option<String> {
            Some("block drop all\n".to_owned())
        }
        fn apply(&self, _body: &str) -> bool {
            true
        }
        fn read_back(&self) -> bool {
            true
        }
    }

    /// `Healthy`, with one probe forced to fail.
    struct Broken {
        which: Step,
    }

    impl BootProbes for Broken {
        fn is_root(&self) -> bool {
            self.which != Step::Privilege
        }
        fn anchor_body(&self) -> Option<String> {
            (self.which != Step::AnchorBody).then(|| "block drop all\n".to_owned())
        }
        fn apply(&self, _body: &str) -> bool {
            self.which != Step::Apply
        }
        fn read_back(&self) -> bool {
            self.which != Step::ReadBack
        }
    }

    #[test]
    fn a_healthy_host_applies_the_anchor_and_records_every_step() {
        let sequence = run(&Healthy);
        assert!(sequence.is_applied());
        assert_eq!(sequence.steps().len(), Step::ALL.len());
        assert_eq!(sequence.refusal(), None);
        let ran: Vec<Step> = sequence.steps().iter().map(|(s, _)| *s).collect();
        assert_eq!(ran, Step::ALL.to_vec());
    }

    #[test]
    fn every_step_stops_the_sequence_where_it_failed() {
        for which in Step::ALL {
            let sequence = run(&Broken { which });
            assert!(!sequence.is_applied(), "{which:?} did not stop the boot");
            let (step, code) = sequence.refusal().expect("a refusal");
            assert_eq!(step, which);
            assert!(code.as_str().contains('.'), "a registered code");
            assert_eq!(
                sequence.steps().len(),
                Step::ALL.iter().position(|s| *s == which).expect("a step") + 1,
                "steps after the refusal must not be recorded"
            );
        }
    }

    #[test]
    fn a_load_that_returned_ok_is_not_a_read_back() {
        // **W-24, and the reason this step did not move to the extension with
        // everything else.** `apply` succeeded here — the probe says so — and
        // the sequence still refuses, because the kernel does not agree.
        let sequence = run(&Broken {
            which: Step::ReadBack,
        });
        assert_eq!(
            sequence.refusal().map(|(_, c)| c.as_str()),
            Some("POLICY.KILLSWITCH.ASSERTION_MISMATCH")
        );
        // And the failure is DISTINGUISHABLE from arming having failed: they
        // have different next actions, so they must not share a code.
        let armed = run(&Broken { which: Step::Apply });
        assert_ne!(
            armed.refusal().map(|(_, c)| c.as_str()),
            sequence.refusal().map(|(_, c)| c.as_str())
        );
    }

    #[test]
    fn the_anchor_body_is_read_and_this_module_has_no_way_to_write_one() {
        // PS-7 as an API shape. `BootProbes` has `anchor_body` and no
        // `write_anchor`, so "the authority rewrote the package's artifact" is
        // not something a caller can do by forgetting a branch.
        let source = include_str!("boot.rs");
        let production = source.split("#[cfg(test)]").next().expect("a first half");
        for forbidden in ["fs::write", "write_anchor", "File::create", "OpenOptions"] {
            assert!(
                !production.contains(forbidden),
                "{forbidden} would let ksd rewrite a package-owned artifact"
            );
        }
    }

    #[test]
    fn this_daemon_has_no_step_that_serves_a_request() {
        // PS-22's table: `ksd` holds "no core, no keys, no network sockets, no
        // management interface". The sequence is four steps and none of them
        // accepts anything, which is the structural form of that rule.
        assert_eq!(Step::ALL.len(), 4);
        let tags: Vec<&str> = Step::ALL.iter().map(|s| s.tag()).collect();
        for absent in ["endpoint", "accept", "core", "mgmt", "listen"] {
            assert!(!tags.contains(&absent), "{absent} is not ksd's");
        }
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
