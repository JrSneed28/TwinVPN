//! §3.6's run record — "a verdict not bound to a run record is not a result."
//!
//! **Authority:** `docs/testing-strategy.md` §3.6, §6.5 rule **C-5**
//! (evidence binding), §6.5 blocker **B-15**.
//!
//! # What is recorded, and what is deliberately not
//!
//! §3.6 enumerates the record's contents. Everything it names that can be
//! produced without a live rig is produced here: the scenario document's content
//! hash, the resolved seed, the host's kernel and tool versions, the §3.4.2
//! conformance results, the executed command log, and the per-oracle verdict.
//!
//! Two of §3.6's fields are **not** produced, and are named as absent rather
//! than defaulted, because inventing them would be worse than lacking them:
//!
//! - **the commit or dirty-worktree snapshot of every binary in the rig** —
//!   [`RunRecord::binaries`] is empty unless a caller supplies it, because a
//!   record that asserts a commit it did not verify is exactly the unbound
//!   evidence C-5 exists to prevent;
//! - **the signature** — §3.6 says "signed"; signing needs a key, and this
//!   domain generates no key material and holds none. [`RunRecord::signed`] is
//!   `false` and [`RunRecord::is_release_evidence`] returns `false` while it is.
//!
//! The record is therefore honest about being *unsigned run evidence* rather
//! than release evidence, which is a smaller claim and a true one.

use crate::capability::HostCapabilities;
use crate::determinism::{Class, Tier};
use crate::exec::Invocation;
use crate::outcome::Verdict;

/// One oracle's verdict inside a run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OracleResult {
    /// The oracle's name, as the scenario declares it.
    pub oracle: String,
    /// What it decided.
    pub verdict: Verdict,
}

/// A §3.4.2 conformance result for one simulator.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConformanceResult {
    /// Which simulator.
    pub simulator: String,
    /// The assertion.
    pub assertion: String,
    /// Whether it held. A `false` here voids the whole run (**B-15**).
    pub passed: bool,
}

/// §3.6's run record.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunRecord {
    /// The scenario id.
    pub scenario_id: String,
    /// SHA-256 of the scenario document, as `twinvpn-crypto` computes it.
    pub document_hash: String,
    /// The resolved seed, in hex.
    pub seed: String,
    /// The declared determinism class.
    pub determinism: Class,
    /// The tiers this scenario belongs to.
    pub tiers: Vec<Tier>,
    /// The host's probed capabilities, including the kernel version §3.6 wants.
    pub host: HostCapabilities,
    /// The `tc`/`nft`/`ip` version strings, where the tools exist.
    pub tool_versions: Vec<(String, String)>,
    /// §3.4.2's conformance results for every simulator the run used.
    pub conformance: Vec<ConformanceResult>,
    /// Every command the run executed.
    pub commands: Vec<Invocation>,
    /// One entry per oracle.
    pub oracles: Vec<OracleResult>,
    /// The binaries in the rig, bound to a commit or a snapshot. Empty means
    /// **not established**, never "clean".
    pub binaries: Vec<(String, String)>,
    /// Whether the record carries a signature. Always `false` from this domain.
    pub signed: bool,
}

impl RunRecord {
    /// A record for a scenario, with the host probed.
    #[must_use]
    pub fn new(scenario_id: &str, document: &str, seed: &str, determinism: Class) -> Self {
        Self {
            scenario_id: scenario_id.to_owned(),
            document_hash: document_hash(document),
            seed: seed.to_owned(),
            determinism,
            tiers: Vec::new(),
            host: HostCapabilities::probe(),
            tool_versions: Vec::new(),
            conformance: Vec::new(),
            commands: Vec::new(),
            oracles: Vec::new(),
            binaries: Vec::new(),
            signed: false,
        }
    }

    /// The run's overall verdict.
    ///
    /// A conformance failure **voids** the run before any oracle is consulted —
    /// B-15's "the results are void, not merely suspect". Then a blocking oracle
    /// wins over an unavailable one, and an unavailable one over a pass, so a
    /// run is never reported greener than its weakest component.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        if let Some(c) = self.conformance.iter().find(|c| !c.passed) {
            return Verdict::Void {
                simulator: c.simulator.clone(),
                assertion: c.assertion.clone(),
            };
        }
        if let Some(o) = self.oracles.iter().find(|o| o.verdict.is_blocking()) {
            return o.verdict.clone();
        }
        if let Some(o) = self
            .oracles
            .iter()
            .find(|o| matches!(o.verdict, Verdict::Unavailable { .. }))
        {
            return o.verdict.clone();
        }
        if self.oracles.is_empty() {
            return Verdict::Fail {
                expected: "at least one oracle".to_owned(),
                observed: "a run with no oracle proves nothing".to_owned(),
            };
        }
        Verdict::Pass
    }

    /// Whether this record may be cited as release evidence under **C-5**.
    ///
    /// Requires a signature and a binary binding, and this domain produces
    /// neither — so it answers `false`, which is the honest answer rather than
    /// an absent check.
    #[must_use]
    pub fn is_release_evidence(&self) -> bool {
        self.signed && !self.binaries.is_empty()
    }

    /// The record as JSON, for the artifact store.
    ///
    /// # Errors
    ///
    /// Propagates a serialization failure.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// The scenario document's content hash.
///
/// SHA-256 through `twinvpn-crypto`, so `lab/` declares no hash implementation
/// of its own — CD-I2's habit applied outside `core/`, where it is not required
/// but is still the right shape.
#[must_use]
pub fn document_hash(document: &str) -> String {
    use core::fmt::Write as _;
    twinvpn_crypto::sha256(document.as_bytes()).iter().fold(
        String::with_capacity(64),
        |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Facility;

    fn record() -> RunRecord {
        RunRecord::new("S-NAT-EIM-EIM-V4-01", "id = \"x\"\n", "9f1c", Class::Bit)
    }

    #[test]
    fn a_conformance_failure_voids_the_run_before_any_oracle_is_read() {
        let mut r = record();
        r.oracles.push(OracleResult {
            oracle: "outcome_class".to_owned(),
            verdict: Verdict::Pass,
        });
        r.conformance.push(ConformanceResult {
            simulator: "N-EIM-EIF".to_owned(),
            assertion: "RFC 5780 prober reports EIF".to_owned(),
            passed: false,
        });
        assert!(
            matches!(r.verdict(), Verdict::Void { .. }),
            "B-15: a simulator conformance failure voids the results"
        );
    }

    #[test]
    fn a_run_with_no_oracle_is_a_failure_and_not_a_pass() {
        assert!(record().verdict().is_blocking());
    }

    #[test]
    fn an_unavailable_oracle_prevents_a_pass_without_blocking() {
        let mut r = record();
        r.oracles.push(OracleResult {
            oracle: "a".to_owned(),
            verdict: Verdict::Pass,
        });
        r.oracles.push(OracleResult {
            oracle: "b".to_owned(),
            verdict: Verdict::Unavailable {
                missing: Facility::Nftables,
                needed_for: "the personality",
            },
        });
        let v = r.verdict();
        assert!(!v.is_evidence_of_success());
        assert!(!v.is_blocking());
    }

    #[test]
    fn a_blocking_oracle_outranks_an_unavailable_one() {
        let mut r = record();
        r.oracles.push(OracleResult {
            oracle: "a".to_owned(),
            verdict: Verdict::Unavailable {
                missing: Facility::Nftables,
                needed_for: "x",
            },
        });
        r.oracles.push(OracleResult {
            oracle: "b".to_owned(),
            verdict: Verdict::Fail {
                expected: "x".to_owned(),
                observed: "y".to_owned(),
            },
        });
        assert!(r.verdict().is_blocking());
    }

    #[test]
    fn positive_control_all_oracles_passing_is_a_pass() {
        let mut r = record();
        r.oracles.push(OracleResult {
            oracle: "a".to_owned(),
            verdict: Verdict::Pass,
        });
        assert_eq!(r.verdict(), Verdict::Pass);
    }

    #[test]
    fn an_unsigned_record_is_never_release_evidence() {
        let mut r = record();
        r.binaries.push(("twinvpnd".into(), "deadbeef".into()));
        assert!(!r.is_release_evidence(), "C-5 needs a signature too");
        r.signed = true;
        assert!(r.is_release_evidence());
        r.binaries.clear();
        assert!(!r.is_release_evidence(), "C-5 needs a binary binding too");
    }

    #[test]
    fn the_document_hash_changes_with_the_document() {
        // A content hash that ignored its input would make every reproduction
        // claim vacuous, so the negative half is asserted alongside.
        let a = document_hash("id = \"a\"");
        let b = document_hash("id = \"b\"");
        assert_ne!(a, b);
        assert_eq!(a, document_hash("id = \"a\""));
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn the_record_serializes_and_carries_its_seed_and_class() {
        let json = record().to_json().expect("json");
        assert!(json.contains("\"seed\": \"9f1c\""), "{json}");
        assert!(json.contains("\"determinism\": \"Bit\""), "{json}");
    }
}
