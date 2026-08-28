//! The **read-back**: what `pfctl` says is loaded, parsed.
//!
//! **Authority:** ADR-0015 §11.6 rule 1 (the `ProtectionAssertion` is produced by
//! *querying the enforcement layer*, "never of the agent's belief"), ADR-0012 K12
//! ("enforcement state MUST be observable by querying installed rules, not by
//! trusting the agent's belief") and §11.9 (the leak canary reads the deny
//! counters), `docs/implementation/ownership.md` §8 **W-24**.
//!
//! # Why this module exists at all
//!
//! `twinvpn.h`'s F-9 vtable offers `set_ruleset` with **no getter**, so a shell
//! bound only to the C ABI cannot produce a `ProtectionAssertion` — W-24. This
//! adapter is bound as a Rust crate, so it does not have that limit:
//! [`twinvpn_platform::NetworkConfig::installed_ruleset`] runs `pfctl` and reads
//! the posture out of **pf's own answer**. Nothing here is cached and nothing has
//! a default: the reconciler's job is to notice that something else changed the
//! rules, and a cache cannot.
//!
//! # Three questions, three reads
//!
//! | Question | Command | Parser |
//! |---|---|---|
//! | is pf even on? | `pfctl -s info` | [`parse_status`] |
//! | which posture, which generation, over how much scope? | `pfctl -a twinvpn -s Tables` | [`parse_tables`] |
//! | did the canary's packet get dropped? | `pfctl -a twinvpn -s labels` | [`parse_labels`] |
//!
//! The first is not optional. **An anchor loaded while pf is disabled is not
//! protection**, and a read-back that reported the posture without reporting that
//! pf was off would be exactly the confident-but-false assertion ADR-0015 §11.6
//! forbids. [`Assertion`] therefore carries both and cannot be constructed with
//! only one.
//!
//! # Pure, and therefore tested
//!
//! Every function here takes `&str` and returns a value. `pfctl` does not exist on
//! this Linux host and is not needed: the parsers run under `cargo test` against
//! captured output shapes, exactly as the Linux adapter tests its `nft --json`
//! parser.

use std::collections::BTreeMap;

use twinvpn_platform::{ContractGeneration, Ruleset};
use twinvpn_types::PerFamily;

use crate::pf::{GENERATION_PREFIX, POSTURE_BLOCKED, POSTURE_PROTECTED, SCOPE_COUNT_PREFIX};

/// Whether the packet filter itself is enabled.
///
/// Three states rather than two: an output that could not be parsed is **not**
/// "disabled" and **not** "enabled". O-18's fail-safe direction renders the
/// indicator `UNKNOWN`, and collapsing this into a `bool` is how "we could not
/// tell" becomes "it is fine".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PfStatus {
    /// `Status: Enabled`.
    Enabled,
    /// `Status: Disabled`.
    Disabled,
    /// `pfctl -s info` produced something this parser does not recognise.
    Unknown,
}

/// What a read-back of the installed anchor reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Installed {
    /// The posture pf is holding.
    pub ruleset: Ruleset,
    /// The generation pf is holding.
    pub generation: Option<ContractGeneration>,
    /// How many prefixes the Tier-2 drop covers, per family.
    ///
    /// A posture table records what was *intended*; this records what the rules
    /// actually cover. `PerFamily::new(0, 0)` alongside [`Ruleset::Blocked`] is an
    /// anchor that claims to be fail-closed and drops nothing — a **value** a
    /// caller can see rather than an invisible one.
    pub scope: PerFamily<usize>,
}

impl Installed {
    /// Whether the installed rules actually cover anything, in **both** families.
    ///
    /// KS-5: "an implementation that can install the Tier-2 rule set for one
    /// family without the other is **non-conforming**, not degraded." So this is
    /// an `&&`, not an `||`.
    #[must_use]
    pub const fn covers_a_scope(&self) -> bool {
        self.scope.v4 > 0 && self.scope.v6 > 0
    }
}

/// The whole protection assertion, as pf answered it.
///
/// Constructed only from a status **and** an anchor read, so there is no way to
/// report a posture without reporting whether the filter that holds it is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assertion {
    /// Whether pf is enabled.
    pub status: PfStatus,
    /// What our anchor holds, or `None` when the anchor carries neither posture
    /// table — an anchor somebody else built under our name, or one this build
    /// does not recognise. Deliberately **not** "unprotected": the caller turns it
    /// into a refusal.
    pub installed: Option<Installed>,
}

impl Assertion {
    /// Whether this assertion supports claiming protection for `expected`.
    ///
    /// Every clause is a separate reason to refuse, and each is a condition a
    /// support case can name:
    ///
    /// - pf is not `Enabled` — the anchor is loaded into a filter that is off;
    /// - the anchor holds no posture table — it is not ours;
    /// - the posture is not the one the core asked for — something else changed
    ///   the rules, which is exactly what the reconciler exists to notice;
    /// - the scope is empty in either family — KS-5.
    #[must_use]
    pub fn supports(&self, expected: Ruleset) -> bool {
        matches!(self.status, PfStatus::Enabled)
            && self
                .installed
                .is_some_and(|i| i.ruleset == expected && i.covers_a_scope())
    }
}

/// Parses `pfctl -s info`'s first line.
///
/// The real output begins `Status: Enabled for 0 days 00:04:11   Debug: Urgent`
/// or `Status: Disabled`. Only the word after `Status:` is read; everything else
/// on the line is uptime and debug level, which are not this question's answer.
#[must_use]
pub fn parse_status(text: &str) -> PfStatus {
    for line in text.lines() {
        let Some(rest) = line.trim_start().strip_prefix("Status:") else {
            continue;
        };
        return match rest.split_whitespace().next() {
            Some("Enabled") => PfStatus::Enabled,
            Some("Disabled") => PfStatus::Disabled,
            _ => PfStatus::Unknown,
        };
    }
    PfStatus::Unknown
}

/// Reads the posture, the generation and the scope cardinality out of
/// `pfctl -a twinvpn -s Tables`.
///
/// Accepts both the plain form (one name per line) and the `-v` form
/// (`--a-r-- tv_scope4`), because a diagnostic capture is as likely to be one as
/// the other and a parser that only understood one would fail on a support
/// bundle. The name is the **last** whitespace-separated token: a pf table name
/// cannot contain whitespace.
///
/// Returns `None` when the anchor carries **neither** posture table.
#[must_use]
pub fn parse_tables(text: &str) -> Option<Installed> {
    let mut ruleset = None;
    let mut generation = None;
    let mut scope = PerFamily::new(0usize, 0usize);
    for line in text.lines() {
        let Some(name) = line.split_whitespace().next_back() else {
            continue;
        };
        match name {
            POSTURE_BLOCKED => ruleset = Some(Ruleset::Blocked),
            POSTURE_PROTECTED => {
                // Both posture tables present at once is a ruleset nobody
                // rendered — KS-17 says there are exactly two postures and a swap
                // between them, so this can only be a partially applied load or a
                // third party's anchor. `Protected` must never win by accident, so
                // the ambiguity resolves to the closed direction.
                ruleset = Some(match ruleset {
                    Some(Ruleset::Blocked) => Ruleset::Blocked,
                    _ => Ruleset::Protected,
                });
            }
            other => {
                if let Some(digits) = other.strip_prefix(GENERATION_PREFIX) {
                    if let Ok(n) = digits.parse::<u64>() {
                        generation = Some(ContractGeneration(n));
                    }
                }
                for (prefix, family) in SCOPE_COUNT_PREFIX {
                    if let Some(digits) = other.strip_prefix(prefix) {
                        if let Ok(n) = digits.parse::<usize>() {
                            *scope.get_mut(family) = n;
                        }
                    }
                }
            }
        }
    }
    ruleset.map(|ruleset| Installed {
        ruleset,
        generation,
        scope,
    })
}

/// One label's counters, as pf reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LabelCounters {
    /// How many times the rule was evaluated.
    pub evaluations: u64,
    /// How many packets matched.
    pub packets: u64,
    /// How many bytes matched.
    pub bytes: u64,
}

/// Parses `pfctl -a twinvpn -s labels`.
///
/// The output is one line per labelled rule: the label, then a run of decimal
/// counters. macOS's `pfctl` prints `evaluations packets bytes` first and then a
/// varying number of further columns depending on the release, so the parser reads
/// **the first three numbers and ignores the rest** rather than pinning a column
/// count a point release could change. A line with fewer than three numbers is
/// skipped; a label seen twice sums, because pf emits one line per rule and two
/// rules may legitimately share a label (the two DNS containment rules do).
#[must_use]
pub fn parse_labels(text: &str) -> BTreeMap<String, LabelCounters> {
    let mut out: BTreeMap<String, LabelCounters> = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(label) = fields.next() else {
            continue;
        };
        let numbers: Vec<u64> = fields.filter_map(|f| f.parse::<u64>().ok()).collect();
        if numbers.len() < 3 {
            continue;
        }
        let entry = out.entry(label.to_owned()).or_default();
        entry.evaluations = entry.evaluations.saturating_add(numbers[0]);
        entry.packets = entry.packets.saturating_add(numbers[1]);
        entry.bytes = entry.bytes.saturating_add(numbers[2]);
    }
    out
}

/// The packet count on one label, or zero when the label is absent.
///
/// **Zero for an absent label is the right answer here and only here.** The leak
/// canary asks "did my packet get dropped", and a label that is not installed
/// cannot have dropped it — so an absent label and a label at zero are the same
/// negative answer, and both are `POLICY.LEAK.EGRESS_OBSERVED` when the canary
/// expected an increment.
#[must_use]
pub fn packets_on(labels: &BTreeMap<String, LabelCounters>, label: &str) -> u64 {
    labels.get(label).map_or(0, |c| c.packets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pf::{DENY_LABEL, DNS_DENY_LABEL, EXEMPT_LABEL};
    use twinvpn_types::AddressFamily;

    #[test]
    fn pf_being_off_is_a_distinct_answer_from_pf_being_on() {
        assert_eq!(
            parse_status("Status: Enabled for 0 days 00:04:11   Debug: Urgent\n"),
            PfStatus::Enabled
        );
        assert_eq!(parse_status("Status: Disabled\n"), PfStatus::Disabled);
    }

    #[test]
    fn output_we_do_not_recognise_is_unknown_and_never_enabled() {
        // O-18's fail-safe direction. "We could not tell" must not read as "it is
        // fine", which is what a `bool` would have made it.
        for text in ["", "pfctl: Operation not permitted.\n", "Status: Wat\n"] {
            assert_eq!(parse_status(text), PfStatus::Unknown, "{text:?}");
        }
    }

    #[test]
    fn the_posture_and_the_generation_come_from_pf_and_not_from_memory() {
        let text = "tv_scope4\ntv_scope6\ntv_posture_protected\ntv_gen_42\n\
                    tv_scope4_n3\ntv_scope6_n2\n";
        let installed = parse_tables(text).expect("our anchor");
        assert_eq!(installed.ruleset, Ruleset::Protected);
        assert_eq!(installed.generation, Some(ContractGeneration(42)));
        assert_eq!(installed.scope.v4, 3);
        assert_eq!(installed.scope.v6, 2);
        assert!(installed.covers_a_scope());
    }

    #[test]
    fn the_verbose_form_parses_too_because_a_support_bundle_may_carry_either() {
        let text = "--a-r-- tv_posture_blocked\n--a-r-- tv_gen_7\n\
                    --a-r-- tv_scope4_n1\n--a-r-- tv_scope6_n1\n";
        let installed = parse_tables(text).expect("our anchor");
        assert_eq!(installed.ruleset, Ruleset::Blocked);
        assert_eq!(installed.generation, Some(ContractGeneration(7)));
    }

    #[test]
    fn an_anchor_that_is_not_ours_is_none_and_never_unprotected() {
        // Deliberately not "no ruleset installed": the caller turns `None` into a
        // refusal, and O-18 renders the indicator UNKNOWN.
        assert_eq!(parse_tables(""), None);
        assert_eq!(parse_tables("somebody_elses_table\nanother\n"), None);
    }

    #[test]
    fn both_posture_tables_at_once_resolves_closed() {
        for text in [
            "tv_posture_blocked\ntv_posture_protected\n",
            "tv_posture_protected\ntv_posture_blocked\n",
        ] {
            let installed = parse_tables(text).expect("our anchor");
            assert_eq!(
                installed.ruleset,
                Ruleset::Blocked,
                "ambiguity must resolve to the closed direction"
            );
        }
    }

    #[test]
    fn blocked_over_nothing_is_a_value_a_caller_can_see() {
        // The R-6 shape: a posture table with an empty scope reads back as
        // `Blocked` and would satisfy a naive reconciler. `covers_a_scope` is what
        // makes it visible.
        let installed =
            parse_tables("tv_posture_blocked\ntv_scope4_n0\ntv_scope6_n0\n").expect("our anchor");
        assert_eq!(installed.ruleset, Ruleset::Blocked);
        assert!(!installed.covers_a_scope());
    }

    #[test]
    fn ks5_one_family_covered_and_the_other_not_is_not_covered() {
        let one_sided =
            parse_tables("tv_posture_protected\ntv_scope4_n4\ntv_scope6_n0\n").expect("ours");
        assert!(
            !one_sided.covers_a_scope(),
            "a v4 drop with no v6 counterpart is KS-5 non-conformance, not a \
             degraded mode"
        );
    }

    #[test]
    fn an_assertion_needs_pf_to_be_on_as_well_as_the_anchor_to_be_right() {
        let installed = parse_tables("tv_posture_protected\ntv_scope4_n2\ntv_scope6_n2\n");
        assert!(Assertion {
            status: PfStatus::Enabled,
            installed,
        }
        .supports(Ruleset::Protected));

        // The whole reason `PfStatus` is carried: an anchor loaded into a filter
        // that is off is not protection.
        assert!(!Assertion {
            status: PfStatus::Disabled,
            installed,
        }
        .supports(Ruleset::Protected));
        assert!(!Assertion {
            status: PfStatus::Unknown,
            installed,
        }
        .supports(Ruleset::Protected));
        // And the posture must be the one that was asked for.
        assert!(!Assertion {
            status: PfStatus::Enabled,
            installed,
        }
        .supports(Ruleset::Blocked));
        assert!(!Assertion {
            status: PfStatus::Enabled,
            installed: None,
        }
        .supports(Ruleset::Protected));
    }

    #[test]
    fn the_canary_reads_a_per_family_counter_out_of_pfs_own_answer() {
        let text = "twinvpn.deny.v4 12 3 240 0 0 3 240 0\n\
                    twinvpn.deny.v6 9 0 0 0 0 0 0 0\n\
                    twinvpn.exempt.v4 400 400 51200\n\
                    twinvpn.exempt.v6 12 12 900\n";
        let labels = parse_labels(text);
        assert_eq!(packets_on(&labels, DENY_LABEL[0].0), 3);
        assert_eq!(
            packets_on(&labels, DENY_LABEL[1].0),
            0,
            "a v6 canary that did not increment is POLICY.LEAK.EGRESS_OBSERVED"
        );
        assert_eq!(labels[DENY_LABEL[0].0].bytes, 240);
        // KS-11's per-family exempt accounting.
        assert_eq!(packets_on(&labels, EXEMPT_LABEL[0].0), 400);
        assert_eq!(packets_on(&labels, EXEMPT_LABEL[1].0), 12);
        assert_eq!(DENY_LABEL[1].1, AddressFamily::V6);
    }

    #[test]
    fn two_rules_sharing_one_label_sum_rather_than_the_last_one_winning() {
        // The two DNS containment rules (ports 53/853, and the DoH table) both
        // carry `twinvpn.deny.dns`. A parser that overwrote would report only the
        // second rule's drops, understating the containment counter.
        let text = format!("{DNS_DENY_LABEL} 5 2 100\n{DNS_DENY_LABEL} 3 1 60\n");
        let labels = parse_labels(&text);
        assert_eq!(packets_on(&labels, DNS_DENY_LABEL), 3);
        assert_eq!(labels[DNS_DENY_LABEL].bytes, 160);
    }

    #[test]
    fn a_malformed_label_line_is_skipped_rather_than_poisoning_the_map() {
        let labels = parse_labels("\nnot-a-rule\ntwinvpn.deny.v4 1 1\ngood 1 2 3\n");
        assert!(!labels.contains_key("not-a-rule"));
        assert!(
            !labels.contains_key("twinvpn.deny.v4"),
            "fewer than three counters is not a labelled rule line"
        );
        assert_eq!(packets_on(&labels, "good"), 2);
        assert_eq!(packets_on(&labels, "absent"), 0);
    }
}
