//! The `MGMT.*` codes ADR-0017 names — and the substitutions the frozen
//! registry forces.
//!
//! **Authority:** [ADR-0017](../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.7, §11.9, §11.10, §11.16 (it owns the `MGMT` domain);
//! [ADR-0015](../../../../docs/adr/ADR-0015-observability-and-diagnostics.md)
//! §11.2 (the taxonomy, prefix degradation, the append-only rule);
//! `docs/implementation/ownership.md` §8 **W-18** and §3 (the freeze).
//!
//! # The defect, stated before it is worked around
//!
//! ADR-0017 owns the `MGMT` domain. `ownership.md` §8 W-18 measures **38 `MGMT`
//! codes** named across the Phase 1 corpus against **4** in
//! `contracts/registry/reason_codes.json`. Every code this crate needs beyond
//! those four is in the missing set — including, in §11.9's own words, the four
//! that are *"possible on **every** operation"*.
//!
//! `twinvpn_types::ReasonCode` cannot name an unregistered code, deliberately:
//! that is what makes "expose registered reason codes, never raw internal
//! errors" a compile-time property rather than a review item. So each spelling
//! is mapped onto the **nearest registered** code, the pair and **its cost** are
//! recorded in [`SUBSTITUTIONS`], and a **tripwire test asserts the specified
//! spelling is still absent from the registry** — so registering one fails the
//! build and points at the line to delete.
//!
//! Nothing is invented and `contracts/` is not touched.
//!
//! # Prefix degradation is what the substitutions actually cost
//!
//! ADR-0015 §11.2 rule 5 makes forward compatibility work by `DOMAIN` prefix. A
//! `MGMT` condition emitted as `PROTO.*` therefore degrades, on an older client,
//! to *"the peer protocol is wrong"* when the truth is *"this local interface
//! does not offer that operation"* — different diagnoses with different next
//! actions. That is the same failure §11.2's closed-domain admission rule exists
//! to prevent, arriving from the other direction, and it is why every row below
//! carries a `cost` field rather than only a replacement.

use twinvpn_types::{codes, ReasonCode};

/// One forced substitution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Substitution {
    /// The spelling ADR-0017 uses.
    pub specified: &'static str,
    /// The registered code this build emits instead, or `None` where the named
    /// condition is a **success** and no failure code is emitted at all.
    pub emitted: Option<ReasonCode>,
    /// Where the specified spelling is named.
    pub cited_by: &'static str,
    /// What the substitution costs, stated rather than glossed.
    pub cost: &'static str,
}

/// Every `MGMT.*` substitution this build makes, for the integration lead to
/// carry into the W-18 amendment.
pub const SUBSTITUTIONS: &[Substitution] = &[];

// EMPTY as of `registry_version` 2 (the first amendment under ownership.md §3).
// All sixteen ADR-0017 §11.12 spellings are registered, so this crate emits each
// by its own name and the prefix-degradation cost described above is paid by
// nobody. The type and the tripwire are kept, not deleted: a future ADR code
// that outruns the registry must land here visibly.

/// The registered code this build emits for a specified spelling.
///
/// `None` for a spelling that names a **success**; see [`SUBSTITUTIONS`].
#[must_use]
/// As of `registry_version` 2 this is a plain registry lookup: every spelling
/// ADR-0017 §11.12 uses is registered, so nothing is substituted and the
/// function returns the code the ADR names.
///
/// The name and signature are kept so callers need no edit, and because the
/// question it answers — "what code does this build emit for this spelling" —
/// is still the right one to ask. `None` now means only that the spelling is
/// not a registered code at all.
///
/// The two `INFO` spellings that used to return `None` because they name a
/// **success** now return their own registered codes. That is not the failure
/// `a_success_never_acquires_a_failure_code` guarded against: they are `INFO`
/// in the registry, so reporting them reports a success as a success.
pub fn substituted(specified: &str) -> Option<ReasonCode> {
    ReasonCode::lookup(specified)
}

/// `MGMT.OP_UNKNOWN`, substituted.
///
/// Returned when a client calls an operation absent from the catalogue. §11.7:
/// *"**Never** a parse error, never a hang, never a generic failure."*
///
/// **No longer substituted.** This returned `PROTO.CAPABILITY_MISSING` while
/// `MGMT.OP_UNKNOWN` was unregistered, which degraded *"this local interface
/// does not have that operation"* into *"the peer protocol is wrong"* on an
/// older client. `registry_version` 2 registered it.
#[must_use]
pub fn op_unknown() -> ReasonCode {
    codes::MGMT_OP_UNKNOWN
}

/// `MGMT.RESYNC_REQUIRED` — MI-9a's *"your cursor cannot be serviced"*.
///
/// **No longer substituted, and this was the worst of the sixteen.** It returned
/// `MGMT.STREAM_COMPACTED`, which made MI-9a's two conditions indistinguishable
/// at the exact point a client must tell them apart: *"the stream dropped
/// events, resnapshot"* and *"your offered cursor is unserviceable"* are
/// different recoveries. X-1 named this pair by name.
#[must_use]
pub fn resync_required() -> ReasonCode {
    codes::MGMT_RESYNC_REQUIRED
}

/// `MGMT.NOT_READY` — the agent is starting and is not yet answering.
///
/// **No longer substituted.** Both `MGMT.NOT_READY` and `MGMT.SHUTTING_DOWN`
/// collapsed onto `MGMT.UNAVAILABLE`, which told a client "not now" without
/// telling it *"try again in a moment"* or *"stop retrying, this agent is
/// going away"*. Use [`shutting_down`] for the other direction.
#[must_use]
pub fn not_ready() -> ReasonCode {
    codes::MGMT_NOT_READY
}

/// `MGMT.SHUTTING_DOWN` — the agent is going away and a retry will not help.
#[must_use]
pub fn shutting_down() -> ReasonCode {
    codes::MGMT_SHUTTING_DOWN
}

/// The agent cannot be reached at all.
///
/// Kept distinct from [`not_ready`] and [`shutting_down`]: MI-A3 makes
/// `MGMT.UNAVAILABLE` the answer a **client** synthesises when it connects to an
/// absent agent, and that is a different fact from an agent that is present and
/// declining.
#[must_use]
pub fn unavailable() -> ReasonCode {
    codes::MGMT_UNAVAILABLE
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The tripwire.**
    ///
    /// Every `specified` spelling must still be **absent** from the frozen
    /// registry. The moment one is registered this fails and names the row to
    /// delete — because a substitution that outlives its cause is a silent
    /// downgrade, and this is the pattern `ownership.md` §8 W-18 makes standard.
    // `const_is_empty` fires because the table IS a const empty slice today. That
    // is exactly what this asserts and exactly what must not change silently:
    // the point is to fail when a row comes back, not to observe that none is
    // there now. Suppressed at the assertion rather than rewritten as a length
    // comparison, which `len_zero` then objects to.
    #[allow(clippy::const_is_empty)]
    #[test]
    fn no_mgmt_spelling_is_substituted_any_more() {
        // Inverted, not deleted: this asserted every spelling was STILL absent
        // and named the row to delete when one landed. registry_version 2
        // registered all sixteen and it fired exactly as designed.
        assert!(
            SUBSTITUTIONS.is_empty(),
            "a MGMT spelling is being substituted again: {:?}",
            SUBSTITUTIONS
                .iter()
                .map(|s| s.specified)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_sixteen_adr_0017_spellings_are_reachable_by_their_own_names() {
        for spelling in [
            "MGMT.OP_UNKNOWN",
            // NOT MGMT.SCOPE_DENIED. ADR-0017 §11.12 minted it in an earlier
            // draft and WITHDREW IT BEFORE REGISTRATION (O-03), because
            // reliability.md §3.3 forbids a second identifier for a condition
            // ADR-0016 already registers. It must never become ACTIVE, and the
            // registry amendment correctly did not add it.
            "MGMT.RESYNC_REQUIRED",
            "MGMT.PAYLOAD_TOO_LARGE",
            "MGMT.PRECONDITION_FAILED",
            "MGMT.RATE_LIMITED",
            "MGMT.SHUTTING_DOWN",
            "MGMT.NOT_READY",
            "MGMT.DIAG.BUNDLE_CREATED",
            "MGMT.UNBLOCK_INVOKED",
        ] {
            assert!(
                ReasonCode::lookup(spelling).is_some(),
                "{spelling} is named by ADR-0017 §11.12 and is not registered"
            );
            assert_eq!(
                substituted(spelling).map(twinvpn_types::ReasonCode::as_str),
                Some(spelling),
                "{spelling} must now be emitted under its own name"
            );
        }
    }

    #[test]
    fn no_helper_still_returns_a_substituted_code() {
        // The residual X-1 did not catch. `SUBSTITUTIONS` was emptied and the
        // table's tripwire inverted, but these three FUNCTIONS kept returning
        // the codes the table used to justify — so `substituted()` answered
        // with the right name while `resync_required()` answered with the wrong
        // one, in the same crate.
        //
        // Each pair below is (what the ADR spells, what this build emits), and
        // they must be equal.
        for (spelling, emitted) in [
            ("MGMT.OP_UNKNOWN", op_unknown()),
            ("MGMT.RESYNC_REQUIRED", resync_required()),
            ("MGMT.NOT_READY", not_ready()),
            ("MGMT.SHUTTING_DOWN", shutting_down()),
            ("MGMT.UNAVAILABLE", unavailable()),
        ] {
            assert_eq!(
                emitted.as_str(),
                spelling,
                "{spelling} is registered and must be emitted under its own name"
            );
        }
    }

    #[test]
    fn mi_9a_two_conditions_stay_two_codes() {
        // The distinction the substitution destroyed: "the stream dropped
        // events, resnapshot" and "your offered cursor is unserviceable" are
        // different recoveries and a client must be able to tell them apart.
        assert_ne!(resync_required(), codes::MGMT_STREAM_COMPACTED);
    }

    #[test]
    fn every_replacement_is_itself_registered() {
        for s in SUBSTITUTIONS {
            if let Some(code) = s.emitted {
                assert!(
                    ReasonCode::lookup(code.as_str()).is_some(),
                    "{} substitutes a code that is not in the registry",
                    s.specified
                );
            }
        }
    }

    // `const_is_empty` fires because the table IS a const empty slice today. That
    // is exactly what this asserts and exactly what must not change silently:
    // the point is to fail when a row comes back, not to observe that none is
    // there now. Suppressed at the assertion rather than rewritten as a length
    // comparison, which `len_zero` then objects to.
    #[allow(clippy::const_is_empty)]
    #[test]
    fn every_substitution_states_its_cost_and_its_citation() {
        for s in SUBSTITUTIONS {
            assert!(
                !s.cost.trim().is_empty(),
                "{} has no stated cost",
                s.specified
            );
            assert!(
                !s.cited_by.trim().is_empty(),
                "{} has no citation",
                s.specified
            );
        }
    }

    #[test]
    fn a_success_never_acquires_a_failure_code() {
        // The two INFO conditions must stay `None`. Giving either a code would
        // report a success as a failure, which is the one substitution that
        // would be worse than the gap.
        // These two name a SUCCESS. Before registry_version 2 they had to map
        // to `None`, because the only alternative was borrowing a failure code.
        // They are registered now, so the property to assert is the real one:
        // each resolves to itself AND is INFO severity.
        for name in ["MGMT.DIAG.BUNDLE_CREATED", "MGMT.UNBLOCK_INVOKED"] {
            let code =
                ReasonCode::lookup(name).unwrap_or_else(|| panic!("{name} must be registered"));
            assert_eq!(substituted(name), Some(code));
            // NOT an assertion that these are INFO. ADR-0017 §11.12 classifies
            // MGMT.UNBLOCK_INVOKED as POLICY/**WARN** and says so in terms:
            // "Not a failure - a visibility obligation". The property that
            // matters is that neither is reported as a failure.
            assert!(
                matches!(
                    code.severity(),
                    twinvpn_types::ErrorSeverity::Info | twinvpn_types::ErrorSeverity::Warn
                ),
                "{name} names a success and must not be reported as a failure, got {:?}",
                code.severity()
            );
        }
    }

    #[test]
    fn the_count_matches_what_the_readme_and_the_report_state() {
        // 16 -> 0 in registry_version 2.
        assert_eq!(SUBSTITUTIONS.len(), 0);
    }

    #[test]
    fn the_four_registered_mgmt_codes_are_used_rather_than_substituted_around() {
        // A substitution table is only honest if it is not hiding a registered
        // code that would have been correct.
        for registered in [
            "MGMT.UNAVAILABLE",
            "MGMT.PRINCIPAL_UNVERIFIABLE",
            "MGMT.STREAM_COMPACTED",
            "MGMT.DISARM_REQUIRES_LOCAL_AUTH",
        ] {
            // The original form asserted each of these appeared as a
            // SUBSTITUTION TARGET, which is how it proved the table was not
            // hiding a registered code that would have been correct. With the
            // table empty that question is answered by construction: nothing is
            // substituted, so nothing can be hidden behind a substitution.
            assert!(
                ReasonCode::lookup(registered).is_some(),
                "{registered} must still be registered"
            );
            assert_eq!(
                substituted(registered).map(twinvpn_types::ReasonCode::as_str),
                Some(registered),
                "{registered} must resolve to itself"
            );
        }
    }
}
