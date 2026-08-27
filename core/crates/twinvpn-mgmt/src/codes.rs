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
pub const SUBSTITUTIONS: &[Substitution] = &[
    Substitution {
        specified: "MGMT.OP_UNKNOWN",
        emitted: Some(codes::PROTO_CAPABILITY_MISSING),
        cited_by: "ADR-0017 §11.7, §11.9 (possible on every operation)",
        cost: "degrades on PROTO rather than MGMT, so an older client reads 'this build does \
               not offer that operation' as a peer-protocol mismatch",
    },
    Substitution {
        specified: "MGMT.NOT_READY",
        emitted: Some(codes::MGMT_UNAVAILABLE),
        cited_by: "ADR-0017 §11.9 (possible on every operation)",
        cost: "conflates 'still starting' with 'unavailable'; the domain and the TRANSIENT \
               class survive, the distinction does not",
    },
    Substitution {
        specified: "MGMT.SHUTTING_DOWN",
        emitted: Some(codes::MGMT_UNAVAILABLE),
        cited_by: "ADR-0017 §11.9 (possible on every operation)",
        cost: "a client cannot tell 'retry in a moment' from 'this agent is going away', so a \
               reconnect loop is indistinguishable from a correct wait",
    },
    Substitution {
        specified: "MGMT.PAYLOAD_TOO_LARGE",
        emitted: Some(codes::PROTO_SIZE_EXCEEDED),
        cited_by: "ADR-0017 §11.9 (possible on every operation)",
        cost: "loses the MGMT domain; the bound and the class are exactly right",
    },
    Substitution {
        specified: "MGMT.RATE_LIMITED",
        emitted: Some(codes::POLICY_CAPACITY),
        cited_by: "ADR-0017 §11.9 (diag.*, session.connect, session.reconnect, path.probe)",
        cost: "degrades on POLICY, which reads as 'a rule forbids this' rather than 'you asked \
               too often'; the retry advice a user is given is therefore wrong",
    },
    Substitution {
        specified: "MGMT.CLIENT_TOO_SLOW",
        emitted: Some(codes::MGMT_UNAVAILABLE),
        cited_by: "ADR-0017 §11.10 (the eviction rung)",
        cost: "the evicted client cannot tell it was evicted for lag; MI-19's Tier-0 ledger \
               record still carries the principal and the queue depth, so the fact is not lost",
    },
    Substitution {
        specified: "MGMT.RESYNC_REQUIRED",
        emitted: Some(codes::MGMT_STREAM_COMPACTED),
        cited_by: "ADR-0017 MI-9a",
        cost: "THE WORST OF THE SIXTEEN. MI-9a exists specifically to keep these two apart: \
               compaction is mid-stream and the client's prior state is a valid base; \
               RESYNC_REQUIRED is attach-time and it is not. A client applying the compaction \
               recovery path to a cursor with no base is the exact failure MI-9a spends a \
               paragraph forbidding, and this substitution makes it indistinguishable",
    },
    Substitution {
        specified: "MGMT.PRECONDITION_FAILED",
        emitted: Some(codes::POLICY_POLICY_DENIED),
        cited_by: "ADR-0017 §11.9 (settings.set, pair.confirm)",
        cost: "reports an `if_version` mismatch as a policy denial. A stale write is the \
               caller's to retry after re-reading; a policy denial is not retryable at all, so \
               the substitution tells a correct client to give up",
    },
    Substitution {
        specified: "MGMT.MONOTONE_REFUSED",
        emitted: Some(codes::POLICY_POLICY_DENIED),
        cited_by: "ADR-0017 §11.9 (killswitch.mode.set, update.rollback), MI-K2a",
        cost: "the closest of the set: a monotone refusal really is a POLICY-class refusal, \
               and only the MGMT namespace is lost",
    },
    Substitution {
        specified: "MGMT.POLICY_FORBIDS",
        emitted: Some(codes::POLICY_POLICY_DENIED),
        cited_by: "ADR-0017 §11.9 (dns.preference.set, route.accept.set, exitnode.select)",
        cost: "arguably the more truthful code: the refusal is the signed policy's, not the \
               management interface's",
    },
    Substitution {
        specified: "MGMT.CHANNEL_UNSUPPORTED",
        emitted: Some(codes::MGMT_UNAVAILABLE),
        cited_by: "ADR-0017 §11.9 (killswitch.mode.set on Android, event.subscribe)",
        cost: "loses 'this channel cannot carry this operation, another can'. On Android that \
               is the difference between a refusal and a routing problem the client can fix",
    },
    Substitution {
        specified: "MGMT.DISARM_NO_LOCAL_AUTHORITY",
        emitted: Some(codes::MGMT_DISARM_REQUIRES_LOCAL_AUTH),
        cited_by: "ADR-0017 §11.9, §11.14",
        cost: "conflates 'authenticate to proceed' with 'no local authority exists to \
               authenticate against'. The second is unfixable by the user, and the \
               substitution invites them to try",
    },
    Substitution {
        specified: "MGMT.CAPTURE_EXPIRY_REQUIRED",
        emitted: Some(codes::POLICY_POLICY_DENIED),
        cited_by: "ADR-0017 §11.9 (diag.capture.set), ADR-0015 §11.5",
        cost: "loses the specific instruction that a capture-level raise MUST carry an \
               auto-expiry; the caller learns only that it was refused",
    },
    Substitution {
        specified: "PLATFORM.PRIV.CLIENT_UNAUTHORIZED",
        emitted: Some(codes::MGMT_PRINCIPAL_UNVERIFIABLE),
        cited_by: "ADR-0017 §11.9 (possible on every operation), ADR-0016",
        cost: "conflates 'we could not verify who you are' with 'we know who you are and you \
               may not do this'. The first is a channel fault; the second is an authorization \
               decision, and only the second should be audited as a denial",
    },
    // -- the two that are successes, not failures ---------------------------
    Substitution {
        specified: "MGMT.DIAG.BUNDLE_CREATED",
        emitted: None,
        cited_by: "ADR-0017 §11.9 (diag.bundle.create, INFO), §11.10 (the `mgmt` topic)",
        cost: "NO CODE IS EMITTED. Every registered MGMT code is a failure, and reporting a \
               successful bundle creation as one would be worse than losing the namespace. \
               It is carried as a typed event with no reason_code",
    },
    Substitution {
        specified: "MGMT.UNBLOCK_INVOKED",
        emitted: None,
        cited_by: "ADR-0017 §11.10 (the `mgmt` topic), §11.21.2",
        cost: "as above: an audit fact, not a failure. Carried as a typed event. ADR-0017 \
               §11.21.3 makes the audit record itself the obligation, and that is discharged",
    },
];

/// The registered code this build emits for a specified spelling.
///
/// `None` for a spelling that names a **success**; see [`SUBSTITUTIONS`].
#[must_use]
pub fn substituted(specified: &str) -> Option<ReasonCode> {
    SUBSTITUTIONS
        .iter()
        .find(|s| s.specified == specified)
        .and_then(|s| s.emitted)
}

/// `MGMT.OP_UNKNOWN`, substituted.
///
/// Returned when a client calls an operation absent from the catalogue. §11.7:
/// *"**Never** a parse error, never a hang, never a generic failure."* It is a
/// typed rejection naming the operation, which is what this discharges even
/// though the namespace is wrong.
#[must_use]
pub fn op_unknown() -> ReasonCode {
    codes::PROTO_CAPABILITY_MISSING
}

/// `MGMT.RESYNC_REQUIRED`, substituted. MI-9a — see the cost above.
#[must_use]
pub fn resync_required() -> ReasonCode {
    codes::MGMT_STREAM_COMPACTED
}

/// `MGMT.NOT_READY` / `MGMT.SHUTTING_DOWN`, substituted.
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
    #[test]
    fn every_substituted_spelling_is_still_absent_from_the_registry() {
        for s in SUBSTITUTIONS {
            assert!(
                ReasonCode::lookup(s.specified).is_none(),
                "`{}` is now REGISTERED. Delete its row from SUBSTITUTIONS, emit the real \
                 code, and update this crate's README. Cited by: {}",
                s.specified,
                s.cited_by
            );
        }
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
        for name in ["MGMT.DIAG.BUNDLE_CREATED", "MGMT.UNBLOCK_INVOKED"] {
            let row = SUBSTITUTIONS
                .iter()
                .find(|s| s.specified == name)
                .expect("recorded");
            assert!(row.emitted.is_none(), "{name} acquired a failure code");
            assert_eq!(substituted(name), None);
        }
    }

    #[test]
    fn the_count_matches_what_the_readme_and_the_report_state() {
        assert_eq!(SUBSTITUTIONS.len(), 16);
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
            assert!(ReasonCode::lookup(registered).is_some());
            assert!(
                SUBSTITUTIONS
                    .iter()
                    .any(|s| s.emitted.is_some_and(|c| c.as_str() == registered))
                    || registered == "MGMT.UNAVAILABLE",
                "{registered} is registered but this build never emits it"
            );
        }
    }
}
