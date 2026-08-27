//! Every boolean the §4.5 `Guard` column reads, in one place.
//!
//! **Authority:** `docs/reliability.md` §4.5 (the `Guard` column), §5.3's two
//! adopted-guard tables, §7.7 (guard inputs consumed from other ADRs).
//!
//! # These are inputs, not decisions
//!
//! §5.3: "None introduces a state or a transition; each is computed by its
//! owning ADR and read here." So this struct is a plain record with no logic of
//! its own — the state machine reads it and the owning subsystem writes it. That
//! separation is what lets `twinvpn-session` be exercised against a mock
//! adapter with no network at all (CB-2/CD-5): a scenario sets guards.

use crate::state::EnforcementMode;

/// The guard inputs, evaluated at the moment a trigger is applied.
///
/// Every field is `false` by default, and every default is the **restrictive**
/// answer: no candidates, no alternate, no budget, no authority. A guard nobody
/// set can therefore never widen what the machine does — the same grant/deny
/// asymmetry §9.2 applies to authority, applied to the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(clippy::struct_excessive_bools)]
// Twenty-six independent booleans, each named by a normative table row. A
// bitflags type would let two unrelated guards be set by one mask, which is
// exactly the class of mistake the named-guard tables exist to prevent.
pub struct Guards {
    // -- establishment ------------------------------------------------------
    /// T01: this device's credentials are inside their validity window.
    pub credentials_valid: bool,
    /// T02: they are not. Distinct from `!credentials_valid` because "not yet
    /// checked" must not read as "expired".
    pub credentials_expired: bool,
    /// T01: the peer is an authorized `TrustedPeer` at the current epoch.
    pub peer_authorized: bool,
    /// T03: at least one usable candidate exists.
    pub usable_candidate: bool,
    /// T04: gathering produced nothing **on either family**.
    pub no_candidate_either_family: bool,

    // -- validation and racing ---------------------------------------------
    /// T08–T10, T25: the winning path passed authenticated path validation.
    pub path_validated: bool,
    /// T09: no L2 path won the race.
    pub no_l2_path_won: bool,
    /// T10: no direct path has won yet.
    pub no_direct_path_won: bool,
    /// T14: the peer is confirmed on the same L2 segment.
    pub same_l2_confirmed: bool,

    // -- migration ----------------------------------------------------------
    /// T15: the new path is committed.
    pub new_path_committed: bool,
    /// T16 vs T17: whether the outgoing path is still alive.
    pub old_path_alive: bool,
    /// T19 vs T20: a **validated or warm** alternate exists.
    pub alternate_available: bool,
    /// T21: the local address changed (as opposed to the interface).
    pub local_address_changed: bool,

    // -- quality ------------------------------------------------------------
    /// T22: the violation has been sustained for `T_QOS_CONFIRM`.
    pub qos_violation_sustained: bool,
    /// T23: restoration has been sustained for `T_QOS_CLEAR`.
    pub qos_restored_sustained: bool,

    // -- recovery -----------------------------------------------------------
    /// T07, T12, T31: the retry budget for the relevant target class has a token.
    pub retry_budget_available: bool,
    /// T33: the terminal code's `retry_precondition` is satisfied.
    pub retry_precondition_met: bool,

    // -- enforcement --------------------------------------------------------
    /// T26/T27: the enforcement mode in force.
    pub enforcement: Option<EnforcementMode>,
    /// T30: an authorized secure path is established.
    pub secure_path_established: bool,
    /// T30: enforcement reconciliation passes, for **v4 and v6**.
    pub enforcement_reconciled: bool,
    /// T32: the ADR-0012 authenticated user action has been performed.
    ///
    /// Defaulting to `false` is the whole point: leaving fail-closed is "a
    /// deliberate, authenticated, logged act — never an automatic one".
    pub authenticated_disarm: bool,

    // -- lifecycle ----------------------------------------------------------
    /// T34/T36: some peer has declared an inbound reachability requirement.
    pub inbound_required: bool,
    /// T35: a path plausibly survived the suspend.
    pub path_plausibly_survived: bool,
    /// T35: the elapsed-clock delta across the suspend exceeded the rekey
    /// window, so a full handshake is forced (§11.3).
    pub rekey_window_exceeded: bool,

    // -- ADR-0006 relay guards, §5.3 ---------------------------------------
    /// `RELAY_SET_NONEMPTY` — at least one relay candidate is admissible for
    /// this family and carriage.
    pub relay_set_nonempty: bool,
    /// `RELAY_STANDBY_SELECTED` — a warm standby has been chosen.
    pub relay_standby_selected: bool,
    /// `RELAY_FAILOVER_TARGET_READY` — "the guard that separates T19 from T20 on
    /// relay death".
    pub relay_failover_target_ready: bool,
    /// `RELAY_REGION_FAILED`.
    pub relay_region_failed: bool,
    /// `RELAY_FLEET_EXHAUSTED` — read by T20 and T26. `DEGRADED` is **not**
    /// available here.
    pub relay_fleet_exhausted: bool,
    /// `DIRECT_UPGRADE_ELIGIBLE` — validated, better, and stable while relayed.
    pub direct_upgrade_eligible: bool,
    /// `UPGRADE_FLAP_SUPPRESSED`.
    pub upgrade_flap_suppressed: bool,

    // -- ADR-0009 guards, §7.7 ---------------------------------------------
    /// `policy_grant_expired` — read by T29.
    pub policy_grant_expired: bool,
    /// `trust_state_expired` — read by T29, but **MUST NOT by itself** drive
    /// `BLOCKED` or `FAILED` (R-11). See [`Guards::trust_expiry_blocks`].
    pub trust_state_expired: bool,
    /// `trust_epoch_behind` — diagnostic only. Never a gate.
    pub trust_epoch_behind: bool,
    /// `cursor_unavailable` — diagnostic only. Never a gate.
    pub cursor_unavailable: bool,
}

impl Guards {
    /// Whether fail-closed is in force. `None` reads as fail-closed.
    ///
    /// An unset enforcement mode is the safest reading, not an error: I3 says
    /// there is no configuration in which protected traffic silently leaves the
    /// device untunneled, and "we have not been told" is not a licence.
    #[must_use]
    pub fn fail_closed(self) -> bool {
        self.enforcement
            .is_none_or(EnforcementMode::is_fail_closed)
    }

    /// Whether `trust_state_expired` may contribute to a `BLOCKED` decision.
    ///
    /// **Never on its own** (§7.7, R-11): "Baseline reachability to a known
    /// `TrustedPeer` is untouched, so this MUST NOT by itself drive `BLOCKED` or
    /// `FAILED`." It can only compound a grant withdrawal that would leave
    /// protected traffic unprotected.
    #[must_use]
    pub const fn trust_expiry_blocks(self) -> bool {
        self.trust_state_expired && self.policy_grant_expired
    }

    /// T13's composite: an upgrade is admissible only when it is eligible **and**
    /// not flap-suppressed.
    #[must_use]
    pub const fn upgrade_admissible(self) -> bool {
        self.direct_upgrade_eligible && !self.upgrade_flap_suppressed
    }

    /// Every guard as `(name, value)`, so a diagnostic can state *why* a row did
    /// not fire rather than leaving the caller to infer it.
    #[must_use]
    pub fn as_pairs(self) -> [(&'static str, bool); 30] {
        [
            ("credentials_valid", self.credentials_valid),
            ("credentials_expired", self.credentials_expired),
            ("peer_authorized", self.peer_authorized),
            ("usable_candidate", self.usable_candidate),
            ("no_candidate_either_family", self.no_candidate_either_family),
            ("path_validated", self.path_validated),
            ("no_l2_path_won", self.no_l2_path_won),
            ("no_direct_path_won", self.no_direct_path_won),
            ("same_l2_confirmed", self.same_l2_confirmed),
            ("new_path_committed", self.new_path_committed),
            ("old_path_alive", self.old_path_alive),
            ("alternate_available", self.alternate_available),
            ("local_address_changed", self.local_address_changed),
            ("qos_violation_sustained", self.qos_violation_sustained),
            ("qos_restored_sustained", self.qos_restored_sustained),
            ("retry_budget_available", self.retry_budget_available),
            ("retry_precondition_met", self.retry_precondition_met),
            ("secure_path_established", self.secure_path_established),
            ("enforcement_reconciled", self.enforcement_reconciled),
            ("authenticated_disarm", self.authenticated_disarm),
            ("inbound_required", self.inbound_required),
            ("path_plausibly_survived", self.path_plausibly_survived),
            ("rekey_window_exceeded", self.rekey_window_exceeded),
            ("relay_set_nonempty", self.relay_set_nonempty),
            ("relay_standby_selected", self.relay_standby_selected),
            (
                "relay_failover_target_ready",
                self.relay_failover_target_ready,
            ),
            ("relay_region_failed", self.relay_region_failed),
            ("relay_fleet_exhausted", self.relay_fleet_exhausted),
            ("direct_upgrade_eligible", self.direct_upgrade_eligible),
            ("upgrade_flap_suppressed", self.upgrade_flap_suppressed),
        ]
    }
}
