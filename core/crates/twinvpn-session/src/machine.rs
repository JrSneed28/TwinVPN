//! The machine. **The only way to change a `Session`'s state.**
//!
//! **Authority:** `docs/reliability.md` §4.5 (normative), §10.1 (the boundary
//! rule), §10.2 (E1–E7), §11.1 (timer profiles); ADR-0018 CD-1/CD-2.
//!
//! # E1, made structural
//!
//! > Emission is a property of the **transition**, not of a call site. One
//! > transition, one event — never zero, never two.
//!
//! [`SessionMachine::state`] is private and there is no setter. [`SessionMachine::apply`]
//! is the only function in the crate that writes it, and it returns the
//! [`TransitionRecord`] it produced. A caller cannot move the machine without
//! receiving the record, and cannot receive a record without having moved it.
//!
//! # CD-1: every timer takes the monotonic clock
//!
//! The machine holds an [`Env`] and stamps `occurred_at` from
//! [`Env::now_monotonic`]. It never reads the wall clock and never reads the
//! elapsed clock — §5.3.1 puts the elapsed clock on *authority deadlines*, which
//! `twinvpn-trust` owns, and on §11.3's suspend-gap measurement, which arrives
//! here as the pre-computed `rekey_window_exceeded` guard.

use twinvpn_env::Env;
use twinvpn_types::{
    codes, Component, Diagnostic, EvidenceValue, PathId, ReasonCode, SessionId,
};

use crate::event::Trigger;
use crate::guards::Guards;
use crate::state::SessionState;
use crate::table::{self, Context};
use crate::timers::TimerProfile;
use crate::transition::{Row, TransitionRecord};

/// What [`SessionMachine::apply`] did.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// A row fired. Exactly one [`TransitionRecord`] was produced.
    Transitioned(Box<TransitionRecord>),
    /// No row matched. **Not** a silent drop: the trigger and the state that
    /// ignored it are both named, so §10's "no silent failure" still holds for a
    /// trigger that legitimately means nothing here.
    Ignored {
        /// The state that ignored it.
        state: SessionState,
        /// What was ignored.
        trigger: Trigger,
    },
}

impl Outcome {
    /// The record, when one was produced.
    #[must_use]
    pub fn record(&self) -> Option<&TransitionRecord> {
        match self {
            Outcome::Transitioned(r) => Some(r),
            Outcome::Ignored { .. } => None,
        }
    }
}

/// One `Session`'s state machine.
pub struct SessionMachine {
    env: Env,
    session_id: SessionId,
    state: SessionState,
    /// The code the current state was **entered** with. `Some` exactly when
    /// `state.requires_reason_code()`, which is an invariant `apply` maintains
    /// and `state_and_reason_agree` asserts.
    reason: Option<ReasonCode>,
    path_id: Option<PathId>,
    profile: TimerProfile,
    /// Every record produced, in order. This is `docs/testing-strategy.md`
    /// §2.2's oracle and ADR-0015 O-05's stream.
    history: Vec<TransitionRecord>,
    /// §10.2 E7's defect counter. Never reset.
    invariant_violations: u32,
}

impl SessionMachine {
    /// A machine resting in `DISCONNECTED`.
    #[must_use]
    pub fn new(env: Env, session_id: SessionId) -> Self {
        Self {
            env,
            session_id,
            state: SessionState::Disconnected,
            reason: None,
            path_id: None,
            profile: TimerProfile::Foreground,
            history: Vec::new(),
            invariant_violations: 0,
        }
    }

    /// A machine restored from the durable journal (§6.5, S-12).
    ///
    /// A restarted client "resumes into `RECONNECTING` for each known peer
    /// rather than starting from `DISCONNECTED`". The restored state therefore
    /// arrives already carrying its code, which is why this constructor takes
    /// one and refuses to invent it.
    #[must_use]
    pub fn resumed(
        env: Env,
        session_id: SessionId,
        state: SessionState,
        reason: Option<ReasonCode>,
    ) -> Self {
        let reason = if state.requires_reason_code() {
            Some(reason.unwrap_or_else(|| default_resume_reason(state)))
        } else {
            None
        };
        Self {
            env,
            session_id,
            state,
            reason,
            path_id: None,
            profile: TimerProfile::Foreground,
            history: Vec::new(),
            invariant_violations: 0,
        }
    }

    /// The current state. Read-only by construction.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// The code the current state was entered with.
    #[must_use]
    pub const fn reason(&self) -> Option<ReasonCode> {
        self.reason
    }

    /// The `Session` identity. Durable, never reassigned.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// The timer profile in force (§11.1).
    #[must_use]
    pub const fn profile(&self) -> TimerProfile {
        self.profile
    }

    /// Binds the `Path` a transition event will name. `None` in the three states
    /// that have no `Path`.
    pub fn set_path(&mut self, path_id: Option<PathId>) {
        self.path_id = path_id;
    }

    /// Every record produced, oldest first.
    #[must_use]
    pub fn history(&self) -> &[TransitionRecord] {
        &self.history
    }

    /// How many §10.2 E7 defects this machine has produced. Any value above zero
    /// is a bug.
    #[must_use]
    pub const fn invariant_violations(&self) -> u32 {
        self.invariant_violations
    }

    /// Whether the machine's own invariant holds: a reason-bearing state has a
    /// code, and no other state carries one.
    #[must_use]
    pub const fn state_and_reason_agree(&self) -> bool {
        self.state.requires_reason_code() == self.reason.is_some()
    }

    /// Applies a trigger. **The only mutator.**
    ///
    /// Produces exactly one [`TransitionRecord`] when a row fires, and exactly
    /// one [`Outcome::Ignored`] when none does.
    pub fn apply(&mut self, trigger: Trigger, guards: Guards, ctx: Context) -> Outcome {
        let Some(resolution) = table::resolve(self.state, trigger, guards, ctx) else {
            return Outcome::Ignored {
                state: self.state,
                trigger,
            };
        };

        let from = self.state;
        let to = resolution.target.state(from);

        // A no-change row restates the code the state was ENTERED with, so a
        // heartbeat row cannot relabel the violation that put the machine here.
        let reason = if resolution.target.is_no_change() {
            self.reason
        } else {
            resolution.target.reason()
        };

        self.profile = next_profile(self.profile, to, trigger, guards);

        let occurred_at_micros = self.env.now_monotonic().as_micros();
        let path_id = if to.has_path() { self.path_id } else { None };

        let diagnostic = reason.map(|code| {
            Diagnostic::builder(code, Component::TunnelEngine)
                .transition(from.connection_state(), to.connection_state())
                .evidence(
                    "invariant",
                    EvidenceValue::Text(resolution.row.label().to_owned()),
                )
                .build()
        });

        let mut record = TransitionRecord {
            from,
            to,
            trigger,
            row: resolution.row,
            reason_code: reason,
            session_id: self.session_id,
            path_id,
            occurred_at_micros,
            diagnostic,
        };

        // §10.2 E7: a malformed record is a defect, counted and made loud —
        // never swallowed, and never silently repaired into something plausible.
        if !record.is_well_formed() {
            self.invariant_violations = self.invariant_violations.saturating_add(1);
            if record.reason_code.is_none() && record.to.requires_reason_code() {
                record.reason_code = Some(codes::INTERNAL_MISSING_REASON);
                record.diagnostic = Some(
                    Diagnostic::invariant_violated(
                        Component::TunnelEngine,
                        "reliability.md §10.1: reason-bearing state entered without a code",
                    ),
                );
            }
        }

        self.state = to;
        self.reason = record.reason_code.filter(|_| to.requires_reason_code());
        self.history.push(record.clone());
        Outcome::Transitioned(Box::new(record))
    }

    /// Every distinct §4.5 row this machine has taken.
    ///
    /// `docs/testing-strategy.md` §2.2 makes transition coverage a merge gate;
    /// this is the per-machine half of the measurement.
    #[must_use]
    pub fn rows_covered(&self) -> Vec<Row> {
        let mut rows: Vec<Row> = self.history.iter().map(|r| r.row).collect();
        rows.sort_unstable();
        rows.dedup();
        rows
    }
}

/// The code a restored reason-bearing state carries when the journal lost it.
///
/// Each answer is **class-compatible with its state** (§10.2's static rule), so
/// a record recovered from a corrupt journal is still a well-formed record. A
/// restored `Session` that cannot say why it is blocked is a defect, but it must
/// not become a *second* defect by carrying a code the state cannot hold.
fn default_resume_reason(state: SessionState) -> ReasonCode {
    match state {
        // POLICY, and the honest answer: fail-closed is holding traffic.
        SessionState::Blocked => codes::POLICY_KILLSWITCH_ENGAGED,
        // PERSISTENT: nothing is carrying traffic and we cannot say more.
        SessionState::Failed => codes::NET_NO_ROUTE,
        // TRANSIENT: §6.5's "a restarted client resumes into RECONNECTING".
        SessionState::Reconnecting { .. } => codes::PLATFORM_PROCESS_RESTARTED,
        // TRANSIENT: the only class DEGRADED admits.
        SessionState::Degraded { .. } => codes::NET_QOS_DEGRADED_TIMEOUT,
        _ => codes::PLATFORM_PROCESS_RESTARTED,
    }
}

/// §11.1: `EV_BACKGROUND` / `EV_FOREGROUND` switch the timer profile, and a park
/// selects the third one.
fn next_profile(
    current: TimerProfile,
    to: SessionState,
    trigger: Trigger,
    guards: Guards,
) -> TimerProfile {
    use crate::event::Event as E;
    match trigger.event() {
        Some(E::Foreground | E::Resume) => TimerProfile::Foreground,
        Some(E::Background | E::Suspend) => {
            let parked = matches!(to, SessionState::Reconnecting { parked: true });
            if !parked && guards.inbound_required {
                TimerProfile::Background
            } else {
                TimerProfile::Parked
            }
        }
        _ => current,
    }
}
