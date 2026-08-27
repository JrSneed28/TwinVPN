//! `TransitionEvent`, and the row identifiers §4.5 numbers.
//!
//! **Authority:** `docs/reliability.md` §4.5 (normative: exactly one event per
//! transition), §10.2 (the event's shape and the seven E-rules),
//! `contracts/proto/twinvpn/v1/diagnostics.proto` `TransitionEvent`.
//!
//! The record is produced **only** by [`crate::machine::SessionMachine::apply`],
//! which is the only mutator of the machine's state. That is E1's "emission is a
//! property of the transition, not of a call site", expressed as the absence of
//! any other way to move.

use twinvpn_types::{
    codes, Component, ConnectionState, Diagnostic, EvidenceValue, PathId, ReasonCode, SessionId,
};

use crate::event::Trigger;
use crate::state::SessionState;

/// The row of §4.5 that fired.
///
/// Carried alongside `trigger` because §10.2 E2 needs the pairs T16/T17 and
/// T19/T20 told apart, and those differ by **guard**, not by event. The
/// transition-coverage gate of `docs/testing-strategy.md` §2.2 counts these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(missing_docs)]
pub enum Row {
    T01, T02, T03, T04, T05, T06, T07, T08, T09, T10,
    T11, T12, T13, T14, T15, T16, T17, T18, T19, T20,
    T21, T22, T23, T24, T25, T26, T27, T28, T29, T30,
    T31, T32, T33, T34, T35, T36, T37, T38,
}

impl Row {
    /// Every row of §4.5, in table order — which is also guard-evaluation order.
    pub const ALL: [Row; 38] = [
        Row::T01, Row::T02, Row::T03, Row::T04, Row::T05, Row::T06, Row::T07,
        Row::T08, Row::T09, Row::T10, Row::T11, Row::T12, Row::T13, Row::T14,
        Row::T15, Row::T16, Row::T17, Row::T18, Row::T19, Row::T20, Row::T21,
        Row::T22, Row::T23, Row::T24, Row::T25, Row::T26, Row::T27, Row::T28,
        Row::T29, Row::T30, Row::T31, Row::T32, Row::T33, Row::T34, Row::T35,
        Row::T36, Row::T37, Row::T38,
    ];

    /// `"T01"` … `"T38"`.
    #[must_use]
    pub fn label(self) -> &'static str {
        const LABELS: [&str; 38] = [
            "T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09", "T10",
            "T11", "T12", "T13", "T14", "T15", "T16", "T17", "T18", "T19", "T20",
            "T21", "T22", "T23", "T24", "T25", "T26", "T27", "T28", "T29", "T30",
            "T31", "T32", "T33", "T34", "T35", "T36", "T37", "T38",
        ];
        LABELS[self as usize]
    }
}

/// §10.2's record, with typed fields.
///
/// `occurred_at` is the **monotonic** reading, per E5: "wall clocks jump across
/// suspend/resume — the single most common transition-producing event on a
/// laptop". Wall-clock time rides along as evidence when the caller has a
/// resolved reading; this type does not fabricate one.
#[derive(Debug, Clone, PartialEq)]
pub struct TransitionRecord {
    /// The state left.
    pub from: SessionState,
    /// The state entered. May equal `from` for the three no-state-change rows
    /// (T18, T31, T36), which §4.5 still lists as rows and which therefore still
    /// emit exactly one event.
    pub to: SessionState,
    /// What fired.
    pub trigger: Trigger,
    /// Which row of §4.5.
    pub row: Row,
    /// Required when `to` is `DEGRADED`, `BLOCKED`, `RECONNECTING` or `FAILED`.
    pub reason_code: Option<ReasonCode>,
    /// Never null (S-12).
    pub session_id: SessionId,
    /// Null in `DISCONNECTED`, `DISCOVERING` and `NEGOTIATING`.
    pub path_id: Option<PathId>,
    /// Monotonic microseconds.
    pub occurred_at_micros: u64,
    /// The accompanying `Diagnostic`, present exactly when `reason_code` is.
    ///
    /// §10.2: "`TransitionEvent` and `Diagnostic` are distinct records with
    /// distinct lifetimes … exactly one `Diagnostic` is emitted alongside the
    /// `TransitionEvent`, carrying the same `reason_code` and the same
    /// `occurred_at`".
    pub diagnostic: Option<Diagnostic>,
}

impl TransitionRecord {
    /// Whether this record satisfies §10.1's boundary rule.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        if self.to.requires_reason_code() && self.reason_code.is_none() {
            return false;
        }
        if self.reason_code.is_some() != self.diagnostic.is_some() {
            return false;
        }
        if !self.to.has_path() && self.path_id.is_some() {
            return false;
        }
        true
    }

    /// The frozen `twinvpn.v1.TransitionEvent` this record is.
    ///
    /// Built rather than redeclared: `ownership.md` §6 rule 2 forbids
    /// redeclaring a message `contracts/` already defines.
    #[must_use]
    pub fn to_proto(&self) -> twinvpn_schema::v1::TransitionEvent {
        twinvpn_schema::v1::TransitionEvent {
            from: self.from.connection_state().to_wire(),
            to: self.to.connection_state().to_wire(),
            trigger: self.trigger.name().to_owned(),
            reason_code: self
                .reason_code
                .map(|c| c.as_str().to_owned())
                .unwrap_or_default(),
            session_id: self.session_id.as_bytes_vec(),
            path_id: self
                .path_id
                .map(|p| p.to_array().to_vec())
                .unwrap_or_default(),
            occurred_at: Some(twinvpn_schema::v1::MonotonicMicros {
                value: self.occurred_at_micros,
            }),
            diagnostic: None,
        }
    }

    /// The `INTERNAL.INVARIANT_VIOLATED` this record is, when it is malformed.
    ///
    /// §10.2 E7: a transition into one of the four states with
    /// `reason_code = null` "MUST itself emit `INTERNAL.INVARIANT_VIOLATED` and
    /// MUST be counted as a defect, not swallowed".
    #[must_use]
    pub fn invariant_violation(&self) -> Option<Diagnostic> {
        if self.is_well_formed() {
            return None;
        }
        Some(
            Diagnostic::builder(codes::INTERNAL_INVARIANT_VIOLATED, Component::TunnelEngine)
                .evidence(
                    "invariant",
                    EvidenceValue::Text(
                        "reliability.md §10.1: a reason-bearing state was entered without a code"
                            .to_owned(),
                    ),
                )
                .transition(
                    self.from.connection_state(),
                    self.to.connection_state(),
                )
                .build(),
        )
    }
}

/// Helper so `SessionId`'s bytes reach the proto without a second `Identifier`
/// import at every call site.
trait IdBytes {
    fn as_bytes_vec(&self) -> Vec<u8>;
}

impl IdBytes for SessionId {
    fn as_bytes_vec(&self) -> Vec<u8> {
        self.to_array().to_vec()
    }
}

/// A `ConnectionState` pair, for coverage bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StatePair {
    /// From.
    pub from: ConnectionState,
    /// To.
    pub to: ConnectionState,
}
