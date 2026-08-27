//! The state value, and the four targets that cannot be entered without a
//! `reason_code`.
//!
//! **Authority:** `docs/reliability.md` §4.1 (parameterised states), §4.4
//! (per-state invariants), §10.1 (the state-machine-boundary rule).
//!
//! # Why `Target` exists alongside `SessionState`
//!
//! §10.1 is normative:
//!
//! > `DEGRADED`, `BLOCKED`, `RECONNECTING`, and `FAILED` are **unenterable
//! > without a `reason_code`**.
//!
//! It then asks for that to be "an enforceable rule rather than a slogan", with
//! the transition function taking the code "as a **required argument** for those
//! four targets". [`Target`] is the strongest available form of that: the four
//! reason-bearing variants carry a **non-`Option`** [`ReasonCode`], so a
//! code-less entry does not type-check. There is no runtime check to forget,
//! because there is no runtime check.

use twinvpn_types::{ConnectionState, PathClass, ReasonCode, TrafficDisposition};

/// The state of one `Session`, with the two parameterised states carrying their
/// parameters.
///
/// `docs/reliability.md` §4.1: `DEGRADED{carrier}` and `MIGRATING{from → to}`
/// "are still the canonical single state name". The parameters live here rather
/// than as extra states, exactly as the document requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionState {
    /// `DISCONNECTED`.
    Disconnected,
    /// `DISCOVERING`.
    Discovering,
    /// `NEGOTIATING`.
    Negotiating,
    /// `CONNECTING`.
    Connecting,
    /// One of the three steady carrier states.
    Steady(PathClass),
    /// `MIGRATING{from → to}`.
    Migrating {
        /// The outgoing path class.
        from: PathClass,
        /// The incoming path class.
        to: PathClass,
    },
    /// `DEGRADED{carrier}`.
    Degraded {
        /// The class actually carrying traffic while a quality objective is
        /// violated.
        carrier: PathClass,
    },
    /// `RECONNECTING`, with §11.2's park flag.
    ///
    /// A park is `RECONNECTING` and not a thirteenth state — §11.2 is explicit —
    /// but T35 distinguishes a parked `Session` from an ordinary one, so the flag
    /// rides along in the same way `carrier` does for `DEGRADED`.
    Reconnecting {
        /// Whether this is §11.2's background park.
        parked: bool,
    },
    /// `BLOCKED`.
    Blocked,
    /// `FAILED`.
    Failed,
}

impl SessionState {
    /// The canonical `ConnectionState` this is.
    #[must_use]
    pub const fn connection_state(self) -> ConnectionState {
        match self {
            SessionState::Disconnected => ConnectionState::Disconnected,
            SessionState::Discovering => ConnectionState::Discovering,
            SessionState::Negotiating => ConnectionState::Negotiating,
            SessionState::Connecting => ConnectionState::Connecting,
            SessionState::Steady(PathClass::LocalDirect) => ConnectionState::LocalDirect,
            SessionState::Steady(PathClass::WanDirect) => ConnectionState::WanDirect,
            SessionState::Steady(PathClass::Relayed) => ConnectionState::Relayed,
            SessionState::Migrating { .. } => ConnectionState::Migrating,
            SessionState::Degraded { .. } => ConnectionState::Degraded,
            SessionState::Reconnecting { .. } => ConnectionState::Reconnecting,
            SessionState::Blocked => ConnectionState::Blocked,
            SessionState::Failed => ConnectionState::Failed,
        }
    }

    /// Whether entering this state requires a `reason_code` (§10.1).
    #[must_use]
    pub const fn requires_reason_code(self) -> bool {
        matches!(
            self,
            SessionState::Degraded { .. }
                | SessionState::Reconnecting { .. }
                | SessionState::Blocked
                | SessionState::Failed
        )
    }

    /// The class carrying traffic, where exactly one is.
    ///
    /// `MIGRATING` has two and therefore has none: §4.4 gives it
    /// `TUNNELED_DUAL`, not a single carrier.
    #[must_use]
    pub const fn carrier(self) -> Option<PathClass> {
        match self {
            SessionState::Steady(c) | SessionState::Degraded { carrier: c } => Some(c),
            _ => None,
        }
    }

    /// Whether a `Path` exists, i.e. whether `path_id` may be non-null on a
    /// transition event.
    ///
    /// §10.2 E-rule: "`path_id` is nullable — `DISCONNECTED`, `DISCOVERING`, and
    /// `NEGOTIATING` have no `Path`".
    #[must_use]
    pub const fn has_path(self) -> bool {
        !matches!(
            self,
            SessionState::Disconnected | SessionState::Discovering | SessionState::Negotiating
        )
    }

    /// §4.4's traffic disposition for this state under the given enforcement
    /// mode, for a peer inside the protected scope.
    ///
    /// The `MIGRATING` answer is `TUNNELED_DUAL`; the bounded-queue case
    /// (`QUEUED_BOUNDED`, old path already gone) is a property of the migration
    /// in flight and is supplied by [`Self::disposition_migrating`].
    #[must_use]
    pub const fn disposition(self, fail_closed: bool) -> TrafficDisposition {
        // `DEGRADED` shares its carrier's disposition exactly: §4.4's row reads
        // "the carrier's disposition (traffic **continues to flow**)". Deriving
        // it from `carrier()` rather than restating three pairs of arms is what
        // makes that impossible to get wrong for one family and right for the
        // other.
        if let Some(carrier) = self.carrier() {
            return match carrier {
                PathClass::LocalDirect => TrafficDisposition::TunneledLocalDirect,
                PathClass::WanDirect => TrafficDisposition::TunneledWanDirect,
                PathClass::Relayed => TrafficDisposition::TunneledRelay,
            };
        }
        match self {
            SessionState::Migrating { .. } => TrafficDisposition::TunneledDual,
            // §4.4 BLOCKED: "DROPPED_FAIL_CLOSED — always, without exception".
            SessionState::Blocked => TrafficDisposition::DroppedFailClosed,
            _ => {
                if fail_closed {
                    TrafficDisposition::DroppedFailClosed
                } else {
                    TrafficDisposition::DroppedNoRoute
                }
            }
        }
    }

    /// §4.4's `MIGRATING` disposition, which depends on whether the old path is
    /// still alive.
    #[must_use]
    pub const fn disposition_migrating(old_path_alive: bool) -> TrafficDisposition {
        if old_path_alive {
            TrafficDisposition::TunneledDual
        } else {
            TrafficDisposition::QueuedBounded
        }
    }
}

/// A transition target. The four reason-bearing states carry their code **by
/// type**, which is §10.1's mechanism.
///
/// There is no `Target` variant for `DEGRADED`, `RECONNECTING`, `BLOCKED` or
/// `FAILED` that omits the code, and [`SessionState`] is not itself a legal
/// argument to the transition function — so "enter `BLOCKED` quietly" is not a
/// program that compiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// `DISCONNECTED`.
    Disconnected,
    /// `DISCOVERING`.
    Discovering,
    /// `NEGOTIATING`.
    Negotiating,
    /// `CONNECTING`.
    Connecting,
    /// A steady carrier state.
    Steady(PathClass),
    /// `MIGRATING{from → to}`.
    Migrating {
        /// Outgoing class.
        from: PathClass,
        /// Incoming class.
        to: PathClass,
    },
    /// `DEGRADED{carrier}` — code required.
    Degraded {
        /// The carrier that keeps carrying traffic.
        carrier: PathClass,
        /// The `NET.QOS.*` code and its measured value.
        reason: ReasonCode,
    },
    /// `RECONNECTING` — code required.
    Reconnecting {
        /// Whether this is §11.2's park.
        parked: bool,
        /// Why.
        reason: ReasonCode,
    },
    /// `BLOCKED` — code required.
    Blocked {
        /// The policy code, per T29/T26.
        reason: ReasonCode,
    },
    /// `FAILED` — code required.
    Failed {
        /// The terminal code, carrying its retry precondition.
        reason: ReasonCode,
    },
    /// The three no-state-change rows: T18, T31, T36.
    ///
    /// §4.5 still lists them as rows, so they still emit exactly one transition
    /// event with `from == to`. They carry no new code: the machine restates the
    /// code the state was **entered** with, so a `DEGRADED → DEGRADED` heartbeat
    /// row cannot silently relabel the violation that put it there.
    NoChange,
}

impl Target {
    /// The state this target resolves to, given the state being left.
    ///
    /// `current` is consulted only for [`Target::NoChange`].
    #[must_use]
    pub const fn state(self, current: SessionState) -> SessionState {
        match self {
            Target::Disconnected => SessionState::Disconnected,
            Target::Discovering => SessionState::Discovering,
            Target::Negotiating => SessionState::Negotiating,
            Target::Connecting => SessionState::Connecting,
            Target::Steady(c) => SessionState::Steady(c),
            Target::Migrating { from, to } => SessionState::Migrating { from, to },
            Target::Degraded { carrier, .. } => SessionState::Degraded { carrier },
            Target::Reconnecting { parked, .. } => SessionState::Reconnecting { parked },
            Target::Blocked { .. } => SessionState::Blocked,
            Target::Failed { .. } => SessionState::Failed,
            Target::NoChange => current,
        }
    }

    /// The transition's `reason_code`, where the target or the row carries one.
    ///
    /// Always `Some` for the four states §10.1 names; `None` for an ordinary
    /// success, which §4.5 consequence 4 permits.
    #[must_use]
    pub const fn reason(self) -> Option<ReasonCode> {
        match self {
            Target::Degraded { reason, .. }
            | Target::Reconnecting { reason, .. }
            | Target::Blocked { reason }
            | Target::Failed { reason } => Some(reason),
            _ => None,
        }
    }

    /// Whether this target restates the current state rather than leaving it.
    #[must_use]
    pub const fn is_no_change(self) -> bool {
        matches!(self, Target::NoChange)
    }
}

/// Enforcement mode (§4.1). Owned by ADR-0012; read here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnforcementMode {
    /// The kill switch is armed.
    FailClosed,
    /// The user has explicitly disabled it, and it is announced.
    PermissiveAnnounced,
}

impl EnforcementMode {
    /// Whether fail-closed is in force.
    #[must_use]
    pub const fn is_fail_closed(self) -> bool {
        matches!(self, EnforcementMode::FailClosed)
    }
}
