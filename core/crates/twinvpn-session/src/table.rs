//! `docs/reliability.md` §4.5, row by row, with guards evaluated in the written
//! order.
//!
//! **Authority:** §4.5 (normative), §4.2 (the three always-wins edges), §4.6.
//!
//! # Order is part of the specification
//!
//! §4.5 opens with "Guards are evaluated in the order written". [`resolve`]
//! therefore walks [`Row::ALL`] in table order and takes the first row whose
//! source state, trigger and guards all match. That makes T32 (leaving `BLOCKED`
//! by authenticated user action) win over T38 (the wildcard disconnect), which
//! is the only place the order is load-bearing — and it is exactly the place
//! §4.2 warns about.

use twinvpn_types::{codes, PathClass, ReasonCode};

use crate::codes as reason;
use crate::event::{Event, TimerId, Trigger};
use crate::guards::Guards;
use crate::state::{EnforcementMode, SessionState, Target};
use crate::transition::Row;

/// Per-attempt facts a row needs but the trigger does not carry.
///
/// T12 and T27 both require "the **most specific** … code observed, never a
/// generic one". The machine cannot invent that: it is accumulated by
/// `twinvpn-path`, `twinvpn-relay-client` and `twinvpn-tunnel` as they fail, and
/// handed in here.
#[derive(Debug, Clone, Copy, Default)]
pub struct Context {
    /// T12: the most specific transport code observed on this attempt —
    /// `NAT.UDP_BLOCKED`, `NAT.*`, `RELAY.NONE_REACHABLE`, …
    pub transport_code: Option<ReasonCode>,
    /// T27: the most specific `FATAL`- or `PERSISTENT`-class code observed.
    pub terminal_code: Option<ReasonCode>,
    /// T28's cause, when a credential or trust condition drove it.
    pub terminal_auth_code: Option<ReasonCode>,
}

impl Context {
    /// T12's fallback ladder.
    ///
    /// Where nothing more specific was observed, `NET.NO_USABLE_CANDIDATES` is
    /// the honest answer — it is what actually happened — rather than a generic
    /// "connection failed", which §3.3 prohibits outright.
    #[must_use]
    pub fn transport_or_default(self) -> ReasonCode {
        self.transport_code
            .unwrap_or(codes::NET_NO_USABLE_CANDIDATES)
    }

    /// T27's fallback ladder, which §4.5 spells out: "where nothing more
    /// specific exists, `RELAY.FLEET.UNREACHABLE` or `NET.NO_USABLE_CANDIDATES`
    /// with the full candidate ledger as evidence".
    #[must_use]
    pub fn terminal_or_default(self, fleet_exhausted: bool) -> ReasonCode {
        self.terminal_code.unwrap_or(if fleet_exhausted {
            // `RELAY.FLEET.UNREACHABLE` is unregistered; see `crate::codes`.
            codes::RELAY_FAILOVER_EXHAUSTED
        } else {
            codes::NET_NO_USABLE_CANDIDATES
        })
    }
}

/// The outcome of consulting the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolution {
    /// Which row fired.
    pub row: Row,
    /// Where the machine goes. Equal to the source state for T18, T31 and T36.
    pub target: Target,
}

/// Resolves a `(state, trigger, guards)` triple to a row, or to `None` when the
/// trigger is not admissible in this state.
///
/// A `None` is **not** a silent drop: [`crate::machine::SessionMachine::apply`]
/// records it as an ignored trigger with the state that ignored it, so "nothing
/// happened" is still observable.
#[must_use]
#[allow(clippy::too_many_lines)] // One arm per normative row; splitting it would
                                 // hide the table's order, which IS the spec.
pub fn resolve(
    state: SessionState,
    trigger: Trigger,
    guards: Guards,
    ctx: Context,
) -> Option<Resolution> {
    for row in Row::ALL {
        if let Some(target) = row_applies(row, state, trigger, guards, ctx) {
            return Some(Resolution { row, target });
        }
    }
    None
}

#[allow(clippy::too_many_lines, clippy::match_same_arms)]
fn row_applies(
    row: Row,
    state: SessionState,
    trigger: Trigger,
    g: Guards,
    ctx: Context,
) -> Option<Target> {
    use Event as E;
    use SessionState as S;
    let ev = trigger.event();
    let tm = match trigger {
        Trigger::Timer(t) => Some(t),
        Trigger::Event(_) => None,
    };

    match row {
        // T01 | DISCONNECTED | EV_CONNECT_REQUESTED | credentials valid ∧ peer authorized
        Row::T01 => (state == S::Disconnected
            && ev == Some(E::ConnectRequested)
            && g.credentials_valid
            && g.peer_authorized)
            .then_some(Target::Discovering),

        // T02 | DISCONNECTED | EV_CONNECT_REQUESTED | credentials expired
        Row::T02 => {
            (state == S::Disconnected && ev == Some(E::ConnectRequested) && g.credentials_expired)
                .then_some(Target::Failed {
                    reason: codes::AUTH_CRED_EXPIRED,
                })
        }

        // T03 | DISCOVERING | EV_CANDIDATES_READY | >=1 usable candidate
        Row::T03 => {
            (state == S::Discovering && ev == Some(E::CandidatesReady) && g.usable_candidate)
                .then_some(Target::Negotiating)
        }

        // T04 | DISCOVERING | EV_CANDIDATE_TIMEOUT | no candidate on either family
        Row::T04 => (state == S::Discovering
            && (ev == Some(E::CandidateTimeout) || tm == Some(TimerId::Discover))
            && g.no_candidate_either_family)
            .then_some(Target::Reconnecting {
                parked: false,
                reason: codes::NET_NO_USABLE_CANDIDATES,
            }),

        // T05 | NEGOTIATING | EV_NEGOTIATION_OK | —
        Row::T05 => {
            (state == S::Negotiating && ev == Some(E::NegotiationOk)).then_some(Target::Connecting)
        }

        // T06 | NEGOTIATING | EV_VERSION_INCOMPATIBLE | —
        Row::T06 => (state == S::Negotiating && ev == Some(E::VersionIncompatible)).then_some(
            Target::Failed {
                reason: codes::PROTO_VERSION_UNSUPPORTED,
            },
        ),

        // T07 | NEGOTIATING | EV_NEGOTIATION_FAIL ∨ T_NEGOTIATE | retry budget available
        Row::T07 => (state == S::Negotiating
            && (ev == Some(E::NegotiationFail) || tm == Some(TimerId::Negotiate))
            && g.retry_budget_available)
            .then_some(Target::Reconnecting {
                parked: false,
                reason: codes::NET_SESSION_NEGOTIATION_FAILED,
            }),

        // T08 | CONNECTING | EV_HANDSHAKE_OK{L2} | path validated
        Row::T08 => (state == S::Connecting
            && ev == Some(E::HandshakeOk(PathClass::LocalDirect))
            && g.path_validated)
            .then_some(Target::Steady(PathClass::LocalDirect)),

        // T09 | CONNECTING | EV_HANDSHAKE_OK{WAN} | path validated ∧ no L2 path won
        Row::T09 => (state == S::Connecting
            && ev == Some(E::HandshakeOk(PathClass::WanDirect))
            && g.path_validated
            && g.no_l2_path_won)
            .then_some(Target::Steady(PathClass::WanDirect)),

        // T10 | CONNECTING | EV_HANDSHAKE_OK{RELAY} | validated ∧ no direct path won yet
        Row::T10 => (state == S::Connecting
            && ev == Some(E::HandshakeOk(PathClass::Relayed))
            && g.path_validated
            && g.no_direct_path_won)
            .then_some(Target::Steady(PathClass::Relayed)),

        // T11 | CONNECTING | EV_AUTH_REJECTED ∨ EV_PEER_REVOKED | —
        Row::T11 => (state == S::Connecting
            && matches!(ev, Some(E::AuthRejected | E::PeerRevoked)))
        .then_some(Target::Failed {
            reason: if ev == Some(E::PeerRevoked) {
                codes::AUTH_DEVICE_REVOKED
            } else {
                codes::AUTH_PEER_UNTRUSTED
            },
        }),

        // T12 | CONNECTING | EV_HANDSHAKE_FAIL ∨ T_CONNECT | retry budget available
        Row::T12 => (state == S::Connecting
            && (ev == Some(E::HandshakeFail) || tm == Some(TimerId::Connect))
            && g.retry_budget_available)
            .then_some(Target::Reconnecting {
                parked: false,
                reason: ctx.transport_or_default(),
            }),

        // T13 | RELAYED | EV_PATH_UPGRADE_AVAILABLE{WAN} | validated ∧ better by hysteresis
        Row::T13 => (state == S::Steady(PathClass::Relayed)
            && ev == Some(E::PathUpgradeAvailable(PathClass::WanDirect))
            && g.path_validated
            && g.upgrade_admissible())
        .then_some(Target::Migrating {
            from: PathClass::Relayed,
            to: PathClass::WanDirect,
        }),

        // T14 | RELAYED ∨ WAN_DIRECT | EV_PATH_UPGRADE_AVAILABLE{L2} | validated ∧ same L2
        Row::T14 => match state {
            S::Steady(from @ (PathClass::Relayed | PathClass::WanDirect))
                if ev == Some(E::PathUpgradeAvailable(PathClass::LocalDirect))
                    && g.path_validated
                    && g.same_l2_confirmed =>
            {
                Some(Target::Migrating {
                    from,
                    to: PathClass::LocalDirect,
                })
            }
            _ => None,
        },

        // T15 | MIGRATING | EV_PATH_VALIDATED{to} | new path committed
        Row::T15 => match state {
            S::Migrating { to, .. } if ev == Some(E::PathValidated(to)) && g.new_path_committed => {
                Some(Target::Steady(to))
            }
            _ => None,
        },

        // T16 | MIGRATING | EV_MIGRATION_FAIL ∨ T_MIGRATE | old path still alive
        Row::T16 => match state {
            S::Migrating { from, .. }
                if (ev == Some(E::MigrationFail) || tm == Some(TimerId::Migrate))
                    && g.old_path_alive =>
            {
                Some(Target::Steady(from))
            }
            _ => None,
        },

        // T17 | MIGRATING | EV_MIGRATION_FAIL ∨ T_MIGRATE | old path dead
        Row::T17 => match state {
            S::Migrating { .. }
                if (ev == Some(E::MigrationFail) || tm == Some(TimerId::Migrate))
                    && !g.old_path_alive =>
            {
                Some(Target::Reconnecting {
                    parked: false,
                    reason: codes::NET_PATH_MIGRATION_FAILED,
                })
            }
            _ => None,
        },

        // T18 | steady ∨ DEGRADED | EV_PATH_SUSPECT | — | *no state change*
        Row::T18 => (matches!(state, S::Steady(_) | S::Degraded { .. })
            && ev == Some(E::PathSuspect))
        .then_some(Target::NoChange),

        // T19 | steady ∨ DEGRADED | EV_PATH_DEAD ∨ EV_LINK_DOWN ∨ EV_RELAY_GONE
        //     | a validated or warm alternate exists
        Row::T19 => match state {
            S::Steady(from) | S::Degraded { carrier: from }
                if is_death(ev) && alternate_ready(from, g) =>
            {
                Some(Target::Migrating {
                    from,
                    // §8.1: relay death with a warm standby goes RELAY→RELAY'.
                    // Otherwise the alternate is whatever the ledger holds; the
                    // ledger's choice arrives as `alternate_class`.
                    to: alternate_class(from),
                })
            }
            _ => None,
        },

        // T20 | steady ∨ DEGRADED | EV_PATH_DEAD ∨ EV_LINK_DOWN | no alternate
        Row::T20 => match state {
            S::Steady(_) | S::Degraded { .. }
                if matches!(ev, Some(E::PathDead | E::LinkDown(_) | E::RelayGone)) =>
            {
                Some(Target::Reconnecting {
                    parked: false,
                    reason: reason::path_dead_no_alternate(),
                })
            }
            _ => None,
        },

        // T21 | steady | EV_ADDR_CHANGED | local address changed
        Row::T21 => match state {
            S::Steady(c) if ev == Some(E::AddrChanged) && g.local_address_changed => {
                Some(Target::Migrating { from: c, to: c })
            }
            _ => None,
        },

        // T22 | steady | EV_QOS_VIOLATION{m} | sustained >= T_QOS_CONFIRM
        Row::T22 => match (state, ev) {
            (S::Steady(c), Some(E::QosViolation(m))) if g.qos_violation_sustained => {
                Some(Target::Degraded {
                    carrier: c,
                    reason: reason::qos_code(m),
                })
            }
            _ => None,
        },

        // T23 | DEGRADED | EV_QOS_RESTORED | restored >= T_QOS_CLEAR
        Row::T23 => match state {
            S::Degraded { carrier } if ev == Some(E::QosRestored) && g.qos_restored_sustained => {
                Some(Target::Steady(carrier))
            }
            _ => None,
        },

        // T24 | DEGRADED | T_DEGRADED_MAX | —
        Row::T24 => (matches!(state, S::Degraded { .. }) && tm == Some(TimerId::DegradedMax))
            .then_some(Target::Reconnecting {
                parked: false,
                reason: codes::NET_QOS_DEGRADED_TIMEOUT,
            }),

        // T25 | RECONNECTING | EV_HANDSHAKE_OK{class} | path validated
        Row::T25 => match (state, ev) {
            (S::Reconnecting { .. }, Some(E::HandshakeOk(c))) if g.path_validated => {
                Some(Target::Steady(c))
            }
            _ => None,
        },

        // T26 | RECONNECTING | T_RECONNECT_GRACE | enforcement = FAIL_CLOSED
        Row::T26 => (matches!(state, S::Reconnecting { .. })
            && tm == Some(TimerId::ReconnectGrace)
            && g.fail_closed())
        .then_some(Target::Blocked {
            reason: codes::POLICY_KILLSWITCH_ENGAGED,
        }),

        // T27 | RECONNECTING | T_RECONNECT_MAX ∨ EV_RETRY_BUDGET_EXHAUSTED
        //     | enforcement = PERMISSIVE_ANNOUNCED
        Row::T27 => (matches!(state, S::Reconnecting { .. })
            && (tm == Some(TimerId::ReconnectMax) || ev == Some(E::RetryBudgetExhausted))
            && g.enforcement == Some(EnforcementMode::PermissiveAnnounced))
        .then_some(Target::Failed {
            reason: ctx.terminal_or_default(g.relay_fleet_exhausted),
        }),

        // T28 | RECONNECTING | EV_CRED_EXPIRED ∨ EV_PEER_REVOKED ∨ EV_VERSION_INCOMPATIBLE
        Row::T28 => match (state, ev) {
            (S::Reconnecting { .. }, Some(e)) => match e {
                E::CredExpired => Some(Target::Failed {
                    reason: ctx.terminal_auth_code.unwrap_or(codes::AUTH_CRED_EXPIRED),
                }),
                E::PeerRevoked => Some(Target::Failed {
                    reason: codes::AUTH_DEVICE_REVOKED,
                }),
                E::VersionIncompatible => Some(Target::Failed {
                    reason: codes::PROTO_VERSION_UNSUPPORTED,
                }),
                _ => None,
            },
            _ => None,
        },

        // T29 | * | EV_POLICY_VIOLATION{kind} | — | ALWAYS WINS
        Row::T29 => match ev {
            Some(E::PolicyViolation(kind)) => Some(Target::Blocked {
                reason: reason::policy_violation_code(kind),
            }),
            _ => None,
        },

        // T30 | BLOCKED | EV_SECURE_PATH_RESTORED
        //     | authorized secure path ∧ enforcement reconciliation passes
        Row::T30 => (state == S::Blocked
            && ev == Some(E::SecurePathRestored)
            && g.secure_path_established
            && g.enforcement_reconciled)
            .then_some(Target::Steady(
                // The class is supplied by the path ledger; RELAYED is the
                // conservative default because §8.4 makes the relay the floor.
                PathClass::Relayed,
            )),

        // T31 | BLOCKED | backoff tick | retry budget available | *no state change*
        Row::T31 => {
            (state == S::Blocked && tm == Some(TimerId::Backoff) && g.retry_budget_available)
                .then_some(Target::NoChange)
        }

        // T32 | BLOCKED | EV_DISCONNECT_REQUESTED | authenticated user action
        Row::T32 => {
            (state == S::Blocked && ev == Some(E::DisconnectRequested) && g.authenticated_disarm)
                .then_some(Target::Disconnected)
        }

        // T33 | FAILED | EV_CONNECT_REQUESTED ∨ qualifying environment event
        //     | precondition of the terminal code satisfied
        Row::T33 => (state == S::Failed
            && matches!(
                ev,
                Some(E::ConnectRequested | E::LinkUp(_) | E::SecurePathRestored)
            )
            && g.retry_precondition_met)
            .then_some(Target::Discovering),

        // T34 | * | EV_SUSPEND ∨ (EV_BACKGROUND ∧ ¬inbound_required) | park
        Row::T34 => {
            let parking_background = ev == Some(E::Background)
                && !g.inbound_required
                && state != (S::Reconnecting { parked: true });
            (ev == Some(E::Suspend) || parking_background).then_some(Target::Reconnecting {
                parked: true,
                // `PLATFORM.BACKGROUND_SUSPENDED` is unregistered; both park
                // flavours therefore carry `PLATFORM.SUSPENDED`. See
                // `crate::codes::SUBSTITUTIONS`.
                reason: codes::PLATFORM_SUSPENDED,
            })
        }

        // T35 | RECONNECTING (parked) | EV_RESUME
        //     | MIGRATING if a path plausibly survived, else DISCOVERING
        Row::T35 => match state {
            S::Reconnecting { parked: true } if ev == Some(E::Resume) => {
                if g.path_plausibly_survived && !g.rekey_window_exceeded {
                    Some(Target::Migrating {
                        from: PathClass::Relayed,
                        to: PathClass::Relayed,
                    })
                } else {
                    Some(Target::Discovering)
                }
            }
            _ => None,
        },

        // T36 | * | EV_BACKGROUND / EV_FOREGROUND | inbound_required ∨ already parked
        Row::T36 => (matches!(ev, Some(E::Background | E::Foreground))
            && (g.inbound_required || state == (S::Reconnecting { parked: true })))
        .then_some(Target::NoChange),

        // T37 | RELAYED ∨ DEGRADED{RELAYED} | EV_RELAY_DRAINING{deadline}
        Row::T37 => (matches!(
            state,
            S::Steady(PathClass::Relayed)
                | S::Degraded {
                    carrier: PathClass::Relayed
                }
        ) && ev == Some(E::RelayDraining))
        .then_some(Target::Migrating {
            from: PathClass::Relayed,
            to: PathClass::Relayed,
        }),

        // T38 | * | EV_DISCONNECT_REQUESTED | state != BLOCKED
        Row::T38 => (ev == Some(E::DisconnectRequested) && state != S::Blocked)
            .then_some(Target::Disconnected),
    }
}

/// T19's death triggers.
fn is_death(ev: Option<Event>) -> bool {
    matches!(
        ev,
        Some(Event::PathDead | Event::LinkDown(_) | Event::RelayGone)
    )
}

/// T19's guard, split by what died.
///
/// §5.3 registers `RELAY_FAILOVER_TARGET_READY` as "the guard that separates T19
/// from T20 **on relay death**", which is why relay death asks a different
/// question from direct-path death.
fn alternate_ready(from: PathClass, g: Guards) -> bool {
    match from {
        PathClass::Relayed => g.relay_failover_target_ready,
        PathClass::LocalDirect | PathClass::WanDirect => g.alternate_available,
    }
}

/// Which class the alternate is.
///
/// §8.1 fixes the relay case: `RELAYED → MIGRATING{RELAY→RELAY'} → RELAYED`,
/// never through `DISCONNECTED` or `RECONNECTING`. §7.2 fixes the direct case:
/// a warm relay sits behind every `WAN_DIRECT`, so a dead direct path migrates
/// to `RELAYED`.
const fn alternate_class(_from: PathClass) -> PathClass {
    // Both answers are `RELAYED`, for two different reasons, and that is the
    // point rather than a coincidence: a dead relay fails over to another relay,
    // and a dead direct path falls back to the relay §7.2 kept warm behind it.
    // §8.4 is what makes the relay the floor in both cases.
    PathClass::Relayed
}
