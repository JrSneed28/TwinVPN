//! §6.4's dead-peer detection: bidirectional, authenticated, and escalating.
//!
//! **Authority:** `docs/reliability.md` §6.4, §5.2 (`T_SUSPECT`, `T_DEAD`,
//! `T_LEG_DEAD`), §7.1 (five probe loops), §7.4 (reconciling `PATH_FAILING`
//! with the two timers), §11.1.
//!
//! # Unidirectional evidence is explicitly not sufficient
//!
//! > A path is `LIVE` only if an authenticated packet from the peer, on that
//! > path, has been received within `T_DEAD`, **and** the peer has acknowledged
//! > our traffic within `T_DEAD`. … Half-open paths — where one direction works
//! > and the other does not — are a common NAT and firewall failure and are the
//! > classic cause of "connected but nothing loads".
//!
//! [`PathLiveness`] therefore carries **two** timestamps and neither alone can
//! keep a path `Live`.
//!
//! # The three thresholds are three different jobs (§7.4)
//!
//! | Missed | Threshold | Authorises |
//! |---|---|---|
//! | 2 | `T_SUSPECT` (6 s) | probe alternates; **do not touch traffic** (T18) |
//! | 3 | `PATH_FAILING` | demote a *promoted* path to an already-validated one |
//! | 5 | `T_DEAD` (15 s) | migrate (T19) or reconnect (T20) |

use twinvpn_env::MonotonicInstant;

use crate::timers;

/// The liveness ladder. Detection "escalates rather than jumping".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Liveness {
    /// Bidirectional authenticated evidence inside `T_DEAD`.
    Live,
    /// Two missed heartbeats. Start probing alternates; traffic is untouched.
    Suspect,
    /// Three missed. A *promoted* path may be demoted to an already-validated
    /// one — not a synonym for death, which §7.4 asks `networking.md` §4.3 to
    /// record.
    Failing,
    /// Five missed, or a hard signal. Migrate or reconnect.
    Dead,
}

/// One path's liveness bookkeeping.
#[derive(Debug, Clone)]
pub struct PathLiveness {
    /// Last authenticated packet **received from** the peer on this path.
    inbound: Option<MonotonicInstant>,
    /// Last acknowledgement **by** the peer of our traffic on this path.
    outbound_acked: Option<MonotonicInstant>,
    /// Consecutive missed heartbeats.
    missed: u32,
    /// A hard signal bypasses the ladder entirely (R2).
    hard_dead: bool,
    /// §6.4: an authenticated `PEER_RESTARTING` suppresses failure handling for
    /// `T_PEER_RESTART_GRACE`.
    restart_grace_until: Option<MonotonicInstant>,
}

impl Default for PathLiveness {
    fn default() -> Self {
        Self::new()
    }
}

impl PathLiveness {
    /// A path with no evidence yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inbound: None,
            outbound_acked: None,
            missed: 0,
            hard_dead: false,
            restart_grace_until: None,
        }
    }

    /// Records an authenticated inbound packet.
    ///
    /// §6.4: "User data counts as liveness evidence. Heartbeats are suppressed
    /// when data has flowed within the interval, so an active tunnel pays no
    /// heartbeat cost at all." The caller does not distinguish data from
    /// heartbeat here for that reason.
    pub fn observe_inbound(&mut self, at: MonotonicInstant) {
        self.inbound = Some(at);
        self.missed = 0;
    }

    /// Records the peer acknowledging our traffic.
    pub fn observe_outbound_acked(&mut self, at: MonotonicInstant) {
        self.outbound_acked = Some(at);
        self.missed = 0;
    }

    /// Records a heartbeat that went unanswered.
    pub fn observe_missed(&mut self) {
        self.missed = self.missed.saturating_add(1);
    }

    /// A hard signal: `EV_LINK_DOWN`, a socket error, or an ICMP/ICMPv6
    /// unreachable. Bypasses every timer.
    pub fn observe_hard_failure(&mut self) {
        self.hard_dead = true;
    }

    /// An authenticated `PEER_RESTARTING` suppresses the failure path.
    pub fn observe_peer_restarting(&mut self, now: MonotonicInstant) {
        self.restart_grace_until = Some(now.saturating_add(timers::T_PEER_RESTART_GRACE.default));
    }

    /// The current rung.
    #[must_use]
    pub fn evaluate(&self, now: MonotonicInstant) -> Liveness {
        if let Some(until) = self.restart_grace_until {
            if !now.reached(until) && !self.hard_dead {
                return Liveness::Live;
            }
        }
        if self.hard_dead {
            return Liveness::Dead;
        }
        // Bidirectional: BOTH directions must have evidence inside T_DEAD.
        let stale = |t: Option<MonotonicInstant>| match t {
            None => true,
            Some(at) => now.duration_since(at) > timers::T_DEAD.default,
        };
        if stale(self.inbound) || stale(self.outbound_acked) {
            return Liveness::Dead;
        }
        match self.missed {
            0 | 1 => Liveness::Live,
            2 => Liveness::Suspect,
            3 | 4 => Liveness::Failing,
            _ => Liveness::Dead,
        }
    }

    /// Whether the path is half-open: one direction has fresh evidence and the
    /// other does not.
    ///
    /// Surfaced separately because "connected but nothing loads" is the symptom
    /// this whole section exists to name.
    #[must_use]
    pub fn is_half_open(&self, now: MonotonicInstant) -> bool {
        let fresh = |t: Option<MonotonicInstant>| {
            t.is_some_and(|at| now.duration_since(at) <= timers::T_DEAD.default)
        };
        fresh(self.inbound) != fresh(self.outbound_acked)
    }
}

/// The **device↔relay leg**'s own liveness, which is a different question from
/// [`PathLiveness`] and answers it with a different constant.
///
/// §5.2: "a dead leg is a *relay* failure and triggers relay failover (§8),
/// while a silent half-flow on a **live** leg is *peer* loss and MUST NOT cause
/// failover — moving a working relay cannot help."
#[derive(Debug, Clone, Copy, Default)]
pub struct LegLiveness {
    missed_pings: u32,
}

impl LegLiveness {
    /// A fresh leg.
    #[must_use]
    pub const fn new() -> Self {
        Self { missed_pings: 0 }
    }

    /// A `PONG` arrived.
    pub fn observe_pong(&mut self) {
        self.missed_pings = 0;
    }

    /// A `PING` went unanswered.
    pub fn observe_missed_ping(&mut self) {
        self.missed_pings = self.missed_pings.saturating_add(1);
    }

    /// Whether the **relay** is down (as opposed to the peer).
    #[must_use]
    pub const fn is_dead(self) -> bool {
        self.missed_pings >= timers::N_LEG_DEAD_MISSED
    }
}
