//! The canonical `ConnectionState` vocabulary and its two companions.
//!
//! **Authority:** `contracts/proto/twinvpn/v1/connection.proto` (the frozen
//! vocabulary), `docs/reliability.md` §4 (the state machine).
//!
//! This crate carries the **type**. `twinvpn-session` carries the **machine**:
//! which transitions exist, what triggers them, and the transition-coverage
//! obligation of `docs/testing-strategy.md` §2.2. Nothing here decides a
//! transition, and the predicates below restate only what `connection.proto`'s
//! own normative comments say about each state — they are not a second authority.
//!
//! `ConnectionState` is instantiated **per `Session`** — once per `TrustedPeer`
//! relationship. A device in a `TwinNet` with six peers runs six instances, and
//! the `TwinNet`-scope state a UI calls "the connection" is *derived* by
//! `docs/reliability.md` §4.7's aggregation rules. It is not a separate
//! vocabulary and this crate deliberately offers no second enum for it.

use crate::error::TypeError;

/// The canonical connection state: the frozen twelve, plus the proto3 zero
/// value.
///
/// # Why `Unspecified` is here
///
/// Proto3 cannot distinguish "absent" from "zero", so the wire can carry a zero
/// and this type has to be able to name it. It is **not an operating state**:
/// [`ConnectionState::specified`] is the only way to get a real state out, and
/// every decision path takes that. Adding a thirteenth *real* state is a change
/// to `docs/reliability.md`, not to this file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConnectionState {
    /// The proto3 zero value. Never a state; only ever a decoding artifact.
    Unspecified = 0,

    /// Resting. No `Session` keys, no relay allocation, no `Route` for this peer.
    /// **Enforcement rules for the protected scope remain installed if
    /// `FAIL_CLOSED`** — disconnected is not unprotected.
    Disconnected = 1,

    /// Gathering candidates for v4 and v6 **concurrently**. No packet is sent to
    /// the peer over any path yet; no user traffic on an unvalidated path.
    Discovering = 2,

    /// Version and capability agreement plus candidate exchange. Nothing is
    /// committed until agreement. No user traffic.
    Negotiating = 3,

    /// Racing candidate pairs concurrently across v4 and v6 **and** across direct
    /// and relay. No user traffic until a path is both cryptographically
    /// established and validated.
    Connecting = 4,

    /// Steady. A validated direct path over the same L2 segment carries traffic.
    LocalDirect = 5,

    /// Steady. As `LocalDirect`, plus a NAT binding keepalive at the currently
    /// estimated safe interval and at least one alternate path warm or
    /// re-establishable within `T_FAILOVER_TARGET`.
    WanDirect = 6,

    /// Steady. The relay forwards **opaque ciphertext only** and holds no key
    /// capable of decrypting the payload (I1). A direct-upgrade prober runs, and
    /// a standby relay in a **different failure domain** is selected.
    Relayed = 7,

    /// Transient, make-before-break. The `Session`, its keys, and its inner v4
    /// and v6 addresses are **unchanged**. The new path is not committed until it
    /// passes authenticated path validation, and the old path is not released
    /// until the new one is committed whenever the old path is still alive.
    Migrating = 8,

    /// Steady but time-bounded. **Traffic continues to flow.**
    ///
    /// `docs/reliability.md` R6: the violation is a **quality** violation, never a
    /// policy or security violation. A policy violation must not let traffic
    /// continue, so it goes to [`ConnectionState::Blocked`] instead.
    Degraded = 9,

    /// Transient. `Session` context — identity, negotiated capabilities, inner
    /// addresses, cached peer endpoints — is **retained**. Enforcement rules stay
    /// installed. No user traffic is emitted on any path.
    Reconnecting = 10,

    /// Holding, recoverable. Traffic is **dropped fail-closed, always, without
    /// exception**. Entered **by policy, not by fault**. A re-establishment loop
    /// runs inside this state, and the reason code and its remediation are
    /// displayed persistently (I3).
    Blocked = 11,

    /// Terminal for the attempt. Entered only on a non-retryable condition or on
    /// retry-budget exhaustion. Carries the terminal reason code **and its
    /// precondition for retry**. No timers burn CPU or battery here.
    Failed = 12,
}

impl ConnectionState {
    /// The twelve real states, in wire order. Excludes `Unspecified`.
    pub const ALL: [ConnectionState; 12] = [
        ConnectionState::Disconnected,
        ConnectionState::Discovering,
        ConnectionState::Negotiating,
        ConnectionState::Connecting,
        ConnectionState::LocalDirect,
        ConnectionState::WanDirect,
        ConnectionState::Relayed,
        ConnectionState::Migrating,
        ConnectionState::Degraded,
        ConnectionState::Reconnecting,
        ConnectionState::Blocked,
        ConnectionState::Failed,
    ];

    /// Decodes a wire value, rejecting anything outside the frozen vocabulary.
    ///
    /// `Unspecified` (0) decodes successfully — the wire may carry it — and is
    /// then rejected by [`Self::specified`] at the point a state is actually
    /// required. Splitting those two steps is what lets a decoder report
    /// "malformed enum value 47" separately from "a state was required and none
    /// was supplied".
    pub const fn from_wire(value: i32) -> Result<Self, TypeError> {
        match value {
            0 => Ok(ConnectionState::Unspecified),
            1 => Ok(ConnectionState::Disconnected),
            2 => Ok(ConnectionState::Discovering),
            3 => Ok(ConnectionState::Negotiating),
            4 => Ok(ConnectionState::Connecting),
            5 => Ok(ConnectionState::LocalDirect),
            6 => Ok(ConnectionState::WanDirect),
            7 => Ok(ConnectionState::Relayed),
            8 => Ok(ConnectionState::Migrating),
            9 => Ok(ConnectionState::Degraded),
            10 => Ok(ConnectionState::Reconnecting),
            11 => Ok(ConnectionState::Blocked),
            12 => Ok(ConnectionState::Failed),
            observed => Err(TypeError::ConnectionStateUnknown { observed }),
        }
    }

    /// The wire value.
    #[must_use]
    pub const fn to_wire(self) -> i32 {
        self as i32
    }

    /// The state, or a rejection if it is the proto3 zero value.
    pub const fn specified(self) -> Result<Self, TypeError> {
        match self {
            ConnectionState::Unspecified => Err(TypeError::EnumUnspecified {
                enum_name: "twinvpn.v1.ConnectionState",
            }),
            other => Ok(other),
        }
    }

    /// Whether a validated path is carrying traffic in this state.
    ///
    /// True for exactly the three steady carrier states and for `Degraded`, whose
    /// proto comment is emphatic that **traffic continues to flow**. That last
    /// one is the whole reason this predicate exists: "connected" and "traffic is
    /// flowing" are two facts, and conflating them is how a UI renders `Degraded`
    /// as connected.
    #[must_use]
    pub const fn carries_traffic(self) -> bool {
        matches!(
            self,
            ConnectionState::LocalDirect
                | ConnectionState::WanDirect
                | ConnectionState::Relayed
                | ConnectionState::Degraded
                | ConnectionState::Migrating
        )
    }

    /// Whether the state is terminal for the current attempt.
    #[must_use]
    pub const fn is_terminal_for_attempt(self) -> bool {
        matches!(self, ConnectionState::Failed)
    }

    /// The path class carrying traffic, when exactly one is.
    ///
    /// `None` in `Degraded` and `Migrating`: `Degraded` is parameterised by its
    /// carrier and `Migrating` has two endpoints, so neither has a single answer
    /// and neither may be guessed at.
    #[must_use]
    pub const fn steady_carrier(self) -> Option<PathClass> {
        match self {
            ConnectionState::LocalDirect => Some(PathClass::LocalDirect),
            ConnectionState::WanDirect => Some(PathClass::WanDirect),
            ConnectionState::Relayed => Some(PathClass::Relayed),
            _ => None,
        }
    }
}

/// The class of path currently carrying traffic.
///
/// A **subset** of [`ConnectionState`], not a parallel vocabulary: exactly the
/// three states in which a validated path exists. Used as the `carrier`
/// parameter of `DEGRADED{carrier}` and as the endpoints of
/// `MIGRATING{from -> to}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathClass {
    /// A validated direct path over the same L2 segment.
    LocalDirect = 1,
    /// A validated direct path across the WAN.
    WanDirect = 2,
    /// A relayed path carrying opaque ciphertext.
    Relayed = 3,
}

impl PathClass {
    /// Decodes a wire value, rejecting `UNSPECIFIED` and anything unknown.
    pub const fn from_wire(value: i32) -> Result<Self, TypeError> {
        match value {
            1 => Ok(PathClass::LocalDirect),
            2 => Ok(PathClass::WanDirect),
            3 => Ok(PathClass::Relayed),
            0 => Err(TypeError::EnumUnspecified {
                enum_name: "twinvpn.v1.PathClass",
            }),
            observed => Err(TypeError::ConnectionStateUnknown { observed }),
        }
    }

    /// The wire value.
    #[must_use]
    pub const fn to_wire(self) -> i32 {
        self as i32
    }
}

/// What actually happens to user packets right now.
///
/// `docs/reliability.md` §4.1 tracks this **orthogonally** to
/// [`ConnectionState`] and deliberately does not encode it as extra states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrafficDisposition {
    /// Tunneled over a local direct path.
    TunneledLocalDirect = 1,
    /// Tunneled over a WAN direct path.
    TunneledWanDirect = 2,
    /// Tunneled over a relay.
    TunneledRelay = 3,
    /// Both paths alive during a make-before-break window.
    TunneledDual = 4,
    /// Held in a bounded queue.
    QueuedBounded = 5,
    /// Dropped, fail-closed.
    DroppedFailClosed = 6,
    /// Dropped for want of a route.
    DroppedNoRoute = 7,
    /// Sent outside the tunnel. **Exists only when enforcement mode is
    /// `PERMISSIVE_ANNOUNCED`** — the user has explicitly disabled the kill
    /// switch — and even then it is announced with a persistent
    /// `POLICY.KILLSWITCH.UNPROTECTED_FALLBACK` indication.
    UnprotectedAnnounced = 8,
}

impl TrafficDisposition {
    /// Whether user packets are reaching the network at all in this disposition.
    #[must_use]
    pub const fn packets_flow(self) -> bool {
        matches!(
            self,
            TrafficDisposition::TunneledLocalDirect
                | TrafficDisposition::TunneledWanDirect
                | TrafficDisposition::TunneledRelay
                | TrafficDisposition::TunneledDual
                | TrafficDisposition::UnprotectedAnnounced
        )
    }

    /// Whether packets are leaving the host **outside** the tunnel.
    ///
    /// True for exactly one disposition, and that one exists only under an
    /// explicit user opt-out. Anything that must refuse to run while traffic is
    /// unprotected asks this question, not `packets_flow`.
    #[must_use]
    pub const fn is_unprotected(self) -> bool {
        matches!(self, TrafficDisposition::UnprotectedAnnounced)
    }

    /// Decodes a wire value.
    pub const fn from_wire(value: i32) -> Result<Self, TypeError> {
        match value {
            1 => Ok(TrafficDisposition::TunneledLocalDirect),
            2 => Ok(TrafficDisposition::TunneledWanDirect),
            3 => Ok(TrafficDisposition::TunneledRelay),
            4 => Ok(TrafficDisposition::TunneledDual),
            5 => Ok(TrafficDisposition::QueuedBounded),
            6 => Ok(TrafficDisposition::DroppedFailClosed),
            7 => Ok(TrafficDisposition::DroppedNoRoute),
            8 => Ok(TrafficDisposition::UnprotectedAnnounced),
            0 => Err(TypeError::EnumUnspecified {
                enum_name: "twinvpn.v1.TrafficDisposition",
            }),
            observed => Err(TypeError::ConnectionStateUnknown { observed }),
        }
    }

    /// The wire value.
    #[must_use]
    pub const fn to_wire(self) -> i32 {
        self as i32
    }
}
