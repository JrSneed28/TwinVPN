//! `docs/reliability.md` §4.3's events, §5's timers, and the `trigger` that
//! distinguishes two transitions sharing a `(from, to)` pair.
//!
//! **Authority:** §4.3 (the event table), §5 (the timer constants), §10.2 E2.
//!
//! §10.2 E2 is the reason `trigger` is a type rather than a string built at the
//! call site:
//!
//! > `trigger` MUST distinguish transitions that share a `(from, to)` pair. T19
//! > and T20 differ only by whether an alternate exists; T16 and T17 differ only
//! > by whether the old path is alive.
//!
//! Both of those pairs share an *event*, so the event alone is not enough — the
//! discriminator is the row, which [`crate::transition::TransitionRecord`]
//! carries alongside the trigger.

use twinvpn_types::PathClass;

/// A quality metric, as `EV_QOS_VIOLATION{metric}` parameterises it (§5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QosMetric {
    /// Loss > 2 % sustained. `NET.QOS.LOSS_HIGH`.
    Loss,
    /// RTT > 3× baseline, or > 250 ms absolute on a relay path.
    /// `NET.QOS.RTT_HIGH`.
    Rtt,
    /// Jitter > 30 ms standard deviation. `NET.QOS.JITTER_HIGH`.
    Jitter,
    /// Throughput < 25 % of baseline under offered load.
    ///
    /// §5.4's code for this is `NET.QOS.THROUGHPUT_LOW`, which §3.5 contributes
    /// and the frozen registry does **not** yet carry; see [`crate::codes`].
    Throughput,
    /// Effective MTU below the 1280-byte IPv6 minimum. `NET.MTU_TOO_SMALL`.
    EffectiveMtu,
}

/// What kind of policy violation fired `EV_POLICY_VIOLATION{kind}` (§4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyViolationKind {
    /// A DNS query was observed leaving off-tunnel (ADR-0011, ADR-0012 canary).
    DnsQueryOffTunnel,
    /// The installed routes no longer match the desired generation.
    RouteDrift,
    /// The overlay interface is gone.
    InterfaceMissing,
    /// A family that could leak is not carried while policy requires dual-stack
    /// (§5.4's last row: this is a policy violation, **not** `DEGRADED`).
    FamilyUncovered,
    /// The enforcement ruleset was not present for one or both families at a
    /// reconciler tick.
    RulesetAbsent,
    /// A `PolicyBundle` grant expired in a way that would leave protected
    /// traffic unprotected (§7.7 `policy_grant_expired`).
    GrantExpired,
}

/// The class of link that went down, so T20's `caused_by` evidence can name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkKind {
    /// Wi-Fi. `NET.LINK.DOWN_WIFI`.
    WiFi,
    /// Cellular. `NET.LINK.DOWN_CELLULAR`.
    Cellular,
    /// Ethernet. `NET.LINK.CHANGED_ETHERNET`.
    Ethernet,
    /// The platform does not say.
    Unknown,
}

/// §4.3's events, one variant per row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Event {
    /// `EV_CONNECT_REQUESTED`. Idempotent; a request while already connecting is
    /// absorbed.
    ConnectRequested,
    /// `EV_DISCONNECT_REQUESTED`.
    DisconnectRequested,
    /// `EV_CANDIDATES_READY`. Fires on the **first usable** candidate.
    CandidatesReady,
    /// `EV_CANDIDATE_TIMEOUT`.
    CandidateTimeout,
    /// `EV_NEGOTIATION_OK`.
    NegotiationOk,
    /// `EV_NEGOTIATION_FAIL`.
    NegotiationFail,
    /// `EV_VERSION_INCOMPATIBLE`. Non-retryable.
    VersionIncompatible,
    /// `EV_HANDSHAKE_OK{class}`.
    HandshakeOk(PathClass),
    /// `EV_HANDSHAKE_FAIL`.
    HandshakeFail,
    /// `EV_AUTH_REJECTED`. Non-retryable.
    AuthRejected,
    /// `EV_PEER_REVOKED`. Non-retryable.
    PeerRevoked,
    /// `EV_RELAY_READY`.
    RelayReady,
    /// `EV_PATH_UPGRADE_AVAILABLE{class}`.
    PathUpgradeAvailable(PathClass),
    /// `EV_PATH_SUSPECT`.
    PathSuspect,
    /// `EV_PATH_DEAD`.
    PathDead,
    /// `EV_LINK_DOWN`.
    LinkDown(LinkKind),
    /// `EV_LINK_UP`.
    LinkUp(LinkKind),
    /// `EV_ADDR_CHANGED`.
    AddrChanged,
    /// `EV_PATH_VALIDATED{path}`.
    PathValidated(PathClass),
    /// `EV_MIGRATION_FAIL`.
    MigrationFail,
    /// `EV_QOS_VIOLATION{metric}`.
    QosViolation(QosMetric),
    /// `EV_QOS_RESTORED`.
    QosRestored,
    /// `EV_POLICY_VIOLATION{kind}`. Always wins; always → `BLOCKED`.
    PolicyViolation(PolicyViolationKind),
    /// `EV_SECURE_PATH_RESTORED`.
    SecurePathRestored,
    /// `EV_CRED_EXPIRED`.
    CredExpired,
    /// `EV_SUSPEND`.
    Suspend,
    /// `EV_RESUME`.
    Resume,
    /// `EV_BACKGROUND`.
    Background,
    /// `EV_FOREGROUND`.
    Foreground,
    /// `EV_RETRY_BUDGET_EXHAUSTED`.
    RetryBudgetExhausted,
    /// `EV_PEER_CLOSED`.
    PeerClosed,
    /// `EV_PEER_RESTARTING`. Suppresses the failure path for
    /// `T_PEER_RESTART_GRACE`.
    PeerRestarting,
    /// `EV_RELAY_DRAINING{deadline}`. The deadline rides in
    /// [`crate::machine::SessionMachine`]'s drain plan, not in the event, because
    /// §8.3's draw needs the RNG the event source does not hold.
    RelayDraining,
    /// `EV_RELAY_GONE`.
    RelayGone,
}

impl Event {
    /// The `EV_*` spelling, for the transition event's `trigger` field.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Event::ConnectRequested => "EV_CONNECT_REQUESTED",
            Event::DisconnectRequested => "EV_DISCONNECT_REQUESTED",
            Event::CandidatesReady => "EV_CANDIDATES_READY",
            Event::CandidateTimeout => "EV_CANDIDATE_TIMEOUT",
            Event::NegotiationOk => "EV_NEGOTIATION_OK",
            Event::NegotiationFail => "EV_NEGOTIATION_FAIL",
            Event::VersionIncompatible => "EV_VERSION_INCOMPATIBLE",
            Event::HandshakeOk(_) => "EV_HANDSHAKE_OK",
            Event::HandshakeFail => "EV_HANDSHAKE_FAIL",
            Event::AuthRejected => "EV_AUTH_REJECTED",
            Event::PeerRevoked => "EV_PEER_REVOKED",
            Event::RelayReady => "EV_RELAY_READY",
            Event::PathUpgradeAvailable(_) => "EV_PATH_UPGRADE_AVAILABLE",
            Event::PathSuspect => "EV_PATH_SUSPECT",
            Event::PathDead => "EV_PATH_DEAD",
            Event::LinkDown(_) => "EV_LINK_DOWN",
            Event::LinkUp(_) => "EV_LINK_UP",
            Event::AddrChanged => "EV_ADDR_CHANGED",
            Event::PathValidated(_) => "EV_PATH_VALIDATED",
            Event::MigrationFail => "EV_MIGRATION_FAIL",
            Event::QosViolation(_) => "EV_QOS_VIOLATION",
            Event::QosRestored => "EV_QOS_RESTORED",
            Event::PolicyViolation(_) => "EV_POLICY_VIOLATION",
            Event::SecurePathRestored => "EV_SECURE_PATH_RESTORED",
            Event::CredExpired => "EV_CRED_EXPIRED",
            Event::Suspend => "EV_SUSPEND",
            Event::Resume => "EV_RESUME",
            Event::Background => "EV_BACKGROUND",
            Event::Foreground => "EV_FOREGROUND",
            Event::RetryBudgetExhausted => "EV_RETRY_BUDGET_EXHAUSTED",
            Event::PeerClosed => "EV_PEER_CLOSED",
            Event::PeerRestarting => "EV_PEER_RESTARTING",
            Event::RelayDraining => "EV_RELAY_DRAINING",
            Event::RelayGone => "EV_RELAY_GONE",
        }
    }
}

/// The timers §5 registers that can *fire a transition*.
///
/// Not every §5 constant is here: `T_HEARTBEAT_*`, `T_SUSPECT`, `T_LEG_DEAD` and
/// `T_NAT_KEEPALIVE` drive [`crate::liveness`] and [`crate::keepalive`], which
/// synthesise `EV_PATH_SUSPECT` / `EV_PATH_DEAD` rather than acting on the
/// machine directly. Only a timer that names a row of §4.5 is a trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TimerId {
    /// `T_DISCOVER` — the gathering upper bound.
    Discover,
    /// `T_NEGOTIATE`.
    Negotiate,
    /// `T_CONNECT`.
    Connect,
    /// `T_MIGRATE` — the total budget for one migration attempt.
    Migrate,
    /// `T_RECONNECT_GRACE` — the boundary between a blip and an outage.
    ReconnectGrace,
    /// `T_RECONNECT_MAX` — only under `PERMISSIVE_ANNOUNCED`.
    ReconnectMax,
    /// `T_DEGRADED_MAX` — R5, no unbounded degradation.
    DegradedMax,
    /// The backoff tick that drives `BLOCKED`'s internal loop (T31).
    Backoff,
}

impl TimerId {
    /// The `T_*` spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            TimerId::Discover => "T_DISCOVER",
            TimerId::Negotiate => "T_NEGOTIATE",
            TimerId::Connect => "T_CONNECT",
            TimerId::Migrate => "T_MIGRATE",
            TimerId::ReconnectGrace => "T_RECONNECT_GRACE",
            TimerId::ReconnectMax => "T_RECONNECT_MAX",
            TimerId::DegradedMax => "T_DEGRADED_MAX",
            TimerId::Backoff => "T_BACKOFF",
        }
    }
}

/// What fired: an event or a timer. §10.2's `trigger` field is exactly this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Trigger {
    /// An `EV_*`.
    Event(Event),
    /// A `T_*`.
    Timer(TimerId),
}

impl Trigger {
    /// The wire spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Trigger::Event(e) => e.name(),
            Trigger::Timer(t) => t.name(),
        }
    }

    /// The event, when this is one.
    #[must_use]
    pub const fn event(self) -> Option<Event> {
        match self {
            Trigger::Event(e) => Some(e),
            Trigger::Timer(_) => None,
        }
    }
}

impl From<Event> for Trigger {
    fn from(e: Event) -> Self {
        Trigger::Event(e)
    }
}

impl From<TimerId> for Trigger {
    fn from(t: TimerId) -> Self {
        Trigger::Timer(t)
    }
}
