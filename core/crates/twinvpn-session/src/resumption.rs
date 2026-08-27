//! §6.5's survival contract, and §11.3's wake ladder.
//!
//! **Authority:** `docs/reliability.md` §6.2, §6.5 ("This table is a contract.
//! Anything in the 'survives' column that the implementation tears down is a
//! defect"), §11.3; `docs/protocol.md` §12.1; ADR-0018 CD-1.
//!
//! # Resumption must work with the control plane completely down
//!
//! `protocol.md` §12.1, quoted by the contract's `ResumeSession`: "Requiring a
//! control-plane round trip to resume is the root cause of 'missing
//! auto-reconnect' and 'unreliable mobile background operation'." Steps 1–4 of
//! [`RecoveryStep`] therefore reach nothing but the local cache, the peer, and a
//! relay named in the **already-cached** signed map.

use crate::guards::Guards;

/// The disruptions §6.5's table has a column for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Disruption {
    /// Path change, roam, or address change.
    PathChange,
    /// Relay failover.
    RelayFailover,
    /// Process restart.
    ProcessRestart,
    /// A suspend longer than the rekey window.
    SuspendPastRekey,
    /// Credential expiry.
    CredentialExpiry,
}

/// One row of §6.5's table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Item {
    /// `Session` identity — path-independent, durable (S-12).
    SessionIdentity,
    /// `DeviceIdentity` / `DeviceKey`.
    DeviceIdentity,
    /// Negotiated `ProtocolVersion` and `Capability` set.
    Negotiated,
    /// Inner TwinNet IPv4 **and** IPv6 addresses.
    InnerAddresses,
    /// Installed `Route` / `DNSPolicy`.
    RouteAndDns,
    /// Transport (data) keys.
    TransportKeys,
    /// The anti-replay window.
    ReplayWindow,
    /// Application TCP/QUIC connections inside the tunnel.
    InnerFlows,
    /// Relay allocation / `SessionTag`.
    RelayAllocation,
    /// Reflexive `ConnectionCandidate`s.
    ReflexiveCandidates,
    /// Path RTT baseline, PMTU, congestion estimates.
    PathEstimates,
}

/// What happens to an item across a disruption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fate {
    /// Survives unchanged.
    Survives,
    /// Survives, but is re-asserted.
    SurvivesReasserted,
    /// Re-negotiated from surviving inputs.
    Renegotiated,
    /// Invalidated and re-gathered.
    Regathered,
    /// Reset, because it is a property of the path and not of the session.
    Reset,
    /// Lost.
    Lost,
}

/// §6.5's table, verbatim.
///
/// The load-bearing consequence: "**a roam, an IP change, or a relay failover
/// must not break an in-progress SSH session, file transfer, or video call**",
/// which is [`Item::InnerFlows`] being [`Fate::Survives`] in the first two
/// columns.
#[must_use]
// One arm per cell of a normative table. Merging arms that happen to share an
// answer today would hide which row said what, and §6.5 calls this table a
// contract — a reviewer has to be able to read it against the document.
#[allow(clippy::match_same_arms)]
pub const fn fate(item: Item, disruption: Disruption) -> Fate {
    use Disruption as D;
    use Fate as F;
    use Item as I;
    match (item, disruption) {
        (I::SessionIdentity | I::DeviceIdentity | I::InnerAddresses, _) => F::Survives,

        (I::Negotiated, D::ProcessRestart) => F::Renegotiated,
        (I::Negotiated, _) => F::Survives,

        (I::RouteAndDns, D::PathChange | D::SuspendPastRekey) => F::SurvivesReasserted,
        (I::RouteAndDns, _) => F::Survives,

        (I::TransportKeys, D::ProcessRestart | D::SuspendPastRekey) => F::Lost,
        (I::TransportKeys, _) => F::Survives,

        (I::ReplayWindow, D::ProcessRestart | D::SuspendPastRekey) => F::Lost,
        (I::ReplayWindow, _) => F::Survives,

        (I::InnerFlows, D::ProcessRestart | D::SuspendPastRekey) => F::Lost,
        (I::InnerFlows, _) => F::Survives,

        (I::RelayAllocation, D::CredentialExpiry) => F::Survives,
        (I::RelayAllocation, D::ProcessRestart | D::SuspendPastRekey) => F::Lost,
        (I::RelayAllocation, _) => F::Regathered,

        (I::ReflexiveCandidates, D::RelayFailover | D::CredentialExpiry) => F::Survives,
        (I::ReflexiveCandidates, D::ProcessRestart) => F::Lost,
        (I::ReflexiveCandidates, _) => F::Regathered,

        (I::PathEstimates, D::CredentialExpiry) => F::Survives,
        (I::PathEstimates, D::ProcessRestart) => F::Lost,
        (I::PathEstimates, _) => F::Reset,
    }
}

/// §6.2's recovery ladder, "the cheapest recovery that could work", specialised
/// for wake by §11.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecoveryStep {
    /// 1. Re-validate the existing path from a possibly-new local address.
    ///    ~1 RTT, no handshake. The common roaming case.
    RevalidateExisting,
    /// 2. Cut over to a warm standby. ~1 RTT.
    WarmStandby,
    /// 3. Re-probe the peer's last-known `Endpoint` set from cache. 1–2 RTT.
    CachedEndpoints,
    /// 4. Re-allocate a relay from the cached **signed** relay map. 2–3 RTT.
    ///    Works with the control plane down (I5).
    CachedRelayMap,
    /// 5. A full `DISCOVERING → NEGOTIATING → CONNECTING` cycle. Seconds.
    FullCycle,
}

impl RecoveryStep {
    /// The ladder, cheapest first.
    pub const LADDER: [RecoveryStep; 5] = [
        RecoveryStep::RevalidateExisting,
        RecoveryStep::WarmStandby,
        RecoveryStep::CachedEndpoints,
        RecoveryStep::CachedRelayMap,
        RecoveryStep::FullCycle,
    ];

    /// Whether this step needs the control plane.
    ///
    /// §6.2: "Steps 1–4 require **no** control-plane interaction at all."
    /// Step 5 does not either, strictly — it re-uses the same cached inputs —
    /// but it is the step that would *benefit* from a fresh relay map, so it is
    /// the only one marked.
    #[must_use]
    pub const fn benefits_from_control_plane(self) -> bool {
        matches!(self, RecoveryStep::FullCycle)
    }
}

/// The first ladder step admissible under the current guards.
///
/// Returns `None` only when nothing is admissible, which cannot happen: the
/// full cycle has no precondition. It is written as an `Option` anyway so a
/// future guard cannot make the ladder silently empty.
#[must_use]
pub fn next_step(g: Guards, existing_path_plausible: bool) -> Option<RecoveryStep> {
    for step in RecoveryStep::LADDER {
        let admissible = match step {
            RecoveryStep::RevalidateExisting => existing_path_plausible,
            RecoveryStep::WarmStandby => g.relay_standby_selected,
            // Both are always admissible: the cached endpoint set and the full
            // cycle need nothing but local state, which is what makes §6.2's
            // ladder terminate with the control plane down (I5).
            RecoveryStep::CachedEndpoints | RecoveryStep::FullCycle => true,
            RecoveryStep::CachedRelayMap => g.relay_set_nonempty,
        };
        if admissible {
            return Some(step);
        }
    }
    None
}

/// §11.3's wake sequence, in order.
///
/// Two rules make it safe rather than merely fast, and both are encoded by the
/// ordering: **enforcement is re-asserted before traffic is emitted**, and the
/// **`ElapsedClock`** delta — not the wall clock — decides whether a full
/// handshake is forced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WakeStep {
    /// Re-read interfaces, addresses and default routes, for v4 **and** v6.
    ReadInterfaces,
    /// Re-assert `Route` / `DNSPolicy` / firewall rules. **Enforcement first,
    /// always.**
    ReassertEnforcement,
    /// Compare the **`ElapsedClock`** delta against the rekey window.
    CompareElapsedDelta,
    /// Run §6.2's ladder.
    RecoveryLadder,
    /// Emit `NET.SESSION.RECOVERED` with the outage duration.
    EmitRecovered,
}

impl WakeStep {
    /// The sequence.
    pub const SEQUENCE: [WakeStep; 5] = [
        WakeStep::ReadInterfaces,
        WakeStep::ReassertEnforcement,
        WakeStep::CompareElapsedDelta,
        WakeStep::RecoveryLadder,
        WakeStep::EmitRecovered,
    ];
}
