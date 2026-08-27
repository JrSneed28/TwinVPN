//! The RFC 4787 taxonomy, the traversability matrix, and the two bounded
//! techniques ADR-0004 subordinates.
//!
//! **Authority:** ADR-0004 §11 (the ladder, and the bounds on rungs 4 and 5),
//! §11.5's codes; `docs/networking.md` §3.1, §3.2, §3.6.
//!
//! # The old vocabulary is not used, and that is deliberate
//!
//! §3.1: TwinVPN classifies middleboxes "using RFC 4787 / RFC 5382 terms, **not**
//! the obsolete 'full cone / restricted / symmetric' vocabulary, because mapping
//! and filtering behavior are **independent axes** and the old vocabulary
//! conflates them."
//!
//! So [`NatClass`] is a pair of axes, and the legacy name is a `Display`-only
//! cross-reference obtained through [`NatClass::legacy_name`].

use core::time::Duration;

/// RFC 4787 mapping behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mapping {
    /// Endpoint-Independent Mapping.
    EndpointIndependent,
    /// Address-and-Port-Dependent Mapping — "symmetric".
    AddressAndPortDependent,
}

/// RFC 4787 filtering behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Filtering {
    /// Endpoint-Independent Filtering.
    EndpointIndependent,
    /// Address-Dependent Filtering.
    AddressDependent,
    /// Address-and-Port-Dependent Filtering.
    AddressAndPortDependent,
}

/// A measured middlebox class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NatClass {
    /// The mapping axis.
    pub mapping: Mapping,
    /// The filtering axis.
    pub filtering: Filtering,
    /// Whether the device is behind carrier-grade NAT.
    pub cgnat: bool,
    /// Whether native IPv6 is available on this path.
    pub native_v6: bool,
}

impl NatClass {
    /// The legacy name, for cross-reference only.
    #[must_use]
    pub const fn legacy_name(self) -> &'static str {
        if self.cgnat {
            return "CGNAT";
        }
        match (self.mapping, self.filtering) {
            (Mapping::EndpointIndependent, Filtering::EndpointIndependent) => "full cone",
            (Mapping::EndpointIndependent, Filtering::AddressDependent) => {
                "address-restricted cone"
            }
            (Mapping::EndpointIndependent, Filtering::AddressAndPortDependent) => {
                "port-restricted cone"
            }
            (Mapping::AddressAndPortDependent, _) => "symmetric",
        }
    }
}

/// §3.2's expectation for a pair of classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Traversability {
    /// Direct expected.
    Direct,
    /// Direct with port prediction or port mapping — probabilistic.
    DirectProbabilistic,
    /// **Relay by design.** "They are not failures, they do not produce an
    /// error, and they do not stall the state machine."
    RelayByDesign,
}

/// §3.2's matrix.
///
/// > Read the last row and column first: **if both ends have working IPv6, every
/// > cell is `D`.** This is the single highest-leverage fact in the whole
/// > traversal design.
#[must_use]
pub fn traversability(local: NatClass, remote: NatClass) -> Traversability {
    if local.native_v6 && remote.native_v6 {
        return Traversability::Direct;
    }
    let hard = |c: NatClass| c.cgnat || c.mapping == Mapping::AddressAndPortDependent;
    match (hard(local), hard(remote)) {
        // APDM↔APDM and CGNAT↔CGNAT over IPv4 only.
        (true, true) => Traversability::RelayByDesign,
        (true, false) | (false, true) => {
            // CGNAT against a port-restricted cone is relay; everything else on
            // this diagonal is probabilistic.
            let (hard_side, other) = if hard(local) {
                (local, remote)
            } else {
                (remote, local)
            };
            if hard_side.cgnat && other.filtering == Filtering::AddressAndPortDependent {
                Traversability::RelayByDesign
            } else {
                Traversability::DirectProbabilistic
            }
        }
        (false, false) => Traversability::Direct,
    }
}

/// Rung 4: explicit port mapping, in order, with a 250 ms budget **each**.
///
/// "Failure is silent and fast."
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PortMapProtocol {
    /// PCP (RFC 6887). Tried first.
    Pcp,
    /// NAT-PMP.
    NatPmp,
    /// UPnP-IGDv2. Tried last.
    UpnpIgd,
}

impl PortMapProtocol {
    /// The order ADR-0004 §11 fixes.
    pub const LADDER: [PortMapProtocol; 3] = [
        PortMapProtocol::Pcp,
        PortMapProtocol::NatPmp,
        PortMapProtocol::UpnpIgd,
    ];
}

/// The per-protocol budget.
pub const PORTMAP_BUDGET: Duration = Duration::from_millis(250);
/// The requested mapping lifetime, renewed at 50 %.
pub const PORTMAP_LIFETIME: Duration = Duration::from_secs(3600);

/// Rung 5: bounded birthday-paradox port prediction.
///
/// ADR-0004 §11: "`k ≤ 256`, ≤ 2 s, **once**, only vs. observed port-varying
/// mapping". §3.6 adds the reason for the cap: "a burst of 256 probes to
/// sequential ports is indistinguishable from a port scan and will trip IDS.
/// This is a deliberate cap on aggressiveness."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortPrediction {
    /// How many sockets and predicted ports. Capped at [`MAX_K`].
    pub k: u32,
    /// Whether the rendezvous has **observed** the peer's mapping to be
    /// port-varying. Without this, prediction MUST NOT run.
    pub peer_mapping_observed_port_varying: bool,
    /// Whether it has already run for this path attempt.
    pub already_attempted: bool,
}

/// The hard cap on `k`.
pub const MAX_K: u32 = 256;
/// The total budget for one prediction attempt.
pub const PREDICTION_BUDGET: Duration = Duration::from_secs(2);

impl PortPrediction {
    /// Whether prediction is permitted right now.
    ///
    /// Four conditions, and all four are ADR-0004's: bounded `k`, at most once
    /// per attempt, and **only** against an observed port-varying mapping. The
    /// `limits.json` cap on the hint list (`candidates.max_birthday_port_hints`
    /// = 64) bounds what may be *exchanged*; `k` bounds what may be *probed*.
    #[must_use]
    pub const fn permitted(self) -> bool {
        self.k > 0
            && self.k <= MAX_K
            && self.peer_mapping_observed_port_varying
            && !self.already_attempted
    }

    /// The effective `k`, clamped rather than refused, because a caller asking
    /// for more is a bug in the caller and clamping keeps the ladder running.
    #[must_use]
    pub const fn effective_k(self) -> u32 {
        if self.k > MAX_K {
            MAX_K
        } else {
            self.k
        }
    }
}

/// §3.7's detection window: no `PONG` on **any** candidate including
/// relay-over-UDP within 2 s, while TCP/443 to the rendezvous succeeds.
pub const UDP_BLOCKED_WINDOW: Duration = Duration::from_secs(2);

/// Whether the observations amount to `NAT.UDP_BLOCKED`.
#[must_use]
pub const fn udp_blocked(
    any_pong_received: bool,
    relay_over_udp_answered: bool,
    tcp_443_to_rendezvous_succeeded: bool,
) -> bool {
    !any_pong_received && !relay_over_udp_answered && tcp_443_to_rendezvous_succeeded
}

/// §3.1's hairpinning axis (RFC 4787 REQ-9).
///
/// "Two peers behind the *same* NAT must reach each other via their reflexive
/// addresses if the local L2 path is blocked (client isolation)." When
/// hairpinning is unsupported and the L2 path is blocked, the answer is the
/// relay — "do not spin".
#[must_use]
pub const fn hairpin_requires_relay(same_public_ip: bool, l2_blocked: bool, hairpin: bool) -> bool {
    same_public_ip && l2_blocked && !hairpin
}
