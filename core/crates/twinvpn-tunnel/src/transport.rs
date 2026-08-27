//! L-TRANSPORT: pluggable, security-neutral, and **a property of the `Path`, not
//! of the `Session`**.
//!
//! **Authority:** ADR-0001 §7.2's L-TRANSPORT table and the composition rule
//! immediately below it, §7.6, §8; ADR-0005 §11; `docs/reliability.md` §6.5.
//!
//! # The single most important composition rule in ADR-0001
//!
//! > The transport mode is a property of the `Path`, not of the `Session`.
//! > Switching modes **MUST NOT re-run the L-DATA handshake**, **MUST NOT reset
//! > the L-DATA nonce counter or replay window**, and **MUST NOT alter any
//! > L-DATA security property**.
//!
//! [`TransportMode`] is therefore carried on the path and nowhere near
//! [`crate::engine::Tunnel`]'s key state, and
//! [`crate::engine::Tunnel::switch_transport`] takes the mode, touches neither
//! the keys nor the counters, and returns evidence that it did not.

/// ADR-0001 §7.2's three carriages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportMode {
    /// Raw UDP, IPv4 or IPv6. Used for `LOCAL_DIRECT` and `WAN_DIRECT`.
    /// Security contribution: **none** — "L-DATA is self-protecting".
    Udp,
    /// An L-DATA datagram inside an authenticated device↔relay session. Used for
    /// `RELAYED`. It "authorises and rate-limits the device to the relay; **hides
    /// nothing from L-DATA's perspective**".
    Relay,
    /// An L-DATA datagram inside a QUIC DATAGRAM frame (RFC 9221) to :443, for
    /// UDP-blocked or DPI-hostile networks. "**Traffic-shape and port camouflage
    /// only.**"
    Quic,
}

impl TransportMode {
    /// What this carriage contributes to L-DATA's security. **Nothing, always.**
    ///
    /// A function rather than a comment, so a future carriage that claimed
    /// otherwise would have to change this and fail a test. §7.7 is emphatic
    /// about the one that comes closest: `T-QUIC` "is camouflage, not
    /// steganography, and MUST NOT be described to users as making TwinVPN
    /// undetectable".
    #[must_use]
    pub const fn contributes_to_l_data_security(self) -> bool {
        false
    }

    /// Whether switching **to** this mode may re-run the handshake. Never.
    #[must_use]
    pub const fn requires_handshake(self) -> bool {
        false
    }
}

/// A snapshot of the L-DATA state a transport switch must not disturb.
///
/// Taken before the switch and compared after it, so the composition rule is
/// **measured** rather than intended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecuritySnapshot {
    /// The key generation.
    pub key_generation: u64,
    /// The send counter's issued count.
    pub send_counter: u64,
    /// The replay window's highest accepted counter.
    pub replay_highest: u64,
    /// The tunnel's identity.
    pub tunnel_id: twinvpn_types::TunnelId,
}

impl SecuritySnapshot {
    /// Whether nothing L-DATA cares about changed.
    #[must_use]
    pub fn unchanged_from(&self, before: &SecuritySnapshot) -> bool {
        self == before
    }
}

/// `docs/reliability.md` §6.5's contract, for the transport-change column.
///
/// A relay failover is a transport change: "`WAN_DIRECT → MIGRATING → RELAYED`
/// and back is a **datagram-routing change**. The `Session`, its keys, its
/// counters, and its replay window all persist. This eliminates the 'relay
/// failover drops the tunnel' failure class **by construction**."
#[must_use]
pub const fn transport_change_costs_a_handshake() -> bool {
    false
}
