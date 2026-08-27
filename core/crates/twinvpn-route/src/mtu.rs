//! MTU: the 1280 floor, `networking.md` §6.1's overhead table, DPLPMTUD, ICMP
//! validation, and MSS clamping.
//!
//! **Authority:** `docs/networking.md` §6.1–§6.5, ADR-0001 §7.2 (the 32-byte
//! tunnel overhead), ADR-0005 §9.1 (the 16-byte `RelayFrame` header),
//! `docs/reliability.md` §5.4 (effective MTU below 1280 is a quality violation),
//! §7.3 ("PMTU is re-probed on every migration").
//!
//! # Never classic PMTUD
//!
//! §6.2: "Classic PMTUD … depends on receiving ICMP 'Fragmentation Needed' …
//! and those are filtered by a large fraction of real networks. DPLPMTUD
//! requires no ICMP at all. ICMP PTB, when it arrives, is treated as a *hint
//! that triggers an immediate downward probe*, never as an authoritative
//! instruction."
//!
//! [`Dplpmtud::observe_icmp_ptb`] therefore returns a **hint**, and there is no
//! API that sets the MTU from an ICMP message.

use twinvpn_types::AddressFamily;

use crate::plan::MTU_FLOOR;

/// The tunnel's fixed overhead: 16 B data header + 16 B AEAD tag (ADR-0001 §7.2).
pub const TUNNEL_OVERHEAD: u32 = 32;
/// The `RelayFrame` header (ADR-0005 §9.1).
pub const RELAY_FRAME_OVERHEAD: u32 = 16;

/// How a path is carried, for overhead accounting (`networking.md` §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Carriage {
    /// Direct UDP.
    Direct,
    /// Relayed over UDP (`R-UDP`).
    RelayUdp,
    /// Relayed over QUIC (`R-QUIC`), the UDP:443 rung.
    RelayQuic,
    /// Relayed over TLS (`R-TLS`), the last rung on UDP-blocked networks.
    RelayTls,
    /// Relayed over TLS with TCP timestamps, which cost 12 more bytes.
    RelayTlsTimestamps,
}

impl Carriage {
    /// Bytes of outer framing below the tunnel header, for `family`.
    #[must_use]
    pub const fn outer_overhead(self, family: AddressFamily) -> u32 {
        // IP header, then transport, then any record framing.
        let ip = match family {
            AddressFamily::V4 => 20,
            AddressFamily::V6 => 40,
        };
        match self {
            Carriage::Direct => ip + 8,
            Carriage::RelayUdp => ip + 8 + RELAY_FRAME_OVERHEAD,
            Carriage::RelayQuic => ip + 8 + 28 + RELAY_FRAME_OVERHEAD,
            Carriage::RelayTls => ip + 20 + 24 + RELAY_FRAME_OVERHEAD,
            Carriage::RelayTlsTimestamps => ip + 20 + 24 + 12 + RELAY_FRAME_OVERHEAD,
        }
    }

    /// Total overhead, including the tunnel's own 32 bytes.
    #[must_use]
    pub const fn total_overhead(self, family: AddressFamily) -> u32 {
        self.outer_overhead(family) + TUNNEL_OVERHEAD
    }

    /// The **ceiling** overlay MTU for an underlay of `link_mtu`.
    ///
    /// §6.1: "These are ceilings. The operative MTU is whatever DPLPMTUD
    /// confirms; the 1280 floor always holds."
    #[must_use]
    pub const fn overlay_ceiling(self, family: AddressFamily, link_mtu: u32) -> u32 {
        link_mtu.saturating_sub(self.total_overhead(family))
    }

    /// Whether this carriage can carry a 1280-byte overlay packet over
    /// `link_mtu`.
    ///
    /// §6.1: "A carriage that cannot carry a 1280-byte overlay packet MUST be
    /// abandoned."
    #[must_use]
    pub const fn clears_floor(self, family: AddressFamily, link_mtu: u32) -> bool {
        self.overlay_ceiling(family, link_mtu) >= MTU_FLOOR
    }
}

/// What a probe outcome tells the search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The probe was **acknowledged**. §6.2: success is inferred from an
    /// acknowledgement, never from the absence of an ICMP error.
    Acknowledged,
    /// The probe went unanswered.
    Lost,
}

/// §6.2's DPLPMTUD search: binary search between the confirmed floor and the
/// candidate ceiling, four probes per step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dplpmtud {
    confirmed: u32,
    ceiling: u32,
    probing: Option<u32>,
    probes_sent: u8,
    probes_lost: u8,
    blackhole_suspected: bool,
}

/// Probes per step (§6.2).
pub const PROBES_PER_STEP: u8 = 4;

impl Dplpmtud {
    /// Starts at the floor, which is "always correct, which means bring-up never
    /// has to wait for discovery — no stall".
    #[must_use]
    pub const fn new(ceiling: u32) -> Self {
        Self {
            confirmed: MTU_FLOOR,
            ceiling: if ceiling < MTU_FLOOR { MTU_FLOOR } else { ceiling },
            probing: None,
            probes_sent: 0,
            probes_lost: 0,
            blackhole_suspected: false,
        }
    }

    /// The MTU to program on the overlay interface right now.
    #[must_use]
    pub const fn effective(self) -> u32 {
        self.confirmed
    }

    /// Whether a black hole is suspected (`NET.MTU_BLACKHOLE_DETECTED`).
    #[must_use]
    pub const fn blackhole_suspected(self) -> bool {
        self.blackhole_suspected
    }

    /// The next probe size, or `None` when the search has converged.
    #[must_use]
    pub fn next_probe(&mut self) -> Option<u32> {
        if let Some(p) = self.probing {
            return Some(p);
        }
        if self.confirmed >= self.ceiling {
            return None;
        }
        let mid = self.confirmed + (self.ceiling - self.confirmed).div_ceil(2);
        self.probing = Some(mid);
        self.probes_sent = 0;
        self.probes_lost = 0;
        Some(mid)
    }

    /// Records one probe result.
    pub fn observe(&mut self, outcome: ProbeOutcome) {
        let Some(size) = self.probing else { return };
        self.probes_sent = self.probes_sent.saturating_add(1);
        match outcome {
            ProbeOutcome::Acknowledged => {
                self.confirmed = size;
                self.probing = None;
                self.blackhole_suspected = false;
            }
            ProbeOutcome::Lost => {
                self.probes_lost = self.probes_lost.saturating_add(1);
                if self.probes_lost >= PROBES_PER_STEP {
                    // The step failed: lower the ceiling and try again. Losing
                    // every probe at a size the ceiling said should work is what
                    // a black hole looks like from here.
                    self.ceiling = size.saturating_sub(1).max(self.confirmed);
                    self.probing = None;
                    if size > self.confirmed + 1 {
                        self.blackhole_suspected = true;
                    }
                }
            }
        }
    }

    /// §6.3: an ICMP PTB is a **hint**, and only after the quoted inner header
    /// has been validated against our send history.
    ///
    /// Returns the size to start a downward search from, or `None` when the
    /// message must be discarded. A PTB below the floor is never accepted:
    /// "Never accept a PTB below 1280."
    #[must_use]
    pub fn observe_icmp_ptb(&mut self, reported_mtu: u32, quote_validated: bool) -> Option<u32> {
        if !quote_validated {
            // §6.3: "Unvalidated / unquoted ICMP | Discarded. Blind PTB is a
            // known off-path attack."
            return None;
        }
        if reported_mtu < MTU_FLOOR {
            return None;
        }
        if reported_mtu >= self.confirmed {
            return None;
        }
        self.ceiling = reported_mtu;
        self.confirmed = MTU_FLOOR;
        self.probing = None;
        Some(reported_mtu)
    }

    /// §7.3: "PMTU is re-probed on every migration."
    pub fn reset_for_new_path(&mut self, ceiling: u32) {
        *self = Dplpmtud::new(ceiling);
    }
}

/// §6.4's TCP MSS clamp, applied at every forwarding point in both directions.
#[must_use]
pub const fn mss_clamp(path_mtu: u32, family: AddressFamily) -> u32 {
    let headroom = match family {
        AddressFamily::V4 => 40,
        AddressFamily::V6 => 60,
    };
    path_mtu.saturating_sub(headroom)
}

/// §6.5: TwinVPN never fragments overlay IPv6, and always sets DF on the
/// underlay.
///
/// A function rather than a comment so the rule is greppable and testable: an
/// implementation that wants to fragment has to change this and fail its test.
#[must_use]
pub const fn may_fragment(_family: AddressFamily) -> bool {
    false
}
