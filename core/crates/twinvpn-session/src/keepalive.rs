//! §6.6's keepalive policy: the adaptive NAT ladder, mandatory coalescing, and
//! the park.
//!
//! **Authority:** `docs/reliability.md` §5.2 (`T_NAT_KEEPALIVE`), §6.6, §7.1,
//! §11.1, §11.2; `docs/networking.md` §3.5; ADR-0004.
//!
//! # Two purposes, deliberately separated
//!
//! 1. **NAT binding maintenance** — required only for `WAN_DIRECT` behind NAT.
//! 2. **Liveness detection** — required for all paths, at a cadence proportional
//!    to how quickly we need to notice.
//!
//! Conflating them is what makes a sane mobile policy impossible, so
//! [`NatKeepalive`] does only the first and [`crate::liveness`] does only the
//! second.
//!
//! # The ladder reverts, it does not halve
//!
//! > on an observed `NAT.MAPPING_EXPIRED` **reverts to the last known-good rung**
//! > rather than halving — the last rung that actually worked is a measurement,
//! > and half of the current rung is a guess.

use core::time::Duration;

use crate::timers::NAT_LADDER;

/// A network's identity for the learned-lifetime cache.
///
/// §6.6: "cached **per network fingerprint** (gateway MAC + BSSID + reflexive
/// /24), so rejoining a known network starts at the right cadence immediately
/// instead of relearning it."
///
/// The three inputs are hashed by the caller — this type holds only the digest,
/// because a gateway MAC and a BSSID are `SENSITIVE` under ADR-0015 §11.4 and
/// this value is held in memory across networks.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkFingerprint([u8; 16]);

impl NetworkFingerprint {
    /// Wraps a digest the caller computed.
    #[must_use]
    pub const fn from_digest(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl core::fmt::Debug for NetworkFingerprint {
    /// Redacted: a gateway MAC and a BSSID are `SENSITIVE` under ADR-0015 §11.4,
    /// and this value is derived from both.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NetworkFingerprint(<16 B redacted>)")
    }
}

/// The adaptive NAT binding-lifetime estimator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatKeepalive {
    rung: usize,
    last_known_good: usize,
}

impl Default for NatKeepalive {
    fn default() -> Self {
        Self::new()
    }
}

impl NatKeepalive {
    /// Starts at 25 s — "the *most conservative* rung of the ladder".
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rung: 0,
            last_known_good: 0,
        }
    }

    /// Resumes at a cadence learned for this network fingerprint.
    #[must_use]
    pub fn resume_at(seconds: u64) -> Self {
        let rung = NAT_LADDER.iter().position(|&s| s == seconds).unwrap_or(0);
        Self {
            rung,
            last_known_good: rung,
        }
    }

    /// The current interval.
    #[must_use]
    pub fn interval(self) -> Duration {
        Duration::from_secs(NAT_LADDER[self.rung])
    }

    /// The current rung's index, for evidence.
    #[must_use]
    pub const fn rung(self) -> usize {
        self.rung
    }

    /// A binding survived at the current cadence: climb one rung, capped at
    /// 120 s.
    pub fn observe_binding_survived(&mut self) {
        self.last_known_good = self.rung;
        if self.rung + 1 < NAT_LADDER.len() {
            self.rung += 1;
        }
    }

    /// A mapping expired: revert to the **last known-good** rung.
    pub fn observe_mapping_expired(&mut self) {
        self.rung = self.last_known_good;
    }

    /// The learned lifetime to cache for this network fingerprint.
    #[must_use]
    pub fn learned_seconds(self) -> u64 {
        NAT_LADDER[self.last_known_good]
    }
}

/// The single periodic wake window every loop aligns to.
///
/// §6.6 and §7.1: "**Coalescing is mandatory.** All keepalives across all
/// `Session`s and the relay session are aligned to a single periodic wake
/// window. N peers must cost one radio wake, not N."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakeWindow {
    period: Duration,
}

impl WakeWindow {
    /// A window of `period`.
    #[must_use]
    pub const fn new(period: Duration) -> Self {
        Self { period }
    }

    /// The period.
    #[must_use]
    pub const fn period(self) -> Duration {
        self.period
    }

    /// Rounds a desired cadence **up** to the next multiple of the window.
    ///
    /// Up, never down: rounding down would wake the radio more often than the
    /// window, which is the cost the coalescing rule exists to avoid. Rounding a
    /// NAT cadence up past the binding lifetime is prevented by the caller
    /// clamping to [`NatKeepalive::interval`] first.
    #[must_use]
    pub fn align(self, desired: Duration) -> Duration {
        if self.period.is_zero() {
            return desired;
        }
        let p = self.period.as_micros().max(1);
        let d = desired.as_micros();
        let slots = d.div_ceil(p).max(1);
        Duration::from_micros(u64::try_from(slots * p).unwrap_or(u64::MAX))
    }
}

/// Whether a keepalive is needed at all right now.
///
/// §6.6: "**Data suppresses keepalives.** Any authenticated packet resets the
/// timer. An active tunnel never sends a keepalive."
#[must_use]
pub fn keepalive_due(since_last_authenticated_packet: Duration, interval: Duration) -> bool {
    since_last_authenticated_packet >= interval
}
