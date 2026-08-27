//! Authenticated path validation — and the crypto boundary this crate does not
//! cross.
//!
//! **Authority:** `docs/networking.md` §3.4 and §4.3, `docs/reliability.md` §7.3
//! (the hysteresis rule), §7.4's guard table; ADR-0004 §11 ("authenticated under
//! ADR-0001's primitives. **No new cryptographic primitive** (I2)");
//! ADR-0018 CD-I2.
//!
//! # This crate implements no cryptography
//!
//! CD-I2 restricts cryptographic dependencies to `twinvpn-crypto`, and ADR-0004
//! is explicit that the disco probe introduces no new primitive. So
//! [`DiscoAuth`] is a **trait**: the probe's authentication is a seal-and-open
//! over ADR-0001's transport keys, supplied by `twinvpn-crypto`, and this module
//! only decides *when* a path is validated and *what that authorises*.
//!
//! **Integration item.** `twinvpn-crypto` supplies the two operations
//! [`DiscoAuth`] declares.
//!
//! # Why validation is not a reachability check
//!
//! §7.3's hysteresis rule, clause 1: `PATH_VALIDATED` is "an authenticated
//! end-to-end challenge-response, **not** a reachability check. This is what
//! rejects captive-portal Wi-Fi, which looks perfectly usable to the OS and is
//! not."

use core::time::Duration;

use twinvpn_env::MonotonicInstant;

/// The authenticated disco probe's seal/open, supplied by `twinvpn-crypto`.
///
/// The probe is multiplexed on the tunnel's own UDP socket and distinguished by
/// a leading type byte "that cannot collide with the tunnel protocol's message
/// types" (`networking.md` §3.4), so the type byte is the caller's and the
/// authentication is this trait's.
pub trait DiscoAuth: Send + Sync {
    /// Seals a probe body for the peer, authenticating it under the `Session`'s
    /// transport keys.
    ///
    /// # Errors
    ///
    /// Returns `None` when no key state exists for this peer. **Never** falls
    /// back to an unauthenticated probe: an unauthenticated `PONG` would let an
    /// off-path attacker forge liveness.
    fn seal_probe(&self, body: &[u8], out: &mut Vec<u8>) -> Option<()>;

    /// Opens a probe or response, returning the plaintext body.
    ///
    /// # Errors
    ///
    /// `None` on any authentication failure. A failed open is a **drop**, never
    /// a degraded accept.
    fn open_probe(&self, sealed: &[u8], out: &mut Vec<u8>) -> Option<()>;
}

/// `PATH_VALIDATED`'s definition, from `networking.md` §4.3 and §7.4.
///
/// > ≥ 2 successful **authenticated** `PING`/`PONG` on the candidate pair within
/// > 500 ms of each other.
pub const VALIDATION_WINDOW: Duration = Duration::from_millis(500);
/// How many authenticated exchanges validation needs.
pub const VALIDATION_EXCHANGES: u32 = 2;

/// Tracks one candidate pair's progress toward `PATH_VALIDATED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Validation {
    last_success: Option<MonotonicInstant>,
    consecutive: u32,
    validated_at: Option<MonotonicInstant>,
}

impl Validation {
    /// A pair with no evidence yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last_success: None,
            consecutive: 0,
            validated_at: None,
        }
    }

    /// Records an **authenticated** exchange. The caller has already opened the
    /// response through [`DiscoAuth`]; an unauthenticated one never reaches here.
    pub fn observe_authenticated_exchange(&mut self, at: MonotonicInstant) {
        match self.last_success {
            Some(prev) if at.duration_since(prev) <= VALIDATION_WINDOW => {
                self.consecutive = self.consecutive.saturating_add(1);
            }
            // Too far apart: the pair starts counting again. Two exchanges an
            // hour apart are not evidence of a live path.
            _ => self.consecutive = 1,
        }
        self.last_success = Some(at);
        if self.consecutive >= VALIDATION_EXCHANGES && self.validated_at.is_none() {
            self.validated_at = Some(at);
        }
    }

    /// Records a failed or unanswered exchange.
    pub fn observe_failure(&mut self) {
        self.consecutive = 0;
    }

    /// Whether the pair is validated.
    #[must_use]
    pub const fn is_validated(&self) -> bool {
        self.validated_at.is_some()
    }

    /// When it became validated.
    #[must_use]
    pub const fn validated_at(&self) -> Option<MonotonicInstant> {
        self.validated_at
    }
}

/// §7.3's hysteresis rule: **all four** conditions, or the interface does not
/// take over traffic.
///
/// > Wi-Fi that is associated but not yet usable is the classic cause of the
/// > mid-sentence video-call freeze; conditions 1 and 3 exist specifically to
/// > refuse it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Four booleans, and each is one of §7.3's four numbered conditions. Collapsing
// them into a bitflags type would let two be satisfied by one mask, and the rule
// is that ALL FOUR must hold — the whole point of naming them separately.
#[allow(clippy::struct_excessive_bools)]
pub struct Hysteresis {
    /// 1 — `PATH_VALIDATED` on the new path.
    pub validated: bool,
    /// 2 — `PATH_BETTER`: ≥ 15 points **and** ≥ 10 ms RTT.
    pub better: bool,
    /// 3 — `PATH_STABLE`: `PATH_BETTER` held for ≥ 3 probe intervals.
    pub stable: bool,
    /// 4 — policy permits the interface. Metered-link and battery policy may
    /// require explicit consent, "which is a deliberate, **announced** pause,
    /// never a silent refusal".
    pub policy_permits: bool,
}

impl Hysteresis {
    /// Whether the new interface may take over.
    #[must_use]
    pub const fn may_take_over(self) -> bool {
        self.validated && self.better && self.stable && self.policy_permits
    }

    /// Which condition blocked the takeover, for the announced pause.
    #[must_use]
    pub const fn blocked_by(self) -> Option<&'static str> {
        if !self.validated {
            Some("PATH_VALIDATED")
        } else if !self.better {
            Some("PATH_BETTER")
        } else if !self.stable {
            Some("PATH_STABLE")
        } else if !self.policy_permits {
            Some("policy")
        } else {
            None
        }
    }
}

/// Make-before-break, as a predicate over the two paths' liveness.
///
/// §4.4's `MIGRATING` invariant: "The new path is **not committed** until it
/// passes authenticated path validation. The old path is **not released** until
/// the new one is committed, whenever the old path is still alive."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    /// Whether the incoming path has validated.
    pub new_validated: bool,
    /// Whether the outgoing path is still alive.
    pub old_alive: bool,
}

impl Migration {
    /// Whether the new path may be committed.
    #[must_use]
    pub const fn may_commit(self) -> bool {
        self.new_validated
    }

    /// Whether the old path may be released.
    #[must_use]
    pub const fn may_release_old(self) -> bool {
        // Committed, or the old one is gone anyway.
        self.new_validated || !self.old_alive
    }

    /// The traffic disposition during the window.
    ///
    /// `TUNNELED_DUAL` while both are alive; `QUEUED_BOUNDED` for at most
    /// `T_MIGRATE_QUEUE` if the old path is already gone.
    #[must_use]
    pub const fn disposition(self) -> twinvpn_types::TrafficDisposition {
        if self.old_alive {
            twinvpn_types::TrafficDisposition::TunneledDual
        } else {
            twinvpn_types::TrafficDisposition::QueuedBounded
        }
    }
}

/// A validated address change under a live `Session` is the **same peer**.
///
/// §7.3: "The peer learns the new `Endpoint` **from the validated probe itself**,
/// never from the control plane — which is why roaming works with the control
/// plane down (I5). A validated address change under a live `Session` MUST be
/// accepted as the same peer, not treated as a new one."
#[must_use]
pub const fn address_change_is_same_peer(probe_validated: bool) -> bool {
    probe_validated
}
