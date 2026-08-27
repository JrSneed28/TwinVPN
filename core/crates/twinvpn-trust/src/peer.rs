//! `TrustedPeer`: the binding gate, the monotone generation floors, and
//! N-27's freshness ladder.
//!
//! **Authority:** ADR-0007 N-4, N-19, N-22, N-23, N-27; `contracts/proto/twinvpn/v1/peer.proto`;
//! ADR-0009 §11.5; state row S-05.
//!
//! # N-19's record, and what is deliberately absent
//!
//! > "On completion both devices MUST durably write a `TrustedPeer` containing
//! > peer `device_id`, `ik_pub`, `tk_pub`, the verified `TunnelKeyBinding`,
//! > `PairSecret`, the pinned anchor and delegation chain, and the current
//! > `EpochSeed`. **`PairSecret` MUST NOT be transmitted, backed up, or
//! > replicated.**"
//!
//! [`TrustedPeer`] holds the public half. The `PairSecret` and `EpochSeed` are
//! **not** fields here: they are secret-bearing records in the store's `peer/`
//! and `trust/` namespaces, reached by key, so a `TrustedPeer` cannot reach a
//! log, a diagnostic bundle, or a `GetPeersResp` carrying one. `peer.proto` draws
//! the same line and says why: "This message is the TRANSMISSIBLE projection of
//! that record … and is deliberately a strict subset."
//!
//! # N-4, and why `tk` has no setter
//!
//! > "A peer MUST verify `TunnelKeyBinding` … **before writing TK into
//! > `TrustedPeer`**. This check MUST NOT be skippable by configuration."
//!
//! [`TrustedPeer::tk`] returns a [`twinvpn_crypto::VerifiedTunnelKey`], which has
//! no public constructor, and [`TrustedPeer::admit_tunnel_key`] is the only way
//! to install one. There is no `set_tk`, no `tk_from_bytes`, and no
//! configuration flag. A caller holding raw bytes cannot construct a
//! `TrustedPeer` at all.

use twinvpn_crypto::VerifiedTunnelKey;
use twinvpn_env::ElapsedInstant;

use crate::error::{Result, TrustError};

/// `T_TRUST_REFRESH` — 6 h (N-27).
pub const T_TRUST_REFRESH_SECS: u64 = 6 * 3600;
/// `T_TRUST_STALE` — 24 h (N-27).
pub const T_TRUST_STALE_SECS: u64 = 24 * 3600;
/// `T_TRUST_HARD` — 30 d, Owner-configurable within `[24 h, 90 d]` (N-27).
pub const T_TRUST_HARD_DEFAULT_SECS: u64 = 30 * 24 * 3600;
/// The lower bound of the Owner-configurable `T_TRUST_HARD` range.
pub const T_TRUST_HARD_MIN_SECS: u64 = 24 * 3600;
/// The upper bound of the Owner-configurable `T_TRUST_HARD` range.
pub const T_TRUST_HARD_MAX_SECS: u64 = 90 * 24 * 3600;

/// `T_IK_OVERLAP` — 30 d (N-23).
pub const T_IK_OVERLAP_SECS: u64 = 30 * 24 * 3600;
/// `T_TK_OVERLAP` — 14 d (N-23).
pub const T_TK_OVERLAP_SECS: u64 = 14 * 24 * 3600;

/// The locally derived degree of trust (`peer.proto`'s `PeerTrust`).
///
/// "This is a computed view, never a transmitted authority: a peer does not tell
/// you how much you trust it."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTrust {
    /// Confirmed pairing, verified binding, refreshed within `T_TRUST_REFRESH`.
    Trusted,
    /// No refresh for `T_TRUST_STALE`. The `Session` goes `DEGRADED`;
    /// connectivity continues.
    Stale,
    /// No refresh for `T_TRUST_HARD`. Every **granted** authority is suspended.
    Expired,
    /// An Owner-signed revocation has verified. **Terminal.**
    Revoked,
}

impl PeerTrust {
    /// Whether a **new handshake** to an already-known peer is permitted.
    ///
    /// N-27 is emphatic: expiry "MUST **NOT** refuse a new handshake to an
    /// already-known `TrustedPeer` (**R-11**), and established `Session`s MUST
    /// continue (**I5**). **Expiry withdraws grants; it does not withdraw
    /// identity.**"
    ///
    /// So only [`PeerTrust::Revoked`] refuses.
    #[must_use]
    pub const fn permits_handshake(self) -> bool {
        !matches!(self, PeerTrust::Revoked)
    }

    /// Whether **granted** authority — `ExitNode` use, `LANGateway` access,
    /// route acceptance, new pairing — is available.
    #[must_use]
    pub const fn permits_granted_authority(self) -> bool {
        matches!(self, PeerTrust::Trusted | PeerTrust::Stale)
    }

    /// Whether an established `Session` must be torn down.
    ///
    /// Only revocation, and even then the teardown is the caller's: I5 protects
    /// a session from *staleness*, not from a revoked peer.
    #[must_use]
    pub const fn requires_teardown(self) -> bool {
        matches!(self, PeerTrust::Revoked)
    }

    /// The `reason_code` this state surfaces, if any.
    #[must_use]
    pub const fn reason_code(self) -> Option<twinvpn_types::ReasonCode> {
        match self {
            PeerTrust::Trusted => None,
            PeerTrust::Stale => Some(twinvpn_types::codes::AUTH_TRUST_STATE_STALE),
            PeerTrust::Expired => Some(twinvpn_types::codes::AUTH_TRUST_STATE_EXPIRED),
            PeerTrust::Revoked => Some(twinvpn_types::codes::AUTH_DEVICE_REVOKED),
        }
    }
}

/// The Owner-configurable hard-expiry window (N-27).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardExpiry(u64);

impl Default for HardExpiry {
    fn default() -> Self {
        Self(T_TRUST_HARD_DEFAULT_SECS)
    }
}

impl HardExpiry {
    /// Sets the window, clamping into N-27's `[24 h, 90 d]` range.
    ///
    /// Clamped rather than rejected because this is an Owner preference, and a
    /// value outside the range is a UI defect rather than an attack — but it is
    /// clamped, not accepted, so no configuration can push the window past 90
    /// days or below a day.
    #[must_use]
    pub fn new(secs: u64) -> Self {
        Self(secs.clamp(T_TRUST_HARD_MIN_SECS, T_TRUST_HARD_MAX_SECS))
    }

    /// The window in seconds.
    #[must_use]
    pub const fn secs(self) -> u64 {
        self.0
    }
}

/// The local view of a paired peer (S-05, `LOCAL`, no remote replica).
#[derive(Debug, Clone)]
pub struct TrustedPeer {
    device_id: [u8; 32],
    identity_id: [u8; 32],
    label: String,
    tk: VerifiedTunnelKey,
    highest_generation_seen: u64,
    highest_tk_generation_seen: u64,
    last_refreshed: Option<ElapsedInstant>,
    revoked: bool,
}

impl TrustedPeer {
    /// Creates a record. **Requires a verified tunnel key**, which is N-4's
    /// non-skippable check expressed as a constructor signature.
    #[must_use]
    pub fn new(
        device_id: [u8; 32],
        identity_id: [u8; 32],
        label: String,
        tk: VerifiedTunnelKey,
        generation: u64,
    ) -> Self {
        let tk_generation = tk.tk_generation();
        Self {
            device_id,
            identity_id,
            label,
            tk,
            highest_generation_seen: generation,
            highest_tk_generation_seen: tk_generation,
            last_refreshed: None,
            revoked: false,
        }
    }

    /// The peer's permanent name.
    #[must_use]
    pub const fn device_id(&self) -> &[u8; 32] {
        &self.device_id
    }

    /// The current generation's identity.
    #[must_use]
    pub const fn identity_id(&self) -> &[u8; 32] {
        &self.identity_id
    }

    /// The Owner-chosen label. ADR-0014 N-27 requires diagnostics to name a peer
    /// by this, not by a hex id.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The verified tunnel key. There is no other accessor and no setter.
    #[must_use]
    pub const fn tk(&self) -> &VerifiedTunnelKey {
        &self.tk
    }

    /// `highest_generation_seen` (N-22).
    #[must_use]
    pub const fn highest_generation_seen(&self) -> u64 {
        self.highest_generation_seen
    }

    /// `highest_tk_generation_seen` (N-22).
    #[must_use]
    pub const fn highest_tk_generation_seen(&self) -> u64 {
        self.highest_tk_generation_seen
    }

    /// Installs a newly verified tunnel key, enforcing N-22's monotone floor.
    ///
    /// > "Peers MUST store `highest_generation_seen` and
    /// > `highest_tk_generation_seen` per `device_id` and MUST reject any
    /// > statement **at or below** the stored value."
    ///
    /// "At or below" is why the comparison is `<=` and not `<`: re-presenting
    /// the current generation is how a replayed binding would slip through.
    ///
    /// # Errors
    ///
    /// [`TrustError::TrustEpochRollback`], and
    /// [`TrustError::BindingInvalid`] if the binding names a different device.
    pub fn admit_tunnel_key(&mut self, tk: VerifiedTunnelKey) -> Result<()> {
        if tk.device_id() != &self.device_id {
            return Err(TrustError::BindingInvalid {
                step: "binding names a different device",
            });
        }
        if tk.tk_generation() <= self.highest_tk_generation_seen {
            return Err(TrustError::TrustEpochRollback {
                offered: tk.tk_generation(),
                high_water: self.highest_tk_generation_seen,
            });
        }
        self.highest_tk_generation_seen = tk.tk_generation();
        self.identity_id = *tk.identity_id();
        self.tk = tk;
        Ok(())
    }

    /// Records an identity-key rotation, enforcing N-22.
    ///
    /// # Errors
    ///
    /// [`TrustError::TrustEpochRollback`].
    pub fn admit_generation(&mut self, generation: u64, identity_id: [u8; 32]) -> Result<()> {
        if generation <= self.highest_generation_seen {
            return Err(TrustError::TrustEpochRollback {
                offered: generation,
                high_water: self.highest_generation_seen,
            });
        }
        self.highest_generation_seen = generation;
        self.identity_id = identity_id;
        Ok(())
    }

    /// Records a successful trust refresh.
    ///
    /// Takes an [`ElapsedInstant`] — the **suspend-inclusive** clock — because
    /// N-27's windows are hours and days, and a device that slept for a week
    /// must see a week pass. Using the monotonic clock here would let a laptop
    /// stay `Trusted` indefinitely by being closed.
    pub fn mark_refreshed(&mut self, at: ElapsedInstant) {
        self.last_refreshed = Some(at);
    }

    /// Marks the peer revoked. **Terminal**, and there is no inverse.
    pub fn mark_revoked(&mut self) {
        self.revoked = true;
    }

    /// N-27's freshness ladder.
    ///
    /// `now` is the suspend-inclusive reading; `since` is how long ago the last
    /// refresh was, computed by the caller from its `Env`.
    #[must_use]
    pub fn trust(&self, elapsed_since_refresh_secs: Option<u64>, hard: HardExpiry) -> PeerTrust {
        if self.revoked {
            return PeerTrust::Revoked;
        }
        let Some(age) = elapsed_since_refresh_secs else {
            // Never refreshed. That is not "expired" — a freshly paired peer has
            // no refresh yet and is fully trusted; the caller marks it refreshed
            // at pairing. Treating "never" as expired would make every new
            // pairing start with its grants suspended.
            return PeerTrust::Trusted;
        };
        if age >= hard.secs() {
            PeerTrust::Expired
        } else if age >= T_TRUST_STALE_SECS {
            PeerTrust::Stale
        } else {
            PeerTrust::Trusted
        }
    }

    /// Whether a refresh is due (`T_TRUST_REFRESH`).
    #[must_use]
    pub const fn refresh_due(elapsed_since_refresh_secs: u64) -> bool {
        elapsed_since_refresh_secs >= T_TRUST_REFRESH_SECS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::verified_tunnel_key;

    const PEER: [u8; 32] = [0x02; 32];
    const IDENTITY: [u8; 32] = [0x12; 32];

    fn peer() -> TrustedPeer {
        TrustedPeer::new(
            PEER,
            IDENTITY,
            "Study PC".to_owned(),
            verified_tunnel_key(&[0x33; 32], 1),
            0,
        )
    }

    /// N-27's ladder, at each boundary.
    #[test]
    fn the_freshness_ladder_matches_n_27s_thresholds() {
        let p = peer();
        let hard = HardExpiry::default();
        assert_eq!(p.trust(Some(0), hard), PeerTrust::Trusted);
        assert_eq!(
            p.trust(Some(T_TRUST_STALE_SECS - 1), hard),
            PeerTrust::Trusted
        );
        assert_eq!(p.trust(Some(T_TRUST_STALE_SECS), hard), PeerTrust::Stale);
        assert_eq!(
            p.trust(Some(T_TRUST_HARD_DEFAULT_SECS - 1), hard),
            PeerTrust::Stale
        );
        assert_eq!(
            p.trust(Some(T_TRUST_HARD_DEFAULT_SECS), hard),
            PeerTrust::Expired
        );
        assert!(TrustedPeer::refresh_due(T_TRUST_REFRESH_SECS));
        assert!(!TrustedPeer::refresh_due(T_TRUST_REFRESH_SECS - 1));
    }

    /// **The subtle N-27 rule.** Expiry withdraws grants; it does **not**
    /// withdraw identity. A handshake to a known peer must still be permitted,
    /// and an established session must not be torn down.
    #[test]
    fn expiry_withdraws_grants_but_never_identity() {
        assert!(PeerTrust::Expired.permits_handshake(), "R-11");
        assert!(!PeerTrust::Expired.requires_teardown(), "I5");
        assert!(!PeerTrust::Expired.permits_granted_authority());
        // Stale keeps connectivity and grants; only the session goes DEGRADED.
        assert!(PeerTrust::Stale.permits_handshake());
        assert!(PeerTrust::Stale.permits_granted_authority());
        assert_eq!(
            PeerTrust::Stale
                .reason_code()
                .map(twinvpn_types::ReasonCode::as_str),
            Some("AUTH.TRUST_STATE_STALE")
        );
        assert_eq!(
            PeerTrust::Expired
                .reason_code()
                .map(twinvpn_types::ReasonCode::as_str),
            Some("AUTH.TRUST_STATE_EXPIRED")
        );
    }

    /// Revocation is the one state that refuses a handshake and requires a
    /// teardown.
    #[test]
    fn revocation_is_terminal_and_refuses_the_handshake() {
        let mut p = peer();
        p.mark_revoked();
        assert_eq!(p.trust(Some(0), HardExpiry::default()), PeerTrust::Revoked);
        assert!(!PeerTrust::Revoked.permits_handshake());
        assert!(PeerTrust::Revoked.requires_teardown());
        assert!(!PeerTrust::Revoked.permits_granted_authority());
    }

    /// A freshly paired peer has never refreshed and must not start expired.
    #[test]
    fn a_never_refreshed_peer_is_trusted_rather_than_expired() {
        assert_eq!(
            peer().trust(None, HardExpiry::default()),
            PeerTrust::Trusted
        );
    }

    /// **Attack test — N-22.** A binding at or below the stored
    /// `tk_generation` is rejected. "At or below" catches the replay of the
    /// current one, which a `<` comparison would admit.
    #[test]
    fn a_tk_generation_at_or_below_the_floor_is_rejected() {
        let mut p = peer();
        assert_eq!(p.highest_tk_generation_seen(), 1);
        assert!(
            p.admit_tunnel_key(verified_tunnel_key(&[0x44; 32], 1))
                .is_err(),
            "re-presenting the current generation must be rejected"
        );
        assert!(p
            .admit_tunnel_key(verified_tunnel_key(&[0x44; 32], 0))
            .is_err());
        assert_eq!(
            p.tk().tk_pub(),
            &[0x33; 32],
            "a rejected binding must not have been installed"
        );
        // A genuine rotation is accepted.
        p.admit_tunnel_key(verified_tunnel_key(&[0x44; 32], 2))
            .expect("rotation");
        assert_eq!(p.tk().tk_pub(), &[0x44; 32]);
        assert_eq!(p.highest_tk_generation_seen(), 2);
    }

    /// **Attack test.** A binding for a *different* device must not be
    /// installed into this peer's record, however valid it is on its own.
    #[test]
    fn a_binding_for_another_device_is_refused() {
        let mut p = peer();
        let other = crate::testkit::verified_tunnel_key_for(&[0x99; 32], &[0x88; 32], 9);
        assert!(matches!(
            p.admit_tunnel_key(other),
            Err(TrustError::BindingInvalid { .. })
        ));
    }

    /// **Attack test — N-22 for the identity generation.**
    #[test]
    fn an_identity_generation_at_or_below_the_floor_is_rejected() {
        let mut p = peer();
        assert!(p.admit_generation(0, [0x77; 32]).is_err());
        p.admit_generation(1, [0x77; 32]).expect("rotation");
        assert!(p.admit_generation(1, [0x66; 32]).is_err());
        assert_eq!(p.identity_id(), &[0x77; 32]);
    }

    /// N-27's Owner-configurable window is clamped, so no configuration can
    /// push it past 90 days or below a day.
    #[test]
    fn the_hard_expiry_window_is_clamped_to_n_27s_range() {
        assert_eq!(HardExpiry::new(0).secs(), T_TRUST_HARD_MIN_SECS);
        assert_eq!(HardExpiry::new(u64::MAX).secs(), T_TRUST_HARD_MAX_SECS);
        assert_eq!(
            HardExpiry::new(T_TRUST_HARD_DEFAULT_SECS).secs(),
            T_TRUST_HARD_DEFAULT_SECS
        );
    }

    /// N-19's secret fields are not on this type. This test states the
    /// property: a `Debug` of a `TrustedPeer` cannot leak a `PairSecret`,
    /// because there is no field to leak.
    #[test]
    fn the_record_carries_no_secret_material() {
        let rendered = format!("{:?}", peer());
        assert!(rendered.contains("Study PC"));
        assert!(!rendered.to_lowercase().contains("pairsecret"));
        assert!(!rendered.to_lowercase().contains("epochseed"));
    }
}
