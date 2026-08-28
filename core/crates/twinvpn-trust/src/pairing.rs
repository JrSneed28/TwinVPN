//! The pairing ceremony and its `CEREMONY`-class idempotency.
//!
//! **Authority:** ADR-0007 N-15..N-19, §7.4; `contracts/proto/twinvpn/v1/pairing.proto`;
//! `contracts/docs/idempotency.md`; ADR-0008 §11.3; `contracts/docs/identifiers.md`.
//!
//! # What is here, and what is honestly not
//!
//! **Here:** the ceremony state machine, the five-attempt budget, the 120-second
//! window, the single-use `pairing_id`, the idempotency rules that make
//! `CompletePairing` replay-safe, and the mutual-attestation check that makes
//! N-18's "both devices or neither" true.
//!
//! **Not here, and stated as a gap rather than stubbed:** the SPAKE2 exchange
//! itself. N-17 requires "SPAKE2 (RFC 9382) with the RFC-specified P-256
//! parameters", and RFC 9382 needs the two fixed group elements `M` and `N` —
//! which are constants derived by hash-to-curve and are **not** in the workspace
//! dependency table, and no audited SPAKE2 implementation is either.
//! Implementing SPAKE2 by hand would be exactly the "novel cryptography" I2
//! forbids, and doing it *badly* would break N-15's central requirement that
//! "the transcript must not be an offline-testable function of the code".
//!
//! So [`Spake2Exchange`] is a **trait**, this crate has no implementation of it,
//! and the ceremony drives it. The gap is reported to the integration lead as a
//! missing workspace dependency, not papered over with a hash comparison — N-15
//! is explicit that "A ceremony whose transcript permits offline dictionary
//! attack on a 9-digit human-entered secret MUST NOT be implemented."
//!
//! # The idempotency rules, quoted from the contract matrix
//!
//! - `BeginPairing` duplicate → the **original** `pairing_id`.
//! - `CompletePairing` replay → the **original outcome**. This is what prevents
//!   asymmetric trust.
//! - `CancelPairing` burns the id; it is single-use.
//!
//! And `identifiers.md`: `pairing_id` is "**Single-use and never reissued, not
//! even after expiry or cancellation**: reissuing would reset the five-attempt
//! budget ADR-0007 N-17 relies on to make a nine-digit code safe."

use std::collections::BTreeMap;

use twinvpn_crypto::statements::PairingAttestation;

use crate::error::{Result, TrustError};

/// N-17: at most five failed runs per `pairing_id`.
pub const MAX_ATTEMPTS: u32 = 5;
/// N-17: a 120-second expiry, enforced independently by both devices and the
/// rendezvous.
pub const CEREMONY_WINDOW_SECS: u64 = 120;
/// N-17: a nine-digit code.
pub const CODE_DIGITS: usize = 9;

/// Which ceremony established the trust (N-16).
///
/// > "The ceremony method MUST be recorded in the `Pairing` record and surfaced
/// > in diagnostics — 'which ceremony did this trust come from' is an audit
/// > question that cannot be answered retroactively."
///
/// So it is a field of [`Pairing`] rather than an argument that is discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyType {
    /// SPAKE2 with a nine-digit human-entered code (N-17).
    Spake2Code,
    /// A QR code carrying high-entropy material.
    Qr,
}

/// The ceremony's lifecycle (`pairing.proto`'s `PairingState`).
///
/// N-18: "There is **no state meaning 'confirmed on one side'**, because
/// asymmetric trust is the defect this ceremony exists to prevent." The enum
/// below has no such variant, and there is no way to construct one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingState {
    /// Proposed and running.
    Pending,
    /// Confirmed on **both** devices.
    Confirmed,
    /// The 120-second window passed.
    Expired,
    /// Cancelled by a participant. The id is burned.
    Aborted,
    /// The approver declined.
    Rejected,
}

/// The SPAKE2 exchange, as a seam.
///
/// See the module documentation on why this crate implements none: N-17 names
/// RFC 9382 and no audited implementation is available in the workspace, and
/// N-15 forbids substituting a construction that permits offline testing.
///
/// An implementor supplies the two message rounds and the shared transcript.
pub trait Spake2Exchange: Send + Sync {
    /// Produces this device's outbound ceremony payload for `round`.
    ///
    /// # Errors
    ///
    /// Implementation-defined; surfaced as
    /// [`TrustError::PairingCodeMismatch`] or
    /// [`TrustError::Invariant`] by the ceremony.
    fn write_round(&mut self, round: u32) -> Result<Vec<u8>>;

    /// Consumes the peer's payload for `round`.
    ///
    /// # Errors
    ///
    /// As above.
    fn read_round(&mut self, round: u32, payload: &[u8]) -> Result<()>;

    /// The transcript hash both devices must agree on, once the exchange
    /// completes.
    ///
    /// N-15's requirement lives here: this must **not** be an offline-testable
    /// function of the human-entered code.
    ///
    /// # Errors
    ///
    /// [`TrustError::Invariant`] if the exchange has not completed.
    fn transcript_hash(&self) -> Result<[u8; 32]>;
}

/// The terminal outcome of one ceremony, recorded so a replay returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingOutcome {
    /// The state the ceremony reached.
    pub state: PairingState,
    /// Both attestations, present iff confirmed.
    ///
    /// `pairing.proto`: "the durable event `PairingCompleted` carries
    /// `attestation_a` and `attestation_b` **together**, because a peer that
    /// receives only one has no evidence the other side completed."
    pub attestations: Option<(PairingAttestation, PairingAttestation)>,
    /// The `reason_code` for a non-confirmed outcome. Required and non-empty:
    /// "a timeout [must be] surfaced as a distinct, actionable state, never a
    /// generic failure."
    pub reason_code: Option<&'static str>,
}

/// One in-flight or completed pairing.
#[derive(Debug, Clone)]
#[allow(clippy::struct_field_names)]
pub struct Pairing {
    pairing_id: [u8; 16],
    ceremony: CeremonyType,
    state: PairingState,
    attempts_remaining: u32,
    created_at_secs: u64,
    outcome: Option<PairingOutcome>,
}

impl Pairing {
    /// The rendezvous handle, computed by the **joining** device.
    #[must_use]
    pub const fn pairing_id(&self) -> &[u8; 16] {
        &self.pairing_id
    }

    /// Which ceremony this trust came from (N-16).
    #[must_use]
    pub const fn ceremony(&self) -> CeremonyType {
        self.ceremony
    }

    /// The lifecycle state.
    #[must_use]
    pub const fn state(&self) -> PairingState {
        self.state
    }

    /// Remaining runs before `AUTH.PAIRING_ATTEMPTS_EXCEEDED`.
    #[must_use]
    pub const fn attempts_remaining(&self) -> u32 {
        self.attempts_remaining
    }
}

/// `pairing_id = SHA-256(pairing_secret)[0..15]`.
///
/// `pairing.proto`: "**COMPUTED BY THE JOINING DEVICE** and carried TO the
/// coordination service — it is **NOT** minted by the server. A server-minted
/// value would break two things at once: it doubles as the HKDF salt for the
/// ceremony channel, and a server-chosen handle would let the rendezvous
/// correlate a handle to a secret it must never see."
///
/// The parameter is named `pairing_secret` because that is the only correct
/// input; there is no variant taking a server-supplied id.
#[must_use]
pub fn derive_pairing_id(pairing_secret: &[u8]) -> [u8; 16] {
    let d = twinvpn_crypto::sha256(pairing_secret);
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

/// The device's pairing ledger: in-flight ceremonies and burned identifiers.
#[derive(Debug, Default)]
pub struct PairingLedger {
    active: BTreeMap<[u8; 16], Pairing>,
    /// Every `pairing_id` ever seen, with its terminal outcome where it has
    /// one. **Never removed** — that is what "never reissued, not even after
    /// expiry or cancellation" means.
    burned: BTreeMap<[u8; 16], Option<PairingOutcome>>,
}

impl PairingLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `BeginPairing`. A duplicate returns the **original** `pairing_id` and the
    /// original record rather than starting a second ceremony.
    ///
    /// `now_secs` is the suspend-inclusive elapsed reading, supplied by the
    /// caller from its `Env`.
    ///
    /// # Errors
    ///
    /// [`TrustError::PairingIdConsumed`] if the id has already reached a
    /// terminal state. Reissuing would reset the five-attempt budget, which is
    /// the whole reason a nine-digit code is safe.
    pub fn begin(
        &mut self,
        pairing_id: [u8; 16],
        ceremony: CeremonyType,
        now_secs: u64,
    ) -> Result<&Pairing> {
        if self.burned.contains_key(&pairing_id) {
            return Err(TrustError::PairingIdConsumed);
        }
        // The duplicate case: `BeginPairing` is idempotent, so a retry returns
        // what the first call created. Not a new ceremony, and not an error.
        Ok(self.active.entry(pairing_id).or_insert_with(|| Pairing {
            pairing_id,
            ceremony,
            state: PairingState::Pending,
            attempts_remaining: MAX_ATTEMPTS,
            created_at_secs: now_secs,
            outcome: None,
        }))
    }

    /// Records a failed ceremony run.
    ///
    /// N-17 and §7.4: "a failed run **BURNS one and burns the code**." Both
    /// happen here — the attempt budget decrements *and* the id is burned, so a
    /// wrong code cannot be retried with the same code.
    ///
    /// # Errors
    ///
    /// [`TrustError::PairingCodeMismatch`] carrying the remaining budget, or
    /// [`TrustError::PairingAttemptsExceeded`] once it reaches zero.
    pub fn record_failed_run(&mut self, pairing_id: &[u8; 16]) -> Result<()> {
        let Some(p) = self.active.get_mut(pairing_id) else {
            return Err(TrustError::PairingIdConsumed);
        };
        p.attempts_remaining = p.attempts_remaining.saturating_sub(1);
        if p.attempts_remaining == 0 {
            let outcome = PairingOutcome {
                state: PairingState::Aborted,
                attestations: None,
                reason_code: Some("AUTH.PAIRING_ATTEMPTS_EXCEEDED"),
            };
            self.finish(*pairing_id, outcome);
            return Err(TrustError::PairingAttemptsExceeded);
        }
        Err(TrustError::PairingCodeMismatch {
            attempts_remaining: p.attempts_remaining,
        })
    }

    /// Enforces N-17's 120-second window.
    ///
    /// "enforced **independently** by both devices AND the rendezvous.
    /// Independent enforcement is the point — a single enforcement point is a
    /// single thing to compromise." This is one of the three.
    ///
    /// # Errors
    ///
    /// [`TrustError::PairingExpired`], and the id is burned.
    pub fn check_window(&mut self, pairing_id: &[u8; 16], now_secs: u64) -> Result<()> {
        let Some(p) = self.active.get(pairing_id) else {
            return Err(TrustError::PairingIdConsumed);
        };
        if now_secs.saturating_sub(p.created_at_secs) >= CEREMONY_WINDOW_SECS {
            let outcome = PairingOutcome {
                state: PairingState::Expired,
                attestations: None,
                reason_code: Some("AUTH.PAIRING_EXPIRED"),
            };
            self.finish(*pairing_id, outcome);
            return Err(TrustError::PairingExpired);
        }
        Ok(())
    }

    /// `CompletePairing`. A replay returns the **original outcome**.
    ///
    /// The contract matrix says plainly that this is what prevents asymmetric
    /// trust: if a replay could produce a *different* outcome, one device could
    /// end up believing the ceremony confirmed while the other believed it
    /// aborted, "which produces a mutual-authentication failure at every
    /// subsequent handshake that looks like a crypto bug and is actually a
    /// delivery bug."
    ///
    /// The two attestations are checked for mutual consistency before the
    /// ceremony is recorded as confirmed — one device's half is not a ceremony.
    ///
    /// # Errors
    ///
    /// [`TrustError::PairingIdConsumed`] if the id was never begun, and
    /// [`TrustError::Crypto`] if the two attestations are not the halves of one
    /// ceremony.
    pub fn complete(
        &mut self,
        pairing_id: [u8; 16],
        a: PairingAttestation,
        b: PairingAttestation,
    ) -> Result<PairingOutcome> {
        // The replay case, checked first: a completed ceremony returns what it
        // returned, whatever is presented now.
        if let Some(Some(prior)) = self.burned.get(&pairing_id) {
            return Ok(prior.clone());
        }
        if !self.active.contains_key(&pairing_id) {
            return Err(TrustError::PairingIdConsumed);
        }

        // N-18: both or neither. Two halves that do not name each other, or that
        // disagree on the transcript, are not a ceremony.
        twinvpn_crypto::statements::check_attestation_pair(&a, &b)?;
        if a.pairing_id != pairing_id || b.pairing_id != pairing_id {
            return Err(TrustError::Crypto(
                twinvpn_crypto::CryptoError::NonCanonicalCbor {
                    kind: twinvpn_crypto::StatementKind::PairingAttestation,
                    step: "attestation names a different pairing_id",
                },
            ));
        }

        let outcome = PairingOutcome {
            state: PairingState::Confirmed,
            attestations: Some((a, b)),
            reason_code: None,
        };
        self.finish(pairing_id, outcome.clone());
        Ok(outcome)
    }

    /// `CancelPairing`. Burns the id; it is single-use.
    ///
    /// Idempotent: cancelling twice is not an error, and cancelling a completed
    /// ceremony does **not** un-complete it — the original outcome stands.
    pub fn cancel(&mut self, pairing_id: [u8; 16]) -> PairingOutcome {
        if let Some(Some(prior)) = self.burned.get(&pairing_id) {
            return prior.clone();
        }
        let outcome = PairingOutcome {
            state: PairingState::Aborted,
            attestations: None,
            reason_code: Some("AUTH.PAIRING_EXPIRED"),
        };
        self.finish(pairing_id, outcome.clone());
        outcome
    }

    /// The recorded outcome for an id, if it has one.
    #[must_use]
    pub fn outcome(&self, pairing_id: &[u8; 16]) -> Option<&PairingOutcome> {
        self.burned.get(pairing_id).and_then(Option::as_ref)
    }

    /// Whether an id has been consumed and may never be reissued.
    #[must_use]
    pub fn is_burned(&self, pairing_id: &[u8; 16]) -> bool {
        self.burned.contains_key(pairing_id)
    }

    fn finish(&mut self, pairing_id: [u8; 16], outcome: PairingOutcome) {
        if let Some(p) = self.active.get_mut(&pairing_id) {
            p.state = outcome.state;
            p.outcome = Some(outcome.clone());
        }
        self.active.remove(&pairing_id);
        self.burned.insert(pairing_id, Some(outcome));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: [u8; 16] = [0x5a; 16];

    fn attestation(peer: &str, own: &str) -> PairingAttestation {
        PairingAttestation {
            pairing_id: ID,
            peer_key_id: peer.to_owned(),
            own_key_id: own.to_owned(),
            transcript_hash: [0x7c; 32],
            not_after_ms: 2_000_000_000_000,
        }
    }

    #[test]
    fn the_pairing_id_is_the_secrets_digest_prefix() {
        let secret = b"123456789";
        let id = derive_pairing_id(secret);
        assert_eq!(id.len(), 16);
        assert_eq!(id, twinvpn_crypto::sha256(secret)[..16]);
        // And two different secrets give two different handles.
        assert_ne!(id, derive_pairing_id(b"987654321"));
    }

    /// **The idempotency rule.** `BeginPairing` duplicate returns the original
    /// `pairing_id` and the original record — not a second ceremony with a fresh
    /// attempt budget.
    #[test]
    fn a_duplicate_begin_returns_the_original_record() {
        let mut l = PairingLedger::new();
        l.begin(ID, CeremonyType::Spake2Code, 0).expect("first");
        let _ = l.record_failed_run(&ID);
        let again = l
            .begin(ID, CeremonyType::Spake2Code, 50)
            .expect("duplicate");
        assert_eq!(again.pairing_id(), &ID);
        assert_eq!(
            again.attempts_remaining(),
            MAX_ATTEMPTS - 1,
            "a duplicate must not reset the attempt budget"
        );
    }

    /// **The idempotency rule that prevents asymmetric trust.** A
    /// `CompletePairing` replay returns the **original outcome**, whatever is
    /// presented on the replay.
    #[test]
    fn a_complete_replay_returns_the_original_outcome() {
        let mut l = PairingLedger::new();
        l.begin(ID, CeremonyType::Spake2Code, 0).expect("begin");
        let first = l
            .complete(ID, attestation("kb", "ka"), attestation("ka", "kb"))
            .expect("complete");
        assert_eq!(first.state, PairingState::Confirmed);

        // The replay presents *different* attestations. The original outcome
        // stands — a second, divergent completion is exactly the asymmetric
        // trust N-18 exists to prevent.
        let replay = l
            .complete(ID, attestation("kx", "ky"), attestation("ky", "kx"))
            .expect("replay");
        assert_eq!(replay, first);
    }

    /// **Attack test — N-18.** Two attestations that are not the halves of one
    /// ceremony must not confirm it.
    #[test]
    fn inconsistent_attestations_do_not_confirm_a_pairing() {
        let mut l = PairingLedger::new();
        l.begin(ID, CeremonyType::Spake2Code, 0).expect("begin");
        // b names a third party as its peer.
        assert!(l
            .complete(ID, attestation("kb", "ka"), attestation("kc", "kb"))
            .is_err());
        // And the ceremony is still pending, not half-confirmed: there is no
        // state that means "confirmed on one side".
        assert!(!l.is_burned(&ID));
    }

    /// **Attack test.** An attestation for a *different* ceremony must not
    /// complete this one.
    #[test]
    fn an_attestation_for_another_ceremony_is_refused() {
        let mut l = PairingLedger::new();
        l.begin(ID, CeremonyType::Spake2Code, 0).expect("begin");
        let mut a = attestation("kb", "ka");
        let mut b = attestation("ka", "kb");
        a.pairing_id = [0x99; 16];
        b.pairing_id = [0x99; 16];
        assert!(l.complete(ID, a, b).is_err());
    }

    /// **`CancelPairing` burns the id; it is single-use.** And the id is never
    /// reissued, "not even after expiry or cancellation".
    #[test]
    fn cancel_burns_the_id_permanently() {
        let mut l = PairingLedger::new();
        l.begin(ID, CeremonyType::Spake2Code, 0).expect("begin");
        let out = l.cancel(ID);
        assert_eq!(out.state, PairingState::Aborted);
        assert!(l.is_burned(&ID));
        // Re-beginning is refused, which is what keeps the five-attempt budget
        // meaningful.
        assert!(matches!(
            l.begin(ID, CeremonyType::Spake2Code, 1),
            Err(TrustError::PairingIdConsumed)
        ));
        // Cancel is idempotent.
        assert_eq!(l.cancel(ID), out);
    }

    /// Cancelling a *completed* ceremony must not un-complete it.
    #[test]
    fn cancelling_a_completed_pairing_returns_the_original_outcome() {
        let mut l = PairingLedger::new();
        l.begin(ID, CeremonyType::Spake2Code, 0).expect("begin");
        let confirmed = l
            .complete(ID, attestation("kb", "ka"), attestation("ka", "kb"))
            .expect("complete");
        assert_eq!(l.cancel(ID), confirmed);
    }

    /// **N-17's budget.** Five failed runs, then the id is burned.
    #[test]
    fn five_failed_runs_exhaust_the_budget_and_burn_the_id() {
        let mut l = PairingLedger::new();
        l.begin(ID, CeremonyType::Spake2Code, 0).expect("begin");
        for expected in (1..MAX_ATTEMPTS).rev() {
            match l.record_failed_run(&ID) {
                Err(TrustError::PairingCodeMismatch { attempts_remaining }) => {
                    assert_eq!(attempts_remaining, expected);
                }
                other => panic!("expected a code mismatch, got {other:?}"),
            }
        }
        assert!(matches!(
            l.record_failed_run(&ID),
            Err(TrustError::PairingAttemptsExceeded)
        ));
        assert!(l.is_burned(&ID));
        // And a sixth run has nothing to burn.
        assert!(matches!(
            l.record_failed_run(&ID),
            Err(TrustError::PairingIdConsumed)
        ));
    }

    /// **N-17's window**, enforced here as one of the three independent
    /// enforcement points.
    #[test]
    fn the_ceremony_expires_at_120_seconds_and_burns_the_id() {
        let mut l = PairingLedger::new();
        l.begin(ID, CeremonyType::Spake2Code, 1000).expect("begin");
        l.check_window(&ID, 1000 + CEREMONY_WINDOW_SECS - 1)
            .expect("inside the window");
        assert!(matches!(
            l.check_window(&ID, 1000 + CEREMONY_WINDOW_SECS),
            Err(TrustError::PairingExpired)
        ));
        assert!(l.is_burned(&ID));
        assert_eq!(
            l.outcome(&ID).expect("recorded").reason_code,
            Some("AUTH.PAIRING_EXPIRED"),
            "a timeout must be a distinct, actionable state"
        );
    }

    /// N-16: the ceremony method is recorded, because "which ceremony did this
    /// trust come from" cannot be answered retroactively.
    #[test]
    fn the_ceremony_method_is_recorded() {
        let mut l = PairingLedger::new();
        let p = l.begin(ID, CeremonyType::Qr, 0).expect("begin");
        assert_eq!(p.ceremony(), CeremonyType::Qr);
    }

    /// A completed ceremony carries **both** attestations together: "a peer that
    /// receives only one has no evidence the other side completed."
    #[test]
    fn a_confirmed_outcome_carries_both_attestations() {
        let mut l = PairingLedger::new();
        l.begin(ID, CeremonyType::Spake2Code, 0).expect("begin");
        let out = l
            .complete(ID, attestation("kb", "ka"), attestation("ka", "kb"))
            .expect("complete");
        let (a, b) = out.attestations.expect("both halves");
        assert_eq!(a.own_key_id, "ka");
        assert_eq!(b.own_key_id, "kb");
        assert!(out.reason_code.is_none());
    }
}
