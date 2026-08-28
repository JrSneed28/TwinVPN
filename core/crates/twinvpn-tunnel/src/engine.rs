//! The L-DATA engine: the handshake driver, the key state, and endpoint
//! migration.
//!
//! **Authority:** ADR-0001 §7.2, §7.3, §7.6, §8, §11; ADR-0014 N-8, N-16, N-17;
//! `contracts/proto/twinvpn/v1/tunnel.proto` (frozen);
//! `docs/reliability.md` §6.5.
//!
//! # Endpoint migration is authenticated **and** path-validated
//!
//! §7.6 imposes on ADR-0004, and this engine enforces the L-DATA half:
//!
//! > A `Path` change MUST NOT commit bulk traffic to a new `Endpoint` until an
//! > authenticated challenge/response has completed **on that new path**. Until
//! > validation succeeds, the new endpoint MAY receive only the validation
//! > probe, and the **previous endpoint remains authoritative**. Failed
//! > validation MUST NOT tear down the `Session`.
//!
//! [`Tunnel::offer_endpoint`] therefore stages a candidate endpoint, and only
//! [`Tunnel::commit_endpoint`] — which requires a validated probe — makes it
//! authoritative. [`Tunnel::authoritative_endpoint`] answers with the old one
//! until then.

use twinvpn_env::MonotonicInstant;
use twinvpn_types::{Endpoint, SessionId, TunnelId};

use crate::crypto::{CryptoUnavailable, Prologue, TransportKeys};
use crate::rekey::{Action, KeyState};
use crate::replay::{ReplayWindow, SendCounter};
use crate::transport::{SecuritySnapshot, TransportMode};

/// `tunnel.proto`'s `TunnelState`, which is "distinct from `ConnectionState`,
/// which is a property of the **`Session`**".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TunnelState {
    /// No cryptographic state exists.
    Absent,
    /// The ADR-0001 handshake is in flight.
    Handshaking,
    /// Keys established, but `NegotiationConfirm` has not yet matched.
    ///
    /// ADR-0014 N-9: "no `Session` state, no floor and no cached advertisement
    /// may be written before the handshake completes **and**
    /// `NegotiationConfirm` matches. This state is that gap, **named so it is
    /// observable rather than implicit**."
    Confirming,
    /// Established and carrying traffic.
    Established,
    /// Rekeying **in place**. The `Tunnel` identity is unchanged.
    Rekeying,
    /// Terminal. A new `Tunnel` is required. **The `Session` survives.**
    Closed,
}

impl TunnelState {
    /// Whether user traffic may flow.
    ///
    /// `Confirming` answers `false`: the transcript has not matched, and D1 says
    /// no negotiated result is authoritative until it has.
    #[must_use]
    pub const fn carries_traffic(self) -> bool {
        matches!(self, TunnelState::Established | TunnelState::Rekeying)
    }
}

/// Why a tunnel operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TunnelError {
    /// The keys are gone or authentication failed.
    #[error("cryptographic material is unavailable or authentication failed")]
    Crypto,
    /// A counter was replayed. `CRYPTO.REPLAY_DETECTED`, `FATAL`.
    #[error("anti-replay window rejected the counter")]
    Replay,
    /// The send counter is exhausted; a rekey is required before sending again.
    #[error("the send counter is exhausted for this key generation")]
    CounterExhausted,
    /// The tunnel is not in a state that carries traffic.
    #[error("the tunnel is not established")]
    NotEstablished,
    /// `NegotiationConfirm` did not match. `PROTO.TRANSCRIPT_MISMATCH`, and a
    /// **security event, not a network error**.
    #[error("the negotiation transcript did not match")]
    TranscriptMismatch,
}

impl From<CryptoUnavailable> for TunnelError {
    fn from(_: CryptoUnavailable) -> Self {
        TunnelError::Crypto
    }
}

/// The cryptographic transport instance.
///
/// Ephemeral, tied to a key generation, process-local, **not durable** (S-13).
/// "A new `Tunnel` is created only when cryptographic state must be
/// **re-established** — not on a path change and not on a rekey."
pub struct Tunnel {
    id: TunnelId,
    session: SessionId,
    state: TunnelState,
    keys: Option<Box<dyn TransportKeys>>,
    key_state: KeyState,
    send: SendCounter,
    replay: ReplayWindow,
    /// The endpoint bulk traffic actually goes to.
    authoritative: Option<Endpoint>,
    /// A candidate that has not yet passed validation. It "MAY receive **only
    /// the validation probe**".
    staged: Option<Endpoint>,
    transport: TransportMode,
    /// The trust epoch this tunnel's `psk2` was derived at.
    trust_epoch: u64,
}

impl Tunnel {
    /// A tunnel with no cryptographic state yet.
    #[must_use]
    pub fn absent(id: TunnelId, session: SessionId, now: MonotonicInstant) -> Self {
        Self {
            id,
            session,
            state: TunnelState::Absent,
            keys: None,
            key_state: KeyState::new(now),
            send: SendCounter::new(),
            replay: ReplayWindow::new(),
            authoritative: None,
            staged: None,
            transport: TransportMode::Udp,
            trust_epoch: 0,
        }
    }

    /// The tunnel's identity. Unchanged by a rekey or a transport switch.
    #[must_use]
    pub const fn id(&self) -> TunnelId {
        self.id
    }

    /// The `Session` this tunnel serves. **A tunnel teardown does not destroy
    /// it.**
    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    /// The tunnel's state.
    #[must_use]
    pub const fn state(&self) -> TunnelState {
        self.state
    }

    /// The key generation.
    #[must_use]
    pub const fn key_generation(&self) -> u64 {
        self.key_state.generation()
    }

    /// The trust epoch the `psk2` was derived at.
    ///
    /// ADR-0007 N-25(2): "a device MUST NOT accept a handshake below its
    /// `min_acceptable_epoch`."
    #[must_use]
    pub const fn trust_epoch(&self) -> u64 {
        self.trust_epoch
    }

    /// Records a completed handshake, moving to `Confirming`.
    ///
    /// N-8 makes `NegotiationConfirm` the first in-session message, so the
    /// tunnel does **not** go straight to `Established`.
    pub fn handshake_completed(
        &mut self,
        keys: Box<dyn TransportKeys>,
        endpoint: Endpoint,
        trust_epoch: u64,
        now: MonotonicInstant,
    ) {
        self.keys = Some(keys);
        self.key_state = KeyState::new(now);
        self.send = SendCounter::new();
        self.replay = ReplayWindow::new();
        self.authoritative = Some(endpoint);
        self.staged = None;
        self.trust_epoch = trust_epoch;
        self.state = TunnelState::Confirming;
    }

    /// Records that `NegotiationConfirm` matched.
    ///
    /// # Errors
    ///
    /// [`TunnelError::TranscriptMismatch`] when the two hashes differ, which
    /// **tears down the tunnel** — D2, and `PROTO.TRANSCRIPT_MISMATCH` is
    /// `FATAL`/`CRITICAL`.
    pub fn confirm_negotiation(
        &mut self,
        ours: &[u8; 32],
        theirs: &[u8; 32],
    ) -> Result<(), TunnelError> {
        if ours != theirs {
            self.state = TunnelState::Closed;
            self.zeroize();
            return Err(TunnelError::TranscriptMismatch);
        }
        self.state = TunnelState::Established;
        Ok(())
    }

    /// Seals one outbound payload.
    ///
    /// # Errors
    ///
    /// [`TunnelError::NotEstablished`], [`TunnelError::CounterExhausted`] when
    /// the generation's nonce space is used up — **never** wrapping, because the
    /// counter is the AEAD nonce — or [`TunnelError::Crypto`].
    pub fn seal(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<u64, TunnelError> {
        if !self.state.carries_traffic() {
            return Err(TunnelError::NotEstablished);
        }
        let keys = self.keys.as_ref().ok_or(TunnelError::NotEstablished)?;
        let counter = self.send.take_next().ok_or(TunnelError::CounterExhausted)?;
        keys.seal(counter, plaintext, out)?;
        self.key_state.observe_send();
        Ok(counter)
    }

    /// Opens one inbound payload, checking the replay window **after**
    /// authentication.
    ///
    /// The order matters: **admitting** on the window first would let an
    /// attacker advance it with forged counters. WireGuard opens first, then
    /// admits, and so does this — [`ReplayWindow::accept`] runs only after the
    /// AEAD has authenticated the frame.
    ///
    /// The non-mutating [`ReplayWindow::would_accept`] runs *before* the AEAD,
    /// which is safe for the same reason WireGuard's own cheap shed is: it moves
    /// nothing. It is here for a reason that only appears with a real crypto
    /// binding. [`crate::bind::SessionKeys`] wraps a
    /// `twinvpn_crypto::noise::TransportSession`, which carries a replay window
    /// of its own and refuses a duplicate itself — so without this pre-check a
    /// replayed counter would surface as [`TunnelError::Crypto`] (a drop) rather
    /// than [`TunnelError::Replay`] (`CRYPTO.REPLAY_DETECTED`, `FATAL`), and the
    /// engine's own classification would be unreachable in production while
    /// staying reachable under a stub. A security event that downgrades to a
    /// drop when you swap the stub for the real thing is exactly the divergence
    /// worth spending three lines on.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Crypto`] on an authentication failure — a **drop** —
    /// and [`TunnelError::Replay`] on a duplicate, which is `FATAL`.
    pub fn open(
        &mut self,
        counter: u64,
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), TunnelError> {
        if !self.state.carries_traffic() {
            return Err(TunnelError::NotEstablished);
        }
        // Non-mutating: a counter the window can never take is refused before an
        // AEAD is spent on it, and before the keys' own window can classify the
        // same fact more weakly.
        if !self.replay.would_accept(counter) {
            return Err(TunnelError::Replay);
        }
        let keys = self.keys.as_ref().ok_or(TunnelError::NotEstablished)?;
        keys.open(counter, ciphertext, out)?;
        if !self.replay.accept(counter) {
            return Err(TunnelError::Replay);
        }
        Ok(())
    }

    /// What the rekey scheduler wants done now.
    #[must_use]
    pub fn rekey_action(&self, now: MonotonicInstant) -> Action {
        self.key_state.evaluate(now)
    }

    /// Begins an in-place rekey. **The `Tunnel` identity is unchanged.**
    pub fn begin_rekey(&mut self, now: MonotonicInstant) {
        self.key_state.begin_rekey(now);
        self.state = TunnelState::Rekeying;
    }

    /// Completes an in-place rekey with fresh keys.
    ///
    /// The replay window and the send counter reset **because the key
    /// generation changed**, which is §6.5's "lost on rekey" and not a
    /// contradiction of the transport rule.
    pub fn complete_rekey(&mut self, keys: Box<dyn TransportKeys>, now: MonotonicInstant) {
        self.keys = Some(keys);
        self.key_state.complete_rekey(now);
        self.send = SendCounter::new();
        self.replay = ReplayWindow::new();
        self.state = TunnelState::Established;
    }

    /// Zeroes the key material and closes the tunnel.
    ///
    /// The `Session` survives: `tunnel.proto` is explicit that "a `Tunnel`
    /// teardown MUST NOT destroy the `Session`; it triggers `RECONNECTING`".
    pub fn zeroize(&mut self) {
        if let Some(k) = self.keys.as_mut() {
            k.zeroize();
        }
        self.keys = None;
        self.state = TunnelState::Closed;
    }

    // -- §7.6: endpoint migration -------------------------------------------

    /// The endpoint bulk traffic goes to.
    #[must_use]
    pub const fn authoritative_endpoint(&self) -> Option<Endpoint> {
        self.authoritative
    }

    /// Stages a new endpoint. It receives **only the validation probe**.
    ///
    /// The previous endpoint stays authoritative, which is the whole of §7.6's
    /// defence against "an attacker who can *relay* a genuine packet from an
    /// address of their choosing".
    pub fn offer_endpoint(&mut self, candidate: Endpoint) {
        self.staged = Some(candidate);
    }

    /// Whether `endpoint` may receive bulk traffic right now.
    #[must_use]
    pub fn may_carry_bulk(&self, endpoint: Endpoint) -> bool {
        self.authoritative == Some(endpoint)
    }

    /// Commits the staged endpoint after an authenticated challenge/response
    /// completed **on that path**.
    ///
    /// Returns `false` when nothing is staged or validation did not succeed. A
    /// failed validation **MUST NOT tear down the `Session`**, so this changes
    /// nothing on failure.
    pub fn commit_endpoint(&mut self, validated: bool) -> bool {
        match (validated, self.staged.take()) {
            (true, Some(e)) => {
                self.authoritative = Some(e);
                true
            }
            (false, staged) => {
                // Put it back: a failed probe does not discard the candidate,
                // and it certainly does not tear down the Session.
                self.staged = staged;
                false
            }
            (true, None) => false,
        }
    }

    // -- L-TRANSPORT ---------------------------------------------------------

    /// The current carriage.
    #[must_use]
    pub const fn transport(&self) -> TransportMode {
        self.transport
    }

    /// A snapshot of everything a transport switch must leave alone.
    #[must_use]
    pub fn security_snapshot(&self) -> SecuritySnapshot {
        SecuritySnapshot {
            key_generation: self.key_state.generation(),
            send_counter: self.send.issued(),
            replay_highest: self.replay.highest(),
            tunnel_id: self.id,
        }
    }

    /// Switches carriage.
    ///
    /// ADR-0001 §7.2's composition rule, implemented as a function that touches
    /// exactly one field. It returns the snapshot so a caller — and a test — can
    /// compare it against the one taken before.
    pub fn switch_transport(&mut self, mode: TransportMode) -> SecuritySnapshot {
        self.transport = mode;
        self.security_snapshot()
    }
}

/// Assembles the prologue for a handshake.
///
/// Re-exported here so the engine's caller has one place to build it, and so
/// P-1's "no other document may define, extend, or reorder it" has one
/// implementation.
#[must_use]
pub fn prologue(identity_binding_hash: [u8; 32], negotiation_hash: [u8; 32]) -> Prologue {
    Prologue::new(identity_binding_hash, negotiation_hash)
}
