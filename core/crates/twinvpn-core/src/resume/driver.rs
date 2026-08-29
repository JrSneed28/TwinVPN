//! The resume flow, bound to the `Session` that runs it.
//!
//! **Authority:** `docs/protocol.md` §12.1 (resumption is the **first** recovery
//! attempt, and every fallback step is visible); `docs/reliability.md` §4.5 T35,
//! §6.2's ladder, §11.3's wake sequence; ADR-0001 §7.3.2 RS-1 to RS-7.
//!
//! # Why this lives beside the state machine and not beside the tunnel
//!
//! A resume is a **clocked decision that ends in a transition**:
//! [`crate::session_loop::SessionRuntime`] already owns the `Session`'s injected
//! clock and is the only object permitted to move the machine (ADR-0015 O-05).
//! Putting the flow anywhere else would mean a second thing computing a guard
//! the machine reads, which is exactly how a `Session` comes to hold two beliefs
//! about one fact.
//!
//! No new state and no new transition row. §4.5 T35 already says what
//! `EV_RESUME` in `RECONNECTING{parked}` means; what was missing was anything
//! that computed its guard from a **wire fact** instead of a guess.

use twinvpn_crypto::EstablishedHandshake;
use twinvpn_env::BootId;
use twinvpn_platform::iface::ResumeFacts;
use twinvpn_session::event::{Event, Trigger};
use twinvpn_session::{Context, Guards, Outcome};
use twinvpn_types::{codes, ReasonCode, SessionNonce};

use crate::resume::{
    AcceptedResume, PeerTrustFacts, ResumeRefusal, ResumeState, RESUMPTION_LIFETIME,
};
use crate::session_loop::{ResumeVerdict, SessionRuntime};

impl SessionRuntime {
    /// Arms ADR-0001 §7.3.2 resumption for a handshake that just completed.
    ///
    /// The one call that turns a `Session` into one that can resume. Its
    /// production caller is [`crate::execute::establishment`], on every
    /// `Session` whose direct `Noise_IKpsk2` handshake produced a live tunnel;
    /// it is called once, with the `path_epoch` the `Session` was established
    /// at.
    ///
    /// Arming twice replaces the state, which is what a **rekey** should do:
    /// RS-6 bounds resumption by the rekey schedule, so new keys must not
    /// inherit the old material's age or its window.
    ///
    /// # The seam is closed: neither input can be chosen by a caller
    ///
    /// ADR-0001 §7.3.2's input is the **per-session secret** the completed Noise
    /// handshake produced, which no observer of the transcript can recompute.
    /// This function takes [`twinvpn_crypto::EstablishedHandshake`], which is
    /// exactly that value and nothing else: it has no public constructor, and
    /// `twinvpn_crypto::noise::Handshake::split` — which consumes the handshake
    /// — is the only thing in the workspace that mints one. The role is read
    /// **off** it, and the secret comes with it.
    ///
    /// An earlier version of this function took `&[u8]` and a caller-supplied
    /// `Role`, and both were silent downgrades rather than failures:
    ///
    /// - **the handshake hash compiled.** `handshake_hash()` is exported
    ///   deliberately, for ADR-0001 §7.3 D2's confirmation value — a value that
    ///   may be **transmitted and compared in the clear** — and Noise's own
    ///   specification says it is not to be used as secret material. (Note the
    ///   objection is disclosure, not weakness: `IKpsk2`'s `psk` token fires in
    ///   message 2, after `es`, `ss`, `ee` and `se` are mixed into `ck`, so `h`
    ///   *is* a function of the DH outputs and a TwinNet member holding the PSK
    ///   cannot recompute it. Keying from something the design sends on the wire
    ///   is unsound however well it is mixed.)
    /// - **arming both peers under one role compiled**, which collapses the two
    ///   direction labels into one and removes the reflection defence
    ///   `a_resume_reflected_back_at_its_sender_does_not_authenticate` exists to
    ///   guarantee. That test passed anyway, because the harness assigned the
    ///   roles correctly by hand.
    ///
    /// # The crypto-seam decision this used to be blocked on, and how it went
    ///
    /// This block used to report the derivation as an **open** decision. It is
    /// not open any more, and the record is worth keeping straight:
    ///
    /// `snow`'s `HandshakeState::dangerously_get_raw_split`, behind its
    /// `risky-raw-split` feature, returns the two 32-byte outputs of Noise's
    /// `Split()`. `twinvpn-crypto` now enables that feature — a pure feature
    /// flag, `risky-raw-split = []` in snow 0.10.0, which adds no dependency and
    /// therefore does not engage ADR-0018 DP-3's dependency-surface rule — and
    /// derives
    ///
    /// ```text
    /// handshake_secret = HKDF-Extract(salt = "TwinVPN/resumption/v1", ikm = k1 || k2)
    /// ```
    ///
    /// The old objection to those two values was that "reusing keying material
    /// the datapath is actively using for a second purpose is not the derivation
    /// the ADR specifies". The extract answers it: this is the **TLS 1.3 shape**
    /// — RFC 8446 §7.1 derives `resumption_master_secret` from the same secret
    /// the traffic keys come from, separated by a label — and HKDF-Extract is
    /// one-way, so resumption material never yields transport keys. Unlike the
    /// handshake hash, `k1` and `k2` are never disclosed on the wire in any
    /// form. `twinvpn_crypto::established` carries the full argument.
    pub fn arm_resumption(
        &mut self,
        handshake: &EstablishedHandshake,
        session_nonce: SessionNonce,
        path_epoch: u64,
    ) -> Result<(), ResumeRefusal> {
        let state =
            ResumeState::armed(handshake, session_nonce, path_epoch, self.env.now_elapsed())?;
        self.resume = Some(state);
        Ok(())
    }

    /// Drops the resumption material.
    ///
    /// Called when the material must not be used again: the tunnel was torn
    /// down, the peer was revoked, or the rekey window has passed. It is
    /// idempotent, and it is the fail-closed direction — a `Session` with no
    /// material refuses to resume, it does not resume without checking.
    pub fn disarm_resumption(&mut self) {
        self.resume = None;
    }

    /// The resumption state, for reads. `None` after a restart (RS-1).
    #[must_use]
    pub const fn resumption(&self) -> Option<&ResumeState> {
        self.resume.as_ref()
    }

    /// **Producer.** One authenticated `ResumeSession` datagram for the peer.
    ///
    /// §12.1's first recovery attempt: ~1 RTT, no key exchange, no control
    /// plane. A refusal here means this device already knows the resume cannot
    /// succeed and the caller should go straight to a full handshake rather than
    /// spend the RTT.
    pub fn offer_resume(
        &mut self,
        new_endpoint_hint: Option<twinvpn_schema::v1::Endpoint>,
        facts: PeerTrustFacts,
    ) -> Result<Vec<u8>, ResumeRefusal> {
        let now = self.env.now_elapsed();
        let Some(state) = self.resume.as_mut() else {
            return Err(ResumeRefusal::NotArmed);
        };
        let offered = state.offer(new_endpoint_hint, facts, now);
        if let Err(refusal) = offered {
            self.forget_dead_material(refusal);
        }
        offered
    }

    /// **Consumer.** Authenticates and authorizes a peer's `ResumeSession`.
    ///
    /// Does not move the machine; [`SessionRuntime::resume_on_wire`] is the form
    /// that does. Split so that a caller which has already fired `EV_RESUME` for
    /// another reason can still run the wire check.
    pub fn accept_resume_offer(
        &mut self,
        datagram: &[u8],
        facts: PeerTrustFacts,
    ) -> Result<AcceptedResume, ResumeRefusal> {
        let now = self.env.now_elapsed();
        let Some(state) = self.resume.as_mut() else {
            return Err(ResumeRefusal::NotArmed);
        };
        let accepted = state.accept(datagram, facts, now);
        if let Err(refusal) = accepted {
            self.forget_dead_material(refusal);
        }
        accepted
    }

    /// The wire resume, and the transition it earns.
    ///
    /// **This is where §12.1's fallback becomes a state change.** `EV_RESUME` is
    /// applied with `path_plausibly_survived` set to whether the datagram
    /// actually authenticated, so `docs/reliability.md` §4.5 T35 does the rest:
    /// a resume that authenticated takes the `MIGRATING` arm — the existing
    /// `Tunnel` re-bound to a new `Path`, which is RS-3 — and **every** refusal
    /// takes the `DISCOVERING` arm, which is the full handshake §12.1 requires.
    ///
    /// No new state, no new row. A resume was always a `RECONNECTING` concern
    /// and the table already said what it means; what was missing was anything
    /// that computed the guard from a wire fact instead of a guess.
    pub fn resume_on_wire(
        &mut self,
        datagram: &[u8],
        facts: PeerTrustFacts,
        guards: Guards,
        ctx: Context,
    ) -> (Result<AcceptedResume, ResumeRefusal>, Outcome) {
        let verdict = self.accept_resume_offer(datagram, facts);
        let guards = Guards {
            path_plausibly_survived: verdict.is_ok(),
            // T35 reads this second: a resume refused *because* the material
            // aged out is exactly "the rekey window was exceeded", and saying so
            // keeps the reason the machine acted on the same as the reason
            // reported. Any other refusal leaves the caller's value alone.
            rekey_window_exceeded: guards.rekey_window_exceeded
                || verdict == Err(ResumeRefusal::Expired),
            ..guards
        };
        let outcome = self.apply(Trigger::Event(Event::Resume), guards, ctx);
        (verdict, outcome)
    }

    /// Drops material a refusal proved is dead.
    ///
    /// Expiry (RS-6) and revocation (RS-5) are permanent for this `Session`:
    /// retrying is not merely futile, it is the shape that eventually resumes on
    /// a key nobody re-checked. A replayed or forged datagram, by contrast,
    /// says nothing about our own material and must not let an off-path attacker
    /// destroy it.
    fn forget_dead_material(&mut self, refusal: ResumeRefusal) {
        if matches!(
            refusal,
            ResumeRefusal::Expired
                | ResumeRefusal::PeerRevoked
                | ResumeRefusal::TrustEpochBehind { .. }
        ) {
            self.disarm_resumption();
        }
    }
}

impl ResumeVerdict {
    /// [`ResumeVerdict::decide`] against the constant the wire flow uses.
    ///
    /// §11.3's rekey window and ADR-0001 RS-6's bound on the resumption material
    /// are the same bound, so they are the same constant here. Two
    /// independently chosen durations would let the machine believe a wire
    /// resume is admissible while [`crate::resume::ResumeState`] refuses it as
    /// expired — or, the other way round, spend an RTT on one the peer is
    /// obliged to drop.
    #[must_use]
    pub fn decide_for_wire_resume(facts: &ResumeFacts, held_boot_id: Option<BootId>) -> Self {
        Self::decide(facts, held_boot_id, RESUMPTION_LIFETIME)
    }

    /// Whether a wire-level resume may be attempted at all.
    ///
    /// **ADR-0001 RS-1, at the wake decision.** A cold start has no resumption
    /// material by construction — the process is new — and a gap past the rekey
    /// window has material RS-6 forbids using. Both go straight to a full
    /// handshake from cached `TrustedPeer` state, which is still
    /// control-plane-free (RS-7), and neither spends an RTT finding out.
    ///
    /// An **unmeasured** gap answers `false` here for free, because
    /// [`ResumeVerdict::decide`] already reads `suspended_for: None` as
    /// exceeding the window. That is the same safe direction one level down: a
    /// resume we cannot date is one we cannot show is fresh.
    #[must_use]
    pub const fn wire_resume_admissible(self) -> bool {
        !self.cold_start && !self.rekey_window_exceeded
    }

    /// The registered code to publish when [`Self::wire_resume_admissible`] is
    /// `false`.
    ///
    /// §12.1: "Each fallback step MUST be visible." Skipping the resume without
    /// saying so is exactly the invisible fallback that row exists to forbid.
    #[must_use]
    pub const fn inadmissible_reason(self) -> Option<ReasonCode> {
        if self.wire_resume_admissible() {
            None
        } else if self.cold_start {
            // A restarted process runs a full negotiation; there was never any
            // material to call stale.
            Some(codes::NET_FULL_RENEGOTIATE)
        } else {
            Some(codes::NET_RESUME_STALE)
        }
    }
}
