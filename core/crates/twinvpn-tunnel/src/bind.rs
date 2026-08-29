//! The **production** binding of this crate's crypto boundary to
//! `twinvpn-crypto`.
//!
//! **Authority:** ADR-0001 §7.2 (the concrete L-DATA specification), §7.3 D2,
//! §7.3.1 P-1..P-4, §7.5, §11 items 1, 2 and 7; ADR-0014 §11 (`H_X` and the
//! negotiation hash); ADR-0018 CD-I2, CD-2, CD-3;
//! `docs/implementation/ownership.md` §6.
//!
//! # Why this module exists at all
//!
//! [`crate::crypto`] declares three traits and implements none of them, and for
//! most of wave 1 the only implementations in the tree were test stubs — a
//! `make gate` that passes over a product with no working tunnel, where every
//! [`Tunnel`] was built by [`Tunnel::absent`] and no production path could
//! encrypt a packet. This module is the missing half.
//!
//! # It adds no dependency, and that is the point
//!
//! `twinvpn-tunnel` already declares `twinvpn-crypto` (CD-I2's single permitted
//! holder of a cryptographic dependency) and, until now, never referenced it.
//! Implementing *this crate's own* traits for newtypes over `twinvpn-crypto`
//! types uses a dependency that already exists: no manifest change, and nothing
//! here names `snow`, `x25519-dalek`, `chacha20poly1305` or `blake2`. Every
//! primitive still arrives through `twinvpn-crypto`.
//!
//! # Three rules this module refuses to let a caller break
//!
//! | Rule | Where a comment would have gone | The code instead |
//! |---|---|---|
//! | §7.3.1 P-1 — the prologue is *exactly* those 83 bytes, and "no other document may define, extend, or reorder it" | a `// keep these in sync` over two `Prologue` types | [`NoiseBinding`] holds the `twinvpn-crypto` prologue it was built with and **compares it against the [`Prologue`] every trait call carries**. Two independent constructions of the same 83 bytes must agree or there is no handshake |
//! | §11 item 1 — the `psk2` slot carries `TwinNetPSK`, and §7.3.1 fixes the prologue | an optional `psk` field with a `// always set this` | `twinvpn_crypto::noise::HandshakeConfig` has neither field optional, and [`NoiseBinding::new`] takes one whole. There is no PSK-less path to fall back to |
//! | ADR-0007 N-4/N-5 — a peer static is trusted only through a verified `TunnelKeyBinding` | a `// remember to check the binding` on the responder path | [`NoiseBinding::new`] requires a [`VerifiedTunnelKey`] in **both** roles and refuses a completed handshake whose peer static is not that one |
//!
//! # There is no downgrade, in any direction
//!
//! Every refusal here returns [`CryptoUnavailable`]. Nothing has a second,
//! weaker path: a missing key, a disagreeing prologue, an unexpected peer
//! static, an over-long message and a failed AEAD all end the same way, with no
//! session keys produced. §7.3.1 P-3 wants exactly that — a prologue mismatch
//! must be "observationally indistinguishable from any other handshake failure"
//! — and A1's silence on unauthenticated input depends on not telling a prober
//! which check it tripped.
//!
//! # Time and randomness
//!
//! CD-2: [`NoiseBinding::new`] takes [`Env`] and hands it straight to
//! `twinvpn_crypto::noise::Handshake::new`, which draws ephemerals from
//! `Env::entropy`. Nothing here reads a clock; the one `MonotonicInstant` this
//! module handles is a caller's reading passed through.

use std::sync::Mutex;

use twinvpn_crypto::noise::{Handshake, HandshakeConfig, Role, TransportSession};
use twinvpn_crypto::prologue::NEG_LABEL;
use twinvpn_crypto::{EstablishedHandshake, VerifiedTunnelKey};
use twinvpn_env::{Env, MonotonicInstant};
use twinvpn_types::{Endpoint, SessionId, TunnelId};

use crate::crypto::{CryptoUnavailable, NoiseHandshake, Prologue, Transcript, TransportKeys};
use crate::engine::Tunnel;

/// The Noise Protocol Framework's own ceiling on one message, in bytes.
///
/// Revision 34 §3: "the maximum message length is 65535 bytes". It bounds every
/// **untrusted input** here — a handshake message or a sealed record off the
/// network — because it is a specification constant rather than a number chosen
/// at this keyboard, and `ownership.md` §6 rule 10 wants the allocation those
/// inputs drive bounded before it happens. A conforming L-DATA message is far
/// smaller; see [`NoiseBinding`]'s note on the two framings.
pub const NOISE_MAX_MESSAGE_BYTES: usize = 65535;

/// The ChaCha20-Poly1305 tag width. A record shorter than this cannot be one.
pub const AEAD_TAG_BYTES: usize = 16;

/// `H_X`'s domain label, verbatim from ADR-0014 §11:
/// `H_X = SHA-256("TWINVPN-NEG-HALF-v1" || det_CBOR(HalfAdvertisement_X))`.
const NEG_HALF_LABEL: &[u8] = b"TWINVPN-NEG-HALF-v1";

/// The production [`NoiseHandshake`]: `Noise_IKpsk2` over `twinvpn-crypto`.
///
/// # Two framings, and which one this is
///
/// [`NoiseHandshake`]'s documentation names a "148-byte initiation" and a
/// "92-byte response". Those are ADR-0001 §7.2's **WireGuard frame** sizes,
/// which include the message type, the sender and receiver indices and the two
/// MACs. What crosses this boundary is the Noise message the frame carries — 96
/// bytes for `IKpsk2`'s first message with an empty payload, 48 for its second.
/// The framing is the transport layer's, not the handshake's, and putting it
/// here would make L-DATA depend on how it is carried, which §7.2's composition
/// rule forbids. Recorded as an interpretation in this crate's report rather
/// than silently resolved.
///
/// # The responder needs its peer up front, and that is not a burden
///
/// It is tempting to let a responder learn its peer from the initiation. It
/// cannot: `TwinNetPSK` is **pairwise** (ADR-0007 §7.7), so the `psk2` slot
/// cannot be filled before a peer is chosen, and a `Handshake` cannot be built
/// without it. Requiring the [`VerifiedTunnelKey`] alongside is therefore free,
/// and it turns "compare the learned static against the binding" from a rule
/// into a thing that has already happened.
pub struct NoiseBinding {
    /// `None` once the handshake has completed and been converted, or once it
    /// has failed. A second attempt through a spent binding is refused rather
    /// than restarted.
    handshake: Option<Handshake>,
    role: Role,
    /// The 83 bytes this binding was constructed against, for P-1's cross-check.
    prologue: [u8; Prologue::LEN],
    /// The peer static a completed handshake must have proved.
    expected_peer: [u8; 32],
    /// `snow`'s handshake hash, captured at completion for §7.3 D2.
    handshake_hash: Option<[u8; 32]>,
    /// ADR-0001 §7.3.2's authenticated handshake result, captured at completion
    /// and **moved out once** by [`NoiseBinding::take_established`].
    ///
    /// `Option` rather than an accessor returning a reference, because this
    /// keys resumption: RS-1 says the material lives for the life of one
    /// `Session`, and two callers each holding a copy is exactly how it comes to
    /// outlive it. There is no `Clone` on the value and none here.
    established: Option<EstablishedHandshake>,
}

impl NoiseBinding {
    /// Builds a handshake in `role` against `expected_peer`.
    ///
    /// `cfg` carries the four things ADR-0001 fixes and `snow` does not: the
    /// local static, the peer static, the `psk2` contents and the 83-byte
    /// prologue. None of them is optional, here or there.
    ///
    /// For an initiator, `cfg.remote_static` must be `Some(expected_peer)`. The
    /// redundancy is deliberate: `IK` pins the responder's static at
    /// construction, and this makes the value that *pins* it and the value that
    /// is *checked against* provably the same one, so a caller cannot pin one
    /// key and verify another.
    ///
    /// # Errors
    ///
    /// [`CryptoUnavailable`] if the key material is unusable, if the initiator's
    /// pinned and expected statics disagree, or if `twinvpn-crypto` refuses the
    /// configuration. As everywhere in this module, there is no weaker handshake
    /// to fall back to.
    pub fn new(
        env: &Env,
        role: Role,
        cfg: &HandshakeConfig<'_>,
        expected_peer: &VerifiedTunnelKey,
    ) -> Result<Self, CryptoUnavailable> {
        if role == Role::Initiator && cfg.remote_static != Some(expected_peer) {
            return Err(CryptoUnavailable);
        }
        let handshake = Handshake::new(env, role, cfg).map_err(|_| CryptoUnavailable)?;
        Ok(Self {
            handshake: Some(handshake),
            role,
            prologue: *cfg.prologue.as_bytes(),
            expected_peer: *expected_peer.tk_pub(),
            handshake_hash: None,
            established: None,
        })
    }

    /// Which end of the handshake this is.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The Noise handshake hash, once the handshake has completed.
    ///
    /// ADR-0001 §7.3 D2's confirmation runs over the negotiation transcript, and
    /// this is the value that binds that confirmation to *this* handshake rather
    /// than to a concurrent one. `None` until the handshake finishes, which is
    /// N-9's "no state may be written before the handshake completes" expressed
    /// as an absent value.
    #[must_use]
    pub const fn handshake_hash(&self) -> Option<&[u8; 32]> {
        self.handshake_hash.as_ref()
    }

    /// The peer static this binding will accept, and no other.
    #[must_use]
    pub const fn expected_peer_static(&self) -> &[u8; 32] {
        &self.expected_peer
    }

    /// **Moves out** ADR-0001 §7.3.2's authenticated handshake result.
    ///
    /// `None` until the handshake completes — N-9's "no state may be written
    /// before the handshake completes" as an absent value, exactly like
    /// [`Self::handshake_hash`] — and `None` again after the first call.
    ///
    /// # Why once, and not a borrow
    ///
    /// What this hands out keys resumption, and ADR-0001 §7.3.2 RS-1 says that
    /// material lives **in memory only, for the life of the `Session`**. A
    /// second caller receiving a second copy is precisely the shape that ends
    /// with resumption material outliving the `Session` that owns it, so the
    /// value is moved rather than lent or cloned, and
    /// [`twinvpn_crypto::EstablishedHandshake`] implements neither `Clone` nor
    /// `Copy` to make that the only option.
    ///
    /// A caller that wants only the traffic keys ignores this entirely;
    /// `NoiseHandshake`'s three methods are unchanged and still return
    /// `Box<dyn TransportKeys>` on their own.
    #[must_use]
    pub fn take_established(&mut self) -> Option<EstablishedHandshake> {
        self.established.take()
    }

    /// P-1's cross-check: the caller's 83 bytes must be the ones this binding
    /// was built with.
    fn agree_on_prologue(&self, prologue: &Prologue) -> Result<(), CryptoUnavailable> {
        if prologue.as_bytes() == &self.prologue {
            Ok(())
        } else {
            Err(CryptoUnavailable)
        }
    }

    /// Converts a finished handshake into transport keys, checking the peer.
    ///
    /// The order is the security property: the peer static is compared **before**
    /// any key material escapes, so a handshake that completed against the wrong
    /// device yields nothing — §7.3.1's "a mismatch fails the handshake without
    /// producing key-derivation output", applied to the identity binding.
    fn finish(&mut self) -> Result<Box<dyn TransportKeys>, CryptoUnavailable> {
        let handshake = self.handshake.take().ok_or(CryptoUnavailable)?;
        if !handshake.is_finished() {
            return Err(CryptoUnavailable);
        }
        if handshake.remote_static() != Some(&self.expected_peer[..]) {
            return Err(CryptoUnavailable);
        }
        let mut hash = [0u8; 32];
        let observed = handshake.handshake_hash();
        if observed.len() != hash.len() {
            return Err(CryptoUnavailable);
        }
        hash.copy_from_slice(observed);
        // `split` rather than `into_transport`: the transport session is keyed
        // identically either way — `snow`'s `split_raw` only reads the chaining
        // key — and the second half is ADR-0001 §7.3.2's authenticated
        // handshake result, which `twinvpn-core` arms resumption from. It is
        // captured here because this is the one place the `Handshake` is
        // consumed, and it is captured only on the path where the peer static
        // has already been checked, so it can never name a device this binding
        // refused.
        let (session, established) = handshake.split().map_err(|_| CryptoUnavailable)?;
        self.handshake_hash = Some(hash);
        self.established = Some(established);
        Ok(Box::new(SessionKeys::new(session)))
    }
}

impl core::fmt::Debug for NoiseBinding {
    /// Redacted by omission: the prologue, the peer static and the handshake
    /// hash are derived from key or identity material, and `ownership.md` §6
    /// rule 11 keeps them out of a log. The role and liveness are the
    /// diagnostic facts.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NoiseBinding")
            .field("role", &self.role)
            .field("live", &self.handshake.is_some())
            .field("completed", &self.handshake_hash.is_some())
            // Whether the resumption half is still here, never what it holds:
            // `EstablishedHandshake`'s own `Debug` redacts the secret, and this
            // one does not reach for it at all.
            .field("resumption_material_held", &self.established.is_some())
            .finish_non_exhaustive()
    }
}

impl NoiseHandshake for NoiseBinding {
    fn write_initiation(
        &mut self,
        prologue: &Prologue,
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoUnavailable> {
        if self.role != Role::Initiator {
            return Err(CryptoUnavailable);
        }
        self.agree_on_prologue(prologue)?;
        let handshake = self.handshake.as_mut().ok_or(CryptoUnavailable)?;
        write_message(handshake, out)
    }

    fn read_response(
        &mut self,
        message: &[u8],
    ) -> Result<Box<dyn TransportKeys>, CryptoUnavailable> {
        if self.role != Role::Initiator {
            return Err(CryptoUnavailable);
        }
        {
            let handshake = self.handshake.as_mut().ok_or(CryptoUnavailable)?;
            read_message(handshake, message)?;
        }
        self.finish()
    }

    fn read_initiation_write_response(
        &mut self,
        prologue: &Prologue,
        message: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Box<dyn TransportKeys>, CryptoUnavailable> {
        if self.role != Role::Responder {
            return Err(CryptoUnavailable);
        }
        self.agree_on_prologue(prologue)?;
        {
            let handshake = self.handshake.as_mut().ok_or(CryptoUnavailable)?;
            read_message(handshake, message)?;
            // The peer static is learned here and checked here — before the
            // response is written. §7.2's "no response to unauthenticated
            // packets" means a device that is not the expected peer gets
            // silence, not a well-formed message it can measure.
            if handshake.remote_static() != Some(&self.expected_peer[..]) {
                self.handshake = None;
                return Err(CryptoUnavailable);
            }
            write_message(handshake, out)?;
        }
        self.finish()
    }
}

/// Reads one handshake message, bounding the allocation it drives.
///
/// The output buffer is sized from the *message*, which is checked against
/// [`NOISE_MAX_MESSAGE_BYTES`] first — `ownership.md` §6 rule 9's "before any
/// allocation proportional to a declared length".
fn read_message(handshake: &mut Handshake, message: &[u8]) -> Result<(), CryptoUnavailable> {
    if message.is_empty() || message.len() > NOISE_MAX_MESSAGE_BYTES {
        return Err(CryptoUnavailable);
    }
    let mut payload = vec![0u8; message.len()];
    handshake
        .read_message(message, &mut payload)
        .map_err(|_| CryptoUnavailable)?;
    Ok(())
}

/// Writes one handshake message into `out`.
///
/// `out` is cleared first so a caller reusing a buffer cannot emit a message
/// with someone else's bytes appended to it.
fn write_message(handshake: &mut Handshake, out: &mut Vec<u8>) -> Result<(), CryptoUnavailable> {
    out.clear();
    out.resize(NOISE_MAX_MESSAGE_BYTES, 0);
    let n = handshake
        .write_message(&[], out)
        .map_err(|_| CryptoUnavailable)?;
    out.truncate(n);
    Ok(())
}

/// The production [`TransportKeys`]: one `twinvpn-crypto` transport session.
///
/// # Why a `Mutex`
///
/// [`TransportKeys::seal`] and [`TransportKeys::open`] take `&self` — the engine
/// holds the keys behind a shared reference and owns the counter — while
/// `twinvpn_crypto::noise::TransportSession` takes `&mut self`, because it
/// carries its own send counter and its own replay window. The `Mutex` is the
/// smallest thing that reconciles the two; the alternative is duplicating the
/// session's state out here, which is the two-models-of-one-thing shape
/// `ownership.md` W-20 records as a defect class.
///
/// # Two counters, one truth
///
/// The engine's [`crate::replay::SendCounter`] and the session's are both
/// zero-based and both advance by one per record, so they are in lockstep. That
/// is an invariant, not a hope: [`TransportKeys::seal`] **refuses** a counter
/// that is not the one the session is about to issue, so a divergence is a
/// refusal rather than a record sealed under the wrong nonce. Nothing is sealed
/// before the check, so a refusal does not even consume a nonce.
///
/// # Erasure, stated honestly
///
/// [`TransportKeys::zeroize`] calls [`TransportSession::erase`], which
/// **overwrites** the cipher keys in place rather than merely releasing them.
/// This used to be a dropped session and nothing more: `snow` 0.10 implements no
/// `Drop` for its cipher states, so the bytes went back to the allocator intact,
/// and CD-I2 put the fix out of this crate's reach. `twinvpn-crypto` now owns an
/// erasing wrapper — the overwrite goes through `snow`'s own
/// `rekey_manually`, the one public API that writes into the live key
/// allocation — and it runs on `Drop` as well, so an unwind cannot skip it
/// (ADR-0018 §11.3 pins `panic = "unwind"` in every shipped profile).
///
/// **What that does not cover.** The *handshake* state is a different matter:
/// `snow`'s `HandshakeState` holds the local static private key and the
/// ephemeral behind a `Box<dyn Dh>` with no in-place setter, so those bytes are
/// still released unerased. That is an open integration item against `snow`
/// itself, recorded in `twinvpn_crypto`'s `erase` module and in
/// `ownership.md` §8. TM-14 already treats key extraction from process memory as
/// undefended; this narrows the window on the transport keys and does not close
/// it on the handshake ones.
pub struct SessionKeys {
    session: Mutex<Option<TransportSession>>,
}

impl SessionKeys {
    /// Wraps an established session.
    #[must_use]
    pub fn new(session: TransportSession) -> Self {
        Self {
            session: Mutex::new(Some(session)),
        }
    }

    /// Whether the keys are still usable.
    ///
    /// `false` after [`TransportKeys::zeroize`] — ADR-0001 §7.2's
    /// `REJECT_AFTER_TIME` outcome, "keys are unusable and are zeroed".
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.session.lock().is_ok_and(|s| s.is_some())
    }
}

impl core::fmt::Debug for SessionKeys {
    /// Liveness only. The send counter and the replay high-water mark are a
    /// traffic pattern, which `ownership.md` §6 rule 11 keeps out of a bundle.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("live", &self.is_live())
            .finish_non_exhaustive()
    }
}

impl TransportKeys for SessionKeys {
    fn seal(
        &self,
        counter: u64,
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoUnavailable> {
        if plaintext.len() > NOISE_MAX_MESSAGE_BYTES - AEAD_TAG_BYTES {
            return Err(CryptoUnavailable);
        }
        // A poisoned lock means a panic ran inside the session. Fail closed:
        // there is no reading of that state that is safe to seal under.
        let mut guard = self.session.lock().map_err(|_| CryptoUnavailable)?;
        let session = guard.as_mut().ok_or(CryptoUnavailable)?;
        if session.send_counter().sent() != counter {
            return Err(CryptoUnavailable);
        }
        out.clear();
        out.resize(plaintext.len() + AEAD_TAG_BYTES, 0);
        let (nonce, n) = session.seal(plaintext, out).map_err(|_| {
            // The counter was not consumed on a refusal, so the buffer must not
            // be left holding a half-written record.
            CryptoUnavailable
        })?;
        if nonce != counter {
            out.clear();
            return Err(CryptoUnavailable);
        }
        out.truncate(n);
        Ok(())
    }

    fn open(
        &self,
        counter: u64,
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoUnavailable> {
        // Bounded before the allocation, and a record shorter than the tag
        // cannot be one — checking that here is what keeps the length
        // arithmetic below from underflowing on attacker-chosen input.
        if ciphertext.len() < AEAD_TAG_BYTES || ciphertext.len() > NOISE_MAX_MESSAGE_BYTES {
            return Err(CryptoUnavailable);
        }
        let mut guard = self.session.lock().map_err(|_| CryptoUnavailable)?;
        let session = guard.as_mut().ok_or(CryptoUnavailable)?;
        out.clear();
        out.resize(ciphertext.len() - AEAD_TAG_BYTES, 0);
        let n = session.open(counter, ciphertext, out).map_err(|_| {
            out.clear();
            CryptoUnavailable
        })?;
        out.truncate(n);
        Ok(())
    }

    fn zeroize(&mut self) {
        // `Mutex::get_mut` needs no lock and cannot fail on poison, which is
        // what makes erasure reachable even after a panic inside the session.
        if let Ok(slot) = self.session.get_mut() {
            // Erase BEFORE dropping. `*slot = None` alone would rely on the
            // destructor, which does run the same overwrite, but calling it here
            // makes the erasure a statement in this crate rather than a
            // property of another crate's `Drop` that a refactor could silently
            // remove.
            if let Some(session) = slot.as_mut() {
                session.erase();
            }
            *slot = None;
        }
    }
}

/// The production [`Transcript`], over `twinvpn-crypto`'s SHA-256.
///
/// A unit struct because it holds nothing: both hashes are pure functions of
/// their inputs, and a transcript that carried state would be a transcript that
/// could disagree with itself between two calls.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoiseTranscript;

impl Transcript for NoiseTranscript {
    fn half_advertisement_hash(&self, canonical_cbor: &[u8]) -> [u8; 32] {
        twinvpn_crypto::kdf::sha256_parts(&[NEG_HALF_LABEL, canonical_cbor])
    }

    fn negotiation_hash(
        &self,
        h_initiator: &[u8; 32],
        h_responder: &[u8; 32],
        canonical_selection_cbor: &[u8],
    ) -> [u8; 32] {
        // `twinvpn_crypto::prologue::NegotiationBinding::hash` computes exactly
        // this and would have been the obvious call — but it owns its
        // `selection_dcbor` as a `Vec`, so reaching it copies a peer-supplied
        // slice, and this trait has no error with which to refuse an over-long
        // one. Hashing the borrowed slice allocates nothing an untrusted input
        // can drive (`ownership.md` §6 rule 10). The label is `twinvpn-crypto`'s
        // own constant, and `the_negotiation_hash_agrees_with_twinvpn_cryptos_own`
        // pins the two formulas against each other so they cannot drift.
        twinvpn_crypto::kdf::sha256_parts(&[
            NEG_LABEL,
            h_initiator,
            h_responder,
            canonical_selection_cbor,
        ])
    }
}

/// Builds a live [`Tunnel`] from a completed handshake's keys.
///
/// This is the path that did not exist. [`Tunnel::absent`] stays — the engine
/// tests build from it, and `TunnelState::Absent` is a real state a `Session`
/// passes through — but a caller that has *finished* a handshake now has
/// somewhere to put the result other than a test.
///
/// The tunnel comes back in [`crate::engine::TunnelState::Confirming`], not
/// `Established`: N-8 makes `NegotiationConfirm` the first in-session message,
/// and N-9 names the gap between "keys exist" and "the transcript matched" so it
/// is observable rather than implicit. [`Tunnel::confirm_negotiation`] is the
/// way out, and a mismatch there is `PROTO.TRANSCRIPT_MISMATCH` — a security
/// event, not a network error.
#[must_use]
pub fn establish_tunnel(
    id: TunnelId,
    session: SessionId,
    keys: Box<dyn TransportKeys>,
    endpoint: Endpoint,
    trust_epoch: u64,
    now: MonotonicInstant,
) -> Tunnel {
    let mut tunnel = Tunnel::absent(id, session, now);
    tunnel.handshake_completed(keys, endpoint, trust_epoch, now);
    tunnel
}
