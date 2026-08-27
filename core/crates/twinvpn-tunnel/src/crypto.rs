//! The crypto boundary: every operation this engine **drives** and none it
//! implements.
//!
//! **Authority:** ADR-0001 §7.2 and §11, ADR-0018 CD-I2,
//! `docs/implementation/ownership.md` §6 ("Do not invent cryptographic
//! primitives").
//!
//! # This is the whole list, and it is deliberate
//!
//! CD-I2 makes `twinvpn-crypto` the only crate permitted a cryptographic
//! dependency, and `cargo run -p xtask -- lint` fails the build if this one
//! declares `snow`, `x25519-dalek`, `chacha20poly1305`, `blake2` or any of their
//! siblings. So every primitive arrives through one of the traits below, and the
//! engine here does scheduling, counters, replay windows and state — never
//! arithmetic on a key.
//!
//! **Integration items.** `twinvpn-crypto` supplies implementations of
//! [`NoiseHandshake`], [`TransportKeys`] and [`Transcript`]. The exact shapes are
//! listed in this crate's report so the integration lead can reconcile them
//! against what `core-security` built.

use twinvpn_types::TypeError;

/// The 83-byte handshake prologue ADR-0001 §7.3.1 P-1 fixes.
///
/// > The `prologue` MUST be exactly the 83-byte concatenation above. No other
/// > document may define, extend, or reorder it.
///
/// P-3: it "is a local hash input and is **never transmitted**", so this type
/// carries it and nothing serialises it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Prologue([u8; Prologue::LEN]);

impl Prologue {
    /// 19 + 32 + 32.
    pub const LEN: usize = 83;
    /// The fixed label.
    pub const LABEL: &'static [u8; 19] = b"TWINVPN-PROLOGUE-v1";

    /// Assembles the prologue from the two contributed digests.
    ///
    /// ADR-0007 N-20 contributes `identity_binding_hash`; ADR-0014 N-6
    /// contributes `negotiation_hash`. **Neither defines the field**, and this
    /// constructor is the only way to build one.
    #[must_use]
    pub fn new(identity_binding_hash: [u8; 32], negotiation_hash: [u8; 32]) -> Self {
        let mut out = [0u8; Self::LEN];
        out[..19].copy_from_slice(Self::LABEL);
        out[19..51].copy_from_slice(&identity_binding_hash);
        out[51..83].copy_from_slice(&negotiation_hash);
        Self(out)
    }

    /// The bytes, for the handshake's `prologue` input only.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl core::fmt::Debug for Prologue {
    /// Redacted: it is derived from identity and negotiation material and never
    /// leaves the device.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Prologue(<83 B redacted>)")
    }
}

/// The `Noise_IKpsk2` handshake, supplied by `twinvpn-crypto`.
///
/// ADR-0001 §11: L-DATA is **unmodified WireGuard** `Noise_IKpsk2` — X25519,
/// ChaCha20-Poly1305, BLAKE2s — "end-to-end between devices and terminated by no
/// infrastructure component".
pub trait NoiseHandshake: Send + Sync {
    /// Writes the 148-byte initiation, given the prologue and the `psk2` slot.
    ///
    /// # Errors
    ///
    /// [`CryptoUnavailable`] when key material is not available. **Never** falls
    /// back to an unauthenticated or PSK-less handshake.
    fn write_initiation(
        &mut self,
        prologue: &Prologue,
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoUnavailable>;

    /// Consumes a 92-byte response and derives the transport keys.
    ///
    /// # Errors
    ///
    /// [`CryptoUnavailable`] on any authentication failure. A failed handshake
    /// produces **no session keys** — §7.3.1: "a mismatch fails the handshake
    /// without producing key-derivation output".
    fn read_response(
        &mut self,
        message: &[u8],
    ) -> Result<Box<dyn TransportKeys>, CryptoUnavailable>;

    /// Consumes an initiation and writes the response, for the responder role.
    ///
    /// # Errors
    ///
    /// As [`Self::read_response`].
    fn read_initiation_write_response(
        &mut self,
        prologue: &Prologue,
        message: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Box<dyn TransportKeys>, CryptoUnavailable>;
}

/// One handshake's worth of transport keys: **one send key and one receive key**,
/// independent per direction.
///
/// The engine never sees the key bytes. It sees a sealer and an opener and a
/// counter, which is all the L-DATA data path needs.
pub trait TransportKeys: Send + Sync {
    /// Seals one L-DATA payload under the send key at `counter`.
    ///
    /// The nonce is the 64-bit counter, per RFC 8439 as WireGuard uses it. The
    /// engine owns the counter — [`crate::replay::SendCounter`] — because the
    /// counter's exhaustion bound is a *scheduling* decision.
    ///
    /// # Errors
    ///
    /// [`CryptoUnavailable`] when the keys have been zeroed.
    fn seal(
        &self,
        counter: u64,
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoUnavailable>;

    /// Opens one L-DATA payload under the receive key.
    ///
    /// # Errors
    ///
    /// [`CryptoUnavailable`] on any authentication failure. A failed open is a
    /// **drop**, never a degraded accept.
    fn open(
        &self,
        counter: u64,
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoUnavailable>;

    /// Zeroes the key material.
    ///
    /// Called at `REJECT_AFTER_TIME` — §7.2: "keys are unusable and are
    /// **zeroed**".
    fn zeroize(&mut self);
}

/// The two 32-byte digests §7.3.1 mixes into the prologue, and §7.3 D2's
/// confirmation hash.
///
/// ADR-0014 N-8 makes `NegotiationConfirm` "the FIRST in-session message each
/// peer sends", and D2 makes a mismatch a teardown with
/// `PROTO.TRANSCRIPT_MISMATCH` — "a **security event**, not a network error".
pub trait Transcript: Send + Sync {
    /// `SHA-256("TWINVPN-NEG-HALF-v1" || dCBOR(HalfAdvertisement))`.
    fn half_advertisement_hash(&self, canonical_cbor: &[u8]) -> [u8; 32];

    /// `SHA-256("TWINVPN-NEG-v1" || H_initiator || H_responder ||
    /// dCBOR(Selection))`.
    fn negotiation_hash(
        &self,
        h_initiator: &[u8; 32],
        h_responder: &[u8; 32],
        canonical_selection_cbor: &[u8],
    ) -> [u8; 32];
}

/// The one error every crypto operation returns.
///
/// Deliberately carries no detail: a distinguishable failure is an oracle, and
/// ADR-0001 §7.2's "no response to unauthenticated packets" is the same idea one
/// layer up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("cryptographic material is unavailable or authentication failed")]
pub struct CryptoUnavailable;

impl From<TypeError> for CryptoUnavailable {
    fn from(_: TypeError) -> Self {
        CryptoUnavailable
    }
}
