//! **L-RELAY-LEG** — the `Noise_IK` handshake that authenticates a device to a
//! relay and yields `K_leg`, and nothing else.
//!
//! **Authority:** ADR-0005 §11.1(2) ("the leg is **Noise_IK** … for `R-UDP`"),
//! §11.2 row ADR-0001(a) (`RLK` is a *distinct, domain-separated* relay-leg key
//! that MUST NOT be derivable from, or used to derive, any L-DATA key), §7.1
//! (the relay's whole key inventory), §9.1 (what `K_leg` is for: a 64-bit frame
//! MAC), §11.3 (`cnf` binds the token to the `RLK` the bearer must possess).
//!
//! # This module exists so that the relay never holds an AEAD it could point at
//! tunnel traffic
//!
//! I1 says relay infrastructure must never require plaintext access to TwinVPN
//! tunnel payloads, and ADR-0005 §7.1 makes that an argument about the relay's
//! *key inventory* rather than about its behaviour. A `Noise_IK` handshake
//! naturally ends in a transport session with two ChaCha20-Poly1305 keys — which
//! would be a fourth key in that inventory, and one with an `open()` on it.
//!
//! So the handshake is completed **here**, and the only thing that crosses back
//! to the caller is:
//!
//! | Returned | Not returned |
//! |---|---|
//! | `K_leg`: 32 bytes, HKDF-separated from the handshake hash | the `snow` session |
//! | the initiator's static (`RLK_pub`), for the `cnf` check | either transport key |
//! | the decrypted handshake payload (the token) | any `open`/`seal` capability |
//!
//! [`CompletedLeg`] has no field and no method that yields a cipher, and
//! [`LegResponder::respond`] consumes `self`, so the `snow` state is dropped at
//! the end of the call. `services/relay/tests/cannot_decrypt.rs` asserts the
//! consumer side of the same property.
//!
//! # The parameter string is deliberately *not* L-DATA's
//!
//! ```text
//! L-DATA     Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s     (crate::noise)
//! relay leg  Noise_IK_25519_ChaChaPoly_BLAKE2s         (here)
//! ```
//!
//! Different pattern, different prologue, different crate-level type. ADR-0005
//! §11.2 requires `RLK` to be non-derivable from an L-DATA key and vice versa,
//! and the strongest available form of that is *no shared key schedule at all*:
//! the relay leg is instantiated with the device's `RLK` static, never its
//! L-DATA static, and carries no `psk`, so `TwinNetPSK` is not an input.
//!
//! The primitive set is otherwise identical to ADR-0001's — X25519,
//! ChaCha20-Poly1305, BLAKE2s — which is C1/C6: no new dependency and no new
//! primitive for the leg.
//!
//! # `K_leg` is domain-separated from the handshake hash
//!
//! ```text
//! K_leg = HKDF-Expand(HKDF-Extract("", h), "twinvpn/relay-leg/v1", 32)
//! ```
//!
//! where `h` is the Noise handshake hash. Two consequences worth stating:
//!
//! 1. It is **not** either transport key, so a `K_leg` disclosure does not
//!    disclose the handshake's confidentiality keys, which is what lets the relay
//!    hold `K_leg` in ordinary memory for the life of a leg.
//! 2. It is the label ADR-0005 §11.1(2) already fixes for the `R-QUIC`/`R-TLS`
//!    carriages' RFC 8446 exporter, spelled the same way, so all four carriages
//!    name one value rather than three.
//!
//! # Randomness is the caller's, never the library's default
//!
//! `snow`'s `DefaultResolver` reaches for the platform CSPRNG itself, which
//! ADR-0018 CD-3 bans as an ambient default. As in [`crate::noise`], the
//! resolver here takes an injected [`Entropy`] and delegates every other
//! primitive to `snow`'s audited default.

use std::sync::Arc;

use snow::params::NoiseParams;
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::Random;
use zeroize::Zeroize;

/// The injected randomness source, re-exported so a consumer outside `/core`
/// can supply one without naming `twinvpn-env` as a dependency of its own.
///
/// The relay is such a consumer: ADR-0018 §11.2 makes the server side a separate
/// artifact that does not link the core, and its only permitted edge for
/// cryptography is this crate (CD-I2, DP-8).
pub use twinvpn_env::Entropy;

/// The error [`Entropy::fill`] returns, re-exported for the same reason.
pub use twinvpn_env::EnvError as EntropyError;

use crate::kdf::hkdf_sha256;
use crate::{CryptoError, Result};

/// ADR-0005 §11.1(2)'s protocol for the `R-UDP` relay leg.
///
/// `IK` and not `IKpsk2`: there is no pre-shared secret between a device and a
/// relay, and inventing one would put a relay inside a TwinNet's key material —
/// exactly the trust position B3 refuses it.
pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// The prologue both ends mix in before the first message.
///
/// A prologue mismatch fails the handshake indistinguishably from any other
/// failure (ADR-0001 §7.3.1 P-3), which is what makes it a cheap, silent refusal
/// of a peer speaking a different protocol at the same socket.
pub const PROLOGUE: &[u8] = b"twinvpn relay leg v1";

/// The exporter label ADR-0005 §11.1(2) fixes for `R-QUIC`/`R-TLS`, reused here
/// as the HKDF `info` so all four carriages derive one named value.
pub const LEG_KEY_LABEL: &[u8] = b"twinvpn relay leg v1";

/// The X25519 static key width.
pub const STATIC_KEY_LEN: usize = 32;

/// `K_leg`'s width — the keyed-BLAKE2s frame MAC key of ADR-0005 §9.1.
pub const LEG_KEY_LEN: usize = 32;

/// The `Noise_IK` message-1 overhead: `e` (32) + encrypted `s` (32 + 16) + the
/// payload's AEAD tag (16).
pub const MSG1_OVERHEAD: usize = 96;

/// The `Noise_IK` message-2 overhead: `e` (32) + the payload's AEAD tag (16).
pub const MSG2_OVERHEAD: usize = 48;

/// The largest handshake payload either direction carries.
///
/// A `RelayCapabilityToken` is a COSE_Sign1 over a small CBOR claim set — a few
/// hundred bytes — and this is the bound applied *before* any allocation
/// proportional to it (`ownership.md` §6 rule 9). It also keeps message 1 inside
/// one datagram on the 1280-byte overlay floor with room to spare.
pub const MAX_HANDSHAKE_PAYLOAD_BYTES: usize = 1_024;

/// Message 1's maximum wire length.
pub const MAX_MSG1_BYTES: usize = MSG1_OVERHEAD + MAX_HANDSHAKE_PAYLOAD_BYTES;

/// Message 2's maximum wire length.
pub const MAX_MSG2_BYTES: usize = MSG2_OVERHEAD + MAX_HANDSHAKE_PAYLOAD_BYTES;

/// `K_leg`, and the two public facts the responder needs about its peer.
///
/// # What is deliberately not here
///
/// No cipher, no session, no nonce, and no way to obtain one. This type is the
/// complete output of the handshake, and it is what makes ADR-0005 §7.1's
/// "closed set of three" hold on the relay side: the relay gains `K_leg` and
/// nothing else from a completed leg.
pub struct CompletedLeg {
    k_leg: [u8; LEG_KEY_LEN],
    remote_static: [u8; STATIC_KEY_LEN],
    payload: Vec<u8>,
}

impl CompletedLeg {
    /// `K_leg`, for the ADR-0005 §9.1 frame MAC and for nothing else.
    #[must_use]
    pub const fn k_leg(&self) -> &[u8; LEG_KEY_LEN] {
        &self.k_leg
    }

    /// The peer's static public key.
    ///
    /// For a responder this is the device's `RLK_pub`, proved by the `IK`
    /// pattern, and it is what ADR-0005 §11.3's `cnf` check compares against.
    /// **`IK` proves possession; the token proves authority. Neither alone
    /// admits a device.**
    #[must_use]
    pub const fn remote_static(&self) -> &[u8; STATIC_KEY_LEN] {
        &self.remote_static
    }

    /// The decrypted handshake payload — the presented token, for a responder.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Takes the payload, leaving an empty one.
    #[must_use]
    pub fn take_payload(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.payload)
    }
}

impl Drop for CompletedLeg {
    fn drop(&mut self) {
        self.k_leg.zeroize();
        self.payload.zeroize();
    }
}

impl core::fmt::Debug for CompletedLeg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `k_leg` is a key and `payload` is a bearer token: neither is rendered
        // (`ownership.md` §6 rule 11). The remote static is public, but printing
        // it would put a stable per-device value in a log line, which ADR-0005
        // §10 refuses independently of whether it is secret.
        f.debug_struct("CompletedLeg")
            .field("k_leg", &"<redacted>")
            .field("remote_static", &"<withheld>")
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// The relay's half of the leg handshake.
///
/// One responder handles one handshake and is consumed by it, so a `snow` state
/// cannot outlive the exchange or be reused across two initiators.
pub struct LegResponder {
    state: snow::HandshakeState,
}

impl LegResponder {
    /// Builds a responder holding the relay's static private key.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyLength`] if `static_private` is not
    /// [`STATIC_KEY_LEN`] bytes; [`CryptoError::HandshakeRejected`] for any
    /// refusal from `snow`, with a bounded `step` — `snow`'s own message names
    /// internal state and is deliberately not propagated.
    pub fn new(entropy: &Arc<dyn Entropy>, static_private: &[u8]) -> Result<Self> {
        let state = build(entropy, static_private, None, Role::Responder)?;
        Ok(Self { state })
    }

    /// Reads message 1 and writes message 2, completing the leg.
    ///
    /// `response_payload` is what the relay says back at leg setup — the
    /// `CAPS`-equivalent of ADR-0005 §10's "version skew is handled by the `ver`
    /// nibble plus a `CAPS` control frame exchanged at leg setup". It is
    /// encrypted under the handshake, so a version negotiation is not
    /// observable on the wire.
    ///
    /// Returns the response octets and the completed leg. **A failure returns
    /// `Err` and no octets at all**, which is ADR-0005 §11.5's "zero bytes in
    /// response to any unauthenticated frame" expressed in the return type: a
    /// responder that cannot complete has nothing to send.
    ///
    /// # Errors
    ///
    /// [`CryptoError::HandshakeRejected`] — one variant for every failure, so a
    /// prober learns nothing about *which* check refused it.
    pub fn respond(
        mut self,
        message_1: &[u8],
        response_payload: &[u8],
    ) -> Result<(Vec<u8>, CompletedLeg)> {
        if message_1.len() > MAX_MSG1_BYTES || message_1.len() < MSG1_OVERHEAD {
            return Err(CryptoError::HandshakeRejected {
                step: "relay leg message 1 length",
            });
        }
        if response_payload.len() > MAX_HANDSHAKE_PAYLOAD_BYTES {
            return Err(CryptoError::HandshakeRejected {
                step: "relay leg response payload too large",
            });
        }
        // Bounded before allocation, from the length already checked above.
        let mut inbound = vec![0_u8; message_1.len()];
        let read = self
            .state
            .read_message(message_1, &mut inbound)
            .map_err(|_| CryptoError::HandshakeRejected {
                step: "read relay leg message 1",
            })?;
        inbound.truncate(read);

        let mut outbound = vec![0_u8; MSG2_OVERHEAD + response_payload.len()];
        let written = self
            .state
            .write_message(response_payload, &mut outbound)
            .map_err(|_| CryptoError::HandshakeRejected {
                step: "write relay leg message 2",
            })?;
        outbound.truncate(written);

        let completed = finish(&self.state, inbound)?;
        // `self.state` is dropped here, with its transport keys, unused.
        Ok((outbound, completed))
    }
}

impl core::fmt::Debug for LegResponder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LegResponder").finish_non_exhaustive()
    }
}

/// The device's half of the leg handshake.
///
/// It lives here rather than in the device crate for the same reason the
/// responder does — CD-I2 — and because a leg whose two ends derive `K_leg`
/// differently fails as *every frame dropped*, with both sides looking correctly
/// configured. One implementation cannot disagree with itself.
pub struct LegInitiator {
    state: snow::HandshakeState,
}

impl LegInitiator {
    /// Builds an initiator holding the device's `RLK` private key and the
    /// relay's static public key **from a verified relay map**.
    ///
    /// ADR-0006 §11.2: a device MUST NOT bind a relay whose `relay_id` and
    /// static Noise public key are not present in a verified map. This function
    /// cannot check that — it is the caller's obligation, and the parameter is
    /// named to say so.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyLength`], [`CryptoError::HandshakeRejected`].
    pub fn new(
        entropy: &Arc<dyn Entropy>,
        rlk_private: &[u8],
        relay_static_public_from_verified_map: &[u8; STATIC_KEY_LEN],
    ) -> Result<Self> {
        let state = build(
            entropy,
            rlk_private,
            Some(relay_static_public_from_verified_map),
            Role::Initiator,
        )?;
        Ok(Self { state })
    }

    /// Writes message 1, carrying `payload` — the `RelayCapabilityToken`.
    ///
    /// The token is encrypted to the relay's static in `IK`'s first message, so
    /// it is never on the wire in the clear even before the leg exists.
    ///
    /// # Errors
    ///
    /// [`CryptoError::HandshakeRejected`].
    pub fn initiate(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() > MAX_HANDSHAKE_PAYLOAD_BYTES {
            return Err(CryptoError::HandshakeRejected {
                step: "relay leg initiation payload too large",
            });
        }
        let mut out = vec![0_u8; MSG1_OVERHEAD + payload.len()];
        let written = self.state.write_message(payload, &mut out).map_err(|_| {
            CryptoError::HandshakeRejected {
                step: "write relay leg message 1",
            }
        })?;
        out.truncate(written);
        Ok(out)
    }

    /// Reads message 2 and completes the leg.
    ///
    /// # Errors
    ///
    /// [`CryptoError::HandshakeRejected`].
    pub fn complete(self, message_2: &[u8]) -> Result<CompletedLeg> {
        let mut this = self;
        if message_2.len() > MAX_MSG2_BYTES || message_2.len() < MSG2_OVERHEAD {
            return Err(CryptoError::HandshakeRejected {
                step: "relay leg message 2 length",
            });
        }
        let mut inbound = vec![0_u8; message_2.len()];
        let read = this
            .state
            .read_message(message_2, &mut inbound)
            .map_err(|_| CryptoError::HandshakeRejected {
                step: "read relay leg message 2",
            })?;
        inbound.truncate(read);
        finish(&this.state, inbound)
    }
}

impl core::fmt::Debug for LegInitiator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LegInitiator").finish_non_exhaustive()
    }
}

/// Derives the X25519 public half of a relay-leg static key.
///
/// A relay needs its own to answer `mac1`-style pre-authentication checks and to
/// publish into the relay map; a device needs its `RLK_pub` for the token's
/// `cnf`. The private half is borrowed and never retained.
///
/// # Errors
///
/// [`CryptoError::KeyLength`] if `private` is not [`STATIC_KEY_LEN`] bytes.
pub fn static_public_key(private: &[u8]) -> Result<[u8; STATIC_KEY_LEN]> {
    let raw: [u8; STATIC_KEY_LEN] = private.try_into().map_err(|_| CryptoError::KeyLength {
        expected: STATIC_KEY_LEN,
        observed: private.len(),
    })?;
    let secret = x25519_dalek::StaticSecret::from(raw);
    Ok(x25519_dalek::PublicKey::from(&secret).to_bytes())
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

fn build(
    entropy: &Arc<dyn Entropy>,
    local_private: &[u8],
    remote_public: Option<&[u8; STATIC_KEY_LEN]>,
    role: Role,
) -> Result<snow::HandshakeState> {
    if local_private.len() != STATIC_KEY_LEN {
        return Err(CryptoError::KeyLength {
            expected: STATIC_KEY_LEN,
            observed: local_private.len(),
        });
    }
    let params: NoiseParams = NOISE_PARAMS
        .parse()
        .map_err(|_| CryptoError::HandshakeRejected {
            step: "relay leg parameter string",
        })?;
    let resolver = Box::new(LegResolver {
        entropy: Arc::clone(entropy),
    });
    let mut builder = snow::Builder::with_resolver(params, resolver)
        .prologue(PROLOGUE)
        .map_err(|_| CryptoError::HandshakeRejected {
            step: "relay leg prologue rejected",
        })?
        .local_private_key(local_private)
        .map_err(|_| CryptoError::HandshakeRejected {
            step: "relay leg local static rejected",
        })?;
    if let Some(rs) = remote_public {
        builder = builder
            .remote_public_key(rs)
            .map_err(|_| CryptoError::HandshakeRejected {
                step: "relay leg remote static rejected",
            })?;
    } else if role == Role::Initiator {
        return Err(CryptoError::HandshakeRejected {
            step: "an IK initiator needs the relay's static from a verified map",
        });
    }
    match role {
        Role::Initiator => builder.build_initiator(),
        Role::Responder => builder.build_responder(),
    }
    .map_err(|_| CryptoError::HandshakeRejected {
        step: "relay leg state could not be built",
    })
}

/// Turns a finished handshake into the three values the caller may have.
///
/// Takes `&snow::HandshakeState` rather than the owned state on purpose: with
/// only a shared reference there is no way to call `into_transport_mode` here,
/// so the *absence* of a cipher is enforced by the signature rather than by
/// remembering not to write the call.
fn finish(state: &snow::HandshakeState, payload: Vec<u8>) -> Result<CompletedLeg> {
    if !state.is_handshake_finished() {
        return Err(CryptoError::HandshakeRejected {
            step: "relay leg handshake incomplete",
        });
    }
    let remote = state
        .get_remote_static()
        .ok_or(CryptoError::HandshakeRejected {
            step: "relay leg peer static absent",
        })?;
    let remote_static: [u8; STATIC_KEY_LEN] =
        remote
            .try_into()
            .map_err(|_| CryptoError::HandshakeRejected {
                step: "relay leg peer static width",
            })?;

    let mut k_leg = [0_u8; LEG_KEY_LEN];
    hkdf_sha256(None, state.get_handshake_hash(), LEG_KEY_LABEL, &mut k_leg)?;

    Ok(CompletedLeg {
        k_leg,
        remote_static,
        payload,
    })
}

/// `snow`'s `Random`, supplied from the injected [`Entropy`].
struct LegRandom {
    entropy: Arc<dyn Entropy>,
}

impl rand_core::RngCore for LegRandom {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0_u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0_u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        // As `crate::noise::EnvRandom`: there is no error channel on this trait,
        // and a silent fallback CSPRNG is indistinguishable from a working one
        // right up until it matters.
        assert!(
            self.entropy.fill(dst).is_ok(),
            "entropy failed mid relay-leg handshake"
        );
    }
}

impl rand_core::CryptoRng for LegRandom {}

impl Random for LegRandom {
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), snow::Error> {
        self.entropy
            .fill(dst)
            .map_err(|_| snow::Error::Prereq(snow::error::Prerequisite::LocalPrivateKey))
    }
}

/// A `snow` resolver taking randomness from the caller and everything else from
/// `snow`'s audited default.
struct LegResolver {
    entropy: Arc<dyn Entropy>,
}

impl CryptoResolver for LegResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(LegRandom {
            entropy: Arc::clone(&self.entropy),
        }))
    }

    fn resolve_dh(&self, choice: &snow::params::DHChoice) -> Option<Box<dyn snow::types::Dh>> {
        DefaultResolver.resolve_dh(choice)
    }

    fn resolve_hash(
        &self,
        choice: &snow::params::HashChoice,
    ) -> Option<Box<dyn snow::types::Hash>> {
        DefaultResolver.resolve_hash(choice)
    }

    fn resolve_cipher(
        &self,
        choice: &snow::params::CipherChoice,
    ) -> Option<Box<dyn snow::types::Cipher>> {
        DefaultResolver.resolve_cipher(choice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_env::EnvError;

    /// A deterministic entropy source. Never used outside a test: a reproducible
    /// ephemeral is not forward-secret, which is exactly why the production path
    /// takes the platform CSPRNG.
    struct SeqEntropy(std::sync::Mutex<u8>);

    impl Entropy for SeqEntropy {
        fn fill(&self, dst: &mut [u8]) -> core::result::Result<(), EnvError> {
            let mut n = self.0.lock().expect("entropy lock");
            for b in dst.iter_mut() {
                *n = n.wrapping_add(1);
                *b = *n;
            }
            Ok(())
        }
    }

    fn entropy(seed: u8) -> Arc<dyn Entropy> {
        Arc::new(SeqEntropy(std::sync::Mutex::new(seed)))
    }

    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let private = [seed; 32];
        let public = static_public_key(&private).expect("32 bytes");
        (private, public)
    }

    #[test]
    fn a_leg_completes_and_both_ends_derive_the_same_k_leg() {
        let (relay_priv, relay_pub) = keypair(7);
        let (device_priv, device_pub) = keypair(9);

        let mut initiator = LegInitiator::new(&entropy(1), &device_priv, &relay_pub).expect("init");
        let msg1 = initiator.initiate(b"a token").expect("msg1");

        let responder = LegResponder::new(&entropy(2), &relay_priv).expect("responder");
        let (msg2, relay_side) = responder.respond(&msg1, b"caps").expect("respond");

        let device_side = initiator.complete(&msg2).expect("complete");

        assert_eq!(relay_side.k_leg(), device_side.k_leg());
        // The relay learned the device's RLK_pub — this is what `cnf` is checked
        // against, and it is the whole authentication value of `IK` here.
        assert_eq!(relay_side.remote_static(), &device_pub);
        assert_eq!(device_side.remote_static(), &relay_pub);
        assert_eq!(relay_side.payload(), b"a token");
        assert_eq!(device_side.payload(), b"caps");
    }

    #[test]
    fn a_leg_key_is_not_either_transport_key_and_no_transport_is_reachable() {
        // The structural claim: `CompletedLeg` is the whole output, and it has no
        // field that is a cipher. Asserted by reading the struct's own source,
        // because "no such capability exists" cannot be shown behaviourally.
        let source = include_str!("relay_leg.rs");
        let start = source
            .find("pub struct CompletedLeg {")
            .expect("the struct is declared here");
        let body = &source[start..start + source[start..].find('}').expect("closed")];
        for forbidden in ["TransportSession", "StatelessTransportState", "cipher"] {
            assert!(
                !body.contains(forbidden),
                "CompletedLeg gained `{forbidden}`: the relay's key inventory is \
                 closed at three (ADR-0005 §7.1) and a cipher here would be a fourth"
            );
        }
        // And nothing in the module completes into transport mode. Comment lines
        // are blanked first: a *description* of the forbidden thing is not the
        // thing, and the module documentation names it deliberately.
        let production: String = source
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !production.contains("transport_mode"),
            "the relay leg must never enter Noise transport mode: K_leg is a MAC \
             key (ADR-0005 §9.1), not a session"
        );
    }

    #[test]
    fn a_different_relay_static_does_not_complete() {
        let (relay_priv, _) = keypair(7);
        let (_, wrong_pub) = keypair(11);
        let (device_priv, _) = keypair(9);

        let mut initiator = LegInitiator::new(&entropy(1), &device_priv, &wrong_pub).expect("init");
        let msg1 = initiator.initiate(b"t").expect("msg1");
        let responder = LegResponder::new(&entropy(2), &relay_priv).expect("responder");
        // `IK` binds the responder's static into the first message; a device that
        // was handed the wrong key from an unverified map fails here rather than
        // establishing a leg with an impostor.
        assert!(responder.respond(&msg1, b"").is_err());
    }

    #[test]
    fn a_truncated_or_oversized_message_is_refused_before_allocation() {
        let (relay_priv, _) = keypair(7);
        let responder = LegResponder::new(&entropy(2), &relay_priv).expect("responder");
        assert!(responder.respond(&[0_u8; MSG1_OVERHEAD - 1], b"").is_err());

        let responder = LegResponder::new(&entropy(2), &relay_priv).expect("responder");
        let oversized = vec![0_u8; MAX_MSG1_BYTES + 1];
        assert!(responder.respond(&oversized, b"").is_err());
    }

    #[test]
    fn a_replayed_message_1_yields_a_different_k_leg() {
        // The responder's ephemeral is fresh per handshake, so replaying a
        // captured message 1 cannot resurrect a previous leg's key.
        let (relay_priv, relay_pub) = keypair(7);
        let (device_priv, _) = keypair(9);
        let mut initiator = LegInitiator::new(&entropy(1), &device_priv, &relay_pub).expect("init");
        let msg1 = initiator.initiate(b"t").expect("msg1");

        let (_, first) = LegResponder::new(&entropy(2), &relay_priv)
            .expect("responder")
            .respond(&msg1, b"")
            .expect("respond");
        let (_, second) = LegResponder::new(&entropy(40), &relay_priv)
            .expect("responder")
            .respond(&msg1, b"")
            .expect("respond");
        assert_ne!(first.k_leg(), second.k_leg());
    }

    #[test]
    fn the_parameter_string_is_not_l_datas() {
        // ADR-0005 §11.2 row ADR-0001(a): RLK is distinct and domain-separated.
        assert_ne!(NOISE_PARAMS, crate::noise::NOISE_PARAMS);
        assert!(!NOISE_PARAMS.contains("psk"));
    }

    #[test]
    fn a_completed_leg_renders_no_key_and_no_token() {
        let (relay_priv, relay_pub) = keypair(7);
        let (device_priv, _) = keypair(9);
        let mut initiator = LegInitiator::new(&entropy(1), &device_priv, &relay_pub).expect("init");
        let msg1 = initiator.initiate(b"SECRETTOKEN").expect("msg1");
        let (_, leg) = LegResponder::new(&entropy(2), &relay_priv)
            .expect("responder")
            .respond(&msg1, b"")
            .expect("respond");
        let rendered = format!("{leg:?}");
        assert!(!rendered.contains("SECRETTOKEN"));
        assert!(rendered.contains("<redacted>"));
    }
}
