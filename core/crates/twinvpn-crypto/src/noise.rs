//! L-DATA — the WireGuard protocol, unmodified, over the audited [`snow`]
//! implementation.
//!
//! **Authority:** ADR-0001 §7.2 (the concrete specification), §11 items 1, 2 and
//! 7, §12 ("A2 lost on I2"), ADR-0018 CD-2 and CD-3.
//!
//! # Why `snow` and not a hand-rolled state machine
//!
//! ADR-0001 §12, on why instantiating Noise ourselves was rejected:
//!
//! > "Instantiating Noise ourselves gives audited primitives inside an
//! > **unaudited protocol**. VPNs do not usually fail at the primitive layer;
//! > they fail at the protocol layer — timer handling, replay windows, rekey
//! > races, fragmentation."
//!
//! That argument applies with equal force to writing the `Noise_IKpsk2` state
//! machine by hand inside a crate whose job is to *avoid* novel cryptography. So
//! the handshake is `snow`'s, and this module is a thin, typed shell around it
//! that supplies the four things ADR-0001 fixes and `snow` does not: the exact
//! parameter string, the `psk2` slot's contents, the 83-byte prologue, and the
//! rule that a peer static must have arrived through a verified
//! `TunnelKeyBinding`.
//!
//! # The parameter string
//!
//! ```text
//! Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
//! ```
//!
//! Which is ADR-0001 §7.2 read left to right: `Noise_IKpsk2`, X25519,
//! ChaCha20-Poly1305, BLAKE2s. It is a `const` and there is no way to pass a
//! different one — K4 says L-DATA has no crypto agility, "Agility is where
//! downgrades live", so there is no suite parameter to attack.
//!
//! # Randomness comes from `Env`, never from the library's default
//!
//! `snow`'s default resolver reaches for the platform CSPRNG itself, which CD-3
//! bans outside `twinvpn-env`'s binding and CD-2 bans as an ambient default.
//! This module's private `EnvResolver` supplies `snow`'s `Random` from
//! [`twinvpn_env::Env::entropy`], and delegates the primitives to `snow`'s own
//! `DefaultResolver`. Handshake ephemerals draw from the **CSPRNG**, not from a
//! seeded per-consumer stream: forward secrecy is a claim about
//! unpredictability, and a reproducible ephemeral is not forward-secret.
//!
//! # Session keys are erased, not merely dropped
//!
//! `snow` 0.10 implements no `Drop` and no zeroize on its cipher states, so
//! dropping a [`TransportSession`] would hand the send and receive keys back to
//! the allocator **intact**. ADR-0001 §7.2's `REJECT_AFTER_TIME` says keys "are
//! unusable and are **zeroed**", and both halves are honoured here:
//! [`TransportSession`] holds its `snow` state inside `crate::erase`'s
//! wrapper, which overwrites both keys in place — on an explicit
//! [`TransportSession::erase`] and again on drop, so an early return or an
//! unwind cannot skip it — and refuses every keyed operation afterwards. Read
//! `crate::erase`'s module documentation for what that achieves and, more
//! importantly, what it does not.
//!
//! # What this module does not do
//!
//! It does not schedule. `REKEY_AFTER_TIME`, `REJECT_AFTER_TIME`,
//! `REKEY_ATTEMPT_TIME` and the keepalives are exported here as constants
//! because they belong to ADR-0001 §7.2, but the timers that fire on them take a
//! [`twinvpn_env::MonotonicClock`] and live in `twinvpn-tunnel`. A scheduler in
//! this crate would need an `Env`, and a crate that holds an `Env` is a crate
//! that can read a clock — which is not what a primitive library should be able
//! to do.

use core::time::Duration;
use std::sync::Arc;

use snow::params::NoiseParams;
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::Random;
use twinvpn_env::{Entropy, Env};
use zeroize::Zeroize as _;

use crate::binding::VerifiedTunnelKey;
use crate::erase::ErasingTransport;
use crate::established::{EstablishedHandshake, HandshakeSecret};
use crate::locked::LockedBytes;
use crate::psk::{TwinNetPsk, PSK_LEN};
use crate::replay::{ReplayWindow, SendCounter};
use crate::{CryptoError, Result};

/// ADR-0001 §7.2's protocol, exactly. Not configurable — see the module docs.
pub const NOISE_PARAMS: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// The `psk2` slot index. `Noise_IKpsk2` mixes the PSK after the ephemeral
/// exchange, which is what gives ADR-0001 §7.5's three properties.
pub const PSK_SLOT: u8 = 2;

/// `REKEY_AFTER_TIME` — 120 s. The initiator begins a new handshake.
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
/// `REJECT_AFTER_TIME` — 180 s. Keys are unusable and are zeroed.
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
/// `REKEY_ATTEMPT_TIME` — 90 s, after which the `Session` fails.
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
/// Passive keepalive — 10 s after receiving data with nothing to send.
pub const KEEPALIVE_PASSIVE: Duration = Duration::from_secs(10);
/// Persistent keepalive — 25 s, and **only** where ADR-0001 §7.2 R11 permits:
/// "ONLY when the peer is behind NAT or the path is RELAYED".
pub const KEEPALIVE_PERSISTENT: Duration = Duration::from_secs(25);

/// The X25519 private key width.
pub const STATIC_KEY_LEN: usize = 32;

/// Derives the X25519 public half of the L-DATA static key.
///
/// A device needs this to publish its own `tk_pub` in a `TunnelKeyBinding`, and
/// it is the only operation in the crate that touches the *private* tunnel key
/// outside the handshake. The result is public material and is returned by
/// value; the private half never leaves [`LockedBytes`].
///
/// # Errors
///
/// [`CryptoError::KeyLength`] if the key is not [`STATIC_KEY_LEN`] bytes.
pub fn static_public_key(private: &LockedBytes) -> Result<[u8; 32]> {
    let raw: [u8; 32] = private
        .expose()
        .try_into()
        .map_err(|_| CryptoError::KeyLength {
            expected: STATIC_KEY_LEN,
            observed: private.len(),
        })?;
    let secret = x25519_dalek::StaticSecret::from(raw);
    Ok(x25519_dalek::PublicKey::from(&secret).to_bytes())
}

/// Which end of the handshake this device is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Sends the initiation.
    Initiator,
    /// Answers it.
    Responder,
}

/// Everything a handshake needs, and nothing optional that matters.
///
/// The two fields that would be tempting to make optional are not:
/// `psk` is required because ADR-0001 §11 item 1 says the `psk2` slot **carries**
/// `TwinNetPSK`, and `prologue` is required because §7.3.1 P-1 fixes it. A
/// handshake without either would interoperate with a peer that also omitted it,
/// which is a downgrade that succeeds silently.
pub struct HandshakeConfig<'a> {
    /// This device's L-DATA static X25519 private key, unsealed into the locked
    /// allocator. CB-5 row 2.
    pub local_static: &'a LockedBytes,
    /// The peer's static, **only** obtainable from a verified
    /// `TunnelKeyBinding`. Required for an initiator (`IK` needs the
    /// responder's static up front); `None` for a responder, which learns it
    /// from the initiation and must check the binding afterwards.
    pub remote_static: Option<&'a VerifiedTunnelKey>,
    /// The `psk2` contents for this pair at this epoch.
    pub psk: &'a TwinNetPsk,
    /// The 83-byte prologue of ADR-0001 §7.3.1.
    pub prologue: &'a crate::prologue::Prologue,
}

/// An in-progress `Noise_IKpsk2` handshake.
pub struct Handshake {
    state: snow::HandshakeState,
    role: Role,
}

impl Handshake {
    /// Starts a handshake in `role`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyLength`] if the local static is not 32 bytes;
    /// [`CryptoError::HandshakeRejected`] for any refusal from `snow`, with a
    /// bounded `step` — `snow`'s own message can name key lengths and internal
    /// state and is deliberately not propagated.
    pub fn new(env: &Env, role: Role, cfg: &HandshakeConfig<'_>) -> Result<Self> {
        if cfg.local_static.len() != STATIC_KEY_LEN {
            return Err(CryptoError::KeyLength {
                expected: STATIC_KEY_LEN,
                observed: cfg.local_static.len(),
            });
        }
        if role == Role::Initiator && cfg.remote_static.is_none() {
            return Err(CryptoError::HandshakeRejected {
                step: "an IK initiator needs the responder's verified static",
            });
        }
        let params: NoiseParams =
            NOISE_PARAMS
                .parse()
                .map_err(|_| CryptoError::HandshakeRejected {
                    step: "noise parameter string",
                })?;
        let resolver = Box::new(EnvResolver {
            entropy: Arc::clone(env.entropy()),
        });
        let psk = cfg.psk.as_psk_array();
        let mut builder = snow::Builder::with_resolver(params, resolver)
            .prologue(cfg.prologue.as_bytes())
            .map_err(|_| CryptoError::HandshakeRejected {
                step: "prologue rejected",
            })?
            .local_private_key(cfg.local_static.expose())
            .map_err(|_| CryptoError::HandshakeRejected {
                step: "local static rejected",
            })?
            .psk(PSK_SLOT, &psk)
            .map_err(|_| CryptoError::HandshakeRejected {
                step: "psk2 slot rejected",
            })?;
        if let Some(rs) = cfg.remote_static {
            builder = builder.remote_public_key(rs.tk_pub()).map_err(|_| {
                CryptoError::HandshakeRejected {
                    step: "remote static rejected",
                }
            })?;
        }
        let state = match role {
            Role::Initiator => builder.build_initiator(),
            Role::Responder => builder.build_responder(),
        }
        .map_err(|_| CryptoError::HandshakeRejected {
            step: "handshake state could not be built",
        })?;
        debug_assert_eq!(psk.len(), PSK_LEN);
        Ok(Self { state, role })
    }

    /// Which end this is.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Writes the next handshake message into `out`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::HandshakeRejected`].
    pub fn write_message(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize> {
        self.state
            .write_message(payload, out)
            .map_err(|_| CryptoError::HandshakeRejected {
                step: "write handshake message",
            })
    }

    /// Reads a handshake message.
    ///
    /// A failure here is indistinguishable from any other handshake failure by
    /// design: ADR-0001 §7.3.1 P-3 notes that a prologue mismatch "is
    /// observationally indistinguishable from any other handshake failure", and
    /// A1's "silence on unauthenticated input" depends on not telling a prober
    /// *why* it failed.
    ///
    /// # Errors
    ///
    /// [`CryptoError::HandshakeRejected`].
    pub fn read_message(&mut self, message: &[u8], out: &mut [u8]) -> Result<usize> {
        self.state
            .read_message(message, out)
            .map_err(|_| CryptoError::HandshakeRejected {
                step: "read handshake message",
            })
    }

    /// Whether the handshake is complete.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// The peer's static, as learned from the handshake.
    ///
    /// A **responder** must compare this against the static in the peer's
    /// verified `TunnelKeyBinding` before treating the session as
    /// authenticated — `IK` proves the peer holds the static, and the binding is
    /// what proves the static belongs to that identity. Neither alone is enough.
    #[must_use]
    pub fn remote_static(&self) -> Option<&[u8]> {
        self.state.get_remote_static()
    }

    /// The Noise handshake hash, for the transcript confirmation of §7.3 D2.
    #[must_use]
    pub fn handshake_hash(&self) -> &[u8] {
        self.state.get_handshake_hash()
    }

    /// Completes the handshake into a transport session.
    ///
    /// **Stateless** transport mode: the nonce is supplied per message rather
    /// than tracked inside `snow`, which is what lets [`replay::ReplayWindow`]
    /// own the receive side and survive a transport-mode change without being
    /// reset (ADR-0001 §7.2's composition rule).
    ///
    /// [`replay::ReplayWindow`]: crate::replay::ReplayWindow
    ///
    /// # Errors
    ///
    /// [`CryptoError::HandshakeRejected`] if the handshake is not complete.
    pub fn into_transport(self) -> Result<TransportSession> {
        let state = self.state.into_stateless_transport_mode().map_err(|_| {
            CryptoError::HandshakeRejected {
                step: "handshake incomplete",
            }
        })?;
        Ok(TransportSession {
            transport: ErasingTransport::new(state),
            send: SendCounter::new(),
            recv: ReplayWindow::new(),
        })
    }

    /// Completes the handshake into a transport session **and** the
    /// authenticated result ADR-0001 §7.3.2 keys resumption from.
    ///
    /// This is the **only** thing in the workspace that can mint an
    /// [`EstablishedHandshake`]. It consumes the handshake, so a second call is
    /// not a thing that exists, and every field of the result is taken from the
    /// handshake rather than from a caller:
    ///
    /// - the role is `self.role`, fixed by [`Handshake::new`] before a byte
    ///   moved;
    /// - the peer static is the one `snow` says the peer **proved** it holds —
    ///   absent, this refuses rather than returning an "authenticated" value
    ///   that authenticated nobody;
    /// - the secret is HKDF-Extract over Noise's own `Split()` outputs, which
    ///   `crate::established` documents in full.
    ///
    /// [`Self::into_transport`] is unchanged and still available for a caller
    /// that wants only the traffic keys.
    ///
    /// # Why the raw split, and why that is not the transport keys leaking
    ///
    /// `snow`'s `dangerously_get_raw_split` returns the same two 32-byte values
    /// the two cipher states are keyed from, and this method calls it **before**
    /// converting the state — `SymmetricState::split_raw` only reads the
    /// chaining key, so the transport session that follows is keyed identically
    /// to one from [`Self::into_transport`]. Those two values do not leave this
    /// function: what escapes is `HKDF-Extract(salt, k1 ‖ k2)`, and inverting
    /// that is a preimage attack on HMAC-SHA-256. Resumption material therefore
    /// cannot yield transport keys, which is the property `crate::established`
    /// exists to make true.
    ///
    /// # Errors
    ///
    /// [`CryptoError::HandshakeRejected`] if the handshake is not complete or
    /// authenticated no peer static;
    /// [`CryptoError::LockedAllocationUnavailable`] if the locked allocator
    /// could not hold the secret — fail-closed, because a secret this crate
    /// cannot protect is one it must not hand out.
    pub fn split(mut self) -> Result<(TransportSession, EstablishedHandshake)> {
        if !self.is_finished() {
            return Err(CryptoError::HandshakeRejected {
                step: "handshake incomplete",
            });
        }
        let remote_static: [u8; STATIC_KEY_LEN] = self
            .remote_static()
            .and_then(|rs| <[u8; STATIC_KEY_LEN]>::try_from(rs).ok())
            .ok_or_else(crate::established::no_peer_static)?;
        let role = self.role;
        // Erased on the way out whatever happens below: these two arrays are
        // the transport keys in the clear, and an early return must not leave
        // them on the stack.
        let (mut k1, mut k2) = self.state.dangerously_get_raw_split();
        let secret = HandshakeSecret::extract(&k1, &k2);
        k1.zeroize();
        k2.zeroize();
        let established = EstablishedHandshake::new(role, remote_static, secret?);
        Ok((self.into_transport()?, established))
    }
}

impl core::fmt::Debug for Handshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Handshake")
            .field("role", &self.role)
            .field("finished", &self.is_finished())
            .finish_non_exhaustive()
    }
}

/// An established L-DATA session.
///
/// Owns its send counter and its replay window, and there is **no method that
/// resets either**. A transport-mode change (`T-UDP` ↔ `T-RELAY` ↔ `T-QUIC`) or
/// a path resumption keeps this object, which is ADR-0001 §11 item 2 and §7.3.2
/// RS-3 expressed as ownership rather than as a rule.
///
/// # Its keys are erased before they are freed
///
/// The `snow` state lives inside `ErasingTransport`, so both cipher keys are
/// overwritten in place on [`Self::erase`] **and** on drop, and every keyed
/// operation is refused afterwards. `snow` 0.10 does none of that itself; see
/// `crate::erase` for the mechanism and its honest limits.
pub struct TransportSession {
    transport: ErasingTransport,
    send: SendCounter,
    recv: ReplayWindow,
}

impl TransportSession {
    /// Encrypts `payload` into `out`, returning `(nonce, len)`.
    ///
    /// The nonce is returned rather than hidden because the caller must put it
    /// on the wire — WireGuard's transport header carries it — and because a
    /// nonce the caller cannot see is a nonce the caller cannot bind into a
    /// frame's own authentication.
    ///
    /// # Errors
    ///
    /// [`CryptoError::RekeyFailed`] at `REJECT_AFTER_MESSAGES`, and once the
    /// session has been erased; [`CryptoError::HandshakeRejected`] if `out` is
    /// too small.
    pub fn seal(&mut self, payload: &[u8], out: &mut [u8]) -> Result<(u64, usize)> {
        // Before the counter moves, not after: an erased session must not spend
        // a nonce it can never seal under, because `twinvpn-tunnel` runs its own
        // counter in lockstep with this one.
        self.transport.usable()?;
        let nonce = self.send.take()?;
        let n = self.transport.write_message(nonce, payload, out)?;
        Ok((nonce, n))
    }

    /// Decrypts a frame, then records its counter.
    ///
    /// The order is the security property: the replay window is advanced
    /// **only** after the AEAD has authenticated the frame, so an attacker
    /// cannot advance a peer's window with forged traffic and lock out the real
    /// peer. [`crate::replay::ReplayWindow::would_accept`] is offered for a
    /// cheap pre-filter, and it does not mutate.
    ///
    /// # Errors
    ///
    /// [`CryptoError::ReplayDetected`] before the AEAD if the counter is
    /// obviously stale, or after it if the frame is a replay;
    /// [`CryptoError::HandshakeRejected`] if the AEAD fails;
    /// [`CryptoError::RekeyFailed`] once the session has been erased.
    pub fn open(&mut self, nonce: u64, frame: &[u8], out: &mut [u8]) -> Result<usize> {
        // An erased session is finished, and saying so is more useful to a
        // diagnostic than reporting whatever the replay window happens to think
        // of a counter no key can authenticate.
        self.transport.usable()?;
        // Cheap shed first: a counter that cannot be accepted is dropped without
        // spending an AEAD on it. This does not mutate the window.
        if !self.recv.would_accept(nonce) {
            return Err(CryptoError::ReplayDetected { counter: nonce });
        }
        let n = self.transport.read_message(nonce, frame, out)?;
        // Only now, with the frame authenticated, does the window move.
        self.recv.accept(nonce)?;
        Ok(n)
    }

    /// The send counter, for the rekey-on-volume decision.
    #[must_use]
    pub const fn send_counter(&self) -> &SendCounter {
        &self.send
    }

    /// The receive window, for diagnostics.
    #[must_use]
    pub const fn replay_window(&self) -> &ReplayWindow {
        &self.recv
    }

    /// The peer's static, as established by the handshake.
    ///
    /// Still answers after [`Self::erase`]: `tk_pub` is a **public** key and it
    /// is the identity this session was established against, so a teardown
    /// diagnostic that could not name the peer would cost readability for no
    /// confidentiality.
    #[must_use]
    pub fn remote_static(&self) -> Option<&[u8]> {
        self.transport.remote_static()
    }

    /// Overwrites both session keys and makes the session permanently unusable.
    ///
    /// ADR-0001 §7.2's `REJECT_AFTER_TIME` outcome — "keys are unusable and are
    /// **zeroed**" — reached explicitly rather than by waiting for a drop. It is
    /// idempotent, and [`Drop`] calls it, so an early return, a `?`, or an
    /// unwind through a scope holding this session reaches the same place. After
    /// it, [`Self::seal`] and [`Self::open`] return
    /// [`CryptoError::RekeyFailed`]; there is no method that makes the session
    /// usable again, because a rekey is a **new** session (§7.3.2 RS-3).
    ///
    /// See `crate::erase` for what the overwrite does and does not achieve.
    pub fn erase(&mut self) {
        self.transport.erase();
    }

    /// Whether the session keys have been erased.
    #[must_use]
    pub const fn is_erased(&self) -> bool {
        self.transport.is_erased()
    }

    /// The wrapper itself, for `crate::erase`'s own tests only.
    ///
    /// `cfg(test)` rather than `pub(crate)`: the erasure tests must be able to
    /// look at the `snow` state *behind* the guard that refuses an erased
    /// session, and nothing in a shipped build may.
    #[cfg(test)]
    pub(crate) const fn transport_for_test(&self) -> &ErasingTransport {
        &self.transport
    }

    /// As [`Self::transport_for_test`], mutably.
    #[cfg(test)]
    pub(crate) const fn transport_for_test_mut(&mut self) -> &mut ErasingTransport {
        &mut self.transport
    }
}

impl zeroize::Zeroize for TransportSession {
    /// The ecosystem spelling of [`Self::erase`], so a caller holding this
    /// behind a `Zeroize` bound gets the real erasure rather than a `Drop` that
    /// used to be one. `twinvpn-tunnel` does not declare `zeroize` and calls
    /// [`Self::erase`] instead; both reach the same code.
    fn zeroize(&mut self) {
        self.erase();
    }
}

/// The erasure runs in `ErasingTransport`'s destructor, which is this type's
/// field, so [`TransportSession`] needs no `Drop` of its own to honour the
/// marker.
impl zeroize::ZeroizeOnDrop for TransportSession {}

impl core::fmt::Debug for TransportSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransportSession")
            .field("sent", &self.send.sent())
            .field("recv", &self.recv)
            .field("erased", &self.is_erased())
            .finish_non_exhaustive()
    }
}

/// `snow`'s `Random`, supplied from [`twinvpn_env::Env`].
struct EnvRandom {
    entropy: Arc<dyn Entropy>,
}

impl rand_core::RngCore for EnvRandom {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        // As `twinvpn_env`'s own `EntropyRng`: there is no error channel here,
        // and a fallback CSPRNG is indistinguishable from a working one right up
        // until it matters. ADR-0018 F-7 contains the panic at the ABI boundary
        // and reports `INTERNAL.CORE_PANIC`, which is the correct visible
        // outcome for "this device has no randomness".
        assert!(
            self.entropy.fill(dst).is_ok(),
            "platform entropy failed mid-handshake; the core instance is poisoned (F-7)"
        );
    }
}

impl rand_core::CryptoRng for EnvRandom {}

impl Random for EnvRandom {
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), snow::Error> {
        self.entropy
            .fill(dst)
            .map_err(|_| snow::Error::Prereq(snow::error::Prerequisite::LocalPrivateKey))
    }
}

/// A `snow` resolver that takes randomness from `Env` and everything else from
/// `snow`'s audited default.
struct EnvResolver {
    entropy: Arc<dyn Entropy>,
}

impl CryptoResolver for EnvResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(EnvRandom {
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
