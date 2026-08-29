//! The opaque, **authenticated** result of a completed `Noise_IKpsk2`
//! handshake, and the `handshake_secret` ADR-0001 §7.3.2 keys resumption from.
//!
//! **Authority:** ADR-0001 §7.2 (session keys are derived from the final Noise
//! chaining key), §7.3.2 RS-1 (the resumption material is in-memory only),
//! §11 item 7 (no novel key schedule); ADR-0018 CB-5, CD-I2; RFC 5869 §2.2
//! (HKDF-Extract); RFC 8446 §7.1 (the TLS 1.3 shape this follows).
//!
//! # The hole this closes
//!
//! `ResumptionKeys::derive` used to take a bare `&[u8]` and a caller-supplied
//! [`Role`]. Both were silent downgrades:
//!
//! - passing the **handshake hash** compiled, and keys resumption from a value
//!   ADR-0001 §7.3 D2 puts on the wire;
//! - arming **both** peers with the same `Role` compiled, and collapsed the two
//!   direction labels into one, removing the reflection defence entirely.
//!
//! Neither is expressible now. [`EstablishedHandshake`] has **no public
//! constructor**: the only thing in the workspace that can mint one is
//! [`crate::noise::Handshake::split`], which takes the role from the handshake
//! it consumes and the secret from that handshake's own chaining key. A caller
//! cannot name either.
//!
//! # The derivation, and why this one
//!
//! ```text
//! handshake_secret = HKDF-Extract(salt = "TwinVPN/resumption/v1", ikm = k1 || k2)
//! ```
//!
//! where `(k1, k2)` are the two 32-byte outputs of Noise's own `Split()` — the
//! same two values the transport cipher states are keyed from.
//!
//! **This is the TLS 1.3 shape.** RFC 8446 §7.1 derives
//! `resumption_master_secret` from the same secret the traffic keys come from,
//! separated by a label rather than by a second exchange; TLS's resumption
//! material is not an independent secret and neither is this one. ADR-0001 §11
//! item 7 forbids a *novel* key schedule, and reproducing the standard one is
//! the opposite of that.
//!
//! **The extract is one-way.** HKDF-Extract is `HMAC(salt, ikm)`, so recovering
//! `k1 ‖ k2` from `handshake_secret` is a preimage attack on HMAC-SHA-256.
//! Resumption material therefore never yields transport keys, which is what
//! makes RS-6's "resumption provides no new forward secrecy" a bounded
//! statement rather than an open one: an attacker who takes this secret out of
//! memory can forge a resume, and still cannot read or forge one packet of
//! traffic.
//!
//! **And unlike `handshake_hash()`, it is never disclosed.** The handshake hash
//! is exported *deliberately*, for §7.3 D2's confirmation value, which may be
//! transmitted and compared in the clear; Noise's own specification says it is
//! not to be used as secret material. `k1` and `k2` are never transmitted in
//! any form, and this secret is a one-way function of them.
//!
//! # In memory only, and erased
//!
//! RS-1 / S-13: the secret lives in [`LockedBytes`] — the project's approved
//! protected-memory strategy — so it is `mlock`ed, excluded from a core dump,
//! wiped on `fork` where the kernel allows, and **overwritten before it is
//! freed**. Read `crate::locked` for what that achieves and, more importantly,
//! what TM-14 already concedes it does not. Neither type here is `Clone`, is
//! serialisable, or renders a byte in `Debug`.

use zeroize::Zeroize as _;

use crate::locked::LockedBytes;
use crate::noise::{Role, STATIC_KEY_LEN};
use crate::{CryptoError, Result};

/// The `handshake_secret` width, in bytes. HKDF-Extract with SHA-256 produces a
/// 32-byte PRK, and ADR-0001 §7.3.2's two expansions consume it as one.
pub const HANDSHAKE_SECRET_LEN: usize = 32;

/// The HKDF-Extract salt, fixed and versioned.
///
/// A salt rather than an empty one because RFC 5869 §3.1 is explicit that a
/// non-secret salt still adds domain separation, and the version suffix is what
/// lets a future revision of §7.3.2 derive a *different* secret from the same
/// handshake without either side silently accepting the other's.
pub const RESUMPTION_SALT: &[u8] = b"TwinVPN/resumption/v1";

/// The per-session secret a completed handshake produced.
///
/// **There is no public constructor and no `Clone`.** It is minted by
/// [`crate::noise::Handshake::split`] and by nothing else, so "the caller passed
/// the wrong bytes" is not a state this type can be in.
pub struct HandshakeSecret {
    /// Exactly [`HANDSHAKE_SECRET_LEN`] bytes, in the locked allocator.
    bytes: LockedBytes,
}

impl HandshakeSecret {
    /// Extracts the secret from Noise's two raw split outputs.
    ///
    /// Private to the crate: `k1` and `k2` are the transport keys themselves,
    /// and the only place in the workspace that holds them is
    /// [`crate::noise::Handshake::split`], one module over.
    ///
    /// The caller is responsible for erasing its own copies of `k1` and `k2`;
    /// this function erases the concatenation it builds.
    pub(crate) fn extract(k1: &[u8; 32], k2: &[u8; 32]) -> Result<Self> {
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(k1);
        ikm[32..].copy_from_slice(k2);
        // `hkdf`'s own Extract, never a hand-rolled HMAC: ADR-0001 §11 item 7
        // permits the *composition* and not a re-implementation, and `kdf.rs`
        // already made this crate's choice of HKDF implementation.
        let (mut prk, _) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(RESUMPTION_SALT), &ikm);
        ikm.zeroize();
        let bytes = LockedBytes::new_with(HANDSHAKE_SECRET_LEN, |dst| dst.copy_from_slice(&prk));
        // Before the `?`: an allocation failure must not leave the PRK on the
        // stack for the unwind to walk past.
        prk.as_mut_slice().zeroize();
        Ok(Self { bytes: bytes? })
    }

    /// The secret octets, for a KDF that consumes them.
    ///
    /// Exposing them is not the hole this module closes — a consumer must be
    /// able to key an HKDF from the secret, and `twinvpn-core`'s
    /// `ResumptionKeys` is one crate over. What is closed is the *inbound*
    /// direction: there is no way to put chosen bytes **in**.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.bytes.expose()
    }

    /// Always [`HANDSHAKE_SECRET_LEN`]. Present so a consumer can assert it
    /// rather than assume it.
    #[must_use]
    pub const fn len(&self) -> usize {
        HANDSHAKE_SECRET_LEN
    }

    /// Never. A [`HandshakeSecret`] is a fixed 32 bytes by construction.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl core::fmt::Debug for HandshakeSecret {
    /// `<redacted>`, in full. Not a length, not a prefix, not a digest: a digest
    /// of a 32-byte secret in a support bundle correlates two captures of the
    /// same `Session`, which is the thing `ownership.md` §6 rule 11 forbids.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HandshakeSecret(<redacted>)")
    }
}

/// The overwrite runs in [`LockedBytes`]'s own destructor, which is this type's
/// only field, so no `Drop` of its own is needed to honour the marker.
impl zeroize::ZeroizeOnDrop for HandshakeSecret {}

/// A completed `Noise_IKpsk2` handshake, as an **authenticated** value.
///
/// Carries the three facts a consumer must not be trusted to supply itself:
///
/// | Fact | Where it comes from | What a caller-supplied version broke |
/// |---|---|---|
/// | [`Self::local_role`] | `Handshake::role`, fixed at construction from the two `DeviceId`s | two peers arming under one role collapse both direction labels, removing the reflection defence |
/// | [`Self::remote_static`] | `snow`'s `get_remote_static`, i.e. the key the peer **proved** it holds | peer identity travelling separately from the result it belongs to |
/// | [`Self::secret`] | HKDF-Extract over Noise's own split outputs | the handshake hash — a value §7.3 D2 puts on the wire — keying resumption |
///
/// **No public constructor, no `Clone`, no `serde`.** The one way to obtain one
/// is [`crate::noise::Handshake::split`], which consumes the handshake that
/// produced it. RS-1's "in memory only, for the life of the `Session`" is
/// therefore a property of the type rather than a rule someone has to remember.
pub struct EstablishedHandshake {
    role: Role,
    remote_static: [u8; STATIC_KEY_LEN],
    secret: HandshakeSecret,
}

impl EstablishedHandshake {
    /// The one assembly point, reachable only from inside `twinvpn-crypto` and
    /// called from exactly one place: [`crate::noise::Handshake::split`].
    /// `grep -rn 'EstablishedHandshake::new' core/crates/twinvpn-crypto` is how
    /// a reviewer confirms that, and the type is `pub` with no `pub fn new`, so
    /// no crate above this one can add a second.
    pub(crate) const fn new(
        role: Role,
        remote_static: [u8; STATIC_KEY_LEN],
        secret: HandshakeSecret,
    ) -> Self {
        Self {
            role,
            remote_static,
            secret,
        }
    }

    /// **This device's** authenticated role in the handshake.
    ///
    /// There is no setter, here or anywhere: the value was fixed by
    /// `Handshake::new` before a single byte moved, and a resumption consumer
    /// reads it rather than being told it.
    #[must_use]
    pub const fn local_role(&self) -> Role {
        self.role
    }

    /// The peer's X25519 static, as the handshake **proved** it.
    ///
    /// Public material, and it travels with the result rather than beside it so
    /// a consumer cannot pair one session's secret with another's peer.
    #[must_use]
    pub const fn remote_static(&self) -> &[u8; STATIC_KEY_LEN] {
        &self.remote_static
    }

    /// The `handshake_secret` of ADR-0001 §7.3.2.
    #[must_use]
    pub const fn secret(&self) -> &HandshakeSecret {
        &self.secret
    }
}

impl core::fmt::Debug for EstablishedHandshake {
    /// The role only. The peer static is public but identifying, and the secret
    /// renders as `<redacted>` wherever it appears.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EstablishedHandshake")
            .field("local_role", &self.role)
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Erasure runs in [`HandshakeSecret`]'s destructor, which runs in this type's,
/// so the marker is honoured without a `Drop` here. The peer static is public
/// key material and is deliberately not erased — it is the identity a teardown
/// diagnostic names, exactly as `noise::TransportSession::remote_static` is.
impl zeroize::ZeroizeOnDrop for EstablishedHandshake {}

/// The refusal a `split` reports when the handshake authenticated no peer.
///
/// Not reachable from `Noise_IKpsk2`, which always learns a remote static
/// before it finishes. It is a refusal rather than an `expect` or a
/// `debug_assert` because "authenticated" is the whole claim
/// [`EstablishedHandshake`] makes, and a `debug_assert` makes that claim for
/// free in every release build.
#[must_use]
pub(crate) const fn no_peer_static() -> CryptoError {
    CryptoError::HandshakeRejected {
        step: "the completed handshake authenticated no peer static",
    }
}

#[cfg(test)]
mod tests {
    use super::{HandshakeSecret, HANDSHAKE_SECRET_LEN, RESUMPTION_SALT};

    #[test]
    fn the_secret_is_the_rfc_5869_extract_of_the_two_split_outputs() {
        // The derivation is stated in the module docs and asserted here against
        // an INDEPENDENT computation, so a change to either one fails rather
        // than quietly redefining the other.
        let k1 = [0xa1u8; 32];
        let k2 = [0xb2u8; 32];
        let secret = HandshakeSecret::extract(&k1, &k2).expect("extract");

        let mut ikm = Vec::with_capacity(64);
        ikm.extend_from_slice(&k1);
        ikm.extend_from_slice(&k2);
        let (expected, _) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(RESUMPTION_SALT), &ikm);
        assert_eq!(secret.expose(), &expected[..]);
        assert_eq!(secret.expose().len(), HANDSHAKE_SECRET_LEN);
    }

    #[test]
    fn swapping_the_two_split_outputs_yields_a_different_secret() {
        // `k1 || k2` is ordered, and the two halves key opposite directions. A
        // derivation that hashed them into a set would give both peers the same
        // input under either ordering and hide a real disagreement.
        let k1 = [0x01u8; 32];
        let k2 = [0x02u8; 32];
        let a = HandshakeSecret::extract(&k1, &k2).expect("extract");
        let b = HandshakeSecret::extract(&k2, &k1).expect("extract");
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn debug_renders_no_byte_of_the_secret() {
        let secret = HandshakeSecret::extract(&[0x7fu8; 32], &[0x80u8; 32]).expect("extract");
        // Exact equality, deliberately: a `contains` check would pass on a
        // rendering that appended the material, and "the whole string is this
        // constant" is the only assertion that proves nothing escaped.
        assert_eq!(format!("{secret:?}"), "HandshakeSecret(<redacted>)");
        // The material itself is still reachable through the named accessor,
        // which is the point — what is closed is the inbound direction, not the
        // outbound one.
        assert_eq!(secret.expose().len(), HANDSHAKE_SECRET_LEN);
    }
}
