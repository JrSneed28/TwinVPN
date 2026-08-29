//! `TK` — the L-DATA static X25519 key: generated here, sealed here, unsealed
//! here.
//!
//! **Authority:** ADR-0007 N-1 and **N-5**, ADR-0018 CB-5 row 2, §11.16 (c) and
//! **B-09**, ADR-0020 **ST-1** and §11.2 row **S-01b**, ADR-0001 **L-STORE**,
//! threat-model **TM-14**; the ruling at
//! `docs/implementation/ownership.md` §11.4 **D-6**, closing **G-17**.
//!
//! # Why this module did not exist until now
//!
//! It is the gap G-17 named: **no production X25519 key generation existed
//! anywhere in the tree.** Every `StaticSecret` in `core/`, `services/` and
//! `shells/` was a `StaticSecret::from(raw)` public-half derivation over bytes
//! already held — so the workspace could *use* a tunnel key it had no way to
//! *make*. `pair.begin` could not fill field 3 of a `PairingOffer` for that
//! reason and no other.
//!
//! What blocked writing it was not difficulty. It was that four questions had no
//! answer in the corpus — which component generates TK, whether the sealed form
//! is a Tier-1 item or a Tier-2 record, what its availability class is, and who
//! unseals it — and ownership.md §6 rule 14 forbids an implementation agent to
//! settle a key-custody question locally. D-6 answers all four.
//!
//! # The four answers, as they land in this file
//!
//! **Generated here, at enrolment.** ADR-0007 N-1 makes IK and TK one
//! `DeviceIdentity`, so TK is created when the identity is. The 32 bytes come
//! from [`twinvpn_env::Entropy`], which is the host's `os_csprng` vtable entry:
//! ADR-0018 CD-3 bans `getrandom` inside the core, and the `arch-lint` deny-list
//! enforces it, so there is no other source to reach for.
//!
//! **Sealed into Tier 2 `identity/`; the wrapping key is the Tier-1 item.**
//! ST-1's rule 1 admits to Tier 1 only a value "usable only through an operation
//! the platform key API can perform … with the value itself never readable by
//! the process". TK fails that test *by design* — N-5, CB-5 row 2 and §11.16 (c)
//! all require it to be unsealed **into** locked core memory, "precisely because
//! platform key APIs largely do not offer X25519 ECDH". Rule 2 is also no: live
//! tunnel key state is S-13, Tier 0, and TK survives reboot. So ST-1's
//! else-branch applies and the sealed blob is a Tier-2 record. ST-1 puts "the
//! `TunnelStaticKey` **wrapping** key" in Tier 1 in those words, and that is
//! [`TK_WRAP_ITEM`].
//!
//! **The core unseals**, into [`LockedBytes`]. `tw_host_vtable` gains no wrap or
//! unwrap entry and stays at ABI minor 2 — there was no ABI ask here, which is
//! the part of G-17 that made it look expensive.
//!
//! # What this does NOT achieve, stated plainly
//!
//! **TM-14 stands: TK extraction from process memory is undefended.** The
//! locked allocator stops the key reaching swap, a core dump or a hibernation
//! image; it does not stop a debugger, and [`crate::locked`] says so at more
//! length. B-09 bought PB-1 and PB-2 with exactly this residual, and D-6 does
//! not move it by one bit — an unsealed TK was always going to be in core
//! memory. What changed is that the *sealed* form now has one declared home
//! instead of two contradictory ones.
//!
//! The blast radius is bounded and worth stating beside the residual: TK
//! compromise lets an attacker decrypt this device's tunnels. It confers **no**
//! ability to authenticate as this `Device` — that is IK, which never leaves the
//! element (CB-5 row 1, CD-I4) — so the compromise ends at TK rotation rather
//! than outliving the device. That asymmetry is the whole reason the two keys
//! are separate, and it is why a `TunnelKeyBinding` exists at all.

use twinvpn_env::{ConsumerId, Env};

use crate::aead::{self, Sealed, StoreKey};
use crate::locked::LockedBytes;
use crate::noise::{static_public_key, STATIC_KEY_LEN};
use crate::{CryptoError, Result};

/// The **Tier-1** item name for the `TK` wrapping key.
///
/// ADR-0020 ST-1 names this item in words — "the `TunnelStaticKey` wrapping
/// key" — and ST-34's crypto-erase ladder deletes it at step 1 as one of "the
/// IK/TK handles". It follows `twinvpn-store`'s existing convention
/// (`twinvpn.store.sek`, `twinvpn.store.anchor`) and is deliberately under
/// `identity.` rather than `store.`: this key belongs to the `DeviceIdentity`,
/// not to the vault, and the two are erased on different occasions.
///
/// **It does not extend the store's Tier-1 set.** ADR-0018 §11.16, `twinvpn.h`
/// and ADR-0020 §11.7 each enumerate three Tier-1 *store* items — SEK, `K_bind`,
/// the S-53 anchor — and this is not one of them. G-17 read those three
/// enumerations as evidence that TK had no Tier-1 home; the resolution is that
/// they enumerate a different set.
pub const TK_WRAP_ITEM: &str = "twinvpn.identity.tkwrap";

/// The **Tier-2** record key holding the sealed `TK`.
///
/// `identity/` is ST-14's namespace for this, classified `SecretBearing`, and
/// `twinvpn-store`'s `Namespace::secrecy` already said "the sealed `TK` lives in
/// `identity/`" beside the code. D-6 makes that comment the ruling rather than
/// one of two contradictory ones.
pub const TK_RECORD_KEY: &str = "identity/tk";

/// The entropy consumer for `TK` generation.
///
/// Named so a diagnostic can tell a tunnel key draw apart from a record nonce
/// draw, and so the CD-3 lint has one call site to point at.
pub const TK_CONSUMER: ConsumerId = ConsumerId::new("identity/tunnel-static");

/// The AEAD associated data binding a sealed `TK` to its slot.
///
/// Without it a sealed blob is ciphertext that opens under the wrapping key
/// wherever it is put, so a blob lifted from one record and written into another
/// would unseal cleanly. The label costs nothing and makes the record key part
/// of what the tag covers.
const SEAL_AAD: &[u8] = b"TwinVPN/identity/tk/v1";

/// This device's own L-DATA static X25519 key.
///
/// The private half lives in [`LockedBytes`] and there is **no accessor that
/// returns it as bytes** — [`Self::local_static`] hands out the borrowed
/// `LockedBytes` that [`crate::noise::HandshakeConfig`] requires, and nothing
/// else reaches inside. That is the same shape [`StoreKey`] has, and for the
/// same reason: a key that can be copied into a `Vec` is a key that can reach a
/// log.
///
/// It is **this device's**, never a peer's. A peer's static arrives only as
/// [`crate::VerifiedTunnelKey`], which has no public constructor.
pub struct TunnelStaticKey {
    secret: LockedBytes,
    public: [u8; 32],
}

impl TunnelStaticKey {
    /// Generates a fresh `TK` from the platform CSPRNG.
    ///
    /// The 32 bytes are drawn straight into locked memory: [`LockedBytes::new_with`]
    /// fills the allocation in place, so the private half has no earlier
    /// residence in an unlocked buffer to regret — which is the compromise
    /// [`LockedBytes::adopt`] has to state and this path does not.
    ///
    /// No clamping is applied here. X25519 clamps the scalar at use, in both
    /// [`x25519_dalek`] and `snow`, so clamping on generation would be a second
    /// place for the two to disagree about what this key *is* — and the public
    /// half is derived through the same [`static_public_key`] the handshake
    /// uses, so the two cannot drift.
    ///
    /// # Errors
    ///
    /// [`CryptoError::DerivationFailed`] if the platform CSPRNG fails. It is
    /// **not** papered over with a fallback: ADR-0018's vtable comment on
    /// `os_csprng` says a silent downgrade "is indistinguishable from working",
    /// and a predictable tunnel static is a total loss of confidentiality for
    /// every tunnel this device ever builds.
    pub fn generate(env: &Env) -> Result<Self> {
        let entropy = env.entropy();
        // `new_with`'s closure cannot fail, so the CSPRNG's error is carried
        // out rather than swallowed. The alternative — fill a stack array and
        // `adopt` it — would put a freshly generated tunnel static in unlocked
        // memory first, which is exactly the residual `adopt` exists to declare
        // and this path does not have to accept.
        let mut drawn = false;
        let secret = LockedBytes::new_with(STATIC_KEY_LEN, |buf| {
            drawn = entropy.fill(buf).is_ok();
        })?;
        if !drawn {
            // `secret` drops here and zeroes whatever partial fill it holds.
            return Err(CryptoError::DerivationFailed {
                invariant: "a tunnel static key must come from the platform CSPRNG",
            });
        }
        let public = static_public_key(&secret)?;
        Ok(Self { secret, public })
    }

    /// The public half, for `tk_pub` in a `TunnelKeyBinding` or a
    /// `PairingOffer`.
    #[must_use]
    pub const fn public(&self) -> &[u8; 32] {
        &self.public
    }

    /// The private half, as [`crate::noise::HandshakeConfig::local_static`]
    /// requires it.
    ///
    /// Returns the locked buffer itself, not its contents. The handshake is the
    /// only caller: `snow` needs the scalar to run `IK`, which is B-09's whole
    /// bargain.
    #[must_use]
    pub const fn local_static(&self) -> &LockedBytes {
        &self.secret
    }

    /// Seals `TK` under the Tier-1 wrapping key, for the Tier-2 `identity/`
    /// record.
    ///
    /// # Errors
    ///
    /// As [`crate::aead::seal`].
    pub fn seal(&self, env: &Env, wrapping: &StoreKey) -> Result<Sealed> {
        aead::seal(env, wrapping, SEAL_AAD, self.secret.expose())
    }

    /// Unseals `TK` from the Tier-2 record into locked memory.
    ///
    /// This is the operation N-5 constrains — "unsealed **only** into locked,
    /// non-swappable, non-dumpable memory" — and D-6 places it in the core
    /// rather than behind a new vtable entry.
    ///
    /// # Errors
    ///
    /// [`CryptoError::DerivationFailed`] if the tag does not verify or the
    /// plaintext is not [`STATIC_KEY_LEN`] bytes. The two are deliberately one
    /// error: distinguishing "wrong key" from "right key, wrong length" tells a
    /// caller nothing it can act on, and TM-14 is not helped by a more talkative
    /// failure here.
    pub fn unseal(wrapping: &StoreKey, sealed: &Sealed) -> Result<Self> {
        let mut plain =
            aead::open(wrapping, &sealed.nonce, SEAL_AAD, &sealed.ciphertext).map_err(|_| {
                CryptoError::DerivationFailed {
                    invariant: "the sealed TK did not open under the wrapping key",
                }
            })?;
        if plain.len() != STATIC_KEY_LEN {
            // Zeroed before the refusal: whatever this is, it is not leaving
            // this function in an unlocked buffer.
            zeroize::Zeroize::zeroize(&mut plain);
            return Err(CryptoError::KeyLength {
                expected: STATIC_KEY_LEN,
                observed: plain.len(),
            });
        }
        // `adopt` zeroes `plain` before returning. Its docs state the residual
        // that the plaintext existed briefly in unlocked memory; that is
        // unavoidable for an AEAD that returns a `Vec`, and it is bounded by
        // these three lines.
        let secret = LockedBytes::adopt(&mut plain)?;
        let public = static_public_key(&secret)?;
        Ok(Self { secret, public })
    }
}

impl core::fmt::Debug for TunnelStaticKey {
    /// Redacted. The public half is not secret, but a `Debug` that printed the
    /// struct would invite the next field added to it to be printed too.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TunnelStaticKey(<locked>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::KEY_LEN;
    use std::sync::Arc;
    use twinvpn_env::rng::SystemRngSource;
    use twinvpn_env::{Entropy, EnvParts, WallClockReading};

    /// A deterministic stand-in for the host `os_csprng`. Not random, and it
    /// does not need to be: what these tests assert is the *shape* of the
    /// generate/seal/unseal path, and a fixed stream makes a failure legible.
    struct CountingEntropy(std::sync::Mutex<u64>);

    impl Entropy for CountingEntropy {
        fn fill(&self, dst: &mut [u8]) -> core::result::Result<(), twinvpn_env::EnvError> {
            let mut s = self.0.lock().expect("mutex");
            for b in dst.iter_mut() {
                *s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                *b = u8::try_from((*s >> 33) & 0xff).unwrap_or(0);
            }
            Ok(())
        }
    }

    /// An `os_csprng` that refuses. The point of the test below.
    struct DeadEntropy;

    impl Entropy for DeadEntropy {
        fn fill(&self, _dst: &mut [u8]) -> core::result::Result<(), twinvpn_env::EnvError> {
            Err(twinvpn_env::EnvError::EntropyUnavailable)
        }
    }

    fn env_with(entropy: Arc<dyn Entropy>) -> Env {
        let vt = twinvpn_env::virtual_time::VirtualTime::new(WallClockReading::Unset);
        Env::new(EnvParts {
            monotonic: vt.monotonic(),
            elapsed: vt.elapsed(),
            wall: vt.wall(),
            timer: vt.timer(),
            runtime: vt.runtime(),
            entropy: Arc::clone(&entropy),
            rng: Arc::new(SystemRngSource::new(entropy)),
        })
    }

    fn env() -> Env {
        env_with(Arc::new(CountingEntropy(std::sync::Mutex::new(11))))
    }

    fn wrapping_key() -> StoreKey {
        let mut raw = [0x7bu8; KEY_LEN];
        StoreKey::adopt_sek(&mut raw).expect("wrapping key")
    }

    /// The whole lifecycle D-6 rules on: generated in the core from the host
    /// CSPRNG, sealed under the Tier-1 wrapping key, unsealed back into locked
    /// memory as the same key.
    #[test]
    fn a_generated_tk_survives_a_seal_and_unseal_round_trip() {
        let e = env();
        let wrap = wrapping_key();

        let tk = TunnelStaticKey::generate(&e).expect("generate");
        let sealed = tk.seal(&e, &wrap).expect("seal");
        let reopened = TunnelStaticKey::unseal(&wrap, &sealed).expect("unseal");

        assert_eq!(reopened.public(), tk.public());
        assert_eq!(reopened.local_static().expose(), tk.local_static().expose());
    }

    /// The public half is the one the handshake would derive. If these two ever
    /// disagreed, this device would publish a `tk_pub` no peer could reach it
    /// on — and nothing else would fail first.
    #[test]
    fn the_published_public_half_is_the_handshakes_own() {
        let tk = TunnelStaticKey::generate(&env()).expect("generate");
        assert_eq!(
            tk.public(),
            &static_public_key(tk.local_static()).expect("derive")
        );
    }

    /// **Attack test.** The sealed blob is bound to its slot by the AAD, so a
    /// blob lifted into another record does not open even under the right
    /// wrapping key.
    #[test]
    fn a_sealed_tk_does_not_open_under_a_different_aad() {
        let e = env();
        let wrap = wrapping_key();
        let sealed = TunnelStaticKey::generate(&e)
            .expect("generate")
            .seal(&e, &wrap)
            .expect("seal");
        assert!(
            crate::aead::open(&wrap, &sealed.nonce, b"some/other/slot", &sealed.ciphertext)
                .is_err()
        );
    }

    /// A different wrapping key does not open it either — the Tier-1 item is
    /// load-bearing, not decorative.
    #[test]
    fn a_sealed_tk_does_not_open_under_a_different_wrapping_key() {
        let e = env();
        let sealed = TunnelStaticKey::generate(&e)
            .expect("generate")
            .seal(&e, &wrapping_key())
            .expect("seal");
        let mut other = [0x11u8; KEY_LEN];
        let wrong = StoreKey::adopt_sek(&mut other).expect("other key");
        assert!(TunnelStaticKey::unseal(&wrong, &sealed).is_err());
    }

    /// **The failure that must not be papered over.** A device whose CSPRNG is
    /// unavailable gets no tunnel key, not a predictable one. ADR-0018's vtable
    /// comment: a silent downgrade "is indistinguishable from working".
    #[test]
    fn a_dead_csprng_refuses_rather_than_producing_a_predictable_key() {
        let e = env_with(Arc::new(DeadEntropy));
        assert!(TunnelStaticKey::generate(&e).is_err());
    }

    /// `Debug` does not print the key. A support bundle is not a place to find
    /// a tunnel static.
    #[test]
    fn debug_is_redacted() {
        let tk = TunnelStaticKey::generate(&env()).expect("generate");
        assert_eq!(format!("{tk:?}"), "TunnelStaticKey(<locked>)");
    }
}
