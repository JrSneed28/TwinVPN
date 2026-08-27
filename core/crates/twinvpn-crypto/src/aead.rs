//! The record AEAD and the store key hierarchy.
//!
//! **Authority:** ADR-0020 ST-16, ST-17, ST-18, §11.6; ADR-0018 CB-5 row 3,
//! CB-6a; ADR-0018 CD-I2.
//!
//! # Why this lives in `twinvpn-crypto` and not in `twinvpn-store`
//!
//! CD-I2: "ONLY `twinvpn-crypto` may declare a dependency on a cryptographic
//! implementation." `twinvpn-store` owns the transaction engine — write-ahead
//! ordering, crash recovery, monotone rejection, migration, multi-key commit —
//! and CB-7 puts all of that in the core. But it may not name
//! `chacha20poly1305`, so the sealing and opening of a record envelope, and the
//! HKDF hierarchy above it, are here.
//!
//! # ST-16, quoted, and the one thing it forbids
//!
//! > "AEAD is XChaCha20-Poly1305 with a **random 192-bit nonce per write**,
//! > chosen because random nonces are safe at this size **without a counter that
//! > a rollback could reuse**. AES-256-GCM is permitted where the platform
//! > provides a hardware AEAD and the nonce is drawn from a Tier-1-backed
//! > counter; **a random 96-bit GCM nonce MUST NOT be used.**"
//!
//! The reason the parenthetical matters is the whole anti-rollback story: a
//! counter-based nonce is state, state can be rolled back, and a reused
//! (key, nonce) pair under a polynomial MAC is a key recovery, not merely a
//! confidentiality loss. A 192-bit random nonce has no state to roll back.
//!
//! This module therefore offers **only** the XChaCha20-Poly1305 path. The
//! AES-256-GCM alternative ST-16 permits is a *platform-performed* AEAD
//! (`RecordAeadCustody::PlatformPerformed`), which by definition does not run
//! here — the shell performs it and the core never holds the key. There is no
//! GCM code in this crate, so the forbidden 96-bit-random-nonce construction
//! cannot be written by accident.
//!
//! # The nonce is drawn from `Env`, and the caller cannot supply one
//!
//! [`seal`] takes an [`twinvpn_env::Env`] and draws the nonce itself. A
//! `seal_with_nonce` would be the API through which a caller reintroduces a
//! counter, so it does not exist.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use twinvpn_env::{ConsumerId, Env};

use crate::kdf::hkdf_sha256;
use crate::locked::LockedBytes;
use crate::{CryptoError, Result};

/// The AEAD key width.
pub const KEY_LEN: usize = 32;
/// The XChaCha20-Poly1305 nonce width: 192 bits (ST-16).
pub const NONCE_LEN: usize = 24;
/// The Poly1305 tag width.
pub const TAG_LEN: usize = 16;

/// `store_id`'s width, from `StoreAntiRollbackAnchor` (ST-21): `bstr(16)`.
pub const STORE_ID_LEN: usize = 16;

/// The CD-4 consumer id for record nonces.
///
/// A `const` at its one consumer, per CD-4, so adding another consumer of
/// randomness cannot shift this one's stream.
pub const NONCE_CONSUMER: ConsumerId = ConsumerId::new("store/record-nonce");

/// The `info` labels of ADR-0020 §11.6's hierarchy, verbatim.
mod info {
    pub const NS_PREFIX: &[u8] = b"TwinVPN/store/ns/v1";
    pub const RING: &[u8] = b"TwinVPN/store/ring/v1";
    pub const BIND: &[u8] = b"TwinVPN/store/bind/v1";
}

/// A key in the ADR-0020 §11.6 hierarchy, held in locked memory.
///
/// Both the `SEK` and every key derived from it are CB-5 row 3 — "the only
/// *principled* member of the core-held set" — so both get the locked
/// allocator. There is no accessor that yields the bytes: the only thing a
/// `StoreKey` can do is [`seal`] and [`open`], which is what keeps it from
/// reaching a log, a diagnostic, or a backup.
pub struct StoreKey {
    bytes: LockedBytes,
}

impl StoreKey {
    /// Adopts an `SEK` unsealed by the shell.
    ///
    /// `raw` is zeroed before this returns. See
    /// [`LockedBytes::adopt`][crate::locked::LockedBytes::adopt] on why the
    /// original's earlier residence in unlocked memory is a stated compromise
    /// rather than a solved problem.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyLength`] if `raw` is not [`KEY_LEN`] bytes.
    pub fn adopt_sek(raw: &mut [u8]) -> Result<Self> {
        if raw.len() != KEY_LEN {
            return Err(CryptoError::KeyLength {
                expected: KEY_LEN,
                observed: raw.len(),
            });
        }
        Ok(Self {
            bytes: LockedBytes::adopt(raw)?,
        })
    }

    /// `K_ns = HKDF-SHA-256(SEK, salt = store_id, info = "TwinVPN/store/ns/v1" || namespace)`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::DerivationFailed`].
    pub fn derive_namespace_key(
        &self,
        store_id: &[u8; STORE_ID_LEN],
        namespace: &str,
    ) -> Result<Self> {
        let mut info = Vec::with_capacity(info::NS_PREFIX.len() + namespace.len());
        info.extend_from_slice(info::NS_PREFIX);
        info.extend_from_slice(namespace.as_bytes());
        self.derive(store_id, &info)
    }

    /// `K_ring = HKDF-SHA-256(SEK, salt = store_id, info = "TwinVPN/store/ring/v1")`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::DerivationFailed`].
    pub fn derive_ring_key(&self, store_id: &[u8; STORE_ID_LEN]) -> Result<Self> {
        self.derive(store_id, info::RING)
    }

    /// `K_bind = HKDF-SHA-256(SEK, salt = store_id, info = "TwinVPN/store/bind/v1")`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::DerivationFailed`].
    pub fn derive_bind_key(&self, store_id: &[u8; STORE_ID_LEN]) -> Result<Self> {
        self.derive(store_id, info::BIND)
    }

    fn derive(&self, store_id: &[u8; STORE_ID_LEN], info: &[u8]) -> Result<Self> {
        let mut derived = [0u8; KEY_LEN];
        let outcome = hkdf_sha256(Some(store_id), self.bytes.expose(), info, &mut derived);
        let key = LockedBytes::new_with(KEY_LEN, |dst| dst.copy_from_slice(&derived));
        zeroize::Zeroize::zeroize(&mut derived);
        outcome?;
        Ok(Self { bytes: key? })
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305> {
        let raw: &[u8; KEY_LEN] =
            self.bytes
                .expose()
                .try_into()
                .map_err(|_| CryptoError::KeyLength {
                    expected: KEY_LEN,
                    observed: self.bytes.len(),
                })?;
        Ok(XChaCha20Poly1305::new(raw.into()))
    }

    /// What the locked allocator granted for this key (CB-6a).
    #[must_use]
    pub fn custody_report(&self) -> crate::locked::LockedMemoryReport {
        self.bytes.report()
    }
}

impl core::fmt::Debug for StoreKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreKey")
            .field("protection", &self.bytes.report().tag())
            .finish_non_exhaustive()
    }
}

/// A sealed record: the nonce that was drawn and the ciphertext with its tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// The 192-bit nonce, drawn fresh for this write.
    pub nonce: [u8; NONCE_LEN],
    /// `XChaCha20-Poly1305(K, nonce, plaintext, aad)`, tag appended.
    pub ciphertext: Vec<u8>,
}

/// Seals `plaintext` under `key` with `aad`, drawing a fresh random nonce.
///
/// # Errors
///
/// [`CryptoError::DerivationFailed`] if the AEAD refuses the input (only for
/// inputs beyond the construction's length bound).
pub fn seal(env: &Env, key: &StoreKey, aad: &[u8], plaintext: &[u8]) -> Result<Sealed> {
    let mut nonce = [0u8; NONCE_LEN];
    // ST-16's "random 192-bit nonce per write", from the platform CSPRNG. A
    // failure here is not papered over: `Entropy::fill` has an error channel
    // precisely so a device with no randomness does not silently write a
    // predictable nonce.
    env.entropy()
        .fill(&mut nonce)
        .map_err(|_| CryptoError::DerivationFailed {
            invariant: "a record nonce must come from the platform CSPRNG",
        })?;
    let ciphertext = key
        .cipher()?
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::DerivationFailed {
            invariant: "AEAD refused the plaintext length",
        })?;
    Ok(Sealed { nonce, ciphertext })
}

/// Opens a sealed record.
///
/// # Errors
///
/// [`CryptoError::SignatureInvalid`] with
/// [`StatementKind::DeviceIdentityRecord`][crate::StatementKind::DeviceIdentityRecord]
/// is **not** used here — a failed record tag is a storage integrity condition,
/// not a trust one, so this returns [`CryptoError::ReplayDetected`]? No: it
/// returns [`AeadOpenError`], a distinct type, because the caller
/// (`twinvpn-store`) must map it onto `STORE.RECORD_CORRUPT` and reporting it as
/// a `CRYPTO.*` or `AUTH.*` code would send a support engineer looking for a
/// trust problem when the disk is failing.
pub fn open(
    key: &StoreKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> core::result::Result<Vec<u8>, AeadOpenError> {
    // A ciphertext shorter than the tag cannot be authentic, and checking first
    // means a truncated record does not reach the AEAD at all.
    if ciphertext.len() < TAG_LEN {
        return Err(AeadOpenError::Truncated);
    }
    let cipher = key.cipher().map_err(|_| AeadOpenError::KeyUnusable)?;
    cipher
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AeadOpenError::TagMismatch)
}

/// Why a record could not be opened.
///
/// Three outcomes, deliberately distinguished, because they mean different
/// things to an operator: a truncated record is a torn write, a tag mismatch is
/// corruption **or** tampering, and an unusable key is a custody failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadOpenError {
    /// The ciphertext is shorter than the authentication tag.
    Truncated,
    /// The tag did not verify: corruption, or a record moved between namespaces,
    /// keys or sequence numbers — all of which the AAD binds.
    TagMismatch,
    /// The key material is the wrong width.
    KeyUnusable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use twinvpn_env::{Entropy, EnvError, EnvParts, SystemRngSource, WallClockReading};

    struct CountingEntropy(std::sync::Mutex<u64>);

    impl Entropy for CountingEntropy {
        fn fill(&self, dst: &mut [u8]) -> core::result::Result<(), EnvError> {
            let mut s = self.0.lock().expect("mutex");
            for b in dst.iter_mut() {
                *s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                *b = u8::try_from((*s >> 33) & 0xff).unwrap_or(0);
            }
            Ok(())
        }
    }

    fn env() -> Env {
        let vt = twinvpn_env::virtual_time::VirtualTime::new(WallClockReading::Unset);
        let entropy: Arc<dyn Entropy> = Arc::new(CountingEntropy(std::sync::Mutex::new(7)));
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

    fn sek() -> StoreKey {
        let mut raw = [0x5eu8; KEY_LEN];
        StoreKey::adopt_sek(&mut raw).expect("sek")
    }

    const STORE_ID: [u8; STORE_ID_LEN] = [0x1d; STORE_ID_LEN];

    #[test]
    fn a_sealed_record_opens_with_the_same_key_and_aad() {
        let e = env();
        let k = sek()
            .derive_namespace_key(&STORE_ID, "peer/")
            .expect("k_ns");
        let sealed = seal(&e, &k, b"aad", b"plaintext").expect("seal");
        let opened = open(&k, &sealed.nonce, b"aad", &sealed.ciphertext).expect("open");
        assert_eq!(opened, b"plaintext");
    }

    /// **Attack test.** ST-17: the AAD binds a record to its namespace, key and
    /// `rec_seq`. Opening it under a different AAD must fail, which is what
    /// makes moving a record between namespaces or replaying it at a different
    /// sequence detectable rather than silent.
    #[test]
    fn a_record_does_not_open_under_a_different_aad() {
        let e = env();
        let k = sek()
            .derive_namespace_key(&STORE_ID, "peer/")
            .expect("k_ns");
        let sealed = seal(&e, &k, b"peer/alice|7", b"plaintext").expect("seal");
        assert_eq!(
            open(&k, &sealed.nonce, b"peer/alice|8", &sealed.ciphertext),
            Err(AeadOpenError::TagMismatch)
        );
        assert_eq!(
            open(&k, &sealed.nonce, b"trust/alice|7", &sealed.ciphertext),
            Err(AeadOpenError::TagMismatch)
        );
    }

    /// **Attack test.** A record sealed under one namespace's key must not open
    /// under another's, so a namespace compromise does not become a vault
    /// compromise.
    #[test]
    fn namespace_keys_are_independent() {
        let e = env();
        let s = sek();
        let a = s.derive_namespace_key(&STORE_ID, "peer/").expect("a");
        let b = s.derive_namespace_key(&STORE_ID, "trust/").expect("b");
        let sealed = seal(&e, &a, b"aad", b"x").expect("seal");
        assert_eq!(
            open(&b, &sealed.nonce, b"aad", &sealed.ciphertext),
            Err(AeadOpenError::TagMismatch)
        );
    }

    /// The `store_id` is the HKDF salt, so two vaults with the same `SEK` still
    /// derive different namespace keys. A vault copied to another install
    /// therefore does not decrypt under the new install's derivation.
    #[test]
    fn the_store_id_salts_the_hierarchy() {
        let e = env();
        let s = sek();
        let a = s.derive_namespace_key(&STORE_ID, "peer/").expect("a");
        let b = s
            .derive_namespace_key(&[0x2d; STORE_ID_LEN], "peer/")
            .expect("b");
        let sealed = seal(&e, &a, b"aad", b"x").expect("seal");
        assert_eq!(
            open(&b, &sealed.nonce, b"aad", &sealed.ciphertext),
            Err(AeadOpenError::TagMismatch)
        );
    }

    /// **Attack test.** A flipped bit anywhere in the ciphertext must fail the
    /// tag — E4/ST-17's "silent corruption is *detected* rather than returned as
    /// data".
    #[test]
    fn any_corruption_of_the_ciphertext_fails_the_tag() {
        let e = env();
        let k = sek().derive_namespace_key(&STORE_ID, "peer/").expect("k");
        let sealed = seal(&e, &k, b"aad", b"a longer plaintext to corrupt").expect("seal");
        for i in 0..sealed.ciphertext.len() {
            let mut ct = sealed.ciphertext.clone();
            ct[i] ^= 0x01;
            assert_eq!(
                open(&k, &sealed.nonce, b"aad", &ct),
                Err(AeadOpenError::TagMismatch),
                "corruption at {i} was not detected"
            );
        }
    }

    /// A truncated record is refused before the AEAD runs.
    #[test]
    fn a_truncated_record_is_refused() {
        let k = sek().derive_namespace_key(&STORE_ID, "peer/").expect("k");
        assert_eq!(
            open(&k, &[0u8; NONCE_LEN], b"aad", &[0u8; TAG_LEN - 1]),
            Err(AeadOpenError::Truncated)
        );
    }

    /// ST-16: the nonce is 192 bits and is drawn fresh for every write. Two
    /// seals of the same plaintext must differ, or the construction has become
    /// deterministic and the ciphertext leaks equality.
    #[test]
    fn every_write_draws_a_fresh_nonce() {
        let e = env();
        let k = sek().derive_namespace_key(&STORE_ID, "peer/").expect("k");
        let a = seal(&e, &k, b"aad", b"same").expect("a");
        let b = seal(&e, &k, b"aad", b"same").expect("b");
        assert_eq!(a.nonce.len(), 24, "ST-16 fixes a 192-bit nonce");
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn a_key_of_the_wrong_width_is_refused() {
        let mut raw = [0u8; 16];
        assert!(matches!(
            StoreKey::adopt_sek(&mut raw),
            Err(CryptoError::KeyLength {
                expected: 32,
                observed: 16
            })
        ));
    }

    #[test]
    fn debug_never_renders_key_material() {
        let k = sek();
        let s = format!("{k:?}");
        assert!(s.starts_with("StoreKey"));
        assert!(!s.contains("5e"));
    }
}
