//! CB-5 identity custody and CB-7 Tier-1 storage, over the Android Keystore.
//!
//! **Authority:** ADR-0018 CB-5, **CB-6a**, CB-7, §11.16 (c) and (l);
//! ADR-0020 §11's Android rows (Keystore EC P-256, StrongBox → TEE → software;
//! SEK as an AES-256-GCM Keystore key with `setRandomizedEncryptionRequired`;
//! credential-encrypted storage; `dataExtractionRules` excluding both sections);
//! ADR-0007 N-5 and N-6; ADR-0022 **LC-15**.
//!
//! # Android is one of the two targets with mandatory platform AEAD
//!
//! CB-6a: *"the honest aggregate from ADR-0020's per-target survey: **mandatory
//! platform AEAD exists on 2 of 10 targets** — Android (Keystore AES-GCM with
//! `setRandomizedEncryptionRequired`) and Windows with a TPM."*
//!
//! So [`AndroidSecureStore::record_aead_custody`] returns
//! [`RecordAeadCustody::PlatformPerformed`] — **1** across `twinvpn.h`'s F-9 —
//! and the SEK is never materialised in core memory. That is a declared fact
//! under CB-6a, not an inference from the code, and it is pinned by a test.
//!
//! It holds at **every** `SecurityLevel`, including a software keymaster: the
//! flag governs who performs the AEAD, not where the key lives. A software
//! keymaster still performs the AEAD in Keystore; what it loses is *hardware
//! backing*, which is a separate fact reported separately by
//! [`AndroidIdentityCustody::identity_attestation`]. Conflating the two is the
//! erosion CB-6a exists to stop.
//!
//! # I4, held at the trait boundary
//!
//! No method here returns private key material and no parameter accepts any.
//! [`KeystoreElement`] has no `export`, no `raw`, and nothing that could carry a
//! scalar; the identity key is generated in Keystore with `setKeySize` and
//! `setDigests` and is non-exportable by construction, which is what makes
//! ADR-0020's `HARDWARE_ATTESTED` claim true rather than asserted.
//!
//! # LC-15: locked before first unlock, fail-closed and *named*
//!
//! ADR-0020 puts the identity key and the SEK in **credential-encrypted**
//! storage, which is unreadable before the first unlock after a reboot — and
//! always-on VPN starts the service at boot. LC-15's answer is not to weaken the
//! key: it is to come up fail-closed with a name, and complete rehydration on
//! the first unlock. Every method here therefore reports
//! [`PlatformError::IdentityKeyUnavailable`] or
//! [`PlatformError::SecureStoreUnavailable`] rather than degrading, and
//! [`crate::codes::keystore_locked`] carries the substitution for ADR-0020's
//! unregistered `STORE.KEYSTORE_LOCKED`.

use std::path::PathBuf;
use std::sync::Arc;

use futures_core::future::BoxFuture;

use twinvpn_platform::{
    IdentityAttestation, IdentityCustody, IdentityKeyRef, IdentityPublic, PeerPublicKey,
    PlatformError, RecordAeadCustody, SecureItem, SecureItemKey, SecureStore, SharedSecret,
    Signature, StoreRoot, StoreRootAttributes,
};

use crate::hostcall::{KeystoreElement, SecurityLevel};
use crate::oserr;
use crate::shutdown::ShutdownLatch;

/// The attestation format tag recorded in S-46.
///
/// Stable and non-localised. ADR-0020's ladder distinguishes
/// `HARDWARE_ATTESTED` from `HARDWARE_UNATTESTED` by whether a chain was
/// obtainable, and a peer MUST NOT treat hardware backing as evidence without
/// one (ADR-0007 N-6) — so the format is only ever reported alongside a chain.
pub const ATTESTATION_FORMAT: &str = "android-key-attestation";

/// The file-protection class tag for a vended [`StoreRoot`].
///
/// ADR-0020 §11's Android row: the **default credential-encrypted context**, not
/// `createDeviceProtectedStorageContext()`. The distinction is load-bearing —
/// device-encrypted storage is readable before first unlock and may hold only
/// the non-secret bootstrap record LC-15 permits.
pub const PROTECTION_CLASS: &str = "android-credential-encrypted";

/// An element on a device where the Keystore could not be opened at all.
///
/// Refuses every operation and reports `hardware_backed: false` truthfully.
/// §11.16 (l)'s specified behaviour, not an omission: the alternative it forbids
/// is a silent file-backed signer.
///
/// On a real Android device this should never be constructed — every Android
/// release has a Keystore. It exists so that "we could not open it" is a value
/// the adapter can hold and report, rather than a `None` the shell has to
/// interpret.
#[derive(Debug, Clone, Copy, Default)]
pub struct AbsentElement;

impl KeystoreElement for AbsentElement {
    fn name(&self) -> &'static str {
        "absent"
    }
    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::Absent
    }
    fn public_identity(&self) -> Result<IdentityPublic, PlatformError> {
        Err(PlatformError::IdentityKeyUnavailable(None))
    }
    fn sign(&self, _key: IdentityKeyRef, _message: &[u8]) -> Result<Signature, PlatformError> {
        Err(PlatformError::IdentityKeyUnavailable(None))
    }
    fn agree(
        &self,
        _key: IdentityKeyRef,
        _peer: &PeerPublicKey,
    ) -> Result<SharedSecret, PlatformError> {
        Err(PlatformError::OsUnsupported(None))
    }
    fn attestation(&self) -> Option<Vec<u8>> {
        None
    }
    fn item_read(&self, _key: &SecureItemKey) -> Result<Option<Vec<u8>>, PlatformError> {
        Err(PlatformError::SecureStoreUnavailable(None))
    }
    fn item_write_atomic(&self, _key: &SecureItemKey, _value: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::SecureStoreUnavailable(None))
    }
    fn item_delete(&self, _key: &SecureItemKey) -> Result<(), PlatformError> {
        Err(PlatformError::SecureStoreUnavailable(None))
    }
}

/// Identity operations performed inside the Keystore (CB-5).
#[derive(Debug, Clone)]
pub struct AndroidIdentityCustody {
    element: Arc<dyn KeystoreElement>,
    shutdown: ShutdownLatch,
}

impl AndroidIdentityCustody {
    /// Binds the custody surface to an element.
    #[must_use]
    pub fn new(element: Arc<dyn KeystoreElement>, shutdown: ShutdownLatch) -> Self {
        Self { element, shutdown }
    }

    /// The element's stable name, for S-46.
    #[must_use]
    pub fn element_name(&self) -> &'static str {
        self.element.name()
    }

    /// The `SecurityLevel` the key material actually reached.
    #[must_use]
    pub fn security_level(&self) -> SecurityLevel {
        self.element.security_level()
    }
}

impl IdentityCustody for AndroidIdentityCustody {
    fn public_identity(&self) -> BoxFuture<'_, Result<IdentityPublic, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            self.element.public_identity()
        })
    }

    fn identity_sign<'a>(
        &'a self,
        key: IdentityKeyRef,
        message: &'a [u8],
    ) -> BoxFuture<'a, Result<Signature, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            self.element.sign(key, message)
        })
    }

    fn identity_agree<'a>(
        &'a self,
        key: IdentityKeyRef,
        peer: &'a PeerPublicKey,
    ) -> BoxFuture<'a, Result<SharedSecret, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            self.element.agree(key, peer)
        })
    }

    fn identity_attestation(&self) -> BoxFuture<'_, Result<IdentityAttestation, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            let level = self.element.security_level();
            let attestation = self.element.attestation();
            Ok(IdentityAttestation {
                // TRUTHFULLY, per §11.16 (l). A software keymaster reports
                // `false` and the core records the fact; it does not refuse, and
                // it does not silently substitute.
                hardware_backed: level.hardware_backed(),
                // The format is reported only WITH a chain: ADR-0007 N-6 says a
                // peer must not treat hardware backing as evidence without one,
                // and a format tag with no blob would suggest otherwise.
                format: attestation.as_ref().map(|_| ATTESTATION_FORMAT),
                attestation,
            })
        })
    }
}

/// Tier-1 secure items and the vended vault directory (CB-7).
#[derive(Debug, Clone)]
pub struct AndroidSecureStore {
    element: Arc<dyn KeystoreElement>,
    /// **Injected, never discovered** (CD-2, CB-7). The shell supplies the
    /// credential-encrypted app directory it created with its attributes already
    /// applied; this crate never calls `Context.getFilesDir()` itself.
    root: PathBuf,
    shutdown: ShutdownLatch,
}

impl AndroidSecureStore {
    /// Binds the store over an element and a vended directory.
    #[must_use]
    pub fn new(element: Arc<dyn KeystoreElement>, root: PathBuf, shutdown: ShutdownLatch) -> Self {
        Self {
            element,
            root,
            shutdown,
        }
    }
}

impl SecureStore for AndroidSecureStore {
    fn secure_item_read<'a>(
        &'a self,
        key: &'a SecureItemKey,
    ) -> BoxFuture<'a, Result<Option<SecureItem>, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            Ok(self.element.item_read(key)?.map(SecureItem::new))
        })
    }

    fn secure_item_write_atomic<'a>(
        &'a self,
        key: &'a SecureItemKey,
        value: &'a SecureItem,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            self.element.item_write_atomic(key, value.as_bytes())
        })
    }

    fn secure_item_delete<'a>(
        &'a self,
        key: &'a SecureItemKey,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            // NOT gated on the shutdown latch. A delete that silently succeeded
            // without deleting would leave a Tier-1 secret durable after the
            // caller believed it gone -- which is exactly the direction W-35
            // records as the harmful one.
            self.element.item_delete(key)
        })
    }

    fn store_root(&self) -> BoxFuture<'_, Result<StoreRoot, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            if !self.root.is_absolute() {
                // A relative vault path would resolve against whatever the
                // process's working directory happens to be, which on Android is
                // `/`. Refused rather than resolved.
                return Err(oserr::unavailable("store_root", libc::EINVAL));
            }
            Ok(StoreRoot {
                path: self.root.clone(),
                attributes: StoreRootAttributes {
                    // ADR-0020 §11: `android:allowBackup="false"`, or
                    // `dataExtractionRules` excluding the store path in BOTH
                    // `<cloud-backup>` and `<device-transfer>` (API 31+). The
                    // shell's manifest is what makes this true; the adapter
                    // DECLARES it so S-46 records it rather than assuming it.
                    backup_excluded: true,
                    protection_class: Some(PROTECTION_CLASS),
                    // App UID, mode 0700, and only the `VpnService` process holds
                    // the store open (ADR-0020 §11, ADR-0016 H2).
                    owner_only: true,
                },
            })
        })
    }

    fn record_aead_custody(&self) -> RecordAeadCustody {
        // CB-6a, and one of only two targets in ten. See the module docs: this
        // holds at every SecurityLevel, because the flag governs who performs
        // the AEAD and not where the key lives.
        RecordAeadCustody::PlatformPerformed
    }
}

#[cfg(test)]
mod tests;
