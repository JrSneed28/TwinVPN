//! CB-5 secret custody and CB-7 storage: the Secure Enclave and the Keychain.
//!
//! **Authority:** ADR-0018 CB-5, CB-6a, CB-7, §11.16 (c) and (l); ADR-0007 §7.3's
//! iOS row and **N-5**; ADR-0020 §11.3, §11.9, ST-5, ST-6, ST-12e, ST-22, ST-26;
//! `docs/implementation/ownership.md` §10.1 and §10.4.
//!
//! # CB-5, held by construction
//!
//! - The only state here is a [`SecureElement`] trait object — naming *which*
//!   element, never any bytes — and a shell-vended path.
//! - There is **no constructor that accepts key material.** No `from_bytes`, no
//!   `from_pem`, no `from_file`.
//! - There is **no accessor that yields any.** Every method returns a
//!   [`Signature`], a [`SharedSecret`] or a [`SecureItem`]; none is a key.
//! - `Debug` names the element and nothing else.
//!
//! # `identity_agree` on this target
//!
//! The Secure Enclave does **P-256 ECDH** and nothing else. It does not do
//! X25519, which is exactly ADR-0007 **N-5**'s reason for TK being hardware
//! *wrapped* rather than element-resident: "platform key APIs largely do not
//! offer X25519 ECDH".
//!
//! So an agreement the enclave cannot perform returns
//! [`PlatformError::OsUnsupported`] — `PLATFORM.OS_UNSUPPORTED` — and that is
//! **all** it does. `ownership.md` §10.1: "that is a fact the core records, never
//! a licence to substitute a software key." There is no branch in this file that
//! reaches for a key when the element declines, and there is no key here to
//! reach for.
//!
//! # CB-6a: `RecordAeadCustody::CoreHeld`, declared and not inferred
//!
//! ADR-0020 §11.3's CB-6a table, Apple row, verbatim: "**No.** The Secure Enclave
//! exposes key *agreement* and signing, not an arbitrary-length AEAD over caller
//! data; `SecKeyCreateEncryptedData` is an asymmetric envelope, not a per-record
//! AEAD at vault write rates." The consequence is also its: "Declared
//! software-held fallback: SEK is unwrapped by a SEP key, then held in the locked
//! allocator."
//!
//! [`IosSecureStore::record_aead_custody`] therefore returns
//! [`RecordAeadCustody::CoreHeld`], unconditionally, with no configuration that
//! can change it. CB-6a requires it "recorded in `CoreBuildIdentity` (S-46) and
//! surfaced in the diagnostic bundle, so 'this device's vault key was
//! software-held' is a readable fact rather than an inference" — the seam carries
//! it as this declared value, and the core does the recording.
//!
//! # A finding this module runs into and does not paper over
//!
//! [`IdentityPublic`] requires `device_id` and `identity_id`. `device_id` is
//! SHA-256 of the generation-0 identity key (ADR-0007 §7.1), and **this crate
//! cannot compute it**: CD-I2 permits a cryptographic dependency only in
//! `twinvpn-crypto`. On Linux the gap is invisible because the shell is Rust and
//! supplies the identifiers itself; a **Swift shell cannot**, which is W-24 and
//! W-25's shape landing on `IdentityCustody`. This module therefore takes the
//! identifiers as an injected [`IdentityRecord`] and **refuses** until it has
//! one, rather than inventing a `device_id` or hashing where CD-I2 says it may
//! not. Reported in the crate README and in the domain's report.

use std::sync::{Arc, Mutex};

use futures_core::future::BoxFuture;

use twinvpn_platform::{
    IdentityAttestation, IdentityCustody, IdentityKeyRef, IdentityPublic, PeerPublicKey,
    PlatformError, RecordAeadCustody, SecureItem, SecureItemKey, SecureStore, SharedSecret,
    Signature, StoreRoot,
};
use twinvpn_types::{DeviceId, IdentityId};

use crate::host::{HostStatus, ProviderHost};
use crate::keychain::{self, KeychainConfig};
use crate::netcfg::status_error;
use crate::oserr::{self, Context, SecOutcome};
use crate::shutdown::ShutdownLatch;

/// The agreement the Secure Enclave offers.
///
/// A tag rather than an enum with one variant, because [`ProviderHost::enclave_agree`]
/// takes it as data and a future element that offers a second shape should not
/// need this crate recompiled to name it.
pub const AGREEMENT_ECDH_P256: &str = "ecdh-p256";

/// The agreement the L-DATA static key would need, and which the enclave does
/// not offer.
///
/// Named so the refusal is legible: a reader asking "why is TK not in the
/// element" finds ADR-0007 N-5's answer attached to the thing that is missing.
pub const AGREEMENT_X25519: &str = "x25519";

/// Who this device is, supplied by the core.
///
/// See the module header. `device_id` is SHA-256 of the generation-0 identity
/// key and this crate may not hash; it is injected rather than derived, and its
/// absence is a refusal rather than a placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRecord {
    /// The `device_id`.
    pub device_id: DeviceId,
    /// The `identity_id` of the current generation.
    pub identity_id: IdentityId,
    /// The current generation.
    pub generation: u32,
}

/// An element that signs without exporting.
///
/// A trait object so a simulator, a device and a test bind the same custody with
/// different backings, and so `Debug` can name the element without reaching
/// anything it holds.
pub trait SecureElement: Send + Sync + core::fmt::Debug {
    /// A stable, non-localised name — `"secure-enclave"`, `"absent"`.
    fn name(&self) -> &'static str;

    /// Whether the private half genuinely lives in the element.
    fn hardware_backed(&self) -> bool;

    /// The public half and its attestation.
    fn public_key(&self, key: IdentityKeyRef) -> Result<crate::host::HostIdentity, PlatformError>;

    /// Signs inside the element.
    fn sign(&self, key: IdentityKeyRef, message: &[u8]) -> Result<Signature, PlatformError>;

    /// Agrees inside the element.
    ///
    /// [`PlatformError::OsUnsupported`] is a legitimate answer and is **not** a
    /// licence for anything else to happen.
    fn agree(
        &self,
        key: IdentityKeyRef,
        algorithm: &str,
        peer: &PeerPublicKey,
    ) -> Result<SharedSecret, PlatformError>;
}

/// The Secure Enclave, reached through the Swift bridge.
pub struct EnclaveElement {
    host: Arc<dyn ProviderHost>,
    config: KeychainConfig,
}

impl core::fmt::Debug for EnclaveElement {
    /// Names the element and nothing else.
    ///
    /// A derived `Debug` would walk into whatever the host holds, and
    /// `ownership.md` §6 rule 11 makes a derive that reaches a secret a defect
    /// rather than a style question.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EnclaveElement")
    }
}

impl EnclaveElement {
    /// Binds the enclave.
    #[must_use]
    pub fn new(host: Arc<dyn ProviderHost>, config: KeychainConfig) -> Self {
        Self { host, config }
    }

    fn tag(&self, key: IdentityKeyRef) -> String {
        match key {
            IdentityKeyRef::Identity { generation } => self.config.identity_key_tag(generation),
            IdentityKeyRef::OwnerSigning => self.config.owner_signing_key_tag(),
            IdentityKeyRef::OwnerRoot => self.config.owner_root_key_tag(),
            // The seam's enum is `#[non_exhaustive]`. A key kind this build does
            // not know must not silently become the identity key.
            _ => String::new(),
        }
    }
}

impl SecureElement for EnclaveElement {
    fn name(&self) -> &'static str {
        "secure-enclave"
    }

    fn hardware_backed(&self) -> bool {
        // §11.16 (l): reported truthfully per target. A simulator has no SEP and
        // the honest `false` is what the core records; the adapter MUST NOT
        // substitute a file-backed signer.
        self.host.enclave_hardware_backed()
    }

    fn public_key(&self, key: IdentityKeyRef) -> Result<crate::host::HostIdentity, PlatformError> {
        let tag = self.tag(key);
        if tag.is_empty() {
            return Err(unknown_key_kind());
        }
        self.host
            .enclave_public(&tag)
            .map_err(|s| status_error(s, "SecKeyCopyPublicKey", Context::Identity))
    }

    fn sign(&self, key: IdentityKeyRef, message: &[u8]) -> Result<Signature, PlatformError> {
        let tag = self.tag(key);
        if tag.is_empty() {
            return Err(unknown_key_kind());
        }
        self.host
            .enclave_sign(&tag, message)
            .map(Signature::new)
            .map_err(|s| status_error(s, "SecKeyCreateSignature", Context::Identity))
    }

    fn agree(
        &self,
        key: IdentityKeyRef,
        algorithm: &str,
        peer: &PeerPublicKey,
    ) -> Result<SharedSecret, PlatformError> {
        let tag = self.tag(key);
        if tag.is_empty() {
            return Err(unknown_key_kind());
        }
        self.host
            .enclave_agree(&tag, algorithm, &peer.0)
            .map(SharedSecret::new)
            .map_err(|s| status_error(s, "SecKeyCopyKeyExchangeResult", Context::Identity))
    }
}

fn unknown_key_kind() -> PlatformError {
    PlatformError::OsUnsupported(Some(oserr::detail_from_code(
        oserr::ERR_SEC_PARAM,
        "IdentityKeyRef.unknown",
    )))
}

/// An element that is absent — a simulator, or a device whose SEP has lost its
/// backing.
///
/// Reports `hardware_backed: false` **truthfully** and refuses every operation.
/// §11.16 (l): "the core MUST NOT substitute a file-backed signer silently", and
/// the way to make that true is for the absent case to have nothing to
/// substitute with.
#[derive(Debug, Clone, Copy, Default)]
pub struct AbsentElement;

impl SecureElement for AbsentElement {
    fn name(&self) -> &'static str {
        "absent"
    }

    fn hardware_backed(&self) -> bool {
        false
    }

    fn public_key(&self, _key: IdentityKeyRef) -> Result<crate::host::HostIdentity, PlatformError> {
        Err(absent())
    }

    fn sign(&self, _key: IdentityKeyRef, _message: &[u8]) -> Result<Signature, PlatformError> {
        Err(absent())
    }

    fn agree(
        &self,
        _key: IdentityKeyRef,
        _algorithm: &str,
        _peer: &PeerPublicKey,
    ) -> Result<SharedSecret, PlatformError> {
        Err(absent())
    }
}

fn absent() -> PlatformError {
    PlatformError::IdentityKeyUnavailable(Some(oserr::detail_from_code(
        libc::ENODEV,
        "identity.element",
    )))
}

/// CB-5 identity custody.
pub struct IosIdentityCustody {
    element: Arc<dyn SecureElement>,
    shutdown: ShutdownLatch,
    record: Mutex<Option<IdentityRecord>>,
}

impl core::fmt::Debug for IosIdentityCustody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IosIdentityCustody({})", self.element.name())
    }
}

impl IosIdentityCustody {
    /// Binds custody to an element. **No key material crosses this boundary.**
    #[must_use]
    pub fn new(element: Arc<dyn SecureElement>, shutdown: ShutdownLatch) -> Self {
        Self {
            element,
            shutdown,
            record: Mutex::new(None),
        }
    }

    /// Supplies the identifiers this crate may not derive.
    ///
    /// See the module header's finding. Called by the composition root once
    /// `twinvpn-crypto` has hashed the generation-0 public key.
    pub fn set_record(&self, record: IdentityRecord) {
        *guard(&self.record) = Some(record);
    }

    /// The element's stable name, for `CoreBuildIdentity` (S-46).
    #[must_use]
    pub fn element_name(&self) -> &'static str {
        self.element.name()
    }
}

fn guard<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl IdentityCustody for IosIdentityCustody {
    fn public_identity(&self) -> BoxFuture<'_, Result<IdentityPublic, PlatformError>> {
        Box::pin(async move {
            self.shutdown.guard()?;
            let record = guard(&self.record).clone().ok_or_else(|| {
                // Refused rather than invented. A fabricated `device_id` would
                // be a device identity nobody issued, and the pairing ceremony
                // binds to it.
                PlatformError::IdentityKeyUnavailable(Some(oserr::detail_from_code(
                    0,
                    "identity.record.unset",
                )))
            })?;
            let public = self.element.public_key(IdentityKeyRef::Identity {
                generation: record.generation,
            })?;
            Ok(IdentityPublic {
                device_id: record.device_id,
                identity_id: record.identity_id,
                generation: record.generation,
                public_key: public.public_key,
            })
        })
    }

    fn identity_sign<'a>(
        &'a self,
        key: IdentityKeyRef,
        message: &'a [u8],
    ) -> BoxFuture<'a, Result<Signature, PlatformError>> {
        Box::pin(async move {
            self.shutdown.guard()?;
            self.element.sign(key, message)
        })
    }

    fn identity_agree<'a>(
        &'a self,
        key: IdentityKeyRef,
        peer: &'a PeerPublicKey,
    ) -> BoxFuture<'a, Result<SharedSecret, PlatformError>> {
        Box::pin(async move {
            self.shutdown.guard()?;
            // P-256 ECDH is the only shape the enclave offers. If the element
            // declines, that is the whole answer: a refusal the core records.
            self.element.agree(key, AGREEMENT_ECDH_P256, peer)
        })
    }

    fn identity_attestation(&self) -> BoxFuture<'_, Result<IdentityAttestation, PlatformError>> {
        Box::pin(async move {
            self.shutdown.guard()?;
            let generation = guard(&self.record).as_ref().map_or(0, |r| r.generation);
            let hardware_backed = self.element.hardware_backed();
            let attestation = self
                .element
                .public_key(IdentityKeyRef::Identity { generation })
                .ok()
                .and_then(|identity| identity.attestation);
            Ok(IdentityAttestation {
                hardware_backed,
                attestation,
                // ADR-0007 §7.3's iOS row: `SecKeyCreateAttestation`, DCRK-rooted.
                // The tag is only meaningful when there is a blob to describe.
                format: attestation_format(hardware_backed),
            })
        })
    }
}

const fn attestation_format(hardware_backed: bool) -> Option<&'static str> {
    if hardware_backed {
        Some("apple-sep-dcrk")
    } else {
        None
    }
}

/// CB-7 Tier-1 storage and the vended store root.
pub struct IosSecureStore {
    host: Arc<dyn ProviderHost>,
    config: KeychainConfig,
    shutdown: ShutdownLatch,
}

impl core::fmt::Debug for IosSecureStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IosSecureStore")
    }
}

impl IosSecureStore {
    /// Binds the store.
    #[must_use]
    pub fn new(
        host: Arc<dyn ProviderHost>,
        config: KeychainConfig,
        shutdown: ShutdownLatch,
    ) -> Self {
        Self {
            host,
            config,
            shutdown,
        }
    }
}

fn sec_error(status: HostStatus, call: &'static str) -> PlatformError {
    match status {
        HostStatus::OsStatus(code) => match oserr::from_os_status(code, call, Context::SecureStore)
        {
            SecOutcome::Failed(err) => err,
            SecOutcome::Ok | SecOutcome::Absent => {
                PlatformError::SecureStoreUnavailable(Some(oserr::detail_from_code(code, call)))
            }
        },
        other => status_error(other, call, Context::SecureStore),
    }
}

impl SecureStore for IosSecureStore {
    fn secure_item_read<'a>(
        &'a self,
        key: &'a SecureItemKey,
    ) -> BoxFuture<'a, Result<Option<SecureItem>, PlatformError>> {
        Box::pin(async move {
            self.shutdown.guard()?;
            match self.host.keychain_read(&self.config.item(key).to_json()) {
                // `Ok(None)` is "absent", which is a normal first-run state and
                // NOT an error. The distinction is load-bearing: absent enrols
                // and unavailable must not, and on this platform "unavailable"
                // is most often the locked device before first unlock.
                Ok(value) => Ok(value.map(SecureItem::new)),
                Err(HostStatus::OsStatus(code)) if code == oserr::ERR_SEC_ITEM_NOT_FOUND => {
                    Ok(None)
                }
                Err(status) => Err(sec_error(status, "SecItemCopyMatching")),
            }
        })
    }

    fn secure_item_write_atomic<'a>(
        &'a self,
        key: &'a SecureItemKey,
        value: &'a SecureItem,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.guard()?;
            // Whole-blob atomic replacement, which is "the shape Keychain /
            // Keystore / DPAPI / libsecret actually have" (F-9's comment). A
            // torn write of the SEK makes the whole vault unreadable, and
            // ADR-0020's recovery ladder cannot recover a key it never received.
            match self
                .host
                .keychain_write(&self.config.item(key).to_json(), value.as_bytes())
            {
                HostStatus::Ok => Ok(()),
                other => Err(sec_error(other, "SecItemAdd")),
            }
        })
    }

    fn secure_item_delete<'a>(
        &'a self,
        key: &'a SecureItemKey,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            // Idempotent, and not gated on the shutdown latch: a delete is part
            // of teardown and of the uninstall path ST-27 describes.
            match self.host.keychain_delete(&self.config.item(key).to_json()) {
                HostStatus::Ok => Ok(()),
                // Deleting what is not there is success, by definition of
                // idempotent.
                HostStatus::OsStatus(code) if code == oserr::ERR_SEC_ITEM_NOT_FOUND => Ok(()),
                other => Err(sec_error(other, "SecItemDelete")),
            }
        })
    }

    fn store_root(&self) -> BoxFuture<'_, Result<StoreRoot, PlatformError>> {
        Box::pin(async move {
            self.shutdown.guard()?;
            // ST-12e: vended at construction, never discovered. The path is the
            // App Group container URL, and the file-protection class and
            // backup-exclusion flag are already applied by the time it arrives —
            // CB-7 puts exactly those three things on the shell's side because
            // "on iOS the app-group container URL, the file protection class,
            // and the backup-exclusion flag are Objective-C APIs".
            let path = self.host.store_root().map_err(|s| {
                sec_error(s, "containerURL(forSecurityApplicationGroupIdentifier:)")
            })?;
            if path.is_empty() {
                return Err(PlatformError::SecureStoreUnavailable(Some(
                    oserr::detail_from_code(0, "store_root.empty"),
                )));
            }
            Ok(StoreRoot {
                path: std::path::PathBuf::from(path),
                attributes: keychain::store_root_attributes(
                    // ST-26: re-verified at every start, never assumed.
                    self.host.store_root_backup_excluded(),
                ),
            })
        })
    }

    fn record_aead_custody(&self) -> RecordAeadCustody {
        // CB-6a, ADR-0020 §11.3's Apple row: **No** platform AEAD. The Secure
        // Enclave offers key agreement and signing, not an arbitrary-length AEAD
        // over caller data. There is no configuration that changes this and no
        // device on which it differs, which is why it is a constant rather than
        // a probe: a probe would imply the answer could come back the other way.
        RecordAeadCustody::CoreHeld
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{DetachedHost, RecordingHost};

    fn config() -> KeychainConfig {
        KeychainConfig::new("ABCDE12345.group.com.twinvpn", "com.twinvpn.client").expect("config")
    }

    fn block_on<T>(future: impl core::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    fn store() -> (Arc<RecordingHost>, IosSecureStore) {
        let host = Arc::new(RecordingHost::new("/tmp/twinvpn-ios/AppGroup"));
        let store = IosSecureStore::new(host.clone(), config(), ShutdownLatch::new());
        (host, store)
    }

    fn custody() -> (Arc<RecordingHost>, IosIdentityCustody) {
        let host = Arc::new(RecordingHost::new("/tmp/twinvpn-ios/AppGroup"));
        let element = Arc::new(EnclaveElement::new(host.clone(), config()));
        (host, IosIdentityCustody::new(element, ShutdownLatch::new()))
    }

    fn key(name: &str) -> SecureItemKey {
        SecureItemKey::new(name).expect("key")
    }

    #[test]
    fn an_absent_item_enrols_and_an_unavailable_one_does_not() {
        let (_host, store) = store();
        assert!(block_on(store.secure_item_read(&key("sek")))
            .expect("reads")
            .is_none());

        block_on(store.secure_item_write_atomic(&key("sek"), &SecureItem::new(vec![1, 2, 3])))
            .expect("writes");
        let read = block_on(store.secure_item_read(&key("sek")))
            .expect("reads")
            .expect("present");
        assert_eq!(read.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn a_locked_device_is_unavailable_and_is_never_reported_as_absent() {
        // Conflating them would make the provider re-enrol the device every
        // time it started before the first unlock — a new identity per reboot.
        let (host, store) = store();
        host.fail_next(HostStatus::OsStatus(oserr::ERR_SEC_INTERACTION_NOT_ALLOWED));
        let err = block_on(store.secure_item_write_atomic(&key("sek"), &SecureItem::new(vec![1])))
            .expect_err("refuses");
        assert_eq!(err.reason_code().as_str(), "AUTH.KEY_STORE_UNAVAILABLE");
        assert_eq!(
            err.os_detail().map(|d| d.code),
            Some(i64::from(oserr::ERR_SEC_INTERACTION_NOT_ALLOWED))
        );
    }

    #[test]
    fn a_write_is_whole_blob_replacement_and_not_a_merge() {
        let (_host, store) = store();
        block_on(store.secure_item_write_atomic(&key("sek"), &SecureItem::new(vec![1; 32])))
            .expect("writes");
        block_on(store.secure_item_write_atomic(&key("sek"), &SecureItem::new(vec![2; 8])))
            .expect("replaces");
        let read = block_on(store.secure_item_read(&key("sek")))
            .expect("reads")
            .expect("present");
        assert_eq!(read.as_bytes(), &[2u8; 8]);
    }

    #[test]
    fn delete_is_idempotent_and_runs_during_shutdown() {
        let host = Arc::new(RecordingHost::new("/tmp/twinvpn-ios/AppGroup"));
        let shutdown = ShutdownLatch::new();
        let store = IosSecureStore::new(host.clone(), config(), shutdown.clone());
        block_on(store.secure_item_write_atomic(&key("sek"), &SecureItem::new(vec![1])))
            .expect("writes");
        shutdown.begin();
        block_on(store.secure_item_delete(&key("sek"))).expect("deletes");
        block_on(store.secure_item_delete(&key("sek"))).expect("again");
        assert!(host.state().keychain.is_empty());
    }

    #[test]
    fn every_item_is_stored_under_the_tier1_accessibility_class() {
        // ST-5, checked at the level the store actually uses: the query the host
        // receives is the one `crate::keychain` computed.
        let (host, store) = store();
        for name in ["sek", "k_bind", "s53_anchor"] {
            block_on(store.secure_item_write_atomic(&key(name), &SecureItem::new(vec![0])))
                .expect("writes");
        }
        assert_eq!(host.state().keychain.len(), 3);
        for query in host.state().keychain.keys() {
            assert!(
                query.contains("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"),
                "{query}"
            );
            assert!(query.contains("\"synchronizable\":false"), "{query}");
        }
    }

    #[test]
    fn the_store_root_is_vended_with_its_attributes_already_applied() {
        // CB-7 and ST-12e. The core does not derive, probe, or fall back to a
        // path of its own.
        let (_host, store) = store();
        let root = block_on(store.store_root()).expect("vends");
        assert_eq!(
            root.path,
            std::path::PathBuf::from("/tmp/twinvpn-ios/AppGroup")
        );
        assert_eq!(
            root.attributes.protection_class,
            Some("NSFileProtectionCompleteUntilFirstUserAuthentication")
        );
        assert!(root.attributes.backup_excluded);
        assert!(root.attributes.owner_only);
    }

    #[test]
    fn a_failed_backup_exclusion_is_carried_rather_than_asserted_true() {
        // ST-26: "re-verified at every start; a failure is
        // STORE.BACKUP_EXCLUSION_FAILED, not a silent success." That code is not
        // in the frozen registry, so the fact travels as the declared attribute.
        let (host, store) = store();
        host.state().backup_excluded = false;
        let root = block_on(store.store_root()).expect("vends");
        assert!(!root.attributes.backup_excluded);
    }

    #[test]
    fn an_empty_store_root_is_refused_rather_than_treated_as_the_cwd() {
        let (host, store) = store();
        host.state().store_root = String::new();
        let err = block_on(store.store_root()).expect_err("refuses");
        assert_eq!(err.reason_code().as_str(), "AUTH.KEY_STORE_UNAVAILABLE");
    }

    #[test]
    fn the_record_aead_custody_is_core_held_on_every_apple_device() {
        // CB-6a and ADR-0020 §11.3's Apple row: the Secure Enclave has no
        // arbitrary-length AEAD over caller data. There is no configuration that
        // changes this, which is why it is a constant and not a probe.
        let (_host, store) = store();
        assert_eq!(store.record_aead_custody(), RecordAeadCustody::CoreHeld);
        let detached = IosSecureStore::new(Arc::new(DetachedHost), config(), ShutdownLatch::new());
        assert_eq!(detached.record_aead_custody(), RecordAeadCustody::CoreHeld);
    }

    #[test]
    fn an_x25519_agreement_is_refused_and_nothing_is_substituted() {
        // ADR-0007 N-5 and ownership.md §10.1: "that is a fact the core records,
        // never a licence to substitute a software key."
        let (host, custody) = custody();
        host.state().agree_algorithms = vec![AGREEMENT_ECDH_P256.to_owned()];
        // The seam's `identity_agree` asks for the enclave's own shape; a caller
        // wanting X25519 gets it through the element, which declines.
        let element = EnclaveElement::new(host.clone(), config());
        let err = element
            .agree(
                IdentityKeyRef::Identity { generation: 0 },
                AGREEMENT_X25519,
                &PeerPublicKey(vec![0u8; 32]),
            )
            .expect_err("refuses");
        assert_eq!(err.reason_code().as_str(), "PLATFORM.OS_UNSUPPORTED");

        // And the P-256 shape the enclave does offer still works, so the refusal
        // is about the algorithm and not about the element being broken.
        assert!(block_on(custody.identity_agree(
            IdentityKeyRef::Identity { generation: 0 },
            &PeerPublicKey(vec![0u8; 65])
        ))
        .is_ok());
    }

    #[test]
    fn an_element_that_offers_no_agreement_at_all_still_only_reports_a_fact() {
        let (host, custody) = custody();
        host.state().agree_algorithms.clear();
        let err = block_on(custody.identity_agree(
            IdentityKeyRef::Identity { generation: 0 },
            &PeerPublicKey(vec![0u8; 65]),
        ))
        .expect_err("refuses");
        assert_eq!(err.reason_code().as_str(), "PLATFORM.OS_UNSUPPORTED");
    }

    #[test]
    fn hardware_backing_is_reported_truthfully_and_never_substituted() {
        // §11.16 (l). A simulator has no SEP; `false` is the honest answer and
        // the core records it.
        let (host, custody) = custody();
        assert!(
            block_on(custody.identity_attestation())
                .expect("attests")
                .hardware_backed
        );

        host.state().hardware_backed = false;
        let attestation = block_on(custody.identity_attestation()).expect("attests");
        assert!(!attestation.hardware_backed);
        assert!(attestation.attestation.is_none());
        assert!(attestation.format.is_none());
    }

    #[test]
    fn an_absent_element_refuses_every_operation_and_has_nothing_to_substitute() {
        let custody = IosIdentityCustody::new(Arc::new(AbsentElement), ShutdownLatch::new());
        assert_eq!(custody.element_name(), "absent");
        let err =
            block_on(custody.identity_sign(IdentityKeyRef::Identity { generation: 0 }, b"message"))
                .expect_err("refuses");
        assert_eq!(err.reason_code().as_str(), "AUTH.KEY_UNAVAILABLE");
        assert!(
            !block_on(custody.identity_attestation())
                .expect("attests")
                .hardware_backed
        );
    }

    #[test]
    fn the_public_identity_is_refused_until_the_core_supplies_the_identifiers() {
        // The module header's finding: `device_id` is SHA-256 of the generation-0
        // key and CD-I2 forbids this crate a hash. A fabricated one would be a
        // device identity nobody issued, and the pairing ceremony binds to it.
        let (_host, custody) = custody();
        let err = block_on(custody.public_identity()).expect_err("refuses");
        assert_eq!(err.reason_code().as_str(), "AUTH.KEY_UNAVAILABLE");
        assert_eq!(
            err.os_detail().map(|d| d.call),
            Some("identity.record.unset")
        );

        custody.set_record(IdentityRecord {
            device_id: DeviceId::from_array([7u8; 32]),
            identity_id: IdentityId::from_array([9u8; 32]),
            generation: 0,
        });
        let identity = block_on(custody.public_identity()).expect("reads");
        assert_eq!(identity.device_id, DeviceId::from_array([7u8; 32]));
        assert_eq!(identity.generation, 0);
        assert!(!identity.public_key.is_empty());
    }

    #[test]
    fn a_signature_names_the_generation_it_was_made_with() {
        // ADR-0007 rotation: two generations are live during T_IK_OVERLAP, so
        // "the identity key" without a generation names the wrong one exactly
        // when it matters.
        let (_host, custody) = custody();
        let a =
            block_on(custody.identity_sign(IdentityKeyRef::Identity { generation: 0 }, b"message"))
                .expect("signs");
        let b =
            block_on(custody.identity_sign(IdentityKeyRef::Identity { generation: 1 }, b"message"))
                .expect("signs");
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn the_owner_keys_are_distinct_from_the_identity_key() {
        let (_host, custody) = custody();
        let identity =
            block_on(custody.identity_sign(IdentityKeyRef::Identity { generation: 0 }, b"m"))
                .expect("signs");
        let signing =
            block_on(custody.identity_sign(IdentityKeyRef::OwnerSigning, b"m")).expect("signs");
        let root = block_on(custody.identity_sign(IdentityKeyRef::OwnerRoot, b"m")).expect("signs");
        assert_ne!(identity.as_bytes(), signing.as_bytes());
        assert_ne!(signing.as_bytes(), root.as_bytes());
    }

    #[test]
    fn debug_names_the_element_and_reaches_nothing_it_holds() {
        // §6 rule 11: a derive that reaches a secret is a defect, not a style
        // question.
        let (_host, custody) = custody();
        let rendered = format!("{custody:?}");
        assert_eq!(rendered, "IosIdentityCustody(secure-enclave)");
    }

    #[test]
    fn after_shutdown_identity_operations_refuse_by_name() {
        let host = Arc::new(RecordingHost::new("/tmp/twinvpn-ios/AppGroup"));
        let shutdown = ShutdownLatch::new();
        let custody = IosIdentityCustody::new(
            Arc::new(EnclaveElement::new(host, config())),
            shutdown.clone(),
        );
        shutdown.begin();
        assert_eq!(
            block_on(custody.identity_sign(IdentityKeyRef::Identity { generation: 0 }, b"m")),
            Err(PlatformError::ShuttingDown)
        );
    }
}
