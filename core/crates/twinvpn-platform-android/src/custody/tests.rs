//! Keystore custody over an in-memory element, so CB-6a, §11.16 (l)'s truthful
//! reporting and LC-15's locked-device path are all executed on this host.

use std::collections::BTreeMap;
use std::sync::Mutex;

use super::*;
use twinvpn_types::{DeviceId, IdentityId};

/// An in-memory element that performs the AEAD "itself", so the CB-6a
/// contract is exercised rather than asserted.
#[derive(Debug)]
struct FakeKeystore {
    level: SecurityLevel,
    attested: bool,
    locked: Mutex<bool>,
    items: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl FakeKeystore {
    fn new(level: SecurityLevel, attested: bool) -> Arc<Self> {
        Arc::new(Self {
            level,
            attested,
            locked: Mutex::new(false),
            items: Mutex::new(BTreeMap::new()),
        })
    }
    fn lock(&self) {
        *self.locked.lock().expect("lock") = true;
    }
    fn check(&self) -> Result<(), PlatformError> {
        if *self.locked.lock().expect("lock") {
            // ADR-0022 LC-15 / ADR-0020's `STORE.KEYSTORE_LOCKED`.
            return Err(PlatformError::SecureStoreUnavailable(None));
        }
        Ok(())
    }
}

impl KeystoreElement for FakeKeystore {
    fn name(&self) -> &'static str {
        "fake-keystore"
    }
    fn security_level(&self) -> SecurityLevel {
        self.level
    }
    fn public_identity(&self) -> Result<IdentityPublic, PlatformError> {
        self.check()?;
        Ok(IdentityPublic {
            device_id: DeviceId::from_array([0xd0; 32]),
            identity_id: IdentityId::from_array([0xd1; 32]),
            generation: 0,
            public_key: vec![0x04; 65],
        })
    }
    fn sign(&self, _key: IdentityKeyRef, message: &[u8]) -> Result<Signature, PlatformError> {
        self.check()?;
        // Not a signature scheme: this is a fake, and its output is a
        // length-correct opaque blob so the CALLER's handling is what the
        // test exercises. CD-I2 forbids a cryptographic dependency here.
        let mut sig = vec![0u8; 64];
        sig[0] = u8::try_from(message.len() & 0xff).unwrap_or(0);
        Ok(Signature::new(sig))
    }
    fn agree(
        &self,
        _key: IdentityKeyRef,
        _peer: &PeerPublicKey,
    ) -> Result<SharedSecret, PlatformError> {
        // Android Keystore offers ECDH on P-256 from API 31 and never offers
        // X25519. `OsUnsupported` is the honest answer at the floor.
        Err(PlatformError::OsUnsupported(None))
    }
    fn attestation(&self) -> Option<Vec<u8>> {
        self.attested.then(|| vec![0x30, 0x82, 0x01, 0x00])
    }
    fn item_read(&self, key: &SecureItemKey) -> Result<Option<Vec<u8>>, PlatformError> {
        self.check()?;
        Ok(self.items.lock().expect("lock").get(key.as_str()).cloned())
    }
    fn item_write_atomic(&self, key: &SecureItemKey, value: &[u8]) -> Result<(), PlatformError> {
        self.check()?;
        self.items
            .lock()
            .expect("lock")
            .insert(key.as_str().to_owned(), value.to_vec());
        Ok(())
    }
    fn item_delete(&self, key: &SecureItemKey) -> Result<(), PlatformError> {
        self.items.lock().expect("lock").remove(key.as_str());
        Ok(())
    }
}

fn store(element: Arc<dyn KeystoreElement>) -> AndroidSecureStore {
    AndroidSecureStore::new(
        element,
        PathBuf::from("/data/user/0/net.twinvpn.android/files/vault"),
        ShutdownLatch::new(),
    )
}

fn block_on<T>(mut future: BoxFuture<'_, T>) -> T {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll, Waker};
    struct Flag(AtomicBool);
    impl std::task::Wake for Flag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let flag = Arc::new(Flag(AtomicBool::new(false)));
    let waker = Waker::from(Arc::clone(&flag));
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
        std::thread::yield_now();
    }
}

/// **CB-6a, pinned.** Android is one of only two targets in ten where the
/// platform performs the record AEAD. Across `twinvpn.h`'s F-9 this is `1`.
#[test]
fn the_platform_performs_the_record_aead_at_every_security_level() {
    for level in [
        SecurityLevel::StrongBox,
        SecurityLevel::TrustedEnvironment,
        SecurityLevel::Software,
    ] {
        let store = store(FakeKeystore::new(level, false));
        assert_eq!(
            store.record_aead_custody(),
            RecordAeadCustody::PlatformPerformed,
            "Keystore AES-GCM with setRandomizedEncryptionRequired performs \
             the AEAD at {level:?}; hardware backing is a SEPARATE fact"
        );
    }
}

#[test]
fn hardware_backing_is_reported_truthfully_and_never_substituted() {
    for (level, expected) in [
        (SecurityLevel::StrongBox, true),
        (SecurityLevel::TrustedEnvironment, true),
        (SecurityLevel::Software, false),
        (SecurityLevel::Absent, false),
    ] {
        let element: Arc<dyn KeystoreElement> = match level {
            SecurityLevel::Absent => Arc::new(AbsentElement),
            _ => FakeKeystore::new(level, false),
        };
        let custody = AndroidIdentityCustody::new(element, ShutdownLatch::new());
        let attestation =
            block_on(custody.identity_attestation()).expect("attestation is readable");
        assert_eq!(attestation.hardware_backed, expected, "{level:?}");
    }
}

/// ADR-0007 N-6: a peer MUST NOT treat hardware backing as evidence without
/// a chain, so the format tag never appears without one.
#[test]
fn the_attestation_format_is_reported_only_alongside_a_chain() {
    let unattested = AndroidIdentityCustody::new(
        FakeKeystore::new(SecurityLevel::TrustedEnvironment, false),
        ShutdownLatch::new(),
    );
    let a = block_on(unattested.identity_attestation()).expect("readable");
    assert!(a.hardware_backed, "HARDWARE_UNATTESTED is still hardware");
    assert_eq!(a.attestation, None);
    assert_eq!(a.format, None);

    let attested = AndroidIdentityCustody::new(
        FakeKeystore::new(SecurityLevel::StrongBox, true),
        ShutdownLatch::new(),
    );
    let b = block_on(attested.identity_attestation()).expect("readable");
    assert!(b.attestation.is_some());
    assert_eq!(b.format, Some(ATTESTATION_FORMAT));
}

/// §11.16 (l): on an element that cannot serve, the answer is a refusal —
/// **never** a silently substituted file-backed signer.
#[test]
fn an_absent_element_refuses_rather_than_substituting_a_software_signer() {
    let custody = AndroidIdentityCustody::new(Arc::new(AbsentElement), ShutdownLatch::new());
    let err =
        block_on(custody.identity_sign(IdentityKeyRef::Identity { generation: 0 }, b"transcript"))
            .expect_err("refuses");
    assert_eq!(err.reason_code().as_str(), "AUTH.KEY_UNAVAILABLE");
    assert!(block_on(custody.public_identity()).is_err());
    assert_eq!(custody.element_name(), "absent");
}

/// ADR-0018 §11.16 (c) / ADR-0007 N-5: in-element agree is NOT required, and
/// `OsUnsupported` is a fact the core records — not a licence to fall back
/// to a private key the core does not have.
#[test]
fn in_element_agree_may_be_unsupported_and_that_is_a_reported_fact() {
    let custody = AndroidIdentityCustody::new(
        FakeKeystore::new(SecurityLevel::StrongBox, true),
        ShutdownLatch::new(),
    );
    let err = block_on(custody.identity_agree(
        IdentityKeyRef::Identity { generation: 0 },
        &PeerPublicKey(vec![0x04; 65]),
    ))
    .expect_err("unsupported");
    assert_eq!(err.reason_code().as_str(), "PLATFORM.OS_UNSUPPORTED");
}

#[test]
fn a_tier_one_item_round_trips_and_absent_is_not_an_error() {
    let element = FakeKeystore::new(SecurityLevel::StrongBox, true);
    let store = store(element.clone());
    let key = SecureItemKey::new("sek").expect("name");

    // Absent is a normal first-run state and enrols; unavailable must not.
    assert!(block_on(store.secure_item_read(&key))
        .expect("readable")
        .is_none());

    block_on(store.secure_item_write_atomic(&key, &SecureItem::new(vec![7u8; 32]))).expect("write");
    let read = block_on(store.secure_item_read(&key))
        .expect("readable")
        .expect("present");
    assert_eq!(read.as_bytes(), &[7u8; 32]);

    block_on(store.secure_item_delete(&key)).expect("delete");
    block_on(store.secure_item_delete(&key)).expect("delete is idempotent");
    assert!(block_on(store.secure_item_read(&key))
        .expect("readable")
        .is_none());
}

/// LC-15: locked before first unlock is fail-closed **and named**, never a
/// degradation.
#[test]
fn a_locked_device_is_reported_as_unavailable_and_never_as_absent() {
    let element = FakeKeystore::new(SecurityLevel::StrongBox, true);
    let store = store(element.clone());
    let key = SecureItemKey::new("sek").expect("name");
    block_on(store.secure_item_write_atomic(&key, &SecureItem::new(vec![1u8; 32])))
        .expect("write while unlocked");

    element.lock();
    let err = block_on(store.secure_item_read(&key)).expect_err("locked");
    // **A named residual, not an oversight.** `registry_version` 2 registered
    // `STORE.KEYSTORE_LOCKED`, and `codes::keystore_locked()` emits it — but
    // this error arrives through `PlatformError::SecureStoreUnavailable`, whose
    // mapping lives in `twinvpn-platform` and is shared by every adapter. So
    // the *specific* condition ("locked; wait for first unlock") is reachable
    // by name while the *seam's* answer is still the generic "the key store is
    // unavailable".
    //
    // Both are asserted rather than one being glossed: the day the seam carries
    // the specific code, the second assertion fails and points here.
    assert_eq!(err.reason_code().as_str(), "AUTH.KEY_STORE_UNAVAILABLE");
    assert_eq!(
        crate::codes::keystore_locked().as_str(),
        "STORE.KEYSTORE_LOCKED",
        "the adapter can name the condition even where the seam flattens it"
    );
    assert_ne!(
        err.reason_code(),
        crate::codes::keystore_locked(),
        "PlatformError::SecureStoreUnavailable still degrades to the generic code"
    );
    // TRANSIENT: the device will be unlocked, and rehydration completes then.
    assert_eq!(
        err.reason_code().class(),
        twinvpn_types::ErrorClass::Transient
    );
}

#[test]
fn the_vault_directory_is_vended_with_its_declared_attributes() {
    let store = store(FakeKeystore::new(SecurityLevel::StrongBox, true));
    let root = block_on(store.store_root()).expect("vended");
    assert!(
        root.attributes.backup_excluded,
        "ADR-0020: allowBackup=false"
    );
    assert_eq!(root.attributes.protection_class, Some(PROTECTION_CLASS));
    assert!(root.attributes.owner_only);
    assert!(root.path.is_absolute());
}

#[test]
fn a_relative_vault_path_is_refused_rather_than_resolved() {
    let store = AndroidSecureStore::new(
        FakeKeystore::new(SecurityLevel::StrongBox, true),
        PathBuf::from("files/vault"),
        ShutdownLatch::new(),
    );
    assert!(block_on(store.store_root()).is_err());
}

#[test]
fn a_delete_still_works_after_shutdown_begins() {
    let latch = ShutdownLatch::new();
    let element = FakeKeystore::new(SecurityLevel::StrongBox, true);
    let store = AndroidSecureStore::new(element, PathBuf::from("/vault"), latch.clone());
    let key = SecureItemKey::new("k_bind").expect("name");
    latch.begin();
    block_on(store.secure_item_delete(&key))
        .expect("a Tier-1 secret must not survive a delete the caller believed succeeded");
    assert!(block_on(store.secure_item_read(&key)).is_err());
}
