//! CB-5 identity custody and CB-7 Tier-1 storage.
//!
//! **Authority:** [`twinvpn_platform::custody`], ADR-0018 CB-5, CB-6a, CB-7,
//! §11.16 (c) and (l), CD-I4; ADR-0020's custody survey; ADR-0016 §11.3 O6/O7/O8
//! and §11.9 (`StateDirectory=twinvpn`, mode 0700, `UMask=0077`);
//! threat-model I4 / TM-13 / TM-14.
//!
//! # CB-5, made structurally impossible rather than documented
//!
//! > The identity key (IK), `OwnerSigningKey` and `OwnerRootKey` may **never** be
//! > held by the core. Operations are vtable calls performed **inside the
//! > element**.
//!
//! The mechanism here is the same one `twinvpn-platform` uses one level up, and
//! it is a property of the *types*, not of the comments:
//!
//! - [`LinuxIdentityCustody`] has **no field that can hold a private scalar**.
//!   Its whole state is a [`SigningElement`] — a trait object naming *which
//!   element*, never any bytes — and a cached public identity.
//! - There is **no constructor that accepts key material.**
//!   [`LinuxIdentityCustody::new`] takes an element; there is no `from_bytes`,
//!   no `from_pem`, no `from_file`.
//! - There is **no accessor that yields any.** The trait returns a
//!   [`Signature`] or a [`SharedSecret`], both of which are opaque and neither of
//!   which is a key.
//! - The `Debug` impl names the element and nothing else.
//!
//! An implementation that wanted to hold a key would have to add a field, which
//! is a visible change to a type in this file, not an invisible change to a
//! comment. `no_type_in_this_module_can_hold_a_private_scalar` asserts the size
//! of the struct to make even that visible.
//!
//! # §11.16 (l): no element means `false`, and no substitute
//!
//! > reports `hardware_backed` **truthfully per target**, so S-46 records it
//! > rather than the core assuming it. On a target with no secure element the
//! > residual is TM-13's, unchanged; **the core MUST NOT substitute a
//! > file-backed signer silently.**
//!
//! This build ships one element — [`AbsentElement`] — which reports
//! `hardware_backed: false` and refuses every operation with
//! `AUTH.KEY_UNAVAILABLE`. That is the specified behaviour on a host with no
//! TPM, **not** a gap being papered over: substituting a file-backed signer is
//! what §11.16 (l) forbids in terms, and a refusal the core records is strictly
//! better than a signature it cannot attribute to an element.
//!
//! A TPM 2.0 element over `/dev/tpmrm0` (ADR-0016 §11.9's `DeviceAllow`) is the
//! intended production implementation and is **not** in this wave: it needs a
//! TPM crate that `core/Cargo.toml` does not declare, and that manifest is the
//! integration lead's. [`tpm_resource_manager_present`] detects the device so
//! the shell can report the mismatch rather than the user discovering it.
//!
//! # CB-7's shell half
//!
//! > what genuinely has no stable C-callable form is … *obtaining* the vault
//! > directory and stamping its platform attributes.
//!
//! On Linux the attributes are POSIX ones: the directory is created `0700` and
//! owned by the service account, and there is no backup-exclusion flag and no
//! file-protection class to stamp — so [`StoreRootAttributes`] reports
//! `backup_excluded: false` and `protection_class: None`, **truthfully**, rather
//! than claiming a property the platform does not have.
//!
//! Ordinary file I/O beneath the vended path is deliberately **not** here: it is
//! POSIX on all ten targets, so by CB-1 it belongs in the core.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures_core::future::BoxFuture;
use twinvpn_platform::{
    IdentityAttestation, IdentityCustody, IdentityKeyRef, IdentityPublic, PeerPublicKey,
    PlatformError, RecordAeadCustody, SecureItem, SecureItemKey, SecureStore, SharedSecret,
    Signature, StoreRoot, StoreRootAttributes,
};

use crate::oserr::{self, Context};
use crate::shutdown::ShutdownLatch;

/// The TPM 2.0 resource manager ADR-0016 §11.9 grants the daemon.
pub const TPM_RESOURCE_MANAGER: &str = "/dev/tpmrm0";

/// Whether this host has a TPM resource manager.
///
/// Reported so the shell can say "this host has a TPM and this build cannot use
/// it" rather than reporting the same `hardware_backed: false` it would report
/// on a container with no TPM at all. Those are different facts with different
/// remediations, and collapsing them is the kind of silence §11.16 (l) exists to
/// prevent.
#[must_use]
pub fn tpm_resource_manager_present() -> bool {
    Path::new(TPM_RESOURCE_MANAGER).exists()
}

/// An element that performs identity operations **inside itself**.
///
/// Every method names *which* key and returns a *result*. No method takes key
/// material and no method returns any, so an implementation of this trait cannot
/// hand a private scalar to its caller even if it wanted to — which is CD-I4
/// ("no type in the workspace can carry an identity private scalar") enforced at
/// the one boundary where it would otherwise be tempting.
pub trait SigningElement: Send + Sync + std::fmt::Debug {
    /// A stable, non-localised name — `"tpm2"`, `"absent"`.
    fn name(&self) -> &'static str;

    /// Whether the private half genuinely lives in hardware.
    fn hardware_backed(&self) -> bool;

    /// The public identity, if the element has one.
    ///
    /// # Errors
    ///
    /// [`PlatformError::IdentityKeyUnavailable`] where there is no element.
    fn public_identity(&self) -> Result<IdentityPublic, PlatformError>;

    /// Signs inside the element.
    fn sign(&self, key: IdentityKeyRef, message: &[u8]) -> Result<Signature, PlatformError>;

    /// Agrees inside the element.
    ///
    /// §11.16 (c) is explicit that in-element **agree** is not required on every
    /// target, so [`PlatformError::OsUnsupported`] is a legitimate answer and is
    /// **not** a licence for the core to fall back to a private key it does not
    /// have.
    fn agree(
        &self,
        key: IdentityKeyRef,
        peer: &PeerPublicKey,
    ) -> Result<SharedSecret, PlatformError>;

    /// The element's own attestation blob, if it produces one.
    fn attestation(&self) -> Option<(Vec<u8>, &'static str)>;
}

/// The element on a host with no usable secure element.
///
/// Refuses every operation with `AUTH.KEY_UNAVAILABLE` and reports
/// `hardware_backed: false`. See the module documentation: this is §11.16 (l)'s
/// specified behaviour, not an omission — the alternative it forbids is a
/// silent file-backed signer.
#[derive(Debug, Clone, Copy, Default)]
pub struct AbsentElement;

impl SigningElement for AbsentElement {
    fn name(&self) -> &'static str {
        "absent"
    }

    fn hardware_backed(&self) -> bool {
        // Truthfully false. TM-13's residual, stated rather than inferred.
        false
    }

    fn public_identity(&self) -> Result<IdentityPublic, PlatformError> {
        Err(PlatformError::IdentityKeyUnavailable(Some(
            oserr::detail_from_code(libc::ENODEV, "identity.element"),
        )))
    }

    fn sign(&self, _key: IdentityKeyRef, _message: &[u8]) -> Result<Signature, PlatformError> {
        Err(PlatformError::IdentityKeyUnavailable(Some(
            oserr::detail_from_code(libc::ENODEV, "identity_sign"),
        )))
    }

    fn agree(
        &self,
        _key: IdentityKeyRef,
        _peer: &PeerPublicKey,
    ) -> Result<SharedSecret, PlatformError> {
        Err(PlatformError::IdentityKeyUnavailable(Some(
            oserr::detail_from_code(libc::ENODEV, "identity_agree"),
        )))
    }

    fn attestation(&self) -> Option<(Vec<u8>, &'static str)> {
        None
    }
}

/// Linux identity custody.
///
/// **Holds no key material.** See the module documentation for the four
/// structural properties that make that true.
pub struct LinuxIdentityCustody {
    element: Arc<dyn SigningElement>,
    shutdown: ShutdownLatch,
}

impl std::fmt::Debug for LinuxIdentityCustody {
    /// Names the element and nothing else.
    ///
    /// A derived `Debug` would walk into whatever an element implementation
    /// holds, and `ownership.md` §6 rule 11 makes a derive that reaches a secret
    /// exactly the accident to prevent.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxIdentityCustody")
            .field("element", &self.element.name())
            .finish_non_exhaustive()
    }
}

impl LinuxIdentityCustody {
    /// Binds an element.
    ///
    /// There is deliberately no other constructor. In particular there is no
    /// `from_bytes`, `from_pem` or `from_file`: the type cannot be given a
    /// private key because no function accepts one.
    #[must_use]
    pub fn new(element: Arc<dyn SigningElement>, shutdown: ShutdownLatch) -> Self {
        Self { element, shutdown }
    }

    /// The element's stable name, for `CoreBuildIdentity` (S-46).
    #[must_use]
    pub fn element_name(&self) -> &'static str {
        self.element.name()
    }
}

impl IdentityCustody for LinuxIdentityCustody {
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
            let (attestation, format) = match self.element.attestation() {
                Some((blob, tag)) => (Some(blob), Some(tag)),
                None => (None, None),
            };
            Ok(IdentityAttestation {
                hardware_backed: self.element.hardware_backed(),
                attestation,
                format,
            })
        })
    }
}

/// Tier-1 secure storage and the vended vault directory.
///
/// # The documented fallback, and what it costs
///
/// The platform store DN-21's sibling table names for Linux is **libsecret**,
/// which is a D-Bus API against `gnome-keyring` or `kwallet`. It is unusable
/// here for two independent reasons, both worth stating:
///
/// 1. **No D-Bus client is in the workspace's dependency set**, and
///    `core/Cargo.toml` is the integration lead's.
/// 2. **libsecret needs a user session.** ADR-0016 §11.14 (f) and (g) require
///    the key handle to be openable "with no user logged in (Linux: TPM without
///    a session keyring)" and the core to initialise without "a user session, a
///    desktop bus, or a login keyring". A daemon that could only read its own
///    vault while a desktop was logged in would fail R-06's unattended-recovery
///    path — so libsecret is the *wrong* mechanism for `twinvpnd` regardless of
///    the dependency question.
///
/// The fallback is therefore **whole-blob files under the vended store root**,
/// mode `0600` in a `0700` directory owned by the service account, replaced
/// atomically (temp → `fsync` → `rename` → directory `fsync`). That is the same
/// shape CB-7 describes — "whole-blob atomic replacement, which is the shape
/// Keychain / Keystore / DPAPI / libsecret actually have" — over POSIX
/// permissions instead of a keyring.
///
/// **What it costs, stated:** the SEK is protected by filesystem permissions and
/// by nothing else. Any process that is `root`, or that is the service account,
/// can read it. That is TM-13's residual on a target with no element, and it is
/// exactly why [`SecureStore::record_aead_custody`] reports
/// [`RecordAeadCustody::CoreHeld`] — CB-6a calls the software-held path "the
/// common case", not "the fallback".
pub struct LinuxSecureStore {
    root: PathBuf,
    shutdown: ShutdownLatch,
}

impl LinuxSecureStore {
    /// The subdirectory Tier-1 items live in, beneath the vended root.
    ///
    /// Separate from the Tier-2 records the core writes so that a `chmod` audit
    /// has one directory to look at, and so an operator can see at a glance which
    /// files are the secret ones.
    pub const TIER1_DIR: &'static str = "tier1";

    /// Binds the store to a vault directory.
    ///
    /// The path is **injected at construction, never discovered** (CD-2, CB-7):
    /// `twinvpn.h` says so in terms, and a store that discovered its own root
    /// from an environment variable would be readable by whoever set it.
    #[must_use]
    pub fn new(root: PathBuf, shutdown: ShutdownLatch) -> Self {
        Self { root, shutdown }
    }

    /// Creates the vault directory with its Linux attributes applied.
    ///
    /// # Errors
    ///
    /// The OS error, named. A vault directory that cannot be created or cannot
    /// be made `0700` is a startup failure: continuing would put the SEK
    /// somewhere world-readable.
    pub fn prepare(&self) -> Result<(), PlatformError> {
        let tier1 = self.root.join(Self::TIER1_DIR);
        let map = |call: &'static str| {
            move |e: std::io::Error| oserr::from_errno(&e, call, Context::SecureStore)
        };
        fs::create_dir_all(&tier1).map_err(map("mkdir(store_root)"))?;
        // 0700 on both, matching ADR-0016 O8's "StateDirectory=twinvpn, mode
        // 0700". Set explicitly rather than relying on `UMask=0077`, because a
        // directory that already existed with a wider mode would otherwise stay
        // wide — and the mode is checked back, not assumed applied.
        for dir in [&self.root, &tier1] {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                .map_err(map("chmod(store_root)"))?;
            let mode = fs::metadata(dir)
                .map_err(map("stat(store_root)"))?
                .permissions()
                .mode()
                & 0o777;
            if mode != 0o700 {
                return Err(oserr::unavailable("store_root.mode", libc::EPERM));
            }
        }
        Ok(())
    }

    fn item_path(&self, key: &SecureItemKey) -> PathBuf {
        // `SecureItemKey` already restricts the name to `[a-z0-9_.-]` and 128
        // bytes, so no path component can escape the directory. The join is
        // safe because the type made it safe, not because of a check here.
        self.root.join(Self::TIER1_DIR).join(key.as_str())
    }
}

impl SecureStore for LinuxSecureStore {
    fn secure_item_read<'a>(
        &'a self,
        key: &'a SecureItemKey,
    ) -> BoxFuture<'a, Result<Option<SecureItem>, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            match fs::read(self.item_path(key)) {
                Ok(bytes) => Ok(Some(SecureItem::new(bytes))),
                // "Absent" is a normal first-run state and not an error — the
                // distinction matters because absent enrols and unavailable
                // must not.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(oserr::from_errno(
                    &e,
                    "read(secure_item)",
                    Context::SecureStore,
                )),
            }
        })
    }

    fn secure_item_write_atomic<'a>(
        &'a self,
        key: &'a SecureItemKey,
        value: &'a SecureItem,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            let path = self.item_path(key);
            let parent = path
                .parent()
                .ok_or_else(|| oserr::unavailable("secure_item.parent", libc::EINVAL))?;
            let map = |call: &'static str| {
                move |e: std::io::Error| oserr::from_errno(&e, call, Context::SecureStore)
            };
            let temp = parent.join(format!(".{}.tmp", key.as_str()));

            // The temp file is created 0600 BEFORE anything is written into it.
            // Creating it 0644 and chmod-ing afterwards leaves a window in which
            // the SEK is world-readable, and that window is exactly long enough.
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp)
                .map_err(map("create(secure_item.tmp)"))?;
            file.write_all(value.as_bytes())
                .map_err(map("write(secure_item.tmp)"))?;
            // "Atomic per item: a torn write of the SEK would make the whole
            // vault unreadable, and ADR-0020's recovery ladder cannot recover a
            // key it never received."
            file.sync_all().map_err(map("fsync(secure_item.tmp)"))?;
            drop(file);
            fs::rename(&temp, &path).map_err(map("rename(secure_item)"))?;
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
            Ok(())
        })
    }

    fn secure_item_delete<'a>(
        &'a self,
        key: &'a SecureItemKey,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            match fs::remove_file(self.item_path(key)) {
                Ok(()) => Ok(()),
                // Idempotent.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(oserr::from_errno(
                    &e,
                    "unlink(secure_item)",
                    Context::SecureStore,
                )),
            }
        })
    }

    fn store_root(&self) -> BoxFuture<'_, Result<StoreRoot, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            self.prepare()?;
            Ok(StoreRoot {
                path: self.root.clone(),
                attributes: StoreRootAttributes {
                    // Linux has no platform backup-exclusion flag. Reporting
                    // `false` is the truthful answer; claiming `true` would put
                    // a property in S-46 that no mechanism enforces.
                    backup_excluded: false,
                    // And no file-protection class. `None` rather than a
                    // made-up tag.
                    protection_class: None,
                    owner_only: true,
                },
            })
        })
    }

    fn record_aead_custody(&self) -> RecordAeadCustody {
        // CB-6a: "mandatory platform AEAD exists on 2 of 10 targets — Android
        // Keystore and Windows with a TPM". Linux is not one of them, so the key
        // is unsealed into the core's locked allocator. Declared, never
        // inferred, so "this device's vault key was software-held" is a readable
        // fact in the bundle rather than something a reader has to work out.
        RecordAeadCustody::CoreHeld
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "twinvpn-store-test-{}-{}",
            std::process::id(),
            // A counter rather than a clock: CD-3 bans a clock read here.
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        path
    }
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    #[test]
    fn no_type_in_this_module_can_hold_a_private_scalar() {
        // CD-I4, asserted rather than asserted-in-prose. `LinuxIdentityCustody`
        // is one `Arc<dyn SigningElement>` plus one `ShutdownLatch` (itself an
        // `Arc`), and nothing else. Adding a field to hold a key would change
        // this number and fail here.
        assert_eq!(
            std::mem::size_of::<LinuxIdentityCustody>(),
            std::mem::size_of::<Arc<dyn SigningElement>>() + std::mem::size_of::<ShutdownLatch>()
        );
    }

    #[test]
    fn the_debug_impl_names_the_element_and_nothing_else() {
        let custody = LinuxIdentityCustody::new(Arc::new(AbsentElement), ShutdownLatch::new());
        let text = format!("{custody:?}");
        assert!(text.contains("absent"));
        assert!(
            !text.contains("key"),
            "no key material, not even a field name"
        );
    }

    #[tokio::test]
    async fn a_host_with_no_element_reports_false_and_refuses_rather_than_substituting() {
        // §11.16 (l): "the core MUST NOT substitute a file-backed signer
        // silently". Refusing is the specified behaviour, and the attestation
        // still answers so S-46 records the truth.
        let custody = LinuxIdentityCustody::new(Arc::new(AbsentElement), ShutdownLatch::new());
        let attestation = custody.identity_attestation().await.expect("answers");
        assert!(!attestation.hardware_backed);
        assert_eq!(attestation.attestation, None);
        assert_eq!(attestation.format, None);

        let err = custody
            .identity_sign(IdentityKeyRef::Identity { generation: 0 }, b"x")
            .await
            .expect_err("no element");
        assert_eq!(err.reason_code().as_str(), "AUTH.KEY_UNAVAILABLE");
        assert_eq!(err.os_detail().map(|d| d.call), Some("identity_sign"));
    }

    #[tokio::test]
    async fn a_tier_one_item_round_trips_and_absent_is_not_an_error() {
        let root = temp_root();
        let store = LinuxSecureStore::new(root.clone(), ShutdownLatch::new());
        store.prepare().expect("prepares");
        let key = SecureItemKey::new("sek.v1").expect("valid");

        // Absent is a normal first-run state.
        assert!(store.secure_item_read(&key).await.expect("reads").is_none());

        store
            .secure_item_write_atomic(&key, &SecureItem::new(vec![7u8; 32]))
            .await
            .expect("writes");
        let read = store
            .secure_item_read(&key)
            .await
            .expect("reads")
            .expect("present");
        assert_eq!(read.as_bytes(), &[7u8; 32]);

        // Idempotent delete.
        store.secure_item_delete(&key).await.expect("deletes");
        store.secure_item_delete(&key).await.expect("idempotent");
        assert!(store.secure_item_read(&key).await.expect("reads").is_none());

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_tier_one_item_is_never_world_readable_even_for_an_instant() {
        // Creating 0644 and chmod-ing afterwards leaves a window in which the
        // SEK is world-readable, and that window is exactly long enough.
        let root = temp_root();
        let store = LinuxSecureStore::new(root.clone(), ShutdownLatch::new());
        store.prepare().expect("prepares");
        let key = SecureItemKey::new("k-bind").expect("valid");
        store
            .secure_item_write_atomic(&key, &SecureItem::new(b"secret".to_vec()))
            .await
            .expect("writes");

        let mode = fs::metadata(root.join(LinuxSecureStore::TIER1_DIR).join("k-bind"))
            .expect("exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        for dir in [&root, &root.join(LinuxSecureStore::TIER1_DIR)] {
            let mode = fs::metadata(dir).expect("exists").permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "ADR-0016 O8: the state directory is 0700");
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_pre_existing_wide_open_vault_directory_is_tightened_not_accepted() {
        let root = temp_root();
        fs::create_dir_all(root.join(LinuxSecureStore::TIER1_DIR)).expect("creates");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).expect("chmod");
        let store = LinuxSecureStore::new(root.clone(), ShutdownLatch::new());
        store.prepare().expect("prepares");
        let mode = fs::metadata(&root).expect("exists").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn the_store_root_declares_only_the_attributes_linux_actually_has() {
        let root = temp_root();
        let store = LinuxSecureStore::new(root.clone(), ShutdownLatch::new());
        let vended = store.store_root().await.expect("vends");
        assert_eq!(vended.path, root);
        assert!(vended.attributes.owner_only);
        assert!(
            !vended.attributes.backup_excluded,
            "Linux has no platform backup-exclusion flag; claiming one would put \
             an unenforced property in S-46"
        );
        assert_eq!(vended.attributes.protection_class, None);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cb6a_custody_is_declared_as_core_held_the_common_case() {
        let store = LinuxSecureStore::new(temp_root(), ShutdownLatch::new());
        assert_eq!(store.record_aead_custody(), RecordAeadCustody::CoreHeld);
    }

    #[tokio::test]
    async fn the_store_refuses_new_work_after_shutdown() {
        let latch = ShutdownLatch::new();
        let store = LinuxSecureStore::new(temp_root(), latch.clone());
        latch.begin();
        let key = SecureItemKey::new("sek.v1").expect("valid");
        match store.secure_item_read(&key).await {
            Err(PlatformError::ShuttingDown) => {}
            other => panic!("expected ShuttingDown, got {other:?}"),
        }
    }
}
