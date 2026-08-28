//! CB-5 secret custody and CB-7 storage: the Keychain, and the vended vault.
//!
//! **Authority:** ADR-0018 CB-5 (the identity private half may never be held by
//! the core), CB-6a, CB-7, §11.16 (c) and (l); ADR-0020 §11.3's **four macOS
//! rows**, ST-1, ST-5/ST-6 (the accessibility class), ST-9a (two probes, minimum
//! wins), ST-22 (the anchor is co-located with the identity key), §10.5 (a
//! signing-identity change is a store migration); ADR-0007 N-5; threat model
//! I4/TM-13/TM-14.
//!
//! # CB-5, and what this module cannot weaken
//!
//! No method here returns private key material. [`SigningElement`] is an
//! *operation* interface — sign, agree, attest — and there is no `export`, no
//! `raw` and no accessor that yields a scalar. An adapter with no element reports
//! `hardware_backed: false` **truthfully** and refuses; §11.16 (l) is explicit
//! that the core must not substitute a file-backed signer silently, and
//! [`AbsentElement`] is what makes the refusal the default rather than a policy.
//!
//! # ADR-0020's four macOS rows, and the one honest answer
//!
//! | Build shape | Tier-1 backend | Custody |
//! |---|---|---|
//! | system extension, Apple silicon / T2 | data-protection keychain (`kSecUseDataProtectionKeychain = true`) + Secure Enclave | `HARDWARE_ATTESTED` **only if the SEK is SEP-wrapped too** |
//! | `launchd` daemon, Developer ID | the **System** keychain, item ACL bound to the Team-signed binary | `SOFTWARE_LOCAL` unless the SEK is SEP-wrapped |
//! | pre-T2 Intel | file-based keychain item, no SEP | `SOFTWARE_LOCAL` |
//! | App Store sandbox | data-protection keychain, App Group container | not this build (H2 rejected it — it forfeits KS-19) |
//!
//! **ST-9a is the rule that makes this a computation rather than a claim:** two
//! probes, the identity key's and the vault key's, and **the minimum wins** —
//! "a macOS Developer ID daemon may hold a SEP-backed IK while its SEK is a
//! System-keychain item". [`CustodyClass::combine`] is that minimum, and it is
//! tested here.
//!
//! # ST-5 / ST-6: the accessibility class is not a preference
//!
//! `kSecAttrAccessibleWhenUnlocked` and `NSFileProtectionComplete` are
//! **forbidden**: a `LaunchDaemon` or a system extension runs with no user session
//! and an item it cannot read is an agent that cannot start.
//! `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` is the choice, and
//! [`Accessibility`] has no variant for the forbidden ones — so the rule is a type
//! rather than a review comment.

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

/// ADR-0020's macOS store path: `root:wheel`, `0700`, "the system extension /
/// `launchd` daemon only".
pub const DEFAULT_STORE_ROOT: &str = "/Library/Application Support/TwinVPN";

/// The mode ADR-0016 O8 requires on the vault directory.
pub const STORE_ROOT_MODE: u32 = 0o700;

/// The Keychain accessibility classes this build may use.
///
/// Two variants, not seven. ST-5/ST-6 forbid `kSecAttrAccessibleWhenUnlocked` and
/// its relatives outright, and an enum that could express them would need a
/// reviewer to notice; an enum that cannot express them needs nobody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accessibility {
    /// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
    ///
    /// The system-extension row's choice. Readable after the first console unlock
    /// since boot and never synced or migrated — which is why a headless Mac that
    /// has rebooted and never been logged into reports `STORE.KEYSTORE_LOCKED`
    /// rather than silently enrolling a second identity.
    AfterFirstUnlockThisDeviceOnly,
    /// The **System** keychain, whose items are readable from boot with no user
    /// session at all.
    ///
    /// ADR-0020's Developer-ID daemon row. Its protection is the item ACL bound
    /// to the Team-signed binary, not an accessibility class, which is why it is a
    /// separate value rather than a third class name.
    SystemKeychain,
}

impl Accessibility {
    /// The stable, non-localised tag recorded in `CoreBuildIdentity` (S-46) and
    /// in [`StoreRootAttributes::protection_class`].
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Accessibility::AfterFirstUnlockThisDeviceOnly => {
                "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"
            }
            Accessibility::SystemKeychain => "SystemKeychainACL",
        }
    }

    /// Whether this shape needs the data-protection keychain.
    ///
    /// `true` for the system extension, `false` for the `launchd` daemon: the
    /// System keychain is the *file* keychain and setting
    /// `kSecUseDataProtectionKeychain` on a query against it makes the item
    /// invisible.
    #[must_use]
    pub const fn uses_data_protection_keychain(self) -> bool {
        matches!(self, Accessibility::AfterFirstUnlockThisDeviceOnly)
    }
}

/// The Keychain item shape Tier-1 items are written with.
///
/// Injected at construction (CD-2): which of ADR-0020's four rows a build is in
/// is a packaging fact, and an adapter that sniffed for a Secure Enclave and
/// picked a row would be deciding its own custody class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeychainItemSpec {
    /// `kSecAttrService`. One service for every TwinVPN item, so an uninstall can
    /// enumerate them.
    pub service: String,
    /// `kSecAttrAccessGroup`, where the build has one. `None` on the Developer-ID
    /// daemon row, which has no app group.
    pub access_group: Option<String>,
    /// The accessibility shape.
    pub accessibility: Accessibility,
}

impl KeychainItemSpec {
    /// `kSecAttrAccount` for one Tier-1 key.
    ///
    /// The seam's [`SecureItemKey`] is already constrained to
    /// `[a-z0-9_.-]{1,128}`, so this is a pass-through rather than an escaping
    /// step — stated because an escaping step here would be a second encoding of
    /// the same name and the two would drift.
    #[must_use]
    pub fn account_for(&self, key: &SecureItemKey) -> String {
        key.as_str().to_owned()
    }

    /// Whether `kSecAttrSynchronizable` must be false.
    ///
    /// Always. ADR-0020 excludes Tier 1 from backup and sync; an item that
    /// synced to iCloud Keychain would put the SEK on every device the Owner
    /// signs into, which is the opposite of `ThisDeviceOnly`.
    #[must_use]
    pub const fn synchronizable(&self) -> bool {
        false
    }
}

/// What the platform truthfully offers for one key.
///
/// ADR-0020's summary table, as a lattice: `Absent < SoftwareLocal <
/// HardwareAttested`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CustodyClass {
    /// No element and no store.
    Absent,
    /// A keychain item with no Secure Enclave behind it.
    SoftwareLocal,
    /// A Secure Enclave key with an attestation.
    HardwareAttested,
}

impl CustodyClass {
    /// **ST-9a: two probes, and the minimum wins.**
    ///
    /// "A macOS Developer ID daemon may hold a SEP-backed IK while its SEK is a
    /// System-keychain item" — and a device whose vault key is software-held is
    /// not hardware-attested, whatever its identity key is. Taking the maximum
    /// here would be the single most flattering and least true line in the
    /// diagnostic bundle.
    #[must_use]
    pub fn combine(identity: Self, vault: Self) -> Self {
        identity.min(vault)
    }

    /// The stable, non-localised tag for S-46.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            CustodyClass::Absent => "ABSENT",
            CustodyClass::SoftwareLocal => "SOFTWARE_LOCAL",
            CustodyClass::HardwareAttested => "HARDWARE_ATTESTED",
        }
    }
}

/// An element that can perform identity operations without releasing the key.
///
/// The Secure Enclave on a T2 or Apple-silicon Mac; a plain Keychain key
/// elsewhere; [`AbsentElement`] where there is neither.
pub trait SigningElement: Send + Sync + std::fmt::Debug {
    /// A stable, non-localised name for the element, recorded in S-46.
    fn name(&self) -> &'static str;

    /// What this element truthfully is.
    fn custody_class(&self) -> CustodyClass;

    /// The public identity.
    ///
    /// # Errors
    ///
    /// [`PlatformError::IdentityKeyUnavailable`] when the element cannot be
    /// reached — a locked keychain, a revoked entitlement, a lost binding.
    fn public_identity(&self) -> Result<IdentityPublic, PlatformError>;

    /// Signs inside the element. ES256 on the IK, never exported.
    fn sign(&self, key: IdentityKeyRef, message: &[u8]) -> Result<Signature, PlatformError>;

    /// Element-resident agreement, where the element offers one.
    ///
    /// **Not required.** ADR-0018 §11.16 (c) is explicit that in-element `agree`
    /// is not required — the Secure Enclave offers P-256 ECDH and **not** X25519,
    /// which is exactly why TK is hardware-*wrapped* rather than element-resident
    /// (ADR-0007 N-5). An element that cannot do this returns
    /// [`PlatformError::OsUnsupported`], which the core records; it is **not** a
    /// licence to fall back to a private key the core does not have.
    fn agree(
        &self,
        key: IdentityKeyRef,
        peer: &PeerPublicKey,
    ) -> Result<SharedSecret, PlatformError>;

    /// The attestation record (§11.16 (l)).
    fn attestation(&self) -> Result<IdentityAttestation, PlatformError>;
}

/// The element on a host that has none.
///
/// Reports `hardware_backed: false` truthfully and **refuses every operation**.
/// The residual is TM-13's, unchanged and stated.
#[derive(Debug, Clone, Copy, Default)]
pub struct AbsentElement;

impl SigningElement for AbsentElement {
    fn name(&self) -> &'static str {
        "absent"
    }

    fn custody_class(&self) -> CustodyClass {
        CustodyClass::Absent
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
        // Not `IdentityKeyUnavailable`: the element does not offer the operation
        // at all, which is a different fact with a different remediation.
        Err(PlatformError::OsUnsupported(None))
    }

    fn attestation(&self) -> Result<IdentityAttestation, PlatformError> {
        Ok(IdentityAttestation {
            hardware_backed: false,
            attestation: None,
            format: None,
        })
    }
}

/// Tier-1 item storage, injected so the transaction above it is testable.
pub trait Tier1Store: Send + Sync + std::fmt::Debug {
    /// Reads an item. `Ok(None)` is **absent**, which is a normal first-run state.
    fn read(&self, account: &str) -> Result<Option<Vec<u8>>, PlatformError>;

    /// Writes an item, replacing any previous value **atomically per item**.
    fn write(&self, account: &str, value: &[u8]) -> Result<(), PlatformError>;

    /// Deletes an item. Idempotent.
    fn delete(&self, account: &str) -> Result<(), PlatformError>;

    /// What this backend truthfully is.
    fn custody_class(&self) -> CustodyClass;
}

/// A Tier-1 store on a host with no Keychain.
///
/// Every operation refuses. **Not a file fallback**: ADR-0018 §11.16 (l) forbids
/// substituting a software store silently, and a Tier-1 store that quietly became
/// a file would put the SEK on disk in plaintext.
#[derive(Debug, Clone, Copy, Default)]
pub struct AbsentTier1Store;

impl Tier1Store for AbsentTier1Store {
    fn read(&self, _account: &str) -> Result<Option<Vec<u8>>, PlatformError> {
        Err(PlatformError::SecureStoreUnavailable(None))
    }

    fn write(&self, _account: &str, _value: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::SecureStoreUnavailable(None))
    }

    fn delete(&self, _account: &str) -> Result<(), PlatformError> {
        Err(PlatformError::SecureStoreUnavailable(None))
    }

    fn custody_class(&self) -> CustodyClass {
        CustodyClass::Absent
    }
}

/// macOS's identity custody.
pub struct MacosIdentityCustody {
    element: Arc<dyn SigningElement>,
    shutdown: ShutdownLatch,
}

impl std::fmt::Debug for MacosIdentityCustody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The element's NAME, never anything derived from a key.
        f.debug_struct("MacosIdentityCustody")
            .field("element", &self.element.name())
            .field("shutting_down", &self.shutdown.is_shutting_down())
            .finish()
    }
}

impl MacosIdentityCustody {
    /// Binds the custody surface.
    #[must_use]
    pub fn new(element: Arc<dyn SigningElement>, shutdown: ShutdownLatch) -> Self {
        Self { element, shutdown }
    }

    /// The element's stable name.
    #[must_use]
    pub fn element_name(&self) -> &'static str {
        self.element.name()
    }

    /// The element's honest custody class.
    #[must_use]
    pub fn custody_class(&self) -> CustodyClass {
        self.element.custody_class()
    }
}

impl IdentityCustody for MacosIdentityCustody {
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
            self.element.attestation()
        })
    }
}

/// macOS's Tier-1 store and vended vault root.
#[derive(Debug)]
pub struct MacosSecureStore {
    root: PathBuf,
    spec: KeychainItemSpec,
    backend: Arc<dyn Tier1Store>,
    shutdown: ShutdownLatch,
}

impl MacosSecureStore {
    /// Binds the store. The root is **injected, never discovered** (CB-7, CD-2).
    #[must_use]
    pub fn new(root: PathBuf, spec: KeychainItemSpec, shutdown: ShutdownLatch) -> Self {
        Self::with_backend(root, spec, Arc::new(AbsentTier1Store), shutdown)
    }

    /// The same, with the Tier-1 backend supplied.
    #[must_use]
    pub fn with_backend(
        root: PathBuf,
        spec: KeychainItemSpec,
        backend: Arc<dyn Tier1Store>,
        shutdown: ShutdownLatch,
    ) -> Self {
        Self {
            root,
            spec,
            backend,
            shutdown,
        }
    }

    /// The item spec in force.
    #[must_use]
    pub const fn spec(&self) -> &KeychainItemSpec {
        &self.spec
    }

    /// The combined custody class, per **ST-9a**.
    #[must_use]
    pub fn custody_class(&self, identity: CustodyClass) -> CustodyClass {
        CustodyClass::combine(identity, self.backend.custody_class())
    }

    /// Creates the vault directory with ADR-0016 O8's mode, before the core asks
    /// for it.
    ///
    /// # Errors
    ///
    /// [`PlatformError::SecureStoreUnavailable`] if the directory cannot be
    /// created or its mode cannot be set. **Never a wider mode**: a vault the
    /// group can read is a vault every local account can read, and PS-12a makes
    /// "every local account can enumerate this device's peers" an install-time
    /// decision rather than a platform default.
    pub fn prepare(&self) -> Result<(), PlatformError> {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::create_dir_all(&self.root)
            .map_err(|e| oserr::from_errno(&e, "mkdir(store)", Context::SecureStore))?;
        let permissions = std::fs::Permissions::from_mode(STORE_ROOT_MODE);
        std::fs::set_permissions(&self.root, permissions)
            .map_err(|e| oserr::from_errno(&e, "chmod(store)", Context::SecureStore))?;
        Ok(())
    }

    /// Whether the directory's mode is what [`prepare`](Self::prepare) set.
    ///
    /// Checked rather than assumed: an installer, a migration or a curious
    /// administrator can widen it, and a vault whose mode drifted is a Tier-2
    /// store readable by every local account.
    #[must_use]
    // `& 0o077 == 0` is how a POSIX mode is read; `trailing_zeros() >= 6` says the
    // same thing in a vocabulary nobody checking a vault's permissions thinks in.
    #[allow(clippy::verbose_bit_mask)]
    pub fn root_is_owner_only(path: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o077 == 0)
            .unwrap_or(false)
    }
}

impl SecureStore for MacosSecureStore {
    fn secure_item_read<'a>(
        &'a self,
        key: &'a SecureItemKey,
    ) -> BoxFuture<'a, Result<Option<SecureItem>, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            Ok(self
                .backend
                .read(&self.spec.account_for(key))?
                .map(SecureItem::new))
        })
    }

    fn secure_item_write_atomic<'a>(
        &'a self,
        key: &'a SecureItemKey,
        value: &'a SecureItem,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            self.backend
                .write(&self.spec.account_for(key), value.as_bytes())
        })
    }

    fn secure_item_delete<'a>(
        &'a self,
        key: &'a SecureItemKey,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            self.backend.delete(&self.spec.account_for(key))
        })
    }

    fn store_root(&self) -> BoxFuture<'_, Result<StoreRoot, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            Ok(StoreRoot {
                path: self.root.clone(),
                attributes: StoreRootAttributes {
                    // **Declared, not performed.** ADR-0020's macOS row needs
                    // `NSURLIsExcludedFromBackupKey` on the root *and* a
                    // `tmutil addexclusion` registered by the installer. The
                    // first is a Foundation API this crate does not link and the
                    // second is the package's; both live in
                    // `shells/macos/packaging/install.sh`. Reporting `true` here
                    // would be the core recording an exclusion nobody applied, so
                    // it reports what this crate can actually vouch for.
                    backup_excluded: false,
                    protection_class: Some(self.spec.accessibility.tag()),
                    owner_only: Self::root_is_owner_only(&self.root),
                },
            })
        })
    }

    fn record_aead_custody(&self) -> RecordAeadCustody {
        // CB-6a: "where the platform key API can perform the record AEAD itself,
        // it MUST". The Secure Enclave performs ECIES and signing, and does
        // **not** offer a general AEAD over caller-supplied data, so the SEK is
        // unsealed into `twinvpn-crypto`'s locked allocator on every macOS row.
        // ADR-0020's own survey says mandatory platform AEAD exists on two of ten
        // targets — Android Keystore and Windows with a TPM — and macOS is not
        // one of them. Declared, not inferred.
        RecordAeadCustody::CoreHeld
    }
}
