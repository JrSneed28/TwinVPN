//! `StoreError`, and the honest mapping onto the `STORE.*` codes the frozen
//! registry actually contains.
//!
//! **Authority:** ADR-0020 §11.12 and ST-32a, ADR-0015 §11.2,
//! `contracts/registry/reason_codes.json`, `docs/implementation/ownership.md`
//! §6 rule 12.
//!
//! # An open contract gap, worked around rather than patched
//!
//! ADR-0020 §11.12 registers **twenty** `STORE.*` codes. The frozen registry
//! contains **six**: `VAULT_CORRUPT`, `ROLLBACK_DETECTED`, `ANCHOR_MISMATCH`,
//! `CUSTODY_DEGRADED`, `SCHEMA_TOO_NEW`, `PRESERVE_RULE_MISSING`. The fourteen
//! absent ones include several this implementation genuinely reaches:
//! `STORE.RECORD_CORRUPT`, `STORE.NAMESPACE_REBUILT`, `STORE.ANCHOR_MISSING`,
//! `STORE.MIGRATION_FAILED`, `STORE.LOCK_CONTENDED`,
//! `STORE.WRITE_SPACE_EXHAUSTED`, `STORE.READONLY_FILESYSTEM`,
//! `STORE.KEYSTORE_LOCKED`, `STORE.KEYSTORE_UNAVAILABLE`,
//! `STORE.KEY_INVALIDATED`, `STORE.PATH_UNSUITABLE`,
//! `STORE.BACKUP_EXCLUSION_FAILED`, `STORE.RESTORED_FOREIGN_HOST`,
//! `STORE.WIPE_INCOMPLETE`. ADR-0020 ST-23 also names
//! `CONTROL.CONSISTENCY.VERSION_ROLLBACK_REJECTED`, which is likewise absent —
//! the registry has only `CONTROL.CONSISTENCY.REPLICA_BEHIND_CURSOR`.
//!
//! `contracts/` is frozen (`ownership.md` §3), and "a genuine defect is a
//! finding you report, not a patch you land". So this module maps each
//! unavailable condition onto the **nearest registered code that does not
//! overstate or understate the condition**, and names the intended code in the
//! variant's documentation so the mapping is removable in one edit once the
//! registry is amended. The choices are conservative in one direction: where the
//! nearest available code is *more* severe than the intended one, that is
//! preferred to a code that would let a caller treat a real failure as routine.
//!
//! This is reported to the integration lead as a contract gap.

use twinvpn_types::{codes, Component, Diagnostic, EvidenceValue, ReasonCode};

/// Which recovery rung a failure was detected at (ADR-0020 §11.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rung {
    /// Healthy.
    L0,
    /// One record failed its AEAD tag or checksum.
    L1,
    /// A whole namespace is unreadable.
    L2,
    /// The vault cannot be opened, or `trust/`/`peer/` is unreadable.
    L3,
    /// The anchor is absent or inconsistent.
    L4,
    /// A rollback was classified at open.
    L5,
}

impl Rung {
    /// A stable tag for the `rung` evidence field.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Rung::L0 => "L0",
            Rung::L1 => "L1",
            Rung::L2 => "L2",
            Rung::L3 => "L3",
            Rung::L4 => "L4",
            Rung::L5 => "L5",
        }
    }
}

/// Every way a store operation can fail.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The vault could not be opened, its header is invalid, or a floor-bearing
    /// namespace is unreadable. Rung L3.
    ///
    /// **Intended code:** `STORE.VAULT_CORRUPT` — registered, and used.
    #[error("vault corrupt at rung {rung:?}: {detector}")]
    VaultCorrupt {
        /// Which rung detected it.
        rung: Rung,
        /// Which of the four detectors fired.
        detector: &'static str,
    },

    /// One record failed its AEAD tag or its checksum. Rung L1.
    ///
    /// **Intended code:** `STORE.RECORD_CORRUPT` (TRANSIENT/WARN), which the
    /// frozen registry does not contain. Mapped to `STORE.VAULT_CORRUPT`, which
    /// is *more* severe than intended — deliberately, because the alternative
    /// available codes would either claim a rollback (`ROLLBACK_DETECTED`, a
    /// security event) or say nothing about the store at all.
    #[error("record corrupt in {namespace}: {detector}")]
    RecordCorrupt {
        /// Which namespace the record was in.
        namespace: &'static str,
        /// Which detector fired.
        detector: &'static str,
    },

    /// A monotone floor would have decreased. **Refused, never applied.**
    ///
    /// ST-23 step 2. The registered code is `AUTH.TRUST_EPOCH_ROLLBACK`, which
    /// ADR-0020 names first for exactly this case.
    #[error("floor {floor} would decrease: offered {offered}, held {held}")]
    FloorWouldDecrease {
        /// Which floor.
        floor: &'static str,
        /// The value offered.
        offered: u64,
        /// The value already held.
        held: u64,
    },

    /// The anchor is ahead of the vault: a restore, a rollback, or a crash
    /// between ST-23 steps 3 and 5. Rung L5.
    ///
    /// **Intended and registered:** `STORE.ROLLBACK_DETECTED`.
    #[error("rollback detected: anchor at {anchor_seq}, vault at {vault_seq}")]
    RollbackDetected {
        /// `store_seq` from the Tier-1 anchor.
        anchor_seq: u64,
        /// `store_seq` from the vault.
        vault_seq: u64,
        /// Whether this is consistent with a crash rather than an attack.
        crash_recovery: bool,
    },

    /// Anchor and vault agree on `store_seq` but disagree on the digest.
    ///
    /// **Intended and registered:** `STORE.ANCHOR_MISMATCH` (FATAL).
    #[error("anchor mismatch at store_seq {store_seq}")]
    AnchorMismatch {
        /// The sequence both claim.
        store_seq: u64,
    },

    /// The anchor is absent while the identity is present.
    ///
    /// **Intended code:** `STORE.ANCHOR_MISSING`, absent from the registry.
    /// Mapped to `STORE.ANCHOR_MISMATCH`, which is the closest registered
    /// statement about the anchor. That is *more* severe (FATAL rather than
    /// PERSISTENT), which is the safe direction: ADR-0020 ST-24 suspends granted
    /// authority in this state either way.
    #[error("anti-rollback anchor absent")]
    AnchorMissing,

    /// The vault schema is above this build's maximum.
    ///
    /// **Intended and registered:** `STORE.SCHEMA_TOO_NEW`. ST-15 rule 2: it
    /// "MUST NOT delete, reset, downgrade, or 'repair' the store", which is what
    /// makes an ADR-0021 rollback non-destructive.
    #[error("vault schema {found} is above this build's maximum {max_supported}")]
    SchemaTooNew {
        /// The schema found on disk.
        found: u32,
        /// The highest this build reads.
        max_supported: u32,
    },

    /// A schema migration failed; the pre-migration store is intact.
    ///
    /// **Intended code:** `STORE.MIGRATION_FAILED`, absent from the registry.
    /// Mapped to `STORE.VAULT_CORRUPT`, whose user-facing text ("Local data was
    /// damaged and has been rebuilt") overstates the outcome — the previous
    /// store *is* intact — which is why this is called out as a gap rather than
    /// accepted as adequate.
    #[error("migration from schema {from} to {to} failed at {step}")]
    MigrationFailed {
        /// The schema migrated from.
        from: u32,
        /// The schema migrated to.
        to: u32,
        /// Which step failed.
        step: &'static str,
    },

    /// A key outside the declared namespaces (ST-14).
    ///
    /// ADR-0020 names `INTERNAL.INVARIANT_VIOLATED` for this, which **is**
    /// registered.
    #[error("key outside the declared namespaces")]
    UndeclaredNamespace,

    /// The platform's Tier-1 store refused an operation.
    ///
    /// **Intended codes:** `STORE.KEYSTORE_LOCKED` / `STORE.KEYSTORE_UNAVAILABLE`,
    /// neither registered. Mapped to `AUTH.KEY_STORE_UNAVAILABLE`, which **is**
    /// registered, is non-terminal, and carries the right meaning — the
    /// `STORE.*` variants exist to distinguish locked from unavailable, and that
    /// distinction is lost until the registry carries them.
    #[error("tier-1 secure storage unavailable")]
    SecureStoreUnavailable,

    /// Vault file I/O failed.
    ///
    /// **Intended codes:** `STORE.WRITE_SPACE_EXHAUSTED`,
    /// `STORE.READONLY_FILESYSTEM`, `STORE.PATH_UNSUITABLE`,
    /// `STORE.LOCK_CONTENDED` — none registered. Mapped to
    /// `STORE.VAULT_CORRUPT`, and the `detector` field carries which condition it
    /// actually was so a support bundle is not silent about it. **No `errno`
    /// crosses this boundary** (ST-32a): `detector` is a closed set of
    /// `&'static str`.
    #[error("vault i/o failed: {detector}")]
    VaultIo {
        /// A closed-set name for the condition. Never an `errno`.
        detector: &'static str,
    },

    /// The SEK is software-held where the target's declared class expects
    /// otherwise, or the locked allocator granted less than declared.
    ///
    /// **Intended and registered:** `STORE.CUSTODY_DEGRADED`.
    #[error("custody degraded: {asset} is {class_to}")]
    CustodyDegraded {
        /// `identity` or `vault`.
        asset: &'static str,
        /// The class actually achieved.
        class_to: &'static str,
    },

    /// A cryptographic operation the store delegates to `twinvpn-crypto` failed
    /// for a reason that is a caller defect rather than an input condition.
    #[error("store crypto invariant: {invariant}")]
    CryptoInvariant {
        /// The invariant.
        invariant: &'static str,
    },
}

impl StoreError {
    /// The registered `reason_code`.
    ///
    /// Where the intended code is absent from the frozen registry, the mapping
    /// and its justification are in the variant's own documentation.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            StoreError::VaultCorrupt { .. }
            | StoreError::RecordCorrupt { .. }
            | StoreError::MigrationFailed { .. }
            | StoreError::VaultIo { .. } => codes::STORE_VAULT_CORRUPT,
            StoreError::FloorWouldDecrease { .. } => codes::AUTH_TRUST_EPOCH_ROLLBACK,
            StoreError::RollbackDetected { .. } => codes::STORE_ROLLBACK_DETECTED,
            StoreError::AnchorMismatch { .. } | StoreError::AnchorMissing => {
                codes::STORE_ANCHOR_MISMATCH
            }
            StoreError::SchemaTooNew { .. } => codes::STORE_SCHEMA_TOO_NEW,
            StoreError::SecureStoreUnavailable => codes::AUTH_KEY_STORE_UNAVAILABLE,
            StoreError::CustodyDegraded { .. } => codes::STORE_CUSTODY_DEGRADED,
            StoreError::UndeclaredNamespace | StoreError::CryptoInvariant { .. } => {
                codes::INTERNAL_INVARIANT_VIOLATED
            }
        }
    }

    /// The typed diagnostic, with only the evidence the registry declares.
    #[must_use]
    pub fn diagnostic(&self, component: Component) -> Diagnostic {
        let mut b = Diagnostic::builder(self.reason_code(), component);
        match self {
            StoreError::FloorWouldDecrease { offered, held, .. } => {
                b = b
                    .evidence("offered_epoch", EvidenceValue::Uint(*offered))
                    .evidence("high_water_epoch", EvidenceValue::Uint(*held));
            }
            StoreError::SchemaTooNew { found, .. } => {
                b = b.evidence("schema_version", EvidenceValue::Uint(u64::from(*found)));
            }
            StoreError::UndeclaredNamespace => {
                b = b.evidence(
                    "invariant",
                    EvidenceValue::Text("ST-14 declared namespaces".to_owned()),
                );
            }
            StoreError::CryptoInvariant { invariant } => {
                b = b.evidence("invariant", EvidenceValue::Text((*invariant).to_owned()));
            }
            // The remaining registered codes declare no evidence fields the
            // frozen registry would accept — `STORE.VAULT_CORRUPT`'s
            // `rung`/`detector` and `STORE.ROLLBACK_DETECTED`'s
            // `store_seq_anchor`/`store_seq_vault` are named by ADR-0020 §11.12
            // but are NOT in `reason_codes.json`'s `evidence_fields` for those
            // codes, which lists none. Attaching them would be silently dropped
            // by `Evidence::new`, so they are deliberately not attached and the
            // gap is reported with the missing codes above.
            StoreError::VaultCorrupt { .. }
            | StoreError::RecordCorrupt { .. }
            | StoreError::MigrationFailed { .. }
            | StoreError::VaultIo { .. }
            | StoreError::RollbackDetected { .. }
            | StoreError::AnchorMismatch { .. }
            | StoreError::AnchorMissing
            | StoreError::SecureStoreUnavailable
            | StoreError::CustodyDegraded { .. } => {}
        }
        b.build()
    }
}

impl From<twinvpn_platform::PlatformError> for StoreError {
    /// Every platform failure becomes `SecureStoreUnavailable`.
    ///
    /// ST-32a: "Raw OS status values (`OSStatus`, `NTSTATUS`, `errno`, a
    /// Keystore exception class) MUST NOT be attached: they are coarsened to the
    /// declared category field, because a raw status is both unstable across OS
    /// versions and a fingerprinting surface." `PlatformError` already carries
    /// only coarse categories, and this conversion drops even those rather than
    /// inventing a `STORE.*` code the registry does not have.
    fn from(_: twinvpn_platform::PlatformError) -> Self {
        StoreError::SecureStoreUnavailable
    }
}

impl From<twinvpn_crypto::CryptoError> for StoreError {
    fn from(e: twinvpn_crypto::CryptoError) -> Self {
        match e {
            twinvpn_crypto::CryptoError::KeyLength { .. } => StoreError::CustodyDegraded {
                asset: "vault",
                class_to: "key material of the wrong width",
            },
            _ => StoreError::CryptoInvariant {
                invariant: "a store cryptographic operation failed",
            },
        }
    }
}

/// The crate's result alias.
pub type Result<T> = core::result::Result<T, StoreError>;
