//! `StoreError`, and the honest mapping onto the `STORE.*` codes the frozen
//! registry actually contains.
//!
//! **Authority:** ADR-0020 §11.12 and ST-32a, ADR-0015 §11.2,
//! `contracts/registry/reason_codes.json`, `docs/implementation/ownership.md`
//! §6 rule 12.
//!
//! # The gap that was worked around, and is now closed
//!
//! ADR-0020 §11.12 registers **twenty** `STORE.*` codes. The freeze of
//! 2026-08-27 carried **six** of them, so this module mapped each unavailable
//! condition onto the nearest registered code and named the intended one in the
//! variant's documentation "so the mapping is removable in one edit once the
//! registry is amended".
//!
//! **Amendment 1 to `contracts/FROZEN` amended it** (201 → 454 codes, W-18), and
//! the fourteen absent `STORE.*` codes — and ST-23's
//! `CONTROL.CONSISTENCY.VERSION_ROLLBACK_REJECTED` — have been registered since.
//! The edit the old text promised is this one: every condition below is emitted
//! under **its own** code, and no `STORE.*` condition is reported under another
//! condition's identifier any more.
//!
//! What that cost while it stood, recorded rather than quietly dropped: an
//! L1 single-record tag failure (`TRANSIENT`/`WARN`, "wait") arrived as
//! `STORE.VAULT_CORRUPT` (`PERSISTENT`/`ERROR`, "Local data was damaged and has
//! been rebuilt", user-actionable), a survivable migration failure said the same
//! thing about a store that was intact, a contended lock — ADR-0020 SI-5's
//! *security event* — was indistinguishable from a corrupt vault, and every
//! secure-storage refusal degraded on the `AUTH` prefix to "authentication
//! problem" when the truth was "this device's local secure storage is not
//! answering". ADR-0015 §11.2 rule 5's prefix degradation is what made the
//! domain half of that a real cost and not a cosmetic one.
//!
//! # The residue, stated
//!
//! Two distinctions ADR-0020 §11.12 draws still cannot be drawn here, because
//! the *seam* does not carry them rather than because the registry does not:
//!
//! - `STORE.KEYSTORE_LOCKED` vs `STORE.KEYSTORE_UNAVAILABLE`.
//!   [`twinvpn_platform::PlatformError`] coarsens every Tier-1 refusal to
//!   `SecureStoreUnavailable`, so "the device is locked" and "the backend is not
//!   answering" arrive identical. Both are `TRANSIENT` and both remediate by
//!   waiting, so the emitted code is the non-accusatory of the two.
//! - The four `VaultIo` file-set conditions are separated by
//!   [`crate::vault`]'s closed-set `detector`, which is exactly ST-32a's
//!   coarsening of `errno` — so `WRITE_SPACE_EXHAUSTED`, `READONLY_FILESYSTEM`,
//!   `LOCK_CONTENDED` and `PATH_UNSUITABLE` are emitted by name, and anything
//!   the detector does not name stays `STORE.VAULT_CORRUPT` rather than being
//!   guessed into one of them. **No `errno` crosses this boundary**, so the
//!   `errno`/`syscall`/`os_error_code`/`platform` evidence those codes declare is
//!   deliberately not attached.
//!
//! A test-only `INTENDED` table pins every pairing above, and a test asserts
//! each intended code is **registered** — the inverse of the tripwire the other
//! domains carry, and the one this module lacked while its prose went stale.

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
    /// **Registered and emitted:** `STORE.RECORD_CORRUPT` (`TRANSIENT`/`WARN`,
    /// remediation `WAIT`). One record is not the vault: this used to be emitted
    /// as `STORE.VAULT_CORRUPT`, which told the user their local data "has been
    /// rebuilt" for a condition rung L1 recovers from in place.
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
    /// **Registered and emitted:** `STORE.ANCHOR_MISSING` (`PERSISTENT`/`ERROR`).
    /// It used to be emitted as `STORE.ANCHOR_MISMATCH`, which is `FATAL` and
    /// `terminal` — the safe direction while the code was unavailable, but a
    /// terminal verdict on a state ADR-0020 ST-24 recovers from by suspending
    /// granted authority and re-anchoring.
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
    /// **Registered and emitted:** `STORE.MIGRATION_FAILED`, with the
    /// `schema_from` / `schema_to` / `step` evidence the registry declares. It
    /// used to be emitted as `STORE.VAULT_CORRUPT`, whose user-facing text
    /// ("Local data was damaged and has been rebuilt") contradicted this
    /// variant's own guarantee that the pre-migration store is intact.
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
    /// **Registered and emitted:** `STORE.KEYSTORE_UNAVAILABLE`
    /// (`TRANSIENT`/`WARN`, remediation `WAIT`) — the same class and severity as
    /// the `AUTH.KEY_STORE_UNAVAILABLE` this used to emit, in the domain the
    /// condition actually belongs to. `STORE.KEYSTORE_LOCKED` is registered too
    /// and is **not** emitted here: the platform seam coarsens both to one
    /// variant (see the module header's residue note), and claiming "locked"
    /// would tell the user to unlock a device that may be answering fine.
    #[error("tier-1 secure storage unavailable")]
    SecureStoreUnavailable,

    /// Vault file I/O failed.
    ///
    /// **Registered and emitted, one code per detector:**
    /// `STORE.WRITE_SPACE_EXHAUSTED`, `STORE.READONLY_FILESYSTEM`,
    /// `STORE.LOCK_CONTENDED` and `STORE.PATH_UNSUITABLE`, with
    /// `STORE.VAULT_CORRUPT` for a detector that names none of them. The split is
    /// [`StoreError::reason_code`]'s, over the same closed set
    /// [`crate::vault`] coarsens `io::ErrorKind` into. **No `errno` crosses this
    /// boundary** (ST-32a): `detector` is a closed set of `&'static str`.
    ///
    /// `STORE.LOCK_CONTENDED` matters most of the four: ADR-0020 SI-5 calls a
    /// second opener "a security event rather than a retryable condition", and
    /// under `STORE.VAULT_CORRUPT` it read as damaged data.
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
    /// Every condition is emitted under its own registered code; the module
    /// header records the two distinctions the platform seam cannot draw.
    ///
    /// Not `const`: the `VaultIo` split matches on the detector's closed set of
    /// `&'static str`, and `str` comparison is not yet available in a `const fn`.
    #[must_use]
    pub fn reason_code(&self) -> ReasonCode {
        match self {
            StoreError::VaultCorrupt { .. } => codes::STORE_VAULT_CORRUPT,
            StoreError::RecordCorrupt { .. } => codes::STORE_RECORD_CORRUPT,
            StoreError::MigrationFailed { .. } => codes::STORE_MIGRATION_FAILED,
            // The detector is `vault::io_error`'s ST-32a coarsening of
            // `io::ErrorKind`. A detector this match does not name stays
            // `STORE.VAULT_CORRUPT` rather than being sorted into the nearest
            // file-set code, which is the direction that does not invent a
            // diagnosis.
            StoreError::VaultIo { detector } => match *detector {
                "no space" => codes::STORE_WRITE_SPACE_EXHAUSTED,
                "read-only filesystem" => codes::STORE_READONLY_FILESYSTEM,
                "lock contended" => codes::STORE_LOCK_CONTENDED,
                "permission denied" | "path absent" => codes::STORE_PATH_UNSUITABLE,
                _ => codes::STORE_VAULT_CORRUPT,
            },
            StoreError::FloorWouldDecrease { .. } => codes::AUTH_TRUST_EPOCH_ROLLBACK,
            StoreError::RollbackDetected { .. } => codes::STORE_ROLLBACK_DETECTED,
            StoreError::AnchorMismatch { .. } => codes::STORE_ANCHOR_MISMATCH,
            StoreError::AnchorMissing => codes::STORE_ANCHOR_MISSING,
            StoreError::SchemaTooNew { .. } => codes::STORE_SCHEMA_TOO_NEW,
            StoreError::SecureStoreUnavailable => codes::STORE_KEYSTORE_UNAVAILABLE,
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
            // Declared by `STORE.RECORD_CORRUPT` since Amendment 1, and both
            // are closed-set `&'static str` rather than anything the record
            // itself contained: `record_class` is not attached because this
            // layer knows the namespace, not the class within it.
            StoreError::RecordCorrupt {
                namespace,
                detector,
            } => {
                b = b
                    .evidence("namespace", EvidenceValue::Text((*namespace).to_owned()))
                    .evidence("detector", EvidenceValue::Text((*detector).to_owned()));
            }
            // Declared by `STORE.MIGRATION_FAILED` since Amendment 1. `step` is
            // this crate's own closed set of step names, never an OS string.
            StoreError::MigrationFailed { from, to, step } => {
                b = b
                    .evidence("schema_from", EvidenceValue::Uint(u64::from(*from)))
                    .evidence("schema_to", EvidenceValue::Uint(u64::from(*to)))
                    .evidence("step", EvidenceValue::Text((*step).to_owned()));
            }
            // The remaining codes declare no evidence field this layer can
            // honestly fill. `STORE.VAULT_CORRUPT`'s `rung`/`detector` and
            // `STORE.ROLLBACK_DETECTED`'s `store_seq_anchor`/`store_seq_vault`
            // are named by ADR-0020 §11.12 but are NOT in
            // `reason_codes.json`'s `evidence_fields` for those codes, which
            // lists none; attaching them would be silently dropped by
            // `Evidence::new`. The four `VaultIo` codes declare
            // `errno`/`syscall`/`os_error_code`/`platform`, and ST-32a is why
            // none of them crosses this boundary — the detector chose the code
            // and is not itself re-attached as a raw status.
            StoreError::VaultCorrupt { .. }
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
    /// only coarse categories, and this conversion drops even those.
    ///
    /// It is also where `STORE.KEYSTORE_LOCKED` is lost: the collapse happens
    /// here, in the seam, not in the registry. Splitting it needs a
    /// `PlatformError` variant that says *locked* — a change to
    /// [`twinvpn_platform`]'s contract, and therefore not this crate's to make.
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

/// Every condition that used to be substituted, and the code it is emitted
/// under now.
///
/// The inverse of the tripwire tables the other domains carry. Theirs assert a
/// spelling is still **absent**, so registering one fails the build; this one
/// asserts each is **present**, so a registry that lost a code — or a build
/// wired to a stale one — fails here rather than degrading a diagnosis silently.
/// The pairing that went stale in this module's prose for a whole amendment
/// cycle is the reason it is a test and not a paragraph.
#[cfg(test)]
const INTENDED: &[(&str, &str)] = &[
    ("record corrupt", "STORE.RECORD_CORRUPT"),
    ("anchor missing", "STORE.ANCHOR_MISSING"),
    ("migration failed", "STORE.MIGRATION_FAILED"),
    ("tier-1 refusal", "STORE.KEYSTORE_UNAVAILABLE"),
    ("no space", "STORE.WRITE_SPACE_EXHAUSTED"),
    ("read-only filesystem", "STORE.READONLY_FILESYSTEM"),
    ("lock contended", "STORE.LOCK_CONTENDED"),
    ("path unsuitable", "STORE.PATH_UNSUITABLE"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_types::Evidence;

    /// Every code this module now emits is in the frozen registry.
    #[test]
    fn every_intended_code_is_registered() {
        for (condition, code) in INTENDED {
            assert!(
                ReasonCode::lookup(code).is_some(),
                "{condition} emits {code}, which the frozen registry does not carry"
            );
        }
    }

    /// The conditions that were collapsed onto one code are distinguishable
    /// again — asserted as a set, so a future collapse fails here.
    #[test]
    fn no_two_store_conditions_share_one_code() {
        let emitted = [
            StoreError::VaultCorrupt {
                rung: Rung::L3,
                detector: "header",
            }
            .reason_code(),
            StoreError::RecordCorrupt {
                namespace: "peer",
                detector: "aead tag",
            }
            .reason_code(),
            StoreError::MigrationFailed {
                from: 1,
                to: 2,
                step: "rewrite",
            }
            .reason_code(),
            StoreError::VaultIo {
                detector: "no space",
            }
            .reason_code(),
            StoreError::VaultIo {
                detector: "read-only filesystem",
            }
            .reason_code(),
            StoreError::VaultIo {
                detector: "lock contended",
            }
            .reason_code(),
            StoreError::VaultIo {
                detector: "permission denied",
            }
            .reason_code(),
            StoreError::AnchorMismatch { store_seq: 3 }.reason_code(),
            StoreError::AnchorMissing.reason_code(),
            StoreError::SecureStoreUnavailable.reason_code(),
        ];
        let mut seen: Vec<&str> = emitted.iter().map(|c| c.as_str()).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(
            before,
            seen.len(),
            "two conditions share one code: {seen:?}"
        );
    }

    /// A detector the split does not name is not sorted into the nearest
    /// file-set code. The positive control is in the same test: the four it
    /// does name are.
    #[test]
    fn an_unnamed_detector_stays_vault_corrupt() {
        assert_eq!(
            StoreError::VaultIo {
                detector: "vault i/o"
            }
            .reason_code()
            .as_str(),
            "STORE.VAULT_CORRUPT"
        );
        assert_eq!(
            StoreError::VaultIo {
                detector: "path absent"
            }
            .reason_code()
            .as_str(),
            "STORE.PATH_UNSUITABLE"
        );
    }

    /// The evidence Amendment 1 declared is actually attached — and survives
    /// `Evidence`'s declared-set filter, which silently drops what a code does
    /// not declare. A test that only built the diagnostic would pass either way.
    #[test]
    fn the_declared_evidence_survives_the_filter() {
        let d = StoreError::RecordCorrupt {
            namespace: "peer",
            detector: "aead tag",
        }
        .diagnostic(Component::Store);
        let keys: Vec<&str> = d.evidence().entries().iter().map(Evidence::key).collect();
        assert!(keys.contains(&"namespace"), "evidence dropped: {keys:?}");
        assert!(keys.contains(&"detector"), "evidence dropped: {keys:?}");

        let m = StoreError::MigrationFailed {
            from: 1,
            to: 2,
            step: "rewrite",
        }
        .diagnostic(Component::Store);
        let keys: Vec<&str> = m.evidence().entries().iter().map(Evidence::key).collect();
        for k in ["schema_from", "schema_to", "step"] {
            assert!(keys.contains(&k), "evidence dropped: {k} not in {keys:?}");
        }
    }
}
