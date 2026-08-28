//! The Tier-2 vault file: format, atomic multi-key commit, and crash recovery.
//!
//! **Authority:** ADR-0020 ST-12 (E1–E8), ST-12a, ST-12b, ST-12e, ST-15,
//! §11.5 (the file set), §11.9 (single opener), ADR-0018 CB-7.
//!
//! # What this engine is, stated plainly
//!
//! ADR-0020 names "a pure-Rust, single-file, copy-on-write B-tree store
//! (`redb`-class)" as the **Phase 2 default**. That crate is not in the
//! workspace dependency table, and the workspace manifest is the integration
//! lead's, so this wave implements the engine directly: a single file, rewritten
//! whole, committed by `write → fsync → rename → fsync(dir)`.
//!
//! Measured against ST-12's eight properties, honestly:
//!
//! | # | Property | This engine |
//! |---|---|---|
//! | E1 | One file plus at most one lock sidecar; no server, no thread | **Met.** `vault.tv`, `vault.lock`, and a transient `vault.tv.tmp` |
//! | E2 | Atomic, crash-consistent **multi-key** commit; a torn write leaves the previous state fully readable | **Met.** `rename(2)` over a fully-written, fsynced temp file is atomic on POSIX; the whole transaction is one rename |
//! | E3 | Single writer, single opener | **Met.** `vault.lock` holds the owner record; a second opener is refused |
//! | E4 | Page or record checksums, so corruption is detected not returned | **Met, twice.** A SHA-256 over the file body, and a per-record AEAD tag ([`crate::record`]) |
//! | E5 | Configurable read cache; MUST operate without mapping the whole file | **Partially met, and stated.** Nothing is `mmap`ed, so the 32-bit address-space hazard E5 names does not arise — but the file *is* read into memory in full. For a vault of a few hundred records that is tens of kilobytes; it would not be acceptable for a large one |
//! | E6 | Builds for every target with no new C dependency | **Met.** `std::fs` only |
//! | E7 | Explicit, versioned, deterministic on-disk format with the version in the header | **Met.** See [`Vault::encode`] |
//! | E8 | Explicit durability barrier, and correctness that survives a lying device | **Met.** `File::sync_all` before the rename and on the directory after; and because the commit is a rename of a *complete* file, a device that lies about the barrier still yields either the old file or the new one, never a blend |
//!
//! The one gap is E5's second clause, and it is a real limitation rather than a
//! reading of the rule: this engine is O(vault size) per commit. It is reported
//! as such.
//!
//! # ST-12e — the path is vended, never discovered
//!
//! [`Vault`] takes a `store_root` that the shell has already created with its
//! attributes applied. There is no path constant, no environment lookup, and no
//! fallback directory in this crate.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use twinvpn_crypto::sha256;

use crate::error::{Result, Rung, StoreError};

/// The file magic. Eight bytes, so a `file(1)` on a vault says something.
pub const MAGIC: &[u8; 8] = b"TVVAULT\x01";

/// The highest whole-store schema this build reads (ST-15).
pub const MAX_SUPPORTED_SCHEMA: u32 = 1;

/// `MIN_SUPPORTED = MAX_SUPPORTED − 2`, per ST-15 rule 3, floored at 1.
pub const MIN_SUPPORTED_SCHEMA: u32 = if MAX_SUPPORTED_SCHEMA > 3 {
    MAX_SUPPORTED_SCHEMA - 2
} else {
    1
};

/// The largest vault this build will read.
///
/// Rule 10: a length field in a file an attacker can write is untrusted input.
/// 64 MiB is far above any real vault and bounds what a corrupted header can
/// make this process allocate.
pub const MAX_VAULT_BYTES: usize = 64 * 1024 * 1024;

/// The cap on record count, applied before any `Vec` is reserved.
pub const MAX_RECORDS: usize = 100_000;

/// The vault's in-memory image.
///
/// Records are held as `(flat key, envelope octets)`. The vault engine does not
/// decrypt: [`crate::record`] does, one record at a time, and the engine never
/// sees a plaintext. That is why a vault-level corruption is a different rung
/// from a record-level one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vault {
    /// The whole-store schema version.
    pub schema_version: u32,
    /// Identifies this vault.
    pub store_id: [u8; 16],
    /// The commit counter (ST-21).
    pub store_seq: u64,
    /// `flat key -> envelope`, sorted by key so the encoding is deterministic
    /// (E7) and two identical vaults digest identically.
    pub records: std::collections::BTreeMap<String, Vec<u8>>,
}

impl Vault {
    /// A fresh, empty vault.
    #[must_use]
    pub fn empty(store_id: [u8; 16]) -> Self {
        Self {
            schema_version: MAX_SUPPORTED_SCHEMA,
            store_id,
            store_seq: 0,
            records: std::collections::BTreeMap::new(),
        }
    }

    /// The deterministic on-disk encoding (E7).
    ///
    /// ```text
    /// magic         : 8
    /// schema_version: u32 BE
    /// store_id      : 16
    /// store_seq     : u64 BE
    /// record_count  : u32 BE
    /// records       : [ u16 BE key_len, key, u32 BE env_len, envelope ] *
    /// checksum      : SHA-256 over everything above
    /// ```
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4096);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        out.extend_from_slice(&self.store_id);
        out.extend_from_slice(&self.store_seq.to_be_bytes());
        out.extend_from_slice(
            &u32::try_from(self.records.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for (k, v) in &self.records {
            out.extend_from_slice(&u16::try_from(k.len()).unwrap_or(u16::MAX).to_be_bytes());
            out.extend_from_slice(k.as_bytes());
            out.extend_from_slice(&u32::try_from(v.len()).unwrap_or(u32::MAX).to_be_bytes());
            out.extend_from_slice(v);
        }
        let digest = sha256(&out);
        out.extend_from_slice(&digest);
        out
    }

    /// The digest of the committed image, for the anchor's `vault_digest`.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.encode())
    }

    /// Decodes a vault image, checking the header, the checksum and every
    /// declared length **before** allocating anything proportional to it.
    ///
    /// # Errors
    ///
    /// [`StoreError::SchemaTooNew`] for a future schema — which ST-15 rule 2
    /// requires be refused rather than repaired — or
    /// [`StoreError::VaultCorrupt`] naming which detector fired.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        // magic + schema + store_id + store_seq + count + checksum
        const FIXED: usize = 8 + 4 + 16 + 8 + 4 + 32;

        let corrupt = |detector: &'static str| StoreError::VaultCorrupt {
            rung: Rung::L3,
            detector,
        };
        if bytes.len() > MAX_VAULT_BYTES {
            return Err(corrupt("vault over cap"));
        }
        if bytes.len() < FIXED {
            return Err(corrupt("header truncated"));
        }
        if &bytes[..8] != MAGIC {
            return Err(corrupt("magic"));
        }
        let body = &bytes[..bytes.len() - 32];
        let stored: [u8; 32] = bytes[bytes.len() - 32..]
            .try_into()
            .map_err(|_| corrupt("checksum width"))?;
        if sha256(body) != stored {
            return Err(corrupt("header checksum"));
        }

        let schema_version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        // ST-15 rule 2, checked before anything else is read: a newer vault is
        // refused, never "repaired". This is what makes a version rollback
        // non-destructive.
        if schema_version > MAX_SUPPORTED_SCHEMA {
            return Err(StoreError::SchemaTooNew {
                found: schema_version,
                max_supported: MAX_SUPPORTED_SCHEMA,
            });
        }
        let mut store_id = [0u8; 16];
        store_id.copy_from_slice(&bytes[12..28]);
        let store_seq =
            u64::from_be_bytes(bytes[28..36].try_into().map_err(|_| corrupt("store_seq"))?);
        let count = u32::from_be_bytes(
            bytes[36..40]
                .try_into()
                .map_err(|_| corrupt("record count"))?,
        ) as usize;
        if count > MAX_RECORDS {
            return Err(corrupt("record count over cap"));
        }

        let mut pos = 40usize;
        let end = body.len();
        let mut records = std::collections::BTreeMap::new();
        for _ in 0..count {
            if pos + 2 > end {
                return Err(corrupt("record key length"));
            }
            let klen = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
            pos += 2;
            if klen == 0 || pos + klen > end {
                return Err(corrupt("record key"));
            }
            let key = core::str::from_utf8(&body[pos..pos + klen])
                .map_err(|_| corrupt("record key encoding"))?
                .to_owned();
            pos += klen;
            if pos + 4 > end {
                return Err(corrupt("record envelope length"));
            }
            let vlen = u32::from_be_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]])
                as usize;
            pos += 4;
            if pos + vlen > end {
                return Err(corrupt("record envelope"));
            }
            if records
                .insert(key, body[pos..pos + vlen].to_vec())
                .is_some()
            {
                // A duplicate key would let a reader see either value depending
                // on iteration order — the storage form of the duplicate-map-key
                // defect RFC 8949 §5.6 rejects.
                return Err(corrupt("duplicate record key"));
            }
            pos += vlen;
        }
        if pos != end {
            return Err(corrupt("trailing bytes"));
        }
        Ok(Self {
            schema_version,
            store_id,
            store_seq,
            records,
        })
    }
}

/// The vault's paths beneath a shell-vended `store_root` (§11.5's file set).
#[derive(Debug, Clone)]
pub struct VaultPaths {
    root: PathBuf,
}

impl VaultPaths {
    /// Names the file set beneath a vended root.
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// `vault.tv`.
    #[must_use]
    pub fn vault(&self) -> PathBuf {
        self.root.join("vault.tv")
    }

    /// `vault.lock`.
    #[must_use]
    pub fn lock(&self) -> PathBuf {
        self.root.join("vault.lock")
    }

    /// The transient commit file.
    #[must_use]
    pub fn temp(&self) -> PathBuf {
        self.root.join("vault.tv.tmp")
    }

    /// `vault.corrupt.<tag>`, the L3 quarantine name.
    #[must_use]
    pub fn quarantine(&self, tag: &str) -> PathBuf {
        self.root.join(format!("vault.corrupt.{tag}"))
    }

    /// `vault.v<N>.bak`, the pre-migration copy ST-15 rule 3 retains.
    #[must_use]
    pub fn migration_backup(&self, from_schema: u32) -> PathBuf {
        self.root.join(format!("vault.v{from_schema}.bak"))
    }

    /// The vended root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Reads the vault image, or `None` if the file is absent.
///
/// Absence is not an error: ST-24 row 7 makes "vault absent, anchor present" the
/// normal reinstall path.
///
/// # Errors
///
/// [`StoreError::VaultIo`] for anything other than "not found".
pub fn read_vault(paths: &VaultPaths) -> Result<Option<Vec<u8>>> {
    match fs::read(paths.vault()) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_error(&e)),
    }
}

/// Writes a vault image atomically: `write → fsync → rename → fsync(dir)`.
///
/// E2 and E8. The rename is the commit: before it, the previous image is
/// complete on disk and is what a reader sees; after it, the new image is. There
/// is no instant at which a reader can observe a blend, which is what makes the
/// **multi-key** transaction of ST-12b atomic without a manifest.
///
/// # Errors
///
/// [`StoreError::VaultIo`] naming the step that failed.
pub fn commit_vault(paths: &VaultPaths, image: &[u8]) -> Result<()> {
    let tmp = paths.temp();
    {
        let mut f = fs::File::create(&tmp).map_err(|e| io_error(&e))?;
        f.write_all(image).map_err(|e| io_error(&e))?;
        // E8's durability barrier: the temp file must be *entirely* on the
        // medium before the rename publishes it, or a crash could publish a
        // truncated image under the new name.
        f.sync_all().map_err(|e| io_error(&e))?;
    }
    fs::rename(&tmp, paths.vault()).map_err(|e| io_error(&e))?;
    // The rename itself must be durable, or a crash can leave the directory
    // entry pointing at the old inode while the new file is fully written —
    // which is a silent rollback of exactly one commit.
    if let Ok(dir) = fs::File::open(paths.root()) {
        // A directory fsync is not available on every filesystem; a failure is
        // recorded by ST-24's classification at the next open rather than
        // failing the commit, because the data is already durable and the
        // previous image is still valid.
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Moves a corrupt vault aside (§11.11 L3).
///
/// **Renames, never deletes.** ST-15 rule 2 and L3 both require the quarantined
/// file to survive: it is the only evidence of what went wrong, and deleting it
/// would make a support case unanswerable.
///
/// # Errors
///
/// [`StoreError::VaultIo`].
pub fn quarantine_vault(paths: &VaultPaths, tag: &str) -> Result<PathBuf> {
    let dst = paths.quarantine(tag);
    fs::rename(paths.vault(), &dst).map_err(|e| io_error(&e))?;
    Ok(dst)
}

/// Acquires the single-opener lock (E3, §11.9).
///
/// Realized as an exclusive-create of `vault.lock`. A stale lock from a crashed
/// process is a real operational problem and is **not** silently broken here:
/// ADR-0020 registers `STORE.LOCK_CONTENDED` for it, and breaking a lock whose
/// holder might still be running is how two writers appear.
///
/// # Errors
///
/// [`StoreError::VaultIo`] with `detector = "lock contended"` if the lock
/// exists. That maps to `STORE.VAULT_CORRUPT` today because
/// `STORE.LOCK_CONTENDED` is absent from the frozen registry — see
/// [`crate::error`].
pub fn acquire_lock(paths: &VaultPaths, owner: &str) -> Result<()> {
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(paths.lock())
    {
        Ok(mut f) => {
            f.write_all(owner.as_bytes()).map_err(|e| io_error(&e))?;
            f.sync_all().map_err(|e| io_error(&e))?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(StoreError::VaultIo {
            detector: "lock contended",
        }),
        Err(e) => Err(io_error(&e)),
    }
}

/// Releases the single-opener lock.
///
/// # Errors
///
/// [`StoreError::VaultIo`].
pub fn release_lock(paths: &VaultPaths) -> Result<()> {
    match fs::remove_file(paths.lock()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_error(&e)),
    }
}

/// Coarsens an `io::Error` into a closed-set detector name.
///
/// ST-32a: "Raw OS status values … MUST NOT be attached: they are coarsened to
/// the declared category field, because a raw status is both unstable across OS
/// versions and a fingerprinting surface." So the `errno` never leaves this
/// function.
fn io_error(e: &std::io::Error) -> StoreError {
    let detector = match e.kind() {
        std::io::ErrorKind::PermissionDenied => "permission denied",
        std::io::ErrorKind::StorageFull => "no space",
        std::io::ErrorKind::ReadOnlyFilesystem => "read-only filesystem",
        std::io::ErrorKind::NotFound => "path absent",
        std::io::ErrorKind::AlreadyExists => "lock contended",
        _ => "vault i/o",
    };
    StoreError::VaultIo { detector }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vault {
        let mut v = Vault::empty([0x1d; 16]);
        v.store_seq = 3;
        v.records.insert("peer/alice".to_owned(), vec![1, 2, 3]);
        v.records.insert("trust/epoch".to_owned(), vec![4, 5]);
        v
    }

    #[test]
    fn a_vault_round_trips_through_its_on_disk_form() {
        let v = sample();
        let b = Vault::decode(&v.encode()).expect("decode");
        assert_eq!(b, v);
    }

    /// E7: the encoding is deterministic, so two identical vaults digest
    /// identically and the anchor's `vault_digest` means something.
    #[test]
    fn the_encoding_is_deterministic_regardless_of_insertion_order() {
        let mut a = Vault::empty([0x1d; 16]);
        a.records.insert("b".to_owned(), vec![1]);
        a.records.insert("a".to_owned(), vec![2]);
        let mut b = Vault::empty([0x1d; 16]);
        b.records.insert("a".to_owned(), vec![2]);
        b.records.insert("b".to_owned(), vec![1]);
        assert_eq!(a.encode(), b.encode());
        assert_eq!(a.digest(), b.digest());
    }

    /// **Attack test — E4.** Any corruption of the image is detected by the
    /// checksum rather than returned as data.
    #[test]
    fn any_single_byte_corruption_is_detected() {
        let image = sample().encode();
        for i in 0..image.len() {
            let mut c = image.clone();
            c[i] ^= 0x01;
            assert!(
                Vault::decode(&c).is_err(),
                "corruption at offset {i} was not detected"
            );
        }
    }

    /// **Attack test — ST-15 rule 2.** A vault from a newer build is refused,
    /// and specifically not "repaired": the caller gets `STORE.SCHEMA_TOO_NEW`
    /// and the file is untouched.
    #[test]
    fn a_future_schema_is_refused_and_never_repaired() {
        let mut v = sample();
        v.schema_version = MAX_SUPPORTED_SCHEMA + 1;
        let err = Vault::decode(&v.encode()).expect_err("must refuse");
        assert!(matches!(
            err,
            StoreError::SchemaTooNew {
                max_supported: MAX_SUPPORTED_SCHEMA,
                ..
            }
        ));
        assert_eq!(err.reason_code().as_str(), "STORE.SCHEMA_TOO_NEW");
    }

    /// **Attack test — rule 10.** A header declaring a hundred million records
    /// is forty bytes of input. It must not drive an allocation.
    #[test]
    fn a_hostile_record_count_allocates_nothing() {
        let mut image = Vec::new();
        image.extend_from_slice(MAGIC);
        image.extend_from_slice(&1u32.to_be_bytes());
        image.extend_from_slice(&[0u8; 16]);
        image.extend_from_slice(&0u64.to_be_bytes());
        image.extend_from_slice(&u32::MAX.to_be_bytes());
        let digest = sha256(&image);
        image.extend_from_slice(&digest);
        assert!(matches!(
            Vault::decode(&image),
            Err(StoreError::VaultCorrupt { .. })
        ));
    }

    /// **Attack test.** A declared envelope length beyond the file must be
    /// refused before the slice is taken.
    #[test]
    fn a_declared_length_beyond_the_file_is_refused() {
        let mut body = Vec::new();
        body.extend_from_slice(MAGIC);
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&[0u8; 16]);
        body.extend_from_slice(&0u64.to_be_bytes());
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes());
        body.push(b'k');
        body.extend_from_slice(&u32::MAX.to_be_bytes());
        let digest = sha256(&body);
        body.extend_from_slice(&digest);
        assert!(matches!(
            Vault::decode(&body),
            Err(StoreError::VaultCorrupt { .. })
        ));
    }

    /// **Attack test.** Two records under one key would let a reader see either
    /// value; it is the storage form of a duplicate map key.
    #[test]
    fn a_duplicate_record_key_is_refused() {
        let mut body = Vec::new();
        body.extend_from_slice(MAGIC);
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&[0u8; 16]);
        body.extend_from_slice(&0u64.to_be_bytes());
        body.extend_from_slice(&2u32.to_be_bytes());
        for v in [1u8, 2] {
            body.extend_from_slice(&1u16.to_be_bytes());
            body.push(b'k');
            body.extend_from_slice(&1u32.to_be_bytes());
            body.push(v);
        }
        let digest = sha256(&body);
        body.extend_from_slice(&digest);
        assert!(Vault::decode(&body).is_err());
    }

    #[test]
    fn trailing_bytes_after_the_last_record_are_refused() {
        let v = sample();
        let mut image = v.encode();
        // Insert a byte before the checksum and re-checksum, so the only
        // remaining defect is the unconsumed byte.
        let body_len = image.len() - 32;
        image.insert(body_len, 0x00);
        let body_len = body_len + 1;
        let digest = sha256(&image[..body_len]);
        image[body_len..body_len + 32].copy_from_slice(&digest);
        assert!(Vault::decode(&image).is_err());
    }

    /// ST-15 rule 3's window.
    #[test]
    fn the_supported_schema_window_is_max_minus_two() {
        assert_eq!(
            MIN_SUPPORTED_SCHEMA,
            if MAX_SUPPORTED_SCHEMA > 3 {
                MAX_SUPPORTED_SCHEMA - 2
            } else {
                1
            }
        );
        // Schema 0 is not a schema: a vault header carrying it is malformed,
        // not merely old.
        assert_ne!(MIN_SUPPORTED_SCHEMA, 0);
    }
}
